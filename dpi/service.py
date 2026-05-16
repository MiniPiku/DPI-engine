"""High-level DPI analysis API for CLI and web."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from typing import List, Literal, Optional

from .dpi_engine import DPIEngine, EngineConfig
from .dpi_simple import run_collect as run_simple_collect
from .report import AppBreakdown, ProcessingReport, SniEntry, ThreadStat
from .rules import BlockingRules
from .types import AppType, app_type_to_string

EngineMode = Literal["multithreaded", "simple"]


def _apply_rules(
    rules: BlockingRules,
    block_ips: List[str],
    block_apps: List[str],
    block_domains: List[str],
) -> None:
    for ip in block_ips:
        rules.block_ip(ip)
    for app in block_apps:
        rules.block_app(app)
    for dom in block_domains:
        rules.block_domain(dom)


def _report_from_mt(engine: DPIEngine, output_file: str) -> ProcessingReport:
    stats = engine._stats
    total = stats.total_packets or 1

    apps = [
        AppBreakdown(
            name=app_type_to_string(app),
            count=count,
            percent=round(100.0 * count / total, 1),
        )
        for app, count in sorted(stats.app_counts.items(), key=lambda x: -x[1])
    ]
    snis = [
        SniEntry(domain=sni, app=app_type_to_string(app))
        for sni, app in sorted(stats.detected_snis.items())
    ]
    threads: List[ThreadStat] = []
    for i, lb in enumerate(engine._lbs):
        threads.append(ThreadStat(id=i, label=f"LB{i} dispatched", value=lb.dispatched))
    for i, fp in enumerate(engine._fps):
        threads.append(ThreadStat(id=i, label=f"FP{i} processed", value=fp.processed))

    return ProcessingReport(
        success=True,
        mode="multithreaded",
        output_file=output_file,
        total_packets=stats.total_packets,
        total_bytes=stats.total_bytes,
        tcp_packets=stats.tcp_packets,
        udp_packets=stats.udp_packets,
        forwarded=stats.forwarded,
        dropped=stats.dropped,
        apps=apps,
        snis=snis,
        threads=threads,
        config={"lbs": engine.config.num_lbs, "fps": engine.config.fps_per_lb},
    )


def _report_from_simple(
    total_packets: int,
    forwarded: int,
    dropped: int,
    flows: dict,
    app_stats: dict,
    output_file: str,
) -> ProcessingReport:
    total = total_packets or 1
    apps = [
        AppBreakdown(
            name=app_type_to_string(app),
            count=count,
            percent=round(100.0 * count / total, 1),
        )
        for app, count in sorted(app_stats.items(), key=lambda x: -x[1])
    ]
    snis_map: dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            snis_map[flow.sni] = flow.app_type
    snis = [
        SniEntry(domain=sni, app=app_type_to_string(app))
        for sni, app in sorted(snis_map.items())
    ]

    return ProcessingReport(
        success=True,
        mode="simple",
        output_file=output_file,
        total_packets=total_packets,
        forwarded=forwarded,
        dropped=dropped,
        active_flows=len(flows),
        apps=apps,
        snis=snis,
    )


def analyze_pcap(
    input_path: str | Path,
    output_path: str | Path,
    *,
    mode: EngineMode = "multithreaded",
    block_ips: Optional[List[str]] = None,
    block_apps: Optional[List[str]] = None,
    block_domains: Optional[List[str]] = None,
    lbs: int = 2,
    fps: int = 2,
    quiet: bool = True,
) -> ProcessingReport:
    """Run DPI on a PCAP file and return a structured report."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    block_ips = block_ips or []
    block_apps = block_apps or []
    block_domains = block_domains or []

    if not input_path.is_file():
        return ProcessingReport(
            success=False,
            mode=mode,
            output_file=str(output_path),
            error=f"Input file not found: {input_path}",
        )

    stdout_ctx = (
        contextlib.redirect_stdout(io.StringIO())
        if quiet
        else contextlib.nullcontext()
    )

    try:
        with stdout_ctx:
            if mode == "simple":
                rules = BlockingRules()
                _apply_rules(rules, block_ips, block_apps, block_domains)
                code, stats = run_simple_collect(
                    str(input_path), str(output_path), rules, quiet=quiet
                )
                if code != 0 or stats is None:
                    return ProcessingReport(
                        success=False,
                        mode=mode,
                        output_file=str(output_path),
                        error="Processing failed (could not open input or output)",
                    )
                total, fwd, drop, flows, app_stats = stats
                return _report_from_simple(
                    total, fwd, drop, flows, app_stats, str(output_path)
                )

            cfg = EngineConfig(num_lbs=lbs, fps_per_lb=fps)
            engine = DPIEngine(cfg)
            _apply_rules(engine._rules, block_ips, block_apps, block_domains)
            if not engine.process(str(input_path), str(output_path)):
                return ProcessingReport(
                    success=False,
                    mode=mode,
                    output_file=str(output_path),
                    error="Processing failed (invalid PCAP or output path)",
                )
            return _report_from_mt(engine, str(output_path))
    except Exception as exc:
        return ProcessingReport(
            success=False,
            mode=mode,
            output_file=str(output_path),
            error=str(exc),
        )

