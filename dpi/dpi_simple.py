"""Single-threaded DPI engine (learning / small captures)."""

from __future__ import annotations

import argparse
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

from .packet_parser import parse_packet
from .pcap_reader import PACKET_HEADER_FMT, PcapReader
from .rules import BlockingRules
from .sni_extractor import extract_http_host, extract_sni
from .types import AppType, FiveTuple, app_type_to_string, sni_to_app_type
from .console import configure_stdout
from .utils import make_five_tuple, payload_bounds


@dataclass
class Flow:
    tuple: FiveTuple = field(default_factory=lambda: FiveTuple(0, 0, 0, 0, 0))
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


def _print_banner() -> None:
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0 (Python)                   ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()


def _print_report(
    total_packets: int,
    forwarded: int,
    dropped: int,
    flows: Dict[FiveTuple, Flow],
    app_stats: Dict[AppType, int],
) -> None:
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:>10}                             ║")
    print(f"║ Forwarded:          {forwarded:>10}                             ║")
    print(f"║ Dropped:            {dropped:>10}                             ║")
    print(f"║ Active Flows:       {len(flows):>10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = 100.0 * count / total_packets if total_packets else 0
        bar = "#" * int(pct / 5)
        print(
            f"║ {app_type_to_string(app):<15} {count:>8} "
            f"{pct:5.1f}% {bar:<20}  ║"
        )

    print("╚══════════════════════════════════════════════════════════════╝")

    unique_snis: Dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type

    if unique_snis:
        print("\n[Detected Applications/Domains]")
        for sni, app in sorted(unique_snis.items()):
            print(f"  - {sni} -> {app_type_to_string(app)}")


def run(
    input_file: str,
    output_file: str,
    rules: BlockingRules,
    *,
    quiet: bool = False,
) -> int:
    code, _ = run_collect(input_file, output_file, rules, quiet=quiet)
    return code


def run_collect(
    input_file: str,
    output_file: str,
    rules: BlockingRules,
    *,
    quiet: bool = False,
) -> Tuple[int, Optional[Tuple[int, int, int, Dict[FiveTuple, Flow], Dict[AppType, int]]]]:
    if not quiet:
        _print_banner()

    reader = PcapReader()
    if not reader.open(input_file):
        return 1, None

    assert reader.global_header is not None
    out_path = Path(output_file)
    try:
        output = out_path.open("wb")
    except OSError:
        if not quiet:
            print("Error: Cannot open output file")
        reader.close()
        return 1, None

    hdr = reader.global_header
    output.write(
        struct.pack(
            "<IHHIIII",
            hdr.magic_number,
            hdr.version_major,
            hdr.version_minor,
            hdr.thiszone,
            hdr.sigfigs,
            hdr.snaplen,
            hdr.network,
        )
    )

    flows: Dict[FiveTuple, Flow] = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = defaultdict(int)

    if not quiet:
        print("[DPI] Processing packets...")

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        total_packets += 1
        parsed = parse_packet(raw)
        if parsed is None or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        tuple_ = make_five_tuple(parsed)
        flow = flows.setdefault(tuple_, Flow())
        if flow.packets == 0:
            flow.tuple = tuple_
        flow.packets += 1
        flow.bytes += len(raw.data)

        payload_offset, payload_len = payload_bounds(raw.data, parsed)

        if (
            flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 443
            and payload_len > 5
        ):
            sni = extract_sni(raw.data[payload_offset : payload_offset + payload_len])
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)

        if (
            flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 80
            and payload_len > 0
        ):
            host = extract_http_host(raw.data[payload_offset : payload_offset + payload_len])
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)

        if flow.app_type == AppType.UNKNOWN and (
            parsed.dest_port == 53 or parsed.src_port == 53
        ):
            flow.app_type = AppType.DNS

        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked and not quiet:
                print(
                    f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} "
                    f"({app_type_to_string(flow.app_type)}"
                    + (f": {flow.sni}" if flow.sni else "")
                    + ")"
                )

        app_stats[flow.app_type] += 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            output.write(
                struct.pack(
                    "<IIII",
                    raw.header.ts_sec,
                    raw.header.ts_usec,
                    len(raw.data),
                    len(raw.data),
                )
            )
            output.write(raw.data)

    reader.close()
    output.close()

    if not quiet:
        _print_report(total_packets, forwarded, dropped, flows, app_stats)
        print(f"\nOutput written to: {output_file}")
    return 0, (total_packets, forwarded, dropped, flows, app_stats)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DPI Engine - Single-threaded Deep Packet Inspection",
    )
    parser.add_argument("input_pcap", help="Input PCAP file")
    parser.add_argument("output_pcap", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOM")
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdout()
    args = build_arg_parser().parse_args(argv)
    rules = BlockingRules()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for dom in args.block_domain:
        rules.block_domain(dom)
    return run(args.input_pcap, args.output_pcap, rules)


if __name__ == "__main__":
    raise SystemExit(main())
