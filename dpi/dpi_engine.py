"""Multi-threaded DPI engine."""

from __future__ import annotations

import argparse
import struct
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Dict, List, Optional

from .packet_parser import parse_packet
from .pcap_reader import PcapReader
from .rules import BlockingRules
from .sni_extractor import extract_http_host, extract_sni
from .types import (
    AppType,
    FiveTuple,
    app_type_to_string,
    five_tuple_hash,
    sni_to_app_type,
)
from .console import configure_stdout
from .utils import make_five_tuple, payload_bounds


@dataclass
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int = 0
    payload_offset: int = 0
    payload_length: int = 0


@dataclass
class FlowEntry:
    tuple: FiveTuple = field(default_factory=lambda: FiveTuple(0, 0, 0, 0, 0))
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


class TSQueue:
    """Thread-safe bounded queue."""

    def __init__(self, max_size: int = 10000) -> None:
        self._queue: Queue = Queue(maxsize=max_size)
        self._shutdown = False
        self._lock = threading.Lock()

    def push(self, item: Packet, timeout: float = 30.0) -> None:
        if self._shutdown:
            return
        deadline = time.monotonic() + timeout
        while not self._shutdown:
            try:
                self._queue.put(item, timeout=min(0.1, max(0, deadline - time.monotonic())))
                return
            except Full:
                if time.monotonic() >= deadline:
                    return

    def pop(self, timeout_ms: int = 100) -> Optional[Packet]:
        if self._shutdown and self._queue.empty():
            return None
        try:
            return self._queue.get(timeout=timeout_ms / 1000.0)
        except Empty:
            return None

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True

    def size(self) -> int:
        return self._queue.qsize()

    @property
    def is_shutdown(self) -> bool:
        return self._shutdown


class Stats:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self._lock = threading.Lock()
        self.app_counts: Dict[AppType, int] = defaultdict(int)
        self.detected_snis: Dict[str, AppType] = {}

    def record_app(self, app: AppType, sni: str) -> None:
        with self._lock:
            self.app_counts[app] += 1
            if sni:
                self.detected_snis[sni] = app


class FastPath:
    def __init__(
        self,
        fp_id: int,
        rules: BlockingRules,
        stats: Stats,
        output_queue: TSQueue,
    ) -> None:
        self.id = fp_id
        self._rules = rules
        self._stats = stats
        self._output_queue = output_queue
        self.input_queue = TSQueue()
        self._flows: Dict[FiveTuple, FlowEntry] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.processed = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"FP{self.id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread:
            self._thread.join()

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue.pop(100)
            if pkt is None:
                continue

            self.processed += 1
            flow = self._flows.setdefault(pkt.tuple, FlowEntry())
            if flow.packets == 0:
                flow.tuple = pkt.tuple
            flow.packets += 1
            flow.bytes += len(pkt.data)

            if not flow.classified:
                self._classify_flow(pkt, flow)

            if not flow.blocked:
                flow.blocked = self._rules.is_blocked(
                    pkt.tuple.src_ip, flow.app_type, flow.sni
                )

            self._stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self._stats.dropped += 1
            else:
                self._stats.forwarded += 1
                self._output_queue.push(pkt)

    def _classify_flow(self, pkt: Packet, flow: FlowEntry) -> None:
        if pkt.tuple.dst_port == 443 and pkt.payload_length > 5:
            payload = pkt.data[pkt.payload_offset : pkt.payload_offset + pkt.payload_length]
            sni = extract_sni(payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 80 and pkt.payload_length > 10:
            payload = pkt.data[pkt.payload_offset : pkt.payload_offset + pkt.payload_length]
            host = extract_http_host(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class LoadBalancer:
    def __init__(self, lb_id: int, fps: List[FastPath]) -> None:
        self.id = lb_id
        self._fps = fps
        self._num_fps = len(fps)
        self.input_queue = TSQueue()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.dispatched = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run, name=f"LB{self.id}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread:
            self._thread.join()

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue.pop(100)
            if pkt is None:
                continue
            fp_idx = five_tuple_hash(pkt.tuple) % self._num_fps
            self._fps[fp_idx].input_queue.push(pkt)
            self.dispatched += 1


@dataclass
class EngineConfig:
    num_lbs: int = 2
    fps_per_lb: int = 2


class DPIEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        total_fps = config.num_lbs * config.fps_per_lb

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║         DPI ENGINE v2.0 (Multi-threaded, Python)              ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(
            f"║ Load Balancers: {config.num_lbs:>2}    "
            f"FPs per LB: {config.fps_per_lb:>2}    "
            f"Total FPs: {total_fps:>2}     ║"
        )
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

        self._rules = BlockingRules()
        self._stats = Stats()
        self._output_queue = TSQueue()
        self._fps: List[FastPath] = []
        self._lbs: List[LoadBalancer] = []

        for i in range(total_fps):
            self._fps.append(FastPath(i, self._rules, self._stats, self._output_queue))

        for lb in range(config.num_lbs):
            start = lb * config.fps_per_lb
            lb_fps = self._fps[start : start + config.fps_per_lb]
            self._lbs.append(LoadBalancer(lb, lb_fps))

    def block_ip(self, ip: str) -> None:
        self._rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self._rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self._rules.block_domain(domain)

    def process(self, input_file: str, output_file: str) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        assert reader.global_header is not None
        try:
            output = Path(output_file).open("wb")
        except OSError:
            print("Cannot open output file")
            reader.close()
            return False

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

        for fp in self._fps:
            fp.start()
        for lb in self._lbs:
            lb.start()

        output_running = threading.Event()
        output_running.set()

        def output_thread() -> None:
            while output_running.is_set() or self._output_queue.size() > 0:
                pkt = self._output_queue.pop(50)
                if pkt is None:
                    continue
                output.write(
                    struct.pack(
                        "<IIII",
                        pkt.ts_sec,
                        pkt.ts_usec,
                        len(pkt.data),
                        len(pkt.data),
                    )
                )
                output.write(pkt.data)

        writer = threading.Thread(target=output_thread, name="OutputWriter", daemon=True)
        writer.start()

        print("[Reader] Processing packets...")
        pkt_id = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            parsed = parse_packet(raw)
            if parsed is None or not parsed.has_ip or (
                not parsed.has_tcp and not parsed.has_udp
            ):
                continue

            payload_offset, payload_length = payload_bounds(raw.data, parsed)

            pkt = Packet(
                id=pkt_id,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                tuple=make_five_tuple(parsed),
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=payload_offset,
                payload_length=payload_length,
            )
            pkt_id += 1

            self._stats.total_packets += 1
            self._stats.total_bytes += len(pkt.data)
            if parsed.has_tcp:
                self._stats.tcp_packets += 1
            elif parsed.has_udp:
                self._stats.udp_packets += 1

            lb_idx = five_tuple_hash(pkt.tuple) % len(self._lbs)
            self._lbs[lb_idx].input_queue.push(pkt)

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        time.sleep(0.5)

        for lb in self._lbs:
            lb.stop()
        for fp in self._fps:
            fp.stop()

        output_running.clear()
        self._output_queue.shutdown()
        writer.join(timeout=5.0)
        output.close()

        self._print_report()
        return True

    def _print_report(self) -> None:
        stats = self._stats
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {stats.total_packets:>12}                           ║")
        print(f"║ Total Bytes:        {stats.total_bytes:>12}                           ║")
        print(f"║ TCP Packets:        {stats.tcp_packets:>12}                           ║")
        print(f"║ UDP Packets:        {stats.udp_packets:>12}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Forwarded:          {stats.forwarded:>12}                           ║")
        print(f"║ Dropped:            {stats.dropped:>12}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                             ║")
        for i, lb in enumerate(self._lbs):
            print(f"║   LB{i} dispatched:   {lb.dispatched:>12}                           ║")
        for i, fp in enumerate(self._fps):
            print(f"║   FP{i} processed:    {fp.processed:>12}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        total = stats.total_packets
        sorted_apps = sorted(stats.app_counts.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = 100.0 * count / total if total else 0
            bar = "#" * int(pct / 5)
            print(
                f"║ {app_type_to_string(app):<15} {count:>8} "
                f"{pct:5.1f}% {bar:<20}  ║"
            )

        print("╚══════════════════════════════════════════════════════════════╝")

        if stats.detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in sorted(stats.detected_snis.items()):
                print(f"  - {sni} -> {app_type_to_string(app)}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DPI Engine v2.0 - Multi-threaded Deep Packet Inspection",
    )
    parser.add_argument("input_pcap", help="Input PCAP file")
    parser.add_argument("output_pcap", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOM")
    parser.add_argument("--lbs", type=int, default=2, help="Load balancer threads")
    parser.add_argument("--fps", type=int, default=2, help="Fast-path threads per LB")
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdout()
    args = build_arg_parser().parse_args(argv)
    cfg = EngineConfig(num_lbs=args.lbs, fps_per_lb=args.fps)
    engine = DPIEngine(cfg)

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for dom in args.block_domain:
        engine.block_domain(dom)

    if not engine.process(args.input_pcap, args.output_pcap):
        return 1

    print(f"\nOutput written to: {args.output_pcap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
