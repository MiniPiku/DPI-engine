"""Structured processing report for API / web UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AppBreakdown:
    name: str
    count: int
    percent: float


@dataclass
class SniEntry:
    domain: str
    app: str


@dataclass
class ThreadStat:
    id: int
    label: str
    value: int


@dataclass
class ProcessingReport:
    success: bool
    mode: str
    output_file: str
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    forwarded: int = 0
    dropped: int = 0
    active_flows: int = 0
    apps: List[AppBreakdown] = field(default_factory=list)
    snis: List[SniEntry] = field(default_factory=list)
    threads: List[ThreadStat] = field(default_factory=list)
    config: Optional[Dict[str, int]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
