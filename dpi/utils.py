"""Shared helpers for DPI processing."""

from __future__ import annotations

from .packet_parser import ParsedPacket
from .types import FiveTuple, parse_ip_string


def make_five_tuple(parsed: ParsedPacket) -> FiveTuple:
    return FiveTuple(
        src_ip=parse_ip_string(parsed.src_ip),
        dst_ip=parse_ip_string(parsed.dest_ip),
        src_port=parsed.src_port,
        dst_port=parsed.dest_port,
        protocol=parsed.protocol,
    )


def payload_bounds(data: bytes, parsed: ParsedPacket) -> tuple[int, int]:
    """Return (payload_offset, payload_length) within packet data."""
    if parsed.payload_length > 0:
        return parsed.payload_offset, parsed.payload_length

    offset = 14
    if len(data) <= offset:
        return 0, 0

    ip_ihl = data[offset] & 0x0F
    offset += ip_ihl * 4

    if parsed.has_tcp and offset + 12 < len(data):
        tcp_off = (data[offset + 12] >> 4) & 0x0F
        offset += tcp_off * 4
    elif parsed.has_udp:
        offset += 8

    if offset >= len(data):
        return 0, 0
    return offset, len(data) - offset
