"""Network protocol packet parser."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .pcap_reader import RawPacket
from .types import format_ip

ETH_HEADER_LEN = 14
MIN_IP_HEADER_LEN = 20
MIN_TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

ETHERTYPE_IPV4 = 0x0800

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_length: int = 0
    payload_offset: int = 0


def _mac_to_string(data: bytes, offset: int = 0) -> str:
    return ":".join(f"{data[offset + i]:02x}" for i in range(6))


def _read_uint16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_uint32_be(data: bytes, offset: int) -> int:
    return struct.unpack(">I", data[offset : offset + 4])[0]


def parse_packet(raw: RawPacket) -> Optional[ParsedPacket]:
    parsed = ParsedPacket(
        timestamp_sec=raw.header.ts_sec,
        timestamp_usec=raw.header.ts_usec,
    )
    data = raw.data
    length = len(data)
    offset = 0

    if length < ETH_HEADER_LEN:
        return None

    parsed.dest_mac = _mac_to_string(data, 0)
    parsed.src_mac = _mac_to_string(data, 6)
    parsed.ether_type = _read_uint16_be(data, 12)
    offset = ETH_HEADER_LEN

    if parsed.ether_type != ETHERTYPE_IPV4:
        parsed.payload_offset = offset
        parsed.payload_length = max(0, length - offset)
        return parsed

    if length < offset + MIN_IP_HEADER_LEN:
        return None

    ip_data = data[offset:]
    version_ihl = ip_data[0]
    parsed.ip_version = (version_ihl >> 4) & 0x0F
    ihl = version_ihl & 0x0F

    if parsed.ip_version != 4:
        return None

    ip_header_len = ihl * 4
    if ip_header_len < MIN_IP_HEADER_LEN or length < offset + ip_header_len:
        return None

    parsed.ttl = ip_data[8]
    parsed.protocol = ip_data[9]
    parsed.src_ip = format_ip(struct.unpack("<I", ip_data[12:16])[0])
    parsed.dest_ip = format_ip(struct.unpack("<I", ip_data[16:20])[0])
    parsed.has_ip = True
    offset += ip_header_len

    if parsed.protocol == PROTO_TCP:
        if length < offset + MIN_TCP_HEADER_LEN:
            return None
        tcp_data = data[offset:]
        parsed.src_port = _read_uint16_be(tcp_data, 0)
        parsed.dest_port = _read_uint16_be(tcp_data, 2)
        parsed.seq_number = _read_uint32_be(tcp_data, 4)
        parsed.ack_number = _read_uint32_be(tcp_data, 8)
        data_offset = (tcp_data[12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4
        parsed.tcp_flags = tcp_data[13]
        if tcp_header_len < MIN_TCP_HEADER_LEN or length < offset + tcp_header_len:
            return None
        parsed.has_tcp = True
        offset += tcp_header_len

    elif parsed.protocol == PROTO_UDP:
        if length < offset + UDP_HEADER_LEN:
            return None
        udp_data = data[offset:]
        parsed.src_port = _read_uint16_be(udp_data, 0)
        parsed.dest_port = _read_uint16_be(udp_data, 2)
        parsed.has_udp = True
        offset += UDP_HEADER_LEN

    parsed.payload_offset = offset
    parsed.payload_length = max(0, length - offset)
    return parsed


def tcp_flags_to_string(flags: int) -> str:
    names = []
    if flags & TCP_SYN:
        names.append("SYN")
    if flags & TCP_ACK:
        names.append("ACK")
    if flags & TCP_FIN:
        names.append("FIN")
    if flags & TCP_RST:
        names.append("RST")
    if flags & TCP_PSH:
        names.append("PSH")
    if flags & TCP_URG:
        names.append("URG")
    return " ".join(names) if names else "none"


def protocol_to_string(protocol: int) -> str:
    if protocol == PROTO_ICMP:
        return "ICMP"
    if protocol == PROTO_TCP:
        return "TCP"
    if protocol == PROTO_UDP:
        return "UDP"
    return f"Unknown({protocol})"
