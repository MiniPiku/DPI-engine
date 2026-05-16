"""PCAP file reader."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

GLOBAL_HEADER_FMT = "<IHHIIII"
PACKET_HEADER_FMT = "<IIII"
GLOBAL_HEADER_SIZE = struct.calcsize(GLOBAL_HEADER_FMT)
PACKET_HEADER_SIZE = struct.calcsize(PACKET_HEADER_FMT)


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self._needs_byte_swap = False

    def open(self, filename: str | Path) -> bool:
        self.close()
        path = Path(filename)
        try:
            self._file = path.open("rb")
        except OSError as exc:
            print(f"Error: Could not open file: {path} ({exc})")
            return False

        raw = self._file.read(GLOBAL_HEADER_SIZE)
        if len(raw) < GLOBAL_HEADER_SIZE:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        magic, vmaj, vmin, thiszone, sigfigs, snaplen, network = struct.unpack(
            GLOBAL_HEADER_FMT, raw
        )

        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            vmaj, vmin, snaplen, network = self._swap_after_read(vmaj, vmin, snaplen, network)
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08x}")
            self.close()
            return False

        self.global_header = PcapGlobalHeader(
            magic, vmaj, vmin, thiszone, sigfigs, snaplen, network
        )

        print(f"Opened PCAP file: {path}")
        print(f"  Version: {vmaj}.{vmin}")
        print(f"  Snaplen: {snaplen} bytes")
        link = " (Ethernet)" if network == 1 else ""
        print(f"  Link type: {network}{link}")
        return True

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._needs_byte_swap = False

    def read_next_packet(self) -> Optional[RawPacket]:
        if self._file is None or self.global_header is None:
            return None

        raw_hdr = self._file.read(PACKET_HEADER_SIZE)
        if len(raw_hdr) < PACKET_HEADER_SIZE:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(PACKET_HEADER_FMT, raw_hdr)
        if self._needs_byte_swap:
            ts_sec, ts_usec, incl_len, orig_len = self._swap_after_read(
                ts_sec, ts_usec, incl_len, orig_len
            )

        snaplen = self.global_header.snaplen
        if incl_len > snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data")
            return None

        header = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)
        return RawPacket(header, data)

    @staticmethod
    def _swap16(value: int) -> int:
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)

    @staticmethod
    def _swap32(value: int) -> int:
        return (
            ((value & 0xFF000000) >> 24)
            | ((value & 0x00FF0000) >> 8)
            | ((value & 0x0000FF00) << 8)
            | ((value & 0x000000FF) << 24)
        )

    def _swap_after_read(self, *values: int) -> tuple:
        out = []
        for v in values:
            if v > 0xFFFF:
                out.append(self._swap32(v))
            else:
                out.append(self._swap16(v))
        return tuple(out)
