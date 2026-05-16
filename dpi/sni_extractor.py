"""TLS SNI, HTTP Host, and DNS extractors."""

from __future__ import annotations

from typing import Optional

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _read_uint16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_uint24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    if len(payload) < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False
    version = _read_uint16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False
    record_length = _read_uint16_be(payload, 3)
    if record_length > len(payload) - 5:
        return False
    if payload[5] != HANDSHAKE_CLIENT_HELLO:
        return False
    return True


def extract_sni(payload: bytes) -> Optional[str]:
    if not is_tls_client_hello(payload):
        return None

    offset = 5
    offset += 4  # handshake header (type + 3-byte length)

    offset += 2   # client version
    offset += 32  # random

    if offset >= len(payload):
        return None

    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > len(payload):
        return None
    cipher_suites_length = _read_uint16_be(payload, offset)
    offset += 2 + cipher_suites_length

    if offset >= len(payload):
        return None
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length

    if offset + 2 > len(payload):
        return None
    extensions_length = _read_uint16_be(payload, offset)
    offset += 2

    extensions_end = min(offset + extensions_length, len(payload))

    while offset + 4 <= extensions_end:
        extension_type = _read_uint16_be(payload, offset)
        extension_length = _read_uint16_be(payload, offset + 2)
        offset += 4

        if offset + extension_length > extensions_end:
            break

        if extension_type == EXTENSION_SNI and extension_length >= 5:
            sni_list_length = _read_uint16_be(payload, offset)
            if sni_list_length < 3:
                break
            sni_type = payload[offset + 2]
            sni_length = _read_uint16_be(payload, offset + 3)
            if sni_type != SNI_TYPE_HOSTNAME:
                break
            if sni_length > extension_length - 5:
                break
            return payload[offset + 5 : offset + 5 + sni_length].decode(
                "ascii", errors="replace"
            )

        offset += extension_length

    return None


def is_http_request(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
    return any(payload[:4] == m for m in methods)


def extract_http_host(payload: bytes) -> Optional[str]:
    if not is_http_request(payload):
        return None

    length = len(payload)
    i = 0
    while i + 5 < length:
        if (
            payload[i] in (ord("H"), ord("h"))
            and payload[i + 1] in (ord("o"), ord("O"))
            and payload[i + 2] in (ord("s"), ord("S"))
            and payload[i + 3] in (ord("t"), ord("T"))
            and payload[i + 4] == ord(":")
        ):
            start = i + 5
            while start < length and payload[start] in (ord(" "), ord("\t")):
                start += 1
            end = start
            while end < length and payload[end] not in (ord("\r"), ord("\n")):
                end += 1
            if end > start:
                host = payload[start:end].decode("ascii", errors="replace")
                colon = host.find(":")
                if colon != -1:
                    host = host[:colon]
                return host
        i += 1
    return None


def is_dns_query(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    if payload[2] & 0x80:
        return False
    qdcount = (payload[4] << 8) | payload[5]
    return qdcount > 0


def extract_dns_query(payload: bytes) -> Optional[str]:
    if not is_dns_query(payload):
        return None

    offset = 12
    domain_parts: list[str] = []
    length = len(payload)

    while offset < length:
        label_length = payload[offset]
        if label_length == 0:
            break
        if label_length > 63:
            break
        offset += 1
        if offset + label_length > length:
            break
        domain_parts.append(
            payload[offset : offset + label_length].decode("ascii", errors="replace")
        )
        offset += label_length

    return ".".join(domain_parts) if domain_parts else None
