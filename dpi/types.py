"""Core data types for the DPI engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class AppType(IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


_APP_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    return _APP_NAMES.get(app, "Unknown")


def parse_ip_string(ip: str) -> int:
    result = 0
    octet = 0
    shift = 0
    for c in ip:
        if c == ".":
            result |= octet << shift
            shift += 8
            octet = 0
        elif c.isdigit():
            octet = octet * 10 + (ord(c) - ord("0"))
    return result | (octet << shift)


def format_ip(addr: int) -> str:
    return (
        f"{addr & 0xFF}.{(addr >> 8) & 0xFF}."
        f"{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"
    )


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> FiveTuple:
        return FiveTuple(
            self.dst_ip, self.src_ip,
            self.dst_port, self.src_port,
            self.protocol,
        )

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{format_ip(self.src_ip)}:{self.src_port} -> "
            f"{format_ip(self.dst_ip)}:{self.dst_port} ({proto})"
        )


def five_tuple_hash(t: FiveTuple) -> int:
    h = 0
    for val in (t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.protocol):
        h ^= hash(val) + 0x9E3779B9 + ((h << 6) + (h >> 2))
    return h & 0xFFFFFFFFFFFFFFFF


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    if any(x in lower for x in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE
    if any(x in lower for x in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE
    if any(x in lower for x in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK
    if any(x in lower for x in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM
    if any(x in lower for x in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP
    if any(x in lower for x in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER
    if any(x in lower for x in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX
    if any(x in lower for x in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON
    if any(
        x in lower
        for x in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")
    ):
        return AppType.MICROSOFT
    if any(x in lower for x in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE
    if any(x in lower for x in ("telegram", "t.me")):
        return AppType.TELEGRAM
    if any(x in lower for x in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK
    if any(x in lower for x in ("spotify", "scdn.co")):
        return AppType.SPOTIFY
    if "zoom" in lower:
        return AppType.ZOOM
    if any(x in lower for x in ("discord", "discordapp")):
        return AppType.DISCORD
    if any(x in lower for x in ("github", "githubusercontent")):
        return AppType.GITHUB
    if any(x in lower for x in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    return AppType.HTTPS


def app_type_from_name(name: str) -> Optional[AppType]:
    for app in AppType:
        if app == AppType.APP_COUNT:
            continue
        if app_type_to_string(app) == name:
            return app
    return None
