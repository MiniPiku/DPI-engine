"""Blocking rules for the DPI engine."""

from __future__ import annotations

import threading
from typing import List, Set

from .types import AppType, app_type_from_name, app_type_to_string, parse_ip_string


class BlockingRules:
    def __init__(self) -> None:
        self._blocked_ips: Set[int] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: List[str] = []
        self._mutex = threading.Lock()

    def block_ip(self, ip: str) -> None:
        with self._mutex:
            self._blocked_ips.add(parse_ip_string(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        found = app_type_from_name(app)
        if found is None:
            print(f"[Rules] Unknown app: {app}")
            return
        with self._mutex:
            self._blocked_apps.add(found)
        print(f"[Rules] Blocked app: {app}")

    def block_domain(self, domain: str) -> None:
        with self._mutex:
            self._blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        with self._mutex:
            if src_ip in self._blocked_ips:
                return True
            if app in self._blocked_apps:
                return True
            for dom in self._blocked_domains:
                if dom in sni:
                    return True
        return False


def list_app_names() -> List[str]:
    return [
        app_type_to_string(app)
        for app in AppType
        if app != AppType.APP_COUNT
    ]
