"""Zbieranie danych: strona glowna (z przekierowaniami), sonda HTTP, robots.txt, security.txt, sitemap.

Ruch do celu jest jak przy zwyklym otwarciu strony: kilka zadan GET, bez skanowania portow,
bez wysylania formularzy, bez JavaScriptu. Wszystko w obrebie hosta koncowego.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .fetch import Fetcher, FetchResult
from .parsers import parse_robots
from .target import Target, TargetError, parse_target

SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")


@dataclass
class SiteData:
    target: Target
    main: FetchResult
    http_probe: FetchResult | None = None
    robots: FetchResult | None = None
    security_txt: FetchResult | None = None
    sitemap: FetchResult | None = None
    sitemap_url: str | None = None
    notes: list[str] = field(default_factory=list)
    requests: int = 0

    @property
    def final(self) -> Target | None:
        if self.main.response is None:
            return None
        try:
            return parse_target(self.main.response.url)
        except TargetError:
            return None


def collect(target: Target, fetcher: Fetcher, extras: bool = True,
            progress: Callable[[str], None] | None = None) -> SiteData:
    say = progress or (lambda _m: None)
    say(f"Pobieram {target.url} ...")
    data = SiteData(target, fetcher.get(target))
    if data.main.error_kind in ("blocked", "invalid"):
        data.requests = fetcher.requests
        return data

    if target.scheme == "https" and target.default_port:
        say("Sprawdzam, czy http:// przekierowuje na https:// ...")
        data.http_probe = fetcher.get(target.with_scheme("http").with_path("/"), follow=False)

    final = data.final
    if extras and final is not None:
        base = final.with_path("/")
        scope = in_scope(final)
        say("robots.txt, security.txt, sitemap ...")
        data.robots = fetcher.get(base.with_path("/robots.txt"), scope=scope)
        for path in SECURITY_TXT_PATHS:
            res = fetcher.get(base.with_path(path), scope=scope)
            data.security_txt = res
            if res.response is not None and res.response.status == 200:
                break
        data.sitemap_url = _pick_sitemap(data.robots, final, data.notes)
        data.sitemap = fetcher.get(data.sitemap_url, scope=scope)
    data.requests = fetcher.requests
    return data


def in_scope(final: Target):
    """Pliki pomocnicze tylko z hosta koncowego: ten sam origin albo podniesienie do https:443.

    Sprawdzane przed kazdym zadaniem i kazdym skokiem, wiec obcy host nie dostaje ani jednego zadania.
    """
    def check(t: Target) -> bool:
        if t.host != final.host:
            return False
        return (t.scheme, t.port) == (final.scheme, final.port) or (t.scheme == "https" and t.port == 443)
    return check


def _pick_sitemap(robots: FetchResult | None, final: Target, notes: list[str]) -> str:
    default = final.with_path("/sitemap.xml").url
    if robots is None or robots.response is None or robots.response.status != 200:
        return default
    for url in parse_robots(robots.response.text()).sitemaps:
        try:
            t = parse_target(url)
        except TargetError:
            continue
        if in_scope(final)(t):
            return t.url
        notes.append(f"sitemap z robots.txt poza audytowanym hostem pominięta: {url}")
    return default
