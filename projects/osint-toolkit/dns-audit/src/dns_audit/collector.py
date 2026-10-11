"""Zbieranie rekordow DNS domeny przez Resolver (bez interpretacji; ocena jest w analyze.py)."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .dkim import DEFAULT_SELECTORS
from .resolver import DnsAnswer, Resolver, Status
from .spf import SpfLookups, count_lookups, parse_spf, select_spf

_APEX = {
    "a": "A",
    "aaaa": "AAAA",
    "ns": "NS",
    "soa": "SOA",
    "mx": "MX",
    "txt": "TXT",
    "caa": "CAA",
    "dnskey": "DNSKEY",
    "ds": "DS",
}


@dataclass
class DomainData:
    domain: str
    a: DnsAnswer
    aaaa: DnsAnswer
    ns: DnsAnswer
    soa: DnsAnswer
    mx: DnsAnswer
    txt: DnsAnswer
    caa: DnsAnswer
    dnskey: DnsAnswer
    ds: DnsAnswer
    dmarc: DnsAnswer
    mta_sts: DnsAnswer
    tls_rpt: DnsAnswer
    bimi: DnsAnswer
    # host MX -> True (rozwiazuje sie na A/AAAA), False (brak adresu), None (blad zapytania)
    mx_hosts: dict[str, bool | None] = field(default_factory=dict)
    wildcard: dict[str, DnsAnswer] = field(default_factory=dict)
    dkim: dict[str, DnsAnswer] = field(default_factory=dict)
    dkim_control: DnsAnswer | None = None  # losowy selektor: odpowiedz oznacza wildcard
    explicit_selectors: tuple[str, ...] = ()  # selektory podane jawnie (--selectors): wildcard ich nie ukrywa
    spf_lookups: SpfLookups | None = None
    resolver_name: str = ""


def _safe(resolver: Resolver, name: str, rtype: str) -> DnsAnswer:
    try:
        return resolver.query(name, rtype)
    except Exception as exc:  # noqa: BLE001 - audyt nie moze sie wywrocic na jednym zapytaniu
        return DnsAnswer(Status.ERROR, error=f"{type(exc).__name__}: {exc}"[:200])


def merge_selectors(custom: Iterable[str] | None, use_defaults: bool = True) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    base = list(DEFAULT_SELECTORS) if use_defaults else []
    for s in [*base, *(custom or [])]:
        s = s.strip().strip(".").lower()
        if s.endswith("._domainkey"):
            s = s[: -len("._domainkey")]
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def collect(
    domain: str,
    resolver: Resolver,
    selectors: Iterable[str] | None = None,
    workers: int = 8,
    progress: Callable[[str], None] | None = None,
    explicit_selectors: Iterable[str] | None = None,
) -> DomainData:
    domain = domain.rstrip(".").lower()
    sels = list(selectors) if selectors is not None else list(DEFAULT_SELECTORS)
    control = f"dnsaudit-{secrets.token_hex(5)}"

    jobs: dict[str, tuple[str, str]] = {key: (domain, rtype) for key, rtype in _APEX.items()}
    jobs["dmarc"] = (f"_dmarc.{domain}", "TXT")
    jobs["mta_sts"] = (f"_mta-sts.{domain}", "TXT")
    jobs["tls_rpt"] = (f"_smtp._tls.{domain}", "TXT")
    jobs["bimi"] = (f"default._bimi.{domain}", "TXT")
    for s in sels:
        jobs[f"dkim:{s}"] = (f"{s}._domainkey.{domain}", "TXT")
    jobs["dkim_control"] = (f"{control}._domainkey.{domain}", "TXT")
    jobs["wildcard:A"] = (f"{control}.{domain}", "A")
    jobs["wildcard:MX"] = (f"{control}.{domain}", "MX")

    if progress:
        progress(f"{len(jobs)} zapytan DNS...")
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {k: ex.submit(_safe, resolver, name, rtype) for k, (name, rtype) in jobs.items()}
        results = {k: f.result() for k, f in futures.items()}

    data = DomainData(
        domain=domain,
        resolver_name=getattr(resolver, "description", ""),
        dkim={s: results[f"dkim:{s}"] for s in sels},
        dkim_control=results["dkim_control"],
        explicit_selectors=tuple(merge_selectors(explicit_selectors, use_defaults=False)),
        **{k: results[k] for k in (*_APEX, "dmarc", "mta_sts", "tls_rpt", "bimi")},
    )
    data.wildcard = {"A": results["wildcard:A"], "MX": results["wildcard:MX"]}

    # Hosty MX: czy sie rozwiazuja (MX wskazujacy w pustke = poczta nie dojdzie)
    hosts = []
    for rec in data.mx.records:
        parts = rec.split()
        if len(parts) >= 2:
            host = parts[1].rstrip(".").lower()
            if host and host not in hosts:
                hosts.append(host)
    if hosts:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            fa = {h: ex.submit(_safe, resolver, h, "A") for h in hosts}
            fb = {h: ex.submit(_safe, resolver, h, "AAAA") for h in hosts}
            for h in hosts:
                a, b = fa[h].result(), fb[h].result()
                if a.ok or b.ok:
                    data.mx_hosts[h] = True
                elif a.failed or b.failed:
                    data.mx_hosts[h] = None
                else:
                    data.mx_hosts[h] = False

    # SPF: rekurencyjne pobranie include/redirect
    spfs = select_spf(data.txt.records)
    if len(spfs) == 1:
        cache: dict[str, list[str] | None] = {}

        def fetch(name: str) -> list[str] | None:
            if name not in cache:
                ans = _safe(resolver, name, "TXT")
                cache[name] = None if ans.failed else list(ans.records)
            return cache[name]

        data.spf_lookups = count_lookups(domain, parse_spf(spfs[0]), fetch)
    return data
