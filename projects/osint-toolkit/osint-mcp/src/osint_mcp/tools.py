"""Logika narzędzi MCP: walidacja wejścia + argumenty podprocesu. Bez zależności od MCP (łatwe testy offline)."""

from __future__ import annotations

import subprocess
from typing import Callable

from .runner import run_module, valid_domain, valid_ip, valid_phone, valid_region

Run = Callable[..., subprocess.CompletedProcess]


def _as_dict(result: object) -> dict:
    """Narzędzia MCP zwracają obiekt JSON; ewentualną listę opakowujemy."""
    return result if isinstance(result, dict) else {"result": result}


def dns_audit(domain: str, *, run: Run | None = None) -> dict:
    d = valid_domain(domain)
    return _as_dict(run_module("dns-audit", [d, "--json"], 120, run=run))


def phone_check(number: str, region: str = "PL", *, run: Run | None = None) -> dict:
    n, r = valid_phone(number), valid_region(region)
    result = run_module("phone-check", [n, "--region", r], 30, json_file="phone.json", run=run)
    # phone-check zapisuje listę (po jednym wpisie na numer); tu zawsze jeden numer
    if isinstance(result, list) and len(result) == 1:
        result = result[0]
    return _as_dict(result)


def hibp_domain_breaches(domain: str, *, run: Run | None = None) -> dict:
    d = valid_domain(domain)
    return _as_dict(run_module("hibp-monitor", ["breaches", "--domain", d, "--no-save", "--json"], 90, run=run))


def ip_info(ip: str, *, run: Run | None = None) -> dict:
    return _as_dict(run_module("net-intel", ["ip", valid_ip(ip), "--json"], 60, run=run))


def rdap(domain: str, *, run: Run | None = None) -> dict:
    return _as_dict(run_module("net-intel", ["rdap", valid_domain(domain), "--json"], 90, run=run))


def subdomains(domain: str, *, run: Run | None = None) -> dict:
    return _as_dict(run_module("net-intel", ["subdomains", valid_domain(domain), "--json"], 150, run=run))
