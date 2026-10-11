"""Import JSON z dns-audit (`dns-audit domena --json`): Domain, hosty NS/MX (Domain, kind=ns_host/mx_host) i adresy IP.
Logika węzłów i krawędzi jest ta sama co w transformacji `dns_audit` (dns_result); błędy zapytań DNS zostają błędami."""
from __future__ import annotations

from ..model import Status
from ..normalize import EntityType
from ..transforms.domain import dns_result, parse_dns_audit
from .base import ImportCtx, Imported, failed, from_transform

TOOL = "dns-audit"


def detect(data) -> bool:
    return isinstance(data, dict) and isinstance(data.get("summary"), dict) and isinstance(data.get("domain"), str)


def parse(data, ctx: ImportCtx) -> Imported:
    reports = data if isinstance(data, list) else [data]
    imp = Imported(TOOL)
    for report in reports:
        raw = report.get("domain") if isinstance(report, dict) else None
        try:
            node = ctx.node(EntityType.DOMAIN, str(raw))
        except ValueError as exc:
            imp.runs.append((str(raw)[:60], Status.ERROR, f"nieprawidłowa domena: {exc}"))
            continue
        parsed = parse_dns_audit(report)
        if parsed is None:
            imp.runs.append((node.id, Status.ERROR, "dns-audit: brak sekcji summary"))
            continue
        res = dns_result(node, parsed, ctx)
        from_transform(imp, ctx, node, res, node.id)
    return imp if imp.runs else failed(TOOL, "pusta lista raportów dns-audit")
