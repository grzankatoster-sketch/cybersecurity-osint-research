"""Raport: podsumowanie zebranych danych oraz render tekstowy, JSON i HTML."""

from __future__ import annotations

import html
import json
import shutil
import textwrap
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .analyze import (
    kv_record, mx_provider, parse_caa, parse_dnskey_algorithms, parse_mx, parse_soa,
    scan_dkim, select_records, status_note, zone_ad,
)
from .collector import DomainData
from .dmarc import is_dmarc, parse_dmarc
from .models import Finding, Severity
from .spf import DNS_LOOKUP_LIMIT, parse_spf, select_spf
from .verification import detect_verifications, is_email_auth


@dataclass
class Report:
    domain: str
    resolver: str
    generated: str
    summary: dict
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "tool": f"dns-audit {__version__}",
            "domain": self.domain,
            "resolver": self.resolver,
            "generated": self.generated,
            "counts": self.counts,
            "summary": self.summary,
            "findings": [
                {"severity": f.severity.value, "area": f.area, "title": f.title, "recommendation": f.recommendation}
                for f in self.findings
            ],
        }


def build_report(data: DomainData, findings: list[Finding]) -> Report:
    return Report(
        domain=data.domain,
        resolver=data.resolver_name or "systemowy",
        generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        summary=summarize(data),
        findings=findings,
    )


def _rec(ans) -> list[str]:
    return sorted(r.rstrip(".") if not r.startswith("v=") else r for r in ans.records)


def _first_tags(ans, kind: str) -> dict | None:
    recs = select_records(ans, kind)  # ten sam selektor co w analyze.py
    return (kv_record(recs[0]) if recs else None) or None


def summarize(d: DomainData) -> dict:
    mx = parse_mx(d.mx.records)
    spfs = select_spf(d.txt.records)
    spf = None
    if spfs:
        rec = parse_spf(spfs[0])
        lk = d.spf_lookups
        spf = {
            "raw": rec.raw,
            "records": len(spfs),
            "all": (lk.effective_all if lk else rec.all_qualifier),
            "lookups": lk.count if lk else None,
            "lookup_limit": DNS_LOOKUP_LIMIT,
            "includes": lk.includes if lk else [t.value for t in rec.terms if t.mechanism == "include"],
            "errors": rec.errors + (lk.errors if lk else []),
        }
    dm_raw = [r for r in d.dmarc.records if is_dmarc(r)]
    dmarc = None
    if dm_raw:
        dm = parse_dmarc(dm_raw[0])
        dmarc = {"raw": dm.raw, "p": dm.p, "sp": dm.sp, "pct": dm.pct, "rua": dm.rua, "ruf": dm.ruf,
                 "adkim": dm.adkim, "aspf": dm.aspf, "errors": dm.errors}
    scan = scan_dkim(d)
    dkim = [{"selector": sel, "key_type": k.key_type, "key_bits": k.key_bits, "revoked": k.revoked,
             "testing": k.testing, "valid": k.valid, "errors": k.errors} for sel, k in scan.keys.items()]
    wildcard = scan.wildcard
    ver = detect_verifications(d.txt.records)
    # Odpowiedzi, ktorych nie udalo sie uzyskac: "nie udalo sie sprawdzic" to nie to samo co "nie znaleziono"
    failed = {key: status_note(ans) for key, ans in (
        ("a", d.a), ("aaaa", d.aaaa), ("ns", d.ns), ("soa", d.soa), ("mx", d.mx), ("txt", d.txt), ("caa", d.caa),
        ("dnskey", d.dnskey), ("ds", d.ds), ("dmarc", d.dmarc), ("mta_sts", d.mta_sts), ("tls_rpt", d.tls_rpt),
        ("bimi", d.bimi),
    ) if ans.failed}
    if d.dkim and len(scan.failed) == len(d.dkim):
        failed["dkim"] = f"{len(scan.failed)} selektorów"
    return {
        "a": _rec(d.a), "aaaa": _rec(d.aaaa), "ns": _rec(d.ns),
        "soa": parse_soa(d.soa.records),
        "mx": [{"priority": p, "host": h, "provider": mx_provider(h)} for p, h in mx],
        "txt": list(d.txt.records),
        "caa": [{"tag": t, "value": v} for t, v in parse_caa(d.caa.records)],
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "dkim_selectors_checked": len(d.dkim),
        "dkim_selectors_failed": len(scan.failed),
        "dkim_wildcard": wildcard,
        "dnssec": {
            "dnskey": len(d.dnskey.records), "ds": len(d.ds.records),
            "algorithms": sorted(set(parse_dnskey_algorithms(d.dnskey.records))),
            "ad_flag": zone_ad(d),
        },
        "mta_sts": _first_tags(d.mta_sts, "mta_sts"),
        "tls_rpt": _first_tags(d.tls_rpt, "tls_rpt"),
        "bimi": _first_tags(d.bimi, "bimi"),
        "verifications": [{"service": v.service, "category": v.category, "record": v.record} for v in ver],
        "other_txt": [r for r in d.txt.records
                      if not is_email_auth(r) and not any(v.record == r.strip() for v in ver)],
        "failed": failed,
    }


_UNCHECKED = "nie udało się sprawdzić"


def summary_rows(s: dict) -> list[tuple[str, str]]:
    """Wiersze 'etykieta: wartosc' wspolne dla tekstu i HTML."""
    failed = s.get("failed", {})

    def miss(*keys: str) -> str | None:
        bad = [f"{k.upper()}: {failed[k]}" for k in keys if k in failed]
        return f"{_UNCHECKED} ({'; '.join(bad)})" if bad else None

    rows: list[tuple[str, str]] = []
    rows.append(("A", miss("a") or ", ".join(s["a"]) or "-"))
    rows.append(("AAAA", miss("aaaa") or ", ".join(s["aaaa"]) or "-"))
    rows.append(("NS", miss("ns") or ", ".join(s["ns"]) or "-"))
    soa = s["soa"]
    rows.append(("SOA", miss("soa") or (f"{soa['mname']} serial={soa['serial']} refresh={soa['refresh']} expire={soa['expire']}" if soa else "-")))
    mx = s["mx"]
    rows.append(("MX", miss("mx") or "; ".join(f"{m['priority']} {m['host'] or '.'}" + (f" [{m['provider']}]" if m["provider"] else "") for m in mx) or "-"))
    spf = s["spf"]
    if spf:
        lk = f"{spf['lookups']}/{spf['lookup_limit']}" if spf["lookups"] is not None else "?"
        rows.append(("SPF", f"{spf['raw']}  [lookupy: {lk}, all: {spf['all'] or 'brak'}]"))
    else:
        rows.append(("SPF", miss("txt") or "-"))
    dm = s["dmarc"]
    rows.append(("DMARC", miss("dmarc") or (f"{dm['raw']}" if dm else "-")))
    nsel, nfail = s["dkim_selectors_checked"], s.get("dkim_selectors_failed", 0)
    if s["dkim_wildcard"]:
        text = "wildcard na _domainkey (sondowanie selektorów niewiarygodne)"
        if s["dkim"]:
            text += "; jawne/różne od wildcard: " + ", ".join(k["selector"] for k in s["dkim"])
        rows.append(("DKIM", text))
    elif s["dkim"]:
        parts = []
        for k in s["dkim"]:
            desc = "unieważniony" if k["revoked"] else (f"{k['key_type'].upper()} {k['key_bits']}" if k["key_bits"] else k["key_type"].upper())
            if k.get("errors"):
                desc += ", błąd klucza"
            parts.append(f"{k['selector']} ({desc})")
        text = ", ".join(parts)
        if nfail:
            text += f"; nie udało się sprawdzić {nfail} z {nsel} selektorów"
        rows.append(("DKIM", text))
    elif "dkim" in failed:
        rows.append(("DKIM", f"{_UNCHECKED} ({failed['dkim']})"))
    else:
        text = f"nie znaleziono ({nsel} selektorów)"
        if nfail:
            text += f"; nie udało się sprawdzić {nfail} z nich"
        rows.append(("DKIM", text))
    ds = s["dnssec"]
    rows.append(("DNSSEC", miss("dnskey", "ds") or f"DNSKEY={ds['dnskey']}, DS={ds['ds']}, AD={'tak' if ds['ad_flag'] else 'nie'}"))
    rows.append(("CAA", miss("caa") or "; ".join(f"{c['tag']} {c['value']}" for c in s["caa"]) or "-"))
    rows.append(("MTA-STS", miss("mta_sts") or (" ".join(f"{k}={v}" for k, v in s["mta_sts"].items()) if s["mta_sts"] else "-")))
    rows.append(("TLS-RPT", miss("tls_rpt") or (" ".join(f"{k}={v}" for k, v in s["tls_rpt"].items()) if s["tls_rpt"] else "-")))
    rows.append(("BIMI", miss("bimi") or (" ".join(f"{k}={v}" for k, v in s["bimi"].items()) if s["bimi"] else "-")))
    ver = s["verifications"]
    if ver:
        rows.append(("Weryfikacje", "; ".join(sorted({f"{v['service']}" for v in ver}))))
    else:
        rows.append(("Weryfikacje", miss("txt") or "-"))
    if s["other_txt"]:
        rows.append(("Inne TXT", " | ".join(s["other_txt"])))
    return rows


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -f.severity.rank)  # stabilne: kolejnosc obszarow zachowana


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def printable(text: str) -> str:
    """Znaki sterujace (Unicode Cc poza nowa linia i tabulatorem, m.in. ESC) -> widoczne \\xNN.

    Niezaufane rekordy TXT nie moga sterowac terminalem (czyszczenie ekranu, sekwencje ESC).
    """
    return "".join(
        c if c in "\n\t" or unicodedata.category(c) != "Cc" else f"\\x{ord(c):02x}"
        for c in text
    )


def render_text(report: Report, width: int | None = None) -> str:
    width = width or min(max(shutil.get_terminal_size((100, 24)).columns, 80), 120)
    out: list[str] = []
    out.append(printable(f"AUDYT DNS I POCZTY: {report.domain}"))
    out.append(printable(f"Resolver: {report.resolver} | {report.generated}"))
    out.append("=" * width)
    out.append("ZEBRANE DANE")
    for label, value in summary_rows(report.summary):
        wrapped = textwrap.wrap(printable(value), width - 14, subsequent_indent="") or ["-"]
        out.append(f"{label:<12}{wrapped[0]}")
        for line in wrapped[1:]:
            out.append(" " * 12 + line)
    out.append("")
    out.append("USTALENIA")
    out.append(f"{'WAGA':<5} {'OBSZAR':<8} USTALENIE")
    out.append("-" * width)
    for f in _sorted_findings(report.findings):
        lines = textwrap.wrap(printable(f.title), width - 15) or [""]
        out.append(f"{f.severity.value:<5} {f.area:<8} {lines[0]}")
        out.extend(" " * 15 + line for line in lines[1:])
        if f.recommendation:
            for i, line in enumerate(textwrap.wrap(printable(f.recommendation), width - 18)):
                out.append(" " * 15 + ("-> " if i == 0 else "   ") + line)
    out.append("-" * width)
    c = report.counts
    out.append(f"Podsumowanie: FAIL {c['FAIL']} | WARN {c['WARN']} | INFO {c['INFO']} | OK {c['OK']}")
    return "\n".join(out)


_HTML_STYLE = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6570;--line:#d8dee4;--ok:#1a7f37;--info:#0969da;--warn:#9a6700;--fail:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--ok:#3fb950;--info:#58a6ff;--warn:#d29922;--fail:#f85149}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif;margin:0 auto;max-width:1000px;padding:24px 16px}
h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.05rem;margin:28px 0 8px}
.meta{color:var(--muted);margin-bottom:16px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}.k{white-space:nowrap;color:var(--muted);width:1%}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:.9em;word-break:break-all}
.sev{font-weight:700;white-space:nowrap}.OK{color:var(--ok)}.INFO{color:var(--info)}.WARN{color:var(--warn)}.FAIL{color:var(--fail)}
.rec{color:var(--muted);display:block;margin-top:2px}
.sum span{display:inline-block;margin-right:16px;font-weight:600}
"""


def render_html(report: Report) -> str:
    e = html.escape
    parts = [
        "<!doctype html><html lang=\"pl\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>Audyt DNS {e(report.domain)}</title><style>{_HTML_STYLE}</style></head><body>",
        f"<h1>Audyt DNS i poczty: {e(report.domain)}</h1>",
        f"<div class=\"meta\">Resolver: {e(report.resolver)} &middot; {e(report.generated)} &middot; dns-audit {__version__}</div>",
    ]
    c = report.counts
    parts.append("<div class=\"sum\">" + "".join(
        f"<span class=\"{k}\">{k} {c[k]}</span>" for k in ("FAIL", "WARN", "INFO", "OK")) + "</div>")
    parts.append("<h2>Ustalenia</h2><table><tr><th>Waga</th><th>Obszar</th><th>Ustalenie i zalecenie</th></tr>")
    for f in _sorted_findings(report.findings):
        rec = f"<span class=\"rec\">Zalecenie: {e(f.recommendation)}</span>" if f.recommendation else ""
        parts.append(
            f"<tr><td class=\"sev {f.severity.value}\">{f.severity.value}</td><td>{e(f.area)}</td>"
            f"<td>{e(f.title)}{rec}</td></tr>")
    parts.append("</table><h2>Zebrane dane</h2><table>")
    for label, value in summary_rows(report.summary):
        parts.append(f"<tr><td class=\"k\">{e(label)}</td><td class=\"mono\">{e(value)}</td></tr>")
    parts.append("</table>")
    ver = report.summary["verifications"]
    if ver:
        parts.append("<h2>Rekordy weryfikacyjne</h2><table><tr><th>Usługa</th><th>Kategoria</th><th>Rekord</th></tr>")
        for v in ver:
            parts.append(f"<tr><td>{e(v['service'])}</td><td>{e(v['category'])}</td><td class=\"mono\">{e(v['record'])}</td></tr>")
        parts.append("</table>")
    parts.append("</body></html>")
    return "".join(parts)
