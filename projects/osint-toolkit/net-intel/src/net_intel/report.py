"""Raport: budowa z wyników poszczególnych podkomend oraz render tekstowy, JSON i HTML."""

from __future__ import annotations

import html
import json
import shutil
import textwrap
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .ipinfo import IpInfo, Rdns
from .models import Finding, Severity
from .rdap import RdapResult, evaluate
from .subdomains import SubdomainResult

UNCHECKED = "nie udało się sprawdzić"


@dataclass
class Section:
    title: str
    rows: list[tuple[str, str]] = field(default_factory=list)       # tryb "etykieta: wartość"
    headers: list[str] = field(default_factory=list)                # tryb tabeli
    table: list[list[str]] = field(default_factory=list)


@dataclass
class Report:
    command: str                 # ip | rdap | subdomains
    subject: str
    title: str
    status: str                  # ok | partial | failed
    headline: str
    data: dict
    sections: list[Section] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    generated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    @property
    def exit_code(self) -> int:
        c = self.counts
        return 1 if self.status == "failed" or c["WARN"] or c["FAIL"] else 0

    def to_dict(self) -> dict:
        return {
            "tool": f"net-intel {__version__}",
            "command": self.command,
            "subject": self.subject,
            "generated": self.generated,
            "status": self.status,
            "headline": self.headline,
            "counts": self.counts,
            "result": self.data,
            "findings": [
                {"severity": f.severity.value, "area": f.area, "title": f.title, "recommendation": f.recommendation}
                for f in self.findings
            ],
        }


def _v(value) -> str:
    return "-" if value is None or value == "" else str(value)


# --- ip ---------------------------------------------------------------------------------------

def build_ip_report(ip: str, scope_note: str | None, info: IpInfo | None, info_error: str,
                    rdns: Rdns | None) -> Report:
    findings: list[Finding] = []
    data: dict = {"ip": ip, "scope": "local" if scope_note else "public"}
    sections: list[Section] = []
    if scope_note:
        data.update(local_reason=scope_note, ipinfo=None, reverse_dns=None)
        findings.append(Finding("IP", Severity.INFO, scope_note))
        sections.append(Section("Adres", rows=[("IP", ip), ("Zakres", scope_note)]))
        return Report("ip", ip, f"Adres IP: {ip}", "ok", "adres lokalny, nie pytano żadnego źródła", data,
                      sections, findings)

    rows: list[tuple[str, str]] = [("IP", ip)]
    if info is not None:
        asn_txt = " ".join(x for x in (info.asn, info.org_name) if x) or None
        rows += [("ASN / organizacja", _v(asn_txt)), ("Hostname (ipinfo)", _v(info.hostname)),
                 ("Miasto", _v(info.city)), ("Region", _v(info.region)), ("Kraj", _v(info.country)),
                 ("Strefa czasowa", _v(info.timezone)),
                 ("Anycast", "tak" if info.anycast else ("nie" if info.anycast is False else "-")),
                 ("Bogon", "tak" if info.bogon else "nie")]
        data["ipinfo"] = info.to_dict()
        if info.bogon:
            findings.append(Finding("IP", Severity.INFO, "ipinfo.io oznacza adres jako bogon (nie jest routowalny publicznie)"))
        if info.anycast:
            findings.append(Finding("IP", Severity.INFO, "adres anycast: lokalizacja nie wskazuje jednego serwera"))
    else:
        rows.append(("ipinfo.io", f"{UNCHECKED} ({info_error})"))
        data["ipinfo"] = None
        data["ipinfo_error"] = info_error
    if rdns is not None:
        if rdns.status == "ok":
            rows.append(("PTR (DNS)", ", ".join(rdns.names)))
        elif rdns.status == "none":
            rows.append(("PTR (DNS)", "brak rekordu PTR"))
            findings.append(Finding("DNS", Severity.INFO, "adres nie ma rekordu PTR (odwrotnego DNS)"))
        else:
            rows.append(("PTR (DNS)", f"{UNCHECKED} ({rdns.error})"))
        data["reverse_dns"] = {"status": rdns.status, "names": rdns.names, "error": rdns.error or None}
    sections.append(Section("Adres", rows=rows))

    info_ok = info is not None
    rdns_ok = rdns is not None and rdns.status != "error"
    if not info_ok and not rdns_ok:
        status, headline = "failed", f"{UNCHECKED} (wszystkie źródła zawiodły)"
        findings.append(Finding("IP", Severity.FAIL, f"{UNCHECKED}: ipinfo.io ({info_error}); PTR ({rdns.error if rdns else '-'})",
                                "Sprawdź połączenie z internetem i spróbuj ponownie."))
    elif not info_ok or not rdns_ok:
        status = "partial"
        headline = "wynik niepełny: jedno ze źródeł zawiodło"
        what = f"ipinfo.io ({info_error})" if not info_ok else f"PTR ({rdns.error})"  # type: ignore[union-attr]
        findings.append(Finding("IP", Severity.INFO, f"{UNCHECKED}: {what}; pozostałe dane pochodzą z drugiego źródła"))
    else:
        status, headline = "ok", "dane z ipinfo.io i odwrotnego DNS"
    return Report("ip", ip, f"Adres IP: {ip}", status, headline, data, sections, findings)


# --- rdap -------------------------------------------------------------------------------------

def build_rdap_report(res: RdapResult) -> Report:
    findings = evaluate(res)
    if not res.found:
        headline = "RDAP: domena nieznana w rejestrze"
        sections = [Section("RDAP", rows=[("Domena", res.domain), ("Źródło", _v(res.source))])]
    else:
        headline = f"RDAP z {res.source}"
        d = res.days_to_expiry
        sections = [Section("RDAP", rows=[
            ("Domena", res.domain),
            ("Rejestrator", _v(res.registrar) + (f" (IANA {res.registrar_iana_id})" if res.registrar_iana_id else "")),
            ("Utworzona", _v(res.created)), ("Zmieniona", _v(res.updated)),
            ("Wygasa", _v(res.expires) + (f" (za {d} dni)" if d is not None and d >= 0 else f" (minęło {-d} dni)" if d is not None else "")),
            ("Statusy", ", ".join(res.status) or "-"),
            ("Serwery nazw", ", ".join(res.nameservers) or "-"),
            ("DNSSEC (delegacja)", {True: "podpisana", False: "niepodpisana"}.get(res.dnssec_signed, "-")),
            ("Źródło", _v(res.source)),
        ])]
    return Report("rdap", res.domain, f"RDAP: {res.domain}", "ok", headline, res.to_dict(), sections, findings)


def build_rdap_failed_report(domain: str, error: str) -> Report:
    f = [Finding("RDAP", Severity.FAIL, f"{UNCHECKED}: {error}", "Spróbuj ponownie później; sprawdź połączenie z internetem.")]
    data = {"domain": domain, "found": None, "error": error}
    return Report("rdap", domain, f"RDAP: {domain}", "failed", f"{UNCHECKED} (wszystkie drogi RDAP zawiodły)",
                  data, [Section("RDAP", rows=[("Domena", domain), ("Błąd", error)])], f)


# --- subdomains -------------------------------------------------------------------------------

def build_subdomains_report(res: SubdomainResult, skipped_resolve: int = 0) -> Report:
    findings: list[Finding] = []
    src_rows = [(s.name, s.status_text) for s in res.sources]
    sections = [Section("Źródła", rows=src_rows)]
    n = len(res.entries)
    failed = [s for s in res.sources if not s.ok]
    if res.all_failed:
        headline = f"{UNCHECKED} (wszystkie źródła zawiodły)"
        findings.append(Finding(
            "SUBDOMENY", Severity.FAIL, f"{UNCHECKED} (wszystkie źródła zawiodły); to NIE jest wynik „0 subdomen”",
            "Spróbuj ponownie za kilka minut (limity i przeciążenie źródeł są częste)."))
    else:
        if failed:
            headline = (f"znaleziono {n} nazw; wynik niepełny: {len(failed)} z {len(res.sources)} źródeł zawiodło "
                        f"({', '.join(s.name for s in failed)})")
            findings.append(Finding(
                "SUBDOMENY", Severity.INFO,
                f"{UNCHECKED}: {', '.join(f'{s.name} ({s.error})' for s in failed)}; lista może być niepełna"))
        elif n:
            headline = f"znaleziono {n} nazw (wszystkie {len(res.sources)} źródła odpowiedziały)"
        else:
            headline = f"0 nazw: wszystkie {len(res.sources)} źródła odpowiedziały i nic nie znalazły"
        if n:
            findings.append(Finding("SUBDOMENY", Severity.INFO, f"znaleziono {n} nazw w obrębie {res.domain}"))
        else:
            findings.append(Finding("SUBDOMENY", Severity.OK,
                                    "źródła odpowiedziały poprawnie, ale nie zgłosiły żadnej subdomeny"
                                    + (" (część źródeł zawiodła, więc brak wyników nie jest pełny)" if failed else "")))
        for s in res.sources:
            if s.ok and s.note:
                findings.append(Finding("SUBDOMENY", Severity.INFO, f"{s.name}: {s.note}"))
    if res.resolved:
        ok = sum(1 for e in res.entries if e.resolved)
        none = sum(1 for e in res.entries if e.resolved == [])
        bad = sum(1 for e in res.entries if e.resolved is None)
        findings.append(Finding("DNS", Severity.INFO,
                                f"rozwiązywanie A/AAAA: {ok} rozwiązuje się, {none} bez adresu, {bad} {UNCHECKED}"
                                + (f"; pominięto {skipped_resolve} nazw (limit)" if skipped_resolve else "")))
    if n:
        headers = ["Nazwa", "Źródła"]
        headers += ["Adresy (HackerTarget)"] if any(e.passive_ips for e in res.entries) else []
        if res.resolved:
            headers.append("Rozwiązanie DNS")
        rows = []
        for e in res.entries:
            row = [e.name, ", ".join(e.sources)]
            if any(x.passive_ips for x in res.entries):
                row.append(", ".join(e.passive_ips) or "-")
            if res.resolved:
                row.append(", ".join(e.resolved) if e.resolved else
                           (f"{UNCHECKED} ({e.resolve_error})" if e.resolved is None else "brak adresu"))
            rows.append(row)
        sections.append(Section(f"Subdomeny ({n})", headers=headers, table=rows))
    return Report("subdomains", res.domain, f"Subdomeny: {res.domain}", res.status, headline, res.to_dict(),
                  sections, findings)


# --- render -----------------------------------------------------------------------------------

def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -f.severity.rank)  # stabilne


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def printable(text: str) -> str:
    """Znaki sterujące (Unicode Cc poza nową linią i tabulatorem, m.in. ESC) -> widoczne \\xNN.

    Dane z cudzych serwerów nie mogą sterować terminalem (czyszczenie ekranu, sekwencje ESC).
    """
    return "".join(
        c if c in "\n\t" or unicodedata.category(c) != "Cc" else f"\\x{ord(c):02x}"
        for c in text
    )


def render_text(report: Report, width: int | None = None) -> str:
    width = width or min(max(shutil.get_terminal_size((100, 24)).columns, 80), 120)
    out: list[str] = [printable(report.title.upper()), printable(f"{report.generated} | net-intel {__version__}"),
                      "=" * width, printable(f"WYNIK: {report.headline}")]
    for sec in report.sections:
        out.append("")
        out.append(sec.title.upper())
        if sec.rows:
            for label, value in sec.rows:
                wrapped = textwrap.wrap(printable(value), width - 22) or ["-"]
                out.append(f"{label:<20}{wrapped[0]}")
                out.extend(" " * 20 + line for line in wrapped[1:])
        if sec.table:
            cols = len(sec.headers)
            widths = [min(max(len(printable(r[i])) for r in [sec.headers, *sec.table]), 60) for i in range(cols)]
            out.append("  ".join(h.ljust(w) for h, w in zip(sec.headers, widths)).rstrip())
            for r in sec.table:
                out.append("  ".join(printable(c).ljust(w) for c, w in zip(r, widths)).rstrip())
    out.append("")
    out.append("USTALENIA")
    out.append(f"{'WAGA':<5} {'OBSZAR':<10} USTALENIE")
    out.append("-" * width)
    for f in _sorted_findings(report.findings):
        lines = textwrap.wrap(printable(f.title), width - 17) or [""]
        out.append(f"{f.severity.value:<5} {f.area:<10} {lines[0]}")
        out.extend(" " * 17 + line for line in lines[1:])
        if f.recommendation:
            for i, line in enumerate(textwrap.wrap(printable(f.recommendation), width - 20)):
                out.append(" " * 17 + ("-> " if i == 0 else "   ") + line)
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
.headline{font-weight:600;margin:0 0 12px}.headline.failed{color:var(--fail)}.headline.partial{color:var(--warn)}
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
        f"<title>{e(report.title)}</title><style>{_HTML_STYLE}</style></head><body>",
        f"<h1>{e(report.title)}</h1>",
        f"<div class=\"meta\">{e(report.generated)} &middot; net-intel {__version__}</div>",
        f"<p class=\"headline {e(report.status)}\">Wynik: {e(report.headline)}</p>",
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
    parts.append("</table>")
    for sec in report.sections:
        parts.append(f"<h2>{e(sec.title)}</h2><table>")
        for label, value in sec.rows:
            parts.append(f"<tr><td class=\"k\">{e(label)}</td><td class=\"mono\">{e(value)}</td></tr>")
        if sec.table:
            parts.append("<tr>" + "".join(f"<th>{e(h)}</th>" for h in sec.headers) + "</tr>")
            for r in sec.table:
                parts.append("<tr>" + "".join(f"<td class=\"mono\">{e(x)}</td>" for x in r) + "</tr>")
        parts.append("</table>")
    parts.append("</body></html>")
    return "".join(parts)
