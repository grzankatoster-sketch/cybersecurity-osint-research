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
from .collector import SiteData
from .models import Finding, Severity

SHOWN_HEADERS = (
    "server", "content-type", "strict-transport-security", "content-security-policy",
    "content-security-policy-report-only", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "x-powered-by",
    "access-control-allow-origin",
)


@dataclass
class Report:
    url: str
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
            "tool": f"site-audit {__version__}",
            "url": self.url,
            "generated": self.generated,
            "counts": self.counts,
            "summary": self.summary,
            "findings": [
                {"severity": f.severity.value, "area": f.area, "title": f.title, "recommendation": f.recommendation}
                for f in self.findings
            ],
        }


def build_report(data: SiteData, findings: list[Finding]) -> Report:
    return Report(
        url=data.target.url,
        generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        summary=summarize(data),
        findings=findings,
    )


def _cert_summary(cert: dict | None) -> dict | None:
    if not cert:
        return None

    def name(seq):
        return ", ".join(f"{k}={v}" for rdn in seq or () for k, v in rdn)

    return {
        "subject": name(cert.get("subject")),
        "issuer": name(cert.get("issuer")),
        "not_after": cert.get("notAfter"),
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:20],
    }


def summarize(d: SiteData) -> dict:
    r = d.main.response
    s: dict = {
        "chain": [{"url": h.url, "status": h.status, "location": h.location} for h in d.main.chain],
        "error": d.main.error,
        "requests": d.requests,
    }
    if r is None:
        return s
    s.update({
        "final_url": r.url,
        "status": r.status,
        "ip": r.ip,
        "headers": {k: r.header(k) for k in SHOWN_HEADERS if r.header(k) is not None},
        "cookies": [v.split("=", 1)[0].strip() for v in r.header_all("set-cookie")],
    })
    if r.tls is not None:
        s["tls"] = {"version": r.tls.version, "cipher": r.tls.cipher,
                    "verify_error": r.tls.verify_error, "cert": _cert_summary(r.tls.cert)}
    for key, res in (("security_txt", d.security_txt), ("robots_txt", d.robots), ("sitemap", d.sitemap)):
        if res is not None:
            s[key] = {"url": res.response.url if res.response else res.url,
                      "status": res.response.status if res.response else None,
                      "error": res.error}
    return s


def summary_rows(s: dict) -> list[tuple[str, str]]:
    rows = [("Łańcuch", " → ".join(f"{h['url']} [{h['status'] or 'błąd'}]" for h in s["chain"]))]
    if "final_url" not in s:
        rows.append(("Błąd", s.get("error") or "-"))
        return rows
    rows.append(("IP", s["ip"]))
    tls = s.get("tls")
    if tls:
        rows.append(("TLS", f"{tls['version'] or '-'} {tls['cipher'] or ''}".strip()))
        cert = tls.get("cert")
        if cert:
            rows.append(("Certyfikat", f"{cert['subject']} | wystawca: {cert['issuer']} | do: {cert['not_after']}"))
        elif tls.get("verify_error"):
            rows.append(("Certyfikat", f"NIEZWERYFIKOWANY: {tls['verify_error']}"))
    for k, v in s["headers"].items():
        rows.append((k, v))
    if s["cookies"]:
        rows.append(("Ciasteczka", ", ".join(s["cookies"])))
    for key, label in (("security_txt", "security.txt"), ("robots_txt", "robots.txt"), ("sitemap", "sitemap")):
        if key in s:
            x = s[key]
            rows.append((label, f"{x['url']} [{x['status'] or x['error'] or '-'}]"))
    rows.append(("Żądania", str(s["requests"])))
    return rows


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -f.severity.rank)  # stabilne: kolejnosc obszarow zachowana


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


# znaki sterujace kierunkiem tekstu (Trojan Source): moga wizualnie przestawiac fragmenty raportu
_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def printable(text: str) -> str:
    """Znaki sterujace (Unicode Cc poza nowa linia i tabulatorem, m.in. ESC) i sterujace kierunkiem
    tekstu -> widoczne \\xNN / \\uNNNN. Niezaufane naglowki i tresci nie moga sterowac terminalem.
    """
    return "".join(
        f"\\u{ord(c):04x}" if c in _BIDI
        else c if c in "\n\t" or unicodedata.category(c) != "Cc"
        else f"\\x{ord(c):02x}"
        for c in str(text)
    )


def render_text(report: Report, width: int | None = None) -> str:
    width = width or min(max(shutil.get_terminal_size((100, 24)).columns, 80), 120)
    out: list[str] = []
    out.append(printable(f"AUDYT STRONY: {report.url}"))
    out.append(printable(f"{report.generated} | site-audit {__version__}"))
    out.append("=" * width)
    out.append("ZEBRANE DANE")
    for label, value in summary_rows(report.summary):
        wrapped = textwrap.wrap(printable(value), width - 30) or ["-"]
        out.append(f"{printable(label)[:28]:<29}{wrapped[0]}")
        out.extend(" " * 29 + line for line in wrapped[1:])
    out.append("")
    out.append("USTALENIA")
    out.append(f"{'WAGA':<5} {'OBSZAR':<13} USTALENIE")
    out.append("-" * width)
    for f in _sorted_findings(report.findings):
        lines = textwrap.wrap(printable(f.title), width - 20) or [""]
        out.append(f"{f.severity.value:<5} {f.area:<13} {lines[0]}")
        out.extend(" " * 20 + line for line in lines[1:])
        if f.recommendation:
            for i, line in enumerate(textwrap.wrap(printable(f.recommendation), width - 23)):
                out.append(" " * 20 + ("-> " if i == 0 else "   ") + line)
    out.append("-" * width)
    c = report.counts
    out.append(f"Podsumowanie: FAIL {c['FAIL']} | WARN {c['WARN']} | INFO {c['INFO']} | OK {c['OK']}")
    return "\n".join(out)


_HTML_STYLE = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6570;--line:#d8dee4;--ok:#1a7f37;--info:#0969da;--warn:#9a6700;--fail:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--ok:#3fb950;--info:#58a6ff;--warn:#d29922;--fail:#f85149}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif;margin:0 auto;max-width:1000px;padding:24px 16px}
h1{font-size:1.4rem;margin:0 0 4px;word-break:break-all}h2{font-size:1.05rem;margin:28px 0 8px}
.meta{color:var(--muted);margin-bottom:16px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}.k{white-space:nowrap;color:var(--muted);width:1%}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:.9em;word-break:break-all}
.sev{font-weight:700;white-space:nowrap}.OK{color:var(--ok)}.INFO{color:var(--info)}.WARN{color:var(--warn)}.FAIL{color:var(--fail)}
.rec{color:var(--muted);display:block;margin-top:2px}
.sum span{display:inline-block;margin-right:16px;font-weight:600}
"""


def render_html(report: Report) -> str:
    def e(x) -> str:
        return html.escape(printable(x))

    parts = [
        "<!doctype html><html lang=\"pl\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>Audyt strony {e(report.url)}</title><style>{_HTML_STYLE}</style></head><body>",
        f"<h1>Audyt strony: {e(report.url)}</h1>",
        f"<div class=\"meta\">{e(report.generated)} &middot; site-audit {__version__}</div>",
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
    parts.append("</table></body></html>")
    return "".join(parts)
