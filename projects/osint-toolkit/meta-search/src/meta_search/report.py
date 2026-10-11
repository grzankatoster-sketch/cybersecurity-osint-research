"""Raport HTML wyniku Meta (bez skryptów; każda wartość z API escapowana)."""
from __future__ import annotations

from html import escape

from .contract import LABELS_PL, MetaResult, St

KIND_PL = {"api": "oficjalne API", "html_heuristic": "heurystyka HTML", "manual": "link do ręcznego sprawdzenia"}
GOOD = {St.FOUND, St.MANUAL}
NEUTRAL = {St.NO_RESULT}


def _link(url: str) -> str:
    if not url.startswith("https://"):
        return escape(url)
    return f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{escape(url)}</a>'


HEADS = {"profile": "Nick|Nazwa|Obserwujący|Bio|Profil", "post": "Autor|Czas|Typ|Treść|Link",
         "page": "Strona|Kategoria|Fani|O stronie|Link", "link": "Platforma|Opis|Adres||"}


def _row(it: dict) -> str:
    kind = it.get("type")
    if kind == "profile":
        site = f"<br>{_link(it['website'])}" if it.get("website") else ""
        return (f"<tr><td>@{escape(it['username'])}{' ✔' if it.get('is_verified') else ''}</td>"
                f"<td>{escape(it.get('name', ''))}</td><td>{escape(str(it.get('follower_count') if it.get('follower_count') is not None else '-'))}</td>"
                f"<td>{escape(it.get('biography', ''))}</td><td>{_link(it['profile_url'])}{site}</td></tr>")
    if kind == "post":
        return (f"<tr><td>@{escape(it.get('username', ''))}</td><td>{escape(it.get('timestamp', ''))}</td>"
                f"<td>{escape(it.get('media_type', ''))}</td><td>{escape(it.get('text', ''))}</td>"
                f"<td>{_link(it.get('permalink', ''))}</td></tr>")
    if kind == "page":
        mark = f" ({escape(it['verification_status'])})" if it.get("verification_status") else ""
        site = f"<br>{_link(it['website'])}" if it.get("website") else ""
        return (f"<tr><td>{escape(it.get('name', ''))}{mark}</td><td>{escape(it.get('category', ''))}</td>"
                f"<td>{escape(str(it.get('fan_count') if it.get('fan_count') is not None else '-'))}</td>"
                f"<td>{escape(it.get('about', ''))}</td><td>{_link(it.get('link', ''))}{site}</td></tr>")
    if kind == "link":
        return (f"<tr><td>{escape(it['platform'])}</td><td>{escape(it['label'])}</td>"
                f"<td colspan=3>{_link(it['url'])}</td></tr>")
    return ""


def _items(res: MetaResult) -> str:
    """Osobna tabela dla każdego typu pozycji (np. profil Instagrama i jego media), w kolejności pierwszego wystąpienia."""
    groups: dict[str, list[str]] = {}
    for it in res.items:
        row = _row(it)
        if row:
            groups.setdefault(it.get("type", "link"), []).append(row)
    tables = []
    for kind, rows in groups.items():
        th = "".join(f"<th>{h}</th>" for h in HEADS[kind].split("|") if h)
        tables.append(f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(rows)}</tbody></table>")
    return "".join(tables)


def render_html(res: MetaResult) -> str:
    cls = "ok" if res.status in GOOD else ("neutral" if res.status in NEUTRAL else "bad")
    caveats = "".join(f"<li>{escape(c)}</li>" for c in res.caveats)
    meta = [("Platforma", res.platform), ("Operacja", res.operation), ("Zapytanie", res.query),
            ("Źródło", KIND_PL.get(res.source_kind.value, res.source_kind.value)), ("Endpoint", res.endpoint or "-"),
            ("Wersja API", res.api_version or "-"), ("Pobrano (UTC)", res.fetched_at),
            ("HTTP / kod błędu", f"{res.http_status or '-'} / {res.error_code or '-'}")]
    dl = "".join(f"<dt>{escape(k)}</dt><dd>{escape(str(v))}</dd>" for k, v in meta)
    # Raport bez zasobów zdalnych także po otwarciu z dysku (file://, bez nagłówków panelu): CSP blokuje obrazy,
    # skrypty i fonty z sieci, a no-referrer nie zdradza adresu raportu po kliknięciu linku.
    return f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Meta: {escape(res.query)}</title>
<style>
:root{{--bg:#fff;--ink:#1c1d1f;--muted:#6b6d72;--line:#dedcd5;--ok:#1f5c4a;--bad:#a3271f;--neutral:#6b6d72}}
@media (prefers-color-scheme:dark){{:root{{--bg:#1d1f21;--ink:#e8e6e1;--muted:#9a9ca1;--line:#303236;--ok:#6fc2a4;
--bad:#ef7d73;--neutral:#9a9ca1}}}}
body{{margin:0;padding:16px;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,sans-serif}}
h1{{font-size:17px;margin:0 0 8px}} .badge{{font-weight:600;padding:2px 8px;border-radius:99px;border:1px solid}}
.ok{{color:var(--ok)}} .bad{{color:var(--bad)}} .neutral{{color:var(--neutral)}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;color:var(--muted);font-size:13px}}
dd{{margin:0;color:var(--ink);word-break:break-all}} table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}}
table+table{{margin-top:16px}} td{{word-break:break-word}} a{{color:var(--ok)}} .note{{color:var(--muted);font-size:13px}}
</style></head><body>
<h1>Meta · {escape(res.operation)} · <span class="badge {cls}">{escape(LABELS_PL[res.status])}</span></h1>
<p>{escape(res.message)}</p>
<dl>{dl}</dl>
{_items(res)}
<ul class="note">{caveats}</ul>
</body></html>
"""
