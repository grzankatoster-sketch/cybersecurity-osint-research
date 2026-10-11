"""Raport HTML (jeden plik, bez JS i zasobów zewnętrznych) oraz eksport CSV."""
from __future__ import annotations

import csv
import re
from datetime import datetime
from html import escape
from pathlib import Path

from .fsutil import atomic_open
from .models import Result, Status, is_abort_placeholder
from .urlnorm import is_http_url

MANUAL_LIMIT = 300    # tyle pozycji „sprawdź ręcznie” w raporcie HTML; reszta jest policzona i wskazana (CSV/JSON mają całość)

CSS = """
:root{--bg:#fafaf9;--fg:#1c1917;--mut:#78716c;--line:#e7e5e4;--card:#fff;--ok:#15803d;--warn:#b45309;--err:#b91c1c;--acc:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--mut:#a8a29e;--line:#44403c;--card:#292524;--ok:#4ade80;--warn:#fbbf24;--err:#f87171;--acc:#93c5fd}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:8px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}a{color:var(--acc);word-break:break-all}
.hi{color:var(--ok);font-weight:600}.md{color:var(--warn);font-weight:600}.lo{color:var(--err)}
.stats{display:flex;gap:16px;flex-wrap:wrap}.stats div{min-width:110px}.stats b{display:block;font-size:20px}
details summary{cursor:pointer;color:var(--mut)}code{font-size:13px}
"""


def _link(url: str, label: str | None = None) -> str:
    """Odnośnik tylko dla adresów http/https; każdy inny schemat (javascript:, data:...) to zwykły tekst."""
    text = escape(url if label is None else label)
    if not is_http_url(url):
        return text
    return f"<a href='{escape(url)}' rel='noreferrer noopener' target='_blank'>{text}</a>"


def _conf_class(c: float) -> str:
    return "hi" if c >= 0.85 else "md" if c >= 0.6 else "lo"


def _found_table(results: list[Result], min_conf: float) -> str:
    rows = sorted((r for r in results if r.status is Status.FOUND and r.confidence >= min_conf),
                  key=lambda r: (-r.confidence, r.site.lower()))
    if not rows:
        return "<p class='mut'>Brak trafień powyżej progu.</p>"
    body = "".join(
        f"<tr><td class='{_conf_class(r.confidence)}'>{r.confidence:.2f}</td><td>{escape(r.site)}</td>"
        f"<td>{_link(r.url)}</td>"
        f"<td>{_profile_cell(r.profile)}</td><td class='mut'>{escape(r.channel)}</td><td class='mut'>{escape(r.reason)}"
        + (" <span class='lo'>bez weryfikacji TLS (wynik niezaufany, pewność ograniczona)</span>" if r.insecure else "")
        + "</td></tr>"
        for r in rows)
    return ("<table><tr><th>Pewność</th><th>Serwis</th><th>Profil</th><th>Dane z profilu</th><th>Kanał</th><th>Dlaczego</th>"
            f"</tr>{body}</table>")


def channel_text(info: dict | None) -> str:
    """Jedna linia o kanale skanu (tryb, proxy bez danych logowania, adres wyjścia, liczby wyników na kanał)."""
    if not info:
        return ""
    mode = info.get("mode")
    if mode == "tor":
        head = "Tor" + (f" (wyjście {info['exit_ip_masked']})" if info.get("exit_ip_masked") else "")
    elif mode == "proxy":
        head = f"proxy {info.get('proxy_label', '')}"
    else:
        head = "bezpośrednio (adres IP widoczny dla serwisów)"
    counts = info.get("counts") or {}
    tail = ", ".join(f"{k}: {v}" for k, v in counts.items())
    return f"Kanał: {head}" + (f" — wyniki wg kanału: {tail}" if tail else "")


def _profile_cell(p: dict) -> str:
    if not p:
        return ""
    bits = []
    for key, label in (("name", "nazwa"), ("location", "lokalizacja"), ("created", "założone"),
                       ("website", "www"), ("bio", "bio")):
        if p.get(key):
            val = p[key] if key != "bio" else p[key][:120]
            bits.append(f"<b>{label}:</b> {escape(val)}")
    if p.get("links"):
        bits.append(f"<b>linki:</b> {len(p['links'])}")
    return "<br>".join(bits)


def _analysis_block(a: dict | None) -> str:
    if not a:
        return ""
    out = ["<h2>Analiza (poszlaki, nie fakty)</h2><div class='card'>"]
    if a.get("country"):
        for c in a["country"]:
            ev = "".join(f"<li>{escape(e)}</li>" for e in c["evidence"])
            out.append(f"<p><b>Kraj: {escape(c['country'])}</b> — {c['percent']}% głosów, siła dowodów: "
                       f"{escape(c['strength'])}</p><ul class='mut'>{ev}</ul>")
    else:
        out.append(f"<p class='mut'>Kraj: brak poszlak (profile z danymi: {a.get('profiles_with_data', 0)}).</p>")
    if a.get("variant_links"):
        rows = "".join(
            f"<tr><td><code>{escape(v)}</code></td><td>"
            + ("—" if i["score"] is None else escape(_level(i)))
            + f"</td><td>{escape(i.get('pair', ''))}</td><td class='mut'>{escape('; '.join(i['reasons']))}</td></tr>"
            for v, i in a["variant_links"].items())
        out.append("<p><b>Powiązanie wariantów z nazwą wyjściową</b></p><table><tr><th>Wariant</th><th>Powiązanie"
                   f"</th><th>Najmocniejsza para</th><th>Powody</th></tr>{rows}</table>")
    if a.get("pairs"):
        rows = "".join(f"<tr><td>{escape(_level(p))}</td><td>{escape(p['a'])}</td><td>{escape(p['b'])}</td>"
                       f"<td class='mut'>{escape('; '.join(p['reasons']))}</td></tr>" for p in a["pairs"])
        out.append("<p><b>Możliwe powiązania kont</b> (poziom dowodów, nie procent pewności; pola kopiowalne "
                   "nie wystarczają)</p><table><tr><th>Dowody</th><th>Konto</th><th>Konto</th>"
                   f"<th>Powody</th></tr>{rows}</table>")
    out.append("</div>")
    return "".join(out)


def _level(info: dict) -> str:
    """Poziom dowodów zamiast procentu; starsze pliki bez poziomu: brak oceny poziomu."""
    level = info.get("level") or "nieokreślony"
    return level + (", tylko pola kopiowalne" if info.get("copy_only") else "")


MANUAL_HINTS = ("anty-bot", "wymaga logowania", "dostęp zabroniony", "limit zapytań", "zablokowane")


def split_errors(results: list[Result]) -> tuple[list[Result], list[Result]]:
    """Jeden przebieg: (błędy do sprawdzenia ręcznie, pozostałe błędy)."""
    manual, other = [], []
    for r in results:
        if r.status is Status.ERROR:
            (manual if any(h in r.reason for h in MANUAL_HINTS) else other).append(r)
    return manual, other


def manual_check(results: list[Result]) -> list[Result]:
    """Serwisy, których automat nie mógł sprawdzić (blokada, logowanie) — człowiek otworzy je w przeglądarce."""
    return split_errors(results)[0]


def _manual_block(results: list[Result], limit: int = MANUAL_LIMIT) -> str:
    rows = manual_check(results)
    if not rows:
        return ""
    body = "".join(
        f"<tr><td>{escape(r.site)}</td><td>{_link(r.url)}</td><td class='mut'>{escape(r.reason)}</td></tr>"
        for r in rows[:limit])
    if len(rows) > limit:
        body += (f"<tr><td colspan='3' class='mut'>… pominięto {len(rows) - limit} pozycji (limit {limit} w raporcie "
                 "HTML; pełna lista: --csv lub --json)</td></tr>")
    return (f"<details><summary>Sprawdź ręcznie: {len(rows)} serwisów zablokowało automat albo wymaga logowania "
            f"— otwórz w zwykłej przeglądarce</summary><table><tr><th>Serwis</th><th>Profil</th><th>Powód</th></tr>"
            f"{body}</table></details>")


MANUAL_INSTRUCTION = "Otwórz w Tor Browserze; serwis zablokował automatyczne sprawdzenie (błąd ≠ brak konta)."
ABORTED_NOTE = "nie sprawdzono: skan przerwany (proxy przestało działać)"


def manual_entries(results: list[Result]) -> tuple[list[Result], list[Result]]:
    """Lista „do ręcznego sprawdzenia”: (błędy serwisów, serwisy niesprawdzone po przerwaniu skanu)."""
    errors = [r for r in results if r.status is Status.ERROR]
    return ([r for r in errors if not is_abort_placeholder(r)], [r for r in errors if is_abort_placeholder(r)])


PRESKIPPED_REASON = "zablokowane wg kontroli bazy (anty-bot / logowanie)"   # pominięte przed skanem, bez zapytania


def manual_summary(results: list[Result]) -> str:
    errs, skipped = manual_entries(results)
    pre = sum(1 for r in errs if r.reason == PRESKIPPED_REASON)
    text = f"{len(errs) - pre} błędów skanu"
    if pre:
        text += f" + {pre} pominiętych (blokują automaty wg kontroli bazy)"
    return text + (f" + {len(skipped)} niesprawdzonych (skan przerwany)" if skipped else "")


def _manual_all_block(results: list[Result]) -> str:
    """Wszystkie ERROR (bez limitu) z adresem profilu; zastępniki po przerwaniu skanu policzone osobno."""
    errs, skipped = manual_entries(results)
    if not errs and not skipped:
        return ""
    body = "".join(
        f"<tr><td>{escape(r.site)}</td><td>{_link(r.url)}</td>"
        f"<td class='mut'>{escape(ABORTED_NOTE if is_abort_placeholder(r) else r.reason)}</td></tr>"
        for r in errs + skipped)
    return (f"<h2>Do ręcznego sprawdzenia</h2><p class='mut'>{escape(MANUAL_INSTRUCTION)}</p>"
            f"<p><b>{escape(manual_summary(results))}</b></p>"
            f"<table><tr><th>Serwis</th><th>Profil</th><th>Powód</th></tr>{body}</table>")


def _errors_block(results: list[Result]) -> str:
    errs = split_errors(results)[1]
    if not errs:
        return ""
    body = "".join(f"<tr><td>{escape(r.site)}</td><td class='mut'>{escape(r.reason)}</td></tr>" for r in errs)
    return (f"<details><summary>Nie udało się sprawdzić: {len(errs)} serwisów (błędy nie oznaczają braku konta)"
            f"</summary><table>{body}</table></details>")


def render_html(
    query: str,
    scans: dict[str, list[Result]],
    summaries: dict[str, dict],
    dork_links: list[dict],
    wayback: dict[str, list] | None = None,
    min_conf: float = 0.6,
    analysis: dict | None = None,
    manual_extra: list[Result] | None = None,
    retention_note: str | None = None,
    channel_info: dict | None = None,
    level: str | None = None,
    aborted: dict | None = None,
) -> str:
    """`level` (quick|standard|full) włącza sekcję „Do ręcznego sprawdzenia” (zamiast dwóch starszych list błędów) i,
    dla quick, nagłówek trybu pasywnego; `aborted` ({"checked": X, "total": Y}) = baner raportu częściowego."""
    quick = level == "quick"
    parts = [f"<h1>Username Engine: {escape(query)}</h1>",
             (f"<p class='card lo'><b>Raport częściowy: proxy przestało działać</b> — sprawdzono "
              f"{int(aborted.get('checked', 0))} z {int(aborted.get('total', 0))} serwisów, reszta ma status ERROR "
              "(błąd ≠ brak konta). Skan przerwano bez ruchu bezpośredniego.</p>") if aborted else "",
             "<p class='card'><b>Tryb szybki: tylko źródła pasywne</b> — żadne zapytanie nie poszło do serwisów "
             "docelowych (archiwum i linki do wyszukiwarek).</p>" if quick else "",
             f"<p class='mut'>Raport z {datetime.now():%Y-%m-%d %H:%M}. Ta sama nazwa ≠ ta sama osoba: "
             "trafienie to trop, nie dowód. Potwierdź profil (avatar, bio, linki) przed wnioskami.</p>",
             f"<p class='card'><b>{escape(retention_note)}</b></p>" if retention_note else "",
             f"<p class='card'>{escape(channel_text(channel_info))}</p>" if channel_info else "",
             _analysis_block(analysis)]
    first = next(iter(scans), None)
    for name, results in (() if quick else scans.items()):
        if name == first and manual_extra:
            results = results + manual_extra      # tylko do listy „sprawdź ręcznie”, bez zapytań do tych serwisów
        s = summaries[name]
        parts.append(f"<h2>Nazwa: <code>{escape(name)}</code></h2><div class='card stats'>"
                     f"<div><b>{sum(1 for r in results if r.status is Status.FOUND and r.confidence >= min_conf)}</b>"
                     f"znalezione (≥{min_conf})</div><div><b>{s['checked']}</b>sprawdzone</div>"
                     f"<div><b>{s['error']}</b>błędy</div><div><b>{s['unsupported']}</b>nieobsługiwane</div></div>")
        parts.append(_found_table(results, min_conf))
        if level:
            parts.append(_manual_all_block(results))
        else:
            parts.append(_manual_block(results))
            parts.append(_errors_block(results))
    if wayback:
        rows = "".join(
            f"<tr><td>{_link(url)}</td><td>"
            + (", ".join(_link(sn.archive_url, sn.date) for sn in snaps)
               if isinstance(snaps, list) else f"<span class='lo'>{escape(str(snaps))}</span>")
            + "</td></tr>"
            for url, snaps in wayback.items())
        note = "Ślad w archiwum (nie dowód istnienia konta)." if quick else "Zrzuty profili, także usuniętych."
        parts.append(f"<h2>Archiwum (Wayback Machine)</h2><p class='mut'>{note} Puste = brak zrzutu.</p>"
                     f"<table><tr><th>Profil</th><th>Zrzuty</th></tr>{rows}</table>")
    if dork_links:
        rows = "".join(
            f"<tr><td>{escape(d['engine'])}</td><td>{_link(d['url'], d['query'])}</td></tr>" for d in dork_links)
        parts.append("<h2>Wyszukiwarki (dorki)</h2><p class='mut'>Wzmianki o nazwie poza profilami, "
                     f"także podobne nazwy. Kliknij, aby otworzyć.</p><table>{rows}</table>")
    return ("<!doctype html><html lang='pl'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Username Engine: {escape(query)}</title><style>{CSS}</style></head>"
            f"<body><main>{''.join(parts)}</main></body></html>")


_FORMULA = re.compile(r"^[\s\x00-\x1f\x7f]*[=+\-@]|^[\t\r]")


def csv_safe(value):
    """Neutralizacja formuł arkusza (CSV injection): tekst zaczynający się (też po spacjach i znakach sterujących)
    od = + - @ albo od tabulatora/CR dostaje prefiks apostrofu."""
    if isinstance(value, str) and _FORMULA.match(value):
        return "'" + value
    return value


def write_csv(path: str | Path, scans: dict[str, list[Result]]) -> None:
    """Eksport CSV dla Excela: pola tekstowe zneutralizowane (csv_safe), zapis atomowy (plik tymczasowy + os.replace)."""
    with atomic_open(path, encoding="utf-8-sig", newline="") as f:   # BOM: Excel poprawnie czyta polskie znaki
        w = csv.writer(f, delimiter=";")
        w.writerow(["nazwa", "serwis", "status", "pewnosc", "url", "uzasadnienie", "kod_http", "kanal", "tls_niezweryfikowany"])
        for name, results in scans.items():
            for r in results:
                w.writerow([csv_safe(v) for v in (name, r.site, r.status.value, f"{r.confidence:.2f}", r.url,
                                                  r.reason, r.http_status or "", r.channel,
                                                  "tak" if r.insecure else "")])
