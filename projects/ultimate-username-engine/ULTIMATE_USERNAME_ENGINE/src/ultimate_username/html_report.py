"""Self-contained HTML report rendered from analyst documents (``*.analyst.json``).

One file, no JavaScript and no external resources (a CSP meta forbids them). Every value comes
from third-party pages or from a user-supplied file, so everything is escaped as text and links
exist only for plain http(s) URLs. Optional sections (identity, geo, wayback, dorks, variants,
request economy, control record) are rendered only when the document has them."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from html import escape
from urllib.parse import urlsplit

HIT_STATUSES = ("FOUND", "PROBABLE")
MAX_TEXT = 600
MAX_LISTED = 300
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")

CSS = """
:root{color-scheme:light dark;--bg:#fafaf9;--fg:#1c1917;--mut:#6b6560;--line:#e2dfdc;--card:#fff;
--ok:#15803d;--warn:#b45309;--err:#b91c1c;--acc:#1d4ed8;--chip:#f0eeec}
@media (prefers-color-scheme:dark){:root{--bg:#171513;--fg:#f3f1ef;--mut:#a9a39d;--line:#3d3935;
--card:#23201d;--ok:#4ade80;--warn:#fbbf24;--err:#f87171;--acc:#93c5fd;--chip:#2e2a27}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
h3{font-size:15px;margin:16px 0 6px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:12px 16px;margin:8px 0}
.stats{display:flex;gap:8px 24px;flex-wrap:wrap}.stats div{min-width:96px}
.stats b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}a{color:var(--acc);overflow-wrap:anywhere}
code{font-size:13px;overflow-wrap:anywhere}.url{overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;background:var(--chip);
font-size:12px;font-weight:600}
.FOUND{color:var(--ok)}.PROBABLE{color:var(--warn)}.bad{color:var(--err)}
tr.detail>td{background:var(--card);padding:8px 16px 16px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px 24px}
dl{margin:4px 0;display:grid;grid-template-columns:max-content 1fr;gap:2px 12px}
dt{color:var(--mut)}dd{margin:0;overflow-wrap:anywhere}ul{margin:4px 0;padding-left:20px}
details>summary{cursor:pointer;color:var(--mut);margin:6px 0}
@media (max-width:640px){dl{grid-template-columns:1fr}main{padding:16px 12px 32px}}
@media print{details:not([open])>*:not(summary){display:block}}
"""

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


# ------------------------------------------------------------------------------ primitives


def _text(value: object, limit: int = MAX_TEXT) -> str:
    """Any value as short escaped text (no control characters; containers as compact JSON)."""
    if value is None:
        return ""
    if isinstance(value, str):
        raw = value
    elif isinstance(value, bool):
        raw = "tak" if value else "nie"
    elif isinstance(value, int | float):
        raw = str(value)
    elif isinstance(value, list | tuple) and all(isinstance(v, str | int | float) for v in value):
        raw = ", ".join(str(v) for v in value)
    else:
        try:
            raw = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            raw = str(value)
    raw = _CONTROL_CHARS.sub("", raw)
    if len(raw) > limit:
        raw = raw[:limit] + "…"
    return escape(raw, quote=True)


_UNSAFE_URL_CHARS = frozenset("<>\"'`")


def _http_url(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 2048 or _CONTROL_CHARS.search(value):
        return None
    if any(c.isspace() for c in value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if any(c in _UNSAFE_URL_CHARS for c in parts.netloc):
        return None  # markup in the host: never a link and never echoed raw
    return value if parts.scheme in ("http", "https") and parts.netloc else None


def _link(value: object, label: object = None) -> str:
    """Anchor for a plain http(s) URL; anything else (javascript:, data:, ...) stays text."""
    url = _http_url(value)
    shown = _text(label if label is not None else value, 200)
    if url is None:
        return shown
    return (
        f'<a href="{escape(url, quote=True)}" rel="noopener noreferrer" target="_blank">{shown}</a>'
    )


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, dict) else {}


def _seq(value: object) -> list[object]:
    return list(value) if isinstance(value, list | tuple) else []


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _host(value: object, fallback: object) -> str:
    url = _http_url(value)
    return escape(urlsplit(url).netloc, quote=True) if url else _text(fallback, 120)


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="wrap"><table><tr>{head}</tr>{body}</table></div>'


def _dl(pairs: Iterable[tuple[str, str]]) -> str:
    items = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in pairs if v)
    return f"<dl>{items}</dl>" if items else ""


# --------------------------------------------------------------------------- hit components


def _control_block(control: object) -> str:
    record = _map(control)
    if not record:
        return ""
    diffs = ", ".join(_text(d, 80) for d in _seq(record.get("diffs")))
    pairs = [
        ("rodzaj", f"<b>{_text(record.get('kind'))}</b>"),
        ("klasa", _text(record.get("class"))),
        (
            "status: główny / kontrolny",
            f"{_text(record.get('status_real')) or '—'} / "
            f"{_text(record.get('status_control')) or '—'}",
        ),
        ("tytuł główny", _text(record.get("title_real"), 160)),
        ("tytuł kontrolny", _text(record.get("title_control"), 160)),
        (
            "długość: główna / kontrolna",
            f"{_text(record.get('len_real')) or '—'} / {_text(record.get('len_control')) or '—'}",
        ),
        ("podobieństwo", _text(record.get("similarity"))),
        ("różnice", diffs),
        (
            "nazwa kontrolna",
            f"<code>{_text(record.get('control_name'), 80)}</code>"
            if record.get("control_name")
            else "",
        ),
        (
            "kontrola wygląda na brak strony",
            _text(record.get("absent_like")) if "absent_like" in record else "",
        ),
        ("z pamięci podręcznej", _text(record.get("cached")) if "cached" in record else ""),
    ]
    return "<h3>Żądanie kontrolne</h3>" + _dl(pairs)


def _rules_block(profile: Mapping[str, object]) -> str:
    rules = [_map(r) for r in _seq(profile.get("evidence"))]
    signals = [_map(s) for s in _seq(profile.get("signals"))]
    out = ""
    if rules:
        rows = [
            (
                f"<code>{_text(r.get('rule_id'), 80)}</code>",
                _text(r.get("strategy"), 80),
                _text(r.get("polarity"), 40),
                _text(r.get("locator"), 120),
                _text(r.get("observed"), 160),
            )
            for r in rules
        ]
        out += "<h3>Dowody: reguły, które trafiły</h3>" + _table(
            ("reguła", "strategia", "kierunek", "miejsce", "obserwacja"), rows
        )
    if signals:
        sig_rows = [
            (
                _text(s.get("kind"), 80),
                _text(s.get("strength"), 40),
                _text(s.get("weight"), 12),
                _text(s.get("independence_group"), 60),
                _text(s.get("locator"), 80),
                _text(s.get("value"), 160),
            )
            for s in signals
        ]
        out += (
            f"<details><summary>Sygnały ({len(sig_rows)})</summary>"
            + _table(("sygnał", "siła", "waga", "grupa", "miejsce", "wartość"), sig_rows)
            + "</details>"
        )
    return out


def _identity_block(entry: Mapping[str, object] | None) -> str:
    if not entry:
        return ""
    score = entry.get("score")
    head = _dl(
        [
            ("wynik", f"<b>{_text(score)}</b>" if score is not None else ""),
            ("decyzja", f"<b>{_text(entry.get('decision'))}</b>"),
            ("ziarno (seed)", _text(entry.get("seed_used"))),
        ]
    )
    signals = [_map(s) for s in _seq(entry.get("signals"))]
    body = ""
    if signals:
        rows = [
            (
                _text(s.get("kind"), 80),
                _text(s.get("weight"), 12),
                _text(s.get("group"), 60),
                _text(s.get("fields"), 160),
                "<br>".join(_link(src) for src in _seq(s.get("sources"))[:6]),
                _text(s.get("detail"), 240),
            )
            for s in signals
        ]
        body = _table(("sygnał", "waga", "grupa", "pola", "źródła", "uzasadnienie"), rows)
    else:
        body = '<p class="mut">Brak sygnałów w dokumencie.</p>'
    return "<h3>Tożsamość (identity score)</h3>" + head + body


def _fields_block(profile: Mapping[str, object]) -> str:
    sources = _map(profile.get("field_sources"))
    rows: list[tuple[str, ...]] = []
    for group, fields in _map(profile.get("useful_metadata")).items():
        for name, value in _map(fields).items():
            if value is None:
                continue
            src = _map(sources.get(name))
            rows.append(
                (
                    _text(group, 40),
                    f"<b>{_text(name, 60)}</b>",
                    _text(value, 400),
                    _link(src.get("source_url")) if src else '<span class="mut">brak</span>',
                    _text(src.get("extractor"), 60),
                    _text(src.get("locator"), 120),
                    _text(src.get("quality"), 20),
                )
            )
    if not rows:
        return ""
    return "<h3>Pola profilu i ich źródła</h3>" + _table(
        ("grupa", "pole", "wartość", "źródło", "ekstraktor", "miejsce", "jakość"), rows
    )


def _identity_index(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    index: dict[str, Mapping[str, object]] = {}
    for entry in _seq(_map(document.get("identity")).get("profiles")):
        item = _map(entry)
        for key in (item.get("profile_url"), item.get("site")):
            if isinstance(key, str) and key not in index:
                index[key] = item
    return index


def _hits(document: Mapping[str, object]) -> str:
    profiles = [_map(p) for p in _seq(document.get("profiles"))]
    hits = [p for p in profiles if p.get("status") in HIT_STATUSES]
    if not hits:
        return '<p class="mut">Brak trafień FOUND ani PROBABLE.</p>'
    hits.sort(key=lambda p: (p.get("status") != "FOUND", str(p.get("site", "")).lower()))
    identity = _identity_index(document)
    rows = []
    for p in hits:
        status = _text(p.get("status"), 20)
        confidence = _map(p.get("confidence"))
        strength = _text(confidence.get("strength"), 20)
        if confidence.get("probability") is not None:
            strength += f" ({_text(confidence.get('probability'), 8)})"
        reasons = "<br>".join(_text(r, 200) for r in _seq(p.get("evidence_summary")))
        issues = _seq(p.get("issues"))
        if issues:
            reasons += f'<br><span class="mut">uwagi: {_text(issues, 200)}</span>'
        url = p.get("profile_url") or p.get("requested_url")
        id_entry = identity.get(str(p.get("profile_url"))) or identity.get(str(p.get("site")))
        score = (
            f'<br><span class="badge">tożsamość {_text(id_entry.get("score"), 12)}'
            f" · {_text(id_entry.get('decision'), 30)}</span>"
            if id_entry
            else ""
        )
        rows.append(
            f"<tr><td><b>{_text(p.get('site'), 80)}</b>{score}</td>"
            f'<td class="url">{_link(url)}</td>'
            f'<td class="{status}"><b>{status}</b></td><td>{strength}</td><td>{reasons}</td></tr>'
            '<tr class="detail"><td colspan="5"><div class="cols"><div>'
            + _rules_block(p)
            + "</div><div>"
            + (_control_block(p.get("control")) or "")
            + _identity_block(id_entry)
            + "</div></div>"
            + _fields_block(p)
            + "</td></tr>"
        )
    head = "".join(f"<th>{h}</th>" for h in ("Serwis", "Profil", "Werdykt", "Siła", "Powody"))
    return f'<div class="wrap"><table><tr>{head}</tr>{"".join(rows)}</table></div>'


# ------------------------------------------------------------------------- aggregate profile

_LANGUAGE_FIELDS = ("language", "languages")
MAX_SOURCES = 8


def _source_label(site: str, source: Mapping[str, object]) -> str:
    extractor = _text(source.get("extractor"), 60) or "—"
    quality = _text(source.get("quality"), 20) or "—"
    return f"{site} · {extractor} · {quality}"


def _hit_values(
    profiles: Sequence[Mapping[str, object]], names: Sequence[str]
) -> list[tuple[str, str, str]]:
    """(raw value, site, source label) of the named fields on every FOUND/PROBABLE profile."""
    found: list[tuple[str, str, str]] = []
    for p in profiles:
        if p.get("status") not in HIT_STATUSES:
            continue
        site = _text(p.get("site"), 80) or "—"
        sources = _map(p.get("field_sources"))
        for group in _map(p.get("useful_metadata")).values():
            fields = _map(group)
            for name in names:
                value = fields.get(name)
                items = value if isinstance(value, list | tuple) else [value]
                for item in items:
                    if isinstance(item, str | int | float) and not isinstance(item, bool):
                        raw = " ".join(str(item).split())
                        if raw:
                            found.append((raw, site, _source_label(site, _map(sources.get(name)))))
    return found


def _value_table(label: str, values: Sequence[tuple[str, str, str]]) -> str:
    """Distinct values (case-insensitive), most common first, each with its list of sources."""
    groups: dict[str, tuple[str, dict[str, None], set[str]]] = {}
    for raw, site, source in values:
        shown, sources, sites = groups.setdefault(raw.casefold(), (raw, {}, set()))
        sources[source] = None
        sites.add(site)
    ranked = sorted(groups.values(), key=lambda g: (-len(g[2]), g[0].casefold()))
    rows = []
    for index, (shown, sources, sites) in enumerate(ranked[:MAX_LISTED]):
        text = _text(shown, 160)
        listed = list(sources)
        more = f"<br>… i {len(listed) - MAX_SOURCES} więcej" if len(listed) > MAX_SOURCES else ""
        rows.append(
            (
                f"<b>{text}</b>" if index == 0 else text,
                _text(len(sites), 8),
                "<br>".join(listed[:MAX_SOURCES]) + more,
            )
        )
    return f"<h3>{label}</h3>" + _table(
        ("wartość", "liczba źródeł", "źródła (serwis · ekstraktor · jakość)"), rows
    )


def _timeline(values: Sequence[tuple[str, str, str]]) -> str:
    def order(entry: tuple[str, str, str]) -> tuple[int, str, str]:
        raw = entry[0]
        return (0 if re.match(r"\d{4}-\d{2}-\d{2}", raw) else 1, raw, entry[1])

    rows = [
        (_text(raw, 60), _text(site, 80), source) for raw, site, source in sorted(values, key=order)
    ]
    return "<h3>Oś czasu: daty założenia kont</h3>" + _table(
        ("data założenia", "serwis", "źródło (serwis · ekstraktor · jakość)"), rows[:MAX_LISTED]
    )


def _related_table(related: Sequence[object]) -> str:
    rows = [
        (
            _text(r.get("platform"), 40),
            _link(r.get("url")),
            _link(r.get("from_profile")),
            _text(r.get("field"), 40),
        )
        for r in map(_map, related[:MAX_LISTED])
        if r.get("url")
    ]
    if not rows:
        return ""
    return (
        "<h3>Konta powiązane (poza trafieniami skanu)</h3>"
        '<p class="mut">Linki z profili do znanych platform. To nie są trafienia: '
        "nie sprawdzono, czy konto istnieje.</p>"
        + _table(("platforma", "konto", "z profilu", "pole"), rows)
    )


def _graph_table(graph: Mapping[str, object]) -> str:
    edges = [e for e in map(_map, _seq(graph.get("edges"))) if e.get("from") and e.get("to")]
    if not edges:
        return ""
    rows = [
        (
            _link(e.get("from")),
            _link(e.get("to")),
            "tak" if e.get("reciprocal") is True else "nie",
            _text(e.get("source_field"), 40),
        )
        for e in edges[:MAX_LISTED]
    ]
    return (
        f"<h3>Graf linków: kto linkuje do kogo ({len(_seq(graph.get('nodes')))} węzłów, "
        f"{len(edges)} krawędzi)</h3>"
        + _table(("z profilu", "do profilu", "wzajemny", "pole"), rows)
    )


def _aggregate_block(document: Mapping[str, object]) -> str:
    profiles = [_map(p) for p in _seq(document.get("profiles"))]
    identity = _map(document.get("identity"))
    names = _hit_values(profiles, ("display_name",))
    locations = _hit_values(profiles, ("location",))
    languages = _hit_values(profiles, _LANGUAGE_FIELDS)
    created = _hit_values(profiles, ("created_at",))
    parts = [
        _value_table(label, values)
        for label, values in (
            ("Najczęstsza nazwa wyświetlana", names),
            ("Lokalizacje", locations),
            ("Języki", languages),
        )
        if values
    ]
    if created:
        parts.append(_timeline(created))
    parts.append(_related_table(_seq(identity.get("related_accounts"))))
    parts.append(_graph_table(_map(identity.get("graph"))))
    body = "".join(parts)
    if not body:
        body = (
            '<p class="mut">Brak danych profilowych do podsumowania: trafienia nie zawierają '
            "nazwy, lokalizacji, języka, dat założenia ani linków do innych kont.</p>"
        )
    return (
        "<h2>Profil zbiorczy</h2>"
        '<p class="mut">Zestawienie pól z trafień FOUND i PROBABLE. Każda wartość ma listę źródeł; '
        "zgodność nazw lub lokalizacji nie dowodzi, że to ta sama osoba.</p>" + body
    )


# --------------------------------------------------------------------------- other results


def _reason_of(profile: Mapping[str, object]) -> str:
    issues = _seq(profile.get("issues"))
    summary = _seq(profile.get("evidence_summary"))
    reason = issues[0] if issues else summary[0] if summary else profile.get("response_class")
    return f"{profile.get('status')}: {reason or 'brak powodu'}"


def _not_found_block(profiles: list[Mapping[str, object]]) -> str:
    rows = [p for p in profiles if p.get("status") == "NOT_FOUND"]
    if not rows:
        return ""
    hosts = sorted(
        {_host(p.get("requested_url") or p.get("profile_url"), p.get("site")) for p in rows}
    )
    shown = ", ".join(hosts[:MAX_LISTED])
    more = f" … i {len(hosts) - MAX_LISTED} więcej" if len(hosts) > MAX_LISTED else ""
    return (
        f"<details><summary>NOT_FOUND: {len(rows)} serwisów</summary>"
        f'<p class="mut">{shown}{more}</p></details>'
    )


def _unknown_block(profiles: list[Mapping[str, object]]) -> str:
    skip = {*HIT_STATUSES, "NOT_FOUND"}
    groups: dict[str, list[str]] = defaultdict(list)
    for p in profiles:
        if p.get("status") not in skip:
            groups[_reason_of(p)].append(_text(p.get("site"), 80))
    if not groups:
        return ""
    out = ["<h3>Bez rozstrzygnięcia (UNKNOWN i inne), wg powodu</h3>"]
    for reason, sites in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        listed = ", ".join(sorted(sites)[:MAX_LISTED])
        more = f" … i {len(sites) - MAX_LISTED} więcej" if len(sites) > MAX_LISTED else ""
        out.append(
            f"<details><summary>{_text(reason, 160)}: {len(sites)}</summary>"
            f'<p class="mut">{listed}{more}</p></details>'
        )
    return "".join(out)


def _counts_block(summary: Mapping[str, object]) -> str:
    out = ""
    for key, title in (
        ("not_tested_reasons", "Nie testowano, wg powodu"),
        ("excluded_before_search", "Wykluczone przed szukaniem"),
    ):
        data = {k: v for k, v in _map(summary.get(key)).items() if _int(v)}
        if data:
            rows = [(_text(k, 80), _text(v, 12)) for k, v in sorted(data.items())]
            out += (
                f"<details><summary>{title}</summary>{_table(('powód', 'liczba'), rows)}</details>"
            )
    return out


# ------------------------------------------------------------------------ optional sections


def _economy_block(economy: Mapping[str, object]) -> str:
    pairs = [
        (_text(k, 60), _text(v, 40))
        for k, v in economy.items()
        if isinstance(v, int | float | str) and not isinstance(v, bool)
    ]
    if not pairs:
        return ""
    cells = "".join(f"<div><b>{v}</b>{k}</div>" for k, v in pairs)
    return f'<h3>Ekonomia żądań</h3><div class="card stats">{cells}</div>'


def _geo_block(geo: Mapping[str, object]) -> str:
    out = ["<h2>Geo (poszlaki, nie fakty)</h2>"]
    countries = [_map(c) for c in _seq(geo.get("countries"))]
    if not countries:
        out.append(
            f'<p class="mut">Brak poszlak (profile rozważone: '
            f"{_text(geo.get('profiles_considered'))}).</p>"
        )
    for c in countries:
        evidence = "".join(
            f"<li>{_text(e.get('site'), 60)} · {_text(e.get('field'), 40)} · "
            f"{_text(e.get('signal'), 40)}"
            f" (waga {_text(e.get('weight'), 8)}): {_text(e.get('detail'), 200)}</li>"
            for e in map(_map, _seq(c.get("evidence")))
        )
        out.append(
            f'<div class="card"><b>Kraj: {_text(c.get("country"), 20)}</b> · '
            f"{_text(c.get('percent'), 8)}% głosów · siła: {_text(c.get('strength'), 20)}"
            f'<ul class="mut">{evidence}</ul></div>'
        )
    if geo.get("note"):
        out.append(f'<p class="mut">{_text(geo.get("note"), 300)}</p>')
    return "".join(out)


def _wayback_block(wayback: Mapping[str, object]) -> str:
    rows = []
    for entry in map(_map, _seq(wayback.get("profiles"))):
        snaps = []
        for s in [_map(x) for x in _seq(entry.get("snapshots"))[:5]]:
            stamp, original = s.get("timestamp"), s.get("original")
            archive = (
                f"https://web.archive.org/web/{stamp}/{original}"
                if isinstance(stamp, str) and stamp.isdigit() and isinstance(original, str)
                else None
            )
            snaps.append(_link(archive, stamp))
        error = entry.get("error")
        rows.append(
            (
                _link(entry.get("profile_url")),
                _text(entry.get("first_seen"), 20) or "—",
                _text(entry.get("last_seen"), 20) or "—",
                f'<span class="bad">błąd: {_text(error, 120)}</span>'
                if error
                else ", ".join(snaps) or "brak zrzutów",
            )
        )
    meta = (
        f"żądania: {_text(wayback.get('requests'))} z budżetu {_text(wayback.get('budget'))}, "
        f"błędy: {_text(wayback.get('errors'))}, "
        f"pominięte: {_text(wayback.get('skipped_over_budget'))}"
    )
    table = _table(("profil", "pierwszy zrzut", "ostatni zrzut", "zrzuty"), rows) if rows else ""
    return (
        "<h2>Archiwum (Wayback Machine)</h2>"
        '<p class="mut">Ślad w archiwum, nie dowód istnienia konta. '
        f"Błąd zapytania to nie brak zrzutu. {meta}</p>{table}"
    )


def _dorks_block(dorks: Mapping[str, object]) -> str:
    queries = "".join(f"<li><code>{_text(q, 400)}</code></li>" for q in _seq(dorks.get("queries")))
    sent = "" if dorks.get("sent") else " Nic nie zostało wysłane."
    return (
        '<h2>Dorki</h2><p class="mut">Zapytania do wklejenia w wyszukiwarkę.'
        f"{sent}</p><ul>{queries}</ul>"
    )


def _variants_block(variants: Mapping[str, object]) -> str:
    if variants.get("is_variant"):
        text = f"Wariant nazwy <code>{_text(variants.get('variant_of'), 80)}</code>."
    else:
        text = "Nazwa wpisana wprost (nie wariant)."
    return f'<p class="mut">{text}</p>'


# ------------------------------------------------------------------------------ top level


def _document(document: Mapping[str, object]) -> str:
    profiles = [_map(p) for p in _seq(document.get("profiles"))]
    summary = _map(document.get("summary"))
    counts = _map(summary.get("counts"))
    meta = _map(document.get("meta"))
    cells = "".join(
        f"<div><b>{_int(counts.get(key))}</b>{label}</div>"
        for key, label in (
            ("found", "FOUND"),
            ("probable", "PROBABLE"),
            ("not_found", "NOT_FOUND"),
            ("unknown", "UNKNOWN"),
            ("tested", "sprawdzone"),
            ("not_tested", "nie testowano"),
            ("request_attempts", "żądania"),
        )
    )
    mode = " · ".join(_text(meta.get(k), 40) for k in ("mode", "selection") if meta.get(k))
    parts = [
        f"<h2>Nazwa: <code>{_text(document.get('username'), 120)}</code>"
        + (f' <span class="badge">{mode}</span>' if mode else "")
        + "</h2>",
        f'<div class="card stats">{cells}</div>',
        _aggregate_block(document),
    ]
    if document.get("variants"):
        parts.append(_variants_block(_map(document.get("variants"))))
    economy = _map(document.get("request_economy"))
    if economy:
        parts.append(_economy_block(economy))
    parts.append("<h3>Trafienia (FOUND, PROBABLE)</h3>" + _hits(document))
    parts.append(_not_found_block(profiles))
    parts.append(_unknown_block(profiles))
    parts.append(_counts_block(summary))
    if document.get("geo"):
        parts.append(_geo_block(_map(document.get("geo"))))
    if document.get("wayback"):
        parts.append(_wayback_block(_map(document.get("wayback"))))
    if document.get("dorks"):
        parts.append(_dorks_block(_map(document.get("dorks"))))
    hit_keys = {str(p.get("profile_url")) for p in profiles if p.get("status") in HIT_STATUSES}
    extra = [
        e
        for e in map(_map, _seq(_map(document.get("identity")).get("profiles")))
        if str(e.get("profile_url")) not in hit_keys
        and not any(
            str(p.get("site")) == str(e.get("site"))
            for p in profiles
            if p.get("status") in HIT_STATUSES
        )
    ]
    if extra:
        parts.append(
            "<h2>Tożsamość: pozostałe profile</h2>"
            + "".join(
                f'<div class="card"><b>{_text(e.get("site"), 80)}</b> {_link(e.get("profile_url"))}'
                f"{_identity_block(e)}</div>"
                for e in extra
            )
        )
    return "".join(parts)


def render_report(
    documents: Sequence[Mapping[str, object]], *, generated_at: datetime | None = None
) -> str:
    """HTML page for one or more analyst documents (one section per scanned name)."""
    when = generated_at or datetime.now()
    names = ", ".join(_text(d.get("username"), 60) for d in documents)
    body = "".join(_document(d) for d in documents)
    return (
        '<!doctype html><html lang="pl"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{escape(CSP, quote=True)}">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>Raport: {names}</title><style>{CSS}</style></head><body><main>"
        f"<h1>Raport: {names}</h1>"
        f'<p class="mut">Wygenerowano {when:%Y-%m-%d %H:%M}. '
        "Ta sama nazwa nie oznacza tej samej osoby: "
        "trafienie to trop, nie dowód. Potwierdź profil przed wnioskami.</p>"
        f"{body}</main></body></html>"
    )
