"""Import baz WhatsMyName (CC BY-SA 4.0) i Maigret (MIT) do wspólnego schematu Site."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .models import Site
from .urlnorm import normalize_url

LIST_FIELDS = ("presenseStrs", "absenceStrs", "tags")


def from_wmn(data: dict) -> list[Site]:
    sites = []
    for s in data.get("sites", []):
        if s.get("valid") is False or not s.get("uri_check"):
            continue
        check = s["uri_check"].replace("{account}", "{username}")
        pretty = (s.get("uri_pretty") or "").replace("{account}", "{username}")
        body = s.get("post_body")
        sites.append(Site(
            name=s["name"],
            url=pretty or check,
            probe_url=check if pretty and pretty != check else None,
            method="POST" if body else "GET",
            headers=dict(s.get("headers") or {}),
            body=body.replace("{account}", "{username}") if body else None,
            check_type="message",
            e_code=s.get("e_code"),
            e_strings=[s["e_string"]] if s.get("e_string") else [],
            m_code=s.get("m_code"),
            m_strings=[s["m_string"]] if s.get("m_string") else [],
            tags=[s["cat"]] if s.get("cat") else [],
            source="wmn",
            known=list(s.get("known") or []),
        ))
    return sites


def _apply_engine(site: dict, engines: dict) -> dict:
    """Szablon silnika (XenForo, phpBB…) + nadpisania serwisu. Listy są łączone, skalary serwisu wygrywają."""
    engine = engines.get(site.get("engine") or "")
    if not engine:
        return dict(site)
    merged = dict(engine.get("site") or {})
    for key, value in site.items():
        if key in LIST_FIELDS and isinstance(value, list):
            merged[key] = list(dict.fromkeys(list(merged.get(key) or []) + value))
        else:
            merged[key] = value
    return merged


def _fill(template: str | None, s: dict) -> str | None:
    if not template:
        return None
    main = s.get("urlMain") or ""
    sub = s.get("urlSubpath") or ""
    out = template.replace("{urlSubpath}", sub)
    if "{urlMain}" in out:
        head, tail = out.split("{urlMain}", 1)
        if main.endswith("/") and tail.startswith("/"):
            tail = tail[1:]
        elif main and not main.endswith("/") and tail and not tail.startswith("/"):
            tail = "/" + tail
        out = head + main + tail
    return out


def from_maigret(data: dict, include_disabled: bool = False) -> list[Site]:
    engines = data.get("engines", {})
    sites = []
    for name, raw in data.get("sites", {}).items():
        s = _apply_engine(raw, engines)
        if s.get("disabled") and not include_disabled:
            continue
        if s.get("type") not in (None, "username"):
            continue  # identyfikatory innego typu (gaia_id, steam_id…) — poza zakresem
        url = _fill(s.get("url"), s)
        if not url or "{username}" not in url:
            continue
        presence, absence = s.get("presenseStrs") or [], s.get("absenceStrs") or []
        check_type = s.get("checkType") or ("message" if presence or absence else "status_code")
        payload = s.get("requestPayload")
        sites.append(Site(
            name=name,
            url=url,
            probe_url=_fill(s.get("urlProbe"), s),
            method=(s.get("requestMethod") or ("POST" if payload else "GET")).upper(),
            headers=dict(s.get("headers") or {}),
            body=json.dumps(payload) if isinstance(payload, (dict, list)) else payload,
            check_type=check_type,
            e_strings=list(presence) if check_type != "status_code" else [],
            m_strings=list(absence) if check_type != "status_code" else [],
            regex=s.get("regexCheck"),
            tags=list(s.get("tags") or []),
            source="maigret",
            known=[s["usernameClaimed"]] if s.get("usernameClaimed") else [],
        ))
    return sites


def from_custom(data: dict) -> list[Site]:
    """Własne, zweryfikowane reguły (resources/custom_sites.json) w schemacie Site. Mają pierwszeństwo przy scalaniu."""
    sites = []
    for d in data.get("sites", []):
        if d.get("disabled") or "{username}" not in d.get("url", ""):
            continue
        s = Site.from_dict(d)
        s.source = "custom"
        sites.append(s)
    return sites


def apply_tag_overrides(sites: list[Site], overrides: dict) -> int:
    """Dopisuje tagi do serwisów z upstreamu (WMN/Maigret) po nazwie, bez zmiany reguł. `overrides` to treść
    resources/tag_overrides.json: {"tags": {"Nazwa serwisu": ["tag", ...]}}. Zwraca liczbę zmienionych serwisów."""
    wanted = {name.lower(): tags for name, tags in (overrides.get("tags") or {}).items()}
    changed = 0
    for site in sites:
        extra = wanted.get(site.name.lower())
        if not extra:
            continue
        merged = list(dict.fromkeys([*site.tags, *extra]))
        if merged != site.tags:
            site.tags = merged
            changed += 1
    return changed


def site_tags(site: Site) -> list[str]:
    """site.tags plus 'pl', gdy host adresu profilu kończy się na '.pl' (np. .com.pl, {username}.blog.pl)."""
    tags = list(site.tags)
    host = urlsplit(site.url).hostname or ""
    if host.lower().endswith(".pl") and "pl" not in {t.lower() for t in tags}:
        tags.append("pl")
    return tags


def site_key(site: Site) -> str:
    """Klucz deduplikacji: domena bez www + ścieżka + query szablonu profilu (wspólna normalizacja, urlnorm.py).

    Wielkość liter ścieżki jest zachowana (/User i /user to różne zasoby), a query jest częścią klucza, bo w wielu
    szablonach (phpBB/SMF/XenForo, Maigret '/members/?username=...') nazwa użytkownika siedzi wyłącznie w query —
    bez niej różne serwisy na tym samym hoście/ścieżce cicho by się scalały. Fragment liczy się tylko wtedy, gdy
    jest szablonem ({username}). Niepoprawny adres: klucz = sam tekst szablonu (nie scala się z niczym innym).
    """
    key = normalize_url(site.url, keep_fragment=False)
    fragment = urlsplit(site.url).fragment if key else ""
    if not key:
        return site.url
    key += "#" + fragment if "{" in fragment else ""
    if "{username}" not in site.url:
        # nazwa tylko w treści zapytania: wspólny endpoint nie czyni reguł duplikatami
        key += f"\n{(site.method or 'GET').upper()}\n{site.body or ''}"
    return key


def merge(*groups: list[Site]) -> list[Site]:
    """Pierwsza grupa ma pierwszeństwo (WMN: ściślejsze reguły); z kolejnych dochodzą tylko nowe serwisy i tagi."""
    out: dict[str, Site] = {}
    names: set[str] = set()
    for group in groups:
        for site in group:
            key = site_key(site)
            if key in out:
                kept = out[key]
                kept.tags = list(dict.fromkeys(kept.tags + site.tags))
                continue
            # nazwa jest kluczem w health.json i raportach — musi być unikalna (03.10.2026: 19 kolizji WMN/Maigret);
            # przy kolejnych kolizjach (też w obrębie jednego źródła) dochodzi licznik: X [wmn], X [wmn 2], ...
            if site.name.lower() in names:
                base = f"{site.name} [{site.source or 'alt'}"
                candidate, n = base + "]", 1
                while candidate.lower() in names:
                    n += 1
                    candidate = f"{base} {n}]"
                site.name = candidate
            names.add(site.name.lower())
            out[key] = site
    return list(out.values())


def save_db(sites: list[Site], path: str | Path, meta: dict | None = None) -> None:
    """Zapis atomowy: plik tymczasowy + rename, żeby przerwany zapis nie uszkodził bazy."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"meta": meta or {}, "sites": [s.to_dict() for s in sites]}
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_db(path: str | Path, warn: Callable[[str], None] | None = None) -> list[Site]:
    """Wczytuje bazę. Wadliwy wpis (zły typ pola, brak nazwy/adresu) jest pomijany z ostrzeżeniem (`warn`,
    domyślnie stderr) — jeden zepsuty wpis nie blokuje całej bazy."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("sites"), list):
        raise ValueError(f"{path}: niepoprawny format bazy (oczekiwano {{'sites': [...]}})")
    warn = warn or (lambda msg: print(f"Ostrzeżenie: {msg}", file=sys.stderr))
    sites = []
    for i, d in enumerate(doc["sites"]):
        try:
            sites.append(Site.from_dict(d))
        except (ValueError, TypeError) as e:
            warn(f"pominięto wpis #{i} bazy {path}: {e}")
    return sites
