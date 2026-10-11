"""Import wyniku meta-search (--json): profil Threads / konto profesjonalne Instagram z oficjalnego API -> Username +
konto (URL, kind=profile, relacja has_account), posty (wyszukiwanie Threads, media Instagrama) -> autor (Username) + post
(URL, kind=post, relacja authored), Strona Facebooka -> Organizacja (kind=facebook_page) + jej URL (relacja has_page;
nazwa zawiera id Strony, więc Strona nie scala się sama z firmą o tej samej nazwie). Pochodzenie (API, endpoint,
czas pobrania) zostaje na węzłach. Brak wyniku, brak konfiguracji i błędy nie tworzą węzłów: brak wyniku to UNKNOWN (API pokazuje tylko
część profili), błędy to ERROR. Treści postów i bio nie są przenoszone (minimalizacja danych); z profilu zostają sygnały
potrzebne do porównania: strona www, adresy z bio i odcisk bio (skróty słów, bez treści)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from ..evidence import bio_fingerprint
from ..model import Status
from ..normalize import normalize_url
from ..normalize import EntityType
from .base import ImportCtx, Imported, failed

TOOL = "meta-search"
MAX_ITEMS = 100
ERROR_STATUSES = {"auth_error", "permission_denied", "rate_limited", "source_error", "invalid_input"}
IDENTITY = "Ta sama nazwa nie dowodzi tej samej osoby"
OPERATIONS = {"threads_profile": ("threads", {"profile"}), "threads_search": ("threads", {"post"}),
              "instagram_profile": ("instagram", {"profile", "post"}), "facebook_page": ("facebook", {"page"})}
HOSTS = {"threads": {"threads.com", "www.threads.com", "threads.net", "www.threads.net"},
         "instagram": {"instagram.com", "www.instagram.com"}, "facebook": {"facebook.com", "www.facebook.com"}}


def _url(raw, platform: str) -> str:
    if not isinstance(raw, str) or re.search(r"[\x00-\x20\x7f]", raw):
        raise ValueError("nieprawidlowy URL")
    parts = urlsplit(raw)
    if parts.scheme != "https" or parts.hostname not in HOSTS.get(platform, set()) or parts.username or parts.password \
            or parts.port not in (None, 443):
        raise ValueError("URL spoza platformy")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def detect(data) -> bool:
    return isinstance(data, dict) and data.get("tool") == TOOL and isinstance(data.get("schema"), int)


def _origin(data: dict) -> dict:
    src = data.get("source") if isinstance(data.get("source"), dict) else {}
    try:
        endpoint = urlsplit(str(src.get("endpoint", "")))
        clean_endpoint = urlunsplit((endpoint.scheme, endpoint.hostname or "", endpoint.path, "", ""))
    except ValueError:
        clean_endpoint = ""
    return {"source_kind": str(src.get("kind", ""))[:30], "source_endpoint": clean_endpoint[:200],
            "fetched_at": str(data.get("fetched_at", ""))[:40]}


URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']{3,300}")
MAX_LINKS = 10


def _profile_signals(it: dict) -> dict:
    """Pola do porównania profili: nazwa, strona www, adresy z bio, odcisk bio. Treść bio nie zostaje."""
    out: dict = {}
    if it.get("name"):
        out["display_name"] = str(it["name"])[:120]
    website = it.get("website")
    if isinstance(website, str) and website.startswith(("http://", "https://")):
        try:
            out["website"] = normalize_url(website)[1][:300]
        except ValueError:
            pass
    bio = it.get("biography") if isinstance(it.get("biography"), str) else ""
    links = []
    for raw in URL_IN_TEXT.findall(bio[:2000]):
        try:
            links.append(normalize_url(raw.rstrip(".,;)"))[1])
        except ValueError:
            continue
    if links:
        out["links"] = list(dict.fromkeys(links))[:MAX_LINKS]
    if bio:
        out["bio_fingerprint"] = bio_fingerprint(bio)
    return out


def _account(it: dict, kind: str, ctx: ImportCtx, platform: str, origin: dict, op: str):
    url = it.get("profile_url") if kind == "profile" else it.get("permalink")
    name = it.get("username")
    if not url or not name:
        return None
    url = _url(url, platform)
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._]{1,30}", name):
        return None
    if kind == "profile":
        expected = "/@" + name if platform == "threads" else "/" + name
        if urlsplit(url).path.rstrip("/").lower() != expected.lower():
            return None
    user = ctx.node(EntityType.USERNAME, str(name))
    attrs = {"kind": kind, "site": platform.capitalize(), **origin}
    if kind == "profile":
        attrs.update(_profile_signals(it))
    if kind == "post" and it.get("timestamp"):
        attrs["published"] = str(it["timestamp"])[:40]
    target = ctx.node(EntityType.URL, str(url), attrs)
    evidence = (f"{TOOL}: {op} ({origin['source_endpoint']}, {origin['fetched_at']}): "
                + ("dokładny nick w oficjalnym API. " if kind == "profile" else "autor posta wg API. ") + IDENTITY)
    return user, target, ctx.edge(op, user, target, "has_account" if kind == "profile" else "authored", 1.0, evidence)


def _page(it: dict, ctx: ImportCtx, platform: str, origin: dict, op: str):
    """Strona Facebooka (organizacja/marka/osoba publiczna z publicznych metadanych), nie profil prywatny."""
    page_id, name, url = str(it.get("id") or "")[:40], str(it.get("name") or "")[:120], it.get("link")
    if not page_id or not name or not url:
        return None
    if not page_id.isascii() or not page_id.isdigit():
        return None
    url = _url(url, platform)
    attrs = {"kind": "facebook_page", "site": platform.capitalize(), "page_id": page_id, "page_name": name, **origin}
    if it.get("category"):
        attrs["category"] = str(it["category"])[:100]
    if it.get("verification_status"):
        attrs["verification_status"] = str(it["verification_status"])[:30]
    org = ctx.node(EntityType.ORGANIZATION, f"{name} [Facebook {page_id}]", attrs)
    target = ctx.node(EntityType.URL, str(url), {"kind": "page", "site": platform.capitalize(), **origin})
    evidence = (f"{TOOL}: {op} ({origin['source_endpoint']}, {origin['fetched_at']}): publiczne dane Strony wg "
                "oficjalnego API. Nazwa Strony nie dowodzi powiązania z firmą ani osobą o tej samej nazwie")
    return org, target, ctx.edge(op, org, target, "has_page", 1.0, evidence)


def parse(data: dict, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    if type(data.get("schema")) is not int or data["schema"] != 1:
        return failed(TOOL, "nieobslugiwana wersja schematu")
    status, op = str(data.get("status", "")), str(data.get("operation", ""))
    label = f"{op}:{str(data.get('query', ''))[:50]}"
    message = str(data.get("message", ""))[:300]
    if status in ERROR_STATUSES:
        imp.runs.append((label, Status.ERROR, f"{data.get('status_label') or status}: {message}"))
        return imp
    if status in ("no_result", "not_configured", "manual"):
        why = {"no_result": "brak wyniku w API - to nie dowód braku konta",
               "not_configured": "API nie skonfigurowane - nic nie sprawdzono",
               "manual": "tylko linki do ręcznego sprawdzenia - nic nie sprawdzono"}[status]
        imp.runs.append((label, Status.UNKNOWN, why))
        return imp
    if status != "found":
        return failed(TOOL, f"nieznany status wyniku: {status[:30]}")
    origin, platform = _origin(data), str(data.get("platform", ""))[:30]
    if op not in OPERATIONS or platform != OPERATIONS[op][0]:
        return failed(TOOL, "niezgodna platforma lub operacja")
    if origin["source_kind"] != "api":
        return failed(TOOL, "import obsługuje tylko wyniki z oficjalnego API (source.kind=api)")
    items = data.get("items") if isinstance(data.get("items"), list) else []
    added = 0
    for it in items[:MAX_ITEMS]:
        if not isinstance(it, dict):
            continue
        kind = it.get("type")
        if not isinstance(kind, str) or kind not in OPERATIONS[op][1]:
            continue
        try:
            if kind == "page":
                pair = _page(it, ctx, platform, origin, op)
            elif kind in ("profile", "post"):
                pair = _account(it, kind, ctx, platform, origin, op)
            else:
                continue
        except ValueError:
            continue
        if pair is None:
            continue
        imp.nodes += pair[:2]
        imp.edges.append(pair[2])
        added += 1
    if not added:
        imp.runs.append((label, Status.ERROR, "wynik 'found' bez poprawnych pozycji"))
    else:
        imp.runs.append((label, Status.FOUND, f"{added} pozycji z oficjalnego API"))
    return imp
