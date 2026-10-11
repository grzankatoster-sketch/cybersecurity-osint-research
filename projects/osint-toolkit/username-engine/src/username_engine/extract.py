"""Wyciąganie danych z pobranej strony/API znalezionego profilu: nazwa, bio, lokalizacja, avatar, strona www,
data założenia, linki do innych kont. Bez sieci — działa na odpowiedzi, którą skan już pobrał.
Treść strony nie jest przechowywana; zostają tylko wyciągnięte pola (minimalizacja danych)."""
from __future__ import annotations

import json
import re
from html import unescape
from html.parser import HTMLParser

MAX_FIELD = 300

# klucze JSON (API serwisów) -> nasze pole; porównanie bez wielkości liter i podkreśleń
JSON_KEYS = {
    "location": ("location", "loc", "city", "hometown", "homelocation", "country", "countrycode", "region",
                 "address", "geo", "place"),
    "name": ("name", "fullname", "displayname", "realname", "nickname"),
    "bio": ("bio", "description", "about", "aboutme", "summary", "note", "headline", "tagline"),
    # bez "url"/"link": w API (np. GitHub) to adres samego API, nie strona właściciela
    "website": ("blog", "website", "homepage", "websiteurl", "personalwebsite"),
    "avatar": ("avatarurl", "avatar", "profileimageurl", "image", "picture", "photo", "iconimg", "avatarlarge"),
    "created": ("createdat", "created", "joined", "joindate", "registered", "createdutc", "membersince",
                "creationdate", "datejoined"),
}
_KEY_INDEX = {k: field for field, keys in JSON_KEYS.items() for k in keys}

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)


def _norm_key(k: str) -> str:
    return re.sub(r"[_\-\s]", "", k).lower()


def _clip(v) -> str | None:
    if v is None or isinstance(v, (dict, list, bool)):
        return None
    s = unescape(str(v)).strip()
    return s[:MAX_FIELD] if s else None


_ID_KEYS = {"login", "username", "userid", "screenname", "handle", "nick", "nickname", "acct", "preferredusername",
            "slug", "uniqueid", "usernamedisplay"}


def _is_subject(d: dict, username: str) -> bool:
    """Obiekt opisuje sprawdzane konto: jego login/username/screen_name... == nazwa (bez wielkości liter, bez @host)."""
    want = username.lower()
    for k, v in d.items():
        if _norm_key(str(k)) in _ID_KEYS and isinstance(v, str) and v.lstrip("@").lower().split("@")[0] == want:
            return True
    return False


def _find_subject(obj, username: str, depth: int = 0):
    """Pierwszy (najpłytszy) obiekt JSON opisujący konto o danej nazwie albo None."""
    level = [obj]
    for _ in range(5):
        nxt = []
        for node in level:
            if isinstance(node, dict):
                if _is_subject(node, username):
                    return node
                nxt.extend(v for v in node.values() if isinstance(v, (dict, list)))
            elif isinstance(node, list):
                nxt.extend(v for v in node[:20] if isinstance(v, (dict, list)))
        level = nxt
        if not level:
            break
    return None


def _walk_json(obj, out: dict, depth: int = 0) -> None:
    """Pola z własnych kluczy obiektu mają pierwszeństwo przed zagnieżdżonymi (organizacja przed profilem)."""
    if depth > 3:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            field = _KEY_INDEX.get(_norm_key(str(k)))
            if field and field not in out:
                if isinstance(v, dict) and field == "location":       # {"location": {"name": "Kraków"}}
                    v = v.get("name") or v.get("city") or v.get("country")
                val = _clip(v)
                if val:
                    out[field] = val
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _walk_json(v, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:5]:
            _walk_json(item, out, depth + 1)


class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.ld_json: list[str] = []
        self.lang: str | None = None
        self._in_ld = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and a.get("lang"):
            self.lang = a["lang"].split("-")[0].lower()[:5]
        elif tag == "meta":
            key = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            if key and a.get("content") and key not in self.meta:
                self.meta[key] = a["content"]
        elif tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_ld, self._buf = True, []

    def handle_data(self, data):
        if self._in_ld:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_ld:
            self._in_ld = False
            self.ld_json.append("".join(self._buf))


def _from_ld(blocks: list[str], out: dict) -> None:
    for raw in blocks:
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        items = data if isinstance(data, list) else data.get("@graph", [data]) if isinstance(data, dict) else []
        for it in items:
            if not isinstance(it, dict):
                continue
            main = it.get("mainEntity") if isinstance(it.get("mainEntity"), dict) else it
            if main.get("@type") not in ("Person", "ProfilePage", "Organization") and it is main:
                continue
            addr = main.get("address") or main.get("homeLocation")
            if isinstance(addr, dict):
                parts = [addr.get(k) for k in ("addressLocality", "addressRegion", "addressCountry", "name")]
                addr = ", ".join(str(p if not isinstance(p, dict) else p.get("name", "")) for p in parts if p)
            for field, val in (("name", main.get("name")), ("bio", main.get("description")),
                               ("location", addr), ("nationality", main.get("nationality")),
                               ("avatar", main.get("image") if isinstance(main.get("image"), str) else None)):
                if isinstance(val, dict):
                    val = val.get("name")
                v = _clip(val)
                if v and field not in out:
                    out[field] = v
            same = main.get("sameAs")
            if same:
                out.setdefault("_links", []).extend(same if isinstance(same, list) else [same])


def extract_profile(text: str, content_type: str = "", username: str | None = None) -> dict:
    """Zwraca słownik z polami: name, bio, location, nationality, website, avatar, created, links, page_lang.
    Puste pola są pomijane. Z `username` dane JSON pochodzą z obiektu opisującego to konto (jeśli da się go
    wskazać), a nie z pierwszej napotkanej organizacji czy innego użytkownika."""
    out: dict = {}
    t = text.lstrip()
    if "json" in content_type.lower() or t[:1] in "{[":
        try:
            data = json.loads(t)
            subject = _find_subject(data, username) if username else None
            _walk_json(data if subject is None else subject, out)
        except ValueError:
            pass
    if not out and "<" in t[:2000]:
        p = _MetaParser()
        try:
            p.feed(text[:1_000_000])
        except Exception:
            pass
        _from_ld(p.ld_json, out)
        m = p.meta
        for field, keys in (("name", ("og:title", "twitter:title", "profile:username")),
                            ("bio", ("og:description", "description", "twitter:description")),
                            ("avatar", ("og:image", "twitter:image")),
                            ("location", ("geo.placename", "og:locality", "og:country-name", "geo.region"))):
            if field not in out:
                for k in keys:
                    v = _clip(m.get(k))
                    if v:
                        out[field] = v
                        break
        if p.lang:
            out["page_lang"] = p.lang
    links = list(dict.fromkeys(
        [u.rstrip(".,") for u in out.pop("_links", []) if isinstance(u, str)]
        + URL_RE.findall(out.get("bio", "")) + ([out["website"]] if out.get("website", "").startswith("http") else [])
    ))
    if links:
        out["links"] = links[:15]
    return out
