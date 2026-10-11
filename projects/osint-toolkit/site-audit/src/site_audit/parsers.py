"""Czyste parsery (bez sieci): HSTS, CSP, Set-Cookie, security.txt, robots.txt, sitemap, HTML."""

from __future__ import annotations

import re
from xml.parsers import expat
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

# --------------------------------------------------------------------- HSTS

_DIGITS = re.compile(r"[0-9]{1,15}")


@dataclass
class Hsts:
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    errors: list[str] = field(default_factory=list)


def parse_hsts(value: str) -> Hsts:
    """RFC 6797: dyrektywy rozdzielone ';', bez rozroznienia wielkosci liter, max-age wymagane."""
    h = Hsts()
    seen: set[str] = set()
    for raw in value.split(";"):
        part = raw.strip()
        if not part:
            continue
        name, _, val = part.partition("=")
        name = name.strip().lower()
        if name in seen:
            h.errors.append(f"powtórzona dyrektywa {name}")
            continue
        seen.add(name)
        if name == "max-age":
            v = val.strip().strip('"')
            if _DIGITS.fullmatch(v):  # isdigit() przepuszcza np. "²", ktorego int() nie przyjmie
                h.max_age = int(v)
            else:
                h.errors.append(f"nieprawidłowe max-age={val.strip()!r}")
        elif name == "includesubdomains":
            h.include_subdomains = True
        elif name == "preload":
            h.preload = True
    if h.max_age is None and not any(e.startswith("nieprawidłowe max-age") for e in h.errors):
        h.errors.append("brak max-age")
    return h


# ---------------------------------------------------------------------- CSP

# CSP3: elementy <script>, atrybuty zdarzen i eval() maja osobne lancuchy zastepstwa
SCRIPT_ELEM = ("script-src-elem", "script-src", "default-src")
SCRIPT_ATTR = ("script-src-attr", "script-src", "default-src")
SCRIPT_EVAL = ("script-src", "default-src")
WILDCARD_SOURCES = ("*", "http:", "https:", "data:", "blob:")


def parse_csp(value: str) -> dict[str, list[str]]:
    """CSP3: dyrektywy po ';', pierwsze wystapienie wygrywa, nazwy bez rozroznienia wielkosci."""
    out: dict[str, list[str]] = {}
    for raw in value.split(";"):
        tokens = raw.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in out:
            out[name] = tokens[1:]
    return out


def _has_nonce_or_hash(tokens: list[str]) -> bool:
    return any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in tokens)


def frame_ancestors_open(policy: dict[str, list[str]]) -> bool | None:
    """None: brak dyrektywy; True: dopuszcza dowolne strony (*, http:, https:)."""
    if "frame-ancestors" not in policy:
        return None
    return any(t.lower() in ("*", "http:", "https:") for t in policy["frame-ancestors"])


def csp_effective(policy: dict[str, list[str]], *names: str) -> tuple[str | None, list[str]]:
    for n in names:
        if n in policy:
            return n, policy[n]
    return None, []


def csp_issues(policy: dict[str, list[str]]) -> list[str]:
    """Slabosci polityki. Zwraca opisy po polsku (puste = brak uwag)."""
    issues: list[str] = []
    name, script = csp_effective(policy, *SCRIPT_ELEM)
    if name is None:
        issues.append("brak script-src i default-src: skrypty z dowolnego źródła")
    else:
        low = [t.lower() for t in script]
        if "'unsafe-inline'" in low and not _has_nonce_or_hash(low):
            issues.append(f"{name} dopuszcza 'unsafe-inline' bez nonce/hash (XSS przez wstrzyknięty skrypt)")
        if "'strict-dynamic'" not in low:
            wild = sorted({t for t in low if t in WILDCARD_SOURCES})
            if wild:
                issues.append(f"{name} dopuszcza szerokie źródła: {' '.join(wild)}")
    attr_name, attr = csp_effective(policy, *SCRIPT_ATTR)
    if attr_name is not None and attr_name != name:
        low = [t.lower() for t in attr]
        if "'unsafe-inline'" in low and not _has_nonce_or_hash(low):
            issues.append(f"{attr_name} dopuszcza skrypty w atrybutach zdarzeń (onclick=...)")
    eval_name, ev = csp_effective(policy, *SCRIPT_EVAL)
    if eval_name is not None and "'unsafe-eval'" in [t.lower() for t in ev]:
        issues.append(f"{eval_name} dopuszcza 'unsafe-eval'")
    obj_name, obj = csp_effective(policy, "object-src", "default-src")
    if obj_name is None or [t.lower() for t in obj] != ["'none'"]:
        issues.append("object-src nie jest 'none' (wtyczki/obiekty)")
    if "base-uri" not in policy:
        issues.append("brak base-uri (podmiana <base> przy wstrzyknięciu HTML)")
    return issues


# ------------------------------------------------------------------ Cookies


@dataclass
class Cookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    session: bool = True


def parse_set_cookie(value: str) -> Cookie | None:
    parts = value.split(";")
    name, sep, _ = parts[0].partition("=")
    name = name.strip()
    if not sep or not name:
        return None
    c = Cookie(name)
    for raw in parts[1:]:
        k, _, v = raw.strip().partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "secure":
            c.secure = True
        elif k == "httponly":
            c.httponly = True
        elif k == "samesite":
            c.samesite = v.capitalize() if v else ""
        elif k == "domain":
            c.domain = v.lstrip(".").lower() or None
        elif k == "path":
            c.path = v or None
        elif k in ("expires", "max-age"):
            c.session = False
    return c


def cookie_issues(c: Cookie, https: bool) -> list[tuple[str, str]]:
    """(waga, opis). Wagi jako tekst, zeby parser nie zalezal od models."""
    out: list[tuple[str, str]] = []
    if c.name.startswith("__Host-") and (not c.secure or c.domain or c.path != "/"):
        out.append(("FAIL", "prefiks __Host- wymaga Secure, Path=/ i braku Domain (przeglądarka odrzuci)"))
    elif c.name.startswith("__Secure-") and not c.secure:
        out.append(("FAIL", "prefiks __Secure- wymaga Secure (przeglądarka odrzuci)"))
    if c.samesite == "None" and not c.secure:
        out.append(("FAIL", "SameSite=None bez Secure (przeglądarki odrzucają)"))
    if https and not c.secure:
        out.append(("WARN", "brak Secure: ciasteczko może wyciec przez HTTP"))
    if not c.httponly:
        out.append(("INFO", "brak HttpOnly: dostępne dla JavaScriptu (ok tylko, jeśli skrypt go potrzebuje)"))
    if c.samesite is None:
        out.append(("INFO", "brak SameSite (przeglądarka przyjmie Lax)"))
    elif c.samesite not in ("Lax", "Strict", "None"):
        out.append(("WARN", f"nieznana wartość SameSite={c.samesite!r}"))
    return out


# ------------------------------------------------------------- security.txt

_PGP_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----"
_PGP_SIG = "-----BEGIN PGP SIGNATURE-----"
SECURITY_TXT_FIELDS = (
    "acknowledgments", "canonical", "contact", "encryption", "expires",
    "hiring", "policy", "preferred-languages", "csaf",
)


@dataclass
class SecurityTxt:
    fields: dict[str, list[str]] = field(default_factory=dict)
    signed: bool = False
    unknown: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    expires: datetime | None = None


def parse_security_txt(text: str) -> SecurityTxt:
    """RFC 9116. Podpis PGP rozpoznawany (nie weryfikowany)."""
    st = SecurityTxt()
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[0].strip() == _PGP_BEGIN:
        st.signed = True
        # naglowki "Hash: ..." do pierwszej pustej linii, tresc do podpisu
        try:
            start = lines.index("", 1) + 1
        except ValueError:
            start = 1
        end = next((i for i, l in enumerate(lines) if l.strip() == _PGP_SIG), len(lines))
        lines = [l[2:] if l.startswith("- ") else l for l in lines[start:end]]
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        name, sep, val = s.partition(":")
        if not sep:
            st.errors.append(f"linia bez dwukropka: {s[:60]!r}")
            continue
        key = name.strip().lower()
        val = val.strip()
        if key in SECURITY_TXT_FIELDS:
            st.fields.setdefault(key, []).append(val)
        else:
            st.unknown.append(key)
    if "contact" not in st.fields:
        st.errors.append("brak wymaganego pola Contact")
    exp = st.fields.get("expires", [])
    if not exp:
        st.errors.append("brak wymaganego pola Expires")
    else:
        if len(exp) > 1:
            st.errors.append("pole Expires występuje więcej niż raz")
        st.expires = parse_rfc3339(exp[0])
        if st.expires is None:
            st.errors.append(f"Expires nie jest datą RFC 3339: {exp[0]!r}")
    for key in ("preferred-languages",):
        if len(st.fields.get(key, [])) > 1:
            st.errors.append(f"pole {key} występuje więcej niż raz")
    return st


def parse_rfc3339(value: str) -> datetime | None:
    v = value.strip()
    if v.endswith(("Z", "z")):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


# ---------------------------------------------------------------- robots.txt


@dataclass
class Robots:
    groups: int = 0
    disallow: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    blocks_all: bool = False   # User-agent: * + Disallow: /


def parse_robots(text: str) -> Robots:
    r = Robots()
    seen_dis: set[str] = set()
    seen_maps: set[str] = set()
    agents: list[str] = []
    in_rules = False
    star_disallow: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        k, sep, v = s.partition(":")
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if k == "user-agent":
            if in_rules:
                agents, in_rules = [], False
            if not agents:
                r.groups += 1
            agents.append(v.lower())
        elif k in ("allow", "disallow"):
            in_rules = True
            if k == "disallow" and v:
                if v not in seen_dis:
                    seen_dis.add(v)
                    r.disallow.append(v)
                if "*" in agents:
                    star_disallow.append(v)
        elif k == "sitemap" and v and v not in seen_maps:
            seen_maps.add(v)
            r.sitemaps.append(v)
    r.blocks_all = "/" in star_disallow
    return r


# ------------------------------------------------------------------ sitemap


@dataclass
class Sitemap:
    kind: str | None = None      # urlset | sitemapindex
    count: int = 0
    error: str | None = None


class _Refused(Exception):
    pass


def parse_sitemap(body: bytes) -> Sitemap:
    """Strumieniowo przez expat. DTD i encje odrzucane w parserze, wiec takze w UTF-16."""
    state = {"depth": 0, "root": None, "count": 0}

    def refuse(*_a):
        raise _Refused()

    def start(name, _attrs):
        local = name.rsplit(" ", 1)[-1].rsplit("}", 1)[-1]
        if state["depth"] == 0:
            state["root"] = local
        elif state["depth"] == 1 and local == ("url" if state["root"] == "urlset" else "sitemap"):
            state["count"] += 1
        state["depth"] += 1

    def end(_name):
        state["depth"] -= 1

    parser = expat.ParserCreate(namespace_separator=" ")
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(body, True)
    except _Refused:
        return Sitemap(error="sitemap zawiera DOCTYPE/ENTITY: nie parsuję (ochrona przed bombą XML)")
    except expat.ExpatError as exc:
        return Sitemap(error=f"niepoprawny XML: {exc}")
    if state["root"] not in ("urlset", "sitemapindex"):
        return Sitemap(error=f"nieoczekiwany element główny <{state['root']}>")
    return Sitemap(kind=state["root"], count=state["count"])


# --------------------------------------------------------------------- HTML

_MIXED_ATTRS = {
    "script": ("src", "aktywna"), "iframe": ("src", "aktywna"), "frame": ("src", "aktywna"),
    "embed": ("src", "aktywna"), "object": ("data", "aktywna"),
    "img": ("src", "pasywna"), "audio": ("src", "pasywna"), "video": ("src", "pasywna"),
    "source": ("src", "pasywna"),
}
_VERSION_RE = re.compile(r"\d+(\.\d+)+")


@dataclass
class Page:
    title: str | None = None
    description: str | None = None
    generator: str | None = None
    canonical: str | None = None
    mixed_active: list[str] = field(default_factory=list)
    mixed_passive: list[str] = field(default_factory=list)
    insecure_forms: list[str] = field(default_factory=list)
    external_scripts_without_sri: list[str] = field(default_factory=list)
    links_internal: int = 0
    links_external: int = 0
    incomplete: str | None = None   # parser przerwany: analiza tresci niepelna


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url if not url.startswith("//") else "https:" + url).hostname or "").lower()
    except ValueError:
        return ""


class _PageParser(HTMLParser):
    def __init__(self, host: str):
        super().__init__(convert_charrefs=True)
        self.page = Page()
        self.host = host
        self._in_title = False
        self._title: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        p = self.page
        if tag == "title" and p.title is None:
            self._in_title = True
        elif tag == "meta":
            name = a.get("name", "").lower()
            if name == "description" and p.description is None:
                p.description = a.get("content", "").strip()[:300]
            elif name == "generator" and p.generator is None:
                p.generator = a.get("content", "").strip()[:120]
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            href = a.get("href", "")
            if "canonical" in rel and p.canonical is None:
                p.canonical = href
            if "stylesheet" in rel and href.lower().startswith("http://"):
                p.mixed_active.append(href)
        elif tag == "form":
            action = a.get("action", "")
            if action.lower().startswith("http://"):
                p.insecure_forms.append(action)
        elif tag == "a":
            href = a.get("href", "")
            if href.lower().startswith(("http://", "https://", "//")):
                h = _host_of(href)
                if h == self.host or h.endswith("." + self.host):
                    p.links_internal += 1
                else:
                    p.links_external += 1
            elif href and not href.lower().startswith(("#", "mailto:", "tel:", "javascript:")):
                p.links_internal += 1
        if tag in _MIXED_ATTRS:
            attr, kind = _MIXED_ATTRS[tag]
            url = a.get(attr, "")
            if url.lower().startswith("http://"):
                (p.mixed_active if kind == "aktywna" else p.mixed_passive).append(url)
        if tag == "script":
            src = a.get("src", "")
            if src.lower().startswith(("https://", "//")) and "integrity" not in a:
                h = _host_of(src)
                if h and h != self.host and not h.endswith("." + self.host):
                    p.external_scripts_without_sri.append(src)

    def handle_endtag(self, tag):
        if tag == "title" and self._in_title:
            self._in_title = False
            self.page.title = " ".join("".join(self._title).split())[:200] or None

    def handle_data(self, data):
        if self._in_title:
            self._title.append(data)


def parse_page(html_text: str, host: str) -> Page:
    parser = _PageParser(host.lower())
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # HTMLParser bywa wrazliwy na skrajnie zepsuty HTML: zwracamy to, co zebrane
        parser.page.incomplete = f"{type(exc).__name__}: {exc}"[:200]
    return parser.page


def discloses_version(value: str | None) -> bool:
    return bool(value and _VERSION_RE.search(value))
