"""Adresy kandydatów profili: walidacja, kanonizacja i klasyfikacja (bez sieci).

Zasady:
  * tylko http(s), bez danych logowania w adresie (userinfo), bez spacji i znaków sterujących;
  * serwis rozpoznawany po FAKTYCZNEJ nazwie hosta (równa domenie albo jej subdomena), nigdy po podciągu:
    ``facebook.com.example.org`` i ``evilfacebook.com`` to nie Facebook;
  * kanonizacja: https, host bez www/m., bez parametrów śledzących i zbędnych; zostają identyfikatory
    (``profile.php?id=``, ``story_fbid``, ``fbid``, ``v``). Różne ``id`` = różne adresy. Małe litery tylko w hoście,
    słowach kluczowych ścieżki (``p``, ``posts``, ``groups``...) i nazwach kont (Facebook vanity, Instagram, Threads),
    które serwisy traktują bez wielkości liter; kody postów (``/p/AbC``) i nierozpoznane ścieżki zachowują pisownię;
  * adres z danymi kontaktowymi, logowania albo sekretami (e-mail, telefon, token, hasło itp. w ścieżce, zapytaniu
    lub fragmencie) nie jest zapisywany w żadnej postaci: :func:`persist_problem` podaje przyczynę odrzucenia;
  * klasa adresu opisuje KSZTAŁT URL-a, nie osobę: „prawdopodobny profil” to wciąż hipoteza (na Facebooku adres
    profilu i strony wyglądają tak samo). Niejasne adresy to „nieustalony” i zostają do przeglądu.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlsplit

from .normalize import normalize_url

MAX_URL = 2048
OTHER = "inny serwis"
CLASS_PROFILE = "prawdopodobny profil"
CLASS_POST = "post lub treść"
CLASS_GROUP = "grupa"
CLASS_ORG = "strona organizacji"
CLASS_UNKNOWN = "nieustalony"
# klasy, które mogą być kontem osoby (do decyzji operatora); post, grupa i strona organizacji nie są kontem
ACCOUNT_CLASSES = (CLASS_PROFILE, CLASS_UNKNOWN)

# domena bazowa -> (host kanoniczny, nazwa serwisu)
PLATFORMS = {
    "facebook.com": ("facebook.com", "Facebook"),
    "fb.com": ("facebook.com", "Facebook"),
    "instagram.com": ("instagram.com", "Instagram"),
    "threads.com": ("threads.com", "Threads"),
    "threads.net": ("threads.com", "Threads"),
}
_FB_RESERVED = frozenset(
    {
        "login",
        "login.php",
        "help",
        "policies",
        "policy.php",
        "privacy",
        "legal",
        "about",
        "settings",
        "home.php",
        "search",
        "public",
        "directory",
        "gaming",
        "business",
        "ads",
        "notes",
        "media",
        "messages",
        "friends",
        "bookmarks",
        "recover",
        "checkpoint",
        "dialog",
        "sharer",
        "sharer.php",
        "l.php",
        "plugins",
        "terms",
    }
)
_FB_POST_ROOTS = frozenset(
    {
        "permalink.php",
        "story.php",
        "photo.php",
        "watch",
        "reel",
        "reels",
        "videos",
        "events",
        "share",
        "posts",
        "photo",
        "stories",
        "marketplace",
        "hashtag",
        "live",
    }
)
_FB_POST_SUB = frozenset(
    {"posts", "videos", "photos", "photo", "reels", "reel", "permalink", "notes", "events", "live_videos"}
)
_FB_PROFILE_SUB = frozenset({"about", "friends", "followers", "following", "photos_by", "reviews"})
_FB_KEEP = {
    "profile.php": ("id",),
    "permalink.php": ("story_fbid", "id"),
    "story.php": ("story_fbid", "id"),
    "photo.php": ("fbid",),
    "watch": ("v",),
}
_IG_RESERVED = frozenset(
    {
        "accounts",
        "about",
        "developer",
        "legal",
        "direct",
        "web",
        "directory",
        "privacy",
        "help",
        "explore",
        "emails",
        "challenge",
        "session",
        "graphql",
        "api",
    }
)
_IG_POST = frozenset({"p", "reel", "reels", "tv", "stories"})
_IG_PROFILE_SUB = frozenset({"reels", "tagged", "followers", "following", "guides", "saved"})
_IG_HANDLE = re.compile(r"[a-z0-9._]{1,30}")
_FB_VANITY = re.compile(r"[a-z0-9.\-]{2,80}")
_BAD = re.compile(r"[\s\x00-\x1f\x7f]")


@dataclass(frozen=True)
class ProfileUrl:
    source: str  # adres taki, jak przyszedł (po walidacji)
    canonical: str  # adres kanoniczny (klucz deduplikacji)
    platform: str  # Facebook / Instagram / Threads / inny serwis
    url_class: str  # jedna z CLASS_*
    identifier: dict = field(default_factory=dict)  # {"type": "id"|"nazwa", "value": ...} z adresu, jeśli jest

    @property
    def is_account(self) -> bool:
        return self.url_class in ACCOUNT_CLASSES


def platform_of(host: str) -> tuple[str, str] | None:
    """(host kanoniczny, serwis) dla nazwy hosta równej domenie serwisu albo jej subdomeny; inaczej None."""
    host = host.lower().rstrip(".")
    for base, value in PLATFORMS.items():
        if host == base or host.endswith("." + base):
            return value
    return None


def _validate(raw: object):
    if not isinstance(raw, str):
        raise ValueError("adres: oczekiwano tekstu")  # noqa: TRY004 - wywołujący łapią ValueError
    text = raw.strip()
    if not text or len(text) > MAX_URL or _BAD.search(text):
        raise ValueError("adres: pusty, za długi albo ze spacjami / znakami sterującymi")
    try:
        parts = urlsplit(text)
        parts.port  # noqa: B018 - zły port to ValueError
    except ValueError:
        raise ValueError("adres: nieprawidłowy URL") from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("adres: tylko http(s) z nazwą hosta")
    if "@" in parts.netloc:
        raise ValueError("adres: dane logowania w adresie są niedozwolone")
    return text, parts


class UnsafeUrl(ValueError):
    """Adres poprawny technicznie, ale niezapisywalny (kontakt, dane logowania albo sekret w adresie)."""


# nazwy parametrów, których wartości nie zapisujemy: kontakt, logowanie, sekrety (dokładne nazwy i rdzenie)
# (nazwa użytkownika w parametrze, np. ?user=, to identyfikator, nie sekret: zostaje)
_SECRET_NAMES = frozenset(
    {"tel", "sid", "sig", "pwd", "pass", "key", "code", "otp", "auth", "mail", "pin", "ssn", "pesel"}
)
_SECRET_STEMS = (
    "token",
    "secret",
    "passw",
    "session",
    "email",
    "e-mail",
    "phone",
    "credential",
    "apikey",
    "api_key",
    "signature",
    "mobile",
    "msisdn",
    "telefon",
    "haslo",
    "hasło",
    "contact",
    "kontakt",
)
_URL_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# numer telefonu w adresie: z "+" albo z separatorami (same cyfry to zwykle identyfikator, np. profile.php?id=)
_URL_PHONE = re.compile(
    r"(?<![\w])(?:\+\d[\d\s().-]{6,}\d|\d{2,4}[\s.-]\d{2,4}[\s.-]\d{2,4}(?:[\s.-]\d{2,4})?)(?![\w])"
)


def persist_problem(text: str) -> str | None:
    """Przyczyna, dla której adresu nie wolno zapisać (albo None). Sprawdza ścieżkę, zapytanie i fragment po
    zdekodowaniu %xx: e-mail, numer telefonu z separatorami lub '+', parametr o nazwie kontaktu/logowania/sekretu.
    To heurystyka dla STRUKTURY adresu, nie pełny filtr danych wrażliwych (np. sekret jako zwykły segment ścieżki
    nie zostanie rozpoznany)."""
    parts = urlsplit(text)
    pieces = [unquote(parts.path)]  # w ścieżce '+' to znak, nie spacja
    for blob in (parts.query, parts.fragment):
        for name, value in parse_qsl(blob, keep_blank_values=True):
            low = name.strip().lower()
            if low in _SECRET_NAMES or any(stem in low for stem in _SECRET_STEMS):
                return "adres zawiera parametr z danymi kontaktowymi, logowania albo sekretem: nie zapisujemy go"
            pieces += [name, value]
        if blob and "=" not in blob:
            pieces.append(unquote_plus(blob))
    joined = "\n".join(pieces)
    if _URL_EMAIL.search(joined):
        return "adres zawiera adres e-mail: nie zapisujemy go"
    if any(sum(c.isdigit() for c in m.group(0)) >= 9 for m in _URL_PHONE.finditer(joined)):  # daty mają 8 cyfr
        return "adres zawiera numer telefonu: nie zapisujemy go"
    return None


def _query(parts, keep: tuple[str, ...]) -> str:
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=False) if k in keep]
    return urlencode(sorted(pairs))


def _facebook(segs: list[str], raw: list[str], parts) -> tuple[str, str, dict, str]:
    """-> (klasa, ścieżka kanoniczna, identyfikator, zapytanie kanoniczne). ``segs`` małymi literami służą tylko
    do rozpoznania; w ścieżce zostają oryginalne segmenty, poza słowami kluczowymi i nazwą profilu (vanity)."""
    if not segs:
        return CLASS_UNKNOWN, "", {}, ""
    s0 = segs[0]
    query = _query(parts, _FB_KEEP.get(s0, ()))
    if s0 == "profile.php":
        ids = [v for k, v in parse_qsl(parts.query) if k == "id"]
        if len(ids) == 1 and ids[0].isdigit():
            return CLASS_PROFILE, "/profile.php", {"type": "id", "value": ids[0]}, f"id={ids[0]}"
        return CLASS_UNKNOWN, "/profile.php", {}, ""
    if s0 == "people" and len(segs) >= 3 and segs[2].isdigit():
        # slug nazwy jest ozdobnikiem (serwis kieruje po id), więc małe litery są tu bezpieczne
        return CLASS_PROFILE, "/" + "/".join(segs[:3]), {"type": "id", "value": segs[2]}, ""
    if s0 == "groups":
        if len(segs) >= 4 and segs[2] in ("posts", "permalink"):
            return CLASS_POST, _join([s0], raw[1:2], [segs[2]], raw[3:4]), {}, ""
        return CLASS_GROUP, _join([s0], raw[1:2]), {}, ""
    if s0 in ("pages", "pg"):
        return CLASS_ORG, _join([s0], raw[1:]), {}, ""
    if s0 in _FB_POST_ROOTS:
        return CLASS_POST, _join([s0], raw[1:]), {}, query
    if s0 in _FB_RESERVED or not _FB_VANITY.fullmatch(s0):
        return CLASS_UNKNOWN, _join(raw), {}, ""
    # nazwa profilu (vanity) na Facebooku nie rozróżnia wielkości liter
    if len(segs) == 1 or (len(segs) == 2 and segs[1] in _FB_PROFILE_SUB):
        return CLASS_PROFILE, "/" + s0, {"type": "nazwa", "value": s0}, ""
    if segs[1] in _FB_POST_SUB:
        return CLASS_POST, _join(segs[:2], raw[2:]), {}, ""
    return CLASS_UNKNOWN, _join(raw), {}, ""


def _instagram(segs: list[str], raw: list[str]) -> tuple[str, str, dict, str]:
    """Nazwa konta Instagram nie rozróżnia wielkości liter; kod posta/rolki (``/p/AbC``) rozróżnia."""
    if not segs or segs[0] in _IG_RESERVED:
        return CLASS_UNKNOWN, _join(raw), {}, ""
    if segs[0] in _IG_POST:
        return CLASS_POST, _join(segs[:1], raw[1:2]), {}, ""
    handle = segs[0]
    if not _IG_HANDLE.fullmatch(handle):
        return CLASS_UNKNOWN, _join(raw), {}, ""
    if len(segs) == 1 or (len(segs) == 2 and segs[1] in _IG_PROFILE_SUB):
        return CLASS_PROFILE, "/" + handle, {"type": "nazwa", "value": handle}, ""
    if segs[1] in ("p", "reel"):
        return CLASS_POST, _join(segs[:2], raw[2:3]), {}, ""
    return CLASS_UNKNOWN, _join(raw), {}, ""


def _threads(segs: list[str], raw: list[str]) -> tuple[str, str, dict, str]:
    """@nazwa w Threads jak na Instagramie (bez wielkości liter); kod posta zachowuje pisownię."""
    if segs and segs[0].startswith("@") and _IG_HANDLE.fullmatch(segs[0][1:]):
        handle = segs[0][1:]
        if len(segs) == 1 or (len(segs) == 2 and segs[1] in ("replies", "reposts", "media")):
            return CLASS_PROFILE, "/@" + handle, {"type": "nazwa", "value": handle}, ""
        if segs[1] == "post" and len(segs) >= 3:
            return CLASS_POST, _join(segs[:2], raw[2:3]), {}, ""
    return CLASS_UNKNOWN, _join(raw), {}, ""


def _join(*groups: list[str]) -> str:
    return "/" + "/".join(s for g in groups for s in g)


def check_url(raw: object, require_platform: bool = True) -> ProfileUrl:
    """Waliduje i klasyfikuje adres. require_platform: tylko Facebook / Instagram / Threads (wyniki wyszukiwania);
    False: dowolny publiczny adres http(s) (materiał operatora), klasa „nieustalony” poza tymi serwisami.
    Błąd = ValueError z powodem (adres odrzucony, nic nie zapisujemy); komunikat nigdy nie zawiera samego adresu.
    Adres z kontaktem, danymi logowania albo sekretem = :class:`UnsafeUrl` (nie skracamy go do "bezpiecznej"
    postaci: zmiana istotnej części adresu fabrykowałaby źródło)."""
    text, parts = _validate(raw)
    found = platform_of(parts.hostname)
    if found is None and require_platform:
        raise ValueError("adres spoza obsługiwanych serwisów (Facebook, Instagram, Threads)")
    problem = persist_problem(text)
    if problem:
        raise UnsafeUrl(problem)
    if found is None:
        try:
            _, display = normalize_url(text)
        except ValueError:
            raise ValueError("adres: nieprawidłowy URL") from None
        return ProfileUrl(text, display, OTHER, CLASS_UNKNOWN, {})
    host, platform = found
    raw = [s for s in parts.path.split("/") if s]
    segs = [s.lower() for s in raw]  # tylko do rozpoznania; pisownię identyfikatorów zachowuje `raw`
    if platform == "Facebook":
        cls, path, ident, query = _facebook(segs, raw, parts)
    elif platform == "Instagram":
        cls, path, ident, query = _instagram(segs, raw)
    else:
        cls, path, ident, query = _threads(segs, raw)
    canonical = f"https://{host}{path}" + (f"?{query}" if query else "")
    try:
        _, display = normalize_url(canonical)
    except ValueError:
        raise ValueError("adres: nieprawidłowy URL") from None
    return ProfileUrl(text, display, platform, cls, dict(ident, platform=platform) if ident else {})
