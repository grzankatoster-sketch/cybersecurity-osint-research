"""Rejects identity fields that carry no information about the account owner.

A page about any account of a service repeats its template: the nick echoed back
("@alice", "alice's profile"), marketing phrases ("You can view and join @alice"), default
images and values identical on a control page. All checks are bounded and linear; none of
them lists hosts.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from ultimate_username.detection import ResponseView
from ultimate_username.domain.models import TransportResponse

TEXT_FIELDS = frozenset({"display_name", "bio", "description", "location"})
IMAGE_FIELDS = frozenset({"avatar_url", "banner_url"})
MAX_CHECKED = 300  # characters of a value the phrase checks ever look at
LONG_BIO = 140  # generic marketing phrases ("sign up") are not tested in longer text
MIN_CONTROL_VALUE = 3
MAX_DIGESTS = 16
DIGEST_SOURCE_LIMIT = 262144

NICK_ECHO = "NICK_ECHO"
TEMPLATE_VALUE = "TEMPLATE_VALUE"
CONTROL_SAME_VALUE = "CONTROL_SAME_VALUE"
SELF_LINK = "SELF_LINK"

_FILLER = frozenset(
    {
        "s", "profile", "profil", "perfil", "profilo", "on", "at", "user", "users", "member",
        "account", "page", "by", "the", "of", "is", "a", "an", "in", "from", "official",
        "channel", "blog", "konto", "utilisateur", "benutzer", "usuario", "na", "sur", "auf",
        "en", "de", "von", "профиль", "пользователь", "на",
    }
)  # fmt: skip
_WORD = re.compile(r"[^\W_]+")
_SITE_FREE_PHRASES = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\byou can view and join\b",
        r"\bif you have telegram\b",
        r"\bcheck out\b.{0,60}['’]s\s+(?:profile|page|channel)\b",
        r"\bprofile on\b",
        r"\bcreate your own\b",
        r"\bdownload the app\b",
        r"\bget the app\b",
        r"\bdołącz do\b",
        r"\bzarejestruj się\b",
        r"\bzaloguj się\b",
        r"\bpobierz aplikację\b",
        r"\bprofil użytkownika\b",
        r"\búnete a\b",
        r"\bregístrate\b",
        r"\binicia sesión\b",
        r"\bdescarga la app\b",
        r"\brejoignez\b",
        r"\binscrivez-vous\b",
        r"\bconnectez-vous\b",
        r"\btélécharger l'application\b",
        r"\bregistrier(?:e|en)\b",
        r"\bapp herunterladen\b",
        r"\btritt\b.{0,40}\bbei\b",
        r"\bjunte-se\b",
        r"\bbaixe o app\b",
        r"\bunisciti a\b",
        r"присоединяйтесь",
        r"зарегистрируйтесь",
        r"скачать приложение",
        r"вы можете посмотреть",
    )
)
_SHORT_TEXT_PHRASES = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (r"\bsign ?up\b", r"\bsign ?in\b", r"\blog ?in\b", r"\bregister now\b")
)
_WHOLE_VALUE_PHRASES = frozenset({"link in bio", "linkinbio", "link in my bio", "see bio"})

_DEFAULT_IMAGE = re.compile(
    r"(?:^|[/_.\-=?&])"
    r"(?:no[-_]?(?:photo|avatar|image|pic|picture|profile)|nophoto|noimage|missing|placeholder"
    r"|blank|spacer|identicon|monsterid|wavatar|robohash|silhouette|anonymous|zaslepka|egg"
    r"|unknown|empty|default(?:[-_]?(?:avatar|user|profile|image|pic|picture|photo))?"
    r"|(?:avatar|user|profile)[-_]?default)"
    r"(?:[/_.\-=?&]|$|\d)",
    re.IGNORECASE,
)
_GRAVATAR_DEFAULT = re.compile(
    r"[?&](?:d|default)=(?:mp|mm|identicon|monsterid|wavatar|retro|robohash|blank)(?:&|$)"
    r"|[?&](?:f|forcedefault)=y(?:&|$)",
    re.IGNORECASE,
)
_GENERATED_SEGMENTS = frozenset(
    {"og", "opengraph", "open-graph", "share", "social", "card", "cards", "preview"}
)


def squash(text: str) -> str:
    return "".join(_WORD.findall(text.casefold()))


def squash_text(text: str) -> str:
    """Case, `@` and name separators (`_ . -`) dropped; spaces stay, so a spelled name differs."""
    return " ".join(re.sub(r"[_.\-@·•]+", "", text.casefold()).split())


def site_tokens(site_name: str, url: str) -> tuple[str, ...]:
    host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    tokens = {site_name.strip().casefold(), host, host.split(".")[0] if host else ""}
    return tuple(sorted((t for t in tokens if len(t) >= 2), key=len, reverse=True))


@lru_cache(maxsize=256)
def _site_phrases(tokens: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    if not tokens:
        return ()
    sites = "|".join(re.escape(t) for t in tokens)
    return tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            rf"\bis on (?:{sites})\b",
            rf"^join\b.{{0,80}}\bon\s+(?:{sites})\b",
            rf"\bview\b.{{0,60}}\bon\s+(?:{sites})\b",
        )
    )


def _words_without_nick(text: str, nick: str) -> list[str] | None:
    words, nick_words = _WORD.findall(text.casefold()), _WORD.findall(nick.casefold())
    if not nick_words or not words:
        return None
    size, kept, i, removed = len(nick_words), [], 0, False
    while i < len(words):
        if words[i : i + size] == nick_words:
            removed, i = True, i + size
        else:
            kept.append(words[i])
            i += 1
    return kept if removed else None


def is_nick_echo(name: str, value: str, nick: str, tokens: tuple[str, ...]) -> bool:
    if name not in TEXT_FIELDS and name != "website":
        return False
    text = value[:MAX_CHECKED]
    nick_key = squash_text(nick)
    if not nick_key:
        return False
    if squash_text(text) == nick_key:
        return True
    if name == "website":
        return False
    rest = _words_without_nick(text, nick)
    if rest is None:
        return False
    site_words = {w for token in tokens for w in _WORD.findall(token)}
    return all(w in _FILLER or w in site_words for w in rest)


def is_template_text(value: str, tokens: tuple[str, ...]) -> bool:
    text = " ".join(value[:MAX_CHECKED].split())
    if not text:
        return False
    if " ".join(_WORD.findall(text.casefold())) in _WHOLE_VALUE_PHRASES:
        return True
    if any(p.search(text) for p in _SITE_FREE_PHRASES):
        return True
    if any(p.search(text) for p in _site_phrases(tokens)):
        return True
    return len(text) <= LONG_BIO and any(p.search(text) for p in _SHORT_TEXT_PHRASES)


def is_template_image(value: str, nick: str) -> bool:
    parts = urlsplit(value)
    path = unquote(parts.path)
    probe = path + ("?" + parts.query if parts.query else "")
    if _DEFAULT_IMAGE.search(probe) or _GRAVATAR_DEFAULT.search("?" + parts.query):
        return True
    lowered = path.casefold()
    if "/static/" in lowered and "logo" in lowered:
        return True
    segments = [s for s in lowered.split("/") if s]
    key = squash(nick)
    for i, segment in enumerate(segments):
        if segment in _GENERATED_SEGMENTS:
            for later in segments[i + 1 :]:
                if key and squash(later.rsplit(".", 1)[0]) == key:
                    return True
    return False


def _link_key(url: str) -> tuple[str, str, str] | None:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").casefold().removeprefix("www.")
    except ValueError:
        return None
    if not host:
        return None
    return host, unquote(parts.path).rstrip("/").casefold(), parts.query


def is_self_link(value: str, nick: str, own_urls: Iterable[str]) -> bool:
    """A link that is the profile's own URL, or just `/nick` on the host the profile lives on."""
    key = _link_key(value)
    if key is None:
        return False
    host, path, query = key
    nick_key = nick.casefold()
    for own in own_urls:
        mine = _link_key(own)
        if mine is None or mine[0] != host:
            continue
        if (path, query) == (mine[1], mine[2]) or (path.lstrip("/").lstrip("@") == nick_key):
            return True
    return False


def control_digest(value: str, nick: str) -> str:
    """Hash of a value with the nick replaced, so a control page and the real page compare."""
    text = " ".join(value.split()).casefold()
    folded = nick.casefold()
    if folded:
        text = text.replace(folded, "\x00")
    return hashlib.blake2s(text.encode("utf-8", "replace"), digest_size=8).hexdigest()


def filter_reason(
    name: str,
    value: str,
    nick: str,
    site_name: str,
    url: str,
    control: frozenset[str] = frozenset(),
) -> str:
    """Why an identity field is not information about this account, or an empty string."""
    if name in IMAGE_FIELDS:
        if is_template_image(value, nick):
            return TEMPLATE_VALUE
    elif name in TEXT_FIELDS or name == "website":
        tokens = site_tokens(site_name, url)
        if name in TEXT_FIELDS and is_template_text(value, tokens):
            return TEMPLATE_VALUE
        if is_nick_echo(name, value, nick, tokens):
            return NICK_ECHO
    else:
        return ""
    if (
        control
        and len(value.strip()) >= MIN_CONTROL_VALUE
        and control_digest(value, nick) in control
    ):
        return CONTROL_SAME_VALUE
    return ""


class _MetaCollector(HTMLParser):
    KEYS = frozenset(
        {
            "og:title",
            "og:description",
            "og:image",
            "twitter:title",
            "twitter:description",
            "twitter:image",
            "twitter:image:src",
            "description",
        }
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []
        self._title = False
        self._title_text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._title = True
        elif tag == "meta" and len(self.values) < 64:
            a = {k: v for k, v in attrs if v is not None}
            if a.get("property", a.get("name", "")).lower() in self.KEYS and a.get("content"):
                self.values.append(a["content"])

    def handle_data(self, data: str) -> None:
        if self._title and len(self._title_text) < 1024:
            self._title_text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._title:
            self._title = False
            self.values.append(self._title_text)


def response_digests(response: TransportResponse, nick: str) -> frozenset[str]:
    """Digests of the title and social meta values of a (control) page."""
    ctype = (response.header("Content-Type") or "").lower()
    if response.status is None or not response.body or (ctype and "html" not in ctype):
        return frozenset()
    try:
        text = ResponseView(response).text[:DIGEST_SOURCE_LIMIT]
        parser = _MetaCollector()
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        return frozenset()
    return digests_of(parser.values, nick)


def digests_of(values: Iterable[str], nick: str) -> frozenset[str]:
    found = {control_digest(v, nick) for v in values if len(v.strip()) >= MIN_CONTROL_VALUE}
    return frozenset(sorted(found)[:MAX_DIGESTS])
