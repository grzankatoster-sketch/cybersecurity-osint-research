"""General extractors for state a page embeds for its own scripts, and for visible label-value text.

`EmbeddedStateExtractor` finds the object that belongs to the requested nick inside embedded JSON
(script bodies, `window.X = {...}`, `data-*` attributes, JSON responses) and reads fields from
that object only. `LabelValueExtractor` reads "Location: ..." / "Joined: ..." pairs from visible
text at LOW quality. Both are bounded in size, depth and object count and name no hosts.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable, Iterator
from datetime import date
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from ultimate_username.domain.json_types import json_value, parse_json
from ultimate_username.domain.metadata import EvidenceQuality
from ultimate_username.domain.models import JSONValue

if TYPE_CHECKING:
    from ultimate_username.enrichment import ExtractionContext, ParsedDocument

MAX_SOURCE_CHARS = 2 * 1024 * 1024
MAX_TOTAL_CHARS = 6 * 1024 * 1024
MAX_NODES = 50_000
MAX_TOTAL_NODES = 150_000
MAX_DEPTH = 24
MAX_OWNERS = 64
MAX_SOURCES = 32
MAX_ASSIGNMENTS = 8
MAX_LINKS = 32
EMBEDDED_PRIORITY = 25
LABEL_PRIORITY = 70
MAX_LABEL_VALUE = 80
MAX_TEXT_NODES = 4000

OWNER_KEYS = (
    "username",
    "login",
    "screen_name",
    "handle",
    "slug",
    "acct",
    "nickname",
    "user_name",
    "userName",
    "uniqueId",
)
# A different value under one of these means the object describes someone else.
STRONG_OWNER_KEYS = frozenset(OWNER_KEYS) - {"nickname"}
DISPLAY_KEYS = (
    "displayName",
    "display_name",
    "fullName",
    "full_name",
    "fullname",
    "realName",
    "name",
    "nickname",
    "screenname",
    "screenName",
)
BIO_KEYS = (
    "bio",
    "biography",
    "about",
    "aboutMe",
    "about_me",
    "signature",
    "briefdescription",
    "description",
    "summary",
)
LOCATION_KEYS = ("location", "city", "country", "region")
AVATAR_KEYS = (
    "avatarUrl",
    "avatar_url",
    "avatar",
    "profile_image_url",
    "profileImageUrl",
    "profile_image",
    "profilePicture",
    "profile_picture",
    "profilePictureUrl",
    "picture",
    "pfp",
    "photo",
    "photoUrl",
    "image",
    "icon",
    "thumbUrl",
)
IMAGE_URL_KEYS = ("url", "src", "large", "original", "medium", "small")
TEXT_VALUE_KEYS = ("name", "title", "label", "value", "text")
CREATED_KEYS = (
    "createdAt",
    "created_at",
    "created",
    "joined",
    "joinedAt",
    "joined_at",
    "registered",
    "registeredAt",
    "registered_at",
    "memberSince",
    "time_created",
    "creation_date",
    "dateCreated",
    "signupDate",
    "ts",
)
WEBSITE_KEYS = ("website", "website_url", "websiteUrl", "blog", "homepage", "homepageUrl", "url")
LINK_KEYS = (
    "links",
    "external_links",
    "externalLinks",
    "socials",
    "social",
    "social_links",
    "socialLinks",
    "social_profiles",
    "bio_links",
    "bioLinks",
)
LINK_ITEM_KEYS = ("url", "link", "href", "value")
COUNTER_KEYS = {
    "followers": (
        "followers",
        "followersCount",
        "followers_count",
        "followerCount",
        "follower_count",
    ),
    "following": ("following", "followingCount", "following_count", "followCount"),
    "posts": ("posts_count", "postsCount", "statuses_count", "postCount", "posts"),
}
ID_KEYS = ("id", "userId", "user_id", "uid")
VERIFIED_KEYS = ("verified", "is_verified", "isVerified")
# Conflicts here mean two different people share the nick; elsewhere only that field is dropped.
IDENTITY_FIELDS = frozenset({"display_name", "bio", "user_id", "created_at"})

_ASSIGN = re.compile(
    r"(?:\b(?:window|self|globalThis)\s*(?:\.\s*[\w$]+|\[\s*[\"'][\w$]+[\"']\s*\])"
    r"|\b(?:__\w+__|initials|initialData|initialState|INITIAL_STATE|PRELOADED_STATE))"
    r"\s*=\s*(?=[{\[]|JSON\.parse\s*\(\s*\")"
)
_DECODER = json.JSONDecoder()
_ISO_START = re.compile(r"\d{4}-\d{2}-\d{2}")

Fields = dict[str, tuple[JSONValue, str]]


def decode_json_text(text: str) -> JSONValue | None:
    """Strict JSON, optionally URL-encoded; anything else is not state."""
    stripped = text.strip()
    if stripped[:3].lower() in ("%7b", "%5b"):
        stripped = unquote(stripped)
    if stripped[:1] not in ("{", "["):
        return None
    try:
        return parse_json(stripped)
    except (ValueError, RecursionError):
        return None


def _decode_at(text: str, start: int) -> JSONValue | None:
    try:
        value, _ = _DECODER.raw_decode(text, start)
        return json_value(value)
    except (ValueError, RecursionError):
        return None


def script_states(text: str) -> Iterator[tuple[str, JSONValue]]:
    """`name = {...}`, `name = JSON.parse("...")` and URL-encoded bodies of an inline script."""
    if text.lstrip()[:1] in ("{", "[", "%") and (direct := decode_json_text(text)) is not None:
        yield "body", direct
    for count, match in enumerate(_ASSIGN.finditer(text)):
        if count >= MAX_ASSIGNMENTS:
            return
        label = " ".join(match.group(0).split())[:48]
        start = match.end()
        if text.startswith("JSON.parse", start):
            quote = text.find('"', start)
            raw = _decode_at(text, quote) if quote >= 0 else None
            inner = decode_json_text(raw) if isinstance(raw, str) else None
            if inner is not None:
                yield label, inner
            continue
        value = _decode_at(text, start)
        if value is not None:
            yield label, value


def attribute_state(value: str) -> JSONValue | None:
    text = html.unescape(value) if "&" in value else value
    return decode_json_text(text)


def _sources(document: ParsedDocument) -> Iterator[tuple[str, JSONValue]]:
    emitted, chars = 0, 0
    for locator, data in document.json_documents:
        if locator != "jsonld":
            emitted += 1
            yield locator, data
    for index, text in enumerate(document.inline_scripts):
        chars += len(text)
        if chars > MAX_TOTAL_CHARS or emitted >= MAX_SOURCES:
            return
        if len(text) > MAX_SOURCE_CHARS:
            continue
        for label, data in script_states(text):
            emitted += 1
            yield f"script[{index}]:{label}", data
    for name, value in document.data_attrs:
        chars += len(value)
        if chars > MAX_TOTAL_CHARS or emitted >= MAX_SOURCES:
            return
        if len(value) > MAX_SOURCE_CHARS:
            continue
        data = attribute_state(value)
        if data is not None:
            emitted += 1
            yield name, data


def _is_owner(node: dict[str, JSONValue], matches: Callable[[str], bool]) -> bool:
    hit = False
    for key in OWNER_KEYS:
        value = node.get(key)
        if isinstance(value, str):
            if matches(value):
                hit = True
            elif key in STRONG_OWNER_KEYS:
                return False
    name = node.get("name")
    return hit or (isinstance(name, str) and matches(name))


def find_owners(
    root: JSONValue, matches: Callable[[str], bool], budget: list[int]
) -> list[tuple[str, dict[str, JSONValue]]]:
    """Objects of one document that name the nick; document order, bounded walk."""
    owners: list[tuple[str, dict[str, JSONValue]]] = []
    stack: list[tuple[JSONValue, int, str]] = [(root, 0, "")]
    nodes = 0
    while stack and len(owners) < MAX_OWNERS:
        node, depth, path = stack.pop()
        nodes += 1
        budget[0] -= 1
        if nodes > MAX_NODES or budget[0] < 0:
            break
        if isinstance(node, dict):
            if _is_owner(node, matches):
                owners.append((path, node))
            if depth < MAX_DEPTH:
                for key, child in reversed(list(node.items())):
                    if isinstance(child, (dict, list)):
                        stack.append((child, depth + 1, f"{path}.{key}"))
        elif isinstance(node, list) and depth < MAX_DEPTH:
            for index in range(len(node) - 1, -1, -1):
                child = node[index]
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1, f"{path}[{index}]"))
    return owners


def _text(value: JSONValue) -> str | None:
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, dict):
        for key in TEXT_VALUE_KEYS:
            inner = value.get(key)
            if isinstance(inner, str) and inner.strip():
                return inner
    return None


def _first_text(
    obj: dict[str, JSONValue], keys: tuple[str, ...], skip: str = ""
) -> tuple[str, str] | None:
    for key in keys:
        text = _text(obj.get(key))
        if text is not None and text.lstrip("@").casefold() != skip:
            return text, key
    return None


def _image(value: JSONValue) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, dict):
        for key in IMAGE_URL_KEYS:
            inner = value.get(key)
            if isinstance(inner, str) and inner.strip():
                return inner
    return None


def _epoch(value: int) -> int | None:
    if 10**11 <= value <= 4_102_444_800_000:
        return value // 1000
    return value if 10**8 <= value <= 4_102_444_800 else None


def _created(obj: dict[str, JSONValue]) -> tuple[JSONValue, str] | None:
    for key in CREATED_KEYS:
        value = obj.get(key)
        if type(value) is int:
            seconds = _epoch(value)
            if seconds is not None:
                return seconds, key
        elif isinstance(value, str) and _ISO_START.match(value.strip()):
            return value.strip(), key
    return None


def _http_url(value: JSONValue) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        if urlsplit(text).scheme in ("http", "https") and len(text) <= 2048:
            return text
    return None


def _links(obj: dict[str, JSONValue]) -> tuple[tuple[str, ...], str] | None:
    for key in LINK_KEYS:
        value = obj.get(key)
        items: list[JSONValue]
        if isinstance(value, list):
            items = list(value[: MAX_LINKS * 2])
        elif isinstance(value, dict):
            items = list(value.values())[: MAX_LINKS * 2]
        else:
            continue
        found: list[str] = []
        for item in items:
            url = _http_url(item)
            if url is None and isinstance(item, dict):
                url = next((u for k in LINK_ITEM_KEYS if (u := _http_url(item.get(k)))), None)
            if url and url not in found:
                found.append(url)
        if found:
            return tuple(found[:MAX_LINKS]), key
    return None


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


def owner_fields(obj: dict[str, JSONValue], nick: str, page_host: str) -> Fields:
    """Fields of one owner object, each with the key it came from; nothing from its neighbours."""
    out: Fields = {}
    for name, keys, skip in (
        ("display_name", DISPLAY_KEYS, nick),
        ("bio", BIO_KEYS, ""),
        ("location", LOCATION_KEYS, ""),
    ):
        if (hit := _first_text(obj, keys, skip)) is not None:
            out[name] = hit
    for key in AVATAR_KEYS:
        if (url := _image(obj.get(key))) is not None:
            out["avatar_url"] = (url, key)
            break
    for counter_name, counter_keys in COUNTER_KEYS.items():
        for key in counter_keys:
            counter = obj.get(key)
            if type(counter) is int or (isinstance(counter, str) and counter.strip()):
                out[counter_name] = (counter, key)
                break
    if (created := _created(obj)) is not None:
        out["created_at"] = created
    for key in WEBSITE_KEYS:
        url = _http_url(obj.get(key))
        if url and (key != "url" or _host(url) != page_host):
            out["website"] = (url, key)
            break
    if (links := _links(obj)) is not None:
        urls: list[JSONValue] = list(links[0])
        out["external_links"] = (urls, links[1])
    for key in VERIFIED_KEYS:
        if type(obj.get(key)) is bool:
            out["verified"] = (obj[key], key)
            break
    for key in ID_KEYS:
        ident = obj.get(key)
        if type(ident) is int or (isinstance(ident, str) and 0 < len(ident) <= 128):
            out["user_id"] = (ident, key)
            break
    return out


def merge_owners(
    found: list[tuple[str, Fields]],
) -> tuple[dict[str, tuple[JSONValue, str]], bool]:
    """Compatible objects are one owner; a conflict on identity fields means no owner."""
    merged: dict[str, tuple[JSONValue, str]] = {}
    dropped: set[str] = set()
    for path, fields in found:
        for name, (value, key) in fields.items():
            if name in dropped:
                continue
            if name not in merged:
                merged[name] = (value, f"{path}.{key}")
            elif merged[name][0] != value:
                if name in IDENTITY_FIELDS:
                    return {}, True
                dropped.add(name)
                del merged[name]
    return merged, False


class EmbeddedStateExtractor:
    """Owner-bound fields from state embedded in the page or returned as the JSON response."""

    NAME = "EmbeddedStateExtractor"

    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        if "OWNER_BINDING_FAILED" in context.diagnostics:
            return  # another extractor already saw a contradicting owner
        nick = context.username.casefold()
        page_host = _host(context.url)

        def matches(value: str) -> bool:
            bare = value.lstrip("@")
            # The case policy (generic platforms are case-sensitive) lives in owner_matches.
            return bare == context.username or (
                bare.casefold() == nick and context.owner_matches(bare)
            )

        found: list[tuple[str, Fields]] = []
        budget = [MAX_TOTAL_NODES]
        for source, data in _sources(document):
            for path, obj in find_owners(data, matches, budget):
                fields = owner_fields(obj, nick, page_host)
                if fields:
                    found.append((source + path, fields))
            if budget[0] < 0:
                break
        if not found:
            return
        merged, ambiguous = merge_owners(found)
        if ambiguous:
            context.diagnostics.add("AMBIGUOUS_OWNER")
            return
        for name, (value, locator) in merged.items():
            context.add(
                name,
                value,
                self.NAME,
                locator,
                EvidenceQuality.MEDIUM,
                EMBEDDED_PRIORITY,
            )


# ------------------------------------------------------------------ label-value text

LOCATION_LABELS = frozenset(
    {
        "location",
        "lokalizacja",
        "местоположение",
        "ort",
        "ubicación",
        "ubicacion",
        "localisation",
        "standort",
        "wohnort",
        "miejscowość",
        "lieu",
    }
)
JOINED_LABELS = frozenset(
    {
        "joined",
        "member since",
        "dołączył",
        "dołączyła",
        "dołączył(a)",
        "на сайте с",
        "registered",
        "registered since",
        "registration date",
        "user since",
        "enlisted",
        "miembro desde",
        "mitglied seit",
        "inscrit depuis",
        "data dołączenia",
        "join date",
        "date joined",
        "zarejestrowany",
        "zarejestrowana",
        "зарегистрирован",
        "дата регистрации",
    }
)
EMPTY_VALUES = frozenset(
    {"n/a", "na", "none", "unknown", "-", "—", "?", "not specified", "brak", "null", "undefined"}
)
_MONTH_WORDS = (
    "january jan stycznia styczeń januar enero января",
    "february feb lutego luty februar febrero февраля",
    "march mar marca marzec märz marzo марта",
    "april apr kwietnia kwiecień abril апреля",
    "may maja maj mai mayo мая",
    "june jun czerwca czerwiec juni junio июня",
    "july jul lipca lipiec juli julio июля",
    "august aug sierpnia sierpień agosto августа",
    "september sep sept września wrzesień septiembre сентября",
    "october oct października październik oktober octubre октября",
    "november nov listopada listopad noviembre ноября",
    "december dec grudnia grudzień dezember diciembre декабря",
)
MONTHS = {word: number for number, words in enumerate(_MONTH_WORDS, 1) for word in words.split()}
_SPLIT = re.compile(r"([^:：]{1,40}?)\s*[:：]\s*(\S.{0,200})")
_ISO_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?")
_DOTTED = re.compile(r"(\d{1,2})\.(\d{1,2})\.(\d{4})")
_MONTH_FIRST = re.compile(r"([^\W\d_]+)\.?\s+(\d{1,2}),?\s+(\d{4})")
_DAY_FIRST = re.compile(r"(\d{1,2})\.?\s+([^\W\d_]+)\.?,?\s+(\d{4})(?:\s*г\.?)?")


def _make_date(year: str, month: int | None, day: str) -> str | None:
    if month is None:
        return None
    try:
        return date(int(year), month, int(day)).isoformat()
    except ValueError:
        return None


def parse_visible_date(text: str) -> str | None:
    value = " ".join(text.split())
    if m := _ISO_DATE.fullmatch(value):
        return _make_date(m[1], int(m[2]), m[3])
    if m := _DOTTED.fullmatch(value):
        return _make_date(m[3], int(m[2]), m[1])
    if m := _MONTH_FIRST.fullmatch(value):
        return _make_date(m[3], MONTHS.get(m[1].casefold()), m[2])
    if m := _DAY_FIRST.fullmatch(value):
        return _make_date(m[3], MONTHS.get(m[2].casefold()), m[1])
    return None


def _label_key(text: str) -> str:
    return " ".join(text.casefold().split()).rstrip(":：").strip()


def _usable_value(text: str) -> str | None:
    value = " ".join(text.split())
    folded = value.casefold()
    if (
        not value
        or len(value) > MAX_LABEL_VALUE
        or "://" in value
        or "www." in folded
        or "@" in value
        or folded in EMPTY_VALUES
        or _label_key(value) in LOCATION_LABELS | JOINED_LABELS
    ):
        return None
    return value


class LabelValueExtractor:
    """`Location: Oslo` / `<dt>Joined</dt><dd>...` in visible text; LOW quality, last resort."""

    NAME = "LabelValueExtractor"

    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        if "OWNER_BINDING_FAILED" in context.diagnostics:
            return
        nodes = document.text_nodes[:MAX_TEXT_NODES]
        nick = context.username.casefold()
        if not any(nick in text.casefold() for text, _ in nodes):
            return
        have = {c.name for c in context.candidates}
        done: set[str] = set()
        for i, (text, in_anchor) in enumerate(nodes):
            pair = None if in_anchor else self._pair(nodes, i, text)
            if pair is None:
                continue
            label, raw = pair
            key = _label_key(label)
            name = (
                "location"
                if key in LOCATION_LABELS
                else "created_at"
                if key in JOINED_LABELS
                else ""
            )
            if not name or name in have or name in done:
                continue
            value = _usable_value(raw)
            if value is not None and name == "created_at":
                value = parse_visible_date(value)
            if value is None:
                continue
            done.add(name)
            context.add(
                name,
                value,
                self.NAME,
                f"text:{label.strip()[:40]}",
                EvidenceQuality.LOW,
                LABEL_PRIORITY,
            )

    @staticmethod
    def _pair(nodes: list[tuple[str, bool]], index: int, text: str) -> tuple[str, str] | None:
        split = _SPLIT.fullmatch(text)
        if split and _label_key(split[1]) in LOCATION_LABELS | JOINED_LABELS:
            return split[1], split[2]
        if _label_key(text) in LOCATION_LABELS | JOINED_LABELS and index + 1 < len(nodes):
            return text, nodes[index + 1][0]
        return None
