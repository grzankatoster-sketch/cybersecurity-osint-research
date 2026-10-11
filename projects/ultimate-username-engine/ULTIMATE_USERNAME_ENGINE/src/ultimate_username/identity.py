"""identity_score: does a hit belong to the target person or to a namesake?

A pure function over finished ``SearchResult`` objects (plus an optional seed). It never changes
an existence verdict; it only answers "is this account probably the same person as the others,
or as the seed".
Network access is needed only for the optional avatar perceptual hash (``fetch_avatar_hashes``).

Model (docs/SPEC_IDENTITY.md, pattern ported from OSINT ``correlate.py``):

* signals are either *control* (hard to fake: reciprocal links, platform verification, a URL the
  user gave as the target's) or *copyable* (anyone can copy a display name, bio, avatar, location);
* all copyable signals form ONE dependent group: only the strongest counts, capped at
  ``copyable_cap``;
* the final score is ``1 - prod(1 - s)`` over the control signals and the capped copyable group,
  capped at ``max_score``;
* a contradiction (impersonation/fan marker, display name clearly different from the seed's) cuts
  the score to ``contradiction_cap`` and the decision to ``UNRELATED_LIKELY``.

Result key: ``result_key(result)`` = ``result.profile_url`` (fallback ``site:<site_id>``). It is
stable across runs for the same account. ``avatar_hashes`` is keyed by the avatar URL taken from
``profile_metadata``.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import statistics
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from enum import StrEnum
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ultimate_username.domain.models import (
    JSONValue,
    SearchResult,
    TimeoutProfile,
    TransportRequest,
    Verdict,
)
from ultimate_username.domain.urls import is_public_host
from ultimate_username.transport import Transport

# --------------------------------------------------------------------------------------------------
# Configuration (all weights and thresholds in one place so they can be tuned from outside)
# --------------------------------------------------------------------------------------------------


_UNIT_FIELDS = frozenset(
    {
        "w_link_reciprocal",
        "w_link_oneway",
        "w_seed_url",
        "w_verified",
        "w_seed_name",
        "w_same_display_name",
        "w_similar_bio",
        "w_avatar",
        "w_location",
        "w_reach",
        "copyable_cap",
        "max_score",
        "contradiction_cap",
        "threshold",
        "name_jaccard_min",
        "bio_jaccard_min",
    }
)


@dataclass(frozen=True, slots=True)
class IdentityConfig:
    """Starting heuristics; tune on the dev set only. ``from_mapping`` loads overrides from JSON."""

    # control group
    w_link_reciprocal: float = 0.85
    w_link_oneway: float = 0.70
    w_seed_url: float = 0.85
    w_verified: float = 0.50
    # copyable group
    w_seed_name: float = 0.60
    w_same_display_name: float = 0.35
    w_similar_bio: float = 0.35
    w_avatar: float = 0.50
    w_location: float = 0.20
    w_reach: float = 0.30
    # combination
    copyable_cap: float = 0.70
    max_score: float = 0.95
    contradiction_cap: float = 0.15
    threshold: float = 0.5
    # signal parameters
    name_jaccard_min: float = 0.6
    bio_jaccard_min: float = 0.5
    bio_min_words: int = 4
    display_name_min_len: int = 4
    reach_followers: int = 10_000
    phash_max_distance: int = 6
    boilerplate_min_hits: int = 3

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{field.name}: expected a number")
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{field.name}: expected a finite non-negative number")
            if field.name in _UNIT_FIELDS and value > 1:
                raise ValueError(f"{field.name}: expected a value in [0, 1]")
        if self.phash_max_distance > 64:
            raise ValueError("phash_max_distance: at most 64 bits")
        if self.boilerplate_min_hits < 2:
            raise ValueError("boilerplate_min_hits: at least 2")

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> IdentityConfig:
        """Build from a (partial) mapping; unknown keys and wrong types are rejected."""
        known = {f.name: f for f in fields(cls)}
        unknown = sorted(set(values) - set(known))
        if unknown:
            raise ValueError(f"Unknown identity config keys: {unknown}")
        converted: dict[str, float | int] = {}
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name}: expected a number")
            is_int = isinstance(getattr(DEFAULT_CONFIG, name), int)
            if is_int:
                if int(value) != value:
                    raise ValueError(f"{name}: expected an integer")
                converted[name] = int(value)
            else:
                converted[name] = float(value)
        return cls(**converted)  # type: ignore[arg-type]

    @classmethod
    def load(cls, path: Path) -> IdentityConfig:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Identity config must be a JSON object")
        return cls.from_mapping(data)

    def to_mapping(self) -> dict[str, float | int]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


DEFAULT_CONFIG = IdentityConfig()


# --------------------------------------------------------------------------------------------------
# Types
# --------------------------------------------------------------------------------------------------


class IdentityDecision(StrEnum):
    TARGET_LIKELY = "TARGET_LIKELY"
    UNRELATED_LIKELY = "UNRELATED_LIKELY"
    UNDETERMINED = "UNDETERMINED"


GROUP_CONTROL = "control"
GROUP_COPYABLE = "copyable"
GROUP_CONTRADICTION = "contradiction"
GROUP_NONE = "none"
_GROUP_ORDER = {GROUP_CONTROL: 0, GROUP_COPYABLE: 1, GROUP_CONTRADICTION: 2, GROUP_NONE: 3}

NO_IDENTITY_DATA = "NO_IDENTITY_DATA"
_SEED_KINDS = frozenset({"seed_name_match", "seed_name_conflict", "seed_url_match", "link_to_seed"})


@dataclass(frozen=True, slots=True)
class IdentitySeed:
    """What the user already knows about the target: a real name and/or URLs of known accounts."""

    name: str = ""
    urls: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not self.name.strip() and not any(u.strip() for u in self.urls)


@dataclass(frozen=True, slots=True)
class IdentitySignal:
    kind: str
    weight: float
    group: str
    fields: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "kind": self.kind,
            "weight": self.weight,
            "group": self.group,
            "fields": list(self.fields),
            "sources": list(self.sources),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class IdentityAssessment:
    key: str
    profile_url: str
    site_id: str
    score: float
    decision: IdentityDecision
    signals: tuple[IdentitySignal, ...] = ()
    seed_used: bool = False

    def to_dict(self, site: str | None = None) -> dict[str, JSONValue]:
        return {
            "profile_url": self.profile_url,
            "site": site or self.site_id,
            "score": self.score,
            "decision": self.decision.value,
            "signals": [s.to_dict() for s in self.signals],
            "seed_used": self.seed_used,
        }


# --------------------------------------------------------------------------------------------------
# Text and URL normalisation
# --------------------------------------------------------------------------------------------------

_FOLD_MAP = str.maketrans(
    {
        "ł": "l",
        "Ł": "L",
        "ø": "o",
        "Ø": "O",
        "đ": "d",
        "Đ": "D",
        "ß": "ss",
        "æ": "ae",
        "Æ": "AE",
        "œ": "oe",
        "Œ": "OE",
        "ð": "d",
        "þ": "th",
        "ı": "i",
    }
)


def fold(text: str) -> str:
    """Case/diacritic-insensitive form (ł->l, é->e); the same function is used on both sides."""
    decomposed = unicodedata.normalize("NFKD", text.translate(_FOLD_MAP))
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold()


def _tokens(text: str) -> list[str]:
    return re.findall(r"[^\W_]+", fold(text))


def _bare(text: str) -> str:
    return "".join(_tokens(text))


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _words(text: str) -> set[str]:
    return set(re.findall(r"\w{3,}", fold(text)))


_HOST_ALIASES = {"twitter.com": "x.com", "mobile.twitter.com": "x.com"}
_HOST_PREFIXES = ("www.", "m.", "mobile.")


def url_key(raw: str) -> str:
    """host+path of a URL (no scheme, ``www./m.``, query, fragment; lower case); "" if invalid."""
    text = raw.strip()
    if not text or any(c.isspace() for c in text):
        return ""
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    if not host or "." not in host:
        return ""
    for prefix in _HOST_PREFIXES:
        if host.startswith(prefix) and "." in host[len(prefix) :]:
            host = host[len(prefix) :]
            break
    host = _HOST_ALIASES.get(host, host)
    return host + unquote(parts.path).lower().rstrip("/")


_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\\]+"
    r"|(?<![\w@./:-])(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:/[^\s<>\"'\\]*)?",
    re.IGNORECASE,
)
_HANDLE_RE = re.compile(r"(?<![\w@.])@([A-Za-z0-9_][A-Za-z0-9_.]{1,38})")
_PLATFORM_HINT_RE = re.compile(
    r"(?:^|[^a-z])(ig|insta|instagram|twitter|tw|x|tiktok|tt|twitch|yt|youtube|github|gh|"
    r"snap|snapchat|telegram|tg|reddit|kick|facebook|fb|threads|vk)\s*[:|/\-–]?\s*$",
    re.IGNORECASE,
)
_PLATFORM_TEMPLATES: dict[str, tuple[str, ...]] = {
    **dict.fromkeys(("ig", "insta", "instagram"), ("instagram.com/{h}",)),
    **dict.fromkeys(("twitter", "tw", "x"), ("x.com/{h}",)),
    **dict.fromkeys(("tiktok", "tt"), ("tiktok.com/@{h}",)),
    "twitch": ("twitch.tv/{h}",),
    **dict.fromkeys(
        ("yt", "youtube"), ("youtube.com/@{h}", "youtube.com/c/{h}", "youtube.com/user/{h}")
    ),
    **dict.fromkeys(("github", "gh"), ("github.com/{h}",)),
    **dict.fromkeys(("snap", "snapchat"), ("snapchat.com/add/{h}",)),
    **dict.fromkeys(("telegram", "tg"), ("t.me/{h}",)),
    "reddit": ("reddit.com/user/{h}", "reddit.com/u/{h}"),
    "kick": ("kick.com/{h}",),
    **dict.fromkeys(("facebook", "fb"), ("facebook.com/{h}",)),
    "threads": ("threads.net/@{h}",),
    "vk": ("vk.com/{h}",),
}
_TRAILING = ".,;:!?)]}'\"»"


def _with_scheme(raw: str) -> str:
    return raw if "://" in raw else "https://" + raw


def extract_links(text: str) -> dict[str, str]:
    """URL key -> the URL as written (scheme added when missing) for links mentioned in free text.

    Full or scheme-less URLs and ``ig: @handle`` mentions. A bare ``@handle`` without a platform
    word before it is ignored: every hit shares the searched nick, so a platformless handle would
    "link" to everything.
    """
    links: dict[str, str] = {}
    for match in _URL_RE.finditer(text):
        raw = match.group(0).rstrip(_TRAILING)
        key = url_key(raw)
        if key:
            links.setdefault(key, _with_scheme(raw))
    for match in _HANDLE_RE.finditer(text):
        hint = _PLATFORM_HINT_RE.search(text[max(0, match.start() - 20) : match.start()])
        if not hint:
            continue
        handle = match.group(1).rstrip(".").lower()
        for template in _PLATFORM_TEMPLATES.get(hint.group(1).lower(), ()):
            key = template.format(h=handle)
            links.setdefault(key, "https://" + key)
    return links


def extract_link_keys(text: str) -> set[str]:
    """URL keys mentioned in free text (see ``extract_links``)."""
    return set(extract_links(text))


# Hosts of public profile pages -> platform name. A link counts as an account link only when its
# path looks like a profile (see ``classify_link``); the rest of the web is not a "platform".
_HOST_PLATFORM = {
    "x.com": "x",
    "instagram.com": "instagram",
    "tiktok.com": "tiktok",
    "youtube.com": "youtube",
    "twitch.tv": "twitch",
    "kick.com": "kick",
    "github.com": "github",
    "gitlab.com": "gitlab",
    "bitbucket.org": "bitbucket",
    "linkedin.com": "linkedin",
    "facebook.com": "facebook",
    "fb.com": "facebook",
    "reddit.com": "reddit",
    "discord.gg": "discord",
    "discord.com": "discord",
    "t.me": "telegram",
    "telegram.me": "telegram",
    "bsky.app": "bluesky",
    "steamcommunity.com": "steam",
    "open.spotify.com": "spotify",
    "soundcloud.com": "soundcloud",
    "patreon.com": "patreon",
    "linktr.ee": "linktree",
    "threads.net": "threads",
    "snapchat.com": "snapchat",
    "pinterest.com": "pinterest",
    "medium.com": "medium",
    "vk.com": "vk",
    "ko-fi.com": "kofi",
    "buymeacoffee.com": "buymeacoffee",
    "bio.link": "biolink",
    "beacons.ai": "beacons",
    "deviantart.com": "deviantart",
    "behance.net": "behance",
    "dribbble.com": "dribbble",
    "stackoverflow.com": "stackoverflow",
    "keybase.io": "keybase",
    "flickr.com": "flickr",
    "vimeo.com": "vimeo",
    "last.fm": "lastfm",
}
_SUBDOMAIN_PLATFORM = {
    ".substack.com": "substack",
    ".bandcamp.com": "bandcamp",
    ".tumblr.com": "tumblr",
}
_AT_ONLY = frozenset({"tiktok.com", "threads.net", "medium.com"})
# host -> first path segments that introduce an account (then a second segment is required)
_PREFIXED = {
    "linkedin.com": frozenset({"in", "company", "school"}),
    "reddit.com": frozenset({"user", "u"}),
    "discord.com": frozenset({"invite", "users"}),
    "bsky.app": frozenset({"profile"}),
    "steamcommunity.com": frozenset({"id", "profiles"}),
    "open.spotify.com": frozenset({"user", "artist"}),
    "snapchat.com": frozenset({"add"}),
    "flickr.com": frozenset({"people", "photos"}),
    "last.fm": frozenset({"user"}),
    "stackoverflow.com": frozenset({"users"}),
}
_NOT_ACCOUNT = frozenset(
    {
        "i", "intent", "share", "sharer", "sharer.php", "home", "search", "hashtag", "explore",
        "login", "signup", "join", "settings", "messages", "notifications", "compose", "about",
        "privacy", "terms", "legal", "help", "p", "reel", "reels", "stories", "tv", "direct",
        "accounts", "watch", "results", "playlist", "feed", "shorts", "videos", "directory",
        "downloads", "features", "pricing", "orgs", "sponsors", "topics", "marketplace",
        "enterprise", "security", "events", "photo", "photos", "photo.php", "dialog", "plugins",
        "l.php", "posts", "gallery", "shots", "addstickers", "s", "joinchat", "tr",
    }
)  # fmt: skip


def classify_link(key: str) -> str | None:
    """Platform name when the URL key is the page of a person/account on a known platform."""
    host, _, rest = key.partition("/")
    segments = [s for s in rest.split("/") if s]
    platform = _HOST_PLATFORM.get(host)
    if platform is None:
        for suffix, name in _SUBDOMAIN_PLATFORM.items():
            if host.endswith(suffix) and host.count(".") >= 2 and not host.startswith("www."):
                return name
        if len(segments) == 1 and segments[0].startswith("@") and len(segments[0]) > 1:
            return "mastodon"
        return None
    if not segments:
        return None
    first = segments[0]
    if host in _AT_ONLY:
        return platform if first.startswith("@") and len(first) > 1 else None
    if host == "youtube.com":
        if first.startswith("@") and len(first) > 1:
            return platform
        return platform if first in ("c", "channel", "user") and len(segments) > 1 else None
    prefixes = _PREFIXED.get(host)
    if prefixes is not None:
        return platform if first in prefixes and len(segments) > 1 else None
    return None if first in _NOT_ACCOUNT else platform


_DEFAULT_AVATAR_RE = re.compile(r"default|placeholder|blank|anonymous|no[-_]?avatar", re.IGNORECASE)
_PAGE_TITLE_RE = re.compile(r"\bprofile?\b", re.IGNORECASE)

# Impersonation / fan / parody markers. Patterns are folded with the same function as the text.
_MARKER_SOURCE = "|".join(
    [
        # English
        r"\bnot (?:the |an? )?(?:real|official|actual|original)\b",
        r"\bfan[\s-]?(?:account|acc|page|club|site)\b",
        r"\bfanpage\b",
        r"\bparod(?:y|ie|ia)\b",
        r"\bfake\b",
        r"\bunofficial\b",
        r"\bimpersonat",
        r"\bnot affiliated\b",
        r"\btribute (?:account|page)\b",
        r"\bstan account\b",
        # Polish
        r"\bnie jestem\b",
        r"\bnieoficjaln",
        r"\bkonto (?:fanowsk|parodystyczn|fanow)",
        r"\bfanowsk",
        r"\bfalszyw",
        r"\bpodrobk",
        # Russian / Ukrainian
        r"не\s+настоящ",
        r"не\s+официальн",
        r"неофициальн",
        r"фан[\s-]?аккаунт",
        r"фан[\s-]?страниц",
        r"фейк",
        r"пародия",
        # Spanish / Portuguese / French / German
        r"\bno soy (?:el|la) (?:verdader|real|autentic)",
        r"\bcuenta (?:de fans|falsa|no oficial)",
        r"\bno oficial\b",
        r"\bnao oficial\b",
        r"\bconta (?:de fa|falsa)",
        r"\bkein echter\b",
        r"\bnicht (?:der|die) echte\b",
        r"\bfanseite\b",
        r"\binoffiziell",
        r"\bpas (?:le|la) vrai",
        r"\bcompte (?:de fan|fan|parodique)",
        r"\bnon officiel",
        # Chinese / Japanese / Korean
        r"非官方|非公式|粉丝号|粉丝账号|恶搞|冒充|なりすまし|ファンアカウント|ファンページ|비공식",
    ]
)
_MARKER_RE = re.compile(fold(_MARKER_SOURCE), re.IGNORECASE)


def _public_http_url(url: str) -> bool:
    """An avatar may only be fetched from a public http(s) host on a standard port.

    Uses the shared host check (numeric IPv4 spellings, local names); the guarded transport adds
    the resolved-address check. Redirects are never followed when avatars are fetched, so a
    redirect cannot lead anywhere else.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or parts.username or parts.password:
        return False
    if port not in (None, 80, 443):
        return False
    return is_public_host(host)


# --------------------------------------------------------------------------------------------------
# Avatar perceptual hash (64-bit DCT pHash, Pillow optional)
# --------------------------------------------------------------------------------------------------

_HASH_SIZE = 32
_COSINES = [
    [math.cos((2 * x + 1) * u * math.pi / (2 * _HASH_SIZE)) for x in range(_HASH_SIZE)]
    for u in range(8)
]
PHASH_ALGORITHM = "phash64-dct"
MAX_AVATAR_BYTES = 5 * 1024 * 1024
_MAX_PIXELS = 64_000_000


def phash_pixels(pixels: Sequence[float]) -> int:
    """64-bit pHash of a 32x32 grayscale image given as 1024 row-major values.

    2-D DCT-II, the 8x8 low-frequency block, one bit per coefficient (above the AC median).
    """
    if len(pixels) != _HASH_SIZE * _HASH_SIZE:
        raise ValueError("Expected 1024 grayscale values (32x32)")
    rows = [
        [
            sum(pixels[y * _HASH_SIZE + x] * _COSINES[u][x] for x in range(_HASH_SIZE))
            for u in range(8)
        ]
        for y in range(_HASH_SIZE)
    ]
    block = [
        sum(rows[y][u] * _COSINES[v][y] for y in range(_HASH_SIZE))
        for v in range(8)
        for u in range(8)
    ]
    median = statistics.median(block[1:])
    value = 0
    for coefficient in block:
        value = (value << 1) | (1 if coefficient > median else 0)
    return value


def hamming(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def pillow_available() -> bool:
    try:
        import PIL.Image  # noqa: F401
    except ImportError:
        return False
    return True


def phash_image(data: bytes) -> int | None:
    """pHash of encoded image bytes; None without Pillow, for undecodable, huge or flat images."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(BytesIO(data)) as source:
            if source.width * source.height > _MAX_PIXELS:
                return None
            image = source.convert("RGBA")
        background = Image.new("RGBA", image.size, (255, 255, 255, 255))
        background.alpha_composite(image)
        gray = background.convert("L").resize((_HASH_SIZE, _HASH_SIZE), Image.Resampling.LANCZOS)
        pixels = list(gray.tobytes())
    except Exception:  # corrupt or unsupported image: skip, never fail the run
        return None
    if statistics.pstdev(pixels) < 2.0:  # blank/solid placeholder: every such image would "match"
        return None
    return phash_pixels(pixels)


@dataclass(frozen=True, slots=True)
class AvatarHash:
    """Hash with provenance: which URL was fetched, how, and how many bytes."""

    url: str
    phash: int
    size_bytes: int
    algorithm: str = PHASH_ALGORITHM

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "algorithm": self.algorithm,
            "hash": f"{self.phash:016x}",
            "bytes": self.size_bytes,
            "fetched_from": self.url,
        }


def _field(result: SearchResult, name: str) -> object:
    meta = result.profile_metadata
    return None if name in meta.conflicts else meta.get(name)


def _text(result: SearchResult, name: str) -> str:
    value = _field(result, name)
    return value.strip() if isinstance(value, str) else ""


def _is_hit(result: SearchResult) -> bool:
    return result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)


def result_key(result: SearchResult) -> str:
    """Stable key of a hit: its profile URL (``site:<site_id>`` when the URL is empty)."""
    return result.profile_url or f"site:{result.site_id}"


def _avatar_candidates(results: Sequence[SearchResult], min_hits: int) -> list[str]:
    counts: Counter[str] = Counter()
    for key_result in {result_key(r): r for r in results if _is_hit(r)}.values():
        url = _text(key_result, "avatar_url")
        if url:
            counts[url] += 1
    return sorted(
        url
        for url, hits in counts.items()
        if hits < min_hits and not _DEFAULT_AVATAR_RE.search(url) and _public_http_url(url)
    )


async def fetch_avatar_records(
    results: Sequence[SearchResult],
    transport: Transport,
    *,
    budget: int = 50,
    max_bytes: int = MAX_AVATAR_BYTES,
    concurrency: int = 4,
    request_timeout: TimeoutProfile | None = None,
    min_hits: int = DEFAULT_CONFIG.boilerplate_min_hits,
) -> dict[str, AvatarHash]:
    """Download avatars of hits through the engine transport and hash them.

    At most ``budget`` image requests (an enrichment-style budget), each limited to ``max_bytes``.
    Placeholder URLs and URLs shared by >= ``min_hits`` hits are not fetched at all. Without Pillow
    nothing is requested. Any failure of one image only drops that image.
    """
    if budget <= 0 or max_bytes <= 0 or not pillow_available():
        return {}
    urls = _avatar_candidates(results, min_hits)[:budget]
    gate = asyncio.Semaphore(max(1, concurrency))
    profile = request_timeout or TimeoutProfile(connect=5.0, read=10.0, total=15.0, queue=60.0)

    async def one(url: str) -> AvatarHash | None:
        async with gate:
            try:
                response = await transport.send(
                    TransportRequest(
                        url,
                        headers=(("Accept", "image/*"),),
                        timeout=profile,
                        body_limit=max_bytes,
                    )
                )
            except Exception:  # transport failure: the signal is optional
                return None
        if (
            response.error is not None
            or response.status != 200
            or not response.body_complete
            or not response.body
            or len(response.body) > max_bytes
        ):
            return None
        value = phash_image(response.body)
        return None if value is None else AvatarHash(url, value, len(response.body))

    fetched = await asyncio.gather(*(one(u) for u in urls))
    return {record.url: record for record in fetched if record is not None}


async def fetch_avatar_hashes(
    results: Sequence[SearchResult],
    transport: Transport,
    *,
    budget: int = 50,
    max_bytes: int = MAX_AVATAR_BYTES,
    concurrency: int = 4,
    request_timeout: TimeoutProfile | None = None,
    min_hits: int = DEFAULT_CONFIG.boilerplate_min_hits,
) -> dict[str, int]:
    """``{avatar_url: pHash}`` for ``score_identities``; ``fetch_avatar_records`` has provenance."""
    records = await fetch_avatar_records(
        results,
        transport,
        budget=budget,
        max_bytes=max_bytes,
        concurrency=concurrency,
        request_timeout=request_timeout,
        min_hits=min_hits,
    )
    return {url: record.phash for url, record in records.items()}


# --------------------------------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Hit:
    index: int
    result: SearchResult
    key: str
    url: str
    nick: str
    own: set[str]
    out: dict[str, set[str]]  # url key -> fields the link was found in
    urls: dict[str, str]  # url key -> the link as written
    display: str
    display_norm: str
    note: str
    note_field: str
    note_words: set[str]
    location: str
    avatar: str
    followers: int | None
    verified: bool
    has_data: bool
    markers: list[tuple[str, str]]  # (field, matched text)


def _count(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        match = re.fullmatch(r"\s*(\d+(?:[.,]\d+)?)\s*([kKmM]?)\s*", value.replace(" ", " "))
        if not match:
            digits = re.sub(r"[\s,.]", "", value)
            return int(digits) if digits.isdigit() else None
        number = float(match.group(1).replace(",", "."))
        return int(number * {"": 1, "k": 1_000, "m": 1_000_000}[match.group(2).lower()])
    return None


_DATA_FIELDS = (
    "display_name",
    "bio",
    "description",
    "location",
    "avatar_url",
    "website",
    "external_links",
    "followers",
    "verified",
)
_NON_LINK_FIELDS = frozenset(
    {
        "username",
        "display_name",
        "user_id",
        "avatar_url",
        "banner_url",
        "profile_url",
        "location",
        "followers",
        "following",
        "posts",
        "created_at",
        "updated_at",
        "latest_activity_at",
        "account_type",
        "verified",
        "category",
        "tags",
    }
)


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, tuple | list):
        return [v for v in value if isinstance(v, str)]
    return []


def _build_hit(index: int, result: SearchResult) -> _Hit:
    meta = result.profile_metadata
    url = result.profile_url
    own = {k for k in (url_key(url), url_key(_text(result, "profile_url"))) if k}
    out: dict[str, set[str]] = {}
    urls: dict[str, str] = {}

    def add(links: Mapping[str, str], field_name: str) -> None:
        for key, link in links.items():
            out.setdefault(key, set()).add(field_name)
            urls.setdefault(key, link)

    for name in ("website", "external_links"):
        if name in meta.conflicts:
            continue
        for candidate in meta.fields + meta.extra_fields:
            if candidate.name != name:
                continue
            for value in _strings(candidate.value):
                direct = url_key(value)
                links = extract_links(value)
                if direct:
                    links.setdefault(direct, _with_scheme(value.strip()))
                add(links, name)
    for name in ("bio", "description"):
        add(extract_links(_text(result, name)), name)
    for candidate in meta.extra_fields:
        if candidate.name in _NON_LINK_FIELDS or candidate.name in meta.conflicts:
            continue
        for value in _strings(candidate.value):
            add(extract_links(value), candidate.name)
    nick = result.username.raw
    display = _text(result, "display_name")
    bio, description = _text(result, "bio"), _text(result, "description")
    note_field, note = ("bio", bio) if bio else ("description", description)
    markers: list[tuple[str, str]] = []
    for name, value in (("bio", bio), ("description", description), ("display_name", display)):
        found = _MARKER_RE.search(fold(value)) if value else None
        if found:
            markers.append((name, found.group(0)))
    extra_text = any(isinstance(c.value, (str, tuple)) for c in meta.extra_fields)
    return _Hit(
        index=index,
        result=result,
        key=result_key(result),
        url=url or result_key(result),
        nick=nick,
        own=own,
        out=out,
        urls=urls,
        display=display,
        display_norm=" ".join(_tokens(display)),
        note=note,
        note_field=note_field,
        note_words=_words(note),
        location=" ".join(_tokens(_text(result, "location"))),
        avatar=_text(result, "avatar_url"),
        followers=_count(_field(result, "followers")),
        verified=_field(result, "verified") is True
        or (isinstance(_field(result, "verified"), str) and _field(result, "verified") == "true"),
        has_data=any(_field(result, n) not in (None, "", ()) for n in _DATA_FIELDS) or extra_text,
        markers=markers,
    )


def _same_account(a: _Hit, b: _Hit) -> bool:
    service_a, service_b = a.result.canonical_service, b.result.canonical_service
    return bool(a.own & b.own) or bool(service_a and service_a == service_b)


def _names_service(name: str, hit: _Hit) -> bool:
    bare = _bare(name)
    service = _bare(hit.result.canonical_service or hit.result.site_id)
    return len(service) >= 4 and service in bare


def _display_usable(hit: _Hit, config: IdentityConfig) -> bool:
    """A display name that can serve as evidence: long enough, not the nick, not a page template."""
    if len(hit.display_norm) < config.display_name_min_len:
        return False
    if _bare(hit.display) in {_bare(hit.nick), _bare(_text(hit.result, "username"))}:
        return False
    return not (_PAGE_TITLE_RE.search(hit.display) or _names_service(hit.display, hit))


def _signal(
    kind: str,
    weight: float,
    group: str,
    fields_used: Sequence[str],
    sources: Sequence[str],
    detail: str,
) -> IdentitySignal:
    return IdentitySignal(
        kind,
        round(weight, 4),
        group,
        tuple(sorted(set(fields_used))),
        tuple(sorted(set(sources))),
        detail,
    )


def _combine(parts: Sequence[float]) -> float:
    rest = 1.0
    for part in parts:
        rest *= 1 - part
    return 1 - rest


def _select_hits(results: Sequence[SearchResult]) -> list[_Hit]:
    """FOUND/PROBABLE hits in key order; the same account seen twice keeps the richer record."""
    chosen: dict[str, SearchResult] = {}
    for result in results:
        if not _is_hit(result):
            continue
        key = result_key(result)
        current = chosen.get(key)
        if current is None or len(_dump_fields(result)) > len(_dump_fields(current)):
            chosen[key] = result
    return [_build_hit(i, chosen[k]) for i, k in enumerate(sorted(chosen))]


_EDGE_FIELD_ORDER = ("external_links", "website", "bio", "description")


def _edge_field(fields_used: set[str]) -> str:
    for name in _EDGE_FIELD_ORDER:
        if name in fields_used:
            return name
    return min(fields_used)


def identity_graph(results: Sequence[SearchResult]) -> dict[str, JSONValue]:
    """Link graph of the scan's hits: nodes = profile URLs, edge A -> B when A links to B.

    ``reciprocal`` is true when B links back to A too (both directions are listed). Links come
    from website, external_links, bio, description and extra text fields of the profile.
    """
    hits = _select_hits(results)
    edges: list[tuple[str, str, bool, str]] = []
    for hit in hits:
        for other in hits:
            if other.index == hit.index or _same_account(hit, other):
                continue
            keys = [k for k in sorted(other.own) if k in hit.out]
            if keys:
                reciprocal = any(k in other.out for k in hit.own)
                edges.append((hit.url, other.url, reciprocal, _edge_field(hit.out[keys[0]])))
    listed: list[JSONValue] = [
        {"from": a, "to": b, "reciprocal": r, "source_field": f} for a, b, r, f in sorted(edges)
    ]
    nodes: list[JSONValue] = [h.url for h in sorted(hits, key=lambda h: h.url)]
    return {"nodes": nodes, "edges": listed}


_MAX_RELATED_PER_PROFILE = 50


def related_accounts(results: Sequence[SearchResult]) -> list[dict[str, JSONValue]]:
    """Accounts on known platforms that hits point to but the scan did not find (not hits).

    One entry per (link, linking profile): ``{url, platform, from_profile, field}``, sorted.
    """
    hits = _select_hits(results)
    scanned = {k for h in hits for k in h.own}
    found: list[tuple[str, str, dict[str, JSONValue]]] = []
    for hit in hits:
        taken = 0
        for key in sorted(hit.out):
            platform = classify_link(key)
            if platform is None or key in scanned:
                continue
            if taken >= _MAX_RELATED_PER_PROFILE:
                break
            taken += 1
            found.append(
                (
                    key,
                    hit.url,
                    {
                        "url": hit.urls.get(key, "https://" + key),
                        "platform": platform,
                        "from_profile": hit.url,
                        "field": _edge_field(hit.out[key]),
                    },
                )
            )
    found.sort(key=lambda item: (item[0], item[1]))
    return [entry for _, _, entry in found]


def score_identities(
    results: Sequence[SearchResult],
    seed: IdentitySeed | None = None,
    avatar_hashes: Mapping[str, int] | None = None,
    config: IdentityConfig = DEFAULT_CONFIG,
) -> dict[str, IdentityAssessment]:
    """Identity assessment of every FOUND/PROBABLE hit, keyed by ``result_key``.

    Deterministic: independent of the input order. Hits sharing a key (the same account seen
    through two definitions) are merged into the one with more metadata. Non-hits are not scored.
    """
    seed = seed if seed is not None and not seed.empty else None
    hashes = avatar_hashes or {}
    hits = _select_hits(results)
    seed_keys: dict[str, str] = {}
    seed_tokens: set[str] = set()
    if seed is not None:
        seed_keys = {k: u for u in seed.urls if (k := url_key(u))}
        seed_tokens = set(_tokens(seed.name))

    drafts: dict[int, list[IdentitySignal]] = {h.index: [] for h in hits}

    # --- avatar boilerplate -------------------------------------------------------------------
    url_counts = Counter(h.avatar for h in hits if h.avatar)

    def avatar_hash(hit: _Hit) -> int | None:
        return hashes.get(hit.avatar) if hit.avatar else None

    clusters: dict[int, int] = {}

    def hash_cluster(hit: _Hit) -> int:
        """Hits carrying (nearly) this avatar; >= boilerplate_min_hits means boilerplate."""
        mine = avatar_hash(hit)
        if mine is None:
            return 0
        if hit.index not in clusters:
            clusters[hit.index] = sum(
                1
                for other in hits
                if (h := avatar_hash(other)) is not None
                and hamming(mine, h) <= config.phash_max_distance
            )
        return clusters[hit.index]

    def url_usable(hit: _Hit) -> bool:
        return (
            bool(hit.avatar)
            and not _DEFAULT_AVATAR_RE.search(hit.avatar)
            and url_counts[hit.avatar] < config.boilerplate_min_hits
        )

    seed_hits = {h.index: bool(seed_keys and h.own & seed_keys.keys()) for h in hits}

    # --- link signals ---------------------------------------------------------------------------
    for hit in hits:
        reciprocal: dict[str, set[str]] = {}
        outbound: dict[str, set[str]] = {}
        inbound: dict[str, set[str]] = {}
        reciprocal_keys: set[str] = set()
        for other in hits:
            if other.index == hit.index or _same_account(hit, other):
                continue
            hit_links_other = [k for k in other.own if k in hit.out]
            other_links_hit = [k for k in hit.own if k in other.out]
            if hit_links_other and other_links_hit:
                reciprocal[other.url] = set(hit.out[hit_links_other[0]])
                reciprocal_keys |= other.own
            elif hit_links_other:
                # a link to the seed account is scored once, as ``link_to_seed``
                if not (seed_hits[other.index]):
                    outbound[other.url] = set(hit.out[hit_links_other[0]])
            elif other_links_hit and not seed_hits[hit.index]:
                inbound[other.url] = {"profile_url"}
        if reciprocal:
            drafts[hit.index].append(
                _signal(
                    "link_reciprocal",
                    config.w_link_reciprocal,
                    GROUP_CONTROL,
                    [f for fs in reciprocal.values() for f in fs],
                    list(reciprocal),
                    "both accounts point at each other",
                )
            )
        if outbound or inbound:
            drafts[hit.index].append(
                _signal(
                    "link_oneway",
                    config.w_link_oneway,
                    GROUP_CONTROL,
                    [f for fs in (*outbound.values(), *inbound.values()) for f in fs],
                    [*outbound, *inbound],
                    "links to " + str(len(outbound)) + " hit(s), linked from " + str(len(inbound)),
                )
            )
        if seed is not None:
            own_seed = [seed_keys[k] for k in hit.own if k in seed_keys]
            if own_seed:
                drafts[hit.index].append(
                    _signal(
                        "seed_url_match",
                        config.w_seed_url,
                        GROUP_CONTROL,
                        ["profile_url"],
                        own_seed,
                        "the profile URL is one the user gave as the target's",
                    )
                )
            linked_seed = [
                (k, seed_keys[k])
                for k in hit.out
                if k in seed_keys and k not in hit.own and k not in reciprocal_keys
            ]
            if linked_seed:
                drafts[hit.index].append(
                    _signal(
                        "link_to_seed",
                        config.w_link_oneway,
                        GROUP_CONTROL,
                        [f for k, _ in linked_seed for f in hit.out[k]],
                        [u for _, u in linked_seed],
                        "the profile links to a seed URL",
                    )
                )
        if hit.verified:
            drafts[hit.index].append(
                _signal(
                    "verified",
                    config.w_verified,
                    GROUP_CONTROL,
                    ["verified"],
                    [hit.url],
                    "platform-verified account",
                )
            )

    # --- seed name ------------------------------------------------------------------------------
    if seed is not None and seed_tokens:
        for hit in hits:
            display_tokens = set(_tokens(hit.display))
            if not display_tokens:
                continue
            similarity = _jaccard(display_tokens, seed_tokens)
            if (
                similarity >= config.name_jaccard_min
                and _bare(hit.display) != _bare(hit.nick)
                and _bare(hit.display) != _bare(_text(hit.result, "username"))
            ):
                drafts[hit.index].append(
                    _signal(
                        "seed_name_match",
                        config.w_seed_name,
                        GROUP_COPYABLE,
                        ["display_name"],
                        [hit.url],
                        f'display name "{hit.display[:60]}" matches the seed name '
                        f"(Jaccard {similarity:.2f})",
                    )
                )
            elif similarity == 0 and len(display_tokens) >= 2 and len(seed_tokens) >= 2:
                drafts[hit.index].append(
                    _signal(
                        "seed_name_conflict",
                        0.0,
                        GROUP_CONTRADICTION,
                        ["display_name"],
                        [hit.url],
                        f'display name "{hit.display[:60]}" shares no token with the seed name',
                    )
                )

    # --- pairwise copyable signals --------------------------------------------------------------
    for hit in hits:
        same_name: list[_Hit] = []
        same_bio: list[_Hit] = []
        same_loc: list[_Hit] = []
        same_avatar: list[tuple[_Hit, str]] = []
        for other in hits:
            if other.index == hit.index or _same_account(hit, other):
                continue
            if (
                _display_usable(hit, config)
                and _display_usable(other, config)
                and hit.display_norm == other.display_norm
            ):
                same_name.append(other)
            if (
                len(hit.note_words) >= config.bio_min_words
                and len(other.note_words) >= config.bio_min_words
                and _jaccard(hit.note_words, other.note_words) >= config.bio_jaccard_min
            ):
                same_bio.append(other)
            if len(hit.location) >= 3 and hit.location == other.location:
                same_loc.append(other)
            if url_usable(hit) and hit.avatar == other.avatar and url_usable(other):
                same_avatar.append((other, "identical avatar URL"))
            else:
                mine, theirs = avatar_hash(hit), avatar_hash(other)
                if (
                    mine is not None
                    and theirs is not None
                    and not _DEFAULT_AVATAR_RE.search(hit.avatar)
                    and not _DEFAULT_AVATAR_RE.search(other.avatar)
                    and hamming(mine, theirs) <= config.phash_max_distance
                    and hash_cluster(hit) < config.boilerplate_min_hits
                ):
                    same_avatar.append((other, f"pHash distance {hamming(mine, theirs)} bits"))
        sink = drafts[hit.index]
        if same_name:
            sink.append(
                _signal(
                    "same_display_name",
                    config.w_same_display_name,
                    GROUP_COPYABLE,
                    ["display_name"],
                    [o.url for o in same_name],
                    f'display name "{hit.display[:60]}" also on {len(same_name)} other hit(s)',
                )
            )
        if same_bio:
            sink.append(
                _signal(
                    "similar_bio",
                    config.w_similar_bio,
                    GROUP_COPYABLE,
                    [hit.note_field],
                    [o.url for o in same_bio],
                    f"similar text on {len(same_bio)} other hit(s)",
                )
            )
        if same_avatar:
            sink.append(
                _signal(
                    "same_avatar",
                    config.w_avatar,
                    GROUP_COPYABLE,
                    ["avatar_url"],
                    [o.url for o, _ in same_avatar],
                    "; ".join(sorted({why for _, why in same_avatar})),
                )
            )
        if same_loc:
            sink.append(
                _signal(
                    "same_location",
                    config.w_location,
                    GROUP_COPYABLE,
                    ["location"],
                    [o.url for o in same_loc],
                    f'location "{_text(hit.result, "location")[:60]}" also on '
                    f"{len(same_loc)} other hit(s)",
                )
            )

    # --- contradictions and reach ---------------------------------------------------------------
    for hit in hits:
        for field_name, matched in hit.markers:
            drafts[hit.index].append(
                _signal(
                    "impersonation_marker",
                    0.0,
                    GROUP_CONTRADICTION,
                    [field_name],
                    [hit.url],
                    f'"{matched}" marks a fan, parody or impersonation account',
                )
            )
        if (
            hit.followers is not None
            and hit.followers >= config.reach_followers
            and any(s.group in (GROUP_CONTROL, GROUP_COPYABLE) for s in drafts[hit.index])
        ):
            drafts[hit.index].append(
                _signal(
                    "reach",
                    config.w_reach,
                    GROUP_COPYABLE,
                    ["followers"],
                    [hit.url],
                    f"{hit.followers} followers",
                )
            )

    # --- combination and decision ---------------------------------------------------------------
    assessments: dict[str, IdentityAssessment] = {}
    for hit in hits:
        signals = sorted(
            drafts[hit.index], key=lambda s: (_GROUP_ORDER[s.group], s.kind, s.sources, s.detail)
        )
        control = [s.weight for s in signals if s.group == GROUP_CONTROL]
        copyable = [s.weight for s in signals if s.group == GROUP_COPYABLE]
        parts = control + ([min(config.copyable_cap, max(copyable))] if copyable else [])
        score = min(config.max_score, _combine(parts))
        contradicted = any(s.group == GROUP_CONTRADICTION for s in signals)
        if contradicted:
            score = min(score, config.contradiction_cap)
        if not signals and not hit.has_data:
            signals = [
                _signal(
                    NO_IDENTITY_DATA,
                    0.0,
                    GROUP_NONE,
                    [],
                    [hit.url],
                    "no profile fields usable for identity comparison",
                )
            ]
        if contradicted:
            decision = IdentityDecision.UNRELATED_LIKELY
        elif score >= config.threshold:
            decision = IdentityDecision.TARGET_LIKELY
        else:
            decision = IdentityDecision.UNDETERMINED
        assessments[hit.key] = IdentityAssessment(
            key=hit.key,
            profile_url=hit.result.profile_url,
            site_id=hit.result.site_id,
            score=round(score, 4),
            decision=decision,
            signals=tuple(signals),
            seed_used=any(s.kind in _SEED_KINDS for s in signals),
        )
    return assessments


def _dump_fields(result: SearchResult) -> tuple[str, ...]:
    meta = result.profile_metadata
    return tuple(f.name for f in meta.fields + meta.extra_fields)


# --------------------------------------------------------------------------------------------------
# Output document (used by the CLI and by tools/identity_offline.py)
# --------------------------------------------------------------------------------------------------


def identity_document(
    assessments: Mapping[str, IdentityAssessment],
    *,
    config: IdentityConfig = DEFAULT_CONFIG,
    seed: IdentitySeed | None = None,
    site_names: Mapping[str, str] | None = None,
    avatar_records: Mapping[str, AvatarHash] | None = None,
    images: bool = False,
    results: Sequence[SearchResult] | None = None,
) -> dict[str, JSONValue]:
    names = site_names or {}
    decisions = Counter(a.decision.value for a in assessments.values())
    profiles: list[JSONValue] = [
        a.to_dict(names.get(a.site_id)) for a in sorted(assessments.values(), key=lambda a: a.key)
    ]
    seed_value: JSONValue = (
        None if seed is None or seed.empty else {"name": seed.name, "urls": list(seed.urls)}
    )
    return {
        "threshold": config.threshold,
        "seed": seed_value,
        "images": images,
        "counts": dict(sorted(decisions.items())),
        "profiles": profiles,
        "graph": identity_graph(results or ()),
        "related_accounts": list(related_accounts(results or ())),
        "avatar_hashes": {
            url: record.to_dict() for url, record in sorted((avatar_records or {}).items())
        },
    }
