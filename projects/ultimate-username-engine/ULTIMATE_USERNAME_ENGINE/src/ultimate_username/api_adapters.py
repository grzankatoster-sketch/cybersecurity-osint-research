"""Public profile-API adapters (E3): follow-up targets and bounded JSON parsing.

A confirmed hit (FOUND/PROBABLE) may get ONE extra GET to the public API of the platform that
serves the profile. Two kinds of adapters exist:

* families recognised from the profile page itself (Mastodon, Discourse, MediaWiki, Lemmy; Habbo
  by its hotel hosts), so one adapter covers every instance, and
* single platforms recognised by the profile host (Gravatar, Dailymotion, Farcaster, ...).

This module only builds the API URL and turns the JSON into candidate fields. It never touches
the network: the engine sends the request through its own transport and budget. Every adapter
binds the fields to the owner object (its username/acct/login/name equals the nick; usernames of
all supported services are case-insensitive, which is why the comparison is case-folded); anything
else yields no field and a diagnostic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, unquote, urljoin, urlsplit

from ultimate_username.domain.models import JSONValue, TransportResponse

API_BODY_LIMIT = 262_144
HTML_SCAN_LIMIT = 262_144
MAX_LINKS = 16
MAX_TAGS = 16

NO_PROFILE = "API_NO_PROFILE"
OWNER_FAILED = "OWNER_BINDING_FAILED"
PROFILE_HIDDEN = "API_PROFILE_HIDDEN"

_HABBO_HOST = re.compile(r"^(?:www\.)?habbo\.(?:com|es|nl|de|fr|it|fi|com\.br|com\.tr)$")
_DISCOURSE_PATH = re.compile(r"^/u/[^/]+\.json$")
_DEFAULT_BIOS = frozenset({"hey there! i am using spotistats", "hey there! i am using stats.fm"})
_LOCATION_LABELS = frozenset(
    {"location", "lokalizacja", "miejsce", "miejscowość", "ort", "lieu", "ubicación", "localização"}
)
_PLATFORM_URLS = {
    "x": "https://x.com/{}",
    "twitter": "https://x.com/{}",
    "github": "https://github.com/{}",
    "instagram": "https://www.instagram.com/{}",
    "telegram": "https://t.me/{}",
    "reddit": "https://www.reddit.com/user/{}",
}


@dataclass(frozen=True, slots=True)
class ApiTarget:
    kind: str
    url: str


@dataclass(frozen=True, slots=True)
class ApiField:
    name: str
    value: JSONValue
    locator: str


@dataclass(frozen=True, slots=True)
class ApiProfile:
    kind: str
    owner: str
    fields: tuple[ApiField, ...]


def _q(value: str) -> str:
    return quote(value, safe="")


def _same(value: object, nick: str) -> bool:
    return isinstance(value, str) and bool(nick) and value.casefold() == nick.casefold()


def _text(value: object, limit: int = 4096) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:limit] if stripped else None


def _count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _url(value: object) -> str | None:
    text = _text(value, 512)
    if text and text.lower().startswith(("http://", "https://")) and " " not in text:
        return text
    return None


def _links(values: object) -> list[JSONValue]:
    result: list[JSONValue] = []
    if not isinstance(values, (list, tuple)):
        return result
    for value in values:
        link = _url(value)
        if link and link not in result:
            result.append(link)
        if len(result) >= MAX_LINKS:
            break
    return result


class _TextOnly(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "br":
            self.parts.append("\n")
        elif tag == "a" and len(self.hrefs) < 32:
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("p", "div", "li"):
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _html(value: object) -> tuple[str | None, list[str]]:
    """Plain text and link targets of a small HTML fragment (Mastodon note, Discourse bio)."""
    raw = _text(value, 16384)
    if raw is None:
        return None, []
    parser = _TextOnly()
    try:
        parser.feed(raw)
        parser.close()
    except (ValueError, AssertionError):
        return None, []
    text = "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())
    return (text[:4096] or None), parser.hrefs


def _put(fields: list[ApiField], name: str, value: JSONValue, locator: str) -> None:
    if value is None or value == "" or value == []:
        return
    fields.append(ApiField(name, value, locator))


def _dict(value: object) -> dict[str, JSONValue] | None:
    return value if isinstance(value, dict) else None


# --------------------------------------------------------------------------- target selection


class _PageFacts(HTMLParser):
    """Generator meta, EditURI link, element ids and the lemmy-ui hydration marker."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.generator = ""
        self.edit_uri = ""
        self.ids: set[str] = set()
        self.lemmy = False
        self._script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if a.get("id") and len(self.ids) < 64:
            self.ids.add(a["id"])
        if tag == "meta" and a.get("name", "").lower() == "generator" and not self.generator:
            self.generator = a.get("content", "")[:120]
        elif tag == "link" and "edituri" in a.get("rel", "").lower().split():
            self.edit_uri = self.edit_uri or a.get("href", "")[:512]
        elif tag == "script":
            self._script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._script = False

    def handle_data(self, data: str) -> None:
        if self._script and "isoData" in data and "lemmy" in data.lower():
            self.lemmy = True


def _facts(response: TransportResponse) -> _PageFacts | None:
    ctype = (response.header("Content-Type") or "").lower()
    if not response.body or (ctype and "html" not in ctype):
        return None
    facts = _PageFacts()
    try:
        text = response.body[:HTML_SCAN_LIMIT].decode("utf-8", "replace")
        facts.feed(text)
        facts.close()
    except (ValueError, AssertionError):
        return None
    if not facts.lemmy and "lemmy-ui" in text.lower():
        facts.lemmy = True
    return facts


def _mastodon_header(response: TransportResponse) -> bool:
    return any(
        name.lower() in ("server", "x-powered-by", "x-generator") and "mastodon" in value.lower()
        for name, value in response.headers
    )


def _wiki_user(parts_path: str, query: str) -> str | None:
    title = (parse_qs(query).get("title") or [""])[0]
    if not title:
        segments = [unquote(s) for s in parts_path.split("/") if s]
        title = segments[-1] if segments else ""
    namespace, _, name = title.partition(":")
    return name if namespace.casefold() == "user" and name else None


def _wiki_same(value: object, nick: str) -> bool:
    if not isinstance(value, str):
        return False
    a, b = value.replace("_", " ").strip(), nick.replace("_", " ").strip()
    return bool(a) and a[:1].casefold() + a[1:] == b[:1].casefold() + b[1:]


def _family_target(profile_url: str, nick: str, response: TransportResponse) -> ApiTarget | None:
    parts = urlsplit(profile_url)
    base = f"{parts.scheme}://{parts.netloc}"
    final = urlsplit(response.final_url or response.requested_url)
    if response.status != 200 or (final.scheme, final.netloc.lower()) != (
        parts.scheme,
        parts.netloc.lower(),
    ):
        return None
    facts = _facts(response)
    if facts is None:
        return None
    segments = [unquote(s) for s in parts.path.split("/") if s]
    generator = facts.generator.casefold()
    if ("mastodon" in generator or "mastodon" in facts.ids or _mastodon_header(response)) and (
        len(segments) == 1
        and _same(segments[0], "@" + nick)
        or len(segments) == 2
        and segments[0] == "users"
        and _same(segments[1], nick)
    ):
        return ApiTarget("mastodon", f"{base}/api/v1/accounts/lookup?acct={_q(nick)}")
    if generator.startswith("discourse") and (
        len(segments) == 2 and segments[0] in ("u", "users") and _same(segments[1], nick)
    ):
        return ApiTarget("discourse", f"{base}/u/{_q(nick)}.json")
    if generator.startswith("mediawiki"):
        wiki_user = _wiki_user(parts.path, parts.query)
        if wiki_user is not None and _wiki_same(wiki_user, nick):
            api = f"{base}/api.php"
            if facts.edit_uri:
                candidate = urlsplit(urljoin(profile_url, facts.edit_uri))
                if (candidate.scheme, candidate.netloc.lower()) == (
                    parts.scheme,
                    parts.netloc.lower(),
                ) and candidate.path.endswith("api.php"):
                    api = f"{base}{candidate.path}"
            query = (
                f"action=query&list=users&ususers={_q(nick)}"
                "&usprop=registration%7Ceditcount%7Cgender&format=json"
            )
            return ApiTarget("mediawiki", f"{api}?{query}")
    if (
        (facts.lemmy or "lemmy" in generator)
        and len(segments) == 2
        and segments[0] == "u"
        and _same(segments[1], nick)
    ):
        return ApiTarget("lemmy", f"{base}/api/v3/user?username={_q(nick)}")
    return None


def _host_target(profile_url: str, nick: str) -> ApiTarget | None:
    parts = urlsplit(profile_url)
    host = (parts.hostname or "").lower()
    bare = host.removeprefix("www.")
    segments = [unquote(s) for s in parts.path.split("/") if s]
    last = segments[-1] if segments else ""
    q = _q(nick)
    if not _same(last, nick) and not (bare == "bsky.app" and len(segments) == 2):
        return None
    if (bare == "gravatar.com" or bare.endswith(".gravatar.com")) and len(segments) == 1:
        return ApiTarget("gravatar", f"https://api.gravatar.com/v3/profiles/{q}")
    if bare == "dailymotion.com" and (
        len(segments) == 1 or len(segments) == 2 and segments[0] == "user"
    ):
        fields = (
            "id,username,screenname,description,url,avatar_360_url,created_time,followers_total,"
            "website_url,facebook_url,twitter_url,instagram_url,country,language"
        )
        return ApiTarget("dailymotion", f"https://api.dailymotion.com/user/{q}?fields={fields}")
    if bare in ("warpcast.com", "farcaster.xyz") and len(segments) == 1:
        return ApiTarget("farcaster", f"https://api.warpcast.com/v2/user-by-username?username={q}")
    if bare == "picsart.com" and len(segments) == 2 and segments[0] == "u":
        return ApiTarget("picsart", f"https://api.picsart.com/users/show/{q}.json")
    if bare == "bandlab.com" and len(segments) == 1 and segments[0] != "api":
        return ApiTarget("bandlab", f"https://www.bandlab.com/api/v1.3/users/{q}")
    if bare == "inaturalist.org" and len(segments) == 2 and segments[0] == "people":
        return ApiTarget("inaturalist", f"https://api.inaturalist.org/v1/users/{q}")
    if (bare == "picarto.tv" or bare.endswith(".picarto.tv")) and 1 <= len(segments) <= 2:
        return ApiTarget("picarto", f"https://api.picarto.tv/api/v1/channel/name/{q}")
    if bare == "stats.fm" and len(segments) == 1:
        return ApiTarget("statsfm", f"https://api.stats.fm/api/v1/users/{q}")
    if bare == "keybase.io" and len(segments) == 1:
        lookup = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={q}"
        return ApiTarget("keybase", lookup + "&fields=basics,profile,proofs_summary")
    if _HABBO_HOST.match(host) and len(segments) == 2 and segments[0] == "profile":
        return ApiTarget("habbo", f"https://{parts.netloc}/api/public/users?name={q}")
    if bare == "bsky.app" and len(segments) == 2 and segments[0] == "profile":
        actor = segments[1].casefold()
        handle = actor if "." in actor else actor + ".bsky.social"
        if handle.split(".")[0] == nick.casefold():
            base = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
            return ApiTarget("bluesky", f"{base}?actor={_q(handle)}")
    return None


def select_target(profile_url: str, nick: str, response: TransportResponse) -> ApiTarget | None:
    """The one public API request worth making for this confirmed profile, or None."""
    try:
        if not nick or urlsplit(profile_url).scheme not in ("http", "https"):
            return None
        return _host_target(profile_url, nick) or _family_target(profile_url, nick, response)
    except (ValueError, UnicodeError):
        return None


def api_kind(url: str) -> str | None:
    """Which adapter owns a response fetched from this API URL (None: not an API follow-up)."""
    try:
        parts = urlsplit(url)
        host, path = (parts.hostname or "").lower(), parts.path
        query = parse_qs(parts.query)
    except ValueError:
        return None
    exact = {
        ("api.gravatar.com", "/v3/profiles/"): "gravatar",
        ("api.dailymotion.com", "/user/"): "dailymotion",
        ("api.picsart.com", "/users/show/"): "picsart",
        ("www.bandlab.com", "/api/v1.3/users/"): "bandlab",
        ("api.picarto.tv", "/api/v1/channel/name/"): "picarto",
        ("api.stats.fm", "/api/v1/users/"): "statsfm",
        ("api.inaturalist.org", "/v1/users/"): "inaturalist",
    }
    for (api_host, prefix), kind in exact.items():
        if host == api_host and path.startswith(prefix) and len(path) > len(prefix):
            return kind
    if host == "api.warpcast.com" and path == "/v2/user-by-username":
        return "farcaster"
    if host == "public.api.bsky.app" and path == "/xrpc/app.bsky.actor.getProfile":
        return "bluesky"
    if host == "keybase.io" and path == "/_/api/1.0/user/lookup.json":
        return "keybase"
    if _HABBO_HOST.match(host) and path == "/api/public/users":
        return "habbo"
    if path == "/api/v1/accounts/lookup" and "acct" in query:
        return "mastodon"
    if path == "/api/v3/user" and "username" in query:
        return "lemmy"
    if _DISCOURSE_PATH.match(path):
        return "discourse"
    if (
        path.endswith("api.php")
        and query.get("action") == ["query"]
        and query.get("list") == ["users"]
    ):
        return "mediawiki"
    return None


# --------------------------------------------------------------------------- adapters

Result = ApiProfile | str


def _mastodon(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None:
        return NO_PROFILE
    acct, username = obj.get("acct"), obj.get("username")
    page = obj.get("url")
    if not (_same(acct, nick) and _same(username, nick)):
        return OWNER_FAILED
    if isinstance(page, str) and urlsplit(page).netloc.lower() != urlsplit(url).netloc.lower():
        return OWNER_FAILED
    owner = str(username)
    note, note_links = _html(obj.get("note"))
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.username")
    _put(fields, "user_id", _text(obj.get("id"), 64), "$.id")
    _put(fields, "display_name", _text(obj.get("display_name"), 512), "$.display_name")
    _put(fields, "bio", note, "$.note")
    _put(fields, "avatar_url", _url(obj.get("avatar")), "$.avatar")
    _put(fields, "banner_url", _url(obj.get("header")), "$.header")
    _put(fields, "created_at", _text(obj.get("created_at"), 64), "$.created_at")
    _put(fields, "followers", _count(obj.get("followers_count")), "$.followers_count")
    _put(fields, "following", _count(obj.get("following_count")), "$.following_count")
    _put(fields, "posts", _count(obj.get("statuses_count")), "$.statuses_count")
    _put(fields, "latest_activity_at", _text(obj.get("last_status_at"), 64), "$.last_status_at")
    if obj.get("bot") is True:
        _put(fields, "account_type", "bot", "$.bot")
    links: list[str] = list(note_links)
    meta = obj.get("fields")
    for item in meta[:8] if isinstance(meta, list) else []:
        entry = _dict(item)
        if entry is None:
            continue
        value, hrefs = _html(entry.get("value"))
        label = _text(entry.get("name"), 64)
        if label and label.casefold() in _LOCATION_LABELS and value and not hrefs:
            _put(fields, "location", value, "$.fields.location")
        links.extend(hrefs)
    external = _links(links)
    _put(fields, "external_links", external, "$.fields[].value")
    if external:
        _put(fields, "website", external[0], "$.fields[].value")
    return ApiProfile("MastodonApi", owner, tuple(fields))


def _gravatar(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None:
        return NO_PROFILE
    page = urlsplit(str(obj.get("profile_url") or ""))
    host = (page.hostname or "").lower().removeprefix("www.")
    segments = [unquote(s) for s in page.path.split("/") if s]
    if not (
        (host == "gravatar.com" or host.endswith(".gravatar.com"))
        and len(segments) == 1
        and _same(segments[0], nick)
    ):
        return OWNER_FAILED
    owner = segments[0]
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.profile_url")
    _put(fields, "display_name", _text(obj.get("display_name"), 512), "$.display_name")
    _put(fields, "bio", _text(obj.get("description")), "$.description")
    _put(fields, "location", _text(obj.get("location"), 256), "$.location")
    # No avatar: the API always returns an avatar_url, even for the default Gravatar logo, and
    # nothing in the profile says whether an image was ever uploaded (only ?d=404 would tell).
    _put(fields, "company", _text(obj.get("company"), 256), "$.company")
    urls: list[object] = []
    for key in ("links", "verified_accounts"):
        items = obj.get(key)
        for item in items[:16] if isinstance(items, list) else []:
            entry = _dict(item)
            if entry is not None:
                urls.append(entry.get("url"))
    external = _links(urls)
    _put(fields, "external_links", external, "$.links[].url")
    if external:
        _put(fields, "website", external[0], "$.links[].url")
    return ApiProfile("GravatarApi", owner, tuple(fields))


def _dailymotion(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None or "error" in obj:
        return NO_PROFILE
    if not _same(obj.get("username"), nick):
        return OWNER_FAILED
    owner = str(obj["username"])
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.username")
    _put(fields, "user_id", _text(obj.get("id"), 64), "$.id")
    _put(fields, "display_name", _text(obj.get("screenname"), 512), "$.screenname")
    _put(fields, "bio", _text(obj.get("description")), "$.description")
    _put(fields, "avatar_url", _url(obj.get("avatar_360_url")), "$.avatar_360_url")
    _put(fields, "created_at", _count(obj.get("created_time")), "$.created_time")
    _put(fields, "followers", _count(obj.get("followers_total")), "$.followers_total")
    _put(fields, "location", _text(obj.get("country"), 64), "$.country")
    _put(fields, "language", _text(obj.get("language"), 16), "$.language")
    website = _url(obj.get("website_url"))
    _put(fields, "website", website, "$.website_url")
    external = _links(
        [obj.get(k) for k in ("website_url", "facebook_url", "twitter_url", "instagram_url")]
    )
    _put(fields, "external_links", external, "$.*_url")
    return ApiProfile("DailymotionApi", owner, tuple(fields))


def _farcaster(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    result = _dict(root.get("result")) if root else None
    user = _dict(result.get("user")) if result else None
    if user is None:
        return NO_PROFILE
    if not _same(user.get("username"), nick):
        return OWNER_FAILED
    owner = str(user["username"])
    profile = _dict(user.get("profile")) or {}
    bio = _dict(profile.get("bio")) or {}
    place = _dict(profile.get("location")) or {}
    pfp = _dict(user.get("pfp")) or {}
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.result.user.username")
    _put(fields, "user_id", _count(user.get("fid")), "$.result.user.fid")
    _put(fields, "display_name", _text(user.get("displayName"), 512), "$.result.user.displayName")
    _put(fields, "bio", _text(bio.get("text")), "$.result.user.profile.bio.text")
    _put(fields, "location", _text(place.get("description"), 256), "$.result.user.profile.location")
    _put(fields, "avatar_url", _url(pfp.get("url")), "$.result.user.pfp.url")
    _put(fields, "followers", _count(user.get("followerCount")), "$.result.user.followerCount")
    _put(fields, "following", _count(user.get("followingCount")), "$.result.user.followingCount")
    accounts = user.get("connectedAccounts")
    urls: list[object] = []
    for item in accounts[:16] if isinstance(accounts, list) else []:
        entry = _dict(item)
        if entry is None:
            continue
        platform, handle = _text(entry.get("platform"), 32), _text(entry.get("username"), 128)
        template = _PLATFORM_URLS.get((platform or "").casefold())
        if template and handle and re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", handle):
            urls.append(template.format(_q(handle)))
    _put(fields, "external_links", _links(urls), "$.result.user.connectedAccounts")
    return ApiProfile("FarcasterApi", owner, tuple(fields))


def _habbo(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None:
        return NO_PROFILE
    if not _same(obj.get("name"), nick):
        return OWNER_FAILED
    owner = str(obj["name"])
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.name")
    _put(fields, "user_id", _text(obj.get("uniqueId"), 64), "$.uniqueId")
    _put(fields, "bio", _text(obj.get("motto"), 512), "$.motto")
    _put(fields, "created_at", _text(obj.get("memberSince"), 64), "$.memberSince")
    _put(fields, "latest_activity_at", _text(obj.get("lastAccessTime"), 64), "$.lastAccessTime")
    return ApiProfile("HabboApi", owner, tuple(fields))


def _picsart(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None or obj.get("status") != "success":
        return NO_PROFILE
    if not _same(obj.get("username"), nick):
        return OWNER_FAILED
    owner = str(obj["username"])
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.username")
    _put(fields, "user_id", _count(obj.get("id")), "$.id")
    _put(fields, "display_name", _text(obj.get("name"), 512), "$.name")
    _put(fields, "bio", _text(obj.get("status_message")), "$.status_message")
    if obj.get("default_profile_pic") is not True:
        _put(fields, "avatar_url", _url(obj.get("photo")), "$.photo")
    _put(fields, "banner_url", _url(obj.get("cover")), "$.cover")
    _put(fields, "followers", _count(obj.get("followers_count")), "$.followers_count")
    _put(fields, "following", _count(obj.get("following_count")), "$.following_count")
    _put(fields, "posts", _count(obj.get("photos_count")), "$.photos_count")
    if isinstance(obj.get("is_verified"), bool):
        _put(fields, "verified", obj["is_verified"], "$.is_verified")
    return ApiProfile("PicsartApi", owner, tuple(fields))


def _names(items: object) -> list[JSONValue]:
    result: list[JSONValue] = []
    for item in items[:MAX_TAGS] if isinstance(items, list) else []:
        entry = _dict(item)
        name = _text(entry.get("name"), 64) if entry else _text(item, 64)
        if name and name not in result:
            result.append(name)
    return result


def _bandlab(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None:
        return NO_PROFILE
    if not _same(obj.get("username"), nick):
        return OWNER_FAILED
    owner = str(obj["username"])
    picture = _dict(obj.get("picture")) or {}
    background = _dict(obj.get("backgroundPicture")) or {}
    counters = _dict(obj.get("counters")) or {}
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.username")
    _put(fields, "user_id", _text(obj.get("id"), 64), "$.id")
    _put(fields, "display_name", _text(obj.get("name"), 512), "$.name")
    _put(fields, "bio", _text(obj.get("about")), "$.about")
    if picture.get("isDefault") is not True:
        _put(fields, "avatar_url", _url(picture.get("url")), "$.picture.url")
    if background.get("isDefault") is not True:
        _put(fields, "banner_url", _url(background.get("url")), "$.backgroundPicture.url")
    _put(fields, "created_at", _text(obj.get("createdOn"), 64), "$.createdOn")
    _put(fields, "followers", _count(counters.get("followers")), "$.counters.followers")
    _put(fields, "following", _count(counters.get("following")), "$.counters.following")
    if isinstance(obj.get("isVerified"), bool):
        _put(fields, "verified", obj["isVerified"], "$.isVerified")
    place = obj.get("place")
    _put(
        fields,
        "location",
        _text(place) if isinstance(place, str) else _text((_dict(place) or {}).get("name"), 256),
        "$.place",
    )
    _put(fields, "tags", _names(obj.get("genres")) + _names(obj.get("skills")), "$.genres")
    links = _dict(obj.get("links"))
    _put(fields, "external_links", _links(list(links.values())) if links else [], "$.links")
    return ApiProfile("BandLabApi", owner, tuple(fields))


def _picarto(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None:
        return NO_PROFILE
    if not _same(obj.get("name"), nick):
        return OWNER_FAILED
    owner = str(obj["name"])
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.name")
    _put(fields, "user_id", _count(obj.get("user_id")), "$.user_id")
    _put(fields, "display_name", _text(obj.get("name"), 512), "$.name")
    _put(fields, "avatar_url", _url(obj.get("avatar")), "$.avatar")
    _put(fields, "created_at", _text(obj.get("creation_date"), 64), "$.creation_date")
    _put(fields, "followers", _count(obj.get("followers")), "$.followers")
    _put(fields, "tags", _names(obj.get("category")), "$.category")
    return ApiProfile("PicartoApi", owner, tuple(fields))


def _statsfm(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    obj = _dict(root.get("item")) if root else None
    if obj is None:
        return NO_PROFILE
    if not _same(obj.get("customId"), nick):
        return OWNER_FAILED
    owner = str(obj["customId"])
    profile = _dict(obj.get("profile")) or {}
    bio = _text(profile.get("bio"))
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.item.customId")
    _put(fields, "user_id", _text(obj.get("id"), 64), "$.item.id")
    _put(fields, "display_name", _text(obj.get("displayName"), 512), "$.item.displayName")
    if bio and bio.casefold() not in _DEFAULT_BIOS:
        _put(fields, "bio", bio, "$.item.profile.bio")
    _put(fields, "avatar_url", _url(obj.get("image")), "$.item.image")
    _put(fields, "created_at", _text(obj.get("createdAt"), 64), "$.item.createdAt")
    return ApiProfile("StatsFmApi", owner, tuple(fields))


def _inaturalist(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    results = root.get("results") if root else None
    if not isinstance(results, list):
        return NO_PROFILE
    owners = [
        entry
        for entry in (_dict(item) for item in results[:50])
        if entry and (_same(entry.get("login_exact"), nick) or _same(entry.get("login"), nick))
    ]
    if not owners:
        return OWNER_FAILED if results else NO_PROFILE
    if len({entry.get("id") for entry in owners}) != 1:
        return OWNER_FAILED
    obj = owners[0]
    owner = str(obj.get("login_exact") or obj.get("login"))
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.results[].login_exact")
    _put(fields, "user_id", _count(obj.get("id")), "$.results[].id")
    _put(fields, "display_name", _text(obj.get("name"), 512), "$.results[].name")
    _put(fields, "bio", _text(obj.get("description")), "$.results[].description")
    _put(
        fields,
        "avatar_url",
        _url(obj.get("icon_url")) or _url(obj.get("icon")),
        "$.results[].icon_url",
    )
    _put(fields, "created_at", _text(obj.get("created_at"), 64), "$.results[].created_at")
    _put(fields, "posts", _count(obj.get("observations_count")), "$.results[].observations_count")
    return ApiProfile("INaturalistApi", owner, tuple(fields))


def _lemmy(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    view = _dict(root.get("person_view")) if root else None
    person = _dict(view.get("person")) if view else None
    if person is None or view is None:
        return NO_PROFILE
    if not _same(person.get("name"), nick):
        return OWNER_FAILED
    if person.get("deleted") is True:
        return NO_PROFILE
    owner = str(person["name"])
    counts = _dict(view.get("counts")) or {}
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.person_view.person.name")
    _put(fields, "user_id", _count(person.get("id")), "$.person_view.person.id")
    _put(fields, "display_name", _text(person.get("display_name"), 512), "$.person_view.person")
    _put(fields, "bio", _text(person.get("bio")), "$.person_view.person.bio")
    _put(fields, "avatar_url", _url(person.get("avatar")), "$.person_view.person.avatar")
    _put(fields, "banner_url", _url(person.get("banner")), "$.person_view.person.banner")
    _put(fields, "created_at", _text(person.get("published"), 64), "$.person_view.person.published")
    _put(fields, "posts", _count(counts.get("post_count")), "$.person_view.counts.post_count")
    if person.get("bot_account") is True:
        _put(fields, "account_type", "bot", "$.person_view.person.bot_account")
    return ApiProfile("LemmyApi", owner, tuple(fields))


def _discourse(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    user = _dict(root.get("user")) if root else None
    if user is None:
        return NO_PROFILE
    if not _same(user.get("username"), nick):
        return OWNER_FAILED
    owner = str(user["username"])
    if user.get("profile_hidden") is True:
        return PROFILE_HIDDEN
    bio = _text(user.get("bio_raw")) or _html(user.get("bio_excerpt"))[0]
    template = _text(user.get("avatar_template"), 512)
    avatar = None
    if template and "letter_avatar" not in template:
        avatar = template.replace("{size}", "240")
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.user.username")
    _put(fields, "user_id", _count(user.get("id")), "$.user.id")
    _put(fields, "display_name", _text(user.get("name"), 512), "$.user.name")
    _put(fields, "bio", bio, "$.user.bio_raw")
    _put(fields, "location", _text(user.get("location"), 256), "$.user.location")
    _put(fields, "website", _url(user.get("website")), "$.user.website")
    _put(fields, "avatar_url", avatar, "$.user.avatar_template")
    _put(fields, "created_at", _text(user.get("created_at"), 64), "$.user.created_at")
    _put(
        fields,
        "latest_activity_at",
        _text(user.get("last_seen_at") or user.get("last_posted_at"), 64),
        "$.user.last_seen_at",
    )
    _put(fields, "posts", _count(user.get("post_count")), "$.user.post_count")
    return ApiProfile("DiscourseApi", owner, tuple(fields))


def _mediawiki(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    query = _dict(root.get("query")) if root else None
    users = query.get("users") if query else None
    if not isinstance(users, list):
        return NO_PROFILE
    owners = [
        entry
        for entry in (_dict(item) for item in users[:50])
        if entry and _wiki_same(entry.get("name"), nick)
    ]
    if not owners:
        return OWNER_FAILED if users else NO_PROFILE
    obj = owners[0]
    if "missing" in obj or "invalid" in obj:
        return NO_PROFILE
    fields: list[ApiField] = []
    _put(fields, "username", nick, "$.query.users[].name")
    _put(fields, "user_id", _count(obj.get("userid")), "$.query.users[].userid")
    _put(fields, "created_at", _text(obj.get("registration"), 64), "$.query.users[].registration")
    _put(fields, "posts", _count(obj.get("editcount")), "$.query.users[].editcount")
    gender = _text(obj.get("gender"), 16)
    if gender in ("male", "female"):
        _put(fields, "gender", gender, "$.query.users[].gender")
    return ApiProfile("MediaWikiApi", nick, tuple(fields))


def _bluesky(data: JSONValue, nick: str, url: str) -> Result:
    obj = _dict(data)
    if obj is None or "error" in obj:
        return NO_PROFILE
    actor = (parse_qs(urlsplit(url).query).get("actor") or [""])[0]
    handle = obj.get("handle")
    if not (
        isinstance(handle, str)
        and handle.casefold() == actor.casefold()
        and handle.split(".")[0].casefold() == nick.casefold()
    ):
        return OWNER_FAILED
    owner = handle.split(".")[0]
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.handle")
    _put(fields, "user_id", _text(obj.get("did"), 128), "$.did")
    _put(fields, "display_name", _text(obj.get("displayName"), 512), "$.displayName")
    _put(fields, "bio", _text(obj.get("description")), "$.description")
    _put(fields, "avatar_url", _url(obj.get("avatar")), "$.avatar")
    _put(fields, "banner_url", _url(obj.get("banner")), "$.banner")
    _put(fields, "created_at", _text(obj.get("createdAt"), 64), "$.createdAt")
    _put(fields, "followers", _count(obj.get("followersCount")), "$.followersCount")
    _put(fields, "following", _count(obj.get("followsCount")), "$.followsCount")
    _put(fields, "posts", _count(obj.get("postsCount")), "$.postsCount")
    return ApiProfile("BlueskyApi", owner, tuple(fields))


def _keybase(data: JSONValue, nick: str, url: str) -> Result:
    root = _dict(data)
    them = root.get("them") if root else None
    if not isinstance(them, list) or not them:
        return NO_PROFILE
    obj = _dict(them[0])
    if obj is None:
        return NO_PROFILE
    basics = _dict(obj.get("basics")) or {}
    if not _same(basics.get("username"), nick):
        return OWNER_FAILED
    owner = str(basics["username"])
    profile = _dict(obj.get("profile")) or {}
    summary = _dict(obj.get("proofs_summary")) or {}
    proofs = summary.get("all")
    urls: list[object] = []
    website: str | None = None
    for item in proofs[:32] if isinstance(proofs, list) else []:
        proof = _dict(item)
        if proof is None or proof.get("state") not in (1, None):
            continue
        link = _url(proof.get("service_url"))
        if link:
            urls.append(link)
            if website is None and proof.get("proof_type") in ("dns", "generic_web_site"):
                website = link
    fields: list[ApiField] = []
    _put(fields, "username", owner, "$.them[0].basics.username")
    _put(fields, "user_id", _text(obj.get("id"), 64), "$.them[0].id")
    _put(fields, "display_name", _text(profile.get("full_name"), 512), "$.them[0].profile")
    _put(fields, "bio", _text(profile.get("bio")), "$.them[0].profile.bio")
    _put(fields, "location", _text(profile.get("location"), 256), "$.them[0].profile.location")
    _put(fields, "created_at", _count(basics.get("ctime")), "$.them[0].basics.ctime")
    _put(fields, "website", website, "$.them[0].proofs_summary.all")
    _put(fields, "external_links", _links(urls), "$.them[0].proofs_summary.all")
    return ApiProfile("KeybaseApi", owner, tuple(fields))


_ADAPTERS = {
    "mastodon": _mastodon,
    "gravatar": _gravatar,
    "dailymotion": _dailymotion,
    "farcaster": _farcaster,
    "habbo": _habbo,
    "picsart": _picsart,
    "bandlab": _bandlab,
    "picarto": _picarto,
    "statsfm": _statsfm,
    "inaturalist": _inaturalist,
    "lemmy": _lemmy,
    "discourse": _discourse,
    "mediawiki": _mediawiki,
    "bluesky": _bluesky,
    "keybase": _keybase,
}


def parse_api(url: str, data: JSONValue, nick: str) -> Result:
    """Owner-bound fields of one API answer, or a diagnostic code when nothing may be used."""
    kind = api_kind(url)
    adapter = _ADAPTERS.get(kind or "")
    if adapter is None:
        return NO_PROFILE
    return adapter(data, nick, url)
