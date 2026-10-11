"""Deterministic response gates and narrowly scoped public profile evidence.

No JavaScript execution, HTTP, probabilistic scores, recursive identity searches or
promotion from reflected titles. Rules operate on the bounded downloaded response.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import cast
from urllib.parse import parse_qs, unquote, urlsplit

from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import ErrorCode, JSONValue, TransportResponse
from ultimate_username.profile_adapters import embedded_profile


@dataclass(frozen=True, slots=True)
class ResponseQuality:
    kind: str = "UNCLASSIFIED"
    reason: str = ""
    level: int = 0
    fields: tuple[tuple[str, JSONValue], ...] = ()
    partial_verified: bool = False
    locator: str = ""


class PageSignals(HTMLParser):
    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.in_title = False
        self.canonicals: list[str] = []
        self.meta: dict[str, str] = {}
        self.password = False
        self.iframes: list[str] = []
        self.anubis_structure = False
        self.feed(text[:1_048_576])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "link" and a.get("rel") == "canonical" and a.get("href"):
            self.canonicals.append(a["href"] or "")
        if tag == "meta":
            key = a.get("property") or a.get("name")
            if key:
                self.meta[key] = a.get("content") or ""
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.password = True
        if tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"] or "")
        if (
            tag == "script"
            and a.get("id") == "anubis_challenge"
            and a.get("type") == "application/json"
        ):
            self.anubis_structure = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data[:512]


def profile_url(url: object, host: str, path: str) -> bool:
    if not isinstance(url, str):
        return False
    p = urlsplit(url)
    return (
        p.scheme == "https"
        and p.netloc.lower() == host
        and unquote(p.path).rstrip("/").casefold() == path.rstrip("/").casefold()
        and not p.query
        and not p.fragment
    )


def profile_kind(url: str, username: str) -> str:
    p = urlsplit(url)
    routes = {
        "kick": ("kick.com", "/api/v2/channels/" + username),
        "chess": ("api.chess.com", "/pub/player/" + username),
        "faceit": ("www.faceit.com", "/api/users/v1/nicknames/" + username),
        "gog": ("www.gog.com", "/u/" + username),
        "mcbans": ("www.mcbans.com", "/api/players/" + username),
    }
    for kind, (host, path) in routes.items():
        if profile_url(url, host, path):
            return kind
    if p.scheme == "https" and p.netloc == "www.pinterest.com" and p.path == "/oembed.json":
        query = parse_qs(p.query)
        if set(query) == {"url"} and len(query["url"]) == 1:
            if profile_url(query["url"][0], "www.pinterest.com", "/" + username):
                return "pinterest"
    return ""


def reviewed_profile(response: TransportResponse, text: str, username: str) -> ResponseQuality:
    kind = profile_kind(response.requested_url, username)
    if not kind or profile_kind(response.final_url or response.requested_url, username) != kind:
        return ResponseQuality()
    if response.status != 200 or not response.body_complete or response.error:
        return ResponseQuality()
    try:
        if kind == "gog":
            marker = "window.profilesData.profileUser = "
            start = text.find(marker)
            if start < 0:
                return ResponseQuality()
            value, _ = json.JSONDecoder().raw_decode(text[start + len(marker) :].lstrip())
            data = cast(JSONValue, value)
        else:
            data = parse_json(text)
    except (ValueError, RecursionError):
        return ResponseQuality()
    if not isinstance(data, dict):
        return ResponseQuality()
    obj = data
    fields: dict[str, JSONValue] = {}
    if kind == "kick":
        user = data.get("user")
        if not isinstance(user, dict):
            return ResponseQuality()
        identity, uid = user.get("username"), user.get("id")
        if data.get("user_id") != uid or not isinstance(data.get("slug"), str):
            return ResponseQuality()
        if str(data["slug"]).casefold() != username.casefold():
            return ResponseQuality("WRONG_USER", "CHANNEL_SLUG_MISMATCH")
        fields = {
            "bio": user.get("bio"),
            "avatar_url": user.get("profile_pic"),
            "banner_url": data.get("banner_image"),
            "verified": data.get("verified"),
        }
    elif kind == "chess":
        identity, uid = data.get("username"), data.get("player_id")
        if not profile_url(
            data.get("url"), "www.chess.com", "/member/" + username
        ) or not profile_url(data.get("@id"), "api.chess.com", "/pub/player/" + username):
            return ResponseQuality("WRONG_USER", "PLAYER_PROFILE_URL_MISMATCH")
        fields = {
            "avatar_url": data.get("avatar"),
            "location": data.get("location") or data.get("country"),
            "followers": data.get("followers"),
            "created_at": data.get("joined"),
            "latest_activity_at": data.get("last_online"),
            "account_type": data.get("status"),
            "profile_url": data.get("url"),
        }
    elif kind == "faceit":
        payload = data.get("payload")
        if data.get("result") != "OK" or not isinstance(payload, dict):
            return ResponseQuality()
        obj = payload
        identity, uid = obj.get("nickname"), obj.get("id")
        fields = {
            "location": obj.get("country"),
            "created_at": obj.get("created_at"),
            "avatar_url": obj.get("avatar"),
            "account_type": obj.get("registration_status"),
        }
    elif kind == "gog":
        identity, uid = data.get("username"), data.get("userId")
        background = data.get("background")
        fields = {
            "avatar_url": data.get("avatar"),
            "created_at": data.get("created_date"),
            "banner_url": background.get("src") if isinstance(background, dict) else None,
        }
    elif kind == "mcbans":
        identity, uid = data.get("name"), data.get("playerId")
        uuid = data.get("uuid")
        if not isinstance(uuid, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", uuid):
            return ResponseQuality()
        fields = {"game_uuid": uuid, "reputation": data.get("reputation")}
    else:
        author = data.get("author_url")
        if not profile_url(author, "www.pinterest.com", "/" + username):
            return ResponseQuality("WRONG_USER", "OEMBED_AUTHOR_URL_MISMATCH")
        embed = data.get("html")
        name = data.get("author_name")
        if (
            data.get("provider_name") != "Pinterest"
            or data.get("type") != "rich"
            or not isinstance(embed, str)
        ):
            return ResponseQuality()
        frames = PageSignals(embed).iframes
        valid_embed = any(
            urlsplit(url).netloc == "assets.pinterest.com"
            and urlsplit(url).path == "/ext/embed.html"
            and parse_qs(urlsplit(url).query).get("grid", [""])[0].casefold() == username.casefold()
            for url in frames
        )
        if not valid_embed or not isinstance(name, str) or not name.strip() or name == "Pinterest":
            return ResponseQuality()
        return ResponseQuality(
            "PROFILE",
            "PINTEREST_AUTHOR_URL_AND_PROFILE_EMBED",
            3,
            (("username", username), ("display_name", name), ("profile_url", author)),
        )
    if isinstance(identity, str) and identity.casefold() != username.casefold():
        return ResponseQuality("WRONG_USER", "STRUCTURED_OWNER_MISMATCH")
    valid_id = (
        isinstance(uid, str)
        and bool(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uid))
        if kind == "faceit"
        else isinstance(uid, str) and 0 < len(uid) <= 32 and uid.isdecimal() and int(uid) > 0
        if kind == "gog"
        else type(uid) is int and uid > 0
    )
    if not isinstance(identity, str) or not identity or not valid_id:
        return ResponseQuality()
    fields.update({"username": identity, "user_id": uid})
    return ResponseQuality(
        "PROFILE", kind.upper() + "_BOUND_PROFILE_OBJECT", 4, tuple(fields.items())
    )


def discovery_url(profile: str, probe: str) -> bool:
    for url in (profile, probe):
        p = urlsplit(url)
        segments = p.path.lower().strip("/").split("/")
        if segments and segments[0] in ("search", "search.php") and (len(segments) > 1 or p.query):
            return True
        if p.netloc == "auth.roblox.com" and p.path == "/v1/usernames/validate":
            return True
    return False


def response_quality(
    response: TransportResponse, text: str, username: str, profile: str
) -> ResponseQuality:
    page = PageSignals(text) if "<" in text[:1000] else None
    title = unescape(page.title).strip().lower() if page else ""
    final = urlsplit(response.final_url or response.requested_url)
    host = final.hostname or ""
    if (response.header("x-amzn-waf-action") or "").lower() in ("challenge", "captcha"):
        return ResponseQuality("CHALLENGE", "EXPLICIT_WAF_CHALLENGE_HEADER")
    if page and (
        ("not a bot" in title and page.anubis_structure)
        or (title == "oh noes!" and page.anubis_structure)
        or (title == "security verification" and "/verify-human/" in final.path)
    ):
        return ResponseQuality("CHALLENGE", "VERIFIED_CHALLENGE_DOCUMENT")
    if (
        page
        and page.password
        and title in ("sign in", "signin", "log in", "login", "authentication required")
    ):
        return ResponseQuality("LOGIN_REQUIRED", "LOGIN_TITLE_AND_PASSWORD_FORM")
    if discovery_url(profile, response.requested_url):
        return ResponseQuality("DISCOVERY_ONLY", "SEARCH_OR_AVAILABILITY_ENDPOINT")
    original = urlsplit(profile)
    # Any host: after the redirect policy follows apex/www or alias hops, a profile URL that
    # ends on a site root is still the homepage, not a profile.
    if original.path not in ("", "/") and final.path in ("", "/"):
        return ResponseQuality("REDIRECT_ONLY", "PROFILE_REDIRECTED_TO_HOMEPAGE")
    if len(text) < 500 and re.search(r'window\.location\.href\s*=\s*["\']/lander["\']', text):
        return ResponseQuality("REDIRECT_ONLY", "PARKED_DOMAIN_LANDER_SCRIPT")
    if host in ("www.shelf.im", "shelf.im") and re.search(r"\bnotFound\s*:\s*true\b", text):
        return ResponseQuality("GENERIC_PAGE", "SHELF_EXPLICIT_NOT_FOUND_SHELL")
    if host == "forum.moonbeam.network" and "conversation continues on discord" in title:
        return ResponseQuality("GENERIC_PAGE", "FORUM_MIGRATION_LANDING")
    if host == "www.mercadolivre.com.br" and title == "parece que esta página não existe":
        return ResponseQuality("GENERIC_PAGE", "SOFT_404_TITLE")
    if host == "www.engadget.com" and title == "- engadget - engadget":
        return ResponseQuality("GENERIC_PAGE", "EMPTY_AUTHOR_TEMPLATE")
    if (
        host == "www.hozpitality.com"
        and page
        and title == "profile | hozpitality awards"
        and page.meta.get("og:type") == "article"
    ):
        return ResponseQuality("GENERIC_PAGE", "ARTICLE_ROUTE_NOT_USER_PROFILE")
    if (
        host == "www.mcbans.com"
        and page
        and "global banning system" in title
        and username not in text
    ):
        return ResponseQuality("GENERIC_PAGE", "APPLICATION_SHELL_WITHOUT_PROFILE")
    if host == "dating.rambler.ru" and page:
        parts = page.title.split("|")
        if (
            len(parts) >= 3
            and parts[-1].strip() == host
            and parts[-2].strip().casefold() != username.casefold()
        ):
            return ResponseQuality("WRONG_USER", "PROFILE_TITLE_OWNER_MISMATCH")
    reviewed = reviewed_profile(response, text, username)
    if reviewed.kind != "UNCLASSIFIED":
        return reviewed
    if response.error and response.error.code != ErrorCode.BODY_LIMIT:
        return reviewed
    embedded = embedded_profile(response, text, username, profile)
    if embedded:
        return ResponseQuality(
            "PROFILE",
            embedded.detector + "_BOUND_EMBEDDED_OBJECT",
            3 if embedded.detector in ("EngadgetAuthor", "RamblerOwner") else 4,
            embedded.fields,
            not response.body_complete,
            embedded.locator,
        )
    return reviewed
