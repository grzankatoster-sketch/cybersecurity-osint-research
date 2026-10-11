"""Bounded public embedded-state adapters. Data parsing only; never JavaScript execution."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import JSONValue, TransportResponse
from ultimate_username.literal_data import read_literal


@dataclass(frozen=True, slots=True)
class AdapterProfile:
    detector: str
    fields: tuple[tuple[str, JSONValue], ...]
    locator: str
    partial_document: bool = False


class EmbeddedDocuments(HTMLParser):
    """Only closed script elements count as complete evidence units."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[tuple[str, str]] = []
        self.canonicals: list[str] = []
        self.active: tuple[str, list[str]] | None = None
        self.meta: dict[str, str] = {}
        self.title = ""
        self.heading = ""
        self.in_title = self.in_heading = False
        self.classes: set[str] = set()
        self.links: list[str] = []
        self.author_images: list[dict[str, str | None]] = []
        self.feed(text[:1_048_576])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = (values.get("class") or "").split()
        self.classes.update(classes)
        if tag == "title":
            self.in_title = True
        if tag == "h1" and "page-header" in classes:
            self.in_heading = True
        if tag == "a" and values.get("href"):
            self.links.append(values.get("href") or "")
        if tag == "img" and "author-image" in classes:
            self.author_images.append(values)
        if tag == "meta":
            key = values.get("property") or values.get("name") or ""
            self.meta[key] = values.get("content") or ""
        if tag == "script":
            self.active = (values.get("id") or values.get("type") or "script", [])
        if tag == "link" and "canonical" in (values.get("rel") or "").lower().split():
            self.canonicals.append(values.get("href") or "")

    def handle_data(self, data: str) -> None:
        if self.active:
            self.active[1].append(data)
        if self.in_title:
            self.title += data[:512]
        if self.in_heading:
            self.heading += data[:512]

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        if tag == "h1":
            self.in_heading = False
        if tag == "script" and self.active:
            kind, chunks = self.active
            text = "".join(chunks)
            # Ignore large executable libraries; retain bounded data scripts.
            relevant = kind in ("application/ld+json", "application/json", "__NEXT_DATA__") or any(
                marker in text for marker in ("urql_transport", "initialRoomDossier", "kit.start")
            )
            if relevant and len(text) <= 262_144 and len(self.scripts) < 128:
                self.scripts.append((kind, text))
            self.active = None


def same_profile(left: object, right: str) -> bool:
    if not isinstance(left, str):
        return False
    try:
        a, b = urlsplit(left), urlsplit(right)
        return (
            a.scheme == b.scheme == "https"
            and a.netloc.lower() == b.netloc.lower()
            and unquote(a.path).rstrip("/").casefold() == unquote(b.path).rstrip("/").casefold()
            and not a.query
            and not a.fragment
            and not b.query
            and not b.fragment
        )
    except ValueError:
        return False


def scoped_adapter_route(profile: str, probe: str) -> bool:
    routes = (
        "https://opensea.io/{username}",
        "https://chaturbate.com/{username}/",
        "https://www.engadget.com/author/{username}/",
        "https://www.shelf.im/{username}",
        "https://dating.rambler.ru/page/{username}",
    )
    return profile in routes and (probe or profile) == profile


def identifier(value: JSONValue) -> bool:
    return (
        type(value) is int
        and value > 0
        or isinstance(value, str)
        and bool(re.fullmatch(r"[0-9]{1,32}|[0-9a-fA-F]{32}|[0-9a-fA-F-]{36}", value))
        and any(c != "0" and c != "-" for c in value)
    )


def opensea(document: EmbeddedDocuments, username: str) -> AdapterProfile | None:
    marker = '(window[Symbol.for("urql_transport")] ??= []).push('
    profiles: list[dict[str, JSONValue]] = []
    for _, script in document.scripts:
        if not script.strip().startswith(marker):
            continue
        payload = script.strip()[len(marker) :]
        try:
            raw, consumed = json.JSONDecoder().raw_decode(payload)
            if payload[consumed:].strip() not in (")", ");") or not isinstance(raw, dict):
                continue
            hydrated = raw.get("rehydrate")
            if not isinstance(hydrated, dict) or len(hydrated) > 64:
                continue
            for record in hydrated.values():
                if not isinstance(record, dict) or record.get("hasNext") is not False:
                    continue
                data = record.get("data")
                obj = data.get("profileByIdentifierV2") if isinstance(data, dict) else None
                if isinstance(obj, dict):
                    profiles.append(obj)
        except (ValueError, RecursionError):
            continue
    if not profiles:
        return None
    keys = {
        (p.get("username"), p.get("accountId"))
        for p in profiles
        if isinstance(p.get("username"), str) and isinstance(p.get("accountId"), str)
    }
    if len(keys) != 1 or len(keys) != len(
        {(str(p.get("username")), str(p.get("accountId"))) for p in profiles}
    ):
        return None
    p = profiles[0]
    if not (
        p.get("__typename") == "Profile"
        and p.get("kind") == "ACCOUNT"
        and isinstance(p.get("username"), str)
        and str(p["username"]).casefold() == username.casefold()
        and identifier(p.get("accountId"))
    ):
        return None
    mapping = {
        "username": "username",
        "user_id": "accountId",
        "display_name": "displayName",
        "avatar_url": "imageUrl",
        "banner_url": "bannerImageUrl",
        "bio": "bio",
        "website": "externalUrl",
        "twitter_username": "twitterUsername",
        "created_at": "dateJoined",
        "followers": "followerCount",
        "following": "followingCount",
        "verified": "profileIsVerified",
    }
    return AdapterProfile(
        "OpenSeaUrql",
        tuple((name, p.get(key)) for name, key in mapping.items()),
        "script:urql_transport.rehydrate.*.data.profileByIdentifierV2",
    )


def chaturbate(document: EmbeddedDocuments, username: str) -> AdapterProfile | None:
    marker = "window.initialRoomDossier = "
    for _, script in document.scripts:
        stripped = script.strip()
        if not stripped.startswith(marker):
            continue
        try:
            value, end = json.JSONDecoder().raw_decode(stripped[len(marker) :])
            tail = stripped[len(marker) + end :].lstrip()
            if not tail.startswith(";") or not isinstance(value, str):
                continue
            data = parse_json(value)
        except (ValueError, RecursionError):
            continue
        if not isinstance(data, dict):
            continue
        owner, uid = data.get("broadcaster_username"), data.get("broadcaster_uid")
        if (
            not isinstance(owner, str)
            or owner.casefold() != username.casefold()
            or not isinstance(uid, str)
            or not re.fullmatch(r"[A-Za-z0-9]{4,32}", uid)
            or data.get("room_uid") != uid
        ):
            continue
        # Do not expose visitor identity, stream thumbnails or generated room text as bio.
        return AdapterProfile(
            "RoomDossier",
            (("username", owner), ("user_id", uid)),
            "script:window.initialRoomDossier.broadcaster_username/broadcaster_uid",
        )
    return None


def structured_page(
    document: EmbeddedDocuments, username: str, profile_url: str
) -> AdapterProfile | None:
    for kind, script in document.scripts:
        if kind not in ("application/ld+json", "__NEXT_DATA__"):
            continue
        try:
            data = parse_json(script)
        except (ValueError, RecursionError):
            continue
        if not isinstance(data, dict):
            continue
        if kind == "application/ld+json":
            if data.get("@type") != "ProfilePage" or not same_profile(data.get("url"), profile_url):
                continue
            obj = data.get("mainEntity")
            if not isinstance(obj, dict) or obj.get("@type") not in ("Person", "Organization"):
                continue
            name, uid = obj.get("alternateName"), obj.get("identifier")
            mapping = {"display_name": "name", "avatar_url": "image", "bio": "description"}
        else:
            props = data.get("props")
            page = props.get("pageProps") if isinstance(props, dict) else None
            if not isinstance(page, dict):
                continue
            obj = page.get("profile")
            if not isinstance(obj, dict):
                continue
            name, uid = obj.get("username"), obj.get("id")
            mapping = {"display_name": "displayName", "avatar_url": "avatarUrl", "bio": "bio"}
        if (
            not isinstance(name, str)
            or name != username
            or not identifier(uid)
            or not same_profile(obj.get("url"), profile_url)
        ):
            continue
        fields: list[tuple[str, JSONValue]] = [
            ("username", name),
            ("user_id", uid),
            ("profile_url", profile_url),
        ]
        fields.extend((key, obj.get(source)) for key, source in mapping.items())
        return AdapterProfile(
            "StructuredProfilePage", tuple(fields), "script:" + kind + ".profile_owner"
        )
    return None


def shelf(document: EmbeddedDocuments, username: str) -> AdapterProfile | None:
    if document.meta.get("profile:username") != username or not same_profile(
        document.meta.get("og:url"), "https://shelf.im/" + username
    ):
        return None
    for _, script in document.scripts:
        if "kit.start(app, element," not in script:
            continue
        match = re.search(r'data:\s*\[null,\{type:"data",data:', script)
        if not match:
            continue
        try:
            data = read_literal(script[match.end() :])
        except (ValueError, RecursionError):
            continue
        if not isinstance(data, dict) or data.get("notFound"):
            continue
        user = data.get("user")
        if (
            not isinstance(user, dict)
            or user.get("username") != username
            or not identifier(user.get("id"))
        ):
            continue
        fields = (
            ("username", username),
            ("user_id", user.get("id")),
            ("display_name", user.get("name")),
            ("avatar_url", user.get("avatarUrl")),
            ("bio", user.get("bio")),
        )
        return AdapterProfile("ShelfHydration", fields, "script:kit.start.data[1].data.user")
    return None


def editorial_page(
    document: EmbeddedDocuments, username: str, profile: str
) -> AdapterProfile | None:
    if not same_profile(profile, "https://www.engadget.com/author/" + username):
        return None
    name = document.heading.strip()
    if (
        not name
        or document.title.strip() != name + " - Engadget"
        or not {"author-section", "author-bio-container"} <= document.classes
        or not same_profile(document.meta.get("og:url"), profile)
    ):
        return None
    images = [i for i in document.author_images if i.get("alt") == "Photo of " + name]
    if len(images) != 1:
        return None
    return AdapterProfile(
        "EngadgetAuthor",
        (
            ("username", username),
            ("display_name", name),
            ("profile_url", profile),
            ("avatar_url", images[0].get("src")),
        ),
        "main.author .author-section h1 + .author-image",
    )


def rambler(document: EmbeddedDocuments, username: str, profile: str) -> AdapterProfile | None:
    parts = document.title.split("|")
    if (
        not same_profile(profile, "https://dating.rambler.ru/page/" + username)
        or len(parts) < 3
        or parts[-1].strip() != "dating.rambler.ru"
        or parts[-2].strip().casefold() != username.casefold()
        or "/a-message/login-" + username not in document.links
    ):
        return None
    return AdapterProfile(
        "RamblerOwner",
        (("username", username), ("profile_url", profile)),
        "title.owner + profile contact action + canonical",
    )


def embedded_profile(
    response: TransportResponse, text: str, username: str, profile: str
) -> AdapterProfile | None:
    if response.status != 200 or not same_profile(
        response.final_url or response.requested_url, profile
    ):
        return None
    document = EmbeddedDocuments(text)
    if response.body_complete and same_profile(profile, "https://www.shelf.im/" + username):
        return shelf(document, username)
    if not document.canonicals or any(not same_profile(c, profile) for c in document.canonicals):
        return None
    host = urlsplit(profile).netloc
    if host == "opensea.io" and same_profile(profile, "https://opensea.io/" + username):
        return opensea(document, username)
    if not response.body_complete:
        return None
    if host == "chaturbate.com" and same_profile(profile, "https://chaturbate.com/" + username):
        return chaturbate(document, username)
    if host == "www.engadget.com":
        return editorial_page(document, username, profile)
    if host == "dating.rambler.ru":
        return rambler(document, username, profile)
    return structured_page(document, username, profile)
