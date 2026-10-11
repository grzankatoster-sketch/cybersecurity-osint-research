"""Profile-bound extraction from one shared document; no network or JavaScript execution."""

from __future__ import annotations

import html
import re
from datetime import UTC, date, datetime
from decimal import Decimal
from html.parser import HTMLParser
from time import perf_counter
from typing import Protocol
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

import regex

from ultimate_username.api_adapters import ApiProfile, api_kind, parse_api
from ultimate_username.detection import ResponseView, classify_response
from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.metadata import (
    EvidenceQuality,
    FieldCandidate,
    FieldCoverage,
    FieldValue,
    MetadataState,
    ProfileMetadata,
)
from ultimate_username.domain.models import (
    DetectionResult,
    ExecutionState,
    JSONValue,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.domain.urls import origin
from ultimate_username.embedded_state import EmbeddedStateExtractor, LabelValueExtractor
from ultimate_username.enrichment_filters import (
    CONTROL_SAME_VALUE,
    NICK_ECHO,
    SELF_LINK,
    control_digest,
    filter_reason,
    is_self_link,
)
from ultimate_username.extraction import at_path
from ultimate_username.field_model import generic_value
from ultimate_username.planning import plan_request
from ultimate_username.profile_binding import github_profile_url, github_response
from ultimate_username.response_quality import profile_kind, response_quality

STANDARD = frozenset(
    {
        "username",
        "display_name",
        "user_id",
        "bio",
        "description",
        "avatar_url",
        "banner_url",
        "profile_url",
        "website",
        "external_links",
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
COUNTERS = frozenset(
    {
        "followers",
        "following",
        "posts",
        "public_repos_count",
        "public_gists_count",
        "xenforo_points",
    }
)
URLS = frozenset({"avatar_url", "banner_url", "profile_url", "website"})
ALIASES = {
    "username": "username",
    "login": "username",
    "screen_name": "username",
    "name": "display_name",
    "display_name": "display_name",
    "displayName": "display_name",
    "fullName": "display_name",
    "fullname": "display_name",
    "id": "user_id",
    "uid": "user_id",
    "user_id": "user_id",
    "bio": "bio",
    "summary": "bio",
    "description": "description",
    "avatar_url": "avatar_url",
    "profile_image": "avatar_url",
    "image": "avatar_url",
    "banner_url": "banner_url",
    "header": "banner_url",
    "html_url": "profile_url",
    "url": "profile_url",
    "website": "website",
    "website_url": "website",
    "blog": "website",
    "location": "location",
    "followers": "followers",
    "followers_count": "followers",
    "followersCount": "followers",
    "following": "following",
    "following_count": "following",
    "posts_count": "posts",
    "statuses_count": "posts",
    "created_at": "created_at",
    "updated_at": "updated_at",
    "verified": "verified",
    "is_verified": "verified",
    "type": "account_type",
    "account_type": "account_type",
    "category": "category",
    "tags": "tags",
    "public_repos": "public_repos_count",
    "public_gists": "public_gists_count",
    "hireable": "is_looking_for_job",
    "company": "company",
    "node_id": "node_id",
    "email": "email",
    "twitter_username": "twitter_username",
    "github_username": "github_username",
    "joined_at": "joined_text",
}


HIDDEN_TEXT_TAGS = frozenset(
    {
        "script",
        "style",
        "noscript",
        "template",
        "head",
        "title",
        "select",
        "option",
        "textarea",
        "nav",
        "footer",
        "button",
        "svg",
    }
)
MAX_DATA_ATTRS = 16
MAX_INLINE_SCRIPTS = 16
MAX_INLINE_SCRIPT = 2 * 1024 * 1024
MAX_TEXT_NODES = 4000
MAX_TEXT_NODE = 300
# Escaped, URL-encoded or plain JSON object/array.
JSON_START = ("{", "[", "%7b", "%5b")


def json_like(value: str) -> bool:
    head = value.lstrip()[:3].lower()
    return len(value) > 2 and head.startswith(JSON_START)


def same_url(left: str, right: str) -> bool:
    try:
        a, b = urlsplit(left), urlsplit(right)
        return (
            origin(left) == origin(right)
            and a.path.rstrip("/") == b.path.rstrip("/")
            and a.query == b.query
        )
    except ValueError:
        return False


class ParsedDocument(HTMLParser):
    """Retains small useful nodes, not a DOM; duplicate metadata remains visible."""

    def __init__(self, response: TransportResponse) -> None:
        super().__init__(convert_charrefs=True)
        started = perf_counter()
        self.view = ResponseView(response)
        self.metadata: dict[str, list[str]] = {}
        self.canonicals: list[str] = []
        self.json_documents: list[tuple[str, JSONValue]] = []
        self.errors: list[str] = []
        self.nodes: list[tuple[str, dict[str, str]]] = []
        self.title = ""
        self.icons: list[str] = []
        self._in_title = False
        self._script: tuple[str, list[str]] | None = None
        self._in_script = False
        self.html_parse_count = 0
        self._node_count = 0
        self.inline_scripts: list[str] = []
        self.data_attrs: list[tuple[str, str]] = []
        self.text_nodes: list[tuple[str, bool]] = []
        self._plain: list[str] | None = None
        self._plain_size = 0
        self._hidden = 0
        self._anchor = 0
        if self.view.parse_error:
            self.errors.append("decode:" + self.view.parse_error)
        elif "json" in (
            response.header("Content-Type") or ""
        ).lower() or self.view.text.lstrip().startswith(("{", "[")):
            self._json("response", self.view.text)
        else:
            self.html_parse_count = 1
            self.feed(self.view.text)
            self.close()
            if self._script:
                self.errors.append("json:unterminated script")
        self.parse_seconds = perf_counter() - started

    def _json(self, locator: str, text: str) -> None:
        if len(self.json_documents) >= 32:
            self.errors.append("json:document limit")
            return
        if text[:3].lower() in ("%7b", "%5b"):
            text = unquote(text)
        try:
            self.json_documents.append((locator, parse_json(text)))
        except (ValueError, RecursionError) as exc:
            self.errors.append(f"json:{locator}:{type(exc).__name__}")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._node_count += 1
        if self._node_count > 10000:
            raise ValueError("HTML node budget exceeded")
        a = {k: v for k, v in attrs if v is not None}
        if tag in HIDDEN_TEXT_TAGS:
            self._hidden += 1
        elif tag == "a":
            self._anchor += 1
        if len(self.data_attrs) < MAX_DATA_ATTRS:
            for key, val in a.items():
                if key.startswith("data-") and json_like(val):
                    self.data_attrs.append((f"{tag}[{key}]", val))
        if tag == "script":
            self._in_script = True
            kind = a.get("type", "").lower().split(";")[0].strip()
            if (
                kind in ("application/json", "application/ld+json")
                or a.get("id") == "__NEXT_DATA__"
            ):
                self._script = (
                    "jsonld" if kind == "application/ld+json" else "script:" + a.get("id", "json"),
                    [],
                )
            elif "src" not in a and self._plain is None:
                self._plain, self._plain_size = [], 0
        elif tag == "meta":
            key = a.get("property", a.get("name", "")).lower()
            if key and "content" in a:
                self.metadata.setdefault(key, []).append(a["content"])
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split():
            if a.get("href"):
                self.canonicals.append(a["href"])
        elif tag == "title" and not self.title:
            self._in_title = True
        if (
            tag == "link"
            and "icon" in a.get("rel", "").lower()
            and a.get("href")
            and len(self.icons) < 16
        ):
            self.icons.append(a["href"])
        if tag in ("time", "div") and len(self.nodes) < 512:
            self.nodes.append((tag, a))

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 1024:
            self.title += data
        if self._script:
            self._script[1].append(data)
        elif self._plain is not None:
            self._plain_size += len(data)
            if self._plain_size <= MAX_INLINE_SCRIPT:
                self._plain.append(data)
        elif not self._hidden and len(self.text_nodes) < MAX_TEXT_NODES:
            text = " ".join(data.split())
            if text:
                self.text_nodes.append((text[:MAX_TEXT_NODE], self._anchor > 0))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in HIDDEN_TEXT_TAGS:
            self._hidden = max(0, self._hidden - 1)
        elif tag == "a":
            self._anchor = max(0, self._anchor - 1)
        if tag == "script":
            if self._script:
                locator, chunks = self._script
                self._json(locator, "".join(chunks))
            if self._plain is not None:
                body = "".join(self._plain)
                if (
                    self._plain_size <= MAX_INLINE_SCRIPT
                    and len(self.inline_scripts) < MAX_INLINE_SCRIPTS
                    and ("{" in body or "[" in body or "%7" in body[:8].lower())
                ):
                    self.inline_scripts.append(body)
            self._script = None
            self._plain = None
            self._in_script = False

    def values(self, name: str) -> list[str]:
        return self.metadata.get(name, [])


def normalize_field(name: str, value: JSONValue, source_url: str) -> FieldValue | None:
    if value is None or value == "" or isinstance(value, dict):
        return None
    if name.endswith("_at") and type(value) is int:
        # Unix seconds are accepted only for declared timestamp fields, never arbitrary numbers.
        try:
            return (
                datetime.fromtimestamp(value, UTC).isoformat()
                if 0 <= value <= 253402300799
                else None
            )
        except (ValueError, OverflowError, OSError):
            return None
    if name in COUNTERS:
        if type(value) is int:
            return value if value >= 0 else None
        if isinstance(value, str):
            match = re.fullmatch(r"(\d+(?:\.\d+)?)([KMB]?)", value.strip(), re.I)
            if match:
                number = (
                    Decimal(match[1])
                    * {"": 1, "K": 1000, "M": 1000000, "B": 1000000000}[match[2].upper()]
                )
                if number == number.to_integral_value() and number <= 10**18:
                    return int(number)
        return None
    if name in ("verified", "is_looking_for_job"):
        return value if type(value) is bool else None
    if name == "user_id" and type(value) is int:
        return str(value)
    if name in ("external_links", "tags"):
        if not isinstance(value, list) or len(value) > 32:
            return None
        result: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                continue
            normalized = normalize_field(
                "website" if name == "external_links" else "tag", item, source_url
            )
            if isinstance(normalized, str) and normalized not in result:
                result.append(normalized)
        return tuple(result) or None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if (
        not value
        or len(value.encode("utf-8")) > 8192
        or any(ord(c) < 32 and c not in "\n\t" for c in value)
    ):
        return None
    if name in URLS:
        value = urljoin(source_url, value)
        try:
            origin(value)
        except ValueError:
            return None
    if name == "email" and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        return None
    if name.endswith("_at"):
        try:
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                return date.fromisoformat(value).isoformat()
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return None
    return value


class ExtractionContext:
    def __init__(
        self,
        response: TransportResponse,
        username: str,
        site: SiteDefinition,
        control_digests: frozenset[str] = frozenset(),
    ) -> None:
        self.response, self.username, self.site = response, username, site
        self.control_digests = control_digests
        self.url = response.final_url or response.requested_url
        self.profile_url = plan_request(username, site, "enrichment").profile_url
        self.timestamp = datetime.now(UTC).isoformat()
        self.candidates: list[FieldCandidate] = []
        self.errors: list[str] = []
        self.diagnostics: set[str] = set()
        self.available: set[str] = set()
        self.rejected: set[str] = set()
        self.invalid: set[str] = set()
        self.nulls: set[str] = set()
        self.reviewed_owner = False

    def owner_matches(self, identity: JSONValue) -> bool:
        return isinstance(identity, str) and (
            identity == self.username
            or self.reviewed_owner
            and identity.casefold() == self.username.casefold()
            or github_response(self.response, self.username)
            and identity.casefold() == self.username.casefold()
            or bool(profile_kind(self.url, self.username))
            and identity.casefold() == self.username.casefold()
        )

    def control_same(self, raw: str, name: str) -> bool:
        """A raw page value identical (nick aside) on the control page is template, not data."""
        if (
            self.control_digests
            and len(raw.strip()) >= 3
            and control_digest(raw, self.username) in self.control_digests
        ):
            self.available.add(name)
            self.rejected.add(name)
            self.diagnostics.add(CONTROL_SAME_VALUE)
            return True
        return False

    def _without_self_links(self, value: FieldValue) -> FieldValue | None:
        """Drops links that only point back at this very profile; None when nothing is left."""
        own = (self.url, self.profile_url)
        if isinstance(value, str):
            return None if is_self_link(value, self.username, own) else value
        if isinstance(value, tuple):
            kept = tuple(
                v for v in value if not (isinstance(v, str) and is_self_link(v, self.username, own))
            )
            return kept or None
        return value

    def url_matches(self, url: str) -> bool:
        return same_url(url, self.profile_url) or (
            github_response(self.response, self.username)
            and github_profile_url(self.profile_url, self.username)
            and github_profile_url(url, self.username)
        )

    def add(
        self,
        name: str,
        value: JSONValue,
        extractor: str,
        locator: str,
        quality: EvidenceQuality,
        priority: int,
    ) -> None:
        self.available.add(name)
        if value is None:
            self.nulls.add(name)
            return
        if isinstance(value, str) and name not in URLS and "&" in value:
            value = html.unescape(value)
        normalized = normalize_field(name, value, self.url)
        if normalized is None:
            self.invalid.add(name)
            self.diagnostics.add("FIELDS_REJECTED")
            return
        if name in ("website", "external_links"):
            normalized = self._without_self_links(normalized)
            if normalized is None:
                self.rejected.add(name)
                self.diagnostics.add(SELF_LINK)
                return
        if name == "username" and not self.owner_matches(value):
            self.rejected.add(name)
            self.diagnostics.add("OWNER_BINDING_FAILED")
            return
        if isinstance(normalized, str):
            reason = filter_reason(
                name, normalized, self.username, self.site.name, self.url, self.control_digests
            )
            if reason:
                self.rejected.add(name)
                self.diagnostics.add(reason)
                return
        if isinstance(normalized, str) and generic_value(name, normalized, self.site.name):
            self.rejected.add(name)
            self.diagnostics.add("GENERIC_PAGE_FIELD")
            return
        if len(self.candidates) >= 128:
            if "candidate limit" not in self.errors:
                self.errors.append("candidate limit")
            return
        self.candidates.append(
            FieldCandidate(
                name,
                normalized,
                self.site.id,
                self.url,
                extractor,
                locator[:256],
                self.timestamp,
                quality,
                priority,
            )
        )


class ProfileExtractor(Protocol):
    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None: ...


def profile_objects(
    value: JSONValue, path: str = "$", depth: int = 0
) -> list[tuple[str, dict[str, JSONValue]]]:
    """Only explicit profile containers; never walk viewer/recommendations/member lists."""
    if depth > 12 or not isinstance(value, dict):
        return []
    result = [(path, value)]
    for key in (
        "props",
        "pageProps",
        "data",
        "profile",
        "user",
        "account",
        "userInfo",
        "accountData",
    ):
        if key in value:
            result.extend(profile_objects(value[key], path + "." + key, depth + 1))
    return result[:128]


class StructuredJsonExtractor:
    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        for source, data in document.json_documents:
            if source == "jsonld":
                continue
            for path, obj in profile_objects(data):
                identity = obj.get("username", obj.get("login", obj.get("screen_name")))
                if not context.owner_matches(identity):
                    if identity is not None:
                        context.diagnostics.add("OWNER_BINDING_FAILED")
                        names = {ALIASES[key] for key in obj if key in ALIASES}
                        context.available.update(names)
                        context.rejected.update(names)
                    continue
                if (
                    github_response(context.response, context.username)
                    and "html_url" in obj
                    and (
                        not isinstance(obj["html_url"], str)
                        or not context.url_matches(obj["html_url"])
                    )
                ):
                    context.diagnostics.add("OWNER_BINDING_FAILED")
                    names = {ALIASES[key] for key in obj if key in ALIASES}
                    context.available.update(names)
                    context.rejected.update(names)
                    continue
                if obj.get("@type") == "Organization":
                    context.diagnostics.add("GENERIC_PAGE")
                    continue
                extractor = (
                    "StructuredJsonExtractor" if source == "response" else "EmbeddedJsonExtractor"
                )
                for key, value in obj.items():
                    if key in ALIASES:
                        # API resource URL is not a second contradictory human profile URL.
                        if key == "url" and github_response(context.response, context.username):
                            continue
                        if ALIASES[key] == "profile_url" and (
                            not isinstance(value, str)
                            or not context.url_matches(urljoin(context.url, value))
                        ):
                            context.available.add(ALIASES[key])
                            context.rejected.add(ALIASES[key])
                            context.diagnostics.add("PROFILE_URL_MISMATCH")
                            continue
                        context.add(
                            ALIASES[key],
                            value,
                            extractor,
                            source + path + "." + key,
                            EvidenceQuality.HIGH,
                            10,
                        )


class ReviewedProfileExtractor:
    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        assessment = response_quality(
            context.response, document.view.text, context.username, context.profile_url
        )
        if assessment.kind != "PROFILE":
            return
        context.reviewed_owner = True
        for name, value in assessment.fields:
            context.add(
                name,
                value,
                "ReviewedProfileExtractor",
                (assessment.locator or assessment.reason) + "." + name,
                EvidenceQuality.HIGH if assessment.level == 4 else EvidenceQuality.MEDIUM,
                5,
            )


class JsonLdExtractor:
    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        for source, data in document.json_documents:
            if source == "jsonld":
                self._visit(data, "jsonld", context)

    def _visit(
        self,
        value: JSONValue,
        path: str,
        context: ExtractionContext,
        depth: int = 0,
        bound: bool = False,
    ) -> None:
        if depth > 12:
            return
        if isinstance(value, list):
            for i, child in enumerate(value[:128]):
                self._visit(child, f"{path}[{i}]", context, depth + 1, bound)
        elif isinstance(value, dict):
            kind = value.get("@type")
            kinds = kind if isinstance(kind, list) else [kind]
            if "Person" in kinds:
                url = value.get("url")
                if self._person_bound(value, context, bound):
                    mapping = {
                        "alternateName": "username",
                        "name": "display_name",
                        "identifier": "user_id",
                        "description": "description",
                        "image": "avatar_url",
                        "url": "profile_url",
                        "sameAs": "external_links",
                        "dateCreated": "created_at",
                    }
                    for key, name in mapping.items():
                        if key not in value:
                            continue
                        if key == "url" and not (
                            isinstance(url, str) and context.url_matches(urljoin(context.url, url))
                        ):
                            continue
                        context.add(
                            name,
                            value.get(key),
                            "JsonLdExtractor",
                            path + "." + key,
                            EvidenceQuality.HIGH,
                            20,
                        )
            inherited = "ProfilePage" in kinds and self._points_to_profile(value, context)
            for key in ("@graph", "mainEntity"):
                if key in value and kind != "Organization":
                    self._visit(value[key], path + "." + key, context, depth + 1, inherited)

    @staticmethod
    def _profile_reference(url: str, context: ExtractionContext) -> bool:
        """The URL is this profile, or ends in /nick on the same host."""
        absolute = urldefrag(urljoin(context.url, url))[0]
        if context.url_matches(absolute):
            return True
        host = (urlsplit(absolute).hostname or "").lower().removeprefix("www.")
        own = {
            (urlsplit(u).hostname or "").lower().removeprefix("www.")
            for u in (context.url, context.profile_url)
        }
        last = unquote(urlsplit(absolute).path).rstrip("/").rsplit("/", 1)[-1]
        return host in own and last.lstrip("@").casefold() == context.username.casefold()

    def _points_to_profile(self, value: dict[str, JSONValue], context: ExtractionContext) -> bool:
        return self._references_match(value, context) is True

    def _references_match(
        self, value: dict[str, JSONValue], context: ExtractionContext
    ) -> bool | None:
        """None without url/@id/mainEntityOfPage; otherwise whether all of them are this page."""
        refs: list[JSONValue] = []
        for key in ("url", "@id", "mainEntityOfPage"):
            ref = value.get(key)
            if isinstance(ref, dict):
                ref = ref.get("@id", ref.get("url"))
            if ref is not None:
                refs.append(ref)
        if not refs:
            return None
        return all(isinstance(r, str) and self._profile_reference(r, context) for r in refs)

    def _person_bound(
        self, value: dict[str, JSONValue], context: ExtractionContext, inherited: bool
    ) -> bool:
        alternate = value.get("alternateName")
        if alternate is not None and not context.owner_matches(alternate):
            return False
        match = self._references_match(value, context)
        return inherited if match is None else match


def html_binding(document: ParsedDocument, context: ExtractionContext) -> str | None:
    urls = document.canonicals + document.values("og:url")
    # Conflicting owners/canonical URLs make the document ambiguous.
    identities = document.values("profile:username")
    if identities and any(not context.owner_matches(i) for i in identities):
        context.diagnostics.add("OWNER_BINDING_FAILED")
        return None
    if not urls or any(not context.url_matches(urljoin(context.url, u)) for u in urls):
        return None
    if identities and "profile" in document.values("og:type"):
        return "profile"
    path = unquote(urlsplit(context.profile_url).path).rstrip("/")
    if re.fullmatch(r"/u/" + re.escape(context.username) + r"(?:/summary)?", path):
        if "discourse" in document.view.text.lower() and (
            document.values("og:description") or document.values("og:image")
        ):
            return "discourse"
    match = re.fullmatch(r"/members/" + re.escape(context.username) + r"\.(\d+)", path)
    if match and any(
        a.get("data-user-id") == match[1] and "memberHeader" in a.get("class", "")
        for _, a in document.nodes
    ):
        return "xenforo"
    return None


class OpenGraphExtractor:
    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        if html_binding(document, context) is None:
            return
        mapping = {
            "profile:username": "username",
            "og:title": "display_name",
            "og:description": "description",
            "og:image": "avatar_url",
            "og:url": "profile_url",
        }
        for key, name in mapping.items():
            for i, value in enumerate(document.values(key)):
                context.add(
                    name,
                    value,
                    "OpenGraphExtractor",
                    f"meta:{key}[{i}]",
                    EvidenceQuality.MEDIUM,
                    30,
                )
        for value in document.canonicals:
            context.add(
                "profile_url",
                value,
                "OpenGraphExtractor",
                "link:canonical",
                EvidenceQuality.MEDIUM,
                30,
            )


class ForumProfileExtractor:
    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        binding = html_binding(document, context)
        if binding not in ("discourse", "xenforo"):
            return
        urls = document.canonicals + document.values("og:url")
        path = unquote(urlsplit(urljoin(context.url, urls[0])).path).rstrip("/")
        username = path.split("/")[-1]
        if binding == "xenforo":
            username, uid = username.rsplit(".", 1)
            context.add(
                "user_id",
                uid,
                "ForumProfileExtractor",
                "og:url member ID",
                EvidenceQuality.HIGH,
                15,
            )
        if username == "summary":
            username = path.split("/")[-2]
        context.add(
            "username",
            username,
            "ForumProfileExtractor",
            "profile URL path",
            EvidenceQuality.HIGH,
            15,
        )
        for tag, attrs in document.nodes:
            if tag == "time" and attrs.get("itemprop") == "dateCreated":
                context.add(
                    "created_at",
                    attrs.get("datetime"),
                    "ForumProfileExtractor",
                    "time[itemprop=dateCreated]",
                    EvidenceQuality.HIGH,
                    15,
                )


class DeclaredRuleExtractor:
    """Legacy JSON/regex rules gain validation and binding; the old API is unchanged."""

    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        for rule in context.site.extractors[:64]:
            if rule.expected_host and urlsplit(context.url).hostname != rule.expected_host:
                continue
            try:
                value: JSONValue = None
                if rule.strategy == "json" and rule.owner_path:
                    data = next((d for s, d in document.json_documents if s == "response"), None)
                    if at_path(data, rule.owner_path) != context.username:
                        continue
                    value = at_path(data, rule.path)
                elif rule.strategy == "regex" and html_binding(document, context):
                    found = regex.search(rule.pattern, document.view.text, timeout=0.02)
                    value = found.group(rule.group) if found else None
                else:
                    continue
                if rule.prefix and isinstance(value, str):
                    value = rule.prefix + value
                context.add(
                    rule.name,
                    value,
                    "DeclaredRuleExtractor",
                    "/".join(rule.path) or "regex capture",
                    EvidenceQuality.MEDIUM,
                    40,
                )
            except KeyError:
                continue
            except (ValueError, TypeError, IndexError, TimeoutError, regex.error) as exc:
                context.errors.append(f"DeclaredRuleExtractor:{type(exc).__name__}")


_BAD_NAME_WORDS = regex.compile(
    r"\b(?:log ?in|sign ?(?:up|in)|not found|error|404|page|access denied|just a moment)\b",
    regex.IGNORECASE,
)
_GENERIC_NAMES = frozenset({"profile", "home", "welcome", "user", "users", "member", "account"})
_SEPARATORS = r"[|\-–—·•:]"
# A name that survives suffix stripping but still carries template glue is a page title.
_TEMPLATE_GLUE = regex.compile(
    r"\s(?:[|\-–—·•]|::|on|at)\s|:\s|['’]s(?:\s|$)"
    r"|さんの|님의|的",
    regex.IGNORECASE,
)
# Words of slogans, listings and statistics pages: a person's name never contains them.
_SLOGAN_WORDS = frozenset(
    {
        "make", "your", "buy", "shop", "watch", "join", "free", "live", "best", "online",
        "download", "gifs", "community", "profile", "stats", "overview", "porn", "chat", "merch",
    }
)  # fmt: skip
_BAD_IMAGE_PATH = regex.compile(
    r"logo|default|placeholder|favicon|og-image|share|banner|brand", regex.IGNORECASE
)
_IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif"})
_AVATAR_SEGMENTS = frozenset(
    {"avatar", "avatars", "profile", "profiles", "user", "users", "photo", "photos", "pfp"}
)
_GENERIC_DIRECTORIES = frozenset(
    {"static", "assets", "images", "img", "media", "cdn", "uploads", "files", "public", "content"}
)


def _site_pattern(token: str) -> str:
    """A site token as a pattern: `premium.chat` also matches the title text `Premium Chat`."""
    return r"[\s._\-]{0,2}".join(regex.escape(part) for part in regex.split(r"[\s._\-]+", token))


MAX_NAME_CHARS = 40
MAX_NAME_WORDS = 4
MAX_DIGIT_SHARE = 0.3


# A page title is hostile input: only its first characters are ever cleaned (a name longer than
# 80 characters is rejected anyway), which also bounds every pattern applied to it.
MAX_RAW_NAME = 300


class PageMetaExtractor:
    """Last-resort display_name/avatar from social meta tags of an already-detected profile.

    Runs after every other extractor and fills only fields nobody else produced.
    Candidates are LOW quality at priority 60; the detection verdict is never touched.
    Descriptions are never taken: a page description is a site template far more often than a
    bio. A display name comes only from og:title/twitter:title and only when it is a bare name.
    """

    NAME = "PageMetaExtractor"

    def extract(self, document: ParsedDocument, context: ExtractionContext) -> None:
        # A contradicted owner, or a page that never mentions the requested handle, is no profile.
        if "OWNER_BINDING_FAILED" in context.diagnostics:
            return
        if context.username.casefold() not in document.view.text.casefold():
            return
        have = {c.name for c in context.candidates}
        if "display_name" not in have:
            self._display_name(document, context)
        if "avatar_url" not in have:
            self._avatar(document, context)

    def _add(self, context: ExtractionContext, name: str, value: str, locator: str) -> None:
        context.add(name, value, self.NAME, locator, EvidenceQuality.LOW, 60)

    @staticmethod
    def _meta(
        document: ParsedDocument, keys: tuple[tuple[str, str], ...]
    ) -> list[tuple[str, str]]:
        return [
            (value, f"meta[{attr}={key}]")
            for key, attr in keys
            for value in document.values(key)[:2]
        ]

    def _site_tokens(self, context: ExtractionContext) -> list[str]:
        host = (
            urlsplit(context.url).hostname or urlsplit(context.profile_url).hostname or ""
        ).lower()
        host = host.removeprefix("www.")
        tokens = {context.site.name.strip(), host, host.split(".")[0] if host else ""}
        return sorted((t for t in tokens if len(t) >= 2), key=len, reverse=True)

    def clean_name(self, raw: str, context: ExtractionContext) -> str:
        text = " ".join(html.unescape(raw[:MAX_RAW_NAME]).split())
        nick = regex.escape(context.username)
        sites = "|".join(_site_pattern(t) for t in self._site_tokens(context)) or "(?!)"
        text = regex.sub(r"\(\s*@[^()]{0,100}\)", " ", text)
        text = regex.sub(rf"\(\s*(?:{nick}|{sites})\s*\)", " ", text, flags=regex.IGNORECASE)
        text = regex.sub(rf"(?<!\w)@{nick}(?!\w)", " ", text, flags=regex.IGNORECASE)
        for _ in range(4):
            before = text
            text = " ".join(text.split())
            text = regex.sub(
                rf"(?:^|\s+)(?:on|at|de|en|sur|auf|bei|na)\s+(?:{sites})\s*$",
                "",
                text,
                flags=regex.IGNORECASE,
            )
            text = regex.sub(
                rf"\s*{_SEPARATORS}\s*(?:{sites})\s*$", "", text, flags=regex.IGNORECASE
            )
            text = regex.sub(
                rf"^(?:{sites})\s*{_SEPARATORS}\s*", "", text, flags=regex.IGNORECASE
            )
            text = regex.sub(
                rf"\s*{_SEPARATORS}\s*(?:profile|profil)\s*$", "", text, flags=regex.IGNORECASE
            )
            text = regex.sub(r"(?:'s|’s)\s+profile\s*$", "", text, flags=regex.IGNORECASE)
            text = regex.sub(r"\s+profile\s*$", "", text, flags=regex.IGNORECASE)
            text = text.strip(" \t|-–—·•:")
            if text == before:
                break
        return text

    def valid_name(self, text: str, context: ExtractionContext) -> bool:
        """A bare person-like name: short, no template glue, no slogan words."""
        folded = text.casefold()
        digits = sum(c.isdigit() for c in text)
        return not (
            not text
            or len(text) > MAX_NAME_CHARS
            or len(text.split()) > MAX_NAME_WORDS
            or digits > len(text) * MAX_DIGIT_SHARE
            or folded in _GENERIC_NAMES
            or folded in {t.casefold() for t in self._site_tokens(context)}
            or generic_value("display_name", text, context.site.name)
            or _BAD_NAME_WORDS.search(text)
            or _TEMPLATE_GLUE.search(text)
            or not _SLOGAN_WORDS.isdisjoint(regex.findall(r"\w+", folded))
        )

    def _display_name(self, document: ParsedDocument, context: ExtractionContext) -> None:
        sources = self._meta(
            document,
            (("og:title", "property"), ("twitter:title", "name")),
        )
        nick = context.username.casefold()
        for raw, locator in sources:
            if context.control_same(raw, "display_name"):
                continue
            text = self.clean_name(raw, context)
            if nick and nick in text.casefold():
                context.available.add("display_name")
                context.rejected.add("display_name")
                context.diagnostics.add(NICK_ECHO)
                continue
            if self.valid_name(text, context):
                self._add(context, "display_name", text, locator)
                return

    @staticmethod
    def plausible_avatar_path(path: str) -> bool:
        """An image file, or a deep path that names an avatar; never a bare directory."""
        decoded = unquote(path).casefold()
        segments = [s for s in decoded.split("/") if s]
        if not segments or decoded.endswith("/"):
            return False
        last = segments[-1]
        if "." in last and "." + last.rsplit(".", 1)[-1] in _IMAGE_EXTENSIONS:
            return True
        return last not in _GENERIC_DIRECTORIES and not _AVATAR_SEGMENTS.isdisjoint(segments[:-1])

    def _avatar(self, document: ParsedDocument, context: ExtractionContext) -> None:
        icons = {urlsplit(urljoin(context.url, i)).path for i in document.icons}
        sources = self._meta(
            document,
            (("og:image", "property"), ("twitter:image", "name"), ("twitter:image:src", "name")),
        )
        for raw, locator in sources:
            value = raw.strip()
            if not value or value.casefold().startswith(("data:", "javascript:", "blob:")):
                continue
            if context.control_same(value, "avatar_url"):
                continue
            absolute = urljoin(context.url, value)
            parts = urlsplit(absolute)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                continue
            if _BAD_IMAGE_PATH.search(unquote(parts.path)) or parts.path in icons:
                continue
            if not self.plausible_avatar_path(parts.path):
                continue
            self._add(context, "avatar_url", absolute, locator)
            return


EXTRACTORS: tuple[ProfileExtractor, ...] = (
    ReviewedProfileExtractor(),
    StructuredJsonExtractor(),
    JsonLdExtractor(),
    EmbeddedStateExtractor(),
    ForumProfileExtractor(),
    OpenGraphExtractor(),
    DeclaredRuleExtractor(),
    PageMetaExtractor(),
    LabelValueExtractor(),
)


def merge_metadata(*results: ProfileMetadata) -> ProfileMetadata:
    candidates = tuple(c for result in results for c in result.candidates)[:256]
    selected: dict[str, FieldCandidate] = {}
    conflicts: set[str] = set()
    rank = {
        EvidenceQuality.HIGH: 0,
        EvidenceQuality.MEDIUM: 1,
        EvidenceQuality.LOW: 2,
        EvidenceQuality.UNVERIFIED: 3,
    }
    for candidate in sorted(candidates, key=lambda c: (rank[c.quality], c.priority)):
        previous = selected.setdefault(candidate.name, candidate)
        if type(previous.value) is not type(candidate.value) or previous.value != candidate.value:
            conflicts.add(candidate.name)
    errors = tuple(e for result in results for e in result.errors)[:64]
    available = {f for r in results for f in r.coverage.available_fields}
    rejected = {f for r in results for f in r.coverage.rejected_fields}
    invalid = {f for r in results for f in r.coverage.invalid_fields}
    nulls = {f for r in results for f in r.coverage.null_fields} - selected.keys()
    state = (
        MetadataState.PARTIAL
        if selected and errors
        else MetadataState.SUCCESS
        if selected
        else MetadataState.ERROR
        if errors
        else MetadataState.EMPTY
    )
    if (
        not selected
        and not errors
        and results
        and all(r.state == MetadataState.UNAVAILABLE for r in results)
    ):
        state = MetadataState.UNAVAILABLE
    return ProfileMetadata(
        state,
        tuple(v for k, v in selected.items() if k in STANDARD),
        tuple(v for k, v in selected.items() if k not in STANDARD),
        candidates,
        tuple(sorted(conflicts)),
        errors,
        sum(r.parser_failures for r in results),
        sum(r.extractor_failures for r in results),
        sum(r.parse_seconds for r in results),
        sum(r.enrichment_seconds for r in results),
        sum(r.html_parse_count for r in results),
        sum(r.request_count for r in results),
        diagnostics=tuple(sorted({d for r in results for d in r.diagnostics})),
        coverage=FieldCoverage(
            tuple(sorted(available)),
            tuple(sorted(selected)),
            tuple(sorted(rejected)),
            tuple(sorted(available - selected.keys() - rejected - invalid - nulls)),
            tuple(sorted(invalid)),
            tuple(sorted(nulls)),
        ),
    )


API_PRIORITY = 5  # an owner-bound API answer outranks every page-derived candidate


def api_enrich(response: TransportResponse, username: str, site: SiteDefinition) -> ProfileMetadata:
    """Fields of a public profile-API answer (E3): same filters as pages, owner binding first."""
    started = perf_counter()
    url = response.final_url or response.requested_url
    if api_kind(response.requested_url) is None or api_kind(url) != api_kind(
        response.requested_url
    ):
        return ProfileMetadata(MetadataState.UNAVAILABLE, diagnostics=("API_UNSUPPORTED",))
    if response.status is None or not 200 <= response.status < 300 or not response.body_complete:
        reason = "API_RATE_LIMITED" if response.status == 429 else "API_RESPONSE_UNAVAILABLE"
        return ProfileMetadata(MetadataState.UNAVAILABLE, diagnostics=(reason,))
    try:
        data = parse_json(response.body.decode("utf-8"))
    except (ValueError, RecursionError, UnicodeError):
        return ProfileMetadata(
            MetadataState.EMPTY,
            diagnostics=("API_INVALID_JSON",),
            parser_failures=1,
            enrichment_seconds=perf_counter() - started,
        )
    parsed = parse_api(response.requested_url, data, username)
    context = ExtractionContext(response, username, site)
    if isinstance(parsed, ApiProfile):
        # The adapter already bound the owner (case-insensitive services), so the username
        # check of the page extractors may fold case here.
        context.reviewed_owner = True
        for item in parsed.fields:
            context.add(
                item.name,
                item.value,
                parsed.kind,
                "api:" + item.locator,
                EvidenceQuality.HIGH,
                API_PRIORITY,
            )
        if not context.candidates and not context.diagnostics:
            context.diagnostics.add("NO_SUPPORTED_FIELDS")
    else:
        context.diagnostics.add(parsed)
    result = ProfileMetadata(
        candidates=tuple(context.candidates),
        errors=tuple(context.errors),
        extractor_failures=len(context.errors),
        enrichment_seconds=perf_counter() - started,
        diagnostics=tuple(sorted(context.diagnostics)),
        coverage=FieldCoverage(
            available_fields=tuple(sorted(context.available)),
            rejected_fields=tuple(sorted(context.rejected)),
            invalid_fields=tuple(sorted(context.invalid)),
            null_fields=tuple(sorted(context.nulls)),
        ),
    )
    return merge_metadata(result)


def enrich(
    response: TransportResponse,
    username: str,
    site: SiteDefinition,
    detection: DetectionResult,
    *,
    extractors: tuple[ProfileExtractor, ...] = EXTRACTORS,
    control_digests: frozenset[str] = frozenset(),
    follow_up: bool = False,
) -> ProfileMetadata:
    started = perf_counter()
    assessment = response_quality(
        response,
        ResponseView(response).text,
        username,
        plan_request(username, site, "enrichment").profile_url,
    )
    if detection.state != ExecutionState.OK or detection.verdict not in (
        Verdict.FOUND,
        Verdict.PROBABLE,
    ):
        return ProfileMetadata(MetadataState.UNAVAILABLE, diagnostics=("DETECTION_UNAVAILABLE",))
    if follow_up and api_kind(response.requested_url):
        return api_enrich(response, username, site)
    if (
        response.status is None
        or not 200 <= response.status < 300
        or response.error
        and not assessment.partial_verified
        or not response.body_complete
        and not assessment.partial_verified
    ):
        return ProfileMetadata(MetadataState.UNAVAILABLE, diagnostics=("RESPONSE_UNAVAILABLE",))
    if not response.body:
        return ProfileMetadata(MetadataState.EMPTY, diagnostics=("BODY_UNAVAILABLE",))
    ctype = (response.header("Content-Type") or "").lower()
    if ctype and not any(t in ctype for t in ("json", "html", "xml", "text/")):
        return ProfileMetadata(MetadataState.EMPTY, diagnostics=("CONTENT_TYPE_UNSUPPORTED",))
    if len(response.body) > min(site.body_limit, 1048576):
        return ProfileMetadata(
            MetadataState.ERROR, errors=("body budget exceeded",), parser_failures=1
        )
    try:
        document = ParsedDocument(response)
        if classify_response(document.view, plan_request(username, site, "enrichment")):
            return ProfileMetadata(MetadataState.UNAVAILABLE, diagnostics=("GENERIC_PAGE",))
        assessment = response_quality(
            response,
            document.view.text,
            username,
            plan_request(username, site, "enrichment").profile_url,
        )
        if assessment.kind not in ("UNCLASSIFIED", "PROFILE"):
            return ProfileMetadata(MetadataState.UNAVAILABLE, diagnostics=(assessment.kind,))
        context = ExtractionContext(response, username, site, control_digests)
        if assessment.partial_verified:
            extractors = (ReviewedProfileExtractor(),)
            context.diagnostics.add("METADATA_FROM_COMPLETE_EVIDENCE_UNIT_IN_PARTIAL_DOCUMENT")
        for extractor in extractors:
            try:
                extractor.extract(document, context)
            except Exception as exc:
                context.errors.append(type(extractor).__name__ + ":" + type(exc).__name__)
        if not context.candidates and not context.diagnostics:
            context.diagnostics.add(
                "NO_SUPPORTED_FIELDS"
                if context.available
                else "GENERIC_PAGE"
                if document.metadata
                else "NO_EXTRACTOR_MATCHED"
            )
        if document.errors:
            context.diagnostics.add("PARSER_EMPTY")
        result = ProfileMetadata(
            candidates=tuple(context.candidates),
            errors=tuple(document.errors + context.errors),
            parser_failures=len(document.errors),
            extractor_failures=len(context.errors),
            parse_seconds=document.parse_seconds,
            enrichment_seconds=perf_counter() - started,
            html_parse_count=document.html_parse_count,
            diagnostics=tuple(sorted(context.diagnostics)),
            coverage=FieldCoverage(
                available_fields=tuple(sorted(context.available)),
                rejected_fields=tuple(sorted(context.rejected)),
                invalid_fields=tuple(sorted(context.invalid)),
                null_fields=tuple(sorted(context.nulls)),
            ),
        )
        return merge_metadata(result)
    except (ValueError, RecursionError, UnicodeError) as exc:
        return ProfileMetadata(
            MetadataState.ERROR,
            errors=(type(exc).__name__,),
            parser_failures=1,
            enrichment_seconds=perf_counter() - started,
        )
