import json
from dataclasses import replace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.models import (
    DetectionSpec,
    ExtractionRule,
    HttpMethod,
    IdentifierPolicy,
    RetryPolicy,
    Rule,
    SiteDefinition,
    TimeoutProfile,
)
from ultimate_username.domain.urls import origin, request_key
from ultimate_username.domain.validation import SiteDefinitionValidator
from ultimate_username.planning import normalize, plan_request
from ultimate_username.registry import SiteRegistry


def site() -> SiteDefinition:
    return SiteDefinition(
        "example",
        "Example",
        "https://example.invalid/u/{username}",
        DetectionSpec(present=Rule("message", "profile")),
    )


@pytest.mark.parametrize("raw", ["@Alice", " Alice ", "Żółć", "e\u0301", "A/a?#%", "UPPER"])
def test_non_destructive_normalization_and_path_encoding(raw: str) -> None:
    name = normalize(raw)
    assert name.raw == name.canonical == name.site_specific == raw
    request = plan_request(raw, site(), "task")
    parsed = urlsplit(request.request.url)
    assert not parsed.query and not parsed.fragment
    assert unquote(parsed.path.removeprefix("/u/")) == raw


@pytest.mark.parametrize("raw", ["", "  ", "x" * 4097, "a\nb", "\ud800"])
def test_invalid_input(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize(raw)


def test_site_specific_transformations_have_provenance() -> None:
    policy = IdentifierPolicy(
        strip_whitespace=True, strip_at=True, lowercase=True, unicode_form="NFC"
    )
    result = normalize(" @E\u0301 ", policy)
    assert result.raw == result.canonical == " @E\u0301 "
    assert result.site_specific == "é"
    assert result.transformations == ("strip_whitespace", "strip_at", "lowercase", "NFC")


def test_json_body_recurses_and_escapes_username() -> None:
    definition = replace(site(), method=HttpMethod.POST, json_body='{"user":[{"x":"{username}"}]}')
    raw = 'a"\\?/#'
    result = plan_request(raw, definition, "t")
    assert json.loads(result.request.body) == {"user": [{"x": raw}]}
    assert dict(result.request.headers)["Content-Type"] == "application/json"


def test_form_and_query_encoding_preserves_method() -> None:
    definition = replace(
        site(),
        method=HttpMethod.PUT,
        query=(("q", "{username}"),),
        form_body=(("user", "{username}"),),
    )
    result = plan_request("a&b#?", definition, "t")
    assert result.request.method == HttpMethod.PUT
    assert parse_qs(urlsplit(result.request.url).query) == {"q": ["a&b#?"]}
    assert parse_qs(result.request.body.decode()) == {"user": ["a&b#?"]}


def test_strict_codec_and_invalid_record_isolation() -> None:
    valid = json.loads(to_json(site()))
    missing = {"id": "missing"}
    unknown = {**valid, "id": "unknown", "typo": True}
    wrong_type = {**valid, "id": "wrong", "disabled": "false"}
    registry = SiteRegistry.from_json(json.dumps([valid, missing, unknown, wrong_type]))
    assert len(registry.entries) == 4
    assert not registry.entries[0].issues
    assert all(entry.issues for entry in registry.entries[1:])


def test_codec_roundtrip_nested_rules() -> None:
    definition = replace(
        site(),
        detection=DetectionSpec(
            present=Rule(
                "all",
                children=(Rule("status", statuses=(200,)), Rule("json", "false", path=("hidden",))),
            )
        ),
    )
    assert from_json(SiteDefinition, to_json(definition)) == definition


@pytest.mark.parametrize(
    "rule",
    [
        Rule("missing"),
        Rule("regex", "["),
        Rule("message", ""),
        Rule("not"),
        Rule("all"),
        Rule("json", "notjson", path=("x",)),
        Rule("regex", "(x)", group="missing"),
    ],
)
def test_invalid_detection_rules(rule: Rule) -> None:
    definition = replace(site(), detection=DetectionSpec(present=rule))
    assert SiteDefinitionValidator().validate(definition)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0.0, -1.0])
def test_invalid_timeouts(value: float) -> None:
    definition = replace(site(), timeout=TimeoutProfile(total=value))
    assert SiteDefinitionValidator().validate(definition)


@pytest.mark.parametrize(
    "template",
    [
        "file:///tmp/{username}",
        "https://{username}.invalid/u",
        "https://x.invalid/{typo}",
        "https://x.invalid/{username.__class__}",
        "https://x.invalid/#fragment",
        "https://user:secret@x.invalid/u",
        "https://bad host.invalid/u",
    ],
)
def test_invalid_url_templates(template: str) -> None:
    assert SiteDefinitionValidator().validate(replace(site(), profile_url=template))


def test_extractor_capture_contract() -> None:
    definition = replace(
        site(), extractors=(ExtractionRule("id", "regex", pattern="no_group", group=1),)
    )
    assert SiteDefinitionValidator().validate(definition)


def test_duplicate_id_quarantines_both_entries() -> None:
    registry = SiteRegistry([site(), site()])
    assert len(registry.entries) == 2
    assert all(e.issues for e in registry.entries)
    assert registry.get("example") is None


def test_empty_registry_and_selection() -> None:
    registry = SiteRegistry([])
    assert registry.select() == ()
    assert registry.categories == ()


def test_registry_filters_disabled_categories_and_id() -> None:
    registry = SiteRegistry(
        [site(), replace(site(), id="disabled", disabled=True, category="coding")]
    )
    assert len(registry.select()) == 2
    assert len(registry.select(include_disabled=False)) == 1
    assert registry.select(categories=["coding"])[0].id == "disabled"
    assert registry.select(ids=[]) == ()


def test_request_identity_preserves_path_case_query_and_context() -> None:
    request = plan_request("A", site(), "t").request
    assert request_key(request) != request_key(replace(request, url=request.url.lower()))
    assert request_key(request) != request_key(replace(request, url=request.url + "?x=1"))
    assert request_key(request) != request_key(replace(request, context_id="other"))
    assert origin("https://a.co.uk/u") != origin("https://b.co.uk/u")
    assert (
        origin("https://example.invalid/?url=https://other.invalid")
        == "https://example.invalid:443"
    )


def test_invalid_retry_and_contradiction() -> None:
    assert SiteDefinitionValidator().validate(replace(site(), retry=RetryPolicy(max_attempts=0)))
    same = Rule("message", "profile")
    assert SiteDefinitionValidator().validate(replace(site(), detection=DetectionSpec(same, same)))
