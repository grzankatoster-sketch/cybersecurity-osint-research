"""E3: public profile-API adapters as follow-up enrichment (families and single platforms)."""

import asyncio
import json
from pathlib import Path

import pytest

from ultimate_username.api_adapters import api_kind, select_target
from ultimate_username.domain.metadata import EnrichmentMode, EvidenceQuality, MetadataState
from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.enrichment import enrich
from ultimate_username.profile_service import ProfileService
from ultimate_username.registry import SiteRegistry
from ultimate_username.request_economy import economy
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.transport import FakeTransport

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "api" / "profiles.json").read_text("utf-8")
)
CASES.pop("_note")
JSON = (("Content-Type", "application/json"),)
HTML = (("Content-Type", "text/html; charset=utf-8"),)
SITE = SiteDefinition(
    "api-demo",
    "Api demo",
    "https://social.example/@{username}",
    DetectionSpec(Rule("status", statuses=(200,))),
)
FOUND = DetectionResult(Verdict.FOUND)


_SAME = object()


def api_response(case, body=_SAME, status=200, headers=JSON):
    payload = case["body"] if body is _SAME else body
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return TransportResponse(case["api_url"], status, raw, headers, case["api_url"])


def page_response(case, text=None, url=None):
    url = url or case["profile_url"]
    return TransportResponse(url, 200, (text or case["page"] or "").encode(), HTML, url)


def run(case, response=None, nick=None):
    return enrich(
        response or api_response(case),
        nick or case["nick"],
        SITE,
        FOUND,
        follow_up=True,
    )


def values(result):
    return {f.name: f.value for f in result.fields + result.extra_fields}


def plain(value):
    return list(value) if isinstance(value, tuple) else value


@pytest.mark.parametrize("kind", sorted(CASES))
def test_target_selected_from_profile_url_or_page(kind):
    case = CASES[kind]
    target = select_target(case["profile_url"], case["nick"], page_response(case))
    assert target is not None and target.kind == kind and target.url == case["api_url"]
    assert api_kind(target.url) == kind


@pytest.mark.parametrize("kind", sorted(CASES))
def test_fields_bound_to_owner_with_api_provenance(kind):
    case = CASES[kind]
    result = run(case)
    got = {name: plain(value) for name, value in values(result).items()}
    for name, expected in case["expect"].items():
        assert got.get(name) == expected, (kind, name, got)
    for name in case["absent"]:
        assert name not in got, (kind, name)
    assert result.state == MetadataState.SUCCESS
    for field in result.fields + result.extra_fields:
        assert field.quality == EvidenceQuality.HIGH
        assert field.source_url == case["api_url"]
        assert field.extractor.endswith("Api")


@pytest.mark.parametrize("kind", sorted(CASES))
def test_other_owner_yields_nothing_and_a_diagnostic(kind):
    case = CASES[kind]
    text = json.dumps(case["body"]).replace("alice", "bob").replace("Alice", "Bob")
    result = run(case, api_response(case, text.encode()))
    assert not result.fields and not result.extra_fields
    assert "OWNER_BINDING_FAILED" in result.diagnostics


@pytest.mark.parametrize("kind", sorted(CASES))
@pytest.mark.parametrize("body", [{}, [], None, "text", {"error": "not found"}])
def test_missing_or_foreign_shape_gives_no_fields_without_error(kind, body):
    result = run(CASES[kind], api_response(CASES[kind], body))
    assert not result.fields and not result.extra_fields
    assert result.diagnostics


@pytest.mark.parametrize("kind", sorted(CASES))
@pytest.mark.parametrize(
    "status,code", [(404, "API_RESPONSE_UNAVAILABLE"), (429, "API_RATE_LIMITED"), (500, None)]
)
def test_http_errors_give_no_fields(kind, status, code):
    result = run(CASES[kind], api_response(CASES[kind], status=status))
    assert not result.fields and result.state == MetadataState.UNAVAILABLE
    assert code is None or code in result.diagnostics


@pytest.mark.parametrize("kind", sorted(CASES))
@pytest.mark.parametrize("raw", [b"{not json", b"<html>blocked</html>", b"", b"\xff\xfe"])
def test_invalid_json_gives_no_fields_without_exception(kind, raw):
    result = run(CASES[kind], api_response(CASES[kind], raw))
    assert not result.fields and not result.extra_fields
    assert "API_INVALID_JSON" in result.diagnostics


def test_api_answer_is_only_parsed_for_follow_ups():
    case = CASES["mastodon"]
    page = enrich(api_response(case), "alice", SITE, FOUND)
    assert all(f.extractor != "MastodonApi" for f in page.fields + page.extra_fields)


def test_follow_up_for_an_unknown_url_uses_the_regular_path():
    url = "https://social.example/api/alice"
    body = json.dumps({"username": "alice", "followers": 12}).encode()
    result = enrich(
        TransportResponse(url, 200, body, JSON, url), "alice", SITE, FOUND, follow_up=True
    )
    assert values(result)["followers"] == 12


# ---------------------------------------------------------------- detection of families


def test_mastodon_recognised_by_header_and_users_path_but_not_without_evidence():
    case = CASES["mastodon"]
    url = "https://social.example/users/alice"
    bare = "<html><body>hello</body></html>"
    assert select_target(url, "alice", page_response(case, bare, url)) is None
    headed = TransportResponse(url, 200, bare.encode(), HTML + (("Server", "Mastodon"),), url)
    target = select_target(url, "alice", headed)
    assert target is not None and target.kind == "mastodon"


def test_family_pages_need_the_owner_path_and_the_same_origin():
    case = CASES["mastodon"]
    assert select_target("https://social.example/@bob", "alice", page_response(case)) is None
    assert select_target("https://social.example/about", "alice", page_response(case)) is None
    foreign = TransportResponse(
        "https://social.example/@alice",
        200,
        case["page"].encode(),
        HTML,
        "https://elsewhere.example/@alice",
    )
    assert select_target(case["profile_url"], "alice", foreign) is None
    missing = TransportResponse(case["profile_url"], 404, case["page"].encode(), HTML)
    assert select_target(case["profile_url"], "alice", missing) is None


def test_discourse_and_lemmy_share_the_u_path_but_need_their_own_markers():
    discourse, lemmy = CASES["discourse"], CASES["lemmy"]
    for case, kind in ((discourse, "discourse"), (lemmy, "lemmy")):
        target = select_target(case["profile_url"], "alice", page_response(case))
        assert target is not None and target.kind == kind
    # Neither family is assumed from the /u/ path alone.
    unmarked = page_response(lemmy, "<html><body>plain</body></html>")
    assert select_target(lemmy["profile_url"], "alice", unmarked) is None


def test_mediawiki_needs_a_user_page_and_keeps_the_api_on_the_wiki_origin():
    case = CASES["mediawiki"]
    other = "https://wiki.example/wiki/Main_Page"
    assert select_target(other, "alice", page_response(case, url=other)) is None
    evil = case["page"].replace("//wiki.example/w/api.php", "//evil.example/w/api.php")
    target = select_target(case["profile_url"], "alice", page_response(case, evil))
    assert target is not None and target.url.startswith("https://wiki.example/api.php?")
    plain_wiki = case["page"].replace('<link rel="EditURI"', '<link rel="alternate"')
    assert (
        "/api.php?"
        in select_target(case["profile_url"], "alice", page_response(case, plain_wiki)).url
    )


def test_single_platform_hosts_need_the_nick_in_the_expected_place():
    case = CASES["gravatar"]
    page = page_response(case, "<html></html>")
    assert select_target("https://en.gravatar.com/bob", "alice", page) is None
    assert select_target("https://en.gravatar.com/alice/extra", "alice", page) is None
    assert select_target("https://unknown.example/alice", "alice", page) is None
    assert select_target("ftp://gravatar.com/alice", "alice", page) is None
    habbo = select_target("https://www.habbo.es/profile/alice", "alice", page)
    assert habbo is not None and habbo.url == "https://www.habbo.es/api/public/users?name=alice"
    odd = select_target("https://bsky.app/profile/someone.example.com", "alice", page)
    assert odd is None


def test_api_url_quotes_the_nick():
    case = CASES["gravatar"]
    target = select_target("https://gravatar.com/a%2Fb", "a/b", page_response(case, "<html/>"))
    assert target is not None and "a%2Fb" in target.url and "a/b" not in target.url


# ---------------------------------------------------------------- filters and special bindings


def test_default_values_and_echoes_are_dropped():
    case = CASES["statsfm"]
    body = json.loads(json.dumps(case["body"]))
    body["item"]["displayName"] = "alice"
    result = run(case, api_response(case, body))
    names = values(result)
    assert "bio" not in names and "display_name" not in names
    assert "NICK_ECHO" in result.diagnostics

    case = CASES["mastodon"]
    body = dict(case["body"], avatar="https://social.example/avatars/original/missing.png")
    assert "avatar_url" not in values(run(case, api_response(case, body)))

    case = CASES["bandlab"]
    body = json.loads(json.dumps(case["body"]))
    body["picture"]["isDefault"] = True
    assert "avatar_url" not in values(run(case, api_response(case, body)))

    case = CASES["picsart"]
    assert "avatar_url" not in values(
        run(case, api_response(case, dict(case["body"], default_profile_pic=True)))
    )


def test_template_text_is_dropped_by_the_page_filter():
    case = CASES["gravatar"]
    body = dict(case["body"], description="You can view and join @alice right away")
    assert "bio" not in values(run(case, api_response(case, body)))


def test_mastodon_remote_account_or_other_host_is_not_the_owner():
    case = CASES["mastodon"]
    remote = dict(case["body"], acct="alice@other.example")
    assert not run(case, api_response(case, remote)).fields
    moved = dict(case["body"], url="https://other.example/@alice")
    assert not run(case, api_response(case, moved)).fields


def test_only_the_owner_object_of_a_list_is_used():
    case = CASES["inaturalist"]
    stranger = {"id": 1, "login": "alicia", "login_exact": "alicia", "name": "Someone Else"}
    body = {"results": [stranger, case["body"]["results"][0]]}
    result = run(case, api_response(case, body))
    assert values(result)["display_name"] == "Alice Smith"
    assert not run(case, api_response(case, {"results": [stranger]})).fields

    case = CASES["mediawiki"]
    body = {"query": {"users": [{"name": "Bob", "userid": 1, "editcount": 9}]}}
    assert not run(case, api_response(case, body)).fields
    gone = {"query": {"users": [{"name": "alice", "missing": ""}]}}
    assert not run(case, api_response(case, gone)).fields


def test_lemmy_instance_block_is_never_a_profile_field():
    case = CASES["lemmy"]
    result = run(case)
    assert all("Instance rules" not in str(f.value) for f in result.fields + result.extra_fields)
    deleted = json.loads(json.dumps(case["body"]))
    deleted["person_view"]["person"]["deleted"] = True
    assert not run(case, api_response(case, deleted)).fields


def test_discourse_hidden_profile_and_letter_avatar():
    case = CASES["discourse"]
    hidden = {"user": {"id": 1, "username": "alice", "profile_hidden": True, "name": "Alice X"}}
    result = run(case, api_response(case, hidden))
    assert not result.fields and "API_PROFILE_HIDDEN" in result.diagnostics
    letter = json.loads(json.dumps(case["body"]))
    letter["user"]["avatar_template"] = "/letter_avatar_proxy/v4/letter/a/b0b0b0/{size}.png"
    assert "avatar_url" not in values(run(case, api_response(case, letter)))


def test_bluesky_binds_the_handle_to_the_requested_actor():
    case = CASES["bluesky"]
    other = dict(case["body"], handle="alice.example.com")
    assert not run(case, api_response(case, other)).fields
    empty_name = dict(case["body"], displayName="", description="")
    result = run(case, api_response(case, empty_name))
    assert "display_name" not in values(result) and values(result)["followers"] == 116


def test_keybase_unknown_user_and_unverified_proofs():
    case = CASES["keybase"]
    nothing = {"status": {"code": 205, "name": "NOT_FOUND"}, "them": [None]}
    assert not run(case, api_response(case, nothing)).fields
    links = plain(values(run(case))["external_links"])
    assert "https://x.com/gone" not in links


def test_oversized_text_is_rejected_not_truncated_into_the_record():
    case = CASES["gravatar"]
    body = dict(case["body"], description="x" * 20000)
    result = run(case, api_response(case, body))
    assert len(values(result).get("bio", "")) <= 4096


def test_incomplete_body_is_unavailable():
    case = CASES["gravatar"]
    cut = TransportResponse(
        case["api_url"], 200, b'{"profile_url": "https://gravatar.com/al', JSON, body_complete=False
    )
    result = run(case, cut)
    assert not result.fields and "API_RESPONSE_UNAVAILABLE" in result.diagnostics


# ---------------------------------------------------------------- engine: budget and economy


class InlineProfiles(ProfileService):
    async def run(self, response, username, site, detection, control_digests=frozenset(), **kw):
        return enrich(response, username, site, detection, control_digests=control_digests, **kw)


def profile_site(case):
    template = case["profile_url"].replace(case["nick"], "{username}")
    return SiteDefinition(
        "e3",
        "E3 fixture",
        template,
        DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
    )


def search(case, budget, mode=EnrichmentMode.FULL, api_status=200, api_body=None):
    page = (case["page"] or "<html><body>profile</body></html>").replace(
        "</body>", "<p>profile</p></body>"
    )
    seen = []

    def handler(request, index):
        seen.append(request.url)
        if request.url == case["profile_url"]:
            return TransportResponse(request.url, 200, page.encode(), HTML, request.url)
        body = case["body"] if api_body is None else api_body
        return TransportResponse(request.url, api_status, json.dumps(body).encode(), JSON)

    async def go():
        async with UsernameEngine(
            SiteRegistry([profile_site(case)]),
            FakeTransport(handler=handler),
            profiles=InlineProfiles(),
            config=SchedulerConfig(concurrency=1, per_origin=1, per_job=1),
        ) as engine:
            results = await engine.search(
                case["nick"],
                options=SearchOptions(enrichment_mode=mode, enrichment_request_budget=budget),
            )
            assert not engine._additional_inputs and not engine._enrichment_inputs
        return results[0], seen

    return asyncio.run(go())


@pytest.mark.parametrize("kind", ["mastodon", "gravatar", "habbo", "lemmy"])
def test_engine_followup_pays_from_enrichment_budget_and_fills_fields(kind):
    case = CASES[kind]
    result, seen = search(case, budget=1)
    assert result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)
    assert seen == [case["profile_url"], case["api_url"]]
    assert [a.budget_reason for a in result.enrichment_attempts] == ["ENRICHMENT"]
    assert result.profile_metadata.request_count == 1
    assert result.profile_metadata.get("display_name") or result.profile_metadata.get("bio")
    stats = economy((result,), request_budget=100, canonical_services=1, definitions_considered=1)
    assert stats["enrichment_requests"] == 1


@pytest.mark.parametrize("kind", ["mastodon", "keybase"])
def test_zero_budget_makes_no_request_and_says_why(kind):
    case = CASES[kind]
    result, seen = search(case, budget=0)
    assert seen == [case["profile_url"]]
    assert not result.enrichment_attempts
    assert "ENRICHMENT_BUDGET" in result.profile_metadata.diagnostics
    assert result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)


def test_budget_is_spent_once_per_hit():
    case = CASES["gravatar"]
    result, seen = search(case, budget=5)
    assert len(seen) == 2 and len(result.enrichment_attempts) == 1


def test_basic_mode_follows_up_like_full():
    case = CASES["gravatar"]
    result, seen = search(case, budget=1, mode=EnrichmentMode.BASIC)
    assert seen == [case["profile_url"], case["api_url"]]
    assert [a.budget_reason for a in result.enrichment_attempts] == ["ENRICHMENT"]
    assert result.profile_metadata.get("display_name") == "Alice Smith"


def test_basic_mode_with_zero_budget_makes_no_request():
    case = CASES["gravatar"]
    result, seen = search(case, budget=0, mode=EnrichmentMode.BASIC)
    assert seen == [case["profile_url"]] and not result.enrichment_attempts
    assert "ENRICHMENT_BUDGET" in result.profile_metadata.diagnostics


def test_off_mode_never_follows_up():
    case = CASES["gravatar"]
    result, seen = search(case, budget=3, mode=EnrichmentMode.OFF)
    assert seen == [case["profile_url"]] and not result.enrichment_attempts


@pytest.mark.parametrize("status", [404, 429, 500])
def test_api_failure_never_changes_detection(status):
    case = CASES["mastodon"]
    result, seen = search(case, budget=1, api_status=status)
    assert len(seen) == 2
    assert result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)
    assert result.profile_metadata.get("display_name") is None
    assert result.profile_metadata.get("followers") is None


def test_wrong_owner_in_api_answer_adds_nothing_in_the_engine():
    case = CASES["mastodon"]
    body = dict(case["body"], acct="bob", username="bob")
    result, _ = search(case, budget=1, api_body=body)
    assert result.profile_metadata.get("followers") is None
    assert "OWNER_BINDING_FAILED" in result.profile_metadata.diagnostics


def test_page_without_family_evidence_costs_nothing():
    case = dict(CASES["mastodon"], page="<html><body>profile</body></html>")
    result, seen = search(case, budget=3)
    assert seen == [case["profile_url"]] and not result.enrichment_attempts


def test_real_profile_service_worker_receives_the_follow_up_flag():
    case = CASES["gravatar"]

    async def go():
        return await ProfileService().run(api_response(case), "alice", SITE, FOUND, follow_up=True)

    result = asyncio.run(go())
    assert values(result)["display_name"] == "Alice Smith"
