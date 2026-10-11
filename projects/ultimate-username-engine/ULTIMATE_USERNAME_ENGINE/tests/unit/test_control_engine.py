"""Control request wired into the engine: every case of section 6 of the spec."""

import asyncio
import json
import re
from dataclasses import dataclass, replace

import pytest

from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.metadata import EnrichmentMode
from ultimate_username.domain.models import (
    Control,
    DetectionSpec,
    HttpMethod,
    RateProfile,
    RedirectPolicy,
    RetryPolicy,
    Rule,
    SearchResult,
    SiteDefinition,
    TimeoutProfile,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.presentation import analyst_record
from ultimate_username.registry import SiteRegistry
from ultimate_username.request_economy import economy
from ultimate_username.runtime_policy import MODES, RuntimePolicy, runtime_selection
from ultimate_username.selection import select_services
from ultimate_username.transport import FakeTransport

REAL = {"alice", "bobby"}
FILLER = "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor. " * 5
STATUS_OK = Rule("status", statuses=tuple(range(200, 300)))
NOT_FOUND_404 = Rule("status", statuses=(404,))
POSTS = Rule("message", "Posts by")
NO_SUCH = Rule("message", "no such user")


def name_of(request):
    return request.url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]


def is_control(request):
    return name_of(request) not in REAL and "/u/" in request.url


def page(name, extra="", title=None):
    return (
        f"<html><head><title>{title or name}</title></head><body><h1>{name}</h1>"
        f"<p>{extra} {FILLER}</p></body></html>"
    )


def ok(request, body, status=200, headers=()):
    data = body.encode() if isinstance(body, str) else body
    return TransportResponse(request.url, status, data, tuple(headers), request.url)


def site(present=STATUS_OK, absent=NOT_FOUND_404, sid="s", host="ctl.test", **changes):
    base = SiteDefinition(
        sid, sid, f"https://{host}/u/{{username}}", DetectionSpec(present, absent), **changes
    )
    return base


def policy(control=10, budget=30, **changes):
    values = dict(
        request_budget=budget,
        retry_budget=0,
        fallback_limit=0,
        min_quality=-100,
        control_budget=control,
        retry_min_delay=0.01,
        rate_limit_seconds=0.02,
    )
    values.update(changes)
    return RuntimePolicy(**values)


@dataclass
class Outcome:
    results: list
    transport: FakeTransport
    summary: object
    registry: SiteRegistry
    selection: object
    engine: UsernameEngine

    def one(self) -> SearchResult:
        assert len(self.results) == 1
        return self.results[0]

    @property
    def controls(self):
        return [r for r in self.transport.requests if is_control(r)]


async def _run(sites, handler, pol, usernames, seed):
    registry = SiteRegistry(sites)
    assert not [e for e in registry.entries if e.issues], [e.issues for e in registry.entries]
    transport = FakeTransport(handler=handler)
    results = []
    async with UsernameEngine(registry, transport, random_seed=seed) as engine:
        for username in usernames:
            selection = runtime_selection(registry, select_services(registry, username), pol)
            async for r in engine.search_stream(
                username,
                site_ids=selection.selected,
                options=SearchOptions(
                    job_timeout=pol.job_timeout,
                    request_budget=pol.request_budget,
                    enrichment_mode=EnrichmentMode.OFF,
                ),
                runtime=pol,
                selection=selection,
            ):
                results.append(r)
        summary = engine.summaries[-1]
    return Outcome(results, transport, summary, registry, selection, engine)


def run(sites, handler, pol=None, usernames=("alice",), seed=5):
    return asyncio.run(_run(sites, handler, pol or policy(), usernames, seed))


def reasons(result):
    return result.detection.reasons


def budget_reasons(result):
    return [a.budget_reason for a in result.attempts]


# 1 ---------------------------------------------------------------- status-only probable


def test_status_only_200_vs_404_with_name_is_probable():
    def handler(request, i):
        if is_control(request):
            return ok(request, "<html><body>Not Found</body></html>", 404)
        return ok(request, page(name_of(request)))

    out = run([site()], handler)
    result = out.one()
    assert result.detection.verdict == Verdict.PROBABLE
    assert reasons(result) == ("CONTROL_DIFFERS_STRONG",)
    assert result.detection.evidence_level == 2
    assert out.transport.total == 2 and len(out.controls) == 1
    evidence = result.detection.evidence[-1]
    assert evidence.rule_id == "control" and evidence.strategy == "control_request"
    record = json.loads(evidence.observed)
    assert record["status_real"] == 200 and record["status_control"] == 404
    assert record["control_name"] == name_of(out.controls[0]) and "seed" in record
    assert result.detection.signals[-1].independence_group == "control"
    assert from_json(SearchResult, to_json(result)) == result


# 2 ---------------------------------------------------------------- content present found


def test_message_present_with_404_control_is_found():
    def handler(request, i):
        if is_control(request):
            return ok(request, "Not Found", 404)
        return ok(request, page("alice", "Posts by alice"))

    result = run([site(POSTS)], handler).one()
    assert result.detection.verdict == Verdict.FOUND
    assert reasons(result) == ("CONTROL_DIFFERS_STRONG",)
    assert (result.detection.confidence.strength, result.detection.evidence_level) == (
        "MODERATE",
        2,
    )


# 3 ---------------------------------------------------------------- identical pages


def test_same_page_for_both_names_is_unknown_control_identical():
    def handler(request, i):
        name = name_of(request)
        return ok(request, page(name, f"Posts by {name}"))

    result = run([site(POSTS)], handler).one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert reasons(result)[0] == "CONTROL_IDENTICAL"


# 4 ---------------------------------------------------------------- deleted accounts

DELETED = {
    "en": "This account has been suspended.",
    "pl": "Konto zostało usunięte.",
    "ru": "Аккаунт пользователя удалён.",
    "ko": "탈퇴한 회원입니다.",
    "zh": "该账号异常，无法访问。",
}


@pytest.mark.parametrize("language", sorted(DELETED))
def test_deleted_account_page_is_never_a_hit(language):
    text = DELETED[language]

    def handler(request, i):
        if is_control(request):
            return ok(request, "Not Found", 404)
        return ok(request, f"<html><body><p>{text}</p></body></html>")

    result = run([site()], handler).one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert reasons(result)[0] == "ACCOUNT_STATE_SIGNATURE"
    signature = [s for s in result.detection.signals if s.source == "control_request"]
    assert signature and signature[0].kind == "ACCOUNT_STATE_SIGNATURE"


@pytest.mark.parametrize("language", sorted(DELETED))
def test_deleted_account_cannot_become_a_stale_rule_probable(language):
    text = DELETED[language]

    def handler(request, i):
        if is_control(request):
            return ok(request, "Not Found", 404)
        return ok(request, page("alice", text))

    result = run([site(POSTS, NO_SUCH)], handler).one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert reasons(result)[0] == "ACCOUNT_STATE_SIGNATURE"


# 5 ---------------------------------------------------------------- empty shell


def test_empty_200_shell_against_404_is_not_a_hit():
    shell = '<html><body><div id="root"></div><script src="/app.js"></script></body></html>'

    def handler(request, i):
        if is_control(request):
            return ok(request, "<html><body>Not Found</body></html>", 404)
        return ok(request, shell)

    result = run([site()], handler).one()
    assert result.detection.verdict not in (Verdict.FOUND, Verdict.PROBABLE)
    assert "NOT_SUBSTANTIVE" in reasons(result)


# 6, 7 ------------------------------------------------------------- class B


def test_b_soft_404_identical_to_control_is_not_found():
    def handler(request, i):
        return ok(request, page(name_of(request), "Something went wrong, try again later"))

    result = run([site(POSTS, NO_SUCH)], handler).one()
    assert result.detection.verdict == Verdict.NOT_FOUND
    assert reasons(result) == ("CONTROL_IDENTICAL_ABSENCE",)
    assert result.detection.evidence_level == 1  # a 2xx soft 404 is weaker than a real 404
    assert result.detection.confidence.strength == "COMPOSITE"
    assert result.detection.evidence[-1].polarity.value == "SUPPORTS_ABSENT"


def test_b_identical_404_is_not_found():
    result = run([site(POSTS, NO_SUCH)], lambda r, i: ok(r, "Gone", 404)).one()
    assert result.detection.verdict == Verdict.NOT_FOUND
    assert result.detection.evidence_level == 2


def test_b_identical_js_shell_is_unknown():
    shell = '<html><body><div id="root"></div></body></html>'
    result = run([site(POSTS, NO_SUCH)], lambda r, i: ok(r, shell)).one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert reasons(result)[:2] == ("CONTROL_IDENTICAL", "JS_SHELL")


# 8 ---------------------------------------------------------------- stale rule


def test_b_stale_rule_200_with_name_vs_404_is_probable():
    def handler(request, i):
        if is_control(request):
            return ok(request, "no such user", 404)
        return ok(request, page("alice", "Recent activity"))

    result = run([site(POSTS, NO_SUCH)], handler).one()
    assert result.detection.verdict == Verdict.PROBABLE
    assert reasons(result) == ("CONTROL_DIFFERS_STALE_RULE",)


# 9 ---------------------------------------------------------------- class C


def test_c_404_is_not_found_only_with_a_verified_donor_control():
    handler = lambda r, i: ok(r, "Not Found", 404)  # noqa: E731
    donor = (Control("bob", Verdict.FOUND, True),)
    out = run([site(controls=donor)], handler)
    assert out.one().detection.verdict == Verdict.NOT_FOUND
    assert reasons(out.one()) == ("STATUS_ABSENCE_DONOR_VERIFIED",)
    assert out.transport.total == 1
    out = run([site()], handler)
    assert out.one().detection.verdict == Verdict.UNKNOWN and out.transport.total == 1
    unverified = (Control("bob", Verdict.FOUND, False),)
    assert run([site(controls=unverified)], handler).one().detection.verdict == Verdict.UNKNOWN
    unclaimed = (Control("zed", Verdict.NOT_FOUND, True),)
    assert run([site(controls=unclaimed)], handler).one().detection.verdict == Verdict.UNKNOWN


# 10 --------------------------------------------------------------- class D


def test_d_status_only_presence_loses_to_content_absence():
    out = run([site(STATUS_OK, NO_SUCH)], lambda r, i: ok(r, "no such user"))
    assert out.one().detection.verdict == Verdict.NOT_FOUND
    assert reasons(out.one()) == ("ABSENCE_CONTENT_OVERRIDES_STATUS",)
    assert out.transport.total == 1


def test_d_content_presence_and_content_absence_stay_contradictory():
    out = run([site(POSTS, NO_SUCH)], lambda r, i: ok(r, "Posts by alice, no such user"))
    assert out.one().detection.verdict == Verdict.UNKNOWN
    assert reasons(out.one()) == ("CONTRADICTORY_EVIDENCE",)
    assert out.transport.total == 1


# 11 --------------------------------------------------------------- blocked control


@pytest.mark.parametrize(
    "control",
    [
        (403, "denied", ()),
        (429, "slow down", (("Retry-After", "30"),)),
        (200, "<title>Just a moment...</title>", ()),
        (500, "boom", ()),
    ],
)
def test_blocked_control_leaves_the_verdict_alone(control):
    status, body, headers = control

    def handler(request, i):
        if is_control(request):
            return ok(request, body, status, headers)
        return ok(request, page("alice", "Posts by alice"))

    out = run([site(POSTS)], handler)
    result = out.one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert result.detection.state.value == "OK"
    assert reasons(result)[0] == "CONTROL_UNAVAILABLE"
    assert "NO_PROFILE_SPECIFIC_EVIDENCE" in reasons(result)
    assert budget_reasons(result) == ["PRIMARY_CHECK", "CONTROL_CHECK"]
    if status == 429:
        assert "CONTROL_UNAVAILABLE_RATE_LIMITED" in reasons(result)


# 12 --------------------------------------------------------------- non-GET/HEAD/POST


def test_method_other_than_get_head_post_gets_no_control():
    put = site(method=HttpMethod.PUT, json_body='{"u": "{username}"}', idempotent=False)
    out = run([put], lambda r, i: ok(r, page("alice")))
    result = out.one()
    assert out.transport.total == 1
    assert result.detection.verdict == Verdict.UNKNOWN
    assert "CONTROL_UNAVAILABLE" in reasons(result)
    assert "CONTROL_UNAVAILABLE_METHOD" in reasons(result)


# 13 --------------------------------------------------------------- untouchable results


def test_explicit_not_found_is_never_touched():
    out = run([site(POSTS, NO_SUCH)], lambda r, i: ok(r, "no such user"))
    assert out.one().detection.verdict == Verdict.NOT_FOUND
    assert reasons(out.one()) == ("NEGATIVE_EVIDENCE",)
    assert out.transport.total == 1


def test_explicit_found_with_binding_is_never_touched():
    spec = DetectionSpec(
        Rule("message", "owner={username}"), NO_SUCH, Rule("message", "owner={username}")
    )
    bound = SiteDefinition("b", "b", "https://ctl.test/u/{username}", spec)
    out = run([bound], lambda r, i: ok(r, "owner=alice"))
    assert out.one().detection.verdict == Verdict.FOUND
    assert reasons(out.one()) == ("POSITIVE_EVIDENCE",)
    assert out.transport.total == 1


def test_reviewed_profile_adapter_is_never_touched():
    body = json.dumps(
        {
            "@id": "https://api.chess.com/pub/player/alice",
            "url": "https://www.chess.com/member/alice",
            "username": "alice",
            "player_id": 42,
        }
    )
    chess = SiteDefinition(
        "chess",
        "chess",
        "https://www.chess.com/member/{username}",
        DetectionSpec(STATUS_OK, NOT_FOUND_404),
        probe_url="https://api.chess.com/pub/player/{username}",
    )
    out = run([chess], lambda r, i: ok(r, body))
    result = out.one()
    assert (
        result.detection.verdict == Verdict.FOUND and result.detection.response_class == "PROFILE"
    )
    assert out.transport.total == 1 and "control" not in [
        e.rule_id for e in result.detection.evidence
    ]


@pytest.mark.parametrize(
    ("kind", "response"),
    [
        ("challenge", lambda r: ok(r, "<title>Just a moment...</title>")),
        ("blocked", lambda r: ok(r, "denied", 403)),
        ("parked", lambda r: ok(r, "<script>window.location.href='/lander'</script>")),
        (
            "homepage",
            lambda r: TransportResponse(r.url, 200, b"home", (), "https://ctl.test/"),
        ),
    ],
)
def test_gated_responses_get_no_control(kind, response):
    out = run([site()], lambda r, i: response(r))
    assert out.transport.total == 1, kind
    assert "control" not in [e.rule_id for e in out.one().detection.evidence]


def test_discovery_only_definition_gets_no_control():
    out = run([site(discovery_only=True)], lambda r, i: ok(r, page("alice")))
    assert out.transport.total == 1
    assert out.one().detection.verdict == Verdict.UNKNOWN


# 14 --------------------------------------------------------------- budgets


def present_handler(request, i):
    if is_control(request):
        return ok(request, "Not Found", 404)
    return ok(request, page(name_of(request)))


def test_control_budget_zero_sends_nothing():
    out = run([site()], present_handler, policy(control=0))
    result = out.one()
    assert out.transport.total == 1 and not out.controls
    assert result.detection.verdict == Verdict.UNKNOWN
    assert "CONTROL_UNAVAILABLE" not in reasons(result)
    stats = economy(out.results, request_budget=30, canonical_services=1, definitions_considered=1)
    assert stats["control_requests"] == 0


def test_control_budget_is_a_shared_ceiling_and_reported_in_economy():
    sites = [site(sid=f"s{i}", host=f"h{i}.test") for i in range(3)]
    out = run(sites, present_handler, policy(control=1))
    assert out.transport.total == 4 and len(out.controls) == 1
    verdicts = sorted(r.detection.verdict.value for r in out.results)
    assert verdicts == ["PROBABLE", "UNKNOWN", "UNKNOWN"]
    starved = [r for r in out.results if r.detection.verdict == Verdict.UNKNOWN]
    assert all("CONTROL_UNAVAILABLE_BUDGET" in reasons(r) for r in starved)
    stats = economy(out.results, request_budget=30, canonical_services=3, definitions_considered=3)
    assert stats["control_requests"] == 1 and stats["primary_requests"] == 3
    assert stats["total_requests"] == 4
    assert dict(out.summary.request_counts) == {"PRIMARY_CHECK": 3, "CONTROL_CHECK": 1}


@pytest.mark.parametrize("budget", [1, 2, 3, 5])
def test_hard_request_budget_still_holds_with_controls(budget):
    sites = [site(sid=f"s{i}", host=f"h{i}.test") for i in range(6)]
    out = run(sites, present_handler, policy(control=100, budget=budget))
    assert out.transport.total <= budget
    assert sum(dict(out.summary.request_counts).values()) == out.transport.total
    assert out.summary.budget_remaining == budget - out.transport.total


def test_budget_exhausted_before_control_is_a_clean_unknown():
    out = run([site()], present_handler, policy(control=5, budget=1))
    result = out.one()
    assert out.transport.total == 1
    assert result.detection.verdict == Verdict.UNKNOWN and result.detection.state.value == "OK"
    assert "CONTROL_UNAVAILABLE_BUDGET" in reasons(result)


def test_modes_and_policy_fields():
    assert MODES["quick"].control_budget == 0
    assert MODES["normal"].control_budget == 150  # F3.3: was 25
    assert MODES["deep"].control_budget == 150
    assert MODES["exhaustive"].control_budget == 2500
    for name in ("found", "absence", "stale_rule", "status_absence", "content_override"):
        assert getattr(RuntimePolicy(), "control_" + name) is True
    assert RuntimePolicy().control_signatures is True
    with pytest.raises(ValueError):
        RuntimePolicy(control_budget=-1)
    with pytest.raises(ValueError):
        RuntimePolicy(control_found=1)
    assert from_json(RuntimePolicy, '{"control_budget": 7}').control_budget == 7
    assert replace(MODES["exhaustive"], control_budget=0).control_budget == 0


def test_rule_flags_switch_rules_off():
    one = run([site()], present_handler, policy(control_found=False))
    assert one.transport.total == 1 and one.one().detection.verdict == Verdict.UNKNOWN
    handler = lambda r, i: ok(r, "Not Found", 404)  # noqa: E731
    donor = (Control("bob", Verdict.FOUND, True),)
    off = run([site(controls=donor)], handler, policy(control_status_absence=False))
    assert off.one().detection.verdict == Verdict.UNKNOWN
    off = run(
        [site(STATUS_OK, NO_SUCH)],
        lambda r, i: ok(r, "no such user"),
        policy(control_content_override=False),
    )
    assert off.one().detection.verdict == Verdict.UNKNOWN

    def deleted(request, i):
        if is_control(request):
            return ok(request, "Not Found", 404)
        return ok(request, page("alice", "This account has been suspended."))

    assert run([site()], deleted).one().detection.verdict == Verdict.UNKNOWN
    off = run([site()], deleted, policy(control_signatures=False))
    assert off.one().detection.verdict == Verdict.PROBABLE


# 15 --------------------------------------------------------------- attempts


def test_control_does_not_disturb_the_main_attempt():
    out = run([site()], present_handler)
    result = out.one()
    main, control = result.attempts
    assert (main.number, main.budget_reason, main.status) == (1, "PRIMARY_CHECK", 200)
    assert main.url == "https://ctl.test/u/alice" == result.probe_url == result.final_url
    assert (control.number, control.budget_reason, control.status) == (2, "CONTROL_CHECK", 404)
    assert control.url != main.url
    assert dict(out.summary.request_counts) == {"PRIMARY_CHECK": 1, "CONTROL_CHECK": 1}
    record = analyst_record(result, out.registry)
    assert record["http_status"] == 200 and record["request_count"] == 2
    assert record["status"] == "PROBABLE"
    assert result.fallback_chain[0].block_class == ""
    control_record = record["control"]
    assert isinstance(control_record, dict)
    assert control_record["kind"].startswith("CONTROL_")
    assert (control_record["status_real"], control_record["status_control"]) == (200, 404)
    assert control_record["control_name"]
    assert all(e["rule_id"] != "control" for e in record["evidence"])


def test_control_follows_redirects_with_its_own_history():
    follow = RedirectPolicy(follow=True)

    def handler(request, i):
        if request.url == "https://ctl.test/":
            return ok(request, page("home", "Welcome"))
        if is_control(request):
            return ok(request, "", 302, (("Location", "/"),))
        return ok(request, page("alice", "Posts by alice"))

    out = run([site(POSTS, redirects=follow)], handler)
    result = out.one()
    assert budget_reasons(result) == ["PRIMARY_CHECK", "CONTROL_CHECK", "CONTROL_CHECK"]
    assert result.redirects == () and result.detection.verdict == Verdict.FOUND
    assert out.summary.budget_remaining == 30 - 3


# 16 --------------------------------------------------------------- cache


def test_one_control_request_per_definition_across_names():
    out = run([site()], present_handler, usernames=("alice", "bobby"))
    assert len(out.results) == 2 and out.transport.total == 3 and len(out.controls) == 1
    first, second = out.results
    assert first.detection.verdict == second.detection.verdict == Verdict.PROBABLE
    cached = json.loads(second.detection.evidence[-1].observed)
    assert cached["cached"] is True
    assert budget_reasons(second) == ["PRIMARY_CHECK"]


def test_failed_control_is_not_cached():
    state = {"n": 0}

    def handler(request, i):
        if is_control(request):
            state["n"] += 1
            return ok(request, "denied", 403) if state["n"] == 1 else ok(request, "Not Found", 404)
        return ok(request, page(name_of(request)))

    out = run([site()], handler, usernames=("alice", "bobby"))
    first, second = out.results
    assert reasons(first)[0] == "CONTROL_UNAVAILABLE"
    assert second.detection.verdict == Verdict.PROBABLE
    assert len(out.controls) == 2


def test_control_name_is_reproducible_from_the_logged_seed():
    import random

    from ultimate_username import control as ctl

    out = run([site()], present_handler, seed=99)
    record = json.loads(out.one().detection.evidence[-1].observed)
    assert ctl.control_name(random.Random(record["seed"]), "alice") == record["control_name"]


def test_control_name_respects_site_pattern_and_never_contains_real_name():
    from ultimate_username.domain.models import IdentifierPolicy

    restricted = site(identifier=IdentifierPolicy(pattern=r"[a-z][a-z0-9]{4,7}"))
    out = run([restricted], present_handler)
    assert re.fullmatch(r"[a-z][a-z0-9]{4,7}", name_of(out.controls[0]))
    impossible = site(identifier=IdentifierPolicy(pattern=r"(?:[a-z]+|alice)"))
    out = run([impossible], present_handler)
    assert not out.controls
    assert "CONTROL_UNAVAILABLE_NAME" in reasons(out.one())


def test_query_probe_without_username_is_not_compared_with_itself():
    static = site(probe_url="https://ctl.test/static")
    out = run([static], lambda r, i: ok(r, page("x")))
    assert out.transport.total == 1
    assert "CONTROL_UNAVAILABLE_REQUEST" in reasons(out.one())


def test_cli_control_budget_flag_is_validated_before_the_journal(tmp_path):
    from ultimate_username.cli import main, parser

    assert parser().parse_args(["search", "alice", "--control-budget", "7"]).control_budget == 7
    path = tmp_path / "run.sqlite"
    assert main(["search", "alice", "--control-budget", "-1", "--journal", str(path)]) == 2
    assert not path.exists()


# review fixes ---------------------------------------------------------------------------


def test_deleted_account_signature_survives_entities_and_line_breaks():
    body = (
        "<html><body><nav>" + "&nbsp;\n" * 1500 + "</nav>"
        "<p>User <b>alice</b> has\n been&nbsp;deleted.</p></body></html>"
    )

    def handler(request, i):
        if is_control(request):
            return ok(request, "Not Found", 404)
        return ok(request, body)

    result = run([site()], handler).one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert reasons(result)[0] == "ACCOUNT_STATE_SIGNATURE"


SHELL_WITH_NAME_IN_TITLE = (
    "<html><head><title>alice - Site</title></head><body>"
    '<div id="root"></div><script src="/app.js"></script></body></html>'
)


@pytest.mark.parametrize("definition", [site(), site(POSTS, NO_SUCH)], ids=["A", "B"])
def test_shell_with_the_name_only_in_the_title_is_not_a_hit(definition):
    def handler(request, i):
        if is_control(request):
            return ok(request, "<html><body>Not Found</body></html>", 404)
        return ok(request, SHELL_WITH_NAME_IN_TITLE)

    result = run([definition], handler).one()
    assert result.detection.verdict not in (Verdict.FOUND, Verdict.PROBABLE)


def test_a_control_that_passes_the_same_rule_does_not_discriminate():
    noise = " ".join(f"zq{c}" for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")

    def handler(request, i):
        if is_control(request):
            name = name_of(request)
            return ok(request, page(name, f"Posts by {name} {noise}", title="Other"))
        return ok(request, page("alice", "Posts by alice"))

    result = run([site(POSTS)], handler).one()
    assert result.detection.verdict == Verdict.UNKNOWN
    assert reasons(result)[0] == "CONTROL_NONDISCRIMINATING"


def test_control_that_is_rate_limited_is_not_retried_and_does_not_block_the_result():
    retrying = site(retry=RetryPolicy(max_attempts=4, base_delay=0.01, max_delay=0.02))

    def handler(request, i):
        if is_control(request):
            return ok(request, "slow down", 429, (("Retry-After", "30"),))
        return ok(request, page("alice"))

    out = run([retrying], handler, policy(retry_budget=5))
    result = out.one()
    assert len(out.controls) == 1 and out.transport.total == 2
    assert result.detection.verdict == Verdict.UNKNOWN and result.detection.state.value == "OK"
    assert "CONTROL_UNAVAILABLE_RATE_LIMITED" in reasons(result)
    assert budget_reasons(result) == ["PRIMARY_CHECK", "CONTROL_CHECK"]
    stats = economy(out.results, request_budget=30, canonical_services=1, definitions_considered=1)
    assert stats["control_requests"] == 1 and stats["retries"] == 0
    assert stats["http_429_responses"] == 0


def test_main_answer_survives_a_deadline_that_expires_during_the_control():
    slow = site(rate=RateProfile(min_interval=0.3), timeout=TimeoutProfile(queue=0.05, total=1.0))
    out = run([slow], present_handler)
    result = out.one()
    assert out.transport.total == 1 and not out.controls
    assert result.detection.state.value == "OK"
    assert result.detection.verdict == Verdict.UNKNOWN
    assert "CONTROL_UNAVAILABLE_TIMEOUT" in reasons(result)
    assert "QUEUE_TIMEOUT" in reasons(result)
    assert budget_reasons(result) == ["PRIMARY_CHECK"]


def test_main_answer_survives_a_job_deadline_hit_during_the_control():
    out = run([site(rate=RateProfile(min_interval=0.5))], present_handler, policy(job_timeout=0.2))
    result = out.one()
    assert result.detection.state.value == "OK" and not out.controls
    assert "CONTROL_UNAVAILABLE_TIMEOUT" in reasons(result)
    assert "JOB_TIMEOUT" in reasons(result)


def test_open_circuit_before_the_control_keeps_the_main_answer(monkeypatch):
    from time import monotonic

    from ultimate_username.engine import _SearchWork

    original = _SearchWork._begin_control

    def open_circuit_after_main(self, response, request, detection):
        started, updated = original(self, response, request, detection)
        if started:
            self.budget.circuit_until[self.origin] = monotonic() + 60
        return started, updated

    monkeypatch.setattr(_SearchWork, "_begin_control", open_circuit_after_main)
    out = run([site()], present_handler)
    result = out.one()
    assert not out.controls and out.transport.total == 1
    assert result.detection.state.value == "OK" and result.detection.verdict == Verdict.UNKNOWN
    assert "CONTROL_UNAVAILABLE_ORIGIN" in reasons(result)


def test_cli_warns_when_control_budget_has_no_runtime_mode(tmp_path, capsys):
    from ultimate_username.cli import main

    missing = tmp_path / "none.json"
    args = ["search", "alice", "--registry", str(missing), "--journal", str(tmp_path / "j.sqlite")]
    main([*args, "--control-budget", "5", "--selection", "all"])
    assert "--control-budget" in capsys.readouterr().err
    main([*args, "--control-budget", "5"])
    assert "--control-budget has no effect" not in capsys.readouterr().err


# F3.5 ------------------------------------------------------------- POST with a body

API = "https://ctl.test/api/check"


def post_name(request):
    """The searched name sits only in the body: JSON, form or (static) raw."""
    body = (request.body or b"").decode()
    if body.startswith("{"):
        return json.loads(body)["u"]
    return dict(pair.split("=") for pair in body.split("&"))["u"]


def post_site(kind="json", present=STATUS_OK, absent=NOT_FOUND_404, **changes):
    body = {
        "json": dict(json_body='{"u": "{username}"}'),
        "form": dict(form_body=(("u", "{username}"), ("k", "1"))),
    }[kind]
    return site(
        present, absent, method=HttpMethod.POST, probe_url=API, idempotent=True, **body, **changes
    )


def taken_handler(taken_real, taken_control):
    def handler(request, i):
        name = post_name(request)
        taken = taken_real if name in REAL else taken_control
        return ok(request, json.dumps({"taken": taken, "pad": FILLER}))

    return handler


def get_twin(taken_real, taken_control, present=STATUS_OK, absent=NOT_FOUND_404):
    def handler(request, i):
        taken = taken_real if name_of(request) in REAL else taken_control
        return ok(request, json.dumps({"taken": taken, "pad": FILLER}))

    return run([site(present, absent)], handler).one()


@pytest.mark.parametrize("kind", ["json", "form"])
@pytest.mark.parametrize(
    "taken_real,taken_control",
    [(True, False), (False, True), (True, True), (False, False)],
    ids=["differs", "inverted", "same-true", "same-false"],
)
def test_post_control_behaves_like_the_get_control_on_the_same_answers(
    kind, taken_real, taken_control
):
    out = run([post_site(kind)], taken_handler(taken_real, taken_control))
    result = out.one()
    twin = get_twin(taken_real, taken_control)
    assert (result.detection.verdict, reasons(result)) == (twin.detection.verdict, reasons(twin))
    assert out.transport.total == 2  # the answer plus one control
    assert "CONTROL_UNAVAILABLE_METHOD" not in reasons(result)
    assert budget_reasons(result) == ["PRIMARY_CHECK", "CONTROL_CHECK"]


def test_post_taken_true_against_false_is_a_control_difference():
    # JSON {"taken": true} for the searched name, {"taken": false} for the control name
    # with a status-only definition: same outcome as the GET twin, which is the rules' call.
    result = run([post_site()], taken_handler(True, False)).one()
    twin = get_twin(True, False)
    assert result.detection.verdict == twin.detection.verdict
    assert reasons(result) == reasons(twin)
    assert any("CONTROL" in r for r in reasons(result))


def test_post_control_with_a_rule_on_the_flag_matches_the_get_twin():
    flag = Rule("message", '"taken": true')
    absent = Rule("message", '"taken": false')
    for real, control in ((True, False), (False, True), (True, True)):
        result = run([post_site(present=flag, absent=absent)], taken_handler(real, control)).one()
        twin = get_twin(real, control, flag, absent)
        assert (result.detection.verdict, reasons(result)) == (
            twin.detection.verdict,
            reasons(twin),
        )


def test_post_status_difference_is_probable_with_the_control_name_in_the_record():
    def handler(request, i):
        if post_name(request) in REAL:
            return ok(request, page(post_name(request)))
        return ok(request, "<html><body>Not Found</body></html>", 404)

    out = run([post_site()], handler)
    result = out.one()
    assert result.detection.verdict == Verdict.PROBABLE
    assert reasons(result) == ("CONTROL_DIFFERS_STRONG",)
    record = json.loads(result.detection.evidence[-1].observed)
    assert record["status_real"] == 200 and record["status_control"] == 404
    assert record["control_name"] == post_name(out.transport.requests[1])


def test_post_identical_answers_decide_by_the_same_rules_as_get():
    out = run([post_site()], taken_handler(True, True))
    result = out.one()
    assert result.detection.verdict in (Verdict.UNKNOWN, Verdict.NOT_FOUND)
    assert result.detection.verdict != Verdict.PROBABLE
    twin = get_twin(True, True)
    assert result.detection.verdict == twin.detection.verdict


def test_post_control_request_carries_the_control_name_in_every_body_kind():
    seen = {}

    def handler(request, i):
        seen.setdefault(request.url + (request.body or b"").decode(), request)
        if post_name(request) in REAL:
            return ok(request, page(post_name(request)))
        return ok(request, "Gone", 404)

    for kind in ("json", "form"):
        seen.clear()
        out = run([post_site(kind)], handler)
        names = [post_name(r) for r in out.transport.requests]
        assert names[0] == "alice" and names[1] not in REAL and len(names) == 2
        assert out.transport.requests[1].url == API  # only the body carries the name
        assert out.transport.requests[1].method == HttpMethod.POST


def test_post_with_a_static_body_cannot_have_a_distinct_control():
    static = site(method=HttpMethod.POST, probe_url=API, raw_body="constant", idempotent=True)
    out = run([static], lambda r, i: ok(r, page("alice")))
    result = out.one()
    assert out.transport.total == 1
    assert "CONTROL_UNAVAILABLE_REQUEST" in reasons(result)


def test_post_control_is_cached_per_definition_like_get():
    out = run([post_site()], taken_handler(True, False), usernames=("alice", "bobby"))
    assert len(out.results) == 2
    assert len(out.controls) == 0  # is_control looks at /u/ urls; count bodies instead
    controls = [r for r in out.transport.requests if post_name(r) not in REAL]
    assert len(controls) == 1


def _limited_then(calls, headers, again=False):
    def handler(request, i):
        if is_control(request):
            calls.append(request.url)
            if again or len(calls) == 1:
                return ok(request, "slow down", 429, headers)
            return ok(request, page(name_of(request), "No such member here"), 404)
        return ok(request, page("alice", "Posts by alice"))

    return handler


@pytest.mark.parametrize("headers", [(), (("Retry-After", "0.01"),), (("Retry-After", "10"),)])
def test_rate_limited_control_is_retried_once_and_then_decides(headers):
    calls: list[str] = []
    out = run([site(POSTS)], _limited_then(calls, headers), policy(rate_limit_seconds=0.02))
    result = out.one()
    assert len(calls) == 2 and calls[0] == calls[1] and out.transport.total == 3
    assert budget_reasons(result) == ["PRIMARY_CHECK", "CONTROL_CHECK", "CONTROL_CHECK"]
    assert "CONTROL_UNAVAILABLE_RATE_LIMITED" not in reasons(result)
    assert result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)


def test_control_rate_retry_is_a_single_one_and_stays_in_the_control_budget():
    calls: list[str] = []
    out = run([site(POSTS)], _limited_then(calls, (), again=True), policy(rate_limit_seconds=0.02))
    result = out.one()
    assert len(calls) == 2 and out.transport.total == 3
    assert "CONTROL_UNAVAILABLE_RATE_LIMITED" in reasons(result)
    assert result.detection.verdict == Verdict.UNKNOWN
    assert out.summary.budget_remaining == 30 - 3
    calls.clear()
    tight = run([site(POSTS)], _limited_then(calls, ()), policy(control=1, rate_limit_seconds=0.02))
    assert len(calls) == 1 and tight.transport.total == 2
    assert "CONTROL_UNAVAILABLE_RATE_LIMITED" in reasons(tight.one())


def test_control_with_a_long_retry_after_is_not_retried():
    calls: list[str] = []
    out = run([site(POSTS)], _limited_then(calls, (("Retry-After", "30"),)), policy())
    assert len(calls) == 1 and out.transport.total == 2
    assert "CONTROL_UNAVAILABLE_RATE_LIMITED" in reasons(out.one())


# 99 --------------------------------------------------------------- control page digests


def test_control_observation_keeps_name_independent_digests_of_the_control_page():
    from ultimate_username.enrichment_filters import control_digest

    def handler(request, i):
        if is_control(request):
            name = name_of(request)
            return ok(
                request,
                f"<html><head><title>{name} | Demo</title>"
                f'<meta property="og:description" content="Watch videos of {name} now">'
                f"</head><body>Not Found</body></html>",
                404,
            )
        return ok(request, page(name_of(request)))

    out = run([site()], handler)
    (observation,) = out.engine._control_cache.values()
    control = name_of(out.controls[0])
    assert control_digest(f"{control} | Demo", control) in observation.digests
    assert control_digest("Watch videos of alice now", "alice") in observation.digests
