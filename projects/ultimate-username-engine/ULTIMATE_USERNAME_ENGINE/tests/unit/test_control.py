"""Pure control-request model: names, normalization, comparison and decision tables."""

import random
import re

import pytest

from ultimate_username import control as ctl
from ultimate_username.detection import DetectionEngine
from ultimate_username.domain.models import (
    DetectionSpec,
    ExecutionState,
    IdentifierPolicy,
    Polarity,
    PredicateState,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.planning import plan_request

T, F, U = PredicateState.TRUE, PredicateState.FALSE, PredicateState.UNOBSERVED


# ---------------------------------------------------------------- name generator


@pytest.mark.parametrize("real", ["alice", "Sampler51", "x" * 30, "ab"])
def test_control_name_shape_and_length_first(real):
    name = ctl.control_name(random.Random(7), real)
    assert name is not None
    assert re.fullmatch(r"[a-z][a-z0-9]*", name)
    assert len(name) == max(len(real), 8)
    assert sum(c.isdigit() for c in name) >= min(2, len(name) - 1)
    assert not re.search(r"[a-z]{3}", name), "no word-like runs of letters"
    assert name.casefold() not in real.casefold() and real.casefold() not in name.casefold()


def test_control_name_is_deterministic_for_a_seed():
    assert ctl.control_name(random.Random(3), "alice") == ctl.control_name(
        random.Random(3), "alice"
    )
    assert ctl.control_name(random.Random(3), "alice") != ctl.control_name(
        random.Random(4), "alice"
    )


def test_control_name_never_contains_or_is_contained_in_real_name():
    for seed in range(300):
        for real in ("a1", "q9z", "k3"):
            name = ctl.control_name(random.Random(seed), real)
            assert name is None or (
                name.casefold() not in real.casefold() and real.casefold() not in name.casefold()
            )


def test_control_name_falls_back_to_other_lengths_until_pattern_matches():
    policy = IdentifierPolicy(pattern=r"[a-z0-9]{8}")
    name = ctl.control_name(random.Random(1), "alice", policy)  # tries 8 first
    assert name is not None and len(name) == 8
    narrow = IdentifierPolicy(pattern=r"[a-z0-9]{3,6}")  # 8, 14, 10 are refused, 6 passes
    name = ctl.control_name(random.Random(1), "alice", narrow)
    assert name is not None and len(name) == 6
    tiny = IdentifierPolicy(pattern=r"[a-z0-9]{3}")
    name = ctl.control_name(random.Random(1), "ab", tiny)
    assert name is not None and len(name) == 3


def test_control_name_is_at_least_eight_long_for_short_real_names():
    for real in ("a", "ab", "xyz", "bob", "alice", "bobby12"):
        for seed in range(20):
            name = ctl.control_name(random.Random(seed), real)
            assert name is not None and len(name) >= 8


def test_control_name_none_when_pattern_is_impossible():
    assert ctl.control_name(random.Random(1), "alice", IdentifierPolicy(pattern=r"[A-Z]+")) is None
    assert ctl.control_name(random.Random(1), "alice", IdentifierPolicy(pattern=r"[a-z]+")) is None


def test_control_name_respects_site_transformations():
    policy = IdentifierPolicy(lowercase=True, pattern=r"[a-z][a-z0-9]{2,15}")
    name = ctl.control_name(random.Random(2), "Alice", policy)
    assert name is not None and re.fullmatch(r"[a-z][a-z0-9]{2,15}", name)


# ---------------------------------------------------------------- normalization


def test_visible_text_strips_scripts_styles_comments_head_and_tags():
    html = (
        "<html><head><title>T</title><style>p{x:y}</style></head><body>"
        "<!-- hidden --><script>var a = 'secret';</script><noscript>enable javascript</noscript>"
        "<p>Hello <b>world</b></p></body></html>"
    )
    assert ctl.visible_text(html).split() == ["Hello", "world"]


def test_visible_text_keeps_json_as_is():
    assert ctl.visible_text('{"a": "<b>x</b>"}') == '{"a": "<b>x</b>"}'


def test_normalization_removes_name_in_all_forms():
    text = "Hello Alice! alice ALICE a%20b profile of a%20b"
    assert "alice" not in ctl.normalize_content(text, "alice")
    assert "a%20b" not in ctl.normalize_content(text, "a b")


def test_normalization_removes_volatile_tokens():
    a = (
        "<p>Welcome</p> csrf=Qk3Z9aP7mXw2LrT8vB5nYc1d token 1699999999 at 2024-05-01T10:11:12Z "
        "and 12:34:56 and 09:15"
    )
    b = (
        "<p>Welcome</p> csrf=Zz8Y1xV4cQ7bN2mK5jH9gF3s token 1700000555 "
        "at 2025-06-02T11:12:13+02:00 "
        "and 13:35:57 and 10:16"
    )
    assert ctl.normalize_content(ctl.visible_text(a), "x") == ctl.normalize_content(
        ctl.visible_text(b), "x"
    )


def test_normalization_collapses_whitespace_lowers_and_clips():
    assert ctl.normalize_content("A  \n\t B", "zz") == "a b"
    long = "x " * 30000
    assert len(ctl.normalize_content(long, "zz")) <= 40001


def test_short_names_are_removed_only_on_word_boundaries():
    assert ctl.normalize_content("table ab cab", "ab") == "table cab"


def test_normalize_title_and_url():
    assert ctl.normalize_title("<title> Profile of Alice | Site </title>", "alice") == (
        "profile of | site"
    )
    assert ctl.normalize_title("no title", "alice") == ""
    assert ctl.normalize_url("https://Example.test/u/Alice/?x=1", "alice") == "example.test/u/<n>"
    assert ctl.normalize_url("https://alice.example.test/", "alice") == "<n>.example.test"
    assert ctl.normalize_url("https://example.test/u/a%20b", "a b") == "example.test/u/<n>"


def test_similarity():
    assert ctl.similarity("a b c", "a b c") == 1.0
    assert ctl.similarity("", "") == 1.0
    assert ctl.similarity("a", "") == 0.0
    assert ctl.similarity("a b", "c d") == 0.0
    assert ctl.similarity("a a b", "a b b") == pytest.approx(2 / 3)
    assert ctl.similarity("a b c d", "a b c e") == pytest.approx(0.75)


# ---------------------------------------------------------------- facts


def resp(body="", status=200, url="https://example.test/u/alice", final=None, headers=()):
    data = body.encode() if isinstance(body, str) else body
    return TransportResponse(url, status, data, tuple(headers), final or url)


LONG = "This is a perfectly ordinary public page with plenty of descriptive text. " * 6


def test_facts_text_len_name_flags_and_js_shell():
    big = ctl.page_facts(resp("<html><body><p>" + LONG + "</p></body></html>"), "alice")
    assert big.text_len >= 200 and not big.js_shell and not big.name_in_text
    named = ctl.page_facts(resp("<html><title>x</title><body>hi Alice</body></html>"), "alice")
    assert named.name_in_text and not named.name_in_title and named.js_shell  # thin text
    titled = ctl.page_facts(resp("<html><title>Alice</title><body>hi</body></html>"), "alice")
    assert not titled.name_in_text and titled.name_in_title and titled.js_shell
    empty = ctl.page_facts(resp("<html><body><div id='root'></div></body></html>"), "alice")
    assert empty.js_shell and empty.text_len == 0


def test_facts_name_in_json_ignores_url_echo():
    echo = ctl.page_facts(resp('{"url": "https://example.test/u/alice"}'), "alice")
    assert not echo.name_in_text and not echo.name_in_title
    real = ctl.page_facts(resp('{"username": "alice", "bio": "hi"}'), "alice")
    assert real.name_in_text


def test_facts_js_shell_marker_with_empty_root():
    html = (
        "<html><body><noscript>You need to enable JavaScript to run this app. "
        + "x " * 150
        + "</noscript><div id='root'></div></body></html>"
    )
    assert ctl.page_facts(resp(html), "alice").js_shell


def test_facts_final_url_and_redirect_away():
    away = ctl.page_facts(
        resp("<html></html>", url="https://example.test/u/alice", final="https://example.test/"),
        "alice",
    )
    assert away.redirects_away and away.final == "example.test"
    stay = ctl.page_facts(resp("x"), "alice")
    assert not stay.redirects_away and stay.final == "example.test/u/<n>"
    moved = ctl.page_facts(
        resp("", 302, headers=(("Location", "/login"),), url="https://example.test/u/alice"),
        "alice",
    )
    assert moved.redirects_away and moved.final == "example.test/login"


@pytest.mark.parametrize(
    "text",
    [
        "Your account has been suspended",
        "This account was deleted by the owner",
        "this account is banned",
        "User is banned",
        "Suspended account",
        "Account locked",
        "user has been removed",
        "Konto zostało usunięte",
        "To konto jest obecnie zablokowane",
        "Konto zawieszone",
        "Аккаунт пользователя удалён",
        "Профиль пользователя заблокирован",
        "탈퇴한 회원입니다",
        "정지된 계정입니다",
        "该账号异常，无法访问",
        "此帐号已注销",
        "このアカウントは凍結されています",
        "Dieses Konto gesperrt",
        "Esta cuenta suspendida",
        "Ce compte suspendu",
        "Esta conta suspensa",
        "locked: yes",
    ],
)
def test_account_state_signatures_match(text):
    assert ctl.account_signature("", text, "")


def test_account_state_signature_in_title_and_html_marker_and_negatives():
    assert ctl.account_signature("Account suspended | Site", "", "")
    assert ctl.account_signature("", "", '<div class="centralauth-admin-info-locked">')
    assert not ctl.account_signature("Alice - profile", "Alice posts about gardening.", "")
    assert not ctl.account_signature("", "x " * 5000 + "account has been suspended", "")


def test_facts_carry_signature():
    page = resp("<html><title>Alice</title><body>This account has been suspended.</body></html>")
    assert ctl.page_facts(page, "alice").signature


# ---------------------------------------------------------------- rule outcome / classes

STATUS_OK = Rule("status", statuses=tuple(range(200, 300)))


def site(present, absent, **kw):
    spec = DetectionSpec(present, absent)
    return SiteDefinition("s", "S", "https://example.test/u/{username}", spec, **kw)


def detect(definition, body="", status=200):
    plan = plan_request("alice", definition, "t")
    response = TransportResponse(plan.request.url, status, body.encode(), (), plan.request.url)
    engine = DetectionEngine()
    return engine.detect(response, plan), ctl.rule_outcome(engine, response, plan)


def klass(definition, body="", status=200):
    result, rules = detect(definition, body, status)
    return ctl.classify_unknown(result, rules)


NOT_FOUND_404 = Rule("status", statuses=(404,))


def test_classes():
    status_only = site(STATUS_OK, NOT_FOUND_404)
    assert klass(status_only, "x", 200) == "A"  # WEAK_STATUS_ONLY_DEFINITION
    assert klass(site(Rule("message", "hello"), NOT_FOUND_404), "hello", 200) == "A"
    assert klass(site(Rule("message", "member"), Rule("message", "gone")), "other", 200) == "B"
    assert klass(site(Rule("message", "member"), Rule("message", "gone")), "other", 404) == "B"
    assert klass(site(Rule("message", "member"), Rule("message", "gone")), "", 301) == "B"
    assert klass(site(STATUS_OK, NOT_FOUND_404), "x", 404) == "C"
    assert klass(site(STATUS_OK, Rule("message", "gone")), "gone", 200) == "D"
    assert klass(site(Rule("message", "member"), Rule("message", "gone")), "member gone") == "D"
    assert klass(site(STATUS_OK, NOT_FOUND_404), "x", 403) == ""  # execution error, not OK


def test_classes_exclude_decided_and_gated_results():
    both = site(Rule("message", "member"), Rule("message", "gone"))
    assert klass(both, "gone", 404) == ""  # explicit NOT_FOUND
    bound = DetectionSpec(
        Rule("message", "owner={username}"),
        Rule("message", "gone"),
        Rule("message", "owner={username}"),
    )
    plan_site = SiteDefinition("s", "S", "https://example.test/u/{username}", bound)
    result, rules = detect(plan_site, "owner=alice", 200)
    assert result.verdict == Verdict.FOUND and ctl.classify_unknown(result, rules) == ""
    redirected = site(Rule("message", "member"), Rule("message", "gone"))
    plan = plan_request("alice", redirected, "t")
    response = TransportResponse(plan.request.url, 200, b"x", (), "https://example.test/")
    engine = DetectionEngine()
    detection = engine.detect(response, plan)
    assert detection.response_class == "REDIRECT_ONLY"
    assert ctl.classify_unknown(detection, ctl.rule_outcome(engine, response, plan)) == ""


def test_rule_outcome_leaf_kinds():
    _, rules = detect(site(STATUS_OK, Rule("message", "gone")), "gone", 200)
    assert rules.present == T and rules.absent == T
    assert rules.present_status_only and not rules.absent_status_only
    assert rules.absent_content and not rules.present_content
    _, rules = detect(site(STATUS_OK, NOT_FOUND_404), "x", 404)
    assert rules.present == F and rules.absent == T and rules.absent_status_only
    assert not rules.absent_content
    _, rules = detect(site(Rule("message", "member"), None), "member", 200)
    assert rules.present == T and rules.present_content and not rules.present_status_only
    assert rules.absent == F and not rules.absent_status_only


def test_rule_outcome_handles_detector_failure():
    broken = site(Rule("regex", "("), None)
    plan = plan_request("alice", broken, "t")
    response = TransportResponse(plan.request.url, 200, b"x", (), plan.request.url)
    assert ctl.rule_outcome(DetectionEngine(), response, plan) is None


# ---------------------------------------------------------------- comparison


def facts(**kw):
    base = dict(
        status=200,
        final="example.test/u/<n>",
        title="t",
        length=1000,
        words={"a": 10, "b": 10},
        text_len=1000,
        name_in_text=True,
    )
    base.update(kw)
    return ctl.PageFacts(**base)


def rules(present=T, absent=F, **kw):
    base = dict(
        present_content=False,
        absent_content=False,
        present_status_only=True,
        absent_status_only=True,
    )
    base.update(kw)
    return ctl.RuleOutcome(present, absent, **base)


def observation(f=None, r=None):
    return ctl.ControlObservation(f or facts(), r or rules(), "k3x9q", 11)


def compare(real=None, rr=None, control=None):
    return ctl.compare(real or facts(), rr or rules(), control)


def test_compare_unavailable_when_no_control():
    assert compare(control=None).kind == ctl.CONTROL_UNAVAILABLE


def test_compare_identical():
    cmp = compare(control=observation())
    assert cmp.kind == ctl.CONTROL_IDENTICAL and cmp.similarity == 1.0 and cmp.diffs == ()


@pytest.mark.parametrize(
    ("change", "diff"),
    [
        ({"status": 404}, "status"),
        ({"final": "example.test"}, "url"),
        ({"title": "other"}, "title"),
    ],
)
def test_compare_strong_on_status_url_or_title(change, diff):
    cmp = compare(control=observation(facts(**change)))
    assert cmp.kind == ctl.CONTROL_DIFFERS_STRONG and diff in cmp.diffs


def test_compare_strong_when_catalog_rule_judges_control_differently():
    cmp = compare(control=observation(r=rules(present=F, absent=T)))
    assert cmp.kind == ctl.CONTROL_IDENTICAL  # identical pages: rules alone do not matter
    cmp = compare(control=observation(facts(words={"a": 10, "b": 4}), rules(present=F)))
    assert cmp.kind == ctl.CONTROL_DIFFERS_STRONG and "rule" in cmp.diffs


def test_compare_weak_on_length_or_similarity_only():
    cmp = compare(control=observation(facts(length=2000)))
    assert cmp.kind == ctl.CONTROL_DIFFERS_WEAK and "length" in cmp.diffs
    cmp = compare(control=observation(facts(words={"a": 10, "c": 10})))
    assert cmp.kind == ctl.CONTROL_DIFFERS_WEAK and "similarity" in cmp.diffs


def test_compare_absent_like_strict_and_control_present_miss_are_separate():
    for change in ({"status": 404}, {"status": 410}, {"redirects_away": True}):
        assert compare(control=observation(facts(**change))).absent_like_strict
    assert compare(control=observation(r=rules(absent=T))).absent_like_strict
    quiet = compare(control=observation(r=rules(present=F)))
    assert not quiet.absent_like_strict and quiet.control_present_miss
    assert quiet.absent_like_a
    plain = compare(control=observation(facts(title="other")))
    assert not plain.absent_like_strict and not plain.control_present_miss
    assert not plain.absent_like_a


def test_compare_control_found_by_rule():
    assert compare(control=observation()).control_rule_found
    assert not compare(control=observation(r=rules(absent=T))).control_rule_found
    assert not compare(control=observation(r=rules(present=F))).control_rule_found


# ---------------------------------------------------------------- decisions


def decide(klass_, real=None, rr=None, control=None, flags=None):
    real = real or facts()
    rr = rr or rules()
    cmp = ctl.compare(real, rr, control)
    return ctl.decide_with_control(klass_, real, rr, cmp, flags or ctl.ControlFlags())


STRONG_ABSENT = lambda: observation(facts(status=404, title="", length=10, words={}))  # noqa: E731


def test_class_a_unavailable_and_identical():
    d = decide("A", control=None)
    assert d.verdict == Verdict.UNKNOWN and d.reasons[0] == ctl.CONTROL_UNAVAILABLE
    d = decide("A", control=observation())
    assert d.verdict == Verdict.UNKNOWN and d.reasons[0] == ctl.CONTROL_IDENTICAL
    # control also "found" by the rule and textually near-identical, though the title differs
    d = decide("A", control=observation(facts(title="other")))
    assert d.verdict == Verdict.UNKNOWN and d.reasons[0] == ctl.CONTROL_IDENTICAL


def test_class_a_found_needs_content_leaf_absent_like_control_and_substance():
    content = rules(present_content=True, present_status_only=False)
    d = decide("A", rr=content, control=STRONG_ABSENT())
    assert (d.verdict, d.strength, d.level) == (Verdict.FOUND, "MODERATE", 2)
    assert d.reasons[0] == ctl.CONTROL_DIFFERS_STRONG


def test_class_a_status_only_is_probable_not_found():
    d = decide("A", control=STRONG_ABSENT())
    assert (d.verdict, d.strength, d.level) == (Verdict.PROBABLE, "MODERATE", 2)


def test_class_a_empty_shell_is_never_positive():
    shell = facts(text_len=0, name_in_text=False, name_in_title=False, js_shell=True)
    for rr in (rules(), rules(present_content=True, present_status_only=False)):
        d = decide("A", real=shell, rr=rr, control=STRONG_ABSENT())
        assert d.verdict == Verdict.UNKNOWN and ctl.NOT_SUBSTANTIVE in d.reasons


CONTENT_LEAF = dict(present_content=True, present_status_only=False)


def test_class_a_script_heavy_modern_profile_with_some_text_is_found():
    """A page with 12 <script> tags and 600 chars of text is no longer a 'shell' in class A."""
    body = LONG[:600]
    html = "<html><body><p>" + body + "</p>" + "<script>var a=1;</script>" * 12 + "</body></html>"
    real = ctl.page_facts(resp(html), "alice")
    assert 200 <= real.text_len < 1500  # js_shell (if any) no longer matters for class A
    d = decide("A", real=real, rr=rules(**CONTENT_LEAF), control=STRONG_ABSENT())
    assert (d.verdict, d.reasons[0]) == (Verdict.FOUND, ctl.CONTROL_DIFFERS_STRONG)


def test_class_a_js_shell_flag_is_irrelevant_when_text_is_substantive():
    real = facts(js_shell=True, text_len=600, name_in_text=False)
    d = decide("A", real=real, rr=rules(**CONTENT_LEAF), control=STRONG_ABSENT())
    assert d.verdict == Verdict.FOUND


def test_class_a_content_leaf_name_in_title_without_text_is_found():
    real = facts(js_shell=True, text_len=0, name_in_text=False, name_in_title=True)
    d = decide("A", real=real, rr=rules(**CONTENT_LEAF), control=STRONG_ABSENT())
    assert (d.verdict, d.reasons[0]) == (Verdict.FOUND, ctl.CONTROL_DIFFERS_STRONG)


def test_class_a_status_only_name_only_in_title_is_not_substantive():
    """Deleted account: bare 200 page titled with the name, while a missing name is a 404."""
    real = facts(js_shell=True, text_len=15, name_in_text=False, name_in_title=True)
    d = decide("A", real=real, rr=rules(), control=STRONG_ABSENT())
    assert d.verdict == Verdict.UNKNOWN and ctl.NOT_SUBSTANTIVE in d.reasons


def test_class_a_status_only_long_text_without_name_is_probable():
    real = facts(js_shell=True, text_len=600, name_in_text=False, name_in_title=False)
    d = decide("A", real=real, rr=rules(), control=STRONG_ABSENT())
    assert (d.verdict, d.strength, d.level) == (Verdict.PROBABLE, "MODERATE", 2)


def test_class_a_status_only_short_text_with_name_in_text_is_probable():
    real = facts(js_shell=True, text_len=30, name_in_text=True)
    assert decide("A", real=real, rr=rules(), control=STRONG_ABSENT()).verdict == Verdict.PROBABLE


def test_class_a_content_leaf_without_text_name_or_title_is_not_substantive():
    real = facts(js_shell=True, text_len=10, name_in_text=False, name_in_title=False)
    d = decide("A", real=real, rr=rules(**CONTENT_LEAF), control=STRONG_ABSENT())
    assert d.verdict == Verdict.UNKNOWN and ctl.NOT_SUBSTANTIVE in d.reasons


def test_class_a_account_state_signature_still_wins():
    real = facts(signature="account suspended", text_len=600)
    d = decide(
        "A",
        real=real,
        rr=rules(**CONTENT_LEAF),
        control=STRONG_ABSENT(),
        flags=ctl.ControlFlags(signatures=True),
    )
    assert d.reasons == (ctl.ACCOUNT_STATE_SIGNATURE,)


def test_class_a_strong_with_control_hit_needs_low_similarity_and_content_leaf():
    content = rules(present_content=True, present_status_only=False)
    far = observation(facts(title="other", words={"c": 10, "d": 10}))
    d = decide("A", rr=content, control=far)
    assert d.verdict == Verdict.PROBABLE and d.strength == "WEAK" and d.level == 2
    near = observation(facts(title="other", words={"a": 10, "c": 10}))  # similarity 0.5
    d = decide("A", rr=content, control=near)
    assert d.verdict == Verdict.UNKNOWN and d.reasons == (ctl.CONTROL_NONDISCRIMINATING,)
    d = decide("A", control=far)  # status-only rule: no content leaf
    assert d.verdict == Verdict.UNKNOWN and d.reasons == (ctl.CONTROL_NONDISCRIMINATING,)


def test_class_a_control_that_misses_the_present_rule_is_absent_like():
    content = rules(present_content=True, present_status_only=False)
    quiet = observation(facts(title="other", words={"a": 10, "c": 10}), rules(present=F))
    d = decide("A", rr=content, control=quiet)
    assert (d.verdict, d.level) == (Verdict.FOUND, 2)
    d = decide("A", control=quiet)
    assert d.verdict == Verdict.PROBABLE and d.strength == "MODERATE"


def test_class_a_weak_difference_with_control_hit_is_nondiscriminating():
    weak = observation(facts(words={"a": 10, "c": 10}))
    for rr in (rules(present_content=True, present_status_only=False), rules()):
        d = decide("A", rr=rr, control=weak)
        assert d.verdict == Verdict.UNKNOWN and d.reasons == (ctl.CONTROL_NONDISCRIMINATING,)


def test_class_a_account_state_signature_wins_over_everything():
    deleted = facts(signature="account has been suspended")
    d = decide("A", real=deleted, control=STRONG_ABSENT())
    assert d.verdict == Verdict.UNKNOWN and d.reasons[0] == ctl.ACCOUNT_STATE_SIGNATURE
    assert ctl.signature_decision("A", deleted, ctl.ControlFlags()) is not None
    assert ctl.signature_decision("A", facts(), ctl.ControlFlags()) is None
    assert ctl.signature_decision("A", deleted, ctl.ControlFlags(signatures=False)) is None
    assert ctl.signature_decision("B", deleted, ctl.ControlFlags()) is None


def test_class_a_flag_off_never_positive():
    d = decide("A", control=STRONG_ABSENT(), flags=ctl.ControlFlags(found=False))
    assert d.verdict == Verdict.UNKNOWN


def test_class_b_identical_absence():
    for status, level in ((200, 1), (404, 2), (410, 2)):
        real = facts(status=status)
        d = decide("B", real=real, rr=rules(present=F), control=observation(real))
        assert d.verdict == Verdict.NOT_FOUND, status
        assert d.reasons[0] == ctl.CONTROL_IDENTICAL_ABSENCE and d.strength == "COMPOSITE"
        assert d.level == level, status
    away = facts(status=302, final="example.test/login", redirects_away=True, js_shell=True)
    d = decide("B", real=away, rr=rules(present=F), control=observation(away))
    assert d.verdict == Verdict.NOT_FOUND


def test_class_b_js_shell_identical_is_unknown():
    shell = facts(js_shell=True, text_len=0)
    d = decide("B", real=shell, rr=rules(present=F), control=observation(shell))
    assert d.verdict == Verdict.UNKNOWN
    assert d.reasons[:2] == (ctl.CONTROL_IDENTICAL, ctl.JS_SHELL)


def test_class_b_identical_redirect_to_profile_is_not_absence():
    to_profile = facts(status=302, final="example.test/u/<n>", js_shell=True)
    d = decide("B", real=to_profile, rr=rules(present=F), control=observation(to_profile))
    assert d.verdict == Verdict.UNKNOWN


def test_class_b_stale_rule_needs_strict_absent_like_control():
    real = facts(name_in_text=True)
    quiet = observation(facts(title="other", words={"c": 10, "d": 10}), rules(present=F))
    assert ctl.compare(real, rules(present=F), quiet).control_present_miss
    d = decide("B", real=real, rr=rules(present=F), control=quiet)
    assert d.verdict == Verdict.UNKNOWN and d.reasons[0] == ctl.CONTROL_INCONCLUSIVE
    redirected = observation(facts(redirects_away=True, title="other"), rules(present=F))
    d = decide("B", real=real, rr=rules(present=F), control=redirected)
    assert d.verdict == Verdict.PROBABLE


def test_class_b_stale_rule_probable():
    real = facts(name_in_text=True)
    d = decide("B", real=real, rr=rules(present=F), control=STRONG_ABSENT())
    assert d.verdict == Verdict.PROBABLE and d.reasons[0] == ctl.CONTROL_DIFFERS_STALE_RULE
    assert d.strength == "WEAK" and d.level == 1


@pytest.mark.parametrize(
    "change",
    [
        {"name_in_text": False},
        {"text_len": 50},
        {"js_shell": True},
        {"status": 301},
        {"status": 404},
        {"signature": "account has been suspended"},
    ],
)
def test_class_b_stale_rule_requires_all_conditions(change):
    real = facts(**change)
    d = decide("B", real=real, rr=rules(present=F), control=STRONG_ABSENT())
    assert d.verdict == Verdict.UNKNOWN
    if "signature" in change:
        assert d.reasons[0] == ctl.ACCOUNT_STATE_SIGNATURE


def test_class_b_unavailable_and_flags():
    d = decide("B", rr=rules(present=F), control=None)
    assert d.verdict == Verdict.UNKNOWN and d.reasons[0] == ctl.CONTROL_UNAVAILABLE
    real = facts()
    off = ctl.ControlFlags(absence=False, stale_rule=False)
    d = decide("B", real=real, rr=rules(present=F), control=observation(real), flags=off)
    assert d.verdict == Verdict.UNKNOWN
    d = decide("B", rr=rules(present=F), control=STRONG_ABSENT(), flags=off)
    assert d.verdict == Verdict.UNKNOWN


def test_requests_wanted_follows_flags():
    on = ctl.ControlFlags()
    assert ctl.wants_request("A", on) and ctl.wants_request("B", on)
    assert not ctl.wants_request("C", on) and not ctl.wants_request("", on)
    assert not ctl.wants_request("A", ctl.ControlFlags(found=False))
    assert ctl.wants_request("B", ctl.ControlFlags(absence=False))
    assert not ctl.wants_request("B", ctl.ControlFlags(absence=False, stale_rule=False))


# ---------------------------------------------------------------- C and D (no request)


def test_class_c_needs_donor_verified_control_and_same_host_404():
    only_status = rules(present=F, absent=T)
    ok = ctl.decide_no_request(
        "C",
        only_status,
        404,
        "https://example.test/u/alice",
        "https://example.test/u/alice",
        True,
        ctl.ControlFlags(),
    )
    assert ok is not None and ok.verdict == Verdict.NOT_FOUND
    assert ok.reasons[0] == ctl.STATUS_ABSENCE_DONOR_VERIFIED
    assert (ok.strength, ok.level) == ("COMPOSITE", 1)


@pytest.mark.parametrize(
    ("status", "final", "donor", "absent_status_only", "flags"),
    [
        (404, "https://example.test/u/alice", False, True, ctl.ControlFlags()),
        (403, "https://example.test/u/alice", True, True, ctl.ControlFlags()),
        (404, "https://other.test/u/alice", True, True, ctl.ControlFlags()),
        (404, "https://example.test/", True, True, ctl.ControlFlags()),
        (404, "https://example.test/u/alice", True, False, ctl.ControlFlags()),
        (404, "https://example.test/u/alice", True, True, ctl.ControlFlags(status_absence=False)),
    ],
)
def test_class_c_stays_unknown_otherwise(status, final, donor, absent_status_only, flags):
    r = rules(present=F, absent=T, absent_status_only=absent_status_only)
    got = ctl.decide_no_request("C", r, status, final, "https://example.test/u/alice", donor, flags)
    assert got is None


def test_class_d_content_absence_overrides_status_presence():
    r = rules(present=T, absent=T, absent_content=True, absent_status_only=False)
    d = ctl.decide_no_request("D", r, 200, "u", "u", False, ctl.ControlFlags())
    assert d.verdict == Verdict.NOT_FOUND and d.reasons[0] == ctl.ABSENCE_CONTENT_OVERRIDES_STATUS
    assert (d.strength, d.level) == ("COMPOSITE", 2)
    keep = rules(
        present=T, absent=T, present_content=True, present_status_only=False, absent_content=True
    )
    assert ctl.decide_no_request("D", keep, 200, "u", "u", False, ctl.ControlFlags()) is None
    status_absent = rules(present=T, absent=T, absent_content=False)
    assert (
        ctl.decide_no_request("D", status_absent, 200, "u", "u", False, ctl.ControlFlags()) is None
    )
    flag_off = ctl.ControlFlags(content_override=False)
    assert ctl.decide_no_request("D", r, 200, "u", "u", False, flag_off) is None


# ---------------------------------------------------------------- applying a decision


def test_apply_decision_adds_evidence_signal_and_keeps_invariants():
    result, _ = detect(site(STATUS_OK, NOT_FOUND_404), "x", 200)
    assert result.verdict == Verdict.UNKNOWN
    decision = decide("A", control=STRONG_ABSENT())
    updated = ctl.apply_decision(result, decision, {"kind": "CONTROL_DIFFERS_STRONG", "seed": 11})
    assert updated.verdict == Verdict.PROBABLE and updated.state == ExecutionState.OK
    assert updated.reasons == (ctl.CONTROL_DIFFERS_STRONG,)
    assert updated.evidence_level == 2 and updated.confidence.strength == "MODERATE"
    assert updated.evidence[-1].rule_id == "control"
    assert updated.evidence[-1].strategy == "control_request"
    assert updated.evidence[-1].polarity == Polarity.PRESENT
    assert updated.evidence[-1].state == PredicateState.TRUE
    assert '"seed": 11' in updated.evidence[-1].observed
    signal = updated.signals[-1]
    assert signal.source == "control_request" and signal.independence_group == "control"
    assert signal.kind == ctl.CONTROL_DIFFERS_STRONG
    assert len(updated.evidence) == len(result.evidence) + 1


def test_apply_unknown_decision_keeps_original_reasons_and_context_polarity():
    result, _ = detect(site(STATUS_OK, NOT_FOUND_404), "x", 200)
    decision = decide("A", control=None)
    updated = ctl.apply_decision(result, decision, {"kind": ctl.CONTROL_UNAVAILABLE})
    assert updated.verdict == Verdict.UNKNOWN
    assert updated.reasons == (ctl.CONTROL_UNAVAILABLE, *result.reasons)
    assert updated.evidence[-1].polarity == Polarity.CONTEXT
    assert updated.confidence == result.confidence


def test_apply_not_found_has_absent_polarity():
    result, _ = detect(site(STATUS_OK, NOT_FOUND_404), "x", 404)
    d = ctl.decide_no_request(
        "C",
        rules(present=F, absent=T),
        404,
        "https://e.test/a",
        "https://e.test/a",
        True,
        ctl.ControlFlags(),
    )
    updated = ctl.apply_decision(result, d, {"kind": d.reasons[0]})
    assert updated.verdict == Verdict.NOT_FOUND
    assert updated.evidence[-1].polarity == Polarity.ABSENT
    assert updated.response_class == "NOT_FOUND"


# ---------------------------------------------------------------- review fixes: signatures


@pytest.mark.parametrize(
    "html",
    [
        "<p>This account<br>\n  has\n been&nbsp;suspended.</p>",
        "<p>This&nbsp;account&nbsp;has&nbsp;been&nbsp;suspended.</p>",
        "<p>This\u00a0account\u00a0was\u00a0deleted</p>",
        "<nav>" + "&nbsp;\n" * 1500 + "</nav><p>Account suspended</p>",
        "<div>" + "\n \t" * 1500 + "</div><p>User banned</p>",
        "<p>User <b>alice</b> has been deleted.</p>",
        "<p>The account <i>alice</i> has been suspended.</p>",
        "<p>Account 'alice' was banned</p>",
        "<p>Konto  użytkownika\nalice zostało usunięte</p>",
        "<p>Аккаунт\nпользователя  удалён</p>",
        "<p>탈퇴한\n회원입니다</p>",
        "<p>该账号<b>异常</b>，无法访问</p>",
        "<p>此帐号已<b>注销</b></p>",
        "<p>このアカウントは<br>凍結されています</p>",
        "<p>Das Konto  wurde gelöscht</p>",
        "<p>Esta cuenta ha sido suspendida</p>",
    ],
)
def test_account_signature_survives_markup_whitespace_and_entities(html):
    assert ctl.page_facts(resp(html), "alice").signature
    assert ctl.account_signature("", ctl.visible_text(html), html)


def test_account_signature_title_is_unescaped_and_window_is_measured_after_collapse():
    assert ctl.account_signature("Account&nbsp;suspended | Site", "", "")
    assert ctl.account_signature("A", "Account\u00a0\u00a0suspended", "")
    words = " ".join(["word"] * 1000)
    assert not ctl.account_signature("", words + " account has been suspended", "")


def test_account_signature_has_no_false_positive_on_ordinary_pages():
    text = "Alice manages her account settings. The user guide explains how to delete posts."
    assert not ctl.account_signature("Alice", text, "")
    assert not ctl.account_signature("", "The account page lists users who were removed", "")


# ---------------------------------------------------------------- review fixes: JS shells

SHELL_TITLE = (
    "<html><head><title>alice - Site</title></head><body>"
    '<div id="root"></div><script src="/app.js"></script></body></html>'
)


def test_shell_with_name_only_in_title_is_not_named():
    facts_ = ctl.page_facts(resp(SHELL_TITLE), "alice")
    assert facts_.js_shell and not facts_.name_in_text and facts_.name_in_title


@pytest.mark.parametrize(
    "html",
    [
        '<html><body><div id="__next"></div><script id="__NEXT_DATA__" type="application/json">'
        '{"props":{}}</script></body></html>',
        '<html><body><p>Loading</p><script>window.__INITIAL_STATE__={"a":1}</script></body></html>',
        "<html><body><script>window.__NUXT__={}</script><p>Hello Alice</p></body></html>",
        "<html><body><script>window.__APOLLO_STATE__={}</script><p>Hello Alice</p></body></html>",
        '<html><body><div id="app"><p>Hello Alice, a short intro.</p></div>'
        '<script src="/bundle.js"></script></body></html>',
        '<html><body><div class="x" id="___gatsby"><p>Hi Alice</p></div>'
        '<script src="/a.js"></script></body></html>',
    ],
)
def test_js_shell_is_detected_by_framework_markers(html):
    got = ctl.page_facts(resp(html), "alice")
    assert got.js_shell


def test_rich_server_rendered_page_with_markers_is_not_a_shell():
    html = (
        '<html><body><div id="__next"><p>' + LONG * 40 + "</p></div>"
        '<script id="__NEXT_DATA__" type="application/json">{}</script></body></html>'
    )
    got = ctl.page_facts(resp(html), "alice")
    assert not got.js_shell and got.text_len >= 200
    plain = '<html><body><div id="app"><p>' + LONG + "</p></div></body></html>"
    assert ctl.page_facts(resp(plain), "alice").text_len >= 200


def test_class_b_identical_2xx_on_a_marker_shell_is_unknown():
    shell = ctl.page_facts(resp(SHELL_TITLE), "alice")
    d = decide("B", real=shell, rr=rules(present=F), control=observation(shell))
    assert d.verdict == Verdict.UNKNOWN and d.reasons[:2] == (ctl.CONTROL_IDENTICAL, ctl.JS_SHELL)


# ---------------------------------------------------------------- review fixes: performance


@pytest.mark.parametrize(
    "body",
    [
        "<script>" * 25_000,
        "<svg>" * 25_000 + "x",
        "<style>" * 30_000,
        "<noscript>" * 15_000,
        "<template>" * 15_000,
        "<!--" * 50_000,
        "<head>" * 25_000,
        "<title>" * 20_000,
        "<div " * 30_000,
        "<div id=" * 20_000,
        "a < b " * 20_000,
        "<a " * 40_000,
        "<body>" + " " * 200_000,
        "<div>" * 100_000,
        "<html>" + "x" * 300_000,
    ],
    ids=lambda v: v[:12],
)
def test_page_facts_is_fast_on_hostile_markup(body):
    import time

    started = time.perf_counter()
    ctl.page_facts(resp(body), "alice")
    assert time.perf_counter() - started < 0.5


def test_raw_text_is_clipped_before_processing():
    head = "<html><body><p>start</p>"
    middle = "<p>middle marker words</p>" * 20_000
    tail = "<p>the very end</p></body></html>"
    got = ctl.page_facts(resp(head + middle + tail), "alice")
    assert got.words.get("start") and got.words.get("end")
    assert sum(got.words.values()) < 40_000


# ---------------------------------------------------------------- review fixes: CJK


def test_similarity_of_cjk_pages_uses_character_bigrams():
    base = "这是一个关于园艺和花卉种植的公开页面，作者分享了许多关于土壤和浇水的实用经验。" * 6
    a = base + " 访问次数 123 次，最新文章：春天的玫瑰。"
    b = base + " 访问次数 456 次，最新文章：夏天的牡丹。"
    assert ctl.similarity(a, b) >= ctl.SIMILARITY_IDENTICAL
    other = "完全不同的内容，讲述的是关于编程语言和数据库设计的技术文章，包含大量代码示例。" * 6
    assert ctl.similarity(a, other) < 0.5
    assert ctl.similarity("日本語のページ", "日本語のぺーじ") > 0.3
    assert ctl.similarity("한국어 페이지", "한국어 페이지") == 1.0
    assert ctl.similarity("mixed 中文 text", "mixed 中文 text") == 1.0


# ---------------------------------------------------------------- tuning: badge signature


@pytest.mark.parametrize(
    "text",
    [
        "Zelvarocks Banned 0 Posts 0 Followers",
        "Home Explore Zelvarocks suspended 0 Posts",
        "zelvarocks: Deactivated · joined 2020",
        "Banned Zelvarocks 0 Posts",
        "ZELVAROCKS   zablokowany 0 wpisów",
        "Zelvarocks заблокирован 0 постов",
        "Zelvarocks 封禁 0",
        "Zelvarocks 凍結 0",
        "Zelvarocks 정지 0",
    ],
)
def test_badge_signature_next_to_the_name(text):
    assert ctl.account_signature("", text, "", "zelvarocks")


@pytest.mark.parametrize(
    "text",
    [
        "Zelvarocks 0 Posts. I got banned once from chess, long story about it all.",
        "Zelvarocks plays chess. " + "filler word " * 30 + "someone else got banned here",
        "Zelvarocks writes about unbanned players",
        "spammer99 Banned 0 Posts of note. Zelvarocks says hello to everybody on the page",
        "Zelvarocks Posts 12 Followers 3",
    ],
)
def test_badge_signature_requires_adjacency_and_a_standalone_word(text):
    assert not ctl.account_signature("", text, "", "zelvarocks")


def test_badge_signature_needs_the_name_argument():
    assert not ctl.account_signature("", "Zelvarocks Banned 0 Posts")
    assert not ctl.account_signature("", "Zelvarocks Banned 0 Posts", "", "")


def test_badge_signature_other_banned_user_in_comments_is_not_the_account():
    page = (
        "Zelvarocks 120 Posts 40 Followers. Recent comments: spammer99 Banned 3 Posts "
        + "nice game " * 20
    )
    assert not ctl.account_signature("", page, "", "zelvarocks")


JSON_BANNED = '{"id":"7","username":"zelvarocks","display":"Chira","is_banned":true}'


def test_json_banned_flag_near_the_name_key():
    assert ctl.account_signature("", "", JSON_BANNED, "zelvarocks")
    assert ctl.account_signature("", "", JSON_BANNED, "ZelvaRocks")
    reverse = '{"suspended": true,"x":1,"screen_name":"zelvarocks"}'
    assert ctl.account_signature("", "", reverse, "zelvarocks")
    escaped = "{&quot;preferredUsername&quot;:&quot;zelvarocks&quot;,&quot;deleted&quot;:true}"
    assert ctl.account_signature("", "", escaped, "zelvarocks")


def test_json_banned_false_or_far_or_foreign_does_not_match():
    assert not ctl.account_signature("", "", JSON_BANNED.replace("true", "false"), "zelvarocks")
    far = '{"username":"zelvarocks","pad":"' + "x" * 500 + '","banned":true}'
    assert not ctl.account_signature("", "", far, "zelvarocks")
    other = '{"username":"someoneelse","banned":true}'
    assert not ctl.account_signature("", "", other, "zelvarocks")
    assert not ctl.account_signature("", "", '{"banned":true}', "zelvarocks")


def test_page_facts_passes_the_name_to_the_signature():
    assert ctl.page_facts(resp("<p>Zelvarocks Banned 0 Posts</p>"), "zelvarocks").signature
    assert not ctl.page_facts(resp("<p>Zelvarocks Banned 0 Posts</p>"), "other").signature
    assert ctl.page_facts(
        resp('<script>{"username":"alice","is_banned":true}</script>'), "alice"
    ).signature
    ok = '<script>{"username":"alice","is_banned":false}</script><p>' + LONG + "</p>"
    assert not ctl.page_facts(resp(ok), "alice").signature


# ---------------------------------------------------------------- tuning: heavy script shell


def heavy_page(visible_chars=400, scripts=1, blob=300_000):
    text = ("Some public sentence about nothing in particular. " * 20)[:visible_chars]
    data = '{"a":"' + "q " * (blob // 2) + '"}'
    return (
        "<html><head><title>Site</title></head><body><p>"
        + text
        + "</p>"
        + f"<script>var ytInitialData={data};</script>" * scripts
        + "</body></html>"
    )


def test_heavy_page_with_little_visible_text_is_a_shell():
    got = ctl.page_facts(resp(heavy_page()), "alice")
    assert got.js_shell


def test_heavy_page_with_several_scripts_below_1500_chars_is_a_shell():
    got = ctl.page_facts(resp(heavy_page(visible_chars=1000, scripts=6, blob=10_000)), "alice")
    assert got.js_shell


def test_large_page_with_real_text_is_not_a_shell():
    text = "Real readable paragraph with plenty of words in it. " * 400
    html = "<html><body><p>" + text + "</p><script>" + "z " * 5_000 + "</script></body></html>"
    got = ctl.page_facts(resp(html), "alice")
    assert not got.js_shell and got.text_len >= 200


def test_large_json_is_never_a_heavy_shell():
    body = '{"items":[' + ",".join('{"k":"%s"}' % ("v" * 8) for _ in range(8000)) + "]}"
    assert not ctl.page_facts(resp(body), "alice").js_shell


def test_class_b_identical_2xx_on_a_heavy_shell_is_unknown_not_absent():
    shell = ctl.page_facts(resp(heavy_page()), "alice")
    d = decide("B", real=shell, rr=rules(present=F), control=observation(shell))
    assert d.verdict == Verdict.UNKNOWN and d.reasons[:2] == (ctl.CONTROL_IDENTICAL, ctl.JS_SHELL)


def test_class_b_identical_404_stays_absence_level_2():
    gone = facts(status=404, js_shell=True, text_len=0)
    d = decide("B", real=gone, rr=rules(present=F), control=observation(gone))
    assert d.verdict == Verdict.NOT_FOUND and d.level == 2
