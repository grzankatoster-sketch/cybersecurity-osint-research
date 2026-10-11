"""F3.1 health ranking: judge, health.json, quality points, selection, passive, probe, CLI."""

import asyncio
import json
from dataclasses import replace
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from ultimate_username import cli
from ultimate_username.cli import main
from ultimate_username.domain.codec import to_json
from ultimate_username.domain.models import (
    AttemptRecord,
    Control,
    DefinitionObservation,
    DetectionResult,
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    Rule,
    SearchError,
    SearchResult,
    SiteDefinition,
    Timing,
    TransportResponse,
    Username,
    Verdict,
)
from ultimate_username.health_probe import (
    BROKEN_SHARE_LIMIT,
    HEALTH_POINTS,
    STATES,
    HealthEntry,
    broken_share,
    fill_missing,
    judge,
    load_health,
    parse_health,
    passive_health,
    probe_health,
    save_health,
)
from ultimate_username.registry import SiteRegistry
from ultimate_username.runtime_policy import MODES, runtime_selection, technical_quality
from ultimate_username.selection import select_services
from ultimate_username.storage import export_results
from ultimate_username.transport import FakeTransport

TODAY = date(2026, 10, 10)


# ------------------------------------------------------------------ result builders


def attempt(status=200, body="b", state=ExecutionState.OK, error=None, reason="PRIMARY_CHECK"):
    return AttemptRecord(
        1, "https://x.test/u/a", status, state, Timing(), error, body_sha256=body,
        budget_reason=reason,
    )  # fmt: skip


def result(
    verdict=Verdict.UNKNOWN,
    state=ExecutionState.OK,
    codes=(),
    reasons=(),
    status=200,
    body="b",
    site="s",
    attempts=None,
):
    errors = tuple(SearchError(c, "t", "m") for c in codes)
    if errors and status == 200 and body == "b":  # transport failure: nothing was received
        status, body = None, ""
    detection = DetectionResult(verdict, state, reasons=tuple(reasons), errors=errors)
    made = (
        attempts
        if attempts is not None
        else (attempt(status, body, state, errors[0] if errors else None),)
    )
    return SearchResult(
        "job", "task", site, Username("a", "a", "a"), detection, attempts=tuple(made)
    )


FOUND = result(Verdict.FOUND, body="known")
NOT_FOUND = result(Verdict.NOT_FOUND, status=404, body="gone")
DNS = result(state=ExecutionState.NETWORK_ERROR, codes=[ErrorCode.DNS_NOT_FOUND], status=None)
FORBIDDEN = result(state=ExecutionState.BLOCKED, codes=[ErrorCode.ACCESS_DENIED], status=403)


# ------------------------------------------------------------------------- judge


def test_judge_ok():
    assert judge(FOUND, NOT_FOUND)[0] == "ok"
    assert judge(result(Verdict.PROBABLE), NOT_FOUND)[0] == "ok"


def test_judge_dead_needs_both_observations_unreachable():
    assert judge(DNS, DNS)[0] == "dead"
    assert judge(None, DNS)[0] == "dead"
    refused = result(state=ExecutionState.NETWORK_ERROR, codes=[ErrorCode.CONNECTION_FAILED])
    # F3.6: a refused connection can be our own network or proxy: never "dead".
    assert judge(refused, refused)[0] == "unstable"
    assert judge(refused, DNS)[0] == "unstable"
    assert judge(None, refused)[0] == "unstable"
    assert judge(DNS, NOT_FOUND)[0] == "unstable"  # one side answered: only unstable
    temporary = result(state=ExecutionState.NETWORK_ERROR, codes=[ErrorCode.DNS_TEMPORARY])
    assert judge(temporary, temporary)[0] == "unstable"


def test_judge_blocked_variants_and_precedence():
    assert judge(FORBIDDEN, FORBIDDEN)[0] == "blocked"
    challenge = result(state=ExecutionState.BLOCKED, codes=[ErrorCode.CHALLENGE], status=200)
    assert judge(challenge, challenge)[0] == "blocked"
    login = result(codes=[ErrorCode.LOGIN_REQUIRED], status=401)
    limited = result(state=ExecutionState.RATE_LIMITED, codes=[ErrorCode.RATE_LIMITED], status=429)
    assert judge(login, limited)[0] == "blocked"
    assert judge(None, FORBIDDEN)[0] == "blocked"
    assert judge(FORBIDDEN, DNS)[0] == "unstable"  # mixed failures: neither dead nor blocked
    assert judge(FOUND, FORBIDDEN)[0] == "ok"  # known account still detected
    assert judge(FORBIDDEN, NOT_FOUND)[0] == "unstable"


def test_judge_false_positive_wins_over_a_working_known_name():
    assert judge(FOUND, result(Verdict.FOUND))[0] == "false_positive"
    assert judge(FOUND, result(Verdict.PROBABLE))[0] == "false_positive"
    assert judge(None, result(Verdict.FOUND))[0] == "false_positive"


def test_judge_uninformative():
    shell = result(reasons=["CONTROL_IDENTICAL", "JS_SHELL"])
    assert judge(shell, NOT_FOUND)[0] == "uninformative"
    identical = result(reasons=["CONTROL_IDENTICAL"])
    assert judge(identical, NOT_FOUND)[0] == "uninformative"
    same_a = result(Verdict.UNKNOWN, body="same")
    same_b = result(Verdict.UNKNOWN, body="same")
    assert judge(same_a, same_b) == ("uninformative", "IDENTICAL_RESPONSES")
    # Identical 404 pages are an ordinary missing-page answer, not a blind rule.
    gone = result(Verdict.NOT_FOUND, status=404, body="same")
    assert judge(gone, gone)[0] == "stale"
    # false_positive is checked before uninformative
    assert judge(shell, result(Verdict.FOUND))[0] == "false_positive"


def test_judge_stale_unstable_untested():
    assert judge(NOT_FOUND, NOT_FOUND)[0] == "stale"
    timeout = result(state=ExecutionState.TIMEOUT, codes=[ErrorCode.READ_TIMEOUT], status=None)
    assert judge(timeout, NOT_FOUND)[0] == "unstable"
    assert judge(FOUND, timeout)[0] == "unstable"
    server = result(state=ExecutionState.SERVER_ERROR, codes=[ErrorCode.SERVER_ERROR], status=503)
    assert judge(server, server)[0] == "unstable"
    assert judge(result(), NOT_FOUND)[0] == "unstable"  # known name undecided
    assert judge(None, NOT_FOUND) == ("untested", "NO_DONOR_CONTROL")
    assert judge(FOUND, None) == ("untested", "NO_RANDOM_NAME")
    assert judge(None, None)[0] == "untested"
    skipped = result(state=ExecutionState.SKIPPED)
    assert judge(skipped, skipped)[0] == "untested"
    assert judge(FOUND, result())[0] == "ok"  # random name undecided: positives still work


def test_judge_ignores_control_attempts_for_status_and_hash():
    main_attempt = attempt(200, "known")
    control_attempt = attempt(403, "other", reason="CONTROL_CHECK")
    known = result(Verdict.FOUND, attempts=(main_attempt, control_attempt))
    assert judge(known, NOT_FOUND)[0] == "ok"


# ----------------------------------------------------------------------- file I/O


def entries():
    return {
        "a": HealthEntry("ok", "R", TODAY, "alice"),
        "b": HealthEntry("dead", "DNS_NOT_FOUND", TODAY - timedelta(days=3)),
    }


def test_health_file_round_trip_and_format(tmp_path):
    path = tmp_path / "data" / "health.json"
    save_health(path, entries(), source="probe", today=TODAY)
    doc = json.loads(path.read_text("utf-8"))
    assert doc["meta"] == {
        "checked": "2026-10-10",
        "source": "probe",
        "states": {"dead": 1, "ok": 1},
    }
    assert doc["sites"]["a"] == {
        "state": "ok", "reason": "R", "checked": "2026-10-10", "known": "alice", "source": "probe"
    }  # fmt: skip
    assert load_health(path, today=TODAY) == entries()
    assert [p.name for p in path.parent.iterdir()] == ["health.json"]


def test_health_missing_file_is_empty(tmp_path):
    assert load_health(tmp_path / "none.json") == {}


def test_health_entries_older_than_30_days_are_ignored():
    def doc(days):
        day = (TODAY - timedelta(days=days)).isoformat()
        return json.dumps(
            {"meta": {}, "sites": {"x": {"state": "dead", "reason": "r", "checked": day}}}
        )

    assert "x" in parse_health(doc(30), today=TODAY)
    assert parse_health(doc(31), today=TODAY) == {}
    assert "x" in parse_health(doc(31), today=TODAY, max_age_days=60)


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"sites": []}',
        '{"meta": {}, "sites": {}, "extra": 1}',
        '{"meta": {"checked": "yesterday"}, "sites": {}}',
        '{"meta": {"zzz": 1}, "sites": {}}',
        '{"sites": {"x": {"state": "great", "reason": "r", "checked": "2026-10-10"}}}',
        '{"sites": {"x": {"state": "ok", "reason": 5, "checked": "2026-10-10"}}}',
        '{"sites": {"x": {"state": "ok", "reason": "r"}}}',
        '{"sites": {"x": {"state": "ok", "reason": "r", "checked": "2026-13-40"}}}',
        '{"sites": {"x": {"state": "ok", "reason": "r", "checked": "2026-10-10", "z": 1}}}',
        '{"sites": {"x": {"state": "ok", "reason": "r", "checked": "2026-10-10", "source": "?"}}}',
        '{"sites": {"x": {"state": "ok", "reason": "r", "checked": "2027-10-10"}}}',
        '{"sites": {"x": "ok"}}',
    ],
)
def test_health_validation_is_strict(text):
    with pytest.raises(ValueError):
        parse_health(text, today=TODAY)


def test_fill_missing_prefers_primary():
    probe = {"a": HealthEntry("ok", "p", TODAY)}
    passive = {
        "a": HealthEntry("dead", "x", TODAY, source="passive"),
        "b": HealthEntry("ok", "q", TODAY),
    }
    merged = fill_missing(probe, passive)
    assert merged["a"].state == "ok" and merged["b"].reason == "q"


# ------------------------------------------------------------- quality and selection

STATUS_OK = Rule("status", statuses=tuple(range(200, 300)))
NOT_FOUND_404 = Rule("status", statuses=(404,))
POSTS = Rule("message", "Posts by")


def site(sid, present=POSTS, absent=NOT_FOUND_404, **changes):
    return SiteDefinition(
        sid,
        sid,
        f"https://{sid}.test/u/{{username}}",
        DetectionSpec(present, absent),
        controls=(Control("alice", Verdict.FOUND),),
        **changes,
    )


def registry_of(*ids, **special):
    return SiteRegistry([special.get(i) or site(i) for i in ids])


def rate(state, day=TODAY):
    return HealthEntry(state, "t", day)


def test_health_points_follow_the_spec():
    assert HEALTH_POINTS == {
        "ok": 15, "untested": 0, "unstable": -10, "stale": -30,
        "uninformative": -40, "blocked": -50, "dead": -100, "false_positive": -100,
    }  # fmt: skip
    assert set(HEALTH_POINTS) == set(STATES)


@pytest.mark.parametrize("state", STATES)
def test_technical_quality_applies_health_points_with_a_reason(state):
    entry = registry_of("a").entries[0]
    base = technical_quality(entry)
    rated = technical_quality(entry, health={"a": rate(state)})
    assert rated.value == base.value + HEALTH_POINTS[state]
    assert rated.reasons == base.reasons + (f"HEALTH_{state.upper()}:{HEALTH_POINTS[state]:+d}",)


def test_no_health_means_no_effect_on_quality():
    entry = registry_of("a").entries[0]
    assert technical_quality(entry) == technical_quality(entry, health={})
    assert technical_quality(entry) == technical_quality(entry, health={"other": rate("dead")})
    assert technical_quality(entry) == technical_quality(entry, health=None)


def plan(registry, mode, health=None, include_broken=False, **policy):
    policy_obj = replace(MODES[mode], **policy)
    selection = runtime_selection(
        registry, select_services(registry, "alice"), policy_obj, health, include_broken
    )
    return selection


def test_normal_deep_quick_skip_dead_blocked_and_false_positive():
    registry = registry_of("good", "dead", "blk", "fp", "stale", "meh")
    health = {
        "good": rate("ok"), "dead": rate("dead"), "blk": rate("blocked"),
        "fp": rate("false_positive"), "stale": rate("stale"), "meh": rate("unstable"),
    }  # fmt: skip
    for mode in ("quick", "normal", "deep"):
        selection = plan(registry, mode, health, min_quality=-100)
        assert set(selection.selected) == {"good", "stale", "meh"}, mode
        assert {r for s, r in selection.excluded if s in {"dead", "blk", "fp"}} == {
            "HEALTH_DEAD", "HEALTH_BLOCKED", "HEALTH_FALSE_POSITIVE"
        }  # fmt: skip
        assert selection.selected[0] == "good"
        assert selection.selected.index("meh") < selection.selected.index("stale")


def test_exhaustive_only_orders_and_never_drops():
    registry = registry_of("good", "dead", "fp", "plain")
    health = {"good": rate("ok"), "dead": rate("dead"), "fp": rate("false_positive")}
    selection = plan(registry, "exhaustive", health)
    assert set(selection.selected) == {"good", "dead", "fp", "plain"}
    assert selection.selected[0] == "good" and selection.selected[1] == "plain"
    assert set(selection.selected[2:]) == {"dead", "fp"}
    assert not any(r.startswith("HEALTH_") for _, r in selection.excluded)


def test_gate_threshold_does_not_see_health_points_either():
    weak = site("weak")  # status-only present rule, no absent rule: low base score
    registry = SiteRegistry([replace(weak, detection=DetectionSpec(STATUS_OK, None))])
    base = technical_quality(registry.entries[0]).value
    for mode in ("quick", "normal", "deep"):
        # a good rating cannot lift the service over the threshold ...
        up = plan(registry, mode, {"weak": rate("ok")}, min_quality=base + 1)
        assert up.selected == () and ("weak", "MODE_QUALITY_THRESHOLD") in up.excluded, mode
        # ... and a mediocre one cannot sink it below
        down = plan(registry, mode, {"weak": rate("unstable")}, min_quality=base)
        assert down.selected == ("weak",), mode
    # health still orders the queue
    ranked = plan(registry_of("x", "y"), "normal", {"y": rate("ok")})
    assert ranked.selected[0] == "y"


def test_exhaustive_threshold_does_not_see_health_points():
    weak = site("weak")  # status-only present rule, no absent rule: low base score
    registry = SiteRegistry([replace(weak, detection=DetectionSpec(STATUS_OK, None))])
    base = technical_quality(registry.entries[0]).value
    assert base + HEALTH_POINTS["dead"] < -100 <= base
    selection = plan(registry, "exhaustive", {"weak": rate("dead")})
    assert selection.selected == ("weak",)


def test_include_broken_keeps_everything_in_normal_mode():
    registry = registry_of("good", "dead")
    health = {"good": rate("ok"), "dead": rate("dead")}
    assert plan(registry, "normal", health).selected == ("good",)
    kept = plan(registry, "normal", health, include_broken=True)
    assert kept.selected == ("good", "dead")
    assert not any(r.startswith("HEALTH_") for _, r in kept.excluded)


def test_a_healthy_variant_becomes_the_primary_of_a_service():
    twin = replace(site("twin"), profile_url="https://good.test/u/{username}")
    registry = SiteRegistry([site("good"), twin])
    selection = plan(registry, "normal", {"good": rate("dead"), "twin": rate("ok")})
    assert selection.selected == ("twin",)
    selection = plan(registry, "normal", {"good": rate("dead"), "twin": rate("dead")})
    assert selection.selected == ()


@pytest.mark.parametrize("mode", tuple(MODES))
def test_selection_without_health_is_unchanged(mode):
    registry = registry_of("a", "b", "c")
    reference = plan(registry, mode)
    assert plan(registry, mode, {}) == reference
    assert plan(registry, mode, None, include_broken=True) == reference
    assert plan(registry, mode, {"unrelated": rate("dead")}) == reference
    assert all("HEALTH" not in "".join(s.quality.reasons) for s in reference.services)


def test_only_the_non_exhaustive_modes_skip_by_health():
    assert [m for m, p in MODES.items() if p.health_skip] == ["quick", "normal", "deep"]


def test_work_order_is_descending_quality_through_the_engine():
    from ultimate_username.engine import SearchOptions, UsernameEngine

    registry = registry_of("a", "b", "c")
    health = {"a": rate("unstable"), "b": rate("ok"), "c": rate("stale")}
    policy = replace(MODES["exhaustive"], service_budget=10)
    selection = runtime_selection(registry, select_services(registry, "alice"), policy, health)
    assert selection.selected == ("b", "a", "c")

    async def go():
        seen = []
        transport = FakeTransport(handler=lambda r, i: seen.append(r.url) or reply(r, "x", 404))
        async with UsernameEngine(registry, transport) as engine:
            out = [
                r
                async for r in engine.search_stream(
                    "alice",
                    options=SearchOptions(request_budget=100),
                    runtime=policy,
                    selection=selection,
                )
            ]
        return [r.site_id for r in out], seen

    ids, _ = asyncio.run(go())
    assert ids == ["b", "a", "c"]


# --------------------------------------------------------------------- passive


def pr(site_id, verdict=Verdict.UNKNOWN, **kw):
    return result(verdict, site=site_id, **kw)


def test_passive_states_from_aggregated_results():
    rows = (
        [
            pr(
                "dead",
                state=ExecutionState.NETWORK_ERROR,
                codes=[ErrorCode.DNS_NOT_FOUND],
                status=None,
            )
        ]
        * 3
        + [pr("walled", state=ExecutionState.BLOCKED, codes=[ErrorCode.ACCESS_DENIED], status=403)]
        * 4
        + [pr("walled", Verdict.NOT_FOUND, status=404)]
        + [pr("shell", reasons=["CONTROL_IDENTICAL", "JS_SHELL"])] * 2
        + [pr("flaky", state=ExecutionState.TIMEOUT, codes=[ErrorCode.READ_TIMEOUT], status=None)]
        * 2
        + [pr("hit", Verdict.FOUND)] * 2
        + [pr("hit", state=ExecutionState.TIMEOUT, codes=[ErrorCode.READ_TIMEOUT], status=None)] * 2
        + [pr("quiet", Verdict.NOT_FOUND, status=404)] * 3
        + [
            pr(
                "single",
                state=ExecutionState.NETWORK_ERROR,
                codes=[ErrorCode.DNS_NOT_FOUND],
                status=None,
            )
        ]
        + [pr("skipped", state=ExecutionState.SKIPPED)]
    )
    got = {k: v.state for k, v in passive_health(rows, today=TODAY).items()}
    assert got == {
        "dead": "dead", "walled": "blocked", "shell": "uninformative", "flaky": "unstable",
        "hit": "ok", "quiet": "untested", "single": "untested",
    }  # fmt: skip
    entry = passive_health(rows, today=TODAY)["dead"]
    assert entry.source == "passive" and entry.checked == TODAY and "n=3" in entry.reason


def test_passive_uses_fallback_chain_steps_per_definition():
    step = DefinitionObservation(
        "alt", "FALLBACK_CHECK", DetectionResult(Verdict.FOUND), (attempt(),)
    )
    chained = replace(pr("main", state=ExecutionState.BLOCKED, status=403), fallback_chain=(step,))
    got = passive_health([chained], today=TODAY)
    assert set(got) == {"alt"} and got["alt"].state == "ok"


def test_passive_is_deterministic_and_does_no_requests():
    rows = [pr("a", Verdict.FOUND), pr("b", Verdict.NOT_FOUND, status=404)]
    assert passive_health(rows, today=TODAY) == passive_health(list(reversed(rows)), today=TODAY)


# ------------------------------------------------------------------------ probe

REAL = {"alice"}


def reply(request, body, status=200):
    data = body.encode() if isinstance(body, str) else body
    return TransportResponse(request.url, status, data, (), request.url)


def name_of(request):
    return request.url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]


FP_CALLS = [0]


def handler(request, index):
    host = request.url.split("/")[2]
    name = name_of(request)
    if host == "dead.test":
        return TransportResponse(
            request.url, error=SearchError(ErrorCode.DNS_NOT_FOUND, "dns", "no host")
        )
    if host == "fp.test":
        # A rule that answers the first request of every pair and 404s the control that
        # follows it: the random name looks like an account (a quirk, not a real profile).
        FP_CALLS[0] += 1
        if FP_CALLS[0] % 2 == 0:
            return reply(request, "<html><body>Not here</body></html>", 404)
        return reply(request, f"<html><title>{name}</title><body>Posts by {name} " + "text " * 80)
    if host == "wall.test":
        return reply(request, "Forbidden", 403)
    if name in REAL:
        return reply(request, f"<html><title>{name}</title><body>Posts by {name} " + "text " * 80)
    return reply(request, "<html><body>Not here</body></html>", 404)


def probe_registry():
    return SiteRegistry(
        [
            site("good"),
            replace(site("dead"), profile_url="https://dead.test/u/{username}"),
            replace(site("fp"), profile_url="https://fp.test/u/{username}"),
            replace(site("wall"), profile_url="https://wall.test/u/{username}"),
            replace(site("nodonor"), controls=()),
        ]
    )


def run_probe(registry=None, ids=None, **kw):
    FP_CALLS[0] = 0
    registry = registry or probe_registry()
    transport = FakeTransport(handler=handler)
    out = asyncio.run(
        probe_health(registry, transport, ids, today=TODAY, concurrency=4, job_timeout=20, **kw)
    )
    return out, transport


def test_probe_rates_artificial_definitions_through_the_engine():
    out, transport = run_probe()
    assert {k: v.state for k, v in out.items()} == {
        "good": "ok", "dead": "dead", "fp": "false_positive", "wall": "blocked",
        "nodonor": "untested",
    }  # fmt: skip
    assert out["good"].known == "alice" and out["nodonor"].known == ""
    assert all(e.checked == TODAY and e.source == "probe" for e in out.values())
    good_calls = [r for r in transport.requests if "good.test" in r.url]
    assert {name_of(r) for r in good_calls} >= {"alice"} and len(good_calls) >= 2


def test_probe_random_name_is_seeded_and_never_the_known_name():
    first, t1 = run_probe()
    second, t2 = run_probe()
    assert first == second
    names1 = sorted(name_of(r) for r in t1.requests if "good.test" in r.url)
    names2 = sorted(name_of(r) for r in t2.requests if "good.test" in r.url)
    assert names1 == names2
    random_names = [n for n in names1 if n != "alice"]
    assert random_names and all("alice" not in n and len(n) >= 8 for n in random_names)


def test_probe_restricts_to_the_requested_ids_and_skips_invalid():
    broken = SiteDefinition(
        "bad", "bad", "https://bad.test/u/{username}", DetectionSpec(None, None)
    )
    registry = SiteRegistry([site("good"), broken])
    out, _ = run_probe(registry, ["good", "bad", "missing"])
    assert set(out) == {"good"}


def test_probe_bounds_concurrency():
    sites = [
        replace(site(f"s{i}"), profile_url=f"https://h{i}.test/u/{{username}}") for i in range(12)
    ]
    transport = FakeTransport(handler=handler, delay=0.01)
    asyncio.run(
        probe_health(SiteRegistry(sites), transport, today=TODAY, concurrency=3, job_timeout=20)
    )
    assert transport.peak_active <= 3 * 2


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def catalog(tmp_path):
    path = tmp_path / "data" / "catalog.json"
    path.parent.mkdir()
    registry = probe_registry()
    path.write_text(to_json(tuple(e.definition for e in registry.entries)), encoding="utf-8")
    return path


@pytest.fixture
def fake_net(monkeypatch):
    """Every transport the CLI builds records into one list (an engine closes its own)."""
    FP_CALLS[0] = 0
    net = SimpleNamespace(requests=[])

    def recording(request, index):
        net.requests.append(request)
        return handler(request, index)

    monkeypatch.setattr(cli, "AiohttpTransport", lambda config: FakeTransport(handler=recording))
    return net


def test_cli_health_probe_writes_health_json(tmp_path, catalog, fake_net, capsys):
    out = tmp_path / "out" / "health.json"
    code = main(
        ["health-probe", "--registry", str(catalog), "--out", str(out), "--concurrency", "4"]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "sites": 5,
        "states": {"blocked": 1, "dead": 1, "false_positive": 1, "ok": 1, "untested": 1},
    }
    doc = json.loads(out.read_text("utf-8"))
    assert doc["sites"]["dead"]["state"] == "dead" and doc["meta"]["source"] == "probe"


def test_cli_health_probe_sites_limit_and_merge(tmp_path, catalog, fake_net, capsys):
    out = tmp_path / "health.json"
    base = ["health-probe", "--registry", str(catalog), "--out", str(out), "--force"]
    assert main([*base, "--sites", "good", "dead"]) == 0
    assert set(json.loads(out.read_text("utf-8"))["sites"]) == {"good", "dead"}
    assert main([*base, "--sites", "fp", "--merge"]) == 0
    assert set(json.loads(out.read_text("utf-8"))["sites"]) == {"good", "dead", "fp"}
    assert main([*base, "--limit", "1"]) == 0  # sorted ids: "bad..." not present; first is "dead"
    assert set(json.loads(out.read_text("utf-8"))["sites"]) == {"dead"}
    assert main([*base, "--sites", "nope"]) == 2
    assert main([*base, "--limit", "0"]) == 2
    capsys.readouterr()


def test_broken_share_counts_dead_and_blocked():
    assert broken_share({}) == 0.0
    rows = {s: rate(s) for s in ("dead", "blocked", "ok", "unstable", "stale")}
    assert broken_share(rows) == pytest.approx(0.4)
    assert BROKEN_SHARE_LIMIT == 0.4


def test_cli_health_probe_refuses_to_write_when_most_results_are_broken(
    tmp_path, catalog, fake_net, capsys
):
    out = tmp_path / "health.json"
    base = ["health-probe", "--registry", str(catalog), "--out", str(out)]
    assert main([*base, "--sites", "dead"]) == 3  # 100% dead
    err = capsys.readouterr().err
    assert "Refusing to write" in err and "--force" in err
    assert not out.exists()
    assert main([*base, "--sites", "dead", "--force"]) == 0
    assert out.is_file()
    capsys.readouterr()
    out.unlink()
    # exactly 40% (dead + blocked of five) is allowed
    assert main(base) == 0 and out.is_file()
    capsys.readouterr()


def test_cli_health_passive_refuses_a_broken_majority_too(tmp_path, capsys):
    dead = [
        pr("d", state=ExecutionState.NETWORK_ERROR, codes=[ErrorCode.DNS_NOT_FOUND], status=None)
    ] * 2
    results = tmp_path / "results.json"
    export_results(results, [*dead, pr("a", Verdict.FOUND)])
    out = tmp_path / "health.json"
    assert main(["health-passive", "--results", str(results), "--out", str(out)]) == 3
    assert "Refusing to write" in capsys.readouterr().err and not out.exists()
    assert main(["health-passive", "--results", str(results), "--out", str(out), "--force"]) == 0
    assert json.loads(out.read_text("utf-8"))["sites"]["d"]["state"] == "dead"
    capsys.readouterr()


def test_cli_health_passive_merges_under_probe(tmp_path, capsys):
    results = tmp_path / "results.json"
    export_results(
        results,
        [pr("a", Verdict.FOUND), pr("b", Verdict.FOUND), pr("b", Verdict.FOUND)],
    )
    out = tmp_path / "health.json"
    save_health(out, {"b": HealthEntry("dead", "probe says", date.today())}, source="probe")
    assert main(["health-passive", "--results", str(results), "--out", str(out), "--merge"]) == 0
    sites = json.loads(out.read_text("utf-8"))["sites"]
    assert sites["a"]["state"] == "ok" and sites["a"]["source"] == "passive"
    assert sites["b"]["state"] == "dead" and sites["b"]["source"] == "probe"
    fresh = tmp_path / "fresh.json"
    assert main(["health-passive", "--results", str(results), "--out", str(fresh)]) == 0
    assert json.loads(fresh.read_text("utf-8"))["sites"]["b"]["state"] == "ok"
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert main(["health-passive", "--results", str(bad), "--out", str(fresh)]) == 2
    capsys.readouterr()


def search(tmp_path, catalog, *extra):
    return main(
        [
            "search", "alice", "--registry", str(catalog), "--mode", "normal",
            "--enrich", "off", "--output", str(tmp_path / "r.json"),
            "--journal", str(tmp_path / "j.sqlite"), *extra,
        ]
    )  # fmt: skip


def hosts(net):
    return {r.url.split("/")[2] for r in net.requests}


def test_cli_search_skips_broken_by_health_and_include_broken_restores(
    tmp_path, catalog, fake_net, capsys
):
    save_health(
        catalog.with_name("health.json"),
        {
            "dead": HealthEntry("dead", "r", date.today()),
            "good": HealthEntry("ok", "r", date.today()),
        },
    )
    search(tmp_path, catalog)
    assert "dead.test" not in hosts(fake_net) and "good.test" in hosts(fake_net)
    capsys.readouterr()
    fake_net.requests.clear()
    search(tmp_path, catalog, "--include-broken")
    assert "dead.test" in hosts(fake_net)
    capsys.readouterr()
    fake_net.requests.clear()
    search(tmp_path, catalog, "--mode", "exhaustive")
    assert "dead.test" in hosts(fake_net)


def test_cli_search_without_health_file_or_with_stale_one_is_unchanged(
    tmp_path, catalog, fake_net, capsys
):
    search(tmp_path, catalog)
    baseline = hosts(fake_net)
    assert "dead.test" in baseline
    fake_net.requests.clear()
    old = date.today() - timedelta(days=45)
    save_health(catalog.with_name("health.json"), {"dead": HealthEntry("dead", "r", old)})
    search(tmp_path, catalog)
    assert hosts(fake_net) == baseline
    fake_net.requests.clear()
    search(tmp_path, catalog, "--health", str(tmp_path / "nowhere.json"))
    assert hosts(fake_net) == baseline
    capsys.readouterr()


def test_cli_search_rejects_a_corrupt_health_file(tmp_path, catalog, fake_net, capsys):
    corrupt = '{"sites": {"x": {"state": "??"}}}'
    catalog.with_name("health.json").write_text(corrupt, encoding="utf-8")
    # discovered automatically: a warning, no health ranking, the run goes on
    assert search(tmp_path, catalog) == 1  # 1: the fixture's dead/blocked sites report failures
    err = capsys.readouterr().err
    assert "Warning: ignoring" in err and "health.json" in err
    assert "dead.test" in hosts(fake_net)
    fake_net.requests.clear()
    # explicit --health must be valid: configuration error
    assert search(tmp_path, catalog, "--health", str(catalog.with_name("health.json"))) == 2
    assert "Configuration/output error" in capsys.readouterr().err
    assert not fake_net.requests
