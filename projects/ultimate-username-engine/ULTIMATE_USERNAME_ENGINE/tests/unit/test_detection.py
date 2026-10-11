from dataclasses import replace

import pytest

from ultimate_username.detection import DetectionContext, DetectionEngine, ResponseView
from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    Polarity,
    PredicateState,
    Rule,
    SearchError,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.planning import plan_request


def make_plan(spec=None):
    spec = spec or DetectionSpec(
        present=Rule("message", "profile:"),
        absent=Rule("message", "missing"),
        binding=Rule("regex", r"profile:(?P<user>\w+)", group="user"),
    )
    return plan_request(
        "alice", SiteDefinition("example", "Example", "https://example.test/{username}", spec), "t1"
    )


def response(status=200, body=b"profile:alice", **kwargs):
    return TransportResponse(
        "https://example.test/alice", status, body, final_url="https://example.test/alice", **kwargs
    )


@pytest.mark.parametrize(
    ("status", "body", "verdict", "state"),
    [
        (200, b"profile:alice", Verdict.FOUND, ExecutionState.OK),
        (200, b"missing", Verdict.NOT_FOUND, ExecutionState.OK),
        (200, b"generic page", Verdict.UNKNOWN, ExecutionState.OK),
        (200, b"profile:bob", Verdict.UNKNOWN, ExecutionState.OK),
        (200, b"profile:alice missing", Verdict.UNKNOWN, ExecutionState.OK),
        (301, b"", Verdict.UNKNOWN, ExecutionState.OK),
        (302, b"", Verdict.UNKNOWN, ExecutionState.OK),
        (403, b"profile:alice", Verdict.UNKNOWN, ExecutionState.BLOCKED),
        (404, b"missing", Verdict.NOT_FOUND, ExecutionState.OK),
        (404, b"profile:alice", Verdict.UNKNOWN, ExecutionState.OK),
        (429, b"missing", Verdict.UNKNOWN, ExecutionState.RATE_LIMITED),
        (500, b"missing", Verdict.UNKNOWN, ExecutionState.SERVER_ERROR),
        (
            200,
            b"<title>Just a moment...</title>profile:alice",
            Verdict.UNKNOWN,
            ExecutionState.BLOCKED,
        ),
    ],
)
def test_failure_gate_and_account_evidence(status, body, verdict, state):
    result = DetectionEngine().detect(response(status, body), make_plan())
    assert (result.verdict, result.state) == (verdict, state)
    assert result.evidence
    assert result.confidence.value is None


@pytest.mark.parametrize("code", list(ErrorCode))
def test_every_explicit_error_is_unknown(code):
    result = DetectionEngine().detect(
        response(error=SearchError(code, "test", "failure")), make_plan()
    )
    assert result.verdict == Verdict.UNKNOWN
    assert result.state != ExecutionState.OK


def test_status_only_and_absence_of_negative_cannot_prove_found():
    for spec in [
        DetectionSpec(present=Rule("status", statuses=(200,))),
        DetectionSpec(present=Rule("not", children=(Rule("message", "missing"),))),
    ]:
        assert DetectionEngine().detect(response(), make_plan(spec)).verdict == Verdict.UNKNOWN
    spec = DetectionSpec(absent=Rule("message", "missing"))
    assert DetectionEngine().detect(response(), make_plan(spec)).verdict == Verdict.UNKNOWN


@pytest.mark.parametrize("body", [b"{broken", b"\xff"])
def test_invalid_json_or_encoding_is_parse_error(body):
    spec = DetectionSpec(present=Rule("json", '"alice"', path=("name",)))
    result = DetectionEngine().detect(response(body=body), make_plan(spec))
    assert result.state == ExecutionState.PARSE_ERROR


@pytest.mark.parametrize(("value", "expected"), [("false", "false"), ("0", "0"), ('""', '""')])
def test_json_preserves_false_zero_and_empty(value, expected):
    plan = make_plan(DetectionSpec(present=Rule("json", expected, path=("field",))))
    result = DetectionEngine().detect(response(body=('{"field":' + value + "}").encode()), plan)
    assert result.verdict == Verdict.UNKNOWN
    assert result.evidence[0].state == PredicateState.TRUE


def test_unobserved_not_remains_unobserved():
    plan = make_plan()
    context = DetectionContext(plan, Polarity.PRESENT, "x", 0.05)
    rule = Rule("not", children=(Rule("status", statuses=(200,)),))
    result = DetectionEngine().evaluate(rule, ResponseView(response(status=None)), context)
    assert result.state == PredicateState.UNOBSERVED


def test_composite_and_exact_redirect_header_binding():
    spec = DetectionSpec(
        present=Rule(
            "all",
            children=(
                Rule("status", statuses=(200,)),
                Rule("message", "profile:"),
                Rule("header", "yes", scope="X-Profile"),
            ),
        ),
        binding=Rule("redirect", "{profile_url}"),
    )
    result = DetectionEngine().detect(response(headers=(("x-profile", "yes"),)), make_plan(spec))
    assert result.verdict == Verdict.FOUND
    assert len(result.evidence) == 4


def test_login_and_truncated_body():
    plan = make_plan()
    assert (
        DetectionEngine()
        .detect(replace(response(), final_url="https://example.test/login"), plan)
        .state
        == ExecutionState.BLOCKED
    )
    assert (
        DetectionEngine().detect(response(body_complete=False), plan).state
        == ExecutionState.PARSE_ERROR
    )


def test_plugin_failure_is_contained_and_override_rejected():
    class Broken:
        def evaluate(self, *args):
            raise RuntimeError("secret must not leak")

    detector = DetectionEngine({"broken": Broken()})
    result = detector.detect(response(), make_plan(DetectionSpec(present=Rule("broken"))))
    assert result.state == ExecutionState.DETECTION_ERROR
    assert "secret" not in str(result)
    with pytest.raises(ValueError):
        DetectionEngine({"status": Broken()})


def test_pathological_regex_has_time_budget():
    plan = make_plan(DetectionSpec(present=Rule("regex", "(a+)+$")))
    result = DetectionEngine(regex_timeout=0.001).detect(response(body=b"a" * 20000 + b"!"), plan)
    assert result.state == ExecutionState.DETECTION_ERROR
