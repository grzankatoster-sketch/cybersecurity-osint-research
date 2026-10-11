from dataclasses import FrozenInstanceError

import pytest

from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import (
    Confidence,
    DetectionResult,
    DetectionSpec,
    ExecutionState,
    FieldObservation,
    SiteDefinition,
    TransportResponse,
    Verdict,
)


@pytest.mark.parametrize("state", [s for s in ExecutionState if s != ExecutionState.OK])
@pytest.mark.parametrize("verdict", [Verdict.FOUND, Verdict.NOT_FOUND, Verdict.PROBABLE])
def test_execution_error_cannot_assert_account(state: ExecutionState, verdict: Verdict) -> None:
    with pytest.raises(ValueError, match="execution error"):
        DetectionResult(verdict=verdict, state=state)


def test_definition_frozen() -> None:
    site = SiteDefinition("x", "X", "https://x.invalid/{username}", DetectionSpec())
    with pytest.raises(FrozenInstanceError):
        site.name = "Changed"
    assert site.name == "X"


@pytest.mark.parametrize("text,expected", [("0", 0), ("false", False), ('"[x]"', "[x]")])
def test_typed_field_value(text: str, expected: object) -> None:
    field = FieldObservation("field", text, "https://x.invalid/u", "test")
    assert field.value() == expected
    assert type(field.value()) is type(expected)


def test_field_nested_value_does_not_share_mutable_state() -> None:
    field = FieldObservation("list", "[1,2]", "https://x.invalid/u", "test")
    first = field.value()
    assert isinstance(first, list)
    first.append(3)
    assert field.value() == [1, 2]


def test_unknown_status_is_not_synthesized() -> None:
    response = TransportResponse("https://x.invalid/u", body=b"profile")
    assert response.status is None


def test_confidence_is_null_without_calibration() -> None:
    assert DetectionResult().confidence.value is None
    for value in [float("nan"), float("inf"), -0.1, 1.1]:
        with pytest.raises(ValueError):
            Confidence(value=value)


def test_json_boundary_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError, match="Non-finite"):
        parse_json('{"value":NaN}')
