"""Validate JSON boundary values without letting Any propagate into domain models."""

from __future__ import annotations

import json
import math

from ultimate_username.domain.models import JSONValue


def json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite JSON number")
        return value
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, JSONValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            result[key] = json_value(item)
        return result
    raise ValueError(f"Not a JSON value: {type(value).__name__}")


def _reject_constant(name: str) -> object:
    raise ValueError("Non-finite JSON number")


def _finite_float(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def parse_json(text: str) -> JSONValue:
    """json.loads only yields str keys and JSON scalars; the sole invalid inputs are
    NaN/Infinity and overflowing floats, rejected by the hooks (no second tree walk)."""
    decoded: object = json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
    return decoded  # type: ignore[return-value]
