"""Codec must resolve type hints once per class, not once per decoded object."""

from __future__ import annotations

from dataclasses import dataclass

from ultimate_username.domain import codec


@dataclass(frozen=True)
class _Leaf:
    name: str
    size: int = 0


@dataclass(frozen=True)
class _Root:
    leaves: tuple[_Leaf, ...]
    note: str | None = None


def test_type_hints_resolved_once_per_class(monkeypatch) -> None:
    calls: list[type] = []
    real = codec.get_type_hints

    def counting(cls: type) -> dict[str, object]:
        calls.append(cls)
        return real(cls)

    monkeypatch.setattr(codec, "get_type_hints", counting)
    codec._class_plan.cache_clear()
    value = {"leaves": [{"name": f"n{i}", "size": i} for i in range(50)], "note": None}
    decoded = codec.from_value(_Root, value)
    assert len(decoded.leaves) == 50
    assert decoded.leaves[7] == _Leaf("n7", 7)
    assert len(calls) == 2
    codec.from_value(_Root, value)
    assert len(calls) == 2


def test_errors_unchanged_for_unknown_and_missing() -> None:
    import pytest

    with pytest.raises(ValueError, match="unknown fields"):
        codec.from_value(_Leaf, {"name": "a", "bogus": 1})
    with pytest.raises(ValueError, match="required field missing"):
        codec.from_value(_Leaf, {"size": 1})


def test_to_value_roundtrip_matches_plain_structure() -> None:
    import json

    root = _Root((_Leaf("a", 1), _Leaf("b", 2)), "x")
    assert codec.to_value(root) == {
        "leaves": [{"name": "a", "size": 1}, {"name": "b", "size": 2}],
        "note": "x",
    }
    assert codec.from_value(_Root, json.loads(codec.to_json(root))) == root
    assert codec.to_value(True) is True
    assert codec.to_value(2.5) == 2.5


def test_parse_json_rejects_non_finite_numbers() -> None:
    import pytest

    from ultimate_username.domain.json_types import parse_json

    for text in ("NaN", "Infinity", "-Infinity", "[1e999]", '{"a": [NaN]}'):
        with pytest.raises(ValueError):
            parse_json(text)
    assert parse_json('{"a": [1, 2.5, null, true, "x"]}') == {"a": [1, 2.5, None, True, "x"]}
