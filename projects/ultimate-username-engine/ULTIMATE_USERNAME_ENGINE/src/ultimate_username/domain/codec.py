"""Strict dataclass JSON codec. Only application-owned types are constructed."""

from __future__ import annotations

import dataclasses
import json
import types
from collections.abc import Callable
from functools import lru_cache
from enum import Enum
from typing import TypeVar, Union, get_args, get_origin, get_type_hints

from ultimate_username.domain.json_types import json_value, parse_json
from ultimate_username.domain.models import JSONValue

T = TypeVar("T")


Decoder = Callable[[JSONValue, str], object]


def _unexpected(value: JSONValue, path: str) -> object:
    raise ValueError(f"{path}: unexpected type {type(value).__name__}")


@lru_cache(maxsize=None)
def _compile(expected: object) -> Decoder:
    """Build the decoder for one annotation once; the check order matches the old walker."""
    origin = get_origin(expected)
    args: tuple[object, ...] = get_args(expected)
    if origin in (types.UnionType, Union):
        alternatives = tuple(_compile(alternative) for alternative in args)

        def decode_union(value: JSONValue, path: str) -> object:
            for alternative in alternatives:
                try:
                    return alternative(value, path)
                except (ValueError, TypeError):
                    continue
            raise ValueError(f"{path}: value does not match union")

        return decode_union
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            item = _compile(args[0])

            def decode_variadic(value: JSONValue, path: str) -> object:
                if not isinstance(value, list):
                    raise ValueError(f"{path}: expected array")
                return tuple(item(v, f"{path}[{i}]") for i, v in enumerate(value))

            return decode_variadic
        items = tuple(_compile(t) for t in args)

        def decode_fixed(value: JSONValue, path: str) -> object:
            if not isinstance(value, list):
                raise ValueError(f"{path}: expected array")
            if len(items) != len(value):
                raise ValueError(f"{path}: wrong tuple length")
            return tuple(d(v, f"{path}[{i}]") for i, (d, v) in enumerate(zip(items, value, strict=True)))

        return decode_fixed
    if expected is type(None):

        def decode_none(value: JSONValue, path: str) -> object:
            if value is None:
                return None
            return _unexpected(value, path)

        return decode_none
    if isinstance(expected, type) and issubclass(expected, Enum):
        enum_type = expected

        def decode_enum(value: JSONValue, path: str) -> object:
            return enum_type(value)

        return decode_enum
    if isinstance(expected, type) and dataclasses.is_dataclass(expected):
        dataclass_type = expected

        def decode_dataclass(value: JSONValue, path: str) -> object:
            return from_value(dataclass_type, value, path)

        return decode_dataclass
    if expected is float:

        def decode_float(value: JSONValue, path: str) -> object:
            if type(value) in (int, float):
                return float(value)  # type: ignore[arg-type]
            return _unexpected(value, path)

        return decode_float
    if expected in (str, int, bool):

        def decode_scalar(value: JSONValue, path: str) -> object:
            if type(value) is expected:
                return value
            return _unexpected(value, path)

        return decode_scalar
    return _unexpected


def _decode(expected: object, value: JSONValue, path: str) -> object:
    return _compile(expected)(value, path)


@lru_cache(maxsize=None)
def _class_plan(cls: type) -> tuple[frozenset[str], tuple[tuple[str, bool, Decoder], ...]]:
    """Field names plus (name, required, decoder) per field, computed once per class.

    ``get_type_hints`` re-evaluates every string annotation on each call, which
    dominated catalog loading (about 130k calls for ~9k records).
    """
    hints: dict[str, object] = get_type_hints(cls)
    plan = tuple(
        (
            field.name,
            field.default is dataclasses.MISSING and field.default_factory is dataclasses.MISSING,
            _compile(hints[field.name]),
        )
        for field in dataclasses.fields(cls)
    )
    return frozenset(name for name, _, _ in plan), plan


def from_value(cls: type[T], value: JSONValue, path: str = "root") -> T:
    if not isinstance(value, dict) or not dataclasses.is_dataclass(cls):
        raise ValueError(f"{path}: expected a typed object")
    names, plan = _class_plan(cls)
    unknown = value.keys() - names
    if unknown:
        raise ValueError(f"{path}: unknown fields {sorted(unknown)}")
    values: dict[str, object] = {}
    for name, required, decoder in plan:
        if name not in value:
            if required:
                raise ValueError(f"{path}.{name}: required field missing")
            continue
        values[name] = decoder(value[name], f"{path}.{name}")
    return cls(**values)


def from_json(cls: type[T], text: str) -> T:
    return from_value(cls, parse_json(text))


@lru_cache(maxsize=None)
def _field_names(cls: type) -> tuple[str, ...]:
    return tuple(field.name for field in dataclasses.fields(cls))


def to_value(value: object) -> JSONValue:
    kind = type(value)
    if kind is str or kind is int or kind is bool or value is None:
        return value  # type: ignore[return-value]
    if kind is tuple or kind is list:
        return [to_value(item) for item in value]  # type: ignore[attr-defined]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {name: to_value(getattr(value, name)) for name in _field_names(kind)}
    if isinstance(value, Enum):
        return json_value(value.value)
    if isinstance(value, (tuple, list)):
        return [to_value(item) for item in value]
    return json_value(value)


def to_json(value: object, *, indent: int | None = None) -> str:
    return json.dumps(to_value(value), ensure_ascii=False, allow_nan=False, indent=indent)
