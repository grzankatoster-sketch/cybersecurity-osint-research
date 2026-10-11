"""Small bounded data-literal reader; rejects expressions, calls and executable JS."""

from __future__ import annotations

import json
import re
from typing import cast

from ultimate_username.domain.models import JSONValue


def read_literal(text: str) -> JSONValue:
    text = text[:65_536]
    offset = 0
    nodes = 0

    def whitespace() -> None:
        nonlocal offset
        while offset < len(text) and text[offset].isspace():
            offset += 1

    def token(value: str) -> None:
        nonlocal offset
        whitespace()
        if not text.startswith(value, offset):
            raise ValueError("Unexpected data token")
        offset += len(value)

    def read(depth: int = 0) -> JSONValue:
        nonlocal offset, nodes
        nodes += 1
        if depth > 16 or nodes > 512:
            raise ValueError("Literal budget exceeded")
        whitespace()
        if offset >= len(text):
            raise ValueError("Incomplete literal")
        current = text[offset]
        if current == "{":
            offset += 1
            obj: dict[str, JSONValue] = {}
            whitespace()
            while not text.startswith("}", offset):
                whitespace()
                if text.startswith('"', offset):
                    key = read(depth + 1)
                    if not isinstance(key, str):
                        raise ValueError("Invalid key")
                else:
                    match = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", text[offset:])
                    if not match:
                        raise ValueError("Invalid key")
                    key = match[0]
                    offset += len(key)
                if key in obj:
                    raise ValueError("Duplicate key")
                token(":")
                obj[key] = read(depth + 1)
                whitespace()
                if text.startswith("}", offset):
                    break
                token(",")
            token("}")
            return obj
        if current == "[":
            offset += 1
            items: list[JSONValue] = []
            whitespace()
            while not text.startswith("]", offset):
                items.append(read(depth + 1))
                whitespace()
                if text.startswith("]", offset):
                    break
                token(",")
            token("]")
            return items
        if text.startswith("void 0", offset):
            offset += 6
            return None
        value, consumed = json.JSONDecoder().raw_decode(text[offset:])
        if isinstance(value, (dict, list)):
            raise ValueError("Unexpected composite")
        offset += consumed
        return cast(JSONValue, value)

    return read()
