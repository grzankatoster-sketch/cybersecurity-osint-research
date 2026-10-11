"""Normalizacja nazwy domeny (kopia normalize_domain z dns-audit: moduly sa niezalezne)."""

from __future__ import annotations

import re

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":")[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"nieprawidłowa domena: {raw!r}") from exc
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        raise ValueError(f"nieprawidłowa domena: {raw!r}")
    return d
