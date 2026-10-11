"""Wspolne typy: waga ustalenia i ustalenie."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    OK = "OK"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"

    @property
    def rank(self) -> int:
        return _RANK[self.value]


_RANK = {"OK": 0, "INFO": 1, "WARN": 2, "FAIL": 3}


@dataclass(frozen=True)
class Finding:
    area: str
    severity: Severity
    title: str
    recommendation: str = ""
