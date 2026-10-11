"""Prywatność: haszowanie identyfikatora celu.

Naprawia wyciek z audytu (holehe zapisywał e-mail celu w nazwie pliku CSV i
drukował go wprost). Tutaj surowy identyfikator nigdy nie trafia do Finding,
logów ani eksportu — zamiast niego używamy ``subject_ref`` = HMAC-SHA256 z solą
per-sprawa.
"""
from __future__ import annotations

import hashlib
import hmac

from .model import Subject


def subject_ref(subject: Subject, salt: str) -> str:
    """Zwróć stabilny, niewrażliwy identyfikator celu.

    Normalizacja: trim + lower, aby ten sam cel dawał ten sam ref. Sól (klucz
    HMAC) powinna być tajna i różna per sprawa — bez niej hash e-maila jest
    trywialnie odwracalny słownikiem.
    """
    if not salt:
        raise ValueError("salt (klucz per-sprawa) jest wymagany")
    norm = subject.value.strip().lower()
    key = salt.encode("utf-8")
    msg = f"{subject.kind.value}:{norm}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
