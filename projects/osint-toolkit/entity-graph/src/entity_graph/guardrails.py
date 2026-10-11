"""Zabezpieczenia obowiązkowe: cel badania (--purpose) i dziennik audytu (kto/kiedy/po co/co).

Dziennik to plik JSONL tylko do dopisywania; każdy wpis zawiera skrót SHA-256 poprzedniego wpisu (łańcuch),
więc późniejsza edycja lub usunięcie wpisu z środka jest wykrywalne (verify_audit). Pierwszy wpis powstaje
PRZED jakimkolwiek zapytaniem; gdy nie da się go zapisać, badanie się nie zaczyna.
Dziennik nie zawiera sekretów: wartości z kluczami API nie są do niego przekazywane."""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import re
from pathlib import Path

from . import __version__
from .model import utc_now

MIN_PURPOSE_CHARS = 12
MIN_PURPOSE_WORDS = 2
_PLACEHOLDERS = {"test", "testy", "xxx", "asdf", "none", "brak", "n/a", "na", "todo", "tbd", "purpose"}
GENESIS = "0" * 64

# Co narzędzie świadomie NIE robi. Używane w raporcie i testach; to nie jest lista do wyłączenia.
EXCLUDED_CAPABILITIES = (
    "wyszukiwanie osoby po numerze telefonu (CallApp, Truecaller, Sync.me i podobne)",
    "omijanie logowania, rozwiązywanie CAPTCHA, podrabianie odcisku przeglądarki i rotacja IP po blokadzie "
    "w celu obejścia zabezpieczeń (dozwolone jest tylko stałe proxy chroniące tożsamość badacza, np. Tor, i tylko przy "
    "poprawnej konfiguracji: przy błędzie proxy/Tora skan zatrzymuje się, a nie jedzie dalej bez ochrony, "
    "czyli fail-closed; rotacja IP po blokadzie i podrabianie odcisku przeglądarki są zabronione)",
    "scrapowanie wyszukiwarek i prywatnych lub nieoficjalnych API",
    "geolokalizacja osoby na podstawie adresu IP (tylko to, co publicznie podaje RDAP/ASN: organizacja, kraj)",
)


class GuardrailError(ValueError):
    """Naruszenie zasad (np. brak celu badania). Komunikat jest bezpieczny do pokazania użytkownikowi."""


def validate_purpose(purpose: str | None) -> str:
    text = re.sub(r"\s+", " ", (purpose or "")).strip()
    words = [w for w in re.split(r"\s+", text) if w]
    if (len(text) < MIN_PURPOSE_CHARS or len(words) < MIN_PURPOSE_WORDS
            or text.lower() in _PLACEHOLDERS or not re.search(r"[^\W\d_]{3}", text)):
        raise GuardrailError(
            f"--purpose jest wymagany: opisz cel i podstawę badania (min. {MIN_PURPOSE_WORDS} słowa, "
            f"{MIN_PURPOSE_CHARS} znaków), np. 'audyt własnej infrastruktury firmy X, zlecenie 2026/14'."
        )
    return text


def current_operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - brak użytkownika w środowisku nie może blokować (ale zostaje ślad)
        return "nieznany"


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class AuditLog:
    """Dopisuje wpisy JSONL z łańcuchem skrótów."""

    def __init__(self, path: str | Path, operator: str | None = None):
        self.path = Path(path)
        self.operator = operator or current_operator()
        self._prev = GENESIS
        if self.path.exists():
            lines = [ln for ln in self.path.read_text(encoding="utf-8").split("\n") if ln.strip()]
            if lines:
                self._prev = _line_hash(lines[-1])

    def write(self, event: str, **fields) -> dict:
        entry = {"ts": utc_now(), "event": event, "operator": self.operator, **fields, "prev": self._prev}
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._prev = _line_hash(line)
        return entry

    def start(self, purpose: str, inputs: list[dict], options: dict, case_ref: str = "") -> dict:
        return self.write(
            "start", purpose=purpose, case_ref=case_ref, inputs=inputs, options=options,
            host=platform.node(), tool=f"entity-graph {__version__}",
        )


def verify_audit(path: str | Path) -> tuple[bool, str]:
    """Sprawdza ciągłość łańcucha skrótów. -> (ok, opis)."""
    prev = GENESIS
    try:
        lines = [ln for ln in Path(path).read_text(encoding="utf-8").split("\n") if ln.strip()]
    except OSError as exc:
        return False, f"nie można odczytać: {exc}"
    if not lines:
        return False, "dziennik jest pusty"
    for i, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, f"wpis {i}: uszkodzony JSON"
        if entry.get("prev") != prev:
            return False, f"wpis {i}: przerwany łańcuch skrótów (wpis zmieniony lub usunięty)"
        prev = _line_hash(line)
    first = json.loads(lines[0])
    if first.get("event") != "start" or not first.get("purpose"):
        return False, "pierwszy wpis nie jest wpisem 'start' z celem badania"
    return True, f"{len(lines)} wpisów, łańcuch spójny"
