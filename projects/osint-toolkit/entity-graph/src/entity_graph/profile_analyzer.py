"""Analizator materiału kandydata profilu: lokalny, bez LLM i bez sieci.

Analizuje WYŁĄCZNIE przekazany tekst (fragment wyniku wyszukiwarki albo tekst dostarczony przez operatora).
Sam adres URL nie jest treścią. Pusty materiał = „brak materiału do analizy”, zero ustaleń.

Zakres zapisu jest POZYTYWNY: tekst materiału jest analizowany w pamięci i nigdy nie jest kopiowany do sprawy
(ani jako fragment, ani jako tytuł). Zapisujemy wyłącznie ustalenia z listy poniżej, a dowodem każdego jest
dokładnie ten krótki fragment, który je stanowi (dopasowany adres, „Nazwa (@nick)”, wzmianka nazwy), z pozycją
w materiale. Materiał można później porównać z kopią operatora po skrócie SHA-256.
  * jawny adres http(s) w tekście (z rozpoznaniem serwisu i klasy adresu) — to PROPOZYCJA do ręcznego otwarcia,
    niczego nie uruchamia; adres z kontaktem, danymi logowania albo sekretem jest pomijany (z przyczyną);
  * identyfikator profilu odczytany z takiego adresu (profile.php?id=, nazwa w ścieżce, @nazwa w Threads);
  * para „Nazwa (@nick)” w formacie fragmentów Instagram/Threads;
  * wzmianka szukanego imienia i nazwiska (porównanie po złożeniu polskich znaków). Zgodność nazwy NIE
    potwierdza tożsamości.
Świadomie NIE wyciąga ani nie zapisuje: zawodu, miejsca pracy lub zamieszkania, treści bio, relacji, ocen osoby,
kontaktów ani danych wrażliwych. To ograniczenie wynika z zakresu zapisu, nie z filtra: moduł nie twierdzi, że
rozpoznaje dane wrażliwe (dowód „Nazwa (@nick)” to dosłowny fragment i może zawierać dowolne słowa z wielkiej litery).
Tekst jest niezaufanymi danymi: polecenia w nim zawarte nie są wykonywane (moduł nie ma żadnych akcji).
"""

from __future__ import annotations

import re
import unicodedata

from .normalize import fold
from .profile_urls import UnsafeUrl, check_url

KIND_SNIPPET = "search_snippet"
KIND_MANUAL = "manual_text"
KIND_LABELS = {
    KIND_SNIPPET: "fragment wyniku wyszukiwarki (nie odczyt całego profilu)",
    KIND_MANUAL: "tekst dostarczony przez operatora (niezweryfikowana kopia strony)",
}
STATUS_EMPTY = "brak materiału do analizy"
STATUS_DONE = {
    KIND_SNIPPET: "przeanalizowano fragment wyszukiwarki (nie cały profil)",
    KIND_MANUAL: "przeanalizowano materiał operatora",
}
MAX_MATERIAL = 20_000
MAX_EVIDENCE = 120
MAX_FINDINGS = 30

F_LINK = "odnośnik w materiale (propozycja do ręcznego otwarcia)"
F_IDENT = "identyfikator profilu z adresu w materiale"
F_HANDLE = "nazwa wyświetlana i @nazwa (format wyniku Instagram/Threads)"
F_NAME = "wzmianka szukanej nazwy (zgodność nazwy nie potwierdza tożsamości)"
METHODS = {
    F_LINK: "wzorzec adresu http(s) + klasyfikacja adresu",
    F_IDENT: "odczyt z adresu w materiale",
    F_HANDLE: "wzorzec 'Nazwa (@nazwa)'",
    F_NAME: "dopasowanie dokładne po złożeniu znaków diakrytycznych",
}

_URL = re.compile(r"https?://[^\s<>\"'\[\]{}|\\^`]+", re.IGNORECASE)
# nazwa = 1-4 słowa od wielkiej litery tuż przed "(@nick)" (np. "...videos from Jan Testowy (@jtestowy)")
_UP = "A-ZÀ-ÖØ-ÞĄĆĘŁŃŚŹŻ"
_HANDLE = re.compile(
    rf"(?P<name>(?:[{_UP}][\w.'’-]*\s){{0,3}}[{_UP}][\w.'’-]*)\s\(@(?P<handle>[A-Za-z0-9._]{{1,30}})\)"
)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def clean_material(raw: object, limit: int = MAX_MATERIAL) -> str:
    """Tekst materiału: NFC, bez znaków sterujących (poza końcami linii i tabulacją). Za długi = błąd, nie cięcie."""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ValueError("materiał: oczekiwano tekstu")  # noqa: TRY004 - wywołujący łapią ValueError
    text = unicodedata.normalize("NFC", raw).replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > limit:
        raise ValueError(f"materiał: najwyżej {limit} znaków (podano {len(text)})")
    return _CTRL.sub(" ", text).strip()


def _evidence(text: str, start: int, end: int) -> str:
    """Dowód = dokładnie dopasowany fragment (bez otoczenia), białe znaki złożone do spacji."""
    span = " ".join(text[start:end].split())
    return span if len(span) <= MAX_EVIDENCE else span[: MAX_EVIDENCE - 1].rstrip() + "…"


def _name_spans(text: str, name: str) -> list[tuple[int, int]]:
    """Pozycje szukanej nazwy w tekście po złożeniu znaków (granice słów). Złożenie liczone znak po znaku, więc
    pozycja w oryginale jest znana także wtedy, gdy złożenie zmienia długość (np. 'ß' -> 'ss')."""
    target = " ".join(fold(name).split())
    if not target:
        return []
    folded, index = [], []
    for i, ch in enumerate(text):
        f = fold(ch)
        folded.append(f)
        index += [i] * len(f)
    spaced = re.sub(r"\s", " ", "".join(folded))
    pattern = r"(?<!\w)" + r"\s+".join(re.escape(w) for w in target.split()) + r"(?!\w)"
    return [(index[m.start()], index[m.end() - 1] + 1) for m in re.finditer(pattern, spaced)]


def analyze(text: object, kind: str, person: str, observed_at: str, source: str) -> dict:
    """-> {"status", "findings": [{kind, value, evidence, position, method, observed_at, source}], "skipped": [...]}.
    Nie zwraca tekstu materiału ani jego wycinków poza dowodami ustaleń."""
    if kind not in KIND_LABELS:
        raise ValueError(f"nieznany rodzaj materiału: {kind}")
    text = clean_material(text)
    if not text:
        return {"status": STATUS_EMPTY, "findings": [], "skipped": []}
    findings: list[dict] = []
    skipped: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()

    def add(fkind: str, value: str, start: int, end: int, **extra) -> None:
        if (fkind, value) in seen or len(findings) >= MAX_FINDINGS:
            return
        seen.add((fkind, value))
        findings.append(
            {
                "kind": fkind,
                "value": value,
                "evidence": _evidence(text, start, end),
                "position": [start, end],
                "method": METHODS[fkind],
                "observed_at": observed_at,
                "source": source,
                **extra,
            }
        )

    for m in _URL.finditer(text):
        raw = m.group(0).rstrip(".,;:!?)")
        try:
            purl = check_url(raw, require_platform=False)
        except ValueError as exc:  # UnsafeUrl: kontakt / logowanie / sekret w adresie; inaczej adres niepoprawny
            why = str(exc) if isinstance(exc, UnsafeUrl) else "adres nieprawidłowy albo z danymi logowania"
            skipped[why] = skipped.get(why, 0) + 1
            continue
        end = m.start() + len(raw)
        add(F_LINK, purl.canonical, m.start(), end, platform=purl.platform, url_class=purl.url_class)
        if purl.identifier:
            ident = purl.identifier
            add(F_IDENT, f"{ident['platform']} {ident['type']}: {ident['value']}", m.start(), end)
    for m in _HANDLE.finditer(text):
        name = " ".join(m.group("name").split())
        add(F_HANDLE, f"{name} (@{m.group('handle')})", m.start("name"), m.end())
    for start, end in _name_spans(text, person)[:1]:
        add(F_NAME, " ".join(text[start:end].split()), start, end)
    return {
        "status": STATUS_DONE[kind],
        "findings": findings,
        "skipped": [{"what": "adres w materiale", "why": why, "count": n} for why, n in sorted(skipped.items())],
    }
