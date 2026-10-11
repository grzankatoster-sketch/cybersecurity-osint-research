"""Normalizacja domen, nazw firm, identyfikatorow (NIP/REGON/KRS) i adresow URL.

Logika domen i URL oraz fold() pochodzi z entity-graph/src/entity_graph/normalize.py, a sumy kontrolne
NIP/REGON z osint-poland/src/osint_poland/web/routes_detect.py (pakiety sie nie importuja nawzajem,
dlatego kod jest skopiowany i dostosowany). KRS nie ma sumy kontrolnej: sprawdzamy tylko format.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TRACKING_PARAMS = {"fbclid", "gclid", "igshid", "mc_cid", "mc_eid", "ref", "ref_src", "si", "feature"}
_NIP_W = (6, 5, 7, 2, 3, 4, 5, 6, 7)
_REGON9_W = (8, 9, 2, 3, 4, 5, 6, 7)
_REGON14_W = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)


def fold(text: str) -> str:
    """'Łukasz Żółć' -> 'lukasz zolc' (ł nie rozkłada się w NFKD, więc osobno)."""
    text = text.replace("ł", "l").replace("Ł", "L")
    norm = unicodedata.normalize("NFKD", text)
    return "".join(c for c in norm if not unicodedata.combining(c)).casefold()


def collapse_spaces(text: str) -> str:
    text = unicodedata.normalize("NFC", str(text))
    text = "".join(c for c in text if unicodedata.category(c) != "Cc" or c in " \t")
    return re.sub(r"\s+", " ", text).strip()


# --- domeny -----------------------------------------------------------------


def normalize_domain(raw: str) -> str:
    """Domena w postaci ASCII (punycode), male litery, bez `www.`, schematu, sciezki, portu i danych logowania.

    Zglasza ValueError dla smieci (puste, jedna etykieta, adres IP, niepoprawne znaki)."""
    d = str(raw or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#\\]", d, maxsplit=1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = re.sub(r":[0-9]*$", "", d).rstrip(".")
    if d.startswith("www.") and d.count(".") >= 2:
        d = d[4:]
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"nieprawidłowa domena: {raw!r}") from exc
    labels = d.split(".")
    if not d or len(d) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels) or labels[-1].isdigit():
        raise ValueError(f"nieprawidłowa domena: {raw!r}")
    return d


def is_same_or_subdomain(candidate: str, parent: str) -> bool:
    return candidate == parent or candidate.endswith("." + parent)


# --- nazwy firm -------------------------------------------------------------

# Kolejnosc ma znaczenie: dluzsze wzorce przed krotszymi. Tokeny po fold() i zamianie interpunkcji na spacje.
_LEGAL_FORMS: list[tuple[tuple[str, ...], str]] = [
    (("spolka", "z", "ograniczona", "odpowiedzialnoscia"), "sp. z o.o."),
    (("sp", "z", "o", "o"), "sp. z o.o."),
    (("sp", "z", "oo"), "sp. z o.o."),
    (("sp", "zoo"), "sp. z o.o."),
    (("spzoo",), "sp. z o.o."),
    (("spolka", "akcyjna"), "s.a."),
    (("s", "a"), "s.a."),
    (("spolka", "komandytowa"), "sp.k."),
    (("sp", "k"), "sp.k."),
    (("spolka", "jawna"), "sp.j."),
    (("sp", "j"), "sp.j."),
]
_STATE_SUFFIXES = [
    ("w", "likwidacji"),
    ("w", "upadlosci"),
    ("w", "restrukturyzacji"),
]
_QUOTES = "\"'„”“‚‘’«»`´"


def _name_tokens(name: str) -> list[str]:
    text = fold(collapse_spaces(name))
    for q in _QUOTES:
        text = text.replace(q, " ")
    text = re.sub(r"[^\w&]+", " ", text.replace("_", " "))
    return text.split()


def split_company_name(name: str) -> tuple[str, list[str]]:
    """-> (rdzen nazwy bez form prawnych, lista form prawnych w postaci ujednoliconej).

    Formy prawne i oznaczenia stanu ("w likwidacji") sa rozpoznawane tylko na koncu nazwy."""
    tokens = _name_tokens(name)
    forms: list[str] = []
    states: list[str] = []
    changed = True
    while changed and tokens:
        changed = False
        for suffix in _STATE_SUFFIXES:
            n = len(suffix)
            if len(tokens) > n and tuple(tokens[-n:]) == suffix:
                states.insert(0, " ".join(suffix))
                tokens = tokens[:-n]
                changed = True
        for pattern, canon in _LEGAL_FORMS:
            n = len(pattern)
            if len(tokens) > n and tuple(tokens[-n:]) == pattern:
                forms.insert(0, canon)
                tokens = tokens[:-n]
                changed = True
                break
    return " ".join(tokens), forms + states


def normalize_company_name(name: str) -> str:
    """Klucz do porownan: nazwa bez diakrytykow, male litery, ujednolicona forma prawna.

    'Example Sp.z o.o.' == 'EXAMPLE spółka z ograniczoną odpowiedzialnością' == 'example sp. z o.o.'."""
    core, forms = split_company_name(name)
    return " ".join(x for x in [core, *forms] if x)


def company_names_match(a: str, b: str) -> bool:
    """Rowne klucze albo rowne rdzenie, gdy ktoras ze stron nie podaje formy prawnej."""
    ca, fa = split_company_name(a)
    cb, fb = split_company_name(b)
    if not ca or not cb:
        return False
    return ca == cb and (fa == fb or not fa or not fb)


# --- status organizacji -------------------------------------------------------

# Mala, zamknieta lista statusow (tekst z rejestru jest zachowywany osobno jako status_raw).
ORG_STATUSES = ("aktywna", "zawieszona", "w_likwidacji", "w_upadlosci", "w_restrukturyzacji", "wykreslona", "inny")


def normalize_org_status(raw) -> str | None:
    """Tekst statusu z rejestru (KRS/CEIDG/REGON) -> jedna wartosc z ORG_STATUSES; pusty -> None.

    Idempotentne dla wartosci z listy. Wykreslenie ma pierwszenstwo przed pozostalymi (np. 'wykreslona z powodu
    likwidacji'); nierozpoznany tekst to 'inny', a nie zgadywanie."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = fold(collapse_spaces(raw)).replace("_", " ")
    if "wykresl" in text or "skresl" in text:
        return "wykreslona"
    for needle, status in (
        ("upadlo", "w_upadlosci"),
        ("likwidac", "w_likwidacji"),
        ("restrukt", "w_restrukturyzacji"),
        ("zawiesz", "zawieszona"),
    ):
        if needle in text:
            return status
    if "nieaktyw" in text or "oczekuje" in text:
        return "inny"
    if "aktyw" in text or "czynn" in text:
        return "aktywna"
    return "inny"


# --- identyfikatory ---------------------------------------------------------


def _digits(raw) -> str:
    return re.sub(r"[\s-]", "", str(raw or ""))


def normalize_nip(raw) -> str | None:
    """NIP 10 cyfr z poprawna suma kontrolna (prefiks PL dozwolony); inaczej None."""
    text = _digits(raw).upper().removeprefix("PL")
    if not re.fullmatch(r"[0-9]{10}", text) or int(text) == 0:
        return None
    s = sum(int(c) * w for c, w in zip(text, _NIP_W, strict=False)) % 11
    return text if s != 10 and s == int(text[9]) else None


def _regon_ok(digits: str, weights: tuple[int, ...]) -> bool:
    s = sum(int(c) * w for c, w in zip(digits, weights, strict=False)) % 11
    return (0 if s == 10 else s) == int(digits[len(weights)])


def normalize_regon(raw) -> str | None:
    """REGON 9 albo 14 cyfr z poprawna suma kontrolna (dlugosc zachowana); inaczej None."""
    text = _digits(raw)
    if re.fullmatch(r"[0-9]{9}", text):
        return text if int(text) and _regon_ok(text, _REGON9_W) else None
    if re.fullmatch(r"[0-9]{14}", text):
        return text if _regon_ok(text[:9], _REGON9_W) and _regon_ok(text, _REGON14_W) else None
    return None


def normalize_krs(raw) -> str | None:
    """KRS: 1-10 cyfr uzupelnione zerami do 10; same zera odrzucone. Brak sumy kontrolnej w numerze KRS."""
    text = _digits(raw)
    if not re.fullmatch(r"[0-9]{1,10}", text) or int(text) == 0:
        return None
    return text.zfill(10)


# --- URL ---------------------------------------------------------------------


def normalize_url(raw: str) -> tuple[str, str]:
    """-> (klucz do deduplikacji, adres do pokazania).

    Usuwa fragment, parametry utm_* i sledzace, koncowy ukosnik, dane logowania i domyslny port; host malymi
    literami. Klucz nie zawiera schematu (http i https to to samo zrodlo)."""
    text = str(raw or "").strip()
    if not text or re.search(r"\s", text):
        raise ValueError(f"nieprawidłowy URL: {raw!r}")
    if "://" not in text:
        raise ValueError(f"nieprawidłowy URL (wymagany schemat http/https): {raw!r}")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"nieprawidłowy URL (tylko http/https): {raw!r}")
    host = parts.hostname.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"nieprawidłowy URL: {raw!r}") from exc
    if not re.fullmatch(r"[a-z0-9._-]+|[0-9a-f:.]+", host):
        raise ValueError(f"nieprawidłowy host w URL: {raw!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"nieprawidłowy URL: {raw!r}") from exc
    netloc = f"[{host}]" if ":" in host else host
    if port and port != {"http": 80, "https": 443}[scheme]:
        netloc += f":{port}"
    path = parts.path.rstrip("/")
    query = urlencode(
        sorted(
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not k.lower().startswith("utm_") and k.lower() not in _TRACKING_PARAMS
        )
    )
    key = netloc + path + (f"?{query}" if query else "")
    return key, f"{scheme}://{key}"
