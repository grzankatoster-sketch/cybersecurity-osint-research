"""Konektor Brave Search API: linki do możliwych profili po imieniu i nazwisku (OFFICIAL_API).

Oficjalne API z WŁASNYM kluczem operatora (nagłówek ``X-Subscription-Token``), bez scrapowania wyszukiwarki,
bez logowania do serwisów i bez pobierania stron z wyników. Jedno wywołanie ``check`` = jedno żądanie HTTP
(stronicowanie wyłączone: ``offset`` nie jest wysyłany). Budżet wywołań, czasu i kandydatów egzekwuje wołający.

Dokumentacja dostawcy (sprawdzona 2026-10-04, api-dashboard.search.brave.com):
  * ``GET https://api.search.brave.com/res/v1/web/search``, autoryzacja nagłówkiem ``X-Subscription-Token``;
  * ``q``: niepuste, najwyżej 600 znaków i 75 słów; ``count``: 1-20; ``offset``: 0-9;
  * wyniki: ``web.results[]`` z ``title``, ``url``, ``description``; limit: HTTP 429 + ``X-RateLimit-*``;
  * operatory ``site:`` i ``"..."`` (oznaczone przez dostawcę jako eksperymentalne).
Kody 401/403/422 nie są opisane na tych stronach: mapowanie poniżej to przyjęte założenie, nie fakt z dokumentacji.

Mapowanie: 200 + wyniki -> FOUND; 200 bez wyników -> NOT_FOUND (brak wyników TEGO zapytania, nie brak kont);
brak klucza -> NotConfigured; 401/403 -> AuthRequired; 429 -> RateLimited; 400/422 -> RequestRejected;
5xx i błąd sieci -> TransportError; zły JSON -> ParseError; inna struktura, dokument błędu, nieznany ``type`` albo
lista samych uszkodzonych rekordów -> SchemaChanged (szczegóły: :func:`parse_response`).

Prywatność: klucz występuje wyłącznie w nagłówku żądania. Imię i nazwisko (cel) nie trafia do Finding; wynik
zawiera tylko zminimalizowane rekordy wyników (adres, tytuł, krótki fragment), bez całej odpowiedzi API.
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlencode

from ..connector import Context, connector
from ..errors import (AuthRequired, ConnectorError, NotConfigured, ParseError, RateLimited, RequestRejected,
                      SchemaChanged, TransportError)
from ..model import Finding, InputKind, SourceKind, Status, Subject

ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
MAX_COUNT = 20                 # dokumentacja: count 1-20
MAX_QUERY_CHARS = 600          # dokumentacja: q najwyżej 600 znaków
MAX_QUERY_WORDS = 75           # dokumentacja: q najwyżej 75 słów
SITES = ("facebook.com", "instagram.com", "threads.com")
MAX_NAME_CHARS = 100
MAX_NAME_WORDS = 6
MAX_CONTEXT_CHARS = 100
MAX_CONTEXT_WORDS = 5
MAX_TITLE = 200
MAX_SNIPPET = 300
MAX_URL = 2048

VARIANT_BASE = "podstawowy"
VARIANT_CONTEXT = "z kontekstem"
VARIANT_ASCII = "bez znaków diakrytycznych"

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# słowo nazwiska: litery, wewnątrz łączniki / apostrofy / kropki (Nowak-Kowalska, O'Brien, Jr.)
_NAME_WORD = re.compile(r"[^\W\d_]+(?:[-'’.][^\W\d_]+)*\.?")
# słowo kontekstu: litery i cyfry, wewnątrz łącznik / kropka / apostrof; żadnych ':' '"' '+' ani '-' na początku
_CONTEXT_WORD = re.compile(r"[^\W_]+(?:[-.'’][^\W_]+)*")
_TAG = re.compile(r"<[^<>]{0,200}>")


@dataclass(frozen=True)
class Query:
    """Jedno zapytanie z planu: tekst dla API, wariant nazwy, serwis i rodzaj wariantu."""

    text: str
    name: str
    site: str
    variant: str


def _clean(raw: object, label: str, max_chars: int) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"{label}: oczekiwano tekstu")
    if _CTRL.search(raw):
        raise ValueError(f"{label}: niedozwolone znaki sterujące")
    text = " ".join(unicodedata.normalize("NFC", raw).split())
    if len(text) > max_chars:
        raise ValueError(f"{label}: najwyżej {max_chars} znaków")
    return text


def validate_name(raw: object) -> str:
    """Imię i nazwisko jako dane: 2-6 słów z liter; bez cudzysłowów, dwukropków i operatorów wyszukiwarki."""
    text = _clean(raw, "imię i nazwisko", MAX_NAME_CHARS)
    words = text.split()
    if len(text) < 3 or not 2 <= len(words) <= MAX_NAME_WORDS:
        raise ValueError(f"imię i nazwisko: 2-{MAX_NAME_WORDS} słów, 3-{MAX_NAME_CHARS} znaków")
    if not all(_NAME_WORD.fullmatch(w) for w in words):
        raise ValueError("imię i nazwisko: tylko litery, spacje oraz '-', \"'\", '.' wewnątrz słów "
                         "(bez cudzysłowów, dwukropków i operatorów wyszukiwarki)")
    return text


def validate_context(raw: object) -> str:
    """Opcjonalny kontekst (np. miasto, firma): do 5 słów, litery i cyfry; zapisywany małymi literami, więc
    operatory logiczne dostawcy (AND/OR/NOT wymagają wielkich liter) nie działają."""
    if raw is None:
        return ""
    text = _clean(raw, "kontekst", MAX_CONTEXT_CHARS)
    if not text:
        return ""
    words = text.split()
    if len(words) > MAX_CONTEXT_WORDS or not all(_CONTEXT_WORD.fullmatch(w) for w in words):
        raise ValueError(f"kontekst: najwyżej {MAX_CONTEXT_WORDS} słów z liter i cyfr (bez ':', '\"', '+', '-' "
                         "na początku słowa)")
    return text.casefold()


def fold_diacritics(text: str) -> str:
    """'Łukasz Żółć' -> 'Lukasz Zolc' (wielkość liter zachowana; ł nie rozkłada się w NFKD)."""
    text = text.replace("ł", "l").replace("Ł", "L")
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def _query(name: str, context: str, site: str, variant: str) -> Query:
    text = f'"{name}" {context + " " if context else ""}site:{site}'
    if len(text) > MAX_QUERY_CHARS or len(text.split()) > MAX_QUERY_WORDS:
        raise ValueError("zapytanie przekracza limit dostawcy (600 znaków, 75 słów)")
    return Query(text, name, site, variant)


def build_queries(name: object, context: object = "") -> list[Query]:
    """Deterministyczny plan: nazwa w cudzysłowie + site: dla każdego serwisu; potem wariant z kontekstem (jeśli
    podany); potem wariant bez znaków diakrytycznych (tylko gdy różni się od oryginału). Zapytania podstawowe są
    zawsze pierwsze, więc kontekst niczego nie wypiera. Warianty nazwy nie są nickami."""
    name = validate_name(name)
    context = validate_context(context)
    plan = [_query(name, "", s, VARIANT_BASE) for s in SITES]
    if context:
        plan += [_query(name, context, s, VARIANT_CONTEXT) for s in SITES]
    ascii_name = fold_diacritics(name)
    if ascii_name != name:
        plan += [_query(ascii_name, "", s, VARIANT_ASCII) for s in SITES]
    return plan


def _plain(raw: object, limit: int) -> str:
    """Tekst z wyniku: bez znaczników HTML (<strong>), encji i znaków sterujących, przycięty."""
    if not isinstance(raw, str):
        return ""
    text = html.unescape(_TAG.sub("", raw))
    text = " ".join(_CTRL.sub(" ", text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


@dataclass(frozen=True)
class Parsed:
    """Wynik walidacji odpowiedzi: poprawne rekordy, flaga dostawcy i liczba odrzuconych (uszkodzonych) rekordów."""

    results: list
    more: bool
    skipped: int


def parse_response(payload: object) -> Parsed:
    """Walidacja otoczki odpowiedzi wyszukiwania (pozytywna, nie "jakikolwiek znany klucz").

    Dokumentacja dostawcy opisuje ``query`` (``original``, ``more_results_available``) oraz ``web.results[]``
    z ``url``, ``title``, ``description``. Wartości ``type`` ani kształtu dokumentu błędu nie opisuje wprost, więc:
      * otoczka = słownik bez klucza ``error``; ``type`` (jeśli jest) musi być ``"search"`` (ZAŁOŻENIE na podstawie
        obserwowanego kształtu odpowiedzi, nie zapis z dokumentacji); musi być ``query`` albo ``web`` jako obiekt;
      * ``query``/``web`` innego typu niż obiekt, ``web`` bez listy ``results`` -> SchemaChanged;
      * poprawna odpowiedź bez sekcji ``web`` = zero wyników (NOT_FOUND tego zapytania);
      * lista mieszana: rekord bez tekstowego ``url`` (albo z niepoprawnym adresem) jest pomijany i liczony
        w ``skipped``; gdy NIEPUSTA lista nie ma ani jednego poprawnego rekordu -> SchemaChanged (nigdy "brak wyników").
    Pola opisowe (``title``, ``description``) innego typu niż tekst dają pusty tekst: rekord z poprawnym adresem zostaje.
    """
    if not isinstance(payload, dict):
        raise SchemaChanged("odpowiedź nie jest obiektem JSON")
    if "error" in payload:
        raise SchemaChanged("dokument błędu dostawcy zamiast wyników wyszukiwania")
    kind = payload.get("type", "search")
    if kind != "search":
        raise SchemaChanged("nieoczekiwany typ odpowiedzi (oczekiwano wyników wyszukiwania)")
    query, web = payload.get("query"), payload.get("web")
    if query is None and web is None:
        raise SchemaChanged("odpowiedź bez sekcji query ani web")
    if query is not None and not isinstance(query, dict):
        raise SchemaChanged("sekcja query ma nieoczekiwany format")
    more = bool(query.get("more_results_available")) if isinstance(query, dict) else False
    if web is None:
        return Parsed([], more, 0)
    if not isinstance(web, dict) or not isinstance(web.get("results"), list):
        raise SchemaChanged("sekcja web.results ma nieoczekiwany format")
    out, skipped = [], 0
    for item in web["results"]:
        url = item.get("url") if isinstance(item, dict) else None
        url = url.strip() if isinstance(url, str) else ""
        if not url or len(url) > MAX_URL or _CTRL.search(url):
            skipped += 1
            continue
        out.append({"url": url, "title": _plain(item.get("title"), MAX_TITLE),
                    "snippet": _plain(item.get("description"), MAX_SNIPPET)})
    if web["results"] and not out:
        raise SchemaChanged("wszystkie rekordy web.results są uszkodzone")
    return Parsed(out, more, skipped)


def parse_results(payload: object) -> tuple[list[dict], bool]:
    """-> (wyniki [{url, title, snippet}], czy dostawca ma więcej wyników); reguły: :func:`parse_response`."""
    parsed = parse_response(payload)
    return parsed.results, parsed.more


@connector
class BraveSearch:
    name = "brave_search"
    source_kind = SourceKind.OFFICIAL_API
    supported_inputs = frozenset({InputKind.PERSON_NAME})

    async def check(self, subject: Subject, ctx: Context) -> Finding:
        if subject.kind is not InputKind.PERSON_NAME:
            raise RequestRejected("brave_search obsługuje tylko imię i nazwisko")
        query = (ctx.extra or {}).get("query")
        name = validate_name(subject.value)
        if not isinstance(query, Query) or query.name not in (name, fold_diacritics(name)):
            raise RequestRejected("zapytanie spoza planu dla tej osoby")
        key = (ctx.extra or {}).get("api_key")
        if not isinstance(key, str) or not key.strip():
            raise NotConfigured("brak klucza BRAVE_SEARCH_API_KEY")
        if ctx.http is None:
            raise NotConfigured("brak klienta HTTP w kontekście")
        count = (ctx.extra or {}).get("count", MAX_COUNT)
        if type(count) is not int or not 1 <= count <= MAX_COUNT:
            raise RequestRejected(f"count: 1-{MAX_COUNT}")
        url = ENDPOINT + "?" + urlencode({"q": query.text, "count": count})
        try:
            resp = await ctx.http.get(url, headers={"Accept": "application/json", "X-Subscription-Token": key},
                                      timeout=ctx.timeout)
        except ConnectorError:
            raise
        except Exception as exc:  # klient spoza pakietu: błąd transportu bez treści (może zawierać adres)
            raise TransportError(f"błąd klienta HTTP ({type(exc).__name__})") from None
        code = getattr(resp, "status_code", None)
        if code == 200:
            try:
                payload = resp.json()
            except Exception:
                raise ParseError("niepoprawny JSON odpowiedzi") from None
            parsed = parse_response(payload)
            results = parsed.results
            return Finding(
                connector=self.name, source=self.source_kind,
                status=Status.FOUND if results else Status.NOT_FOUND,
                confidence=0.0,   # wynik wyszukiwarki nie jest dowodem istnienia konta osoby
                subject_ref="",
                evidence=(f"Brave Search API: {len(results)} wyników" if results else
                          "Brave Search API: brak wyników dla tego zapytania (nie oznacza braku kont)")
                + (f"; pominięto uszkodzone rekordy: {parsed.skipped}" if parsed.skipped else ""),
                extra={"results": results, "http_status": 200, "more_results_available": parsed.more,
                       "skipped_records": parsed.skipped},
            )
        if code in (401, 403):
            raise AuthRequired(f"HTTP {code}: klucz odrzucony albo brak uprawnień")
        if code == 429:
            raise RateLimited("HTTP 429: limit dostawcy")
        if code in (400, 422):
            raise RequestRejected(f"HTTP {code}: dostawca odrzucił zapytanie")
        if isinstance(code, int) and 500 <= code < 600:
            raise TransportError(f"HTTP {code}: błąd po stronie dostawcy")
        raise SchemaChanged(f"nieoczekiwany status HTTP {code}")
