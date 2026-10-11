"""Skan jednej nazwy w wielu serwisach."""
from __future__ import annotations

import asyncio
import functools
import json
import re
import secrets
import string
from collections import Counter
from typing import Any, AsyncContextManager, Awaitable, Callable, Protocol
from urllib.parse import quote_plus
from xml.sax.saxutils import escape as xml_escape

from .classify import classify, matched_evidence, not_found_kind
from .extract import extract_profile
from .http import PROXY_DOWN
from .models import ABORT_REASON, Response, Result, Site, Status

CONTROL_MODES = ("auto", "all", "none")
MAX_REGEX_LEN = 500        # dłuższe wzorce z bazy odrzucamy (baza jest niezaufanym wejściem)
MAX_NAME_LEN = 128         # dłuższych nazw nie dopasowujemy do wzorców
CONTROL_LENGTHS = (14, 10, 8, 6, 4, 3)   # długości nazwy kontrolnej próbowane po kolei (reguły z limitem znaków)
INSECURE_MAX_CONF = 0.6    # pewność trafienia z odpowiedzi bez weryfikacji TLS nie przekracza tej wartości
_QUANT_RE = re.compile(r"\{(\d*)(,?)(\d*)\}")


class FetcherLike(Protocol):
    async def fetch(self, method: str, url: str, headers: dict | None = None, body: str | None = None) -> Response: ...


# fabryka kanału: każde wywołanie daje NOWY Fetcher (async context manager), np. z nowym obwodem Tora
FetcherFactory = Callable[[], AsyncContextManager[Any]]
CHANNELS = ("direct", "proxy", "proxy-retry", "fallback")
PROXY_ABORT_AFTER = 15     # tyle kolejnych wyników „proxy martwe” przerywa skan (bez proxy bezpiecznik jest wyłączony)


class ScanResults(list):
    """Lista wyników (jak dotąd) + informacja, czy skan przerwano z powodu martwego proxy.
    `aborted`: bezpiecznik zadziałał; `skipped`: ile serwisów zastąpiono wynikiem ERROR (ABORT_REASON) bez zapytania."""
    aborted: bool = False
    skipped: int = 0


def random_name(length: int = 14) -> str:
    """Losowa nazwa kontrolna: zaczyna się literą, same małe litery i cyfry (pasuje do większości regexów)."""
    alphabet = string.ascii_lowercase + string.digits
    return secrets.choice(string.ascii_lowercase) + "".join(secrets.choice(alphabet) for _ in range(max(1, length) - 1))


_ALNUM = string.ascii_letters + string.digits
_DELIMS = string.punctuation + " "


def _atoms(body: str) -> list[tuple[str, bool]]:
    """Atomy wzorca (znak, [klasa], escape) z informacją, czy zaraz za nimi stoi kwantyfikator."""
    out: list[tuple[str, bool]] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            atom, i = body[i:i + 2], i + 2
        elif c == "[":
            j = i + 1
            if j < n and body[j] == "^":
                j += 1
            if j < n and body[j] == "]":
                j += 1
            while j < n and body[j] != "]":
                j += 2 if body[j] == "\\" else 1
            atom, i = body[i:j + 1], j + 1
        elif c in "()|^$?+*":
            i += 1
            if c in "?+*" and out:
                out[-1] = (out[-1][0], True)
            continue
        elif c == "{":
            m = _QUANT_RE.match(body, i)
            if m and out:
                out[-1] = (out[-1][0], True)
                i = m.end()
                continue
            atom, i = c, i + 1
        else:
            atom, i = c, i + 1
        out.append((atom, False))
    return out


def _matches(atom: str, ch: str) -> bool:
    try:
        return re.fullmatch(atom, ch) is not None
    except re.error:
        return True


def _delimiter_led(body: str) -> bool:
    """Grupa typu (-[a-z0-9]+)* : zaczyna się obowiązkowym znakiem-separatorem (interpunkcja), którego reszta grupy
    nie potrafi dopasować — iteracje są jednoznaczne, więc nie ma wykładniczego nawrotu."""
    if "|" in body:
        return False
    atoms = _atoms(body)
    if len(atoms) < 2 or atoms[0][1]:
        return False
    first = atoms[0][0]
    if any(_matches(first, ch) for ch in _ALNUM):
        return False
    delims = [ch for ch in _DELIMS if _matches(first, ch)]
    return bool(delims) and not any(_matches(a, ch) for a, _ in atoms[1:] for ch in delims)


def has_nested_quantifier(pattern: str) -> bool:
    """Heurystyka ReDoS (bez zewnętrznego silnika regex z limitem czasu): grupa z nieograniczonym kwantyfikatorem
    w środku (+, *, {n,}), która sama ma taki kwantyfikator: (a+)+, (a*)*, (a+)*, (a*)+, (?:x+y)*.
    Wyjątek: grupa zaczynająca się jednoznacznym separatorem, np. (?:[._-][a-z0-9]+)* — jest bezpieczna."""
    def unbounded_at(i: int) -> tuple[bool, int]:
        """Czy w pozycji i stoi nieograniczony kwantyfikator; zwraca (czy, pozycja za nim)."""
        if i >= len(pattern):
            return False, i
        c = pattern[i]
        if c in "+*":
            end = i + 1
        elif c == "{":
            m = _QUANT_RE.match(pattern, i)
            if not m or not (m.group(1) or m.group(3)):
                return False, i
            if m.group(2) and not m.group(3):
                end = m.end()
            else:
                return False, m.end()
        else:
            return False, i
        if end < len(pattern) and pattern[end] in "?+":      # leniwy / dzierżawczy
            end += 1
        return True, end

    stack: list[list] = []      # [czy w środku jest nieograniczony kwantyfikator, początek treści grupy]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
        elif c == "[":
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
        elif c == "(":
            i += 1
            if pattern.startswith("?P<", i):
                i = pattern.find(">", i) + 1 or n
            elif pattern.startswith(("?<=", "?<!"), i):
                i += 3
            elif pattern.startswith("?", i):
                if pattern[i + 1:i + 2] in (":", "=", "!"):
                    i += 2
                else:                                   # flagi inline, np. (?i)
                    while i < n and pattern[i] not in ":)":
                        i += 1
                    i += pattern[i:i + 1] == ":"
            stack.append([False, i])
        elif c == ")":
            inner, start = stack.pop() if stack else (False, i)
            q, end = unbounded_at(i + 1)
            if q and inner and not _delimiter_led(pattern[start:i]):
                return True
            if stack and (inner or q):
                stack[-1][0] = True
            i = end if q else i + 1
        else:
            q, end = unbounded_at(i)
            if q:
                if stack:
                    stack[-1][0] = True
                i = end
            else:
                i += 1
    return False


@functools.lru_cache(maxsize=4096)
def _compiled(pattern: str):
    try:
        return re.compile(pattern)
    except re.error:
        return None


def regex_problem(site: Site) -> str | None:
    """Powód odrzucenia wzorca nazwy z bazy (zbyt długi / ryzykowny) albo None."""
    if not site.regex:
        return None
    if len(site.regex) > MAX_REGEX_LEN:
        return f"wzorzec nazwy z bazy odrzucony (dłuższy niż {MAX_REGEX_LEN} znaków)"
    if has_nested_quantifier(site.regex):
        return "wzorzec nazwy z bazy odrzucony (zagnieżdżone kwantyfikatory, ryzyko zawieszenia)"
    return None


def name_problem(site: Site, username: str) -> str | None:
    """Powód, dla którego nazwy nie sprawdzamy w serwisie (UNSUPPORTED), albo None."""
    if len(username) > MAX_NAME_LEN:
        return f"nazwa dłuższa niż {MAX_NAME_LEN} znaków"
    problem = regex_problem(site)
    if problem:
        return problem
    if site.regex:
        compiled = _compiled(site.regex)
        if compiled is not None and compiled.search(username) is None:   # zepsuty regex nie blokuje sprawdzenia
            return "nazwa niezgodna z formatem serwisu"
    return None


def name_allowed(site: Site, username: str) -> bool:
    return name_problem(site, username) is None


def control_name_for(site: Site) -> str | None:
    """Losowa nazwa kontrolna zgodna z regułą serwisu (długość 14, potem krótsze); None = kontrola niemożliwa."""
    for length in CONTROL_LENGTHS:
        for _ in range(3):
            name = random_name(length)
            if name_allowed(site, name):
                return name
    return None


def needs_control(site: Site, mode: str) -> bool:
    if mode == "all":
        return True
    if mode == "none":
        return False
    return not any(site.e_strings)  # auto: tylko słabe reguły (bez tekstu obecności)


def _render(template: str | None, username: str, headers: dict | None = None) -> str | None:
    """Treść POST z nazwą wstawioną z escapowaniem właściwym dla Content-Type (nazwa nie psuje JSON-a ani formularza)."""
    if template is None:
        return None
    ctype = next((v for k, v in (headers or {}).items() if k.lower() == "content-type"), "").lower()
    head = template.lstrip()[:1]
    if "json" in ctype or (not ctype and head in ("{", "[")):
        fragment = json.dumps(username)[1:-1]            # fragment wewnątrz cudzysłowu JSON
    elif "x-www-form-urlencoded" in ctype or (not ctype and "=" in template and head not in ("{", "[", "<")):
        fragment = quote_plus(username)
    elif "xml" in ctype or (not ctype and head == "<"):
        fragment = xml_escape(username)
    else:
        fragment = username
    return template.replace("{username}", fragment)


async def check_site(site: Site, username: str, fetcher: FetcherLike, control: str = "auto") -> Result:
    url = site.profile_url(username)
    problem = name_problem(site, username)
    if problem:
        return Result(site.name, url, Status.UNSUPPORTED, reason=problem)

    async def get(name: str) -> Response:
        return await fetcher.fetch(site.method, site.request_url(name), site.headers,
                                   _render(site.body, name, site.headers))

    control_name = control_resp = None
    control_impossible = False
    if needs_control(site, control):
        control_name = control_name_for(site)
        control_impossible = control_name is None
    if control_name:
        resp, control_resp = await asyncio.gather(get(username), get(control_name))
    else:
        resp = await get(username)

    insecure = resp.insecure or (control_resp is not None and control_resp.insecure)
    status, confidence, reason = classify(site, resp, username, control_resp, control_name)
    if status is Status.FOUND and control_resp is None and control != "none":
        # kontrola „na żądanie”: reguły z tekstem obecności sprawdzamy losową nazwą dopiero przy trafieniu
        # (tanio — trafień jest kilkanaście). Pomiar 03.10.2026: reguła wiki pasowała do każdej nazwy.
        lazy_name = control_name_for(site)
        if lazy_name:
            lazy_resp = await get(lazy_name)
            insecure = insecure or lazy_resp.insecure
            status, confidence, reason = classify(site, resp, username, lazy_resp, lazy_name)
        else:
            control_impossible = True
    kind = not_found_kind(status, reason)
    if status is Status.FOUND and control_impossible and control != "none":
        reason += " [kontrola niemożliwa: nazwa nie spełnia reguły serwisu]"
    if insecure:
        reason += " [certyfikat nieważny, TLS bez weryfikacji]"
        if status is Status.FOUND:
            confidence = min(confidence, INSECURE_MAX_CONF)
    profile = {}
    evidence = []
    if status is Status.FOUND:
        if not insecure:      # odpowiedź bez weryfikacji TLS bywa podmieniona — nie wyciągamy z niej danych profilu
            try:
                profile = extract_profile(resp.text, resp.headers.get("Content-Type", ""), username)
            except Exception:
                profile = {}  # ekstrakcja jest dodatkiem — nie może zepsuć wyniku
        evidence = matched_evidence(site, resp, username)
    return Result(site.name, url, status, confidence, reason, resp.status, profile, evidence, kind, insecure)


async def scan(
    username: str,
    sites: list[Site],
    fetcher: FetcherLike,
    control: str = "auto",
    concurrency: int = 50,
    on_result: Callable[[Result], Awaitable[None] | None] | None = None,
    channel: str = "direct",
    abort_after: int | None = PROXY_ABORT_AFTER,
) -> ScanResults:
    """Skan nazwy w serwisach. Bezpiecznik (tylko kanały przez proxy, nie „direct”): `abort_after` kolejnych wyników
    z PROXY_DOWN = proxy padło, więc nie planujemy dalszych sprawdzeń; reszta to ERROR z ABORT_REASON (nigdy
    NOT_FOUND), a `.aborted` zwróconej listy jest True. `abort_after` 0/None wyłącza bezpiecznik."""
    if control not in CONTROL_MODES:
        raise ValueError(f"control musi być jednym z {CONTROL_MODES}")
    sem = asyncio.Semaphore(concurrency)
    breaker = bool(abort_after) and abort_after > 0 and channel != "direct"
    state = {"streak": 0, "tripped": False, "skipped": 0}

    async def one(site: Site) -> Result:
        async with sem:
            if state["tripped"]:                      # proxy martwe: bez żadnego zapytania
                url = site.profile_url(username)
                problem = name_problem(site, username)
                if problem:
                    result = Result(site.name, url, Status.UNSUPPORTED, reason=problem)
                else:
                    result = Result(site.name, url, Status.ERROR, reason=ABORT_REASON)
                    state["skipped"] += 1
                result.channel = channel
                if on_result:
                    maybe = on_result(result)
                    if asyncio.iscoroutine(maybe):
                        await maybe
                return result
            try:
                result = await check_site(site, username, fetcher, control)
            except asyncio.CancelledError:
                # anulowanie samego fetchera (np. wewnętrzny gather) nie może przerwać
                # całego skanu; realne anulowanie z zewnątrz (cancelling() > 0) idzie dalej
                if asyncio.current_task().cancelling() == 0:
                    result = Result(site.name, site.profile_url(username), Status.ERROR, reason="wyjątek: CancelledError")
                else:
                    raise
            except Exception as e:  # błąd jednego serwisu nie może zniknąć ani przerwać skanu
                result = Result(site.name, site.profile_url(username), Status.ERROR, reason=f"wyjątek: {type(e).__name__}")
        result.channel = channel
        if breaker:
            if result.status is Status.ERROR and result.reason.startswith(PROXY_DOWN):
                state["streak"] += 1
                if state["streak"] >= abort_after:
                    state["tripped"] = True
            else:
                state["streak"] = 0
        if on_result:
            maybe = on_result(result)
            if asyncio.iscoroutine(maybe):
                await maybe
        return result

    out = ScanResults(await asyncio.gather(*(one(s) for s in sites)))
    out.aborted, out.skipped = state["tripped"], state["skipped"]
    return out


async def rescan_errors(
    username: str,
    sites: list[Site],
    results: list[Result],
    fresh: FetcherFactory | None,
    fallback: FetcherFactory | None = None,
    retries: int = 2,
    control: str = "auto",
    concurrency: int = 50,
    on_round: Callable[[str, int], None] | None = None,
    on_recovered: Callable[[Result], None] | None = None,
) -> ScanResults:
    """Ponowne sprawdzenie błędów SIECIOWYCH kanałem proxy (pomiar przez Tora: ~17% rozstrzygających wyników ginie).
    Do `retries` rund na NOWYM Fetcherze z `fresh` (nowy obwód, kanał „proxy-retry”), potem jedna runda przez
    `fallback` (drugie proxy, kanał „fallback”). ERROR zastępujemy tylko wynikiem, który nim nie jest; UNSUPPORTED
    nie ponawiamy; martwe proxy (PROXY_DOWN) nie jest młotkowane rundami na tym samym proxy. Nigdy nie wracamy do
    ruchu bezpośredniego: bez `fresh` i `fallback` nic się nie dzieje. `on_round(kanał, liczba)` i `on_recovered(wynik)` — tylko do komunikatów.

    Ponawiamy WYŁĄCZNIE błędy transportu (serwis nie odpowiedział: `http_status is None` — timeout, DNS, połączenie,
    awaria proxy). Odpowiedź serwera sklasyfikowana jako ERROR — odmowa dostępu 401/403/451, limit 429, CAPTCHA,
    wymóg logowania, 5xx — NIE jest ponawiana: zmiana obwodu/tożsamości po blokadzie to obchodzenie zabezpieczeń
    (sprzeczne z guardrails), a 429 trzeba uszanować. Takie wyniki zostają w dzienniku bez zmiany tożsamości."""
    out = ScanResults(results)
    out.aborted = getattr(results, "aborted", False)
    out.skipped = getattr(results, "skipped", 0)
    by_name = {s.name: s for s in sites}

    def pending(skip_dead_proxy: bool) -> list[int]:
        # tylko awarie transportu (brak odpowiedzi serwera); 403/429/CAPTCHA/5xx mają http_status i nie są ponawiane
        return [i for i, r in enumerate(out) if r.status is Status.ERROR and r.site in by_name
                and r.http_status is None
                and not (skip_dead_proxy and r.reason.startswith(PROXY_DOWN))]

    async def one_round(factory: FetcherFactory, idx: list[int], channel: str) -> None:
        async with factory() as fetcher:
            fresh_results = await scan(username, [by_name[out[i].site] for i in idx], fetcher, control,
                                       concurrency, channel=channel)
        out.aborted = out.aborted or getattr(fresh_results, "aborted", False)
        for i, new in zip(idx, fresh_results):
            if new.status is not Status.ERROR:
                out[i] = new
                if on_recovered:
                    on_recovered(new)

    rounds = max(0, retries) if fresh is not None else 0
    for _ in range(rounds):
        if out.aborted:
            break
        idx = pending(skip_dead_proxy=True)
        if not idx:
            break
        if on_round:
            on_round("proxy-retry", len(idx))
        await one_round(fresh, idx, "proxy-retry")
    if fallback is not None and not out.aborted:
        idx = pending(skip_dead_proxy=False)
        if idx:
            if on_round:
                on_round("fallback", len(idx))
            await one_round(fallback, idx, "fallback")
    return out


def channel_counts(results: list[Result]) -> dict[str, int]:
    """Ile wyników sprawdzono którym kanałem (tylko niezerowe)."""
    counts = Counter(r.channel for r in results)
    return {c: counts[c] for c in CHANNELS if counts.get(c)} | {c: n for c, n in counts.items() if c not in CHANNELS}


def summarize(results: list[Result]) -> dict:
    by_status = Counter(r.status.value for r in results)
    errors = Counter(r.reason.split(" (")[0] for r in results if r.status is Status.ERROR)
    return {
        "checked": len(results),
        "found": by_status.get("FOUND", 0),
        "not_found": by_status.get("NOT_FOUND", 0),
        "error": by_status.get("ERROR", 0),
        "unsupported": by_status.get("UNSUPPORTED", 0),
        "top_errors": errors.most_common(5),
        "not_found_explicit": sum(1 for r in results if r.not_found_kind == "negative_match"),
        "channels": channel_counts(results),
    }
