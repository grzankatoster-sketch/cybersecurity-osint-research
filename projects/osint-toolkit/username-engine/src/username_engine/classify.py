"""Decyzja „czy konto istnieje” z kilku sygnałów.

Różnice względem Blackbirda/Maigreta (patrz ANALIZA_KODU_BLACKBIRD_MAIGRET_2026-10-03.md):
- błąd transportu, limit, CAPTCHA, 5xx → ERROR, nigdy NOT_FOUND;
- puste teksty reguł są ignorowane (w Blackbirdzie pusty m_string blokował trafienie na zawsze);
- reguły „sam kod 2xx” są porównywane ze stroną kontrolną (losowa nazwa) — soft-404 nie daje trafienia;
- reguła, która pasuje także do losowej nazwy, jest oznaczana jako niewiarygodna (ERROR), a nie FOUND;
- przekierowanie poza adres zawierający nazwę oznacza brak konta.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

from .http import _parse_retry_after
from .models import Response, Site, Status

BLOCK_MARKERS = (
    "cf-chl-",
    "challenge-platform",
    "<title>Just a moment...</title>",
    "Attention Required! | Cloudflare",
    "DDoS-Guard",
    "Checking your browser before accessing",
    "hcaptcha.com/1/api.js",
    "Please complete the security check",
)

LOGIN_PATH = re.compile(
    r"/(login|log-in|log_in|signin|sign-in|sign_in|sign_up|signup|auth|authorize|session|sessions|"
    r"accounts/login|uas/login|logowanie|zaloguj)(/|$)", re.IGNORECASE)
PASSWORD_INPUT = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.IGNORECASE)
SEARCH_URL = re.compile(r"[?&](q|query|keyword|search|term|nickname|s)=|/search[/?]", re.IGNORECASE)
SEARCH_PATH = re.compile(r"/(explore|search|tags?|hashtags?|discover)(/|$)", re.IGNORECASE)
CHALLENGE_STATUSES = {403, 503}
DENIED_STATUSES = {401, 403, 407, 451}  # odmowa dostępu: serwis nie pozwolił sprawdzić konta, nie mówi że konta nie ma
SOFT404_LEN_TOLERANCE = 0.05   # strony różniące się długością o <5% po usunięciu nazwy MOGĄ być identyczne...
SOFT404_SIMILARITY = 0.8       # ...ale tylko gdy też ich treść (zbiór słów) pokrywa się w co najmniej 80%
SIMILARITY_CLIP = 20_000       # porównujemy początek i koniec strony (po tyle znaków), nie cały megabajt
ABSENCE_CODES = {404, 410}     # kody, które bez dodatkowej reguły znaczą „brak konta”; inne nietypowe kody to ERROR

Decision = tuple[Status, float, str]

TRUNCATED_REASON = "odpowiedź obcięta (limit rozmiaru): brak tekstu nie dowodzi braku konta"
NEGATIVE_MATCH = "negative_match"    # reguła wprost potwierdziła brak konta (tekst albo kod braku konta)
NO_MATCH_DEFAULT = "no_match_default"  # NOT_FOUND domyślny: brak dopasowania do reguły obecności


def not_found_kind(status: Status, reason: str) -> str | None:
    """Rodzaj uzasadnienia NOT_FOUND: NEGATIVE_MATCH (reguła wprost mówi „brak konta”) albo
    NO_MATCH_DEFAULT (wniosek domyślny). Dla innych statusów zwraca None."""
    if status is not Status.NOT_FOUND:
        return None
    if reason.startswith("tekst braku konta") or reason.startswith("kod braku konta"):
        return NEGATIVE_MATCH
    return NO_MATCH_DEFAULT


def _clean(strings: list[str]) -> list[str]:
    return [s for s in strings if s]


def _blocked(resp: Response, site: Site | None = None) -> str | None:
    """Zwraca opis blokady albo None."""
    if resp.status is None:
        return resp.error or "brak odpowiedzi"
    if resp.status == 429:
        wait = _parse_retry_after(resp.headers.get("Retry-After"))
        hint = f", Retry-After {math.ceil(wait)} s" if wait is not None else ""
        return f"limit zapytań (429{hint}): serwis ograniczył zapytania, to nie dowodzi braku konta"
    if site is not None and site.m_code == resp.status and resp.status >= 500:
        return None  # serwis tak sygnalizuje brak konta (Hejto: 500), reguła mówi to wprost
    if resp.status >= 500 and resp.status != 503:
        return f"błąd serwera ({resp.status})"
    # Cloudflare wstrzykuje skrypt challenge-platform także do zwykłych stron (200/404),
    # więc znaczniki blokady liczą się tylko przy kodach, którymi odpowiada wyzwanie (pomiar 03.10.2026).
    if resp.status in CHALLENGE_STATUSES:
        for marker in BLOCK_MARKERS:
            if marker in resp.text:
                return f"blokada anty-bot ({marker})"
    if resp.status == 503:
        return "błąd serwera (503)"
    # odmowa dostępu bez dopasowania reguły braku konta to ERROR, nie NOT_FOUND (pomiar 03.10.2026: 99 serwisów)
    if resp.status in DENIED_STATUSES and site is not None:
        if site.m_code == resp.status:
            return None
        if any(s in resp.text for s in _clean(site.m_strings)):
            return None
        return f"dostęp zabroniony ({resp.status})"
    return None


def _code_ok(site: Site, status: int) -> bool:
    if site.e_code is not None:
        return status == site.e_code
    return 200 <= status < 300


def _is_search_page(url: str) -> bool:
    return SEARCH_URL.search(url) is not None or SEARCH_PATH.search(urlsplit(url).path) is not None


def _redirected_away(site: Site, resp: Response, username: str) -> bool:
    if not resp.final_url:
        return False
    requested = unquote(site.request_url(username))
    final = unquote(resp.final_url)
    if final.rstrip("/") == requested.rstrip("/"):
        return False
    return username.lower() not in final.lower()


def _redirected_to_search(site: Site, resp: Response, username: str) -> bool:
    """Profil przekierował na wyszukiwarkę serwisu (Giphy: /{nazwa} -> /explore/{nazwa}). Nazwa jest w adresie,
    ale strona pokazuje cudze wyniki, więc jej teksty nie dowodzą konta."""
    if not resp.final_url:
        return False
    requested = unquote(site.request_url(username))
    final = unquote(resp.final_url)
    return final.rstrip("/") != requested.rstrip("/") and _is_search_page(final) and not _is_search_page(requested)


def _login_redirect(resp: Response) -> bool:
    """Wylądowaliśmy na stronie logowania. Sprawdzamy ścieżkę, nie cały URL: '/login?next=/u/alice'
    zawiera nazwę, ale profilu nie pokazuje."""
    if not resp.final_url:
        return False
    return LOGIN_PATH.search(urlsplit(resp.final_url).path) is not None


def _exact_name(text: str, username: str) -> bool:
    """Nazwa jako osobny identyfikator (w cudzysłowie, po @ lub / albo w znaczniku), bez rozróżniania wielkości."""
    pat = r"""(?:["'>/@])""" + re.escape(username) + r"""(?:["'<]|$|@)"""
    return re.search(pat, text, re.IGNORECASE) is not None


def _password_form(text: str) -> bool:
    return PASSWORD_INPUT.search(text) is not None


def _has_presence(text: str, marker: str, username: str) -> bool:
    """Tekst obecności w stronie. Znacznik z {username} musi zawierać sprawdzaną nazwę (bez wielkości liter):
    ogólny znacznik profilu na stronie cudzego konta albo strony zastępczej nie jest trafieniem."""
    if "{username}" not in marker:
        return marker in text
    pattern = re.escape(marker).replace(re.escape("{username}"), re.escape(username))
    if marker.endswith("{username}"):
        # natgeo1 / natgeo.foo must not confirm natgeo; percent encoding can also extend the value.
        pattern += r"(?![A-Za-z0-9._%+\-])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def _evidence(site: Site, resp: Response, username: str) -> Decision | None:
    """Ocena samej odpowiedzi, bez kontroli. None = reguła nie ma tekstów, rozstrzyga kod + kontrola."""
    assert resp.status is not None
    m_strings = _clean(site.m_strings)
    e_strings = _clean(site.e_strings)
    if any(s in resp.text for s in m_strings):
        return Status.NOT_FOUND, 0.0, "tekst braku konta"
    if site.m_code is not None and site.m_code != site.e_code and resp.status == site.m_code:
        return Status.NOT_FOUND, 0.0, f"kod braku konta ({resp.status})"
    if resp.status == 202 and site.e_code != 202:
        return Status.ERROR, 0.0, "wyzwanie anty-bot (202)"
    if _login_redirect(resp):
        return Status.ERROR, 0.0, "wymaga logowania (przekierowanie na logowanie)"
    if not _code_ok(site, resp.status):
        # nierozpoznany kod (400, 405, 5xx...) nie dowodzi braku konta; NOT_FOUND tylko dla jawnie rozpoznanych:
        # 404/410 albo kod 2xx, gdy reguła odróżnia konto po kodzie (e_code), a m_code/m_string obsłużono wyżej
        if resp.status in ABSENCE_CODES or (site.e_code is not None and 200 <= resp.status < 300):
            return Status.NOT_FOUND, 0.0, f"kod {resp.status}"
        return Status.ERROR, 0.0, f"nierozpoznany kod HTTP ({resp.status})"
    if _redirected_away(site, resp, username):
        return Status.NOT_FOUND, 0.0, "przekierowanie poza profil"
    if _redirected_to_search(site, resp, username):
        return Status.NOT_FOUND, 0.0, "przekierowanie na wyszukiwarkę serwisu zamiast profilu"
    if SEARCH_URL.search(site.request_url(username)) and not _exact_name(resp.text, username):
        # wyszukiwarka serwisu zwraca też podobne nazwy (Mastodon ?q=sampler.51 -> 'X-51', 'hitman51')
        if resp.truncated:
            return Status.ERROR, 0.0, TRUNCATED_REASON
        return Status.NOT_FOUND, 0.0, "wyszukiwarka serwisu bez dokładnej nazwy"
    if e_strings:
        if any(_has_presence(resp.text, s, username) for s in e_strings):
            return Status.FOUND, 0.9, "tekst obecności konta"
        if _password_form(resp.text):
            return Status.ERROR, 0.0, "wymaga logowania (formularz hasła zamiast profilu)"
        if resp.truncated:
            return Status.ERROR, 0.0, TRUNCATED_REASON    # tekstu może brakować tylko w uciętej części strony
        if m_strings:
            # reguła zna oba teksty, a strona nie pasuje do żadnego — nie wiemy, co dostaliśmy
            # (pomiar 03.10.2026: przy obciążeniu serwisy oddają inne strony; wcześniej było to „brak”)
            return Status.ERROR, 0.0, "nierozpoznana strona (brak tekstu obecności i braku konta)"
        if site.absence_unproven:
            # serwis nie ma rozpoznawalnej strony „brak konta” (Facebook): zmieniony HTML to nie dowód braku
            return Status.ERROR, 0.0, "nierozpoznana strona: brak tekstu obecności nie dowodzi braku konta"
        return Status.NOT_FOUND, 0.0, "brak tekstu obecności konta"
    return None


def matched_evidence(site: Site, resp: Response, username: str = "") -> list[str]:
    """Teksty obecności konta (e_strings) znalezione w odpowiedzi, w kolejności reguły, bez duplikatów."""
    if resp.status is None:
        return []
    found = []
    for s in _clean(site.e_strings):
        if "{username}" in s and not username:
            continue
        if _has_presence(resp.text, s, username) and s not in found:
            found.append(s)
    return found


def _norm_text(text: str, name: str) -> str:
    """Tekst strony bez nazwy konta (bez rozróżniania wielkości liter), małymi literami."""
    return re.sub(re.escape(name), "", text, flags=re.IGNORECASE).lower() if name else text.lower()


def _title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _clip(text: str) -> str:
    if len(text) <= 2 * SIMILARITY_CLIP:
        return text
    return text[:SIMILARITY_CLIP] + " " + text[-SIMILARITY_CLIP:]


def _similarity(a: str, b: str) -> float:
    """Pokrycie zbiorów słów (multizbiór): 1.0 = te same słowa w tych samych ilościach."""
    wa, wb = Counter(re.findall(r"\w+", _clip(a))), Counter(re.findall(r"\w+", _clip(b)))
    total = max(sum(wa.values()), sum(wb.values()))
    if total == 0:
        return 1.0
    return sum((wa & wb).values()) / total


def _same_page(a: Response, a_name: str, b: Response, b_name: str) -> bool:
    """Czy dwie odpowiedzi to ta sama strona (soft-404). Sama zbliżona długość nie wystarcza: potrzebna jest też
    zgodność treści i tytułu. Odpowiedzi obcięte mają tę samą długość z definicji — rozstrzyga tylko treść."""
    if a.status != b.status:
        return False
    ta, tb = _norm_text(a.text, a_name), _norm_text(b.text, b_name)
    if not (a.truncated or b.truncated):
        longest = max(len(ta), len(tb))
        if longest == 0:
            return True
        if abs(len(ta) - len(tb)) / longest >= SOFT404_LEN_TOLERANCE:
            return False
    title_a, title_b = _norm_text(_title(a.text), a_name), _norm_text(_title(b.text), b_name)
    if title_a and title_b and title_a != title_b:
        return False
    return _similarity(ta, tb) >= SOFT404_SIMILARITY


def classify(
    site: Site,
    resp: Response,
    username: str,
    control: Response | None = None,
    control_name: str | None = None,
) -> Decision:
    """Status, pewność 0–1 i uzasadnienie dla jednej odpowiedzi serwisu."""
    blocked = _blocked(resp, site)
    if blocked:
        return Status.ERROR, 0.0, blocked

    decision = _evidence(site, resp, username)
    control_ok = control is not None and control_name is not None and _blocked(control, site) is None

    if decision is not None:
        status, conf, reason = decision
        if status is Status.FOUND and control_ok:
            c_decision = _evidence(site, control, control_name)
            if c_decision is not None and c_decision[0] is Status.FOUND:
                return Status.ERROR, 0.0, "reguła niewiarygodna: pasuje też do losowej nazwy"
            if c_decision is not None and c_decision[0] is Status.NOT_FOUND:
                conf = 0.97                       # tylko jednoznaczny brak konta dla nazwy kontrolnej podnosi pewność
                reason += " + kontrola potwierdza"
            else:
                reason += " (kontrola niejednoznaczna)"   # np. strona logowania, ERROR: nie podnosi pewności
        if status is Status.FOUND and username.lower() in resp.text.lower():
            conf = min(0.99, conf + 0.02)
        return status, conf, reason

    if resp.truncated and _clean(site.m_strings) and not _clean(site.e_strings):
        return Status.ERROR, 0.0, TRUNCATED_REASON    # tekstu braku konta mogło brakować tylko w uciętej części
    # reguła bez tekstów: kod HTTP był „dobry”, rozstrzyga porównanie z kontrolą
    if control_ok and control.status != resp.status and not _same_page(resp, username, control, control_name):
        # mocny dowód; formularz logowania w nagłówku strony go nie unieważnia (rosyjskie fora, pomiar 03.10.2026)
        return Status.FOUND, 0.8, f"kod {resp.status} vs kontrola {control.status}"
    if _password_form(resp.text):
        return Status.ERROR, 0.0, "wymaga logowania (formularz hasła zamiast profilu)"
    if not control_ok:
        why = "brak kontroli" if control is None else "kontrola nieudana"
        return Status.FOUND, 0.45, f"tylko kod HTTP ({why})"
    if _same_page(resp, username, control, control_name):
        return Status.NOT_FOUND, 0.0, "strona jak dla losowej nazwy (soft-404)"
    # sama różnica długości jest słaba: dynamiczne strony różnią się między zapytaniami
    # (8 z 9 fałszywych trafień w pomiarze 03.10.2026 pochodziło z tej gałęzi)
    return Status.FOUND, 0.5, "strona różni się od kontrolnej"
