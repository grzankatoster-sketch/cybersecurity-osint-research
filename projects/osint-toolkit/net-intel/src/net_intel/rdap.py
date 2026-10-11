"""RDAP domeny: bootstrap IANA -> serwer rejestru, fallback rdap.org.

Z odpowiedzi czytamy WYŁĄCZNIE dane techniczne i nazwę rejestratora (registrar). Dane kontaktowe
(vcard rejestrującego, administracyjnego, technicznego, abuse) nie są nigdzie odczytywane ani wypisywane.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from .http import Fetch, FetchError
from .models import Finding, Severity

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
FALLBACK_URL = "https://rdap.org/domain/{domain}"
RDAP_HEADERS = {"Accept": "application/rdap+json, application/json;q=0.9"}

WARN_DAYS = 30
FAIL_DAYS = 7
_HOLD = {"clienthold", "serverhold"}
_DELETING = {"pendingdelete", "redemptionperiod"}


class RdapError(Exception):
    """Nie udało się ustalić odpowiedzi RDAP (komunikat bezpieczny do pokazania)."""


class Bootstrap:
    """Bootstrap IANA pobierany co najwyżej raz w trakcie jednego uruchomienia (cache w pamięci)."""

    def __init__(self, fetch: Fetch, timeout: float):
        self._fetch, self._timeout = fetch, timeout
        self._data: dict[str, list[str]] | None = None
        self._error: str | None = None

    def _load(self) -> dict[str, list[str]]:
        if self._data is not None:
            return self._data
        if self._error is not None:
            raise RdapError(self._error)
        try:
            resp = self._fetch(BOOTSTRAP_URL, headers={"Accept": "application/json"}, timeout=self._timeout)
            if resp.status != 200:
                raise RdapError(f"bootstrap IANA: HTTP {resp.status}")
            raw = json.loads(resp.text)
            table: dict[str, list[str]] = {}
            for entry in raw["services"]:
                tlds, urls = entry[0], entry[1]
                for tld in tlds:
                    table[str(tld).lower()] = [str(u) for u in urls]
        except FetchError as exc:
            self._error = f"bootstrap IANA: {exc}"
            raise RdapError(self._error) from None
        except RdapError as exc:
            self._error = str(exc)
            raise
        except (ValueError, KeyError, IndexError, TypeError):
            self._error = "bootstrap IANA: nieprawidłowy format"
            raise RdapError(self._error) from None
        self._data = table
        return table

    def base_url(self, domain: str) -> str | None:
        """Adres serwera RDAP dla TLD domeny (None, gdy TLD nie ma w bootstrapie)."""
        table = self._load()
        labels = domain.split(".")
        for i in range(len(labels)):  # najdłuższy sufiks najpierw (bootstrap zwykle ma same TLD)
            urls = table.get(".".join(labels[i:]))
            if urls:
                https = [u for u in urls if u.lower().startswith("https://")]
                return (https or urls)[0]
        return None


@dataclass
class RdapResult:
    domain: str
    found: bool = True
    source: str = ""          # host serwera, z którego pochodzi odpowiedź
    registrar: str | None = None
    registrar_iana_id: str | None = None
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    status: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    dnssec_signed: bool | None = None
    days_to_expiry: int | None = None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain, "found": self.found, "source": self.source,
            "registrar": self.registrar, "registrar_iana_id": self.registrar_iana_id,
            "created": self.created, "updated": self.updated, "expires": self.expires,
            "days_to_expiry": self.days_to_expiry, "status": self.status,
            "nameservers": self.nameservers, "dnssec_delegation_signed": self.dnssec_signed,
        }


def parse_dt(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _registrar(data: dict) -> tuple[str | None, str | None]:
    """Nazwa rejestratora (fn z jego vcard) i publiczny numer IANA. Reszty vcard nie dotykamy."""
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict) or "registrar" not in [str(r).lower() for r in ent.get("roles") or []]:
            continue
        name = None
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn" and isinstance(prop[3], str):
                    name = prop[3].strip() or None
                    break
        iana = None
        for pid in ent.get("publicIds") or []:
            if isinstance(pid, dict) and "iana" in str(pid.get("type", "")).lower() and pid.get("identifier"):
                iana = str(pid["identifier"])
                break
        return name, iana
    return None, None


def _now(today: date | datetime | None) -> datetime:
    if today is None:
        return datetime.now(timezone.utc)
    if isinstance(today, datetime):
        return today if today.tzinfo else today.replace(tzinfo=timezone.utc)
    return datetime(today.year, today.month, today.day, tzinfo=timezone.utc)


def parse_rdap(data: dict, domain: str, today: date | datetime | None = None, source: str = "") -> RdapResult:
    res = RdapResult(domain=domain, source=source)
    res.registrar, res.registrar_iana_id = _registrar(data)
    for ev in data.get("events") or []:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction", "")).lower()
        when = ev.get("eventDate") if isinstance(ev.get("eventDate"), str) else None
        if action == "registration" and res.created is None:
            res.created = when
        elif action == "last changed" and res.updated is None:
            res.updated = when
        elif action == "expiration" and res.expires is None:
            res.expires = when
    res.status = sorted({str(s) for s in data.get("status") or [] if isinstance(s, str)})
    res.nameservers = sorted({
        str(ns["ldhName"]).rstrip(".").lower()
        for ns in data.get("nameservers") or []
        if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str) and ns["ldhName"].strip()
    })
    sec = data.get("secureDNS")
    if isinstance(sec, dict) and isinstance(sec.get("delegationSigned"), bool):
        res.dnssec_signed = sec["delegationSigned"]
    exp = parse_dt(res.expires)
    if exp is not None:
        now = _now(today)
        # pełne dni do wygaśnięcia (floor); po terminie wartość ujemna
        res.days_to_expiry = (exp - now).days
    return res


def _query(url: str, fetch: Fetch, timeout: float) -> tuple[str, dict | str]:
    """('ok', dane) | ('notfound', '') | ('error', komunikat)."""
    try:
        resp = fetch(url, headers=RDAP_HEADERS, timeout=timeout)
    except FetchError as exc:
        return "error", str(exc)
    if resp.status == 404:
        return "notfound", ""
    if resp.status == 429:
        return "error", "limit zapytań (HTTP 429)"
    if resp.status != 200:
        return "error", f"HTTP {resp.status}"
    try:
        data = json.loads(resp.text)
    except ValueError:
        return "error", "nieprawidłowy JSON w odpowiedzi"
    if not isinstance(data, dict):
        return "error", "nieoczekiwany format odpowiedzi"
    return "ok", data


def lookup(domain: str, fetch: Fetch, timeout: float = 15.0, today: date | datetime | None = None,
           bootstrap: Bootstrap | None = None) -> RdapResult:
    """RDAP przez bootstrap IANA, a gdy to zawiedzie (lub TLD nieznany) przez rdap.org.

    404 z serwera rejestru jest rzetelną odpowiedzią (found=False), nie powodem do fallbacku.
    Gdy zawiodły wszystkie drogi: RdapError (to nie to samo co 'domena nie istnieje').
    """
    bootstrap = bootstrap or Bootstrap(fetch, timeout)
    errors: list[str] = []
    attempts: list[str] = []
    try:
        base = bootstrap.base_url(domain)
        if base is None:
            errors.append("TLD nie występuje w bootstrapie IANA")
        else:
            attempts.append(base.rstrip("/") + f"/domain/{domain}")
    except RdapError as exc:
        errors.append(str(exc))
    attempts.append(FALLBACK_URL.format(domain=domain))
    for url in attempts:
        kind, data = _query(url, fetch, timeout)
        host = url.split("/")[2]
        if kind == "ok":
            return parse_rdap(data, domain, today, source=host)  # type: ignore[arg-type]
        if kind == "notfound":
            return RdapResult(domain=domain, found=False, source=host)
        errors.append(f"{host}: {data}")
    raise RdapError("; ".join(errors))


def evaluate(res: RdapResult) -> list[Finding]:
    f: list[Finding] = []
    if not res.found:
        f.append(Finding(
            "RDAP", Severity.WARN,
            "RDAP nie zna tej nazwy: domena nie jest zarejestrowana albo to subdomena",
            "RDAP opisuje tylko domenę zarejestrowaną (np. example.com, nie www.example.com); sprawdź pisownię."))
        return f
    d = res.days_to_expiry
    if res.expires is None or d is None:
        f.append(Finding("WAŻNOŚĆ", Severity.INFO,
                         "rejestr nie podaje (lub podaje w nieczytelnym formacie) daty wygaśnięcia domeny",
                         "Datę wygaśnięcia sprawdź u rejestratora."))
    elif d < 0:
        f.append(Finding("WAŻNOŚĆ", Severity.FAIL, f"domena wygasła {-d} dni temu ({res.expires[:10]})",
                         "Odnów domenę natychmiast lub sprawdź, czy nie weszła w okres karencji."))
    elif d < FAIL_DAYS:
        f.append(Finding("WAŻNOŚĆ", Severity.FAIL, f"domena wygasa za {d} dni ({res.expires[:10]})",
                         "Odnów domenę teraz; włącz automatyczne odnawianie."))
    elif d < WARN_DAYS:
        f.append(Finding("WAŻNOŚĆ", Severity.WARN, f"domena wygasa za {d} dni ({res.expires[:10]})",
                         "Zaplanuj odnowienie; włącz automatyczne odnawianie."))
    else:
        f.append(Finding("WAŻNOŚĆ", Severity.OK, f"domena wygasa za {d} dni ({res.expires[:10]})"))
    lowered = {s.replace(" ", "").lower() for s in res.status}
    holds = sorted(s for s in res.status if s.replace(" ", "").lower() in _HOLD)
    if holds:
        f.append(Finding("STATUS", Severity.WARN, f"domena ma status wstrzymania: {', '.join(holds)} (nie działa w DNS)",
                         "Skontaktuj się z rejestratorem (zaległa płatność, spór albo weryfikacja danych)."))
    deleting = sorted(s for s in res.status if s.replace(" ", "").lower() in _DELETING)
    if deleting:
        f.append(Finding("STATUS", Severity.WARN, f"domena w procedurze usuwania: {', '.join(deleting)}",
                         "Odnów domenę u rejestratora, jeśli ma pozostać Twoja."))
    if res.status and not holds and not deleting:
        f.append(Finding("STATUS", Severity.OK, f"statusy: {', '.join(res.status)}"))
    if res.status and not ({"clienttransferprohibited", "servertransferprohibited"} & lowered):
        f.append(Finding("STATUS", Severity.INFO, "brak blokady transferu domeny (clientTransferProhibited)",
                         "Włącz blokadę transferu u rejestratora, by utrudnić przejęcie domeny."))
    if res.dnssec_signed is True:
        f.append(Finding("DNSSEC", Severity.OK, "delegacja podpisana DNSSEC (DS w rejestrze)"))
    elif res.dnssec_signed is False:
        f.append(Finding("DNSSEC", Severity.INFO, "delegacja niepodpisana DNSSEC (brak DS w rejestrze)",
                         "Szczegóły konfiguracji DNS sprawdzi dns-audit."))
    if not res.nameservers:
        f.append(Finding("DNS", Severity.INFO, "rejestr nie podaje serwerów nazw"))
    return f
