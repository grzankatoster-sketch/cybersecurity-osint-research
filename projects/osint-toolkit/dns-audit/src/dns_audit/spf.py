"""Parser SPF (RFC 7208) i liczenie lookupow DNS (limit 10)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field

DNS_LOOKUP_LIMIT = 10
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
KNOWN_MECHANISMS = LOOKUP_MECHANISMS | {"all", "ip4", "ip6"}
MAX_DEPTH = 10
MAX_EXPANSIONS = 50  # globalny budzet rozwiniec include/redirect (ochrona przed rozrostem grafu SPF)

_MECH_RE = re.compile(r"^([+\-~?]?)([A-Za-z0-9]+)(?:([:/])(.*))?$")
_MOD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]*)=(.*)$")
_DUAL_CIDR_RE = re.compile(r"^(?:/(\d+))?(?://(\d+))?$")


@dataclass
class SpfTerm:
    qualifier: str  # + - ~ ?
    mechanism: str  # male litery
    value: str | None = None


@dataclass
class SpfRecord:
    raw: str
    terms: list[SpfTerm] = field(default_factory=list)
    redirect: str | None = None
    exp: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def all_qualifier(self) -> str | None:
        for t in self.terms:
            if t.mechanism == "all":
                return t.qualifier
        return None


def is_spf(txt: str) -> bool:
    t = txt.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def select_spf(txts: list[str] | tuple[str, ...]) -> list[str]:
    return [t.strip() for t in txts if is_spf(t)]


def _valid_prefix(spec: str) -> bool:
    """Prefiksy mechanizmow a/mx: '/24', '//64' albo '/24//64' (IPv4 0-32, IPv6 0-128)."""
    m = _DUAL_CIDR_RE.match(spec)
    if not m:
        return False
    v4, v6 = m.group(1), m.group(2)
    return (v4 is None or int(v4) <= 32) and (v6 is None or int(v6) <= 128)


def _valid_ip_term(name: str, value: str) -> bool:
    addr, slash, prefix = value.partition("/")
    if slash and not prefix.isdigit():
        return False  # np. maska sieci zamiast dlugosci prefiksu
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return net.version == (4 if name == "ip4" else 6)


def parse_spf(raw: str) -> SpfRecord:
    rec = SpfRecord(raw=raw.strip())
    tokens = rec.raw.split()
    for tok in tokens[1:]:
        mod = _MOD_RE.match(tok)
        if mod and tok[0] not in "+-~?":
            name, value = mod.group(1).lower(), mod.group(2)
            if name == "redirect":
                if rec.redirect is not None:
                    rec.errors.append("wiele modyfikatorow redirect")
                rec.redirect = value.rstrip(".").lower()
            elif name == "exp":
                rec.exp = value
            continue
        m = _MECH_RE.match(tok)
        if not m:
            rec.errors.append(f"nieprawidlowy skladnik: {tok!r}")
            continue
        qual, name, sep, rest = m.group(1) or "+", m.group(2).lower(), m.group(3), m.group(4)
        if name not in KNOWN_MECHANISMS:
            rec.errors.append(f"nieznany mechanizm: {tok!r}")
            continue
        value: str | None = None
        if name in ("a", "mx"):
            domain, spec = None, ""
            if sep == "/":
                spec = "/" + (rest or "")
            elif sep == ":":
                domain, slash, tail = (rest or "").partition("/")
                spec = slash + tail
                if not domain:
                    rec.errors.append(f"mechanizm {name} bez domeny: {tok!r}")
                    continue
            if spec and not _valid_prefix(spec):
                rec.errors.append(f"nieprawidlowy prefiks CIDR: {tok!r}")
                continue
            if domain:
                value = domain if "%" in domain else domain.rstrip(".").lower()
        elif sep == ":" and rest:
            value = rest
            if name in ("include", "exists", "ptr") and "%" not in value:
                value = value.rstrip(".").lower()
        elif sep == "/" or (name == "all" and sep):
            rec.errors.append(f"nieprawidlowy skladnik: {tok!r}")
            continue
        if name in ("include", "exists") and not value:
            rec.errors.append(f"mechanizm {name} bez domeny")
            continue
        if name in ("ip4", "ip6"):
            if not value:
                rec.errors.append(f"mechanizm {name} bez adresu")
                continue
            if not _valid_ip_term(name, value):
                rec.errors.append(f"nieprawidlowy adres {name}: {tok!r}")
                continue
        rec.terms.append(SpfTerm(qual, name, value))
    return rec


@dataclass
class SpfLookups:
    count: int = 0
    includes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    syntax_errors: list[str] = field(default_factory=list)  # bledy skladni rekordow z include/redirect (z nazwa domeny)
    effective_all: str | None = None  # kwalifikator koncowego "all" (takze przez redirect)
    uses_ptr: bool = False
    budget_exceeded: bool = False  # analiza przerwana: wynik (count) jest dolnym ograniczeniem

    @property
    def over_limit(self) -> bool:
        return self.count > DNS_LOOKUP_LIMIT


class _BudgetExceeded(Exception):
    pass


def count_lookups(
    domain: str,
    record: SpfRecord,
    fetch_txt: Callable[[str], list[str] | None],
) -> SpfLookups:
    """Liczy mechanizmy wymagajace zapytania DNS (include, a, mx, ptr, exists, redirect), rekurencyjnie.

    fetch_txt(domain) zwraca liste TXT albo None, gdy zapytanie sie nie udalo.
    Dla mx nie sumujemy zapytan o hosty MX (RFC liczy je osobno, limit 10 nazw na mechanizm).
    Mechanizmy po pierwszym `all` sa pomijane (RFC 7208 5.1). Kazda domena jest rozwijana raz (memo),
    a laczny budzet to MAX_EXPANSIONS rozwiniec: po jego przekroczeniu analiza konczy sie bledem.
    """
    res = SpfLookups()
    memo: dict[str, tuple[int, str | None]] = {}  # domena -> (lookupy poddrzewa, kwalifikator all)
    expansions = 0

    def error(msg: str) -> None:
        if msg not in res.errors:
            res.errors.append(msg)

    def follow(target: str, path: tuple[str, ...], depth: int, kind: str) -> str | None:
        nonlocal expansions
        if "%" in target:
            error(f"{kind} {target}: makro, pominieto")
            return None
        if target in path:
            error(f"{kind} {target}: petla w SPF")
            return None
        if target in memo:
            sub, all_q = memo[target]
            res.count += sub
            return all_q
        if depth >= MAX_DEPTH:
            error(f"{kind} {target}: zbyt gleboko zagniezdzone")
            return None
        expansions += 1
        if expansions > MAX_EXPANSIONS:
            res.budget_exceeded = True
            error(f"przekroczono budżet analizy SPF (maks. {MAX_EXPANSIONS} rozwinięć include/redirect): wynik niepełny")
            raise _BudgetExceeded
        before = res.count
        all_q: str | None = None
        txts = fetch_txt(target)
        if txts is None:
            error(f"{kind} {target}: nie udalo sie pobrac TXT")
        else:
            spfs = select_spf(txts)
            if not spfs:
                error(f"{kind} {target}: brak rekordu SPF (PermError)")
            elif len(spfs) > 1:
                error(f"{kind} {target}: wiele rekordow SPF (PermError)")
            else:
                child = parse_spf(spfs[0])
                res.syntax_errors.extend(f"{target}: {e}" for e in child.errors)
                all_q = walk(child, path + (target,), depth + 1)
        memo[target] = (res.count - before, all_q)
        return all_q

    def walk(rec: SpfRecord, path: tuple[str, ...], depth: int) -> str | None:
        for t in rec.terms:
            if t.mechanism == "all":
                return t.qualifier  # dalsze mechanizmy (i redirect) sa ignorowane
            if t.mechanism in LOOKUP_MECHANISMS:
                res.count += 1
                if t.mechanism == "ptr":
                    res.uses_ptr = True
                if t.mechanism == "include" and t.value:
                    res.includes.append(t.value)
                    follow(t.value, path, depth, "include")
        if rec.redirect:
            res.count += 1
            res.includes.append(rec.redirect)
            return follow(rec.redirect, path, depth, "redirect")
        return None

    try:
        res.effective_all = walk(record, (domain.rstrip(".").lower(),), 0)
    except _BudgetExceeded:
        res.effective_all = record.all_qualifier
    return res
