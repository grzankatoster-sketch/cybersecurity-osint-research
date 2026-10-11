"""Ocena zebranych danych: lista ustalen z waga (OK/INFO/WARN/FAIL) i zaleceniem po polsku."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .collector import DomainData
from .dkim import DkimKey, is_dkim, parse_dkim
from .dmarc import POLICY_RANK, DmarcRecord, is_dmarc, parse_dmarc
from .models import Finding, Severity
from .resolver import DnsAnswer, Status
from .spf import DNS_LOOKUP_LIMIT, SpfRecord, parse_spf, select_spf
from .verification import detect_verifications, is_email_auth

OK, INFO, WARN, FAIL = Severity.OK, Severity.INFO, Severity.WARN, Severity.FAIL

MX_PROVIDERS = [
    (("google.com", "googlemail.com"), "Google Workspace / Gmail"),
    (("mail.protection.outlook.com", "outlook.com"), "Microsoft 365 (Exchange Online)"),
    (("pphosted.com", "ppe-hosted.com"), "Proofpoint"),
    (("mimecast.com",), "Mimecast"),
    (("protonmail.ch",), "Proton Mail"),
    (("zoho.com", "zoho.eu"), "Zoho Mail"),
    (("yandex.net", "yandex.ru"), "Yandex"),
    (("mx.ovh.net", "ovh.net"), "OVH"),
    (("home.pl",), "home.pl"),
    (("icloud.com",), "iCloud"),
    (("secureserver.net",), "GoDaddy"),
    (("messagelabs.com",), "Broadcom/Symantec Email Security"),
    (("barracudanetworks.com",), "Barracuda"),
    (("fastmail.com", "messagingengine.com"), "Fastmail"),
    (("yahoodns.net",), "Yahoo"),
    (("mailgun.org",), "Mailgun"),
]

WEAK_DNSSEC_ALGORITHMS = {1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1"}


def parse_mx(records) -> list[tuple[int, str]]:
    out = []
    for rec in records:
        parts = rec.split()
        if len(parts) >= 2 and parts[0].isdigit():
            out.append((int(parts[0]), parts[1].rstrip(".").lower()))
    return sorted(out)


def is_null_mx(mx: list[tuple[int, str]]) -> bool:
    return len(mx) == 1 and mx[0][1] == ""


def mx_provider(host: str) -> str | None:
    for suffixes, name in MX_PROVIDERS:
        if any(host == s or host.endswith("." + s) for s in suffixes):
            return name
    return None


_CAA_RE = re.compile(r'^(\d+)\s+(\w+)\s+"?(.*?)"?\s*$')


def parse_caa(records) -> list[tuple[str, str]]:
    out = []
    for rec in records:
        m = _CAA_RE.match(rec.strip())
        if m:
            out.append((m.group(2).lower(), m.group(3)))
    return out


def parse_soa(records) -> dict | None:
    for rec in records:
        p = rec.split()
        if len(p) >= 7 and all(x.isdigit() for x in p[2:7]):
            return {
                "mname": p[0].rstrip("."), "rname": p[1].rstrip("."), "serial": int(p[2]),
                "refresh": int(p[3]), "retry": int(p[4]), "expire": int(p[5]), "minimum": int(p[6]),
            }
    return None


def parse_dnskey_algorithms(records) -> list[int]:
    algs = []
    for rec in records:
        p = rec.split()
        if len(p) >= 3 and p[2].isdigit():
            algs.append(int(p[2]))
    return algs


def parse_ds_digest_types(records) -> list[int]:
    out = []
    for rec in records:
        p = rec.split()
        if len(p) >= 3 and p[2].isdigit():
            out.append(int(p[2]))
    return out


def kv_record(raw: str) -> dict[str, str]:
    """Parser 'k=v; k=v' (MTA-STS, TLS-RPT, BIMI)."""
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


def _status_note(ans: DnsAnswer) -> str:
    return ans.status.value + (f": {ans.error}" if ans.error else "")


status_note = _status_note

# Jeden selektor rekordow TXT dla analizy i raportu: dokladna wersja (po strip), wersja konczy sie ';' albo koncem rekordu.
_RECORD_VERSION = {
    "mta_sts": re.compile(r"^v=stsv1\s*(?:;|$)", re.IGNORECASE),
    "tls_rpt": re.compile(r"^v=tlsrptv1\s*(?:;|$)", re.IGNORECASE),
    "bimi": re.compile(r"^v=bimi1\s*(?:;|$)", re.IGNORECASE),
}


def select_records(ans: DnsAnswer, kind: str) -> list[str]:
    rx = _RECORD_VERSION[kind]
    return [r.strip() for r in ans.records if rx.match(r.strip())]


def zone_ad(d: DomainData) -> bool:
    """Flaga AD tylko z odpowiedzi samej strefy (DNSKEY/SOA); AD na DS dotyczy delegacji, nie danych strefy."""
    return bool(d.dnskey.ad or d.soa.ad)


@dataclass
class DkimScan:
    keys: dict[str, DkimKey] = field(default_factory=dict)
    wildcard: bool = False
    wildcard_revoked: bool = False
    control_failed: DnsAnswer | None = None
    failed: list[str] = field(default_factory=list)  # selektory, ktorych zapytanie sie nie udalo


def scan_dkim(d: DomainData) -> DkimScan:
    """Wspolny wybor kluczy DKIM dla analizy i raportu.

    Przy wildcardzie pomijamy tylko selektory z odpowiedzia identyczna jak wildcard i niepodane jawnie.
    """
    scan = DkimScan()
    ctl_ans = d.dkim_control
    ctl_raw = [r for r in (ctl_ans.records if ctl_ans else ()) if is_dkim(r)]
    scan.wildcard = bool(ctl_raw)
    scan.wildcard_revoked = scan.wildcard and all(parse_dkim(r).revoked for r in ctl_raw)
    if ctl_ans is not None and ctl_ans.failed:
        scan.control_failed = ctl_ans
    explicit = set(d.explicit_selectors)
    for sel, ans in d.dkim.items():
        if ans.failed:
            scan.failed.append(sel)
        for r in ans.records:
            if is_dkim(r):
                if not (scan.wildcard and sel not in explicit and r in ctl_raw):
                    scan.keys[sel] = parse_dkim(r)
                break
    return scan


def _unreachable(area: str, what: str, ans: DnsAnswer) -> Finding:
    return Finding(
        area, INFO,
        f"Nie udało się sprawdzić: {what} ({_status_note(ans)})",
        "Powtórz audyt lub użyj innego resolvera (--resolver 1.1.1.1). To nie oznacza braku rekordu.",
    )


def _filter(ans: DnsAnswer, pred) -> list[str]:
    return [r for r in ans.records if pred(r)]


def analyze(d: DomainData) -> list[Finding]:
    if d.soa.status is Status.NXDOMAIN and d.ns.status is Status.NXDOMAIN:
        return [Finding(
            "DNS", FAIL, f"Domena {d.domain} nie istnieje (NXDOMAIN)",
            "Sprawdź pisownię domeny. Jeśli to Twoja domena, sprawdź, czy nie wygasła u rejestratora.",
        )]
    mx = parse_mx(d.mx.records)
    null_mx = is_null_mx(mx)
    mail = bool(mx) and not null_mx  # tylko do wagi braku SPF/DMARC
    send = not null_mx  # DKIM/MTA-STS/TLS-RPT/BIMI pomijamy wylacznie przy jawnym null MX (RFC 7505)
    f: list[Finding] = []
    f += _addresses(d)
    f += _ns(d)
    f += _soa(d)
    f += _mx(d, mx, null_mx)
    f += _spf(d, mail)
    f += _dmarc(d, mail)
    f += _dkim(d, send)
    f += _dnssec(d)
    f += _caa(d)
    f += _wildcard(d)
    f += _mta_sts(d, send)
    f += _tls_rpt(d, send)
    f += _bimi(d, send)
    f += _verifications(d)
    return f


# --- adresy, NS, SOA, MX -----------------------------------------------------

def _addresses(d: DomainData) -> list[Finding]:
    out = []
    for ans, label in ((d.a, "A"), (d.aaaa, "AAAA")):
        if ans.failed:
            out.append(_unreachable("Adresy", label, ans))
    if d.a.failed or d.aaaa.failed:
        return out
    if not d.a.ok and not d.aaaa.ok:
        out.append(Finding(
            "Adresy", INFO, "Brak rekordów A/AAAA na apeksie domeny",
            "Jeśli domena ma obsługiwać WWW, dodaj A/AAAA; w przeciwnym razie to normalne (np. domena tylko do poczty).",
        ))
        return out
    out.append(Finding("Adresy", OK, f"A: {len(d.a.records)}, AAAA: {len(d.aaaa.records)}"))
    if d.a.ok and not d.aaaa.ok:
        out.append(Finding(
            "Adresy", INFO, "Brak IPv6 (AAAA) na apeksie domeny",
            "Rozważ dodanie AAAA, jeśli hosting go obsługuje.",
        ))
    return out


def _ns(d: DomainData) -> list[Finding]:
    if d.ns.failed:
        return [_unreachable("NS", "NS", d.ns)]
    n = len(d.ns.records)
    if n == 0:
        return [Finding(
            "NS", WARN, "Brak rekordów NS na tym poziomie",
            "Jeśli to subdomena, to normalne; dla domeny rejestrowanej sprawdź delegację u rejestratora.",
        )]
    if n == 1:
        return [Finding(
            "NS", WARN, "Tylko jeden serwer nazw (brak redundancji)",
            "Dodaj co najmniej drugi serwer nazw, najlepiej u innego dostawcy lub w innej sieci.",
        )]
    return [Finding("NS", OK, f"{n} serwery nazw: " + ", ".join(sorted(r.rstrip(".").lower() for r in d.ns.records)))]


def _soa(d: DomainData) -> list[Finding]:
    if d.soa.failed:
        return [_unreachable("SOA", "SOA", d.soa)]
    soa = parse_soa(d.soa.records)
    if not soa:
        return [Finding("SOA", INFO, "Brak rekordu SOA na apeksie (domena może być subdomeną strefy nadrzędnej)")]
    return [Finding(
        "SOA", OK,
        f"SOA: primary {soa['mname']}, serial {soa['serial']}, kontakt {soa['rname']}",
    )]


def _mx(d: DomainData, mx: list[tuple[int, str]], null_mx: bool) -> list[Finding]:
    if d.mx.failed:
        return [_unreachable("MX", "MX", d.mx)]
    if null_mx:
        return [Finding("MX", OK, "Null MX (RFC 7505): domena jawnie deklaruje brak poczty")]
    if not mx:
        extra = " Poczta trafiłaby na rekord A (niejawny MX)." if d.a.ok else ""
        return [Finding(
            "MX", INFO, "Brak rekordów MX." + extra,
            "Jeśli domena nie obsługuje poczty, dodaj null MX (0 .) oraz SPF 'v=spf1 -all' i DMARC p=reject.",
        )]
    out: list[Finding] = []
    providers = sorted({p for _, h in mx if (p := mx_provider(h))})
    hosts = ", ".join(f"{p} {h}" for p, h in mx)
    title = f"{len(mx)} MX: {hosts}"
    if providers:
        title += f" (dostawca: {', '.join(providers)})"
    out.append(Finding("MX", OK, title))
    if len(mx) == 1:
        out.append(Finding(
            "MX", INFO, "Tylko jeden MX (brak zapasowego serwera poczty)",
            "Dodaj zapasowy MX o niższym priorytecie, jeśli dostawca tego nie robi sam.",
        ))
    wildcard_a = d.wildcard.get("A")
    wildcard_a_ok = bool(wildcard_a and wildcard_a.ok)
    for host, status in d.mx_hosts.items():
        is_ip = bool(re.fullmatch(r"[\d.]+|[0-9a-f:]+", host) and ("." in host or ":" in host))
        if is_ip:
            out.append(Finding(
                "MX", FAIL, f"MX wskazuje na adres IP zamiast nazwy hosta: {host}",
                "MX musi wskazywać nazwę hosta (RFC 5321), nie adres IP.",
            ))
        elif status is False:
            out.append(Finding(
                "MX", FAIL, f"Host MX {host} nie ma rekordu A/AAAA",
                "Napraw lub usuń ten MX; poczta kierowana tam nie zostanie dostarczona.",
            ))
        elif status is None:
            out.append(Finding("MX", INFO, f"Nie udało się rozwiązać hosta MX {host}"))
        if not is_ip and status is True and wildcard_a_ok and host.endswith("." + d.domain):
            out.append(Finding(
                "MX", INFO,
                f"Host MX {host} rozwiązuje się, ale strefa ma wildcard A: wynik może być fałszywie dodatni",
                "Sprawdź, czy host MX ma własny rekord A/AAAA niezależny od wildcardu; w przeciwnym razie "
                "poczta może trafiać gdzie indziej niż zamierzono.",
            ))
    return out


# --- SPF ------------------------------------------------------------------------

def _spf(d: DomainData, mail: bool) -> list[Finding]:
    if d.txt.failed:
        return [_unreachable("SPF", "TXT (SPF)", d.txt)]
    spfs = select_spf(d.txt.records)
    if not spfs:
        sev = FAIL if mail else WARN
        rec = (
            "Dodaj rekord TXT SPF z listą dozwolonych nadawców, np. 'v=spf1 include:... -all'."
            if mail else "Dla domeny bez poczty opublikuj 'v=spf1 -all', aby utrudnić podszywanie."
        )
        return [Finding("SPF", sev, "Brak rekordu SPF", rec)]
    if len(spfs) > 1:
        return [Finding(
            "SPF", FAIL, f"Wiele rekordów SPF ({len(spfs)}): receiver zwróci PermError",
            "Scal wszystkie mechanizmy w jeden rekord TXT zaczynający się od v=spf1.",
        )]
    rec: SpfRecord = parse_spf(spfs[0])
    out: list[Finding] = []
    for err in rec.errors:
        out.append(Finding("SPF", FAIL, f"Błąd składni SPF: {err}", "Popraw rekord; błąd składni daje PermError."))

    lk = d.spf_lookups
    if lk is not None:
        if lk.count > DNS_LOOKUP_LIMIT:
            out.append(Finding(
                "SPF", FAIL, f"SPF: {lk.count} lookupów DNS, limit to {DNS_LOOKUP_LIMIT} (PermError)",
                "Ogranicz include/a/mx/redirect: usuń nieużywane usługi, zastąp include adresami ip4/ip6 lub użyj flatteningu.",
            ))
        elif lk.count >= DNS_LOOKUP_LIMIT - 2:
            out.append(Finding(
                "SPF", WARN, f"SPF: {lk.count}/{DNS_LOOKUP_LIMIT} lookupów DNS (blisko limitu)",
                "Zostaw zapas na zmiany u dostawców (ich rekordy SPF mogą urosnąć). Usuń nieużywane include.",
            ))
        else:
            out.append(Finding("SPF", OK, f"SPF: {lk.count}/{DNS_LOOKUP_LIMIT} lookupów DNS"))
        for err in lk.errors:
            if lk.budget_exceeded and err.startswith("przekroczono budżet"):
                out.append(Finding(
                    "SPF", FAIL, f"SPF: {err}",
                    "Rekord SPF rozwija się w zbyt rozległy graf include/redirect (limit RFC to 10 lookupów): uprość go lub użyj flatteningu.",
                ))
            else:
                out.append(Finding(
                    "SPF", WARN, f"SPF: {err}",
                    "Napraw lub usuń wadliwe odwołanie; include do domeny bez SPF kończy się PermError.",
                ))
        for err in lk.syntax_errors:
            out.append(Finding(
                "SPF", FAIL, f"Błąd składni SPF w rekordzie {err}",
                "Popraw rekord tej zależności (include/redirect); błąd składni daje PermError całego SPF.",
            ))
        if lk.uses_ptr:
            out.append(Finding("SPF", WARN, "SPF używa przestarzałego mechanizmu ptr", "Zastąp ptr mechanizmami ip4/ip6/a/include (RFC 7208 odradza ptr)."))
        qual = lk.effective_all
        redirect_fetch_failed = any(
            err.startswith("redirect ") and "nie udalo sie pobrac TXT" in err for err in lk.errors
        )
    else:
        qual = rec.all_qualifier
        redirect_fetch_failed = False
        if any(t.mechanism == "ptr" for t in rec.terms):
            out.append(Finding("SPF", WARN, "SPF używa przestarzałego mechanizmu ptr", "Zastąp ptr mechanizmami ip4/ip6/a/include."))

    if qual == "+":
        out.append(Finding("SPF", FAIL, "SPF kończy się '+all': każdy serwer może wysyłać w imieniu domeny", "Zmień na '-all' (lub tymczasowo '~all')."))
    elif qual == "?":
        out.append(Finding("SPF", WARN, "SPF kończy się '?all' (neutralny): brak ochrony przed podszywaniem", "Zmień na '-all' (lub '~all' na czas wdrożenia)."))
    elif qual == "~":
        out.append(Finding("SPF", INFO, "SPF kończy się '~all' (softfail)", "Przy egzekwowanym DMARC to akceptowalne; po weryfikacji nadawców rozważ '-all'."))
    elif qual == "-":
        out.append(Finding("SPF", OK, "SPF kończy się '-all' (twarda odmowa)"))
    elif redirect_fetch_failed:
        out.append(Finding(
            "SPF", INFO,
            "SPF: kwalifikatora końcowego nie ustalono (redirect wskazuje na cel, którego nie udało się pobrać)",
        ))
    elif not (lk is not None and lk.budget_exceeded):
        out.append(Finding("SPF", WARN, "SPF nie kończy się mechanizmem 'all' ani redirect", "Dodaj '-all' (lub '~all') na końcu rekordu."))
    return out


# --- DMARC ----------------------------------------------------------------------

def _effective_dmarc_policy(rec: DmarcRecord) -> str | None:
    """Zwraca efektywną politykę p; brak tagu p z poprawnym rua liczy się jako p=none (RFC 7489 §6.6.3)."""
    if rec.p is not None:
        return rec.p
    return "none" if rec.rua else None


def _dmarc(d: DomainData, mail: bool) -> list[Finding]:
    if d.dmarc.failed:
        return [_unreachable("DMARC", "_dmarc", d.dmarc)]
    recs = _filter(d.dmarc, is_dmarc)
    if not recs:
        return [Finding(
            "DMARC", FAIL if mail else WARN,
            "Brak rekordu DMARC (brak rekordu na tej nazwie; polityka może być dziedziczona z domeny organizacyjnej)",
            "Dodaj TXT _dmarc: 'v=DMARC1; p=none; rua=mailto:dmarc@domena' i stopniowo zaostrzaj politykę do quarantine/reject.",
        )]
    if len(recs) > 1:
        return [Finding("DMARC", FAIL, f"Wiele rekordów DMARC ({len(recs)}): receiver je zignoruje", "Zostaw jeden rekord TXT na _dmarc.")]
    rec: DmarcRecord = parse_dmarc(recs[0])
    out = [Finding("DMARC", FAIL, f"Błąd w rekordzie DMARC: {e}", "Popraw rekord; błędny DMARC bywa ignorowany.") for e in rec.errors]
    p = _effective_dmarc_policy(rec)
    if p == "none":
        out.append(Finding("DMARC", WARN, "Polityka p=none: tylko monitoring, brak ochrony przed podszywaniem", "Po analizie raportów przejdź na p=quarantine, a potem p=reject."))
    elif p == "quarantine":
        out.append(Finding("DMARC", INFO, "Polityka p=quarantine", "Docelowo p=reject, gdy raporty nie pokazują fałszywych odrzuceń."))
    elif p == "reject":
        out.append(Finding("DMARC", OK, "Polityka p=reject"))
    if p in ("quarantine", "reject") and rec.pct < 100:
        out.append(Finding("DMARC", WARN, f"pct={rec.pct}: polityka dotyczy tylko części wiadomości", "Podnieś pct do 100, gdy wdrożenie się ustabilizuje."))
    sp = rec.sp
    if sp and p in POLICY_RANK and sp in POLICY_RANK and POLICY_RANK[sp] < POLICY_RANK[p]:
        out.append(Finding("DMARC", WARN, f"Polityka subdomen sp={sp} słabsza niż p={p}", "Ustaw sp na tę samą lub ostrzejszą wartość (subdomeny to częsty cel podszywania)."))
    if not rec.rua:
        out.append(Finding("DMARC", INFO, "Brak adresu raportów zbiorczych (rua)", "Dodaj rua=mailto:..., aby widzieć, kto wysyła w imieniu domeny."))
    else:
        out.append(Finding("DMARC", OK, "Raporty zbiorcze (rua): " + ", ".join(rec.rua)))
    return out


# --- DKIM -----------------------------------------------------------------------

def _dkim(d: DomainData, evaluate: bool) -> list[Finding]:
    if not evaluate:
        return []
    scan = scan_dkim(d)
    out: list[Finding] = []
    if scan.wildcard_revoked:
        out.append(Finding(
            "DKIM", INFO, "Wildcard na _domainkey z pustym p= (każdy selektor unieważniony): nie da się sondować selektorów",
            "To celowe zabezpieczenie dla domen bez poczty. Dla domeny z pocztą upewnij się, że realne selektory mają własne rekordy.",
        ))
    elif scan.wildcard:
        out.append(Finding(
            "DKIM", WARN, "Wildcard na _domainkey: każdy selektor zwraca klucz, wyniki sondowania są niewiarygodne",
            "Usuń wildcard TXT z *._domainkey lub zweryfikuj selektory ręcznie (--selectors); selektory podane jawnie i różne od wildcard są oceniane poniżej.",
        ))
    elif scan.control_failed is not None:
        out.append(Finding(
            "DKIM", INFO,
            f"Niepełne sprawdzenie DKIM: nie udało się wykonać kontroli wildcard ({_status_note(scan.control_failed)})",
            "Nie wiadomo, czy domena ma wildcard na _domainkey, więc wyniki sondowania mogą być niewiarygodne. Powtórz audyt.",
        ))
    partial = None
    if scan.failed:
        more = ", ..." if len(scan.failed) > 5 else ""
        partial = Finding(
            "DKIM", INFO,
            f"Niepełne sprawdzenie DKIM: nie udało się sprawdzić {len(scan.failed)} z {len(d.dkim)} selektorów ({', '.join(scan.failed[:5])}{more})",
            "Powtórz audyt lub użyj innego resolvera (--resolver 1.1.1.1). To nie oznacza braku rekordu.",
        )
    found = scan.keys
    if not found:
        if scan.wildcard:
            return out
        if d.dkim and len(scan.failed) == len(d.dkim):
            return out + [_unreachable("DKIM", "selektory DKIM", d.dkim[scan.failed[0]])]
        out.append(Finding(
            "DKIM", INFO, f"Nie znaleziono DKIM dla {len(d.dkim)} sprawdzonych selektorów",
            "Selektory są dowolne, więc to nie dowodzi braku DKIM. Podaj własny selektor: --selectors nazwa (widać go w nagłówku DKIM-Signature: s=...).",
        ))
        if partial:
            out.append(partial)
        return out
    revoked = [s for s, k in found.items() if k.revoked]
    if revoked:
        out.append(Finding("DKIM", INFO, "Klucz unieważniony (p= puste) dla selektorów: " + ", ".join(revoked), "Usuń rekordy, jeśli selektory nie są już używane."))
    for sel, key in found.items():
        label = f"DKIM selektor '{sel}'"
        if key.revoked:
            continue
        for e in key.errors:
            out.append(Finding("DKIM", WARN, f"{label}: {e}", "Popraw rekord klucza DKIM; odbiorcy mogą odrzucić podpis."))
        if key.valid:
            strength = f"{key.key_type.upper()} {key.key_bits} bit"
            if key.key_type == "rsa" and key.key_bits < 1024:
                out.append(Finding("DKIM", FAIL, f"{label}: klucz {strength} jest zbyt słaby", "Wygeneruj klucz RSA 2048 bit."))
            elif key.key_type == "rsa" and key.key_bits < 2048:
                out.append(Finding("DKIM", WARN, f"{label}: klucz {strength} (zalecane 2048)", "Zrotuj klucz na RSA 2048 bit."))
            else:
                out.append(Finding("DKIM", OK, f"{label}: {strength}"))
        if key.testing:
            out.append(Finding("DKIM", WARN, f"{label}: tryb testowy (t=y)", "Usuń flagę t=y po zakończeniu testów, inaczej odbiorcy mogą ignorować błędy podpisu."))
    if partial:
        out.append(partial)
    return out


# --- DNSSEC ---------------------------------------------------------------------

def _dnssec(d: DomainData) -> list[Finding]:
    dk, ds = d.dnskey, d.ds
    failed = [(name, ans) for name, ans in (("DNSKEY", dk), ("DS", ds)) if ans.failed]
    if failed:
        # Nieudany odczyt nie dowodzi braku rekordu: zadnych wnioskow (FAIL/zalecen usuniecia DS) z jednego bledu.
        return [_unreachable("DNSSEC", "/".join(n for n, _ in failed), failed[0][1])]
    has_dk, has_ds = dk.ok, ds.ok
    ad = zone_ad(d)
    if has_dk and has_ds:
        out = []
        algs = parse_dnskey_algorithms(dk.records)
        weak = sorted({WEAK_DNSSEC_ALGORITHMS[a] for a in algs if a in WEAK_DNSSEC_ALGORITHMS})
        title = f"DNSSEC włączony (DNSKEY: {len(dk.records)}, DS: {len(ds.records)})"
        out.append(Finding("DNSSEC", OK, title + ("; resolver potwierdził walidację (flaga AD)" if ad else "")))
        if not ad:
            out.append(Finding(
                "DNSSEC", INFO, "Resolver nie zwrócił flagi AD dla odpowiedzi strefy (DNSKEY/SOA): walidacji nie potwierdzono",
                "Użyj walidującego resolvera (--resolver 1.1.1.1), aby sprawdzić poprawność łańcucha zaufania.",
            ))
        if weak:
            out.append(Finding("DNSSEC", WARN, "Przestarzały algorytm podpisu: " + ", ".join(weak), "Zmień algorytm na ECDSA P-256 (13) lub Ed25519 (15)."))
        if ds.ok and set(parse_ds_digest_types(ds.records)) == {1}:
            out.append(Finding("DNSSEC", WARN, "DS używa wyłącznie skrótu SHA-1", "Opublikuj DS ze skrótem SHA-256 (typ 2)."))
        return out
    if has_dk and not has_ds:
        return [Finding("DNSSEC", WARN, "Strefa ma DNSKEY, ale brak rekordu DS w strefie nadrzędnej: DNSSEC nie działa", "Dodaj rekord DS u rejestratora domeny (z panelu DNS operatora).")]
    if has_ds and not has_dk:
        return [Finding("DNSSEC", FAIL, "Jest rekord DS, ale strefa nie publikuje DNSKEY: walidujące resolvery odrzucą domenę", "Włącz podpisywanie strefy u operatora DNS albo usuń DS u rejestratora.")]
    return [Finding("DNSSEC", WARN, "Brak DNSSEC (brak DNSKEY i DS)", "Włącz DNSSEC u operatora DNS i dodaj DS u rejestratora, jeśli oba to wspierają.")]


# --- CAA, MTA-STS, TLS-RPT, BIMI --------------------------------------------------

def caa_cas(caa: list[tuple[str, str]], tag: str) -> set[str] | None:
    """Dozwoleni wystawcy dla danego tagu: None = brak wpisow tagu, pusty zbior = zakaz (';')."""
    vals = [v for t, v in caa if t == tag]
    if not vals:
        return None
    return {name for v in vals if (name := v.split(";", 1)[0].strip().strip('"').strip())}


def _caa_policy_text(cas: set[str] | None, absent: str) -> str:
    if cas is None:
        return absent
    return ", ".join(sorted(cas)) if cas else "zabronione"


def _caa(d: DomainData) -> list[Finding]:
    if d.caa.failed:
        return [_unreachable("CAA", "CAA", d.caa)]
    if not d.caa.ok:
        return [Finding(
            "CAA", INFO, "Brak lokalnego rekordu CAA (może dziedziczyć z domeny nadrzędnej)",
            "Sprawdź CAA domeny nadrzędnej; jeśli go brak, dodaj CAA ograniczający wystawców, np. '0 issue \"letsencrypt.org\"', oraz iodef.",
        )]
    caa = parse_caa(d.caa.records)
    issue, wild = caa_cas(caa, "issue"), caa_cas(caa, "issuewild")
    out = [Finding(
        "CAA", OK,
        "CAA: issue: " + _caa_policy_text(issue, "brak wpisu (bez ograniczeń z tego zestawu)")
        + "; issuewild: " + _caa_policy_text(wild, "brak wpisu (obowiązuje issue)"),
    )]
    if issue is None:
        out.append(Finding(
            "CAA", INFO, "CAA nie ogranicza wystawców zwykłych certyfikatów (brak wpisu issue)",
            "Dodaj '0 issue \"...\"' z listą dozwolonych urzędów (lub ';' dla zakazu).",
        ))
    if not any(t == "iodef" for t, _ in caa):
        out.append(Finding("CAA", INFO, "CAA bez iodef", "Dodaj iodef, aby dostawać zgłoszenia o odrzuconych próbach wystawienia."))
    return out


def _wildcard_mx_finding(d: DomainData) -> Finding:
    title = "Wildcard MX: losowa subdomena przyjmuje pocztę (host może odbierać wiadomości dla nieistniejących adresów)"
    rec = (
        "Jeśli to nie catch-all, usuń wildcard MX. Zadbaj też o politykę DMARC dla subdomen (sp), "
        "bo słaba polityka zwiększa ryzyko nadużycia wildcardu do podszywania."
    )
    if d.dmarc.failed:
        return Finding("Wildcard", INFO, f"{title} (nie udało się sprawdzić DMARC)", rec)
    recs = _filter(d.dmarc, is_dmarc)
    policy = None
    if recs:
        parsed = parse_dmarc(recs[0])
        policy = parsed.sp or parsed.p
    if policy in ("quarantine", "reject"):
        return Finding("Wildcard", INFO, title, rec)
    return Finding("Wildcard", WARN, title, rec)


def _wildcard(d: DomainData) -> list[Finding]:
    if not d.wildcard:
        return []
    out: list[Finding] = []
    found = False
    failed = False
    a_ans = d.wildcard.get("A")
    if a_ans is not None:
        if a_ans.failed:
            failed = True
            out.append(Finding(
                "Wildcard", INFO,
                f"Niepełne sprawdzenie wildcard DNS: A ({_status_note(a_ans)})",
                "Powtórz audyt lub użyj innego resolvera (--resolver 1.1.1.1). To nie oznacza braku wildcardu.",
            ))
        elif a_ans.ok:
            found = True
            out.append(Finding(
                "Wildcard", WARN,
                f"Wildcard DNS: losowa subdomena rozwiązuje się na A ({', '.join(a_ans.records)})",
                "Rozwiązania subdomen (np. hostów MX, mechanizmów a:/mx: w SPF) mogą być fałszywie dodatnie.",
            ))
    mx_ans = d.wildcard.get("MX")
    if mx_ans is not None:
        if mx_ans.failed:
            failed = True
            out.append(Finding(
                "Wildcard", INFO,
                f"Niepełne sprawdzenie wildcard DNS: MX ({_status_note(mx_ans)})",
                "Powtórz audyt lub użyj innego resolvera (--resolver 1.1.1.1). To nie oznacza braku wildcardu.",
            ))
        elif mx_ans.ok:
            found = True
            out.append(_wildcard_mx_finding(d))
    if not found and not failed:
        out.append(Finding("Wildcard", OK, "Brak wildcard DNS (A, MX)"))
    return out


def _multi_record(area: str, n: int, rfc: str) -> Finding:
    return Finding(
        area, WARN, f"Wiele rekordów {area} ({n}): wg {rfc} polityka nie zostanie wykryta",
        f"Zostaw dokładnie jeden rekord TXT {area}.",
    )


def _mta_sts(d: DomainData, evaluate: bool) -> list[Finding]:
    if not evaluate:
        return []
    if d.mta_sts.failed:
        return [_unreachable("MTA-STS", "_mta-sts", d.mta_sts)]
    recs = select_records(d.mta_sts, "mta_sts")
    if not recs:
        return [Finding("MTA-STS", INFO, "Brak MTA-STS: połączenia SMTP można zdegradować do niezaszyfrowanych", "Opublikuj TXT _mta-sts ('v=STSv1; id=...') i plik https://mta-sts.domena/.well-known/mta-sts.txt (najpierw tryb testing).")]
    if len(recs) > 1:
        return [_multi_record("MTA-STS", len(recs), "RFC 8461")]
    tags = kv_record(recs[0])
    if not tags.get("id"):
        return [Finding("MTA-STS", FAIL, "Rekord MTA-STS bez wymaganego pola id", "Dodaj id=<unikalny ciąg>, zmieniaj je przy każdej zmianie polityki.")]
    return [Finding("MTA-STS", OK, f"MTA-STS opublikowany (id={tags['id']}); treść polityki HTTPS nie jest tu sprawdzana")]


def _tls_rpt(d: DomainData, evaluate: bool) -> list[Finding]:
    if not evaluate:
        return []
    if d.tls_rpt.failed:
        return [_unreachable("TLS-RPT", "_smtp._tls", d.tls_rpt)]
    recs = select_records(d.tls_rpt, "tls_rpt")
    if not recs:
        return [Finding("TLS-RPT", INFO, "Brak TLS-RPT", "Dodaj TXT _smtp._tls: 'v=TLSRPTv1; rua=mailto:...', by dostawać raporty o problemach z TLS w poczcie.")]
    if len(recs) > 1:
        return [_multi_record("TLS-RPT", len(recs), "RFC 8460")]
    tags = kv_record(recs[0])
    if not tags.get("rua"):
        return [Finding("TLS-RPT", WARN, "TLS-RPT bez adresu rua", "Dodaj rua=mailto:... lub rua=https://...")]
    return [Finding("TLS-RPT", OK, f"TLS-RPT: raporty na {tags['rua']}")]


def _bimi(d: DomainData, evaluate: bool) -> list[Finding]:
    if not evaluate:
        return []
    if d.bimi.failed:
        return [_unreachable("BIMI", "default._bimi", d.bimi)]
    recs = select_records(d.bimi, "bimi")
    if not recs:
        return [Finding("BIMI", INFO, "Brak BIMI (opcjonalne: logo marki w skrzynkach odbiorców)", "Wymaga DMARC p=quarantine/reject; opcjonalnie certyfikat VMC.")]
    if len(recs) > 1:
        return [_multi_record("BIMI", len(recs), "specyfikacji BIMI")]
    tags = kv_record(recs[0])
    out = [Finding("BIMI", OK, f"BIMI: logo {tags.get('l') or '(puste, deklaracja rezygnacji)'}" + (", certyfikat VMC" if tags.get("a") else ""))]
    dm = [parse_dmarc(r) for r in _filter(d.dmarc, is_dmarc)]
    if dm and _effective_dmarc_policy(dm[0]) == "none":
        out.append(Finding("BIMI", WARN, "BIMI wymaga DMARC p=quarantine lub reject, a jest p=none", "Zaostrz politykę DMARC, inaczej BIMI nie zadziała."))
    elif not dm and not d.dmarc.failed:
        out.append(Finding("BIMI", WARN, "BIMI wymaga egzekwowanego DMARC (p=quarantine/reject), a DMARC nie jest opublikowany", "Opublikuj DMARC z p=quarantine lub reject, inaczej BIMI nie zadziała."))
    return out


# --- rekordy weryfikacyjne ----------------------------------------------------------

def _verifications(d: DomainData) -> list[Finding]:
    if d.txt.failed or not d.txt.ok:
        return []
    ver = detect_verifications(d.txt.records)
    others = [r for r in d.txt.records if not is_email_auth(r) and not any(v.record == r.strip() for v in ver)]
    if not ver and not others:
        return []
    out: list[Finding] = []
    if ver:
        services = sorted({v.service for v in ver})
        out.append(Finding(
            "TXT", INFO, f"Rekordy weryfikacyjne ujawniają {len(services)} usług: " + "; ".join(services),
            "Sprawdź, czy wszystkie są nadal używane. Nieużywane rekordy usuń: zdradzają dostawców i mogą pozwolić na przejęcie weryfikacji.",
        ))
    if others:
        out.append(Finding("TXT", INFO, f"Nierozpoznane rekordy TXT: {len(others)} (ani weryfikacja usługi, ani poczta)"))
    return out
