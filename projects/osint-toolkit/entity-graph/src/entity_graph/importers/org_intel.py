"""Import eksportu JSON albo lokalnego magazynu `store.json` pakietu org-intel (OFFLINE, sama stdlib).

Co trafia do grafu (bez nowych typów encji):
  * Organization (kind=company): wartość = nazwa prawna; krs/nip/regon (znormalizowane jak w identifiers.py, z sumą
    kontrolną), previous_names, country, opcjonalnie status (z listy ORG_STATUSES), status_raw i registered_address
    (adres siedziby osoby prawnej; org-intel nie przyjmuje adresów osób fizycznych), org_intel_id, provenance;
  * Domain: verification_status, verified_at (tylko razem ze statusem verified), org_intel_id, provenance;
  * Incident -> Organization z kind=breach, TA SAMA konwencja klucza co importer hibp-monitor (wartość = tytuł, a bez
    niego nazwa), więc incydent z org-intel i wyciek z hibp-monitor to jeden węzeł;
  * Source -> URL z kind=source (nigdy profile/gravatar, więc źródło nie bierze udziału w korelacji kont).
Relacje: owns_domain (Organization->Domain), associated_with_incident (Domain->Incident: ta sama domena = direct,
subdomena incydentu = inferred, jak org-intel/correlate.py), has_source (Organization/Domain/Incident -> Source).
Edge.source = "org-intel:<znormalizowany URL źródła>": dwa źródła tego samego faktu to dwie krawędzie, ponowny import to
ta sama krawędź (niezależnie od nazwy pliku). Osoby z eksportu są POMIJANE w całości: żadnych węzłów ani krawędzi
Person/Email/Username/Phone (twarda asercja na końcu parse).

Walidacja jest niezależna od org-intel (pakiety nie importują się nawzajem): strażnicy są SKOPIOWANE z
org-intel/src/org_intel/guards.py (check_secrets, check_source_signals, reject_forbidden_relations, reguły źródeł) i
quality.py (jakość źródła), a potem WZMOCNIONE (fail-closed): dane logowania i adresy e-mail w URL, hosty IP / lokalne /
ukryte / fora wycieków, zgodność hosta z typem źródła (allowlisty poniżej), brak wartości domyślnych dla derivation,
reliability i statusu domeny, sumy kontrolne NIP/REGON, prawdziwe daty (nie z przyszłości), e-maile maskowane w każdym
polu tekstowym zapisywanym do grafu. Rekord odrzucony nie blokuje pozostałych (poza trybem strict).

Wartości krawędzi: pewność high=0.9, medium=0.6, low=0.3, a dla inferred najwyżej 0.6; znacznik czasu = najwcześniejsza
obserwacja z danego źródła (nie zmienia się, gdy źródło zostanie pobrane ponownie)."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from urllib.parse import unquote, urlsplit

from ..identifiers import normalize_krs, normalize_nip, normalize_regon, regon_core
from ..model import Edge, Graph, Node, Status
from ..normalize import EntityType, normalize
from .base import ImportCtx, Imported

TOOL = "org-intel"
SCHEMA_VERSION = 1
SOURCE_PREFIX = "org-intel:"
MAX_DESCRIPTION = 2000
MAX_RECORDS = 20000
MAX_CLASSES = 30
MAX_PREVIOUS_NAMES = 20
INFERRED_CAP = 0.6
CONFIDENCE = {"high": 0.9, "medium": 0.6, "low": 0.3}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_STATUS_RANK = {"verified": 3, "pending": 2, "unverified": 1, "failed": 0}  # failed nie nadpisuje verified
SECTIONS = ("sources", "organizations", "domains", "persons", "incidents", "observations")
# Kopia ORG_STATUSES z org-intel/normalize.py (pakiety się nie importują): status organizacji z rejestru.
ORG_STATUSES = frozenset(
    {"aktywna", "zawieszona", "w_likwidacji", "w_upadlosci", "w_restrukturyzacji", "wykreslona", "inny"}
)
MAX_ADDRESS = 300
RELATIONS = frozenset({"owns_domain", "associated_with_incident", "has_source"})
# Twarda granica importera: te typy nigdy nie powstają z org-intel (osoby i konta poza zakresem).
FORBIDDEN_TYPES = frozenset({EntityType.PERSON, EntityType.EMAIL, EntityType.USERNAME, EntityType.PHONE})
_STATUS_FLAGS = {
    "verified": "is_verified",
    "fabricated": "is_fabricated",
    "spam_list": "is_spam_list",
    "sensitive": "is_sensitive",
    "retired": "is_retired",
    "malware": "is_malware",
    "stealer_log": "is_stealer_log",
}
FLAG_KEYS = tuple(_STATUS_FLAGS.values())
_TAG_RE = re.compile(r"<[^>]*>")
_DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_MIN_YEAR = 1990
_FUTURE_SLACK = timedelta(days=1)

# Znane pola rekordów (schemat eksportu/store org-intel). Nieznane: liczone w raporcie; w trybie strict odrzucają rekord.
KNOWN_FIELDS = {
    "source": frozenset(
        {"id", "name", "url", "source_type", "license", "retrieved_at", "reliability", "notes", "content_hash"}
    ),
    "organization": frozenset(
        {
            "id",
            "legal_name",
            "previous_names",
            "krs",
            "nip",
            "regon",
            "country",
            "official_domain",
            "source_ids",
            "status",
            "status_raw",
            "registered_address",
        }
    ),
    "domain": frozenset({"id", "domain", "organization_id", "verification_status", "verified_at", "source_ids"}),
    "incident": frozenset(
        {
            "id",
            "name",
            "incident_date",
            "published_date",
            "affected_domain",
            "affected_accounts_count",
            "data_classes",
            "status",
            "description",
            "source_ids",
            "title",
        }
    ),
    "observation": frozenset(
        {
            "id",
            "entity_type",
            "entity_id",
            "source_id",
            "observed_at",
            "evidence_url",
            "confidence",
            "derivation",
            "evidence_hash",
            "notes",
        }
    ),
    "top": frozenset({*SECTIONS, "schema_version", "exported_at", "emails_masked", "attribution", "verifications"}),
}


# ------------------------------------------------------------------ strażnicy (kopia z org-intel/guards.py)


class Rejected(Exception):
    """Rekord albo źródło odrzucone z czytelnym powodem (bez danych z rekordu)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_SOURCE_TYPES = (
    "official_registry",
    "company_website",
    "official_document",
    "cert_advisory",
    "hibp_catalog",
    "ct_log",
    "passive_dns",
    "manual",
)
_FIRST_PARTY = frozenset({"official_registry", "company_website", "official_document"})
_LEAK_WORDS = ("dump", "leak", "combolist", "stealer", "paste", "breachforums", "t.me/", "telegram")
_LEAK_HOSTS = ("t.me", "telegram.me", "telegram.org", "pastebin.com", "ghostbin.com", "rentry.co", "anonfiles.com")
# Komunikaty CERT, dokumenty urzędowe i katalog HIBP opisują wycieki z natury ("wyciek-stealer-2023"): dla nich słowa
# kluczowe sprawdza się tylko w nazwie hosta (dokładnie jak w guards.py).
_DESCRIBES_LEAKS = frozenset({"cert_advisory", "official_document", "hibp_catalog"})
_PERSON_RELATION_KEYS = frozenset(
    {
        "person",
        "persons",
        "people",
        "email",
        "emails",
        "e_mail",
        "account",
        "accounts",
        "address",
        "addresses",
        "affected_emails",
        "affected_persons",
    }
)


def _norm_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_").replace(" ", "_")


def check_source_signals(name: str, source_type: str, url: str) -> None:
    """Odrzuca źródła wyglądające na dump / paste / Telegram / forum z wyciekami (guards.check_source_signals)."""
    host = (urlsplit(url).hostname or "").lower()
    _leak_signals(host if source_type in _DESCRIBES_LEAKS else f"{name} {source_type} {url}".lower(), host)


def _leak_signals(blob: str, host: str) -> None:
    """Słowa wycieku w `blob` (sam host albo nazwa+typ+URL) i znane hosty wycieków -> Rejected."""
    for word in _LEAK_WORDS:
        if word in blob:
            raise Rejected(f"źródło wygląda na dane z wycieku (sygnał: '{word}'); takie źródła są niedozwolone")
    if any(host == h or host.endswith("." + h) for h in _LEAK_HOSTS):
        raise Rejected(f"źródło wygląda na dane z wycieku (host {host}); takie źródła są niedozwolone")


_SECRET_KEY_EXACT = frozenset({"pass", "pwd", "hash", "session", "cookie", "authorization"})
_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "cookie",
    "authorization",
)
_HASH_KEYS_ALLOWED = frozenset({"content_hash", "evidence_hash"})
_URL_KEYS = frozenset({"url", "evidence_url"})
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_BCRYPT_RE = re.compile(r"\$2[aby]\$[0-9]{2}\$")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_EMAIL_PASS_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+[:;|](?!\d+(?:/|$))\S{3,}")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")


def _secret_key(key: str) -> bool:
    k = _norm_key(key)
    if k in _HASH_KEYS_ALLOWED:
        return False
    if k in _SECRET_KEY_EXACT or k.endswith(("_hash", "_session")) or k.startswith("session_"):
        return True
    return any(part in k for part in _SECRET_KEY_PARTS)


def check_secrets(value: object, path: str = "") -> None:
    """Rekurencyjnie sprawdza klucze i wartości; Rejected przy surowym sekrecie (guards.check_secrets).

    Dozwolone: pola content_hash/evidence_hash (sha256) oraz klasa danych "Passwords" jako etykieta."""
    if isinstance(value, dict):
        for key, item in value.items():
            if _secret_key(str(key)):
                raise Rejected(f"pole sekretu w rekordzie: '{key}' (surowe hasła, tokeny i hashe są niedozwolone)")
            check_secrets(item, f"{path}.{key}" if path else str(key))
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            check_secrets(item, path)
        return
    if not isinstance(value, str):
        return
    leaf = path.rsplit(".", 1)[-1]
    if _JWT_RE.search(value):
        raise Rejected(f"token JWT w wartości pola '{leaf}'")
    if _PRIVATE_KEY_RE.search(value):
        raise Rejected(f"klucz prywatny w wartości pola '{leaf}'")
    if _BCRYPT_RE.search(value):
        raise Rejected(f"hash bcrypt w wartości pola '{leaf}'")
    if _BEARER_RE.search(value):
        raise Rejected(f"token Bearer w wartości pola '{leaf}'")
    if not re.match(r"^https?://", value.strip(), re.IGNORECASE) and _EMAIL_PASS_RE.search(value):
        raise Rejected(f"para e-mail:hasło w wartości pola '{leaf}'")
    if _norm_key(leaf) not in _HASH_KEYS_ALLOWED | _URL_KEYS and _HEX_RE.search(value):
        raise Rejected(f"ciąg hex 32/40/64 znaków (podejrzenie hasha) w polu '{leaf}'")


def reject_forbidden_relations(record: dict) -> None:
    """Incydent nie łączy się z osobami, e-mailami ani kontami (guards.reject_forbidden_relations, kind=incident)."""
    if {_norm_key(k) for k in record} & _PERSON_RELATION_KEYS:
        raise Rejected("incydent nie może być powiązany z osobami, adresami e-mail ani kontami")


# ------------------------------------------------------------------ hosty: blokady i allowlisty (fail-closed)

# Hosty, których nie przyjmujemy w żadnym polu URL (źródło, evidence_url): adresy IP w każdej postaci, nazwy lokalne
# i wewnętrzne, sieci ukryte oraz znane fora i rynki wycieków (dopasowanie hosta i subdomen oraz słowa w hoście).
LOCAL_SUFFIXES = ("localhost", "local", "internal", "onion", "i2p")
FORUM_HOSTS = (
    "raidforums.com",
    "breachforums.st",
    "breachforums.is",
    "breachforums.hn",
    "xss.is",
    "exploit.in",
    "cracked.io",
    "nulled.to",
    "leakbase.io",
    "leakbase.cc",
    "dread.cx",
)
FORUM_WORDS = ("raidforums", "breachforums", "leakbase")  # słowo gdziekolwiek w nazwie hosta
FORUM_LABEL_PREFIXES = ("nulled",)  # etykieta hosta zaczyna się od słowa (żeby nie łapać "annulled")
FORUM_LABELS = ("dread",)  # cała etykieta hosta (żeby nie łapać "dreadnought")
_NUMERIC_PART = re.compile(r"0[xX][0-9a-fA-F]+|[0-9]+")


def _under(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def is_ip_host(host: str) -> bool:
    """Adres IP w każdej postaci: IPv4 z kropkami, dziesiętny (2130706433), szesnastkowy/ósemkowy (0x7f000001,
    0177.0.0.1), IPv6 (także w nawiasach). Host z numeryczną ostatnią etykietą też jest traktowany jak IP."""
    h = host.strip().strip("[]").split("%", 1)[0].rstrip(".")
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    parts = h.split(".")
    return (len(parts) <= 4 and all(_NUMERIC_PART.fullmatch(p) for p in parts)) or bool(
        _NUMERIC_PART.fullmatch(parts[-1])
    )


def check_host(host: str, what: str) -> None:
    """Odrzuca hosty IP, lokalne/wewnętrzne/ukryte i fora wycieków. `what` = np. "źródło" (do komunikatu)."""
    if not host:
        raise Rejected(f"{what}: adres bez nazwy hosta")
    if is_ip_host(host):
        raise Rejected(f"{what}: adres IP zamiast nazwy hosta (w żadnej postaci) jest niedozwolony")
    if "." not in host or _under(host, LOCAL_SUFFIXES):
        raise Rejected(
            f"{what}: host lokalny, wewnętrzny albo z sieci ukrytej (.onion, .i2p, localhost, .local, .internal)"
        )
    labels = host.split(".")
    if (
        _under(host, FORUM_HOSTS)
        or any(w in host for w in FORUM_WORDS)
        or any(lab in FORUM_LABELS or lab.startswith(FORUM_LABEL_PREFIXES) for lab in labels)
    ):
        raise Rejected(f"{what}: host znanego forum albo rynku z wyciekami jest niedozwolony")


def _fully_unquoted(text: str) -> str:
    """Odkodowanie %XX do skutku (także podwójne %2540 -> %40 -> @), najwyżej kilka rund."""
    for _ in range(4):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


def _split_url(url: str, what: str) -> tuple[str, str]:
    """Surowy URL (przed jakąkolwiek normalizacją) -> (host, ścieżka). Dane logowania i '@' w URL (także zakodowane
    jako %40) = odrzucenie; tylko HTTPS na porcie 443 (fail-closed: bez TLS i z innym portem nie przyjmujemy)."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise Rejected(f"{what} wymaga adresu http/https")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        raise Rejected(f"{what}: niepoprawny adres URL") from None
    if "@" in parts.netloc:
        raise Rejected(f"{what}: URL z danymi logowania (user:hasło@ albo user@) jest odrzucany, nie czyszczony")
    if "@" in url:
        raise Rejected(f"{what}: URL zawiera '@' poza hostem (adres e-mail albo dane logowania)")
    if "@" in _fully_unquoted(url):
        raise Rejected(f"{what}: URL zawiera zakodowany '@' (%40): dane logowania albo adres e-mail")
    if parts.scheme.lower() != "https" or port not in (None, 443):
        raise Rejected(f"{what}: wymagany HTTPS na porcie 443 (bez TLS albo inny port = odrzucenie)")
    check_host(host, what)
    return host, parts.path.lower()


@dataclass(frozen=True)
class HostRules:
    """Allowlisty hostów wg typu źródła. Wartości produkcyjne to stałe poniżej; testy wstrzykują własne obiektem
    (dataclasses.replace), nigdy przez CLI. Domena oficjalna organizacji z tego samego importu jest osobnym źródłem
    zaufania (company_website, vendor_advisory, public_report)."""

    registry: tuple[tuple[str, str], ...] = (
        ("ekrs.ms.gov.pl", ""),
        ("prs.ms.gov.pl", ""),
        ("api-krs.ms.gov.pl", ""),
        ("wyszukiwarkaregon.stat.gov.pl", ""),
        ("api.stat.gov.pl", ""),
        ("biznes.gov.pl", "/ceidg"),
        ("dane.biznes.gov.pl", ""),
        ("wl-api.mf.gov.pl", ""),
    )
    advisory: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("cert", ("cert.pl", "cert.europa.eu", "enisa.europa.eu")),
        ("nask", ("nask.pl",)),
        ("csirt", ("csirt.gov.pl", "gov.pl")),
    )
    public_report: tuple[str, ...] = ("gov.pl", "europa.eu")
    hibp: tuple[str, ...] = ("haveibeenpwned.com", "api.haveibeenpwned.com")  # dokładnie te hosty
    ct_log: tuple[str, ...] = (
        "crt.sh",
        "ct.googleapis.com",
        "ct.cloudflare.com",
        "ct.letsencrypt.org",
        "ct.digicert.com",
        "ct.sectigo.com",
    )


DEFAULT_RULES = HostRules()


@dataclass(frozen=True)
class SourceRule:
    categories: tuple[str, ...]  # kategorie importera, jakie może dostać typ org-intel
    host_rule: str  # opis reguły hosta (dokumentacja i komunikaty)


# Jawne mapowanie typów org-intel na kategorie importera. Typ bez wpisu = odrzucenie (fail-closed).
SOURCE_TYPE_TABLE: dict[str, SourceRule] = {
    "official_registry": SourceRule(("official_registry",), "tylko rejestry: HostRules.registry"),
    "company_website": SourceRule(("official_company",), "tylko host = domena oficjalna organizacji z importu"),
    "cert_advisory": SourceRule(
        ("cert", "csirt", "nask", "vendor_advisory"),
        "hosty CERT/CSIRT/NASK (HostRules.advisory) albo domena oficjalna organizacji z importu (vendor_advisory)",
    ),
    "official_document": SourceRule(
        ("public_report",), "*.gov.pl, *.europa.eu (HostRules.public_report) albo domena oficjalna organizacji"
    ),
    "hibp_catalog": SourceRule(("hibp_catalog",), "tylko haveibeenpwned.com i api.haveibeenpwned.com"),
    "ct_log": SourceRule(("ct_log",), "tylko znane logi CT (HostRules.ct_log, m.in. crt.sh)"),
    "passive_dns": SourceRule(
        ("passive_dns",), "dowolny host publiczny (blokady IP/lokalne/fora); jakość najwyżej low"
    ),
    "manual": SourceRule(("manual",), "dowolny host publiczny (blokady IP/lokalne/fora); jakość najwyżej low"),
}
# Bazowa jakość kategorii (kopia z org-intel/quality.py, z jawnym vendor_advisory = medium: organizacja o sobie).
CATEGORY_QUALITY = {
    "official_registry": "high",
    "official_company": "high",
    "cert": "high",
    "csirt": "high",
    "nask": "high",
    "vendor_advisory": "medium",
    "public_report": "medium",  # high dla hostów urzędowych (poniżej)
    "hibp_catalog": "medium",
    "ct_log": "medium",
    "passive_dns": "low",
    "manual": "low",
}
_OFFICIAL_HOSTS = ("gov.pl", "nask.pl", "cert.pl", "ms.gov.pl", "europa.eu")


def classify_source(
    source_type: str, host: str, path: str, official: frozenset[str], rules: HostRules
) -> tuple[str, bool]:
    """-> (kategoria importera, czy przyjęta tylko dzięki domenie oficjalnej z importu) albo Rejected (host nie pasuje
    do typu źródła). Domena oficjalna pochodzi z tego samego, niezaufanego pliku: pozwala przypisać kategorię, ale nie
    podnosi jakości (patrz OFFICIAL_DOMAIN_QUALITY)."""
    if source_type not in SOURCE_TYPE_TABLE:
        raise Rejected(f"typ źródła bez reguły hosta: {source_type[:40]!r}")
    rule = SOURCE_TYPE_TABLE[source_type]
    ok: str | None = None
    via_official = False
    if source_type == "official_registry":
        if any(_under(host, [h]) and path.startswith(prefix) for h, prefix in rules.registry):
            ok = "official_registry"
    elif source_type == "company_website":
        ok, via_official = ("official_company", True) if _under(host, official) else (None, False)
    elif source_type == "cert_advisory":
        for category, hosts in rules.advisory:
            if _under(host, hosts):
                ok = category
                break
        else:
            ok, via_official = ("vendor_advisory", True) if _under(host, official) else (None, False)
    elif source_type == "official_document":
        if _under(host, rules.public_report):
            ok = "public_report"
        elif _under(host, official):
            ok, via_official = "public_report", True
    elif source_type == "hibp_catalog":
        ok = "hibp_catalog" if host in rules.hibp else None
    elif source_type == "ct_log":
        ok = "ct_log" if _under(host, rules.ct_log) else None
    else:
        ok = rule.categories[0]
    if ok is None:
        raise Rejected(f"host {host} nie pasuje do typu źródła {source_type} (dozwolone: {rule.host_rule})")
    return ok, via_official


# Źródło przyjęte tylko dlatego, że jego host to domena oficjalna wskazana w tym samym pliku: ta domena jest
# niezweryfikowana (plik mógł ją podać dowolnie), więc jakość takiego źródła jest najwyżej low.
OFFICIAL_DOMAIN_QUALITY = "low"


def _official_evidence_host(host: str, rules: HostRules) -> bool:
    """Host z allowlist instytucji (rejestry, CERT/CSIRT/NASK, raporty urzędowe, HIBP, hosty urzędowe)."""
    advisory = [h for _, hosts in rules.advisory for h in hosts]
    registry = [h for h, _ in rules.registry]
    return _under(host, [*registry, *advisory, *rules.public_report, *rules.hibp, *_OFFICIAL_HOSTS])


def category_quality(category: str, host: str, reliability: str, via_official: bool = False) -> str:
    """min(baza kategorii, reliability); dokument z hosta urzędowego ma bazę high (jak w org-intel/quality.py);
    źródło uznane tylko przez domenę oficjalną z importu: najwyżej OFFICIAL_DOMAIN_QUALITY."""
    base = CATEGORY_QUALITY[category]
    if category == "public_report" and _under(host, _OFFICIAL_HOSTS):
        base = "high"
    if via_official:
        base = min(base, OFFICIAL_DOMAIN_QUALITY, key=_CONF_RANK.__getitem__)
    return min(base, reliability, key=_CONF_RANK.__getitem__)


# ------------------------------------------------------------------ identyfikatory firm i daty

_NIP_W = (6, 5, 7, 2, 3, 4, 5, 6, 7)
_REGON9_W = (8, 9, 2, 3, 4, 5, 6, 7)
_REGON14_W = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)


def _nip_ok(nip: str) -> bool:
    s = sum(int(c) * w for c, w in zip(nip, _NIP_W, strict=False)) % 11
    return s != 10 and s == int(nip[9]) and int(nip) != 0


def _regon_ok(digits: str, weights: tuple[int, ...]) -> bool:
    s = sum(int(c) * w for c, w in zip(digits, weights, strict=False)) % 11
    return (0 if s == 10 else s) == int(digits[len(weights)])


def _regon_valid(regon: str) -> bool:
    if len(regon) == 9:
        return int(regon) != 0 and _regon_ok(regon, _REGON9_W)
    return _regon_ok(regon[:9], _REGON9_W) and _regon_ok(regon, _REGON14_W)


def _identifiers(rec: dict) -> dict[str, str]:
    """KRS/NIP/REGON (format i suma kontrolna): niepoprawny identyfikator odrzuca organizację (nie jest wycinany)."""
    out: dict[str, str] = {}
    for name, fn in (("krs", normalize_krs), ("nip", normalize_nip), ("regon", normalize_regon)):
        raw = rec.get(name)
        if raw is None or raw == "":
            continue
        value = fn(raw)
        if value is None or (name == "nip" and not _nip_ok(value)) or (name == "regon" and not _regon_valid(value)):
            raise Rejected(f"niepoprawny {name.upper()} (format albo suma kontrolna)")
        out[name] = value
    return out


def _moment(value: object, now: datetime, what: str) -> datetime:
    """Realna data ISO 8601 (data albo data z czasem; bez strefy = UTC), od 1990 i nie dalej niż doba w przyszłość."""
    if not isinstance(value, str) or not value.strip():
        raise Rejected(f"{what}: brak daty")
    text = value.strip()
    try:
        if _DATE_ONLY_RE.fullmatch(text):
            dt = datetime.combine(date.fromisoformat(text), time(), tzinfo=UTC)
        else:
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            dt = dt.astimezone(UTC)
    except ValueError:
        raise Rejected(f"{what}: niepoprawna data (ISO 8601, istniejący dzień)") from None
    if dt.year < _MIN_YEAR:
        raise Rejected(f"{what}: data sprzed {_MIN_YEAR} roku")
    if dt > now + _FUTURE_SLACK:
        raise Rejected(f"{what}: data z przyszłości")
    return dt


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _domain(raw: object, what: str) -> tuple[str, str]:
    """Domena (klucz, wartość): bez '@', bez adresu IP w żadnej postaci i poprawna po normalizacji entity-graph."""
    text = str(raw or "").strip()
    if "@" in text:
        raise Rejected(f"{what}: domena zawiera '@' (dane logowania albo adres e-mail)")
    bare = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text.lower())
    if is_ip_host(bare if bare.startswith("[") else re.split(r"[/:?#]", bare, maxsplit=1)[0]):
        raise Rejected(f"{what}: adres IP podany jako domena")
    try:
        key, display = normalize(EntityType.DOMAIN, text)
    except ValueError:
        raise Rejected(f"{what}: niepoprawna domena") from None
    if is_ip_host(key):
        raise Rejected(f"{what}: adres IP podany jako domena")
    return key, display


# ------------------------------------------------------------------ konfiguracja przebiegu, maskowanie, liczniki

# Lokalna część z "*": adres już częściowo zamaskowany przez org-intel (np. j***@domena) też znika w całości.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+*-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
EMAIL_MASK = "[e-mail ukryty]"


class _Tally:
    """Liczniki (zamaskowane pola, nieznane pola) zatwierdzane dopiero, gdy rekord został przyjęty."""

    def __init__(self) -> None:
        self.total: Counter[str] = Counter()
        self._pending: Counter[str] = Counter()

    def add(self, key: str, n: int = 1) -> None:
        self._pending[key] += n

    def commit(self) -> None:
        self.total.update(self._pending)
        self._pending.clear()

    def rollback(self) -> None:
        self._pending.clear()


@dataclass
class _Cfg:
    now: datetime
    strict: bool
    rules: HostRules
    official: frozenset[str]
    import_id: str
    tally: _Tally = field(default_factory=_Tally)

    def mask(self, text: str) -> str:
        """Adresy e-mail w polu tekstowym zapisywanym do grafu -> EMAIL_MASK w całości: bez pierwszej litery i bez
        domeny (zlicza zamaskowane pola)."""
        out = _EMAIL_RE.sub(EMAIL_MASK, text)
        if out != text:
            self.tally.add("masked")
        return out

    def unknown(self, rec: dict, kind: str) -> None:
        extra = set(rec) - KNOWN_FIELDS[kind]
        if not extra:
            return
        self.tally.add("unknown", len(extra))
        if self.strict:
            names = sorted(str(k) for k in extra if re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", str(k)))[:5]
            raise Rejected("nieznane pola rekordu (tryb strict): " + (", ".join(names) or "(nazwy pominięte)"))


# ------------------------------------------------------------------ rozpoznanie formatu


def kind_of(data) -> str | None:
    """'export' (org-intel export --format json), 'store' (lokalny store.json), 'unsupported' (inna wersja
    schematu) albo None. Znaczniki: schema_version + wszystkie sekcje jako listy oraz exported_at (eksport) albo
    verifications (magazyn). Plik wejściowy org-intel (sources z `key`, bez schema_version) nie jest rozpoznawany."""
    if not isinstance(data, dict) or not all(isinstance(data.get(k), list) for k in SECTIONS):
        return None
    if "exported_at" in data:
        kind = "export"
    elif isinstance(data.get("verifications"), dict):
        kind = "store"
    else:
        return None
    version = data.get("schema_version")
    return kind if type(version) is int and version == SCHEMA_VERSION else "unsupported"


# ------------------------------------------------------------------ wynik importu


@dataclass
class Rejection:
    label: str  # rodzaj + identyfikator org-intel (+ nazwa tylko, gdy bezpieczna); bez danych osobowych
    reason: str


@dataclass
class OrgIntelImported(Imported):
    format: str = ""
    rejected: list[Rejection] = field(default_factory=list)
    rejected_edges: int = 0
    skipped_people: int = 0
    warnings: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)  # liczby rekordów w pliku (bez treści)
    import_id: str = ""
    masked_fields: int = 0  # pola tekstowe, w których zamaskowano e-mail
    unknown_fields: int = 0  # nieznane pola przyjętych rekordów (w strict odrzucają rekord)
    strict: bool = False


@dataclass
class _Src:
    id: str
    name: str  # nazwa źródła z org-intel (po maskowaniu e-maili)
    original: str  # adres dokładnie w postaci zapisanej przez org-intel (nie przez entity-graph)
    url: str  # adres do pokazania w węźle URL (entity-graph normalize_url: bez www., fragmentu i danych logowania)
    key: str  # klucz URL (stabilny, bez schematu): source_url_normalized, tylko do deduplikacji i identyfikacji węzła
    source_type: str
    category: str  # kategoria importera (SOURCE_TYPE_TABLE)
    license: str
    retrieved_at: str
    reliability: str
    content_hash: str | None
    quality: str


@dataclass
class _Obs:
    source: _Src
    observed_at: str
    confidence: str
    derivation: str
    evidence_hash: str | None
    evidence_url: str


def _safe_name(value) -> str:
    """Nazwa do etykiety odrzucenia: tylko gdy nie wygląda na sekret ani adres e-mail."""
    text = " ".join(str(value or "").split())[:60]
    if not text or "@" in text:
        return ""
    try:
        check_secrets(text, "name")
    except Rejected:
        return ""
    return text


def _label(kind: str, rec, index: int, name_field: str | None = None) -> str:
    rid = rec.get("id") if isinstance(rec, dict) else None
    base = (
        f"{kind} {rid}" if isinstance(rid, str) and re.fullmatch(r"[a-z]{3}_[0-9a-f]{16}", rid) else f"{kind} #{index}"
    )
    name = _safe_name(rec.get(name_field)) if name_field and isinstance(rec, dict) else ""
    return f"{base} ({name})" if name else base


def _clean_description(text: str) -> str:
    text = html.unescape(_TAG_RE.sub("", text))
    text = " ".join(text.split())
    if len(text) > MAX_DESCRIPTION:
        text = text[: MAX_DESCRIPTION - 1].rstrip() + "…"
    return text


def _text(value, cfg: _Cfg, width: int = 200) -> str:
    return cfg.mask(" ".join(str(value or "").split())[:width])


def _require_enum(rec: dict, key: str, allowed, what: str) -> str:
    """Wartość wymagana i z enuma (dokładnie, bez wartości domyślnych)."""
    value = rec.get(key)
    if not isinstance(value, str) or not value.strip():
        raise Rejected(f"{what}: brak pola {key}")
    value = value.strip()
    if value not in allowed:
        raise Rejected(f"{what}: niepoprawna wartość pola {key}")
    return value


# ------------------------------------------------------------------ źródła i obserwacje


def _build_source(rec: dict, cfg: _Cfg) -> _Src:
    """Źródło wymaga nazwy, typu z listy, adresu http/https (bez danych logowania, hosta IP/lokalnego/forum, z hostem
    zgodnym z typem), retrieved_at ISO 8601 i reliability z enuma (guards.validate_source, wzmocnione)."""
    check_secrets(rec)
    sid = rec.get("id")
    if not isinstance(sid, str) or not sid:
        raise Rejected("źródło bez identyfikatora")
    cfg.unknown(rec, "source")
    name = str(rec.get("name") or "").strip()
    url = str(rec.get("url") or "").strip()
    raw_type = str(rec.get("source_type") or "").strip()
    try:
        check_source_signals(name, raw_type, url)
    except ValueError:  # urlsplit na zepsutym adresie
        raise Rejected("niepoprawny adres url źródła") from None
    if not name:
        raise Rejected("źródło bez nazwy")
    if raw_type not in _SOURCE_TYPES:
        raise Rejected(f"nieznany typ źródła: {raw_type[:40]!r}")
    host, path = _split_url(url, "źródło")
    try:
        key, display = normalize(EntityType.URL, url)
    except ValueError:
        raise Rejected("niepoprawny adres url źródła") from None
    retrieved = _iso(_moment(rec.get("retrieved_at"), cfg.now, "źródło: retrieved_at"))
    reliability = _require_enum(rec, "reliability", CONFIDENCE, "źródło")
    content_hash = rec.get("content_hash")
    if content_hash is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", str(content_hash)):
        raise Rejected("content_hash musi być sha256 w hex (64 znaki)")
    category, via_official = classify_source(raw_type, host, path, cfg.official, cfg.rules)
    return _Src(
        sid,
        _text(name, cfg),
        url,
        display,
        key,
        raw_type,
        category,
        _text(rec.get("license"), cfg),
        retrieved,
        reliability,
        str(content_hash).lower() if content_hash else None,
        category_quality(category, host, reliability, via_official),
    )


def _build_observation(rec: dict, source: _Src, cfg: _Cfg) -> _Obs:
    check_secrets(rec)
    cfg.unknown(rec, "observation")
    confidence = _require_enum(rec, "confidence", CONFIDENCE, "obserwacja")
    derivation = _require_enum(rec, "derivation", ("direct", "inferred"), "obserwacja")
    observed = _iso(_moment(rec.get("observed_at"), cfg.now, "obserwacja: observed_at"))
    evidence_hash = rec.get("evidence_hash")
    if evidence_hash is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", str(evidence_hash)):
        raise Rejected("evidence_hash musi być sha256 w hex (64 znaki)")
    evidence_url = source.original
    raw_url = rec.get("evidence_url")
    if raw_url is not None and str(raw_url).strip():
        raw_url = str(raw_url).strip()
        _split_url(raw_url, "obserwacja: evidence_url")  # surowy string: dane logowania/IP/forum = odrzucenie rekordu
        # te same sygnały wycieku co dla URL źródła (pastebin, t.me, dump/leak/stealer itd.). Jak dla źródeł: oficjalny
        # komunikat (typ opisujący wycieki albo host z allowlist CERT/urzędów/rejestrów/HIBP) jest sprawdzany tylko
        # po hoście, więc słowo "stealer" w ścieżce komunikatu CERT nie odrzuca rekordu.
        try:
            ev_host = (urlsplit(raw_url).hostname or "").lower().rstrip(".")
            host_only = source.source_type in _DESCRIBES_LEAKS or _official_evidence_host(ev_host, cfg.rules)
            _leak_signals(ev_host if host_only else raw_url.lower(), ev_host)
        except Rejected as exc:
            raise Rejected(f"obserwacja: evidence_url: {exc.reason}") from None
        except ValueError:
            raise Rejected("obserwacja: niepoprawny evidence_url") from None
        try:
            normalize(EntityType.URL, raw_url)  # tylko walidacja; w dowodzie zostaje adres, jak zapisał org-intel
        except ValueError:
            raise Rejected("obserwacja: niepoprawny evidence_url") from None
        evidence_url = raw_url
    return _Obs(
        source, observed, confidence, derivation, str(evidence_hash).lower() if evidence_hash else None, evidence_url
    )


def _entity_observations(
    rec: dict,
    etype: str,
    sources: dict[str, _Src],
    bad_sources: dict[str, str],
    obs_index: dict[tuple[str, str], list[dict]],
    cfg: _Cfg,
) -> list[_Obs]:
    """Źródła rekordu i jego obserwacje z poprawnych źródeł; brak źródła / proweniencji = odrzucenie."""
    ids = rec.get("source_ids")
    if not isinstance(ids, list) or not ids:
        raise Rejected("brak źródła")
    usable: dict[str, _Src] = {}
    dropped: list[str] = []
    for sid in ids:
        if not isinstance(sid, str) or not sid:
            raise Rejected("brak źródła (niepoprawny identyfikator źródła)")
        if sid in sources:
            usable[sid] = sources[sid]
        elif sid in bad_sources:
            dropped.append(bad_sources[sid])
        else:
            raise Rejected(f"brak źródła (nieistniejące źródło {sid[:40]!r})")
    if not usable:
        raise Rejected(
            "rekord oparty wyłącznie na odrzuconych źródłach (" + "; ".join(sorted(set(dropped)))[:200] + ")"
        )
    out: list[_Obs] = []
    for orec in obs_index.get((etype, str(rec.get("id"))), []):
        src = usable.get(orec.get("source_id"))
        if src is not None:
            out.append(_build_observation(orec, src, cfg))
    if not out:
        raise Rejected("brak obserwacji (proweniencji) z poprawnego źródła")
    return out


# ------------------------------------------------------------------ proweniencja i krawędzie


def _best(items: list[_Obs], derive: Callable[[_Obs], str] | None = None) -> _Obs:
    """Najmocniejsza obserwacja: direct przed inferred, wyższa pewność, potem najwcześniejsza (stabilność)."""
    derive = derive or (lambda o: o.derivation)
    return min(items, key=lambda o: (derive(o) != "direct", -_CONF_RANK[o.confidence], o.observed_at, o.source.id))


def _by_source(obs: list[_Obs]) -> dict[str, list[_Obs]]:
    groups: dict[str, list[_Obs]] = {}
    for o in obs:
        groups.setdefault(o.source.key, []).append(o)
    return groups


def _provenance(obs: list[_Obs], cfg: _Cfg) -> list[dict]:
    """Lista {source_url_original, source_url_normalized, source_name, source_type, source_category, retrieved_at,
    confidence, derivation, evidence_hash, quality, import_id}, bez duplikatów po (source_url_normalized, derivation);
    przy powtórzeniu zostaje obserwacja o wyższej pewności, a potem wcześniejsza. Oryginał to adres zapisany przez
    org-intel. import_id to identyfikator pierwszego importu, który wniósł wpis (przy ponownym imporcie istniejący wpis
    zostaje, więc graf się nie zmienia)."""
    chosen: dict[tuple[str, str], _Obs] = {}
    for o in obs:
        key = (o.source.key, o.derivation)
        cur = chosen.get(key)
        if cur is None or (-_CONF_RANK[o.confidence], o.observed_at) < (-_CONF_RANK[cur.confidence], cur.observed_at):
            chosen[key] = o
    return [
        {
            "source_url_original": o.source.original,
            "source_url_normalized": o.source.key,
            "source_name": o.source.name,
            "source_type": o.source.source_type,
            "source_category": o.source.category,
            "retrieved_at": o.observed_at,
            "confidence": o.confidence,
            "derivation": o.derivation,
            "evidence_hash": o.evidence_hash,
            "quality": o.source.quality,
            "import_id": cfg.import_id,
        }
        for _, o in sorted(chosen.items())
    ]


def _edge_confidence(label: str, derivation: str) -> float:
    value = CONFIDENCE[label]
    return min(value, INFERRED_CAP) if derivation == "inferred" else value


def _edge(src: Node, dst: Node, relation: str, obs: _Obs, derivation: str) -> Edge:
    evidence = (
        f"{derivation}; {obs.source.source_type}; {obs.observed_at}; {obs.source.original}; "
        f"evidence_hash={(obs.evidence_hash or 'brak')[:12]}"
    )
    if obs.evidence_url != obs.source.original:
        evidence += f"; evidence_url={obs.evidence_url}"
    return Edge(
        src.id,
        dst.id,
        relation,
        SOURCE_PREFIX + obs.source.key,
        _edge_confidence(obs.confidence, derivation),
        evidence,
        obs.observed_at,
    )


def _first_party_direct(o: _Obs) -> str:
    """Jak _domain_derivation w org-intel/correlate.py: direct tylko z obserwacji direct ze źródła first-party."""
    return "direct" if o.derivation == "direct" and o.source.source_type in _FIRST_PARTY else "inferred"


def _is_same_or_subdomain(candidate: str, parent: str) -> bool:
    return candidate == parent or candidate.endswith("." + parent)


# ------------------------------------------------------------------ budowa węzłów


def _text_list(values, cfg: _Cfg, limit: int, width: int) -> list[str]:
    if not isinstance(values, list):
        return []
    return [_text(v, cfg, width) for v in values if isinstance(v, str) and v.strip()][:limit]


def _id_conflicts(node: Node, ids: dict[str, str]) -> list[str]:
    out = []
    for name, fn in (("krs", normalize_krs), ("nip", normalize_nip), ("regon", normalize_regon)):
        mine, theirs = fn(node.attrs.get(name)), ids.get(name)
        if name == "regon":
            mine, theirs = regon_core(mine), regon_core(theirs)
        if mine and theirs and mine != theirs:
            out.append(name.upper())
    return out


def match_org(candidates: Iterable[Node], ids: dict[str, str]) -> Node | None:
    """Organizacja z tym samym KRS, potem NIP, potem REGON (spośród kandydatów: węzły sprawy i węzły z tego pliku).
    Ten sam identyfikator przy sprzecznym innym (np. ten sam KRS, inny NIP) odrzuca rekord z powodem."""
    candidates = list(candidates)
    for name, fn in (("krs", normalize_krs), ("nip", normalize_nip), ("regon", normalize_regon)):
        want = ids.get(name)
        if not want:
            continue
        for node in candidates:
            have = fn(node.attrs.get(name))
            same = regon_core(have) == regon_core(want) if name == "regon" else have == want
            if have and same:
                clash = _id_conflicts(node, ids)
                if clash:
                    raise Rejected(
                        f"konflikt identyfikatorów: ten sam {name.upper()} co istniejąca organizacja, ale "
                        f"sprzeczny {', '.join(clash)}"
                    )
                return node
    return None


def _node(etype: EntityType, raw: str, attrs: dict, sources: list[str]) -> Node:
    clean = {k: v for k, v in attrs.items() if v not in (None, "", [], {})}
    node = Node.make(etype, raw, clean, sources[0])
    node.sources = list(sources)
    return node


def _org_precheck(rec) -> str | None:
    """Domena oficjalna organizacji do reguł hostów (przed pełną walidacją): tylko z rekordu bez sekretów, z poprawną
    nazwą, identyfikatorami i domeną."""
    try:
        if not isinstance(rec, dict) or not rec.get("official_domain"):
            return None
        check_secrets(rec)
        if not isinstance(rec.get("legal_name"), str) or not rec["legal_name"].strip():
            return None
        _identifiers(rec)
        return _domain(rec["official_domain"], "official_domain")[0]
    except Rejected:
        return None


def _build_org(rec: dict, obs: list[_Obs], cfg: _Cfg, existing: Graph | None, file_nodes: list[Node]) -> Node:
    cfg.unknown(rec, "organization")
    name = rec.get("legal_name")
    if not isinstance(name, str) or not name.strip():
        raise Rejected("organizacja bez nazwy")
    name = _text(name, cfg, 500)
    ids = _identifiers(rec)
    if rec.get("official_domain"):
        _domain(rec["official_domain"], "official_domain")
    previous = _text_list(rec.get("previous_names"), cfg, MAX_PREVIOUS_NAMES, 200)
    status = rec.get("status")
    if status not in (None, "") and (not isinstance(status, str) or status not in ORG_STATUSES):
        raise Rejected("organizacja: niepoprawna wartość pola status")
    for key in ("status_raw", "registered_address"):
        if rec.get(key) not in (None, "") and not isinstance(rec[key], str):
            raise Rejected(f"organizacja: pole {key} musi być tekstem")
    companies = (
        [n for n in existing.nodes_of_type(EntityType.ORGANIZATION) if n.attrs.get("kind") != "breach"]
        if existing is not None
        else []
    )
    target = match_org([*companies, *file_nodes], ids)
    display = target.value if target is not None else name
    try:
        probe = Node.make(EntityType.ORGANIZATION, display)
        own_key = Node.make(EntityType.ORGANIZATION, name).key
    except ValueError:
        raise Rejected("niepoprawna nazwa organizacji") from None
    if target is not None and own_key != probe.key:
        previous.insert(0, name.strip())  # inna nazwa przy tym samym identyfikatorze: stara nazwa do previous_names
    previous = [p for p in dict.fromkeys(previous) if p != display]
    clash = existing.nodes.get(probe.id) if existing is not None else None
    if clash is not None and clash.attrs.get("kind") == "breach":
        raise Rejected(
            "kolizja klucza: w grafie jest węzeł wycieku o tej samej nazwie (dane firmy nie zostaną "
            "scalone z wyciekiem)"
        )
    attrs = {
        "kind": "company",
        **ids,
        "previous_names": previous,
        "country": _text(rec.get("country"), cfg, 8),
        "status": status or "",
        "status_raw": _text(rec.get("status_raw"), cfg, 200),
        "registered_address": _text(rec.get("registered_address"), cfg, MAX_ADDRESS),
        "org_intel_id": str(rec.get("id") or ""),
        "provenance": _provenance(obs, cfg),
    }
    return _node(EntityType.ORGANIZATION, display, attrs, _node_sources(obs))


def _build_domain(rec: dict, obs: list[_Obs], cfg: _Cfg) -> Node:
    cfg.unknown(rec, "domain")
    _key, display = _domain(rec.get("domain"), "domena")
    status = _require_enum(rec, "verification_status", _STATUS_RANK, "domena")
    verified_at = ""
    if status == "verified":  # status verified bez poprawnej daty to rekord niespójny: odrzucenie, nie degradacja
        verified_at = _iso(_moment(rec.get("verified_at"), cfg.now, "domena: verified_at"))
    attrs = {
        "verification_status": status,
        "verified_at": verified_at,
        "org_intel_id": str(rec.get("id") or ""),
        "provenance": _provenance(obs, cfg),
    }
    return _node(EntityType.DOMAIN, display, attrs, _node_sources(obs))


def _optional_date(rec: dict, key: str, cfg: _Cfg) -> str:
    value = rec.get(key)
    if value is None or value == "":
        return ""
    dt = _moment(value, cfg.now, f"incydent: {key}")
    return str(value).strip() if _DATE_ONLY_RE.fullmatch(str(value).strip()) else _iso(dt)


def _build_incident(
    rec: dict, obs: list[_Obs], cfg: _Cfg, existing: Graph | None, company_ids: set[str]
) -> tuple[Node, str]:
    reject_forbidden_relations(rec)
    cfg.unknown(rec, "incident")
    name = _text(rec.get("name"), cfg, 300)
    title = _text(rec.get("title"), cfg, 300)
    if not (name or title):
        raise Rejected("incydent bez nazwy")
    affected = _domain(rec["affected_domain"], "incydent: affected_domain")[0] if rec.get("affected_domain") else ""
    count = rec.get("affected_accounts_count")
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 0):
        raise Rejected("affected_accounts_count musi być liczbą całkowitą >= 0")
    raw_status = rec.get("status") or []
    if isinstance(raw_status, str):
        raw_status = [raw_status]
    statuses = {str(x).strip().lower() for x in raw_status}
    if not statuses <= set(_STATUS_FLAGS):
        raise Rejected("nieznany status incydentu")
    attrs = {"kind": "breach", "breach_name": name or title}
    for fld in ("incident_date", "published_date"):
        attrs[fld] = _optional_date(rec, fld, cfg)
    attrs.update(
        {
            "affected_domain": affected,
            "affected_accounts_count": count,
            "data_classes": _text_list(rec.get("data_classes"), cfg, MAX_CLASSES, 60),
            "description": cfg.mask(_clean_description(str(rec.get("description") or ""))),
            "org_intel_id": str(rec.get("id") or ""),
            "provenance": _provenance(obs, cfg),
        }
    )
    attrs.update({flag: True for status, flag in _STATUS_FLAGS.items() if status in statuses})
    node = _node(EntityType.ORGANIZATION, title or name, attrs, _node_sources(obs))
    clash = existing.nodes.get(node.id) if existing is not None else None
    if node.id in company_ids or (clash is not None and clash.attrs.get("kind") != "breach"):
        raise Rejected(
            "kolizja klucza: tytuł incydentu jest nazwą firmy w grafie (incydent nie zostanie scalony z firmą)"
        )
    return node, affected


def _node_sources(obs: list[_Obs]) -> list[str]:
    return sorted({SOURCE_PREFIX + o.source.key for o in obs})


def _source_node(src: _Src) -> Node:
    attrs = {
        "kind": "source",
        "source_url_original": src.original,
        "source_category": src.category,
        "source_type": src.source_type,
        "retrieved_at": src.retrieved_at,
        "reliability": src.reliability,
        "license": src.license,
        "content_hash": src.content_hash,
        "quality": src.quality,
    }
    return Node.make(EntityType.URL, src.url, {k: v for k, v in attrs.items() if v}, SOURCE_PREFIX + src.key)


def _absorb(first: Node, other: Node) -> None:
    """Dwa rekordy tego samego węzła w jednym pliku (np. ten sam KRS): atrybuty scalane jak przy imporcie do sprawy."""
    if first is other:
        return
    for k, v in other.attrs.items():
        if k == "provenance":
            first.attrs[k] = _merge_provenance(first.attrs.get(k), v)
        elif k not in first.attrs:
            first.attrs[k] = v
        elif isinstance(first.attrs[k], list) and isinstance(v, list):
            first.attrs[k] = first.attrs[k] + [x for x in v if x not in first.attrs[k]]
    _rank_pair(first, other)
    first.sources += [s for s in other.sources if s not in first.sources]


# ------------------------------------------------------------------ parse


def _fail(reason: str, fmt: str = "") -> OrgIntelImported:
    return OrgIntelImported(TOOL, error=reason, format=fmt)


def _parse_now(ctx: ImportCtx) -> datetime:
    dt = datetime.fromisoformat(ctx.now())
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def make_import_id(file_sha256: str, now: str) -> str:
    """imp_<12 hex z sha256(skrót pliku + czas importu)>: stabilny w obrębie jednego uruchomienia."""
    return "imp_" + hashlib.sha256(f"{file_sha256}|{now}".encode()).hexdigest()[:12]


def parse(
    data,
    ctx: ImportCtx,
    existing: Graph | None = None,
    *,
    strict: bool = False,
    rules: HostRules = DEFAULT_RULES,
    file_sha256: str | None = None,
) -> OrgIntelImported:
    """Eksport JSON / store.json org-intel -> węzły i krawędzie. `existing` (graf sprawy) służy tylko do odczytu:
    deduplikacji firm po KRS/NIP/REGON i wykrywania kolizji kluczy (nic nie jest w nim zmieniane). `strict`: nieznane
    pola rekordu odrzucają rekord (domyślnie są ignorowane i liczone). `rules`: allowlisty hostów (testy wstrzykują
    własne; CLI zawsze używa DEFAULT_RULES)."""
    kind = kind_of(data)
    if kind is None:
        return _fail("to nie jest eksport JSON ani store.json org-intel")
    if kind == "unsupported":
        return _fail(f"nieobsługiwana wersja schematu org-intel (obsługiwana: {SCHEMA_VERSION})", kind)
    if any(len(data[k]) > MAX_RECORDS for k in SECTIONS):
        return _fail(f"za dużo rekordów (limit {MAX_RECORDS} na sekcję)", kind)
    now = _parse_now(ctx)
    if file_sha256 is None:
        file_sha256 = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    official = frozenset(d for d in (_org_precheck(r) for r in data["organizations"]) if d)
    cfg = _Cfg(now, strict, rules, official, make_import_id(file_sha256, ctx.now()))
    imp = OrgIntelImported(TOOL, format=kind, import_id=cfg.import_id, strict=strict)
    imp.skipped_people = sum(1 for p in data["persons"] if isinstance(p, dict))  # osoby: poza zakresem importu
    imp.counts = {k: len(data[k]) for k in SECTIONS if k not in ("persons", "observations")}
    imp.counts["persons_skipped"] = imp.skipped_people
    if kind == "export" and data.get("emails_masked") is not True:
        imp.warnings.append(
            "eksport nie ma emails_masked=true: zachowanie ostrożne, e-maile w polach tekstowych są maskowane, "
            "osoby pominięte"
        )
    elif kind == "store":
        imp.warnings.append(
            "store.json nie ma pola emails_masked (może zawierać pełne adresy e-mail osób): osoby pominięte, "
            "e-maile w polach tekstowych maskowane"
        )
    top_unknown = len(set(data) - KNOWN_FIELDS["top"])
    cfg.tally.add("unknown", top_unknown)
    cfg.tally.commit()

    def reject(label: str, reason: str) -> None:
        cfg.tally.rollback()
        imp.rejected.append(Rejection(label, reason))
        imp.runs.append((label, Status.UNKNOWN, f"odrzucony: {reason}"))

    if strict and top_unknown:  # tryb strict: nieznany klucz najwyższego poziomu = odmowa całego pliku
        names = sorted(str(k) for k in set(data) - KNOWN_FIELDS["top"] if re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", str(k)))
        reject("plik", "nieznane klucze najwyższego poziomu (tryb strict): " + (", ".join(names[:5]) or "(pominięte)"))

    sources: dict[str, _Src] = {}
    bad_sources: dict[str, str] = {}
    for i, rec in enumerate(data["sources"], 1):
        label = _label("źródło", rec, i)
        try:
            if not isinstance(rec, dict):
                raise Rejected("rekord nie jest obiektem")
            src = _build_source(rec, cfg)
            clash = existing.nodes.get(f"url:{src.key}") if existing is not None else None
            if clash is not None and clash.attrs.get("kind") != "source":  # fail-closed: nie wiążemy z cudzym URL
                raise Rejected(f"kolizja: URL źródła istnieje w grafie jako {clash.attrs.get('kind') or 'brak kind'}")
            sources[src.id] = src
            cfg.tally.commit()
        except Rejected as exc:
            reject(label, exc.reason)
            if isinstance(rec, dict) and isinstance(rec.get("id"), str):
                bad_sources[rec["id"]] = exc.reason
    obs_index: dict[tuple[str, str], list[dict]] = {}
    for orec in data["observations"]:
        if isinstance(orec, dict) and orec.get("entity_type") != "person":
            obs_index.setdefault((str(orec.get("entity_type")), str(orec.get("entity_id"))), []).append(orec)

    orgs: dict[str, tuple[Node, list[_Obs]]] = {}  # id org-intel -> (węzeł, obserwacje)
    org_nodes: dict[str, Node] = {}  # id węzła grafu -> pierwszy węzeł z tego pliku (duplikaty po KRS/NIP/REGON)
    domains: dict[str, tuple[Node, list[_Obs], dict]] = {}
    incidents: list[tuple[Node, list[_Obs], str]] = []
    rejected_ids: dict[str, set[str]] = {"organization": set(), "domain": set(), "incident": set()}

    def entity(section: str, etype: str, label_kind: str, name_field: str | None, build) -> None:
        for i, rec in enumerate(data[section], 1):
            label = _label(label_kind, rec, i, name_field)
            try:
                if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
                    raise Rejected("rekord bez identyfikatora")
                check_secrets(rec)
                obs = _entity_observations(rec, etype, sources, bad_sources, obs_index, cfg)  # też sekrety/daty
                build(rec, obs)
                cfg.tally.commit()
            except Rejected as exc:
                reject(label, exc.reason)
                if isinstance(rec, dict) and isinstance(rec.get("id"), str):
                    rejected_ids[etype].add(rec["id"])

    def add_org(rec: dict, obs: list[_Obs]) -> None:
        node = _build_org(rec, obs, cfg, existing, list(org_nodes.values()))
        first = org_nodes.setdefault(node.id, node)
        _absorb(first, node)
        orgs[rec["id"]] = (first, obs)

    def add_domain(rec: dict, obs: list[_Obs]) -> None:
        domains[rec["id"]] = (_build_domain(rec, obs, cfg), obs, rec)

    entity("organizations", "organization", "organizacja", "legal_name", add_org)
    entity("domains", "domain", "domena", "domain", add_domain)
    company_ids = {n.id for n, _ in orgs.values()}

    def add_incident(rec: dict, obs: list[_Obs]) -> None:
        node, affected = _build_incident(rec, obs, cfg, existing, company_ids)
        incidents.append((node, obs, affected))

    entity("incidents", "incident", "incydent", "name", add_incident)

    nodes: dict[str, Node] = {}
    edges: dict[tuple, Edge] = {}

    def keep(node: Node) -> Node:
        first = nodes.setdefault(node.id, node)
        _absorb(first, node)
        return first

    def link_sources(node: Node, obs: list[_Obs]) -> None:
        for _key, group in sorted(_by_source(obs).items()):
            best = _best(group)
            target = keep(_source_node(best.source))
            edge = _edge(node, target, "has_source", best, best.derivation)
            edges.setdefault(edge.key, edge)

    for node, obs in orgs.values():
        link_sources(keep(node), obs)
    for node, obs, _rec in domains.values():
        link_sources(keep(node), obs)
    for node, obs, _affected in incidents:
        link_sources(keep(node), obs)

    for node, obs, rec in domains.values():  # organizacja -> domena
        org_ref = rec.get("organization_id")
        if not isinstance(org_ref, str) or not org_ref or org_ref not in orgs:
            continue
        org_node = orgs[org_ref][0]
        for _key, group in sorted(_by_source(obs).items()):
            best = _best(group, _first_party_direct)
            edge = _edge(org_node, nodes[node.id], "owns_domain", best, _first_party_direct(best))
            edges.setdefault(edge.key, edge)

    domain_nodes = {node.key: nodes[node.id] for node, _obs, _rec in domains.values()}
    for inc_node, obs, affected in incidents:  # domena -> incydent
        if not affected:
            continue
        for dkey, dom_node in sorted(domain_nodes.items()):
            if not _is_same_or_subdomain(affected, dkey):
                continue
            same = affected == dkey  # ta sama domena: direct; subdomena domeny znanej w eksporcie: inferred

            def derive(o: _Obs, same: bool = same) -> str:
                return "direct" if same and o.derivation == "direct" else "inferred"

            for _key, group in sorted(_by_source(obs).items()):
                best = _best(group, derive)
                edge = _edge(dom_node, nodes[inc_node.id], "associated_with_incident", best, derive(best))
                edges.setdefault(edge.key, edge)

    imp.rejected_edges = _count_rejected_edges(data, obs_index, rejected_ids, set(bad_sources))
    imp.masked_fields = cfg.tally.total["masked"]
    imp.unknown_fields = cfg.tally.total["unknown"]

    imp.nodes = list(nodes.values())
    imp.edges = list(edges.values())
    for node in {id(n): n for n, _ in orgs.values()}.values():
        imp.runs.append((node.id, Status.FOUND, ""))
    for node, _obs, _rec in domains.values():
        imp.runs.append((node.id, Status.FOUND, ""))
    for node, _obs, _affected in incidents:
        imp.runs.append((node.id, Status.FOUND, ""))
    _assert_scope(imp)
    imp.note = (
        f"org-intel ({kind}): rekordów przyjętych {len(orgs) + len(domains) + len(incidents)}, "
        f"odrzuconych {len(imp.rejected)}, pominiętych osób {imp.skipped_people}"
    )
    return imp


def _count_rejected_edges(
    data: dict, obs_index: dict[tuple[str, str], list[dict]], rejected: dict[str, set[str]], bad_sources: set[str]
) -> int:
    """Krawędzie, które powstałyby z rekordów pliku, a nie powstały, bo któryś ich koniec (organizacja, domena,
    incydent) albo źródło zostało odrzucone: has_source, owns_domain i associated_with_incident (także inferred od
    domeny nadrzędnej). Krawędź liczy się raz (klucz: relacja, końce, id źródła); bez obserwacji nic by nie powstało."""

    def usable(etype: str, rec: dict) -> set[str]:
        listed = rec.get("source_ids")
        listed = {x for x in listed if isinstance(x, str)} if isinstance(listed, list) else set()
        return listed & {o.get("source_id") for o in obs_index.get((etype, rec["id"]), [])}

    records = {
        etype: [r for r in data[section] if isinstance(r, dict) and isinstance(r.get("id"), str)]
        for etype, section in (("organization", "organizations"), ("domain", "domains"), ("incident", "incidents"))
    }
    org_ids = {r["id"] for r in records["organization"]}
    domain_keys: list[tuple[str, str]] = []
    for rec in records["domain"]:
        try:
            domain_keys.append((rec["id"], normalize(EntityType.DOMAIN, str(rec.get("domain") or ""))[0]))
        except ValueError:
            pass
    lost: set[tuple] = set()

    def consider(relation: str, ends: tuple[tuple[str, str], ...], sid: str) -> None:
        if sid in bad_sources or any(rid in rejected[etype] for etype, rid in ends):
            lost.add((relation, ends, sid))

    for etype, recs in records.items():
        for rec in recs:
            for sid in usable(etype, rec):
                consider("has_source", ((etype, rec["id"]),), sid)
    for rec in records["domain"]:
        org_ref = rec.get("organization_id")
        if isinstance(org_ref, str) and org_ref in org_ids:
            for sid in usable("domain", rec):
                consider("owns_domain", (("organization", org_ref), ("domain", rec["id"])), sid)
    for rec in records["incident"]:
        try:
            affected = (
                normalize(EntityType.DOMAIN, str(rec["affected_domain"]))[0] if rec.get("affected_domain") else ""
            )
        except ValueError:
            continue
        for dom_id, dkey in domain_keys:
            if affected and _is_same_or_subdomain(affected, dkey):
                for sid in usable("incident", rec):
                    consider("associated_with_incident", (("domain", dom_id), ("incident", rec["id"])), sid)
    return len(lost)


def _assert_scope(imp: OrgIntelImported, graph: Graph | None = None) -> None:
    """Twarda granica (raise, nie assert, więc działa też przy -O): bez Person/Email/Username/Phone, bez krawędzi
    spoza trzech relacji, a has_source zawsze do węzła URL kind=source (w imporcie i, gdy podano `graph`, w grafie
    docelowym: istniejący węzeł o tym id z innym kind, np. profile, jest naruszeniem)."""
    forbidden = {t.value for t in FORBIDDEN_TYPES}
    bad = [n.id for n in imp.nodes if n.type in FORBIDDEN_TYPES]
    bad += [e.src for e in imp.edges if e.src.split(":", 1)[0] in forbidden]
    bad += [e.dst for e in imp.edges if e.dst.split(":", 1)[0] in forbidden]
    bad += [e.relation for e in imp.edges if e.relation not in RELATIONS]
    bad += [n.id for n in imp.nodes if n.type is EntityType.URL and n.attrs.get("kind") != "source"]
    in_import = {n.id: n for n in imp.nodes}
    for e in imp.edges:
        if e.relation != "has_source":
            continue
        target = in_import.get(e.dst)
        existing = graph.nodes.get(e.dst) if graph is not None else None
        if (
            target is None
            or target.type is not EntityType.URL
            or target.attrs.get("kind") != "source"
            or existing is not None
            and existing.attrs.get("kind") != "source"
        ):
            bad.append(e.dst)
    if bad:
        raise AssertionError(f"import org-intel naruszył granicę zakresu: {len(bad)} pozycji")


# ------------------------------------------------------------------ ranking i scalanie w grafie


def _merge_provenance(old, new) -> list[dict]:
    """Suma wpisów po (source_url_normalized, derivation); przy powtórzeniu zostaje wpis o wyższej pewności, a przy
    remisie istniejący (stąd import_id pierwszego importu)."""
    merged: dict[tuple[str, str], dict] = {}
    for entry in [*(old if isinstance(old, list) else []), *(new if isinstance(new, list) else [])]:
        if not isinstance(entry, dict):
            continue
        key = (str(entry.get("source_url_normalized")), str(entry.get("derivation")))
        cur = merged.get(key)
        if cur is None or _CONF_RANK.get(entry.get("confidence"), -1) > _CONF_RANK.get(cur.get("confidence"), -1):
            merged[key] = entry
    return [merged[k] for k in sorted(merged)]


def _rank_pair(old: Node, node: Node) -> None:
    """Ranking pól „lepsze nie jest nadpisywane gorszym” między dwoma węzłami tej samej encji (po obu stronach)."""
    if node.type is EntityType.DOMAIN:
        _rank_status(old, node)
    elif node.attrs.get("kind") == "breach":
        a, b = old.attrs.get("affected_accounts_count"), node.attrs.get("affected_accounts_count")
        if isinstance(a, int) and isinstance(b, int) and not isinstance(a, bool) and not isinstance(b, bool):
            node.attrs["affected_accounts_count"] = old.attrs["affected_accounts_count"] = max(a, b)
        for flag in FLAG_KEYS:
            if old.attrs.get(flag) is True and flag not in node.attrs:
                node.attrs[flag] = True
            elif node.attrs.get(flag) is True:
                old.attrs[flag] = True


def rank_existing(graph: Graph, imp: Imported) -> None:
    """„Nie nadpisuj lepszych danych gorszymi”: merge_value zostawia pierwszą niepustą wartość skalara, więc pola
    z rankingiem ustawiamy PRZED scaleniem w istniejącym węźle i w węźle importu (merge staje się no-opem).
    verification_status: verified > pending > unverified > failed (verified_at tylko razem z verified);
    affected_accounts_count = max; flagi is_* = OR; provenance bez duplikatów (source_url_normalized, derivation).
    Obserwowane pola (OBSERVED_FIELDS) i model.py pozostają nietknięte."""
    for node in imp.nodes:
        old = graph.nodes.get(node.id)
        if old is None:
            continue
        if "provenance" in node.attrs:
            node.attrs["provenance"] = old.attrs["provenance"] = _merge_provenance(
                old.attrs.get("provenance"), node.attrs["provenance"]
            )
        _rank_pair(old, node)


def _rank_status(old: Node, new: Node) -> None:
    a, b = old.attrs.get("verification_status"), new.attrs.get("verification_status")
    if a not in _STATUS_RANK or b not in _STATUS_RANK:
        return
    winner = b if _STATUS_RANK[b] > _STATUS_RANK[a] else a
    old.attrs["verification_status"] = new.attrs["verification_status"] = winner
    if winner == "verified":
        when = (
            old.attrs.get("verified_at")
            if a == "verified" and old.attrs.get("verified_at")
            else new.attrs.get("verified_at")
        )
        if when:
            old.attrs["verified_at"] = new.attrs["verified_at"] = when
    else:
        old.attrs.pop("verified_at", None)
        new.attrs.pop("verified_at", None)


@dataclass
class ImportStats:
    nodes_created: int = 0
    nodes_updated: int = 0
    nodes_unchanged: int = 0
    edges_created: int = 0
    edges_updated: int = 0
    edges_unchanged: int = 0
    rejected_records: int = 0
    rejected_edges: int = 0
    skipped_people: int = 0
    masked_fields: int = 0
    unknown_fields: int = 0
    import_id: str = ""

    @property
    def changed(self) -> bool:
        return bool(self.nodes_created or self.nodes_updated or self.edges_created or self.edges_updated)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _fingerprint(obj) -> str:
    return hashlib.sha256(json.dumps(obj.to_dict(), sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def apply(graph: Graph, imp: OrgIntelImported, filename: str, now: str) -> ImportStats:
    """rank_existing + merge_into_graph (importers/__init__) i liczenie utworzonych/zaktualizowanych/bez zmian.
    „Zaktualizowany” = węzeł lub krawędź istniały, a ich zapis (attrs, źródła, pewność, dowód) się zmienił.
    RunRecord dopisywany przez merge_into_graph to dziennik przebiegów, nie część idempotencji danych."""
    from . import merge_into_graph

    _assert_scope(imp, graph)  # przed jakąkolwiek zmianą grafu
    before_nodes = {n.id: _fingerprint(graph.nodes[n.id]) for n in imp.nodes if n.id in graph.nodes}
    before_edges = {e.key: _fingerprint(graph.edges[e.key]) for e in imp.edges if e.key in graph.edges}
    rank_existing(graph, imp)  # po odcisku "przed": ulepszenie istniejącego węzła też jest zmianą
    merge_into_graph(graph, imp, filename, now)
    stats = ImportStats(
        rejected_records=len(imp.rejected),
        rejected_edges=imp.rejected_edges,
        skipped_people=imp.skipped_people,
        masked_fields=imp.masked_fields,
        unknown_fields=imp.unknown_fields,
        import_id=imp.import_id,
    )
    for node in imp.nodes:
        if node.id not in before_nodes:
            stats.nodes_created += 1
        elif _fingerprint(graph.nodes[node.id]) != before_nodes[node.id]:
            stats.nodes_updated += 1
        else:
            stats.nodes_unchanged += 1
    for edge in imp.edges:
        if edge.key not in graph.edges:
            continue
        if edge.key not in before_edges:
            stats.edges_created += 1
        elif _fingerprint(graph.edges[edge.key]) != before_edges[edge.key]:
            stats.edges_updated += 1
        else:
            stats.edges_unchanged += 1
    return stats
