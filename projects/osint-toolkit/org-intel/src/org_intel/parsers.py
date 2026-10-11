"""Parsery wejscia: wlasny format JSON oraz katalog metadanych HIBP (2 warianty).

Parser nie dotyka sieci ani magazynu. Zwraca zaakceptowane encje, obserwacje (proweniencja) i liste
odrzucen; odrzucenie jednego rekordu nie przerywa importu pozostalych.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from . import guards, quality
from .correlate import find_matching_organization, find_organization
from .guards import RejectedRecord
from .hibp_catalog import CATALOG_FIELDS
from .logging_redact import mask_emails
from .models import (
    FIRST_PARTY_TYPES,
    Confidence,
    Derivation,
    Domain,
    EntityType,
    Incident,
    IncidentStatus,
    Observation,
    Organization,
    Person,
    Source,
    SourceType,
    incident_id,
    make_id,
    observation_id,
    organization_id,
    person_id,
    sha256_hex,
)
from .normalize import (
    collapse_spaces,
    normalize_domain,
    normalize_krs,
    normalize_nip,
    normalize_org_status,
    normalize_regon,
    normalize_url,
)

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_DESCRIPTION = 2000
HIBP_CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_LICENSE = "CC BY 4.0 (wymagana atrybucja: Have I Been Pwned)"
HIBP_PAGE = "https://haveibeenpwned.com/PwnedWebsites"

FORMAT_OWN = "own"
FORMAT_HIBP_API = "hibp_api"
FORMAT_HIBP_MONITOR = "hibp_monitor"


class ParseError(Exception):
    """Blad calego wejscia (nieczytelny plik, zly format) z komunikatem dla uzytkownika."""


@dataclass
class Rejection:
    label: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "reason": self.reason}


@dataclass
class ParseResult:
    format: str = ""
    sources: list[Source] = field(default_factory=list)
    organizations: list[Organization] = field(default_factory=list)
    domains: list[Domain] = field(default_factory=list)
    persons: list[Person] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)
    warnings: list[Rejection] = field(default_factory=list)
    raw_records: list[dict] = field(default_factory=list)  # zaakceptowane rekordy wejsciowe (tylko audit-mode)

    @property
    def accepted_count(self) -> int:
        return len(self.organizations) + len(self.domains) + len(self.persons) + len(self.incidents)


# --- wczytywanie ---------------------------------------------------------------


def load_json_file(path: Path) -> object:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ParseError(f"Nie można odczytać pliku {path}: {exc.strerror or exc}") from None
    if size > MAX_FILE_BYTES:
        raise ParseError(f"Plik {path} ma {size // (1024 * 1024)} MB; limit to {MAX_FILE_BYTES // (1024 * 1024)} MB.")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ParseError(f"Nie można odczytać pliku {path} jako UTF-8: {exc}") from None
    return load_json_text(text, str(path))


def load_json_text(text: str, origin: str = "wejście") -> object:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError(f"{origin}: to nie jest poprawny JSON ({exc}).") from None


def detect_format(data: object) -> str:
    if isinstance(data, list):
        if any(isinstance(x, dict) and ("Name" in x or "name" in x) for x in data):
            return FORMAT_HIBP_API if any(isinstance(x, dict) and "Name" in x for x in data) else FORMAT_HIBP_MONITOR
        if not data:
            raise ParseError("Pusta lista: nie rozpoznano formatu (oczekiwano katalogu HIBP albo obiektu z sekcjami).")
        raise ParseError("Nie rozpoznano formatu: lista bez obiektów z polem Name (katalog HIBP).")
    if isinstance(data, dict):
        if isinstance(data.get("breaches"), list):
            return FORMAT_HIBP_MONITOR
        if any(k in data for k in ("sources", "organizations", "domains", "persons", "incidents")):
            return FORMAT_OWN
        raise ParseError(
            "Nie rozpoznano formatu: oczekiwano sekcji sources/organizations/domains/persons/incidents "
            "albo katalogu HIBP (lista /api/v3/breaches albo wynik `hibp-monitor breaches --catalog --json`)."
        )
    raise ParseError("Nie rozpoznano formatu: korzeń JSON musi być obiektem lub listą.")


def parse_file(path: Path, *, known_orgs: Iterable[Organization] = (), now: datetime | None = None) -> ParseResult:
    data = load_json_file(path)
    meta = CatalogMeta(content_hash=hashlib.sha256(path.read_bytes()).hexdigest(), origin="plik lokalny")
    return parse_data(data, known_orgs=known_orgs, now=now, meta=meta)


def parse_text(
    text: str,
    *,
    known_orgs: Iterable[Organization] = (),
    now: datetime | None = None,
    meta: CatalogMeta | None = None,
) -> ParseResult:
    return parse_data(load_json_text(text), known_orgs=known_orgs, now=now, meta=meta)


def parse_data(
    data: object,
    *,
    known_orgs: Iterable[Organization] = (),
    now: datetime | None = None,
    meta: CatalogMeta | None = None,
) -> ParseResult:
    fmt = detect_format(data)
    if fmt == FORMAT_OWN:
        return parse_own(data, known_orgs=known_orgs)  # type: ignore[arg-type]
    return parse_hibp_catalog(data, now=now, meta=meta)


# --- wspolne ----------------------------------------------------------------------


def _now_iso(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label(section: str, idx: int, rec: object, name_keys: tuple[str, ...]) -> str:
    if isinstance(rec, dict):
        for k in name_keys:
            if rec.get(k):
                return f"{section}[{idx}] {str(rec[k])[:60]}"
    return f"{section}[{idx}]"


def _text(rec: dict, key: str, *, required: bool = False, limit: int = 500) -> str:
    value = rec.get(key)
    if value is None or value == "":
        if required:
            raise RejectedRecord(f"brak pola '{key}'")
        return ""
    if not isinstance(value, str):
        raise RejectedRecord(f"pole '{key}' musi być tekstem")
    return collapse_spaces(value)[:limit]


def _org_status(rec: dict) -> tuple[str | None, str | None]:
    """-> (status znormalizowany, status_raw). `status` moze byc tekstem z rejestru albo wartoscia z ORG_STATUSES;
    `status_raw` (opcjonalny) to oryginalny tekst z rejestru. Oba puste -> (None, None)."""
    given = _text(rec, "status", limit=200)
    raw = _text(rec, "status_raw", limit=200)
    if not given and not raw:
        return None, None
    return normalize_org_status(given or raw), raw or given


def _registered_address(rec: dict, ids: dict, srcs: list[Source]) -> str | None:
    """Adres siedziby tylko dla osoby prawnej / jednostki z rejestru urzedowego: wymaga KRS albo jawnego
    `legal_entity: true` (REGON typu P) oraz zrodla official_registry. Inaczej rekord jest odrzucany (adresy osob
    fizycznych, w tym JDG z CEIDG, nigdy nie trafiaja do magazynu)."""
    address = _text(rec, "registered_address", limit=300)
    if not address:
        return None
    legal = rec.get("legal_entity")
    if legal is not None and not isinstance(legal, bool):
        raise RejectedRecord("pole 'legal_entity' musi być true albo false")
    if legal is False or not (ids["krs"] or legal is True):
        raise RejectedRecord(
            "registered_address dozwolony tylko dla osoby prawnej / jednostki z KRS (KRS albo legal_entity=true); "
            "adresów osób fizycznych nie przyjmujemy"
        )
    if not any(s.source_type is SourceType.OFFICIAL_REGISTRY for s in srcs):
        raise RejectedRecord("registered_address wymaga źródła official_registry")
    return address


def _declared(rec: dict) -> tuple[Confidence | None, Derivation | None]:
    conf = rec.get("confidence")
    der = rec.get("derivation")
    try:
        c = Confidence(str(conf).strip().lower()) if conf not in (None, "") else None
    except ValueError:
        raise RejectedRecord(f"niepoprawna confidence: {conf!r}") from None
    try:
        d = Derivation(str(der).strip().lower()) if der not in (None, "") else None
    except ValueError:
        raise RejectedRecord(f"niepoprawna derivation: {der!r}") from None
    return c, d


def _evidence(rec: dict) -> tuple[str | None, str | None]:
    """-> (evidence_url, evidence_hash). Cytat dowodu jest tylko haszowany, nie zapisywany."""
    url = rec.get("evidence_url")
    display = None
    if url not in (None, ""):
        try:
            display = normalize_url(str(url))[1]
        except ValueError:
            raise RejectedRecord(f"niepoprawny evidence_url: {url!r}") from None
    ehash = rec.get("evidence_hash")
    if ehash not in (None, ""):
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(ehash)):
            raise RejectedRecord("evidence_hash musi być sha256 w hex (64 znaki)")
        return display, str(ehash).lower()
    quote_ = rec.get("evidence_quote")
    if isinstance(quote_, str) and quote_.strip():
        return display, sha256_hex(collapse_spaces(quote_))
    return display, None


def _iso_date(rec: dict, key: str) -> str | None:
    value = rec.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise RejectedRecord(f"pole '{key}' musi być datą ISO 8601")
    try:
        datetime.fromisoformat(value.strip())
    except ValueError:
        raise RejectedRecord(f"niepoprawna data w polu '{key}': {value!r}") from None
    return value.strip()


class _Builder:
    """Zbiera zaakceptowane encje i obserwacje dla jednego parsowania."""

    def __init__(self, result: ParseResult):
        self.result = result

    def observe(
        self,
        etype: EntityType,
        entity_id: str,
        sources: list[Source],
        *,
        declared: Confidence | None = None,
        derivation: Derivation | None = None,
        evidence_url: str | None = None,
        evidence_hash: str | None = None,
        notes: str = "",
        incident_status: list[IncidentStatus] | None = None,
    ) -> None:
        for src in sources:
            conf = quality.observation_confidence(src, declared, incident_status)
            der = derivation or Derivation.DIRECT
            url = evidence_url or src.url
            self.result.observations.append(
                Observation(
                    id=observation_id(etype, entity_id, src.id, url, src.retrieved_at, der),
                    entity_type=etype,
                    entity_id=entity_id,
                    source_id=src.id,
                    observed_at=src.retrieved_at,
                    evidence_url=url,
                    confidence=conf,
                    derivation=der,
                    evidence_hash=evidence_hash,
                    notes=notes,
                )
            )
            if src.id not in {s.id for s in self.result.sources}:
                self.result.sources.append(src)


# --- wlasny format ----------------------------------------------------------------


def _default_domain_derivation(sources: list[Source]) -> Derivation:
    return Derivation.DIRECT if any(s.source_type in FIRST_PARTY_TYPES for s in sources) else Derivation.INFERRED


def parse_own(data: dict, *, known_orgs: Iterable[Organization] = ()) -> ParseResult:
    result = ParseResult(format=FORMAT_OWN)
    build = _Builder(result)
    for section in ("sources", "organizations", "domains", "persons", "incidents"):
        if section in data and not isinstance(data[section], list):
            raise ParseError(f"Sekcja '{section}' musi być listą.")

    # 1. zrodla -------------------------------------------------------------
    key_map: dict[str, Source] = {}
    rejected_keys: set[str] = set()
    declared_sources: list[Source] = []
    for idx, rec in enumerate(data.get("sources", [])):
        label = _label("sources", idx, rec, ("key", "name"))
        try:
            if not isinstance(rec, dict):
                raise RejectedRecord("źródło musi być obiektem")
            key = rec.get("key")
            if not isinstance(key, str) or not key.strip():
                raise RejectedRecord("źródło bez pola 'key'")
            if key in key_map or key in rejected_keys:
                raise RejectedRecord(f"powtórzony klucz źródła {key!r}")
            try:
                sid = make_id("source", normalize_url(str(rec.get("url") or ""))[0])
            except ValueError:
                sid = ""  # validate_source zglosi dokladny powod
            body = {k: v for k, v in rec.items() if k != "key"}
            src = guards.validate_source(body, sid)
            key_map[key] = src
            declared_sources.append(src)
        except RejectedRecord as exc:
            if isinstance(rec, dict) and isinstance(rec.get("key"), str):
                rejected_keys.add(rec["key"])
            result.rejections.append(Rejection(label, exc.reason))

    # 2. organizacje ----------------------------------------------------------
    registry: dict[str, Organization] = {o.id: Organization.from_dict(o.to_dict()) for o in known_orgs}
    batch_org_ids: list[str] = []
    for idx, rec in enumerate(data.get("organizations", [])):
        label = _label("organizations", idx, rec, ("legal_name",))
        try:
            if not isinstance(rec, dict):
                raise RejectedRecord("rekord musi być obiektem")
            guards.check_secrets(rec)
            srcs = guards.require_sources(rec.get("sources"), key_map, rejected_keys)
            name = _text(rec, "legal_name", required=True, limit=300)
            ids = {}
            for attr, norm in (("krs", normalize_krs), ("nip", normalize_nip), ("regon", normalize_regon)):
                raw = rec.get(attr)
                if raw in (None, ""):
                    ids[attr] = None
                    continue
                ids[attr] = norm(raw)
                if ids[attr] is None:
                    raise RejectedRecord(f"niepoprawny {attr.upper()} (format lub suma kontrolna): {raw!r}")
            domain = None
            if rec.get("official_domain") not in (None, ""):
                try:
                    domain = normalize_domain(rec["official_domain"])
                except ValueError as exc:
                    raise RejectedRecord(str(exc)) from None
            prev = rec.get("previous_names") or []
            if not isinstance(prev, list) or not all(isinstance(x, str) for x in prev):
                raise RejectedRecord("previous_names musi być listą tekstów")
            status, status_raw = _org_status(rec)
            address = _registered_address(rec, ids, srcs)
            declared, derivation = _declared(rec)
            ev_url, ev_hash = _evidence(rec)

            org = Organization(
                id=organization_id(name, ids["krs"], ids["nip"], ids["regon"]),
                legal_name=name,
                previous_names=[collapse_spaces(x) for x in prev if x.strip()],
                krs=ids["krs"],
                nip=ids["nip"],
                regon=ids["regon"],
                country=(_text(rec, "country", limit=2) or "PL").upper(),
                official_domain=domain,
                source_ids=[s.id for s in srcs],
                status=status,
                status_raw=status_raw,
                registered_address=address,
            )
            match = find_matching_organization(registry.values(), org)
            if match is not None:
                for w in match.merge(org):
                    result.warnings.append(Rejection(label, w))
                org = match
            else:
                registry[org.id] = org
            if org.id not in batch_org_ids:
                batch_org_ids.append(org.id)
            build.observe(
                EntityType.ORGANIZATION,
                org.id,
                srcs,
                declared=declared,
                derivation=derivation,
                evidence_url=ev_url,
                evidence_hash=ev_hash,
            )
            result.raw_records.append({"kind": "organization", "record": rec})
            if domain:
                dom = Domain(
                    id=make_id("domain", domain), domain=domain, organization_id=org.id, source_ids=[s.id for s in srcs]
                )
                result.domains.append(dom)
                build.observe(
                    EntityType.DOMAIN,
                    dom.id,
                    srcs,
                    declared=declared,
                    derivation=derivation or _default_domain_derivation(srcs),
                    evidence_url=ev_url,
                    evidence_hash=ev_hash,
                    notes="official_domain z rekordu organizacji",
                )
        except RejectedRecord as exc:
            result.rejections.append(Rejection(label, exc.reason))
    result.organizations = [registry[i] for i in batch_org_ids]

    # 3. domeny -----------------------------------------------------------------
    for idx, rec in enumerate(data.get("domains", [])):
        label = _label("domains", idx, rec, ("domain",))
        try:
            if not isinstance(rec, dict):
                raise RejectedRecord("rekord musi być obiektem")
            guards.check_secrets(rec)
            srcs = guards.require_sources(rec.get("sources"), key_map, rejected_keys)
            try:
                domain = normalize_domain(rec.get("domain"))
            except ValueError as exc:
                raise RejectedRecord(str(exc)) from None
            org_id = None
            if rec.get("organization") not in (None, ""):
                org = find_organization(registry.values(), str(rec["organization"]))
                if org is None:
                    raise RejectedRecord(f"nieznana organizacja: {rec['organization']!r}")
                org_id = org.id
            declared, derivation = _declared(rec)
            ev_url, ev_hash = _evidence(rec)
            dom = Domain(
                id=make_id("domain", domain), domain=domain, organization_id=org_id, source_ids=[s.id for s in srcs]
            )
            result.domains.append(dom)
            build.observe(
                EntityType.DOMAIN,
                dom.id,
                srcs,
                declared=declared,
                derivation=derivation or _default_domain_derivation(srcs),
                evidence_url=ev_url,
                evidence_hash=ev_hash,
            )
            result.raw_records.append({"kind": "domain", "record": rec})
        except RejectedRecord as exc:
            result.rejections.append(Rejection(label, exc.reason))

    # 4. osoby publiczne ------------------------------------------------------------
    for idx, rec in enumerate(data.get("persons", [])):
        label = _label("persons", idx, rec, ("name",))
        try:
            if not isinstance(rec, dict):
                raise RejectedRecord("rekord musi być obiektem")
            guards.check_secrets(rec)
            guards.reject_forbidden_relations(rec, "person")
            srcs = guards.require_sources(rec.get("sources"), key_map, rejected_keys)
            ok_srcs, dropped = guards.require_person_sources(srcs)
            name = _text(rec, "name", required=True, limit=200)
            ref = rec.get("organization")
            if ref in (None, ""):
                raise RejectedRecord("osoba wymaga pola 'organization' (KRS, NIP, REGON lub nazwa)")
            org = find_organization(registry.values(), str(ref))
            if org is None:
                raise RejectedRecord(f"nieznana organizacja: {ref!r}")
            declared, derivation = _declared(rec)
            ev_url, ev_hash = _evidence(rec)

            email_src_keys = rec.get("email_source")
            if email_src_keys in (None, ""):
                email_srcs = ok_srcs
            else:
                email_srcs = guards.require_sources(email_src_keys, key_map, rejected_keys)
            decision = guards.decide_person_email(
                rec.get("public_email"),
                email_srcs,
                org.official_domain,
                rec.get("evidence_quote") if isinstance(rec.get("evidence_quote"), str) else None,
            )
            conf = quality.max_confidence(*(quality.observation_confidence(s, declared) for s in ok_srcs))
            person = Person(
                id=person_id(org.id, name),
                name=name,
                role=_text(rec, "role", limit=200),
                organization_id=org.id,
                public_email=decision.email,
                source_ids=[s.id for s in ok_srcs],
                confidence=conf,
            )
            result.persons.append(person)
            build.observe(
                EntityType.PERSON,
                person.id,
                ok_srcs,
                declared=declared,
                derivation=derivation,
                evidence_url=ev_url,
                evidence_hash=ev_hash,
                notes=decision.note,
            )
            if decision.note:
                result.warnings.append(Rejection(label, decision.note))
            for s in dropped:
                result.warnings.append(
                    Rejection(
                        label, f"pominięto źródło {s.name!r} (typ {s.source_type.value} nie dopuszcza danych osób)"
                    )
                )
            result.raw_records.append({"kind": "person", "record": rec})
        except RejectedRecord as exc:
            result.rejections.append(Rejection(label, exc.reason))

    # 5. incydenty --------------------------------------------------------------------
    for idx, rec in enumerate(data.get("incidents", [])):
        label = _label("incidents", idx, rec, ("name",))
        try:
            if not isinstance(rec, dict):
                raise RejectedRecord("rekord musi być obiektem")
            guards.check_secrets(rec)
            guards.reject_forbidden_relations(rec, "incident")
            srcs = guards.require_sources(rec.get("sources"), key_map, rejected_keys)
            name = _text(rec, "name", required=True, limit=200)
            affected = None
            if rec.get("affected_domain") not in (None, ""):
                try:
                    affected = normalize_domain(rec["affected_domain"])
                except ValueError as exc:
                    raise RejectedRecord(str(exc)) from None
            count = rec.get("affected_accounts_count")
            if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 0):
                raise RejectedRecord("affected_accounts_count musi być liczbą całkowitą >= 0")
            classes = rec.get("data_classes") or []
            if not isinstance(classes, list) or not all(isinstance(x, str) for x in classes):
                raise RejectedRecord("data_classes musi być listą tekstów")
            raw_status = rec.get("status") or []
            if isinstance(raw_status, str):
                raw_status = [raw_status]
            try:
                status = [IncidentStatus(str(x).strip().lower()) for x in raw_status]
            except ValueError as exc:
                raise RejectedRecord(f"nieznany status incydentu ({exc})") from None
            declared, derivation = _declared(rec)
            ev_url, ev_hash = _evidence(rec)
            inc = Incident(
                id=incident_id(name),
                name=name,
                incident_date=_iso_date(rec, "incident_date"),
                published_date=_iso_date(rec, "published_date"),
                affected_domain=affected,
                affected_accounts_count=count,
                data_classes=[collapse_spaces(x) for x in classes],
                status=[s for s in IncidentStatus if s in status],
                description=clean_description(str(rec.get("description") or "")),
                source_ids=[s.id for s in srcs],
                title=_text(rec, "title", limit=200),
            )
            result.incidents.append(inc)
            build.observe(
                EntityType.INCIDENT,
                inc.id,
                srcs,
                declared=declared,
                derivation=derivation,
                evidence_url=ev_url,
                evidence_hash=ev_hash,
                incident_status=inc.status,
            )
            result.raw_records.append({"kind": "incident", "record": rec})
        except RejectedRecord as exc:
            result.rejections.append(Rejection(label, exc.reason))

    # zrodla zadeklarowane, ale nieuzyte przez zaden rekord, tez trafiaja do magazynu (maja swoja proweniencje)
    known_ids = {s.id for s in result.sources}
    for src in declared_sources:
        if src.id not in known_ids:
            result.sources.append(src)
            known_ids.add(src.id)
    return result


# --- katalog HIBP ---------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]*>")
_BLOCK_TAG_RE = re.compile(
    r"</?(?:p|br|div|li|ul|ol|tr|td|th|table|blockquote|h[1-6])(?![A-Za-z])[^>]*>", re.IGNORECASE
)
MAX_TITLE = 200
MAX_NAME = 200
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_ALLOWED_RAW_KEYS = frozenset(CATALOG_FIELDS) | frozenset(CATALOG_FIELDS.values())


def clean_description(text: str) -> str:
    """Usuwa znaczniki HTML, odkodowuje encje (zapis to czysty tekst; nawiasy z encji zostaja tekstem), zwija biale
    znaki, maskuje adresy e-mail (j***@domena) i tnie do 2000 znakow."""
    text = html.unescape(_TAG_RE.sub("", _BLOCK_TAG_RE.sub(" ", text)))
    text = mask_emails(collapse_spaces(text))
    if len(text) > MAX_DESCRIPTION:
        text = text[: MAX_DESCRIPTION - 1].rstrip() + "…"
    return text


@dataclass(frozen=True)
class CatalogMeta:
    """Proweniencja pobrania/wczytania katalogu: skrot sha256 odpowiedzi (albo pliku), skad (online/cache/plik),
    ETag i Last-Modified, o ile serwer je podal. Trafia do notatek zrodla i do `evidence_hash` obserwacji."""

    content_hash: str | None = None
    origin: str = ""
    etag: str | None = None
    last_modified: str | None = None

    def details(self) -> str:
        parts = []
        if self.origin:
            parts.append(f"Pochodzenie: {self.origin}.")
        if self.etag:
            parts.append(f"ETag: {self.etag[:24]}.")
        if self.last_modified:
            parts.append(f"Last-Modified: {self.last_modified[:40]}.")
        if self.content_hash:
            parts.append("content_hash = sha256 odpowiedzi (przed minimalizacją).")
        return " ".join(parts)


def _meta_hash(meta: CatalogMeta | None) -> str | None:
    if meta and meta.content_hash and _SHA256_RE.fullmatch(meta.content_hash):
        return meta.content_hash.lower()
    return None


def hibp_source(retrieved_at: str, meta: CatalogMeta | None = None) -> Source:
    base = "Tylko metadane incydentów (bez danych kont, bez LogoPath)."
    record = {
        "name": "Have I Been Pwned - publiczny katalog metadanych naruszeń",
        "url": HIBP_CATALOG_URL,
        "source_type": SourceType.HIBP_CATALOG.value,
        "license": HIBP_LICENSE,
        "retrieved_at": retrieved_at,
        "reliability": Confidence.MEDIUM.value,
        "notes": f"{base} {meta.details()}".strip() if meta else base,
        "content_hash": _meta_hash(meta),
    }
    source_id = make_id("source", normalize_url(HIBP_CATALOG_URL)[0])
    try:
        return guards.validate_source(record, source_id)
    except RejectedRecord:  # np. nietypowy ETag wygladajacy na sekret: zostaje sam hash
        record["notes"] = base
        return guards.validate_source(record, source_id)


def _get(rec: dict, camel: str, snake: str, default=None):
    if camel in rec:
        return rec[camel]
    return rec.get(snake, default)


def _flag(value: object) -> bool:
    """Flaga jakosci: tylko jawne prawdy (bool/1/'true'); tekst 'false' nie jest prawda."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value == 1)


def _raw_projection(rec: dict) -> dict:
    """Do trybu audytowego trafiaja tylko dozwolone pola (bez LogoPath i pol spoza listy), e-maile zamaskowane."""
    out = {k: v for k, v in rec.items() if k in _ALLOWED_RAW_KEYS}
    for key in ("Title", "title", "Description", "description"):
        if isinstance(out.get(key), str):
            out[key] = mask_emails(out[key])
    return out


def parse_hibp_catalog(data: object, *, now: datetime | None = None, meta: CatalogMeta | None = None) -> ParseResult:
    """Obsluguje liste z API /api/v3/breaches (PascalCase) i wynik `hibp-monitor breaches --catalog --json`.

    Czytane sa tylko pola z `CATALOG_FIELDS`; rekord z polami kont/e-mail/sekretow jest odrzucany w calosci."""
    fmt = detect_format(data)
    if fmt == FORMAT_OWN:
        raise ParseError("To nie jest katalog HIBP.")
    items = data["breaches"] if isinstance(data, dict) else data
    result = ParseResult(format=fmt)
    build = _Builder(result)
    source = hibp_source(_now_iso(now), meta)
    evidence_hash = _meta_hash(meta)
    for idx, rec in enumerate(items):  # type: ignore[arg-type]
        label = _label("breaches", idx, rec, ("Name", "name"))
        try:
            if not isinstance(rec, dict):
                raise RejectedRecord("rekord musi być obiektem")
            for key in rec:
                reason = guards.catalog_forbidden_key(key)
                if reason:
                    raise RejectedRecord(reason)
            guards.check_secrets(rec)
            name = collapse_spaces(str(_get(rec, "Name", "name", "") or ""))
            if not name:
                raise RejectedRecord("brak pola Name")
            if "@" in name:
                raise RejectedRecord("nazwa incydentu nie może zawierać adresu e-mail")
            if len(name) > MAX_NAME:
                raise RejectedRecord(f"nazwa incydentu dłuższa niż {MAX_NAME} znaków")
            affected = None
            notes: list[str] = []
            raw_domain = _get(rec, "Domain", "domain", "")
            if raw_domain:
                try:
                    affected = normalize_domain(raw_domain)
                except ValueError:
                    notes.append(f"niepoprawna domena w katalogu: {str(raw_domain)[:80]!r}")
            count = _get(rec, "PwnCount", "pwn_count", None)
            try:
                count = int(count) if count not in (None, "") else None
            except (TypeError, ValueError):
                raise RejectedRecord(f"niepoprawne PwnCount: {count!r}") from None
            if count is not None and count < 0:
                raise RejectedRecord("PwnCount nie może być ujemne")
            classes = _get(rec, "DataClasses", "data_classes", []) or []
            if not isinstance(classes, list) or not all(isinstance(x, str) for x in classes):
                raise RejectedRecord("DataClasses musi być listą tekstów")
            flags = {
                IncidentStatus.VERIFIED: _get(rec, "IsVerified", "is_verified"),
                IncidentStatus.FABRICATED: _get(rec, "IsFabricated", "is_fabricated"),
                IncidentStatus.SPAM_LIST: _get(rec, "IsSpamList", "is_spam_list"),
                IncidentStatus.SENSITIVE: _get(rec, "IsSensitive", "is_sensitive"),
                IncidentStatus.RETIRED: _get(rec, "IsRetired", "is_retired"),
                IncidentStatus.MALWARE: _get(rec, "IsMalware", "is_malware"),
                IncidentStatus.STEALER_LOG: _get(rec, "IsStealerLog", "is_stealer_log"),
            }
            status = [s for s in IncidentStatus if _flag(flags.get(s))]
            modified = _date_or_none(_get(rec, "ModifiedDate", "modified_date"))
            if modified:
                notes.append(f"zmodyfikowano w katalogu: {modified}")
            inc = Incident(
                id=incident_id(name),
                name=name,
                incident_date=_date_or_none(_get(rec, "BreachDate", "breach_date")),
                published_date=_date_or_none(_get(rec, "AddedDate", "added_date")),
                affected_domain=affected,
                affected_accounts_count=count,
                data_classes=[collapse_spaces(x) for x in classes],
                status=status,
                description=clean_description(str(_get(rec, "Description", "description", "") or "")),
                source_ids=[source.id],
                title=mask_emails(collapse_spaces(str(_get(rec, "Title", "title", "") or "")))[:MAX_TITLE],
            )
            result.incidents.append(inc)
            build.observe(
                EntityType.INCIDENT,
                inc.id,
                [source],
                derivation=Derivation.DIRECT,
                evidence_url=f"{HIBP_PAGE}#{quote(name, safe='')}",
                evidence_hash=evidence_hash,
                incident_status=status,
                notes="; ".join(notes),
            )
            result.raw_records.append({"kind": "incident", "record": _raw_projection(rec)})
        except RejectedRecord as exc:
            result.rejections.append(Rejection(label, exc.reason))
    if not result.sources:
        result.sources.append(source)
    return result


def _date_or_none(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        datetime.fromisoformat(text)
    except ValueError:
        return None
    return text
