"""Model danych: zrodla, organizacje, domeny, osoby publiczne, incydenty i obserwacje (proweniencja).

Nie ma typow zrodel dla wyciekow ani relacji e-mail->osoba i osoba->incydent: incydent laczy sie
wylacznie z domena/organizacja (patrz correlate.py).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, ClassVar

from .normalize import collapse_spaces, fold, normalize_company_name


class SourceType(str, Enum):
    OFFICIAL_REGISTRY = "official_registry"  # KRS / CEIDG / REGON
    COMPANY_WEBSITE = "company_website"  # strona firmy (first-party)
    OFFICIAL_DOCUMENT = "official_document"  # PDF urzedowy albo firmowy
    CERT_ADVISORY = "cert_advisory"  # CERT Polska / NASK / CSIRT GOV / producent
    HIBP_CATALOG = "hibp_catalog"  # publiczny katalog metadanych incydentow HIBP
    CT_LOG = "ct_log"
    PASSIVE_DNS = "passive_dns"
    MANUAL = "manual"


# Zrodla, z ktorych wolno brac dane o osobach publicznych.
FIRST_PARTY_TYPES = frozenset({SourceType.OFFICIAL_REGISTRY, SourceType.COMPANY_WEBSITE, SourceType.OFFICIAL_DOCUMENT})


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Derivation(str, Enum):
    DIRECT = "direct"
    INFERRED = "inferred"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class IncidentStatus(str, Enum):
    """Flagi metadanych incydentu z katalogu HIBP. Incydent ma LISTE statusow (mozna miec kilka naraz)."""

    VERIFIED = "verified"
    FABRICATED = "fabricated"
    SPAM_LIST = "spam_list"
    SENSITIVE = "sensitive"
    RETIRED = "retired"
    MALWARE = "malware"
    STEALER_LOG = "stealer_log"  # tylko flaga metadanych; pakiet nie obsluguje stealer logs


class EntityType(str, Enum):
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    PERSON = "person"
    INCIDENT = "incident"


_PREFIX = {
    "source": "src",
    "organization": "org",
    "domain": "dom",
    "person": "per",
    "incident": "inc",
    "observation": "obs",
}


def make_id(kind: str, key: str) -> str:
    """Deterministyczny, krotki identyfikator: prefiks + 16 znakow sha256(typ|klucz naturalny)."""
    digest = hashlib.sha256(f"{kind}|{key}".encode()).hexdigest()[:16]
    return f"{_PREFIX[kind]}_{digest}"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def organization_id(legal_name: str, krs: str | None = None, nip: str | None = None, regon: str | None = None) -> str:
    """Klucz: KRS > NIP > REGON > znormalizowana nazwa."""
    if krs:
        key = f"krs:{krs}"
    elif nip:
        key = f"nip:{nip}"
    elif regon:
        key = f"regon:{regon}"
    else:
        key = f"name:{normalize_company_name(legal_name)}"
    return make_id("organization", key)


def _ser(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, list):
        return [_ser(x) for x in value]
    return value


class _Model:
    _ENUMS: ClassVar[dict[str, type[Enum]]] = {}
    _ENUM_LISTS: ClassVar[dict[str, type[Enum]]] = {}

    def to_dict(self) -> dict[str, Any]:
        return {f.name: _ser(getattr(self, f.name)) for f in fields(self)}  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        kwargs: dict[str, Any] = {}
        for f in fields(cls):  # type: ignore[arg-type]
            if f.name not in data:
                continue
            value = data[f.name]
            if f.name in cls._ENUMS and value is not None:
                value = cls._ENUMS[f.name](value)
            elif f.name in cls._ENUM_LISTS:
                value = [cls._ENUM_LISTS[f.name](x) for x in value or []]
            elif isinstance(value, list):
                value = list(value)
            kwargs[f.name] = value
        return cls(**kwargs)


def _union(a: list[str], b: list[str]) -> list[str]:
    out = list(a)
    out.extend(x for x in b if x not in out)
    return out


@dataclass
class Source(_Model):
    id: str
    name: str
    url: str
    source_type: SourceType
    license: str
    retrieved_at: str
    reliability: Confidence = Confidence.MEDIUM
    notes: str = ""
    content_hash: str | None = None

    _ENUMS: ClassVar[dict[str, type[Enum]]] = {"source_type": SourceType, "reliability": Confidence}


@dataclass
class Organization(_Model):
    id: str
    legal_name: str
    previous_names: list[str] = field(default_factory=list)
    krs: str | None = None
    nip: str | None = None
    regon: str | None = None
    country: str = "PL"
    official_domain: str | None = None
    source_ids: list[str] = field(default_factory=list)
    # Opcjonalne pola z rejestrow urzedowych. status: wartosc znormalizowana (normalize.ORG_STATUSES), status_raw:
    # tekst z rejestru. registered_address: adres siedziby TYLKO osoby prawnej / jednostki z KRS (patrz parsers).
    status: str | None = None
    status_raw: str | None = None
    registered_address: str | None = None

    def merge(self, other: Organization) -> list[str]:
        """Scala `other` do siebie (pierwsza wartosc wygrywa). Zwraca ostrzezenia o konfliktach."""
        warnings: list[str] = []
        if normalize_company_name(other.legal_name) != normalize_company_name(self.legal_name):
            for name in [other.legal_name, *other.previous_names]:
                if name != self.legal_name and name not in self.previous_names:
                    self.previous_names.append(name)
        else:
            self.previous_names = _union(self.previous_names, other.previous_names)
        for attr in ("krs", "nip", "regon", "official_domain"):
            mine, theirs = getattr(self, attr), getattr(other, attr)
            if not mine and theirs:
                setattr(self, attr, theirs)
            elif mine and theirs and mine != theirs:
                warnings.append(f"konflikt {attr} dla {self.legal_name}: zachowano {mine}, pominięto {theirs}")
        # Status i adres: pierwsza wartosc wygrywa (bez cichego nadpisania); status_raw idzie za statusem.
        if not self.status and other.status:
            self.status, self.status_raw = other.status, other.status_raw
        elif self.status and other.status and self.status != other.status:
            warnings.append(f"konflikt status dla {self.legal_name}: zachowano {self.status}, pominięto {other.status}")
        if not self.registered_address and other.registered_address:
            self.registered_address = other.registered_address
        elif (
            self.registered_address
            and other.registered_address
            and collapse_spaces(self.registered_address) != collapse_spaces(other.registered_address)
        ):
            warnings.append(f"konflikt registered_address dla {self.legal_name}: zachowano pierwszy adres")
        self.source_ids = _union(self.source_ids, other.source_ids)
        return warnings


@dataclass
class Domain(_Model):
    id: str
    domain: str
    organization_id: str | None = None
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verified_at: str | None = None
    source_ids: list[str] = field(default_factory=list)

    _ENUMS: ClassVar[dict[str, type[Enum]]] = {"verification_status": VerificationStatus}

    def merge(self, other: Domain) -> list[str]:
        warnings: list[str] = []
        if not self.organization_id and other.organization_id:
            self.organization_id = other.organization_id
        elif other.organization_id and other.organization_id != self.organization_id:
            warnings.append(f"konflikt organizacji dla domeny {self.domain}: zachowano pierwszą")
        self.source_ids = _union(self.source_ids, other.source_ids)
        return warnings  # status weryfikacji nigdy nie jest cofany przez ponowny import


@dataclass
class Person(_Model):
    id: str
    name: str
    role: str = ""
    organization_id: str = ""
    public_email: str | None = None
    source_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM

    _ENUMS: ClassVar[dict[str, type[Enum]]] = {"confidence": Confidence}

    def merge(self, other: Person) -> list[str]:
        if not self.role and other.role:
            self.role = other.role
        if not self.public_email and other.public_email:
            self.public_email = other.public_email
        self.source_ids = _union(self.source_ids, other.source_ids)
        return []


def person_id(organization_id_: str, name: str) -> str:
    return make_id("person", f"{organization_id_}|{fold(name).strip()}")


@dataclass
class Incident(_Model):
    """Publicznie opisany incydent (metadane). `status` to lista IncidentStatus (np. verified + sensitive)."""

    id: str
    name: str
    incident_date: str | None = None
    published_date: str | None = None
    affected_domain: str | None = None
    affected_accounts_count: int | None = None
    data_classes: list[str] = field(default_factory=list)
    status: list[IncidentStatus] = field(default_factory=list)
    description: str = ""
    source_ids: list[str] = field(default_factory=list)
    title: str = ""

    _ENUM_LISTS: ClassVar[dict[str, type[Enum]]] = {"status": IncidentStatus}

    def merge(self, other: Incident) -> list[str]:
        for attr in (
            "incident_date",
            "published_date",
            "affected_domain",
            "affected_accounts_count",
            "description",
            "title",
        ):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))
        self.data_classes = _union(self.data_classes, other.data_classes)
        self.status = [s for s in IncidentStatus if s in self.status or s in other.status]
        self.source_ids = _union(self.source_ids, other.source_ids)
        return []


def incident_id(name: str) -> str:
    return make_id("incident", fold(name).strip())


@dataclass
class Observation(_Model):
    """Kazda zaakceptowana encja ma co najmniej jedna obserwacje: skad, kiedy, z jaka pewnoscia."""

    id: str
    entity_type: EntityType
    entity_id: str
    source_id: str
    observed_at: str
    evidence_url: str
    confidence: Confidence
    derivation: Derivation = Derivation.DIRECT
    evidence_hash: str | None = None
    notes: str = ""

    _ENUMS: ClassVar[dict[str, type[Enum]]] = {
        "entity_type": EntityType,
        "confidence": Confidence,
        "derivation": Derivation,
    }


def observation_id(
    entity_type: EntityType, entity_id: str, source_id: str, evidence_url: str, observed_at: str, derivation: Derivation
) -> str:
    return make_id(
        "observation", f"{entity_type.value}|{entity_id}|{source_id}|{evidence_url}|{observed_at}|{derivation.value}"
    )
