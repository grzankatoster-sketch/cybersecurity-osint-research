"""Resolver organizacji i BEZPIECZNE relacje miedzy encjami.

Dozwolone relacje (kazda z `derivation` i proweniencja):
  organizacja -> oficjalna domena          (direct: z rejestru/strony firmy; inferred: dopasowanie po nazwie
                                            albo zrodlo niebedace first-party)
  domena      -> incydent                  (direct: ta sama domena; inferred: incydent na subdomenie)
  organizacja -> publiczna osoba           (Person.organization_id)
Nie istnieje i nie jest tworzona relacja e-mail -> osoba ani osoba -> incydent.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .models import (
    FIRST_PARTY_TYPES,
    Confidence,
    Derivation,
    Domain,
    EntityType,
    Incident,
    Observation,
    Organization,
    Person,
    Source,
)
from .normalize import (
    company_names_match,
    is_same_or_subdomain,
    normalize_company_name,
    normalize_domain,
    normalize_krs,
    normalize_nip,
    normalize_regon,
    split_company_name,
)
from .quality import max_confidence

if TYPE_CHECKING:  # pragma: no cover
    from .store import Store


# --- rozpoznawanie organizacji ---------------------------------------------------


def find_organization(orgs: Iterable[Organization], ref: str) -> Organization | None:
    """Dopasowanie po referencji: KRS > NIP > REGON > znormalizowana nazwa (takze poprzednie nazwy)."""
    orgs = list(orgs)
    ref = str(ref or "").strip()
    if not ref:
        return None
    for attr, norm in (("krs", normalize_krs), ("nip", normalize_nip), ("regon", normalize_regon)):
        value = norm(ref)
        if value:
            for org in orgs:
                if getattr(org, attr) == value:
                    return org
    for org in orgs:
        if company_names_match(org.legal_name, ref):
            return org
    for org in orgs:
        if any(company_names_match(p, ref) for p in org.previous_names):
            return org
    return None


def find_matching_organization(orgs: Iterable[Organization], candidate: Organization) -> Organization | None:
    """Istniejaca organizacja tozsama z kandydatem: ten sam identyfikator (KRS > NIP > REGON) albo ta sama nazwa
    bez sprzecznych identyfikatorow."""
    orgs = list(orgs)
    for attr in ("krs", "nip", "regon"):
        value = getattr(candidate, attr)
        if value:
            for org in orgs:
                if getattr(org, attr) == value:
                    return org
    for org in orgs:
        conflict = any(
            getattr(org, a) and getattr(candidate, a) and getattr(org, a) != getattr(candidate, a)
            for a in ("krs", "nip", "regon")
        )
        if not conflict and company_names_match(org.legal_name, candidate.legal_name):
            return org
    return None


# --- widoki z proweniencja ---------------------------------------------------------


@dataclass
class Link:
    """Powiazana encja wraz z rodzajem relacji i dowodami."""

    entity: Domain | Person | Incident
    derivation: Derivation
    via: str
    confidence: Confidence
    source_ids: list[str]
    observations: list[Observation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity.to_dict(),
            "derivation": self.derivation.value,
            "via": self.via,
            "confidence": self.confidence.value,
            "source_ids": list(self.source_ids),
            "observations": [o.to_dict() for o in self.observations],
        }


@dataclass
class CompanyView:
    organization: Organization
    confidence: Confidence
    observations: list[Observation]
    domains: list[Link] = field(default_factory=list)
    persons: list[Link] = field(default_factory=list)
    incidents: list[Link] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "organization": self.organization.to_dict(),
            "confidence": self.confidence.value,
            "observations": [o.to_dict() for o in self.observations],
            "domains": [x.to_dict() for x in self.domains],
            "persons": [x.to_dict() for x in self.persons],
            "incidents": [x.to_dict() for x in self.incidents],
            "sources": [s.to_dict() for s in self.sources],
        }


def _best_confidence(obs: list[Observation]) -> Confidence:
    return max_confidence(*(o.confidence for o in obs)) if obs else Confidence.LOW


def _link(store: Store, entity, etype: EntityType, derivation: Derivation, via: str) -> Link:
    obs = store.observations_for(etype, entity.id)
    return Link(entity, derivation, via, _best_confidence(obs), list(entity.source_ids), obs)


def _domain_derivation(store: Store, dom: Domain) -> Derivation:
    """direct, gdy istnieje obserwacja direct pochodzaca ze zrodla first-party/official; inaczej inferred."""
    for o in store.observations_for(EntityType.DOMAIN, dom.id):
        src = store.sources.get(o.source_id)
        if o.derivation is Derivation.DIRECT and src and src.source_type in FIRST_PARTY_TYPES:
            return Derivation.DIRECT
    return Derivation.INFERRED


def _person_derivation(store: Store, person: Person) -> Derivation:
    obs = store.observations_for(EntityType.PERSON, person.id)
    return Derivation.DIRECT if any(o.derivation is Derivation.DIRECT for o in obs) else Derivation.INFERRED


def _domain_matches_name(domain: str, org: Organization) -> bool:
    """Heurystyka: glowna etykieta domeny rowna rdzeniowi nazwy firmy (bez spacji), np. example.test ~ Example."""
    label = domain.split(".")[-2] if domain.count(".") >= 1 else domain
    for name in [org.legal_name, *org.previous_names]:
        core, _forms = split_company_name(name)
        compact = core.replace(" ", "")
        if compact and compact == label.replace("-", ""):
            return True
    return False


def incidents_for_domain(store: Store, domain: str) -> list[Link]:
    """Incydenty na tej domenie (direct) i jej subdomenach (inferred)."""
    d = normalize_domain(domain)
    out: list[Link] = []
    for inc in sorted(store.incidents.values(), key=lambda i: (i.incident_date or "", i.name)):
        if not inc.affected_domain or not is_same_or_subdomain(inc.affected_domain, d):
            continue
        if inc.affected_domain == d:
            out.append(_link(store, inc, EntityType.INCIDENT, Derivation.DIRECT, f"affected_domain == {d}"))
        else:
            out.append(
                _link(
                    store,
                    inc,
                    EntityType.INCIDENT,
                    Derivation.INFERRED,
                    f"incydent na subdomenie {inc.affected_domain} domeny {d}",
                )
            )
    return out


def company_view(store: Store, org: Organization) -> CompanyView:
    view = CompanyView(
        organization=org,
        confidence=_best_confidence(store.observations_for(EntityType.ORGANIZATION, org.id)),
        observations=store.observations_for(EntityType.ORGANIZATION, org.id),
    )
    used_sources: set[str] = set(org.source_ids)

    # organizacja -> domeny
    seen_domains: set[str] = set()
    for dom in sorted(store.domains.values(), key=lambda x: x.domain):
        if dom.organization_id == org.id:
            der = _domain_derivation(store, dom)
            via = "Domain.organization_id" + ("" if der is Derivation.DIRECT else " (źródło niebędące first-party)")
            view.domains.append(_link(store, dom, EntityType.DOMAIN, der, via))
        elif not dom.organization_id and _domain_matches_name(dom.domain, org):
            view.domains.append(
                _link(store, dom, EntityType.DOMAIN, Derivation.INFERRED, "dopasowanie nazwy firmy do domeny")
            )
        else:
            continue
        seen_domains.add(dom.domain)

    # domena -> incydenty (relacja pochodna: inferred, gdy domena albo dopasowanie jest inferred)
    seen_incidents: dict[str, Link] = {}
    for dlink in view.domains:
        for ilink in incidents_for_domain(store, dlink.entity.domain):  # type: ignore[union-attr]
            if dlink.derivation is Derivation.INFERRED:
                ilink.derivation = Derivation.INFERRED
                ilink.via += f"; domena {dlink.entity.domain} powiązana z firmą jako inferred"  # type: ignore[union-attr]
            prev = seen_incidents.get(ilink.entity.id)
            if prev is None or (prev.derivation is Derivation.INFERRED and ilink.derivation is Derivation.DIRECT):
                seen_incidents[ilink.entity.id] = ilink
    view.incidents = list(seen_incidents.values())

    # organizacja -> publiczne osoby
    for person in sorted(store.persons.values(), key=lambda p: p.name):
        if person.organization_id == org.id:
            view.persons.append(
                _link(store, person, EntityType.PERSON, _person_derivation(store, person), "Person.organization_id")
            )

    for link in (*view.domains, *view.persons, *view.incidents):
        used_sources.update(link.source_ids)
    view.sources = [store.sources[s] for s in sorted(used_sources) if s in store.sources]
    return view


def search_company(store: Store, query: str) -> list[CompanyView]:
    """Dopasowanie po KRS/NIP/REGON albo po tokenach nazwy (po fold, takze poprzednie nazwy)."""
    query = str(query or "").strip()
    if not query:
        raise ValueError("Puste zapytanie.")
    ids = {normalize_krs(query), normalize_nip(query), normalize_regon(query)} - {None}
    q_tokens = set(normalize_company_name(query).split())
    matched: list[Organization] = []
    for org in store.organizations.values():
        hit = bool(ids & {org.krs, org.nip, org.regon})
        if not hit and q_tokens:
            for name in [org.legal_name, *org.previous_names]:
                if q_tokens <= set(normalize_company_name(name).split()):
                    hit = True
                    break
        if hit:
            matched.append(org)
    matched.sort(key=lambda o: (normalize_company_name(o.legal_name), o.id))
    return [company_view(store, o) for o in matched]
