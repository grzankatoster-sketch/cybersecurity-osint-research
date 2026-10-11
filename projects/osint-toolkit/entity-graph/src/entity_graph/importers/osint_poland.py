"""Import danych spółki z osint-poland: (1) snapshot "teczka-spolki/v1" (raport JSON), (2) surowa odpowiedź Wykazu VAT
(`result.subject`, z rachunkami bankowymi), (3) surowy odpis KRS (`odpis`), (4) odpowiedź ULDK (tekst) -> działka.

Węzeł: Organization z KRS/NIP/REGON, adresem, rachunkami (IBAN) i identyfikatorami działek. Dane osób NIE są importowane:
KRS jest w źródle zanonimizowany, a lista przedstawicieli/prokurentów/wspólników z Wykazu VAT jest celowo pomijana.
ULDK daje geometrię i położenie działki, nie właściciela: działka nie jest łączona z żadną osobą."""
from __future__ import annotations

import math
from collections.abc import Iterable

from ..identifiers import normalize_iban, normalize_krs, normalize_nip, normalize_regon
from ..model import Node, Status
from ..normalize import EntityType, normalize_domain
from .base import ImportCtx, Imported, failed

TOOL = "osint-poland"
MAX_ACCOUNTS = 500
MAX_PARCELS = 200
PARCEL_PREDICATES = ("kw.dzial1.dzialka", "uldk.teryt")
ULDK_FIELDS = ("teryt", "voivodeship", "county", "commune", "region", "parcel", "geom_extent")
CHECK_STATUS = {"FOUND": Status.FOUND, "NOT_FOUND": Status.NOT_FOUND, "ERROR": Status.ERROR}
PERSONS_NOTE = "dane osób (KRS zanonimizowany w źródle; przedstawiciele z Wykazu VAT) nie są importowane"


def kind_of(data) -> str | None:
    if not isinstance(data, dict):
        return None
    if str(data.get("schema", "")).startswith("teczka-spolki/") and isinstance(data.get("facts"), list):
        return "snapshot"
    result = data.get("result")
    if isinstance(result, dict) and "subject" in result:
        return "vat"
    if isinstance(data.get("odpis"), dict):
        return "krs"
    return None


# ------------------------------------------------------------------ wspólny budowniczy organizacji

def _org(ctx: ImportCtx, name: str, nip, regon, krs, address: str, extra: dict) -> Node:
    ids = {"nip": normalize_nip(nip), "regon": normalize_regon(regon), "krs": normalize_krs(krs)}
    attrs = {"kind": "company", **{k: v for k, v in ids.items() if v}, **extra}
    if address.strip():
        attrs["address"] = address.strip()[:200]
    if not name.strip():
        if not any(ids.values()):
            raise ValueError("brak nazwy i identyfikatorów (NIP, REGON, KRS)")
        name = "podmiot " + next(f"{k.upper()} {v}" for k, v in ids.items() if v)
    return ctx.node(EntityType.ORGANIZATION, name, attrs)


def _ibans(values: Iterable) -> tuple[list[str], int]:
    good, bad = [], 0
    for v in values:
        iban = normalize_iban(v)
        if iban is None:
            bad += 1
        elif iban not in good:
            good.append(iban)
    return good[:MAX_ACCOUNTS], bad


def _address(adr: dict) -> str:
    street = " ".join(str(x) for x in (adr.get("ulica"), adr.get("nrDomu")) if x)
    if adr.get("nrLokalu"):
        street += f"/{adr['nrLokalu']}"
    town = f"{adr.get('kodPocztowy', '')} {adr.get('miejscowosc', '')}".strip()
    return ", ".join(p for p in (street, town) if p)


# ------------------------------------------------------------------ snapshot teczki

def parse_snapshot(data: dict, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    facts: dict[str, list] = {}
    for f in data["facts"]:
        if isinstance(f, dict) and f.get("predicate") and f.get("value") not in (None, ""):
            facts.setdefault(str(f["predicate"]), []).append(str(f["value"]))

    def first(*preds: str) -> str:
        return next((facts[p][0] for p in preds if facts.get(p)), "")

    query = data.get("query") if isinstance(data.get("query"), dict) else {}
    qtype, qvalue = str(query.get("type", "")).lower(), query.get("value")
    name = first("krs.nazwa", "vat.nazwa", "krs_hist.nazwa")
    nip = first("krs.nip", "krs_hist.nip") or (qvalue if qtype == "nip" else "")
    regon = first("krs.regon", "vat.regon", "krs_hist.regon")
    krs = first("vat.krs") or (qvalue if qtype == "krs" else "")
    extra: dict = {"register_sources": sorted({p.split(".")[0] for p in facts if p.split(".")[0] in ("krs", "vat", "krs_hist")})}
    if first("krs.forma_prawna", "krs_hist.forma_prawna"):
        extra["legal_form"] = first("krs.forma_prawna", "krs_hist.forma_prawna")[:80]
    if first("vat.status"):
        extra["vat_status"] = first("vat.status")[:40]
    ls = data.get("legal_status")
    if isinstance(ls, dict) and ls.get("label"):
        extra["legal_status"] = str(ls["label"])[:120]
    accounts, bad = _ibans(v for p, vs in facts.items() if "rachun" in p or "account" in p for v in vs)
    if accounts:
        extra["bank_accounts"] = accounts
    try:
        org = _org(ctx, name, nip, regon, krs, first("krs.adres", "vat.adres"), extra)
    except ValueError as exc:
        return failed(TOOL, f"snapshot teczki: {exc}")
    imp.nodes.append(org)
    for pid in dict.fromkeys(v.strip() for p in PARCEL_PREDICATES for v in facts.get(p, [])):
        try:
            parcel = ctx.node(EntityType.PARCEL, pid, {"kind": "parcel"})
        except ValueError:
            continue
        imp.nodes.append(parcel)
        imp.edges.append(ctx.edge("", org, parcel, "related_parcel", 0.5,
                                  "identyfikator działki w tym samym pliku teczki (KW/ULDK); to położenie, "
                                  "nie dowód własności"))
        if len([n for n in imp.nodes if n.type is EntityType.PARCEL]) >= MAX_PARCELS:
            break
    for c in data.get("checks") or []:
        if not isinstance(c, dict):
            continue
        status = CHECK_STATUS.get(str(c.get("status")), Status.UNKNOWN)   # NOT_EXECUTED/CANCELLED to nie "brak danych"
        imp.runs.append((f"{org.id}#{c.get('check')}", status, str(c.get("reason") or "")[:200]))
    if not imp.runs:
        imp.runs.append((org.id, Status.FOUND, ""))
    outcome = data.get("outcome") if isinstance(data.get("outcome"), dict) else {}
    imp.note = "; ".join(x for x in (PERSONS_NOTE, f"stan raportu: {outcome.get('state')}" if outcome.get("state") else "",
                                     f"{bad} nieczytelnych rachunków pominięto" if bad else "") if x)
    return imp


# ------------------------------------------------------------------ Wykaz VAT (surowy)

def parse_vat(data: dict, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    subject = data["result"].get("subject")
    if subject is None:
        imp.runs.append(("wykaz-vat", Status.NOT_FOUND, "NIP nieobecny w Wykazie VAT na wskazany dzień (to nie jest dowód nieistnienia)"))
        return imp
    if not isinstance(subject, dict):
        return failed(TOOL, "Wykaz VAT: subject nie jest obiektem")
    extra: dict = {"register_sources": ["vat"]}
    if isinstance(subject.get("statusVat"), str):
        extra["vat_status"] = subject["statusVat"][:40]
    accounts, bad = _ibans(a for a in subject.get("accountNumbers") or [] if isinstance(a, (str, int)))
    if accounts:
        extra["bank_accounts"] = accounts
    if subject.get("hasVirtualAccounts") is True:
        extra["vat_has_virtual_accounts"] = True
    addr = subject.get("workingAddress") or subject.get("residenceAddress") or ""
    try:
        org = _org(ctx, str(subject.get("name") or ""), subject.get("nip"), subject.get("regon"), subject.get("krs"),
                   str(addr), extra)
    except ValueError as exc:
        return failed(TOOL, f"Wykaz VAT: {exc}")
    imp.nodes.append(org)
    imp.runs.append((org.id, Status.FOUND, ""))
    imp.note = "; ".join(x for x in (PERSONS_NOTE, f"{bad} nieczytelnych rachunków pominięto" if bad else "") if x)
    return imp


# ------------------------------------------------------------------ odpis KRS (surowy)

def parse_krs(data: dict, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    try:
        odpis = data["odpis"]
        head, d1 = odpis["naglowekA"], odpis["dane"]["dzial1"]
        subj, ids = d1["danePodmiotu"], d1["danePodmiotu"]["identyfikatory"]
        name = subj["nazwa"]
        if not (isinstance(head, dict) and isinstance(subj, dict) and isinstance(ids, dict) and isinstance(name, str)):
            raise TypeError("zły kształt")
    except (KeyError, TypeError):
        return failed(TOOL, "odpis KRS: nieoczekiwany kształt danych (brak dzial1.danePodmiotu)")
    seat = d1.get("siedzibaIAdres") if isinstance(d1.get("siedzibaIAdres"), dict) else {}
    adr = seat.get("adres") if isinstance(seat.get("adres"), dict) else {}
    extra: dict = {"register_sources": ["krs"]}
    if isinstance(subj.get("formaPrawna"), str):
        extra["legal_form"] = subj["formaPrawna"][:80]
    if head.get("stanZDnia"):
        extra["krs_as_of"] = str(head["stanZDnia"])[:20]
    try:
        org = _org(ctx, name, ids.get("nip"), ids.get("regon"), head.get("numerKRS"), _address(adr), extra)
    except ValueError as exc:
        return failed(TOOL, f"odpis KRS: {exc}")
    imp.nodes.append(org)
    site = seat.get("adresStronyInternetowej")
    if isinstance(site, str) and site.strip():
        try:
            host = normalize_domain(site.strip().lower().removeprefix("www."))
        except ValueError:
            host = None
        if host:
            dom = ctx.node(EntityType.DOMAIN, host, {"kind": "company_website"})
            imp.nodes.append(dom)
            imp.edges.append(ctx.edge("", org, dom, "has_website", 0.9,
                                      f"adres strony internetowej podmiotu wpisany w KRS ({site.strip()[:80]})"))
    mail = seat.get("adresPocztyElektronicznej")
    if isinstance(mail, str) and mail.strip():
        try:
            email = ctx.node(EntityType.EMAIL, mail.strip())
        except ValueError:
            email = None
        if email:
            imp.nodes.append(email)
            imp.edges.append(ctx.edge("", org, email, "has_email", 0.9, "adres e-mail podmiotu wpisany w KRS"))
    imp.runs.append((org.id, Status.FOUND, ""))
    imp.note = PERSONS_NOTE
    return imp


# ------------------------------------------------------------------ ULDK (tekst)

def detect_uldk(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    head = lines[0].strip()
    if head.startswith("-1") and "brak wyników" in head:
        return True
    return head == "0" and len(lines) >= 2 and len(lines[1].split("|")) == len(ULDK_FIELDS)


def parse_uldk(text: str, ctx: ImportCtx) -> Imported:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    imp = Imported(TOOL)
    if lines[0].strip().startswith("-1"):
        imp.runs.append(("uldk", Status.NOT_FOUND, "ULDK: brak działki w zbiorczej bazie (nie dowodzi nieistnienia działki)"))
        return imp
    for line in lines[1:MAX_PARCELS + 1]:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != len(ULDK_FIELDS):
            imp.runs.append((line[:40], Status.ERROR, "ULDK: zła liczba pól w wierszu"))
            continue
        v = dict(zip(ULDK_FIELDS, parts, strict=True))
        attrs = {"kind": "parcel", "voivodeship": v["voivodeship"], "county": v["county"], "commune": v["commune"],
                 "region": v["region"], "parcel_number": v["parcel"],
                 "note": "ULDK podaje położenie i geometrię działki, nie właściciela"}
        coords = v["geom_extent"].split(",")
        try:
            nums = [float(c) for c in coords]
            if len(nums) == 4 and all(math.isfinite(x) for x in nums):
                attrs["extent_wgs84"] = nums
        except ValueError:
            pass
        try:
            node = ctx.node(EntityType.PARCEL, v["teryt"], {k: x for k, x in attrs.items() if x})
        except ValueError as exc:
            imp.runs.append((v["teryt"][:40], Status.ERROR, str(exc)))
            continue
        imp.nodes.append(node)
        imp.runs.append((node.id, Status.FOUND, ""))
    return imp if imp.runs else failed(TOOL, "ULDK: brak wierszy z danymi")


def parse(data, ctx: ImportCtx) -> Imported:
    kind = kind_of(data)
    if kind == "snapshot":
        return parse_snapshot(data, ctx)
    if kind == "vat":
        return parse_vat(data, ctx)
    if kind == "krs":
        return parse_krs(data, ctx)
    return failed(TOOL, "nierozpoznany układ pliku osint-poland")

