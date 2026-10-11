"""Transformacje e-maila: domena z adresu, istnienie profilu Gravatar (po skrócie), HIBP (tylko z własnym kluczem)."""
from __future__ import annotations

import hashlib
import importlib
import unicodedata
from urllib.parse import quote

from .. import siblings
from ..http import classify_http
from ..model import Node, Status
from ..normalize import EntityType
from .base import GENERIC_MAIL_PROVIDERS, Context, TransformResult, register

HIBP_ENV = "HIBP_API_KEY"


def gravatar_hashes(email: str) -> dict[str, str]:
    data = email.strip().lower().encode("utf-8")
    return {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data, usedforsecurity=False).hexdigest()}


@register("email_domain", (EntityType.EMAIL,), "Domena z adresu e-mail (czysta, bez sieci)", network=False)
def email_domain(node: Node, ctx: Context) -> TransformResult:
    domain_part = node.key.rsplit("@", 1)[1]
    generic = domain_part in GENERIC_MAIL_PROVIDERS
    dom = Node.make(EntityType.DOMAIN, domain_part, {"generic_mail_provider": True} if generic else {}, "email_domain")
    res = TransformResult(Status.FOUND, nodes=[dom],
                          note="domena publicznego dostawcy poczty: nie jest dalej badana" if generic else "")
    res.edges.append(ctx.edge("email_domain", node, dom, "mailbox_at", 1.0, "adres e-mail zawiera tę domenę"))
    return res


def _label_scripts(label: str) -> set[str]:
    return {unicodedata.name(c, "UNKNOWN").split()[0] for c in label if c.isalpha()}


@register("email_idn", (EntityType.EMAIL,),
          "Domena IDN/punycode w adresie: forma Unicode i mieszane pisma (bez sieci)", network=False)
def email_idn(node: Node, ctx: Context) -> TransformResult:
    labels = node.key.rsplit("@", 1)[1].split(".")
    if not any(lb.startswith("xn--") for lb in labels):
        return TransformResult(Status.NOT_FOUND, note="domena ASCII, nie IDN")
    decoded: list[str] = []
    for lb in labels:
        if lb.startswith("xn--"):
            try:
                lb = lb[4:].encode("ascii").decode("punycode")
            except UnicodeError:
                return TransformResult(Status.UNKNOWN, note="nie udało się zdekodować etykiety punycode")
        decoded.append(lb)
    scripts: set[str] = set()
    mixed_labels: list[str] = []
    for lb in decoded:
        s = _label_scripts(lb)
        scripts |= s
        if len(s) > 1:
            mixed_labels.append(lb)
    domain_unicode = ".".join(decoded)
    attrs = {
        "email_idn": True,
        "email_domain_unicode": domain_unicode,
        "email_idn_scripts": sorted(scripts),
        "email_idn_mixed_labels": mixed_labels,
        "email_idn_mixed_script": bool(mixed_labels),
    }
    note = f"domena IDN: {domain_unicode}"
    if mixed_labels:
        note = f"mieszane pisma w etykiecie {', '.join(mixed_labels)}: możliwy homograf"
    return TransformResult(Status.FOUND, node_attrs=attrs, note=note)


ROLE_LOCALPARTS = frozenset({
    "admin", "administrator", "info", "kontakt", "contact", "abuse", "noreply", "no-reply", "postmaster",
    "hostmaster", "webmaster", "support", "sales", "biuro", "office", "security", "hr",
})

DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com", "temp-mail.org",
    "trashmail.com", "sharklasers.com", "dispostable.com",
})


@register("email_classify", (EntityType.EMAIL,), "E-mail: konto rolowe, domena jednorazowa, alias plus (offline)",
          network=False)
def email_classify(node: Node, ctx: Context) -> TransformResult:
    local, domain = node.key.rsplit("@", 1)
    head = local.split("+", 1)[0]
    base_local = head if head else local
    base_address = f"{base_local}@{domain}"
    attrs = {"role_account": base_local in ROLE_LOCALPARTS, "disposable": domain in DISPOSABLE_DOMAINS,
             "base_address": base_address}
    res = TransformResult(Status.FOUND, node_attrs=attrs)
    if base_address != node.key:
        base = Node.make(EntityType.EMAIL, base_address, {}, "email_classify")
        res.nodes.append(base)
        res.edges.append(ctx.edge("email_classify", node, base, "alias_of", 0.9,
                                  f"plus_addressing: {node.key} to alias adresu {base_address} "
                                  "(nie każdy dostawca obsługuje plus addressing)"))
    return res


@register("email_gravatar",(EntityType.EMAIL,), "Gravatar: czy istnieje awatar dla skrótu adresu (publiczny endpoint)")
def email_gravatar(node: Node, ctx: Context) -> TransformResult:
    hashes = gravatar_hashes(node.key)
    resp = ctx.fetch.get(ctx.endpoints["gravatar"] + hashes["sha256"] + "?d=404&s=1")
    status, reason = classify_http(resp)
    attrs = {"gravatar_sha256": hashes["sha256"], "gravatar_md5": hashes["md5"]}
    if status is Status.NOT_FOUND:
        return TransformResult(Status.NOT_FOUND, node_attrs=attrs, note="Gravatar: brak awatara dla tego adresu")
    if status is not None:
        return TransformResult.failed(status, "Gravatar: " + reason)
    prof = Node.make(EntityType.URL, f"https://gravatar.com/{hashes['sha256']}",
                     {"kind": "gravatar", "site": "Gravatar", "avatar_hash": hashes["sha256"]}, "email_gravatar")
    res = TransformResult(Status.FOUND, nodes=[prof], node_attrs=attrs)
    res.edges.append(ctx.edge("email_gravatar", node, prof, "has_gravatar", 0.95,
                              "Gravatar zwrócił awatar dla skrótu SHA-256 tego adresu (konto Gravatar istnieje)"))
    return res


@register("email_hibp", (EntityType.EMAIL,), "HIBP: wycieki z adresem (tylko z WŁASNYM kluczem w HIBP_API_KEY)")
def email_hibp(node: Node, ctx: Context) -> TransformResult:
    key = str(ctx.env.get(HIBP_ENV, "")).strip()
    if not key:
        return TransformResult.failed(Status.UNKNOWN, f"pominięto: brak klucza w zmiennej {HIBP_ENV} (własny klucz HIBP)")
    try:
        siblings.import_sibling("hibp-monitor", ctx.tools_dir)
        http_mod = importlib.import_module("hibp_monitor.http")
        breaches_mod = importlib.import_module("hibp_monitor.breaches")
    except (siblings.SiblingUnavailable, ImportError) as exc:
        return TransformResult.failed(Status.UNKNOWN, f"hibp-monitor niedostępny: {exc}")
    client = ctx.hibp_client_factory() if ctx.hibp_client_factory else http_mod.HttpClient(
        user_agent="entity-graph (wlasny klucz uzytkownika)")
    url = f"{breaches_mod.BASE}/breachedaccount/{quote(node.key, safe='')}?truncateResponse=false"
    try:
        resp = client.get(url, {"hibp-api-key": key, "Accept": "application/json"})
    except http_mod.HibpError as exc:
        return TransformResult.failed(Status.ERROR, f"HIBP: {exc}")   # komunikaty hibp-monitor nie zawierają klucza
    if resp.status == 404:
        return TransformResult(Status.NOT_FOUND, note="HIBP: adres nie występuje w znanych wyciekach")
    if resp.status in (401, 403):
        return TransformResult.failed(Status.ERROR, f"HIBP: HTTP {resp.status}, klucz odrzucony lub bez uprawnień")
    if resp.status != 200:
        return TransformResult.failed(Status.ERROR, f"HIBP: HTTP {resp.status}")
    try:
        found = breaches_mod.parse_breaches(resp.text)
    except http_mod.HibpError as exc:
        return TransformResult.failed(Status.ERROR, f"HIBP: {exc}")
    res = TransformResult(Status.FOUND, node_attrs={"hibp_breach_count": len(found)}, stats={"breaches": len(found)})
    if len(found) > ctx.settings.max_breaches:
        res.note = f"pokazano {ctx.settings.max_breaches} z {len(found)} wycieków"
    for b in found[: ctx.settings.max_breaches]:
        org = Node.make(EntityType.ORGANIZATION, b.title or b.name,
                        {"kind": "breach", "breach_date": b.breach_date, "data_classes": b.data_classes}, "email_hibp")
        res.nodes.append(org)
        res.edges.append(ctx.edge("email_hibp", node, org, "appears_in_breach", 1.0,
                                  f"HIBP: adres w wycieku {b.name} ({b.breach_date or 'data n/d'}); "
                                  f"dane: {', '.join(b.data_classes[:6]) or 'n/d'}"))
    return res
