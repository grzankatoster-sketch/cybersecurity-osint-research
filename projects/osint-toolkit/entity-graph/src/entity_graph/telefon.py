"""Kontekst numeru telefonu w sprawie: wynik phone-check (plan numeracyjny) i opcjonalna ręczna weryfikacja
aktualnego operatora, zapisane jako obserwacje węzła Phone ze źródłem i czasem.

Zakres jest wąski z założenia: E.164, poprawność i możliwość w planie numeracji, kraj i region planu numeracyjnego,
typ linii, pierwotny przydział operatora z ostrzeżeniem o przenoszeniu numerów, strefy czasowe planu. Region planu
numeracyjnego to obszar przydziału puli numerów, nie miejsce urządzenia ani osoby; numer nie jest wiązany z osobą.

  * import tego samego wyniku drugi raz nic nie zmienia (rozpoznanie po skrócie SHA-256 metadanych)
  * różne wartości z dwóch źródeł zostają jako konflikt obserwacji (pole nieznane), bez wybierania zwycięzcy
  * operator z ręcznej weryfikacji to osobne pole (phone_carrier_manual) z referencją źródła i datą; nie nadpisuje
    operatora z planu numeracji, a przeniesienie numeru nie jest rozstrzygane
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date

from .model import Graph, Node, utc_now
from .normalize import EntityType
from .transforms.phone import phone_attrs

LOG = "phone_context_log"
PLAN_SOURCE = "phone-check"
MANUAL_SOURCE = "reczna-weryfikacja"
MAX_CARRIER = 80

LABELS = (
    ("phone_e164", "numer E.164"),
    ("phone_valid", "poprawny w planie numeracji"),
    ("phone_possible", "możliwy (długość) w planie numeracji"),
    ("phone_region", "kraj planu numeracyjnego (ISO)"),
    ("phone_country_name", "kraj planu numeracyjnego"),
    ("phone_plan_region", "region planu numeracyjnego"),
    ("phone_plan_region_note", "uwaga do regionu planu numeracyjnego"),
    ("phone_line_type", "typ linii"),
    ("phone_carrier", "operator: pierwotny przydział z planu numeracji"),
    ("phone_carrier_note", "ostrzeżenie o przenoszeniu numerów"),
    ("phone_carrier_manual", "operator podany po ręcznej weryfikacji"),
    ("phone_timezones", "strefy czasowe planu numeracyjnego"),
)


def _digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _logged(node: Node | None, digest: str) -> bool:
    return node is not None and any(isinstance(x, dict) and x.get("sha256") == digest
                                    for x in node.attrs.get(LOG) or [])


def attach_plan(graph: Graph, row: dict, now: str | None = None, region: str = "PL") -> tuple[Node, bool]:
    """Wynik phone-check -> węzeł Phone (jeden na numer E.164) z obserwacją źródła. -> (węzeł, czy zmieniono)."""
    if not isinstance(row, dict) or not row.get("parsed"):
        raise ValueError(f"phone-check nie sparsował numeru: {(row or {}).get('error') if isinstance(row, dict) else '?'}")
    attrs = phone_attrs(row)
    digest = _digest(attrs)
    node_id = Node.make(EntityType.PHONE, str(row.get("e164") or row.get("input")), region=region).id
    existing = graph.nodes.get(node_id)
    if _logged(existing, digest):
        return existing, False
    now = now or utc_now()
    source = f"{PLAN_SOURCE}#{digest[:8]}"
    entry = {"kind": "plan", "source": source, "tool": PLAN_SOURCE, "observed_at": now, "sha256": digest}
    node = Node.make(EntityType.PHONE, str(row.get("e164") or row.get("input")), {**attrs, LOG: [entry]}, source,
                     region)
    return graph.add_node(node, now), True


def check_day(raw: str | None) -> str:
    text = str(raw or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        raise ValueError("data weryfikacji: RRRR-MM-DD")
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise ValueError("data weryfikacji: nieprawidłowa data") from None
    if day > date.today():
        raise ValueError("data weryfikacji nie może być z przyszłości")
    return text


def attach_manual_carrier(graph: Graph, number: str, carrier: str, reference: dict, verified_on: str,
                          now: str | None = None, region: str = "PL") -> tuple[Node, bool]:
    """Operator wskazany przez oficjalną weryfikację wykonaną RĘCZNIE przez człowieka (np. baza UKE), jako osobna
    obserwacja z referencją i datą. Numer musi już być w sprawie (najpierw wynik phone-check)."""
    node_id = Node.make(EntityType.PHONE, number, region=region).id
    node = graph.nodes.get(node_id)
    if node is None:
        raise ValueError("numeru nie ma w sprawie: najpierw dołącz wynik phone-check")
    carrier = " ".join(str(carrier or "").split())
    if not 2 <= len(carrier) <= MAX_CARRIER or re.search(r"[\x00-\x1f\x7f]", carrier):
        raise ValueError(f"operator z ręcznej weryfikacji: 2-{MAX_CARRIER} znaków")
    if not isinstance(reference, dict) or not reference.get("ref"):
        raise ValueError("ręczna weryfikacja wymaga referencji źródła")
    verified_on = check_day(verified_on)
    digest = _digest({"carrier": carrier.casefold(), "ref": reference, "day": verified_on})
    if _logged(node, digest):
        return node, False
    now = now or utc_now()
    source = f"{MANUAL_SOURCE}#{digest[:8]}"
    entry = {"kind": "manual", "source": source, "observed_at": now, "verified_on": verified_on,
             "reference": reference, "sha256": digest}
    graph.add_node(Node(EntityType.PHONE, node.key, node.value, {"phone_carrier_manual": carrier, LOG: [entry]},
                        [source]), now)
    return graph.nodes[node_id], True


def context(node: Node) -> dict:
    """Kontekst numeru do pokazania: pola z etykietami, obserwacje ze źródłami, konflikty, dziennik obserwacji."""
    a = node.attrs
    fields = []
    for key, label in LABELS:
        value = a.get(key)
        if key == "phone_plan_region" and value in (None, "") and a.get("phone_geo_description"):
            value = a.get("phone_country_name") if a.get("phone_line_type") == "komórkowy" else a["phone_geo_description"]
        if value not in (None, "", []):
            fields.append({"key": key, "label": label, "value": ", ".join(value) if isinstance(value, list) else value})
    observed = node.observed()
    obs = {k: v for k, v in observed.items() if k.startswith("phone_")}
    return {"value": node.value, "fields": fields, "observations": obs,
            "conflicts": [c for c in node.conflicts() if c.startswith("phone_")],
            "log": [x for x in a.get(LOG) or [] if isinstance(x, dict)],
            "manual_check_url": a.get("phone_carrier_check_url") or "",
            "linked_person": "brak: narzędzie nie wiąże numeru z osobą"}
