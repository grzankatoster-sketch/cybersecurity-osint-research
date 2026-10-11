"""Transformacja telefonu: WYŁĄCZNIE metadane z planu numeracji (phone-check, offline).

Celowo nie istnieje żadna transformacja numer -> osoba (CallApp, Truecaller, Sync.me, wyszukiwarki książek
kontaktowych): brak oficjalnego API, dane z książek adresowych użytkowników, ToS i RODO. Patrz README.

Region planu numeracyjnego to obszar, któremu przydzielono pulę numerów, a nie miejsce urządzenia ani osoby. Dla
numeru komórkowego zapisujemy wyłącznie kraj planu (bez opisu miasta czy województwa, nawet jeśli biblioteka go zna)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .. import siblings
from ..model import Node, Status
from ..normalize import EntityType
from .base import Context, TransformResult, register

KEEP = ("valid", "possible", "country_name", "region", "line_type", "carrier", "e164", "timezones")
MOBILE_CODES = ("MOBILE",)
MOBILE_LABELS = ("komórkowy",)
CARRIER_NOTE = "pierwotny przydział z planu numeracji; numer mógł zostać przeniesiony"
PLAN_REGION_NOTE_MOBILE = ("numer komórkowy: region planu numeracyjnego to kraj; numer nie wskazuje miasta "
                           "ani pozycji użytkownika")
PLAN_REGION_NOTE_FIXED = ("obszar numeru kierunkowego z planu numeracyjnego; to nie jest bieżące miejsce "
                          "urządzenia ani osoby")


def parse_phone_check(payload) -> dict | None:
    rows = payload if isinstance(payload, list) else [payload]
    row = rows[0] if rows and isinstance(rows[0], dict) else None
    return row if row and "parsed" in row else None


def is_mobile(row: dict) -> bool:
    return row.get("line_type_code") in MOBILE_CODES or str(row.get("line_type") or "").strip() in MOBILE_LABELS


def plan_region(row: dict) -> tuple[str, str]:
    """(region planu numeracyjnego, uwaga). Komórkowy: tylko kraj planu; inne: opis obszaru kierunkowego."""
    country = str(row.get("country_name") or "").strip()
    if is_mobile(row):
        return country, PLAN_REGION_NOTE_MOBILE if country else ""
    desc = str(row.get("geo_description") or "").strip()
    return desc, PLAN_REGION_NOTE_FIXED if desc and desc != country else ""


def phone_attrs(row: dict) -> dict:
    """Atrybuty węzła Phone z wiersza phone-check: wyłącznie metadane planu numeracji (używane też przez importer)."""
    attrs = {f"phone_{k}": row[k] for k in KEEP if row.get(k) not in (None, "", [])}
    region, note = plan_region(row)
    if region:
        attrs["phone_plan_region"] = region
    if note:
        attrs["phone_plan_region_note"] = note
    if row.get("carrier"):
        attrs["phone_carrier_note"] = CARRIER_NOTE
    url = str(row.get("carrier_check_url") or "")
    if url.startswith("https://"):
        attrs["phone_carrier_check_url"] = url    # link do RĘCZNEJ weryfikacji; nic go nie otwiera automatycznie
    return attrs


def run_phone_check(raw: str, region: str, ctx: Context) -> tuple[dict | None, Status, str]:
    """Podproces phone-check (offline) -> (wiersz wyniku, status, komunikat). Wiersz None przy błędzie."""
    with tempfile.TemporaryDirectory(prefix="eg-pc-", dir=ctx.tmp_dir) as tmp:
        out_path = Path(tmp) / "phone.json"
        args = ["--json", str(out_path), "--region", region, "--", raw]
        try:
            out = siblings.run_sibling("phone-check", args, ctx.tools_dir, ctx.settings.sibling_timeout, ctx.runner)
        except siblings.SiblingUnavailable as exc:
            return None, Status.UNKNOWN, f"phone-check niedostępny: {exc}"
        except TimeoutError as exc:
            return None, Status.ERROR, f"phone-check: {exc}"
        # kod 1 = numer niepoprawny w planie numeracji (JSON i tak powstaje); 2 = błąd użycia
        if out.returncode not in (0, 1) or not out_path.exists():
            return None, Status.ERROR, f"phone-check: kod {out.returncode}, {out.stderr.strip()[:200]}"
        try:
            row = parse_phone_check(json.loads(out_path.read_text(encoding="utf-8")))
        except (ValueError, TypeError):
            row = None
    if row is None:
        return None, Status.ERROR, "phone-check: nieprawidłowy plik wyniku"
    if not row.get("parsed"):
        return None, Status.ERROR, f"phone-check nie sparsował numeru: {row.get('error')}"
    if not row.get("valid"):
        return row, Status.NOT_FOUND, f"numer niepoprawny w planie numeracji: {row.get('error')}"
    return row, Status.FOUND, ""


@register("phone_metadata", (EntityType.PHONE,), "phone-check (siostrzane, offline): kraj, typ linii, plan numeracji", network=False)
def phone_metadata(node: Node, ctx: Context) -> TransformResult:
    row, status, msg = run_phone_check(node.value, ctx.settings.phone_region, ctx)
    if row is None:
        return TransformResult.failed(status, msg)
    res = TransformResult(status, node_attrs=phone_attrs(row), note=msg)
    e164 = row.get("e164")
    if e164 and e164 != node.value:
        res.canonical = Node.make(EntityType.PHONE, e164, {}, "phone_metadata")
    return res
