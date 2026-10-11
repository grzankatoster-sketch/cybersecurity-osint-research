"""Parser DMARC (RFC 7489)."""

from __future__ import annotations

from dataclasses import dataclass, field

POLICIES = ("none", "quarantine", "reject")
POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}


@dataclass
class DmarcRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def p(self) -> str | None:
        return self.tags.get("p")

    @property
    def sp(self) -> str | None:
        return self.tags.get("sp")

    @property
    def pct(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def rua(self) -> list[str]:
        return _uris(self.tags.get("rua"))

    @property
    def ruf(self) -> list[str]:
        return _uris(self.tags.get("ruf"))

    @property
    def adkim(self) -> str:
        return self.tags.get("adkim", "r")

    @property
    def aspf(self) -> str:
        return self.tags.get("aspf", "r")


def _uris(value: str | None) -> list[str]:
    if not value:
        return []
    return [u.strip() for u in value.split(",") if u.strip()]


def is_dmarc(txt: str) -> bool:
    t = txt.strip().lower().replace(" ", "")
    return t.startswith("v=dmarc1")


def parse_dmarc(raw: str) -> DmarcRecord:
    rec = DmarcRecord(raw=raw.strip())
    for part in rec.raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            rec.errors.append(f"nieprawidlowy tag: {part!r}")
            continue
        k, v = part.split("=", 1)
        k, v = k.strip().lower(), v.strip()
        if k in rec.tags:
            rec.errors.append(f"powtorzony tag {k}")
            continue
        rec.tags[k] = v
    if rec.tags.get("v", "").upper() != "DMARC1":
        rec.errors.append("v=DMARC1 musi byc pierwszym tagiem")
    p = rec.tags.get("p")
    if p is None:
        if not rec.rua:
            rec.errors.append("brak wymaganego tagu p")
    elif p.lower() not in POLICIES:
        rec.errors.append(f"nieprawidlowa wartosc p={p}")
    else:
        rec.tags["p"] = p.lower()
    sp = rec.tags.get("sp")
    if sp is not None:
        if sp.lower() not in POLICIES:
            rec.errors.append(f"nieprawidlowa wartosc sp={sp}")
        else:
            rec.tags["sp"] = sp.lower()
    pct = rec.tags.get("pct")
    if pct is not None:
        try:
            if not 0 <= int(pct) <= 100:
                raise ValueError
        except ValueError:
            rec.errors.append(f"nieprawidlowa wartosc pct={pct}")
    return rec
