"""Spójność oceny między komponentami: username-engine (link_accounts) i entity-graph (evidence) dają ten sam POZIOM
dowodów dla tych samych scenariuszy (syntetycznych). Pomijany, gdy obok nie ma kodu username-engine."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from entity_graph.evidence import Record, bio_fingerprint, compare, level_of, weight
from entity_graph.normalize import avatar_hash_from_url, normalize_url

UE_SRC = Path(__file__).resolve().parents[2] / "username-engine" / "src"
if not (UE_SRC / "username_engine" / "correlate.py").exists():
    pytest.skip("brak username-engine obok entity-graph", allow_module_level=True)
sys.path.insert(0, str(UE_SRC))
from username_engine.correlate import COPYABLE_CAP as UE_CAP, Account, link_accounts  # noqa: E402

from entity_graph.evidence import COPYABLE_CAP  # noqa: E402

A_URL, B_URL = "https://alpha.example/u/ziarno7", "https://beta.example/u/ziarno_7"
BIO = "Tworze otwarte narzedzia mapowe oraz projekty edukacyjne"
BASIC = {"name": "Ala Testowa", "location": "Gdansk"}
STRONG_A = {**BASIC, "website": "https://ziarno.example", "links": [B_URL]}
STRONG_B = {**BASIC, "website": "https://ziarno.example", "links": [A_URL]}
COPY = {**BASIC, "website": "https://pracodawca.example", "bio": BIO, "avatar": "https://cdn.example/images/photo123.jpg"}

CASES = [
    ("nick_only", {}, {}, "brak"),
    ("name_and_city", BASIC, BASIC, "słabe"),
    ("reciprocal_links_and_own_website", STRONG_A, STRONG_B, "mocne"),
    ("copied_profile_without_crosslinks", COPY, COPY, "umiarkowane"),
    ("same_employer_website_only", {"website": "https://pracodawca.example"},
     {"website": "https://pracodawca.example"}, "umiarkowane"),
]


def record(url: str, site: str, p: dict) -> Record:
    return Record(url=normalize_url(url)[0], site=site, display_name=p.get("name", ""),
                  avatar_hash=avatar_hash_from_url(p["avatar"]) if p.get("avatar") else "",
                  website=p.get("website", ""), links=tuple(p.get("links", [])),
                  bio_fingerprint=tuple(bio_fingerprint(p.get("bio", ""))), reliability=0.95)


@pytest.mark.parametrize("label, left, right, expected", CASES, ids=[c[0] for c in CASES])
def test_same_level_in_both_components(label, left, right, expected):
    ue = link_accounts(Account("ziarno7", "Alpha", A_URL, left), Account("ziarno_7", "Beta", B_URL, right))
    signals, contradictions = compare(record(A_URL, "Alpha", left), record(B_URL, "Beta", right))
    assert ue.level == level_of(signals).label == expected
    if expected != "mocne":
        assert ue.score <= COPYABLE_CAP and weight(signals, contradictions) <= COPYABLE_CAP


def test_shared_constants():
    assert UE_CAP == COPYABLE_CAP
