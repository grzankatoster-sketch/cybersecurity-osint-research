"""Eksport CSV dla Maltego (`export.to_maltego_csv`, `sprawa.save_case`, `eg export --maltego`).

Tylko dane syntetyczne, zero ruchu sieciowego (gniazda zablokowane w całym module)."""

from __future__ import annotations

import csv
import io
import json
import os
import socket
from pathlib import Path

import pytest

from entity_graph import cli, sprawa
from entity_graph.export import MALTEGO_EMAIL_MASK, MALTEGO_HEADER, MALTEGO_SECRET_MARK, to_maltego_csv
from entity_graph.guardrails import AuditLog
from entity_graph.importers import import_files
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

FX = Path(__file__).parent / "fixtures" / "org_intel"
NOW = "2026-10-05T12:00:00+00:00"
PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/57"
NCOLS = len(MALTEGO_HEADER)
HASH = "ab" * 32
HEADER_LINE = ",".join(MALTEGO_HEADER) + "\r\n"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise AssertionError("test próbował użyć sieci")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


# ------------------------------------------------------------------ pomocnicze


def rows_of(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline="")))


def raw_node(etype: T, value: str, source: str = "seed") -> Node:
    return Node(etype, value.casefold(), value, {}, [source])


def pair_graph(
    a_value: str = "Jan Kowalski",
    b_value: str = "jkowalski",
    evidence: str = "profil publiczny",
    source: str = "profile-check",
    relation: str = "candidate_username",
    confidence: float = 0.4,
) -> Graph:
    g = Graph({"purpose": PURPOSE})
    a = g.add_node(raw_node(T.PERSON, a_value))  # bez normalizacji: wartości celowo "brudne"
    b = g.add_node(raw_node(T.USERNAME, b_value, source))
    g.add_edge(Edge(a.id, b.id, relation, source, confidence, evidence, "2026-10-05T10:00:00+00:00"))
    return g


def make_case(tmp_path: Path, graph: Graph, name: str = "sprawa") -> Path:
    case = tmp_path / name
    case.mkdir()
    graph.save(case / "graph.json")
    AuditLog(case / "audit.jsonl", "ala").start(PURPOSE, [], {})
    return case


def graph_file(tmp_path: Path, graph: Graph, name: str = "graph.json") -> Path:
    folder = tmp_path / "wej"
    folder.mkdir(exist_ok=True)
    graph.save(folder / name)
    return folder / name


def export_cli(graph_path: Path, out: Path | str, *extra: str) -> int:
    return cli.main(["export", str(graph_path), "--maltego", str(out), *extra])


# ------------------------------------------------------------------ format podstawowy


def test_export_has_header_and_row_for_each_relation():
    g = pair_graph()
    text = to_maltego_csv(g)
    rows = rows_of(text)
    assert tuple(rows[0]) == MALTEGO_HEADER
    assert len(rows) == 2 and all(len(r) == NCOLS for r in rows)
    row = dict(zip(MALTEGO_HEADER, rows[1], strict=True))
    assert row["source_type"] == "maltego.Person" and row["source_value"] == "Jan Kowalski"
    assert row["target_type"] == "maltego.Alias" and row["target_value"] == "jkowalski"
    assert row["relation"] == "candidate_username" and row["confidence"] == "0.400"
    assert row["evidence"] == "profil publiczny" and row["source"] == "profile-check"
    assert row["timestamp_utc"] == "2026-10-05T10:00:00+00:00"
    assert row["source_id"] == g.nodes[next(iter(g.nodes))].id and row["target_id"] == "username:jkowalski"
    assert row["derivation"] == "" and row["evidence_hash"] == "" and row["evidence_ref"] == ""


def test_header_keeps_original_columns_first():
    assert MALTEGO_HEADER[:9] == (
        "source_type",
        "source_value",
        "relation",
        "target_type",
        "target_value",
        "confidence",
        "evidence",
        "source",
        "timestamp_utc",
    )
    assert MALTEGO_HEADER[9:] == ("source_id", "target_id", "derivation", "evidence_hash", "evidence_ref")


def test_empty_graph_exports_only_header_bytes():
    out = to_maltego_csv(Graph({"purpose": PURPOSE}))
    assert out == HEADER_LINE
    assert out.encode("utf-8") == HEADER_LINE.encode("utf-8")


def test_graph_with_relations_and_isolated_node():
    g = pair_graph()
    c = g.add_node(Node.make(T.DOMAIN, "example.test", source="seed"))
    p2 = g.add_node(Node.make(T.PERSON, "Anna Nowak", source="seed"))
    g.add_edge(Edge(p2.id, c.id, "owns_domain", "seed", 0.8, "dowód", "2026-10-05T10:00:00+00:00"))
    lone = g.add_node(Node.make(T.USERNAME, "samotny", source="seed"))
    rows = rows_of(to_maltego_csv(g))
    assert len(rows) == 1 + 2 + 1
    assert rows[2][2] == "owns_domain" and rows[2][3] == "maltego.Domain"
    assert rows[3][0] == "maltego.Alias" and rows[3][1] == "samotny" and rows[3][2] == ""
    assert rows[3][9] == lone.id and rows[3][10] == ""


def test_output_is_deterministic_and_crlf_terminated():
    g = pair_graph()
    first = to_maltego_csv(g)
    assert first == to_maltego_csv(g) == to_maltego_csv(Graph.from_dict(g.to_dict()))
    data = first.encode("utf-8")
    assert data.endswith(b"\r\n") and data.count(b"\n") == data.count(b"\r\n") == data.count(b"\r") == 2


def test_unicode_roundtrip_utf8_without_bom():
    g = pair_graph(
        a_value="Żaneta Łukasiewicz-Ćwik", b_value="zażółć_gęślą_jaźń", evidence="profil 🙂 ąęłńóśźż — „cytat”"
    )
    data = to_maltego_csv(g).encode("utf-8")
    assert not data.startswith(b"\xef\xbb\xbf") and data.startswith(b"source_type,")
    rows = rows_of(data.decode("utf-8"))
    assert rows[1][1] == "Żaneta Łukasiewicz-Ćwik"
    assert rows[1][4] == "zażółć_gęślą_jaźń"
    assert rows[1][6] == "profil 🙂 ąęłńóśźż — „cytat”"


def test_commas_quotes_and_newlines_keep_column_count():
    nasty = 'a, "b", c\nd\r\ne\rf\u2028g\x00h'
    g = pair_graph(a_value='Jan, "Kowal" Nowak', evidence=nasty, source='zr"odlo,1')
    text = to_maltego_csv(g)
    rows = rows_of(text)
    assert len(rows) == 2 and all(len(r) == NCOLS for r in rows)
    assert rows[1][1] == 'Jan, "Kowal" Nowak'
    assert rows[1][6] == 'a, "b", c d  e f gh'  # CR/LF/U+2028 -> spacja, NUL usuwany
    assert rows[1][7] == 'zr"odlo,1'
    data = text.encode("utf-8")
    assert data.count(b"\n") == data.count(b"\r\n") == 2  # jedna fizyczna linia na wiersz


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t=", " ="])
def test_formula_injection_is_neutralised_in_every_column(prefix):
    g = pair_graph(
        a_value=f"{prefix}cmd|' /C calc'!A0",
        b_value="ofiara",
        evidence=f"{prefix}HYPERLINK(1)",
        source=f"{prefix}zrodlo",
        relation="rel",
    )
    for cell in rows_of(to_maltego_csv(g))[1]:
        assert cell == "" or cell.lstrip()[:1] not in ("=", "+", "-", "@") or cell.startswith("'")
    row = rows_of(to_maltego_csv(g))[1]
    assert row[1].startswith("'") and row[6].startswith("'") and row[7].startswith("'")


def test_phone_number_is_not_prefixed():
    g = Graph({"purpose": PURPOSE})
    a = g.add_node(Node.make(T.PERSON, "Jan Kowalski", source="seed"))
    b = g.add_node(Node.make(T.PHONE, "+48 603 123 456", source="seed"))
    g.add_edge(Edge(a.id, b.id, "has_phone", "seed", 0.5, "x"))
    assert rows_of(to_maltego_csv(g))[1][4].startswith("+48")


# ------------------------------------------------------------------ sekrety i e-maile

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig-sig_sig"
SECRETS = {
    "jwt": f"token sesji {JWT}",
    "bearer": "nagłówek Bearer abcdefghijklmnopqrstuvwxyz0123456789",
    "bearer_split_by_newline": "Bearer\nabcdefghijklmnopqrstuvwxyz0123456789",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow",
    "bcrypt": "hash $2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
    "email_password": "jan.kowalski@example.test:Tajne123!",
    "email_password_semicolon": "anna@example.test;S3kret!",
    "url_password": "https://jan:TajneHaslo@example.test/panel",
    "kv_password": "password=SuperTajne99",
    "zero_width_split": "Bea\u200brer abcdefghijklmnopqrstuvwxyz0123456789",
}


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_secrets_are_removed_from_every_column(name):
    secret = SECRETS[name]
    g = pair_graph(
        a_value=f"Osoba {secret}", b_value=secret, evidence=secret, source=f"zr-{secret}", relation=f"rel {secret}"
    )
    text = to_maltego_csv(g)
    row = rows_of(text)[1]
    for idx in (1, 2, 4, 6, 7, 10):  # source_value, relation, target_value, evidence, source, target_id
        assert row[idx] == MALTEGO_SECRET_MARK, (MALTEGO_HEADER[idx], row[idx])
    for fragment in (
        JWT,
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "PRIVATE KEY",
        "$2b$12$",
        "Tajne123",
        "S3kret",
        "TajneHaslo",
        "SuperTajne99",
        "MIIEow",
    ):
        assert fragment not in text


def test_ordinary_text_is_not_mistaken_for_secret():
    g = pair_graph(evidence="1 token = 1 zl; klasa danych: Passwords; sekret handlowy firmy")
    assert rows_of(to_maltego_csv(g))[1][6] == "1 token = 1 zl; klasa danych: Passwords; sekret handlowy firmy"


def test_emails_are_masked_in_every_column():
    mail = "jan.kowalski@example.test"
    g = pair_graph(
        a_value=f"Jan ({mail})",
        b_value=f"konto-{mail}",
        evidence=f"zgłoszony przez {mail}, tel. 1",
        source=f"rejestr:{mail}",
        relation=f"mail {mail}",
    )
    text = to_maltego_csv(g)
    assert "@example.test" not in text and "jan.kowalski" not in text
    row = rows_of(text)[1]
    assert MALTEGO_EMAIL_MASK in row[1] and MALTEGO_EMAIL_MASK in row[2] and MALTEGO_EMAIL_MASK in row[4]
    assert row[6] == f"zgłoszony przez {MALTEGO_EMAIL_MASK}, tel. 1"
    assert MALTEGO_EMAIL_MASK in row[7] and MALTEGO_EMAIL_MASK in row[9] or MALTEGO_EMAIL_MASK in row[10]


def test_email_nodes_are_not_exported_and_neighbours_stay_as_rows():
    g = Graph({"purpose": PURPOSE})
    p = g.add_node(Node.make(T.PERSON, "Jan Kowalski", source="seed"))
    m = g.add_node(Node.make(T.EMAIL, "jan.kowalski@example.test", source="seed"))
    g.add_edge(Edge(p.id, m.id, "has_email", "seed", 0.9, "dowód"))
    lone = g.add_node(Node.make(T.EMAIL, "anna@example.test", source="seed"))
    assert lone.id in g.nodes
    text = to_maltego_csv(g)
    assert "example.test" not in text and "maltego.EmailAddress" not in text and "has_email" not in text
    rows = rows_of(text)
    assert len(rows) == 2 and rows[1][0] == "maltego.Person" and rows[1][1] == "Jan Kowalski" and rows[1][2] == ""


# ------------------------------------------------------------------ proweniencja z importu org-intel


def org_intel_graph(tmp_path: Path) -> Graph:
    data = json.loads((FX / "export_subdomain.json").read_text(encoding="utf-8"))
    for obs in data["observations"]:
        if obs["entity_type"] == "incident":
            obs["evidence_hash"] = HASH
    path = tmp_path / "org.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    g = Graph({"purpose": PURPOSE})
    import_files(g, [path], NOW)
    return g


def test_org_intel_provenance_columns(tmp_path):
    g = org_intel_graph(tmp_path)
    text = to_maltego_csv(g)
    rows = [dict(zip(MALTEGO_HEADER, r, strict=True)) for r in rows_of(text)[1:]]
    assert len(rows) == len(g.edges) == 8
    assert all(r["source"].startswith("org-intel:") and r["confidence"] and r["derivation"] for r in rows)
    incident = {r["source_id"]: r for r in rows if r["relation"] == "associated_with_incident"}
    sub = incident["domain:example.test"]  # domena główna powiązana z incydentem tylko przez subdomenę
    assert sub["derivation"] == "inferred" and sub["confidence"] == "0.600"
    assert sub["evidence_hash"] == HASH and sub["target_id"] == "organization:demobreach"
    assert sub["evidence"].startswith("inferred; cert_advisory;")
    direct = incident["domain:shop.example.test"]
    assert direct["derivation"] == "direct" and direct["confidence"] == "0.900" and direct["evidence_hash"] == HASH
    cert = "org-intel:cert.pl/posts/2026/10/demo-wyciek-stealer"
    assert all(r["evidence_hash"] == (HASH if r["source"] == cert else "") for r in rows)  # "brak" -> puste pole
    assert all(r["derivation"] in ("direct", "inferred") for r in rows)
    assert "@" not in text


def test_evidence_ref_is_exported():
    g = pair_graph()
    edge = next(iter(g.edges.values()))
    edge.evidence_ref = ["vault/aa11", "vault/bb22"]
    assert rows_of(to_maltego_csv(g))[1][13] == "vault/aa11 vault/bb22"


def test_derivation_is_not_guessed_for_other_sources():
    g = pair_graph(evidence="direct; wpisane ręcznie przez operatora")
    row = dict(zip(MALTEGO_HEADER, rows_of(to_maltego_csv(g))[1], strict=True))
    assert row["derivation"] == ""


# ------------------------------------------------------------------ sprawa


def test_save_case_writes_maltego_csv_atomically(tmp_path):
    case_dir = make_case(tmp_path, pair_graph())
    case = sprawa.open_case(case_dir, "ala")
    sprawa.save_case(case)
    data = (case_dir / "maltego.csv").read_bytes()
    assert data == to_maltego_csv(case.graph).encode("utf-8") and data.startswith(b"source_type,")
    assert "maltego.csv" in sprawa.CASE_FILES
    assert not [p.name for p in case_dir.iterdir() if p.name.endswith(".tmp")]
    assert {p.name for p in case_dir.iterdir()} >= {
        "graph.json",
        "graph.graphml",
        "maltego.csv",
        "report.html",
        "kropki.svg",
        "audit.jsonl",
    }


# ------------------------------------------------------------------ eg export --maltego


def test_export_cli_creates_new_file_byte_exact(tmp_path, capsys):
    g = pair_graph(a_value="Żaneta", evidence="ąę")
    gp = graph_file(tmp_path, g)
    out = tmp_path / "wyj.csv"
    assert export_cli(gp, out) == 0
    assert out.read_bytes() == to_maltego_csv(Graph.load(gp)).encode("utf-8")
    assert b"\r\r" not in out.read_bytes() and out.read_bytes().count(b"\r\n") == 2
    assert sorted(p.name for p in tmp_path.iterdir()) == ["wej", "wyj.csv"]  # bez plików tymczasowych
    assert "Maltego CSV" in capsys.readouterr().out


def test_export_cli_refuses_existing_file(tmp_path, capsys):
    gp = graph_file(tmp_path, pair_graph())
    out = tmp_path / "cudzy.csv"
    out.write_bytes(b"moje dane, nie ruszac\n")
    assert export_cli(gp, out) == 2
    assert out.read_bytes() == b"moje dane, nie ruszac\n"
    assert "już istnieje" in capsys.readouterr().err
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cudzy.csv", "wej"]


def test_export_cli_force_overwrites_atomically(tmp_path):
    g = pair_graph()
    gp = graph_file(tmp_path, g)
    out = tmp_path / "wyj.csv"
    out.write_bytes(b"stare\n")
    assert export_cli(gp, out, "--force") == 0
    assert out.read_bytes() == to_maltego_csv(g).encode("utf-8")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["wej", "wyj.csv"]


def test_export_cli_refuses_foreign_temp_file_and_leaves_it(tmp_path):
    gp = graph_file(tmp_path, pair_graph())
    out = tmp_path / "wyj.csv"
    foreign = tmp_path / f".wyj.csv.{os.getpid()}.tmp"
    foreign.write_bytes(b"cudzy plik tymczasowy")
    assert export_cli(gp, out) == 2
    assert not out.exists() and foreign.read_bytes() == b"cudzy plik tymczasowy"
    assert export_cli(gp, out, "--force") == 2  # także z --force: cudzy plik tymczasowy nie jest ruszany
    assert not out.exists() and foreign.read_bytes() == b"cudzy plik tymczasowy"


@pytest.mark.parametrize(
    "name",
    [
        "graph.json",
        "audit.jsonl",
        "graph.graphml",
        "report.html",
        "kropki.svg",
        "GRAPH.JSON",
        "audit.jsonl.",
        "graph.json:x",
    ],
)
def test_export_cli_refuses_case_file_names(tmp_path, name):
    case = make_case(tmp_path, pair_graph())
    before = {p.name: p.read_bytes() for p in case.iterdir()}
    elsewhere = tmp_path / "gdzie_indziej"
    elsewhere.mkdir()
    for folder in (case, elsewhere):
        assert export_cli(case / "graph.json", folder / name, "--force") == 2
    assert {p.name: p.read_bytes() for p in case.iterdir()} == before
    assert list(elsewhere.iterdir()) == []


def test_export_cli_refuses_case_files_via_dotdot_and_input_file(tmp_path):
    case = make_case(tmp_path, pair_graph())
    before = (case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()
    tricky = case / "podkatalog" / ".." / "graph.json"
    (case / "podkatalog").mkdir()
    assert export_cli(case / "graph.json", tricky, "--force") == 2
    gp = graph_file(tmp_path, pair_graph(), name="moj.json")
    assert export_cli(gp, gp, "--force") == 2
    assert (case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes() == before
    assert Graph.load(gp).nodes


def test_export_cli_maltego_csv_name_refused_inside_case_dir_but_allowed_elsewhere(tmp_path):
    case = make_case(tmp_path, pair_graph())
    assert export_cli(case / "graph.json", case / "maltego.csv", "--force") == 2
    assert not (case / "maltego.csv").exists()
    other = tmp_path / "inny"
    other.mkdir()
    assert export_cli(case / "graph.json", other / "maltego.csv") == 0
    assert (other / "maltego.csv").read_bytes().startswith(b"source_type,")


def test_export_cli_missing_directory_or_directory_target(tmp_path):
    gp = graph_file(tmp_path, pair_graph())
    assert export_cli(gp, tmp_path / "brak" / "x.csv") == 2
    assert export_cli(gp, tmp_path) == 2


def test_export_cli_refusal_happens_before_other_outputs(tmp_path):
    gp = graph_file(tmp_path, pair_graph())
    out = tmp_path / "cudzy.csv"
    out.write_bytes(b"x")
    graphml = tmp_path / "g.graphml"
    assert cli.main(["export", str(gp), "--graphml", str(graphml), "--maltego", str(out)]) == 2
    assert not graphml.exists() and out.read_bytes() == b"x"
