"""Asystent sprawy: reguły (porządek, sprzeczności, dozwolone kroki), filtr odpowiedzi lokalnego AI,
tylko pętla zwrotna, dziennik audytu i eksport CSV dla Maltego. Bez sieci: model zastępuje atrapa."""

from __future__ import annotations

import csv
import io
import json
import urllib.error
from pathlib import Path

import pytest

from entity_graph import asystent, cli
from entity_graph.export import to_maltego_csv
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/52"
JAN, ANNA = "Jan Kowalski", "Anna Kowalska"
SRC = "https://example.org/rejestr/wpis-17"


def _case(tmp_path: Path) -> Path:
    g = Graph({"purpose": PURPOSE})
    for p in (JAN, ANNA):
        g.add_node(Node.make(T.PERSON, p, source="seed"))
    case = tmp_path / "sprawa"
    case.mkdir()
    g.save(case / "graph.json")
    AuditLog(case / "audit.jsonl", "ala").start(PURPOSE, [], {})
    return case


def _relacja(case: Path, typ: str, a=ANNA, b=JAN) -> int:
    return cli.main(
        [
            "relacja",
            str(case),
            "--person",
            a,
            "--typ",
            typ,
            "--druga-osoba",
            b,
            "--zrodlo",
            SRC,
            "--dowod",
            "akt z dokumentów klienta",
            "--operator",
            "ala",
        ]
    )


def _run(capsys, *argv) -> dict:
    assert cli.main(list(argv)) == 0
    return json.loads(capsys.readouterr().out)


def test_rules_find_contradiction_and_propose_only_allowed_steps(tmp_path, capsys):
    case = _case(tmp_path)
    assert _relacja(case, "rodzic") == 0 and _relacja(case, "rodzenstwo") == 0  # sprzeczne twierdzenia
    capsys.readouterr()
    out = _run(capsys, "asystent", str(case))
    assert out["porzadek"]["osoby"] == [JAN, ANNA] or set(out["porzadek"]["osoby"]) == {JAN, ANNA}
    assert out["porzadek"]["twierdzenia"] == {"oczekuje": 2}
    assert any(s["rodzaj"] == "relacje" for s in out["sprzecznosci"])
    kinds = {s["krok"] for s in out["kroki"]}
    assert {"wyjasnij_sprzecznosc", "decyzja_relacji"} <= kinds <= set(asystent.ALLOWED_STEPS)
    assert all(s["opis"] == asystent.ALLOWED_STEPS[s["krok"]] for s in out["kroki"])
    assert "ai" not in out and out["ograniczenia"]


def test_pattern_usernames_are_hypotheses_and_one_step_per_person():
    g = Graph({"purpose": PURPOSE})
    jan = g.add_node(Node.make(T.PERSON, JAN, source="seed"))
    for name in ("jkowalski", "jan.kowalski", "kowalskij"):
        u = Node.make(T.USERNAME, name, source="person_candidates")
        u.attrs["candidate"] = True
        u = g.add_node(u)
        g.add_edge(
            Edge(
                jan.id,
                u.id,
                "candidate_username",
                source="person_candidates",
                confidence=0.0,
                evidence="wygenerowano ze wzorca",
            )
        )
    out = asystent.analyze(g)
    assert out["porzadek"]["nazwy_uzytkownika"] == {
        "podane_przez_operatora": 0,
        "hipotezy_ze_wzorcow_niesprawdzone": 3,
        "hipotezy_sprawdzone_skanem": 0,
    }
    rounds = [s for s in out["kroki"] if s["krok"] == "runda_kandydatow"]
    assert len(rounds) == 1 and rounds[0]["dotyczy"].startswith(JAN) and "3 nazw-hipotez" in rounds[0]["dotyczy"]


def test_rules_do_not_change_the_case(tmp_path, capsys):
    case = _case(tmp_path)
    before = {f.name: f.read_bytes() for f in case.iterdir()}
    _run(capsys, "asystent", str(case))
    assert {f.name: f.read_bytes() for f in case.iterdir()} == before


def test_profile_confirmed_for_two_people_is_a_contradiction():
    g = Graph({"purpose": PURPOSE})
    people = [g.add_node(Node.make(T.PERSON, p, source="seed")) for p in (JAN, ANNA)]
    prof = Node.make(T.URL, "https://github.com/jkowalski", source="username-engine")
    prof.attrs.update({"kind": "profile", "site": "GitHub", "manual": True})
    prof = g.add_node(prof)
    for person in people:
        g.add_edge(
            Edge(
                person.id, prof.id, "confirmed_profile", source="operator", confidence=1.0, evidence="decyzja operatora"
            )
        )
    out = asystent.analyze(g)
    assert any(c["rodzaj"] == "profil" and "kilku osób" in c["opis"] for c in out["sprzecznosci"])


@pytest.mark.parametrize(
    "line",
    [
        "To jest ta sama osoba co na profilu GitHub.",
        "Tożsamość została potwierdzona przez zdjęcie.",
        "Zaloguj się na konto i sprawdź prywatny profil.",
        "Obejdź CAPTCHA, aby pobrać wyniki.",
        "Użyj PimEyes do wyszukania twarzy.",
        "Zlokalizuj telefon przez operatora.",
        "Sprawdź wycieki haseł w DeHashed.",
        "1. Ze źródła potwierdzono istnienie 12 nazw użytkowników.",  # hipotezy ze wzorcow to nie konta
        # obejscia wskazane w przegladzie 05.10
        "To konto należy do Jana Kowalskiego.",
        "To konto Jana Kowalskiego.",
        "Oba profile należą do tej samej osoby.",
        "Same person on both profiles.",
        "It is him.",
        "This account belongs to Jan.",
        "To na pewno on.",
        "To ten sam człowiek.",
        "**To** ta   sama osoba",
        "To ta\u200b sama osoba",
        "Zaloguj się do konta.",
        "Kup dostęp do bazy.",
        "Użyj bramki SMS.",
        "Załóż fałszywe konto.",
        "Użyj social engineering.",
        "Zrób wyszukiwanie po twarzy.",
        "Uruchom Maigret.",
        "Sprawdź hasło w wycieku.",
        "Omiń to.",
    ],
)
def test_ai_filter_drops_identity_claims_and_out_of_bounds_steps(line):
    text, dropped = asystent.filter_ai_text("1. Rozstrzygnij twierdzenie r-1 z dowodem.\n" + line)
    assert dropped == 1 and line not in text and "Rozstrzygnij" in text


def test_ai_filter_catches_claim_split_over_two_lines_and_keeps_harmless_lines():
    text, dropped = asystent.filter_ai_text(
        "1. Porządek.\nJan Kowalski to ta\nsama osoba co profil.\n2. Obejrzyj profil."
    )
    assert dropped == 2 and "sama osoba" not in text and "Porządek" in text
    assert "Obejrzyj profil" in text  # 'obejrzyj' to nie 'obejdz'


def test_ai_receives_only_counts_kinds_and_step_numbers(tmp_path):
    g = Graph({"purpose": PURPOSE})
    people = [g.add_node(Node.make(T.PERSON, p, source="seed")) for p in (JAN, ANNA)]
    prof = Node.make(T.URL, "https://github.com/jkowalski", source="username-engine")
    prof.attrs.update({"kind": "profile", "site": "GitHub"})
    prof = g.add_node(prof)
    for person in people:
        g.add_edge(Edge(person.id, prof.id, "confirmed_profile", source="operator", confidence=1.0, evidence="x"))
    analysis = asystent.analyze(g)
    payload = json.dumps(asystent.ai_payload(analysis), ensure_ascii=False)
    prompt = asystent._prompt(analysis)
    for secret in (JAN, ANNA, "github.com", "jkowalski"):
        assert secret not in payload and secret not in prompt
    assert [k["nr"] for k in analysis["kroki"]] == list(range(1, len(analysis["kroki"]) + 1))
    assert prompt.rstrip().endswith("Pisz zwykłym tekstem.")  # zasady powtorzone po danych


def test_ai_redirect_from_loopback_is_not_followed():
    import http.server
    import threading

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "http://198.51.100.7/api/generate")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    ai = asystent.ai_review(
        {
            "porzadek": {
                "osoby": [],
                "nazwy_uzytkownika": {},
                "telefony": 0,
                "twierdzenia": {},
                "kandydaci": {},
                "przebiegi_zrodel": {},
                "zrodla": {},
            },
            "sprzecznosci": [],
            "kroki": [],
        },
        url=f"http://127.0.0.1:{srv.server_address[1]}",
        timeout=5,
    )
    srv.server_close()
    assert ai["status"] == "ERROR" and "302" in ai["uwaga"]


def test_ai_only_on_loopback():
    for bad in ("http://user:pw@127.0.0.1:11434", "http://127.0.0.1:abc", "http://127.0.0.1:11434/?x=1"):
        with pytest.raises(ValueError):
            asystent.check_loopback(bad)
    for bad in ("http://10.0.0.5:11434", "https://127.0.0.1:11434", "http://example.com", "http://127.0.0.1.nip.io"):
        with pytest.raises(ValueError, match="na tym komputerze"):
            asystent.check_loopback(bad)
    assert asystent.check_loopback("http://localhost:11434/") == "http://localhost:11434"


def test_ai_review_filters_hashes_and_never_sends_material(tmp_path, capsys):
    sent = {}

    def fake_post(url, body, timeout):
        sent.update(url=url, body=body)
        return {"response": "1. Najpierw wyjaśnij sprzeczność.\nTo ta sama osoba, na pewno."}

    analysis = {"porzadek": {"osoby": [JAN]}, "sprzecznosci": [], "kroki": []}
    ai = asystent.ai_review(analysis, post=fake_post)
    assert ai["status"] == "FOUND" and ai["usuniete_linie"] == 1 and "ta sama osoba" not in ai["tekst"]
    assert len(ai["sha256"]) == 64 and "niezweryfikowana" in ai["uwaga"]
    assert sent["url"] == "http://127.0.0.1:11434/api/generate" and sent["body"]["stream"] is False
    assert "ograniczenia" not in sent["body"]["prompt"]  # tylko wynik regul: porzadek, sprzecznosci, kroki


def test_ai_unavailable_is_unknown_not_empty_result():
    def refused(url, body, timeout):
        raise urllib.error.URLError(ConnectionRefusedError("odmowa"))

    def timed_out(url, body, timeout):
        raise urllib.error.URLError(TimeoutError("czas"))

    assert asystent.ai_review({"porzadek": {}, "sprzecznosci": [], "kroki": []}, post=refused)["status"] == "UNKNOWN"
    assert asystent.ai_review({"porzadek": {}, "sprzecznosci": [], "kroki": []}, post=timed_out)["status"] == "ERROR"


def test_ai_use_is_audited_with_hash_not_text(tmp_path, capsys, monkeypatch):
    case = _case(tmp_path)
    graph_before = (case / "graph.json").read_bytes()
    monkeypatch.setattr(asystent, "_post_json", lambda url, body, timeout: {"response": "1. Przejrzyj kandydatów."})
    out = _run(capsys, "asystent", str(case), "--ai", "--operator", "ala")
    assert out["ai"]["status"] == "FOUND"
    lines = [json.loads(x) for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    before, last = lines[-2], lines[-1]
    assert before["event"] == "asystent_ai" and before["phase"] == "przed" and len(before["dane_sha256"]) == 64
    assert before["adres"] == "http://127.0.0.1:11434"
    assert last["event"] == "asystent_ai" and last["phase"] == "po" and last["sha256"] == out["ai"]["sha256"]
    assert "Przejrzyj" not in json.dumps(last, ensure_ascii=False)  # w dzienniku skrot, nie tresc
    assert verify_audit(case / "audit.jsonl")[0]
    assert (case / "graph.json").read_bytes() == graph_before  # odpowiedz AI nie trafia do grafu


def test_audit_log_view(tmp_path, capsys):
    case = _case(tmp_path)
    assert _relacja(case, "rodzic") == 0
    capsys.readouterr()
    out = _run(capsys, "dziennik", str(case))
    assert out["spojny"] is True and out["wszystkich"] >= 3
    assert out["wpisy"][0]["event"] == "start"
    assert all("prev" not in e["szczegoly"] for e in out["wpisy"])


def test_audit_log_view_works_on_broken_chain(tmp_path, capsys):
    case = _case(tmp_path)
    assert _relacja(case, "rodzic") == 0
    lines = (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    (case / "audit.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")  # usuniety wpis
    capsys.readouterr()
    out = _run(capsys, "dziennik", str(case))
    assert out["spojny"] is False and "przerwany" in out["opis"]


def test_assistant_has_no_tools_or_external_network():
    # asystent ma liste blokowanych slow (filtr), wiec zamiast skanu slow: brak podprocesow, przegladarek i
    # gniazd; jedyne wyjscie sieciowe to _post_json z pustym ProxyHandler (petla zwrotna sprawdzana wyzej)
    src = (Path(asystent.__file__)).read_text(encoding="utf-8")
    for banned in ("import subprocess", "import socket", "webdriver", "selenium", "import playwright", "os.system"):
        assert banned not in src
    assert src.count("urlopen") == 0 and src.count("opener.open(") == 1 and "ProxyHandler({})" in src


def test_maltego_csv_is_spreadsheet_safe():
    g = Graph({"purpose": PURPOSE})
    p = Node.make(T.PERSON, '=HYPERLINK("http://zly")', source="seed")
    u = Node.make(T.USERNAME, "jkowalski", source="seed")
    g.add_node(p)
    g.add_node(u)
    g.add_edge(Edge(p.id, u.id, "candidate_username", source="operator", confidence=0.2, evidence="-x\ny"))
    rows = list(csv.reader(io.StringIO(to_maltego_csv(g))))
    assert rows[0][:3] == ["source_type", "source_value", "relation"]
    assert rows[1][0] == "maltego.Person" and rows[1][1].startswith("'=") and rows[1][3] == "maltego.Alias"
    assert rows[1][6] == "'-x y"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("+48 603 123 456", "+48 603 123 456"),  # numer telefonu zostaje wartoscia encji
        ("-12.5", "-12.5"),
        ("@anna", "'@anna"),
        ("=1+1", "'=1+1"),
        ("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0"),
        ("-2+SUM(A1)", "'-2+SUM(A1)"),
        (" =1", "' =1"),
        ("\t=1", "' =1"),
        ("jkowalski", "jkowalski"),
    ],
)
def test_csv_cell_neutralises_formulas_but_keeps_numbers(value, expected):
    from entity_graph.export import _csv_cell

    assert _csv_cell(value) == expected


def test_case_save_writes_maltego_csv(tmp_path):
    case = _case(tmp_path)
    assert _relacja(case, "rodzic") == 0
    assert (case / "maltego.csv").read_text(encoding="utf-8").startswith("source_type,")


INVISIBLE = ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\ufeff", "\u00ad"]


@pytest.mark.parametrize("char", INVISIBLE)
def test_zero_width_pattern_matches_every_invisible_char_and_filter_still_catches_hidden_claim(char):
    assert asystent._ZERO_WIDTH.fullmatch(char)
    text, dropped = asystent.filter_ai_text(f"To ta{char} sama osoba")
    assert dropped == 1 and text == ""


def test_sources_contain_no_literal_invisible_characters():
    # wzorce zapisane jako \uXXXX, nie dosłownie (dosłowne znaki niewidoczne ukrywają treść kodu)
    import unicodedata

    for path in (Path(asystent.__file__), Path(__file__)):
        text = path.read_text(encoding="utf-8")
        bad = [hex(ord(c)) for c in text if c not in "\t\n\r" and unicodedata.category(c) in ("Cf", "Cc")]
        assert bad == [], (path.name, bad)
