"""Podkomenda `polacz`: cel badania, dziennik audytu, wyjścia (JSON/GraphML/HTML), kody wyjścia, tryb offline."""
import json
import shutil
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from entity_graph import cli
from entity_graph.guardrails import verify_audit
from entity_graph.model import Graph, Status

IMP = Path(__file__).parent / "fixtures" / "import"
PURPOSE = "łączenie wyników własnego audytu firmy X, zlecenie 2026/14"
GOOD = ["krs_acme.json", "vat_acme.json", "dns_acme.json", "dns_sklep.json", "hibp_domain_search.json", "ue_acme.json",
        "phone.json", "exif.csv"]


def run(args):
    return cli.main(["polacz", *args])


def good_dir(tmp_path, names=GOOD) -> Path:
    d = tmp_path / "in"
    d.mkdir()
    for n in names:
        shutil.copy(IMP / n, d / n)
    return d


def test_polacz_requires_purpose_and_input(tmp_path):
    with pytest.raises(SystemExit) as exc:
        run(["--out", str(tmp_path / "o"), str(IMP)])
    assert exc.value.code == 2 and not (tmp_path / "o").exists()
    with pytest.raises(SystemExit):
        run(["--purpose", PURPOSE])


@pytest.mark.parametrize("purpose", ["", "test", "xx yy"])
def test_polacz_rejects_weak_purpose_before_reading_any_file(purpose, capsys, tmp_path):
    assert run(["--purpose", purpose, "--out", str(tmp_path / "o"), str(IMP)]) == 2
    assert "--purpose" in capsys.readouterr().err and not (tmp_path / "o").exists()


def test_polacz_end_to_end_outputs_audit_and_exit_code_0_for_clean_inputs(capsys, tmp_path):
    out = tmp_path / "wynik"
    rc = run(["--purpose", PURPOSE, "--case-ref", "ZL-9", "--operator", "ala", "--out", str(out), str(good_dir(tmp_path))])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    for name in ("graph.json", "graph.graphml", "report.html", "audit.jsonl"):
        assert (out / name).is_file()
    g = Graph.load(out / "graph.json")
    assert g.meta["purpose"] == PURPOSE and g.meta["options"]["offline"] is True
    assert len(g.meta["imports"]) == len(GOOD) and all(i["status"] == "IMPORTED" for i in g.meta["imports"])
    assert any(e.source == "links" for e in g.edges.values())
    ET.fromstring((out / "graph.graphml").read_text(encoding="utf-8"))          # poprawny XML
    assert "IMPORTED=8, SKIPPED=0, ERROR=0" in cap.out
    ok, _ = verify_audit(out / "audit.jsonl")
    assert ok
    events = [json.loads(ln) for ln in (out / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[0]["event"] == "start" and events[0]["purpose"] == PURPOSE and events[0]["operator"] == "ala"
    assert events[0]["inputs"] == [{"type": "file", "value": str(tmp_path / "in")}]
    kinds = [e["event"] for e in events]
    assert kinds.count("import") == len(GOOD) and kinds[0] == "start" and kinds[-2:] == ["merge", "end"]
    imp = [e for e in events if e["event"] == "import"]
    assert all(len(e["sha256"]) == 64 and e["status"] == "IMPORTED" for e in imp)
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Powiązania między źródłami" in html and "email_matches_org_domain" in html


def test_polacz_exit_code_1_and_report_when_inputs_have_skipped_and_errors(capsys, tmp_path):
    out = tmp_path / "o"
    rc = run(["--purpose", PURPOSE, "--out", str(out), str(IMP)])
    cap = capsys.readouterr()
    assert rc == 1
    g = Graph.load(out / "graph.json")
    statuses = {i["status"] for i in g.meta["imports"]}
    assert statuses == {"IMPORTED", "SKIPPED", "ERROR"}
    assert "SKIPPED" in cap.err and "ERROR" in cap.err
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "SKIPPED=6" in html and "ERROR=2" in html
    assert any(r.status is Status.ERROR for r in g.runs)
    events = [json.loads(ln) for ln in (out / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    skipped = [e for e in events if e["event"] == "import" and e["status"] == "SKIPPED"]
    assert skipped and all(e["reason"] for e in skipped)
    assert verify_audit(out / "audit.jsonl")[0]


def test_polacz_exit_code_1_when_nothing_imported(capsys, tmp_path):
    d = tmp_path / "in"
    d.mkdir()
    shutil.copy(IMP / "notatki.txt", d / "notatki.txt")
    rc = run(["--purpose", PURPOSE, "--out", str(tmp_path / "o"), str(d)])
    assert rc == 1 and "nic nie zaimportowano" in capsys.readouterr().err
    assert (tmp_path / "o" / "graph.json").is_file()


def test_polacz_refuses_to_overwrite_existing_graph(tmp_path):
    out = tmp_path / "o"
    assert run(["--purpose", PURPOSE, "--out", str(out), str(good_dir(tmp_path))]) == 0
    assert run(["--purpose", PURPOSE, "--out", str(out), str(IMP)]) == 2


def test_polacz_does_not_reimport_its_own_output_directory(tmp_path):
    d = good_dir(tmp_path)
    out = d / "wyniki-polacz"
    assert run(["--purpose", PURPOSE, "--out", str(out), str(d)]) == 0
    g = Graph.load(out / "graph.json")
    assert len(g.meta["imports"]) == len(GOOD)          # graph.json i audit.jsonl z --out nie wróciły jako wejście


def test_polacz_merges_previous_investigation_graph(tmp_path):
    first = tmp_path / "pierwszy"
    assert run(["--purpose", PURPOSE, "--out", str(first), str(good_dir(tmp_path, ["krs_acme.json", "dns_acme.json"]))]) == 0
    second = tmp_path / "drugi"
    d2 = tmp_path / "in2"
    d2.mkdir()
    shutil.copy(IMP / "hibp_domain_search.json", d2 / "h.json")
    assert run(["--purpose", PURPOSE, "--out", str(second), str(first / "graph.json"), str(d2)]) == 0
    g = Graph.load(second / "graph.json")
    assert "organization:acme testowa spolka akcyjna" in g.nodes and "email:biuro@acme-testowa.example" in g.nodes
    assert {i["format"] for i in g.meta["imports"]} == {"entity-graph", "hibp-monitor"}
    assert any(e.relation == "email_matches_org_domain" for e in g.edges.values())    # kropki z dwóch badań się spięły


def test_polacz_min_confidence_validated_and_applied(tmp_path):
    d = good_dir(tmp_path, ["ue_acme.json"])
    assert run(["--purpose", PURPOSE, "--out", str(tmp_path / "x"), "--min-confidence", "7", str(d)]) == 2
    assert run(["--purpose", PURPOSE, "--out", str(tmp_path / "o"), "--min-confidence", "0.6", str(d)]) == 0
    assert "url:slabe.example/acme_testowa" not in Graph.load(tmp_path / "o" / "graph.json").nodes


def test_polacz_is_offline_and_leaks_no_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("HIBP_API_KEY", "bardzo-tajny-klucz-123")  # atrapa (kanarek wycieku)  gitleaks:allow

    def no_net(*a, **k):
        raise AssertionError("polacz nie może używać sieci")
    monkeypatch.setattr(socket, "socket", no_net)
    monkeypatch.setattr(socket, "create_connection", no_net)
    out = tmp_path / "o"
    assert run(["--purpose", PURPOSE, "--out", str(out), str(good_dir(tmp_path))]) == 0
    text = "".join(p.read_text(encoding="utf-8") for p in out.iterdir() if p.is_file())
    assert "bardzo-tajny-klucz-123" not in text



def test_polacz_record_level_error_in_imported_file_gives_exit_code_1(capsys, tmp_path):
    d = good_dir(tmp_path, ["exif.json", "dns_acme.json"])        # exif.json zawiera nieczytelne zdjęcie
    out = tmp_path / "o"
    assert run(["--purpose", PURPOSE, "--out", str(out), str(d)]) == 1
    g = Graph.load(out / "graph.json")
    assert [i["status"] for i in g.meta["imports"]] == ["IMPORTED", "IMPORTED"]
    assert any(r.status is Status.ERROR and "IMG_0003" in r.node_id for r in g.runs)
