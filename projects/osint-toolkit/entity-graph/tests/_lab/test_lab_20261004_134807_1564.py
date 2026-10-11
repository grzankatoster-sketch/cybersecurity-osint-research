"""Skarbiec dowodów: surowe odpowiedzi źródeł z SHA-256, URL, czasem i statusem HTTP; evidence_ref na węzłach
i krawędziach, skróty w łańcuchu audytu, sekcja w raporcie, GraphML i eg evidence-verify. Bez sieci (FakeFetch)."""
import hashlib
import json

from conftest import FakeFetch
from entity_graph import cli
from entity_graph.engine import Options, investigate, new_graph
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.http import HttpResponse
from entity_graph.model import Graph, Node, Status
from entity_graph.normalize import EntityType as T

NOW = "2026-10-03T12:00:00+00:00"
PURPOSE = "audyt własnej infrastruktury firmy X"
RIPE = json.dumps({"status": "ok", "data": {"resource": "1.1.1.0/24", "announced": True,
                                           "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}]}}) + "\n"
ROUTES = [("stat.ripe.net", HttpResponse(200, RIPE)),
          ("internetdb.shodan.io", HttpResponse(404, '{"detail":"No information available"}'))]
ONLY = frozenset({"ip_asn", "ip_internetdb"})


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def index(folder):
    return [json.loads(l) for l in (folder / "index.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def audit_events(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def vault_ctx(make_ctx, tmp_path, routes):
    from entity_graph.vault import EvidenceVault, RecordingFetcher
    ctx = make_ctx(routes=routes)
    vault = EvidenceVault(tmp_path / "evidence", now=ctx.now)
    ctx.fetch = RecordingFetcher(ctx.fetch, vault)
    ctx.vault = vault
    audit = AuditLog(tmp_path / "audit.jsonl", "ala")
    audit.start(PURPOSE, [], {})
    g = new_graph(PURPOSE, "ala", "", [], {}, "2026-10-03")
    investigate(g, [Node.make(T.IP, "1.1.1.1")], ctx, audit, Options(only=ONLY))
    return g, audit


def run(ctx, out, *extra):
    return cli.main(["run", "--purpose", PURPOSE, "--ip", "1.1.1.1", "--only", "ip_asn,ip_internetdb",
                     "--operator", "ala", "--out", str(out), *extra], ctx)


def test_recording_fetcher_stores_raw_body_with_sha_url_time_status(tmp_path):
    from entity_graph.vault import EvidenceVault, RecordingFetcher
    body = '{"a": 1}\n{"b": "zażółć"}\n'
    inner = FakeFetch([("api.example.org", HttpResponse(200, body, {"content-type": "application/json"}))])
    vault = EvidenceVault(tmp_path / "evidence", now=lambda: NOW)
    fetch = RecordingFetcher(inner, vault)
    vault.begin("ip_asn", "ip:1.1.1.1")
    resp = fetch.get("https://api.example.org/x?q=1", {"hibp-api-key": "bardzo-tajny-klucz"})
    assert resp.status == 200 and resp.text == body                       # odpowiedź przechodzi bez zmian
    assert inner.calls == [("https://api.example.org/x?q=1", {"hibp-api-key": "bardzo-tajny-klucz"})]
    entries = vault.take()
    assert len(entries) == 1
    entry = entries[0]
    assert vault.take() == []                                             # take() opróżnia bieżące uruchomienie
    assert entry["url"] == "https://api.example.org/x?q=1" and entry["status"] == 200
    assert entry["fetched_at"] == NOW and entry["sha256"] == sha(body)
    assert entry["size"] == len(body.encode("utf-8"))
    assert entry["transform"] == "ip_asn" and entry["node"] == "ip:1.1.1.1" and entry["ref"]
    assert (tmp_path / "evidence" / entry["file"]).read_bytes() == body.encode("utf-8")   # surowo, bez CRLF
    assert index(tmp_path / "evidence") == [entry]
    stored = "".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in (tmp_path / "evidence").rglob("*") if p.is_file())
    assert "bardzo-tajny-klucz" not in stored                             # nagłówki żądania (klucze) nie trafiają do skarbca


def test_error_responses_are_recorded_but_stay_error(make_ctx, tmp_path):
    # stat.ripe.net: 429; internetdb: brak trasy = błąd sieci (status None)
    g, audit = vault_ctx(make_ctx, tmp_path, [("stat.ripe.net", HttpResponse(429, "slow down", {"retry-after": "1"}))])
    assert {r.transform: r.status for r in g.runs} == {"ip_asn": Status.ERROR, "ip_internetdb": Status.ERROR}
    entries = {e["transform"]: e for e in index(tmp_path / "evidence")}
    assert entries["ip_asn"]["status"] == 429 and entries["ip_asn"]["sha256"] == sha("slow down")
    net = entries["ip_internetdb"]
    assert net["status"] is None and net["error"] == "brak trasy w teście"
    assert net["sha256"] == sha("") and net["size"] == 0
    ev = {e["transform"]: e for e in audit_events(audit.path) if e["event"] == "transform"}
    assert [x["status"] for x in ev["ip_asn"]["evidence"]] == [429]
    assert [x["status"] for x in ev["ip_internetdb"]["evidence"]] == [None]
    assert verify_audit(audit.path)[0]


def test_engine_links_edges_and_nodes_to_evidence_and_chains_sha_in_audit(make_ctx, tmp_path):
    g, audit = vault_ctx(make_ctx, tmp_path, ROUTES)
    entries = index(tmp_path / "evidence")
    assert sorted(e["status"] for e in entries) == [200, 404]          # 404 (NOT_FOUND) też jest dowodem
    ripe = next(e for e in entries if "stat.ripe.net" in e["url"])
    edges = [e for e in g.edges.values() if e.relation == "announced_by"]
    assert len(edges) == 1
    assert edges[0].evidence_ref == [ripe["ref"]]
    assert ripe["ref"] in g.nodes[edges[0].dst].attrs["evidence_ref"]
    assert ripe["ref"] in g.nodes["ip:1.1.1.1"].attrs["evidence_ref"]   # atrybuty z odpowiedzi (bgp_prefix, asn)
    ev = [e for e in audit_events(audit.path) if e["event"] == "transform" and e["transform"] == "ip_asn"]
    assert ev[0]["evidence"] == [{"ref": ripe["ref"], "url": ripe["url"], "status": 200, "sha256": sha(RIPE)}]
    assert verify_audit(audit.path)[0]
    g.save(tmp_path / "graph.json")
    loaded = [e for e in Graph.load(tmp_path / "graph.json").edges.values() if e.relation == "announced_by"]
    assert loaded[0].evidence_ref == [ripe["ref"]]


def test_cli_run_builds_vault_visible_in_graph_report_and_graphml(capsys, make_ctx, tmp_path):
    out = tmp_path / "wyniki"
    assert run(make_ctx(routes=ROUTES), out) == 0
    assert (out / "evidence" / "index.jsonl").is_file()
    entries = index(out / "evidence")
    assert len(entries) == 2
    ripe = next(e for e in entries if "stat.ripe.net" in e["url"])
    data = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    edge = [e for e in data["edges"] if e["relation"] == "announced_by"]
    assert edge[0]["evidence_ref"] == [ripe["ref"]]
    assert data["meta"]["evidence_vault"]["count"] == 2
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Skarbiec dowodów" in html and ripe["ref"] in html and ripe["sha256"][:16] in html
    assert "evidence_ref" in (out / "graph.graphml").read_text(encoding="utf-8")
    events = audit_events(out / "audit.jsonl")
    assert events[0]["options"]["evidence_vault"] is True and events[-1]["event"] == "end"
    assert verify_audit(out / "audit.jsonl")[0]
    assert "Skarbiec dowodów: 2" in capsys.readouterr().out


def test_cli_no_evidence_opt_out_leaves_no_vault(make_ctx, tmp_path):
    out = tmp_path / "bez"
    assert run(make_ctx(routes=ROUTES), out, "--no-evidence") == 0
    assert not (out / "evidence").exists()
    data = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert not any(e.get("evidence_ref") for e in data["edges"])
    assert audit_events(out / "audit.jsonl")[0]["options"]["evidence_vault"] is False


def test_evidence_verify_detects_tampered_rewritten_index_and_missing_file(capsys, make_ctx, tmp_path):
    out = tmp_path / "wyniki"
    assert run(make_ctx(routes=ROUTES), out) == 0
    folder = out / "evidence"
    assert (folder / "index.jsonl").is_file()
    original_index = (folder / "index.jsonl").read_bytes()
    capsys.readouterr()
    assert cli.main(["evidence-verify", str(out)]) == 0
    assert capsys.readouterr().out.startswith("OK")

    entries = index(folder)
    ripe = next(e for e in entries if "stat.ripe.net" in e["url"])
    body = folder / ripe["file"]
    forged = RIPE.replace("CLOUDFLARENET", "INNA-FIRMA")
    body.write_bytes(forged.encode("utf-8"))
    assert cli.main(["evidence-verify", str(out)]) == 1
    msg = capsys.readouterr().out
    assert msg.startswith("BŁĄD") and ripe["ref"] in msg

    # podmiana skrótu także w indeksie nie pomaga: oryginalny skrót jest w łańcuchu audytu
    rewritten = [dict(e, sha256=sha(forged), size=len(forged.encode("utf-8"))) if e["ref"] == ripe["ref"] else e
                 for e in entries]
    (folder / "index.jsonl").write_bytes(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in rewritten).encode("utf-8"))
    assert cli.main(["evidence-verify", str(out)]) == 1
    assert ripe["ref"] in capsys.readouterr().out

    # przywrócenie oryginału: znów OK; usunięcie pliku: błąd
    (folder / "index.jsonl").write_bytes(original_index)
    body.write_bytes(RIPE.encode("utf-8"))
    assert cli.main(["evidence-verify", str(out)]) == 0
    capsys.readouterr()
    other = next(e for e in entries if e["ref"] != ripe["ref"])
    (folder / other["file"]).unlink()
    assert cli.main(["evidence-verify", str(out)]) == 1
    assert other["ref"] in capsys.readouterr().out
