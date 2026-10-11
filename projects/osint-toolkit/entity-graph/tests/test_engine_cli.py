import json
from pathlib import Path

import pytest

from conftest import fx, ok, writes_json_to_flag
from entity_graph import cli
from entity_graph.engine import Options, investigate, new_graph
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.http import HttpResponse
from entity_graph.model import Graph, Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY, TransformResult
from entity_graph.transforms.base import Transform

ROUTES = [
    ("rdap.org/ip/", ok(fx("rdap_ip.json"))), ("stat.ripe.net", ok(fx("ripestat.json"))),
    ("internetdb.shodan.io", HttpResponse(404, '{"detail":"No information available"}')),
    ("rdap.org/domain/", ok(fx("rdap_domain.json"))), ("crt.sh", ok(fx("crtsh.json"))),
    ("gravatar.com/avatar", HttpResponse(404)),
]
HANDLERS = {"dns_audit": None}


def go(make_ctx, tmp_path, seeds, opts=None, routes=ROUTES, handlers=None, **settings):
    ctx = make_ctx(routes=routes, handlers=handlers if handlers is not None else {
        "dns_audit": lambda cmd: (0, fx("dns_audit.json"), "")}, **settings)
    audit = AuditLog(tmp_path / "audit.jsonl", "ala")
    audit.start("audyt własnej firmy X", [], {})
    g = new_graph("audyt własnej firmy X", "ala", "", [], {}, "2026-10-03")
    investigate(g, seeds, ctx, audit, opts or Options())
    return g, ctx, audit


def test_domain_investigation_pivots_to_ips_with_depth(make_ctx, tmp_path):
    g, ctx, _ = go(make_ctx, tmp_path, [Node.make(T.DOMAIN, "example.com")])
    ran = {(r.transform, r.node_id) for r in g.runs}
    assert ("dns_audit", "domain:example.com") in ran and ("domain_crtsh", "domain:example.com") in ran
    assert ("ip_rdap", "ip:93.184.216.34") in ran and ("ip_asn", "ip:93.184.216.34") in ran   # głębokość 1: IP z DNS
    assert ("dns_audit", "domain:a.iana-servers.net") not in ran      # hosty NS/MX nie są rozwijane (cudza infrastruktura)
    assert ("dns_audit", "domain:www.example.com") not in ran         # subdomeny tylko na prośbę
    assert "domain:www.example.com" in g.nodes                        # ale są w grafie
    statuses = {r.transform: r.status for r in g.runs if r.node_id == "ip:93.184.216.34"}
    assert statuses["ip_internetdb"] is Status.NOT_FOUND and statuses["ip_rdap"] is Status.FOUND


def test_depth_zero_and_expand_subdomains(make_ctx, tmp_path):
    g, _, _ = go(make_ctx, tmp_path, [Node.make(T.DOMAIN, "example.com")], Options(depth=0))
    assert not any(r.node_id.startswith("ip:") for r in g.runs)
    (tmp_path / "b").mkdir()
    g, _, _ = go(make_ctx, tmp_path / "b", [Node.make(T.DOMAIN, "example.com")], Options(depth=1, expand_subdomains=True))
    assert ("domain_rdap", "domain:mail.example.com") in {(r.transform, r.node_id) for r in g.runs}


def test_offline_skips_network_transforms_as_unknown(make_ctx, tmp_path):
    g, ctx, _ = go(make_ctx, tmp_path, [Node.make(T.DOMAIN, "example.com"), Node.make(T.PERSON, "Jan Kowalski")],
                   Options(offline=True))
    assert ctx.fetch.calls == [] and ctx.runner.calls == []
    by = {r.transform: r.status for r in g.runs}
    assert by["dns_audit"] is Status.UNKNOWN and by["person_candidates"] is Status.FOUND


def test_exception_in_transform_becomes_error_not_not_found(make_ctx, tmp_path):
    def boom(node, ctx):
        raise RuntimeError("sekret w komunikacie")
    registry = {"boom": Transform("boom", (T.DOMAIN,), "x", True, boom)}
    ctx = make_ctx()
    audit = AuditLog(tmp_path / "a.jsonl", "ala")
    audit.start("audyt własnej firmy X", [], {})
    g = new_graph("audyt własnej firmy X", "ala", "", [], {}, "x")
    investigate(g, [Node.make(T.DOMAIN, "example.com")], ctx, audit, Options(), registry)
    [run] = g.runs
    assert run.status is Status.ERROR and "RuntimeError" in run.error and "sekret" not in run.error
    assert "sekret" not in (tmp_path / "a.jsonl").read_text(encoding="utf-8")


def test_candidates_not_scanned_unless_requested(make_ctx, tmp_path):
    handlers = {"username_engine": writes_json_to_flag(fx("ue_scan_clean.json"))}
    g, ctx, _ = go(make_ctx, tmp_path, [Node.make(T.PERSON, "Jan Kowalski")], handlers=handlers, max_usernames=3)
    assert ctx.runner.calls == [] and len(g.nodes_of_type(T.USERNAME)) == 3
    (tmp_path / "c").mkdir()
    g, ctx, _ = go(make_ctx, tmp_path / "c", [Node.make(T.PERSON, "Jan Kowalski")], Options(expand_candidates=True),
                   handlers=handlers, max_usernames=3)
    assert len(ctx.runner.calls) == 3


def test_limits_truncate_and_are_recorded(make_ctx, tmp_path):
    g, _, audit = go(make_ctx, tmp_path, [Node.make(T.DOMAIN, "example.com")], Options(max_runs=2))
    assert len(g.runs) == 2 and "limit uruchomień" in g.meta["truncated"]
    assert '"event": "limit"' in audit.path.read_text(encoding="utf-8")


def test_generic_mail_provider_not_expanded(make_ctx, tmp_path):
    g, ctx, _ = go(make_ctx, tmp_path, [Node.make(T.EMAIL, "jan@gmail.com")])
    assert "domain:gmail.com" in g.nodes
    assert not [r for r in g.runs if r.node_id == "domain:gmail.com"]
    assert not any("gmail.com" in url and "rdap" in url for url, _ in ctx.fetch.calls)


def test_email_at_company_domain_is_expanded(make_ctx, tmp_path):
    g, _, _ = go(make_ctx, tmp_path, [Node.make(T.EMAIL, "jan@example.com")])
    assert ("dns_audit", "domain:example.com") in {(r.transform, r.node_id) for r in g.runs}


def test_phone_canonical_merge(make_ctx, tmp_path):
    payload = json.loads(fx("phone_check.json"))
    payload[0]["e164"] = "+48603123499"
    g, _, _ = go(make_ctx, tmp_path, [Node.make(T.PHONE, "+48603123456")],
                 handlers={"phone_check": writes_json_to_flag(json.dumps(payload))})
    assert list(g.nodes) == ["phone:+48603123499"]
    assert g.nodes["phone:+48603123499"].attrs["phone_valid"] is True


def test_username_scan_then_correlation(make_ctx, tmp_path):
    g, _, _ = go(make_ctx, tmp_path, [Node.make(T.USERNAME, "jkowalski")],
                 handlers={"username_engine": writes_json_to_flag(fx("ue_scan.json"))})
    same = [e for e in g.edges.values() if e.relation == "same_person"]
    assert len(same) == 1
    e = same[0]
    assert e.confidence == 0.9 and e.evidence                    # ograniczone pewnością słabszego konta (0.9)
    for tag in ("cross_link", "same_domain", "name_and_avatar"):
        assert tag in e.evidence


def test_audit_trail_complete(make_ctx, tmp_path):
    g, _, audit = go(make_ctx, tmp_path, [Node.make(T.IP, "1.1.1.1")])
    ok_, msg = verify_audit(audit.path)
    assert ok_, msg
    events = [json.loads(l) for l in audit.path.read_text(encoding="utf-8").splitlines()]
    assert events[0]["event"] == "start" and events[-1]["event"] == "end"
    assert [e["transform"] for e in events if e["event"] == "transform"] == [r.transform for r in g.runs]


# ------------------------------------------------------------------ CLI

def run_cli(args, ctx=None):
    return cli.main(args, ctx)


def test_cli_requires_purpose(capsys, tmp_path):
    with pytest.raises(SystemExit) as exc:
        run_cli(["run", "--domain", "example.com", "--out", str(tmp_path / "o")])
    assert exc.value.code == 2
    assert not (tmp_path / "o").exists()          # nic nie powstało, zero zapytań


@pytest.mark.parametrize("purpose", ["", "test", "xx yy"])
def test_cli_rejects_weak_purpose_before_any_work(purpose, capsys, tmp_path, make_ctx):
    ctx = make_ctx()
    rc = run_cli(["run", "--purpose", purpose, "--domain", "example.com", "--out", str(tmp_path / "o")], ctx)
    assert rc == 2 and "--purpose" in capsys.readouterr().err
    assert not (tmp_path / "o").exists() and ctx.fetch.calls == []


def test_cli_requires_seed_and_valid_values(capsys, tmp_path, make_ctx):
    base = ["run", "--purpose", "audyt własnej firmy X", "--out", str(tmp_path / "o")]
    assert run_cli(base, make_ctx()) == 2
    assert run_cli(base + ["--ip", "999.1.1.1"], make_ctx()) == 2
    assert run_cli(base + ["--domain", "example.com", "--only", "nie_ma_takiej"], make_ctx()) == 2
    assert not (tmp_path / "o").exists()


def test_cli_end_to_end_writes_all_outputs(capsys, tmp_path, make_ctx):
    ctx = make_ctx(routes=ROUTES, handlers={"dns_audit": lambda cmd: (0, fx("dns_audit.json"), "")})
    out = tmp_path / "wyniki"
    rc = run_cli(["run", "--purpose", "audyt własnej infrastruktury firmy X", "--case-ref", "ZL-7", "--domain",
                  "example.com", "--operator", "ala", "--out", str(out)], ctx)
    assert rc == 0, capsys.readouterr().err
    for name in ("graph.json", "graph.graphml", "report.html", "audit.jsonl"):
        assert (out / name).is_file()
    g = Graph.load(out / "graph.json")
    assert g.meta["purpose"] == "audyt własnej infrastruktury firmy X" and g.meta["case_ref"] == "ZL-7"
    assert verify_audit(out / "audit.jsonl")[0]
    start = json.loads((out / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert start["operator"] == "ala" and start["inputs"] == [{"type": "domain", "value": "example.com"}]
    assert "HIBP_API_KEY" not in json.dumps(start) and start["options"]["hibp_key_present"] is False
    # drugi bieg do tego samego katalogu jest odrzucony (nie nadpisujemy wyników)
    assert run_cli(["run", "--purpose", "audyt własnej infrastruktury firmy X", "--domain", "example.com",
                    "--out", str(out)], make_ctx()) == 2


def test_cli_exit_code_1_when_any_transform_errors(capsys, tmp_path, make_ctx):
    ctx = make_ctx(routes=[("rdap", HttpResponse(None, error="timeout")), ("stat.ripe", HttpResponse(None, error="timeout")),
                           ("shodan", HttpResponse(None, error="timeout"))])
    ctx.rdns = lambda ip: (None, "timeout")
    rc = run_cli(["run", "--purpose", "audyt własnej firmy X", "--ip", "1.1.1.1", "--out", str(tmp_path / "o")], ctx)
    assert rc == 1
    g = Graph.load(tmp_path / "o" / "graph.json")
    assert all(r.status is not Status.NOT_FOUND for r in g.runs)    # błędy sieci nigdy nie są brakiem danych


def test_cli_audit_key_flag_recorded_without_value(tmp_path, make_ctx, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "bardzo-tajny-klucz")
    rc = run_cli(["run", "--purpose", "audyt własnej firmy X", "--email", "jan@gmail.com", "--offline",
                  "--out", str(tmp_path / "o")], make_ctx())
    assert rc == 0
    text = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "o").iterdir() if p.is_file())
    assert "bardzo-tajny-klucz" not in text and '"hibp_key_present": true' in text


def test_cli_export_and_transforms_and_verify(capsys, tmp_path, make_ctx):
    out = tmp_path / "o"
    run_cli(["run", "--purpose", "audyt własnej firmy X", "--person", "Jan Kowalski", "--out", str(out)], make_ctx())
    rc = run_cli(["export", str(out / "graph.json"), "--graphml", str(tmp_path / "x.graphml"),
                  "--html", str(tmp_path / "x.html")])
    assert rc == 0 and (tmp_path / "x.graphml").read_text(encoding="utf-8").startswith("<?xml")
    assert run_cli(["export", str(out / "graph.json")]) == 2
    assert run_cli(["export", str(tmp_path / "brak.json"), "--html", str(tmp_path / "y.html")]) == 2
    capsys.readouterr()
    assert run_cli(["transforms"]) == 0 and "phone_metadata" in capsys.readouterr().out
    assert run_cli(["audit-verify", str(out / "audit.jsonl")]) == 0
    (out / "audit.jsonl").write_text("{}\n", encoding="utf-8")
    assert run_cli(["audit-verify", str(out / "audit.jsonl")]) == 1
