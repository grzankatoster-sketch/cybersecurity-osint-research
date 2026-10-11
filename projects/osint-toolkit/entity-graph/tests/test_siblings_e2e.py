"""Podprocesy narzędzi siostrzanych i test end-to-end na lokalnym serwerze 127.0.0.1 (prawdziwy HttpClient)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from conftest import fx
from entity_graph import siblings
from entity_graph.engine import Options, investigate, new_graph
from entity_graph.guardrails import AuditLog
from entity_graph.http import HttpClient
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import Context, Settings

REAL_ROOT = siblings.tools_root()


def test_scrubbed_env_removes_secrets():
    env = siblings.scrubbed_env({"PATH": "x", "HIBP_API_KEY": "k", "GITHUB_TOKEN": "t", "DB_PASSWORD": "p",
                                 "MY_SECRET": "s", "HOME": "h"})
    assert set(env) == {"PATH", "HOME", "PYTHONUTF8", "PYTHONIOENCODING"}


def test_build_command_uses_sibling_venv_and_src(tools_dir):
    (tools_dir / "phone-check" / ".venv" / "Scripts").mkdir(parents=True)
    (tools_dir / "phone-check" / ".venv" / "Scripts" / "python.exe").write_text("", encoding="utf-8")
    cmd, env, cwd = siblings.build_command("phone-check", ["--x"], tools_dir)
    assert cmd[0].endswith("python.exe") and cmd[1:] == ["-m", "phone_check", "--x"]
    assert env["PYTHONPATH"].endswith("src") and cwd == tools_dir / "phone-check"
    cmd, _, _ = siblings.build_command("dns-audit", [], tools_dir)
    assert cmd[0]                                           # bez .venv: bieżący interpreter


def test_missing_sibling_is_reported(tmp_path):
    with pytest.raises(siblings.SiblingUnavailable):
        siblings.build_command("dns-audit", [], tmp_path)
    with pytest.raises(siblings.SiblingUnavailable):
        siblings.build_command("nieznane", [], tmp_path)


def test_tools_root_env_override(tmp_path):
    assert siblings.tools_root({"ENTITY_GRAPH_TOOLS_DIR": str(tmp_path)}) == tmp_path


@pytest.mark.skipif(not (REAL_ROOT / "phone-check" / ".venv").exists(), reason="brak .venv phone-check")
def test_real_phone_check_subprocess_offline(tmp_path):
    """Prawdziwe wywołanie siostrzanego phone-check (offline, bez sieci)."""
    ctx = Context(fetch=None, tools_dir=REAL_ROOT, settings=Settings(sibling_timeout=60), tmp_dir=tmp_path)
    from entity_graph.transforms import REGISTRY
    r = REGISTRY["phone_metadata"].run(Node.make(T.PHONE, "603 123 456"), ctx)
    assert r.status is Status.FOUND and r.node_attrs["phone_country_name"] and r.node_attrs["phone_e164"] == "+48603123456"


# ------------------------------------------------------------------ lokalny serwer jako wszystkie źródła

class Api(BaseHTTPRequestHandler):
    seen: list[str] = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Api.seen.append(self.path)
        routes = {
            "/rdap-ip/": fx("rdap_ip.json"), "/ripestat": fx("ripestat.json"),
            "/internetdb/": json.dumps({"ip": "8.8.8.8", "ports": [53], "cpes": [], "hostnames": [], "tags": [], "vulns": []}),
        }
        for prefix, body in routes.items():
            if self.path.startswith(prefix):
                data = body.encode("utf-8")
                self.send_response(200)
                break
        else:
            data = b'{"detail":"x"}'
            self.send_response(404 if self.path.startswith("/rdap-ip-ripe") else 503)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def test_ip_investigation_over_real_http_to_localhost(tmp_path):
    Api.seen = []
    srv = HTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        ctx = Context(
            fetch=HttpClient(timeout=3, min_interval=0, sleep=lambda s: None), rdns=lambda ip: ("dns.google", None),
            endpoints={"rdap_ip": base + "/rdap-ip/", "rdap_ip_ripe": base + "/rdap-ip-ripe/",
                       "ripestat": base + "/ripestat", "internetdb": base + "/internetdb/"},
            settings=Settings(), env={}, tmp_dir=tmp_path)
        audit = AuditLog(tmp_path / "a.jsonl", "ala")
        audit.start("audyt własnej firmy X", [], {})
        g = new_graph("audyt własnej firmy X", "ala", "", [], {}, "x")
        investigate(g, [Node.make(T.IP, "8.8.8.8")], ctx, audit, Options())
    finally:
        srv.shutdown()
    by = {r.transform: r.status for r in g.runs}
    assert by == {"ip_rdap": Status.FOUND, "ip_asn": Status.FOUND, "ip_rdns": Status.FOUND, "ip_internetdb": Status.FOUND}
    node = g.nodes["ip:8.8.8.8"]
    assert node.attrs["rdap_country"] == "AU" and node.attrs["open_ports"] == [53] and node.attrs["ptr"] == "dns.google"
    assert {n.type for n in g.nodes.values()} == {T.IP, T.ORGANIZATION, T.DOMAIN}
    assert any(p.startswith("/ripestat?resource=8.8.8.8") for p in Api.seen)
    assert all(e.evidence and 0 <= e.confidence <= 1 and e.timestamp for e in g.edges.values())
