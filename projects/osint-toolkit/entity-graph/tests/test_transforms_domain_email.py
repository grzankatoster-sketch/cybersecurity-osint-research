import json
from types import SimpleNamespace

import pytest

from conftest import FakeRunner, fx, ok, writes_json_to_flag
from entity_graph.http import HttpResponse
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.siblings import SiblingUnavailable
from entity_graph.transforms import REGISTRY
from entity_graph.transforms.domain import parse_crtsh, parse_dns_audit, parse_rdap_domain
from entity_graph.transforms.email import gravatar_hashes

DOM = lambda v="example.com": Node.make(T.DOMAIN, v)  # noqa: E731
EML = lambda v="jan@example.com": Node.make(T.EMAIL, v)  # noqa: E731


def run(name, node, ctx):
    return REGISTRY[name].run(node, ctx)


def dns_runner(stdout="", rc=0, stderr=""):
    return {"dns_audit": lambda cmd: (rc, stdout, stderr)}


# ------------------------------------------------------------------ dns_audit

def test_parse_dns_audit():
    p = parse_dns_audit(json.loads(fx("dns_audit.json")))
    assert p["a"] == ["93.184.216.34"] and p["ns"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert p["mx"] == ["mail.example.com"] and p["has_data"]
    assert p["attrs"]["dmarc_policy"] == "reject" and p["attrs"]["spf_all"] == "-all" and p["attrs"]["dnssec_signed"] is True
    assert parse_dns_audit({"nie": "raport"}) is None


def test_dns_audit_found(make_ctx):
    ctx = make_ctx(handlers=dns_runner(fx("dns_audit.json")))
    r = run("dns_audit", DOM(), ctx)
    assert r.status is Status.FOUND
    kinds = {(e.relation, next(n.key for n in r.nodes if n.id == e.dst)) for e in r.edges}
    assert ("resolves_to", "93.184.216.34") in kinds and ("nameserver", "a.iana-servers.net") in kinds
    assert ("mail_exchanger", "mail.example.com") in kinds
    call = ctx.runner.calls[0]
    assert call["module"] == "dns_audit" and "--json" in call["cmd"] and "example.com" in call["cmd"]


def test_dns_audit_not_found_vs_error(make_ctx):
    assert run("dns_audit", DOM(), make_ctx(handlers=dns_runner(fx("dns_audit_empty.json")))).status is Status.NOT_FOUND
    r = run("dns_audit", DOM(), make_ctx(handlers=dns_runner(fx("dns_audit_failed.json"))))
    assert r.status is Status.ERROR and "żadne zapytanie" in r.error    # błędy zapytań != brak rekordów
    assert run("dns_audit", DOM(), make_ctx(handlers=dns_runner("nie json"))).status is Status.ERROR
    assert run("dns_audit", DOM(), make_ctx(handlers=dns_runner("", rc=2, stderr="Błąd"))).status is Status.ERROR


def test_dns_audit_partial_data_keeps_warning(make_ctx):
    data = json.loads(fx("dns_audit.json"))
    data["summary"]["failed"] = {"caa": "timeout"}
    r = run("dns_audit", DOM(), make_ctx(handlers=dns_runner(json.dumps(data))))
    assert r.status is Status.FOUND and "caa" in r.note


def test_dns_audit_timeout_and_unavailable(make_ctx, tmp_path):
    def boom(cmd):
        raise TimeoutError("limit czasu")
    assert run("dns_audit", DOM(), make_ctx(handlers={"dns_audit": boom})).status is Status.ERROR
    ctx = make_ctx()
    ctx.tools_dir = tmp_path / "nie-ma"
    assert run("dns_audit", DOM(), ctx).status is Status.UNKNOWN


def test_subprocess_env_has_no_secrets(make_ctx, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "sekret-123")
    monkeypatch.setenv("MY_TOKEN", "t")
    ctx = make_ctx(handlers=dns_runner(fx("dns_audit.json")))
    run("dns_audit", DOM(), ctx)
    env = ctx.runner.calls[0]["env"]
    assert "HIBP_API_KEY" not in env and "MY_TOKEN" not in env and env["PYTHONUTF8"] == "1"
    assert "sekret-123" not in json.dumps({k: v for k, v in env.items()})


# ------------------------------------------------------------------ RDAP domeny

def test_rdap_domain_skips_registrant(make_ctx):
    p = parse_rdap_domain(json.loads(fx("rdap_domain.json")))
    assert p["registrar"] == "RESERVED-Internet Assigned Numbers Authority" and p["expires"].startswith("2026")
    ctx = make_ctx(routes=[("rdap.org/domain/example.com", ok(fx("rdap_domain.json")))])
    r = run("domain_rdap", DOM(), ctx)
    assert r.status is Status.FOUND and r.edges[0].relation == "registered_via"
    assert "Jan Rejestrant" not in json.dumps([n.to_dict() for n in r.nodes]) + json.dumps(r.node_attrs)


def test_rdap_domain_404_is_unknown_not_not_found(make_ctx):
    r = run("domain_rdap", DOM(), make_ctx(routes=[("rdap", HttpResponse(404))]))
    assert r.status is Status.UNKNOWN and "serwera RDAP" in r.note
    for resp in (HttpResponse(None, error="timeout"), HttpResponse(429), ok("[]")):
        assert run("domain_rdap", DOM(), make_ctx(routes=[("rdap", resp)])).status is Status.ERROR


# ------------------------------------------------------------------ crt.sh

def test_parse_crtsh_filters_and_dedupes():
    subs = parse_crtsh(json.loads(fx("crtsh.json")), "example.com")
    assert sorted(subs) == ["dev.example.com", "mail.example.com", "www.example.com"]   # bez apex, e-maila, obcych domen
    assert subs["www.example.com"]["id"] == 333                                           # najwcześniejszy certyfikat


def test_crtsh_transform_and_cap(make_ctx):
    ctx = make_ctx(routes=[("crt.sh/", ok(fx("crtsh.json")))], max_subdomains=2)
    r = run("domain_crtsh", DOM(), ctx)
    assert r.status is Status.FOUND and len(r.nodes) == 2 and "ucięto" in r.note
    assert r.stats == {"subdomains": 3, "kept": 2}
    assert "q=%25.example.com" in ctx.fetch.calls[0][0]
    assert all(e.relation == "has_subdomain" and "nie dowodzi" in e.evidence for e in r.edges)


def test_crtsh_empty_and_failures(make_ctx):
    assert run("domain_crtsh", DOM(), make_ctx(routes=[("crt.sh", ok("[]"))])).status is Status.NOT_FOUND
    for resp in (HttpResponse(502), HttpResponse(None, error="timeout"), ok("<html>przeciążony</html>"),
                 HttpResponse(404)):
        assert run("domain_crtsh", DOM(), make_ctx(routes=[("crt.sh", resp)])).status is Status.ERROR


# ------------------------------------------------------------------ e-mail

def test_email_domain_generic_provider_flag(make_ctx):
    ctx = make_ctx()
    r = run("email_domain", EML("jan@Gmail.com"), ctx)
    assert r.nodes[0].key == "gmail.com" and r.nodes[0].attrs["generic_mail_provider"] is True
    r = run("email_domain", EML(), ctx)
    assert r.nodes[0].key == "example.com" and "generic_mail_provider" not in r.nodes[0].attrs
    assert r.edges[0].relation == "mailbox_at" and r.edges[0].confidence == 1.0


def test_gravatar(make_ctx):
    h = gravatar_hashes("Jan@Example.com ")
    assert len(h["sha256"]) == 64 and len(h["md5"]) == 32 and h == gravatar_hashes("jan@example.com")
    ctx = make_ctx(routes=[("gravatar.com/avatar/", ok("GIF89a", 200))])
    r = run("email_gravatar", EML(), ctx)
    assert r.status is Status.FOUND and r.nodes[0].attrs["avatar_hash"] == h["sha256"]
    assert "d=404" in ctx.fetch.calls[0][0]
    assert run("email_gravatar", EML(), make_ctx(routes=[("gravatar", HttpResponse(404))])).status is Status.NOT_FOUND
    for resp in (HttpResponse(None, error="timeout"), HttpResponse(429)):
        assert run("email_gravatar", EML(), make_ctx(routes=[("gravatar", resp)])).status is Status.ERROR


class FakeHibp:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def get(self, url, headers=None):
        self.calls.append((url, dict(headers or {})))
        if self.exc:
            raise self.exc
        return self.resp


@pytest.fixture
def real_tools_dir():
    from entity_graph.siblings import tools_root
    root = tools_root()
    if not (root / "hibp-monitor" / "src" / "hibp_monitor").is_dir():
        pytest.skip("brak hibp-monitor obok entity-graph")
    return root


def hibp_ctx(make_ctx, real_tools_dir, client, key="sekret-klucz"):
    ctx = make_ctx(env={"HIBP_API_KEY": key} if key else {})
    ctx.tools_dir = real_tools_dir
    ctx.hibp_client_factory = lambda: client
    return ctx


def test_hibp_requires_user_key(make_ctx, real_tools_dir):
    client = FakeHibp(SimpleNamespace(status=200, text="[]", headers={}))
    r = run("email_hibp", EML(), hibp_ctx(make_ctx, real_tools_dir, client, key=""))
    assert r.status is Status.UNKNOWN and "HIBP_API_KEY" in r.note and client.calls == []


def test_hibp_found_and_key_not_leaked(make_ctx, real_tools_dir):
    client = FakeHibp(SimpleNamespace(status=200, text=fx("hibp_breaches.json"), headers={}))
    r = run("email_hibp", EML(), hibp_ctx(make_ctx, real_tools_dir, client))
    assert r.status is Status.FOUND and len(r.nodes) == 2 and r.node_attrs["hibp_breach_count"] == 2
    url, headers = client.calls[0]
    assert "breachedaccount/jan%40example.com" in url and headers["hibp-api-key"] == "sekret-klucz"
    blob = json.dumps([n.to_dict() for n in r.nodes] + [e.to_dict() for e in r.edges]) + r.note + r.error + json.dumps(r.node_attrs)
    assert "sekret-klucz" not in blob


@pytest.mark.parametrize("status,expected", [(404, Status.NOT_FOUND), (401, Status.ERROR), (403, Status.ERROR),
                                             (500, Status.ERROR)])
def test_hibp_status_mapping(make_ctx, real_tools_dir, status, expected):
    client = FakeHibp(SimpleNamespace(status=status, text="", headers={}))
    r = run("email_hibp", EML(), hibp_ctx(make_ctx, real_tools_dir, client))
    assert r.status is expected and "sekret-klucz" not in r.error + r.note


def test_hibp_client_error_is_error(make_ctx, real_tools_dir):
    from entity_graph import siblings
    siblings.import_sibling("hibp-monitor", real_tools_dir)
    from hibp_monitor.http import HibpError
    r = run("email_hibp", EML(), hibp_ctx(make_ctx, real_tools_dir, FakeHibp(exc=HibpError("Błąd sieci: timeout"))))
    assert r.status is Status.ERROR
