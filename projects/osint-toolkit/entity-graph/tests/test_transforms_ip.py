import json

from conftest import FakeFetch, fx, ok
from entity_graph.http import HttpResponse
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY
from entity_graph.transforms.ip import (default_rdns, parse_internetdb, parse_rdap_ip, parse_ripestat)

IP = lambda v="1.1.1.1": Node.make(T.IP, v)  # noqa: E731


def run(name, node, ctx):
    return REGISTRY[name].run(node, ctx)


def test_parse_rdap_skips_individuals():
    p = parse_rdap_ip(json.loads(fx("rdap_ip.json")))
    assert p["country"] == "AU" and p["cidrs"] == ["1.1.1.0/24"] and p["registered"].startswith("2011")
    assert [o for o, _ in p["orgs"]] == ["APNIC Research and Development"]   # osoba fizyczna pominięta
    assert "Jan Prywatny" not in json.dumps(p) and "jan@example.org" not in json.dumps(p)


def test_ip_rdap_found(make_ctx):
    ctx = make_ctx(routes=[("rdap.org/ip/1.1.1.1", ok(fx("rdap_ip.json")))])
    r = run("ip_rdap", IP(), ctx)
    assert r.status is Status.FOUND
    assert r.node_attrs["rdap_country"] == "AU" and r.node_attrs["rdap_cidrs"] == ["1.1.1.0/24"]
    assert r.nodes[0].type is T.ORGANIZATION and r.edges[0].relation == "allocated_to"
    assert 0 < r.edges[0].confidence <= 1 and r.edges[0].evidence
    technical = parse_rdap_ip({"entities": [{"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "NOC Org"], ["kind", {}, "text", "org"]]]}]})
    assert technical["orgs"] == [("NOC Org", ["technical"])]


def test_ip_rdap_falls_back_to_ripe_on_error_only(make_ctx):
    ctx = make_ctx(routes=[("rdap.org/", HttpResponse(503)), ("rdap.db.ripe.net/ip/1.1.1.1", ok(fx("rdap_ip.json")))])
    assert run("ip_rdap", IP(), ctx).status is Status.FOUND
    ctx = make_ctx(routes=[("rdap.org/", HttpResponse(404))])
    assert run("ip_rdap", IP(), ctx).status is Status.NOT_FOUND     # 404 jest odpowiedzią: bez zapasu
    assert len(ctx.fetch.calls) == 1


def test_ip_rdap_errors_never_become_not_found(make_ctx):
    for resp in (HttpResponse(None, error="timeout"), HttpResponse(429), HttpResponse(500), ok("<html>nie json</html>")):
        ctx = make_ctx(routes=[("rdap", resp)])
        r = run("ip_rdap", IP(), ctx)
        assert r.status is Status.ERROR and r.error, resp


def test_private_ip_is_unknown_and_sends_nothing(make_ctx):
    ctx = make_ctx()
    for name in ("ip_rdap", "ip_asn", "ip_rdns", "ip_internetdb"):
        assert run(name, IP("192.168.1.10"), ctx).status is Status.UNKNOWN
    assert ctx.fetch.calls == []


def test_ripestat_parse_and_found(make_ctx):
    p = parse_ripestat(json.loads(fx("ripestat.json")))
    assert p["asns"] == [("AS13335", "CLOUDFLARENET - Cloudflare, Inc.")] and p["prefix"] == "1.1.1.0/24"
    ctx = make_ctx(routes=[("stat.ripe.net", ok(fx("ripestat.json")))])
    r = run("ip_asn", IP(), ctx)
    assert r.status is Status.FOUND and r.node_attrs["asn"] == ["AS13335"] and r.node_attrs["bgp_prefix"] == "1.1.1.0/24"
    assert r.nodes[0].attrs["asn"] == ["AS13335"] and r.edges[0].relation == "announced_by"
    assert "resource=1.1.1.1" in ctx.fetch.calls[0][0]


def test_ripestat_unannounced_is_not_found_and_bad_status_is_error(make_ctx):
    ctx = make_ctx(routes=[("stat.ripe.net", ok(fx("ripestat_unannounced.json")))])
    assert run("ip_asn", IP("8.8.4.4"), ctx).status is Status.NOT_FOUND
    ctx = make_ctx(routes=[("stat.ripe.net", ok('{"status":"error","data":{}}'))])
    assert run("ip_asn", IP(), ctx).status is Status.ERROR


def test_rdns(make_ctx):
    ctx = make_ctx()
    ctx.rdns = lambda ip: ("one.one.one.one", None)
    r = run("ip_rdns", IP(), ctx)
    assert r.status is Status.FOUND and r.nodes[0].key == "one.one.one.one" and r.node_attrs["ptr"] == "one.one.one.one"
    ctx.rdns = lambda ip: (None, None)
    assert run("ip_rdns", IP(), ctx).status is Status.NOT_FOUND
    ctx.rdns = lambda ip: (None, "timeout")
    assert run("ip_rdns", IP(), ctx).status is Status.ERROR
    ctx.rdns = lambda ip: ("nie wolno_tak", None)
    assert run("ip_rdns", IP(), ctx).status is Status.ERROR


def test_default_rdns_maps_socket_errors(monkeypatch):
    import socket

    def raising(exc):
        def f(ip):
            raise exc
        return f

    monkeypatch.setattr(socket, "gethostbyaddr", raising(socket.herror(1, "Unknown host")))
    assert default_rdns("1.1.1.1") == (None, None)                      # jawny brak PTR
    monkeypatch.setattr(socket, "gethostbyaddr", raising(socket.herror(2, "try again")))
    assert default_rdns("1.1.1.1")[1]                                    # błąd, nie brak
    monkeypatch.setattr(socket, "gethostbyaddr", raising(socket.gaierror(-3, "x")))
    assert default_rdns("1.1.1.1")[1]
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("h.example.com", [], [ip]))
    assert default_rdns("1.1.1.1") == ("h.example.com", None)


def test_internetdb(make_ctx):
    p = parse_internetdb(json.loads(fx("internetdb.json")))
    assert p["ports"] == [53, 80, 443] and p["cpes"] and p["vulns"] == ["CVE-2021-0001"]
    ctx = make_ctx(routes=[("internetdb.shodan.io/1.1.1.1", ok(fx("internetdb.json")))])
    r = run("ip_internetdb", IP(), ctx)
    assert r.status is Status.FOUND
    assert r.node_attrs["open_ports"] == [53, 80, 443] and r.node_attrs["vulns_unverified"] == ["CVE-2021-0001"]
    assert [n.key for n in r.nodes] == ["one.one.one.one"]          # nazwa z '<' odrzucona przez normalizację
    assert r.edges[0].confidence == 0.7


def test_internetdb_404_and_errors(make_ctx):
    ctx = make_ctx(routes=[("internetdb", HttpResponse(404, '{"detail":"No information available"}'))])
    r = run("ip_internetdb", IP(), ctx)
    assert r.status is Status.NOT_FOUND and "nie dowód" in r.note
    for resp in (HttpResponse(None, error="timeout"), HttpResponse(429), ok("[]"), ok("nie json")):
        ctx = make_ctx(routes=[("internetdb", resp)])
        assert run("ip_internetdb", IP(), ctx).status is Status.ERROR


def test_ip_rdap_contact_roles_get_weaker_relation(make_ctx):
    data = json.loads(fx("rdap_ip.json"))
    data["entities"][0]["roles"] = ["technical"]
    r = run("ip_rdap", IP(), make_ctx(routes=[("rdap.org/ip/", ok(json.dumps(data)))]))
    assert r.edges[0].relation == "contact_org" and r.edges[0].confidence == 0.6
