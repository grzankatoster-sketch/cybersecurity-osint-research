import json
from pathlib import Path

import pytest

from conftest import fx, writes_json_to_flag
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY
from entity_graph.transforms.person import dork_links, generate_usernames, name_tokens
from entity_graph.transforms.username import aggregate_status, parse_scan


def run(name, node, ctx):
    return REGISTRY[name].run(node, ctx)


# ------------------------------------------------------------------ osoba

def test_polish_diacritics_folded():
    assert name_tokens("Łukasz Żółć-Nowak") == ["lukasz", "zolc", "nowak"]
    names = [n for n, _ in generate_usernames("Łukasz Żółć", 50)]
    assert "lukasz.zolc" in names and "lzolc" in names and "zolc_lukasz" in names and "lukaszz" in names
    assert all(n.isascii() for n in names)


def test_candidates_capped_unique_and_ordered():
    names = [n for n, _ in generate_usernames("Jan Kowalski", 5)]
    assert names == ["jankowalski", "jan.kowalski", "jan_kowalski", "jan-kowalski", "jkowalski"]
    full = [n for n, _ in generate_usernames("Jan Kowalski", 100)]
    assert len(full) == len(set(full)) and len(full) <= 25
    assert generate_usernames("Jan Kowalski", 0) == [] and generate_usernames("Jan", 5) == []
    assert all(len(n) >= 2 for n in full)


def test_person_transform(make_ctx):
    ctx = make_ctx(max_usernames=4)
    r = run("person_candidates", Node.make(T.PERSON, "Jan Kowalski"), ctx)
    assert r.status is Status.FOUND and len(r.nodes) == 4 and all(n.attrs["candidate"] for n in r.nodes)
    assert all(e.confidence == 0.0 and "HIPOTEZA" in e.evidence for e in r.edges)    # kandydat to nie dowód
    assert ctx.fetch.calls == []                                                      # zero zapytań sieciowych
    links = r.node_attrs["manual_review_links"]
    assert links and all(l["url"].startswith("https://") for l in links)
    assert {l["engine"] for l in links} == {"google", "bing", "duckduckgo"}


def test_person_single_token_unknown(make_ctx):
    assert run("person_candidates", Node.make(T.PERSON, "Kowalski"), make_ctx()).status is Status.UNKNOWN


def test_dork_links_encode_and_add_ascii_variant():
    links = dork_links('Łukasz "Żółć"')
    assert all(" " not in l["url"] and '"' not in l["url"] for l in links)
    assert any("lukasz+zolc" in l["url"] for l in links)             # wariant bez polskich znaków
    assert any("site%3Alinkedin.com%2Fin" in l["url"] for l in links)


# ------------------------------------------------------------------ telefon

def test_phone_metadata_only(make_ctx):
    ctx = make_ctx(handlers={"phone_check": writes_json_to_flag(fx("phone_check.json"), rc=0)})
    r = run("phone_metadata", Node.make(T.PHONE, "603 123 456"), ctx)
    assert r.status is Status.FOUND and r.node_attrs["phone_line_type"] == "komórkowy"
    assert r.node_attrs["phone_country_name"] == "Polska" and "przeniesiony" in r.node_attrs["phone_carrier_note"]
    assert r.nodes == [] and r.edges == [] and ctx.fetch.calls == []     # żadnych powiązań z osobą, zero sieci
    cmd = ctx.runner.calls[0]["cmd"]
    assert cmd[-2:] == ["--", "+48603123456"] and "--region" in cmd


def test_phone_invalid_and_errors(make_ctx):
    ctx = make_ctx(handlers={"phone_check": writes_json_to_flag(fx("phone_check_invalid.json"), rc=1)})
    r = run("phone_metadata", Node.make(T.PHONE, "+4812345678"), ctx)
    assert r.status is Status.NOT_FOUND and "niepoprawny" in r.note
    ctx = make_ctx(handlers={"phone_check": lambda cmd: (2, "", "Błąd użycia")})
    assert run("phone_metadata", Node.make(T.PHONE, "+48603123456"), ctx).status is Status.ERROR
    ctx = make_ctx(handlers={"phone_check": writes_json_to_flag("nie json")})
    assert run("phone_metadata", Node.make(T.PHONE, "+48603123456"), ctx).status is Status.ERROR


def test_phone_canonical_when_e164_differs(make_ctx):
    payload = json.loads(fx("phone_check.json"))
    payload[0]["e164"] = "+48603123499"
    ctx = make_ctx(handlers={"phone_check": writes_json_to_flag(json.dumps(payload))})
    r = run("phone_metadata", Node.make(T.PHONE, "+48603123456"), ctx)
    assert r.canonical is not None and r.canonical.key == "+48603123499"


def test_no_caller_id_or_phone_to_person_transforms():
    """Wykluczenie z README: żadna transformacja nie przyjmuje telefonu poza metadanymi i nie produkuje osób."""
    phone_transforms = [t for t in REGISTRY.values() if T.PHONE in t.inputs]
    assert [t.name for t in phone_transforms] == ["phone_metadata"]
    assert not phone_transforms[0].network
    banned = ("callapp", "truecaller", "sync", "caller", "reverse_phone", "numlookup")
    assert not [n for n in REGISTRY if any(b in n for b in banned)]
    src = "".join(p.read_text(encoding="utf-8").lower() for p in Path(__file__).parents[1].joinpath("src").rglob("*.py"))
    for host in ("api.truecaller", "callapp.com/", "api.sync.me", "getcontact"):
        assert host not in src


# ------------------------------------------------------------------ username-engine

def test_parse_scan_filters_by_confidence():
    hits, counts = parse_scan(json.loads(fx("ue_scan.json")), 0.6)
    assert [h["site"] for h in hits] == ["GitHub", "Twitter"]
    assert counts["FOUND"] == 3 and counts["NOT_FOUND"] == 1 and counts["ERROR"] == 1
    with pytest.raises(ValueError):
        parse_scan({"nie": "to"}, 0.6)


def test_aggregate_status_errors_are_not_not_found():
    assert aggregate_status([], {"ERROR": 3, "NOT_FOUND": 100})[0] is Status.UNKNOWN
    assert aggregate_status([], {"NOT_FOUND": 100, "UNSUPPORTED": 2})[0] is Status.NOT_FOUND
    assert aggregate_status([], {})[0] is Status.UNKNOWN
    assert aggregate_status([{"x": 1}], {"ERROR": 9})[0] is Status.FOUND


def test_username_scan_builds_profiles(make_ctx):
    ctx = make_ctx(handlers={"username_engine": writes_json_to_flag(fx("ue_scan.json"))}, ue_tags="social", ue_limit=50)
    r = run("username_scan", Node.make(T.USERNAME, "JKowalski"), ctx)
    assert r.status is Status.FOUND and [n.attrs["site"] for n in r.nodes] == ["GitHub", "Twitter"]
    gh = r.nodes[0]
    assert gh.attrs["display_name"] == "Jan Kowalski" and gh.attrs["avatar_hash"].startswith("u-")
    assert gh.attrs["links"] == ["https://x.com/jkowalski"]            # utm i śmieci odfiltrowane, twitter->x
    assert "bio" not in gh.attrs and "location" not in gh.attrs and "Kraków" not in json.dumps(gh.attrs)
    assert [e.confidence for e in r.edges] == [0.97, 0.9] and all("nie dowodzi" in e.evidence for e in r.edges)
    cmd = ctx.runner.calls[0]["cmd"]
    assert cmd[-2:] == ["--", "JKowalski"] and "--no-variants" in cmd and cmd[cmd.index("--tags") + 1] == "social"
    assert cmd[cmd.index("--limit") + 1] == "50"


def test_username_option_like_name_is_not_flag(make_ctx):
    ctx = make_ctx(handlers={"username_engine": writes_json_to_flag(fx("ue_scan_clean.json"))})
    run("username_scan", Node.make(T.USERNAME, "--json"), ctx)
    cmd = ctx.runner.calls[0]["cmd"]
    assert cmd[-2:] == ["--", "--json"]


def test_username_scan_statuses(make_ctx):
    def go(payload, rc=0):
        ctx = make_ctx(handlers={"username_engine": writes_json_to_flag(payload, rc)})
        return run("username_scan", Node.make(T.USERNAME, "x"), ctx)
    assert go(fx("ue_scan_only_errors.json")).status is Status.UNKNOWN
    assert go(fx("ue_scan_clean.json")).status is Status.NOT_FOUND
    assert go("nie json").status is Status.ERROR
    assert go(fx("ue_scan.json"), rc=2).status is Status.ERROR
    ctx = make_ctx(handlers={"username_engine": lambda cmd: (2, "", "brak bazy")})
    r = run("username_scan", Node.make(T.USERNAME, "x"), ctx)
    assert r.status is Status.ERROR and "brak bazy" in r.error


def test_username_scan_timeout_is_error(make_ctx):
    def boom(cmd):
        raise TimeoutError("limit")
    assert run("username_scan", Node.make(T.USERNAME, "x"), make_ctx(handlers={"username_engine": boom})).status is Status.ERROR


def test_url_host(make_ctx):
    r = run("url_host", Node.make(T.URL, "https://blog.example.com/a"), make_ctx())
    assert r.nodes[0].id == "domain:blog.example.com"
    r = run("url_host", Node.make(T.URL, "http://8.8.8.8/x"), make_ctx())
    assert r.nodes[0].id == "ip:8.8.8.8"


def test_username_scan_passes_bare_json_name_and_results_dir(make_ctx):
    """username-engine przyjmuje w --json tylko nazwę pliku (bez katalogu): pełna ścieżka dawała kod 2 w prawdziwym
    przebiegu, czego atrapa nie wykrywała."""
    from entity_graph.transforms import REGISTRY
    payload = json.dumps({"results": {"jan": [{"site": "A", "url": "https://a.example/jan", "status": "FOUND",
                                               "confidence": 0.9}]}})
    ctx = make_ctx(handlers={"username_engine": writes_json_to_flag(payload)})
    res = REGISTRY["username_scan"].run(Node.make(T.USERNAME, "jan"), ctx)
    cmd = ctx.runner.calls[0]["cmd"]
    assert cmd[cmd.index("--json") + 1] == "scan.json" and "--results-dir" in cmd
    assert res.status is Status.FOUND and len(res.nodes) == 1
