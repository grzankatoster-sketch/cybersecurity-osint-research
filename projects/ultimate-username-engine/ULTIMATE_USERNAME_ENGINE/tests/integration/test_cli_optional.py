"""Opt-in OSINT features of the CLI (variants, dorks, wayback, geo); all offline."""

import json

import pytest

from ultimate_username import cli
from ultimate_username.cli import expand_variants, main


def analyst_documents(output):
    paths = sorted(output.parent.glob(output.stem + "*.analyst.json"))
    return [json.loads(p.read_text("utf-8")) for p in paths]


def run_demo(tmp_path, *args, name="wyniki"):
    output = tmp_path / (name + ".json")
    code = main(
        [
            "demo",
            *args,
            "--output",
            str(output),
            "--journal",
            str(tmp_path / (name + ".sqlite")),
        ]
    )
    return code, output


def test_expand_variants_typed_first_and_marks_source():
    names, source = expand_variants(["Alice"], 4)
    assert names[0] == "Alice" and len(names) == 4
    assert "alice" not in names and "Alice" not in source
    assert all(source[n] == "Alice" for n in names[1:])


def test_expand_variants_person_name_scans_only_variants():
    names, source = expand_variants(["Jan Kowalski"], 3)
    assert names == ("jankowalski", "jan.kowalski", "jan_kowalski")
    assert set(source) == set(names)


def test_expand_variants_explicit_inputs_are_not_variants_and_dedup():
    names, source = expand_variants(["alice", "alice_"], 3)
    assert names.count("alice_") == 1 and "alice_" not in source and "alice" not in source
    assert expand_variants(["!!!"], 3) == (("!!!",), {})


def test_variants_are_off_by_default(tmp_path):
    code, output = run_demo(tmp_path, "alice", "--site", "found")
    assert code == 0
    assert [r["username"]["raw"] for r in json.loads(output.read_text("utf-8"))] == ["alice"]
    assert "variants" not in analyst_documents(output)[0]


def test_cli_variants_scans_variants_and_labels_them(tmp_path):
    code, output = run_demo(
        tmp_path, "alice", "--site", "found", "--variants", "--max-variants", "3"
    )
    assert code == 0
    names = [r["username"]["raw"] for r in json.loads(output.read_text("utf-8"))]
    assert len(names) == 3 and names[0] == "alice"
    documents = {d["username"]: d for d in analyst_documents(output)}
    assert documents["alice"]["variants"] == {"is_variant": False, "variant_of": None}
    for name in names[1:]:
        assert documents[name]["variants"] == {"is_variant": True, "variant_of": "alice"}
        assert documents[name]["profiles"][0]["status"] == "FOUND"


@pytest.mark.parametrize("value", ["0", "-2"])
def test_cli_rejects_bad_max_variants_before_io(tmp_path, value):
    journal = tmp_path / "must-not-exist.sqlite"
    code = main(["demo", "alice", "--variants", "--max-variants", value, "--journal", str(journal)])
    assert code == 2 and not journal.exists()


# --- F5.2: dorks and Wayback -------------------------------------------------------------------


@pytest.fixture
def archive(monkeypatch):
    """Demo registry whose transport also answers Wayback CDX requests (no network)."""
    from ultimate_username.demo import make_demo
    from ultimate_username.domain.models import TransportResponse
    from ultimate_username.transport import FakeTransport

    registry, demo_transport = make_demo()
    state = {"cdx": [], "mode": "ok"}

    def handler(request, index):
        if not request.url.startswith("https://web.archive.org/cdx/"):
            return demo_transport.handler(request, index)
        state["cdx"].append(request.url)
        if state["mode"] == "error":
            return TransportResponse(request.url, 503, b"")
        rows = [
            ["timestamp", "original", "statuscode"],
            ["20200102030405", "https://found.example.test/alice", "200"],
            ["20180102030405", "https://found.example.test/alice", "200"],
        ]
        return TransportResponse(request.url, 200, json.dumps(rows).encode())

    def fresh():  # the engine closes its transport, so every CLI run needs a new one
        state["transport"] = FakeTransport(handler=handler)
        return registry, state["transport"]

    monkeypatch.setattr(cli, "make_demo", fresh)
    return state


def test_dorks_lists_queries_and_sends_nothing(tmp_path, archive):
    state = archive
    code, output = run_demo(tmp_path, "alice", "--site", "found", "--dorks")
    assert code == 0
    document = analyst_documents(output)[0]
    queries = document["dorks"]["queries"]
    assert queries[0] == '"alice"' and any("site:github.com" in q for q in queries)
    assert document["dorks"]["sent"] is False
    assert "wayback" not in document and state["cdx"] == []
    assert all(r.url.startswith("https://found.") for r in state["transport"].requests)


def test_dorks_with_variants_cover_the_group_once(tmp_path, archive):
    code, output = run_demo(
        tmp_path, "alice", "--site", "found", "--dorks", "--variants", "--max-variants", "3"
    )
    assert code == 0
    documents = {d["username"]: d for d in analyst_documents(output)}
    assert len(documents) == 3
    assert sum("dorks" in d for d in documents.values()) == 1
    first = documents["alice"]["dorks"]["queries"][0]
    assert first.startswith("(") and '"alice"' in first and " OR " in first


def test_wayback_off_by_default_and_on_with_flag(tmp_path, archive):
    state = archive
    code, output = run_demo(tmp_path, "alice", "--site", "found", name="off")
    assert code == 0 and state["cdx"] == []
    assert "wayback" not in analyst_documents(output)[0]
    code, output = run_demo(tmp_path, "alice", "--site", "found", "--wayback", name="on")
    assert code == 0 and len(state["cdx"]) == 1
    wayback = analyst_documents(output)[0]["wayback"]
    assert wayback["requests"] == 1 and wayback["budget"] == 20 and wayback["errors"] == 0
    entry = wayback["profiles"][0]
    assert entry["profile_url"] == "https://found.example.test/alice"
    assert entry["first_seen"] == "2018-01-02" and entry["last_seen"] == "2020-01-02"
    assert entry["snapshots"][0] == {
        "timestamp": "20180102030405",
        "original": "https://found.example.test/alice",
        "status": "200",
    }


def test_wayback_budget_is_total_for_run_and_zero_sends_nothing(tmp_path, archive):
    state = archive
    args = ("alice", "--site", "found", "--variants", "--max-variants", "3", "--wayback")
    code, output = run_demo(tmp_path, *args, "--wayback-budget", "2")
    assert code == 0 and len(state["cdx"]) == 2
    documents = analyst_documents(output)
    assert sorted(d["wayback"]["requests"] for d in documents) == [0, 1, 1]
    state["cdx"].clear()
    code, output = run_demo(tmp_path, *args, "--wayback-budget", "0", name="zero")
    assert code == 0 and state["cdx"] == []
    assert all(d["wayback"]["requests"] == 0 for d in analyst_documents(output))


def test_wayback_archive_errors_are_reported_not_hidden(tmp_path, archive):
    state = archive
    state["mode"] = "error"
    code, output = run_demo(tmp_path, "alice", "--site", "found", "--wayback")
    assert code == 0  # an archive failure does not change the search outcome
    wayback = analyst_documents(output)[0]["wayback"]
    assert wayback["errors"] == 1
    assert wayback["profiles"][0]["error"] == "HTTP 503"
    assert wayback["profiles"][0]["first_seen"] is None


def test_wayback_is_counted_separately_in_request_economy(tmp_path, archive, monkeypatch):
    from ultimate_username.demo import make_demo
    from ultimate_username.domain.codec import to_json

    registry, _ = make_demo()
    source = tmp_path / "registry.json"
    source.write_text(to_json(tuple(e.definition for e in registry.entries)), encoding="utf-8")
    monkeypatch.setattr(cli, "AiohttpTransport", lambda config: cli.make_demo()[1])
    output = tmp_path / "search.json"
    code = main(
        [
            "search",
            "alice",
            "--registry",
            str(source),
            "--site",
            "found",
            "--wayback",
            "--output",
            str(output),
            "--journal",
            str(tmp_path / "search.sqlite"),
        ]
    )
    assert code == 0
    document = analyst_documents(output)[0]
    economy = document["request_economy"]
    assert economy["wayback_requests"] == 1 == document["wayback"]["requests"]
    # archive lookups are not part of the search budget accounting
    search_requests = (
        sum(
            economy[k]
            for k in ("primary_requests", "fallback_requests", "retries", "enrichment_requests")
        )
        + economy["control_requests"]
    )
    assert economy["total_requests"] == search_requests
    assert economy["total_requests"] == archive["transport"].total - 1


def test_wayback_unknown_flag_includes_unknown_profiles(tmp_path, archive):
    state = archive
    run_demo(tmp_path, "alice", "--wayback", name="plain")
    plain = list(state["cdx"])
    state["cdx"].clear()
    run_demo(tmp_path, "alice", "--wayback", "--wayback-unknown", name="unk")
    assert len(plain) == 1 and len(state["cdx"]) > len(plain)


def test_cli_rejects_negative_wayback_budget_before_io(tmp_path):
    journal = tmp_path / "must-not-exist.sqlite"
    code = main(["demo", "alice", "--wayback-budget", "-1", "--journal", str(journal)])
    assert code == 2 and not journal.exists()


# --- F5.4: geo ------------------------------------------------------------------------------


@pytest.fixture
def located(monkeypatch):
    """Demo registry whose 'found' profiles carry a location."""
    from ultimate_username.demo import make_demo
    from ultimate_username.domain.models import TransportResponse
    from ultimate_username.transport import FakeTransport

    registry, demo_transport = make_demo()

    def handler(request, index):
        name = request.url.rsplit("/", 1)[-1]
        if request.url.startswith("https://found."):
            body = {"profile": True, "username": name, "display_name": "Jan", "bio": "hello"}
            body["location"] = "Kraków, Poland" if name == "alice" else "Berlin, Germany"
            return TransportResponse(request.url, 200, json.dumps(body).encode())
        return demo_transport.handler(request, index)

    monkeypatch.setattr(cli, "make_demo", lambda: (registry, FakeTransport(handler=handler)))


def test_geo_is_off_by_default(tmp_path, located):
    code, output = run_demo(tmp_path, "alice", "--site", "found")
    assert code == 0 and "geo" not in analyst_documents(output)[0]


def test_geo_adds_section_with_sources(tmp_path, located):
    code, output = run_demo(tmp_path, "alice", "--site", "found", "--geo")
    assert code == 0
    geo = analyst_documents(output)[0]["geo"]
    assert geo["profiles_considered"] == 1
    top = geo["countries"][0]
    assert top["country"] == "PL" and top["percent"] == 100 and top["strength"] == "medium"
    assert top["evidence"][0]["site"] == "Found" and top["evidence"][0]["field"] == "location"
    assert "not a fact" in geo["note"]


def test_geo_per_document_with_variants(tmp_path, located):
    code, output = run_demo(
        tmp_path, "alice", "--site", "found", "--geo", "--variants", "--max-variants", "2"
    )
    assert code == 0
    countries = {
        d["username"]: d["geo"]["countries"][0]["country"] for d in analyst_documents(output)
    }
    assert countries == {"alice": "PL", "alice_": "DE"}


def test_geo_gazetteer_option_and_bad_paths(tmp_path, located):
    extra = tmp_path / "geo.json"
    extra.write_text(json.dumps({"countries": {"poland": "DE"}}), encoding="utf-8")
    code, output = run_demo(
        tmp_path, "alice", "--site", "found", "--geo", "--geo-gazetteer", str(extra)
    )
    assert code == 0
    assert analyst_documents(output)[0]["geo"]["countries"][0]["country"] == "DE"
    journal = tmp_path / "must-not-exist.sqlite"
    for path in (tmp_path / "missing.json", tmp_path):
        code = main(
            ["demo", "alice", "--geo", "--geo-gazetteer", str(path), "--journal", str(journal)]
        )
        assert code == 2 and not journal.exists()
    extra.write_text("[1]", encoding="utf-8")
    assert (
        main(["demo", "a", "--geo", "--geo-gazetteer", str(extra), "--journal", str(journal)]) == 2
    )


# --- F5.5: HTML report ---------------------------------------------------------------------------


def test_search_html_flag_writes_self_contained_report(tmp_path):
    html_path = tmp_path / "raport.html"
    code, output = run_demo(
        tmp_path, "alice", "--site", "found", "--geo", "--dorks", "--html", str(html_path)
    )
    assert code == 0
    html = html_path.read_text("utf-8")
    assert html.startswith("<!doctype html>")
    for text in ("Raport: alice", "Found", "FOUND", "Pola profilu i ich źródła", "Geo (", "Dorki"):
        assert text in html, text
    assert "<script" not in html and "<link" not in html
    document = analyst_documents(output)[0]
    assert document["meta"]["selection"] == "quality"
    found = next(p for p in document["profiles"] if p["status"] == "FOUND")
    assert found["field_sources"]["display_name"]["extractor"]
    assert found["field_sources"]["display_name"]["quality"] in {
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNVERIFIED",
    }
    assert found["control"] is None and isinstance(found["evidence"], list)


def test_no_html_without_flag(tmp_path):
    code, _ = run_demo(tmp_path, "alice", "--site", "found")
    assert code == 0 and not list(tmp_path.glob("*.html"))


def test_search_html_with_variants_puts_all_names_in_one_report(tmp_path):
    html_path = tmp_path / "all.html"
    code, _ = run_demo(
        tmp_path,
        "alice",
        "--site",
        "found",
        "--variants",
        "--max-variants",
        "3",
        "--html",
        str(html_path),
    )
    assert code == 0 and html_path.read_text("utf-8").count("Nazwa:") == 3


def test_report_command_renders_existing_analyst_document(tmp_path):
    code, output = run_demo(tmp_path, "alice", "--site", "found", "--geo")
    assert code == 0
    analyst = next(tmp_path.glob("*.analyst.json"))
    target = tmp_path / "from-json.html"
    assert main(["report", str(analyst), "--html", str(target)]) == 0
    html = target.read_text("utf-8")
    assert "Raport: alice" in html and "Geo (" in html
    assert main(["report", str(analyst)]) == 0
    assert analyst.with_suffix(".html").exists()


def test_report_command_rejects_non_analyst_input(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert main(["report", str(bad), "--html", str(tmp_path / "o.html")]) == 2
    bad.write_text("{not json", encoding="utf-8")
    assert main(["report", str(bad), "--html", str(tmp_path / "o.html")]) == 2
    assert main(["report", str(tmp_path / "missing.json")]) == 2
    assert not (tmp_path / "o.html").exists()
