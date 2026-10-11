"""Import wyników meta-search: pochodzenie na węzłach, brak wyniku != brak konta, błędy bez węzłów."""
import json

from entity_graph.importers import import_files
from entity_graph.model import Graph, Node
from entity_graph.normalize import EntityType as T

NOW = "2026-10-03T12:00:00+00:00"


def doc(status="found", items=None, op="threads_profile", kind="api"):
    return {"tool": "meta-search", "schema": 1, "platform": "threads", "operation": op, "query": "meta",
            "status": status, "status_label": status, "message": "m", "fetched_at": "2026-10-03T10:00:00+00:00",
            "source": {"kind": kind, "endpoint": "https://graph.threads.net/v1.0/profile_lookup", "api_version": "v1.0"},
            "items": items or []}


def run(tmp_path, data):
    f = tmp_path / "meta.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    g = Graph({"purpose": "test"})
    return g, import_files(g, [f], NOW)[0]


def test_profile_found_keeps_origin_and_identity_caveat(tmp_path):
    g, rep = run(tmp_path, doc(items=[{"type": "profile", "username": "meta", "name": "Meta",
                                       "profile_url": "https://www.threads.com/@meta", "biography": "prywatne bio"}]))
    assert rep.format == "meta-search" and rep.status == "IMPORTED"
    url = next(n for n in g.nodes.values() if n.type is T.URL)
    assert url.attrs["source_kind"] == "api" and url.attrs["fetched_at"].startswith("2026-10-03")
    assert url.attrs["kind"] == "profile" and "biography" not in json.dumps(url.attrs)
    edge = next(iter(g.edges.values()))
    assert edge.relation == "has_account" and "nie dowodzi tej samej osoby" in edge.evidence
    assert [n for n in g.nodes.values() if n.type is T.USERNAME]


def test_search_posts_link_author_without_text(tmp_path):
    g, _ = run(tmp_path, doc(op="threads_search", items=[
        {"type": "post", "username": "meta", "text": "treść", "permalink": "https://www.threads.com/@meta/post/1",
         "timestamp": "2026-10-01T00:00:00+0000"}]))
    assert next(iter(g.edges.values())).relation == "authored"
    assert "treść" not in json.dumps([n.to_dict() for n in g.nodes.values()], ensure_ascii=False)


def test_no_result_and_not_configured_are_unknown_without_nodes(tmp_path):
    for status in ("no_result", "not_configured", "manual"):
        g, rep = run(tmp_path, doc(status=status))
        assert not g.nodes and rep.status == "IMPORTED"
        assert g.runs[-1].status.value == "UNKNOWN"


def test_errors_are_error_never_absence(tmp_path):
    for status in ("auth_error", "permission_denied", "rate_limited", "source_error"):
        g, rep = run(tmp_path, doc(status=status))
        assert not g.nodes and rep.status == "ERROR"


def test_non_api_found_rejected(tmp_path):
    _, rep = run(tmp_path, doc(kind="html_heuristic", items=[{"type": "profile", "username": "a",
                                                             "profile_url": "https://www.threads.com/@a"}]))
    assert rep.status == "ERROR"


def test_foreign_or_mismatched_profile_url_cannot_create_account(tmp_path):
    for url in ("https://evil.example/@meta", "https://www.threads.com/@someone_else"):
        g, rep = run(tmp_path, doc(items=[{"type": "profile", "username": "meta", "profile_url": url}]))
        assert not g.nodes and rep.status == "ERROR"


def test_import_drops_credentials_from_endpoint_query(tmp_path):
    data = doc(items=[{"type": "profile", "username": "meta", "profile_url": "https://www.threads.com/@meta"}])
    data["source"]["endpoint"] += "?access_token=SHOULD_NOT_PERSIST"
    g, rep = run(tmp_path, data)
    assert rep.status == "IMPORTED"
    assert "SHOULD_NOT_PERSIST" not in json.dumps([n.to_dict() for n in g.nodes.values()])
    assert all("SHOULD_NOT_PERSIST" not in e.evidence for e in g.edges.values())


def test_unknown_schema_and_invalid_item_type_are_errors(tmp_path):
    data = doc(items=[{"type": {"bad": 1}}])
    g, rep = run(tmp_path, data)
    assert not g.nodes and rep.status == "ERROR"
    data["schema"] = 999
    g, rep = run(tmp_path, data)
    assert not g.nodes and rep.status == "ERROR"


def ig_doc(items):
    d = doc(op="instagram_profile", items=items)
    d.update(platform="instagram", query="natgeo")
    d["source"]["endpoint"] = "https://graph.facebook.com/v23.0/{ig-user-id}"
    return d


def test_instagram_profile_and_media_are_accounts_and_posts_without_text(tmp_path):
    g, rep = run(tmp_path, ig_doc([
        {"type": "profile", "username": "natgeo", "name": "NG", "profile_url": "https://www.instagram.com/natgeo/",
         "biography": "prywatne bio", "website": "https://natgeo.com", "follower_count": 5},
        {"type": "post", "username": "natgeo", "text": "podpis posta", "permalink": "https://www.instagram.com/p/A/",
         "timestamp": "2026-10-01T00:00:00+0000"}]))
    assert rep.status == "IMPORTED"
    relations = sorted(e.relation for e in g.edges.values())
    assert relations == ["authored", "has_account"]
    profile = next(n for n in g.nodes.values() if n.type is T.URL and n.attrs["kind"] == "profile")
    assert profile.attrs["site"] == "Instagram" and profile.attrs["source_kind"] == "api"
    assert profile.attrs["fetched_at"].startswith("2026-10-03") and "{ig-user-id}" in profile.attrs["source_endpoint"]
    dump = json.dumps([n.to_dict() for n in g.nodes.values()], ensure_ascii=False)
    assert "prywatne bio" not in dump and "podpis posta" not in dump and "follower_count" not in dump
    # sygnały do porównania profili zostają: strona www i odcisk bio (skróty słów, bez treści)
    assert profile.attrs["website"] == "https://natgeo.com" and len(profile.attrs["bio_fingerprint"]) == 2


def test_instagram_profile_keeps_links_from_bio_without_bio_text(tmp_path):
    g, _ = run(tmp_path, ig_doc([
        {"type": "profile", "username": "natgeo", "profile_url": "https://www.instagram.com/natgeo/",
         "biography": "Zobacz https://alpha.example/u/natgeo, oraz nic wiecej"}]))
    profile = next(n for n in g.nodes.values() if n.type is T.URL and n.attrs["kind"] == "profile")
    assert profile.attrs["links"] == ["https://alpha.example/u/natgeo"]
    assert "Zobacz" not in json.dumps(profile.attrs, ensure_ascii=False)


def fb_doc(items, status="found"):
    d = doc(status=status, op="facebook_page", items=items)
    d.update(platform="facebook", query="natgeo")
    d["source"]["endpoint"] = "https://graph.facebook.com/v23.0/{page-id}"
    return d


PAGE = {"type": "page", "id": "23497828950", "name": "National Geographic", "category": "Media",
        "link": "https://www.facebook.com/natgeo/", "fan_count": 5, "about": "o nas", "website": "https://natgeo.com",
        "verification_status": "blue_verified"}


def test_facebook_page_is_organization_with_url_and_origin(tmp_path):
    g, rep = run(tmp_path, fb_doc([PAGE]))
    assert rep.status == "IMPORTED"
    org = next(n for n in g.nodes.values() if n.type is T.ORGANIZATION)
    assert org.attrs["kind"] == "facebook_page" and org.attrs["page_id"] == "23497828950"
    assert org.attrs["source_kind"] == "api" and org.attrs["fetched_at"].startswith("2026-10-03")
    assert "website" not in org.attrs and "about" not in json.dumps(org.attrs)   # bez automatycznego łączenia z domeną
    url = next(n for n in g.nodes.values() if n.type is T.URL)
    assert url.attrs["kind"] == "page" and url.attrs["site"] == "Facebook"
    edge = next(iter(g.edges.values()))
    assert edge.relation == "has_page" and "nie dowodzi powiązania" in edge.evidence
    assert not [n for n in g.nodes.values() if n.type is T.USERNAME]


def test_facebook_page_does_not_merge_with_same_named_company(tmp_path):
    f = tmp_path / "meta.json"
    f.write_text(json.dumps(fb_doc([PAGE])), encoding="utf-8")
    g = Graph({"purpose": "test"})
    g.add_node(Node.make(T.ORGANIZATION, "National Geographic", {}, "krs", "PL"))
    import_files(g, [f], NOW)
    assert len([n for n in g.nodes.values() if n.type is T.ORGANIZATION]) == 2


def test_facebook_page_without_id_or_link_is_not_imported(tmp_path):
    g, rep = run(tmp_path, fb_doc([{**PAGE, "id": ""}, {**PAGE, "link": ""}]))
    assert not g.nodes and g.runs[-1].status.value == "ERROR"


def test_facebook_no_result_and_permission_denied_create_no_nodes(tmp_path):
    g, _ = run(tmp_path, fb_doc([], status="no_result"))
    assert not g.nodes and g.runs[-1].status.value == "UNKNOWN"
    g, rep = run(tmp_path, fb_doc([], status="permission_denied"))
    assert not g.nodes and rep.status == "ERROR"
