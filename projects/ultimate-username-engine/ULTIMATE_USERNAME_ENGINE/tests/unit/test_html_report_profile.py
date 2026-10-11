"""E5: the "Profil zbiorczy" section of the HTML report (aggregate profile of the hits)."""

from __future__ import annotations

from datetime import datetime
from html.parser import HTMLParser

from ultimate_username.field_model import FieldGroup, field_spec
from ultimate_username.html_report import CSP, render_report

XSS = "<script>alert(1)</script>"


def src(extractor: str, quality: str = "HIGH", url: str = "https://example.org/p") -> dict:
    return {"source_url": url, "extractor": extractor, "locator": "x", "quality": quality}


def profile(site: str, status: str = "FOUND", **fields: object) -> dict:
    sources = fields.pop("sources", {})
    return {
        "site": site,
        "status": status,
        "requested_url": f"https://{site.lower()}.example/alice",
        "profile_url": f"https://{site.lower()}.example/alice",
        "useful_metadata": {"PROFILE_CONTEXT": dict(fields)},
        "field_sources": sources,
        "evidence_summary": [],
        "issues": [],
    }


def document(profiles: list, identity: dict | None = None) -> dict:
    doc = {"username": "alice", "profiles": profiles, "summary": {"counts": {"found": 3}}}
    if identity is not None:
        doc["identity"] = identity
    return doc


def render(doc: dict) -> str:
    return render_report([doc], generated_at=datetime(2026, 10, 11, 12, 0))


def rich_document() -> dict:
    return document(
        [
            profile(
                "GitHub",
                display_name="Alice  Liddell",
                location="Wonderland",
                language="en",
                created_at="2019-05-01T10:00:00Z",
                sources={
                    "display_name": src("json_ld"),
                    "location": src("embedded_state", "MEDIUM"),
                    "language": src("api", "HIGH"),
                    "created_at": src("api", "HIGH"),
                },
            ),
            profile(
                "Twitch",
                display_name="alice liddell",
                location="Paris",
                created_at="2015-01-02",
                sources={"display_name": src("opengraph", "LOW"), "created_at": src("meta")},
            ),
            profile("Kick", display_name="Al", created_at="not a date"),
            profile("Reddit", status="NOT_FOUND", display_name="Ghost Name"),
        ],
        identity={
            "profiles": [],
            "graph": {
                "nodes": ["https://github.example/alice", "https://twitch.example/alice"],
                "edges": [
                    {
                        "from": "https://github.example/alice",
                        "to": "https://twitch.example/alice",
                        "reciprocal": True,
                        "source_field": "external_links",
                    },
                    {
                        "from": "https://twitch.example/alice",
                        "to": "https://github.example/alice",
                        "reciprocal": True,
                        "source_field": "website",
                    },
                ],
            },
            "related_accounts": [
                {
                    "url": "https://www.instagram.com/Alice_Real/",
                    "platform": "instagram",
                    "from_profile": "https://github.example/alice",
                    "field": "bio",
                }
            ],
        },
    )


def section(html: str) -> str:
    start = html.index("Profil zbiorczy")
    end = html.index("Trafienia (FOUND, PROBABLE)")
    assert start < end
    return html[start:end]


def test_section_sits_above_the_hits_and_shows_most_common_name_with_source_count():
    part = section(render(rich_document()))
    assert "Alice Liddell" in part  # first spelling, whitespace collapsed
    assert "<b>Alice Liddell</b></td><td>2</td>" in part
    assert "Ghost Name" not in part  # NOT_FOUND profiles are not aggregated
    assert part.index("Alice Liddell") < part.index("Al<")  # most frequent first


def test_every_value_lists_its_sources_service_extractor_quality():
    part = section(render(rich_document()))
    for text in (
        "GitHub · json_ld · HIGH",
        "Twitch · opengraph · LOW",
        "GitHub · embedded_state · MEDIUM",
        "Wonderland",
        "Paris",
    ):
        assert text in part, text
    assert "Kick · — · —" in part  # source unknown but still listed


def test_languages_locations_and_creation_timeline_sorted_by_date():
    part = section(render(rich_document()))
    assert ">en<" in part
    assert part.index("2015-01-02") < part.index("2019-05-01") < part.index("not a date")
    assert "Twitch · meta · HIGH" in part


def test_related_accounts_and_edge_table_are_rendered_without_script():
    html = render(rich_document())
    part = section(html)
    assert "instagram" in part and "Alice_Real" in part
    assert 'href="https://www.instagram.com/Alice_Real/"' in part
    assert "external_links" in part and "website" in part
    assert part.count("tak") >= 2  # reciprocal edges
    assert "<script" not in html.lower()


def test_section_without_profile_data_shows_a_placeholder_not_empty_tables():
    html = render(document([profile("GitHub")]))
    part = section(html)
    assert "Brak danych profilowych" in part
    assert "<table" not in part
    html = render({"username": "x", "profiles": []})
    assert "Profil zbiorczy" in html or "Brak trafień" in html


def test_missing_optional_identity_keeps_the_section_data_from_profiles():
    doc = rich_document()
    del doc["identity"]
    part = section(render(doc))
    assert "Alice Liddell" in part and "instagram" not in part


def test_malformed_data_does_not_crash():
    doc = document(
        [
            {"status": "FOUND", "site": 5, "useful_metadata": {"X": "nope"}},
            {"status": "FOUND", "useful_metadata": {"PROFILE_CONTEXT": {"display_name": [1, {}]}}},
            {
                "status": "FOUND",
                "site": "A",
                "useful_metadata": {
                    "PROFILE_CONTEXT": {"created_at": {"a": 1}, "language": ["pl"]}
                },
                "field_sources": {"language": "nope", "created_at": [1]},
            },
        ],
        identity={"graph": {"edges": [None, 3, {"from": 1}]}, "related_accounts": "x"},
    )
    assert "Profil zbiorczy" in render(doc)
    assert "Profil zbiorczy" in render(document([], identity={"graph": [], "related_accounts": 3}))


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_untrusted_values_are_escaped_everywhere_in_the_section():
    evil = document(
        [
            profile(
                "Git" + XSS,
                display_name=XSS,
                location='"><img src=x onerror=alert(2)>',
                language=XSS,
                created_at=XSS,
                bio=XSS,
                sources={
                    "display_name": src(XSS, XSS, "javascript:alert(3)"),
                    "created_at": src("<b>x</b>"),
                },
            )
        ],
        identity={
            "graph": {
                "edges": [
                    {
                        "from": "javascript:alert(4)",
                        "to": 'https://x.example/"><script>alert(5)</script>',
                        "reciprocal": XSS,
                        "source_field": XSS,
                    }
                ]
            },
            "related_accounts": [
                {
                    "url": "javascript:alert(6)",
                    "platform": XSS,
                    "from_profile": 'https://a.example/"onmouseover="alert(7)',
                    "field": XSS,
                }
            ],
        },
    )
    html = render(evil)
    lowered = html.lower()
    assert "<script" not in lowered and "<img" not in lowered and "<b>x" not in lowered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    parsed = Collector()
    parsed.feed(html)
    names = {tag for tag, _ in parsed.tags}
    assert not names & {"script", "img", "iframe", "object", "embed", "svg"}
    assert not any(k.startswith("on") for _, attrs in parsed.tags for k in attrs)
    for tag, attrs in parsed.tags:
        if tag == "a":
            assert attrs["href"].startswith(("http://", "https://"))
    assert "javascript:alert" not in " ".join(a.get("href", "") for _, a in parsed.tags)


def test_section_adds_no_external_resources_and_csp_is_unchanged():
    html = render(rich_document())
    parsed = Collector()
    parsed.feed(html)
    for tag, attrs in parsed.tags:
        assert "src" not in attrs, tag
        assert tag not in {"link", "script", "img", "iframe", "form", "base", "object", "embed"}
        if "href" in attrs:
            assert tag == "a"
    assert "content=\"default-src 'none'; style-src 'unsafe-inline'" in html.replace("&#x27;", "'")
    assert (
        CSP == "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
    )
    assert "@import" not in html and "url(" not in html


def test_language_is_a_shown_profile_field():
    assert field_spec("language").group == FieldGroup.PROFILE_CONTEXT
