"""HTML report: sections, optional parts, escaping of third-party text and no external resources."""

from datetime import datetime
from html.parser import HTMLParser

from ultimate_username.html_report import render_report

XSS = "<script>alert(1)</script>"
IMG = '"><img src=x onerror=alert(2)>'


def hit(**overrides):
    record = {
        "site": "GitHub",
        "status": "FOUND",
        "tested": True,
        "response_class": "PROFILE",
        "signals": [
            {
                "kind": "DETECTION_RULE_MATCH",
                "source": "https://github.com/alice",
                "strength": "MODERATE",
                "weight": 2,
                "independence_group": "declared-rule",
                "value": "present",
                "locator": "gate.0",
            }
        ],
        "requested_url": "https://github.com/alice",
        "profile_url": "https://github.com/alice",
        "useful_metadata": {
            "IDENTITY": {"username": "alice", "display_name": "Alice " + XSS},
            "PROFILE_CONTEXT": {"bio": XSS + IMG, "location": None},
        },
        "field_sources": {
            "display_name": {
                "source_url": "https://github.com/alice",
                "extractor": "json_ld",
                "locator": "script[type=ld+json]",
                "quality": "HIGH",
            },
            "bio": {
                "source_url": "javascript:alert(3)",
                "extractor": "meta",
                "locator": "og:description",
                "quality": "LOW",
            },
        },
        "confidence": {"strength": "STRONG", "probability": None},
        "evidence_summary": ["POSITIVE_EVIDENCE " + XSS],
        "evidence": [
            {
                "rule_id": "present.0",
                "strategy": "status_code",
                "polarity": "SUPPORTS_PRESENT",
                "locator": "status",
                "observed": "200",
            }
        ],
        "control": {
            "kind": "CONTROL_DIFFERS_STRONG",
            "class": "A",
            "diffs": ["status", "title"],
            "status_real": 200,
            "status_control": 404,
            "title_real": "alice " + XSS,
            "title_control": "Not found",
            "similarity": 0.12,
            "control_name": "zq7xkd3mw",
            "absent_like": True,
        },
        "issues": [],
    }
    record.update(overrides)
    return record


def full_document():
    return {
        "view": "ANALYST",
        "username": "alice" + XSS,
        "meta": {"mode": "normal", "selection": "quality"},
        "profiles": [
            hit(),
            hit(
                site="Blog",
                status="PROBABLE",
                profile_url="javascript:alert(9)",
                requested_url="javascript:alert(9)",
                control=None,
                evidence=[],
                field_sources={},
                useful_metadata={},
            ),
            {
                "site": "Nope",
                "status": "NOT_FOUND",
                "requested_url": "https://nope.example/alice",
                "issues": [],
                "evidence_summary": [],
            },
            {
                "site": "Shield",
                "status": "BLOCKED",
                "issues": ["CHALLENGE"],
                "evidence_summary": ["CHALLENGE"],
            },
            {
                "site": "Shield2",
                "status": "BLOCKED",
                "issues": ["CHALLENGE"],
                "evidence_summary": [],
            },
            {"site": "Odd", "status": "UNKNOWN", "issues": [], "evidence_summary": ["NO_RULE"]},
        ],
        "summary": {
            "counts": {
                "found": 1,
                "probable": 1,
                "not_found": 1,
                "unknown": 3,
                "tested": 6,
                "not_tested": 40,
                "request_attempts": 9,
            },
            "not_tested_reasons": {"SERVICE_BUDGET": 40},
            "excluded_before_search": {"MODE_QUALITY_THRESHOLD": 12},
        },
        "request_economy": {"total_requests": 9, "control_requests": 2, "budget_remaining": 91},
        "identity": {
            "profiles": [
                {
                    "profile_url": "https://github.com/alice",
                    "site": "GitHub",
                    "score": 0.83,
                    "decision": "LIKELY_SAME",
                    "seed_used": True,
                    "signals": [
                        {
                            "kind": "SHARED_AVATAR",
                            "weight": 3,
                            "group": "visual",
                            "fields": ["avatar_hash"],
                            "sources": ["https://github.com/alice", "javascript:evil()"],
                            "detail": "same hash " + XSS,
                        }
                    ],
                },
                {"profile_url": "https://other.example/x", "site": "Other", "score": 0.2},
            ]
        },
        "geo": {
            "profiles_considered": 2,
            "countries": [
                {
                    "country": "PL",
                    "percent": 100,
                    "strength": "weak",
                    "evidence": [
                        {
                            "site": "GitHub",
                            "field": "bio",
                            "signal": "language",
                            "weight": 0.4,
                            "detail": XSS,
                        }
                    ],
                }
            ],
            "note": "Inference from clues.",
        },
        "wayback": {
            "budget": 20,
            "requests": 2,
            "errors": 1,
            "skipped_over_budget": 0,
            "profiles": [
                {
                    "profile_url": "https://github.com/alice",
                    "first_seen": "2018-01-02",
                    "last_seen": "2020-01-02",
                    "snapshots": [
                        {
                            "timestamp": "20180102030405",
                            "original": "https://github.com/alice",
                            "status": "200",
                        }
                    ],
                },
                {"profile_url": "https://x.example/a", "snapshots": [], "error": "HTTP 503"},
            ],
        },
        "dorks": {
            "queries": ['"alice" ' + XSS, "(inurl:alice) -site:pinterest.com"],
            "sent": False,
        },
        "variants": {"is_variant": True, "variant_of": "alice_"},
    }


def render(document=None):
    return render_report([document or full_document()], generated_at=datetime(2026, 10, 10, 12, 0))


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def tags(html, name):
    parser = Collector()
    parser.feed(html)
    return [attrs for tag, attrs in parser.tags if tag == name]


def test_full_document_has_every_section():
    html = render()
    for text in (
        "FOUND",
        "PROBABLE",
        "Dowody: reguły, które trafiły",
        "present.0",
        "Żądanie kontrolne",
        "CONTROL_DIFFERS_STRONG",
        "zq7xkd3mw",
        "200 / 404",
        "Tożsamość (identity score)",
        "LIKELY_SAME",
        "SHARED_AVATAR",
        "avatar_hash",
        "Pola profilu i ich źródła",
        "json_ld",
        "og:description",
        "Geo (poszlaki, nie fakty)",
        "Archiwum (Wayback Machine)",
        "HTTP 503",
        "Dorki",
        "inurl:alice",
        "alice_",
        "Ekonomia żądań",
        "total_requests",
        "normal",
        "2026-10-10 12:00",
    ):
        assert text in html, text


def test_not_found_collapsed_and_unknown_grouped_by_reason():
    html = render()
    assert "NOT_FOUND: 1 serwisów" in html and "nope.example" in html
    assert "BLOCKED: CHALLENGE: 2" in html
    assert "UNKNOWN: NO_RULE: 1" in html
    assert "SERVICE_BUDGET" in html and "MODE_QUALITY_THRESHOLD" in html
    assert "<details>" in html


def test_missing_optional_sections_are_not_rendered():
    document = full_document()
    for key in ("identity", "geo", "wayback", "dorks", "variants", "request_economy", "meta"):
        del document[key]
    for profile in document["profiles"]:
        profile.pop("control", None)
        profile.pop("evidence", None)
        profile.pop("field_sources", None)
    html = render(document)
    for text in (
        "Tożsamość",
        "Geo (",
        "Wayback",
        "Dorki",
        "Ekonomia żądań",
        "Żądanie kontrolne",
        "Dowody: reguły",
    ):
        assert text not in html, text
    assert "FOUND" in html and "GitHub" in html


def test_minimal_and_malformed_documents_do_not_crash():
    assert "Brak trafień" in render({"username": "x", "profiles": []})
    assert "Raport" in render({"view": "ANALYST"})
    weird = {
        "username": 5,
        "profiles": [None, 3, {"status": "FOUND", "site": ["a"]}],
        "summary": [],
    }
    weird["identity"] = {"profiles": "nope"}
    weird["geo"] = {"countries": [None, {"evidence": 7}]}
    weird["wayback"] = {"profiles": [1, {"snapshots": [None, {"timestamp": 1}]}]}
    assert "<html" in render(weird)


def test_identity_without_matching_hit_is_listed_separately():
    html = render()
    assert "Tożsamość: pozostałe profile" in html and "other.example/x" in html


def test_third_party_text_is_escaped_not_executed():
    html = render()
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    parsed = Collector()
    parsed.feed(html)
    names = {tag for tag, _ in parsed.tags}
    assert "script" not in names and "img" not in names and "iframe" not in names
    assert not any(k.startswith("on") for _, attrs in parsed.tags for k in attrs)


def test_control_characters_are_stripped():
    document = {"username": "a", "profiles": [hit(evidence_summary=["x\x00y\x1b[31m z"])]}
    html = render(document)
    assert "\x00" not in html and "\x1b" not in html and " " not in html


def test_links_open_safely_and_only_for_http():
    html = render()
    anchors = tags(html, "a")
    assert anchors
    for attrs in anchors:
        assert attrs["href"].startswith(("http://", "https://"))
        assert set(attrs["rel"].split()) == {"noopener", "noreferrer"}
        assert attrs["target"] == "_blank"
    assert "javascript:" not in " ".join(a["href"] for a in anchors)
    assert "https://web.archive.org/web/20180102030405/https://github.com/alice" in html


def test_attribute_injection_through_url_is_neutralised():
    nasty = 'https://x.example/"onmouseover="alert(1)'
    html = render({"username": "a", "profiles": [hit(profile_url=nasty)]})
    assert "onmouseover" not in " ".join(k for attrs in tags(html, "a") for k in attrs)
    spaced = "https://x.example/a b"
    html = render({"username": "a", "profiles": [hit(profile_url=spaced)]})
    assert spaced not in " ".join(a["href"] for a in tags(html, "a"))


def test_self_contained_no_external_resources():
    html = render()
    for name in ("link", "script", "img", "iframe", "source", "embed", "object", "video"):
        assert tags(html, name) == [], name
    parsed = Collector()
    parsed.feed(html)
    resource_attrs = {"src", "srcset", "data", "poster", "action", "formaction", "ping"}
    assert not [a for _, attrs in parsed.tags for a in attrs if a in resource_attrs]
    assert "@import" not in html and "url(" not in html
    csp = [a for a in tags(html, "meta") if a.get("http-equiv") == "Content-Security-Policy"]
    assert csp and "default-src 'none'" in csp[0]["content"]
    assert tags(html, "html")[0]["lang"] == "pl"


def test_supports_light_and_dark_scheme_and_responsive_layout():
    html = render()
    assert "prefers-color-scheme:dark" in html and "max-width:640px" in html
    assert 'name="viewport"' in html


def test_several_documents_share_one_page():
    a, b = full_document(), full_document()
    b["username"] = "bob"
    html = render_report([a, b], generated_at=datetime(2026, 10, 10))
    assert html.count("<main>") == 1 and "bob" in html and html.count("Nazwa:") == 2
