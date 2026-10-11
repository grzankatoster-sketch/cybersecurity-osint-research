"""E2 step 4: label-value pairs in visible HTML text (location, joined date), quality LOW."""

import time

import pytest

from ultimate_username.domain.metadata import EvidenceQuality
from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.embedded_state import LabelValueExtractor
from ultimate_username.enrichment import EXTRACTORS, enrich

SITE = SiteDefinition(
    "social",
    "Social",
    "https://social.example/u/{username}",
    DetectionSpec(Rule("status", statuses=(200,))),
)
ONLY = (LabelValueExtractor(),)


def run(body, nick="alice", extractors=ONLY):
    url = f"https://social.example/u/{nick}"
    response = TransportResponse(
        url, 200, body.encode(), (("Content-Type", "text/html; charset=utf-8"),), url
    )
    return enrich(response, nick, SITE, DetectionResult(Verdict.FOUND), extractors=extractors)


def values(result):
    return {f.name: f.value for f in result.fields + result.extra_fields}


def profile(inner):
    return f"<html><head><title>t</title></head><body><h1>alice</h1>{inner}</body></html>"


def test_dt_dd_pairs():
    got = values(
        run(
            profile(
                "<dl><dt>Location</dt><dd>Oslo, Norway</dd>"
                "<dt>Joined</dt><dd>March 3, 2019</dd></dl>"
            )
        )
    )
    assert got == {"location": "Oslo, Norway", "created_at": "2019-03-03"}


def test_colon_in_one_text_node_and_table_cells():
    got = values(
        run(
            profile(
                "<p>Location: Warsaw</p>"
                "<table><tr><th>Member since</th><td>2018-07-21</td></tr></table>"
            )
        )
    )
    assert got == {"location": "Warsaw", "created_at": "2018-07-21"}


@pytest.mark.parametrize(
    "label,value,expected",
    [
        ("Lokalizacja", "Kraków", "Kraków"),
        ("Местоположение", "Москва", "Москва"),
        ("Ort", "Berlin", "Berlin"),
        ("Ubicación", "Madrid", "Madrid"),
    ],
)
def test_location_labels_in_other_languages(label, value, expected):
    assert values(run(profile(f"<span>{label}:</span> <span>{value}</span>"))) == {
        "location": expected
    }


@pytest.mark.parametrize(
    "label,value,expected",
    [
        ("Dołączył", "3 marca 2019", "2019-03-03"),
        ("На сайте с", "3 марта 2019", "2019-03-03"),
        ("Registered", "21 July 2018", "2018-07-21"),
        ("Joined", "Jul 21, 2018", "2018-07-21"),
        ("Joined", "21.07.2018", "2018-07-21"),
        ("Enlisted", "2012-11-05", "2012-11-05"),
    ],
)
def test_joined_labels_and_date_formats(label, value, expected):
    assert values(run(profile(f"<div><b>{label}</b><span>{value}</span></div>"))) == {
        "created_at": expected
    }


@pytest.mark.parametrize(
    "inner",
    [
        "<dt>Joined</dt><dd>3 years ago</dd>",
        "<dt>Joined</dt><dd>sometime in 2019</dd>",
        "<dt>Location</dt><dd>https://evil.example/where</dd>",
        "<dt>Location</dt><dd>www.example.com</dd>",
        "<dt>Location</dt><dd>" + "x" * 81 + "</dd>",
        "<dt>Location</dt><dd></dd>",
        "<dt>Location</dt><dd>N/A</dd>",
        "<dt>Location</dt><dd>Joined</dd>",
        "<nav><a>Location</a><a>Events</a></nav>",
        "<script>var s = 'Location: Mars';</script>",
        "<style>.x:before{content:'Location: Mars'}</style>",
        "<!-- Location: Mars -->",
        '<div title="Location: Mars">x</div>',
    ],
)
def test_unsafe_or_invisible_values_are_ignored(inner):
    assert values(run(profile(inner))) == {}


def test_page_that_never_shows_the_handle_gives_nothing():
    body = "<html><body><dl><dt>Location</dt><dd>Oslo</dd></dl></body></html>"
    assert values(run(body)) == {}


def test_values_are_low_quality_with_provenance():
    result = run(profile("<dl><dt>Location</dt><dd>Oslo</dd></dl>"))
    cand = next(c for c in result.candidates if c.name == "location")
    assert cand.quality == EvidenceQuality.LOW
    assert cand.extractor == "LabelValueExtractor"
    assert cand.priority == 70
    assert "Location" in cand.evidence
    assert cand.source_url == "https://social.example/u/alice"


def test_does_not_overwrite_fields_from_stronger_extractors():
    body = (
        '<script type="application/json">{"user":{"username":"alice","location":"Bergen"}}</script>'
        + profile("<dl><dt>Location</dt><dd>Oslo</dd></dl>")
    )
    result = run(body, extractors=EXTRACTORS)
    assert values(result)["location"] == "Bergen"
    assert not [c for c in result.candidates if c.extractor == "LabelValueExtractor"]


def test_first_pair_wins_and_template_values_are_filtered():
    got = values(
        run(profile("<dl><dt>Location</dt><dd>Oslo</dd><dt>Location</dt><dd>Mars</dd></dl>"))
    )
    assert got == {"location": "Oslo"}
    assert values(run(profile("<dl><dt>Location</dt><dd>alice</dd></dl>"))) == {}


def test_large_text_is_linear():
    body = profile("<p>" + "Location " * 50000 + "</p>" + "<p>x</p>" * 20000)
    started = time.perf_counter()
    run(body)
    assert time.perf_counter() - started < 2.0
