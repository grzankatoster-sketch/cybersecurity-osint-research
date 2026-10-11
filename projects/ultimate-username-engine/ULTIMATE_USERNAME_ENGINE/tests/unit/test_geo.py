import json

import pytest

from ultimate_username.geo import (
    WEIGHTS,
    Gazetteer,
    GeoSource,
    aggregate,
    flag_country,
    geo_section,
    language_country,
    page_lang_country,
    source_hints,
    tld_country,
)


def test_weights_match_osint_values():
    assert WEIGHTS == {
        "location": 1.0,
        "nationality": 1.0,
        "language": 0.4,
        "page_lang": 0.1,
        "tld": 0.15,
        "tag": 0.1,
    }


def test_gazetteer_resolves_country_city_flag_and_us_state():
    gaz = Gazetteer()
    assert gaz.resolve("Kraków, Poland")[0] == "PL"
    assert gaz.resolve("Warszawa") == ("PL", 0.85, "warszawa")
    assert gaz.resolve("🇩🇪 somewhere")[0] == "DE"
    assert gaz.resolve("San Francisco, CA")[0] == "US"
    assert gaz.resolve("somewhere nice") is None
    assert gaz.resolve("") is None


def test_flag_language_tld_helpers():
    assert flag_country("hi 🇵🇱") == "PL"
    assert language_country("zażółć gęślą")[0] == "PL"
    assert language_country("plain ascii") is None
    assert tld_country("https://example.pl/u") == "PL"
    assert tld_country("https://example.uk/u") == "GB"
    assert tld_country("https://example.io/u") is None
    assert page_lang_country("pl-PL") == "PL"
    assert page_lang_country("de-AT") == "AT"
    assert page_lang_country("cs") == "CZ"
    assert page_lang_country("en") is None
    assert page_lang_country("not a tag!") is None


def test_source_hints_cite_site_and_field():
    source = GeoSource(
        "GitHub",
        "https://github.com/jan",
        {"location": "Kraków, Poland", "bio": "zażółć", "page_lang": "pl"},
    )
    hints = source_hints(source, Gazetteer())
    by_signal = {h.signal: h for h in hints}
    assert by_signal["location"].country == "PL" and by_signal["location"].weight == 1.0
    assert by_signal["location"].site == "GitHub" and by_signal["location"].field == "location"
    assert by_signal["language"].field == "bio" and by_signal["language"].weight == 0.4
    assert by_signal["page_lang"].weight == 0.1
    assert "tld" not in by_signal  # .com carries no country


def test_national_service_does_not_double_count_language_with_tld():
    source = GeoSource("Wykop", "https://wykop.pl/ludzie/x", {"bio": "zażółć"})
    signals = [h.signal for h in source_hints(source, Gazetteer())]
    assert signals == ["tld"]


def test_tag_only_for_non_global_single_country_service():
    local = GeoSource("Lokalny", "https://lokalny.example/u", {}, tags=("social", "pl"))
    assert [h.signal for h in source_hints(local, Gazetteer())] == ["tag"]
    glob = GeoSource("Codeberg", "https://codeberg.example/u", {}, tags=("global", "de"))
    assert source_hints(glob, Gazetteer()) == []
    two = GeoSource("X", "https://x.example/u", {}, tags=("pl", "de"))
    assert source_hints(two, Gazetteer()) == []


def test_aggregate_percent_strength_and_ranking():
    sources = [
        GeoSource("A", "https://a.example/u", {"location": "Warszawa"}),
        GeoSource("B", "https://b.example/u", {"location": "Berlin, Germany"}),
        GeoSource("C", "https://c.pl/u", {}),
        GeoSource("D", "https://d.example/u", {"location": "Kraków, Poland"}),
    ]
    gaz = Gazetteer()
    hints = [h for s in sources for h in source_hints(s, gaz)]
    ranked = aggregate(hints)
    assert [r["country"] for r in ranked][0] == "PL"
    assert sum(int(str(r["percent"])) for r in ranked) in range(98, 103)
    assert ranked[0]["strength"] == "strong" and ranked[1]["strength"] == "medium"
    assert {e["site"] for e in ranked[0]["evidence"]} == {"A", "C", "D"}  # type: ignore[attr-defined]
    assert aggregate([]) == []


def test_lone_tld_is_full_share_but_weak():
    ranked = aggregate(source_hints(GeoSource("S", "https://s.de/u", {}), Gazetteer()))
    assert ranked[0]["percent"] == 100 and ranked[0]["strength"] == "weak"


def test_geo_section_and_optional_gazetteer_file(tmp_path):
    extra = tmp_path / "geo.json"
    extra.write_text(
        json.dumps({"countries": {"narnia": "GB"}, "cities": {"cair paravel": "GB"}}),
        encoding="utf-8",
    )
    sources = [GeoSource("S", "https://s.example/u", {"location": "Cair Paravel"})]
    assert geo_section(sources)["countries"] == []
    section = geo_section(sources, gazetteer=Gazetteer(extra))
    assert section["profiles_considered"] == 1
    assert section["countries"][0]["country"] == "GB"  # type: ignore[index]
    assert "not a fact" in str(section["note"])


def test_gazetteer_file_is_validated(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"countries": ["x"]}', encoding="utf-8")
    with pytest.raises(ValueError):
        Gazetteer(bad)
    bad.write_text('{"cities": {"x": 1}}', encoding="utf-8")
    with pytest.raises(ValueError):
        Gazetteer(bad)
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError):
        Gazetteer(bad)
    with pytest.raises(OSError):
        Gazetteer(tmp_path / "missing.json")


def test_sources_from_results_use_hits_and_skip_conflicts():
    from ultimate_username.demo import make_demo
    from ultimate_username.domain.metadata import EvidenceQuality, FieldCandidate, ProfileMetadata
    from ultimate_username.domain.models import (
        AttemptRecord,
        DetectionResult,
        ExecutionState,
        SearchResult,
        Timing,
        Username,
        Verdict,
    )
    from ultimate_username.geo import sources_from_results

    registry, _ = make_demo()

    def field(name, value):
        return FieldCandidate(name, value, "found", "u", "x", "e", "t", EvidenceQuality.HIGH, 1)

    def result(verdict, fields=(), conflicts=(), tested=True):
        attempt = AttemptRecord(1, "u", 200, ExecutionState.OK, Timing())
        return SearchResult(
            "j",
            "t",
            "found",
            Username("a", "a", "a"),
            DetectionResult(verdict=verdict),
            profile_url="https://found.example.test/a",
            attempts=(attempt,) if tested else (),
            profile_metadata=ProfileMetadata(fields=tuple(fields), conflicts=tuple(conflicts)),
        )

    results = [
        result(Verdict.FOUND, [field("location", "Warszawa"), field("followers", 3)]),
        result(Verdict.PROBABLE, [field("location", "Berlin")], conflicts=["location"]),
        result(Verdict.NOT_FOUND, [field("location", "Paris")]),
        result(Verdict.UNKNOWN, [field("location", "Rome")]),
        result(Verdict.FOUND, [field("location", "Oslo")], tested=False),
    ]
    sources = sources_from_results(results, registry)
    assert [dict(s.fields) for s in sources] == [{"location": "Warszawa"}, {}]
    assert sources[0].site == "Found"
    section = geo_section(sources)
    assert section["countries"][0]["country"] == "PL"  # type: ignore[index]
