import json

from username_engine.correlate import Account, link_accounts, variant_links
from username_engine.extract import extract_profile
from username_engine.geo import (Evidence, Gazetteer, aggregate, flag_country, language_country,
                                 profile_evidence, tld_country)
from username_engine.models import Result, Status

GITHUB_API = json.dumps({"login": "sampler51", "url": "https://api.github.com/users/sampler51",
                         "name": "Jan Sampler", "blog": "https://sampler.pl", "location": "Kraków, Poland",
                         "bio": "Programista. Lubię żeglarstwo https://x.com/sampler_51",
                         "created_at": "2015-03-01T10:00:00Z", "avatar_url": "https://avatars.example/1"})

HTML_PAGE = """<html lang="pl"><head>
<meta property="og:title" content="Jan Sampler (@sampler_51)">
<meta property="og:description" content="Żeglarz z Gdańska">
<meta property="og:image" content="https://cdn.example/a.jpg">
<script type="application/ld+json">{"@type":"ProfilePage","mainEntity":{"@type":"Person","name":"Jan Sampler",
 "address":{"@type":"PostalAddress","addressLocality":"Gdańsk","addressCountry":"PL"},
 "sameAs":["https://github.com/sampler51"]}}</script></head><body></body></html>"""


def test_extract_from_api_json_skips_api_url():
    p = extract_profile(GITHUB_API, "application/json")
    assert p["name"] == "Jan Sampler" and p["location"] == "Kraków, Poland"
    assert p["website"] == "https://sampler.pl"                     # nie adres API z pola "url"
    assert "https://x.com/sampler_51" in p["links"] and p["created"].startswith("2015")


def test_extract_from_html_jsonld_and_og():
    p = extract_profile(HTML_PAGE, "text/html")
    assert p["name"] == "Jan Sampler" and "Gdańsk" in p["location"]
    assert p["bio"] == "Żeglarz z Gdańska" and p["page_lang"] == "pl"
    assert "https://github.com/sampler51" in p["links"]


def test_extract_garbage_is_empty_not_crash():
    assert isinstance(extract_profile("<<<not html", ""), dict)
    assert extract_profile("{broken json", "application/json") == {}
    assert extract_profile("", "") == {}


def test_gazetteer_resolution():
    g = Gazetteer()
    assert g.resolve("Kraków, Poland")[0] == "PL"
    assert g.resolve("Warszawa")[0] == "PL"
    assert g.resolve("Living in Germany")[0] == "DE"
    assert g.resolve("Berlin / DE")[0] == "DE"
    assert g.resolve("🇵🇱")[0] == "PL"
    assert g.resolve("somewhere nice") is None


def test_us_state_abbreviation_not_country(tmp_path):
    geo = tmp_path / "geo.json"
    geo.write_text(json.dumps({"countries": {}, "cities": {"san jose": "US", "toronto": "CA"}}), encoding="utf-8")
    g = Gazetteer(geo)
    assert g.resolve("San Jose, CA")[0] == "US"                 # Kalifornia, nie Kanada
    assert g.resolve("Toronto, CA")[0] == "CA"                  # miasto kanadyjskie -> zostaje Kanada
    cc, conf, _ = g.resolve("somewhere, CA")
    assert cc == "CA" and conf < 0.5                            # bez kontekstu: niska pewność
    assert g.resolve("Berlin, DE")[0] == "DE"


def test_full_gazetteer_common_words_not_cities(tmp_path):
    geo = tmp_path / "geo.json"
    geo.write_text(json.dumps({"countries": {}, "cities": {"nice": "FR", "reading": "GB", "gdynia": "PL"}}),
                   encoding="utf-8")
    g = Gazetteer(geo)
    assert g.resolve("somewhere nice, reading books") is None
    assert g.resolve("Living in Nice")[0] == "FR"
    assert g.resolve("Gdynia")[0] == "PL"


def test_language_tld_flag():
    assert language_country("Lubię żeglarstwo")[0] == "PL"
    assert language_country("Привіт, я з Києва")[0] == "UA"
    assert language_country("just english") is None
    assert tld_country("https://wykop.pl/ludzie/x") == "PL"
    assert tld_country("https://itch.io/profile/x") is None          # .io to domena „ogólna”
    assert flag_country("hej 🇩🇪") == "DE"


def test_country_aggregate_strength():
    g = Gazetteer()
    ev = profile_evidence("GitHub", "https://github.com/x", extract_profile(GITHUB_API, "application/json"), [], g)
    ev += profile_evidence("Wykop", "https://wykop.pl/ludzie/x", {}, ["pl"], g)
    top = aggregate(ev)[0]
    assert top["country"] == "PL" and top["percent"] == 100 and top["strength"] in ("średnia", "mocna")
    weak = aggregate([Evidence("PL", 0.15, "domena .pl")])[0]
    assert weak["percent"] == 100 and weak["strength"] == "słaba"     # 100% głosów, ale słabo


def test_national_site_language_not_double_counted():
    ev = profile_evidence("RamblerDating", "https://dating.rambler.ru/page/x",
                          {"bio": "Знакомства на Рамблере, бесплатный сайт"}, [], Gazetteer())
    assert [e.country for e in ev] == ["RU"] and ev[0].weight <= 0.15


def test_link_accounts_crosslink_and_name():
    a = Account("sampler51", "GitHub", "https://github.com/sampler51", extract_profile(GITHUB_API, "application/json"))
    b = Account("sampler_51", "X", "https://x.com/sampler_51", {"name": "Jan Sampler", "location": "Krakow, Poland"})
    link = link_accounts(a, b, Gazetteer())
    assert link.score >= 0.7 and any("linkuje" in r for r in link.reasons)


def test_no_profile_data_no_claim():
    a = Account("sampler51", "S1", "https://s1/sampler51", {})
    b = Account("sampler.51", "S2", "https://s2/sampler.51", {})
    assert link_accounts(a, b).score == 0


def test_variant_links_summary():
    gh = Result("GitHub", "https://github.com/sampler51", Status.FOUND, 0.97,
                profile=extract_profile(GITHUB_API, "application/json"))
    x = Result("X", "https://x.com/sampler_51", Status.FOUND, 0.9, profile={"name": "Jan Sampler"})
    scans = {"sampler51": [gh], "sampler_51": [x], "sampler.51": []}
    links = variant_links(scans, "sampler51", Gazetteer())
    assert links["sampler_51"]["score"] >= 0.7
    assert links["sampler.51"]["score"] is None
