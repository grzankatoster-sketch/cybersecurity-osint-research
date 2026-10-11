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
from ultimate_username.enrichment import enrich
from ultimate_username.enrichment_filters import is_self_link

HEADERS = (("Content-Type", "text/html; charset=utf-8"),)
OWN = ("https://www.dailymotion.com/vexalune", "https://www.dailymotion.com/vexalune")


@pytest.mark.parametrize(
    "link",
    [
        "https://www.dailymotion.com/vexalune",
        "https://dailymotion.com/vexalune/",
        "HTTPS://WWW.DAILYMOTION.COM/Vexalune",
        "https://www.dailymotion.com/vexalune#about",
        "https://www.dailymotion.com/@vexalune",
        "https://dailymotion.com/VEXALUNE",
    ],
)
def test_own_profile_url_is_a_self_link(link):
    assert is_self_link(link, "vexalune", OWN)


@pytest.mark.parametrize(
    "link",
    [
        "https://vexalune.dev",
        "https://twitter.com/vexalune",
        "https://www.dailymotion.com/other",
        "https://www.dailymotion.com/vexalune/videos",
        "https://www.dailymotion.com/",
        "not a url",
    ],
)
def test_other_links_are_not_self_links(link):
    assert not is_self_link(link, "vexalune", OWN)


class Adapter:
    def __init__(self, name, value):
        self.name, self.value = name, value

    def extract(self, document, context):
        context.add(self.name, self.value, "Adapter", "x", EvidenceQuality.HIGH, 10)


def run(name, value, nick="vexalune"):
    site = SiteDefinition(
        "dm",
        "Dailymotion",
        "https://www.dailymotion.com/{username}",
        DetectionSpec(Rule("status", statuses=(200,))),
    )
    final = f"https://www.dailymotion.com/{nick}"
    response = TransportResponse(final, 200, b"<html>vexalune</html>", HEADERS, final)
    return enrich(
        response, nick, site, DetectionResult(Verdict.FOUND), extractors=(Adapter(name, value),)
    )


def fields(result):
    return {f.name: f.value for f in result.fields + result.extra_fields}


def test_website_equal_to_own_profile_is_rejected():
    result = run("website", "https://www.dailymotion.com/vexalune")
    assert "website" not in fields(result)
    assert "SELF_LINK" in result.diagnostics


def test_website_with_only_the_nick_path_on_the_same_host_is_rejected():
    result = run("website", "https://dailymotion.com/@Vexalune/")
    assert "website" not in fields(result) and "SELF_LINK" in result.diagnostics


def test_real_website_is_kept():
    assert fields(run("website", "https://vexalune.dev"))["website"] == "https://vexalune.dev"


def test_external_links_lose_only_the_self_links():
    links = ["https://www.dailymotion.com/vexalune", "https://github.com/vexa"]
    assert fields(run("external_links", links))["external_links"] == ("https://github.com/vexa",)


def test_external_links_with_only_self_links_are_rejected():
    result = run("external_links", ["https://www.dailymotion.com/vexalune/"])
    assert "external_links" not in fields(result) and "SELF_LINK" in result.diagnostics


def test_html_entities_are_unescaped_before_the_filters():
    result = run("display_name", "Vexalune&#039;s Profil")
    assert "display_name" not in fields(result) and "NICK_ECHO" in result.diagnostics
    assert fields(run("display_name", "Tom &amp; Jerry"))["display_name"] == "Tom & Jerry"
