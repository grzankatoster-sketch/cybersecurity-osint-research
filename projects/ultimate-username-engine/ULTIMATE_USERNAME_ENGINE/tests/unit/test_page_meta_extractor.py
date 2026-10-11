import pytest

from ultimate_username.domain.metadata import EvidenceQuality, MetadataState
from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.enrichment import EXTRACTORS, PageMetaExtractor, enrich

HEADERS = (("Content-Type", "text/html; charset=utf-8"),)


def make_site(name="Kwai"):
    return SiteDefinition(
        "kwai",
        name,
        "https://www.kwai.com/@{username}",
        DetectionSpec(Rule("status", statuses=(200,))),
    )


def run(
    body,
    nick="PublicRefA",
    name="Kwai",
    verdict=Verdict.FOUND,
    extractors=EXTRACTORS,
    mentions_nick=True,
):
    if mentions_nick:
        body += f"<!-- {nick} -->"
    final = f"https://www.kwai.com/@{nick}"
    response = TransportResponse(final, 200, body.encode(), HEADERS, final)
    return enrich(response, nick, make_site(name), DetectionResult(verdict), extractors=extractors)


def fields(result):
    return {f.name: f.value for f in result.fields + result.extra_fields}


def og(title):
    return f'<meta property="og:title" content="{title}">'


KWAI = (
    "<html><head><title>Ingrid Testova (@PublicRefA) on Kwai</title>"
    '<meta property="og:title" content="Ingrid Testova (@PublicRefA) on Kwai">'
    '<meta property="og:description" content="World chess champion and streamer from Norway">'
    '<meta property="og:image" content="https://cdn.kwai.net/u/9f3a/photo.jpg">'
    "</head><body>x</body></html>"
)


def test_kwai_like_page_yields_cautious_low_quality_name_and_avatar_but_no_bio():
    result = run(KWAI)
    values = fields(result)
    assert values["display_name"] == "Ingrid Testova"
    assert values["avatar_url"] == "https://cdn.kwai.net/u/9f3a/photo.jpg"
    assert "bio" not in values
    assert result.state == MetadataState.SUCCESS
    cands = [c for c in result.candidates if c.extractor == "PageMetaExtractor"]
    assert {c.name for c in cands} == {"display_name", "avatar_url"}
    assert all(c.quality == EvidenceQuality.LOW and c.priority == 60 for c in cands)
    by = {c.name: c for c in cands}
    assert by["display_name"].evidence == "meta[property=og:title]"
    assert by["display_name"].source_url.startswith("https://www.kwai.com/")


def test_twitter_title_and_image_tags_are_accepted():
    body = (
        '<meta name="twitter:title" content="Jane Doe | Kwai">'
        '<meta name="twitter:image" content="https://cdn.example.net/a/jane.png">'
    )
    result = run(body, nick="jd77")
    values = fields(result)
    assert values["display_name"] == "Jane Doe"
    assert values["avatar_url"] == "https://cdn.example.net/a/jane.png"
    assert {c.name: c.evidence for c in result.candidates}["display_name"] == (
        "meta[name=twitter:title]"
    )


def test_title_tag_alone_is_never_a_display_name_source():
    assert "display_name" not in fields(run("<title>Jane Doe | Kwai</title>", nick="jd77"))


@pytest.mark.parametrize(
    "title",
    [
        "Kwai",
        "Login - Kwai",
        "Sign up | Kwai",
        "Page not found",
        "404 Error",
        "Kwai - Profile",
        "@PublicRefA on Kwai",
        "x" * 90,
    ],
)
def test_site_name_or_generic_title_gives_no_display_name(title):
    assert "display_name" not in fields(run(og(title)))


def test_display_name_equal_to_nick_is_rejected_as_echo():
    result = run(og("publicrefa on Kwai"))
    assert "display_name" not in fields(result)
    assert "NICK_ECHO" in result.diagnostics


def test_spelled_out_name_differs_from_the_camel_case_nick():
    assert fields(run(og("Ingrid Testova | Kwai")))["display_name"] == "Ingrid Testova"


# One synthetic page per wrong value found by the live field sample: the template pattern, not
# the host, is what must be rejected.
WRONG_TITLES = [
    ("vexalune", "vexalune님의블로그 : 네이버 블로그", "Naver Blog"),
    ("vexalune", "vexalune's porn videos and reels, nude photos and bio", "xHamster"),
    ("PublicRefCh", "PublicRefCh — профиль игрока Minecraft, статистика и скин", "Minecraft"),
    ("vexalune", "vexalune — Bio Sites", "Bio Sites"),
    ("vexalune", "Mommy Vexa on Premium Chat", "Kwai"),
    ("vexalune", "Vexalune&#039;s Profil", "mydealz"),
    ("publicrefb", "publicrefbさんのプロフィール - はてな", "Hatena"),
    ("publicrefb", "Make Your Day", "Kwai"),
    ("publicrefb", "Steam Community :: Publicref", "Steam"),
    ("vexalune", "GIFs on GIPHY - Be Animated", "Giphy"),
    ("PublicRefA", "Carol Anne has 1 book on Goodreads", "Goodreads"),
    ("PublicRefA", "Rank (osu): Global #1,298,706 | Country #37,222", "osu!"),
    ("PublicRefA", "Ingrid Testova profile information and Fameswap history", "Fameswap"),
]


@pytest.mark.parametrize(("nick", "title", "site"), WRONG_TITLES)
@pytest.mark.parametrize("tag", ["og:title", "twitter:title"])
def test_template_titles_from_live_sample_give_no_display_name(nick, title, site, tag):
    attr = "property" if tag.startswith("og") else "name"
    body = f'<meta {attr}="{tag}" content="{title}"><title>{title}</title>'
    assert "display_name" not in fields(run(body, nick=nick, name=site))


def test_site_suffix_is_stripped_even_when_the_title_spaces_the_host_name():
    # The catalog calls the site "premium.chat"; the page title says "Premium Chat".
    result = run(og("Mommy Vexa on Premium Chat"), nick="vexalune", name="premium.chat")
    assert fields(result)["display_name"] == "Mommy Vexa"


@pytest.mark.parametrize(
    "title",
    [
        "Ingrid Testova (@PublicRefA) on Kwai",
        "Ingrid Testova | Kwai",
        "Kwai - Ingrid Testova",
        "Ingrid Testova",
        "Anna María",
    ],
)
def test_plain_names_with_site_suffix_are_kept(title):
    assert fields(run(og(title)))["display_name"].startswith(("Ingrid Testova", "Anna"))


@pytest.mark.parametrize(
    "title",
    [
        "One Two Three Four Five",
        "A Name With 1234567",
        "Alexander Maximilian Bartholomew Montgomery",
        "Ala: Ma Kota",
        "Jean's Place",
    ],
)
def test_names_that_are_too_long_numeric_or_templated_are_rejected(title):
    assert "display_name" not in fields(run(og(title)))


# Meta descriptions are site templates, statistics or marketing: never a bio or description.
WRONG_DESCRIPTIONS = [
    "Carol Anne has 1 book on Goodreads",
    "Rank (osu): Global #1,298,706 | Country #37,222",
    "Check out PublicRefA's newest porn videos, nude photo galleries on xHamster.",
    "Ingrid Testova (@PublicRefA) on Kwai | 122 Like(s). 242 Followers. Watch the latest video",
    "PublicRefA profile information and Fameswap history",
    "263.7K Followers • 0 Threads • The Internet's Chess Teacher. See the latest conversations",
    "Host your images online with an easy to use image uploader, albums, photo hosting",
    "PublicRefA's profile page. Share your pics and videos. Every day, thousands join",
    "The home of the Rockstar Games' modification frameworks for GTAV and Red Dead Redemption 2.",
    "World chess champion and streamer from Norway",
]


@pytest.mark.parametrize("text", WRONG_DESCRIPTIONS)
@pytest.mark.parametrize(
    "tag", ['property="og:description"', 'name="twitter:description"', 'name="description"']
)
def test_meta_descriptions_never_become_bio_or_description(text, tag):
    values = fields(run(f'<meta {tag} content="{text}"><title>Ingrid Testova on Kwai</title>'))
    assert "bio" not in values and "description" not in values


@pytest.mark.parametrize(
    "path",
    [
        "/avatars/123.jpg",
        "/u/9f3a/photo.JPEG",
        "/a/b.webp",
        "/a/b.gif",
        "/a/b.avif",
        "/media/a.png?size=200",
        "/user/42/picture",
    ],
)
def test_image_with_extension_or_avatar_segment_is_an_avatar(path):
    body = f'<meta property="og:image" content="https://cdn.kwai.net{path}">'
    assert fields(run(body))["avatar_url"] == f"https://cdn.kwai.net{path}"


@pytest.mark.parametrize(
    "image",
    [
        "https://cdn.robertsspaceindustries.com/static",
        "https://cdn.kwai.net/",
        "https://cdn.kwai.net/static/",
        "https://cdn.kwai.net/avatars/",
        "https://cdn.kwai.net/user/static",
        "https://cdn.kwai.net/u/9f3a/photo",
        "https://cdn.kwai.net/media/a.svg",
    ],
)
def test_truncated_or_directory_like_image_gives_no_avatar(image):
    body = f'<meta property="og:image" content="{image}">'
    assert "avatar_url" not in fields(run(body))


@pytest.mark.parametrize(
    "image",
    [
        "https://cdn.kwai.net/static/logo.png",
        "https://cdn.kwai.net/img/default-user.png",
        "https://cdn.kwai.net/placeholder.jpg",
        "https://cdn.kwai.net/og-image.png",
        "https://cdn.kwai.net/share/card.jpg",
        "https://cdn.kwai.net/banner/1.jpg",
        "https://cdn.kwai.net/brand/a.jpg",
        "https://cdn.kwai.net/favicon.ico",
        "data:image/png;base64,AAAA",
        "javascript:alert(1)",
    ],
)
def test_logo_like_or_non_http_image_gives_no_avatar(image):
    body = f'<title>Ingrid Testova on Kwai</title><meta property="og:image" content="{image}">'
    assert "avatar_url" not in fields(run(body))


def test_image_matching_favicon_path_is_rejected():
    body = (
        '<link rel="icon" href="/static/i/a.png">'
        '<meta property="og:image" content="https://www.kwai.com/static/i/a.png">'
    )
    assert "avatar_url" not in fields(run(body))


def test_existing_extractors_take_precedence():
    body = (
        '<link rel="canonical" href="https://www.kwai.com/@alice">'
        '<meta property="og:type" content="profile">'
        '<meta property="profile:username" content="alice">'
        '<meta property="og:title" content="Alicja Testowa">'
        '<meta property="og:description" content="Fixture bio of Alicja here">'
        '<meta property="og:image" content="https://cdn.kwai.net/alice.jpg">'
        '<meta name="twitter:title" content="Other Name">'
        '<meta name="twitter:description" content="Totally different words here">'
        '<meta name="twitter:image" content="https://cdn.kwai.net/other.jpg">'
        "<title>Other Title on Kwai</title>"
    )
    result = run(body, nick="alice")
    values = fields(result)
    assert values["display_name"] == "Alicja Testowa"
    assert values["avatar_url"] == "https://cdn.kwai.net/alice.jpg"
    assert values["description"] == "Fixture bio of Alicja here"
    assert not [c for c in result.candidates if c.extractor == "PageMetaExtractor"]


def test_adapter_display_name_blocks_page_meta_but_other_fields_still_fill():
    class Adapter:
        def extract(self, document, context):
            context.add("display_name", "Adapter Name", "Adapter", "x", EvidenceQuality.HIGH, 10)

    page_meta = tuple(e for e in EXTRACTORS if isinstance(e, PageMetaExtractor))
    assert page_meta
    result = run(KWAI, extractors=(Adapter(), *page_meta))
    values = fields(result)
    assert values["display_name"] == "Adapter Name"
    assert "PageMetaExtractor" not in {
        c.extractor for c in result.candidates if c.name == "display_name"
    }
    assert values["avatar_url"] == "https://cdn.kwai.net/u/9f3a/photo.jpg"
    assert "bio" not in values


def test_not_run_for_non_profile_verdicts():
    result = run(KWAI, verdict=Verdict.NOT_FOUND)
    assert result.state == MetadataState.UNAVAILABLE and not result.candidates


def test_page_never_mentioning_the_handle_is_not_trusted():
    body = "<title>Twitter / X</title>" + KWAI
    assert fields(run(body, nick="zzz", mentions_nick=False)) == {}


def test_contradicted_owner_binding_blocks_page_meta():
    body = (
        '<link rel="canonical" href="https://www.kwai.com/@alice">'
        '<meta property="og:type" content="profile">'
        '<meta property="profile:username" content="bob">'
        '<meta property="og:title" content="Alicja Testowa">'
        '<meta property="og:image" content="https://cdn.kwai.net/alice.jpg">'
    )
    assert fields(run(body, nick="alice")) == {}
