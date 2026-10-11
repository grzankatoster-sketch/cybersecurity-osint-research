"""identity_score: each signal alone, combination, contradictions, seed, avatars, determinism."""

from __future__ import annotations

import asyncio
import io
import json
import math
import random

import pytest

from ultimate_username.domain.metadata import (
    EvidenceQuality,
    FieldCandidate,
    MetadataState,
    ProfileMetadata,
)
from ultimate_username.domain.models import (
    DetectionResult,
    SearchResult,
    TransportResponse,
    Username,
    Verdict,
)
from ultimate_username.identity import (
    DEFAULT_CONFIG,
    NO_IDENTITY_DATA,
    IdentityConfig,
    IdentityDecision,
    IdentitySeed,
    extract_link_keys,
    fetch_avatar_hashes,
    fetch_avatar_records,
    hamming,
    identity_document,
    phash_image,
    phash_pixels,
    result_key,
    score_identities,
    url_key,
)
from ultimate_username.transport import FakeTransport

NICK = "vexalune"


def make(
    site: str,
    url: str | None = None,
    *,
    nick: str = NICK,
    verdict: Verdict = Verdict.FOUND,
    extra: dict[str, object] | None = None,
    conflicts: tuple[str, ...] = (),
    **values: object,
) -> SearchResult:
    url = url if url is not None else f"https://{site}.example/{nick}"

    def candidate(name: str, value: object) -> FieldCandidate:
        return FieldCandidate(
            name,
            value,
            site,
            url,
            "test",
            "fixture",
            "2026-10-10",
            EvidenceQuality.HIGH,
            5,  # type: ignore[arg-type]
        )

    metadata = ProfileMetadata(
        state=MetadataState.SUCCESS,
        fields=tuple(candidate(n, v) for n, v in values.items()),
        extra_fields=tuple(candidate(n, v) for n, v in (extra or {}).items()),
        conflicts=conflicts,
    )
    return SearchResult(
        "job",
        "task-" + site,
        site,
        Username(nick, nick, nick),
        DetectionResult(verdict=verdict),
        profile_url=url,
        canonical_service=site,
        profile_metadata=metadata,
    )


def only(assessments, site):
    return next(a for a in assessments.values() if a.site_id == site)


def kinds(assessment):
    return [s.kind for s in assessment.signals]


# ----------------------------------------------------------------------------- URL helpers


def test_url_key_normalises_scheme_www_query_case_and_twitter_alias():
    assert url_key("HTTPS://www.Twitch.TV/Vexalune/?ref=x#top") == "twitch.tv/vexalune"
    assert url_key("twitter.com/Vexalune") == url_key("https://x.com/vexalune/")
    assert url_key("https://m.youtube.com/@Vexa") == "youtube.com/@vexa"
    assert url_key("not a url") == "" and url_key("") == "" and url_key("localhost/x") == ""


def test_extract_link_keys_urls_schemeless_and_platform_handles():
    text = "Sub: https://www.twitch.tv/Vexalune. ig: @vexalune, mail me@gmail.com, yt @vexa"
    keys = extract_link_keys(text)
    assert "twitch.tv/vexalune" in keys
    assert "instagram.com/vexalune" in keys
    assert "youtube.com/@vexa" in keys
    assert not any("gmail" in k for k in keys)
    assert extract_link_keys("follow @vexalune everywhere") == set()  # platformless handle ignored
    assert "tiktok.com/@vexa" in extract_link_keys("my tiktok.com/@Vexa page")


# ----------------------------------------------------------------------------- control signals


def test_reciprocal_link_between_two_hits_scores_085():
    a = make(
        "twitter", "https://twitter.com/vexalune", bio="Streams at https://www.twitch.tv/Vexalune/"
    )
    b = make(
        "twitch", "https://www.twitch.tv/vexalune", description="also on x.com/vexalune?lang=en"
    )
    out = score_identities([a, b])
    for site in ("twitter", "twitch"):
        assessment = only(out, site)
        assert kinds(assessment) == ["link_reciprocal"]
        assert assessment.score == 0.85
        assert assessment.decision == IdentityDecision.TARGET_LIKELY
        assert assessment.signals[0].group == "control"
    signal = only(out, "twitter").signals[0]
    assert signal.fields == ("bio",) and signal.sources == ("https://www.twitch.tv/vexalune",)


def test_one_way_link_scores_070_for_both_ends_and_other_hits_are_untouched():
    a = make("twitter", "https://twitter.com/vexalune", bio="live: twitch.tv/vexalune")
    b = make("twitch", "https://www.twitch.tv/vexalune", bio="hi")
    c = make("reddit", "https://reddit.com/user/vexalune", bio="hello")
    out = score_identities([a, b, c])
    assert only(out, "twitter").score == only(out, "twitch").score == 0.7
    assert kinds(only(out, "twitter")) == kinds(only(out, "twitch")) == ["link_oneway"]
    assert only(out, "reddit").score == 0.0 and only(out, "reddit").decision == "UNDETERMINED"


def test_platform_handle_mention_links_to_the_matching_hit():
    a = make("twitter", "https://twitter.com/vexalune", bio="ig: @vexalune")
    b = make("instagram", "https://www.instagram.com/vexalune/", bio="x")
    out = score_identities([a, b])
    assert kinds(only(out, "instagram")) == ["link_oneway"]


def test_links_in_extra_fields_and_external_links_count():
    a = make("github", "https://github.com/vexalune", website="https://twitch.tv/vexalune")
    b = make(
        "twitch",
        "https://twitch.tv/vexalune",
        extra={"blog_note": "see https://github.com/vexalune"},
    )
    assert kinds(only(score_identities([a, b]), "github")) == ["link_reciprocal"]
    c = make("kick", "https://kick.com/vexalune", external_links=("https://github.com/vexalune",))
    assert "link_oneway" in kinds(only(score_identities([a, c]), "kick"))


def test_same_account_seen_twice_is_not_a_link():
    a = make("twitch", "https://twitch.tv/vexalune", bio="https://www.twitch.tv/vexalune")
    b = make("twitch", "https://twitch.tv/vexalune/", bio="x", nick=NICK)
    assert score_identities([a, b])[a.profile_url].score == 0.0


def test_verified_alone_reaches_threshold_but_only_as_control():
    out = score_identities([make("twitter", verified=True), make("kick", verified=False)])
    assert only(out, "twitter").score == 0.5
    assert only(out, "twitter").decision == "TARGET_LIKELY"
    assert only(out, "twitter").signals[0].group == "control"
    assert only(out, "kick").signals == () and only(out, "kick").decision == "UNDETERMINED"


# ----------------------------------------------------------------------------- copyable signals


def test_seed_name_match_by_tokens_and_not_nick():
    seed = IdentitySeed(name="Alune Orvo")
    good = make("twitter", display_name="Alune “vexalune” Orvo")
    half = make("kick", display_name="Alune")  # Jaccard 0.5 < 0.6
    out = score_identities([good, half], seed)
    assert kinds(only(out, "twitter")) == ["seed_name_match"] and only(out, "twitter").score == 0.6
    assert only(out, "twitter").decision == "TARGET_LIKELY" and only(out, "twitter").seed_used
    assert only(out, "kick").signals == () and not only(out, "kick").seed_used
    nick_only = score_identities(
        [make("x", display_name="VexaLune")], IdentitySeed(name="Vexa Lune")
    )
    assert nick_only["https://x.example/vexalune"].signals == ()


def test_seed_name_matching_ignores_diacritics_and_order():
    out = score_identities(
        [make("a", display_name="Fixtur, Lena")], IdentitySeed(name="Łéna Fixtur")
    )
    assert kinds(next(iter(out.values()))) == ["seed_name_match"]


def test_same_display_name_needs_two_hits_length_4_and_not_the_nick():
    a = make("twitter", display_name="Alune Orvo")
    b = make("kick", display_name="alune  orvo")
    c = make("reddit", display_name="Pok")
    d = make("tiktok", display_name="Pok")
    e = make("vk", display_name="VexaLune")
    f = make("ok", display_name="VexaLune")
    out = score_identities([a, b, c, d, e, f])
    assert kinds(only(out, "twitter")) == ["same_display_name"]
    assert only(out, "twitter").score == 0.35 and only(out, "twitter").decision == "UNDETERMINED"
    assert only(out, "reddit").signals == ()  # "Pok" is < 4 characters
    assert only(out, "vk").signals == ()  # equals the searched nick


def test_page_title_and_service_name_display_names_are_not_evidence():
    a = make("audiojungle", display_name="vexalune's profile on AudioJungle")
    b = make("videohive", display_name="vexalune's profile on AudioJungle")
    c = make("cashapp", display_name="Pay me on Cashapp")
    d = make("cashapp2", display_name="Pay me on Cashapp", canonical_service="cashapp")
    out = score_identities([a, b, c, d])
    assert all(x.signals == () for x in out.values())


def test_similar_bio_jaccard_and_minimum_words():
    a = make("twitter", bio="Streamer gamer coffee lover living in Los Angeles")
    b = make("kick", bio="streamer, gamer & coffee lover living in los angeles!")
    c = make("reddit", bio="Totally different text about knitting socks")
    short = make("vk", bio="Hello there friend")
    short2 = make("ok", bio="Hello there friend")
    out = score_identities([a, b, c, short, short2])
    assert kinds(only(out, "twitter")) == ["similar_bio"] and only(out, "twitter").score == 0.35
    assert only(out, "reddit").signals == ()
    assert only(out, "vk").signals == ()  # fewer than 4 words


def test_same_location_after_normalisation():
    a = make("twitter", location="Los Angeles, CA")
    b = make("kick", location="los angeles ca")
    c = make("reddit", location="Paris")
    out = score_identities([a, b, c])
    assert kinds(only(out, "twitter")) == ["same_location"] and only(out, "twitter").score == 0.2
    assert only(out, "reddit").signals == ()


def test_reach_is_a_supporting_signal_only():
    lone = score_identities([make("twitter", followers=5_000_000)])
    assert next(iter(lone.values())).signals == () and next(iter(lone.values())).score == 0.0
    a = make("twitter", followers="1.2M", location="Los Angeles")
    b = make("kick", followers=900, location="Los Angeles")
    out = score_identities([a, b])
    assert kinds(only(out, "twitter")) == ["reach", "same_location"] or set(
        kinds(only(out, "twitter"))
    ) == {
        "reach",
        "same_location",
    }
    assert (
        only(out, "twitter").score == 0.3
    )  # max of the copyable group (0.30 reach > 0.20 location)
    assert kinds(only(out, "kick")) == ["same_location"]


# ----------------------------------------------------------------------------- avatars


def test_identical_avatar_url_signal_and_default_and_boilerplate_exclusions():
    shared = "https://cdn.example/u/vexalune-1.png"
    a = make("twitter", avatar_url=shared)
    b = make("kick", avatar_url=shared)
    out = score_identities([a, b])
    assert kinds(only(out, "twitter")) == ["same_avatar"] and only(out, "twitter").score == 0.5

    default = "https://cdn.example/default_profile.png"
    out = score_identities([make("a", avatar_url=default), make("b", avatar_url=default)])
    assert all(x.signals == () for x in out.values())

    boiler = "https://cdn.example/family/logo.png"
    out = score_identities([make(s, avatar_url=boiler) for s in ("a", "b", "c")])
    assert all(x.signals == () for x in out.values())  # same URL on 3 hits = boilerplate


def test_avatar_hash_signal_distance_threshold():
    a = make("twitter", avatar_url="https://i.example/1.jpg")
    b = make("kick", avatar_url="https://j.example/2.jpg")
    base = 0x0F0F_0F0F_0F0F_0F0F
    near = base ^ 0b111111  # 6 bits
    far = base ^ 0b1111111  # 7 bits
    out = score_identities(
        [a, b],
        avatar_hashes={
            a.profile_metadata.get("avatar_url"): base,
            b.profile_metadata.get("avatar_url"): near,
        },
    )
    assert kinds(only(out, "twitter")) == ["same_avatar"]
    assert "pHash distance 6" in only(out, "twitter").signals[0].detail
    out = score_identities(
        [a, b], avatar_hashes={"https://i.example/1.jpg": base, "https://j.example/2.jpg": far}
    )
    assert only(out, "twitter").signals == ()


def test_avatar_hash_boilerplate_cluster_of_three_is_disabled():
    hits = [make(s, avatar_url=f"https://{s}.cdn/a.png") for s in ("a", "b", "c")]
    hashes = {h.profile_metadata.get("avatar_url"): 0xABCDEF for h in hits}
    out = score_identities(hits, avatar_hashes=hashes)
    assert all(x.signals == () for x in out.values())
    out = score_identities(hits[:2], avatar_hashes=hashes)
    assert all(kinds(x) == ["same_avatar"] for x in out.values())


def test_avatar_never_stands_alone_above_the_copyable_cap():
    a = make("twitter", avatar_url="https://cdn.example/x.png")
    b = make("kick", avatar_url="https://cdn.example/x.png")
    cfg = IdentityConfig(w_avatar=0.99)
    out = score_identities([a, b], config=cfg)
    assert only(out, "twitter").score == 0.7  # copyable_cap


# ----------------------------------------------------------------------------- combining


def test_combination_formula_control_plus_capped_copyable_group():
    a = make(
        "twitter",
        "https://twitter.com/vexalune",
        bio="Streamer gamer coffee lover living in Los Angeles twitch.tv/vexalune",
        display_name="Alune Orvo",
        location="Los Angeles",
        verified=True,
    )
    b = make(
        "twitch",
        "https://twitch.tv/vexalune",
        bio="Streamer gamer coffee lover living in Los Angeles https://x.com/vexalune",
        display_name="Alune Orvo",
        location="Los Angeles",
    )
    assessment = only(score_identities([a, b]), "twitter")
    assert set(kinds(assessment)) == {
        "link_reciprocal",
        "verified",
        "same_display_name",
        "similar_bio",
        "same_location",
    }
    # control: 0.85 and 0.50; copyable group counts once: max(0.35, 0.35, 0.20) = 0.35
    expected = 1 - (1 - 0.85) * (1 - 0.5) * (1 - 0.35)
    assert assessment.score == pytest.approx(min(0.95, expected), abs=1e-4)
    assert assessment.score == 0.95  # also the global ceiling


def test_ceiling_095_and_copyable_group_uses_only_the_strongest_signal():
    many = make(
        "twitter",
        display_name="Alune Orvo",
        location="Los Angeles",
        bio="Streamer gamer coffee lover living in Los Angeles",
    )
    other = make(
        "kick",
        display_name="Alune Orvo",
        location="Los Angeles",
        bio="Streamer gamer coffee lover living in Los Angeles",
    )
    assessment = only(score_identities([many, other]), "twitter")
    assert len(assessment.signals) == 3
    assert assessment.score == 0.35  # not 1 - 0.65 * 0.65 * 0.8


def test_contradiction_beats_a_high_score():
    bad = make("kick", verified=True, bio="i am not the real vexalune", display_name="x")
    other = make("twitch", bio="see kick.com/vexalune")
    out = score_identities([bad, other])
    assessment = only(out, "kick")
    assert assessment.score == 0.15 and assessment.decision == "UNRELATED_LIKELY"
    assert "impersonation_marker" in kinds(assessment)
    marker = next(s for s in assessment.signals if s.kind == "impersonation_marker")
    assert marker.group == "contradiction" and marker.weight == 0 and marker.fields == ("bio",)


@pytest.mark.parametrize(
    "text",
    [
        "Fan account of Vexalune",
        "official FANPAGE",
        "this is a parody",
        "totally fake",
        "Unofficial profile",
        "Nie jestem prawdziwą Vexalune",
        "konto fanowskie",
        "Это не настоящий аккаунт",
        "фан-аккаунт",
        "cuenta de fans",
        "kein echter Account",
        "非官方账号",
    ],
)
def test_impersonation_markers_in_many_languages(text):
    out = score_identities([make("kick", verified=True, bio=text)])
    assessment = next(iter(out.values()))
    assert assessment.decision == "UNRELATED_LIKELY" and assessment.score <= 0.15


def test_ordinary_bios_are_not_contradictions():
    out = score_identities(
        [make("kick", verified=True, bio="Streamer. Big fan of coffee and cats.")]
    )
    assert next(iter(out.values())).decision == "TARGET_LIKELY"


def test_seed_name_conflict_needs_two_tokens_on_both_sides():
    seed = IdentitySeed(name="Alune Orvo")
    other = make("kick", display_name="Jan Kowalski", verified=True)
    one_token = make("vk", display_name="Kowalski", verified=True)
    out = score_identities([other, one_token], seed)
    assert only(out, "kick").decision == "UNRELATED_LIKELY" and only(out, "kick").score == 0.15
    assert only(out, "kick").seed_used
    assert only(out, "vk").decision == "TARGET_LIKELY"
    assert (
        score_identities([other])[other.profile_url].decision == "TARGET_LIKELY"
    )  # no seed, no conflict
    assert (
        score_identities([other], IdentitySeed(name="Alune"))[other.profile_url].decision
        == "TARGET_LIKELY"
    )


# ----------------------------------------------------------------------------- no data, seed URLs


def test_no_data_gives_no_identity_data_with_score_zero():
    empty = make("kick")
    out = score_identities([empty])
    assessment = out[empty.profile_url]
    assert assessment.score == 0.0 and assessment.decision == "UNDETERMINED"
    assert [s.kind for s in assessment.signals] == [NO_IDENTITY_DATA]
    with_data = score_identities([make("kick", bio="hello")])
    assert (
        next(iter(with_data.values())).signals == ()
    )  # data but nothing to compare: not "no data"


def test_inbound_link_alone_is_not_no_data():
    a = make("twitter", "https://twitter.com/vexalune", bio="twitch.tv/vexalune")
    b = make("twitch", "https://twitch.tv/vexalune")
    assert kinds(only(score_identities([a, b]), "twitch")) == ["link_oneway"]


def test_seed_urls_matching_and_linking():
    seed = IdentitySeed(urls=("https://www.GitHub.com/Vexa/",))
    own = make("github", "https://github.com/vexa")
    linker = make("twitch", "https://twitch.tv/vexa2", bio="code: github.com/vexa")
    stranger = make("kick", "https://kick.com/vexa", bio="hello")
    out = score_identities([own, linker, stranger], seed)
    assert kinds(only(out, "github")) == ["seed_url_match"] and only(out, "github").score == 0.85
    assert kinds(only(out, "twitch")) == ["link_to_seed"] and only(out, "twitch").score == 0.7
    assert only(out, "github").seed_used and only(out, "twitch").seed_used
    assert only(out, "kick").signals == () and not only(out, "kick").seed_used
    plain = score_identities([own, linker])  # no seed: an ordinary one-way link
    assert kinds(only(plain, "github")) == kinds(only(plain, "twitch")) == ["link_oneway"]
    # the seed account linking back makes the link reciprocal
    back = make("github", "https://github.com/vexa", bio="twitch.tv/vexa2")
    both = score_identities([back, linker], seed)
    assert set(kinds(only(both, "github"))) == {"seed_url_match", "link_reciprocal"}
    assert only(both, "github").score == 0.95
    assert kinds(only(both, "twitch")) == ["link_reciprocal"]  # the seed link is not counted twice


def test_empty_seed_is_the_same_as_no_seed():
    hits = [make("a", display_name="Alune Orvo"), make("b", display_name="Alune Orvo")]
    assert score_identities(hits, IdentitySeed()) == score_identities(hits, None)


# ----------------------------------------------------------------------------- robustness


def test_non_hits_are_not_scored_and_missing_fields_do_not_crash():
    weird = make("odd", None, followers="lots", verified="maybe", location=("a", "b"), bio=5)
    missing = make("kick", "")
    absent = make("gone", verdict=Verdict.NOT_FOUND, verified=True)
    unknown = make("unk", verdict=Verdict.UNKNOWN)
    out = score_identities([weird, missing, absent, unknown])
    assert set(out) == {weird.profile_url, "site:kick"}
    assert result_key(missing) == "site:kick"


def test_conflicting_fields_are_ignored():
    out = score_identities(
        [make("kick", verified=True, conflicts=("verified",)), make("x", display_name="Alune Orvo")]
    )
    assert only(out, "kick").signals[0].kind == NO_IDENTITY_DATA or only(out, "kick").signals == ()
    assert only(out, "kick").score == 0.0


def test_result_is_deterministic_and_independent_of_input_order():
    hits = [
        make(
            "twitter",
            "https://twitter.com/vexalune",
            bio="twitch.tv/vexalune",
            display_name="Alune Orvo",
            verified=True,
        ),
        make(
            "twitch", "https://twitch.tv/vexalune", bio="x.com/vexalune", display_name="Alune Orvo"
        ),
        make("kick", display_name="Alune Orvo", location="LA"),
        make("reddit", location="LA", bio="not the real one"),
        make("vk"),
    ]
    baseline = score_identities(hits, IdentitySeed(name="Alune Orvo"))
    for seed_value in range(5):
        shuffled = hits[:]
        random.Random(seed_value).shuffle(shuffled)
        assert score_identities(shuffled, IdentitySeed(name="Alune Orvo")) == baseline
    assert list(baseline) == sorted(baseline)
    assert json.dumps(identity_document(baseline), sort_keys=True) == json.dumps(
        identity_document(score_identities(hits, IdentitySeed(name="Alune Orvo"))), sort_keys=True
    )


# ----------------------------------------------------------------------------- configuration


def test_threshold_is_a_parameter_and_weights_are_tunable():
    hit = make("twitter", verified=True)
    assert next(iter(score_identities([hit]).values())).decision == "TARGET_LIKELY"
    strict = IdentityConfig(threshold=0.6)
    assert next(iter(score_identities([hit], config=strict).values())).decision == "UNDETERMINED"
    weak = IdentityConfig(w_verified=0.1)
    assert next(iter(score_identities([hit], config=weak).values())).score == 0.1


def test_config_from_mapping_and_file_validation(tmp_path):
    cfg = IdentityConfig.from_mapping({"threshold": 0.7, "bio_min_words": 3})
    assert cfg.threshold == 0.7 and cfg.bio_min_words == 3 and cfg.w_verified == 0.5
    for bad in (
        {"nope": 1},
        {"threshold": "x"},
        {"threshold": 1.5},
        {"bio_min_words": 2.5},
        {"w_avatar": -1},
    ):
        with pytest.raises(ValueError):
            IdentityConfig.from_mapping(bad)
    path = tmp_path / "w.json"
    path.write_text(json.dumps({"w_avatar": 0.4}), encoding="utf-8")
    assert IdentityConfig.load(path).w_avatar == 0.4
    assert DEFAULT_CONFIG.to_mapping()["threshold"] == 0.5
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        IdentityConfig.load(path)


# ----------------------------------------------------------------------------- pHash


def _blob(cx, cy, tilt=0.0):
    return [
        255 * math.exp(-((x - cx) ** 2 + (y - cy) ** 2) / 60) + tilt * x
        for y in range(32)
        for x in range(32)
    ]


def test_phash_pixels_is_stable_and_separates_different_images():
    base = _blob(11, 14)
    noisy = [v + (2 if i % 5 == 0 else -1) for i, v in enumerate(base)]
    other = _blob(24, 20, 1.5)
    assert phash_pixels(base) == phash_pixels(list(base))
    assert hamming(phash_pixels(base), phash_pixels(noisy)) <= 6
    assert hamming(phash_pixels(base), phash_pixels(other)) > 12
    with pytest.raises(ValueError):
        phash_pixels([0.0] * 10)


def _png(draw) -> bytes:
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (96, 96), (240, 240, 240))
    draw(ImageDraw.Draw(image))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def _face(d, shift=0):
    d.ellipse((20 + shift, 18, 76 + shift, 74), fill=(30, 30, 30))
    d.rectangle((10, 70, 86, 95), fill=(200, 60, 60))


def test_phash_image_near_identical_small_distance_different_large():
    pytest.importorskip("PIL")
    a = phash_image(_png(lambda d: _face(d)))
    a_slight = phash_image(_png(lambda d: (_face(d), d.point((3, 3), fill=(250, 250, 250)))))
    different = phash_image(
        _png(
            lambda d: [
                d.rectangle((0, i * 12, 96, i * 12 + 5), fill=(20, 20, 200)) for i in range(8)
            ]
        )
    )
    assert a is not None and a_slight is not None and different is not None
    assert hamming(a, a_slight) <= 6
    assert hamming(a, different) > 12
    assert phash_image(b"not an image") is None
    assert phash_image(_png(lambda d: None)) is None  # flat placeholder is not hashed


def test_fetch_avatar_hashes_budget_limit_boilerplate_and_failures():
    pytest.importorskip("PIL")
    face = _png(lambda d: _face(d))
    other = _png(lambda d: _face(d, 6))
    hits = [
        make("twitter", avatar_url="https://img.example/a.png"),
        make("kick", avatar_url="https://img.example/b.png"),
        make("vk", avatar_url="https://img.example/default_avatar.png"),
        make("ok", avatar_url="https://img.example/big.png"),
        make("tt", avatar_url="http://127.0.0.1/secret.png"),
        make("gone", avatar_url="https://img.example/gone.png"),
        make("none"),
    ]
    big = TransportResponse("https://img.example/big.png", 200, b"x" * 100, body_complete=False)

    def respond(request, index):
        url = request.url
        assert request.body_limit == 5 * 1024 * 1024
        return {
            "https://img.example/a.png": TransportResponse(url, 200, face),
            "https://img.example/b.png": TransportResponse(url, 200, other),
            "https://img.example/big.png": big,
        }.get(url, TransportResponse(url, 404))

    transport = FakeTransport(handler=respond)
    records = asyncio.run(fetch_avatar_records(hits, transport))
    requested = {r.url for r in transport.requests}
    assert requested == {
        "https://img.example/a.png",
        "https://img.example/b.png",
        "https://img.example/big.png",
        "https://img.example/gone.png",
    }  # default placeholder and local address were never requested
    assert set(records) == {"https://img.example/a.png", "https://img.example/b.png"}
    record = records["https://img.example/a.png"]
    assert record.to_dict()["algorithm"] == "phash64-dct" and len(record.to_dict()["hash"]) == 16
    assert record.size_bytes == len(face)
    hashes = asyncio.run(fetch_avatar_hashes(hits, FakeTransport(handler=respond), budget=1))
    assert list(hashes) == ["https://img.example/a.png"]  # budget = 1 request
    assert asyncio.run(fetch_avatar_hashes(hits, FakeTransport(handler=respond), budget=0)) == {}
    # the two shifted portraits are close, so the hash signal fires through score_identities
    out = score_identities(hits[:2], avatar_hashes=hashes_for(records))
    assert kinds(only(out, "twitter")) == ["same_avatar"]


def hashes_for(records):
    return {u: r.phash for u, r in records.items()}


def test_fetch_avatar_hashes_survives_transport_exceptions():
    pytest.importorskip("PIL")

    def boom(request, index):
        raise RuntimeError("down")

    hits = [make("twitter", avatar_url="https://img.example/a.png")]
    assert asyncio.run(fetch_avatar_hashes(hits, FakeTransport(handler=boom))) == {}


def test_identity_document_shape():
    a = make("twitter", verified=True)
    doc = identity_document(
        score_identities([a]),
        seed=IdentitySeed(name="X Y"),
        site_names={"twitter": "Twitter"},
    )
    assert doc["threshold"] == 0.5 and doc["seed"] == {"name": "X Y", "urls": []}
    profile = doc["profiles"][0]
    assert set(profile) == {"profile_url", "site", "score", "decision", "signals", "seed_used"}
    assert profile["site"] == "Twitter" and profile["decision"] == "TARGET_LIKELY"
    assert set(profile["signals"][0]) == {"kind", "weight", "group", "fields", "sources", "detail"}
    json.dumps(doc)
