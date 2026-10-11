"""E4: link graph between hits, related accounts outside the scan, SPEC name-conflict rule."""

from __future__ import annotations

import json
from dataclasses import replace

from ultimate_username.domain.metadata import (
    EvidenceQuality,
    FieldCandidate,
    MetadataState,
    ProfileMetadata,
)
from ultimate_username.domain.models import (
    DetectionResult,
    SearchResult,
    Username,
    Verdict,
)
from ultimate_username.identity import (
    IdentitySeed,
    identity_document,
    identity_graph,
    related_accounts,
    score_identities,
)

NICK = "vexalune"


def make(
    site: str,
    url: str | None = None,
    *,
    verdict: Verdict = Verdict.FOUND,
    conflicts: tuple[str, ...] = (),
    **values: object,
) -> SearchResult:
    url = url if url is not None else f"https://{site}.example/{NICK}"

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
        conflicts=conflicts,
    )
    return SearchResult(
        "job",
        "task-" + site,
        site,
        Username(NICK, NICK, NICK),
        DetectionResult(verdict=verdict),
        profile_url=url,
        canonical_service=site,
        profile_metadata=metadata,
    )


def only(assessments, site):
    return next(a for a in assessments.values() if a.site_id == site)


def kinds(assessment):
    return [s.kind for s in assessment.signals]


# ----------------------------------------------------------------------------- link graph


def test_graph_edges_use_external_links_website_and_bio_with_reciprocity():
    gh = make(
        "github",
        "https://github.com/vexalune",
        external_links=("https://twitch.tv/vexalune", "https://blog.example/x"),
    )
    tw = make("twitch", "https://twitch.tv/vexalune", website="https://github.com/vexalune")
    kick = make("kick", "https://kick.com/vexalune", bio="live on https://twitch.tv/vexalune")
    graph = identity_graph([gh, tw, kick])
    assert graph["nodes"] == sorted([gh.profile_url, tw.profile_url, kick.profile_url])
    edges = {(e["from"], e["to"]): e for e in graph["edges"]}
    assert set(edges) == {
        (gh.profile_url, tw.profile_url),
        (tw.profile_url, gh.profile_url),
        (kick.profile_url, tw.profile_url),
    }
    assert edges[(gh.profile_url, tw.profile_url)]["reciprocal"] is True
    assert edges[(gh.profile_url, tw.profile_url)]["source_field"] == "external_links"
    assert edges[(tw.profile_url, gh.profile_url)]["reciprocal"] is True
    assert edges[(tw.profile_url, gh.profile_url)]["source_field"] == "website"
    assert edges[(kick.profile_url, tw.profile_url)]["reciprocal"] is False
    assert edges[(kick.profile_url, tw.profile_url)]["source_field"] == "bio"
    assert "link_reciprocal" in kinds(only(score_identities([gh, tw, kick]), "github"))
    json.dumps(graph)


def test_graph_ignores_same_account_and_conflicting_fields_and_is_order_independent():
    a = make("twitch", "https://twitch.tv/vexalune", bio="https://www.twitch.tv/vexalune")
    b = make("twitch", "https://twitch.tv/vexalune/", bio="x")
    assert identity_graph([a, b])["edges"] == []
    c = make(
        "github",
        "https://github.com/vexalune",
        website="https://twitch.tv/vexalune",
        conflicts=("website",),
    )
    assert identity_graph([a, c])["edges"] == []
    d = make("github", "https://github.com/vexalune", website="https://twitch.tv/vexalune")
    assert identity_graph([a, d]) == identity_graph([d, a])
    assert identity_graph([]) == {"nodes": [], "edges": []}
    miss = make("kick", "https://kick.com/p", verdict=Verdict.NOT_FOUND)
    assert identity_graph([miss]) == {"nodes": [], "edges": []}


def test_graph_collects_links_from_every_candidate_of_a_field():
    first = make("github", "https://github.com/vexalune", external_links=("https://x.example/1",))
    second = make("github", "https://github.com/vexalune", external_links=("https://twitch.tv/p",))
    meta = first.profile_metadata
    merged = replace(
        first,
        profile_metadata=replace(meta, fields=meta.fields + second.profile_metadata.fields),
    )
    twitch = make("twitch", "https://twitch.tv/p")
    assert [(e["from"], e["to"]) for e in identity_graph([merged, twitch])["edges"]] == [
        (merged.profile_url, twitch.profile_url)
    ]


# ------------------------------------------------------------------------ related accounts


def test_related_accounts_are_known_platform_links_missing_from_hits():
    gh = make(
        "github",
        "https://github.com/vexalune",
        external_links=(
            "https://twitter.com/Vexa_Real",
            "https://www.instagram.com/Vexa.Real/",
            "https://blog.example/about",
            "https://twitch.tv/vexalune",
            "https://linktr.ee/Vexa",
            "https://t.me/vexachat",
            "https://mastodon.social/@vexa",
            "https://youtube.com/watch?v=abc",
            "https://github.com/vexalune",
        ),
        bio="discord: https://discord.gg/AbC123 and bsky.app/profile/vexa.bsky.social",
    )
    tw = make("twitch", "https://twitch.tv/vexalune")
    found = related_accounts([gh, tw])
    by_platform = {r["platform"]: r for r in found}
    assert set(by_platform) == {
        "x",
        "instagram",
        "linktree",
        "telegram",
        "mastodon",
        "discord",
        "bluesky",
    }
    assert by_platform["x"]["url"] == "https://twitter.com/Vexa_Real"  # original case kept
    assert by_platform["instagram"]["url"] == "https://www.instagram.com/Vexa.Real/"
    assert by_platform["discord"]["url"] == "https://discord.gg/AbC123"
    assert by_platform["x"]["from_profile"] == gh.profile_url
    assert by_platform["x"]["field"] == "external_links"
    assert by_platform["discord"]["field"] == "bio"
    assert all(set(r) == {"url", "platform", "from_profile", "field"} for r in found)
    assert not any("twitch" in r["url"] or "blog.example" in r["url"] for r in found)
    assert not any("youtube" in r["url"] for r in found)  # a video, not an account


def test_related_accounts_are_deduplicated_sorted_and_empty_without_hits():
    a = make("github", "https://github.com/p", bio="ig: @vexa tiktok.com/@vexa")
    b = make("kick", "https://kick.com/p", website="https://instagram.com/vexa")
    found = related_accounts([a, b])
    assert [(r["platform"], r["from_profile"]) for r in found] == [
        ("instagram", a.profile_url),
        ("instagram", b.profile_url),
        ("tiktok", a.profile_url),
    ]
    assert related_accounts([]) == []
    assert related_accounts([make("kick", verdict=Verdict.NOT_FOUND, bio="ig: @vexa")]) == []


def test_identity_document_carries_graph_and_related_accounts():
    gh = make("github", "https://github.com/vexalune", website="https://twitch.tv/vexalune")
    tw = make("twitch", "https://twitch.tv/vexalune", bio="https://x.com/vexa")
    assessments = score_identities([gh, tw])
    doc = identity_document(assessments, results=[gh, tw])
    assert doc["graph"]["nodes"] == sorted([gh.profile_url, tw.profile_url])
    assert [(e["from"], e["to"]) for e in doc["graph"]["edges"]] == [
        (gh.profile_url, tw.profile_url)
    ]
    assert doc["related_accounts"] == [
        {
            "url": "https://x.com/vexa",
            "platform": "x",
            "from_profile": tw.profile_url,
            "field": "bio",
        }
    ]
    json.dumps(doc)
    bare = identity_document(assessments)
    assert bare["graph"] == {"nodes": [], "edges": []} and bare["related_accounts"] == []


# ------------------------------------------------------------------- SPEC: name conflict


def test_single_word_pseudonym_is_no_conflict_but_two_unrelated_names_are():
    seed = IdentitySeed(name="Casey Fixton")
    pseudonym = make("kick", display_name="Publicref", verified=True)
    other_person = make("vk", display_name="Rosa Fixturez", verified=True)
    out = score_identities([pseudonym, other_person], seed)
    assert only(out, "kick").decision == "TARGET_LIKELY"
    assert "seed_name_conflict" not in kinds(only(out, "kick"))
    assert only(out, "vk").decision == "UNRELATED_LIKELY"
    assert "seed_name_conflict" in kinds(only(out, "vk"))
    one_word_seed = score_identities(
        [make("x", display_name="Alune Orvo", verified=True)], IdentitySeed(name="Publicref")
    )
    assert next(iter(one_word_seed.values())).decision == "TARGET_LIKELY"
    two = score_identities(
        [make("x", display_name="Rosa Fixturez", verified=True)],
        IdentitySeed(name="Alune Orvo"),
    )
    assert next(iter(two.values())).decision == "UNRELATED_LIKELY"
