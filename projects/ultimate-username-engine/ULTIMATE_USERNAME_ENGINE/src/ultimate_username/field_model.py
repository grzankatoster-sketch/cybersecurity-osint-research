"""Analytical usefulness is independent of evidence quality and probability."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FieldGroup(StrEnum):
    IDENTITY = "IDENTITY"
    CORRELATION = "CORRELATION"
    PROFILE_CONTEXT = "PROFILE_CONTEXT"
    ACCOUNT_INFO = "ACCOUNT_INFO"
    PUBLIC_ACTIVITY = "PUBLIC_ACTIVITY"
    MEDIA = "MEDIA"
    TECHNICAL = "TECHNICAL"


class Usefulness(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    TECHNICAL = "TECHNICAL"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    group: FieldGroup
    usefulness: Usefulness


GROUPS = {
    FieldGroup.IDENTITY: ("username", "display_name", "user_id", "profile_url"),
    FieldGroup.CORRELATION: (
        "website",
        "external_links",
        "linked_accounts",
        "twitter_username",
        "github_username",
        "email",
        "node_id",
        "same_username_references",
    ),
    FieldGroup.PROFILE_CONTEXT: (
        "bio",
        "description",
        "location",
        "language",
        "company",
        "account_type",
        "category",
        "tags",
    ),
    FieldGroup.ACCOUNT_INFO: (
        "created_at",
        "updated_at",
        "latest_activity_at",
        "verified",
        "is_looking_for_job",
        "joined_text",
    ),
    FieldGroup.PUBLIC_ACTIVITY: (
        "followers",
        "following",
        "posts",
        "public_repos_count",
        "public_gists_count",
        "xenforo_points",
    ),
    FieldGroup.MEDIA: ("avatar_url", "banner_url"),
}
HIGH = frozenset(
    {
        "username",
        "user_id",
        "display_name",
        "profile_url",
        "avatar_url",
        "website",
        "external_links",
        "linked_accounts",
        "twitter_username",
        "email",
        "node_id",
        "location",
    }
)


def field_spec(name: str) -> FieldSpec:
    for group, fields in GROUPS.items():
        if name in fields:
            return FieldSpec(group, Usefulness.HIGH if name in HIGH else Usefulness.MEDIUM)
    return FieldSpec(FieldGroup.TECHNICAL, Usefulness.TECHNICAL)


def generic_value(name: str, value: str, site_name: str) -> bool:
    """Small exact denylist, not a classifier of arbitrary people's names/bios."""
    text = value.strip().casefold()
    if name == "avatar_url":
        return any(
            marker in text
            for marker in ("/default-avatar.", "/default_avatar.", "/avatar-default.")
        )
    if name not in ("display_name", "bio", "description"):
        return False
    return text in {
        site_name.strip().casefold(),
        "sign in",
        "log in",
        "login",
        "access denied",
        "page not found",
        "404 not found",
        "just a moment...",
        "accept all cookies",
        "twitch is the world's leading video platform and community for gamers.",
    }
