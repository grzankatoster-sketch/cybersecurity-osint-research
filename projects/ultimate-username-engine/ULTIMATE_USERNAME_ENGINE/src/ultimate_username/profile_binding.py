"""Platform-scoped identity rules shared by detection and extraction."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit

from ultimate_username.domain.models import JSONValue, TransportResponse


def github_endpoint(url: str, username: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.netloc.lower() == "api.github.com"
            and not parsed.query
            and unquote(parsed.path).rstrip("/").casefold() == "/users/" + username.casefold()
        )
    except ValueError:
        return False


def github_response(response: TransportResponse, username: str) -> bool:
    return github_endpoint(response.requested_url, username) and github_endpoint(
        response.final_url or response.requested_url, username
    )


def github_profile_url(url: str, username: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.netloc.lower() in ("github.com", "www.github.com")
            and not parsed.query
            and not parsed.fragment
            and unquote(parsed.path).rstrip("/").casefold() == "/" + username.casefold()
        )
    except ValueError:
        return False


def github_object(value: JSONValue, response: TransportResponse, username: str) -> bool:
    if not isinstance(value, dict) or not github_response(response, username):
        return False
    login, uid, url = value.get("login"), value.get("id"), value.get("html_url")
    return (
        isinstance(login, str)
        and login.casefold() == username.casefold()
        and type(uid) is int
        and uid > 0
        and isinstance(url, str)
        and github_profile_url(url, username)
    )


def dev_object(value: JSONValue, response: TransportResponse, username: str) -> bool:
    if not isinstance(value, dict):
        return False
    for url in (response.requested_url, response.final_url or response.requested_url):
        parsed = urlsplit(url)
        if not (
            parsed.scheme == "https"
            and parsed.netloc == "dev.to"
            and parsed.path == "/api/users/by_username"
            and parse_qs(parsed.query) == {"url": [username]}
        ):
            return False
    uid = value.get("id")
    return (
        value.get("username") == username
        and value.get("type_of") == "user"
        and type(uid) is int
        and uid > 0
    )
