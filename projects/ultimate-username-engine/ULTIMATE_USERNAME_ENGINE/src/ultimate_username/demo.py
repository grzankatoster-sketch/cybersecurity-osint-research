"""Deterministic, entirely offline demonstration suitable for training."""

import json
from urllib.parse import unquote, urlsplit

from ultimate_username.domain.models import (
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.registry import SiteRegistry
from ultimate_username.transport import FakeTransport


def make_demo() -> tuple[SiteRegistry, FakeTransport]:
    sites = [
        SiteDefinition(
            name,
            name.title(),
            f"https://{name}.example.test/{{username}}",
            DetectionSpec(
                Rule("message", "profile"),
                Rule("message", "missing"),
                Rule("redirect", "{profile_url}"),
            ),
        )
        for name in ("found", "missing", "limited", "challenge")
    ]
    responses = {
        "found": (200, b"profile"),
        "missing": (200, b"missing"),
        "limited": (429, b""),
        "challenge": (200, b"<title>Just a moment</title>profile"),
    }

    def respond(request: TransportRequest, index: int) -> TransportResponse:
        status, body = responses[request.url.split("//")[1].split(".")[0]]
        if request.url.startswith("https://found."):
            body = json.dumps(
                {
                    "profile": True,
                    "username": unquote(urlsplit(request.url).path[1:]),
                    "display_name": "Profil szkoleniowy",
                    "bio": "Kontrolowana odpowiedź demo",
                    "followers": 0,
                    "verified": False,
                },
                ensure_ascii=False,
            ).encode()
        return TransportResponse(
            request.url, status, body, (("Content-Type", "application/json; charset=utf-8"),)
        )

    return SiteRegistry(sites), FakeTransport(handler=respond)
