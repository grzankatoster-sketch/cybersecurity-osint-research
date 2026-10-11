"""Small explicit live corpus. One GET per case, no retries or authentication."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/runtime-quality/live-corpus.json"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    corpus = []
    github_names = ["JanKowalski", "octocat", "uue-audit-negative-8c27ae31954b"]
    cases = [
        (
            "github:" + name,
            "GitHub",
            name,
            "https://github.com/{username}",
            "https://api.github.com/users/{username}",
            name != github_names[-1],
            "JSON",
        )
        for name in github_names
    ] + [
        (
            "dev:json",
            "DEV",
            "ben",
            "https://dev.to/{username}",
            "https://dev.to/api/users/by_username?url={username}",
            True,
            "JSON",
        ),
        (
            "dev:html",
            "DEV",
            "ben",
            "https://dev.to/{username}",
            "https://dev.to/{username}",
            True,
            "HTML",
        ),
    ]
    opener = build_opener(NoRedirect)
    for sid, name, username, profile, probe, expected, kind in cases:
        url = probe.replace("{username}", username)
        record = {
            "id": sid,
            "username": username,
            "expected_exists": expected,
            "expected_type": kind,
            "expected_basis": (
                "public project/profile selected before GET; "
                "random negative candidate requires 404 confirmation"
            ),
            "site": {
                "id": sid,
                "name": name,
                "profile_url": profile,
                "probe_url": probe,
                "detection": {
                    "present": {"strategy": "status", "statuses": [200]},
                    "absent": {"strategy": "status", "statuses": [404]},
                },
            },
            "url": url,
            "captured_at": datetime.now(UTC).isoformat(),
        }
        request = Request(
            url,
            headers={
                "User-Agent": "UsernameEngineValidation/1.0",
                "Accept": "application/json" if kind == "JSON" else "text/html",
            },
        )
        try:
            try:
                reply = opener.open(request, timeout=20)
            except HTTPError as exc:
                reply = exc
            with reply:
                body = reply.read(1_048_577)
                record.update(
                    {
                        "status": reply.code,
                        "content_type": reply.headers.get("Content-Type", ""),
                        "body_complete": len(body) <= 1_048_576,
                        "body_base64": base64.b64encode(body[:1_048_576]).decode(),
                        "body_sha256": hashlib.sha256(body[:1_048_576]).hexdigest(),
                        "final_url": reply.geturl(),
                    }
                )
        except (OSError, URLError) as exc:
            record["error"] = type(exc).__name__ + ": " + str(exc)
        corpus.append(record)
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(corpus, ensure_ascii=False, indent=2), encoding="utf-8")
        print(
            json.dumps({"case": sid, "status": record.get("status"), "error": record.get("error")}),
            flush=True,
        )


if __name__ == "__main__":
    main()
