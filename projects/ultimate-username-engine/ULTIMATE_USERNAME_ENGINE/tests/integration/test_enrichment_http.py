import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ultimate_username.domain.metadata import EnrichmentMode
from ultimate_username.domain.models import DetectionSpec, Rule, SiteDefinition, Verdict
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.http_transport import AiohttpTransport
from ultimate_username.registry import SiteRegistry


@pytest.mark.local_http
def test_real_local_http_full_enrichment():
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            data = {"username": "alice", "profile": True, "display_name": "Test profile"}
            if self.path.startswith("/api/"):
                data = {"username": "alice", "followers": 12}
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    site = SiteDefinition(
        "local",
        "Local fixture",
        base + "/u/{username}",
        DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
        enrichment_urls=(base + "/api/{username}",),
    )

    async def run():
        async with UsernameEngine(SiteRegistry([site]), AiohttpTransport()) as engine:
            result = (
                await engine.search(
                    "alice",
                    options=SearchOptions(
                        enrichment_mode=EnrichmentMode.FULL, enrichment_request_budget=1
                    ),
                )
            )[0]
        assert result.detection.verdict == Verdict.FOUND
        assert result.profile_metadata.get("display_name") == "Test profile"
        assert result.profile_metadata.get("followers") == 12
        assert result.profile_metadata.request_count == 1
        assert result.attempts[0].backend == "aiohttp"
        assert result.enrichment_attempts[0].backend == "aiohttp"
        assert paths == ["/u/alice", "/api/alice"]

    try:
        asyncio.run(run())
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
