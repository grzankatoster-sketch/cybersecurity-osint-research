"""CLI: ``--identity`` adds an identity section to the analyst document and nothing else changes."""

from __future__ import annotations

import io
import json
from urllib.parse import unquote, urlsplit

import pytest

from ultimate_username import cli
from ultimate_username.cli import main
from ultimate_username.domain.models import (
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.registry import SiteRegistry
from ultimate_username.transport import FakeTransport


def run(tmp_path, *extra, command="demo", username="alice", site="found"):
    output = tmp_path / "out.json"
    code = main(
        [
            command,
            username,
            "--site",
            site,
            "--journal",
            str(tmp_path / "run.sqlite"),
            "--output",
            str(output),
            *extra,
        ]
    )
    analyst = json.loads(output.with_suffix(".analyst.json").read_text("utf-8"))
    return code, analyst, json.loads(output.read_text("utf-8"))


def test_identity_is_off_by_default_and_does_not_touch_the_export(tmp_path):
    code, analyst, export = run(tmp_path)
    assert code == 0 and "identity" not in analyst
    assert all("identity" not in r for r in export)


def test_identity_section_with_seed_name(tmp_path, capsys):
    code, analyst, export = run(
        tmp_path,
        "--identity",
        "--seed-name",
        "Profil szkoleniowy",
        "--seed-url",
        "https://x.test/a",
    )
    assert code == 0
    identity = analyst["identity"]
    assert identity["threshold"] == 0.5 and identity["images"] is False
    assert identity["seed"] == {"name": "Profil szkoleniowy", "urls": ["https://x.test/a"]}
    assert identity["graph"] == {"nodes": ["https://found.example.test/alice"], "edges": []}
    assert identity["related_accounts"] == []
    (profile,) = identity["profiles"]
    assert set(profile) == {"profile_url", "site", "score", "decision", "signals", "seed_used"}
    assert (
        profile["site"] == "Found" and profile["profile_url"] == "https://found.example.test/alice"
    )
    assert (
        profile["decision"] == "TARGET_LIKELY" and profile["score"] == 0.6 and profile["seed_used"]
    )
    assert profile["signals"][0]["kind"] == "seed_name_match"
    assert profile["signals"][0]["group"] == "copyable"
    assert all("identity" not in r for r in export)  # the SearchResult export is unchanged
    assert "identity options have no effect" not in capsys.readouterr().err


def test_identity_without_seed_and_with_threshold(tmp_path):
    _, analyst, _ = run(tmp_path, "--identity")
    (profile,) = analyst["identity"]["profiles"]
    assert profile["decision"] == "UNDETERMINED" and profile["score"] == 0.0
    assert analyst["identity"]["seed"] is None
    other = tmp_path / "second"
    other.mkdir()
    _, analyst, _ = run(
        other, "--identity", "--seed-name", "Profil szkoleniowy", "--identity-threshold", "0.7"
    )
    assert analyst["identity"]["threshold"] == 0.7
    assert analyst["identity"]["profiles"][0]["decision"] == "UNDETERMINED"


def test_identity_weights_file_and_validation(tmp_path, capsys):
    weights = tmp_path / "w.json"
    weights.write_text(json.dumps({"w_seed_name": 0.9}), encoding="utf-8")
    _, analyst, _ = run(
        tmp_path,
        "--identity",
        "--seed-name",
        "Profil szkoleniowy",
        "--identity-weights",
        str(weights),
    )
    assert analyst["identity"]["profiles"][0]["score"] == 0.7  # copyable cap
    for bad in (["--identity-threshold", "1.5"], ["--identity-threshold", "nan"]):
        journal = tmp_path / "bad.sqlite"
        assert main(["demo", "alice", "--identity", *bad, "--journal", str(journal)]) == 2
        assert not journal.exists()
    weights.write_text("{bad", encoding="utf-8")
    assert main(["demo", "alice", "--identity", "--identity-weights", str(weights)]) == 2
    capsys.readouterr()


def test_identity_options_without_identity_warn(tmp_path, capsys):
    run(tmp_path, "--seed-name", "Someone Else")
    assert "identity options have no effect" in capsys.readouterr().err


def _portrait(shift: int, speck: bool) -> bytes:
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (96, 96), (240, 240, 240))
    draw = ImageDraw.Draw(image)
    draw.ellipse((20 + shift, 18, 76 + shift, 74), fill=(30, 30, 30))
    draw.rectangle((10, 70, 86, 95), fill=(200, 60, 60))
    if speck:
        draw.point((3, 3), fill=(250, 250, 250))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def _avatar_demo():
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
        for name in ("alpha", "beta")
    ]
    images = {"alpha": _portrait(0, False), "beta": _portrait(0, True)}

    def respond(request: TransportRequest, index: int) -> TransportResponse:
        host = urlsplit(request.url).hostname or ""
        if host == "img.example.test":
            return TransportResponse(
                request.url, 200, images[unquote(urlsplit(request.url).path[1:-4])]
            )
        name = host.split(".")[0]
        body = json.dumps(
            {
                "profile": True,
                "username": "alice",
                "display_name": "Alice Example",
                "avatar_url": f"https://img.example.test/{name}.png",
            }
        ).encode()
        return TransportResponse(
            request.url, 200, body, (("Content-Type", "application/json; charset=utf-8"),)
        )

    return SiteRegistry(sites), FakeTransport(handler=respond)


def test_identity_images_hash_avatars_through_the_engine_transport(tmp_path, monkeypatch):
    pytest.importorskip("PIL")
    registry, transport = _avatar_demo()
    monkeypatch.setattr(cli, "make_demo", lambda: (registry, transport))
    output = tmp_path / "out.json"
    code = main(
        [
            "demo",
            "alice",
            "--identity",
            "--identity-images",
            "--journal",
            str(tmp_path / "j.sqlite"),
            "--output",
            str(output),
        ]
    )
    assert code == 0
    identity = json.loads(output.with_suffix(".analyst.json").read_text("utf-8"))["identity"]
    assert identity["images"] is True
    assert set(identity["avatar_hashes"]) == {
        "https://img.example.test/alpha.png",
        "https://img.example.test/beta.png",
    }
    record = identity["avatar_hashes"]["https://img.example.test/alpha.png"]
    assert record["algorithm"] == "phash64-dct" and record["fetched_from"].endswith("alpha.png")
    kinds = {p["site"]: [s["kind"] for s in p["signals"]] for p in identity["profiles"]}
    assert "same_avatar" in kinds["Alpha"] and "same_avatar" in kinds["Beta"]
    assert any(r.url.startswith("https://img.example.test/") for r in transport.requests)


def test_identity_without_images_never_requests_an_image(tmp_path, monkeypatch):
    registry, transport = _avatar_demo()
    monkeypatch.setattr(cli, "make_demo", lambda: (registry, transport))
    main(
        [
            "demo",
            "alice",
            "--identity",
            "--journal",
            str(tmp_path / "j.sqlite"),
            "--output",
            str(tmp_path / "o.json"),
        ]
    )
    assert not any("img.example.test" in r.url for r in transport.requests)


def test_html_report_renders_the_identity_section_from_the_search_document(tmp_path):
    html_path = tmp_path / "report.html"
    code, analyst, _ = run(
        tmp_path,
        "--identity",
        "--seed-name",
        "Profil szkoleniowy",
        "--html",
        str(html_path),
    )
    assert code == 0
    (profile,) = analyst["identity"]["profiles"]
    html = html_path.read_text("utf-8")
    assert "Tożsamość (identity score)" in html
    assert "TARGET_LIKELY" in html and str(profile["score"]) in html
    for signal in profile["signals"]:
        assert signal["kind"] in html
    # the same document, rendered later from the analyst file, shows the identity block too
    again = tmp_path / "again.html"
    assert main(["report", str(tmp_path / "out.analyst.json"), "--html", str(again)]) == 0
    assert "seed_name_match" in again.read_text("utf-8")
