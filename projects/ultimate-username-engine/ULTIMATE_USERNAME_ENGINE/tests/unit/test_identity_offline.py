"""tools/identity_offline.py on a synthetic results.json (no network, no images)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from test_identity import make

from ultimate_username.domain.codec import to_json

SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "identity_offline.py"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("identity_offline", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic() -> list:
    return [
        make("twitter", "https://twitter.com/vexa", display_name="Alune Orvo", verified=True),
        make("twitch", "https://twitch.tv/vexa", display_name="Alune Orvo"),
        make("kick", "https://kick.com/vexa", bio="i am not the real vexa"),
        make("vk", "https://vk.com/vexa"),
    ]


def write_results(path: Path, results) -> Path:
    path.write_text("[\n" + ",\n".join(to_json(r) for r in results) + "\n]\n", encoding="utf-8")
    return path


def run(tool, *args) -> int:
    return tool.main([str(a) for a in args])


def test_offline_scores_a_saved_results_file(tool, tmp_path):
    source = write_results(tmp_path / "results.json", synthetic())
    out = tmp_path / "id.json"
    code = run(
        tool,
        "--results",
        source,
        "--seed-name",
        "Alune Orvo",
        "--seed-url",
        "https://x.test/a",
        "--out",
        out,
    )
    assert code == 0
    document = json.loads(out.read_text("utf-8"))
    assert document["results_loaded"] == 4 and document["seed"]["name"] == "Alune Orvo"
    by_site = {p["site"]: p for p in document["profiles"]}
    assert by_site["twitter"]["decision"] == "TARGET_LIKELY"
    # verified (control 0.5) + seed name (copyable 0.6)
    assert by_site["twitter"]["score"] == pytest.approx(1 - 0.5 * 0.4, abs=1e-4)
    assert by_site["kick"]["decision"] == "UNRELATED_LIKELY"
    assert [s["kind"] for s in by_site["vk"]["signals"]] == ["NO_IDENTITY_DATA"]
    assert document["config"]["threshold"] == 0.5


def test_offline_weights_and_threshold_change_the_outcome(tool, tmp_path):
    source = write_results(tmp_path / "results.json", synthetic())
    weights = tmp_path / "w.json"
    weights.write_text(json.dumps({"w_verified": 0.2, "threshold": 0.9}), encoding="utf-8")
    out = tmp_path / "id.json"
    assert run(tool, "--results", source, "--weights", weights, "--out", out) == 0
    document = json.loads(out.read_text("utf-8"))
    twitter = next(p for p in document["profiles"] if p["site"] == "twitter")
    # verified 0.2 + same display name 0.35 (shared with twitch)
    assert twitter["score"] == 0.48 and twitter["decision"] == "UNDETERMINED"
    args = ("--results", source, "--weights", weights, "--threshold", "0.1", "--out", out)
    assert run(tool, *args) == 0
    assert json.loads(out.read_text("utf-8"))["threshold"] == 0.1


def test_offline_accepts_wrapped_and_ndjson_inputs_and_reports_errors(tool, tmp_path, capsys):
    results = synthetic()
    wrapped = tmp_path / "wrapped.json"
    body = ",".join(to_json(r) for r in results)
    wrapped.write_text('{"results": [' + body + "]}", encoding="utf-8")
    ndjson = tmp_path / "lines.ndjson"
    ndjson.write_text("\n".join(to_json(r) for r in results) + "\n", encoding="utf-8")
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    assert run(tool, "--results", wrapped, "--out", first) == 0
    assert run(tool, "--results", ndjson, "--out", second) == 0
    a, b = json.loads(first.read_text("utf-8")), json.loads(second.read_text("utf-8"))
    assert a["profiles"] == b["profiles"]
    bad = tmp_path / "bad.json"
    bad.write_text('[{"nope": 1}]', encoding="utf-8")
    assert run(tool, "--results", bad, "--out", tmp_path / "x.json") == 2
    assert run(tool, "--results", tmp_path / "missing.json", "--out", tmp_path / "x.json") == 2
    assert "identity_offline" in capsys.readouterr().err


def test_offline_is_deterministic(tool, tmp_path):
    source = write_results(tmp_path / "results.json", synthetic())
    outs = []
    for name in ("one.json", "two.json"):
        out = tmp_path / name
        assert run(tool, "--results", source, "--out", out) == 0
        outs.append(out.read_text("utf-8"))
    assert outs[0] == outs[1]


def test_offline_output_has_link_graph_and_related_accounts(tool, tmp_path):
    results = [
        make(
            "github",
            "https://github.com/vexa",
            external_links=("https://twitch.tv/vexa", "https://www.instagram.com/Vexa_Real/"),
        ),
        make("twitch", "https://twitch.tv/vexa", website="https://github.com/vexa"),
    ]
    source = write_results(tmp_path / "results.json", results)
    out = tmp_path / "id.json"
    assert run(tool, "--results", source, "--out", out) == 0
    document = json.loads(out.read_text("utf-8"))
    assert document["graph"]["nodes"] == ["https://github.com/vexa", "https://twitch.tv/vexa"]
    assert [(e["from"], e["to"], e["reciprocal"]) for e in document["graph"]["edges"]] == [
        ("https://github.com/vexa", "https://twitch.tv/vexa", True),
        ("https://twitch.tv/vexa", "https://github.com/vexa", True),
    ]
    assert document["related_accounts"] == [
        {
            "url": "https://www.instagram.com/Vexa_Real/",
            "platform": "instagram",
            "from_profile": "https://github.com/vexa",
            "field": "external_links",
        }
    ]
