"""No public network in tests; local fixture servers remain available."""

from __future__ import annotations

import ipaddress
import json
import socket
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OUTCOMES: dict[str, str] = {}


def pytest_collection_modifyitems(items):
    manifest = ROOT / "docs/regression-manifest.json"
    if not manifest.exists():
        return
    records = json.loads(manifest.read_text("utf-8"))
    by_test = {}
    for record in records:
        for node in record["tests"]:
            by_test.setdefault(node, []).append(record["id"])
    for item in items:
        for identifier in by_test.get(item.nodeid.split("[")[0], []):
            item.add_marker(pytest.mark.regression(identifier))


def pytest_runtest_logreport(report):
    if report.failed:
        OUTCOMES[report.nodeid] = "FAILED"
    elif report.skipped:
        OUTCOMES.setdefault(report.nodeid, "SKIPPED")
    elif report.when == "call":
        OUTCOMES.setdefault(report.nodeid, "PASSED")


def pytest_sessionfinish(session, exitstatus):
    artifact = ROOT / "artifacts"
    artifact.mkdir(exist_ok=True)
    manifest_path = ROOT / "docs/regression-manifest.json"
    records = json.loads(manifest_path.read_text("utf-8")) if manifest_path.exists() else []
    proof = {}
    for record in records:
        matching = {
            node: state for node, state in OUTCOMES.items() if node.split("[")[0] in record["tests"]
        }
        complete = set(record["tests"]) <= {node.split("[")[0] for node in matching}
        proof[record["id"]] = {
            "status": record["status"],
            "run_verified": bool(matching)
            and complete
            and all(s == "PASSED" for s in matching.values()),
            "nodes": matching,
        }
    payload = {
        "exit_code": int(exitstatus),
        "summary": dict(Counter(OUTCOMES.values())),
        "outcomes": OUTCOMES,
        "regression": proof,
    }
    (artifact / "test-results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    original = socket.getaddrinfo

    def local_only(host: str | bytes | None, *args: object, **kwargs: object) -> object:
        name = host.decode() if isinstance(host, bytes) else host
        if name not in (None, "localhost"):
            try:
                if not ipaddress.ip_address(name).is_loopback:
                    raise AssertionError(f"External network prohibited in tests: {name}")
            except ValueError as exc:
                raise AssertionError(f"External DNS prohibited in tests: {name}") from exc
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", local_only)
    for method in ("connect", "connect_ex"):
        original_connect = getattr(socket.socket, method)

        def guarded_connect(sock, address, _original=original_connect):
            if isinstance(address, tuple):
                name = address[0]
                if name != "localhost":
                    try:
                        if not ipaddress.ip_address(name).is_loopback:
                            raise AssertionError("External connection prohibited")
                    except ValueError as exc:
                        raise AssertionError("External connection prohibited") from exc
            return _original(sock, address)

        monkeypatch.setattr(socket.socket, method, guarded_connect)
