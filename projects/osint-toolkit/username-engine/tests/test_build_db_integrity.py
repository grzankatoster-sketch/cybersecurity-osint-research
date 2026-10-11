"""OPEN-09: przypięte źródła katalogu i weryfikacja SHA-256 (bez sieci)."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_db.py"
_spec = importlib.util.spec_from_file_location("build_db_under_test", SCRIPT)
build_db = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = build_db  # dataclasses resolve their module via sys.modules
_spec.loader.exec_module(build_db)


def _write(tmp_path: Path, name: str, data: bytes) -> tuple[str, str]:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path), hashlib.sha256(data).hexdigest()


def test_pins_are_full_commits_and_sha256_digests():
    for pin in build_db.PINS.values():
        assert len(pin.ref) == 40 and int(pin.ref, 16) >= 0
        assert len(pin.sha256) == 64 and int(pin.sha256, 16) >= 0
        assert "/main/" not in build_db.source_url(pin, pin.ref)


def test_local_file_with_matching_explicit_hash_loads(tmp_path):
    path, digest = _write(tmp_path, "wmn.json", b'{"sites": []}')
    data, meta = build_db.load("wmn", path, None, digest)
    assert data == {"sites": []} and meta["sha256"] == digest and meta["path"] == path


def test_tampered_local_file_is_rejected_against_the_pin(tmp_path):
    path, _ = _write(tmp_path, "wmn.json", b'{"sites": ["tampered"]}')
    with pytest.raises(build_db.IntegrityError, match="SHA-256"):
        build_db.load("wmn", path, None, None)


@pytest.mark.parametrize("ref", ["main", "master", "HEAD", "062bcfe", "g" * 40])
def test_branch_names_and_short_refs_are_rejected(ref):
    with pytest.raises(build_db.IntegrityError, match="commit"):
        build_db.expected_pin("wmn", ref, "0" * 64)


def test_other_commit_requires_an_explicit_hash():
    with pytest.raises(build_db.IntegrityError, match="sha256"):
        build_db.expected_pin("maigret", "a" * 40, None)


@pytest.mark.parametrize("sha", ["abc", "z" * 64, "0" * 63])
def test_malformed_expected_hash_is_rejected(sha):
    with pytest.raises(build_db.IntegrityError):
        build_db.expected_pin("wmn", None, sha)


@pytest.mark.parametrize("url", ["http://example.com/x.json", "file:///etc/passwd", "ftp://example.com/x"])
def test_fetch_refuses_non_https_without_network(url):
    with pytest.raises(build_db.IntegrityError, match="https"):
        build_db.fetch(url)


def test_main_writes_nothing_when_a_source_fails_verification(tmp_path):
    wmn, _ = _write(tmp_path, "wmn.json", b'{"sites": []}')
    mg, mg_digest = _write(tmp_path, "mg.json", b'{"sites": {}}')
    out = tmp_path / "sites.json"
    code = build_db.main(["--wmn", wmn, "--maigret", mg, "--maigret-sha256", mg_digest, "--out", str(out)])
    assert code == 2 and not out.exists()
