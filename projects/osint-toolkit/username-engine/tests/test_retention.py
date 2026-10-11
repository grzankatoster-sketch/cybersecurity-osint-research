"""Retencja raportów: termin ważności, manifest, purge, rejestr usunięć, bezpieczeństwo usuwania (bez sieci)."""
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from username_engine import cli, retention
from username_engine.models import Response, Site
from username_engine.report import render_html
from username_engine.sources import save_db

T0 = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
NICK = "SEKRETNY_NICK_123"


def make_scan(root, ttl=12, now=T0, files=None):
    scan = retention.start_scan(root, ttl, now=now)
    for name, content in (files or {"raport.html": f"<h1>{NICK}</h1>", "wyniki.csv": f"{NICK};a"}).items():
        (scan.path / name).write_text(content, encoding="utf-8")
    retention.seal_scan(scan)
    return scan


def registry(root):
    p = root / retention.REGISTRY
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


# ---------------------------------------------------------------- termin i manifest

def test_start_scan_sets_12h_expiry_and_provisional_manifest(tmp_path):
    scan = retention.start_scan(tmp_path, 12, now=T0)
    assert retention.SCAN_ID_RE.fullmatch(scan.scan_id) and scan.path == tmp_path / scan.scan_id
    m = json.loads((scan.path / retention.MANIFEST).read_text(encoding="utf-8"))
    assert m["scan_id"] == scan.scan_id and m["ttl_hours"] == 12
    assert m["created_at"] == "2026-10-03T12:00:00Z" and m["expires_at"] == "2026-10-04T00:00:00Z"
    assert m["files"] == []


def test_ttl_zero_means_no_expiry_only_when_explicit(tmp_path):
    scan = make_scan(tmp_path, ttl=0)
    m = json.loads((scan.path / retention.MANIFEST).read_text(encoding="utf-8"))
    assert m["expires_at"] is None and scan.expires_at is None
    far = T0 + timedelta(days=3650)
    assert retention.purge_expired(tmp_path, now=far)["deleted"] == 0 and scan.path.exists()
    assert retention.DEFAULT_TTL_HOURS == 12


def test_seal_scan_lists_files_with_sha256_and_skips_manifest_and_tmp(tmp_path):
    scan = retention.start_scan(tmp_path, 12, now=T0)
    (scan.path / "a.json").write_bytes(b"{}")
    (scan.path / "a.json.x1.tmp").write_bytes(b"polowa")
    retention.seal_scan(scan)
    m = json.loads((scan.path / retention.MANIFEST).read_text(encoding="utf-8"))
    assert m["files"] == [{"name": "a.json", "bytes": 2, "sha256": hashlib.sha256(b"{}").hexdigest()}]


def test_manifest_has_no_username(tmp_path):
    scan = make_scan(tmp_path)
    assert NICK not in (scan.path / retention.MANIFEST).read_text(encoding="utf-8")


@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf"), 10 ** 6])
def test_parse_ttl_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        retention.parse_ttl_hours(bad)


def test_parse_ttl_accepts_zero_and_fraction():
    assert retention.parse_ttl_hours(0) == 0 and retention.parse_ttl_hours(0.5) == 0.5


@pytest.mark.parametrize("name", ["", "../x.html", "..\\x.html", "a/b.html", "C:\\x.html", "C:x.html", "/etc/p",
                                  ".ukryty", "manifest.json", "MANIFEST.JSON", "x.tmp", "con.html", "a.html ",
                                  "a.", "x" * 200, "a\x00b.html", "usuniecia.jsonl"])
def test_output_name_must_be_a_bare_safe_file_name(name):
    with pytest.raises(ValueError):
        retention.safe_output_name(name)


def test_output_name_accepts_plain_names():
    assert retention.safe_output_name("raport 1.html") == "raport 1.html"
    assert retention.safe_output_name("wyniki-mozilla.v2.csv") == "wyniki-mozilla.v2.csv"


# ---------------------------------------------------------------- purge

def test_purge_removes_only_expired_scans_with_all_files(tmp_path):
    old = make_scan(tmp_path, now=T0)
    (old.path / "polowa.csv.ab.tmp").write_text("x", encoding="utf-8")       # plik pośredni
    (old.path / "dodatkowy.txt").write_text("y", encoding="utf-8")
    fresh = make_scan(tmp_path, now=T0 + timedelta(hours=11))
    res = retention.purge_expired(tmp_path, now=T0 + timedelta(hours=12, minutes=1))
    assert res["deleted"] == 1 and res["errors"] == [] and res["skipped"] == 0
    assert not old.path.exists() and fresh.path.exists()
    assert sorted(p.name for p in fresh.path.iterdir()) == ["manifest.json", "raport.html", "wyniki.csv"]


def test_expiry_boundary_is_inclusive(tmp_path):
    scan = make_scan(tmp_path, now=T0)
    assert retention.purge_expired(tmp_path, now=T0 + timedelta(hours=12) - timedelta(seconds=1))["deleted"] == 0
    assert retention.purge_expired(tmp_path, now=T0 + timedelta(hours=12))["deleted"] == 1
    assert not scan.path.exists()


def test_registry_has_ids_times_count_hashes_but_no_username_or_content(tmp_path):
    scan = make_scan(tmp_path, now=T0)
    now = T0 + timedelta(hours=13)
    retention.purge_expired(tmp_path, now=now)
    (entry,) = registry(tmp_path)
    assert entry["scan_id"] == scan.scan_id and entry["created_at"] == "2026-10-03T12:00:00Z"
    assert entry["deleted_at"] == "2026-10-04T01:00:00Z" and entry["files"] == 3     # 2 raporty + manifest
    assert entry["sha256"] == sorted(hashlib.sha256(c.encode()).hexdigest()
                                     for c in (f"<h1>{NICK}</h1>", f"{NICK};a"))
    assert NICK not in (tmp_path / retention.REGISTRY).read_text(encoding="utf-8")


def test_registry_is_append_only_and_purge_idempotent(tmp_path):
    make_scan(tmp_path, now=T0)
    retention.purge_expired(tmp_path, now=T0 + timedelta(hours=13))
    first = (tmp_path / retention.REGISTRY).read_text(encoding="utf-8")
    assert retention.purge_expired(tmp_path, now=T0 + timedelta(hours=14))["deleted"] == 0
    make_scan(tmp_path, now=T0 + timedelta(hours=1))
    retention.purge_expired(tmp_path, now=T0 + timedelta(hours=14))
    text = (tmp_path / retention.REGISTRY).read_text(encoding="utf-8")
    assert text.startswith(first) and len(registry(tmp_path)) == 2


def test_dry_run_deletes_nothing(tmp_path):
    scan = make_scan(tmp_path, now=T0)
    res = retention.purge_expired(tmp_path, now=T0 + timedelta(days=1), dry_run=True)
    assert res["deleted"] == 0 and res["would_delete"] == 1 and scan.path.exists() and registry(tmp_path) == []


def test_missing_results_dir_is_not_an_error(tmp_path):
    res = retention.purge_expired(tmp_path / "nie-ma", now=T0)
    assert res["deleted"] == 0 and res["errors"] == []
    assert not (tmp_path / "nie-ma").exists()


def test_purge_ignores_foreign_files_and_dirs(tmp_path):
    (tmp_path / "przyklad-mozilla.html").write_text("stary raport", encoding="utf-8")
    foreign = tmp_path / "moje-dokumenty"
    foreign.mkdir()
    (foreign / "manifest.json").write_text(json.dumps({"scan_id": "moje-dokumenty", "expires_at": "2000-01-01T00:00:00Z",
                                                       "created_at": "2000-01-01T00:00:00Z"}), encoding="utf-8")
    (foreign / "wazne.txt").write_text("x", encoding="utf-8")
    retention.purge_expired(tmp_path, now=T0 + timedelta(days=9999))
    assert (tmp_path / "przyklad-mozilla.html").exists() and (foreign / "wazne.txt").exists()


def test_manifest_with_other_scan_id_or_garbage_is_skipped(tmp_path):
    a, b = make_scan(tmp_path, now=T0), make_scan(tmp_path, now=T0)
    mf = json.loads((a.path / retention.MANIFEST).read_text(encoding="utf-8"))
    mf["scan_id"] = b.scan_id
    (a.path / retention.MANIFEST).write_text(json.dumps(mf), encoding="utf-8")
    (b.path / retention.MANIFEST).write_text("{nie json", encoding="utf-8")
    res = retention.purge_expired(tmp_path, now=T0 + timedelta(days=2))
    assert res["deleted"] == 0 and res["skipped"] == 2 and a.path.exists() and b.path.exists()


def test_unexpected_subdirectory_blocks_deletion(tmp_path):
    scan = make_scan(tmp_path, now=T0)
    (scan.path / "podkatalog").mkdir()
    (scan.path / "podkatalog" / "x.txt").write_text("x", encoding="utf-8")
    res = retention.purge_expired(tmp_path, now=T0 + timedelta(days=2))
    assert res["deleted"] == 0 and res["skipped"] == 1 and (scan.path / "raport.html").exists()


def test_symlinked_scan_dir_is_never_followed(tmp_path):
    outside = tmp_path / "poza"
    outside.mkdir()
    (outside / "wazne.txt").write_text("nie ruszac", encoding="utf-8")
    root = tmp_path / "wyniki"
    real = make_scan(root, now=T0)
    # katalog "skanu" będący dowiązaniem do katalogu poza wynikami, z poprawnym (podrobionym) manifestem
    shutil_manifest = (real.path / retention.MANIFEST).read_text(encoding="utf-8")
    fake_id = "20200101T000000Z-deadbeef"
    mf = json.loads(shutil_manifest)
    mf.update(scan_id=fake_id, created_at="2020-01-01T00:00:00Z", expires_at="2020-01-02T00:00:00Z")
    (outside / retention.MANIFEST).write_text(json.dumps(mf), encoding="utf-8")
    try:
        os.symlink(outside, root / fake_id, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("brak uprawnień do tworzenia dowiązań symbolicznych")
    res = retention.purge_expired(root, now=T0 + timedelta(days=2))
    assert (outside / "wazne.txt").read_text(encoding="utf-8") == "nie ruszac"
    assert (outside / retention.MANIFEST).exists() and res["skipped"] >= 1


def test_symlinked_file_inside_scan_removes_link_not_target(tmp_path):
    outside = tmp_path / "sekret.txt"
    outside.write_text("tajne", encoding="utf-8")
    root = tmp_path / "wyniki"
    scan = make_scan(root, now=T0)
    try:
        os.symlink(outside, scan.path / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("brak uprawnień do tworzenia dowiązań symbolicznych")
    res = retention.purge_expired(root, now=T0 + timedelta(days=2))
    assert res["deleted"] == 1 and not scan.path.exists() and outside.read_text(encoding="utf-8") == "tajne"


def test_leftover_purging_dir_is_finished_next_time(tmp_path):
    scan = make_scan(tmp_path, now=T0)
    stuck = tmp_path / f".usuwanie-{scan.scan_id}-0a1b2c3d"
    scan.path.rename(stuck)
    res = retention.purge_expired(tmp_path, now=T0 + timedelta(days=2))
    assert res["deleted"] == 1 and not stuck.exists() and registry(tmp_path)[0]["scan_id"] == scan.scan_id


def test_scan_that_cannot_be_removed_is_reported_and_retried(tmp_path, monkeypatch):
    scan = make_scan(tmp_path, now=T0)
    real_unlink = os.unlink

    def fail(p, *a, **k):
        if str(p).endswith("raport.html"):
            raise PermissionError("otwarty w przeglądarce")
        return real_unlink(p, *a, **k)

    monkeypatch.setattr(os, "unlink", fail)
    res = retention.purge_expired(tmp_path, now=T0 + timedelta(days=2))
    assert res["deleted"] == 0 and len(res["errors"]) == 1 and registry(tmp_path) == []
    monkeypatch.setattr(os, "unlink", real_unlink)
    assert retention.purge_expired(tmp_path, now=T0 + timedelta(days=2))["deleted"] == 1
    assert registry(tmp_path)[0]["scan_id"] == scan.scan_id


def test_registry_symlink_is_refused(tmp_path):
    target = tmp_path / "gdzie_indziej.jsonl"
    target.write_text("", encoding="utf-8")
    root = tmp_path / "wyniki"
    make_scan(root, now=T0)
    try:
        os.symlink(target, root / retention.REGISTRY)
    except (OSError, NotImplementedError):
        pytest.skip("brak uprawnień do tworzenia dowiązań symbolicznych")
    res = retention.purge_expired(root, now=T0 + timedelta(days=2))
    assert res["errors"] and target.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------- raport HTML

def test_html_shows_expiry_note():
    scan_note = retention.expiry_note(T0 + timedelta(hours=12))
    html = render_html("a", {"a": []}, {"a": {"checked": 0, "error": 0, "unsupported": 0}}, [],
                       retention_note=scan_note)
    assert "ważny do" in html.lower() and "2026-10-" in html
    assert "bez terminu" in retention.expiry_note(None).lower()
    html = render_html("a", {"a": []}, {"a": {"checked": 0, "error": 0, "unsupported": 0}}, [])
    assert "ważny do" not in html.lower()


# ---------------------------------------------------------------- CLI

class _F:
    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *e): pass
    async def fetch(self, method, url, headers=None, body=None):
        return Response(200 if url.endswith("/alice") else 404, "avatar", final_url=url)


def _db(tmp_path):
    db = tmp_path / "sites.json"
    save_db([Site("Gh", "https://gh.com/{username}", e_strings=["avatar"])], db)
    return db


def test_cli_scan_writes_into_scan_dir_with_manifest_and_expiry(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Fetcher", _F)
    out = tmp_path / "w"
    rc = cli.main(["alice", "--db", str(_db(tmp_path)), "--no-variants", "--results-dir", str(out),
                   "--report", "r.html", "--csv", "r.csv", "--json", "r.json"])
    assert rc == 0
    (scan_dir,) = [p for p in out.iterdir() if p.is_dir()]
    assert sorted(p.name for p in scan_dir.iterdir()) == ["manifest.json", "r.csv", "r.html", "r.json"]
    m = json.loads((scan_dir / "manifest.json").read_text(encoding="utf-8"))
    assert [f["name"] for f in m["files"]] == ["r.csv", "r.html", "r.json"] and m["ttl_hours"] == 12
    created = datetime.fromisoformat(m["created_at"])
    assert datetime.fromisoformat(m["expires_at"]) - created == timedelta(hours=12)
    for f in m["files"]:
        assert f["sha256"] == hashlib.sha256((scan_dir / f["name"]).read_bytes()).hexdigest()
    assert "alice" not in (scan_dir / "manifest.json").read_text(encoding="utf-8")
    assert "ważny do" in (scan_dir / "r.html").read_text(encoding="utf-8").lower()
    assert str(scan_dir / "r.html") in capsys.readouterr().out


def test_cli_ttl_hours_option_and_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Fetcher", _F)
    db = str(_db(tmp_path))
    out = tmp_path / "w"
    assert cli.main(["alice", "--db", db, "--no-variants", "--results-dir", str(out), "--json", "a.json",
                     "--ttl-hours", "2"]) == 0
    assert cli.main(["alice", "--db", db, "--no-variants", "--results-dir", str(out), "--report", "b.html",
                     "--ttl-hours", "0"]) == 0
    ms = [json.loads((d / "manifest.json").read_text(encoding="utf-8")) for d in sorted(out.iterdir()) if d.is_dir()]
    by_ttl = {m["ttl_hours"]: m for m in ms}
    assert by_ttl[2]["expires_at"] and by_ttl[0]["expires_at"] is None
    html = next(d for d in out.iterdir() if d.is_dir() and (d / "b.html").exists()) / "b.html"
    assert "bez terminu" in html.read_text(encoding="utf-8").lower()


@pytest.mark.parametrize("extra", [["--ttl-hours", "-3"], ["--ttl-hours", "nan"], ["--report", "../x.html"],
                                   ["--csv", "podkatalog/x.csv"], ["--json", "manifest.json"],
                                   ["--report", "a.x", "--csv", "A.X"]])
def test_cli_rejects_bad_ttl_and_output_names(tmp_path, monkeypatch, capsys, extra):
    monkeypatch.setattr(cli, "Fetcher", _F)
    out = tmp_path / "w"
    rc = cli.main(["alice", "--db", str(_db(tmp_path)), "--no-variants", "--results-dir", str(out), *extra])
    assert rc == 2 and (not out.exists() or not any(out.iterdir()))


def test_cli_scan_purges_expired_scans_on_start(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Fetcher", _F)
    out = tmp_path / "w"
    old = make_scan(out, now=datetime.now(timezone.utc) - timedelta(hours=30))
    assert cli.main(["alice", "--db", str(_db(tmp_path)), "--no-variants", "--results-dir", str(out),
                     "--json", "n.json"]) == 0
    assert not old.path.exists() and registry(out)[0]["scan_id"] == old.scan_id
    assert "Usunięto 1 wygasł" in capsys.readouterr().out


def test_cli_scan_without_exports_creates_no_files_but_still_purges(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Fetcher", _F)
    out = tmp_path / "w"
    old = make_scan(out, now=datetime.now(timezone.utc) - timedelta(hours=30))
    assert cli.main(["alice", "--db", str(_db(tmp_path)), "--no-variants", "--results-dir", str(out)]) == 0
    assert not old.path.exists() and [p for p in out.iterdir() if p.is_dir()] == []


def test_cli_purge_subcommand(tmp_path, capsys):
    out = tmp_path / "w"
    old = make_scan(out, now=datetime.now(timezone.utc) - timedelta(hours=30))
    fresh = make_scan(out, now=datetime.now(timezone.utc))
    assert cli.main(["purge", "--results-dir", str(out), "--dry-run"]) == 0
    assert old.path.exists()
    assert cli.main(["purge", "--results-dir", str(out)]) == 0
    assert not old.path.exists() and fresh.path.exists()
    assert "Usunięto 1" in capsys.readouterr().out


def test_cli_purge_uses_default_results_dir(monkeypatch, capsys):
    old = make_scan(cli.DEFAULT_RESULTS, now=datetime.now(timezone.utc) - timedelta(hours=30))
    assert cli.main(["purge"]) == 0
    assert not old.path.exists()


def test_cli_username_purge_still_possible_after_double_dash(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Fetcher", _F)
    assert cli.main(["--db", str(_db(tmp_path)), "--no-variants", "--", "purge"]) == 0


@pytest.mark.skipif(os.name != "nt", reason="junction to mechanizm Windows")
def test_junction_scan_dir_is_never_followed(tmp_path):
    import subprocess
    outside = tmp_path / "poza"
    outside.mkdir()
    (outside / "wazne.txt").write_text("nie ruszac", encoding="utf-8")
    fake_id = "20200101T000000Z-deadbeef"
    (outside / retention.MANIFEST).write_text(json.dumps({
        "scan_id": fake_id, "created_at": "2020-01-01T00:00:00Z", "expires_at": "2020-01-02T00:00:00Z"}),
        encoding="utf-8")
    root = tmp_path / "wyniki"
    root.mkdir()
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / fake_id), str(outside)],
                          stdin=subprocess.DEVNULL, capture_output=True)
    if made.returncode != 0:
        pytest.skip("nie udało się utworzyć junctiona")
    res = retention.purge_expired(root, now=T0)
    assert res["deleted"] == 0 and res["skipped"] == 1
    assert sorted(p.name for p in outside.iterdir()) == ["manifest.json", "wazne.txt"]
