"""compare.py --mode: domyślnie exhaustive (bez zmiany zachowania), inny tryb ma osobny katalog."""
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))

import compare  # noqa: E402


def test_default_mode_is_exhaustive_and_argv_is_unchanged():
    out = Path("o")
    argv = compare.ultimate_argv("nick", out)
    assert argv == ["search", "nick", "--mode", "exhaustive", "--output", str(out / "results.json"),
                    "--journal", str(out / "journal.sqlite")]
    assert compare.DEFAULT_MODE == "exhaustive"


def test_normal_mode_is_passed_to_the_cli():
    assert compare.ultimate_argv("nick", Path("o"), "normal")[2:4] == ["--mode", "normal"]


def test_results_directory_is_separate_for_other_modes():
    assert compare.results_dir("2026-10-10") == compare.BENCH / "results" / "2026-10-10"
    assert compare.results_dir("2026-10-10", "normal") == compare.BENCH / "results" / "2026-10-10_normal"


def test_summary_header_names_the_mode():
    summary = {"date": "d", "nicks": [], "ultimate_mode": "normal"}
    assert "`--mode normal`" in compare.render_md(summary)
    assert "`--mode exhaustive`" in compare.render_md({"date": "d", "nicks": []})


def test_ultimate_source_hashes_cover_overlay_and_health_files_when_present(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "catalog.json").write_text("[]", encoding="utf-8")
    monkeypatch.setattr(compare, "ULTIMATE", tmp_path)
    assert set(compare.source_hashes("ultimate")) == {"src/m.py", "data/catalog.json"}
    (tmp_path / "data" / "osint_custom.json").write_text("[]", encoding="utf-8")
    (tmp_path / "data" / "health.json").write_text("{}", encoding="utf-8")
    before = compare.source_hashes("ultimate")
    assert {"data/osint_custom.json", "data/health.json"} <= set(before)
    (tmp_path / "data" / "health.json").write_text('{"sites": {}}', encoding="utf-8")
    assert compare.source_hashes("ultimate") != before
