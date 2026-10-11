"""Testy samego skryptu kontroli (ci/run_checks.py): skaner sekretow, maskowanie, kontrola danych spraw i koncowek linii.

Wartosci przypominajace sekrety sa skladane w czasie dzialania testu (konkatenacja), zeby plik nie wygladal jak wyciek."""

from __future__ import annotations

import json

import pytest

import run_checks as rc

JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJ0ZXN0In0" + ".c2lnbmF0dXJl"
BEARER = "Authorization: Bearer " + "abcdEFGH0123456789xyz"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
EMAIL = "jan.kowalski" + "@" + "example.test"


@pytest.mark.parametrize(
    "text,kind",
    [
        (f"token={JWT}", "jwt"),
        (BEARER, "bearer"),
        (PEM, "private-key"),
        ("klucz ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4", "token"),
        ("api_key = " + "x" * 8 + "Y1z2W3v4", "secret-assignment"),
        (f"kontakt: {EMAIL}", "email"),
        ("AssertionError: jan.kowalski" + "@" + "exa...", "email"),  # adres ucięty przez pytest
    ],
)
def test_scanner_detects_each_secret_kind_without_printing_the_value(text, kind):
    hits = rc.scan_text(text, "plik.md")
    assert kind in {h.kind for h in hits}
    assert all(h.path == "plik.md" and h.line == 1 for h in hits)
    assert all(text not in str(h) and "example.test" not in str(h) for h in hits)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "233 passed in 1.75s",
        "kontakt: p***@example.test",
        "    @pytest.fixture",
        "def f(a, b): return a @ b",
        "FAILED tests/x.py::test_a - AssertionError",
        "token ok",
    ],
)
def test_scanner_accepts_clean_and_masked_text(text):
    assert rc.scan_text(text) == []


def test_mask_hides_every_kind_of_secret_and_email():
    masked = rc.mask(f"{EMAIL} {JWT} {BEARER} {PEM} jan@example.com")
    assert "@" not in masked and "eyJ" not in masked and "abcdEFGH" not in masked and "PRIVATE KEY" not in masked
    assert "<e-mail>" in masked and "<jwt>" in masked and "<private-key>" in masked


def test_scan_artifacts_deletes_offending_files_and_keeps_clean_ones(tmp_path):
    (tmp_path / "summary.md").write_text("# OK\n233 passed\n", encoding="utf-8")
    (tmp_path / "zly.txt").write_text(f"ok\nkontakt {EMAIL}\n", encoding="utf-8")
    hits = rc.scan_artifacts(tmp_path)
    assert [(h.path, h.line, h.kind) for h in hits] == [("zly.txt", 2, "email")]
    assert not (tmp_path / "zly.txt").exists() and (tmp_path / "summary.md").exists()


def test_scan_artifacts_on_missing_folder_is_empty(tmp_path):
    assert rc.scan_artifacts(tmp_path / "brak") == []


def test_main_writes_clean_summary_and_scanner_runs_on_it(tmp_path, capsys):
    code = rc.main(["--only", "hygiene:case-data", "--artifacts", str(tmp_path / "art")])
    out = capsys.readouterr().out
    assert code == rc.EXIT_OK and "artifacts:scan" in out
    data = json.loads((tmp_path / "art" / "summary.json").read_text(encoding="utf-8"))
    assert [d["step"] for d in data] == ["hygiene:case-data"] and (tmp_path / "art" / "summary.md").is_file()


# ------------------------------------------------------------------ dane spraw w repozytorium


def test_case_data_violations_flag_case_files_results_and_env_files():
    bad = rc.case_data_violations(
        [
            "graph.json",
            "panel/wyniki/sprawa_1/audit.jsonl",
            "entity-graph/out/graph.graphml",
            "x/maltego.csv",
            "org-intel-data/store.json",
            "data/store.json",
            "osint-poland/brave.env",
            ".env",
            ".env.production",
            "panel/wyniki/notatka.txt",
        ]
    )
    assert len(bad) == 10


def test_case_data_violations_allow_fixtures_examples_and_code():
    assert (
        rc.case_data_violations(
            [
                "entity-graph/tests/fixtures/org_intel/store_basic.json",
                "entity-graph/tests/fixtures/sprawa/graph.json",
                "osint-poland/.env.example",
                "entity-graph/src/entity_graph/sprawa.py",
                "org-intel/src/org_intel/store.py",
                "panel/app.py",
                "README.md",
            ]
        )
        == []
    )


# ------------------------------------------------------------------ koncowki linii


@pytest.mark.parametrize(
    "data,kind",
    [
        (b"", "none"),
        (b"jedna linia", "none"),
        (b"a\nb\n", "lf"),
        (b"a\r\nb\r\n", "crlf"),
        (b"a\r\nb\n", "mixed"),
        (b"\x00\x01a\r\nb\n", "binary"),
    ],
)
def test_eol_kind(data, kind):
    assert rc.eol_kind(data) == kind


def test_eol_scope_covers_pipeline_packages_only():
    assert rc.in_eol_scope("entity-graph/tests/test_x.py") and rc.in_eol_scope("ci/run_checks.py")
    assert rc.in_eol_scope(".github/workflows/osint-pipeline.yml")
    assert rc.in_eol_scope("osint-poland/src/osint_poland/org_intel_feed.py")
    assert not rc.in_eol_scope("osint-poland/src/osint_poland/api.py") and not rc.in_eol_scope("panel/app.py")
    assert not rc.in_eol_scope(".github/workflows/workspace.yml")


def test_known_mixed_file_parses_comments(tmp_path):
    path = tmp_path / "known.txt"
    path.write_text("# komentarz\n\na/b.py  # powod\n c/d.py\n", encoding="utf-8")
    assert rc.read_known_mixed(path) == {"a/b.py", "c/d.py"}


def test_mixed_eol_in_a_plain_tree_is_found_from_bytes(tmp_path, monkeypatch):
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci" / "zly.py").write_bytes(b"a\r\nb\n")
    (tmp_path / "ci" / "dobry.py").write_bytes(b"a\r\nb\r\n")
    (tmp_path / "panel").mkdir()
    (tmp_path / "panel" / "poza.py").write_bytes(b"a\r\nb\n")  # poza zasiegiem
    monkeypatch.setattr(rc, "is_git_root", lambda _root: False)
    assert rc.mixed_eol_files(tmp_path) == (["ci/zly.py"], "tree")


# ------------------------------------------------------------------ wybor krokow i kody wyjscia


def test_step_selection_by_name_group_and_unknown_token():
    steps = rc.build_steps()
    assert {s.name for s in rc.selected(steps, ["hygiene"], [])} == {"hygiene:case-data", "hygiene:eol"}
    assert [s.name for s in rc.selected(steps, ["test:ci", "lint:ci"], [])] == ["test:ci", "lint:ci"]
    assert not any(s.name.startswith("lint:") for s in rc.selected(steps, [], ["lint"]))
    with pytest.raises(ValueError, match="nieznany"):
        rc.selected(steps, ["nie-ma"], [])


def test_exit_codes_for_list_and_usage_errors(capsys):
    assert rc.main(["--list"]) == rc.EXIT_OK
    assert "test:org-intel" in capsys.readouterr().out
    assert rc.main(["--only", "nie-ma-takiego-kroku"]) == rc.EXIT_USAGE
    assert rc.main(["--nieznana-flaga"]) == rc.EXIT_USAGE
    capsys.readouterr()


def test_unpublished_osint_poland_has_no_step():
    # Public monorepo: username-engine is tracked (tested by its own workflow job); osint-poland is not published.
    assert "username-engine" not in rc.NOT_IN_REPO
    if not rc.FEED_AVAILABLE:
        assert "osint-poland" in rc.NOT_IN_REPO
        assert not any("osint-poland" in s.name for s in rc.build_steps())
