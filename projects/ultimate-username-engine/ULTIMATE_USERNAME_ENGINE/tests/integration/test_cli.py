import json

from ultimate_username.cli import main
from ultimate_username.demo import make_demo
from ultimate_username.domain.codec import to_json


def test_cli_demo_errors_preserved_and_exact_output_path(tmp_path, capsys):
    output = tmp_path / "nested" / "wyniki.json"
    journal = tmp_path / "run.sqlite"
    code = main(["demo", "../Żółć", "--output", str(output), "--journal", str(journal)])
    assert code == 1  # two explicit blocked/rate-limited fixtures; no hidden filtering
    values = json.loads(output.read_text("utf-8"))
    assert len(values) == 4
    assert {r["detection"]["state"] for r in values} == {"OK", "BLOCKED", "RATE_LIMITED"}
    assert all(r["username"]["raw"] == "../Żółć" for r in values)
    assert "Output:" in capsys.readouterr().err


def test_cli_filters_stdout_and_reused_journal_exports_current_run(tmp_path, capsys):
    journal = tmp_path / "run.sqlite"
    for username in ("alice", "bob"):
        assert (
            main(["demo", username, "--site", "found", "--journal", str(journal), "--output", "-"])
            == 0
        )
        data = json.loads(capsys.readouterr().out)
        assert len(data) == 1 and data[0]["username"]["raw"] == username


def test_cli_rejects_bad_limits_and_unknown_selection_before_io(tmp_path):
    for option, value in [
        ("--concurrency", "0"),
        ("--queue", "-1"),
        ("--job-timeout", "nan"),
        ("--request-budget", "0"),
        ("--site", "unknown"),
        ("--category", "unknown"),
    ]:
        journal = tmp_path / "must-not-exist.sqlite"
        assert main(["demo", "alice", option, value, "--journal", str(journal)]) == 2
        assert not journal.exists()


def test_validate_offline_registry_and_csv_output(tmp_path, capsys):
    registry, _ = make_demo()
    source = tmp_path / "registry.json"
    source.write_text(to_json(tuple(e.definition for e in registry.entries)), encoding="utf-8")
    assert main(["validate", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 4
    csv = tmp_path / "out.csv"
    assert (
        main(
            [
                "demo",
                "=SUM(A1)",
                "--site",
                "found",
                "--format",
                "csv",
                "--output",
                str(csv),
                "--journal",
                str(tmp_path / "run.sqlite"),
            ]
        )
        == 0
    )
    assert "'=SUM(A1)" in csv.read_text("utf-8")
