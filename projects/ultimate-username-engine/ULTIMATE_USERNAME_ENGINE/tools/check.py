"""Run the complete local quality gates and verify actual regression outcomes."""

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    environment = {**os.environ, "PYTHONUTF8": "1"}
    (ROOT / ".test-runs").mkdir(exist_ok=True)
    commands = [
        ["ruff", "check", "."],
        ["ruff", "format", "--check", "."],
        ["mypy", "src"],
        ["pytest", "-q", "--basetemp", str(ROOT / ".test-runs" / uuid4().hex)],
    ]
    records = []
    for command in commands:
        completed = subprocess.run(
            [sys.executable, "-m", *command],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
        print(completed.stdout, end="")
        print(completed.stderr, end="", file=sys.stderr)
        records.append(
            {
                "command": command,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
    report = json.loads((ROOT / "artifacts/test-results.json").read_text("utf-8"))
    unverified = [
        key
        for key, row in report["regression"].items()
        if row["status"] == "COVERED" and not row["run_verified"]
    ]
    passed = all(record["exit_code"] == 0 for record in records) and not unverified
    (ROOT / "artifacts/quality-gates.json").write_text(
        json.dumps(
            {
                "passed": passed,
                "unverified_regressions": unverified,
                "checks": records,
                "python": sys.version,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("ALL QUALITY GATES PASSED" if passed else "QUALITY GATE FAILURE")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
