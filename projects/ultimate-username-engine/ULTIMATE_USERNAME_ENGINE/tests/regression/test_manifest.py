import ast
import json
from pathlib import Path


def test_regression_manifest_complete_and_tests_exist():
    root = Path(__file__).resolve().parents[2]
    records = json.loads((root / "docs/regression-manifest.json").read_text("utf-8"))
    ledger = json.loads((root / "docs/audit-ledger.json").read_text("utf-8"))
    assert len(records) == len({r["id"] for r in records}) == 92
    assert {r["id"] for r in records} == {r["id"] for r in ledger}
    for record in records:
        assert record["status"] in {"COVERED", "NOT_APPLICABLE", "REQUIRES_RUNTIME"}
        assert record["scope"]
        if record["status"] == "COVERED":
            assert record["tests"]
        for nodeid in record["tests"]:
            filename, function = nodeid.split("::")
            parsed = ast.parse((root / filename).read_text("utf-8"))
            assert any(
                isinstance(n, ast.FunctionDef) and n.name == function for n in ast.walk(parsed)
            )
