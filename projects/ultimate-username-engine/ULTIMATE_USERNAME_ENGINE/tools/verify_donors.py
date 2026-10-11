"""Read-only integrity check against the inventory captured by the preceding audit."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts/donor-integrity.json",
    )
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text("utf-8-sig"))
    rows = []
    for project in inventory:
        root = Path(project["path"])
        changed = [
            item["path"]
            for item in project["files"]
            if hashlib.sha256((root / item["path"]).read_bytes()).hexdigest() != item["sha256"]
        ]
        git = [
            "git",
            "--no-optional-locks",
            "-c",
            "safe.directory=" + root.as_posix(),
            "-C",
            str(root),
        ]
        head = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
        status = subprocess.check_output([*git, "status", "--porcelain"], text=True).strip()
        rows.append(
            {
                "project": project["project"],
                "files_checked": len(project["files"]),
                "changed_files": changed,
                "head": head,
                "expected_head": project["head"],
                "worktree_clean": not status,
            }
        )
    passed = all(
        not r["changed_files"] and r["head"] == r["expected_head"] and r["worktree_clean"]
        for r in rows
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"passed": passed, "projects": rows}, indent=2), encoding="utf-8"
    )
    print(json.dumps({"passed": passed, "files_checked": sum(r["files_checked"] for r in rows)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
