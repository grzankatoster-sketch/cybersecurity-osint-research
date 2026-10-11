"""Składa dev_v1.jsonl z oznaczonych paczek (dev_batches/labeled_*.jsonl), kont usuniętych
(deleted_candidates_v1.jsonl) i opcjonalnie paczek nicków dev (dev_batches/labeled_b*.jsonl).
Grupa pochodzi z dev_sample_v1.json / dev_sample_v1b.json (dopisana PO etykietowaniu). Deterministyczne."""
from __future__ import annotations

import json
from pathlib import Path

GT = Path(__file__).resolve().parent


def rows(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text("utf-8").splitlines() if x.strip()]


def groups(name: str) -> dict[str, str]:
    p = GT / name
    return {it["id"]: it["group"] for it in json.loads(p.read_text("utf-8"))["items"]} if p.exists() else {}


def main() -> None:
    grp = groups("dev_sample_v1.json") | groups("dev_sample_v1b.json")
    out = []
    for p in sorted((GT / "dev_batches").glob("labeled_*.jsonl")):
        for r in rows(p):
            r["group"] = grp.get(r["id"], "unknown")
            out.append(r)
    for i, r in enumerate(rows(GT / "deleted_candidates_v1.jsonl"), 1):
        r = {"id": f"dx-{i:03d}", **r, "group": "deleted_extra"}
        out.append(r)
    out.sort(key=lambda r: r["id"])
    ids = [r["id"] for r in out]
    assert len(ids) == len(set(ids)), "zdublowane id"
    (GT / "dev_v1.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in out), encoding="utf-8")
    from collections import Counter
    print(len(out), Counter(r["label"] for r in out), Counter(r["group"] for r in out))


if __name__ == "__main__":
    main()
