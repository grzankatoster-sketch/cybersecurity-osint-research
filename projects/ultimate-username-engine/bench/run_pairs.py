"""Pomiar Ultimate dla par (nick, host), których nicka NIE ma w verdicts.json danego przebiegu.

Użycie (z katalogu OSINTCHYBANOWY):
    .uee-tools\\Scripts\\python.exe bench\\run_pairs.py --pairs bench\\ground_truth\\to_label_dev_v1.jsonl --run bench\\results\\2026-10-10

Dla każdego nicka spoza verdicts.json: z katalogu Ultimate (data/catalog.json, czytany raz) wybiera definicje, których
host URL-a profilu (po podstawieniu nicka, bez www) równa się hostowi pary, i uruchamia CLI Ultimate tak jak
bench/compare.py (`search --mode exhaustive --enrich basic`), ograniczone opcją `--site <id definicji>` (CLI przyjmuje
identyfikatory katalogu, np. `maigret:2c4b...`). Wynik normalizuje compare.ultimate_rows + evaluate.aggregate i scala do
<run>/verdicts_extra.json (nicks -> nick -> ultimate -> host -> {category, raw, url}); surowe wyjście CLI leży w
<run>/raw_extra/<nick>/. Hosty już obecne w verdicts_extra.json nie są mierzone ponownie.
evaluate.py scala verdicts_extra.json przy wczytaniu werdyktów (tylko brakujące nicki/hosty). OSINT nie jest uruchamiany.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path.insert(0, str(BENCH))

import compare  # noqa: E402
import evaluate  # noqa: E402

CLI_TIMEOUT = 2 * 3600


def load_pairs(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def site_ids_for(catalog: dict[str, dict], host: str, nick: str) -> list[str]:
    """Identyfikatory definicji, których profile_url (z podstawionym nickiem) ma ten host (bez www)."""
    return sorted(sid for sid, s in catalog.items()
                  if compare.hostkey(s["profile_url"].replace("{username}", nick)) == host)


def cli_argv(nick: str, site_ids: list[str], out: Path) -> list[str]:
    argv = ["search", nick, "--mode", "exhaustive", "--enrich", "basic",
            "--output", str(out / "results.json"), "--journal", str(out / "journal.sqlite")]
    for sid in site_ids:
        argv += ["--site", sid]
    return argv


def run_cli(nick: str, site_ids: list[str], out: Path) -> int:
    """Uruchamia CLI Ultimate w podprocesie (jak worker w compare.py, bez licznika żądań). Zwraca kod wyjścia."""
    out.mkdir(parents=True, exist_ok=True)
    with (out / "stderr.log").open("w", encoding="utf-8") as err:
        proc = subprocess.run([sys.executable, "-m", "ultimate_username", *cli_argv(nick, site_ids, out)],
                              cwd=str(out), stderr=err, timeout=CLI_TIMEOUT)
    return proc.returncode


def merge_extra(base: dict, new: dict) -> dict:
    """Dopisuje tylko brakujące nicki/hosty; nic nie nadpisuje."""
    for nick, engines in new.get("nicks", {}).items():
        for engine, hosts in engines.items():
            slot = base.setdefault("nicks", {}).setdefault(nick, {}).setdefault(engine, {})
            for host, v in hosts.items():
                slot.setdefault(host, v)
    return base


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pairs", type=Path, required=True)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--catalog", type=Path, default=ROOT / "ULTIMATE_USERNAME_ENGINE" / "data" / "catalog.json")
    args = ap.parse_args(argv)
    known = set(json.loads((args.run / "verdicts.json").read_text("utf-8"))["nicks"])
    extra_path = args.run / "verdicts_extra.json"
    extra = json.loads(extra_path.read_text("utf-8")) if extra_path.exists() else {"source": "bench/run_pairs.py", "nicks": {}}
    wanted: dict[str, set[str]] = defaultdict(set)
    for p in load_pairs(args.pairs):
        if p["nick"] not in known and p["host"]:
            have = extra["nicks"].get(p["nick"], {}).get("ultimate", {})
            if p["host"] not in have:
                wanted[p["nick"]].add(p["host"])
    if not wanted:
        print("Nic do zmierzenia (wszystkie nicki w verdicts.json albo już w verdicts_extra.json).")
        return 0
    catalog = {s["id"]: s for s in json.loads(args.catalog.read_text("utf-8-sig"))}
    for nick in sorted(wanted):
        ids: list[str] = []
        for host in sorted(wanted[nick]):
            found = site_ids_for(catalog, host, nick)
            if not found:
                print(f"[brak definicji] {nick}:{host}")
            ids += [i for i in found if i not in ids]
        if not ids:
            continue
        out = (args.run / "raw_extra" / nick).resolve()
        print(f"start {nick}: {len(ids)} definicji dla {len(wanted[nick])} hostów", flush=True)
        code = run_cli(nick, ids, out)
        print(f"koniec {nick}: kod={code}", flush=True)
        if not (out / "results.json").exists():
            print(f"[błąd] {nick}: brak results.json (zobacz {out / 'stderr.log'})")
            continue
        new = {"nicks": {nick: {"ultimate": evaluate.aggregate(compare.ultimate_rows(out))}}}
        merge_extra(extra, new)
    extra_path.write_text(json.dumps(extra, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
    print("zapisano", extra_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
