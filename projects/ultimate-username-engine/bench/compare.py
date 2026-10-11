"""Powtarzalny pomiar porównawczy: Ultimate (--mode exhaustive) kontra OSINT username-engine (--level full).

Oba silniki uruchamiane są BEZ ZMIAN, każdy w osobnym podprocesie, z obserwacyjnym liczeniem żądań HTTP
(wzorce z ../full_runtime.py: ObservedTransport i hashe źródeł, ../compare_sampler51.py oraz
../old_full_runtime.py: patch aiohttp.ClientSession._request, ../full_runtime_report.py: urlkey).

Użycie (z katalogu OSINTCHYBANOWY, interpreter .uee-tools):
    .uee-tools\\Scripts\\python.exe bench\\compare.py Sampler51 PublicRefA publicrefb
    ... --date 2026-10-10        katalog wyników bench/results/<data>/ (domyślnie dziś)
    ... --only ultimate|osint    tylko jeden silnik
    ... --mode normal            tryb Ultimate (domyślnie exhaustive); wyniki innego trybu w bench/results/<data>_<tryb>/
    ... --report-only            bez skanowania, tylko przelicz tabelę z istniejących raw/
Wynik: bench/results/<data>/summary.json, SUMMARY.md, raw/<nick>/<silnik>/ (surowe, poza gitem).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import urlsplit

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
ULTIMATE = ROOT / "ULTIMATE_USERNAME_ENGINE"
OSINT = ROOT.parent / "osint-toolkit" / "username-engine"
ENGINES = ("ultimate", "osint")
WORKER_TIMEOUT = 2 * 3600
ULTIMATE_MODES = ("quick", "normal", "deep", "exhaustive")
DEFAULT_MODE = "exhaustive"

# Wspólne, rozłączne kategorie końcowe (jedna na serwis).
CATEGORIES = ("FOUND", "PROBABLE", "NOT_FOUND", "UNKNOWN", "BLOCKED", "ERROR", "SKIPPED")
# OSINT: ERROR z blokadą po stronie serwisu (anty-bot, 403/429, wymuszone logowanie).
OSINT_BLOCKED = ("anty-bot", "captcha", "zabroniony", "logowania", "(403)", "(429)", "limit zapytań", "rate")
# OSINT: ERROR z odpowiedzią, której reguły nie rozstrzygnęły (odpowiednik UNKNOWN przy stanie OK w Ultimate).
OSINT_UNKNOWN = ("nierozpoznana strona", "nierozpoznany kod")
ULTIMATE_BLOCKED = ("BLOCKED", "RATE_LIMITED")
ULTIMATE_SKIPPED = ("SKIPPED", "UNSUPPORTED", "INVALID_INPUT", "API_REQUIRED", "CONFIG_ERROR")


def utc() -> str:
    return datetime.now(UTC).isoformat()


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def source_hashes(engine: str) -> dict[str, str]:
    if engine == "ultimate":
        data = [ULTIMATE / "data" / name for name in ("catalog.json", "osint_custom.json", "health.json")]
        paths = sorted((ULTIMATE / "src").rglob("*.py")) + [p for p in data if p.is_file()]
        base = ULTIMATE
    else:
        paths = sorted((OSINT / "src").rglob("*.py")) + [OSINT / "data/sites.json", OSINT / "data/health.json"]
        base = OSINT
    return {p.relative_to(base).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def hostkey(url: str) -> str:
    """Klucz dopasowania serwisu: host bez www (szablony URL obu katalogów różnią się ścieżką)."""
    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


# --------------------------------------------------------------------------- workery (podprocesy)

def ultimate_argv(nick: str, out: Path, mode: str = DEFAULT_MODE) -> list[str]:
    return ["search", nick, "--mode", mode, "--output", str(out / "results.json"),
            "--journal", str(out / "journal.sqlite")]


def worker_ultimate(nick: str, out: Path, mode: str = DEFAULT_MODE) -> None:
    from ultimate_username import cli
    from ultimate_username.http_transport import AiohttpTransport

    stats = {"requests": 0, "statuses": Counter(), "transport_errors": Counter(), "hosts": set()}

    class ObservedTransport(AiohttpTransport):
        async def send(self, request):
            stats["requests"] += 1
            stats["hosts"].add(hostkey(request.url))
            response = await super().send(request)
            stats["statuses"][str(response.status)] += 1
            if response.error:
                stats["transport_errors"][str(getattr(response.error, "code", response.error))] += 1
            return response

    cli.AiohttpTransport = ObservedTransport
    argv = ultimate_argv(nick, out, mode)
    before = source_hashes("ultimate")
    started, t = utc(), time.perf_counter()
    with (out / "stderr.log").open("w", encoding="utf-8") as err:
        sys.stderr = err
        try:
            code = cli.main(argv)
        finally:
            sys.stderr = sys.__stderr__
    dump(out / "manifest.json", {
        "engine": "ultimate", "nick": nick, "mode": mode, "argv": argv, "exit_code": code,
        "exit_code_note": "1 = co najmniej jeden serwis z błędem/blokadą (normalne przy pełnym skanie)",
        "started_at_utc": started, "wall_seconds": time.perf_counter() - t,
        "requests": stats["requests"], "distinct_hosts": len(stats["hosts"]),
        "http_statuses": dict(stats["statuses"]), "transport_errors": dict(stats["transport_errors"]),
        "source_revision": "sha256:" + hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        "sources_unchanged": before == source_hashes("ultimate"),
        "python": sys.version})


def worker_osint(nick: str, out: Path) -> None:
    sys.path.insert(0, str(OSINT / "src"))
    import aiohttp
    from username_engine import cli

    stats = {"requests": 0, "statuses": Counter(), "errors": Counter()}
    original = aiohttp.ClientSession._request

    async def observed_request(self, method, url, *args, **kwargs):
        stats["requests"] += 1
        try:
            response = await original(self, method, url, *args, **kwargs)
            stats["statuses"][str(response.status)] += 1
            return response
        except Exception as exc:
            stats["errors"][type(exc).__name__] += 1
            raise

    aiohttp.ClientSession._request = observed_request
    argv = [nick, "--level", "full", "--no-variants", "--direct", "--strict-tls", "--json", "results.json",
            "--results-dir", str(out / "runs"), "--ttl-hours", "0"]
    before = source_hashes("osint")
    started, t = utc(), time.perf_counter()
    import contextlib
    with (out / "stdout.log").open("w", encoding="utf-8") as so, (out / "stderr.log").open("w", encoding="utf-8") as se:
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            code = cli.main(argv)
    produced = sorted((out / "runs").rglob("results.json"))
    dump(out / "manifest.json", {
        "engine": "osint", "nick": nick, "argv": argv, "exit_code": code,
        "started_at_utc": started, "wall_seconds": time.perf_counter() - t,
        "requests": stats["requests"], "http_statuses": dict(stats["statuses"]),
        "transport_exceptions": dict(stats["errors"]),
        "results_file": str(produced[-1]) if produced else None,
        "source_revision": "sha256:" + hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        "sources_unchanged": before == source_hashes("osint"),
        "python": sys.version})


# --------------------------------------------------------------------------- normalizacja wyników

def ultimate_rows(raw: Path) -> list[dict]:
    rows = []
    for r in json.loads((raw / "results.json").read_text("utf-8")):
        d = r["detection"]
        verdict, state = d["verdict"], d["state"]
        if verdict in ("FOUND", "PROBABLE", "NOT_FOUND"):
            cat = verdict
        elif not r.get("attempts") or state in ULTIMATE_SKIPPED:
            cat = "SKIPPED"
        elif state == "OK":
            cat = "UNKNOWN"
        elif state in ULTIMATE_BLOCKED:
            cat = "BLOCKED"
        else:
            cat = "ERROR"
        rows.append({"key": hostkey(r["profile_url"]), "url": r["profile_url"], "site": r.get("canonical_service") or r["site_id"],
                     "category": cat, "raw": f"{verdict}/{state}"})
    return rows


def osint_rows(raw: Path, min_conf: float = 0.6) -> list[dict]:
    manifest = json.loads((raw / "manifest.json").read_text("utf-8"))
    data = json.loads(Path(manifest["results_file"]).read_text("utf-8"))
    rows = []
    for results in data["results"].values():
        for r in results:
            status, reason = r["status"], (r.get("reason") or "")
            if status == "FOUND":
                cat = "FOUND" if r.get("confidence", 0) >= min_conf else "PROBABLE"
            elif status == "NOT_FOUND":
                cat = "NOT_FOUND"
            elif status == "UNSUPPORTED":
                cat = "SKIPPED"
            elif any(m in reason.lower() for m in OSINT_UNKNOWN):
                cat = "UNKNOWN"
            elif any(m in reason.lower() for m in OSINT_BLOCKED):
                cat = "BLOCKED"
            else:
                cat = "ERROR"
            rows.append({"key": hostkey(r["url"]), "url": r["url"], "site": r["site"], "category": cat,
                         "raw": f"{status}/{r.get('confidence')}/{reason[:60]}"})
    return rows


def summarize_nick(nick: str, raw: Path) -> dict:
    out = {"nick": nick, "engines": {}}
    rows = {}
    for engine in ENGINES:
        mf = raw / nick / engine / "manifest.json"
        if not mf.exists():
            continue
        manifest = json.loads(mf.read_text("utf-8"))
        rows[engine] = (ultimate_rows if engine == "ultimate" else osint_rows)(raw / nick / engine)
        counts = Counter(r["category"] for r in rows[engine])
        out["engines"][engine] = {
            "services": len(rows[engine]), "counts": {c: counts.get(c, 0) for c in CATEGORIES},
            "requests": manifest["requests"], "wall_seconds": round(manifest["wall_seconds"], 1),
            "exit_code": manifest["exit_code"], "sources_unchanged": manifest["sources_unchanged"],
            "source_revision": manifest["source_revision"],
            "hits": sorted({r["key"] for r in rows[engine] if r["category"] in ("FOUND", "PROBABLE")}),
            "found": sorted({r["key"] for r in rows[engine] if r["category"] == "FOUND"}),
        }
    if len(rows) == 2:
        u, o = out["engines"]["ultimate"], out["engines"]["osint"]
        decided = {e: {r["key"] for r in rows[e] if r["category"] in ("FOUND", "PROBABLE", "NOT_FOUND")} for e in rows}
        both = sorted(set(u["hits"]) & set(o["hits"]))
        only_u = sorted(set(u["hits"]) - set(o["hits"]))
        only_o = sorted(set(o["hits"]) - set(u["hits"]))
        out["overlap"] = {
            "key": "host bez www; trafienie = FOUND lub PROBABLE",
            "both": both, "only_ultimate": only_u, "only_osint": only_o,
            # Czy druga strona w ogóle rozstrzygnęła ten serwis (NOT_FOUND = sprzeczność, brak = poza zasięgiem/błąd).
            "only_ultimate_osint_said_not_found": sorted(k for k in only_u if k in decided["osint"]),
            "only_osint_ultimate_said_not_found": sorted(k for k in only_o if k in decided["ultimate"]),
            "found_both": sorted(set(u["found"]) & set(o["found"])),
        }
    return out


def render_md(summary: dict) -> str:
    lines = [f"# Bench: Ultimate vs OSINT ({summary['date']})", "",
             f"Ultimate: `--mode {summary.get('ultimate_mode', DEFAULT_MODE)}`, rewizja `{summary.get('ultimate_revision', '?')[:23]}`. "
             f"OSINT: `--level full --no-variants --direct --strict-tls`, rewizja `{summary.get('osint_revision', '?')[:23]}`.",
             "Kategorie są rozłączne (jedna na serwis). UNKNOWN = odpowiedź bez rozstrzygnięcia; BLOCKED = anty-bot/403/429/logowanie; "
             "ERROR = sieć, timeout, TLS, 5xx; SKIPPED = nazwa niezgodna z serwisem, brak próby lub API. "
             "OSINT: FOUND = FOUND z pewnością ≥0,6 (domyślny próg CLI), PROBABLE = FOUND <0,6. Część wspólna po hoście.", "",
             "| Nick | Silnik | Serwisy | FOUND | PROBABLE | NOT_FOUND | UNKNOWN | BLOCKED | Błędy | Pominięte | Żądania | Czas [s] | Wspólne | Tylko ten |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for n in summary["nicks"]:
        ov = n.get("overlap", {})
        for engine in ENGINES:
            e = n["engines"].get(engine)
            if not e:
                continue
            c = e["counts"]
            only = ov.get("only_ultimate" if engine == "ultimate" else "only_osint")
            lines.append(f"| {n['nick']} | {engine} | {e['services']} | {c['FOUND']} | {c['PROBABLE']} | {c['NOT_FOUND']} | "
                         f"{c['UNKNOWN']} | {c['BLOCKED']} | {c['ERROR']} | {c['SKIPPED']} | {e['requests']} | {e['wall_seconds']} | "
                         f"{len(ov['both']) if ov else '-'} | {len(only) if only is not None else '-'} |")
    lines += ["", "## Trafienia (FOUND + PROBABLE) po hoście", ""]
    for n in summary["nicks"]:
        ov = n.get("overlap")
        if not ov:
            continue
        lines += [f"### {n['nick']}", "",
                  f"- Wspólne ({len(ov['both'])}): {', '.join(ov['both']) or '—'}",
                  f"- Tylko Ultimate ({len(ov['only_ultimate'])}): {', '.join(ov['only_ultimate']) or '—'}",
                  f"  - z tego OSINT rozstrzygnął NOT_FOUND: {', '.join(ov['only_ultimate_osint_said_not_found']) or '—'}",
                  f"- Tylko OSINT ({len(ov['only_osint'])}): {', '.join(ov['only_osint']) or '—'}",
                  f"  - z tego Ultimate rozstrzygnął NOT_FOUND: {', '.join(ov['only_osint_ultimate_said_not_found']) or '—'}",
                  f"- FOUND w obu: {', '.join(ov['found_both']) or '—'}", ""]
    lines += ["Uwaga: wynik live zależy od sieci, IP i anty-botów; obie aplikacje uruchamiano sekwencyjnie, nie równolegle. "
              "Trafienie ≠ ta sama osoba (zbieżność nazw); to pomiar pokrycia silnika, nie identyfikacji.", ""]
    return "\n".join(lines)


def results_dir(day: str, mode: str = DEFAULT_MODE) -> Path:
    """Domyślny tryb zostaje w bench/results/<data>/; inny tryb nie miesza się z jego wynikami."""
    return BENCH / "results" / (day if mode == DEFAULT_MODE else f"{day}_{mode}")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # konsola Windows cp1250
    if len(sys.argv) >= 4 and sys.argv[1] in ("_ultimate", "_osint"):
        out = Path(sys.argv[3])
        out.mkdir(parents=True, exist_ok=True)
        if sys.argv[1] == "_ultimate":
            worker_ultimate(sys.argv[2], out, sys.argv[4] if len(sys.argv) > 4 else DEFAULT_MODE)
        else:
            worker_osint(sys.argv[2], out)
        return 0
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("nicks", nargs="+")
    ap.add_argument("--date", default=date.today().isoformat())
    ap.add_argument("--only", choices=ENGINES)
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--mode", choices=ULTIMATE_MODES, default=DEFAULT_MODE,
                    help="tryb Ultimate (domyślnie exhaustive; inny tryb ma osobny katalog wyników)")
    args = ap.parse_args()
    day = results_dir(args.date, args.mode)
    raw = day / "raw"
    engines = (args.only,) if args.only else ENGINES
    if not args.report_only:
        for nick in args.nicks:
            for engine in engines:
                target = raw / nick / engine
                if (target / "manifest.json").exists():
                    print(f"[pomijam] {nick}/{engine}: wynik już istnieje ({target})", flush=True)
                    continue
                target.mkdir(parents=True, exist_ok=True)
                print(f"[{utc()}] start {nick}/{engine}", flush=True)
                command = [sys.executable, str(Path(__file__).resolve()), "_" + engine, nick, str(target)]
                if engine == "ultimate" and args.mode != DEFAULT_MODE:
                    command.append(args.mode)
                proc = subprocess.run(command, cwd=str(target), timeout=WORKER_TIMEOUT)
                mf = target / "manifest.json"
                info = json.loads(mf.read_text("utf-8")) if mf.exists() else {}
                print(f"[{utc()}] koniec {nick}/{engine}: proces={proc.returncode} "
                      f"żądania={info.get('requests')} czas={round(info.get('wall_seconds', 0), 1)}s", flush=True)
    nicks = [summarize_nick(n, raw) for n in args.nicks]
    summary = {"date": args.date, "generated_at_utc": utc(), "ultimate_mode": args.mode,
               "categories": list(CATEGORIES), "nicks": nicks}
    for engine in ENGINES:
        revs = {n["engines"][engine]["source_revision"] for n in nicks if engine in n["engines"]}
        summary[f"{engine}_revision"] = (revs.pop() if len(revs) == 1 else f"MIESZANE: {sorted(revs)}" if revs
                                         else "brak przebiegu")
    dump(day / "summary.json", summary)
    (day / "SUMMARY.md").write_text(render_md(summary), encoding="utf-8")
    print((day / "SUMMARY.md").read_text("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
