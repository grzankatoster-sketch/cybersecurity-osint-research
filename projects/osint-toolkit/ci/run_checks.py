"""Kontrole CI pipeline'u OSINT (rejestry -> adapter -> org-intel -> entity-graph -> eksport), tylko stdlib.

Uzycie (z katalogu glownego repozytorium, ten sam skrypt lokalnie i w GitHub Actions):
  py ci/run_checks.py                       wszystkie kroki
  py ci/run_checks.py --list                lista krokow
  py ci/run_checks.py --only test:org-intel --only lint     wybrane kroki albo cale grupy (hygiene, test, lint)
  py ci/run_checks.py --skip lint           pomin grupe / krok
  py ci/run_checks.py --artifacts ci-artifacts              zapisz summary.json / summary.md i przeskanuj je

Kody wyjscia: 0 wszystko OK; 1 testy albo kontrole nieudane (takze trafienie skanera artefaktow);
2 blad uzycia albo srodowiska (nieznany krok, brak pytest/ruff/zaleznosci, zly katalog, Python < 3.12).

Zasady: zadnej sieci (testy sieciowe wylaczone: zmienne EG_*, BRAVE_*, OSINT_*, HIBP_*, ORG_INTEL_* i proxy nie trafiaja do
krokow), zadnych sekretow (workflow ich nie potrzebuje), raporty bez e-maili i tokenow (pytest -q bez -l/--showlocals,
wypisywane podsumowanie jest maskowane, artefakty skanowane przed uploadem)."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2
MIN_PYTHON = (3, 12)
LINE_LENGTH = "120"

PIPELINE_PACKAGES = ("osint-connectors", "org-intel", "hibp-monitor", "entity-graph", "meta-search")
# username-engine jest w .gitignore ("osobne repo"): nie ma go w checkoutcie CI, wiec nie ma tez kroku testowego.
NOT_IN_REPO: dict[str, str] = {}
FEED_AVAILABLE = (ROOT / "osint-poland" / "src" / "osint_poland" / "org_intel_feed.py").is_file()
if not FEED_AVAILABLE:
    NOT_IN_REPO["osint-poland"] = "not published in the public monorepo; registry adapter steps skipped"

# Pliki, ktore sa ruff-czyste (ruff 0.16, --line-length 120, uruchamiane z katalogu pakietu, zeby `src` dalo poprawny
# podzial na first-party). Pozostale pliki pakietow nie sa objete (starszy styl); rozszerzac, gdy pakiet bedzie czysty.
LINT_TARGETS: dict[str, tuple[str, tuple[str, ...]]] = {
    "org-intel": ("org-intel", (".",)),
    "entity-graph": (
        "entity-graph",
        (
            "src/entity_graph/importers/org_intel.py",
            "src/entity_graph/profile_analyzer.py",
            "src/entity_graph/profile_discovery.py",
            "src/entity_graph/profile_urls.py",
            "tests/test_import_org_intel.py",
            "tests/test_profile_discovery.py",
            "tests/test_profile_discovery_proxy.py",
            "tests/test_maltego_export.py",
            "tests/test_guardrails_proxy_rule.py",
        ),
    ),
    "hibp-monitor": ("hibp-monitor", ("tests/test_catalog_boundary.py",)),
    "osint-poland-feed": (
        "osint-poland",
        ("src/osint_poland/org_intel_feed.py", "tests/test_org_intel_feed.py"),
    ),
    "ci": ("ci", (".",)),
}

# Zasieg kontroli koncowek linii: pakiety pipeline'u + pliki CI (reszta repo ma stare pliki CRLF/LF i nie jest sprawdzana).
EOL_SCOPE = (
    "osint-connectors/",
    "org-intel/",
    "hibp-monitor/",
    "entity-graph/",
    "meta-search/",
    "ci/",
    ".github/workflows/osint-pipeline.yml",
    "osint-poland/src/osint_poland/org_intel_feed.py",
    "osint-poland/tests/test_org_intel_feed.py",
    "osint-poland/tests/fixtures/org_intel_feed/",
)
KNOWN_MIXED_FILE = ROOT / "ci" / "known_mixed_eol.txt"

# Zmienne srodowiska, ktore nie moga trafic do krokow (siec, konfiguracja wyszukiwarki, baza, testy online).
DROP_PREFIXES = ("BRAVE_", "OSINT_", "EG_", "HIBP_", "ORG_INTEL_")
DROP_EXACT = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "PYTHONPATH", "PYTHONSTARTUP"}

# --------------------------------------------------------------------------- maskowanie i skaner sekretow

# Takze adres uciety przez pytest (`a@exa...`): wystarczy lokalna czesc + `@` + znak domeny. Zamaskowane `p***@x.y` nie pasuja.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|BSA[A-Za-z0-9_-]{20,}|(?:sk|pk|rk)_live_[A-Za-z0-9]{16,}"
    r"|whsec_[A-Za-z0-9]{16,})"
)
ASSIGNMENT_RE = re.compile(
    r"\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[=:]\s*[\"']?[A-Za-z0-9_\-/+=.]{12,}", re.IGNORECASE
)
SCAN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", JWT_RE),
    ("bearer", BEARER_RE),
    ("private-key", PRIVATE_KEY_RE),
    ("token", TOKEN_RE),
    ("secret-assignment", ASSIGNMENT_RE),
    ("email", EMAIL_RE),
)


def mask(text: str) -> str:
    """Maskuje e-maile, JWT, Bearer, klucze prywatne i tokeny w tekscie wypisywanym przez skrypt."""
    text = PRIVATE_KEY_RE.sub("<private-key>", text)
    text = JWT_RE.sub("<jwt>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = TOKEN_RE.sub("<token>", text)
    text = ASSIGNMENT_RE.sub("<secret-assignment>", text)
    return EMAIL_RE.sub("<e-mail>", text)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    kind: str

    def __str__(self) -> str:  # nigdy nie zawiera znalezionej wartosci
        return f"{self.path}:{self.line}: {self.kind}"


def scan_text(text: str, path: str = "<text>") -> list[Hit]:
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        hits += [Hit(path, number, kind) for kind, rule in SCAN_RULES if rule.search(line)]
    return hits


def scan_artifacts(folder: Path, delete_offenders: bool = True) -> list[Hit]:
    """Skanuje wszystkie pliki w katalogu artefaktow; plik z trafieniem jest usuwany (nie pojdzie do uploadu)."""
    hits: list[Hit] = []
    if not folder.is_dir():
        return hits
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        rel = path.relative_to(folder).as_posix()
        found = scan_text(path.read_bytes().decode("utf-8", errors="replace"), rel)
        if found and delete_offenders:
            path.unlink()
        hits += found
    return hits


# --------------------------------------------------------------------------- kontrole higieny repozytorium


def git(args: Sequence[str], root: Path = ROOT) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None


def is_git_root(root: Path) -> bool:
    proc = git(["rev-parse", "--show-toplevel"], root)
    if proc is None or proc.returncode != 0:
        return False
    try:
        return Path(proc.stdout.decode("utf-8", errors="replace").strip()).resolve() == root.resolve()
    except OSError:
        return False


_WALK_SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", "ci-artifacts"}


def list_files(root: Path = ROOT) -> tuple[list[str], str]:
    """(sciezki wzgledne z '/', tryb). Tryb 'git' = `git ls-files`; poza repo git (np. katalog z `git archive`)
    'tree' = przejscie po plikach z pominieciem srodowisk i cache'y."""
    if is_git_root(root):
        proc = git(["ls-files", "-z"], root)
        if proc is not None and proc.returncode == 0:
            return [p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p], "git"
    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _WALK_SKIP]
        files += [Path(base, n).relative_to(root).as_posix() for n in names]
    return sorted(files), "tree"


_FIXTURE_DIR = re.compile(r"(^|/)tests/fixtures/")
_CASE_BASENAMES = {"graph.json", "audit.jsonl", "graph.graphml", "maltego.csv", "store.json"}
_CASE_SEGMENTS = {"wyniki", "org-intel-data"}


def case_data_violations(files: Iterable[str]) -> list[str]:
    """Pliki, ktorych nie wolno wersjonowac: dane spraw (graph.json, audit.jsonl, graph.graphml, maltego.csv,
    store.json poza tests/fixtures), katalogi wynikow (`wyniki/`, `org-intel-data/`), pliki *.env i .env* poza .env.example."""
    bad = []
    for path in files:
        parts = path.split("/")
        name = parts[-1]
        lower = name.lower()
        in_fixtures = bool(_FIXTURE_DIR.search(path))
        is_env = lower.endswith(".env") or lower == ".env" or (lower.startswith(".env.") and lower != ".env.example")
        if (
            (name in _CASE_BASENAMES and not in_fixtures)
            or (_CASE_SEGMENTS & {p.lower() for p in parts[:-1]} and not in_fixtures)
            or is_env
        ):
            bad.append(path)
    return sorted(bad)


def eol_kind(data: bytes) -> str:
    """'binary' | 'none' | 'lf' | 'crlf' | 'mixed' (mixed = jednoczesnie CRLF i samotne LF, jak w git ls-files --eol)."""
    if b"\0" in data[:8000]:
        return "binary"
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    if crlf and lf:
        return "mixed"
    return "crlf" if crlf else ("lf" if lf else "none")


def in_eol_scope(path: str) -> bool:
    return any(path == s or (s.endswith("/") and path.startswith(s)) for s in EOL_SCOPE)


def mixed_eol_files(root: Path = ROOT) -> tuple[list[str], str]:
    """Pliki tekstowe z MIESZANYMI koncowkami linii w zasiegu pipeline'u. git: `git ls-files --eol` (i/mixed lub w/mixed);
    poza git: bajty plikow."""
    if is_git_root(root):
        proc = git(["ls-files", "--eol", "-z"], root)
        if proc is not None and proc.returncode == 0:
            mixed = []
            for entry in proc.stdout.decode("utf-8", errors="replace").split("\0"):
                info, _, path = entry.partition("\t")
                if path and in_eol_scope(path) and ("i/mixed" in info.split() or "w/mixed" in info.split()):
                    mixed.append(path)
            return sorted(mixed), "git"
    files, _ = list_files(root)
    mixed = []
    for path in files:
        if in_eol_scope(path) and (root / path).is_file() and eol_kind((root / path).read_bytes()) == "mixed":
            mixed.append(path)
    return sorted(mixed), "tree"


def read_known_mixed(path: Path = KNOWN_MIXED_FILE) -> set[str]:
    if not path.is_file():
        return set()
    lines = (ln.split("#", 1)[0].strip() for ln in path.read_text(encoding="utf-8").splitlines())
    return {ln for ln in lines if ln}


# --------------------------------------------------------------------------- kroki


@dataclass
class Result:
    name: str
    status: str  # OK | FAIL | SKIP
    seconds: float
    detail: str = ""
    notes: list[str] = field(default_factory=list)
    output_tail: str = ""


@dataclass
class Step:
    name: str
    describe: str
    run: object  # callable(Context) -> Result


@dataclass
class Context:
    python: str
    ruff: list[str] | None
    root: Path = ROOT


def step_env() -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items() if not k.upper().startswith(DROP_PREFIXES) and k.upper() not in DROP_EXACT
    }
    env.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1")
    return env


def run_process(cmd: Sequence[str], cwd: Path, timeout: int = 1500) -> tuple[int, str, float]:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=str(cwd),
            env=step_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr, time.monotonic() - start
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        text = out.decode("utf-8", errors="replace") if isinstance(out, bytes) else out
        return 124, text + f"\nPrzekroczono limit {timeout} s", time.monotonic() - start


_PYTEST_SUMMARY = re.compile(
    r"^=*\s*(?:\d+ (?:passed|failed|skipped|errors?|deselected|xfailed|xpassed|warnings?)[^\n]*)$"
)


def pytest_detail(output: str) -> str:
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    for line in reversed(lines):
        if _PYTEST_SUMMARY.match(line) or line.startswith("no tests ran"):
            return line.strip("= ")
    return lines[-1] if lines else "brak wyjscia"


def tail(output: str, n: int = 40) -> str:
    return mask("\n".join(output.splitlines()[-n:]))


def make_pytest_step(name: str, package: str, targets: Sequence[str] = ()) -> Step:
    def run(ctx: Context) -> Result:
        # -q bez -l/--showlocals: wartosci zmiennych lokalnych (moga zawierac dane) nigdy nie trafiaja do logu
        code, out, secs = run_process(
            [ctx.python, "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets], ctx.root / package
        )
        detail = pytest_detail(out)
        if code == 0 and not re.search(r"\b\d+ passed", detail):
            return Result(name, "FAIL", secs, f"{detail} (brak zaliczonych testow)", output_tail=tail(out))
        failed = [ln for ln in out.splitlines() if ln.startswith(("FAILED ", "ERROR "))][:15]
        return Result(
            name,
            "OK" if code == 0 else "FAIL",
            secs,
            mask(detail),
            notes=[mask(ln)[:200] for ln in failed],
            output_tail="" if code == 0 else tail(out),
        )

    return Step(name, f"pytest w {package}/ {' '.join(targets)}".strip(), run)


def make_lint_step(name: str, package: str, targets: Sequence[str]) -> Step:
    def run(ctx: Context) -> Result:
        assert ctx.ruff, "ruff nieznaleziony"
        start = time.monotonic()
        lines, ok = [], True
        for sub in (["check", "--no-cache", "--output-format", "concise"], ["format", "--no-cache", "--check"]):
            code, out, _ = run_process([*ctx.ruff, *sub, "--line-length", LINE_LENGTH, *targets], ctx.root / package)
            ok &= code == 0
            lines.append(
                f"ruff {sub[0]}: " + ("OK" if code == 0 else "BLAD") + ("" if code == 0 else "\n" + tail(out, 25))
            )
        secs = time.monotonic() - start
        return Result(
            name,
            "OK" if ok else "FAIL",
            secs,
            f"check + format --check, {len(targets)} cel(e)",
            output_tail="" if ok else "\n".join(lines),
        )

    return Step(name, f"ruff check + format --check (--line-length {LINE_LENGTH}) w {package}/", run)


def step_case_data(ctx: Context) -> Result:
    start = time.monotonic()
    files, mode = list_files(ctx.root)
    bad = case_data_violations(files)
    notes = [f"zrodlo listy plikow: {mode} ({len(files)} plikow)"]
    if mode == "tree":
        notes.append("uwaga: katalog nie jest repozytorium git, skanowane drzewo plikow (nie git ls-files)")
    notes += [f"ZABRONIONY PLIK: {p}" for p in bad]
    return Result(
        "hygiene:case-data",
        "FAIL" if bad else "OK",
        time.monotonic() - start,
        f"{len(bad)} trafien" if bad else "brak danych spraw, plikow *.env ani katalogow wynikow",
        notes,
    )


def step_eol(ctx: Context) -> Result:
    start = time.monotonic()
    mixed, mode = mixed_eol_files(ctx.root)
    known = read_known_mixed()
    new = [p for p in mixed if p not in known]
    old = [p for p in mixed if p in known]
    stale = sorted(known - set(mixed))
    notes = [f"zrodlo: {mode}"]
    notes += [f"MIESZANE KONCOWKI (nowe): {p}" for p in new]
    notes += [f"mieszane koncowki (znany dlug, ci/known_mixed_eol.txt): {p}" for p in old]
    notes += [f"wpis do usuniecia z ci/known_mixed_eol.txt (plik juz niemieszany): {p}" for p in stale]
    detail = f"{len(new)} nowych, {len(old)} znanych"
    return Result("hygiene:eol", "FAIL" if new else "OK", time.monotonic() - start, detail, notes)


def build_steps() -> list[Step]:
    steps = [
        Step("hygiene:case-data", "git ls-files: brak danych spraw, *.env, katalogow wynikow", step_case_data),
        Step(
            "hygiene:eol",
            "git ls-files --eol: brak plikow z mieszanymi koncowkami linii w pakietach pipeline'u",
            step_eol,
        ),
    ]
    steps += [make_pytest_step(f"test:{p}", p) for p in PIPELINE_PACKAGES]
    if FEED_AVAILABLE:
        steps.append(make_pytest_step("test:osint-poland-feed", "osint-poland", ("tests/test_org_intel_feed.py",)))
    steps.append(make_pytest_step("test:ci", "ci"))
    steps += [
        make_lint_step(f"lint:{key}", pkg, targets)
        for key, (pkg, targets) in LINT_TARGETS.items()
        if FEED_AVAILABLE or pkg != "osint-poland"
    ]
    return steps


def selected(steps: list[Step], only: list[str], skip: list[str]) -> list[Step]:
    names = {s.name for s in steps}
    groups = {s.name.split(":", 1)[0] for s in steps}
    for token in (*only, *skip):
        if token not in names and token not in groups:
            raise ValueError(f"nieznany krok albo grupa: {token!r} (zobacz --list)")

    def matches(step: Step, tokens: list[str]) -> bool:
        return any(step.name == t or step.name.split(":", 1)[0] == t for t in tokens)

    return [s for s in steps if (not only or matches(s, only)) and not matches(s, skip)]


# --------------------------------------------------------------------------- srodowisko i raport


def find_ruff(explicit: str | None) -> list[str] | None:
    candidates: list[list[str]] = []
    spec = explicit or os.environ.get("RUFF")
    if spec:
        candidates.append(shlex.split(spec, posix=os.name != "nt"))
    candidates += [[sys.executable, "-m", "ruff"], ["ruff"]]
    for cmd in candidates:
        if cmd[0] != sys.executable and shutil.which(cmd[0]) is None and not Path(cmd[0]).exists():
            continue
        try:
            proc = subprocess.run([*cmd, "--version"], capture_output=True, text=True, check=False, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0:
            return cmd
    return None


def pinned(package: str) -> str | None:
    req = ROOT / "ci" / "requirements.txt"
    if not req.is_file():
        return None
    for line in req.read_text(encoding="utf-8").splitlines():
        m = re.match(rf"{re.escape(package)}==([^\s#;]+)", line.strip())
        if m:
            return m.group(1)
    return None


def preflight(ctx: Context, steps: list[Step]) -> list[str]:
    problems = []
    if sys.version_info < MIN_PYTHON:
        problems.append(f"Python {sys.version_info.major}.{sys.version_info.minor}: pakiety wymagaja >= 3.12")
    need = {"pytest"} if any(s.name.startswith("test:") for s in steps) else set()
    if any(s.name == "test:osint-poland-feed" for s in steps):
        need |= {"httpx", "pydantic", "psycopg"}  # conftest osint-poland importuje psycopg, konektory httpx i pydantic
    for module in sorted(need):
        proc = subprocess.run([ctx.python, "-c", f"import {module}"], capture_output=True, check=False)
        if proc.returncode != 0:
            problems.append(f"brak modulu {module}: pip install -r ci/requirements.txt")
    if any(s.name.startswith("lint:") for s in steps) and ctx.ruff is None:
        problems.append("brak ruff (--ruff, zmienna RUFF albo pip install -r ci/requirements.txt)")
    return problems


def render_markdown(results: list[Result], total: float) -> str:
    ok = all(r.status != "FAIL" for r in results)
    lines = [
        f"# Kontrole CI pipeline'u: {'OK' if ok else 'BLAD'}",
        "",
        f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}, laczny czas {total:.1f} s.",
        "",
        "| Krok | Wynik | Czas | Szczegoly |",
        "|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.name} | {r.status} | {r.seconds:.1f} s | {mask(r.detail)} |")
    for r in results:
        extra = [mask(n) for n in r.notes if r.status == "FAIL" or n.startswith(("mieszane", "wpis", "uwaga"))]
        if extra:
            lines += ["", f"## {r.name}", *[f"- {n}" for n in extra]]
    for name, why in NOT_IN_REPO.items():
        lines += ["", f"Pominiete: {name} ({why})."]
    return "\n".join(lines) + "\n"


def print_results(results: list[Result], total: float) -> None:
    print("\n=== Podsumowanie ===")
    width = max(len(r.name) for r in results) if results else 10
    for r in results:
        print(f"[{r.status:^4}] {r.name:<{width}}  {r.seconds:6.1f}s  {mask(r.detail)}")
    for r in results:
        for note in r.notes:
            if r.status == "FAIL" or note.startswith(("mieszane", "wpis", "uwaga")):
                print(f"       {r.name}: {mask(note)}")
    for name, why in NOT_IN_REPO.items():
        print(f"[SKIP] {name}: {why}")
    failed = [r.name for r in results if r.status == "FAIL"]
    print(f"Razem {total:.1f}s; nieudane: {', '.join(failed) if failed else 'brak'}")


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--list", action="store_true", help="wypisz kroki i zakoncz")
    p.add_argument("--only", action="append", default=[], metavar="KROK|GRUPA", help="uruchom tylko te kroki/grupy")
    p.add_argument("--skip", action="append", default=[], metavar="KROK|GRUPA", help="pomin te kroki/grupy")
    p.add_argument("--fail-fast", action="store_true", help="przerwij po pierwszym nieudanym kroku")
    p.add_argument("--artifacts", metavar="KATALOG", help="zapisz summary.json/summary.md i przeskanuj katalog")
    p.add_argument("--ruff", metavar="KOMENDA", help="komenda ruff (domyslnie: python -m ruff albo ruff z PATH)")
    p.add_argument("--python", default=sys.executable, help="interpreter dla pytest (domyslnie biezacy)")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code in (0, None) else EXIT_USAGE
    all_steps = build_steps()
    if args.list:
        for s in all_steps:
            print(f"{s.name:<26} {s.describe}")
        return EXIT_OK
    try:
        steps = selected(all_steps, args.only, args.skip)
    except ValueError as exc:
        print(f"Blad uzycia: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not (ROOT / "org-intel").is_dir() or not (ROOT / "entity-graph").is_dir():
        print(f"Blad: {ROOT} nie wyglada na katalog glowny repozytorium OSINT", file=sys.stderr)
        return EXIT_USAGE
    wants_lint = any(s.name.startswith("lint:") for s in steps)
    ctx = Context(python=args.python, ruff=find_ruff(args.ruff) if wants_lint else None)
    problems = preflight(ctx, steps)
    if problems:
        print("Blad srodowiska (kod 2):", *problems, sep="\n  - ", file=sys.stderr)
        return EXIT_USAGE
    want_ruff = pinned("ruff")
    if ctx.ruff and want_ruff:
        got = subprocess.run([*ctx.ruff, "--version"], capture_output=True, text=True, check=False).stdout.strip()
        if want_ruff not in got:
            print(f"uwaga: ruff to '{got}', a ci/requirements.txt przypina {want_ruff} (wyniki format moga sie roznic)")

    print(f"Python {sys.version.split()[0]} ({ctx.python}); korzen repo: {ROOT}")
    results: list[Result] = []
    started = time.monotonic()
    for step in steps:
        print(f"\n--- {step.name}: {step.describe}", flush=True)
        try:
            result = step.run(ctx)  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - blad kroku to wynik FAIL, nie crash calego skryptu
            result = Result(step.name, "FAIL", 0.0, f"wyjatek skryptu: {type(exc).__name__}")
        results.append(result)
        print(f"[{result.status}] {result.name} ({result.seconds:.1f}s): {mask(result.detail)}", flush=True)
        if result.status == "FAIL":
            for note in result.notes:
                print(f"    {mask(note)}")
            if result.output_tail:
                print("    --- koniec wyjscia (zamaskowany) ---")
                print("\n".join("    " + ln for ln in result.output_tail.splitlines()))
            if args.fail_fast:
                break
    total = time.monotonic() - started

    if args.artifacts:
        folder = Path(args.artifacts)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "summary.md").write_text(render_markdown(results, total), encoding="utf-8", newline="\n")
        data = [
            {"step": r.name, "status": r.status, "seconds": round(r.seconds, 2), "detail": mask(r.detail)}
            for r in results
        ]
        (folder / "summary.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        hits = scan_artifacts(folder)
        scan = Result("artifacts:scan", "FAIL" if hits else "OK", 0.0, f"{len(hits)} trafien" if hits else "czyste")
        scan.notes = [f"TRAFIENIE (plik usuniety): {h}" for h in hits]
        results.append(scan)
        print(f"\n[{scan.status}] artifacts:scan: {scan.detail}")
        for note in scan.notes:
            print(f"    {note}")

    print_results(results, total)
    return EXIT_FAIL if any(r.status == "FAIL" for r in results) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
