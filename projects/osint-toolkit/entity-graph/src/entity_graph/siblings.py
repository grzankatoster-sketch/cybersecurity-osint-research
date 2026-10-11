"""Uruchamianie narzędzi siostrzanych z tego repo (username-engine, dns-audit, phone-check) jako podprocesów
w ich własnych środowiskach oraz import hibp-monitor (sama stdlib). Kod siostrzany nie jest kopiowany.

Podproces dostaje środowisko bez zmiennych wyglądających na sekrety (klucze API, tokeny, hasła)."""
from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

MODULES = {
    "username-engine": "username_engine",
    "dns-audit": "dns_audit",
    "hibp-monitor": "hibp_monitor",
    "phone-check": "phone_check",
    "osint-connectors": "osint_connectors",   # importowany (stdlib): konektor brave_search
}
_SECRET_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)

# runner(cmd, env=..., cwd=..., timeout=...) -> (returncode, stdout, stderr); w testach podstawiany fake
Runner = Callable[..., tuple[int, str, str]]


class SiblingUnavailable(Exception):
    """Narzędzia nie ma na dysku albo nie da się go uruchomić (to nie jest wynik 'brak danych')."""


def tools_root(environ: Mapping[str, str] | None = None) -> Path:
    env = environ if environ is not None else os.environ
    override = env.get("ENTITY_GRAPH_TOOLS_DIR", "").strip()
    return Path(override) if override else Path(__file__).resolve().parents[3]


def sibling_dir(name: str, root: Path) -> Path:
    if name not in MODULES:
        raise SiblingUnavailable(f"nieznane narzędzie: {name}")
    d = root / name
    if not (d / "src" / MODULES[name]).is_dir():
        raise SiblingUnavailable(f"nie znaleziono {name} w {root} (ustaw ENTITY_GRAPH_TOOLS_DIR)")
    return d


def python_for(name: str, root: Path) -> str:
    """Interpreter z .venv narzędzia, jeśli jest (tam są jego zależności), inaczej bieżący."""
    d = root / name
    for rel in (".venv/Scripts/python.exe", ".venv/bin/python"):
        if (d / rel).is_file():
            return str(d / rel)
    return sys.executable


def scrubbed_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    src = base if base is not None else os.environ
    env = {k: v for k, v in src.items() if not _SECRET_RE.search(k)}
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def build_command(name: str, args: list[str], root: Path) -> tuple[list[str], dict[str, str], Path]:
    d = sibling_dir(name, root)
    env = scrubbed_env()
    env["PYTHONPATH"] = str(d / "src")
    return [python_for(name, root), "-m", MODULES[name], *args], env, d


def default_runner(cmd: list[str], *, env: dict, cwd: Path, timeout: float) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"przekroczono limit czasu {timeout:.0f} s") from exc
    except OSError as exc:
        raise SiblingUnavailable(f"nie można uruchomić: {type(exc).__name__}: {exc}") from exc
    return p.returncode, p.stdout, p.stderr


@dataclass
class Outcome:
    returncode: int
    stdout: str
    stderr: str


def run_sibling(name: str, args: list[str], root: Path, timeout: float, runner: Runner = default_runner) -> Outcome:
    cmd, env, cwd = build_command(name, args, root)
    rc, out, err = runner(cmd, env=env, cwd=cwd, timeout=timeout)
    return Outcome(rc, out, err)


def import_sibling(name: str, root: Path):
    """Import modułu narzędzia siostrzanego w tym procesie (tylko dla narzędzi bez zależności zewnętrznych)."""
    d = sibling_dir(name, root)
    src = str(d / "src")
    if src not in sys.path:
        sys.path.append(src)
    try:
        return importlib.import_module(MODULES[name])
    except ImportError as exc:
        raise SiblingUnavailable(f"import {MODULES[name]} nieudany: {exc}") from exc
