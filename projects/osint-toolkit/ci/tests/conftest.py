"""Wspolne narzedzia testow E2E pipeline'u: sciezki pakietow, uruchamianie CLI w podprocesach i zakaz sieci.

Pakiety (org-intel, entity-graph, osint-poland/org_intel_feed) NIE musza byc zainstalowane: podprocesy dostaja
PYTHONPATH na ich `src`. Siec jest zablokowana dwa razy: w procesie testu (autouse) i w kazdym podprocesie
(sitecustomize z _nonet/, dziennik prob w CI_NONET_LOG sprawdzany po kazdym tescie)."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "ci"
NONET_DIR = Path(__file__).resolve().parent / "_nonet"

SRC_DIRS = (
    ROOT / "org-intel" / "src",
    ROOT / "entity-graph" / "src",
    ROOT / "osint-poland" / "src",
)
FEED_FIXTURES = ROOT / "osint-poland" / "tests" / "fixtures" / "org_intel_feed"
# Public monorepo: osint-poland (registry adapter) is not published, so the registry stage of the E2E chain is skipped.
FEED_AVAILABLE = (ROOT / "osint-poland" / "src" / "osint_poland" / "org_intel_feed.py").is_file()
HIBP_FIXTURES = ROOT / "org-intel" / "tests" / "fixtures"

for _path in (CI_DIR, *SRC_DIRS):  # import w procesie testu (run_checks, entity_graph, org_intel)
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

# Zmienne, ktore moglyby wlaczyc siec, konfiguracje wyszukiwarki albo bazy: nigdy nie trafiaja do podprocesow.
_DROP_PREFIXES = ("BRAVE_", "OSINT_", "EG_", "HIBP_", "ORG_INTEL_")
_DROP_EXACT = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "PYTHONPATH", "PYTHONSTARTUP"}


def clean_env(netlog: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items() if not k.upper().startswith(_DROP_PREFIXES) and k.upper() not in _DROP_EXACT
    }
    env.update(
        PYTHONPATH=os.pathsep.join([str(NONET_DIR), *(str(p) for p in SRC_DIRS)]),
        PYTHONUTF8="1",
        PYTHONIOENCODING="utf-8",
        PYTHONDONTWRITEBYTECODE="1",
        CI_NONET_LOG=str(netlog),
    )
    env.update(extra or {})
    return env


class Runner:
    """Uruchamia `python -m <modul>` z czystym srodowiskiem i dziennikiem prob polaczen."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.netlog = workdir / "netlog.txt"

    def run(self, module: str, *args: object, env: dict[str, str] | None = None, cwd: Path | None = None):
        return subprocess.run(
            [sys.executable, "-m", module, *(str(a) for a in args)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=clean_env(self.netlog, env),
            cwd=str(cwd or self.workdir),
            timeout=180,
            check=False,
        )

    def run_code(self, code: str, *args: object, env: dict[str, str] | None = None, cwd: Path | None = None):
        return subprocess.run(
            [sys.executable, "-c", code, *(str(a) for a in args)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=clean_env(self.netlog, env),
            cwd=str(cwd or self.workdir),
            timeout=180,
            check=False,
        )

    def attempts(self) -> list[str]:
        if not self.netlog.exists():
            return []
        return [ln for ln in self.netlog.read_text(encoding="utf-8").splitlines() if ln.strip()]

    # skroty do trzech narzedzi lancucha
    def feed(self, *args: object, **kw):
        return self.run("osint_poland.org_intel_feed", *args, **kw)

    def org_intel(self, *args: object, **kw):
        return self.run("org_intel", *args, **kw)

    def eg(self, *args: object, **kw):
        return self.run("entity_graph", *args, **kw)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Proba polaczenia w procesie testu = blad testu (podprocesy: straznik z _nonet/ + dziennik)."""

    def blocked(*_a, **_k):
        raise AssertionError("test probowal uzyc sieci")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def runner(tmp_path):
    r = Runner(tmp_path / "run")
    yield r
    assert r.attempts() == [], f"podproces probowal sie polaczyc z siecia: {r.attempts()[:3]}"
