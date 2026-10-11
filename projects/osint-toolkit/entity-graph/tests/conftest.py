"""Wspólne atrapy: fetcher HTTP z trasami, runner podprocesów, kontekst bez sieci. Zero połączeń z internetem."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from entity_graph.http import HttpResponse
from entity_graph.siblings import MODULES
from entity_graph.transforms import Context, Settings

FIXTURES = Path(__file__).parent / "fixtures"


def fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ok(text: str, status: int = 200) -> HttpResponse:
    return HttpResponse(status, text)


class FakeFetch:
    """Trasy: lista (fragment adresu, odpowiedź). Brak trasy = błąd sieci (test zauważy niespodziewane zapytanie)."""

    def __init__(self, routes: list[tuple[str, HttpResponse]] | None = None):
        self.routes = routes or []
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, headers: dict | None = None) -> HttpResponse:
        self.calls.append((url, dict(headers or {})))
        for fragment, resp in self.routes:
            if fragment in url:
                return resp
        return HttpResponse(None, error="brak trasy w teście")


class FakeRunner:
    """Udaje podproces narzędzia siostrzanego. handlers: {moduł: funkcja(cmd) -> (rc, stdout, stderr)}."""

    def __init__(self, handlers: dict | None = None):
        self.handlers = handlers or {}
        self.calls: list[dict] = []

    def __call__(self, cmd, *, env, cwd, timeout):
        module = cmd[cmd.index("-m") + 1]
        self.calls.append({"cmd": list(cmd), "env": dict(env), "cwd": cwd, "timeout": timeout, "module": module})
        handler = self.handlers.get(module)
        if handler is None:
            raise AssertionError(f"niespodziewane uruchomienie {module}")
        return handler(cmd)


def writes_json_to_flag(payload: str, rc: int = 0):
    """Handler: zapisuje payload do pliku wskazanego po --json (tak działają username-engine i phone-check)."""
    def handler(cmd):
        target = Path(cmd[cmd.index("--json") + 1])
        if "--results-dir" in cmd:   # username-engine: sama nazwa pliku w podkatalogu skanu
            target = Path(cmd[cmd.index("--results-dir") + 1]) / "scan-test" / target.name
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
        return rc, "", ""
    return handler


@pytest.fixture
def tools_dir(tmp_path):
    """Atrapa katalogu z narzędziami siostrzanymi (tylko struktura katalogów)."""
    for name, module in MODULES.items():
        (tmp_path / "tools" / name / "src" / module).mkdir(parents=True)
    return tmp_path / "tools"


@pytest.fixture
def make_ctx(tools_dir, tmp_path):
    def build(routes=None, handlers=None, env=None, **settings) -> Context:
        return Context(
            fetch=FakeFetch(routes), runner=FakeRunner(handlers), env=env or {}, tools_dir=tools_dir,
            settings=Settings(**settings), now=lambda: "2026-10-03T12:00:00+00:00", tmp_dir=tmp_path,
            rdns=lambda ip: (None, None),
        )
    return build


def dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)
