"""Falszywy podproces: testy bez uruchamiania prawdziwych modulow i bez sieci."""

import subprocess
from pathlib import Path

import pytest

from osint_mcp import runner


class FakeRun:
    """Zastepuje subprocess.run. `reply(cmd, kwargs)` zwraca CompletedProcess albo rzuca wyjatek."""

    def __init__(self, stdout="{}", stderr="", returncode=0, json_file_content=None, exc=None):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode
        self.json_file_content = json_file_content
        self.exc = exc
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if self.exc is not None:
            raise self.exc
        if self.json_file_content is not None and "--json" in cmd:
            Path(cmd[cmd.index("--json") + 1]).write_text(self.json_file_content, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    """Drzewo z .venv dla wszystkich modulow."""
    for mod in runner.MODULES.values():
        py = tmp_path / mod.folder / ".venv" / "Scripts" / "python.exe"
        py.parent.mkdir(parents=True)
        py.write_text("", encoding="utf-8")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    return tmp_path
