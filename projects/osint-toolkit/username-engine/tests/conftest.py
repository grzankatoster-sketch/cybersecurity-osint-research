"""Wspólne ustawienia testów: żaden test nie może dotykać prawdziwego katalogu wyników (wyniki/)."""
import pytest

from username_engine import cli


@pytest.fixture(autouse=True)
def _isolated_results_dir(tmp_path_factory, monkeypatch):
    monkeypatch.setattr(cli, "DEFAULT_RESULTS", tmp_path_factory.mktemp("domyslne_wyniki"))
