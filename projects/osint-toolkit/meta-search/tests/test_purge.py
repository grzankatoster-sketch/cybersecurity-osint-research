"""Retencja wyników (purge): tylko stare meta_*.json/.html, domyślnie podgląd. Bez sieci."""
import os
import time

from meta_search.cli import main, purge

DAY = 86400


def _file(path, age_days):
    path.write_text("{}", encoding="utf-8")
    t = time.time() - age_days * DAY
    os.utime(path, (t, t))
    return path


def test_preview_deletes_nothing(tmp_path, capsys):
    old = _file(tmp_path / "meta_threads_profile_x_1.json", 40)
    assert purge(str(tmp_path), 30, delete=False) == 0
    assert old.exists() and "do usunięcia: meta_threads_profile_x_1.json" in capsys.readouterr().out


def test_delete_only_old_meta_results(tmp_path):
    old_json = _file(tmp_path / "meta_facebook_page_a_1.json", 40)
    old_html = _file(tmp_path / "meta_facebook_page_a_1.html", 40)
    fresh = _file(tmp_path / "meta_facebook_page_b_2.json", 5)
    other_tool = _file(tmp_path / "dns_example_1.html", 400)
    not_meta = _file(tmp_path / "notatki.json", 400)
    sub = tmp_path / "meta_dir.json"
    sub.mkdir()
    assert purge(str(tmp_path), 30, delete=True) == 0
    assert not old_json.exists() and not old_html.exists()
    assert fresh.exists() and other_tool.exists() and not_meta.exists() and sub.is_dir()


def test_invalid_arguments(tmp_path):
    assert purge(str(tmp_path / "brak"), 30, delete=True) == 2
    assert purge(str(tmp_path), 0, delete=True) == 2


def test_cli_purge_needs_no_config(tmp_path, monkeypatch):
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    _file(tmp_path / "meta_links_x_1.html", 100)
    assert main(["purge", str(tmp_path), "--days", "30", "--delete"]) == 0
    assert not (tmp_path / "meta_links_x_1.html").exists()


def test_error_on_one_file_does_not_abort(tmp_path, monkeypatch, capsys):
    """Plik zajety/zablokowany (Windows) nie przerywa retencji w polowie: reszta usunieta, kod 1, lista bledow."""
    locked = _file(tmp_path / "meta_a_1.json", 40)
    other = _file(tmp_path / "meta_b_2.json", 40)
    real_unlink = type(locked).unlink

    def unlink(self, *a, **kw):
        if self.name == locked.name:
            raise PermissionError("zajety")
        return real_unlink(self, *a, **kw)
    monkeypatch.setattr(type(locked), "unlink", unlink)
    assert purge(str(tmp_path), 30, delete=True) == 1
    assert locked.exists() and not other.exists()
    err = capsys.readouterr().err
    assert "meta_a_1.json" in err
