"""Dziennik wynikow: WAL + synchronous=NORMAL (bez fsync przy kazdym zapisie, odporny na przerwanie procesu)."""

import sqlite3

from ultimate_username.storage import ResultJournal


def test_journal_uses_wal_with_normal_sync(tmp_path):
    with ResultJournal(tmp_path / "j.sqlite") as journal:
        assert journal.connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert journal.connection.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL


def test_committed_rows_survive_without_close(tmp_path):
    """Przerwanie procesu (brak close()) nie traci zatwierdzonych wierszy: leza w WAL."""
    path = tmp_path / "j.sqlite"
    journal = ResultJournal(path)
    with journal.connection:
        journal.connection.execute("INSERT INTO results VALUES ('t', 'j', '{}', '{}')")
    other = sqlite3.connect(path)
    try:
        assert other.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 1
    finally:
        other.close()
        journal.close()
