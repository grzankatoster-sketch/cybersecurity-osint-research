"""Zapis plików atomowo: plik tymczasowy w tym samym katalogu + os.replace, żeby przerwany zapis nie zostawił
uciętego pliku."""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def atomic_open(path: str | Path, encoding: str = "utf-8", newline: str | None = None):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.resolve().parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            yield f
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def atomic_write_text(path: str | Path, text: str, encoding: str = "utf-8") -> None:
    with atomic_open(path, encoding=encoding) as f:
        f.write(text)
