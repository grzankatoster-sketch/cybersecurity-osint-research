"""Kontrakt konektora + jawny rejestr.

Naprawia „kontrakt przez konwencję nazw" z audytu (holehe/ignorant pobierały
funkcję przez ``module.__dict__[nazwa_pliku]`` i leciały ``KeyError`` przy
rozjeździe). Tutaj konektor to jawny obiekt z interfejsem, rejestrowany
dekoratorem, a odkrywanie izoluje błąd importu pojedynczego modułu.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Protocol, runtime_checkable

from .model import Finding, InputKind, SourceKind, Subject


@dataclass
class Context:
    """Zależności wstrzykiwane do konektora przez runner.

    ``salt`` służy do haszowania celu. ``dataset`` to opcjonalne dane pasywne
    (offline). ``http`` zarezerwowane dla konektorów API (None w Fazie 1).
    """

    salt: str
    timeout: float = 10.0
    dataset: Optional[dict] = None
    http: object = None
    extra: dict = field(default_factory=dict)


@runtime_checkable
class Connector(Protocol):
    name: str
    source_kind: SourceKind
    supported_inputs: FrozenSet[InputKind]

    async def check(self, subject: Subject, ctx: Context) -> Finding:
        ...


class ConnectorRegistry:
    """Jawny rejestr. Konektory rejestrują się dekoratorem ``@registry.register``."""

    def __init__(self) -> None:
        self._items: Dict[str, Connector] = {}
        self.load_errors: List[str] = []

    def register(self, connector: Connector) -> Connector:
        if not isinstance(connector.name, str) or not connector.name:
            raise ValueError("konektor musi mieć niepustą nazwę")
        if connector.name in self._items:
            raise ValueError(f"duplikat nazwy konektora: {connector.name}")
        if not isinstance(connector, Connector):
            raise TypeError(f"{connector.name} nie spełnia kontraktu Connector")
        self._items[connector.name] = connector
        return connector

    def get(self, name: str) -> Connector:
        return self._items[name]

    def for_input(self, kind: InputKind) -> List[Connector]:
        return [c for c in self.all() if kind in c.supported_inputs]

    def all(self) -> List[Connector]:
        # Deterministycznie po nazwie.
        return [self._items[n] for n in sorted(self._items)]

    def names(self) -> List[str]:
        return sorted(self._items)

    def discover(self, package_name: str) -> None:
        """Zaimportuj podmoduły pakietu, izolując błąd importu każdego z osobna.

        W przeciwieństwie do oryginałów awaria jednego modułu NIE wywraca startu —
        jest logowana w ``load_errors`` i pomijana. Importujemy wyłącznie własny,
        zaufany pakiet konektorów.
        """
        package = importlib.import_module(package_name)
        for _loader, mod_name, _is_pkg in pkgutil.iter_modules(package.__path__):
            full = f"{package_name}.{mod_name}"
            try:
                importlib.import_module(full)
            except Exception as exc:  # izolacja — świadomie szeroki, z zapisem przyczyny
                self.load_errors.append(f"{full}: {type(exc).__name__}: {exc}")


#: Domyślny, globalny rejestr pakietu.
registry = ConnectorRegistry()


def connector(cls=None):
    """Dekorator klasy: instancjonuje i rejestruje konektor w globalnym rejestrze."""

    def wrap(klass):
        instance = klass()
        registry.register(instance)
        return klass

    return wrap if cls is None else wrap(cls)
