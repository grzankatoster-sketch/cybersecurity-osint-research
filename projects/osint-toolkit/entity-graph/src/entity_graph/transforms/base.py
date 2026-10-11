"""Wspólne typy transformacji: kontekst, wynik, rejestr.

Konwencja: każda transformacja to (1) czyste funkcje parse_* (dane -> węzły/krawędzie, bez sieci, testowane na
fixture'ach) oraz (2) cienka funkcja run(node, ctx), która pobiera dane przez ctx i woła parse_*.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from ..http import Fetcher, HttpClient
from ..model import Edge, Node, Status, utc_now
from ..normalize import EntityType
from .. import siblings

DEFAULT_ENDPOINTS = {
    "rdap_ip": "https://rdap.org/ip/",
    "rdap_ip_ripe": "https://rdap.db.ripe.net/ip/",
    "rdap_domain": "https://rdap.org/domain/",
    "ripestat": "https://stat.ripe.net/data/prefix-overview/data.json",
    "internetdb": "https://internetdb.shodan.io/",
    "crtsh": "https://crt.sh/",
    "gravatar": "https://gravatar.com/avatar/",
}

GENERIC_MAIL_PROVIDERS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
    "me.com", "proton.me", "protonmail.com", "wp.pl", "o2.pl", "onet.pl", "interia.pl", "poczta.fm",
    "op.pl", "gazeta.pl", "tlen.pl", "vp.pl", "int.pl",
})


@dataclass
class Settings:
    max_usernames: int = 12
    max_subdomains: int = 100
    max_breaches: int = 30
    phone_region: str = "PL"
    ue_tags: str | None = None
    ue_limit: int | None = None
    ue_timeout: float = 900.0
    ue_min_confidence: float = 0.6
    sibling_timeout: float = 60.0
    offline: bool = False


@dataclass
class Context:
    fetch: Fetcher = field(default_factory=HttpClient)
    runner: siblings.Runner = siblings.default_runner
    rdns: Callable[[str], tuple[str | None, str | None]] | None = None   # ip -> (nazwa|None, błąd|None)
    env: Mapping[str, str] = field(default_factory=lambda: os.environ)
    settings: Settings = field(default_factory=Settings)
    endpoints: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_ENDPOINTS))
    tools_dir: Path = field(default_factory=siblings.tools_root)
    hibp_client_factory: Callable[[], object] | None = None
    now: Callable[[], str] = utc_now
    tmp_dir: Path | None = None
    vault: object | None = None                      # skarbiec dowodów (vault.EvidenceVault) albo None

    def edge(self, source: str, src: Node, dst: Node, relation: str, confidence: float, evidence: str) -> Edge:
        return Edge(src.id, dst.id, relation, source, confidence, evidence, self.now())


@dataclass
class TransformResult:
    status: Status
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    node_attrs: dict = field(default_factory=dict)   # atrybuty do dopisania do węzła wejściowego
    note: str = ""
    error: str = ""
    stats: dict = field(default_factory=dict)
    canonical: Node | None = None                    # węzeł wejściowy to ta sama encja co ten (scalenie)

    @classmethod
    def failed(cls, status: Status, reason: str) -> "TransformResult":
        return cls(status, error=reason if status is Status.ERROR else "", note="" if status is Status.ERROR else reason)


@dataclass(frozen=True)
class Transform:
    name: str
    inputs: tuple[EntityType, ...]
    description: str
    network: bool
    run: Callable[[Node, Context], TransformResult]


REGISTRY: dict[str, Transform] = {}


def register(name: str, inputs: tuple[EntityType, ...], description: str, network: bool = True):
    def deco(fn: Callable[[Node, Context], TransformResult]):
        if name in REGISTRY:
            raise ValueError(f"zduplikowana transformacja: {name}")
        REGISTRY[name] = Transform(name, inputs, description, network, fn)
        return fn
    return deco
