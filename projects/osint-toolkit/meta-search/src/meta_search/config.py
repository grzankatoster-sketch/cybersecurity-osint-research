"""Konfiguracja tokenów Meta: tylko zmienne środowiskowe albo plik POZA repozytorium.

Kolejność: zmienne środowiskowe -> plik z META_SEARCH_ENV_FILE -> ~/.osint/meta.env (środowisko wygrywa z plikiem).
Klucze: THREADS_ACCESS_TOKEN (Threads), INSTAGRAM_ACCESS_TOKEN + INSTAGRAM_USER_ID (Instagram Business Discovery:
token i id konta profesjonalnego WŁAŚCICIELA tokenu), FACEBOOK_ACCESS_TOKEN (Strony), GRAPH_API_VERSION (graph.facebook.com),
THREADS_API_VERSION (graph.threads.net), META_PROXY (proxy HTTP/HTTPS ze stałym IP, np. http://127.0.0.1:8080;
bez fallbacku na połączenie bezpośrednie), META_REQUIRE_PROXY (1 = fail-closed bez proxy). Plik w katalogu
repozytorium jest odrzucany (sekret nie może trafić do gita).
Wartości tokenów nigdy nie są wypisywane."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_TOKEN = "THREADS_ACCESS_TOKEN"
ENV_VERSION = "THREADS_API_VERSION"
ENV_IG_TOKEN = "INSTAGRAM_ACCESS_TOKEN"
ENV_IG_USER = "INSTAGRAM_USER_ID"
ENV_FB_TOKEN = "FACEBOOK_ACCESS_TOKEN"
ENV_GRAPH_VERSION = "GRAPH_API_VERSION"
ENV_PROXY = "META_PROXY"
ENV_REQUIRE_PROXY = "META_REQUIRE_PROXY"
ENV_FILE = "META_SEARCH_ENV_FILE"
DEFAULT_FILE = Path.home() / ".osint" / "meta.env"
DEFAULT_THREADS_VERSION = "v1.0"   # https://developers.facebook.com/docs/threads (03.10.2026)
DEFAULT_GRAPH_VERSION = "v26.0"    # graph.facebook.com; najnowsza wg changelogu Meta (29.07.2026), sprawdzona 04.10.2026
_VERSION = re.compile(r"^v\d{1,2}\.\d{1,2}$")
_IG_USER = re.compile(r"^\d{5,30}$")
_KEYS = {ENV_TOKEN, ENV_VERSION, ENV_IG_TOKEN, ENV_IG_USER, ENV_FB_TOKEN, ENV_GRAPH_VERSION, ENV_PROXY,
         ENV_REQUIRE_PROXY}
_PROXY = re.compile(r"^https?://(?:[^@/\s:]+:[^@/\s]+@)?(?P<host>[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\]):(?P<port>\d{1,5})/?$")
_TOKENS = (("threads", ENV_TOKEN), ("instagram", ENV_IG_TOKEN), ("facebook", ENV_FB_TOKEN))


@dataclass
class Config:
    threads_token: str | None = field(default=None, repr=False)
    threads_version: str = DEFAULT_THREADS_VERSION
    instagram_token: str | None = field(default=None, repr=False)
    instagram_user_id: str | None = field(default=None, repr=False)
    facebook_token: str | None = field(default=None, repr=False)
    graph_version: str = DEFAULT_GRAPH_VERSION
    proxy: str | None = field(default=None, repr=False)   # może zawierać login:hasło - nie wypisywać
    proxy_blocked: bool = False                           # błędna konfiguracja albo wymagane proxy bez proxy: zero ruchu
    require_proxy: bool = False                          # ścieżka produkcyjna: brak proxy = zero ruchu
    token_sources: dict = field(default_factory=dict)    # {"threads": "env" | "plik: <ścieżka>", ...}
    problems: list[str] = field(default_factory=list)

    @property
    def token_source(self) -> str:
        return self.token_sources.get("threads", "")

    @property
    def instagram_ready(self) -> bool:
        return bool(self.instagram_token and self.instagram_user_id)

    def describe(self) -> dict:
        """Stan konfiguracji do pokazania użytkownikowi — bez wartości tokenów i identyfikatorów."""
        def has(value) -> str:
            return "ustawiony" if value else "brak"
        return {
            "threads_token": has(self.threads_token), "token_source": self.token_source,
            "threads_api_version": self.threads_version, "graph_api_version": self.graph_version,
            "require_proxy": self.require_proxy,
            "sources": {
                "threads": {"configured": bool(self.threads_token), "token": has(self.threads_token),
                            "token_source": self.token_sources.get("threads", ""), "api_version": self.threads_version},
                "instagram": {"configured": self.instagram_ready, "token": has(self.instagram_token),
                              "user_id": has(self.instagram_user_id),
                              "token_source": self.token_sources.get("instagram", ""), "api_version": self.graph_version},
                "facebook": {"configured": bool(self.facebook_token), "token": has(self.facebook_token),
                             "token_source": self.token_sources.get("facebook", ""), "api_version": self.graph_version},
            },
            "proxy": proxy_label(self),
            "problems": self.problems,
        }


def proxy_label(cfg: "Config") -> str:
    """Opis proxy bez loginu i hasła."""
    if cfg.proxy_blocked:
        return "BŁĘDNE - zapytania zablokowane"
    if not cfg.proxy:
        return "brak (połączenie bezpośrednie / systemowe)"
    m = _PROXY.match(cfg.proxy)
    return f"{cfg.proxy.split(':', 1)[0]}://{m.group('host')}:{m.group('port')}" if m else "ustawione"


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
        return True
    except ValueError:
        return False


def _read_env_file(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key in _KEYS and val:
            out[key] = val
    return out


def load_config(environ: dict | None = None) -> Config:
    env = os.environ if environ is None else environ
    cfg = Config()
    values: dict[str, str] = {}
    origin: dict[str, str] = {}          # klucz -> "env" | "plik: <ścieżka>"
    file_path = Path(env[ENV_FILE]) if env.get(ENV_FILE) else DEFAULT_FILE
    if file_path.is_file():
        if _inside_repo(file_path):
            cfg.problems.append(f"plik konfiguracji leży w repozytorium ({file_path.name}) - pominięty; "
                                "przenieś go poza repo, np. do ~/.osint/meta.env")
        else:
            try:
                values = _read_env_file(file_path)
                origin = {k: f"plik: {file_path}" for k in values}
            except (OSError, UnicodeDecodeError) as exc:
                cfg.problems.append(f"nie można odczytać pliku konfiguracji: {type(exc).__name__}")
    elif env.get(ENV_FILE):
        cfg.problems.append("META_SEARCH_ENV_FILE wskazuje nieistniejący plik")
    for key in _KEYS:
        if str(env.get(key, "")).strip():
            values[key], origin[key] = str(env[key]).strip(), "env"
    for name, key in _TOKENS:
        token = values.get(key)
        if token and (len(token) < 20 or any(c.isspace() for c in token)):
            cfg.problems.append(f"{key}: nieprawidłowy format tokenu (za krótki albo zawiera spacje) - pominięty")
            token = None
        setattr(cfg, f"{name}_token", token)
        if token:
            cfg.token_sources[name] = origin[key]
    user = values.get(ENV_IG_USER)
    if user and not _IG_USER.match(user):
        cfg.problems.append(f"{ENV_IG_USER}: oczekiwany sam numeryczny identyfikator konta - pominięty")
        user = None
    cfg.instagram_user_id = user
    proxy = values.get(ENV_PROXY)
    if proxy:
        m = _PROXY.match(proxy)
        if m and 1 <= int(m.group("port")) <= 65535:
            cfg.proxy = proxy
        else:
            cfg.proxy_blocked = True
            cfg.problems.append(f"{ENV_PROXY}: oczekiwane http(s)://host:port (socks nieobsługiwane - użyj VPN "
                                "systemowego albo proxy HTTP); zapytania do API zablokowane, bez połączenia bezpośredniego")
    cfg.require_proxy = values.get(ENV_REQUIRE_PROXY, "").strip() == "1"
    if cfg.require_proxy and not cfg.proxy and not cfg.proxy_blocked and any(
            getattr(cfg, attr) for attr in ("threads_token", "instagram_token", "facebook_token")):
        cfg.proxy_blocked = True
        cfg.problems.append(f"{ENV_PROXY}: brak; przy {ENV_REQUIRE_PROXY}=1 zapytania do API są zablokowane, "
                            "aby nie ujawnić bezpośredniego adresu IP")
    for key, attr, default in ((ENV_VERSION, "threads_version", DEFAULT_THREADS_VERSION),
                               (ENV_GRAPH_VERSION, "graph_version", DEFAULT_GRAPH_VERSION)):
        version = values.get(key, default)
        if _VERSION.match(version):
            setattr(cfg, attr, version)
        else:
            cfg.problems.append(f"{key}: nieprawidłowa wersja API, używam {default}")
    return cfg
