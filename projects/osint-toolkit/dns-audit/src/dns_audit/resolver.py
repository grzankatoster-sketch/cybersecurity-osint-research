"""Warstwa DNS za interfejsem. Prawdziwy resolver (dnspython) i testowy fake implementuja ten sam protokol."""

from __future__ import annotations

import http.client
import ipaddress
import secrets
import socket
import ssl
import struct
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import unquote, urlsplit


class Status(str, Enum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    TIMEOUT = "timeout"
    SERVFAIL = "servfail"
    ERROR = "error"


@dataclass(frozen=True)
class DnsAnswer:
    status: Status
    records: tuple[str, ...] = ()
    ad: bool = False  # flaga Authenticated Data zwrocona przez resolver
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is Status.OK and bool(self.records)

    @property
    def absent(self) -> bool:
        """Pewny brak rekordu (NXDOMAIN / NODATA), w odroznieniu od bledu zapytania."""
        return self.status in (Status.NXDOMAIN, Status.NODATA)

    @property
    def failed(self) -> bool:
        return self.status in (Status.TIMEOUT, Status.SERVFAIL, Status.ERROR)


class Resolver(Protocol):
    def query(self, name: str, rtype: str) -> DnsAnswer: ...


class DnsPythonResolver:
    """Resolver oparty o dnspython. TXT zwracany jako jeden string (segmenty sklejone)."""

    def __init__(self, nameserver: str | None = None, timeout: float = 4.0, lifetime: float = 8.0):
        import dns.flags
        import dns.resolver

        self._dns_resolver = dns.resolver
        self._dns_flags = dns.flags
        r = dns.resolver.Resolver(configure=True)
        if nameserver:
            try:
                ipaddress.ip_address(nameserver)
            except ValueError as exc:
                raise ValueError(f"resolver musi byc adresem IP: {nameserver!r}") from exc
            r.nameservers = [nameserver]
        r.timeout = timeout
        r.lifetime = lifetime
        r.use_edns(0, dns.flags.DO, 1232)  # DO: prosimy o dane DNSSEC
        r.flags = dns.flags.RD | dns.flags.AD
        self._r = r
        self.description = nameserver or "systemowy (" + ", ".join(r.nameservers) + ")"

    def query(self, name: str, rtype: str) -> DnsAnswer:
        dr = self._dns_resolver
        try:
            ans = self._r.resolve(name, rtype, raise_on_no_answer=True)
        except dr.NXDOMAIN:
            return DnsAnswer(Status.NXDOMAIN)
        except dr.NoAnswer:
            return DnsAnswer(Status.NODATA)
        except dr.NoNameservers as exc:
            return DnsAnswer(Status.SERVFAIL, error=_short(exc))
        except (dr.LifetimeTimeout, TimeoutError) as exc:
            return DnsAnswer(Status.TIMEOUT, error=_short(exc))
        except Exception as exc:  # noqa: BLE001 - zaden blad sieci nie moze przerwac audytu
            return DnsAnswer(Status.ERROR, error=_short(exc))
        records = tuple(self._rdata_text(rtype, rd) for rd in ans)
        ad = bool(ans.response.flags & self._dns_flags.AD)
        return DnsAnswer(Status.OK, records, ad)

    @staticmethod
    def _rdata_text(rtype: str, rdata) -> str:
        return _rdata_text(rtype, rdata)


def _rdata_text(rtype: str, rdata) -> str:
    if rtype.upper() == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    return rdata.to_text()


def _short(exc: Exception) -> str:
    text = str(exc).replace("\n", " ")
    return (type(exc).__name__ + ": " + text)[:200]


# --- Tryb OPSEC: DNS-over-HTTPS (RFC 8484) przez proxy SOCKS5 (Tor) ---------------------------------------------

class _ProxyError(Exception):
    """Blad handshake'u SOCKS5 / HTTP (komunikat bez danych logowania)."""


_SOCKS_REPLY = {
    1: "ogolny blad serwera SOCKS", 2: "polaczenie zabronione regula proxy", 3: "siec nieosiagalna",
    4: "host nieosiagalny", 5: "polaczenie odrzucone", 6: "TTL wygasl", 7: "polecenie nieobslugiwane",
    8: "typ adresu nieobslugiwany",
}


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise _ProxyError("proxy zamknelo polaczenie w trakcie handshake'u SOCKS5")
        buf += chunk
    return buf


def _parse_proxy(proxy: str) -> tuple[str, int, str | None, str | None]:
    """socks5[h]://[user:pass@]host[:port] -> (host, port, user, password). Inne schematy: ValueError."""
    try:
        u = urlsplit(proxy.strip())
        host, port = u.hostname, u.port
    except ValueError as exc:
        raise ValueError("nieprawidlowy adres proxy (oczekiwano socks5h://host:port)") from exc
    if u.scheme.lower() not in ("socks5", "socks5h"):
        raise ValueError("proxy musi miec schemat socks5:// lub socks5h:// (zwykly DNS/HTTP nie przejdzie przez Tor)")
    if not host or u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("nieprawidlowy adres proxy (oczekiwano socks5h://[user:haslo@]host:port)")
    user = unquote(u.username) if u.username is not None else None
    pw = unquote(u.password) if u.password is not None else None
    if user is not None and not (1 <= len(user.encode()) <= 255 and len((pw or "").encode()) <= 255):
        raise ValueError("login/haslo proxy musza miec 1-255 bajtow")
    return host, port or 1080, user, pw


def _socks5_connect(sock: socket.socket, host: str, port: int, user: str, password: str) -> None:
    """RFC 1928 CONNECT z ATYP=3 (nazwa domeny przekazana proxy; lokalnie nigdy nie rozwiazujemy hosta) + RFC 1929."""
    hb = host.encode("idna")
    if not 1 <= len(hb) <= 255:
        raise _ProxyError("nieprawidlowa nazwa hosta DoH")
    sock.sendall(b"\x05\x02\x00\x02")  # wersja 5, 2 metody: brak uwierzytelnienia, user/pass
    ver, method = _recv_exact(sock, 2)
    if ver != 5:
        raise _ProxyError("to nie jest serwer SOCKS5")
    if method == 2:
        ub, pb = user.encode(), password.encode()
        sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        if _recv_exact(sock, 2)[1] != 0:
            raise _ProxyError("proxy odrzucilo uwierzytelnienie")
    elif method != 0:
        raise _ProxyError("proxy nie akceptuje zadnej oferowanej metody uwierzytelnienia")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    ver, rep, _rsv, atyp = _recv_exact(sock, 4)
    if ver != 5:
        raise _ProxyError("niepoprawna odpowiedz SOCKS5")
    if rep != 0:
        raise _ProxyError("SOCKS5: " + _SOCKS_REPLY.get(rep, f"kod {rep}"))
    if atyp == 1:
        _recv_exact(sock, 4 + 2)
    elif atyp == 4:
        _recv_exact(sock, 16 + 2)
    elif atyp == 3:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    else:
        raise _ProxyError("SOCKS5: nieznany typ adresu w odpowiedzi")


class _SocksHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection, ktorej connect() laczy sie z hostem DoH wylacznie przez proxy SOCKS5."""

    def __init__(self, host, port, *, proxy, ssl_context, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl_context)
        self._proxy = proxy  # (host, port, user, password)

    def connect(self) -> None:
        phost, pport, user, pw = self._proxy
        sock = socket.create_connection((phost, pport), self.timeout)  # lokalnie rozwiazujemy tylko adres proxy
        try:
            sock.settimeout(self.timeout)
            _socks5_connect(sock, self.host, self.port, user, pw)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class DohResolver:
    """DNS-over-HTTPS (RFC 8484, POST application/dns-message) przez proxy SOCKS5 (np. Tor).

    Nazwa hosta DoH idzie do proxy jako domena (ATYP=3): nic nie jest rozwiazywane lokalnie, wiec dostawca
    internetu nie widzi audytowanej domeny. Bez danych logowania w proxy losujemy login (jeden na instancje),
    dzieki czemu Tor izoluje obwod tego audytu od reszty ruchu. Polaczenie jest keep-alive, osobne dla kazdego
    watku (collector odpytuje rownolegle). Bledy wracaja jako DnsAnswer, nigdy wyjatek.

    ssl_context: do testow (wlasny CA); produkcyjnie domyslny ssl.create_default_context()."""

    def __init__(self, doh_url: str, proxy: str, timeout: float = 10.0, ssl_context: ssl.SSLContext | None = None):
        try:
            u = urlsplit(doh_url.strip())
            host, port = u.hostname, u.port
        except ValueError as exc:
            raise ValueError("nieprawidlowy adres DoH") from exc
        if u.scheme.lower() != "https" or not host or u.username is not None or u.password is not None:
            raise ValueError("adres DoH musi miec postac https://host[:port]/sciezka (bez loginu)")
        phost, pport, user, pw = _parse_proxy(proxy)
        if user is None:  # izolacja obwodu Tora: losowy login, jedna tozsamosc na instancje
            user, pw = secrets.token_hex(8), "x"
        self._host, self._port = host, port or 443
        self._path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        self._proxy = (phost, pport, user, pw or "")
        self._timeout = timeout
        self._ctx = ssl_context or ssl.create_default_context()
        self._local = threading.local()
        self._conns: list[http.client.HTTPSConnection] = []
        self._lock = threading.Lock()
        phost_l = f"[{phost}]" if ":" in phost else phost
        dhost_l = f"[{host}]" if ":" in host else host
        durl = f"https://{dhost_l}" + (f":{port}" if port else "") + self._path
        scheme = "socks5h" if _proxy_scheme(proxy) == "socks5h" else "socks5"
        self.description = f"DoH {durl} przez {scheme}://{phost_l}:{pport}"  # bez danych logowania

    def close(self) -> None:
        with self._lock:
            conns, self._conns = self._conns, []
        for c in conns:
            try:
                c.close()
            except OSError:
                pass

    def _conn(self) -> tuple[http.client.HTTPSConnection, bool]:
        c = getattr(self._local, "conn", None)
        if c is not None:
            return c, True
        c = _SocksHTTPSConnection(self._host, self._port, proxy=self._proxy, ssl_context=self._ctx, timeout=self._timeout)
        self._local.conn = c
        with self._lock:
            self._conns.append(c)
        return c, False

    def _drop(self, c: http.client.HTTPSConnection) -> None:
        self._local.conn = None
        with self._lock:
            if c in self._conns:
                self._conns.remove(c)
        try:
            c.close()
        except OSError:
            pass

    def _post(self, wire: bytes) -> bytes:
        headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
        attempt = 0
        while True:
            c, reused = self._conn()
            try:
                c.request("POST", self._path, body=wire, headers=headers)
                resp = c.getresponse()
                body = resp.read(65536 + 1)
            except (ConnectionError, http.client.HTTPException):
                self._drop(c)
                if reused and attempt == 0:  # zerwane polaczenie keep-alive: jedna ponowna proba
                    attempt += 1
                    continue
                raise
            except BaseException:
                self._drop(c)
                raise
            if resp.status != 200:
                self._drop(c)
                raise _ProxyError(f"serwer DoH zwrocil HTTP {resp.status}")
            if len(body) > 65536:
                self._drop(c)
                raise _ProxyError("odpowiedz DoH zbyt duza")
            return body

    def _scrub(self, text: str) -> str:
        user, pw = self._proxy[2], self._proxy[3]
        for secret in (pw, user):
            if secret and len(secret) > 1:
                text = text.replace(secret, "***")
        return text

    def query(self, name: str, rtype: str) -> DnsAnswer:
        try:
            import dns.flags
            import dns.message
            import dns.name
            import dns.rcode
            import dns.rdatatype

            rdtype = dns.rdatatype.from_text(rtype)
            q = dns.message.make_query(
                dns.name.from_text(name), rdtype, want_dnssec=True, use_edns=0, payload=1232,
                flags=dns.flags.RD | dns.flags.AD, id=0,  # RFC 8484: id=0 (lepsze cache'owanie)
            )
            msg = dns.message.from_wire(self._post(q.to_wire()))
            rcode = msg.rcode()
            if rcode == dns.rcode.NXDOMAIN:
                return DnsAnswer(Status.NXDOMAIN)
            if rcode == dns.rcode.SERVFAIL:
                return DnsAnswer(Status.SERVFAIL, error="SERVFAIL")
            if rcode != dns.rcode.NOERROR:
                return DnsAnswer(Status.ERROR, error=f"rcode {dns.rcode.to_text(rcode)}")
            records = tuple(
                _rdata_text(rtype, rd) for rrset in msg.answer if rrset.rdtype == rdtype for rd in rrset
            )
            if not records:
                return DnsAnswer(Status.NODATA)
            return DnsAnswer(Status.OK, records, bool(msg.flags & dns.flags.AD))
        except TimeoutError as exc:  # socket.timeout to alias
            return DnsAnswer(Status.TIMEOUT, error=self._scrub(_short(exc)))
        except Exception as exc:  # noqa: BLE001 - zaden blad sieci nie moze przerwac audytu
            return DnsAnswer(Status.ERROR, error=self._scrub(_short(exc)))


def _proxy_scheme(proxy: str) -> str:
    return urlsplit(proxy.strip()).scheme.lower()


def preflight(resolver: Resolver) -> str | None:
    """Jedno zapytanie kontrolne (example.com A). None = kanal dziala, inaczej tekst bledu."""
    ans = resolver.query("example.com", "A")
    if ans.ok:
        return None
    return ans.error or ans.status.value
