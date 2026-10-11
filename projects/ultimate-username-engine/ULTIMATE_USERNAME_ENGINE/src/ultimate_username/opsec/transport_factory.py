"""Single egress entry point shared by every OSINT adapter.

`build_transport` is the integration contract in code: all adapters (Username
Engine, Email Engine, Google Enrichment) obtain their `Transport` here instead of
constructing one directly. It guarantees that a mandatory proxy cannot silently
degrade to direct traffic.
"""

from __future__ import annotations

from ultimate_username.opsec.config import ProxyConfig
from ultimate_username.opsec.guard import GuardedTransport
from ultimate_username.opsec.policy import EgressPolicy, Resolver
from ultimate_username.opsec.server import ProxyError, default_resolver
from ultimate_username.transport import Transport


def build_transport(
    config: ProxyConfig,
    inner: Transport,
    *,
    inner_routes_through_proxy: bool = False,
    resolver: Resolver = default_resolver,
) -> Transport:
    """Return the egress transport to use, enforcing the proxy contract.

    - proxy disabled                -> ``inner`` unchanged (operator opted out).
    - enabled + fail_closed, but the inner transport is NOT routed through the
      proxy -> raise. We refuse to hand back a direct transport when the proxy is
      mandatory (no silent fallback to direct traffic).
    - enabled                       -> ``inner`` wrapped in ``GuardedTransport`` so
      allowlist + SSRF policy is enforced in-process regardless of routing.

    ``inner_routes_through_proxy`` is set by the caller when ``inner`` (e.g. an
    ``AiohttpTransport``) has its proxy pointed at the local OSINT_OPSEC server.
    """

    if not config.enabled:
        return inner

    problems = config.validate()
    if problems:
        raise ProxyError(500, "; ".join(problems))
    if config.fail_closed and not inner_routes_through_proxy:
        raise ProxyError(
            500,
            "proxy is mandatory (enabled + fail_closed) but the inner transport is "
            "not routed through it; refusing to build a direct transport",
        )
    return GuardedTransport(inner, config.policy(), resolver=resolver)


def _no_dns(host: str) -> list[str]:
    raise LookupError("local DNS disabled: the proxy resolves names")


def public_egress_transport(
    inner: Transport, *, resolver: Resolver = default_resolver, resolve_dns: bool = True
) -> GuardedTransport:
    """SSRF belt for ordinary scans: any public http(s) destination, nothing internal.

    No allowlist and no port limit (site definitions decide those), but every request, redirect
    hop, avatar and Wayback lookup is refused when the host is a numeric/local spelling of an
    internal address or any resolved address is private, loopback, link-local, reserved or
    multicast. Unresolvable names reach ``inner`` so DNS errors keep their normal verdicts, and
    ``.onion`` hosts (resolved by a proxy) are left to ``inner``, which requires one. With
    ``resolve_dns=False`` (an explicit proxy is in use) no local lookup is made, so names do not
    leak outside the proxy; literal and local spellings are still refused.
    """
    policy = EgressPolicy(
        allowed_schemes=frozenset({"http", "https"}),
        allowed_ports=frozenset(),
        require_allowlist=False,
    )
    return GuardedTransport(
        inner,
        policy,
        resolver=resolver if resolve_dns else _no_dns,
        dns_failure_passes=True,
        unresolved_suffixes=(".onion",),
    )
