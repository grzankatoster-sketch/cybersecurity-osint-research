"""Transformacja URL: host adresu jako węzeł Domena albo IP (czysta, bez sieci)."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from ..model import Node, Status
from ..normalize import EntityType, normalize_domain, normalize_ip
from .base import Context, TransformResult, register


@register("url_host", (EntityType.URL,), "Host z adresu URL jako domena lub IP (czysta, bez sieci)", network=False)
def url_host(node: Node, ctx: Context) -> TransformResult:
    host = urlsplit(node.value).hostname or ""
    try:
        ipaddress.ip_address(host)
        target = Node.make(EntityType.IP, normalize_ip(host), {}, "url_host")
    except ValueError:
        try:
            target = Node.make(EntityType.DOMAIN, normalize_domain(host), {}, "url_host")
        except ValueError:
            return TransformResult.failed(Status.UNKNOWN, "host adresu nie jest poprawną domeną")
    res = TransformResult(Status.FOUND, nodes=[target])
    res.edges.append(ctx.edge("url_host", node, target, "hosted_on", 1.0, "host z adresu URL"))
    return res
