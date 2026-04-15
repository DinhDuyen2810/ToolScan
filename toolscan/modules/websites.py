from __future__ import annotations

import socket
from urllib.parse import urlparse


def _extract_host(domain_or_url: str) -> str:
    value = (domain_or_url or '').strip()
    if not value:
        return ''
    if value.startswith(('http://', 'https://')):
        return urlparse(value).hostname or ''
    return value.split('/', 1)[0].split(':', 1)[0]


def resolve_public_ip(domain_or_url: str) -> str:
    host = _extract_host(domain_or_url)
    if not host:
        return 'N/A'
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception:
        return 'N/A'

    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return ', '.join(ips) if ips else 'N/A'
