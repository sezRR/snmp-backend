"""Request-scoped accessors for the objects built in the lifespan.

They live on `app.state`, so these exist to keep `request.app.state.…` and its
`RuntimeError` handling out of every endpoint.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.config import Settings, get_settings
from app.db.pool import Database
from app.security.crypto import CredentialCipher
from app.services.bus import MetricBus
from app.services.collector import Collector
from app.services.credentials import CredentialCache
from app.services.openstack import CachedOpenStack
from app.services.ratelimit import LoginRateLimiter
from app.services.snmp import SnmpSampler


def get_db(request: Request) -> Database:
    db: Database | None = getattr(request.app.state, "db", None)
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database pool is not open",
        )
    return db


def get_lookup(request: Request) -> CachedOpenStack:
    return request.app.state.lookup


def get_bus(request: Request) -> MetricBus:
    return request.app.state.bus


def get_collector(request: Request) -> Collector:
    return request.app.state.collector


def get_sampler(request: Request) -> SnmpSampler:
    return request.app.state.sampler


def get_credentials(request: Request) -> CredentialCache:
    return request.app.state.credentials


def get_login_limiter(request: Request) -> LoginRateLimiter:
    return request.app.state.login_limiter


def get_client_ip(request: Request) -> str | None:
    """The caller's address as the ASGI server reports it, or None.

    Deliberately `request.client` and not the `X-Forwarded-For` header: reading
    that header here would let any caller pick its own rate-limit bucket by
    inventing one. Uvicorn's own `ProxyHeadersMiddleware` does the same job
    safely because it only believes the header when the *connection* comes from
    a trusted address — which is why the Deployment sets `FORWARDED_ALLOW_IPS`.
    Without that, every request behind Traefik shares Traefik's address and the
    per-address limit becomes a per-cluster one.

    None when the scope carries no client, as with an in-process test transport.
    """
    return request.client.host if request.client is not None else None


def get_cipher(request: Request) -> CredentialCipher:
    """The credential cipher, or a 503 if this deployment has no key ring.

    `Settings` only demands one when `SNMP_SIMULATE=false`, so a simulated stack
    can reach the credential endpoints with nothing to encrypt with. Better a
    503 naming the missing variable than a 500 out of the crypto layer.
    """
    cipher: CredentialCipher = request.app.state.cipher
    if not cipher.usable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "no SNMP credential key is configured; set SNMP_CREDENTIAL_KEYS "
                "and SNMP_CREDENTIAL_ACTIVE_KEY (openssl rand -hex 32)"
            ),
        )
    return cipher


DbDep = Annotated[Database, Depends(get_db)]
LookupDep = Annotated[CachedOpenStack, Depends(get_lookup)]
BusDep = Annotated[MetricBus, Depends(get_bus)]
CollectorDep = Annotated[Collector, Depends(get_collector)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
SamplerDep = Annotated[SnmpSampler, Depends(get_sampler)]
CredentialCacheDep = Annotated[CredentialCache, Depends(get_credentials)]
CipherDep = Annotated[CredentialCipher, Depends(get_cipher)]
LoginLimiterDep = Annotated[LoginRateLimiter, Depends(get_login_limiter)]
ClientIpDep = Annotated[str | None, Depends(get_client_ip)]
