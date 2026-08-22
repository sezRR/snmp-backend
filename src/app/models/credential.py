from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Self
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class SnmpVersion(StrEnum):
    V2C = "2c"
    V3 = "3"


class SecurityLevel(StrEnum):
    NO_AUTH_NO_PRIV = "noAuthNoPriv"
    AUTH_NO_PRIV = "authNoPriv"
    AUTH_PRIV = "authPriv"


class AuthProtocol(StrEnum):
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"


class PrivProtocol(StrEnum):
    DES = "DES"
    TRIPLE_DES = "3DES"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"


# Broken, not merely dated: MD5 and DES are trivially attackable and
# noAuthNoPriv is v3 with the security off. Reachable only with `allow_weak`,
# because deployed snmpd builds still exist that support nothing else.
WEAK_AUTH_PROTOCOLS = frozenset({AuthProtocol.MD5})
WEAK_PRIV_PROTOCOLS = frozenset({PrivProtocol.DES})


def _weakness(
    security_level: SecurityLevel | None,
    auth_protocol: AuthProtocol | None,
    priv_protocol: PrivProtocol | None,
) -> list[str]:
    """Everything about this combination that is not fit for new credentials."""
    weak: list[str] = []
    if security_level is SecurityLevel.NO_AUTH_NO_PRIV:
        weak.append("noAuthNoPriv sends every request unauthenticated")
    if auth_protocol in WEAK_AUTH_PROTOCOLS:
        weak.append(f"{auth_protocol} authentication is broken")
    if priv_protocol in WEAK_PRIV_PROTOCOLS:
        weak.append(f"{priv_protocol} privacy is broken")
    return weak


class SnmpCredentialBase(BaseModel):
    """The USM shape, shared by create and by the inline test payload."""

    snmp_version: SnmpVersion
    community: str | None = Field(
        default=None,
        description="v2c only. The community string.",
    )
    username: str | None = Field(
        default=None, max_length=200, description="v3 only. The USM securityName."
    )
    security_level: SecurityLevel | None = None
    auth_protocol: AuthProtocol | None = None
    auth_passphrase: str | None = Field(default=None, min_length=8, max_length=200)
    priv_protocol: PrivProtocol | None = None
    priv_passphrase: str | None = Field(default=None, min_length=8, max_length=200)
    allow_weak: bool = Field(
        default=False,
        description="Permit MD5, DES or noAuthNoPriv. Off by default.",
    )

    @model_validator(mode="after")
    def _shape_matches_version(self) -> Self:
        """Reject every combination USM itself would not accept.

        The database has the same constraints. Both exist: this one produces a
        422 that names the missing field, the other guarantees a hand-edited row
        can never reach the sampler half-formed.
        """
        if self.snmp_version is SnmpVersion.V2C:
            missing_or_extra = [
                name
                for name, value in (
                    ("username", self.username),
                    ("security_level", self.security_level),
                    ("auth_protocol", self.auth_protocol),
                    ("auth_passphrase", self.auth_passphrase),
                    ("priv_protocol", self.priv_protocol),
                    ("priv_passphrase", self.priv_passphrase),
                )
                if value is not None
            ]
            if missing_or_extra:
                raise ValueError(
                    f"{', '.join(missing_or_extra)} {'is' if len(missing_or_extra) == 1 else 'are'} "
                    "for SNMPv3; a 2c credential carries only `community`"
                )
            if not self.community:
                raise ValueError("`community` is required for an SNMPv2c credential")
            return self

        if self.community is not None:
            raise ValueError("`community` is for SNMPv2c; a v3 credential has a user")
        if not self.username:
            raise ValueError("`username` is required for an SNMPv3 credential")
        if self.security_level is None:
            raise ValueError(
                "`security_level` is required for an SNMPv3 credential: "
                "noAuthNoPriv, authNoPriv or authPriv"
            )

        needs_auth = self.security_level is not SecurityLevel.NO_AUTH_NO_PRIV
        needs_priv = self.security_level is SecurityLevel.AUTH_PRIV
        for needed, label, protocol, passphrase in (
            (needs_auth, "auth", self.auth_protocol, self.auth_passphrase),
            (needs_priv, "priv", self.priv_protocol, self.priv_passphrase),
        ):
            if needed and (protocol is None or passphrase is None):
                raise ValueError(
                    f"security_level {self.security_level} requires "
                    f"`{label}_protocol` and `{label}_passphrase`"
                )
            if not needed and (protocol is not None or passphrase is not None):
                raise ValueError(
                    f"security_level {self.security_level} takes no "
                    f"`{label}_protocol` or `{label}_passphrase`"
                )

        weak = _weakness(self.security_level, self.auth_protocol, self.priv_protocol)
        if weak and not self.allow_weak:
            raise ValueError(
                f"{'; '.join(weak)}. Pass `allow_weak: true` if the agent "
                "genuinely supports nothing better."
            )
        return self

    def secret_payload(self) -> dict[str, Any]:
        """The part that gets encrypted. Everything else is metadata."""
        if self.snmp_version is SnmpVersion.V2C:
            return {"community": self.community}
        return {"auth": self.auth_passphrase, "priv": self.priv_passphrase}


class SnmpCredentialCreate(SnmpCredentialBase):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)


class SnmpCredentialUpdate(BaseModel):
    """All fields optional. Any secret field present bumps `secret_version`.

    Deliberately not a partial USM edit: changing `security_level` from
    authNoPriv to authPriv without supplying a priv passphrase would leave a row
    that no validator can repair. So a change to any USM field requires the full
    shape, and the handler re-validates it through `SnmpCredentialBase`.
    """

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    # Omitted keeps the current value; present replaces the whole USM shape.
    snmp_version: SnmpVersion | None = None
    community: str | None = None
    username: str | None = Field(default=None, max_length=200)
    security_level: SecurityLevel | None = None
    auth_protocol: AuthProtocol | None = None
    auth_passphrase: str | None = Field(default=None, min_length=8, max_length=200)
    priv_protocol: PrivProtocol | None = None
    priv_passphrase: str | None = Field(default=None, min_length=8, max_length=200)
    allow_weak: bool = False

    # ClassVar, or pydantic would make it a field named SECRET_FIELDS.
    SECRET_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "snmp_version",
            "community",
            "username",
            "security_level",
            "auth_protocol",
            "auth_passphrase",
            "priv_protocol",
            "priv_passphrase",
        }
    )

    @property
    def touches_secret(self) -> bool:
        return bool(self.model_fields_set & self.SECRET_FIELDS)


class SnmpCredential(BaseModel):
    """A credential as the API returns it. There is no secret field here."""

    id: UUID
    name: str
    description: str | None
    snmp_version: SnmpVersion
    username: str | None
    security_level: SecurityLevel | None
    auth_protocol: AuthProtocol | None
    priv_protocol: PrivProtocol | None
    secret_version: int
    # Truncated keyed HMAC: tells two profiles apart, and whether a rotation
    # changed anything, without returning the secret.
    fingerprint: str
    created_at: datetime
    updated_at: datetime


class CredentialBind(BaseModel):
    credential_id: UUID


class CredentialTestRequest(BaseModel):
    """Optionally test an unsaved credential instead of the bound one.

    There is no address field, and there must never be one: the address comes
    from the machine's own row. An endpoint that probes an arbitrary address with
    a stored credential is the credential-relay attack this design exists to
    prevent, wrapped in a supported API and made synchronous.

    An unsaved credential in the body is fine — the caller supplied the secret,
    so there is nothing here they did not already know.
    """

    credential: SnmpCredentialBase | None = None


class CredentialTestResult(BaseModel):
    ok: bool
    ipv4: str
    credential_id: UUID | None
    duration_seconds: float
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """A decrypted credential, in memory only.

    Never serialised and never logged: `name` is what identifies it in a log
    line. Held by `app.services.credentials.CredentialCache` and handed to the
    sampler, which keys its pysnmp objects on `(id, secret_version)`.
    """

    id: UUID
    name: str
    secret_version: int
    snmp_version: SnmpVersion
    community: str | None = None
    username: str | None = None
    security_level: SecurityLevel | None = None
    auth_protocol: AuthProtocol | None = None
    priv_protocol: PrivProtocol | None = None
    auth_passphrase: str | None = None
    priv_passphrase: str | None = None

    @property
    def cache_key(self) -> tuple[UUID, int]:
        return (self.id, self.secret_version)

    def __repr__(self) -> str:
        # The default repr would put both passphrases into any traceback.
        return (
            f"ResolvedCredential(id={self.id}, name={self.name!r}, "
            f"snmp_version={self.snmp_version}, secret_version={self.secret_version})"
        )
