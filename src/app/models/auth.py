"""Request and response shapes for authentication, users and roles.

The rule this file exists to enforce: `password_hash` never leaves the process.
The ORM classes in `app.db.tables` carry it, so nothing maps them to responses
automatically — every outbound model is built by an explicit `from_row`, and
adding a column to `users` cannot leak it by accident.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator

from app.security.scopes import SCOPE_DESCRIPTIONS, unknown_scopes

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.db.tables import Role, User


def _validate_scopes(values: list[str]) -> list[str]:
    unknown = unknown_scopes(values)
    if unknown:
        raise ValueError(
            f"unknown scope(s): {', '.join(unknown)}. "
            f"Valid scopes: {', '.join(sorted(SCOPE_DESCRIPTIONS))}"
        )
    return sorted(set(values))


# --- Tokens ------------------------------------------------------------------


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    # OAuth2 says this field is called token_type and its value is "bearer".
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime, in seconds")


class RefreshRequest(BaseModel):
    refresh_token: str


class StreamTicket(BaseModel):
    ticket: str
    expires_in: float = Field(description="Seconds before the ticket is useless")


# --- Passwords ---------------------------------------------------------------


class PasswordChange(BaseModel):
    """Self-service. Proving the current password is what makes a stolen access
    token insufficient to take over an account."""

    current_password: str
    new_password: str


class PasswordReset(BaseModel):
    """Administrative reset — no current password, needs `users:write`."""

    new_password: str


# --- Users -------------------------------------------------------------------


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str
    roles: list[str] = Field(default_factory=list)

    @field_validator("username")
    @classmethod
    def _strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("username cannot be blank")
        return stripped


class UserUpdate(BaseModel):
    is_active: bool | None = None


class UserRoles(BaseModel):
    roles: list[str]


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    is_active: bool
    roles: list[str]
    scopes: list[str] = Field(description="Union of the scopes this user's roles hold")
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, user: User) -> UserOut:
        return cls(
            id=user.id,
            username=user.username,
            is_active=user.is_active,
            roles=sorted(role.name for role in user.roles),
            scopes=sorted(user.scopes),
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class Me(UserOut):
    """`/auth/me`. Same shape as a user — the caller is one."""


# --- Roles -------------------------------------------------------------------


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    scopes: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("role name cannot be blank")
        return stripped

    _check_scopes = field_validator("scopes")(_validate_scopes)


class RoleUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=500)


class RoleScopes(BaseModel):
    scopes: list[str]

    _check_scopes = field_validator("scopes")(_validate_scopes)


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    is_system: bool = Field(
        description="Built in. Cannot be deleted or have its scopes changed."
    )
    scopes: list[str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, role: Role) -> RoleOut:
        return cls(
            id=role.id,
            name=role.name,
            description=role.description,
            is_system=role.is_system,
            scopes=sorted(role.scope_set),
            created_at=role.created_at,
            updated_at=role.updated_at,
        )


class ScopeInfo(BaseModel):
    """One entry of the fixed catalogue, for building a role editor."""

    name: str
    description: str
