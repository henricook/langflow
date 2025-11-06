from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlmodel import Column, DateTime, Field, Relationship, SQLModel, func

from langflow.schema.serialize import UUIDstr

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User


def utc_now():
    return datetime.now(timezone.utc)


class OIDCIdentityBase(SQLModel):
    provider_name: str = Field(index=True, nullable=False)
    """Display name of the OIDC provider (e.g., 'Azure AD', 'Google')"""

    provider_user_id: str = Field(index=True, nullable=False)
    """Subject identifier (sub claim) from the OIDC provider"""

    issuer: str = Field(index=True, nullable=False)
    """Issuer URL from the OIDC ID token (iss claim)"""

    email: str = Field(index=True, nullable=False)
    """Email address from OIDC claims"""

    email_verified: bool = Field(default=False)
    """Whether the email is verified by the OIDC provider"""

    name: str | None = Field(default=None, nullable=True)
    """Full name from OIDC claims (optional)"""

    picture: str | None = Field(default=None, nullable=True)
    """Profile picture URL from OIDC claims (optional)"""


class OIDCIdentity(OIDCIdentityBase, table=True):  # type: ignore[call-arg]
    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, unique=True)

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )
    """When this OIDC identity was first linked"""

    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(
            DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
        ),
    )
    """When this OIDC identity was last updated"""

    last_login_at: datetime | None = Field(default=None, nullable=True)
    """Last time this OIDC identity was used to log in"""

    # User relationship
    user_id: UUIDstr = Field(index=True, foreign_key="user.id")
    user: "User" = Relationship(back_populates="oidc_identities")


class OIDCIdentityCreate(OIDCIdentityBase):
    user_id: UUIDstr
    created_at: datetime | None = Field(default_factory=utc_now)
    updated_at: datetime | None = Field(default_factory=utc_now)
    last_login_at: datetime | None = None


class OIDCIdentityRead(OIDCIdentityBase):
    id: UUIDstr
    user_id: UUIDstr
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None


class OIDCIdentityUpdate(SQLModel):
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    picture: str | None = None
    last_login_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utc_now)
