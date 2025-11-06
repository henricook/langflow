from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy.orm import selectinload
from sqlmodel import and_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.oidc_identity.model import (
    OIDCIdentity,
    OIDCIdentityCreate,
    OIDCIdentityRead,
    OIDCIdentityUpdate,
)
from langflow.services.database.models.user.model import User

if TYPE_CHECKING:
    from sqlmodel.sql.expression import SelectOfScalar


async def get_oidc_identity_by_issuer_and_subject(
    session: AsyncSession, issuer: str, provider_user_id: str
) -> OIDCIdentity | None:
    """Get OIDC identity by issuer and subject ID.

    This is the canonical way to look up OIDC identities. We use the issuer
    (from the ID token's iss claim) rather than provider_name (from config)
    because the issuer is stable and uniquely identifies the OIDC provider,
    while provider_name can be changed by admins.
    """
    query: SelectOfScalar = (
        select(OIDCIdentity)
        .options(selectinload(OIDCIdentity.user))
        .where(
            and_(
                OIDCIdentity.issuer == issuer,
                OIDCIdentity.provider_user_id == provider_user_id,
            )
        )
    )
    return (await session.exec(query)).first()


async def get_oidc_identities_by_user_id(session: AsyncSession, user_id: UUID) -> list[OIDCIdentityRead]:
    """Get all OIDC identities for a user."""
    query: SelectOfScalar = select(OIDCIdentity).where(OIDCIdentity.user_id == user_id)
    identities = (await session.exec(query)).all()
    return [OIDCIdentityRead.model_validate(identity) for identity in identities]


async def create_oidc_identity(
    session: AsyncSession, oidc_identity_create: OIDCIdentityCreate
) -> OIDCIdentity:
    """Create a new OIDC identity."""
    oidc_identity = OIDCIdentity.model_validate(oidc_identity_create)

    session.add(oidc_identity)
    await session.commit()
    await session.refresh(oidc_identity)
    return oidc_identity


async def update_oidc_identity(
    session: AsyncSession, oidc_identity: OIDCIdentity, update_data: OIDCIdentityUpdate
) -> OIDCIdentity:
    """Update an existing OIDC identity."""
    update_dict = update_data.model_dump(exclude_unset=True)
    update_dict["updated_at"] = datetime.now(timezone.utc)

    for key, value in update_dict.items():
        setattr(oidc_identity, key, value)

    session.add(oidc_identity)
    await session.commit()
    await session.refresh(oidc_identity)
    return oidc_identity


async def update_last_login(session: AsyncSession, oidc_identity: OIDCIdentity) -> OIDCIdentity:
    """Update the last login timestamp for an OIDC identity."""
    oidc_identity.last_login_at = datetime.now(timezone.utc)
    oidc_identity.updated_at = datetime.now(timezone.utc)
    session.add(oidc_identity)
    await session.commit()
    await session.refresh(oidc_identity)
    return oidc_identity


async def delete_oidc_identity(session: AsyncSession, oidc_identity_id: UUID) -> None:
    """Delete an OIDC identity."""
    oidc_identity = await session.get(OIDCIdentity, oidc_identity_id)
    if oidc_identity is None:
        msg = "OIDC Identity not found"
        raise ValueError(msg)
    await session.delete(oidc_identity)
    await session.commit()
