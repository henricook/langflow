from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from lfx.log.logger import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.user.model import User, UserUpdate


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return (await db.exec(stmt)).first()


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
    if isinstance(user_id, str):
        user_id = UUID(user_id)
    stmt = select(User).where(User.id == user_id)
    return (await db.exec(stmt)).first()


async def update_user(user_db: User | None, user: UserUpdate, db: AsyncSession) -> User:
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    # user_db_by_username = get_user_by_username(db, user.username)
    # if user_db_by_username and user_db_by_username.id != user_id:
    #     raise HTTPException(status_code=409, detail="Username already exists")

    user_data = user.model_dump(exclude_unset=True)
    changed = False
    for attr, value in user_data.items():
        if hasattr(user_db, attr) and value is not None:
            setattr(user_db, attr, value)
            changed = True

    if not changed:
        raise HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Nothing to update")

    user_db.updated_at = datetime.now(timezone.utc)
    flag_modified(user_db, "updated_at")

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e)) from e

    return user_db


async def update_user_last_login_at(user_id: UUID, db: AsyncSession):
    try:
        user_data = UserUpdate(last_login_at=datetime.now(timezone.utc))
        user = await get_user_by_id(db, user_id)
        return await update_user(user, user_data, db)
    except Exception as e:  # noqa: BLE001
        await logger.aerror(f"Error updating user last login at: {e!s}")


async def get_all_superusers(db: AsyncSession) -> list[User]:
    """Get all superuser accounts from the database."""
    stmt = select(User).where(User.is_superuser == True)  # noqa: E712
    result = await db.exec(stmt)
    return list(result.all())


async def add_user(db: AsyncSession, user: "UserCreate") -> User:
    """Add a new user to the database.

    Args:
        db: Database session
        user: UserCreate object with user data (password should already be hashed)

    Returns:
        Created user object

    Raises:
        IntegrityError: If username already exists
    """
    from langflow.services.database.models.user.model import UserCreate

    new_user = User.model_validate(user, from_attributes=True)

    try:
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except IntegrityError as e:
        await db.rollback()
        logger.error(f"Error creating user: {e}")
        raise HTTPException(
            status_code=400,
            detail="This username is unavailable.",
        ) from e


async def update_user_by_id(db: AsyncSession, user_id: UUID, update_data: dict) -> User:
    """Update a user by ID with a dictionary of updates.

    This is a convenience function for updating users with a dict of fields,
    useful for programmatic updates (e.g., from OIDC authentication).

    Args:
        db: Database session.
        user_id: User ID to update.
        update_data: Dictionary of fields to update (e.g., {"last_login_at": datetime.now()}).

    Returns:
        Updated user object.

    Raises:
        HTTPException: If user not found or update fails.
    """
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Update fields
    changed = False
    for attr, value in update_data.items():
        if hasattr(user, attr) and value is not None:
            setattr(user, attr, value)
            changed = True

    if not changed:
        raise HTTPException(
            status_code=status.HTTP_304_NOT_MODIFIED,
            detail="Nothing to update",
        )

    user.updated_at = datetime.now(timezone.utc)
    flag_modified(user, "updated_at")

    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return user
