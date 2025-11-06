"""CRUD operations for audit log entries."""

from datetime import datetime
from uuid import UUID

from sqlmodel import desc, select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.audit_log.model import (
    AuditLog,
    AuditLogCreate,
    AuditLogEventType,
    AuditLogRead,
    AuditLogResult,
)


async def create_audit_log(session: AsyncSession, audit_log_data: AuditLogCreate) -> AuditLog:
    """Create a new audit log entry.

    Args:
        session: Database session.
        audit_log_data: Data for the new audit log entry.

    Returns:
        Created AuditLog object.
    """
    audit_log = AuditLog.model_validate(audit_log_data)
    session.add(audit_log)
    await session.commit()
    await session.refresh(audit_log)
    return audit_log


async def get_audit_logs(
    session: AsyncSession,
    *,
    user_id: UUID | None = None,
    event_type: AuditLogEventType | None = None,
    result: AuditLogResult | None = None,
    provider: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLogRead]:
    """Query audit logs with filters.

    Args:
        session: Database session.
        user_id: Filter by user ID.
        event_type: Filter by event type.
        result: Filter by result (success/failure).
        provider: Filter by provider (local, oidc, api_key).
        start_date: Filter by start date (inclusive).
        end_date: Filter by end date (inclusive).
        limit: Maximum number of results (default 100, max 1000).
        offset: Number of results to skip for pagination.

    Returns:
        List of audit log entries matching the filters.
    """
    # Build query with filters
    query = select(AuditLog)

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if result:
        query = query.where(AuditLog.result == result)
    if provider:
        query = query.where(AuditLog.provider == provider)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)

    # Order by most recent first
    query = query.order_by(desc(AuditLog.created_at))

    # Apply pagination
    query = query.limit(min(limit, 1000)).offset(offset)

    # Execute and convert to read models
    result_set = await session.exec(query)
    audit_logs = result_set.all()

    return [AuditLogRead.model_validate(log) for log in audit_logs]


async def get_audit_log_by_id(session: AsyncSession, audit_log_id: UUID) -> AuditLog | None:
    """Get a single audit log entry by ID.

    Args:
        session: Database session.
        audit_log_id: ID of the audit log entry.

    Returns:
        AuditLog object or None if not found.
    """
    return await session.get(AuditLog, audit_log_id)


async def get_failed_login_attempts(
    session: AsyncSession,
    username: str,
    since: datetime,
    limit: int = 10,
) -> list[AuditLogRead]:
    """Get recent failed login attempts for a username.

    Useful for detecting brute force attacks or account issues.

    Args:
        session: Database session.
        username: Username to check.
        since: Only return attempts since this datetime.
        limit: Maximum number of attempts to return.

    Returns:
        List of failed login audit log entries.
    """
    query = (
        select(AuditLog)
        .where(AuditLog.username == username)
        .where(AuditLog.result == AuditLogResult.FAILURE)
        .where(
            AuditLog.event_type.in_(
                [
                    AuditLogEventType.LOGIN_FAILURE,
                    AuditLogEventType.OIDC_LOGIN_FAILURE,
                ]
            )
        )
        .where(AuditLog.created_at >= since)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )

    result_set = await session.exec(query)
    audit_logs = result_set.all()

    return [AuditLogRead.model_validate(log) for log in audit_logs]


async def count_audit_logs(
    session: AsyncSession,
    *,
    user_id: UUID | None = None,
    event_type: AuditLogEventType | None = None,
    result: AuditLogResult | None = None,
    provider: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> int:
    """Count audit logs matching filters.

    Useful for pagination.

    Args:
        session: Database session.
        user_id: Filter by user ID.
        event_type: Filter by event type.
        result: Filter by result.
        provider: Filter by provider.
        start_date: Filter by start date.
        end_date: Filter by end date.

    Returns:
        Count of matching audit log entries.
    """
    from sqlalchemy import func

    query = select(func.count(AuditLog.id))

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if result:
        query = query.where(AuditLog.result == result)
    if provider:
        query = query.where(AuditLog.provider == provider)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)

    result_set = await session.exec(query)
    return result_set.one()
