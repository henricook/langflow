"""Audit logging service for security events.

This service provides convenient methods for logging authentication and
security events to the audit log database.
"""

from typing import Any
from uuid import UUID

from fastapi import Request
from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.audit_log import crud as audit_crud
from langflow.services.database.models.audit_log.model import (
    AuditLogCreate,
    AuditLogEventType,
    AuditLogResult,
)


def get_client_ip(request: Request | None) -> str | None:
    """Extract client IP address from request.

    Handles X-Forwarded-For header for load balancers/proxies.

    Args:
        request: FastAPI request object.

    Returns:
        Client IP address or None if not available.
    """
    if not request:
        return None

    # Check X-Forwarded-For header (load balancers, proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client address
    if request.client:
        return request.client.host

    return None


def get_user_agent(request: Request | None) -> str | None:
    """Extract user agent from request.

    Args:
        request: FastAPI request object.

    Returns:
        User agent string or None if not available.
    """
    if not request:
        return None
    return request.headers.get("User-Agent")


class AuditService:
    """Service for logging security and authentication events.

    This service provides methods to log various types of events to the
    audit log database with automatic extraction of request metadata.
    """

    @staticmethod
    async def log_event(
        db: AsyncSession,
        event_type: AuditLogEventType,
        result: AuditLogResult,
        *,
        user_id: UUID | None = None,
        username: str | None = None,
        provider: str | None = None,
        provider_name: str | None = None,
        failure_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
        request: Request | None = None,
    ) -> None:
        """Log a security event to the audit log.

        Args:
            db: Database session.
            event_type: Type of event (from AuditLogEventType enum).
            result: Whether the event succeeded or failed.
            user_id: User ID if event is associated with a user.
            username: Username for the event.
            provider: Authentication provider (e.g., "local", "oidc", "api_key").
            provider_name: Human-readable provider name (e.g., "Azure AD").
            failure_reason: Reason for failure if result is FAILURE.
            metadata: Additional structured data about the event.
            request: FastAPI request object (for extracting IP, user agent).
        """
        try:
            audit_log_data = AuditLogCreate(
                event_type=event_type,
                result=result,
                user_id=user_id,
                username=username,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                provider=provider,
                provider_name=provider_name,
                failure_reason=failure_reason,
                metadata=metadata,
            )

            await audit_crud.create_audit_log(db, audit_log_data)

            # Also log to application logs for immediate visibility
            log_message = (
                f"Audit: {event_type.value} - {result.value} "
                f"[user={username or 'N/A'}, provider={provider or 'N/A'}"
            )
            if failure_reason:
                log_message += f", reason={failure_reason}"
            log_message += "]"

            if result == AuditLogResult.FAILURE:
                logger.warning(log_message)
            else:
                logger.info(log_message)

        except Exception as e:
            # Never fail the main operation due to audit logging errors
            logger.exception(f"Failed to create audit log entry: {e}")

    @staticmethod
    async def log_login_success(
        db: AsyncSession,
        user_id: UUID,
        username: str,
        provider: str = "local",
        provider_name: str | None = None,
        request: Request | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log a successful login attempt.

        Args:
            db: Database session.
            user_id: User ID.
            username: Username.
            provider: Authentication provider.
            provider_name: Human-readable provider name.
            request: FastAPI request object.
            metadata: Additional event data.
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.LOGIN_SUCCESS,
            AuditLogResult.SUCCESS,
            user_id=user_id,
            username=username,
            provider=provider,
            provider_name=provider_name,
            request=request,
            metadata=metadata,
        )

    @staticmethod
    async def log_login_failure(
        db: AsyncSession,
        username: str,
        failure_reason: str,
        provider: str = "local",
        provider_name: str | None = None,
        request: Request | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log a failed login attempt.

        Args:
            db: Database session.
            username: Username that failed to authenticate.
            failure_reason: Reason for authentication failure.
            provider: Authentication provider.
            provider_name: Human-readable provider name.
            request: FastAPI request object.
            metadata: Additional event data.
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.LOGIN_FAILURE,
            AuditLogResult.FAILURE,
            username=username,
            provider=provider,
            provider_name=provider_name,
            failure_reason=failure_reason,
            request=request,
            metadata=metadata,
        )

    @staticmethod
    async def log_oidc_login_success(
        db: AsyncSession,
        user_id: UUID,
        username: str,
        provider_name: str,
        request: Request | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log a successful OIDC login.

        Args:
            db: Database session.
            user_id: User ID.
            username: Username.
            provider_name: OIDC provider name (e.g., "Azure AD", "Google").
            request: FastAPI request object.
            metadata: Additional event data (can include OIDC claims).
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.OIDC_LOGIN_SUCCESS,
            AuditLogResult.SUCCESS,
            user_id=user_id,
            username=username,
            provider="oidc",
            provider_name=provider_name,
            request=request,
            metadata=metadata,
        )

    @staticmethod
    async def log_oidc_login_failure(
        db: AsyncSession,
        username: str | None,
        failure_reason: str,
        provider_name: str,
        request: Request | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log a failed OIDC login attempt.

        Args:
            db: Database session.
            username: Username if available (may be None for early failures).
            failure_reason: Reason for authentication failure.
            provider_name: OIDC provider name.
            request: FastAPI request object.
            metadata: Additional event data (error details, state, etc.).
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.OIDC_LOGIN_FAILURE,
            AuditLogResult.FAILURE,
            username=username,
            provider="oidc",
            provider_name=provider_name,
            failure_reason=failure_reason,
            request=request,
            metadata=metadata,
        )

    @staticmethod
    async def log_oidc_user_provisioned(
        db: AsyncSession,
        user_id: UUID,
        username: str,
        provider_name: str,
        request: Request | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log when a new user is auto-provisioned via OIDC.

        Args:
            db: Database session.
            user_id: Newly created user ID.
            username: Username (email).
            provider_name: OIDC provider name.
            request: FastAPI request object.
            metadata: Additional event data (OIDC claims, etc.).
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.OIDC_USER_PROVISIONED,
            AuditLogResult.SUCCESS,
            user_id=user_id,
            username=username,
            provider="oidc",
            provider_name=provider_name,
            request=request,
            metadata=metadata,
        )

    @staticmethod
    async def log_oidc_identity_linked(
        db: AsyncSession,
        user_id: UUID,
        username: str,
        provider_name: str,
        request: Request | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log when an OIDC identity is linked to an existing user.

        Args:
            db: Database session.
            user_id: Existing user ID.
            username: Username.
            provider_name: OIDC provider name.
            request: FastAPI request object.
            metadata: Additional event data.
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.OIDC_IDENTITY_LINKED,
            AuditLogResult.SUCCESS,
            user_id=user_id,
            username=username,
            provider="oidc",
            provider_name=provider_name,
            request=request,
            metadata=metadata,
        )

    @staticmethod
    async def log_unauthorized_access(
        db: AsyncSession,
        request: Request,
        reason: str,
        username: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log an unauthorized access attempt.

        Args:
            db: Database session.
            request: FastAPI request object.
            reason: Reason for denial (e.g., "Invalid token", "Expired session").
            username: Username if available.
            metadata: Additional event data.
        """
        await AuditService.log_event(
            db,
            AuditLogEventType.UNAUTHORIZED_ACCESS,
            AuditLogResult.FAILURE,
            username=username,
            failure_reason=reason,
            request=request,
            metadata=metadata,
        )
