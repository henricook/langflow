"""Audit log database models for security event tracking.

This module provides models for tracking authentication and security events
including login attempts, OIDC authentication, and other security-relevant actions.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

from langflow.schema.serialize import UUIDstr


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


class AuditLogEventType(str, Enum):
    """Types of audit log events.

    These event types categorize security-relevant actions in Langflow.
    """

    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_EXPIRED = "token_expired"

    # OIDC events
    OIDC_LOGIN_INITIATED = "oidc_login_initiated"
    OIDC_LOGIN_SUCCESS = "oidc_login_success"
    OIDC_LOGIN_FAILURE = "oidc_login_failure"
    OIDC_CALLBACK_RECEIVED = "oidc_callback_received"
    OIDC_USER_PROVISIONED = "oidc_user_provisioned"
    OIDC_IDENTITY_LINKED = "oidc_identity_linked"

    # API key events
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_DELETED = "api_key_deleted"
    API_KEY_INVALID = "api_key_invalid"

    # User management events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    PASSWORD_CHANGED = "password_changed"

    # Security events
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"
    INVALID_TOKEN = "invalid_token"


class AuditLogResult(str, Enum):
    """Result of an audit log event."""

    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"


class AuditLog(SQLModel, table=True):  # type: ignore[call-arg]
    """Audit log entry for security events.

    Tracks authentication, authorization, and security-relevant events
    with structured metadata for analysis and compliance.

    Attributes:
        id: Unique identifier for the audit log entry.
        event_type: Type of event (login, logout, API key usage, etc.).
        result: Whether the event succeeded, failed, or is pending.
        user_id: User ID associated with the event (if applicable).
        username: Username associated with the event (denormalized for query performance).
        ip_address: Client IP address that triggered the event.
        user_agent: Client user agent string.
        provider: Authentication provider (e.g., "local", "oidc", "api_key").
        provider_name: Human-readable provider name (e.g., "Azure AD", "Google").
        failure_reason: Reason for failure (if result is FAILURE).
        metadata: Additional structured data about the event (JSON).
        created_at: When the event occurred (immutable).
    """

    __tablename__ = "auditlog"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, unique=True)

    event_type: AuditLogEventType = Field(
        index=True,
        nullable=False,
        description="Type of security event",
    )

    result: AuditLogResult = Field(
        index=True,
        nullable=False,
        description="Whether the event succeeded or failed",
    )

    user_id: UUIDstr | None = Field(
        default=None,
        index=True,
        nullable=True,
        description="User ID if event is associated with a user",
    )

    username: str | None = Field(
        default=None,
        index=True,
        nullable=True,
        description="Username for the event (denormalized for performance)",
    )

    ip_address: str | None = Field(
        default=None,
        nullable=True,
        description="Client IP address",
    )

    user_agent: str | None = Field(
        default=None,
        nullable=True,
        description="Client user agent string",
    )

    provider: str | None = Field(
        default=None,
        index=True,
        nullable=True,
        description="Authentication provider (local, oidc, api_key, etc.)",
    )

    provider_name: str | None = Field(
        default=None,
        nullable=True,
        description="Human-readable provider name (e.g., 'Azure AD')",
    )

    failure_reason: str | None = Field(
        default=None,
        nullable=True,
        description="Reason for failure if result is FAILURE",
    )

    metadata: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Additional structured data about the event",
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        nullable=False,
        index=True,
        description="When the event occurred (immutable)",
    )


class AuditLogRead(SQLModel):
    """Read model for audit log entries.

    Used for API responses to return audit log data.
    """

    id: UUIDstr
    event_type: AuditLogEventType
    result: AuditLogResult
    user_id: UUIDstr | None
    username: str | None
    ip_address: str | None
    user_agent: str | None
    provider: str | None
    provider_name: str | None
    failure_reason: str | None
    metadata: dict[str, Any] | None
    created_at: datetime


class AuditLogCreate(SQLModel):
    """Create model for audit log entries.

    Used when creating new audit log entries programmatically.
    """

    event_type: AuditLogEventType
    result: AuditLogResult
    user_id: UUIDstr | None = None
    username: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    provider: str | None = None
    provider_name: str | None = None
    failure_reason: str | None = None
    metadata: dict[str, Any] | None = None
