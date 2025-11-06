"""OIDC authentication endpoints.

These endpoints handle the OIDC (OpenID Connect) authentication flow:
1. GET /auth/oidc/config - Returns OIDC configuration for frontend
2. GET /auth/oidc/login - Initiates OIDC login flow
3. GET /auth/oidc/callback - Handles OIDC callback after authentication
"""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import RedirectResponse
from loguru import logger
from pydantic import BaseModel

from langflow.api.utils import DbSession
from langflow.api.v1.schemas import Token
from langflow.initial_setup.setup import get_or_create_default_folder
from langflow.services.auth.oidc_service import OIDCService
from langflow.services.auth.utils import create_user_tokens
from langflow.services.deps import get_settings_service, get_variable_service

router = APIRouter(tags=["OIDC"])

# Temporary in-memory storage for state and nonce
# WARNING: This implementation uses in-memory storage which has limitations:
# - Does not work with multiple Langflow instances (load balancer/k8s replicas)
# - State is lost on server restart
# - No automatic cleanup of expired states
# TODO: For production deployments with multiple instances, implement:
# - Redis-based state storage with expiration
# - Database-backed state storage with TTL cleanup
# - Or stateless JWT-based state parameter
_oidc_state_storage: dict[str, dict[str, Any]] = {}


class OIDCConfigResponse(BaseModel):
    """OIDC configuration response for frontend."""

    enabled: bool
    provider_name: str | None
    disable_local_auth: bool


@router.get("/auth/oidc/config", response_model=OIDCConfigResponse)
async def get_oidc_config():
    """Get OIDC configuration for the frontend.

    Returns information about whether OIDC is enabled and configured.
    """
    auth_settings = get_settings_service().auth_settings

    return OIDCConfigResponse(
        enabled=auth_settings.OIDC_ENABLED,
        provider_name=auth_settings.OIDC_PROVIDER_NAME,
        disable_local_auth=auth_settings.OIDC_DISABLE_LOCAL_AUTH,
    )


@router.get("/auth/oidc/login")
async def oidc_login():
    """Initiate OIDC login flow.

    Generates an authorization URL and redirects the user to the OIDC provider.
    """
    auth_settings = get_settings_service().auth_settings

    # Check if OIDC is enabled
    if not auth_settings.OIDC_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC authentication is not enabled",
        )

    # Validate required settings
    if not all(
        [
            auth_settings.OIDC_CLIENT_ID,
            auth_settings.OIDC_CLIENT_SECRET,
            auth_settings.OIDC_ISSUER_URL,
            auth_settings.OIDC_REDIRECT_URI,
        ]
    ):
        logger.error("OIDC is enabled but not properly configured")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC is not properly configured. Please contact your administrator.",
        )

    try:
        oidc_service = OIDCService(auth_settings)

        # Generate state and nonce for CSRF and replay protection
        state = oidc_service.generate_state()
        nonce = oidc_service.generate_nonce()

        # Store state and nonce temporarily (will be validated in callback)
        _oidc_state_storage[state] = {
            "nonce": nonce,
            "timestamp": secrets.token_urlsafe(16),  # For expiration check if needed
        }

        # Generate authorization URL
        authorization_url = await oidc_service.get_authorization_url(state, nonce)

        logger.info(f"Redirecting to OIDC provider: {auth_settings.OIDC_PROVIDER_NAME}")
        return RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)

    except ValueError as e:
        logger.error(f"OIDC configuration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(f"Failed to initiate OIDC login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate OIDC login",
        ) from e


@router.get("/auth/oidc/callback")
async def oidc_callback(
    response: Response,
    db: DbSession,
    code: str = Query(..., description="Authorization code from OIDC provider"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    error: str | None = Query(None, description="Error from OIDC provider"),
    error_description: str | None = Query(None, description="Error description from OIDC provider"),
):
    """Handle OIDC callback after user authentication.

    This endpoint is called by the OIDC provider after the user authenticates.
    It exchanges the authorization code for tokens and creates/updates the user.
    """
    auth_settings = get_settings_service().auth_settings

    # Check for errors from OIDC provider
    if error:
        logger.error(f"OIDC provider returned error: {error} - {error_description}")
        # Redirect to frontend with error
        frontend_url = "/"  # TODO: Make this configurable
        error_params = urlencode({"error": error, "error_description": error_description or ""})
        return RedirectResponse(
            url=f"{frontend_url}?{error_params}",
            status_code=status.HTTP_302_FOUND,
        )

    # Validate state parameter (CSRF protection)
    if state not in _oidc_state_storage:
        logger.error("Invalid or expired state parameter")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter",
        )

    # Retrieve nonce from storage
    state_data = _oidc_state_storage.pop(state)  # Remove after use
    nonce = state_data["nonce"]

    try:
        oidc_service = OIDCService(auth_settings)

        # Exchange authorization code for tokens
        token_response = await oidc_service.exchange_code_for_tokens(code, state)

        if "id_token" not in token_response:
            msg = "OIDC provider did not return an ID token"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

        # Validate ID token
        id_token_claims = await oidc_service.validate_id_token(token_response["id_token"], nonce)

        # Optionally fetch additional user info
        userinfo = {}
        if "access_token" in token_response:
            userinfo = await oidc_service.get_userinfo(token_response["access_token"])

        # Create or update user from OIDC claims
        user = await oidc_service.create_or_update_user_from_oidc(id_token_claims, userinfo, db)

        # Generate Langflow JWT tokens
        tokens = await create_user_tokens(user_id=user.id, db=db, update_last_login=True)

        # Set cookies (same as login endpoint)
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "apikey_tkn_lflw",
            str(user.store_api_key) if user.store_api_key else "",
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )

        # Initialize user variables and default folder
        await get_variable_service().initialize_user_variables(user.id, db)
        await get_or_create_default_folder(db, user.id)

        # Redirect to frontend
        frontend_url = "/"  # TODO: Make this configurable
        logger.info(f"OIDC login successful for user: {user.username}")
        return RedirectResponse(url=frontend_url, status_code=status.HTTP_302_FOUND)

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Failed to complete OIDC callback: {e}")
        # Redirect to frontend with error
        frontend_url = "/"
        error_params = urlencode({"error": "authentication_failed", "error_description": str(e)})
        return RedirectResponse(
            url=f"{frontend_url}?{error_params}",
            status_code=status.HTTP_302_FOUND,
        )
