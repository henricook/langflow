"""OIDC (OpenID Connect) authentication service.

This service provides generic OIDC authentication that works with any OIDC-compliant provider
including Azure AD, Google, Okta, Auth0, Keycloak, and others.
"""

import secrets
from datetime import datetime, timezone
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebKey, jwt
from authlib.oidc.core import CodeIDToken
from fastapi import HTTPException, status
from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.auth.audit_service import AuditService
from langflow.services.database.models.oidc_identity import crud as oidc_crud
from langflow.services.database.models.oidc_identity.model import OIDCIdentityCreate, OIDCIdentityUpdate
from langflow.services.database.models.user import crud as user_crud
from langflow.services.database.models.user.model import User, UserCreate
from lfx.services.settings.auth import AuthSettings


class OIDCConfig:
    """OIDC provider configuration discovered from the OIDC provider.

    This class parses and stores the OpenID Connect Discovery document
    from the provider's .well-known/openid-configuration endpoint.

    Args:
        config_data: Dictionary containing OIDC configuration from discovery endpoint.
            Must contain: issuer, authorization_endpoint, token_endpoint, jwks_uri.
            Optional: userinfo_endpoint, response_types_supported, etc.

    Attributes:
        issuer: The OIDC issuer URL that identifies the provider.
        authorization_endpoint: URL where users are redirected for authentication.
        token_endpoint: URL for exchanging authorization codes for tokens.
        userinfo_endpoint: Optional URL for fetching additional user information.
        jwks_uri: URL for retrieving JSON Web Key Set for token verification.
        response_types_supported: List of OAuth2 response types the provider supports.
        subject_types_supported: List of subject identifier types supported.
        id_token_signing_alg_values_supported: List of signing algorithms for ID tokens.

    Raises:
        KeyError: If required fields are missing from config_data.
    """

    def __init__(self, config_data: dict[str, Any]) -> None:
        """Initialize OIDC configuration from discovery document."""
        self.issuer: str = config_data["issuer"]
        self.authorization_endpoint: str = config_data["authorization_endpoint"]
        self.token_endpoint: str = config_data["token_endpoint"]
        self.userinfo_endpoint: str | None = config_data.get("userinfo_endpoint")
        self.jwks_uri: str = config_data["jwks_uri"]
        self.response_types_supported: list[str] = config_data.get("response_types_supported", [])
        self.subject_types_supported: list[str] = config_data.get("subject_types_supported", [])
        self.id_token_signing_alg_values_supported: list[str] = config_data.get(
            "id_token_signing_alg_values_supported", ["RS256"]
        )


class OIDCService:
    """Service for handling OIDC authentication flows.

    This service implements the OpenID Connect authorization code flow,
    including token validation, user provisioning, and identity linking.

    Args:
        settings: Authentication settings containing OIDC configuration.

    Attributes:
        settings: The auth settings instance.
        _config: Cached OIDC provider configuration.
        _jwks: Cached JSON Web Key Set for token validation.
    """

    def __init__(self, settings: AuthSettings) -> None:
        """Initialize OIDC service with authentication settings."""
        self.settings = settings
        self._config: OIDCConfig | None = None
        self._jwks: dict[str, Any] | None = None

    async def _fetch_openid_configuration(self) -> OIDCConfig:
        """Fetch OIDC configuration from the provider's discovery endpoint.

        Uses OIDC Discovery (https://openid.net/specs/openid-connect-discovery-1_0.html)
        to fetch provider configuration from /.well-known/openid-configuration
        """
        if self._config is not None:
            return self._config

        if not self.settings.OIDC_ISSUER_URL:
            msg = "OIDC_ISSUER_URL is not configured"
            raise ValueError(msg)

        discovery_url = f"{self.settings.OIDC_ISSUER_URL.rstrip('/')}/.well-known/openid-configuration"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url, timeout=10.0)
                response.raise_for_status()
                config_data = response.json()

            self._config = OIDCConfig(config_data)
            logger.info(f"Successfully fetched OIDC configuration from {discovery_url}")
            return self._config

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch OIDC configuration from {discovery_url}: {e}")
            msg = f"Failed to fetch OIDC configuration: {e}"
            raise HTTPException(status_code=500, detail=msg) from e

    async def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch JSON Web Key Set (JWKS) from the provider.

        JWKS contains the public keys used to verify ID token signatures.
        """
        if self._jwks is not None:
            return self._jwks

        config = await self._fetch_openid_configuration()
        jwks_uri = self.settings.OIDC_JWKS_URI or config.jwks_uri

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                self._jwks = response.json()

            logger.info(f"Successfully fetched JWKS from {jwks_uri}")
            return self._jwks

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS from {jwks_uri}: {e}")
            msg = f"Failed to fetch JWKS: {e}"
            raise HTTPException(status_code=500, detail=msg) from e

    def _get_oauth_client(self) -> AsyncOAuth2Client:
        """Create an OAuth2 client for making OIDC requests."""
        if not self.settings.OIDC_CLIENT_ID or not self.settings.OIDC_CLIENT_SECRET:
            msg = "OIDC_CLIENT_ID and OIDC_CLIENT_SECRET must be configured"
            raise ValueError(msg)

        return AsyncOAuth2Client(
            client_id=self.settings.OIDC_CLIENT_ID,
            client_secret=self.settings.OIDC_CLIENT_SECRET.get_secret_value()
            if self.settings.OIDC_CLIENT_SECRET
            else None,
            scope=self.settings.OIDC_SCOPES,
        )

    async def get_authorization_url(self, state: str, nonce: str) -> str:
        """Generate the authorization URL to redirect the user to the OIDC provider.

        Args:
            state: Random state parameter for CSRF protection
            nonce: Random nonce parameter for replay attack protection

        Returns:
            Authorization URL to redirect the user to
        """
        config = await self._fetch_openid_configuration()
        auth_endpoint = self.settings.OIDC_AUTHORIZATION_ENDPOINT or config.authorization_endpoint

        if not self.settings.OIDC_REDIRECT_URI:
            msg = "OIDC_REDIRECT_URI is not configured"
            raise ValueError(msg)

        client = self._get_oauth_client()

        # Generate authorization URL with OIDC parameters
        authorization_url, _ = client.create_authorization_url(
            auth_endpoint,
            redirect_uri=self.settings.OIDC_REDIRECT_URI,
            state=state,
            nonce=nonce,
            # OIDC requires response_type=code for authorization code flow
            response_type="code",
        )

        logger.info(f"Generated authorization URL for OIDC provider: {self.settings.OIDC_PROVIDER_NAME}")
        return authorization_url

    async def exchange_code_for_tokens(self, code: str, state: str) -> dict[str, Any]:
        """Exchange authorization code for access token and ID token.

        Args:
            code: Authorization code from the OIDC provider
            state: State parameter for validation

        Returns:
            Token response containing access_token, id_token, and other fields
        """
        config = await self._fetch_openid_configuration()
        token_endpoint = self.settings.OIDC_TOKEN_ENDPOINT or config.token_endpoint

        if not self.settings.OIDC_REDIRECT_URI:
            msg = "OIDC_REDIRECT_URI is not configured"
            raise ValueError(msg)

        client = self._get_oauth_client()

        try:
            # Exchange authorization code for tokens
            token_response = await client.fetch_token(
                token_endpoint,
                grant_type="authorization_code",
                code=code,
                redirect_uri=self.settings.OIDC_REDIRECT_URI,
            )

            logger.info("Successfully exchanged authorization code for tokens")
            return token_response

        except Exception as e:
            logger.error(f"Failed to exchange authorization code for tokens: {e}")
            msg = f"Failed to exchange authorization code: {e}"
            raise HTTPException(status_code=400, detail=msg) from e

    async def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        """Validate the ID token from the OIDC provider.

        Performs the following validations:
        - Verifies JWT signature using provider's public keys (JWKS)
        - Validates issuer (iss claim)
        - Validates audience (aud claim)
        - Validates expiration (exp claim)
        - Validates nonce for replay attack protection

        Args:
            id_token: ID token JWT from the provider
            nonce: Expected nonce value

        Returns:
            Decoded and validated ID token claims
        """
        config = await self._fetch_openid_configuration()
        jwks_data = await self._fetch_jwks()

        try:
            # Load JWKS for signature verification
            jwks = JsonWebKey.import_key_set(jwks_data)

            # Decode and validate ID token
            claims = jwt.decode(
                id_token,
                jwks,
                claims_cls=CodeIDToken,
                claims_options={
                    "iss": {"essential": True, "value": config.issuer},
                    "aud": {"essential": True, "value": self.settings.OIDC_CLIENT_ID},
                    "nonce": {"essential": True, "value": nonce},
                },
            )

            # Validate the claims
            claims.validate()

            logger.info(f"Successfully validated ID token for subject: {claims.get('sub')}")
            return dict(claims)

        except Exception as e:
            logger.error(f"Failed to validate ID token: {e}")
            msg = f"Invalid ID token: {e}"
            raise HTTPException(status_code=401, detail=msg) from e

    async def get_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch additional user information from the userinfo endpoint.

        This is optional and used to get additional user claims not included in the ID token.

        Args:
            access_token: Access token from the token response

        Returns:
            User information from the userinfo endpoint
        """
        config = await self._fetch_openid_configuration()

        if not config.userinfo_endpoint:
            # Some providers don't have a userinfo endpoint, return empty dict
            logger.debug("OIDC provider does not have a userinfo endpoint")
            return {}

        userinfo_endpoint = self.settings.OIDC_USERINFO_ENDPOINT or config.userinfo_endpoint

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10.0,
                )
                response.raise_for_status()
                userinfo = response.json()

            logger.info("Successfully fetched userinfo")
            return userinfo

        except httpx.HTTPError as e:
            logger.warning(f"Failed to fetch userinfo (non-critical): {e}")
            # Userinfo is optional, don't fail if it's not available
            return {}

    async def create_or_update_user_from_oidc(
        self, id_token_claims: dict[str, Any], userinfo: dict[str, Any], db: AsyncSession
    ) -> User:
        """Create or update a user based on OIDC claims.

        This handles user auto-provisioning and linking of OIDC identities to existing users.

        Args:
            id_token_claims: Validated claims from the ID token
            userinfo: Additional user information from userinfo endpoint
            db: Database session

        Returns:
            User object (existing or newly created)
        """
        # Extract standard OIDC claims
        provider_user_id = id_token_claims["sub"]
        issuer = id_token_claims["iss"]
        email = id_token_claims.get("email") or userinfo.get("email")
        email_verified = id_token_claims.get("email_verified", False) or userinfo.get("email_verified", False)
        name = id_token_claims.get("name") or userinfo.get("name")
        picture = id_token_claims.get("picture") or userinfo.get("picture")

        if not email:
            msg = "Email claim is required but was not provided by the OIDC provider"
            raise HTTPException(status_code=400, detail=msg)

        # Check email verification if required
        if self.settings.OIDC_REQUIRE_EMAIL_VERIFIED and not email_verified:
            msg = "Email verification is required. Please verify your email with the identity provider."
            raise HTTPException(status_code=403, detail=msg)

        # Check if OIDC identity already exists
        oidc_identity = await oidc_crud.get_oidc_identity_by_issuer_and_subject(db, issuer, provider_user_id)

        if oidc_identity:
            # Existing OIDC identity - update and return user
            logger.info(f"Found existing OIDC identity for {email}")

            # Update OIDC identity with latest information
            update_data = OIDCIdentityUpdate(
                email=email,
                email_verified=email_verified,
                name=name,
                picture=picture,
                last_login_at=datetime.now(timezone.utc),
            )
            await oidc_crud.update_oidc_identity(db, oidc_identity, update_data)

            # Update user's last login
            user = oidc_identity.user
            await user_crud.update_user_by_id(db, user.id, {"last_login_at": datetime.now(timezone.utc)})

            return user

        # Check if user with this email already exists
        existing_user = await user_crud.get_user_by_username(db, email)

        if existing_user:
            # Link OIDC identity to existing user
            logger.info(f"Linking OIDC identity to existing user: {email}")

            oidc_identity_create = OIDCIdentityCreate(
                user_id=existing_user.id,
                provider_name=self.settings.OIDC_PROVIDER_NAME or "OIDC",
                provider_user_id=provider_user_id,
                issuer=issuer,
                email=email,
                email_verified=email_verified,
                name=name,
                picture=picture,
                last_login_at=datetime.now(timezone.utc),
            )

            await oidc_crud.create_oidc_identity(db, oidc_identity_create)

            # Update user's last login
            await user_crud.update_user_by_id(db, existing_user.id, {"last_login_at": datetime.now(timezone.utc)})

            # Log identity linking event
            await AuditService.log_oidc_identity_linked(
                db=db,
                user_id=existing_user.id,
                username=email,
                provider_name=self.settings.OIDC_PROVIDER_NAME or "OIDC",
                metadata={
                    "issuer": issuer,
                    "provider_user_id": provider_user_id,
                    "email_verified": email_verified,
                },
            )

            return existing_user

        # Auto-provision new user if enabled
        if not self.settings.OIDC_AUTO_PROVISION_USERS:
            msg = (
                f"User with email {email} does not exist and auto-provisioning is disabled. "
                "Please contact your administrator."
            )
            raise HTTPException(status_code=403, detail=msg)

        logger.info(f"Auto-provisioning new user from OIDC: {email}")

        # Create new user
        # Use email as username and generate a random password (won't be used for OIDC login)
        user_create = UserCreate(
            username=email,
            password=self.settings.pwd_context.hash(secrets.token_urlsafe(32)),  # Random unused password
        )

        new_user = await user_crud.add_user(db, user_create)

        # Activate user automatically for OIDC users
        await user_crud.update_user_by_id(
            db,
            new_user.id,
            {
                "is_active": True,
                "profile_image": picture,
                "last_login_at": datetime.now(timezone.utc),
            },
        )

        # Refresh to get updated user
        await db.refresh(new_user)

        # Create OIDC identity for new user
        oidc_identity_create = OIDCIdentityCreate(
            user_id=new_user.id,
            provider_name=self.settings.OIDC_PROVIDER_NAME or "OIDC",
            provider_user_id=provider_user_id,
            issuer=issuer,
            email=email,
            email_verified=email_verified,
            name=name,
            picture=picture,
            last_login_at=datetime.now(timezone.utc),
        )

        await oidc_crud.create_oidc_identity(db, oidc_identity_create)

        # Log user provisioning event
        await AuditService.log_oidc_user_provisioned(
            db=db,
            user_id=new_user.id,
            username=email,
            provider_name=self.settings.OIDC_PROVIDER_NAME or "OIDC",
            metadata={
                "issuer": issuer,
                "provider_user_id": provider_user_id,
                "email_verified": email_verified,
                "name": name,
            },
        )

        logger.info(f"Successfully created new user from OIDC: {email}")
        return new_user

    def generate_state(self) -> str:
        """Generate a random state parameter for CSRF protection."""
        return secrets.token_urlsafe(32)

    def generate_nonce(self) -> str:
        """Generate a random nonce parameter for replay attack protection."""
        return secrets.token_urlsafe(32)
