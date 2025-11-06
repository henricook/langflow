"""Unit tests for OIDC authentication service."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.auth.oidc_service import OIDCConfig, OIDCService
from langflow.services.database.models.oidc_identity.model import OIDCIdentity
from langflow.services.database.models.user.model import User
from lfx.services.settings.auth import AuthSettings


@pytest.fixture
def mock_oidc_settings():
    """Create mock OIDC settings for testing."""
    settings = MagicMock(spec=AuthSettings)
    settings.OIDC_ENABLED = True
    settings.OIDC_CLIENT_ID = "test-client-id"
    settings.OIDC_CLIENT_SECRET = MagicMock()
    settings.OIDC_CLIENT_SECRET.get_secret_value.return_value = "test-secret"
    settings.OIDC_ISSUER_URL = "https://test-issuer.example.com"
    settings.OIDC_REDIRECT_URI = "https://langflow.example.com/api/v1/auth/oidc/callback"
    settings.OIDC_SCOPES = "openid profile email"
    settings.OIDC_PROVIDER_NAME = "Test Provider"
    settings.OIDC_AUTO_PROVISION_USERS = True
    settings.OIDC_REQUIRE_EMAIL_VERIFIED = True
    settings.OIDC_AUTHORIZATION_ENDPOINT = None
    settings.OIDC_TOKEN_ENDPOINT = None
    settings.OIDC_USERINFO_ENDPOINT = None
    settings.OIDC_JWKS_URI = None
    settings.pwd_context = MagicMock()
    settings.pwd_context.hash.return_value = "hashed_password"
    return settings


@pytest.fixture
def mock_discovery_config():
    """Create mock OIDC discovery configuration."""
    return {
        "issuer": "https://test-issuer.example.com",
        "authorization_endpoint": "https://test-issuer.example.com/authorize",
        "token_endpoint": "https://test-issuer.example.com/token",
        "userinfo_endpoint": "https://test-issuer.example.com/userinfo",
        "jwks_uri": "https://test-issuer.example.com/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


class TestOIDCConfig:
    """Tests for OIDCConfig class."""

    def test_oidc_config_initialization(self, mock_discovery_config):
        """Test OIDC config initialization from discovery document."""
        config = OIDCConfig(mock_discovery_config)

        assert config.issuer == "https://test-issuer.example.com"
        assert config.authorization_endpoint == "https://test-issuer.example.com/authorize"
        assert config.token_endpoint == "https://test-issuer.example.com/token"
        assert config.userinfo_endpoint == "https://test-issuer.example.com/userinfo"
        assert config.jwks_uri == "https://test-issuer.example.com/.well-known/jwks.json"

    def test_oidc_config_missing_required_field(self):
        """Test OIDC config raises error when required field is missing."""
        incomplete_config = {
            "issuer": "https://test-issuer.example.com",
            # Missing other required fields
        }

        with pytest.raises(KeyError):
            OIDCConfig(incomplete_config)

    def test_oidc_config_optional_fields(self):
        """Test OIDC config handles optional fields correctly."""
        minimal_config = {
            "issuer": "https://test-issuer.example.com",
            "authorization_endpoint": "https://test-issuer.example.com/authorize",
            "token_endpoint": "https://test-issuer.example.com/token",
            "jwks_uri": "https://test-issuer.example.com/.well-known/jwks.json",
            # userinfo_endpoint is optional
        }

        config = OIDCConfig(minimal_config)
        assert config.userinfo_endpoint is None
        assert config.response_types_supported == []


class TestOIDCService:
    """Tests for OIDCService class."""

    def test_oidc_service_initialization(self, mock_oidc_settings):
        """Test OIDC service initialization."""
        service = OIDCService(mock_oidc_settings)

        assert service.settings == mock_oidc_settings
        assert service._config is None
        assert service._jwks is None

    @pytest.mark.asyncio
    async def test_fetch_openid_configuration_success(self, mock_oidc_settings, mock_discovery_config):
        """Test successful OIDC discovery."""
        service = OIDCService(mock_oidc_settings)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_response = AsyncMock()
            mock_response.json.return_value = mock_discovery_config
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            config = await service._fetch_openid_configuration()

            assert isinstance(config, OIDCConfig)
            assert config.issuer == mock_discovery_config["issuer"]
            mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_openid_configuration_failure(self, mock_oidc_settings):
        """Test OIDC discovery failure."""
        service = OIDCService(mock_oidc_settings)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.side_effect = Exception("Network error")
            mock_client_class.return_value = mock_client

            with pytest.raises(HTTPException) as exc_info:
                await service._fetch_openid_configuration()

            assert exc_info.value.status_code == 500

    def test_generate_state(self, mock_oidc_settings):
        """Test state generation."""
        service = OIDCService(mock_oidc_settings)
        state = service.generate_state()

        assert isinstance(state, str)
        assert len(state) > 20  # Should be reasonably long

    def test_generate_nonce(self, mock_oidc_settings):
        """Test nonce generation."""
        service = OIDCService(mock_oidc_settings)
        nonce = service.generate_nonce()

        assert isinstance(nonce, str)
        assert len(nonce) > 20  # Should be reasonably long

    def test_generate_unique_state_and_nonce(self, mock_oidc_settings):
        """Test that state and nonce are unique."""
        service = OIDCService(mock_oidc_settings)

        state1 = service.generate_state()
        state2 = service.generate_state()
        nonce1 = service.generate_nonce()
        nonce2 = service.generate_nonce()

        assert state1 != state2
        assert nonce1 != nonce2

    @pytest.mark.asyncio
    async def test_get_authorization_url(self, mock_oidc_settings, mock_discovery_config):
        """Test authorization URL generation."""
        service = OIDCService(mock_oidc_settings)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_response = AsyncMock()
            mock_response.json.return_value = mock_discovery_config
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            state = "test-state"
            nonce = "test-nonce"

            with patch.object(service, "_get_oauth_client") as mock_oauth_client:
                mock_client_instance = MagicMock()
                mock_client_instance.create_authorization_url.return_value = (
                    "https://test-issuer.example.com/authorize?...",
                    "test-state",
                )
                mock_oauth_client.return_value = mock_client_instance

                url = await service.get_authorization_url(state, nonce)

                assert isinstance(url, str)
                assert url.startswith("https://")
                mock_client_instance.create_authorization_url.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_or_update_user_no_email(self, mock_oidc_settings):
        """Test user creation fails when email is missing."""
        service = OIDCService(mock_oidc_settings)
        db = AsyncMock(spec=AsyncSession)

        id_token_claims = {
            "sub": "12345",
            "iss": "https://test-issuer.example.com",
            # Missing email
        }

        with pytest.raises(HTTPException) as exc_info:
            await service.create_or_update_user_from_oidc(id_token_claims, {}, db)

        assert exc_info.value.status_code == 400
        assert "email" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_create_or_update_user_email_not_verified(self, mock_oidc_settings):
        """Test user creation fails when email not verified and required."""
        service = OIDCService(mock_oidc_settings)
        db = AsyncMock(spec=AsyncSession)

        id_token_claims = {
            "sub": "12345",
            "iss": "https://test-issuer.example.com",
            "email": "test@example.com",
            "email_verified": False,
        }

        with pytest.raises(HTTPException) as exc_info:
            await service.create_or_update_user_from_oidc(id_token_claims, {}, db)

        assert exc_info.value.status_code == 403
        assert "email verification" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_create_or_update_user_existing_identity(self, mock_oidc_settings):
        """Test login with existing OIDC identity."""
        service = OIDCService(mock_oidc_settings)
        db = AsyncMock(spec=AsyncSession)

        # Mock existing OIDC identity
        existing_user = User(
            id=uuid4(),
            username="test@example.com",
            password="hashed",
            is_active=True,
        )
        existing_identity = OIDCIdentity(
            id=uuid4(),
            user_id=existing_user.id,
            provider_name="Test Provider",
            provider_user_id="12345",
            issuer="https://test-issuer.example.com",
            email="test@example.com",
            email_verified=True,
        )
        existing_identity.user = existing_user

        id_token_claims = {
            "sub": "12345",
            "iss": "https://test-issuer.example.com",
            "email": "test@example.com",
            "email_verified": True,
        }

        with patch("langflow.services.database.models.oidc_identity.crud.get_oidc_identity_by_issuer_and_subject") as mock_get_identity:  # noqa: E501
            mock_get_identity.return_value = existing_identity

            with patch("langflow.services.database.models.oidc_identity.crud.update_oidc_identity"):
                with patch("langflow.services.database.models.user.crud.update_user_by_id"):
                    user = await service.create_or_update_user_from_oidc(id_token_claims, {}, db)

                    assert user == existing_user
                    mock_get_identity.assert_called_once()
