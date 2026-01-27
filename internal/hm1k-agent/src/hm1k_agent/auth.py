"""
Authentication and token management for HM1K Agent.

Handles:
- JWT token storage and validation
- Discovery mode registration (one-time code flow)
- Pre-shared token authentication
- Token refresh and revocation handling
"""

import secrets
import string
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import logging

import jwt

from hm1k_agent.config import Config

logger = logging.getLogger(__name__)


@dataclass
class TokenInfo:
    """Information extracted from a JWT token."""

    agent_id: str
    issued_at: datetime
    expires_at: Optional[datetime]
    is_valid: bool
    error: Optional[str] = None


@dataclass
class RegistrationResult:
    """Result of a registration attempt."""

    success: bool
    token: Optional[str] = None
    error: Optional[str] = None
    registration_code: Optional[str] = None


class AuthManager:
    """
    Manages agent authentication with the HM1K server.

    Supports two authentication modes:
    1. Discovery mode: Agent generates a one-time code, admin approves in UI
    2. Pre-shared token: Token generated in UI and passed to agent init
    """

    def __init__(self, config: Config):
        """
        Initialize auth manager.

        Args:
            config: Agent configuration
        """
        self.config = config
        self._token = config.server.token

    @property
    def token(self) -> Optional[str]:
        """Get the current authentication token."""
        return self._token

    @property
    def is_authenticated(self) -> bool:
        """Check if agent has a valid token."""
        if not self._token:
            return False

        info = self.get_token_info()
        return info.is_valid

    def get_token_info(self) -> TokenInfo:
        """
        Decode and validate the current token.

        Note: This performs local validation only. The token may still
        be revoked server-side.

        Returns:
            TokenInfo with decoded claims or error
        """
        if not self._token:
            return TokenInfo(
                agent_id="",
                issued_at=datetime.min,
                expires_at=None,
                is_valid=False,
                error="No token configured",
            )

        try:
            # Decode without verification (we don't have the server's secret)
            # Server-side validation happens on each API call
            payload = jwt.decode(self._token, options={"verify_signature": False})

            agent_id = payload.get("agent_id", payload.get("sub", ""))
            iat = payload.get("iat")
            exp = payload.get("exp")

            issued_at = datetime.fromtimestamp(iat) if iat else datetime.min
            expires_at = datetime.fromtimestamp(exp) if exp else None

            # Check expiration locally
            is_expired = expires_at and datetime.now() > expires_at

            return TokenInfo(
                agent_id=agent_id,
                issued_at=issued_at,
                expires_at=expires_at,
                is_valid=not is_expired,
                error="Token expired" if is_expired else None,
            )
        except jwt.DecodeError as e:
            return TokenInfo(
                agent_id="",
                issued_at=datetime.min,
                expires_at=None,
                is_valid=False,
                error=f"Invalid token format: {e}",
            )

    def generate_registration_code(self) -> str:
        """
        Generate a short, human-readable registration code.

        The code is used in discovery mode for server-side approval.
        Format: 6 uppercase alphanumeric characters (e.g., "ABC123")

        Returns:
            Registration code string
        """
        # Use only uppercase letters and digits for readability
        # Exclude confusing characters: 0, O, I, 1, L
        alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        code = "".join(secrets.choice(alphabet) for _ in range(6))
        return code

    async def register_discovery_mode(self, api_client: "APIClient") -> RegistrationResult:
        """
        Register agent using discovery mode.

        Flow:
        1. Generate one-time registration code
        2. Send registration request to server with agent info
        3. Server stores pending registration with code
        4. Admin enters code in HM1K UI to approve
        5. Server issues JWT token to agent
        6. Agent stores token and begins normal operation

        Args:
            api_client: API client for server communication

        Returns:
            RegistrationResult with token or error
        """
        code = self.generate_registration_code()

        logger.info(f"Starting discovery mode registration with code: {code}")

        try:
            # Send registration request
            response = await api_client.register_agent(
                agent_id=self.config.agent.id,
                agent_name=self.config.agent.name,
                agent_description=self.config.agent.description,
                registration_code=code,
            )

            if response.get("status") == "pending":
                # Registration is pending admin approval
                return RegistrationResult(
                    success=False,
                    registration_code=code,
                    error="Waiting for admin approval",
                )

            elif response.get("status") == "approved":
                # Admin pre-approved or immediately approved
                token = response.get("token")
                if token:
                    self._token = token
                    self._save_token(token)
                    return RegistrationResult(success=True, token=token)
                else:
                    return RegistrationResult(success=False, error="No token in response")

            else:
                return RegistrationResult(
                    success=False,
                    error=response.get("error", "Unknown registration status"),
                )

        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return RegistrationResult(success=False, error=str(e))

    async def poll_for_approval(
        self, api_client: "APIClient", code: str, timeout: int = 300
    ) -> RegistrationResult:
        """
        Poll server waiting for admin approval of registration.

        Args:
            api_client: API client for server communication
            code: Registration code being approved
            timeout: Max seconds to wait for approval

        Returns:
            RegistrationResult with token or timeout error
        """
        import asyncio

        start_time = datetime.now()
        poll_interval = 5  # seconds

        while (datetime.now() - start_time).total_seconds() < timeout:
            try:
                response = await api_client.check_registration_status(
                    agent_id=self.config.agent.id,
                    registration_code=code,
                )

                if response.get("status") == "approved":
                    token = response.get("token")
                    if token:
                        self._token = token
                        self._save_token(token)
                        return RegistrationResult(success=True, token=token)

                elif response.get("status") == "rejected":
                    return RegistrationResult(
                        success=False,
                        error="Registration rejected by admin",
                    )

                # Still pending, wait and retry
                await asyncio.sleep(poll_interval)

            except Exception as e:
                logger.warning(f"Poll error (will retry): {e}")
                await asyncio.sleep(poll_interval)

        return RegistrationResult(
            success=False,
            error=f"Registration timed out after {timeout} seconds",
        )

    def set_token(self, token: str) -> None:
        """
        Set authentication token (for pre-shared token mode).

        Args:
            token: JWT token from server
        """
        self._token = token
        self._save_token(token)

    def clear_token(self) -> None:
        """Clear the stored authentication token."""
        self._token = None
        # Update config file to remove token
        self.config.server.token = None
        self.config.save()

    def _save_token(self, token: str) -> None:
        """Save token to config file."""
        self.config.server.token = token
        self.config.save()
        logger.info("Token saved to config file")
