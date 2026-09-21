from __future__ import annotations


class EtsyOAuthError(Exception):
    """Base class. Messages never contain tokens, secrets or full callback URLs."""


class CredentialsError(EtsyOAuthError):
    """API key missing or malformed."""


class NotAuthorized(EtsyOAuthError):
    """No usable token in the store; run `etsy-oauth login`."""


class CallbackError(EtsyOAuthError):
    """The redirect back from Etsy failed validation (state, path, error, code)."""


class AuthorizationExpired(CallbackError):
    """The local authorization attempt expired; start a new login."""


def safe_error_code(value: object) -> str:
    """Only print recognized protocol codes, never arbitrary upstream text."""

    known = {
        "access_denied", "invalid_request", "invalid_client", "invalid_grant",
        "unauthorized_client", "unsupported_grant_type", "unsupported_response_type",
        "invalid_scope", "invalid_token", "insufficient_scope", "server_error",
        "temporarily_unavailable", "invalid_target",
    }
    return f": {value}" if isinstance(value, str) and value in known else ""


def network_hint(exc: Exception) -> str:
    """Classify failures without copying URLs or credentials from exception text."""

    import socket
    import ssl

    reason = getattr(exc, "reason", exc)
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout; check network / HTTPS_PROXY"
    if isinstance(reason, ssl.SSLError):
        return "TLS failure; check certificates / HTTPS_PROXY"
    if isinstance(reason, socket.gaierror):
        return "DNS failure; check network / HTTPS_PROXY"
    return "connection failed; check network / HTTPS_PROXY"


class TokenEndpointError(EtsyOAuthError):
    """The token endpoint did not return a usable token."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ApiError(EtsyOAuthError):
    """An Etsy API call returned HTTP >= 400."""

    def __init__(self, status: int, body: object, headers: dict[str, str]) -> None:
        detail = safe_error_code(body.get("error")) if isinstance(body, dict) else ""
        super().__init__(f"Etsy API returned HTTP {status}{detail}")
        self.status = status
        self.body = body
        self.headers = headers


class TransportError(EtsyOAuthError):
    """Network-level failure (DNS, proxy, TLS, timeout) before any HTTP status was received."""
