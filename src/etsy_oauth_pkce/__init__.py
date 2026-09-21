"""Zero-dependency OAuth 2.0 Authorization Code + PKCE scaffold for the Etsy Open API v3."""

from .credentials import Credentials, CredentialsError
from .errors import ApiError, CallbackError, EtsyOAuthError, NotAuthorized, TokenEndpointError
from .flow import (
    ALL_SCOPES,
    DEFAULT_REDIRECT_URI,
    DEFAULT_SCOPES,
    AuthorizationRequest,
    TokenEndpoint,
    parse_callback,
)
from .session import ApiResponse, EtsySession, RateLimit
from .store import FileTokenStore, MemoryTokenStore, TokenStore
from .tokens import Token

__all__ = [
    "ALL_SCOPES",
    "DEFAULT_REDIRECT_URI",
    "DEFAULT_SCOPES",
    "ApiError",
    "ApiResponse",
    "AuthorizationRequest",
    "CallbackError",
    "Credentials",
    "CredentialsError",
    "EtsyOAuthError",
    "EtsySession",
    "FileTokenStore",
    "MemoryTokenStore",
    "NotAuthorized",
    "RateLimit",
    "Token",
    "TokenEndpoint",
    "TokenEndpointError",
    "TokenStore",
    "parse_callback",
]

__version__ = "0.1.0"
