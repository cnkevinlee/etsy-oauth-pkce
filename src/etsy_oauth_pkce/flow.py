from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from . import pkce
from .errors import AuthorizationExpired, CallbackError, TokenEndpointError, network_hint, safe_error_code
from .tokens import Token

AUTHORIZE_URL = "https://www.etsy.com/oauth/connect"
TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"
DEFAULT_REDIRECT_URI = "https://localhost:18443/oauth/callback"
USER_AGENT = "etsy-oauth-pkce/0.1"

# From the Open API v3 spec, 2026-08-06 snapshot. `profile_*` and `address_w` currently
# have zero endpoints but are still accepted by the consent screen.
ALL_SCOPES: tuple[str, ...] = (
    "address_r",
    "address_w",
    "email_r",
    "listings_d",
    "listings_r",
    "listings_w",
    "profile_r",
    "profile_w",
    "shops_r",
    "shops_w",
    "transactions_r",
    "transactions_w",
)
DEFAULT_SCOPES: tuple[str, ...] = ("listings_r", "shops_r", "transactions_r")
PENDING_TTL_SECONDS = 600


def validate_scopes(scopes: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    cleaned = tuple(sorted(set(scope.strip() for scope in scopes if scope.strip())))
    unknown = [scope for scope in cleaned if scope not in ALL_SCOPES]
    if not cleaned:
        raise ValueError("at least one scope is required")
    if unknown:
        raise ValueError(f"unknown scope(s): {' '.join(unknown)}; valid: {' '.join(ALL_SCOPES)}")
    return cleaned


def validate_redirect_uri(redirect_uri: str) -> str:
    parsed = urllib.parse.urlsplit(redirect_uri)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        raise ValueError("redirect_uri must be an https:// URL without a fragment (Etsy rejects http)")
    return redirect_uri


@dataclass(frozen=True)
class AuthorizationRequest:
    """Everything one authorization attempt needs: the PKCE verifier never leaves this process."""

    client_id: str = field(repr=False)
    redirect_uri: str
    scopes: tuple[str, ...]
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    created_at: float

    @classmethod
    def create(
        cls,
        client_id: str,
        *,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        scopes: tuple[str, ...] | list[str] = DEFAULT_SCOPES,
        clock: Callable[[], float] = time.time,
    ) -> "AuthorizationRequest":
        return cls(
            client_id=client_id,
            redirect_uri=validate_redirect_uri(redirect_uri),
            scopes=validate_scopes(scopes),
            state=pkce.generate_state(),
            verifier=pkce.generate_verifier(),
            created_at=clock(),
        )

    @property
    def url(self) -> str:
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(self.scopes),
                "client_id": self.client_id,
                "state": self.state,
                "code_challenge": pkce.code_challenge(self.verifier),
                "code_challenge_method": "S256",
            }
        )
        return f"{AUTHORIZE_URL}?{query}"

    @property
    def callback_path(self) -> str:
        return urllib.parse.urlsplit(self.redirect_uri).path

    def to_json(self) -> str:
        return json.dumps(
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scopes": list(self.scopes),
                "state": self.state,
                "verifier": self.verifier,
                "created_at": self.created_at,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str) -> "AuthorizationRequest":
        try:
            payload = json.loads(raw)
            request = cls(
                client_id=str(payload["client_id"]),
                redirect_uri=str(payload["redirect_uri"]),
                scopes=tuple(str(value) for value in payload["scopes"]),
                state=str(payload["state"]),
                verifier=str(payload["verifier"]),
                created_at=float(payload["created_at"]),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise CallbackError("pending authorization file is invalid") from None
        if not request.state or not request.verifier or not request.redirect_uri:
            raise CallbackError("pending authorization file is invalid")
        return request

    def is_expired(self, now: float) -> bool:
        return now - self.created_at >= PENDING_TTL_SECONDS


def parse_callback(url: str, request: AuthorizationRequest, *, now: float | None = None) -> str:
    """Validate the redirect Etsy sent the browser to and return the authorization code."""

    if request.is_expired(time.time() if now is None else now):
        raise AuthorizationExpired("authorization attempt expired; run `etsy-oauth login` again")
    try:
        actual = urllib.parse.urlsplit(url.strip())
    except ValueError:
        raise CallbackError("callback URL is malformed") from None
    expected = urllib.parse.urlsplit(request.redirect_uri)
    if (actual.scheme, actual.netloc, actual.path) != (expected.scheme, expected.netloc, expected.path):
        raise CallbackError("callback URL does not match the registered redirect_uri")
    try:
        values = urllib.parse.parse_qs(actual.query, strict_parsing=True)
    except ValueError:
        raise CallbackError("callback URL query string is malformed") from None
    if values.get("state") != [request.state]:
        raise CallbackError("callback state does not match this login attempt (possible CSRF or stale tab)")
    if "error" in values:
        detail = safe_error_code(values["error"][0])
        raise CallbackError(f"Etsy denied the authorization{detail}; review app settings and requested scopes")
    codes = values.get("code")
    if not codes or len(codes) != 1 or not codes[0]:
        raise CallbackError("callback URL has no authorization code")
    return codes[0]


class TokenEndpoint:
    """POST /v3/public/oauth/token. Honors HTTPS_PROXY / NO_PROXY from the environment like urllib does."""

    def __init__(
        self,
        *,
        opener: urllib.request.OpenerDirector | None = None,
        timeout: float = 30.0,
        clock: Callable[[], float] = time.time,
        max_body_bytes: int = 1024 * 1024,
    ) -> None:
        self.opener = opener or urllib.request.build_opener()
        self.timeout = timeout
        self.clock = clock
        self.max_body_bytes = max_body_bytes

    def exchange(self, request: AuthorizationRequest, code: str) -> Token:
        if request.is_expired(self.clock()):
            raise AuthorizationExpired("authorization attempt expired; run `etsy-oauth login` again")
        return self._post(
            {
                "grant_type": "authorization_code",
                "client_id": request.client_id,
                "redirect_uri": request.redirect_uri,
                "code": code,
                "code_verifier": request.verifier,
            }
        )

    def refresh(self, client_id: str, refresh_token: str) -> Token:
        return self._post(
            {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            }
        )

    def probe(self) -> None:
        """Fail before the user goes through the browser: any HTTP status proves the route to Etsy works."""

        http_request = urllib.request.Request(TOKEN_URL, method="GET", headers={"User-Agent": USER_AGENT})
        try:
            with self.opener.open(http_request, timeout=self.timeout):
                pass
        except urllib.error.HTTPError as exc:
            exc.close()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise _unreachable(exc) from None

    def _post(self, form: dict[str, str]) -> Token:
        body = urllib.parse.urlencode(form).encode("utf-8")
        http_request = urllib.request.Request(
            TOKEN_URL,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with self.opener.open(http_request, timeout=self.timeout) as response:
                raw = response.read(self.max_body_bytes + 1)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            detail = _error_detail(exc.read(self.max_body_bytes))
            exc.close()
            raise TokenEndpointError(f"token endpoint returned HTTP {status}{detail}", status) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise _unreachable(exc) from None
        if len(raw) > self.max_body_bytes:
            raise TokenEndpointError("token response exceeds the local size limit")
        if status != 200:
            raise TokenEndpointError(f"token endpoint returned HTTP {status}", status)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TokenEndpointError("token endpoint returned non-JSON body") from None
        return Token.from_payload(payload, now=self.clock())


def _unreachable(exc: Exception) -> TokenEndpointError:
    return TokenEndpointError(f"token endpoint unreachable: {network_hint(exc)}")


def _error_detail(raw: bytes) -> str:
    """Only recognized protocol codes may enter printable exception messages."""

    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return safe_error_code(payload.get("error"))
