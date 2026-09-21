from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping

from .credentials import Credentials
from .errors import ApiError, NotAuthorized, TransportError, network_hint
from .flow import USER_AGENT, TokenEndpoint
from .store import TokenStore
from .tokens import Token

API_BASE = "https://openapi.etsy.com"
REFRESH_MARGIN_SECONDS = 300


@dataclass(frozen=True)
class RateLimit:
    """Etsy's quota headers; use the current response, not a fixed quota assumption."""

    per_second: int | None
    remaining_this_second: int | None
    per_day: int | None
    remaining_today: int | None

    @classmethod
    def from_headers(cls, headers: Mapping[str, str]) -> "RateLimit":
        lowered = {key.lower(): value for key, value in headers.items()}

        def pick(*names: str) -> int | None:
            for name in names:
                value = lowered.get(name)
                if value is not None:
                    try:
                        return int(value)
                    except ValueError:
                        return None
            return None

        return cls(
            per_second=pick("x-limit-per-second"),
            remaining_this_second=pick("x-remaining-this-second", "x-remaining-this-secon"),
            per_day=pick("x-limit-per-day"),
            remaining_today=pick("x-remaining-today"),
        )

    def as_dict(self) -> dict[str, int | None]:
        return {
            "per_second": self.per_second,
            "remaining_this_second": self.remaining_this_second,
            "per_day": self.per_day,
            "remaining_today": self.remaining_today,
        }


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: object
    headers: dict[str, str]
    rate_limit: RateLimit


class EtsySession:
    """Authenticated requests with transparent refresh. Drop-in for any Seller App script."""

    def __init__(
        self,
        credentials: Credentials,
        store: TokenStore,
        *,
        token_endpoint: TokenEndpoint | None = None,
        opener: urllib.request.OpenerDirector | None = None,
        base_url: str = API_BASE,
        timeout: float = 30.0,
        clock: Callable[[], float] = time.time,
        refresh_margin_seconds: float = REFRESH_MARGIN_SECONDS,
        max_body_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self.credentials = credentials
        self.store = store
        self.token_endpoint = token_endpoint or TokenEndpoint(opener=opener, timeout=timeout, clock=clock)
        self.opener = opener or urllib.request.build_opener()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.clock = clock
        self.refresh_margin_seconds = refresh_margin_seconds
        self.max_body_bytes = max_body_bytes

    def token(self) -> Token:
        token = self.store.load()
        if token is None:
            raise NotAuthorized("not logged in; run `etsy-oauth login`")
        return token

    def access_token(self, *, stale: str | None = None) -> str:
        """Return a usable access token, refreshing under a lock when it is expiring or known-stale."""

        token = self.token()
        if stale is None and not token.is_expiring(self.clock(), self.refresh_margin_seconds):
            return token.access_token
        with self.store.lock():
            token = self.token()
            if token.access_token == stale or token.is_expiring(self.clock(), self.refresh_margin_seconds):
                token = self.token_endpoint.refresh(self.credentials.client_id, token.refresh_token)
                self.store.save(token)
            return token.access_token

    def refresh(self) -> Token:
        self.access_token(stale=self.token().access_token)
        return self.token()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
        json_body: object | None = None,
    ) -> ApiResponse:
        """Call `/v3/application/...`; raises ApiError on HTTP >= 400 after one refresh-and-retry on 401."""

        if not path.startswith("/") or path.startswith("//") or any(ord(c) < 33 for c in path):
            raise ValueError("API path must start with a single / and contain no whitespace or controls")
        url = f"{self.base_url}{path}"
        base, target = urllib.parse.urlsplit(self.base_url), urllib.parse.urlsplit(url)
        if (target.scheme, target.netloc) != (base.scheme, base.netloc) or target.fragment:
            raise ValueError("API path must stay on the configured origin and contain no fragment")
        if params:
            url = f"{url}?{urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})}"
        access = self.access_token()
        response = self._send(method, url, access, json_body)
        if response.status == 401:
            access = self.access_token(stale=access)
            response = self._send(method, url, access, json_body)
        if response.status >= 400:
            raise ApiError(response.status, response.body, response.headers)
        return response

    def get(self, path: str, params: Mapping[str, object] | None = None) -> ApiResponse:
        return self.request("GET", path, params=params)

    def get_me(self) -> ApiResponse:
        """`getMe` needs `shops_r`; returns {user_id, shop_id}."""

        return self.get("/v3/application/users/me")

    def _send(self, method: str, url: str, access_token: str, json_body: object | None) -> ApiResponse:
        headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        http_request = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        http_request.add_unredirected_header("x-api-key", self.credentials.api_key_header)
        http_request.add_unredirected_header("Authorization", f"Bearer {access_token}")
        try:
            with self.opener.open(http_request, timeout=self.timeout) as response:
                raw = response.read(self.max_body_bytes + 1)
                status = int(response.status)
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            raw = exc.read(self.max_body_bytes + 1)
            exc.close()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise TransportError(f"could not reach Etsy: {network_hint(exc)}") from None
        if len(raw) > self.max_body_bytes:
            raise TransportError("response exceeds the local size limit")
        body: object
        try:
            body = json.loads(raw) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = raw.decode("utf-8", errors="replace")
        return ApiResponse(status, body, response_headers, RateLimit.from_headers(response_headers))
