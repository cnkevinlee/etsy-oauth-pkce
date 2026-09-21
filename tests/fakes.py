from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message

from etsy_oauth_pkce.tokens import Token


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        message = Message()
        for key, value in (headers or {}).items():
            message[key] = value
        self.headers = message

    def read(self, _amount: int = -1) -> bytes:
        return self.body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class FakeOpener:
    """Queue of responses; HTTP >= 400 is raised as HTTPError like urllib does."""

    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.requests: list[object] = []

    def open(self, request: object, timeout: float) -> FakeResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        if response.status >= 400:
            raise urllib.error.HTTPError(
                request.full_url,  # type: ignore[attr-defined]
                response.status,
                "error",
                response.headers,
                io.BytesIO(response.body),
            )
        return response


def token_json(**overrides: object) -> bytes:
    payload = {
        "access_token": "123.access",
        "refresh_token": "123.refresh",
        "expires_in": 3600,
        "scope": "shops_r listings_r",
        "token_type": "Bearer",
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def make_token(expires_at: float = 10_000, access: str = "123.access") -> Token:
    return Token(access, "123.refresh", expires_at, ("listings_r", "shops_r"), 123)
