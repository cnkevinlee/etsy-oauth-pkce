from __future__ import annotations

import json
from dataclasses import dataclass, field

from .errors import TokenEndpointError


@dataclass(frozen=True)
class Token:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: float
    scopes: tuple[str, ...]
    user_id: int

    @classmethod
    def from_payload(cls, payload: object, *, now: float) -> "Token":
        """Parse the /oauth/token JSON body. Etsy access tokens are `<user_id>.<opaque>`."""

        if not isinstance(payload, dict):
            raise TokenEndpointError("token response is not a JSON object")
        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        expires_in = payload.get("expires_in")
        raw_scope = payload.get("scope", "")
        if (
            not isinstance(access_token, str)
            or not access_token
            or not isinstance(refresh_token, str)
            or not refresh_token
            or isinstance(expires_in, bool)
            or not isinstance(expires_in, (int, float))
            or float(expires_in) <= 0
            or not isinstance(raw_scope, str)
        ):
            raise TokenEndpointError("token response has missing or invalid fields")
        try:
            user_id = int(access_token.split(".", 1)[0])
        except (ValueError, IndexError):
            raise TokenEndpointError("access token lacks the numeric user_id prefix") from None
        if user_id <= 0:
            raise TokenEndpointError("access token user_id prefix is invalid")
        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=now + float(expires_in),
            scopes=tuple(sorted(set(raw_scope.split()))),
            user_id=user_id,
        )

    @classmethod
    def from_json(cls, raw: str) -> "Token":
        try:
            payload = json.loads(raw)
            token = cls(
                access_token=str(payload["access_token"]),
                refresh_token=str(payload["refresh_token"]),
                expires_at=float(payload["expires_at"]),
                scopes=tuple(sorted(set(str(item) for item in payload["scopes"]))),
                user_id=int(payload["user_id"]),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise TokenEndpointError("stored token file is invalid") from None
        if not token.access_token or not token.refresh_token or token.user_id <= 0:
            raise TokenEndpointError("stored token file is invalid")
        return token

    def to_json(self) -> str:
        return json.dumps(
            {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "expires_at": self.expires_at,
                "scopes": list(self.scopes),
                "user_id": self.user_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def expires_in(self, now: float) -> int:
        return max(0, round(self.expires_at - now))

    def is_expiring(self, now: float, margin_seconds: float) -> bool:
        return self.expires_at - now <= margin_seconds

    def status(self, now: float) -> dict[str, object]:
        """Safe-to-print summary: never includes the token strings."""

        return {
            "authorized": True,
            "user_id": self.user_id,
            "scopes": list(self.scopes),
            "expires_in_seconds": self.expires_in(now),
            "expired": self.expires_at <= now,
        }
