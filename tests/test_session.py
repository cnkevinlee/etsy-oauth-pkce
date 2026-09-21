import json
import unittest

from etsy_oauth_pkce.credentials import Credentials
from etsy_oauth_pkce.errors import ApiError, NotAuthorized
from etsy_oauth_pkce.flow import TokenEndpoint
from etsy_oauth_pkce.session import EtsySession, RateLimit
from etsy_oauth_pkce.store import MemoryTokenStore

from .fakes import FakeOpener, FakeResponse, make_token, token_json

CREDS = Credentials("keystring", "shared-secret")
ME = b'{"user_id":123,"shop_id":456}'
LIMITS = {"x-limit-per-second": "10", "x-remaining-this-second": "9", "x-limit-per-day": "10000", "x-remaining-today": "9905"}


def session(store, api: FakeOpener, token: FakeOpener | None = None, now: float = 1000.0) -> EtsySession:
    endpoint = TokenEndpoint(opener=token or FakeOpener(), clock=lambda: now)  # type: ignore[arg-type]
    return EtsySession(CREDS, store, token_endpoint=endpoint, opener=api, clock=lambda: now)  # type: ignore[arg-type]


class SessionTests(unittest.TestCase):
    def test_request_sets_both_headers_and_parses_rate_limit(self) -> None:
        api = FakeOpener(FakeResponse(200, ME, LIMITS))
        response = session(MemoryTokenStore(make_token(expires_at=10_000)), api).get_me()
        request = api.requests[0]
        self.assertEqual(request.get_header("X-api-key"), "keystring:shared-secret")  # type: ignore[attr-defined]
        self.assertEqual(request.get_header("Authorization"), "Bearer 123.access")  # type: ignore[attr-defined]
        self.assertEqual(request.full_url, "https://openapi.etsy.com/v3/application/users/me")  # type: ignore[attr-defined]
        self.assertEqual(response.body, {"user_id": 123, "shop_id": 456})
        self.assertEqual(response.rate_limit, RateLimit(10, 9, 10000, 9905))

    def test_refreshes_before_expiry_and_persists(self) -> None:
        store = MemoryTokenStore(make_token(expires_at=1100))  # within the 300 s margin
        token_opener = FakeOpener(FakeResponse(200, token_json(access_token="123.new")))
        api = FakeOpener(FakeResponse(200, ME))
        session(store, api, token_opener).get_me()
        self.assertEqual(store.token.access_token, "123.new")
        self.assertEqual(api.requests[0].get_header("Authorization"), "Bearer 123.new")  # type: ignore[attr-defined]
        body = token_opener.requests[0].data.decode()  # type: ignore[attr-defined]
        self.assertIn("grant_type=refresh_token", body)
        self.assertNotIn("shared-secret", body)

    def test_401_triggers_one_refresh_then_retry(self) -> None:
        store = MemoryTokenStore(make_token(expires_at=10_000))
        token_opener = FakeOpener(FakeResponse(200, token_json(access_token="123.new")))
        api = FakeOpener(FakeResponse(401, b'{"error":"invalid_token"}'), FakeResponse(200, ME))
        response = session(store, api, token_opener).get_me()
        self.assertEqual(response.status, 200)
        self.assertEqual(len(api.requests), 2)
        self.assertEqual(len(token_opener.requests), 1)

    def test_second_401_raises_api_error(self) -> None:
        store = MemoryTokenStore(make_token(expires_at=10_000))
        token_opener = FakeOpener(FakeResponse(200, token_json(access_token="123.new")))
        api = FakeOpener(FakeResponse(401, b"{}"), FakeResponse(401, b'{"error":"still bad"}'))
        with self.assertRaisesRegex(ApiError, "HTTP 401") as ctx:
            session(store, api, token_opener).get_me()
        self.assertEqual(ctx.exception.status, 401)

    def test_forbidden_raises_without_refresh(self) -> None:
        token_opener = FakeOpener()
        api = FakeOpener(FakeResponse(403, b'{"error":"no scope"}', LIMITS))
        with self.assertRaises(ApiError) as ctx:
            session(MemoryTokenStore(make_token(expires_at=10_000)), api, token_opener).get("/v3/application/shops/1")
        self.assertEqual(ctx.exception.headers["x-remaining-today"], "9905")
        self.assertEqual(token_opener.requests, [])

    def test_not_logged_in(self) -> None:
        with self.assertRaises(NotAuthorized):
            session(MemoryTokenStore(), FakeOpener()).get_me()

    def test_params_and_json_body(self) -> None:
        api = FakeOpener(FakeResponse(200, b"[]"))
        session(MemoryTokenStore(make_token(expires_at=10_000)), api).request(
            "put", "/v3/application/x", params={"limit": 5, "offset": None}, json_body={"a": 1}
        )
        request = api.requests[0]
        self.assertEqual(request.full_url, "https://openapi.etsy.com/v3/application/x?limit=5")  # type: ignore[attr-defined]
        self.assertEqual(request.get_method(), "PUT")  # type: ignore[attr-defined]
        self.assertEqual(json.loads(request.data), {"a": 1})  # type: ignore[attr-defined]
