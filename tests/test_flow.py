import time
import unittest
import urllib.parse

from etsy_oauth_pkce import pkce
from etsy_oauth_pkce.errors import CallbackError, TokenEndpointError
from etsy_oauth_pkce.flow import ALL_SCOPES, AuthorizationRequest, TokenEndpoint, parse_callback

from .fakes import FakeOpener, FakeResponse, token_json


def make_request(**overrides: object) -> AuthorizationRequest:
    values = dict(
        client_id="keystring",
        redirect_uri="https://localhost:18443/oauth/callback",
        scopes=("listings_r", "shops_r"),
        state="known-state",
        verifier="v" * 64,
        created_at=time.time(),
    )
    values.update(overrides)
    return AuthorizationRequest(**values)  # type: ignore[arg-type]


class AuthorizationRequestTests(unittest.TestCase):
    def test_url_carries_pkce_state_and_scopes(self) -> None:
        request = make_request()
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["client_id"], ["keystring"])
        self.assertEqual(query["code_challenge"], [pkce.code_challenge(request.verifier)])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["state"], ["known-state"])
        self.assertEqual(query["scope"], ["listings_r shops_r"])
        self.assertEqual(query["redirect_uri"], ["https://localhost:18443/oauth/callback"])
        self.assertNotIn("verifier", request.url)

    def test_create_rejects_unknown_scope_and_http_redirect(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown scope"):
            AuthorizationRequest.create("k", scopes=["listings_r", "bogus"])
        with self.assertRaisesRegex(ValueError, "https"):
            AuthorizationRequest.create("k", redirect_uri="http://localhost:18443/cb")
        request = AuthorizationRequest.create("k", scopes=list(ALL_SCOPES), clock=lambda: 5.0)
        self.assertEqual(request.scopes, tuple(sorted(ALL_SCOPES)))
        self.assertEqual(request.created_at, 5.0)

    def test_json_roundtrip_and_expiry(self) -> None:
        request = make_request(created_at=1.0)
        restored = AuthorizationRequest.from_json(request.to_json())
        self.assertEqual(restored, request)
        self.assertFalse(restored.is_expired(now=100.0))
        self.assertTrue(restored.is_expired(now=10_000.0))
        with self.assertRaises(CallbackError):
            AuthorizationRequest.from_json("{}")


class ParseCallbackTests(unittest.TestCase):
    def test_accepts_matching_callback(self) -> None:
        request = make_request()
        self.assertEqual(
            parse_callback("https://localhost:18443/oauth/callback?code=abc&state=known-state", request),
            "abc",
        )

    def test_rejects_state_path_error_and_missing_code(self) -> None:
        request = make_request()
        cases = {
            "state": "https://localhost:18443/oauth/callback?code=abc&state=wrong",
            "redirect_uri": "https://localhost:18443/other?code=abc&state=known-state",
            "denied": "https://localhost:18443/oauth/callback?error=access_denied&state=known-state",
            "no authorization code": "https://localhost:18443/oauth/callback?state=known-state",
            "malformed": "https://localhost:18443/oauth/callback?&&state=known-state",
        }
        for expected, url in cases.items():
            with self.subTest(expected):
                with self.assertRaisesRegex(CallbackError, expected):
                    parse_callback(url, request)


class TokenEndpointTests(unittest.TestCase):
    def test_exchange_posts_client_id_and_verifier_never_secret(self) -> None:
        opener = FakeOpener(FakeResponse(200, token_json()))
        endpoint = TokenEndpoint(opener=opener, clock=lambda: 100.0)  # type: ignore[arg-type]
        token = endpoint.exchange(make_request(), "auth-code")
        body = urllib.parse.parse_qs(opener.requests[0].data.decode())  # type: ignore[attr-defined]
        self.assertEqual(body["grant_type"], ["authorization_code"])
        self.assertEqual(body["client_id"], ["keystring"])
        self.assertEqual(body["code_verifier"], ["v" * 64])
        self.assertEqual(body["code"], ["auth-code"])
        self.assertNotIn("client_secret", body)
        self.assertEqual(token.user_id, 123)
        self.assertEqual(token.expires_at, 3700.0)
        self.assertEqual(token.scopes, ("listings_r", "shops_r"))

    def test_refresh_grant(self) -> None:
        opener = FakeOpener(FakeResponse(200, token_json(access_token="123.new")))
        token = TokenEndpoint(opener=opener, clock=lambda: 0.0).refresh("keystring", "123.refresh")  # type: ignore[arg-type]
        body = urllib.parse.parse_qs(opener.requests[0].data.decode())  # type: ignore[attr-defined]
        self.assertEqual(body["grant_type"], ["refresh_token"])
        self.assertEqual(body["refresh_token"], ["123.refresh"])
        self.assertEqual(token.access_token, "123.new")

    def test_http_error_surfaces_status_and_etsy_error_but_not_body_secrets(self) -> None:
        opener = FakeOpener(FakeResponse(400, b'{"error":"invalid_grant","error_description":"code expired"}'))
        with self.assertRaisesRegex(TokenEndpointError, "HTTP 400: invalid_grant") as ctx:
            TokenEndpoint(opener=opener).exchange(make_request(), "stale")  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.status, 400)

    def test_invalid_payload_rejected(self) -> None:
        opener = FakeOpener(FakeResponse(200, b'{"access_token":"nouserid","refresh_token":"r","expires_in":60}'))
        with self.assertRaisesRegex(TokenEndpointError, "user_id"):
            TokenEndpoint(opener=opener).exchange(make_request(), "c")  # type: ignore[arg-type]
