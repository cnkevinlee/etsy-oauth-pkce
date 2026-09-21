import json
import unittest

from etsy_oauth_pkce.errors import TokenEndpointError
from etsy_oauth_pkce.tokens import Token


class TokenTests(unittest.TestCase):
    def test_from_payload_validates_fields(self) -> None:
        bad = [
            {"access_token": "", "refresh_token": "r", "expires_in": 10},
            {"access_token": "1.a", "refresh_token": "", "expires_in": 10},
            {"access_token": "1.a", "refresh_token": "r", "expires_in": 0},
            {"access_token": "1.a", "refresh_token": "r", "expires_in": True},
            {"access_token": "0.a", "refresh_token": "r", "expires_in": 10},
            [],
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                with self.assertRaises(TokenEndpointError):
                    Token.from_payload(payload, now=0)

    def test_json_roundtrip_and_status_hides_secrets(self) -> None:
        token = Token.from_payload(
            {"access_token": "77.secret", "refresh_token": "77.refresh", "expires_in": 3600, "scope": "b a"},
            now=100,
        )
        restored = Token.from_json(token.to_json())
        self.assertEqual(restored, token)
        self.assertEqual(restored.scopes, ("a", "b"))
        status = json.dumps(token.status(now=200))
        self.assertNotIn("secret", status)
        self.assertNotIn("refresh", status)
        self.assertIn('"expires_in_seconds": 3500', status)
        self.assertTrue(token.is_expiring(now=3500, margin_seconds=300))
        self.assertFalse(token.is_expiring(now=3000, margin_seconds=300))
        with self.assertRaises(TokenEndpointError):
            Token.from_json("not json")
