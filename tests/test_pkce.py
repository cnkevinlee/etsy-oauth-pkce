import base64
import hashlib
import unittest

from etsy_oauth_pkce import pkce


class PkceTests(unittest.TestCase):
    def test_verifier_is_within_rfc_range_and_urlsafe(self) -> None:
        verifier = pkce.generate_verifier()
        self.assertTrue(43 <= len(verifier) <= 128)
        self.assertRegex(verifier, r"^[A-Za-z0-9_-]+$")

    def test_challenge_is_s256_without_padding(self) -> None:
        verifier = "a" * 64
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(pkce.code_challenge(verifier), expected)
        self.assertNotIn("=", pkce.code_challenge(verifier))

    def test_state_is_random(self) -> None:
        self.assertNotEqual(pkce.generate_state(), pkce.generate_state())
