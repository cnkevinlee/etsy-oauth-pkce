import json
import os
import tempfile
import unittest
from pathlib import Path

from etsy_oauth_pkce import credentials
from etsy_oauth_pkce.errors import CredentialsError
from etsy_oauth_pkce.store import FileTokenStore

from .fakes import make_token


class FileTokenStoreTests(unittest.TestCase):
    def test_roundtrip_is_private_and_clear_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = FileTokenStore(Path(temp) / "nested" / "token.json")
            self.assertIsNone(store.load())
            store.save(make_token())
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(store.path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.load(), make_token())
            self.assertEqual([p.name for p in store.path.parent.iterdir()], ["token.json"])
            with store.lock():
                self.assertTrue(store.lock_path.exists())
            store.clear()
            store.clear()
            self.assertIsNone(store.load())


class CredentialsTests(unittest.TestCase):
    def test_parse_requires_one_colon(self) -> None:
        for raw in ("nocolon", "a:b:c", ":b", "a:", "a b:c", "a:" + "x" * 600):
            with self.subTest(raw=raw):
                with self.assertRaises(CredentialsError):
                    credentials.parse(raw)
        parsed = credentials.parse(" key:secret\n")
        self.assertEqual(parsed.client_id, "key")
        self.assertEqual(parsed.api_key_header, "key:secret")

    def test_resolution_order_env_file_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            with self.assertRaisesRegex(CredentialsError, "no API key"):
                credentials.load(home=home, env={})
            prompted = credentials.load(home=home, env={}, prompt=lambda _m: "p:q")
            self.assertEqual(prompted.client_id, "p")
            path = credentials.save(prompted, home=home)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())["api_key"], "p:q")
            self.assertEqual(credentials.load(home=home, env={}).client_id, "p")
            self.assertEqual(credentials.load(home=home, env={"ETSY_API_KEY": "e:f"}).client_id, "e")
            path.write_text("{broken")
            with self.assertRaisesRegex(CredentialsError, "not valid JSON"):
                credentials.load(home=home, env={})
