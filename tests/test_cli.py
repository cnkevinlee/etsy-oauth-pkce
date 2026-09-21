import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from etsy_oauth_pkce import cli
from etsy_oauth_pkce.flow import AuthorizationRequest, TokenEndpoint
from etsy_oauth_pkce.store import FileTokenStore

from .fakes import FakeOpener, FakeResponse, make_token, token_json


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main(list(argv))
        except SystemExit as exc:
            code = int(exc.code or 0)
        else:
            code = 0
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.home = Path(self._temp.name)
        self.addCleanup(self._temp.cleanup)
        environment = mock.patch.dict(os.environ, {"ETSY_OAUTH_HOME": str(self.home)}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_status_without_token_exits_1(self) -> None:
        code, out, _err = run("--home", str(self.home), "status")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["authorized"], False)

    def test_status_with_token_hides_secrets(self) -> None:
        FileTokenStore(self.home / "token.json").save(make_token(expires_at=10**12))
        code, out, _err = run("--home", str(self.home), "status")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["user_id"], 123)
        self.assertNotIn("access", out)
        code, out, _err = run("--home", str(self.home), "logout")
        self.assertEqual(code, 0)
        self.assertFalse((self.home / "token.json").exists())

    def test_login_rejects_unknown_scope_before_any_network(self) -> None:
        (self.home / "credentials.json").write_text('{"api_key":"k:s"}')
        code, _out, err = run("--home", str(self.home), "login", "--scope", "bogus", "--no-browser")
        self.assertEqual(code, 1)
        self.assertIn("unknown scope", err)

    def _paste_login(self, opener: object, *bad_pastes: str) -> tuple[int, str, str, mock.Mock, list[str]]:
        """Run `login --callback paste`; after the bad pastes, paste the redirect Etsy would really send."""

        pastes = list(bad_pastes)
        prompts: list[str] = []

        def paste(message: str) -> str:
            prompts.append(message)
            if pastes:
                return pastes.pop(0)
            self.assertFalse((self.home / "pending.json").exists())
            request = authorization
            return f"{request.redirect_uri}?code=auth-code&state={request.state}"

        authorization = AuthorizationRequest.create("keystring")
        browser = mock.Mock()
        with mock.patch.dict(os.environ, {"ETSY_API_KEY": "keystring:secret"}), \
                mock.patch.object(cli, "TokenEndpoint", lambda: TokenEndpoint(opener=opener)), \
                mock.patch.object(cli.credentials_module, "hidden_prompt", paste), \
                mock.patch.object(cli.webbrowser, "open", browser), \
                mock.patch.object(cli.AuthorizationRequest, "create", return_value=authorization):
            code, out, err = run("--home", str(self.home), "login", "--callback", "paste")
        return code, out, err, browser, prompts

    def test_paste_login_never_opens_a_local_browser_and_retries_a_bad_paste(self) -> None:
        opener = FakeOpener(FakeResponse(404, b"{}"), FakeResponse(200, token_json()))
        code, out, err, browser, prompts = self._paste_login(opener, "")
        self.assertEqual(code, 0, err)
        browser.assert_not_called()
        self.assertEqual(len(prompts), 2)
        self.assertIn("paste again (2 left)", err)
        self.assertIn("another machine is fine", out)
        self.assertIn("Authorized user_id=123", out)
        self.assertEqual(opener.requests[0].get_method(), "GET")  # type: ignore[attr-defined]
        self.assertIn(b"code=auth-code", opener.requests[1].data)  # type: ignore[attr-defined]
        self.assertFalse((self.home / "pending.json").exists())
        self.assertEqual(FileTokenStore(self.home / "token.json").load().user_id, 123)  # type: ignore[union-attr]

    def test_paste_login_gives_up_after_three_bad_pastes(self) -> None:
        opener = FakeOpener(FakeResponse(404, b"{}"))
        wrong_state = "https://localhost:18443/oauth/callback?code=x&state=stale"
        code, _out, err, _browser, prompts = self._paste_login(opener, "", "not a url", wrong_state)
        self.assertEqual(code, 1)
        self.assertEqual(len(prompts), 3)
        self.assertIn("state does not match", err)
        self.assertEqual(len(opener.requests), 1)
        self.assertFalse((self.home / "pending.json").exists())
        self.assertFalse((self.home / "token.json").exists())

    def test_login_stops_before_the_browser_when_etsy_is_unreachable(self) -> None:
        class Unreachable:
            def open(self, request: object, timeout: float) -> object:
                raise urllib.error.URLError(ConnectionResetError("reset by proxy"))

        code, out, err, _browser, prompts = self._paste_login(Unreachable())
        self.assertEqual(code, 1)
        self.assertIn("token endpoint unreachable", err)
        self.assertIn("HTTPS_PROXY", err)
        self.assertEqual(prompts, [])
        self.assertNotIn("oauth/connect", out)

    def test_whoami_without_credentials_is_a_clear_error(self) -> None:
        env = dict(os.environ)
        os.environ.pop("ETSY_API_KEY", None)
        try:
            code, _out, err = run("--home", str(self.home), "whoami")
        finally:
            os.environ.clear()
            os.environ.update(env)
        self.assertEqual(code, 1)
        self.assertIn("no API key", err)

    def test_doctor_offline_reports_failures_and_changes(self) -> None:
        code, out, _err = run("--home", str(self.home), "doctor", "--offline")
        self.assertEqual(code, 1)
        self.assertIn("[fail] credentials", out)
        self.assertIn("[fail] token", out)
        self.assertIn("[info] change 2026-07-13", out)
        self.assertIn("skipped (--offline)", out)

    def test_setup_tls_import(self) -> None:
        cert = self.home / "c.pem"
        key = self.home / "k.pem"
        cert.write_text("c")
        key.write_text("k")
        code, out, _err = run("--home", str(self.home), "setup-tls", "--cert", str(cert), "--key", str(key))
        self.assertEqual(code, 0)
        self.assertIn("imported", out)
        self.assertIn("https://localhost:18443/oauth/callback", out)
        code, _out, err = run("--home", str(self.home), "setup-tls", "--cert", str(cert))
        self.assertEqual(code, 2)
