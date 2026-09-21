"""Synthetic values only; no account, proxy or external network required."""

import contextlib
import getpass
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
import warnings
from pathlib import Path
from unittest import mock

from etsy_oauth_pkce import cli
from etsy_oauth_pkce.credentials import Credentials, hidden_prompt
from etsy_oauth_pkce.errors import ApiError, AuthorizationExpired, CallbackError, EtsyOAuthError, TransportError
from etsy_oauth_pkce.flow import AuthorizationRequest, TokenEndpoint, parse_callback
from etsy_oauth_pkce.session import EtsySession
from etsy_oauth_pkce.store import FileTokenStore, MemoryTokenStore

from .fakes import FakeOpener, FakeResponse, make_token, token_json


MARKER = "SYNTHETIC_SECRET_MARKER"


class SecurityTests(unittest.TestCase):
    def test_hidden_input_never_falls_back_to_echo(self) -> None:
        def insecure_prompt(_message):
            warnings.warn("synthetic terminal failure", getpass.GetPassWarning)
            self.fail("echo fallback must not run")

        with mock.patch("getpass.getpass", insecure_prompt):
            with self.assertRaisesRegex(EtsyOAuthError, "interactive terminal"):
                hidden_prompt("fake prompt")

    def test_sensitive_reprs_and_proxy_summary(self) -> None:
        request = AuthorizationRequest(MARKER, "https://localhost:18443/cb", (), MARKER, MARKER, 1)
        for value in (Credentials(MARKER, MARKER), make_token(access=MARKER), request):
            self.assertNotIn(MARKER, repr(value))
        for url in (
            f"http://user:{MARKER}@proxy.example:8080/{MARKER}?key={MARKER}#{MARKER}",
            f"http://user:{MARKER}@[::1]:8080/",
            f"http://proxy.example:{MARKER}",
        ):
            self.assertNotIn(MARKER, cli._proxy_summary(url))
        self.assertIn("proxy.example:8080", cli._proxy_summary("http://user:pass@proxy.example:8080"))

    def test_external_errors_do_not_enter_messages(self) -> None:
        body = {"error": MARKER, "error_description": MARKER}
        error = ApiError(400, body, {"private": MARKER})
        self.assertNotIn(MARKER, str(error))
        self.assertEqual(error.body, body)  # Deliberate raw inspection remains available.
        for field in ("error", "error_description"):
            opener = FakeOpener(FakeResponse(400, json.dumps({field: MARKER}).encode()))
            with self.assertRaises(EtsyOAuthError) as ctx:
                TokenEndpoint(opener=opener).refresh("fake", "123.fake")
            self.assertNotIn(MARKER, str(ctx.exception))
        request = AuthorizationRequest.create("fake")
        url = request.redirect_uri + "?" + urllib.parse.urlencode({"state": request.state, **body})
        with self.assertRaises(CallbackError) as ctx:
            parse_callback(url, request)
        self.assertNotIn(MARKER, str(ctx.exception))

    def test_network_errors_are_classified_without_raw_text(self) -> None:
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError(f"http://user:{MARKER}@proxy.example")
        session = EtsySession(Credentials("fake", "fake"), MemoryTokenStore(make_token(10**12)), opener=opener)
        for call in (session.get_me, TokenEndpoint(opener=opener).probe):
            with self.assertRaises(EtsyOAuthError) as ctx:
                call()
            self.assertNotIn(MARKER, str(ctx.exception))
            self.assertIn("HTTPS_PROXY", str(ctx.exception))

    def test_paths_are_rejected_before_loading_token(self) -> None:
        store = mock.Mock()
        session = EtsySession(Credentials("fake", "fake"), store)
        for path in ("@other.example/x", "//other.example/x", "https://other.example/x", "", "/x#fragment", "/x\n"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                session.get(path)
        store.load.assert_not_called()

    def test_redirects_never_copy_authentication_headers(self) -> None:
        opener = FakeOpener(FakeResponse(200, b"{}"))
        session = EtsySession(Credentials("fake", MARKER), MemoryTokenStore(make_token(10**12)), opener=opener)
        session.get_me()
        first = opener.requests[0]
        self.assertIn(MARKER, first.get_header("X-api-key"))
        self.assertEqual(first.get_header("Authorization"), "Bearer 123.access")
        handler = urllib.request.HTTPRedirectHandler()
        for target in ("https://other.example/x", "https://openapi.etsy.com/next"):
            for status in (301, 302, 303, 307, 308):
                redirected = handler.redirect_request(first, None, status, "redirect", {}, target)
                self.assertIsNone(redirected.get_header("Authorization"))
                self.assertIsNone(redirected.get_header("X-api-key"))

    def test_expiry_is_enforced_on_callback_and_exchange(self) -> None:
        request = AuthorizationRequest.create("fake", clock=lambda: 100)
        url = f"{request.redirect_uri}?code=fake&state={request.state}"
        self.assertEqual(parse_callback(url, request, now=699), "fake")
        with self.assertRaises(AuthorizationExpired):
            parse_callback(url, request, now=700)
        opener = mock.Mock()
        with self.assertRaises(AuthorizationExpired):
            TokenEndpoint(opener=opener, clock=lambda: 700).exchange(request, "fake")
        opener.open.assert_not_called()

    def test_expired_paste_does_not_retry(self) -> None:
        request = AuthorizationRequest.create("fake", clock=lambda: 1)
        with mock.patch.object(cli.credentials_module, "hidden_prompt", return_value="anything") as prompt:
            with self.assertRaises(AuthorizationExpired):
                cli._paste_code(request)
            self.assertEqual(prompt.call_count, 1)

    def test_paste_interrupt_does_not_persist_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            with mock.patch.dict("os.environ", {"ETSY_API_KEY": "fake:fake"}, clear=True), \
                    mock.patch.object(cli, "TokenEndpoint") as endpoint, \
                    mock.patch.object(cli.credentials_module, "hidden_prompt", side_effect=KeyboardInterrupt), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    cli.main(["--home", str(home), "login", "--callback", "paste"])
                self.assertEqual(ctx.exception.code, 130)
                endpoint.return_value.exchange.assert_not_called()
            self.assertEqual(list(home.iterdir()), [])

    def test_unsupported_store_fails_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp, mock.patch("etsy_oauth_pkce.store.fcntl", None):
            path = Path(temp) / "new" / "token.json"
            with self.assertRaisesRegex(EtsyOAuthError, "Windows is not supported"):
                FileTokenStore(path)
            self.assertFalse(path.parent.exists())
