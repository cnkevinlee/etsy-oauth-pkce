import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from etsy_oauth_pkce import callback
from etsy_oauth_pkce.errors import CallbackError
from etsy_oauth_pkce.flow import AuthorizationRequest, parse_callback


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class WaitForCallbackTests(unittest.TestCase):
    def test_rejects_bad_state_then_accepts_code(self) -> None:
        port = free_port()
        request = AuthorizationRequest.create("k", redirect_uri=f"https://localhost:{port}/cb")
        opened: list[str] = []
        result: dict[str, str] = {}

        def serve() -> None:
            result["url"] = callback.wait_for_callback(request, tls=None, open_browser=opened.append, timeout=10)

        thread = threading.Thread(target=serve)
        thread.start()
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{base}/cb?state=wrong&code=x") as response:
                    self.fail(f"unexpected {response.status}")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 400)
                exc.close()
                break
            except urllib.error.URLError:
                threading.Event().wait(0.05)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{base}/nope")
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()
        with urllib.request.urlopen(f"{base}/cb?code=abc&state={request.state}") as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"Authorization received", response.read())
        thread.join(5)
        self.assertEqual(opened, [request.url])
        self.assertEqual(parse_callback(result["url"], request), "abc")

    def test_times_out(self) -> None:
        port = free_port()
        request = AuthorizationRequest.create("k", redirect_uri=f"https://localhost:{port}/cb")
        with self.assertRaisesRegex(CallbackError, "no callback"):
            callback.wait_for_callback(request, tls=None, open_browser=None, timeout=1.5)

    def test_rejects_non_loopback_redirect(self) -> None:
        request = AuthorizationRequest.create("k", redirect_uri="https://example.com/cb")
        with self.assertRaisesRegex(CallbackError, "localhost"):
            callback.wait_for_callback(request, tls=None, open_browser=None)


class TlsFilesTests(unittest.TestCase):
    def test_create_prefers_mkcert_then_openssl(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            commands: list[list[str]] = []

            def run(command, **_kwargs):
                commands.append(command)
                Path(command[command.index("-cert-file") + 1] if "-cert-file" in command else command[command.index("-out") + 1]).write_text("cert")
                Path(command[command.index("-key-file") + 1] if "-key-file" in command else command[command.index("-keyout") + 1]).write_text("key")

                class Done:
                    returncode = 0

                return Done()

            files, method = callback.create_tls(home, which=lambda name: "/bin/" + name, run=run)
            self.assertEqual(method, "mkcert")
            self.assertEqual(files.cert.stat().st_mode & 0o777, 0o600)
            files.cert.unlink()
            files.key.unlink()
            _files, method = callback.create_tls(home, which=lambda name: "/bin/openssl" if name == "openssl" else None, run=run)
            self.assertEqual(method, "openssl-self-signed")
            self.assertIn("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1", commands[1])
            with self.assertRaisesRegex(CallbackError, "paste"):
                callback.create_tls(home, which=lambda _name: None, run=run)

    def test_import_copies_with_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            cert = home / "c.pem"
            key = home / "k.pem"
            cert.write_text("c")
            key.write_text("k")
            files = callback.import_tls(cert, key, home)
            self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            self.assertEqual(files.cert.read_text(), "c")
            self.assertEqual(files.key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(callback.find_tls(home), files)
