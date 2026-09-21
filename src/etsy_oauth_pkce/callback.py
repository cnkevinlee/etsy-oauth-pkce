from __future__ import annotations

import html
import http.server
import shutil
import ssl
import subprocess
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .errors import CallbackError
from .flow import AuthorizationRequest
from .paths import config_dir, ensure_private_dir

CALLBACK_TIMEOUT_SECONDS = 300
TLS_DIR_NAME = "tls"
CERT_NAME = "localhost.pem"
KEY_NAME = "localhost-key.pem"


@dataclass(frozen=True)
class TlsFiles:
    cert: Path
    key: Path


def tls_dir(home: Path | None = None) -> Path:
    return (home or config_dir()) / TLS_DIR_NAME


def _private_tls_dir(home: Path | None) -> Path:
    ensure_private_dir(home or config_dir())
    return ensure_private_dir(tls_dir(home))


def find_tls(home: Path | None = None) -> TlsFiles | None:
    directory = tls_dir(home)
    files = TlsFiles(directory / CERT_NAME, directory / KEY_NAME)
    return files if files.cert.is_file() and files.key.is_file() else None


def import_tls(cert: Path, key: Path, home: Path | None = None) -> TlsFiles:
    """Copy an existing cert/key pair (for example one you already made with mkcert) into the config dir."""

    directory = _private_tls_dir(home)
    target = TlsFiles(directory / CERT_NAME, directory / KEY_NAME)
    for source, destination in ((cert, target.cert), (key, target.key)):
        destination.write_bytes(Path(source).expanduser().read_bytes())
        destination.chmod(0o600)
    return target


def create_tls(
    home: Path | None = None,
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[TlsFiles, str]:
    """Prefer mkcert (browser-trusted, no warning); fall back to an openssl self-signed cert."""

    directory = _private_tls_dir(home)
    files = TlsFiles(directory / CERT_NAME, directory / KEY_NAME)
    mkcert = which("mkcert")
    openssl = which("openssl")
    if mkcert:
        command = [mkcert, "-cert-file", str(files.cert), "-key-file", str(files.key), "localhost", "127.0.0.1", "::1"]
        method = "mkcert"
    elif openssl:
        command = [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "825",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
            "-keyout", str(files.key), "-out", str(files.cert),
        ]
        method = "openssl-self-signed"
    else:
        raise CallbackError(
            "neither mkcert nor openssl found; install mkcert (recommended) or use `--callback paste`"
        )
    result = run(command, capture_output=True, text=True, check=False, timeout=60)
    if result.returncode != 0 or not files.cert.is_file() or not files.key.is_file():
        raise CallbackError(f"{method} failed to create the localhost certificate")
    files.cert.chmod(0o600)
    files.key.chmod(0o600)
    return files, method


def ensure_tls(home: Path | None = None) -> TlsFiles:
    return find_tls(home) or create_tls(home)[0]


_PAGE = """<!doctype html><meta charset="utf-8"><title>etsy-oauth-pkce</title>
<body style="font:16px system-ui;margin:3rem auto;max-width:36rem"><h2>{title}</h2><p>{body}</p></body>"""


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server_version = "etsy-oauth-pkce/0.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != server.expected_path:  # type: ignore[attr-defined]
            self.send_error(404)
            return
        values = urllib.parse.parse_qs(parsed.query)
        if values.get("state") != [server.expected_state] or (  # type: ignore[attr-defined]
            "code" not in values and "error" not in values
        ):
            self._respond(400, "Invalid callback", "The state parameter does not match this login attempt. Start `etsy-oauth login` again.")
            return
        server.received_query = parsed.query  # type: ignore[attr-defined]
        if "error" in values:
            self._respond(200, "Authorization was not granted", "Etsy reported an error; you can close this tab and check the terminal.")
        else:
            self._respond(200, "Authorization received", "You can close this tab and return to the terminal.")

    def _respond(self, status: int, title: str, body: str) -> None:
        payload = _PAGE.format(title=html.escape(title), body=html.escape(body)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return None


def wait_for_callback(
    request: AuthorizationRequest,
    *,
    tls: TlsFiles | None,
    timeout: float = CALLBACK_TIMEOUT_SECONDS,
    open_browser: Callable[[str], object] | None = webbrowser.open,
    bind_host: str = "127.0.0.1",
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """Serve the redirect_uri on loopback until Etsy sends the browser back; return the full callback URL.

    `tls=None` serves plain HTTP — only useful in tests, Etsy refuses http redirect URIs.
    """

    parsed = urllib.parse.urlsplit(request.redirect_uri)
    if parsed.hostname not in {"localhost", "127.0.0.1"} or parsed.port is None:
        raise CallbackError("local callback needs a redirect_uri like https://localhost:<port>/<path>")
    server = http.server.HTTPServer((bind_host, parsed.port), _CallbackHandler)
    server.timeout = 1.0
    server.expected_path = parsed.path  # type: ignore[attr-defined]
    server.expected_state = request.state  # type: ignore[attr-defined]
    server.received_query = None  # type: ignore[attr-defined]
    if tls is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=tls.cert, keyfile=tls.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        if open_browser is not None:
            open_browser(request.url)
        deadline = clock() + timeout
        while server.received_query is None and clock() < deadline:  # type: ignore[attr-defined]
            server.handle_request()
        query = server.received_query  # type: ignore[attr-defined]
    finally:
        server.server_close()
    if query is None:
        raise CallbackError(f"no callback within {int(timeout)} seconds")
    return f"{request.redirect_uri}?{query}"
