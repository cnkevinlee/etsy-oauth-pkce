from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import urllib.parse
import webbrowser
from datetime import date
from pathlib import Path

from . import __version__, changes, credentials as credentials_module
from .callback import create_tls, ensure_tls, find_tls, import_tls, tls_dir, wait_for_callback
from .errors import ApiError, AuthorizationExpired, CallbackError, EtsyOAuthError, NotAuthorized
from .flow import ALL_SCOPES, DEFAULT_REDIRECT_URI, DEFAULT_SCOPES, AuthorizationRequest, TokenEndpoint, parse_callback
from .paths import config_dir
from .session import EtsySession
from .store import FileTokenStore

PASTE_ATTEMPTS = 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="etsy-oauth",
        description="OAuth 2.0 Authorization Code + PKCE for Etsy Seller Apps. Zero dependencies.",
    )
    parser.add_argument("--version", action="version", version=f"etsy-oauth-pkce {__version__}")
    parser.add_argument(
        "--home",
        type=Path,
        default=None,
        help="config directory (default: $ETSY_OAUTH_HOME or ~/.config/etsy-oauth-pkce)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    login = commands.add_parser("login", help="authorize this app for your own shop and store the token")
    login.add_argument("--scope", nargs="+", default=list(DEFAULT_SCOPES), metavar="SCOPE",
                       help=f"scopes to request (default: {' '.join(DEFAULT_SCOPES)}; valid: {' '.join(ALL_SCOPES)})")
    login.add_argument("--callback", choices=("local", "paste"), default="local",
                       help="local = HTTPS listener on loopback (default); paste = no listener, approve in any browser "
                            "(also on another machine) and paste the redirected URL")
    login.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI,
                       help="must match Your Apps exactly; https only")
    login.add_argument("--no-browser", action="store_true",
                       help="local mode: print the authorization URL instead of opening it (paste mode never opens one)")
    login.add_argument("--no-save-key", action="store_true", help="do not persist a prompted API key to credentials.json")

    commands.add_parser("status", help="show token owner, scopes and expiry (never prints the token)")
    commands.add_parser("refresh", help="force a refresh_token grant now")
    commands.add_parser("whoami", help="call getMe and print user_id, shop_id and rate-limit headers")
    commands.add_parser("logout", help="delete the stored token")

    tls = commands.add_parser("setup-tls", help="prepare the localhost certificate for the local callback")
    tls.add_argument("--cert", type=Path, help="import an existing certificate (PEM) instead of generating one")
    tls.add_argument("--key", type=Path, help="private key (PEM) that pairs with --cert")

    doctor = commands.add_parser("doctor", help="check credentials, token, TLS, proxy and known API breaking changes")
    doctor.add_argument("--offline", action="store_true", help="skip the live getMe call")
    return parser


def _store(home: Path | None) -> FileTokenStore:
    return FileTokenStore((home or config_dir()) / "token.json")


def _session(home: Path | None) -> EtsySession:
    return EtsySession(credentials_module.load(home=home), _store(home))


def _print_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _paste_code(request: AuthorizationRequest) -> str:
    """Re-prompt on a bad paste: the same authorization URL can be reopened, so one mistake need not restart login."""

    attempts_left = PASTE_ATTEMPTS
    while True:
        try:
            return parse_callback(credentials_module.hidden_prompt("Redirected URL (input hidden): "), request)
        except AuthorizationExpired:
            raise
        except CallbackError as exc:
            attempts_left -= 1
            if not attempts_left:
                raise
            print(f"error: {exc}; paste again ({attempts_left} left)", file=sys.stderr)


def cmd_login(args: argparse.Namespace) -> int:
    home = args.home
    store = _store(home)  # Fail before prompting or writing on unsupported platforms.
    prompted: list[bool] = []

    def prompt(message: str) -> str:
        prompted.append(True)
        return credentials_module.hidden_prompt(message)

    creds = credentials_module.load(home=home, prompt=prompt)
    if prompted and not args.no_save_key:
        path = credentials_module.save(creds, home=home)
        print(f"API key saved to {path} (mode 0600)")

    request = AuthorizationRequest.create(creds.client_id, redirect_uri=args.redirect_uri, scopes=args.scope)
    endpoint = TokenEndpoint()
    endpoint.probe()

    if args.callback == "local":
        tls = ensure_tls(home)
        print(f"Listening on {request.redirect_uri} (cert: {tls.cert})")
        if args.no_browser:
            print(f"Open this URL in your browser:\n{request.url}")
        print("Waiting up to 5 minutes for Etsy to redirect back...")
        callback_url = wait_for_callback(request, tls=tls, open_browser=None if args.no_browser else webbrowser.open)
        code = parse_callback(callback_url, request)
    else:
        # Never opens a browser here: the shop is often signed in on another machine (remote desktop, VPS).
        print(
            "Open this URL in a browser where your shop is signed in (another machine is fine):\n"
            f"{request.url}\n\n"
            f"After you click Allow, the browser goes to {request.redirect_uri}?code=... and the page fails to load.\n"
            "That is expected. Copy the full URL from the address bar and paste it here."
        )
        code = _paste_code(request)

    with store.lock():
        token = endpoint.exchange(request, code)
        store.save(token)
    print(f"Authorized user_id={token.user_id} scopes={' '.join(token.scopes)} (access token valid {token.expires_in(time.time()) // 60} min, refresh token 90 days)")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    token = _store(args.home).load()
    if token is None:
        _print_json({"authorized": False, "hint": "run `etsy-oauth login`"})
        return 1
    payload = token.status(time.time())
    payload["token_path"] = str(_store(args.home).path)
    _print_json(payload)
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    token = _session(args.home).refresh()
    _print_json(token.status(time.time()))
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    response = _session(args.home).get_me()
    _print_json({"me": response.body, "rate_limit": response.rate_limit.as_dict()})
    return 0


def cmd_logout(args: argparse.Namespace) -> int:
    store = _store(args.home)
    with store.lock():
        store.clear()
    print("Token deleted.")
    return 0


def cmd_setup_tls(args: argparse.Namespace) -> int:
    if (args.cert is None) != (args.key is None):
        print("error: --cert and --key must be given together", file=sys.stderr)
        return 2
    if args.cert is not None:
        files = import_tls(args.cert, args.key, args.home)
        method = "imported"
    elif find_tls(args.home):
        files = find_tls(args.home)
        method = "already present"
    else:
        files, method = create_tls(args.home)
    print(f"Certificate: {files.cert} ({method})")
    if method == "openssl-self-signed":
        print("Self-signed: your browser will warn once on the callback page; choose 'Advanced -> proceed'.")
        print("Install mkcert (`mkcert -install`) and rerun `setup-tls` for a warning-free certificate.")
    print(f"Register exactly this callback URL in Your Apps: {DEFAULT_REDIRECT_URI}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    home = args.home
    checks: list[dict[str, object]] = []
    failed = False

    def add(name: str, ok: bool | None, detail: str) -> None:
        nonlocal failed
        if ok is False:
            failed = True
        checks.append({"check": name, "status": {True: "ok", False: "fail", None: "info"}[ok], "detail": detail})

    add("python", sys.version_info >= (3, 11), f"{sys.version.split()[0]} (need >= 3.11)")

    creds = None
    try:
        creds = credentials_module.load(home=home)
        source = "env" if os.environ.get(credentials_module.ENV_VAR) else str(credentials_module.credentials_path(home))
        add("credentials", True, f"keystring:shared_secret present ({source})")
    except EtsyOAuthError as exc:
        add("credentials", False, str(exc))

    store = _store(home)
    token = None
    try:
        token = store.load()
    except EtsyOAuthError as exc:
        add("token", False, str(exc))
    if token is None and not any(check["check"] == "token" for check in checks):
        add("token", False, f"none at {store.path}; run `etsy-oauth login`")
    elif token is not None:
        now = time.time()
        add("token", True, f"user_id={token.user_id} scopes={' '.join(token.scopes)} expires_in={token.expires_in(now)}s"
            + (" (expired; will refresh on next call)" if token.expires_at <= now else ""))

    tls = find_tls(home)
    tools = [name for name in ("mkcert", "openssl") if shutil.which(name)]
    add("tls", None if tls else (True if tools else None),
        f"certificate at {tls.cert}" if tls else f"no certificate in {tls_dir(home)}; available generators: {', '.join(tools) or 'none (use --callback paste)'}")

    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    add("proxy", None, _proxy_summary(proxy))

    if not args.offline and creds is not None and token is not None:
        try:
            response = EtsySession(creds, store).get_me()
            body = response.body if isinstance(response.body, dict) else {}
            add("live", True, f"getMe ok user_id={body.get('user_id')} shop_id={body.get('shop_id')} rate_limit={response.rate_limit.as_dict()}")
        except ApiError as exc:
            add("live", False, str(exc))
        except EtsyOAuthError as exc:
            add("live", False, str(exc))
    elif args.offline:
        add("live", None, "skipped (--offline)")

    add("changes", None, f"curated list last reviewed {changes.LAST_REVIEWED.isoformat()}; not a live monitor")
    today = date.today()
    for change in changes.relevant(today):
        when = "upcoming" if change.effective > today else "effective"
        add(f"change {change.effective.isoformat()}", None, f"[{when}] {change.title} — {change.self_check}")

    for check in checks:
        print(f"[{check['status']:>4}] {check['check']}: {check['detail']}")
    return 1 if failed else 0


def _proxy_summary(proxy: str | None) -> str:
    if not proxy:
        return "no HTTPS_PROXY set (direct connection)"
    try:
        parsed = urllib.parse.urlsplit(proxy)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "proxy configured (unrecognized URL)"
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"HTTPS_PROXY={parsed.scheme}://{host}{port} (credentials and URL suffix omitted)"
    except ValueError:
        return "proxy configured (invalid URL)"


COMMANDS = {
    "login": cmd_login,
    "status": cmd_status,
    "refresh": cmd_refresh,
    "whoami": cmd_whoami,
    "logout": cmd_logout,
    "setup-tls": cmd_setup_tls,
    "doctor": cmd_doctor,
}


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        code = COMMANDS[args.command](args)
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except NotAuthorized as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except (EtsyOAuthError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    raise SystemExit(code)
