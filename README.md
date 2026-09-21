# etsy-oauth-pkce

[![CI](https://github.com/cnkevinlee/etsy-oauth-pkce/actions/workflows/ci.yml/badge.svg)](https://github.com/cnkevinlee/etsy-oauth-pkce/actions/workflows/ci.yml)

A lightweight Python OAuth 2.0 + PKCE tool for the Etsy Open API v3: first login,
cross-device authorization and ongoing token management. Zero runtime dependencies.

**Supported:** macOS and Linux, Python 3.11–3.14. Windows file storage is not supported.
This is an alpha project, not an official Etsy SDK. Install the versioned wheel from
[GitHub Releases](https://github.com/cnkevinlee/etsy-oauth-pkce/releases). This package is not currently
published on PyPI:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install "https://github.com/cnkevinlee/etsy-oauth-pkce/releases/download/v0.1.0/etsy_oauth_pkce-0.1.0-py3-none-any.whl"
.venv/bin/etsy-oauth --help
```

Alternatively, install from the tagged source (requires Git):

```sh
.venv/bin/python -m pip install "git+https://github.com/cnkevinlee/etsy-oauth-pkce.git@v0.1.0"
```

## Why use it?

Existing Etsy SDKs already implement PKCE and token refresh. This package focuses on the
local setup around them: HTTPS callback setup, hidden callback pasting from another device,
private token storage, process-safe refresh and a diagnostic command. It does not implement
every Etsy endpoint or run a hosted service.

## Setup

1. Register your app in [Your Apps](https://www.etsy.com/developers/your-apps).
   [Seller API Access](https://github.com/etsy/open-api/discussions/1647) is available to eligible
   sellers for their own shop; this tool does not change Etsy's eligibility or permissions.
2. Register exactly `https://localhost:18443/oauth/callback` as the callback URL.
3. Run `etsy-oauth login --callback paste` (activate your virtual environment first).
   Enter `keystring:shared_secret` at the hidden prompt. A prompted key is saved locally;
   add `--no-save-key` to avoid saving it. An existing `ETSY_API_KEY` environment variable
   takes precedence and is not written to the credential file.

For cross-device authorization, open the printed authorization URL on the device where your
shop is signed in. Click **Allow**. The browser redirects to localhost and may fail to load;
copy that full address into the hidden prompt on the machine running this tool. No callback
server or certificate is needed in paste mode. It never opens a browser automatically.

The local attempt expires after ten minutes. Bad pastes allow three tries; an expired attempt
requires a new login. PKCE verifier and pending state stay in memory. Treat both the authorization
URL and full callback URL as private: do not put them in tickets, screenshots or shell commands.

Alternatively, when the browser is on the same machine:

```sh
etsy-oauth setup-tls
etsy-oauth login
```

TLS setup uses an existing certificate, `mkcert`, or an `openssl` self-signed certificate.
`mkcert` must have its local CA installed for browser trust; a self-signed certificate causes a
browser warning. Use paste mode if local certificate setup is inconvenient.

```sh
etsy-oauth login --scope listings_r shops_r transactions_r  # default read scopes
etsy-oauth login --no-browser                              # local callback, print URL
etsy-oauth status
etsy-oauth whoami
etsy-oauth doctor --offline
etsy-oauth doctor
etsy-oauth refresh
etsy-oauth logout                                          # local deletion, not remote revocation
```

The initial token-endpoint probe checks network reachability only; an HTTP response does not
prove that the app is approved or credentials are valid. Online commands may refresh a token.

## Use from Python

```python
from etsy_oauth_pkce import EtsySession, FileTokenStore, credentials

session = EtsySession(credentials.load(), FileTokenStore())
me = session.get_me().body
page = session.get(f"/v3/application/shops/{me['shop_id']}/listings",
                   params={"state": "active", "limit": 25})
print(page.body["count"], page.rate_limit.as_dict())
```

`request()` adds the API key and bearer token, refreshes five minutes before expiry and retries
once after a 401. API paths must start with a single `/` and stay on the configured origin.
Authentication headers are not copied to redirected requests by the standard urllib opener.
Custom openers remain supported; callers are responsible for any custom transport or redirect logic.

`TokenStore` provides `load`, `save`, `clear` and `lock`. `FileTokenStore` serializes refresh,
CLI login completion and logout with the same POSIX file lock. Its low-level `save` and `clear`
methods do not acquire the lock themselves: custom read-modify-write operations must use `lock()`.
`MemoryTokenStore` has no concurrency guarantees.

## Privacy and diagnostics

- Token and credential files are stored outside the repository, with mode 0600 inside a 0700
  directory. Writes are atomic. The default is `~/.config/etsy-oauth-pkce`; use `--home` or
  `ETSY_OAUTH_HOME` for an isolated store. Never maintain independent refresh-token copies.
- Standard `https_proxy` / `HTTPS_PROXY` and `NO_PROXY` variables are respected. The lowercase
  proxy setting takes precedence. `doctor` omits proxy userinfo, path, query and fragment.
- Built-in error messages omit arbitrary server error text, and sensitive dataclass fields are
  excluded from default `repr`. `ApiError.body` and `.headers` still expose the raw response for
  deliberate inspection; do not log or publish them without review. Explicit token serialization
  remains sensitive by design.
- `whoami`, `status` and `doctor` display account IDs, paths and operational details to the local
  user. They are **not** ready-to-share reports. Replace those values with synthetic examples before
  opening an issue. Never share tokens, API keys, authorization URLs, callback URLs or TLS private keys.
- API changes are a [manually curated snapshot](docs/api-breaking-changes.md), not live monitoring.
  Quotas come from response headers; no fixed quota is promised.

## Maintenance and contributions

The public repository is exported from the maintainer's development repository. Generic fixes
are applied and tested at that source, then exported here. Reports and pull requests are welcome;
public releases use normal commits, without importing private development history.
All bundled examples and test credentials are synthetic. Please describe reproducible failures
with synthetic inputs; do not attach real API responses.

## Development

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -t . -v
python3 -m unittest discover -s release_checks -v
```

CI tests Python 3.11–3.14 on macOS/Linux, builds wheel and source distributions, and checks their
contents before installation smoke tests. Packaging checks are heuristic plus an explicit file
allowlist; they do not replace human review of a release.

Use is subject to the [Etsy API Terms of Use](https://www.etsy.com/legal/api).
MIT licensed; no guarantee of Etsy approval or suitability for a particular business use.
