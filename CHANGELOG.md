# Changelog

## 0.1.0 — 2026-09-22

Initial public alpha release, licensed under MIT.

- OAuth Authorization Code + PKCE with state validation, local HTTPS callbacks and cross-device paste authorization.
- Local token storage with atomic private writes and POSIX locking across refresh, login completion and logout.
- CLI commands for login, status, refresh, identity, logout, TLS setup and diagnostics.
- Lightweight Python client with proactive token refresh and one retry after a 401.
- Sensitive values excluded from default object representations and diagnostic error text;
  authentication headers are not forwarded on urllib redirects.
- macOS/Linux, Python 3.11–3.14 CI, synthetic offline regression tests and distribution-content checks.

Windows file storage is not supported. Diagnostics use a manually curated compatibility snapshot,
not live monitoring. Distribution is through GitHub Releases; there is no PyPI release yet.
