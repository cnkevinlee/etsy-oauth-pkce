# Etsy API compatibility notes

Last checked against primary sources: **2026-09-22**. This is a manually maintained snapshot,
not an automatic change detector. `doctor` shows the review date and dated entries from
`changes.py`; it does not query announcements or compare the current API specification.

## Current authentication baseline

The [official authentication guide](https://developer.etsy.com/documentation/essentials/authentication/)
requires `x-api-key: keystring:shared_secret` for v3 requests. Scoped endpoints also require OAuth.
The documented authorization flow uses PKCE S256 and an HTTPS redirect registered in Your Apps;
this implementation additionally validates state, sends the same redirect URI when exchanging
the code, and limits local authorization attempts to ten minutes.

The guide documents one-hour access tokens and 90-day refresh tokens. Check local expiry and
handle refresh failure instead of assuming a token will remain valid indefinitely.
These statements were verified on the date above; it is not the date the requirements changed.

## Dated announcements

| Announced | Change | Practical consequence |
|---|---|---|
| 2026-07-13 | [Seller API Access introduced](https://github.com/etsy/open-api/discussions/1647) | Eligible sellers can request access for their own shop; commercial applications use a separate access path. |

Read current quota headers using `whoami` or `RateLimit`; a quota observed on one account does
not establish another account's allowance. Undated or unverified reports about endpoint removals,
query parameters and quota changes are not included in the diagnostic timeline.
