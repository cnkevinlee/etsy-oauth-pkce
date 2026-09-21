"""Known Etsy Open API v3 breaking changes. Mirror of docs/api-breaking-changes.md — keep both in sync."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class BreakingChange:
    effective: date
    title: str
    impact: str
    self_check: str
    source: str


# Only entries with a dated primary source belong here. This is a curated snapshot,
# not a live monitor. Undated authentication requirements are documented separately.
LAST_REVIEWED = date(2026, 9, 22)
BREAKING_CHANGES: tuple[BreakingChange, ...] = (
    BreakingChange(
        date(2026, 7, 13),
        "Seller API Access launched",
        "Eligible sellers can request access for their own shop; commercial applications use a separate access path.",
        "Check app eligibility in Your Apps; this tool manages one token store at a time.",
        "https://github.com/etsy/open-api/discussions/1647",
    ),
)


def relevant(today: date, *, window_days: int = 365) -> tuple[BreakingChange, ...]:
    """Changes effective within the past `window_days` or still upcoming."""

    return tuple(
        change
        for change in BREAKING_CHANGES
        if change.effective >= today or (today - change.effective).days <= window_days
    )
