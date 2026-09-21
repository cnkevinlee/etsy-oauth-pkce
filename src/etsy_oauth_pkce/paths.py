from __future__ import annotations

import os
import tempfile
from pathlib import Path

HOME_ENV = "ETSY_OAUTH_HOME"


def config_dir() -> Path:
    """Per-user private directory. Override with $ETSY_OAUTH_HOME (used by tests and CI)."""

    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "etsy-oauth-pkce"


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def write_private_file(path: Path, data: str) -> None:
    """Atomic 0600 write: temp file in the same directory, then os.replace."""

    ensure_private_dir(path.parent)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(data)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
