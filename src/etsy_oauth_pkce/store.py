from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Iterator, Protocol

from .paths import config_dir, ensure_private_dir, write_private_file
from .tokens import Token
from .errors import EtsyOAuthError

try:  # File storage requires POSIX locking; Windows is not supported.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


class TokenStore(Protocol):
    def load(self) -> Token | None: ...

    def save(self, token: Token) -> None: ...

    def clear(self) -> None: ...

    def lock(self) -> contextlib.AbstractContextManager[None]: ...


class MemoryTokenStore:
    def __init__(self, token: Token | None = None) -> None:
        self.token = token

    def load(self) -> Token | None:
        return self.token

    def save(self, token: Token) -> None:
        self.token = token

    def clear(self) -> None:
        self.token = None

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        yield


class FileTokenStore:
    """One 0600 JSON file per store; refresh is serialised with a sibling flock file."""

    def __init__(self, path: Path | None = None) -> None:
        if fcntl is None:
            raise EtsyOAuthError("FileTokenStore requires macOS or Linux; Windows is not supported")
        self.path = (path or config_dir() / "token.json").expanduser()
        self.lock_path = self.path.with_suffix(".lock")

    def load(self) -> Token | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        return Token.from_json(raw)

    def save(self, token: Token) -> None:
        write_private_file(self.path, token.to_json() + "\n")

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        ensure_private_dir(self.lock_path.parent)
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
