from __future__ import annotations

import getpass
import json
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from .errors import CredentialsError
from .paths import config_dir, write_private_file

ENV_VAR = "ETSY_API_KEY"
MAX_LENGTH = 512


@dataclass(frozen=True)
class Credentials:
    """An Etsy app's keystring + shared secret, as shown on https://www.etsy.com/developers/your-apps."""

    keystring: str = field(repr=False)
    shared_secret: str = field(repr=False)

    @property
    def api_key_header(self) -> str:
        """Value for `x-api-key` — required by the v3 authentication documentation (checked 2026-09-22)."""

        return f"{self.keystring}:{self.shared_secret}"

    @property
    def client_id(self) -> str:
        """The token endpoint only takes the keystring; the shared secret never leaves the header."""

        return self.keystring


def parse(raw: str) -> Credentials:
    value = raw.strip()
    parts = value.split(":")
    if (
        len(parts) != 2
        or not all(parts)
        or len(value) > MAX_LENGTH
        or any(character.isspace() for character in value)
    ):
        raise CredentialsError("API key must look like `keystring:shared_secret` (one colon, no spaces)")
    return Credentials(keystring=parts[0], shared_secret=parts[1])


def credentials_path(home: Path | None = None) -> Path:
    return (home or config_dir()) / "credentials.json"


def load(
    *,
    home: Path | None = None,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> Credentials:
    """Resolution order: $ETSY_API_KEY > credentials.json > interactive hidden prompt."""

    import os

    environment = os.environ if env is None else env
    raw = environment.get(ENV_VAR)
    if raw:
        return parse(raw)
    path = credentials_path(home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        payload = None
    except (OSError, json.JSONDecodeError):
        raise CredentialsError(f"{path} is not valid JSON") from None
    if isinstance(payload, dict) and isinstance(payload.get("api_key"), str):
        return parse(payload["api_key"])
    if prompt is None:
        raise CredentialsError(
            f"no API key: set {ENV_VAR}=keystring:shared_secret or run `etsy-oauth login`"
        )
    return parse(prompt("Etsy app API key (keystring:shared_secret, input hidden): "))


def hidden_prompt(message: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(message)
        except getpass.GetPassWarning:
            raise CredentialsError("hidden input is unavailable; run this command in an interactive terminal") from None


def save(credentials: Credentials, *, home: Path | None = None) -> Path:
    path = credentials_path(home)
    write_private_file(path, json.dumps({"api_key": credentials.api_key_header}) + "\n")
    return path
