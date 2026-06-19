"""Resolve runtime configuration from CLI args, env vars, and .env."""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from dotenv import load_dotenv

from .errors import ConfigError


@dataclass(frozen=True)
class DownloadConfig:
    url: str
    token: str
    ctf_name: str
    output_dir: str
    workers: int
    skip_solved: bool
    config_dir: str
    http_timeout: float


_DEPRECATED_ENV_ALIASES = {
    "CTFD_URL": "BASE_URL",
    "CTFD_TOKEN": "PERSONAL_ACCESS_TOKEN",
}


def _env_with_deprecation(name: str) -> str | None:
    value = os.environ.get(name)
    if value:
        return value
    legacy = _DEPRECATED_ENV_ALIASES.get(name)
    if legacy and os.environ.get(legacy):
        print(
            f"[ctf-forge] warning: {legacy} is deprecated; use {name} instead "
            "(legacy name will be removed in v0.3.0)",
            file=sys.stderr,
        )
        return os.environ[legacy]
    return None


def resolve_download_config(args: argparse.Namespace) -> DownloadConfig:
    load_dotenv()
    url = args.url or _env_with_deprecation("CTFD_URL")
    token = args.token or _env_with_deprecation("CTFD_TOKEN")
    ctf_name = args.ctf_name or os.environ.get("CTF_NAME")
    if not url:
        raise ConfigError("missing CTFd URL: pass --url or set CTFD_URL")
    if not token:
        raise ConfigError("missing CTFd token: pass --token or set CTFD_TOKEN")
    if not ctf_name:
        raise ConfigError("missing CTF name: pass --ctf-name or set CTF_NAME")
    raw_timeout = os.environ.get("CTF_FORGE_HTTP_TIMEOUT", "30")
    try:
        http_timeout = float(raw_timeout)
    except ValueError as exc:
        raise ConfigError(
            f"CTF_FORGE_HTTP_TIMEOUT must be numeric (got {raw_timeout!r})"
        ) from exc
    return DownloadConfig(
        url=url.rstrip("/"),
        token=token,
        ctf_name=ctf_name,
        output_dir=args.output_dir or ".",
        workers=args.workers,
        skip_solved=bool(args.skip_solved),
        config_dir=args.config_dir or "config",
        http_timeout=http_timeout,
    )
