"""Tests for download config resolution."""
from __future__ import annotations

import argparse
from typing import Any

import pytest

from ctf_forge.config import DownloadConfig, resolve_download_config
from ctf_forge.errors import ConfigError


def _ns(**overrides: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "url": None,
        "token": None,
        "ctf_name": None,
        "output_dir": None,
        "workers": 4,
        "skip_solved": False,
        "config_dir": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_cli_args_take_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTFD_URL", "https://env.example.com")
    monkeypatch.setenv("CTFD_TOKEN", "env-token")
    monkeypatch.setenv("CTF_NAME", "env-ctf")
    cfg = resolve_download_config(_ns(url="https://cli.example.com/", token="cli", ctf_name="cli-ctf"))
    assert cfg.url == "https://cli.example.com"
    assert cfg.token == "cli"
    assert cfg.ctf_name == "cli-ctf"


def test_env_used_when_cli_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTFD_URL", "https://env.example.com")
    monkeypatch.setenv("CTFD_TOKEN", "env-token")
    monkeypatch.setenv("CTF_NAME", "env-ctf")
    cfg = resolve_download_config(_ns())
    assert cfg.url == "https://env.example.com"
    assert cfg.token == "env-token"


def test_legacy_env_vars_accepted_with_warning(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("CTFD_URL", raising=False)
    monkeypatch.delenv("CTFD_TOKEN", raising=False)
    monkeypatch.setenv("BASE_URL", "https://legacy.example.com")
    monkeypatch.setenv("PERSONAL_ACCESS_TOKEN", "legacy-token")
    monkeypatch.setenv("CTF_NAME", "legacy-ctf")
    cfg = resolve_download_config(_ns())
    err = capsys.readouterr().err
    assert "BASE_URL is deprecated" in err
    assert "PERSONAL_ACCESS_TOKEN is deprecated" in err
    assert cfg.url == "https://legacy.example.com"
    assert cfg.token == "legacy-token"


def test_missing_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CTFD_URL", "BASE_URL", "CTFD_TOKEN", "PERSONAL_ACCESS_TOKEN", "CTF_NAME"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigError, match="CTFd URL"):
        resolve_download_config(_ns(token="t", ctf_name="c"))


def test_http_timeout_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CTF_FORGE_HTTP_TIMEOUT", raising=False)
    monkeypatch.setenv("CTFD_URL", "https://x")
    monkeypatch.setenv("CTFD_TOKEN", "t")
    monkeypatch.setenv("CTF_NAME", "c")
    cfg = resolve_download_config(_ns())
    assert cfg.http_timeout == 30.0


def test_http_timeout_invalid_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTFD_URL", "https://x")
    monkeypatch.setenv("CTFD_TOKEN", "t")
    monkeypatch.setenv("CTF_NAME", "c")
    monkeypatch.setenv("CTF_FORGE_HTTP_TIMEOUT", "not-a-number")
    with pytest.raises(ConfigError, match="CTF_FORGE_HTTP_TIMEOUT"):
        resolve_download_config(_ns())


def test_returns_dataclass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTFD_URL", "https://x")
    monkeypatch.setenv("CTFD_TOKEN", "t")
    monkeypatch.setenv("CTF_NAME", "c")
    cfg = resolve_download_config(_ns(output_dir="./out", workers=8, skip_solved=True, config_dir="./tpl"))
    assert isinstance(cfg, DownloadConfig)
    assert cfg.workers == 8
    assert cfg.skip_solved is True
    assert cfg.output_dir == "./out"
    assert cfg.config_dir == "./tpl"
