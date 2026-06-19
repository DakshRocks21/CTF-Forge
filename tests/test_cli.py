"""CLI smoke tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf_forge.cli import main


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "ctf-forge" in capsys.readouterr().out


def test_init_copies_templates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_dir = tmp_path / "config"
    rc = main(["init", "--config-dir", str(config_dir)])
    assert rc == 0
    assert (config_dir / "default" / "solve.py").exists()
    assert "copied" in capsys.readouterr().out


def test_download_missing_config_returns_two(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CTFD_URL", "BASE_URL", "CTFD_TOKEN", "PERSONAL_ACCESS_TOKEN", "CTF_NAME"):
        monkeypatch.delenv(name, raising=False)
    rc = main(["download"])
    assert rc == 2
