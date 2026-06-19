# CTF-Forge v0.2.0 Public-Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship CTF-Forge v0.2.0 as a proper Python package and pre-built binary with all four known bugs fixed, real tests, and CI-driven releases.

**Architecture:** Replace the single 290-line `downloader.py` with a small `ctf_forge` package (CLI in `cli.py`, CTFd client in `ctfd.py`, workspace orchestration in `workspace.py`, template handling in `templates.py`, config in `config.py`, exceptions in `errors.py`). Distribute via PyPI/source and as PyInstaller binaries built by GitHub Actions on tag.

**Tech Stack:** Python 3.11+, `requests`, `python-dotenv`, `pytest`, `responses`, `ruff`, `mypy --strict`, `pyinstaller`, GitHub Actions.

**Spec:** [docs/superpowers/specs/2026-06-19-public-release-design.md](../specs/2026-06-19-public-release-design.md)

## Global Constraints

- Python 3.11 minimum (matches existing pyproject).
- Runtime deps: `requests>=2.31,<3`, `python-dotenv>=1,<2`. No new runtime deps.
- CLI is `argparse` (stdlib). Do not introduce `click` or `typer`.
- Every `requests` call goes through `CTFdClient` (single `Session`) with explicit timeout.
- File writes go directly to the per-challenge directory. Nothing writes to CWD.
- `safe_path_component` applied to every untrusted path component derived from CTFd data.
- Public-facing strings use `ctf-forge` (hyphenated). Python module is `ctf_forge` (underscored).
- All commits use Conventional Commits prefixes (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`).
- Working directory for every task: `/Users/dakshthapar/Dev/ctfs/tools/CTF-Forge`.

---

## File Structure (delta from current repo)

**Remove:**
- `downloader.py` (replaced by `ctf_forge/`)
- `dist/downloader`, `dist/downloader.exe` (removed from version control; rebuilt by CI)
- `requirements.txt` (replaced by `pyproject.toml`)

**Add:**
- `ctf_forge/__init__.py` — version export
- `ctf_forge/__main__.py` — `python -m ctf_forge` entry
- `ctf_forge/cli.py` — argparse, subcommand dispatch
- `ctf_forge/config.py` — CLI/env/.env merge, `DownloadConfig` dataclass
- `ctf_forge/errors.py` — `CTFForgeError`, `ConfigError`, `CTFdAPIError`, `WorkspaceError`
- `ctf_forge/ctfd.py` — `CTFdClient`, `Challenge` dataclass
- `ctf_forge/templates.py` — placeholder substitution, category fallback chain, `init_user_config`
- `ctf_forge/workspace.py` — `safe_path_component`, `setup_challenge`, `setup_all_challenges`
- `ctf_forge/default_templates/{default,pwn,web,rev,crypto,misc}/{solve.py,solution.md}`
- `tests/test_sanitize.py`
- `tests/test_templates.py`
- `tests/test_ctfd.py`
- `tests/test_workspace.py`
- `scripts/build.sh`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `LICENSE` (MIT)

**Modify:**
- `pyproject.toml` — proper package, deps, scripts, ruff, mypy
- `.gitignore` — add `dist/`, `build/`, `*.egg-info/`, `*.spec`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`
- `.example.env` — rename `BASE_URL`→`CTFD_URL`, `PERSONAL_ACCESS_TOKEN`→`CTFD_TOKEN`
- `README.md` — full rewrite (last task)

---

## Task 1: Scaffold the package and remove legacy files

**Files:**
- Create: `pyproject.toml` (replace), `LICENSE`, `ctf_forge/__init__.py`, `ctf_forge/__main__.py`
- Modify: `.gitignore`
- Delete from git: `downloader.py`, `dist/downloader`, `dist/downloader.exe`, `requirements.txt`

**Interfaces:**
- Produces: importable `ctf_forge` package; `python -m ctf_forge --help` exits 0; `ctf-forge` console script registered.

- [ ] **Step 1: Write the new `pyproject.toml`**

Replace the existing file with:

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ctf-forge"
version = "0.2.0"
description = "Forge local challenge workspaces from CTFd instances."
readme = "README.md"
requires-python = ">=3.11"
license = { file = "LICENSE" }
authors = [{ name = "Daksh Thapar" }]
keywords = ["ctf", "ctfd", "security", "cli"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
dependencies = [
    "requests>=2.31,<3",
    "python-dotenv>=1,<2",
]

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "responses>=0.25",
    "ruff>=0.5",
    "mypy>=1.10",
    "pyinstaller>=6",
    "types-requests",
]

[project.scripts]
ctf-forge = "ctf_forge.cli:main"

[tool.setuptools.packages.find]
include = ["ctf_forge*"]

[tool.setuptools.package-data]
ctf_forge = ["default_templates/**/*"]

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM"]

[tool.mypy]
python_version = "3.11"
strict = true
files = ["ctf_forge"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Write `LICENSE` (MIT, 2026)**

```
MIT License

Copyright (c) 2026 Daksh Thapar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: Replace `.gitignore`**

```
# Build artefacts
dist/
build/
*.egg-info/
*.spec

# Python
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage

# Virtualenvs
.venv/
venv/
env/

# Secrets and local config
.env
!.example.env

# OS
.DS_Store
Thumbs.db
```

- [ ] **Step 4: Create `ctf_forge/__init__.py`**

```python
"""CTF-Forge: scaffold local CTFd challenge workspaces from templates."""
__version__ = "0.2.0"
```

- [ ] **Step 5: Create `ctf_forge/__main__.py`**

```python
from ctf_forge.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Create a minimal `ctf_forge/cli.py` stub**

This lets the package install before later tasks add real subcommands.

```python
"""CLI entry point. Real subcommands are wired up in later tasks."""
from __future__ import annotations

import argparse


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-forge",
        description="Forge local challenge workspaces from CTFd instances.",
    )
    parser.add_argument("--version", action="version", version="ctf-forge 0.2.0")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("download", help="Download CTFd challenges and apply templates")
    sub.add_parser("init", help="Copy bundled templates to config dir")
    sub.add_parser("install", help="Print PATH instructions for the binary")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    parser.exit(0, f"command '{args.command}' is not implemented yet\n")
    return 0
```

- [ ] **Step 7: Remove legacy files from git tracking**

```bash
git rm downloader.py dist/downloader dist/downloader.exe requirements.txt
rmdir dist 2>/dev/null || true
```

- [ ] **Step 8: Install and verify**

```bash
pip install -e '.[dev]'
python -m ctf_forge --version
python -m ctf_forge download
ctf-forge --version
```

Expected: `--version` prints `ctf-forge 0.2.0`. `download` prints "command 'download' is not implemented yet" and exits 0.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore: scaffold ctf_forge package and drop legacy downloader

Remove single-file downloader.py and checked-in binaries. Introduce
proper pyproject.toml, console script entry, LICENSE, and an importable
ctf_forge package with a CLI stub. Subcommands land in later commits."
```

---

## Task 2: Errors module

**Files:**
- Create: `ctf_forge/errors.py`

**Interfaces:**
- Produces: `CTFForgeError` (base), `ConfigError`, `CTFdAPIError(status, url, body_snippet)`, `WorkspaceError(challenge_id, slug, cause)`. Later tasks raise these.

- [ ] **Step 1: Create `ctf_forge/errors.py`**

```python
"""Exception types for CTF-Forge."""
from __future__ import annotations


class CTFForgeError(Exception):
    """Base exception for all CTF-Forge errors."""


class ConfigError(CTFForgeError):
    """Missing or invalid user configuration."""


class CTFdAPIError(CTFForgeError):
    """HTTP error returned by the CTFd API."""

    def __init__(self, status: int, url: str, body_snippet: str) -> None:
        super().__init__(f"CTFd API {status} at {url}: {body_snippet[:200]}")
        self.status = status
        self.url = url
        self.body_snippet = body_snippet


class WorkspaceError(CTFForgeError):
    """Error while setting up a challenge workspace."""

    def __init__(self, challenge_id: int, slug: str, cause: str) -> None:
        super().__init__(f"workspace error for {slug} (id {challenge_id}): {cause}")
        self.challenge_id = challenge_id
        self.slug = slug
        self.cause = cause
```

- [ ] **Step 2: Verify it imports**

```bash
python -c "from ctf_forge.errors import CTFForgeError, ConfigError, CTFdAPIError, WorkspaceError"
```

Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add ctf_forge/errors.py
git commit -m "feat: add typed error hierarchy"
```

---

## Task 3: `safe_path_component` with tests

**Files:**
- Create: `ctf_forge/workspace.py` (initial — only the sanitizer)
- Create: `tests/__init__.py`, `tests/test_sanitize.py`

**Interfaces:**
- Produces: `safe_path_component(name: str, fallback_id: int | None = None) -> str`

- [ ] **Step 1: Write the failing test (`tests/test_sanitize.py`)**

```python
"""Tests for the path-component sanitizer."""
from __future__ import annotations

import pytest

from ctf_forge.workspace import safe_path_component


@pytest.mark.parametrize(
    "name,fallback,expected",
    [
        ("simple", None, "simple"),
        ("with spaces", None, "with_spaces"),
        ("multi   spaces", None, "multi_spaces"),
        ("../etc/passwd", None, "_._etc_passwd"),
        ("./hidden", None, "_._hidden"),
        ("/leading/slash", None, "_leading_slash"),
        (".", 7, "challenge-7"),
        ("..", 7, "challenge-7"),
        ("", 7, "challenge-7"),
        ("", None, "challenge"),
        ("a" * 200, None, "a" * 80),
        ("héllo wörld", None, "héllo_wörld"),
        ("name\twith\ttabs", None, "name_with_tabs"),
        ("name\nwith\nnewlines", None, "name_with_newlines"),
        ("dotted.name.ok", None, "dotted.name.ok"),
        ("with(parens)", None, "with_parens_"),
    ],
)
def test_sanitization(name: str, fallback: int | None, expected: str) -> None:
    assert safe_path_component(name, fallback_id=fallback) == expected
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
pytest tests/test_sanitize.py -v
```

Expected: collection error or import error (`workspace` module / `safe_path_component` missing).

- [ ] **Step 3: Create `ctf_forge/workspace.py` with the sanitizer**

```python
"""Workspace orchestration: directory layout, sanitization, file writes.

This module will grow in later tasks. For now it only exports the
path-component sanitizer.
"""
from __future__ import annotations

import re

_UNSAFE_PATTERN = re.compile(r"[^\w\-. ]", re.UNICODE)
_WHITESPACE_RUN = re.compile(r"\s+", re.UNICODE)
_MAX_LEN = 80


def safe_path_component(name: str, fallback_id: int | None = None) -> str:
    """Return a string safe to use as a single path component.

    - Replaces characters outside ``[\\w\\-. ]`` with ``_``.
    - Collapses whitespace runs into single ``_``.
    - Rejects ``.`` and ``..``.
    - Truncates to 80 characters.
    - Returns ``challenge-{fallback_id}`` (or ``challenge``) when the
      result is empty or equal to ``.``/``..``.
    """
    if not isinstance(name, str):
        name = ""
    replaced = _UNSAFE_PATTERN.sub("_", name)
    collapsed = _WHITESPACE_RUN.sub("_", replaced)
    if collapsed in ("", ".", ".."):
        return f"challenge-{fallback_id}" if fallback_id is not None else "challenge"
    return collapsed[:_MAX_LEN]
```

- [ ] **Step 4: Create `tests/__init__.py`** (empty file so pytest collects from the package).

```bash
: > tests/__init__.py
```

- [ ] **Step 5: Run the tests, confirm they pass**

```bash
pytest tests/test_sanitize.py -v
```

Expected: all parametrized cases pass.

- [ ] **Step 6: Commit**

```bash
git add ctf_forge/workspace.py tests/__init__.py tests/test_sanitize.py
git commit -m "feat: add safe_path_component sanitizer with parametrized tests"
```

---

## Task 4: Config loading

**Files:**
- Create: `ctf_forge/config.py`
- Create: `tests/test_config.py`
- Modify: `.example.env`

**Interfaces:**
- Consumes: `argparse.Namespace` from the `download` subcommand.
- Produces: `DownloadConfig` dataclass with fields `url, token, ctf_name, output_dir, workers, skip_solved, config_dir, http_timeout`. Function `resolve_download_config(args) -> DownloadConfig`. Raises `ConfigError`.

- [ ] **Step 1: Write the failing tests**

`tests/test_config.py`:

```python
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
```

- [ ] **Step 2: Run the tests, confirm they fail**

```bash
pytest tests/test_config.py -v
```

Expected: ImportError (`ctf_forge.config` doesn't exist).

- [ ] **Step 3: Create `ctf_forge/config.py`**

```python
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
```

- [ ] **Step 4: Update `.example.env`**

Replace contents with:

```
CTFD_URL=""
CTFD_TOKEN=""
CTF_NAME=""

# Optional: HTTP read timeout in seconds (default 30).
# CTF_FORGE_HTTP_TIMEOUT=30
```

- [ ] **Step 5: Run the tests, confirm they pass**

```bash
pytest tests/test_config.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 6: Commit**

```bash
git add ctf_forge/config.py tests/test_config.py .example.env
git commit -m "feat: resolve config from CLI args, env vars, and .env

CLI flags override env vars override .env. Legacy BASE_URL and
PERSONAL_ACCESS_TOKEN are accepted with a deprecation warning printed
to stderr; removal scheduled for v0.3.0. HTTP timeout is configurable
via CTF_FORGE_HTTP_TIMEOUT."
```

---

## Task 5: CTFd client with timeouts and parallel detail fetch

**Files:**
- Create: `ctf_forge/ctfd.py`
- Create: `tests/test_ctfd.py`

**Interfaces:**
- Produces:
  - `Challenge` dataclass: `id: int`, `name: str`, `description: str`, `category: str`, `connection_info: str`, `files: list[str]`, `tags: list[Any]`, `hints: list[Any]`, `solved: bool`.
  - `CTFdClient(base_url, token, read_timeout=30.0)` with methods `list_challenges() -> list[dict]`, `get_challenge_detail(id) -> dict`, `get_challenges(workers=4) -> list[Challenge]`, `download_file(file_url, dest_dir) -> Path`.
  - All HTTP calls raise `CTFdAPIError` on non-200.

- [ ] **Step 1: Write the failing tests**

`tests/test_ctfd.py`:

```python
"""Tests for the CTFd HTTP client."""
from __future__ import annotations

from pathlib import Path

import pytest
import responses

from ctf_forge.ctfd import Challenge, CTFdClient
from ctf_forge.errors import CTFdAPIError


@pytest.fixture
def mocked_responses() -> responses.RequestsMock:
    with responses.RequestsMock() as rsps:
        yield rsps


def test_list_challenges_returns_data(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        json={"data": [{"id": 1, "name": "intro", "solved_by_me": False}]},
        status=200,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    assert client.list_challenges() == [{"id": 1, "name": "intro", "solved_by_me": False}]


def test_list_challenges_non_200_raises(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        body="forbidden",
        status=403,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    with pytest.raises(CTFdAPIError) as excinfo:
        client.list_challenges()
    assert excinfo.value.status == 403


def test_get_challenges_aggregates_detail_calls(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        json={"data": [
            {"id": 1, "solved_by_me": False},
            {"id": 2, "solved_by_me": True},
        ]},
        status=200,
    )
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges/1",
        json={"data": {
            "id": 1, "name": "Intro", "description": "<p>hi</p>",
            "category": "misc", "connection_info": "",
            "files": ["/files/abc/flag.txt"], "tags": [], "hints": [],
        }},
        status=200,
    )
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges/2",
        json={"data": {
            "id": 2, "name": "Pwn it", "description": "boom",
            "category": "pwn", "connection_info": "nc host 1337",
            "files": [], "tags": [{"value": "easy"}], "hints": [{"content": "hint"}],
        }},
        status=200,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    challenges = client.get_challenges(workers=2)
    assert {c.id for c in challenges} == {1, 2}
    by_id = {c.id: c for c in challenges}
    assert by_id[1].solved is False
    assert by_id[2].solved is True
    assert by_id[2].connection_info == "nc host 1337"
    assert by_id[2].hints == [{"content": "hint"}]


def test_download_file_writes_to_dest_dir(tmp_path: Path, mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/files/abc/flag.txt",
        body=b"FLAG{x}",
        status=200,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    target = client.download_file("/files/abc/flag.txt?token=xyz", tmp_path)
    assert target == tmp_path / "flag.txt"
    assert target.read_bytes() == b"FLAG{x}"


def test_download_file_rejects_unsafe_basename(tmp_path: Path) -> None:
    client = CTFdClient("https://ctf.example.com", "tok")
    with pytest.raises(CTFdAPIError):
        client.download_file("/files/abc/..", tmp_path)


def test_session_carries_token_header(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        json={"data": []},
        status=200,
        match=[responses.matchers.header_matcher({"Authorization": "Token sekret"})],
    )
    client = CTFdClient("https://ctf.example.com", "sekret")
    client.list_challenges()


def test_timeout_is_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Session's get is called with timeout=(connect, read)."""
    captured: dict[str, object] = {}

    class _FakeResp:
        status_code = 200
        text = "{}"

        def json(self) -> dict[str, list[object]]:
            return {"data": []}

    def fake_get(self: object, url: str, **kwargs: object) -> _FakeResp:
        captured.update(kwargs)
        return _FakeResp()

    import requests

    monkeypatch.setattr(requests.Session, "get", fake_get)
    client = CTFdClient("https://ctf.example.com", "tok", read_timeout=15.0)
    client.list_challenges()
    assert captured["timeout"] == (5.0, 15.0)
```

- [ ] **Step 2: Run the tests, confirm they fail**

```bash
pytest tests/test_ctfd.py -v
```

Expected: ImportError (`ctf_forge.ctfd` doesn't exist).

- [ ] **Step 3: Create `ctf_forge/ctfd.py`**

```python
"""HTTP client for CTFd plus the Challenge dataclass."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from .errors import CTFdAPIError

_CONNECT_TIMEOUT = 5.0


@dataclass(frozen=True)
class Challenge:
    id: int
    name: str
    description: str
    category: str
    connection_info: str
    files: list[str] = field(default_factory=list)
    tags: list[Any] = field(default_factory=list)
    hints: list[Any] = field(default_factory=list)
    solved: bool = False


class CTFdClient:
    """Thin HTTP wrapper around CTFd's REST API."""

    def __init__(self, base_url: str, token: str, read_timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout: tuple[float, float] = (_CONNECT_TIMEOUT, read_timeout)
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Token {token}", "Content-Type": "application/json"}
        )

    def _get(self, path_or_url: str, **kwargs: Any) -> requests.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{path_or_url}"
        resp = self.session.get(url, timeout=self.timeout, **kwargs)
        if resp.status_code != 200:
            raise CTFdAPIError(resp.status_code, url, resp.text or "")
        return resp

    def list_challenges(self) -> list[dict[str, Any]]:
        return list(self._get("/api/v1/challenges").json().get("data", []))

    def get_challenge_detail(self, challenge_id: int) -> dict[str, Any]:
        data = self._get(f"/api/v1/challenges/{challenge_id}").json()
        return dict(data.get("data", {}))

    def get_challenges(self, workers: int = 4) -> list[Challenge]:
        summaries = self.list_challenges()
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            details = list(
                pool.map(lambda s: self.get_challenge_detail(int(s["id"])), summaries)
            )
        challenges: list[Challenge] = []
        for summary, detail in zip(summaries, details):
            challenges.append(
                Challenge(
                    id=int(detail["id"]),
                    name=str(detail.get("name") or ""),
                    description=str(detail.get("description") or ""),
                    category=str(detail.get("category") or "misc"),
                    connection_info=str(detail.get("connection_info") or ""),
                    files=list(detail.get("files") or []),
                    tags=list(detail.get("tags") or []),
                    hints=list(detail.get("hints") or []),
                    solved=bool(summary.get("solved_by_me", False)),
                )
            )
        return challenges

    def download_file(self, file_url: str, dest_dir: Path) -> Path:
        basename = Path(file_url.split("?", 1)[0]).name
        if not basename or basename in (".", ".."):
            raise CTFdAPIError(0, file_url, "could not derive a safe filename")
        dest_dir.mkdir(parents=True, exist_ok=True)
        full_url = f"{self.base_url}/files/{file_url.lstrip('/')}"
        target = dest_dir / basename
        with self.session.get(full_url, stream=True, timeout=self.timeout) as resp:
            if resp.status_code != 200:
                raise CTFdAPIError(resp.status_code, full_url, resp.text or "")
            with target.open("wb") as out:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        out.write(chunk)
        return target
```

- [ ] **Step 4: Note about `download_file` URL behavior**

The current implementation prepends `/files/` to the URL the same way the original code did, preserving compatibility with the CTFd `location` field. The basename check rejects `.` and `..` to make path traversal impossible even on the file side.

- [ ] **Step 5: Run the tests, confirm they pass**

```bash
pytest tests/test_ctfd.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 6: Commit**

```bash
git add ctf_forge/ctfd.py tests/test_ctfd.py
git commit -m "feat: add CTFdClient with timeouts and parallel detail fetch

Single requests.Session per client carries the auth header. All calls
go through _get with an explicit (connect, read) timeout pair, so a
hung CTFd can no longer wedge the tool. get_challenges parallelizes
the per-challenge detail GETs through a small thread pool, dropping a
50-challenge listing from 50 sequential round-trips to a handful of
batches. download_file writes straight to its destination directory
and refuses unsafe basenames."
```

---

## Task 6: Bundled default templates

**Files:**
- Create: `ctf_forge/default_templates/default/solve.py`
- Create: `ctf_forge/default_templates/default/solution.md`
- Create: `ctf_forge/default_templates/pwn/solve.py`
- Create: `ctf_forge/default_templates/pwn/solution.md`
- Create: `ctf_forge/default_templates/web/solve.py`
- Create: `ctf_forge/default_templates/web/solution.md`
- Create: `ctf_forge/default_templates/rev/solve.py`
- Create: `ctf_forge/default_templates/rev/solution.md`
- Create: `ctf_forge/default_templates/crypto/solve.py`
- Create: `ctf_forge/default_templates/crypto/solution.md`
- Create: `ctf_forge/default_templates/misc/solve.py`
- Create: `ctf_forge/default_templates/misc/solution.md`

**Interfaces:**
- Produces: templates discoverable via `importlib.resources.files("ctf_forge.default_templates")`.

- [ ] **Step 1: Create the `default` templates** (used as the bottom of the fallback chain)

`ctf_forge/default_templates/default/solve.py`:

```python
#!/usr/bin/env python3
# %challname% (solve script)

"""
Challenge: %challname%
Category: %category%
URL: %url%
Connection: %connection_info%

Files:
%files%

Tags: %tags%

Hints (%hint_count%):
%hints%
"""

print("Solving %challname% (%category%)")
```

`ctf_forge/default_templates/default/solution.md`:

```markdown
# %challname%

- Category: %category%
- URL: %url%
- Connection: %connection_info%
- Tags: %tags%

## Description

%description%

## Files

%files%

## Hints (%hint_count%)

%hints%

## Approach

> Notes on how you solved it.

## Flag

`FLAG{FLAG_HERE}`
```

- [ ] **Step 2: Create the `pwn` templates**

`ctf_forge/default_templates/pwn/solve.py`:

```python
#!/usr/bin/env python3
# %challname% (pwn solve script)

from pwn import *

debug = False

if debug:
    r = process("./binary")
    # gdb.attach(r, "b *main\nc")
else:
    r = remote("HOST", 1337)  # %connection_info%

# Example: basic buffer overflow
offset = 72
payload = b"A" * offset + p64(0xdeadbeef)
# r.sendline(payload)

r.interactive()
```

`ctf_forge/default_templates/pwn/solution.md`:

```markdown
# %challname% — pwn

- Connection: %connection_info%
- Tags: %tags%

## Binary analysis

```
checksec ./binary
file ./binary
```

## Vulnerability

> Describe the bug class (BOF, UAF, format string, ...).

## Exploit

See `solve.py`.

## Flag

`FLAG{FLAG_HERE}`
```

- [ ] **Step 3: Create the `web` templates**

`ctf_forge/default_templates/web/solve.py`:

```python
#!/usr/bin/env python3
# %challname% (web solve script)

import requests

URL = "%connection_info%"  # or hardcoded target

session = requests.Session()
resp = session.get(URL, timeout=10)
print(resp.status_code)
print(resp.text[:500])
```

`ctf_forge/default_templates/web/solution.md`:

```markdown
# %challname% — web

- URL: %connection_info%
- Tags: %tags%

## Recon

> `curl -sI`, view source, robots.txt, sitemap, framework fingerprint.

## Vulnerability

> Bug class and where.

## Exploit

See `solve.py`.

## Flag

`FLAG{FLAG_HERE}`
```

- [ ] **Step 4: Create the `rev` templates**

`ctf_forge/default_templates/rev/solve.py`:

```python
#!/usr/bin/env python3
# %challname% (reverse engineering scratchpad)

# Static analysis tools to try:
#   file ./binary
#   strings ./binary | less
#   objdump -d ./binary | less
#   ghidra / cutter / radare2

# Dynamic analysis:
#   strace ./binary
#   ltrace ./binary
#   gdb ./binary

# Solution scratchpad:
print("see solution.md for the writeup")
```

`ctf_forge/default_templates/rev/solution.md`:

```markdown
# %challname% — rev

- Tags: %tags%

## Triage

```
file ./binary
strings ./binary | head -50
```

## Approach

> Key insight here.

## Flag

`FLAG{FLAG_HERE}`
```

- [ ] **Step 5: Create the `crypto` templates**

`ctf_forge/default_templates/crypto/solve.py`:

```python
#!/usr/bin/env python3
# %challname% (crypto solve script)

# from Crypto.Cipher import AES
# from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
# import gmpy2

# Document the scheme and the assumed weakness here.

print("Solving %challname%")
```

`ctf_forge/default_templates/crypto/solution.md`:

```markdown
# %challname% — crypto

- Tags: %tags%

## Scheme

> RSA / AES-CBC / ECDSA / custom / etc.

## Weakness

> Small e, reused nonce, weak prime, padding oracle, ...

## Solver

See `solve.py`.

## Flag

`FLAG{FLAG_HERE}`
```

- [ ] **Step 6: Create the `misc` templates**

`ctf_forge/default_templates/misc/solve.py`:

```python
#!/usr/bin/env python3
# %challname% (misc solve script)

# Misc is anything: forensics, OSINT, steganography, programming, ...
# Common tools:
#   binwalk -e file
#   exiftool file
#   zsteg image.png
#   strings file | grep -i flag

print("Solving %challname%")
```

`ctf_forge/default_templates/misc/solution.md`:

```markdown
# %challname% — misc

- Tags: %tags%

## What it is

> Forensics / stego / OSINT / programming / ...

## Solution

See `solve.py`.

## Flag

`FLAG{FLAG_HERE}`
```

- [ ] **Step 7: Verify templates are discoverable**

```bash
pip install -e .
python -c "from importlib import resources; print(sorted(p.name for p in resources.files('ctf_forge.default_templates').iterdir()))"
```

Expected: `['crypto', 'default', 'misc', 'pwn', 'rev', 'web']`.

- [ ] **Step 8: Commit**

```bash
git add ctf_forge/default_templates/
git commit -m "feat: ship bundled default templates per category

Templates moved out of inline Python strings and into data files
shipped via setuptools package-data. Covers default / pwn / web /
rev / crypto / misc. The 'default' bucket is the fallback used for
any category without a dedicated template."
```

---

## Task 7: Template loading and rendering with tests

**Files:**
- Create: `ctf_forge/templates.py`
- Create: `tests/test_templates.py`

**Interfaces:**
- Consumes: bundled templates (Task 6).
- Produces:
  - `render_template(content: str, placeholders: dict[str, str]) -> str`.
  - `category_template_files(category: str, config_dir: Path) -> list[tuple[str, str]]` — returns `[(filename, rendered_content)]` via the fallback chain.
  - `init_user_config(config_dir: Path) -> list[Path]` — copies bundled templates into the user's config dir; never overwrites existing files.

- [ ] **Step 1: Write the failing tests**

`tests/test_templates.py`:

```python
"""Tests for template rendering, fallback chain, and init_user_config."""
from __future__ import annotations

from pathlib import Path

from ctf_forge.templates import (
    category_template_files,
    init_user_config,
    render_template,
)


def test_render_template_substitutes_placeholders() -> None:
    out = render_template("Hello %name%, %name%!", {"name": "world"})
    assert out == "Hello world, world!"


def test_render_template_leaves_unknown_placeholders_literal() -> None:
    out = render_template("a %x% b %y% c", {"x": "1"})
    assert out == "a 1 b %y% c"


def test_render_template_ignores_non_placeholder_percents() -> None:
    out = render_template("100% safe", {})
    assert out == "100% safe"


def test_user_category_dir_wins(tmp_path: Path) -> None:
    cat_dir = tmp_path / "pwn"
    cat_dir.mkdir()
    (cat_dir / "solve.py").write_text("# user pwn solve")
    files = category_template_files("pwn", tmp_path)
    names = {n for n, _ in files}
    assert "solve.py" in names
    contents = dict(files)
    assert contents["solve.py"] == "# user pwn solve"


def test_user_default_dir_used_when_category_missing(tmp_path: Path) -> None:
    default_dir = tmp_path / "default"
    default_dir.mkdir()
    (default_dir / "note.md").write_text("# user default")
    files = category_template_files("blockchain", tmp_path)
    assert files == [("note.md", "# user default")]


def test_falls_back_to_bundled_when_user_dir_empty(tmp_path: Path) -> None:
    files = category_template_files("pwn", tmp_path)
    names = {n for n, _ in files}
    # The bundled pwn templates exist:
    assert "solve.py" in names
    assert "solution.md" in names


def test_falls_back_to_bundled_default_for_unknown_category(tmp_path: Path) -> None:
    files = category_template_files("blockchain", tmp_path)
    names = {n for n, _ in files}
    assert "solve.py" in names
    assert "solution.md" in names


def test_init_user_config_copies_templates(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    created = init_user_config(config_dir)
    assert any(p.name == "solve.py" for p in created)
    assert (config_dir / "default" / "solve.py").exists()
    assert (config_dir / "pwn" / "solve.py").exists()


def test_init_user_config_does_not_overwrite(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    init_user_config(config_dir)
    user_file = config_dir / "default" / "solve.py"
    user_file.write_text("# user-edited")
    init_user_config(config_dir)
    assert user_file.read_text() == "# user-edited"
```

- [ ] **Step 2: Run the tests, confirm they fail**

```bash
pytest tests/test_templates.py -v
```

Expected: ImportError (`ctf_forge.templates` doesn't exist).

- [ ] **Step 3: Create `ctf_forge/templates.py`**

```python
"""Template loading, placeholder substitution, and user-config init."""
from __future__ import annotations

import re
from importlib import resources
from importlib.abc import Traversable
from pathlib import Path

_PLACEHOLDER = re.compile(r"%([a-zA-Z0-9_]+)%")
_BUNDLED_PACKAGE = "ctf_forge.default_templates"


def render_template(content: str, placeholders: dict[str, str]) -> str:
    def replacer(match: re.Match[str]) -> str:
        key = match.group(1)
        return placeholders.get(key, match.group(0))

    return _PLACEHOLDER.sub(replacer, content)


def _files_in(directory: Path) -> list[tuple[str, str]]:
    return [
        (p.name, p.read_text(encoding="utf-8"))
        for p in sorted(directory.iterdir())
        if p.is_file()
    ]


def _bundled_files(name: str) -> list[tuple[str, str]]:
    root: Traversable = resources.files(_BUNDLED_PACKAGE).joinpath(name)
    if not root.is_dir():
        return []
    files: list[tuple[str, str]] = []
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.is_file():
            files.append((entry.name, entry.read_text(encoding="utf-8")))
    return files


def category_template_files(category: str, config_dir: Path) -> list[tuple[str, str]]:
    """Return [(filename, content)] for the category, using the fallback chain.

    Order:
      1. ``<config_dir>/<category>/``
      2. ``<config_dir>/default/``
      3. bundled ``<category>``
      4. bundled ``default``
    """
    for sub in (category, "default"):
        candidate = config_dir / sub
        if candidate.is_dir():
            files = _files_in(candidate)
            if files:
                return files
    for sub in (category, "default"):
        files = _bundled_files(sub)
        if files:
            return files
    return []


def init_user_config(config_dir: Path) -> list[Path]:
    """Copy bundled templates into ``config_dir``. Never overwrites."""
    created: list[Path] = []
    root = resources.files(_BUNDLED_PACKAGE)
    for cat in sorted(root.iterdir(), key=lambda e: e.name):
        if not cat.is_dir():
            continue
        target_dir = config_dir / cat.name
        target_dir.mkdir(parents=True, exist_ok=True)
        for entry in sorted(cat.iterdir(), key=lambda e: e.name):
            if not entry.is_file():
                continue
            target = target_dir / entry.name
            if target.exists():
                continue
            target.write_text(entry.read_text(encoding="utf-8"), encoding="utf-8")
            created.append(target)
    return created
```

- [ ] **Step 4: Run the tests, confirm they pass**

```bash
pytest tests/test_templates.py -v
```

Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add ctf_forge/templates.py tests/test_templates.py
git commit -m "feat: template loading with user/bundled fallback chain

User templates in <config_dir>/<category>/ win, falling back to
<config_dir>/default/, then bundled <category>, then bundled default.
init_user_config copies bundled templates into the user's config dir
without overwriting existing files."
```

---

## Task 8: Workspace orchestration + race regression test

**Files:**
- Modify: `ctf_forge/workspace.py` (add `setup_challenge`, `setup_all_challenges`, `placeholders_for`)
- Create: `tests/test_workspace.py`

**Interfaces:**
- Consumes: `Challenge`, `CTFdClient` (Task 5); `category_template_files`, `render_template` (Task 7); `safe_path_component` (Task 3); `WorkspaceError` (Task 2).
- Produces:
  - `placeholders_for(challenge: Challenge, base_url: str) -> dict[str, str]`.
  - `setup_challenge(client: CTFdClient, challenge: Challenge, ctf_name: str, output_dir: Path, config_dir: Path, base_url: str) -> Path`.
  - `setup_all_challenges(client, challenges, *, ctf_name, output_dir, config_dir, base_url, workers, skip_solved) -> tuple[list[Path], list[tuple[int, str, Exception]]]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_workspace.py`:

```python
"""Workspace orchestration tests, including the parallel-race regression."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from ctf_forge.ctfd import Challenge, CTFdClient
from ctf_forge.workspace import (
    placeholders_for,
    setup_all_challenges,
    setup_challenge,
)


class _FakeClient:
    """Stand-in for CTFdClient.download_file that writes a known marker."""

    def __init__(self, payload_by_url: dict[str, bytes] | None = None) -> None:
        self.calls: list[tuple[str, Path]] = []
        self.payloads = payload_by_url or {}
        self.lock = threading.Lock()

    def download_file(self, file_url: str, dest_dir: Path) -> Path:
        basename = Path(file_url.split("?", 1)[0]).name
        target = dest_dir / basename
        dest_dir.mkdir(parents=True, exist_ok=True)
        with self.lock:
            self.calls.append((file_url, target))
        target.write_bytes(self.payloads.get(file_url, file_url.encode()))
        return target


def _challenge(**overrides: Any) -> Challenge:
    base: dict[str, Any] = {
        "id": 1,
        "name": "Demo",
        "description": "desc",
        "category": "misc",
        "connection_info": "",
        "files": [],
        "tags": [],
        "hints": [],
        "solved": False,
    }
    base.update(overrides)
    return Challenge(**base)


def test_placeholders_for_includes_tags_and_hints() -> None:
    challenge = _challenge(
        tags=["easy", "intro"],
        hints=[{"content": "first hint"}, {"content": "second hint"}],
    )
    p = placeholders_for(challenge, base_url="https://x")
    assert p["tags"] == "easy, intro"
    assert "- first hint" in p["hints"]
    assert "- second hint" in p["hints"]
    assert p["hint_count"] == "2"
    assert p["url"] == "https://x/challenges/1"


def test_placeholders_handle_empty_hints_and_tags() -> None:
    p = placeholders_for(_challenge(), base_url="")
    assert p["tags"] == "none"
    assert p["hints"] == "none"
    assert p["hint_count"] == "0"


def test_setup_challenge_writes_template_and_downloads(tmp_path: Path) -> None:
    client = _FakeClient()
    challenge = _challenge(
        id=42,
        name="My Challenge",
        category="web",
        files=["/files/abc/flag.txt"],
    )
    result = setup_challenge(
        client,  # type: ignore[arg-type]
        challenge,
        ctf_name="ctf",
        output_dir=tmp_path,
        config_dir=tmp_path / "config",
        base_url="https://x",
    )
    assert result == tmp_path / "ctf" / "web" / "My_Challenge"
    assert (result / "flag.txt").exists()
    # A bundled web/solve.py exists, so the rendered file should exist:
    assert (result / "solve.py").exists()


def test_setup_challenge_sanitizes_name(tmp_path: Path) -> None:
    client = _FakeClient()
    challenge = _challenge(id=99, name="../escape", category="misc")
    result = setup_challenge(
        client,  # type: ignore[arg-type]
        challenge,
        ctf_name="ctf",
        output_dir=tmp_path,
        config_dir=tmp_path / "config",
        base_url="",
    )
    assert tmp_path in result.parents
    assert ".." not in str(result.relative_to(tmp_path))


def test_parallel_downloads_with_same_basename_dont_collide(tmp_path: Path) -> None:
    """Regression: previously, two parallel downloads with same basename
    both wrote to CWD before being moved, racing each other. Now each
    writes to its own per-challenge directory, so collisions are impossible.
    """
    client = _FakeClient(
        payload_by_url={
            "/files/a/flag.txt": b"AAAA",
            "/files/b/flag.txt": b"BBBB",
        }
    )
    challenges = [
        _challenge(id=1, name="One", category="misc", files=["/files/a/flag.txt"]),
        _challenge(id=2, name="Two", category="misc", files=["/files/b/flag.txt"]),
    ]
    successes, failures = setup_all_challenges(
        client,  # type: ignore[arg-type]
        challenges,
        ctf_name="ctf",
        output_dir=tmp_path,
        config_dir=tmp_path / "config",
        base_url="",
        workers=4,
        skip_solved=False,
    )
    assert failures == []
    assert len(successes) == 2
    one = tmp_path / "ctf" / "misc" / "One" / "flag.txt"
    two = tmp_path / "ctf" / "misc" / "Two" / "flag.txt"
    assert one.read_bytes() == b"AAAA"
    assert two.read_bytes() == b"BBBB"


def test_skip_solved_excludes_solved_challenges(tmp_path: Path) -> None:
    client = _FakeClient()
    challenges = [
        _challenge(id=1, name="One", solved=False),
        _challenge(id=2, name="Two", solved=True),
    ]
    successes, _ = setup_all_challenges(
        client,  # type: ignore[arg-type]
        challenges,
        ctf_name="ctf",
        output_dir=tmp_path,
        config_dir=tmp_path / "config",
        base_url="",
        workers=2,
        skip_solved=True,
    )
    assert len(successes) == 1
    assert "One" in str(successes[0])


def test_failed_challenge_does_not_abort_others(tmp_path: Path) -> None:
    class FlakyClient(_FakeClient):
        def download_file(self, file_url: str, dest_dir: Path) -> Path:
            if "boom" in file_url:
                raise RuntimeError("nope")
            return super().download_file(file_url, dest_dir)

    client = FlakyClient()
    challenges = [
        _challenge(id=1, name="Good", files=["/files/a/x.txt"]),
        _challenge(id=2, name="Bad", files=["/files/boom/x.txt"]),
    ]
    successes, failures = setup_all_challenges(
        client,  # type: ignore[arg-type]
        challenges,
        ctf_name="ctf",
        output_dir=tmp_path,
        config_dir=tmp_path / "config",
        base_url="",
        workers=2,
        skip_solved=False,
    )
    assert len(successes) == 1
    assert len(failures) == 1
    fail_id, fail_name, exc = failures[0]
    assert fail_id == 2
    assert fail_name == "Bad"
    assert "nope" in str(exc)
```

- [ ] **Step 2: Run the tests, confirm they fail**

```bash
pytest tests/test_workspace.py -v
```

Expected: ImportError (`setup_challenge` etc. not yet exported from `ctf_forge.workspace`).

- [ ] **Step 3: Extend `ctf_forge/workspace.py`** (append to the existing file from Task 3)

Append (after the existing `safe_path_component`):

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Protocol

from .ctfd import Challenge
from .errors import WorkspaceError
from .templates import category_template_files, render_template


class _Downloader(Protocol):
    def download_file(self, file_url: str, dest_dir: Path) -> Path: ...


def placeholders_for(challenge: Challenge, base_url: str) -> dict[str, str]:
    hint_lines: list[str] = []
    for hint in challenge.hints:
        if isinstance(hint, dict):
            hint_lines.append(f"- {hint.get('content', '')}")
        else:
            hint_lines.append(f"- {hint}")
    tags_str = ", ".join(
        str(t.get("value")) if isinstance(t, dict) and "value" in t else str(t)
        for t in challenge.tags
    )
    files_str = "\n".join(
        Path(str(f).split("?", 1)[0]).name for f in challenge.files
    )
    return {
        "challname": challenge.name,
        "category": challenge.category,
        "description": challenge.description,
        "url": f"{base_url}/challenges/{challenge.id}" if base_url else "",
        "connection_info": challenge.connection_info,
        "files": files_str,
        "tags": tags_str or "none",
        "hints": "\n".join(hint_lines) or "none",
        "hint_count": str(len(challenge.hints)),
    }


def setup_challenge(
    client: _Downloader,
    challenge: Challenge,
    *,
    ctf_name: str,
    output_dir: Path,
    config_dir: Path,
    base_url: str,
) -> Path:
    safe_category = safe_path_component(challenge.category, fallback_id=challenge.id) or "misc"
    safe_name = safe_path_component(challenge.name, fallback_id=challenge.id)
    target_dir = output_dir / ctf_name / safe_category / safe_name
    target_dir.mkdir(parents=True, exist_ok=True)

    placeholders = placeholders_for(challenge, base_url)
    for filename, content in category_template_files(challenge.category, config_dir):
        rendered = render_template(content, placeholders)
        (target_dir / filename).write_text(rendered, encoding="utf-8")

    for file_url in challenge.files:
        try:
            client.download_file(str(file_url), target_dir)
        except Exception as exc:
            raise WorkspaceError(challenge.id, safe_name, f"file download failed: {exc}") from exc

    return target_dir


def setup_all_challenges(
    client: _Downloader,
    challenges: Iterable[Challenge],
    *,
    ctf_name: str,
    output_dir: Path,
    config_dir: Path,
    base_url: str,
    workers: int,
    skip_solved: bool,
) -> tuple[list[Path], list[tuple[int, str, Exception]]]:
    selected = [c for c in challenges if not (skip_solved and c.solved)]
    successes: list[Path] = []
    failures: list[tuple[int, str, Exception]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(
                setup_challenge,
                client,
                challenge,
                ctf_name=ctf_name,
                output_dir=output_dir,
                config_dir=config_dir,
                base_url=base_url,
            ): challenge
            for challenge in selected
        }
        for fut in as_completed(futures):
            challenge = futures[fut]
            try:
                successes.append(fut.result())
            except Exception as exc:  # noqa: BLE001 — surfaced in summary
                failures.append((challenge.id, challenge.name, exc))
    return successes, failures
```

- [ ] **Step 4: Run the tests, confirm they pass**

```bash
pytest tests/test_workspace.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 5: Run the full suite as a checkpoint**

```bash
pytest -v
```

Expected: all tests across all files pass.

- [ ] **Step 6: Commit**

```bash
git add ctf_forge/workspace.py tests/test_workspace.py
git commit -m "feat: per-challenge workspace setup with race-safe downloads

Each challenge gets its own directory under <output>/<ctf>/<category>/<safe_name>/.
Files download directly into that directory, eliminating the previous
CWD race. Failed challenges no longer abort the run; failures are
collected and returned. Placeholders cover tags, hints, hint_count,
url, connection_info, and files."
```

---

## Task 9: Wire up the `download` and `init` subcommands

**Files:**
- Modify: `ctf_forge/cli.py` (replace the stub from Task 1)
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `resolve_download_config` (Task 4), `CTFdClient` (Task 5), `setup_all_challenges` (Task 8), `init_user_config` (Task 7).
- Produces: `main(argv: list[str] | None = None) -> int` returning 0/1/2 per spec.

- [ ] **Step 1: Write a minimal failing test**

`tests/test_cli.py`:

```python
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
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
pytest tests/test_cli.py -v
```

Expected: the stub from Task 1 still calls `parser.exit`, so behavior won't match. Tests fail.

- [ ] **Step 3: Replace `ctf_forge/cli.py`** with the real implementation

```python
"""CLI entry point: download, init, install subcommands."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .config import resolve_download_config
from .ctfd import CTFdClient
from .errors import CTFForgeError, ConfigError
from .templates import init_user_config
from .workspace import setup_all_challenges


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-forge",
        description="Forge local challenge workspaces from CTFd instances.",
    )
    parser.add_argument("--version", action="version", version=f"ctf-forge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    download = sub.add_parser("download", help="Download CTFd challenges and apply templates")
    download.add_argument("--url", help="CTFd base URL (overrides CTFD_URL)")
    download.add_argument("--token", help="CTFd API token (overrides CTFD_TOKEN)")
    download.add_argument("--ctf-name", help="Local directory name for this CTF")
    download.add_argument("--output-dir", help="Where to put the CTF directory (default: .)")
    download.add_argument("--workers", type=int, default=4, help="Parallel workers (default: 4)")
    download.add_argument("--skip-solved", action="store_true", help="Skip challenges marked solved")
    download.add_argument("--config-dir", help="User template directory (default: ./config)")
    download.set_defaults(func=_cmd_download)

    init = sub.add_parser("init", help="Copy bundled templates to a config dir")
    init.add_argument("--config-dir", default="config", help="Target directory (default: ./config)")
    init.set_defaults(func=_cmd_init)

    install = sub.add_parser("install", help="Print PATH instructions for the binary")
    install.add_argument(
        "--shell",
        default="auto",
        choices=["auto", "zsh", "bash", "fish"],
        help="Shell to print instructions for (default: auto-detect)",
    )
    install.set_defaults(func=_cmd_install)

    return parser


def _cmd_download(args: argparse.Namespace) -> int:
    config = resolve_download_config(args)
    client = CTFdClient(config.url, config.token, read_timeout=config.http_timeout)
    print(f"[*] listing challenges from {config.url}", file=sys.stderr)
    challenges = client.get_challenges(workers=config.workers)
    print(
        f"[*] found {len(challenges)} challenges; setting up under "
        f"{config.output_dir.rstrip('/')}/{config.ctf_name}/",
        file=sys.stderr,
    )
    successes, failures = setup_all_challenges(
        client,
        challenges,
        ctf_name=config.ctf_name,
        output_dir=Path(config.output_dir),
        config_dir=Path(config.config_dir),
        base_url=config.url,
        workers=config.workers,
        skip_solved=config.skip_solved,
    )
    print(
        f"[*] {len(successes)} succeeded, {len(failures)} failed",
        file=sys.stderr,
    )
    for cid, cname, exc in failures:
        print(f"    [!] {cname} (id {cid}): {exc}", file=sys.stderr)
    return 1 if failures else 0


def _cmd_init(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    created = init_user_config(config_dir)
    print(f"[*] copied {len(created)} template files into {config_dir}/")
    for path in created:
        print(f"    + {path}")
    return 0


def _detect_shell() -> str:
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return "zsh"
    if "fish" in shell:
        return "fish"
    return "bash"


def _path_instructions(shell: str, binary_dir: Path) -> str:
    if shell == "fish":
        rc = "~/.config/fish/config.fish"
        line = f"set -gx PATH {binary_dir} $PATH"
    elif shell == "zsh":
        rc = "~/.zshrc"
        line = f'export PATH="{binary_dir}:$PATH"'
    else:
        rc = "~/.bashrc"
        line = f'export PATH="{binary_dir}:$PATH"'
    return (
        f"To put ctf-forge on your PATH, add the following line to {rc}:\n\n"
        f"  {line}\n\n"
        f"Then restart your shell, or run: source {rc}\n"
    )


def _cmd_install(args: argparse.Namespace) -> int:
    binary = Path(shutil.which("ctf-forge") or sys.argv[0]).resolve()
    binary_dir = binary.parent
    shell = args.shell if args.shell != "auto" else _detect_shell()
    print(_path_instructions(shell, binary_dir))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"[!] config error: {exc}", file=sys.stderr)
        return 2
    except CTFForgeError as exc:
        print(f"[!] error: {exc}", file=sys.stderr)
        return 1
```

- [ ] **Step 4: Run the tests, confirm they pass**

```bash
pytest tests/test_cli.py -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Run the full suite**

```bash
pytest -v
```

Expected: full suite green.

- [ ] **Step 6: Commit**

```bash
git add ctf_forge/cli.py tests/test_cli.py
git commit -m "feat: implement download, init, install subcommands

download wires resolve_download_config + CTFdClient + setup_all_challenges
together. init copies bundled templates into a user config dir. install
detects the user's shell and prints the line to add the binary's
directory to PATH (does not mutate dotfiles)."
```

---

## Task 10: Lint and type-check clean

**Files:**
- Modify (only if lint flags real issues): any file under `ctf_forge/` or `tests/`.

**Interfaces:**
- Produces: `ruff check ctf_forge tests` passes; `mypy` passes.

- [ ] **Step 1: Run ruff**

```bash
ruff check ctf_forge tests
```

Expected: no errors. If there are, fix them inline.

- [ ] **Step 2: Run mypy**

```bash
mypy
```

Expected: `Success: no issues found`. If there are, fix them inline by adding type annotations or guards. Common likely fix: `types-requests` is already in dev extras.

- [ ] **Step 3: If any files changed, run the tests**

```bash
pytest -v
```

Expected: still green.

- [ ] **Step 4: Commit (only if changes were needed)**

```bash
git add -A
git commit -m "chore: clean ruff and mypy --strict"
```

---

## Task 11: Build script and binary smoke test

**Files:**
- Create: `scripts/build.sh`

**Interfaces:**
- Produces: `dist/ctf-forge` (or `dist/ctf-forge.exe`) executable that bundles `default_templates/`.

- [ ] **Step 1: Create `scripts/build.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

rm -rf build dist ctf-forge.spec

pyinstaller \
  --noconfirm \
  --onefile \
  --name ctf-forge \
  --add-data "ctf_forge/default_templates:ctf_forge/default_templates" \
  ctf_forge/__main__.py

ls -la dist/
```

Make it executable:

```bash
chmod +x scripts/build.sh
```

- [ ] **Step 2: Run the build locally**

```bash
./scripts/build.sh
```

Expected: `dist/ctf-forge` exists.

- [ ] **Step 3: Smoke-test the binary**

```bash
./dist/ctf-forge --version
./dist/ctf-forge init --config-dir /tmp/ctf-forge-smoke
ls /tmp/ctf-forge-smoke/default/
rm -rf /tmp/ctf-forge-smoke
```

Expected: version prints; init creates `solve.py` and `solution.md` under `/tmp/ctf-forge-smoke/default/`. If `init` fails to find bundled templates, the `--add-data` flag is wrong; fix the path mapping.

- [ ] **Step 4: Commit**

```bash
git add scripts/build.sh
git commit -m "build: add pyinstaller build script bundling default templates"
```

---

## Task 12: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: GitHub Actions workflow that runs ruff, mypy, and pytest on PRs and pushes to main.

- [ ] **Step 1: Create `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: |
          python -m pip install --upgrade pip
          pip install -e '.[dev]'
      - name: Lint
        run: ruff check ctf_forge tests
      - name: Type-check
        run: mypy
      - name: Test
        run: pytest -v
```

- [ ] **Step 2: Verify the YAML parses locally** (optional)

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
```

Expected: no exception. (If `pyyaml` isn't installed, skip.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: lint, type-check, and test on Python 3.11 and 3.12"
```

---

## Task 13: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Produces: GitHub Actions workflow that builds Linux and macOS binaries on a `v*` tag and attaches them to the GitHub Release.

- [ ] **Step 1: Create `.github/workflows/release.yml`**

```yaml
name: release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            asset: ctf-forge-linux-x86_64
          - os: macos-latest
            asset: ctf-forge-macos-arm64
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: |
          python -m pip install --upgrade pip
          pip install -e '.[dev]'
      - name: Build binary
        run: ./scripts/build.sh
      - name: Rename binary
        run: mv dist/ctf-forge dist/${{ matrix.asset }}
      - name: Smoke-test binary
        run: ./dist/${{ matrix.asset }} --version
      - name: Attach to release
        uses: softprops/action-gh-release@v2
        with:
          files: dist/${{ matrix.asset }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build and release Linux and macOS binaries on tag push"
```

---

## Task 14: README rewrite

**Files:**
- Replace: `README.md`

- [ ] **Step 1: Replace `README.md`** with:

```markdown
# CTF-Forge

Forge local challenge workspaces from any CTFd instance. CTF-Forge fetches
challenges and files, applies your templates per category, and lays them out
in a tidy `ctf-name/category/challenge/` tree so you can start solving.

## Install

### With pipx (recommended for Python users)

```bash
pipx install git+https://github.com/<you>/CTF-Forge.git
```

### Pre-built binary

Download the appropriate binary from the
[GitHub Releases](https://github.com/<you>/CTF-Forge/releases) page,
then run:

```bash
chmod +x ctf-forge-*
./ctf-forge-* install
```

The `install` subcommand prints the line to add the binary's directory to
your shell's PATH. It does **not** edit your dotfiles automatically.

### From source

```bash
git clone https://github.com/<you>/CTF-Forge.git
cd CTF-Forge
pip install -e .
```

## Quick start

```bash
# 1. (Optional) copy the bundled templates into ./config so you can customise.
ctf-forge init

# 2. Configure CTFd access. Create a `.env`:
cat > .env <<EOF
CTFD_URL="https://ctf.example.com"
CTFD_TOKEN="ctfd_xxx"
CTF_NAME="acme-2026"
EOF

# 3. Run the download.
ctf-forge download
```

Result: `./acme-2026/<category>/<safe-challenge-name>/solve.py`,
`solution.md`, plus any attached challenge files, for every challenge.

## Configuration

All settings can be provided via CLI flags, env vars, or `.env`. CLI flags
take precedence; env vars override `.env`.

| Setting          | CLI flag         | Env var                  | Default     |
|------------------|------------------|--------------------------|-------------|
| CTFd base URL    | `--url`          | `CTFD_URL`               | —           |
| CTFd API token   | `--token`        | `CTFD_TOKEN`             | —           |
| CTF directory    | `--ctf-name`     | `CTF_NAME`               | —           |
| Output directory | `--output-dir`   | —                        | `.`         |
| Parallel workers | `--workers`      | —                        | `4`         |
| Skip solved      | `--skip-solved`  | —                        | off         |
| User templates   | `--config-dir`   | —                        | `./config`  |
| HTTP read timeout | —               | `CTF_FORGE_HTTP_TIMEOUT` | `30` (sec)  |

> Legacy `BASE_URL` / `PERSONAL_ACCESS_TOKEN` are still accepted (with a
> deprecation warning) through the v0.2.x series and will be removed in
> v0.3.0.

## Templates

Templates are plain text files with `%placeholder%` substitution. The
following placeholders are available:

| Placeholder         | Filled with                                  |
|---------------------|----------------------------------------------|
| `%challname%`       | Challenge name                               |
| `%category%`        | Challenge category                           |
| `%description%`     | Description (HTML preserved as-is)           |
| `%url%`             | Direct link to the challenge in CTFd         |
| `%connection_info%` | Connection string from CTFd                  |
| `%files%`           | Newline-separated list of attached basenames |
| `%tags%`            | Comma-joined tag list, or `none`             |
| `%hints%`           | Bulleted hint list, or `none`                |
| `%hint_count%`      | Integer count of hints                       |

### Template resolution (fallback chain)

When CTF-Forge sets up a challenge with category `web`, it tries each of
these in order and uses the first that contains files:

1. `<config_dir>/web/`
2. `<config_dir>/default/`
3. Bundled `web/`
4. Bundled `default/`

So a challenge with an obscure category (e.g. `blockchain`) just works
using the default template.

## CLI reference

```
ctf-forge download [--url URL] [--token TOKEN] [--ctf-name NAME]
                   [--output-dir DIR] [--workers N] [--skip-solved]
                   [--config-dir DIR]
ctf-forge init     [--config-dir DIR]
ctf-forge install  [--shell auto|zsh|bash|fish]
ctf-forge --version
ctf-forge --help
```

## Development

```bash
git clone https://github.com/<you>/CTF-Forge.git
cd CTF-Forge
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

ruff check ctf_forge tests
mypy
pytest -v
```

Build the binary locally:

```bash
./scripts/build.sh
```

## License

MIT. See [LICENSE](LICENSE).
```

- [ ] **Step 2: Spot-check the README renders**

```bash
ls README.md
head -20 README.md
```

Expected: file is in place and the top-of-file content is correct.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for v0.2.0

Document install paths, config sources, full placeholder list, the
template fallback chain, and the CLI surface. Drop the TODO list
(addressed in code)."
```

---

## Task 15: Tag and verify release

**Files:** none (tagging operation only).

- [ ] **Step 1: Final full-suite check**

```bash
ruff check ctf_forge tests
mypy
pytest -v
./scripts/build.sh
./dist/ctf-forge --version
```

Expected: all green; binary prints `ctf-forge 0.2.0`.

- [ ] **Step 2: Update the `solve.py` template links if any path drifted**

Cross-check that bundled `default_templates/` files match what tests expect:

```bash
ls ctf_forge/default_templates/
ls ctf_forge/default_templates/default/
```

Expected: directories `default crypto misc pwn rev web`, each with `solve.py` and `solution.md`.

- [ ] **Step 3: (Manual, requires user) Push and tag**

```bash
git push origin main
git tag v0.2.0
git push origin v0.2.0
```

The release workflow builds the binaries and attaches them to the GitHub Release. Verify in the Actions tab.

> **Stop here for executor:** Pushing tags is a user-authorized action.
> Do not run step 3 without explicit user approval — surface the commands
> and wait.

---

## Self-Review Notes

This plan covers:

- All four spec bugs: CWD-race (Task 8 race test), missing timeouts (Task 5 timeout test), path traversal (Task 3 sanitizer + Task 5 download-file rejection), `None`-into-`.env` (eliminated by Task 4 removing the buggy code path).
- README TODOs: PATH install (Task 9 `install` subcommand), manual install docs (Task 14 README).
- Spec scope sections: module layout (Task 1+), CLI surface (Task 9), behavior changes (Tasks 3–8), packaging (Task 1), distribution (Tasks 11–13), tests (Tasks 3–9), linting/typing (Task 10), README (Task 14), versioning + deprecation (Task 4 + Task 14).

Names and signatures used in later tasks match those declared earlier:

- `safe_path_component(name, fallback_id=None)` defined Task 3, used Task 8.
- `Challenge` dataclass defined Task 5, consumed Task 8.
- `CTFdClient.download_file(file_url, dest_dir)` defined Task 5, consumed Task 8 via `_Downloader` Protocol.
- `category_template_files`, `render_template` defined Task 7, used Task 8.
- `resolve_download_config`, `DownloadConfig` defined Task 4, used Task 9.
- `init_user_config` defined Task 7, used Task 9.
- `setup_all_challenges` keyword arguments — defined Task 8, called with the same keyword names Task 9.
