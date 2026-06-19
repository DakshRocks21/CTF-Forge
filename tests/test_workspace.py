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
