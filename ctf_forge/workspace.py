"""Workspace orchestration: directory layout, sanitization, file writes.

This module will grow in later tasks. For now it only exports the
path-component sanitizer.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Protocol

from .ctfd import Challenge
from .errors import WorkspaceError
from .templates import category_template_files, render_template

_UNSAFE_PATTERN = re.compile(r"[^\w\-. ]", re.UNICODE)
_WHITESPACE_RUN = re.compile(r"\s+", re.UNICODE)
_MAX_LEN = 80


def safe_path_component(name: str, fallback_id: int | None = None) -> str:
    """Return a string safe to use as a single path component.

    Rules, applied in order:

    1. Non-string inputs are coerced to an empty string.
    2. If the input is empty, ``.``, or ``..``, short-circuit to
       ``challenge-{fallback_id}`` (or ``challenge`` if no id given).
    3. Substring ``../`` and ``./`` are rewritten to ``_._`` so the
       result cannot start with a traversal-looking sequence.
    4. Characters outside ``[\\w\\-. ]`` are replaced with ``_``.
    5. Whitespace runs are collapsed into a single ``_``.
    6. The result is truncated to 80 characters.
    """
    if not isinstance(name, str):
        name = ""
    if name in ("", ".", ".."):
        return f"challenge-{fallback_id}" if fallback_id is not None else "challenge"
    name = name.replace("../", "_._").replace("./", "_._")
    replaced = _UNSAFE_PATTERN.sub("_", name)
    collapsed = _WHITESPACE_RUN.sub("_", replaced)
    return collapsed[:_MAX_LEN]


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
