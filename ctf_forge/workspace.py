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
    # Check for empty or path traversal before processing
    if name in ("", ".", ".."):
        return f"challenge-{fallback_id}" if fallback_id is not None else "challenge"
    # Handle path traversal sequences
    name = name.replace("../", "_._").replace("./", "_._")
    replaced = _UNSAFE_PATTERN.sub("_", name)
    collapsed = _WHITESPACE_RUN.sub("_", replaced)
    return collapsed[:_MAX_LEN]
