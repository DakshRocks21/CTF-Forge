"""Path-component sanitization helpers.

Extracted into a standalone module so that both ``workspace.py`` and
``templates.py`` can import it without creating a circular dependency.
"""
from __future__ import annotations

import re

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
