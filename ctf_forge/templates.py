"""Template loading, placeholder substitution, and user-config init."""
from __future__ import annotations

import re
from importlib import resources
from importlib.resources.abc import Traversable
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
        # Skip __pycache__ and other non-template directories
        if cat.name.startswith("__"):
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
