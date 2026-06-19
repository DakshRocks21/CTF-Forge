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


def test_traversal_category_falls_back_to_bundled(tmp_path: Path) -> None:
    """A category string containing '..' or '/' must not traverse out
    of config_dir. The fallback chain should still find bundled
    templates."""
    files = category_template_files("../../etc", tmp_path)
    names = {n for n, _ in files}
    assert "solve.py" in names
    assert "solution.md" in names
    # Sanity: we got the bundled default templates, not something from /etc.
    contents = dict(files)
    assert "%challname%" in contents["solve.py"]
