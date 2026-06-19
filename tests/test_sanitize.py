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
