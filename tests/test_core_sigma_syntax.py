"""Tests for Sigma value escaping helpers."""

from __future__ import annotations

import pytest

from core.sigma_syntax import escape_sigma_value, sigma_field_name, unescape_sigma_value


@pytest.mark.parametrize(
    ("literal", "escaped"),
    [
        ("cmd.exe", "cmd.exe"),
        (r"C:\Users\bob", r"C:\\Users\\bob"),
        ("\\", "\\\\"),
        ("a*b", r"a\*b"),
        ("a?b", r"a\?b"),
        (r"C:\Temp\*.dll", r"C:\\Temp\\\*.dll"),
        ("http://e.test/a.php?id=1", r"http://e.test/a.php\?id=1"),
    ],
)
def test_escape_marks_every_sigma_metacharacter(literal: str, escaped: str) -> None:
    assert escape_sigma_value(literal) == escaped


@pytest.mark.parametrize(
    "literal",
    [
        "cmd.exe",
        r"C:\Users\bob",
        "\\",
        r"C:\Users\bob" + "\\",
        "a*b?c",
        r"C:\Temp\*.dll",
        "http://e.test/a.php?id=1&x=2",
        "",
    ],
)
def test_escape_round_trips_back_to_the_literal_value(literal: str) -> None:
    assert unescape_sigma_value(escape_sigma_value(literal)) == literal


def test_escaped_path_never_ends_in_a_lone_backslash() -> None:
    escaped = escape_sigma_value("C:\\Users\\bob\\")

    assert escaped.endswith("\\\\")
    assert (len(escaped) - len(escaped.rstrip("\\"))) % 2 == 0


def test_unescape_preserves_unknown_escape_sequences() -> None:
    assert unescape_sigma_value(r"C:\Users") == r"C:\Users"
    assert unescape_sigma_value("trailing\\") == "trailing\\"


def test_sigma_field_name_drops_modifiers() -> None:
    assert sigma_field_name("QueryName|contains") == "QueryName"
    assert sigma_field_name("destination.ip") == "destination.ip"
    assert sigma_field_name("Image|endswith|base64") == "Image"
