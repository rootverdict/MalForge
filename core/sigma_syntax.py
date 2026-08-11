"""Sigma value escaping helpers shared by generation and conversion."""

from __future__ import annotations

SIGMA_SPECIAL_CHARACTERS = ("\\", "*", "?")


def escape_sigma_value(value: object) -> str:
    """Escape a literal value so Sigma does not read it as a wildcard pattern."""
    escaped: list[str] = []
    for char in str(value):
        if char in SIGMA_SPECIAL_CHARACTERS:
            escaped.append("\\")
        escaped.append(char)
    return "".join(escaped)


def unescape_sigma_value(value: object) -> str:
    """Recover the literal value behind an escaped Sigma selector value."""
    characters = iter(str(value))
    literal: list[str] = []
    for char in characters:
        if char != "\\":
            literal.append(char)
            continue
        following = next(characters, None)
        if following is None:
            literal.append("\\")
        elif following in SIGMA_SPECIAL_CHARACTERS:
            literal.append(following)
        else:
            literal.extend(("\\", following))
    return "".join(literal)


def sigma_field_name(selector_key: object) -> str:
    """Strip Sigma modifiers so only the plain log field name remains."""
    return str(selector_key).split("|", 1)[0]


def has_dangling_escape(value: object) -> bool:
    """Report a trailing lone backslash, which Sigma parsers reject."""
    text = str(value)
    trailing = len(text) - len(text.rstrip("\\"))
    return trailing % 2 == 1


def has_ambiguous_escape(value: object) -> bool:
    """Report a backslash that escapes an ordinary character.

    Sigma tolerates `\\T` as a plain backslash for backwards compatibility, so
    raw Windows paths parse without error. They still change meaning the moment
    a separator lands in front of a wildcard: `C:\\Temp\\*.dll` reads as
    `C:\\Temp` plus a literal `*`, silently dropping the separator. Any value
    containing a non-escape backslash pair is raw text that was never escaped.
    """
    text = str(value)
    index = 0
    while index < len(text):
        if text[index] != "\\":
            index += 1
            continue
        if index + 1 >= len(text):
            return True
        if text[index + 1] not in SIGMA_SPECIAL_CHARACTERS:
            return True
        index += 2
    return False


def unescaped_wildcards(value: object) -> str:
    """Return the wildcard characters left unescaped in a selector value.

    Raw evidence copied straight into a selector keeps `*` and `?` as Sigma
    wildcards, which silently widens or breaks the rule. Deliberate wildcards
    in hand-written rules also land here, so callers should treat this as a
    signal to review rather than a hard failure.
    """
    text = str(value)
    found: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in ("*", "?") and char not in found:
            found.append(char)
        index += 1
    return "".join(found)
