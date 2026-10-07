"""Requirement 2: property-based fuzzing of the validators."""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from ssm import validators as v

CONTROL = [chr(c) for c in range(0x20)] + ["\x7f"]
DANGEROUS = ["\n", "\r", "[", "]", "%", ";", "#", "\\", " ", " ", "\x85"]
LOOKALIKES = ["［", "］", "％", "；", "＃", " ", "​", "﻿", "е", "а", "ﬁ"]

any_text = st.text(alphabet=st.characters(codec="utf-8"), max_size=80)
spiced = st.builds(
    lambda pre, bad, post: pre + bad + post,
    any_text,
    st.sampled_from(CONTROL + DANGEROUS + LOOKALIKES),
    any_text,
)

SHARE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", re.ASCII)
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}", re.ASCII)


def _accepts(fn: object, value: str) -> bool:
    try:
        fn(value)  # type: ignore[operator]
    except v.ValidationError:
        return False
    return True


@settings(max_examples=2000)
@given(st.one_of(any_text, spiced))
def test_share_name_accepts_only_regex(s: str) -> None:
    if _accepts(v.validate_share_name, s):
        assert SHARE_RE.fullmatch(s)
        assert s == s.strip()
        assert s.lower() not in v.RESERVED_SHARE_NAMES


@settings(max_examples=2000)
@given(st.one_of(any_text, spiced))
def test_username_accepts_only_regex(s: str) -> None:
    if _accepts(v.validate_username, s):
        assert USER_RE.fullmatch(s)
        assert s.isascii()


@settings(max_examples=2000)
@given(st.one_of(any_text, spiced))
def test_comment_never_contains_control_or_substitution(s: str) -> None:
    if _accepts(v.validate_comment, s):
        assert not v.has_control_chars(s)
        assert "%" not in s
        assert "\\" not in s
        assert "\n" not in s and "\r" not in s


@settings(max_examples=2000)
@given(st.one_of(any_text, spiced), st.sampled_from(CONTROL))
def test_any_control_char_rejected_by_every_validator(s: str, ch: str) -> None:
    value = s + ch
    for fn in (
        v.validate_share_name,
        v.validate_username,
        v.validate_comment,
        v.validate_filename,
        v.validate_password,
    ):
        assert not _accepts(fn, value), (fn.__name__, value)


@settings(max_examples=2000)
@given(st.one_of(any_text, spiced))
def test_sanitized_upload_name_is_safe_filename(s: str) -> None:
    try:
        out = v.sanitize_upload_filename(s)
    except v.ValidationError:
        return
    assert v.validate_filename(out) == out
    assert "/" not in out and "\\" not in out
    assert out not in (".", "..")
    assert not v.has_control_chars(out)
