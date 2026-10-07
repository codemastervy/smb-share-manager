"""Requirement 2: fuzz the renderer. Either it refuses, or the output has exactly one section
per share and every value appears verbatim on a single line."""

from __future__ import annotations

import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ssm import render
from ssm.models import ShareSpec

NASTY = ["\n", "\r", "[", "]", "%", ";", "#", "\\", "=", " ", "\x85", "\x00", "\x7f",
         "［", "］", " ", "﻿", "е"]

text = st.text(alphabet=st.one_of(st.characters(codec="utf-8"), st.sampled_from(NASTY)),
               max_size=40)
names = st.one_of(text, st.from_regex(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,20}", fullmatch=True))
users = st.one_of(text, st.from_regex(r"[a-z_][a-z0-9_-]{0,10}", fullmatch=True))
paths = st.one_of(text, st.builds(lambda t: "/mnt/files/" + t, text))
shares = st.builds(
    ShareSpec,
    name=names,
    path=paths,
    comment=text,
    members=st.dictionaries(users, st.sampled_from(["ro", "rw", "x", "rw\n"]), max_size=3),
    all_users=st.sampled_from([None, "ro", "rw", "bad"]),
    no_unix_perms=st.booleans(),
)

SECTION_RE = re.compile(r"^\s*\[", re.M)


@settings(max_examples=3000, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(shares, max_size=4))
def test_render_refuses_or_is_structurally_sound(specs: list[ShareSpec]) -> None:
    try:
        out = render.render_shares(specs)
    except render.RenderError:
        return
    lines = out.split("\n")
    assert len(SECTION_RE.findall(out)) == len(specs)
    assert render.parse_sections(out).keys() == {s.name for s in specs}
    for s in specs:
        assert f"[{s.name}]" in lines
        assert f"\tpath = {s.path}" in lines
        if s.comment:
            assert f"\tcomment = {s.comment}" in lines
    for ln in lines:
        assert "%" not in ln
        assert not any(ord(c) < 0x20 and c != "\t" for c in ln)
        assert not ln.endswith("\\")
