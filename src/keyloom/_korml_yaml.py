# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""YAML through korml: reading, writing and source-preserving edits.

The syntax is korml v0: unversioned, single-document, JSON-shaped YAML.
Every scalar is a string, as in korml itself; keyloom gives no meaning to
the other values of a file, which it keeps verbatim, and every secret is a
string.
"""

from __future__ import annotations

import typing as _typing

import korml as _korml
import korml.model as _model

import keyloom as _keyloom


class _YamlMap(dict):
    """An editable mapping holding the original korml stream at the root."""


class _YamlList(list):
    """An editable sequence holding the original korml stream at the root."""


def _problem(exc: _korml.KormlError) -> _keyloom.ParseError:
    """Do not allow a compiler diagnostic to reproduce secret source text."""
    code = exc.code()
    reason = {
        "DUPLICATE_KEY": "duplicate key",
        "TOO_DEEP": "nested too deeply",
        "INPUT_TOO_LARGE": "input too large",
        "TOO_MANY_TOKENS": "too many tokens",
        "TOO_COMPLEX": "document too complex",
    }.get(code, "syntax error")
    if code == "INVALID_ESCAPE" and "Unicode scalar value" in exc.message():
        reason = "lone surrogate or invalid Unicode scalar"
    span = getattr(exc, "span", None)
    if callable(span):
        span = span()
    if span is not None:
        reason += f" at line {span.start.line}, column {span.start.column}"
    return _keyloom.ParseError(f"invalid YAML: {reason}")


def read(*, text: str, roundtrip: bool) -> _typing.Any:
    """Read YAML text; every scalar is a string.

    With roundtrip, a mapping or sequence document keeps the korml stream, so
    write() can change values without reformatting the rest of the file.
    """
    try:
        stream = _korml.loads(text)
    except _korml.KormlError as exc:
        raise _problem(exc) from exc
    if (
        stream.version is not _model.Version.v0
        or len(stream.document_array) > 1
    ):
        raise _keyloom.ParseError(
            "invalid YAML: only unversioned single-document KORML v0 "
            "is supported"
        )
    if not stream.document_array:
        return None
    data = stream.document_array[0].to_builtin()
    if not roundtrip:
        return data
    if isinstance(data, dict):
        result: _typing.Any = _YamlMap(data)
    elif isinstance(data, list):
        result = _YamlList(data)
    else:
        return data
    result._korml_stream = stream
    return result


def dump(*, data: _typing.Any) -> str:
    """Write new YAML; every scalar must be a string."""
    try:
        return _korml.dumps(data, version=_model.Version.v0)
    except (TypeError, ValueError) as exc:
        # korml's message can quote the value, so it is not repeated.
        raise _keyloom.UnsupportedFormat(
            "YAML cannot store this data: every value must be a string, a "
            "list or a mapping with string keys"
        ) from exc


def _replacements(
    *,
    original: _model.Value,
    current: _typing.Any,
    found: list[tuple[_model.Value, str]],
) -> None:
    """Collect the values of original that current replaces with a string."""
    if original.to_builtin() == current:
        return
    if isinstance(original, _model.Mapping) and isinstance(current, dict):
        if list(original.keys()) != list(current.keys()):
            raise _keyloom.UnsupportedFormat(
                "YAML edit cannot change mapping keys"
            )
        for key, node in original.value_map.items():
            _replacements(original=node, current=current[key], found=found)
        return
    if isinstance(original, _model.Sequence) and isinstance(current, list):
        if len(original) != len(current):
            raise _keyloom.UnsupportedFormat(
                "YAML edit cannot change sequence length"
            )
        for node, value in zip(original, current, strict=True):
            _replacements(original=node, current=value, found=found)
        return
    if not isinstance(current, str):
        raise _keyloom.UnsupportedFormat(
            "YAML edit can only replace a value with a string"
        )
    found.append((original, current))


def write(*, data: _YamlMap | _YamlList) -> str:
    """Return the source of data's stream with its changed values replaced.

    korml.edit writes every replacement as a double-quoted scalar, keeps
    every other token, and checks that the result reads back as the edited
    data, so no secret can turn into structure.
    """
    stream = data._korml_stream
    found: list[tuple[_model.Value, str]] = []
    _replacements(original=stream.document_array[0], current=data, found=found)
    if not found:
        return stream.source
    try:
        return _korml.edit(stream=stream, replacements=found)
    except ValueError as exc:
        raise _keyloom.UnsupportedFormat(f"YAML edit failed: {exc}") from exc
