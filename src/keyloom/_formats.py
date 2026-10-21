# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Reading and writing TOML, YAML and JSON.

``load_file`` and ``dump_text`` round-trip a document with its comments and
formatting, for operations that write the file back. ``load_plain`` parses
into plain Python types, for applications that only read it.
"""

import collections.abc as _abc
import json as _json
import pathlib as _pathlib
import tomllib as _tomllib
import typing as _typing

import tomlkit as _tomlkit
import tomlkit.exceptions as _tomlkit_exceptions

import keyloom as _keyloom
import keyloom._korml_yaml as _korml_yaml

_SUFFIXES = {
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
}


def _describe(*, error: Exception, syntax: str) -> str:
    """Describe a parse error without quoting the document.

    The TOML and JSON parsers report a position and at most one character;
    YAML errors come from korml already described by position only.
    """
    if syntax == "json" and str(error) == "duplicate object key":
        return "invalid JSON: duplicate object key"
    if isinstance(
        error,
        (
            _json.JSONDecodeError,
            _tomllib.TOMLDecodeError,
            _tomlkit_exceptions.ParseError,
        ),
    ):
        return f"invalid {syntax.upper()}: {error}"
    # A parser converted a value and Python refused, for example an integer
    # of more than sys.get_int_max_str_digits() digits. Such a message can
    # quote the value, so it is not repeated.
    return (
        f"invalid {syntax.upper()}: a value cannot be read, such as an "
        "integer with too many digits"
    )


def check_strings(
    *, data: _typing.Any, error: type["_keyloom.KeyloomError"], prefix: str
) -> None:
    """Raise ``error`` if a string of ``data`` cannot be written as UTF-8.

    JSON and YAML escapes such as ``\\ud800`` decode to a lone surrogate,
    which no UTF-8 file can hold. The walk is iterative and visits every
    container once, so neither deep nesting nor recursive aliases stop it.
    """
    pending = [data]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise error(
                    f"{prefix}: a string contains a lone surrogate, which "
                    "UTF-8 cannot encode"
                ) from exc
        elif isinstance(item, (_abc.Mapping, list)):
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, _abc.Mapping):
                pending.extend(item.keys())
                pending.extend(item.values())
            else:
                pending.extend(item)


def detect_syntax(*, path: str | _pathlib.Path) -> str:
    suffix = _pathlib.Path(path).suffix.lower()
    if suffix not in _SUFFIXES:
        raise _keyloom.UnsupportedFormat(
            f"unsupported file format: {suffix or '<none>'}"
        )
    return _SUFFIXES[suffix]


def _unique_json_object(pairs: list[tuple[str, _typing.Any]]) -> dict:
    """Reject duplicate JSON members, including those nested in arrays.

    Do not include the key or value in errors: either can be a secret.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _parse_json(*, text: str) -> _typing.Any:
    return _json.loads(text, object_pairs_hook=_unique_json_object)


def load_text(*, text: str, syntax: str) -> _typing.Any:
    if syntax not in _SUFFIXES.values():
        raise _keyloom.UnsupportedFormat(f"unsupported format: {syntax}")
    try:
        if syntax == "toml":
            data = _tomlkit.parse(text)
        elif syntax == "yaml":
            data = _korml_yaml.read(text=text, roundtrip=True)
        else:
            data = _parse_json(text=text)
    except ValueError as exc:
        message = _describe(error=exc, syntax=syntax)
        raise _keyloom.ParseError(message) from exc
    check_strings(
        data=data, error=_keyloom.ParseError, prefix=f"invalid {syntax.upper()}"
    )
    return data


def dump_text(*, data: _typing.Any, syntax: str) -> str:
    if syntax == "toml":
        return _tomlkit.dumps(data)
    if syntax == "yaml":
        if isinstance(data, (_korml_yaml._YamlMap, _korml_yaml._YamlList)):
            return _korml_yaml.write(data=data)
        return _korml_yaml.dump(data=data)
    if syntax == "json":
        return _json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    raise _keyloom.UnsupportedFormat(f"unsupported format: {syntax}")


def _read(*, path: _pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise _keyloom.ParseError(f"not valid UTF-8: {exc}") from exc


def load_plain(*, path: str | _pathlib.Path) -> _typing.Any:
    """Parse a file into plain dicts, lists and scalars."""
    path = _pathlib.Path(path)
    syntax = detect_syntax(path=path)
    text = _read(path=path)
    try:
        if syntax == "toml":
            data = _tomllib.loads(text)
        elif syntax == "yaml":
            data = _korml_yaml.read(text=text, roundtrip=False)
        else:
            data = _parse_json(text=text)
    except ValueError as exc:
        message = _describe(error=exc, syntax=syntax)
        raise _keyloom.ParseError(message) from exc
    check_strings(
        data=data, error=_keyloom.ParseError, prefix=f"invalid {syntax.upper()}"
    )
    return data


def load_file(*, path: str | _pathlib.Path) -> tuple[_typing.Any, str]:
    """Parse a file for round-tripping; return the document and its syntax."""
    path = _pathlib.Path(path)
    syntax = detect_syntax(path=path)
    text = _read(path=path)
    return load_text(text=text, syntax=syntax), syntax
