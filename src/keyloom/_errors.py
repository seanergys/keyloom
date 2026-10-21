# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Error helpers. The exception classes are defined in the package itself."""

import contextlib as _contextlib
import typing as _typing

import keyloom as _keyloom


@_contextlib.contextmanager
def context(*, prefix: str) -> _typing.Iterator[None]:
    """Prefix the message of any KeyloomError raised inside the block.

    The error keeps its type, so callers can still tell failures apart.
    """
    try:
        yield
    except _keyloom.KeyloomError as exc:
        raise type(exc)(f"{prefix}: {exc}") from exc


@_contextlib.contextmanager
def nesting(*, error: type["_keyloom.KeyloomError"]) -> _typing.Iterator[None]:
    """Turn running out of stack on deeply nested data into ``error``.

    The parsers and the walks over a document recurse once per level of
    nesting, so a document nested deeply enough exceeds Python's recursion
    limit.
    """
    try:
        yield
    except RecursionError as exc:
        raise error("data is nested too deeply") from exc
