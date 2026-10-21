# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""The ``__keyloom__`` marker convention on parsed data trees.

A mapping that contains the reserved ``__keyloom__`` key is a secret
wrapper. Inside a file at rest, its ``value`` must be an encrypted envelope;
plaintext there is an error everywhere except in ``encrypt_secrets``, which
is the only operation that turns it into an envelope. A wrapper whose
``value`` is the reserved ``PLACEHOLDER`` string marks where a secret will
go: ``encrypt_secrets`` asks for it, so it never exists in the file as
plaintext.
"""

import collections.abc as _abc
import json as _json
import re as _re
import typing as _typing

import keyloom as _keyloom
import keyloom._envelope as _envelope
import keyloom._errors as _errors

MARKER_KEY = "__keyloom__"
MARKER_VALUE = "secret"
VALUE_KEY = "value"
PLACEHOLDER = "__keyloom__secret__"

_FIELDS = frozenset({MARKER_KEY, VALUE_KEY})

Location = tuple[str | int, ...]

# Called once per placeholder with its rendered location; returns its value.
Prompt = _abc.Callable[[str], _typing.Any]

_BARE_KEY = _re.compile(r"[A-Za-z0-9_-]+")


def format_location(*, location: Location) -> str:
    """Render a path into the data tree, such as ``git."a.b".token[0]``."""
    if not location:
        return "<document>"
    text = ""
    for part in location:
        if isinstance(part, int):
            text += f"[{part}]"
            continue
        key = str(part)
        if not _BARE_KEY.fullmatch(key):
            key = _json.dumps(key, ensure_ascii=False)
        text += f".{key}" if text else key
    return text


def secret(*, value: _typing.Any) -> dict[str, _typing.Any]:
    """Mark a value as a secret, for data passed to ``store``."""
    return {MARKER_KEY: MARKER_VALUE, VALUE_KEY: value}


def is_secret(*, value: _typing.Any) -> bool:
    """Return whether ``value`` is a secret wrapper, valid or not."""
    return isinstance(value, _abc.Mapping) and MARKER_KEY in value


def validate_secret(*, value: _abc.Mapping) -> None:
    """Raise InvalidSecret unless the wrapper is a valid secret.

    ``__keyloom__`` is reserved: a wrapper must use the ``secret`` marker
    and contain a ``value`` field, and nothing else.
    """
    marker = value.get(MARKER_KEY)
    if marker != MARKER_VALUE:
        raise _keyloom.InvalidSecret(
            f"unsupported {MARKER_KEY} marker: {marker!r}"
        )
    unknown = sorted(str(key) for key in value if key not in _FIELDS)
    if unknown:
        raise _keyloom.InvalidSecret(
            f"unexpected field in {MARKER_KEY} secret: {unknown[0]!r}"
        )
    if VALUE_KEY not in value:
        raise _keyloom.InvalidSecret(
            f"{MARKER_KEY} secret is missing {VALUE_KEY!r}"
        )


def is_placeholder(*, wrapper: _abc.Mapping) -> bool:
    """Return whether a valid wrapper holds the placeholder value."""
    return wrapper[VALUE_KEY] == PLACEHOLDER


def _missing() -> "_keyloom.MissingSecret":
    return _keyloom.MissingSecret(
        "secret is a placeholder; run keyloom encrypt to enter it"
    )


def _children(*, value: _typing.Any) -> _typing.Iterator[str | int]:
    if isinstance(value, _abc.MutableMapping):
        yield from list(value.keys())
    elif isinstance(value, _abc.MutableSequence):
        yield from range(len(value))


def _wrappers(
    *, value: _typing.Any, location: Location
) -> _typing.Iterator[tuple[Location, _typing.Any]]:
    """Yield every secret wrapper in the tree with its location."""
    if is_secret(value=value):
        yield location, value
        return
    for child in _children(value=value):
        yield from _wrappers(value=value[child], location=(*location, child))


def _encrypted(*, wrapper: _abc.Mapping) -> str:
    """Return the envelope of a wrapper, or raise why there is none."""
    validate_secret(value=wrapper)
    if is_placeholder(wrapper=wrapper):
        raise _missing()
    secret = wrapper[VALUE_KEY]
    if not _envelope.is_encrypted(value=secret):
        raise _keyloom.PlaintextSecret(
            "secret is not encrypted; run keyloom encrypt"
        )
    return secret


def encrypt_secrets(
    *, data: _typing.Any, password: str, algorithm: str, prompt: Prompt | None
) -> int:
    """Encrypt every plaintext secret and placeholder in place.

    Existing envelopes are decrypted with ``password`` first, to verify it,
    so one file cannot accumulate secrets encrypted with different passwords
    and nobody is asked for a secret before a wrong password is detected.
    They keep their algorithm. Plaintext values, the password and the
    algorithm are checked next. Then ``prompt`` is called for every
    placeholder, in document order; without ``prompt``, a placeholder raises
    MissingSecret. Every value is encrypted only after all were entered.
    Return how many secrets were encrypted.
    """
    pending = []
    for location, wrapper in _wrappers(value=data, location=()):
        with _errors.context(prefix=format_location(location=location)):
            validate_secret(value=wrapper)
            if is_placeholder(wrapper=wrapper):
                pending.append((location, wrapper))
                continue
            secret = wrapper[VALUE_KEY]
            if _envelope.is_encrypted(value=secret):
                _envelope.decrypt_value(value=secret, password=password)
            else:
                _envelope.check_plaintext(value=secret)
                pending.append((location, wrapper))
    if pending:
        _envelope.check_parameters(password=password, algorithm=algorithm)

    values = []
    for location, wrapper in pending:
        where = format_location(location=location)
        with _errors.context(prefix=where):
            if not is_placeholder(wrapper=wrapper):
                values.append(wrapper[VALUE_KEY])
            elif prompt is None:
                raise _missing()
            else:
                value = prompt(where)
                _envelope.check_plaintext(value=value)
                values.append(value)

    for (location, wrapper), value in zip(pending, values, strict=True):
        with _errors.context(prefix=format_location(location=location)):
            wrapper[VALUE_KEY] = _envelope.encrypt_value(
                value=value, password=password, algorithm=algorithm
            )
    return len(pending)


def decrypt_secrets(*, data: _typing.Any, password: str) -> None:
    """Decrypt every secret in place; plaintext secrets are an error."""
    for location, wrapper in _wrappers(value=data, location=()):
        with _errors.context(prefix=format_location(location=location)):
            encoded = _encrypted(wrapper=wrapper)
            wrapper[VALUE_KEY] = _envelope.decrypt_value(
                value=encoded, password=password
            )


def find_problems(*, data: _typing.Any, password: str | None) -> list[str]:
    """Return a message for every secret that is not properly encrypted.

    Without a password only the structure is checked: every wrapper must be
    valid and hold a well-formed envelope. With a password every envelope is
    also decrypted.
    """
    problems = []
    for location, wrapper in _wrappers(value=data, location=()):
        where = format_location(location=location)
        try:
            encoded = _encrypted(wrapper=wrapper)
            if password is None:
                _envelope.validate_envelope(encoded=encoded)
            else:
                _envelope.decrypt_value(value=encoded, password=password)
        except _keyloom.KeyloomError as exc:
            problems.append(f"{where}: {exc}")
    return problems


def _unwrap(*, data: _typing.Any, location: Location) -> _typing.Any:
    if is_secret(value=data):
        with _errors.context(prefix=format_location(location=location)):
            validate_secret(value=data)
            if is_placeholder(wrapper=data):
                raise _missing()
        return _unwrap(data=data[VALUE_KEY], location=location)
    for child in _children(value=data):
        item = data[child]
        replacement = _unwrap(data=item, location=(*location, child))
        # Assign only what changed, so round-trip documents keep the
        # formatting of every untouched value.
        if replacement is not item:
            data[child] = replacement
    return data


def unwrap_secrets(*, data: _typing.Any) -> _typing.Any:
    """Replace every secret wrapper by its value, in place.

    The containers are changed where they are, so a round-trip TOML or YAML
    document keeps its comments. The return value is ``data``, or the
    wrapped value if ``data`` itself is a secret wrapper.
    """
    return _unwrap(data=data, location=())
