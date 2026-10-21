# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Field-level encryption for configuration files.

A configuration file marks each secret value with a wrapper,
`{"__keyloom__": "secret", "value": ...}`. keyloom encrypts the value
in place and leaves the rest of the file readable. A wrapper whose value is
`__keyloom__secret__` is a placeholder, whose secret is entered when the
file is encrypted.
Applications read such a file with `load`; tools write one with `store` or
encrypt one with `encrypt_file`.

Everything listed in `__all__` is defined here and is the whole public API.
The modules whose names start with an underscore are the implementation.
"""

from __future__ import annotations

import typing as _typing

import keyloom._envelope as _envelope
import keyloom._files as _files
import keyloom._metadata as _metadata
import keyloom._tree as _tree

# The annotations name typing and pathlib rather than private aliases, so that
# the API reference reads naturally; they are never evaluated at run time.
if _typing.TYPE_CHECKING:
    import pathlib
    import typing

__version__ = _metadata.__version__
"""The version of the installed keyloom package."""

# ------------------------------------------------------------------------------
# Errors
# ------------------------------------------------------------------------------


class KeyloomError(Exception):
    """Base class of every failure a user can cause or fix.

    Any other exception raised by keyloom is a bug.
    """


class PasswordError(KeyloomError):
    """The vault password is empty or was not confirmed."""


class ParseError(KeyloomError):
    """A file is not valid TOML, YAML, JSON or UTF-8."""


class UnsupportedFormat(KeyloomError):
    """A file extension is not supported, or the format cannot hold the data."""


class InvalidSecret(KeyloomError):
    """A `__keyloom__` wrapper is not a valid secret."""


class PlaintextSecret(KeyloomError):
    """A secret that must be encrypted holds plaintext."""


class MissingSecret(KeyloomError):
    """A secret is a placeholder, or no value was entered for it."""


class MalformedEnvelope(KeyloomError):
    """An encrypted value is not a valid envelope."""


class UnsupportedAlgorithm(KeyloomError):
    """An algorithm name is not known to this version of keyloom."""


class DecryptionError(KeyloomError):
    """The password is wrong or the encrypted value was modified."""


class UnsafeOutput(KeyloomError):
    """Writing the output would replace the encrypted input with plaintext."""


# ------------------------------------------------------------------------------
# Configuration in applications
# ------------------------------------------------------------------------------


def load(*, path: str | pathlib.Path, password: str) -> typing.Any:
    """Read a configuration file and return it with its secrets decrypted.

    The result is made of plain dicts, lists and scalars, with every secret
    wrapper replaced by its value.

    @param path TOML, YAML or JSON file, chosen by its extension.

    @param password The vault password.

    @return The decrypted configuration.

    @throws PlaintextSecret A secret in the file is not encrypted.

    @throws MissingSecret A secret in the file is a placeholder.

    @throws DecryptionError The password is wrong or a value was modified.
    """
    return _files.load(path=path, password=password)


def store(
    *,
    path: str | pathlib.Path,
    data: typing.Any,
    password: str,
    algorithm: str,
    dangerous_allow_writing_to_symlink: bool = False,
    dangerous_allow_hard_links: bool = False,
) -> int:
    """Write data to a configuration file with its secrets encrypted.

    Mark each secret in `data` with `secret`. The file is written fresh and
    atomically: comments of an existing file are not kept, but its
    permissions are, and a new file gets mode 0600. `data` itself is not
    changed.

    @param path TOML, YAML or JSON file, chosen by its extension.

    @param data Dicts, lists and scalars, with secrets marked by `secret`.

    @param password The vault password.

    @param algorithm The algorithm for the secrets, from `algorithms`.

    @return The number of secrets encrypted.

    @param dangerous_allow_writing_to_symlink Write to the file a symbolic
    link at the output path points to, instead of raising UnsafeOutput.

    @param dangerous_allow_hard_links Replace an output that other hard links
    point to, instead of raising UnsafeOutput; the other links keep the old
    content.

    @throws MissingSecret A secret in `data` is a placeholder.

    @throws UnsupportedFormat The file format cannot hold the data.
    """
    return _files.store(
        path=path,
        data=data,
        password=password,
        algorithm=algorithm,
        safety=_files.OutputSafety(
            allow_symlink=dangerous_allow_writing_to_symlink,
            allow_hard_links=dangerous_allow_hard_links,
        ),
    )


def secret(*, value: typing.Any) -> dict[str, typing.Any]:
    """Mark a value as a secret, for the data passed to `store`.

    @param value The secret string.

    @return The wrapper `{"__keyloom__": "secret", "value": value}`.
    """
    return _tree.secret(value=value)


# ------------------------------------------------------------------------------
# Files
# ------------------------------------------------------------------------------


def encrypt_file(
    *,
    input_path: str | pathlib.Path,
    output_path: str | pathlib.Path,
    password: str,
    algorithm: str,
    prompt: typing.Callable[[str], typing.Any] | None,
    dangerous_allow_writing_to_symlink: bool = False,
    dangerous_allow_hard_links: bool = False,
) -> int:
    """Encrypt the plaintext secrets and placeholders of a configuration file.

    Pass the same path twice to encrypt in place. The output is written
    atomically and keeps the permissions of a file it replaces. A file
    without plaintext secrets or placeholders is not rewritten in place, so
    its formatting stays exactly as it was. Existing envelopes keep their
    algorithm.

    Existing envelopes are checked against `password` before `prompt` is
    called, and every value is encrypted only after all placeholders have
    one, so nothing is written if any step fails.

    @param input_path The file to read.

    @param output_path The file to write; may be `input_path`.

    @param password The vault password, also checked against existing
    envelopes.

    @param algorithm The algorithm for newly encrypted secrets.

    @param prompt Called once for every placeholder, in document order, with
    its location such as `git."gitlab.example.org".token`; returns its
    value. None makes a placeholder an error.

    @return The number of secrets encrypted, placeholders included.

    @param dangerous_allow_writing_to_symlink Write to the file a symbolic
    link at the output path points to, instead of raising UnsafeOutput.

    @param dangerous_allow_hard_links Replace an output that other hard links
    point to, instead of raising UnsafeOutput; the other links keep the old
    content.

    @throws DecryptionError An existing envelope uses another password.

    @throws MissingSecret The file has a placeholder and `prompt` is None.
    """
    return _files.encrypt_file(
        input_path=input_path,
        output_path=output_path,
        password=password,
        algorithm=algorithm,
        prompt=prompt,
        safety=_files.OutputSafety(
            allow_symlink=dangerous_allow_writing_to_symlink,
            allow_hard_links=dangerous_allow_hard_links,
        ),
    )


def decrypt_file(
    *,
    input_path: str | pathlib.Path,
    output_path: str | pathlib.Path,
    password: str,
    dangerous_allow_writing_to_symlink: bool = False,
    dangerous_allow_hard_links: bool = False,
) -> None:
    """Decrypt the secrets of a configuration file into a plaintext file.

    The wrappers are kept, so `encrypt_file` turns the output back into an
    encrypted file. The output is written atomically with mode 0600.

    @param input_path The encrypted file.

    @param output_path The plaintext file; must not be `input_path`.

    @param password The vault password.

    @param dangerous_allow_writing_to_symlink Write to the file a symbolic
    link at the output path points to, instead of raising UnsafeOutput.

    @param dangerous_allow_hard_links Replace an output that other hard links
    point to, instead of raising UnsafeOutput; the other links keep the old
    content.

    @throws UnsafeOutput The output is the input file, directly or through a
    link.

    @throws PlaintextSecret A secret in the file is not encrypted.

    @throws MissingSecret A secret in the file is a placeholder.
    """
    _files.decrypt_file(
        input_path=input_path,
        output_path=output_path,
        password=password,
        safety=_files.OutputSafety(
            allow_symlink=dangerous_allow_writing_to_symlink,
            allow_hard_links=dangerous_allow_hard_links,
        ),
    )


def reencrypt_file(
    *,
    input_path: str | pathlib.Path,
    output_path: str | pathlib.Path,
    password: str,
    new_password: str,
    algorithm: str,
    dangerous_allow_writing_to_symlink: bool = False,
    dangerous_allow_hard_links: bool = False,
) -> int:
    """Encrypt every secret of a file again, without writing plaintext.

    Every secret is decrypted with `password` and encrypted with
    `new_password` and `algorithm`, in memory. Pass the same password twice
    to change only the algorithm, and the same path twice to work in place.

    @param input_path The encrypted file.

    @param output_path The file to write; may be `input_path`.

    @param password The current vault password.

    @param new_password The vault password to encrypt with.

    @param algorithm The algorithm to encrypt with.

    @return The number of secrets encrypted again.

    @param dangerous_allow_writing_to_symlink Write to the file a symbolic
    link at the output path points to, instead of raising UnsafeOutput.

    @param dangerous_allow_hard_links Replace an output that other hard links
    point to, instead of raising UnsafeOutput; the other links keep the old
    content.

    @throws PlaintextSecret A secret in the file is not encrypted.

    @throws MissingSecret A secret in the file is a placeholder.
    """
    return _files.reencrypt_file(
        input_path=input_path,
        output_path=output_path,
        password=password,
        new_password=new_password,
        algorithm=algorithm,
        safety=_files.OutputSafety(
            allow_symlink=dangerous_allow_writing_to_symlink,
            allow_hard_links=dangerous_allow_hard_links,
        ),
    )


# ------------------------------------------------------------------------------
# Single values
# ------------------------------------------------------------------------------


def encrypt_value(*, value: typing.Any, password: str, algorithm: str) -> str:
    """Encrypt one value into a self-contained envelope string.

    The envelope names its algorithm and carries its own salt and nonce, so
    it can be decrypted wherever it is copied.

    @param value The secret string.

    @param password The vault password.

    @param algorithm The algorithm, from `algorithms`.

    @return An envelope such as `$KEYLOOM;1;argon2;s=...;n=...;c=...`.

    @throws InvalidSecret The value is not a string, or is a string that
    starts with `$KEYLOOM;`.

    @throws UnsupportedAlgorithm The algorithm is not known.
    """
    return _envelope.encrypt_value(
        value=value, password=password, algorithm=algorithm
    )


def decrypt_value(*, value: str, password: str) -> typing.Any:
    """Authenticate and decrypt one envelope string.

    @param value The envelope.

    @param password The vault password.

    @return The original string.

    @throws DecryptionError The password is wrong or the value was modified.

    @throws MalformedEnvelope The value is not a valid envelope.
    """
    return _envelope.decrypt_value(value=value, password=password)


def algorithms() -> tuple[str, ...]:
    """Return the names of the supported algorithms.

    An algorithm name fixes every cryptographic parameter; new parameters
    come as a new name.

    @return The names, such as `("argon2",)`.
    """
    return _envelope.algorithms()


__all__ = [
    "DecryptionError",
    "InvalidSecret",
    "KeyloomError",
    "MalformedEnvelope",
    "MissingSecret",
    "ParseError",
    "PasswordError",
    "PlaintextSecret",
    "UnsafeOutput",
    "UnsupportedAlgorithm",
    "UnsupportedFormat",
    "__version__",
    "algorithms",
    "decrypt_file",
    "decrypt_value",
    "encrypt_file",
    "encrypt_value",
    "load",
    "reencrypt_file",
    "secret",
    "store",
]
