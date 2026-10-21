# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""File-level operations behind the public API and the command line."""

import collections.abc as _abc
import contextlib as _contextlib
import copy as _copy
import dataclasses as _dataclasses
import os as _os
import pathlib as _pathlib
import secrets as _secrets
import stat as _stat
import tempfile as _tempfile
import typing as _typing

import tomlkit as _tomlkit
import tomlkit.exceptions as _tomlkit_exceptions

import keyloom as _keyloom
import keyloom._errors as _errors
import keyloom._formats as _formats
import keyloom._tree as _tree

PathLike = str | _pathlib.Path


@_dataclasses.dataclass(frozen=True)
class OutputSafety:
    """Which unsafe outputs a write may go ahead with anyway.

    Both are refused by default. A symbolic link at the output path would
    redirect the output to any file the user can write. An output with other
    hard links is replaced by a new file, so the other links keep the old
    content, which for in-place encryption is the plaintext.
    """

    allow_symlink: bool
    allow_hard_links: bool


@_contextlib.contextmanager
def _destination(
    *, path: _pathlib.Path, safety: OutputSafety
) -> _typing.Iterator[tuple[_pathlib.Path, int | None]]:
    """Resolve output symlinks once and pin the destination directory.

    A symbolic link at the output path itself is refused unless
    safety.allow_symlink; symlinked parent directories are followed, since
    whoever controls a parent directory controls the path anyway. The
    directory fd allows stat, temporary-file creation and replacement to act
    on the same directory, even if a parent symlink is later retargeted.
    """
    if path.is_symlink() and not safety.allow_symlink:
        raise _keyloom.UnsafeOutput(
            f"refusing to write through a symbolic link: {path}; pass "
            "--dangerous-allow-writing-to-symlink to write to its target"
        )
    resolved = path.resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    directory_fd = None
    if _os.name == "posix":
        directory_fd = _os.open(
            resolved.parent, _os.O_RDONLY | getattr(_os, "O_DIRECTORY", 0)
        )
    try:
        yield resolved, directory_fd
    finally:
        if directory_fd is not None:
            _os.close(directory_fd)


def _target_stat(
    *, path: _pathlib.Path, directory_fd: int | None
) -> _os.stat_result | None:
    try:
        if directory_fd is not None:
            info = _os.stat(
                path.name, dir_fd=directory_fd, follow_symlinks=False
            )
        else:
            info = path.lstat()
    except FileNotFoundError:
        return None
    # A symlink appearing after the original resolution must not be followed
    # or silently replaced. The original symlink, if any, remains untouched.
    if _stat.S_ISLNK(info.st_mode):
        raise _keyloom.UnsafeOutput(
            f"output destination changed to a symlink: {path}"
        )
    return info


def _check_hard_links(
    *, path: _pathlib.Path, info: _os.stat_result | None, safety: OutputSafety
) -> None:
    """Refuse to replace a file that other hard links still point to."""
    if info is None or info.st_nlink <= 1 or safety.allow_hard_links:
        return
    others = info.st_nlink - 1
    raise _keyloom.UnsafeOutput(
        f"{path} has {others} other hard link{'s' if others > 1 else ''}, "
        "which would keep its old content; pass --dangerous-allow-hard-links "
        "to write anyway"
    )


def _atomic_write(
    *,
    path: _pathlib.Path,
    directory_fd: int | None,
    text: str,
    mode: int | None,
    safety: OutputSafety,
    protected_identity: tuple[int, int] | None = None,
) -> None:
    """Atomically replace a pinned output, never writing plaintext in place.

    If ``mode`` is None, preserve an existing output's permission bits. The
    temp file begins at 0600, independently of the eventual output mode.
    """
    temp_name = f".{path.name}.{_secrets.token_hex(16)}"
    if directory_fd is None:
        # Portable fallback on platforms without POSIX dir_fd operations.
        fd, temp = _tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = _pathlib.Path(temp)
        try:
            with _os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                _os.fsync(handle.fileno())
            info = _target_stat(path=path, directory_fd=None)
            _check_hard_links(path=path, info=info, safety=safety)
            if (
                protected_identity is not None
                and info is not None
                and (info.st_dev, info.st_ino) == protected_identity
            ):
                raise _keyloom.UnsafeOutput(
                    "refusing to write plaintext over the encrypted "
                    f"input: {path}"
                )
            permissions = (
                (info.st_mode & 0o777)
                if mode is None and info is not None
                else (mode if mode is not None else 0o600)
            )
            tmp.chmod(permissions)
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)
        return

    flags = (
        _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | getattr(_os, "O_CLOEXEC", 0)
    )
    fd = _os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
    try:
        with _os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            _os.fsync(handle.fileno())
        info = _target_stat(path=path, directory_fd=directory_fd)
        _check_hard_links(path=path, info=info, safety=safety)
        if (
            protected_identity is not None
            and info is not None
            and (info.st_dev, info.st_ino) == protected_identity
        ):
            raise _keyloom.UnsafeOutput(
                f"refusing to write plaintext over the encrypted input: {path}"
            )
        permissions = (
            (info.st_mode & 0o777)
            if mode is None and info is not None
            else (mode if mode is not None else 0o600)
        )
        _os.chmod(temp_name, permissions, dir_fd=directory_fd)
        _os.replace(
            temp_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
    finally:
        with _contextlib.suppress(FileNotFoundError):
            _os.unlink(temp_name, dir_fd=directory_fd)


def _nesting() -> _typing.ContextManager[None]:
    return _errors.nesting(error=_keyloom.ParseError)


def _same_file(*, first: _pathlib.Path, second: _pathlib.Path) -> bool:
    if first.resolve() == second.resolve():
        return True
    # Hard links resolve to different paths but share one inode.
    try:
        return first.samefile(second)
    except FileNotFoundError:
        return False


# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------


def load(*, path: PathLike, password: str) -> _typing.Any:
    """Load a file, decrypt its secrets and return a plain structure.

    The result contains only dicts, lists and scalars, with every secret
    wrapper replaced by its value. Every secret must be encrypted; plaintext
    raises PlaintextSecret.
    """
    with _errors.context(prefix=str(path)), _nesting():
        data = _formats.load_plain(path=path)
        _tree.decrypt_secrets(data=data, password=password)
        return _tree.unwrap_secrets(data=data)


def encrypt_file(
    *,
    input_path: PathLike,
    output_path: PathLike,
    password: str,
    algorithm: str,
    prompt: _tree.Prompt | None,
    safety: OutputSafety,
) -> int:
    """Encrypt the plaintext secrets and placeholders of a file.

    Return how many secrets were encrypted. ``prompt`` supplies the value of
    each placeholder; see ``encrypt_secrets``. Pass the same path twice to
    encrypt in place. The output is written atomically and keeps the
    permissions of a file it replaces. A file without plaintext secrets or
    placeholders is not rewritten in place, so its formatting stays
    untouched.
    """
    source = _pathlib.Path(input_path)
    target = _pathlib.Path(output_path)
    with _errors.context(prefix=str(source)), _nesting():
        data, syntax = _formats.load_file(path=source)
        count = _tree.encrypt_secrets(
            data=data, password=password, algorithm=algorithm, prompt=prompt
        )
        if count == 0 and _same_file(first=source, second=target):
            return count
        text = _formats.dump_text(data=data, syntax=syntax)
    with _destination(path=target, safety=safety) as (
        resolved,
        directory_fd,
    ):
        _atomic_write(
            path=resolved,
            directory_fd=directory_fd,
            text=text,
            mode=None,
            safety=safety,
        )
    return count


def decrypt_file(
    *,
    input_path: PathLike,
    output_path: PathLike,
    password: str,
    safety: OutputSafety,
) -> None:
    """Decrypt the secrets of a file into a plaintext file.

    The wrappers are kept, so encrypt_file turns the output back into the
    encrypted file. The output is written atomically with mode 0600, and
    writing onto the input file itself is refused.
    """
    decrypt_to(
        input_path=input_path,
        output_path=output_path,
        password=password,
        unwrap=False,
        safety=safety,
    )


def reencrypt_file(
    *,
    input_path: PathLike,
    output_path: PathLike,
    password: str,
    new_password: str,
    algorithm: str,
    safety: OutputSafety,
) -> int:
    """Encrypt every secret again; return how many there were.

    Every secret is decrypted with ``password`` and encrypted with
    ``new_password`` and ``algorithm``, in memory, so no plaintext touches
    the disk. Pass the same password twice to change only the algorithm, and
    the same path twice to work in place. Every secret must be encrypted.
    """
    source = _pathlib.Path(input_path)
    target = _pathlib.Path(output_path)
    with _errors.context(prefix=str(source)), _nesting():
        data, syntax = _formats.load_file(path=source)
        _tree.decrypt_secrets(data=data, password=password)
        count = _tree.encrypt_secrets(
            data=data, password=new_password, algorithm=algorithm, prompt=None
        )
        text = _formats.dump_text(data=data, syntax=syntax)
    with _destination(path=target, safety=safety) as (
        resolved,
        directory_fd,
    ):
        _atomic_write(
            path=resolved,
            directory_fd=directory_fd,
            text=text,
            mode=None,
            safety=safety,
        )
    return count


def _inline_wrappers(*, data: _typing.Any) -> _typing.Any:
    """Turn secret wrappers into TOML inline tables, which read better."""
    if _tree.is_secret(value=data):
        table = _tomlkit.inline_table()
        table.update(data)
        return table
    if isinstance(data, _abc.Mapping):
        return {key: _inline_wrappers(data=item) for key, item in data.items()}
    if isinstance(data, list):
        return [_inline_wrappers(data=item) for item in data]
    return data


def store(
    *,
    path: PathLike,
    data: _typing.Any,
    password: str,
    algorithm: str,
    safety: OutputSafety,
) -> int:
    """Write ``data`` to a file with its secrets encrypted.

    Mark secrets in ``data`` with ``secret(value=...)``; return how many were
    encrypted. The syntax follows the file extension. The file is written
    fresh and atomically, so comments of an existing file are not kept, but
    its permissions are. ``data`` itself is not changed.
    """
    target = _pathlib.Path(path)
    syntax = _formats.detect_syntax(path=target)
    with (
        _errors.context(prefix=str(target)),
        _errors.nesting(error=_keyloom.UnsupportedFormat),
    ):
        data = _copy.deepcopy(data)
        count = _tree.encrypt_secrets(
            data=data, password=password, algorithm=algorithm, prompt=None
        )
        # After encryption, so a secret's own problem is reported as such.
        _formats.check_strings(
            data=data,
            error=_keyloom.UnsupportedFormat,
            prefix=f"{syntax.upper()} cannot store this data",
        )
        if syntax == "toml":
            data = _inline_wrappers(data=data)
        try:
            text = _formats.dump_text(data=data, syntax=syntax)
            text.encode("utf-8")
        except _tomlkit_exceptions.ConvertError as exc:
            raise _keyloom.UnsupportedFormat(
                f"TOML cannot store this data: {exc}"
            ) from exc
        except (TypeError, ValueError) as exc:
            # These messages can quote the data, so they are not repeated.
            raise _keyloom.UnsupportedFormat(
                f"{syntax.upper()} cannot store this data: a value has an "
                "unsupported type, is a lone surrogate or is an integer with "
                "too many digits"
            ) from exc
    with _destination(path=target, safety=safety) as (
        resolved,
        directory_fd,
    ):
        _atomic_write(
            path=resolved,
            directory_fd=directory_fd,
            text=text,
            mode=None,
            safety=safety,
        )
    return count


# ------------------------------------------------------------------------------
# Command-line helpers
# ------------------------------------------------------------------------------


def decrypt_text(*, path: PathLike, password: str, unwrap: bool) -> str:
    """Decrypt a file and return the serialized plaintext document."""
    with _errors.context(prefix=str(path)), _nesting():
        data, syntax = _formats.load_file(path=path)
        _tree.decrypt_secrets(data=data, password=password)
        if unwrap:
            data = _tree.unwrap_secrets(data=data)
        return _formats.dump_text(data=data, syntax=syntax)


def decrypt_to(
    *,
    input_path: PathLike,
    output_path: PathLike,
    password: str,
    unwrap: bool,
    safety: OutputSafety,
) -> None:
    """Write the decrypted document to a 0600 file other than the input."""
    source = _pathlib.Path(input_path)
    target = _pathlib.Path(output_path)
    # Pin the destination before decrypting. Retargeting an output or parent
    # symlink cannot redirect the subsequent atomic replacement.
    with _destination(path=target, safety=safety) as (
        resolved,
        directory_fd,
    ):
        if _same_file(first=source, second=resolved):
            raise _keyloom.UnsafeOutput(
                "refusing to write plaintext over the encrypted "
                f"input: {target}"
            )
        source_info = source.stat()
        text = decrypt_text(path=source, password=password, unwrap=unwrap)
        _atomic_write(
            path=resolved,
            directory_fd=directory_fd,
            text=text,
            mode=0o600,
            safety=safety,
            protected_identity=(source_info.st_dev, source_info.st_ino),
        )


def check_file(*, path: PathLike, password: str | None) -> list[str]:
    """Return a message for every secret of a file that is not encrypted.

    With ``password`` None only the structure is checked; otherwise every
    secret is also decrypted. Each message starts with the file name.
    """
    with _errors.context(prefix=str(path)), _nesting():
        data, _syntax = _formats.load_file(path=path)
        problems = _tree.find_problems(data=data, password=password)
    return [f"{path}: {problem}" for problem in problems]
