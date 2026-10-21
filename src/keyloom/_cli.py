# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""The keyloom command-line interface.

No exception escapes a command. It succeeds; or it ends a failure the user
can cause or fix with a one-line message and exit status 1, or invalid usage
with argparse's message and status 2; or it treats any other exception as a
bug in keyloom, prints a report to paste into an issue, and exits with
status 70.
"""

import argparse as _argparse
import errno as _errno
import getpass as _getpass
import importlib.metadata as _importlib_metadata
import os as _os
import pathlib as _pathlib
import platform as _platform
import sys as _sys
import traceback as _traceback
import warnings as _warnings

import keyloom as _keyloom
import keyloom._envelope as _envelope
import keyloom._files as _files
import keyloom._metadata as _metadata

# sysexits.h: an internal software error has been detected.
EX_SOFTWARE = 70
EX_INTERRUPTED = 130
# The status of a process ended by SIGPIPE, as when the reader of its output
# goes away, like `keyloom decrypt FILE | head`.
EX_BROKEN_PIPE = 141

_COMMANDS = ("encrypt", "decrypt", "reencrypt", "check")


def _stderr(*, text: str) -> None:
    """Write one message to standard error, which may be closed."""
    stream = _sys.stderr
    if stream is None:
        return
    try:
        stream.write(text + "\n")
        stream.flush()
    except (OSError, ValueError):
        pass


def _stdout(*, text: str) -> None:
    """Write text to standard output as UTF-8, the encoding of the files.

    Decrypted documents are written as bytes, so a terminal or pipe with
    another encoding receives them unchanged instead of failing.
    """
    stream = _sys.stdout
    if stream is None:
        raise OSError(_errno.EBADF, "standard output is closed")
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        stream.write(text)
        return
    stream.flush()
    buffer.write(text.encode("utf-8"))
    buffer.flush()


class _NoTerminal(Exception):
    """There is no terminal to read a hidden line from."""


def _hidden(*, prompt: str) -> str:
    """Read one line from the terminal without echo.

    Without a terminal, getpass falls back to standard input and echoes what
    is typed, with only a warning. That warning is turned into _NoTerminal,
    so a password or a secret is only ever read hidden.
    """
    with _warnings.catch_warnings():
        _warnings.simplefilter("error", _getpass.GetPassWarning)
        try:
            return _getpass.getpass(prompt)
        except _getpass.GetPassWarning as exc:
            raise _NoTerminal from exc


def _prompt(*, prompt: str, confirm: bool) -> str:
    try:
        first = _hidden(prompt=prompt)
        if not first:
            raise _keyloom.PasswordError("vault password must not be empty")
        if confirm:
            second = _hidden(prompt=f"Confirm {prompt[0].lower()}{prompt[1:]}")
            if first != second:
                raise _keyloom.PasswordError("vault passwords do not match")
    except _NoTerminal as exc:
        raise _keyloom.PasswordError(
            "there is no terminal to enter the vault password; use "
            "--password-stdin or --password-file"
        ) from exc
    except EOFError as exc:
        raise _keyloom.PasswordError("no vault password was entered") from exc
    return first


def _enter_secret(location: str) -> str:
    """Ask for the value of the placeholder at ``location``, twice."""
    try:
        first = _hidden(prompt=f"Secret for {location}: ")
        if not first:
            raise _keyloom.MissingSecret("secret must not be empty")
        second = _hidden(prompt=f"Confirm secret for {location}: ")
    except _NoTerminal as exc:
        raise _keyloom.MissingSecret(
            "secret is a placeholder, and there is no terminal to enter it"
        ) from exc
    except EOFError as exc:
        raise _keyloom.MissingSecret("no secret was entered") from exc
    if first != second:
        raise _keyloom.InvalidSecret("entered secrets do not match")
    return first


def _strip_line_ending(*, text: str) -> str:
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def _read_password_file(*, path: _pathlib.Path) -> str:
    """Read a password file, warning if other users can access it."""
    if _os.name == "posix":
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            _stderr(
                text=f"keyloom: warning: {path} is accessible to other users "
                f"(mode {mode:04o}); restrict it with chmod 600"
            )
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _keyloom.PasswordError(
            f"{path}: the vault password is not valid UTF-8"
        ) from exc
    return _strip_line_ending(text=text)


def _read_password_stdin() -> str:
    stream = _sys.stdin
    if stream is None:
        raise _keyloom.PasswordError("standard input is closed")
    buffer = getattr(stream, "buffer", None)
    try:
        if buffer is None:
            return _strip_line_ending(text=stream.readline())
        return _strip_line_ending(text=buffer.readline().decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise _keyloom.PasswordError(
            "the vault password on standard input is not valid UTF-8"
        ) from exc


def _password(*, args: _argparse.Namespace, confirm: bool) -> str:
    if args.password_stdin:
        password = _read_password_stdin()
    elif args.password_file is not None:
        password = _read_password_file(path=args.password_file)
    else:
        return _prompt(prompt="Vault password: ", confirm=confirm)

    if not password:
        raise _keyloom.PasswordError("vault password must not be empty")
    return password


def _add_password_arguments(*, parser: _argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the vault password from stdin instead of prompting",
    )
    source.add_argument(
        "--password-file",
        type=_pathlib.Path,
        metavar="FILE",
        help="read the vault password from FILE instead of prompting",
    )


def _add_output_safety_arguments(*, parser: _argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dangerous-allow-writing-to-symlink",
        action="store_true",
        help=(
            "if the output is a symbolic link, replace the file it points to "
            "instead of refusing"
        ),
    )
    parser.add_argument(
        "--dangerous-allow-hard-links",
        action="store_true",
        help=(
            "replace an output that other hard links point to; they keep the "
            "old content"
        ),
    )


def _output_safety(*, args: _argparse.Namespace) -> _files.OutputSafety:
    return _files.OutputSafety(
        allow_symlink=args.dangerous_allow_writing_to_symlink,
        allow_hard_links=args.dangerous_allow_hard_links,
    )


def _parser() -> _argparse.ArgumentParser:
    parser = _argparse.ArgumentParser(
        prog="keyloom",
        description="Encrypt configuration values marked as secrets.",
    )
    parser.add_argument(
        "--version", action="version", version=_metadata.__version__
    )
    sub = parser.add_subparsers(dest="command", required=True)

    encrypt = sub.add_parser(
        "encrypt", help="encrypt plaintext secrets and enter placeholders"
    )
    encrypt.add_argument("file", type=_pathlib.Path)
    encrypt.add_argument("-o", "--output", type=_pathlib.Path)
    encrypt.add_argument(
        "--algorithm",
        choices=_envelope.algorithms(),
        default=_envelope.DEFAULT_ALGORITHM,
        help="algorithm for newly encrypted secrets (default: %(default)s)",
    )
    _add_password_arguments(parser=encrypt)
    _add_output_safety_arguments(parser=encrypt)

    decrypt = sub.add_parser("decrypt", help="decrypt tagged secrets to stdout")
    decrypt.add_argument("file", type=_pathlib.Path)
    decrypt.add_argument(
        "--unwrap",
        action="store_true",
        help="remove __keyloom__ wrappers in the emitted plaintext",
    )
    decrypt.add_argument(
        "-o",
        "--output",
        type=_pathlib.Path,
        help="write plaintext to a file instead of stdout",
    )
    _add_password_arguments(parser=decrypt)
    _add_output_safety_arguments(parser=decrypt)

    reencrypt = sub.add_parser(
        "reencrypt", help="encrypt every secret again, without plaintext"
    )
    reencrypt.add_argument("file", type=_pathlib.Path)
    reencrypt.add_argument("-o", "--output", type=_pathlib.Path)
    reencrypt.add_argument(
        "--algorithm",
        choices=_envelope.algorithms(),
        default=_envelope.DEFAULT_ALGORITHM,
        help="algorithm to encrypt with (default: %(default)s)",
    )
    _add_password_arguments(parser=reencrypt)
    _add_output_safety_arguments(parser=reencrypt)
    new = reencrypt.add_mutually_exclusive_group()
    new.add_argument(
        "--change-password",
        action="store_true",
        help="prompt for a new vault password",
    )
    new.add_argument(
        "--new-password-file",
        type=_pathlib.Path,
        metavar="FILE",
        help="read the new vault password from FILE",
    )

    check = sub.add_parser(
        "check", help="fail if any tagged secret is not encrypted"
    )
    check.add_argument("files", type=_pathlib.Path, nargs="+", metavar="FILE")
    check.add_argument(
        "--verify",
        action="store_true",
        help="also decrypt every secret with the vault password",
    )
    _add_password_arguments(parser=check)

    return parser


def _secrets(*, count: int) -> str:
    return f"{count} secret" if count == 1 else f"{count} secrets"


def _encrypt(*, args: _argparse.Namespace) -> int:
    password = _password(args=args, confirm=True)
    count = _files.encrypt_file(
        input_path=args.file,
        output_path=args.output or args.file,
        password=password,
        algorithm=args.algorithm,
        prompt=_enter_secret,
        safety=_output_safety(args=args),
    )
    if count == 0 and args.output is None:
        _stdout(text=f"{args.file}: nothing to encrypt\n")
    else:
        target = args.output or args.file
        _stdout(text=f"{target}: encrypted {_secrets(count=count)}\n")
    return 0


def _decrypt(*, args: _argparse.Namespace) -> int:
    password = _password(args=args, confirm=False)
    if args.output:
        _files.decrypt_to(
            input_path=args.file,
            output_path=args.output,
            password=password,
            unwrap=args.unwrap,
            safety=_output_safety(args=args),
        )
    else:
        text = _files.decrypt_text(
            path=args.file, password=password, unwrap=args.unwrap
        )
        _stdout(text=text)
    return 0


def _new_password(*, args: _argparse.Namespace, password: str) -> str:
    if args.change_password:
        return _prompt(prompt="New vault password: ", confirm=True)
    if args.new_password_file is not None:
        new_password = _read_password_file(path=args.new_password_file)
        if not new_password:
            raise _keyloom.PasswordError("vault password must not be empty")
        return new_password
    return password


def _reencrypt(*, args: _argparse.Namespace) -> int:
    password = _password(args=args, confirm=False)
    new_password = _new_password(args=args, password=password)
    target = args.output or args.file
    count = _files.reencrypt_file(
        input_path=args.file,
        output_path=target,
        password=password,
        new_password=new_password,
        algorithm=args.algorithm,
        safety=_output_safety(args=args),
    )
    _stdout(text=f"{target}: re-encrypted {_secrets(count=count)}\n")
    return 0


def _check(*, args: _argparse.Namespace) -> int:
    password = _password(args=args, confirm=False) if args.verify else None
    problems = []
    for path in args.files:
        try:
            problems.extend(_files.check_file(path=path, password=password))
        except (_keyloom.KeyloomError, OSError) as exc:
            problems.append(_describe(error=exc))
    if problems:
        _stdout(text="".join(f"{problem}\n" for problem in problems))
    return 1 if problems else 0


def _describe(*, error: Exception) -> str:
    """Return the one-line message of a failure the user can fix."""
    if isinstance(error, OSError) and error.strerror:
        if error.filename is not None:
            return f"{error.filename}: {error.strerror}"
        return error.strerror
    return str(error)


def _environment() -> str:
    lines = [
        f"keyloom {_metadata.__version__}",
        f"python {_platform.python_version()} on {_platform.platform()}",
    ]
    for name in ("cryptography", "korml", "tomlkit"):
        try:
            lines.append(f"{name} {_importlib_metadata.version(name)}")
        except _importlib_metadata.PackageNotFoundError:
            lines.append(f"{name} not installed")
    return "\n".join(lines)


def _command(*, argv: list[str]) -> str:
    """Return the command and its options, without any of their values.

    Values are file names and paths, which a report does not need.
    """
    words = ["keyloom"]
    for word in argv:
        if word.startswith("-"):
            words.append(word.partition("=")[0])
        elif word in _COMMANDS and not any(w in _COMMANDS for w in words):
            words.append(word)
    return " ".join(words)


def bug_report(*, error: BaseException, argv: list[str]) -> str:
    """Return the report of an internal error, ready to paste into an issue.

    It holds the command and its options, the versions of keyloom, Python
    and the dependencies, and the traceback. Tracebacks show code, not
    variables, but exception messages can quote data, so the user is asked
    to check the report before posting it.
    """
    trace = "".join(_traceback.format_exception(error)).rstrip("\n")
    url = _metadata.issues_url()
    where = f"at {url}" if url else "with the keyloom maintainers"
    return "\n".join(
        [
            f"keyloom: internal error: {type(error).__name__}: {error}",
            "",
            f"This is a bug in keyloom {_metadata.__version__}. Please open an "
            f"issue {where}",
            "and paste the bug report below into it, from its heading to the",
            "end. Check first that it contains no secrets.",
            "",
            "### Bug report",
            "",
            f"Command: `{_command(argv=argv)}`",
            "",
            "```text",
            _environment(),
            "```",
            "",
            "```text",
            trace,
            "```",
        ]
    )


def run(*, argv: list[str]) -> int:
    """Run the command line with ``argv``, excluding the program name.

    Return the exit status. Invalid usage raises SystemExit from argparse,
    as for --help; nothing else escapes.
    """
    try:
        parser = _parser()
        args = parser.parse_args(argv)
        password_given = args.password_stdin or args.password_file is not None
        if args.command == "check" and not args.verify and password_given:
            parser.error("a password source requires --verify")
        commands = {
            "encrypt": _encrypt,
            "decrypt": _decrypt,
            "reencrypt": _reencrypt,
            "check": _check,
        }
        status = commands[args.command](args=args)
        # Flush here, so a failing write is handled below rather than at
        # interpreter exit.
        if _sys.stdout is not None:
            _sys.stdout.flush()
        return status
    except _keyloom.KeyloomError as exc:
        _stderr(text=f"keyloom: {_describe(error=exc)}")
        return 1
    except BrokenPipeError:
        _discard_stdout()
        return EX_BROKEN_PIPE
    except OSError as exc:
        _stderr(text=f"keyloom: {_describe(error=exc)}")
        return 1
    except KeyboardInterrupt:
        _stderr(text="\nkeyloom: interrupted")
        return EX_INTERRUPTED
    except Exception as exc:
        _stderr(text=bug_report(error=exc, argv=argv))
        return EX_SOFTWARE


def _discard_stdout() -> None:
    """Point standard output at /dev/null after its reader went away.

    Otherwise Python fails once more when it flushes the stream at exit.
    """
    try:
        devnull = _os.open(_os.devnull, _os.O_WRONLY)
        _os.dup2(devnull, _sys.stdout.fileno())
    except (AttributeError, OSError, ValueError):
        pass


def main() -> int:
    """Console entry point."""
    # Messages name files, whose names may not be encodable in the terminal
    # encoding; escape such characters rather than fail.
    for stream in (_sys.stdout, _sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    return run(argv=_sys.argv[1:])
