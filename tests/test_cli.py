# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
import getpass as _getpass
import io as _io
import os as _os
import pathlib as _pathlib
import warnings as _warnings

import pytest

import keyloom._cli as _cli
import keyloom._files as _files

_CREDENTIALS = (
    '[git."gitlab.example.org"]\n'
    'username = "oauth2"\n'
    'token = { __keyloom__ = "secret", value = "abc" }\n'
)


def _write(*, tmp_path: _pathlib.Path) -> tuple[_pathlib.Path, _pathlib.Path]:
    path = tmp_path / "credentials.toml"
    path.write_text(_CREDENTIALS, encoding="utf-8")
    password_file = tmp_path / "vault-password"
    password_file.write_text("password\n", encoding="utf-8")
    password_file.chmod(0o600)
    return path, password_file


def test_encrypt_and_decrypt_with_password_stdin(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, _password_file = _write(tmp_path=tmp_path)

    monkeypatch.setattr("sys.stdin", _io.StringIO("password\n"))
    assert _cli.run(argv=["encrypt", "--password-stdin", str(path)]) == 0
    capsys.readouterr()
    assert "$KEYLOOM;1;argon2-v2;" in path.read_text("utf-8")

    monkeypatch.setattr("sys.stdin", _io.StringIO("password\n"))
    assert _cli.run(argv=["decrypt", "--password-stdin", str(path)]) == 0
    assert 'value = "abc"' in capsys.readouterr().out


def test_encrypt_and_decrypt_with_password_file(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]

    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    capsys.readouterr()
    assert "$KEYLOOM;1;argon2-v2;" in path.read_text("utf-8")

    assert _cli.run(argv=["decrypt", *source, str(path)]) == 0
    assert 'value = "abc"' in capsys.readouterr().out


def test_encrypt_reports_the_count(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]

    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    assert capsys.readouterr().out == f"{path}: encrypted 1 secret\n"
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    assert capsys.readouterr().out == f"{path}: nothing to encrypt\n"


def test_password_sources_are_mutually_exclusive(
    tmp_path: _pathlib.Path,
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    argv = [
        "encrypt",
        "--password-stdin",
        "--password-file",
        str(password_file),
        str(path),
    ]

    with pytest.raises(SystemExit) as exc_info:
        _cli.run(argv=argv)

    assert exc_info.value.code == 2


def test_empty_noninteractive_password_is_rejected(
    tmp_path: _pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _password_file = _write(tmp_path=tmp_path)
    monkeypatch.setattr("sys.stdin", _io.StringIO("\n"))

    assert _cli.run(argv=["encrypt", "--password-stdin", str(path)]) == 1


def test_decrypt_refuses_to_overwrite_input(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    encrypted = path.read_text(encoding="utf-8")

    argv = ["decrypt", *source, "--output", str(path), str(path)]
    assert _cli.run(argv=argv) == 1
    assert "refusing to write plaintext" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == encrypted


def test_parse_error_is_a_clean_message(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _path, password_file = _write(tmp_path=tmp_path)
    broken = tmp_path / "broken.yaml"
    broken.write_text("a: [1, 2\n", encoding="utf-8")

    argv = ["decrypt", "--password-file", str(password_file), str(broken)]
    assert _cli.run(argv=argv) == 1

    err = capsys.readouterr().err
    assert err.startswith(f"keyloom: {broken}: invalid YAML")
    assert "Traceback" not in err


def _explode(**_kwargs: object) -> str:
    raise RuntimeError("boom")


def test_internal_error_prints_a_bug_report(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    monkeypatch.setattr(_files, "decrypt_text", _explode)
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))

    argv = [
        "decrypt",
        "--unwrap",
        f"--password-file={password_file}",
        str(path),
    ]
    assert _cli.run(argv=argv) == _cli.EX_SOFTWARE

    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err
    assert err.startswith("keyloom: internal error: RuntimeError: boom\n")
    assert "This is a bug in keyloom" in err
    assert "contains no secrets" in err
    report = err[err.index("### Bug report") :]
    assert "Command: `keyloom decrypt --unwrap --password-file`" in report
    assert str(tmp_path) not in report
    assert "```text\nkeyloom " in report
    assert "Traceback (most recent call last)" in report
    assert report.rstrip("\n").endswith("RuntimeError: boom\n```")
    # Nothing is saved: the report is printed for the user to copy.
    assert not list(tmp_path.glob("keyloom-*"))


def test_debug_option_is_gone(tmp_path: _pathlib.Path) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    argv = ["--debug", "decrypt", "--password-file", str(password_file)]
    with pytest.raises(SystemExit) as exc_info:
        _cli.run(argv=[*argv, str(path)])
    assert exc_info.value.code == 2


def test_check_passes_encrypted_files(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    capsys.readouterr()

    assert _cli.run(argv=["check", str(path)]) == 0
    assert _cli.run(argv=["check", "--verify", *source, str(path)]) == 0
    assert capsys.readouterr().out == ""


def test_check_lists_every_problem_in_every_file(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plain, _password_file = _write(tmp_path=tmp_path)
    broken = tmp_path / "broken.yaml"
    broken.write_text("a: [1\n", encoding="utf-8")
    other = tmp_path / "other.json"
    other.write_text(
        '{"x": {"__keyloom__": "secret", "value": 1},'
        ' "y": {"__keyloom__": "secret", "value": 2}}',
        encoding="utf-8",
    )

    argv = ["check", str(plain), str(broken), str(other)]
    assert _cli.run(argv=argv) == 1

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == (
        f'{plain}: git."gitlab.example.org".token: secret is not encrypted; '
        "run keyloom encrypt"
    )
    assert lines[1].startswith(f"{broken}: invalid YAML")
    assert [line for line in lines if line.startswith(str(other))] == [
        f"{other}: x: secret is not encrypted; run keyloom encrypt",
        f"{other}: y: secret is not encrypted; run keyloom encrypt",
    ]


def test_check_verify_detects_a_wrong_password(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    assert (
        _cli.run(
            argv=["encrypt", "--password-file", str(password_file), str(path)]
        )
        == 0
    )
    capsys.readouterr()

    monkeypatch.setattr("sys.stdin", _io.StringIO("wrong\n"))
    argv = ["check", "--verify", "--password-stdin", str(path)]
    assert _cli.run(argv=argv) == 1
    assert "wrong password" in capsys.readouterr().out


def test_check_password_source_requires_verify(tmp_path: _pathlib.Path) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    with pytest.raises(SystemExit) as exc_info:
        _cli.run(
            argv=["check", "--password-file", str(password_file), str(path)]
        )
    assert exc_info.value.code == 2


def test_encrypt_accepts_only_known_algorithms(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]

    argv = ["encrypt", *source, "--algorithm", "argon2", str(path)]
    assert _cli.run(argv=argv) == 0
    assert "$KEYLOOM;1;argon2;" in path.read_text(encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        _cli.run(argv=["encrypt", *source, "--algorithm", "chamar", str(path)])
    assert exc_info.value.code == 2


def test_reencrypt_keeps_or_changes_the_password(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    first = path.read_text(encoding="utf-8")
    capsys.readouterr()

    assert _cli.run(argv=["reencrypt", *source, str(path)]) == 0
    assert capsys.readouterr().out == f"{path}: re-encrypted 1 secret\n"
    assert path.read_text(encoding="utf-8") != first
    assert _cli.run(argv=["check", "--verify", *source, str(path)]) == 0

    new_file = tmp_path / "new-password"
    new_file.write_text("changed\n", encoding="utf-8")
    argv = [
        "reencrypt",
        *source,
        "--new-password-file",
        str(new_file),
        str(path),
    ]
    assert _cli.run(argv=argv) == 0
    argv = ["check", "--verify", "--password-file", str(new_file), str(path)]
    assert _cli.run(argv=argv) == 0

    prompts = iter(["changed", "again", "again"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(prompts))
    argv = ["reencrypt", "--change-password", str(path)]
    assert _cli.run(argv=argv) == 0
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", _io.StringIO("again\n"))
    argv = ["check", "--verify", "--password-stdin", str(path)]
    assert _cli.run(argv=argv) == 0


_PLACEHOLDER = (
    '[git."gitlab.example.org"]\n'
    'username = "oauth2"\n'
    'token = { __keyloom__ = "secret", value = "__keyloom__secret__" '
    "}\n"
)


def _write_placeholder(
    *, tmp_path: _pathlib.Path
) -> tuple[_pathlib.Path, list[str]]:
    path = tmp_path / "credentials.toml"
    path.write_text(_PLACEHOLDER, encoding="utf-8")
    password_file = tmp_path / "vault-password"
    password_file.write_text("password\n", encoding="utf-8")
    password_file.chmod(0o600)
    return path, ["--password-file", str(password_file)]


def test_encrypt_prompts_for_each_placeholder(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, source = _write_placeholder(tmp_path=tmp_path)
    asked = []
    answers = iter(["glpat-entered", "glpat-entered"])

    def getpass(prompt: str) -> str:
        asked.append(prompt)
        return next(answers)

    monkeypatch.setattr("getpass.getpass", getpass)
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0

    assert asked == [
        'Secret for git."gitlab.example.org".token: ',
        'Confirm secret for git."gitlab.example.org".token: ',
    ]
    assert capsys.readouterr().out == f"{path}: encrypted 1 secret\n"
    assert "glpat-entered" not in path.read_text(encoding="utf-8")
    assert _cli.run(argv=["decrypt", "--unwrap", *source, str(path)]) == 0
    assert 'token = "glpat-entered"' in capsys.readouterr().out


@pytest.mark.parametrize(
    ("answers", "message"),
    [
        (["one", "two"], "entered secrets do not match"),
        ([""], "secret must not be empty"),
    ],
)
def test_encrypt_rejects_a_bad_entry(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answers: list[str],
    message: str,
) -> None:
    path, source = _write_placeholder(tmp_path=tmp_path)
    entries = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(entries))

    assert _cli.run(argv=["encrypt", *source, str(path)]) == 1

    assert message in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == _PLACEHOLDER


def test_encrypt_without_a_terminal_never_reads_a_placeholder(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, source = _write_placeholder(tmp_path=tmp_path)

    # What getpass does when it cannot open a terminal: warn, then read
    # standard input with echo.
    def getpass(prompt: str) -> str:
        _warnings.warn(
            "Can not control echo on the terminal.",
            _getpass.GetPassWarning,
            stacklevel=2,
        )
        raise AssertionError("read a secret without a terminal")

    monkeypatch.setattr("getpass.getpass", getpass)
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 1

    err = capsys.readouterr().err
    assert "no terminal to enter it" in err
    assert path.read_text(encoding="utf-8") == _PLACEHOLDER


def test_check_reports_a_placeholder(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _source = _write_placeholder(tmp_path=tmp_path)

    assert _cli.run(argv=["check", str(path)]) == 1

    assert capsys.readouterr().out == (
        f'{path}: git."gitlab.example.org".token: secret is a placeholder; '
        "run keyloom encrypt to enter it\n"
    )


def test_vault_password_is_never_read_without_a_terminal(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, _password_file = _write(tmp_path=tmp_path)

    # What getpass does when it cannot open a terminal: warn, then read
    # standard input with echo.
    def getpass(prompt: str) -> str:
        _warnings.warn(
            "Can not control echo on the terminal.",
            _getpass.GetPassWarning,
            stacklevel=2,
        )
        raise AssertionError("read a password without a terminal")

    monkeypatch.setattr("getpass.getpass", getpass)
    assert _cli.run(argv=["decrypt", str(path)]) == 1

    err = capsys.readouterr().err
    assert "no terminal to enter the vault password" in err
    assert "--password-stdin" in err


@pytest.mark.skipif(_os.name != "posix", reason="POSIX permissions")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_accessible_password_file_is_warned_about(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str], mode: int
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    password_file.chmod(mode)

    argv = ["encrypt", "--password-file", str(password_file), str(path)]
    assert _cli.run(argv=argv) == 0

    err = capsys.readouterr().err
    assert f"warning: {password_file} is accessible to other users" in err
    assert f"mode {mode:04o}" in err


@pytest.mark.skipif(_os.name != "posix", reason="POSIX permissions")
def test_private_password_file_is_not_warned_about(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)

    argv = ["encrypt", "--password-file", str(password_file), str(path)]
    assert _cli.run(argv=argv) == 0
    assert capsys.readouterr().err == ""


def test_end_of_input_at_the_password_prompt_is_an_error(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, _password_file = _write(tmp_path=tmp_path)

    def getpass(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("getpass.getpass", getpass)
    assert _cli.run(argv=["decrypt", str(path)]) == 1
    assert "no vault password was entered" in capsys.readouterr().err


def test_end_of_input_at_a_placeholder_prompt_is_an_error(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, source = _write_placeholder(tmp_path=tmp_path)

    def getpass(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("getpass.getpass", getpass)
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 1
    assert "no secret was entered" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == _PLACEHOLDER


def test_password_file_must_be_utf8(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    password_file.write_bytes(b"pass\xffword\n")

    argv = ["decrypt", "--password-file", str(password_file), str(path)]
    assert _cli.run(argv=argv) == 1
    assert "is not valid UTF-8" in capsys.readouterr().err


def test_password_stdin_must_be_utf8(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, _password_file = _write(tmp_path=tmp_path)
    stdin = _io.TextIOWrapper(_io.BytesIO(b"pass\xffword\n"), encoding="utf-8")
    monkeypatch.setattr("sys.stdin", stdin)

    assert _cli.run(argv=["decrypt", "--password-stdin", str(path)]) == 1
    assert "standard input is not valid UTF-8" in capsys.readouterr().err


def test_closed_standard_streams_are_errors(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    capsys.readouterr()

    monkeypatch.setattr("sys.stdin", None)
    assert _cli.run(argv=["decrypt", "--password-stdin", str(path)]) == 1
    assert "standard input is closed" in capsys.readouterr().err

    monkeypatch.setattr("sys.stdout", None)
    assert _cli.run(argv=["decrypt", *source, str(path)]) == 1
    assert "standard output is closed" in capsys.readouterr().err


class _ClosedPipe(_io.TextIOWrapper):
    def __init__(self) -> None:
        super().__init__(_io.BytesIO(), encoding="utf-8")

    def write(self, text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        raise BrokenPipeError(32, "Broken pipe")


def test_closed_pipe_ends_quietly(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    capsys.readouterr()

    monkeypatch.setattr("sys.stdout", _ClosedPipe())
    argv = ["decrypt", *source, str(path)]
    assert _cli.run(argv=argv) == _cli.EX_BROKEN_PIPE
    assert capsys.readouterr().err == ""


def test_decrypted_output_is_utf8_whatever_the_terminal(
    tmp_path: _pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(
        'token = { __keyloom__ = "secret", value = "glpat-äöü-漢字" }\n',
        encoding="utf-8",
    )
    password_file = tmp_path / "vault-password"
    password_file.write_text("password\n", encoding="utf-8")
    password_file.chmod(0o600)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0

    raw = _io.BytesIO()
    monkeypatch.setattr("sys.stdout", _io.TextIOWrapper(raw, encoding="ascii"))
    assert _cli.run(argv=["decrypt", "--unwrap", *source, str(path)]) == 0
    assert raw.getvalue().decode("utf-8") == 'token = "glpat-äöü-漢字"\n'


def test_missing_file_is_a_one_line_error(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.toml"
    assert _cli.run(argv=["check", str(missing)]) == 1
    assert capsys.readouterr().out == f"{missing}: No such file or directory\n"


_HOSTILE = {
    "huge.yaml": "a: " + "9" * 5000 + "\n",
    "huge.json": '{"a": ' + "9" * 5000 + "}",
    "deep.json": "[" * 2_000 + "]" * 2_000,
    "deep.toml": "a = " + "[" * 2_000 + "]" * 2_000 + "\n",
    "lone.json": '{"a": {"__keyloom__": "secret", "value": "\\ud800"}}',
    "tag.yaml": "a:\n  __keyloom__: secret\n  value: !foo bar\n",
    "date.toml": 'a = { __keyloom__ = "secret", value = 1979-05-27 }\n',
    "key.yaml": "? [1, 2]\n: x\nb:\n  __keyloom__: secret\n  value: s\n",
    "marker.yaml": "a:\n  __keyloom__: [1]\n  value: s\n",
    "nested.yaml": "a:\n  __keyloom__: secret\n  value: {b: 1}\n",
    "top.json": '{"__keyloom__": "secret", "value": "x"}',
    "scalar.yaml": "just a string\n",
    "empty.yaml": "",
    "bom.json": "\ufeff{}",
    "envelope.yaml": 'a:\n  __keyloom__: secret\n  value: "$KEYLOOM;1;é;s=a"\n',
    "binary.txt": "not a config file\n",
}


@pytest.mark.parametrize("name", sorted(_HOSTILE))
@pytest.mark.parametrize(
    "command",
    [
        ["check"],
        ["check", "--verify"],
        ["decrypt"],
        ["decrypt", "--unwrap"],
        ["encrypt"],
        ["reencrypt"],
    ],
    ids=" ".join,
)
def test_no_exception_escapes_a_command(
    tmp_path: _pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    command: list[str],
) -> None:
    path = tmp_path / name
    path.write_text(_HOSTILE[name], encoding="utf-8")
    _path, password_file = _write(tmp_path=tmp_path)

    source = (
        [] if command == ["check"] else ["--password-file", str(password_file)]
    )
    assert _cli.run(argv=[*command, *source, str(path)]) in (0, 1)
    err = capsys.readouterr().err
    assert "internal error" not in err
    assert "Traceback" not in err


def test_cli_refuses_an_output_symlink_unless_allowed(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    source = ["--password-file", str(password_file)]
    assert _cli.run(argv=["encrypt", *source, str(path)]) == 0
    target = tmp_path / "plain.toml"
    target.write_text("old", encoding="utf-8")
    alias = tmp_path / "output.toml"
    alias.symlink_to(target)
    capsys.readouterr()

    argv = ["decrypt", *source, "-o", str(alias), str(path)]
    assert _cli.run(argv=argv) == 1
    assert "--dangerous-allow-writing-to-symlink" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "old"

    assert _cli.run(argv=[*argv, "--dangerous-allow-writing-to-symlink"]) == 0
    assert alias.is_symlink()
    assert target.read_text(encoding="utf-8") != "old"


@pytest.mark.skipif(_os.name != "posix", reason="POSIX hard links")
def test_cli_refuses_a_hard_linked_output_unless_allowed(
    tmp_path: _pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, password_file = _write(tmp_path=tmp_path)
    _os.link(path, tmp_path / "copy.toml")
    source = ["--password-file", str(password_file)]

    assert _cli.run(argv=["encrypt", *source, str(path)]) == 1
    assert "--dangerous-allow-hard-links" in capsys.readouterr().err

    argv = ["encrypt", *source, "--dangerous-allow-hard-links", str(path)]
    assert _cli.run(argv=argv) == 0
