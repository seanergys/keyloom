# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
import os as _os
import pathlib as _pathlib
import re as _re
import stat as _stat

import pytest

import keyloom
import keyloom._files as _files
import keyloom._formats as _formats

_TOML = (
    "# keep this comment\n"
    '[git."gitlab.example.org"]\n'
    'username = "oauth2"\n'
    'token = { __keyloom__ = "secret", value = "abc" }\n'
)
_YAML = (
    "# keep this comment\n"
    "git:\n"
    "  gitlab.example.org:\n"
    "    username: oauth2\n"
    "    token:\n"
    "      __keyloom__: secret\n"
    "      value: abc\n"
)
_JSON = (
    '{"git":{"gitlab.example.org":{"username":"oauth2",'
    '"token":{"__keyloom__":"secret","value":"abc"}}}}\n'
)

_SAFE = _files.OutputSafety(allow_symlink=False, allow_hard_links=False)


@pytest.mark.parametrize(
    ("suffix", "text"),
    [(".toml", _TOML), (".yaml", _YAML), (".json", _JSON)],
)
def test_file_round_trip(
    tmp_path: _pathlib.Path, suffix: str, text: str
) -> None:
    path = tmp_path / f"credentials{suffix}"
    path.write_text(text, encoding="utf-8")

    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    encrypted_text = path.read_text(encoding="utf-8")
    assert "$KEYLOOM;1;argon2;" in encrypted_text
    if suffix != ".json":
        assert "keep this comment" in encrypted_text

    plaintext = _files.decrypt_text(
        path=path, password="password", unwrap=False
    )
    assert "abc" in plaintext

    resolved = keyloom.load(path=path, password="password")
    assert resolved["git"]["gitlab.example.org"]["username"] == "oauth2"
    assert resolved["git"]["gitlab.example.org"]["token"] == "abc"


def test_yaml_preserves_backslash_across_long_quoted_scalar(
    tmp_path: _pathlib.Path,
) -> None:
    # Regression for fuzz seed 3413: ruamel.yaml, which keyloom used then,
    # wrapped right after an escaped backslash, and folding inserted a space
    # on reload.
    public = (
        "3-<i&GjQZv&fY'字{Hä\n"
        "wA{äGs🙂2F;q+@GEQq2+ QAiX~|5bj9ä-漢$f.é;Lö(\n"
        "AéF}cDj:ét`XiD4O字I\\cPbe&{v 70[kü<5I<!H3SßP6ésQp+aü字</"
    )
    data = {
        "public": public,
        "token": {"__keyloom__": "secret", "value": "abc"},
    }
    path = tmp_path / "credentials.yaml"
    path.write_text(
        _formats.dump_text(data=data, syntax="yaml"), encoding="utf-8"
    )

    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    resolved = keyloom.load(path=path, password="password")

    assert resolved["public"] == public
    assert resolved["token"] == "abc"


def _encrypted_toml(*, tmp_path: _pathlib.Path) -> _pathlib.Path:
    path = tmp_path / "credentials.toml"
    path.write_text(
        'token = { __keyloom__ = "secret", value = "abc" }\n',
        encoding="utf-8",
    )
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    return path


def test_decrypt_file_to_writes_mode_0600(tmp_path: _pathlib.Path) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    target = tmp_path / "plain.toml"

    _files.decrypt_to(
        input_path=source,
        output_path=target,
        password="password",
        unwrap=True,
        safety=_SAFE,
    )

    assert target.read_text(encoding="utf-8") == 'token = "abc"\n'
    assert _stat.S_IMODE(target.stat().st_mode) == 0o600


def test_decrypt_file_to_replaces_existing_file_without_inheriting_mode(
    tmp_path: _pathlib.Path,
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    target = tmp_path / "plain.toml"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o644)
    old_inode = target.stat().st_ino

    _files.decrypt_to(
        input_path=source,
        output_path=target,
        password="password",
        unwrap=False,
        safety=_SAFE,
    )

    # A new inode shows the plaintext never went into the 0644 file.
    assert target.stat().st_ino != old_inode
    assert _stat.S_IMODE(target.stat().st_mode) == 0o600
    assert 'value = "abc"' in target.read_text(encoding="utf-8")


@pytest.mark.parametrize("link", ["same", "symlink", "hardlink"])
def test_decrypt_file_to_refuses_input_as_output(
    tmp_path: _pathlib.Path, link: str
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    before = source.read_text(encoding="utf-8")
    target = tmp_path / "alias.toml"
    if link == "same":
        target = source
    elif link == "symlink":
        target.symlink_to(source)
    else:
        _os.link(source, target)

    with pytest.raises(keyloom.UnsafeOutput):
        _files.decrypt_to(
            input_path=source,
            output_path=target,
            password="password",
            unwrap=False,
            safety=_SAFE,
        )

    assert source.read_text(encoding="utf-8") == before


@pytest.mark.skipif(_os.name != "posix", reason="POSIX symlink semantics")
def test_output_file_symlink_is_followed_when_allowed(
    tmp_path: _pathlib.Path,
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    target = tmp_path / "actual.toml"
    target.write_text("old", encoding="utf-8")
    alias = tmp_path / "output.toml"
    alias.symlink_to(target)

    keyloom.decrypt_file(
        input_path=source,
        output_path=alias,
        password="password",
        dangerous_allow_writing_to_symlink=True,
    )

    assert alias.is_symlink()
    assert alias.resolve() == target
    assert 'value = "abc"' in target.read_text(encoding="utf-8")
    assert _stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.skipif(_os.name != "posix", reason="POSIX symlink semantics")
def test_output_directory_symlink_is_followed(
    tmp_path: _pathlib.Path,
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    actual_dir = tmp_path / "actual"
    actual_dir.mkdir()
    alias = tmp_path / "linked"
    alias.symlink_to(actual_dir, target_is_directory=True)

    keyloom.decrypt_file(
        input_path=source, output_path=alias / "plain.toml", password="password"
    )

    assert alias.is_symlink()
    assert 'value = "abc"' in (actual_dir / "plain.toml").read_text()


@pytest.mark.skipif(_os.name != "posix", reason="POSIX symlink semantics")
def test_retargeted_output_symlink_cannot_redirect_plaintext(
    tmp_path: _pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    encrypted_before = source.read_bytes()
    target = tmp_path / "plain.toml"
    target.write_text("old", encoding="utf-8")
    alias = tmp_path / "output.toml"
    alias.symlink_to(target)
    original = _files.decrypt_text

    def retarget(*, path: _pathlib.Path, password: str, unwrap: bool) -> str:
        result = original(path=path, password=password, unwrap=unwrap)
        alias.unlink()
        alias.symlink_to(source)
        return result

    monkeypatch.setattr(_files, "decrypt_text", retarget)
    keyloom.decrypt_file(
        input_path=source,
        output_path=alias,
        password="password",
        dangerous_allow_writing_to_symlink=True,
    )

    assert source.read_bytes() == encrypted_before
    assert alias.is_symlink()
    assert alias.resolve() == source
    assert 'value = "abc"' in target.read_text(encoding="utf-8")


@pytest.mark.skipif(_os.name != "posix", reason="POSIX symlink semantics")
def test_retargeted_parent_symlink_cannot_redirect_plaintext(
    tmp_path: _pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    encrypted_before = source.read_bytes()
    initial_dir = tmp_path / "initial"
    initial_dir.mkdir()
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "plain.toml").write_text("untouched", encoding="utf-8")
    alias = tmp_path / "linked"
    alias.symlink_to(initial_dir, target_is_directory=True)
    original = _files.decrypt_text

    def retarget(*, path: _pathlib.Path, password: str, unwrap: bool) -> str:
        result = original(path=path, password=password, unwrap=unwrap)
        alias.unlink()
        alias.symlink_to(other_dir, target_is_directory=True)
        return result

    monkeypatch.setattr(_files, "decrypt_text", retarget)
    keyloom.decrypt_file(
        input_path=source, output_path=alias / "plain.toml", password="password"
    )

    assert source.read_bytes() == encrypted_before
    assert (other_dir / "plain.toml").read_text(encoding="utf-8") == "untouched"
    assert 'value = "abc"' in (initial_dir / "plain.toml").read_text()


@pytest.mark.skipif(_os.name != "posix", reason="POSIX symlink semantics")
@pytest.mark.parametrize("swap", ["symlink", "hardlink"])
def test_swapped_destination_entry_cannot_overwrite_input(
    tmp_path: _pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    swap: str,
) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    encrypted_before = source.read_bytes()
    target = tmp_path / "output.toml"
    target.write_text("old", encoding="utf-8")
    original = _files.decrypt_text

    def retarget(*, path: _pathlib.Path, password: str, unwrap: bool) -> str:
        result = original(path=path, password=password, unwrap=unwrap)
        target.unlink()
        if swap == "symlink":
            target.symlink_to(source)
        else:
            _os.link(source, target)
        return result

    monkeypatch.setattr(_files, "decrypt_text", retarget)
    with pytest.raises(keyloom.UnsafeOutput):
        keyloom.decrypt_file(
            input_path=source, output_path=target, password="password"
        )

    assert source.read_bytes() == encrypted_before
    assert target.samefile(source)
    assert not list(tmp_path.glob(".output.toml.*"))


def test_encrypt_without_plaintext_leaves_the_file_alone(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "config.json"
    text = '{"a":1,"t":{"__keyloom__":"secret","value":"x"}}\n'
    path.write_text(text, encoding="utf-8")
    assert (
        keyloom.encrypt_file(
            input_path=path,
            output_path=path,
            password="pw",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
        == 1
    )
    encrypted = path.read_text(encoding="utf-8")
    inode = path.stat().st_ino

    assert (
        keyloom.encrypt_file(
            input_path=path,
            output_path=path,
            password="pw",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
        == 0
    )
    assert path.stat().st_ino == inode
    assert path.read_text(encoding="utf-8") == encrypted

    untouched = tmp_path / "plain.json"
    untouched.write_text('{"a":1}', encoding="utf-8")
    assert (
        keyloom.encrypt_file(
            input_path=untouched,
            output_path=untouched,
            password="pw",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
        == 0
    )
    assert untouched.read_text(encoding="utf-8") == '{"a":1}'


def test_load_rejects_plaintext_secrets(tmp_path: _pathlib.Path) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(
        'token = { __keyloom__ = "secret", value = "PLAINTEXT" }\n',
        encoding="utf-8",
    )
    with pytest.raises(
        keyloom.PlaintextSecret, match=r"credentials\.toml: token"
    ):
        keyloom.load(path=path, password="password")


@pytest.mark.parametrize(
    ("suffix", "text"), [(".toml", _TOML), (".yaml", _YAML)]
)
def test_decrypt_unwrap_keeps_comments(
    tmp_path: _pathlib.Path, suffix: str, text: str
) -> None:
    path = tmp_path / f"credentials{suffix}"
    path.write_text(text, encoding="utf-8")
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )

    plaintext = _files.decrypt_text(path=path, password="password", unwrap=True)

    assert plaintext.startswith("# keep this comment\n")
    assert plaintext.endswith("\n")
    assert "__keyloom__" not in plaintext
    reloaded = _formats.load_text(text=plaintext, syntax=suffix[1:])
    assert reloaded["git"]["gitlab.example.org"]["token"] == "abc"


@pytest.mark.parametrize(
    ("suffix", "text"),
    [
        (
            ".toml",
            'flag = true\ncount = 3\nratio = 0.5\nname = "x"\n'
            "list = [1, 2]\n"
            'token = { __keyloom__ = "secret", value = "7" }\n',
        ),
    ],
)
def test_load_returns_plain_python_types(
    tmp_path: _pathlib.Path, suffix: str, text: str
) -> None:
    path = tmp_path / f"config{suffix}"
    path.write_text(text, encoding="utf-8")
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )

    loaded = keyloom.load(path=path, password="password")

    assert type(loaded) is dict
    assert loaded == {
        "flag": True,
        "count": 3,
        "ratio": 0.5,
        "name": "x",
        "list": [1, 2],
        "token": "7",
    }
    assert [type(loaded[key]) for key in loaded] == [
        bool,
        int,
        float,
        str,
        list,
        str,
    ]


def test_load_reports_parse_errors(tmp_path: _pathlib.Path) -> None:
    path = tmp_path / "broken.toml"
    path.write_text("a = [\n", encoding="utf-8")
    with pytest.raises(keyloom.ParseError, match=r"broken\.toml: invalid TOML"):
        keyloom.load(path=path, password="password")


@pytest.mark.parametrize(
    ("suffix", "text", "expected"),
    [
        (
            ".toml",
            'token = { __keyloom__ = "secret", '
            'value = "__keyloom__secret__" }\n',
            r'token = \{ __keyloom__ = "secret", value = "\$KEYLOOM'
            r';[^"]*" \}\n',
        ),
        (
            ".yaml",
            "token:\n  __keyloom__: secret\n  value: __keyloom__secret__\n",
            r'token:\n  __keyloom__: secret\n  value: "\$KEYLOOM;\S*"\n',
        ),
        (
            ".json",
            '{"token": {"__keyloom__": "secret", '
            '"value": "__keyloom__secret__"}}\n',
            r'"value": "\$KEYLOOM;',
        ),
    ],
)
def test_placeholder_keeps_the_layout(
    tmp_path: _pathlib.Path, suffix: str, text: str, expected: str
) -> None:
    path = tmp_path / f"credentials{suffix}"
    path.write_text(text, encoding="utf-8")

    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="pw",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=lambda _location: "entered",
    )

    assert _re.search(expected, path.read_text(encoding="utf-8"))
    assert keyloom.load(path=path, password="pw") == {"token": "entered"}


@pytest.mark.parametrize(
    "text",
    [
        'token:\n  __keyloom__: secret\n  value: "hunter2\n',
        "token: hunter2\ntoken: hunter3\n",
        "a: [hunter2\n",
    ],
)
def test_yaml_parse_errors_do_not_quote_the_file(
    tmp_path: _pathlib.Path, text: str
) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text(text, encoding="utf-8")

    for parse in (_files.check_file, _files.load):
        with pytest.raises(keyloom.ParseError) as exc_info:
            parse(path=path, password="password")
        message = str(exc_info.value)
        assert "hunter" not in message
        assert "line " in message


@pytest.mark.parametrize(
    "json_text",
    [
        '{"token":{"__keyloom__":"secret","value":"PLAINTEXT"},'
        '"token":"public"}',
        '{"nested":{"token":1,"token":2}}',
        '{"items":[{"a":1,"a":2}]}',
        '{"\\u0061":1,"a":2}',
    ],
)
def test_duplicate_json_keys_are_rejected_without_disclosing_values(
    tmp_path: _pathlib.Path, json_text: str
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(json_text, encoding="utf-8")
    for operation in (
        lambda: _files.check_file(path=path, password=None),
        lambda: keyloom.load(path=path, password="password"),
        lambda: keyloom.encrypt_file(
            input_path=path,
            output_path=path,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        ),
        lambda: _formats.load_plain(path=path),
        lambda: _formats.load_text(text=json_text, syntax="json"),
    ):
        with pytest.raises(
            keyloom.ParseError, match="duplicate object key"
        ) as exc:
            operation()
        assert "PLAINTEXT" not in str(exc.value)


def test_yaml_duplicate_key_is_named() -> None:
    with pytest.raises(keyloom.ParseError, match="duplicate key at line 2"):
        _formats.load_text(text="a: 1\na: 2\n", syntax="yaml")


_HUGE = "9" * 5000


@pytest.mark.parametrize(
    ("name", "text", "message"),
    [
        ("huge.json", f'{{"a": {_HUGE}}}', "integer with too many digits"),
        ("deep.json", "[" * 2_000 + "]" * 2_000, "nested too deeply"),
        ("deep.yaml", "[" * 2_000 + "]" * 2_000, "nested too deeply"),
        ("lone.json", '{"a": "\\ud800"}', "lone surrogate"),
        ("lone.yaml", 'a: "\\ud800"\n', "lone surrogate"),
    ],
    ids=[
        "huge-json",
        "deep-json",
        "deep-yaml",
        "lone-json",
        "lone-yaml",
    ],
)
def test_unreadable_documents_are_parse_errors(
    tmp_path: _pathlib.Path, name: str, text: str, message: str
) -> None:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")

    for operation in (
        lambda: _files.check_file(path=path, password=None),
        lambda: _files.load(path=path, password="password"),
        lambda: _files.decrypt_text(
            path=path, password="password", unwrap=False
        ),
        lambda: _files.encrypt_file(
            input_path=path,
            output_path=path,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2_V2,
            prompt=None,
            safety=_SAFE,
        ),
    ):
        with pytest.raises(keyloom.ParseError, match=message):
            operation()


@pytest.mark.parametrize(
    ("suffix", "data"),
    [
        (".json", {"a": {1, 2}}),
        (".json", {"a": "\ud800"}),
        (".yaml", {"a": "\ud800"}),
        (".json", {"a": 10**5000}),
        (".yaml", {"a": 10**5000}),
    ],
    ids=[
        "json-set",
        "json-lone-surrogate",
        "yaml-lone-surrogate",
        "json-huge-integer",
        "yaml-huge-integer",
    ],
)
def test_unstorable_data_is_unsupported(
    tmp_path: _pathlib.Path, suffix: str, data: dict[str, object]
) -> None:
    with pytest.raises(keyloom.UnsupportedFormat, match="cannot store"):
        _files.store(
            path=tmp_path / f"data{suffix}",
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2_V2,
            safety=_SAFE,
        )
    assert not list(tmp_path.iterdir())


def test_store_rejects_deeply_nested_data(tmp_path: _pathlib.Path) -> None:
    data: list[object] = []
    for _ in range(2_000):
        data = [data]
    with pytest.raises(keyloom.UnsupportedFormat, match="nested too deeply"):
        _files.store(
            path=tmp_path / "deep.json",
            data={"a": data},
            password="password",
            algorithm=keyloom.Algorithm.ARGON2_V2,
            safety=_SAFE,
        )


@pytest.mark.parametrize(
    ("value", "message"),
    [("\ud800", "lone surrogate"), (10**5000, "must be a string")],
    ids=["lone-surrogate", "integer"],
)
def test_unencryptable_secret_is_invalid(
    tmp_path: _pathlib.Path, value: object, message: str
) -> None:
    with pytest.raises(keyloom.InvalidSecret, match=message):
        _files.store(
            path=tmp_path / "data.json",
            data={"a": keyloom.secret(value=value)},
            password="password",
            algorithm=keyloom.Algorithm.ARGON2_V2,
            safety=_SAFE,
        )


def test_output_symlink_is_refused_by_default(tmp_path: _pathlib.Path) -> None:
    source = _encrypted_toml(tmp_path=tmp_path)
    victim = tmp_path / "victim.toml"
    victim.write_text("untouched", encoding="utf-8")
    alias = tmp_path / "output.toml"
    alias.symlink_to(victim)

    with pytest.raises(keyloom.UnsafeOutput, match="symbolic link"):
        keyloom.decrypt_file(
            input_path=source, output_path=alias, password="password"
        )

    assert alias.is_symlink()
    assert victim.read_text(encoding="utf-8") == "untouched"


def test_in_place_encrypt_through_a_symlink_is_refused_by_default(
    tmp_path: _pathlib.Path,
) -> None:
    actual = tmp_path / "actual.toml"
    actual.write_text(
        'token = { __keyloom__ = "secret", value = "abc" }\n', encoding="utf-8"
    )
    alias = tmp_path / "config.toml"
    alias.symlink_to(actual)
    arguments = {
        "input_path": alias,
        "output_path": alias,
        "password": "password",
        "algorithm": "argon2",
        "prompt": None,
    }

    with pytest.raises(keyloom.UnsafeOutput, match="symbolic link"):
        keyloom.encrypt_file(**arguments)
    assert (
        keyloom.encrypt_file(
            **arguments, dangerous_allow_writing_to_symlink=True
        )
        == 1
    )

    assert alias.is_symlink()
    assert "abc" not in actual.read_text(encoding="utf-8")


@pytest.mark.skipif(_os.name != "posix", reason="POSIX hard links")
def test_in_place_encrypt_of_a_hard_linked_file_is_refused_by_default(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        'token = { __keyloom__ = "secret", value = "abc" }\n', encoding="utf-8"
    )
    other = tmp_path / "copy.toml"
    _os.link(path, other)
    arguments = {
        "input_path": path,
        "output_path": path,
        "password": "password",
        "algorithm": "argon2",
        "prompt": None,
    }

    with pytest.raises(keyloom.UnsafeOutput, match="1 other hard link,"):
        keyloom.encrypt_file(**arguments)
    assert "abc" in path.read_text(encoding="utf-8")

    assert (
        keyloom.encrypt_file(**arguments, dangerous_allow_hard_links=True) == 1
    )
    assert "abc" not in path.read_text(encoding="utf-8")
    # The other link keeps the plaintext, as the flag's name warns.
    assert "abc" in other.read_text(encoding="utf-8")
