# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""KORML is the only reader for YAML; Keyloom preserves scalar semantics."""

import pathlib as _pathlib

import pytest

import keyloom
import keyloom._files as _files
import keyloom._formats as _formats


def test_every_yaml_scalar_is_a_string(tmp_path: _pathlib.Path) -> None:
    source = (
        "enabled: true\n"
        "count: 3\n"
        "ratio: -1.25\n"
        "empty: null\n"
        "quoted_bool: 'true'\n"
        'quoted_count: "3"\n'
        "items: [false, 2, 'false', null]\n"
    )
    path = tmp_path / "config.yaml"
    path.write_text(source, encoding="utf-8")
    expected = {
        "enabled": "true",
        "count": "3",
        "ratio": "-1.25",
        "empty": "null",
        "quoted_bool": "true",
        "quoted_count": "3",
        "items": ["false", "2", "false", "null"],
    }
    assert _formats.load_plain(path=path) == expected
    data, syntax = _formats.load_file(path=path)
    assert syntax == "yaml"
    assert data == expected
    assert _formats.dump_text(data=data, syntax=syntax) == source


def test_new_yaml_accepts_strings_only() -> None:
    assert (
        _formats.dump_text(data={"a": ["b"]}, syntax="yaml")
        == '"a":\n  - "b"\n'
    )
    with pytest.raises(keyloom.UnsupportedFormat, match="must be a string"):
        _formats.dump_text(data={"port": 22}, syntax="yaml")


def test_multi_line_secret_at_a_nested_key_decrypts(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "secrets.yaml"
    path.write_text(
        "db:\n  prod:\n    key:\n      __keyloom__: secret\n"
        "      value: __keyloom__secret__\n",
        encoding="utf-8",
    )
    secret = "line1\nadmin: true\n"
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm="argon2",
        prompt=lambda _location: secret,
    )

    for unwrap in (False, True):
        text = _files.decrypt_text(
            path=path, password="password", unwrap=unwrap
        )
        loaded = _formats.load_text(text=text, syntax="yaml")
        value = loaded["db"]["prod"]["key"]
        assert (value["value"] if not unwrap else value) == secret
        assert "admin" not in loaded["db"]["prod"]


@pytest.mark.parametrize(
    "source",
    [
        "secret: hunter2\nsecret: hunter3\n",
        "nested: {a: x, a: y}\n",
        "items: [a,,b]\n",
        "value: *unsafe\n",
        "value: &unsafe token\n",
        "---\nsecret: hunter2\n",
        "%!korml version 1.0\n---\nsecret: hunter2\n...\n",
    ],
)
def test_invalid_or_unsupported_yaml_is_rejected_without_secrets(
    source: str,
) -> None:
    with pytest.raises(keyloom.ParseError) as caught:
        _formats.load_text(text=source, syntax="yaml")
    assert "hunter" not in str(caught.value)
    assert "invalid YAML" in str(caught.value)


def test_nested_source_is_preserved_on_encryption(
    tmp_path: _pathlib.Path,
) -> None:
    source = (
        "# retain the heading\n"
        "flags: [true, 3, '3']\n"
        "credentials:\n"
        "  # retain this label\n"
        "  token: {__keyloom__: secret, value: old-token}\n"
        "  public: 'x:y' # unchanged\n"
    )
    path = tmp_path / "secrets.yaml"
    path.write_text(source, encoding="utf-8")
    assert (
        keyloom.encrypt_file(
            input_path=path,
            output_path=path,
            password="password",
            algorithm="argon2",
            prompt=None,
        )
        == 1
    )
    encrypted = path.read_text(encoding="utf-8")
    assert "# retain the heading" in encrypted
    assert "  # retain this label" in encrypted
    assert "  public: 'x:y' # unchanged" in encrypted
    assert encrypted.startswith("# retain the heading\nflags: [true, 3, '3']\n")
    assert keyloom.load(path=path, password="password") == {
        "flags": ["true", "3", "3"],
        "credentials": {"token": "old-token", "public": "x:y"},
    }


def test_typed_secret_with_unwrap(
    tmp_path: _pathlib.Path,
) -> None:
    source = (
        "# this stays\n"
        "public: true\n"
        "number:\n"
        "  __keyloom__: secret\n"
        '  value: "17"\n'
    )
    path = tmp_path / "config.yml"
    path.write_text(source, encoding="utf-8")
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="password",
        algorithm="argon2",
        prompt=None,
    )
    import keyloom._files as files

    text = files.decrypt_text(path=path, password="password", unwrap=True)
    assert text.startswith('# this stays\npublic: true\nnumber: "17"\n')
    assert _formats.load_text(text=text, syntax="yaml")["number"] == "17"


def test_roundtrip_guard_rejects_unsupported_structure_change() -> None:
    data = _formats.load_text(text="a: first\n", syntax="yaml")
    data["new_key"] = "bad"
    with pytest.raises(keyloom.UnsupportedFormat, match="mapping keys"):
        _formats.dump_text(data=data, syntax="yaml")
