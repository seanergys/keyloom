# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""The public API: what ``import keyloom`` offers, and nothing else."""

import inspect as _inspect
import pathlib as _pathlib
import stat as _stat

import pytest

import keyloom

_TOML = (
    "# comment\n"
    'user = "oauth2"\n'
    'token = { __keyloom__ = "secret", value = "glpat-abc" }\n'
)


def test_public_names_are_exactly_the_api() -> None:
    assert sorted(keyloom.__all__) == sorted(
        [
            "DecryptionError",
            "InvalidSecret",
            "MalformedEnvelope",
            "MissingSecret",
            "ParseError",
            "PasswordError",
            "PlaintextSecret",
            "KeyloomError",
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
    )
    for name in keyloom.__all__:
        assert hasattr(keyloom, name)
    # "annotations" is bound by "from __future__ import annotations".
    public = {
        name
        for name in vars(keyloom)
        if not name.startswith("_") and name != "annotations"
    }
    assert public == set(keyloom.__all__) - {"__version__"}


def test_errors_share_one_base() -> None:
    for name in keyloom.__all__:
        value = getattr(keyloom, name)
        if isinstance(value, type) and issubclass(value, Exception):
            assert issubclass(value, keyloom.KeyloomError)


def test_encrypt_in_place_and_load(tmp_path: _pathlib.Path) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(_TOML, encoding="utf-8")

    count = keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="pw",
        algorithm="argon2",
        prompt=None,
    )

    assert count == 1
    text = path.read_text(encoding="utf-8")
    assert "glpat-abc" not in text
    assert "$KEYLOOM;1;argon2;" in text
    loaded = keyloom.load(path=path, password="pw")
    assert loaded == {"user": "oauth2", "token": "glpat-abc"}


def test_decrypt_file_is_the_inverse_of_encrypt_file(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(_TOML, encoding="utf-8")
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="pw",
        algorithm="argon2",
        prompt=None,
    )
    plain = tmp_path / "plain.toml"

    keyloom.decrypt_file(input_path=path, output_path=plain, password="pw")

    assert plain.read_text(encoding="utf-8") == _TOML
    assert _stat.S_IMODE(plain.stat().st_mode) == 0o600
    with pytest.raises(keyloom.UnsafeOutput):
        keyloom.decrypt_file(input_path=path, output_path=path, password="pw")


def test_encrypt_file_to_another_path(tmp_path: _pathlib.Path) -> None:
    source = tmp_path / "plain.yaml"
    source.write_text(
        "token:\n  __keyloom__: secret\n  value: abc\n", encoding="utf-8"
    )
    target = tmp_path / "encrypted.yaml"

    keyloom.encrypt_file(
        input_path=source,
        output_path=target,
        password="pw",
        algorithm="argon2",
        prompt=None,
    )

    assert "abc" in source.read_text(encoding="utf-8")
    assert keyloom.load(path=target, password="pw") == {"token": "abc"}


def test_single_values_round_trip() -> None:
    envelope = keyloom.encrypt_value(
        value="secret", password="pw", algorithm="argon2"
    )
    assert envelope.startswith("$KEYLOOM;1;argon2;")
    assert keyloom.decrypt_value(value=envelope, password="pw") == "secret"
    with pytest.raises(keyloom.DecryptionError):
        keyloom.decrypt_value(value=envelope, password="wrong")


def test_algorithms_lists_the_default() -> None:
    assert "argon2" in keyloom.algorithms()


@pytest.mark.parametrize("suffix", [".toml", ".yaml", ".json"])
def test_store_and_load_round_trip(
    tmp_path: _pathlib.Path, suffix: str
) -> None:
    path = tmp_path / f"config{suffix}"
    data = {
        "user": "oauth2",
        "token": keyloom.secret(value="glpat-abc"),
        "hosts": [{"name": "a", "port": keyloom.secret(value="22")}],
    }
    before = repr(data)

    count = keyloom.store(
        path=path, data=data, password="pw", algorithm="argon2"
    )

    assert count == 2
    assert repr(data) == before
    text = path.read_text(encoding="utf-8")
    assert "glpat-abc" not in text
    assert _stat.S_IMODE(path.stat().st_mode) == 0o600
    assert keyloom.load(path=path, password="pw") == {
        "user": "oauth2",
        "token": "glpat-abc",
        "hosts": [{"name": "a", "port": "22"}],
    }


def test_store_writes_toml_secrets_as_inline_tables(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "config.toml"
    keyloom.store(
        path=path,
        data={"git": {"token": keyloom.secret(value="abc")}},
        password="pw",
        algorithm="argon2",
    )
    text = path.read_text(encoding="utf-8")
    assert '[git]\ntoken = {__keyloom__ = "secret", value = "$KEYLOOM;' in (
        text
    )


def test_store_keeps_the_permissions_of_an_existing_file(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o640)
    keyloom.store(path=path, data={"a": 1}, password="pw", algorithm="argon2")
    assert _stat.S_IMODE(path.stat().st_mode) == 0o640


def test_store_reports_data_toml_cannot_hold(tmp_path: _pathlib.Path) -> None:
    with pytest.raises(keyloom.UnsupportedFormat, match="TOML cannot"):
        keyloom.store(
            path=tmp_path / "config.toml",
            data={"a": None},
            password="pw",
            algorithm="argon2",
        )


def test_reencrypt_changes_the_password_without_plaintext(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(_TOML, encoding="utf-8")
    keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="old",
        algorithm="argon2",
        prompt=None,
    )
    before = path.read_text(encoding="utf-8")

    count = keyloom.reencrypt_file(
        input_path=path,
        output_path=path,
        password="old",
        new_password="new",
        algorithm="argon2",
    )

    assert count == 1
    after = path.read_text(encoding="utf-8")
    assert after != before
    assert after.startswith("# comment\n")
    assert "glpat-abc" not in after
    assert keyloom.load(path=path, password="new")["token"] == "glpat-abc"
    with pytest.raises(keyloom.DecryptionError):
        keyloom.load(path=path, password="old")


def test_reencrypt_requires_every_secret_encrypted(
    tmp_path: _pathlib.Path,
) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(_TOML, encoding="utf-8")
    with pytest.raises(keyloom.PlaintextSecret):
        keyloom.reencrypt_file(
            input_path=path,
            output_path=path,
            password="pw",
            new_password="pw",
            algorithm="argon2",
        )


def test_public_api_is_defined_in_the_package() -> None:
    # cpdocs documents what the package defines, not what it imports.
    for name in keyloom.__all__:
        value = getattr(keyloom, name)
        if callable(value):
            assert value.__module__ == "keyloom", name


def test_encrypting_functions_require_an_algorithm() -> None:
    for function in (
        keyloom.store,
        keyloom.encrypt_file,
        keyloom.reencrypt_file,
        keyloom.encrypt_value,
    ):
        parameter = _inspect.signature(function).parameters["algorithm"]
        assert parameter.kind is _inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is _inspect.Parameter.empty, function.__name__


def test_encrypt_file_requires_a_prompt_argument() -> None:
    parameter = _inspect.signature(keyloom.encrypt_file).parameters["prompt"]
    assert parameter.kind is _inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is _inspect.Parameter.empty


def test_encrypt_file_fills_placeholders(tmp_path: _pathlib.Path) -> None:
    path = tmp_path / "credentials.toml"
    path.write_text(
        'user = "oauth2"\n'
        'token = { __keyloom__ = "secret", '
        'value = "__keyloom__secret__" }\n',
        encoding="utf-8",
    )

    with pytest.raises(keyloom.MissingSecret):
        keyloom.load(path=path, password="pw")
    with pytest.raises(keyloom.MissingSecret):
        keyloom.encrypt_file(
            input_path=path,
            output_path=path,
            password="pw",
            algorithm="argon2",
            prompt=None,
        )
    count = keyloom.encrypt_file(
        input_path=path,
        output_path=path,
        password="pw",
        algorithm="argon2",
        prompt=lambda location: f"entered-for-{location}",
    )

    assert count == 1
    text = path.read_text(encoding="utf-8")
    assert "entered-for" not in text
    assert keyloom.load(path=path, password="pw") == {
        "user": "oauth2",
        "token": "entered-for-token",
    }
