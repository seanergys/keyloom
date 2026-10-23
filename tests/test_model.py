# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
import copy as _copy

import pytest

import keyloom
import keyloom._envelope as _envelope
import keyloom._tree as _tree


def test_only_explicitly_marked_values_are_encrypted() -> None:
    data = {
        "username": "oauth2",
        "token": {"__keyloom__": "secret", "value": "glpat-secret"},
        "looks_secret_but_is_not_marked": "password123",
    }

    _tree.encrypt_secrets(
        data=data,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )

    assert data["username"] == "oauth2"
    assert data["looks_secret_but_is_not_marked"] == "password123"
    assert _envelope.is_encrypted(value=data["token"]["value"])


def test_nested_lists_and_dicts() -> None:
    data = {
        "items": [
            {"name": "one"},
            {"credential": {"__keyloom__": "secret", "value": "abc"}},
        ]
    }
    _tree.encrypt_secrets(
        data=data,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    credential = data["items"][1]["credential"]
    assert _envelope.is_encrypted(value=credential["value"])
    _tree.decrypt_secrets(data=data, password="password")
    assert credential["value"] == "abc"


def test_encrypt_is_idempotent() -> None:
    data = {"token": {"__keyloom__": "secret", "value": "abc"}}
    assert (
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
        == 1
    )
    once = _copy.deepcopy(data)
    assert (
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
        == 0
    )
    assert data == once


def test_unwrap_works_in_place() -> None:
    data = {
        "git": {
            "host": {
                "username": "oauth2",
                "token": {"__keyloom__": "secret", "value": "abc"},
            }
        },
        "list": [{"__keyloom__": "secret", "value": 1}, 2],
    }
    result = _tree.unwrap_secrets(data=data)
    assert result is data
    assert data == {
        "git": {"host": {"username": "oauth2", "token": "abc"}},
        "list": [1, 2],
    }


def test_unwrap_of_a_root_wrapper_returns_its_value() -> None:
    data = {"__keyloom__": "secret", "value": "abc"}
    assert _tree.unwrap_secrets(data=data) == "abc"


def test_encrypt_rejects_different_password_for_existing_ciphertext() -> None:
    data = {"a": {"__keyloom__": "secret", "value": "one"}}
    _tree.encrypt_secrets(
        data=data,
        password="first-password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    data["b"] = {"__keyloom__": "secret", "value": "two"}

    with pytest.raises(keyloom.DecryptionError):
        _tree.encrypt_secrets(
            data=data,
            password="second-password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )


def test_reserved_marker_must_be_valid() -> None:
    unknown = {"x": {"__keyloom__": "unknown", "value": "a"}}
    with pytest.raises(keyloom.InvalidSecret):
        _tree.encrypt_secrets(
            data=unknown,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
    misspelt = {"x": {"__keyloom__": "secret", "valeu": "a"}}
    with pytest.raises(keyloom.InvalidSecret, match="'valeu'"):
        _tree.encrypt_secrets(
            data=misspelt,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )


def test_wrapper_needs_a_value() -> None:
    data = {"x": {"__keyloom__": "secret"}}
    with pytest.raises(keyloom.InvalidSecret, match="missing 'value'"):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )


def test_placeholders_are_prompted_in_document_order() -> None:
    data = {
        "git": {
            "gitlab.example.org": {
                "token": {
                    "__keyloom__": "secret",
                    "value": _tree.PLACEHOLDER,
                }
            },
            "github.com": {
                "token": {
                    "__keyloom__": "secret",
                    "value": _tree.PLACEHOLDER,
                }
            },
        },
        "plain": {"__keyloom__": "secret", "value": "abc"},
    }
    asked = []

    def prompt(location: str) -> str:
        asked.append(location)
        return f"value-{len(asked)}"

    count = _tree.encrypt_secrets(
        data=data,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=prompt,
    )

    assert count == 3
    assert asked == [
        'git."gitlab.example.org".token',
        'git."github.com".token',
    ]
    _tree.decrypt_secrets(data=data, password="password")
    assert _tree.unwrap_secrets(data=data) == {
        "git": {
            "gitlab.example.org": {"token": "value-1"},
            "github.com": {"token": "value-2"},
        },
        "plain": "abc",
    }


def test_wrong_password_fails_before_any_prompt() -> None:
    data = {"a": {"__keyloom__": "secret", "value": "one"}}
    _tree.encrypt_secrets(
        data=data,
        password="right",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    data["b"] = {"__keyloom__": "secret", "value": _tree.PLACEHOLDER}

    def prompt(location: str) -> str:
        raise AssertionError(f"prompted for {location}")

    with pytest.raises(keyloom.DecryptionError):
        _tree.encrypt_secrets(
            data=data,
            password="wrong",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=prompt,
        )


def test_bad_plaintext_fails_before_any_prompt() -> None:
    data = {
        "a": {"__keyloom__": "secret", "value": _tree.PLACEHOLDER},
        "b": {"__keyloom__": "secret", "value": [1, 2]},
    }

    def prompt(location: str) -> str:
        raise AssertionError(f"prompted for {location}")

    with pytest.raises(keyloom.InvalidSecret, match=r"^b: a secret must be"):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=prompt,
        )
    with pytest.raises(keyloom.UnsupportedAlgorithm):
        _tree.encrypt_secrets(
            data={"a": {"__keyloom__": "secret", "value": _tree.PLACEHOLDER}},
            password="password",
            algorithm="unknown",
            prompt=prompt,
        )


def test_failed_prompt_leaves_the_data_unchanged() -> None:
    data = {
        "a": {"__keyloom__": "secret", "value": "one"},
        "b": {"__keyloom__": "secret", "value": _tree.PLACEHOLDER},
    }
    before = _copy.deepcopy(data)

    def prompt(location: str) -> str:
        raise keyloom.MissingSecret("secret must not be empty")

    with pytest.raises(keyloom.MissingSecret, match=r"^b: secret must"):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=prompt,
        )
    assert data == before


def test_placeholder_without_prompt_names_its_location() -> None:
    data = {"a": {"b": {"__keyloom__": "secret", "value": _tree.PLACEHOLDER}}}
    with pytest.raises(
        keyloom.MissingSecret, match=r"^a\.b: secret is a placeholder"
    ):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )


def test_placeholder_is_not_a_valid_encrypted_secret() -> None:
    data = {"token": {"__keyloom__": "secret", "value": _tree.PLACEHOLDER}}
    with pytest.raises(keyloom.MissingSecret):
        _tree.decrypt_secrets(data=data, password="password")
    with pytest.raises(keyloom.MissingSecret):
        _tree.unwrap_secrets(data=data)
    problems = _tree.find_problems(data=data, password=None)
    assert problems == [
        "token: secret is a placeholder; run keyloom encrypt to enter it"
    ]


def test_errors_name_the_location_of_the_secret() -> None:
    data = {
        "git": {
            "gitlab.example.org": {
                "tokens": [
                    {"__keyloom__": "secret", "value": "a"},
                    {"__keyloom__": "secrte", "value": "b"},
                ]
            }
        }
    }
    with pytest.raises(keyloom.InvalidSecret) as exc_info:
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
    assert str(exc_info.value).startswith(
        'git."gitlab.example.org".tokens[1]: unsupported __keyloom__'
    )


def test_non_scalar_secret_names_its_location() -> None:
    data = {"a": {"b": {"__keyloom__": "secret", "value": [1, 2]}}}
    with pytest.raises(keyloom.InvalidSecret, match=r"^a\.b: a secret must"):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )


def test_wrong_password_names_its_location() -> None:
    data = {"token": {"__keyloom__": "secret", "value": "abc"}}
    _tree.encrypt_secrets(
        data=data,
        password="right",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    with pytest.raises(
        keyloom.DecryptionError, match=r"^token: wrong password"
    ):
        _tree.decrypt_secrets(data=data, password="wrong")


def test_root_location_is_named() -> None:
    assert _tree.format_location(location=()) == "<document>"


def test_decrypt_rejects_plaintext_secrets() -> None:
    data = {"a": {"b": {"__keyloom__": "secret", "value": "plain"}}}
    with pytest.raises(keyloom.PlaintextSecret, match=r"^a\.b: secret is not"):
        _tree.decrypt_secrets(data=data, password="password")


def test_obfuscated_text_is_still_plaintext() -> None:
    # Only a well-formed envelope counts as encrypted; base64 does not.
    data = {"t": {"__keyloom__": "secret", "value": "Z2xwYXQtc2VjcmV0"}}
    with pytest.raises(keyloom.PlaintextSecret):
        _tree.decrypt_secrets(data=data, password="password")


def _problem_data() -> dict:
    data = {
        "good": {"__keyloom__": "secret", "value": "a"},
        "other": {"__keyloom__": "secret", "value": "b"},
    }
    _tree.encrypt_secrets(
        data=data,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    data["plain"] = {"__keyloom__": "secret", "value": "c"}
    data["broken"] = {"__keyloom__": "secret", "value": "$KEYLOOM;1;x"}
    data["marker"] = {"__keyloom__": "secrte", "value": "d"}
    return data


def test_find_problems_without_password_checks_structure() -> None:
    problems = _tree.find_problems(data=_problem_data(), password=None)
    assert [problem.split(":")[0] for problem in problems] == [
        "plain",
        "broken",
        "marker",
    ]
    assert "not encrypted" in problems[0]
    assert "malformed" in problems[1]
    assert "marker" in problems[2]


def test_find_problems_with_password_decrypts() -> None:
    data = _problem_data()
    assert len(_tree.find_problems(data=data, password="password")) == 3
    problems = _tree.find_problems(data=data, password="wrong")
    assert [problem.split(":")[0] for problem in problems] == [
        "good",
        "other",
        "plain",
        "broken",
        "marker",
    ]


def test_find_problems_accepts_a_clean_tree() -> None:
    data = {"t": {"__keyloom__": "secret", "value": "a"}, "n": 1}
    _tree.encrypt_secrets(
        data=data,
        password="password",
        algorithm=keyloom.Algorithm.ARGON2,
        prompt=None,
    )
    assert _tree.find_problems(data=data, password=None) == []
    assert _tree.find_problems(data=data, password="password") == []


def test_encrypt_refuses_a_malformed_envelope() -> None:
    data = {
        "token": {"__keyloom__": "secret", "value": "Z2xwYXQtLi4u"},
        "key": {"__keyloom__": "secret", "value": "$KEYLOOM;1;arg"},
    }
    before = _copy.deepcopy(data)

    with pytest.raises(keyloom.MalformedEnvelope, match=r"^key: "):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )
    assert data == before


def test_prompted_envelope_prefix_is_rejected() -> None:
    data = {"a": {"__keyloom__": "secret", "value": _tree.PLACEHOLDER}}
    before = _copy.deepcopy(data)

    with pytest.raises(keyloom.InvalidSecret, match=r"^a: value starts with"):
        _tree.encrypt_secrets(
            data=data,
            password="password",
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=lambda _location: "$KEYLOOM;typed at the prompt",
        )
    assert data == before
