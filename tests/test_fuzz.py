# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
import os as _os
import pathlib as _pathlib
import random as _random
import string as _string
import typing as _typing

import pytest

import keyloom
import keyloom._envelope as _envelope
import keyloom._formats as _formats

_PASSWORD = "fuzz-test-password"
_SUFFIXES = {
    "toml": ".toml",
    "yaml": ".yaml",
    "json": ".json",
}
_ALPHABET = (
    _string.ascii_letters
    + _string.digits
    + _string.punctuation
    + " \t\n"
    + "äöüßé漢字🙂🚀"
)


def _random_string(*, rng: _random.Random, max_length: int) -> str:
    length = rng.randint(0, max_length)
    return "".join(rng.choice(_ALPHABET) for _ in range(length))


def _case(
    *, rng: _random.Random, case_id: int
) -> tuple[dict[str, _typing.Any], _typing.Any, str]:
    secret = _random_string(rng=rng, max_length=128)
    public = _random_string(rng=rng, max_length=128)
    data = {
        "case": str(case_id),
        "public": public,
        "payload": {
            "label": _random_string(rng=rng, max_length=64),
            "items": [
                {
                    "name": f"secret-{case_id}",
                    "credential": {
                        "__keyloom__": "secret",
                        "value": secret,
                    },
                }
            ],
        },
    }
    return data, secret, public


@pytest.mark.parametrize("syntax", _SUFFIXES)
def test_randomized_file_round_trips(
    tmp_path: _pathlib.Path, syntax: str
) -> None:
    seed = int(_os.environ.get("KEYLOOM_FUZZ_SEED", "0"))
    cases = int(_os.environ.get("KEYLOOM_FUZZ_CASES", "25"))
    assert cases > 0

    # Give each syntax an independent deterministic stream while retaining
    # one externally visible seed for easy CI reproduction.
    rng = _random.Random(f"{seed}:{syntax}")
    suffix = _SUFFIXES[syntax]

    for case_id in range(cases):
        data, expected_secret, expected_public = _case(rng=rng, case_id=case_id)
        path = tmp_path / f"case-{case_id}{suffix}"
        text = _formats.dump_text(data=data, syntax=syntax)
        path.write_text(text, encoding="utf-8")

        keyloom.encrypt_file(
            input_path=path,
            output_path=path,
            password=_PASSWORD,
            algorithm=keyloom.Algorithm.ARGON2,
            prompt=None,
        )

        encrypted, encrypted_syntax = _formats.load_file(path=path)
        assert encrypted_syntax == syntax
        credential = encrypted["payload"]["items"][0]["credential"]
        assert credential["__keyloom__"] == "secret"
        assert _envelope.is_encrypted(value=credential["value"])
        assert encrypted["public"] == expected_public

        resolved = keyloom.load(path=path, password=_PASSWORD)
        assert resolved["public"] == expected_public
        item = resolved["payload"]["items"][0]
        assert item["credential"] == expected_secret
