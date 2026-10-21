# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
import cryptography.hazmat.primitives.ciphers.aead as _aead
import pytest

import keyloom
import keyloom._envelope as _envelope


def _encrypt(*, value: object, password: str) -> str:
    return _envelope.encrypt_value(
        value=value, password=password, algorithm="argon2"
    )


def _replace_field(*, encoded: str, name: str, value: str) -> str:
    parts = encoded.split(";")
    index = next(i for i, p in enumerate(parts) if p.startswith(f"{name}="))
    parts[index] = f"{name}={value}"
    return ";".join(parts)


def _flip_first(*, text: str) -> str:
    return ("A" if text[0] != "A" else "B") + text[1:]


@pytest.mark.parametrize("value", ["token", "123", "", "é\n\\"])
def test_round_trip_scalar(value: object) -> None:
    encrypted = _encrypt(value=value, password="correct horse")
    assert _envelope.is_encrypted(value=encrypted)
    decrypted = _envelope.decrypt_value(
        value=encrypted, password="correct horse"
    )
    assert decrypted == value


def test_non_ascii_password_round_trips() -> None:
    encrypted = _encrypt(value="secret", password="pässwört-漢字🙂")
    decrypted = _envelope.decrypt_value(
        value=encrypted, password="pässwört-漢字🙂"
    )
    assert decrypted == "secret"


@pytest.mark.real_kdf
def test_argon2_uses_its_frozen_parameters() -> None:
    assert _envelope._algorithms() == {
        "argon2": {
            "memory_cost": 65536,
            "iterations": 3,
            "lanes": 4,
            "padding": 0,
            "normalization": None,
        },
        "argon2-v2": {
            "memory_cost": 65536,
            "iterations": 3,
            "lanes": 4,
            "padding": 32,
            "normalization": "NFC",
        },
    }
    encrypted = _encrypt(value="secret", password="password")
    assert encrypted.startswith("$KEYLOOM;1;argon2;s=")
    decrypted = _envelope.decrypt_value(value=encrypted, password="password")
    assert decrypted == "secret"


# Envelopes written by earlier versions, with the real parameters. A name
# never changes meaning, so each must decrypt forever.
_KNOWN_ANSWERS = {
    "argon2": (
        "$KEYLOOM;1;argon2;s=0CikPAME-byta3-E871iCA;n=IqybQLEb8_vQJqC-;"
        "c=Jl8Lakk200a5vpsdGNU4PtOng2h5NdAHmATnUIbU"
    ),
    "argon2-v2": (
        "$KEYLOOM;1;argon2-v2;s=DQM7NPPHfKqv5RMyzsqKSQ;n=WdCwW-fW8xwvMhcN;"
        "c=SyC47BfBQ-0n-QgwI-9HGkAxqdkRDMI_GO6bBBDHTzvWNSxDctdGnMyFj_rFIbss"
    ),
}


@pytest.mark.real_kdf
@pytest.mark.parametrize("algorithm", sorted(_KNOWN_ANSWERS))
def test_known_answer_still_decrypts(algorithm: str) -> None:
    decrypted = _envelope.decrypt_value(
        value=_KNOWN_ANSWERS[algorithm], password="correct horse"
    )
    assert decrypted == "known answer"


@pytest.mark.parametrize("algorithm", _envelope.algorithms())
def test_every_algorithm_round_trips(algorithm: str) -> None:
    encrypted = _envelope.encrypt_value(
        value="secret", password="password", algorithm=algorithm
    )
    assert encrypted.startswith(f"$KEYLOOM;1;{algorithm};")
    decrypted = _envelope.decrypt_value(value=encrypted, password="password")
    assert decrypted == "secret"
    assert algorithm in _envelope.algorithms()


def test_unknown_algorithm_is_rejected_for_encryption() -> None:
    with pytest.raises(keyloom.UnsupportedAlgorithm, match="'chamar'"):
        _envelope.encrypt_value(
            value="secret", password="password", algorithm="chamar"
        )


def test_unknown_algorithm_is_rejected_for_decryption() -> None:
    encrypted = _encrypt(value="secret", password="password")
    modified = encrypted.replace(";argon2;", ";chamar;", 1)
    with pytest.raises(keyloom.UnsupportedAlgorithm, match="'chamar'"):
        _envelope.decrypt_value(value=modified, password="password")


def test_ciphertext_is_randomized() -> None:
    first = _encrypt(value="same", password="password")
    second = _encrypt(value="same", password="password")
    assert first != second


def test_wrong_password_fails() -> None:
    encrypted = _encrypt(value="secret", password="right-password")
    with pytest.raises(keyloom.DecryptionError):
        _envelope.decrypt_value(value=encrypted, password="wrong-password")


@pytest.mark.parametrize("name", ["s", "n", "c"])
def test_modified_salt_nonce_or_ciphertext_fails(name: str) -> None:
    encrypted = _encrypt(value="secret", password="password")
    original = encrypted.split(f";{name}=", 1)[1].split(";", 1)[0]
    modified = _replace_field(
        encoded=encrypted, name=name, value=_flip_first(text=original)
    )
    with pytest.raises(keyloom.DecryptionError):
        _envelope.decrypt_value(value=modified, password="password")


def test_reordered_fields_are_rejected() -> None:
    encrypted = _encrypt(value="secret", password="password")
    parts = encrypted.split(";")
    parts[3], parts[4] = parts[4], parts[3]
    with pytest.raises(keyloom.MalformedEnvelope, match="malformed"):
        _envelope.decrypt_value(value=";".join(parts), password="password")


def _field(*, encoded: str, name: str) -> str:
    return encoded.split(f";{name}=", 1)[1].split(";", 1)[0]


def _flip_unused_bit(*, text: str) -> str:
    # The last character carries 6 bits, of which only those that complete a
    # byte are used. Flipping the lowest one changes the spelling, not the
    # decoded bytes.
    unused = 6 * len(text) % 8
    assert unused > 0, "the field has no unused bits"
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    return text[:-1] + alphabet[alphabet.index(text[-1]) ^ 1]


# A 16-byte salt leaves 4 unused bits. The ciphertext of "token" is 7 bytes
# of JSON and the 16-byte tag, 23 bytes in all, which leaves 2. A 12-byte
# nonce fills its last character exactly, so it has none.
@pytest.mark.parametrize("name", ["s", "c"])
def test_non_zero_unused_bits_are_rejected(name: str) -> None:
    encrypted = _encrypt(value="token", password="password")
    modified = _replace_field(
        encoded=encrypted,
        name=name,
        value=_flip_unused_bit(text=_field(encoded=encrypted, name=name)),
    )
    with pytest.raises(keyloom.MalformedEnvelope, match="non-canonical"):
        _envelope.decrypt_value(value=modified, password="password")


@pytest.mark.parametrize("name", ["s", "n", "c"])
def test_padded_field_is_rejected(name: str) -> None:
    encrypted = _encrypt(value="token", password="password")
    modified = _replace_field(
        encoded=encrypted,
        name=name,
        value=_field(encoded=encrypted, name=name) + "==",
    )
    with pytest.raises(keyloom.MalformedEnvelope, match="base64"):
        _envelope.decrypt_value(value=modified, password="password")


def test_long_salt_is_rejected() -> None:
    encrypted = _encrypt(value="secret", password="password")
    modified = _replace_field(encoded=encrypted, name="s", value="A" * 32)
    with pytest.raises(keyloom.MalformedEnvelope, match="salt"):
        _envelope.decrypt_value(value=modified, password="password")


def test_other_format_version_is_rejected() -> None:
    encrypted = _encrypt(value="secret", password="password")
    modified = encrypted.replace("$KEYLOOM;1;", "$KEYLOOM;2;", 1)
    with pytest.raises(keyloom.MalformedEnvelope, match="envelope version"):
        _envelope.decrypt_value(value=modified, password="password")


def test_pre_release_envelope_is_not_encrypted_again() -> None:
    legacy = "$SEAN_VAULT;1;ARGON2ID;AES256_GCM;m=65536;t=3;p=4;s=a;n=b;c=c"
    assert not _envelope.is_encrypted(value=legacy)
    with pytest.raises(keyloom.MalformedEnvelope, match="pre-release"):
        _encrypt(value=legacy, password="password")


def test_non_encrypted_value_is_rejected() -> None:
    with pytest.raises(keyloom.MalformedEnvelope):
        _envelope.decrypt_value(value="plaintext", password="password")


def test_non_scalar_value_is_an_invalid_secret() -> None:
    with pytest.raises(keyloom.InvalidSecret, match="not dict"):
        _encrypt(value={"x": 1}, password="password")


def test_empty_password_is_a_password_error() -> None:
    with pytest.raises(keyloom.PasswordError):
        _encrypt(value="secret", password="")


@pytest.mark.parametrize(
    "value",
    [
        "$KEYLOOM;my plaintext token",
        "$KEYLOOM;1;argon2;s=a;n=b;c=c",
    ],
)
def test_envelope_prefix_is_never_plaintext(value: str) -> None:
    with pytest.raises(keyloom.InvalidSecret, match="is not plaintext"):
        _encrypt(value=value, password="password")


def test_well_formed_envelope_is_not_encrypted_again() -> None:
    encrypted = _encrypt(value="token", password="password")
    with pytest.raises(keyloom.InvalidSecret, match="is not plaintext"):
        _encrypt(value=encrypted, password="password")


@pytest.mark.real_kdf
def test_algorithm_table_cannot_be_changed_by_callers() -> None:
    table = _envelope._algorithms()
    table["argon2"]["memory_cost"] = 8
    assert _envelope._algorithms()["argon2"]["memory_cost"] == 64 * 1024


def test_algorithm_must_be_a_known_name() -> None:
    for algorithm in ("chamar", ["argon2"], None):
        with pytest.raises(keyloom.UnsupportedAlgorithm):
            _envelope.encrypt_value(
                value="token",
                password="password",
                algorithm=algorithm,  # type: ignore[arg-type]
            )


def test_padding_hides_the_length_of_short_values() -> None:
    lengths = {
        len(
            _envelope.encrypt_value(
                value=value, password="password", algorithm="argon2-v2"
            )
        )
        for value in ("", "true", "7", "1234567", "glpat-abcdefghijklmnop")
    }
    assert len(lengths) == 1


@pytest.mark.parametrize("length", [0, 28, 29, 30, 31, 61, 62])
def test_padded_values_round_trip_at_block_edges(length: int) -> None:
    value = "x" * length
    encrypted = _envelope.encrypt_value(
        value=value, password="password", algorithm="argon2-v2"
    )
    assert _envelope.decrypt_value(value=encrypted, password="password") == (
        value
    )


def test_argon2_v2_normalizes_the_password() -> None:
    composed, decomposed = "caf\u00e9", "cafe\u0301"
    encrypted = _envelope.encrypt_value(
        value="token", password=composed, algorithm="argon2-v2"
    )
    assert (
        _envelope.decrypt_value(value=encrypted, password=decomposed) == "token"
    )


def test_argon2_keeps_the_password_as_entered() -> None:
    encrypted = _envelope.encrypt_value(
        value="token", password="caf\u00e9", algorithm="argon2"
    )
    with pytest.raises(keyloom.DecryptionError):
        _envelope.decrypt_value(value=encrypted, password="cafe\u0301")


def test_invalid_padding_is_malformed() -> None:
    algorithm = "argon2-v2"
    salt, nonce = b"s" * _envelope.SALT_BYTES, b"n" * _envelope.NONCE_BYTES
    key = _envelope._argon2(password="password", salt=salt, algorithm=algorithm)
    ciphertext = _aead.AESGCM(key).encrypt(
        nonce, b'"unpadded"', _envelope._aad(algorithm=algorithm)
    )
    encoded = ";".join(
        (
            "$KEYLOOM;1;argon2-v2",
            f"s={_envelope._b64encode(data=salt)}",
            f"n={_envelope._b64encode(data=nonce)}",
            f"c={_envelope._b64encode(data=ciphertext)}",
        )
    )
    with pytest.raises(keyloom.MalformedEnvelope, match="padding"):
        _envelope.decrypt_value(value=encoded, password="password")


def test_password_with_a_lone_surrogate_is_rejected() -> None:
    with pytest.raises(keyloom.PasswordError, match="lone surrogate"):
        _encrypt(value="token", password="pass\udcffword")
    with pytest.raises(keyloom.PasswordError, match="lone surrogate"):
        _envelope.check_parameters(password="\ud800", algorithm="argon2-v2")


@pytest.mark.parametrize("value", [123, 1.25, True, None, b"bytes"])
def test_only_strings_can_be_encrypted(value: object) -> None:
    with pytest.raises(keyloom.InvalidSecret, match="must be a string"):
        _envelope.encrypt_value(
            value=value, password="password", algorithm="argon2-v2"
        )
