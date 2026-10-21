# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""The keyloom envelope: one encrypted scalar as one string.

An envelope names the algorithm that encrypted it. An algorithm is a frozen
suite: the name fixes every cryptographic parameter, and nobody can choose
them. Changing a parameter means adding an algorithm under a new name, so a
name never changes meaning and old envelopes stay readable.
"""

import base64 as _base64
import json as _json
import os as _os
import typing as _typing
import unicodedata as _unicodedata

import cryptography.exceptions as _exceptions
import cryptography.hazmat.primitives.ciphers.aead as _aead
import cryptography.hazmat.primitives.kdf.argon2 as _argon2id

import keyloom as _keyloom

MAGIC = "$KEYLOOM"
# The version of the envelope grammar, independent of the algorithm. It only
# changes if the layout of the string changes.
VERSION = "1"
DEFAULT_ALGORITHM = "argon2-v2"

KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16

# Values written by the pre-release format, which is not readable here.
_LEGACY_PREFIX = "$SEAN_VAULT;"
_FIELDS = ("s", "n", "c")


class _Parameters(_typing.TypedDict):
    """The parameters of an algorithm; the key encrypts with AES-256-GCM."""

    # Argon2id memory in KiB, passes and lanes.
    memory_cost: int
    iterations: int
    lanes: int
    # The plaintext is padded to a multiple of this many bytes, so the
    # envelope does not reveal its exact length. 0 means no padding.
    padding: int
    # The Unicode normalization form applied to the password before it is
    # encoded as UTF-8, or None to use it as it was entered.
    normalization: _typing.Literal["NFC"] | None


def _algorithms() -> dict[str, _Parameters]:
    """Return every algorithm with the parameters its name fixes.

    This table is the only place the parameters are defined. It is built
    anew on every call, so no caller can change it, and a change to it is a
    change to this one function. Tests replace the function to lower the
    Argon2id cost.
    """
    return {
        "argon2": {
            "memory_cost": 64 * 1024,
            "iterations": 3,
            "lanes": 4,
            "padding": 0,
            "normalization": None,
        },
        "argon2-v2": {
            "memory_cost": 64 * 1024,
            "iterations": 3,
            "lanes": 4,
            "padding": 32,
            "normalization": "NFC",
        },
    }


def algorithms() -> tuple[str, ...]:
    """Return the names of the supported algorithms."""
    return tuple(_algorithms())


def _parameters(*, algorithm: str) -> _Parameters:
    table = _algorithms()
    parameters = table.get(algorithm) if isinstance(algorithm, str) else None
    if parameters is None:
        known = ", ".join(table)
        raise _keyloom.UnsupportedAlgorithm(
            f"unknown algorithm {algorithm!r}; supported: {known}"
        )
    return parameters


def _aad(*, algorithm: str) -> bytes:
    return f"{MAGIC};{VERSION};{algorithm}".encode("ascii")


def is_encrypted(*, value: _typing.Any) -> bool:
    return isinstance(value, str) and value.startswith(f"{MAGIC};")


def _b64encode(*, data: bytes) -> str:
    return _base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(*, text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        data = _base64.urlsafe_b64decode(text + padding)
    # binascii.Error varies by Python implementation.
    except Exception as exc:
        raise _keyloom.MalformedEnvelope(
            "invalid base64 data in keyloom value"
        ) from exc
    # The decoder ignores the unused bits of the last character and skips
    # characters outside the alphabet, so several strings decode to the same
    # bytes. Only the one the encoder writes is accepted.
    if _b64encode(data=data) != text:
        raise _keyloom.MalformedEnvelope(
            "non-canonical base64 data in keyloom value"
        )
    return data


def _key_material(*, password: str, parameters: _Parameters) -> bytes:
    """Return the bytes of the password that the key is derived from."""
    if not password:
        raise _keyloom.PasswordError("vault password must not be empty")
    form = parameters["normalization"]
    if form is not None:
        password = _unicodedata.normalize(form, password)
    try:
        return password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _keyloom.PasswordError(
            "vault password contains a lone surrogate, which UTF-8 cannot "
            "encode"
        ) from exc


def _argon2(*, password: str, salt: bytes, algorithm: str) -> bytes:
    """Derive the key of an envelope with the parameters of its algorithm."""
    parameters = _parameters(algorithm=algorithm)
    material = _key_material(password=password, parameters=parameters)
    kdf = _argon2id.Argon2id(
        salt=salt,
        length=KEY_BYTES,
        iterations=parameters["iterations"],
        lanes=parameters["lanes"],
        memory_cost=parameters["memory_cost"],
        ad=None,
        secret=None,
    )
    return kdf.derive(material)


def _pad(*, data: bytes, block: int) -> bytes:
    """Pad to a multiple of ``block`` bytes as in ISO/IEC 7816-4.

    One 0x80 byte follows the data, then as many zero bytes as needed.
    """
    if block == 0:
        return data
    data += b"\x80"
    return data + b"\x00" * (-len(data) % block)


def _unpad(*, data: bytes, block: int) -> bytes:
    if block == 0:
        return data
    stripped = data.rstrip(b"\x00")
    if len(data) % block or not stripped.endswith(b"\x80"):
        raise _keyloom.MalformedEnvelope("decrypted value has invalid padding")
    return stripped[:-1]


def _serialize_scalar(*, value: _typing.Any) -> bytes:
    """Serialize a secret, which is always a string, as a JSON string.

    The JSON form is the plaintext format of every envelope; keeping it means
    envelopes written before secrets were strings only still decrypt.
    """
    if not isinstance(value, str):
        raise _keyloom.InvalidSecret(
            f"a secret must be a string, not {type(value).__name__}"
        )
    text = _json.dumps(value, ensure_ascii=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _keyloom.InvalidSecret(
            "string contains a lone surrogate, which UTF-8 cannot encode"
        ) from exc


def _deserialize_scalar(*, data: bytes) -> str:
    try:
        result = _json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, _json.JSONDecodeError) as exc:
        raise _keyloom.MalformedEnvelope(
            "decrypted value is not a valid keyloom secret"
        ) from exc
    if not isinstance(result, str):
        raise _keyloom.MalformedEnvelope(
            "decrypted value is not a string; secrets are strings only"
        )
    return result


def check_parameters(*, password: str, algorithm: str) -> None:
    """Raise what encrypt_value would raise for its password or algorithm."""
    _key_material(
        password=password, parameters=_parameters(algorithm=algorithm)
    )


def check_plaintext(*, value: _typing.Any) -> None:
    """Raise what encrypt_value would raise for a plaintext value.

    This costs no key derivation, so a caller can reject a bad value before
    asking a user for anything.
    """
    if isinstance(value, str) and value.startswith(_LEGACY_PREFIX):
        raise _keyloom.MalformedEnvelope(
            "value uses the pre-release $SEAN_VAULT format; decrypt it with "
            "seanervault 0.1.0 and encrypt it again"
        )
    # A string with the envelope prefix is never plaintext, whether it is
    # well-formed or not, so it is never encrypted and never kept as it is.
    if is_encrypted(value=value):
        raise _keyloom.InvalidSecret(
            f"value starts with {MAGIC}; and is not plaintext"
        )
    _serialize_scalar(value=value)


def encrypt_value(*, value: _typing.Any, password: str, algorithm: str) -> str:
    """Encrypt one scalar into a self-contained keyloom envelope."""
    check_plaintext(value=value)

    parameters = _parameters(algorithm=algorithm)
    salt = _os.urandom(SALT_BYTES)
    nonce = _os.urandom(NONCE_BYTES)
    key = _argon2(password=password, salt=salt, algorithm=algorithm)
    plaintext = _pad(
        data=_serialize_scalar(value=value), block=parameters["padding"]
    )
    aad = _aad(algorithm=algorithm)
    ciphertext = _aead.AESGCM(key).encrypt(nonce, plaintext, aad)

    # Keep the representation on one line so it works naturally in TOML
    # inline tables as well as YAML and JSON.
    return ";".join(
        (
            MAGIC,
            VERSION,
            algorithm,
            f"s={_b64encode(data=salt)}",
            f"n={_b64encode(data=nonce)}",
            f"c={_b64encode(data=ciphertext)}",
        )
    )


def _parse_envelope(*, encoded: str) -> tuple[str, bytes, bytes, bytes]:
    parts = encoded.split(";")
    if len(parts) < 2 or parts[0] != MAGIC:
        raise _keyloom.MalformedEnvelope("value is not a keyloom envelope")
    if parts[1] != VERSION:
        raise _keyloom.MalformedEnvelope(
            f"unsupported keyloom envelope version {parts[1]!r}"
        )
    if len(parts) != 3 + len(_FIELDS):
        raise _keyloom.MalformedEnvelope("malformed keyloom value")

    algorithm = parts[2]
    # Raises UnsupportedAlgorithm for a name this version does not know.
    _parameters(algorithm=algorithm)

    fields: dict[str, str] = {}
    for name, part in zip(_FIELDS, parts[3:], strict=True):
        key, separator, value = part.partition("=")
        if key != name or not separator:
            raise _keyloom.MalformedEnvelope(
                f"malformed keyloom field, expected {name}=..."
            )
        fields[name] = value

    salt = _b64decode(text=fields["s"])
    nonce = _b64decode(text=fields["n"])
    ciphertext = _b64decode(text=fields["c"])

    if len(salt) != SALT_BYTES:
        raise _keyloom.MalformedEnvelope(f"salt must be {SALT_BYTES} bytes")
    if len(nonce) != NONCE_BYTES:
        raise _keyloom.MalformedEnvelope(f"nonce must be {NONCE_BYTES} bytes")
    if len(ciphertext) < TAG_BYTES:
        raise _keyloom.MalformedEnvelope("ciphertext is too short")

    return algorithm, salt, nonce, ciphertext


def validate_envelope(*, encoded: str) -> None:
    """Check the structure of an envelope without decrypting it.

    Raises MalformedEnvelope or UnsupportedAlgorithm unless ``encoded`` is a
    well-formed envelope. Only decryption can tell whether it was encrypted
    with a given password.
    """
    if not is_encrypted(value=encoded):
        raise _keyloom.MalformedEnvelope("value is not encrypted with keyloom")
    _parse_envelope(encoded=encoded)


def decrypt_value(*, value: str, password: str) -> _typing.Any:
    """Decrypt and authenticate one keyloom envelope.

    The envelope names its algorithm, so there is nothing to choose.
    """
    if not is_encrypted(value=value):
        raise _keyloom.MalformedEnvelope("value is not encrypted with keyloom")

    algorithm, salt, nonce, ciphertext = _parse_envelope(encoded=value)
    key = _argon2(password=password, salt=salt, algorithm=algorithm)
    aad = _aad(algorithm=algorithm)

    try:
        plaintext = _aead.AESGCM(key).decrypt(nonce, ciphertext, aad)
    except _exceptions.InvalidTag as exc:
        raise _keyloom.DecryptionError(
            "wrong password or modified keyloom value"
        ) from exc

    block = _parameters(algorithm=algorithm)["padding"]
    return _deserialize_scalar(data=_unpad(data=plaintext, block=block))
