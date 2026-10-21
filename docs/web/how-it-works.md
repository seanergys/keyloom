<!--
SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
SPDX-License-Identifier: Apache-2.0
-->

# How it works

This page explains what Keyloom does with a file and why, for readers who
have followed [Getting started](getting-started.md).

## The secret wrapper

A secret is an object with two fields: the marker `__keyloom__ = "secret"`
and the `value`:

```toml
[database]
host = "db.example.org"
password = { __keyloom__ = "secret", value = "hunter2" }
```

The value is a scalar, typically a string such as a token, a password or a
PEM-encoded key. The reserved string `__keyloom__secret__` marks a
placeholder, whose secret is entered at the prompt of `encrypt`. A prompt
takes a single line, so a multi-line secret is written into `value` directly.

Any other field in a wrapper is an error. Wrappers can appear at any depth of
the configuration tree, and a file can hold any number of them.

Encryption touches only the `value` field. The marker stays in place, so the
file still shows which fields are secret, and every tool can find them again
without a password.

## Encrypting a file

`encrypt` works in five steps:

1. It reads the file and collects every wrapper.
2. It decrypts every value that is already encrypted with the supplied
   password. If one of them does not decrypt, it stops.
3. It asks for the secret of every placeholder, in the order of the file.
4. It encrypts every plaintext value and every entered secret into its own
   envelope.
5. It writes the file back with only those values replaced.

Nothing is written unless every step succeeds. Values that were already
encrypted are left as they are, and a file with nothing to encrypt is not
rewritten at all.

Step 2 is what makes adding a secret safe. Take a file with one encrypted
token and one new placeholder:

```toml
[git."gitlab.example.org"]
username = "oauth2"
token = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }

[git."github.com"]
username = "ci-bot"
token = { __keyloom__ = "secret", value = "__keyloom__secret__" }
```

Running `keyloom encrypt credentials.toml` with the password of the first
token asks for the second one and encrypts it. With any other password, the
first token fails its [authentication](#authentication) check and the command
stops before asking. The file is never left with two secrets under two
different passwords.

## Envelopes

An encrypted value is a single string:

```text
$KEYLOOM;1;argon2-v2;s=...
```

It names the algorithm that produced it, here `argon2-v2`, and carries its own
random salt, its nonce, the ciphertext and an authentication tag. No
information about it is kept anywhere else in the file. Two consequences
follow.

An envelope can be copied between files. Moving the encrypted token from
`credentials.toml` into `deploy.toml` keeps it decryptable with the same
password, without re-encrypting it.

Equal secrets produce different envelopes. Encrypting `glpat-...` twice gives
two unrelated strings:

```toml
a = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=Q8f..." }
b = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=n2K..." }
```

A reader of the file therefore cannot tell that two fields hold the same
secret. In version control, `encrypt` changes only the lines of newly
encrypted secrets, while `reencrypt` changes every secret line, even when no
secret changed.

## Authentication

The authentication tag is a keyed checksum. AES-GCM computes it from the
key derived from the password, the nonce, the ciphertext and the header
`$KEYLOOM;1;argon2-v2` of the envelope, and only that key produces it.
Decryption derives the key again, recomputes the tag and compares it with the
one stored in the envelope. If the two differ, decryption fails with
`wrong password or modified keyloom value` and no plaintext is returned.

Two things make the tags differ. A wrong password derives a different key,
and a different key produces a different tag. A modified envelope changes the
data the tag is computed from: a changed ciphertext, nonce or header enters
the tag directly, and a changed salt derives a different key. Either way
`decrypt` and @apidocs::keyloom.load fail for that file. Without the tag, both
cases would return random bytes as if they were the secret.

The check is probabilistic. The tag is 128 bits long, so a wrong password or a
modified envelope passes it with a probability of about 2⁻¹²⁸, which is
negligible in practice.

The tag covers the envelope and nothing outside it. It does not record which
file or field the envelope belongs to. This is what lets an envelope be copied
between files, and also why swapping two envelopes goes undetected, as
[What is protected](#what-is-protected) shows.

## Kinds of values

The form of a marked value alone decides what it is:

| Kind        | Marked value                  | Example                   |
| ----------- | ----------------------------- | ------------------------- |
| placeholder | the reserved placeholder      | `__keyloom__secret__`     |
| encrypted   | a well-formed envelope        | `$KEYLOOM;1;argon2-v2;s=...` |
| malformed   | any other `$KEYLOOM;` string  | `$KEYLOOM;1;arg`          |
| plaintext   | anything else                 | `glpat-...`               |

`encrypt` turns plaintext and placeholders into envelopes, and stops at a
malformed envelope instead of encrypting it as plaintext. A secret entered for
a placeholder, or passed to @apidocs::keyloom.encrypt_value, follows the same
rule: a string that starts with `$KEYLOOM;` is rejected, so it is never
written to the file as it was entered. `check` fails and
@apidocs::keyloom.load refuses the file if any marked value is not encrypted.

## Wrapped and unwrapped data

The wrappers exist on disk so that Keyloom can find the secrets. Readers
choose whether to see them. `keyloom decrypt` keeps them:

```toml
token = { __keyloom__ = "secret", value = "glpat-..." }
```

`keyloom decrypt --unwrap` replaces each wrapper by its value:

```toml
token = "glpat-..."
```

@apidocs::keyloom.load always unwraps, so an application receives plain
data and never handles the marker:

```python
{"git": {"gitlab.example.org": {"username": "oauth2", "token": "glpat-..."}}}
```

## What is protected

Keyloom protects the confidentiality of the marked values at rest. It does
not protect the file against someone who can write to it. Such a person can
leave every envelope intact and still cause harm:

```toml
[upload]
url = "https://attacker.example.org"
token = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }
```

Here only the readable `url` was changed. The token decrypts correctly, and
the application sends it to the wrong server. Swapping the envelopes of two
fields has the same effect, because the authentication tag does not bind an
envelope to its field.

Guarding the file is the job of its permissions and of the repository it
lives in. Because the file stays readable, such a change is visible in review
like any other.

An envelope also reveals the length of its secret. `argon2-v2` pads each value
to a multiple of 32 bytes, so the length is revealed only to the nearest
block, and short values such as PINs, port numbers and short tokens all look
alike. `argon2` reveals the exact length.

!!! warning
    Once an application decrypts a secret, the plaintext exists in the
    application's memory. Printing, logging or serialising the loaded
    configuration exposes it again.

    Keyloom cannot wipe that memory afterwards, nor the copies of the vault
    password and the derived keys. Python strings and bytes are immutable and
    freed whenever the interpreter decides, so they can stay in memory, and
    reach swap or a core dump, after they are used. Keep core dumps and swap
    of processes that handle secrets protected accordingly.
