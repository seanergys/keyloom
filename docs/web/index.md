<!--
SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
SPDX-License-Identifier: Apache-2.0
-->

<h1 class="keyloom-title"><img src="assets/brand/logo-horizontal/svg/keyloom-logo-horizontal-color-on-transparent-none.svg" alt="Keyloom"></h1>

Keyloom is a tool that encrypts the secrets in configuration files without
changing the rest of the file. It is designed for situations where secrets are
embedded in configuration files and the files need to be stored securely
without exposing the secrets, while staying readable and editable.

Keyloom also lets users copy encrypted secrets from one file to another
without decrypting them first, as long as both files use the same password.
This makes it easy to share configuration files between environments or
systems without exposing the secrets.

Every encrypted value is authenticated. Alongside its salt and nonce, it
carries an authentication tag, a keyed checksum of the encrypted value that
is recomputed on decryption. A wrong password or a modified value yields a
different tag and is reported as an error instead of silently producing
corrupted plaintext. The check is probabilistic: a wrong password or a
modified value passes it with a probability of about 2⁻¹²⁸.
[How it works](how-it-works.md#authentication) covers the details.

Finally, Keyloom lets users add new secrets to a configuration file without
ever storing them in the file in plaintext. A secret is denoted with a special
placeholder, which tells Keyloom to prompt the user for the secret when the
file is encrypted.

The software provides both a command line interface and a Python API, making
it easy to integrate into existing workflows and applications.

## Example

A secret is marked by wrapping its value with `__keyloom__`. The value can be
a placeholder, plaintext, or an envelope copied from another file:

```toml
[git."gitlab.example.org"]
username = "oauth2"
# Asked for at a prompt when the file is encrypted
token = { __keyloom__ = "secret", value = "__keyloom__secret__" }

[database]
host = "db.example.org"
# Written in plaintext, for example on a tmpfs
password = { __keyloom__ = "secret", value = "correct-horse-battery" }

[smtp]
host = "mail.example.org"
# Copied, already encrypted, from a file with the same password
password = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }
```

Encrypting the file prompts for the token, encrypts the plaintext password and
leaves the copied envelope as it is. Everything else, comments included, stays
unchanged:

```toml
[git."gitlab.example.org"]
username = "oauth2"
# Asked for at a prompt when the file is encrypted
token = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }

[database]
host = "db.example.org"
# Written in plaintext, for example on a tmpfs
password = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }

[smtp]
host = "mail.example.org"
# Copied, already encrypted, from a file with the same password
password = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }
```

## Capabilities

- **Field-level encryption.** Only marked values are encrypted. Keys,
  structure, comments and every other value are left untouched.
- **Secrets entered at a prompt.** Each placeholder is asked for once, so the
  secret goes from the terminal to its envelope without being written to the
  file. A secret can also be written into the file directly, for example on a
  tmpfs, and is encrypted in place.
- **A guard against plaintext.** `keyloom check` confirms, without a
  password, that every marked value is encrypted. It suits a pre-commit hook
  or a CI job.
- **Re-encryption in memory.** A file moves to a new password or a new
  algorithm without its secrets touching the disk.
- **Self-contained values.** Every envelope carries its algorithm, salt,
  nonce and authentication tag, which is what allows it to be copied between
  files.
- **A Python API.** @apidocs::keyloom.load returns the decrypted
  configuration as plain dicts, lists and scalars;
  @apidocs::keyloom.store writes one with its secrets encrypted.

## File formats

The format of a file follows its extension:

| Format | Extensions      |
| ------ | --------------- |
| TOML   | `.toml`         |
| YAML   | `.yaml`, `.yml` |
| JSON   | `.json`         |

The marker means the same in every format. A secret is always a string; a
number or a boolean that is secret is written as one, such as `"5432"`. Encrypting a
TOML or YAML file keeps its comments and the formatting of every value it does
not change.

## Algorithms

An algorithm is chosen by name, and the name fixes every cryptographic
parameter. Users never tune iteration counts or memory sizes. Stronger
parameters ship as a new algorithm name, existing files keep decrypting
because each value names its algorithm, and
`keyloom reencrypt --algorithm NAME` moves a file to the new one.

| Algorithm             | Key derivation                      | Encryption  |
| --------------------- | ----------------------------------- | ----------- |
| `argon2-v2` (default) | Argon2id, 64 MiB, 3 passes, 4 lanes | AES-256-GCM |
| `argon2`              | Argon2id, 64 MiB, 3 passes, 4 lanes | AES-256-GCM |

`argon2-v2` pads each value to a multiple of 32 bytes, so an envelope does not
reveal the exact length of its secret, and normalizes the password to Unicode
NFC. `argon2` does neither; it stays readable, and `keyloom reencrypt` moves a
file from it to `argon2-v2`.

Each secret is encrypted on its own, with a random salt and nonce, and
authenticated as [How it works](how-it-works.md#authentication) describes.

## Scope

Keyloom is a small encryption primitive with a command line for people and a
Python API for applications. It protects the confidentiality of the marked
values at rest. It does not protect the file against someone who can write to
it, and once an application decrypts a secret, keeping it safe in memory is
the application's job; [How it works](how-it-works.md#what-is-protected) shows
what that means in practice.

The narrow scope lets higher-level tools share the file format while choosing
their own credential storage and user interaction. Keyloom does not:

- infer which fields are sensitive;
- manage or recover vault passwords;
- encrypt whole files;
- decide how an application stores or obtains its password;
- hide the structure or the non-secret contents of a configuration.

## Documentation

- [Getting started](getting-started.md) encrypts and decrypts one file on the
  command line and in Python, then covers checks in CI, password changes and
  automation.
- [How it works](how-it-works.md) explains the wrapper, the envelopes, the
  kinds of values and what Keyloom protects.
- The [command-line reference](reference.md) lists every command and option.
- The [Python API](api.md) documents the public package.
