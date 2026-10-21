<!--
SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
SPDX-License-Identifier: Apache-2.0
-->

# Reference

## Supported files

Keyloom determines the serialization format from the filename extension.

| Format | Extensions |
| --- | --- |
| TOML | `.toml` |
| YAML | `.yaml`, `.yml` |
| JSON | `.json` |

YAML input uses the KORML v0 reader: unversioned, single-document,
JSON-shaped YAML with block and flow collections. YAML anchors, aliases,
custom tags and multi-document streams are not supported. Duplicate mapping
keys and malformed collections are rejected. Every YAML scalar is a string,
quoted or not: `port: 5432` reads as the string `"5432"`, and Keyloom gives no
meaning to the values it does not encrypt. New YAML files can therefore hold
strings, lists and mappings only. When changing a loaded file, Keyloom
replaces only the values it changes, written double-quoted, and keeps every
comment and the formatting of everything else.

The `__keyloom__` representation has the same semantics in every format.

## Secret marker

A mapping is a Keyloom secret when it contains:

```text
__keyloom__ = "secret"
value = <scalar>
```

`__keyloom__` is reserved. If it is present, its value must currently be
`secret`, the mapping must contain `value`, and it may contain no other field.

A `value` of exactly `__keyloom__secret__` is a placeholder. `encrypt` asks
for its secret; every other operation rejects it:

```text
__keyloom__ = "secret"
value = "__keyloom__secret__"
```

### TOML

```toml
token = { __keyloom__ = "secret", value = "plaintext" }
```

### YAML

```yaml
token:
  __keyloom__: secret
  value: plaintext
```

### JSON

```json
{
  "token": {
    "__keyloom__": "secret",
    "value": "plaintext"
  }
}
```

Keyloom encrypts strings only, in every format; a secret that is a number or
a boolean is written as a string, such as `"5432"`. Any other value in a
secret wrapper is rejected with `InvalidSecret`, and an envelope that decrypts
to anything but a string with `MalformedEnvelope`. A placeholder always
receives a string.

### Kinds of values

The form of a `value` alone decides its kind. The placeholder
`__keyloom__secret__` is a placeholder. A string that starts with
`$KEYLOOM;` is an envelope: encrypted if it is well-formed, as described
below, and malformed otherwise. Any other value is plaintext.

`encrypt` turns plaintext and placeholders into envelopes and stops at a
malformed envelope. A secret entered for a placeholder that starts with
`$KEYLOOM;` is rejected, because it would not be plaintext. Every other
operation accepts only encrypted values.

## Encrypted value format

An encrypted scalar is one string, in this exact form:

```text
$KEYLOOM;1;argon2-v2;s=<salt>;n=<nonce>;c=<data>
```

| Field | Meaning |
| --- | --- |
| `1` | Version of the envelope grammar |
| `argon2-v2` | The algorithm that encrypted the value |
| `s` | URL-safe Base64 salt, 16 random bytes per scalar |
| `n` | URL-safe Base64 AES-GCM nonce, 12 random bytes per scalar |
| `c` | URL-safe Base64 ciphertext followed by the 16-byte GCM tag |

Each of `s`, `n` and `c` is URL-safe Base64 without `=` padding, in the
canonical form of [RFC 4648, section 3.5][rfc4648-canonical]: the unused bits
of the last character are zero. A field in any other spelling is malformed,
even when it decodes to the expected bytes, so every envelope has exactly one
spelling.

[rfc4648-canonical]: https://datatracker.ietf.org/doc/html/rfc4648#section-3.5

The envelope version only changes if the layout of the string changes. The
algorithm is a separate axis.

## Algorithms

An algorithm is a frozen suite: its name fixes every cryptographic parameter,
and neither the command line nor the API can choose them. Changing a parameter
means adding an algorithm under a new name, so a name never changes meaning and
every envelope stays readable by later versions. Decryption takes the algorithm
from the envelope; only encryption chooses one.

| Algorithm | Key derivation | Password | Padding | Encryption |
| --- | --- | --- | --- | --- |
| `argon2-v2` (default) | Argon2id, 64 MiB, 3 passes, 4 lanes | NFC, UTF-8 | 32-byte blocks | AES-256-GCM |
| `argon2` | Argon2id, 64 MiB, 3 passes, 4 lanes | UTF-8 as entered | none | AES-256-GCM |

The password is normalized to Unicode NFC before it is encoded as UTF-8, so a
password typed with a precomposed `é` and one typed as `e` plus a combining
accent derive the same key. `argon2` encodes the password exactly as entered.

AES-GCM encrypts the JSON serialization of the scalar and authenticates it
together with the first three fields, `$KEYLOOM;1;<algorithm>`, as associated
data. The file and the location of the value are not part of it, so an
envelope can be copied to another file or field;
[How it works](how-it-works.md#authentication) explains the tag. An envelope
with another layout, field order or field length is malformed, and an
algorithm this version does not know raises `UnsupportedAlgorithm`.

With padding, the serialization is followed by one `0x80` byte and as many
zero bytes as reach the next multiple of the block size, as in ISO/IEC
7816-4. An envelope therefore reveals the length of its secret only to the
nearest block: every string whose serialization takes at most 31 bytes, such
as a string of up to 29 ASCII characters, gives an envelope of the same
length. Without padding, as in `argon2`, the envelope reveals the exact
length.

## Command line

```text
keyloom encrypt [PASSWORD] [--algorithm NAME] [-o OUTPUT] FILE
keyloom decrypt [PASSWORD] [--unwrap] [-o OUTPUT] FILE
keyloom reencrypt [PASSWORD] [NEW] [--algorithm NAME] [-o OUTPUT] FILE
keyloom check [--verify [PASSWORD]] FILE...
```

`PASSWORD` is one of the password sources below: `--password-stdin` or
`--password-file FILE`. Without one, the command prompts. `NEW` is
`--change-password` or `--new-password-file FILE`.

### `keyloom encrypt`

Encrypt all marked plaintext values in a file, and ask for the value of every
placeholder.

```bash
keyloom encrypt credentials.toml
```

Without `--output`, the source file is replaced atomically. Its existing
permission bits are retained when possible.

With an explicit output:

```bash
keyloom encrypt \
  --output credentials.encrypted.toml \
  credentials.toml
```

`--algorithm` chooses the algorithm for newly encrypted values; the default is
`argon2-v2`. Already-encrypted marked values are not encrypted again. They are
authenticated with the supplied password before the operation proceeds.

The command reports how many secrets it encrypted. A file without plaintext
secrets is not rewritten, so its formatting stays exactly as it was:

```text
credentials.toml: encrypted 2 secrets
credentials.toml: nothing to encrypt
```

Interactive password input prompts twice:

```text
Vault password:
Confirm vault password:
```

After the password, whatever its source, and after every existing envelope has
been checked against it, the command asks for each placeholder in the order of
the file. Each secret is entered twice, without echo, and the prompt names its
location:

```text
Secret for git."gitlab.example.org".token:
Confirm secret for git."gitlab.example.org".token:
```

An empty secret or two different entries end the command, and so does a
placeholder when there is no terminal to prompt on. A prompt reads one line.
The file is written only after every secret has been entered.

### `keyloom decrypt`

Decrypt marked values and write the resulting document to standard output.
Every secret must be encrypted; a plaintext secret is an error.

```bash
keyloom decrypt credentials.toml
```

The secret wrappers are retained:

```toml
token = { __keyloom__ = "secret", value = "plaintext" }
```

Use `--unwrap` to replace every wrapper by its value in the emitted document.
Comments and formatting of the rest of the document are kept:

```bash
keyloom decrypt --unwrap credentials.toml
```

which emits:

```toml
token = "plaintext"
```

Writing plaintext to disk is explicit:

```bash
keyloom decrypt \
  --output credentials.plain.toml \
  credentials.toml
```

The plaintext output file is written atomically with mode `0600`; the
permissions of a file it replaces are not inherited. Keyloom refuses to
write the plaintext onto the input file itself, including through a symlink or
a hard link.

Every command that writes a file refuses two kinds of output by default. A
symbolic link at the output path would redirect the output, plaintext
included, to any file you can write; `--dangerous-allow-writing-to-symlink`
writes to the file the link points to instead and keeps the link. An output
that other hard links point to is replaced by a new file, so the other links
keep its old content, which for an in-place `encrypt` is the plaintext;
`--dangerous-allow-hard-links` writes anyway. Symlinked parent directories
are followed. The library functions take the same options as
`dangerous_allow_writing_to_symlink` and `dangerous_allow_hard_links`.

### `keyloom reencrypt`

Encrypt every secret of a file again, in memory, without writing plaintext
anywhere. This moves a file to another algorithm, or to a new password:

```bash
keyloom reencrypt --algorithm argon2-v2 credentials.toml
keyloom reencrypt --change-password credentials.toml
keyloom reencrypt --new-password-file new-password credentials.toml
```

Without `--change-password` or `--new-password-file`, the password stays the
same. `--change-password` prompts for the new password twice. The file is
replaced atomically unless `--output` names another file. Every secret must
already be encrypted.

### `keyloom check`

Fail if any secret in the given files is not encrypted:

```bash
keyloom check credentials.toml deploy/*.yaml
```

Without a password, `check` verifies the structure: every wrapper must be a
valid secret whose `value` is a well-formed envelope. It needs no password, so
it suits a CI job or a pre-commit hook that guards against committing
plaintext. With `--verify`, it also decrypts every secret with the vault
password, which shows that the file is complete and uses one password:

```bash
keyloom check --verify --password-file /run/secrets/vault credentials.toml
```

Every problem in every file is printed on its own line, and the exit status is
1 if there was any:

```text
credentials.toml: token: secret is not encrypted; run keyloom encrypt
credentials.toml: key: secret is a placeholder; run keyloom encrypt to enter it
```

A password source without `--verify` is a usage error.

## Password sources

Password-source options are mutually exclusive.

### Interactive prompt

If no password option is supplied, Keyloom reads the password with a
terminal prompt.

```bash
keyloom decrypt credentials.toml
```

The password is never echoed. Without a terminal, as in a CI job, the command
fails instead of reading it from standard input with echo; use
`--password-stdin` or `--password-file` there.

### `--password-stdin`

Read one password line from standard input:

```bash
printf '%s\n' "$KEYLOOM_PASSWORD" |
  keyloom decrypt --password-stdin credentials.toml
```

One trailing `\n` or `\r\n` line ending is removed.

### `--password-file FILE`

Read the password from a file:

```bash
keyloom decrypt \
  --password-file /run/secrets/keyloom-password \
  credentials.toml
```

One trailing `\n` or `\r\n` line ending is removed. On POSIX systems, a file
that other users can access, such as one with mode `0644`, gives a warning on
standard error; the command still runs. `chmod 600` silences it. The same
holds for `--new-password-file`.

An empty password is rejected.

## Errors and exit status

| Status | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | A failure the user can fix, reported in one line |
| 2 | Invalid command-line usage |
| 70 | An internal error: a bug in keyloom |
| 130 | Interrupted |
| 141 | The reader of standard output went away, as when piped into `head` |

No command ends with a Python traceback. A failure the user can fix, such as
a wrong password, a malformed file, an invalid secret wrapper or a missing
file, names the file and the location of the value inside it:

```text
keyloom: app.toml: token: wrong password or modified keyloom value
```

Error messages name keys and positions but never quote a line of the file or
a secret value, so a secret near a syntax error does not end up in a terminal
or a CI log.

Any other exception is a bug. The command then prints a bug report to
standard error, ready to paste into an issue at the tracker named in the
package metadata:

````text
keyloom: internal error: RuntimeError: ...

This is a bug in keyloom 0.1.0. Please open an issue at ...

### Bug report

Command: `keyloom decrypt --unwrap --password-file`

```text
keyloom 0.1.0
python 3.12.3 on Linux-...
cryptography ...
```

```text
Traceback (most recent call last):
  ...
```
````

The report names the command and its options but none of their values, such
as file names. A traceback shows code, not variables, but an exception
message can quote data, so check the report for secrets before posting it.
Nothing is saved to disk.

In Python, every failure the user can fix raises a subclass of
@apidocs::keyloom.KeyloomError; the [Python API](api.md) describes
each one.
