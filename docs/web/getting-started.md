---
numbered: true
unnumbered: [next-steps]
---

<!--
SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
SPDX-License-Identifier: Apache-2.0
-->

# Getting started

This page takes one file, `credentials.toml`, through the basic steps: marking
its secrets, encrypting it and decrypting it, on the command line and in
Python. The sections after that cover checks in CI, changing the password and
supplying it in automation.

## Mark the secrets

A value is secret only when it is wrapped in an object carrying the reserved
`__keyloom__` marker. Keyloom never infers from a field name such as
`token` or `password` that a value is sensitive. The `value` holds either the
secret itself or the placeholder `__keyloom__secret__`:

=== "TOML"

    ```toml
    [git."gitlab.example.org"]
    username = "oauth2"
    token = { __keyloom__ = "secret", value = "__keyloom__secret__" }
    ```

=== "YAML"

    ```yaml
    git:
      gitlab.example.org:
        username: oauth2
        token:
          __keyloom__: secret
          value: __keyloom__secret__
    ```

=== "JSON"

    ```json
    {
      "git": {
        "gitlab.example.org": {
          "username": "oauth2",
          "token": {
            "__keyloom__": "secret",
            "value": "__keyloom__secret__"
          }
        }
      }
    }
    ```

The wrapper is the same logical object in all three formats, so the rest of
this page uses TOML. There are two ways to provide the secret:

- Write the placeholder, as above, and type the secret when the file is
  encrypted. The secret then never exists in the file as plaintext.
- Write the secret itself into `value`. This suits a file kept on a tmpfs or
  other storage where plaintext is acceptable, a secret that spans several
  lines such as a PEM key, and an existing plaintext configuration.

## Encrypt the file

### On the command line

```bash
keyloom encrypt credentials.toml
```

The command asks for the vault password and then for the secret of every
placeholder, each named by its location in the file and each entered twice.
Nothing is echoed:

```text
Vault password:
Confirm vault password:
Secret for git."gitlab.example.org".token:
Confirm secret for git."gitlab.example.org".token:
credentials.toml: encrypted 1 secret
```

A secret typed at the prompt goes to its envelope in memory; a secret written
into `value` is encrypted without a prompt. Either way the file ends up the
same, and everything outside the wrappers stays readable:

```toml
[git."gitlab.example.org"]
username = "oauth2"
token = { __keyloom__ = "secret", value = "$KEYLOOM;1;argon2-v2;s=..." }
```

Adding a secret later is the same step: add a wrapper and run `encrypt`
again. Values that are already encrypted are left encrypted and are first
verified against the supplied password, so a single run never produces a file
whose secrets use different passwords.

Placeholders need a terminal. Where there is none, as in a CI job, a
placeholder is an error and nothing is written; secrets written into `value`
need no terminal.

### In Python

@apidocs::keyloom.encrypt_file does the same for a file. `prompt` is
called once for every placeholder with its location and returns the secret;
None makes a placeholder an error. Pass the same path twice to encrypt in
place:

```python
import getpass

import keyloom

keyloom.encrypt_file(
    input_path="credentials.toml",
    output_path="credentials.toml",
    password=password,
    algorithm="argon2-v2",
    prompt=lambda location: getpass.getpass(f"Secret for {location}: "),
)
```

An application that produces its configuration itself marks the secrets with
@apidocs::keyloom.secret and writes the data with
@apidocs::keyloom.store, which encrypts them on the way to the file:

```python
keyloom.store(
    path="credentials.toml",
    data={"git": {"token": keyloom.secret(value=token)}},
    password=password,
    algorithm="argon2-v2",
)
```

`store` writes the file fresh, so the comments of an existing file are lost;
`encrypt_file` keeps the file as it is apart from the encrypted values. Unlike
the command line, the API has no default algorithm: every call that encrypts
names one.

## Decrypt the file

### On the command line

`decrypt` writes the decrypted file to standard output with the wrappers still
in place:

```bash
keyloom decrypt credentials.toml
```

`--unwrap` replaces each wrapper by its value and emits the ordinary
configuration:

```bash
keyloom decrypt --unwrap credentials.toml
```

`--output FILE` writes the decrypted file to disk instead, with mode `0600`.

### In Python

An application reads the file with @apidocs::keyloom.load, which decrypts
and unwraps the marked values in memory and returns ordinary Python data:

```python
import keyloom

credentials = keyloom.load(path="credentials.toml", password=password)
token = credentials["git"]["gitlab.example.org"]["token"]
```

@apidocs::keyloom.decrypt_file writes the decrypted file to disk with its
wrappers and mode `0600`, so `encrypt_file` turns it back into an encrypted
file. It refuses to write onto the input file:

```python
keyloom.decrypt_file(
    input_path="credentials.toml",
    output_path="credentials.plain.toml",
    password=password,
)
```

In both, a marked value that is still plaintext is an error. A file that was
never encrypted, or whose envelope was replaced by plaintext, is therefore
never decrypted silently.

## Advanced use

### Keep plaintext out of the repository

```bash
keyloom check credentials.toml
```

`check` fails if any marked value is not a well-formed envelope: plaintext, a
placeholder, or a malformed envelope. It needs no password, so it fits a
pre-commit hook or a CI job.

### Change the password or the algorithm

`reencrypt` encrypts every secret again in memory, so the plaintext never
reaches the disk:

```bash
keyloom reencrypt --change-password credentials.toml
```

The same command moves a file to another algorithm with `--algorithm`.

In Python, @apidocs::keyloom.reencrypt_file takes the current and the new
password. Passing the same password twice changes only the algorithm:

```python
keyloom.reencrypt_file(
    input_path="credentials.toml",
    output_path="credentials.toml",
    password=password,
    new_password=new_password,
    algorithm="argon2-v2",
)
```

### Supply the password in automation


Interactive commands prompt for the password. CI jobs, containers and other
non-interactive environments pass it on standard input or in a file:

```bash
printf '%s\n' "$KEYLOOM_PASSWORD" |
  keyloom decrypt --password-stdin credentials.toml
```

```bash
keyloom decrypt \
  --password-file /run/secrets/keyloom-password \
  credentials.toml
```

!!! note
    Keyloom has no `--password PASSWORD` option. A password given as a
    command-line argument can leak through shell history, logs or process
    inspection.

## Next steps

[How it works](how-it-works.md) explains the wrapper, the envelopes and what
Keyloom protects. The [command-line reference](reference.md) and the
[Python API](api.md) list every command, option and function.
