<!--
SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
SPDX-License-Identifier: Apache-2.0
-->

# Python API

cpdocs generates the reference of the Python API from the source of every
published version. The whole API is the `keyloom` package:

| Purpose | API |
| --- | --- |
| Read configuration in an application | @apidocs::keyloom.load |
| Write configuration with encrypted secrets | @apidocs::keyloom.store, @apidocs::keyloom.secret |
| Encrypt, decrypt or re-encrypt a file | @apidocs::keyloom.encrypt_file, @apidocs::keyloom.decrypt_file, @apidocs::keyloom.reencrypt_file |
| Encrypt or decrypt a single value | @apidocs::keyloom.encrypt_value, @apidocs::keyloom.decrypt_value |
| Name an algorithm | @apidocs::keyloom.Algorithm, @apidocs::keyloom.algorithms |
| Catch failures | @apidocs::keyloom.KeyloomError and its subclasses |

Every parameter is keyword-only and required. `algorithm` appears only where
something is encrypted, and the caller always names it as a member of
`keyloom.Algorithm`; decryption takes the algorithm from each envelope.

## Versions

@apidocs-versions
