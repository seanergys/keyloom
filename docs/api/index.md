<!--
SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
SPDX-License-Identifier: Apache-2.0
-->
# {{ project }} {{ version }}

The Python API of keyloom. Everything public is defined in the
`keyloom` package; its underscore modules are the implementation and are
not part of the API.

```python
import keyloom

config = keyloom.load(path="credentials.toml", password=password)
```

The [project documentation](projectdocs:) explains the file format, the
command line and how the encryption works.
