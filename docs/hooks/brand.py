# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Publish the brand kit with the documentation.

The brand kit that brandgen writes to share/keyloom/brandkit/generated is
published under assets/brand, so the theme and the pages use the committed
marks instead of copies inside docs/web. The API reference takes its logo and
colours from site.theme in docs/cpdocs.yml.
"""

import pathlib as _pathlib
import typing as _typing

import properdocs.structure.files as _files

_ROOT = _pathlib.Path(__file__).resolve().parents[2]
_BRANDKIT = _ROOT / "share" / "keyloom" / "brandkit" / "generated"


def on_files(
    files: _files.Files, config: _typing.Any, **_kwargs: _typing.Any
) -> _files.Files:
    for path in sorted(_BRANDKIT.rglob("*")):
        if path.suffix not in (".svg", ".png", ".pdf"):
            continue
        uri = "assets/brand/" + path.relative_to(_BRANDKIT).as_posix()
        files.append(_files.File.generated(config, uri, abs_src_path=str(path)))
    return files
