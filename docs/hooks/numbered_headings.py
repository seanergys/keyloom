# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Number the sections of pages that ask for it in their front matter.

A page with `numbered: true` gets its `##` sections numbered 1, 2, ... and
its `###` sections 1.1, 1.2, ..., in the page and in its table of contents.
`unnumbered` lists the anchors of sections that stay without a number, with
their subsections, such as a closing "Next steps". The numbers are added after
the anchors are made, so the anchors carry no numbers and do not change when
the sections are reordered.
"""

import re as _re
import typing as _typing

_LEVELS = (2, 3)


def _number(
    *,
    items: _typing.Iterable[_typing.Any],
    prefix: tuple[int, ...],
    skip: frozenset[str],
) -> dict[str, str]:
    numbers: dict[str, str] = {}
    count = 0
    for item in items:
        if item.id in skip:
            continue
        if item.level in _LEVELS:
            count += 1
            number = ".".join(str(part) for part in (*prefix, count))
            numbers[item.id] = number
            item.title = f"{number} {item.title}"
            children = (*prefix, count)
        else:
            children = prefix
        numbers.update(_number(items=item.children, prefix=children, skip=skip))
    return numbers


def on_page_content(
    html: str, page: _typing.Any, **_kwargs: _typing.Any
) -> str:
    if not page.meta.get("numbered"):
        return html
    skip = frozenset(page.meta.get("unnumbered", ()))
    numbers = _number(items=page.toc, prefix=(), skip=skip)

    def heading(match: _re.Match[str]) -> str:
        number = numbers.get(match["id"])
        if number is None:
            return match[0]
        return f'{match[0]}<span class="heading-number">{number}</span> '

    return _re.sub(r'<h[23] id="(?P<id>[^"]+)"[^>]*>', heading, html)
