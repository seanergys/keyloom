# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Version and project metadata of the keyloom distribution.

The version is defined here and only here; hatchling reads it at build time.
The project URLs are defined once, in pyproject.toml, and read back from the
installed distribution.
"""

import importlib.metadata as _importlib_metadata

__version__ = "0.2.0"

# Major, minor and patch as integers, for comparisons.
version = tuple(int(part) for part in __version__.split("."))


def issues_url() -> str | None:
    """Return the issue tracker URL, or None if it cannot be determined."""
    try:
        metadata = _importlib_metadata.metadata("keyloom")
    except _importlib_metadata.PackageNotFoundError:
        return None
    for entry in metadata.get_all("Project-URL") or []:
        label, _, url = entry.partition(",")
        if label.strip().lower() == "issues":
            return url.strip()
    return None
