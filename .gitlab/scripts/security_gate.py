# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""Fail the pipeline on findings in GitLab's security reports.

Without GitLab Ultimate, scanner findings appear only in the report artifacts
and never fail a pipeline. This script fails on any detected secret and on
Critical or High SAST and IaC findings, and lists every finding. Missing or
malformed reports fail closed: a successful scanner always produces a report.
The security-gate job requires reports in every pipeline, including tags.

Run it in the directory that holds the downloaded reports.
"""

import json as _json
import pathlib as _pathlib
import sys as _sys


def describe(*, finding: dict) -> str:
    """Return one line naming the severity, location and title of a finding."""
    severity = finding.get("severity", "Unknown")
    location = finding.get("location", {})
    where = f"{location.get('file')}:{location.get('start_line')}"
    title = finding.get("name") or finding.get("message")
    return f"{severity}: {where}: {title}"


def check(*, path: _pathlib.Path, blocking: set[str] | None) -> bool:
    """Print findings; fail on blocking findings or an unreadable report.

    With blocking None, every finding blocks. Even a clean scanner must
    generate a valid report with a vulnerabilities array.
    """
    try:
        report = _json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("report must be a JSON object")
        findings = report.get("vulnerabilities")
        if not isinstance(findings, list) or any(
            not isinstance(finding, dict) for finding in findings
        ):
            raise ValueError("vulnerabilities must be an array of objects")
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"{path.name}: missing or invalid security report: {exc}")
        return True
    print(f"{path.name}: {len(findings)} finding(s)")
    failed = False
    for finding in findings:
        print(f"  {describe(finding=finding)}")
        if blocking is None or finding.get("severity") in blocking:
            failed = True
    return failed


def main() -> int:
    """Check every required scanner report in the working directory."""
    failed = False
    for name, blocking in (
        ("gl-secret-detection-report.json", None),
        ("gl-sast-report.json", {"Critical", "High"}),
        ("gl-iac-sast-report.json", {"Critical", "High"}),
    ):
        # Do not short-circuit: a missing report must not hide other findings.
        failed = check(path=_pathlib.Path(name), blocking=blocking) or failed
    return 1 if failed else 0


if __name__ == "__main__":
    _sys.exit(main())
