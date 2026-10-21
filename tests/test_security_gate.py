# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
"""The security gate script that the security-gate CI job runs."""

import json as _json
import pathlib as _pathlib
import subprocess as _subprocess
import sys as _sys

import pytest

_SCRIPT = (
    _pathlib.Path(__file__).resolve().parents[1]
    / ".gitlab"
    / "scripts"
    / "security_gate.py"
)


def _report(*, path: _pathlib.Path, findings: list[dict]) -> None:
    path.write_text(
        _json.dumps({"vulnerabilities": findings}), encoding="utf-8"
    )


def _finding(*, severity: str) -> dict:
    return {
        "severity": severity,
        "name": f"{severity} finding",
        "location": {"file": "src/example.py", "start_line": 7},
    }


def _run(*, directory: _pathlib.Path) -> _subprocess.CompletedProcess[str]:
    return _subprocess.run(
        [_sys.executable, str(_SCRIPT)],
        cwd=directory,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("secrets", "sast", "status"),
    [
        ([], [], 0),
        ([], [_finding(severity="Medium")], 0),
        ([], [_finding(severity="High")], 1),
        ([], [_finding(severity="Critical")], 1),
        ([_finding(severity="Info")], [], 1),
    ],
)
def test_exit_status_follows_the_blocking_findings(
    tmp_path: _pathlib.Path, secrets: list, sast: list, status: int
) -> None:
    _report(path=tmp_path / "gl-secret-detection-report.json", findings=secrets)
    _report(path=tmp_path / "gl-sast-report.json", findings=sast)
    _report(path=tmp_path / "gl-iac-sast-report.json", findings=[])

    result = _run(directory=tmp_path)

    assert result.returncode == status, result.stdout
    for finding in [*secrets, *sast]:
        assert f"src/example.py:7: {finding['name']}" in result.stdout


def test_missing_reports_fail_closed(tmp_path: _pathlib.Path) -> None:
    result = _run(directory=tmp_path)
    assert result.returncode == 1
    assert "gl-secret-detection-report.json: missing" in result.stdout
    assert "gl-sast-report.json: missing" in result.stdout
    assert "gl-iac-sast-report.json: missing" in result.stdout


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "{broken",
        "{}",
        '{"vulnerabilities": null}',
        '{"vulnerabilities": {}}',
        '{"vulnerabilities": [null]}',
    ],
)
def test_invalid_reports_fail_closed(
    tmp_path: _pathlib.Path, invalid: str
) -> None:
    for name in (
        "gl-secret-detection-report.json",
        "gl-sast-report.json",
        "gl-iac-sast-report.json",
    ):
        _report(path=tmp_path / name, findings=[])
        (tmp_path / name).write_text(invalid, encoding="utf-8")
        result = _run(directory=tmp_path)
        assert result.returncode == 1
        assert f"{name}: missing or invalid" in result.stdout
        _report(path=tmp_path / name, findings=[])


@pytest.mark.parametrize("severity", ["Info", "Medium", "High", "Critical"])
def test_iac_findings_are_gated(tmp_path: _pathlib.Path, severity: str) -> None:
    _report(path=tmp_path / "gl-secret-detection-report.json", findings=[])
    _report(path=tmp_path / "gl-sast-report.json", findings=[])
    _report(
        path=tmp_path / "gl-iac-sast-report.json",
        findings=[_finding(severity=severity)],
    )
    result = _run(directory=tmp_path)
    assert result.returncode == (1 if severity in {"High", "Critical"} else 0)
    assert "src/example.py:7:" in result.stdout
