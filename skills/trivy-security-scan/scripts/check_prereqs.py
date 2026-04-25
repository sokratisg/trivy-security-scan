#!/usr/bin/env python3
"""Check prerequisites for the Trivy security scan skill."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REQUIRED_COMMANDS = ["filesystem", "repository", "config", "image", "sbom", "convert"]
MIN_PYTHON = (3, 9)


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def parse_version(output: str) -> tuple[int, ...] | None:
    match = re.search(r"Version:\s*([0-9]+(?:\.[0-9]+){1,2})", output)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def check_command_help(command: str) -> tuple[bool, str]:
    completed = run(["trivy", command, "--help"])
    if completed.returncode == 0:
        return True, f"trivy {command}: available"
    return False, f"trivy {command}: unavailable ({completed.stderr.strip() or completed.stdout.strip()})"


def check_db_download() -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="trivy-prereq-") as temp_dir:
        completed = run(["trivy", "fs", "--download-db-only", "--no-progress", temp_dir])
    if completed.returncode == 0:
        return True, "Trivy vulnerability DB: download/update succeeded"
    return False, "Trivy vulnerability DB: download/update failed: " + (completed.stderr.strip() or completed.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify prerequisites for the Trivy security scan skill.")
    parser.add_argument(
        "--download-db",
        action="store_true",
        help="Also verify that Trivy can download/update its public vulnerability database.",
    )
    args = parser.parse_args()

    failures: list[str] = []
    print("Trivy security scan prerequisite check")
    print(f"Python: {sys.version.split()[0]}")
    if sys.version_info < MIN_PYTHON:
        failures.append(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required")

    trivy_path = shutil.which("trivy")
    if not trivy_path:
        failures.append("trivy was not found in PATH")
    else:
        print(f"trivy: {trivy_path}")
        version_check = run(["trivy", "--version"])
        version = parse_version(version_check.stdout + version_check.stderr)
        if version:
            print("Trivy version: " + ".".join(str(part) for part in version))
        else:
            failures.append("Unable to parse `trivy --version` output")

        for command in REQUIRED_COMMANDS:
            ok, message = check_command_help(command)
            print(message)
            if not ok:
                failures.append(message)

        plugin_check = run(["trivy", "plugin", "list"])
        plugin_output = (plugin_check.stdout + plugin_check.stderr).strip()
        if "mcp" in plugin_output.lower():
            print("Trivy MCP plugin: installed (optional)")
        else:
            print("Trivy MCP plugin: not installed (optional)")

        if args.download_db:
            ok, message = check_db_download()
            print(message)
            if not ok:
                failures.append(message)
        else:
            print("Trivy vulnerability DB: not checked; rerun with --download-db to verify first-run DB download")

    if failures:
        print("\nPrerequisite check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nPrerequisite check passed.")
    print("No Aqua subscription, Aqua token, Trivy MCP plugin, or Trivy server is required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
