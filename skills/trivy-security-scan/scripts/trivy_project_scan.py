#!/usr/bin/env python3
"""Run local Trivy scans and summarize HIGH/CRITICAL remediation."""

from __future__ import annotations

import argparse
import json
import shutil
import shlex
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
DEFAULT_SCANNERS = {
    "fs": "vuln,misconfig,secret,license",
    "repo": "vuln,misconfig,secret,license",
    "image": "vuln,misconfig,secret,license",
    "rootfs": "vuln,misconfig,secret,license",
    "vm": "vuln,misconfig,secret",
    "config": None,
    "sbom": "vuln,license",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Trivy locally and emit a Markdown remediation report."
    )
    parser.add_argument("--target", default=".", help="Path, image name, repo URL, SBOM, rootfs, or VM target.")
    parser.add_argument("--mode", choices=sorted(DEFAULT_SCANNERS), default="fs", help="Trivy scan mode to run.")
    parser.add_argument("--severity", default="HIGH,CRITICAL", help="Comma-separated severities.")
    parser.add_argument("--scanners", help="Override Trivy scanners for modes that support --scanners.")
    parser.add_argument("--timeout", default="15m", help="Trivy global timeout.")
    parser.add_argument("--output", help="Write Markdown report to this path instead of stdout.")
    parser.add_argument("--json-output", help="Keep the raw Trivy JSON report at this path.")
    parser.add_argument("--artifact-format", choices=["table", "sarif", "cyclonedx", "spdx-json", "github"])
    parser.add_argument("--artifact-output", help="Write a converted artifact report to this path.")
    parser.add_argument("--skip-db-update", action="store_true", help="Pass --skip-db-update to Trivy.")
    parser.add_argument("--skip-java-db-update", action="store_true", help="Pass --skip-java-db-update to Trivy.")
    parser.add_argument("--offline-scan", action="store_true", help="Pass --offline-scan to supported modes.")
    parser.add_argument("--ignore-unfixed", action="store_true", help="Pass --ignore-unfixed to vulnerability scans.")
    parser.add_argument("--include-dev-deps", action="store_true", help="Include dev dependencies where supported.")
    parser.add_argument("--dependency-tree", action="store_true", help="Ask Trivy to include dependency tree data.")
    parser.add_argument("--comprehensive", action="store_true", default=True, help="Use comprehensive detection priority.")
    parser.add_argument("--precise", action="store_true", help="Use precise detection priority instead.")
    parser.add_argument(
        "--trivy-arg",
        action="append",
        default=[],
        help="Extra raw Trivy argument. Repeat for multiple args, e.g. --trivy-arg=--skip-dirs --trivy-arg=node_modules.",
    )
    return parser.parse_args()


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def require_trivy() -> None:
    if not shutil.which("trivy"):
        raise SystemExit(
            "trivy was not found in PATH. Install Trivy first: https://trivy.dev/latest/getting-started/installation/"
        )


def build_scan_command(args: argparse.Namespace, json_path: Path) -> list[str]:
    cmd = [
        "trivy",
        "--timeout",
        args.timeout,
        args.mode,
        "--format",
        "json",
        "--output",
        str(json_path),
        "--severity",
        args.severity,
        "--disable-telemetry",
        "--skip-version-check",
    ]

    scanners = args.scanners if args.scanners is not None else DEFAULT_SCANNERS[args.mode]
    if scanners:
        cmd.extend(["--scanners", scanners])

    if args.mode not in {"config"}:
        cmd.extend(["--detection-priority", "precise" if args.precise else "comprehensive"])
        cmd.append("--no-progress")

    if args.skip_db_update and args.mode not in {"config"}:
        cmd.append("--skip-db-update")
    if args.skip_java_db_update and args.mode not in {"config"}:
        cmd.append("--skip-java-db-update")
    if args.offline_scan and args.mode not in {"config"}:
        cmd.append("--offline-scan")
    if args.ignore_unfixed and args.mode not in {"config"}:
        cmd.append("--ignore-unfixed")
    if args.include_dev_deps and args.mode in {"fs", "repo"}:
        cmd.append("--include-dev-deps")
    if args.dependency_tree and args.mode not in {"config"}:
        cmd.append("--dependency-tree")

    cmd.extend(args.trivy_arg)
    cmd.append(args.target)
    return cmd


def load_report(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def truncate(value: str, limit: int = 180) -> str:
    clean = " ".join(str(value).split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def target_location(result: dict[str, Any], item: dict[str, Any]) -> str:
    target = result.get("Target") or result.get("Class") or "unknown target"
    metadata = item.get("CauseMetadata") or {}
    file_name = metadata.get("Resource") or metadata.get("FilePath") or item.get("File") or item.get("Target")
    line = metadata.get("StartLine") or item.get("StartLine")
    if file_name and line:
        return f"{file_name}:{line}"
    if file_name:
        return str(file_name)
    return str(target)


def vuln_fix(vuln: dict[str, Any]) -> str:
    fixed = vuln.get("FixedVersion")
    package = vuln.get("PkgName", "the affected package")
    installed = vuln.get("InstalledVersion")
    if fixed:
        return f"Upgrade `{package}` from `{installed or 'current'}` to `{fixed}` or later."
    status = vuln.get("Status")
    if status in {"will_not_fix", "fix_deferred", "end_of_life"}:
        return "No fixed version is reported; replace the dependency/base image, remove the package, or document risk acceptance with VEX or `.trivyignore` after review."
    return "No fixed version is reported; check the upstream advisory, refresh lockfiles/base images, or remove the vulnerable dependency if it is unused."


def flatten_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "type": "Vulnerability",
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "id": vuln.get("VulnerabilityID", "unknown"),
                    "title": vuln.get("Title") or vuln.get("PkgName") or "Vulnerability",
                    "location": target_location(result, vuln),
                    "package": vuln.get("PkgName"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": vuln.get("FixedVersion"),
                    "url": vuln.get("PrimaryURL"),
                    "remediation": vuln_fix(vuln),
                }
            )

        for misconfig in result.get("Misconfigurations", []) or []:
            resolution = misconfig.get("Resolution") or "Update the affected IaC or configuration file to satisfy this control."
            findings.append(
                {
                    "type": "Misconfiguration",
                    "severity": misconfig.get("Severity", "UNKNOWN"),
                    "id": misconfig.get("ID", "unknown"),
                    "title": misconfig.get("Title") or misconfig.get("Message") or "Misconfiguration",
                    "location": target_location(result, misconfig),
                    "url": misconfig.get("PrimaryURL"),
                    "remediation": resolution,
                }
            )

        for secret in result.get("Secrets", []) or []:
            findings.append(
                {
                    "type": "Secret",
                    "severity": secret.get("Severity", "UNKNOWN"),
                    "id": secret.get("RuleID") or secret.get("Category") or "secret",
                    "title": secret.get("Title") or secret.get("Category") or "Potential secret",
                    "location": target_location(result, secret),
                    "remediation": "Revoke or rotate the credential, remove it from source, purge exposed history if needed, and replace it with a secret manager or environment injection.",
                }
            )

        for license_item in result.get("Licenses", []) or []:
            severity = license_item.get("Severity") or "UNKNOWN"
            findings.append(
                {
                    "type": "License",
                    "severity": severity,
                    "id": license_item.get("Name") or license_item.get("FilePath") or "license",
                    "title": license_item.get("Name") or "License finding",
                    "location": target_location(result, license_item),
                    "remediation": "Review license policy compatibility; replace the dependency or add an approved exception only after legal/security review.",
                }
            )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["type"], f["id"]))


def markdown_report(args: argparse.Namespace, cmd: list[str], report: dict[str, Any], completed: subprocess.CompletedProcess[str]) -> str:
    findings = flatten_findings(report)
    counts = Counter((f["severity"], f["type"]) for f in findings)
    lines = [
        "# Trivy Security Scan Report",
        "",
        f"- Target: `{args.target}`",
        f"- Mode: `{args.mode}`",
        f"- Severity filter: `{args.severity}`",
        f"- Command: `{' '.join(shlex.quote(part) for part in cmd)}`",
        f"- Trivy exit code: `{completed.returncode}`",
        "",
    ]

    if completed.stderr.strip():
        lines.extend(["## Trivy Messages", "", "```text", completed.stderr.strip(), "```", ""])

    if not findings:
        lines.extend(["## HIGH/CRITICAL Findings", "", "No findings matched the selected severity filter.", ""])
        return "\n".join(lines)

    lines.extend(["## Summary", ""])
    for (severity, finding_type), count in sorted(
        counts.items(), key=lambda item: (SEVERITY_ORDER.get(item[0][0], 99), item[0][1])
    ):
        lines.append(f"- {severity} {finding_type}: {count}")
    lines.append("")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[finding["severity"]].append(finding)

    for severity in sorted(grouped, key=lambda sev: SEVERITY_ORDER.get(sev, 99)):
        lines.extend([f"## {severity} Findings", ""])
        for finding in grouped[severity]:
            lines.append(f"### {finding['type']}: {finding['id']}")
            lines.append(f"- Title: {truncate(finding['title'])}")
            lines.append(f"- Location: `{finding['location']}`")
            if finding.get("package"):
                lines.append(f"- Package: `{finding['package']}`")
            if finding.get("installed"):
                lines.append(f"- Installed: `{finding['installed']}`")
            if finding.get("fixed"):
                lines.append(f"- Fixed version: `{finding['fixed']}`")
            if finding.get("url"):
                lines.append(f"- Reference: {finding['url']}")
            lines.append(f"- Mitigation: {truncate(finding['remediation'], 300)}")
            lines.append("")

    return "\n".join(lines)


def convert_artifact(args: argparse.Namespace, json_path: Path) -> subprocess.CompletedProcess[str] | None:
    if not args.artifact_format:
        return None
    if not args.artifact_output:
        raise SystemExit("--artifact-output is required when --artifact-format is set")
    cmd = [
        "trivy",
        "convert",
        "--format",
        args.artifact_format,
        "--output",
        args.artifact_output,
        "--severity",
        args.severity,
        str(json_path),
    ]
    return run(cmd)


def main() -> int:
    args = parse_args()
    require_trivy()

    with tempfile.NamedTemporaryFile(prefix="trivy-", suffix=".json", delete=False) as tmp:
        json_path = Path(tmp.name)

    cmd = build_scan_command(args, json_path)
    completed = run(cmd)
    report = load_report(json_path)
    output = markdown_report(args, cmd, report, completed)

    if args.json_output:
        Path(args.json_output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)

    converted = convert_artifact(args, json_path)
    if converted and converted.returncode != 0:
        sys.stderr.write(converted.stderr)
        return converted.returncode
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
