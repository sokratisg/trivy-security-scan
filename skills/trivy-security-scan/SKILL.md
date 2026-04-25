---
name: trivy-security-scan
description: Run local Trivy CLI security scans and summarize remediation for severe findings. Use when an AI agent needs to scan projects, repositories, container images, SBOMs, root filesystems, or IaC/config files with Trivy for vulnerabilities, misconfigurations, secrets, or license findings; prioritize HIGH and CRITICAL findings; explain mitigations or fix actions; generate SARIF/SBOM-style reports; or advise on Trivy MCP without requiring an Aqua subscription.
---

# Trivy Security Scan

## Workflow

Use the installed `trivy` CLI directly. Do not require an Aqua subscription, Aqua Platform token, Trivy server, or MCP server for ordinary local scans.

1. Resolve bundled script paths relative to this skill directory.
2. Run `scripts/check_prereqs.py` when the user asks to verify setup, when `trivy` may be missing, or before first use in a new environment.
3. Confirm the target and scan mode from the user request.
4. Prefer `scripts/trivy_project_scan.py` for local project scans and remediation summaries.
5. Read `references/cli-command-map.md` when choosing non-default scan modes or flags.
6. Read `references/remediation.md` before giving mitigation advice.
7. Read `references/mcp.md` only when the user asks about Trivy MCP or IDE/MCP integration.
8. Report HIGH and CRITICAL findings first. Include MEDIUM/LOW only when the user asks for all findings.

## Prerequisite Check

Run:

```bash
python3 scripts/check_prereqs.py
```

Use `--download-db` only when the user wants to verify first-run Trivy database download:

```bash
python3 scripts/check_prereqs.py --download-db
```

The prerequisite checker verifies Python, `trivy`, required Trivy commands, and optional MCP plugin state. It does not require Aqua credentials.

## Default Scan

For a local project, run from this skill directory or substitute the absolute path to the script:

```bash
python3 scripts/trivy_project_scan.py --target . --mode fs
```

The wrapper runs Trivy in JSON mode with a broad local profile:

- `--scanners vuln,misconfig,secret,license`
- `--severity HIGH,CRITICAL`
- `--detection-priority comprehensive`
- `--disable-telemetry`
- `--no-progress`
- `--skip-version-check`

It parses vulnerabilities, misconfigurations, secrets, and licenses into a Markdown remediation report. It never prints matched secret values.

## Mode Selection

- Use `--mode fs` for a local project directory or file.
- Use `--mode repo` for a local or remote Git repository, especially when branch, tag, or commit selection matters.
- Use `--mode config` for IaC/config-only scanning.
- Use `--mode image` for container images or tar archives; pass Trivy-specific flags with repeated `--trivy-arg`.
- Use `--mode sbom` for CycloneDX, SPDX, or supported attestation files.
- Use `--mode rootfs` for unpacked root filesystems.
- Use `--mode vm` only when the user explicitly asks for experimental VM image scanning.

Examples:

```bash
python3 scripts/trivy_project_scan.py --target . --mode fs --include-dev-deps
python3 scripts/trivy_project_scan.py --target alpine:3.19 --mode image
python3 scripts/trivy_project_scan.py --target ./infra --mode config
python3 scripts/trivy_project_scan.py --target ./sbom.cdx.json --mode sbom
```

## Reports

Keep raw JSON when deeper analysis is needed:

```bash
python3 scripts/trivy_project_scan.py --target . --mode fs --json-output trivy.json --output trivy-report.md
```

Generate converted artifacts when requested:

```bash
python3 scripts/trivy_project_scan.py --target . --mode fs --artifact-format sarif --artifact-output trivy.sarif
```

Supported artifact formats are `table`, `sarif`, `cyclonedx`, `spdx-json`, and `github`.

## Remediation Guidance

For vulnerabilities, prefer Trivy's fixed version. For images, recommend base image refreshes or package removal when package upgrades are not enough. For IaC misconfigurations, use Trivy's resolution and line metadata. For secrets, recommend rotation/revocation before cleanup and never expose the matched secret. For licenses, frame findings as policy review inputs, not legal advice.

Use `.trivyignore`, `--ignore-policy`, or VEX only for reviewed false positives or accepted risk. Prefer fixing over suppressing.

## Offline and MCP Notes

Trivy database downloads do not require an Aqua subscription, but they may require network access. If updates fail because the environment is offline, retry with `--skip-db-update` only when a local database already exists.

MCP is optional. If `trivy plugin list` does not show `mcp`, do not use `trivy mcp` unless the user asks to install or configure the plugin.
