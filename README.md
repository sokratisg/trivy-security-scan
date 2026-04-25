# Trivy Security Scan

Agent-neutral local security scanning helpers built around the open-source [Trivy](https://trivy.dev/) CLI.

This repository ships an installable AI-agent skill plus reusable scripts for scanning local projects, repositories, container images, SBOMs, root filesystems, and IaC/config files. It focuses remediation output on `HIGH` and `CRITICAL` findings.

No Aqua subscription, Aqua token, hosted Trivy server, or Trivy MCP plugin is required.

## Prerequisites

- Python 3.9+
- Trivy CLI installed and available on `PATH`
- Network access for the first Trivy vulnerability database download, unless a local Trivy DB is already cached

Install Trivy using the official instructions: <https://trivy.dev/latest/getting-started/installation/>

Check local prerequisites:

```bash
python3 skills/trivy-security-scan/scripts/check_prereqs.py
```

Verify first-run Trivy database download:

```bash
python3 skills/trivy-security-scan/scripts/check_prereqs.py --download-db
```

## Direct Usage

Scan a local project:

```bash
python3 skills/trivy-security-scan/scripts/trivy_project_scan.py --target . --mode fs
```

Scan an image:

```bash
python3 skills/trivy-security-scan/scripts/trivy_project_scan.py --target alpine:3.19 --mode image
```

Scan IaC/config only:

```bash
python3 skills/trivy-security-scan/scripts/trivy_project_scan.py --target ./infra --mode config
```

Write Markdown plus raw JSON:

```bash
python3 skills/trivy-security-scan/scripts/trivy_project_scan.py \
  --target . \
  --mode fs \
  --output trivy-report.md \
  --json-output trivy.json
```

Generate SARIF:

```bash
python3 skills/trivy-security-scan/scripts/trivy_project_scan.py \
  --target . \
  --mode fs \
  --artifact-format sarif \
  --artifact-output trivy.sarif
```

## Install with skills.sh

Install through the open agent skills CLI:

```bash
npx skills add sokratisg/trivy-security-scan
```

List the skill before installing:

```bash
npx skills add sokratisg/trivy-security-scan --list
```

Install globally for a specific agent:

```bash
npx skills add sokratisg/trivy-security-scan --skill trivy-security-scan -g -a codex -y
```

Install into the current project for Codex:

```bash
npx skills add sokratisg/trivy-security-scan --skill trivy-security-scan -a codex -y
```

## Install for Codex

Install the skill from GitHub:

```bash
python3 ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo sokratisg/trivy-security-scan \
  --path skills/trivy-security-scan
```

Restart Codex after installation so it can discover the skill.

Manual install:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/trivy-security-scan "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Then invoke:

```text
Use $trivy-security-scan to scan this project and recommend fixes for HIGH and CRITICAL findings.
```

## Use with Other Agents

Point the agent at `skills/trivy-security-scan/SKILL.md` and ask it to follow the workflow. The bundled scripts and references use only local files and the `trivy` CLI, so they are not tied to Codex.

Suggested prompt:

```text
Use the Trivy security scan skill in skills/trivy-security-scan to scan this project locally and recommend fixes for HIGH and CRITICAL findings.
```

## What It Scans

The default project scan uses:

```text
trivy fs --scanners vuln,misconfig,secret,license --severity HIGH,CRITICAL
```

Supported modes:

- `fs`: local filesystems and project directories
- `repo`: local or remote Git repositories
- `config`: IaC/config files
- `image`: container images and image archives
- `sbom`: SBOMs and supported attestations
- `rootfs`: unpacked root filesystems
- `vm`: experimental VM targets supported by Trivy

## Trivy MCP

Trivy MCP is optional. This project does not install or require it. Use `trivy plugin install mcp` only if you explicitly want MCP/IDE integration.

## Development

Run tests:

```bash
python3 -m unittest discover -s tests
```

Compile scripts:

```bash
python3 -m py_compile skills/trivy-security-scan/scripts/*.py
```
