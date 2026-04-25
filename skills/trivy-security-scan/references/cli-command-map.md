# Trivy CLI Command Map

Use the installed `trivy` binary directly. Prefer local CLI scans over Aqua Platform features unless the user explicitly asks for subscription-backed behavior.

## Default Local Project Scan

Use `trivy fs` for a checked-out project:

```bash
trivy fs --scanners vuln,misconfig,secret,license --severity HIGH,CRITICAL --detection-priority comprehensive --no-progress --format json --output trivy.json .
```

This covers dependency vulnerabilities, IaC and config misconfigurations, hard-coded secrets, and license findings where Trivy supports them.

## Command Selection

- `trivy fs <path>`: default for local project directories and single files.
- `trivy repo <path-or-url>`: use for a local Git repository when branch, tag, or commit selection matters, or for remote repository URLs.
- `trivy config <dir>`: use when the user only wants IaC/config checks for Terraform, Kubernetes YAML, Helm, Dockerfiles, CloudFormation, Azure ARM, or Ansible.
- `trivy image <image>`: use for container images from Docker, containerd, Podman, remote registries, or tar archives with `--input`.
- `trivy sbom <sbom>`: use for CycloneDX, SPDX, or supported attestation files.
- `trivy rootfs <dir>`: use for unpacked root filesystems.
- `trivy vm <target>`: experimental; use for AWS AMI/EBS-style VM scans only when requested.
- `trivy convert <result.json>`: convert a JSON report to `table`, `sarif`, `cyclonedx`, `spdx-json`, `github`, or another supported report format.
- `trivy kubernetes`: experimental live-cluster scan; avoid unless the user explicitly asks to scan a Kubernetes cluster.

## Useful Flags

- `--severity HIGH,CRITICAL`: focus on actionable severe findings.
- `--scanners vuln,misconfig,secret,license`: broad local project coverage for `fs`, `repo`, `image`, and `rootfs`.
- `--detection-priority comprehensive`: find more issues at the cost of more false positives.
- `--detection-priority precise`: use when the user prioritizes fewer false positives.
- `--ignore-unfixed`: show only vulnerabilities with a reported fixed version.
- `--include-dev-deps`: include npm, Yarn, or Gradle development dependencies in `fs` and `repo` scans.
- `--offline-scan`: avoid API calls where supported.
- `--no-progress`: keep captured reports readable.
- `--skip-db-update` and `--skip-java-db-update`: use only when a local DB is already present or the network is unavailable.
- `--ignorefile .trivyignore`: default ignore file; review ignored findings before trusting a clean report.
- `--vex <source>`: use VEX statements when the user has them.
- `--format json --output <file>`: use for machine parsing before summarizing.
- `--format sarif`: use when the user wants GitHub code scanning compatible output.

## Network and Databases

Trivy fetches open vulnerability and Java databases automatically. This does not require an Aqua subscription, but it may require network access. If database update fails because the environment is offline, retry with `--skip-db-update` only if a local DB has already been downloaded.
