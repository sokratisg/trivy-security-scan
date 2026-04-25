# Remediation Rules

## Vulnerabilities

- Prefer the exact `FixedVersion` reported by Trivy.
- For application dependencies, update the manifest and lockfile using the project's package manager, then rerun tests and the scan.
- For OS packages in images, rebuild on a newer base image, run the distro package upgrade in the Dockerfile, or remove the package.
- If no fixed version is available, check whether the vulnerable component is reachable, replace it, remove it, or record a reviewed VEX or `.trivyignore` entry.
- Treat end-of-life base images or distributions as requiring base image replacement, not only package upgrades.

## Misconfigurations

- Use Trivy's `Resolution`, `Message`, and line metadata as the primary fix clue.
- For Terraform, Kubernetes, Helm, Dockerfile, CloudFormation, Azure ARM, and Ansible findings, recommend the smallest config change that satisfies the control.
- Do not apply config changes automatically unless the user asks for remediation edits.
- After remediation, rerun the same scan mode and severity filter.

## Secrets

- Do not print matched secret values.
- Recommend immediate rotation/revocation before code cleanup if a real secret may have been committed.
- Remove the secret from source, replace it with a secret manager or environment variable injection, and purge Git history only when exposure warrants it.
- For false positives, tune `trivy-secret.yaml` or add narrowly scoped ignores with review context.

## Licenses

- Treat Trivy license findings as policy review inputs, not legal advice.
- Recommend dependency replacement or an approved exception when a license conflicts with the project policy.
- Use `--ignored-licenses` only when the user has an explicit allow/ignore policy.

## Suppression and Risk Acceptance

- Prefer fixing findings over suppressing them.
- Use `.trivyignore`, `--ignore-policy`, or VEX only with a reason, owner, and review date.
- Mention ignored or suppressed findings when `--show-suppressed` is used.
