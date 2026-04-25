# Agent Guidance

Use `skills/trivy-security-scan/SKILL.md` for Trivy-based local security scanning tasks.

Prefer the bundled scripts over ad hoc Trivy command construction:

- `scripts/check_prereqs.py` checks whether the environment can run the skill.
- `scripts/trivy_project_scan.py` runs Trivy and summarizes severe findings.

Do not require Aqua subscriptions, Aqua tokens, Trivy MCP, or Trivy server mode unless the user explicitly asks for those integrations.
