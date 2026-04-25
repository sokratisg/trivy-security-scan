import importlib.util
import subprocess
import unittest
from argparse import Namespace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "trivy-security-scan" / "scripts" / "trivy_project_scan.py"


spec = importlib.util.spec_from_file_location("trivy_project_scan", SCRIPT)
trivy_project_scan = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(trivy_project_scan)


class TrivyProjectScanTests(unittest.TestCase):
    def test_build_scan_command_defaults_to_broad_fs_scan(self):
        args = Namespace(
            timeout="15m",
            mode="fs",
            severity="HIGH,CRITICAL",
            scanners=None,
            precise=False,
            skip_db_update=False,
            skip_java_db_update=False,
            offline_scan=False,
            ignore_unfixed=False,
            include_dev_deps=False,
            dependency_tree=False,
            trivy_arg=[],
            target=".",
        )

        cmd = trivy_project_scan.build_scan_command(args, Path("/tmp/result.json"))

        self.assertIn("fs", cmd)
        self.assertIn("--scanners", cmd)
        self.assertIn("vuln,misconfig,secret,license", cmd)
        self.assertIn("--severity", cmd)
        self.assertIn("HIGH,CRITICAL", cmd)
        self.assertIn("--no-progress", cmd)
        self.assertIn("--disable-telemetry", cmd)

    def test_flatten_findings_handles_vulnerability_fix(self):
        report = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-0000-0001",
                            "Severity": "CRITICAL",
                            "PkgName": "demo",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                        }
                    ],
                }
            ]
        }

        findings = trivy_project_scan.flatten_findings(report)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("1.0.1", findings[0]["remediation"])

    def test_secret_report_does_not_require_secret_value(self):
        report = {
            "Results": [
                {
                    "Target": "app.env",
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Severity": "HIGH",
                            "Title": "AWS Access Key ID",
                            "Match": "AKIAEXAMPLESECRET",
                            "StartLine": 2,
                        }
                    ],
                }
            ]
        }
        args = Namespace(target=".", mode="fs", severity="HIGH,CRITICAL")
        completed = subprocess.CompletedProcess(["trivy"], 0, "", "")

        output = trivy_project_scan.markdown_report(args, ["trivy"], report, completed)

        self.assertIn("AWS Access Key ID", output)
        self.assertIn("rotate", output)
        self.assertNotIn("AKIAEXAMPLESECRET", output)


if __name__ == "__main__":
    unittest.main()
