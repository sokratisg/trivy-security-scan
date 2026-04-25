import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "trivy-security-scan" / "SKILL.md"


class SkillMetadataTests(unittest.TestCase):
    def test_frontmatter_has_required_fields(self):
        text = SKILL.read_text(encoding="utf-8")
        match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
        self.assertIsNotNone(match)
        frontmatter = match.group(1)
        self.assertIn("name: trivy-security-scan", frontmatter)
        self.assertIn("description:", frontmatter)

    def test_skill_has_no_user_local_paths(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertNotIn("/Users/sgaliatsis", text)
        self.assertNotIn(".codex/skills/trivy-security-scan/scripts", text)


if __name__ == "__main__":
    unittest.main()
