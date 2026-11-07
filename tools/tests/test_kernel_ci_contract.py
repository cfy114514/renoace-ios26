import hashlib
from pathlib import Path
import re
import tomllib
import unittest

from tools import prepare_renoace_kernel_ci as ci


ROOT = Path(__file__).resolve().parents[2]
DEVICE = ROOT / "device" / "renoace"
WORKFLOW = ROOT / ".github" / "workflows" / "renoace-kernel.yml"


class KernelCiContractTests(unittest.TestCase):
    """Keep the UniXNU kernel-only staging contract from silently drifting."""

    def test_pinned_inputs_exist_and_match(self):
        for relative in ci.FILES:
            path = DEVICE / relative
            self.assertTrue(path.is_file(), relative)
            self.assertFalse(path.is_symlink(), relative)
        patch = DEVICE / ci.DEVICE_PATCH
        digest = hashlib.sha256(patch.read_bytes()).hexdigest()
        self.assertEqual(digest, ci.DEVICE_PATCH_SHA256)

        feeds = tomllib.loads((DEVICE / "feeds.toml").read_text(encoding="utf-8"))
        xnu = [item for item in feeds.get("source", [])
               if item.get("name") == "xnu" and item.get("kind") == "refer"]
        self.assertEqual(len(xnu), 1)
        self.assertEqual(xnu[0].get("commit"), ci.XNU_COMMIT)

    def test_research_board_stays_guarded(self):
        board_path = DEVICE / "board.toml"
        board = tomllib.loads(board_path.read_text(encoding="utf-8"))
        self.assertEqual(board["board"]["name"], "renoace")
        self.assertTrue(board["board"]["example"])
        self.assertNotIn("outputs", board["kernel"])
        self.assertNotIn("prelink", board["kernel"])

    def test_workflow_uses_the_same_reviewed_pins(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(ci.FRAMEWORK_COMMIT, text)
        self.assertIn("repository: none24smu/UniXNU", text)
        self.assertIn("--local-module \"patch:xnu-12377=", text)
        self.assertGreaterEqual(text.count("--local-module \"patch:xnu-12377="), 4)
        self.assertIn("--verify-build", text)
        self.assertIn("--collect", text)
        self.assertNotRegex(text, r"fastboot|flash|ipsw|rootfs", re.IGNORECASE)


if __name__ == "__main__":
    unittest.main()
