import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("p10_model", ROOT / "tools/test_renoace_smmu_probe.py")
p10 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p10)


class SmmuProbeSourceModelTests(unittest.TestCase):
    def test_all_host_cases_pass(self):
        result = p10.run()
        self.assertTrue(result["passed"])
        self.assertTrue(all(result["cases"].values()))

    def test_maximum_bounded_rows(self):
        result = p10.read_pass(p10.fixture(255))
        self.assertEqual(result["row_count"], 255)
        self.assertEqual(result["raw_bytes"], 3 * 4 + 255 * 8)

    def test_source_has_no_mmio_store_instruction(self):
        source = (ROOT / "device/renoace/xnu_smmu_probe/smmu_snapshot.c").read_text()
        self.assertIsNone(re.search(r"^\s*\*word\s*=", source, re.MULTILINE))
        self.assertNotIn("msr", source)


if __name__ == "__main__":
    unittest.main()
