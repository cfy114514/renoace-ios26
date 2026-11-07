import unittest

from tools.validate_renoace_timer_contract import run_cases


class TimerContractTests(unittest.TestCase):
    def test_contract_cases_pass(self):
        report = run_cases()
        self.assertTrue(report["passed"], report)
        self.assertEqual(len(report["cases"]), 8)
        self.assertFalse(report["hardware_tested"])


if __name__ == "__main__":
    unittest.main()
