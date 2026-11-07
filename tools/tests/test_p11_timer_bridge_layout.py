import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "device/renoace/xnu_p11_probe/mmu_bridge.h"
ASSEMBLY = ROOT / "device/renoace/xnu_p11_probe/mmu_bridge.S"


class P11TimerBridgeLayoutTests(unittest.TestCase):
    def test_saved_and_witness_offsets_are_fixed(self):
        text = HEADER.read_text(encoding="utf-8")
        expected = {
            "MMU_SAVE_CNTV_CTL": 0x2F0,
            "MMU_SAVE_CNTV_CVAL": 0x2F8,
            "MMU_SAVE_CNTP_CTL": 0x300,
            "MMU_SAVE_CNTP_CVAL": 0x308,
            "MMU_SAVE_CNTV_ISTATUS": 0x310,
            "MMU_SAVE_CNTP_ISTATUS": 0x318,
            "MMU_SAVE_TIMER_VALID": 0x320,
            "MMU_TIMER_DAIF_AT_RESTORE": 0x768,
            "MMU_TIMER_DAIF_DURING": 0x770,
            "MMU_TIMER_RESTORE_VALID": 0x7B0,
        }
        for name, value in expected.items():
            match = re.search(rf"#define {name} (0x[0-9a-fA-F]+)", text)
            self.assertIsNotNone(match, name)
            self.assertEqual(int(match.group(1), 16), value, name)

    def test_restore_order_masks_daif_and_uses_absolute_cvals(self):
        text = ASSEMBLY.read_text(encoding="utf-8")
        save = text.index("SAVE_SYS cntv_ctl_el0")
        save_cval = text.index("SAVE_SYS cntv_cval_el0")
        self.assertLess(save, save_cval)
        mask = text.index("msr daifset, #15", text.index(".Lfp_restore_done:"))
        cval = text.index("RESTORE_SYS cntv_cval_el0", mask)
        pval = text.index("RESTORE_SYS cntp_cval_el0", cval)
        vctl = text.index("msr cntv_ctl_el0", pval)
        pctl = text.index("msr cntp_ctl_el0", vctl)
        self.assertLess(mask, cval)
        self.assertLess(cval, pval)
        self.assertLess(pval, vctl)
        self.assertLess(vctl, pctl)
        self.assertIn("OBS_SYS cntv_ctl_el0, MMU_TIMER_RESTORED_CNTV_CTL", text)
        self.assertIn("OBS_SYS cntp_ctl_el0, MMU_TIMER_RESTORED_CNTP_CTL", text)
        self.assertIn("str x9, [x16, #MMU_SAVE_TIMER_VALID]", text)


if __name__ == "__main__":
    unittest.main()
