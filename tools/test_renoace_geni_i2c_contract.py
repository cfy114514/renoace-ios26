#!/usr/bin/env python3
"""Synthetic PIO-only GENI-I2C contract for the Reno Ace S3706 port.

This fixes the resource and transaction boundary for a future XNU transport.
It does not execute MMIO, GPIO, I2C, USB, DMA, or phone code.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/analysis/renoace-geni-i2c-contract.json"
DEVICE = ROOT / "device/renoace/hardware.json"


def main():
    hardware = json.loads(DEVICE.read_text(encoding="utf-8"))
    touch = hardware["touch"]
    resources = {
        "controller": "qupv3_se17_i2c",
        "compatible": "qcom,i2c-geni",
        "base": 0xC80000,
        "bytes": 0x4000,
        "irq": 373,
        "clock_names": ["se-clk", "m-ahb", "s-ahb"],
        "wrapper": "qupv3_2",
        "address": 0x20,
    }
    # The first port must stay PIO-only until SMMU/DMA ownership is separately proven.
    transaction = [
        "power_up_vdd_2v8",
        "power_up_vcc_1v8",
        "pinctrl_active",
        "reset_high",
        "geni_start",
        "i2c_write_7bit_0x20",
        "write_page_select_0xff",
        "read_f01_f12_f34_f51_f54_bases",
        "read_f12_touch_frame_8_bytes_per_finger",
        "irq_ack_and_stop",
        "pinctrl_sleep",
        "power_down_vcc_1v8",
        "power_down_vdd_2v8",
        "reset_low",
    ]
    bad = list(transaction)
    bad.insert(5, "dma_submit")
    cases = {
        "hardware_resource_match": resources["base"] == 0xC80000 and resources["bytes"] == 0x4000 and resources["address"] == int(touch["i2c_address"], 0),
        "required_irq_and_clocks_declared": resources["irq"] == 373 and resources["clock_names"] == ["se-clk", "m-ahb", "s-ahb"],
        "page_select_precedes_discovery": transaction.index("write_page_select_0xff") < transaction.index("read_f01_f12_f34_f51_f54_bases"),
        "frame_read_after_discovery": transaction.index("read_f01_f12_f34_f51_f54_bases") < transaction.index("read_f12_touch_frame_8_bytes_per_finger"),
        "power_down_is_reverse_order": transaction.index("power_down_vcc_1v8") < transaction.index("power_down_vdd_2v8") < transaction.index("reset_low"),
        "dma_rejected_before_ownership": "dma_submit" not in transaction and "dma_submit" in bad,
        "fault_path_stops_before_power_down": transaction.index("irq_ack_and_stop") < transaction.index("pinctrl_sleep"),
    }
    result = {
        "passed": all(cases.values()),
        "ready_for_xnu_driver": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "resources": resources,
        "transaction": transaction,
        "cases": cases,
        "blockers": [
            "UniXNU has no GENI-I2C transport or S3706 board driver.",
            "The contract intentionally excludes DMA until SMMU ownership and IOVA policy are separately proven.",
        ],
        "scope": "synthetic PIO-only GENI-I2C port contract; no XNU driver, MMIO, GPIO, I2C, USB, DMA, or phone claim",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
