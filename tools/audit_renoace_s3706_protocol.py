#!/usr/bin/env python3
"""Extract the fixed Linux S3706 I2C/power/IRQ contract for later porting.

This is a source audit only. It is not an XNU driver and does not touch GPIO,
power, I2C, USB, DMA, or the phone.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "references/oppo-kernel/msm-4.14/drivers/input/touchscreen/oppo_touchscreen/Synaptics/S3706/synaptics_drivers_s3706.c"
HEADER = SOURCE.with_name("synaptics_s3706.h")
HARDWARE = ROOT / "device/renoace/hardware.json"
OUT = ROOT / "out/analysis/renoace-s3706-protocol.json"


def main():
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    hardware = json.loads(HARDWARE.read_text(encoding="utf-8"))
    checks = {
        "identity_and_i2c": 'TPD_DEVICE "synaptics-s3706"' in source and "touch_i2c_read_block" in source,
        "paged_register_select": all("touch_i2c_write_byte(chip_info->client, 0xff, 0x%X" % page in source for page in (0, 1, 4)),
        "function_discovery": all(token in source for token in ("0xDD, 4", "0xE3, 4", "0xE9, 4")),
        "touch_frame_reads": "8*fingers_to_process" in source and "F12_2D_DATA_BASE" in source,
        "power_up_order": source.index("tp_powercontrol_2v8") < source.index("tp_powercontrol_1v8") < source.index("POWEWRUP_TO_RESET_TIME"),
        "power_down_order": source.index("tp_powercontrol_1v8(chip_info->hw_res, false)") < source.index("tp_powercontrol_2v8(chip_info->hw_res, false)"),
        "irq_status_path": "F01_RMI_DATA01" in source and "F01_RMI_CTRL01" in source,
        "register_layout_declared": "struct synaptics_register" in header and "F54_ANALOG_COMMAND_BASE" in header,
        "measured_resource_match": hardware["touch"]["compatible"] == "synaptics-s3706" and hardware["touch"]["i2c_address"] == "0x20",
    }
    result = {
        "passed": all(checks.values()),
        "ready_for_xnu_port": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "checks": checks,
        "source": {"path": str(SOURCE.relative_to(ROOT)), "sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(), "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest()},
        "contract": {"page_select_register": "0xff", "discovery_pages": [0, 1, 4], "discovery_offsets": ["0xdd", "0xe3", "0xe9"], "touch_data": "F12 data base, 8 bytes per finger", "power_up": ["vdd_2v8", "vcc_1v8", "delay", "reset high"], "power_down": ["vcc_1v8 off", "vdd_2v8 off", "reset low"]},
        "measured_resources": {"i2c": hardware["touch"]["i2c_address"], "mmio": hardware["touch"]["mmio"], "irq_gpio": hardware["touch"]["irq_gpio"], "reset_gpio": hardware["touch"]["reset_gpio"], "enable_1v8_gpio": hardware["touch"]["enable_1v8_gpio"], "vdd_supply": hardware["touch"]["vdd_supply"]},
        "blockers": ["No XNU GENI-I2C transport or board binding exists.", "The source contract does not prove Reno Ace power, IRQ delivery, firmware identity, or touch reports under XNU."],
        "scope": "offline fixed Linux S3706 protocol extraction; no XNU/UEFI driver or hardware operation claim",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
