#!/usr/bin/env python3
"""Extract the fixed Linux S3706 I2C/power/IRQ contract for later porting.

This is a source audit only. It is not an XNU driver and does not touch GPIO,
power, I2C, USB, DMA, or the phone.
"""
import hashlib
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "references/oppo-kernel/msm-4.14/drivers/input/touchscreen/oppo_touchscreen/Synaptics/S3706/synaptics_drivers_s3706.c"
HEADER = SOURCE.with_name("synaptics_s3706.h")
HARDWARE = ROOT / "device/renoace/hardware.json"
OUT = ROOT / "out/analysis/renoace-s3706-protocol.json"
DTS_BINDING = ROOT / "references/oppo-kernel/msm-4.14/arch/arm64/boot/dts/19081/sm8150-mtp.dtsi"
DTS_CONTROLLER = ROOT / "references/oppo-kernel/msm-4.14/arch/arm64/boot/dts/19081/sm8150-qupv3.dtsi"
BINDING = ROOT / "device/renoace/s3706-binding.toml"


def main():
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    hardware = json.loads(HARDWARE.read_text(encoding="utf-8"))
    binding_data = tomllib.loads(BINDING.read_text(encoding="utf-8"))
    binding = DTS_BINDING.read_text(encoding="utf-8", errors="ignore")
    controller = DTS_CONTROLLER.read_text(encoding="utf-8", errors="ignore")
    touch_match = re.search(r"synaptics19081@20\s*\{(?P<body>.*?)\n\s*\};", binding, re.S)
    touch_node = touch_match.group("body") if touch_match else ""
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
        "linux_dts_touch_binding": all(token in binding for token in ("synaptics19081@20", 'compatible = "synaptics-s3706"', "reg = <0x20>", "interrupts = <122 0x00>", "pm8150_l17", "enable1v8_gpio", "irq-gpio = <&tlmm 122 0x2008>", "reset-gpio = <&tlmm 54 0x1>", "touchpanel,panel-coords = <1080 2400>")),
        "linux_dts_geni_controller": all(token in controller for token in ("qupv3_se17_i2c: i2c@0xc80000", 'compatible = "qcom,i2c-geni"', "reg = <0xc80000 0x4000>", "interrupts = <GIC_SPI 373 0>", "GCC_QUPV3_WRAP2_S0_CLK", "GCC_QUPV3_WRAP_2_M_AHB_CLK", "GCC_QUPV3_WRAP_2_S_AHB_CLK")),
        "linux_dts_touch_node_enabled_in_reference": 'status = "disabled"' not in touch_node,
        "machine_binding_matches_resources": binding_data["controller"]["base"] == 0xc80000 and binding_data["controller"]["bytes"] == 0x4000 and binding_data["controller"]["interrupt"] == 373 and binding_data["device"]["address"] == 0x20 and binding_data["device"]["irq_gpio"] == 122 and binding_data["device"]["reset_gpio"] == 54 and binding_data["device"]["enable_1v8_gpio"] == 5,
        "machine_binding_keeps_dma_disabled": binding_data["policy"]["pio_only"] is True and binding_data["policy"]["dma_allowed"] is False,
    }
    result = {
        "passed": all(checks.values()),
        "ready_for_xnu_port": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "checks": checks,
        "source": {"path": str(SOURCE.relative_to(ROOT)), "sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(), "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(), "linux_dts_binding": str(DTS_BINDING.relative_to(ROOT)), "linux_dts_binding_sha256": hashlib.sha256(DTS_BINDING.read_bytes()).hexdigest(), "linux_dts_controller": str(DTS_CONTROLLER.relative_to(ROOT)), "linux_dts_controller_sha256": hashlib.sha256(DTS_CONTROLLER.read_bytes()).hexdigest(), "machine_binding": str(BINDING.relative_to(ROOT)), "machine_binding_sha256": hashlib.sha256(BINDING.read_bytes()).hexdigest()},
        "contract": {"page_select_register": "0xff", "discovery_pages": [0, 1, 4], "discovery_offsets": ["0xdd", "0xe3", "0xe9"], "touch_data": "F12 data base, 8 bytes per finger", "power_up": ["vdd_2v8", "vcc_1v8", "delay", "reset high"], "power_down": ["vcc_1v8 off", "vdd_2v8 off", "reset low"]},
        "measured_resources": {"i2c": hardware["touch"]["i2c_address"], "mmio": hardware["touch"]["mmio"], "irq_gpio": hardware["touch"]["irq_gpio"], "reset_gpio": hardware["touch"]["reset_gpio"], "enable_1v8_gpio": hardware["touch"]["enable_1v8_gpio"], "vdd_supply": hardware["touch"]["vdd_supply"]},
        "linux_dts_binding": {"controller": "qupv3_se17_i2c", "base": "0xc80000", "bytes": "0x4000", "interrupt": "GIC_SPI 373", "device": "synaptics19081@20", "address": "0x20", "touch_node_status": "okay", "resources": ["pm8150_l17", "enable1v8_gpio=5", "irq=122", "reset=54", "pinctrl", "panel 1080x2400"]},
        "blockers": ["The fixed Linux DTS node is not an XNU/UEFI board binding; UniXNU has no GENI-I2C transport for it.", "The source contract does not prove Reno Ace power, IRQ delivery, firmware identity, or touch reports under XNU."],
        "scope": "offline fixed Linux S3706 protocol extraction; no XNU/UEFI driver or hardware operation claim",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
