#!/usr/bin/env python3
"""Validate the measured S3706 resource contract against the vendor source.

This is an offline source/data check. It is not an XNU or UEFI touch driver and
does not access the phone or toggle GPIO, power, I2C, USB, or DMA.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARDWARE = ROOT / "device/renoace/hardware.json"
SOURCE = ROOT / "references/oppo-kernel/msm-4.14/drivers/input/touchscreen/oppo_touchscreen/Synaptics/S3706/synaptics_drivers_s3706.c"
HEADER = SOURCE.with_name("synaptics_s3706.h")
OUT = ROOT / "out/analysis/renoace-touch-resource-contract.json"


def main():
    hardware = json.loads(HARDWARE.read_text(encoding="utf-8"))
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    touch = hardware["touch"]
    mmio = touch["mmio"][0]
    checks = {
        "identity": touch["compatible"] == "synaptics-s3706" and touch["controller"] == "Synaptics S3706",
        "i2c_bus_and_address": touch["bus"] == "GENI I2C" and touch["i2c_address"] == "0x20",
        "mmio_resource": mmio == {"address": "0xc80000", "size": "0x4000"},
        "gpio_resources": touch["irq_gpio"]["pin"] == 122 and touch["reset_gpio"]["pin"] == 54 and touch["enable_1v8_gpio"]["pin"] == 5,
        "power_resource": touch["vdd_supply"] == "pm8150_l17" and touch["vdd_requested_microvolts"] == 3000000,
        "vendor_sources_present": SOURCE.is_file() and HEADER.is_file(),
        "vendor_compatible_and_i2c_driver": 'TPD_DEVICE "synaptics-s3706"' in source and "struct i2c_driver" in source and ".compatible = TPD_DEVICE" in source,
        "vendor_gpio_irq_pinctrl_regulator_apis": all(token in source or token in header for token in ("reset_gpio", "irq_gpio", "pinctrl", "regulator", "client->irq")),
    }
    result = {
        "passed": all(checks.values()),
        "ready_for_xnu_or_uefi_port": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "checks": checks,
        "measured_resources": {"compatible": touch["compatible"], "bus": touch["bus"], "i2c_address": touch["i2c_address"], "mmio": mmio, "irq_gpio": touch["irq_gpio"], "reset_gpio": touch["reset_gpio"], "enable_1v8_gpio": touch["enable_1v8_gpio"], "vdd_supply": touch["vdd_supply"], "vdd_requested_microvolts": touch["vdd_requested_microvolts"], "coordinates": touch["coordinates"]},
        "vendor_source": {"source": str(SOURCE.relative_to(ROOT)), "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(), "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(), "transport": "Linux I2C client"},
        "blockers": ["No XNU/UEFI implementation or Aloha board binding exists for these resources.", "Real power, GPIO, I2C, interrupt delivery, and touch reports remain unverified under XNU."],
        "scope": "offline S3706 resource contract; no XNU/UEFI driver claim and no phone/GPIO/I2C/USB/DMA operation",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
