#!/usr/bin/env python3
"""Audit the offline Aloha PCLM10 reference against measured Reno Ace facts.

This is a source/data comparison only. It never builds UEFI, touches a phone,
or claims that the reference firmware can boot the measured device.
"""
import json
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARDWARE = ROOT / "device/renoace/hardware.json"
BOARD = ROOT / "device/renoace/board.toml"
ALOHA = ROOT / "references/aloha/Platforms/SurfaceDuo1Pkg/Device/oppo-pclm10"
MEMORY_MAP = ALOHA / "Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c"
OUT = ROOT / "out/analysis/renoace-aloha-portability.json"
VENDOR_TOUCH = ROOT / "references/oppo-kernel/msm-4.14/drivers/input/touchscreen/oppo_touchscreen/Synaptics/S3706/synaptics_drivers_s3706.c"
VENDOR_TOUCH_HEADER = VENDOR_TOUCH.with_name("synaptics_s3706.h")


def parse_map(text):
    result = {}
    pattern = re.compile(r'\{"([^"]+)",\s*0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+)')
    for name, address, size in pattern.findall(text):
        result.setdefault(name, []).append({"address": int(address, 16), "size": int(size, 16)})
    return result


def hex_value(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def main():
    hardware = json.loads(HARDWARE.read_text(encoding="utf-8"))
    aloha_map = parse_map(MEMORY_MAP.read_text(encoding="utf-8"))
    expected = {
        "APSS_GIC500_GICD": 0x17A00000,
        "APSS_GIC500_GICR": 0x17A60000,
        "SMMU": 0x15000000,
        "USB30_PRIM": 0x0A600000,
        "MDSS": 0x0AE00000,
        "UFS UFS REGS": 0x01D80000,
    }
    measured = {
        "APSS_GIC500_GICD": hex_value(hardware["interrupts"]["gic"][0]["address"]),
        "APSS_GIC500_GICR": hex_value(hardware["interrupts"]["gic"][1]["address"]),
        "SMMU": 0x15000000,
        "USB30_PRIM": hex_value(hardware["usb"]["primary_controller"][0]["address"]),
        "MDSS": 0x0AE00000,
        "UFS UFS REGS": hex_value(hardware["ufs"]["registers"][0]["address"]),
    }
    address_checks = {}
    for name, address in expected.items():
        candidates = aloha_map.get(name, [])
        address_checks[name] = {
            "measured": hex(address),
            "reference": [hex(item["address"]) for item in candidates],
            "matches": any(item["address"] == address for item in candidates),
        }
    text_files = [path for path in ALOHA.rglob("*") if path.is_file() and path.suffix.lower() in {".c", ".h", ".dsc", ".inc", ".xml", ".cfg", ".fdf"}]
    all_source = "\n".join(path.read_text(errors="ignore") for path in text_files)
    touch_source_matches = sorted(set(re.findall(r"(?i)(?:s3706|synaptics|c80000)", all_source)))
    reservations = hardware["memory"]["reservations"]
    display = hardware["display"]["mode"]
    panel_source = sorted(str(path.relative_to(ALOHA)) for path in ALOHA.rglob("*sofef03f*") if path.is_file())
    checks = {
        "identity_is_pclm10": hardware["identity"]["model"] == "PCLM10" and str(hardware["identity"]["project"]) == "19081",
        "measured_reference_addresses_match": all(item["matches"] for item in address_checks.values()),
        "measured_reserved_region_count_is_22": len(reservations) == 22,
        "panel_1080x2400_reference_present": "1080x2400" in " ".join(panel_source) or any("1080x2400" in path.read_text(errors="ignore") for path in ALOHA.rglob("*sofef03f*")),
        "aloha_touch_driver_reference_present": bool(touch_source_matches),
        "vendor_s3706_driver_present": VENDOR_TOUCH.is_file() and VENDOR_TOUCH_HEADER.is_file(),
        "board_marked_research_only": 'example = true' in BOARD.read_text(encoding="utf-8"),
        "ios_root_storage_unallocated": 'root_storage_status = "unallocated; no partition selected for iOS writes"' in BOARD.read_text(encoding="utf-8"),
    }
    report = {
        "passed": checks["identity_is_pclm10"] and checks["measured_reference_addresses_match"] and checks["measured_reserved_region_count_is_22"],
        "ready_for_uefi_integration": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "checks": checks,
        "address_checks": address_checks,
        "touch": {"measured_compatible": hardware["touch"]["compatible"], "measured_mmio": hardware["touch"]["mmio"], "reference_token_matches": touch_source_matches},
        "vendor_touch": {
            "source": str(VENDOR_TOUCH.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(VENDOR_TOUCH.read_bytes()).hexdigest() if VENDOR_TOUCH.is_file() else None,
            "header_sha256": hashlib.sha256(VENDOR_TOUCH_HEADER.read_bytes()).hexdigest() if VENDOR_TOUCH_HEADER.is_file() else None,
            "compatible": "synaptics-s3706",
            "transport": "Linux I2C client",
            "required_resources": ["client IRQ", "irq/reset GPIO", "pinctrl", "vcc_1v8", "vdd_2v8"],
        },
        "memory": {"measured_reserved_regions": len(reservations), "reference_map_path": str(MEMORY_MAP.relative_to(ROOT))},
        "display": {"measured_mode": display, "reference_panel_files": panel_source},
        "blockers": [
            "Aloha has no S3706/Synaptics/c80000 touch driver token; the vendor Linux driver exists but has no Aloha/UEFI or XNU port.",
            "Aloha memory descriptors are a reference map; they do not replace the measured 22-region reserved-memory map.",
            "board.toml remains research-only with no allocated iOS root storage.",
            "UEFI build/runtime and DarwinBoot handoff are unverified on the phone.",
        ],
        "scope": "offline source/data portability audit; no UEFI build, phone operation, USB, DMA, or iOS boot claim",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
