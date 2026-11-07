#!/usr/bin/env python3
"""Compare restored UniXNU driver personalities with measured Reno Ace needs."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XNU = ROOT / "references/UniXNU-ios26/drivers"
HW = json.loads((ROOT / "device/renoace/hardware.json").read_text(encoding="utf-8"))
OUT = ROOT / "out/analysis/renoace-xnu-driver-gaps.json"


def text(path):
    return path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""


def main():
    hid = text(XNU / "NativeHidInput/README.md") + text(XNU / "NativeHidInput/NativeHidInput.cpp")
    geni = text(XNU / "NativeGeniSpi/README.md") + text(XNU / "NativeGeniSpi/GeniSpi.c")
    display = text(XNU / "NativeMobileDisplay/README.md") + "\n".join(text(p) for p in (XNU / "NativeMobileDisplay").glob("*.cpp"))
    ufs = text(XNU / "NativeUfs/README.md") + text(XNU / "NativeUfs/NativeUfs.cpp") + text(XNU / "NativeUfs/GccUfs.h")
    checks = {
        "hid_touch_personality_exists": "touch" in hid.lower(),
        "hid_touch_is_sheng_bound": "sheng" in hid.lower(),
        "hid_touch_uses_spi_personality": "SPI" in hid,
        "geni_driver_is_spi": "SPI" in geni and "I2C" not in geni,
        "display_is_sheng_or_generic": "sheng" in display.lower(),
        "ufs_is_sm8550_sheng": "sm8550" in ufs.lower() and "sheng" in ufs.lower(),
        "ufs_base_matches_measured_controller": "0x01d84000" in ufs,
    }
    result = {
        "passed": all(checks.values()),
        "ready_for_renoace_xnu_drivers": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "measured": {
            "touch": HW["touch"],
            "display": HW["display"],
            "ufs": HW["ufs"],
        },
        "checks": checks,
        "driver_findings": {
            "touch": "NativeHidInput has a sheng/SPI-oriented touch feed; no S3706 I2C resource binding is present.",
            "geni": "NativeGeniSpi is SPI-only; Reno Ace S3706 requires GENI I2C address 0x20.",
            "display": "NativeMobileDisplay documents sheng/GOP scanout and generic legacy handoff, not the measured SOFEF03F panel sequence.",
            "ufs": "NativeUfs is documented for sheng/SM8550; its 0x01d84000 controller address matches a measured register window but does not prove SM8150 Plus clock/PHY/SMMU compatibility.",
        },
        "blockers": [
            "S3706 I2C/GPIO/regulator/IRQ board binding and XNU touch transport are missing.",
            "Measured Samsung SOFEF03F DSC command-mode panel and PMIC/DSI sequence are not wired into the generic display driver.",
            "UFS SM8150 Plus PHY/GCC/SMMU ownership and a safe root-storage policy remain unverified.",
        ],
        "scope": "offline restored-UniXNU source audit; no XNU build, phone, USB, DMA, or iOS boot claim",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
