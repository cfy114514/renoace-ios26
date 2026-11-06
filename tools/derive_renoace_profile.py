#!/usr/bin/env python3
"""Derive non-secret board facts from a local, read-only ADB capture.

Uses the pinned ios-flame FDT reader. Never copies /chosen/bootargs, seeds,
serial numbers, IMEI, firmware or partition contents into the public profile.
This is a hardware inventory, not an Apple device tree or a bootable image.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]


def main():
    evidence = ROOT / "local-device" / (ROOT / "local-device/latest.txt").read_text().strip()
    if evidence.parent != ROOT / "local-device":
        raise ValueError("capture must be an immediate child of local-device")
    manifest = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    props = manifest["properties"]
    if props["ro.product.device"] != "OP4A89" or props["ro.boot.prjname"] != "19081":
        raise ValueError("wrong device capture")
    blob = (evidence / "live.dtb").read_bytes()
    if hashlib.sha256(blob).hexdigest() != manifest["files"]["live.dtb"]["sha256"]:
        raise ValueError("captured FDT hash mismatch")
    spec = importlib.util.spec_from_file_location("flame_fdt", ROOT / "references/ios-flame/tools/fdt.py")
    fdt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fdt)
    tree = fdt.parse(blob)
    phandles = fdt.by_phandle(tree)
    node = lambda path: fdt.lookup(tree, path)

    def registers(n):
        return [{"address": hex(a), "size": hex(s)} for a, s in n.reg()]

    def gpio(n, name):
        cells = n.u32s(name)
        return {"controller": phandles[cells[0]].path, "pin": cells[1], "flags": hex(cells[2])}

    boot = (evidence / "boot.img").read_bytes()
    if boot[:8] != b"ANDROID!":
        raise ValueError("not an Android boot image")
    names = ("kernel_size", "kernel_addr", "ramdisk_size", "ramdisk_addr", "second_size",
             "second_addr", "tags_addr", "page_size", "header_version", "os_version")
    header = dict(zip(names, struct.unpack_from("<10I", boot, 8)))
    if header["header_version"] != 2 or header["page_size"] != 4096:
        raise ValueError("boot layout differs from the measured v2/4096 profile")
    header["recovery_dtbo_size"], header["recovery_dtbo_offset"], header["header_size"] = struct.unpack_from("<IQI", boot, 1632)
    header["dtb_size"], header["dtb_addr"] = struct.unpack_from("<IQ", boot, 1648)
    header["kernel_compression"] = "gzip" if boot[4096:4098] == b"\x1f\x8b" else "unknown"
    align = lambda size: (size + 4095) & ~4095
    dtb_offset = 4096 + sum(align(header[key]) for key in ("kernel_size", "ramdisk_size", "second_size", "recovery_dtbo_size"))
    boot_dtb = boot[dtb_offset:dtb_offset + header["dtb_size"]]
    if len(boot_dtb) != header["dtb_size"] or boot_dtb[:4] != b"\xd0\x0d\xfe\xed":
        raise ValueError("invalid embedded boot DTB extent")
    (evidence / "boot.dtb").write_bytes(boot_dtb)
    stream = zlib.decompressobj(31)
    stream.decompress(boot[4096:4096+header["kernel_size"]])
    if not stream.eof or stream.unused_data != boot_dtb:
        raise ValueError("expected matching appended and independent DTBs")
    header["kernel_field_layout"] = "gzip(Image) followed by DTB"
    header["dtb_copies_identical"] = True
    (evidence / "boot-header.json").write_text(json.dumps(header, indent=2) + "\n")

    touch = node("/soc/i2c@0xc80000/synaptics19081@20")
    panel = node("/soc/qcom,mdss_mdp@ae00000/qcom,mdss_dsi_samsung_sofef03f_m_fhd_plus_90fps_cmd")
    timings = panel.child("qcom,mdss-dsi-display-timings")
    cpuinfo = (evidence / "cpuinfo.txt").read_text()
    features = sorted({flag for line in cpuinfo.splitlines() if line.startswith("Features") for flag in line.split(":", 1)[1].split()})
    profile = {
        "status": "measured-in-Android; XNU and iOS not boot-tested",
        "evidence": {"capture": str(evidence.relative_to(ROOT)).replace("\\", "/"), "fdt_sha256": hashlib.sha256(blob).hexdigest()},
        "identity": {"manufacturer": "OPPO", "model": props["ro.product.model"], "device": props["ro.product.device"], "project": props["ro.boot.prjname"], "soc": "SM8150_Plus", "soc_id": 339, "soc_revision": "2.2"},
        "android": {"product": props["ro.product.name"], "version": props["ro.build.version.release"], "verified_boot_state": props["ro.boot.verifiedbootstate"], "root_read_verified": manifest["root"], "fastboot_boot_tested": False},
        "cpu": {"count": 8, "features_reported_by_linux": features, "paca_reported": "paca" in features, "pacg_reported": "pacg" in features, "native_el1_pauth_tested": False,
                "dt_cpu_regs": [n.u32s("reg") for n in node("/cpus").children if n.name.startswith("cpu@")], "psci_method": node("/psci").str("method")},
        "memory": {"banks": registers(node("/memory")), "note": "Bank extents include reserved regions; do not use as allocator free ranges.",
                   "reservations": [{"node": n.path, "ranges": registers(n)} for n in node("/reserved-memory").children if "reg" in n.props]},
        "interrupts": {"gic": registers(node("/soc/interrupt-controller@17a00000")), "timer_hz": node("/soc/timer").u32s("clock-frequency")[0], "timer_interrupt_cells": node("/soc/timer").u32s("interrupts")},
        "display": {"component_report": "SOFEF03F_M / samsung1024", "node": panel.path, "mode": panel.str("qcom,mdss-dsi-panel-type"),
                    "timings": [{"width": n.u32s("qcom,mdss-dsi-panel-width")[0], "height": n.u32s("qcom,mdss-dsi-panel-height")[0], "refresh_hz": n.u32s("qcom,mdss-dsi-panel-framerate")[0]} for n in timings.children],
                    "splash_reserved_region": registers(node("/reserved-memory/cont_splash_region")), "actual_bootloader_scanout_address": None, "actual_stride_bytes": None},
        "touch": {"compatible": touch.str("compatible"), "controller": "Synaptics S3706", "bus": "GENI I2C", "mmio": registers(touch.parent), "i2c_address": hex(touch.u32s("reg")[0]),
                  "irq_gpio": gpio(touch, "irq-gpio"), "reset_gpio": gpio(touch, "reset-gpio"), "enable_1v8_gpio": gpio(touch, "enable1v8_gpio"),
                  "vdd_supply": phandles[touch.u32s("vdd_2v8-supply")[0]].str("regulator-name"), "vdd_requested_microvolts": touch.u32s("vdd_2v8_volt")[0], "coordinates": touch.u32s("touchpanel,panel-coords")},
        "volume_keys": {n.name: gpio(n, "gpios") for n in node("/soc/gpio_keys").children},
        "gpu": {"model": (evidence / "gpu.txt").read_text().strip(), "registers": registers(node("/soc/qcom,kgsl-3d0@2C00000"))},
        "ufs": {"registers": registers(node("/soc/ufshc@1d84000")), "ios_partition_selected": False},
        "usb": {"primary_controller": registers(node("/soc/ssusb@a600000")), "hs_phy": registers(node("/soc/hsphy@88e2000"))},
        "installed_boot_image": header,
        "backup_scope": ["boot", "dtbo", "recovery", "vbmeta"],
        "missing": ["fastboot temporary boot contract", "Reno Ace UEFI or target-XNU-compatible shim", "native XNU boot log", "bootloader display state", "SM8150 drivers for XNU 12377", "complete recovery/calibration/user-data backup", "iOS 26 userland inputs and ABI validation"],
    }
    fastboot_record = ROOT / "out/bootchain/fastboot-variables.json"
    if fastboot_record.is_file():
        values = json.loads(fastboot_record.read_text())
        profile["android"]["fastboot_unlocked_reported"] = "unlocked: yes" in values.get("unlocked", {}).get("output", "")
    boot_test = ROOT / "out/bootchain/stock-ram-boot.txt"
    if boot_test.is_file():
        result = boot_test.read_text()
        if "unknown command" in result:
            profile["android"]["fastboot_boot_tested"] = True
            profile["android"]["fastboot_boot_accepted"] = False
            profile["android"]["fastboot_boot_result"] = "download accepted; boot command rejected as unknown"
            profile["missing"].remove("fastboot temporary boot contract")
            profile["missing"].insert(0, "alternative boot entry; ABL lacks standard fastboot boot")
    target = ROOT / "device/renoace/hardware.json"
    target.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {target}; extracted {len(boot_dtb)} bytes of boot DTB to private evidence")


if __name__ == "__main__":
    main()
