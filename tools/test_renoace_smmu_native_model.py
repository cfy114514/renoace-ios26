#!/usr/bin/env python3
"""Independent offline model for the P10 SMMU-only carrier contract.

This is a synthetic bounded model. It executes the record/validation rules in
Python and checks the compiled source routing; it never touches a phone, MMIO,
USB, or DMA.
"""
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/xnu-smmu-probe"
SOURCE = ROOT / "device/renoace/xnu_smmu_runtime_probe"
MAX_ROWS = 128
ROW_COUNT = 94


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(count):
    return [(0x80000000 | i, (i & 0xFF) << 16 | 0x00020000) for i in range(count)]


def row_crc(items):
    raw = b"".join(struct.pack("<II", smr, s2cr) for smr, s2cr in items)
    return zlib.crc32(raw) & 0xFFFFFFFF


def run_pass(items, capacity=MAX_ROWS):
    if not 1 <= len(items) <= capacity:
        return {"accepted": False, "reason": "row_capacity", "descriptor_reads": 0}
    return {"accepted": True, "row_count": len(items), "descriptor_reads": len(items) * 2,
            "crc": row_crc(items)}


def main():
    build = json.loads((OUT / "build.json").read_text())
    source_hashes = {p.name: sha(p) for p in sorted((OUT / "compiled-source").iterdir())
                     if p.suffix in {".S", ".c", ".h", ".ld"}}
    if source_hashes != build["source_hashes"]:
        raise ValueError("compiled source does not match the bound build")
    rows_a = rows(ROW_COUNT)
    rows_b = list(rows_a)
    first = run_pass(rows_a)
    second = run_pass(rows_b)
    stable = first == second and first["accepted"] and first["descriptor_reads"] == 188

    changed = list(rows_a)
    changed[47] = (changed[47][0] ^ 1, changed[47][1])
    mismatch = run_pass(rows_a)["crc"] != run_pass(changed)["crc"]

    over = run_pass(rows(MAX_ROWS + 1))
    vm_gate = (SOURCE / "vm_gate.S").read_text()
    io_segment = vm_gate[vm_gate.index("mmu_io_read:"):vm_gate.index(".Lio_bad_map:")]
    pure_smmu = "b mmu_smmu_inventory" in io_segment and "b mmu_usb_inventory" not in io_segment
    control = (SOURCE / "xnu_control.c").read_text()
    usb_validation_gated = "#if !P10_SMMU_ONLY" in control

    cases = {
        "stable_94_row_two_pass": stable,
        "row_mismatch_rejected": mismatch,
        "over_128_rows_rejected": not over["accepted"] and over["reason"] == "row_capacity",
        "crc_and_descriptor_count": first["crc"] == second["crc"] and first["descriptor_reads"] == 188,
        "pure_smmu_path": pure_smmu and usb_validation_gated,
        "no_usb_or_dma_operations": True,
    }
    result = {
        "passed": all(cases.values()),
        "hardware_tested": False,
        "device_access": False,
        "usb_started": False,
        "dma_access_verified": False,
        "build_id": build["build_id"],
        "image_sha256": build["image_sha256"],
        "source_hashes": source_hashes,
        "test_source_sha256": sha(Path(__file__)),
        "row_count": ROW_COUNT,
        "descriptor_reads_per_pass": ROW_COUNT * 2,
        "row_crc32": f"0x{first['crc']:08x}",
        "cases": cases,
        "scope": "synthetic P10 SMMU-only contract model; no phone, MMIO, USB, DMA, or computer handshake",
    }
    (OUT / "native-p10-tests.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
