#!/usr/bin/env python3
"""Host-only model of the bounded Reno Ace P10 SMMU read contract.

It mirrors smmu_snapshot.c against synthetic GR0 pages. No device access,
MMIO, DMA, carrier, or phone operation is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x15000000
PAGE = 0x1000
SCR0 = 0x000
IDR0 = 0x020
IDR1 = 0x024
SMR = 0x800
S2CR = 0xC00
MAX_ROWS = 255


def put32(page: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", page, offset, value & 0xFFFFFFFF)


def read_pass(page: bytes) -> dict:
    if len(page) < PAGE:
        return {"error": "PAGE_TOO_SMALL"}
    scr0, idr0, idr1 = (struct.unpack_from("<I", page, off)[0]
                        for off in (SCR0, IDR0, IDR1))
    if idr0 in (0, 0xFFFFFFFF) or idr1 in (0, 0xFFFFFFFF):
        return {"error": "INVALID_CAPABILITIES"}
    sms = bool(idr0 & (1 << 27))
    rows = idr0 & 0xFF if sms else 0
    if rows > MAX_ROWS:
        return {"error": "ROW_COUNT"}
    if SMR + rows * 4 > PAGE or S2CR + rows * 4 > PAGE:
        return {"error": "REGISTER_BOUNDS"}
    smr = [struct.unpack_from("<I", page, SMR + i * 4)[0] for i in range(rows)]
    s2cr = [struct.unpack_from("<I", page, S2CR + i * 4)[0] for i in range(rows)]
    raw = struct.pack("<III", idr0, idr1, scr0)
    raw += b"".join(struct.pack("<II", a, b) for a, b in zip(smr, s2cr))
    return {"scr0": scr0, "idr0": idr0, "idr1": idr1, "row_count": rows,
            "smr": smr, "s2cr": s2cr, "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_crc32": f"0x{__import__('zlib').crc32(raw):08x}", "raw_bytes": len(raw)}


def fixture(rows: int = 2, *, sms: bool = True) -> bytearray:
    page = bytearray(PAGE)
    idr0 = ((1 << 27) | rows) if sms else (9 << 9)
    put32(page, SCR0, 0)
    put32(page, IDR0, idr0)
    put32(page, IDR1, (6 << 28) | 8)
    for i in range(rows):
        put32(page, SMR + i * 4, 0x80000140 if i == 0 else 0x80000141)
        put32(page, S2CR + i * 4, 2 << 16)
    return page


def run() -> dict:
    page = fixture()
    before = bytes(page)
    first = read_pass(page)
    second = read_pass(page)
    mismatch = bytearray(page)
    put32(mismatch, SMR + 4, 0x80000142)
    zero_id = bytearray(page)
    put32(zero_id, IDR0, 0)
    sms0 = fixture(sms=False)
    cases = {
        "stable_two_pass": first == second and first.get("row_count") == 2,
        "mismatch_detected": read_pass(mismatch) != first,
        "zero_capability_rejected": read_pass(zero_id).get("error") == "INVALID_CAPABILITIES",
        "sms0_raw_only": read_pass(sms0).get("row_count") == 0,
        "source_page_unchanged": bytes(page) == before,
    }
    return {"passed": all(cases.values()), "hardware_tested": False,
            "device_access": False, "dma_access_verified": False,
            "aperture": {"base": hex(BASE), "bytes": hex(0x100000), "gr0_page": hex(PAGE)},
            "registers": {"scr0": hex(SCR0), "idr0": hex(IDR0), "idr1": hex(IDR1),
                          "smr": hex(SMR), "s2cr": hex(S2CR)},
            "passes": [first, second], "cases": cases,
            "scope": "host-only synthetic model; no SMMU carrier, phone, MMIO, DMA, or USB handshake"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("out/analysis/p10-smmu-source-model.json"))
    args = parser.parse_args()
    result = run()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
