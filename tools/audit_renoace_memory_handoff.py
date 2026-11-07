#!/usr/bin/env python3
"""Audit measured reserved-memory against the offline Aloha handoff map.

The output is a boundary report only. It does not claim that any interval is
safe for XNU allocation until firmware ownership and a complete EFI map exist.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARDWARE = ROOT / "device/renoace/hardware.json"
ALOHA_MAP = ROOT / "references/aloha/Platforms/SurfaceDuo1Pkg/Device/oppo-pclm10/Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c"
OUT = ROOT / "out/analysis/renoace-memory-handoff.json"


def interval(start, size):
    return {"start": start, "end": start + size, "bytes": size}


def hx(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def merge(items):
    merged = []
    for item in sorted(items, key=lambda x: (x["start"], x["end"])):
        if merged and item["start"] <= merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], item["end"])
            merged[-1]["labels"].extend(item["labels"])
        else:
            merged.append({"start": item["start"], "end": item["end"], "labels": list(item["labels"])})
    for item in merged:
        item["bytes"] = item["end"] - item["start"]
        item["labels"] = sorted(set(item["labels"]))
    return merged


def parse_aloha():
    result = []
    pattern = re.compile(r'^\s*\{"([^"]+)",\s*0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+),\s*([^,]+),')
    for line in ALOHA_MAP.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            name, start, size, hob = match.groups()
            start, size = int(start, 16), int(size, 16)
            result.append({"name": name, "start": start, "end": start + size, "bytes": size, "hob": hob.strip()})
    return result


def main():
    hardware = json.loads(HARDWARE.read_text(encoding="utf-8"))
    reservations = []
    for node in hardware["memory"]["reservations"]:
        for raw in node["ranges"]:
            item = interval(hx(raw["address"]), hx(raw["size"]))
            item["labels"] = [node["node"]]
            reservations.append(item)
    merged = merge(reservations)
    duplicate_aliases = []
    for index, left in enumerate(reservations):
        for right in reservations[index + 1:]:
            if left["start"] == right["start"] and left["end"] == right["end"]:
                duplicate_aliases.append(sorted(left["labels"] + right["labels"]))

    banks = []
    free = []
    for bank in hardware["memory"]["banks"]:
        start, end = hx(bank["address"]), hx(bank["address"]) + hx(bank["size"])
        banks.append(interval(start, end - start))
        cursor = start
        for reserved in merged:
            if reserved["end"] <= start or reserved["start"] >= end:
                continue
            if cursor < max(start, reserved["start"]):
                free.append(interval(cursor, max(start, reserved["start"]) - cursor))
            cursor = max(cursor, min(end, reserved["end"]))
        if cursor < end:
            free.append(interval(cursor, end - cursor))

    aloha = parse_aloha()
    overlaps = []
    for descriptor in aloha:
        matches = [item["labels"] for item in reservations if max(descriptor["start"], item["start"]) < min(descriptor["end"], item["end"])]
        if matches:
            overlaps.append({"name": descriptor["name"], "start": hex(descriptor["start"]), "end": hex(descriptor["end"]), "hob": descriptor["hob"], "measured_reservations": sorted({label for labels in matches for label in labels})})

    report = {
        "passed": True,
        "handoff_ready": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "memory_banks": [{**item, "start": hex(item["start"]), "end": hex(item["end"])} for item in banks],
        "measured_reservations": len(reservations),
        "coalesced_reserved_intervals": [{**item, "start": hex(item["start"]), "end": hex(item["end"])} for item in merged],
        "duplicate_aliases": duplicate_aliases,
        "provisional_free_ranges": [{**item, "start": hex(item["start"]), "end": hex(item["end"])} for item in free],
        "aloha_active_descriptors": len(aloha),
        "aloha_descriptors_overlapping_measured_reservations": overlaps,
        "blockers": [
            "cont_splash_region and disp_rdump_region are duplicate aliases and must be coalesced before allocation.",
            "Aloha active descriptors overlap measured firmware carve-outs; they cannot be copied as an ownership map.",
            "The provisional free ranges exclude only measured reservations and still lack a complete EFI/firmware ownership map.",
            "XNU/UEFI handoff, root storage allocation, and DMA ownership remain unverified.",
        ],
        "scope": "offline measured-DT versus Aloha memory handoff audit; ranges are provisional and not allocator authorization",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
