#!/usr/bin/env python3
"""Read and verify the P10 SMMU record without rebooting or writing a phone."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]
PROPERTY = "/sys/firmware/devicetree/base/chosen/renoace-probe-log"
REQUIRED = {
    "xnu_status", "xnu_attempted", "xnu_returned", "smmu_verified", "smmu_status",
    "smmu_stage", "smmu_count", "smmu_scr0", "smmu_idr0", "smmu_idr1",
    "smmu_scr0_2", "smmu_idr0_2", "smmu_idr1_2", "smmu_rows_crc1", "smmu_rows_crc2",
}


def read_record(data, expected_build):
    if not 32 <= len(data) <= 8192 or not data.endswith(b"\0"):
        raise ValueError("record length or NUL termination is invalid")
    lines = data[:-1].splitlines(keepends=True)
    if len(lines) < 4 or not lines[0].startswith(b"RENOACE-XNU-"):
        raise ValueError("unexpected P10 record magic")
    if lines[1] != ("build=" + expected_build + "\n").encode():
        raise ValueError("record build identity mismatch")
    match = re.fullmatch(rb"crc32=0x([0-9a-f]{16})\n", lines[-1])
    if not match:
        raise ValueError("record CRC32 line is missing")
    crc = int(match.group(1), 16)
    if zlib.crc32(b"".join(lines[:-1])) != crc:
        raise ValueError("record CRC32 mismatch")
    fields = {}
    for line in lines[2:-1]:
        match = re.fullmatch(rb"([a-z0-9_]+)=0x([0-9a-f]{16})\n", line)
        if not match:
            raise ValueError("malformed record field")
        key = match.group(1).decode()
        if key in fields:
            raise ValueError("duplicate record field: " + key)
        fields[key] = int(match.group(2), 16)
    missing = REQUIRED - fields.keys()
    if missing:
        raise ValueError("missing P10 fields: " + ",".join(sorted(missing)))
    if fields["xnu_status"] != 0 or fields["xnu_attempted"] != 1 or fields["xnu_returned"] != 1:
        raise ValueError("XNU did not return successfully")
    if fields["smmu_verified"] != 1 or fields["smmu_status"] != 2 or fields["smmu_stage"] != 2:
        raise ValueError("SMMU record is incomplete")
    if not 1 <= fields["smmu_count"] <= 128:
        raise ValueError("SMMU row count is outside the bounded carrier contract")
    for name in ("scr0", "idr0", "idr1"):
        if fields["smmu_" + name] != fields["smmu_" + name + "_2"]:
            raise ValueError("SMMU header changed between passes: " + name)
    if fields["smmu_rows_crc1"] != fields["smmu_rows_crc2"]:
        raise ValueError("SMMU row CRC changed between passes")
    return {
        "build_id": expected_build,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "crc32": f"0x{crc:08x}",
        "xnu_status": fields["xnu_status"],
        "smmu_status": fields["smmu_status"],
        "smmu_stage": fields["smmu_stage"],
        "smmu_count": fields["smmu_count"],
        "smmu_headers": [{name: hex(fields["smmu_" + name]) for name in ("scr0", "idr0", "idr1")},
                         {name: hex(fields["smmu_" + name + "_2"]) for name in ("scr0", "idr0", "idr1")}],
        "smmu_rows_crc": [hex(fields["smmu_rows_crc1"]), hex(fields["smmu_rows_crc2"])],
        "smmu_descriptor_reads": fields["smmu_count"] * 2,
        "scope": "P10 SMMU GR0 read-only two-pass record; USB/DMA/computer handshake are separate",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "out/xnu-smmu-probe")
    parser.add_argument("--serial")
    parser.add_argument("--file", type=Path, help="validate a local record instead of reading a phone")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    build_id = json.loads((args.build / "build.json").read_text())["build_id"]
    if args.file:
        data = args.file.read_bytes()
        origin = "local record; not hardware proof"
    else:
        serial = args.serial or ""
        if not serial:
            raise ValueError("--serial is required for phone capture")
        result = subprocess.run(["adb", "-s", serial, "shell", "-T", "su -c 'base64 " + PROPERTY + "'"],
                                check=True, capture_output=True)
        data = base64.b64decode(b"".join(result.stdout.split()), validate=True)
        origin = "phone FDT property; read-only transfer"
    report = read_record(data, build_id)
    report["origin"] = origin
    destination = args.out or ROOT / "local-device" / ("p10-capture-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "probe-log.bin").write_bytes(data)
    (destination / "record.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"Evidence: {destination}")


if __name__ == "__main__":
    main()
