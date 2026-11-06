#!/usr/bin/env python3
"""Read and verify P02's FDT record. No reboot, image write or driver change."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]
PROPERTY = "/sys/firmware/devicetree/base/chosen/renoace-probe-log"
FIELDS = {"image", "original_dtb", "log_dtb", "initrd_start", "initrd_end",
          "current_el", "midr", "mpidr", "isar0", "isar1", "mmfr0", "mmfr1", "cntfrq"}


def parse_record(data, expected_build):
    if not 32 <= len(data) <= 4096 or not data.endswith(b"\0") or b"\0" in data[:-1]:
        raise ValueError("record length or NUL termination is invalid")
    lines = data[:-1].splitlines(keepends=True)
    if lines[:2] != [b"RENOACE-CHAINPROBE-P02\n", ("build=" + expected_build + "\n").encode()]:
        raise ValueError("record magic or build identity does not match")
    check = re.fullmatch(rb"crc32=0x([0-9a-f]{16})\n", lines[-1])
    if not check or int(check[1], 16) != zlib.crc32(b"".join(lines[:-1])):
        raise ValueError("record CRC32 mismatch")
    fields = {}
    for line in lines[2:-1]:
        match = re.fullmatch(rb"([a-z0-9_]+)=0x([0-9a-f]{16})\n", line)
        if not match:
            raise ValueError("malformed field")
        key = match[1].decode()
        if key in fields or key not in FIELDS:
            raise ValueError("duplicate or unknown field: " + key)
        fields[key] = int(match[2], 16)
    if set(fields) != FIELDS or fields["current_el"] not in (1, 2) or not fields["cntfrq"]:
        raise ValueError("incomplete or invalid CPU record")
    if fields["initrd_end"] <= fields["initrd_start"]:
        raise ValueError("invalid initrd extent")
    return {"build_id": expected_build, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "crc32_verified": True,
            "registers": {key: hex(value) for key, value in fields.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "out/chainprobe")
    parser.add_argument("--serial")
    parser.add_argument("--file", type=Path, help="validate a local fixture instead of reading a phone")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    build = json.loads((args.build / "build.json").read_text())
    if args.file:
        data = args.file.read_bytes()
        origin = "local fixture; not hardware proof"
    else:
        serial = args.serial
        if not serial:
            latest = (ROOT / "local-device/p01-test-latest.txt").read_text().strip()
            serial = json.loads((ROOT / "local-device" / latest / "state.json").read_text())["adb_serial"]

        def remote(command, rooted=False):
            text = "su -c " + shlex.quote(command) if rooted else command
            result = subprocess.run(["adb", "-s", serial, "shell", "-T", text],
                                    capture_output=True, timeout=20)
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors="replace"))
            return result.stdout

        if remote("getprop ro.product.model").strip() != b"PCLM10" or remote("getprop ro.boot.prjname").strip() != b"19081":
            raise ValueError("connected device does not match Reno Ace project 19081")
        if not remote("id", True).startswith(b"uid=0("):
            raise ValueError("authorized root read unavailable")
        encoded = remote("base64 " + PROPERTY, True)
        data = base64.b64decode(b"".join(encoded.split()), validate=True)
        expected_hash = remote("sha256sum " + PROPERTY, True).decode().split()[0]
        if hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError("phone/host transfer SHA256 mismatch")
        origin = "phone FDT property; transfer SHA256 matched"
    destination = args.out or ROOT / "local-device" / ("chainprobe-capture-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "probe-log.bin").write_bytes(data)
    result = parse_record(data, build["build_id"])
    result["origin"] = origin
    (destination / "record.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    print(f"Evidence: {destination}")


if __name__ == "__main__":
    main()
