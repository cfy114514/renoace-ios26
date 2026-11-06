#!/usr/bin/env python3
"""Read Reno Ace hardware evidence over ADB; never write to or reboot the phone.

Raw evidence goes to ignored local-device/. Binary stdout is copied as bytes,
including on Windows. --boot-images reads boot/dtbo/recovery/vbmeta only; it
does not back up Android user data or per-device calibration partitions.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROPERTIES = (
    "ro.product.manufacturer", "ro.product.model", "ro.product.device",
    "ro.product.name", "ro.product.board", "ro.board.platform",
    "ro.boot.prjname", "ro.build.version.release", "ro.build.version.sdk",
    "ro.build.version.security_patch", "ro.build.display.id",
    "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
    "ro.boot.verifiedbootstate", "ro.boot.slot_suffix",
    "ro.boot.dynamic_partitions", "ro.boot.boot_devices",
)
TEXT_READS = {
    "cpuinfo": "cat /proc/cpuinfo",
    "memory": "cat /proc/meminfo",
    "kernel": "uname -a",
    "soc": "for f in soc_id revision machine; do echo $f; cat /sys/devices/soc0/$f; done",
    "gpu": "cat /sys/class/kgsl/kgsl-3d0/gpu_model",
    "screen": "wm size",
    "components": "for f in tp lcd ddr_type ufs; do echo $f; cat /proc/devinfo/$f; done",
    "input": "cat /proc/bus/input/devices",
    "partitions": "cat /proc/partitions; ls -l /dev/block/by-name",
    "iomem": "cat /proc/iomem",
    "buses": "for f in /sys/bus/i2c/devices/*/name /sys/bus/spi/devices/*/modalias; do echo $f; cat $f; done",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="store_true", help="use an already authorized su")
    parser.add_argument("--boot-images", action="store_true", help="read four boot-related partitions")
    parser.add_argument("--serial", help="ADB device serial (otherwise exactly one device is required)")
    args = parser.parse_args()
    adb = shutil.which("adb")
    if not adb:
        parser.error("adb is not on PATH")
    devices = subprocess.run([adb, "devices"], capture_output=True, text=True,
                             check=True, timeout=15).stdout.splitlines()[1:]
    available = [line.split()[0] for line in devices if len(line.split()) >= 2 and line.split()[1] == "device"]
    if args.serial:
        if args.serial not in available:
            parser.error("the selected device is not connected and authorized")
        serial = args.serial
    elif len(available) == 1:
        serial = available[0]
    else:
        parser.error("exactly one authorized device is required; use --serial otherwise")
    prefix = [adb, "-s", serial]

    def run(command, root=False, timeout=30):
        remote = ["su", "-c", command] if root else [command]
        return subprocess.run(prefix + ["exec-out"] + remote, capture_output=True, timeout=timeout)

    props = {}
    for prop in PROPERTIES:
        result = run("getprop " + prop)
        result.check_returncode()
        props[prop] = result.stdout.decode("utf-8", "replace").strip()
    if (props["ro.product.manufacturer"].upper(), props["ro.product.model"], props["ro.product.device"], props["ro.boot.prjname"]) != ("OPPO", "PCLM10", "OP4A89", "19081"):
        parser.error("identity does not match this port's PCLM10 / OP4A89 / 19081 target")
    if args.boot_images and not args.root:
        parser.error("--boot-images requires --root")
    if args.root:
        result = run("id", root=True, timeout=20)
        if result.returncode or not result.stdout.startswith(b"uid=0("):
            parser.error("Shell root authorization is unavailable")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = ROOT / "local-device" / stamp
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {"captured_at_utc": stamp, "root": args.root, "properties": props, "files": {}, "errors": {}}

    def save(name, data):
        (destination / name).write_bytes(data)
        manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    for name, command in TEXT_READS.items():
        result = run(command, root=args.root)
        save(name + ".txt", result.stdout)
        if result.returncode or result.stderr:
            manifest["errors"][name] = {"returncode": result.returncode, "stderr": result.stderr.decode("utf-8", "replace")}

    if args.root:
        result = run("cat /sys/firmware/fdt", root=True)
        if result.returncode == 0 and len(result.stdout) >= 40:
            magic, size = struct.unpack_from(">II", result.stdout)
            if magic == 0xD00DFEED and size == len(result.stdout):
                save("live.dtb", result.stdout)
            else:
                manifest["errors"]["fdt"] = "unexpected FDT magic or size; binary not accepted"
        else:
            manifest["errors"]["fdt"] = result.stderr.decode("utf-8", "replace")

    if args.boot_images:
        for partition in ("boot", "dtbo", "recovery", "vbmeta"):
            path = "/dev/block/by-name/" + partition
            size_result = run("blockdev --getsize64 " + path, root=True)
            size_result.check_returncode()
            expected = int(size_result.stdout.strip())
            if not 0 < expected <= 256 * 1024 * 1024:
                raise ValueError("unexpected size for " + partition)
            result = run("cat " + path, root=True, timeout=120)
            result.check_returncode()
            if len(result.stdout) != expected:
                raise ValueError("short partition read: " + partition)
            local_hash = hashlib.sha256(result.stdout).hexdigest()
            remote_hash = run("sha256sum " + path, root=True, timeout=60)
            remote_hash.check_returncode()
            if remote_hash.stdout.decode().split()[0] != local_hash:
                raise ValueError("device/host hash mismatch: " + partition)
            save(partition + ".img", result.stdout)
            print(f"Read {partition}: {expected} bytes, device/host SHA-256 matched", flush=True)

    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / "local-device" / "latest.txt").write_text(destination.name + "\n", encoding="utf-8")
    print(f"Evidence: {destination}")
    print(f"Accepted files: {len(manifest['files'])}; read errors: {len(manifest['errors'])}")


if __name__ == "__main__":
    main()
