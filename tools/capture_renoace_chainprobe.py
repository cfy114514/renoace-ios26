#!/usr/bin/env python3
"""Read and verify P02/P03 FDT records. No reboot, image write or driver change."""
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
XNU_FIELDS = {"xnu_status", "xnu_attempted", "xnu_returned", "xnu_window_used", "xnu_phys_base",
              "xnu_window_size", "xnu_source_crc32", "xnu_source_offset", "xnu_copied", "xnu_zeroed",
              "xnu_elapsed_ticks", "xnu_args", "xnu_entry", "xnu_gate", "xnu_x0", "xnu_x20", "xnu_x21",
              "xnu_sp_before", "xnu_sp_after", "xnu_vbar_before", "xnu_vbar_after",
              "xnu_sctlr_before", "xnu_sctlr_after", "xnu_nzcv_before", "xnu_nzcv_after",
              "xnu_daif_before", "xnu_daif_after", "xnu_oslsr_before", "xnu_oslsr_after"}
XNU_STATUS_NAMES = {
    0: "entry_return_verified", 1: "exception_level_refused", 2: "mmu_or_cache_refused",
    3: "os_lock_refused", 4: "memory_window_refused", 5: "initrd_extent_refused",
    6: "counter_frequency_refused", 7: "time_budget_exceeded", 8: "source_crc_mismatch",
    9: "original_gate_mismatch", 10: "segment_extent_refused", 11: "loaded_data_mismatch",
    12: "private_gate_refused", 13: "entry_did_not_return", 14: "entry_capture_mismatch",
    15: "crc_instructions_unavailable",
}
XNU_DIAGNOSTIC_FIELDS = {
    "xnu_budget_ms", "xnu_phase", "xnu_segment", "xnu_phase_bytes", "xnu_phase_total", "xnu_phase_ticks",
    "xnu_source_crc_ticks", "xnu_cache_ticks", "xnu_copy_ticks", "xnu_zero_ticks",
    "xnu_verify_crc_ticks", "xnu_verify_zero_ticks",
}
XNU_PHASE_NAMES = {0: "not_started", 1: "source_crc", 2: "cache_invalidation", 3: "segment_copy",
                   4: "bss_zero", 5: "copied_segment_crc", 6: "bss_readback", 7: "arguments_and_gate", 8: "entry_call"}


def parse_record(data, expected_build, build=None):
    if not 32 <= len(data) <= 4096 or not data.endswith(b"\0") or b"\0" in data[:-1]:
        raise ValueError("record length or NUL termination is invalid")
    lines = data[:-1].splitlines(keepends=True)
    is_xnu = bool(build and "xnu" in build)
    magic = b"RENOACE-XNU-ENTRY-P03\n" if is_xnu else b"RENOACE-CHAINPROBE-P02\n"
    allowed = FIELDS | XNU_FIELDS if is_xnu else FIELDS
    diagnostics = build["xnu"].get("diagnostics_version", 0) if is_xnu else 0
    if diagnostics not in (0, 1):
        raise ValueError("unsupported XNU diagnostic schema")
    if diagnostics:
        allowed = allowed | XNU_DIAGNOSTIC_FIELDS
    if lines[:2] != [magic, ("build=" + expected_build + "\n").encode()]:
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
        if key in fields or key not in allowed:
            raise ValueError("duplicate or unknown field: " + key)
        fields[key] = int(match[2], 16)
    if set(fields) != allowed or fields["current_el"] not in (1, 2) or not fields["cntfrq"]:
        raise ValueError("incomplete or invalid CPU record")
    if fields["initrd_end"] <= fields["initrd_start"]:
        raise ValueError("invalid initrd extent")
    result = {"build_id": expected_build, "sha256": hashlib.sha256(data).hexdigest(),
              "bytes": len(data), "crc32_verified": True,
              "registers": {key: hex(value) for key, value in fields.items()}}
    if is_xnu:
        layout, config = build["xnu"]["constants"], build["constants"]
        base = config["XNU_PHYS_BASE"]
        expected = {"current_el": 1, "xnu_status": 0, "xnu_attempted": 1, "xnu_returned": 1,
                    "xnu_window_used": 1, "xnu_phys_base": base, "xnu_window_size": config["XNU_WINDOW_SIZE"],
                    "xnu_source_crc32": int(build["xnu"]["source_crc32"], 16),
                    "xnu_source_offset": build["xnu"]["member_data_offset"],
                    "xnu_copied": sum(s["fil"] for s in build["xnu"]["segments"]),
                    "xnu_zeroed": sum(s["mem"]-s["fil"] for s in build["xnu"]["segments"]),
                    "xnu_args": base+layout["XNU_ARGS_OFFSET"], "xnu_entry": base+layout["XNU_ENTRY_OFFSET"],
                    "xnu_gate": base+layout["XNU_GATE_OFFSET"], "xnu_x0": base+layout["XNU_VECTOR_OFFSET"],
                    "xnu_x20": base+layout["XNU_ARGS_OFFSET"], "xnu_x21": 0}
        failures = [key for key, value in expected.items() if fields[key] != value]
        for name in ("sp", "vbar", "sctlr", "nzcv", "daif"):
            if fields["xnu_"+name+"_before"] != fields["xnu_"+name+"_after"]:
                failures.append(name+" restoration")
        if (fields["xnu_oslsr_before"] | fields["xnu_oslsr_after"]) & 2:
            failures.append("OS lock gate")
        if diagnostics:
            phase = fields["xnu_phase"]
            if phase not in XNU_PHASE_NAMES or fields["xnu_phase_bytes"] > fields["xnu_phase_total"]:
                raise ValueError("invalid XNU phase or progress")
            if fields["xnu_status"] == 0 and (phase != 8 or fields["xnu_budget_ms"] != build["xnu"]["budget_ms"]):
                failures.append("diagnostic completion")
            segment = fields["xnu_segment"]
            segments = build["xnu"]["segments"]
            if phase and segment not in (*range(len(segments)+1), 0xffffffffffffffff):
                raise ValueError("invalid XNU diagnostic segment")
            segment_name = (None if not phase else "source" if segment == 0xffffffffffffffff else
                            segments[segment]["name"] if segment < len(segments) else "arguments")
            result.update(xnu_budget_seconds=fields["xnu_budget_ms"]/1000,
                          xnu_phase_name=XNU_PHASE_NAMES[phase], xnu_segment_name=segment_name,
                          xnu_phase_progress_bytes={"completed": fields["xnu_phase_bytes"], "total": fields["xnu_phase_total"]},
                          xnu_phase_elapsed_seconds=fields["xnu_phase_ticks"]/fields["cntfrq"],
                          xnu_stage_seconds={name: fields["xnu_"+name+"_ticks"]/fields["cntfrq"] for name in
                                             ("source_crc", "cache", "copy", "zero", "verify_crc", "verify_zero")})
        result.update(xnu_entry_verified=not failures, xnu_verification_failures=failures,
                      xnu_instruction_count=7 if not failures else None,
                      xnu_status_name=XNU_STATUS_NAMES.get(fields["xnu_status"], "unknown"),
                      xnu_elapsed_seconds=fields["xnu_elapsed_ticks"]/fields["cntfrq"],
                      scope="bounded original XNU entry only; full kernel/MMU/iOS startup not established")
    return result


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
    result = parse_record(data, build["build_id"], build)
    result["origin"] = origin
    (destination / "record.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    print(f"Evidence: {destination}")


if __name__ == "__main__":
    main()
