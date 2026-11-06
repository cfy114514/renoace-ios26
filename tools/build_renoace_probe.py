#!/usr/bin/env python3
"""Build and verify P01 locally. This tool never invokes adb or fastboot.

The output is a proposed temporary RECOVERY replacement, not a RAM-boot image
on the measured ABL (which has no boot command). Flashing is a separate step.
Retains the current recovery ramdisk, embedded DTBO, command line and both DTB
copies; replaces only its executable kernel with the freestanding probe.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NDK = Path("C:/Users/123/AppData/Local/Android/Sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/windows-x86_64/bin")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unpack(data):
    if data[:8] != b"ANDROID!":
        raise ValueError("not an Android boot image")
    values = struct.unpack_from("<10I", data, 8)
    header = dict(zip(("kernel_size", "kernel_addr", "ramdisk_size", "ramdisk_addr", "second_size",
                      "second_addr", "tags_addr", "page_size", "header_version", "os_version"), values))
    if header["header_version"] != 2 or header["page_size"] != 4096:
        raise ValueError("only the measured v2/4K layout is admitted")
    header["recovery_dtbo_size"], header["recovery_dtbo_offset"], header["header_size"] = struct.unpack_from("<IQI", data, 1632)
    header["dtb_size"], header["dtb_addr"] = struct.unpack_from("<IQ", data, 1648)
    pos, parts = 4096, {}
    for name in ("kernel", "ramdisk", "second", "recovery_dtbo", "dtb"):
        size = header[name + "_size"]
        if name == "recovery_dtbo" and size and pos != header["recovery_dtbo_offset"]:
            raise ValueError("DTBO offset does not match its extent")
        if pos + size > len(data):
            raise ValueError("truncated " + name)
        parts[name] = data[pos:pos+size]
        pos += (size + 4095) & ~4095
    sha = hashlib.sha1()
    for name in ("kernel", "ramdisk", "second", "recovery_dtbo", "dtb"):
        sha.update(parts[name]); sha.update(struct.pack("<I", len(parts[name])))
    if data[576:596] != sha.digest():
        raise ValueError("Android image ID mismatch")
    return header, parts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-bin", type=Path, default=DEFAULT_NDK)
    parser.add_argument("--reset-mode", choices=("psci", "direct"), default="psci",
                        help="direct tests the verified PS_HOLD path without calling PSCI")
    parser.add_argument("--delay-ms", type=int, default=3000, choices=range(1000, 8001), metavar="1000..8000")
    args = parser.parse_args()
    ndk = args.ndk_bin
    output = ROOT / ("out/renoace-p01-direct" if args.reset_mode == "direct" else "out/renoace-p01")
    if args.delay_ms != 3000:
        output = ROOT / f"out/renoace-p01-{args.reset_mode}-{args.delay_ms}"
    output.mkdir(parents=True, exist_ok=True)
    private = ROOT / "local-device/20261106T115059Z"
    manifest = json.loads((private / "manifest.json").read_text())
    original = (private / "recovery.img").read_bytes()
    if digest(original) != manifest["files"]["recovery.img"]["sha256"]:
        raise ValueError("recovery backup changed")
    header, parts = unpack(original)
    original_kernel = zlib.decompressobj(31)
    original_kernel.decompress(parts["kernel"])
    if not original_kernel.eof or original_kernel.unused_data != parts["dtb"]:
        raise ValueError("expected matching appended and v2 DTBs")
    if parts["second"]:
        raise ValueError("unexpected second-stage payload")

    source = ROOT / "device/renoace/probe"
    commands = []
    def run(command):
        command = [str(v) for v in command]
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    objects = []
    common = [ndk / "clang.exe", "--target=aarch64-none-elf", "-mcpu=cortex-a55", "-O2", "-ffreestanding",
              "-nostdlib", "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-stack-protector", "-fno-jump-tables",
              "-fno-asynchronous-unwind-tables", "-mgeneral-regs-only", "-mstrict-align", "-Wall", "-Wextra", "-Werror"]
    common.append(f"-DPROBE_DIRECT_PS_HOLD={int(args.reset_mode == 'direct')}")
    common.append(f"-DPROBE_DELAY_MS={args.delay_ms}")
    for name in ("start.S", "probe.c"):
        obj = output / (Path(name).stem + ".o")
        run(common + ["-c", source / name, "-o", obj]); objects.append(obj)
    relocations = run([ndk / "llvm-readelf.exe", "-r", objects[1]])
    if "R_AARCH64_ABS" in relocations:
        raise ValueError("probe C code contains a non-relocatable absolute reference")
    elf = output / "probe.elf"
    run([ndk / "ld.lld.exe", "-static", "-nostdlib", "-T", source / "probe.ld", "--build-id=none", "-N", *objects, "-o", elf])
    image = output / "Image"
    run([ndk / "llvm-objcopy.exe", "-O", "binary", elf, image])
    symbols = run([ndk / "llvm-nm.exe", "-n", elf])
    end = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(" _end"))
    raw = image.read_bytes()
    if len(raw) > end or end > 0x200000:
        raise ValueError("unexpected probe extent")
    raw += bytes(end-len(raw)); image.write_bytes(raw)
    if raw[56:60] != b"ARM\x64" or struct.unpack_from("<QQQ", raw, 8) != (0x80000, end, 0xa):
        raise ValueError("invalid Linux Image header")
    assembled = run([ndk / "llvm-objdump.exe", "-d", elf])
    (output / "probe.disassembly.txt").write_text(assembled)
    if run([ndk / "llvm-nm.exe", "-u", elf]).strip():
        raise ValueError("unresolved symbols")

    kernel = gzip.compress(raw, mtime=0) + parts["dtb"]
    (output / "Image.gz-dtb").write_bytes(kernel)
    for name in ("ramdisk", "recovery_dtbo", "dtb"):
        (output / name).write_bytes(parts[name])
    # avbtool verifies hash descriptors by the partition's basename.
    proposed = output / "recovery.img"
    aosp = ROOT / "references/aosp-tools"
    pins = json.loads((aosp / "sources.json").read_text())
    for name in ("mkbootimg-v2.py", "avbtool.py"):
        if digest((aosp / name).read_bytes()) != pins[name]["sha256"]:
            raise ValueError("AOSP tool identity changed: " + name)
    # Android 11's script used Python 2 integer division. Keep the downloaded
    # source intact and make this one explicit, checked Python 3 correction.
    legacy = (aosp / "mkbootimg-v2.py").read_text()
    old = "return (image_size + page_size - 1) / page_size"
    if legacy.count(old) != 1:
        raise ValueError("legacy packer no longer matches the audited division fix")
    packer = output / "mkbootimg-python3.py"
    packer.write_text(legacy.replace(old, old.replace(" / ", " // ")))
    run([sys.executable, packer, "--header_version", "2", "--pagesize", "4096",
         "--base", "0", "--kernel_offset", str(header["kernel_addr"]), "--ramdisk_offset", str(header["ramdisk_addr"]),
         "--tags_offset", str(header["tags_addr"]), "--dtb_offset", str(header["dtb_addr"]),
         "--kernel", output / "Image.gz-dtb", "--ramdisk", output / "ramdisk", "--recovery_dtbo", output / "recovery_dtbo",
         "--dtb", output / "dtb", "--output", proposed])
    generated = bytearray(proposed.read_bytes())
    # Preserve all original header fields except the three that must change.
    keep = bytearray(original[:4096])
    keep[8:12] = generated[8:12]
    keep[576:608] = generated[576:608]
    keep[1636:1644] = generated[1636:1644]
    generated[:4096] = keep
    proposed.write_bytes(generated)
    new_header, new_parts = unpack(generated)
    if new_parts["kernel"] != kernel:
        raise ValueError("kernel packaging mismatch")
    for name in ("ramdisk", "second", "recovery_dtbo", "dtb"):
        if new_parts[name] != parts[name]:
            raise ValueError("unexpected change in " + name)
    decompressor = zlib.decompressobj(31)
    if decompressor.decompress(new_parts["kernel"]) != raw or decompressor.unused_data != parts["dtb"]:
        raise ValueError("gzip/DTB failed round-trip")
    # No old signature is copied. Unlocked acceptance is a future device test.
    run([sys.executable, aosp / "avbtool.py", "add_hash_footer", "--image", proposed, "--partition_name", "recovery",
         "--partition_size", str(len(original)), "--algorithm", "NONE", "--salt", "00" * 32])
    avb_info = run([sys.executable, aosp / "avbtool.py", "info_image", "--image", proposed])
    avb_check = run([sys.executable, aosp / "avbtool.py", "verify_image", "--image", proposed])
    (output / "avb-info.txt").write_text(avb_info)
    (output / "avb-check.txt").write_text(avb_check)
    final = proposed.read_bytes(); unpack(final)
    report = {
        "status": "built-and-offline-verified; NOT flashed or hardware tested",
        "image": proposed.name, "bytes": len(final), "sha256": digest(final),
        "restore_image": str((private / "recovery.img").relative_to(ROOT)), "restore_sha256": digest(original),
        "probe_image_bytes": len(raw), "probe_image_sha256": digest(raw),
        "header": new_header, "preserved": ["ramdisk", "recovery_dtbo", "dtb", "cmdline", "os_version", "load_addresses"],
        "dtb_copies": "gzip trailer and v2 DTB section, byte-identical to current recovery",
        "ramoops": {"address": "0xb7e00000", "max_record_bytes": "0x40000", "runtime_FDT_check_required": True},
        "reset_mode": args.reset_mode,
        "probe_delay_ms": args.delay_ms,
        "reset": "PM8150 bootloader reason + verified warm PS_HOLD type; " + (f"direct PS_HOLD after {args.delay_ms}ms, no PSCI call" if args.reset_mode == "direct" else f"PSCI after {args.delay_ms}ms with gated PS_HOLD fallback") + "; hardware-unverified",
        "early_failure": "If return setup is unverified, parks instead of looping into recovery. Manual reset may be required.",
        "avb": "fresh unsigned NONE descriptor, hash verified; acceptance by ABL is untested",
        "source_hashes": {p.name:digest(p.read_bytes()) for p in source.iterdir() if p.is_file()},
        "commands": commands,
    }
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Built and verified: {proposed}\nSHA256: {report['sha256']}\nBytes: {len(final)}; phone not modified")


if __name__ == "__main__":
    main()
