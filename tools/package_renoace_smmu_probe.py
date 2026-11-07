#!/usr/bin/env python3
"""Package the offline P10 SMMU candidate into a reversible recovery carrier."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/xnu-smmu-probe"
PRIVATE = ROOT / "local-device/20261106T115059Z"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    build = json.loads((OUT / "build.json").read_text())
    model = json.loads((ROOT / "out/analysis/p10-smmu-source-model.json").read_text())
    if not model.get("passed"):
        raise ValueError("P10 source model did not pass")
    if build.get("hardware_tested") or build.get("device_access"):
        raise ValueError("P10 package must remain hardware-untested")
    pack_spec = ROOT / "tools/build_renoace_probe.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("p10_pack", pack_spec)
    pack = importlib.util.module_from_spec(spec); spec.loader.exec_module(pack)
    normal = (PRIVATE / "boot.img").read_bytes()
    recovery = (PRIVATE / "recovery.img").read_bytes()
    header, parts = pack.unpack(normal)
    recovery_header, recovery_parts = pack.unpack(recovery)
    aosp = ROOT / "references/aosp-tools"
    pins = json.loads((aosp / "sources.json").read_text())
    for name in ("mkbootimg-v2.py", "avbtool.py"):
        if sha((aosp / name).read_bytes()) != pins[name]["sha256"]:
            raise ValueError("AOSP tool pin mismatch")
    legacy = (aosp / "mkbootimg-v2.py").read_text()
    old = "return (image_size + page_size - 1) / page_size"
    if legacy.count(old) != 1:
        raise ValueError("legacy packer division fix mismatch")
    packer = OUT / "mkbootimg-python3.py"
    packer.write_text(legacy.replace(old, old.replace(" / ", " // ")))
    for name, data in (("dtb", parts["dtb"]), ("recovery_dtbo", recovery_parts["recovery_dtbo"])):
        (OUT / name).write_bytes(data)
    proposed = OUT / "recovery.img"
    command = [sys.executable, str(packer), "--header_version", "2", "--pagesize", "4096", "--base", "0",
               "--kernel_offset", str(header["kernel_addr"]), "--ramdisk_offset", str(header["ramdisk_addr"]),
               "--tags_offset", str(header["tags_addr"]), "--dtb_offset", str(header["dtb_addr"]),
               "--kernel", str(OUT / "Image.gz-dtb"), "--ramdisk", str(OUT / "ramdisk"),
               "--recovery_dtbo", str(OUT / "recovery_dtbo"), "--dtb", str(OUT / "dtb"), "--output", str(proposed)]
    subprocess.run(command, check=True, cwd=OUT)
    result = bytearray(proposed.read_bytes()); keep = bytearray(normal[:4096])
    for a, b in ((8, 12), (16, 20), (576, 608), (1632, 1644)):
        keep[a:b] = result[a:b]
    result[:4096] = keep; proposed.write_bytes(result)
    _, actual = pack.unpack(result)
    expected = {"kernel": (OUT / "Image.gz-dtb").read_bytes(), "ramdisk": (OUT / "ramdisk").read_bytes(),
                "second": b"", "recovery_dtbo": recovery_parts["recovery_dtbo"], "dtb": parts["dtb"]}
    if actual != expected:
        raise ValueError("carrier parts mismatch")
    subprocess.run([sys.executable, str(aosp / "avbtool.py"), "add_hash_footer", "--image", str(proposed),
                    "--partition_name", "recovery", "--partition_size", str(len(recovery)),
                    "--algorithm", "NONE", "--salt", "00" * 32], check=True)
    verify = subprocess.run([sys.executable, str(aosp / "avbtool.py"), "verify_image", "--image", str(proposed)],
                            check=True, capture_output=True, text=True)
    (OUT / "avb-check.txt").write_text(verify.stdout)
    final = proposed.read_bytes(); pack.unpack(final)
    report = {"passed": True, "hardware_tested": False, "device_access": False,
              "dma_access_verified": False, "carrier_sha256": sha(final), "carrier_bytes": len(final),
              "restore_sha256": sha(recovery), "scope": "P10 source-contract carrier; no phone execution, SMMU capture, USB, or DMA",
              "model": "out/analysis/p10-smmu-source-model.json"}
    (OUT / "package-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
