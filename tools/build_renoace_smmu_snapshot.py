#!/usr/bin/env python3
"""Build the host-independent P10 SMMU read-only source contract.

This compiles only the bounded snapshot helper. It does not package or run a
phone carrier; the carrier remains blocked until a native gate/model exists.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "device/renoace/xnu_smmu_probe"
OUT = ROOT / "out/xnu-smmu-snapshot"
WINDOWS_NDK = Path("C:/Users/123/AppData/Local/Android/Sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/windows-x86_64/bin")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(ndk, name):
    for candidate in (ndk / name, ndk / (name + ".exe")):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(candidate)


def main():
    ndk = Path(os.environ.get("RENOACE_NDK_BIN", str(WINDOWS_NDK)))
    OUT.mkdir(parents=True, exist_ok=True)
    source_hashes = {p.name: sha(p) for p in sorted(SOURCE.iterdir())
                     if p.suffix in {".c", ".h"}}
    obj = OUT / "smmu_snapshot.o"
    command = [tool(ndk, "clang"), "--target=aarch64-none-elf", "-mcpu=cortex-a55",
               "-O2", "-ffreestanding", "-nostdlib", "-fno-builtin", "-fno-pic",
               "-fno-pie", "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
               "-I", SOURCE, "-c", SOURCE / "smmu_snapshot.c", "-o", obj]
    subprocess.run([str(x) for x in command], check=True, cwd=OUT)
    disassembly = OUT / "disassembly.txt"
    with disassembly.open("w", encoding="utf-8") as stream:
        subprocess.run([str(tool(ndk, "llvm-objdump")), "-d", obj], check=True,
                       cwd=OUT, stdout=stream)
    report = {
        "status": "offline P10 SMMU read-only source contract",
        "hardware_tested": False,
        "device_access": False,
        "dma_access_verified": False,
        "carrier": "blocked pending native XNU gate, FDT raw-record layout, and instruction model",
        "source_hashes": source_hashes,
        "object_sha256": sha(obj),
        "object_bytes": obj.stat().st_size,
        "disassembly_sha256": sha(disassembly),
        "command": [str(x) for x in command],
        "scope": "GR0 sCR0/IDR0/IDR1 and bounded SMR/S2CR reads only; no writes, context banks, TTBRs, DMA, USB, or phone",
    }
    (OUT / "build.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
