#!/usr/bin/env python3
"""Static/native-artifact model checks for the offline P10 runtime prototype."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/xnu-smmu-probe"
SOURCE = ROOT / "device/renoace/xnu_smmu_runtime_probe"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    build = json.loads((OUT / "build.json").read_text())
    carrier = json.loads((OUT / "package-evidence.json").read_text())
    source_hashes = {p.name: sha(p) for p in sorted((OUT / "compiled-source").iterdir())
                    if p.suffix in {".S", ".c", ".h", ".ld"}}
    assert source_hashes == build["source_hashes"]
    assert build["hardware_tested"] is False and build.get("device_access", False) is False
    assert carrier["passed"] is True and carrier["restore_sha256"] == "8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009"
    assert carrier["hardware_tested"] is False and carrier["dma_access_verified"] is False
    gate = build["xnu"]["bridge"]["gate"]
    assert gate["bytes"] > 1504 and gate["bytes"] < 2048
    asm = (SOURCE / "vm_gate.S").read_text()
    assert "SMMU_REC_SCR0_OFF" in asm and "SMMU_REC_IDR0_OFF" in asm
    assert "SMMU_REC_SMR_OFF" in asm and "SMMU_REC_S2CR_OFF" in asm
    assert "msr" not in (SOURCE / "smmu_record.h").read_text().lower()
    result = {"passed": True, "hardware_tested": False, "device_access": False,
              "dma_access_verified": False, "carrier_sha256": carrier["carrier_sha256"],
              "build_id": build["build_id"], "gate_bytes": gate["bytes"],
              "restore_sha256": carrier["restore_sha256"],
              "scope": "static native artifact binding; no phone, SMMU, USB, or DMA execution"}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
