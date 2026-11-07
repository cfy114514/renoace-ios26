#!/usr/bin/env python3
"""Inventory local iOS/XNU userland inputs without downloading anything."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOARD = ROOT / "device/renoace/board.toml"
OUT = ROOT / "out/analysis/renoace-ios-artifact-inventory.json"


def files(root):
    return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]


def main():
    board = BOARD.read_text(encoding="utf-8")
    roots = {name: ROOT / name for name in ("references/UniXNU-ios26", "references/UniXNU-zeta", "references/ios-flame")}
    all_files = [p for root in roots.values() if root.is_dir() for p in files(root)]
    source_root = roots["references/UniXNU-ios26"]
    submodule_paths = re.findall(r"^\s*path\s*=\s*(.+)$", (source_root / ".gitmodules").read_text(encoding="utf-8"), re.M) if (source_root / ".gitmodules").is_file() else []
    submodule_initialized = {path: (source_root / path).is_dir() and any((source_root / path).iterdir()) for path in submodule_paths}
    names = [p.name.lower() for p in all_files]
    def matching(pattern, allowed=None):
        rx = re.compile(pattern, re.I)
        return [str(p.relative_to(ROOT)) for p in all_files if "patches" not in p.parts and (allowed is None or p.suffix.lower() in allowed) and rx.search(p.name)]
    declared = {
        "product": re.search(r'^product\s*=\s*"([^"]+)"', board, re.M).group(1),
        "version": re.search(r'^version\s*=\s*"([^"]+)"', board, re.M).group(1),
        "build": re.search(r'^build\s*=\s*"([^"]+)"', board, re.M).group(1),
        "fetch": re.search(r'^fetch\s*=\s*\[([^]]+)\]', board, re.M).group(1),
    }
    local = {
        "ipsw_or_firmware_files": matching(r"\.(ipsw|zip|dmg)$", {".ipsw", ".zip", ".dmg"}),
        "kernelcache": matching(r"kernel.?cache", {"", ".img", ".bin"}),
        "device_tree": matching(r"device.?tree|\.dtb$|\.dtbo$", {".dtb", ".dtbo", ".img", ".bin"}),
        "trustcache": matching(r"trust.?cache", {"", ".trustcache", ".bin", ".img"}),
        "cryptex": matching(r"cryptex", {"", ".dmg", ".img", ".bin"}),
        "rootfs_or_system": matching(r"rootfs|system.?volume|\.dmg$", {".dmg", ".img", ".bin"}),
        "dyld_shared_cache": matching(r"dyld.?shared.?cache", {"", ".dylib", ".bin", ".img"}),
    }
    availability = {key: bool(value) for key, value in local.items()}
    result = {
        "passed": True,
        "userspace_ready": False,
        "hardware_tested": False,
        "device_access": False,
        "usb_or_dma_started": False,
        "ipsw_declared": declared,
        "local_artifacts": local,
        "availability": availability,
        "references": {
            "UniXNU_ios26_worktree_files": len(files(source_root)) if source_root.is_dir() else 0,
            "UniXNU_ios26_submodules_total": len(submodule_paths),
            "UniXNU_ios26_submodules_initialized": sum(submodule_initialized.values()),
            "UniXNU_zeta_transform_scripts": len([p for p in all_files if "UniXNU-zeta" in str(p) and "scripts" in p.parts]),
        },
        "missing_inputs": [key for key, present in availability.items() if not present] + ([] if submodule_initialized and all(submodule_initialized.values()) else ["checked-out pinned UniXNU-ios26 source/submodules"]),
        "next_safe_step": "obtain authorized local IPSW/firmware inputs before any userland or DarwinBoot claim" if submodule_initialized and all(submodule_initialized.values()) else "initialize the pinned UniXNU source tree, then obtain authorized local IPSW/firmware inputs",
        "scope": "offline local artifact inventory; no download, build, phone, USB, or DMA operation",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
