#!/usr/bin/env python3
"""Stage an allowlisted Reno Ace kernel-only CI device copy; never alter it in place."""
import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_COMMIT = "a8b90c0c645fd62ae850cd43e80c87bab4cc157d"
KERNEL_OUTPUT = "build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf"
FILES = (
    "board.toml", "feeds.toml", "configs/renoace_research_defconfig",
    "drivers/ArmCpu/ArmCpu.cpp", "drivers/ArmCpu/Info.plist",
    "drivers/ArmCpu/LICENSE", "drivers/ArmCpu/README.md",
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def prepare(framework, output):
    source = ROOT / "device/renoace"
    if source.resolve() != source:
        raise ValueError("source device directory must not traverse a symlink")
    if output == source or source in output.parents or output in source.parents:
        raise ValueError("CI output must not contain or modify the source device directory")
    if command(["git", "rev-parse", "HEAD"], framework) != FRAMEWORK_COMMIT:
        raise ValueError("framework commit differs from the reviewed pin")
    target = output / "device"
    if target.exists():
        raise ValueError("CI device destination already exists; use a fresh output directory")
    hashes = {}
    for relative in FILES:
        path = source / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source):
            raise ValueError("missing or symlinked source: " + relative)
        hashes[relative] = sha(path)
    text = (source / "board.toml").read_text(encoding="utf-8")
    original = tomllib.loads(text)
    if original["board"]["name"] != "renoace" or original["board"].get("example") is not True:
        raise ValueError("expected the original guarded Reno Ace research board")
    if "prelink" in original["kernel"] or "outputs" in original["kernel"]:
        raise ValueError("review CI staging before adding prelink or outputs to the source board")
    if text.count("example = true") != 1 or text.count("[kernel]\n") != 1:
        raise ValueError("source board layout changed")
    staged = text.replace("example = true", "example = false", 1).replace(
        "[kernel]\n", "[kernel]\noutputs = " + json.dumps([KERNEL_OUTPUT]) + "\n", 1)
    expected = copy.deepcopy(original)
    expected["board"]["example"] = False
    expected["kernel"]["outputs"] = [KERNEL_OUTPUT]
    if tomllib.loads(staged) != expected:
        raise ValueError("CI staging changed unrelated board values")
    for relative in FILES:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, destination)
    (target / "board.toml").write_text(staged, encoding="utf-8", newline="\n")
    evidence = output / "evidence"
    shutil.copytree(target, evidence / "device-inputs")
    manifest = {
        "scope": "kernel-only; no prelink, IPSW, root filesystem, boot image or phone operation",
        "source_commit": command(["git", "rev-parse", "HEAD"], ROOT),
        "framework_repository": "none24smu/UniXNU", "framework_commit": FRAMEWORK_COMMIT,
        "framework_submodules": command(["git", "submodule", "status", "--recursive"], framework).splitlines(),
        "source_device_sha256": hashes,
        "staged_device_sha256": {relative: sha(target / relative) for relative in FILES},
        "generator_sha256": sha(Path(__file__)), "kernel_output": KERNEL_OUTPUT,
        "source_board_example": True, "staged_board_example": False,
    }
    (evidence / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if hashes != {relative: sha(source / relative) for relative in FILES}:
        raise ValueError("source files changed during staging")
    print("Prepared kernel-only device copy: " + str(target))


def collect(output):
    evidence = output / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    work = output / "build/renoace"
    for log in (work / "logs").glob("*.log"):
        destination = evidence / "logs" / log.name
        destination.parent.mkdir(exist_ok=True)
        shutil.copy2(log, destination)
    for source, name in ((work / ".config", "effective-defconfig.txt"),
                         (output / "device/unixnu.lock", "resolved-feeds.toml")):
        if source.is_file():
            shutil.copy2(source, evidence / name)
    tools = {}
    for args in (["xcodebuild", "-version"], ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"],
                 ["xcrun", "--sdk", "iphoneos", "--find", "clang"],
                 ["xcrun", "--sdk", "iphoneos", "clang", "--version"],
                 ["xcrun", "--sdk", "macosx", "--show-sdk-version"], ["clang", "--version"],
                 ["git", "--version"], ["cmake", "--version"], ["ninja", "--version"]):
        try:
            tools[" ".join(args)] = command(args)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            tools[" ".join(args)] = {"unavailable": str(error)}
    (evidence / "toolchain.json").write_text(json.dumps(tools, indent=2) + "\n")
    kernels = {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)}
               for p in (work / "kernel").glob("*") if p.is_file()}
    (evidence / "kernel-manifest.json").write_text(json.dumps(kernels, indent=2) + "\n")
    print("Collected available kernel/build evidence: " + str(evidence))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", type=Path, default=ROOT / "worktrees/UniXNU-renoace")
    parser.add_argument("--output", type=Path, default=ROOT / "out/renoace-kernel-ci")
    parser.add_argument("--collect", action="store_true", help="collect only existing logs/tool versions after a build")
    args = parser.parse_args()
    if args.collect:
        collect(args.output.resolve())
    else:
        prepare(args.framework.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
