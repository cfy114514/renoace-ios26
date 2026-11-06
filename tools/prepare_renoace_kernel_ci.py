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
XNU_COMMIT = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"
DEVICE_PATCH = "patches/native-arm-io-zero-base.patch"
DEVICE_PATCH_SHA256 = "b971f39f86c44ea65f6c5f3e546764744bff51eb0dd3c9622f29592469f0ec8c"
APPENDED_PATCH = "zzzzz-renoace-native-arm-io-zero-base.patch"
XNU_VERSION = "12377.121.6"
SOURCE_FILES = ("pexpert/arm/pe_identify_machine.c", "pexpert/pexpert/arm/protos.h",
                "pexpert/arm/pe_init.c")
KERNEL_OUTPUT = "build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf"
FILES = (
    "board.toml", "feeds.toml", "configs/renoace_research_defconfig",
    "drivers/ArmCpu/ArmCpu.cpp", "drivers/ArmCpu/Info.plist",
    "drivers/ArmCpu/LICENSE", "drivers/ArmCpu/README.md",
    DEVICE_PATCH,
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def file_hashes(directory):
    return {p.relative_to(directory).as_posix(): sha(p)
            for p in sorted(directory.rglob("*")) if p.is_file()}


def stage_patch_module(framework, output, device):
    """Preserve the complete pinned module before appending the board patch."""
    relative = "patches/xnu-12377"
    source = framework / relative
    entries = command(["git", "ls-tree", "-r", "HEAD", "--", relative], framework).splitlines()
    if not entries:
        raise ValueError("pinned framework patch module is empty")
    tracked = set()
    for entry in entries:
        metadata, name = entry.split("\t", 1)
        mode, kind, blob = metadata.split()
        path = framework / name
        if mode not in ("100644", "100755") or kind != "blob" or path.is_symlink():
            raise ValueError("patch module contains a nonregular tracked entry: " + name)
        data = path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != blob:
            raise ValueError("framework patch module differs from its pin: " + name)
        tracked.add(path.relative_to(source).as_posix())
    if any(p.is_symlink() for p in source.rglob("*")) or set(file_hashes(source)) != tracked:
        raise ValueError("patch module contains extra or symlinked files")
    target = output / "patch-modules/xnu-12377"
    if target.exists():
        raise ValueError("CI patch-module destination already exists")
    inherited = file_hashes(source)
    shutil.copytree(source, target)
    if (target / APPENDED_PATCH).exists():
        raise ValueError("device patch collides with the inherited module")
    shutil.copy2(device / DEVICE_PATCH, target / APPENDED_PATCH)
    hashes = file_hashes(target)
    series = sorted(p.name for p in target.glob("*.patch"))
    if series[-1] != APPENDED_PATCH:
        raise ValueError("device patch must follow the complete inherited series")
    if inherited != file_hashes(source):
        raise ValueError("framework patch module changed during staging")
    return {
        "module": "patch:xnu-12377", "path": str(target),
        "selection": "--local-module patch:xnu-12377=" + str(target),
        "inherited_sha256": inherited, "effective_sha256": hashes,
        "effective_module_sha256": hashlib.sha256(json.dumps(
            hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "module_hash_encoding": "SHA-256 of UTF-8 compact sorted-key JSON path-to-SHA256 map",
        "ordered_patch_series": series, "appended_patch": APPENDED_PATCH,
    }


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
    if hashes[DEVICE_PATCH] != DEVICE_PATCH_SHA256:
        raise ValueError("device patch differs from the reviewed SHA-256")
    xnu = [s for s in tomllib.loads((source / "feeds.toml").read_text(encoding="utf-8"))
           .get("source", []) if s.get("name") == "xnu" and s.get("kind") == "refer"]
    if len(xnu) != 1 or xnu[0].get("commit") != XNU_COMMIT:
        raise ValueError("XNU source differs from the reviewed pin")
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
    patch_module = stage_patch_module(framework, output, target)
    (evidence / "patch-module-manifest.json").write_text(
        json.dumps(patch_module, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "scope": "kernel-only; no prelink, IPSW, root filesystem, boot image or phone operation",
        "source_commit": command(["git", "rev-parse", "HEAD"], ROOT),
        "framework_repository": "none24smu/UniXNU", "framework_commit": FRAMEWORK_COMMIT,
        "xnu_commit": XNU_COMMIT, "device_patch_sha256": DEVICE_PATCH_SHA256,
        "patch_module_sha256": patch_module["effective_module_sha256"],
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
    print("Complete patch module: " + patch_module["selection"])


def source_compile_evidence(output, required=False):
    evidence = output / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    tree = output / "build/renoace/tree"
    sources = tree / (".cache/xnu-" + XNU_VERSION + "-work")
    objects = tree / ("build/xnu-" + XNU_VERSION + "/ios-obj/DEVELOPMENT_ARM64_BCM2837")
    module = output / "patch-modules/xnu-12377"
    result = {"xnu_commit_expected": XNU_COMMIT, "source_sha256": {},
              "object_sha256": {}, "compile_records": {}, "errors": []}
    try:
        manifest = json.loads((evidence / "patch-module-manifest.json").read_text(encoding="utf-8"))
        if file_hashes(module) != manifest["effective_sha256"]:
            raise ValueError("staged patch module hashes changed")
        linked = tree / "patches/xnu-12377"
        result["selected_patch_module"] = str(linked.resolve())
        if linked.resolve() != module.resolve():
            raise ValueError("assembled build tree did not select the staged complete patch module")
        result["xnu_commit_actual"] = command(["git", "rev-parse", "HEAD"], sources)
        if result["xnu_commit_actual"] != XNU_COMMIT:
            raise ValueError("compiled source checkout differs from its pin")
        command(["git", "apply", "--reverse", "--check", str(module / APPENDED_PATCH)], sources)
        result["device_patch_reverse_check"] = True
        for relative in SOURCE_FILES:
            result["source_sha256"][relative] = sha(sources / relative)
        for name in ("pe_identify_machine", "pe_init"):
            obj = objects / ("pexpert/DEVELOPMENT/" + name + ".o")
            result["object_sha256"][name + ".o"] = sha(obj)
            record = obj.with_suffix(".o.json")
            destination = evidence / "compile-records" / record.name
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(record, destination)
            result["compile_records"][record.name] = sha(record)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["errors"].append(str(error))
    (evidence / "source-compile-manifest.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if required and result["errors"]:
        raise ValueError("source/compile provenance verification failed: " + "; ".join(result["errors"]))
    return result


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
    source_compile_evidence(output)
    print("Collected available kernel/build evidence: " + str(evidence))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", type=Path, default=ROOT / "worktrees/UniXNU-renoace")
    parser.add_argument("--output", type=Path, default=ROOT / "out/renoace-kernel-ci")
    parser.add_argument("--collect", action="store_true", help="collect only existing logs/tool versions after a build")
    parser.add_argument("--verify-build", action="store_true", help="require pinned patched sources and compiled object evidence")
    args = parser.parse_args()
    if args.verify_build:
        source_compile_evidence(args.output.resolve(), required=True)
    elif args.collect:
        collect(args.output.resolve())
    else:
        prepare(args.framework.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
