#!/usr/bin/env python3
"""Install the pinned Android NDK LLVM tools used by the Reno Ace probes.

The probe only needs the freestanding AArch64 clang/LLD/LLVM utilities, but
using the pinned NDK keeps local and CI object files reproducible.  The archive
is downloaded outside the repository and is never copied into Git history.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys
import urllib.request
import zipfile


VERSION = "30.0.14904198"
ARCHIVE = "android-ndk-r30-beta1-linux.zip"
URL = "https://dl.google.com/android/repository/" + ARCHIVE
SHA1 = "26b746e5a1e7ac3371f2a862a2f52a7c0740aa8a"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT.parent / "toolchains" / "android-ndk"
TOOL_RELATIVE = Path("android-ndk-r30-beta1/toolchains/llvm/prebuilt/linux-x86_64/bin")
TOOLS = ("clang", "ld.lld", "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf")


def digest(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_dir(root: Path) -> Path:
    return root / TOOL_RELATIVE


def check(root: Path) -> bool:
    directory = tool_dir(root)
    missing = [name for name in TOOLS if not (directory / name).is_file()]
    if missing:
        print("missing tools: " + ", ".join(missing), file=sys.stderr)
        return False
    print(directory)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(os.environ.get("RENOACE_NDK_ROOT", DEFAULT_ROOT)))
    parser.add_argument("--check", action="store_true", help="only verify an existing installation")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    if args.check:
        return 0 if check(root) else 1
    root.mkdir(parents=True, exist_ok=True)
    archive = root / ARCHIVE
    if archive.is_file():
        actual = digest(archive)
        if actual != SHA1:
            raise SystemExit(f"SHA-1 mismatch for {archive}: {actual} != {SHA1}")
    else:
        print(f"downloading {URL}", flush=True)
        urllib.request.urlretrieve(URL, archive)
        actual = digest(archive)
        if actual != SHA1:
            archive.unlink(missing_ok=True)
            raise SystemExit(f"SHA-1 mismatch after download: {actual} != {SHA1}")
    if not tool_dir(root).is_dir():
        print(f"extracting {archive}", flush=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(root)
    if not check(root):
        raise SystemExit("NDK archive did not contain the expected LLVM tools")
    print(f"RENOACE_NDK_BIN={tool_dir(root)}")
    print(f"NDK {VERSION} ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
