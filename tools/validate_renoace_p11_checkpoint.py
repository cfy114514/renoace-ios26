#!/usr/bin/env python3
"""Validate the next offline XNU checkpoint; never touches a device."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_KERNEL_RELATIVE_CANDIDATES = (
    "out/cloud-kernel/42306878464/extracted/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf",
    "out/cloud-kernel/42306878464/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf",
)


def default_kernel() -> Path:
    """Find the pinned artifact in either connector or CI extraction layout."""
    for relative in _KERNEL_RELATIVE_CANDIDATES:
        candidate = ROOT / relative
        if candidate.is_file():
            return candidate
    # Keep a stable diagnostic path when the ignored artifact is unavailable.
    return ROOT / _KERNEL_RELATIVE_CANDIDATES[0]


DEFAULT_KERNEL = default_kernel()
EXPECTED_SHA = "c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743"
BASE = 0xfffffff007004000
ARM_INIT = 0xfffffff007b33594
PE_INIT_PLATFORM = 0xfffffff007aa4c70
SECOND_PE_CALL = 0xfffffff007b33fa8
SECOND_PE_RETURN = 0xfffffff007b33fac
TIMER_ENABLE = 0xfffffff007509498


def fail(message: str) -> None:
    raise ValueError(message)


def bl_target(pc: int, word: int) -> int:
    if word & 0xfc000000 != 0x94000000:
        fail(f"{pc:#x}: expected BL, got {word:#x}")
    imm = word & 0x03ffffff
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + (imm << 2)


def adrp_target(pc: int, word: int) -> int:
    if word & 0x9f000000 != 0x90000000:
        fail(f"{pc:#x}: expected ADRP, got {word:#x}")
    imm = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xfff) + (imm << 12)


def macho_symbols(data: bytes) -> dict[str, int]:
    if struct.unpack_from("<4I", data)[:4] != (0xfeedfacf, 0x100000c, 0, 2):
        fail("not the pinned thin ARM64 Mach-O")
    ncmds, command_bytes = struct.unpack_from("<II", data, 16)
    at, symtab = 32, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        if size < 8 or at + size > 32 + command_bytes:
            fail("invalid Mach-O command")
        if cmd == 2:
            symtab = struct.unpack_from("<4I", data, at + 8)
        at += size
    if symtab is None:
        fail("missing symbol table")
    symoff, nsyms, stroff, strsize = symtab
    out = {}
    for i in range(nsyms):
        off = symoff + i * 16
        string_index, typ, section, desc, value = struct.unpack_from("<IBBHQ", data, off)
        if not value or not typ & 0x0e or string_index >= strsize:
            continue
        end = data.find(b"\0", stroff + string_index, stroff + strsize)
        if end < 0:
            fail("unterminated symbol")
        out[data[stroff + string_index:end].decode(errors="replace")] = value
    return out


def segments(data: bytes) -> list[dict[str, int]]:
    ncmds, command_bytes = struct.unpack_from("<II", data, 16)
    at, out = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        if cmd == 0x19:
            va, mem, off, fil = struct.unpack_from("<4Q", data, at + 24)
            if mem:
                out.append({"va": va, "mem": mem, "off": off, "fil": fil})
        at += size
    return out


def file_offset(data: bytes, va: int) -> int:
    for seg in segments(data):
        if seg["va"] <= va < seg["va"] + seg["fil"]:
            return seg["off"] + va - seg["va"]
    fail(f"VA is not file-backed: {va:#x}")


def word(data: bytes, va: int) -> int:
    return struct.unpack_from("<I", data, file_offset(data, va))[0]


def check(data: bytes) -> dict:
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        fail("kernel SHA-256 does not match the reviewed pinned source-port artifact")
    syms = macho_symbols(data)
    if syms.get("_arm_init") != ARM_INIT or syms.get("_PE_init_platform") != PE_INIT_PLATFORM:
        fail("arm_init or PE_init_platform symbol moved")
    if bl_target(SECOND_PE_CALL, word(data, SECOND_PE_CALL)) != PE_INIT_PLATFORM:
        fail("second PE(TRUE) call target changed")
    expected = {
        SECOND_PE_RETURN: 0xaa1303e0,       # mov x0, x19
        ARM_INIT - BASE + BASE: 0xd10343ff, # original SUB SP,#0xd0
        0xfffffff007b33e50: 0xaa0003f3,    # serial return
        0xfffffff007b33f98: 0xf0000613,    # ADRP x19
        0xfffffff007b33f9c: 0x913d8273,    # ADD x19,#0xf60
        0xfffffff007b33fa0: 0x52800020,    # x0=TRUE
        0xfffffff007b33fa4: 0xaa1303e1,    # x1=&BootCpuData
        0xfffffff007b33fe4: 0x97e75529,    # fiq_context_init call
        TIMER_ENABLE: 0xd51be328,           # CNTV_CTL_EL0 write
    }
    for va, expected_word in expected.items():
        actual = word(data, va)
        if actual != expected_word:
            fail(f"{va:#x}: expected {expected_word:#x}, got {actual:#x}")
    if adrp_target(0xfffffff007b33f98, word(data, 0xfffffff007b33f98)) + 0xf60 != 0xfffffff007bf6f60:
        fail("BootCpuData ADRP/ADD witness changed")
    # The timer helper lives in a lower-address function called later by the
    # arm_init sequence; numeric VA ordering is not execution ordering here.
    result = {
        "passed": True,
        "kernel_sha256": EXPECTED_SHA,
        "arm_init_va": hex(ARM_INIT),
        "second_pe_call_va": hex(SECOND_PE_CALL),
        "second_pe_call_target": hex(PE_INIT_PLATFORM),
        "second_pe_return_va": hex(SECOND_PE_RETURN),
        "second_pe_return_file_offset": hex(file_offset(data, SECOND_PE_RETURN)),
        "expected_stop_word": hex(0xaa1303e0),
        "expected_x19_boot_cpu_data": hex(0xfffffff007bf6f60),
        "expected_x20_serialmode": hex(0xfffffff0071b3dc8),
        "expected_x21_page_shift": hex(0xfffffff0071b5120),
        "sp_el0": hex(0xfffffff007dbff30),
        "sp_el1": hex(0xfffffff007dc8000),
        "first_new_system_register_write": {
            "va": hex(TIMER_ENABLE),
            "instruction": "msr cntv_ctl_el0, x8",
            "word": hex(0xd51be328),
            "must_not_be_crossed_without_timer_recovery": True,
        },
        "execution_order": "second PE(TRUE) return -> early debug/CPU setup -> fiq_context_init -> CNTV_CTL_EL0 write",
        "hardware_tested": False,
        "irq_ready": False,
        "xnu_runtime_connection": False,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=default_kernel())
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = check(args.kernel.read_bytes())
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8", newline="\n")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
