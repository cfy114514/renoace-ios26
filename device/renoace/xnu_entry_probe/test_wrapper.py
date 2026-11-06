#!/usr/bin/env python3
"""Independent actual-instruction test of xnu_gate_call ONLY.

The C loader, full-segment copy/BSS initialization, CPIO, and hardware are NOT
validated here. Real wrapper bytes and three pages from the pinned real XNU
are executed. Privileged register semantics are explicitly modeled. The
unpatched-gate case is stopped by the TEST guard before VBAR can change; it
does not claim the assembly wrapper itself validates the private RET gate.
"""
from pathlib import Path
import copy
import hashlib
import json
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = ROOT / "out/xnu-wrapper-tests"
HERE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "out/probe-test-deps"))
import unicorn
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as ar
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

OUT = ROOT / "out/xnu-entry-probe"
BUILD_PATH, IMAGE_PATH = OUT / "build.json", OUT / "Image"
BUILD_BYTES, IMAGE = BUILD_PATH.read_bytes(), IMAGE_PATH.read_bytes()
BUILD = json.loads(BUILD_BYTES)
XNU_LAYOUT = json.loads((OUT / "xnu-layout.json").read_text())
XNU_PATH = ROOT / XNU_LAYOUT["source"]
XNU = XNU_PATH.read_bytes()
SHA = lambda b: hashlib.sha256(b).hexdigest()
assert SHA(IMAGE) == BUILD["image_sha256"]
assert SHA(XNU) == XNU_LAYOUT["source_sha256"] == "c973fe6cf1f039781972b580a9423613effd08806e66bd88ac5a2d2a9e3ef0fb"
for name, expected in BUILD["source_hashes"].items():
    assert SHA((ROOT / "device/renoace/xnu_entry_probe" / name).read_bytes()) == expected, name

BASE = 0xA8880000
XBASE = BUILD["constants"]["XNU_PHYS_BASE"]
SLICE_OFFSET, SLICE_BYTES = 0x538000, 0x3000
ENTRY_OFFSET, GATE_OFFSET = 0x538518, 0x53A098
ORIGINAL = [
    (0x538518, "da060014"), (0x53A080, "9f1010d5"),
    (0x53A084, "df4f03d5"), (0x53A088, "f40300aa"),
    (0x53A08C, "150080d2"), (0x53A090, "e0fffff0"),
    (0x53A094, "00000091"),
]
for offset, value in ORIGINAL:
    assert XNU[offset:offset + 4].hex() == value
assert XNU[GATE_OFFSET:GATE_OFFSET + 4].hex() == "00c018d5"
DECODER = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
WRAPPER_OFFSET = BUILD["symbols"]["xnu_gate_call"]
WRAPPER_INSNS = []
for instruction in DECODER.disasm(IMAGE[WRAPPER_OFFSET:WRAPPER_OFFSET + 1024], BASE + WRAPPER_OFFSET):
    WRAPPER_INSNS.append(instruction)
    if instruction.mnemonic == "ret":
        break
assert WRAPPER_INSNS and WRAPPER_INSNS[-1].mnemonic == "ret"
WRAPPER_END = WRAPPER_INSNS[-1].address + 4
WRAPPER_BYTES = IMAGE[WRAPPER_OFFSET:WRAPPER_END - BASE]
WRAPPER_PCS = {i.address for i in WRAPPER_INSNS}
SENTINEL = 0x70000000


def reg(name):
    return getattr(ar, "UC_ARM64_REG_" + name.upper())


def run_case(name, os_lock=0, patched=True, initial_daif=0x3C0, spsel=1):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(BASE, len(IMAGE))
    machine.mem_write(BASE, IMAGE)
    kernel = bytearray(XNU[SLICE_OFFSET:SLICE_OFFSET + SLICE_BYTES])
    if patched:
        struct.pack_into("<I", kernel, GATE_OFFSET - SLICE_OFFSET, 0xD65F03C0)
    machine.mem_map(XBASE + SLICE_OFFSET, SLICE_BYTES)
    machine.mem_write(XBASE + SLICE_OFFSET, bytes(kernel))
    argument = XBASE + XNU_LAYOUT["constants"]["XNU_ARGS_OFFSET"]
    machine.mem_map(argument, 0x1000)
    machine.mem_write(argument, struct.pack("<I", 0x00020002) + bytes(0x47C))
    machine.mem_map(SENTINEL, 0x1000)
    machine.mem_write(SENTINEL, bytes.fromhex("1f2003d5"))
    capture = BASE + BUILD["constants"]["DTB_OFFSET"] + 0x1000
    machine.mem_write(capture, bytes(128))
    original_sp = BASE + BUILD["symbols"]["_stack_top"]
    machine.reg_write(ar.UC_ARM64_REG_PSTATE, 4 | spsel | initial_daif)
    machine.reg_write(ar.UC_ARM64_REG_SP, original_sp)
    machine.reg_write(ar.UC_ARM64_REG_NZCV, 0xA0000000)
    original_regs = {}
    for i in range(31):
        value = 0x1155000000000000 + i * 0x10001
        if i == 0:
            value = XBASE + ENTRY_OFFSET
        elif i == 1:
            value = argument
        elif i == 2:
            value = capture
        elif i == 30:
            value = SENTINEL
        machine.reg_write(reg("x" + str(i)), value)
        original_regs[i] = value
    state = {"vbar_el1": BASE + BUILD["symbols"]["chain_vectors"],
             "sctlr_el1": 0x30D00800, "oslsr_el1": 8 | (os_lock << 1), "daif": initial_daif}
    initial_state = copy.deepcopy(state)
    events, kernel_trace, violations, writes = [], [], [], []
    attempted_vbar = []
    instruction_count = 0

    def read_gpr(engine, name):
        return 0 if name == "xzr" else engine.reg_read(reg(name))

    def stop_invalid(engine, access, address, size, value, user):
        violations.append(f"unmapped access {access}: {address:#x}+{size}")
        return False

    def write_hook(engine, access, address, size, value, user):
        allowed = (original_sp - 0x200 <= address and address + size <= original_sp) or (
            capture <= address and address + size <= capture + 128)
        writes.append([hex(address), size])
        if not allowed:
            violations.append(f"write outside wrapper frame/capture: {address:#x}+{size}")
            engine.emu_stop()

    def code_hook(engine, address, size, user):
        nonlocal instruction_count
        instruction_count += 1
        if address == SENTINEL:
            engine.emu_stop()
            return
        is_kernel = XBASE + SLICE_OFFSET <= address < XBASE + SLICE_OFFSET + SLICE_BYTES
        if is_kernel:
            index = len(kernel_trace)
            expected = ORIGINAL + [(GATE_OFFSET, "c0035fd6")]
            if address == XBASE + GATE_OFFSET and not patched:
                assert bytes(engine.mem_read(address, 4)).hex() == "00c018d5"
                attempted_vbar.append({"pc": hex(address), "word": "0xd518c000", "executed": False})
                engine.emu_stop()
                return
            assert index < len(expected), "extra XNU instruction"
            offset, word = expected[index]
            assert address == XBASE + offset, f"wrong XNU execution order: {address:#x}"
            assert bytes(engine.mem_read(address, 4)).hex() == word
            kernel_trace.append({"pc": hex(address), "source_file_offset": hex(offset), "bytes": word,
                                 "original_xnu_instruction": index < 7})
        else:
            assert address in WRAPPER_PCS, f"execution outside wrapper/control: {address:#x}"
        insn = next(DECODER.disasm(bytes(engine.mem_read(address, 4)), address))
        mnemonic, operands = insn.mnemonic.lower(), insn.op_str.lower()
        if mnemonic == "mrs":
            target, key = [part.strip() for part in operands.split(",", 1)]
            if key == "nzcv":
                value = engine.reg_read(ar.UC_ARM64_REG_NZCV)
            else:
                assert key in state, "unexpected system register read: " + key
                value = state[key]
            engine.reg_write(reg(target), value)
            events.append({"pc": hex(address), "operation": "modeled MRS", "register": key, "value": hex(value)})
            engine.reg_write(ar.UC_ARM64_REG_PC, address + 4)
        elif mnemonic == "msr":
            key, source = [part.strip() for part in operands.split(",", 1)]
            value = int(source[1:], 0) if source.startswith("#") else read_gpr(engine, source)
            assert key in ("nzcv", "daif", "daifset", "oslar_el1"), "unexpected privileged write: " + key
            if key == "nzcv":
                engine.reg_write(ar.UC_ARM64_REG_NZCV, value)
            elif key == "oslar_el1":
                assert value == 0, "unexpected OS Lock request"
                state["oslsr_el1"] &= ~2
            else:
                state["daif"] = state["daif"] | (value << 6) if key == "daifset" else value
                pstate = engine.reg_read(ar.UC_ARM64_REG_PSTATE)
                engine.reg_write(ar.UC_ARM64_REG_PSTATE, (pstate & ~0x3C0) | (state["daif"] & 0x3C0))
            events.append({"pc": hex(address), "operation": "modeled MSR", "register": key, "value": hex(value)})
            engine.reg_write(ar.UC_ARM64_REG_PC, address + 4)
        else:
            assert mnemonic not in ("smc", "hvc", "svc", "dc", "ic", "wfe", "wfi"), mnemonic

    machine.hook_add(UC_HOOK_MEM_INVALID, stop_invalid)
    machine.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    machine.hook_add(UC_HOOK_CODE, code_hook)
    start = time.monotonic()
    try:
        machine.emu_start(BASE + WRAPPER_OFFSET, SENTINEL, timeout=5_000_000, count=1000)
    except UcError as error:
        raise AssertionError((name, error, violations)) from error
    assert not violations, violations
    assert bytes(machine.mem_read(XBASE + SLICE_OFFSET, SLICE_BYTES)) == bytes(kernel), "guest modified XNU code"
    values = list(struct.unpack("<16Q", machine.mem_read(capture, 128)))
    capture_names = ("returned", "x0", "x20", "x21", "sp_before", "sp_after", "vbar_before", "vbar_after",
                     "sctlr_before", "sctlr_after", "nzcv_before", "nzcv_after", "daif_before", "daif_after",
                     "oslsr_before", "oslsr_after")
    observed = dict(zip(capture_names, values))
    if not patched:
        assert len(kernel_trace) == 7 and len(attempted_vbar) == 1
        assert values[0] == 0 and state["vbar_el1"] == initial_state["vbar_el1"]
        result_kind = "test guard stopped an unpatched VBAR instruction BEFORE execution; wrapper is not the production gate validator"
    else:
        assert machine.reg_read(ar.UC_ARM64_REG_PC) == SENTINEL
        assert machine.reg_read(ar.UC_ARM64_REG_SP) == original_sp
        assert machine.reg_read(ar.UC_ARM64_REG_PSTATE) & 1 == spsel
        assert machine.reg_read(ar.UC_ARM64_REG_NZCV) == 0xA0000000
        assert state == initial_state, (state, initial_state)
        for i in range(1, 31):
            assert machine.reg_read(reg("x" + str(i))) == original_regs[i], "GPR not restored: x" + str(i)
        assert machine.reg_read(ar.UC_ARM64_REG_X0) == 0  # documented function status, not preserved argument x0
        if os_lock:
            assert not kernel_trace and observed["returned"] == 0
            result_kind = "OSLK=1 branch returned without entering XNU"
        else:
            assert len(kernel_trace) == 8 and observed["returned"] == 1
            assert (observed["x20"], observed["x21"], observed["x0"]) == (argument, 0, XBASE + 0x539000)
            for left, right in (("sp_before", "sp_after"), ("vbar_before", "vbar_after"),
                                ("sctlr_before", "sctlr_after"), ("nzcv_before", "nzcv_after"), ("oslsr_before", "oslsr_after")):
                assert observed[left] == observed[right], (left, right)
            assert observed["sp_before"] == original_sp - 0x200
            assert observed["daif_after"] == 0x3C0
            result_kind = "exact seven original XNU instructions plus private RET; wrapper caller state restored"
    return {"name": name, "passed": True, "result": result_kind, "elapsed_seconds": round(time.monotonic() - start, 4),
            "instruction_count": instruction_count, "guest_write_count": len(writes),
            "write_scope": "512-byte wrapper frame and 128-byte capture only", "xnu_trace": kernel_trace,
            "rejected_vbar_attempt": attempted_vbar, "capture": {k: hex(v) for k, v in observed.items()},
            "privileged_instruction_models": events, "hardware_execution": False}


def main():
    cases = [run_case("unlocked-EL1-SP1"), run_case("unlocked-EL1-SP0", spsel=0),
             run_case("DAIF-restoration-nondefault", initial_daif=0x140),
             run_case("OSLK-locked-refusal", os_lock=1), run_case("unpatched-gate-test-guard", patched=False)]
    assert SHA(IMAGE_PATH.read_bytes()) == SHA(IMAGE), "P03 Image changed while testing"
    assert BUILD_PATH.read_bytes() == BUILD_BYTES, "build report changed while testing"
    assert SHA(XNU_PATH.read_bytes()) == XNU_LAYOUT["source_sha256"], "source kernel changed"
    report = {"scope": "wrapper-only ACTUAL instruction/control test; C loader, CPIO and full BSS NOT validated",
              "hardware_execution": False, "unicorn_version": unicorn.__version__, "passed": len(cases), "failed": 0,
              "build_id": BUILD["build_id"], "image_sha256": SHA(IMAGE), "build_report_sha256": SHA(BUILD_BYTES),
              "source_hashes": BUILD["source_hashes"], "xnu_source_sha256": SHA(XNU),
              "wrapper_start_offset": hex(WRAPPER_OFFSET), "wrapper_bytes": len(WRAPPER_BYTES),
              "wrapper_sha256": SHA(WRAPPER_BYTES), "test_sha256": SHA(Path(__file__).read_bytes()),
              "physical_probe_base": hex(BASE), "xnu_physical_base": hex(XBASE), "cases": cases,
              "limitations": ["Privileged register reads/writes are explicit models, not real CPU evidence.",
                              "The unpatched-gate refusal is a harness guard, not a test of xnu_validate_gate().",
                              "Only the needed XNU pages are preloaded. Full Mach-O loading/BSS ownership/copy/CRC are outside scope.",
                              "No original Linux instruction, MMU enable, VBAR write, storage or phone action executed."]}
    (HERE / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(cases)} wrapper-only cases; build {BUILD['build_id']}; original XNU source unchanged")
    print("Wrapper SHA-256: " + report["wrapper_sha256"])
    print("Unpatched VBAR case rejected by explicit test guard; production C gate remains separate.")


if __name__ == "__main__":
    main()
