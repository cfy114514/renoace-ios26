#!/usr/bin/env python3
"""Independent tests of the actual compiled P08 memory primitives.

CRC32X/W/B and LDP/STP execute in Unicorn, rather than being replaced by a
host checksum/copy. Only counter reads are modeled. This does not measure
phone performance, memory attributes/coherency, or run the C loader/kernel.
"""
from pathlib import Path
import hashlib
import json
import random
import re
import struct
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[3]
HERE = ROOT / "out/xnu-io-primitive-tests"
HERE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "out/probe-test-deps"))
import unicorn
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as ar
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

OUT = ROOT / "out/xnu-io-probe"
BUILD_BYTES = (OUT / "build.json").read_bytes()
BUILD = json.loads(BUILD_BYTES)
IMAGE = (OUT / "Image").read_bytes()
ELF = (OUT / "probe.elf").read_bytes()
LAYOUT = json.loads((OUT / "xnu-layout.json").read_text())
XNU = (ROOT / LAYOUT["source"]).read_bytes()
SHA = lambda data: hashlib.sha256(data).hexdigest()
assert SHA(IMAGE) == BUILD["image_sha256"]
assert SHA(XNU) == LAYOUT["source_sha256"]
BASE, SRC, DST, SENTINEL = 0xA8880000, 0x20000000, 0x24000000, 0x70000000
TAIL = BUILD["constants"]["LINUX_EFFECTIVE_SIZE"]
SYMS = BUILD["symbols"]
DECODER = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def elf_functions(data):
    assert data[:6] == b"\x7fELF\x02\x01"
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_bytes, count = struct.unpack_from("<HH", data, 58)
    assert section_bytes == 64
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, section_offset + i * section_bytes) for i in range(count)]
    result = {}
    for s in sections:
        if s[1] != 2:
            continue
        names = sections[s[6]]
        strings = data[names[4]:names[4] + names[5]]
        assert s[9] == 24
        for at in range(s[4], s[4] + s[5], 24):
            name, info, other, section, address, size = struct.unpack_from("<IBBHQQ", data, at)
            if info & 15 == 2 and section and size:
                end = strings.index(0, name)
                result[address] = (strings[name:end].decode(), size)
    return result


FUNCTIONS = elf_functions(ELF)
BY_NAME = {name: (address, size) for address, (name, size) in FUNCTIONS.items()}
PRIMITIVES = ("crc32_bounded", "copy_bounded", "zero_bounded", "check_zero_bounded")
for name in PRIMITIVES:
    assert name in BY_NAME, name


def functions_for(name):
    pending, included = [BY_NAME[name][0]], set()
    while pending:
        address = pending.pop()
        if address in included:
            continue
        included.add(address)
        function_name, size = FUNCTIONS[address]
        assert function_name not in ("chain_main", "xnu_control", "xnu_gate_call")
        for instruction in DECODER.disasm(IMAGE[address:address + size], address):
            assert instruction.mnemonic not in ("smc", "hvc", "svc", "blr"), function_name
            if instruction.mnemonic in ("bl", "b") and instruction.op_str.startswith("#0x"):
                target = int(instruction.op_str[1:], 16)
                if target in FUNCTIONS and target != address:
                    pending.append(target)
    return included


def reg(name):
    return getattr(ar, "UC_ARM64_REG_" + name.upper())


def run(name, data=b"", n=None, source_alignment=0, destination_alignment=0,
        destination_data=None, expire_on_counter=None, check_reads=True):
    n = len(data) if n is None else n
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(BASE + TAIL, len(IMAGE) - TAIL)
    machine.mem_write(BASE + TAIL, IMAGE[TAIL:])
    source = SRC + 0x1000 + source_alignment
    target = DST + 0x1000 + destination_alignment
    source_capacity = max(0x3000, (len(data) + 0x3000 + 4095) & ~4095)
    target_capacity = max(0x3000, (n + 0x3000 + 4095) & ~4095)
    machine.mem_map(SRC, source_capacity)
    machine.mem_map(DST, target_capacity)
    machine.mem_write(source - 32, b"\x69" * 32 + data + b"\x96" * 32)
    initial_target = b"\xA5" * n if destination_data is None else destination_data
    assert len(initial_target) == n
    machine.mem_write(target - 32, b"\xC3" * 32 + initial_target + b"\x3C" * 32)
    machine.mem_map(SENTINEL, 0x1000)
    machine.mem_write(SENTINEL, bytes.fromhex("1f2003d5"))
    bad = BASE + BUILD["constants"]["DTB_OFFSET"] + 0x1000
    machine.mem_write(bad, bytes(8))
    original_sp = BASE + SYMS["_stack_top"]
    machine.reg_write(ar.UC_ARM64_REG_PSTATE, 0x3C5)
    machine.reg_write(ar.UC_ARM64_REG_SP, original_sp)
    machine.reg_write(ar.UC_ARM64_REG_X30, SENTINEL)
    for key, value in (("active_result", 0), ("started", 0), ("budget_ticks", 10000)):
        assert key in SYMS, key
        machine.mem_write(BASE + SYMS[key], struct.pack("<Q", value))
    if name == "crc32_bounded":
        arguments = (source, n, bad)
    elif name == "copy_bounded":
        arguments = (target, source, n)
    else:
        arguments = (target, n)
    for i, value in enumerate(arguments):
        machine.reg_write(reg("x" + str(i)), value)
    permitted = functions_for(name)
    ranges = [(BASE + a, BASE + a + FUNCTIONS[a][1]) for a in permitted]
    counter_calls, writes, read_count, faults = [0], [0], [0], []

    def invalid(engine, access, address, size, value, user):
        faults.append(f"invalid memory {access} at {address:#x}+{size}")
        return False

    def write(engine, access, address, size, value, user):
        writes[0] += 1
        allowed = original_sp - 0x4000 <= address and address + size <= original_sp
        allowed |= bad <= address and address + size <= bad + 4
        if name in ("copy_bounded", "zero_bounded"):
            allowed |= target <= address and address + size <= target + n
        if not allowed:
            faults.append(f"unexpected write {address:#x}+{size}")
            engine.emu_stop()

    def read(engine, access, address, size, value, user):
        if SRC <= address < SRC + source_capacity:
            read_count[0] += 1
            if not (source <= address and address + size <= source + n):
                faults.append(f"source overread {address:#x}+{size}")
                engine.emu_stop()
            if size in (4, 8, 16) and address % min(size, 8):
                faults.append(f"unnatural scalar alignment {address:#x}+{size}")
                engine.emu_stop()
        elif DST <= address < DST + target_capacity:
            read_count[0] += 1
            if not (target <= address and address + size <= target + n):
                faults.append(f"destination overread {address:#x}+{size}")
                engine.emu_stop()

    def block(engine, address, size, user):
        if address == SENTINEL:
            engine.emu_stop()
        elif not any(low <= address < high for low, high in ranges):
            faults.append(f"execution outside primitive/dependencies {address:#x}")
            engine.emu_stop()

    def timer(engine, address, size, destination):
        counter_calls[0] += 1
        value = 10001 if expire_on_counter and counter_calls[0] >= expire_on_counter else 0
        engine.reg_write(reg(destination), value)
        engine.reg_write(ar.UC_ARM64_REG_PC, address + 4)

    machine.hook_add(UC_HOOK_MEM_INVALID, invalid)
    machine.hook_add(UC_HOOK_MEM_WRITE, write)
    if check_reads:
        machine.hook_add(UC_HOOK_MEM_READ, read)
    machine.hook_add(UC_HOOK_BLOCK, block)
    instruction_names = set()
    for address in permitted:
        function_name, size = FUNCTIONS[address]
        for instruction in DECODER.disasm(IMAGE[address:address + size], BASE + address):
            instruction_names.add(instruction.mnemonic)
            if instruction.mnemonic == "mrs":
                destination, system = [v.strip() for v in instruction.op_str.lower().split(",", 1)]
                assert system == "cntvct_el0", (function_name, instruction.op_str)
                machine.hook_add(UC_HOOK_CODE, timer, user_data=destination, begin=instruction.address, end=instruction.address)
            assert instruction.mnemonic != "msr", (function_name, instruction.op_str)
    if name == "crc32_bounded":
        assert "crc32x" in instruction_names, "compiled helper has no CRC32X"
        assert "crc32cx" not in instruction_names, "wrong CRC polynomial"
    started = time.monotonic()
    try:
        machine.emu_start(BASE + BY_NAME[name][0], SENTINEL, timeout=60_000_000, count=100_000_000)
    except UcError as error:
        raise AssertionError((name, n, error, faults)) from error
    assert not faults, faults
    assert machine.reg_read(ar.UC_ARM64_REG_PC) == SENTINEL
    assert machine.reg_read(ar.UC_ARM64_REG_SP) == original_sp
    assert machine.mem_read(source - 32, len(data) + 64) == b"\x69" * 32 + data + b"\x96" * 32
    assert machine.mem_read(target - 32, 32) == b"\xC3" * 32
    assert machine.mem_read(target + n, 32) == b"\x3C" * 32
    result = machine.reg_read(ar.UC_ARM64_REG_X0) & 0xFFFFFFFF
    signed = result - (1 << 32) if result & (1 << 31) else result
    bad_value = struct.unpack("<I", machine.mem_read(bad, 4))[0]
    actual_target = bytes(machine.mem_read(target, n))
    if expire_on_counter:
        assert bad_value == 1 if name == "crc32_bounded" else signed == -1
    elif name == "crc32_bounded":
        assert result == zlib.crc32(data[:n]) and bad_value == 0
    elif name == "copy_bounded":
        assert signed == 0 and actual_target == data[:n]
    elif name == "zero_bounded":
        assert signed == 0 and actual_target == bytes(n)
    else:
        assert signed == (-2 if any(initial_target) else 0)
        assert actual_target == initial_target
    return {"primitive": name, "bytes": n, "source_alignment": source_alignment,
            "destination_alignment": destination_alignment, "counter_expiry_call": expire_on_counter,
            "result": hex(result), "bad": bad_value, "writes_checked": writes[0],
            "data_reads_checked": read_count[0] if check_reads else "disabled for full-file case; boundary cases traced",
            "counter_reads_modeled": counter_calls[0], "host_seconds": round(time.monotonic() - started, 4), "passed": True}


def main():
    rng = random.Random(114514)
    cases = []
    for alignment in (0, 8, 16, 24):
        for size in (0, 1, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65):
            data = rng.randbytes(size)
            cases.append(run("crc32_bounded", data, source_alignment=alignment))
    cases.append(run("crc32_bounded", b"123456789"))
    for name in ("copy_bounded", "zero_bounded", "check_zero_bounded"):
        for alignment in (0, 8, 16, 24):
            for size in (0, 8, 16, 24, 32, 40, 56, 64, 72):
                data = rng.randbytes(size) if name == "copy_bounded" else bytes(size)
                initial = bytes(size) if name == "check_zero_bounded" else None
                cases.append(run(name, data, destination_alignment=alignment, source_alignment=alignment, destination_data=initial))
    for name in PRIMITIVES:
        size = 0x10000 + 8
        data = rng.randbytes(size) if name in ("crc32_bounded", "copy_bounded") else bytes(size)
        initial = bytes(size) if name == "check_zero_bounded" else None
        cases.append(run(name, data, destination_data=initial))
        cases.append(run(name, data, destination_data=initial, expire_on_counter=1))
        cases.append(run(name, data, destination_data=initial, expire_on_counter=2))
    for at in (0, 7, 15, 16, 31, 32, 0xFFFF, 0x10000 + 7):
        value = bytearray(0x10000 + 8)
        value[at] = 0x80
        cases.append(run("check_zero_bounded", bytes(len(value)), destination_data=bytes(value)))
    cases.append(run("crc32_bounded", XNU, check_reads=False))
    assert SHA((OUT / "Image").read_bytes()) == SHA(IMAGE), "owner rebuilt Image during test"
    assert (OUT / "build.json").read_bytes() == BUILD_BYTES, "owner changed build report during test"
    functions = {name: {"offset": hex(BY_NAME[name][0]), "bytes": BY_NAME[name][1],
                        "sha256": SHA(IMAGE[BY_NAME[name][0]:BY_NAME[name][0] + BY_NAME[name][1]])} for name in PRIMITIVES}
    report = {"scope": "standalone actual compiled memory primitives; counters modeled; no full loader or hardware",
              "build_id": BUILD["build_id"], "image_sha256": SHA(IMAGE), "elf_sha256": SHA(ELF),
              "source_hashes": BUILD["source_hashes"], "test_sha256": SHA(Path(__file__).read_bytes()),
              "unicorn_version": unicorn.__version__, "functions": functions, "passed": len(cases), "failed": 0,
              "xnu_crc_expected": hex(zlib.crc32(XNU)), "cases": cases,
              "limits": ["CRC instructions execute in Unicorn; they are not replaced by zlib.",
                         "This is not a benchmark of the phone or of M=0 Device-memory bus behavior.",
                         "No MMU, cache mode, storage, reset, Linux or XNU entry is executed."]}
    (HERE / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS {len(cases)} actual primitive cases; build {BUILD['build_id']}; XNU CRC {zlib.crc32(XNU):08x}")


if __name__ == "__main__":
    main()
