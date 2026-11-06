#!/usr/bin/env python3
"""Execute the actual compiled P01 Image in Unicorn with bounded hardware peers.

No phone operations. CPU instructions, branches, stack/BSS initialization, FDT
parser, pstore writer and PMIC/error control flow execute from the shipped Image.
Only system registers, SPMI, PSCI, PS_HOLD and counter progression are synthetic.
These tests do NOT establish ABL acceptance, register accessibility, reset/DRAM
retention, cache coherency or behavior of the real SoC.

Dependency: python -m pip install --only-binary=:all: --target out/probe-test-deps unicorn==2.1.4
Primary API reference: https://github.com/unicorn-engine/unicorn/blob/2.1.4/samples/sample_arm64.c
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "out/probe-test-deps"))
try:
    import unicorn as un
    from unicorn import arm64_const as ar
    import capstone as cs
except ImportError as exc:
    raise SystemExit("Unicorn 2.1.4 and Capstone are required; see script header") from exc

IMAGE_BASE = 0x80080000
DTB_BASE = 0x84500000
RAMOOPS = 0xB7E00000
RECORD_BYTES = 0x40000
CORE = 0x0C440000
CONFIG = 0x0C40A000
APID = 3
OBSERVER = 0x0E600000 + 0x80 * APID
CHANNEL = 0x0C600000 + 0x10000 * APID
IMEM_REASON = 0x146BF65C
PS_HOLD = 0x0C264000
FREQ = 19_200_000
MAX_INSNS = 4_000_000
PAGE = 4096


def sha(data):
    return hashlib.sha256(data).hexdigest()


def align(n):
    return (n + PAGE - 1) & -PAGE


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def elf_symbols(elf, image):
    """Read symbols only after allocated ELF bytes match the executed Image."""
    require(elf[:6] == b"\x7fELF\x02\x01", "expected ELF64 LE")
    shoff = struct.unpack_from("<Q", elf, 40)[0]
    entsize, count = struct.unpack_from("<HH", elf, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", elf, shoff + i * entsize) for i in range(count)]
    executable = []
    for _, typ, flags, addr, offset, size, _, _, _, _ in sections:
        if flags & 2 and typ != 8:
            require(image[addr:addr + size] == elf[offset:offset + size], "ELF/Image allocated bytes differ")
        if flags & 4:
            executable.append((addr, addr + size))
    symbols = {}
    for _, typ, _, _, offset, size, link, _, _, step in sections:
        if typ != 2:
            continue
        strings = sections[link]
        data = elf[strings[4]:strings[4] + strings[5]]
        for pos in range(offset, offset + size, step):
            name, info, other, index, value, length = struct.unpack_from("<IBBHQQ", elf, pos)
            if name:
                symbols[data[name:data.index(0, name)].decode()] = value
    require(symbols["_head"] == 0 and symbols["_end"] == len(image), "ELF/Image extent mismatch")
    return symbols, executable


def property_offsets(blob):
    """Independent fixture locator; returns raw value ranges, never executes C."""
    magic, total, pos, strings = struct.unpack_from(">4I", blob)
    require(magic == 0xD00DFEED and total == len(blob), "fixture FDT header mismatch")
    stack, result = [], {}
    while pos + 4 <= len(blob):
        token = struct.unpack_from(">I", blob, pos)[0]
        pos += 4
        if token == 1:
            end = blob.index(0, pos)
            stack.append(blob[pos:end].decode())
            pos = (end + 4) & ~3
        elif token == 2:
            stack.pop()
        elif token == 3:
            size, offset = struct.unpack_from(">II", blob, pos)
            pos += 8
            name = blob[strings + offset:blob.index(0, strings + offset)].decode()
            path = "/" + "/".join(part for part in stack if part)
            result[path, name] = (pos, size)
            pos = (pos + size + 3) & ~3
        elif token == 4:
            pass
        elif token == 9:
            return result
        else:
            raise ValueError("invalid fixture token")
    raise ValueError("fixture has no END token")


@dataclass(frozen=True)
class Scenario:
    name: str
    fdt_mutation: str = "none"
    fault: str = "none"
    smc_returns: bool = False
    el: int = 1
    mmu_on: bool = False


class ProbeMachine:
    def __init__(self, image, symbols, executable, fixture, scenario):
        self.scenario = scenario
        self.image = image
        self.symbols = symbols
        self.executable = executable
        self.fixture = self.mutate_fdt(fixture)
        self.uc = un.Uc(un.UC_ARCH_ARM64, un.UC_MODE_ARM)
        self.decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
        self.cache = {}
        self.instructions = 0
        self.ticks = 0
        self.events = []
        self.sys_writes = []
        self.counts = Counter()
        self.failure = None
        self.outcome = None
        self.pending_stop = None
        self.pmic = {0x8F: 0xA1, 0x5A: 0xA7, 0x5B: 0xD5}
        self.initial_pmic = dict(self.pmic)
        self.wdata = 0
        self.transactions = 0
        self.fault_triggered = False
        self.last_command = None
        self.external_writes = []
        self.allowed_pages = {
            CORE & -PAGE, (CORE + 0x1100) & -PAGE,
            CONFIG & -PAGE, OBSERVER & -PAGE, CHANNEL & -PAGE,
            IMEM_REASON & -PAGE, PS_HOLD & -PAGE,
        }
        self.uc.mem_map(IMAGE_BASE, align(len(image)), un.UC_PROT_ALL)
        self.uc.mem_write(IMAGE_BASE, image)
        self.uc.mem_map(DTB_BASE, align(len(self.fixture)), un.UC_PROT_READ)
        self.uc.mem_write(DTB_BASE, self.fixture)
        self.uc.mem_map(RAMOOPS, RECORD_BYTES, un.UC_PROT_READ | un.UC_PROT_WRITE)
        for page in sorted(self.allowed_pages):
            self.uc.mem_map(page, PAGE, un.UC_PROT_READ | un.UC_PROT_WRITE)
        self.write32(CORE, 0x40000000 if scenario.fault == "wrong_arbiter" else 0x50000000)
        self.write32(CORE + 4, APID + 1)
        self.write32(CORE + 0x900 + 4 * APID, 8 << 8)
        self.write32(CONFIG + 0x700 + 4 * APID, 1 if scenario.fault == "owner_denied" else 0)
        self.write32(PS_HOLD, 0x11223344)
        self.uc.reg_write(ar.UC_ARM64_REG_X0, DTB_BASE)
        self.uc.hook_add(un.UC_HOOK_CODE, self.on_instruction)
        self.uc.hook_add(un.UC_HOOK_MEM_READ | un.UC_HOOK_MEM_WRITE, self.on_memory)
        self.uc.hook_add(un.UC_HOOK_MEM_INVALID, self.on_invalid_memory)
        self.uc.hook_add(un.UC_HOOK_INTR, self.on_interrupt)

    def mutate_fdt(self, original):
        b = bytearray(original)
        kind = self.scenario.fdt_mutation
        if kind == "bad_magic":
            b[:4] = bytes(4)
        elif kind == "short_header":
            struct.pack_into(">I", b, 4, 16)
        elif kind in ("wrong_region", "wrong_record", "nonzero_ecc"):
            table = property_offsets(original)
            node = "/reserved-memory/ramoops@0x0xB7E00000"
            prop = {"wrong_region": "reg", "wrong_record": "record-size", "nonzero_ecc": "ecc-size"}[kind]
            offset, length = table[node, prop]
            if kind == "wrong_region":
                struct.pack_into(">I", b, offset + 4, RAMOOPS + PAGE)
            else:
                struct.pack_into(">I", b, offset, 0x20000 if kind == "wrong_record" else 16)
        elif kind != "none":
            raise ValueError(kind)
        return bytes(b)

    def write32(self, address, value):
        self.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def fail(self, message):
        if self.failure is None:
            self.failure = message
        self.uc.emu_stop()

    def on_invalid_memory(self, uc, access, address, size, value, _):
        self.fail(f"unmapped/protected access kind={access} address={address:#x} size={size}")
        return False

    def on_interrupt(self, uc, number, _):
        self.fail(f"unmodelled CPU exception {number} at {uc.reg_read(ar.UC_ARM64_REG_PC):#x}")

    def on_instruction(self, uc, address, size, _):
        if self.pending_stop:
            self.outcome = self.pending_stop
            uc.emu_stop()
            return
        self.instructions += 1
        offset = address - IMAGE_BASE
        if not any(a <= offset and offset + 4 <= b for a, b in self.executable):
            self.fail(f"execution outside compiled text at {address:#x}")
            return
        if offset not in self.cache:
            self.cache[offset] = next(self.decoder.disasm(self.image[offset:offset + 4], address), None)
        ins = self.cache[offset]
        if ins is None:
            self.fail(f"undecodable instruction at {address:#x}")
            return
        if ins.mnemonic == "mrs":
            dest, name = [part.strip().lower() for part in ins.op_str.split(",")]
            values = {
                "currentel": self.scenario.el << 2,
                "sctlr_el1": int(self.scenario.mmu_on), "sctlr_el2": int(self.scenario.mmu_on),
                "midr_el1": 0x51DF805E, "mpidr_el1": 0x81000000,
                "id_aa64isar0_el1": 0x10211120, "id_aa64isar1_el1": 0,
                "id_aa64mmfr0_el1": 0x1122, "id_aa64mmfr1_el1": 0,
                "cntfrq_el0": FREQ,
            }
            if name == "cntvct_el0":
                self.ticks += FREQ // 1000
                value = self.ticks
            elif name in values:
                value = values[name]
            else:
                self.fail("unmodelled system register read: " + name)
                return
            uc.reg_write(getattr(ar, "UC_ARM64_REG_" + dest.upper()), value)
            self.counts["mrs_" + name] += 1
            uc.reg_write(ar.UC_ARM64_REG_PC, address + 4)
        elif ins.mnemonic == "msr":
            name, operand = [part.strip().lower() for part in ins.op_str.split(",")]
            if name not in ("daifset", "spsel", "vbar_el1", "vbar_el2"):
                self.fail("unexpected system register write: " + name)
                return
            value = int(operand.lstrip("#"), 0) if operand.startswith("#") else uc.reg_read(getattr(ar, "UC_ARM64_REG_" + operand.upper()))
            self.sys_writes.append({"name": name, "value": value})
            uc.reg_write(ar.UC_ARM64_REG_PC, address + 4)
        elif ins.mnemonic == "smc":
            function = uc.reg_read(ar.UC_ARM64_REG_X0)
            if function != 0x84000009:
                self.fail(f"unexpected SMC function {function:#x}")
                return
            self.events.append({"event": "psci_system_reset", "ticks": self.ticks})
            if self.scenario.smc_returns:
                uc.reg_write(ar.UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)
                uc.reg_write(ar.UC_ARM64_REG_PC, address + 4)
            else:
                self.outcome = "psci_reset"
                uc.emu_stop()
        elif ins.mnemonic == "wfe":
            if offset != self.symbols["probe_park"]:
                self.fail("WFE outside declared park loop")
                return
            self.outcome = "park"
            uc.emu_stop()

    def on_memory(self, uc, access, address, size, value, _):
        if access == un.UC_MEM_WRITE:
            if IMAGE_BASE + self.symbols["_bss_start"] <= address and address + size <= IMAGE_BASE + self.symbols["_end"]:
                self.counts["image_data_writes"] += 1
                return
            if RAMOOPS <= address and address + size <= RAMOOPS + RECORD_BYTES:
                self.counts["ramoops_writes"] += 1
                return
            if size != 4 or address not in (OBSERVER, CHANNEL, CHANNEL + 0x10, IMEM_REASON, PS_HOLD):
                self.fail(f"unexpected external write {address:#x} size={size} value={value:#x}")
                return
            self.external_writes.append({"address": hex(address), "value": hex(value), "ticks": self.ticks})
            if address == CHANNEL + 0x10:
                if not 0 <= value <= 0xFF:
                    self.fail("SPMI single-byte write contains extra data")
                self.wdata = value
            elif address in (OBSERVER, CHANNEL):
                self.command(address, value)
            elif address == IMEM_REASON:
                if value != 0x77665500:
                    self.fail("unexpected IMEM restart reason")
            elif address == PS_HOLD:
                if value != 0:
                    self.fail("PS_HOLD must be deasserted")
                if self.pmic[0x8F] != 5 or self.pmic[0x5A] & 15 != 1 or not self.pmic[0x5B] & 0x80:
                    self.fail("PS_HOLD used before verified bootloader/warm configuration")
                self.events.append({"event": "ps_hold", "ticks": self.ticks})
                self.pending_stop = "ps_hold_reset"
        else:
            if IMAGE_BASE <= address and address + size <= IMAGE_BASE + len(self.image):
                return
            if DTB_BASE <= address and address + size <= DTB_BASE + len(self.fixture):
                return
            if RAMOOPS <= address and address + size <= RAMOOPS + RECORD_BYTES:
                return
            permitted = address in (CORE, CORE + 4, OBSERVER + 8, OBSERVER + 0x18, CHANNEL + 8)
            permitted |= CORE + 0x900 <= address < CORE + 0x900 + 4 * (APID + 1)
            permitted |= CONFIG + 0x700 <= address < CONFIG + 0x700 + 4 * (APID + 1)
            if size != 4 or not permitted:
                self.fail(f"unexpected external read {address:#x} size={size}")
                return
            self.counts["mmio_reads"] += 1

    def command(self, channel, word):
        reading = channel == OBSERVER
        opcode, offset = word >> 27, (word >> 4) & 0xFF
        if opcode != int(reading) or word & 15 or offset not in (0x8F, 0x5A, 0x5B):
            self.fail(f"unexpected SPMI command {word:#x}")
            return
        self.transactions += 1
        self.last_command = (reading, offset)
        fault = self.scenario.fault
        status = 1
        if fault == "read_timeout" and self.transactions == 1:
            status = 0
        elif fault == "read_error" and self.transactions == 1:
            status = 3
        elif fault == "reason_write_error" and not reading and offset == 0x8F:
            status = 3
        elif fault == "warm_read_error" and reading and offset == 0x5A:
            status = 3
        elif fault == "warm_write_error" and not reading and offset == 0x5A and self.wdata & 15 == 1 and not self.fault_triggered:
            self.fault_triggered = True
            status = 3
        self.write32(channel + 8, status)
        if status == 1:
            if reading:
                data = self.pmic[offset]
                if fault == "reason_readback_mismatch" and offset == 0x8F and self.transactions >= 3:
                    data ^= 4
                self.write32(channel + 0x18, data)
            else:
                self.pmic[offset] = self.wdata
                self.events.append({"event": "pmic_write", "offset": hex(offset), "value": hex(self.wdata), "ticks": self.ticks})

    def run(self):
        started = time.monotonic()
        try:
            self.uc.emu_start(IMAGE_BASE, IMAGE_BASE + len(self.image), timeout=20_000_000, count=MAX_INSNS)
        except un.UcError as exc:
            self.failure = self.failure or f"Unicorn: {exc}"
        if self.outcome is None and self.failure is None:
            self.failure = "execution budget exhausted without terminal outcome"
        sig, start, size = struct.unpack("<III", self.uc.mem_read(RAMOOPS, 12))
        log = ""
        if sig == 0x43474244 and start == size and size <= RECORD_BYTES - 12:
            log = bytes(self.uc.mem_read(RAMOOPS + 12, size)).decode("ascii", "strict")
        return {
            "scenario": self.scenario.__dict__, "outcome": self.outcome, "failure": self.failure,
            "instructions": self.instructions, "wall_seconds": round(time.monotonic() - started, 3),
            "counter_ticks": self.ticks, "transactions": self.transactions, "counts": dict(self.counts),
            "pstore_header": {"signature": hex(sig), "start": start, "size": size}, "log": log,
            "final_pmic": {hex(k): hex(v) for k, v in self.pmic.items()}, "events": self.events,
            "external_writes": self.external_writes, "system_register_writes": self.sys_writes,
            "executed_image_unchanged": bytes(self.uc.mem_read(IMAGE_BASE, self.symbols["_bss_start"])) == self.image[:self.symbols["_bss_start"]],
            "fixture_unchanged": bytes(self.uc.mem_read(DTB_BASE, len(self.fixture))) == self.fixture,
        }


def verify(scenario, result):
    require(result["failure"] is None, result["failure"])
    require(result["executed_image_unchanged"], "compiled code/rodata was modified")
    require(result["fixture_unchanged"], "FDT was modified")
    events = result["events"]
    reset_events = [e for e in events if e["event"] in ("psci_system_reset", "ps_hold")]
    if scenario.fdt_mutation != "none" or scenario.mmu_on:
        require(result["outcome"] == "park", "invalid entry should park")
        require(not result["external_writes"] and not result["counts"].get("ramoops_writes"), "invalid entry wrote external memory")
        require(not reset_events, "invalid entry attempted reset")
    elif scenario.fault in ("wrong_arbiter", "owner_denied", "read_timeout", "read_error", "reason_write_error", "reason_readback_mismatch"):
        require(result["outcome"] == "park" and not reset_events, "unverified boot reason should park")
        require("bootloader_reason_result=0xffff" in result["log"], "SPMI error not persisted")
        require("midr=" not in result["log"], "CPU survey continued after SPMI error")
        require(result["counter_ticks"] <= FREQ, "100ms transfer failure exceeded bounded counter budget")
    elif scenario.fault in ("warm_read_error", "warm_write_error"):
        require(result["outcome"] == "park", "returned PSCI after failed warm setup should park")
        require([e["event"] for e in reset_events] == ["psci_system_reset"], "unverified warm reset used PS_HOLD")
        require(result["final_pmic"]["0x5a"] == "0xa7" and result["final_pmic"]["0x5b"] == "0xd5", "failed warm setup did not preserve/restore PMIC control bytes")
    else:
        expected = "ps_hold_reset" if scenario.smc_returns else "psci_reset"
        require(result["outcome"] == expected, "successful reset outcome differs")
        require(result["log"].startswith("====0.0-D\nRENOACE-P01 entry\n"), "invalid Linux DMESG record header")
        require(result["log"].endswith("RENOACE-P01 PSCI reset\n"), "final reset marker absent")
        require("bootloader_reason_result=0x0000000000000000" in result["log"], "bootloader preparation did not succeed")
        require(f"current_el=0x{scenario.el:016x}" in result["log"], "wrong EL path")
        require(result["final_pmic"] == {"0x8f": "0x5", "0x5a": "0xa1", "0x5b": "0xd5"}, "PMIC unrelated bits not preserved")
        writes = [e for e in events if e["event"] == "pmic_write"]
        require([(e["offset"], e["value"]) for e in writes] == [("0x8f", "0x5"), ("0x5b", "0x55"), ("0x5a", "0xa1"), ("0x5b", "0xd5")], "unexpected PMIC write sequence")
        require(writes[2]["ticks"] - writes[1]["ticks"] >= FREQ // 2000, "PS_HOLD type changed before 500us delay")
        require(reset_events[0]["ticks"] - writes[-1]["ticks"] >= 3 * FREQ, "three-second delay did not execute")
        expected_events = ["psci_system_reset", "ps_hold"] if scenario.smc_returns else ["psci_system_reset"]
        require([e["event"] for e in reset_events] == expected_events, "unexpected reset calls")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "out/renoace-p01")
    parser.add_argument("--fixture", type=Path, default=ROOT / "local-device/20261106T115059Z/live.dtb")
    parser.add_argument("--output", type=Path, default=ROOT / "out/probe-tests")
    parser.add_argument("--case", help="run one named scenario")
    args = parser.parse_args()
    require(un.__version__ == "2.1.4", "dependency must be pinned Unicorn 2.1.4")
    metadata = json.loads((args.build / "build.json").read_text())
    image = (args.build / "Image").read_bytes()
    require(sha(image) == metadata["probe_image_sha256"], "Image changed since build.json")
    require(sha((args.build / "recovery.img").read_bytes()) == metadata["sha256"], "recovery image changed since build.json")
    symbols, executable = elf_symbols((args.build / "probe.elf").read_bytes(), image)
    fixture = args.fixture.read_bytes()
    scenarios = [
        Scenario("success_el1"), Scenario("success_el2", el=2), Scenario("psci_return_fallback", smc_returns=True),
        Scenario("bad_fdt_magic", fdt_mutation="bad_magic"), Scenario("short_fdt_header", fdt_mutation="short_header"),
        Scenario("wrong_ramoops_region", fdt_mutation="wrong_region"), Scenario("wrong_record_size", fdt_mutation="wrong_record"),
        Scenario("nonzero_ecc", fdt_mutation="nonzero_ecc"), Scenario("mmu_on_park", mmu_on=True),
        Scenario("wrong_arbiter", fault="wrong_arbiter"), Scenario("owner_denied", fault="owner_denied"),
        Scenario("read_timeout", fault="read_timeout"), Scenario("read_error", fault="read_error"),
        Scenario("reason_write_error", fault="reason_write_error"), Scenario("reason_readback_mismatch", fault="reason_readback_mismatch"),
        Scenario("warm_read_error_psci_return", fault="warm_read_error", smc_returns=True),
        Scenario("warm_write_error_psci_return", fault="warm_write_error", smc_returns=True),
    ]
    if args.case:
        scenarios = [s for s in scenarios if s.name == args.case]
        require(scenarios, "unknown case")
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for scenario in scenarios:
        result = ProbeMachine(image, symbols, executable, fixture, scenario).run()
        try:
            verify(scenario, result)
            result["passed"] = True
        except (AssertionError, KeyError) as exc:
            result["passed"] = False
            result["assertion_failure"] = str(exc)
        results.append(result)
        (args.output / (scenario.name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        print(f"{'PASS' if result['passed'] else 'FAIL'} {scenario.name}: {result['outcome']}, {result['instructions']} instructions" + ("; " + result["assertion_failure"] if not result["passed"] else ""), flush=True)
    summary = {
        "unicorn_version": un.__version__, "capstone_version": cs.__version__,
        "image_sha256": sha(image), "recovery_sha256": metadata["sha256"], "fixture_sha256": sha(fixture),
        "load_address": hex(IMAGE_BASE), "fixture_address": hex(DTB_BASE), "instruction_budget_per_case": MAX_INSNS,
        "passed": sum(r["passed"] for r in results), "total": len(results),
        "scope": "Actual compiled ARM64 Image with synthetic system registers, counter, SPMI, PSCI and PS_HOLD peers. No hardware tested.",
        "limitations": ["No ABL/secure-boot acceptance proof", "No real MMIO accessibility or SPMI ownership proof", "No reset, PMIC electrical behavior, cache coherency or DRAM retention proof", "A stopped counter or non-returning hardware bus access cannot be validated by this responsive synthetic peer", "MSR/MRS/SMC/WFE behavior is modelled at the instruction boundary; ordinary ARM64 instructions execute in Unicorn"],
        "cases": [{"name": r["scenario"]["name"], "passed": r["passed"], "outcome": r["outcome"]} for r in results],
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
