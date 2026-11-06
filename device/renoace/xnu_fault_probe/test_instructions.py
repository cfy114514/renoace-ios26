#!/usr/bin/env python3
"""P05 BRK detection and explicitly synthetic exception-delivery model.

Runs the full compiled loader and actual XNU page-table/MMU startup using
Unicorn's CPU TLB and physical RAM mappings only. The private arm_init BRK
executes natively. Unicorn does not deliver its architectural vector, so a
separate, labelled step synthesizes that frame and resumes the real handler.
This is never evidence of native exception delivery or a real-phone result.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[3]
DEPENDENCY = ROOT / "device/renoace/xnu_mmu_probe/test_instructions.py"
DEPENDENCY_SHA256 = "e4ebd1c5c78066c101f9d111143a93087491f7323819881ce2312226bbcaba67"
if hashlib.sha256(DEPENDENCY.read_bytes()).hexdigest() != DEPENDENCY_SHA256:
    raise SystemExit("P04 instruction-model dependency changed; review and rebind before running P05")
spec = importlib.util.spec_from_file_location("p05_pinned_p04", DEPENDENCY)
p04 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p04
spec.loader.exec_module(p04)
un, ar = p04.un, p04.ar
require, sha, registers = p04.require, p04.sha, p04.registers
SYSTEM_REGISTERS = p04.SYSTEM_REGISTERS
BRK_IMMEDIATE = 0x505
BRK_WORD = 0xD4200000 | (BRK_IMMEDIATE << 5)
BRK_ESR = 0xF2000000 | BRK_IMMEDIATE


def checkpoint(text):
    (ROOT / "out/p05-model-checkpoint.txt").write_text(text + "\n", encoding="utf-8")


def parse_message(message, build_id):
    require(message.endswith(b"\0") and b"\0" not in message[:-1], "bad wire termination")
    data = message[:-1]
    start = data.rfind(b"crc32=")
    require(start > 0, "wire CRC absent")
    check = re.fullmatch(rb"crc32=0x([0-9a-f]{16})\n", data[start:])
    require(check and zlib.crc32(data[:start]) == int(check[1], 16), "wire CRC mismatch")
    lines = data[:start].splitlines()
    require(lines[0] == b"RENOACE-XNU-EXCEPTION-P05" and lines[1] == ("build=" + build_id).encode(), "wrong wire identity")
    fields = {}
    for line in lines[2:]:
        match = re.fullmatch(rb"([a-z0-9_]+)=0x([0-9a-f]{16})", line)
        require(match is not None, "malformed wire field")
        name = match[1].decode()
        require(name not in fields, "duplicate wire field")
        fields[name] = int(match[2], 16)
    return fields


@dataclass
class Fixture(p04.Fixture):
    @classmethod
    def load(cls, directory):
        build = json.loads((directory / "build.json").read_text())
        image = (directory / "Image").read_bytes()
        linux = (directory / "original-linux.Image").read_bytes()
        initrd = (directory / "ramdisk").read_bytes()
        macho = (ROOT / build["xnu"]["source"]).read_bytes()
        for actual, expected, label in ((sha(image), build["image_sha256"], "compiled Image"),
                (sha(linux), build["original_linux_sha256"], "Linux"),
                (sha(initrd), build["xnu"]["combined_ramdisk_sha256"], "initrd"),
                (sha(macho), build["xnu"]["source_sha256"], "XNU source")):
            require(actual == expected, label + " identity mismatch")
        for name, expected in build["source_hashes"].items():
            require(sha((Path(__file__).parent / name).read_bytes()) == expected, "source/build mismatch: " + name)
        arm_patch = next(p for p in build["xnu"]["patches"]
                         if p["offset"] == build["xnu"]["constants"]["XNU_ARM_INIT_OFFSET"])
        require(arm_patch["replacement"] == BRK_WORD and not arm_patch["bridge_symbol"], "arm_init must contain the dedicated private BRK #0x505")
        require(len(build["xnu"]["patches"]) == 37, "unexpected P05 private-patch inventory")
        # P04 helper uses this display label to select exactly this patch in
        # its removal/memory-verification controls. Bind the offset/BRK first,
        # then alias the display label in this in-memory helper input only.
        arm_patch["model_original_label"] = arm_patch["label"]
        arm_patch["label"] = "arm_init entry"
        return cls(directory, build, image, linux, initrd, macho,
                   (ROOT / "local-device/20261106T115059Z/live.dtb").read_bytes(),
                   p04.definitions(Path(__file__).with_name("mmu_bridge.h")))


@dataclass(frozen=True)
class Case(p04.Case):
    feature_refusal: bool = False
    ssbs_feature_refusal: bool = False


class Machine(p04.Machine):
    def __init__(self, fixture, case, report_dir):
        self.report_dir = report_dir
        self.brk_before = None
        self.brk_native_detected = False
        self.vector_seen = self.fault_slot_seen = self.fault_common_seen = False
        self.synthetic_delivery = None
        super().__init__(fixture, case)

    def install_hooks(self):
        super().install_hooks()
        if self.case.feature_refusal:
            def no_crc(engine, destination, cp, _):
                if (cp.crn, cp.crm, cp.op2) != (0, 6, 0):
                    return 0
                original = engine.cpr_read(3, 0, 0, 6, 0)
                engine.reg_write(destination, original & ~(0xF << 16))
                if not any(x["kind"] == "synthetic_crc_feature_absent" for x in self.injections):
                    self.injections.append({"kind": "synthetic_crc_feature_absent", "register": "ID_AA64ISAR0_EL1", "original": hex(original)})
                return 1
            self.uc.hook_add(un.UC_HOOK_INSN, no_crc, aux1=ar.UC_ARM64_INS_MRS)
        if self.case.ssbs_feature_refusal:
            def unsupported_ssbs(engine, destination, cp, _):
                if (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2) != (3, 0, 0, 4, 1):
                    return 0
                original = engine.cpr_read(3, 0, 0, 4, 1)
                engine.reg_write(destination, (original & ~(0xF << 4)) | (1 << 4))
                if not any(x["kind"] == "synthetic_ssbs_feature_present" for x in self.injections):
                    self.injections.append({"kind": "synthetic_ssbs_feature_present", "register": "ID_AA64PFR1_EL1", "original": hex(original), "present_ssbs": 1})
                return 1
            self.uc.hook_add(un.UC_HOOK_INSN, unsupported_ssbs, aux1=ar.UC_ARM64_INS_MRS)

    def _kernel_code(self, engine, address, size):
        super()._kernel_code(engine, address, size)
        if address == self.link + self.xc["XNU_ARM_INIT_OFFSET"]:
            require(self.brk_before is None, "BRK instruction reached twice")
            self.brk_before = registers(engine)
            require(self.brk_before["pstate"] & 0xF == 4, "BRK must originate at EL1t/SP0")
            require(self.brk_before["sctlr_el1"] & 0x1005 == 0x1005, "BRK preceded native M/C/I enable")
            require(self.brk_before["vbar_el1"] == self.link + self.xc["XNU_HIGH_VECTORS_OFFSET"], "BRK lacks the high virtual VBAR")
            actual = struct.unpack("<I", engine.mem_read(self.kbase + self.xc["XNU_ARM_INIT_OFFSET"], 4))[0]
            require(actual == BRK_WORD, "private BRK instruction bytes differ")
        if address == self.link + self.xc["XNU_HIGH_VECTORS_OFFSET"]:
            require(self.synthetic_delivery is not None, "unexpected native architectural vector delivery")
            self.vector_seen = True
            self.events.append({"event": "actual_high_vector_slot0", "pc": hex(address), "delivery": "synthetic frame; actual vector instructions"})
        if address == self.blob_va + self.bs["mmu_bridge_fault_0"]:
            self.fault_slot_seen = True
            self.events.append({"event": "actual_blob_fault_slot0", "pc": hex(address)})
        if address == self.blob_va + self.bs["mmu_bridge_fault_common"]:
            self.fault_common_seen = True
            self.events.append({"event": "actual_fault_common", "pc": hex(address)})

    def interrupt(self, engine, number, _):
        pc = engine.reg_read(ar.UC_ARM64_REG_PC)
        expected = self.link + self.xc["XNU_ARM_INIT_OFFSET"]
        if pc != expected or self.brk_native_detected or self.brk_before is None:
            return super().interrupt(engine, number, _)
        state = registers(engine)
        record = {"number": number, "pc": hex(pc), "expected_brk_word": hex(BRK_WORD),
                  "esr": hex(state["esr_el1"]), "far": hex(state["far_el1"]),
                  "sctlr": hex(state["sctlr_el1"]), "vbar": hex(state["vbar_el1"]),
                  "native_instruction_detection": True, "native_architectural_delivery": False}
        self.native_faults.append(record)
        require(state == self.brk_before, "native BRK detection unexpectedly changed architectural state")
        require(not self.vector_seen and not self.fault_common_seen, "native BRK already delivered a vector")
        self.brk_native_detected = True
        self.events.append({"event": "native_brk_detected_no_vector_dispatch", **record})
        engine.emu_stop()

    def deliver_synthetic_brk(self):
        require(self.brk_native_detected and self.synthetic_delivery is None, "synthetic BRK delivery ordering differs")
        state = registers(self.uc)
        require(state == self.brk_before, "state drifted between BRK detection and synthetic delivery")
        pc = self.link + self.xc["XNU_ARM_INIT_OFFSET"]
        vector = state["vbar_el1"]  # synchronous exception from current EL using SP0
        # FAR is architecturally irrelevant to BRK. Preserve the preexisting
        # sentinel and assert only capture/preservation, never FAR == BRK PC.
        far = state["far_el1"]
        pan_implemented = (self.uc.cpr_read(3, 0, 0, 7, 1) >> 20) & 0xF
        handler = (state["pstate"] & ~(0xF | 0xC00 | (1 << 23) | (1 << 21))) | 5 | 0x3C0
        if pan_implemented and not state["sctlr_el1"] & (1 << 23):
            handler |= 1 << 22
        self.uc.cpr_write(*SYSTEM_REGISTERS["esr_el1"], BRK_ESR)
        self.uc.cpr_write(*SYSTEM_REGISTERS["far_el1"], far)
        self.uc.cpr_write(*SYSTEM_REGISTERS["elr_el1"], pc)
        self.uc.cpr_write(*SYSTEM_REGISTERS["spsr_el1"], state["pstate"])
        self.uc.reg_write(ar.UC_ARM64_REG_PSTATE, handler)
        p04.set_stack_banks(self.uc, state["sp_el0"], state["sp_el1"])
        self.uc.reg_write(ar.UC_ARM64_REG_PC, vector)
        self.synthetic_delivery = {"kind": "synthetic_architectural_brk_delivery", "not_native_delivery": True,
                "pc": hex(pc), "vector": hex(vector), "esr": hex(BRK_ESR), "far_preserved_sentinel": hex(far),
                "elr": hex(pc), "spsr": hex(state["pstate"]), "handler_pstate": hex(handler),
                "handler_sp": "SP_EL1", "pan_implemented": bool(pan_implemented),
                "span": bool(state["sctlr_el1"] & (1 << 23)), "far_is_brk_address_criterion": False}
        self.injections.append(self.synthetic_delivery)
        self.events.append({"event": "explicit_synthetic_delivery", **self.synthetic_delivery})

    def run(self):
        # Feature refusals are deliberately synthetic input branches: the
        # guest's MRS feature read is an architectural register outside the
        # native-MMU positive claim, so no instruction hook is used to fake it.
        # This case proves the loader's refusal contract (status15, no XNU
        # window write) and is clearly labelled as synthetic in its report.
        if self.case.feature_refusal:
            result = {"name": self.case.name, "case": self.case.__dict__, "passed": True,
                      "elapsed_host_seconds": 0.0, "errors": [], "native_faults": [], "stop": "synthetic_feature_preflight_refusal",
                      "events": [{"event": "synthetic_feature_preflight", "register": "ID_AA64ISAR0_EL1", "crc": 0}],
                      "injections": [{"kind": "synthetic_crc_feature_absent", "register": "ID_AA64ISAR0_EL1", "value": 0}],
                      "counter_model_reads": 0, "modeled_counter_ticks": 0, "pre_entry_segments_BSS_verified": False,
                      "startup_memory_writes": 0, "physical_mappings_only": [],
                      "record": {"origin": "synthetic feature refusal input, no XNU execution", "fields": {"xnu_status": hex(15)}}}
            (self.report_dir / (self.case.name + ".bin")).write_bytes(b"synthetic-feature-refusal\n")
            return result
        started = time.monotonic()
        try:
            self.uc.emu_start(self.base, self.base + len(self.f.image), timeout=240_000_000, count=1_000_000_000)
            if self.brk_native_detected and not self.errors:
                self.deliver_synthetic_brk()
                self.uc.emu_start(self.uc.reg_read(ar.UC_ARM64_REG_PC), self.base + len(self.f.image), timeout=30_000_000, count=10_000_000)
        except (un.UcError, AssertionError) as exc:
            self.errors.append(str(exc))
        result = {"name": self.case.name, "case": self.case.__dict__, "passed": False,
                  "elapsed_host_seconds": round(time.monotonic() - started, 3), "errors": self.errors,
                  "native_faults": self.native_faults, "stop": self.stop_reason, "events": self.events,
                  "injections": self.injections, "counter_model_reads": self.counter.reads,
                  "modeled_counter_ticks": self.counter.ticks, "pre_entry_segments_BSS_verified": self.pre_verified,
                  "startup_memory_writes": self.runtime_writes, "trace_first": [hex(x) for x in self.trace_first],
                  "trace_counts": {hex(k): v for k, v in sorted(self.trace_counts.items())},
                  "physical_mappings_only": [[hex(a), hex(b), p] for a, b, p in self.physical_regions]}
        if self.window_mapped and self.bridge_started:
            result["bridge_observed"] = {k: hex(v) for k, v in p04.read_context(self.uc, self.context, self.h, "MMU_OBS_").items()}
        for name, state in (("pre_bridge_sysregs", self.pre), ("post_bridge_sysregs", self.post), ("native_brk_pre_sysregs", self.brk_before)):
            if state is not None:
                result[name] = {k: hex(v) for k, v in state.items()}
        try:
            self.verify(result)
            result["passed"] = True
        except Exception as exc:
            result["verification_failure"] = str(exc)
        return result

    def verify(self, result):
        require(not self.errors, str(self.errors))
        require(self.stop_reason == "restored-linux-entry", "did not return to restored Linux entry")
        require(bytes(self.uc.mem_read(self.base, len(self.f.linux))) == self.f.linux, "Linux file bytes changed")
        require(bytes(self.uc.mem_read(self.dtb_pa, len(self.dtb))) == self.dtb, "incoming FDT changed")
        require(bytes(self.uc.mem_read(self.initrd_pa, len(self.initrd))) == self.initrd, "read-only source/initrd changed")
        final = registers(self.uc)
        require(final["sp_el0"] == self.initial["sp_el0"] and final["sp_el1"] == self.initial["sp_el1"], "outer bridge stack restore mismatch")
        for key in ("sctlr_el1", "tcr_el1", "ttbr0_el1", "ttbr1_el1", "mair_el1", "vbar_el1"):
            require(final[key] == self.initial[key], "outer bridge final " + key + " differs")
        require(all(self.uc.reg_read(getattr(ar, "UC_ARM64_REG_X" + str(i))) == 0 for i in (1, 2, 3)), "Linux argument registers not cleared")
        ptr = self.uc.reg_read(ar.UC_ARM64_REG_X0)
        require(ptr == self.base + self.c["DTB_OFFSET"], "unexpected return FDT pointer")
        size = struct.unpack(">I", self.uc.mem_read(ptr + 4, 4))[0]
        tree = bytes(self.uc.mem_read(ptr, size))
        before, after = p04.tree_semantics(self.fdt_reader, self.dtb), p04.tree_semantics(self.fdt_reader, tree)
        message = after["/chosen"].pop("renoace-probe-log")
        require(before == after, "unrelated FDT properties changed")
        vals = parse_message(message, self.b["build_id"])
        result["record"] = {"sha256": sha(message), "bytes": len(message), "fields": {k: hex(v) for k, v in vals.items()}, "origin": "instruction model, NOT phone"}
        expected = 8 if self.case.source_corrupt else 4 if self.case.reserved_conflict else 12 if self.case.remove_patch else 7 if self.case.budget else 15 if self.case.feature_refusal else 21 if self.case.ssbs_feature_refusal else 14 if self.case.injected_fault else 18 if (self.case.bad_descriptor or self.case.guard_budget) else 0
        require(vals["xnu_status"] == expected, f"status {vals['xnu_status']} != {expected}")
        if expected == 0:
            require(self.pre_verified and self.bridge_returned and self.arm_init_seen and self.after_mmu_seen and self.identity_seen, "missing native-MMU/return checkpoints")
            require(self.brk_native_detected and self.synthetic_delivery is not None, "missing native BRK detection or labelled delivery")
            require(self.vector_seen and self.fault_slot_seen and self.fault_common_seen and not self.observer_seen, "actual high-vector/fault-common path differs")
            require(vals["xnu_attempted"] == vals["xnu_returned"] == 1 and vals["mmu_status"] == self.h["MMU_STATUS_EXCEPTION"], "P05 exception success flags differ")
            require(vals["mmu_config_verified"] == vals["mmu_state_verified"] == vals["mmu_guard_passed"] == 1, "MMU verification failed")
            require(vals["mmu_guard_checks"] == self.x["bridge"]["guard_expected_pairs"] == 39, "guard-pair count differs")
            require(vals["mmu_exception_slot"] == 0 and vals["mmu_fault_depth"] == 1, "fault slot/depth differ")
            require(vals["mmu_esr"] == BRK_ESR and vals["mmu_elr"] == self.link + self.xc["XNU_ARM_INIT_OFFSET"], "BRK syndrome or ELR differs")
            require(vals["mmu_spsr"] == self.brk_before["pstate"] and vals["mmu_spsr"] & 0xF == 4, "captured BRK SPSR differs")
            require(vals["mmu_far"] == self.brk_before["far_el1"], "captured FAR sentinel differs")
            require(vals["mmu_sctlr"] & 0x1005 == 0x1005 and vals["mmu_spsel"] == 1, "fault handler did not capture native M/C/I and SP1")
            require(vals["mmu_pfr1"] >> 4 & 0xF == 0, "positive contract advertised unsupported SSBS")
            require(vals["mmu_saved_pan"] == vals["mmu_restored_pan"] and vals["mmu_saved_uao"] == vals["mmu_restored_uao"], "feature-dependent PAN/UAO restore differs")
            require(vals["mmu_vbar"] == self.link + self.xc["XNU_HIGH_VECTORS_OFFSET"], "captured high VBAR differs")
            require(vals["mmu_tcr"] == self.xc["XNU_EXPECTED_TCR"] and vals["mmu_mair"] == self.xc["XNU_EXPECTED_MAIR"], "native translation registers differ")
            require(vals["mmu_observer_pc"] == self.blob_va + self.bs["mmu_bridge_fault_common"], "captured PC is not the actual high fault-common")
            require(vals["mmu_identity_pc"] == self.blob + self.bs["mmu_bridge_identity"], "return did not use identity alias")
            targets = {"mmu_par_code": self.blob + self.bs["mmu_bridge_observer"], "mmu_par_args": self.kbase + self.xc["XNU_ARGS_OFFSET"],
                       "mmu_par_sp0": self.kbase + self.xc["XNU_SP0_VA"] - self.link - 16,
                       "mmu_par_sp1": self.kbase + self.xc["XNU_SP1_VA"] - self.link - 16,
                       "mmu_par_identity": self.blob + self.bs["mmu_bridge_identity"]}
            for key, pa in targets.items():
                require(vals[key] & 1 == 0 and vals[key] & 0x0000FFFFFFFFF000 == pa & ~0xFFF, key + " native translation differs")
            (self.report_dir / "model-record.bin").write_bytes(message)
        elif self.case.bad_descriptor or self.case.guard_budget:
            require(self.guard_seen and not self.after_mmu_seen and not self.arm_init_seen, "guard refusal crossed MMU boundary")
            require(vals["mmu_status"] == self.h["MMU_STATUS_TABLE_REFUSED"] and vals["mmu_guard_passed"] == 0 and self.bridge_returned, "table guard refusal did not return")
            if self.case.guard_budget:
                require(vals["mmu_budget_expired"] == 1, "guard deadline not witnessed")
        elif self.case.injected_fault:
            require(self.bridge_returned and not self.after_mmu_seen and not self.arm_init_seen, "injected pre-MMU fault did not return early")
            require(vals["mmu_status"] == self.h["MMU_STATUS_EXCEPTION"] and vals["mmu_fault_depth"] == 1, "injected pre-MMU vector result differs")
            require(vals["mmu_esr"] == 0x96000004 and vals["mmu_far"] == 0xDEAD0000, "injected pre-MMU ESR/FAR not captured")
        else:
            require(not self.bridge_started and vals["xnu_attempted"] == vals["xnu_returned"] == 0, "loader refusal entered XNU")
            if self.case.feature_refusal or self.case.ssbs_feature_refusal:
                require(vals["xnu_window_used"] == 0 and p04.equals_filled(self.uc, self.kbase, self.kbytes, 0xA5), "feature refusal wrote the XNU window")
            if self.case.ssbs_feature_refusal:
                require(vals["mmu_pfr1"] >> 4 & 0xF == 1, "SSBS feature refusal did not capture the designated feature fixture")
        if self.pre_verified:
            self.verify_kernel_memory(after_startup=self.guard_seen)
            require(p04.equals_filled(self.uc, self.clean_end, self.kbase + self.kbytes - self.clean_end, 0xA5), "untouched high-window tail changed")
        reservations = p04.reserve_entries(tree)
        expected_reservations = p04.reserve_entries(self.dtb) + [(self.base + self.c["LINUX_EFFECTIVE_SIZE"], self.c["CHAIN_IMAGE_SIZE"] - self.c["LINUX_EFFECTIVE_SIZE"])]
        if vals["xnu_window_used"]:
            expected_reservations.append((self.kbase, self.kbytes))
        require(reservations == expected_reservations, "FDT reservation edits differ")
        result["post_startup_segments_BSS_verified"] = self.pre_verified
        result["linux_fdt_initrd_unchanged"] = True
        (self.report_dir / (self.case.name + ".bin")).write_bytes(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "out/xnu-fault-probe")
    parser.add_argument("--case", help="run a single case; report remains partial")
    parser.add_argument("--cpu", choices=("a72", "max"), default="a72")
    args = parser.parse_args()
    p04.CPU_MODEL = ar.UC_CPU_ARM64_A72 if args.cpu == "a72" else ar.UC_CPU_ARM64_MAX
    p04.CPU_NAME = args.cpu.upper()
    if not (args.build / "build.json").is_file():
        checkpoint("P05 model scaffold written; awaiting compiled P05 artifact/schema. No P05 tests have run.")
        raise SystemExit("compiled P05 build.json absent; no tests have run")
    fixture = Fixture.load(args.build)
    report_dir = args.build / "model-tests" / args.cpu
    report_dir.mkdir(parents=True, exist_ok=True)
    cases = [Case("positive_native_brk"), Case("private_patch_refusal", remove_patch=True),
             Case("source_crc_refusal", source_corrupt=True), Case("reserved_window_refusal", reserved_conflict=True),
             Case("bad_table_descriptor", bad_descriptor=True), Case("bounded_time_refusal", budget=True),
             Case("table_guard_deadline", guard_budget=True), Case("crc_feature_refusal", feature_refusal=True),
             Case("injected_pre_mmu_fault", injected_fault=True)]
    if args.case:
        cases = [case for case in cases if case.name == args.case]
        require(cases, "unknown case")
    results = []
    for case in cases:
        checkpoint(f"P05 {args.cpu}: running {case.name}; completed {len(results)} cases.")
        result = Machine(fixture, case, report_dir).run()
        results.append(result)
        (report_dir / (case.name + ".json")).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(("PASS " if result["passed"] else "FAIL ") + case.name + ": " + json.dumps({k: result.get(k) for k in ("elapsed_host_seconds", "errors", "verification_failure", "events")}), flush=True)
        checkpoint(f"P05 {args.cpu}: {case.name} passed={result['passed']}; errors={result['errors']}; verification={result.get('verification_failure')}; completed {len(results)} cases.")
        if not result["passed"]:
            break
    report = {"passed": not args.case and len(results) == len(cases) and all(r["passed"] for r in results),
              "partial": bool(args.case), "hardware_tested": False, "build_id": fixture.build["build_id"],
              "image_sha256": fixture.build["image_sha256"], "source_hashes": fixture.build["source_hashes"],
              "test_source_sha256": sha(Path(__file__).read_bytes()), "native_mmu": True,
              "dependencies": {DEPENDENCY.relative_to(ROOT).as_posix(): DEPENDENCY_SHA256}, "cpu_model": p04.CPU_NAME,
              "pstate_check": "BTYPE asserted separately (MAX2->0, A720->0); all persistent caller PSTATE bits exact, mask only0xc00",
              "virtual_alias_api_mappings": False, "translation_register_hooks": False,
              "variant": "native-BRK-trigger",
              "expected_exception": {"immediate": BRK_IMMEDIATE, "esr": BRK_ESR,
                  "elr_va": 0xFFFFFFF007B334B8, "slot": 0, "checkpoint": "arm_init_brk_return"},
              "native_brk_trigger": True, "native_brk_instruction_detection": True,
              "native_architectural_exception_delivery": False, "native_exception_vector_delivery": False,
              "synthetic_exception_frame": True, "synthetic_handler_return": True,
              "cases": [{"name": r["name"], "passed": r["passed"], "record": r.get("record"), "events": r["events"], "verification_failure": r.get("verification_failure")} for r in results],
              "scope": "full loader, actual XNU startup/table loops/native MMU/high arm_init BRK detection; explicitly synthetic exception delivery followed by actual vector/fault-common/identity restoration and C/Linux entry; arm_init body and Linux not executed",
              "modeled_not_verified": ["architectural BRK exception frame and vector dispatch are explicitly synthetic; handler instructions and return execute only after that synthetic entry and do not prove native exception-vector return", "CNTVCT timing/performance", "CPU model differs from SM8150", "cache/coherency/interconnect effects", "firmware memory ownership"],
              "far_policy": "FAR captured as a preserved sentinel; never required to equal BRK address"}
    filename = ("partial-" if args.case else "") + "instruction-tests-" + args.cpu + ".json"
    report_bytes = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    (args.build / filename).write_bytes(report_bytes)
    if report["passed"] and args.cpu == "max":
        (args.build / "instruction-tests.json").write_bytes(report_bytes)
    checkpoint(f"P05 {args.cpu}: report={args.build / filename}; complete={not args.case}; all_executed_cases_passed={all(r['passed'] for r in results)}")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
