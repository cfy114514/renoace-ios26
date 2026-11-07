#!/usr/bin/env python3
"""P07 full-VM instruction model (no phone operations).

Runs the full loader, actual XNU bootstrap/MMU startup, arm_init FP snapshot,
and original early C through the complete arm_vm_init return checkpoint.
Only deterministic CNTVCT progression is supplied by a labelled MRS peer.
Physical RAM is mapped; high virtual aliases are never mapped through the API.
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
sys.path.insert(0, str(ROOT / "out/probe-test-deps"))
import unicorn as un
from unicorn import arm64_const as ar

FREQUENCY = 19_200_000
PHYSICAL_LIMIT = 1 << 40
CPU_MODEL = ar.UC_CPU_ARM64_A72
CPU_NAME = "A72"
SYSTEM_REGISTERS = {
    "cntkctl_el1": (3, 0, 14, 1, 0),
    "sctlr_el1": (3, 0, 1, 0, 0), "tcr_el1": (3, 0, 2, 0, 2),
    "ttbr0_el1": (3, 0, 2, 0, 0), "ttbr1_el1": (3, 0, 2, 0, 1),
    "mair_el1": (3, 0, 10, 2, 0), "amair_el1": (3, 0, 10, 3, 0),
    "vbar_el1": (3, 0, 12, 0, 0), "cpacr_el1": (3, 0, 1, 0, 2),
    "contextidr_el1": (3, 0, 13, 0, 1), "tpidr_el1": (3, 0, 13, 0, 4),
    "tpidr_el0": (3, 3, 13, 0, 2), "tpidrro_el0": (3, 3, 13, 0, 3),
    "par_el1": (3, 0, 7, 4, 0), "elr_el1": (3, 0, 4, 0, 1),
    "spsr_el1": (3, 0, 4, 0, 0), "csselr_el1": (3, 2, 0, 0, 0),
    "esr_el1": (3, 0, 5, 2, 0), "far_el1": (3, 0, 6, 0, 0),
}


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dependency_hashes():
    paths = [ROOT / "references/ios-flame/tools/fdt.py"]
    paths += [p for p in (ROOT / "out/probe-test-deps/unicorn").rglob("*")
              if p.is_file() and p.suffix.lower() in (".py", ".dll")]
    require(len(paths) > 1, "Unicorn dependency inventory absent")
    return {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sorted(paths)}


def checkpoint(message):
    (ROOT / "out/p06-model-checkpoint.txt").write_text(message + "\n", encoding="utf-8")


def fp_state(uc):
    return {"q": [uc.reg_read(getattr(ar, "UC_ARM64_REG_Q" + str(i))) for i in range(32)],
            "fpcr": uc.reg_read(ar.UC_ARM64_REG_FPCR), "fpsr": uc.reg_read(ar.UC_ARM64_REG_FPSR)}


def align(size):
    return (size + 4095) & ~4095


def physical_map(uc, address, size, permissions=un.UC_PROT_ALL):
    require(address >= 0 and address + size <= PHYSICAL_LIMIT, "refusing a high-VA or out-of-PA mapping")
    uc.mem_map(address, align(size), permissions)


def native_cpu():
    require(un.__version__ == "2.1.4", "pinned Unicorn2.1.4 required")
    uc = un.Uc(un.UC_ARCH_ARM64, un.UC_MODE_ARM)
    uc.ctl_set_cpu_model(CPU_MODEL)
    uc.ctl_set_tlb_mode(un.UC_TLB_CPU)
    # Establish the higher-EL AArch64 regime before entering the EL1 fixture.
    # Without these initial bits Unicorn selects AArch32 table semantics.
    uc.cpr_write(3, 6, 1, 1, 0, uc.cpr_read(3, 6, 1, 1, 0) | 1 | (1 << 10))
    uc.cpr_write(3, 4, 1, 1, 0, 1 << 31)  # HCR.RW=1, stage2/VM=0
    uc.cpr_write(3, 3, 14, 0, 0, FREQUENCY)
    # Model the measured unlocked OS debug state through its real control.
    # Reset OSLSR may be0xa; OSLAR=0 makes it0x8, as on the phone.
    uc.cpr_write(2, 0, 1, 0, 4, 0)
    uc.reg_write(ar.UC_ARM64_REG_PSTATE, 0x3C5)
    return uc


def registers(uc):
    values = {name: uc.cpr_read(*encoding) for name, encoding in SYSTEM_REGISTERS.items()}
    pstate = uc.reg_read(ar.UC_ARM64_REG_PSTATE)
    # Unicorn's active SP lives separately from the inactive bank cache.
    # Reading the current bank through SP_ELn can otherwise report stale data.
    values.update(sp_el0=uc.reg_read(ar.UC_ARM64_REG_SP_EL0),
                  sp_el1=uc.reg_read(ar.UC_ARM64_REG_SP_EL1), pstate=pstate)
    values["sp_el1" if pstate & 1 else "sp_el0"] = uc.reg_read(ar.UC_ARM64_REG_SP)
    return values


def set_stack_banks(uc, sp0, sp1):
    uc.reg_write(ar.UC_ARM64_REG_SP_EL0, sp0)
    uc.reg_write(ar.UC_ARM64_REG_SP_EL1, sp1)
    uc.reg_write(ar.UC_ARM64_REG_SP, sp1 if uc.reg_read(ar.UC_ARM64_REG_PSTATE) & 1 else sp0)


def definitions(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"#define\s+((?:MMU|P11)_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+|[0-9]+)", line.strip())
        if match:
            result[match[1]] = int(match[2], 0)
    return result


def fdt_locations(blob):
    structure, strings = struct.unpack_from(">II", blob, 8)
    at, stack, found = structure, [], {}
    while True:
        token = struct.unpack_from(">I", blob, at)[0]
        at += 4
        if token == 1:
            end = blob.index(0, at)
            stack.append(blob[at:end].decode())
            at = (end + 4) & ~3
        elif token == 2:
            stack.pop()
        elif token == 3:
            length, offset = struct.unpack_from(">II", blob, at)
            at += 8
            name = blob[strings + offset:blob.index(0, strings + offset)].decode()
            found["/" + "/".join(stack[1:]), name] = (at, length)
            at = (at + length + 3) & ~3
        elif token == 4:
            pass
        elif token == 9:
            return found
        else:
            raise ValueError("bad FDT fixture token")


def macho_inventory(data):
    require(struct.unpack_from("<4I", data) == (0xFEEDFACF, 0x100000C, 0, 2), "expected plain ARM64 executable Mach-O")
    count, command_bytes = struct.unpack_from("<II", data, 16)
    at, segments, symtab = 32, [], None
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, at)
        require(size >= 8 and at + size <= 32 + command_bytes, "invalid Mach-O load commands")
        if command == 0x19:
            name = data[at + 8:at + 24].split(b"\0")[0].decode()
            va, memory_size, offset, file_size = struct.unpack_from("<4Q", data, at + 24)
            if memory_size:
                require(file_size <= memory_size and offset + file_size <= len(data), "bad segment bounds")
                segments.append(dict(name=name, va=va, mem=memory_size, off=offset, fil=file_size))
        elif command == 2:
            symtab = struct.unpack_from("<4I", data, at + 8)
        at += size
    require(at == 32 + command_bytes and segments and symtab, "incomplete Mach-O inventory")
    offset, count, strings, string_bytes = symtab
    require(offset + count * 16 <= len(data) and strings + string_bytes <= len(data), "bad symbol-table bounds")
    names = {}
    for i in range(count):
        name, typ, section, desc, value = struct.unpack_from("<IBBHQ", data, offset + 16 * i)
        if not name or name >= string_bytes:
            continue
        text = data[strings + name:data.index(0, strings + name, strings + string_bytes)].decode("utf-8", "replace")
        if typ & 0xE == 0xE:
            names[text] = value
    return segments, names


def branch_target(word, pc):
    require(word & 0xFC000000 == 0x14000000, "expected a direct AArch64 B")
    immediate = word & 0x3FFFFFF
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return (pc + immediate * 4) & 0xFFFFFFFFFFFFFFFF


def load_fdt_reader():
    spec = importlib.util.spec_from_file_location("p04_fdt", ROOT / "references/ios-flame/tools/fdt.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree_semantics(reader, blob):
    return {node.path: dict(node.props) for node in reader.parse(blob).walk()}


def reserve_entries(blob):
    at = struct.unpack_from(">I", blob, 16)[0]
    entries = []
    while at + 16 <= len(blob):
        address, size = struct.unpack_from(">QQ", blob, at)
        at += 16
        if not address and not size:
            return entries
        entries.append((address, size))
    raise ValueError("unterminated reservation map")


def parse_message(message, build_id):
    require(message.endswith(b"\0") and b"\0" not in message[:-1], "bad wire termination")
    data = message[:-1]
    start = data.rfind(b"crc32=")
    require(start > 0, "wire CRC absent")
    check = re.fullmatch(rb"crc32=0x([0-9a-f]{16})\n", data[start:])
    require(check and zlib.crc32(data[:start]) == int(check[1], 16), "wire CRC mismatch")
    lines = data[:start].splitlines()
    require(lines[0] == b"RENOACE-XNU-VM-P07" and lines[1] == ("build=" + build_id).encode(), "wrong wire identity")
    fields = {}
    for line in lines[2:]:
        match = re.fullmatch(rb"([a-z0-9_]+)=0x([0-9a-f]{16})", line)
        require(match is not None, "malformed wire field")
        name = match[1].decode()
        require(name not in fields, "duplicate wire field")
        fields[name] = int(match[2], 16)
    return fields


def read_context(uc, address, offsets, prefix):
    return {name: struct.unpack("<Q", uc.mem_read(address + offset, 8))[0]
            for name, offset in offsets.items() if name.startswith(prefix)}


def equals_filled(uc, address, size, byte):
    for offset in range(0, size, 1 << 20):
        length = min(1 << 20, size - offset)
        if bytes(uc.mem_read(address + offset, length)) != bytes([byte]) * length:
            return False
    return True


def validate_adt_fixture(data):
    """Independent host parser; these input tests do not execute guest C."""
    found, fields = {}, {}
    def node(at, parent, depth):
        require(depth <= 16 and at + 8 <= len(data), "truncated ADT node")
        np, nc = struct.unpack_from("<II", data, at); at += 8
        require(np <= 64 and nc <= 64, "ADT node counts exceed bounds")
        props, locations = {}, {}
        for _ in range(np):
            require(at + 36 <= len(data), "truncated ADT property header")
            raw = data[at:at + 32]
            require(b"\0" in raw, "unterminated ADT property")
            name = raw.split(b"\0", 1)[0].decode()
            size = struct.unpack_from("<I", data, at + 32)[0]; at += 36
            require(name and name not in props and size < 0x80000000 and at + size <= len(data), "bad ADT property bounds")
            props[name] = data[at:at + size]; locations[name] = (at, size)
            padded = (at + size + 3) & ~3
            require(padded <= len(data) and not any(data[at + size:padded]), "bad ADT padding")
            at = padded
        name = props.get("name", b"")
        require(name.endswith(b"\0") and b"\0" not in name[:-1], "bad ADT node name")
        path = "/" if depth == 0 else parent.rstrip("/") + "/" + name[:-1].decode()
        require(path not in found, "duplicate ADT path")
        found[path] = props
        fields.update({(path, key): value for key, value in locations.items()})
        for _ in range(nc):
            at = node(at, path, depth + 1)
        return at
    require(node(0, "", 0) == len(data), "ADT has trailing bytes")
    for path in ("/", "/arm-io"):
        require(found[path].get("#address-cells") == struct.pack("<I", 2) and found[path].get("#size-cells") == struct.pack("<I", 2), "ADT cells must be 2/2")
    require(found["/arm-io"].get("ranges") == struct.pack("<QQQ", 0, 0, 0xFFFFFFFF), "ADT identity range differs")
    require(found["/arm-io"].get("device_type") == b"arm-io\0", "ADT arm-io device_type differs")
    cpu = found["/cpus/cpu0"]
    require(cpu.get("state") == b"running\0" and cpu.get("reg") == struct.pack("<I", 0), "ADT running CPU0 differs")
    require(cpu.get("timebase-frequency") == struct.pack("<I", FREQUENCY), "ADT CPU0 timebase differs")
    return found, fields


def host_input_tests(fixture):
    data = (fixture.directory / "renoace.adt").read_bytes()
    _, fields = validate_adt_fixture(data)
    cases = [{"name": "valid_complete_identity_ADT", "passed": True}]
    for name, key, replacement in (
            ("identity_parent_changed", ("/arm-io", "ranges"), struct.pack("<QQQ", 0, 1, 0xFFFFFFFF)),
            ("identity_size_truncated", ("/arm-io", "ranges"), struct.pack("<QQQ", 0, 0, 0x100000)),
            ("arm_io_cells_wrong", ("/arm-io", "#address-cells"), struct.pack("<I", 1)),
            ("cpu0_timebase_wrong", ("/cpus/cpu0", "timebase-frequency"), struct.pack("<I", 24_000_000))):
        at, size = fields[key]
        require(size == len(replacement), "host mutation size differs")
        changed = bytearray(data); changed[at:at + size] = replacement
        try:
            validate_adt_fixture(bytes(changed))
        except AssertionError as exc:
            cases.append({"name": name, "passed": True, "rejected": str(exc)})
        else:
            cases.append({"name": name, "passed": False, "rejected": None})
    return {"passed": all(c["passed"] for c in cases), "scope": "independent host ADT input validation only; malformed ADT is not executed by guest C", "cases": cases}


@dataclass
class CounterPeer:
    """Keep CNTVCT deterministic and mirror CVAL around Unicorn's timer quirk."""
    ticks: int = 0
    step: int = 64
    reads: int = 0
    cvals: dict = None

    def __post_init__(self):
        if self.cvals is None:
            self.cvals = {(3, 3, 14, 3, 0): 0, (3, 3, 14, 2, 0): 0}

    def install(self, uc):
        def read(engine, destination, cp, _):
            key = (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2)
            if key == (3, 3, 14, 0, 2):
                self.ticks += self.step
                self.reads += 1
                engine.reg_write(destination, self.ticks)
                return 1
            if key in self.cvals:
                engine.reg_write(destination, self.cvals[key])
                return 1
            return 0  # native MRS, including all MMU/feature registers

        def write(_engine, _source, cp, _):
            key = (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2)
            if key in self.cvals:
                self.cvals[key] = cp.val
                return 1
            return 0

        uc.hook_add(un.UC_HOOK_INSN, read, aux1=ar.UC_ARM64_INS_MRS)
        uc.hook_add(un.UC_HOOK_INSN, write, aux1=ar.UC_ARM64_INS_MSR)


@dataclass
class Fixture:
    directory: Path
    build: dict
    image: bytes
    linux: bytes
    initrd: bytes
    macho: bytes
    fdt: bytes
    header: dict

    @classmethod
    def load(cls, directory):
        build = json.loads((directory / "build.json").read_text())
        image = (directory / "Image").read_bytes()
        linux = (directory / "original-linux.Image").read_bytes()
        initrd = (directory / "ramdisk").read_bytes()
        macho = (ROOT / build["xnu"]["source"]).read_bytes()
        require(sha(image) == build["image_sha256"], "compiled Image identity mismatch")
        require(sha(linux) == build["original_linux_sha256"], "original Linux identity mismatch")
        require(sha(initrd) == build["xnu"]["combined_ramdisk_sha256"], "initrd identity mismatch")
        require(sha(macho) == build["xnu"]["source_sha256"], "XNU source identity mismatch")
        for name, expected in build["source_hashes"].items():
            require(sha((Path(__file__).parent / name).read_bytes()) == expected, "source/build mismatch: " + name)
        require(build["xnu"]["constants"]["XNU_PATCH_COUNT"] == 155, "unexpected P11 private-patch inventory")
        header = definitions(Path(__file__).with_name("mmu_bridge.h"))
        header.update(definitions(Path(__file__).with_name("p11_gate_layout.h")))
        return cls(directory, build, image, linux, initrd, macho,
                   (ROOT / "local-device/20261106T115059Z/live.dtb").read_bytes(), header)


@dataclass(frozen=True)
class Case:
    name: str
    source_corrupt: bool = False
    reserved_conflict: bool = False
    remove_patch: bool = False
    bad_descriptor: bool = False
    budget: bool = False
    guard_budget: bool = False
    injected_fault: bool = False


class Machine:
    def __init__(self, fixture, case, report_dir=None):
        self.f = fixture
        self.case = case
        self.b = fixture.build
        self.c = self.b["constants"]
        self.x = self.b["xnu"]
        self.xc = self.x["constants"]
        self.s = self.b["symbols"]
        self.h = fixture.header
        self.report_dir = report_dir or fixture.directory / "model-tests" / CPU_NAME.lower()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.base = 0xA8880000
        self.kbase = self.c["XNU_PHYS_BASE"]
        self.kbytes = self.c["XNU_WINDOW_SIZE"]
        self.link = self.xc["XNU_LINK_BASE"]
        self.blob = self.kbase + self.xc["XNU_BLOB_OFFSET"]
        self.blob_va = self.link + self.xc["XNU_BLOB_OFFSET"]
        self.bs = self.x["bridge"]["symbols"]
        self.context = self.blob + self.bs["mmu_bridge_context"]
        self.clean_end = self.kbase + self.xc["XNU_TOP_DATA_OFFSET"]
        self.window_mapped = not (case.source_corrupt or case.reserved_conflict or case.budget)
        self.c_return_seen = False
        self.fp_seen = False
        self.c_mutation_ranges = [(int(r["offset"]), int(r["offset"])+int(r["bytes"])) for r in self.x.get("expected_mutable_ranges", [])]
        self.uc = native_cpu()
        self.counter = CounterPeer(step=400_000_000 if case.budget else 64)
        self.counter.install(self.uc)
        self.errors, self.native_faults, self.events, self.injections = [], [], [], []
        self.trace_counts = {}
        self.trace_first = []
        self.stop_reason = None
        self.first_linux = False
        self.pre = None
        self.post = None
        self.pre_verified = False
        self.bridge_started = False
        self.bridge_returned = False
        self.return_address = None
        self.arm_init_seen = False
        self.after_mmu_seen = False
        self.guard_seen = False
        self.identity_seen = False
        self.observer_seen = False
        self.runtime_writes = 0
        self.runtime_write_ranges = []
        self.table_patch = None
        self.fdt_reader = load_fdt_reader()
        self.initial_setup()
        self.install_hooks()

    def initial_setup(self):
        segments, symbols = macho_inventory(self.f.macho)
        self.kernel_helper_ranges = [(symbols[name] - self.link, symbols[name] - self.link + size)
                                     for name, size in (("_set_mmu_ttb", 16), ("_set_mmu_ttb_alternate", 16), ("_set_tcr", 12))]
        require(min(s["va"] for s in segments) == self.link, "independent link-base mismatch")
        for measured, expected in zip(segments, self.x["segments"]):
            require(all(measured[k] == expected[k] for k in ("name", "va", "mem", "off", "fil")), "independent segment mismatch")
        require(len(segments) == len(self.x["segments"]), "independent segment-count mismatch")
        require(symbols["_arm_init"] == self.link + self.xc["XNU_ARM_INIT_OFFSET"], "independent arm_init symbol mismatch")
        for patch in self.x["patches"]:
            require(struct.unpack_from("<I", self.f.macho, patch["file_offset"])[0] == patch["original"], "patch source word mismatch")
            if patch["bridge_symbol"]:
                require(branch_target(patch["replacement"], self.kbase + patch["offset"]) == self.blob + self.bs[patch["bridge_symbol"]], "private B target mismatch")
        self.bridge_binary = (self.f.directory / "mmu_bridge.bin").read_bytes()
        require(sha(self.bridge_binary) == self.x["bridge"]["sha256"], "bridge identity mismatch")
        for patch in self.x["bridge"]["resume_patches"]:
            word = struct.unpack_from("<I", self.bridge_binary, patch["blob_offset"])[0]
            require(word == patch["replacement"] and branch_target(word, self.blob + patch["blob_offset"]) == self.kbase + patch["target_kernel_offset"], "bridge resume B mismatch")
        self.args = (self.f.directory / "boot-args.bin").read_bytes()
        self.adt = (self.f.directory / "renoace.adt").read_bytes()
        require(sha(self.args) == self.x["boot_args"]["sha256"] and sha(self.adt) == self.x["ADT"]["sha256"], "metadata identity mismatch")
        end = self.base - 0x80000 + 0x8000000
        self.initrd_pa = end - align(len(self.f.initrd)) - 4096
        self.dtb_pa = self.initrd_pa - 0x200000 - 4096
        dtb = bytearray(self.f.fdt)
        locations = fdt_locations(dtb)
        for key, value in (("linux,initrd-start", self.initrd_pa), ("linux,initrd-end", self.initrd_pa + len(self.f.initrd))):
            at, size = locations["/chosen", key]
            require(size == 8, "unexpected FDT initrd property")
            struct.pack_into(">Q", dtb, at, value)
        if self.case.reserved_conflict:
            at, size = locations["/reserved-memory/hyp_mem", "reg"]
            require(size == 16, "unexpected reservation fixture")
            struct.pack_into(">QQ", dtb, at, self.kbase, self.kbytes)
        self.dtb = bytes(dtb)
        initrd = bytearray(self.f.initrd)
        if self.case.source_corrupt:
            initrd[self.xc["XNU_INITRD_OFFSET"] + 0x1000] ^= 1
        self.initrd = bytes(initrd)
        physical_map(self.uc, self.base, len(self.f.image))
        self.uc.mem_write(self.base, self.f.image)
        physical_map(self.uc, self.dtb_pa, len(self.dtb), un.UC_PROT_READ)
        self.uc.mem_write(self.dtb_pa, self.dtb)
        physical_map(self.uc, self.initrd_pa, len(self.initrd), un.UC_PROT_READ)
        self.uc.mem_write(self.initrd_pa, self.initrd)
        if self.window_mapped:
            physical_map(self.uc, self.kbase, self.kbytes)
            fill = bytes([0xA5]) * (1 << 20)
            for offset in range(0, self.kbytes, len(fill)):
                self.uc.mem_write(self.kbase + offset, fill)
        set_stack_banks(self.uc, 0xB7400000, 0xB7500000)
        self.uc.cpr_write(*SYSTEM_REGISTERS["vbar_el1"], 0x83800000)
        self.uc.cpr_write(*SYSTEM_REGISTERS["ttbr0_el1"], 0x42000000)
        self.uc.cpr_write(*SYSTEM_REGISTERS["ttbr1_el1"], 0x42001000)
        self.uc.cpr_write(*SYSTEM_REGISTERS["mair_el1"], 0xFF00)
        self.uc.cpr_write(*SYSTEM_REGISTERS["tpidr_el0"], 0x11223344)
        self.uc.cpr_write(*SYSTEM_REGISTERS["tpidr_el1"], 0x55667788)
        self.uc.cpr_write(*SYSTEM_REGISTERS["tpidrro_el0"], 0x99AABBCC)
        self.uc.cpr_write(*SYSTEM_REGISTERS["esr_el1"], 0x1234)
        self.uc.cpr_write(*SYSTEM_REGISTERS["far_el1"], 0x70003000)
        self.uc.reg_write(ar.UC_ARM64_REG_X0, self.dtb_pa)
        for i in range(32):
            self.uc.reg_write(getattr(ar, "UC_ARM64_REG_Q" + str(i)),
                              (0x1020304050607080 ^ (i * 0x0101010101010101)) |
                              ((0xF0E0D0C0B0A09080 ^ (i * 0x111111111111111)) << 64))
        self.uc.reg_write(ar.UC_ARM64_REG_FPCR, 0x07C00000)
        self.uc.reg_write(ar.UC_ARM64_REG_FPSR, 0x0800009F)
        self.initial = registers(self.uc)
        self.physical_regions = list(self.uc.mem_regions())
        require(all(end < PHYSICAL_LIMIT for _, end, _ in self.physical_regions), "high virtual alias was mapped")

    def fail(self, message):
        self.errors.append(message)
        self.uc.emu_stop()

    def protect_linux(self, engine, access, address, size, value, _):
        allowed = (self.base <= address and address + size <= self.base + 4)
        allowed |= self.base + 16 <= address and address + size <= self.base + 24
        if not allowed:
            self.fail(f"unexpected Linux write {address:#x}+{size}")

    def kernel_write(self, engine, access, address, size, value, _):
        if not self.bridge_started or self.bridge_returned:
            return
        address = self.kbase + address - self.link if address >= self.link else address
        pool = self.kbase + self.xc["XNU_BOOTSTRAP_OFFSET"]
        allowed = pool <= address and address + size <= pool + self.xc["XNU_BOOTSTRAP_BYTES"]
        allowed |= self.context <= address and address + size <= self.context + self.h["MMU_BRIDGE_CONTEXT_BYTES"]
        if self.arm_init_seen:
            off = address - self.kbase
            allowed |= any(lo <= off and off + size <= hi for lo, hi in self.c_mutation_ranges)
            # Early C may update the explicitly declared static-if record/text ranges.
            contract = self.x.get("early_c_mutation_contract", {})
            rec = contract.get("static_if_records", {})
            if rec:
                lo = int(rec["start"], 16) - self.link; hi = int(rec["end_exclusive"], 16) - self.link
                allowed |= lo <= off and off + size <= hi
            for va in contract.get("text_instruction_sites", []):
                lo = int(va, 16) - self.link
                allowed |= lo <= off and off + size <= lo + 4
        if not allowed:
            self.fail(f"unexpected XNU startup/early-C write {address:#x}+{size} pc={engine.reg_read(ar.UC_ARM64_REG_PC):#x}")
        self.runtime_writes += 1
        self.runtime_write_ranges.append([address, size])

    def invalid(self, engine, access, address, size, value, _):
        self.fail(f"unmapped/protected access {access} {address:#x}+{size} pc={engine.reg_read(ar.UC_ARM64_REG_PC):#x}")
        return False

    def interrupt(self, engine, number, _):
        record = {"number": number, "pc": hex(engine.reg_read(ar.UC_ARM64_REG_PC)),
                  "sctlr": hex(engine.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"])),
                  "esr": hex(engine.cpr_read(*SYSTEM_REGISTERS["esr_el1"])),
                  "far": hex(engine.cpr_read(*SYSTEM_REGISTERS["far_el1"]))}
        self.native_faults.append(record)
        self.fail("unexpected native CPU fault: " + json.dumps(record))

    def install_hooks(self):
        u = self.uc
        u.hook_add(un.UC_HOOK_MEM_INVALID, self.invalid)
        u.hook_add(un.UC_HOOK_INTR, self.interrupt)
        u.hook_add(un.UC_HOOK_MEM_WRITE, self.protect_linux, begin=self.base, end=self.base + self.c["LINUX_EFFECTIVE_SIZE"] - 1)
        if self.window_mapped:
            u.hook_add(un.UC_HOOK_MEM_WRITE, self.kernel_write, begin=self.kbase, end=self.clean_end - 1)
            u.hook_add(un.UC_HOOK_MEM_WRITE, self.kernel_write, begin=self.link, end=self.link + self.clean_end - self.kbase - 1)
            u.hook_add(un.UC_HOOK_MEM_WRITE, lambda *args: self.fail("write beyond owned clean extent"), begin=self.clean_end, end=self.kbase + self.kbytes - 1)
            u.hook_add(un.UC_HOOK_CODE, self.kernel_code, begin=self.kbase, end=self.kbase + self.kbytes - 1)
            u.hook_add(un.UC_HOOK_CODE, self.kernel_code, begin=self.link, end=self.link + self.kbytes - 1)

        def linux(engine, address, size, _):
            if not self.first_linux:
                self.first_linux = True
            else:
                self.stop_reason = "restored-linux-entry"
                engine.emu_stop()
        u.hook_add(un.UC_HOOK_CODE, linux, begin=self.base, end=self.base)
        for address in (self.base + self.s["chain_park"], self.blob + self.bs["mmu_bridge_park"], self.blob_va + self.bs["mmu_bridge_park"]):
            u.hook_add(un.UC_HOOK_CODE, lambda *args: self.fail("unexpected park"), begin=address, end=address)
        if self.case.remove_patch:
            def remove(engine, address, size, _):
                patch = next(p for p in self.x["patches"] if p["offset"] == self.xc["XNU_ARM_INIT_OFFSET"])
                engine.mem_write(self.kbase + patch["offset"], struct.pack("<I", patch["original"]))
                self.injections.append({"kind": "remove_private_arm_init_patch", "pa": hex(self.kbase + patch["offset"])})
            u.hook_add(un.UC_HOOK_CODE, remove, begin=self.base + self.s["xnu_validate_gate"], end=self.base + self.s["xnu_validate_gate"])

    def expected_pool(self):
        m = self.x["bootstrap_expected_mutations"]
        data = bytearray(m["pool_bytes"])
        pool = self.kbase + m["pool_image_offset"]
        for name in ("TTBR0", "TTBR1"):
            entry = m[name + "_root_entry"]
            struct.pack_into("<Q", data, m[name + "_root_pa"] - pool + entry["index"] * 8, entry["value"])
        for table_name, first_index in (("identity_L2_pa", m["identity_L2_index_first"]), ("high_L2_pa", m["high_L2_index_first"])):
            for i in range(m["leaf_count_each"]):
                struct.pack_into("<Q", data, m[table_name] - pool + (first_index + i) * 8,
                                 m["first_leaf_pa"] + i * m["leaf_stride"] | m["leaf_flags"])
        if self.table_patch:
            at, word = self.table_patch
            struct.pack_into("<Q", data, at - pool, word)
        return bytes(data)

    def _c_mutable(self, offset, size):
        if not self.arm_init_seen:
            return False
        if any(lo <= offset and offset + size <= hi for lo, hi in self.c_mutation_ranges):
            return True
        contract = self.x.get("early_c_mutation_contract", {})
        rec = contract.get("static_if_records", {})
        if rec:
            lo = int(rec["start"], 16) - self.link; hi = int(rec["end_exclusive"], 16) - self.link
            if lo <= offset and offset + size <= hi:
                return True
        for va in contract.get("text_instruction_sites", []):
            lo = int(va, 16) - self.link
            if lo <= offset and offset + size <= lo + 4:
                return True
        return False

    def _compare_segment(self, actual, expected, offset):
        if actual == expected:
            return True
        # C may self-modify only in builder-declared ranges. Compare every
        # byte outside those ranges so accidental writes remain visible.
        for i, (a, e) in enumerate(zip(actual, expected)):
            if a != e and not self._c_mutable(offset + i, 1):
                return False
        return True

    def verify_kernel_memory(self, after_startup=False):
        pool_start = self.xc["XNU_BOOTSTRAP_OFFSET"]
        pool = self.expected_pool() if after_startup else None
        for segment in self.x["segments"]:
            expected = bytearray(self.f.macho[segment["off"]:segment["off"] + segment["fil"]])
            offset = segment["relative"]
            for patch in self.x["patches"]:
                if offset <= patch["offset"] < offset + segment["fil"]:
                    value = patch["original"] if self.case.remove_patch and patch["offset"] == self.xc["XNU_ARM_INIT_OFFSET"] else patch["replacement"]
                    struct.pack_into("<I", expected, patch["offset"] - offset, value)
            if pool:
                low, high = max(offset, pool_start), min(offset + segment["fil"], pool_start + len(pool))
                if low < high:
                    expected[low - offset:high - offset] = pool[low - pool_start:high - pool_start]
            actual = bytes(self.uc.mem_read(self.kbase + offset, segment["fil"]))
            require(self._compare_segment(actual, expected, offset), self.case.name + ": segment file bytes differ outside declared early-C ranges: " + segment["name"])
            start, size = offset + segment["fil"], segment["mem"] - segment["fil"]
            if size:
                expected_zero = bytearray(size)
                if pool:
                    low, high = max(start, pool_start), min(start + size, pool_start + len(pool))
                    if low < high:
                        expected_zero[low - start:high - start] = pool[low - pool_start:high - pool_start]
                actual_zero = bytes(self.uc.mem_read(self.kbase + start, size))
                require(self._compare_segment(actual_zero, expected_zero, start),
                        self.case.name + ": BSS differs outside declared early-C ranges: " + segment["name"])
        require(bytes(self.uc.mem_read(self.kbase + self.xc["XNU_ARGS_OFFSET"], len(self.args))) == self.args, "boot_args changed")
        require(bytes(self.uc.mem_read(self.kbase + self.xc["XNU_ADT_OFFSET"], len(self.adt))) == self.adt, "ADT changed")
        context_offset = self.bs["mmu_bridge_context"]
        require(bytes(self.uc.mem_read(self.blob, context_offset)) == self.bridge_binary[:context_offset], "bridge code changed")
        require(equals_filled(self.uc, self.blob + len(self.bridge_binary), self.xc["XNU_BLOB_RESERVE"] - len(self.bridge_binary), 0), "bridge reserve tail changed")

    def bridge_enter(self):
        require(not self.bridge_started, "bridge entered twice")
        self.verify_kernel_memory()
        self.pre_verified = True
        self.pre = registers(self.uc)
        self.pre_fp = fp_state(self.uc)
        self.pre_gprs = [self.uc.reg_read(getattr(ar, "UC_ARM64_REG_X" + str(i))) for i in range(31)]
        self.return_address = self.pre_gprs[30]
        self.config_before = bytes(self.uc.mem_read(self.context, 0x100))
        self.bridge_started = True
        self.events.append({"event": "bridge_entry", "pc": hex(self.blob + self.bs["mmu_bridge_entry"])})

        def returned(engine, address, size, _):
            require(not self.bridge_returned, "bridge returned twice")
            self.post = registers(engine)
            now = [engine.reg_read(getattr(ar, "UC_ARM64_REG_X" + str(i))) for i in range(31)]
            require(now[1:] == self.pre_gprs[1:], "bridge did not restore all caller GPRs except x0")
            self.return_fp = fp_state(engine)
            require(self.return_fp == self.pre_fp, "bridge did not restore all Q registers and FP controls")
            # BLR sets transient BTYPE=2 on BTI-capable CPU_MAX; the first
            # ordinary callee instruction consumes it and RET returns BTYPE=0.
            # This is independently reproduced by a plain BLR/STR/RET control.
            # Assert that transition explicitly; every other PSTATE bit and
            # all system/stack registers must still match exactly.
            entry_btype = (self.pre["pstate"] >> 10) & 3
            return_btype = (self.post["pstate"] >> 10) & 3
            require(entry_btype == (2 if CPU_MODEL == ar.UC_CPU_ARM64_MAX else 0),
                    "unexpected caller BLR BTYPE")
            require(return_btype == 0, "return retained a transient BTYPE")
            expected_state, restored_state = dict(self.pre), dict(self.post)
            expected_state["pstate"] &= ~0xC00
            restored_state["pstate"] &= ~0xC00
            require(restored_state == expected_state, "bridge system register/stack restore differs outside BTYPE: " + str({k: [hex(expected_state[k]), hex(restored_state[k])] for k in expected_state if expected_state[k] != restored_state[k]}))
            require(bytes(engine.mem_read(self.context, 0x100)) == self.config_before, "bridge configuration changed")
            self.bridge_returned = True
            self.events.append({"event": "bridge_return", "status": now[0],
                                "entry_btype": entry_btype, "return_btype": return_btype,
                                "other_pstate_and_system_registers_exact": True})
        self.uc.hook_add(un.UC_HOOK_CODE, returned, begin=self.return_address, end=self.return_address)

    def kernel_code(self, engine, address, size, _):
        try:
            self._kernel_code(engine, address, size)
        except Exception as exc:
            self.fail(str(exc))

    def _kernel_code(self, engine, address, size):
        self.trace_counts[address] = self.trace_counts.get(address, 0) + 1
        if len(self.trace_first) < 80:
            self.trace_first.append(address)
        offset = address - (self.link if address >= self.link else self.kbase)
        startup_low = min(self.xc["XNU_ENTRY_OFFSET"], self.xc["XNU_HIGH_VECTORS_OFFSET"], self.xc["XNU_LOW_VECTORS_OFFSET"])
        startup_high = self.xc["XNU_COMMON_START_OFFSET"] + 0x1000
        blob_code_end = self.xc["XNU_BLOB_OFFSET"] + self.bs["mmu_bridge_context"]
        allowed = startup_low <= offset < startup_high or offset == self.xc["XNU_ARM_INIT_OFFSET"]
        allowed |= self.xc["XNU_BLOB_OFFSET"] <= offset < blob_code_end
        allowed |= any(low <= offset < high for low, high in self.kernel_helper_ranges)
        # After arm_init, permit execution in the declared early-C text window;
        # the bridge observer stops at the first PE_init_platform(FALSE,args) return.
        if self.arm_init_seen:
            allowed |= 0 <= offset < self.xc["XNU_FILE_SIZE"]

        require(allowed, f"unexpected XNU execution outside bounded startup: {address:#x}")
        if address == self.blob + self.bs["mmu_bridge_entry"]:
            self.bridge_enter()
        elif address == self.blob + self.bs["mmu_bridge_guard"]:
            self.guard_seen = True
            require(not engine.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"]) & 1, "guard entered after MMU enable")
            require(bytes(engine.mem_read(self.kbase + self.xc["XNU_BOOTSTRAP_OFFSET"], self.xc["XNU_BOOTSTRAP_BYTES"])) == self.expected_pool(), "original XNU table loops produced unexpected descriptors")
            self.events.append({"event": "table_guard", "pc": hex(address)})
            if self.case.bad_descriptor:
                m = self.x["bootstrap_expected_mutations"]
                at = m["high_L2_pa"] + m["high_L2_index_first"] * 8
                original = struct.unpack("<Q", engine.mem_read(at, 8))[0]
                self.table_patch = (at, original ^ (1 << 10))
                engine.mem_write(at, struct.pack("<Q", self.table_patch[1]))
                self.injections.append({"kind": "bad_descriptor_before_guard", "pa": hex(at), "original": hex(original), "changed": hex(self.table_patch[1])})
            if self.case.guard_budget:
                self.counter.ticks += FREQUENCY * 30
                self.injections.append({"kind": "counter_expired_at_table_guard"})
        elif address == self.blob + self.bs["mmu_bridge_after_mmu"]:
            self.after_mmu_seen = True
            require(engine.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"]) & 0x1005 == 0x1005, "native M/C/I did not enable")
            require(engine.cpr_read(*SYSTEM_REGISTERS["vbar_el1"]) == self.kbase + self.xc["XNU_LOW_VECTORS_OFFSET"], "high VBAR was installed before after-MMU helper")
            self.events.append({"event": "after_native_mmu", "pc": hex(address), "sctlr": hex(engine.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"]))})
        elif address == self.link + self.xc["XNU_ARM_INIT_OFFSET"]:
            self.arm_init_seen = True
            require(engine.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"]) & 1, "arm_init VA reached with MMU disabled")
            self.events.append({"event": "arm_init_virtual_entry", "pc": hex(address)})
        elif address in (self.blob + self.bs["mmu_bridge_fp_snapshot"], self.blob_va + self.bs["mmu_bridge_fp_snapshot"]):
            self.fp_seen = True
            require(self.arm_init_seen, "FP helper before arm_init")
            require(fp_state(engine) == self.pre_fp, "native startup changed FP before snapshot")
            self.events.append({"event": "native_fp_snapshot", "pc": hex(address)})
        elif address == self.blob_va + self.bs["mmu_bridge_observer"]:
            self.observer_seen = True
            require(self.arm_init_seen and self.after_mmu_seen, "observer reached without original high-VA startup")
            self.events.append({"event": "first_PE_init_platform_false_return", "pc": hex(address)})
        elif address == self.blob + self.bs["mmu_bridge_identity"]:
            self.identity_seen = True
            self.events.append({"event": "identity_return", "pc": hex(address), "sctlr": hex(engine.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"]))})
        if self.case.injected_fault:
            after = next(p for p in self.x["patches"] if p["bridge_symbol"] == "mmu_bridge_after_mmu")
            before_m = self.kbase + after["offset"] - 8
            if address == before_m and not any(i["kind"] == "injected_architectural_fault" for i in self.injections):
                self.inject_fault(address)

    def inject_fault(self, pc):
        state = registers(self.uc)
        require(not state["sctlr_el1"] & 1, "pre-MMU injected fault was too late")
        vector = state["vbar_el1"] + (0x200 if state["pstate"] & 1 else 0)
        require(state["vbar_el1"] == self.kbase + self.xc["XNU_LOW_VECTORS_OFFSET"], "injection has no physical low VBAR")
        esr, far = 0x96000004, 0xDEAD0000
        self.uc.cpr_write(*SYSTEM_REGISTERS["esr_el1"], esr)
        self.uc.cpr_write(*SYSTEM_REGISTERS["far_el1"], far)
        self.uc.cpr_write(*SYSTEM_REGISTERS["elr_el1"], pc)
        self.uc.cpr_write(*SYSTEM_REGISTERS["spsr_el1"], state["pstate"])
        self.uc.reg_write(ar.UC_ARM64_REG_PSTATE, (state["pstate"] & ~0xF) | 5 | 0x3C0)
        set_stack_banks(self.uc, state["sp_el0"], state["sp_el1"])
        self.uc.reg_write(ar.UC_ARM64_REG_PC, vector)
        self.injections.append({"kind": "injected_architectural_fault", "not_native_delivery": True,
                                "pc": hex(pc), "vector": hex(vector), "esr": hex(esr), "far": hex(far)})

    def run(self):
        started = time.monotonic()
        try:
            self.uc.emu_start(self.base, self.base + len(self.f.image), timeout=240_000_000, count=1_000_000_000)
        except (un.UcError, AssertionError) as exc:
            self.errors.append(str(exc))
        elapsed = time.monotonic() - started
        result = {"name": self.case.name, "case": self.case.__dict__, "passed": False,
                  "elapsed_host_seconds": round(elapsed, 3), "errors": self.errors, "native_faults": self.native_faults,
                  "stop": self.stop_reason, "events": self.events, "injections": self.injections,
                  "counter_model_reads": self.counter.reads, "modeled_counter_ticks": self.counter.ticks,
                  "pre_entry_segments_BSS_verified": self.pre_verified, "startup_memory_writes": self.runtime_writes,
                  "trace_first": [hex(x) for x in self.trace_first],
                  "trace_counts": {hex(k): v for k, v in sorted(self.trace_counts.items())},
                  "physical_mappings_only": [[hex(a), hex(b), p] for a, b, p in self.physical_regions]}
        if self.window_mapped and self.bridge_started:
            result["bridge_observed"] = {k: hex(v) for k, v in read_context(self.uc, self.context, self.h, "MMU_OBS_").items()}
        if self.pre is not None:
            result["pre_bridge_sysregs"] = {k: hex(v) for k, v in self.pre.items()}
        if self.post is not None:
            result["post_bridge_sysregs"] = {k: hex(v) for k, v in self.post.items()}
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
        before, after = tree_semantics(self.fdt_reader, self.dtb), tree_semantics(self.fdt_reader, tree)
        message = after["/chosen"].pop("renoace-probe-log")
        require(before == after, "unrelated FDT properties changed")
        vals = parse_message(message, self.b["build_id"])
        result["record"] = {"sha256": sha(message), "bytes": len(message), "fields": {k: hex(v) for k, v in vals.items()}, "origin": "instruction model, NOT phone"}
        expected = 8 if self.case.source_corrupt else 4 if self.case.reserved_conflict else 12 if self.case.remove_patch else 7 if self.case.budget else 18 if (self.case.bad_descriptor or self.case.guard_budget or self.case.injected_fault) else 0
        require(vals["xnu_status"] == expected, f"status {vals['xnu_status']} != {expected}")
        if expected == 0:
            require(self.pre_verified and self.bridge_returned and self.arm_init_seen and self.observer_seen and self.after_mmu_seen and self.identity_seen and self.fp_seen, "missing successful native-MMU/early-C checkpoints")
            require(vals["xnu_attempted"] == vals["xnu_returned"] == 1 and vals["mmu_status"] == self.h["MMU_STATUS_ARM_INIT"], "MMU success flags differ")
            require(vals["mmu_config_verified"] == vals["mmu_state_verified"] == vals["mmu_guard_passed"] == 1, "MMU verification failed")
            require(vals["mmu_guard_checks"] == self.x["bridge"]["guard_expected_pairs"], "guard-pair count differs")
            require(vals["mmu_tcr"] == self.xc["XNU_EXPECTED_TCR"] and vals["mmu_mair"] == self.xc["XNU_EXPECTED_MAIR"], "native translation registers differ")
            require(vals["mmu_observer_pc"] == self.blob_va + self.bs["mmu_bridge_observer"], "observer did not execute at expected high VA")
            require(vals["mmu_identity_pc"] == self.blob + self.bs["mmu_bridge_identity"], "return was not through identity alias")
            targets = {"mmu_par_code": self.blob + self.bs["mmu_bridge_observer"], "mmu_par_args": self.kbase + self.xc["XNU_ARGS_OFFSET"],
                       "mmu_par_sp0": self.kbase + self.xc["XNU_SP0_VA"] - self.link - 16,
                       "mmu_par_sp1": self.kbase + self.xc["XNU_SP1_VA"] - self.link - 16,
                       "mmu_par_identity": self.blob + self.bs["mmu_bridge_identity"]}
            for key, pa in targets.items():
                require(vals[key] & 1 == 0 and vals[key] & 0x0000FFFFFFFFF000 == pa & ~0xFFF, key + " native translation differs")
            require(vals.get("c_fp_saved") == 1 and vals.get("c_fp_verified") == 1, "FP/SIMD snapshot not restored")
            require(vals.get("c_pe_initialized") == 1 and vals.get("c_dt_initialized") == 1, "PE/DT globals not initialized")
            require(vals.get("c_soc_base") == 0 and vals.get("c_timebase_frequency") == FREQUENCY and vals.get("c_dec_clock_rate") == FREQUENCY, "early-C witness globals differ")
            require(vals.get("c_boot_args_global_verified") == 1, "constant boot_args/ADT globals differ")
            require(vals["xnu_x20"] == self.xc["XNU_EXPECTED_OBS_X20"] and vals["mmu_x30"] == self.xc["XNU_P11_FIQ_RETURN_VA"], "P11 checkpoint X20/LR differ")
            require(vals["mmu_sp_el0"] == self.xc["XNU_OBS_SP0_VA"] and vals["mmu_sp_el1"] == self.xc["XNU_OBS_SP1_VA"] and vals["mmu_spsel"] == 0, "checkpoint stack banks differ")
            adt_va = self.link + self.xc["XNU_ADT_OFFSET"]
            for name, wanted in {"c_pe_dt_head": adt_va, "c_pe_boot_args": self.xc["XNU_CONST_BOOT_ARGS_VA"], "c_pe_dt_size": len(self.adt),
                                 "c_dt_root": adt_va, "c_dt_size": len(self.adt), "c_dt_end": adt_va + len(self.adt)}.items():
                require(vals[name] == wanted, name + " differs")
            before_q = bytes(self.uc.mem_read(self.context + self.h["MMU_FP_Q_BEFORE"], 0x200))
            after_q = bytes(self.uc.mem_read(self.context + self.h["MMU_FP_Q_AFTER"], 0x200))
            wanted_q = b"".join(q.to_bytes(16, "little") for q in self.pre_fp["q"])
            require(before_q == after_q == wanted_q, "actual FP snapshot/readback differs from seeded 32-Q bank")
            for key in ("fpcr", "fpsr"):
                require(vals["c_" + key + "_before"] == vals["c_" + key + "_after"] == self.pre_fp[key], "actual " + key + " snapshot differs")
            result["fp_evidence"] = {
                "seeded_q": [hex(q) for q in self.pre_fp["q"]],
                "context_before_q": [hex(int.from_bytes(before_q[i:i + 16], "little")) for i in range(0, 0x200, 16)],
                "context_after_q": [hex(int.from_bytes(after_q[i:i + 16], "little")) for i in range(0, 0x200, 16)],
                "cpu_return_q": [hex(q) for q in self.return_fp["q"]],
            }
            for key in ("fpcr", "fpsr"):
                result["fp_evidence"].update({
                    "seeded_" + key: hex(self.pre_fp[key]),
                    "context_before_" + key: hex(vals["c_" + key + "_before"]),
                    "context_after_" + key: hex(vals["c_" + key + "_after"]),
                    "cpu_return_" + key: hex(self.return_fp[key]),
                })
            (self.report_dir / "model-record.bin").write_bytes(message)
            if CPU_NAME == "MAX":
                (self.f.directory / "model-record.bin").write_bytes(message)
        elif self.case.bad_descriptor or self.case.guard_budget:
            require(self.guard_seen and not self.after_mmu_seen and not self.arm_init_seen, "guard refusal crossed MMU boundary")
            require(vals["mmu_status"] == self.h["MMU_STATUS_TABLE_REFUSED"] and vals["mmu_guard_passed"] == 0 and self.bridge_returned, "table guard refusal did not return")
            if self.case.guard_budget:
                require(vals["mmu_budget_expired"] == 1, "guard deadline not witnessed")
        elif self.case.injected_fault:
            require(self.bridge_returned and not self.after_mmu_seen and not self.arm_init_seen, "injected pre-MMU fault did not return early")
            require(vals["mmu_status"] == self.h["MMU_STATUS_EXCEPTION"] and vals["mmu_fault_depth"] == 1, "injected vector result differs")
            require(vals["mmu_esr"] == 0x96000004 and vals["mmu_far"] == 0xDEAD0000, "injected ESR/FAR not captured")
        else:
            require(not self.bridge_started and vals["xnu_attempted"] == vals["xnu_returned"] == 0, "loader refusal entered XNU")
        if self.pre_verified:
            self.verify_kernel_memory(after_startup=self.guard_seen)
            require(equals_filled(self.uc, self.clean_end, self.kbase + self.kbytes - self.clean_end, 0xA5), "untouched high-window tail changed")
        reservations = reserve_entries(tree)
        expected_reservations = reserve_entries(self.dtb) + [(self.base + self.c["LINUX_EFFECTIVE_SIZE"], self.c["CHAIN_IMAGE_SIZE"] - self.c["LINUX_EFFECTIVE_SIZE"])]
        if vals["xnu_window_used"]:
            expected_reservations.append((self.kbase, self.kbytes))
        require(reservations == expected_reservations, "FDT reservation edits differ")
        result["post_startup_segments_BSS_verified"] = self.pre_verified
        result["linux_fdt_initrd_unchanged"] = True
        (self.report_dir / (self.case.name + ".bin")).write_bytes(message)


@dataclass(frozen=True)
class VMCase(Case):
    post_vm_fault: bool = False


class VMProduction(Machine):
    """Native packaged P07 path. The positive case performs no host mutations."""
    def __init__(self, fixture, case, report_dir):
        self.full_vm_return = False
        self.second_pe_return = False
        self.fiq_return_seen = False
        self.vm_final = None
        self.gate_seen = False
        self.gate_fault_seen = False
        self.allocation_high = 0
        self.allocation_pages = set()
        self.write_pages = set()
        self.write_text_sites = set()
        self.bootstrap_pool_guard = None
        self.post_vm_injected = False
        self.native_write_hook_proof = None
        super().__init__(fixture, case, report_dir)
        _, self.native_symbols = macho_inventory(fixture.macho)
        self.gate = self.x["bridge"]["gate"]
        self.gate_symbols = self.gate["symbols"]
        self.allowed_data_ranges = [(s["va"], s["va"] + s["mem"]) for s in self.x["segments"]
                                    if s["name"] in {"__DATA_CONST", "__LASTDATA_CONST", "__KLDDATA", "__DATA", "__BOOTDATA"}]
        # These are independently decoded original static-if patch sites. New
        # native execution must still write exactly one aligned instruction.
        self.static_if_text = {0xfffffff0073a4044, 0xfffffff0073a404c, 0xfffffff0073a4054,
                               0xfffffff0075172c0, 0xfffffff0075172cc, 0xfffffff0073a4084,
                               0xfffffff0073a408c, 0xfffffff0073a4094, 0xfffffff0075172dc,
                               0xfffffff0075172e8}
        self.uc.cpr_write(*SYSTEM_REGISTERS["cntkctl_el1"], 0x100)
        self.initial = registers(self.uc)
        self.initial_cntkctl = self.initial["cntkctl_el1"]
        _, adt_fields = validate_adt_fixture(self.adt)
        seed_at, seed_bytes = adt_fields["/chosen", "random-seed"]
        self.seed_wipe_range = (self.kbase + self.xc["XNU_ADT_OFFSET"] + seed_at,
                                self.kbase + self.xc["XNU_ADT_OFFSET"] + seed_at + seed_bytes)
        gate_binary = (fixture.directory / "vm_gate.bin").read_bytes()
        require(sha(gate_binary) == self.gate["sha256"], "P07 RX gate binary identity differs")
        require(len(gate_binary) == self.gate["bytes"], "P07 RX gate size differs")
        gate_off = self.gate["offset"]
        expected_gate = bytearray(fixture.macho[gate_off:gate_off + len(gate_binary)])
        for patch in self.x["patches"]:
            if gate_off <= patch["offset"] < gate_off + len(gate_binary):
                struct.pack_into("<I", expected_gate, patch["offset"] - gate_off, patch["replacement"])
            if patch.get("gate_symbol"):
                require(branch_target(patch["replacement"], self.link + patch["offset"]) == self.gate_symbols[patch["gate_symbol"]], "P07 RX gate branch target differs")
        require(bytes(expected_gate) == gate_binary, "embedded gate patch inventory differs from compiled gate")
        # The cache clean loop is still executed natively; only its Python
        # observation path is reduced to avoid a dict/list operation per line.
        code = self.bridge_binary[:self.bs["mmu_bridge_context"]]
        self.clean_loop = set()
        for at in range(0, len(code) - 12, 4):
            if struct.unpack_from("<I", code, at)[0] == 0xd50b7e2a:  # dc civac,x10
                self.clean_loop.update(self.blob + at + j for j in (0, 4, 8, 12))
        self.clean_instructions = 0

    def walk(self, root, va, high=True):
        tcr = self.uc.cpr_read(*SYSTEM_REGISTERS["tcr_el1"])
        bits = 64 - (((tcr >> 16) if high else tcr) & 63)
        require(30 < bits <= 39, "independent walker input width unsupported")
        if high:
            require((tcr >> 30) & 3 == 2, "independent walker requires TTBR1 4KiB")
        else:
            require((tcr >> 14) & 3 == 0, "independent walker requires TTBR0 4KiB")
        address = va & ((1 << bits) - 1)
        table = root & 0x0000fffffffff000
        entries = []
        pxnt = uxnt = apt = 0
        for level, shift in ((1, 30), (2, 21), (3, 12)):
            entry_pa = table + ((address >> shift) & 511) * 8
            require(self.kbase <= entry_pa < self.kbase + self.kbytes, "walk table outside mapped kernel RAM")
            word = int.from_bytes(self.uc.mem_read(entry_pa, 8), "little")
            entries.append({"level": level, "pa": hex(entry_pa), "value": hex(word)})
            if not word & 1:
                return {"valid": False, "descriptors": entries}
            if level < 3 and word & 2:
                pxnt |= (word >> 59) & 1; uxnt |= (word >> 60) & 1; apt |= (word >> 61) & 3
                table = word & 0x0000fffffffff000
                continue
            pa = (word & 0x0000fffffffff000 & ~((1 << shift) - 1)) | (address & ((1 << shift) - 1))
            return {"valid": True, "pa": pa, "leaf": word, "level": level,
                    "pxn": bool(pxnt or word & (1 << 53)), "uxn": bool(uxnt or word & (1 << 54)),
                    "ap": (word >> 6) & 3, "table_ap": apt, "descriptors": entries}
        raise AssertionError("walk ended without a leaf")

    def resolve_write(self, address):
        # In Unicorn2 native CPU/TLB mode this hook normally reports the PA
        # after hardware translation. Never reinterpret that PA as a TTBR0 VA.
        # Retain a STR base/address witness below to bind this runtime behavior.
        if self.kbase <= address < self.kbase + self.kbytes:
            return address
        if not self.uc.cpr_read(*SYSTEM_REGISTERS["sctlr_el1"]) & 1:
            return address
        high = address >= 1 << 63
        root = self.uc.cpr_read(*SYSTEM_REGISTERS["ttbr1_el1" if high else "ttbr0_el1"])
        translated = self.walk(root, address, high)
        require(translated["valid"], f"guest write has no independent native-root translation: {address:#x}")
        return translated["pa"]

    def kernel_write(self, engine, access, address, size, value, _):
        if not self.bridge_started or self.bridge_returned:
            return
        try:
            pa = self.resolve_write(address)
            last = self.resolve_write(address + size - 1)
            require(last == pa + size - 1, "guest store crosses noncontiguous PA mappings")
            if pa == self.kbase + self.xc["XNU_VM_KVA_ACTIVE_OFFSET"] and self.arm_init_seen:
                pc = engine.reg_read(ar.UC_ARM64_REG_PC)
                x8 = engine.reg_read(ar.UC_ARM64_REG_X8)
                guest_va = x8 + 0x40
                independent = self.walk(engine.cpr_read(*SYSTEM_REGISTERS["ttbr1_el1"]), guest_va)
                require(independent["valid"] and independent["pa"] == pa, "native write-hook PA witness differs from independent final-root translation")
                self.native_write_hook_proof = {"pc": hex(pc), "instruction": "str w24,[x8,#0x40]", "x8": hex(x8), "guest_va": hex(guest_va), "hook_address": hex(address), "independent_pa": hex(independent["pa"])}
            pool = self.kbase + self.xc["XNU_BOOTSTRAP_OFFSET"]
            allowed = pool <= pa and pa + size <= pool + self.xc["XNU_BOOTSTRAP_BYTES"]
            allowed |= self.context <= pa and pa + size <= self.context + self.h["MMU_BRIDGE_CONTEXT_BYTES"]
            if self.arm_init_seen:
                va = self.link + pa - self.kbase
                allowed |= any(lo <= va and va + size <= hi for lo, hi in self.allowed_data_ranges)
                allowed |= self.seed_wipe_range[0] <= pa and pa + size <= self.seed_wipe_range[1]
                allowed |= va in self.static_if_text and size == 4
                if va in self.static_if_text:
                    self.write_text_sites.add(va)
                if self.clean_end <= pa and pa + size <= self.xc["XNU_VM_MAX_ALLOC_PA"]:
                    allowed = True
                    self.allocation_high = max(self.allocation_high, pa + size)
                    self.allocation_pages.add(pa & ~4095)
            require(allowed, f"guest write exceeds kernel/global/allocation contract PA={pa:#x} VA={address:#x}+{size} PC={engine.reg_read(ar.UC_ARM64_REG_PC):#x}")
            self.runtime_writes += 1
            self.write_pages.add(pa & ~4095)
        except Exception as exc:
            self.fail(str(exc))

    def install_hooks(self):
        u = self.uc
        u.hook_add(un.UC_HOOK_MEM_INVALID, self.invalid)
        u.hook_add(un.UC_HOOK_INTR, self.interrupt)
        u.hook_add(un.UC_HOOK_MEM_WRITE, self.protect_linux, begin=self.base, end=self.base + self.c["LINUX_EFFECTIVE_SIZE"] - 1)
        u.hook_add(un.UC_HOOK_MEM_WRITE, self.kernel_write)
        if self.window_mapped:
            u.hook_add(un.UC_HOOK_CODE, self.kernel_code, begin=self.kbase, end=self.kbase + self.kbytes - 1)
            u.hook_add(un.UC_HOOK_CODE, self.kernel_code, begin=self.link, end=self.link + self.kbytes - 1)
        def linux(engine, address, size, _):
            if not self.first_linux:
                self.first_linux = True
            else:
                self.stop_reason = "restored-linux-entry"; engine.emu_stop()
        u.hook_add(un.UC_HOOK_CODE, linux, begin=self.base, end=self.base)
        for address in (self.base + self.s["chain_park"], self.blob + self.bs["mmu_bridge_park"], self.blob_va + self.bs["mmu_bridge_park"]):
            u.hook_add(un.UC_HOOK_CODE, lambda *args: self.fail("unexpected park"), begin=address, end=address)
        if self.case.remove_patch:
            def remove(engine, address, size, _):
                patch = next(q for q in self.x["patches"] if q["offset"] == self.xc["XNU_ARM_INIT_OFFSET"])
                engine.mem_write(self.kbase + patch["offset"], struct.pack("<I", patch["original"]))
                self.injections.append({"kind": "remove_private_arm_init_patch", "pa": hex(self.kbase + patch["offset"])})
            u.hook_add(un.UC_HOOK_CODE, remove, begin=self.base + self.s["xnu_validate_gate"], end=self.base + self.s["xnu_validate_gate"])

    def _kernel_code(self, engine, address, size):
        if address in self.clean_loop:
            self.clean_instructions += 1
            return
        super()._kernel_code(engine, address, size)
        if address == self.blob + self.bs["mmu_bridge_guard"]:
            self.bootstrap_pool_guard = bytes(engine.mem_read(self.kbase + self.xc["XNU_BOOTSTRAP_OFFSET"], self.xc["XNU_BOOTSTRAP_BYTES"]))
        elif address == self.link + self.xc["XNU_CHECKPOINT_OFFSET"]:
            self._record_vm_return(engine, address, "native_full_vm_return")
        elif address == self.gate_symbols["mmu_vm_gate_checkpoint"]:
            phase_offset = self.h.get("P11_PHASE")
            require(phase_offset is not None, "P11 phase offset missing from bridge ABI")
            phase = int.from_bytes(engine.mem_read(self.context + phase_offset, 8), "little")
            self.gate_seen = True
            if phase == 0:
                require(self.full_vm_return, "phase-0 RX gate reached before VM return checkpoint")
                self.events.append({"event": "compiled_RX_gate_checkpoint", "pc": hex(address), "phase": phase})
            elif phase == 1:
                if not self.second_pe_return:
                    self.second_pe_return = True
                self.events.append({"event": "second_PE_true_return", "pc": hex(self.xc["XNU_P11_SECOND_PE_VA"]),
                                    "gate_pc": hex(address), "x19": hex(engine.reg_read(ar.UC_ARM64_REG_X19)),
                                    "x20": hex(engine.reg_read(ar.UC_ARM64_REG_X20)), "phase": phase})
            elif phase == 2:
                require(not self.fiq_return_seen, "fiq_context_init return gate executed twice")
                self.fiq_return_seen = True
                self.events.append({"event": "fiq_context_init_return", "pc": hex(self.xc["XNU_P11_FIQ_RETURN_VA"]),
                                    "gate_pc": hex(address), "phase": phase})
            else:
                raise AssertionError("unexpected P11 gate phase: " + str(phase))
        elif address == self.xc["XNU_P11_SECOND_PE_VA"]:
            require(not self.second_pe_return, "second PE return executed twice")
            self.second_pe_return = True
            self.events.append({"event": "second_PE_true_return", "pc": hex(address), "x19": hex(engine.reg_read(ar.UC_ARM64_REG_X19)), "x20": hex(engine.reg_read(ar.UC_ARM64_REG_X20))})
        elif address == self.gate_symbols["mmu_vm_gate_fault_0"]:
            self.gate_fault_seen = True
            self.events.append({"event": "compiled_RX_gate_fault_0", "pc": hex(address)})

    def _record_vm_return(self, engine, address, event_name):
        require(not self.full_vm_return, "full VM checkpoint executed twice")
        self.full_vm_return = True
        state = registers(engine)
        root = state["ttbr1_el1"]
        self.vm_final = {"pc": hex(address), "sysregs": {k: hex(v) for k, v in state.items()},
                         "gprs": {"x" + str(i): hex(engine.reg_read(getattr(ar, "UC_ARM64_REG_X" + str(i)))) for i in (0, 19, 20, 21, 29, 30)},
                         "gate": self.walk(root, self.xc["XNU_VM_GATE_NORMAL_VA"]),
                         "observer": self.walk(root, self.blob_va + self.bs["mmu_bridge_observer"]),
                         "context": self.walk(root, self.blob_va + self.bs["mmu_bridge_context"]),
                         "bootstrap_pool_unchanged": self.bootstrap_pool_guard == bytes(engine.mem_read(self.kbase + self.xc["XNU_BOOTSTRAP_OFFSET"], self.xc["XNU_BOOTSTRAP_BYTES"]))}
        self.events.append({"event": event_name, "pc": hex(address), "ttbr0": hex(state["ttbr0_el1"]), "ttbr1": hex(root)})

    def inject_post_vm_fault(self, pc):
        state = registers(self.uc)
        require(state["sctlr_el1"] & 1 and state["ttbr1_el1"] == self.xc["XNU_VM_CPU_ROOT_PA"], "post VM synthetic fault has wrong native MMU state")
        vector = state["vbar_el1"] + (0x200 if state["pstate"] & 1 else 0)
        esr, far = 0x96000004, 0xDEAD0000
        for name, value in (("esr_el1", esr), ("far_el1", far), ("elr_el1", pc), ("spsr_el1", state["pstate"])):
            self.uc.cpr_write(*SYSTEM_REGISTERS[name], value)
        self.uc.reg_write(ar.UC_ARM64_REG_PSTATE, (state["pstate"] & ~0xF) | 5 | 0x3C0)
        set_stack_banks(self.uc, state["sp_el0"], state["sp_el1"])
        self.uc.reg_write(ar.UC_ARM64_REG_PC, vector)
        self.post_vm_injected = True
        self.injections.append({"kind": "synthetic_post_VM_architectural_exception_state", "native_delivery": False,
                                "pc": hex(pc), "vector": hex(vector), "esr": hex(esr), "far": hex(far), "native_final_root_retained": True})

    def verify(self, result):
        require(not self.errors, str(self.errors))
        require(self.stop_reason == "restored-linux-entry", "did not return to restored Linux entry")
        require(bytes(self.uc.mem_read(self.base, len(self.f.linux))) == self.f.linux, "original Linux bytes changed")
        require(bytes(self.uc.mem_read(self.dtb_pa, len(self.dtb))) == self.dtb, "incoming FDT changed")
        require(bytes(self.uc.mem_read(self.initrd_pa, len(self.initrd))) == self.initrd, "source initrd changed")
        final = registers(self.uc)
        for key in ("sp_el0", "sp_el1", "sctlr_el1", "tcr_el1", "ttbr0_el1", "ttbr1_el1", "mair_el1", "vbar_el1", "cntkctl_el1"):
            require(final[key] == self.initial[key], "outer return fixture differs: " + key)
        require(all(self.uc.reg_read(getattr(ar, "UC_ARM64_REG_X" + str(i))) == 0 for i in (1, 2, 3)), "Linux arguments x1-x3 not cleared")
        ptr = self.uc.reg_read(ar.UC_ARM64_REG_X0)
        require(ptr == self.base + self.c["DTB_OFFSET"], "Linux FDT pointer differs")
        size = struct.unpack(">I", self.uc.mem_read(ptr + 4, 4))[0]
        tree = bytes(self.uc.mem_read(ptr, size))
        before, after = tree_semantics(self.fdt_reader, self.dtb), tree_semantics(self.fdt_reader, tree)
        message = after["/chosen"].pop("renoace-probe-log")
        require(before == after, "unrelated FDT fields changed")
        vals = parse_message(message, self.b["build_id"])
        result["record"] = {"sha256": sha(message), "bytes": len(message), "fields": {k: hex(v) for k, v in vals.items()}, "origin": "native instruction model; NOT phone"}
        expected = 8 if self.case.source_corrupt else 4 if self.case.reserved_conflict else 12 if self.case.remove_patch else 7 if self.case.budget else 18 if (self.case.bad_descriptor or self.case.guard_budget or self.case.injected_fault or self.case.post_vm_fault) else 0
        require(vals["xnu_status"] == expected, f"C status {vals['xnu_status']} != {expected}")
        result.update(full_arm_vm_init_return=self.full_vm_return, vm_final=self.vm_final,
                      actual_allocation_high=hex(self.allocation_high), allocation_pages=len(self.allocation_pages),
                      tracked_write_pages=len(self.write_pages), tracked_text_sites=[hex(x) for x in sorted(self.write_text_sites)],
                      caller_state_exact=self.bridge_returned if self.bridge_started else None,
                      FP_SIMD_exact=self.bridge_returned if self.bridge_started else None,
                      CNTKCTL_exact=final["cntkctl_el1"] == self.initial_cntkctl,
                      native_cache_clean_instructions=self.clean_instructions)
        result["native_memory_write_hook_semantics"] = self.native_write_hook_proof
        if expected == 0:
            require(not self.injections, "positive case contains host injection")
            require(self.full_vm_return and self.second_pe_return and self.fiq_return_seen and self.gate_seen and self.observer_seen and self.identity_seen and self.bridge_returned, "missing P11 full VM/second PE/FIQ gate/recovery checkpoints")
            require(vals["vm_verified"] == 1 and vals["vm_gate_entered"] == vals["vm_gate_completed"] == 1, "compiled C did not verify VM witnesses")
            require(vals["vm_ttbr0"] == self.xc["XNU_VM_INVALID_ROOT_PA"] and vals["vm_ttbr1"] == self.xc["XNU_VM_CPU_ROOT_PA"], "VM native roots differ")
            require(vals["vm_restored_ttbr0"] == vals["mmu_guard_ttbr0"] and vals["vm_restored_ttbr1"] == vals["mmu_guard_ttbr1"], "RX gate did not restore guarded bootstrap roots")
            require(vals["vm_soc_valid"] == 1 and vals["c_soc_base"] == 0 and vals["c_timebase_frequency"] == vals["c_dec_clock_rate"] == FREQUENCY, "new source zero-base clock witnesses differ")
            require(self.vm_final["bootstrap_pool_unchanged"], "bootstrap recovery pool changed during VM")
            require(self.vm_final["gate"]["valid"] and not self.vm_final["gate"]["pxn"] and self.vm_final["gate"]["ap"] == 2, "independent final-root gate walk is not RX")
            require(self.vm_final["observer"]["valid"] and self.vm_final["observer"]["pxn"] and self.vm_final["observer"]["ap"] == 0, "independent final-root blob walk is not RWNX")
            avail = vals["vm_first_avail"]
            require(self.clean_end < avail <= self.xc["XNU_VM_MAX_ALLOC_PA"] and not avail & 4095, "final allocation bound/alignment differs")
            require(self.allocation_high <= avail, "native writes passed final first_avail")
            require(equals_filled(self.uc, avail, self.kbase + self.kbytes - avail, 0xA5), "physical bytes above first_avail changed")
            before_q = bytes(self.uc.mem_read(self.context + self.h["MMU_FP_Q_BEFORE"], 0x200))
            after_q = bytes(self.uc.mem_read(self.context + self.h["MMU_FP_Q_AFTER"], 0x200))
            wanted_q = b"".join(q.to_bytes(16, "little") for q in self.pre_fp["q"])
            require(before_q == after_q == wanted_q, "all 32 independent Q snapshots differ")
            require(self.pre_fp == self.return_fp, "CPU FP/SIMD bank/control return differs")
            require(vals["vm_saved_cntkctl"] == vals["restored_cntkctl"] == self.initial_cntkctl and vals["vm_cntkctl"] != self.initial_cntkctl, "CNTKCTL save/change/restore witnesses differ")
            require(vals["xnu_x20"] == self.xc["XNU_EXPECTED_OBS_X20"] and vals["xnu_x21"] == self.xc["XNU_EXPECTED_OBS_X21"] and vals["mmu_x30"] == self.xc["XNU_P11_FIQ_RETURN_VA"], "P11 post VM X20/X21/LR differ")
            require(vals["xnu_timer_restore_valid"] == 1 and
                    vals["xnu_cntv_cval_before"] == vals["xnu_cntv_cval_after"] and
                    vals["xnu_cntp_cval_before"] == vals["xnu_cntp_cval_after"] and
                    (vals["xnu_cntv_ctl_before"] & 3) == (vals["xnu_cntv_ctl_after"] & 3) and
                    (vals["xnu_cntp_ctl_before"] & 3) == (vals["xnu_cntp_ctl_after"] & 3) and
                    (vals["xnu_timer_daif_at_restore"] & 0x3c0) == 0x3c0 and
                    (vals["xnu_timer_daif_during"] & 0x3c0) == 0x3c0,
                    "P11 timer state restoration witnesses differ")
            result["positive_injections"] = []
            result["physical_tail_after_first_avail_untouched"] = True
            result["FP_SIMD_evidence"] = {"q_before_sha256": sha(before_q), "q_after_sha256": sha(after_q), "seeded_sha256": sha(wanted_q), "fpcr": hex(self.pre_fp["fpcr"]), "fpsr": hex(self.pre_fp["fpsr"])}
            (self.f.directory / "model-record.bin").write_bytes(message)
        elif self.case.post_vm_fault:
            require(self.full_vm_return and self.post_vm_injected and self.gate_fault_seen and self.identity_seen and self.bridge_returned, "synthetic final-root exception did not pass compiled RX recovery gate")
            require(vals["mmu_status"] == self.h["MMU_STATUS_EXCEPTION"] and vals["mmu_fault_depth"] == 1 and vals["mmu_esr"] == 0x96000004 and vals["mmu_far"] == 0xDEAD0000, "post VM fault capture differs")
            require(vals["vm_ttbr1"] == self.xc["XNU_VM_CPU_ROOT_PA"] and vals["vm_restored_ttbr1"] == vals["mmu_guard_ttbr1"], "post VM synthetic exception bypassed final-root recovery")
        elif self.case.bad_descriptor or self.case.guard_budget:
            require(self.guard_seen and not self.after_mmu_seen and self.bridge_returned and vals["mmu_status"] == self.h["MMU_STATUS_TABLE_REFUSED"], "guard refusal crossed MMU boundary")
        elif self.case.injected_fault:
            require(self.bridge_returned and not self.after_mmu_seen and vals["mmu_status"] == self.h["MMU_STATUS_EXCEPTION"], "synthetic pre-MMU exception failed to return")
        else:
            require(not self.bridge_started and vals["xnu_attempted"] == vals["xnu_returned"] == 0, "loader refusal entered XNU")
        reservations = reserve_entries(tree)
        wanted = reserve_entries(self.dtb) + [(self.base + self.c["LINUX_EFFECTIVE_SIZE"], self.c["CHAIN_IMAGE_SIZE"] - self.c["LINUX_EFFECTIVE_SIZE"])]
        if vals["xnu_window_used"]: wanted.append((self.kbase, self.kbytes))
        require(reservations == wanted, "FDT reservation map differs")
        (self.report_dir / (self.case.name + ".bin")).write_bytes(message)


def main():
    global CPU_MODEL, CPU_NAME
    parser = argparse.ArgumentParser(description="P11 packaged second PE return; no phone operations")
    parser.add_argument("--build", type=Path, default=ROOT / "out/xnu-vm-probe")
    parser.add_argument("--case", help="single case, partial report only")
    args = parser.parse_args()
    test_source_start_sha256 = sha(Path(__file__).read_bytes())
    CPU_MODEL = ar.UC_CPU_ARM64_MAX; CPU_NAME = "MAX"
    fixture = Fixture.load(args.build)
    cases = [VMCase("positive_native_second_pe")]
    if args.case:
        cases = [c for c in cases if c.name == args.case]; require(cases, "unknown case")
    output = args.build / "model-tests/max"; output.mkdir(parents=True, exist_ok=True)
    results = []
    for case in cases:
        print("RUN " + case.name, flush=True)
        result = VMProduction(fixture, case, output).run(); results.append(result)
        (output / (case.name + ".json")).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(("PASS " if result["passed"] else "FAIL ") + case.name + " " + json.dumps({k: result.get(k) for k in ("elapsed_host_seconds", "errors", "verification_failure", "full_arm_vm_init_return")}), flush=True)
        if not result["passed"]: break
    positive = next((r for r in results if r["name"] == "positive_native_second_pe"), {})
    report = {"passed": not args.case and bool(results) and all(r["passed"] for r in results), "partial": bool(args.case),
              "build_id": fixture.build["build_id"], "image_sha256": fixture.build["image_sha256"], "source_hashes": fixture.build["source_hashes"],
              "test_source_sha256": test_source_start_sha256, "dependency_hashes": dependency_hashes(), "hardware_tested": False,
              "cpu_model": "MAX", "native_mmu": True, "full_arm_vm_init_return": positive.get("full_arm_vm_init_return", False),
              "translation_register_hooks": False, "virtual_alias_api_mappings": False,
              "positive_injections": positive.get("injections", []),
              "negative_cases_passed": len([r for r in results if r["name"] != "positive_native_second_pe" and r["passed"]]) == 8,
              "caller_state_exact": positive.get("caller_state_exact", False), "FP_SIMD_exact": positive.get("FP_SIMD_exact", False),
              "CNTKCTL_exact": positive.get("CNTKCTL_exact", False), "cases": results,
              "modeled_not_verified": ["CNTVCT progression/performance", "MAX model CPU differs from phone; phone LSE/ISA verification separate", "cache/coherency", "firmware memory ownership", "exception delivery is synthetic only in labelled negative cases"],
              "scope": "actual compiled P07 loader, original XNU startup/early C/full arm_vm_init, compiled RX recovery gate, native root restore and caller/FP/SIMD/CNTKCTL recovery"}
    path = args.build / (("partial-" + args.case + ".json") if args.case else "native-p11-tests.json")
    require(sha(Path(__file__).read_bytes()) == test_source_start_sha256, "test source changed while model ran; rerun")
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if results and all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

