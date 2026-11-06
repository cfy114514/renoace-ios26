#!/usr/bin/env python3
"""Prepare an OFFLINE, EARLY-ENTRY-ONLY XNU load plan; never boot or patch it.

Outputs JSON, a minimal generated ADT, and a boot_args structure. No kernel
copy, Android image, loader, partition write, or phone operation is produced.
The unchanged candidate still has timer INTID 27. A future bounded probe must
implement a stop before IOKit/CPU registration; this tool does not install it.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KERNEL = ROOT / "out/analysis/xnu-candidate/extracted/zeta/kernel/mach.development.bcm2837.unstripped.noctf"
KERNEL_SHA256 = "c973fe6cf1f039781972b580a9423613effd08806e66bd88ac5a2d2a9e3ef0fb"
ADT_HELPER_SHA256 = "43d91d2e4fb0a78190a610b4bab7c206489cdede797bfc37175fb2f18367ac00"
PAGE, BLOCK, ARGS_BYTES, SEED_BYTES = 0x1000, 0x200000, 0x480, 256
U64_MAX = (1 << 64) - 1
COMMAND_LINE = ("-v serial=0 keepsyms=1 cpus=1 sheng-smp=0 armcpu-skip-gic=1 "
                "native-ufs-probe=0 native-ufs-root=0 boot-progress=0 "
                "offline-mobile-graphics-load=0")
FORBIDDEN_PROPS = {"serial-device", "unixnu,dwc3-console", "unixnu,qcom-usb0",
                   "RAMDisk", "PackedRAMDisk", "TrustCache", "root-matching"}


class InvalidControl(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidControl(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def aligned(value, alignment):
    return (value + alignment - 1) & -alignment


def extent(start, size, limit, label):
    require(isinstance(start, int) and not isinstance(start, bool) and
            isinstance(size, int) and not isinstance(size, bool), label + ": not integers")
    require(0 <= start <= limit and 0 <= size <= limit - start,
            label + ": range overflow or out of bounds")
    return start + size


def integer(value):
    require(isinstance(value, (int, str)) and not isinstance(value, bool), "address must be an integer or string")
    return int(value, 0) if isinstance(value, str) else int(value)


def parse_macho(data):
    """Validate the actual Mach-O layout without trusting a previous report."""
    require(32 <= len(data) <= 128 * 1024 * 1024, "kernel size outside 32 B..128 MiB")
    magic, cpu, subtype, kind, count, size, flags, _ = struct.unpack_from("<8I", data)
    require((magic, cpu, subtype, kind) == (0xFEEDFACF, 0x100000C, 0, 2),
            "require a thin little-endian plain ARM64 Mach-O executable")
    require(0 < count <= 512 and size <= len(data) - 32, "invalid load-command bounds")
    cursor, commands_end = 32, 32 + size
    segments, sections, symtables, entries = [], [], [], []
    for _ in range(count):
        require(cursor + 8 <= commands_end, "truncated load command")
        command, length = struct.unpack_from("<II", data, cursor)
        require(length >= 8 and length % 8 == 0 and length <= commands_end - cursor,
                "invalid load-command size")
        if command == 0x19:
            require(length >= 72, "truncated segment command")
            va, memory_bytes, file_offset, file_bytes, maximum, protection, nsects, _ = struct.unpack_from("<4Q4I", data, cursor + 24)
            name_raw = data[cursor + 8:cursor + 24]
            name = name_raw.split(b"\0", 1)[0].decode("ascii")
            require(length == 72 + nsects * 80, "segment section-table size mismatch")
            require(file_bytes <= memory_bytes, name + ": file extent exceeds memory extent")
            extent(va, memory_bytes, U64_MAX, name + " memory")
            extent(file_offset, file_bytes, len(data), name + " file")
            require(0 <= protection <= maximum <= 7 and protection & ~maximum == 0,
                    name + ": invalid protections")
            if memory_bytes:
                require(va % PAGE == 0, name + ": unaligned virtual base")
            else:
                require(file_bytes == 0, name + ": empty memory has file data")
            segment = dict(name=name, va=va, memory_bytes=memory_bytes, file_offset=file_offset,
                           file_bytes=file_bytes, protection=protection, command_offset=cursor)
            segments.append(segment)
            for i in range(nsects):
                at = cursor + 72 + i * 80
                section_name = data[at:at + 16].split(b"\0", 1)[0].decode("ascii")
                address, length_bytes, offset, alignment, reloc_offset, reloc_count, section_flags = struct.unpack_from("<QQ5I", data, at + 32)
                end = extent(address, length_bytes, U64_MAX, section_name + " memory")
                require(va <= address and end <= va + memory_bytes,
                        section_name + ": section is outside its segment")
                require(alignment <= 31, section_name + ": unreasonable alignment")
                if length_bytes:
                    require(address % (1 << alignment) == 0, section_name + ": misaligned section")
                zero_fill = section_flags & 0xFF in (1, 0xC, 0x12)
                if not zero_fill and length_bytes:
                    file_end = extent(offset, length_bytes, len(data), section_name + " file")
                    require(file_offset <= offset and file_end <= file_offset + file_bytes,
                            section_name + ": file extent leaves its segment")
                    require(address - va == offset - file_offset,
                            section_name + ": inconsistent file/virtual mapping")
                extent(reloc_offset, reloc_count * 8, len(data), section_name + " relocations")
                sections.append(dict(name=section_name, zero_fill=zero_fill, address=address,
                                     bytes=length_bytes, segment=name))
        elif command == 5:
            require(length == 288, "unexpected ARM64 thread-command size")
            flavor, words = struct.unpack_from("<II", data, cursor + 8)
            require((flavor, words) == (6, 68), "unexpected ARM64 thread-state flavor")
            entries.append(struct.unpack_from("<Q", data, cursor + 272)[0])
        elif command == 2:
            require(length == 24, "invalid symbol-table command")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, cursor + 8)
            extent(symoff, nsyms * 16, len(data), "symbol table")
            extent(stroff, strsize, len(data), "string table")
            symtables.append((symoff, nsyms, stroff, strsize))
        cursor += length
    require(cursor == commands_end, "load commands do not consume sizeofcmds")
    require(len(entries) == 1 and entries[0] % 4 == 0, "require one aligned LC_UNIXTHREAD entry")
    live = sorted((s for s in segments if s["memory_bytes"]), key=lambda s: s["va"])
    require(live and len(live) <= 64, "invalid segment count")
    for left, right in zip(live, live[1:]):
        require(left["va"] + left["memory_bytes"] <= right["va"], "overlapping memory segments")
    backed = sorted((s for s in segments if s["file_bytes"]), key=lambda s: s["file_offset"])
    for left, right in zip(backed, backed[1:]):
        require(left["file_offset"] + left["file_bytes"] <= right["file_offset"], "overlapping file segments")
    entry = entries[0]
    entry_segment = next((s for s in live if s["protection"] & 4 and
                          s["va"] <= entry < s["va"] + s["file_bytes"]), None)
    require(entry_segment is not None, "entry is not in a file-backed executable segment")
    entry_file_offset = entry_segment["file_offset"] + entry - entry_segment["va"]
    entry_word = struct.unpack_from("<I", data, entry_file_offset)[0]
    require(entry_word & 0xFC000000 == 0x14000000, "candidate entry is not its original B instruction")
    symbols = {}
    wanted = {"__start", "_start_first_cpu", "_arm_init", "_PE_init_iokit"}
    for symoff, nsyms, stroff, strsize in symtables:
        strings = data[stroff:stroff + strsize]
        for i in range(nsyms):
            nameoff, symbol_type, section, _, address = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
            require(nameoff < strsize, "symbol name is outside string table")
            end = strings.find(b"\0", nameoff)
            require(end != -1, "unterminated symbol name")
            require(section <= len(sections), "invalid symbol section index")
            if symbol_type & 0xE == 0xE and section:
                name = strings[nameoff:end].decode("utf-8", "replace")
                if name in wanted:
                    require(name not in symbols or symbols[name] == address, "ambiguous checkpoint symbol")
                    symbols[name] = address
    require(symbols.get("__start") == entry and "_arm_init" in symbols,
            "required entry/arm_init symbols are absent or inconsistent")
    return dict(base=live[0]["va"], end=max(s["va"] + s["memory_bytes"] for s in live),
                entry=entry, entry_file_offset=entry_file_offset, entry_word=entry_word,
                segments=segments, sections=sections, symbols=symbols, flags=flags)


def hardware_ranges(hardware):
    identity = hardware.get("identity", {})
    require((identity.get("model"), identity.get("device"), str(identity.get("project"))) ==
            ("PCLM10", "OP4A89", "19081"), "not the measured Reno Ace profile")
    def one(record, label):
        start, size = integer(record["address"]), integer(record["size"])
        require(size > 0, label + ": empty range")
        return start, extent(start, size, U64_MAX, label)
    banks = sorted(one(r, "RAM bank") for r in hardware["memory"]["banks"])
    require(banks, "profile has no RAM banks")
    require(all(a[1] <= b[0] for a, b in zip(banks, banks[1:])), "RAM banks overlap")
    reservations = [one(r, row["node"]) for row in hardware["memory"]["reservations"] for r in row["ranges"]]
    return banks, reservations


def select_window(banks, reservations, size, residue, requested=None):
    require(0x10000000 <= size <= 0x40000000 and size % BLOCK == 0,
            "control window must be 256 MiB..1 GiB in 2 MiB increments")
    def valid(start):
        end = extent(start, size, U64_MAX, "candidate RAM window")
        return (start % BLOCK == residue and any(a <= start and end <= b for a, b in banks)
                and not any(start < b and a < end for a, b in reservations))
    if requested is not None:
        require(valid(requested), "requested PA window conflicts with RAM, reservations or 2 MiB congruence")
        return requested
    for bank_start, bank_end in reversed(banks):
        free = [(bank_start, bank_end)]
        for reserved_start, reserved_end in sorted(reservations):
            remaining = []
            for start, end in free:
                if reserved_end <= start or reserved_start >= end:
                    remaining.append((start, end))
                else:
                    if start < reserved_start:
                        remaining.append((start, reserved_start))
                    if reserved_end < end:
                        remaining.append((reserved_end, end))
            free = remaining
        for start, end in free:
            candidate = aligned(start - residue, BLOCK) + residue
            if candidate + size <= end and valid(candidate):
                return candidate
    raise InvalidControl("no suitable window in measured banks after reservations")


def adt_helper():
    path = ROOT / "references/ios-flame/tools/adt.py"
    require(digest(path.read_bytes()) == ADT_HELPER_SHA256, "pinned ios-flame ADT serializer changed")
    spec = importlib.util.spec_from_file_location("pinned_flame_adt", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nvram_proxy():
    """Build an empty volatile CHRP bank, following the open zeta generator."""
    image = bytearray(8192)
    def partition(offset, label, length):
        raw = bytearray(struct.pack("<BBH12s", 0x70, 0, length // 16, label))
        total = sum(raw)
        while total > 255:
            total = (total & 255) + (total >> 8)
        raw[1] = total
        image[offset:offset + 16] = raw
    partition(0, b"nvram", 32)
    partition(32, b"common", 16 + 2048)
    partition(2096, b"free", len(image) - 2096)
    struct.pack_into("<I", image, 16, zlib.adler32(image[20:]))
    return image


def generate_adt(physical_base, memory_size, timer_hz):
    adt = adt_helper()
    def node(name, props=(), children=()):
        result = adt.Node()
        result.props = [("name", 0, name.encode("ascii") + b"\0")]
        for key, data in props:
            require(0 < len(key.encode("ascii")) < 32, "ADT property name must fit with terminator")
            result.props.append((key, 0, bytes(data)))
        result.children = list(children)
        return result
    u32, u64 = lambda x: struct.pack("<I", x), lambda x: struct.pack("<Q", x)
    seed = os.urandom(SEED_BYTES)
    nvram = nvram_proxy()
    root = node("device-tree", [("model", b"OPPO Reno Ace early-entry control\0"),
                                ("compatible", b"oppo,renoace\0qcom,sm8150\0")], [
        node("chosen", [("random-seed", seed), ("kernel-ctrr-to-be-enabled", u32(0)),
                        ("dram-base", u64(physical_base)), ("dram-size", u64(memory_size)),
                        ("darwinboot-memory-size", u64(memory_size)),
                        ("nvram-bank-size", u32(len(nvram))), ("nvram-bank-count", u32(1)),
                        ("nvram-current-bank", u32(0)), ("nvram-proxy-data", nvram)]),
        node("cpus", children=[node("cpu0", [("device_type", b"cpu\0"), ("state", b"running\0"),
                                            ("reg", u32(0)), ("compatible", b"qcom,kryo\0"),
                                            ("timebase-frequency", u32(timer_hz))])]),
        node("defaults", [("sleep-disabled", u32(1))]), node("options"),
        # Intentionally no intc/USB/UFS/GPU/input child. This is not a full boot tree.
        node("arm-io", [("device_type", b"arm-io\0")]),
    ])
    return adt.serialize(root)


def parse_adt_independently(data):
    """Strict bounded reader, independent of the imported serializer/parser."""
    def read(offset, parent, depth):
        require(depth <= 16 and offset + 8 <= len(data), "ADT node is truncated/deep")
        prop_count, child_count = struct.unpack_from("<II", data, offset)
        offset += 8
        require(prop_count <= 64 and child_count <= 64, "ADT count exceeds control bounds")
        props = {}
        for _ in range(prop_count):
            require(offset + 36 <= len(data), "ADT property header truncated")
            raw = data[offset:offset + 32]
            require(b"\0" in raw, "ADT property name lacks terminator")
            key = raw.split(b"\0", 1)[0].decode("ascii")
            length = struct.unpack_from("<I", data, offset + 32)[0]
            require(key and key not in props and length < 0x80000000, "ADT duplicate/placeholder property")
            offset += 36
            end = extent(offset, length, len(data), "ADT property")
            padded = aligned(end, 4)
            require(padded <= len(data) and data[end:padded] == bytes(padded - end), "invalid ADT padding")
            props[key] = data[offset:end]
            offset = padded
        name = props.get("name", b"")
        require(name.endswith(b"\0") and b"\0" not in name[:-1], "invalid ADT node name")
        name = name[:-1].decode("ascii")
        path = "/" if depth == 0 else parent.rstrip("/") + "/" + name
        found = {path: props}
        for _ in range(child_count):
            child, offset = read(offset, path, depth + 1)
            require(not found.keys() & child.keys(), "duplicate ADT node")
            found.update(child)
        return found, offset
    found, end = read(0, "", 0)
    require(end == len(data), "ADT has trailing bytes")
    return found


def validate_outputs(plan, adt, args, hardware, kernel):
    parsed = parse_macho(kernel)
    require(digest(kernel) == KERNEL_SHA256 == plan["kernel"]["sha256"], "candidate kernel digest mismatch")
    require(plan["scope"] == "EARLY-ENTRY-ONLY" and not plan["handoff_permitted"] and
            not plan["ready_for_boot"] and not plan["stop_gate"]["implemented"] and
            not plan["root_filesystem_present"] and not plan["bootable_or_flashable_image_generated"], "invalid control scope")
    require(plan["sources"]["generator_sha256"] == digest(Path(__file__).read_bytes()) and
            plan["sources"]["adt_serializer_sha256"] == ADT_HELPER_SHA256, "preparation source digest mismatch")
    require(plan["kernel"]["compiled_timer_intid"] == 27 and plan["kernel"]["renoace_timer_intid"] == 19 and
            not plan["kernel"]["source_override_applied_to_this_binary"], "incorrect kernel IRQ provenance")
    banks, reservations = hardware_ranges(hardware)
    memory = plan["memory"]
    physical, size = int(memory["physical_base"], 16), int(memory["bytes"], 16)
    require(not memory["firmware_runtime_ownership_verified"], "RAM ownership cannot be inferred from DT")
    select_window(banks, reservations, size, parsed["base"] % BLOCK, physical)
    span = parsed["end"] - parsed["base"]
    expected_args_pa = aligned(physical + span, 0x4000)
    expected_adt_pa = expected_args_pa + PAGE
    expected_adt_va = parsed["base"] + expected_adt_pa - physical
    expected_top = aligned(expected_adt_pa + len(adt), 0x4000)
    require(expected_top <= physical + size - BLOCK, "control exceeds its proposed window")
    expected_layout = {"boot_args_pa": hex(expected_args_pa), "boot_args_bytes": ARGS_BYTES,
                       "adt_pa": hex(expected_adt_pa), "adt_va": hex(expected_adt_va),
                       "adt_bytes": len(adt), "top_of_kernel_data_pa": hex(expected_top)}
    require(plan["layout"] == expected_layout, "load-plan placement does not match actual kernel/ADT")
    for key, value in {"bytes": len(kernel), "virtual_base": hex(parsed["base"]), "memory_span": hex(span),
                       "entry_va": hex(parsed["entry"]), "entry_pa": hex(physical + parsed["entry"] - parsed["base"]),
                       "entry_file_offset": hex(parsed["entry_file_offset"])}.items():
        require(plan["kernel"][key] == value, "load-plan kernel field mismatch: " + key)
    expected_segments = []
    for segment in parsed["segments"]:
        if not segment["memory_bytes"]:
            continue
        start = physical + segment["va"] - parsed["base"]
        require(physical <= start and start + segment["memory_bytes"] <= expected_args_pa,
                "loaded segment leaves its kernel extent")
        expected_segments.append({"name": segment["name"], "virtual_address": hex(segment["va"]),
                                  "physical_address": hex(start), "memory_bytes": hex(segment["memory_bytes"]),
                                  "copy_from_file_offset": hex(segment["file_offset"]), "copy_bytes": hex(segment["file_bytes"]),
                                  "zero_fill_pa": hex(start + segment["file_bytes"]),
                                  "zero_fill_bytes": hex(segment["memory_bytes"] - segment["file_bytes"])})
    require(plan["segments"] == expected_segments, "load-plan segment copy/zero-fill extents differ")
    nodes = parse_adt_independently(adt)
    require(set(nodes) == {"/", "/chosen", "/cpus", "/cpus/cpu0", "/defaults", "/options", "/arm-io"}, "unexpected ADT nodes")
    require(nodes["/"]["name"] == b"device-tree\0", "wrong root name")
    require(all(not FORBIDDEN_PROPS & props.keys() for props in nodes.values()), "peripheral/root property enabled")
    require(len(nodes["/chosen"]["random-seed"]) == SEED_BYTES, "entropy seed is not 256 bytes")
    require(nodes["/chosen"]["random-seed"] != bytes(SEED_BYTES), "entropy seed is all zero")
    require(nodes["/cpus/cpu0"]["reg"] == struct.pack("<I", 0), "control must contain only CPU0")
    require(nodes["/cpus/cpu0"]["timebase-frequency"] == struct.pack("<I", hardware["interrupts"]["timer_hz"]), "timer frequency mismatch")
    require(nodes["/chosen"]["dram-base"] == struct.pack("<Q", physical) and
            nodes["/chosen"]["dram-size"] == struct.pack("<Q", size), "ADT RAM-window mismatch")
    require(len(args) == ARGS_BYTES, "boot_args has wrong size")
    require(struct.unpack_from("<HH", args) == (2, 2), "boot_args revision/version mismatch")
    expected = {0x08: parsed["base"], 0x10: physical, 0x18: size,
                0x20: expected_top, 0x60: expected_adt_va, 0x470: 0, 0x478: size}
    for offset, value in expected.items():
        require(struct.unpack_from("<Q", args, offset)[0] == value, f"boot_args mismatch at {offset:#x}")
    require(struct.unpack_from("<I", args, 0x68)[0] == len(adt), "boot_args ADT size mismatch")
    require(args[0x28:0x60] == bytes(0x38), "unverified framebuffer/machineType must be zero")
    require(args[0x6C:0x46C] == COMMAND_LINE.encode().ljust(1024, b"\0"), "unexpected boot arguments")
    require(args[4:8] == bytes(4) and args[0x46C:0x470] == bytes(4), "nonzero ABI padding")
    require(digest(adt) == plan["outputs"]["adt_sha256"] and digest(args) == plan["outputs"]["boot_args_sha256"], "output digest mismatch")


def prepare(kernel_path, hardware_path, output, physical_base=None, memory_size=0x10000000):
    data, raw_profile = kernel_path.read_bytes(), hardware_path.read_bytes()
    require(digest(data) == KERNEL_SHA256, "kernel does not match the reviewed CI candidate")
    image = parse_macho(data)
    hardware = json.loads(raw_profile)
    banks, reservations = hardware_ranges(hardware)
    physical = select_window(banks, reservations, memory_size, image["base"] % BLOCK, physical_base)
    require(hardware["interrupts"]["timer_hz"] == 19200000, "unexpected Reno Ace timer frequency")
    adt = generate_adt(physical, memory_size, hardware["interrupts"]["timer_hz"])
    span = image["end"] - image["base"]
    args_pa = aligned(physical + span, 0x4000)
    adt_pa = args_pa + PAGE
    adt_va = image["base"] + adt_pa - physical
    top = aligned(adt_pa + len(adt), 0x4000)
    require(top <= physical + memory_size - BLOCK, "kernel/args/ADT do not fit with one 2 MiB block spare")
    args = bytearray(ARGS_BYTES)
    struct.pack_into("<HH", args, 0, 2, 2)
    struct.pack_into("<4Q", args, 8, image["base"], physical, memory_size, top)
    struct.pack_into("<QI", args, 0x60, adt_va, len(adt))
    args[0x6C:0x46C] = COMMAND_LINE.encode().ljust(1024, b"\0")
    struct.pack_into("<Q", args, 0x478, memory_size)
    segments = []
    for s in image["segments"]:
        if not s["memory_bytes"]:
            continue
        start = physical + s["va"] - image["base"]
        require(physical <= start and start + s["memory_bytes"] <= args_pa,
                "loaded segment leaves kernel extent")
        segments.append({"name": s["name"], "virtual_address": hex(s["va"]), "physical_address": hex(start),
                         "memory_bytes": hex(s["memory_bytes"]), "copy_from_file_offset": hex(s["file_offset"]),
                         "copy_bytes": hex(s["file_bytes"]), "zero_fill_pa": hex(start + s["file_bytes"]),
                         "zero_fill_bytes": hex(s["memory_bytes"] - s["file_bytes"])})
    plan = {
        "scope": "EARLY-ENTRY-ONLY", "created_utc": datetime.now(timezone.utc).isoformat(),
        "ready_for_boot": False, "handoff_permitted": False, "bootable_or_flashable_image_generated": False,
        "root_filesystem_present": False, "kernel_mutated": False,
        "sources": {"generator": "tools/prepare_renoace_xnu_control.py", "generator_sha256": digest(Path(__file__).read_bytes()),
                    "adt_serializer": "references/ios-flame/tools/adt.py", "adt_serializer_sha256": ADT_HELPER_SHA256,
                    "kernel_source_commit": "7f981f88ca0388079af5f0ff01d9eb544b96a5cb"},
        "stop_gate": {"implemented": False, "required_before": "IOKit platform/CPU registration",
                      "allowed_future_checkpoints": ["entry", "before MMU", "after MMU", "arm_init entry"],
                      "note": "Unchanged kernel does not stop itself. A separately reviewed bounded probe is still required."},
        "kernel": {"path": str(kernel_path.resolve()), "sha256": KERNEL_SHA256, "bytes": len(data),
                   "architecture": "arm64, subtype 0", "virtual_base": hex(image["base"]),
                   "memory_span": hex(span), "entry_va": hex(image["entry"]),
                   "entry_pa": hex(physical + image["entry"] - image["base"]),
                   "entry_file_offset": hex(image["entry_file_offset"]),
                   "checkpoint_symbols": {k: hex(v) for k, v in image["symbols"].items()},
                   "compiled_timer_intid": 27, "renoace_timer_intid": 19,
                   "source_override_applied_to_this_binary": False},
        "hardware": {"path": str(hardware_path.resolve()), "sha256": digest(raw_profile)},
        "memory": {"physical_base": hex(physical), "bytes": hex(memory_size),
                   "selection": "highest measured bank first, excluding all recorded reservations",
                   "firmware_runtime_ownership_verified": False,
                   "note": "DT range exclusion does not prove ABL, firmware, payload or live-runtime ownership."},
        "layout": {"boot_args_pa": hex(args_pa), "boot_args_bytes": ARGS_BYTES, "adt_pa": hex(adt_pa),
                   "adt_va": hex(adt_va), "adt_bytes": len(adt), "top_of_kernel_data_pa": hex(top)},
        "segments": segments, "command_line": COMMAND_LINE,
        "outputs": {"adt": "renoace-entry.adt", "adt_sha256": digest(adt),
                    "boot_args": "boot-args.bin", "boot_args_sha256": digest(args)},
        "limitations": ["No stop trampoline, handoff or boot attempt is implemented.",
                        "The compiled kernel still uses timer INTID 27; the source override to 19 is not in this binary.",
                        "No framebuffer, USB, UFS, root filesystem, secondary CPU or persistent-log path is enabled by this ADT.",
                        "Firmware/runtime ownership of the proposed RAM window and log retention are unverified.",
                        "The phone's current ABL reportedly rejects fastboot boot; this tool provides no alternative flashing path."],
    }
    validate_outputs(plan, adt, bytes(args), hardware, data)
    require(not output.exists() or not any(output.iterdir()), "output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    (output / "renoace-entry.adt").write_bytes(adt)
    (output / "boot-args.bin").write_bytes(args)
    (output / "load-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    (output / "README.txt").write_text(
        "EARLY-ENTRY-ONLY OFFLINE CONTROL — NOT A BOOTABLE IMAGE\n\n"
        "No kernel patch or kernel copy is included. The ADT and boot_args are data for layout review.\n"
        "Do not hand off to the unchanged kernel using this plan: a stop before IOKit/CPU registration\n"
        "is required and has NOT been implemented. The kernel still contains timer INTID 27.\n"
        "No root filesystem, secondary CPU, framebuffer, USB or UFS interface is described.\n"
        "The proposed RAM window avoids the measured DT reservations, but firmware/runtime\n"
        "ownership and log retention are unverified. No phone operation was performed.\n\n"
        "Inspect load-plan.json for segment copies, zero-fill extents, ABI values and limitations.\n",
        encoding="utf-8")
    require(digest(kernel_path.read_bytes()) == KERNEL_SHA256, "source kernel changed during preparation")
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=DEFAULT_KERNEL)
    parser.add_argument("--hardware", type=Path, default=ROOT / "device/renoace/hardware.json")
    parser.add_argument("--out", type=Path, default=ROOT / "out/xnu-control")
    parser.add_argument("--physical-base", type=lambda x: int(x, 0))
    parser.add_argument("--memory-size", type=lambda x: int(x, 0), default=0x10000000)
    parser.add_argument("--verify-only", action="store_true", help="read and verify an existing control")
    args = parser.parse_args()
    try:
        if args.verify_only:
            plan = json.loads((args.out / "load-plan.json").read_text(encoding="utf-8"))
            raw_hardware = args.hardware.read_bytes()
            require(digest(raw_hardware) == plan["hardware"]["sha256"], "hardware profile changed")
            validate_outputs(plan, (args.out / "renoace-entry.adt").read_bytes(),
                             (args.out / "boot-args.bin").read_bytes(), json.loads(raw_hardware), args.kernel.read_bytes())
        else:
            plan = prepare(args.kernel, args.hardware, args.out, args.physical_base, args.memory_size)
        print(f"Verified offline control: {args.out.resolve()}")
        print(f"Proposed RAM {plan['memory']['physical_base']} + {plan['memory']['bytes']}; runtime ownership UNVERIFIED")
        print("NO HANDOFF: stop gate missing; kernel timer still 27; root filesystem absent")
    except (InvalidControl, OSError, ValueError, KeyError, struct.error) as error:
        parser.exit(1, f"prepare_renoace_xnu_control: {error}\n")


if __name__ == "__main__":
    main()
