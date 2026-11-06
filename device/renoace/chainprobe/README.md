# P02: no-reset diagnostic Linux bridge

This exact P02 bridge has executed successfully on the Reno Ace and returned to the existing YAAP Linux kernel. The phone supplied a matching build ID and CRC32 record; transfer SHA-256 and original recovery restoration were verified. See [the hardware record](../STAGE4.md). It is **not XNU**. The builder does not invoke ADB or fastboot; the offline models below remain distinct from the hardware observation.

Before any probe instruction, ABL's decompressor has already written the expanded Image; the probe also writes its tail context/stack before the C memory-map guard. A late overlap guard alone cannot protect an already overwritten DTB/initrd. This originally blocked packaging. The owning ABL audit now establishes an earlier boundary: gzip `avail_out` and header `image_size` are checked against `DTBLoad-KernelLoad`, before handoff. The actual candidate fits the inspected fallback and inferred captured windows. The builder requires that audit to name the exact Image hash and backed-up ABL identity, together with matching instruction-model results, before `--package` works.

This resolves the demonstrated DTB/initrd collision concern; it does not manufacture a captured EFI memory map. Exclusive ownership of every selected-window byte and physical cache/interconnect behavior remain stated hardware limitations. Parent review and any device execution are separate from these offline checks. The first carrier retained as `recovery.img.blocked` predates the completed audit/model checks; use the audited build report to identify the current candidate.

## Layout and execution

The exact normal boot backup provides the kernel and ramdisk. Its decompressed Linux Image is `0x2fb2810` bytes; its header requires `0x37f0000` bytes of effective Image memory. The probe is appended after that effective extent, so it cannot occupy Linux BSS or early page tables. The loader sees all `0x3900000` bytes in the decompressed file, including zero padding and the probe arena.

| Image-relative extent | Purpose |
|---|---|
| `0 .. 0x2fb2810` | Original normal Linux Image; only code0 and header image_size temporarily changed |
| `0x2fb2810 .. 0x37f0000` | Zero padding covering the original effective extent |
| `0x37f0000 .. 0x3800000` | Probe code, data, 32KiB stack and padding |
| `0x3800000 .. 0x3900000` | Capacity for the cloned runtime FDT |

The original entry branch (`0x14960000`, destination Image+`0x2580000`) is temporarily replaced by `B Image+0x37f0000`. The probe derives Image base using a PC-relative linker symbol; **no physical load base is hardcoded**. The original code0 and image_size are restored before branching to the original Linux header. Every other byte of the original file is checked unchanged by the builder.

Only EL1 or EL2 with stage-1 MMU and data cache disabled is admitted, as required by the AArch64 Linux boot ABI. The probe saves/restores SPSel, SP and the current-level VBAR. It does not change the exception level, MMU configuration, timers, GIC, PMIC, UFS or device DMA state. Unexpected entry EL/MMU/cache state parks instead of modifying memory through an unknown translation. Ordinary FDT/bounds refusals restore the Linux header and return the original FDT. An exception after context setup also attempts that fallback once; a second fault parks.

The incoming **runtime** FDT is parsed, not replaced by a stale captured DTB. Before any FDT construction, the code verifies:

- FDT version/layout/token/string bounds, root two-cell addressing, expected SoC339 and one `/chosen`;
- the expanded Image fits entirely inside one memory bank;
- no expanded-Image overlap with input FDT, actual initrd, fixed reserved-memory ranges or memreserve entries;
- runtime initrd length matches the exact normal boot ramdisk;
- enough capacity for the added log property, strings and reservation entry.

On success it clones the tree and adds `/chosen/renoace-probe-log`, keeping original bootargs, initrd addresses, seeds and other nodes unchanged. It adds the **tail arena** as an FDT memreserve entry so Linux cannot reuse the log/tree storage during startup. The log includes a CRC32 of its preceding text. Destination cache lines are invalidated before uncached writes and cleaned to PoC afterwards; the restored Linux entry line is cleaned and I-cache invalidated before the final branch.

## Carrier and remaining hardware questions

`python tools/build_renoace_chainprobe.py` emits the experimental kernel payload and audit report. Run `python device/renoace/chainprobe/test_instructions.py` for the bounded instruction model, then `python tools/build_renoace_chainprobe.py --package` for a candidate carrier after its evidence gates pass. It uses normal boot header fields/command line and its exact ramdisk, the installed recovery's DTBO, both identical normal DTB copies, and a fresh unsigned `recovery` AVB hash footer. The current backups' load-address fields must match. Offline unpacking checks every component and AVB verifies the hash.

The actual compiled tail passed 16 bounded cases: EL1/EL2, SPSel0/1, two physical bases, DTB/initrd/reservation overlap refusals, malformed/unsupported FDT, unsupported MMU/cache state, and injected exception fallback. Each successful case checked 726,853 guest writes, restricted to the original header fields and tail arena. It stopped before executing any restored Linux instruction. Results and exact hashes are in `out/chainprobe/instruction-tests.json`; an actual model-produced log property, including its NUL terminator, is `out/chainprobe/model-record.bin`. CPU register values, cache maintenance and physical exception delivery are modeled, not hardware observations.

Normal boot's Magisk ramdisk has `RECOVERYMODE=false` and lacks `/system/bin/recovery`; the recovery ramdisk includes that executable. AOSP Android15 init determines recovery mode by presence of that executable. Do not add `androidboot.force_normal_boot=1` blindly: that triggers a switch to `/first_stage_ramdisk`, whose layout is not established for this ramdisk. Normal Android startup through this exact recovery carrier has now been observed. Other firmware, ramdisks and command-line variants remain untested.

If it reaches Android, the diagnostic property should be readable at `/sys/firmware/devicetree/base/chosen/renoace-probe-log` (root). Absence is not proof that the probe did not execute; a validation fallback intentionally adds no property. The successful run establishes the reported layout and return for this exact image/device. It does not prove every possible cache/interconnect condition or provide a complete EFI memory map.

## Independent instruction-test plan

Execute only the compiled tail and final handoff in an ARM64 instruction emulator. Start at the **patched original Image entry**, stop when PC reaches that Image base a second time, and never execute the Linux entry instruction after restoration. Model privileged registers/cache operations explicitly; do not count those models as hardware verification.

1. Success at at least two physical bases (`0xa8880000` from Android iomem and `0x80080000` as an alternate congruent base), using a copy of the captured FDT at a separate valid RAM address and simulated EL1/EL2 CPU registers.
2. At stop: original 50,014,224-byte Linux prefix must be byte-identical to its backup; x0 points to a valid FDT; x1/x2/x3 are zero; SP/SPSel/VBAR are restored. Check new log property, CRC, unmodified original FDT, unchanged properties other than log/memreserve, and unchanged initrd addresses.
3. Instrument **every guest write**. Permit only tail arena and the original Image's first64-byte header cache line. Reject any MMIO, original kernel-body, original FDT or initrd write. Reject SMC/HVC/SVC and any reset path.
4. Refusal cases: initrd overlaps the tail, a fixed reservation overlaps it, a memreserve entry overlaps it, Image lies outside memory banks, malformed FDT bounds/tokens, duplicate log property, wrong SoC, wrong ramdisk length and oversized FDT. They must return the original FDT and restore original Linux bytes without extra writes.
5. Unsupported EL or M/C bits set must reach `chain_park` with no speculative memory-edit fallback. Exception-entry test should restore original Linux once; repeated failure should park.
6. Emulate with instruction and wall-time limits. Confirm no instruction in original Linux runs; the test is about this logging bridge, not a simulated Android boot.

Primary protocol source: `references/oppo-kernel` at `289d6118...`, `msm-4.14/Documentation/arm64/booting.txt`; actual kernel geometry comes from the captured boot image. Android init reference: https://github.com/aosp-mirror/platform_system_core/blob/android-15.0.0_r1/init/util.cpp and `first_stage_init.cpp`.
