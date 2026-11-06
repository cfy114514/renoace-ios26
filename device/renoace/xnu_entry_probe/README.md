# P03: bounded XNU-entry control

This candidate executes **seven original instructions from the pinned XNU kernel, then a RET substituted in its private RAM copy**. It does not run XNU's MMU setup, `arm_init`, IOKit, scheduler or iOS userland. The unchanged Android Linux kernel then starts and exposes the diagnostic FDT property. Hardware results and restoration checks are recorded separately in `../STAGE5.md`.

## Inputs and private load

The source Mach-O SHA-256 is `c973fe6cf1f039781972b580a9423613effd08806e66bd88ac5a2d2a9e3ef0fb`,24,158,392bytes. Its original file remains unchanged. The exact normal boot ramdisk gzip remains a byte-identical prefix; one alignment byte and a raw `newc` archive containing `.renoace-xnu-p03.macho` follow it. The second member starts at initrd offset1,531,488. The complete initrd is25,690,004bytes and parses as the original compressed archive plus the new raw archive. The independent CPIO review is in `out/xnu-wrapper-tests/cpio-review.json`.

The generated ten-segment table expands file data and BSS into a256MiB window beginning at `0x180004000`, after runtime-FDT validation against memory banks, fixed reservations, memreserve entries, the Linux Image/clone arena, incoming FDT and initrd. The loaded segment span is `0x08ac8000`. Every source/file-backed segment CRC is checked; BSS is written and read back as zero. Guarded CRC32X/B instructions and paired 64-bit loads/stores reduce uncached DDR transactions without changing MMU/cache state. The revised loader checks a 15-second architected-counter budget at intervals of at most64KiB; expiration refuses the XNU call and returns through Linux. The first five-second candidate is preserved under `out/xnu-entry-probe-attempt1/`.

The revised record includes the active phase/segment, completed bytes, current phase ticks and cumulative ticks for source CRC, invalidation, copy, zeroing, copied-data CRC and zero readback. Copy/zero totals now commit actual completed chunks, including partial segments. Schema identity and the configured budget are pinned in the build report. No completion is inferred from a valid refusal record.

Once any window bytes are used, the clone adds that window to its FDT memreserve map. This is temporary diagnostic-boot RAM usage, not a partition operation. The0x480-byte arguments structure is only an entry-control argument object: its ADT fields are deliberately empty and it must not be described as ready for later XNU startup.

## Exact executed path

| File/Image-relative location | Original instruction |
|---|---|
| `0x538518` | `b start_first_cpu` |
| `0x53a080` | `msr OSLAR_EL1, xzr` |
| `0x53a084` | `msr DAIFSet, #15` |
| `0x53a088` | `mov x20, x0` |
| `0x53a08c` | `mov x21, #0` |
| `0x53a090` | `adrp x0, LowExceptionVectorsBase` |
| `0x53a094` | `add x0, x0, #0` |

At `0x53a098`, original bytes `00 c0 18 d5` (`msr VBAR_EL1,x0`) become `c0 03 5f d6` (`ret`) **only in loaded RAM**. Runtime checks confirm all original prefix words and the RET before `blr` reaches the actual Mach-O entry. EL1 and OSLSR.OSLK=0 are required so the original OSLAR=0 operation is idempotent. The wrapper checks OS lock once more immediately before entry, saves/restores GPRs/LR/NZCV/DAIF/SP context, and records returned registers.

Success requires returned x20=argument PA, x21=0, x0=`physBase+0x539000`, and unchanged SP/VBAR/SCTLR across the bounded call. The lower-level P02 exception fallback remains available; an unexpected trap can return to Linux without a completed P03 record. Missing output is not a successful checkpoint.

## Offline checks completed

- Full compiled-loader instruction model:9/9 cases passed, including the native-base positive, source CRC refusal, high-window reservation refusal, runtime gate-not-patched refusal, OS lock refusal, budget refusal, missing-CRC-ISA refusal, timeout during BSS writes and a corrupted non-first BSS word rejected by real readback.
- Positive trace is exactly the seven original PCs plus the private RET. Linux execution stops before its restored first instruction.
- Full file-backed bytes and BSS are checked against the pinned Mach-O after guest execution. High RAM starts with0xa5; bytes outside used extents remain sentinel values. Source initrd/incoming FDT are read-only in the model, and original Linux bytes are restored exactly.
- The gate-not-patched fixture completes the loader but its real C guard refuses before **any** XNU instruction. It never executes VBAR installation or later startup.
- Independent wrapper model:5/5, bound to unchanged304-byte wrapper SHA `2ede973d84498f07d8ca5e24fc372b8a819389e05979453e0bf4aad1db261de2`.
- Independent compiled memory primitives:190/190 cases passed for CRC, paired copy, zeroing and full zero readback, including tails,64KiB boundaries, deadline refusal and single-bit contamination. The whole source CRC matches zlib. Independent CPIO parsing/source review passed.

System-register values, cache operations, physical exceptions and counter timing are explicit model inputs, not hardware observations. Host model duration is not phone performance. Reports are under `out/xnu-entry-probe/`, `out/xnu-wrapper-tests/` and `out/xnu-memory-primitive-tests/`.

## Build and review artifacts

```powershell
python tools/build_renoace_xnu_entry_probe.py
python device/renoace/xnu_entry_probe/test_instructions.py
python device/renoace/xnu_entry_probe/test_primitives.py
python device/renoace/xnu_entry_probe/test_wrapper.py
python tools/build_renoace_xnu_entry_probe.py --package
```

Packaging requires exact model/source/Image identity, unchanged independently tested wrapper bytes, CPIO/CRC checks and owning-ABL identity/bounds. It recalculates the audited loader formula for the larger initrd. The96MiB carrier retains normal Linux/header/ramdisk prefix, appends the new archive, carries current recovery DTBO and both DTB copies, and uses a fresh unsigned recovery AVB hash footer. Component roundtrips and AVB verification pass. There are no ADB/fastboot calls in the builder or model.

`model-record.bin` is an actual model-produced `/chosen/renoace-probe-log` value including its terminating NUL. It starts `RENOACE-XNU-ENTRY-P03`, includes the exact build id and numeric status/capture fields, and ends with the CRC32 of preceding text. The parent reader must validate completion, build, CRC and device/host transport SHA before treating a record as an observation. A model fixture must retain its non-hardware origin.
