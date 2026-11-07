# P11 offline closeout

- Candidate: `out/xnu-p11-probe/build.json`
- Build ID: `cd420027a092b00d`
- Packed image SHA-256: `5dbb29d0c8abc75eeac6978d69d9bce03b3a3745f1b4e3671094a0f2b5619022`
- Model result: `out/xnu-p11-probe/model-tests/max/positive_native_second_pe.json`
- Model JSON SHA-256: `5f9321c011f5255ce8feb793baec54caaadee8fc37123044ae1e827f8f7a64fe`
- Model result is `passed: true`; it is an offline native instruction model, not phone evidence.

Observed checkpoints:

1. Full `arm_vm_init` return at `0xfffffff007b33e34`.
2. Compiled RX gate checkpoint at `0xfffffff007500800`.
3. Second `PE_init_platform(TRUE)` return at `0xfffffff007b33fac`.
4. Compiled RX gate recovery checkpoint at `0xfffffff007500800`.
5. Identity return and outer bridge return to restored Linux.

The gate is 384 bytes within the 2 KiB RX cave. The continuation immediate is `0x3e40`, which skips the three emulated displaced words. The model verifies caller GPRs, FP/SIMD, CNTKCTL, TTBR recovery, Linux bytes, FDT semantics, and source initrd preservation.

The static validator also passes: `out/analysis/p11-second-pe-static.json`. It still records `hardware_tested=false`, `irq_ready=false`, and `xnu_runtime_connection=false`. Full iOS has not started. No phone package, flash, reboot, USB enumeration, DMA, or transfer test was run for P11.

The remaining next boundary is timer-state recovery before crossing `fiq_context_init`; the first new timer write remains `CNTV_CTL_EL0=1` at `0xfffffff007509498`.

Follow-on candidate: the P11 bridge now saves and restores virtual/physical timer CTL/CVAL state, records read-only ISTATUS and masked DAIF witnesses, continues phase 1 after the second PE return, and enters the RX recovery gate at the `fiq_context_init` return (`0xfffffff007b33fe8`). The pinned CI kernel was recovered at `out/cloud-kernel/42306878464/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf` and its SHA-256 matches the reviewed artifact. The source/model contract passes host tests; compiling the bridge and executing the instruction model still requires the pinned AArch64 NDK and is not hardware evidence.
