# P11 offline closeout

- Candidate: `out/xnu-p11-probe/build.json`
- Build ID: `082d5a90257c6a45`
- Packed image SHA-256: `8930b4b0063d26ca107c0b5dbda25d955c9d9a9d957b31c86dfa32c143dc6e8e`
- RX gate: 460 bytes, 155 private patches
- Model result: `out/xnu-p11-probe/native-p11-tests.json`
- Model JSON SHA-256: `8b2e9682fed80bddbbde5143da544c72b9ae6f4171e545aa4c29bf0b7bd3cb06`
- Native model record SHA-256: `f9e89b16bd16d7556f089d0b974d4ad579b1a015bda0d9e36df28b93c321e370`
- Model result is `passed: true`; it is an offline native instruction model, not phone evidence.
- The current runner contains the positive P11 path only; negative refusal coverage remains pending.
- The runner now accepts `--all-cases` to execute the eight refusal/fault peers; this must be run against the same private fixture before claiming complete negative coverage.

Observed checkpoints:

1. Full `arm_vm_init` return at `0xfffffff007b33e34`.
2. Compiled RX gate checkpoint at `0xfffffff007500800`.
3. Second `PE_init_platform(TRUE)` return at `0xfffffff007b33fac`.
4. `fiq_context_init` return at `0xfffffff007b33fe8`.
5. Compiled RX gate recovery, identity return, and outer bridge return to restored Linux.

The gate is 460 bytes within the 2 KiB RX cave. The continuation immediate is `0x3e40`, and the phase-1 continuation targets `0xfffffff007b33fb0` after the displaced `mov x0,x19`. The model verifies caller GPRs, FP/SIMD, CNTKCTL, timer CVAL/CTL restoration with DAIF masked, TTBR recovery, Linux bytes, FDT semantics, and source initrd preservation.

The static validator and `tools/tests/test_p11_timer_bridge_layout.py` both pass. It still records `hardware_tested=false`, `irq_ready=false`, and `xnu_runtime_connection=false`. Full iOS has not started. No phone package, flash, reboot, USB enumeration, DMA, or transfer test was run for P11.

The next boundary is real timer/IRQ delivery and negative refusal coverage; the first new timer write remains `CNTV_CTL_EL0=1` at `0xfffffff007509498`.

The P11 bridge saves and restores virtual/physical timer CTL/CVAL state, records read-only ISTATUS and masked DAIF witnesses, continues phase 1 after the second PE return, and enters the RX recovery gate at the `fiq_context_init` return (`0xfffffff007b33fe8`). The pinned CI kernel was recovered at `out/cloud-kernel/42306878464/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf` and its SHA-256 matches the reviewed artifact. The positive source/model contract passes host tests; negative refusal coverage remains pending.
