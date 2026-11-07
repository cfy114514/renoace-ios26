# P11 offline closeout

- Candidate: `out/xnu-p11-probe/build.json`
- Build ID: `0598c77656df6380`
- Packed image SHA-256: `96bbc9fa1bf24801182b546b15d886955c1df9e0c39014ac9db06456acaea67d`
- RX gate: 468 bytes, 157 private patches
- Model result: `out/xnu-p11-probe/native-p11-tests.json`
- Model JSON SHA-256: `b6d077bbb7c4ee55be1c55fd493098d1b3430af7f77349b6222b7ad25471a1ee`
- Native model record SHA-256: `1cda023967b4f4fc2e500664a41a2de7164461f229cf20d63f8dd8e731b9ebef`
- Model result is `passed: true`; all nine cases passed, including eight refusal/fault peers. It is an offline native instruction model, not phone evidence.

Observed checkpoints:

1. Full `arm_vm_init` return at `0xfffffff007b33e34`.
2. Compiled RX gate checkpoint at `0xfffffff007500800`.
3. Second `PE_init_platform(TRUE)` return at `0xfffffff007b33fac`.
4. `fiq_context_init` return at `0xfffffff007b33fe8`.
5. Compiled RX gate recovery, identity return, and outer bridge return to restored Linux.

The gate is 468 bytes within the 2 KiB RX cave. The continuation immediate is `0x3e40`, and the phase-1 continuation targets `0xfffffff007b33fb0` after the displaced `mov x0,x19`. Fault kinds branch to fault common after root recovery. The model verifies caller GPRs, FP/SIMD, CNTKCTL, timer CVAL/CTL restoration with DAIF masked, TTBR recovery, Linux bytes, FDT semantics, and source initrd preservation.

The static validator and `tools/tests/test_p11_timer_bridge_layout.py` both pass. It still records `hardware_tested=false`, `irq_ready=false`, and `xnu_runtime_connection=false`. Full iOS has not started. No phone package, flash, reboot, USB enumeration, DMA, or transfer test was run for P11.

The next boundary is real timer/IRQ delivery; the first new timer write remains `CNTV_CTL_EL0=1` at `0xfffffff007509498`.

The P11 bridge saves and restores virtual/physical timer CTL/CVAL state, records read-only ISTATUS and masked DAIF witnesses, continues phase 1 after the second PE return, and enters the RX recovery gate at the `fiq_context_init` return (`0xfffffff007b33fe8`). The pinned CI kernel was recovered at `out/cloud-kernel/42306878464/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf` and its SHA-256 matches the reviewed artifact. The positive source/model contract passes host tests; negative refusal coverage remains pending.
