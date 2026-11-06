/* C-entry: reversible, single-core EL1 startup through real XNU stage-1 MMU.
 * No stack access anywhere. The whole blob/context is copied into owned RAM
 * covered by BOTH the pinned startup's identity and kernel-VA mappings.
 * Only x0 (status) differs on return to the caller. Source kernel is never edited.
 * The embedded config is filled and validated by the loader before entry.
 */
#include "mmu_bridge.h"
.arch armv8.2-a
.section .text.mmu_bridge,"ax",%progbits
.balign 0x800
.global mmu_bridge_start, mmu_bridge_vectors
mmu_bridge_start:
mmu_bridge_vectors:
.macro VECTOR n
.global mmu_bridge_fault_\n
mmu_bridge_fault_\n:
    mov x17, #\n
    b mmu_bridge_fault_common
    .space 0x80 - (. - mmu_bridge_fault_\n)
.endm
VECTOR 0
VECTOR 1
VECTOR 2
VECTOR 3
VECTOR 4
VECTOR 5
VECTOR 6
VECTOR 7
VECTOR 8
VECTOR 9
VECTOR 10
VECTOR 11
VECTOR 12
VECTOR 13
VECTOR 14
VECTOR 15

.macro SAVE_SYS reg, off
    mrs x9, \reg
    str x9, [x16, #\off]
.endm
.macro RESTORE_SYS reg, off
    ldr x9, [x16, #\off]
    msr \reg, x9
.endm
.macro OBS_SYS reg, off
    mrs x9, \reg
    str x9, [x16, #\off]
.endm
.macro OBS_AT off
    at s1e1r, x9
    isb
    mrs x9, par_el1
    str x9, [x16, #\off]
.endm

.global mmu_bridge_entry
.type mmu_bridge_entry,%function
mmu_bridge_entry:
    /* x2 is the caller-validated embedded context PA. Save ALL registers
     * before using a scratch register or changing either stack bank. */
    str x0, [x2, #(MMU_GPR + 0)]
    str x1, [x2, #(MMU_GPR + 8)]
    str x2, [x2, #(MMU_GPR + 16)]
    str x3, [x2, #(MMU_GPR + 24)]
    str x4, [x2, #(MMU_GPR + 32)]
    str x5, [x2, #(MMU_GPR + 40)]
    str x6, [x2, #(MMU_GPR + 48)]
    str x7, [x2, #(MMU_GPR + 56)]
    str x8, [x2, #(MMU_GPR + 64)]
    str x9, [x2, #(MMU_GPR + 72)]
    str x10, [x2, #(MMU_GPR + 80)]
    str x11, [x2, #(MMU_GPR + 88)]
    str x12, [x2, #(MMU_GPR + 96)]
    str x13, [x2, #(MMU_GPR + 104)]
    str x14, [x2, #(MMU_GPR + 112)]
    str x15, [x2, #(MMU_GPR + 120)]
    str x16, [x2, #(MMU_GPR + 128)]
    str x17, [x2, #(MMU_GPR + 136)]
    str x18, [x2, #(MMU_GPR + 144)]
    str x19, [x2, #(MMU_GPR + 152)]
    str x20, [x2, #(MMU_GPR + 160)]
    str x21, [x2, #(MMU_GPR + 168)]
    str x22, [x2, #(MMU_GPR + 176)]
    str x23, [x2, #(MMU_GPR + 184)]
    str x24, [x2, #(MMU_GPR + 192)]
    str x25, [x2, #(MMU_GPR + 200)]
    str x26, [x2, #(MMU_GPR + 208)]
    str x27, [x2, #(MMU_GPR + 216)]
    str x28, [x2, #(MMU_GPR + 224)]
    str x29, [x2, #(MMU_GPR + 232)]
    str x30, [x2, #(MMU_GPR + 240)]
    mrs x9, nzcv
    str x9, [x2, #MMU_SAVE_NZCV]
    mrs x9, daif
    str x9, [x2, #MMU_SAVE_DAIF]
    mov x16, x2
    /* No FP/SIMD instruction executes before the arm_init snapshot hook. */
    str xzr, [x16, #MMU_FP_SAVED]
    adr x9, mmu_bridge_context
    cmp x16, x9
    b.ne .Learly_refuse
    mrs x9, CurrentEL
    str x9, [x16, #MMU_SAVE_CURRENTEL]
    cmp x9, #4
    b.ne .Learly_refuse
    mrs x9, SPSel
    str x9, [x16, #MMU_SAVE_SPSEL]
    msr SPSel, #0
    mov x10, sp
    str x10, [x16, #MMU_SAVE_SP_EL0]
    msr SPSel, #1
    mov x10, sp
    str x10, [x16, #MMU_SAVE_SP_EL1]
    msr SPSel, x9
    SAVE_SYS sctlr_el1, MMU_SAVE_SCTLR
    SAVE_SYS tcr_el1, MMU_SAVE_TCR
    SAVE_SYS ttbr0_el1, MMU_SAVE_TTBR0
    SAVE_SYS ttbr1_el1, MMU_SAVE_TTBR1
    SAVE_SYS mair_el1, MMU_SAVE_MAIR
    SAVE_SYS amair_el1, MMU_SAVE_AMAIR
    SAVE_SYS vbar_el1, MMU_SAVE_VBAR
    SAVE_SYS cpacr_el1, MMU_SAVE_CPACR
    SAVE_SYS contextidr_el1, MMU_SAVE_CONTEXTIDR
    SAVE_SYS tpidr_el1, MMU_SAVE_TPIDR_EL1
    SAVE_SYS tpidr_el0, MMU_SAVE_TPIDR_EL0
    SAVE_SYS tpidrro_el0, MMU_SAVE_TPIDRRO_EL0
    SAVE_SYS par_el1, MMU_SAVE_PAR
    SAVE_SYS elr_el1, MMU_SAVE_ELR
    SAVE_SYS spsr_el1, MMU_SAVE_SPSR
    SAVE_SYS csselr_el1, MMU_SAVE_CSSELR
    SAVE_SYS oslsr_el1, MMU_SAVE_OSLSR
    SAVE_SYS cntvct_el0, MMU_SAVE_CNTVCT
    SAVE_SYS esr_el1, MMU_SAVE_ESR
    SAVE_SYS far_el1, MMU_SAVE_FAR
    SAVE_SYS cntkctl_el1, MMU_SAVE_CNTKCTL
    str xzr, [x16, #MMU_SAVE_FEATURES]
    str xzr, [x16, #MMU_SAVE_PAN]
    str xzr, [x16, #MMU_SAVE_UAO]
    mrs x9, id_aa64mmfr1_el1
    ubfx x9, x9, #20, #4
    cbz x9, .Lsave_uao
    cmp x9, #15
    b.eq .Lsave_uao
    mrs x9, pan
    str x9, [x16, #MMU_SAVE_PAN]
    mov x9, #MMU_FEATURE_PAN
    str x9, [x16, #MMU_SAVE_FEATURES]
.Lsave_uao:
    mrs x9, id_aa64mmfr2_el1
    ubfx x9, x9, #4, #4
    cbz x9, .Lsaved
    cmp x9, #15
    b.eq .Lsaved
    mrs x9, uao
    str x9, [x16, #MMU_SAVE_UAO]
    ldr x9, [x16, #MMU_SAVE_FEATURES]
    orr x9, x9, #MMU_FEATURE_UAO
    str x9, [x16, #MMU_SAVE_FEATURES]
.Lsaved:
    mov x9, #1
    str x9, [x16, #MMU_OBS_PHASE]
    ldr x9, [x16, #MMU_SAVE_SCTLR]
    tbnz x9, #0, .Lrefuse
    tbnz x9, #2, .Lrefuse
    ldr x9, [x16, #MMU_SAVE_OSLSR]
    tbnz x9, #1, .Lrefuse
    ldr x9, [x16, #MMU_CFG_MAGIC]
    movz x10, #0x4231
    movk x10, #0x4d55, lsl #16
    movk x10, #0x344d, lsl #32
    movk x10, #0x5030, lsl #48
    cmp x9, x10
    b.ne .Lrefuse
    ldr x9, [x16, #MMU_CFG_ABI_VERSION]
    cmp x9, #MMU_BRIDGE_ABI_VERSION
    b.ne .Lrefuse
    ldr x9, [x16, #MMU_CFG_CONTEXT_BYTES]
    cmp x9, #MMU_BRIDGE_CONTEXT_BYTES
    b.ne .Lrefuse
    ldr x9, [x16, #MMU_CFG_BLOB_PA]
    adr x10, mmu_bridge_start
    cmp x9, x10
    b.ne .Lrefuse
    ldr x11, [x16, #MMU_CFG_KERNEL_PHYS_BASE]
    ldr x12, [x16, #MMU_CFG_KERNEL_VIRT_BASE]
    sub x13, x9, x11
    add x13, x13, x12
    ldr x14, [x16, #MMU_CFG_BLOB_VA]
    cmp x13, x14
    b.ne .Lrefuse
    ldr x9, [x16, #MMU_CFG_EXPECTED_ARGS_PA]
    ldr x10, [x16, #(MMU_GPR + 8)]
    cmp x9, x10
    b.ne .Lrefuse
    ldr x9, [x16, #MMU_CFG_CLEAN_START_PA]
    ldr x10, [x16, #MMU_CFG_CLEAN_END_PA]
    cmp x9, x11
    b.lo .Lrefuse
    cmp x9, x10
    b.hs .Lrefuse
    and x12, x11, #0xffffffffffe00000
    ldr x13, [x16, #MMU_CFG_WINDOW_SIZE]
    lsr x13, x13, #21
    lsl x13, x13, #21
    cbz x13, .Lrefuse
    add x12, x12, x13
    cmp x10, x12
    b.hi .Lrefuse
    adr x12, mmu_bridge_start
    cmp x12, x9
    b.lo .Lrefuse
    adr x12, mmu_bridge_end
    cmp x12, x10
    b.hi .Lrefuse
    isb
    mrs x9, cntvct_el0
    ldr x10, [x16, #MMU_CFG_BUDGET_START_TICKS]
    sub x9, x9, x10
    str x9, [x16, #MMU_OBS_ELAPSED_TICKS]
    ldr x10, [x16, #MMU_CFG_BUDGET_TICKS]
    cbz x10, .Lentry_expired
    cmp x9, x10
    b.hi .Lentry_expired
    msr daifset, #15
    adr x9, mmu_bridge_vectors
    msr vbar_el1, x9
    isb
    mov x9, #2
    str x9, [x16, #MMU_OBS_PHASE]
    mov x9, #1
    str x9, [x16, #MMU_OBS_ENTERED]
    /* Pinned startup never reads/writes x28 before the table-ready hook.
     * Keeping this context pointer there enables a truly stackless snapshot. */
    mov x28, x16
    ldr x0, [x16, #(MMU_GPR + 8)]
    ldr x16, [x16, #MMU_GPR]
    br x16

.Lentry_expired:
    mov x9, #1
    str x9, [x16, #MMU_OBS_BUDGET_EXPIRED]
    b .Lrefuse
.Learly_refuse:
    mov x9, #MMU_STATUS_REFUSED
    str x9, [x16, #MMU_OBS_STATUS]
    b .Lrestore_gprs
.Lrefuse:
    mov x9, #MMU_STATUS_REFUSED
    str x9, [x16, #MMU_OBS_STATUS]
    b .Lrestore_physical

/* Fixed pinned start.s guard: input x25=TTBR0, x3=TTBR1, x28=context PA.
 * SPSel=0 and both stacks are virtual while M=0. No stack is dereferenced.
 * Preserve every XNU GPR/NZCV, including x28, across a successful guard. */
.global mmu_bridge_guard
mmu_bridge_guard:
    str x0, [x28, #(MMU_SCRATCH + 0)]
    str x1, [x28, #(MMU_SCRATCH + 8)]
    str x2, [x28, #(MMU_SCRATCH + 16)]
    str x3, [x28, #(MMU_SCRATCH + 24)]
    str x4, [x28, #(MMU_SCRATCH + 32)]
    str x5, [x28, #(MMU_SCRATCH + 40)]
    str x6, [x28, #(MMU_SCRATCH + 48)]
    str x7, [x28, #(MMU_SCRATCH + 56)]
    str x8, [x28, #(MMU_SCRATCH + 64)]
    str x9, [x28, #(MMU_SCRATCH + 72)]
    str x10, [x28, #(MMU_SCRATCH + 80)]
    str x11, [x28, #(MMU_SCRATCH + 88)]
    str x12, [x28, #(MMU_SCRATCH + 96)]
    str x13, [x28, #(MMU_SCRATCH + 104)]
    str x14, [x28, #(MMU_SCRATCH + 112)]
    str x15, [x28, #(MMU_SCRATCH + 120)]
    str x16, [x28, #(MMU_SCRATCH + 128)]
    str x17, [x28, #(MMU_SCRATCH + 136)]
    str x18, [x28, #(MMU_SCRATCH + 144)]
    str x19, [x28, #(MMU_SCRATCH + 152)]
    str x20, [x28, #(MMU_SCRATCH + 160)]
    str x21, [x28, #(MMU_SCRATCH + 168)]
    str x22, [x28, #(MMU_SCRATCH + 176)]
    str x23, [x28, #(MMU_SCRATCH + 184)]
    str x24, [x28, #(MMU_SCRATCH + 192)]
    str x25, [x28, #(MMU_SCRATCH + 200)]
    str x26, [x28, #(MMU_SCRATCH + 208)]
    str x27, [x28, #(MMU_SCRATCH + 216)]
    str x28, [x28, #(MMU_SCRATCH + 224)]
    str x29, [x28, #(MMU_SCRATCH + 232)]
    str x30, [x28, #(MMU_SCRATCH + 240)]
    mrs x9, nzcv
    str x9, [x28, #(MMU_SCRATCH + 248)]
    adr x16, mmu_bridge_context
    mov x9, #1
    str x9, [x16, #MMU_OBS_GUARD_ENTERED]
    str x25, [x16, #MMU_OBS_GUARD_TTBR0]
    str x3, [x16, #MMU_OBS_GUARD_TTBR1]
    isb
    mrs x9, cntvct_el0
    ldr x10, [x16, #MMU_CFG_BUDGET_START_TICKS]
    sub x9, x9, x10
    str x9, [x16, #MMU_OBS_ELAPSED_TICKS]
    ldr x10, [x16, #MMU_CFG_BUDGET_TICKS]
    cbz x10, .Lguard_expired
    cmp x9, x10
    b.hi .Lguard_expired
    mrs x9, sctlr_el1
    tbnz x9, #0, .Lguard_refused
    tbnz x9, #2, .Lguard_refused
    ldr x9, [x16, #MMU_CFG_BOOTSTRAP_START_PA]
    cmp x25, x9
    b.ne .Lguard_refused
    add x9, x9, #0x1000
    cmp x3, x9
    b.ne .Lguard_refused
    /* Check every 2MiB block touched by the owned clean range under both
     * aliases, plus its final byte. This covers later cache maintenance. */
    ldr x19, [x16, #MMU_CFG_CLEAN_START_PA]
    ldr x20, [x16, #MMU_CFG_CLEAN_END_PA]
    ldr x21, [x16, #MMU_CFG_KERNEL_PHYS_BASE]
    ldr x22, [x16, #MMU_CFG_KERNEL_VIRT_BASE]
.Lguard_range:
    mov x0, x19
    mov x1, x19
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    sub x0, x19, x21
    add x0, x0, x22
    mov x1, x19
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    and x19, x19, #0xffffffffffe00000
    add x19, x19, #0x200, lsl #12
    cmp x19, x20
    b.lo .Lguard_range
    sub x19, x20, #1
    mov x0, x19
    mov x1, x19
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    sub x0, x19, x21
    add x0, x0, x22
    mov x1, x19
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    /* Explicit code/vector/argument/stack pairs make the guarded contract
     * auditable even though the extent check also covers these blocks. */
    ldr x0, [x16, #MMU_CFG_KERNEL_STARTUP_VA]
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x0, [x16, #MMU_CFG_EXPECTED_ARM_INIT_VA]
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x0, [x16, #MMU_CFG_LOW_VECTORS_VA]
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x0, [x16, #MMU_CFG_HIGH_VECTORS_VA]
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x0, [x16, #MMU_CFG_BLOB_VA]
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x0, [x16, #MMU_CFG_EXPECTED_ARGS_VA]
    ldr x1, [x16, #MMU_CFG_EXPECTED_ARGS_PA]
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x9, [x16, #MMU_CFG_BOOT_ARGS_SIZE]
    cbz x9, .Lguard_refused
    sub x9, x9, #1
    ldr x0, [x16, #MMU_CFG_EXPECTED_ARGS_VA]
    ldr x1, [x16, #MMU_CFG_EXPECTED_ARGS_PA]
    add x0, x0, x9
    add x1, x1, x9
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x0, [x16, #MMU_CFG_ADT_VA]
    ldr x1, [x16, #MMU_CFG_ADT_PA]
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    ldr x9, [x16, #MMU_CFG_ADT_SIZE]
    cbz x9, .Lguard_refused
    sub x9, x9, #1
    ldr x0, [x16, #MMU_CFG_ADT_VA]
    ldr x1, [x16, #MMU_CFG_ADT_PA]
    add x0, x0, x9
    add x1, x1, x9
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    mrs x23, SPSel
    msr SPSel, #0
    mov x19, sp
    msr SPSel, #1
    mov x20, sp
    msr SPSel, x23
    ldr x9, [x16, #MMU_CFG_EXPECTED_SP0_VA]
    cmp x19, x9
    b.ne .Lguard_refused
    ldr x9, [x16, #MMU_CFG_EXPECTED_SP1_VA]
    cmp x20, x9
    b.ne .Lguard_refused
    sub x0, x19, #16
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    sub x0, x20, #16
    sub x1, x0, x22
    add x1, x1, x21
    bl .Lwalk_pair
    cbnz x0, .Lguard_refused
    isb
    mrs x9, cntvct_el0
    ldr x10, [x16, #MMU_CFG_BUDGET_START_TICKS]
    sub x9, x9, x10
    str x9, [x16, #MMU_OBS_ELAPSED_TICKS]
    ldr x10, [x16, #MMU_CFG_BUDGET_TICKS]
    cbz x10, .Lguard_expired
    cmp x9, x10
    b.hi .Lguard_expired
    mov x9, #1
    str x9, [x16, #MMU_OBS_GUARD_PASSED]
    ldr x9, [x16, #MMU_CFG_GUARD_RESUME_PA]
    str x9, [x16, #MMU_OBS_GUARD_RESUME_PC]
    ldr x9, [x16, #(MMU_SCRATCH + 248)]
    msr nzcv, x9
    ldr x0, [x28, #(MMU_SCRATCH + 0)]
    ldr x1, [x28, #(MMU_SCRATCH + 8)]
    ldr x2, [x28, #(MMU_SCRATCH + 16)]
    ldr x3, [x28, #(MMU_SCRATCH + 24)]
    ldr x4, [x28, #(MMU_SCRATCH + 32)]
    ldr x5, [x28, #(MMU_SCRATCH + 40)]
    ldr x6, [x28, #(MMU_SCRATCH + 48)]
    ldr x7, [x28, #(MMU_SCRATCH + 56)]
    ldr x8, [x28, #(MMU_SCRATCH + 64)]
    ldr x9, [x28, #(MMU_SCRATCH + 72)]
    ldr x10, [x28, #(MMU_SCRATCH + 80)]
    ldr x11, [x28, #(MMU_SCRATCH + 88)]
    ldr x12, [x28, #(MMU_SCRATCH + 96)]
    ldr x13, [x28, #(MMU_SCRATCH + 104)]
    ldr x14, [x28, #(MMU_SCRATCH + 112)]
    ldr x15, [x28, #(MMU_SCRATCH + 120)]
    ldr x16, [x28, #(MMU_SCRATCH + 128)]
    ldr x17, [x28, #(MMU_SCRATCH + 136)]
    ldr x18, [x28, #(MMU_SCRATCH + 144)]
    ldr x19, [x28, #(MMU_SCRATCH + 152)]
    ldr x20, [x28, #(MMU_SCRATCH + 160)]
    ldr x21, [x28, #(MMU_SCRATCH + 168)]
    ldr x22, [x28, #(MMU_SCRATCH + 176)]
    ldr x23, [x28, #(MMU_SCRATCH + 184)]
    ldr x24, [x28, #(MMU_SCRATCH + 192)]
    ldr x25, [x28, #(MMU_SCRATCH + 200)]
    ldr x26, [x28, #(MMU_SCRATCH + 208)]
    ldr x27, [x28, #(MMU_SCRATCH + 216)]
    ldr x28, [x28, #(MMU_SCRATCH + 224)]
    ldr x29, [x28, #(MMU_SCRATCH + 232)]
    ldr x30, [x28, #(MMU_SCRATCH + 240)]
    dsb sy
.global mmu_bridge_guard_resume
mmu_bridge_guard_resume:
    /* Loader MUST patch this one immediate B to original common_start PA. */
    b mmu_bridge_park

/* Independent physical walker for the pinned 38-bit, 4KiB L1 -> 2MiB L2
 * bootstrap format. x0=VA, x1=required PA, x16=context. Returns x0=0/1.
 * Table pointers must stay inside the 16-page owned bootstrap pool; exact
 * leaf attributes require privileged RW, AF=1, normal AttrIndx0, PXN=0. */
.Lwalk_pair:
    str x0, [x16, #MMU_OBS_GUARD_FAILURE_VA]
    str xzr, [x16, #MMU_OBS_GUARD_FAILURE_DESCRIPTOR]
    /* T0SZ=T1SZ=26: reject noncanonical aliases rather than masking them
     * into a superficially matching root index. IPS=2 permits 40-bit PA. */
    lsr x4, x0, #38
    cbz x4, .Lwalk_canonical
    mov x5, #0x3ffffff
    cmp x4, x5
    b.ne .Lwalk_bad
.Lwalk_canonical:
    lsr x4, x1, #40
    cbnz x4, .Lwalk_bad
    ldr x4, [x16, #MMU_CFG_CLEAN_START_PA]
    cmp x1, x4
    b.lo .Lwalk_bad
    ldr x4, [x16, #MMU_CFG_CLEAN_END_PA]
    cmp x1, x4
    b.hs .Lwalk_bad
    ldr x4, [x16, #MMU_OBS_GUARD_TTBR0]
    tbz x0, #63, .Lwalk_root
    ldr x4, [x16, #MMU_OBS_GUARD_TTBR1]
.Lwalk_root:
    ldr x5, [x16, #MMU_CFG_BOOTSTRAP_START_PA]
    ldr x6, [x16, #MMU_CFG_BOOTSTRAP_END_PA]
    cmp x4, x5
    b.lo .Lwalk_bad
    add x7, x4, #0x1000
    cmp x7, x6
    b.hi .Lwalk_bad
    tst x4, #0xfff
    b.ne .Lwalk_bad
    ubfx x7, x0, #30, #8
    ldr x8, [x4, x7, lsl #3]
    str x8, [x16, #MMU_OBS_GUARD_FAILURE_DESCRIPTOR]
    and x4, x8, #0x000000fffffff000
    orr x7, x4, #3
    cmp x8, x7
    b.ne .Lwalk_bad
    cmp x4, x5
    b.lo .Lwalk_bad
    add x7, x4, #0x1000
    cmp x7, x6
    b.hi .Lwalk_bad
    ubfx x7, x0, #21, #9
    ldr x8, [x4, x7, lsl #3]
    str x8, [x16, #MMU_OBS_GUARD_FAILURE_DESCRIPTOR]
    and x7, x1, #0x000000ffffe00000
    movz x9, #0x601
    movk x9, #0x40, lsl #48
    orr x7, x7, x9
    cmp x8, x7
    b.ne .Lwalk_bad
    eor x7, x0, x1
    tst x7, #0x1fffff
    b.ne .Lwalk_bad
    ldr x7, [x16, #MMU_OBS_GUARD_CHECKS]
    add x7, x7, #1
    str x7, [x16, #MMU_OBS_GUARD_CHECKS]
    str xzr, [x16, #MMU_OBS_GUARD_FAILURE_VA]
    str xzr, [x16, #MMU_OBS_GUARD_FAILURE_DESCRIPTOR]
    mov x0, #0
    ret
.Lwalk_bad:
    mov x0, #1
    ret
.Lguard_expired:
    mov x9, #1
    str x9, [x16, #MMU_OBS_BUDGET_EXPIRED]
.Lguard_refused:
    mov x9, #MMU_STATUS_TABLE_REFUSED
    str x9, [x16, #MMU_OBS_STATUS]
    adr x9, mmu_bridge_guard
    str x9, [x16, #MMU_OBS_OBSERVER_PC]
    ldr x9, [x16, #MMU_SCRATCH]
    str x9, [x16, #MMU_OBS_X0]
    ldr x9, [x16, #(MMU_SCRATCH + 160)]
    str x9, [x16, #MMU_OBS_X20]
    ldr x9, [x16, #(MMU_SCRATCH + 168)]
    str x9, [x16, #MMU_OBS_X21]
    ldr x9, [x16, #(MMU_SCRATCH + 240)]
    str x9, [x16, #MMU_OBS_X30]
    b .Lcapture_common

/* Diagnostic VBAR handoff. The early high-VBAR MSR is patched to NOP;
 * original SCTLR write + ISB execute unmodified before this hook. x28 is
 * still the physical context pointer, valid through the guarded identity map.
 * Preserve every GPR/NZCV except the replayed original MOVK's x1 result. */
.global mmu_bridge_after_mmu
mmu_bridge_after_mmu:
    str x16, [x28, #MMU_AFTER_MMU_X16]
    str x17, [x28, #MMU_AFTER_MMU_X17]
    adr x17, mmu_bridge_after_mmu
    str x17, [x28, #MMU_AFTER_MMU_PC]
    mrs x16, sctlr_el1
    str x16, [x28, #MMU_AFTER_MMU_SCTLR]
    tbz x16, #0, .Lafter_mmu_refused
    tbz x16, #2, .Lafter_mmu_refused
    tbz x16, #12, .Lafter_mmu_refused
    ldr x17, [x28, #MMU_CFG_HIGH_VECTORS_VA]
    msr vbar_el1, x17
    isb
    mrs x17, vbar_el1
    str x17, [x28, #MMU_AFTER_MMU_VBAR]
    ldr x16, [x28, #MMU_AFTER_MMU_X16]
    ldr x17, [x28, #MMU_AFTER_MMU_X17]
    movk x1, #0, lsl #48
.global mmu_bridge_after_mmu_resume
mmu_bridge_after_mmu_resume:
    /* Loader MUST patch this B to physical original file offset0x501368. */
    b mmu_bridge_park
.Lafter_mmu_refused:
    adr x16, mmu_bridge_context
    str x0, [x16, #MMU_OBS_X0]
    str x20, [x16, #MMU_OBS_X20]
    str x21, [x16, #MMU_OBS_X21]
    str x30, [x16, #MMU_OBS_X30]
    adr x9, mmu_bridge_after_mmu
    str x9, [x16, #MMU_OBS_OBSERVER_PC]
    mov x9, #MMU_STATUS_REFUSED
    str x9, [x16, #MMU_OBS_STATUS]
    b .Lcapture_common

/* Private B at arm_init's original SUB SP,SP,#0xd0 enters here under
 * the native MMU. Pinned startup has enabled CPACR.FPEN and used no SIMD;
 * x28 still names the embedded context's guarded identity alias. Preserve
 * every GPR and NZCV, replay SUB, then resume at original arm_init+4.
 * No stack memory or FP/SIMD state is modified by the snapshot itself. */
.global mmu_bridge_fp_snapshot
mmu_bridge_fp_snapshot:
    str x9, [x28, #MMU_FP_SNAPSHOT_X9]
    str x16, [x28, #MMU_FP_SNAPSHOT_X16]
    str x17, [x28, #MMU_FP_SNAPSHOT_X17]
    mrs x9, nzcv
    str x9, [x28, #MMU_FP_SNAPSHOT_NZCV]
    mrs x16, cpacr_el1
    str x16, [x28, #MMU_FP_SNAPSHOT_CPACR]
    ubfx x17, x16, #20, #2
    cmp x17, #3
    b.ne .Lfp_snapshot_refused
    adr x16, mmu_bridge_context
    adr x9, mmu_bridge_fp_snapshot
    str x9, [x16, #MMU_FP_SNAPSHOT_PC]
    add x17, x16, #MMU_FP_Q_BEFORE
    stp q0, q1, [x17, #0]
    stp q2, q3, [x17, #32]
    stp q4, q5, [x17, #64]
    stp q6, q7, [x17, #96]
    stp q8, q9, [x17, #128]
    stp q10, q11, [x17, #160]
    stp q12, q13, [x17, #192]
    stp q14, q15, [x17, #224]
    stp q16, q17, [x17, #256]
    stp q18, q19, [x17, #288]
    stp q20, q21, [x17, #320]
    stp q22, q23, [x17, #352]
    stp q24, q25, [x17, #384]
    stp q26, q27, [x17, #416]
    stp q28, q29, [x17, #448]
    stp q30, q31, [x17, #480]
    mrs x9, fpcr
    str x9, [x16, #MMU_FPCR_BEFORE]
    mrs x9, fpsr
    str x9, [x16, #MMU_FPSR_BEFORE]
    mov x9, #1
    str x9, [x16, #MMU_FP_SAVED]
    ldr x9, [x28, #MMU_FP_SNAPSHOT_NZCV]
    msr nzcv, x9
    ldr x9, [x28, #MMU_FP_SNAPSHOT_X9]
    ldr x16, [x28, #MMU_FP_SNAPSHOT_X16]
    ldr x17, [x28, #MMU_FP_SNAPSHOT_X17]
    sub sp, sp, #0xd0
.global mmu_bridge_fp_resume
mmu_bridge_fp_resume:
    /* Loader MUST patch this immediate B to virtual original arm_init+4. */
    b mmu_bridge_park
.Lfp_snapshot_refused:
    adr x16, mmu_bridge_context
    str x0, [x16, #MMU_OBS_X0]
    str x20, [x16, #MMU_OBS_X20]
    str x21, [x16, #MMU_OBS_X21]
    str x30, [x16, #MMU_OBS_X30]
    adr x9, mmu_bridge_fp_snapshot
    str x9, [x16, #MMU_OBS_OBSERVER_PC]
    mov x9, #MMU_STATUS_REFUSED
    str x9, [x16, #MMU_OBS_STATUS]
    b .Lcapture_common

.global mmu_bridge_bootstrap_fatal
mmu_bridge_bootstrap_fatal:
    adr x16, mmu_bridge_context
    str x0, [x16, #MMU_OBS_X0]
    str x20, [x16, #MMU_OBS_X20]
    str x21, [x16, #MMU_OBS_X21]
    str x30, [x16, #MMU_OBS_X30]
    mov x9, #1
    str x9, [x16, #MMU_OBS_BOOTSTRAP_FATAL]
    mov x9, #MMU_STATUS_BOOTSTRAP_FATAL
    str x9, [x16, #MMU_OBS_STATUS]
    adr x9, mmu_bridge_bootstrap_fatal
    str x9, [x16, #MMU_OBS_OBSERVER_PC]
    b .Lcapture_common

.global mmu_bridge_observer
mmu_bridge_observer:
    adr x16, mmu_bridge_context
    str x0, [x16, #MMU_OBS_X0]
    str x20, [x16, #MMU_OBS_X20]
    str x21, [x16, #MMU_OBS_X21]
    str x30, [x16, #MMU_OBS_X30]
    adr x9, mmu_bridge_observer
    str x9, [x16, #MMU_OBS_OBSERVER_PC]
    mov x9, #MMU_STATUS_ARM_INIT
    str x9, [x16, #MMU_OBS_STATUS]
    mov x9, #-1
    str x9, [x16, #MMU_OBS_EXCEPTION_SLOT]
    b .Lcapture_common

.global mmu_bridge_fault_common
mmu_bridge_fault_common:
    adr x16, mmu_bridge_context
    mrs x9, esr_el1
    str x9, [x16, #MMU_OBS_SECONDARY_ESR]
    mrs x9, far_el1
    str x9, [x16, #MMU_OBS_SECONDARY_FAR]
    mrs x9, elr_el1
    str x9, [x16, #MMU_OBS_SECONDARY_ELR]
    ldr x9, [x16, #MMU_OBS_FAULT_DEPTH]
    add x9, x9, #1
    str x9, [x16, #MMU_OBS_FAULT_DEPTH]
    cmp x9, #1
    b.hi .Lnested_fault
    str x17, [x16, #MMU_OBS_EXCEPTION_SLOT]
    str x0, [x16, #MMU_OBS_X0]
    str x20, [x16, #MMU_OBS_X20]
    str x21, [x16, #MMU_OBS_X21]
    str x30, [x16, #MMU_OBS_X30]
    adr x9, mmu_bridge_fault_common
    str x9, [x16, #MMU_OBS_OBSERVER_PC]
    ldr x9, [x16, #MMU_OBS_PHASE]
    str x9, [x16, #MMU_OBS_FAULT_PHASE]
    mov x9, #MMU_STATUS_EXCEPTION
    str x9, [x16, #MMU_OBS_STATUS]
    b .Lcapture_common
.Lnested_fault:
    mov x9, #MMU_STATUS_NESTED_EXCEPTION
    str x9, [x16, #MMU_OBS_STATUS]
    dsb sy
    b mmu_bridge_park

.Lcapture_common:
    OBS_SYS nzcv, MMU_OBS_NZCV
    OBS_SYS daif, MMU_OBS_DAIF
    msr daifset, #15
    mov x9, #3
    str x9, [x16, #MMU_OBS_PHASE]
    mrs x10, SPSel
    str x10, [x16, #MMU_OBS_SPSEL]
    msr SPSel, #0
    mov x9, sp
    str x9, [x16, #MMU_OBS_SP_EL0]
    msr SPSel, #1
    mov x9, sp
    str x9, [x16, #MMU_OBS_SP_EL1]
    msr SPSel, x10
    OBS_SYS sctlr_el1, MMU_OBS_SCTLR
    OBS_SYS tcr_el1, MMU_OBS_TCR
    OBS_SYS ttbr0_el1, MMU_OBS_TTBR0
    OBS_SYS ttbr1_el1, MMU_OBS_TTBR1
    OBS_SYS mair_el1, MMU_OBS_MAIR
    OBS_SYS vbar_el1, MMU_OBS_VBAR
    OBS_SYS cpacr_el1, MMU_OBS_CPACR
    OBS_SYS contextidr_el1, MMU_OBS_CONTEXTIDR
    OBS_SYS tpidr_el1, MMU_OBS_TPIDR_EL1
    OBS_SYS tpidr_el0, MMU_OBS_TPIDR_EL0
    OBS_SYS tpidrro_el0, MMU_OBS_TPIDRRO_EL0
    OBS_SYS esr_el1, MMU_OBS_ESR
    OBS_SYS far_el1, MMU_OBS_FAR
    OBS_SYS elr_el1, MMU_OBS_ELR
    OBS_SYS spsr_el1, MMU_OBS_SPSR
    OBS_SYS cntvct_el0, MMU_OBS_CNTVCT
    ldr x9, [x16, #MMU_OBS_SCTLR]
    tbz x9, #0, .Lto_identity
    adr x9, mmu_bridge_observer
    OBS_AT MMU_OBS_PAR_CODE
    ldr x9, [x16, #MMU_CFG_EXPECTED_ARGS_VA]
    OBS_AT MMU_OBS_PAR_ARGS
    ldr x9, [x16, #MMU_OBS_SP_EL0]
    sub x9, x9, #16
    OBS_AT MMU_OBS_PAR_SP0
    ldr x9, [x16, #MMU_OBS_SP_EL1]
    sub x9, x9, #16
    OBS_AT MMU_OBS_PAR_SP1
    adr x9, mmu_bridge_identity
    adr x10, mmu_bridge_start
    sub x9, x9, x10
    ldr x10, [x16, #MMU_CFG_BLOB_PA]
    add x9, x9, x10
    OBS_AT MMU_OBS_PAR_IDENTITY
.Lto_identity:
    adr x9, mmu_bridge_identity
    adr x10, mmu_bridge_start
    sub x9, x9, x10
    ldr x10, [x16, #MMU_CFG_BLOB_PA]
    add x9, x9, x10
    br x9

/* This code MUST execute at VA==PA before M is cleared. ADR now yields PA.
 * The independent pre-MMU guard verified the identity alias, permissions,
 * and every block subsequently touched by the clean/invalidate loop. */
.global mmu_bridge_identity
mmu_bridge_identity:
    adr x16, mmu_bridge_context
    adr x9, mmu_bridge_identity
    str x9, [x16, #MMU_OBS_IDENTITY_PC]
    mov x9, #4
    str x9, [x16, #MMU_OBS_PHASE]
    adr x9, mmu_bridge_vectors
    msr vbar_el1, x9
    isb
    mrs x9, sctlr_el1
    tbz x9, #2, .Ldisable_mci
    mov x9, #5
    str x9, [x16, #MMU_OBS_PHASE]
    ldr x10, [x16, #MMU_CFG_CLEAN_START_PA]
    ldr x11, [x16, #MMU_CFG_CLEAN_END_PA]
    mrs x12, ctr_el0
    ubfx x12, x12, #16, #4
    mov x13, #4
    lsl x12, x13, x12
    sub x13, x12, #1
    bic x10, x10, x13
    dsb sy
.Lclean_owned:
    dc civac, x10
    add x10, x10, x12
    cmp x10, x11
    b.lo .Lclean_owned
.Ldisable_mci:
    /* No stores after the clean loop until C is disabled. */
    dsb sy
    ic iallu
    dsb sy
    isb
    mrs x9, sctlr_el1
    bic x9, x9, #1
    bic x9, x9, #4
    bic x9, x9, #0x1000
    msr sctlr_el1, x9
    isb
    mov x9, #6
    str x9, [x16, #MMU_OBS_PHASE]
    tlbi vmalle1
    dsb sy
    isb
.Lrestore_physical:
    /* The original caller contract is M=0,C=0; no low caller access occurs
     * before this physical restore. Keep our physical VBAR until last. */
    RESTORE_SYS ttbr0_el1, MMU_SAVE_TTBR0
    RESTORE_SYS ttbr1_el1, MMU_SAVE_TTBR1
    RESTORE_SYS mair_el1, MMU_SAVE_MAIR
    RESTORE_SYS amair_el1, MMU_SAVE_AMAIR
    RESTORE_SYS tcr_el1, MMU_SAVE_TCR
    dsb sy
    tlbi vmalle1
    dsb sy
    isb
    /* Early refusal/fault cannot have changed SIMD. Once C was allowed to
     * run, restore every Q and both FP controls before disabling FP access.
     * Readbacks are actual registers after restoration, not copied input. */
    ldr x9, [x16, #MMU_FP_SAVED]
    cbz x9, .Lfp_restore_done
    mrs x9, cpacr_el1
    orr x9, x9, #0x300000
    msr cpacr_el1, x9
    isb
    add x17, x16, #MMU_FP_Q_BEFORE
    ldp q0, q1, [x17, #0]
    ldp q2, q3, [x17, #32]
    ldp q4, q5, [x17, #64]
    ldp q6, q7, [x17, #96]
    ldp q8, q9, [x17, #128]
    ldp q10, q11, [x17, #160]
    ldp q12, q13, [x17, #192]
    ldp q14, q15, [x17, #224]
    ldp q16, q17, [x17, #256]
    ldp q18, q19, [x17, #288]
    ldp q20, q21, [x17, #320]
    ldp q22, q23, [x17, #352]
    ldp q24, q25, [x17, #384]
    ldp q26, q27, [x17, #416]
    ldp q28, q29, [x17, #448]
    ldp q30, q31, [x17, #480]
    ldr x9, [x16, #MMU_FPCR_BEFORE]
    msr fpcr, x9
    ldr x9, [x16, #MMU_FPSR_BEFORE]
    msr fpsr, x9
    add x17, x16, #MMU_FP_Q_AFTER
    stp q0, q1, [x17, #0]
    stp q2, q3, [x17, #32]
    stp q4, q5, [x17, #64]
    stp q6, q7, [x17, #96]
    stp q8, q9, [x17, #128]
    stp q10, q11, [x17, #160]
    stp q12, q13, [x17, #192]
    stp q14, q15, [x17, #224]
    stp q16, q17, [x17, #256]
    stp q18, q19, [x17, #288]
    stp q20, q21, [x17, #320]
    stp q22, q23, [x17, #352]
    stp q24, q25, [x17, #384]
    stp q26, q27, [x17, #416]
    stp q28, q29, [x17, #448]
    stp q30, q31, [x17, #480]
    mrs x9, fpcr
    str x9, [x16, #MMU_FPCR_AFTER]
    mrs x9, fpsr
    str x9, [x16, #MMU_FPSR_AFTER]
.Lfp_restore_done:
    RESTORE_SYS cpacr_el1, MMU_SAVE_CPACR
    isb
    RESTORE_SYS contextidr_el1, MMU_SAVE_CONTEXTIDR
    RESTORE_SYS tpidr_el1, MMU_SAVE_TPIDR_EL1
    RESTORE_SYS tpidr_el0, MMU_SAVE_TPIDR_EL0
    RESTORE_SYS tpidrro_el0, MMU_SAVE_TPIDRRO_EL0
    RESTORE_SYS csselr_el1, MMU_SAVE_CSSELR
    RESTORE_SYS par_el1, MMU_SAVE_PAR
    RESTORE_SYS elr_el1, MMU_SAVE_ELR
    RESTORE_SYS spsr_el1, MMU_SAVE_SPSR
    RESTORE_SYS esr_el1, MMU_SAVE_ESR
    RESTORE_SYS far_el1, MMU_SAVE_FAR
    RESTORE_SYS cntkctl_el1, MMU_SAVE_CNTKCTL
    isb
    OBS_SYS cntkctl_el1, MMU_OBS_RESTORED_CNTKCTL
    ldr x10, [x16, #MMU_SAVE_FEATURES]
    tbz x10, #0, .Lrestore_uao
    RESTORE_SYS pan, MMU_SAVE_PAN
    OBS_SYS pan, MMU_OBS_RESTORED_PAN
.Lrestore_uao:
    tbz x10, #1, .Lrestore_stacks
    RESTORE_SYS uao, MMU_SAVE_UAO
    OBS_SYS uao, MMU_OBS_RESTORED_UAO
.Lrestore_stacks:
    ldr x9, [x16, #MMU_SAVE_SP_EL0]
    msr SPSel, #0
    mov sp, x9
    str x9, [x16, #MMU_OBS_RESTORED_SP0]
    ldr x9, [x16, #MMU_SAVE_SP_EL1]
    msr SPSel, #1
    mov sp, x9
    str x9, [x16, #MMU_OBS_RESTORED_SP1]
    ldr x9, [x16, #MMU_SAVE_SPSEL]
    msr SPSel, x9
    str x9, [x16, #MMU_OBS_RESTORED_SPSEL]
    dsb sy
    ic iallu
    dsb sy
    isb
    RESTORE_SYS sctlr_el1, MMU_SAVE_SCTLR
    isb
    OBS_SYS sctlr_el1, MMU_OBS_RESTORED_SCTLR
    OBS_SYS tcr_el1, MMU_OBS_RESTORED_TCR
    OBS_SYS ttbr0_el1, MMU_OBS_RESTORED_TTBR0
    OBS_SYS ttbr1_el1, MMU_OBS_RESTORED_TTBR1
    OBS_SYS mair_el1, MMU_OBS_RESTORED_MAIR
    RESTORE_SYS vbar_el1, MMU_SAVE_VBAR
    isb
    OBS_SYS vbar_el1, MMU_OBS_RESTORED_VBAR
    mov x9, #7
    str x9, [x16, #MMU_OBS_PHASE]
    mov x9, #1
    str x9, [x16, #MMU_OBS_RETURNED]
    dsb sy
.Lrestore_gprs:
    RESTORE_SYS nzcv, MMU_SAVE_NZCV
    RESTORE_SYS daif, MMU_SAVE_DAIF
    mrs x9, nzcv
    str x9, [x16, #MMU_POST_NZCV]
    mrs x9, daif
    str x9, [x16, #MMU_POST_DAIF]
    ldr x0, [x16, #MMU_OBS_STATUS]
    ldr x1, [x16, #(MMU_GPR + 8)]
    ldr x2, [x16, #(MMU_GPR + 16)]
    ldr x3, [x16, #(MMU_GPR + 24)]
    ldr x4, [x16, #(MMU_GPR + 32)]
    ldr x5, [x16, #(MMU_GPR + 40)]
    ldr x6, [x16, #(MMU_GPR + 48)]
    ldr x7, [x16, #(MMU_GPR + 56)]
    ldr x8, [x16, #(MMU_GPR + 64)]
    ldr x9, [x16, #(MMU_GPR + 72)]
    ldr x10, [x16, #(MMU_GPR + 80)]
    ldr x11, [x16, #(MMU_GPR + 88)]
    ldr x12, [x16, #(MMU_GPR + 96)]
    ldr x13, [x16, #(MMU_GPR + 104)]
    ldr x14, [x16, #(MMU_GPR + 112)]
    ldr x15, [x16, #(MMU_GPR + 120)]
    ldr x18, [x16, #(MMU_GPR + 144)]
    ldr x19, [x16, #(MMU_GPR + 152)]
    ldr x20, [x16, #(MMU_GPR + 160)]
    ldr x21, [x16, #(MMU_GPR + 168)]
    ldr x22, [x16, #(MMU_GPR + 176)]
    ldr x23, [x16, #(MMU_GPR + 184)]
    ldr x24, [x16, #(MMU_GPR + 192)]
    ldr x25, [x16, #(MMU_GPR + 200)]
    ldr x26, [x16, #(MMU_GPR + 208)]
    ldr x27, [x16, #(MMU_GPR + 216)]
    ldr x28, [x16, #(MMU_GPR + 224)]
    ldr x29, [x16, #(MMU_GPR + 232)]
    ldr x30, [x16, #(MMU_GPR + 240)]
    ldp x16, x17, [x16, #(MMU_GPR + 128)]
    ret

.global mmu_bridge_park
mmu_bridge_park:
    msr daifset, #15
    dsb sy
.Lpark:
    wfe
    b .Lpark

.balign 64
.global mmu_bridge_context
mmu_bridge_context:
    .zero MMU_BRIDGE_CONTEXT_BYTES
.global mmu_bridge_end
mmu_bridge_end:
