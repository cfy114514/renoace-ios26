/* P09 OFFLINE GCC-read-only gate, based on the P07 executable recovery gate.
 * The builder generates vm_gate_layout.h with the three absolute KVA constants.
 * ADRP+ADD and immediate B use PC-relative relocations: the corresponding PA
 * alias works too, while the normal post-VM entry always executes at a KVA.
 * The normal-only P08 call borrows the checked XNU stack, saves/restores Q0..31,
 * FPCR/FPSR and the observer inputs. Fault entries bypass the I/O call. x0,x20,x21,x30 and
 * both SP banks survive. x9,x16,x17 are recovery scratch; the original caller's
 * complete GPR/NZCV state remains in MMU_GPR/MMU_SAVE_NZCV for final restoration.
 */
#include "mmu_bridge.h"
#include "vm_gate_layout.h"
#include "io_snapshot.h"
#include "smmu_record.h"
#include "io_gate_layout.h"
.arch armv8.2-a
.section .text.vm_gate,"ax",%progbits
.balign 4
.global mmu_vm_gate_start, mmu_vm_gate_checkpoint, mmu_vm_gate_end
mmu_vm_gate_start:
.set mmu_vm_gate_context_address, mmu_vm_gate_start + (VM_GATE_CONTEXT_VA - 0xfffffff007500800)
.set mmu_vm_gate_observer_address, mmu_vm_gate_start + (VM_GATE_OBSERVER_VA - 0xfffffff007500800)
.set mmu_vm_gate_fault_common_address, mmu_vm_gate_start + (VM_GATE_FAULT_COMMON_VA - 0xfffffff007500800)
mmu_vm_gate_checkpoint:
    mov x17, #-1
    b mmu_vm_gate_common

.macro VM_FAULT n
.global mmu_vm_gate_fault_\n
mmu_vm_gate_fault_\n:
    mov x17, #\n
    b mmu_vm_gate_common
.endm
VM_FAULT 0
VM_FAULT 1
VM_FAULT 2
VM_FAULT 3
VM_FAULT 4
VM_FAULT 5
VM_FAULT 6
VM_FAULT 7
VM_FAULT 8
VM_FAULT 9
VM_FAULT 10
VM_FAULT 11
VM_FAULT 12
VM_FAULT 13
VM_FAULT 14
VM_FAULT 15

.macro VM_OBS reg, off
    mrs x9, \reg
    str x9, [x16, #\off]
.endm

.global mmu_vm_gate_common
mmu_vm_gate_common:
    /* None of the instructions before NZCV/DAIF capture changes flags. */
    adrp x16, mmu_vm_gate_context_address
    add x16, x16, :lo12:mmu_vm_gate_context_address
    str x17, [x16, #MMU_VM_GATE_KIND]
    VM_OBS nzcv, MMU_VM_NZCV
    VM_OBS daif, MMU_VM_DAIF
    msr daifset, #15
    mov x9, #1
    str x9, [x16, #MMU_VM_GATE_ENTERED]
    adr x9, mmu_vm_gate_common
    str x9, [x16, #MMU_VM_GATE_PC]
    VM_OBS ttbr0_el1, MMU_VM_TTBR0
    VM_OBS ttbr1_el1, MMU_VM_TTBR1
    VM_OBS cntkctl_el1, MMU_VM_CNTKCTL
    VM_OBS sctlr_el1, MMU_VM_SCTLR
    VM_OBS tcr_el1, MMU_VM_TCR
    VM_OBS mair_el1, MMU_VM_MAIR
    tbnz x17, #63, mmu_io_snapshot
.global mmu_io_snapshot_return
mmu_io_snapshot_return:
    ldr x9, [x16, #MMU_VM_SCTLR]
    tbz x9, #0, .Lvm_gate_tail
    /* These are the roots independently verified by the original table guard,
     * never MMU_SAVE_TTBR*: the saved native caller entered with M=0.
     * The gate text/context map to the same PAs in both translations. Keep
     * execution here until the global TLB invalidation has completed.
     */
    dsb sy
    ldr x9, [x16, #MMU_OBS_GUARD_TTBR0]
    msr ttbr0_el1, x9
    ldr x9, [x16, #MMU_OBS_GUARD_TTBR1]
    msr ttbr1_el1, x9
    isb
    tlbi vmalle1is
    dsb ish
    isb
.Lvm_gate_tail:
    VM_OBS ttbr0_el1, MMU_VM_RESTORED_TTBR0
    VM_OBS ttbr1_el1, MMU_VM_RESTORED_TTBR1
    mov x9, #1
    str x9, [x16, #MMU_VM_GATE_COMPLETED]
    ldr x17, [x16, #MMU_VM_GATE_KIND]
    tbnz x17, #63, .Lvm_gate_observer
    ldr x9, [x16, #MMU_VM_NZCV]
    msr nzcv, x9
    b mmu_vm_gate_fault_common_address
.Lvm_gate_observer:
    ldr x9, [x16, #MMU_VM_NZCV]
    msr nzcv, x9
    b mmu_vm_gate_observer_address

/* Only normal checkpoint entry reaches this function. No USB/controller/PHY/
 * SMMU/DMA register is accessed. The sole MMIO instruction is LDR W12 below.
 * ml_io_map is the original kernel function and executes under XNU's new roots.
 */
.global mmu_io_snapshot, mmu_io_map_call, mmu_io_map_return, mmu_io_read
.set io_ml_io_map_address, mmu_vm_gate_start + (IO_ML_IO_MAP_VA - 0xfffffff007500800)
.set io_vss_address, mmu_vm_gate_start + (IO_VIRTUAL_SPACE_START_VA - 0xfffffff007500800)
.set io_startup_address, mmu_vm_gate_start + (IO_STARTUP_PHASE_VA - 0xfffffff007500800)
mmu_io_snapshot:
    movz x9, #0x5244
    movk x9, #0x4343, lsl #16
    movk x9, #0x3847, lsl #32
    movk x9, #0x5030, lsl #48
    str x9, [x16, #IO_REC_MAGIC]
    mov x9, #IO_STATUS_ENTERED
    str x9, [x16, #IO_REC_STATUS]
    adr x9, mmu_io_snapshot
    str x9, [x16, #IO_REC_PC]
    mov x9, sp
    str x9, [x16, #IO_REC_SP]
    /* Prove the current stack bank/top and translation geometry before any
     * stack write. Original arm_vm_init already used this same real stack. */
    mrs x10, spsel
    cbnz x10, .Lio_refuse
    ldr x10, [x16, #MMU_CFG_EXPECTED_SP0_VA]
    sub x10, x10, #IO_ARM_INIT_FRAME_BYTES
    cmp x9, x10
    b.ne .Lio_refuse
    ldr x9, [x16, #MMU_VM_SCTLR]
    tbz x9, #0, .Lio_refuse
    ldr x9, [x16, #MMU_VM_TCR]
    ldr x10, [x16, #MMU_CFG_EXPECTED_TCR]
    cmp x9, x10
    b.ne .Lio_refuse
    ldr x9, [x16, #MMU_VM_MAIR]
    ldr x10, [x16, #MMU_CFG_EXPECTED_MAIR]
    cmp x9, x10
    b.ne .Lio_refuse
    adrp x9, io_startup_address
    add x9, x9, :lo12:io_startup_address
    ldr w10, [x9]
    str x10, [x16, #IO_REC_STARTUP]
    cmp w10, #5
    b.hi .Lio_refuse
    adrp x9, io_vss_address
    add x9, x9, :lo12:io_vss_address
    ldr x10, [x9]
    str x10, [x16, #IO_REC_VSS_BEFORE]
    mov x10, #IO_GCC_BYTES
    str x10, [x16, #IO_REC_BYTES]
    /* Full vector preservation: do not rely on AAPCS's partial V8..15 rule. */
    sub sp, sp, #0x280
    str x0, [sp, #0x200]
    str x19, [sp, #0x208]
    str x29, [sp, #0x210]
    str x30, [sp, #0x218]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [sp, #0x220]
    str x10, [sp, #0x228]
    mrs x9, par_el1
    str x9, [sp, #0x230]
    str x20, [sp, #0x240]
    str x21, [sp, #0x248]
    str x22, [sp, #0x250]
    str x23, [sp, #0x258]
    str x24, [sp, #0x260]
    str x25, [sp, #0x268]
    str x26, [sp, #0x270]
    str x27, [sp, #0x278]
    stp q0, q1, [sp, #0x0]
    stp q2, q3, [sp, #0x20]
    stp q4, q5, [sp, #0x40]
    stp q6, q7, [sp, #0x60]
    stp q8, q9, [sp, #0x80]
    stp q10, q11, [sp, #0xa0]
    stp q12, q13, [sp, #0xc0]
    stp q14, q15, [sp, #0xe0]
    stp q16, q17, [sp, #0x100]
    stp q18, q19, [sp, #0x120]
    stp q20, q21, [sp, #0x140]
    stp q22, q23, [sp, #0x160]
    stp q24, q25, [sp, #0x180]
    stp q26, q27, [sp, #0x1a0]
    stp q28, q29, [sp, #0x1c0]
    stp q30, q31, [sp, #0x1e0]
    mov x19, x16
    mov x0, #IO_GCC_PA
    mov x1, #IO_GCC_BYTES
    mov x9, #1
    str x9, [x19, #IO_REC_STAGE]
mmu_io_map_call:
    bl io_ml_io_map_address
mmu_io_map_return:
    str x0, [x19, #IO_REC_VA]
    adrp x9, io_vss_address
    add x9, x9, :lo12:io_vss_address
    ldr x10, [x9]
    str x10, [x19, #IO_REC_VSS_AFTER]
    cbz x0, .Lio_bad_map
    tbz x0, #63, .Lio_bad_map
    tst x0, #0xfff
    b.ne .Lio_bad_map
    /* Native AT is a guard, not a synthesized translation. Device-nGnRnE
     * PAR Attr byte must be 0; the first physical page must be GCC PA. */
    at s1e1r, x0
    isb
    mrs x9, par_el1
    str x9, [x19, #IO_REC_PAR]
    tbnz x9, #0, .Lio_bad_map
    lsr x10, x9, #56
    cbnz x10, .Lio_bad_map
    and x10, x9, #0x0000fffffffff000
    mov x11, #IO_GCC_PA
    cmp x10, x11
    b.ne .Lio_bad_map
    adr x10, .Lio_offsets
    add x11, x19, #IO_REC_VALUES
    mov x13, #0
    mov x9, #2
    str x9, [x19, #IO_REC_STAGE]
.Lio_read_loop:
    ldr w14, [x10], #4
mmu_io_read:
    ldr w12, [x0, x14]
    stp w14, w12, [x11], #8
    add x13, x13, #1
    str x13, [x19, #IO_REC_COUNT]
    cmp x13, #IO_REGISTER_COUNT
    b.lo .Lio_read_loop
    dsb sy
    mov x9, #IO_STATUS_COMPLETE
    str x9, [x19, #IO_REC_STATUS]
    b mmu_usb_inventory
.Lio_bad_map:
    mov x9, #IO_STATUS_REFUSED
    str x9, [x19, #IO_REC_STATUS]
.Lio_restore:
    ldp q0, q1, [sp, #0x0]
    ldp q2, q3, [sp, #0x20]
    ldp q4, q5, [sp, #0x40]
    ldp q6, q7, [sp, #0x60]
    ldp q8, q9, [sp, #0x80]
    ldp q10, q11, [sp, #0xa0]
    ldp q12, q13, [sp, #0xc0]
    ldp q14, q15, [sp, #0xe0]
    ldp q16, q17, [sp, #0x100]
    ldp q18, q19, [sp, #0x120]
    ldp q20, q21, [sp, #0x140]
    ldp q22, q23, [sp, #0x160]
    ldp q24, q25, [sp, #0x180]
    ldp q26, q27, [sp, #0x1a0]
    ldp q28, q29, [sp, #0x1c0]
    ldp q30, q31, [sp, #0x1e0]
    ldr x9, [sp, #0x220]
    ldr x10, [sp, #0x228]
    msr fpcr, x9
    msr fpsr, x10
    ldr x9, [sp, #0x230]
    msr par_el1, x9
    ldr x20, [sp, #0x240]
    ldr x21, [sp, #0x248]
    ldr x22, [sp, #0x250]
    ldr x23, [sp, #0x258]
    ldr x24, [sp, #0x260]
    ldr x25, [sp, #0x268]
    ldr x26, [sp, #0x270]
    ldr x27, [sp, #0x278]
    mov x16, x19
    ldr x0, [sp, #0x200]
    ldr x19, [sp, #0x208]
    ldr x29, [sp, #0x210]
    ldr x30, [sp, #0x218]
    add sp, sp, #0x280
    b mmu_io_snapshot_return
.Lio_refuse:
    mov x9, #IO_STATUS_REFUSED
    str x9, [x16, #IO_REC_STATUS]
    b mmu_io_snapshot_return
.balign 4
.Lio_offsets:
    .word 0xf004, 0xf010, 0xf014, 0xf018
    .word 0xf078, 0xf07c, 0xf050, 0x8c028

/* P09 finite conditional inventory: ordinary load-only status registers.
 * Conditions are source-based observations, never a power/security lease. */
.global mmu_usb_inventory, mmu_usb_map_call, mmu_usb_map_return
.global mmu_usb_gcc_bcr, mmu_usb_gcc_recheck
.global mmu_usb_read_id, mmu_usb_read_hw, mmu_usb_read_gctl
.global mmu_usb_read_dctl, mmu_usb_read_dsts
mmu_usb_inventory:
    movz x9, #0x5244
    movk x9, #0x5342, lsl #16
    movk x9, #0x3955, lsl #32
    movk x9, #0x5030, lsl #48
    str x9, [x19, #USB_REC_MAGIC]
    mov x9, #1
    str x9, [x19, #USB_REC_STATUS]
    str x9, [x19, #USB_REC_STAGE]
    mov x14, #0xf000
mmu_usb_gcc_bcr:
    ldr w9, [x0, x14]
    str x9, [x19, #USB_REC_BCR]
    tbnz w9, #0, .Lusb_guard_refuse
    ldr w9, [x19, #(IO_REC_VALUES+4)]
    tbz w9, #31, .Lusb_guard_refuse
    tbnz w9, #0, .Lusb_guard_refuse
    /* Six wrapper clocks; PHY auxiliary remains diagnostic only. */
    adr x10, .Lusb_clock_indices
    mov x11, #6
.Lusb_clock_guard:
    ldr w12, [x10], #4
    add x13, x19, #IO_REC_VALUES
    ldr w9, [x13, x12]
    tbz w9, #0, .Lusb_guard_refuse
    tbnz w9, #31, .Lusb_guard_refuse
    subs x11, x11, #1
    b.ne .Lusb_clock_guard
    ldr x9, [x19, #IO_REC_VSS_AFTER]
    str x9, [x19, #USB_REC_VSS_BEFORE]
    movz x0, #0xc000
    movk x0, #0xa60, lsl #16
    mov x1, #USB_CORE_BYTES
mmu_usb_map_call:
    bl io_ml_io_map_address
mmu_usb_map_return:
    str x0, [x19, #USB_REC_VA]
    adrp x9, io_vss_address
    add x9, x9, :lo12:io_vss_address
    ldr x10, [x9]
    str x10, [x19, #USB_REC_VSS_AFTER]
    cbz x0, .Lusb_map_refuse
    tbz x0, #63, .Lusb_map_refuse
    tst x0, #0xfff
    b.ne .Lusb_map_refuse
    at s1e1r, x0
    isb
    mrs x9, par_el1
    str x9, [x19, #USB_REC_PAR]
    tbnz x9, #0, .Lusb_map_refuse
    lsr x10, x9, #56
    cbnz x10, .Lusb_map_refuse
    and x10, x9, #0x0000fffffffff000
    movz x11, #0xc000
    movk x11, #0xa60, lsl #16
    cmp x10, x11
    b.ne .Lusb_map_refuse
    /* Repeat the exact GCC batch after mapping and before touching DWC3. */
    ldr x15, [x19, #IO_REC_VA]
    adr x10, .Lusb_recheck_offsets
    add x11, x19, #IO_REC_VALUES
    mov x13, #0
.Lusb_recheck_loop:
    ldr w14, [x10], #4
mmu_usb_gcc_recheck:
    ldr w9, [x15, x14]
    cmp x13, #8
    b.eq .Lusb_recheck_bcr
    ldr w12, [x11, #4]
    add x11, x11, #8
    b .Lusb_recheck_compare
.Lusb_recheck_bcr:
    ldr w12, [x19, #USB_REC_BCR]
.Lusb_recheck_compare:
    cmp w9, w12
    b.ne .Lusb_changed
    add x13, x13, #1
    cmp x13, #9
    b.lo .Lusb_recheck_loop
    mov x9, #1
    str x9, [x19, #USB_REC_COHERENT]
    mov x9, #2
    str x9, [x19, #USB_REC_STAGE]
mmu_usb_read_id:
    ldr w9, [x0, #0x120]
    str x9, [x19, #USB_REC_GSNPSID]
    mov x10, #1
    str x10, [x19, #USB_REC_COUNT]
    lsr w10, w9, #16
    mov w11, #0x5533
    cmp w10, w11
    b.eq .Lusb_id_ok
    mov w11, #0x3331
    cmp w10, w11
    b.ne .Lusb_unknown_id
.Lusb_id_ok:
mmu_usb_read_hw:
    ldr w9, [x0, #0x140]
    str x9, [x19, #USB_REC_HWPARAMS0]
    mov x10, #2
    str x10, [x19, #USB_REC_COUNT]
mmu_usb_read_gctl:
    ldr w10, [x0, #0x110]
    str x10, [x19, #USB_REC_GCTL]
    mov x11, #3
    str x11, [x19, #USB_REC_COUNT]
    tbnz w10, #11, .Lusb_role_refuse
    ubfx w11, w10, #12, #2
    cmp w11, #2
    b.ne .Lusb_role_refuse
    and w11, w9, #3
    cmp w11, #0
    b.eq .Lusb_device_ok
    cmp w11, #2
    b.ne .Lusb_role_refuse
.Lusb_device_ok:
mmu_usb_read_dctl:
    ldr w9, [x0, #0x704]
    str x9, [x19, #USB_REC_DCTL]
    mov x10, #4
    str x10, [x19, #USB_REC_COUNT]
    tbnz w9, #30, .Lusb_reset_refuse
mmu_usb_read_dsts:
    ldr w9, [x0, #0x70c]
    str x9, [x19, #USB_REC_DSTS]
    mov x10, #5
    str x10, [x19, #USB_REC_COUNT]
    dsb sy
    mov x9, #2
    str x9, [x19, #USB_REC_STATUS]
    b mmu_smmu_inventory
.Lusb_guard_refuse:
    mov x9, #3
    b .Lusb_refuse
.Lusb_unknown_id:
    mov x9, #4
    b .Lusb_refuse
.Lusb_role_refuse:
    mov x9, #5
    b .Lusb_refuse
.Lusb_reset_refuse:
    mov x9, #6
    b .Lusb_refuse
.Lusb_map_refuse:
    mov x9, #7
    b .Lusb_refuse
.Lusb_changed:
    mov x9, #8
.Lusb_refuse:
    str x9, [x19, #USB_REC_STATUS]
    str x9, [x19, #USB_REC_REASON]
    b .Lio_restore

/* P10 bounded SMMU GR0 read-only inventory.  It maps one CPU Device page,
 * reads two complete header/descriptor passes, and refuses NUMSMRG values
 * larger than the fixed context record.  No SMMU register is written. */
.global mmu_smmu_inventory
mmu_smmu_inventory:
    movz x9, #0x5553
    movk x9, #0x4d4d, lsl #16
    movk x9, #0x3150, lsl #32
    movk x9, #0x3031, lsl #48
    str x9, [x19, #SMMU_REC_MAGIC]
    mov x9, #SMMU_REC_STATUS_ENTERED
    str x9, [x19, #SMMU_REC_STATUS]
    mov x9, #SMMU_REC_STAGE_HEADERS
    str x9, [x19, #SMMU_REC_STAGE]
    ldr x9, [x19, #IO_REC_VSS_AFTER]
    str x9, [x19, #SMMU_REC_VSS_BEFORE]
    movz x0, #0
    movk x0, #0x1500, lsl #16
    mov x1, #SMMU_REC_BYTES
    bl io_ml_io_map_address
    str x0, [x19, #SMMU_REC_VA]
    adrp x9, io_vss_address
    add x9, x9, :lo12:io_vss_address
    ldr x10, [x9]
    str x10, [x19, #SMMU_REC_VSS_AFTER]
    cbz x0, .Lsmmu_refuse
    tbz x0, #63, .Lsmmu_refuse
    tst x0, #0xfff
    b.ne .Lsmmu_refuse
    mov x20, x0
    at s1e1r, x0
    isb
    mrs x9, par_el1
    str x9, [x19, #SMMU_REC_PAR]
    tbnz x9, #0, .Lsmmu_refuse
    lsr x10, x9, #56
    cbnz x10, .Lsmmu_refuse
    and x10, x9, #0x0000fffffffff000
    movz x11, #0
    movk x11, #0x1500, lsl 16
    cmp x10, x11
    b.ne .Lsmmu_refuse
    mov x9, #SMMU_REC_STAGE_ROWS
    str x9, [x19, #SMMU_REC_STAGE]
.macro SMMU_PASS base,rowbase
    ldr w9, [x20, #SMMU_REC_SCR0_OFF]
    str x9, [x19, #\base]
    ldr w10, [x20, #SMMU_REC_IDR0_OFF]
    str x10, [x19, #(\base+8)]
    ldr w11, [x20, #SMMU_REC_IDR1_OFF]
    str x11, [x19, #(\base+16)]
    cbz w10, .Lsmmu_refuse
    cmp w10, #-1
    b.eq .Lsmmu_refuse
    cbz w11, .Lsmmu_refuse
    cmp w11, #-1
    b.eq .Lsmmu_refuse
    mov x23, #0
    tbz w10, #27, .Lsmmu_sms0_\base
    and x23, x10, #0xff
.Lsmmu_sms0_\base:
    cmp x23, #SMMU_REC_MAX_ROWS
    b.hi .Lsmmu_refuse
    str x23, [x19, #SMMU_REC_COUNT]
    mov x22, x19
    mov x25, #\rowbase
    add x22, x22, x25
    mov x24, #0
.Lsmmu_rows_\base:
    cmp x24, x23
    b.hs .Lsmmu_rows_done_\base
    lsl x25, x24, #2
    add x25, x25, #SMMU_REC_SMR_OFF
    ldr w26, [x20, x25]
    lsl x25, x24, #2
    add x25, x25, #SMMU_REC_S2CR_OFF
    ldr w27, [x20, x25]
    stp w26, w27, [x22], #8
    add x24, x24, #1
    b .Lsmmu_rows_\base
.Lsmmu_rows_done_\base:
.endm
    SMMU_PASS SMMU_REC_SCR0, SMMU_REC_ROWS1
    SMMU_PASS SMMU_REC_SCR0_2, SMMU_REC_ROWS2
    mov x9, #SMMU_REC_STATUS_COMPLETE
    str x9, [x19, #SMMU_REC_STATUS]
    dsb sy
    b .Lio_restore
.Lsmmu_refuse:
    mov x9, #SMMU_REC_STATUS_REFUSED
    str x9, [x19, #SMMU_REC_STATUS]
    mov x9, #1
    str x9, [x19, #SMMU_REC_REASON]
    b .Lio_restore
.balign 4
.Lusb_clock_indices:
    .word 12,20,28,36,44,60
.Lusb_recheck_offsets:
    .word 0xf004,0xf010,0xf014,0xf018,0xf078,0xf07c,0xf050,0x8c028,0xf000
mmu_vm_gate_end:
