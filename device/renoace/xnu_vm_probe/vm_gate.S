/* P07 executable recovery gate, linked into checked original RX text padding.
 * The builder generates vm_gate_layout.h with the three absolute KVA constants.
 * ADRP+ADD and immediate B use PC-relative relocations: the corresponding PA
 * alias works too, while the normal post-VM entry always executes at a KVA.
 * No stack access and no FP/SIMD instruction occurs here. x0,x20,x21,x30 and
 * both SP banks survive. x9,x16,x17 are recovery scratch; the original caller's
 * complete GPR/NZCV state remains in MMU_GPR/MMU_SAVE_NZCV for final restoration.
 */
#include "mmu_bridge.h"
#include "vm_gate_layout.h"
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
mmu_vm_gate_end:
