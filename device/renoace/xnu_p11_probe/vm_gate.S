/* P11 recovery gate: continue after VM, second PE return, then recover after FIQ. */
#include "mmu_bridge.h"
#include "vm_gate_layout.h"
#include "p11_gate_layout.h"
.arch armv8.2-a
.section .text.vm_gate,"ax",%progbits
.balign 4
.global mmu_vm_gate_start, mmu_vm_gate_checkpoint, mmu_vm_gate_end
.set p11_context_address, mmu_vm_gate_start + (VM_GATE_CONTEXT_VA - 0xfffffff007500800)
.set p11_observer_address, mmu_vm_gate_start + (VM_GATE_OBSERVER_VA - 0xfffffff007500800)
.set p11_fault_common_address, mmu_vm_gate_start + (VM_GATE_FAULT_COMMON_VA - 0xfffffff007500800)
mmu_vm_gate_start:
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
    adrp x16, p11_context_address
    add x16, x16, :lo12:p11_context_address
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
    ldr x9, [x16, #P11_PHASE]
    cbz x9, .Lphase0
    cmp x9, #1
    b.ne .Lrestore
    tbnz x17, #63, .Lsecond_continue
    b .Lrestore
.Lphase0:
    tbnz x17, #63, .Lcontinue
.Lrestore:
    dsb sy
    ldr x9, [x16, #MMU_OBS_GUARD_TTBR0]
    msr ttbr0_el1, x9
    ldr x9, [x16, #MMU_OBS_GUARD_TTBR1]
    msr ttbr1_el1, x9
    isb
    tlbi vmalle1is
    dsb ish
    isb
    VM_OBS ttbr0_el1, MMU_VM_RESTORED_TTBR0
    VM_OBS ttbr1_el1, MMU_VM_RESTORED_TTBR1
    mov x9, #1
    str x9, [x16, #MMU_VM_GATE_COMPLETED]
    ldr x9, [x16, #MMU_VM_NZCV]
    msr nzcv, x9
    tbnz x17, #63, .Lrestore_observer
    b p11_fault_common_address
.Lrestore_observer:
    b p11_observer_address
.Lcontinue:
    mov x9, #1
    str x9, [x16, #P11_PHASE]
    /* Reproduce the displaced post-arm_vm_init ADRP/ADD/LDR without PC-relative
     * execution at the patched site, then continue the original arm_init body. */
    movz x9, #0x1000
    movk x9, #0x71a, lsl #16
    movk x9, #0xfff0, lsl #32
    movk x9, #0xffff, lsl #48
    mov x8, x9
    ldr w8, [x8, #P11_DISPLACED_OFF]
    ldr x9, [x16, #MMU_VM_NZCV]
    msr nzcv, x9
    ldr x9, [x16, #MMU_VM_DAIF]
    msr daif, x9
    movz x9, #0x3e40
    movk x9, #0x7b3, lsl #16
    movk x9, #0xfff0, lsl #32
    movk x9, #0xffff, lsl #48
    br x9
.Lsecond_continue:
    /* The second-PE return gate displaces `mov x0,x19`.  Continue the
     * original arm_init body after that instruction and stop at the patched
     * return from fiq_context_init. Refuse to cross the FIQ path if the
     * captured DAIF did not have all four mask bits set. */
    ldr x9, [x16, #MMU_VM_DAIF]
    tst x9, #0x3c0
    b.eq .Lrestore
    mov x0, x19
    mov x9, #2
    str x9, [x16, #P11_PHASE]
    ldr x9, [x16, #MMU_VM_NZCV]
    msr nzcv, x9
    ldr x9, [x16, #MMU_VM_DAIF]
    msr daif, x9
    movz x9, #0x3fb0
    movk x9, #0x7b3, lsl #16
    movk x9, #0xfff0, lsl #32
    movk x9, #0xffff, lsl #48
    br x9
mmu_vm_gate_end:
