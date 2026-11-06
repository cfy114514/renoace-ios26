/* AAPCS wrapper around the pinned seven-instruction XNU entry control.
 * Full GPR snapshot; x0 returns status. Linux/probe SP, LR, NZCV and DAIF
 * are restored. Only the private RAM copy of XNU has the RET gate.
 */
.text
.global xnu_gate_call
xnu_gate_call:
    sub sp, sp, #0x200
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x3, nzcv
    str x3, [sp, #248]
    str x3, [x2, #80]
    mrs x3, daif
    str x3, [sp, #256]
    str x3, [x2, #96]
    mov x3, sp
    str x3, [x2, #32]
    mrs x3, vbar_el1
    str x3, [x2, #48]
    mrs x3, sctlr_el1
    str x3, [x2, #64]
    mrs x3, oslsr_el1
    str x3, [x2, #112]
    tbnz x3, #1, xnu_restore
    mov x16, x0
    mov x0, x1
.global xnu_actual_blr
xnu_actual_blr:
    blr x16
.global xnu_return_checkpoint
xnu_return_checkpoint:
    ldr x9, [sp, #16]
    str x0, [x9, #8]
    str x20, [x9, #16]
    str x21, [x9, #24]
    mov x10, sp
    str x10, [x9, #40]
    mrs x10, vbar_el1
    str x10, [x9, #56]
    mrs x10, sctlr_el1
    str x10, [x9, #72]
    mrs x10, nzcv
    str x10, [x9, #88]
    mrs x10, daif
    str x10, [x9, #104]
    mrs x10, oslsr_el1
    str x10, [x9, #120]
    mov x10, #1
    str x10, [x9, #0]
.global xnu_restore
xnu_restore:
    ldr x10, [sp, #256]
    msr daif, x10
    ldr x10, [sp, #248]
    msr nzcv, x10
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    ldr x1, [sp, #8]
    add sp, sp, #0x200
    mov x0, #0
    ret
