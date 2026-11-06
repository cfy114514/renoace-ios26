/* P02 diagnostic bridge. The Linux image remains at its original load address.
 * This object is linked at LINUX_EFFECTIVE_SIZE, inside the expanded Image.
 * The entry word of Linux branches here; finish restores that word and size.
 */
#include "layout.h"
.section .text.entry, "ax"
.global chain_entry
chain_entry:
    msr daifset, #0xf
    mov x19, x0
    mov x20, sp
    mrs x21, SPSel
    mrs x24, CurrentEL
    adrp x27, __image_base
    add x27, x27, :lo12:__image_base
    cmp x24, #4
    b.eq 1f
    cmp x24, #8
    b.ne chain_park
    mrs x22, vbar_el2
    mrs x23, sctlr_el2
    b 2f
1:  mrs x22, vbar_el1
    mrs x23, sctlr_el1
2:  /* The AArch64 Linux entry contract requires M=0 and C=0. */
    mov x9, #5
    tst x23, x9
    b.ne chain_park
    adrp x10, chain_context
    add x10, x10, :lo12:chain_context
    stp x19, x20, [x10, #0]
    stp x21, x22, [x10, #16]
    stp x24, x23, [x10, #32]
    stp x27, xzr, [x10, #48]
    msr SPSel, #1
    adrp x9, _stack_top
    add x9, x9, :lo12:_stack_top
    mov sp, x9
    adrp x9, chain_vectors
    add x9, x9, :lo12:chain_vectors
    cmp x24, #4
    b.ne 3f
    msr vbar_el1, x9
    b 4f
3:  msr vbar_el2, x9
4:  isb
    mov x0, x19
    mov x1, x27
    bl chain_main
    b chain_finish

.macro slot
    .balign 0x80
    b chain_abort
.endm
.balign 0x800
chain_vectors:
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot
    slot

.global chain_abort
chain_abort:
    adrp x10, chain_context
    add x10, x10, :lo12:chain_context
    ldr x9, [x10, #56]
    cbnz x9, chain_park
    mov x9, #1
    str x9, [x10, #56]
    ldr x0, [x10]                 /* Original FDT; no partially built clone. */
    b chain_finish

.global chain_finish
chain_finish:
    mov x26, x0                  /* New FDT on success, original on refusal. */
    adrp x10, chain_context
    add x10, x10, :lo12:chain_context
    ldr x11, [x10, #48]
    /* C is off. Discard a possible stale cache line BEFORE restoring bytes. */
    dsb sy
    dc ivac, x11
    dsb sy
    movz w12, #(LINUX_ORIGINAL_CODE0 & 0xffff)
    movk w12, #(LINUX_ORIGINAL_CODE0 >> 16), lsl #16
    str w12, [x11]
    movz x12, #(LINUX_EFFECTIVE_SIZE & 0xffff)
    movk x12, #(LINUX_EFFECTIVE_SIZE >> 16), lsl #16
    str x12, [x11, #16]
    dsb sy
    dc cvac, x11
    dsb sy
    ic iallu
    dsb sy
    isb
    ldp x21, x22, [x10, #16]
    ldr x24, [x10, #32]
    ldr x20, [x10, #8]
    cmp x24, #4
    b.ne 5f
    msr vbar_el1, x22
    b 6f
5:  msr vbar_el2, x22
6:  isb
    msr SPSel, x21
    mov sp, x20
    mov x0, x26
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    br x11                       /* Restored, exact Linux entry; never reset. */

.global chain_park
chain_park:
    wfe
    b chain_park

.section .data.context, "aw"
.balign 16
.global chain_context
chain_context:
    .zero 64
