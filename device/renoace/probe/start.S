/* AArch64 Linux Image entry. No Linux, UFS or firmware writes are included. */
.section .text.head, "ax"
.global _head
_head:
    b _start
    .long 0
    .quad 0x80000
    .quad _end
    .quad 0xa
    .quad 0, 0, 0
    .ascii "ARM\x64"
    .long 0

.text
.global _start
_start:
    msr daifset, #0xf
    mov x19, x0
    msr spsel, #1
    adrp x1, _stack_top
    add x1, x1, :lo12:_stack_top
    mov sp, x1
    adrp x1, _bss_start
    add x1, x1, :lo12:_bss_start
    adrp x2, _bss_end
    add x2, x2, :lo12:_bss_end
1:  cmp x1, x2
    b.hs 2f
    str xzr, [x1], #8
    b 1b
2:  adrp x1, vectors
    add x1, x1, :lo12:vectors
    mrs x2, CurrentEL
    cmp x2, #4
    b.ne 3f
    msr vbar_el1, x1
    b 4f
3:  cmp x2, #8
    b.ne reset_now
    msr vbar_el2, x1
4:  isb
    mov x0, x19
    bl probe_main
    b reset_now

.macro vector slot
    .balign 0x80
    mov x0, #\slot
    b probe_exception
.endm
.balign 0x800
vectors:
    vector 0
    vector 1
    vector 2
    vector 3
    vector 4
    vector 5
    vector 6
    vector 7
    vector 8
    vector 9
    vector 10
    vector 11
    vector 12
    vector 13
    vector 14
    vector 15

.global reset_now
reset_now:
    dsb sy
    movz x0, #9
    movk x0, #0x8400, lsl #16
    smc #0
/* If PSCI returns, lower PS_HOLD only after C verified board and PON setup. */
.global reset_fallback
reset_fallback:
    adrp x1, reset_fallback_allowed
    add x1, x1, :lo12:reset_fallback_allowed
    ldr w1, [x1]
    cbz w1, probe_park
    movz x2, #0x4000
    movk x2, #0x0c26, lsl #16
    str wzr, [x2]
    dsb sy
.global probe_park
probe_park:
5:  wfe
    b 5b
