/* layout.ld is generated from the immutable normal boot Image header. */
INCLUDE layout.ld
ENTRY(chain_entry)
SECTIONS {
    __image_base = 0;
    . = LINUX_EFFECTIVE_SIZE;
    _tail_start = .;
    .text : { *(.text.entry) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    . = ALIGN(16);
    _bss_start = .;
    .bss : { *(.bss*) *(COMMON) }
    _bss_end = .;
    . = ALIGN(16);
    . += 0x8000;
    _stack_top = .;
    ASSERT(_stack_top <= DTB_OFFSET, "probe code/data/stack exceeds tail prefix")
    . = DTB_OFFSET;
    _dtb_buffer = .;
    . += DTB_CAPACITY;
    _chain_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
