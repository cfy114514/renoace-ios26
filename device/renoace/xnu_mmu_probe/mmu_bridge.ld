ENTRY(mmu_bridge_entry)
SECTIONS {
  . = 0;
  .text : { KEEP(*(.text.mmu_bridge)) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
  ASSERT(SIZEOF(.text) <= 0x10000, "MMU bridge exceeds reserved 64KiB")
}
