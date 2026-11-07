ENTRY(mmu_vm_gate_checkpoint)
SECTIONS {
  . = 0xfffffff007500800;
  .text : { KEEP(*(.text.vm_gate)) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
  ASSERT(ADDR(.text) == 0xfffffff007500800, "VM gate cave origin changed")
  ASSERT(SIZEOF(.text) <= 0x800, "VM gate exceeds verified RX padding")
}
