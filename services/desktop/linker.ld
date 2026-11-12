/* Measured bounded userspace Store fixture, with an explicitly charged16KiB
 * private RW stack. Both adjacent page holes remain absent; NX comes from the
 * RW-only PT_LOAD and ordinary loader. No boot/kernel stack is enlarged. */
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    stack PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x8000001000;
    .text : ALIGN(4096) { *(.text .text.* .ltext .ltext.*) } :text
    .rodata : ALIGN(4096) { BYTE(0); *(.rodata .rodata.* .lrodata .lrodata.*) } :rodata
    .data : ALIGN(4096) { BYTE(0); *(.data .data.* .ldata .ldata.*) *(.got .got.*) } :data
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.* .lbss .lbss.*) *(COMMON) } :data
    ASSERT(. <= 0x80000ff000, "Store image overlaps lower private-stack guard")
    . = 0x8000100000;
    .store_stack (NOLOAD) : ALIGN(4096) { . += 0x4000; } :stack
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) }
}
