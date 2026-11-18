/* Selected M8 Display: code/data below source's absent lower guard at page63;
 * readonly source ranges64..434 are mapped by the actual Kernel factory.
 * Private32KiB stack480..487 has absent guards479/488. */
ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); rodata PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); stack PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x8000001000;
    .text : ALIGN(4096) { *(.text .text.* .ltext .ltext.*) } :text
    .rodata : ALIGN(4096) { BYTE(0); *(.rodata .rodata.* .lrodata .lrodata.*) } :rodata
    .data : ALIGN(4096) { BYTE(0); *(.data .data.* .ldata .ldata.*) *(.got .got.*) } :data
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.* .lbss .lbss.*) *(COMMON) } :data
    ASSERT(. <= 0x800003f000, "M8 Display code/data intersects Files absent guard at page63")
    . = 0x80001e0000;
    .workspace_display_stack (NOLOAD) : ALIGN(4096) { . += 0x8000; } :stack
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) }
}
