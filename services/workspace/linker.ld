/* V5 Workspace image; private eight-page stack480..487, guards479/488. */
ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); rodata PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); stack PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x8000001000;
    .text : ALIGN(4096) { *(.text .text.* .ltext .ltext.*) } :text
    .rodata : ALIGN(4096) { BYTE(0); *(.rodata .rodata.* .lrodata .lrodata.*) } :rodata
    .data : ALIGN(4096) { BYTE(0); *(.data .data.* .ldata .ldata.*) *(.got .got.*) } :data
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.* .lbss .lbss.*) *(COMMON) } :data
    ASSERT(. <= 0x80001df000, "Workspace image overlaps lower stack guard")
    . = 0x80001e0000;
    .workspace_stack (NOLOAD) : ALIGN(4096) { . += 0x8000; } :stack
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) }
}
