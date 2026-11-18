/* M8 Editor only: one MiB resident document64..319, measured32KiB stack480..487.
 * Surface384..446, File506..507, startup509 and guards remain separate. */
ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); rodata PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); document PT_LOAD FLAGS(6); stack PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x8000001000;
    .text : ALIGN(4096) { *(.text .text.* .ltext .ltext.*) } :text
    .rodata : ALIGN(4096) { BYTE(0); *(.rodata .rodata.* .lrodata .lrodata.*) } :rodata
    .data : ALIGN(4096) { BYTE(0); *(.data .data.* .ldata .ldata.*) *(.got .got.*) } :data
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.* .lbss .lbss.*) *(COMMON) } :data
    ASSERT(. <= 0x800003f000, "Editor code overlaps resident document lower guard")
    . = 0x8000040000;
    .workspace_document (NOLOAD) : ALIGN(4096) { KEEP(*(.workspace_document)) } :document
    ASSERT(SIZEOF(.workspace_document) == 0x100000, "Editor document must be exactly1MiB")
    ASSERT(. == 0x8000140000, "Editor resident document has wrong extent")
    . = 0x80001e0000;
    .workspace_stack (NOLOAD) : ALIGN(4096) { . += 0x8000; } :stack
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) }
}
