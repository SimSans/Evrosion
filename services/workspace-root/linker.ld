/* Selected V5 Root retains its independent legacy Root stack location; package
 * banks, protected source, catalogue, windows and all guards remain absent. */
ENTRY(_start)
PHDRS {text PT_LOAD FLAGS(5);rodata PT_LOAD FLAGS(4);data PT_LOAD FLAGS(6);stack PT_LOAD FLAGS(6);}
SECTIONS {
 . = 0x8000001000;
 .text : ALIGN(4096) {*(.text .text.* .ltext .ltext.*)} :text
 .rodata : ALIGN(4096) {BYTE(0);*(.rodata .rodata.* .lrodata .lrodata.*)} :rodata
 .data : ALIGN(4096) {BYTE(0);*(.data .data.* .ldata .ldata.*) *(.got .got.*)} :data
 .bss (NOLOAD) : ALIGN(4096) {*(.bss .bss.* .lbss .lbss.*) *(COMMON)} :data
 ASSERT(. <= 0x80000ff000,"Root data intersects absent stack lower guard255")
 . = 0x8000100000;
 .workspace_root_stack (NOLOAD) : ALIGN(4096) { . += 0x8000; } :stack
 /DISCARD/ : {*(.eh_frame .eh_frame_hdr) *(.comment)}
}
