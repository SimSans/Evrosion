ENTRY(_start)
PHDRS {text PT_LOAD FLAGS(5);rodata PT_LOAD FLAGS(4);data PT_LOAD FLAGS(6);stack PT_LOAD FLAGS(6);}
SECTIONS {
 . = 0x8000001000;
 .text : ALIGN(4096) {*(.text .text.* .ltext .ltext.*)} :text
 .rodata : ALIGN(4096) {BYTE(0);*(.rodata .rodata.* .lrodata .lrodata.*)} :rodata
 .data : ALIGN(4096) {BYTE(0);*(.data .data.* .ldata .ldata.*) *(.got .got.*)} :data
 .bss (NOLOAD) : ALIGN(4096) {*(.bss .bss.* .lbss .lbss.*) *(COMMON)} :data
 . = 0x8000100000;
 .private_stack (NOLOAD) : { . += 0x4000; } :stack
 /DISCARD/ : {*(.eh_frame .eh_frame_hdr) *(.comment)}
}
