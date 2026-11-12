/* Internal discipline fixture: code plus two measured private thread stacks.
   BASE=0x8000000000; unmapped pages255,257,259 guard each stack1/stack2 side.
   Ordinary primary stack remains loader-owned page511 with guard510. */
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    stack1 PT_LOAD FLAGS(6);
    stack2 PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x8000001000;
    .text : ALIGN(4096) { *(.text .text.* .ltext .ltext.*) } :text
    .rodata : ALIGN(4096) { BYTE(0); *(.rodata .rodata.* .lrodata .lrodata.*) } :rodata
    .data : ALIGN(4096) { BYTE(0); *(.data .data.* .ldata .ldata.*) *(.got .got.*) } :data
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.* .lbss .lbss.*) *(COMMON) } :data
    . = 0x8000100000;
    .thread_stack1 (NOLOAD) : ALIGN(4096) { . += 4096; } :stack1
    . = 0x8000102000;
    .thread_stack2 (NOLOAD) : ALIGN(4096) { . += 4096; } :stack2
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) }
}
