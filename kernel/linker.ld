/* Internal x86-64 M0 layout. The temporary loader maps this static ELF. */
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0xffffffff80000000;
    __ev_kernel_start = .;
    .text : ALIGN(4096) { *(.text .text.*) } :text
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) } :rodata
    .bootloader-config : ALIGN(8) { KEEP(*(.bootloader-config)) } :rodata
    .data : ALIGN(4096) { *(.data .data.*) *(.got .got.*) } :data
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.*) *(COMMON) } :data
    . = ALIGN(4096);
    __ev_kernel_end = .;
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) }
}
