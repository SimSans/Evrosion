// Copied into one retained frame below 1 MiB. Patch fields are written by BSP.
.section .rodata
.balign 16
.global ev_ap_blob
.global ev_ap_blob_end
.global ev_ap_gdt
.global ev_ap_gdtr_base
.global ev_ap_pm_target
.global ev_ap_lm_target
.global ev_ap_pm
.global ev_ap_lm
.global ev_ap_cr3
.global ev_ap_stack
.global ev_ap_entry_address
.global ev_ap_idtr_base
.code16
ev_ap_blob:
    cli
    cld
    mov ax, cs
    mov ds, ax
    movzx ebx, ax
    shl ebx, 4
    lgdt [ev_ap_gdtr_offset]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    .byte 0x66, 0xea
ev_ap_pm_target: .long 0
    .word 8
.code32
ev_ap_pm:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov eax, [ebx + ev_ap_cr3_offset]
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x900
    wrmsr
    mov eax, cr0
    and eax, 0x9fffffff
    or eax, 0x80010001
    mov cr0, eax
    .byte 0xea
ev_ap_lm_target: .long 0
    .word 24
.code64
ev_ap_lm:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov rsp, [rip + ev_ap_stack]
    and rsp, -16
    sub rsp, 8
    mov qword ptr [rsp], 0
    lidt [rip + ev_ap_idtr]
    mov rax, [rip + ev_ap_entry_address]
    jmp rax
.balign 8
ev_ap_gdt:
    .quad 0
    .quad 0x00cf9b000000ffff
    .quad 0x00cf93000000ffff
    .quad 0x00af9b000000ffff
ev_ap_gdtr:
    .word 31
ev_ap_gdtr_base: .long 0
ev_ap_idtr:
    .word 4095
ev_ap_idtr_base: .quad 0
.balign 8
ev_ap_cr3: .quad 0
ev_ap_stack: .quad 0
ev_ap_entry_address: .quad 0
ev_ap_blob_end:
.set ev_ap_gdtr_offset, ev_ap_gdtr - ev_ap_blob
.set ev_ap_cr3_offset, ev_ap_cr3 - ev_ap_blob

.section .text
.global ev_ap_fault
ev_ap_fault:
    cli
    lock or dword ptr [rip + ev_ap_failure], 1
1:  hlt
    jmp 1b
