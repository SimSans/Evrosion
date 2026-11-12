.section .text
.macro NOERR n
ev_isr_\n:
    push 0
    push \n
    jmp ev_exception_common
.endm
.macro ERROR n
ev_isr_\n:
    push \n
    jmp ev_exception_common
.endm
.irp n,0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31,32,128,255
NOERR \n
.endr
.irp n,8,10,11,12,13,14,17,21,29,30
ERROR \n
.endr
ev_exception_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    // Save before any Rust can touch extended state. Only scheduled CPL3
    // entries own ev_active_fx; exact probes and kernel IRQs leave it null.
    test byte ptr [rsp + 144], 3
    jz 91f
    mov rax, [rip + ev_active_fx]
    test rax, rax
    jz 91f
    fxsave64 [rax]
    fxrstor64 [rip + ev_kernel_fx]
    mov qword ptr [rip + ev_active_fx], 0
    xor eax, eax
    mov fs, ax
    mov gs, ax
91:
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    call ev_exception_dispatch
    test rax, rax
    jnz ev_leave_user
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

.global ev_reload_segments
ev_reload_segments:
    push 8
    lea rax, [rip + 2f]
    push rax
    retfq
2:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    ret

.global ev_probe_read
.global ev_probe_read_site
ev_probe_read:
ev_probe_read_site:
    mov rax, [rdi]
    xor eax, eax
    ret
.global ev_probe_write
.global ev_probe_write_site
ev_probe_write:
ev_probe_write_site:
    mov qword ptr [rdi], 0x1234
    xor eax, eax
    ret
.global ev_probe_execute
ev_probe_execute:
    xor eax, eax
    jmp rdi
.global ev_probe_recovered
ev_probe_recovered:
    mov eax, 1
    ret

.section .rodata
.balign 8
.global ev_exception_stubs
ev_exception_stubs:
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,128,255
    .quad ev_isr_\n
.endr
