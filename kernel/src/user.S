.section .text
.global ev_enter_user
ev_enter_user:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rip + ev_user_saved_rsp], rsp
    mov rax, rdi
    mov r8, rsi
    mov rdi, rdx
    mov rsi, rcx
    push 27
    push r8
    push 2
    push 35
    push rax
    mov ax, 27
    mov ds, ax
    mov es, ax
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    iretq
.global ev_leave_user
ev_leave_user:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rsp, [rip + ev_user_saved_rsp]
    mov qword ptr [rip + ev_user_saved_rsp], 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.section .bss
.balign 8
.global ev_user_saved_rsp
ev_user_saved_rsp: .quad 0

// Copied as bytes into an RX user page; only relative internal branches.
.section .rodata
.global ev_user_blob
.global ev_user_blob_end
.global ev_user_read
.global ev_user_read_ok
.global ev_user_write
.global ev_user_write_ok
.global ev_user_execute
.global ev_user_stack
.global ev_user_stack_ok
.global ev_user_io
ev_user_blob:
ev_user_read:
    mov rax, [rdi]
    cmp rax, rsi
    jne ev_user_bad
ev_user_read_ok:
    ud2
ev_user_write:
    mov [rdi], rsi
    cmp [rdi], rsi
    jne ev_user_bad
ev_user_write_ok:
    ud2
ev_user_execute:
    jmp rdi
ev_user_stack:
    push rsi
    pop rax
    cmp rax, rsi
    jne ev_user_bad
ev_user_stack_ok:
    ud2
ev_user_io:
    out dx, al
ev_user_bad:
    ud2
ev_user_blob_end:
