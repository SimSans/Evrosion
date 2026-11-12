.section .text
.global ev_context_switch
// Same privileged CR3 and IF=0; kernel target uses soft-float, no SIMD.
ev_context_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, [rsi]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.global ev_context_register_probe
ev_context_register_probe:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov rbp, rdi
    lea rbx, [rdi + 1]
    lea r12, [rdi + 2]
    lea r13, [rdi + 3]
    lea r14, [rdi + 4]
    lea r15, [rdi + 5]
    call ev_thread_yield
    mov rax, [rsp]
    cmp rbp, rax
    jne 1f
    inc rax
    cmp rbx, rax
    jne 1f
    inc rax
    cmp r12, rax
    jne 1f
    inc rax
    cmp r13, rax
    jne 1f
    inc rax
    cmp r14, rax
    jne 1f
    inc rax
    cmp r15, rax
    jne 1f
    mov eax, 1
    jmp 2f
1:
    xor eax, eax
2:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
