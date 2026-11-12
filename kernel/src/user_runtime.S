.section .text
.global ev_resume_user
ev_resume_user:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rip + ev_user_saved_rsp], rsp
    fxsave64 [rip + ev_kernel_fx]
    mov [rip + ev_active_fx], rsi
    fxrstor64 [rsi]
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov ax, 27
    mov ds, ax
    mov es, ax
    mov rax, rdi
    push qword ptr [rax + 168]
    push qword ptr [rax + 160]
    push qword ptr [rax + 152]
    push qword ptr [rax + 144]
    push qword ptr [rax + 136]
    mov r15, [rax]
    mov r14, [rax + 8]
    mov r13, [rax + 16]
    mov r12, [rax + 24]
    mov r11, [rax + 32]
    mov r10, [rax + 40]
    mov r9, [rax + 48]
    mov r8, [rax + 56]
    mov rdi, [rax + 64]
    mov rsi, [rax + 72]
    mov rbp, [rax + 80]
    mov rdx, [rax + 88]
    mov rcx, [rax + 96]
    mov rbx, [rax + 104]
    mov rax, [rax + 112]
    iretq

// Position-independent finite user programs copied into distinct RX pages.
.section .rodata
.global ev_runtime_blob
.global ev_runtime_blob_end
.global ev_runtime_good
.global ev_runtime_bad
ev_runtime_blob:
ev_runtime_good:
    mov r12, rdi
    mov r13, rdx
    mov [r12 + 48], r11
    mov [r12 + 56], r9
    mov eax, 6
    mov rdi, -1
    int 128
    cmp rax, 1
    jne runtime_fail
    call runtime_fx_init
    call runtime_allocate
    mov eax, 10
    mov rdi, -1
    mov esi, 1
    int 128
    cmp rax, 1
    jne runtime_fail
    call runtime_spin
    mov eax, 7
    mov rdi, r13
    mov esi, 1000
    int 128
    test rax, rax
    jne runtime_fail
2:
    mov eax, 0xfeedbeef
    cmp rsi, rax
    jne runtime_fail
    test rdx, rdx
    jz runtime_fail
    mov rbp, rdx
    mov r15, rdx
    mov eax, 10
    mov rdi, rbp
    mov esi, 2
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 10
    mov rdi, rbp
    mov esi, 1
    int 128
    test rax, rax
    jne runtime_fail
    mov eax, 0xdecafbad
    cmp qword ptr [r12 + 16384], rax
    jne runtime_fail
    mov eax, 4
    mov rdi, rbp
    mov esi, 2
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 4
    mov rdi, rbp
    mov esi, 1
    int 128
    test rax, rax
    jne runtime_fail
    mov eax, 7
    mov rdi, r13
    mov esi, 2
    int 128
    cmp rax, 4
    jne runtime_fail
    mov ebp, 128
3:
    mov eax, 6
    mov rdi, [r12 + 48]
    int 128
    test rax, rax
    jz 4f
    cmp rax, 2
    jne runtime_fail
    dec ebp
    jnz 3b
    jmp runtime_fail
4:
    cmp r9, 2
    jne runtime_fail
    cmp r11, 2
    jne runtime_fail
    test r8, r8
    jz runtime_fail
    mov rax, [r12 + 56]
    cmp rax, 1
    je runtime_fault_pf
    cmp rax, 2
    je runtime_fault_gp
    cmp rsi, 6
    jne runtime_fail
    jmp runtime_fault_nonpf
runtime_fault_gp:
    cmp rsi, 13
    jne runtime_fail
runtime_fault_nonpf:
    test rdx, rdx
    jnz runtime_fail
    jmp runtime_fault_ok
runtime_fault_pf:
    cmp rsi, 14
    jne runtime_fail
    test rdx, 4
    jz runtime_fail
    test rcx, rcx
    jnz runtime_fail
runtime_fault_ok:
    mov eax, 6
    mov rdi, [r12 + 48]
    int 128
    cmp rax, 2
    jne runtime_fail
    mov eax, 9
    mov rdi, r10
    int 128
    test rax, rax
    jne runtime_fail
    mov r14, rdx
    mov eax, 4
    mov rdi, r14
    mov esi, 1
    int 128
    test rax, rax
    jne runtime_fail
    mov eax, 4
    mov rdi, r14
    mov esi, 2
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 9
    mov rdi, r10
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 11
    mov rdi, r15
    int 128
    test rax, rax
    jne runtime_fail
    mov eax, 10
    mov rdi, r15
    mov esi, 1
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 4
    mov rdi, r14
    mov esi, 1
    int 128
    test rax, rax
    jne runtime_fail
    call runtime_fx_check
    cmp qword ptr [r12], 0x11111111
    jne runtime_fail
    cmp qword ptr [r12 + 8], 0
    je runtime_fail
    mov eax, 1
    xor edi, edi
    int 128
    ud2

ev_runtime_bad:
    mov r12, rdi
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    call runtime_fx_init
    mov eax, 0xdecafbad
    mov qword ptr [r12 + 16384], rax
    call runtime_spin
    mov ebp, 128
10:
    mov eax, 8
    int 128
    cmp rax, 1
    je 11f
    dec ebp
    jnz 10b
    jmp runtime_fail
11:
    mov rax, -1
    int 128
    cmp rax, 3
    jne runtime_fail
    mov eax, 2
    mov rdi, -1
    xor esi, esi
    xor edx, edx
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 2
    mov rdi, r13
    mov esi, 0xfeedbeef
    mov rdx, r14
    int 128
    test rax, rax
    jne runtime_fail
    mov eax, 4
    mov rdi, r14
    mov esi, 1
    int 128
    cmp rax, 1
    jne runtime_fail
    call runtime_fx_check
    cmp qword ptr [r12], 0x22222222
    jne runtime_fail
    cmp r15, 1
    je 5f
    cmp r15, 2
    je 6f
    ud2
5:
    xor eax, eax
    mov rax, [rax]
    jmp runtime_fail
6:
    cli
    jmp runtime_fail
runtime_spin:
    mov ebp, 128
7:
    mov ecx, 10000
8:
    inc qword ptr [r12 + 8]
    pause
    loop 8b
    mov eax, 5
    int 128
    call runtime_fx_check
    cmp rax, 2
    jae 9f
    dec ebp
    jnz 7b
    jmp runtime_fail
9:
    ret
runtime_allocate:
    mov eax, 12
    mov rdi, -1
    int 128
    cmp rax, 1
    jne runtime_fail
    mov ebp, 2
runtime_allocate_again:
    mov eax, 12
    mov rdi, rbx
    int 128
    test rax, rax
    jne runtime_fail
    mov r14, rdx
    mov rdi, rsi
    mov ecx, 512
runtime_zero_check:
    cmp qword ptr [rdi], 0
    jne runtime_fail
    mov qword ptr [rdi], -1
    add rdi, 8
    loop runtime_zero_check
    mov eax, 12
    mov rdi, rbx
    int 128
    cmp rax, 2
    jne runtime_fail
    mov eax, 13
    mov rdi, -1
    int 128
    cmp rax, 1
    jne runtime_fail
    mov eax, 13
    mov rdi, r14
    int 128
    test rax, rax
    jne runtime_fail
    mov eax, 13
    mov rdi, r14
    int 128
    cmp rax, 1
    jne runtime_fail
    dec ebp
    jnz runtime_allocate_again
    ret
runtime_fx_init:
    // Initial state must not reveal a previous user or controller context.
    movq rax, xmm0
    test rax, rax
    jnz runtime_fail
    movq rax, xmm15
    test rax, rax
    jnz runtime_fail
    fnstcw word ptr [r12 + 40]
    cmp word ptr [r12 + 40], 0x037f
    jne runtime_fail
    stmxcsr dword ptr [r12 + 40]
    cmp dword ptr [r12 + 40], 0x1f80
    jne runtime_fail
    movq xmm0, [r12]
    movq xmm15, [r12]
    fild dword ptr [r12]
    mov eax, [r12]
    and eax, 3
    shl eax, 13
    or eax, 0x1f80
    mov [r12 + 24], eax
    ldmxcsr dword ptr [r12 + 24]
    mov eax, [r12]
    and eax, 3
    shl eax, 10
    or eax, 0x037f
    mov [r12 + 32], ax
    fldcw word ptr [r12 + 32]
    ret
runtime_fx_check:
    push rax
    movq rax, xmm0
    cmp rax, [r12]
    jne runtime_fail
    movq rax, xmm15
    cmp rax, [r12]
    jne runtime_fail
    fist dword ptr [r12 + 16]
    mov eax, [r12 + 16]
    cmp eax, [r12]
    jne runtime_fail
    stmxcsr dword ptr [r12 + 28]
    mov eax, [r12 + 28]
    cmp eax, [r12 + 24]
    jne runtime_fail
    fnstcw word ptr [r12 + 34]
    mov ax, [r12 + 34]
    cmp ax, [r12 + 32]
    jne runtime_fail
    pop rax
    ret
runtime_fail:
    mov eax, 1
    mov edi, 99
    int 128
    ud2
.global ev_runtime_revoked_read
ev_runtime_revoked_read:
    mov rax, [rdi]
    ud2
ev_runtime_blob_end:
