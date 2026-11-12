.section .text
.global _start
_start:
    and rsp, -16
    call ev_root_main
    ud2
.global memcpy
memcpy:
    mov rax, rdi
    mov rcx, rdx
    rep movsb
    ret
.global memset
memset:
    mov r8, rdi
    mov eax, esi
    mov rcx, rdx
    rep stosb
    mov rax, r8
    ret
.global memmove
memmove:
    mov rax, rdi
    mov rcx, rdx
    cmp rdi, rsi
    jbe 1f
    test rcx, rcx
    jz 2f
    lea rdi, [rdi+rcx-1]
    lea rsi, [rsi+rcx-1]
    std
    rep movsb
    cld
    ret
1:  rep movsb
2:  ret
.global memcmp
memcmp:
    xor eax, eax
    test rdx, rdx
    jz 2f
1:  movzx eax, byte ptr [rdi]
    movzx ecx, byte ptr [rsi]
    sub eax, ecx
    jne 2f
    inc rdi
    inc rsi
    dec rdx
    jnz 1b
2:  ret
