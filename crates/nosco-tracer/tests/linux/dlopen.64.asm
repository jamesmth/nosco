extern dlopen, dlclose

%define RTLD_LAZY 0x1

default rel

section .text
global main:function (main.end - main)

main:
    push rbp
    mov rbp, rsp
    lea rdi, [libm]
    mov rsi, RTLD_LAZY
    call dlopen wrt ..plt     ; call through PLT, to be PIE compatible
    mov rdi, rax
    call dlclose wrt ..plt
    pop rbp
    ret
.end:

section .data
    libm db "libm.so.6"
