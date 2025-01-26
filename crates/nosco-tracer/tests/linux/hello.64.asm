extern puts

default rel

section .text
global main:function (main.end - main)

main:
    lea rdi, [hello]
    call puts wrt ..plt     ; call through PLT, to be PIE compatible
    xor rax, rax
    ret
.end:

section .data
    hello db "Hello, world!"
