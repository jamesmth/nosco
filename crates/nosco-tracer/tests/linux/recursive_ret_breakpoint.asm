section .text

global main:function (main.end - main)
global foo:function (foo.end - foo)

main:
    mov rdi, 2
    call foo
    xor rax, rax
    ret
.end:

foo:
    test rdi, rdi
    je .ret
    sub rdi, 1
    call foo
.ret:
    ret
.end:
