.intel_syntax noprefix
.text

.globl main
.type main, @function
main:
    push rbp
    mov rbp, rsp

    sub rsp, 80

    lea rdi, [rbp-64]
    call pthread_attr_init

    lea rdi, [rbp-72]
    lea rsi, [rbp-64]
    mov edx, OFFSET FLAT:thread_start
    xor rcx, rcx
    call pthread_create

    lea rdi, [rbp-64]
    call pthread_attr_destroy

    mov rdi, QWORD PTR [rbp-72]
    lea rsi, [rbp-80]
    call pthread_join

    mov rdi, QWORD PTR [rbp-80]
    call free

    xor rax, rax
    leave
    ret
.size main, .-main

.type thread_start, @function
thread_start:
    push rbp
    mov rbp, rsp

    mov rdi, 4
    call malloc
    mov DWORD PTR [rax], 7

    leave
    ret
.size thread_start, .-thread_start
