.intel_syntax noprefix
.text

.globl main
.type main, @function
main:
    push ebp
    mov ebp, esp

    sub esp, 72

    lea esi, [ebp-64]
    push esi
    call pthread_attr_init

    push 0
    push OFFSET FLAT:thread_start
    push esi
    lea eax, [ebp-72]
    push eax
    call pthread_create

    add esp, 16
    call pthread_attr_destroy

    lea eax, [ebp-68]
    push eax
    push DWORD PTR [ebp-72]
    call pthread_join

    push DWORD PTR [ebp-68]
    call free

    xor eax, eax
    leave
    ret
 .size main, .-main

.type thread_start, @function
thread_start:
    push ebp
    mov ebp, esp

    push 4
    call malloc
    mov DWORD PTR [eax], 7

    leave
    ret
 .size thread_start, .-thread_start
