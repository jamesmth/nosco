.intel_syntax noprefix
.text

.globl main
.type main, @function
main:
    .cfi_startproc
    push rbp
    .cfi_def_cfa_offset 16
    .cfi_offset 6, -16
    mov rbp, rsp
    .cfi_def_cfa_register 6
    call func1
    xor rax, rax
    pop rbp
    .cfi_def_cfa 7, 8
    ret
    .cfi_endproc
.size main, .-main

.globl func1
.type func1, @function
func1:
    .cfi_startproc
    call func2
    ret
    .cfi_endproc
.size func1, .-func1

.globl func2
.type func2, @function
func2:
    .cfi_startproc
    push rbp
    .cfi_def_cfa_offset 16
    .cfi_offset 6, -16
    mov rbp, rsp
    .cfi_def_cfa_register 6
    sub rsp, 8               # enlarge the stack, for test purposes
    .cfi_def_cfa 7, 24
    call func3
    add rsp, 8
    .cfi_def_cfa 7, 16
    pop rbp
    .cfi_def_cfa 7, 8
    ret
    .cfi_endproc
.size func2, .-func2

.globl func3
.type func3, @function
func3:
    .cfi_startproc
    push rbp
    .cfi_def_cfa_offset 16
    .cfi_offset 6, -16
    mov rbp, rsp
    .cfi_def_cfa_register 6
    call func4
    pop rbp
    .cfi_def_cfa 7, 8
    ret
    .cfi_endproc
.size func3, .-func3

.globl func4
.type func4, @function
func4:
    .cfi_startproc
    sub rsp, 16              # enlarge the stack, for test purposes
    .cfi_def_cfa_offset 24
    call func5
    add rsp, 16
    .cfi_def_cfa_offset 8
    ret
    .cfi_endproc
.size func4, .-func4

.globl func5
.type func5, @function
func5:
    .cfi_startproc
    ret
    .cfi_endproc
.size func5, .-func5
