section .text

global main:function (main.end - main)
global func1:function (func1.end - func1)
global func2:function (func2.end - func2)
global func3:function (func3.end - func3)
global func4:function (func4.end - func4)
global func5:function (func5.end - func5)

main:
    push rbp
    mov rbp, rsp
    call func1
    xor rax, rax
    pop rbp
    ret
.end:

func1:
    call func2
    ret
.end:

func2:
    push rbp
    mov rbp, rsp
    push rax     ; enlarge the stack, for test purposes
    call func3
    pop rax
    pop rbp
    ret
.end:

func3:
    push rbp
    mov rbp, rsp
    call func4
    pop rbp
    ret
.end:

func4:
    call func5
    ret
.end:

func5:
    ret
.end:
