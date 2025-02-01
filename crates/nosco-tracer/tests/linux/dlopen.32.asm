extern dlopen, dlclose
extern _GLOBAL_OFFSET_TABLE_

%define RTLD_LAZY 0x1

default rel

section .text
global main:function (main.end - main)

%macro set_ebx_to_GOT_addr 0.nolist
    call __x86.get_pc_thunk.bx
%%.loc:
    add ebx, _GLOBAL_OFFSET_TABLE_ + $$ - %%.loc wrt ..gotpc
%endmacro

main:
    push ebp
    mov ebp, esp

    ; get `libm` address in a position-independent way, to be PIE compatible
    set_ebx_to_GOT_addr
    lea eax, [ebx + libm wrt ..gotoff]

    mov ecx, RTLD_LAZY
    push ecx
    push eax
    call dlopen wrt ..plt     ; call through PLT, to be PIE compatible
    add esp, 0x8

    push eax
    call dlclose wrt ..plt
    add esp, 0x4

    pop ebp
    ret
.end:

__x86.get_pc_thunk.bx:
    mov ebx, [esp]
    ret

section .data
    libm db "libm.so.6"
