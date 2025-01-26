extern puts
extern _GLOBAL_OFFSET_TABLE_

default rel

section .text
global main:function (main.end - main)

%macro set_ebx_to_GOT_addr 0.nolist
    call __x86.get_pc_thunk.bx
%%.loc:
    add ebx, _GLOBAL_OFFSET_TABLE_ + $$ - %%.loc wrt ..gotpc
%endmacro

main:
    ; get `hello` address in a position-independent way, to be PIE compatible
    set_ebx_to_GOT_addr
    lea eax, [ebx + hello wrt ..gotoff]

    push eax
    call puts wrt ..plt     ; call through PLT, to be PIE compatible
    add esp, 0x4

    xor eax, eax
    ret
.end:

__x86.get_pc_thunk.bx:
    mov ebx, [esp]
    ret

section .data
    hello db "Hello, world!"
