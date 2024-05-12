cmp eax, 0
jnl eax_one
mov esi, -1
mov [0x600000], esi
jmp next_op
eax_one:
mov esi, 1
mov [0x600000], esi
next_op:

cmp ebx, 0
jnl ebx_one
mov esi, -1
mov [0x600004], esi
jmp next_op2
ebx_one:
mov esi, 1
mov [0x600004], esi
next_op2:

cmp ecx, 0
jnl ecx_one
mov esi, -1
mov [0x600008], esi
jmp next_op3
ecx_one:
mov esi, 1
mov [0x600008], esi
next_op3:

cmp edx, 0
jnl edx_one
mov esi, -1
mov [0x60000c], esi
jmp next_op4
edx_one:
mov esi, 1
mov [0x60000c], esi
next_op4:

done:

FLAG: ASM{b3e3824bdba8399815c106745dea10ef63ca83d8}