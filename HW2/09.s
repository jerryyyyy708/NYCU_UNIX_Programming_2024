mov esi, 0x600000
mov edi, 0x600010
mov ecx, 15

convert_loop:
    movzx eax, byte ptr [esi]
    cmp eax, 'Z'
    jnl no_conv
    cmp eax, 'A'
    jge no_conv
    add eax, 32
no_conv:
    mov [edi], eax
    inc esi
    inc edi
    loop convert_loop
done:
FLAG: ASM{4c4197f81627b0c5f442e4ddaebec65809071811}