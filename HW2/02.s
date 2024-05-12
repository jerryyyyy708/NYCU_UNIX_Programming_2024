mov rcx, 9

outer_loop:
    mov rsi, 0x600000
    mov rdx, 0

inner_loop:
    mov eax, [rsi+rdx*4]
    mov ebx, [rsi+rdx*4+4]
    cmp eax, ebx
    jle no_swap
    mov [rsi+rdx*4], ebx
    mov [rsi+rdx*4+4], eax

no_swap:
    add rdx, 1
    cmp rdx, rcx
    jl inner_loop

    dec rcx
    jnz outer_loop

done:
FLAG: ASM{e2899fc02f586c6e77a1b4262745f8b6c5fab572}
