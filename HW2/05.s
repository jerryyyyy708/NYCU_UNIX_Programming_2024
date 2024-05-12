mov cx, 16
lea rdi, [0x600000]

convert_loop:
    shl ax, 1
    jc set_one
    mov byte ptr [rdi], '0'
    jmp short store_char

set_one:
    mov byte ptr [rdi], '1'

store_char:
    inc rdi
    dec cx
    jnz convert_loop

done:
FLAG: ASM{c609df1bcca537262c0569ff1465831f6c77aeed}
