mov eax, [0x600000]
add eax, [0x600004]
sub eax, [0x600008]
mov [0x60000c], eax
done:
ASM{b30ea3278ec8e1eb79f9931ebf572890df2befeb}