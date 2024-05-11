11
mov eax, 0
sub eax, [0x600000]
mov ebx, [0x600004]
mul ebx
add eax, [0x600008]
done:
ASM{9534f42b2762f41d4b4c4b9b945f9995f067734b}