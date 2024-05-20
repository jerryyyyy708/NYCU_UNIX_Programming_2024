mov eax, [0x600000]
add eax, [0x600004]
mov ebx, eax
mov eax, [0x600008]
mul ebx
mov [0x60000c], eax
done:
ASM{a7c9b6aeffcded4c9f08ef4bc27178735cefba9c}