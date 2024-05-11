mov eax, [0x600000]
mov ebx, [0x600008]
mov [0x600000], ebx
mov [0x600008], eax
done:
ASM{792b8364a82df60255fb5dedcde8be32cc04c12f}