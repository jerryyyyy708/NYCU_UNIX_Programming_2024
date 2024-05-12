mov eax, [0x600000]
imul eax, eax, -5
mov esi, eax
mov eax, [0x600004]
neg eax
cdq
idiv dword ptr [0x600008]
mov ecx, edx
mov eax, esi
cdq
idiv ecx
mov [0x60000c], eax
done:

FLAG: ASM{8bfd9c41bced0fa842f1e28049f286fa2edd9b88}