; var1 x -var2
mov eax, [0x600000]
mov esi, [0x600004]
neg esi
imul esi

; var3 - ebx
mov esi, [0x600008]
sub esi, ebx

cdq

; divide
idiv esi
mov [0x600008], eax
done:

FLAG: ASM{1e130521b324b3009f4dd9dcc6a32eab9ce2d36f}