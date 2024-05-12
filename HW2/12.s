mov eax, dword ptr [0x600000]
mov ebx, 5
mul ebx
mov ecx, dword ptr [0x600004]
sub ecx, 3  
xor edx, edx   
div ecx       
mov dword ptr [0x600008], eax 
done:
FLAG: ASM{6b9474a8fcedf00e4f9c73c52bce7f80dca9402c}