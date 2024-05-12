mov cx, ax
and cx, 0x0FE0
shr cx, 5
mov [0x600000], cl
done:
FLAG: ASM{c83ee3bd4dfa3d5bf9c029de64dfcf3e796dba43}