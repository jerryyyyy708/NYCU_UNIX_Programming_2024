cmp CH, 'A'
jg conv

add CH, 32
jmp good

conv:
sub CH, 32

good:
sub CH, 0
done:
FLAG: ASM{c13f14b69f1f42229067722759fe54db168a42f2}