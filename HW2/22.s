cmp CH, 'A'
jg conv

add CH, 32
jmp good

conv:
sub CH, 32

good:
sub CH, 0
done: