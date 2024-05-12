mov edi, 22
call recur
jmp good

recur:
    ; Base cases
    cmp edi, 0
    jle base_case_zero
    cmp edi, 1
    je base_case_one

    push rbx
    push rdx

    ; Calculate r(n-1)
    push rdi            
    dec edi
    call recur          
    mov rbx, rax        
    pop rdi             

    ; Calculate r(n-2)
    sub rdi, 2
    call recur          
    mov rcx, rax        

    ; 2*r(n-1) + 3*r(n-2)
    lea rax, [rbx+rbx] 
    lea rdx, [rcx+rcx]
    add rdx, rcx    
    add rax, rdx    

    ; Restore registers
    pop rdx
    pop rbx

    ret                 

base_case_zero:
    mov rax, 0
    ret

base_case_one:
    mov rax, 1
    ret

good:
done:
FLAG: ASM{248c68348d3c0c6ff259dc6d12081949d61ae82c}