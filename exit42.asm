bits 64
%define sys_exit 60
mov rdi, 42
mov rax, sys_exit
syscall
