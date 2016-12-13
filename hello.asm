bits 64
%define sys_write 1
%define stdout 1
%define sys_exit 60
%define abs(a) (rbx+a-x)

	call x
x:	mov rbx, qword [rsp]
;rbx now contains the address of x
	mov rax, sys_write
	mov rdi, stdout
	lea rsi, [abs(m)]
	mov rdx, 12 ;length of m
	syscall

	mov rdi, 42
	mov rax, sys_exit
	syscall
m:	db "hello world", 10
