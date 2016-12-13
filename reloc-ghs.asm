bits 64
;rdi, rsi, rdx
%define sys_write 1 ;fd, *buf, count
%define stdout 1
%define sys_exit 60 ;code
%define abs(a) (rbx+a-x)

	call x
x:	pop rbx
	;mov rax, sys_write
	xor rax, rax
	inc rax
	;mov rdi, 1=sys_write
	mov rdi, rax
	lea rsi, [abs(s)]
	xor rdx, rdx
	mov dl, s_len - s
	syscall
	;mov rax, sys_exit
	xor rax, rax
	mov al, sys_exit
	;mov rdi, 42
	mov dl, 42
	movzx rdi, dl
	syscall

s:	db "hello world", 10
s_len:
