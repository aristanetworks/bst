/* Freestanding x86 compat probe: exit status is the raw syscall errno. */
.text
.globl _start
_start:
#if defined(__i386__)
	/* Optional 's' selects stat64(NULL, NULL) instead of fsync(-1). */
	cmpl $1, (%esp)
	jle 1f
	mov 8(%esp), %ecx
	cmpb $'s', (%ecx)
	jne 1f
	mov $195, %eax
	xor %ebx, %ebx
	xor %ecx, %ecx
	int $0x80
	jmp 2f
1:
	mov $118, %eax
	mov $-1, %ebx
	int $0x80
2:
	neg %eax
	mov %eax, %ebx
	mov $1, %eax
	int $0x80
#elif defined(__x86_64__) && defined(__ILP32__)
	mov $0x4000004a, %eax /* x32 fsync */
	mov $-1, %edi
	syscall
	neg %eax
	mov %eax, %edi
	mov $0x4000003c, %eax /* x32 exit */
	syscall
#else
# error Expected i386 or x32
#endif
.section .note.GNU-stack,"",@progbits
