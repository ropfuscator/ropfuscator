	.file	"libnaive.c"
	.text
	.globl	func1
	.type	func1, @function
func1:
.LFB0:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 2 "libnaive.c" 1
	popl %ecx
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE0:
	.size	func1, .-func1
	.globl	func2
	.type	func2, @function
func2:
.LFB1:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 7 "libnaive.c" 1
	addl %ecx, %eax
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE1:
	.size	func2, .-func2
	.globl	func3
	.type	func3, @function
func3:
.LFB2:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 12 "libnaive.c" 1
	movl (%edx), %eax
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE2:
	.size	func3, .-func3
	.globl	func4
	.type	func4, @function
func4:
.LFB3:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 17 "libnaive.c" 1
	movl %eax, (%edx)
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE3:
	.size	func4, .-func4
	.globl	func5
	.type	func5, @function
func5:
.LFB4:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 22 "libnaive.c" 1
	xchgl %eax, %ebp
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE4:
	.size	func5, .-func5
	.globl	func6
	.type	func6, @function
func6:
.LFB5:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 27 "libnaive.c" 1
	xchgl %eax, %edx
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE5:
	.size	func6, .-func6
	.globl	func7
	.type	func7, @function
func7:
.LFB6:
	.cfi_startproc
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
#APP
# 32 "libnaive.c" 1
	movl %edx, %eax
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE6:
	.size	func7, .-func7
	.section	.text.__x86.get_pc_thunk.ax,"axG",@progbits,__x86.get_pc_thunk.ax,comdat
	.globl	__x86.get_pc_thunk.ax
	.hidden	__x86.get_pc_thunk.ax
	.type	__x86.get_pc_thunk.ax, @function
__x86.get_pc_thunk.ax:
.LFB7:
	.cfi_startproc
	movl	(%esp), %eax
	ret
	.cfi_endproc
.LFE7:
	.ident	"GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516"
	.section	.note.GNU-stack,"",@progbits
