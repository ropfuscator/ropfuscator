	.text
	.file	"example7.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c"
	.loc	1 9 0                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:9:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$56, %esp
	pushfl
	calll	.chain_0
	jmp	.resume_0
	#APP
.chain_0:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver wcsftime, wcsftime@GLIBC_2.2

	#NO_APP
	pushl	$wcsftime
	addl	$-499234, (%esp)        # imm = 0xFFF861DE
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver _obstack_free, _obstack_free@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_free
	addl	$110979, (%esp)         # imm = 0x1B183
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver __strtol_internal, __strtol_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtol_internal
	addl	$50102, (%esp)          # imm = 0xC3B6
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver sigignore, sigignore@GLIBC_2.1

	#NO_APP
	pushl	$sigignore
	addl	$74490, (%esp)          # imm = 0x122FA
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$101862, (%esp)         # imm = 0x18DE6
	pushl	$-52
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver endusershell, endusershell@GLIBC_2.0

	#NO_APP
	pushl	$endusershell
	addl	$-943469, (%esp)        # imm = 0xFFF19A93
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver isdigit, isdigit@GLIBC_2.0

	#NO_APP
	pushl	$isdigit
	addl	$114410, (%esp)         # imm = 0x1BEEA
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver strerror, strerror@GLIBC_2.0

	#NO_APP
	pushl	$strerror
	addl	$-279594, (%esp)        # imm = 0xFFFBBBD6
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver __strtof128_nan, __strtof128_nan@GLIBC_PRIVATE

	#NO_APP
	pushl	$__strtof128_nan
	addl	$-22262, (%esp)         # imm = 0xA90A
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver getgrgid, getgrgid@GLIBC_2.0

	#NO_APP
	pushl	$getgrgid
	addl	$-530054, (%esp)        # imm = 0xFFF7E97A
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver xdr_hyper, xdr_hyper@GLIBC_2.1.1

	#NO_APP
	pushl	$xdr_hyper
	addl	$-1161891, (%esp)       # imm = 0xFFEE455D
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver printf_size_info, printf_size_info@GLIBC_2.1

	#NO_APP
	pushl	$printf_size_info
	addl	$-71830, (%esp)         # imm = 0xFFFEE76A
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver svcfd_create, svcfd_create@GLIBC_2.0

	#NO_APP
	pushl	$svcfd_create
	addl	$-700124, (%esp)        # imm = 0xFFF55124
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver svcunix_create, svcunix_create@GLIBC_2.1

	#NO_APP
	pushl	$svcunix_create
	addl	$-1132579, (%esp)       # imm = 0xFFEEB7DD
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver getrpcbyname, getrpcbyname@GLIBC_2.0

	#NO_APP
	pushl	$getrpcbyname
	addl	$-979478, (%esp)        # imm = 0xFFF10DEA
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-424675, (%esp)        # imm = 0xFFF9851D
	retl
	#APP
.resume_0:
	#NO_APP
	popfl
	movl	8(%ebp), %ecx
	movl	%eax, -32(%ebp)
.Ltmp0:
	.loc	1 9 35 prologue_end     # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:9:35
	movl	.L__profc_main, %eax
	pushfl
	calll	.chain_1
	jmp	.resume_1
	#APP
.chain_1:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver epoll_create, epoll_create@GLIBC_2.3.2

	#NO_APP
	pushl	$epoll_create
	addl	$-418541, (%esp)        # imm = 0xFFF99D13
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver xdr_rejected_reply, xdr_rejected_reply@GLIBC_2.0

	#NO_APP
	pushl	$xdr_rejected_reply
	addl	$-971514, (%esp)        # imm = 0xFFF12D06
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __wcstoll_internal, __wcstoll_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstoll_internal
	addl	$-393622, (%esp)        # imm = 0xFFF9FE6A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	pushl	$1
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __res_ninit, __res_ninit@GLIBC_2.2

	#NO_APP
	pushl	$__res_ninit
	addl	$-1108829, (%esp)       # imm = 0xFFEF14A3
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver free, free@GLIBC_2.0

	#NO_APP
	pushl	$free
	addl	$-256038, (%esp)        # imm = 0xFFFC17DA
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver htonl, htonl@GLIBC_2.0

	#NO_APP
	pushl	$htonl
	addl	$-879770, (%esp)        # imm = 0xFFF29366
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-226182, (%esp)        # imm = 0xFFFC8C7A
	retl
	#APP
.resume_1:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+4
	movl	%eax, .L__profc_main
	pushfl
	calll	.chain_2
	jmp	.resume_2
	#APP
.chain_2:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver clnt_spcreateerror, clnt_spcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_spcreateerror
	addl	$-994738, (%esp)        # imm = 0xFFF0D24E
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __snprintf, __snprintf@GLIBC_PRIVATE

	#NO_APP
	pushl	$__snprintf
	addl	$306499, (%esp)         # imm = 0x4AD43
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-781178, (%esp)        # imm = 0xFFF41486
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __iswpunct_l, __iswpunct_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswpunct_l
	addl	$-813958, (%esp)        # imm = 0xFFF3947A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __poll_chk, __poll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__poll_chk
	addl	$-879354, (%esp)        # imm = 0xFFF29506
	pushl	$-96
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver putwc_unlocked, putwc_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$putwc_unlocked
	addl	$-348733, (%esp)        # imm = 0xFFFAADC3
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver xdr_bool, xdr_bool@GLIBC_2.0

	#NO_APP
	pushl	$xdr_bool
	addl	$-1018086, (%esp)       # imm = 0xFFF0771A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __readlink_chk, __readlink_chk@GLIBC_2.4

	#NO_APP
	pushl	$__readlink_chk
	addl	$-872394, (%esp)        # imm = 0xFFF2B036
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-1020646, (%esp)       # imm = 0xFFF06D1A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver srand48, srand48@GLIBC_2.0

	#NO_APP
	pushl	$srand48
	addl	$62330, (%esp)          # imm = 0xF37A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __assert_perror_fail, __assert_perror_fail@GLIBC_2.0

	#NO_APP
	pushl	$__assert_perror_fail
	addl	$-30067, (%esp)         # imm = 0x8A8D
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __libc_dlclose, __libc_dlclose@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlclose
	addl	$-1040278, (%esp)       # imm = 0xFFF0206A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver sigorset, sigorset@GLIBC_2.0

	#NO_APP
	pushl	$sigorset
	addl	$387316, (%esp)         # imm = 0x5E8F4
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver key_secretkey_is_set, key_secretkey_is_set@GLIBC_2.1

	#NO_APP
	pushl	$key_secretkey_is_set
	addl	$-1147075, (%esp)       # imm = 0xFFEE7F3D
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver inet_lnaof, inet_lnaof@GLIBC_2.0

	#NO_APP
	pushl	$inet_lnaof
	addl	$-871350, (%esp)        # imm = 0xFFF2B44A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver svcudp_create, svcudp_create@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_create
	addl	$-1159347, (%esp)       # imm = 0xFFEE4F4D
	retl
	#APP
.resume_2:
	#NO_APP
	popfl
.Ltmp1:
	.loc	1 15 19                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:15:19
	movl	4(%eax), %eax
	.loc	1 15 13 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:15:13
	movl	%eax, (%esp)
	leal	.L.str, %eax
	movl	%eax, 4(%esp)
	calll	fopen
	.loc	1 15 11                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:15:11
	movl	%eax, -8(%ebp)
	cmpl	$0, %eax
.Ltmp2:
	.loc	1 15 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:15:7
	je	.LBB0_5
# %bb.1:
	movl	.L__profc_main+8, %eax
	pushfl
	calll	.chain_3
	jmp	.resume_3
	#APP
.chain_3:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver iconv_close, iconv_close@GLIBC_2.1

	#NO_APP
	pushl	$iconv_close
	addl	$542451, (%esp)         # imm = 0x846F3
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver envz_strip, envz_strip@GLIBC_2.0

	#NO_APP
	pushl	$envz_strip
	addl	$-287830, (%esp)        # imm = 0xFFFB9BAA
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver strtod, strtod@GLIBC_2.0

	#NO_APP
	pushl	$strtod
	addl	$42022, (%esp)          # imm = 0xA426
	pushl	$1
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-971389, (%esp)        # imm = 0xFFF12D83
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver qgcvt, qgcvt@GLIBC_2.0

	#NO_APP
	pushl	$qgcvt
	addl	$-776150, (%esp)        # imm = 0xFFF4282A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-801786, (%esp)        # imm = 0xFFF3C406
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	retl
	#APP
.resume_3:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+12
	movl	%eax, .L__profc_main+8
.Ltmp3:
	.loc	1 16 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:16:5
	movl	$.L.str.1, (%esp)
	calll	printf
	.loc	1 17 17                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:17:17
	movl	-32(%ebp), %eax
	movl	8(%eax), %eax
	.loc	1 17 11 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:17:11
	movl	%eax, (%esp)
	movl	$.L.str.2, 4(%esp)
	calll	fopen
	.loc	1 17 9                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:17:9
	movl	%eax, -24(%ebp)
	pushfl
	calll	.chain_4
	jmp	.resume_4
	#APP
.chain_4:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __stack_chk_fail, __stack_chk_fail@GLIBC_2.4

	#NO_APP
	pushl	$__stack_chk_fail
	addl	$-871762, (%esp)        # imm = 0xFFF2B2AE
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver atoll, atoll@GLIBC_2.0

	#NO_APP
	pushl	$atoll
	addl	$452355, (%esp)         # imm = 0x6E703
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __waitpid, __waitpid@GLIBC_2.0

	#NO_APP
	pushl	$__waitpid
	addl	$-550858, (%esp)        # imm = 0xFFF79836
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __merge_grp, __merge_grp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__merge_grp
	addl	$-536054, (%esp)        # imm = 0xFFF7D20A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver setutxent, setutxent@GLIBC_2.1

	#NO_APP
	pushl	$setutxent
	addl	$-1045418, (%esp)       # imm = 0xFFF00C56
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver _obstack_begin, _obstack_begin@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin
	addl	$-440989, (%esp)        # imm = 0xFFF94563
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-303942, (%esp)        # imm = 0xFFFB5CBA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-492058, (%esp)        # imm = 0xFFF87DE6
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver setlogin, setlogin@GLIBC_2.0

	#NO_APP
	pushl	$setlogin
	addl	$-1026966, (%esp)       # imm = 0xFFF0546A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-714118, (%esp)        # imm = 0xFFF51A7A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-943427, (%esp)        # imm = 0xFFF19ABD
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __asprintf_chk, __asprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__asprintf_chk
	addl	$-869142, (%esp)        # imm = 0xFFF2BCEA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __sched_get_priority_max, __sched_get_priority_max@GLIBC_2.0

	#NO_APP
	pushl	$__sched_get_priority_max
	addl	$-353132, (%esp)        # imm = 0xFFFA9C94
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __islower_l, __islower_l@GLIBC_2.1

	#NO_APP
	pushl	$__islower_l
	addl	$-31987, (%esp)         # imm = 0x830D
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver isspace, isspace@GLIBC_2.0

	#NO_APP
	pushl	$isspace
	addl	$114010, (%esp)         # imm = 0x1BD5A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver getrpcbynumber_r, getrpcbynumber_r@GLIBC_2.0

	#NO_APP
	pushl	$getrpcbynumber_r
	addl	$-1236707, (%esp)       # imm = 0xFFED211D
	retl
	#APP
.resume_4:
	#NO_APP
	popfl
	.loc	1 18 11 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:18:11
	movl	%eax, (%esp)
	calll	count_characters
	.loc	1 18 9 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:18:9
	movl	%edx, -12(%ebp)
	movl	%eax, -16(%ebp)
	pushfl
	calll	.chain_5
	jmp	.resume_5
	#APP
.chain_5:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver inet_netof, inet_netof@GLIBC_2.0

	#NO_APP
	pushl	$inet_netof
	addl	$-872226, (%esp)        # imm = 0xFFF2B0DE
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$176515, (%esp)         # imm = 0x2B183
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __nss_hostname_digits_dots, __nss_hostname_digits_dots@GLIBC_2.2.2

	#NO_APP
	pushl	$__nss_hostname_digits_dots
	addl	$-960282, (%esp)        # imm = 0xFFF158E6
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver fsync, fsync@GLIBC_2.0

	#NO_APP
	pushl	$fsync
	addl	$-758822, (%esp)        # imm = 0xFFF46BDA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __isoc99_vfscanf, __isoc99_vfscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfscanf
	addl	$-158794, (%esp)        # imm = 0xFFFD93B6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver setegid, setegid@GLIBC_2.0

	#NO_APP
	pushl	$setegid
	addl	$-931773, (%esp)        # imm = 0xFFF1C843
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver remove, remove@GLIBC_2.0

	#NO_APP
	pushl	$remove
	addl	$-148742, (%esp)        # imm = 0xFFFDBAFA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver process_vm_writev, process_vm_writev@GLIBC_2.15

	#NO_APP
	pushl	$process_vm_writev
	addl	$-806826, (%esp)        # imm = 0xFFF3B056
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-961302, (%esp)        # imm = 0xFFF154EA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-918742, (%esp)        # imm = 0xFFF1FB2A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-902915, (%esp)        # imm = 0xFFF238FD
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-540870, (%esp)        # imm = 0xFFF7BF3A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __openat64_2, __openat64_2@GLIBC_2.7

	#NO_APP
	pushl	$__openat64_2
	addl	$-399468, (%esp)        # imm = 0xFFF9E794
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver shmdt, shmdt@GLIBC_2.0

	#NO_APP
	pushl	$shmdt
	addl	$-948531, (%esp)        # imm = 0xFFF186CD
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __strspn_g, __strspn_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_g
	addl	$-304310, (%esp)        # imm = 0xFFFB5B4A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __nss_lookup, __nss_lookup@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_lookup
	addl	$-1092867, (%esp)       # imm = 0xFFEF52FD
	retl
	#APP
.resume_5:
	#NO_APP
	popfl
	.loc	1 20 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:20:5
	movl	%eax, (%esp)
	movl	$2, 12(%esp)
	movl	$-1, 8(%esp)
	movl	$-1, 4(%esp)
	calll	fseek
	.loc	1 23 60                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:23:60
	movl	-8(%ebp), %eax
	.loc	1 23 54 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:23:54
	movl	%eax, (%esp)
	calll	ftell
	.loc	1 23 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:23:5
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	$.L.str.3, (%esp)
	calll	printf
.LBB0_2:                                # =>This Inner Loop Header: Depth=1
	.loc	1 0 5                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:0:5
	pushfl
	calll	.chain_6
	jmp	.resume_6
	#APP
.chain_6:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$73982, (%esp)          # imm = 0x120FE
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __libc_longjmp, __libc_longjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_longjmp
	addl	$458803, (%esp)         # imm = 0x70033
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __tolower_l, __tolower_l@GLIBC_2.1

	#NO_APP
	pushl	$__tolower_l
	addl	$104006, (%esp)         # imm = 0x19646
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver execle, execle@GLIBC_2.0

	#NO_APP
	pushl	$execle
	addl	$-544502, (%esp)        # imm = 0xFFF7B10A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strncmp_g, __strncmp_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncmp_g
	addl	$-312490, (%esp)        # imm = 0xFFFB3B56
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-1093741, (%esp)       # imm = 0xFFEF4F93
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strlen_g, __strlen_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strlen_g
	addl	$-303590, (%esp)        # imm = 0xFFFB5E1A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver ioperm, ioperm@GLIBC_2.0

	#NO_APP
	pushl	$ioperm
	addl	$-801738, (%esp)        # imm = 0xFFF3C436
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver mrand48_r, mrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$mrand48_r
	addl	$61674, (%esp)          # imm = 0xF0EA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver svcraw_create, svcraw_create@GLIBC_2.0

	#NO_APP
	pushl	$svcraw_create
	addl	$-966678, (%esp)        # imm = 0xFFF13FEA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-374995, (%esp)        # imm = 0xFFFA472D
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __pread64_chk, __pread64_chk@GLIBC_2.4

	#NO_APP
	pushl	$__pread64_chk
	addl	$-863702, (%esp)        # imm = 0xFFF2D22A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __vsnprintf_chk, __vsnprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsnprintf_chk
	addl	$-548940, (%esp)        # imm = 0xFFF79FB4
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver rcmd_af, rcmd_af@GLIBC_2.2

	#NO_APP
	pushl	$rcmd_af
	addl	$-1037891, (%esp)       # imm = 0xFFF029BD
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver atol, atol@GLIBC_2.0

	#NO_APP
	pushl	$atol
	addl	$73866, (%esp)          # imm = 0x1208A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver getmsg, getmsg@GLIBC_2.1

	#NO_APP
	pushl	$getmsg
	addl	$-1169875, (%esp)       # imm = 0xFFEE262D
	retl
	#APP
.resume_6:
	#NO_APP
	popfl
	.loc	1 25 12 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:25:12
	movl	-12(%ebp), %ecx
	.loc	1 25 5 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:25:5
	orl	%ecx, %eax
	je	.LBB0_4
	jmp	.LBB0_3
.LBB0_3:                                #   in Loop: Header=BB0_2 Depth=1
	movl	.L__profc_main+16, %eax
	pushfl
	calll	.chain_7
	jmp	.resume_7
	#APP
.chain_7:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-437837, (%esp)        # imm = 0xFFF951B3
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver xdr_quad_t, xdr_quad_t@GLIBC_2.3.4

	#NO_APP
	pushl	$xdr_quad_t
	addl	$-1028202, (%esp)       # imm = 0xFFF04F96
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver sigismember, sigismember@GLIBC_2.0

	#NO_APP
	pushl	$sigismember
	addl	$76298, (%esp)          # imm = 0x12A0A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-802378, (%esp)        # imm = 0xFFF3C1B6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-924717, (%esp)        # imm = 0xFFF1E3D3
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __libc_vfork, __libc_vfork@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_vfork
	addl	$-544022, (%esp)        # imm = 0xFFF7B2EA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver initgroups, initgroups@GLIBC_2.0

	#NO_APP
	pushl	$initgroups
	addl	$-537898, (%esp)        # imm = 0xFFF7CAD6
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver mblen, mblen@GLIBC_2.0

	#NO_APP
	pushl	$mblen
	addl	$65674, (%esp)          # imm = 0x1008A
	retl
	#APP
.resume_7:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+20
	movl	%eax, .L__profc_main+16
	pushfl
	calll	.chain_8
	jmp	.resume_8
	#APP
.chain_8:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver pthread_attr_init, pthread_attr_init@GLIBC_2.1

	#NO_APP
	pushl	$pthread_attr_init
	addl	$-850946, (%esp)        # imm = 0xFFF303FE
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-710461, (%esp)        # imm = 0xFFF528C3
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver labs, labs@GLIBC_2.0

	#NO_APP
	pushl	$labs
	addl	$57606, (%esp)          # imm = 0xE106
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __getdomainname_chk, __getdomainname_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getdomainname_chk
	addl	$-868518, (%esp)        # imm = 0xFFF2BF5A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __profile_frequency, __profile_frequency@GLIBC_2.0

	#NO_APP
	pushl	$__profile_frequency
	addl	$-817802, (%esp)        # imm = 0xFFF38576
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-924717, (%esp)        # imm = 0xFFF1E3D3
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver getprotobyname_r, getprotobyname_r@GLIBC_2.0

	#NO_APP
	pushl	$getprotobyname_r
	addl	$-1090934, (%esp)       # imm = 0xFFEF5A8A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-766474, (%esp)        # imm = 0xFFF44DF6
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver iruserok_af, iruserok_af@GLIBC_2.2

	#NO_APP
	pushl	$iruserok_af
	addl	$-896582, (%esp)        # imm = 0xFFF251BA
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver endaliasent, endaliasent@GLIBC_2.0

	#NO_APP
	pushl	$endaliasent
	addl	$-904694, (%esp)        # imm = 0xFFF2320A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __stpcpy_small, __stpcpy_small@GLIBC_2.1.1

	#NO_APP
	pushl	$__stpcpy_small
	addl	$-448035, (%esp)        # imm = 0xFFF929DD
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __register_atfork, __register_atfork@GLIBC_2.3.2

	#NO_APP
	pushl	$__register_atfork
	addl	$-854102, (%esp)        # imm = 0xFFF2F7AA
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __ptsname_r_chk, __ptsname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ptsname_r_chk
	addl	$-725180, (%esp)        # imm = 0xFFF4EF44
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-94115, (%esp)         # imm = 0xFFFE905D
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver siggetmask, siggetmask@GLIBC_2.0

	#NO_APP
	pushl	$siggetmask
	addl	$76154, (%esp)          # imm = 0x1297A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __idna_from_dns_encoding, __idna_from_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_from_dns_encoding
	addl	$-1067075, (%esp)       # imm = 0xFFEFB7BD
	retl
	#APP
.resume_8:
	#NO_APP
	popfl
.Ltmp4:
	.loc	1 26 12 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:26:12
	movl	%eax, (%esp)
	calll	fgetc
	.loc	1 26 10 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:26:10
	movb	%al, -1(%ebp)
	.loc	1 27 13 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:27:13
	movsbl	-1(%ebp), %eax
	.loc	1 27 17 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:27:17
	movl	-24(%ebp), %ecx
	.loc	1 27 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:27:7
	movl	%ecx, 4(%esp)
	movl	%eax, (%esp)
	calll	fputc
	.loc	1 28 13 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:28:13
	movl	-8(%ebp), %eax
	.loc	1 28 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:28:7
	movl	%eax, (%esp)
	movl	$1, 12(%esp)
	movl	$-1, 8(%esp)
	movl	$-2, 4(%esp)
	calll	fseek
	.loc	1 29 10 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:29:10
	movl	-16(%ebp), %eax
	pushfl
	calll	.chain_9
	jmp	.resume_9
	#APP
.chain_9:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$111683, (%esp)         # imm = 0x1B443
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver munlock, munlock@GLIBC_2.0

	#NO_APP
	pushl	$munlock
	addl	$-782522, (%esp)        # imm = 0xFFF40F46
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __sysconf, __sysconf@GLIBC_2.2

	#NO_APP
	pushl	$__sysconf
	addl	$-550806, (%esp)        # imm = 0xFFF7986A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fts_set, fts_set@GLIBC_2.0

	#NO_APP
	pushl	$fts_set
	addl	$-744442, (%esp)        # imm = 0xFFF4A406
	pushl	$-1
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_array, xdr_array@GLIBC_2.0

	#NO_APP
	pushl	$xdr_array
	addl	$-1190093, (%esp)       # imm = 0xFFEDD733
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-758998, (%esp)        # imm = 0xFFF46B2A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$62214, (%esp)          # imm = 0xF306
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-171910, (%esp)        # imm = 0xFFFD607A
	retl
	#APP
.resume_9:
	#NO_APP
	popfl
	adcl	$-1, -12(%ebp)
	movl	%eax, -16(%ebp)
.Ltmp5:
	.loc	1 25 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:25:5
	jmp	.LBB0_2
.LBB0_4:
	.loc	1 31 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:31:5
	leal	.L.str.4, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 32 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:32:3
	jmp	.LBB0_6
.Ltmp6:
.LBB0_5:
	.loc	1 33 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:33:5
	leal	.L.str.5, %eax
	movl	%eax, (%esp)
	calll	perror
.Ltmp7:
.LBB0_6:
	.loc	1 0 5 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:0:5
	pushfl
	calll	.chain_10
	jmp	.resume_10
	#APP
.chain_10:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver ptrace, ptrace@GLIBC_2.0

	#NO_APP
	pushl	$ptrace
	addl	$-762098, (%esp)        # imm = 0xFFF45F0E
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __freading, __freading@GLIBC_2.2

	#NO_APP
	pushl	$__freading
	addl	$176723, (%esp)         # imm = 0x2B253
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _IO_setbuffer, _IO_setbuffer@GLIBC_2.0

	#NO_APP
	pushl	$_IO_setbuffer
	addl	$-176874, (%esp)        # imm = 0xFFFD4D16
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver mkstemp64, mkstemp64@GLIBC_2.2

	#NO_APP
	pushl	$mkstemp64
	addl	$-768810, (%esp)        # imm = 0xFFF444D6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$-83, (%esp)
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver setsgent, setsgent@GLIBC_2.10

	#NO_APP
	pushl	$setsgent
	addl	$-824006, (%esp)        # imm = 0xFFF36D3A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __getcwd_chk, __getcwd_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getcwd_chk
	addl	$-872666, (%esp)        # imm = 0xFFF2AF26
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-303942, (%esp)        # imm = 0xFFFB5CBA
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _IO_feof, _IO_feof@GLIBC_2.0

	#NO_APP
	pushl	$_IO_feof
	addl	$-193718, (%esp)        # imm = 0xFFFD0B4A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver clnt_sperror, clnt_sperror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_sperror
	addl	$-1138307, (%esp)       # imm = 0xFFEEA17D
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver ualarm, ualarm@GLIBC_2.0

	#NO_APP
	pushl	$ualarm
	addl	$-761078, (%esp)        # imm = 0xFFF4630A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __fdelt_warn, __fdelt_warn@GLIBC_2.15

	#NO_APP
	pushl	$__fdelt_warn
	addl	$-559116, (%esp)        # imm = 0xFFF777F4
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __strspn_c1, __strspn_c1@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_c1
	addl	$-446963, (%esp)        # imm = 0xFFF92E0D
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver rresvport_af, rresvport_af@GLIBC_2.2

	#NO_APP
	pushl	$rresvport_af
	addl	$-892550, (%esp)        # imm = 0xFFF2617A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver getnetbyname, getnetbyname@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname
	addl	$-1024707, (%esp)       # imm = 0xFFF05D3D
	retl
	#APP
.resume_10:
	#NO_APP
	popfl
	.loc	1 35 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:35:3
	movl	%eax, (%esp)
	calll	fclose
	.loc	1 36 10                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:36:10
	movl	-24(%ebp), %eax
	.loc	1 36 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:36:3
	movl	%eax, (%esp)
	calll	fclose
	.loc	1 37 1 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:37:1
	addl	$56, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp8:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.globl	count_characters        # -- Begin function count_characters
	.p2align	4, 0x90
	.type	count_characters,@function
count_characters:                       # @count_characters
.Lfunc_begin1:
	.loc	1 40 0                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:40:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$24, %esp
	pushfl
	calll	.chain_11
	jmp	.resume_11
	#APP
.chain_11:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _IO_wfile_underflow, _IO_wfile_underflow@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_underflow
	addl	$-184834, (%esp)        # imm = 0xFFFD2DFE
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-596141, (%esp)        # imm = 0xFFF6E753
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __gconv_transliterate, __gconv_transliterate@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_transliterate
	addl	$124598, (%esp)         # imm = 0x1E6B6
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver mbstowcs, mbstowcs@GLIBC_2.0

	#NO_APP
	pushl	$mbstowcs
	addl	$65434, (%esp)          # imm = 0xFF9A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver vwprintf, vwprintf@GLIBC_2.2

	#NO_APP
	pushl	$vwprintf
	addl	$-183834, (%esp)        # imm = 0xFFFD31E6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _setjmp, _setjmp@GLIBC_2.0

	#NO_APP
	pushl	$_setjmp
	addl	$-93933, (%esp)         # imm = 0xFFFE9113
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-72134, (%esp)         # imm = 0xFFFEE63A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver setjmp, setjmp@GLIBC_2.0

	#NO_APP
	pushl	$setjmp
	addl	$72022, (%esp)          # imm = 0x11956
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver inet6_rth_add, inet6_rth_add@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_add
	addl	$-920086, (%esp)        # imm = 0xFFF1F5EA
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver svc_getreqset, svc_getreqset@GLIBC_2.0

	#NO_APP
	pushl	$svc_getreqset
	addl	$-1009094, (%esp)       # imm = 0xFFF09A3A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$-70531, (%esp)         # imm = 0xFFFEEC7D
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver ecvt, ecvt@GLIBC_2.0

	#NO_APP
	pushl	$ecvt
	addl	$-774406, (%esp)        # imm = 0xFFF42EFA
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver ftok, ftok@GLIBC_2.0

	#NO_APP
	pushl	$ftok
	addl	$-490524, (%esp)        # imm = 0xFFF883E4
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver fgetpos, fgetpos@GLIBC_2.0

	#NO_APP
	pushl	$fgetpos
	addl	$-1201779, (%esp)       # imm = 0xFFEDA98D
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver inet6_option_find, inet6_option_find@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_find
	addl	$-916774, (%esp)        # imm = 0xFFF202DA
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __munmap, __munmap@GLIBC_PRIVATE

	#NO_APP
	pushl	$__munmap
	addl	$-918467, (%esp)        # imm = 0xFFF1FC3D
	retl
	#APP
.resume_11:
	#NO_APP
	popfl
.Ltmp9:
	.loc	1 40 32 prologue_end    # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:40:32
	movl	.L__profc_count_characters, %eax
	pushfl
	calll	.chain_12
	jmp	.resume_12
	#APP
.chain_12:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$453171, (%esp)         # imm = 0x6EA33
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-288234, (%esp)        # imm = 0xFFFB9A16
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver thrd_equal, thrd_equal@GLIBC_2.28

	#NO_APP
	pushl	$thrd_equal
	addl	$-855238, (%esp)        # imm = 0xFFF2F33A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$156870, (%esp)         # imm = 0x264C6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver isupper, isupper@GLIBC_2.0

	#NO_APP
	pushl	$isupper
	addl	$-60413, (%esp)         # imm = 0xFFFF1403
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-231782, (%esp)        # imm = 0xFFFC769A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __libc_start_main, __libc_start_main@GLIBC_2.0

	#NO_APP
	pushl	$__libc_start_main
	addl	$158838, (%esp)         # imm = 0x26C76
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-766662, (%esp)        # imm = 0xFFF44D3A
	retl
	#APP
.resume_12:
	#NO_APP
	popfl
	adcl	$0, .L__profc_count_characters+4
	movl	%eax, .L__profc_count_characters
	pushfl
	calll	.chain_13
	jmp	.resume_13
	#APP
.chain_13:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __strspn_cg, __strspn_cg@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_cg
	addl	$-304946, (%esp)        # imm = 0xFFFB58CE
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver jrand48, jrand48@GLIBC_2.0

	#NO_APP
	pushl	$jrand48
	addl	$440963, (%esp)         # imm = 0x6BA83
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver ftw64, ftw64@GLIBC_2.1

	#NO_APP
	pushl	$ftw64
	addl	$-738122, (%esp)        # imm = 0xFFF4BCB6
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_least_wmarker, _IO_least_wmarker@GLIBC_2.2

	#NO_APP
	pushl	$_IO_least_wmarker
	addl	$-176982, (%esp)        # imm = 0xFFFD4CAA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver xdr_uint8_t, xdr_uint8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint8_t
	addl	$-1029242, (%esp)       # imm = 0xFFF04B86
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_free_backup_area, _IO_free_backup_area@GLIBC_2.0

	#NO_APP
	pushl	$_IO_free_backup_area
	addl	$-397405, (%esp)        # imm = 0xFFF9EFA3
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver capget, capget@GLIBC_2.1

	#NO_APP
	pushl	$capget
	addl	$-796854, (%esp)        # imm = 0xFFF3D74A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver inotify_init, inotify_init@GLIBC_2.4

	#NO_APP
	pushl	$inotify_init
	addl	$-805802, (%esp)        # imm = 0xFFF3B456
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __nss_hash, __nss_hash@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_hash
	addl	$-954934, (%esp)        # imm = 0xFFF16DCA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver rexec_af, rexec_af@GLIBC_2.2

	#NO_APP
	pushl	$rexec_af
	addl	$-897030, (%esp)        # imm = 0xFFF24FFA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver mkdirat, mkdirat@GLIBC_2.4

	#NO_APP
	pushl	$mkdirat
	addl	$-854883, (%esp)        # imm = 0xFFF2F49D
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __idna_to_dns_encoding, __idna_to_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_to_dns_encoding
	addl	$-921910, (%esp)        # imm = 0xFFF1EECA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$422036, (%esp)         # imm = 0x67094
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __sched_getparam, __sched_getparam@GLIBC_2.0

	#NO_APP
	pushl	$__sched_getparam
	addl	$-809587, (%esp)        # imm = 0xFFF3A58D
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver hcreate, hcreate@GLIBC_2.0

	#NO_APP
	pushl	$hcreate
	addl	$-777638, (%esp)        # imm = 0xFFF4225A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver fremovexattr, fremovexattr@GLIBC_2.3

	#NO_APP
	pushl	$fremovexattr
	addl	$-931875, (%esp)        # imm = 0xFFF1C7DD
	retl
	#APP
.resume_13:
	#NO_APP
	popfl
	.loc	1 41 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:41:3
	movl	%eax, (%esp)
	movl	$2, 12(%esp)
	movl	$-1, 8(%esp)
	movl	$-1, 4(%esp)
	calll	fseek
	.loc	1 43 13                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:43:13
	movl	8(%ebp), %eax
	.loc	1 43 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:43:7
	movl	%eax, (%esp)
	calll	ftell
	.loc	1 42 8 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:42:8
	movl	%edx, -4(%ebp)
	movl	%eax, -8(%ebp)
	pushfl
	calll	.chain_14
	jmp	.resume_14
	#APP
.chain_14:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver svcerr_noprog, svcerr_noprog@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_noprog
	addl	$-629613, (%esp)        # imm = 0xFFF66493
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getpwnam, getpwnam@GLIBC_2.0

	#NO_APP
	pushl	$getpwnam
	addl	$-546378, (%esp)        # imm = 0xFFF7A9B6
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-177926, (%esp)        # imm = 0xFFFD48FA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __libc_freeres, __libc_freeres@GLIBC_2.1

	#NO_APP
	pushl	$__libc_freeres
	addl	$-1256794, (%esp)       # imm = 0xFFECD2A6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver setdomainname, setdomainname@GLIBC_2.0

	#NO_APP
	pushl	$setdomainname
	addl	$-932605, (%esp)        # imm = 0xFFF1C503
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver posix_spawnattr_setsigdefault, posix_spawnattr_setsigdefault@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setsigdefault
	addl	$-699990, (%esp)        # imm = 0xFFF551AA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver fts64_close, fts64_close@GLIBC_2.23

	#NO_APP
	pushl	$fts64_close
	addl	$-749450, (%esp)        # imm = 0xFFF49076
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getgrnam_r, getgrnam_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getgrnam_r
	addl	$-533078, (%esp)        # imm = 0xFFF7DDAA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getnetgrent, getnetgrent@GLIBC_2.0

	#NO_APP
	pushl	$getnetgrent
	addl	$-904898, (%esp)        # imm = 0xFFF2313E
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver clnt_pcreateerror, clnt_pcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_pcreateerror
	addl	$-615821, (%esp)        # imm = 0xFFF69A73
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver pthread_mutex_destroy, pthread_mutex_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_mutex_destroy
	addl	$-861194, (%esp)        # imm = 0xFFF2DBF6
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __wcsncpy_chk, __wcsncpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncpy_chk
	addl	$-865462, (%esp)        # imm = 0xFFF2CB4A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __nss_group_lookup, __nss_group_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_group_lookup
	addl	$-1100010, (%esp)       # imm = 0xFFEF3716
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver xdr_int32_t, xdr_int32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int32_t
	addl	$-1194445, (%esp)       # imm = 0xFFEDC633
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver xdr_callhdr, xdr_callhdr@GLIBC_2.0

	#NO_APP
	pushl	$xdr_callhdr
	addl	$-963782, (%esp)        # imm = 0xFFF14B3A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_wfile_xsputn, _IO_wfile_xsputn@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_xsputn
	addl	$-190678, (%esp)        # imm = 0xFFFD172A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _mcleanup, _mcleanup@GLIBC_2.0

	#NO_APP
	pushl	$_mcleanup
	addl	$-806310, (%esp)        # imm = 0xFFF3B25A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-1063635, (%esp)       # imm = 0xFFEFC52D
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$112122, (%esp)         # imm = 0x1B5FA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver prlimit, prlimit@GLIBC_2.13

	#NO_APP
	pushl	$prlimit
	addl	$-482828, (%esp)        # imm = 0xFFF8A1F4
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __strtof_l, __strtof_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtof_l
	addl	$-106547, (%esp)        # imm = 0xFFFE5FCD
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __internal_endnetgrent, __internal_endnetgrent@GLIBC_PRIVATE

	#NO_APP
	pushl	$__internal_endnetgrent
	addl	$-902166, (%esp)        # imm = 0xFFF23BEA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver authunix_create, authunix_create@GLIBC_2.0

	#NO_APP
	pushl	$authunix_create
	addl	$-1136675, (%esp)       # imm = 0xFFEEA7DD
	retl
	#APP
.resume_14:
	#NO_APP
	popfl
	.loc	1 44 11                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:44:11
	adcl	$0, -4(%ebp)
	movl	%eax, -8(%ebp)
	pushfl
	calll	.chain_15
	jmp	.resume_15
	#APP
.chain_15:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver xdr_authunix_parms, xdr_authunix_parms@GLIBC_2.0

	#NO_APP
	pushl	$xdr_authunix_parms
	addl	$-956546, (%esp)        # imm = 0xFFF1677E
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __isxdigit_l, __isxdigit_l@GLIBC_2.1

	#NO_APP
	pushl	$__isxdigit_l
	addl	$491075, (%esp)         # imm = 0x77E43
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver sched_getaffinity, sched_getaffinity@GLIBC_2.3.3

	#NO_APP
	pushl	$sched_getaffinity
	addl	$-1087610, (%esp)       # imm = 0xFFEF6786
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-816390, (%esp)        # imm = 0xFFF38AFA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver _authenticate, _authenticate@GLIBC_2.1

	#NO_APP
	pushl	$_authenticate
	addl	$-973850, (%esp)        # imm = 0xFFF123E6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-400525, (%esp)        # imm = 0xFFF9E373
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-751238, (%esp)        # imm = 0xFFF4897A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver strcoll, strcoll@GLIBC_2.0

	#NO_APP
	pushl	$strcoll
	addl	$-278826, (%esp)        # imm = 0xFFFBBED6
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver getrpcent, getrpcent@GLIBC_2.0

	#NO_APP
	pushl	$getrpcent
	addl	$-979286, (%esp)        # imm = 0xFFF10EAA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-1020646, (%esp)       # imm = 0xFFF06D1A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$16797, (%esp)          # imm = 0x419D
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver mcheck_pedantic, mcheck_pedantic@GLIBC_2.2

	#NO_APP
	pushl	$mcheck_pedantic
	addl	$-263990, (%esp)        # imm = 0xFFFBF8CA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver xdr_uint32_t, xdr_uint32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint32_t
	addl	$-708508, (%esp)        # imm = 0xFFF53064
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver getnameinfo, getnameinfo@GLIBC_2.1

	#NO_APP
	pushl	$getnameinfo
	addl	$-1052419, (%esp)       # imm = 0xFFEFF0FD
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver _dl_mcount_wrapper_check, _dl_mcount_wrapper_check@GLIBC_2.1

	#NO_APP
	pushl	$_dl_mcount_wrapper_check
	addl	$-1039014, (%esp)       # imm = 0xFFF0255A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __wcstod_internal, __wcstod_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstod_internal
	addl	$-538867, (%esp)        # imm = 0xFFF7C70D
	retl
	#APP
.resume_15:
	#NO_APP
	popfl
	.loc	1 45 10                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:45:10
	movl	-4(%ebp), %edx
	.loc	1 45 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c:45:3
	addl	$24, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp10:
.Lfunc_end1:
	.size	count_characters, .Lfunc_end1-count_characters
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"r"
	.size	.L.str, 2

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"The FILE has been opened...\n"
	.size	.L.str.1, 29

	.type	.L.str.2,@object        # @.str.2
.L.str.2:
	.asciz	"w"
	.size	.L.str.2, 2

	.type	.L.str.3,@object        # @.str.3
.L.str.3:
	.asciz	"Number of characters to be copied %d\n"
	.size	.L.str.3, 38

	.type	.L.str.4,@object        # @.str.4
.L.str.4:
	.asciz	"\n**File copied successfully in reverse order**\n"
	.size	.L.str.4, 48

	.type	.L.str.5,@object        # @.str.5
.L.str.5:
	.asciz	"Error occured\n"
	.size	.L.str.5, 15

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	2                       # 0x2
	.long	78                      # 0x4e
	.long	82                      # 0x52
	.long	2                       # 0x2
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	67                      # 0x43
	.quad	11040003281             # 0x2920914d1
	.quad	6434320998058244281     # 0x594b4cdb741938b9
	.long	9                       # 0x9
	.quad	24                      # 0x18
	.asciz	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c\001\000\003\005\t\001\005\001\005\t\001\t#\034\002\001\006\007\000 \005\000!\000\242\200\200\200\b\005\000\"\021\004\003\n\f\000\017\t\000\020\000\221\200\200\200\b\t\000\021\005\006\n\007\004\000\212\200\200\200\b\n\000\n\002\004\001\000\000\001\001( \006\002\000\000\000\000\000"
	.size	__llvm_coverage_mapping, 216

	.type	.L__profc_main,@object  # @__profc_main
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_main:
	.zero	24
	.size	.L__profc_main, 24

	.type	.L__profd_main,@object  # @__profd_main
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_main:
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.quad	11040003281             # 0x2920914d1
	.long	.L__profc_main
	.long	main
	.long	0
	.long	3                       # 0x3
	.zero	4
	.size	.L__profd_main, 36

	.type	.L__profc_count_characters,@object # @__profc_count_characters
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_count_characters:
	.zero	8
	.size	.L__profc_count_characters, 8

	.type	.L__profd_count_characters,@object # @__profd_count_characters
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_count_characters:
	.quad	6434320998058244281     # 0x594b4cdb741938b9
	.quad	24                      # 0x18
	.long	.L__profc_count_characters
	.long	count_characters
	.long	0
	.long	1                       # 0x1
	.zero	4
	.size	.L__profd_count_characters, 36

	.type	.L__llvm_prf_nm,@object # @__llvm_prf_nm
	.section	__llvm_prf_names,"a",@progbits
	.p2align	4
.L__llvm_prf_nm:
	.ascii	"\025\035x\332\313M\314\314cL\316/\315+\211O\316H,JL.I-*\006\000X\233\bO"
	.size	.L__llvm_prf_nm, 31

	.type	__llvm_profile_filename,@object # @__llvm_profile_filename
	.section	.rodata.__llvm_profile_filename,"aG",@progbits,__llvm_profile_filename,comdat
	.globl	__llvm_profile_filename
	.p2align	4
__llvm_profile_filename:
	.asciz	"example7-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.file	2 "/usr/include/bits/types/struct_FILE.h"
	.file	3 "/usr/include/bits/types.h"
	.file	4 "/usr/lib64/llvm/7/bin/../../../../lib/clang/7.0.1/include/stddef.h"
	.file	5 "/usr/include/bits/types/FILE.h"
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example7.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"main"                  # string offset=194
.Linfo_string4:
	.asciz	"count_characters"      # string offset=199
.Linfo_string5:
	.asciz	"long int"              # string offset=216
.Linfo_string6:
	.asciz	"argc"                  # string offset=225
.Linfo_string7:
	.asciz	"int"                   # string offset=230
.Linfo_string8:
	.asciz	"argv"                  # string offset=234
.Linfo_string9:
	.asciz	"char"                  # string offset=239
.Linfo_string10:
	.asciz	"i"                     # string offset=244
.Linfo_string11:
	.asciz	"cnt"                   # string offset=246
.Linfo_string12:
	.asciz	"ch"                    # string offset=250
.Linfo_string13:
	.asciz	"ch1"                   # string offset=253
.Linfo_string14:
	.asciz	"fp1"                   # string offset=257
.Linfo_string15:
	.asciz	"_flags"                # string offset=261
.Linfo_string16:
	.asciz	"_IO_read_ptr"          # string offset=268
.Linfo_string17:
	.asciz	"_IO_read_end"          # string offset=281
.Linfo_string18:
	.asciz	"_IO_read_base"         # string offset=294
.Linfo_string19:
	.asciz	"_IO_write_base"        # string offset=308
.Linfo_string20:
	.asciz	"_IO_write_ptr"         # string offset=323
.Linfo_string21:
	.asciz	"_IO_write_end"         # string offset=337
.Linfo_string22:
	.asciz	"_IO_buf_base"          # string offset=351
.Linfo_string23:
	.asciz	"_IO_buf_end"           # string offset=364
.Linfo_string24:
	.asciz	"_IO_save_base"         # string offset=376
.Linfo_string25:
	.asciz	"_IO_backup_base"       # string offset=390
.Linfo_string26:
	.asciz	"_IO_save_end"          # string offset=406
.Linfo_string27:
	.asciz	"_markers"              # string offset=419
.Linfo_string28:
	.asciz	"_IO_marker"            # string offset=428
.Linfo_string29:
	.asciz	"_chain"                # string offset=439
.Linfo_string30:
	.asciz	"_fileno"               # string offset=446
.Linfo_string31:
	.asciz	"_flags2"               # string offset=454
.Linfo_string32:
	.asciz	"_old_offset"           # string offset=462
.Linfo_string33:
	.asciz	"__off_t"               # string offset=474
.Linfo_string34:
	.asciz	"_cur_column"           # string offset=482
.Linfo_string35:
	.asciz	"unsigned short"        # string offset=494
.Linfo_string36:
	.asciz	"_vtable_offset"        # string offset=509
.Linfo_string37:
	.asciz	"signed char"           # string offset=524
.Linfo_string38:
	.asciz	"_shortbuf"             # string offset=536
.Linfo_string39:
	.asciz	"__ARRAY_SIZE_TYPE__"   # string offset=546
.Linfo_string40:
	.asciz	"_lock"                 # string offset=566
.Linfo_string41:
	.asciz	"_IO_lock_t"            # string offset=572
.Linfo_string42:
	.asciz	"_offset"               # string offset=583
.Linfo_string43:
	.asciz	"__off64_t"             # string offset=591
.Linfo_string44:
	.asciz	"_codecvt"              # string offset=601
.Linfo_string45:
	.asciz	"_IO_codecvt"           # string offset=610
.Linfo_string46:
	.asciz	"_wide_data"            # string offset=622
.Linfo_string47:
	.asciz	"_IO_wide_data"         # string offset=633
.Linfo_string48:
	.asciz	"_freeres_list"         # string offset=647
.Linfo_string49:
	.asciz	"_freeres_buf"          # string offset=661
.Linfo_string50:
	.asciz	"__pad5"                # string offset=674
.Linfo_string51:
	.asciz	"long unsigned int"     # string offset=681
.Linfo_string52:
	.asciz	"size_t"                # string offset=699
.Linfo_string53:
	.asciz	"_mode"                 # string offset=706
.Linfo_string54:
	.asciz	"_unused2"              # string offset=712
.Linfo_string55:
	.asciz	"_IO_FILE"              # string offset=721
.Linfo_string56:
	.asciz	"FILE"                  # string offset=730
.Linfo_string57:
	.asciz	"fp2"                   # string offset=735
.Linfo_string58:
	.asciz	"f"                     # string offset=739
.Linfo_string59:
	.asciz	"last_pos"              # string offset=741
	.section	.debug_abbrev,"",@progbits
	.byte	1                       # Abbreviation Code
	.byte	17                      # DW_TAG_compile_unit
	.byte	1                       # DW_CHILDREN_yes
	.byte	37                      # DW_AT_producer
	.byte	14                      # DW_FORM_strp
	.byte	19                      # DW_AT_language
	.byte	5                       # DW_FORM_data2
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	16                      # DW_AT_stmt_list
	.byte	23                      # DW_FORM_sec_offset
	.byte	27                      # DW_AT_comp_dir
	.byte	14                      # DW_FORM_strp
	.ascii	"\264B"                 # DW_AT_GNU_pubnames
	.byte	25                      # DW_FORM_flag_present
	.byte	17                      # DW_AT_low_pc
	.byte	1                       # DW_FORM_addr
	.byte	18                      # DW_AT_high_pc
	.byte	6                       # DW_FORM_data4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	2                       # Abbreviation Code
	.byte	46                      # DW_TAG_subprogram
	.byte	1                       # DW_CHILDREN_yes
	.byte	17                      # DW_AT_low_pc
	.byte	1                       # DW_FORM_addr
	.byte	18                      # DW_AT_high_pc
	.byte	6                       # DW_FORM_data4
	.byte	64                      # DW_AT_frame_base
	.byte	24                      # DW_FORM_exprloc
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	39                      # DW_AT_prototyped
	.byte	25                      # DW_FORM_flag_present
	.byte	63                      # DW_AT_external
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	3                       # Abbreviation Code
	.byte	5                       # DW_TAG_formal_parameter
	.byte	0                       # DW_CHILDREN_no
	.byte	2                       # DW_AT_location
	.byte	24                      # DW_FORM_exprloc
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	4                       # Abbreviation Code
	.byte	52                      # DW_TAG_variable
	.byte	0                       # DW_CHILDREN_no
	.byte	2                       # DW_AT_location
	.byte	24                      # DW_FORM_exprloc
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	5                       # Abbreviation Code
	.byte	46                      # DW_TAG_subprogram
	.byte	1                       # DW_CHILDREN_yes
	.byte	17                      # DW_AT_low_pc
	.byte	1                       # DW_FORM_addr
	.byte	18                      # DW_AT_high_pc
	.byte	6                       # DW_FORM_data4
	.byte	64                      # DW_AT_frame_base
	.byte	24                      # DW_FORM_exprloc
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	39                      # DW_AT_prototyped
	.byte	25                      # DW_FORM_flag_present
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	63                      # DW_AT_external
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	6                       # Abbreviation Code
	.byte	36                      # DW_TAG_base_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	62                      # DW_AT_encoding
	.byte	11                      # DW_FORM_data1
	.byte	11                      # DW_AT_byte_size
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	7                       # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	8                       # Abbreviation Code
	.byte	22                      # DW_TAG_typedef
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	9                       # Abbreviation Code
	.byte	19                      # DW_TAG_structure_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	11                      # DW_AT_byte_size
	.byte	11                      # DW_FORM_data1
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	10                      # Abbreviation Code
	.byte	13                      # DW_TAG_member
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	56                      # DW_AT_data_member_location
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	11                      # Abbreviation Code
	.byte	19                      # DW_TAG_structure_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	60                      # DW_AT_declaration
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	12                      # Abbreviation Code
	.byte	1                       # DW_TAG_array_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	13                      # Abbreviation Code
	.byte	33                      # DW_TAG_subrange_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	55                      # DW_AT_count
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	14                      # Abbreviation Code
	.byte	36                      # DW_TAG_base_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	11                      # DW_AT_byte_size
	.byte	11                      # DW_FORM_data1
	.byte	62                      # DW_AT_encoding
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	15                      # Abbreviation Code
	.byte	22                      # DW_TAG_typedef
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	16                      # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	752                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x2e9 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x82 DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
                                        # DW_AT_prototyped
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0x37:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	225                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x45:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	96
	.long	.Linfo_string8          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	232                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x53:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	92
	.long	.Linfo_string10         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	10                      # DW_AT_decl_line
	.long	225                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x61:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	112
	.long	.Linfo_string11         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	11                      # DW_AT_decl_line
	.long	218                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x6f:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	127
	.long	.Linfo_string12         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	12                      # DW_AT_decl_line
	.long	242                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x7d:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	91
	.long	.Linfo_string13         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	12                      # DW_AT_decl_line
	.long	242                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x8b:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string14         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	13                      # DW_AT_decl_line
	.long	249                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x99:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	104
	.long	.Linfo_string57         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	13                      # DW_AT_decl_line
	.long	249                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	5                       # Abbrev [5] 0xa8:0x32 DW_TAG_subprogram
	.long	.Lfunc_begin1           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin1 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string4          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	40                      # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	218                     # DW_AT_type
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0xbd:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string58         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	40                      # DW_AT_decl_line
	.long	249                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0xcb:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string59         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	42                      # DW_AT_decl_line
	.long	218                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	6                       # Abbrev [6] 0xda:0x7 DW_TAG_base_type
	.long	.Linfo_string5          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	8                       # DW_AT_byte_size
	.byte	6                       # Abbrev [6] 0xe1:0x7 DW_TAG_base_type
	.long	.Linfo_string7          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	7                       # Abbrev [7] 0xe8:0x5 DW_TAG_pointer_type
	.long	237                     # DW_AT_type
	.byte	7                       # Abbrev [7] 0xed:0x5 DW_TAG_pointer_type
	.long	242                     # DW_AT_type
	.byte	6                       # Abbrev [6] 0xf2:0x7 DW_TAG_base_type
	.long	.Linfo_string9          # DW_AT_name
	.byte	6                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	7                       # Abbrev [7] 0xf9:0x5 DW_TAG_pointer_type
	.long	254                     # DW_AT_type
	.byte	8                       # Abbrev [8] 0xfe:0xb DW_TAG_typedef
	.long	265                     # DW_AT_type
	.long	.Linfo_string56         # DW_AT_name
	.byte	5                       # DW_AT_decl_file
	.byte	7                       # DW_AT_decl_line
	.byte	9                       # Abbrev [9] 0x109:0x165 DW_TAG_structure_type
	.long	.Linfo_string55         # DW_AT_name
	.byte	216                     # DW_AT_byte_size
	.byte	2                       # DW_AT_decl_file
	.byte	49                      # DW_AT_decl_line
	.byte	10                      # Abbrev [10] 0x111:0xc DW_TAG_member
	.long	.Linfo_string15         # DW_AT_name
	.long	225                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	51                      # DW_AT_decl_line
	.byte	0                       # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x11d:0xc DW_TAG_member
	.long	.Linfo_string16         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	54                      # DW_AT_decl_line
	.byte	8                       # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x129:0xc DW_TAG_member
	.long	.Linfo_string17         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	55                      # DW_AT_decl_line
	.byte	16                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x135:0xc DW_TAG_member
	.long	.Linfo_string18         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	56                      # DW_AT_decl_line
	.byte	24                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x141:0xc DW_TAG_member
	.long	.Linfo_string19         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	57                      # DW_AT_decl_line
	.byte	32                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x14d:0xc DW_TAG_member
	.long	.Linfo_string20         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	58                      # DW_AT_decl_line
	.byte	40                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x159:0xc DW_TAG_member
	.long	.Linfo_string21         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	59                      # DW_AT_decl_line
	.byte	48                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x165:0xc DW_TAG_member
	.long	.Linfo_string22         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	60                      # DW_AT_decl_line
	.byte	56                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x171:0xc DW_TAG_member
	.long	.Linfo_string23         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	61                      # DW_AT_decl_line
	.byte	64                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x17d:0xc DW_TAG_member
	.long	.Linfo_string24         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	64                      # DW_AT_decl_line
	.byte	72                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x189:0xc DW_TAG_member
	.long	.Linfo_string25         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	65                      # DW_AT_decl_line
	.byte	80                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x195:0xc DW_TAG_member
	.long	.Linfo_string26         # DW_AT_name
	.long	237                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	66                      # DW_AT_decl_line
	.byte	88                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1a1:0xc DW_TAG_member
	.long	.Linfo_string27         # DW_AT_name
	.long	622                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	68                      # DW_AT_decl_line
	.byte	96                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1ad:0xc DW_TAG_member
	.long	.Linfo_string29         # DW_AT_name
	.long	632                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	70                      # DW_AT_decl_line
	.byte	104                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1b9:0xc DW_TAG_member
	.long	.Linfo_string30         # DW_AT_name
	.long	225                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	72                      # DW_AT_decl_line
	.byte	112                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1c5:0xc DW_TAG_member
	.long	.Linfo_string31         # DW_AT_name
	.long	225                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	73                      # DW_AT_decl_line
	.byte	116                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1d1:0xc DW_TAG_member
	.long	.Linfo_string32         # DW_AT_name
	.long	637                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	74                      # DW_AT_decl_line
	.byte	120                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1dd:0xc DW_TAG_member
	.long	.Linfo_string34         # DW_AT_name
	.long	648                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	77                      # DW_AT_decl_line
	.byte	128                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1e9:0xc DW_TAG_member
	.long	.Linfo_string36         # DW_AT_name
	.long	655                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	78                      # DW_AT_decl_line
	.byte	130                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x1f5:0xc DW_TAG_member
	.long	.Linfo_string38         # DW_AT_name
	.long	662                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	79                      # DW_AT_decl_line
	.byte	131                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x201:0xc DW_TAG_member
	.long	.Linfo_string40         # DW_AT_name
	.long	681                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	81                      # DW_AT_decl_line
	.byte	136                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x20d:0xc DW_TAG_member
	.long	.Linfo_string42         # DW_AT_name
	.long	693                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	89                      # DW_AT_decl_line
	.byte	144                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x219:0xc DW_TAG_member
	.long	.Linfo_string44         # DW_AT_name
	.long	704                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	91                      # DW_AT_decl_line
	.byte	152                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x225:0xc DW_TAG_member
	.long	.Linfo_string46         # DW_AT_name
	.long	714                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	92                      # DW_AT_decl_line
	.byte	160                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x231:0xc DW_TAG_member
	.long	.Linfo_string48         # DW_AT_name
	.long	632                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	93                      # DW_AT_decl_line
	.byte	168                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x23d:0xc DW_TAG_member
	.long	.Linfo_string49         # DW_AT_name
	.long	724                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	94                      # DW_AT_decl_line
	.byte	176                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x249:0xc DW_TAG_member
	.long	.Linfo_string50         # DW_AT_name
	.long	725                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	95                      # DW_AT_decl_line
	.byte	184                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x255:0xc DW_TAG_member
	.long	.Linfo_string53         # DW_AT_name
	.long	225                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	96                      # DW_AT_decl_line
	.byte	192                     # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x261:0xc DW_TAG_member
	.long	.Linfo_string54         # DW_AT_name
	.long	743                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	98                      # DW_AT_decl_line
	.byte	196                     # DW_AT_data_member_location
	.byte	0                       # End Of Children Mark
	.byte	7                       # Abbrev [7] 0x26e:0x5 DW_TAG_pointer_type
	.long	627                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x273:0x5 DW_TAG_structure_type
	.long	.Linfo_string28         # DW_AT_name
                                        # DW_AT_declaration
	.byte	7                       # Abbrev [7] 0x278:0x5 DW_TAG_pointer_type
	.long	265                     # DW_AT_type
	.byte	8                       # Abbrev [8] 0x27d:0xb DW_TAG_typedef
	.long	218                     # DW_AT_type
	.long	.Linfo_string33         # DW_AT_name
	.byte	3                       # DW_AT_decl_file
	.byte	150                     # DW_AT_decl_line
	.byte	6                       # Abbrev [6] 0x288:0x7 DW_TAG_base_type
	.long	.Linfo_string35         # DW_AT_name
	.byte	7                       # DW_AT_encoding
	.byte	2                       # DW_AT_byte_size
	.byte	6                       # Abbrev [6] 0x28f:0x7 DW_TAG_base_type
	.long	.Linfo_string37         # DW_AT_name
	.byte	6                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	12                      # Abbrev [12] 0x296:0xc DW_TAG_array_type
	.long	242                     # DW_AT_type
	.byte	13                      # Abbrev [13] 0x29b:0x6 DW_TAG_subrange_type
	.long	674                     # DW_AT_type
	.byte	1                       # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	14                      # Abbrev [14] 0x2a2:0x7 DW_TAG_base_type
	.long	.Linfo_string39         # DW_AT_name
	.byte	8                       # DW_AT_byte_size
	.byte	7                       # DW_AT_encoding
	.byte	7                       # Abbrev [7] 0x2a9:0x5 DW_TAG_pointer_type
	.long	686                     # DW_AT_type
	.byte	15                      # Abbrev [15] 0x2ae:0x7 DW_TAG_typedef
	.long	.Linfo_string41         # DW_AT_name
	.byte	2                       # DW_AT_decl_file
	.byte	43                      # DW_AT_decl_line
	.byte	8                       # Abbrev [8] 0x2b5:0xb DW_TAG_typedef
	.long	218                     # DW_AT_type
	.long	.Linfo_string43         # DW_AT_name
	.byte	3                       # DW_AT_decl_file
	.byte	151                     # DW_AT_decl_line
	.byte	7                       # Abbrev [7] 0x2c0:0x5 DW_TAG_pointer_type
	.long	709                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x2c5:0x5 DW_TAG_structure_type
	.long	.Linfo_string45         # DW_AT_name
                                        # DW_AT_declaration
	.byte	7                       # Abbrev [7] 0x2ca:0x5 DW_TAG_pointer_type
	.long	719                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x2cf:0x5 DW_TAG_structure_type
	.long	.Linfo_string47         # DW_AT_name
                                        # DW_AT_declaration
	.byte	16                      # Abbrev [16] 0x2d4:0x1 DW_TAG_pointer_type
	.byte	8                       # Abbrev [8] 0x2d5:0xb DW_TAG_typedef
	.long	736                     # DW_AT_type
	.long	.Linfo_string52         # DW_AT_name
	.byte	4                       # DW_AT_decl_file
	.byte	62                      # DW_AT_decl_line
	.byte	6                       # Abbrev [6] 0x2e0:0x7 DW_TAG_base_type
	.long	.Linfo_string51         # DW_AT_name
	.byte	7                       # DW_AT_encoding
	.byte	8                       # DW_AT_byte_size
	.byte	12                      # Abbrev [12] 0x2e7:0xc DW_TAG_array_type
	.long	242                     # DW_AT_type
	.byte	13                      # Abbrev [13] 0x2ec:0x6 DW_TAG_subrange_type
	.long	674                     # DW_AT_type
	.byte	20                      # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	0                       # End Of Children Mark
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark
	.section	.debug_pubnames,"",@progbits
	.long	.LpubNames_end0-.LpubNames_begin0 # Length of Public Names Info
.LpubNames_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	756                     # Compilation Unit Length
	.long	38                      # DIE offset
	.asciz	"main"                  # External Name
	.long	168                     # DIE offset
	.asciz	"count_characters"      # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	756                     # Compilation Unit Length
	.long	254                     # DIE offset
	.asciz	"FILE"                  # External Name
	.long	686                     # DIE offset
	.asciz	"_IO_lock_t"            # External Name
	.long	648                     # DIE offset
	.asciz	"unsigned short"        # External Name
	.long	265                     # DIE offset
	.asciz	"_IO_FILE"              # External Name
	.long	693                     # DIE offset
	.asciz	"__off64_t"             # External Name
	.long	655                     # DIE offset
	.asciz	"signed char"           # External Name
	.long	736                     # DIE offset
	.asciz	"long unsigned int"     # External Name
	.long	218                     # DIE offset
	.asciz	"long int"              # External Name
	.long	225                     # DIE offset
	.asciz	"int"                   # External Name
	.long	637                     # DIE offset
	.asciz	"__off_t"               # External Name
	.long	242                     # DIE offset
	.asciz	"char"                  # External Name
	.long	725                     # DIE offset
	.asciz	"size_t"                # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
