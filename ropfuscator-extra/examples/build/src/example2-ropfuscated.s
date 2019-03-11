	.text
	.file	"example2.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c"
	.loc	1 3 0                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:3:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	pushl	%esi
	subl	$36, %esp
	.cfi_offset %esi, -12
	movl	$0, -20(%ebp)
.Ltmp0:
	.loc	1 3 12 prologue_end     # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:3:12
	movl	.L__profc_main, %eax
	pushfl
	calll	.chain_0
	jmp	.resume_0
	#APP
.chain_0:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver __strtof128_nan, __strtof128_nan@GLIBC_PRIVATE

	#NO_APP
	pushl	$__strtof128_nan
	addl	$356291, (%esp)         # imm = 0x56FC3
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver getgrgid, getgrgid@GLIBC_2.0

	#NO_APP
	pushl	$getgrgid
	addl	$-538506, (%esp)        # imm = 0xFFF7C876
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver xdr_hyper, xdr_hyper@GLIBC_2.1.1

	#NO_APP
	pushl	$xdr_hyper
	addl	$-1016998, (%esp)       # imm = 0xFFF07B5A
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver printf_size_info, printf_size_info@GLIBC_2.1

	#NO_APP
	pushl	$printf_size_info
	addl	$-80282, (%esp)         # imm = 0xFFFEC666
	pushl	$1
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver svcfd_create, svcfd_create@GLIBC_2.0

	#NO_APP
	pushl	$svcfd_create
	addl	$-1186189, (%esp)       # imm = 0xFFEDE673
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver svcunix_create, svcunix_create@GLIBC_2.1

	#NO_APP
	pushl	$svcunix_create
	addl	$-987686, (%esp)        # imm = 0xFFF0EDDA
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver getrpcbyname, getrpcbyname@GLIBC_2.0

	#NO_APP
	pushl	$getrpcbyname
	addl	$-987930, (%esp)        # imm = 0xFFF0ECE6
	calll	opaquePredicate
	jne	.chain_0
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-279782, (%esp)        # imm = 0xFFFBBB1A
	retl
	#APP
.resume_0:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+4
	movl	%eax, .L__profc_main
	.loc	1 5 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:5:3
	leal	.L.str, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 6 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:6:3
	leal	.L.str.1, %eax
	movl	%eax, (%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	calll	__isoc99_scanf
	pushfl
	calll	.chain_1
	jmp	.resume_1
	#APP
.chain_1:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver putwc_unlocked, putwc_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$putwc_unlocked
	addl	$-175026, (%esp)        # imm = 0xFFFD544E
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver xdr_bool, xdr_bool@GLIBC_2.0

	#NO_APP
	pushl	$xdr_bool
	addl	$-1018086, (%esp)       # imm = 0xFFF0771A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __readlink_chk, __readlink_chk@GLIBC_2.4

	#NO_APP
	pushl	$__readlink_chk
	addl	$-863942, (%esp)        # imm = 0xFFF2D13A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-1020646, (%esp)       # imm = 0xFFF06D1A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver srand48, srand48@GLIBC_2.0

	#NO_APP
	pushl	$srand48
	addl	$-102833, (%esp)        # imm = 0xFFFE6E4F
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __assert_perror_fail, __assert_perror_fail@GLIBC_2.0

	#NO_APP
	pushl	$__assert_perror_fail
	addl	$114826, (%esp)         # imm = 0x1C08A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __libc_dlclose, __libc_dlclose@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlclose
	addl	$-661725, (%esp)        # imm = 0xFFF5E723
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver sigorset, sigorset@GLIBC_2.0

	#NO_APP
	pushl	$sigorset
	addl	$-89569, (%esp)         # imm = 0xFFFEA21F
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver key_secretkey_is_set, key_secretkey_is_set@GLIBC_2.1

	#NO_APP
	pushl	$key_secretkey_is_set
	addl	$-1002182, (%esp)       # imm = 0xFFF0B53A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver inet_lnaof, inet_lnaof@GLIBC_2.0

	#NO_APP
	pushl	$inet_lnaof
	addl	$-1036513, (%esp)       # imm = 0xFFF02F1F
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver svcudp_create, svcudp_create@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_create
	addl	$-1014454, (%esp)       # imm = 0xFFF0854A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver epoll_create, epoll_create@GLIBC_2.3.2

	#NO_APP
	pushl	$epoll_create
	addl	$-805546, (%esp)        # imm = 0xFFF3B556
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver xdr_rejected_reply, xdr_rejected_reply@GLIBC_2.0

	#NO_APP
	pushl	$xdr_rejected_reply
	addl	$-1128225, (%esp)       # imm = 0xFFEEC8DF
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __wcstoll_internal, __wcstoll_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstoll_internal
	addl	$-402074, (%esp)        # imm = 0xFFF9DD66
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-1040061, (%esp)       # imm = 0xFFF02143
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __res_ninit, __res_ninit@GLIBC_2.2

	#NO_APP
	pushl	$__res_ninit
	addl	$-1099649, (%esp)       # imm = 0xFFEF387F
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver free, free@GLIBC_2.0

	#NO_APP
	pushl	$free
	addl	$-264490, (%esp)        # imm = 0xFFFBF6D6
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver htonl, htonl@GLIBC_2.0

	#NO_APP
	pushl	$htonl
	addl	$-1036481, (%esp)       # imm = 0xFFF02F3F
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-226182, (%esp)        # imm = 0xFFFC8C7A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver wcsftime, wcsftime@GLIBC_2.2

	#NO_APP
	pushl	$wcsftime
	addl	$-498598, (%esp)        # imm = 0xFFF8645A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver _obstack_free, _obstack_free@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_free
	addl	$-412467, (%esp)        # imm = 0xFFF9B4CD
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __strtol_internal, __strtol_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtol_internal
	addl	$58554, (%esp)          # imm = 0xE4BA
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver sigignore, sigignore@GLIBC_2.1

	#NO_APP
	pushl	$sigignore
	addl	$386212, (%esp)         # imm = 0x5E4A4
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$-34579, (%esp)         # imm = 0xFFFF78ED
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver endusershell, endusershell@GLIBC_2.0

	#NO_APP
	pushl	$endusershell
	addl	$-769126, (%esp)        # imm = 0xFFF4439A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver isdigit, isdigit@GLIBC_2.0

	#NO_APP
	pushl	$isdigit
	addl	$-30483, (%esp)         # imm = 0x88ED
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver strerror, strerror@GLIBC_2.0

	#NO_APP
	pushl	$strerror
	addl	$-271142, (%esp)        # imm = 0xFFFBDCDA
	retl
	#APP
.resume_1:
	#NO_APP
	popfl
	.loc	1 9 21                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:9:21
	cmpl	-12(%ebp), %eax
	.loc	1 9 17 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:9:17
	jle	.LBB0_2
# %bb.1:
	movl	.L__profc_main+8, %eax
	pushfl
	calll	.chain_2
	jmp	.resume_2
	#APP
.chain_2:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver qgcvt, qgcvt@GLIBC_2.0

	#NO_APP
	pushl	$qgcvt
	addl	$-397597, (%esp)        # imm = 0xFFF9EEE3
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-801786, (%esp)        # imm = 0xFFF3C406
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver clnt_spcreateerror, clnt_spcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_spcreateerror
	addl	$-1002554, (%esp)       # imm = 0xFFF0B3C6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __snprintf, __snprintf@GLIBC_PRIVATE

	#NO_APP
	pushl	$__snprintf
	addl	$-246397, (%esp)        # imm = 0xFFFC3D83
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-772726, (%esp)        # imm = 0xFFF4358A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __iswpunct_l, __iswpunct_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswpunct_l
	addl	$-822410, (%esp)        # imm = 0xFFF37376
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __poll_chk, __poll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__poll_chk
	addl	$-870902, (%esp)        # imm = 0xFFF2B60A
	retl
	#APP
.resume_2:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+12
	movl	%eax, .L__profc_main+8
	pushfl
	calll	.chain_3
	jmp	.resume_3
	#APP
.chain_3:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver _obstack_begin, _obstack_begin@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin
	addl	$-267282, (%esp)        # imm = 0xFFFBEBEE
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$74611, (%esp)          # imm = 0x12373
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-492058, (%esp)        # imm = 0xFFF87DE6
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver setlogin, setlogin@GLIBC_2.0

	#NO_APP
	pushl	$setlogin
	addl	$-1026966, (%esp)       # imm = 0xFFF0546A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-722570, (%esp)        # imm = 0xFFF4F976
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-972877, (%esp)        # imm = 0xFFF127B3
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __asprintf_chk, __asprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__asprintf_chk
	addl	$-869142, (%esp)        # imm = 0xFFF2BCEA
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __sched_get_priority_max, __sched_get_priority_max@GLIBC_2.0

	#NO_APP
	pushl	$__sched_get_priority_max
	addl	$-673306, (%esp)        # imm = 0xFFF5B9E6
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __islower_l, __islower_l@GLIBC_2.1

	#NO_APP
	pushl	$__islower_l
	addl	$112906, (%esp)         # imm = 0x1B90A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver isspace, isspace@GLIBC_2.0

	#NO_APP
	pushl	$isspace
	addl	$114010, (%esp)         # imm = 0x1BD5A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver getrpcbynumber_r, getrpcbynumber_r@GLIBC_2.0

	#NO_APP
	pushl	$getrpcbynumber_r
	addl	$-1236707, (%esp)       # imm = 0xFFED211D
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver iconv_close, iconv_close@GLIBC_2.1

	#NO_APP
	pushl	$iconv_close
	addl	$163898, (%esp)         # imm = 0x2803A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-553996, (%esp)        # imm = 0xFFF78BF4
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver envz_strip, envz_strip@GLIBC_2.0

	#NO_APP
	pushl	$envz_strip
	addl	$-432723, (%esp)        # imm = 0xFFF965AD
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver strtod, strtod@GLIBC_2.0

	#NO_APP
	pushl	$strtod
	addl	$50474, (%esp)          # imm = 0xC52A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-941939, (%esp)        # imm = 0xFFF1A08D
	retl
	#APP
.resume_3:
	#NO_APP
	popfl
	jmp	.LBB0_3
.LBB0_2:
	.loc	1 0 17                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:0:17
	pushfl
	calll	.chain_4
	jmp	.resume_4
	#APP
.chain_4:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver setegid, setegid@GLIBC_2.0

	#NO_APP
	pushl	$setegid
	addl	$-758066, (%esp)        # imm = 0xFFF46ECE
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver remove, remove@GLIBC_2.0

	#NO_APP
	pushl	$remove
	addl	$229811, (%esp)         # imm = 0x381B3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver process_vm_writev, process_vm_writev@GLIBC_2.15

	#NO_APP
	pushl	$process_vm_writev
	addl	$-806826, (%esp)        # imm = 0xFFF3B056
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-961302, (%esp)        # imm = 0xFFF154EA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-927194, (%esp)        # imm = 0xFFF1DA26
	pushl	$-76
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-932365, (%esp)        # imm = 0xFFF1C5F3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-540870, (%esp)        # imm = 0xFFF7BF3A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __openat64_2, __openat64_2@GLIBC_2.7

	#NO_APP
	pushl	$__openat64_2
	addl	$-719642, (%esp)        # imm = 0xFFF504E6
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver shmdt, shmdt@GLIBC_2.0

	#NO_APP
	pushl	$shmdt
	addl	$-803638, (%esp)        # imm = 0xFFF3BCCA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __strspn_g, __strspn_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_g
	addl	$-304310, (%esp)        # imm = 0xFFFB5B4A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __nss_lookup, __nss_lookup@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_lookup
	addl	$-1092867, (%esp)       # imm = 0xFFEF52FD
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __stack_chk_fail, __stack_chk_fail@GLIBC_2.4

	#NO_APP
	pushl	$__stack_chk_fail
	addl	$-871126, (%esp)        # imm = 0xFFF2B52A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver atoll, atoll@GLIBC_2.0

	#NO_APP
	pushl	$atoll
	addl	$385524, (%esp)         # imm = 0x5E1F4
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __waitpid, __waitpid@GLIBC_2.0

	#NO_APP
	pushl	$__waitpid
	addl	$-687299, (%esp)        # imm = 0xFFF5833D
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
	addl	$-1181859, (%esp)       # imm = 0xFFEDF75D
	retl
	#APP
.resume_4:
	#NO_APP
	popfl
.LBB0_3:
	pushfl
	calll	.chain_5
	jmp	.resume_5
	#APP
.chain_5:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-874286, (%esp)        # imm = 0xFFF2A8D2
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-750374, (%esp)        # imm = 0xFFF48CDA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __libc_vfork, __libc_vfork@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_vfork
	addl	$-544022, (%esp)        # imm = 0xFFF7B2EA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver initgroups, initgroups@GLIBC_2.0

	#NO_APP
	pushl	$initgroups
	addl	$-694609, (%esp)        # imm = 0xFFF566AF
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver mblen, mblen@GLIBC_2.0

	#NO_APP
	pushl	$mblen
	addl	$65674, (%esp)          # imm = 0x1008A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$453171, (%esp)         # imm = 0x6EA33
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __libc_longjmp, __libc_longjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_longjmp
	addl	$-84913, (%esp)         # imm = 0xFFFEB44F
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __tolower_l, __tolower_l@GLIBC_2.1

	#NO_APP
	pushl	$__tolower_l
	addl	$112458, (%esp)         # imm = 0x1B74A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver execle, execle@GLIBC_2.0

	#NO_APP
	pushl	$execle
	addl	$-709665, (%esp)        # imm = 0xFFF52BDF
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __strncmp_g, __strncmp_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncmp_g
	addl	$-304038, (%esp)        # imm = 0xFFFB5C5A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-927850, (%esp)        # imm = 0xFFF1D796
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __strlen_g, __strlen_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strlen_g
	addl	$-468753, (%esp)        # imm = 0xFFF8D8EF
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver ioperm, ioperm@GLIBC_2.0

	#NO_APP
	pushl	$ioperm
	addl	$-801738, (%esp)        # imm = 0xFFF3C436
	pushl	$-32
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver mrand48_r, mrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$mrand48_r
	addl	$-112669, (%esp)        # imm = 0xFFFE47E3
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver svcraw_create, svcraw_create@GLIBC_2.0

	#NO_APP
	pushl	$svcraw_create
	addl	$-1131841, (%esp)       # imm = 0xFFEEBABF
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-238554, (%esp)        # imm = 0xFFFC5C26
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __pread64_chk, __pread64_chk@GLIBC_2.4

	#NO_APP
	pushl	$__pread64_chk
	addl	$-1028865, (%esp)       # imm = 0xFFF04CFF
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __vsnprintf_chk, __vsnprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsnprintf_chk
	addl	$-860662, (%esp)        # imm = 0xFFF2DE0A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver rcmd_af, rcmd_af@GLIBC_2.2

	#NO_APP
	pushl	$rcmd_af
	addl	$-892998, (%esp)        # imm = 0xFFF25FBA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver atol, atol@GLIBC_2.0

	#NO_APP
	pushl	$atol
	addl	$-71027, (%esp)         # imm = 0xFFFEEA8D
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver getmsg, getmsg@GLIBC_2.1

	#NO_APP
	pushl	$getmsg
	addl	$-1024982, (%esp)       # imm = 0xFFF05C2A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver inet_netof, inet_netof@GLIBC_2.0

	#NO_APP
	pushl	$inet_netof
	addl	$-559868, (%esp)        # imm = 0xFFF77504
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$-346931, (%esp)        # imm = 0xFFFAB4CD
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __nss_hostname_digits_dots, __nss_hostname_digits_dots@GLIBC_2.2.2

	#NO_APP
	pushl	$__nss_hostname_digits_dots
	addl	$-951830, (%esp)        # imm = 0xFFF179EA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver fsync, fsync@GLIBC_2.0

	#NO_APP
	pushl	$fsync
	addl	$-903715, (%esp)        # imm = 0xFFF235DD
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __isoc99_vfscanf, __isoc99_vfscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfscanf
	addl	$-150342, (%esp)        # imm = 0xFFFDB4BA
	retl
	#APP
.resume_5:
	#NO_APP
	popfl
.LBB0_4:                                # =>This Inner Loop Header: Depth=1
	.loc	1 12 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:12:3
	movl	.L__profc_main+16, %eax
	pushfl
	calll	.chain_6
	jmp	.resume_6
	#APP
.chain_6:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __register_atfork, __register_atfork@GLIBC_2.3.2

	#NO_APP
	pushl	$__register_atfork
	addl	$-475549, (%esp)        # imm = 0xFFF8BE63
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __ptsname_r_chk, __ptsname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ptsname_r_chk
	addl	$-1045354, (%esp)       # imm = 0xFFF00C96
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$50778, (%esp)          # imm = 0xC65A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver siggetmask, siggetmask@GLIBC_2.0

	#NO_APP
	pushl	$siggetmask
	addl	$67702, (%esp)          # imm = 0x10876
	pushl	$1
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __idna_from_dns_encoding, __idna_from_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_from_dns_encoding
	addl	$-1096525, (%esp)       # imm = 0xFFEF44B3
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-816390, (%esp)        # imm = 0xFFF38AFA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver xdr_quad_t, xdr_quad_t@GLIBC_2.3.4

	#NO_APP
	pushl	$xdr_quad_t
	addl	$-1028202, (%esp)       # imm = 0xFFF04F96
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver sigismember, sigismember@GLIBC_2.0

	#NO_APP
	pushl	$sigismember
	addl	$76298, (%esp)          # imm = 0x12A0A
	retl
	#APP
.resume_6:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+20
	movl	%eax, .L__profc_main+16
	pushfl
	calll	.chain_7
	jmp	.resume_7
	#APP
.chain_7:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver fts_set, fts_set@GLIBC_2.0

	#NO_APP
	pushl	$fts_set
	addl	$-736626, (%esp)        # imm = 0xFFF4C28E
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver xdr_array, xdr_array@GLIBC_2.0

	#NO_APP
	pushl	$xdr_array
	addl	$-637197, (%esp)        # imm = 0xFFF646F3
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-767450, (%esp)        # imm = 0xFFF44A26
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$70666, (%esp)          # imm = 0x1140A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-180362, (%esp)        # imm = 0xFFFD3F76
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver pthread_attr_init, pthread_attr_init@GLIBC_2.1

	#NO_APP
	pushl	$pthread_attr_init
	addl	$-1024653, (%esp)       # imm = 0xFFF05D73
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-1089014, (%esp)       # imm = 0xFFEF620A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver labs, labs@GLIBC_2.0

	#NO_APP
	pushl	$labs
	addl	$57606, (%esp)          # imm = 0xE106
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __getdomainname_chk, __getdomainname_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getdomainname_chk
	addl	$-868518, (%esp)        # imm = 0xFFF2BF5A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __profile_frequency, __profile_frequency@GLIBC_2.0

	#NO_APP
	pushl	$__profile_frequency
	addl	$-809350, (%esp)        # imm = 0xFFF3A67A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-895267, (%esp)        # imm = 0xFFF256DD
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver getprotobyname_r, getprotobyname_r@GLIBC_2.0

	#NO_APP
	pushl	$getprotobyname_r
	addl	$-1090934, (%esp)       # imm = 0xFFEF5A8A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-446300, (%esp)        # imm = 0xFFF930A4
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver iruserok_af, iruserok_af@GLIBC_2.2

	#NO_APP
	pushl	$iruserok_af
	addl	$-1041475, (%esp)       # imm = 0xFFF01BBD
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver endaliasent, endaliasent@GLIBC_2.0

	#NO_APP
	pushl	$endaliasent
	addl	$-904694, (%esp)        # imm = 0xFFF2320A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __stpcpy_small, __stpcpy_small@GLIBC_2.1.1

	#NO_APP
	pushl	$__stpcpy_small
	addl	$-448035, (%esp)        # imm = 0xFFF929DD
	retl
	#APP
.resume_7:
	#NO_APP
	popfl
.Ltmp1:
	.loc	1 13 21                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:21
	cltd
	idivl	-16(%ebp)
	.loc	1 13 26 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:26
	cmpl	$0, %edx
	.loc	1 13 31                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:31
	jne	.LBB0_7
.Ltmp2:
# %bb.5:                                #   in Loop: Header=BB0_4 Depth=1
	.loc	1 13 9                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:9
	movl	.L__profc_main+32, %eax
	pushfl
	calll	.chain_8
	jmp	.resume_8
	#APP
.chain_8:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver ualarm, ualarm@GLIBC_2.0

	#NO_APP
	pushl	$ualarm
	addl	$-382525, (%esp)        # imm = 0xFFFA29C3
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __fdelt_warn, __fdelt_warn@GLIBC_2.15

	#NO_APP
	pushl	$__fdelt_warn
	addl	$-879290, (%esp)        # imm = 0xFFF29546
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strspn_c1, __strspn_c1@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_c1
	addl	$-302070, (%esp)        # imm = 0xFFFB640A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver rresvport_af, rresvport_af@GLIBC_2.2

	#NO_APP
	pushl	$rresvport_af
	addl	$-901002, (%esp)        # imm = 0xFFF24076
	pushl	$1
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver getnetbyname, getnetbyname@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname
	addl	$-1054157, (%esp)       # imm = 0xFFEFEA33
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$-266870, (%esp)        # imm = 0xFFFBED8A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver munlock, munlock@GLIBC_2.0

	#NO_APP
	pushl	$munlock
	addl	$-782522, (%esp)        # imm = 0xFFF40F46
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __sysconf, __sysconf@GLIBC_2.2

	#NO_APP
	pushl	$__sysconf
	addl	$-550806, (%esp)        # imm = 0xFFF7986A
	retl
	#APP
.resume_8:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+36
	movl	%eax, .L__profc_main+32
	pushfl
	calll	.chain_9
	jmp	.resume_9
	#APP
.chain_9:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ecvt, ecvt@GLIBC_2.0

	#NO_APP
	pushl	$ecvt
	addl	$-775042, (%esp)        # imm = 0xFFF42C7E
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ftok, ftok@GLIBC_2.0

	#NO_APP
	pushl	$ftok
	addl	$-423693, (%esp)        # imm = 0xFFF988F3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fgetpos, fgetpos@GLIBC_2.0

	#NO_APP
	pushl	$fgetpos
	addl	$-1065338, (%esp)       # imm = 0xFFEFBE86
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver inet6_option_find, inet6_option_find@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_find
	addl	$-916774, (%esp)        # imm = 0xFFF202DA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __munmap, __munmap@GLIBC_PRIVATE

	#NO_APP
	pushl	$__munmap
	addl	$-782026, (%esp)        # imm = 0xFFF41136
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ptrace, ptrace@GLIBC_2.0

	#NO_APP
	pushl	$ptrace
	addl	$-935805, (%esp)        # imm = 0xFFF1B883
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __freading, __freading@GLIBC_2.2

	#NO_APP
	pushl	$__freading
	addl	$-201830, (%esp)        # imm = 0xFFFCEB9A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_setbuffer, _IO_setbuffer@GLIBC_2.0

	#NO_APP
	pushl	$_IO_setbuffer
	addl	$-176874, (%esp)        # imm = 0xFFFD4D16
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver mkstemp64, mkstemp64@GLIBC_2.2

	#NO_APP
	pushl	$mkstemp64
	addl	$-760358, (%esp)        # imm = 0xFFF465DA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$29367, (%esp)          # imm = 0x72B7
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver setsgent, setsgent@GLIBC_2.10

	#NO_APP
	pushl	$setsgent
	addl	$-824006, (%esp)        # imm = 0xFFF36D3A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __getcwd_chk, __getcwd_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getcwd_chk
	addl	$-552492, (%esp)        # imm = 0xFFF791D4
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-448835, (%esp)        # imm = 0xFFF926BD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_feof, _IO_feof@GLIBC_2.0

	#NO_APP
	pushl	$_IO_feof
	addl	$-193718, (%esp)        # imm = 0xFFFD0B4A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver clnt_sperror, clnt_sperror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_sperror
	addl	$-1138307, (%esp)       # imm = 0xFFEEA17D
	retl
	#APP
.resume_9:
	#NO_APP
	popfl
.Ltmp3:
	.loc	1 13 46                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:46
	cltd
	idivl	-12(%ebp)
	.loc	1 13 51                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:51
	cmpl	$0, %edx
.Ltmp4:
	.loc	1 13 9                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:13:9
	jne	.LBB0_7
# %bb.6:
	movl	.L__profc_main+24, %eax
	pushfl
	calll	.chain_10
	jmp	.resume_10
	#APP
.chain_10:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver mbstowcs, mbstowcs@GLIBC_2.0

	#NO_APP
	pushl	$mbstowcs
	addl	$443987, (%esp)         # imm = 0x6C653
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver vwprintf, vwprintf@GLIBC_2.2

	#NO_APP
	pushl	$vwprintf
	addl	$-183834, (%esp)        # imm = 0xFFFD31E6
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _setjmp, _setjmp@GLIBC_2.0

	#NO_APP
	pushl	$_setjmp
	addl	$80410, (%esp)          # imm = 0x13A1A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-80586, (%esp)         # imm = 0xFFFEC536
	pushl	$1
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver setjmp, setjmp@GLIBC_2.0

	#NO_APP
	pushl	$setjmp
	addl	$-93869, (%esp)         # imm = 0xFFFE9153
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver inet6_rth_add, inet6_rth_add@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_add
	addl	$-920086, (%esp)        # imm = 0xFFF1F5EA
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver svc_getreqset, svc_getreqset@GLIBC_2.0

	#NO_APP
	pushl	$svc_getreqset
	addl	$-1017546, (%esp)       # imm = 0xFFF07936
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$74362, (%esp)          # imm = 0x1227A
	retl
	#APP
.resume_10:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+28
	movl	%eax, .L__profc_main+24
	pushfl
	calll	.chain_11
	jmp	.resume_11
	#APP
.chain_11:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __idna_to_dns_encoding, __idna_to_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_to_dns_encoding
	addl	$-922546, (%esp)        # imm = 0xFFF1EC4E
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$488867, (%esp)         # imm = 0x775A3
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __sched_getparam, __sched_getparam@GLIBC_2.0

	#NO_APP
	pushl	$__sched_getparam
	addl	$-673146, (%esp)        # imm = 0xFFF5BA86
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver hcreate, hcreate@GLIBC_2.0

	#NO_APP
	pushl	$hcreate
	addl	$-777638, (%esp)        # imm = 0xFFF4225A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver fremovexattr, fremovexattr@GLIBC_2.3

	#NO_APP
	pushl	$fremovexattr
	addl	$-795434, (%esp)        # imm = 0xFFF3DCD6
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$-99725, (%esp)         # imm = 0xFFFE7A73
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-279782, (%esp)        # imm = 0xFFFBBB1A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver thrd_equal, thrd_equal@GLIBC_2.28

	#NO_APP
	pushl	$thrd_equal
	addl	$-863690, (%esp)        # imm = 0xFFF2D236
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$165322, (%esp)         # imm = 0x285CA
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver isupper, isupper@GLIBC_2.0

	#NO_APP
	pushl	$isupper
	addl	$113930, (%esp)         # imm = 0x1BD0A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-376675, (%esp)        # imm = 0xFFFA409D
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __libc_start_main, __libc_start_main@GLIBC_2.0

	#NO_APP
	pushl	$__libc_start_main
	addl	$167290, (%esp)         # imm = 0x28D7A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-454940, (%esp)        # imm = 0xFFF90EE4
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _IO_wfile_underflow, _IO_wfile_underflow@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_underflow
	addl	$-329091, (%esp)        # imm = 0xFFFAFA7D
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-974694, (%esp)        # imm = 0xFFF1209A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __gconv_transliterate, __gconv_transliterate@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_transliterate
	addl	$-11843, (%esp)         # imm = 0xD1BD
	retl
	#APP
.resume_11:
	#NO_APP
	popfl
.Ltmp5:
	.loc	1 14 49 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:14:49
	movl	-12(%ebp), %ecx
	pushfl
	calll	.chain_12
	jmp	.resume_12
	#APP
.chain_12:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver getgrnam_r, getgrnam_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getgrnam_r
	addl	$-533078, (%esp)        # imm = 0xFFF7DDAA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver getnetgrent, getnetgrent@GLIBC_2.0

	#NO_APP
	pushl	$getnetgrent
	addl	$-904898, (%esp)        # imm = 0xFFF2313E
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver clnt_pcreateerror, clnt_pcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_pcreateerror
	addl	$-994374, (%esp)        # imm = 0xFFF0D3BA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver pthread_mutex_destroy, pthread_mutex_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_mutex_destroy
	addl	$-852742, (%esp)        # imm = 0xFFF2FCFA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __wcsncpy_chk, __wcsncpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncpy_chk
	addl	$-865462, (%esp)        # imm = 0xFFF2CB4A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __nss_group_lookup, __nss_group_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_group_lookup
	addl	$-1256721, (%esp)       # imm = 0xFFECD2EF
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver xdr_int32_t, xdr_int32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int32_t
	addl	$-1020102, (%esp)       # imm = 0xFFF06F3A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver xdr_callhdr, xdr_callhdr@GLIBC_2.0

	#NO_APP
	pushl	$xdr_callhdr
	addl	$-585229, (%esp)        # imm = 0xFFF711F3
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-1030881, (%esp)       # imm = 0xFFF0451F
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_wfile_xsputn, _IO_wfile_xsputn@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_xsputn
	addl	$-190678, (%esp)        # imm = 0xFFFD172A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _mcleanup, _mcleanup@GLIBC_2.0

	#NO_APP
	pushl	$_mcleanup
	addl	$-971473, (%esp)        # imm = 0xFFF12D2F
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-918742, (%esp)        # imm = 0xFFF1FB2A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$103670, (%esp)         # imm = 0x194F6
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver prlimit, prlimit@GLIBC_2.13

	#NO_APP
	pushl	$prlimit
	addl	$-959713, (%esp)        # imm = 0xFFF15B1F
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __strtof_l, __strtof_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtof_l
	addl	$29894, (%esp)          # imm = 0x74C6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __internal_endnetgrent, __internal_endnetgrent@GLIBC_PRIVATE

	#NO_APP
	pushl	$__internal_endnetgrent
	addl	$-1076509, (%esp)       # imm = 0xFFEF92E3
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver authunix_create, authunix_create@GLIBC_2.0

	#NO_APP
	pushl	$authunix_create
	addl	$-1156945, (%esp)       # imm = 0xFFEE58AF
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __strspn_cg, __strspn_cg@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_cg
	addl	$-312762, (%esp)        # imm = 0xFFFB3A46
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver jrand48, jrand48@GLIBC_2.0

	#NO_APP
	pushl	$jrand48
	addl	$-102753, (%esp)        # imm = 0xFFFE6E9F
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver ftw64, ftw64@GLIBC_2.1

	#NO_APP
	pushl	$ftw64
	addl	$-729670, (%esp)        # imm = 0xFFF4DDBA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_least_wmarker, _IO_least_wmarker@GLIBC_2.2

	#NO_APP
	pushl	$_IO_least_wmarker
	addl	$-176982, (%esp)        # imm = 0xFFFD4CAA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver xdr_uint8_t, xdr_uint8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint8_t
	addl	$-1165683, (%esp)       # imm = 0xFFEE368D
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_free_backup_area, _IO_free_backup_area@GLIBC_2.0

	#NO_APP
	pushl	$_IO_free_backup_area
	addl	$-223062, (%esp)        # imm = 0xFFFC98AA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver capget, capget@GLIBC_2.1

	#NO_APP
	pushl	$capget
	addl	$-485132, (%esp)        # imm = 0xFFF898F4
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver inotify_init, inotify_init@GLIBC_2.4

	#NO_APP
	pushl	$inotify_init
	addl	$-942243, (%esp)        # imm = 0xFFF19F5D
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __nss_hash, __nss_hash@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_hash
	addl	$-954934, (%esp)        # imm = 0xFFF16DCA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver rexec_af, rexec_af@GLIBC_2.2

	#NO_APP
	pushl	$rexec_af
	addl	$-1041923, (%esp)       # imm = 0xFFF019FD
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver mkdirat, mkdirat@GLIBC_2.4

	#NO_APP
	pushl	$mkdirat
	addl	$-709990, (%esp)        # imm = 0xFFF52A9A
	retl
	#APP
.resume_12:
	#NO_APP
	popfl
	.loc	1 14 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:14:7
	leal	.L.str.2, %esi
	movl	%esi, (%esp)
	movl	%eax, 4(%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 12(%esp)
	calll	printf
	.loc	1 15 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:15:7
	jmp	.LBB0_8
.Ltmp6:
.LBB0_7:                                #   in Loop: Header=BB0_4 Depth=1
	.loc	1 0 7 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:0:7
	pushfl
	calll	.chain_13
	jmp	.resume_13
	#APP
.chain_13:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __strchrnul_g, __strchrnul_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_g
	addl	$-384494, (%esp)        # imm = 0xFFFA2212
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver authdes_pk_create, authdes_pk_create@GLIBC_2.1

	#NO_APP
	pushl	$authdes_pk_create
	addl	$-989798, (%esp)        # imm = 0xFFF0E59A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __towctrans, __towctrans@GLIBC_2.1

	#NO_APP
	pushl	$__towctrans
	addl	$-812550, (%esp)        # imm = 0xFFF399FA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver readdir64_r, readdir64_r@GLIBC_2.2

	#NO_APP
	pushl	$readdir64_r
	addl	$-689377, (%esp)        # imm = 0xFFF57B1F
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver globfree64, globfree64@GLIBC_2.1

	#NO_APP
	pushl	$globfree64
	addl	$-572518, (%esp)        # imm = 0xFFF7439A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __sysctl, __sysctl@GLIBC_2.2

	#NO_APP
	pushl	$__sysctl
	addl	$-414861, (%esp)        # imm = 0xFFF9AB73
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_switch_to_wbackup_area, _IO_switch_to_wbackup_area@GLIBC_2.2

	#NO_APP
	pushl	$_IO_switch_to_wbackup_area
	addl	$-342337, (%esp)        # imm = 0xFFFAC6BF
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver wcsxfrm, wcsxfrm@GLIBC_2.0

	#NO_APP
	pushl	$wcsxfrm
	addl	$-435014, (%esp)        # imm = 0xFFF95CBA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-311985, (%esp)        # imm = 0xFFFB3D4F
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __backtrace_symbols_fd, __backtrace_symbols_fd@GLIBC_2.1

	#NO_APP
	pushl	$__backtrace_symbols_fd
	addl	$-858230, (%esp)        # imm = 0xFFF2E78A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_str_underflow, _IO_str_underflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_underflow
	addl	$-240106, (%esp)        # imm = 0xFFFC5616
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __libc_fatal, __libc_fatal@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_fatal
	addl	$-368337, (%esp)        # imm = 0xFFFA612F
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-155274, (%esp)        # imm = 0xFFFDA176
	pushl	$-32
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver pthread_cond_broadcast, pthread_cond_broadcast@GLIBC_2.3.2

	#NO_APP
	pushl	$pthread_cond_broadcast
	addl	$-1026109, (%esp)       # imm = 0xFFF057C3
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-395265, (%esp)        # imm = 0xFFF9F7FF
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __ctype_b_loc, __ctype_b_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_b_loc
	addl	$103798, (%esp)         # imm = 0x19576
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver sendfile, sendfile@GLIBC_2.1

	#NO_APP
	pushl	$sendfile
	addl	$-910305, (%esp)        # imm = 0xFFF21C1F
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver mkstemps64, mkstemps64@GLIBC_2.11

	#NO_APP
	pushl	$mkstemps64
	addl	$-760742, (%esp)        # imm = 0xFFF4645A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver getnetname, getnetname@GLIBC_2.1

	#NO_APP
	pushl	$getnetname
	addl	$-1004374, (%esp)       # imm = 0xFFF0ACAA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver preadv64v2, preadv64v2@GLIBC_2.26

	#NO_APP
	pushl	$preadv64v2
	addl	$-900403, (%esp)        # imm = 0xFFF242CD
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver innetgr, innetgr@GLIBC_2.0

	#NO_APP
	pushl	$innetgr
	addl	$-903142, (%esp)        # imm = 0xFFF2381A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_seekmark, _IO_seekmark@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekmark
	addl	$81524, (%esp)          # imm = 0x13E74
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver read, read@GLIBC_2.0

	#NO_APP
	pushl	$read
	addl	$-856179, (%esp)        # imm = 0xFFF2EF8D
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$161690, (%esp)         # imm = 0x2779A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver getentropy, getentropy@GLIBC_2.25

	#NO_APP
	pushl	$getentropy
	addl	$-84115, (%esp)         # imm = 0xFFFEB76D
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver inet6_rth_init, inet6_rth_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_init
	addl	$-919974, (%esp)        # imm = 0xFFF1F65A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver xdr_u_int, xdr_u_int@GLIBC_2.0

	#NO_APP
	pushl	$xdr_u_int
	addl	$-638397, (%esp)        # imm = 0xFFF64243
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver xdr_authunix_parms, xdr_authunix_parms@GLIBC_2.0

	#NO_APP
	pushl	$xdr_authunix_parms
	addl	$-964362, (%esp)        # imm = 0xFFF148F6
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __isxdigit_l, __isxdigit_l@GLIBC_2.1

	#NO_APP
	pushl	$__isxdigit_l
	addl	$112522, (%esp)         # imm = 0x1B78A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver sched_getaffinity, sched_getaffinity@GLIBC_2.3.3

	#NO_APP
	pushl	$sched_getaffinity
	addl	$-1087610, (%esp)       # imm = 0xFFEF6786
	pushl	$1
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-990733, (%esp)        # imm = 0xFFF0E1F3
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _authenticate, _authenticate@GLIBC_2.1

	#NO_APP
	pushl	$_authenticate
	addl	$-965398, (%esp)        # imm = 0xFFF144EA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-234634, (%esp)        # imm = 0xFFFC6B76
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-751238, (%esp)        # imm = 0xFFF4897A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver strcoll, strcoll@GLIBC_2.0

	#NO_APP
	pushl	$strcoll
	addl	$-271010, (%esp)        # imm = 0xFFFBDD5E
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver getrpcent, getrpcent@GLIBC_2.0

	#NO_APP
	pushl	$getrpcent
	addl	$-600733, (%esp)        # imm = 0xFFF6D563
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-1029098, (%esp)       # imm = 0xFFF04C16
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$161690, (%esp)         # imm = 0x2779A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver mcheck_pedantic, mcheck_pedantic@GLIBC_2.2

	#NO_APP
	pushl	$mcheck_pedantic
	addl	$-272442, (%esp)        # imm = 0xFFFBD7C6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver xdr_uint32_t, xdr_uint32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint32_t
	addl	$-1194573, (%esp)       # imm = 0xFFEDC5B3
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver getnameinfo, getnameinfo@GLIBC_2.1

	#NO_APP
	pushl	$getnameinfo
	addl	$-907526, (%esp)        # imm = 0xFFF226FA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _dl_mcount_wrapper_check, _dl_mcount_wrapper_check@GLIBC_2.1

	#NO_APP
	pushl	$_dl_mcount_wrapper_check
	addl	$-1047466, (%esp)       # imm = 0xFFF00456
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __wcstod_internal, __wcstod_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstod_internal
	addl	$-393974, (%esp)        # imm = 0xFFF9FD0A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver svcerr_noprog, svcerr_noprog@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_noprog
	addl	$-1008166, (%esp)       # imm = 0xFFF09DDA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver getpwnam, getpwnam@GLIBC_2.0

	#NO_APP
	pushl	$getpwnam
	addl	$-682819, (%esp)        # imm = 0xFFF594BD
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-177926, (%esp)        # imm = 0xFFFD48FA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __libc_freeres, __libc_freeres@GLIBC_2.1

	#NO_APP
	pushl	$__libc_freeres
	addl	$-936620, (%esp)        # imm = 0xFFF1B554
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver setdomainname, setdomainname@GLIBC_2.0

	#NO_APP
	pushl	$setdomainname
	addl	$-903155, (%esp)        # imm = 0xFFF2380D
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver posix_spawnattr_setsigdefault, posix_spawnattr_setsigdefault@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setsigdefault
	addl	$-699990, (%esp)        # imm = 0xFFF551AA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver fts64_close, fts64_close@GLIBC_2.23

	#NO_APP
	pushl	$fts64_close
	addl	$-885891, (%esp)        # imm = 0xFFF27B7D
	retl
	#APP
.resume_13:
	#NO_APP
	popfl
	.loc	1 12 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:12:3
	jmp	.LBB0_4
.LBB0_8:
	.loc	1 19 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c:19:3
	xorl	%eax, %eax
	addl	$36, %esp
	popl	%esi
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp7:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Enter two positive integers: "
	.size	.L.str, 30

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"%d %d"
	.size	.L.str.1, 6

	.type	.L.str.2,@object        # @.str.2
.L.str.2:
	.asciz	"The LCM of %d and %d is %d."
	.size	.L.str.2, 28

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	1                       # 0x1
	.long	78                      # 0x4e
	.long	106                     # 0x6a
	.long	2                       # 0x2
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	100                     # 0x64
	.quad	-711077131543345119     # 0xf621bf1dc6748821
	.asciz	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c\001\000\005\001\005\013\r\001\t\t\r\t\r\016\001\003\f\021\002\005\006\033\000\235\200\200\200\b\005\000\035\000\037\002\000\"\000$\006\003\n\000\013\t\000\f\000\215\200\200\200\b\t\000\r\006\004\t\001\t\000\036\t\000\t\0007\021\000\"\0007\r\0008\000\271\200\200\200\b\r\0009\003\006\022\003\006\001\205\200\200\200\b\022\001\005\001\004\000\000\000\000\000"
	.size	__llvm_coverage_mapping, 220

	.type	.L__profc_main,@object  # @__profc_main
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_main:
	.zero	40
	.size	.L__profc_main, 40

	.type	.L__profd_main,@object  # @__profd_main
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_main:
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.quad	-711077131543345119     # 0xf621bf1dc6748821
	.long	.L__profc_main
	.long	main
	.long	0
	.long	5                       # 0x5
	.zero	4
	.size	.L__profd_main, 36

	.type	.L__llvm_prf_nm,@object # @__llvm_prf_nm
	.section	__llvm_prf_names,"a",@progbits
.L__llvm_prf_nm:
	.ascii	"\004\fx\332\313M\314\314\003\000\004\033\001\246"
	.size	.L__llvm_prf_nm, 14

	.type	__llvm_profile_filename,@object # @__llvm_profile_filename
	.section	.rodata.__llvm_profile_filename,"aG",@progbits,__llvm_profile_filename,comdat
	.globl	__llvm_profile_filename
	.p2align	4
__llvm_profile_filename:
	.asciz	"example2-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example2.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"main"                  # string offset=194
.Linfo_string4:
	.asciz	"int"                   # string offset=199
.Linfo_string5:
	.asciz	"n1"                    # string offset=203
.Linfo_string6:
	.asciz	"n2"                    # string offset=206
.Linfo_string7:
	.asciz	"minMultiple"           # string offset=209
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
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	63                      # DW_AT_external
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	3                       # Abbreviation Code
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
	.byte	4                       # Abbreviation Code
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
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	106                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x63 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x40 DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	3                       # DW_AT_decl_line
	.long	102                     # DW_AT_type
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0x3b:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	112
	.long	.Linfo_string5          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.long	102                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x49:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	116
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.long	102                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x57:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string7          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.long	102                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x66:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	0                       # End Of Children Mark
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark
	.section	.debug_pubnames,"",@progbits
	.long	.LpubNames_end0-.LpubNames_begin0 # Length of Public Names Info
.LpubNames_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	110                     # Compilation Unit Length
	.long	38                      # DIE offset
	.asciz	"main"                  # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	110                     # Compilation Unit Length
	.long	102                     # DIE offset
	.asciz	"int"                   # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
