	.text
	.file	"example5.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c"
	.loc	1 7 0                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:7:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$40, %esp
	movl	$0, -20(%ebp)
.Ltmp0:
	.loc	1 7 16 prologue_end     # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:7:16
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
	.loc	1 10 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:10:7
	leal	.L.str, %eax
	movl	%eax, (%esp)
	calll	opendir
	.loc	1 10 5 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:10:5
	movl	%eax, -8(%ebp)
.Ltmp1:
	.loc	1 11 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:11:7
	cmpl	$0, -8(%ebp)
.Ltmp2:
	.loc	1 11 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:11:7
	je	.LBB0_5
# %bb.1:
	movl	.L__profc_main+8, %eax
	pushfl
	calll	.chain_1
	jmp	.resume_1
	#APP
.chain_1:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver wcsftime, wcsftime@GLIBC_2.2

	#NO_APP
	pushl	$wcsftime
	addl	$-120045, (%esp)        # imm = 0xFFFE2B13
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver _obstack_free, _obstack_free@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_free
	addl	$-276026, (%esp)        # imm = 0xFFFBC9C6
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
	addl	$66038, (%esp)          # imm = 0x101F6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$-64029, (%esp)         # imm = 0xFFFF05E3
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
	addl	$105958, (%esp)         # imm = 0x19DE6
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
	adcl	$0, .L__profc_main+12
	movl	%eax, .L__profc_main+8
.LBB0_2:                                # =>This Inner Loop Header: Depth=1
	.loc	1 0 7                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:0:7
	pushfl
	calll	.chain_2
	jmp	.resume_2
	#APP
.chain_2:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-1021282, (%esp)       # imm = 0xFFF06A9E
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver srand48, srand48@GLIBC_2.0

	#NO_APP
	pushl	$srand48
	addl	$440883, (%esp)         # imm = 0x6BA33
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __assert_perror_fail, __assert_perror_fail@GLIBC_2.0

	#NO_APP
	pushl	$__assert_perror_fail
	addl	$106374, (%esp)         # imm = 0x19F86
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
	addl	$67142, (%esp)          # imm = 0x10646
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver key_secretkey_is_set, key_secretkey_is_set@GLIBC_2.1

	#NO_APP
	pushl	$key_secretkey_is_set
	addl	$-1176525, (%esp)       # imm = 0xFFEE0C33
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
	addl	$-1022906, (%esp)       # imm = 0xFFF06446
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver epoll_create, epoll_create@GLIBC_2.3.2

	#NO_APP
	pushl	$epoll_create
	addl	$-797094, (%esp)        # imm = 0xFFF3D65A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver xdr_rejected_reply, xdr_rejected_reply@GLIBC_2.0

	#NO_APP
	pushl	$xdr_rejected_reply
	addl	$-963062, (%esp)        # imm = 0xFFF14E0A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __wcstoll_internal, __wcstoll_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstoll_internal
	addl	$-538515, (%esp)        # imm = 0xFFF7C86D
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-865718, (%esp)        # imm = 0xFFF2CA4A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __res_ninit, __res_ninit@GLIBC_2.2

	#NO_APP
	pushl	$__res_ninit
	addl	$-622764, (%esp)        # imm = 0xFFF67F54
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver free, free@GLIBC_2.0

	#NO_APP
	pushl	$free
	addl	$-400931, (%esp)        # imm = 0xFFF9E1DD
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver htonl, htonl@GLIBC_2.0

	#NO_APP
	pushl	$htonl
	addl	$-871318, (%esp)        # imm = 0xFFF2B46A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-371075, (%esp)        # imm = 0xFFFA567D
	retl
	#APP
.resume_2:
	#NO_APP
	popfl
.Ltmp3:
	.loc	1 12 19 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:12:19
	movl	%eax, (%esp)
	calll	readdir
	.loc	1 12 17 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:12:17
	movl	%eax, -16(%ebp)
	.loc	1 12 31                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:12:31
	cmpl	$0, %eax
	.loc	1 12 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:12:5
	je	.LBB0_4
# %bb.3:                                #   in Loop: Header=BB0_2 Depth=1
	movl	.L__profc_main+16, %eax
	pushfl
	calll	.chain_3
	jmp	.resume_3
	#APP
.chain_3:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver clnt_spcreateerror, clnt_spcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_spcreateerror
	addl	$-615549, (%esp)        # imm = 0xFFF69B83
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __snprintf, __snprintf@GLIBC_PRIVATE

	#NO_APP
	pushl	$__snprintf
	addl	$-80506, (%esp)         # imm = 0xFFFEC586
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-772726, (%esp)        # imm = 0xFFF4358A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __iswpunct_l, __iswpunct_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswpunct_l
	addl	$-822410, (%esp)        # imm = 0xFFF37376
	pushl	$1
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __poll_chk, __poll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__poll_chk
	addl	$-1045245, (%esp)       # imm = 0xFFF00D03
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver putwc_unlocked, putwc_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$putwc_unlocked
	addl	$-174390, (%esp)        # imm = 0xFFFD56CA
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver xdr_bool, xdr_bool@GLIBC_2.0

	#NO_APP
	pushl	$xdr_bool
	addl	$-1026538, (%esp)       # imm = 0xFFF05616
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __readlink_chk, __readlink_chk@GLIBC_2.4

	#NO_APP
	pushl	$__readlink_chk
	addl	$-863942, (%esp)        # imm = 0xFFF2D13A
	retl
	#APP
.resume_3:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+20
	movl	%eax, .L__profc_main+16
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
	addl	$-492573, (%esp)        # imm = 0xFFF87BE3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver atoll, atoll@GLIBC_2.0

	#NO_APP
	pushl	$atoll
	addl	$65350, (%esp)          # imm = 0xFF46
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __waitpid, __waitpid@GLIBC_2.0

	#NO_APP
	pushl	$__waitpid
	addl	$-542406, (%esp)        # imm = 0xFFF7B93A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __merge_grp, __merge_grp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__merge_grp
	addl	$-544506, (%esp)        # imm = 0xFFF7B106
	pushl	$19
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver setutxent, setutxent@GLIBC_2.1

	#NO_APP
	pushl	$setutxent
	addl	$-1211309, (%esp)       # imm = 0xFFED8453
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver _obstack_begin, _obstack_begin@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin
	addl	$-266646, (%esp)        # imm = 0xFFFBEE6A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-312394, (%esp)        # imm = 0xFFFB3BB6
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-483606, (%esp)        # imm = 0xFFF89EEA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver setlogin, setlogin@GLIBC_2.0

	#NO_APP
	pushl	$setlogin
	addl	$-1027602, (%esp)       # imm = 0xFFF051EE
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-335565, (%esp)        # imm = 0xFFFAE133
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-806986, (%esp)        # imm = 0xFFF3AFB6
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
	addl	$-673306, (%esp)        # imm = 0xFFF5B9E6
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __islower_l, __islower_l@GLIBC_2.1

	#NO_APP
	pushl	$__islower_l
	addl	$-61437, (%esp)         # imm = 0xFFFF1003
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
	addl	$-1100266, (%esp)       # imm = 0xFFEF3616
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver iconv_close, iconv_close@GLIBC_2.1

	#NO_APP
	pushl	$iconv_close
	addl	$163898, (%esp)         # imm = 0x2803A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-865718, (%esp)        # imm = 0xFFF2CA4A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver envz_strip, envz_strip@GLIBC_2.0

	#NO_APP
	pushl	$envz_strip
	addl	$-432723, (%esp)        # imm = 0xFFF965AD
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver strtod, strtod@GLIBC_2.0

	#NO_APP
	pushl	$strtod
	addl	$50474, (%esp)          # imm = 0xC52A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-485324, (%esp)        # imm = 0xFFF89834
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver qgcvt, qgcvt@GLIBC_2.0

	#NO_APP
	pushl	$qgcvt
	addl	$-921043, (%esp)        # imm = 0xFFF1F22D
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-793334, (%esp)        # imm = 0xFFF3E50A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-1001299, (%esp)       # imm = 0xFFF0B8AD
	retl
	#APP
.resume_4:
	#NO_APP
	popfl
.Ltmp4:
	.loc	1 13 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:13:7
	leal	.L.str.1, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
.Ltmp5:
	.loc	1 12 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:12:5
	jmp	.LBB0_2
.LBB0_4:
	.loc	1 0 5 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:0:5
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
	.loc	1 15 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:15:5
	movl	%eax, (%esp)
	calll	closedir
.Ltmp6:
.LBB0_5:
	.loc	1 17 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c:17:3
	xorl	%eax, %eax
	addl	$40, %esp
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
	.asciz	"."
	.size	.L.str, 2

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"%s\n"
	.size	.L.str.1, 4

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	1                       # 0x1
	.long	78                      # 0x4e
	.long	42                      # 0x2a
	.long	2                       # 0x2
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	40                      # 0x28
	.quad	706564133976            # 0xa482811458
	.asciz	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c\001\000\001\005\t\006\001\007\020\013\002\001\004\007\000\b\005\000\t\000\212\200\200\200\b\005\000\n\005\004\003\001\f\000&\t\000(\002\006\000"
	.size	__llvm_coverage_mapping, 156

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
	.quad	706564133976            # 0xa482811458
	.long	.L__profc_main
	.long	main
	.long	0
	.long	3                       # 0x3
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
	.asciz	"example5-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.file	2 "/usr/include/dirent.h"
	.file	3 "/usr/include/bits/types.h"
	.file	4 "/usr/include/bits/dirent.h"
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example5.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"main"                  # string offset=194
.Linfo_string4:
	.asciz	"int"                   # string offset=199
.Linfo_string5:
	.asciz	"d"                     # string offset=203
.Linfo_string6:
	.asciz	"__dirstream"           # string offset=205
.Linfo_string7:
	.asciz	"DIR"                   # string offset=217
.Linfo_string8:
	.asciz	"dir"                   # string offset=221
.Linfo_string9:
	.asciz	"d_ino"                 # string offset=225
.Linfo_string10:
	.asciz	"long unsigned int"     # string offset=231
.Linfo_string11:
	.asciz	"__ino_t"               # string offset=249
.Linfo_string12:
	.asciz	"d_off"                 # string offset=257
.Linfo_string13:
	.asciz	"long int"              # string offset=263
.Linfo_string14:
	.asciz	"__off_t"               # string offset=272
.Linfo_string15:
	.asciz	"d_reclen"              # string offset=280
.Linfo_string16:
	.asciz	"unsigned short"        # string offset=289
.Linfo_string17:
	.asciz	"d_type"                # string offset=304
.Linfo_string18:
	.asciz	"unsigned char"         # string offset=311
.Linfo_string19:
	.asciz	"d_name"                # string offset=325
.Linfo_string20:
	.asciz	"char"                  # string offset=332
.Linfo_string21:
	.asciz	"__ARRAY_SIZE_TYPE__"   # string offset=337
.Linfo_string22:
	.asciz	"dirent"                # string offset=357
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
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	3                       # Abbreviation Code
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
	.byte	6                       # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	7                       # Abbreviation Code
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
	.byte	8                       # Abbreviation Code
	.byte	19                      # DW_TAG_structure_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	60                      # DW_AT_declaration
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	9                       # Abbreviation Code
	.byte	19                      # DW_TAG_structure_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	11                      # DW_AT_byte_size
	.byte	5                       # DW_FORM_data2
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
	.byte	1                       # DW_TAG_array_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	12                      # Abbreviation Code
	.byte	33                      # DW_TAG_subrange_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	55                      # DW_AT_count
	.byte	5                       # DW_FORM_data2
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	13                      # Abbreviation Code
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
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	266                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x103 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x1 DW_TAG_pointer_type
	.byte	3                       # Abbrev [3] 0x27:0x32 DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	7                       # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	89                      # DW_AT_type
                                        # DW_AT_external
	.byte	4                       # Abbrev [4] 0x3c:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string5          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	8                       # DW_AT_decl_line
	.long	96                      # DW_AT_type
	.byte	4                       # Abbrev [4] 0x4a:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	112
	.long	.Linfo_string8          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	117                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	5                       # Abbrev [5] 0x59:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	6                       # Abbrev [6] 0x60:0x5 DW_TAG_pointer_type
	.long	101                     # DW_AT_type
	.byte	7                       # Abbrev [7] 0x65:0xb DW_TAG_typedef
	.long	112                     # DW_AT_type
	.long	.Linfo_string7          # DW_AT_name
	.byte	2                       # DW_AT_decl_file
	.byte	127                     # DW_AT_decl_line
	.byte	8                       # Abbrev [8] 0x70:0x5 DW_TAG_structure_type
	.long	.Linfo_string6          # DW_AT_name
                                        # DW_AT_declaration
	.byte	6                       # Abbrev [6] 0x75:0x5 DW_TAG_pointer_type
	.long	122                     # DW_AT_type
	.byte	9                       # Abbrev [9] 0x7a:0x46 DW_TAG_structure_type
	.long	.Linfo_string22         # DW_AT_name
	.short	280                     # DW_AT_byte_size
	.byte	4                       # DW_AT_decl_file
	.byte	22                      # DW_AT_decl_line
	.byte	10                      # Abbrev [10] 0x83:0xc DW_TAG_member
	.long	.Linfo_string9          # DW_AT_name
	.long	192                     # DW_AT_type
	.byte	4                       # DW_AT_decl_file
	.byte	25                      # DW_AT_decl_line
	.byte	0                       # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x8f:0xc DW_TAG_member
	.long	.Linfo_string12         # DW_AT_name
	.long	210                     # DW_AT_type
	.byte	4                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
	.byte	8                       # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0x9b:0xc DW_TAG_member
	.long	.Linfo_string15         # DW_AT_name
	.long	228                     # DW_AT_type
	.byte	4                       # DW_AT_decl_file
	.byte	31                      # DW_AT_decl_line
	.byte	16                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0xa7:0xc DW_TAG_member
	.long	.Linfo_string17         # DW_AT_name
	.long	235                     # DW_AT_type
	.byte	4                       # DW_AT_decl_file
	.byte	32                      # DW_AT_decl_line
	.byte	18                      # DW_AT_data_member_location
	.byte	10                      # Abbrev [10] 0xb3:0xc DW_TAG_member
	.long	.Linfo_string19         # DW_AT_name
	.long	242                     # DW_AT_type
	.byte	4                       # DW_AT_decl_file
	.byte	33                      # DW_AT_decl_line
	.byte	19                      # DW_AT_data_member_location
	.byte	0                       # End Of Children Mark
	.byte	7                       # Abbrev [7] 0xc0:0xb DW_TAG_typedef
	.long	203                     # DW_AT_type
	.long	.Linfo_string11         # DW_AT_name
	.byte	3                       # DW_AT_decl_file
	.byte	146                     # DW_AT_decl_line
	.byte	5                       # Abbrev [5] 0xcb:0x7 DW_TAG_base_type
	.long	.Linfo_string10         # DW_AT_name
	.byte	7                       # DW_AT_encoding
	.byte	8                       # DW_AT_byte_size
	.byte	7                       # Abbrev [7] 0xd2:0xb DW_TAG_typedef
	.long	221                     # DW_AT_type
	.long	.Linfo_string14         # DW_AT_name
	.byte	3                       # DW_AT_decl_file
	.byte	150                     # DW_AT_decl_line
	.byte	5                       # Abbrev [5] 0xdd:0x7 DW_TAG_base_type
	.long	.Linfo_string13         # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	8                       # DW_AT_byte_size
	.byte	5                       # Abbrev [5] 0xe4:0x7 DW_TAG_base_type
	.long	.Linfo_string16         # DW_AT_name
	.byte	7                       # DW_AT_encoding
	.byte	2                       # DW_AT_byte_size
	.byte	5                       # Abbrev [5] 0xeb:0x7 DW_TAG_base_type
	.long	.Linfo_string18         # DW_AT_name
	.byte	8                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	11                      # Abbrev [11] 0xf2:0xd DW_TAG_array_type
	.long	255                     # DW_AT_type
	.byte	12                      # Abbrev [12] 0xf7:0x7 DW_TAG_subrange_type
	.long	262                     # DW_AT_type
	.short	256                     # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	5                       # Abbrev [5] 0xff:0x7 DW_TAG_base_type
	.long	.Linfo_string20         # DW_AT_name
	.byte	6                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	13                      # Abbrev [13] 0x106:0x7 DW_TAG_base_type
	.long	.Linfo_string21         # DW_AT_name
	.byte	8                       # DW_AT_byte_size
	.byte	7                       # DW_AT_encoding
	.byte	0                       # End Of Children Mark
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark
	.section	.debug_pubnames,"",@progbits
	.long	.LpubNames_end0-.LpubNames_begin0 # Length of Public Names Info
.LpubNames_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	270                     # Compilation Unit Length
	.long	39                      # DIE offset
	.asciz	"main"                  # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	270                     # Compilation Unit Length
	.long	235                     # DIE offset
	.asciz	"unsigned char"         # External Name
	.long	255                     # DIE offset
	.asciz	"char"                  # External Name
	.long	122                     # DIE offset
	.asciz	"dirent"                # External Name
	.long	192                     # DIE offset
	.asciz	"__ino_t"               # External Name
	.long	203                     # DIE offset
	.asciz	"long unsigned int"     # External Name
	.long	89                      # DIE offset
	.asciz	"int"                   # External Name
	.long	210                     # DIE offset
	.asciz	"__off_t"               # External Name
	.long	228                     # DIE offset
	.asciz	"unsigned short"        # External Name
	.long	221                     # DIE offset
	.asciz	"long int"              # External Name
	.long	101                     # DIE offset
	.asciz	"DIR"                   # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
