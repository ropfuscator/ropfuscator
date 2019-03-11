	.text
	.file	"example6.c"
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.loc	1 21 0                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:21:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$24, %esp
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
	movl	%eax, -8(%ebp)
.Ltmp0:
	.loc	1 21 35 prologue_end    # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:21:35
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
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
	.loc	1 24 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:24:3
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
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-642093, (%esp)        # imm = 0xFFF633D3
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver srand48, srand48@GLIBC_2.0

	#NO_APP
	pushl	$srand48
	addl	$53878, (%esp)          # imm = 0xD276
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __assert_perror_fail, __assert_perror_fail@GLIBC_2.0

	#NO_APP
	pushl	$__assert_perror_fail
	addl	$114826, (%esp)         # imm = 0x1C08A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __libc_dlclose, __libc_dlclose@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlclose
	addl	$-1048730, (%esp)       # imm = 0xFFEFFF66
	pushl	$1
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver sigorset, sigorset@GLIBC_2.0

	#NO_APP
	pushl	$sigorset
	addl	$-98749, (%esp)         # imm = 0xFFFE7E43
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver key_secretkey_is_set, key_secretkey_is_set@GLIBC_2.1

	#NO_APP
	pushl	$key_secretkey_is_set
	addl	$-1002182, (%esp)       # imm = 0xFFF0B53A
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver inet_lnaof, inet_lnaof@GLIBC_2.0

	#NO_APP
	pushl	$inet_lnaof
	addl	$-879802, (%esp)        # imm = 0xFFF29346
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver svcudp_create, svcudp_create@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_create
	addl	$-1014454, (%esp)       # imm = 0xFFF0854A
	retl
	#APP
.resume_2:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+12
	movl	%eax, .L__profc_main+8
.Ltmp1:
	.loc	1 25 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:25:5
	movl	$.L.str, (%esp)
	calll	printf
	.loc	1 26 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:26:5
	movl	$.L.str.1, (%esp)
	calll	printf
	.loc	1 27 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:27:5
	movl	$.L.str.2, (%esp)
	calll	printf
	leal	-12(%ebp), %eax
	.loc	1 28 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:28:5
	movl	%eax, 4(%esp)
	movl	$.L.str.3, (%esp)
	calll	__isoc99_scanf
	.loc	1 29 13                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:29:13
	movl	-12(%ebp), %eax
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
	pushl	$-1
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
	.loc	1 29 5 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:29:5
	movl	%eax, %ecx
	subl	$3, %ecx
	ja	.LBB0_7
# %bb.2:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	1 0 5                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:0:5
	movl	.LJTI0_0(,%eax,4), %eax
	jmpl	*%eax
.LBB0_3:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	1 29 21                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:29:21
	movl	.L__profc_main+24, %eax
	pushfl
	calll	.chain_4
	jmp	.resume_4
	#APP
.chain_4:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver iconv_close, iconv_close@GLIBC_2.1

	#NO_APP
	pushl	$iconv_close
	addl	$542451, (%esp)         # imm = 0x846F3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver envz_strip, envz_strip@GLIBC_2.0

	#NO_APP
	pushl	$envz_strip
	addl	$-287830, (%esp)        # imm = 0xFFFB9BAA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver strtod, strtod@GLIBC_2.0

	#NO_APP
	pushl	$strtod
	addl	$42022, (%esp)          # imm = 0xA426
	pushl	$1
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-971389, (%esp)        # imm = 0xFFF12D83
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver qgcvt, qgcvt@GLIBC_2.0

	#NO_APP
	pushl	$qgcvt
	addl	$-776150, (%esp)        # imm = 0xFFF4282A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-801786, (%esp)        # imm = 0xFFF3C406
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	retl
	#APP
.resume_4:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+28
	movl	%eax, .L__profc_main+24
	pushfl
	calll	.chain_5
	jmp	.resume_5
	#APP
.chain_5:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __stack_chk_fail, __stack_chk_fail@GLIBC_2.4

	#NO_APP
	pushl	$__stack_chk_fail
	addl	$-871762, (%esp)        # imm = 0xFFF2B2AE
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver atoll, atoll@GLIBC_2.0

	#NO_APP
	pushl	$atoll
	addl	$452355, (%esp)         # imm = 0x6E703
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __waitpid, __waitpid@GLIBC_2.0

	#NO_APP
	pushl	$__waitpid
	addl	$-550858, (%esp)        # imm = 0xFFF79836
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __merge_grp, __merge_grp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__merge_grp
	addl	$-536054, (%esp)        # imm = 0xFFF7D20A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver setutxent, setutxent@GLIBC_2.1

	#NO_APP
	pushl	$setutxent
	addl	$-1045418, (%esp)       # imm = 0xFFF00C56
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver _obstack_begin, _obstack_begin@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin
	addl	$-440989, (%esp)        # imm = 0xFFF94563
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-303942, (%esp)        # imm = 0xFFFB5CBA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-492058, (%esp)        # imm = 0xFFF87DE6
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver setlogin, setlogin@GLIBC_2.0

	#NO_APP
	pushl	$setlogin
	addl	$-1026966, (%esp)       # imm = 0xFFF0546A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-714118, (%esp)        # imm = 0xFFF51A7A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-943427, (%esp)        # imm = 0xFFF19ABD
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __asprintf_chk, __asprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__asprintf_chk
	addl	$-869142, (%esp)        # imm = 0xFFF2BCEA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __sched_get_priority_max, __sched_get_priority_max@GLIBC_2.0

	#NO_APP
	pushl	$__sched_get_priority_max
	addl	$-353132, (%esp)        # imm = 0xFFFA9C94
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __islower_l, __islower_l@GLIBC_2.1

	#NO_APP
	pushl	$__islower_l
	addl	$-31987, (%esp)         # imm = 0x830D
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver isspace, isspace@GLIBC_2.0

	#NO_APP
	pushl	$isspace
	addl	$114010, (%esp)         # imm = 0x1BD5A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver getrpcbynumber_r, getrpcbynumber_r@GLIBC_2.0

	#NO_APP
	pushl	$getrpcbynumber_r
	addl	$-1236707, (%esp)       # imm = 0xFFED211D
	retl
	#APP
.resume_5:
	#NO_APP
	popfl
.Ltmp2:
	.loc	1 31 14 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:31:14
	movl	4(%eax), %eax
	.loc	1 31 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:31:7
	movl	%eax, (%esp)
	calll	insert
	.loc	1 32 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:32:7
	jmp	.LBB0_8
.LBB0_4:                                #   in Loop: Header=BB0_1 Depth=1
	movl	.L__profc_main+32, %eax
	pushfl
	calll	.chain_6
	jmp	.resume_6
	#APP
.chain_6:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-582749, (%esp)        # imm = 0xFFF71BA3
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-927194, (%esp)        # imm = 0xFFF1DA26
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-758022, (%esp)        # imm = 0xFFF46EFA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-549322, (%esp)        # imm = 0xFFF79E36
	pushl	$1
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __openat64_2, __openat64_2@GLIBC_2.7

	#NO_APP
	pushl	$__openat64_2
	addl	$-885533, (%esp)        # imm = 0xFFF27CE3
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver shmdt, shmdt@GLIBC_2.0

	#NO_APP
	pushl	$shmdt
	addl	$-803638, (%esp)        # imm = 0xFFF3BCCA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strspn_g, __strspn_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_g
	addl	$-312762, (%esp)        # imm = 0xFFFB3A46
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __nss_lookup, __nss_lookup@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_lookup
	addl	$-947974, (%esp)        # imm = 0xFFF188FA
	retl
	#APP
.resume_6:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+36
	movl	%eax, .L__profc_main+32
	pushfl
	calll	.chain_7
	jmp	.resume_7
	#APP
.chain_7:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver mrand48_r, mrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$mrand48_r
	addl	$61038, (%esp)          # imm = 0xEE6E
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver svcraw_create, svcraw_create@GLIBC_2.0

	#NO_APP
	pushl	$svcraw_create
	addl	$-588125, (%esp)        # imm = 0xFFF706A3
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-238554, (%esp)        # imm = 0xFFFC5C26
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __pread64_chk, __pread64_chk@GLIBC_2.4

	#NO_APP
	pushl	$__pread64_chk
	addl	$-863702, (%esp)        # imm = 0xFFF2D22A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __vsnprintf_chk, __vsnprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsnprintf_chk
	addl	$-869114, (%esp)        # imm = 0xFFF2BD06
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver rcmd_af, rcmd_af@GLIBC_2.2

	#NO_APP
	pushl	$rcmd_af
	addl	$-1067341, (%esp)       # imm = 0xFFEFB6B3
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver atol, atol@GLIBC_2.0

	#NO_APP
	pushl	$atol
	addl	$73866, (%esp)          # imm = 0x1208A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver getmsg, getmsg@GLIBC_2.1

	#NO_APP
	pushl	$getmsg
	addl	$-1033434, (%esp)       # imm = 0xFFF03B26
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver inet_netof, inet_netof@GLIBC_2.0

	#NO_APP
	pushl	$inet_netof
	addl	$-871590, (%esp)        # imm = 0xFFF2B35A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$-202038, (%esp)        # imm = 0xFFFCEACA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __nss_hostname_digits_dots, __nss_hostname_digits_dots@GLIBC_2.2.2

	#NO_APP
	pushl	$__nss_hostname_digits_dots
	addl	$-1096723, (%esp)       # imm = 0xFFEF43ED
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver fsync, fsync@GLIBC_2.0

	#NO_APP
	pushl	$fsync
	addl	$-758822, (%esp)        # imm = 0xFFF46BDA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __isoc99_vfscanf, __isoc99_vfscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfscanf
	addl	$161380, (%esp)         # imm = 0x27664
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver setegid, setegid@GLIBC_2.0

	#NO_APP
	pushl	$setegid
	addl	$-902323, (%esp)        # imm = 0xFFF23B4D
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver remove, remove@GLIBC_2.0

	#NO_APP
	pushl	$remove
	addl	$-148742, (%esp)        # imm = 0xFFFDBAFA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver process_vm_writev, process_vm_writev@GLIBC_2.15

	#NO_APP
	pushl	$process_vm_writev
	addl	$-943267, (%esp)        # imm = 0xFFF19B5D
	retl
	#APP
.resume_7:
	#NO_APP
	popfl
	.loc	1 34 15                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:34:15
	movl	4(%eax), %eax
	.loc	1 34 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:34:7
	movl	%eax, (%esp)
	calll	display
	.loc	1 35 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:35:7
	jmp	.LBB0_8
.LBB0_5:                                #   in Loop: Header=BB0_1 Depth=1
	movl	.L__profc_main+40, %eax
	pushfl
	calll	.chain_8
	jmp	.resume_8
	#APP
.chain_8:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$453171, (%esp)         # imm = 0x6EA33
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __libc_longjmp, __libc_longjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_longjmp
	addl	$71798, (%esp)          # imm = 0x11876
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __tolower_l, __tolower_l@GLIBC_2.1

	#NO_APP
	pushl	$__tolower_l
	addl	$112458, (%esp)         # imm = 0x1B74A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver execle, execle@GLIBC_2.0

	#NO_APP
	pushl	$execle
	addl	$-552954, (%esp)        # imm = 0xFFF79006
	pushl	$1
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strncmp_g, __strncmp_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncmp_g
	addl	$-478381, (%esp)        # imm = 0xFFF8B353
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-919398, (%esp)        # imm = 0xFFF1F89A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strlen_g, __strlen_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strlen_g
	addl	$-312042, (%esp)        # imm = 0xFFFB3D16
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver ioperm, ioperm@GLIBC_2.0

	#NO_APP
	pushl	$ioperm
	addl	$-793286, (%esp)        # imm = 0xFFF3E53A
	retl
	#APP
.resume_8:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+44
	movl	%eax, .L__profc_main+40
	pushfl
	calll	.chain_9
	jmp	.resume_9
	#APP
.chain_9:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver iruserok_af, iruserok_af@GLIBC_2.2

	#NO_APP
	pushl	$iruserok_af
	addl	$-897218, (%esp)        # imm = 0xFFF24F3E
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver endaliasent, endaliasent@GLIBC_2.0

	#NO_APP
	pushl	$endaliasent
	addl	$-526141, (%esp)        # imm = 0xFFF7F8C3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __stpcpy_small, __stpcpy_small@GLIBC_2.1.1

	#NO_APP
	pushl	$__stpcpy_small
	addl	$-311594, (%esp)        # imm = 0xFFFB3ED6
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __register_atfork, __register_atfork@GLIBC_2.3.2

	#NO_APP
	pushl	$__register_atfork
	addl	$-854102, (%esp)        # imm = 0xFFF2F7AA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __ptsname_r_chk, __ptsname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ptsname_r_chk
	addl	$-1045354, (%esp)       # imm = 0xFFF00C96
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-123565, (%esp)        # imm = 0xFFFE1D53
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver siggetmask, siggetmask@GLIBC_2.0

	#NO_APP
	pushl	$siggetmask
	addl	$76154, (%esp)          # imm = 0x1297A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __idna_from_dns_encoding, __idna_from_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_from_dns_encoding
	addl	$-930634, (%esp)        # imm = 0xFFF1CCB6
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-816390, (%esp)        # imm = 0xFFF38AFA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_quad_t, xdr_quad_t@GLIBC_2.3.4

	#NO_APP
	pushl	$xdr_quad_t
	addl	$-1019750, (%esp)       # imm = 0xFFF0709A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver sigismember, sigismember@GLIBC_2.0

	#NO_APP
	pushl	$sigismember
	addl	$-68595, (%esp)         # imm = 0xFFFEF40D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-793926, (%esp)        # imm = 0xFFF3E2BA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-438652, (%esp)        # imm = 0xFFF94E84
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __libc_vfork, __libc_vfork@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_vfork
	addl	$-688915, (%esp)        # imm = 0xFFF57CED
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver initgroups, initgroups@GLIBC_2.0

	#NO_APP
	pushl	$initgroups
	addl	$-529446, (%esp)        # imm = 0xFFF7EBDA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver mblen, mblen@GLIBC_2.0

	#NO_APP
	pushl	$mblen
	addl	$-79219, (%esp)         # imm = 0xFFFECA8D
	retl
	#APP
.resume_9:
	#NO_APP
	popfl
	.loc	1 37 14                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:37:14
	movl	4(%eax), %eax
	.loc	1 37 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:37:7
	movl	%eax, (%esp)
	calll	update
	.loc	1 38 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:38:7
	jmp	.LBB0_8
.LBB0_6:
	.loc	1 0 7 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:0:7
	xorl	%eax, %eax
	.loc	1 38 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:38:7
	movl	.L__profc_main+48, %eax
	pushfl
	calll	.chain_10
	jmp	.resume_10
	#APP
.chain_10:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver pthread_attr_init, pthread_attr_init@GLIBC_2.1

	#NO_APP
	pushl	$pthread_attr_init
	addl	$-471757, (%esp)        # imm = 0xFFF8CD33
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-1097466, (%esp)       # imm = 0xFFEF4106
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver labs, labs@GLIBC_2.0

	#NO_APP
	pushl	$labs
	addl	$66058, (%esp)          # imm = 0x1020A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __getdomainname_chk, __getdomainname_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getdomainname_chk
	addl	$-876970, (%esp)        # imm = 0xFFF29E56
	pushl	$1
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __profile_frequency, __profile_frequency@GLIBC_2.0

	#NO_APP
	pushl	$__profile_frequency
	addl	$-983693, (%esp)        # imm = 0xFFF0FD73
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-750374, (%esp)        # imm = 0xFFF48CDA
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver getprotobyname_r, getprotobyname_r@GLIBC_2.0

	#NO_APP
	pushl	$getprotobyname_r
	addl	$-1099386, (%esp)       # imm = 0xFFEF3986
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-758022, (%esp)        # imm = 0xFFF46EFA
	retl
	#APP
.resume_10:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+52
	movl	%eax, .L__profc_main+48
	.loc	1 40 7 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:40:7
	movl	$0, (%esp)
	calll	exit
.LBB0_7:                                #   in Loop: Header=BB0_1 Depth=1
	movl	.L__profc_main+56, %eax
	pushfl
	calll	.chain_11
	jmp	.resume_11
	#APP
.chain_11:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$111683, (%esp)         # imm = 0x1B443
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver munlock, munlock@GLIBC_2.0

	#NO_APP
	pushl	$munlock
	addl	$-782522, (%esp)        # imm = 0xFFF40F46
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __sysconf, __sysconf@GLIBC_2.2

	#NO_APP
	pushl	$__sysconf
	addl	$-550806, (%esp)        # imm = 0xFFF7986A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver fts_set, fts_set@GLIBC_2.0

	#NO_APP
	pushl	$fts_set
	addl	$-744442, (%esp)        # imm = 0xFFF4A406
	pushl	$1
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver xdr_array, xdr_array@GLIBC_2.0

	#NO_APP
	pushl	$xdr_array
	addl	$-1190093, (%esp)       # imm = 0xFFEDD733
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-758998, (%esp)        # imm = 0xFFF46B2A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$62214, (%esp)          # imm = 0xF306
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-171910, (%esp)        # imm = 0xFFFD607A
	retl
	#APP
.resume_11:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+60
	movl	%eax, .L__profc_main+56
	.loc	1 42 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:42:7
	leal	.L.str.4, %eax
	movl	%eax, (%esp)
	calll	printf
.LBB0_8:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	1 43 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:43:5
	movl	.L__profc_main+16, %eax
	pushfl
	calll	.chain_12
	jmp	.resume_12
	#APP
.chain_12:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$74611, (%esp)          # imm = 0x12373
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_feof, _IO_feof@GLIBC_2.0

	#NO_APP
	pushl	$_IO_feof
	addl	$-202170, (%esp)        # imm = 0xFFFCEA46
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver clnt_sperror, clnt_sperror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_sperror
	addl	$-993414, (%esp)        # imm = 0xFFF0D77A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver ualarm, ualarm@GLIBC_2.0

	#NO_APP
	pushl	$ualarm
	addl	$-769530, (%esp)        # imm = 0xFFF44206
	pushl	$1
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __fdelt_warn, __fdelt_warn@GLIBC_2.15

	#NO_APP
	pushl	$__fdelt_warn
	addl	$-1045181, (%esp)       # imm = 0xFFF00D43
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __strspn_c1, __strspn_c1@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_c1
	addl	$-302070, (%esp)        # imm = 0xFFFB640A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver rresvport_af, rresvport_af@GLIBC_2.2

	#NO_APP
	pushl	$rresvport_af
	addl	$-901002, (%esp)        # imm = 0xFFF24076
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver getnetbyname, getnetbyname@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname
	addl	$-879814, (%esp)        # imm = 0xFFF2933A
	retl
	#APP
.resume_12:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+20
	movl	%eax, .L__profc_main+16
.Ltmp3:
	.loc	1 24 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:24:3
	jmp	.LBB0_1
.Ltmp4:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
	.section	.rodata,"a",@progbits
	.p2align	2
.LJTI0_0:
	.long	.LBB0_3
	.long	.LBB0_4
	.long	.LBB0_5
	.long	.LBB0_6
                                        # -- End function
	.text
	.globl	insert                  # -- Begin function insert
	.p2align	4, 0x90
	.type	insert,@function
insert:                                 # @insert
.Lfunc_begin1:
	.loc	1 48 0                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:48:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$40, %esp
	pushfl
	calll	.chain_13
	jmp	.resume_13
	#APP
.chain_13:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver inet6_rth_add, inet6_rth_add@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_add
	addl	$-920722, (%esp)        # imm = 0xFFF1F36E
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver svc_getreqset, svc_getreqset@GLIBC_2.0

	#NO_APP
	pushl	$svc_getreqset
	addl	$-630541, (%esp)        # imm = 0xFFF660F3
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$65910, (%esp)          # imm = 0x10176
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver ecvt, ecvt@GLIBC_2.0

	#NO_APP
	pushl	$ecvt
	addl	$-774406, (%esp)        # imm = 0xFFF42EFA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver ftok, ftok@GLIBC_2.0

	#NO_APP
	pushl	$ftok
	addl	$-810698, (%esp)        # imm = 0xFFF3A136
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver fgetpos, fgetpos@GLIBC_2.0

	#NO_APP
	pushl	$fgetpos
	addl	$-1231229, (%esp)       # imm = 0xFFED3683
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver inet6_option_find, inet6_option_find@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_find
	addl	$-916774, (%esp)        # imm = 0xFFF202DA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __munmap, __munmap@GLIBC_PRIVATE

	#NO_APP
	pushl	$__munmap
	addl	$-782026, (%esp)        # imm = 0xFFF41136
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver ptrace, ptrace@GLIBC_2.0

	#NO_APP
	pushl	$ptrace
	addl	$-761462, (%esp)        # imm = 0xFFF4618A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __freading, __freading@GLIBC_2.2

	#NO_APP
	pushl	$__freading
	addl	$-201830, (%esp)        # imm = 0xFFFCEB9A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_setbuffer, _IO_setbuffer@GLIBC_2.0

	#NO_APP
	pushl	$_IO_setbuffer
	addl	$-313315, (%esp)        # imm = 0xFFFB381D
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver mkstemp64, mkstemp64@GLIBC_2.2

	#NO_APP
	pushl	$mkstemp64
	addl	$-448636, (%esp)        # imm = 0xFFF92784
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$29367, (%esp)          # imm = 0x72B7
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver setsgent, setsgent@GLIBC_2.10

	#NO_APP
	pushl	$setsgent
	addl	$-824006, (%esp)        # imm = 0xFFF36D3A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __getcwd_chk, __getcwd_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getcwd_chk
	addl	$-1009107, (%esp)       # imm = 0xFFF09A2D
	retl
	#APP
.resume_13:
	#NO_APP
	popfl
.Ltmp5:
	.loc	1 48 22 prologue_end    # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:48:22
	movl	.L__profc_insert, %eax
	pushfl
	calll	.chain_14
	jmp	.resume_14
	#APP
.chain_14:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_wfile_underflow, _IO_wfile_underflow@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_underflow
	addl	$194355, (%esp)         # imm = 0x2F733
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-983146, (%esp)        # imm = 0xFFF0FF96
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __gconv_transliterate, __gconv_transliterate@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_transliterate
	addl	$133050, (%esp)         # imm = 0x207BA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver mbstowcs, mbstowcs@GLIBC_2.0

	#NO_APP
	pushl	$mbstowcs
	addl	$56982, (%esp)          # imm = 0xDE96
	pushl	$1
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver vwprintf, vwprintf@GLIBC_2.2

	#NO_APP
	pushl	$vwprintf
	addl	$-349725, (%esp)        # imm = 0xFFFAA9E3
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _setjmp, _setjmp@GLIBC_2.0

	#NO_APP
	pushl	$_setjmp
	addl	$80410, (%esp)          # imm = 0x13A1A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-80586, (%esp)         # imm = 0xFFFEC536
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver setjmp, setjmp@GLIBC_2.0

	#NO_APP
	pushl	$setjmp
	addl	$80474, (%esp)          # imm = 0x13A5A
	retl
	#APP
.resume_14:
	#NO_APP
	popfl
	adcl	$0, .L__profc_insert+4
	movl	%eax, .L__profc_insert
	.loc	1 50 23                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:50:23
	movl	$0, 4(%esp)
	movl	$16, (%esp)
	calll	malloc
	.loc	1 50 8 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:50:8
	movl	%eax, -8(%ebp)
	.loc	1 52 15 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:52:15
	movl	$0, 4(%esp)
	movl	$200, (%esp)
	calll	malloc
	.loc	1 51 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:51:3
	movl	-8(%ebp), %ecx
	.loc	1 51 15 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:51:15
	movl	%eax, 4(%ecx)
	pushfl
	calll	.chain_15
	jmp	.resume_15
	#APP
.chain_15:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __nss_hash, __nss_hash@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_hash
	addl	$-955570, (%esp)        # imm = 0xFFF16B4E
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver rexec_af, rexec_af@GLIBC_2.2

	#NO_APP
	pushl	$rexec_af
	addl	$-518477, (%esp)        # imm = 0xFFF816B3
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver mkdirat, mkdirat@GLIBC_2.4

	#NO_APP
	pushl	$mkdirat
	addl	$-718442, (%esp)        # imm = 0xFFF50996
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __idna_to_dns_encoding, __idna_to_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_to_dns_encoding
	addl	$-921910, (%esp)        # imm = 0xFFF1EECA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$101862, (%esp)         # imm = 0x18DE6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __sched_getparam, __sched_getparam@GLIBC_2.0

	#NO_APP
	pushl	$__sched_getparam
	addl	$-839037, (%esp)        # imm = 0xFFF33283
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver hcreate, hcreate@GLIBC_2.0

	#NO_APP
	pushl	$hcreate
	addl	$-777638, (%esp)        # imm = 0xFFF4225A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver fremovexattr, fremovexattr@GLIBC_2.3

	#NO_APP
	pushl	$fremovexattr
	addl	$-795434, (%esp)        # imm = 0xFFF3DCD6
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$74618, (%esp)          # imm = 0x1237A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-279782, (%esp)        # imm = 0xFFFBBB1A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver thrd_equal, thrd_equal@GLIBC_2.28

	#NO_APP
	pushl	$thrd_equal
	addl	$-1000131, (%esp)       # imm = 0xFFF0BD3D
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$165322, (%esp)         # imm = 0x285CA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver isupper, isupper@GLIBC_2.0

	#NO_APP
	pushl	$isupper
	addl	$425652, (%esp)         # imm = 0x67EB4
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-376675, (%esp)        # imm = 0xFFFA409D
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __libc_start_main, __libc_start_main@GLIBC_2.0

	#NO_APP
	pushl	$__libc_start_main
	addl	$167290, (%esp)         # imm = 0x28D7A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-911555, (%esp)        # imm = 0xFFF2173D
	retl
	#APP
.resume_15:
	#NO_APP
	popfl
	.loc	1 54 9 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:54:9
	movl	%eax, (%esp)
	leal	.L.str.5, %eax
	movl	%eax, 4(%esp)
	calll	fopen
	.loc	1 54 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:54:7
	movl	%eax, -16(%ebp)
.Ltmp6:
	.loc	1 55 11 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:55:11
	cmpl	$0, -16(%ebp)
.Ltmp7:
	.loc	1 55 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:55:7
	jne	.LBB1_2
# %bb.1:
	movl	.L__profc_insert+8, %eax
	pushfl
	calll	.chain_16
	jmp	.resume_16
	#APP
.chain_16:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver __strspn_cg, __strspn_cg@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_cg
	addl	$74243, (%esp)          # imm = 0x12203
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver jrand48, jrand48@GLIBC_2.0

	#NO_APP
	pushl	$jrand48
	addl	$53958, (%esp)          # imm = 0xD2C6
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver ftw64, ftw64@GLIBC_2.1

	#NO_APP
	pushl	$ftw64
	addl	$-729670, (%esp)        # imm = 0xFFF4DDBA
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver _IO_least_wmarker, _IO_least_wmarker@GLIBC_2.2

	#NO_APP
	pushl	$_IO_least_wmarker
	addl	$-185434, (%esp)        # imm = 0xFFFD2BA6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver xdr_uint8_t, xdr_uint8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint8_t
	addl	$-1195133, (%esp)       # imm = 0xFFEDC383
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver _IO_free_backup_area, _IO_free_backup_area@GLIBC_2.0

	#NO_APP
	pushl	$_IO_free_backup_area
	addl	$-223062, (%esp)        # imm = 0xFFFC98AA
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver capget, capget@GLIBC_2.1

	#NO_APP
	pushl	$capget
	addl	$-805306, (%esp)        # imm = 0xFFF3B646
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver inotify_init, inotify_init@GLIBC_2.4

	#NO_APP
	pushl	$inotify_init
	addl	$-797350, (%esp)        # imm = 0xFFF3D55A
	retl
	#APP
.resume_16:
	#NO_APP
	popfl
	adcl	$0, .L__profc_insert+12
	movl	%eax, .L__profc_insert+8
.Ltmp8:
	.loc	1 56 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:56:5
	leal	.L.str.6, %eax
	movl	%eax, (%esp)
	calll	perror
	jmp	.LBB1_3
.LBB1_2:
.Ltmp9:
	.loc	1 58 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:58:5
	leal	.L.str.7, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 59 18                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:59:18
	movl	-8(%ebp), %eax
	.loc	1 59 5 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:59:5
	leal	.L.str.3, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
	.loc	1 60 13 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:60:13
	movl	-8(%ebp), %eax
	.loc	1 60 43 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:60:43
	movl	-16(%ebp), %ecx
	.loc	1 60 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:60:5
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$4, 4(%esp)
	calll	fwrite
	.loc	1 61 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:61:5
	leal	.L.str.8, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 62 23                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:62:23
	movl	-8(%ebp), %eax
	.loc	1 62 30 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:62:30
	movl	4(%eax), %eax
	.loc	1 62 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:62:5
	leal	.L.str.9, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
	.loc	1 63 12 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:63:12
	movl	-8(%ebp), %eax
	.loc	1 63 19 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:63:19
	movl	4(%eax), %eax
	.loc	1 63 33                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:63:33
	movl	-16(%ebp), %ecx
	.loc	1 63 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:63:5
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$200, 4(%esp)
	calll	fwrite
	.loc	1 64 10 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:64:10
	movl	count, %eax
	addl	$1, %eax
	movl	%eax, count
.Ltmp10:
.LBB1_3:
	.loc	1 0 10 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:0:10
	pushfl
	calll	.chain_17
	jmp	.resume_17
	#APP
.chain_17:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver getnetgrent, getnetgrent@GLIBC_2.0

	#NO_APP
	pushl	$getnetgrent
	addl	$-904898, (%esp)        # imm = 0xFFF2313E
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver clnt_pcreateerror, clnt_pcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_pcreateerror
	addl	$-615821, (%esp)        # imm = 0xFFF69A73
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver pthread_mutex_destroy, pthread_mutex_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_mutex_destroy
	addl	$-861194, (%esp)        # imm = 0xFFF2DBF6
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __wcsncpy_chk, __wcsncpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncpy_chk
	addl	$-865462, (%esp)        # imm = 0xFFF2CB4A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __nss_group_lookup, __nss_group_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_group_lookup
	addl	$-1100010, (%esp)       # imm = 0xFFEF3716
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver xdr_int32_t, xdr_int32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int32_t
	addl	$-1194445, (%esp)       # imm = 0xFFEDC633
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver xdr_callhdr, xdr_callhdr@GLIBC_2.0

	#NO_APP
	pushl	$xdr_callhdr
	addl	$-963782, (%esp)        # imm = 0xFFF14B3A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver _IO_wfile_xsputn, _IO_wfile_xsputn@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_xsputn
	addl	$-190678, (%esp)        # imm = 0xFFFD172A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver _mcleanup, _mcleanup@GLIBC_2.0

	#NO_APP
	pushl	$_mcleanup
	addl	$-806310, (%esp)        # imm = 0xFFF3B25A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-1063635, (%esp)       # imm = 0xFFEFC52D
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$112122, (%esp)         # imm = 0x1B5FA
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver prlimit, prlimit@GLIBC_2.13

	#NO_APP
	pushl	$prlimit
	addl	$-482828, (%esp)        # imm = 0xFFF8A1F4
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __strtof_l, __strtof_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtof_l
	addl	$-106547, (%esp)        # imm = 0xFFFE5FCD
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __internal_endnetgrent, __internal_endnetgrent@GLIBC_PRIVATE

	#NO_APP
	pushl	$__internal_endnetgrent
	addl	$-902166, (%esp)        # imm = 0xFFF23BEA
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver authunix_create, authunix_create@GLIBC_2.0

	#NO_APP
	pushl	$authunix_create
	addl	$-1136675, (%esp)       # imm = 0xFFEEA7DD
	retl
	#APP
.resume_17:
	#NO_APP
	popfl
	.loc	1 66 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:66:3
	movl	%eax, (%esp)
	calll	fclose
	.loc	1 67 8                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:67:8
	movl	-8(%ebp), %eax
	.loc	1 67 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:67:3
	movl	%eax, (%esp)
	calll	free
	pushfl
	calll	.chain_18
	jmp	.resume_18
	#APP
.chain_18:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getrpcent, getrpcent@GLIBC_2.0

	#NO_APP
	pushl	$getrpcent
	addl	$-979922, (%esp)        # imm = 0xFFF10C2E
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-642093, (%esp)        # imm = 0xFFF633D3
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$153238, (%esp)         # imm = 0x25696
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver mcheck_pedantic, mcheck_pedantic@GLIBC_2.2

	#NO_APP
	pushl	$mcheck_pedantic
	addl	$-263990, (%esp)        # imm = 0xFFFBF8CA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver xdr_uint32_t, xdr_uint32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint32_t
	addl	$-1028682, (%esp)       # imm = 0xFFF04DB6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getnameinfo, getnameinfo@GLIBC_2.1

	#NO_APP
	pushl	$getnameinfo
	addl	$-1081869, (%esp)       # imm = 0xFFEF7DF3
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver _dl_mcount_wrapper_check, _dl_mcount_wrapper_check@GLIBC_2.1

	#NO_APP
	pushl	$_dl_mcount_wrapper_check
	addl	$-1039014, (%esp)       # imm = 0xFFF0255A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __wcstod_internal, __wcstod_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstod_internal
	addl	$-402426, (%esp)        # imm = 0xFFF9DC06
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver svcerr_noprog, svcerr_noprog@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_noprog
	addl	$-1008166, (%esp)       # imm = 0xFFF09DDA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getpwnam, getpwnam@GLIBC_2.0

	#NO_APP
	pushl	$getpwnam
	addl	$-537926, (%esp)        # imm = 0xFFF7CABA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-322819, (%esp)        # imm = 0xFFFB12FD
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __libc_freeres, __libc_freeres@GLIBC_2.1

	#NO_APP
	pushl	$__libc_freeres
	addl	$-1248342, (%esp)       # imm = 0xFFECF3AA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver setdomainname, setdomainname@GLIBC_2.0

	#NO_APP
	pushl	$setdomainname
	addl	$-446540, (%esp)        # imm = 0xFFF92FB4
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver posix_spawnattr_setsigdefault, posix_spawnattr_setsigdefault@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setsigdefault
	addl	$-844883, (%esp)        # imm = 0xFFF31BAD
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver fts64_close, fts64_close@GLIBC_2.23

	#NO_APP
	pushl	$fts64_close
	addl	$-740998, (%esp)        # imm = 0xFFF4B17A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getgrnam_r, getgrnam_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getgrnam_r
	addl	$-677971, (%esp)        # imm = 0xFFF5A7AD
	retl
	#APP
.resume_18:
	#NO_APP
	popfl
	.loc	1 68 15 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:68:15
	movl	4(%eax), %eax
	.loc	1 68 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:68:3
	movl	%eax, (%esp)
	calll	free
	.loc	1 69 1 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:69:1
	addl	$40, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp11:
.Lfunc_end1:
	.size	insert, .Lfunc_end1-insert
	.cfi_endproc
                                        # -- End function
	.globl	display                 # -- Begin function display
	.p2align	4, 0x90
	.type	display,@function
display:                                # @display
.Lfunc_begin2:
	.loc	1 72 0                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:72:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$56, %esp
	pushfl
	calll	.chain_19
	jmp	.resume_19
	#APP
.chain_19:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver preadv64v2, preadv64v2@GLIBC_2.26

	#NO_APP
	pushl	$preadv64v2
	addl	$-756146, (%esp)        # imm = 0xFFF4764E
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver innetgr, innetgr@GLIBC_2.0

	#NO_APP
	pushl	$innetgr
	addl	$-524589, (%esp)        # imm = 0xFFF7FED3
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver _IO_seekmark, _IO_seekmark@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekmark
	addl	$-238650, (%esp)        # imm = 0xFFFC5BC6
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver read, read@GLIBC_2.0

	#NO_APP
	pushl	$read
	addl	$-711286, (%esp)        # imm = 0xFFF5258A
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$153238, (%esp)         # imm = 0x25696
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver getentropy, getentropy@GLIBC_2.25

	#NO_APP
	pushl	$getentropy
	addl	$-113565, (%esp)        # imm = 0xFFFE4463
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver inet6_rth_init, inet6_rth_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_init
	addl	$-919974, (%esp)        # imm = 0xFFF1F65A
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver xdr_u_int, xdr_u_int@GLIBC_2.0

	#NO_APP
	pushl	$xdr_u_int
	addl	$-1025402, (%esp)       # imm = 0xFFF05A86
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver xdr_authunix_parms, xdr_authunix_parms@GLIBC_2.0

	#NO_APP
	pushl	$xdr_authunix_parms
	addl	$-955910, (%esp)        # imm = 0xFFF169FA
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver __isxdigit_l, __isxdigit_l@GLIBC_2.1

	#NO_APP
	pushl	$__isxdigit_l
	addl	$112522, (%esp)         # imm = 0x1B78A
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver sched_getaffinity, sched_getaffinity@GLIBC_2.3.3

	#NO_APP
	pushl	$sched_getaffinity
	addl	$-1224051, (%esp)       # imm = 0xFFED528D
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-816390, (%esp)        # imm = 0xFFF38AFA
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver _authenticate, _authenticate@GLIBC_2.1

	#NO_APP
	pushl	$_authenticate
	addl	$-653676, (%esp)        # imm = 0xFFF60694
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-371075, (%esp)        # imm = 0xFFFA567D
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-751238, (%esp)        # imm = 0xFFF4897A
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver strcoll, strcoll@GLIBC_2.0

	#NO_APP
	pushl	$strcoll
	addl	$-415267, (%esp)        # imm = 0xFFF9A9DD
	retl
	#APP
.resume_19:
	#NO_APP
	popfl
.Ltmp12:
	.loc	1 72 23 prologue_end    # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:72:23
	movl	.L__profc_display, %eax
	pushfl
	calll	.chain_20
	jmp	.resume_20
	#APP
.chain_20:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __libc_fatal, __libc_fatal@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_fatal
	addl	$175379, (%esp)         # imm = 0x2AD13
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-155274, (%esp)        # imm = 0xFFFDA176
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver pthread_cond_broadcast, pthread_cond_broadcast@GLIBC_2.3.2

	#NO_APP
	pushl	$pthread_cond_broadcast
	addl	$-851766, (%esp)        # imm = 0xFFF300CA
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-238554, (%esp)        # imm = 0xFFFC5C26
	pushl	$1
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __ctype_b_loc, __ctype_b_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_b_loc
	addl	$-62093, (%esp)         # imm = 0xFFFF0D73
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver sendfile, sendfile@GLIBC_2.1

	#NO_APP
	pushl	$sendfile
	addl	$-745142, (%esp)        # imm = 0xFFF4A14A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver mkstemps64, mkstemps64@GLIBC_2.11

	#NO_APP
	pushl	$mkstemps64
	addl	$-769194, (%esp)        # imm = 0xFFF44356
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver getnetname, getnetname@GLIBC_2.1

	#NO_APP
	pushl	$getnetname
	addl	$-1004374, (%esp)       # imm = 0xFFF0ACAA
	retl
	#APP
.resume_20:
	#NO_APP
	popfl
	adcl	$0, .L__profc_display+4
	movl	%eax, .L__profc_display
	.loc	1 75 13                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:75:13
	movl	count, %eax
	.loc	1 75 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:75:7
	movl	%eax, -20(%ebp)
	.loc	1 76 22 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:76:22
	movl	$0, 4(%esp)
	movl	$16, (%esp)
	calll	malloc
	.loc	1 76 8 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:76:8
	movl	%eax, -8(%ebp)
	.loc	1 77 24 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:77:24
	movl	$0, 4(%esp)
	movl	$200, (%esp)
	calll	malloc
	.loc	1 77 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:77:3
	movl	-8(%ebp), %ecx
	.loc	1 77 14                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:77:14
	movl	%eax, 4(%ecx)
	pushfl
	calll	.chain_21
	jmp	.resume_21
	#APP
.chain_21:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_fopen, _IO_fopen@GLIBC_2.1

	#NO_APP
	pushl	$_IO_fopen
	addl	$-160706, (%esp)        # imm = 0xFFFD8C3E
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __poll, __poll@GLIBC_2.1

	#NO_APP
	pushl	$__poll
	addl	$-364573, (%esp)        # imm = 0xFFFA6FE3
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_seekpos, _IO_seekpos@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekpos
	addl	$-176634, (%esp)        # imm = 0xFFFD4E06
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __strcat_g, __strcat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strcat_g
	addl	$-303894, (%esp)        # imm = 0xFFFB5CEA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$-210490, (%esp)        # imm = 0xFFFCC9C6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __strchrnul_g, __strchrnul_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_g
	addl	$-478477, (%esp)        # imm = 0xFFF8B2F3
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver authdes_pk_create, authdes_pk_create@GLIBC_2.1

	#NO_APP
	pushl	$authdes_pk_create
	addl	$-989798, (%esp)        # imm = 0xFFF0E59A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __towctrans, __towctrans@GLIBC_2.1

	#NO_APP
	pushl	$__towctrans
	addl	$-821002, (%esp)        # imm = 0xFFF378F6
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver readdir64_r, readdir64_r@GLIBC_2.2

	#NO_APP
	pushl	$readdir64_r
	addl	$-524214, (%esp)        # imm = 0xFFF8004A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver globfree64, globfree64@GLIBC_2.1

	#NO_APP
	pushl	$globfree64
	addl	$-572518, (%esp)        # imm = 0xFFF7439A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __sysctl, __sysctl@GLIBC_2.2

	#NO_APP
	pushl	$__sysctl
	addl	$-938307, (%esp)        # imm = 0xFFF1AEBD
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_switch_to_wbackup_area, _IO_switch_to_wbackup_area@GLIBC_2.2

	#NO_APP
	pushl	$_IO_switch_to_wbackup_area
	addl	$-177174, (%esp)        # imm = 0xFFFD4BEA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver wcsxfrm, wcsxfrm@GLIBC_2.0

	#NO_APP
	pushl	$wcsxfrm
	addl	$-123292, (%esp)        # imm = 0xFFFE1E64
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-291715, (%esp)        # imm = 0xFFFB8C7D
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __backtrace_symbols_fd, __backtrace_symbols_fd@GLIBC_2.1

	#NO_APP
	pushl	$__backtrace_symbols_fd
	addl	$-858230, (%esp)        # imm = 0xFFF2E78A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_str_underflow, _IO_str_underflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_underflow
	addl	$-376547, (%esp)        # imm = 0xFFFA411D
	retl
	#APP
.resume_21:
	#NO_APP
	popfl
	.loc	1 79 9 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:79:9
	movl	%eax, (%esp)
	leal	.L.str.10, %eax
	movl	%eax, 4(%esp)
	calll	fopen
	.loc	1 79 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:79:7
	movl	%eax, -16(%ebp)
.Ltmp13:
	.loc	1 80 13 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:80:13
	cmpl	$0, count
.Ltmp14:
	.loc	1 80 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:80:7
	jne	.LBB2_2
# %bb.1:
	movl	.L__profc_display+8, %eax
	pushfl
	calll	.chain_22
	jmp	.resume_22
	#APP
.chain_22:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver getaliasent_r, getaliasent_r@GLIBC_2.0

	#NO_APP
	pushl	$getaliasent_r
	addl	$-712749, (%esp)        # imm = 0xFFF51FD3
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver srand48, srand48@GLIBC_2.0

	#NO_APP
	pushl	$srand48
	addl	$53878, (%esp)          # imm = 0xD276
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver sigemptyset, sigemptyset@GLIBC_2.0

	#NO_APP
	pushl	$sigemptyset
	addl	$76762, (%esp)          # imm = 0x12BDA
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver clntunix_create, clntunix_create@GLIBC_2.1

	#NO_APP
	pushl	$clntunix_create
	addl	$-993450, (%esp)        # imm = 0xFFF0D756
	pushl	$1
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __iswpunct_l, __iswpunct_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswpunct_l
	addl	$-988301, (%esp)        # imm = 0xFFF0EB73
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __tfind, __tfind@GLIBC_PRIVATE

	#NO_APP
	pushl	$__tfind
	addl	$-779862, (%esp)        # imm = 0xFFF419AA
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver _dl_signal_error, _dl_signal_error@GLIBC_PRIVATE

	#NO_APP
	pushl	$_dl_signal_error
	addl	$-1050442, (%esp)       # imm = 0xFFEFF8B6
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver vwscanf, vwscanf@GLIBC_2.2

	#NO_APP
	pushl	$vwscanf
	addl	$-175686, (%esp)        # imm = 0xFFFD51BA
	retl
	#APP
.resume_22:
	#NO_APP
	popfl
	adcl	$0, .L__profc_display+12
	movl	%eax, .L__profc_display+8
.Ltmp15:
	.loc	1 81 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:81:5
	leal	.L.str.11, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 82 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:82:5
	jmp	.LBB2_9
.Ltmp16:
.LBB2_2:
	.loc	1 84 11                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:84:11
	cmpl	$0, -16(%ebp)
.Ltmp17:
	.loc	1 84 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:84:7
	jne	.LBB2_4
# %bb.3:
	movl	.L__profc_display+16, %eax
	pushfl
	calll	.chain_23
	jmp	.resume_23
	#APP
.chain_23:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver _IO_peekc_locked, _IO_peekc_locked@GLIBC_2.0

	#NO_APP
	pushl	$_IO_peekc_locked
	addl	$170595, (%esp)         # imm = 0x29A63
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __register_frame_info_table, __register_frame_info_table@GLIBC_2.0

	#NO_APP
	pushl	$__register_frame_info_table
	addl	$-1056410, (%esp)       # imm = 0xFFEFE166
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver cfsetispeed, cfsetispeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetispeed
	addl	$-750054, (%esp)        # imm = 0xFFF48E1A
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __libc_pvalloc, __libc_pvalloc@GLIBC_2.0

	#NO_APP
	pushl	$__libc_pvalloc
	addl	$-266522, (%esp)        # imm = 0xFFFBEEE6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __ppoll_chk, __ppoll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__ppoll_chk
	addl	$-1045309, (%esp)       # imm = 0xFFF00CC3
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver _IO_fsetpos64, _IO_fsetpos64@GLIBC_2.2

	#NO_APP
	pushl	$_IO_fsetpos64
	addl	$-170470, (%esp)        # imm = 0xFFFD661A
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __fsetlocking, __fsetlocking@GLIBC_2.2

	#NO_APP
	pushl	$__fsetlocking
	addl	$-210842, (%esp)        # imm = 0xFFFCC866
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver getservent_r, getservent_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getservent_r
	addl	$-888214, (%esp)        # imm = 0xFFF2726A
	retl
	#APP
.resume_23:
	#NO_APP
	popfl
	adcl	$0, .L__profc_display+20
	movl	%eax, .L__profc_display+16
.Ltmp18:
	.loc	1 85 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:85:5
	leal	.L.str.6, %eax
	movl	%eax, (%esp)
	calll	perror
	jmp	.LBB2_8
.LBB2_4:
.Ltmp19:
	.loc	1 87 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:87:5
	jmp	.LBB2_5
.LBB2_5:                                # =>This Inner Loop Header: Depth=1
	cmpl	$0, -20(%ebp)
	je	.LBB2_7
# %bb.6:                                #   in Loop: Header=BB2_5 Depth=1
	movl	.L__profc_display+24, %eax
	pushfl
	calll	.chain_24
	jmp	.resume_24
	#APP
.chain_24:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver stty, stty@GLIBC_2.0

	#NO_APP
	pushl	$stty
	addl	$-382829, (%esp)        # imm = 0xFFFA2893
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver semop, semop@GLIBC_2.0

	#NO_APP
	pushl	$semop
	addl	$-811466, (%esp)        # imm = 0xFFF39E36
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver _IO_file_sync, _IO_file_sync@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_sync
	addl	$-1063270, (%esp)       # imm = 0xFFEFC69A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver isalnum, isalnum@GLIBC_2.0

	#NO_APP
	pushl	$isalnum
	addl	$106198, (%esp)         # imm = 0x19ED6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver readlinkat, readlinkat@GLIBC_2.4

	#NO_APP
	pushl	$readlinkat
	addl	$-894893, (%esp)        # imm = 0xFFF25853
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver timespec_get, timespec_get@GLIBC_2.16

	#NO_APP
	pushl	$timespec_get
	addl	$-517638, (%esp)        # imm = 0xFFF819FA
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver _IO_adjust_column, _IO_adjust_column@GLIBC_2.0

	#NO_APP
	pushl	$_IO_adjust_column
	addl	$-236026, (%esp)        # imm = 0xFFFC6606
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver svc_getreq_common, svc_getreq_common@GLIBC_2.2

	#NO_APP
	pushl	$svc_getreq_common
	addl	$-1008406, (%esp)       # imm = 0xFFF09CEA
	retl
	#APP
.resume_24:
	#NO_APP
	popfl
	adcl	$0, .L__profc_display+28
	movl	%eax, .L__profc_display+24
	pushfl
	calll	.chain_25
	jmp	.resume_25
	#APP
.chain_25:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-172546, (%esp)        # imm = 0xFFFD5DFE
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __finite, __finite@GLIBC_2.0

	#NO_APP
	pushl	$__finite
	addl	$464067, (%esp)         # imm = 0x714C3
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver muntrace, muntrace@GLIBC_2.0

	#NO_APP
	pushl	$muntrace
	addl	$-274858, (%esp)        # imm = 0xFFFBCE56
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver fputws, fputws@GLIBC_2.2

	#NO_APP
	pushl	$fputws
	addl	$-172470, (%esp)        # imm = 0xFFFD5E4A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __isoc99_fwscanf, __isoc99_fwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_fwscanf
	addl	$-456858, (%esp)        # imm = 0xFFF90766
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __fpurge, __fpurge@GLIBC_2.2

	#NO_APP
	pushl	$__fpurge
	addl	$-376493, (%esp)        # imm = 0xFFFA4153
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver _IO_file_sync, _IO_file_sync@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_sync
	addl	$-1063270, (%esp)       # imm = 0xFFEFC69A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __ctype_init, __ctype_init@GLIBC_PRIVATE

	#NO_APP
	pushl	$__ctype_init
	addl	$103606, (%esp)         # imm = 0x194B6
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-766662, (%esp)        # imm = 0xFFF44D3A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver wcsncat, wcsncat@GLIBC_2.0

	#NO_APP
	pushl	$wcsncat
	addl	$-386214, (%esp)        # imm = 0xFFFA1B5A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver strxfrm, strxfrm@GLIBC_2.0

	#NO_APP
	pushl	$strxfrm
	addl	$-420387, (%esp)        # imm = 0xFFF995DD
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver getopt_long, getopt_long@GLIBC_2.0

	#NO_APP
	pushl	$getopt_long
	addl	$-664262, (%esp)        # imm = 0xFFF5DD3A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __isalpha_l, __isalpha_l@GLIBC_2.1

	#NO_APP
	pushl	$__isalpha_l
	addl	$424820, (%esp)         # imm = 0x67B74
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __xmknod, __xmknod@GLIBC_2.0

	#NO_APP
	pushl	$__xmknod
	addl	$-853043, (%esp)        # imm = 0xFFF2FBCD
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-772726, (%esp)        # imm = 0xFFF4358A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver getmntent, getmntent@GLIBC_2.0

	#NO_APP
	pushl	$getmntent
	addl	$-907667, (%esp)        # imm = 0xFFF2266D
	retl
	#APP
.resume_25:
	#NO_APP
	popfl
.Ltmp20:
	.loc	1 89 43                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:89:43
	movl	-16(%ebp), %ecx
	.loc	1 89 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:89:7
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$4, 4(%esp)
	calll	fread
	.loc	1 90 20 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:90:20
	movl	-8(%ebp), %eax
	.loc	1 90 26 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:90:26
	movl	(%eax), %eax
	.loc	1 90 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:90:7
	leal	.L.str.3, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
	.loc	1 91 13 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:91:13
	movl	-8(%ebp), %eax
	.loc	1 91 19 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:91:19
	movl	4(%eax), %eax
	.loc	1 91 33                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:91:33
	movl	-16(%ebp), %ecx
	.loc	1 91 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:91:7
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$200, 4(%esp)
	calll	fread
	.loc	1 92 23 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:92:23
	movl	-8(%ebp), %eax
	.loc	1 92 29 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:92:29
	movl	4(%eax), %eax
	.loc	1 92 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:92:7
	leal	.L.str.12, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
	.loc	1 93 10 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:93:10
	movl	-20(%ebp), %eax
	pushfl
	calll	.chain_26
	jmp	.resume_26
	#APP
.chain_26:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_wdefault_xsputn, _IO_wdefault_xsputn@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_xsputn
	addl	$200147, (%esp)         # imm = 0x30DD3
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver posix_spawnattr_getsigdefault, posix_spawnattr_getsigdefault@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_getsigdefault
	addl	$-708378, (%esp)        # imm = 0xFFF530E6
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __nss_database_lookup, __nss_database_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_database_lookup
	addl	$-945846, (%esp)        # imm = 0xFFF1914A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_str_seekoff, _IO_str_seekoff@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_seekoff
	addl	$-241866, (%esp)        # imm = 0xFFFC4F36
	pushl	$-1
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __libc_rpc_getport, __libc_rpc_getport@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_rpc_getport
	addl	$-1179437, (%esp)       # imm = 0xFFEE00D3
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver pthread_attr_getschedpolicy, pthread_attr_getschedpolicy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_getschedpolicy
	addl	$-851094, (%esp)        # imm = 0xFFF3036A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver gethostbyaddr, gethostbyaddr@GLIBC_2.0

	#NO_APP
	pushl	$gethostbyaddr
	addl	$-880794, (%esp)        # imm = 0xFFF28F66
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __strtol_internal, __strtol_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtol_internal
	addl	$58554, (%esp)          # imm = 0xE4BA
	retl
	#APP
.resume_26:
	#NO_APP
	popfl
	movl	%eax, -20(%ebp)
.Ltmp21:
	.loc	1 87 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:87:5
	jmp	.LBB2_5
.Ltmp22:
.LBB2_7:
	.loc	1 0 5 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:0:5
	jmp	.LBB2_8
.LBB2_8:
	pushfl
	calll	.chain_27
	jmp	.resume_27
	#APP
.chain_27:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-178562, (%esp)        # imm = 0xFFFD467E
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver wcsspn, wcsspn@GLIBC_2.0

	#NO_APP
	pushl	$wcsspn
	addl	$-8541, (%esp)          # imm = 0xDEA3
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver thrd_current, thrd_current@GLIBC_2.28

	#NO_APP
	pushl	$thrd_current
	addl	$-863642, (%esp)        # imm = 0xFFF2D266
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver fremovexattr, fremovexattr@GLIBC_2.3

	#NO_APP
	pushl	$fremovexattr
	addl	$-786982, (%esp)        # imm = 0xFFF3FDDA
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver l64a, l64a@GLIBC_2.0

	#NO_APP
	pushl	$l64a
	addl	$1414, (%esp)           # imm = 0x586
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-888461, (%esp)        # imm = 0xFFF27173
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __strverscmp, __strverscmp@GLIBC_2.1.1

	#NO_APP
	pushl	$__strverscmp
	addl	$-270566, (%esp)        # imm = 0xFFFBDF1A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __libc_thread_freeres, __libc_thread_freeres@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_thread_freeres
	addl	$-278570, (%esp)        # imm = 0xFFFBBFD6
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver isascii, isascii@GLIBC_2.0

	#NO_APP
	pushl	$isascii
	addl	$113290, (%esp)         # imm = 0x1BA8A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __backtrace, __backtrace@GLIBC_2.1

	#NO_APP
	pushl	$__backtrace
	addl	$-857174, (%esp)        # imm = 0xFFF2EBAA
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver wordfree, wordfree@GLIBC_2.1

	#NO_APP
	pushl	$wordfree
	addl	$-839843, (%esp)        # imm = 0xFFF32F5D
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __sched_cpualloc, __sched_cpualloc@GLIBC_2.7

	#NO_APP
	pushl	$__sched_cpualloc
	addl	$-703414, (%esp)        # imm = 0xFFF5444A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver _mcleanup, _mcleanup@GLIBC_2.0

	#NO_APP
	pushl	$_mcleanup
	addl	$-494588, (%esp)        # imm = 0xFFF87404
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver envz_remove, envz_remove@GLIBC_2.0

	#NO_APP
	pushl	$envz_remove
	addl	$-432067, (%esp)        # imm = 0xFFF9683D
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver getsgent, getsgent@GLIBC_2.10

	#NO_APP
	pushl	$getsgent
	addl	$-821814, (%esp)        # imm = 0xFFF375CA
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver endspent, endspent@GLIBC_2.0

	#NO_APP
	pushl	$endspent
	addl	$-963155, (%esp)        # imm = 0xFFF14DAD
	retl
	#APP
.resume_27:
	#NO_APP
	popfl
	.loc	1 96 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:96:3
	movl	%eax, (%esp)
	calll	fclose
	.loc	1 97 8                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:97:8
	movl	-8(%ebp), %eax
	.loc	1 97 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:97:3
	movl	%eax, (%esp)
	calll	free
	pushfl
	calll	.chain_28
	jmp	.resume_28
	#APP
.chain_28:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver _IO_file_overflow, _IO_file_overflow@GLIBC_2.1

	#NO_APP
	pushl	$_IO_file_overflow
	addl	$-220930, (%esp)        # imm = 0xFFFCA0FE
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver strfroml, strfroml@GLIBC_2.25

	#NO_APP
	pushl	$strfroml
	addl	$437779, (%esp)         # imm = 0x6AE13
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver ether_line, ether_line@GLIBC_2.0

	#NO_APP
	pushl	$ether_line
	addl	$-897674, (%esp)        # imm = 0xFFF24D76
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver sendfile, sendfile@GLIBC_2.1

	#NO_APP
	pushl	$sendfile
	addl	$-745142, (%esp)        # imm = 0xFFF4A14A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-549322, (%esp)        # imm = 0xFFF79E36
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __libc_mallopt, __libc_mallopt@GLIBC_2.0

	#NO_APP
	pushl	$__libc_mallopt
	addl	$-435213, (%esp)        # imm = 0xFFF95BF3
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __cxa_atexit, __cxa_atexit@GLIBC_2.1.3

	#NO_APP
	pushl	$__cxa_atexit
	addl	$67194, (%esp)          # imm = 0x1067A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver inet6_option_space, inet6_option_space@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_space
	addl	$-924634, (%esp)        # imm = 0xFFF1E426
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-919398, (%esp)        # imm = 0xFFF1F89A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$70666, (%esp)          # imm = 0x1140A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __swprintf_chk, __swprintf_chk@GLIBC_2.4

	#NO_APP
	pushl	$__swprintf_chk
	addl	$-1011139, (%esp)       # imm = 0xFFF0923D
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver _IO_default_xsgetn, _IO_default_xsgetn@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_xsgetn
	addl	$-225286, (%esp)        # imm = 0xFFFC8FFA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver posix_spawnattr_destroy, posix_spawnattr_destroy@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_destroy
	addl	$-388156, (%esp)        # imm = 0xFFFA13C4
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver setxattr, setxattr@GLIBC_2.3

	#NO_APP
	pushl	$setxattr
	addl	$-932339, (%esp)        # imm = 0xFFF1C60D
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver mlockall, mlockall@GLIBC_2.0

	#NO_APP
	pushl	$mlockall
	addl	$-774118, (%esp)        # imm = 0xFFF4301A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __strchrnul_c, __strchrnul_c@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_c
	addl	$-449027, (%esp)        # imm = 0xFFF925FD
	retl
	#APP
.resume_28:
	#NO_APP
	popfl
	.loc	1 98 14 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:98:14
	movl	4(%eax), %eax
	.loc	1 98 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:98:3
	movl	%eax, (%esp)
	calll	free
.LBB2_9:
	.loc	1 99 1 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:99:1
	addl	$56, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp23:
.Lfunc_end2:
	.size	display, .Lfunc_end2-display
	.cfi_endproc
                                        # -- End function
	.globl	update                  # -- Begin function update
	.p2align	4, 0x90
	.type	update,@function
update:                                 # @update
.Lfunc_begin3:
	.loc	1 102 0                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:102:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	pushl	%esi
	subl	$260, %esp              # imm = 0x104
	.cfi_offset %esi, -12
	pushfl
	calll	.chain_29
	jmp	.resume_29
	#APP
.chain_29:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver fgetpwent, fgetpwent@GLIBC_2.0

	#NO_APP
	pushl	$fgetpwent
	addl	$-537266, (%esp)        # imm = 0xFFF7CD4E
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __xstat, __xstat@GLIBC_2.0

	#NO_APP
	pushl	$__xstat
	addl	$-328333, (%esp)        # imm = 0xFFFAFD73
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$-275322, (%esp)        # imm = 0xFFFBCC86
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __libc_current_sigrtmin_private, __libc_current_sigrtmin_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_current_sigrtmin_private
	addl	$75466, (%esp)          # imm = 0x126CA
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver fattach, fattach@GLIBC_2.1

	#NO_APP
	pushl	$fattach
	addl	$-1033786, (%esp)       # imm = 0xFFF039C6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __pause_nocancel, __pause_nocancel@GLIBC_PRIVATE

	#NO_APP
	pushl	$__pause_nocancel
	addl	$-923725, (%esp)        # imm = 0xFFF1E7B3
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __recv_chk, __recv_chk@GLIBC_2.4

	#NO_APP
	pushl	$__recv_chk
	addl	$-863766, (%esp)        # imm = 0xFFF2D1EA
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __sigdelset, __sigdelset@GLIBC_2.0

	#NO_APP
	pushl	$__sigdelset
	addl	$-1061898, (%esp)       # imm = 0xFFEFCBF6
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver preadv64, preadv64@GLIBC_2.10

	#NO_APP
	pushl	$preadv64
	addl	$-754422, (%esp)        # imm = 0xFFF47D0A
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __gai_sigqueue, __gai_sigqueue@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gai_sigqueue
	addl	$-944278, (%esp)        # imm = 0xFFF1976A
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver inet_ntop, inet_ntop@GLIBC_2.0

	#NO_APP
	pushl	$inet_ntop
	addl	$-1072355, (%esp)       # imm = 0xFFEFA31D
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver gethostbyname_r, gethostbyname_r@GLIBC_2.1.2

	#NO_APP
	pushl	$gethostbyname_r
	addl	$-876278, (%esp)        # imm = 0xFFF2A10A
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver key_setsecret, key_setsecret@GLIBC_2.1

	#NO_APP
	pushl	$key_setsecret
	addl	$-690348, (%esp)        # imm = 0xFFF57754
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver _IO_un_link, _IO_un_link@GLIBC_2.0

	#NO_APP
	pushl	$_IO_un_link
	addl	$-366467, (%esp)        # imm = 0xFFFA687D
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __gethostname_chk, __gethostname_chk@GLIBC_2.4

	#NO_APP
	pushl	$__gethostname_chk
	addl	$-868454, (%esp)        # imm = 0xFFF2BF9A
	calll	opaquePredicate
	jne	.chain_29
	#APP
.symver __fpending, __fpending@GLIBC_2.2

	#NO_APP
	pushl	$__fpending
	addl	$-347203, (%esp)        # imm = 0xFFFAB3BD
	retl
	#APP
.resume_29:
	#NO_APP
	popfl
.Ltmp24:
	.loc	1 102 22 prologue_end   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:102:22
	movl	.L__profc_update, %eax
	pushfl
	calll	.chain_30
	jmp	.resume_30
	#APP
.chain_30:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver pthread_mutex_unlock, pthread_mutex_unlock@GLIBC_2.0

	#NO_APP
	pushl	$pthread_mutex_unlock
	addl	$-474525, (%esp)        # imm = 0xFFF8C263
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver __vwprintf_chk, __vwprintf_chk@GLIBC_2.4

	#NO_APP
	pushl	$__vwprintf_chk
	addl	$-875594, (%esp)        # imm = 0xFFF2A3B6
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver fgetgrent, fgetgrent@GLIBC_2.0

	#NO_APP
	pushl	$fgetgrent
	addl	$-527270, (%esp)        # imm = 0xFFF7F45A
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver __libc_current_sigrtmax_private, __libc_current_sigrtmax_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_current_sigrtmax_private
	addl	$66950, (%esp)          # imm = 0x10586
	pushl	$1
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver getnetent, getnetent@GLIBC_2.0

	#NO_APP
	pushl	$getnetent
	addl	$-1054573, (%esp)       # imm = 0xFFEFE893
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-798534, (%esp)        # imm = 0xFFF3D0BA
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver remove, remove@GLIBC_2.0

	#NO_APP
	pushl	$remove
	addl	$-157194, (%esp)        # imm = 0xFFFD99F6
	calll	opaquePredicate
	jne	.chain_30
	#APP
.symver __fortify_fail, __fortify_fail@GLIBC_PRIVATE

	#NO_APP
	pushl	$__fortify_fail
	addl	$-871286, (%esp)        # imm = 0xFFF2B48A
	retl
	#APP
.resume_30:
	#NO_APP
	popfl
	adcl	$0, .L__profc_update+4
	movl	%eax, .L__profc_update
	.loc	1 105 13                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:105:13
	movl	count, %eax
	pushfl
	calll	.chain_31
	jmp	.resume_31
	#APP
.chain_31:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver strfromf, strfromf@GLIBC_2.25

	#NO_APP
	pushl	$strfromf
	addl	$-19790, (%esp)         # imm = 0xB2B2
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __libc_allocate_rtsig_private, __libc_allocate_rtsig_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_allocate_rtsig_private
	addl	$75338, (%esp)          # imm = 0x1264A
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver mlock, mlock@GLIBC_2.0

	#NO_APP
	pushl	$mlock
	addl	$-774022, (%esp)        # imm = 0xFFF4307A
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __wcscpy_chk, __wcscpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcscpy_chk
	addl	$-1030097, (%esp)       # imm = 0xFFF0482F
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver catclose, catclose@GLIBC_2.0

	#NO_APP
	pushl	$catclose
	addl	$89226, (%esp)          # imm = 0x15C8A
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __libc_allocate_rtsig, __libc_allocate_rtsig@GLIBC_2.1

	#NO_APP
	pushl	$__libc_allocate_rtsig
	addl	$453891, (%esp)         # imm = 0x6ED03
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver getrpcport, getrpcport@GLIBC_2.0

	#NO_APP
	pushl	$getrpcport
	addl	$-1123905, (%esp)       # imm = 0xFFEED9BF
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver mcheck, mcheck@GLIBC_2.0

	#NO_APP
	pushl	$mcheck
	addl	$-263718, (%esp)        # imm = 0xFFFBF9DA
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver closelog, closelog@GLIBC_2.0

	#NO_APP
	pushl	$closelog
	addl	$-937665, (%esp)        # imm = 0xFFF1B13F
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __realpath_chk, __realpath_chk@GLIBC_2.4

	#NO_APP
	pushl	$__realpath_chk
	addl	$-864278, (%esp)        # imm = 0xFFF2CFEA
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver xdr_int64_t, xdr_int64_t@GLIBC_2.1.1

	#NO_APP
	pushl	$xdr_int64_t
	addl	$-1027946, (%esp)       # imm = 0xFFF05096
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver getaliasent_r, getaliasent_r@GLIBC_2.0

	#NO_APP
	pushl	$getaliasent_r
	addl	$-1256465, (%esp)       # imm = 0xFFECD3EF
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver getgrent_r, getgrent_r@GLIBC_2.0

	#NO_APP
	pushl	$getgrent_r
	addl	$-1073146, (%esp)       # imm = 0xFFEFA006
	pushl	$-44
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver getprotobynumber_r, getprotobynumber_r@GLIBC_2.0

	#NO_APP
	pushl	$getprotobynumber_r
	addl	$-1265101, (%esp)       # imm = 0xFFECB233
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver endusershell, endusershell@GLIBC_2.0

	#NO_APP
	pushl	$endusershell
	addl	$-934289, (%esp)        # imm = 0xFFF1BE6F
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __isoc99_vsscanf, __isoc99_vsscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vsscanf
	addl	$-159098, (%esp)        # imm = 0xFFFD9286
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver clntudp_create, clntudp_create@GLIBC_2.0

	#NO_APP
	pushl	$clntudp_create
	addl	$-1166049, (%esp)       # imm = 0xFFEE351F
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __asprintf_chk, __asprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__asprintf_chk
	addl	$-869142, (%esp)        # imm = 0xFFF2BCEA
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-758998, (%esp)        # imm = 0xFFF46B2A
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver xdr_getcredres, xdr_getcredres@GLIBC_2.1

	#NO_APP
	pushl	$xdr_getcredres
	addl	$-1120387, (%esp)       # imm = 0xFFEEE77D
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __underflow, __underflow@GLIBC_2.0

	#NO_APP
	pushl	$__underflow
	addl	$-223350, (%esp)        # imm = 0xFFFC978A
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver __strfmon_l, __strfmon_l@GLIBC_2.1

	#NO_APP
	pushl	$__strfmon_l
	addl	$316004, (%esp)         # imm = 0x4D264
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver posix_spawn, posix_spawn@GLIBC_2.15

	#NO_APP
	pushl	$posix_spawn
	addl	$-845203, (%esp)        # imm = 0xFFF31A6D
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver fgetws_unlocked, fgetws_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$fgetws_unlocked
	addl	$-172278, (%esp)        # imm = 0xFFFD5F0A
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver xdr_getcredres, xdr_getcredres@GLIBC_2.1

	#NO_APP
	pushl	$xdr_getcredres
	addl	$-1120387, (%esp)       # imm = 0xFFEEE77D
	calll	opaquePredicate
	jne	.chain_31
	#APP
.symver gethostbyname_r, gethostbyname_r@GLIBC_2.1.2

	#NO_APP
	pushl	$gethostbyname_r
	addl	$-876278, (%esp)        # imm = 0xFFF2A10A
	retl
	#APP
.resume_31:
	#NO_APP
	popfl
	.loc	1 106 22                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:106:22
	movl	$0, 4(%esp)
	movl	$16, (%esp)
	calll	malloc
	pushfl
	calll	.chain_32
	jmp	.resume_32
	#APP
.chain_32:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __libc_dlvsym, __libc_dlvsym@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlvsym
	addl	$-1120334, (%esp)       # imm = 0xFFEEE7B2
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver posix_spawn_file_actions_adddup2, posix_spawn_file_actions_adddup2@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawn_file_actions_adddup2
	addl	$-699558, (%esp)        # imm = 0xFFF5535A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver _IO_ferror, _IO_ferror@GLIBC_2.0

	#NO_APP
	pushl	$_IO_ferror
	addl	$-193910, (%esp)        # imm = 0xFFFD0A8A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver getwchar_unlocked, getwchar_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$getwchar_unlocked
	addl	$-336961, (%esp)        # imm = 0xFFFADBBF
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __wcstold_internal, __wcstold_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstold_internal
	addl	$-394134, (%esp)        # imm = 0xFFF9FC6A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __libc_current_sigrtmax_private, __libc_current_sigrtmax_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_current_sigrtmax_private
	addl	$453955, (%esp)         # imm = 0x6ED43
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __strcoll_l, __strcoll_l@GLIBC_2.1

	#NO_APP
	pushl	$__strcoll_l
	addl	$-453217, (%esp)        # imm = 0xFFF9159F
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver fts_close, fts_close@GLIBC_2.0

	#NO_APP
	pushl	$fts_close
	addl	$-734326, (%esp)        # imm = 0xFFF4CB8A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver xdr_double, xdr_double@GLIBC_2.0

	#NO_APP
	pushl	$xdr_double
	addl	$-1133185, (%esp)       # imm = 0xFFEEB57F
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver _IO_init_wmarker, _IO_init_wmarker@GLIBC_2.2

	#NO_APP
	pushl	$_IO_init_wmarker
	addl	$-180806, (%esp)        # imm = 0xFFFD3DBA
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __poll, __poll@GLIBC_2.1

	#NO_APP
	pushl	$__poll
	addl	$-751578, (%esp)        # imm = 0xFFF48826
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __sigaddset, __sigaddset@GLIBC_2.0

	#NO_APP
	pushl	$__sigaddset
	addl	$-1218529, (%esp)       # imm = 0xFFED681F
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver posix_spawnattr_getsigmask, posix_spawnattr_getsigmask@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_getsigmask
	addl	$-711050, (%esp)        # imm = 0xFFF52676
	pushl	$-32
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver wcstok, wcstok@GLIBC_2.0

	#NO_APP
	pushl	$wcstok
	addl	$-561565, (%esp)        # imm = 0xFFF76E63
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver getpmsg, getpmsg@GLIBC_2.1

	#NO_APP
	pushl	$getpmsg
	addl	$-1190257, (%esp)       # imm = 0xFFEDD68F
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver endhostent, endhostent@GLIBC_2.0

	#NO_APP
	pushl	$endhostent
	addl	$-886314, (%esp)        # imm = 0xFFF279D6
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __isoc99_fwscanf, __isoc99_fwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_fwscanf
	addl	$-613569, (%esp)        # imm = 0xFFF6A33F
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver printf_size, printf_size@GLIBC_2.1

	#NO_APP
	pushl	$printf_size
	addl	$-69110, (%esp)         # imm = 0xFFFEF20A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __copy_grp, __copy_grp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__copy_grp
	addl	$-535430, (%esp)        # imm = 0xFFF7D47A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver _IO_str_seekoff, _IO_str_seekoff@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_seekoff
	addl	$-378307, (%esp)        # imm = 0xFFFA3A3D
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver unlinkat, unlinkat@GLIBC_2.4

	#NO_APP
	pushl	$unlinkat
	addl	$-720630, (%esp)        # imm = 0xFFF5010A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver __internal_getnetgrent_r, __internal_getnetgrent_r@GLIBC_PRIVATE

	#NO_APP
	pushl	$__internal_getnetgrent_r
	addl	$-590668, (%esp)        # imm = 0xFFF6FCB4
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver ppoll, ppoll@GLIBC_2.4

	#NO_APP
	pushl	$ppoll
	addl	$-888211, (%esp)        # imm = 0xFFF2726D
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver catclose, catclose@GLIBC_2.0

	#NO_APP
	pushl	$catclose
	addl	$89226, (%esp)          # imm = 0x15C8A
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver pwritev2, pwritev2@GLIBC_2.26

	#NO_APP
	pushl	$pwritev2
	addl	$-900883, (%esp)        # imm = 0xFFF240ED
	calll	opaquePredicate
	jne	.chain_32
	#APP
.symver inet6_opt_init, inet6_opt_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_init
	addl	$-918630, (%esp)        # imm = 0xFFF1FB9A
	retl
	#APP
.resume_32:
	#NO_APP
	popfl
	.loc	1 107 24                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:107:24
	movl	$0, 4(%esp)
	movl	$200, (%esp)
	calll	malloc
	.loc	1 107 3 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:107:3
	movl	-8(%ebp), %ecx
	pushfl
	calll	.chain_33
	jmp	.resume_33
	#APP
.chain_33:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-147458, (%esp)        # imm = 0xFFFDBFFE
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver pmap_unset, pmap_unset@GLIBC_2.0

	#NO_APP
	pushl	$pmap_unset
	addl	$-580861, (%esp)        # imm = 0xFFF72303
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver getentropy, getentropy@GLIBC_2.25

	#NO_APP
	pushl	$getentropy
	addl	$52326, (%esp)          # imm = 0xCC66
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver getspent, getspent@GLIBC_2.0

	#NO_APP
	pushl	$getspent
	addl	$-815446, (%esp)        # imm = 0xFFF38EAA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver cfsetospeed, cfsetospeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetospeed
	addl	$-758394, (%esp)        # imm = 0xFFF46D86
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver setgroups, setgroups@GLIBC_2.0

	#NO_APP
	pushl	$setgroups
	addl	$-704045, (%esp)        # imm = 0xFFF541D3
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver ntp_gettime, ntp_gettime@GLIBC_2.1

	#NO_APP
	pushl	$ntp_gettime
	addl	$-528842, (%esp)        # imm = 0xFFF7EE36
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver getdirentries64, getdirentries64@GLIBC_2.2

	#NO_APP
	pushl	$getdirentries64
	addl	$-527142, (%esp)        # imm = 0xFFF7F4DA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __clock_gettime, __clock_gettime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_gettime
	addl	$-856246, (%esp)        # imm = 0xFFF2EF4A
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __ctype_b_loc, __ctype_b_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_b_loc
	addl	$-32643, (%esp)         # imm = 0x807D
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __sbrk, __sbrk@GLIBC_2.0

	#NO_APP
	pushl	$__sbrk
	addl	$-753494, (%esp)        # imm = 0xFFF480AA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver isalnum, isalnum@GLIBC_2.0

	#NO_APP
	pushl	$isalnum
	addl	$426372, (%esp)         # imm = 0x68184
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$-70531, (%esp)         # imm = 0xFFFEEC7D
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __finitel, __finitel@GLIBC_2.0

	#NO_APP
	pushl	$__finitel
	addl	$86506, (%esp)          # imm = 0x151EA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_svc_pollfd
	addl	$-1151155, (%esp)       # imm = 0xFFEE6F4D
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-152494, (%esp)        # imm = 0xFFFDAC52
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver setutxent, setutxent@GLIBC_2.1

	#NO_APP
	pushl	$setutxent
	addl	$-1036966, (%esp)       # imm = 0xFFF02D5A
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver pthread_condattr_destroy, pthread_condattr_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_condattr_destroy
	addl	$-851542, (%esp)        # imm = 0xFFF301AA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __isspace_l, __isspace_l@GLIBC_2.1

	#NO_APP
	pushl	$__isspace_l
	addl	$-52513, (%esp)         # imm = 0xFFFF32DF
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver svcerr_progvers, svcerr_progvers@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_progvers
	addl	$-1008278, (%esp)       # imm = 0xFFF09D6A
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __setmntent, __setmntent@GLIBC_2.2

	#NO_APP
	pushl	$__setmntent
	addl	$-384701, (%esp)        # imm = 0xFFFA2143
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-114385, (%esp)        # imm = 0xFFFE412F
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-793926, (%esp)        # imm = 0xFFF3E2BA
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver _IO_getline, _IO_getline@GLIBC_2.0

	#NO_APP
	pushl	$_IO_getline
	addl	$-329617, (%esp)        # imm = 0xFFFAF86F
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver wscanf, wscanf@GLIBC_2.2

	#NO_APP
	pushl	$wscanf
	addl	$-175542, (%esp)        # imm = 0xFFFD524A
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver clntraw_create, clntraw_create@GLIBC_2.0

	#NO_APP
	pushl	$clntraw_create
	addl	$-966058, (%esp)        # imm = 0xFFF14256
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver inet6_rth_space, inet6_rth_space@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_space
	addl	$-1085057, (%esp)       # imm = 0xFFEF717F
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver wcstombs, wcstombs@GLIBC_2.0

	#NO_APP
	pushl	$wcstombs
	addl	$56662, (%esp)          # imm = 0xDD56
	pushl	$-20
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver getmsg, getmsg@GLIBC_2.1

	#NO_APP
	pushl	$getmsg
	addl	$-1199325, (%esp)       # imm = 0xFFEDB323
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __rpc_thread_svc_fdset, __rpc_thread_svc_fdset@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_svc_fdset
	addl	$-1171249, (%esp)       # imm = 0xFFEE20CF
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-805498, (%esp)        # imm = 0xFFF3B586
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver __strncpy_gg, __strncpy_gg@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncpy_gg
	addl	$-469009, (%esp)        # imm = 0xFFF8D7EF
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver sgetsgent, sgetsgent@GLIBC_2.10

	#NO_APP
	pushl	$sgetsgent
	addl	$-822374, (%esp)        # imm = 0xFFF3739A
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver getipv4sourcefilter, getipv4sourcefilter@GLIBC_2.3.4

	#NO_APP
	pushl	$getipv4sourcefilter
	addl	$289747, (%esp)         # imm = 0x46BD3
	calll	opaquePredicate
	jne	.chain_33
	#APP
.symver setbuf, setbuf@GLIBC_2.0

	#NO_APP
	pushl	$setbuf
	addl	$-197334, (%esp)        # imm = 0xFFFCFD2A
	retl
	#APP
.resume_33:
	#NO_APP
	popfl
	.loc	1 109 9 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:109:9
	movl	%eax, (%esp)
	leal	.L.str.13, %eax
	movl	%eax, 4(%esp)
	calll	fopen
	pushfl
	calll	.chain_34
	jmp	.resume_34
	#APP
.chain_34:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver eventfd_read, eventfd_read@GLIBC_2.7

	#NO_APP
	pushl	$eventfd_read
	addl	$-874734, (%esp)        # imm = 0xFFF2A712
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver gethostent, gethostent@GLIBC_2.0

	#NO_APP
	pushl	$gethostent
	addl	$-877478, (%esp)        # imm = 0xFFF29C5A
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver setlocale, setlocale@GLIBC_2.0

	#NO_APP
	pushl	$setlocale
	addl	$127962, (%esp)         # imm = 0x1F3DA
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver perror, perror@GLIBC_2.0

	#NO_APP
	pushl	$perror
	addl	$-310753, (%esp)        # imm = 0xFFFB421F
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver signalfd, signalfd@GLIBC_2.7

	#NO_APP
	pushl	$signalfd
	addl	$-794214, (%esp)        # imm = 0xFFF3E19A
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver _IO_printf, _IO_printf@GLIBC_2.0

	#NO_APP
	pushl	$_IO_printf
	addl	$306579, (%esp)         # imm = 0x4AD93
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver inet6_rth_init, inet6_rth_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_init
	addl	$-1085137, (%esp)       # imm = 0xFFEF712F
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver __strpbrk_g, __strpbrk_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strpbrk_g
	addl	$-304358, (%esp)        # imm = 0xFFFB5B1A
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver pthread_attr_setinheritsched, pthread_attr_setinheritsched@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_setinheritsched
	addl	$-1015921, (%esp)       # imm = 0xFFF07F8F
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver key_gendes, key_gendes@GLIBC_2.1

	#NO_APP
	pushl	$key_gendes
	addl	$-1003094, (%esp)       # imm = 0xFFF0B1AA
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver putwc, putwc@GLIBC_2.2

	#NO_APP
	pushl	$putwc
	addl	$-182586, (%esp)        # imm = 0xFFFD36C6
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver fscanf, fscanf@GLIBC_2.0

	#NO_APP
	pushl	$fscanf
	addl	$-310385, (%esp)        # imm = 0xFFFB438F
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver getnetbyname_r, getnetbyname_r@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname_r
	addl	$-1099114, (%esp)       # imm = 0xFFEF3A96
	pushl	$-40
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver xdr_void, xdr_void@GLIBC_2.0

	#NO_APP
	pushl	$xdr_void
	addl	$-1190941, (%esp)       # imm = 0xFFEDD3E3
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver __isnanl, __isnanl@GLIBC_2.0

	#NO_APP
	pushl	$__isnanl
	addl	$-78545, (%esp)         # imm = 0xFFFECD2F
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver __getpgid, __getpgid@GLIBC_2.0

	#NO_APP
	pushl	$__getpgid
	addl	$-555386, (%esp)        # imm = 0xFFF78686
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver inet6_opt_find, inet6_opt_find@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_find
	addl	$-1084737, (%esp)       # imm = 0xFFEF72BF
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-816390, (%esp)        # imm = 0xFFF38AFA
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver __lxstat, __lxstat@GLIBC_2.0

	#NO_APP
	pushl	$__lxstat
	addl	$-707174, (%esp)        # imm = 0xFFF5359A
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver __nss_configure_lookup, __nss_configure_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_configure_lookup
	addl	$-1091747, (%esp)       # imm = 0xFFEF575D
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver __libc_alloc_buffer_copy_string, __libc_alloc_buffer_copy_string@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_alloc_buffer_copy_string
	addl	$-269942, (%esp)        # imm = 0xFFFBE18A
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver preadv, preadv@GLIBC_2.10

	#NO_APP
	pushl	$preadv
	addl	$-442476, (%esp)        # imm = 0xFFF93F94
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver cfsetospeed, cfsetospeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetospeed
	addl	$-894835, (%esp)        # imm = 0xFFF2588D
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver svcfd_create, svcfd_create@GLIBC_2.0

	#NO_APP
	pushl	$svcfd_create
	addl	$-1011846, (%esp)       # imm = 0xFFF08F7A
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver getmntent, getmntent@GLIBC_2.0

	#NO_APP
	pushl	$getmntent
	addl	$-907667, (%esp)        # imm = 0xFFF2266D
	calll	opaquePredicate
	jne	.chain_34
	#APP
.symver vfprintf, vfprintf@GLIBC_2.0

	#NO_APP
	pushl	$vfprintf
	addl	$-37094, (%esp)         # imm = 0xFFFF6F1A
	retl
	#APP
.resume_34:
	#NO_APP
	popfl
.Ltmp25:
	.loc	1 110 11                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:110:11
	cmpl	$0, -16(%ebp)
.Ltmp26:
	.loc	1 110 7 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:110:7
	jne	.LBB3_2
# %bb.1:
	movl	.L__profc_update+8, %eax
	pushfl
	calll	.chain_35
	jmp	.resume_35
	#APP
.chain_35:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver __munmap, __munmap@GLIBC_PRIVATE

	#NO_APP
	pushl	$__munmap
	addl	$-395021, (%esp)        # imm = 0xFFF9F8F3
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver xdrrec_create, xdrrec_create@GLIBC_2.0

	#NO_APP
	pushl	$xdrrec_create
	addl	$-978602, (%esp)        # imm = 0xFFF11156
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver __snprintf, __snprintf@GLIBC_PRIVATE

	#NO_APP
	pushl	$__snprintf
	addl	$-72054, (%esp)         # imm = 0xFFFEE68A
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$156870, (%esp)         # imm = 0x264C6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver envz_entry, envz_entry@GLIBC_2.0

	#NO_APP
	pushl	$envz_entry
	addl	$-461133, (%esp)        # imm = 0xFFF8F6B3
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver __libc_init_first, __libc_init_first@GLIBC_2.0

	#NO_APP
	pushl	$__libc_init_first
	addl	$167690, (%esp)         # imm = 0x28F0A
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver _IO_iter_next, _IO_iter_next@GLIBC_2.2

	#NO_APP
	pushl	$_IO_iter_next
	addl	$-239690, (%esp)        # imm = 0xFFFC57B6
	calll	opaquePredicate
	jne	.chain_35
	#APP
.symver __read_chk, __read_chk@GLIBC_2.4

	#NO_APP
	pushl	$__read_chk
	addl	$-863526, (%esp)        # imm = 0xFFF2D2DA
	retl
	#APP
.resume_35:
	#NO_APP
	popfl
	adcl	$0, .L__profc_update+12
	movl	%eax, .L__profc_update+8
.Ltmp27:
	.loc	1 111 5 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:111:5
	leal	.L.str.6, %eax
	movl	%eax, (%esp)
	calll	perror
	jmp	.LBB3_15
.LBB3_2:
.Ltmp28:
	.loc	1 113 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:113:5
	jmp	.LBB3_3
.LBB3_3:                                # =>This Inner Loop Header: Depth=1
	cmpl	$0, -20(%ebp)
	je	.LBB3_5
# %bb.4:                                #   in Loop: Header=BB3_3 Depth=1
	movl	.L__profc_update+16, %eax
	pushfl
	calll	.chain_36
	jmp	.resume_36
	#APP
.chain_36:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver sigvec, sigvec@GLIBC_2.0

	#NO_APP
	pushl	$sigvec
	addl	$456067, (%esp)         # imm = 0x6F583
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver __syslog_chk, __syslog_chk@GLIBC_2.4

	#NO_APP
	pushl	$__syslog_chk
	addl	$-780698, (%esp)        # imm = 0xFFF41666
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-279782, (%esp)        # imm = 0xFFFBBB1A
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver getpwent_r, getpwent_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getpwent_r
	addl	$-547498, (%esp)        # imm = 0xFFF7A556
	pushl	$1
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver inet6_rth_reverse, inet6_rth_reverse@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_reverse
	addl	$-1094557, (%esp)       # imm = 0xFFEF4C63
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-483606, (%esp)        # imm = 0xFFF89EEA
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver __cmsg_nxthdr, __cmsg_nxthdr@GLIBC_2.0

	#NO_APP
	pushl	$__cmsg_nxthdr
	addl	$-810586, (%esp)        # imm = 0xFFF3A1A6
	calll	opaquePredicate
	jne	.chain_36
	#APP
.symver __readlink_chk, __readlink_chk@GLIBC_2.4

	#NO_APP
	pushl	$__readlink_chk
	addl	$-863942, (%esp)        # imm = 0xFFF2D13A
	retl
	#APP
.resume_36:
	#NO_APP
	popfl
	adcl	$0, .L__profc_update+20
	movl	%eax, .L__profc_update+16
	pushfl
	calll	.chain_37
	jmp	.resume_37
	#APP
.chain_37:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver ctermid, ctermid@GLIBC_2.0

	#NO_APP
	pushl	$ctermid
	addl	$-24386, (%esp)         # imm = 0xA0BE
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver munlockall, munlockall@GLIBC_2.0

	#NO_APP
	pushl	$munlockall
	addl	$-395597, (%esp)        # imm = 0xFFF9F6B3
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver iconv_open, iconv_open@GLIBC_2.1

	#NO_APP
	pushl	$iconv_open
	addl	$156566, (%esp)         # imm = 0x26396
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver __isprint_l, __isprint_l@GLIBC_2.1

	#NO_APP
	pushl	$__isprint_l
	addl	$112778, (%esp)         # imm = 0x1B88A
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver ispunct, ispunct@GLIBC_2.0

	#NO_APP
	pushl	$ispunct
	addl	$105638, (%esp)         # imm = 0x19CA6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$-83, (%esp)
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver __wcsncpy_chk, __wcsncpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncpy_chk
	addl	$-865462, (%esp)        # imm = 0xFFF2CB4A
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver _IO_file_open, _IO_file_open@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_open
	addl	$-226074, (%esp)        # imm = 0xFFFC8CE6
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver strfromf128, strfromf128@GLIBC_2.26

	#NO_APP
	pushl	$strfromf128
	addl	$-7446, (%esp)          # imm = 0xE2EA
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver __fgetws_chk, __fgetws_chk@GLIBC_2.4

	#NO_APP
	pushl	$__fgetws_chk
	addl	$-867654, (%esp)        # imm = 0xFFF2C2BA
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver __getmntent_r, __getmntent_r@GLIBC_2.2

	#NO_APP
	pushl	$__getmntent_r
	addl	$-908371, (%esp)        # imm = 0xFFF223AD
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver chflags, chflags@GLIBC_2.0

	#NO_APP
	pushl	$chflags
	addl	$-766502, (%esp)        # imm = 0xFFF44DDA
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver fanotify_init, fanotify_init@GLIBC_2.13

	#NO_APP
	pushl	$fanotify_init
	addl	$-486428, (%esp)        # imm = 0xFFF893E4
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver __isoc99_vfwscanf, __isoc99_vfwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfwscanf
	addl	$-593539, (%esp)        # imm = 0xFFF6F17D
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver _IO_default_doallocate, _IO_default_doallocate@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_doallocate
	addl	$-226022, (%esp)        # imm = 0xFFFC8D1A
	calll	opaquePredicate
	jne	.chain_37
	#APP
.symver __memset_ccn_by4, __memset_ccn_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__memset_ccn_by4
	addl	$-448355, (%esp)        # imm = 0xFFF9289D
	retl
	#APP
.resume_37:
	#NO_APP
	popfl
.Ltmp29:
	.loc	1 116 43                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:116:43
	movl	-16(%ebp), %ecx
	.loc	1 116 7 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:116:7
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$4, 4(%esp)
	calll	fread
	.loc	1 117 20 is_stmt 1      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:117:20
	movl	-8(%ebp), %eax
	.loc	1 117 26 is_stmt 0      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:117:26
	movl	(%eax), %eax
	.loc	1 117 7                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:117:7
	leal	.L.str.3, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
	pushfl
	calll	.chain_38
	jmp	.resume_38
	#APP
.chain_38:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver rand_r, rand_r@GLIBC_2.0

	#NO_APP
	pushl	$rand_r
	addl	$62302, (%esp)          # imm = 0xF35E
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$112122, (%esp)         # imm = 0x1B5FA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __libc_free, __libc_free@GLIBC_2.0

	#NO_APP
	pushl	$__libc_free
	addl	$-256038, (%esp)        # imm = 0xFFFC17DA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __open64_nocancel, __open64_nocancel@GLIBC_PRIVATE

	#NO_APP
	pushl	$__open64_nocancel
	addl	$-748998, (%esp)        # imm = 0xFFF4923A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver svcudp_enablecache, svcudp_enablecache@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_enablecache
	addl	$-1179681, (%esp)       # imm = 0xFFEDFFDF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver rexec, rexec@GLIBC_2.0

	#NO_APP
	pushl	$rexec
	addl	$-898886, (%esp)        # imm = 0xFFF248BA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-582749, (%esp)        # imm = 0xFFF71BA3
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver _nss_files_parse_spent, _nss_files_parse_spent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_spent
	addl	$-984641, (%esp)        # imm = 0xFFF0F9BF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __ttyname_r_chk, __ttyname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ttyname_r_chk
	addl	$-868390, (%esp)        # imm = 0xFFF2BFDA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver quick_exit, quick_exit@GLIBC_2.10

	#NO_APP
	pushl	$quick_exit
	addl	$-1218769, (%esp)       # imm = 0xFFED672F
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver llseek, llseek@GLIBC_2.0

	#NO_APP
	pushl	$llseek
	addl	$-711862, (%esp)        # imm = 0xFFF5234A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __strsep_g, __strsep_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strsep_g
	addl	$-286618, (%esp)        # imm = 0xFFFBA066
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver bindresvport, bindresvport@GLIBC_2.0

	#NO_APP
	pushl	$bindresvport
	addl	$-1121281, (%esp)       # imm = 0xFFEEE3FF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-927194, (%esp)        # imm = 0xFFF1DA26
	pushl	$-60
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver xdr_uint32_t, xdr_uint32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint32_t
	addl	$-1194573, (%esp)       # imm = 0xFFEDC5B3
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver _IO_fgets, _IO_fgets@GLIBC_2.0

	#NO_APP
	pushl	$_IO_fgets
	addl	$-324465, (%esp)        # imm = 0xFFFB0C8F
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver mkstemps, mkstemps@GLIBC_2.11

	#NO_APP
	pushl	$mkstemps
	addl	$-769082, (%esp)        # imm = 0xFFF443C6
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver svcudp_bufcreate, svcudp_bufcreate@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_bufcreate
	addl	$-1178897, (%esp)       # imm = 0xFFEE02EF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver _IO_file_doallocate, _IO_file_doallocate@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_doallocate
	addl	$-156854, (%esp)        # imm = 0xFFFD9B4A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __strchrnul_c, __strchrnul_c@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_c
	addl	$7588, (%esp)           # imm = 0x1DA4
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver posix_madvise, posix_madvise@GLIBC_2.2

	#NO_APP
	pushl	$posix_madvise
	addl	$-702998, (%esp)        # imm = 0xFFF545EA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __rpc_thread_createerr, __rpc_thread_createerr@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_createerr
	addl	$-1006802, (%esp)       # imm = 0xFFF0A32E
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __libc_scratch_buffer_set_array_size, __libc_scratch_buffer_set_array_size@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_scratch_buffer_set_array_size
	addl	$-268294, (%esp)        # imm = 0xFFFBE7FA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver svc_register, svc_register@GLIBC_2.0

	#NO_APP
	pushl	$svc_register
	addl	$-1007030, (%esp)       # imm = 0xFFF0A24A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver clnt_spcreateerror, clnt_spcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_spcreateerror
	addl	$-994102, (%esp)        # imm = 0xFFF0D4CA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver localeconv, localeconv@GLIBC_2.0

	#NO_APP
	pushl	$localeconv
	addl	$-45921, (%esp)         # imm = 0xFFFF4C9F
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver catopen, catopen@GLIBC_2.0

	#NO_APP
	pushl	$catopen
	addl	$89914, (%esp)          # imm = 0x15F3A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver posix_spawnattr_setpgroup, posix_spawnattr_setpgroup@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setpgroup
	addl	$-321693, (%esp)        # imm = 0xFFFB1763
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-958497, (%esp)        # imm = 0xFFF15FDF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver grantpt, grantpt@GLIBC_2.1

	#NO_APP
	pushl	$grantpt
	addl	$-1035126, (%esp)       # imm = 0xFFF0348A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver getrlimit64, getrlimit64@GLIBC_2.1

	#NO_APP
	pushl	$getrlimit64
	addl	$-1253521, (%esp)       # imm = 0xFFECDF6F
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __nss_group_lookup, __nss_group_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_group_lookup
	addl	$-1091558, (%esp)       # imm = 0xFFEF581A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __iswupper_l, __iswupper_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswupper_l
	addl	$-822730, (%esp)        # imm = 0xFFF37236
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __gconv_get_alias_db, __gconv_get_alias_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_alias_db
	addl	$-3537, (%esp)          # imm = 0xF22F
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __explicit_bzero_chk, __explicit_bzero_chk@GLIBC_2.25

	#NO_APP
	pushl	$__explicit_bzero_chk
	addl	$-879482, (%esp)        # imm = 0xFFF29486
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __umoddi3, __umoddi3@GLIBC_2.0

	#NO_APP
	pushl	$__umoddi3
	addl	$-8973, (%esp)          # imm = 0xDCF3
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-1254177, (%esp)       # imm = 0xFFECDCDF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver setlocale, setlocale@GLIBC_2.0

	#NO_APP
	pushl	$setlocale
	addl	$119510, (%esp)         # imm = 0x1D2D6
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver lldiv, lldiv@GLIBC_2.0

	#NO_APP
	pushl	$lldiv
	addl	$-99377, (%esp)         # imm = 0xFFFE7BCF
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __libc_pthread_init, __libc_pthread_init@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_pthread_init
	addl	$-853974, (%esp)        # imm = 0xFFF2F82A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver _IO_sprintf, _IO_sprintf@GLIBC_2.0

	#NO_APP
	pushl	$_IO_sprintf
	addl	$-72134, (%esp)         # imm = 0xFFFEE63A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __open_nocancel, __open_nocancel@GLIBC_PRIVATE

	#NO_APP
	pushl	$__open_nocancel
	addl	$-893763, (%esp)        # imm = 0xFFF25CBD
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver pwritev64v2, pwritev64v2@GLIBC_2.26

	#NO_APP
	pushl	$pwritev64v2
	addl	$-756438, (%esp)        # imm = 0xFFF4752A
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver acct, acct@GLIBC_2.0

	#NO_APP
	pushl	$acct
	addl	$-447036, (%esp)        # imm = 0xFFF92DC4
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver inet6_option_alloc, inet6_option_alloc@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_alloc
	addl	$-1061395, (%esp)       # imm = 0xFFEFCDED
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver printf, printf@GLIBC_2.0

	#NO_APP
	pushl	$printf
	addl	$-71974, (%esp)         # imm = 0xFFFEE6DA
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-376675, (%esp)        # imm = 0xFFFA409D
	calll	opaquePredicate
	jne	.chain_38
	#APP
.symver __endmntent, __endmntent@GLIBC_2.2

	#NO_APP
	pushl	$__endmntent
	addl	$-763398, (%esp)        # imm = 0xFFF459FA
	retl
	#APP
.resume_38:
	#NO_APP
	popfl
	.loc	1 118 33 is_stmt 1      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:118:33
	movl	-16(%ebp), %ecx
	.loc	1 118 7 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:118:7
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$200, 4(%esp)
	calll	fread
	.loc	1 119 23 is_stmt 1      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:119:23
	movl	-8(%ebp), %eax
	.loc	1 119 29 is_stmt 0      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:119:29
	movl	4(%eax), %eax
	.loc	1 119 7                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:119:7
	leal	.L.str.12, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
	pushfl
	calll	.chain_39
	jmp	.resume_39
	#APP
.chain_39:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __pipe, __pipe@GLIBC_2.0

	#NO_APP
	pushl	$__pipe
	addl	$-795118, (%esp)        # imm = 0xFFF3DE12
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver xdr_uint16_t, xdr_uint16_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint16_t
	addl	$-1020502, (%esp)       # imm = 0xFFF06DAA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver xdr_long, xdr_long@GLIBC_2.0

	#NO_APP
	pushl	$xdr_long
	addl	$-1016646, (%esp)       # imm = 0xFFF07CBA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver fopencookie, fopencookie@GLIBC_2.2

	#NO_APP
	pushl	$fopencookie
	addl	$-326065, (%esp)        # imm = 0xFFFB064F
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __strverscmp, __strverscmp@GLIBC_2.1.1

	#NO_APP
	pushl	$__strverscmp
	addl	$-270566, (%esp)        # imm = 0xFFFBDF1A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver xdr_hyper, xdr_hyper@GLIBC_2.1.1

	#NO_APP
	pushl	$xdr_hyper
	addl	$-638445, (%esp)        # imm = 0xFFF64213
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __resolv_context_get, __resolv_context_get@GLIBC_PRIVATE

	#NO_APP
	pushl	$__resolv_context_get
	addl	$-1104417, (%esp)       # imm = 0xFFEF25DF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __strncat_chk, __strncat_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__strncat_chk
	addl	$-859718, (%esp)        # imm = 0xFFF2E1BA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __libc_dlopen_mode, __libc_dlopen_mode@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlopen_mode
	addl	$-1204817, (%esp)       # imm = 0xFFED9DAF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver getpwnam, getpwnam@GLIBC_2.0

	#NO_APP
	pushl	$getpwnam
	addl	$-537926, (%esp)        # imm = 0xFFF7CABA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver xdrrec_skiprecord, xdrrec_skiprecord@GLIBC_2.0

	#NO_APP
	pushl	$xdrrec_skiprecord
	addl	$-978986, (%esp)        # imm = 0xFFF10FD6
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __libc_dynarray_at_failure, __libc_dynarray_at_failure@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dynarray_at_failure
	addl	$-433681, (%esp)        # imm = 0xFFF961EF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver isxdigit, isxdigit@GLIBC_2.0

	#NO_APP
	pushl	$isxdigit
	addl	$105398, (%esp)         # imm = 0x19BB6
	pushl	$-44
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __moddi3, __moddi3@GLIBC_2.0

	#NO_APP
	pushl	$__moddi3
	addl	$-8781, (%esp)          # imm = 0xDDB3
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __strspn_g, __strspn_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_g
	addl	$-469473, (%esp)        # imm = 0xFFF8D61F
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver _IO_sscanf, _IO_sscanf@GLIBC_2.0

	#NO_APP
	pushl	$_IO_sscanf
	addl	$-153818, (%esp)        # imm = 0xFFFDA726
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$-53041, (%esp)         # imm = 0xFFFF30CF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver fwrite_unlocked, fwrite_unlocked@GLIBC_2.1

	#NO_APP
	pushl	$fwrite_unlocked
	addl	$-208326, (%esp)        # imm = 0xFFFCD23A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver recvmmsg, recvmmsg@GLIBC_2.12

	#NO_APP
	pushl	$recvmmsg
	addl	$-801638, (%esp)        # imm = 0xFFF3C49A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver qsort, qsort@GLIBC_2.0

	#NO_APP
	pushl	$qsort
	addl	$-74163, (%esp)         # imm = 0xFFFEDE4D
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver unlinkat, unlinkat@GLIBC_2.4

	#NO_APP
	pushl	$unlinkat
	addl	$-720630, (%esp)        # imm = 0xFFF5010A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver pkey_mprotect, pkey_mprotect@GLIBC_2.27

	#NO_APP
	pushl	$pkey_mprotect
	addl	$-484460, (%esp)        # imm = 0xFFF89B94
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver gethostbyname_r, gethostbyname_r@GLIBC_2.1.2

	#NO_APP
	pushl	$gethostbyname_r
	addl	$-1021171, (%esp)       # imm = 0xFFF06B0D
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver getxattr, getxattr@GLIBC_2.3

	#NO_APP
	pushl	$getxattr
	addl	$-787094, (%esp)        # imm = 0xFFF3FD6A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-628499, (%esp)        # imm = 0xFFF668ED
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver clnt_pcreateerror, clnt_pcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_pcreateerror
	addl	$-994374, (%esp)        # imm = 0xFFF0D3BA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver cfgetispeed, cfgetispeed@GLIBC_2.0

	#NO_APP
	pushl	$cfgetispeed
	addl	$-371325, (%esp)        # imm = 0xFFFA5583
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver preadv64v2, preadv64v2@GLIBC_2.26

	#NO_APP
	pushl	$preadv64v2
	addl	$-763962, (%esp)        # imm = 0xFFF457C6
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver getpass, getpass@GLIBC_2.0

	#NO_APP
	pushl	$getpass
	addl	$-769302, (%esp)        # imm = 0xFFF442EA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver _IO_free_backup_area, _IO_free_backup_area@GLIBC_2.0

	#NO_APP
	pushl	$_IO_free_backup_area
	addl	$-231514, (%esp)        # imm = 0xFFFC77A6
	pushl	$-1
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver xdr_u_long, xdr_u_long@GLIBC_2.0

	#NO_APP
	pushl	$xdr_u_long
	addl	$-1191165, (%esp)       # imm = 0xFFEDD303
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver cbc_crypt, cbc_crypt@GLIBC_2.1

	#NO_APP
	pushl	$cbc_crypt
	addl	$-971846, (%esp)        # imm = 0xFFF12BBA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-983146, (%esp)        # imm = 0xFFF0FF96
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver psiginfo, psiginfo@GLIBC_2.10

	#NO_APP
	pushl	$psiginfo
	addl	$-150822, (%esp)        # imm = 0xFFFDB2DA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-751874, (%esp)        # imm = 0xFFF486FE
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver _IO_wfile_seekoff, _IO_wfile_seekoff@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_seekoff
	addl	$-185734, (%esp)        # imm = 0xFFFD2A7A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver xdr_int, xdr_int@GLIBC_2.0

	#NO_APP
	pushl	$xdr_int
	addl	$-1016774, (%esp)       # imm = 0xFFF07C3A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_svc_pollfd
	addl	$-1006262, (%esp)       # imm = 0xFFF0A54A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver pthread_attr_getinheritsched, pthread_attr_getinheritsched@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_getinheritsched
	addl	$-1015809, (%esp)       # imm = 0xFFF07FFF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-856406, (%esp)        # imm = 0xFFF2EEAA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-414781, (%esp)        # imm = 0xFFF9ABC3
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver _IO_file_setbuf, _IO_file_setbuf@GLIBC_2.1

	#NO_APP
	pushl	$_IO_file_setbuf
	addl	$-374721, (%esp)        # imm = 0xFFFA483F
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver svcerr_noprog, svcerr_noprog@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_noprog
	addl	$-1008166, (%esp)       # imm = 0xFFF09DDA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver explicit_bzero, explicit_bzero@GLIBC_2.25

	#NO_APP
	pushl	$explicit_bzero
	addl	$-470321, (%esp)        # imm = 0xFFF8D2CF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __iswctype, __iswctype@GLIBC_2.0

	#NO_APP
	pushl	$__iswctype
	addl	$-812262, (%esp)        # imm = 0xFFF39B1A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver svcerr_progvers, svcerr_progvers@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_progvers
	addl	$-1016730, (%esp)       # imm = 0xFFF07C66
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __libc_fcntl64, __libc_fcntl64@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_fcntl64
	addl	$-878705, (%esp)        # imm = 0xFFF2978F
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver getspnam_r, getspnam_r@GLIBC_2.0

	#NO_APP
	pushl	$getspnam_r
	addl	$-1097658, (%esp)       # imm = 0xFFEF4046
	pushl	$-84
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver strtoimax, strtoimax@GLIBC_2.1

	#NO_APP
	pushl	$strtoimax
	addl	$-173261, (%esp)        # imm = 0xFFFD5B33
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __vsnprintf_chk, __vsnprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsnprintf_chk
	addl	$-1025825, (%esp)       # imm = 0xFFF058DF
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __strtod_l, __strtod_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtod_l
	addl	$17574, (%esp)          # imm = 0x44A6
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __ppoll_chk, __ppoll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__ppoll_chk
	addl	$-1036129, (%esp)       # imm = 0xFFF0309F
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __strncat_chk, __strncat_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__strncat_chk
	addl	$-859718, (%esp)        # imm = 0xFFF2E1BA
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver thrd_yield, thrd_yield@GLIBC_2.28

	#NO_APP
	pushl	$thrd_yield
	addl	$-855462, (%esp)        # imm = 0xFFF2F25A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver sighold, sighold@GLIBC_2.1

	#NO_APP
	pushl	$sighold
	addl	$-70147, (%esp)         # imm = 0xFFFEEDFD
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __nss_hosts_lookup, __nss_hosts_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_hosts_lookup
	addl	$-1091558, (%esp)       # imm = 0xFFEF581A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$133796, (%esp)         # imm = 0x20AA4
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __res_init, __res_init@GLIBC_2.2

	#NO_APP
	pushl	$__res_init
	addl	$-1082579, (%esp)       # imm = 0xFFEF7B2D
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver getgrent, getgrent@GLIBC_2.0

	#NO_APP
	pushl	$getgrent
	addl	$-529862, (%esp)        # imm = 0xFFF7EA3A
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver _IO_sungetc, _IO_sungetc@GLIBC_2.0

	#NO_APP
	pushl	$_IO_sungetc
	addl	$-372307, (%esp)        # imm = 0xFFFA51AD
	calll	opaquePredicate
	jne	.chain_39
	#APP
.symver __isoc99_vscanf, __isoc99_vscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vscanf
	addl	$-149846, (%esp)        # imm = 0xFFFDB6AA
	retl
	#APP
.resume_39:
	#NO_APP
	popfl
.Ltmp30:
	.loc	1 113 5 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:113:5
	jmp	.LBB3_3
.LBB3_5:
	.loc	1 122 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:122:5
	leal	.L.str.14, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 123 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:123:5
	leal	.L.str.3, %eax
	movl	%eax, (%esp)
	leal	-28(%ebp), %eax
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
	pushfl
	calll	.chain_40
	jmp	.resume_40
	#APP
.chain_40:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-794562, (%esp)        # imm = 0xFFF3E03E
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver _IO_fsetpos, _IO_fsetpos@GLIBC_2.2

	#NO_APP
	pushl	$_IO_fsetpos
	addl	$-161814, (%esp)        # imm = 0xFFFD87EA
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver __uname, __uname@GLIBC_PRIVATE

	#NO_APP
	pushl	$__uname
	addl	$-542038, (%esp)        # imm = 0xFFF7BAAA
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver tr_break, tr_break@GLIBC_2.0

	#NO_APP
	pushl	$tr_break
	addl	$-265942, (%esp)        # imm = 0xFFFBF12A
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver qfcvt, qfcvt@GLIBC_2.0

	#NO_APP
	pushl	$qfcvt
	addl	$-940993, (%esp)        # imm = 0xFFF1A43F
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver nice, nice@GLIBC_2.0

	#NO_APP
	pushl	$nice
	addl	$-753190, (%esp)        # imm = 0xFFF481DA
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver fputws, fputws@GLIBC_2.2

	#NO_APP
	pushl	$fputws
	addl	$206083, (%esp)         # imm = 0x32503
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver __libc_siglongjmp, __libc_siglongjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_siglongjmp
	addl	$-84817, (%esp)         # imm = 0xFFFEB4AF
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver strftime, strftime@GLIBC_2.0

	#NO_APP
	pushl	$strftime
	addl	$-498502, (%esp)        # imm = 0xFFF864BA
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver __nss_database_lookup, __nss_database_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_database_lookup
	addl	$-1111009, (%esp)       # imm = 0xFFEF0C1F
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver atof, atof@GLIBC_2.0

	#NO_APP
	pushl	$atof
	addl	$73994, (%esp)          # imm = 0x1210A
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver thrd_sleep, thrd_sleep@GLIBC_2.28

	#NO_APP
	pushl	$thrd_sleep
	addl	$-863754, (%esp)        # imm = 0xFFF2D1F6
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-1084561, (%esp)       # imm = 0xFFEF736F
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver ppoll, ppoll@GLIBC_2.4

	#NO_APP
	pushl	$ppoll
	addl	$-751770, (%esp)        # imm = 0xFFF48766
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver wcsncmp, wcsncmp@GLIBC_2.0

	#NO_APP
	pushl	$wcsncmp
	addl	$-560781, (%esp)        # imm = 0xFFF77173
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver fgetws_unlocked, fgetws_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$fgetws_unlocked
	addl	$-337441, (%esp)        # imm = 0xFFFAD9DF
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver _IO_padn, _IO_padn@GLIBC_2.0

	#NO_APP
	pushl	$_IO_padn
	addl	$-173354, (%esp)        # imm = 0xFFFD5AD6
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver llistxattr, llistxattr@GLIBC_2.3

	#NO_APP
	pushl	$llistxattr
	addl	$-952401, (%esp)        # imm = 0xFFF177AF
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-146822, (%esp)        # imm = 0xFFFDC27A
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver __sprintf_chk, __sprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__sprintf_chk
	addl	$-860230, (%esp)        # imm = 0xFFF2DFBA
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver getpmsg, getpmsg@GLIBC_2.1

	#NO_APP
	pushl	$getpmsg
	addl	$-1169987, (%esp)       # imm = 0xFFEE25BD
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver _IO_default_finish, _IO_default_finish@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_finish
	addl	$-226998, (%esp)        # imm = 0xFFFC894A
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver atof, atof@GLIBC_2.0

	#NO_APP
	pushl	$atof
	addl	$385716, (%esp)         # imm = 0x5E2B4
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver _IO_link_in, _IO_link_in@GLIBC_2.0

	#NO_APP
	pushl	$_IO_link_in
	addl	$-366547, (%esp)        # imm = 0xFFFA682D
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-751238, (%esp)        # imm = 0xFFF4897A
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver rresvport, rresvport@GLIBC_2.0

	#NO_APP
	pushl	$rresvport
	addl	$-1041139, (%esp)       # imm = 0xFFF01D0D
	calll	opaquePredicate
	jne	.chain_40
	#APP
.symver realpath, realpath@GLIBC_2.3

	#NO_APP
	pushl	$realpath
	addl	$11658, (%esp)          # imm = 0x2D8A
	retl
	#APP
.resume_40:
	#NO_APP
	popfl
	.loc	1 124 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:124:5
	movl	%eax, (%esp)
	movl	$0, 12(%esp)
	movl	$0, 8(%esp)
	movl	$0, 4(%esp)
	calll	fseek
	.loc	1 125 11                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:125:11
	movl	count, %eax
	pushfl
	calll	.chain_41
	jmp	.resume_41
	#APP
.chain_41:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver thrd_sleep, thrd_sleep@GLIBC_2.28

	#NO_APP
	pushl	$thrd_sleep
	addl	$-935662, (%esp)        # imm = 0xFFF1B912
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __res_iclose, __res_iclose@GLIBC_PRIVATE

	#NO_APP
	pushl	$__res_iclose
	addl	$-937974, (%esp)        # imm = 0xFFF1B00A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __isupper_l, __isupper_l@GLIBC_2.1

	#NO_APP
	pushl	$__isupper_l
	addl	$112586, (%esp)         # imm = 0x1B7CA
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver wordfree, wordfree@GLIBC_2.1

	#NO_APP
	pushl	$wordfree
	addl	$-860113, (%esp)        # imm = 0xFFF2E02F
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver _IO_seekpos, _IO_seekpos@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekpos
	addl	$-168182, (%esp)        # imm = 0xFFFD6F0A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver semget, semget@GLIBC_2.0

	#NO_APP
	pushl	$semget
	addl	$-424573, (%esp)        # imm = 0xFFF98583
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __vdprintf_chk, __vdprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__vdprintf_chk
	addl	$-1034913, (%esp)       # imm = 0xFFF0355F
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __fork, __fork@GLIBC_2.0

	#NO_APP
	pushl	$__fork
	addl	$-543478, (%esp)        # imm = 0xFFF7B50A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __sched_cpufree, __sched_cpufree@GLIBC_2.7

	#NO_APP
	pushl	$__sched_cpufree
	addl	$-868657, (%esp)        # imm = 0xFFF2BECF
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver user2netname, user2netname@GLIBC_2.1

	#NO_APP
	pushl	$user2netname
	addl	$-1003702, (%esp)       # imm = 0xFFF0AF4A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver _IO_default_pbackfail, _IO_default_pbackfail@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_pbackfail
	addl	$-238922, (%esp)        # imm = 0xFFFC5AB6
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __nss_hostname_digits_dots, __nss_hostname_digits_dots@GLIBC_2.2.2

	#NO_APP
	pushl	$__nss_hostname_digits_dots
	addl	$-1116993, (%esp)       # imm = 0xFFEEF4BF
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __finitel, __finitel@GLIBC_2.0

	#NO_APP
	pushl	$__finitel
	addl	$78054, (%esp)          # imm = 0x130E6
	pushl	$-44
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __mempcpy_by4, __mempcpy_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__mempcpy_by4
	addl	$-478029, (%esp)        # imm = 0xFFF8B4B3
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __netlink_assert_response, __netlink_assert_response@GLIBC_PRIVATE

	#NO_APP
	pushl	$__netlink_assert_response
	addl	$-1091361, (%esp)       # imm = 0xFFEF58DF
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver xdr_pmap, xdr_pmap@GLIBC_2.0

	#NO_APP
	pushl	$xdr_pmap
	addl	$-968586, (%esp)        # imm = 0xFFF13876
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __libc_pthread_init, __libc_pthread_init@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_pthread_init
	addl	$-1019137, (%esp)       # imm = 0xFFF072FF
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver dirfd, dirfd@GLIBC_2.0

	#NO_APP
	pushl	$dirfd
	addl	$-523910, (%esp)        # imm = 0xFFF8017A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __strchr_g, __strchr_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchr_g
	addl	$-304086, (%esp)        # imm = 0xFFFB5C2A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver svcerr_progvers, svcerr_progvers@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_progvers
	addl	$-1153171, (%esp)       # imm = 0xFFEE676D
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __overflow, __overflow@GLIBC_2.0

	#NO_APP
	pushl	$__overflow
	addl	$-223190, (%esp)        # imm = 0xFFFC982A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver preadv64, preadv64@GLIBC_2.10

	#NO_APP
	pushl	$preadv64
	addl	$-442700, (%esp)        # imm = 0xFFF93EB4
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver isalnum, isalnum@GLIBC_2.0

	#NO_APP
	pushl	$isalnum
	addl	$-30243, (%esp)         # imm = 0x89DD
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver perror, perror@GLIBC_2.0

	#NO_APP
	pushl	$perror
	addl	$-145590, (%esp)        # imm = 0xFFFDC74A
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver splice, splice@GLIBC_2.5

	#NO_APP
	pushl	$splice
	addl	$-940483, (%esp)        # imm = 0xFFF1A63D
	calll	opaquePredicate
	jne	.chain_41
	#APP
.symver __read_chk, __read_chk@GLIBC_2.4

	#NO_APP
	pushl	$__read_chk
	addl	$-863526, (%esp)        # imm = 0xFFF2D2DA
	retl
	#APP
.resume_41:
	#NO_APP
	popfl
.LBB3_6:                                # =>This Inner Loop Header: Depth=1
	.loc	1 126 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:126:5
	cmpl	$0, -20(%ebp)
	je	.LBB3_10
# %bb.7:                                #   in Loop: Header=BB3_6 Depth=1
	movl	.L__profc_update+24, %eax
	pushfl
	calll	.chain_42
	jmp	.resume_42
	#APP
.chain_42:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver __nss_lookup, __nss_lookup@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_lookup
	addl	$-569421, (%esp)        # imm = 0xFFF74FB3
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver _IO_link_in, _IO_link_in@GLIBC_2.0

	#NO_APP
	pushl	$_IO_link_in
	addl	$-230106, (%esp)        # imm = 0xFFFC7D26
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver getpwent, getpwent@GLIBC_2.0

	#NO_APP
	pushl	$getpwent
	addl	$-537734, (%esp)        # imm = 0xFFF7CB7A
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver getwchar, getwchar@GLIBC_2.2

	#NO_APP
	pushl	$getwchar
	addl	$-179994, (%esp)        # imm = 0xFFFD40E6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver __libc_scratch_buffer_grow_preserve, __libc_scratch_buffer_grow_preserve@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_scratch_buffer_grow_preserve
	addl	$-442413, (%esp)        # imm = 0xFFF93FD3
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver _IO_fclose, _IO_fclose@GLIBC_2.0

	#NO_APP
	pushl	$_IO_fclose
	addl	$-1054662, (%esp)       # imm = 0xFFEFE83A
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver timegm, timegm@GLIBC_2.0

	#NO_APP
	pushl	$timegm
	addl	$-492218, (%esp)        # imm = 0xFFF87D46
	calll	opaquePredicate
	jne	.chain_42
	#APP
.symver labs, labs@GLIBC_2.0

	#NO_APP
	pushl	$labs
	addl	$66058, (%esp)          # imm = 0x1020A
	retl
	#APP
.resume_42:
	#NO_APP
	popfl
	adcl	$0, .L__profc_update+28
	movl	%eax, .L__profc_update+24
	pushfl
	calll	.chain_43
	jmp	.resume_43
	#APP
.chain_43:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __twalk, __twalk@GLIBC_PRIVATE

	#NO_APP
	pushl	$__twalk
	addl	$-781954, (%esp)        # imm = 0xFFF4117E
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver munlockall, munlockall@GLIBC_2.0

	#NO_APP
	pushl	$munlockall
	addl	$-395597, (%esp)        # imm = 0xFFF9F6B3
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver getaliasbyname, getaliasbyname@GLIBC_2.0

	#NO_APP
	pushl	$getaliasbyname
	addl	$-913754, (%esp)        # imm = 0xFFF20EA6
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __snprintf_chk, __snprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__snprintf_chk
	addl	$-860582, (%esp)        # imm = 0xFFF2DE5A
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver timerfd_gettime, timerfd_gettime@GLIBC_2.8

	#NO_APP
	pushl	$timerfd_gettime
	addl	$-806554, (%esp)        # imm = 0xFFF3B166
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __libc_scratch_buffer_grow, __libc_scratch_buffer_grow@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_scratch_buffer_grow
	addl	$-442253, (%esp)        # imm = 0xFFF94073
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver _dl_mcount_wrapper, _dl_mcount_wrapper@GLIBC_2.1

	#NO_APP
	pushl	$_dl_mcount_wrapper
	addl	$-1038934, (%esp)       # imm = 0xFFF025AA
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver posix_fallocate, posix_fallocate@GLIBC_2.2

	#NO_APP
	pushl	$posix_fallocate
	addl	$-752186, (%esp)        # imm = 0xFFF485C6
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver _IO_peekc_locked, _IO_peekc_locked@GLIBC_2.0

	#NO_APP
	pushl	$_IO_peekc_locked
	addl	$-207958, (%esp)        # imm = 0xFFFCD3AA
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver fts64_set, fts64_set@GLIBC_2.23

	#NO_APP
	pushl	$fts64_set
	addl	$-742662, (%esp)        # imm = 0xFFF4AAFA
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __strsep_g, __strsep_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strsep_g
	addl	$-423059, (%esp)        # imm = 0xFFF98B6D
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __snprintf_chk, __snprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__snprintf_chk
	addl	$-860582, (%esp)        # imm = 0xFFF2DE5A
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver execv, execv@GLIBC_2.0

	#NO_APP
	pushl	$execv
	addl	$-232700, (%esp)        # imm = 0xFFFC7304
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __isoc99_vfscanf, __isoc99_vfscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfscanf
	addl	$-295235, (%esp)        # imm = 0xFFFB7EBD
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __strchr_g, __strchr_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchr_g
	addl	$-304086, (%esp)        # imm = 0xFFFB5C2A
	calll	opaquePredicate
	jne	.chain_43
	#APP
.symver __cyg_profile_func_enter, __cyg_profile_func_enter@GLIBC_2.2

	#NO_APP
	pushl	$__cyg_profile_func_enter
	addl	$-1003875, (%esp)       # imm = 0xFFF0AE9D
	retl
	#APP
.resume_43:
	#NO_APP
	popfl
.Ltmp31:
	.loc	1 128 43                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:128:43
	movl	-16(%ebp), %ecx
	.loc	1 128 7 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:128:7
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$4, 4(%esp)
	calll	fread
.Ltmp32:
	.loc	1 129 11 is_stmt 1      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:129:11
	movl	-28(%ebp), %eax
	.loc	1 129 17 is_stmt 0      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:129:17
	movl	-8(%ebp), %ecx
	.loc	1 129 14                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:129:14
	cmpl	(%ecx), %eax
.Ltmp33:
	.loc	1 129 11                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:129:11
	jne	.LBB3_9
# %bb.8:
	movl	.L__profc_update+32, %eax
	pushfl
	calll	.chain_44
	jmp	.resume_44
	#APP
.chain_44:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver __mempcpy_by4, __mempcpy_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__mempcpy_by4
	addl	$74867, (%esp)          # imm = 0x12473
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver _toupper, _toupper@GLIBC_2.0

	#NO_APP
	pushl	$_toupper
	addl	$104966, (%esp)         # imm = 0x19A06
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver __syslog_chk, __syslog_chk@GLIBC_2.4

	#NO_APP
	pushl	$__syslog_chk
	addl	$-772246, (%esp)        # imm = 0xFFF4376A
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver putenv, putenv@GLIBC_2.0

	#NO_APP
	pushl	$putenv
	addl	$61974, (%esp)          # imm = 0xF216
	pushl	$1
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver __sched_get_priority_min, __sched_get_priority_min@GLIBC_2.0

	#NO_APP
	pushl	$__sched_get_priority_min
	addl	$-839229, (%esp)        # imm = 0xFFF331C3
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver wprintf, wprintf@GLIBC_2.2

	#NO_APP
	pushl	$wprintf
	addl	$-175462, (%esp)        # imm = 0xFFFD529A
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver tcsetpgrp, tcsetpgrp@GLIBC_2.0

	#NO_APP
	pushl	$tcsetpgrp
	addl	$-759354, (%esp)        # imm = 0xFFF469C6
	calll	opaquePredicate
	jne	.chain_44
	#APP
.symver __fgets_unlocked_chk, __fgets_unlocked_chk@GLIBC_2.4

	#NO_APP
	pushl	$__fgets_unlocked_chk
	addl	$-863334, (%esp)        # imm = 0xFFF2D39A
	retl
	#APP
.resume_44:
	#NO_APP
	popfl
	adcl	$0, .L__profc_update+36
	movl	%eax, .L__profc_update+32
.Ltmp34:
	.loc	1 130 9 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:130:9
	movl	$.L.str.15, (%esp)
	calll	printf
	leal	-232(%ebp), %esi
	.loc	1 131 9                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:131:9
	movl	%esi, 4(%esp)
	movl	$.L.str.9, (%esp)
	calll	__isoc99_scanf
	.loc	1 132 34                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:132:34
	movl	-16(%ebp), %eax
	.loc	1 132 13 is_stmt 0      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:132:13
	movl	%eax, 20(%esp)
	movl	%esi, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$200, 4(%esp)
	calll	fwrite
	.loc	1 132 11                # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:132:11
	movl	%eax, -24(%ebp)
	.loc	1 133 9 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:133:9
	jmp	.LBB3_11
.Ltmp35:
.LBB3_9:                                #   in Loop: Header=BB3_6 Depth=1
	.loc	1 0 9 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:0:9
	pushfl
	calll	.chain_45
	jmp	.resume_45
	#APP
.chain_45:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver _IO_fdopen, _IO_fdopen@GLIBC_2.0

	#NO_APP
	pushl	$_IO_fdopen
	addl	$-1054834, (%esp)       # imm = 0xFFEFE78E
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver wctomb, wctomb@GLIBC_2.0

	#NO_APP
	pushl	$wctomb
	addl	$65018, (%esp)          # imm = 0xFDFA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver ecvt, ecvt@GLIBC_2.0

	#NO_APP
	pushl	$ecvt
	addl	$-774406, (%esp)        # imm = 0xFFF42EFA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __libc_dlsym, __libc_dlsym@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlsym
	addl	$-1039798, (%esp)       # imm = 0xFFF0224A
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __strerror_r, __strerror_r@GLIBC_2.0

	#NO_APP
	pushl	$__strerror_r
	addl	$-436513, (%esp)        # imm = 0xFFF956DF
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver fallocate, fallocate@GLIBC_2.10

	#NO_APP
	pushl	$fallocate
	addl	$-748038, (%esp)        # imm = 0xFFF495FA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __memset_gcn_by4, __memset_gcn_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__memset_gcn_by4
	addl	$75027, (%esp)          # imm = 0x12513
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver sockatmark, sockatmark@GLIBC_2.2.4

	#NO_APP
	pushl	$sockatmark
	addl	$-966561, (%esp)        # imm = 0xFFF1405F
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver getpwent, getpwent@GLIBC_2.0

	#NO_APP
	pushl	$getpwent
	addl	$-537734, (%esp)        # imm = 0xFFF7CB7A
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver vfprintf, vfprintf@GLIBC_2.0

	#NO_APP
	pushl	$vfprintf
	addl	$-202257, (%esp)        # imm = 0xFFFCE9EF
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver posix_spawnattr_setsigmask, posix_spawnattr_setsigmask@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setsigmask
	addl	$-702790, (%esp)        # imm = 0xFFF546BA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver pclose, pclose@GLIBC_2.0

	#NO_APP
	pushl	$pclose
	addl	$-1065082, (%esp)       # imm = 0xFFEFBF86
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver _dl_catch_exception, _dl_catch_exception@GLIBC_PRIVATE

	#NO_APP
	pushl	$_dl_catch_exception
	addl	$-1207265, (%esp)       # imm = 0xFFED941F
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$66166, (%esp)          # imm = 0x10276
	pushl	$-60
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __nss_lookup, __nss_lookup@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_lookup
	addl	$-1122317, (%esp)       # imm = 0xFFEEDFF3
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __strncmp_g, __strncmp_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncmp_g
	addl	$-469201, (%esp)        # imm = 0xFFF8D72F
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver _IO_switch_to_wbackup_area, _IO_switch_to_wbackup_area@GLIBC_2.2

	#NO_APP
	pushl	$_IO_switch_to_wbackup_area
	addl	$-185626, (%esp)        # imm = 0xFFFD2AE6
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver tcsendbreak, tcsendbreak@GLIBC_2.0

	#NO_APP
	pushl	$tcsendbreak
	addl	$-916465, (%esp)        # imm = 0xFFF2040F
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __isoc99_fwscanf, __isoc99_fwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_fwscanf
	addl	$-448406, (%esp)        # imm = 0xFFF9286A
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __isalpha_l, __isalpha_l@GLIBC_2.1

	#NO_APP
	pushl	$__isalpha_l
	addl	$424820, (%esp)         # imm = 0x67B74
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver eventfd_read, eventfd_read@GLIBC_2.7

	#NO_APP
	pushl	$eventfd_read
	addl	$-794374, (%esp)        # imm = 0xFFF3E0FA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver lrand48_r, lrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$lrand48_r
	addl	$61214, (%esp)          # imm = 0xEF1E
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver timerfd_settime, timerfd_settime@GLIBC_2.8

	#NO_APP
	pushl	$timerfd_settime
	addl	$-419501, (%esp)        # imm = 0xFFF99953
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver pthread_condattr_destroy, pthread_condattr_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_condattr_destroy
	addl	$-859994, (%esp)        # imm = 0xFFF2E0A6
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver stty, stty@GLIBC_2.0

	#NO_APP
	pushl	$stty
	addl	$-761382, (%esp)        # imm = 0xFFF461DA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver setipv4sourcefilter, setipv4sourcefilter@GLIBC_2.3.4

	#NO_APP
	pushl	$setipv4sourcefilter
	addl	$-925802, (%esp)        # imm = 0xFFF1DF96
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __finite, __finite@GLIBC_2.0

	#NO_APP
	pushl	$__finite
	addl	$-88829, (%esp)         # imm = 0xFFFEA503
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __strcpy_chk, __strcpy_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__strcpy_chk
	addl	$-859606, (%esp)        # imm = 0xFFF2E22A
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __sched_cpufree, __sched_cpufree@GLIBC_2.7

	#NO_APP
	pushl	$__sched_cpufree
	addl	$-711946, (%esp)        # imm = 0xFFF522F6
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver fts64_set, fts64_set@GLIBC_2.23

	#NO_APP
	pushl	$fts64_set
	addl	$-742662, (%esp)        # imm = 0xFFF4AAFA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver timerfd_create, timerfd_create@GLIBC_2.8

	#NO_APP
	pushl	$timerfd_create
	addl	$-798006, (%esp)        # imm = 0xFFF3D2CA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver fgetws_unlocked, fgetws_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$fgetws_unlocked
	addl	$-317171, (%esp)        # imm = 0xFFFB290D
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver _IO_seekoff, _IO_seekoff@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekoff
	addl	$-167686, (%esp)        # imm = 0xFFFD70FA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __profile_frequency, __profile_frequency@GLIBC_2.0

	#NO_APP
	pushl	$__profile_frequency
	addl	$-497628, (%esp)        # imm = 0xFFF86824
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver __cxa_atexit, __cxa_atexit@GLIBC_2.1.3

	#NO_APP
	pushl	$__cxa_atexit
	addl	$-77699, (%esp)         # imm = 0xFFFED07D
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver setservent, setservent@GLIBC_2.0

	#NO_APP
	pushl	$setservent
	addl	$-887830, (%esp)        # imm = 0xFFF273EA
	calll	opaquePredicate
	jne	.chain_45
	#APP
.symver tcgetpgrp, tcgetpgrp@GLIBC_2.0

	#NO_APP
	pushl	$tcgetpgrp
	addl	$-895715, (%esp)        # imm = 0xFFF2551D
	retl
	#APP
.resume_45:
	#NO_APP
	popfl
	.loc	1 135 33 is_stmt 1      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:135:33
	movl	-16(%ebp), %ecx
	.loc	1 135 7 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:135:7
	movl	%ecx, 20(%esp)
	movl	%eax, (%esp)
	movl	$0, 16(%esp)
	movl	$1, 12(%esp)
	movl	$0, 8(%esp)
	movl	$200, 4(%esp)
	calll	fread
	.loc	1 136 10 is_stmt 1      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:136:10
	movl	-20(%ebp), %eax
	pushfl
	calll	.chain_46
	jmp	.resume_46
	#APP
.chain_46:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __strtold_nan, __strtold_nan@GLIBC_PRIVATE

	#NO_APP
	pushl	$__strtold_nan
	addl	$13306, (%esp)          # imm = 0x33FA
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __read_chk, __read_chk@GLIBC_2.4

	#NO_APP
	pushl	$__read_chk
	addl	$-1028689, (%esp)       # imm = 0xFFF04DAF
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __ctype_init, __ctype_init@GLIBC_PRIVATE

	#NO_APP
	pushl	$__ctype_init
	addl	$112058, (%esp)         # imm = 0x1B5BA
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __sigismember, __sigismember@GLIBC_2.0

	#NO_APP
	pushl	$__sigismember
	addl	$-674733, (%esp)        # imm = 0xFFF5B453
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver authdes_create, authdes_create@GLIBC_2.1

	#NO_APP
	pushl	$authdes_create
	addl	$-1155745, (%esp)       # imm = 0xFFEE5D5F
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __libc_scratch_buffer_grow, __libc_scratch_buffer_grow@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_scratch_buffer_grow
	addl	$-267910, (%esp)        # imm = 0xFFFBE97A
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __register_frame_info, __register_frame_info@GLIBC_2.0

	#NO_APP
	pushl	$__register_frame_info
	addl	$-1212721, (%esp)       # imm = 0xFFED7ECF
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver klogctl, klogctl@GLIBC_2.0

	#NO_APP
	pushl	$klogctl
	addl	$-805914, (%esp)        # imm = 0xFFF3B3E6
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver wcwidth, wcwidth@GLIBC_2.0

	#NO_APP
	pushl	$wcwidth
	addl	$-600257, (%esp)        # imm = 0xFFF6D73F
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver mrand48, mrand48@GLIBC_2.0

	#NO_APP
	pushl	$mrand48
	addl	$54038, (%esp)          # imm = 0xD316
	pushl	$-1
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __strrchr_c, __strrchr_c@GLIBC_2.1.1

	#NO_APP
	pushl	$__strrchr_c
	addl	$-478557, (%esp)        # imm = 0xFFF8B2A3
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver _IO_seekmark, _IO_seekmark@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekmark
	addl	$-395361, (%esp)        # imm = 0xFFF9F79F
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver __fwriting, __fwriting@GLIBC_2.2

	#NO_APP
	pushl	$__fwriting
	addl	$-210378, (%esp)        # imm = 0xFFFCCA36
	calll	opaquePredicate
	jne	.chain_46
	#APP
.symver fsetpos64, fsetpos64@GLIBC_2.1

	#NO_APP
	pushl	$fsetpos64
	addl	$-1223169, (%esp)       # imm = 0xFFED55FF
	retl
	#APP
.resume_46:
	#NO_APP
	popfl
	movl	%eax, -20(%ebp)
.Ltmp36:
	.loc	1 126 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:126:5
	jmp	.LBB3_6
.LBB3_10:                               # %.loopexit
.Ltmp37:
	.loc	1 138 9                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:138:9
	jmp	.LBB3_11
.LBB3_11:
	.loc	1 138 11 is_stmt 0      # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:138:11
	cmpl	$1, -24(%ebp)
.Ltmp38:
	.loc	1 138 9                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:138:9
	jne	.LBB3_13
# %bb.12:
	movl	.L__profc_update+40, %eax
	pushfl
	calll	.chain_47
	jmp	.resume_47
	#APP
.chain_47:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver __fxstatat64, __fxstatat64@GLIBC_2.4

	#NO_APP
	pushl	$__fxstatat64
	addl	$-330093, (%esp)        # imm = 0xFFFAF693
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver swscanf, swscanf@GLIBC_2.2

	#NO_APP
	pushl	$swscanf
	addl	$-184778, (%esp)        # imm = 0xFFFD2E36
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-797046, (%esp)        # imm = 0xFFF3D68A
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver __vsprintf_chk, __vsprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsprintf_chk
	addl	$-868794, (%esp)        # imm = 0xFFF2BE46
	pushl	$1
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver errx, errx@GLIBC_2.0

	#NO_APP
	pushl	$errx
	addl	$-957341, (%esp)        # imm = 0xFFF16463
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver xdr_opaque_auth, xdr_opaque_auth@GLIBC_2.0

	#NO_APP
	pushl	$xdr_opaque_auth
	addl	$-963254, (%esp)        # imm = 0xFFF14D4A
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver pwritev, pwritev@GLIBC_2.10

	#NO_APP
	pushl	$pwritev
	addl	$-763082, (%esp)        # imm = 0xFFF45B36
	calll	opaquePredicate
	jne	.chain_47
	#APP
.symver msgctl, msgctl@GLIBC_2.0

	#NO_APP
	pushl	$msgctl
	addl	$-1088758, (%esp)       # imm = 0xFFEF630A
	retl
	#APP
.resume_47:
	#NO_APP
	popfl
	adcl	$0, .L__profc_update+44
	movl	%eax, .L__profc_update+40
.Ltmp39:
	.loc	1 139 7 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:139:7
	leal	.L.str.16, %eax
	movl	%eax, (%esp)
	calll	printf
	jmp	.LBB3_14
.LBB3_13:
	.loc	1 141 7                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:141:7
	leal	.L.str.17, %eax
	movl	%eax, (%esp)
	calll	printf
.Ltmp40:
.LBB3_14:
	.loc	1 0 7 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:0:7
	pushfl
	calll	.chain_48
	jmp	.resume_48
	#APP
.chain_48:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver xdr_u_char, xdr_u_char@GLIBC_2.0

	#NO_APP
	pushl	$xdr_u_char
	addl	$-1018626, (%esp)       # imm = 0xFFF074FE
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver semctl, semctl@GLIBC_2.2

	#NO_APP
	pushl	$semctl
	addl	$-424685, (%esp)        # imm = 0xFFF98513
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver __sbrk, __sbrk@GLIBC_2.0

	#NO_APP
	pushl	$__sbrk
	addl	$-761946, (%esp)        # imm = 0xFFF45FA6
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver __memset_ccn_by4, __memset_ccn_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__memset_ccn_by4
	addl	$-303462, (%esp)        # imm = 0xFFFB5E9A
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver cfsetispeed, cfsetispeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetispeed
	addl	$-758506, (%esp)        # imm = 0xFFF46D16
	pushl	$-80
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver tee, tee@GLIBC_2.5

	#NO_APP
	pushl	$tee
	addl	$-969517, (%esp)        # imm = 0xFFF134D3
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver perror, perror@GLIBC_2.0

	#NO_APP
	pushl	$perror
	addl	$-145590, (%esp)        # imm = 0xFFFDC74A
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-781178, (%esp)        # imm = 0xFFF41486
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver __isoc99_vwscanf, __isoc99_vwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vwscanf
	addl	$-448150, (%esp)        # imm = 0xFFF9296A
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver __wunderflow, __wunderflow@GLIBC_2.2

	#NO_APP
	pushl	$__wunderflow
	addl	$-179670, (%esp)        # imm = 0xFFFD422A
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver ntp_gettimex, ntp_gettimex@GLIBC_2.12

	#NO_APP
	pushl	$ntp_gettimex
	addl	$-665395, (%esp)        # imm = 0xFFF5D8CD
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver __open_catalog, __open_catalog@GLIBC_PRIVATE

	#NO_APP
	pushl	$__open_catalog
	addl	$89066, (%esp)          # imm = 0x15BEA
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver wcsxfrm, wcsxfrm@GLIBC_2.0

	#NO_APP
	pushl	$wcsxfrm
	addl	$-123292, (%esp)        # imm = 0xFFFE1E64
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver posix_spawn, posix_spawn@GLIBC_2.15

	#NO_APP
	pushl	$posix_spawn
	addl	$-845203, (%esp)        # imm = 0xFFF31A6D
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver fputwc, fputwc@GLIBC_2.2

	#NO_APP
	pushl	$fputwc
	addl	$-170774, (%esp)        # imm = 0xFFFD64EA
	calll	opaquePredicate
	jne	.chain_48
	#APP
.symver copy_file_range, copy_file_range@GLIBC_2.27

	#NO_APP
	pushl	$copy_file_range
	addl	$-891091, (%esp)        # imm = 0xFFF2672D
	retl
	#APP
.resume_48:
	#NO_APP
	popfl
	.loc	1 142 5 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:142:5
	movl	%eax, (%esp)
	calll	fclose
	pushfl
	calll	.chain_49
	jmp	.resume_49
	#APP
.chain_49:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver getsgent, getsgent@GLIBC_2.10

	#NO_APP
	pushl	$getsgent
	addl	$-822450, (%esp)        # imm = 0xFFF3734E
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __iswctype_l, __iswctype_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswctype_l
	addl	$-815030, (%esp)        # imm = 0xFFF3904A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __vswprintf_chk, __vswprintf_chk@GLIBC_2.4

	#NO_APP
	pushl	$__vswprintf_chk
	addl	$-866326, (%esp)        # imm = 0xFFF2C7EA
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver capget, capget@GLIBC_2.1

	#NO_APP
	pushl	$capget
	addl	$-796854, (%esp)        # imm = 0xFFF3D74A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver setegid, setegid@GLIBC_2.0

	#NO_APP
	pushl	$setegid
	addl	$-922593, (%esp)        # imm = 0xFFF1EC1F
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver wcstod, wcstod@GLIBC_2.0

	#NO_APP
	pushl	$wcstod
	addl	$-394054, (%esp)        # imm = 0xFFF9FCBA
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __uname, __uname@GLIBC_PRIVATE

	#NO_APP
	pushl	$__uname
	addl	$-163485, (%esp)        # imm = 0xFFFD8163
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver nice, nice@GLIBC_2.0

	#NO_APP
	pushl	$nice
	addl	$-918353, (%esp)        # imm = 0xFFF1FCAF
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __strtoul_internal, __strtoul_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtoul_internal
	addl	$58378, (%esp)          # imm = 0xE40A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver xdr_char, xdr_char@GLIBC_2.0

	#NO_APP
	pushl	$xdr_char
	addl	$-1183057, (%esp)       # imm = 0xFFEDF2AF
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __strtod_nan, __strtod_nan@GLIBC_PRIVATE

	#NO_APP
	pushl	$__strtod_nan
	addl	$13514, (%esp)          # imm = 0x34CA
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver endaliasent, endaliasent@GLIBC_2.0

	#NO_APP
	pushl	$endaliasent
	addl	$-913146, (%esp)        # imm = 0xFFF21106
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver clock, clock@GLIBC_2.0

	#NO_APP
	pushl	$clock
	addl	$-634529, (%esp)        # imm = 0xFFF6515F
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver fexecve, fexecve@GLIBC_2.0

	#NO_APP
	pushl	$fexecve
	addl	$-552570, (%esp)        # imm = 0xFFF79186
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver getwchar_unlocked, getwchar_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$getwchar_unlocked
	addl	$-346141, (%esp)        # imm = 0xFFFAB7E3
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver _dl_catch_error, _dl_catch_error@GLIBC_PRIVATE

	#NO_APP
	pushl	$_dl_catch_error
	addl	$-1207505, (%esp)       # imm = 0xFFED932F
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __tsearch, __tsearch@GLIBC_PRIVATE

	#NO_APP
	pushl	$__tsearch
	addl	$-787914, (%esp)        # imm = 0xFFF3FA36
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver mbtowc, mbtowc@GLIBC_2.0

	#NO_APP
	pushl	$mbtowc
	addl	$-99825, (%esp)         # imm = 0xFFFE7A0F
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver _IO_list_resetlock, _IO_list_resetlock@GLIBC_2.2

	#NO_APP
	pushl	$_IO_list_resetlock
	addl	$-231574, (%esp)        # imm = 0xFFFC776A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver inet6_opt_init, inet6_opt_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_init
	addl	$-918630, (%esp)        # imm = 0xFFF1FB9A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver wcspbrk, wcspbrk@GLIBC_2.0

	#NO_APP
	pushl	$wcspbrk
	addl	$-531843, (%esp)        # imm = 0xFFF7E27D
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver siggetmask, siggetmask@GLIBC_2.0

	#NO_APP
	pushl	$siggetmask
	addl	$76154, (%esp)          # imm = 0x1297A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver _dl_signal_error, _dl_signal_error@GLIBC_PRIVATE

	#NO_APP
	pushl	$_dl_signal_error
	addl	$-730268, (%esp)        # imm = 0xFFF4DB64
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver _IO_proc_open, _IO_proc_open@GLIBC_2.1

	#NO_APP
	pushl	$_IO_proc_open
	addl	$-310707, (%esp)        # imm = 0xFFFB424D
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver tmpfile64, tmpfile64@GLIBC_2.1

	#NO_APP
	pushl	$tmpfile64
	addl	$-146406, (%esp)        # imm = 0xFFFDC41A
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-911555, (%esp)        # imm = 0xFFF2173D
	calll	opaquePredicate
	jne	.chain_49
	#APP
.symver __isoc99_vfscanf, __isoc99_vfscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfscanf
	addl	$-150342, (%esp)        # imm = 0xFFFDB4BA
	retl
	#APP
.resume_49:
	#NO_APP
	popfl
	.loc	1 143 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:143:5
	movl	%eax, (%esp)
	calll	free
	pushfl
	calll	.chain_50
	jmp	.resume_50
	#APP
.chain_50:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __strtok_r, __strtok_r@GLIBC_2.0

	#NO_APP
	pushl	$__strtok_r
	addl	$-275986, (%esp)        # imm = 0xFFFBC9EE
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-230102, (%esp)        # imm = 0xFFFC7D2A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __socket, __socket@GLIBC_PRIVATE

	#NO_APP
	pushl	$__socket
	addl	$-800582, (%esp)        # imm = 0xFFF3C8BA
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __vsprintf_chk, __vsprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsprintf_chk
	addl	$-860342, (%esp)        # imm = 0xFFF2DF4A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __fpending, __fpending@GLIBC_2.2

	#NO_APP
	pushl	$__fpending
	addl	$-367473, (%esp)        # imm = 0xFFFA648F
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver mrand48_r, mrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$mrand48_r
	addl	$61674, (%esp)          # imm = 0xF0EA
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _IO_iter_file, _IO_iter_file@GLIBC_2.2

	#NO_APP
	pushl	$_IO_iter_file
	addl	$147267, (%esp)         # imm = 0x23F43
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver getutmp, getutmp@GLIBC_2.1.1

	#NO_APP
	pushl	$getutmp
	addl	$-1202513, (%esp)       # imm = 0xFFEDA6AF
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __strncpy_by4, __strncpy_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncpy_by4
	addl	$-303782, (%esp)        # imm = 0xFFFB5D5A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver wcsstr, wcsstr@GLIBC_2.0

	#NO_APP
	pushl	$wcsstr
	addl	$-552561, (%esp)        # imm = 0xFFF7918F
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver msgget, msgget@GLIBC_2.0

	#NO_APP
	pushl	$msgget
	addl	$-802790, (%esp)        # imm = 0xFFF3C01A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __strtoul_internal, __strtoul_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtoul_internal
	addl	$49926, (%esp)          # imm = 0xC306
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver pkey_set, pkey_set@GLIBC_2.27

	#NO_APP
	pushl	$pkey_set
	addl	$-961489, (%esp)        # imm = 0xFFF1542F
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __fsetlocking, __fsetlocking@GLIBC_2.2

	#NO_APP
	pushl	$__fsetlocking
	addl	$-210842, (%esp)        # imm = 0xFFFCC866
	pushl	$-60
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver getdirentries, getdirentries@GLIBC_2.0

	#NO_APP
	pushl	$getdirentries
	addl	$-701373, (%esp)        # imm = 0xFFF54C43
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __chk_fail, __chk_fail@GLIBC_2.3.4

	#NO_APP
	pushl	$__chk_fail
	addl	$-1027569, (%esp)       # imm = 0xFFF0520F
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver pthread_attr_setscope, pthread_attr_setscope@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_setscope
	addl	$-859882, (%esp)        # imm = 0xFFF2E116
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __vwprintf_chk, __vwprintf_chk@GLIBC_2.4

	#NO_APP
	pushl	$__vwprintf_chk
	addl	$-1032305, (%esp)       # imm = 0xFFF03F8F
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver getdirentries64, getdirentries64@GLIBC_2.2

	#NO_APP
	pushl	$getdirentries64
	addl	$-527142, (%esp)        # imm = 0xFFF7F4DA
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _IO_str_init_static, _IO_str_init_static@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_init_static
	addl	$78564, (%esp)          # imm = 0x132E4
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver eventfd_write, eventfd_write@GLIBC_2.7

	#NO_APP
	pushl	$eventfd_write
	addl	$-794454, (%esp)        # imm = 0xFFF3E0AA
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver strtod, strtod@GLIBC_2.0

	#NO_APP
	pushl	$strtod
	addl	$49838, (%esp)          # imm = 0xC2AE
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver tmpnam, tmpnam@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam
	addl	$231923, (%esp)         # imm = 0x389F3
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _IO_puts, _IO_puts@GLIBC_2.0

	#NO_APP
	pushl	$_IO_puts
	addl	$-175242, (%esp)        # imm = 0xFFFD5376
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver fdetach, fdetach@GLIBC_2.1

	#NO_APP
	pushl	$fdetach
	addl	$-1025414, (%esp)       # imm = 0xFFF05A7A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __strspn_c2, __strspn_c2@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_c2
	addl	$-310602, (%esp)        # imm = 0xFFFB42B6
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __setmntent, __setmntent@GLIBC_2.2

	#NO_APP
	pushl	$__setmntent
	addl	$-937597, (%esp)        # imm = 0xFFF1B183
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver exit, exit@GLIBC_2.0

	#NO_APP
	pushl	$exit
	addl	$67946, (%esp)          # imm = 0x1096A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _IO_setbuffer, _IO_setbuffer@GLIBC_2.0

	#NO_APP
	pushl	$_IO_setbuffer
	addl	$-176874, (%esp)        # imm = 0xFFFD4D16
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver svcudp_create, svcudp_create@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_create
	addl	$-1014454, (%esp)       # imm = 0xFFF0854A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _IO_putc, _IO_putc@GLIBC_2.0

	#NO_APP
	pushl	$_IO_putc
	addl	$-196790, (%esp)        # imm = 0xFFFCFF4A
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-685763, (%esp)        # imm = 0xFFF5893D
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver xdr_wrapstring, xdr_wrapstring@GLIBC_2.0

	#NO_APP
	pushl	$xdr_wrapstring
	addl	$-1019430, (%esp)       # imm = 0xFFF071DA
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __uname, __uname@GLIBC_PRIVATE

	#NO_APP
	pushl	$__uname
	addl	$-230316, (%esp)        # imm = 0xFFFC7C54
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver __isdigit_l, __isdigit_l@GLIBC_2.1

	#NO_APP
	pushl	$__isdigit_l
	addl	$-31923, (%esp)         # imm = 0x834D
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver shmdt, shmdt@GLIBC_2.0

	#NO_APP
	pushl	$shmdt
	addl	$-803638, (%esp)        # imm = 0xFFF3BCCA
	calll	opaquePredicate
	jne	.chain_50
	#APP
.symver utimensat, utimensat@GLIBC_2.6

	#NO_APP
	pushl	$utimensat
	addl	$-891427, (%esp)        # imm = 0xFFF265DD
	retl
	#APP
.resume_50:
	#NO_APP
	popfl
	.loc	1 144 5                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:144:5
	movl	%eax, (%esp)
	calll	free
.Ltmp41:
.LBB3_15:
	.loc	1 146 1                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c:146:1
	addl	$260, %esp              # imm = 0x104
	popl	%esi
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp42:
.Lfunc_end3:
	.size	update, .Lfunc_end3-update
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Enter the choice\n"
	.size	.L.str, 18

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"1-Insert a new record into file\n2-Display the records\n"
	.size	.L.str.1, 55

	.type	.L.str.2,@object        # @.str.2
.L.str.2:
	.asciz	"3-Update the record\n4-Exit\n"
	.size	.L.str.2, 28

	.type	.L.str.3,@object        # @.str.3
.L.str.3:
	.asciz	"%d"
	.size	.L.str.3, 3

	.type	.L.str.4,@object        # @.str.4
.L.str.4:
	.asciz	"Enter the correct choice\n"
	.size	.L.str.4, 26

	.type	.L.str.5,@object        # @.str.5
.L.str.5:
	.asciz	"a+"
	.size	.L.str.5, 3

	.type	.L.str.6,@object        # @.str.6
.L.str.6:
	.zero	1
	.size	.L.str.6, 1

	.type	.L.str.7,@object        # @.str.7
.L.str.7:
	.asciz	"Enter the employee id\n"
	.size	.L.str.7, 23

	.type	.L.str.8,@object        # @.str.8
.L.str.8:
	.asciz	"Enter the employee name\n"
	.size	.L.str.8, 25

	.type	.L.str.9,@object        # @.str.9
.L.str.9:
	.asciz	" %[^\n]s"
	.size	.L.str.9, 8

	.type	count,@object           # @count
	.comm	count,4,4
	.type	.L.str.10,@object       # @.str.10
.L.str.10:
	.asciz	"r"
	.size	.L.str.10, 2

	.type	.L.str.11,@object       # @.str.11
.L.str.11:
	.asciz	"no records to display\n"
	.size	.L.str.11, 23

	.type	.L.str.12,@object       # @.str.12
.L.str.12:
	.asciz	" %s\n"
	.size	.L.str.12, 5

	.type	.L.str.13,@object       # @.str.13
.L.str.13:
	.asciz	"r+"
	.size	.L.str.13, 3

	.type	.L.str.14,@object       # @.str.14
.L.str.14:
	.asciz	"enter which employee id to be updated\n"
	.size	.L.str.14, 39

	.type	.L.str.15,@object       # @.str.15
.L.str.15:
	.asciz	"enter employee name for update:"
	.size	.L.str.15, 32

	.type	.L.str.16,@object       # @.str.16
.L.str.16:
	.asciz	"update of the record succesfully\n"
	.size	.L.str.16, 34

	.type	.L.str.17,@object       # @.str.17
.L.str.17:
	.asciz	"update unsuccesful enter correct id\n"
	.size	.L.str.17, 37

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	4                       # 0x4
	.long	78                      # 0x4e
	.long	346                     # 0x15a
	.long	2                       # 0x2
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	55                      # 0x37
	.quad	-6152745038460495821    # 0xaa9d0efc7503d833
	.quad	-5886161843874963488    # 0xae5026fd3d5fdfe0
	.long	35                      # 0x23
	.quad	175973585               # 0xa7d24d1
	.quad	5619966915797317611     # 0x4dfe2222518bf7eb
	.long	97                      # 0x61
	.quad	5113300303230663494     # 0x46f61788cbf5fb46
	.quad	1567579429343904570     # 0x15c1292f8340c33a
	.long	157                     # 0x9d
	.quad	1047914995824842979     # 0xe8af122f8f1d8e3
	.asciz	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c\001\000\001\001\t\t\001\025#\030\002\003\003\n\000\013\005\000\f\000\215\200\200\200\b\005\000\r\024\004\r\006\005\002\f\021\003\005\002\f\025\003\005\002\f\031\003\005\001\016\035\002\005\001+\001\000\001\001\005\005\0010\026\025\002\001\007\007\000\022\005\001\005\000\017\002\000\020\001\210\200\200\200\b\002\001\b\b\004\001\000\006\001\005\002\t\002\t\022\t\027\005\001\r\r\001H\027\033\002\001\b\007\000\021\005\000\022\000\223\200\200\200\b\005\000\023\003\004\002\003\004\001\203\200\200\200\b\002\001\003\017\002\002\000\007\000\022\t\001\005\000\017\n\000\020\001\210\200\200\200\b\n\001\b\t\004\016\001\f\000\017\r\000\020\001\205\200\200\200\b\r\001\005\006\006\001\000\n\001\005\013\005\001\t\022\021\027\005\001\r\r\021\r\021\002\025\002\025\025\001f\026,\002\001\b\007\000\022\005\001\005\000\017\002\000\020\001\210\200\200\200\b\002\001\b!\004\006\001\f\000\017\t\000\020\002\205\200\200\200\b\t\002\005\006\006\016\013\f\000\017\r\000\020\001\205\200\200\200\b\r\001\005\n\006\r\002\013\000\034\021\000\035\000\236\200\200\200\b\021\000\036\005\b\036\005\b\001\207\200\200\200\b\036\001\007\002\006\002\003\t\000\017\025\000\020\001\207\200\200\200\b\025\001\007\0003&\0004\002\207\200\200\200\b&\002\007\0006\000"
	.size	__llvm_coverage_mapping, 520

	.type	.L__profc_main,@object  # @__profc_main
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_main:
	.zero	64
	.size	.L__profc_main, 64

	.type	.L__profd_main,@object  # @__profd_main
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_main:
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.quad	-6152745038460495821    # 0xaa9d0efc7503d833
	.long	.L__profc_main
	.long	main
	.long	0
	.long	8                       # 0x8
	.zero	4
	.size	.L__profd_main, 36

	.type	.L__profc_insert,@object # @__profc_insert
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_insert:
	.zero	16
	.size	.L__profc_insert, 16

	.type	.L__profd_insert,@object # @__profd_insert
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_insert:
	.quad	-5886161843874963488    # 0xae5026fd3d5fdfe0
	.quad	175973585               # 0xa7d24d1
	.long	.L__profc_insert
	.long	insert
	.long	0
	.long	2                       # 0x2
	.zero	4
	.size	.L__profd_insert, 36

	.type	.L__profc_display,@object # @__profc_display
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_display:
	.zero	32
	.size	.L__profc_display, 32

	.type	.L__profd_display,@object # @__profd_display
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_display:
	.quad	5619966915797317611     # 0x4dfe2222518bf7eb
	.quad	5113300303230663494     # 0x46f61788cbf5fb46
	.long	.L__profc_display
	.long	display
	.long	0
	.long	4                       # 0x4
	.zero	4
	.size	.L__profd_display, 36

	.type	.L__profc_update,@object # @__profc_update
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_update:
	.zero	48
	.size	.L__profc_update, 48

	.type	.L__profd_update,@object # @__profd_update
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_update:
	.quad	1567579429343904570     # 0x15c1292f8340c33a
	.quad	1047914995824842979     # 0xe8af122f8f1d8e3
	.long	.L__profc_update
	.long	update
	.long	0
	.long	6                       # 0x6
	.zero	4
	.size	.L__profd_update, 36

	.type	.L__llvm_prf_nm,@object # @__llvm_prf_nm
	.section	__llvm_prf_names,"a",@progbits
	.p2align	4
.L__llvm_prf_nm:
	.ascii	"\032\"x\332\313M\314\314c\314\314+N-*aL\311,.\310I\254d,-HI,I\005\000\201\215\t\267"
	.size	.L__llvm_prf_nm, 36

	.type	__llvm_profile_filename,@object # @__llvm_profile_filename
	.section	.rodata.__llvm_profile_filename,"aG",@progbits,__llvm_profile_filename,comdat
	.globl	__llvm_profile_filename
	.p2align	4
__llvm_profile_filename:
	.asciz	"example6-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.file	2 "/usr/include/bits/types/struct_FILE.h"
	.file	3 "/usr/include/bits/types.h"
	.file	4 "/usr/lib64/llvm/7/bin/../../../../lib/clang/7.0.1/include/stddef.h"
	.file	5 "/usr/include/bits/types/FILE.h"
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example6.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"count"                 # string offset=194
.Linfo_string4:
	.asciz	"int"                   # string offset=200
.Linfo_string5:
	.asciz	"empid"                 # string offset=204
.Linfo_string6:
	.asciz	"name"                  # string offset=210
.Linfo_string7:
	.asciz	"char"                  # string offset=215
.Linfo_string8:
	.asciz	"emprec"                # string offset=220
.Linfo_string9:
	.asciz	"emp"                   # string offset=227
.Linfo_string10:
	.asciz	"main"                  # string offset=231
.Linfo_string11:
	.asciz	"insert"                # string offset=236
.Linfo_string12:
	.asciz	"display"               # string offset=243
.Linfo_string13:
	.asciz	"update"                # string offset=251
.Linfo_string14:
	.asciz	"argc"                  # string offset=258
.Linfo_string15:
	.asciz	"argv"                  # string offset=263
.Linfo_string16:
	.asciz	"choice"                # string offset=268
.Linfo_string17:
	.asciz	"a"                     # string offset=275
.Linfo_string18:
	.asciz	"fp1"                   # string offset=277
.Linfo_string19:
	.asciz	"_flags"                # string offset=281
.Linfo_string20:
	.asciz	"_IO_read_ptr"          # string offset=288
.Linfo_string21:
	.asciz	"_IO_read_end"          # string offset=301
.Linfo_string22:
	.asciz	"_IO_read_base"         # string offset=314
.Linfo_string23:
	.asciz	"_IO_write_base"        # string offset=328
.Linfo_string24:
	.asciz	"_IO_write_ptr"         # string offset=343
.Linfo_string25:
	.asciz	"_IO_write_end"         # string offset=357
.Linfo_string26:
	.asciz	"_IO_buf_base"          # string offset=371
.Linfo_string27:
	.asciz	"_IO_buf_end"           # string offset=384
.Linfo_string28:
	.asciz	"_IO_save_base"         # string offset=396
.Linfo_string29:
	.asciz	"_IO_backup_base"       # string offset=410
.Linfo_string30:
	.asciz	"_IO_save_end"          # string offset=426
.Linfo_string31:
	.asciz	"_markers"              # string offset=439
.Linfo_string32:
	.asciz	"_IO_marker"            # string offset=448
.Linfo_string33:
	.asciz	"_chain"                # string offset=459
.Linfo_string34:
	.asciz	"_fileno"               # string offset=466
.Linfo_string35:
	.asciz	"_flags2"               # string offset=474
.Linfo_string36:
	.asciz	"_old_offset"           # string offset=482
.Linfo_string37:
	.asciz	"long int"              # string offset=494
.Linfo_string38:
	.asciz	"__off_t"               # string offset=503
.Linfo_string39:
	.asciz	"_cur_column"           # string offset=511
.Linfo_string40:
	.asciz	"unsigned short"        # string offset=523
.Linfo_string41:
	.asciz	"_vtable_offset"        # string offset=538
.Linfo_string42:
	.asciz	"signed char"           # string offset=553
.Linfo_string43:
	.asciz	"_shortbuf"             # string offset=565
.Linfo_string44:
	.asciz	"__ARRAY_SIZE_TYPE__"   # string offset=575
.Linfo_string45:
	.asciz	"_lock"                 # string offset=595
.Linfo_string46:
	.asciz	"_IO_lock_t"            # string offset=601
.Linfo_string47:
	.asciz	"_offset"               # string offset=612
.Linfo_string48:
	.asciz	"__off64_t"             # string offset=620
.Linfo_string49:
	.asciz	"_codecvt"              # string offset=630
.Linfo_string50:
	.asciz	"_IO_codecvt"           # string offset=639
.Linfo_string51:
	.asciz	"_wide_data"            # string offset=651
.Linfo_string52:
	.asciz	"_IO_wide_data"         # string offset=662
.Linfo_string53:
	.asciz	"_freeres_list"         # string offset=676
.Linfo_string54:
	.asciz	"_freeres_buf"          # string offset=690
.Linfo_string55:
	.asciz	"__pad5"                # string offset=703
.Linfo_string56:
	.asciz	"long unsigned int"     # string offset=710
.Linfo_string57:
	.asciz	"size_t"                # string offset=728
.Linfo_string58:
	.asciz	"_mode"                 # string offset=735
.Linfo_string59:
	.asciz	"_unused2"              # string offset=741
.Linfo_string60:
	.asciz	"_IO_FILE"              # string offset=750
.Linfo_string61:
	.asciz	"FILE"                  # string offset=759
.Linfo_string62:
	.asciz	"temp1"                 # string offset=764
.Linfo_string63:
	.asciz	"ch"                    # string offset=770
.Linfo_string64:
	.asciz	"var"                   # string offset=773
.Linfo_string65:
	.asciz	"temp"                  # string offset=777
.Linfo_string66:
	.asciz	"id"                    # string offset=782
.Linfo_string67:
	.asciz	"c"                     # string offset=785
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
	.byte	52                      # DW_TAG_variable
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	63                      # DW_AT_external
	.byte	25                      # DW_FORM_flag_present
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	2                       # DW_AT_location
	.byte	24                      # DW_FORM_exprloc
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	3                       # Abbreviation Code
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
	.byte	4                       # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	5                       # Abbreviation Code
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
	.byte	6                       # Abbreviation Code
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
	.byte	7                       # Abbreviation Code
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
	.byte	8                       # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	9                       # Abbreviation Code
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
	.byte	10                      # Abbreviation Code
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
	.byte	11                      # Abbreviation Code
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
	.byte	12                      # Abbreviation Code
	.byte	19                      # DW_TAG_structure_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	60                      # DW_AT_declaration
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	13                      # Abbreviation Code
	.byte	1                       # DW_TAG_array_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	14                      # Abbreviation Code
	.byte	33                      # DW_TAG_subrange_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	55                      # DW_AT_count
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	15                      # Abbreviation Code
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
	.byte	16                      # Abbreviation Code
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
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	990                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x3d7 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end3-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x11 DW_TAG_variable
	.long	.Linfo_string3          # DW_AT_name
	.long	55                      # DW_AT_type
                                        # DW_AT_external
	.byte	1                       # DW_AT_decl_file
	.byte	19                      # DW_AT_decl_line
	.byte	5                       # DW_AT_location
	.byte	3
	.long	count
	.byte	3                       # Abbrev [3] 0x37:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	4                       # Abbrev [4] 0x3e:0x5 DW_TAG_pointer_type
	.long	67                      # DW_AT_type
	.byte	5                       # Abbrev [5] 0x43:0xb DW_TAG_typedef
	.long	78                      # DW_AT_type
	.long	.Linfo_string9          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	14                      # DW_AT_decl_line
	.byte	6                       # Abbrev [6] 0x4e:0x21 DW_TAG_structure_type
	.long	.Linfo_string8          # DW_AT_name
	.byte	16                      # DW_AT_byte_size
	.byte	1                       # DW_AT_decl_file
	.byte	10                      # DW_AT_decl_line
	.byte	7                       # Abbrev [7] 0x56:0xc DW_TAG_member
	.long	.Linfo_string5          # DW_AT_name
	.long	55                      # DW_AT_type
	.byte	1                       # DW_AT_decl_file
	.byte	11                      # DW_AT_decl_line
	.byte	0                       # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x62:0xc DW_TAG_member
	.long	.Linfo_string6          # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	1                       # DW_AT_decl_file
	.byte	12                      # DW_AT_decl_line
	.byte	8                       # DW_AT_data_member_location
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x6f:0x5 DW_TAG_pointer_type
	.long	116                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x74:0x7 DW_TAG_base_type
	.long	.Linfo_string7          # DW_AT_name
	.byte	6                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	8                       # Abbrev [8] 0x7b:0x1 DW_TAG_pointer_type
	.byte	9                       # Abbrev [9] 0x7c:0x3c DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string10         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	21                      # DW_AT_decl_line
                                        # DW_AT_prototyped
                                        # DW_AT_external
	.byte	10                      # Abbrev [10] 0x8d:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string14         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	21                      # DW_AT_decl_line
	.long	55                      # DW_AT_type
	.byte	10                      # Abbrev [10] 0x9b:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string15         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	21                      # DW_AT_decl_line
	.long	464                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0xa9:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	116
	.long	.Linfo_string16         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	22                      # DW_AT_decl_line
	.long	55                      # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	9                       # Abbrev [9] 0xb8:0x3c DW_TAG_subprogram
	.long	.Lfunc_begin1           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin1 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string11         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	48                      # DW_AT_decl_line
                                        # DW_AT_prototyped
                                        # DW_AT_external
	.byte	10                      # Abbrev [10] 0xc9:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string17         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	48                      # DW_AT_decl_line
	.long	111                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0xd7:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	112
	.long	.Linfo_string18         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	49                      # DW_AT_decl_line
	.long	469                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0xe5:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string62         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	50                      # DW_AT_decl_line
	.long	62                      # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	9                       # Abbrev [9] 0xf4:0x58 DW_TAG_subprogram
	.long	.Lfunc_begin2           # DW_AT_low_pc
	.long	.Lfunc_end2-.Lfunc_begin2 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string12         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	72                      # DW_AT_decl_line
                                        # DW_AT_prototyped
                                        # DW_AT_external
	.byte	10                      # Abbrev [10] 0x105:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string17         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	72                      # DW_AT_decl_line
	.long	111                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x113:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	112
	.long	.Linfo_string18         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	73                      # DW_AT_decl_line
	.long	469                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x121:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	107
	.long	.Linfo_string63         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	74                      # DW_AT_decl_line
	.long	116                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x12f:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	108
	.long	.Linfo_string64         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	75                      # DW_AT_decl_line
	.long	55                      # DW_AT_type
	.byte	11                      # Abbrev [11] 0x13d:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string65         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	76                      # DW_AT_decl_line
	.long	62                      # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	9                       # Abbrev [9] 0x14c:0x84 DW_TAG_subprogram
	.long	.Lfunc_begin3           # DW_AT_low_pc
	.long	.Lfunc_end3-.Lfunc_begin3 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string13         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	102                     # DW_AT_decl_line
                                        # DW_AT_prototyped
                                        # DW_AT_external
	.byte	10                      # Abbrev [10] 0x15d:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string17         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	102                     # DW_AT_decl_line
	.long	111                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x16b:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	112
	.long	.Linfo_string18         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	103                     # DW_AT_decl_line
	.long	469                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x179:0xf DW_TAG_variable
	.byte	3                       # DW_AT_location
	.byte	145
	.ascii	"\227~"
	.long	.Linfo_string63         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	104                     # DW_AT_decl_line
	.long	116                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x188:0xf DW_TAG_variable
	.byte	3                       # DW_AT_location
	.byte	145
	.ascii	"\230~"
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	104                     # DW_AT_decl_line
	.long	981                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x197:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	108
	.long	.Linfo_string64         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	105                     # DW_AT_decl_line
	.long	55                      # DW_AT_type
	.byte	11                      # Abbrev [11] 0x1a5:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	100
	.long	.Linfo_string66         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	105                     # DW_AT_decl_line
	.long	55                      # DW_AT_type
	.byte	11                      # Abbrev [11] 0x1b3:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	104
	.long	.Linfo_string67         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	105                     # DW_AT_decl_line
	.long	55                      # DW_AT_type
	.byte	11                      # Abbrev [11] 0x1c1:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string65         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	106                     # DW_AT_decl_line
	.long	62                      # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x1d0:0x5 DW_TAG_pointer_type
	.long	111                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x1d5:0x5 DW_TAG_pointer_type
	.long	474                     # DW_AT_type
	.byte	5                       # Abbrev [5] 0x1da:0xb DW_TAG_typedef
	.long	485                     # DW_AT_type
	.long	.Linfo_string61         # DW_AT_name
	.byte	5                       # DW_AT_decl_file
	.byte	7                       # DW_AT_decl_line
	.byte	6                       # Abbrev [6] 0x1e5:0x165 DW_TAG_structure_type
	.long	.Linfo_string60         # DW_AT_name
	.byte	216                     # DW_AT_byte_size
	.byte	2                       # DW_AT_decl_file
	.byte	49                      # DW_AT_decl_line
	.byte	7                       # Abbrev [7] 0x1ed:0xc DW_TAG_member
	.long	.Linfo_string19         # DW_AT_name
	.long	55                      # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	51                      # DW_AT_decl_line
	.byte	0                       # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x1f9:0xc DW_TAG_member
	.long	.Linfo_string20         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	54                      # DW_AT_decl_line
	.byte	8                       # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x205:0xc DW_TAG_member
	.long	.Linfo_string21         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	55                      # DW_AT_decl_line
	.byte	16                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x211:0xc DW_TAG_member
	.long	.Linfo_string22         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	56                      # DW_AT_decl_line
	.byte	24                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x21d:0xc DW_TAG_member
	.long	.Linfo_string23         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	57                      # DW_AT_decl_line
	.byte	32                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x229:0xc DW_TAG_member
	.long	.Linfo_string24         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	58                      # DW_AT_decl_line
	.byte	40                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x235:0xc DW_TAG_member
	.long	.Linfo_string25         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	59                      # DW_AT_decl_line
	.byte	48                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x241:0xc DW_TAG_member
	.long	.Linfo_string26         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	60                      # DW_AT_decl_line
	.byte	56                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x24d:0xc DW_TAG_member
	.long	.Linfo_string27         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	61                      # DW_AT_decl_line
	.byte	64                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x259:0xc DW_TAG_member
	.long	.Linfo_string28         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	64                      # DW_AT_decl_line
	.byte	72                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x265:0xc DW_TAG_member
	.long	.Linfo_string29         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	65                      # DW_AT_decl_line
	.byte	80                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x271:0xc DW_TAG_member
	.long	.Linfo_string30         # DW_AT_name
	.long	111                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	66                      # DW_AT_decl_line
	.byte	88                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x27d:0xc DW_TAG_member
	.long	.Linfo_string31         # DW_AT_name
	.long	842                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	68                      # DW_AT_decl_line
	.byte	96                      # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x289:0xc DW_TAG_member
	.long	.Linfo_string33         # DW_AT_name
	.long	852                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	70                      # DW_AT_decl_line
	.byte	104                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x295:0xc DW_TAG_member
	.long	.Linfo_string34         # DW_AT_name
	.long	55                      # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	72                      # DW_AT_decl_line
	.byte	112                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2a1:0xc DW_TAG_member
	.long	.Linfo_string35         # DW_AT_name
	.long	55                      # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	73                      # DW_AT_decl_line
	.byte	116                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2ad:0xc DW_TAG_member
	.long	.Linfo_string36         # DW_AT_name
	.long	857                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	74                      # DW_AT_decl_line
	.byte	120                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2b9:0xc DW_TAG_member
	.long	.Linfo_string39         # DW_AT_name
	.long	875                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	77                      # DW_AT_decl_line
	.byte	128                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2c5:0xc DW_TAG_member
	.long	.Linfo_string41         # DW_AT_name
	.long	882                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	78                      # DW_AT_decl_line
	.byte	130                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2d1:0xc DW_TAG_member
	.long	.Linfo_string43         # DW_AT_name
	.long	889                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	79                      # DW_AT_decl_line
	.byte	131                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2dd:0xc DW_TAG_member
	.long	.Linfo_string45         # DW_AT_name
	.long	908                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	81                      # DW_AT_decl_line
	.byte	136                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2e9:0xc DW_TAG_member
	.long	.Linfo_string47         # DW_AT_name
	.long	920                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	89                      # DW_AT_decl_line
	.byte	144                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x2f5:0xc DW_TAG_member
	.long	.Linfo_string49         # DW_AT_name
	.long	931                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	91                      # DW_AT_decl_line
	.byte	152                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x301:0xc DW_TAG_member
	.long	.Linfo_string51         # DW_AT_name
	.long	941                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	92                      # DW_AT_decl_line
	.byte	160                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x30d:0xc DW_TAG_member
	.long	.Linfo_string53         # DW_AT_name
	.long	852                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	93                      # DW_AT_decl_line
	.byte	168                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x319:0xc DW_TAG_member
	.long	.Linfo_string54         # DW_AT_name
	.long	123                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	94                      # DW_AT_decl_line
	.byte	176                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x325:0xc DW_TAG_member
	.long	.Linfo_string55         # DW_AT_name
	.long	951                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	95                      # DW_AT_decl_line
	.byte	184                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x331:0xc DW_TAG_member
	.long	.Linfo_string58         # DW_AT_name
	.long	55                      # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	96                      # DW_AT_decl_line
	.byte	192                     # DW_AT_data_member_location
	.byte	7                       # Abbrev [7] 0x33d:0xc DW_TAG_member
	.long	.Linfo_string59         # DW_AT_name
	.long	969                     # DW_AT_type
	.byte	2                       # DW_AT_decl_file
	.byte	98                      # DW_AT_decl_line
	.byte	196                     # DW_AT_data_member_location
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x34a:0x5 DW_TAG_pointer_type
	.long	847                     # DW_AT_type
	.byte	12                      # Abbrev [12] 0x34f:0x5 DW_TAG_structure_type
	.long	.Linfo_string32         # DW_AT_name
                                        # DW_AT_declaration
	.byte	4                       # Abbrev [4] 0x354:0x5 DW_TAG_pointer_type
	.long	485                     # DW_AT_type
	.byte	5                       # Abbrev [5] 0x359:0xb DW_TAG_typedef
	.long	868                     # DW_AT_type
	.long	.Linfo_string38         # DW_AT_name
	.byte	3                       # DW_AT_decl_file
	.byte	150                     # DW_AT_decl_line
	.byte	3                       # Abbrev [3] 0x364:0x7 DW_TAG_base_type
	.long	.Linfo_string37         # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	8                       # DW_AT_byte_size
	.byte	3                       # Abbrev [3] 0x36b:0x7 DW_TAG_base_type
	.long	.Linfo_string40         # DW_AT_name
	.byte	7                       # DW_AT_encoding
	.byte	2                       # DW_AT_byte_size
	.byte	3                       # Abbrev [3] 0x372:0x7 DW_TAG_base_type
	.long	.Linfo_string42         # DW_AT_name
	.byte	6                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	13                      # Abbrev [13] 0x379:0xc DW_TAG_array_type
	.long	116                     # DW_AT_type
	.byte	14                      # Abbrev [14] 0x37e:0x6 DW_TAG_subrange_type
	.long	901                     # DW_AT_type
	.byte	1                       # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	15                      # Abbrev [15] 0x385:0x7 DW_TAG_base_type
	.long	.Linfo_string44         # DW_AT_name
	.byte	8                       # DW_AT_byte_size
	.byte	7                       # DW_AT_encoding
	.byte	4                       # Abbrev [4] 0x38c:0x5 DW_TAG_pointer_type
	.long	913                     # DW_AT_type
	.byte	16                      # Abbrev [16] 0x391:0x7 DW_TAG_typedef
	.long	.Linfo_string46         # DW_AT_name
	.byte	2                       # DW_AT_decl_file
	.byte	43                      # DW_AT_decl_line
	.byte	5                       # Abbrev [5] 0x398:0xb DW_TAG_typedef
	.long	868                     # DW_AT_type
	.long	.Linfo_string48         # DW_AT_name
	.byte	3                       # DW_AT_decl_file
	.byte	151                     # DW_AT_decl_line
	.byte	4                       # Abbrev [4] 0x3a3:0x5 DW_TAG_pointer_type
	.long	936                     # DW_AT_type
	.byte	12                      # Abbrev [12] 0x3a8:0x5 DW_TAG_structure_type
	.long	.Linfo_string50         # DW_AT_name
                                        # DW_AT_declaration
	.byte	4                       # Abbrev [4] 0x3ad:0x5 DW_TAG_pointer_type
	.long	946                     # DW_AT_type
	.byte	12                      # Abbrev [12] 0x3b2:0x5 DW_TAG_structure_type
	.long	.Linfo_string52         # DW_AT_name
                                        # DW_AT_declaration
	.byte	5                       # Abbrev [5] 0x3b7:0xb DW_TAG_typedef
	.long	962                     # DW_AT_type
	.long	.Linfo_string57         # DW_AT_name
	.byte	4                       # DW_AT_decl_file
	.byte	62                      # DW_AT_decl_line
	.byte	3                       # Abbrev [3] 0x3c2:0x7 DW_TAG_base_type
	.long	.Linfo_string56         # DW_AT_name
	.byte	7                       # DW_AT_encoding
	.byte	8                       # DW_AT_byte_size
	.byte	13                      # Abbrev [13] 0x3c9:0xc DW_TAG_array_type
	.long	116                     # DW_AT_type
	.byte	14                      # Abbrev [14] 0x3ce:0x6 DW_TAG_subrange_type
	.long	901                     # DW_AT_type
	.byte	20                      # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	13                      # Abbrev [13] 0x3d5:0xc DW_TAG_array_type
	.long	116                     # DW_AT_type
	.byte	14                      # Abbrev [14] 0x3da:0x6 DW_TAG_subrange_type
	.long	901                     # DW_AT_type
	.byte	200                     # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	0                       # End Of Children Mark
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark
	.section	.debug_pubnames,"",@progbits
	.long	.LpubNames_end0-.LpubNames_begin0 # Length of Public Names Info
.LpubNames_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	994                     # Compilation Unit Length
	.long	332                     # DIE offset
	.asciz	"update"                # External Name
	.long	124                     # DIE offset
	.asciz	"main"                  # External Name
	.long	184                     # DIE offset
	.asciz	"insert"                # External Name
	.long	244                     # DIE offset
	.asciz	"display"               # External Name
	.long	38                      # DIE offset
	.asciz	"count"                 # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	994                     # Compilation Unit Length
	.long	474                     # DIE offset
	.asciz	"FILE"                  # External Name
	.long	67                      # DIE offset
	.asciz	"emp"                   # External Name
	.long	55                      # DIE offset
	.asciz	"int"                   # External Name
	.long	857                     # DIE offset
	.asciz	"__off_t"               # External Name
	.long	875                     # DIE offset
	.asciz	"unsigned short"        # External Name
	.long	951                     # DIE offset
	.asciz	"size_t"                # External Name
	.long	913                     # DIE offset
	.asciz	"_IO_lock_t"            # External Name
	.long	485                     # DIE offset
	.asciz	"_IO_FILE"              # External Name
	.long	920                     # DIE offset
	.asciz	"__off64_t"             # External Name
	.long	882                     # DIE offset
	.asciz	"signed char"           # External Name
	.long	962                     # DIE offset
	.asciz	"long unsigned int"     # External Name
	.long	868                     # DIE offset
	.asciz	"long int"              # External Name
	.long	78                      # DIE offset
	.asciz	"emprec"                # External Name
	.long	116                     # DIE offset
	.asciz	"char"                  # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
