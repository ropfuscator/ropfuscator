	.text
	.file	"example4.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c"
	.loc	1 8 0                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:8:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$168, %esp
	movl	$0, -12(%ebp)
.Ltmp0:
	.loc	1 8 12 prologue_end     # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:8:12
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
	.loc	1 11 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:11:3
	leal	.L.str, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 12 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:12:3
	leal	.L.str.1, %eax
	movl	%eax, (%esp)
	leal	-8(%ebp), %eax
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
	.loc	1 13 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:13:3
	leal	.L.str.2, %eax
	movl	%eax, (%esp)
	calll	printf
.Ltmp1:
	.loc	1 14 10                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:14:10
	movl	$0, -4(%ebp)
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
	.loc	1 0 10 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:10
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
	addl	$-797730, (%esp)        # imm = 0xFFF3D3DE
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver xdr_rejected_reply, xdr_rejected_reply@GLIBC_2.0

	#NO_APP
	pushl	$xdr_rejected_reply
	addl	$-584509, (%esp)        # imm = 0xFFF714C3
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __wcstoll_internal, __wcstoll_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstoll_internal
	addl	$-402074, (%esp)        # imm = 0xFFF9DD66
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-865718, (%esp)        # imm = 0xFFF2CA4A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __res_ninit, __res_ninit@GLIBC_2.2

	#NO_APP
	pushl	$__res_ninit
	addl	$-942938, (%esp)        # imm = 0xFFF19CA6
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver free, free@GLIBC_2.0

	#NO_APP
	pushl	$free
	addl	$-430381, (%esp)        # imm = 0xFFF96ED3
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver htonl, htonl@GLIBC_2.0

	#NO_APP
	pushl	$htonl
	addl	$-871318, (%esp)        # imm = 0xFFF2B46A
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-234634, (%esp)        # imm = 0xFFFC6B76
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
	addl	$-267574, (%esp)        # imm = 0xFFFBEACA
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __strtol_internal, __strtol_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtol_internal
	addl	$-86339, (%esp)         # imm = 0xFFFEAEBD
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver sigignore, sigignore@GLIBC_2.1

	#NO_APP
	pushl	$sigignore
	addl	$74490, (%esp)          # imm = 0x122FA
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$422036, (%esp)         # imm = 0x67094
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver endusershell, endusershell@GLIBC_2.0

	#NO_APP
	pushl	$endusershell
	addl	$-914019, (%esp)        # imm = 0xFFF20D9D
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver isdigit, isdigit@GLIBC_2.0

	#NO_APP
	pushl	$isdigit
	addl	$114410, (%esp)         # imm = 0x1BEEA
	calll	opaquePredicate
	jne	.chain_1
	#APP
.symver strerror, strerror@GLIBC_2.0

	#NO_APP
	pushl	$strerror
	addl	$-416035, (%esp)        # imm = 0xFFF9A6DD
	retl
	#APP
.resume_1:
	#NO_APP
	popfl
.Ltmp2:
	.loc	1 14 17                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:14:17
	cmpl	-8(%ebp), %eax
.Ltmp3:
	.loc	1 14 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:14:3
	jge	.LBB0_4
# %bb.2:                                #   in Loop: Header=BB0_1 Depth=1
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
	addl	$163262, (%esp)         # imm = 0x27DBE
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-487165, (%esp)        # imm = 0xFFF89103
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver envz_strip, envz_strip@GLIBC_2.0

	#NO_APP
	pushl	$envz_strip
	addl	$-296282, (%esp)        # imm = 0xFFFB7AA6
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
	addl	$-805498, (%esp)        # imm = 0xFFF3B586
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver qgcvt, qgcvt@GLIBC_2.0

	#NO_APP
	pushl	$qgcvt
	addl	$-950493, (%esp)        # imm = 0xFFF17F23
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-793334, (%esp)        # imm = 0xFFF3E50A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-864858, (%esp)        # imm = 0xFFF2CDA6
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver clnt_spcreateerror, clnt_spcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_spcreateerror
	addl	$-994102, (%esp)        # imm = 0xFFF0D4CA
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __snprintf, __snprintf@GLIBC_PRIVATE

	#NO_APP
	pushl	$__snprintf
	addl	$-72054, (%esp)         # imm = 0xFFFEE68A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-917619, (%esp)        # imm = 0xFFF1FF8D
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __iswpunct_l, __iswpunct_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswpunct_l
	addl	$-813958, (%esp)        # imm = 0xFFF3947A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __poll_chk, __poll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__poll_chk
	addl	$-559180, (%esp)        # imm = 0xFFF777B4
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver putwc_unlocked, putwc_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$putwc_unlocked
	addl	$-319283, (%esp)        # imm = 0xFFFB20CD
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver xdr_bool, xdr_bool@GLIBC_2.0

	#NO_APP
	pushl	$xdr_bool
	addl	$-1018086, (%esp)       # imm = 0xFFF0771A
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __readlink_chk, __readlink_chk@GLIBC_2.4

	#NO_APP
	pushl	$__readlink_chk
	addl	$-1008835, (%esp)       # imm = 0xFFF09B3D
	retl
	#APP
.resume_3:
	#NO_APP
	popfl
.Ltmp4:
	.loc	1 15 18 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:15:18
	leal	-136(%ebp,%eax,4), %eax
	.loc	1 15 5 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:15:5
	leal	.L.str.1, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
.Ltmp5:
# %bb.3:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	1 0 5                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:5
	pushfl
	calll	.chain_4
	jmp	.resume_4
	#APP
.chain_4:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-582749, (%esp)        # imm = 0xFFF71BA3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-927194, (%esp)        # imm = 0xFFF1DA26
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-758022, (%esp)        # imm = 0xFFF46EFA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-549322, (%esp)        # imm = 0xFFF79E36
	pushl	$1
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __openat64_2, __openat64_2@GLIBC_2.7

	#NO_APP
	pushl	$__openat64_2
	addl	$-885533, (%esp)        # imm = 0xFFF27CE3
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
	addl	$-312762, (%esp)        # imm = 0xFFFB3A46
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __nss_lookup, __nss_lookup@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_lookup
	addl	$-947974, (%esp)        # imm = 0xFFF188FA
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
	pushl	$-68
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
	.loc	1 14 26 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:14:26
	movl	%eax, -4(%ebp)
	.loc	1 14 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:14:3
	jmp	.LBB0_1
.Ltmp6:
.LBB0_4:
	.loc	1 0 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:3
	xorl	%eax, %eax
	leal	-136(%ebp), %eax
	.loc	1 17 25 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:17:25
	movl	-8(%ebp), %ecx
	.loc	1 17 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:17:3
	movl	%eax, (%esp)
	movl	$0, 4(%esp)
	movl	$0, 8(%esp)
	movl	%ecx, 12(%esp)
	movl	$1, 16(%esp)
	calll	selection
	.loc	1 18 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:18:3
	leal	.L.str.3, %eax
	movl	%eax, (%esp)
	calll	printf
.Ltmp7:
	.loc	1 19 10                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:19:10
	movl	$0, -4(%ebp)
.LBB0_5:                                # =>This Inner Loop Header: Depth=1
	.loc	1 0 10 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:10
	pushfl
	calll	.chain_5
	jmp	.resume_5
	#APP
.chain_5:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver mrand48_r, mrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$mrand48_r
	addl	$61038, (%esp)          # imm = 0xEE6E
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver svcraw_create, svcraw_create@GLIBC_2.0

	#NO_APP
	pushl	$svcraw_create
	addl	$-588125, (%esp)        # imm = 0xFFF706A3
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
	addl	$-863702, (%esp)        # imm = 0xFFF2D22A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __vsnprintf_chk, __vsnprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsnprintf_chk
	addl	$-869114, (%esp)        # imm = 0xFFF2BD06
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver rcmd_af, rcmd_af@GLIBC_2.2

	#NO_APP
	pushl	$rcmd_af
	addl	$-1067341, (%esp)       # imm = 0xFFEFB6B3
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver atol, atol@GLIBC_2.0

	#NO_APP
	pushl	$atol
	addl	$73866, (%esp)          # imm = 0x1208A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver getmsg, getmsg@GLIBC_2.1

	#NO_APP
	pushl	$getmsg
	addl	$-1033434, (%esp)       # imm = 0xFFF03B26
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver inet_netof, inet_netof@GLIBC_2.0

	#NO_APP
	pushl	$inet_netof
	addl	$-871590, (%esp)        # imm = 0xFFF2B35A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$-202038, (%esp)        # imm = 0xFFFCEACA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __nss_hostname_digits_dots, __nss_hostname_digits_dots@GLIBC_2.2.2

	#NO_APP
	pushl	$__nss_hostname_digits_dots
	addl	$-1096723, (%esp)       # imm = 0xFFEF43ED
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
	addl	$161380, (%esp)         # imm = 0x27664
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver setegid, setegid@GLIBC_2.0

	#NO_APP
	pushl	$setegid
	addl	$-902323, (%esp)        # imm = 0xFFF23B4D
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
	addl	$-943267, (%esp)        # imm = 0xFFF19B5D
	retl
	#APP
.resume_5:
	#NO_APP
	popfl
.Ltmp8:
	.loc	1 19 17                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:19:17
	cmpl	-8(%ebp), %eax
.Ltmp9:
	.loc	1 19 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:19:3
	jge	.LBB0_8
# %bb.6:                                #   in Loop: Header=BB0_5 Depth=1
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
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$453171, (%esp)         # imm = 0x6EA33
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __libc_longjmp, __libc_longjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_longjmp
	addl	$71798, (%esp)          # imm = 0x11876
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __tolower_l, __tolower_l@GLIBC_2.1

	#NO_APP
	pushl	$__tolower_l
	addl	$112458, (%esp)         # imm = 0x1B74A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver execle, execle@GLIBC_2.0

	#NO_APP
	pushl	$execle
	addl	$-552954, (%esp)        # imm = 0xFFF79006
	pushl	$1
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strncmp_g, __strncmp_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncmp_g
	addl	$-478381, (%esp)        # imm = 0xFFF8B353
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-919398, (%esp)        # imm = 0xFFF1F89A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strlen_g, __strlen_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strlen_g
	addl	$-312042, (%esp)        # imm = 0xFFFB3D16
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver ioperm, ioperm@GLIBC_2.0

	#NO_APP
	pushl	$ioperm
	addl	$-793286, (%esp)        # imm = 0xFFF3E53A
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
.symver iruserok_af, iruserok_af@GLIBC_2.2

	#NO_APP
	pushl	$iruserok_af
	addl	$-897218, (%esp)        # imm = 0xFFF24F3E
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver endaliasent, endaliasent@GLIBC_2.0

	#NO_APP
	pushl	$endaliasent
	addl	$-526141, (%esp)        # imm = 0xFFF7F8C3
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __stpcpy_small, __stpcpy_small@GLIBC_2.1.1

	#NO_APP
	pushl	$__stpcpy_small
	addl	$-311594, (%esp)        # imm = 0xFFFB3ED6
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __register_atfork, __register_atfork@GLIBC_2.3.2

	#NO_APP
	pushl	$__register_atfork
	addl	$-854102, (%esp)        # imm = 0xFFF2F7AA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __ptsname_r_chk, __ptsname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ptsname_r_chk
	addl	$-1045354, (%esp)       # imm = 0xFFF00C96
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-123565, (%esp)        # imm = 0xFFFE1D53
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver siggetmask, siggetmask@GLIBC_2.0

	#NO_APP
	pushl	$siggetmask
	addl	$76154, (%esp)          # imm = 0x1297A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __idna_from_dns_encoding, __idna_from_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_from_dns_encoding
	addl	$-930634, (%esp)        # imm = 0xFFF1CCB6
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-816390, (%esp)        # imm = 0xFFF38AFA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver xdr_quad_t, xdr_quad_t@GLIBC_2.3.4

	#NO_APP
	pushl	$xdr_quad_t
	addl	$-1019750, (%esp)       # imm = 0xFFF0709A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver sigismember, sigismember@GLIBC_2.0

	#NO_APP
	pushl	$sigismember
	addl	$-68595, (%esp)         # imm = 0xFFFEF40D
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-793926, (%esp)        # imm = 0xFFF3E2BA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-438652, (%esp)        # imm = 0xFFF94E84
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __libc_vfork, __libc_vfork@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_vfork
	addl	$-688915, (%esp)        # imm = 0xFFF57CED
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver initgroups, initgroups@GLIBC_2.0

	#NO_APP
	pushl	$initgroups
	addl	$-529446, (%esp)        # imm = 0xFFF7EBDA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver mblen, mblen@GLIBC_2.0

	#NO_APP
	pushl	$mblen
	addl	$-79219, (%esp)         # imm = 0xFFFECA8D
	retl
	#APP
.resume_7:
	#NO_APP
	popfl
.Ltmp10:
	.loc	1 20 20 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:20:20
	movl	-136(%ebp,%eax,4), %eax
	.loc	1 20 5 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:20:5
	leal	.L.str.4, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
.Ltmp11:
# %bb.7:                                #   in Loop: Header=BB0_5 Depth=1
	.loc	1 0 5                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:5
	pushfl
	calll	.chain_8
	jmp	.resume_8
	#APP
.chain_8:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$74611, (%esp)          # imm = 0x12373
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver _IO_feof, _IO_feof@GLIBC_2.0

	#NO_APP
	pushl	$_IO_feof
	addl	$-202170, (%esp)        # imm = 0xFFFCEA46
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver clnt_sperror, clnt_sperror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_sperror
	addl	$-993414, (%esp)        # imm = 0xFFF0D77A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver ualarm, ualarm@GLIBC_2.0

	#NO_APP
	pushl	$ualarm
	addl	$-769530, (%esp)        # imm = 0xFFF44206
	pushl	$1
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __fdelt_warn, __fdelt_warn@GLIBC_2.15

	#NO_APP
	pushl	$__fdelt_warn
	addl	$-1045181, (%esp)       # imm = 0xFFF00D43
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
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver getnetbyname, getnetbyname@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname
	addl	$-879814, (%esp)        # imm = 0xFFF2933A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$-267506, (%esp)        # imm = 0xFFFBEB0E
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver munlock, munlock@GLIBC_2.0

	#NO_APP
	pushl	$munlock
	addl	$-395517, (%esp)        # imm = 0xFFF9F703
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __sysconf, __sysconf@GLIBC_2.2

	#NO_APP
	pushl	$__sysconf
	addl	$-559258, (%esp)        # imm = 0xFFF77766
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver fts_set, fts_set@GLIBC_2.0

	#NO_APP
	pushl	$fts_set
	addl	$-735990, (%esp)        # imm = 0xFFF4C50A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver xdr_array, xdr_array@GLIBC_2.0

	#NO_APP
	pushl	$xdr_array
	addl	$-1024202, (%esp)       # imm = 0xFFF05F36
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-933341, (%esp)        # imm = 0xFFF1C223
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$70666, (%esp)          # imm = 0x1140A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-180362, (%esp)        # imm = 0xFFFD3F76
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver pthread_attr_init, pthread_attr_init@GLIBC_2.1

	#NO_APP
	pushl	$pthread_attr_init
	addl	$-850310, (%esp)        # imm = 0xFFF3067A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-1089014, (%esp)       # imm = 0xFFEF620A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver labs, labs@GLIBC_2.0

	#NO_APP
	pushl	$labs
	addl	$-78835, (%esp)         # imm = 0xFFFECC0D
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
	addl	$-497628, (%esp)        # imm = 0xFFF86824
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-895267, (%esp)        # imm = 0xFFF256DD
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
	addl	$-902915, (%esp)        # imm = 0xFFF238FD
	retl
	#APP
.resume_8:
	#NO_APP
	popfl
	.loc	1 19 26 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:19:26
	movl	%eax, -4(%ebp)
	.loc	1 19 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:19:3
	jmp	.LBB0_5
.Ltmp12:
.LBB0_8:
	.loc	1 23 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:23:3
	xorl	%eax, %eax
	addl	$168, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp13:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.globl	selection               # -- Begin function selection
	.p2align	4, 0x90
	.type	selection,@function
selection:                              # @selection
.Lfunc_begin1:
	.loc	1 26 0                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:26:0
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
	pushfl
	calll	.chain_9
	jmp	.resume_9
	#APP
.chain_9:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getrpcent, getrpcent@GLIBC_2.0

	#NO_APP
	pushl	$getrpcent
	addl	$-979922, (%esp)        # imm = 0xFFF10C2E
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_int8_t, xdr_int8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int8_t
	addl	$-642093, (%esp)        # imm = 0xFFF633D3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$153238, (%esp)         # imm = 0x25696
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver mcheck_pedantic, mcheck_pedantic@GLIBC_2.2

	#NO_APP
	pushl	$mcheck_pedantic
	addl	$-263990, (%esp)        # imm = 0xFFFBF8CA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_uint32_t, xdr_uint32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint32_t
	addl	$-1028682, (%esp)       # imm = 0xFFF04DB6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getnameinfo, getnameinfo@GLIBC_2.1

	#NO_APP
	pushl	$getnameinfo
	addl	$-1081869, (%esp)       # imm = 0xFFEF7DF3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _dl_mcount_wrapper_check, _dl_mcount_wrapper_check@GLIBC_2.1

	#NO_APP
	pushl	$_dl_mcount_wrapper_check
	addl	$-1039014, (%esp)       # imm = 0xFFF0255A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __wcstod_internal, __wcstod_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstod_internal
	addl	$-402426, (%esp)        # imm = 0xFFF9DC06
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver svcerr_noprog, svcerr_noprog@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_noprog
	addl	$-1008166, (%esp)       # imm = 0xFFF09DDA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getpwnam, getpwnam@GLIBC_2.0

	#NO_APP
	pushl	$getpwnam
	addl	$-537926, (%esp)        # imm = 0xFFF7CABA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-322819, (%esp)        # imm = 0xFFFB12FD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __libc_freeres, __libc_freeres@GLIBC_2.1

	#NO_APP
	pushl	$__libc_freeres
	addl	$-1248342, (%esp)       # imm = 0xFFECF3AA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver setdomainname, setdomainname@GLIBC_2.0

	#NO_APP
	pushl	$setdomainname
	addl	$-446540, (%esp)        # imm = 0xFFF92FB4
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver posix_spawnattr_setsigdefault, posix_spawnattr_setsigdefault@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setsigdefault
	addl	$-844883, (%esp)        # imm = 0xFFF31BAD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fts64_close, fts64_close@GLIBC_2.23

	#NO_APP
	pushl	$fts64_close
	addl	$-740998, (%esp)        # imm = 0xFFF4B17A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getgrnam_r, getgrnam_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getgrnam_r
	addl	$-677971, (%esp)        # imm = 0xFFF5A7AD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getnetgrent, getnetgrent@GLIBC_2.0

	#NO_APP
	pushl	$getnetgrent
	addl	$-904898, (%esp)        # imm = 0xFFF2313E
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver clnt_pcreateerror, clnt_pcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_pcreateerror
	addl	$-615821, (%esp)        # imm = 0xFFF69A73
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver pthread_mutex_destroy, pthread_mutex_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_mutex_destroy
	addl	$-861194, (%esp)        # imm = 0xFFF2DBF6
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __wcsncpy_chk, __wcsncpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncpy_chk
	addl	$-865462, (%esp)        # imm = 0xFFF2CB4A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __nss_group_lookup, __nss_group_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_group_lookup
	addl	$-1100010, (%esp)       # imm = 0xFFEF3716
	pushl	$-52
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_int32_t, xdr_int32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_int32_t
	addl	$-1194445, (%esp)       # imm = 0xFFEDC633
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_callhdr, xdr_callhdr@GLIBC_2.0

	#NO_APP
	pushl	$xdr_callhdr
	addl	$-963782, (%esp)        # imm = 0xFFF14B3A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_wfile_xsputn, _IO_wfile_xsputn@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_xsputn
	addl	$-190678, (%esp)        # imm = 0xFFFD172A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _mcleanup, _mcleanup@GLIBC_2.0

	#NO_APP
	pushl	$_mcleanup
	addl	$-806310, (%esp)        # imm = 0xFFF3B25A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-1063635, (%esp)       # imm = 0xFFEFC52D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$112122, (%esp)         # imm = 0x1B5FA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver prlimit, prlimit@GLIBC_2.13

	#NO_APP
	pushl	$prlimit
	addl	$-482828, (%esp)        # imm = 0xFFF8A1F4
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strtof_l, __strtof_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtof_l
	addl	$-106547, (%esp)        # imm = 0xFFFE5FCD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __internal_endnetgrent, __internal_endnetgrent@GLIBC_PRIVATE

	#NO_APP
	pushl	$__internal_endnetgrent
	addl	$-902166, (%esp)        # imm = 0xFFF23BEA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver authunix_create, authunix_create@GLIBC_2.0

	#NO_APP
	pushl	$authunix_create
	addl	$-1136675, (%esp)       # imm = 0xFFEEA7DD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strspn_cg, __strspn_cg@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_cg
	addl	$-304946, (%esp)        # imm = 0xFFFB58CE
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver jrand48, jrand48@GLIBC_2.0

	#NO_APP
	pushl	$jrand48
	addl	$440963, (%esp)         # imm = 0x6BA83
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ftw64, ftw64@GLIBC_2.1

	#NO_APP
	pushl	$ftw64
	addl	$-738122, (%esp)        # imm = 0xFFF4BCB6
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_least_wmarker, _IO_least_wmarker@GLIBC_2.2

	#NO_APP
	pushl	$_IO_least_wmarker
	addl	$-176982, (%esp)        # imm = 0xFFFD4CAA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver xdr_uint8_t, xdr_uint8_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint8_t
	addl	$-1029242, (%esp)       # imm = 0xFFF04B86
	pushl	$-48
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_free_backup_area, _IO_free_backup_area@GLIBC_2.0

	#NO_APP
	pushl	$_IO_free_backup_area
	addl	$-397405, (%esp)        # imm = 0xFFF9EFA3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver capget, capget@GLIBC_2.1

	#NO_APP
	pushl	$capget
	addl	$-796854, (%esp)        # imm = 0xFFF3D74A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver inotify_init, inotify_init@GLIBC_2.4

	#NO_APP
	pushl	$inotify_init
	addl	$-805802, (%esp)        # imm = 0xFFF3B456
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __nss_hash, __nss_hash@GLIBC_PRIVATE

	#NO_APP
	pushl	$__nss_hash
	addl	$-954934, (%esp)        # imm = 0xFFF16DCA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver rexec_af, rexec_af@GLIBC_2.2

	#NO_APP
	pushl	$rexec_af
	addl	$-897030, (%esp)        # imm = 0xFFF24FFA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver mkdirat, mkdirat@GLIBC_2.4

	#NO_APP
	pushl	$mkdirat
	addl	$-854883, (%esp)        # imm = 0xFFF2F49D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __idna_to_dns_encoding, __idna_to_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_to_dns_encoding
	addl	$-921910, (%esp)        # imm = 0xFFF1EECA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __dgettext, __dgettext@GLIBC_2.0

	#NO_APP
	pushl	$__dgettext
	addl	$422036, (%esp)         # imm = 0x67094
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __sched_getparam, __sched_getparam@GLIBC_2.0

	#NO_APP
	pushl	$__sched_getparam
	addl	$-809587, (%esp)        # imm = 0xFFF3A58D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver hcreate, hcreate@GLIBC_2.0

	#NO_APP
	pushl	$hcreate
	addl	$-777638, (%esp)        # imm = 0xFFF4225A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fremovexattr, fremovexattr@GLIBC_2.3

	#NO_APP
	pushl	$fremovexattr
	addl	$-931875, (%esp)        # imm = 0xFFF1C7DD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$73982, (%esp)          # imm = 0x120FE
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$98771, (%esp)          # imm = 0x181D3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver thrd_equal, thrd_equal@GLIBC_2.28

	#NO_APP
	pushl	$thrd_equal
	addl	$-863690, (%esp)        # imm = 0xFFF2D236
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$165322, (%esp)         # imm = 0x285CA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver isupper, isupper@GLIBC_2.0

	#NO_APP
	pushl	$isupper
	addl	$105478, (%esp)         # imm = 0x19C06
	pushl	$-44
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-406125, (%esp)        # imm = 0xFFF9CD93
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __libc_start_main, __libc_start_main@GLIBC_2.0

	#NO_APP
	pushl	$__libc_start_main
	addl	$167290, (%esp)         # imm = 0x28D7A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-775114, (%esp)        # imm = 0xFFF42C36
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_wfile_underflow, _IO_wfile_underflow@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_underflow
	addl	$-184198, (%esp)        # imm = 0xFFFD307A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-974694, (%esp)        # imm = 0xFFF1209A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __gconv_transliterate, __gconv_transliterate@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_transliterate
	addl	$-11843, (%esp)         # imm = 0xD1BD
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver mbstowcs, mbstowcs@GLIBC_2.0

	#NO_APP
	pushl	$mbstowcs
	addl	$65434, (%esp)          # imm = 0xFF9A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver vwprintf, vwprintf@GLIBC_2.2

	#NO_APP
	pushl	$vwprintf
	addl	$136340, (%esp)         # imm = 0x21494
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _setjmp, _setjmp@GLIBC_2.0

	#NO_APP
	pushl	$_setjmp
	addl	$-64483, (%esp)         # imm = 0xFFFF041D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-72134, (%esp)         # imm = 0xFFFEE63A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver setjmp, setjmp@GLIBC_2.0

	#NO_APP
	pushl	$setjmp
	addl	$-64419, (%esp)         # imm = 0xFFFF045D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver inet6_rth_add, inet6_rth_add@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_add
	addl	$-920722, (%esp)        # imm = 0xFFF1F36E
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver svc_getreqset, svc_getreqset@GLIBC_2.0

	#NO_APP
	pushl	$svc_getreqset
	addl	$-630541, (%esp)        # imm = 0xFFF660F3
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$65910, (%esp)          # imm = 0x10176
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ecvt, ecvt@GLIBC_2.0

	#NO_APP
	pushl	$ecvt
	addl	$-774406, (%esp)        # imm = 0xFFF42EFA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ftok, ftok@GLIBC_2.0

	#NO_APP
	pushl	$ftok
	addl	$-810698, (%esp)        # imm = 0xFFF3A136
	pushl	$-40
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fgetpos, fgetpos@GLIBC_2.0

	#NO_APP
	pushl	$fgetpos
	addl	$-1231229, (%esp)       # imm = 0xFFED3683
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
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ptrace, ptrace@GLIBC_2.0

	#NO_APP
	pushl	$ptrace
	addl	$-761462, (%esp)        # imm = 0xFFF4618A
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
	addl	$-313315, (%esp)        # imm = 0xFFFB381D
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
	addl	$-448636, (%esp)        # imm = 0xFFF92784
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
	addl	$-1009107, (%esp)       # imm = 0xFFF09A2D
	retl
	#APP
.resume_9:
	#NO_APP
	popfl
.Ltmp14:
	.loc	1 26 62 prologue_end    # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:26:62
	movl	.L__profc_selection, %eax
	pushfl
	calll	.chain_10
	jmp	.resume_10
	#APP
.chain_10:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver xdr_authunix_parms, xdr_authunix_parms@GLIBC_2.0

	#NO_APP
	pushl	$xdr_authunix_parms
	addl	$-577357, (%esp)        # imm = 0xFFF730B3
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __isxdigit_l, __isxdigit_l@GLIBC_2.1

	#NO_APP
	pushl	$__isxdigit_l
	addl	$104070, (%esp)         # imm = 0x19686
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sched_getaffinity, sched_getaffinity@GLIBC_2.3.3

	#NO_APP
	pushl	$sched_getaffinity
	addl	$-1079158, (%esp)       # imm = 0xFFEF888A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-824842, (%esp)        # imm = 0xFFF369F6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _authenticate, _authenticate@GLIBC_2.1

	#NO_APP
	pushl	$_authenticate
	addl	$-1139741, (%esp)       # imm = 0xFFEE9BE3
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _IO_enable_locks, _IO_enable_locks@GLIBC_PRIVATE

	#NO_APP
	pushl	$_IO_enable_locks
	addl	$-226182, (%esp)        # imm = 0xFFFC8C7A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-759690, (%esp)        # imm = 0xFFF46876
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver strcoll, strcoll@GLIBC_2.0

	#NO_APP
	pushl	$strcoll
	addl	$-270374, (%esp)        # imm = 0xFFFBDFDA
	retl
	#APP
.resume_10:
	#NO_APP
	popfl
	adcl	$0, .L__profc_selection+4
	movl	%eax, .L__profc_selection
	pushfl
	calll	.chain_11
	jmp	.resume_11
	#APP
.chain_11:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __libc_fatal, __libc_fatal@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_fatal
	addl	$-203810, (%esp)        # imm = 0xFFFCE3DE
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$231731, (%esp)         # imm = 0x38933
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver pthread_cond_broadcast, pthread_cond_broadcast@GLIBC_2.3.2

	#NO_APP
	pushl	$pthread_cond_broadcast
	addl	$-860218, (%esp)        # imm = 0xFFF2DFC6
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-230102, (%esp)        # imm = 0xFFFC7D2A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __ctype_b_loc, __ctype_b_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_b_loc
	addl	$103798, (%esp)         # imm = 0x19576
	pushl	$-52
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver sendfile, sendfile@GLIBC_2.1

	#NO_APP
	pushl	$sendfile
	addl	$-919485, (%esp)        # imm = 0xFFF1F843
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver mkstemps64, mkstemps64@GLIBC_2.11

	#NO_APP
	pushl	$mkstemps64
	addl	$-760742, (%esp)        # imm = 0xFFF4645A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver getnetname, getnetname@GLIBC_2.1

	#NO_APP
	pushl	$getnetname
	addl	$-1012826, (%esp)       # imm = 0xFFF08BA6
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver preadv64v2, preadv64v2@GLIBC_2.26

	#NO_APP
	pushl	$preadv64v2
	addl	$-755510, (%esp)        # imm = 0xFFF478CA
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver innetgr, innetgr@GLIBC_2.0

	#NO_APP
	pushl	$innetgr
	addl	$-903142, (%esp)        # imm = 0xFFF2381A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver _IO_seekmark, _IO_seekmark@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekmark
	addl	$-375091, (%esp)        # imm = 0xFFFA46CD
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver read, read@GLIBC_2.0

	#NO_APP
	pushl	$read
	addl	$-711286, (%esp)        # imm = 0xFFF5258A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver __gconv_get_modules_db, __gconv_get_modules_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_modules_db
	addl	$473412, (%esp)         # imm = 0x73944
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver getentropy, getentropy@GLIBC_2.25

	#NO_APP
	pushl	$getentropy
	addl	$-84115, (%esp)         # imm = 0xFFFEB76D
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver inet6_rth_init, inet6_rth_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_init
	addl	$-919974, (%esp)        # imm = 0xFFF1F65A
	calll	opaquePredicate
	jne	.chain_11
	#APP
.symver xdr_u_int, xdr_u_int@GLIBC_2.0

	#NO_APP
	pushl	$xdr_u_int
	addl	$-1161843, (%esp)       # imm = 0xFFEE458D
	retl
	#APP
.resume_11:
	#NO_APP
	popfl
.Ltmp15:
	.loc	1 29 11                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:29:11
	movl	20(%ebp), %ecx
	.loc	1 29 16 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:29:16
	subl	$1, %ecx
	.loc	1 29 9                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:29:9
	cmpl	%ecx, %eax
.Ltmp16:
	.loc	1 29 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:29:7
	jge	.LBB1_8
# %bb.1:
	movl	.L__profc_selection+8, %eax
	pushfl
	calll	.chain_12
	jmp	.resume_12
	#APP
.chain_12:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver readdir64_r, readdir64_r@GLIBC_2.2

	#NO_APP
	pushl	$readdir64_r
	addl	$-145661, (%esp)        # imm = 0xFFFDC703
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver globfree64, globfree64@GLIBC_2.1

	#NO_APP
	pushl	$globfree64
	addl	$-580970, (%esp)        # imm = 0xFFF72296
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __sysctl, __sysctl@GLIBC_2.2

	#NO_APP
	pushl	$__sysctl
	addl	$-793414, (%esp)        # imm = 0xFFF3E4BA
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_switch_to_wbackup_area, _IO_switch_to_wbackup_area@GLIBC_2.2

	#NO_APP
	pushl	$_IO_switch_to_wbackup_area
	addl	$-185626, (%esp)        # imm = 0xFFFD2AE6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver wcsxfrm, wcsxfrm@GLIBC_2.0

	#NO_APP
	pushl	$wcsxfrm
	addl	$-609357, (%esp)        # imm = 0xFFF6B3B3
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-146822, (%esp)        # imm = 0xFFFDC27A
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver __backtrace_symbols_fd, __backtrace_symbols_fd@GLIBC_2.1

	#NO_APP
	pushl	$__backtrace_symbols_fd
	addl	$-866682, (%esp)        # imm = 0xFFF2C686
	calll	opaquePredicate
	jne	.chain_12
	#APP
.symver _IO_str_underflow, _IO_str_underflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_underflow
	addl	$-231654, (%esp)        # imm = 0xFFFC771A
	retl
	#APP
.resume_12:
	#NO_APP
	popfl
	adcl	$0, .L__profc_selection+12
	movl	%eax, .L__profc_selection+8
.Ltmp17:
	.loc	1 30 9 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:30:9
	cmpl	$0, 24(%ebp)
.Ltmp18:
	.loc	1 30 9 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:30:9
	je	.LBB1_3
# %bb.2:
	movl	.L__profc_selection+16, %eax
	pushfl
	calll	.chain_13
	jmp	.resume_13
	#APP
.chain_13:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_fopen, _IO_fopen@GLIBC_2.1

	#NO_APP
	pushl	$_IO_fopen
	addl	$218483, (%esp)         # imm = 0x35573
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __poll, __poll@GLIBC_2.1

	#NO_APP
	pushl	$__poll
	addl	$-751578, (%esp)        # imm = 0xFFF48826
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver _IO_seekpos, _IO_seekpos@GLIBC_2.0

	#NO_APP
	pushl	$_IO_seekpos
	addl	$-168182, (%esp)        # imm = 0xFFFD6F0A
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __strcat_g, __strcat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strcat_g
	addl	$-312346, (%esp)        # imm = 0xFFFB3BE6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$-376381, (%esp)        # imm = 0xFFFA41C3
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __strchrnul_g, __strchrnul_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_g
	addl	$-304134, (%esp)        # imm = 0xFFFB5BFA
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver authdes_pk_create, authdes_pk_create@GLIBC_2.1

	#NO_APP
	pushl	$authdes_pk_create
	addl	$-998250, (%esp)        # imm = 0xFFF0C496
	calll	opaquePredicate
	jne	.chain_13
	#APP
.symver __towctrans, __towctrans@GLIBC_2.1

	#NO_APP
	pushl	$__towctrans
	addl	$-812550, (%esp)        # imm = 0xFFF399FA
	retl
	#APP
.resume_13:
	#NO_APP
	popfl
	adcl	$0, .L__profc_selection+20
	movl	%eax, .L__profc_selection+16
	pushfl
	calll	.chain_14
	jmp	.resume_14
	#APP
.chain_14:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getsgent, getsgent@GLIBC_2.10

	#NO_APP
	pushl	$getsgent
	addl	$-902174, (%esp)        # imm = 0xFFF23BE2
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver endspent, endspent@GLIBC_2.0

	#NO_APP
	pushl	$endspent
	addl	$-818262, (%esp)        # imm = 0xFFF383AA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_wdefault_xsputn, _IO_wdefault_xsputn@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_xsputn
	addl	$-178406, (%esp)        # imm = 0xFFFD471A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver posix_spawnattr_getsigdefault, posix_spawnattr_getsigdefault@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_getsigdefault
	addl	$-865089, (%esp)        # imm = 0xFFF2CCBF
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __nss_database_lookup, __nss_database_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_database_lookup
	addl	$-945846, (%esp)        # imm = 0xFFF1914A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_str_seekoff, _IO_str_seekoff@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_seekoff
	addl	$145139, (%esp)         # imm = 0x236F3
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __libc_rpc_getport, __libc_rpc_getport@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_rpc_getport
	addl	$-1170257, (%esp)       # imm = 0xFFEE24AF
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver pthread_attr_getschedpolicy, pthread_attr_getschedpolicy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_getschedpolicy
	addl	$-851094, (%esp)        # imm = 0xFFF3036A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver gethostbyaddr, gethostbyaddr@GLIBC_2.0

	#NO_APP
	pushl	$gethostbyaddr
	addl	$-1037505, (%esp)       # imm = 0xFFF02B3F
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __strtol_internal, __strtol_internal@GLIBC_2.0

	#NO_APP
	pushl	$__strtol_internal
	addl	$58554, (%esp)          # imm = 0xE4BA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-180362, (%esp)        # imm = 0xFFFD3F76
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __finite, __finite@GLIBC_2.0

	#NO_APP
	pushl	$__finite
	addl	$-79649, (%esp)         # imm = 0xFFFEC8DF
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver muntrace, muntrace@GLIBC_2.0

	#NO_APP
	pushl	$muntrace
	addl	$-274858, (%esp)        # imm = 0xFFFBCE56
	pushl	$-8
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver fputws, fputws@GLIBC_2.2

	#NO_APP
	pushl	$fputws
	addl	$-346813, (%esp)        # imm = 0xFFFAB543
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __isoc99_fwscanf, __isoc99_fwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_fwscanf
	addl	$-613569, (%esp)        # imm = 0xFFF6A33F
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __fpurge, __fpurge@GLIBC_2.2

	#NO_APP
	pushl	$__fpurge
	addl	$-210602, (%esp)        # imm = 0xFFFCC956
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_file_sync, _IO_file_sync@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_sync
	addl	$-1228433, (%esp)       # imm = 0xFFED416F
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __ctype_init, __ctype_init@GLIBC_PRIVATE

	#NO_APP
	pushl	$__ctype_init
	addl	$112058, (%esp)         # imm = 0x1B5BA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-766662, (%esp)        # imm = 0xFFF44D3A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver wcsncat, wcsncat@GLIBC_2.0

	#NO_APP
	pushl	$wcsncat
	addl	$-531107, (%esp)        # imm = 0xFFF7E55D
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver strxfrm, strxfrm@GLIBC_2.0

	#NO_APP
	pushl	$strxfrm
	addl	$-275494, (%esp)        # imm = 0xFFFBCBDA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getopt_long, getopt_long@GLIBC_2.0

	#NO_APP
	pushl	$getopt_long
	addl	$-352540, (%esp)        # imm = 0xFFFA9EE4
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __isalpha_l, __isalpha_l@GLIBC_2.1

	#NO_APP
	pushl	$__isalpha_l
	addl	$-31795, (%esp)         # imm = 0x83CD
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __xmknod, __xmknod@GLIBC_2.0

	#NO_APP
	pushl	$__xmknod
	addl	$-708150, (%esp)        # imm = 0xFFF531CA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver syscall, syscall@GLIBC_2.0

	#NO_APP
	pushl	$syscall
	addl	$-917619, (%esp)        # imm = 0xFFF1FF8D
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getmntent, getmntent@GLIBC_2.0

	#NO_APP
	pushl	$getmntent
	addl	$-762774, (%esp)        # imm = 0xFFF45C6A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver stty, stty@GLIBC_2.0

	#NO_APP
	pushl	$stty
	addl	$-382829, (%esp)        # imm = 0xFFFA2893
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver semop, semop@GLIBC_2.0

	#NO_APP
	pushl	$semop
	addl	$-811466, (%esp)        # imm = 0xFFF39E36
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_file_sync, _IO_file_sync@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_sync
	addl	$-1063270, (%esp)       # imm = 0xFFEFC69A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver isalnum, isalnum@GLIBC_2.0

	#NO_APP
	pushl	$isalnum
	addl	$106198, (%esp)         # imm = 0x19ED6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver readlinkat, readlinkat@GLIBC_2.4

	#NO_APP
	pushl	$readlinkat
	addl	$-894893, (%esp)        # imm = 0xFFF25853
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver timespec_get, timespec_get@GLIBC_2.16

	#NO_APP
	pushl	$timespec_get
	addl	$-517638, (%esp)        # imm = 0xFFF819FA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_adjust_column, _IO_adjust_column@GLIBC_2.0

	#NO_APP
	pushl	$_IO_adjust_column
	addl	$-236026, (%esp)        # imm = 0xFFFC6606
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver svc_getreq_common, svc_getreq_common@GLIBC_2.2

	#NO_APP
	pushl	$svc_getreq_common
	addl	$-1008406, (%esp)       # imm = 0xFFF09CEA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_peekc_locked, _IO_peekc_locked@GLIBC_2.0

	#NO_APP
	pushl	$_IO_peekc_locked
	addl	$-208594, (%esp)        # imm = 0xFFFCD12E
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __register_frame_info_table, __register_frame_info_table@GLIBC_2.0

	#NO_APP
	pushl	$__register_frame_info_table
	addl	$-669405, (%esp)        # imm = 0xFFF5C923
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver cfsetispeed, cfsetispeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetispeed
	addl	$-758506, (%esp)        # imm = 0xFFF46D16
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __libc_pvalloc, __libc_pvalloc@GLIBC_2.0

	#NO_APP
	pushl	$__libc_pvalloc
	addl	$-258070, (%esp)        # imm = 0xFFFC0FEA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __ppoll_chk, __ppoll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__ppoll_chk
	addl	$-879418, (%esp)        # imm = 0xFFF294C6
	pushl	$-52
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _IO_fsetpos64, _IO_fsetpos64@GLIBC_2.2

	#NO_APP
	pushl	$_IO_fsetpos64
	addl	$-344813, (%esp)        # imm = 0xFFFABD13
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __fsetlocking, __fsetlocking@GLIBC_2.2

	#NO_APP
	pushl	$__fsetlocking
	addl	$-202390, (%esp)        # imm = 0xFFFCE96A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getservent_r, getservent_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getservent_r
	addl	$-896666, (%esp)        # imm = 0xFFF25166
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver getaliasent_r, getaliasent_r@GLIBC_2.0

	#NO_APP
	pushl	$getaliasent_r
	addl	$-1091302, (%esp)       # imm = 0xFFEF591A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver srand48, srand48@GLIBC_2.0

	#NO_APP
	pushl	$srand48
	addl	$62330, (%esp)          # imm = 0xF37A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver sigemptyset, sigemptyset@GLIBC_2.0

	#NO_APP
	pushl	$sigemptyset
	addl	$-68131, (%esp)         # imm = 0xFFFEF5DD
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver clntunix_create, clntunix_create@GLIBC_2.1

	#NO_APP
	pushl	$clntunix_create
	addl	$-984998, (%esp)        # imm = 0xFFF0F85A
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __iswpunct_l, __iswpunct_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswpunct_l
	addl	$-502236, (%esp)        # imm = 0xFFF85624
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver __tfind, __tfind@GLIBC_PRIVATE

	#NO_APP
	pushl	$__tfind
	addl	$-924755, (%esp)        # imm = 0xFFF1E3AD
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver _dl_signal_error, _dl_signal_error@GLIBC_PRIVATE

	#NO_APP
	pushl	$_dl_signal_error
	addl	$-1041990, (%esp)       # imm = 0xFFF019BA
	calll	opaquePredicate
	jne	.chain_14
	#APP
.symver vwscanf, vwscanf@GLIBC_2.2

	#NO_APP
	pushl	$vwscanf
	addl	$-320579, (%esp)        # imm = 0xFFFB1BBD
	retl
	#APP
.resume_14:
	#NO_APP
	popfl
.LBB1_3:
	.loc	1 0 9                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:9
	pushfl
	calll	.chain_15
	jmp	.resume_15
	#APP
.chain_15:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver mlockall, mlockall@GLIBC_2.0

	#NO_APP
	pushl	$mlockall
	addl	$-774754, (%esp)        # imm = 0xFFF42D9E
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __strchrnul_c, __strchrnul_c@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_c
	addl	$74419, (%esp)          # imm = 0x122B3
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-186378, (%esp)        # imm = 0xFFFD27F6
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver wcsspn, wcsspn@GLIBC_2.0

	#NO_APP
	pushl	$wcsspn
	addl	$-387094, (%esp)        # imm = 0xFFFA17EA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver thrd_current, thrd_current@GLIBC_2.28

	#NO_APP
	pushl	$thrd_current
	addl	$-863642, (%esp)        # imm = 0xFFF2D266
	pushl	$-48
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver fremovexattr, fremovexattr@GLIBC_2.3

	#NO_APP
	pushl	$fremovexattr
	addl	$-961325, (%esp)        # imm = 0xFFF154D3
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver l64a, l64a@GLIBC_2.0

	#NO_APP
	pushl	$l64a
	addl	$9866, (%esp)           # imm = 0x268A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-722570, (%esp)        # imm = 0xFFF4F976
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __strverscmp, __strverscmp@GLIBC_2.1.1

	#NO_APP
	pushl	$__strverscmp
	addl	$-270566, (%esp)        # imm = 0xFFFBDF1A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __libc_thread_freeres, __libc_thread_freeres@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_thread_freeres
	addl	$-270118, (%esp)        # imm = 0xFFFBE0DA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver isascii, isascii@GLIBC_2.0

	#NO_APP
	pushl	$isascii
	addl	$-31603, (%esp)         # imm = 0x848D
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __backtrace, __backtrace@GLIBC_2.1

	#NO_APP
	pushl	$__backtrace
	addl	$-857174, (%esp)        # imm = 0xFFF2EBAA
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver wordfree, wordfree@GLIBC_2.1

	#NO_APP
	pushl	$wordfree
	addl	$-383228, (%esp)        # imm = 0xFFFA2704
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver __sched_cpualloc, __sched_cpualloc@GLIBC_2.7

	#NO_APP
	pushl	$__sched_cpualloc
	addl	$-848307, (%esp)        # imm = 0xFFF30E4D
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver _mcleanup, _mcleanup@GLIBC_2.0

	#NO_APP
	pushl	$_mcleanup
	addl	$-806310, (%esp)        # imm = 0xFFF3B25A
	calll	opaquePredicate
	jne	.chain_15
	#APP
.symver envz_remove, envz_remove@GLIBC_2.0

	#NO_APP
	pushl	$envz_remove
	addl	$-432067, (%esp)        # imm = 0xFFF9683D
	retl
	#APP
.resume_15:
	#NO_APP
	popfl
.Ltmp19:
	.loc	1 33 11 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:33:11
	cmpl	20(%ebp), %eax
.Ltmp20:
	.loc	1 33 9 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:33:9
	jge	.LBB1_7
# %bb.4:
	movl	.L__profc_selection+24, %eax
	pushfl
	calll	.chain_16
	jmp	.resume_16
	#APP
.chain_16:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver __cxa_atexit, __cxa_atexit@GLIBC_2.1.3

	#NO_APP
	pushl	$__cxa_atexit
	addl	$445747, (%esp)         # imm = 0x6CD33
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver inet6_option_space, inet6_option_space@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_space
	addl	$-924634, (%esp)        # imm = 0xFFF1E426
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-919398, (%esp)        # imm = 0xFFF1F89A
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$62214, (%esp)          # imm = 0xF306
	pushl	$1
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver __swprintf_chk, __swprintf_chk@GLIBC_2.4

	#NO_APP
	pushl	$__swprintf_chk
	addl	$-1040589, (%esp)       # imm = 0xFFF01F33
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver _IO_default_xsgetn, _IO_default_xsgetn@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_xsgetn
	addl	$-225286, (%esp)        # imm = 0xFFFC8FFA
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver posix_spawnattr_destroy, posix_spawnattr_destroy@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_destroy
	addl	$-708330, (%esp)        # imm = 0xFFF53116
	calll	opaquePredicate
	jne	.chain_16
	#APP
.symver setxattr, setxattr@GLIBC_2.3

	#NO_APP
	pushl	$setxattr
	addl	$-787446, (%esp)        # imm = 0xFFF3FC0A
	retl
	#APP
.resume_16:
	#NO_APP
	popfl
	adcl	$0, .L__profc_selection+28
	movl	%eax, .L__profc_selection+24
	pushfl
	calll	.chain_17
	jmp	.resume_17
	#APP
.chain_17:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __recv_chk, __recv_chk@GLIBC_2.4

	#NO_APP
	pushl	$__recv_chk
	addl	$-864402, (%esp)        # imm = 0xFFF2CF6E
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __sigdelset, __sigdelset@GLIBC_2.0

	#NO_APP
	pushl	$__sigdelset
	addl	$-674893, (%esp)        # imm = 0xFFF5B3B3
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver preadv64, preadv64@GLIBC_2.10

	#NO_APP
	pushl	$preadv64
	addl	$-762874, (%esp)        # imm = 0xFFF45C06
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __gai_sigqueue, __gai_sigqueue@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gai_sigqueue
	addl	$-944278, (%esp)        # imm = 0xFFF1976A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver inet_ntop, inet_ntop@GLIBC_2.0

	#NO_APP
	pushl	$inet_ntop
	addl	$-935914, (%esp)        # imm = 0xFFF1B816
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver gethostbyname_r, gethostbyname_r@GLIBC_2.1.2

	#NO_APP
	pushl	$gethostbyname_r
	addl	$-1050621, (%esp)       # imm = 0xFFEFF803
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver key_setsecret, key_setsecret@GLIBC_2.1

	#NO_APP
	pushl	$key_setsecret
	addl	$-1002070, (%esp)       # imm = 0xFFF0B5AA
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver _IO_un_link, _IO_un_link@GLIBC_2.0

	#NO_APP
	pushl	$_IO_un_link
	addl	$-230026, (%esp)        # imm = 0xFFFC7D76
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __gethostname_chk, __gethostname_chk@GLIBC_2.4

	#NO_APP
	pushl	$__gethostname_chk
	addl	$-868454, (%esp)        # imm = 0xFFF2BF9A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __fpending, __fpending@GLIBC_2.2

	#NO_APP
	pushl	$__fpending
	addl	$-202310, (%esp)        # imm = 0xFFFCE9BA
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver _IO_file_overflow, _IO_file_overflow@GLIBC_2.1

	#NO_APP
	pushl	$_IO_file_overflow
	addl	$-365187, (%esp)        # imm = 0xFFFA6D7D
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver strfroml, strfroml@GLIBC_2.25

	#NO_APP
	pushl	$strfroml
	addl	$59226, (%esp)          # imm = 0xE75A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver ether_line, ether_line@GLIBC_2.0

	#NO_APP
	pushl	$ether_line
	addl	$-577500, (%esp)        # imm = 0xFFF73024
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver sendfile, sendfile@GLIBC_2.1

	#NO_APP
	pushl	$sendfile
	addl	$-890035, (%esp)        # imm = 0xFFF26B4D
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver _nss_files_parse_pwent, _nss_files_parse_pwent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_pwent
	addl	$-540870, (%esp)        # imm = 0xFFF7BF3A
	calll	opaquePredicate
	jne	.chain_17
	#APP
.symver __libc_mallopt, __libc_mallopt@GLIBC_2.0

	#NO_APP
	pushl	$__libc_mallopt
	addl	$-405763, (%esp)        # imm = 0xFFF9CEFD
	retl
	#APP
.resume_17:
	#NO_APP
	popfl
.Ltmp21:
	.loc	1 34 16 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:34:16
	movl	12(%ebp), %ecx
	.loc	1 34 11 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:34:11
	movl	(%eax,%ecx,4), %ecx
	pushfl
	calll	.chain_18
	jmp	.resume_18
	#APP
.chain_18:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getgrent_r, getgrent_r@GLIBC_2.0

	#NO_APP
	pushl	$getgrent_r
	addl	$-1064694, (%esp)       # imm = 0xFFEFC10A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getprotobynumber_r, getprotobynumber_r@GLIBC_2.0

	#NO_APP
	pushl	$getprotobynumber_r
	addl	$-1091394, (%esp)       # imm = 0xFFEF58BE
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver endusershell, endusershell@GLIBC_2.0

	#NO_APP
	pushl	$endusershell
	addl	$-769126, (%esp)        # imm = 0xFFF4439A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __isoc99_vsscanf, __isoc99_vsscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vsscanf
	addl	$-150646, (%esp)        # imm = 0xFFFDB38A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver clntudp_create, clntudp_create@GLIBC_2.0

	#NO_APP
	pushl	$clntudp_create
	addl	$-1000886, (%esp)       # imm = 0xFFF0BA4A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __asprintf_chk, __asprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__asprintf_chk
	addl	$-1034305, (%esp)       # imm = 0xFFF037BF
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-758998, (%esp)        # imm = 0xFFF46B2A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver xdr_getcredres, xdr_getcredres@GLIBC_2.1

	#NO_APP
	pushl	$xdr_getcredres
	addl	$-596941, (%esp)        # imm = 0xFFF6E433
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __underflow, __underflow@GLIBC_2.0

	#NO_APP
	pushl	$__underflow
	addl	$-388513, (%esp)        # imm = 0xFFFA125F
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __strfmon_l, __strfmon_l@GLIBC_2.1

	#NO_APP
	pushl	$__strfmon_l
	addl	$4282, (%esp)           # imm = 0x10BA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver posix_spawn, posix_spawn@GLIBC_2.15

	#NO_APP
	pushl	$posix_spawn
	addl	$-865473, (%esp)        # imm = 0xFFF2CB3F
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver fgetws_unlocked, fgetws_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$fgetws_unlocked
	addl	$-172278, (%esp)        # imm = 0xFFFD5F0A
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver xdr_getcredres, xdr_getcredres@GLIBC_2.1

	#NO_APP
	pushl	$xdr_getcredres
	addl	$-983946, (%esp)        # imm = 0xFFF0FC76
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver gethostbyname_r, gethostbyname_r@GLIBC_2.1.2

	#NO_APP
	pushl	$gethostbyname_r
	addl	$-1041441, (%esp)       # imm = 0xFFF01BDF
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver pthread_mutex_unlock, pthread_mutex_unlock@GLIBC_2.0

	#NO_APP
	pushl	$pthread_mutex_unlock
	addl	$-861530, (%esp)        # imm = 0xFFF2DAA6
	pushl	$-48
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __vwprintf_chk, __vwprintf_chk@GLIBC_2.4

	#NO_APP
	pushl	$__vwprintf_chk
	addl	$-1041485, (%esp)       # imm = 0xFFF01BB3
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver fgetgrent, fgetgrent@GLIBC_2.0

	#NO_APP
	pushl	$fgetgrent
	addl	$-692433, (%esp)        # imm = 0xFFF56F2F
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __libc_current_sigrtmax_private, __libc_current_sigrtmax_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_current_sigrtmax_private
	addl	$66950, (%esp)          # imm = 0x10586
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver getnetent, getnetent@GLIBC_2.0

	#NO_APP
	pushl	$getnetent
	addl	$-1045393, (%esp)       # imm = 0xFFF00C6F
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-798534, (%esp)        # imm = 0xFFF3D0BA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver remove, remove@GLIBC_2.0

	#NO_APP
	pushl	$remove
	addl	$-148742, (%esp)        # imm = 0xFFFDBAFA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __fortify_fail, __fortify_fail@GLIBC_PRIVATE

	#NO_APP
	pushl	$__fortify_fail
	addl	$-1016179, (%esp)       # imm = 0xFFF07E8D
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver fgetpwent, fgetpwent@GLIBC_2.0

	#NO_APP
	pushl	$fgetpwent
	addl	$-536630, (%esp)        # imm = 0xFFF7CFCA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __xstat, __xstat@GLIBC_2.0

	#NO_APP
	pushl	$__xstat
	addl	$-395164, (%esp)        # imm = 0xFFF9F864
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$-411763, (%esp)        # imm = 0xFFF9B78D
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __libc_current_sigrtmin_private, __libc_current_sigrtmin_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_current_sigrtmin_private
	addl	$75466, (%esp)          # imm = 0x126CA
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver fattach, fattach@GLIBC_2.1

	#NO_APP
	pushl	$fattach
	addl	$-1170227, (%esp)       # imm = 0xFFEE24CD
	calll	opaquePredicate
	jne	.chain_18
	#APP
.symver __pause_nocancel, __pause_nocancel@GLIBC_PRIVATE

	#NO_APP
	pushl	$__pause_nocancel
	addl	$-749382, (%esp)        # imm = 0xFFF490BA
	retl
	#APP
.resume_18:
	#NO_APP
	popfl
	.loc	1 34 21                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:34:21
	movl	(%eax,%edx,4), %eax
	.loc	1 34 19                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:34:19
	cmpl	%eax, %ecx
.Ltmp22:
	.loc	1 34 11                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:34:11
	jle	.LBB1_6
# %bb.5:
	movl	.L__profc_selection+32, %eax
	pushfl
	calll	.chain_19
	jmp	.resume_19
	#APP
.chain_19:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver catclose, catclose@GLIBC_2.0

	#NO_APP
	pushl	$catclose
	addl	$467779, (%esp)         # imm = 0x72343
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver __libc_allocate_rtsig, __libc_allocate_rtsig@GLIBC_2.1

	#NO_APP
	pushl	$__libc_allocate_rtsig
	addl	$66886, (%esp)          # imm = 0x10546
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver getrpcport, getrpcport@GLIBC_2.0

	#NO_APP
	pushl	$getrpcport
	addl	$-958742, (%esp)        # imm = 0xFFF15EEA
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver mcheck, mcheck@GLIBC_2.0

	#NO_APP
	pushl	$mcheck
	addl	$-272170, (%esp)        # imm = 0xFFFBD8D6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver closelog, closelog@GLIBC_2.0

	#NO_APP
	pushl	$closelog
	addl	$-946845, (%esp)        # imm = 0xFFF18D63
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver __realpath_chk, __realpath_chk@GLIBC_2.4

	#NO_APP
	pushl	$__realpath_chk
	addl	$-864278, (%esp)        # imm = 0xFFF2CFEA
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver xdr_int64_t, xdr_int64_t@GLIBC_2.1.1

	#NO_APP
	pushl	$xdr_int64_t
	addl	$-1027946, (%esp)       # imm = 0xFFF05096
	calll	opaquePredicate
	jne	.chain_19
	#APP
.symver getaliasent_r, getaliasent_r@GLIBC_2.0

	#NO_APP
	pushl	$getaliasent_r
	addl	$-1091302, (%esp)       # imm = 0xFFEF591A
	retl
	#APP
.resume_19:
	#NO_APP
	popfl
	adcl	$0, .L__profc_selection+36
	movl	%eax, .L__profc_selection+32
	pushfl
	calll	.chain_20
	jmp	.resume_20
	#APP
.chain_20:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver getpmsg, getpmsg@GLIBC_2.1

	#NO_APP
	pushl	$getpmsg
	addl	$-1025730, (%esp)       # imm = 0xFFF0593E
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver endhostent, endhostent@GLIBC_2.0

	#NO_APP
	pushl	$endhostent
	addl	$-499309, (%esp)        # imm = 0xFFF86193
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __isoc99_fwscanf, __isoc99_fwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_fwscanf
	addl	$-456858, (%esp)        # imm = 0xFFF90766
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver printf_size, printf_size@GLIBC_2.1

	#NO_APP
	pushl	$printf_size
	addl	$-69110, (%esp)         # imm = 0xFFFEF20A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __copy_grp, __copy_grp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__copy_grp
	addl	$-543882, (%esp)        # imm = 0xFFF7B376
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver _IO_str_seekoff, _IO_str_seekoff@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_seekoff
	addl	$-407757, (%esp)        # imm = 0xFFF9C733
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver unlinkat, unlinkat@GLIBC_2.4

	#NO_APP
	pushl	$unlinkat
	addl	$-720630, (%esp)        # imm = 0xFFF5010A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __internal_getnetgrent_r, __internal_getnetgrent_r@GLIBC_PRIVATE

	#NO_APP
	pushl	$__internal_getnetgrent_r
	addl	$-910842, (%esp)        # imm = 0xFFF21A06
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver ppoll, ppoll@GLIBC_2.4

	#NO_APP
	pushl	$ppoll
	addl	$-743318, (%esp)        # imm = 0xFFF4A86A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver catclose, catclose@GLIBC_2.0

	#NO_APP
	pushl	$catclose
	addl	$89226, (%esp)          # imm = 0x15C8A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver pwritev2, pwritev2@GLIBC_2.26

	#NO_APP
	pushl	$pwritev2
	addl	$-900883, (%esp)        # imm = 0xFFF240ED
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver inet6_opt_init, inet6_opt_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_init
	addl	$-918630, (%esp)        # imm = 0xFFF1FB9A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver strfromf, strfromf@GLIBC_2.25

	#NO_APP
	pushl	$strfromf
	addl	$372292, (%esp)         # imm = 0x5AE44
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __libc_allocate_rtsig_private, __libc_allocate_rtsig_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_allocate_rtsig_private
	addl	$-69555, (%esp)         # imm = 0xFFFEF04D
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver mlock, mlock@GLIBC_2.0

	#NO_APP
	pushl	$mlock
	addl	$-774022, (%esp)        # imm = 0xFFF4307A
	calll	opaquePredicate
	jne	.chain_20
	#APP
.symver __wcscpy_chk, __wcscpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcscpy_chk
	addl	$-1009827, (%esp)       # imm = 0xFFF0975D
	retl
	#APP
.resume_20:
	#NO_APP
	popfl
.Ltmp23:
	.loc	1 35 21 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:35:21
	movl	12(%ebp), %ecx
	pushfl
	calll	.chain_21
	jmp	.resume_21
	#APP
.chain_21:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver xdr_void, xdr_void@GLIBC_2.0

	#NO_APP
	pushl	$xdr_void
	addl	$-1017234, (%esp)       # imm = 0xFFF07A6E
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __isnanl, __isnanl@GLIBC_2.0

	#NO_APP
	pushl	$__isnanl
	addl	$465171, (%esp)         # imm = 0x71913
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __getpgid, __getpgid@GLIBC_2.0

	#NO_APP
	pushl	$__getpgid
	addl	$-555386, (%esp)        # imm = 0xFFF78686
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver inet6_opt_find, inet6_opt_find@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_find
	addl	$-919574, (%esp)        # imm = 0xFFF1F7EA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-824842, (%esp)        # imm = 0xFFF369F6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __lxstat, __lxstat@GLIBC_2.0

	#NO_APP
	pushl	$__lxstat
	addl	$-881517, (%esp)        # imm = 0xFFF28C93
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __nss_configure_lookup, __nss_configure_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_configure_lookup
	addl	$-946854, (%esp)        # imm = 0xFFF18D5A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __libc_alloc_buffer_copy_string, __libc_alloc_buffer_copy_string@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_alloc_buffer_copy_string
	addl	$-278394, (%esp)        # imm = 0xFFFBC086
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver preadv, preadv@GLIBC_2.10

	#NO_APP
	pushl	$preadv
	addl	$-754198, (%esp)        # imm = 0xFFF47DEA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver cfsetospeed, cfsetospeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetospeed
	addl	$-749942, (%esp)        # imm = 0xFFF48E8A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver svcfd_create, svcfd_create@GLIBC_2.0

	#NO_APP
	pushl	$svcfd_create
	addl	$-1156739, (%esp)       # imm = 0xFFEE597D
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getmntent, getmntent@GLIBC_2.0

	#NO_APP
	pushl	$getmntent
	addl	$-762774, (%esp)        # imm = 0xFFF45C6A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver vfprintf, vfprintf@GLIBC_2.0

	#NO_APP
	pushl	$vfprintf
	addl	$274628, (%esp)         # imm = 0x430C4
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
.symver pmap_unset, pmap_unset@GLIBC_2.0

	#NO_APP
	pushl	$pmap_unset
	addl	$-959414, (%esp)        # imm = 0xFFF15C4A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getentropy, getentropy@GLIBC_2.25

	#NO_APP
	pushl	$getentropy
	addl	$-84115, (%esp)         # imm = 0xFFFEB76D
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getspent, getspent@GLIBC_2.0

	#NO_APP
	pushl	$getspent
	addl	$-895806, (%esp)        # imm = 0xFFF254C2
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver cfsetospeed, cfsetospeed@GLIBC_2.0

	#NO_APP
	pushl	$cfsetospeed
	addl	$-749942, (%esp)        # imm = 0xFFF48E8A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver setgroups, setgroups@GLIBC_2.0

	#NO_APP
	pushl	$setgroups
	addl	$-529702, (%esp)        # imm = 0xFFF7EADA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-1021569, (%esp)       # imm = 0xFFF0697F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver ntp_gettime, ntp_gettime@GLIBC_2.1

	#NO_APP
	pushl	$ntp_gettime
	addl	$-520390, (%esp)        # imm = 0xFFF80F3A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getdirentries64, getdirentries64@GLIBC_2.2

	#NO_APP
	pushl	$getdirentries64
	addl	$-148589, (%esp)        # imm = 0xFFFDBB93
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __clock_gettime, __clock_gettime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_gettime
	addl	$-1021409, (%esp)       # imm = 0xFFF06A1F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __ctype_b_loc, __ctype_b_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_b_loc
	addl	$112250, (%esp)         # imm = 0x1B67A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __sbrk, __sbrk@GLIBC_2.0

	#NO_APP
	pushl	$__sbrk
	addl	$-918657, (%esp)        # imm = 0xFFF1FB7F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver isalnum, isalnum@GLIBC_2.0

	#NO_APP
	pushl	$isalnum
	addl	$114650, (%esp)         # imm = 0x1BFDA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$65910, (%esp)          # imm = 0x10176
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __finitel, __finitel@GLIBC_2.0

	#NO_APP
	pushl	$__finitel
	addl	$-78657, (%esp)         # imm = 0xFFFECCBF
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_svc_pollfd
	addl	$-1014714, (%esp)       # imm = 0xFFF08446
	pushl	$-32
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-246477, (%esp)        # imm = 0xFFFC3D33
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver setutxent, setutxent@GLIBC_2.1

	#NO_APP
	pushl	$setutxent
	addl	$-1202129, (%esp)       # imm = 0xFFEDA82F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver pthread_condattr_destroy, pthread_condattr_destroy@GLIBC_2.0

	#NO_APP
	pushl	$pthread_condattr_destroy
	addl	$-859994, (%esp)        # imm = 0xFFF2E0A6
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __isspace_l, __isspace_l@GLIBC_2.1

	#NO_APP
	pushl	$__isspace_l
	addl	$-52513, (%esp)         # imm = 0xFFFF32DF
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver svcerr_progvers, svcerr_progvers@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_progvers
	addl	$-1008278, (%esp)       # imm = 0xFFF09D6A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __setmntent, __setmntent@GLIBC_2.2

	#NO_APP
	pushl	$__setmntent
	addl	$-763254, (%esp)        # imm = 0xFFF45A8A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-94115, (%esp)         # imm = 0xFFFE905D
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-793926, (%esp)        # imm = 0xFFF3E2BA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_getline, _IO_getline@GLIBC_2.0

	#NO_APP
	pushl	$_IO_getline
	addl	$147268, (%esp)         # imm = 0x23F44
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver wscanf, wscanf@GLIBC_2.2

	#NO_APP
	pushl	$wscanf
	addl	$-320435, (%esp)        # imm = 0xFFFB1C4D
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver clntraw_create, clntraw_create@GLIBC_2.0

	#NO_APP
	pushl	$clntraw_create
	addl	$-957606, (%esp)        # imm = 0xFFF1635A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver inet6_rth_space, inet6_rth_space@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_space
	addl	$-1064787, (%esp)       # imm = 0xFFEFC0AD
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver wcstombs, wcstombs@GLIBC_2.0

	#NO_APP
	pushl	$wcstombs
	addl	$65114, (%esp)          # imm = 0xFE5A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getmsg, getmsg@GLIBC_2.1

	#NO_APP
	pushl	$getmsg
	addl	$-1025618, (%esp)       # imm = 0xFFF059AE
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __rpc_thread_svc_fdset, __rpc_thread_svc_fdset@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_svc_fdset
	addl	$-1006086, (%esp)       # imm = 0xFFF0A5FA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-797046, (%esp)        # imm = 0xFFF3D68A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __strncpy_gg, __strncpy_gg@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncpy_gg
	addl	$-303846, (%esp)        # imm = 0xFFFB5D1A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver sgetsgent, sgetsgent@GLIBC_2.10

	#NO_APP
	pushl	$sgetsgent
	addl	$-987537, (%esp)        # imm = 0xFFF0EE6F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getipv4sourcefilter, getipv4sourcefilter@GLIBC_2.3.4

	#NO_APP
	pushl	$getipv4sourcefilter
	addl	$-916998, (%esp)        # imm = 0xFFF201FA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver setbuf, setbuf@GLIBC_2.0

	#NO_APP
	pushl	$setbuf
	addl	$181219, (%esp)         # imm = 0x2C3E3
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __libc_dlvsym, __libc_dlvsym@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlvsym
	addl	$-1205137, (%esp)       # imm = 0xFFED9C6F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver posix_spawn_file_actions_adddup2, posix_spawn_file_actions_adddup2@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawn_file_actions_adddup2
	addl	$-699558, (%esp)        # imm = 0xFFF5535A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_ferror, _IO_ferror@GLIBC_2.0

	#NO_APP
	pushl	$_IO_ferror
	addl	$-359073, (%esp)        # imm = 0xFFFA855F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver getwchar_unlocked, getwchar_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$getwchar_unlocked
	addl	$-171798, (%esp)        # imm = 0xFFFD60EA
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __wcstold_internal, __wcstold_internal@GLIBC_2.0

	#NO_APP
	pushl	$__wcstold_internal
	addl	$-402586, (%esp)        # imm = 0xFFF9DB66
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __libc_current_sigrtmax_private, __libc_current_sigrtmax_private@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_current_sigrtmax_private
	addl	$-89761, (%esp)         # imm = 0xFFFEA15F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __strcoll_l, __strcoll_l@GLIBC_2.1

	#NO_APP
	pushl	$__strcoll_l
	addl	$-296506, (%esp)        # imm = 0xFFFB79C6
	pushl	$-64
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver fts_close, fts_close@GLIBC_2.0

	#NO_APP
	pushl	$fts_close
	addl	$-908669, (%esp)        # imm = 0xFFF22283
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver xdr_double, xdr_double@GLIBC_2.0

	#NO_APP
	pushl	$xdr_double
	addl	$-1133185, (%esp)       # imm = 0xFFEEB57F
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver _IO_init_wmarker, _IO_init_wmarker@GLIBC_2.2

	#NO_APP
	pushl	$_IO_init_wmarker
	addl	$-189258, (%esp)        # imm = 0xFFFD1CB6
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __poll, __poll@GLIBC_2.1

	#NO_APP
	pushl	$__poll
	addl	$-908289, (%esp)        # imm = 0xFFF223FF
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver __sigaddset, __sigaddset@GLIBC_2.0

	#NO_APP
	pushl	$__sigaddset
	addl	$-1053366, (%esp)       # imm = 0xFFEFED4A
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver posix_spawnattr_getsigmask, posix_spawnattr_getsigmask@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_getsigmask
	addl	$-390876, (%esp)        # imm = 0xFFFA0924
	calll	opaquePredicate
	jne	.chain_21
	#APP
.symver wcstok, wcstok@GLIBC_2.0

	#NO_APP
	pushl	$wcstok
	addl	$-387222, (%esp)        # imm = 0xFFFA176A
	retl
	#APP
.resume_21:
	#NO_APP
	popfl
	.loc	1 36 24                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:36:24
	movl	16(%ebp), %ecx
	.loc	1 36 19 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:36:19
	movl	(%eax,%ecx,4), %ecx
	pushfl
	calll	.chain_22
	jmp	.resume_22
	#APP
.chain_22:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __syslog_chk, __syslog_chk@GLIBC_2.4

	#NO_APP
	pushl	$__syslog_chk
	addl	$-772246, (%esp)        # imm = 0xFFF4376A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-280418, (%esp)        # imm = 0xFFFBB89E
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver getpwent_r, getpwent_r@GLIBC_2.1.2

	#NO_APP
	pushl	$getpwent_r
	addl	$-539046, (%esp)        # imm = 0xFFF7C65A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver inet6_rth_reverse, inet6_rth_reverse@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_reverse
	addl	$-920214, (%esp)        # imm = 0xFFF1F56A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-483606, (%esp)        # imm = 0xFFF89EEA
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __cmsg_nxthdr, __cmsg_nxthdr@GLIBC_2.0

	#NO_APP
	pushl	$__cmsg_nxthdr
	addl	$-967297, (%esp)        # imm = 0xFFF13D7F
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __readlink_chk, __readlink_chk@GLIBC_2.4

	#NO_APP
	pushl	$__readlink_chk
	addl	$-863942, (%esp)        # imm = 0xFFF2D13A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __munmap, __munmap@GLIBC_PRIVATE

	#NO_APP
	pushl	$__munmap
	addl	$-395021, (%esp)        # imm = 0xFFF9F8F3
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver xdrrec_create, xdrrec_create@GLIBC_2.0

	#NO_APP
	pushl	$xdrrec_create
	addl	$-1135313, (%esp)       # imm = 0xFFEEAD2F
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __snprintf, __snprintf@GLIBC_PRIVATE

	#NO_APP
	pushl	$__snprintf
	addl	$-72054, (%esp)         # imm = 0xFFFEE68A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$159, (%esp)
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver envz_entry, envz_entry@GLIBC_2.0

	#NO_APP
	pushl	$envz_entry
	addl	$-286790, (%esp)        # imm = 0xFFFB9FBA
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __libc_init_first, __libc_init_first@GLIBC_2.0

	#NO_APP
	pushl	$__libc_init_first
	addl	$159238, (%esp)         # imm = 0x26E06
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver _IO_iter_next, _IO_iter_next@GLIBC_2.2

	#NO_APP
	pushl	$_IO_iter_next
	addl	$-396401, (%esp)        # imm = 0xFFF9F38F
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __read_chk, __read_chk@GLIBC_2.4

	#NO_APP
	pushl	$__read_chk
	addl	$-871978, (%esp)        # imm = 0xFFF2B1D6
	pushl	$-52
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver eventfd_read, eventfd_read@GLIBC_2.7

	#NO_APP
	pushl	$eventfd_read
	addl	$-968717, (%esp)        # imm = 0xFFF137F3
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver gethostent, gethostent@GLIBC_2.0

	#NO_APP
	pushl	$gethostent
	addl	$-1042641, (%esp)       # imm = 0xFFF0172F
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver setlocale, setlocale@GLIBC_2.0

	#NO_APP
	pushl	$setlocale
	addl	$119510, (%esp)         # imm = 0x1D2D6
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver perror, perror@GLIBC_2.0

	#NO_APP
	pushl	$perror
	addl	$-310753, (%esp)        # imm = 0xFFFB421F
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver signalfd, signalfd@GLIBC_2.7

	#NO_APP
	pushl	$signalfd
	addl	$-794214, (%esp)        # imm = 0xFFF3E19A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver _IO_printf, _IO_printf@GLIBC_2.0

	#NO_APP
	pushl	$_IO_printf
	addl	$-71974, (%esp)         # imm = 0xFFFEE6DA
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver inet6_rth_init, inet6_rth_init@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_init
	addl	$-1064867, (%esp)       # imm = 0xFFEFC05D
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver __strpbrk_g, __strpbrk_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strpbrk_g
	addl	$-304358, (%esp)        # imm = 0xFFFB5B1A
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver pthread_attr_setinheritsched, pthread_attr_setinheritsched@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_setinheritsched
	addl	$-539036, (%esp)        # imm = 0xFFF7C664
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver key_gendes, key_gendes@GLIBC_2.1

	#NO_APP
	pushl	$key_gendes
	addl	$-1147987, (%esp)       # imm = 0xFFEE7BAD
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver putwc, putwc@GLIBC_2.2

	#NO_APP
	pushl	$putwc
	addl	$-174134, (%esp)        # imm = 0xFFFD57CA
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver fscanf, fscanf@GLIBC_2.0

	#NO_APP
	pushl	$fscanf
	addl	$-290115, (%esp)        # imm = 0xFFFB92BD
	calll	opaquePredicate
	jne	.chain_22
	#APP
.symver getnetbyname_r, getnetbyname_r@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname_r
	addl	$-1090662, (%esp)       # imm = 0xFFEF5B9A
	retl
	#APP
.resume_22:
	#NO_APP
	popfl
	.loc	1 36 17                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:36:17
	movl	%ecx, (%eax,%edx,4)
	pushfl
	calll	.chain_23
	jmp	.resume_23
	#APP
.chain_23:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver munlockall, munlockall@GLIBC_2.0

	#NO_APP
	pushl	$munlockall
	addl	$-774786, (%esp)        # imm = 0xFFF42D7E
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver iconv_open, iconv_open@GLIBC_2.1

	#NO_APP
	pushl	$iconv_open
	addl	$543571, (%esp)         # imm = 0x84B53
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __isprint_l, __isprint_l@GLIBC_2.1

	#NO_APP
	pushl	$__isprint_l
	addl	$104326, (%esp)         # imm = 0x19786
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver ispunct, ispunct@GLIBC_2.0

	#NO_APP
	pushl	$ispunct
	addl	$114090, (%esp)         # imm = 0x1BDAA
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$165808, (%esp)         # imm = 0x287B0
	pushl	$-72
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __wcsncpy_chk, __wcsncpy_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncpy_chk
	addl	$-1039805, (%esp)       # imm = 0xFFF02243
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver _IO_file_open, _IO_file_open@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_open
	addl	$-217622, (%esp)        # imm = 0xFFFCADEA
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver strfromf128, strfromf128@GLIBC_2.26

	#NO_APP
	pushl	$strfromf128
	addl	$-15898, (%esp)         # imm = 0xC1E6
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __fgetws_chk, __fgetws_chk@GLIBC_2.4

	#NO_APP
	pushl	$__fgetws_chk
	addl	$-867654, (%esp)        # imm = 0xFFF2C2BA
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __getmntent_r, __getmntent_r@GLIBC_2.2

	#NO_APP
	pushl	$__getmntent_r
	addl	$-763478, (%esp)        # imm = 0xFFF459AA
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver chflags, chflags@GLIBC_2.0

	#NO_APP
	pushl	$chflags
	addl	$-911395, (%esp)        # imm = 0xFFF217DD
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver fanotify_init, fanotify_init@GLIBC_2.13

	#NO_APP
	pushl	$fanotify_init
	addl	$-798150, (%esp)        # imm = 0xFFF3D23A
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __isoc99_vfwscanf, __isoc99_vfwscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfwscanf
	addl	$-136924, (%esp)        # imm = 0xFFFDE924
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver _IO_default_doallocate, _IO_default_doallocate@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_doallocate
	addl	$-370915, (%esp)        # imm = 0xFFFA571D
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver __memset_ccn_by4, __memset_ccn_by4@GLIBC_2.1.1

	#NO_APP
	pushl	$__memset_ccn_by4
	addl	$-303462, (%esp)        # imm = 0xFFFB5E9A
	calll	opaquePredicate
	jne	.chain_23
	#APP
.symver sigvec, sigvec@GLIBC_2.0

	#NO_APP
	pushl	$sigvec
	addl	$-67379, (%esp)         # imm = 0xFFFEF8CD
	retl
	#APP
.resume_23:
	#NO_APP
	popfl
	.loc	1 37 9 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:37:9
	movl	8(%ebp), %ecx
	pushfl
	calll	.chain_24
	jmp	.resume_24
	#APP
.chain_24:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __rpc_thread_createerr, __rpc_thread_createerr@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_createerr
	addl	$-1006166, (%esp)       # imm = 0xFFF0A5AA
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __libc_scratch_buffer_set_array_size, __libc_scratch_buffer_set_array_size@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_scratch_buffer_set_array_size
	addl	$-268930, (%esp)        # imm = 0xFFFBE57E
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver svc_register, svc_register@GLIBC_2.0

	#NO_APP
	pushl	$svc_register
	addl	$-1007030, (%esp)       # imm = 0xFFF0A24A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver clnt_spcreateerror, clnt_spcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_spcreateerror
	addl	$-994102, (%esp)        # imm = 0xFFF0D4CA
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver localeconv, localeconv@GLIBC_2.0

	#NO_APP
	pushl	$localeconv
	addl	$119242, (%esp)         # imm = 0x1D1CA
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver catopen, catopen@GLIBC_2.0

	#NO_APP
	pushl	$catopen
	addl	$-75249, (%esp)         # imm = 0xFFFEDA0F
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver posix_spawnattr_setpgroup, posix_spawnattr_setpgroup@GLIBC_2.2

	#NO_APP
	pushl	$posix_spawnattr_setpgroup
	addl	$-700246, (%esp)        # imm = 0xFFF550AA
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-414781, (%esp)        # imm = 0xFFF9ABC3
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver grantpt, grantpt@GLIBC_2.1

	#NO_APP
	pushl	$grantpt
	addl	$-1200289, (%esp)       # imm = 0xFFEDAF5F
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver getrlimit64, getrlimit64@GLIBC_2.1

	#NO_APP
	pushl	$getrlimit64
	addl	$-1088358, (%esp)       # imm = 0xFFEF649A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __nss_group_lookup, __nss_group_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_group_lookup
	addl	$-1256721, (%esp)       # imm = 0xFFECD2EF
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __iswupper_l, __iswupper_l@GLIBC_2.1

	#NO_APP
	pushl	$__iswupper_l
	addl	$-814278, (%esp)        # imm = 0xFFF3933A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __gconv_get_alias_db, __gconv_get_alias_db@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_get_alias_db
	addl	$153174, (%esp)         # imm = 0x25656
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __explicit_bzero_chk, __explicit_bzero_chk@GLIBC_2.25

	#NO_APP
	pushl	$__explicit_bzero_chk
	addl	$-1036193, (%esp)       # imm = 0xFFF0305F
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __umoddi3, __umoddi3@GLIBC_2.0

	#NO_APP
	pushl	$__umoddi3
	addl	$156918, (%esp)         # imm = 0x264F6
	pushl	$-48
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-1263357, (%esp)       # imm = 0xFFECB903
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver setlocale, setlocale@GLIBC_2.0

	#NO_APP
	pushl	$setlocale
	addl	$-37201, (%esp)         # imm = 0xFFFF6EAF
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver lldiv, lldiv@GLIBC_2.0

	#NO_APP
	pushl	$lldiv
	addl	$57334, (%esp)          # imm = 0xDFF6
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __libc_pthread_init, __libc_pthread_init@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_pthread_init
	addl	$-1019137, (%esp)       # imm = 0xFFF072FF
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver _IO_sprintf, _IO_sprintf@GLIBC_2.0

	#NO_APP
	pushl	$_IO_sprintf
	addl	$-72134, (%esp)         # imm = 0xFFFEE63A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __open_nocancel, __open_nocancel@GLIBC_PRIVATE

	#NO_APP
	pushl	$__open_nocancel
	addl	$-748870, (%esp)        # imm = 0xFFF492BA
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver pwritev64v2, pwritev64v2@GLIBC_2.26

	#NO_APP
	pushl	$pwritev64v2
	addl	$-901331, (%esp)        # imm = 0xFFF23F2D
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver acct, acct@GLIBC_2.0

	#NO_APP
	pushl	$acct
	addl	$-758758, (%esp)        # imm = 0xFFF46C1A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver inet6_option_alloc, inet6_option_alloc@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_alloc
	addl	$-604780, (%esp)        # imm = 0xFFF6C594
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver printf, printf@GLIBC_2.0

	#NO_APP
	pushl	$printf
	addl	$-216867, (%esp)        # imm = 0xFFFCB0DD
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-231782, (%esp)        # imm = 0xFFFC769A
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver __endmntent, __endmntent@GLIBC_2.2

	#NO_APP
	pushl	$__endmntent
	addl	$-908291, (%esp)        # imm = 0xFFF223FD
	calll	opaquePredicate
	jne	.chain_24
	#APP
.symver ctermid, ctermid@GLIBC_2.0

	#NO_APP
	pushl	$ctermid
	addl	$-23750, (%esp)         # imm = 0xA33A
	retl
	#APP
.resume_24:
	#NO_APP
	popfl
	.loc	1 37 17 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:37:17
	movl	%eax, (%ecx,%edx,4)
.Ltmp24:
.LBB1_6:
	.loc	1 0 17                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:17
	xorl	%eax, %eax
	pushfl
	calll	.chain_25
	jmp	.resume_25
	#APP
.chain_25:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver rexec, rexec@GLIBC_2.0

	#NO_APP
	pushl	$rexec
	addl	$-899522, (%esp)        # imm = 0xFFF2463E
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-582749, (%esp)        # imm = 0xFFF71BA3
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver _nss_files_parse_spent, _nss_files_parse_spent@GLIBC_PRIVATE

	#NO_APP
	pushl	$_nss_files_parse_spent
	addl	$-827930, (%esp)        # imm = 0xFFF35DE6
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __ttyname_r_chk, __ttyname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ttyname_r_chk
	addl	$-868390, (%esp)        # imm = 0xFFF2BFDA
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver quick_exit, quick_exit@GLIBC_2.10

	#NO_APP
	pushl	$quick_exit
	addl	$-1062058, (%esp)       # imm = 0xFFEFCB56
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver llseek, llseek@GLIBC_2.0

	#NO_APP
	pushl	$llseek
	addl	$-886205, (%esp)        # imm = 0xFFF27A43
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __strsep_g, __strsep_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strsep_g
	addl	$-278166, (%esp)        # imm = 0xFFFBC16A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver bindresvport, bindresvport@GLIBC_2.0

	#NO_APP
	pushl	$bindresvport
	addl	$-964570, (%esp)        # imm = 0xFFF14826
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-918742, (%esp)        # imm = 0xFFF1FB2A
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver xdr_uint32_t, xdr_uint32_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint32_t
	addl	$-1020230, (%esp)       # imm = 0xFFF06EBA
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver _IO_fgets, _IO_fgets@GLIBC_2.0

	#NO_APP
	pushl	$_IO_fgets
	addl	$-304195, (%esp)        # imm = 0xFFFB5BBD
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver mkstemps, mkstemps@GLIBC_2.11

	#NO_APP
	pushl	$mkstemps
	addl	$-760630, (%esp)        # imm = 0xFFF464CA
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver svcudp_bufcreate, svcudp_bufcreate@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_bufcreate
	addl	$-702012, (%esp)        # imm = 0xFFF549C4
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver _IO_file_doallocate, _IO_file_doallocate@GLIBC_2.0

	#NO_APP
	pushl	$_IO_file_doallocate
	addl	$-301747, (%esp)        # imm = 0xFFFB654D
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver __strchrnul_c, __strchrnul_c@GLIBC_2.1.1

	#NO_APP
	pushl	$__strchrnul_c
	addl	$-304134, (%esp)        # imm = 0xFFFB5BFA
	calll	opaquePredicate
	jne	.chain_25
	#APP
.symver posix_madvise, posix_madvise@GLIBC_2.2

	#NO_APP
	pushl	$posix_madvise
	addl	$-847891, (%esp)        # imm = 0xFFF30FED
	retl
	#APP
.resume_25:
	#NO_APP
	popfl
	.loc	1 39 23 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:39:23
	movl	12(%ebp), %ecx
	pushfl
	calll	.chain_26
	jmp	.resume_26
	#APP
.chain_26:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver gethostbyname_r, gethostbyname_r@GLIBC_2.1.2

	#NO_APP
	pushl	$gethostbyname_r
	addl	$-876278, (%esp)        # imm = 0xFFF2A10A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver getxattr, getxattr@GLIBC_2.3

	#NO_APP
	pushl	$getxattr
	addl	$-787094, (%esp)        # imm = 0xFFF3FD6A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver stime, stime@GLIBC_2.0

	#NO_APP
	pushl	$stime
	addl	$-648769, (%esp)        # imm = 0xFFF619BF
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver clnt_pcreateerror, clnt_pcreateerror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_pcreateerror
	addl	$-994374, (%esp)        # imm = 0xFFF0D3BA
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver cfgetispeed, cfgetispeed@GLIBC_2.0

	#NO_APP
	pushl	$cfgetispeed
	addl	$-371325, (%esp)        # imm = 0xFFFA5583
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver preadv64v2, preadv64v2@GLIBC_2.26

	#NO_APP
	pushl	$preadv64v2
	addl	$-920673, (%esp)        # imm = 0xFFF1F39F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver getpass, getpass@GLIBC_2.0

	#NO_APP
	pushl	$getpass
	addl	$-769302, (%esp)        # imm = 0xFFF442EA
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_free_backup_area, _IO_free_backup_area@GLIBC_2.0

	#NO_APP
	pushl	$_IO_free_backup_area
	addl	$-388225, (%esp)        # imm = 0xFFFA137F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver xdr_u_long, xdr_u_long@GLIBC_2.0

	#NO_APP
	pushl	$xdr_u_long
	addl	$-1016822, (%esp)       # imm = 0xFFF07C0A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver cbc_crypt, cbc_crypt@GLIBC_2.1

	#NO_APP
	pushl	$cbc_crypt
	addl	$-980298, (%esp)        # imm = 0xFFF10AB6
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-1139857, (%esp)       # imm = 0xFFEE9B6F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver psiginfo, psiginfo@GLIBC_2.10

	#NO_APP
	pushl	$psiginfo
	addl	$-159274, (%esp)        # imm = 0xFFFD91D6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-925581, (%esp)        # imm = 0xFFF1E073
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_wfile_seekoff, _IO_wfile_seekoff@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_seekoff
	addl	$-350897, (%esp)        # imm = 0xFFFAA54F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver xdr_int, xdr_int@GLIBC_2.0

	#NO_APP
	pushl	$xdr_int
	addl	$-1025226, (%esp)       # imm = 0xFFF05B36
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd@GLIBC_2.2.3

	#NO_APP
	pushl	$__rpc_thread_svc_pollfd
	addl	$-1171425, (%esp)       # imm = 0xFFEE201F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver pthread_attr_getinheritsched, pthread_attr_getinheritsched@GLIBC_2.0

	#NO_APP
	pushl	$pthread_attr_getinheritsched
	addl	$-850646, (%esp)        # imm = 0xFFF3052A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-857042, (%esp)        # imm = 0xFFF2EC2E
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver iopl, iopl@GLIBC_2.0

	#NO_APP
	pushl	$iopl
	addl	$-793334, (%esp)        # imm = 0xFFF3E50A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_file_setbuf, _IO_file_setbuf@GLIBC_2.1

	#NO_APP
	pushl	$_IO_file_setbuf
	addl	$-209558, (%esp)        # imm = 0xFFFCCD6A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver svcerr_noprog, svcerr_noprog@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_noprog
	addl	$-1008166, (%esp)       # imm = 0xFFF09DDA
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver explicit_bzero, explicit_bzero@GLIBC_2.25

	#NO_APP
	pushl	$explicit_bzero
	addl	$-470321, (%esp)        # imm = 0xFFF8D2CF
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __iswctype, __iswctype@GLIBC_2.0

	#NO_APP
	pushl	$__iswctype
	addl	$-812262, (%esp)        # imm = 0xFFF39B1A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver svcerr_progvers, svcerr_progvers@GLIBC_2.0

	#NO_APP
	pushl	$svcerr_progvers
	addl	$-629725, (%esp)        # imm = 0xFFF66423
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __libc_fcntl64, __libc_fcntl64@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_fcntl64
	addl	$-878705, (%esp)        # imm = 0xFFF2978F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver getspnam_r, getspnam_r@GLIBC_2.0

	#NO_APP
	pushl	$getspnam_r
	addl	$-1089206, (%esp)       # imm = 0xFFEF614A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver strtoimax, strtoimax@GLIBC_2.1

	#NO_APP
	pushl	$strtoimax
	addl	$-164081, (%esp)        # imm = 0xFFFD7F0F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __vsnprintf_chk, __vsnprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__vsnprintf_chk
	addl	$-860662, (%esp)        # imm = 0xFFF2DE0A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __strtod_l, __strtod_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtod_l
	addl	$17574, (%esp)          # imm = 0x44A6
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __ppoll_chk, __ppoll_chk@GLIBC_2.16

	#NO_APP
	pushl	$__ppoll_chk
	addl	$-1036129, (%esp)       # imm = 0xFFF0309F
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __strncat_chk, __strncat_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__strncat_chk
	addl	$-868170, (%esp)        # imm = 0xFFF2C0B6
	pushl	$-48
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver thrd_yield, thrd_yield@GLIBC_2.28

	#NO_APP
	pushl	$thrd_yield
	addl	$-1029805, (%esp)       # imm = 0xFFF04953
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver sighold, sighold@GLIBC_2.1

	#NO_APP
	pushl	$sighold
	addl	$-90417, (%esp)         # imm = 0xFFFE9ECF
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __nss_hosts_lookup, __nss_hosts_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_hosts_lookup
	addl	$-1100010, (%esp)       # imm = 0xFFEF3716
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_wdefault_finish, _IO_wdefault_finish@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wdefault_finish
	addl	$-343089, (%esp)        # imm = 0xFFFAC3CF
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __res_init, __res_init@GLIBC_2.2

	#NO_APP
	pushl	$__res_init
	addl	$-937686, (%esp)        # imm = 0xFFF1B12A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver getgrent, getgrent@GLIBC_2.0

	#NO_APP
	pushl	$getgrent
	addl	$-529862, (%esp)        # imm = 0xFFF7EA3A
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver _IO_sungetc, _IO_sungetc@GLIBC_2.0

	#NO_APP
	pushl	$_IO_sungetc
	addl	$-372307, (%esp)        # imm = 0xFFFA51AD
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __isoc99_vscanf, __isoc99_vscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vscanf
	addl	$-149846, (%esp)        # imm = 0xFFFDB6AA
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver rand_r, rand_r@GLIBC_2.0

	#NO_APP
	pushl	$rand_r
	addl	$374660, (%esp)         # imm = 0x5B784
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$-32771, (%esp)         # imm = 0xFFFF7FFD
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __libc_free, __libc_free@GLIBC_2.0

	#NO_APP
	pushl	$__libc_free
	addl	$-256038, (%esp)        # imm = 0xFFFC17DA
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver __open64_nocancel, __open64_nocancel@GLIBC_PRIVATE

	#NO_APP
	pushl	$__open64_nocancel
	addl	$-893891, (%esp)        # imm = 0xFFF25C3D
	calll	opaquePredicate
	jne	.chain_26
	#APP
.symver svcudp_enablecache, svcudp_enablecache@GLIBC_2.0

	#NO_APP
	pushl	$svcudp_enablecache
	addl	$-1014518, (%esp)       # imm = 0xFFF0850A
	retl
	#APP
.resume_26:
	#NO_APP
	popfl
	.loc	1 39 33 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:39:33
	movl	20(%ebp), %esi
	.loc	1 39 7                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:39:7
	movl	%eax, (%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, 8(%esp)
	movl	%esi, 12(%esp)
	movl	$0, 16(%esp)
	calll	selection
.Ltmp25:
.LBB1_7:
	.loc	1 0 7                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:0:7
	xorl	%eax, %eax
	pushfl
	calll	.chain_27
	jmp	.resume_27
	#APP
.chain_27:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __resolv_context_get, __resolv_context_get@GLIBC_PRIVATE

	#NO_APP
	pushl	$__resolv_context_get
	addl	$-939890, (%esp)        # imm = 0xFFF1A88E
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __strncat_chk, __strncat_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__strncat_chk
	addl	$-481165, (%esp)        # imm = 0xFFF8A873
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __libc_dlopen_mode, __libc_dlopen_mode@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dlopen_mode
	addl	$-1048106, (%esp)       # imm = 0xFFF001D6
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver getpwnam, getpwnam@GLIBC_2.0

	#NO_APP
	pushl	$getpwnam
	addl	$-537926, (%esp)        # imm = 0xFFF7CABA
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver xdrrec_skiprecord, xdrrec_skiprecord@GLIBC_2.0

	#NO_APP
	pushl	$xdrrec_skiprecord
	addl	$-978986, (%esp)        # imm = 0xFFF10FD6
	pushl	$-56
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __libc_dynarray_at_failure, __libc_dynarray_at_failure@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_dynarray_at_failure
	addl	$-442861, (%esp)        # imm = 0xFFF93E13
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver isxdigit, isxdigit@GLIBC_2.0

	#NO_APP
	pushl	$isxdigit
	addl	$113850, (%esp)         # imm = 0x1BCBA
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __moddi3, __moddi3@GLIBC_2.0

	#NO_APP
	pushl	$__moddi3
	addl	$157110, (%esp)         # imm = 0x265B6
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __strspn_g, __strspn_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_g
	addl	$-304310, (%esp)        # imm = 0xFFFB5B4A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver _IO_sscanf, _IO_sscanf@GLIBC_2.0

	#NO_APP
	pushl	$_IO_sscanf
	addl	$-145366, (%esp)        # imm = 0xFFFDC82A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver __ctype_tolower_loc, __ctype_tolower_loc@GLIBC_2.3

	#NO_APP
	pushl	$__ctype_tolower_loc
	addl	$-32771, (%esp)         # imm = 0xFFFF7FFD
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver fwrite_unlocked, fwrite_unlocked@GLIBC_2.1

	#NO_APP
	pushl	$fwrite_unlocked
	addl	$-208326, (%esp)        # imm = 0xFFFCD23A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver recvmmsg, recvmmsg@GLIBC_2.12

	#NO_APP
	pushl	$recvmmsg
	addl	$-489916, (%esp)        # imm = 0xFFF88644
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver qsort, qsort@GLIBC_2.0

	#NO_APP
	pushl	$qsort
	addl	$-74163, (%esp)         # imm = 0xFFFEDE4D
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver unlinkat, unlinkat@GLIBC_2.4

	#NO_APP
	pushl	$unlinkat
	addl	$-720630, (%esp)        # imm = 0xFFF5010A
	calll	opaquePredicate
	jne	.chain_27
	#APP
.symver pkey_mprotect, pkey_mprotect@GLIBC_2.27

	#NO_APP
	pushl	$pkey_mprotect
	addl	$-941075, (%esp)        # imm = 0xFFF1A3ED
	retl
	#APP
.resume_27:
	#NO_APP
	popfl
	.loc	1 41 21 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:41:21
	movl	12(%ebp), %ecx
	.loc	1 41 23 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:41:23
	addl	$1, %ecx
	pushfl
	calll	.chain_28
	jmp	.resume_28
	#APP
.chain_28:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver nice, nice@GLIBC_2.0

	#NO_APP
	pushl	$nice
	addl	$-753190, (%esp)        # imm = 0xFFF481DA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver fputws, fputws@GLIBC_2.2

	#NO_APP
	pushl	$fputws
	addl	$-173106, (%esp)        # imm = 0xFFFD5BCE
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __libc_siglongjmp, __libc_siglongjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_siglongjmp
	addl	$80346, (%esp)          # imm = 0x139DA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver strftime, strftime@GLIBC_2.0

	#NO_APP
	pushl	$strftime
	addl	$-498502, (%esp)        # imm = 0xFFF864BA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __nss_database_lookup, __nss_database_lookup@GLIBC_2.0

	#NO_APP
	pushl	$__nss_database_lookup
	addl	$-945846, (%esp)        # imm = 0xFFF1914A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver atof, atof@GLIBC_2.0

	#NO_APP
	pushl	$atof
	addl	$-91169, (%esp)         # imm = 0xFFFE9BDF
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver thrd_sleep, thrd_sleep@GLIBC_2.28

	#NO_APP
	pushl	$thrd_sleep
	addl	$-855302, (%esp)        # imm = 0xFFF2F2FA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-540845, (%esp)        # imm = 0xFFF7BF53
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver ppoll, ppoll@GLIBC_2.4

	#NO_APP
	pushl	$ppoll
	addl	$-908481, (%esp)        # imm = 0xFFF2233F
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver wcsncmp, wcsncmp@GLIBC_2.0

	#NO_APP
	pushl	$wcsncmp
	addl	$-386438, (%esp)        # imm = 0xFFFA1A7A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver fgetws_unlocked, fgetws_unlocked@GLIBC_2.2

	#NO_APP
	pushl	$fgetws_unlocked
	addl	$-337441, (%esp)        # imm = 0xFFFAD9DF
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver _IO_padn, _IO_padn@GLIBC_2.0

	#NO_APP
	pushl	$_IO_padn
	addl	$-164902, (%esp)        # imm = 0xFFFD7BDA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver llistxattr, llistxattr@GLIBC_2.3

	#NO_APP
	pushl	$llistxattr
	addl	$-795690, (%esp)        # imm = 0xFFF3DBD6
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver tmpnam_r, tmpnam_r@GLIBC_2.0

	#NO_APP
	pushl	$tmpnam_r
	addl	$-311985, (%esp)        # imm = 0xFFFB3D4F
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __sprintf_chk, __sprintf_chk@GLIBC_2.3.4

	#NO_APP
	pushl	$__sprintf_chk
	addl	$-868682, (%esp)        # imm = 0xFFF2BEB6
	pushl	$-44
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver getpmsg, getpmsg@GLIBC_2.1

	#NO_APP
	pushl	$getpmsg
	addl	$-1199437, (%esp)       # imm = 0xFFEDB2B3
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver _IO_default_finish, _IO_default_finish@GLIBC_2.0

	#NO_APP
	pushl	$_IO_default_finish
	addl	$-392161, (%esp)        # imm = 0xFFFA041F
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver atof, atof@GLIBC_2.0

	#NO_APP
	pushl	$atof
	addl	$65542, (%esp)          # imm = 0x10006
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver _IO_link_in, _IO_link_in@GLIBC_2.0

	#NO_APP
	pushl	$_IO_link_in
	addl	$-386817, (%esp)        # imm = 0xFFFA18FF
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver tcflush, tcflush@GLIBC_2.0

	#NO_APP
	pushl	$tcflush
	addl	$-751238, (%esp)        # imm = 0xFFF4897A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver rresvport, rresvport@GLIBC_2.0

	#NO_APP
	pushl	$rresvport
	addl	$-896246, (%esp)        # imm = 0xFFF2530A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver realpath, realpath@GLIBC_2.3

	#NO_APP
	pushl	$realpath
	addl	$-133235, (%esp)        # imm = 0xFFFDF78D
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __pipe, __pipe@GLIBC_2.0

	#NO_APP
	pushl	$__pipe
	addl	$-714758, (%esp)        # imm = 0xFFF517FA
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver xdr_uint16_t, xdr_uint16_t@GLIBC_2.1

	#NO_APP
	pushl	$xdr_uint16_t
	addl	$-708780, (%esp)        # imm = 0xFFF52F54
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver xdr_long, xdr_long@GLIBC_2.0

	#NO_APP
	pushl	$xdr_long
	addl	$-1161539, (%esp)       # imm = 0xFFEE46BD
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver fopencookie, fopencookie@GLIBC_2.2

	#NO_APP
	pushl	$fopencookie
	addl	$-160902, (%esp)        # imm = 0xFFFD8B7A
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver __strverscmp, __strverscmp@GLIBC_2.1.1

	#NO_APP
	pushl	$__strverscmp
	addl	$-415459, (%esp)        # imm = 0xFFF9A91D
	calll	opaquePredicate
	jne	.chain_28
	#APP
.symver xdr_hyper, xdr_hyper@GLIBC_2.1.1

	#NO_APP
	pushl	$xdr_hyper
	addl	$-1016998, (%esp)       # imm = 0xFFF07B5A
	retl
	#APP
.resume_28:
	#NO_APP
	popfl
	.loc	1 41 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:41:5
	movl	%eax, (%esp)
	movl	%ecx, 4(%esp)
	movl	$0, 8(%esp)
	movl	%edx, 12(%esp)
	movl	$1, 16(%esp)
	calll	selection
.Ltmp26:
.LBB1_8:
	.loc	1 43 1 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c:43:1
	addl	$36, %esp
	popl	%esi
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp27:
.Lfunc_end1:
	.size	selection, .Lfunc_end1-selection
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Enter the size of the list: "
	.size	.L.str, 29

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"%d"
	.size	.L.str.1, 3

	.type	.L.str.2,@object        # @.str.2
.L.str.2:
	.asciz	"Enter the elements in list:\n"
	.size	.L.str.2, 29

	.type	.L.str.3,@object        # @.str.3
.L.str.3:
	.asciz	"The sorted list in ascending order is\n"
	.size	.L.str.3, 39

	.type	.L.str.4,@object        # @.str.4
.L.str.4:
	.asciz	"%d  "
	.size	.L.str.4, 5

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	2                       # 0x2
	.long	78                      # 0x4e
	.long	146                     # 0x92
	.long	2                       # 0x2
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	61                      # 0x3d
	.quad	304155309144            # 0x46d111b458
	.quad	-6414643943281764369    # 0xa6fa9b51e01457ef
	.long	85                      # 0x55
	.quad	2509857698620709302     # 0x22d4ce47731119b6
	.ascii	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c\001\000\002\001\005\001\t\t\001\b\f\020\002\003\006\017\000\027\005\000\031\000\034\005\000\035\000\236\200\200\200\b\005\000\036\002\004\007\005\017\000\027\t\000\031\000\034\t\000\035\000\236\200\200\200\b\t\000\036\002\004\001\000\000\r\001\032>\021\002\001\003\007\000\023\005\000\024\000\225\200\200\200\b\005\000\025\r\004\005\001\t\000\r\t\000\016\000\217\200\200\200\b\t\000\017\002\006\005\003\t\000\021\r\000\022\000\223\200\200\200\b\r\000\023\007\006\r\001\013\000\034\021\000\035\000\236\200\200\200\b\021\000\036\004\b"
	.size	__llvm_coverage_mapping, 280

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
	.quad	304155309144            # 0x46d111b458
	.long	.L__profc_main
	.long	main
	.long	0
	.long	3                       # 0x3
	.zero	4
	.size	.L__profd_main, 36

	.type	.L__profc_selection,@object # @__profc_selection
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_selection:
	.zero	40
	.size	.L__profc_selection, 40

	.type	.L__profd_selection,@object # @__profd_selection
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_selection:
	.quad	-6414643943281764369    # 0xa6fa9b51e01457ef
	.quad	2509857698620709302     # 0x22d4ce47731119b6
	.long	.L__profc_selection
	.long	selection
	.long	0
	.long	5                       # 0x5
	.zero	4
	.size	.L__profd_selection, 36

	.type	.L__llvm_prf_nm,@object # @__llvm_prf_nm
	.section	__llvm_prf_names,"a",@progbits
	.p2align	4
.L__llvm_prf_nm:
	.ascii	"\016\026x\332\313M\314\314c,N\315IM.\311\314\317\003\000'l\005m"
	.size	.L__llvm_prf_nm, 24

	.type	__llvm_profile_filename,@object # @__llvm_profile_filename
	.section	.rodata.__llvm_profile_filename,"aG",@progbits,__llvm_profile_filename,comdat
	.globl	__llvm_profile_filename
	.p2align	4
__llvm_profile_filename:
	.asciz	"example4-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example4.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"main"                  # string offset=194
.Linfo_string4:
	.asciz	"int"                   # string offset=199
.Linfo_string5:
	.asciz	"selection"             # string offset=203
.Linfo_string6:
	.asciz	"list"                  # string offset=213
.Linfo_string7:
	.asciz	"__ARRAY_SIZE_TYPE__"   # string offset=218
.Linfo_string8:
	.asciz	"size"                  # string offset=238
.Linfo_string9:
	.asciz	"temp"                  # string offset=243
.Linfo_string10:
	.asciz	"i"                     # string offset=248
.Linfo_string11:
	.asciz	"j"                     # string offset=250
.Linfo_string12:
	.asciz	"flag"                  # string offset=252
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
	.byte	5                       # Abbreviation Code
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
	.byte	1                       # DW_TAG_array_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	8                       # Abbreviation Code
	.byte	33                      # DW_TAG_subrange_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	55                      # DW_AT_count
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	9                       # Abbreviation Code
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
	.byte	10                      # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	263                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x100 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x5f DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	8                       # DW_AT_decl_line
	.long	235                     # DW_AT_type
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0x3b:0xf DW_TAG_variable
	.byte	3                       # DW_AT_location
	.byte	145
	.ascii	"\370~"
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	242                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x4a:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string8          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x58:0xf DW_TAG_variable
	.byte	3                       # DW_AT_location
	.byte	145
	.ascii	"\360~"
	.long	.Linfo_string9          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x67:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	124
	.long	.Linfo_string10         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x75:0xf DW_TAG_variable
	.byte	3                       # DW_AT_location
	.byte	145
	.ascii	"\364~"
	.long	.Linfo_string11         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	9                       # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x85:0x66 DW_TAG_subprogram
	.long	.Lfunc_begin1           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin1 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string5          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
                                        # DW_AT_prototyped
                                        # DW_AT_external
	.byte	5                       # Abbrev [5] 0x96:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
	.long	261                     # DW_AT_type
	.byte	5                       # Abbrev [5] 0xa4:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	12
	.long	.Linfo_string10         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	5                       # Abbrev [5] 0xb2:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	16
	.long	.Linfo_string11         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	5                       # Abbrev [5] 0xc0:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	20
	.long	.Linfo_string8          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	5                       # Abbrev [5] 0xce:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	24
	.long	.Linfo_string12         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	26                      # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0xdc:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string9          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	27                      # DW_AT_decl_line
	.long	235                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	6                       # Abbrev [6] 0xeb:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	7                       # Abbrev [7] 0xf2:0xc DW_TAG_array_type
	.long	235                     # DW_AT_type
	.byte	8                       # Abbrev [8] 0xf7:0x6 DW_TAG_subrange_type
	.long	254                     # DW_AT_type
	.byte	30                      # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	9                       # Abbrev [9] 0xfe:0x7 DW_TAG_base_type
	.long	.Linfo_string7          # DW_AT_name
	.byte	8                       # DW_AT_byte_size
	.byte	7                       # DW_AT_encoding
	.byte	10                      # Abbrev [10] 0x105:0x5 DW_TAG_pointer_type
	.long	235                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark
	.section	.debug_pubnames,"",@progbits
	.long	.LpubNames_end0-.LpubNames_begin0 # Length of Public Names Info
.LpubNames_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	267                     # Compilation Unit Length
	.long	38                      # DIE offset
	.asciz	"main"                  # External Name
	.long	133                     # DIE offset
	.asciz	"selection"             # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	267                     # Compilation Unit Length
	.long	235                     # DIE offset
	.asciz	"int"                   # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
