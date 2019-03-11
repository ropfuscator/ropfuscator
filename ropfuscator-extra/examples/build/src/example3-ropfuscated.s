	.text
	.file	"example3.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c"
	.loc	1 3 0                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:3:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$440, %esp              # imm = 0x1B8
	movl	$0, -12(%ebp)
.Ltmp0:
	.loc	1 3 12 prologue_end     # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:3:12
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
	.loc	1 7 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:7:3
	leal	.L.str, %eax
	movl	%eax, (%esp)
	calll	printf
	.loc	1 8 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:8:3
	leal	.L.str.1, %eax
	movl	%eax, (%esp)
	leal	-8(%ebp), %eax
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
	.loc	1 9 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:9:3
	leal	.L.str.2, %eax
	movl	%eax, (%esp)
	calll	printf
.Ltmp1:
	.loc	1 12 10                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:12:10
	movl	$0, -4(%ebp)
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
	.loc	1 0 10 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:0:10
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
	.loc	1 12 17                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:12:17
	cmpl	-8(%ebp), %eax
.Ltmp3:
	.loc	1 12 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:12:3
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
.symver setlogin, setlogin@GLIBC_2.0

	#NO_APP
	pushl	$setlogin
	addl	$-648413, (%esp)        # imm = 0xFFF61B23
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver lockf64, lockf64@GLIBC_2.1

	#NO_APP
	pushl	$lockf64
	addl	$-722570, (%esp)        # imm = 0xFFF4F976
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver pkey_free, pkey_free@GLIBC_2.27

	#NO_APP
	pushl	$pkey_free
	addl	$-798534, (%esp)        # imm = 0xFFF3D0BA
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __asprintf_chk, __asprintf_chk@GLIBC_2.8

	#NO_APP
	pushl	$__asprintf_chk
	addl	$-877594, (%esp)        # imm = 0xFFF29BE6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver __sched_get_priority_max, __sched_get_priority_max@GLIBC_2.0

	#NO_APP
	pushl	$__sched_get_priority_max
	addl	$-839197, (%esp)        # imm = 0xFFF331E3
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
	addl	$105558, (%esp)         # imm = 0x19C56
	calll	opaquePredicate
	jne	.chain_3
	#APP
.symver getrpcbynumber_r, getrpcbynumber_r@GLIBC_2.0

	#NO_APP
	pushl	$getrpcbynumber_r
	addl	$-1091814, (%esp)       # imm = 0xFFEF571A
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
	.loc	1 13 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:13:5
	movl	%eax, 4(%esp)
	movl	$.L.str.3, (%esp)
	calll	printf
	.loc	1 14 22                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:14:22
	movl	-4(%ebp), %eax
	.loc	1 14 18 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:14:18
	leal	-424(%ebp,%eax,4), %eax
	.loc	1 14 5                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:14:5
	leal	.L.str.4, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	__isoc99_scanf
.Ltmp5:
# %bb.3:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	1 0 5                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:0:5
	pushfl
	calll	.chain_4
	jmp	.resume_4
	#APP
.chain_4:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver inet_netof, inet_netof@GLIBC_2.0

	#NO_APP
	pushl	$inet_netof
	addl	$-493037, (%esp)        # imm = 0xFFF87A13
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __fwritable, __fwritable@GLIBC_2.2

	#NO_APP
	pushl	$__fwritable
	addl	$-210490, (%esp)        # imm = 0xFFFCC9C6
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __nss_hostname_digits_dots, __nss_hostname_digits_dots@GLIBC_2.2.2

	#NO_APP
	pushl	$__nss_hostname_digits_dots
	addl	$-951830, (%esp)        # imm = 0xFFF179EA
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver fsync, fsync@GLIBC_2.0

	#NO_APP
	pushl	$fsync
	addl	$-767274, (%esp)        # imm = 0xFFF44AD6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver __isoc99_vfscanf, __isoc99_vfscanf@GLIBC_2.7

	#NO_APP
	pushl	$__isoc99_vfscanf
	addl	$-324685, (%esp)        # imm = 0xFFFB0BB3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver setegid, setegid@GLIBC_2.0

	#NO_APP
	pushl	$setegid
	addl	$-757430, (%esp)        # imm = 0xFFF4714A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver remove, remove@GLIBC_2.0

	#NO_APP
	pushl	$remove
	addl	$-157194, (%esp)        # imm = 0xFFFD99F6
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver process_vm_writev, process_vm_writev@GLIBC_2.15

	#NO_APP
	pushl	$process_vm_writev
	addl	$-798374, (%esp)        # imm = 0xFFF3D15A
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver clnt_broadcast, clnt_broadcast@GLIBC_2.0

	#NO_APP
	pushl	$clnt_broadcast
	addl	$-961938, (%esp)        # imm = 0xFFF1526E
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver inet6_opt_append, inet6_opt_append@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_append
	addl	$-540189, (%esp)        # imm = 0xFFF7C1E3
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-766474, (%esp)        # imm = 0xFFF44DF6
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
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver shmdt, shmdt@GLIBC_2.0

	#NO_APP
	pushl	$shmdt
	addl	$-977981, (%esp)        # imm = 0xFFF113C3
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
	addl	$-956426, (%esp)        # imm = 0xFFF167F6
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
	addl	$73802, (%esp)          # imm = 0x1204A
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
	addl	$-725244, (%esp)        # imm = 0xFFF4EF04
	calll	opaquePredicate
	jne	.chain_4
	#APP
.symver _obstack_begin, _obstack_begin@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin
	addl	$-411539, (%esp)        # imm = 0xFFF9B86D
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
	addl	$-628499, (%esp)        # imm = 0xFFF668ED
	retl
	#APP
.resume_4:
	#NO_APP
	popfl
	.loc	1 12 22 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:12:22
	movl	%eax, -4(%ebp)
	.loc	1 12 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:12:3
	jmp	.LBB0_1
.Ltmp6:
.LBB0_4:
	.loc	1 18 10 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:18:10
	movl	$1, -4(%ebp)
.LBB0_5:                                # =>This Inner Loop Header: Depth=1
	.loc	1 0 10 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:0:10
	pushfl
	calll	.chain_5
	jmp	.resume_5
	#APP
.chain_5:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$73982, (%esp)          # imm = 0x120FE
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __libc_longjmp, __libc_longjmp@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_longjmp
	addl	$458803, (%esp)         # imm = 0x70033
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __tolower_l, __tolower_l@GLIBC_2.1

	#NO_APP
	pushl	$__tolower_l
	addl	$104006, (%esp)         # imm = 0x19646
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver execle, execle@GLIBC_2.0

	#NO_APP
	pushl	$execle
	addl	$-544502, (%esp)        # imm = 0xFFF7B10A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __strncmp_g, __strncmp_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncmp_g
	addl	$-312490, (%esp)        # imm = 0xFFFB3B56
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver inet6_opt_next, inet6_opt_next@GLIBC_2.5

	#NO_APP
	pushl	$inet6_opt_next
	addl	$-1093741, (%esp)       # imm = 0xFFEF4F93
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver __strlen_g, __strlen_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strlen_g
	addl	$-303590, (%esp)        # imm = 0xFFFB5E1A
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver ioperm, ioperm@GLIBC_2.0

	#NO_APP
	pushl	$ioperm
	addl	$-801738, (%esp)        # imm = 0xFFF3C436
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver mrand48_r, mrand48_r@GLIBC_2.0

	#NO_APP
	pushl	$mrand48_r
	addl	$61674, (%esp)          # imm = 0xF0EA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver svcraw_create, svcraw_create@GLIBC_2.0

	#NO_APP
	pushl	$svcraw_create
	addl	$-966678, (%esp)        # imm = 0xFFF13FEA
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver _IO_marker_delta, _IO_marker_delta@GLIBC_2.0

	#NO_APP
	pushl	$_IO_marker_delta
	addl	$-374995, (%esp)        # imm = 0xFFFA472D
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
	addl	$-548940, (%esp)        # imm = 0xFFF79FB4
	calll	opaquePredicate
	jne	.chain_5
	#APP
.symver rcmd_af, rcmd_af@GLIBC_2.2

	#NO_APP
	pushl	$rcmd_af
	addl	$-1037891, (%esp)       # imm = 0xFFF029BD
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
	addl	$-1169875, (%esp)       # imm = 0xFFEE262D
	retl
	#APP
.resume_5:
	#NO_APP
	popfl
.Ltmp7:
	.loc	1 18 17                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:18:17
	cmpl	-8(%ebp), %eax
.Ltmp8:
	.loc	1 18 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:18:3
	jge	.LBB0_10
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
.symver fgetspent, fgetspent@GLIBC_2.0

	#NO_APP
	pushl	$fgetspent
	addl	$-437837, (%esp)        # imm = 0xFFF951B3
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
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-802378, (%esp)        # imm = 0xFFF3C1B6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-924717, (%esp)        # imm = 0xFFF1E3D3
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __libc_vfork, __libc_vfork@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_vfork
	addl	$-544022, (%esp)        # imm = 0xFFF7B2EA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver initgroups, initgroups@GLIBC_2.0

	#NO_APP
	pushl	$initgroups
	addl	$-537898, (%esp)        # imm = 0xFFF7CAD6
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver mblen, mblen@GLIBC_2.0

	#NO_APP
	pushl	$mblen
	addl	$65674, (%esp)          # imm = 0x1008A
	retl
	#APP
.resume_6:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+20
	movl	%eax, .L__profc_main+16
.Ltmp9:
	.loc	1 20 9 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:20:9
	movss	-424(%ebp), %xmm0       # xmm0 = mem[0],zero,zero,zero
	pushfl
	calll	.chain_7
	jmp	.resume_7
	#APP
.chain_7:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver pthread_attr_init, pthread_attr_init@GLIBC_2.1

	#NO_APP
	pushl	$pthread_attr_init
	addl	$-850946, (%esp)        # imm = 0xFFF303FE
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-710461, (%esp)        # imm = 0xFFF528C3
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
	addl	$-817802, (%esp)        # imm = 0xFFF38576
	pushl	$-68
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
	addl	$-766474, (%esp)        # imm = 0xFFF44DF6
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver iruserok_af, iruserok_af@GLIBC_2.2

	#NO_APP
	pushl	$iruserok_af
	addl	$-896582, (%esp)        # imm = 0xFFF251BA
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
	addl	$-725180, (%esp)        # imm = 0xFFF4EF44
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-94115, (%esp)         # imm = 0xFFFE905D
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
	addl	$-1067075, (%esp)       # imm = 0xFFEFB7BD
	retl
	#APP
.resume_7:
	#NO_APP
	popfl
	.loc	1 20 18 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:20:18
	movss	-424(%ebp,%eax,4), %xmm1 # xmm1 = mem[0],zero,zero,zero
	.loc	1 20 16                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:20:16
	ucomiss	%xmm0, %xmm1
.Ltmp10:
	.loc	1 20 9                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:20:9
	jbe	.LBB0_8
# %bb.7:                                #   in Loop: Header=BB0_5 Depth=1
	movl	.L__profc_main+24, %eax
	pushfl
	calll	.chain_8
	jmp	.resume_8
	#APP
.chain_8:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver _obstack_begin_1, _obstack_begin_1@GLIBC_2.0

	#NO_APP
	pushl	$_obstack_begin_1
	addl	$111683, (%esp)         # imm = 0x1B443
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
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver fts_set, fts_set@GLIBC_2.0

	#NO_APP
	pushl	$fts_set
	addl	$-744442, (%esp)        # imm = 0xFFF4A406
	pushl	$1
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver xdr_array, xdr_array@GLIBC_2.0

	#NO_APP
	pushl	$xdr_array
	addl	$-1190093, (%esp)       # imm = 0xFFEDD733
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-758998, (%esp)        # imm = 0xFFF46B2A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver getenv, getenv@GLIBC_2.0

	#NO_APP
	pushl	$getenv
	addl	$62214, (%esp)          # imm = 0xF306
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver fgetws, fgetws@GLIBC_2.2

	#NO_APP
	pushl	$fgetws
	addl	$-171910, (%esp)        # imm = 0xFFFD607A
	retl
	#APP
.resume_8:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+28
	movl	%eax, .L__profc_main+24
	pushfl
	calll	.chain_9
	jmp	.resume_9
	#APP
.chain_9:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ptrace, ptrace@GLIBC_2.0

	#NO_APP
	pushl	$ptrace
	addl	$-762098, (%esp)        # imm = 0xFFF45F0E
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __freading, __freading@GLIBC_2.2

	#NO_APP
	pushl	$__freading
	addl	$176723, (%esp)         # imm = 0x2B253
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
	addl	$-768810, (%esp)        # imm = 0xFFF444D6
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$-83, (%esp)
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
	addl	$-872666, (%esp)        # imm = 0xFFF2AF26
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-303942, (%esp)        # imm = 0xFFFB5CBA
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
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver ualarm, ualarm@GLIBC_2.0

	#NO_APP
	pushl	$ualarm
	addl	$-761078, (%esp)        # imm = 0xFFF4630A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __fdelt_warn, __fdelt_warn@GLIBC_2.15

	#NO_APP
	pushl	$__fdelt_warn
	addl	$-559116, (%esp)        # imm = 0xFFF777F4
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __strspn_c1, __strspn_c1@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_c1
	addl	$-446963, (%esp)        # imm = 0xFFF92E0D
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver rresvport_af, rresvport_af@GLIBC_2.2

	#NO_APP
	pushl	$rresvport_af
	addl	$-892550, (%esp)        # imm = 0xFFF2617A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver getnetbyname, getnetbyname@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname
	addl	$-1024707, (%esp)       # imm = 0xFFF05D3D
	retl
	#APP
.resume_9:
	#NO_APP
	popfl
.Ltmp11:
	.loc	1 21 16 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:21:16
	movss	-424(%ebp,%eax,4), %xmm0 # xmm0 = mem[0],zero,zero,zero
	.loc	1 21 14 is_stmt 0       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:21:14
	movss	%xmm0, -424(%ebp)
.Ltmp12:
.LBB0_8:                                #   in Loop: Header=BB0_5 Depth=1
	.loc	1 22 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:22:3
	jmp	.LBB0_9
.Ltmp13:
.LBB0_9:                                #   in Loop: Header=BB0_5 Depth=1
	.loc	1 0 3 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:0:3
	pushfl
	calll	.chain_10
	jmp	.resume_10
	#APP
.chain_10:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sigrelse, sigrelse@GLIBC_2.1

	#NO_APP
	pushl	$sigrelse
	addl	$453171, (%esp)         # imm = 0x6EA33
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __strcasestr, __strcasestr@GLIBC_2.1

	#NO_APP
	pushl	$__strcasestr
	addl	$-288234, (%esp)        # imm = 0xFFFB9A16
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver thrd_equal, thrd_equal@GLIBC_2.28

	#NO_APP
	pushl	$thrd_equal
	addl	$-855238, (%esp)        # imm = 0xFFF2F33A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __errno_location, __errno_location@GLIBC_2.0

	#NO_APP
	pushl	$__errno_location
	addl	$156870, (%esp)         # imm = 0x264C6
	pushl	$1
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver isupper, isupper@GLIBC_2.0

	#NO_APP
	pushl	$isupper
	addl	$-60413, (%esp)         # imm = 0xFFFF1403
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _IO_str_overflow, _IO_str_overflow@GLIBC_2.0

	#NO_APP
	pushl	$_IO_str_overflow
	addl	$-231782, (%esp)        # imm = 0xFFFC769A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __libc_start_main, __libc_start_main@GLIBC_2.0

	#NO_APP
	pushl	$__libc_start_main
	addl	$158838, (%esp)         # imm = 0x26C76
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver insque, insque@GLIBC_2.0

	#NO_APP
	pushl	$insque
	addl	$-766662, (%esp)        # imm = 0xFFF44D3A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _IO_wfile_underflow, _IO_wfile_underflow@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_underflow
	addl	$-184834, (%esp)        # imm = 0xFFFD2DFE
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-596141, (%esp)        # imm = 0xFFF6E753
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __gconv_transliterate, __gconv_transliterate@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_transliterate
	addl	$124598, (%esp)         # imm = 0x1E6B6
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver mbstowcs, mbstowcs@GLIBC_2.0

	#NO_APP
	pushl	$mbstowcs
	addl	$65434, (%esp)          # imm = 0xFF9A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver vwprintf, vwprintf@GLIBC_2.2

	#NO_APP
	pushl	$vwprintf
	addl	$-183834, (%esp)        # imm = 0xFFFD31E6
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver _setjmp, _setjmp@GLIBC_2.0

	#NO_APP
	pushl	$_setjmp
	addl	$-93933, (%esp)         # imm = 0xFFFE9113
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sprintf, sprintf@GLIBC_2.0

	#NO_APP
	pushl	$sprintf
	addl	$-72134, (%esp)         # imm = 0xFFFEE63A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver setjmp, setjmp@GLIBC_2.0

	#NO_APP
	pushl	$setjmp
	addl	$72022, (%esp)          # imm = 0x11956
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
	addl	$-1009094, (%esp)       # imm = 0xFFF09A3A
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$-70531, (%esp)         # imm = 0xFFFEEC7D
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver ecvt, ecvt@GLIBC_2.0

	#NO_APP
	pushl	$ecvt
	addl	$-774406, (%esp)        # imm = 0xFFF42EFA
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver ftok, ftok@GLIBC_2.0

	#NO_APP
	pushl	$ftok
	addl	$-490524, (%esp)        # imm = 0xFFF883E4
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver fgetpos, fgetpos@GLIBC_2.0

	#NO_APP
	pushl	$fgetpos
	addl	$-1201779, (%esp)       # imm = 0xFFEDA98D
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver inet6_option_find, inet6_option_find@GLIBC_2.3.3

	#NO_APP
	pushl	$inet6_option_find
	addl	$-916774, (%esp)        # imm = 0xFFF202DA
	calll	opaquePredicate
	jne	.chain_10
	#APP
.symver __munmap, __munmap@GLIBC_PRIVATE

	#NO_APP
	pushl	$__munmap
	addl	$-918467, (%esp)        # imm = 0xFFF1FC3D
	retl
	#APP
.resume_10:
	#NO_APP
	popfl
	.loc	1 18 22 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:18:22
	movl	%eax, -4(%ebp)
	.loc	1 18 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:18:3
	jmp	.LBB0_5
.Ltmp14:
.LBB0_10:
	.loc	1 23 36 is_stmt 1       # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:23:36
	movss	-424(%ebp), %xmm0       # xmm0 = mem[0],zero,zero,zero
	cvtss2sd	%xmm0, %xmm0
	.loc	1 23 3 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:23:3
	leal	.L.str.5, %eax
	movl	%eax, (%esp)
	movsd	%xmm0, 4(%esp)
	calll	printf
	.loc	1 25 3 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c:25:3
	xorl	%eax, %eax
	addl	$440, %esp              # imm = 0x1B8
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp15:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Enter total number of elements(1 to 100): "
	.size	.L.str, 43

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"%d"
	.size	.L.str.1, 3

	.type	.L.str.2,@object        # @.str.2
.L.str.2:
	.asciz	"\n"
	.size	.L.str.2, 2

	.type	.L.str.3,@object        # @.str.3
.L.str.3:
	.asciz	"Enter Number %d: "
	.size	.L.str.3, 18

	.type	.L.str.4,@object        # @.str.4
.L.str.4:
	.asciz	"%f"
	.size	.L.str.4, 3

	.type	.L.str.5,@object        # @.str.5
.L.str.5:
	.asciz	"Largest element = %.2f"
	.size	.L.str.5, 23

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	1                       # 0x1
	.long	78                      # 0x4e
	.long	82                      # 0x52
	.long	2                       # 0x2
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	80                      # 0x50
	.quad	-6692825225941841064    # 0xa31e4eeac7f68b58
	.asciz	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c\001\000\002\001\005\001\t\f\001\003\f\027\002\003\t\017\000\024\005\000\026\000\031\005\000\032\000\233\200\200\200\b\005\000\033\003\004\007\006\017\000\024\t\000\026\000\031\t\000\032\000\233\200\200\200\b\t\000\033\004\004\t\002\t\000\030\r\000\031\001\207\200\200\200\b\r\001\007\000\026\000"
	.size	__llvm_coverage_mapping, 196

	.type	.L__profc_main,@object  # @__profc_main
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_main:
	.zero	32
	.size	.L__profc_main, 32

	.type	.L__profd_main,@object  # @__profd_main
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_main:
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.quad	-6692825225941841064    # 0xa31e4eeac7f68b58
	.long	.L__profc_main
	.long	main
	.long	0
	.long	4                       # 0x4
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
	.asciz	"example3-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example3.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"main"                  # string offset=194
.Linfo_string4:
	.asciz	"int"                   # string offset=199
.Linfo_string5:
	.asciz	"i"                     # string offset=203
.Linfo_string6:
	.asciz	"n"                     # string offset=205
.Linfo_string7:
	.asciz	"arr"                   # string offset=207
.Linfo_string8:
	.asciz	"float"                 # string offset=211
.Linfo_string9:
	.asciz	"__ARRAY_SIZE_TYPE__"   # string offset=217
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
	.byte	5                       # Abbreviation Code
	.byte	1                       # DW_TAG_array_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	6                       # Abbreviation Code
	.byte	33                      # DW_TAG_subrange_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	55                      # DW_AT_count
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	7                       # Abbreviation Code
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
	.long	133                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x7e DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x41 DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	3                       # DW_AT_decl_line
	.long	103                     # DW_AT_type
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0x3b:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	124
	.long	.Linfo_string5          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.long	103                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x49:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	120
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.long	103                     # DW_AT_type
	.byte	3                       # Abbrev [3] 0x57:0xf DW_TAG_variable
	.byte	3                       # DW_AT_location
	.byte	145
	.ascii	"\330|"
	.long	.Linfo_string7          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	5                       # DW_AT_decl_line
	.long	110                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x67:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	5                       # Abbrev [5] 0x6e:0xc DW_TAG_array_type
	.long	122                     # DW_AT_type
	.byte	6                       # Abbrev [6] 0x73:0x6 DW_TAG_subrange_type
	.long	129                     # DW_AT_type
	.byte	100                     # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	4                       # Abbrev [4] 0x7a:0x7 DW_TAG_base_type
	.long	.Linfo_string8          # DW_AT_name
	.byte	4                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	7                       # Abbrev [7] 0x81:0x7 DW_TAG_base_type
	.long	.Linfo_string9          # DW_AT_name
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
	.long	137                     # Compilation Unit Length
	.long	38                      # DIE offset
	.asciz	"main"                  # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	137                     # Compilation Unit Length
	.long	122                     # DIE offset
	.asciz	"float"                 # External Name
	.long	103                     # DIE offset
	.asciz	"int"                   # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
