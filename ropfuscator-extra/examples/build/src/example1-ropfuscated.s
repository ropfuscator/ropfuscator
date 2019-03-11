	.text
	.file	"example1.c"
	.globl	sum                     # -- Begin function sum
	.p2align	4, 0x90
	.type	sum,@function
sum:                                    # @sum
.Lfunc_begin0:
	.file	1 "/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c"
	.loc	1 3 0                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:3:0
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
	pushl	$-56
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
.Ltmp0:
	.loc	1 3 16 prologue_end     # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:3:16
	movl	.L__profc_sum, %eax
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
	adcl	$0, .L__profc_sum+4
	movl	%eax, .L__profc_sum
	pushfl
	calll	.chain_2
	jmp	.resume_2
	#APP
.chain_2:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver iconv_close, iconv_close@GLIBC_2.1

	#NO_APP
	pushl	$iconv_close
	addl	$542451, (%esp)         # imm = 0x846F3
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver __wcsncat_chk, __wcsncat_chk@GLIBC_2.4

	#NO_APP
	pushl	$__wcsncat_chk
	addl	$-874170, (%esp)        # imm = 0xFFF2A946
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver envz_strip, envz_strip@GLIBC_2.0

	#NO_APP
	pushl	$envz_strip
	addl	$-287830, (%esp)        # imm = 0xFFFB9BAA
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver strtod, strtod@GLIBC_2.0

	#NO_APP
	pushl	$strtod
	addl	$42022, (%esp)          # imm = 0xA426
	pushl	$12
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver delete_module, delete_module@GLIBC_2.0

	#NO_APP
	pushl	$delete_module
	addl	$-971389, (%esp)        # imm = 0xFFF12D83
	calll	opaquePredicate
	jne	.chain_2
	#APP
.symver qgcvt, qgcvt@GLIBC_2.0

	#NO_APP
	pushl	$qgcvt
	addl	$-776150, (%esp)        # imm = 0xFFF4282A
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
	pushl	$-56
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
	.loc	1 4 7                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:4:7
	movl	%eax, -4(%ebp)
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
	.loc	1 5 12                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:5:12
	cmpl	$46, -4(%ebp)
	.loc	1 5 3 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:5:3
	jle	.LBB0_3
# %bb.2:                                #   in Loop: Header=BB0_1 Depth=1
	movl	.L__profc_sum+8, %eax
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
	retl
	#APP
.resume_3:
	#NO_APP
	popfl
	adcl	$0, .L__profc_sum+12
	movl	%eax, .L__profc_sum+8
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
	pushl	$-2
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
.Ltmp1:
	.loc	1 6 7 is_stmt 1         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:6:7
	movl	%eax, -4(%ebp)
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
	.loc	1 7 5                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:7:5
	leal	.L.str, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
.Ltmp2:
	.loc	1 5 3                   # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:5:3
	jmp	.LBB0_1
.LBB0_3:
	.loc	1 0 3 is_stmt 0         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:0:3
	pushfl
	calll	.chain_6
	jmp	.resume_6
	#APP
.chain_6:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver iruserok_af, iruserok_af@GLIBC_2.2

	#NO_APP
	pushl	$iruserok_af
	addl	$-897218, (%esp)        # imm = 0xFFF24F3E
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver endaliasent, endaliasent@GLIBC_2.0

	#NO_APP
	pushl	$endaliasent
	addl	$-526141, (%esp)        # imm = 0xFFF7F8C3
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __stpcpy_small, __stpcpy_small@GLIBC_2.1.1

	#NO_APP
	pushl	$__stpcpy_small
	addl	$-311594, (%esp)        # imm = 0xFFFB3ED6
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __register_atfork, __register_atfork@GLIBC_2.3.2

	#NO_APP
	pushl	$__register_atfork
	addl	$-854102, (%esp)        # imm = 0xFFF2F7AA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __ptsname_r_chk, __ptsname_r_chk@GLIBC_2.4

	#NO_APP
	pushl	$__ptsname_r_chk
	addl	$-1045354, (%esp)       # imm = 0xFFF00C96
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __strtoull_l, __strtoull_l@GLIBC_2.1

	#NO_APP
	pushl	$__strtoull_l
	addl	$-123565, (%esp)        # imm = 0xFFFE1D53
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver siggetmask, siggetmask@GLIBC_2.0

	#NO_APP
	pushl	$siggetmask
	addl	$76154, (%esp)          # imm = 0x1297A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __idna_from_dns_encoding, __idna_from_dns_encoding@GLIBC_PRIVATE

	#NO_APP
	pushl	$__idna_from_dns_encoding
	addl	$-930634, (%esp)        # imm = 0xFFF1CCB6
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
	addl	$-1019750, (%esp)       # imm = 0xFFF0709A
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver sigismember, sigismember@GLIBC_2.0

	#NO_APP
	pushl	$sigismember
	addl	$-68595, (%esp)         # imm = 0xFFFEF40D
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver setfsuid, setfsuid@GLIBC_2.0

	#NO_APP
	pushl	$setfsuid
	addl	$-793926, (%esp)        # imm = 0xFFF3E2BA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-438652, (%esp)        # imm = 0xFFF94E84
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver __libc_vfork, __libc_vfork@GLIBC_PRIVATE

	#NO_APP
	pushl	$__libc_vfork
	addl	$-688915, (%esp)        # imm = 0xFFF57CED
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver initgroups, initgroups@GLIBC_2.0

	#NO_APP
	pushl	$initgroups
	addl	$-529446, (%esp)        # imm = 0xFFF7EBDA
	calll	opaquePredicate
	jne	.chain_6
	#APP
.symver mblen, mblen@GLIBC_2.0

	#NO_APP
	pushl	$mblen
	addl	$-79219, (%esp)         # imm = 0xFFFECA8D
	retl
	#APP
.resume_6:
	#NO_APP
	popfl
	.loc	1 9 3 is_stmt 1         # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:9:3
	addl	$24, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp3:
.Lfunc_end0:
	.size	sum, .Lfunc_end0-sum
	.cfi_endproc
                                        # -- End function
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin1:
	.loc	1 12 0                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:12:0
	.cfi_startproc
# %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$24, %esp
.Ltmp4:
	.loc	1 12 12 prologue_end    # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:12:12
	movl	.L__profc_main, %eax
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
	addl	$-471757, (%esp)        # imm = 0xFFF8CD33
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver shmctl, shmctl@GLIBC_2.0

	#NO_APP
	pushl	$shmctl
	addl	$-1097466, (%esp)       # imm = 0xFFEF4106
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver labs, labs@GLIBC_2.0

	#NO_APP
	pushl	$labs
	addl	$66058, (%esp)          # imm = 0x1020A
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __getdomainname_chk, __getdomainname_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getdomainname_chk
	addl	$-876970, (%esp)        # imm = 0xFFF29E56
	pushl	$1
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver __profile_frequency, __profile_frequency@GLIBC_2.0

	#NO_APP
	pushl	$__profile_frequency
	addl	$-983693, (%esp)        # imm = 0xFFF0FD73
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver tcsetattr, tcsetattr@GLIBC_2.0

	#NO_APP
	pushl	$tcsetattr
	addl	$-750374, (%esp)        # imm = 0xFFF48CDA
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver getprotobyname_r, getprotobyname_r@GLIBC_2.0

	#NO_APP
	pushl	$getprotobyname_r
	addl	$-1099386, (%esp)       # imm = 0xFFEF3986
	calll	opaquePredicate
	jne	.chain_7
	#APP
.symver sethostname, sethostname@GLIBC_2.0

	#NO_APP
	pushl	$sethostname
	addl	$-758022, (%esp)        # imm = 0xFFF46EFA
	retl
	#APP
.resume_7:
	#NO_APP
	popfl
	adcl	$0, .L__profc_main+4
	movl	%eax, .L__profc_main
	.loc	1 13 11                 # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:13:11
	movl	$40, (%esp)
	calll	sum
	.loc	1 13 7 is_stmt 0        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:13:7
	movl	%eax, -4(%ebp)
	pushfl
	calll	.chain_8
	jmp	.resume_8
	#APP
.chain_8:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver ptrace, ptrace@GLIBC_2.0

	#NO_APP
	pushl	$ptrace
	addl	$-382909, (%esp)        # imm = 0xFFFA2843
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __freading, __freading@GLIBC_2.2

	#NO_APP
	pushl	$__freading
	addl	$-210282, (%esp)        # imm = 0xFFFCCA96
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver _IO_setbuffer, _IO_setbuffer@GLIBC_2.0

	#NO_APP
	pushl	$_IO_setbuffer
	addl	$-168422, (%esp)        # imm = 0xFFFD6E1A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __clock_settime, __clock_settime@GLIBC_PRIVATE

	#NO_APP
	pushl	$__clock_settime
	addl	$-864858, (%esp)        # imm = 0xFFF2CDA6
	pushl	$256                    # imm = 0x100
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver mkstemp64, mkstemp64@GLIBC_2.2

	#NO_APP
	pushl	$mkstemp64
	addl	$-934701, (%esp)        # imm = 0xFFF1BCD3
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver abort, abort@GLIBC_2.0

	#NO_APP
	pushl	$abort
	addl	$174260, (%esp)         # imm = 0x2A8B4
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver setsgent, setsgent@GLIBC_2.10

	#NO_APP
	pushl	$setsgent
	addl	$-832458, (%esp)        # imm = 0xFFF34C36
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __getcwd_chk, __getcwd_chk@GLIBC_2.4

	#NO_APP
	pushl	$__getcwd_chk
	addl	$-864214, (%esp)        # imm = 0xFFF2D02A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strncat_g, __strncat_g@GLIBC_2.1.1

	#NO_APP
	pushl	$__strncat_g
	addl	$-304578, (%esp)        # imm = 0xFFFB5A3E
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver _IO_feof, _IO_feof@GLIBC_2.0

	#NO_APP
	pushl	$_IO_feof
	addl	$184835, (%esp)         # imm = 0x2D203
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver clnt_sperror, clnt_sperror@GLIBC_2.0

	#NO_APP
	pushl	$clnt_sperror
	addl	$-1001866, (%esp)       # imm = 0xFFF0B676
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver ualarm, ualarm@GLIBC_2.0

	#NO_APP
	pushl	$ualarm
	addl	$-761078, (%esp)        # imm = 0xFFF4630A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __fdelt_warn, __fdelt_warn@GLIBC_2.15

	#NO_APP
	pushl	$__fdelt_warn
	addl	$-879290, (%esp)        # imm = 0xFFF29546
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __strspn_c1, __strspn_c1@GLIBC_2.1.1

	#NO_APP
	pushl	$__strspn_c1
	addl	$-476413, (%esp)        # imm = 0xFFF8BB03
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver rresvport_af, rresvport_af@GLIBC_2.2

	#NO_APP
	pushl	$rresvport_af
	addl	$-892550, (%esp)        # imm = 0xFFF2617A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver getnetbyname, getnetbyname@GLIBC_2.0

	#NO_APP
	pushl	$getnetbyname
	addl	$-888266, (%esp)        # imm = 0xFFF27236
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
	addl	$-774070, (%esp)        # imm = 0xFFF4304A
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver __sysconf, __sysconf@GLIBC_2.2

	#NO_APP
	pushl	$__sysconf
	addl	$-695699, (%esp)        # imm = 0xFFF5626D
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
	addl	$-704028, (%esp)        # imm = 0xFFF541E4
	calll	opaquePredicate
	jne	.chain_8
	#APP
.symver sync, sync@GLIBC_2.0

	#NO_APP
	pushl	$sync
	addl	$-903891, (%esp)        # imm = 0xFFF2352D
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
	addl	$-316803, (%esp)        # imm = 0xFFFB2A7D
	retl
	#APP
.resume_8:
	#NO_APP
	popfl
	.loc	1 14 5 is_stmt 1        # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:14:5
	movl	%eax, -4(%ebp)
	pushfl
	calll	.chain_9
	jmp	.resume_9
	#APP
.chain_9:
	#NO_APP
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _IO_wfile_underflow, _IO_wfile_underflow@GLIBC_2.2

	#NO_APP
	pushl	$_IO_wfile_underflow
	addl	$-184834, (%esp)        # imm = 0xFFFD2DFE
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver des_setparity, des_setparity@GLIBC_2.1

	#NO_APP
	pushl	$des_setparity
	addl	$-596141, (%esp)        # imm = 0xFFF6E753
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver __gconv_transliterate, __gconv_transliterate@GLIBC_PRIVATE

	#NO_APP
	pushl	$__gconv_transliterate
	addl	$124598, (%esp)         # imm = 0x1E6B6
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
	addl	$-183834, (%esp)        # imm = 0xFFFD31E6
	pushl	$-68
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver _setjmp, _setjmp@GLIBC_2.0

	#NO_APP
	pushl	$_setjmp
	addl	$-93933, (%esp)         # imm = 0xFFFE9113
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
	addl	$72022, (%esp)          # imm = 0x11956
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver inet6_rth_add, inet6_rth_add@GLIBC_2.5

	#NO_APP
	pushl	$inet6_rth_add
	addl	$-920086, (%esp)        # imm = 0xFFF1F5EA
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver svc_getreqset, svc_getreqset@GLIBC_2.0

	#NO_APP
	pushl	$svc_getreqset
	addl	$-1009094, (%esp)       # imm = 0xFFF09A3A
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver sigset, sigset@GLIBC_2.1

	#NO_APP
	pushl	$sigset
	addl	$-70531, (%esp)         # imm = 0xFFFEEC7D
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
	addl	$-490524, (%esp)        # imm = 0xFFF883E4
	calll	opaquePredicate
	jne	.chain_9
	#APP
.symver fgetpos, fgetpos@GLIBC_2.0

	#NO_APP
	pushl	$fgetpos
	addl	$-1201779, (%esp)       # imm = 0xFFEDA98D
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
	addl	$-918467, (%esp)        # imm = 0xFFF1FC3D
	retl
	#APP
.resume_9:
	#NO_APP
	popfl
	.loc	1 15 3                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:15:3
	leal	.L.str, %ecx
	movl	%ecx, (%esp)
	movl	%eax, 4(%esp)
	calll	printf
	.loc	1 16 1                  # /tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c:16:1
	xorl	%eax, %eax
	addl	$24, %esp
	popl	%ebp
	.cfi_def_cfa %esp, 4
	retl
.Ltmp5:
.Lfunc_end1:
	.size	main, .Lfunc_end1-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%d\n"
	.size	.L.str, 4

	.type	__llvm_coverage_mapping,@object # @__llvm_coverage_mapping
	.section	__llvm_covmap,"",@progbits
	.p2align	3
__llvm_coverage_mapping:
	.long	2                       # 0x2
	.long	78                      # 0x4e
	.long	42                      # 0x2a
	.long	2                       # 0x2
	.quad	-1973632818483600867    # 0xe49c3f68893b621d
	.long	30                      # 0x1e
	.quad	640088                  # 0x9c458
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.long	9                       # 0x9
	.quad	0                       # 0x0
	.asciz	"\001L/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c\001\000\001\001\005\004\001\003\020\007\002\003\002\n\000\020\005\000\021\000\222\200\200\200\b\005\000\022\003\004\001\000\000\001\001\f\f\004\002\000\000"
	.size	__llvm_coverage_mapping, 176

	.type	.L__profc_sum,@object   # @__profc_sum
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_sum:
	.zero	16
	.size	.L__profc_sum, 16

	.type	.L__profd_sum,@object   # @__profd_sum
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_sum:
	.quad	-1973632818483600867    # 0xe49c3f68893b621d
	.quad	640088                  # 0x9c458
	.long	.L__profc_sum
	.long	sum
	.long	0
	.long	2                       # 0x2
	.zero	4
	.size	.L__profd_sum, 36

	.type	.L__profc_main,@object  # @__profc_main
	.section	__llvm_prf_cnts,"aw",@progbits
	.p2align	3
.L__profc_main:
	.zero	8
	.size	.L__profc_main, 8

	.type	.L__profd_main,@object  # @__profd_main
	.section	__llvm_prf_data,"aw",@progbits
	.p2align	3
.L__profd_main:
	.quad	-2624081020897602054    # 0xdb956436e78dd5fa
	.quad	0                       # 0x0
	.long	.L__profc_main
	.long	main
	.long	0
	.long	1                       # 0x1
	.zero	4
	.size	.L__profd_main, 36

	.type	.L__llvm_prf_nm,@object # @__llvm_prf_nm
	.section	__llvm_prf_names,"a",@progbits
	.p2align	4
.L__llvm_prf_nm:
	.ascii	"\b\020x\332+.\315e\314M\314\314\003\000\r}\002\374"
	.size	.L__llvm_prf_nm, 18

	.type	__llvm_profile_filename,@object # @__llvm_profile_filename
	.section	.rodata.__llvm_profile_filename,"aG",@progbits,__llvm_profile_filename,comdat
	.globl	__llvm_profile_filename
	.p2align	4
__llvm_profile_filename:
	.asciz	"example1-ropfuscated.profdata"
	.size	__llvm_profile_filename, 30

	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 7.0.1 (tags/RELEASE_701/final)" # string offset=0
.Linfo_string1:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/src/example1.c" # string offset=45
.Linfo_string2:
	.asciz	"/tmp/llvm-7.0.0.src/lib/Target/X86/ropfuscator-extra/examples/build/src" # string offset=122
.Linfo_string3:
	.asciz	"sum"                   # string offset=194
.Linfo_string4:
	.asciz	"int"                   # string offset=198
.Linfo_string5:
	.asciz	"main"                  # string offset=202
.Linfo_string6:
	.asciz	"a"                     # string offset=207
.Linfo_string7:
	.asciz	"b"                     # string offset=209
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
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
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
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	128                     # Length of Unit
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	4                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x79 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x26:0x32 DW_TAG_subprogram
	.long	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	3                       # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	124                     # DW_AT_type
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0x3b:0xe DW_TAG_formal_parameter
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	3                       # DW_AT_decl_line
	.long	124                     # DW_AT_type
	.byte	4                       # Abbrev [4] 0x49:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	124
	.long	.Linfo_string7          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.long	124                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	5                       # Abbrev [5] 0x58:0x24 DW_TAG_subprogram
	.long	.Lfunc_begin1           # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin1 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	85
	.long	.Linfo_string5          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	12                      # DW_AT_decl_line
	.long	124                     # DW_AT_type
                                        # DW_AT_external
	.byte	4                       # Abbrev [4] 0x6d:0xe DW_TAG_variable
	.byte	2                       # DW_AT_location
	.byte	145
	.byte	124
	.long	.Linfo_string6          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	13                      # DW_AT_decl_line
	.long	124                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	6                       # Abbrev [6] 0x7c:0x7 DW_TAG_base_type
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
	.long	132                     # Compilation Unit Length
	.long	38                      # DIE offset
	.asciz	"sum"                   # External Name
	.long	88                      # DIE offset
	.asciz	"main"                  # External Name
	.long	0                       # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_begin0 # Length of Public Types Info
.LpubTypes_begin0:
	.short	2                       # DWARF Version
	.long	.Lcu_begin0             # Offset of Compilation Unit Info
	.long	132                     # Compilation Unit Length
	.long	124                     # DIE offset
	.asciz	"int"                   # External Name
	.long	0                       # End Mark
.LpubTypes_end0:

	.ident	"clang version 7.0.1 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
