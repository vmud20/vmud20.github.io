
























#define OE_LOG_MESSAGE_LEN_MAX 2048U
#define OE_MAX_FILENAME_LEN 256U
#define OE_TRACE(level, ...)        \
    do                              \
    {                               \
        oe_log(level, __VA_ARGS__); \
    } while (0)
#define OE_TRACE_ERROR(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_ERROR,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        "__FILE__",                \
        __FUNCTION__,            \
        "__LINE__")
#define OE_TRACE_FATAL(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_FATAL,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        "__FILE__",                \
        __FUNCTION__,            \
        "__LINE__")
#define OE_TRACE_INFO(fmt, ...) \
    OE_TRACE(                   \
        OE_LOG_LEVEL_INFO,      \
        fmt " [%s:%s:%d]\n",    \
        ##__VA_ARGS__,          \
        "__FILE__",               \
        __FUNCTION__,           \
        "__LINE__")
#define OE_TRACE_VERBOSE(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_VERBOSE,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        "__FILE__",                  \
        __FUNCTION__,              \
        "__LINE__")
#define OE_TRACE_WARNING(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_WARNING,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        "__FILE__",                  \
        __FUNCTION__,              \
        "__LINE__")


#define OE_CHAR_BIT 8
#define OE_CHAR_MAX 127
#define OE_CHAR_MIN (-128)
#define OE_INT16_MAX (0x7fff)
#define OE_INT16_MIN (-1 - 0x7fff)
#define OE_INT32_MAX (0x7fffffff)
#define OE_INT32_MIN (-1 - 0x7fffffff)
#define OE_INT64_MAX (0x7fffffffffffffff)
#define OE_INT64_MIN (-1 - 0x7fffffffffffffff)
#define OE_INT8_MAX (0x7f)
#define OE_INT8_MIN (-1 - 0x7f)
#define OE_INT_MAX 0x7fffffff
#define OE_INT_MIN (-1 - 0x7fffffff)
#define OE_LLONG_MAX 0x7fffffffffffffffLL
#define OE_LLONG_MIN (-OE_LLONG_MAX - 1)
#define OE_LONG_MAX 0x7fffffffL
#define OE_LONG_MIN (-OE_LONG_MAX - 1)
#define OE_SCHAR_MAX 127
#define OE_SCHAR_MIN (-128)
#define OE_SHRT_MAX 0x7fff
#define OE_SHRT_MIN (-1 - 0x7fff)
#define OE_SIZE_MAX OE_UINT64_MAX
#define OE_SSIZE_MAX OE_INT64_MAX
#define OE_UCHAR_MAX 255
#define OE_UINT16_MAX (0xffff)
#define OE_UINT32_MAX (0xffffffffu)
#define OE_UINT64_MAX (0xffffffffffffffffu)
#define OE_UINT8_MAX (0xff)
#define OE_UINT_MAX 0xffffffffU
#define OE_ULLONG_MAX (2ULL * OE_LLONG_MAX + 1)
#define OE_ULONG_MAX (2UL * OE_LONG_MAX + 1)
#define OE_USHRT_MAX 0xffff

#define bool _Bool
#define false 0
#define true 1

#define NULL 0L
#define OE_ALIGNED(BYTES) __attribute__((aligned(BYTES)))
#define OE_ALWAYS_INLINE __attribute__((always_inline))
#define OE_API_VERSION 2
#define OE_CHECK_FIELD(T1, T2, F)                               \
    OE_STATIC_ASSERT(OE_OFFSETOF(T1, F) == OE_OFFSETOF(T2, F)); \
    OE_STATIC_ASSERT(sizeof(((T1*)0)->F) == sizeof(((T2*)0)->F));
#define OE_CHECK_SIZE(N, M)          \
    typedef unsigned char OE_CONCAT( \
        __OE_CHECK_SIZE, "__LINE__")[((N) == (M)) ? 1 : -1] OE_UNUSED_ATTRIBUTE
#define OE_CONCAT(X, Y) __OE_CONCAT(X, Y)
#define OE_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))
#define OE_DEPRECATED(FUNC, MSG) FUNC __attribute__((deprecated(MSG)))
#define OE_ENUM_MAX 0xffffffff
#define OE_EXPORT __attribute__((visibility("default")))
#define OE_EXPORT_CONST OE_EXPORT extern const
#define OE_EXTERNC extern "C"
#define OE_EXTERNC_BEGIN \
    extern "C"           \
    {
#define OE_EXTERNC_END }
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))
#define OE_INLINE static __inline
#define OE_NEVER_INLINE __declspec(noinline)
#define OE_NO_OPTIMIZE_BEGIN __pragma(optimize("", off))
#define OE_NO_OPTIMIZE_END __pragma(optimize("", on))
#define OE_NO_RETURN __attribute__((__noreturn__))
#define OE_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#define OE_PACK_BEGIN _Pragma("pack(push, 1)")
#define OE_PACK_END _Pragma("pack(pop)")
#define OE_PAGE_SIZE 0x1000
#define OE_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#define OE_RETURNS_TWICE __attribute__((returns_twice))
#define OE_STATIC_ASSERT(COND)       \
    typedef unsigned char OE_CONCAT( \
        __OE_STATIC_ASSERT, "__LINE__")[(COND) ? 1 : -1] OE_UNUSED_ATTRIBUTE
#define OE_UNUSED(P) (void)(P)
#define OE_UNUSED_ATTRIBUTE __attribute__((unused))
#define OE_UNUSED_FUNC __attribute__((unused))
#define OE_USED __attribute__((__used__))
#define OE_WEAK __attribute__((weak))
#define OE_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))
#define OE_ZERO_SIZED_ARRAY __pragma(warning(suppress : 4200))

#define __OE_CONCAT(X, Y) X##Y
#define OE_F_OK 0
#define OE_NGROUP_MAX 256
#define OE_R_OK 4
#define OE_SEEK_CUR 1
#define OE_SEEK_END 2
#define OE_SEEK_SET 0
#define OE_STDERR_FILENO 2
#define OE_STDIN_FILENO 0
#define OE_STDOUT_FILENO 1
#define OE_W_OK 2
#define OE_X_OK 1


#define oe_va_arg __builtin_va_arg
#define oe_va_copy __builtin_va_copy
#define oe_va_end __builtin_va_end
#define oe_va_list __builtin_va_list
#define oe_va_start __builtin_va_start
#define va_arg oe_va_arg
#define va_copy oe_va_copy
#define va_end oe_va_end
#define va_list oe_va_list
#define va_start oe_va_start




#define OE_SYS__sysctl 156
#define OE_SYS_accept 43
#define OE_SYS_accept4 288
#define OE_SYS_access 21
#define OE_SYS_acct 163
#define OE_SYS_add_key 248
#define OE_SYS_adjtimex 159
#define OE_SYS_afs_syscall 183
#define OE_SYS_alarm 37
#define OE_SYS_arch_prctl 158
#define OE_SYS_bind 49
#define OE_SYS_bpf 321
#define OE_SYS_brk 12
#define OE_SYS_capget 125
#define OE_SYS_capset 126
#define OE_SYS_chdir 80
#define OE_SYS_chmod 90
#define OE_SYS_chown 92
#define OE_SYS_chroot 161
#define OE_SYS_clock_adjtime 305
#define OE_SYS_clock_getres 229
#define OE_SYS_clock_gettime 228
#define OE_SYS_clock_nanosleep 230
#define OE_SYS_clock_settime 227
#define OE_SYS_clone 56
#define OE_SYS_close 3
#define OE_SYS_connect 42
#define OE_SYS_copy_file_range 326
#define OE_SYS_creat 85
#define OE_SYS_create_module 174
#define OE_SYS_delete_module 176
#define OE_SYS_dup 32
#define OE_SYS_dup2 33
#define OE_SYS_dup3 292
#define OE_SYS_epoll_create 213
#define OE_SYS_epoll_create1 291
#define OE_SYS_epoll_ctl 233
#define OE_SYS_epoll_ctl_old 214
#define OE_SYS_epoll_pwait 281
#define OE_SYS_epoll_wait 232
#define OE_SYS_epoll_wait_old 215
#define OE_SYS_eventfd 284
#define OE_SYS_eventfd2 290
#define OE_SYS_execve 59
#define OE_SYS_execveat 322
#define OE_SYS_exit 60
#define OE_SYS_exit_group 231
#define OE_SYS_faccessat 269
#define OE_SYS_fadvise64 221
#define OE_SYS_fallocate 285
#define OE_SYS_fanotify_init 300
#define OE_SYS_fanotify_mark 301
#define OE_SYS_fchdir 81
#define OE_SYS_fchmod 91
#define OE_SYS_fchmodat 268
#define OE_SYS_fchown 93
#define OE_SYS_fchownat 260
#define OE_SYS_fcntl 72
#define OE_SYS_fdatasync 75
#define OE_SYS_fgetxattr 193
#define OE_SYS_finit_module 313
#define OE_SYS_flistxattr 196
#define OE_SYS_flock 73
#define OE_SYS_fork 57
#define OE_SYS_fremovexattr 199
#define OE_SYS_fsetxattr 190
#define OE_SYS_fstat 5
#define OE_SYS_fstatfs 138
#define OE_SYS_fsync 74
#define OE_SYS_ftruncate 77
#define OE_SYS_futex 202
#define OE_SYS_futimesat 261
#define OE_SYS_get_kernel_syms 177
#define OE_SYS_get_mempolicy 239
#define OE_SYS_get_robust_list 274
#define OE_SYS_get_thread_area 211
#define OE_SYS_getcpu 309
#define OE_SYS_getcwd 79
#define OE_SYS_getdents 78
#define OE_SYS_getdents64 217
#define OE_SYS_getegid 108
#define OE_SYS_geteuid 107
#define OE_SYS_getgid 104
#define OE_SYS_getgroups 115
#define OE_SYS_getitimer 36
#define OE_SYS_getpeername 52
#define OE_SYS_getpgid 121
#define OE_SYS_getpgrp 111
#define OE_SYS_getpid 39
#define OE_SYS_getpmsg 181
#define OE_SYS_getppid 110
#define OE_SYS_getpriority 140
#define OE_SYS_getrandom 318
#define OE_SYS_getresgid 120
#define OE_SYS_getresuid 118
#define OE_SYS_getrlimit 97
#define OE_SYS_getrusage 98
#define OE_SYS_getsid 124
#define OE_SYS_getsockname 51
#define OE_SYS_getsockopt 55
#define OE_SYS_gettid 186
#define OE_SYS_gettimeofday 96
#define OE_SYS_getuid 102
#define OE_SYS_getxattr 191
#define OE_SYS_init_module 175
#define OE_SYS_inotify_add_watch 254
#define OE_SYS_inotify_init 253
#define OE_SYS_inotify_init1 294
#define OE_SYS_inotify_rm_watch 255
#define OE_SYS_io_cancel 210
#define OE_SYS_io_destroy 207
#define OE_SYS_io_getevents 208
#define OE_SYS_io_pgetevents 333
#define OE_SYS_io_rseq 334
#define OE_SYS_io_setup 206
#define OE_SYS_io_submit 209
#define OE_SYS_ioctl 16
#define OE_SYS_ioperm 173
#define OE_SYS_iopl 172
#define OE_SYS_ioprio_get 252
#define OE_SYS_ioprio_set 251
#define OE_SYS_kcmp 312
#define OE_SYS_kexec_file_load 320
#define OE_SYS_kexec_load 246
#define OE_SYS_keyctl 250
#define OE_SYS_kill 62
#define OE_SYS_lchown 94
#define OE_SYS_lgetxattr 192
#define OE_SYS_link 86
#define OE_SYS_linkat 265
#define OE_SYS_listen 50
#define OE_SYS_listxattr 194
#define OE_SYS_llistxattr 195
#define OE_SYS_lookup_dcookie 212
#define OE_SYS_lremovexattr 198
#define OE_SYS_lseek 8
#define OE_SYS_lsetxattr 189
#define OE_SYS_lstat 6
#define OE_SYS_madvise 28
#define OE_SYS_mbind 237
#define OE_SYS_membarrier 324
#define OE_SYS_memfd_create 319
#define OE_SYS_migrate_pages 256
#define OE_SYS_mincore 27
#define OE_SYS_mkdir 83
#define OE_SYS_mkdirat 258
#define OE_SYS_mknod 133
#define OE_SYS_mknodat 259
#define OE_SYS_mlock 149
#define OE_SYS_mlock2 325
#define OE_SYS_mlockall 151
#define OE_SYS_mmap 9
#define OE_SYS_modify_ldt 154
#define OE_SYS_mount 165
#define OE_SYS_move_pages 279
#define OE_SYS_mprotect 10
#define OE_SYS_mq_getsetattr 245
#define OE_SYS_mq_notify 244
#define OE_SYS_mq_open 240
#define OE_SYS_mq_timedreceive 243
#define OE_SYS_mq_timedsend 242
#define OE_SYS_mq_unlink 241
#define OE_SYS_mremap 25
#define OE_SYS_msgctl 71
#define OE_SYS_msgget 68
#define OE_SYS_msgrcv 70
#define OE_SYS_msgsnd 69
#define OE_SYS_msync 26
#define OE_SYS_munlock 150
#define OE_SYS_munlockall 152
#define OE_SYS_munmap 11
#define OE_SYS_name_to_handle_at 303
#define OE_SYS_nanosleep 35
#define OE_SYS_newfstatat 262
#define OE_SYS_nfsservctl 180
#define OE_SYS_open 2
#define OE_SYS_open_by_handle_at 304
#define OE_SYS_openat 257
#define OE_SYS_pause 34
#define OE_SYS_perf_event_open 298
#define OE_SYS_personality 135
#define OE_SYS_pipe 22
#define OE_SYS_pipe2 293
#define OE_SYS_pivot_root 155
#define OE_SYS_pkey_alloc 330
#define OE_SYS_pkey_free 331
#define OE_SYS_pkey_mprotect 329
#define OE_SYS_poll 7
#define OE_SYS_ppoll 271
#define OE_SYS_prctl 157
#define OE_SYS_pread64 17
#define OE_SYS_preadv 295
#define OE_SYS_preadv2 327
#define OE_SYS_prlimit64 302
#define OE_SYS_process_vm_readv 310
#define OE_SYS_process_vm_writev 311
#define OE_SYS_pselect6 270
#define OE_SYS_ptrace 101
#define OE_SYS_putpmsg 182
#define OE_SYS_pwrite64 18
#define OE_SYS_pwritev 296
#define OE_SYS_pwritev2 328
#define OE_SYS_query_module 178
#define OE_SYS_quotactl 179
#define OE_SYS_read 0
#define OE_SYS_readahead 187
#define OE_SYS_readlink 89
#define OE_SYS_readlinkat 267
#define OE_SYS_readv 19
#define OE_SYS_reboot 169
#define OE_SYS_recvfrom 45
#define OE_SYS_recvmmsg 299
#define OE_SYS_recvmsg 47
#define OE_SYS_remap_file_pages 216
#define OE_SYS_removexattr 197
#define OE_SYS_rename 82
#define OE_SYS_renameat 264
#define OE_SYS_renameat2 316
#define OE_SYS_request_key 249
#define OE_SYS_restart_syscall 219
#define OE_SYS_rmdir 84
#define OE_SYS_rt_sigaction 13
#define OE_SYS_rt_sigpending 127
#define OE_SYS_rt_sigprocmask 14
#define OE_SYS_rt_sigqueueinfo 129
#define OE_SYS_rt_sigreturn 15
#define OE_SYS_rt_sigsuspend 130
#define OE_SYS_rt_sigtimedwait 128
#define OE_SYS_rt_tgsigqueueinfo 297
#define OE_SYS_sched_get_priority_max 146
#define OE_SYS_sched_get_priority_min 147
#define OE_SYS_sched_getaffinity 204
#define OE_SYS_sched_getattr 315
#define OE_SYS_sched_getparam 143
#define OE_SYS_sched_getscheduler 145
#define OE_SYS_sched_rr_get_interval 148
#define OE_SYS_sched_setaffinity 203
#define OE_SYS_sched_setattr 314
#define OE_SYS_sched_setparam 142
#define OE_SYS_sched_setscheduler 144
#define OE_SYS_sched_yield 24
#define OE_SYS_seccomp 317
#define OE_SYS_security 185
#define OE_SYS_select 23
#define OE_SYS_semctl 66
#define OE_SYS_semget 64
#define OE_SYS_semop 65
#define OE_SYS_semtimedop 220
#define OE_SYS_sendfile 40
#define OE_SYS_sendmmsg 307
#define OE_SYS_sendmsg 46
#define OE_SYS_sendto 44
#define OE_SYS_set_mempolicy 238
#define OE_SYS_set_robust_list 273
#define OE_SYS_set_thread_area 205
#define OE_SYS_set_tid_address 218
#define OE_SYS_setdomainname 171
#define OE_SYS_setfsgid 123
#define OE_SYS_setfsuid 122
#define OE_SYS_setgid 106
#define OE_SYS_setgroups 116
#define OE_SYS_sethostname 170
#define OE_SYS_setitimer 38
#define OE_SYS_setns 308
#define OE_SYS_setpgid 109
#define OE_SYS_setpriority 141
#define OE_SYS_setregid 114
#define OE_SYS_setresgid 119
#define OE_SYS_setresuid 117
#define OE_SYS_setreuid 113
#define OE_SYS_setrlimit 160
#define OE_SYS_setsid 112
#define OE_SYS_setsockopt 54
#define OE_SYS_settimeofday 164
#define OE_SYS_setuid 105
#define OE_SYS_setxattr 188
#define OE_SYS_shmat 30
#define OE_SYS_shmctl 31
#define OE_SYS_shmdt 67
#define OE_SYS_shmget 29
#define OE_SYS_shutdown 48
#define OE_SYS_sigaltstack 131
#define OE_SYS_signalfd 282
#define OE_SYS_signalfd4 289
#define OE_SYS_socket 41
#define OE_SYS_socketpair 53
#define OE_SYS_splice 275
#define OE_SYS_stat 4
#define OE_SYS_statfs 137
#define OE_SYS_statx 332
#define OE_SYS_swapoff 168
#define OE_SYS_swapon 167
#define OE_SYS_symlink 88
#define OE_SYS_symlinkat 266
#define OE_SYS_sync 162
#define OE_SYS_sync_file_range 277
#define OE_SYS_syncfs 306
#define OE_SYS_sysfs 139
#define OE_SYS_sysinfo 99
#define OE_SYS_syslog 103
#define OE_SYS_tee 276
#define OE_SYS_tgkill 234
#define OE_SYS_time 201
#define OE_SYS_timer_create 222
#define OE_SYS_timer_delete 226
#define OE_SYS_timer_getoverrun 225
#define OE_SYS_timer_gettime 224
#define OE_SYS_timer_settime 223
#define OE_SYS_timerfd_create 283
#define OE_SYS_timerfd_gettime 287
#define OE_SYS_timerfd_settime 286
#define OE_SYS_times 100
#define OE_SYS_tkill 200
#define OE_SYS_truncate 76
#define OE_SYS_tuxcall 184
#define OE_SYS_umask 95
#define OE_SYS_umount2 166
#define OE_SYS_uname 63
#define OE_SYS_unlink 87
#define OE_SYS_unlinkat 263
#define OE_SYS_unshare 272
#define OE_SYS_uselib 134
#define OE_SYS_userfaultfd 323
#define OE_SYS_ustat 136
#define OE_SYS_utime 132
#define OE_SYS_utimensat 280
#define OE_SYS_utimes 235
#define OE_SYS_vfork 58
#define OE_SYS_vhangup 153
#define OE_SYS_vmsplice 278
#define OE_SYS_vserver 236
#define OE_SYS_wait4 61
#define OE_SYS_waitid 247
#define OE_SYS_write 1
#define OE_SYS_writev 20
#define OE_R_OR 04
#define OE_S_IFBLK 0060000
#define OE_S_IFCHR 0020000
#define OE_S_IFDIR 0040000
#define OE_S_IFIFO 0010000
#define OE_S_IFLNK 0120000
#define OE_S_IFMT 0170000
#define OE_S_IFREG 0100000
#define OE_S_IFSOCK 0140000
#define OE_S_IRGRP 0x0020
#define OE_S_IROTH 0x0004
#define OE_S_IRUSR 0x0100
#define OE_S_IRWGRP (OE_S_IRGRP | OE_S_IWGRP)
#define OE_S_IRWOTH (OE_S_IROTH | OE_S_IWOTH)
#define OE_S_IRWUSR (OE_S_IRUSR | OE_S_IWUSR)
#define OE_S_IRWXGRP (OE_S_IRGRP | OE_S_IWGRP | OE_S_IXGRP)
#define OE_S_IRWXOTH (OE_S_IROTH | OE_S_IWOTH | OE_S_IXOTH)
#define OE_S_IRWXUSR (OE_S_IRUSR | OE_S_IWUSR | OE_S_IXUSR)
#define OE_S_ISBLK(mode) (((mode)&OE_S_IFMT) == OE_S_IFBLK)
#define OE_S_ISCHR(mode) (((mode)&OE_S_IFMT) == OE_S_IFCHR)
#define OE_S_ISDIR(mode) (((mode)&OE_S_IFMT) == OE_S_IFDIR)
#define OE_S_ISFIFO(mode) (((mode)&OE_S_IFMT) == OE_S_IFIFO)
#define OE_S_ISGID 0x0400
#define OE_S_ISLNK(mode) (((mode)&OE_S_IFMT) == OE_S_IFLNK)
#define OE_S_ISREG(mode) (((mode)&OE_S_IFMT) == OE_S_IFREG)
#define OE_S_ISSOCK(mode) (((mode)&OE_S_IFMT) == OE_S_IFSOCK)
#define OE_S_ISUID 0x0800
#define OE_S_ISVTX 0x0200
#define OE_S_IWGRP 0x0010
#define OE_S_IWOTH 0x0002
#define OE_S_IWUSR 0x0080
#define OE_S_IXGRP 0x0008
#define OE_S_IXOTH 0x0001
#define OE_S_IXUSR 0x0040
#define OE_W_OR 02
#define OE_X_OR 01

#define st_atime st_atim.tv_sec
#define st_ctime st_ctim.tv_sec
#define st_mtime st_mtim.tv_sec

#define OE_AF_ALG OE_PF_ALG
#define OE_AF_APPLETALK OE_PF_APPLETALK
#define OE_AF_ASH OE_PF_ASH
#define OE_AF_ATMPVC OE_PF_ATMPVC
#define OE_AF_ATMSVC OE_PF_ATMSVC
#define OE_AF_AX25 OE_PF_AX25
#define OE_AF_BLUETOOTH OE_PF_BLUETOOTH
#define OE_AF_BRIDGE OE_PF_BRIDGE
#define OE_AF_CAIF OE_PF_CAIF
#define OE_AF_CAN OE_PF_CAN
#define OE_AF_DECnet OE_PF_DECnet
#define OE_AF_ECONET OE_PF_ECONET
#define OE_AF_FILE OE_PF_FILE
#define OE_AF_IB OE_PF_IB
#define OE_AF_IEEE802154 OE_PF_IEEE802154
#define OE_AF_INET OE_PF_INET
#define OE_AF_INET6 OE_PF_INET6
#define OE_AF_IPX OE_PF_IPX
#define OE_AF_IRDA OE_PF_IRDA
#define OE_AF_ISDN OE_PF_ISDN
#define OE_AF_IUCV OE_PF_IUCV
#define OE_AF_KCM OE_PF_KCM
#define OE_AF_KEY OE_PF_KEY
#define OE_AF_LLC OE_PF_LLC
#define OE_AF_LOCAL OE_PF_LOCAL
#define OE_AF_MAX OE_PF_MAX
#define OE_AF_MPLS OE_PF_MPLS
#define OE_AF_NETBEUI OE_PF_NETBEUI
#define OE_AF_NETLINK OE_PF_NETLINK
#define OE_AF_NETROM OE_PF_NETROM
#define OE_AF_NFC OE_PF_NFC
#define OE_AF_PACKET OE_PF_PACKET
#define OE_AF_PHONET OE_PF_PHONET
#define OE_AF_PPPOX OE_PF_PPPOX
#define OE_AF_QIPCRTR OE_PF_QIPCRTR
#define OE_AF_RDS OE_PF_RDS
#define OE_AF_ROSE OE_PF_ROSE
#define OE_AF_ROUTE OE_PF_ROUTE
#define OE_AF_RXRPC OE_PF_RXRPC
#define OE_AF_SECURITY OE_PF_SECURITY
#define OE_AF_SMC OE_PF_SMC
#define OE_AF_SNA OE_PF_SNA
#define OE_AF_TIPC OE_PF_TIPC
#define OE_AF_UNIX OE_PF_UNIX
#define OE_AF_UNSPEC OE_PF_UNSPEC
#define OE_AF_VSOCK OE_PF_VSOCK
#define OE_AF_WANPIPE OE_PF_WANPIPE
#define OE_AF_X25 OE_PF_X25
#define OE_MSG_PEEK 0x0002
#define OE_PF_ALG 38           
#define OE_PF_APPLETALK 5   
#define OE_PF_ASH 18           
#define OE_PF_ATMPVC 8      
#define OE_PF_ATMSVC 20        
#define OE_PF_AX25 3        
#define OE_PF_BLUETOOTH 31     
#define OE_PF_BRIDGE 7      
#define OE_PF_CAIF 37          
#define OE_PF_CAN 29           
#define OE_PF_DECnet 12     
#define OE_PF_ECONET 19        
#define OE_PF_FILE PF_LOCAL 
#define OE_PF_HOST 51          
#define OE_PF_IB 27            
#define OE_PF_IEEE802154 36    
#define OE_PF_INET 2        
#define OE_PF_INET6 10      
#define OE_PF_IPX 4         
#define OE_PF_IRDA 23          
#define OE_PF_ISDN 34          
#define OE_PF_IUCV 32          
#define OE_PF_KCM 41           
#define OE_PF_KEY 15        
#define OE_PF_LLC 26           
#define OE_PF_LOCAL 1       
#define OE_PF_MAX 51           
#define OE_PF_MPLS 28          
#define OE_PF_NETBEUI 13    
#define OE_PF_NETLINK 16
#define OE_PF_NETROM 6      
#define OE_PF_NFC 39           
#define OE_PF_PACKET 17        
#define OE_PF_PHONET 35        
#define OE_PF_PPPOX 24         
#define OE_PF_QIPCRTR 42       
#define OE_PF_RDS 21           
#define OE_PF_ROSE 11       
#define OE_PF_ROUTE PF_NETLINK 
#define OE_PF_RXRPC 33         
#define OE_PF_SECURITY 14   
#define OE_PF_SMC 43           
#define OE_PF_SNA 22           
#define OE_PF_TIPC 30          
#define OE_PF_UNIX PF_LOCAL 
#define OE_PF_UNSPEC 0      
#define OE_PF_VSOCK 40         
#define OE_PF_WANPIPE 25       
#define OE_PF_X25 9         
#define OE_SHUT_RD 0
#define OE_SHUT_RDWR 2
#define OE_SHUT_WR 1
#define OE_SOL_SOCKET 1
#define OE_SO_BROADCAST 6
#define OE_SO_BSDCOMPAT 14
#define OE_SO_DEBUG 1
#define OE_SO_DONTROUTE 5
#define OE_SO_ERROR 4
#define OE_SO_KEEPALIVE 9
#define OE_SO_LINGER 13
#define OE_SO_NO_CHECK 11
#define OE_SO_OOBINLINE 10
#define OE_SO_PRIORITY 12
#define OE_SO_RCVBUF 8
#define OE_SO_RCVBUFFORCE 33
#define OE_SO_REUSEADDR 2
#define OE_SO_REUSEPORT 15
#define OE_SO_SNDBUF 7
#define OE_SO_SNDBUFFORCE 32
#define OE_SO_TYPE 3

#define __OE_IOVEC oe_iovec
#define __OE_MSGHDR oe_msghdr
#define __OE_SOCKADDR_STORAGE oe_sockaddr_storage
#define OE_FD_SETSIZE 1024

#define __OE_FD_SET oe_fd_set

#define OE_POLLERR    0x008
#define OE_POLLHUP    0x010
#define OE_POLLIN     0x001
#define OE_POLLMSG    0x400
#define OE_POLLNVAL   0x020
#define OE_POLLOUT    0x004
#define OE_POLLPRI    0x002
#define OE_POLLRDBAND 0x080
#define OE_POLLRDHUP  0x2000
#define OE_POLLRDNORM 0x040
#define OE_POLLWRBAND 0x200
#define OE_POLLWRNORM 0x100

#define OE_MS_RDONLY 1

#define OE_TIOCGWINSZ 0x5413

#define OE_RAISE_ERRNO(ERRNO)                                  \
    do                                                         \
    {                                                          \
        int __err = ERRNO;                                     \
        oe_log(OE_LOG_LEVEL_ERROR, "oe_errno=%d [%s %s:%d]\n", \
            __err, "__FILE__", __FUNCTION__, "__LINE__");          \
        oe_errno = __err;                                      \
        goto done;                                             \
    }                                                          \
    while (0)
#define OE_RAISE_ERRNO_MSG(ERRNO, FMT, ...)                         \
    do                                                              \
    {                                                               \
        int __err = ERRNO;                                          \
        oe_log(OE_LOG_LEVEL_ERROR, FMT " oe_errno=%d [%s %s:%d]\n", \
           ##__VA_ARGS__, __err, "__FILE__", __FUNCTION__, "__LINE__"); \
        oe_errno = __err;                                           \
        goto done;                                                  \
    }                                                               \
    while (0)

#define OE_DEVICE_NAME_CONSOLE_FILE_SYSTEM "oe_console_file_system"
#define OE_DEVICE_NAME_HOST_EPOLL "oe_host_epoll"
#define OE_DEVICE_NAME_HOST_FILE_SYSTEM OE_HOST_FILE_SYSTEM
#define OE_DEVICE_NAME_HOST_SOCKET_INTERFACE "oe_host_socket_interface"
#define OE_DEVICE_NAME_SGX_FILE_SYSTEM OE_SGX_FILE_SYSTEM




#define OE_EPOLL_CTL_ADD 1
#define OE_EPOLL_CTL_DEL 2
#define OE_EPOLL_CTL_MOD 3

#define OE_LLD(_X_) _X_
#define OE_LLU(_X_) _X_
#define OE_LLX(_X_) _X_


#define __OE_SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))
#define OE_HOST_FILE_SYSTEM "oe_host_file_system"

#define E2BIG OE_E2BIG
#define EACCES OE_EACCES
#define EADDRINUSE OE_EADDRINUSE
#define EADDRNOTAVAIL OE_EADDRNOTAVAIL
#define EADV OE_EADV
#define EAFNOSUPPORT OE_EAFNOSUPPORT
#define EAGAIN OE_EAGAIN
#define EALREADY OE_EALREADY
#define EBADE OE_EBADE
#define EBADF OE_EBADF
#define EBADFD OE_EBADFD
#define EBADMSG OE_EBADMSG
#define EBADR OE_EBADR
#define EBADRQC OE_EBADRQC
#define EBADSLT OE_EBADSLT
#define EBFONT OE_EBFONT
#define EBUSY OE_EBUSY
#define ECANCELED OE_ECANCELED
#define ECHILD OE_ECHILD
#define ECHRNG OE_ECHRNG
#define ECOMM OE_ECOMM
#define ECONNABORTED OE_ECONNABORTED
#define ECONNREFUSED OE_ECONNREFUSED
#define ECONNRESET OE_ECONNRESET
#define EDEADLK OE_EDEADLK
#define EDEADLOCK OE_EDEADLOCK
#define EDESTADDRREQ OE_EDESTADDRREQ
#define EDOM OE_EDOM
#define EDOTDOT OE_EDOTDOT
#define EDQUOT OE_EDQUOT
#define EEXIST OE_EEXIST
#define EFAULT OE_EFAULT
#define EFBIG OE_EFBIG
#define EHOSTDOWN OE_EHOSTDOWN
#define EHOSTUNREACH OE_EHOSTUNREACH
#define EHWPOISON OE_EHWPOISON
#define EIDRM OE_EIDRM
#define EILSEQ OE_EILSEQ
#define EINPROGRESS OE_EINPROGRESS
#define EINTR OE_EINTR
#define EINVAL OE_EINVAL
#define EIO OE_EIO
#define EISCONN OE_EISCONN
#define EISDIR OE_EISDIR
#define EISNAM OE_EISNAM
#define EKEYEXPIRED OE_EKEYEXPIRED
#define EKEYREJECTED OE_EKEYREJECTED
#define EKEYREVOKED OE_EKEYREVOKED
#define EL2HLT OE_EL2HLT
#define EL2NSYNC OE_EL2NSYNC
#define EL3HLT OE_EL3HLT
#define EL3RST OE_EL3RST
#define ELIBACC OE_ELIBACC
#define ELIBBAD OE_ELIBBAD
#define ELIBEXEC OE_ELIBEXEC
#define ELIBMAX OE_ELIBMAX
#define ELIBSCN OE_ELIBSCN
#define ELNRNG OE_ELNRNG
#define ELOOP OE_ELOOP
#define EMEDIUMTYPE OE_EMEDIUMTYPE
#define EMFILE OE_EMFILE
#define EMLINK OE_EMLINK
#define EMSGSIZE OE_EMSGSIZE
#define EMULTIHOP OE_EMULTIHOP
#define ENAMETOOLONG OE_ENAMETOOLONG
#define ENAVAIL OE_ENAVAIL
#define ENETDOWN OE_ENETDOWN
#define ENETRESET OE_ENETRESET
#define ENETUNREACH OE_ENETUNREACH
#define ENFILE OE_ENFILE
#define ENOANO OE_ENOANO
#define ENOBUFS OE_ENOBUFS
#define ENOCSI OE_ENOCSI
#define ENODATA OE_ENODATA
#define ENODEV OE_ENODEV
#define ENOENT OE_ENOENT
#define ENOEXEC OE_ENOEXEC
#define ENOKEY OE_ENOKEY
#define ENOLCK OE_ENOLCK
#define ENOLINK OE_ENOLINK
#define ENOMEDIUM OE_ENOMEDIUM
#define ENOMEM OE_ENOMEM
#define ENOMSG OE_ENOMSG
#define ENONET OE_ENONET
#define ENOPKG OE_ENOPKG
#define ENOPROTOOPT OE_ENOPROTOOPT
#define ENOSPC OE_ENOSPC
#define ENOSR OE_ENOSR
#define ENOSTR OE_ENOSTR
#define ENOSYS OE_ENOSYS
#define ENOTBLK OE_ENOTBLK
#define ENOTCONN OE_ENOTCONN
#define ENOTDIR OE_ENOTDIR
#define ENOTEMPTY OE_ENOTEMPTY
#define ENOTNAM OE_ENOTNAM
#define ENOTRECOVERABLE OE_ENOTRECOVERABLE
#define ENOTSOCK OE_ENOTSOCK
#define ENOTSUP OE_ENOTSUP
#define ENOTTY OE_ENOTTY
#define ENOTUNIQ OE_ENOTUNIQ
#define ENXIO OE_ENXIO
#define EOPNOTSUPP OE_EOPNOTSUPP
#define EOVERFLOW OE_EOVERFLOW
#define EOWNERDEAD OE_EOWNERDEAD
#define EPERM OE_EPERM
#define EPFNOSUPPORT OE_EPFNOSUPPORT
#define EPIPE OE_EPIPE
#define EPROTO OE_EPROTO
#define EPROTONOSUPPORT OE_EPROTONOSUPPORT
#define EPROTOTYPE OE_EPROTOTYPE
#define ERANGE OE_ERANGE
#define EREMCHG OE_EREMCHG
#define EREMOTE OE_EREMOTE
#define EREMOTEIO OE_EREMOTEIO
#define ERESTART OE_ERESTART
#define ERFKILL OE_ERFKILL
#define EROFS OE_EROFS
#define ESHUTDOWN OE_ESHUTDOWN
#define ESOCKTNOSUPPORT OE_ESOCKTNOSUPPORT
#define ESPIPE OE_ESPIPE
#define ESRCH OE_ESRCH
#define ESRMNT OE_ESRMNT
#define ESTALE OE_ESTALE
#define ESTRPIPE OE_ESTRPIPE
#define ETIME OE_ETIME
#define ETIMEDOUT OE_ETIMEDOUT
#define ETOOMANYREFS OE_ETOOMANYREFS
#define ETXTBSY OE_ETXTBSY
#define EUCLEAN OE_EUCLEAN
#define EUNATCH OE_EUNATCH
#define EUSERS OE_EUSERS
#define EWOULDBLOCK OE_EWOULDBLOCK
#define EXDEV OE_EXDEV
#define EXFULL OE_EXFULL
#define OE_E2BIG            7
#define OE_EACCES          13
#define OE_EADDRINUSE      98
#define OE_EADDRNOTAVAIL   99
#define OE_EADV            68
#define OE_EAFNOSUPPORT    97
#define OE_EAGAIN          11
#define OE_EALREADY        114
#define OE_EBADE           52
#define OE_EBADF            9
#define OE_EBADFD          77
#define OE_EBADMSG         74
#define OE_EBADR           53
#define OE_EBADRQC         56
#define OE_EBADSLT         57
#define OE_EBFONT          59
#define OE_EBUSY           16
#define OE_ECANCELED       125
#define OE_ECHILD          10
#define OE_ECHRNG          44
#define OE_ECOMM           70
#define OE_ECONNABORTED    103
#define OE_ECONNREFUSED    111
#define OE_ECONNRESET      104
#define OE_EDEADLK         35
#define OE_EDEADLOCK       OE_EDEADLK
#define OE_EDESTADDRREQ    89
#define OE_EDOM            33
#define OE_EDOTDOT         73
#define OE_EDQUOT          122
#define OE_EEXIST          17
#define OE_EFAULT          14
#define OE_EFBIG           27
#define OE_EHOSTDOWN       112
#define OE_EHOSTUNREACH    113
#define OE_EHWPOISON       133
#define OE_EIDRM           43
#define OE_EILSEQ          84
#define OE_EINPROGRESS     115
#define OE_EINTR            4
#define OE_EINVAL          22
#define OE_EIO              5
#define OE_EISCONN         106
#define OE_EISDIR          21
#define OE_EISNAM          120
#define OE_EKEYEXPIRED     127
#define OE_EKEYREJECTED    129
#define OE_EKEYREVOKED     128
#define OE_EL2HLT          51
#define OE_EL2NSYNC        45
#define OE_EL3HLT          46
#define OE_EL3RST          47
#define OE_ELIBACC         79
#define OE_ELIBBAD         80
#define OE_ELIBEXEC        83
#define OE_ELIBMAX         82
#define OE_ELIBSCN         81
#define OE_ELNRNG          48
#define OE_ELOOP           40
#define OE_EMEDIUMTYPE     124
#define OE_EMFILE          24
#define OE_EMLINK          31
#define OE_EMSGSIZE        90
#define OE_EMULTIHOP       72
#define OE_ENAMETOOLONG    36
#define OE_ENAVAIL         119
#define OE_ENETDOWN        100
#define OE_ENETRESET       102
#define OE_ENETUNREACH     101
#define OE_ENFILE          23
#define OE_ENOANO          55
#define OE_ENOBUFS         105
#define OE_ENOCSI          50
#define OE_ENODATA         61
#define OE_ENODEV          19
#define OE_ENOENT           2
#define OE_ENOEXEC          8
#define OE_ENOKEY          126
#define OE_ENOLCK          37
#define OE_ENOLINK         67
#define OE_ENOMEDIUM       123
#define OE_ENOMEM          12
#define OE_ENOMSG          42
#define OE_ENONET          64
#define OE_ENOPKG          65
#define OE_ENOPROTOOPT     92
#define OE_ENOSPC          28
#define OE_ENOSR           63
#define OE_ENOSTR          60
#define OE_ENOSYS          38
#define OE_ENOTBLK         15
#define OE_ENOTCONN        107
#define OE_ENOTDIR         20
#define OE_ENOTEMPTY       39
#define OE_ENOTNAM         118
#define OE_ENOTRECOVERABLE 131
#define OE_ENOTSOCK        88
#define OE_ENOTSUP         OE_EOPNOTSUPP
#define OE_ENOTTY          25
#define OE_ENOTUNIQ        76
#define OE_ENXIO            6
#define OE_EOPNOTSUPP      95
#define OE_EOVERFLOW       75
#define OE_EOWNERDEAD      130
#define OE_EPERM            1
#define OE_EPFNOSUPPORT    96
#define OE_EPIPE           32
#define OE_EPROCLIM        134
#define OE_EPROTO          71
#define OE_EPROTONOSUPPORT 93
#define OE_EPROTOTYPE      91
#define OE_ERANGE          34
#define OE_EREMCHG         78
#define OE_EREMOTE         66
#define OE_EREMOTEIO       121
#define OE_ERESTART        85
#define OE_ERFKILL         132
#define OE_EROFS           30
#define OE_ESHUTDOWN       108
#define OE_ESOCKTNOSUPPORT 94
#define OE_ESPIPE          29
#define OE_ESRCH            3
#define OE_ESRMNT          69
#define OE_ESTALE          116
#define OE_ESTRPIPE        86
#define OE_ETIME           62
#define OE_ETIMEDOUT       110
#define OE_ETOOMANYREFS    109
#define OE_ETXTBSY         26
#define OE_EUCLEAN         117
#define OE_EUNATCH         49
#define OE_EUSERS          87
#define OE_EWOULDBLOCK     OE_EAGAIN
#define OE_EXDEV           18
#define OE_EXFULL          54

#define errno oe_errno
#define oe_errno *__oe_errno_location()
#define OE_AT_FDCWD (-100)
#define OE_AT_REMOVEDIR 0x200
#define OE_F_DUPFD          0
#define OE_F_GETFD          1
#define OE_F_GETFL          3
#define OE_F_GETLK          5
#define OE_F_GETLK64       OE_F_GETLK
#define OE_F_GETOWN         9
#define OE_F_GETOWNER_UIDS 17
#define OE_F_GETOWN_EX     16
#define OE_F_GETSIG        11
#define OE_F_OFD_GETLK     36
#define OE_F_OFD_SETLK     37
#define OE_F_OFD_SETLKW    38
#define OE_F_SETFD          2
#define OE_F_SETFL          4
#define OE_F_SETLK          6
#define OE_F_SETLK64       OE_F_SETLK
#define OE_F_SETLKW         7
#define OE_F_SETLKW64      OE_F_SETLKW
#define OE_F_SETOWN         8
#define OE_F_SETOWN_EX     15
#define OE_F_SETSIG        10
#define OE_O_APPEND        000002000
#define OE_O_ASYNC         000020000
#define OE_O_CLOEXEC       002000000
#define OE_O_CREAT         000000100
#define OE_O_DIRECT        000040000
#define OE_O_DIRECTORY     000200000
#define OE_O_DSYNC         000010000
#define OE_O_EXCL          000000200
#define OE_O_LARGEFILE     000000000
#define OE_O_NDELAY        O_NONBLOCK
#define OE_O_NOATIME       001000000
#define OE_O_NOCTTY        000000400
#define OE_O_NOFOLLOW      000400000
#define OE_O_NONBLOCK      000004000
#define OE_O_PATH          010000000
#define OE_O_RDONLY        000000000
#define OE_O_RDWR          000000002
#define OE_O_RSYNC         004010000
#define OE_O_SYNC          004010000
#define OE_O_TMPFILE       020200000
#define OE_O_TRUNC         000001000
#define OE_O_WRONLY        000000001

#define oe_flock64 oe_flock
#define OE_DT_BLK 6
#define OE_DT_CHR 2
#define OE_DT_DIR 4
#define OE_DT_FIFO 1
#define OE_DT_LNK 10
#define OE_DT_REG 8
#define OE_DT_SOCK 12
#define OE_DT_UNKNOWN 0
#define OE_DT_WHT 14

#define CHAR_BIT OE_CHAR_BIT
#define CHAR_MAX OE_CHAR_MAX
#define CHAR_MIN OE_CHAR_MIN
#define INT_MAX OE_INT_MAX
#define INT_MIN OE_INT_MIN
#define IOV_MAX OE_IOV_MAX
#define LLONG_MAX OE_LLONG_MAX
#define LLONG_MIN OE_LLONG_MIN
#define LONG_MAX OE_LONG_MAX
#define LONG_MIN OE_LONG_MIN
#define NAME_MAX OE_NAME_MAX
#define NGROUPS_MAX OE_NGROUPS_MAX
#define OE_IOV_MAX 1024
#define OE_NAME_MAX 255
#define OE_NGROUPS_MAX 32
#define OE_PATH_MAX 4096
#define PATH_MAX OE_PATH_MAX
#define SCHAR_MAX OE_SCHAR_MAX
#define SCHAR_MIN OE_SCHAR_MIN
#define SHRT_MAX OE_SHRT_MAX
#define SHRT_MIN OE_SHRT_MIN
#define UCHAR_MAX OE_UCHAR_MAX
#define UINT_MAX OE_UINT_MAX
#define ULLONG_MAX OE_ULLONG_MAX
#define ULONG_MAX OE_ULONG_MAX
#define USHRT_MAX OE_USHRT_MAX

#define SAFE_ADD(a, b, c, minz, maxz) \
    return __builtin_add_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#define SAFE_MULTIPLY(a, b, c, minz, maxz) \
    return __builtin_mul_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#define SAFE_SUBTRACT(a, b, c, minz, maxz) \
    return __builtin_sub_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;

#define __has_builtin(x) 0


#define OE_RESTRICT restrict





#define BUFSIZ OE_BUFSIZ
#define EOF (-1)

#define INT16_MAX OE_INT16_MAX
#define INT16_MIN OE_INT16_MIN
#define INT32_MAX OE_INT32_MAX
#define INT32_MIN OE_INT32_MIN
#define INT64_MAX OE_INT64_MAX
#define INT64_MIN OE_INT64_MIN
#define INT8_MAX OE_INT8_MAX
#define INT8_MIN OE_INT8_MIN
#define SIZE_MAX OE_SIZE_MAX
#define UINT16_MAX OE_UINT16_MAX
#define UINT32_MAX OE_UINT32_MAX
#define UINT64_MAX OE_UINT64_MAX
#define UINT8_MAX OE_UINT8_MAX

#define OE_BUFSIZ 8192
#define OE_EOF (-1)

#define stderr oe_stderr
#define stdin oe_stdin
#define stdout oe_stdout

#define __OE_JMP_BUF oe_jmp_buf
#define ___OE_JMP_BUF _oe_jmp_buf
