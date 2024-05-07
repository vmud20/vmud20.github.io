
#include<bits/wordsize.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<features.h>

#include<time.h>
#include<paths.h>
#include<stddef.h>
#include<sys/types.h>
#include<signal.h>
#include<bits/types.h>
#define OPT_DIRECT 1000
#define OPT_TESTDIR 1001
# define TEST_DATA_LIMIT (64 << 20) 
# define TEST_FUNCTION do_test (argc, argv)
# define TIMEOUT 20
# define init_sig(signo, name, text) \
        case signo: fprintf (f, "signal=%s\n", name); break;
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
#define _SYS_PARAM_H    1

#define clrbit(a,i)     ((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
# define howmany(x, y)  (((x) + ((y) - 1)) / (y))
#define isclr(a,i)      (((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)
#define isset(a,i)      ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define powerof2(x)     ((((x) - 1) & (x)) == 0)
# define roundup(x, y)  (__builtin_constant_p (y) && powerof2 (y)             \
                         ? (((x) + (y) - 1) & ~((y) - 1))                     \
                         : ((((x) + ((y) - 1)) / (y)) * (y)))
#define setbit(a,i)     ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define __sigemptyset(ss) \
  ({ __builtin_memset (ss, '\0', sizeof (sigset_t)); 0; })
#  define BIG_ENDI 1
#   define HIGH_HALF 1
#   define LITTLE_ENDI 1
#   define  LOW_HALF 0
# define __FLOAT_WORD_ORDER __BYTE_ORDER
# define __LONG_LONG_PAIR(HI, LO) LO, HI
#  define be16toh(x) __bswap_16 (x)
#  define be32toh(x) __bswap_32 (x)
#  define be64toh(x) __bswap_64 (x)
#  define htobe16(x) __bswap_16 (x)
#  define htobe32(x) __bswap_32 (x)
#  define htobe64(x) __bswap_64 (x)
#  define htole16(x) (x)
#  define htole32(x) (x)
#  define htole64(x) (x)
#  define le16toh(x) (x)
#  define le32toh(x) (x)
#  define le64toh(x) (x)
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# define __GNUC_PREREQ(maj, min) \
	(("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
#  define __USE_FORTIFY_LEVEL 2
#  define __blkcnt_t_defined
# define __blksize_t_defined
#  define __daddr_t_defined
# define __dev_t_defined
#  define __fsblkcnt_t_defined
#  define __fsfilcnt_t_defined
# define __gid_t_defined
# define __id_t_defined
# define __ino64_t_defined
# define __ino_t_defined
#  define __int8_t_defined
# define __intN_t(N, MODE) \
  typedef int int##N##_t __attribute__ ((__mode__ (MODE)))
# define __key_t_defined
# define __mode_t_defined
# define __need_clock_t


# define __nlink_t_defined
# define __off64_t_defined
# define __off_t_defined
# define __pid_t_defined
# define __ssize_t_defined
#  define __suseconds_t_defined
#  define __u_char_defined
# define __u_intN_t(N, MODE) \
  typedef unsigned int u_int##N##_t __attribute__ ((__mode__ (MODE)))
# define __uid_t_defined
#  define __useconds_t_defined
#define __CPU_MASK_TYPE 	__ULONGWORD_TYPE
# define WCOREDUMP(status)	__WCOREDUMP (status)
# define WEXITSTATUS(status)	__WEXITSTATUS (status)
#  define WIFCONTINUED(status)	__WIFCONTINUED (status)
# define WIFEXITED(status)	__WIFEXITED (status)
# define WIFSIGNALED(status)	__WIFSIGNALED (status)
# define WIFSTOPPED(status)	__WIFSTOPPED (status)
# define WSTOPSIG(status)	__WSTOPSIG (status)
# define WTERMSIG(status)	__WTERMSIG (status)
# define W_EXITCODE(ret, sig)	__W_EXITCODE (ret, sig)
# define W_STOPCODE(sig)	__W_STOPCODE (sig)
#  define __id_t_defined
# define __need_siginfo_t
#  define getrlimit getrlimit64
#  define setrlimit setrlimit64
#define PRIO_MAX        20      
#define PRIO_MIN        -20     
#define PRIO_PGRP PRIO_PGRP
#define PRIO_PROCESS PRIO_PROCESS
#define PRIO_USER PRIO_USER
# define RLIM64_INFINITY 0x7fffffffffffffffLL
# define RLIM_INFINITY 0x7fffffff
#define RUSAGE_CHILDREN RUSAGE_CHILDREN
#define RUSAGE_SELF     RUSAGE_SELF

#   define CLK_TCK ((__clock_t) __sysconf (2))	
#  define CLOCKS_PER_SEC  ((clock_t) 1000000)
# define F_LOCK  1	
# define F_TEST  3	
# define F_TLOCK 2	
# define F_ULOCK 0	
# define TEMP_FAILURE_RETRY(expression) \
  (__extension__							      \
    ({ long int __result;						      \
       do __result = (long int) (expression);				      \
       while (__result == -1L && errno == EINTR);			      \
       __result; }))
#define _POSIX2_LOCALEDEF       __POSIX2_THIS_VERSION
#  define __gid_t_defined
#  define __intptr_t_defined

# define __need_getopt
#  define __off64_t_defined
#  define __off_t_defined
#  define __pid_t_defined
#  define __socklen_t_defined
# define __ssize_t_defined
#  define __uid_t_defined
#  define __useconds_t_defined
#   define ftruncate ftruncate64
#   define lockf lockf64
#  define lseek lseek64
#   define pread pread64
#   define pwrite pwrite64
#   define truncate truncate64
#define _CS_POSIX_V6_ILP32_OFF32_CFLAGS _CS_POSIX_V6_ILP32_OFF32_CFLAGS
#define _CS_POSIX_V6_ILP32_OFF32_LDFLAGS _CS_POSIX_V6_ILP32_OFF32_LDFLAGS
#define _CS_POSIX_V6_ILP32_OFF32_LIBS _CS_POSIX_V6_ILP32_OFF32_LIBS
#define _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS
#define _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS
#define _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS
#define _CS_POSIX_V6_ILP32_OFFBIG_LIBS _CS_POSIX_V6_ILP32_OFFBIG_LIBS
#define _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS
#define _CS_POSIX_V6_LP64_OFF64_CFLAGS _CS_POSIX_V6_LP64_OFF64_CFLAGS
#define _CS_POSIX_V6_LP64_OFF64_LDFLAGS _CS_POSIX_V6_LP64_OFF64_LDFLAGS
#define _CS_POSIX_V6_LP64_OFF64_LIBS _CS_POSIX_V6_LP64_OFF64_LIBS
#define _CS_POSIX_V6_LP64_OFF64_LINTFLAGS _CS_POSIX_V6_LP64_OFF64_LINTFLAGS
#define _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS
#define _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS
#define _CS_POSIX_V6_LPBIG_OFFBIG_LIBS _CS_POSIX_V6_LPBIG_OFFBIG_LIBS
#define _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS
#define _CS_POSIX_V7_ILP32_OFF32_CFLAGS _CS_POSIX_V7_ILP32_OFF32_CFLAGS
#define _CS_POSIX_V7_ILP32_OFF32_LDFLAGS _CS_POSIX_V7_ILP32_OFF32_LDFLAGS
#define _CS_POSIX_V7_ILP32_OFF32_LIBS _CS_POSIX_V7_ILP32_OFF32_LIBS
#define _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS
#define _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS
#define _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS
#define _CS_POSIX_V7_ILP32_OFFBIG_LIBS _CS_POSIX_V7_ILP32_OFFBIG_LIBS
#define _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS
#define _CS_POSIX_V7_LP64_OFF64_CFLAGS _CS_POSIX_V7_LP64_OFF64_CFLAGS
#define _CS_POSIX_V7_LP64_OFF64_LDFLAGS _CS_POSIX_V7_LP64_OFF64_LDFLAGS
#define _CS_POSIX_V7_LP64_OFF64_LIBS _CS_POSIX_V7_LP64_OFF64_LIBS
#define _CS_POSIX_V7_LP64_OFF64_LINTFLAGS _CS_POSIX_V7_LP64_OFF64_LINTFLAGS
#define _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS
#define _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS
#define _CS_POSIX_V7_LPBIG_OFFBIG_LIBS _CS_POSIX_V7_LPBIG_OFFBIG_LIBS
#define _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS
#define _CS_XBS5_ILP32_OFF32_CFLAGS _CS_XBS5_ILP32_OFF32_CFLAGS
#define _CS_XBS5_ILP32_OFF32_LDFLAGS _CS_XBS5_ILP32_OFF32_LDFLAGS
#define _CS_XBS5_ILP32_OFF32_LIBS _CS_XBS5_ILP32_OFF32_LIBS
#define _CS_XBS5_ILP32_OFF32_LINTFLAGS _CS_XBS5_ILP32_OFF32_LINTFLAGS
#define _CS_XBS5_ILP32_OFFBIG_CFLAGS _CS_XBS5_ILP32_OFFBIG_CFLAGS
#define _CS_XBS5_ILP32_OFFBIG_LDFLAGS _CS_XBS5_ILP32_OFFBIG_LDFLAGS
#define _CS_XBS5_ILP32_OFFBIG_LIBS _CS_XBS5_ILP32_OFFBIG_LIBS
#define _CS_XBS5_ILP32_OFFBIG_LINTFLAGS _CS_XBS5_ILP32_OFFBIG_LINTFLAGS
#define _CS_XBS5_LP64_OFF64_CFLAGS _CS_XBS5_LP64_OFF64_CFLAGS
#define _CS_XBS5_LP64_OFF64_LDFLAGS _CS_XBS5_LP64_OFF64_LDFLAGS
#define _CS_XBS5_LP64_OFF64_LIBS _CS_XBS5_LP64_OFF64_LIBS
#define _CS_XBS5_LP64_OFF64_LINTFLAGS _CS_XBS5_LP64_OFF64_LINTFLAGS
#define _CS_XBS5_LPBIG_OFFBIG_CFLAGS _CS_XBS5_LPBIG_OFFBIG_CFLAGS
#define _CS_XBS5_LPBIG_OFFBIG_LDFLAGS _CS_XBS5_LPBIG_OFFBIG_LDFLAGS
#define _CS_XBS5_LPBIG_OFFBIG_LIBS _CS_XBS5_LPBIG_OFFBIG_LIBS
#define _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS
#   define index(s, c)	(strchr ((s), (c)))
#   define rindex(s, c)	(strrchr ((s), (c)))
# define strndupa(s, n)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = __strnlen (__old, (n));				      \
      char *__new = (char *) __builtin_alloca (__len + 1);		      \
      __new[__len] = '\0';						      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
# define __CORRECT_ISO_CPP_STRING_H_PROTO
#define __mempcpy(dest, src, n) __mempcpy_inline (dest, src, n)
#define mempcpy(dest, src, n) __mempcpy_inline (dest, src, n)
# define strdupa(s)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = strlen (__old) + 1;				      \
      char *__new = (char *) __builtin_alloca (__len);			      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
#  define MB_CUR_MAX (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_MB_CUR_MAX))

# define __COMPAR_FN_T
# define __malloc_and_calloc_defined
#define		__need_size_t
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
#  define __need_size_t
#  define __need_wint_t
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
# define __ACTION_FN_T
#define __malloc_initialized __libc_malloc_initialized
#define M_ARENA_MAX         -8
#define M_ARENA_TEST        -7
#define M_CHECK_ACTION      -5
# define M_GRAIN   3    
# define M_KEEP    4    
#define M_MMAP_MAX          -4
#define M_MMAP_THRESHOLD    -3
# define M_MXFAST  1    
# define M_NLBLKS  2    
#define M_PERTURB           -6
#define M_TOP_PAD           -2
#define M_TRIM_THRESHOLD    -1
#define _MALLOC_H 1
# define __MALLOC_DEPRECATED __attribute_deprecated__
# define __MALLOC_HOOK_VOLATILE volatile
# define _GETOPT_H 1
#  define __GNUC_PREREQ(maj, min) (0)
#  define __THROW
#   define getopt __posix_getopt
# define __OPEN_NEEDS_MODE(oflag) \
  (((oflag) & O_CREAT) != 0 || ((oflag) & __O_TMPFILE) == __O_TMPFILE)
# define __mode_t_defined
# define __need_timespec
#  define creat creat64
#  define open open64
#   define openat openat64
#   define posix_fadvise posix_fadvise64
#   define posix_fallocate posix_fallocate64
# define F_DUPFD_CLOEXEC 12	
# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
#define __fstat(fd, buf) __fxstat (_STAT_VER, fd, buf)
#define __fstat64(fd, buf) __fxstat64 (_STAT_VER, fd, buf)
#define __fstatat(dfd, fname, buf, flag) \
  __fxstatat (_STAT_VER, dfd, fname, buf, flag)
#define __fstatat64(dfd, fname, buf, flag) \
  __fxstatat64 (_STAT_VER, dfd, fname, buf, flag)
#define __lstat(fname, buf)  __lxstat (_STAT_VER, fname, buf)
#define __lstat64(fname, buf)  __lxstat64 (_STAT_VER, fname, buf)
#define fstat(fd, buf) __fxstat (_STAT_VER, fd, buf)
#define fstat64(fd, buf) __fxstat64 (_STAT_VER, fd, buf)
#define lstat(fname, buf)  __lxstat (_STAT_VER, fname, buf)
#define lstat64(fname, buf)  __lxstat64 (_STAT_VER, fname, buf)
#define stat(fname, buf) __xstat (_STAT_VER, fname, buf)
#define stat64(fname, buf) __xstat64 (_STAT_VER, fname, buf)
# define ACCESSPERMS (S_IRWXU|S_IRWXG|S_IRWXO) 
# define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)
# define DEFFILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
# define S_ISFIFO(mode)	 __S_ISTYPE((mode), __S_IFIFO)
# define S_ISLNK(mode)	 __S_ISTYPE((mode), __S_IFLNK)
# define S_ISSOCK(mode) __S_ISTYPE((mode), __S_IFSOCK)
# define S_TYPEISMQ(buf) __S_TYPEISMQ(buf)
# define S_TYPEISSEM(buf) __S_TYPEISSEM(buf)
# define S_TYPEISSHM(buf) __S_TYPEISSHM(buf)
#  define __blkcnt_t_defined
#  define __blksize_t_defined
#  define __dev_t_defined
#  define __fxstat __fxstat64
#  define __ino_t_defined
#  define __lxstat __lxstat64
#  define __mode_t_defined
#  define __need_time_t
#  define __need_timespec
#  define __nlink_t_defined
#  define __xstat __xstat64
#   define fstatat fstatat64
#define __S_TYPEISMQ(buf) 0
#define __S_TYPEISSEM(buf) 0
#define __S_TYPEISSHM(buf) 0
#define _MCHECK_H       1
# define GLOB_ABEND GLOB_ABORTED
# define GLOB_ALTDIRFUNC (1 << 9)
# define GLOB_TILDE_CHECK (1 << 14)
# define __nonnull(params)
#  define _Noreturn __attribute__ ((__noreturn__))
# define _Static_assert(expr, diagnostic) \
    extern int (*__Static_assert_function (void)) \
      [!!sizeof (struct { int __error_if_negative: (expr) ? 2 : -1; })]
# define __ASMNAME(cname)  __ASMNAME2 ("__USER_LABEL_PREFIX__", cname)
# define __ASMNAME2(prefix, cname) __STRING (prefix) cname
# define __BEGIN_DECLS
# define __BEGIN_NAMESPACE_C99
# define __BEGIN_NAMESPACE_STD
#define __CONCAT(x,y)	x ## y
# define __END_DECLS
# define __END_NAMESPACE_C99
# define __END_NAMESPACE_STD
# define __LDBL_COMPAT 1
#  define __LDBL_REDIR(name, proto) \
  __LDBL_REDIR1 (name, proto, __nldbl_##name)
#  define __LDBL_REDIR1(name, proto, alias) __REDIRECT (name, proto, alias)
#  define __LDBL_REDIR1_DECL(name, alias) \
  extern __typeof (name) name __asm (__ASMNAME (#alias));
#  define __LDBL_REDIR1_NTH(name, proto, alias) __REDIRECT_NTH (name, proto, alias)
#  define __LDBL_REDIR_DECL(name) \
  extern __typeof (name) name __asm (__ASMNAME ("__nldbl_" #name));
#  define __LDBL_REDIR_NTH(name, proto) \
  __LDBL_REDIR1_NTH (name, proto, __nldbl_##name)
#  define __LEAF , __leaf__
#  define __LEAF_ATTR __attribute__ ((__leaf__))
#   define __NTH(fct)	__LEAF_ATTR fct throw ()
#define __P(args)	args
#define __PMT(args)	args
# define __REDIRECT(name, proto, alias) name proto __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_LDBL(name, proto, alias) \
  __LDBL_REDIR1 (name, proto, __nldbl_##alias)
#  define __REDIRECT_NTH(name, proto, alias) \
     name proto __THROW __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_NTHNL(name, proto, alias) \
     name proto __THROWNL __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_NTH_LDBL(name, proto, alias) \
  __LDBL_REDIR1_NTH (name, proto, __nldbl_##alias)
#define __STRING(x)	#x
#   define __THROWNL
# define __USING_NAMESPACE_C99(name) using __c99::name;
# define __USING_NAMESPACE_STD(name) using std::name;
# define __always_inline __inline __attribute__ ((__always_inline__))
# define __attribute__(xyz)	
# define __attribute_alloc_size__(params) \
  __attribute__ ((__alloc_size__ params))
# define __attribute_artificial__ __attribute__ ((__artificial__))
# define __attribute_const__ __attribute__ ((__const__))
# define __attribute_deprecated__ __attribute__ ((__deprecated__))
# define __attribute_format_arg__(x) __attribute__ ((__format_arg__ (x)))
# define __attribute_format_strfmon__(a,b) \
  __attribute__ ((__format__ (__strfmon__, a, b)))
# define __attribute_malloc__ __attribute__ ((__malloc__))
# define __attribute_noinline__ __attribute__ ((__noinline__))
# define __attribute_pure__ __attribute__ ((__pure__))
# define __attribute_used__ __attribute__ ((__used__))
# define __attribute_warn_unused_result__ \
   __attribute__ ((__warn_unused_result__))
#define __bos(ptr) __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1)
#define __bos0(ptr) __builtin_object_size (ptr, 0)
# define __errordecl(name, msg) \
  extern void name (void) __attribute__((__error__ (msg)))
#  define __extern_always_inline \
  extern __always_inline __attribute__ ((__gnu_inline__))
#  define __extern_inline extern __inline __attribute__ ((__gnu_inline__))
# define __fortify_function __extern_always_inline __attribute_artificial__
# define __glibc_likely(cond)	__builtin_expect ((cond), 1)
# define __glibc_unlikely(cond)	__builtin_expect ((cond), 0)
#define __long_double_t  long double
#define __ptr_t void *
# define __va_arg_pack() __builtin_va_arg_pack ()
# define __va_arg_pack_len() __builtin_va_arg_pack_len ()
# define __warnattr(msg) __attribute__((__warning__ (msg)))
# define __warndecl(name, msg) \
  extern void name (void) __attribute__((__warning__ (msg)))
#  define __wur __attribute_warn_unused_result__
#   define __scandir64_tail (dp, namelist, select, cmp)         \
  __scandir_tail (dp, (struct dirent ***) (namelist),           \
		  (int (*) (const struct dirent *)) (select),   \
		  (int (*) (const struct dirent **,             \
			    const struct dirent **)) (cmp))
#define _ERROR_H 1
