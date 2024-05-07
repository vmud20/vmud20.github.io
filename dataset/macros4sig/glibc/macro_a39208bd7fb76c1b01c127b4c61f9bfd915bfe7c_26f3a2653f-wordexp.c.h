















# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# define __GNUC_PREREQ(maj, min) \

#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
#  define __USE_FORTIFY_LEVEL 2
#define _BITS_LIBC_LOCK_H 1
#define __libc_cleanup_end(DOIT)					    \
  if ((DOIT) && __save_FCT != 0)					    \
    (*__save_FCT)(__save_ARG);						    \

#define __libc_cleanup_pop(execute) __libc_cleanup_region_end (execute)
#define __libc_cleanup_push(fct, arg) __libc_cleanup_region_start (1, fct, arg)
#define __libc_cleanup_region_end(DOIT)					    \
  if ((DOIT) && __save_FCT != 0)					    \
    (*__save_FCT)(__save_ARG);						    \
}
#define __libc_cleanup_region_start(DOIT, FCT, ARG)			    \
{									    \
  typeof (***(FCT)) *__save_FCT = (DOIT) ? (FCT) : 0;			    \
  typeof (ARG) __save_ARG = ARG;					    \
  
#define __libc_getspecific(KEY)		((void) (KEY), (void *) 0)
#define __libc_key_create(KEY,DEST)	((void) (KEY), (void) (DEST), -1)










#define __libc_lock_trylock(NAME) 0
#define __libc_lock_trylock_recursive(NAME) 0



#define __libc_once(ONCE_CONTROL, INIT_FUNCTION) \
  do {									      \
    if ((ONCE_CONTROL) == 0) {						      \
      INIT_FUNCTION ();							      \
      (ONCE_CONTROL) = 1;						      \
    }									      \
  } while (0)
#define __libc_once_define(CLASS, NAME) CLASS int NAME = 0
#define __libc_once_get(ONCE_CONTROL) \
  ((ONCE_CONTROL) == 1)





#define __libc_rwlock_tryrdlock(NAME) 0
#define __libc_rwlock_trywrlock(NAME) 0


#define __libc_setspecific(KEY,VAL)	((void) (KEY), (void) (VAL))






#  define __mbsinit(state) ((state)->__count == 0)
#  define mbsinit(state) ((state)->__count == 0)
# define WCHAR_MAX __WCHAR_MAX
# define WCHAR_MIN __WCHAR_MIN
# define WEOF (0xffffffffu)
# define _WCHAR_H 1
#  define _WINT_T
#  define __CORRECT_ISO_CPP_WCHAR_H_PROTO
#  define __mbstate_t_defined 1
#  define __need_FILE
# define __need_NULL
# define __need___FILE
# define __need___va_list
# define __need_iswxxx
# define __need_wchar_t
# define __need_wint_t
#   define fwscanf __isoc99_fwscanf
#   define swscanf __isoc99_swscanf
#   define vfwscanf __isoc99_vfwscanf
#   define vswscanf __isoc99_vswscanf
#   define vwscanf __isoc99_vwscanf
#   define wscanf __isoc99_wscanf
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
# define WCOREDUMP(status)	__WCOREDUMP (__WAIT_INT (status))
# define WEXITSTATUS(status)	__WEXITSTATUS (__WAIT_INT (status))
#  define WIFCONTINUED(status)	__WIFCONTINUED (__WAIT_INT (status))
# define WIFEXITED(status)	__WIFEXITED (__WAIT_INT (status))
# define WIFSIGNALED(status)	__WIFSIGNALED (__WAIT_INT (status))
# define WIFSTOPPED(status)	__WIFSTOPPED (__WAIT_INT (status))
# define WSTOPSIG(status)	__WSTOPSIG (__WAIT_INT (status))
# define WTERMSIG(status)	__WTERMSIG (__WAIT_INT (status))
# define W_EXITCODE(ret, sig)	__W_EXITCODE (ret, sig)
# define W_STOPCODE(sig)	__W_STOPCODE (sig)
#   define __WAIT_INT(status) \
  (__extension__ (((union { __typeof(status) __in; int __i; }) \
		   { .__in = (status) }).__i))
#  define __id_t_defined
# define __need_siginfo_t
#define __sigemptyset(ss) \
  ({ __builtin_memset (ss, '\0', sizeof (sigset_t)); 0; })
#  define __blkcnt_t_defined
# define __blksize_t_defined
#  define __daddr_t_defined
# define __dev_t_defined
#  define __fsblkcnt_t_defined
#  define __fsfilcnt_t_defined
# define __ino64_t_defined
# define __ino_t_defined
#  define __int8_t_defined
# define __intN_t(N, MODE) \
  typedef int int##N##_t __attribute__ ((__mode__ (MODE)))
# define __key_t_defined
# define __mode_t_defined
# define __need_clock_t


# define __nlink_t_defined
#  define __suseconds_t_defined
#  define __u_char_defined
# define __u_intN_t(N, MODE) \
  typedef unsigned int u_int##N##_t __attribute__ ((__mode__ (MODE)))
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
#  define __fxstat __fxstat64
#  define __lxstat __lxstat64
#  define __need_time_t
#  define __need_timespec
#  define __xstat __xstat64
#   define fstatat fstatat64
#define __S_TYPEISMQ(buf) 0
#define __S_TYPEISSEM(buf) 0
#define __S_TYPEISSHM(buf) 0
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
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
#define DECLARE_NSS_PROTOTYPES(service)					\
extern enum nss_status _nss_ ## service ## _setpwent (int);		\
extern enum nss_status _nss_ ## service ## _endpwent (void);		\
extern enum nss_status _nss_ ## service ## _getpwnam_r			\
		       (const char *name, struct passwd *pwd,		\
			char *buffer, size_t buflen, int *errnop);	\
extern enum nss_status _nss_ ## service ## _getpwuid_r			\
		       (uid_t uid, struct passwd *pwd,			\
			char *buffer, size_t buflen, int *errnop);	\
extern enum nss_status _nss_ ## service ##_getpwent_r			\
		       (struct passwd *result, char *buffer,		\
			size_t buflen, int *errnop);
# define N_(msgid)	msgid
# define _(msgid) \
  __dcgettext (_libc_intl_domainname, msgid, LC_MESSAGES)
#define _nl_C_locobj_ptr ((struct __locale_struct *) &_nl_C_locobj)
#define LC_COLLATE        __LC_COLLATE
#define LC_CTYPE          __LC_CTYPE
#define LC_IDENTIFICATION __LC_IDENTIFICATION
#define LC_MESSAGES       __LC_MESSAGES
#define LC_MONETARY       __LC_MONETARY
#define LC_NUMERIC        __LC_NUMERIC
#define LC_TIME           __LC_TIME
#define __GNU_GETTEXT_SUPPORTED_REVISION(major) \
  ((major) == 0 ? 1 : -1)
#define __USE_GNU_GETTEXT 1
# define dgettext(domainname, msgid) \
  dcgettext (domainname, msgid, LC_MESSAGES)
# define dngettext(domainname, msgid1, msgid2, n) \
  dcngettext (domainname, msgid1, msgid2, n, LC_MESSAGES)
# define gettext(msgid) dgettext (NULL, msgid)
# define ngettext(msgid1, msgid2, n) dngettext (NULL, msgid1, msgid2, n)
# define GLOB_ABEND GLOB_ABORTED
# define GLOB_ALTDIRFUNC (1 << 9)
# define GLOB_TILDE_CHECK (1 << 14)
# define __nonnull(params)
#  define _Noreturn __attribute__ ((__noreturn__))
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
#   define __THROW
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
# define FNM_LEADING_DIR (1 << 3)	
#  define creat creat64
#  define open open64
#   define openat openat64
#   define posix_fadvise posix_fadvise64
#   define posix_fallocate posix_fallocate64
# define F_DUPFD_CLOEXEC 12	
# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
#   define CTYPE_EXTERN_INLINE extern inline
#   define __isdigit_l(c, l) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#   define isdigit(c) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#   define isdigit_l(c, l) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#  define _ISbit(bit)	(1 << (bit))
# define __exctype_l(name) 						      \
  extern int name (int, __locale_t) __THROW
#  define __isalnum_l(c,l)	__isctype_l((c), _ISalnum, (l))
#  define __isalpha_l(c,l)	__isctype_l((c), _ISalpha, (l))
#   define __isascii_l(c,l)	((l), __isascii (c))
#  define __isblank_l(c,l)	__isctype_l((c), _ISblank, (l))
#  define __iscntrl_l(c,l)	__isctype_l((c), _IScntrl, (l))
# define __isctype(c, type) \
  ((*__ctype_b_loc ())[(int) (c)] & (unsigned short int) type)
# define __isctype_f(type) \
  __extern_inline int							      \
  is##type (int __c) __THROW						      \
  {									      \
    return (*__ctype_b_loc ())[(int) (__c)] & (unsigned short int) _IS##type; \
  }
#  define __isctype_l(c, type, locale) \
  ((locale)->__ctype_b[(int) (c)] & (unsigned short int) type)
#  define __isgraph_l(c,l)	__isctype_l((c), _ISgraph, (l))
#  define __islower_l(c,l)	__isctype_l((c), _ISlower, (l))
#  define __isprint_l(c,l)	__isctype_l((c), _ISprint, (l))
#  define __ispunct_l(c,l)	__isctype_l((c), _ISpunct, (l))
#  define __isspace_l(c,l)	__isctype_l((c), _ISspace, (l))
#  define __isupper_l(c,l)	__isctype_l((c), _ISupper, (l))
#  define __isxdigit_l(c,l)	__isctype_l((c), _ISxdigit, (l))
#   define __toascii_l(c,l)	((l), __toascii (c))
#define __tobody(c, f, a, args) \
  (__extension__							      \
   ({ int __res;							      \
      if (sizeof (c) > 1)						      \
	{								      \
	  if (__builtin_constant_p (c))					      \
	    {								      \
	      int __c = (c);						      \
	      __res = __c < -128 || __c > 255 ? __c : (a)[__c];		      \
	    }								      \
	  else								      \
	    __res = f args;						      \
	}								      \
      else								      \
	__res = (a)[(int) (c)];						      \
      __res; }))
#  define __tolower_l(c, locale) \
  __tobody (c, __tolower_l, (locale)->__ctype_tolower, (c, locale))
#  define __toupper_l(c, locale) \
  __tobody (c, __toupper_l, (locale)->__ctype_toupper, (c, locale))
#  define _tolower(c)	((int) (*__ctype_tolower_loc ())[(int) (c)])
#  define _toupper(c)	((int) (*__ctype_toupper_loc ())[(int) (c)])
#  define isalnum_l(c,l)	__isalnum_l ((c), (l))
#  define isalpha_l(c,l)	__isalpha_l ((c), (l))
#  define isascii(c)	__isascii (c)
#   define isascii_l(c,l)	__isascii_l ((c), (l))
#  define isblank_l(c,l)	__isblank_l ((c), (l))
#  define iscntrl_l(c,l)	__iscntrl_l ((c), (l))
#  define isgraph_l(c,l)	__isgraph_l ((c), (l))
#  define islower_l(c,l)	__islower_l ((c), (l))
#  define isprint_l(c,l)	__isprint_l ((c), (l))
#  define ispunct_l(c,l)	__ispunct_l ((c), (l))
#  define isspace_l(c,l)	__isspace_l ((c), (l))
#  define isupper_l(c,l)	__isupper_l ((c), (l))
#  define isxdigit_l(c,l)	__isxdigit_l ((c), (l))
#  define toascii(c)	__toascii (c)
#   define toascii_l(c,l)	__toascii_l ((c), (l))
#  define tolower(c)	__tobody (c, tolower, *__ctype_tolower_loc (), (c))
#  define tolower_l(c, locale)	__tolower_l ((c), (locale))
#  define toupper(c)	__tobody (c, toupper, *__ctype_toupper_loc (), (c))
#  define toupper_l(c, locale)	__toupper_l ((c), (locale))
# define __alloca(size)	__builtin_alloca (size)
# define alloca_account(size, avar) \
  ({ void *old__ = stackinfo_get_sp ();					      \
     void *m__ = __alloca (size);					      \
     avar += stackinfo_sub_sp (old__);					      \
     m__; })
# define extend_alloca(buf, len, newlen) \
  (__typeof (buf)) ({ size_t __newlen = stackinfo_alloca_round (newlen);      \
		      char *__newbuf = __alloca (__newlen);		      \
		      if (__newbuf + __newlen == (char *) buf)		      \
			len += __newlen;				      \
		      else						      \
			len = __newlen;					      \
		      __newbuf; })
# define extend_alloca_account(buf, len, newlen, avar) \
  ({ void *old__ = stackinfo_get_sp ();					      \
     void *m__ = extend_alloca (buf, len, newlen);			      \
     avar += stackinfo_sub_sp (old__);					      \
     m__; })
# define stackinfo_alloca_round(l) (((l) + 15) & -16)
# define alloca(size)	__builtin_alloca (size)
