










# define FNM_LEADING_DIR (1 << 3)	
# define __alloca(size)	__builtin_alloca (size)
# define alloca_account(size, avar) \
  ({ void *old__ = stackinfo_get_sp ();					      \
     void *m__ = __alloca (size);					      \
     avar += stackinfo_sub_sp (old__);					      \
     m__; })
# define extend_alloca(buf, len, newlen) \
  (__typeof (buf)) ({ size_t __newlen = stackinfo_alloca_round (newlen);      \
		      char *__newbuf = __alloca (__newlen);		      \
		      if (__newbuf + __newlen == (char *) (buf))	      \
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
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# define __GNUC_PREREQ(maj, min) \

#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
#  define __USE_FORTIFY_LEVEL 2
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
#  define MB_CUR_MAX (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_MB_CUR_MAX))

# define WEXITSTATUS(status)	__WEXITSTATUS (status)
#  define WIFCONTINUED(status)	__WIFCONTINUED (status)
# define WIFEXITED(status)	__WIFEXITED (status)
# define WIFSIGNALED(status)	__WIFSIGNALED (status)
# define WIFSTOPPED(status)	__WIFSTOPPED (status)
# define WSTOPSIG(status)	__WSTOPSIG (status)
# define WTERMSIG(status)	__WTERMSIG (status)
# define __COMPAR_FN_T
# define __malloc_and_calloc_defined
#define		__need_size_t
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
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
#define NSS_INVALID_FIELD_CHARACTERS ":\n"
#  define __gid_t_defined
# define __need_FILE
#  define __uid_t_defined
#  define __need_size_t
#  define __need_wint_t
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
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
#  define __off_t_defined
#  define __xstat __xstat64
#   define fstatat fstatat64
#define __S_TYPEISMQ(buf) 0
#define __S_TYPEISSEM(buf) 0
#define __S_TYPEISSHM(buf) 0
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
