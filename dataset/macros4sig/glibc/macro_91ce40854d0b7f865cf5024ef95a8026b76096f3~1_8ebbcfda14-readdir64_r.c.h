#include<sys/types.h>

#include<features.h>
#include<bits/wordsize.h>
#include<dirent.h>
#include<stddef.h>



# define DIRENT_TYPE struct dirent
# define __GETDENTS __getdents
# define __READDIR_R __readdir_r
# define __READDIR_R_ALIAS
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
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
# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
#define __OLD_DIRENT_H 1
#  define IS_IN_libc 1
# define SHLIB_COMPAT(lib, introduced, obsoleted)			      \
  _SHLIB_COMPAT (lib, introduced, obsoleted)
# define _SHLIB_COMPAT(lib, introduced, obsoleted)			      \
  ((IS_IN_##lib - 0)							      \
   && (!(ABI_##lib##_##obsoleted - 0)					      \
       || ((ABI_##lib##_##introduced - 0) < (ABI_##lib##_##obsoleted - 0))))
# define compat_symbol(lib, local, symbol, version) \
  compat_symbol_1 (lib, local, symbol, version)
# define compat_symbol_1(lib, local, symbol, version) \
  compat_symbol_2 (local, symbol, VERSION_##lib##_##version)
# define compat_symbol_2(local, symbol, name) \
  symbol_version (local, symbol, name)
#  define libc_sunrpc_symbol(name, aliasname, version) \
  compat_symbol (libc, name, aliasname, version);
# define versioned_symbol(lib, local, symbol, version) \
  versioned_symbol_1 (lib, local, symbol, version)
# define versioned_symbol_1(lib, local, symbol, version) \
  versioned_symbol_2 (local, symbol, VERSION_##lib##_##version)
# define versioned_symbol_2(local, symbol, name) \
  default_symbol_version (local, symbol, name)
