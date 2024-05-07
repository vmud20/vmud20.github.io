











#define CATNAMEMF(line) CATNAMEMF1 (line)
#define CATNAMEMF1(line) str##line
#define DEFINE_CATEGORY(category, category_name, items, a) \
    char CATNAMEMF ("__LINE__")[sizeof (category_name)];
#define ERA_M_FORMAT 1
#define ERA_M_NAME   0
#define ERA_NAME_FORMAT_MEMBERS 4
#define ERA_W_FORMAT 3
#define ERA_W_NAME   2
#define MAX_USAGE_COUNT (UINT_MAX - 1)
#define _ISCTYPE(c, desc) \
  (((((const uint32_t *) (desc)) - 8)[(c) >> 5] >> ((c) & 0x1f)) & 1)
#define _LOCALEINFO_H 1
#define _NL_CURRENT(category, item) \
  ((*_nl_current_##category)->values[_NL_ITEM_INDEX (item)].string)
#define _NL_CURRENT_DATA(category)	(*_nl_current_##category)
#define _NL_CURRENT_DEFINE(category) \
  __thread struct __locale_data *const *_nl_current_##category \
    attribute_hidden = &_nl_global_locale.__locales[category]; \
  asm (".globl " __SYMBOL_PREFIX "_nl_current_" #category "_used\n" \
       _NL_CURRENT_DEFINE_ABS (_nl_current_##category##_used, 1));
# define _NL_CURRENT_DEFINE_ABS(sym, val) ".set " #sym ", " #val
#define _NL_CURRENT_WORD(category, item) \
  ((uint32_t) (*_nl_current_##category)->values[_NL_ITEM_INDEX (item)].word)
#define _NL_CURRENT_WSTR(category, item) \
  ((wchar_t *) (*_nl_current_##category)->values[_NL_ITEM_INDEX (item)].wstr)
#define _GENERIC_BITS_LIBC_TSD_H 1
#define __libc_tsd_address(TYPE, KEY)		(&__libc_tsd_##KEY)
#define __libc_tsd_define(CLASS, TYPE, KEY)	\
  CLASS __thread TYPE __libc_tsd_##KEY attribute_tls_model_ie;
#define __libc_tsd_get(TYPE, KEY)		(__libc_tsd_##KEY)
#define __libc_tsd_set(TYPE, KEY, VALUE)	(__libc_tsd_##KEY = (VALUE))
#  define PARAMS(args) args
# define internal_function
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
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# define __GNUC_PREREQ(maj, min) \

#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
#  define __USE_FORTIFY_LEVEL 2
#define _nl_C_locobj_ptr ((struct __locale_struct *) &_nl_C_locobj)
#define LC_COLLATE        __LC_COLLATE
#define LC_CTYPE          __LC_CTYPE
#define LC_IDENTIFICATION __LC_IDENTIFICATION
#define LC_MESSAGES       __LC_MESSAGES
#define LC_MONETARY       __LC_MONETARY
#define LC_NUMERIC        __LC_NUMERIC
#define LC_TIME           __LC_TIME

# define NL_LOCALE_NAME(category)	_NL_LOCALE_NAME (category)
#define _NL_ITEM(category, index)	(((category) << 16) | (index))
#define _NL_ITEM_CATEGORY(item)		((int) (item) >> 16)
#define _NL_ITEM_INDEX(item)		((int) (item) & 0xffff)
#define _NL_LOCALE_NAME(category)	_NL_ITEM ((category),		      \
						  _NL_ITEM_INDEX (-1))
#define NL_CAT_LOCALE 1
#define NL_SETD 1
#define _NL_TYPES_H 1
# define __CORRECT_ISO_CPP_STRING_H_PROTO
# define strdupa(s)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = strlen (__old) + 1;				      \
      char *__new = (char *) __builtin_alloca (__len);			      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
# define strndupa(s, n)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = strnlen (__old, (n));				      \
      char *__new = (char *) __builtin_alloca (__len + 1);		      \
      __new[__len] = '\0';						      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
#  define MB_CUR_MAX (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_MB_CUR_MAX))

# define __cxa_atexit(func, arg, d) INTUSE(__cxa_atexit) (func, arg, d)
# define WEXITSTATUS(status)	__WEXITSTATUS (__WAIT_INT (status))
#  define WIFCONTINUED(status)	__WIFCONTINUED (__WAIT_INT (status))
# define WIFEXITED(status)	__WIFEXITED (__WAIT_INT (status))
# define WIFSIGNALED(status)	__WIFSIGNALED (__WAIT_INT (status))
# define WIFSTOPPED(status)	__WIFSTOPPED (__WAIT_INT (status))
# define WSTOPSIG(status)	__WSTOPSIG (__WAIT_INT (status))
# define WTERMSIG(status)	__WTERMSIG (__WAIT_INT (status))
# define __COMPAR_FN_T
#   define __WAIT_INT(status) \
  (__extension__ (((union { __typeof(status) __in; int __i; }) \
		   { .__in = (status) }).__i))
# define __malloc_and_calloc_defined
#define		__need_size_t
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
