







# define __BUILTIN_TRANSFORM(Name) \
  extern int Name (struct __gconv_step *step,				      \
		   struct __gconv_step_data *data,			      \
		   const unsigned char **inbuf,				      \
		   const unsigned char *inbufend,			      \
		   unsigned char **outbufstart, size_t *irreversible,	      \
		   int do_flush, int consume_incomplete)
#define norm_add_slashes(str,suffix) \
  ({									      \
    const char *cp = (str);						      \
    char *result;							      \
    char *tmp;								      \
    size_t cnt = 0;							      \
    const size_t suffix_len = strlen (suffix);				      \
									      \
    while (*cp != '\0')							      \
      if (*cp++ == '/')							      \
	++cnt;								      \
									      \
    tmp = result = __alloca (cp - (str) + 3 + suffix_len);		      \
    cp = (str);								      \
    while (*cp != '\0')							      \
      *tmp++ = __toupper_l (*cp++, _nl_C_locobj_ptr);			      \
    if (cnt < 2)							      \
      {									      \
	*tmp++ = '/';							      \
	if (cnt < 1)							      \
	  {								      \
	    *tmp++ = '/';						      \
	    if (suffix_len != 0)					      \
	      tmp = __mempcpy (tmp, suffix, suffix_len);		      \
	  }								      \
      }									      \
    *tmp = '\0';							      \
    result;								      \
  })
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
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# define __GNUC_PREREQ(maj, min) \

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
#   define CTYPE_EXTERN_INLINE extern inline
#  define __isdigit_l(c, l) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#  define isdigit(c) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#  define isdigit_l(c, l) ({ int __c = (c); __c >= '0' && __c <= '9'; })
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
#   define fwscanf __isoc99_fwscanf
#   define swscanf __isoc99_swscanf
#   define vfwscanf __isoc99_vfwscanf
#   define vswscanf __isoc99_vswscanf
#   define vwscanf __isoc99_vwscanf
#   define wscanf __isoc99_wscanf
#define _nl_C_locobj_ptr ((struct __locale_struct *) &_nl_C_locobj)
#define LC_COLLATE        __LC_COLLATE
#define LC_CTYPE          __LC_CTYPE
#define LC_IDENTIFICATION __LC_IDENTIFICATION
#define LC_MESSAGES       __LC_MESSAGES
#define LC_MONETARY       __LC_MONETARY
#define LC_NUMERIC        __LC_NUMERIC
#define LC_TIME           __LC_TIME

# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
