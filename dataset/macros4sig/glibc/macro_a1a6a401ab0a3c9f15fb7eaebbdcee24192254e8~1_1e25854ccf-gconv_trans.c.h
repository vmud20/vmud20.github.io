














#define CATNAMEMF(line) CATNAMEMF1 (line)
#define CATNAMEMF1(line) str##line
#define DEFINE_CATEGORY(category, category_name, items, a) \
    char CATNAMEMF ("__LINE__")[sizeof (category_name)];
#define ERA_M_FORMAT 1
#define ERA_M_NAME   0
#define ERA_NAME_FORMAT_MEMBERS 4
#define ERA_W_FORMAT 3
#define ERA_W_NAME   2
#define LOCFILE_ALIGNED_P(x)	(((x) & LOCFILE_ALIGN_MASK) == 0)
#define LOCFILE_ALIGN_UP(x)	(((x) + LOCFILE_ALIGN - 1)	\
				 & ~LOCFILE_ALIGN_MASK)
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
# define __ACTION_FN_T
# define DL_CALLER RETURN_ADDRESS (0)
# define DL_CALLER_DECL 
# define __dlfcn_argc __libc_argc
# define __dlfcn_argv __libc_argv
#define __libc_dlopen(name) \
  __libc_dlopen_mode (name, RTLD_LAZY | __RTLD_DLOPEN)
#define ELFW(type)	_ElfW (ELF, __ELF_NATIVE_CLASS, type)
#  define FORCED_DYNAMIC_TLS_OFFSET -1
# define symbind symbind32
#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t
#define __ELF_NATIVE_CLASS __WORDSIZE
# define DT_1_SUPPORTED_MASK \
   (DF_1_NOW | DF_1_NODELETE | DF_1_INITFIRST | DF_1_NOOPEN \
    | DF_1_ORIGIN | DF_1_NODEFLIB)
# define DL_CALL_FCT(fctp, args) \
  (_dl_mcount_wrapper_check ((void *) (fctp)), (*(fctp)) args)
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
