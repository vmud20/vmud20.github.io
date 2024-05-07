

















#  define __need_size_t
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
# define _IO_flockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0)				      \
     _IO_lock_lock (*(_fp)->_lock)
# define _IO_funlockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0)				      \
    _IO_lock_unlock (*(_fp)->_lock)

# define EOF (-1)
#   define NULL ((void*)0)
#define _IO_BAD_SEEN 0x4000
# define _IO_BE(expr, res) __builtin_expect ((expr), res)
#define _IO_BOOLALPHA 0200000
#define _IO_BUFSIZ _G_BUFSIZ
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_DEC 020
#define _IO_DELETE_DONT_CLOSE 0x40 
#define _IO_DONT_CLOSE 0100000
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_FIXED 010000
# define _IO_FLAGS2_CLOEXEC 64
# define _IO_FLAGS2_FORTIFY 4
#define _IO_FLAGS2_MMAP 1
# define _IO_FLAGS2_NOCLOSE 32
#define _IO_FLAGS2_NOTCANCEL 2
# define _IO_FLAGS2_SCANF_STD 16
#define _IO_FLAGS2_USER_WBUF 8
#define _IO_HAVE_ST_BLKSIZE _G_HAVE_ST_BLKSIZE
#define _IO_HEX 0100
#define _IO_INTERNAL 010
#define _IO_IN_BACKUP 0x100
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_LEFT 02
#define _IO_LINE_BUF 0x200
#define _IO_LINKED 0x80 
#define _IO_MAGIC 0xFBAD0000 
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_NO_READS 4 
#define _IO_NO_WRITES 8 
#define _IO_OCT 040
#define _IO_PENDING_OUTPUT_COUNT(_fp)	\
	((_fp)->_IO_write_ptr - (_fp)->_IO_write_base)
#define _IO_RIGHT 04
#define _IO_SCIENTIFIC 04000
#define _IO_SHOWBASE 0200
#define _IO_SHOWPOINT 0400
#define _IO_SHOWPOS 02000
#define _IO_SKIPWS 01
#define _IO_STDIO 040000

#define _IO_TIED_PUT_GET 0x400 
#define _IO_UNBUFFERED 2
#define _IO_UNIFIED_JUMPTABLES 1
#define _IO_UNITBUF 020000
#define _IO_UPPERCASE 01000
#define _IO_USER_BUF 1 
#define _IO_USER_LOCK 0x8000
# define _IO_cleanup_region_end(_Doit) 
# define _IO_cleanup_region_start(_fct, _fp) 
#define _IO_feof_unlocked(__fp) (((__fp)->_flags & _IO_EOF_SEEN) != 0)
#define _IO_ferror_unlocked(__fp) (((__fp)->_flags & _IO_ERR_SEEN) != 0)
#define _IO_file_flags _flags
#define _IO_fpos64_t _G_fpos64_t
#define _IO_fpos_t _G_fpos_t
# define _IO_ftrylockfile(_fp) 
#  define _IO_fwide(__fp, __mode) \
  ({ int __result = (__mode);						      \
     if (__result < 0 && ! _IO_fwide_maybe_incompatible)		      \
       {								      \
	 if ((__fp)->_mode == 0)					      \
	   	      \
	   (__fp)->_mode = -1;						      \
	 __result = (__fp)->_mode;					      \
       }								      \
     else if (__builtin_constant_p (__mode) && (__mode) == 0)		      \
       __result = _IO_fwide_maybe_incompatible ? -1 : (__fp)->_mode;	      \
     else								      \
       __result = _IO_fwide (__fp, __result);				      \
     __result; })
#    define _IO_fwide_maybe_incompatible \
  (__builtin_expect (&_IO_stdin_used == NULL, 0))
#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
	? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
# define _IO_getwc_unlocked(_fp) \
  (_IO_BE ((_fp)->_wide_data == NULL					\
	   || ((_fp)->_wide_data->_IO_read_ptr				\
	       >= (_fp)->_wide_data->_IO_read_end), 0)			\
   ? __wuflow (_fp) : (_IO_wint_t) *(_fp)->_wide_data->_IO_read_ptr++)
#define _IO_iconv_t _G_iconv_t
#define _IO_off64_t __off64_t
#define _IO_off_t __off_t
# define _IO_peekc(_fp) _IO_peekc_locked (_fp)
#define _IO_peekc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
	  && __underflow (_fp) == EOF ? EOF \
	: *(unsigned char *) (_fp)->_IO_read_ptr)
#define _IO_pid_t __pid_t
#define _IO_putc_unlocked(_ch, _fp) \
   (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) \
    ? __overflow (_fp, (unsigned char) (_ch)) \
    : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
# define _IO_putwc_unlocked(_wch, _fp) \
  (_IO_BE ((_fp)->_wide_data == NULL					\
	   || ((_fp)->_wide_data->_IO_write_ptr				\
	       >= (_fp)->_wide_data->_IO_write_end), 0)			\
   ? __woverflow (_fp, _wch)						\
   : (_IO_wint_t) (*(_fp)->_wide_data->_IO_write_ptr++ = (_wch)))
#define _IO_size_t size_t
#define _IO_ssize_t __ssize_t
#define _IO_stderr ((_IO_FILE*)(&_IO_2_1_stderr_))
#define _IO_stdin ((_IO_FILE*)(&_IO_2_1_stdin_))
#define _IO_stdout ((_IO_FILE*)(&_IO_2_1_stdout_))
#define _IO_uid_t __uid_t
# define _IO_va_list __gnuc_va_list
#define _IO_wint_t wint_t
#define _OLD_STDIO_MAGIC 0xFABC0000 
#define __HAVE_COLUMN 

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
# define LIBINTL_DLL_EXPORTED
# define PATH_SEPARATOR ';'
# define __builtin_expect(expr, val) (expr)
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





#  define _WINT_T
#  define __iswdigit_l(c, l) ({ wint_t __c = (c); __c >= L'0' && __c <= L'9'; })
# define __need_wint_t
#  define iswdigit(c) ({ wint_t __c = (c); __c >= L'0' && __c <= L'9'; })
#  define iswdigit_l(c, l) ({ wint_t __c = (c); __c >= L'0' && __c <= L'9'; })
#  define WEOF (0xffffffffu)
#   define _ISwbit(bit)	(1 << (bit))
#  define __mbsinit(state) ((state)->__count == 0)
#  define mbsinit(state) ((state)->__count == 0)
# define WCHAR_MAX __WCHAR_MAX
# define WCHAR_MIN __WCHAR_MIN
# define _WCHAR_H 1
#  define __CORRECT_ISO_CPP_WCHAR_H_PROTO
#  define __mbstate_t_defined 1
#  define __need_FILE
# define __need_NULL
# define __need___FILE
# define __need_iswxxx
# define __need_wchar_t
#   define fwscanf __isoc99_fwscanf
#   define swscanf __isoc99_swscanf
#   define vfwscanf __isoc99_vfwscanf
#   define vswscanf __isoc99_vswscanf
#   define vwscanf __isoc99_vwscanf
#   define wscanf __isoc99_wscanf
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
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
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
# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
