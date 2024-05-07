#include<string.h>
#include<grp.h>
#include<stdarg.h>
#include<stdio.h>
#include<ctype.h>
#include<stdint.h>
#include<limits.h>
#include<stddef.h>
#include<inttypes.h>


#include<assert.h>
#include<pwd.h>
#include<stdlib.h>
#include<getopt.h>
#include<stdio_ext.h>
#include<unistd.h>
#include<errno.h>
#include<sys/types.h>
#include<dirent.h>
#include<time.h>
#include<fcntl.h>



# define XALLOC_EXIT_CODE EXIT_FAILURE
#define err_oom()	__err_oom("__FILE__", "__LINE__")
#define AI_ADDRCONFIG 0x0020
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define BUILD_BUG_ON_NULL(e) ((void *)sizeof(struct { int:-!!(e); }))
# define FALSE 0
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#define IUTF8 0040000
# define LOGIN_NAME_MAX 256
# define MAP_ANONYMOUS  (MAP_ANON)
# define NAME_MAX PATH_MAX
#define O_CLOEXEC 0
# define PATH_MAX 4096
# define TRUE 1
# define UL_ASAN_BLACKLIST __attribute__((noinline)) __attribute__((no_sanitize_memory)) __attribute__((no_sanitize_address))
#define UL_BUILD_BUG_ON_ZERO(e) __extension__ (sizeof(struct { int:-!!(e); }))
#define USAGE_ARGUMENTS   _("\nArguments:\n")
#define USAGE_ARG_SEPARATOR    "\n"
#define USAGE_ARG_SIZE(_name) \
		_(" %s arguments may be followed by the suffixes for\n" \
		  "   GiB, TiB, PiB, EiB, ZiB, and YiB (the \"iB\" is optional)\n"), _name
#define USAGE_COLUMNS    _("\nAvailable output columns:\n")
#define USAGE_COMMANDS   _("\nCommands:\n")
#define USAGE_FUNCTIONS  _("\nFunctions:\n")
#define USAGE_HEADER     _("\nUsage:\n")
#define USAGE_HELP_OPTIONS(marg_dsc) \
		"%-" #marg_dsc "s%s\n" \
		"%-" #marg_dsc "s%s\n" \
		, " -h, --help",    USAGE_OPTSTR_HELP \
		, " -V, --version", USAGE_OPTSTR_VERSION
#define USAGE_MAN_TAIL(_man)   _("\nFor more details see %s.\n"), _man
#define USAGE_OPTIONS    _("\nOptions:\n")
#define USAGE_OPTSTR_HELP     _("display this help")
#define USAGE_OPTSTR_VERSION  _("display version")
#define USAGE_SEPARATOR    "\n"

#define UTIL_LINUX_VERSION _("%s from %s\n"), program_invocation_short_name, PACKAGE_STRING
#  define __GNUC_PREREQ(maj, min) \
	(("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
# define __attribute__(_arg_)
  #define __has_attribute(x) 0
  #define __has_feature(x) 0
# define __must_be_array(a) \
	UL_BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(__typeof__(a), __typeof__(&a[0])))
#  define __ul_alloc_size(s) __attribute__((alloc_size(s), warn_unused_result))
#  define __ul_calloc_size(n, s) __attribute__((alloc_size(n, s), warn_unused_result))
# define __ul_returns_nonnull __attribute__((returns_nonnull))
# define abs_diff(x, y) __extension__ ({        \
	__typeof__(x) _a = (x);			\
	__typeof__(y) _b = (y);			\
	(void) (&_a == &_b);			\
	_a > _b ? _a - _b : _b - _a; })
# define cmp_numbers(x, y) __extension__ ({	\
	__typeof__(x) _a = (x);			\
	__typeof__(y) _b = (y);			\
	(void) (&_a == &_b);			\
	_a == _b ? 0 : _a > _b ? 1 : -1; })
#  define cmp_stat_mtime(_a, _b, CMP)	cmp_timespec(&(_a)->st_mtim, &(_b)->st_mtim, CMP)
# define cmp_timespec(a, b, CMP)		\
	(((a)->tv_sec == (b)->tv_sec)		\
	? ((a)->tv_nsec CMP (b)->tv_nsec)	\
	: ((a)->tv_sec CMP (b)->tv_sec))
#define container_of(ptr, type, member) __extension__ ({	\
	const __typeof__( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
# define err(E, FMT...) errmsg(1, E, 1, FMT)
#define errexec(name)	err(errno == ENOENT ? EX_EXEC_ENOENT : EX_EXEC_FAILED, \
			_("failed to execute %s"), name)
#define errtryhelp(eval) __extension__ ({ \
	fprintf(stderr, _("Try '%s --help' for more information.\n"), \
			program_invocation_short_name); \
	exit(eval); \
})
# define errx(E, FMT...) errmsg(1, E, 0, FMT)
# define ignore_result(x) __extension__ ({ \
	__typeof__(x) __dummy __attribute__((__unused__)) = (x); (void) __dummy; \
})
# define max(x, y) __extension__ ({		\
	__typeof__(x) _max1 = (x);		\
	__typeof__(y) _max2 = (y);		\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
# define min(x, y) __extension__ ({		\
	__typeof__(x) _min1 = (x);		\
	__typeof__(y) _min2 = (y);		\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define print_version(eval) __extension__ ({ \
		printf(UTIL_LINUX_VERSION); \
		exit(eval); \
})
#   define program_invocation_short_name \
		prog_inv_sh_nm_from_file(getexecname(), 0)
#   define restrict __restrict 
#define stringify(s) #s
#define stringify_value(s) stringify(s)
# define warn(FMT...) errmsg(0, 0, 1, FMT)
# define warnx(FMT...) errmsg(0, 0, 0, FMT)

#define isdigit_string(_s)	isdigit_strend(_s, NULL)
#define isxdigit_string(_s)	isxdigit_strend(_s, NULL)
#define strdup_between_structs(_dst, _src, _m) \
		strdup_between_offsets((void *)_dst, (void *)_src, offsetof(__typeof__(*(_src)), _m))
#define strdup_to_struct_member(_s, _m, _str) \
		strdup_to_offset((void *) _s, offsetof(__typeof__(*(_s)), _m), _str)
#define strtos16_or_err(_s, _e)	(int16_t) str2num_or_err(_s, 10, _e, INT16_MIN, INT16_MAX)
#define strtos32_or_err(_s, _e)	(int32_t) str2num_or_err(_s, 10, _e, INT32_MIN, INT32_MAX)
#define strtos64_or_err(_s, _e)	str2num_or_err(_s, 10, _e, 0, 0)
#define strtou16_or_err(_s, _e)	(uint16_t) str2unum_or_err(_s, 10, _e, UINT16_MAX)
#define strtou32_or_err(_s, _e)	(uint32_t) str2unum_or_err(_s, 10, _e, UINT32_MAX)
#define strtou64_or_err(_s, _e)	str2unum_or_err(_s, 10, _e, 0)
#define strtox16_or_err(_s, _e)	(uint16_t) str2unum_or_err(_s, 16, _e, UINT16_MAX)
#define strtox32_or_err(_s, _e)	(uint32_t) str2unum_or_err(_s, 16, _e, UINT32_MAX)
#define strtox64_or_err(_s, _e)	str2unum_or_err(_s, 16, _e, 0)


#define _PATH_PROC_LOCKS        "/proc/locks"
#define _PATH_TERMCOLORS_DIRNAME "terminal-colors.d"
#define _PATH_WORDS             "/usr/share/dict/words"
#define _PATH_WORDS_ALT         "/usr/share/dict/web2"

# define ALTMON_1 MON_1
# define ALTMON_10 MON_10
# define ALTMON_11 MON_11
# define ALTMON_12 MON_12
# define ALTMON_2 MON_2
# define ALTMON_3 MON_3
# define ALTMON_4 MON_4
# define ALTMON_5 MON_5
# define ALTMON_6 MON_6
# define ALTMON_7 MON_7
# define ALTMON_8 MON_8
# define ALTMON_9 MON_9
#define LOCALEDIR "/usr/share/locale"
#  define N_(String) gettext_noop (String)
# define P_(Singular, Plural, n) ngettext (Singular, Plural, n)

#  define _(Text) dgettext (UL_TEXTDOMAIN_EXPLICIT, Text)
# define _NL_ABALTMON_1 ABMON_1
# define _NL_ABALTMON_10 ABMON_10
# define _NL_ABALTMON_11 ABMON_11
# define _NL_ABALTMON_12 ABMON_12
# define _NL_ABALTMON_2 ABMON_2
# define _NL_ABALTMON_3 ABMON_3
# define _NL_ABALTMON_4 ABMON_4
# define _NL_ABALTMON_5 ABMON_5
# define _NL_ABALTMON_6 ABMON_6
# define _NL_ABALTMON_7 ABMON_7
# define _NL_ABALTMON_8 ABMON_8
# define _NL_ABALTMON_9 ABMON_9
# define bindtextdomain(Domain, Directory) 
# define localeconv() NULL
# define setlocale(Category, Locale) 
# define textdomain(Domain) 

# define CLOSE_EXIT_CODE EXIT_FAILURE


# define XSETENV_EXIT_CODE EXIT_FAILURE
