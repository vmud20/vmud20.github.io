#include<fcntl.h>
#include<stddef.h>
#include<sys/types.h>
#include<string.h>
#include<sys/stat.h>
#include<errno.h>
#include<stdint.h>
#include<dirent.h>
#include<unistd.h>

#include<assert.h>
#include<paths.h>
#include<time.h>
#include<sys/resource.h>
#include<limits.h>
#include<stdarg.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/time.h>

#define _PATH_PROC_LOCKS        "/proc/locks"
#define _PATH_TERMCOLORS_DIRNAME "terminal-colors.d"
#define _PATH_USERTTY           "/etc/usertty"
#define _PATH_WORDS             "/usr/share/dict/words"
#define _PATH_WORDS_ALT         "/usr/share/dict/web2"

#define AI_ADDRCONFIG 0x0020
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define BUILD_BUG_ON_NULL(e) ((void *)sizeof(struct { int:-!!(e); }))
# define FALSE 0
#define IUTF8 0040000
#define O_CLOEXEC 0
# define PATH_MAX 4096
# define TRUE 1
#  define UL_ASAN_BLACKLIST __attribute__((noinline)) __attribute__((no_sanitize_memory)) __attribute__((no_sanitize_address))
#define UL_BUILD_BUG_ON_ZERO(e) __extension__ (sizeof(struct { int:-!!(e); }))
#define USAGE_HEADER     _("\nUsage:\n")
#define USAGE_HELP       _(" -h, --help     display this help and exit\n")
#define USAGE_MAN_TAIL(_man)   _("\nFor more details see %s.\n"), _man
#define USAGE_OPTIONS    _("\nOptions:\n")
#define USAGE_SEPARATOR    "\n"
#define USAGE_VERSION    _(" -V, --version  output version information and exit\n")

#define UTIL_LINUX_VERSION _("%s from %s\n"), program_invocation_short_name, PACKAGE_STRING
#  define __GNUC_PREREQ(maj, min) \
	(("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
# define __attribute__(_arg_)
# define __must_be_array(a) \
	UL_BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(__typeof__(a), __typeof__(&a[0])))
#  define __ul_alloc_size(s) __attribute__((alloc_size(s), warn_unused_result))
#  define __ul_calloc_size(n, s) __attribute__((alloc_size(n, s), warn_unused_result))
# define cmp_numbers(x, y) __extension__ ({	\
	__typeof__(x) _a = (x);			\
	__typeof__(y) _b = (y);			\
	(void) (&_a == &_b);			\
	_a == _b ? 0 : _a > _b ? 1 : -1; })
#define container_of(ptr, type, member) __extension__ ({	 \
	const __typeof__( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
# define err(E, FMT...) errmsg(1, E, 1, FMT)
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
#   define program_invocation_short_name \
		prog_inv_sh_nm_from_file(getexecname(), 0)
#define stringify(s) #s
#define stringify_value(s) stringify(s)
# define warn(FMT...) errmsg(0, 0, 1, FMT)
# define warnx(FMT...) errmsg(0, 0, 0, FMT)
