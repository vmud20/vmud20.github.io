


#include<sys/param.h>


#include<assert.h>
#include<netinet/in.h>


#include<pthread.h>
#include<limits.h>




#include<unistd.h>
#define RPMDBG()		"at: " "__FILE__" ":" RPMDBG_TOSTR ("__LINE__")
#define RPMDBG_M(msg)		RPMDBG_M_DEBUG(msg)
#define RPMDBG_M_DEBUG(msg)	msg " " RPMDBG()
#define RPMDBG_M_NODEBUG(msg)	NULL
#define RPMDBG_TOSTR(a)		RPMDBG_TOSTR_ARG(a)
#define RPMDBG_TOSTR_ARG(a)	#a


#define RPMLEAD_BINARY 0
#define RPMLEAD_MAGIC0 0xed
#define RPMLEAD_MAGIC1 0xab
#define RPMLEAD_MAGIC2 0xee
#define RPMLEAD_MAGIC3 0xdb
#define RPMLEAD_SIZE 96         
#define RPMLEAD_SOURCE 1

#define N_(Text) Text
#define PATH_MAX MAXPATHLEN
# define _(Text) dgettext (PACKAGE, Text)
#define _free(_ptr) rfree((_ptr))
#define environ (*_NSGetEnviron())
#define xcalloc(_nmemb, _size) rcalloc((_nmemb), (_size))
# define xgetprogname(pn) getprogname(pn)
#define xmalloc(_size) rmalloc((_size))
#define xrealloc(_ptr, _size) rrealloc((_ptr), (_size))
# define xsetprogname(pn) setprogname(pn)
#define xstrdup(_str) rstrdup((_str))
# define FNM_LEADING_DIR (1 << 3)	
#  define __P(protos)	protos
# define RPM_BEGIN_DECLS  extern "C" {
# define RPM_END_DECLS    }
#define RPM_GNUC_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))
#define RPM_GNUC_ALLOC_SIZE2(x,y) __attribute__((__alloc_size__(x,y)))
#define RPM_GNUC_CONST                            \
  __attribute__((__const__))
#define RPM_GNUC_DEPRECATED                            \
  __attribute__((__deprecated__))
#  define RPM_GNUC_EXTENSION __extension__
#define RPM_GNUC_FORMAT( arg_idx )                \
  __attribute__((__format_arg__ (arg_idx)))
#  define RPM_GNUC_INTERNAL __attribute__((visibility("hidden")))
#define RPM_GNUC_MALLOC    			\
  __attribute__((__malloc__))
#define RPM_GNUC_MAY_ALIAS __attribute__((may_alias))
#define RPM_GNUC_NONNULL( ... )	\
  __attribute__((__nonnull__ (__VA_ARGS__)))
#define RPM_GNUC_NORETURN                         \
  __attribute__((__noreturn__))

#define RPM_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#define RPM_GNUC_PRINTF( format_idx, arg_idx )    \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))
#define RPM_GNUC_PURE                            \
  __attribute__((__pure__))
#define RPM_GNUC_SCANF( format_idx, arg_idx )     \
  __attribute__((__format__ (__scanf__, format_idx, arg_idx)))
#define RPM_GNUC_UNUSED                           \
  __attribute__((__unused__))
#define RPM_GNUC_WARN_UNUSED_RESULT 		\
  __attribute__((warn_unused_result))

