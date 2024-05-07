


#include<errno.h>
#include<netinet/in.h>
#include<sys/param.h>

#include<sys/cdefs.h>



#define CHECK_FLAG(x)	(flags && strchr(flags, (x)))
#define DEBUGF(...)							\
	do {								\
		if (fetchDebug)						\
			fprintf(stderr, __VA_ARGS__);			\
	} while (0)

#define ftp_seterr(n)	 fetch_seterr(ftp_errlist, n)
#define http_seterr(n)	 fetch_seterr(http_errlist, n)
#define netdb_seterr(n)	 fetch_seterr(netdb_errlist, n)
#define url_seterr(n)	 fetch_seterr(url_errlist, n)
#define MAXERRSTRING 256
#define URL_PWDLEN 256
#define URL_SCHEMELEN 16
#define URL_USERLEN 256

#define _LIBFETCH_VER "libfetch/2.0"







#define alloca(sz) __builtin_alloca(sz)
#define MB_CUR_MAX_L(x) ((size_t)___mb_cur_max_l(x))


#define XLOCALE_ISCTYPE(__fname, __cat) \
		_XLOCALE_INLINE int is##__fname##_l(int, locale_t); \
		_XLOCALE_INLINE int is##__fname##_l(int __c, locale_t __l)\
		{ return __sbistype_l(__c, __cat, __l); }

#define _XLOCALE_INLINE extern __inline
#define _XLOCALE_RUN_FUNCTIONS_DEFINED 1

#define _CurrentRuneLocale (__getCurrentRuneLocale())
