#include<limits.h>
#include<string.h>
#include<float.h>
#include<stdio.h>
#include<setjmp.h>
#include<math.h>
#include<stdlib.h>
#include<stddef.h>
#include<stdarg.h>


#define INFINITY (DBL_MAX+DBL_MAX)
#define JS_ARRAYLIMIT (1<<26)	
#define JS_ASTLIMIT 100		
#define JS_ENVLIMIT 128		
#define JS_GCFACTOR 5.0		
#define JS_STACKSIZE 256	
#define JS_STRLIMIT (1<<28)	
#define JS_TRYLIMIT 64		
#define NAN (INFINITY-INFINITY)
#define inline __inline
#define isfinite(x) _finite(x)
#define isinf(x) (!_finite(x))
#define isnan(x) _isnan(x)
#define js_trypc(J, PC) \
	setjmp(js_savetrypc(J, PC))

#define nelem(a) (int)(sizeof (a) / sizeof (a)[0])
#define snprintf jsW_snprintf
#define soffsetof(x,y) ((int)offsetof(x,y))
#define vsnprintf jsW_vsnprintf
#define JS_CHECKVERSION(x,y,z) (JS_VERSION >= ((x) * 10000 + (y) * 100 + (z)))
#define JS_NORETURN __attribute__((noreturn))
#define JS_PRINTFLIKE __printflike
#define JS_VERSION (JS_VERSION_MAJOR * 10000 + JS_VERSION_MINOR * 100 + JS_VERSION_PATCH)
#define JS_VERSION_MAJOR 1
#define JS_VERSION_MINOR 3
#define JS_VERSION_PATCH 1
#define js_try(J) \
	setjmp(js_savetry(J))

