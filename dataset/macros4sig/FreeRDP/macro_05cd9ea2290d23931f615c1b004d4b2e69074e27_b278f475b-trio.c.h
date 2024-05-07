

#include<stdarg.h>


#include<wctype.h>

#include<varargs.h>

#include<ctype.h>
#include<errno.h>
#include<stdlib.h>

#include<locale.h>
#include<string.h>
#include<limits.h>


#include<stdio.h>
#include<wchar.h>
#include<unistd.h>
#include<time.h>
#include<inttypes.h>


#include<math.h>
#include<stdint.h>
#include<stddef.h>
#include<signal.h>

#include<float.h>
#include<assert.h>

#define BOOLEAN_T int
#define FALSE (1 == 0)



#define NIL ((char)0)
#define NULL 0

#define TRIO_PRIVATE_STRING TRIO_PRIVATE
#define TRIO_PUBLIC_STRING TRIO_PUBLIC
#define TRUE (!FALSE)







#define strcasecmp(x, y) _stricmp(x, y)
#define strncasecmp(x, y, n) strnicmp(x, y, n)
#define trio_powl(x, y) powl((x), (y))











































































#define TRIO_BSD 1
#define TRIO_C99 1
#define TRIO_DEPRECATED 1
#define TRIO_EMBED_NAN 1
#define TRIO_EMBED_STRING 1
#define TRIO_EXTENSION 1
#define TRIO_FEATURE_ARGFUNC 0
#define TRIO_FEATURE_BINARY TRIO_EXTENSION
#define TRIO_FEATURE_CLOSURE 0
#define TRIO_FEATURE_DYNAMICSTRING 0
#define TRIO_FEATURE_ERRNO TRIO_GNU
#define TRIO_FEATURE_ERRORCODE TRIO_ERRORS
#define TRIO_FEATURE_FD 0
#define TRIO_FEATURE_FILE 0
#define TRIO_FEATURE_FIXED_SIZE TRIO_MICROSOFT
#define TRIO_FEATURE_FLOAT 1
#define TRIO_FEATURE_HEXFLOAT (TRIO_C99 && TRIO_FEATURE_FLOAT)
#define TRIO_FEATURE_INTMAX_T TRIO_C99
#define TRIO_FEATURE_LOCALE 0
#define TRIO_FEATURE_LONGDOUBLE TRIO_FEATURE_FLOAT
#define TRIO_FEATURE_POSITIONAL TRIO_UNIX98
#define TRIO_FEATURE_PTRDIFF_T TRIO_C99
#define TRIO_FEATURE_QUAD (TRIO_BSD || TRIO_GNU)
#define TRIO_FEATURE_QUOTE TRIO_EXTENSION
#define TRIO_FEATURE_ROUNDING TRIO_EXTENSION
#define TRIO_FEATURE_SCANF 0
#define TRIO_FEATURE_SIZE_T TRIO_C99
#define TRIO_FEATURE_SIZE_T_UPPER TRIO_GNU
#define TRIO_FEATURE_STDIO 0
#define TRIO_FEATURE_STICKY TRIO_EXTENSION
#define TRIO_FEATURE_STRERR 0
#define TRIO_FEATURE_USER_DEFINED TRIO_EXTENSION
#define TRIO_FEATURE_VARSIZE TRIO_EXTENSION
#define TRIO_FEATURE_WIDECHAR 0
#define TRIO_FREE(x) free(x)
#define TRIO_GNU 1
#define TRIO_MALLOC(n) malloc(n)
#define TRIO_MICROSOFT 1
#define TRIO_MISC 1
#define TRIO_REALLOC(x, n) realloc((x), (n))

#define TRIO_UNIX98 1






#define PREDEF_STANDARD_POSIX _POSIX_VERSION






#define TRIO_ARGS1(list, a1) list a1;
#define TRIO_ARGS2(list, a1, a2) \
	list a1;                     \
	a2;
#define TRIO_ARGS3(list, a1, a2, a3) \
	list a1;                         \
	a2;                              \
	a3;
#define TRIO_ARGS4(list, a1, a2, a3, a4) \
	list a1;                             \
	a2;                                  \
	a3;                                  \
	a4;
#define TRIO_ARGS5(list, a1, a2, a3, a4, a5) \
	list a1;                                 \
	a2;                                      \
	a3;                                      \
	a4;                                      \
	a5;
#define TRIO_ARGS6(list, a1, a2, a3, a4, a5, a6) \
	list a1;                                     \
	a2;                                          \
	a3;                                          \
	a4;                                          \
	a5;                                          \
	a6;
#define TRIO_ARGS7(list, a1, a2, a3, a4, a5, a6, a7) \
	list a1;                                         \
	a2;                                              \
	a3;                                              \
	a4;                                              \
	a5;                                              \
	a6;                                              \
	a7;
#define TRIO_ARGS8(list, a1, a2, a3, a4, a5, a6, a7, a8) \
	list a1;                                             \
	a2;                                                  \
	a3;                                                  \
	a4;                                                  \
	a5;                                                  \
	a6;                                                  \
	a7;                                                  \
	a8;


#define TRIO_COMPILER_DECC 




#define TRIO_COMPILER_SUNPRO __SUNPRO_CC

#define TRIO_COMPILER_XLC 
#define TRIO_CONST const
#define TRIO_INLINE inline
#define TRIO_NOARGS void
#define TRIO_NO_CEILL 1
#define TRIO_NO_FLOORL 1
#define TRIO_NO_FMODL 1
#define TRIO_NO_LOG10L 1
#define TRIO_NO_POWL 1











#define TRIO_PRIVATE static
#define TRIO_PROTO(x) ()
#define TRIO_SIGNED signed
#define TRIO_SUFFIX_LONG(x) x

#define TRIO_VARGS2 TRIO_ARGS2
#define TRIO_VARGS3 TRIO_ARGS3
#define TRIO_VARGS4 TRIO_ARGS4
#define TRIO_VARGS5 TRIO_ARGS5
#define TRIO_VA_DECL va_dcl
#define TRIO_VA_END(x) va_end(x)
#define TRIO_VA_START(x, y) va_start(x)
#define TRIO_VOLATILE volatile
#define AIX_CLASS(n) _class(n)
#define TRIO_DOUBLE_INDEX(x) (((unsigned char*)&internalEndianMagic)[7 - (x)])
#define TRIO_FALSE (0 == 1)


























#define TRIO_PRIVATE_NAN TRIO_PRIVATE
#define TRIO_PUBLIC_NAN TRIO_PUBLIC
#define TRIO_TRUE (1 == 1)











#define TRIO_ERROR_CODE(x) ((-(x)) & 0x00FF)
#define TRIO_ERROR_NAME(x) trio_strerror(x)
#define TRIO_ERROR_POSITION(x) ((-(x)) >> 8)

#define aprintf trio_aprintf
#define asprintf trio_asprintf
#define dprintf trio_dprintf
#define dscanf trio_dscanf
#define fprintf trio_fprintf
#define fscanf trio_fscanf
#define printf trio_printf
#define scanf trio_scanf
#define snprintf trio_snprintf
#define sprintf trio_sprintf
#define sscanf trio_sscanf
#define vaprintf trio_vaprintf
#define vasprintf trio_vasprintf
#define vdprintf trio_vdprintf
#define vdscanf trio_vdscanf
#define vfprintf trio_vfprintf
#define vfscanf trio_vfscanf
#define vprintf trio_vprintf
#define vscanf trio_vscanf
#define vsnprintf trio_vsnprintf
#define vsprintf trio_vsprintf
#define vsscanf trio_vsscanf
