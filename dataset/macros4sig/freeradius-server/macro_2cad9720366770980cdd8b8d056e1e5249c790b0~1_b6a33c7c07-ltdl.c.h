


#include<sys/types.h>

#define LTDL_H 1
#define LTDL_SET_PRELOADED_SYMBOLS() 		LT_STMT_START{	\
	extern const lt_dlsymlist lt_preloaded_symbols[];		\
	lt_dlpreload_default(lt_preloaded_symbols);			\
						}LT_STMT_END
#  define LT_CONC(s,t)	s##t
#define LT_ERROR(name, diagnostic)	LT_CONC(LT_ERROR_, name),
# define LT_PARAMS(protos)	protos
#  define LT_STMT_END          )
#  define LT_STMT_START        (void)(
#define LT_STRLEN(s)	(((s) && (s)[0]) ? strlen (s) : 0)
#  define R_OK 4
#    define __CYGWIN__ __CYGWIN32__
#      define __WINDOWS__ _WIN32
