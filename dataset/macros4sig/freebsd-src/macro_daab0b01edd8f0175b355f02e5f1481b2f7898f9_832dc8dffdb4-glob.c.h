
#include<sys/stat.h>
#include<sys/types.h>

#include<sys/cdefs.h>
#include<sys/param.h>


#include<errno.h>

#include<sys/unistd.h>

#include<stdint.h>







#define _CurrentRuneLocale (__getCurrentRuneLocale())



#define alloca(sz) __builtin_alloca(sz)
#define MB_CUR_MAX_L(x) (___mb_cur_max_l(x))
#define _PWF(x)		(1 << x)
#define _PW_VERSIONED(x, v)	((unsigned char)(((x) & 0xCF) | ((v)<<4)))


#define XLOCALE_ISCTYPE(__fname, __cat) \
		_XLOCALE_INLINE int is##__fname##_l(int, locale_t); \
		_XLOCALE_INLINE int is##__fname##_l(int __c, locale_t __l)\
		{ return __sbistype_l(__c, __cat, __l); }

#define _XLOCALE_INLINE extern __inline
#define _XLOCALE_RUN_FUNCTIONS_DEFINED 1

