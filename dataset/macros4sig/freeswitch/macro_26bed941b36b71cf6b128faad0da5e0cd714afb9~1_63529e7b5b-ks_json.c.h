#include<stdint.h>
#include<sys/socket.h>
#include<unistd.h>
#include<sys/select.h>
#include<limits.h>
#include<time.h>
#include<assert.h>
#include<errno.h>
#include<stdarg.h>
#include<netinet/tcp.h>
#include<inttypes.h>
#include<ctype.h>
#include<sys/ioctl.h>
#include<string.h>

#include<strings.h>
#include<sys/signal.h>
#include<sys/time.h>
#include<sys/types.h>
#include<math.h>
#include<netdb.h>
#include<float.h>
#include<stdio.h>
#include<netinet/in.h>





#include<stdlib.h>
#define BUF_CHUNK 65536 * 50
#define BUF_START 65536 * 100

#define end_of(_s) *(*_s == '\0' ? _s : _s + strlen(_s) - 1)
#define ks_assert(expr) assert(expr);__analysis_assume( expr )
#define ks_clear_flag(obj, flag) (obj)->flags &= ~(flag)
#define ks_copy_string(_x, _y, _z) strncpy(_x, _y, _z - 1)
#define ks_recv(_h) ks_recv_event(_h, 0, NULL)
#define ks_recv_timed(_h, _ms) ks_recv_event_timed(_h, _ms, 0, NULL)
#define ks_safe_free(_x) if (_x) free(_x); _x = NULL
#define ks_set_flag(obj, flag) (obj)->flags |= (flag)
#define ks_set_string(_x, _y) ks_copy_string(_x, _y, sizeof(_x))
#define ks_strlen_zero(s) (!s || *(s) == '\0')
#define ks_strlen_zero_buf(s) (*(s) == '\0')
#define ks_test_flag(obj, flag) ((obj)->flags & flag)

#define BITS(type)	(BITSPERBYTE * (int)sizeof(type))
#define ENTRY_DATA_BUF(tab_p, entry_p)					\
	(ENTRY_KEY_BUF(entry_p) + (entry_p)->te_key_size)
#define ENTRY_KEY_BUF(entry_p)		((entry_p)->te_key_buf)
#define HASH_MIX(a, b, c)						\
	do {										\
		a -= b; a -= c; a ^= (c >> 13);			\
		b -= c; b -= a; b ^= (a << 8);			\
		c -= a; c -= b; c ^= (b >> 13);			\
		a -= b; a -= c; a ^= (c >> 12);			\
		b -= c; b -= a; b ^= (a << 16);			\
		c -= a; c -= b; c ^= (b >> 5);			\
		a -= b; a -= c; a ^= (c >> 3);			\
		b -= c; b -= a; b ^= (a << 10);			\
		c -= a; c -= b; c ^= (b >> 15);			\
	} while(0)

#define SET_POINTER(pnt, val)					\
	do {										\
		if ((pnt) != NULL) {					\
			(*(pnt)) = (val);					\
		}										\
	} while(0)
#define SHOULD_TABLE_GROW(tab)	((tab)->ta_entry_n > (tab)->ta_bucket_n * 2)
#define SHOULD_TABLE_SHRINK(tab) ((tab)->ta_entry_n < (tab)->ta_bucket_n / 2)
#define TABLE_POINTER(table, type, pnt)		(pnt)


#define MPOOL_ERROR_ALLOC 20 
#define MPOOL_ERROR_ARG_INVALID 3 
#define MPOOL_ERROR_ARG_NULL 2 
#define MPOOL_ERROR_BLOCK_STAT 16 
#define MPOOL_ERROR_FREE_ADDR 17 
#define MPOOL_ERROR_IS_FREE 15 
#define MPOOL_ERROR_MEM  12 
#define MPOOL_ERROR_MEM_OVER 13 
#define MPOOL_ERROR_MMAP 9 
#define MPOOL_ERROR_NONE 1 
#define MPOOL_ERROR_NOT_FOUND 14 
#define MPOOL_ERROR_NO_MEM 8 
#define MPOOL_ERROR_NO_PAGES 19 
#define MPOOL_ERROR_OPEN_ZERO 7 
#define MPOOL_ERROR_PAGE_SIZE 6 
#define MPOOL_ERROR_PNT  4 
#define MPOOL_ERROR_PNT_OVER 21 
#define MPOOL_ERROR_POOL_OVER 5 
#define MPOOL_ERROR_SIZE 10 
#define MPOOL_ERROR_TOO_BIG 11 
#define MPOOL_ERROR_UNUSED  18 
#define MPOOL_FLAG_ANONYMOUS  (1<<3)
#define MPOOL_FLAG_BEST_FIT  (1<<0)
#define MPOOL_FLAG_HEAVY_PACKING (1<<2)
#define MPOOL_FLAG_NO_FREE  (1<<1)
#define MPOOL_FUNC_ALLOC 3 
#define MPOOL_FUNC_CALLOC 4 
#define MPOOL_FUNC_CLEAR 2 
#define MPOOL_FUNC_CLOSE 1 
#define MPOOL_FUNC_FREE  5 
#define MPOOL_FUNC_RESIZE 6 

#define BIT_CLEAR(v,f)		(v) &= ~(f)
#define BIT_FLAG(x)		(1 << (x))
#define BIT_IS_SET(v,f)		((v) & (f))
#define BIT_SET(v,f)		(v) |= (f)
#define BIT_TOGGLE(v,f)		(v) ^= (f)
#define FIRST_ADDR_IN_BLOCK(block_p)	(void *)((char *)(block_p) +	\
												 sizeof(mpool_block_t))
#define MAX_BLOCK_USER_MEMORY(mp_p)	((mp_p)->mp_page_size - \
									 sizeof(mpool_block_t))
#define MEMORY_IN_BLOCK(block_p)	((char *)(block_p)->mb_bounds_p -	\
									 ((char *)(block_p) +				\
									  sizeof(mpool_block_t)))
#define PAGES_IN_SIZE(mp_p, size)	(((size) + sizeof(mpool_block_t) +	\
									  (mp_p)->mp_page_size - 1) /		\
									 (mp_p)->mp_page_size)
#define SIZE_OF_PAGES(mp_p, page_n)	((page_n) * (mp_p)->mp_page_size)


#define KS_CONFIG_DIR "c:\\openks"

#define KS_PATH_SEPARATOR "\\"
#define KS_URL_SEPARATOR "://"
#define ks_false(expr)\
(expr && ( !strcasecmp(expr, "no") ||\
!strcasecmp(expr, "off") ||\
!strcasecmp(expr, "false") ||\
!strcasecmp(expr, "disabled") ||\
!strcasecmp(expr, "inactive") ||\
!strcasecmp(expr, "disallow") ||\
!atoi(expr))) ? 1 : 0
#define ks_is_file_path(file) (*(file +1) == ':' || *file == '/' || strstr(file, SWITCH_URL_SEPARATOR))
#define ks_true(expr)\
(expr && ( !strcasecmp(expr, "yes") ||\
!strcasecmp(expr, "on") ||\
!strcasecmp(expr, "true") ||\
!strcasecmp(expr, "enabled") ||\
!strcasecmp(expr, "active") ||\
!strcasecmp(expr, "allow") ||\
atoi(expr))) ? 1 : 0

#define cJSON_AddFalseToObject(object,name)		cJSON_AddItemToObject(object, name, cJSON_CreateFalse())
#define cJSON_AddNullToObject(object,name)	cJSON_AddItemToObject(object, name, cJSON_CreateNull())
#define cJSON_AddNumberToObject(object,name,n)	cJSON_AddItemToObject(object, name, cJSON_CreateNumber(n))
#define cJSON_AddStringToObject(object,name,s)	cJSON_AddItemToObject(object, name, cJSON_CreateString(s))
#define cJSON_AddTrueToObject(object,name)	cJSON_AddItemToObject(object, name, cJSON_CreateTrue())
#define cJSON_Array 5
#define cJSON_False 0
#define cJSON_IsReference 256
#define cJSON_NULL 2
#define cJSON_Number 3
#define cJSON_Object 6
#define cJSON_String 4
#define cJSON_True 1

#define KS_LOG_ALERT KS_PRE, KS_LOG_LEVEL_ALERT
#define KS_LOG_CRIT KS_PRE, KS_LOG_LEVEL_CRIT
#define KS_LOG_DEBUG KS_PRE, KS_LOG_LEVEL_DEBUG
#define KS_LOG_EMERG KS_PRE, KS_LOG_LEVEL_EMERG
#define KS_LOG_ERROR KS_PRE, KS_LOG_LEVEL_ERROR
#define KS_LOG_INFO KS_PRE, KS_LOG_LEVEL_INFO
#define KS_LOG_LEVEL_ALERT 1
#define KS_LOG_LEVEL_CRIT 2
#define KS_LOG_LEVEL_DEBUG 7
#define KS_LOG_LEVEL_EMERG 0
#define KS_LOG_LEVEL_ERROR 3
#define KS_LOG_LEVEL_INFO 6
#define KS_LOG_LEVEL_NOTICE 5
#define KS_LOG_LEVEL_WARNING 4
#define KS_LOG_NOTICE KS_PRE, KS_LOG_LEVEL_NOTICE
#define KS_LOG_WARNING KS_PRE, KS_LOG_LEVEL_WARNING
#define KS_PRE "__FILE__", __FUNCTION__, "__LINE__"
#define KS_SEQ_AND_COLOR ";"	
#define KS_SEQ_BBLACK KS_SEQ_ESC KS_SEQ_B_BLACK KS_SEQ_END_COLOR
#define KS_SEQ_BBLUE KS_SEQ_ESC KS_SEQ_B_BLUE KS_SEQ_END_COLOR
#define KS_SEQ_BCYAN KS_SEQ_ESC KS_SEQ_B_CYAN KS_SEQ_END_COLOR
#define KS_SEQ_BGREEN KS_SEQ_ESC KS_SEQ_B_GREEN KS_SEQ_END_COLOR
#define KS_SEQ_BMAGEN KS_SEQ_ESC KS_SEQ_B_MAGEN KS_SEQ_END_COLOR
#define KS_SEQ_BRED KS_SEQ_ESC KS_SEQ_B_RED KS_SEQ_END_COLOR
#define KS_SEQ_BWHITE KS_SEQ_ESC KS_SEQ_B_WHITE KS_SEQ_END_COLOR
#define KS_SEQ_BYELLOW KS_SEQ_ESC KS_SEQ_B_YELLOW KS_SEQ_END_COLOR
#define KS_SEQ_B_BLACK "40"
#define KS_SEQ_B_BLUE "44"
#define KS_SEQ_B_CYAN "46"
#define KS_SEQ_B_GREEN "42"
#define KS_SEQ_B_MAGEN "45"
#define KS_SEQ_B_RED "41"
#define KS_SEQ_B_WHITE "47"
#define KS_SEQ_B_YELLOW "43"
#define KS_SEQ_CLEARLINE KS_SEQ_ESC KS_SEQ_CLEARLINE_CHAR_STR
#define KS_SEQ_CLEARLINEEND KS_SEQ_ESC KS_SEQ_CLEARLINEEND_CHAR
#define KS_SEQ_CLEARLINEEND_CHAR "K"
#define KS_SEQ_CLEARLINE_CHAR '1'
#define KS_SEQ_CLEARLINE_CHAR_STR "1"
#define KS_SEQ_CLEARSCR KS_SEQ_ESC KS_SEQ_CLEARSCR_CHAR KS_SEQ_HOME
#define KS_SEQ_CLEARSCR_CHAR "2J"
#define KS_SEQ_CLEARSCR_CHAR0 '2'
#define KS_SEQ_CLEARSCR_CHAR1 'J'
#define KS_SEQ_DEFAULT_COLOR KS_SEQ_FWHITE
#define KS_SEQ_END_COLOR "m"	
#define KS_SEQ_ESC "\033["
#define KS_SEQ_FBLACK KS_SEQ_ESC KS_SEQ_F_BLACK KS_SEQ_END_COLOR
#define KS_SEQ_FBLUE KS_SEQ_ESC KS_SEQ_F_BLUE KS_SEQ_END_COLOR
#define KS_SEQ_FCYAN KS_SEQ_ESC KS_SEQ_F_CYAN KS_SEQ_END_COLOR
#define KS_SEQ_FGREEN KS_SEQ_ESC KS_SEQ_F_GREEN KS_SEQ_END_COLOR
#define KS_SEQ_FMAGEN KS_SEQ_ESC KS_SEQ_F_MAGEN KS_SEQ_END_COLOR
#define KS_SEQ_FRED KS_SEQ_ESC KS_SEQ_F_RED KS_SEQ_END_COLOR
#define KS_SEQ_FWHITE KS_SEQ_ESC KS_SEQ_F_WHITE KS_SEQ_END_COLOR
#define KS_SEQ_FYELLOW KS_SEQ_ESC KS_SEQ_F_YELLOW KS_SEQ_END_COLOR
#define KS_SEQ_F_BLACK "30"
#define KS_SEQ_F_BLUE "34"
#define KS_SEQ_F_CYAN "36"
#define KS_SEQ_F_GREEN "32"
#define KS_SEQ_F_MAGEN "35"
#define KS_SEQ_F_RED "31"
#define KS_SEQ_F_WHITE "37"
#define KS_SEQ_F_YELLOW "33"
#define KS_SEQ_HOME KS_SEQ_ESC KS_SEQ_HOME_CHAR_STR
#define KS_SEQ_HOME_CHAR 'H'
#define KS_SEQ_HOME_CHAR_STR "H"
#define KS_VA_NONE "%s", ""

#define __FUNCTION__ (const char *)__func__
#define HAVE_STRINGS_H 1
#define HAVE_SYS_SOCKET_H 1
#define KS_DECLARE(type)			type __stdcall

#define KS_DECLARE_NONSTD(type)		type __cdecl
#define KS_SOCK_INVALID INVALID_SOCKET
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE



#define _XOPEN_SOURCE 600

#define __inline__ __inline
#define snprintf _snprintf
#define strcasecmp(s1, s2) _stricmp(s1, s2)
#define strerror_r(num, buf, size) strerror_s(buf, size, num)
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
