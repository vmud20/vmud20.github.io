


#include<stdarg.h>




















#  define pj_timer_heap_schedule(ht,e,d) \
			pj_timer_heap_schedule_dbg(ht,e,d,"__FILE__","__LINE__")
#  define pj_timer_heap_schedule_w_grp_lock(ht,e,d,id,g) \
	pj_timer_heap_schedule_w_grp_lock_dbg(ht,e,d,id,g,"__FILE__","__LINE__")
#define PJ_CHECK_TRUNC_STR(ret, str, len) \
    if ((ret) >= (len) || (ret) < 0) pj_ansi_strcpy((str) + (len) - 3, "..")

#define pj_stricmp_alnum    pj_stricmp
#   define PJ_POOL_ALIGNMENT    4
#define PJ_POOL_ALLOC_T(pool,type) \
	    ((type*)pj_pool_alloc(pool, sizeof(type)))
#define PJ_POOL_ZALLOC_T(pool,type) \
	    ((type*)pj_pool_zalloc(pool, sizeof(type)))

#  define PJ_CHECK_STACK() pj_thread_check_stack("__FILE__", "__LINE__")

#  define pj_thread_get_stack_info(thread,f,l)	    (*(f)="",*(l)=0)
#  define pj_thread_get_stack_max_usage(thread)	    0

#define PJ_LOG(level,arg)	do { \
				    if (level <= pj_log_get_level()) { \
					pj_log_wrapper_##level(arg); \
				    } \
				} while (0)

#  define pj_log(sender, level, format, marker)
#  define pj_log_add_indent(indent)
#  define pj_log_get_color(level) 0
#  define pj_log_get_decor()	0
#  define pj_log_get_level()	0
#   define pj_log_init()	PJ_SUCCESS
#  define pj_log_pop_indent()
#  define pj_log_push_indent()
#  define pj_log_set_color(level, color)
#  define pj_log_set_decor(decor)
#  define pj_log_set_level(level)
#  define pj_log_set_log_func(func)
    #define pj_log_wrapper_1(arg)	pj_log_1 arg
    #define pj_log_wrapper_2(arg)	pj_log_2 arg
    #define pj_log_wrapper_3(arg)	pj_log_3 arg
    #define pj_log_wrapper_4(arg)	pj_log_4 arg
    #define pj_log_wrapper_5(arg)	pj_log_5 arg
    #define pj_log_wrapper_6(arg)	pj_log_6 arg

#define pj_grp_lock_add_ref_dbg(grp_lock, x, y) pj_grp_lock_add_ref(grp_lock)
#define pj_grp_lock_dec_ref_dbg(grp_lock, x, y) pj_grp_lock_dec_ref(grp_lock)
#define PJ_DECL_LIST_MEMBER(type)                       \
                                    \
                                   type *prev;          \
                                    \
                                   type *next 


#   define PJ_BUILD_ERR(code,msg) { code, msg " (" #code ")" }
#define PJ_EBUG             (PJ_ERRNO_START_STATUS + 8)	
#define PJ_EBUSY            (PJ_ERRNO_START_STATUS + 11)
#define PJ_EEXISTS          (PJ_ERRNO_START_STATUS + 15)
#define PJ_ERR_MSG_SIZE  80
#define PJ_ETIMEDOUT        (PJ_ERRNO_START_STATUS + 9)	
#define PJ_ETOOMANY         (PJ_ERRNO_START_STATUS + 10)
#define PJ_PERROR(level,arg)	do { \
				    pj_perror_wrapper_##level(arg); \
				} while (0)
#   define PJ_RETURN_OS_ERROR(os_code)   (os_code ? \
					    PJ_STATUS_FROM_OS(os_code) : -1)
#   define PJ_STATUS_FROM_OS(e) (e == 0 ? PJ_SUCCESS : e + PJ_ERRNO_START_SYS)
#   define PJ_STATUS_TO_OS(e) (e == 0 ? PJ_SUCCESS : e - PJ_ERRNO_START_SYS)

    #define pj_perror_wrapper_1(arg)	pj_perror_1 arg
    #define pj_perror_wrapper_2(arg)	pj_perror_2 arg
    #define pj_perror_wrapper_3(arg)	pj_perror_3 arg
    #define pj_perror_wrapper_4(arg)	pj_perror_4 arg
    #define pj_perror_wrapper_5(arg)	pj_perror_5 arg
    #define pj_perror_wrapper_6(arg)	pj_perror_6 arg
#   define PJ_ASSERT_ON_FAIL(expr,exec_on_fail)    \
	    do { \
		pj_assert(expr); \
		if (!(expr)) exec_on_fail; \
	    } while (0)
#   define PJ_ASSERT_RETURN(expr,retval)    \
	    do { \
		if (!(expr)) { pj_assert(expr); return retval; } \
	    } while (0)

#   define pj_assert(expr)   assert(expr)
#  define OSERR_EAFNOSUPPORT   WSAEAFNOSUPPORT
#  define OSERR_ECONNRESET     WSAECONNRESET
#  define OSERR_EINPROGRESS    WSAEINPROGRESS
#  define OSERR_ENOPROTOOPT    WSAENOPROTOOPT
#  define OSERR_ENOTCONN       WSAENOTCONN
#  define OSERR_EWOULDBLOCK    WSAEWOULDBLOCK
#   define PJ_SOCKADDR_RESET_LEN(addr)   (((pj_addr_hdr*)(addr))->sa_zero_len=0)
#   define PJ_SOCKADDR_SET_LEN(addr,len) (((pj_addr_hdr*)(addr))->sa_zero_len=(len))
#   define PJ_SOCK_HAS_GETADDRINFO  1



