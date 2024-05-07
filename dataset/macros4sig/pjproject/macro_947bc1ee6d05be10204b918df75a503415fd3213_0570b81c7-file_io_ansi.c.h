#include<errno.h>




#include<stdarg.h>
#include<stdio.h>


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
#define PJ_ASSERT_ON_FAIL(expr,exec_on_fail)    \
	    do { \
		pj_assert(expr); \
		if (!(expr)) exec_on_fail; \
	    } while (0)
#define PJ_ASSERT_RETURN(expr,retval)    \
	    do { \
		if (!(expr)) { pj_assert(expr); return retval; } \
	    } while (0)

#   define pj_assert(expr)   assert(expr)

