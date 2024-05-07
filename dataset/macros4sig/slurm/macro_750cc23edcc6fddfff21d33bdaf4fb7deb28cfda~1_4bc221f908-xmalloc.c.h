#include<string.h>
#include<stdbool.h>
#include<pthread.h>

#include<stddef.h>
#include<errno.h>
#include<stdio.h>
#include<syslog.h>



#include<sys/types.h>
#include<stdlib.h>
#define XMALLOC_MAGIC 0x42

#define try_xmalloc(__sz) \
	slurm_try_xmalloc(__sz, "__FILE__", "__LINE__", __func__)
#define try_xrealloc(__p, __sz) \
	slurm_try_xrealloc((void **)&(__p), __sz, \
                           "__FILE__", "__LINE__",  __func__)
#define xfree(__p) \
	slurm_xfree((void **)&(__p), "__FILE__", "__LINE__", __func__)
#define xmalloc(__sz) \
	slurm_xmalloc (__sz, true, "__FILE__", "__LINE__", __func__)
#define xmalloc_nz(__sz) \
	slurm_xmalloc (__sz, false, "__FILE__", "__LINE__", __func__)
#define xrealloc(__p, __sz) \
        slurm_xrealloc((void **)&(__p), __sz, true, \
                       "__FILE__", "__LINE__", __func__)
#define xrealloc_nz(__p, __sz) \
        slurm_xrealloc((void **)&(__p), __sz, false, \
                       "__FILE__", "__LINE__", __func__)
#define xsize(__p) \
	slurm_xsize((void *)__p, "__FILE__", "__LINE__", __func__)
#define FUZZY_EPSILON 0.00001
# define HTON_int64(x)	  ((int64_t)  (x))
# define HTON_uint64(x)	  ((uint64_t) (x))
#  define MAX(a,b) ((a) > (b) ? (a) : (b))
#  define MIN(a,b) ((a) < (b) ? (a) : (b))
# define NTOH_int64(x)	  ((int64_t)  (x))
# define NTOH_uint64(x)	  ((uint64_t) (x))
#define SLURM_DIFFTIME(a,b) ((a) - (b))
#  define UINT64_SWAP_LE_BE(val)      ((uint64_t) (                           \
        (((uint64_t) (val) &                                                  \
          (uint64_t) (0x00000000000000ffU)) << 56) |                          \
        (((uint64_t) (val) &                                                  \
          (uint64_t) (0x000000000000ff00U)) << 40) |                          \
        (((uint64_t) (val) &                                                  \
          (uint64_t) (0x0000000000ff0000U)) << 24) |                          \
        (((uint64_t) (val) &                                                  \
          (uint64_t) (0x00000000ff000000U)) <<  8) |                          \
	(((uint64_t) (val)                  >>  8) &                          \
	  (uint64_t) (0x00000000ff000000U))        |                          \
	(((uint64_t) (val)                  >> 24) &                          \
	  (uint64_t) (0x0000000000ff0000U))        |                          \
	(((uint64_t) (val)                  >> 40) &                          \
	  (uint64_t) (0x000000000000ff00U))        |                          \
	(((uint64_t) (val)                  >> 56) &                          \
	  (uint64_t) (0x00000000000000ffU)) ))

#  define __STRING(arg)		#arg
#define fuzzy_equal(v1, v2) ((((v1)-(v2)) > -FUZZY_EPSILON) && (((v1)-(v2)) < FUZZY_EPSILON))
#define slurm_atoul(str) strtoul(str, NULL, 10)
#define slurm_atoull(str) strtoull(str, NULL, 10)
#define slurm_attr_destroy(attr)					\
	do {								\
		if (pthread_attr_destroy(attr))				\
			error("pthread_attr_destroy failed, "		\
				"possible memory leak!: %m");		\
	} while (0)
#  define slurm_attr_init(attr)						\
	do {								\
		if (pthread_attr_init(attr))				\
			fatal("pthread_attr_init: %m");			\
				\
		if (pthread_attr_setscope(attr, PTHREAD_SCOPE_SYSTEM))	\
			error("pthread_attr_setscope: %m");		\
		if (pthread_attr_setstacksize(attr, 1024*1024))		\
			error("pthread_attr_setstacksize: %m");		\
	 } while (0)
#define slurm_cond_broadcast(cond)					\
	do {								\
		int err = pthread_cond_broadcast(cond);			\
		if (err) {						\
			error("%s:%d %s: pthread_cond_broadcast(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_destroy(cond)					\
	do {								\
		int err = pthread_cond_destroy(cond);			\
		if (err) {						\
			error("%s:%d %s: pthread_cond_destroy(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_init(cond, cont_attr)				\
	do {								\
		int err = pthread_cond_init(cond, cont_attr);		\
		if (err) {						\
			fatal("%s:%d %s: pthread_cond_init(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
			abort();					\
		}							\
	} while (0)
#define slurm_cond_signal(cond)					\
	do {								\
		int err = pthread_cond_signal(cond);			\
		if (err) {						\
			error("%s:%d %s: pthread_cond_signal(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_timedwait(cond, mutex, abstime)			\
	do {								\
		int err = pthread_cond_timedwait(cond, mutex, abstime);	\
		if (err && (err != ETIMEDOUT)) {			\
			error("%s:%d %s: pthread_cond_timedwait(): %s",	\
				"__FILE__", "__LINE__", __func__,		\
				strerror(err));				\
		}							\
	} while (0)
#define slurm_cond_wait(cond, mutex)					\
	do {								\
		int err = pthread_cond_wait(cond, mutex);		\
		if (err) {						\
			error("%s:%d %s: pthread_cond_wait(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_mutex_destroy(mutex)					\
	do {								\
		int err = pthread_mutex_destroy(mutex);			\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_mutex_destroy(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
			abort();					\
		}							\
	} while (0)
#define slurm_mutex_init(mutex)						\
	do {								\
		int err = pthread_mutex_init(mutex, NULL);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_mutex_init(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
			abort();					\
		}							\
	} while (0)
#define slurm_mutex_lock(mutex)					\
	do {								\
		int err = pthread_mutex_lock(mutex);			\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_mutex_lock(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
			abort();					\
		}							\
	} while (0)
#define slurm_mutex_unlock(mutex)					\
	do {								\
		int err = pthread_mutex_unlock(mutex);			\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_mutex_unlock(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
			abort();					\
		}							\
	} while (0)
#define slurm_strftime(s, max, format, tm)				\
do {									\
	if (max > 0) {							\
		char tmp_string[(max<256?256:max+1)];			\
		if (strftime(tmp_string, sizeof(tmp_string), format, tm) == 0) \
			memset(tmp_string, '#', max);			\
		tmp_string[max-1] = 0;					\
		strlcpy(s, tmp_string, max);				\
	}								\
} while (0)
#define slurm_thread_create(id, func, arg)				\
	do {								\
		pthread_attr_t attr;					\
		slurm_attr_init(&attr);					\
		if (pthread_create(id, &attr, func, arg))		\
			fatal("%s: pthread_create error %m", __func__);	\
		slurm_attr_destroy(&attr);				\
	} while (0)
#define slurm_thread_create_detached(id, func, arg)			\
	do {								\
		pthread_t *id_ptr, id_local;				\
		pthread_attr_t attr;					\
		id_ptr = (id != (pthread_t *) NULL) ? id : &id_local;	\
		slurm_attr_init(&attr);					\
		if (pthread_attr_setdetachstate(&attr,			\
						PTHREAD_CREATE_DETACHED)) \
			fatal("%s: pthread_attr_setdetachstate %m",	\
			      __func__);				\
		if (pthread_create(id_ptr, &attr, func, arg))		\
			fatal("%s: pthread_create error %m", __func__);	\
		slurm_attr_destroy(&attr);				\
	} while (0)
#    define strong_alias(name, aliasname) \
     extern __typeof (name) aliasname __attribute ((alias (#name)))



