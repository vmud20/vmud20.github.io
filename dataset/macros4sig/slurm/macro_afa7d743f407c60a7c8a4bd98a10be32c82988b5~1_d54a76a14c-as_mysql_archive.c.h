#include<stdbool.h>
#include<stdio.h>




#include<unistd.h>


#include<sys/types.h>
#include<stddef.h>
#include<sys/ioctl.h>


#include<netinet/in.h>
#include<sys/socket.h>
#include<stdlib.h>

#include<pthread.h>

#include<syslog.h>
#include<sys/time.h>



#include<sys/wait.h>


#include<netdb.h>
#include<dirent.h>

#include<errno.h>
#include<pwd.h>
#include<stdint.h>
#include<sys/utsname.h>

#include<string.h>







#include<time.h>




#include<inttypes.h>

#include<fcntl.h>

#include<sys/stat.h>

#include<stdarg.h>
#include<assert.h>

#define DBD_NODE_STATE_DOWN  1
#define DBD_NODE_STATE_UP    2


#define SLURM_ERROR    -1
#define SLURM_FAILURE  -1
#define SLURM_PROTOCOL_ERROR   -1
#define SLURM_PROTOCOL_SUCCESS  0
#define SLURM_SOCKET_ERROR     -1
#define SLURM_SUCCESS   0

#define slurm_seterrno_ret(errnum) do { \
	slurm_seterrno(errnum);         \
	return (errnum ? -1 : 0);       \
	} while (0)

#define CLUSTER_FED_STATE_BASE       0x000f
#define CLUSTER_FED_STATE_DRAIN      0x0010 
#define CLUSTER_FED_STATE_FLAGS      0xfff0
#define CLUSTER_FED_STATE_REMOVE     0x0020 
#define CLUSTER_FLAG_AIX    0x00000040 
#define CLUSTER_FLAG_BG     0x00000001 
#define CLUSTER_FLAG_BGL    0x00000002 
#define CLUSTER_FLAG_BGP    0x00000004 
#define CLUSTER_FLAG_BGQ    0x00000008 
#define CLUSTER_FLAG_CRAY   0x00000500 
#define CLUSTER_FLAG_CRAYXT 0x00000100 
#define CLUSTER_FLAG_CRAY_A 0x00000100 
#define CLUSTER_FLAG_CRAY_N 0x00000400 
#define CLUSTER_FLAG_FE     0x00000200 
#define CLUSTER_FLAG_FED    0x00000800 
#define CLUSTER_FLAG_MULTSD 0x00000080 
#define CLUSTER_FLAG_SC     0x00000010 
#define CLUSTER_FLAG_XCPU   0x00000020 
#define JOBCOND_FLAG_DUP      0x00000001 
#define JOBCOND_FLAG_NO_STEP  0x00000002 
#define JOBCOND_FLAG_NO_TRUNC 0x00000004 
#define JOBCOND_FLAG_NO_WHOLE_HETJOB 0x00000020 
#define JOBCOND_FLAG_RUNAWAY  0x00000008 
#define JOBCOND_FLAG_WHOLE_HETJOB    0x00000010 
#define SLURMDB_CLASSIFIED_FLAG 0x0100
#define SLURMDB_CLASS_BASE      0x00ff
#define SLURMDB_FS_USE_PARENT 0x7FFFFFFF
#define SLURMDB_MODIFY_NO_WAIT       0x00000001
#define SLURMDB_PURGE_ARCHIVE 0x00080000   
#define SLURMDB_PURGE_BASE    0x0000ffff   
#define SLURMDB_PURGE_DAYS    0x00020000   
#define SLURMDB_PURGE_FLAGS   0xffff0000   
#define SLURMDB_PURGE_HOURS   0x00010000   
#define SLURMDB_PURGE_MONTHS  0x00040000   

#  define __slurmdb_cluster_rec_t_defined
#define SLURMDB_PURGE_ARCHIVE_SET(_X) \
	(_X != NO_VAL && _X & SLURMDB_PURGE_ARCHIVE)
#define SLURMDB_PURGE_GET_UNITS(_X) \
	(_X & SLURMDB_PURGE_BASE)
#define SLURMDB_PURGE_IN_DAYS(_X) \
	(_X != NO_VAL && _X & SLURMDB_PURGE_DAYS)
#define SLURMDB_PURGE_IN_HOURS(_X) \
	(_X != NO_VAL && _X & SLURMDB_PURGE_HOURS)
#define SLURMDB_PURGE_IN_MONTHS(_X) \
	(_X != NO_VAL && _X & SLURMDB_PURGE_MONTHS)
#define TRES_STR_CONVERT_UNITS    0x00000080 
#define TRES_STR_FLAG_ALLOW_REAL  0x00000800 
#define TRES_STR_FLAG_BYTES       0x00000800 
#define TRES_STR_FLAG_COMMA1      0x00000020 
#define TRES_STR_FLAG_MAX         0x00000200 
#define TRES_STR_FLAG_MIN         0x00000400 
#define TRES_STR_FLAG_NONE        0x00000000 
#define TRES_STR_FLAG_NO_NULL     0x00000040 
#define TRES_STR_FLAG_ONLY_CONCAT 0x00000001 
#define TRES_STR_FLAG_REMOVE      0x00000004 
#define TRES_STR_FLAG_REPLACE     0x00000002 
#define TRES_STR_FLAG_SIMPLE      0x00000010 
#define TRES_STR_FLAG_SORT_ID     0x00000008 
#define TRES_STR_FLAG_SUM         0x00000100 

#define ADMIN_SET_LIMIT 0xffff
#define CONTROL_TIMEOUT 30	
#define FEATURE_OP_AND  1
#define FEATURE_OP_END  4		
#define FEATURE_OP_OR   0
#define FEATURE_OP_XAND 3
#define FEATURE_OP_XOR  2
#define FRONT_END_MAGIC 0xfe9b82fe
#define MAX_BATCH_REQUEUE 5
#define MAX_SERVER_THREADS 256
#define PART_MAGIC 0xaefe8495
#define PERIODIC_NODE_ACCT 300
#define PURGE_JOB_INTERVAL 60
#define STEP_FLAG 0xbbbb
#define STEP_MAGIC 0xcafecafe
#define TRIGGER_INTERVAL 15

#define XMALLOC_MAGIC 0x42

#define try_xmalloc(__sz) \
	slurm_try_xmalloc((uint64_t) __sz, "__FILE__", "__LINE__", __func__)
#define try_xrealloc(__p, __sz) \
	slurm_try_xrealloc((void **)&(__p), __sz, \
                           "__FILE__", "__LINE__",  __func__)
#define xfree(__p) \
	slurm_xfree((void **)&(__p), "__FILE__", "__LINE__", __func__)
#define xmalloc(__sz) \
	slurm_xmalloc ((uint64_t) __sz, true, "__FILE__", "__LINE__", __func__)
#define xmalloc_nz(__sz) \
	slurm_xmalloc ((uint64_t) __sz, false, "__FILE__", "__LINE__", __func__)
#define xrealloc(__p, __sz) \
        slurm_xrealloc((void **)&(__p), __sz, true, \
                       "__FILE__", "__LINE__", __func__)
#define xrealloc_nz(__p, __sz) \
        slurm_xrealloc((void **)&(__p), __sz, false, \
                       "__FILE__", "__LINE__", __func__)
#define xsize(__p) \
	slurm_xsize((void *)__p, "__FILE__", "__LINE__", __func__)
#define END_TIMER2(from) gettimeofday(&tv2, NULL); \
	slurm_diff_tv_str(&tv1, &tv2, tv_str, 20, from, 0, &delta_t)
#define END_TIMER3(from, limit) gettimeofday(&tv2, NULL); \
	slurm_diff_tv_str(&tv1, &tv2, tv_str, 20, from, limit, &delta_t)
#define TIME_STR 	tv_str


#  define __switch_jobinfo_t_defined
#  define __switch_node_info_t_defined


#define MAX_MSG_LEN 1024
#define SLURM_IO_ALLSTDIN 3
#define SLURM_IO_CONNECTION_TEST 4
#define SLURM_IO_KEY_SIZE 8
#define SLURM_IO_STDERR 2
#define SLURM_IO_STDIN 0
#define SLURM_IO_STDOUT 1

#define io_hdr_packed_size() g_io_hdr_size

#define BUF_MAGIC 0x42554545
#define BUF_SIZE (16 * 1024)
#define FLOAT_MULT 1000000
#define FREE_NULL_BUFFER(_X)		\
	do {				\
		if (_X) free_buf (_X);	\
		_X	= NULL; 	\
	} while (0)
#define MAX_BUF_SIZE ((uint32_t) 0xffff0000)	
#define REASONABLE_BUF_SIZE ((uint32_t) 0xbfff4000) 

#define get_buf_data(__buf)		(__buf->head)
#define get_buf_offset(__buf)		(__buf->processed)
#define pack_bit_fmt(bitmap,buf) do {			\
	assert(buf->magic == BUF_MAGIC);		\
	if (bitmap) {					\
		char _tmp_str[0xfffe];			\
		uint32_t _size;				\
		bit_fmt(_tmp_str,0xfffe,bitmap);	\
		_size = strlen(_tmp_str)+1;		\
		packmem(_tmp_str,_size,buf);		\
	} else						\
		packmem(NULL,(uint32_t)0,buf);		\
} while (0)
#define pack_bit_str_hex(bitmap,buf) do {		\
	assert(buf->magic == BUF_MAGIC);		\
	if (bitmap) {					\
		char *_tmp_str;				\
		uint32_t _size;				\
		_tmp_str = bit_fmt_hexmask(bitmap);	\
		_size = bit_size(bitmap);               \
		pack32(_size, buf);              	\
		_size = strlen(_tmp_str)+1;		\
		packmem(_tmp_str,_size,buf);	        \
		xfree(_tmp_str);			\
	} else						\
		pack32(NO_VAL, buf);                 	\
} while (0)
#define packnull(buf) do { \
	assert(buf != NULL); \
	assert(buf->magic == BUF_MAGIC); \
	packmem(NULL, 0, buf); \
} while (0)
#define packstr(str,buf) do {				\
	uint32_t _size = 0;				\
	if((char *)str != NULL)				\
		_size = (uint32_t)strlen(str)+1;	\
        assert(_size == 0 || str != NULL);             	\
	assert(_size <= 0xffffffff);			\
	assert(buf->magic == BUF_MAGIC);		\
	packmem(str,(uint32_t)_size,buf);		\
} while (0)
#define remaining_buf(__buf)		(__buf->size - __buf->processed)
#define safe_unpack16(valp,buf) do {			\
	assert(sizeof(*valp) == sizeof(uint16_t)); 	\
	assert(buf->magic == BUF_MAGIC);		\
        if (unpack16(valp,buf))				\
		goto unpack_error;			\
} while (0)
#define safe_unpack16_array(valp,size_valp,buf) do {    \
        assert(sizeof(*size_valp) == sizeof(uint32_t)); \
        assert(buf->magic == BUF_MAGIC);                \
        if (unpack16_array(valp,size_valp,buf))         \
                goto unpack_error;                      \
} while (0)
#define safe_unpack32(valp,buf) do {			\
	assert(sizeof(*valp) == sizeof(uint32_t));      \
	assert(buf->magic == BUF_MAGIC);		\
        if (unpack32(valp,buf))				\
		goto unpack_error;			\
} while (0)
#define safe_unpack32_array(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpack32_array(valp,size_valp,buf))		\
		goto unpack_error;			\
} while (0)
#define safe_unpack64(valp,buf) do {			\
	assert(sizeof(*valp) == sizeof(uint64_t));      \
	assert(buf->magic == BUF_MAGIC);		\
        if (unpack64(valp,buf))				\
		goto unpack_error;			\
} while (0)
#define safe_unpack64_array(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpack64_array(valp,size_valp,buf))		\
		goto unpack_error;			\
} while (0)
#define safe_unpack64_array_from_32(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpack64_array_from_32(valp,size_valp,buf))	\
		goto unpack_error;			\
} while (0)
#define safe_unpack8(valp,buf) do {			\
	assert(sizeof(*valp) == sizeof(uint8_t)); 	\
	assert(buf->magic == BUF_MAGIC);		\
        if (unpack8(valp,buf))				\
		goto unpack_error;			\
} while (0)
#define safe_unpack_time(valp,buf) do {			\
	assert(sizeof(*valp) == sizeof(time_t));	\
	assert(buf->magic == BUF_MAGIC);		\
        if (unpack_time(valp,buf))			\
		goto unpack_error;			\
} while (0)
#define safe_unpackdouble(valp,buf) do {		\
	assert(sizeof(*valp) == sizeof(double));        \
	assert(buf->magic == BUF_MAGIC);		\
        if (unpackdouble(valp,buf))			\
		goto unpack_error;			\
} while (0)
#define safe_unpackdouble_array(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackdouble_array(valp,size_valp,buf))	\
		goto unpack_error;			\
} while (0)
#define safe_unpacklongdouble(valp,buf) do {		\
	assert(sizeof(*valp) == sizeof(long double));	\
	assert(buf->magic == BUF_MAGIC);		\
        if (unpacklongdouble(valp,buf))			\
		goto unpack_error;			\
} while (0)
#define safe_unpacklongdouble_array(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpacklongdouble_array(valp,size_valp,buf))	\
		goto unpack_error;			\
} while (0)
#define safe_unpackmem(valp,size_valp,buf) do {		\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackmem(valp,size_valp,buf))		\
		goto unpack_error;			\
} while (0)
#define safe_unpackmem_array(valp,size,buf) do {	\
	assert(valp != NULL);				\
	assert(sizeof(size) == sizeof(uint32_t)); 	\
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackmem_array(valp,size,buf))		\
		goto unpack_error;			\
} while (0)
#define safe_unpackmem_malloc(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackmem_malloc(valp,size_valp,buf))	\
		goto unpack_error;			\
} while (0)
#define safe_unpackmem_ptr(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackmem_ptr(valp,size_valp,buf))		\
		goto unpack_error;			\
} while (0)
#define safe_unpackmem_xmalloc(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackmem_xmalloc(valp,size_valp,buf))	\
		goto unpack_error;			\
} while (0)
#define safe_unpackstr_array(valp,size_valp,buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t)); \
	assert(buf->magic == BUF_MAGIC);		\
	if (unpackstr_array(valp,size_valp,buf))	\
		goto unpack_error;			\
} while (0)
#define safe_unpackstr_xmalloc(valp, size_valp, buf) do {	\
	assert(sizeof(*size_valp) == sizeof(uint32_t));        	\
	assert(buf->magic == BUF_MAGIC);		        \
	if (unpackstr_xmalloc_chooser(valp, size_valp, buf))    \
		goto unpack_error;		       		\
} while (0)
#define set_buf_offset(__buf,__val)	(__buf->processed = __val)
#define size_buf(__buf)			(__buf->size)
#define unpack_bit_str_hex(bitmap,buf) do {				\
	char *tmp_str = NULL;						\
	uint32_t _size, _tmp_uint32;					\
	assert(*bitmap == NULL);					\
	assert(buf->magic == BUF_MAGIC);				\
	safe_unpack32(&_size, buf);					\
	if (_size != NO_VAL) {						\
		safe_unpackstr_xmalloc(&tmp_str, &_tmp_uint32, buf);	\
		*bitmap = bit_alloc(_size);				\
		bit_unfmt_hexmask(*bitmap, tmp_str);			\
		xfree(tmp_str);						\
	} else								\
		*bitmap = NULL;						\
} while (0)
#define unpack_bit_str_hex_as_inx(inx, buf) do {	\
	bitstr_t *b = NULL;				\
	unpack_bit_str_hex(&b, buf);			\
	*inx = bitstr2inx(b);				\
	FREE_NULL_BITMAP(b);				\
} while (0)
#define BITSTR_MAGIC 		0x42434445
#define BITSTR_MAXVAL           0xffffffffffffffff
#define BITSTR_OVERHEAD 	2
#define BITSTR_SHIFT 		BITSTR_SHIFT_WORD64
#define FREE_NULL_BITMAP(_X)		\
	do {				\
		if (_X) bit_free (_X);	\
		_X	= NULL; 	\
	} while (0)
#  define __bitstr_datatypes_defined
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
		int err = pthread_attr_destroy(attr);			\
		if (err) {						\
			errno = err;					\
			error("pthread_attr_destroy failed, "		\
				"possible memory leak!: %m");		\
		}							\
	} while (0)
#  define slurm_attr_init(attr)						\
	do {								\
		int err = pthread_attr_init(attr);			\
		if (err) {						\
			errno = err;					\
			fatal("pthread_attr_init: %m");			\
		}							\
				\
		err = pthread_attr_setscope(attr, PTHREAD_SCOPE_SYSTEM);\
		if (err) {						\
			errno = err;					\
			error("pthread_attr_setscope: %m");		\
		}							\
		err = pthread_attr_setstacksize(attr, 1024*1024);	\
		if (err) {						\
			errno = err;					\
			error("pthread_attr_setstacksize: %m");		\
		}							\
	 } while (0)
#define slurm_cond_broadcast(cond)					\
	do {								\
		int err = pthread_cond_broadcast(cond);			\
		if (err) {						\
			errno = err;					\
			error("%s:%d %s: pthread_cond_broadcast(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_destroy(cond)					\
	do {								\
		int err = pthread_cond_destroy(cond);			\
		if (err) {						\
			errno = err;					\
			error("%s:%d %s: pthread_cond_destroy(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_init(cond, cont_attr)				\
	do {								\
		int err = pthread_cond_init(cond, cont_attr);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_cond_init(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
			abort();					\
		}							\
	} while (0)
#define slurm_cond_signal(cond)					\
	do {								\
		int err = pthread_cond_signal(cond);			\
		if (err) {						\
			errno = err;					\
			error("%s:%d %s: pthread_cond_signal(): %m",	\
				"__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_timedwait(cond, mutex, abstime)			\
	do {								\
		int err = pthread_cond_timedwait(cond, mutex, abstime);	\
		if (err && (err != ETIMEDOUT)) {			\
			errno = err;					\
			error("%s:%d %s: pthread_cond_timedwait(): %m",	\
			      "__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_cond_wait(cond, mutex)					\
	do {								\
		int err = pthread_cond_wait(cond, mutex);		\
		if (err) {						\
			errno = err;					\
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
#define slurm_rwlock_destroy(rwlock)					\
	do {								\
		int err = pthread_rwlock_destroy(rwlock);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_rwlock_destroy(): %m",	\
			      "__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_rwlock_init(rwlock)					\
	do {								\
		int err = pthread_rwlock_init(rwlock, NULL);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_rwlock_init(): %m",	\
			      "__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_rwlock_rdlock(rwlock)					\
	do {								\
		int err = pthread_rwlock_rdlock(rwlock);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_rwlock_rdlock(): %m",	\
			      "__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_rwlock_tryrdlock(rwlock) pthread_rwlock_tryrdlock(rwlock)
#define slurm_rwlock_trywrlock(rwlock) pthread_rwlock_trywrlock(rwlock)
#define slurm_rwlock_unlock(rwlock)					\
	do {								\
		int err = pthread_rwlock_unlock(rwlock);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_rwlock_unlock(): %m",	\
			      "__FILE__", "__LINE__", __func__);		\
		}							\
	} while (0)
#define slurm_rwlock_wrlock(rwlock)					\
	do {								\
		int err = pthread_rwlock_wrlock(rwlock);		\
		if (err) {						\
			errno = err;					\
			fatal("%s:%d %s: pthread_rwlock_wrlock(): %m",	\
			      "__FILE__", "__LINE__", __func__);		\
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
		int err;						\
		slurm_attr_init(&attr);					\
		err = pthread_create(id, &attr, func, arg);		\
		if (err) {						\
			errno = err;					\
			fatal("%s: pthread_create error %m", __func__);	\
		}							\
		slurm_attr_destroy(&attr);				\
	} while (0)
#define slurm_thread_create_detached(id, func, arg)			\
	do {								\
		pthread_t *id_ptr, id_local;				\
		pthread_attr_t attr;					\
		int err;						\
		id_ptr = (id != (pthread_t *) NULL) ? id : &id_local;	\
		slurm_attr_init(&attr);					\
		err = pthread_attr_setdetachstate(&attr,		\
						  PTHREAD_CREATE_DETACHED); \
		if (err) {						\
			errno = err;					\
			fatal("%s: pthread_attr_setdetachstate %m",	\
			      __func__);				\
		}							\
		err = pthread_create(id_ptr, &attr, func, arg);		\
		if (err) {						\
			errno = err;					\
			fatal("%s: pthread_create error %m", __func__);	\
		}							\
		slurm_attr_destroy(&attr);				\
	} while (0)
#    define strong_alias(name, aliasname) \
     extern __typeof (name) aliasname __attribute ((alias (#name)))

#define FORWARD_INIT 0xfffe
#define INFO_LINE(fmt, ...) \
	info("%s (%s:%d) "fmt, __func__, THIS_FILE, "__LINE__", ##__VA_ARGS__);
#define IS_JOB_CANCELLED(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_CANCELLED)
#define IS_JOB_COMPLETE(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_COMPLETE)
#define IS_JOB_COMPLETED(_X)		\
	(IS_JOB_FINISHED(_X) && ((_X->job_state & JOB_COMPLETING) == 0))
#define IS_JOB_COMPLETING(_X)		\
	(_X->job_state & JOB_COMPLETING)
#define IS_JOB_CONFIGURING(_X)		\
	(_X->job_state & JOB_CONFIGURING)
#define IS_JOB_DEADLINE(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_DEADLINE)
#define IS_JOB_FAILED(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_FAILED)
#define IS_JOB_FED_REQUEUED(_X)		\
	(_X->job_state & JOB_REQUEUE_FED)
#define IS_JOB_FINISHED(_X)		\
	((_X->job_state & JOB_STATE_BASE) >  JOB_SUSPENDED)
#define IS_JOB_NODE_FAILED(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_NODE_FAIL)
#define IS_JOB_OOM(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_OOM)
#define IS_JOB_PENDING(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_PENDING)
#define IS_JOB_POWER_UP_NODE(_X)	\
	(_X->job_state & JOB_POWER_UP_NODE)
#define IS_JOB_REQUEUED(_X)		\
	(_X->job_state & JOB_REQUEUE)
#define IS_JOB_RESIZING(_X)		\
	(_X->job_state & JOB_RESIZING)
#define IS_JOB_REVOKED(_X)		\
	(_X->job_state & JOB_REVOKED)
#define IS_JOB_RUNNING(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_RUNNING)
#define IS_JOB_SIGNALING(_X)		\
	(_X->job_state & JOB_SIGNALING)
#define IS_JOB_STAGE_OUT(_X)		\
	(_X->job_state & JOB_STAGE_OUT)
#define IS_JOB_STARTED(_X)		\
	((_X->job_state & JOB_STATE_BASE) >  JOB_PENDING)
#define IS_JOB_SUSPENDED(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_SUSPENDED)
#define IS_JOB_TIMEOUT(_X)		\
	((_X->job_state & JOB_STATE_BASE) == JOB_TIMEOUT)
#define IS_JOB_UPDATE_DB(_X)		\
	(_X->job_state & JOB_UPDATE_DB)
#define IS_NODE_ALLOCATED(_X)		\
	((_X->node_state & NODE_STATE_BASE) == NODE_STATE_ALLOCATED)
#define IS_NODE_CLOUD(_X)		\
	(_X->node_state & NODE_STATE_CLOUD)
#define IS_NODE_COMPLETING(_X)	\
	(_X->node_state & NODE_STATE_COMPLETING)
#define IS_NODE_DOWN(_X)		\
	((_X->node_state & NODE_STATE_BASE) == NODE_STATE_DOWN)
#define IS_NODE_DRAIN(_X)		\
	(_X->node_state & NODE_STATE_DRAIN)
#define IS_NODE_DRAINED(_X)		\
	(IS_NODE_DRAIN(_X) && !IS_NODE_DRAINING(_X))
#define IS_NODE_DRAINING(_X)		\
	((_X->node_state & NODE_STATE_DRAIN) \
	 && (IS_NODE_ALLOCATED(_X) || IS_NODE_MIXED(_X)))
#define IS_NODE_FAIL(_X)		\
	(_X->node_state & NODE_STATE_FAIL)
#define IS_NODE_FUTURE(_X)		\
	((_X->node_state & NODE_STATE_BASE) == NODE_STATE_FUTURE)
#define IS_NODE_IDLE(_X)		\
	((_X->node_state & NODE_STATE_BASE) == NODE_STATE_IDLE)
#define IS_NODE_MAINT(_X)		\
	(_X->node_state & NODE_STATE_MAINT)
#define IS_NODE_MIXED(_X)		\
	((_X->node_state & NODE_STATE_BASE) == NODE_STATE_MIXED)
#define IS_NODE_NO_RESPOND(_X)		\
	(_X->node_state & NODE_STATE_NO_RESPOND)
#define IS_NODE_POWER_SAVE(_X)		\
	(_X->node_state & NODE_STATE_POWER_SAVE)
#define IS_NODE_POWER_UP(_X)		\
	(_X->node_state & NODE_STATE_POWER_UP)
#define IS_NODE_REBOOT(_X)		\
	(_X->node_state & NODE_STATE_REBOOT)
#define IS_NODE_RUNNING_JOB(_X)		\
	(_X->comp_job_cnt || _X->run_job_cnt || _X->sus_job_cnt)
#define IS_NODE_UNKNOWN(_X)		\
	((_X->node_state & NODE_STATE_BASE) == NODE_STATE_UNKNOWN)
#define LAUNCH_NO_ALLOC 	0x00000040
#define LAYOUTS_DUMP_NOLAYOUT 0x00000001
#define LAYOUTS_DUMP_STATE    0x10000000
#define MAX_SLURM_NAME 64
#define REBOOT_FLAGS_ASAP 0x0001	
#define SLURMD_REG_FLAG_RESP     0x0002
#define SLURMD_REG_FLAG_STARTUP  0x0001
#define THIS_FILE ((strrchr("__FILE__", '/') ?: "__FILE__" - 1) + 1)
#define YEAR_MINUTES (365 * 24 * 60)
#define YEAR_SECONDS (365 * 24 * 60 * 60)

#define safe_read(fd, buf, size) do {					\
		int remaining = size;					\
		char *ptr = (char *) buf;				\
		int rc;							\
		while (remaining > 0) {					\
			rc = read(fd, ptr, remaining);			\
			if ((rc == 0) && (remaining == size)) {		\
				debug("%s:%d: %s: safe_read EOF",	\
				      "__FILE__", "__LINE__", __func__); \
				goto rwfail;				\
			} else if (rc == 0) {				\
				debug("%s:%d: %s: safe_read (%d of %d) EOF", \
				      "__FILE__", "__LINE__", __func__, \
				      remaining, (int)size);		\
				goto rwfail;				\
			} else if (rc < 0) {				\
				debug("%s:%d: %s: safe_read (%d of %d) failed: %m", \
				      "__FILE__", "__LINE__", __func__, \
				      remaining, (int)size);		\
				goto rwfail;				\
			} else {					\
				ptr += rc;				\
				remaining -= rc;			\
				if (remaining > 0)			\
					debug3("%s:%d: %s: safe_read (%d of %d) partial read", \
					       "__FILE__", "__LINE__", __func__, \
					       remaining, (int)size);	\
			}						\
		}							\
	} while (0)
#define safe_write(fd, buf, size) do {					\
		int remaining = size;					\
		char *ptr = (char *) buf;				\
		int rc;							\
		while(remaining > 0) {					\
			rc = write(fd, ptr, remaining);			\
 			if (rc < 0) {					\
				debug("%s:%d: %s: safe_write (%d of %d) failed: %m", \
				      "__FILE__", "__LINE__", __func__, \
				      remaining, (int)size);		\
				goto rwfail;				\
			} else {					\
				ptr += rc;				\
				remaining -= rc;			\
				if (remaining > 0)			\
					debug3("%s:%d: %s: safe_write (%d of %d) partial write", \
					       "__FILE__", "__LINE__", __func__, \
					       remaining, (int)size);	\
			}						\
		}							\
	} while (0)
#  define xassert(expr)	((void) (0))


#define FREE_NULL_HOSTLIST(_X)			\
	do {					\
		if (_X) hostlist_destroy (_X);	\
		_X	= NULL; 		\
	} while (0)
#define HIGHEST_BASE 36
#  define HIGHEST_DIMENSIONS 5
#define HOSTLIST_BASE 36
#define MAX_PREFIX_CNT 64*1024

#  define __hostlist_t_defined
#define hostlist_get_base(_dimensions) ((_dimensions) > 1 ? 36 : 10)
#define hostlist_is_empty(__hl) ( hostlist_count(__hl) == 0 )
#define PERSIST_FLAG_ALREADY_INITED 0x0004
#define PERSIST_FLAG_DBD            0x0001
#define PERSIST_FLAG_NONE           0x0000
#define PERSIST_FLAG_P_USER_CASE    0x0008
#define PERSIST_FLAG_RECONNECT      0x0002
#define PERSIST_FLAG_SUPPRESS_ERR   0x0010

#define SLURMDBD_CONNECTION     0x0002
#define SLURM_17_02_PROTOCOL_VERSION ((31 << 8) | 0)
#define SLURM_17_11_PROTOCOL_VERSION ((32 << 8) | 0)
#define SLURM_18_08_PROTOCOL_VERSION ((33 << 8) | 0)
#define SLURM_DEFAULT_LISTEN_BACKLOG 4096
#define SLURM_GLOBAL_AUTH_KEY   0x0001
#define SLURM_MIN_PROTOCOL_VERSION SLURM_17_02_PROTOCOL_VERSION
#define SLURM_MSG_KEEP_BUFFER   0x0004
#define SLURM_ONE_BACK_PROTOCOL_VERSION SLURM_17_11_PROTOCOL_VERSION
#define SLURM_PROTOCOL_FUNCTION_NOT_IMPLEMENTED -2
#define SLURM_PROTOCOL_MAX_MESSAGE_BUFFER_SIZE (512*1024)
#define SLURM_PROTOCOL_NO_FLAGS 0
#define SLURM_PROTOCOL_NO_SEND_RECV_FLAGS 0
#define SLURM_PROTOCOL_VERSION SLURM_18_08_PROTOCOL_VERSION


#  define  __slurm_addr_t_defined

#  define  __sbcast_cred_t_defined
#  define __slurm_cred_t_defined
#define FREE_NULL_LIST(_X)			\
	do {					\
		if (_X) list_destroy (_X);	\
		_X	= NULL; 		\
	} while (0)

# define __COMPAR_FN_T
#  define __list_datatypes_defined


#define CONVERT_NUM_UNIT_EXACT 0x00000001
#define CONVERT_NUM_UNIT_NO    0x00000002
#define CONVERT_NUM_UNIT_RAW   0x00000004
#define MAX_NOALLOC_JOBID ((uint32_t) 0xfffffffd)
#define MIN_NOALLOC_JOBID ((uint32_t) 0xffff0000)




#define SYSTEM_DIMENSIONS 1

#define _EIO_H 1

#define ACCOUNTING_ENFORCE_ASSOCS 0x0001
#define ACCOUNTING_ENFORCE_LIMITS 0x0002
#define ACCOUNTING_ENFORCE_NO_JOBS 0x0020
#define ACCOUNTING_ENFORCE_NO_STEPS 0x0040
#define ACCOUNTING_ENFORCE_QOS    0x0008
#define ACCOUNTING_ENFORCE_SAFE   0x0010
#define ACCOUNTING_ENFORCE_TRES   0x0080
#define ACCOUNTING_ENFORCE_WCKEYS 0x0004
#define ACCOUNTING_STORAGE_TYPE_NONE "accounting_storage/none"
#define DEFAULT_ACCOUNTING_DB      "slurm_acct_db"
#define DEFAULT_ACCOUNTING_ENFORCE  0
#define DEFAULT_ACCOUNTING_STORAGE_TYPE "accounting_storage/none"
#define DEFAULT_ACCOUNTING_TRES  "cpu,mem,energy,node,billing,fs/disk,vmem,pages"
#define DEFAULT_ACCT_GATHER_ENERGY_TYPE "acct_gather_energy/none"
#define DEFAULT_ACCT_GATHER_FILESYSTEM_TYPE "acct_gather_filesystem/none"
#define DEFAULT_ACCT_GATHER_INTERCONNECT_TYPE "acct_gather_interconnect/none"
#define DEFAULT_ACCT_GATHER_PROFILE_TYPE "acct_gather_profile/none"
#  define DEFAULT_ALLOW_SPEC_RESOURCE_USAGE 1
#define DEFAULT_AUTH_TYPE          "auth/munge"
#define DEFAULT_BATCH_START_TIMEOUT 10
#define DEFAULT_CHECKPOINT_TYPE     "checkpoint/none"
#define DEFAULT_COMPLETE_WAIT       0
#define DEFAULT_CORE_SPEC_PLUGIN    "core_spec/none"
#define DEFAULT_CRYPTO_TYPE        "crypto/munge"
#define DEFAULT_DISABLE_ROOT_JOBS   0
#define DEFAULT_ENFORCE_PART_LIMITS 0
#define DEFAULT_EPILOG_MSG_TIME     2000
#define DEFAULT_EXT_SENSORS_TYPE    "ext_sensors/none"
#define DEFAULT_FAST_SCHEDULE       1
#define DEFAULT_FIRST_JOB_ID        1
#define DEFAULT_GET_ENV_TIMEOUT     2
#define DEFAULT_GROUP_FORCE         1	
#define DEFAULT_GROUP_TIME          600
#define DEFAULT_INACTIVE_LIMIT      0
#define DEFAULT_JOB_ACCT_GATHER_FREQ  "30"
#define DEFAULT_JOB_ACCT_GATHER_TYPE  "jobacct_gather/none"
#define DEFAULT_JOB_CKPT_DIR        "/var/slurm/checkpoint"
#define DEFAULT_JOB_COMP_DB         "slurm_jobcomp_db"
#define DEFAULT_JOB_COMP_LOC        "/var/log/slurm_jobcomp.log"
#define DEFAULT_JOB_COMP_TYPE       "jobcomp/none"
#  define DEFAULT_JOB_CONTAINER_PLUGIN  "job_container/cncu"
#define DEFAULT_KEEP_ALIVE_TIME     (NO_VAL16)
#define DEFAULT_KILL_ON_BAD_EXIT    0
#define DEFAULT_KILL_TREE           0
#define DEFAULT_KILL_WAIT           30
#  define DEFAULT_LAUNCH_TYPE         "launch/poe"
#define DEFAULT_MAIL_PROG           "/bin/mail"
#define DEFAULT_MAIL_PROG_ALT       "/usr/bin/mail"
#define DEFAULT_MAX_ARRAY_SIZE      1001
#define DEFAULT_MAX_JOB_COUNT       10000
#define DEFAULT_MAX_JOB_ID          0x03ff0000
#define DEFAULT_MAX_MEM_PER_CPU     0
#define DEFAULT_MAX_STEP_COUNT      40000
#define DEFAULT_MAX_TASKS_PER_NODE  MAX_TASKS_PER_NODE
#define DEFAULT_MCS_PLUGIN          "mcs/none"
#define DEFAULT_MEM_PER_CPU         0
#define DEFAULT_MIN_JOB_AGE         300
#define DEFAULT_MPI_DEFAULT         "none"
#define DEFAULT_MSG_AGGR_WINDOW_MSGS 1
#define DEFAULT_MSG_AGGR_WINDOW_TIME 100
#define DEFAULT_MSG_TIMEOUT         10
#define DEFAULT_MYSQL_PORT          3306
#define DEFAULT_POWER_PLUGIN        ""
#define DEFAULT_PREEMPT_TYPE        "preempt/none"
#define DEFAULT_PRIORITY_CALC_PERIOD 300 
#define DEFAULT_PRIORITY_DECAY      604800 
#define DEFAULT_PRIORITY_TYPE       "priority/basic"
#  define DEFAULT_PROCTRACK_TYPE    "proctrack/sgi_job"
#define DEFAULT_RECONF_KEEP_PART_STATE 0
#define DEFAULT_RESUME_RATE         300
#define DEFAULT_RESUME_TIMEOUT      60
#define DEFAULT_RETURN_TO_SERVICE   0
#define DEFAULT_ROUTE_PLUGIN   	    "route/default"
#define DEFAULT_SAVE_STATE_LOC      "/var/spool"
#define DEFAULT_SCHEDTYPE           "sched/backfill"
#define DEFAULT_SCHED_LOG_LEVEL     0
#define DEFAULT_SCHED_TIME_SLICE    30
#  define DEFAULT_SELECT_TYPE       "select/alps"
#define DEFAULT_SLURMCTLD_PIDFILE   "/var/run/slurmctld.pid"
#define DEFAULT_SLURMCTLD_TIMEOUT   120
#define DEFAULT_SLURMD_PIDFILE      "/var/run/slurmd.pid"
#define DEFAULT_SLURMD_TIMEOUT      300
#define DEFAULT_SPOOLDIR            "/var/spool/slurmd"
#define DEFAULT_STORAGE_HOST        "localhost"
#define DEFAULT_STORAGE_LOC         "/var/log/slurm_jobacct.log"
#define DEFAULT_STORAGE_PORT        0
#define DEFAULT_STORAGE_USER        "root"
#define DEFAULT_SUSPEND_RATE        60
#define DEFAULT_SUSPEND_TIME        0
#define DEFAULT_SUSPEND_TIMEOUT     30
#  define DEFAULT_SWITCH_TYPE         "switch/cray"
#define DEFAULT_TASK_PLUGIN         "task/none"
#define DEFAULT_TCP_TIMEOUT         2
#define DEFAULT_TMP_FS              "/tmp"
#  define DEFAULT_TOPOLOGY_PLUGIN     "topology/3d_torus"
#  define DEFAULT_TREE_WIDTH        50
#define DEFAULT_UNKILLABLE_TIMEOUT  60 
#define DEFAULT_WAIT_TIME           0
#define JOB_ACCT_GATHER_TYPE_NONE "jobacct_gather/none"




#define xhash_free(__p) xhash_free_ptr(&(__p));


#  define __check_jobinfo_t_defined


#define DB_DEBUG(conn, fmt, ...) \
	info("%d(%s:%d) "fmt, conn, THIS_FILE, "__LINE__", ##__VA_ARGS__);
#define TRES_OFFSET 1000


#define ASSOC_MGR_CACHE_ALL   0xffff
#define ASSOC_MGR_CACHE_ASSOC 0x0001
#define ASSOC_MGR_CACHE_QOS   0x0002
#define ASSOC_MGR_CACHE_RES   0x0010
#define ASSOC_MGR_CACHE_TRES  0x0020
#define ASSOC_MGR_CACHE_USER  0x0004
#define ASSOC_MGR_CACHE_WCKEY 0x0008




#define xiso8601timecat(__p, __msec)            _xiso8601timecat(&(__p), __msec)
#define xmemcat(__p, __s, __e)          _xmemcat(&(__p), __s, __e)
#define xrfc5424timecat(__p, __msec)            _xrfc5424timecat(&(__p), __msec)
#define xstrcat(__p, __q)		_xstrcat(&(__p), __q)
#define xstrcatchar(__p, __c)		_xstrcatchar(&(__p), __c)
#define xstrfmtcat(__p, __fmt, args...)	_xstrfmtcat(&(__p), __fmt, ## args)
#define xstrftimecat(__p, __fmt)	_xstrftimecat(&(__p), __fmt)
#define xstrncat(__p, __q, __l)		_xstrncat(&(__p), __q, __l)
#define xstrsubstitute(__p, __pat, __rep) _xstrsubstitute(&(__p), __pat, __rep)
#define xstrsubstituteall(__p, __pat, __rep)			\
	while (_xstrsubstitute(&(__p), __pat, __rep))		\
		;
#define PW_BUF_SIZE 65536



#define PLUGIN_INVALID_HANDLE ((void*)0)

