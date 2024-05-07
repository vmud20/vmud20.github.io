#include<stdlib.h>
#include<errno.h>


#include<string.h>
#include<assert.h>

#include<inttypes.h>
#include<netinet/in.h>

#include<stddef.h>
#include<stdbool.h>
#include<time.h>
#include<pthread.h>
#include<sys/types.h>
#include<stdio.h>
#include<syslog.h>
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
#define BUF_MAGIC 0x42554545
#define BUF_SIZE (16 * 1024)
#define FLOAT_MULT 1000000
#define FREE_NULL_BUFFER(_X)		\
	do {				\
		if (_X) free_buf (_X);	\
		_X	= NULL; 	\
	} while (0)
#define MAX_BUF_SIZE ((uint32_t) 0xffff0000)	

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
		strncpy(s, tmp_string, max);				\
	}								\
} while (0)
#    define strong_alias(name, aliasname) \
     extern __typeof (name) aliasname __attribute ((alias (#name)))


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
