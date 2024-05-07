#include<stdlib.h>

#include<endian.h>

#include<time.h>
#include<errno.h>

#include<semaphore.h>
#include<poll.h>
#include<string.h>
#include<stdbool.h>
#include<sys/types.h>


#include<unistd.h>
#include<stddef.h>
#include<fcntl.h>
#include<pthread.h>
#include<stdint.h>
#include<stdio.h>
#include<sys/socket.h>

#include<sys/uio.h>
#include<stdarg.h>




#include<netinet/in.h>
#define FASTD_BIND_DEFAULT_IPV4 (1U << 1)
#define FASTD_BIND_DEFAULT_IPV6 (1U << 2)
#define FASTD_BIND_DYNAMIC (1U << 3)
#define VECTOR(type)                      \
	struct {                          \
		fastd_vector_desc_t desc; \
		type *data;               \
	}
#define VECTOR_ADD(v, elem)                                                                            \
	({                                                                                             \
		__typeof__(v) *_v = &(v);                                                              \
		__typeof__(*_v->data) _e = (elem);                                                     \
		_fastd_vector_insert(&_v->desc, (void **)&_v->data, &_e, _v->desc.length, sizeof(_e)); \
	})
#define VECTOR_BSEARCH(key, v, cmp)                                                 \
	({                                                                          \
		__typeof__(v) *_v = &(v);                                           \
		const __typeof__(*_v->data) *_key = (key);                          \
		int (*_cmp)(__typeof__(_key), __typeof__(_key)) = (cmp);            \
		(__typeof__(_v->data))                                              \
			bsearch(_key, _v->data, _v->desc.length, sizeof(*_v->data), \
				(int (*)(const void *, const void *))_cmp);         \
	})
#define VECTOR_DATA(v) ((v).data)
#define VECTOR_DELETE(v, pos)                                                                  \
	({                                                                                     \
		__typeof__(v) *_v = &(v);                                                      \
		_fastd_vector_delete(&_v->desc, (void **)&_v->data, (pos), sizeof(*_v->data)); \
	})
#define VECTOR_FREE(v) free((v).data)
#define VECTOR_INDEX(v, i) ((v).data[i])
#define VECTOR_INSERT(v, elem, pos)                                                          \
	({                                                                                   \
		__typeof__(v) *_v = &(v);                                                    \
		__typeof__(*_v->data) _e = (elem);                                           \
		_fastd_vector_insert(&_v->desc, (void **)&_v->data, &_e, (pos), sizeof(_e)); \
	})
#define VECTOR_LEN(v) ((v).desc.length)
#define VECTOR_RESIZE(v, n)                                                                  \
	({                                                                                   \
		__typeof__(v) *_v = &(v);                                                    \
		_fastd_vector_resize(&_v->desc, (void **)&_v->data, (n), sizeof(*_v->data)); \
	})
#define array_size(array) (sizeof(array) / sizeof((array)[0]))
#define be32toh(x) OSSwapBigToHostInt32(x)
#define container_of(ptr, type, member)                               \
	({                                                            \
		const __typeof__(((type *)0)->member) *_mptr = (ptr); \
		(type *)((char *)_mptr - offsetof(type, member));     \
	})
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define FASTD_TIMEOUT_INV INT64_MAX
#define FASTD_TRISTATE_FALSE ((fastd_tristate_t){ true, false })
#define FASTD_TRISTATE_TRUE ((fastd_tristate_t){ true, true })
#define FASTD_TRISTATE_UNDEF ((fastd_tristate_t){ false, false })
#define UNUSED __attribute__((unused))
#define GROUPLIST_TYPE int
#define IP_FREEBIND 15

#define SOCK_NONBLOCK 0
#define fastd_new(type) ((type *)fastd_alloc(sizeof(type)))
#define fastd_new0(type) ((type *)fastd_alloc0(sizeof(type)))
#define fastd_new0_array(members, type) ((type *)fastd_alloc0_array(members, sizeof(type)))
#define fastd_new_aligned(type, align) ((type *)fastd_alloc_aligned(sizeof(type), align))
#define fastd_new_array(members, type) ((type *)fastd_alloc_array(members, sizeof(type)))
#define exit_bug(message) exit_fatal("BUG: %s", message)
#define exit_errno(message) exit_error("%s: %s", message, strerror(errno))
#define exit_error(args...)     \
	do {                    \
		pr_error(args); \
		exit(1);        \
	} while (0)
#define exit_fatal(args...)     \
	do {                    \
		pr_fatal(args); \
		abort();        \
	} while (0)
#define pr_debug(args...) fastd_logf(LL_DEBUG, args)
#define pr_debug2(args...) fastd_logf(LL_DEBUG2, args)
#define pr_debug2_errno(message) pr_debug2("%s: %s", message, strerror(errno))
#define pr_debug_errno(message) pr_debug("%s: %s", message, strerror(errno))
#define pr_error(args...) fastd_logf(LL_ERROR, args)
#define pr_error_errno(message) pr_error("%s: %s", message, strerror(errno))
#define pr_fatal(args...) fastd_logf(LL_FATAL, args)
#define pr_info(args...) fastd_logf(LL_INFO, args)
#define pr_verbose(args...) fastd_logf(LL_VERBOSE, args)
#define pr_warn(args...) fastd_logf(LL_WARN, args)
#define pr_warn_errno(message) pr_warn("%s: %s", message, strerror(errno))
#define FASTD_POLL_FD(type, fd) ((fastd_poll_fd_t){ type, fd })
#define MAX_HANDSHAKE_SIZE 1232
#define RECORD_LEN(len) ((len) + 4)
