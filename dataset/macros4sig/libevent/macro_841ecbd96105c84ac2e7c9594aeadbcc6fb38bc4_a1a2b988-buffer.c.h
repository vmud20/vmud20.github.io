
#include<sys/mman.h>
#include<sys/time.h>

#include<time.h>

#include<string.h>

#include<sys/types.h>
#include<sys/sendfile.h>
#include<sys/ioctl.h>


#include<limits.h>
#include<sys/eventfd.h>
#include<sys/queue.h>
#include<errno.h>
#include<netdb.h>

#include<stdint.h>


#include<sys/stat.h>


#include<sys/uio.h>

#include<stdlib.h>

#include<stddef.h>


#include<stdio.h>
#include<unistd.h>
#include<stdarg.h>
#include<sys/socket.h>

#include<inttypes.h>

#define BEV_DEL_GENERIC_READ_TIMEOUT(bev)	\
		event_del(&(bev)->ev_read)
#define BEV_DEL_GENERIC_WRITE_TIMEOUT(bev)	\
		event_del(&(bev)->ev_write)
#define BEV_IS_ASYNC(bevp) ((bevp)->be_ops == &bufferevent_ops_async)
#define BEV_IS_FILTER(bevp) ((bevp)->be_ops == &bufferevent_ops_filter)
#define BEV_IS_PAIR(bevp) ((bevp)->be_ops == &bufferevent_ops_pair)
#define BEV_IS_SOCKET(bevp) ((bevp)->be_ops == &bufferevent_ops_socket)
#define BEV_LOCK(b) EVUTIL_NIL_STMT_
#define BEV_RESET_GENERIC_READ_TIMEOUT(bev)				\
	do {								\
		if (evutil_timerisset(&(bev)->timeout_read))		\
			event_add(&(bev)->ev_read, &(bev)->timeout_read); \
	} while (0)
#define BEV_RESET_GENERIC_WRITE_TIMEOUT(bev)				\
	do {								\
		if (evutil_timerisset(&(bev)->timeout_write))		\
			event_add(&(bev)->ev_write, &(bev)->timeout_write); \
	} while (0)
#define BEV_SUSPEND_BW 0x02
#define BEV_SUSPEND_BW_GROUP 0x04
#define BEV_SUSPEND_FILT_READ 0x10
#define BEV_SUSPEND_LOOKUP 0x08
#define BEV_SUSPEND_WM 0x01
#define BEV_UNLOCK(b) EVUTIL_NIL_STMT_
#define BEV_UPCAST(b) EVUTIL_UPCAST((b), struct bufferevent_private, bev)

#define bufferevent_wm_suspend_read(b) \
	bufferevent_suspend_read_((b), BEV_SUSPEND_WM)
#define bufferevent_wm_unsuspend_read(b) \
	bufferevent_unsuspend_read_((b), BEV_SUSPEND_WM)






#define EVLIST_ACTIVE_LATER 0x20
#define EVLIST_ALL          0xff
#define EVLIST_FINALIZING   0x40
#define LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;				\
	struct type **le_prev;		\
}
#define LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;  			\
	}
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;				\
	struct type **tqe_prev;		\
}
#define TAILQ_HEAD(name, type)			\
struct name {					\
	struct type *tqh_first;			\
	struct type **tqh_last;			\
}


#define EVENT__SIZEOF_VOID_P EVENT__SIZEOF_VOID__
#define EVUTIL_AI_ADDRCONFIG AI_ADDRCONFIG
#define EVUTIL_AI_ALL AI_ALL
#define EVUTIL_AI_CANONNAME AI_CANONNAME
#define EVUTIL_AI_NUMERICHOST AI_NUMERICHOST
#define EVUTIL_AI_NUMERICSERV AI_NUMERICSERV
#define EVUTIL_AI_PASSIVE AI_PASSIVE
#define EVUTIL_AI_V4MAPPED AI_V4MAPPED
#define EVUTIL_CLOSESOCKET(s) evutil_closesocket(s)
#define EVUTIL_EAI_ADDRFAMILY EAI_ADDRFAMILY
#define EVUTIL_EAI_AGAIN EAI_AGAIN
#define EVUTIL_EAI_BADFLAGS EAI_BADFLAGS
#define EVUTIL_EAI_CANCEL -90001
#define EVUTIL_EAI_FAIL EAI_FAIL
#define EVUTIL_EAI_FAMILY EAI_FAMILY
#define EVUTIL_EAI_MEMORY EAI_MEMORY
#define EVUTIL_EAI_NODATA EAI_NODATA
#define EVUTIL_EAI_NONAME EAI_NONAME
#define EVUTIL_EAI_SERVICE EAI_SERVICE
#define EVUTIL_EAI_SOCKTYPE EAI_SOCKTYPE
#define EVUTIL_EAI_SYSTEM EAI_SYSTEM
#define EVUTIL_SET_SOCKET_ERROR(errcode)		\
	do { WSASetLastError(errcode); } while (0)
#define EVUTIL_SOCKET_ERROR() WSAGetLastError()
#define EV_INT16_MAX  ((ev_int16_t) 0x7fffL)
#define EV_INT16_MIN  ((-EV_INT16_MAX) - 1)
#define EV_INT32_MAX  ((ev_int32_t) 0x7fffffffL)
#define EV_INT32_MIN  ((-EV_INT32_MAX) - 1)
#define EV_INT64_MAX  ((((ev_int64_t) 0x7fffffffL) << 32) | 0xffffffffL)
#define EV_INT64_MIN  ((-EV_INT64_MAX) - 1)
#define EV_INT8_MAX   127
#define EV_INT8_MIN   ((-EV_INT8_MAX) - 1)
#define EV_MONOT_FALLBACK 2
#define EV_MONOT_PRECISE  1
#define EV_SIZE_MAX EV_UINT64_MAX
#define EV_SSIZE_MAX EV_INT64_MAX
#define EV_SSIZE_MIN ((-EV_SSIZE_MAX) - 1)
#define EV_UINT16_MAX ((ev_uint16_t)0xffffUL)
#define EV_UINT32_MAX ((ev_uint32_t)0xffffffffUL)
#define EV_UINT64_MAX ((((ev_uint64_t)0xffffffffUL) << 32) | 0xffffffffUL)
#define EV_UINT8_MAX  255

#define ev_int16_t  int16_t
#define ev_int32_t int32_t
#define ev_int64_t int64_t
#define ev_int8_t int8_t
#define ev_intptr_t intptr_t
#define ev_off_t ev_int64_t
#define ev_socklen_t int
#define ev_ssize_t EVENT__ssize_t
#define ev_uint16_t uint16_t
#define ev_uint32_t uint32_t
#define ev_uint64_t uint64_t
#define ev_uint8_t uint8_t
#define ev_uintptr_t uintptr_t
#define evutil_addrinfo addrinfo
#define evutil_gettimeofday(tv, tz) gettimeofday((tv), (tz))
#define evutil_offsetof(type, field) offsetof(type, field)
#define evutil_socket_error_to_string(errcode) ...
#define evutil_socket_geterror(sock) ...
#define evutil_socket_t intptr_t
#define evutil_timeradd(tvp, uvp, vvp) timeradd((tvp), (uvp), (vvp))
#define evutil_timerclear(tvp) timerclear(tvp)
#define evutil_timerisset(tvp) timerisset(tvp)
#define evutil_timersub(tvp, uvp, vvp) timersub((tvp), (uvp), (vvp))
#define ss_family __ss_family
#define EVENT2_EXPORT_SYMBOL __global


#define ev_token_bucket_decrement_read(b,n)	\
	do {					\
		(b)->read_limit -= (n);		\
	} while (0)
#define ev_token_bucket_decrement_write(b,n)	\
	do {					\
		(b)->write_limit -= (n);	\
	} while (0)

#define EVTHREAD_CONDITION_API_VERSION 1
#define EVTHREAD_LOCKTYPE_READWRITE 2
#define EVTHREAD_LOCKTYPE_RECURSIVE 1
#define EVTHREAD_LOCK_API_VERSION 1
#define EVTHREAD_TRY    0x10
#define EVTHREAD_USE_PTHREADS_IMPLEMENTED 1
#define EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED 1
#define EVBASE_ACQUIRE_LOCK(base, lockvar) do {				\
		EVLOCK_LOCK((base)->lockvar, 0);			\
	} while (0)
#define EVBASE_IN_THREAD(base)				\
	((base)->th_owner_id == evthreadimpl_get_id_())
#define EVBASE_NEED_NOTIFY(base)			 \
	((base)->running_loop &&			 \
	    ((base)->th_owner_id != evthreadimpl_get_id_()))
#define EVBASE_RELEASE_LOCK(base, lockvar) do {				\
		EVLOCK_UNLOCK((base)->lockvar, 0);			\
	} while (0)
#define EVLOCK_ASSERT_LOCKED(lock)					\
	do {								\
		if ((lock) && evthread_lock_debugging_enabled_) {	\
			EVUTIL_ASSERT(evthread_is_debug_lock_held_(lock)); \
		}							\
	} while (0)
#define EVLOCK_LOCK(lockvar,mode)					\
	do {								\
		if (lockvar)						\
			evthreadimpl_lock_lock_(mode, lockvar);		\
	} while (0)
#define EVLOCK_LOCK2(lock1,lock2,mode1,mode2) EVUTIL_NIL_STMT_
#define EVLOCK_SORTLOCKS_(lockvar1, lockvar2)				\
	do {								\
		if (lockvar1 && lockvar2 && lockvar1 > lockvar2) {	\
			void *tmp = lockvar1;				\
			lockvar1 = lockvar2;				\
			lockvar2 = tmp;					\
		}							\
	} while (0)
#define EVLOCK_TRY_LOCK_(lock) 1
#define EVLOCK_UNLOCK(lockvar,mode)					\
	do {								\
		if (lockvar)						\
			evthreadimpl_lock_unlock_(mode, lockvar);	\
	} while (0)
#define EVLOCK_UNLOCK2(lock1,lock2,mode1,mode2) EVUTIL_NIL_STMT_
#define EVTHREAD_ALLOC_COND(condvar)					\
	do {								\
		(condvar) = evthread_cond_fns_.alloc_condition ?	\
		    evthread_cond_fns_.alloc_condition(0) : NULL;	\
	} while (0)
#define EVTHREAD_ALLOC_LOCK(lockvar, locktype)		\
	((lockvar) = evthreadimpl_lock_alloc_(locktype))
#define EVTHREAD_COND_BROADCAST(cond)					\
	( (cond) ? evthread_cond_fns_.signal_condition((cond), 1) : 0 )
#define EVTHREAD_COND_SIGNAL(cond)					\
	( (cond) ? evthread_cond_fns_.signal_condition((cond), 0) : 0 )
#define EVTHREAD_COND_WAIT(cond, lock)					\
	( (cond) ? evthread_cond_fns_.wait_condition((cond), (lock), NULL) : 0 )
#define EVTHREAD_COND_WAIT_TIMED(cond, lock, tv)			\
	( (cond) ? evthread_cond_fns_.wait_condition((cond), (lock), (tv)) : 0 )

#define EVTHREAD_FREE_COND(cond)					\
	do {								\
		if (cond)						\
			evthread_cond_fns_.free_condition((cond));	\
	} while (0)
#define EVTHREAD_FREE_LOCK(lockvar, locktype)				\
	do {								\
		void *lock_tmp_ = (lockvar);				\
		if (lock_tmp_)						\
			evthreadimpl_lock_free_(lock_tmp_, (locktype)); \
	} while (0)
#define EVTHREAD_GET_ID() evthreadimpl_get_id_()

#define EVTHREAD_LOCKING_ENABLED()		\
	(evthread_lock_fns_.lock != NULL)
#define EVTHREAD_SETUP_GLOBAL_LOCK(lockvar, locktype)			\
	do {								\
		lockvar = evthread_setup_global_lock_(lockvar,		\
		    (locktype), enable_locks);				\
		if (!lockvar) {						\
			event_warn("Couldn't allocate %s", #lockvar);	\
			return -1;					\
		}							\
	} while (0);
#define EVUTIL_ASSERT(cond) EVUTIL_NIL_CONDITION_(cond)
#define EVUTIL_ASSERT_LIST_OK(dlist, type, field) do {			\
		struct type *elm1, *elm2, **nextp;			\
		if (LIST_EMPTY((dlist)))				\
			break;						\
									\
				\
					\
		elm1 = LIST_FIRST((dlist));				\
		elm2 = LIST_NEXT(elm1, field);				\
		while (elm1 && elm2) {					\
			EVUTIL_ASSERT(elm1 != elm2);			\
			elm1 = LIST_NEXT(elm1, field);			\
			elm2 = LIST_NEXT(elm2, field);			\
			if (!elm2)					\
				break;					\
			EVUTIL_ASSERT(elm1 != elm2);			\
			elm2 = LIST_NEXT(elm2, field);			\
		}							\
									\
		 \
		nextp = &LIST_FIRST((dlist));				\
		elm1 = LIST_FIRST((dlist));				\
		while (elm1) {						\
			EVUTIL_ASSERT(*nextp == elm1);			\
			EVUTIL_ASSERT(nextp == elm1->field.le_prev);	\
			nextp = &LIST_NEXT(elm1, field);		\
			elm1 = *nextp;					\
		}							\
	} while (0)
#define EVUTIL_ASSERT_TAILQ_OK(tailq, type, field) do {			\
		struct type *elm1, *elm2, **nextp;			\
		if (TAILQ_EMPTY((tailq)))				\
			break;						\
									\
				\
					\
		elm1 = TAILQ_FIRST((tailq));				\
		elm2 = TAILQ_NEXT(elm1, field);				\
		while (elm1 && elm2) {					\
			EVUTIL_ASSERT(elm1 != elm2);			\
			elm1 = TAILQ_NEXT(elm1, field);			\
			elm2 = TAILQ_NEXT(elm2, field);			\
			if (!elm2)					\
				break;					\
			EVUTIL_ASSERT(elm1 != elm2);			\
			elm2 = TAILQ_NEXT(elm2, field);			\
		}							\
									\
		 \
		nextp = &TAILQ_FIRST((tailq));				\
		elm1 = TAILQ_FIRST((tailq));				\
		while (elm1) {						\
			EVUTIL_ASSERT(*nextp == elm1);			\
			EVUTIL_ASSERT(nextp == elm1->field.tqe_prev);	\
			nextp = &TAILQ_NEXT(elm1, field);		\
			elm1 = *nextp;					\
		}							\
		EVUTIL_ASSERT(nextp == (tailq)->tqh_last);		\
	} while (0)
#define EVUTIL_EAI_NEED_RESOLVE      -90002
#define EVUTIL_EFD_CLOEXEC EFD_CLOEXEC
#define EVUTIL_EFD_NONBLOCK EFD_NONBLOCK
#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)			\
	((e) == EINTR || EVUTIL_ERR_IS_EAGAIN(e) || (e) == ECONNABORTED)
#define EVUTIL_ERR_CONNECT_REFUSED(e)					\
	((e) == ECONNREFUSED)
#define EVUTIL_ERR_CONNECT_RETRIABLE(e)			\
	((e) == EINTR || (e) == EINPROGRESS)
#define EVUTIL_ERR_IS_EAGAIN(e) \
	((e) == EAGAIN)
#define EVUTIL_ERR_RW_RETRIABLE(e)				\
	((e) == EINTR || EVUTIL_ERR_IS_EAGAIN(e))
#define EVUTIL_FAILURE_CHECK(cond) 0
#define EVUTIL_NIL_CONDITION_(condition) do { \
	(void)sizeof(!(condition));  \
} while(0)
#define EVUTIL_NIL_STMT_ ((void)0)
#define EVUTIL_SHUT_BOTH SHUT_BOTH
#define EVUTIL_SHUT_RD SHUT_RD
#define EVUTIL_SHUT_WR SHUT_WR
#define EVUTIL_SOCK_CLOEXEC SOCK_CLOEXEC
#define EVUTIL_SOCK_NONBLOCK SOCK_NONBLOCK
#define EVUTIL_UNLIKELY(p) __builtin_expect(!!(p),0)
#define EVUTIL_UPCAST(ptr, type, field)				\
	((type *)(((char*)(ptr)) - evutil_offsetof(type, field)))
#define EVUTIL_WEAKRAND_MAX EV_INT32_MAX
#define EV_I64_ARG(x) ((__int64)(x))
#define EV_I64_FMT "%I64d"
#define EV_SIZE_ARG(x) (x)
#define EV_SIZE_FMT "%zu"
#define EV_SOCK_ARG(x) EV_I64_ARG((x))
#define EV_SOCK_FMT EV_I64_FMT
#define EV_SSIZE_ARG(x) (x)
#define EV_SSIZE_FMT "%zd"
#define EV_U64_ARG(x) ((unsigned __int64)(x))
#define EV_U64_FMT "%I64u"

#define __func__ EVENT____func__
#define inline EVENT__inline
#define ss_family ss_union.ss_sa.sa_family
#define AF_INET6 3333

#define PF_INET6 AF_INET6



#define EVENT_ERR_ABORT_ ((int)0xdeaddead)
#define EV_CHECK_FMT(a,b) __attribute__((format(printf, a, b)))
#define EV_NORETURN __attribute__((noreturn))


#define event_debug(x) do {			\
	if (event_debug_get_logging_mask_()) {	\
		event_debugx_ x;		\
	}					\
	} while (0)
#define event_debug_get_logging_mask_() (event_debug_logging_mask_)

#define ASSERT_EVBUFFER_LOCKED(buffer)			\
	EVLOCK_ASSERT_LOCKED((buffer)->lock)
#define EVBUFFER_CB_NODEFER 2
#define EVBUFFER_CHAIN_EXTRA(t, c) (t *)((struct evbuffer_chain *)(c) + 1)
#define EVBUFFER_CHAIN_MAX ((size_t)EV_SSIZE_MAX)
#define EVBUFFER_CHAIN_SIZE sizeof(struct evbuffer_chain)

#define EVBUFFER_LOCK(buffer)						\
	do {								\
		EVLOCK_LOCK((buffer)->lock, 0);				\
	} while (0)
#define EVBUFFER_LOCK2(buffer1, buffer2)				\
	do {								\
		EVLOCK_LOCK2((buffer1)->lock, (buffer2)->lock, 0, 0);	\
	} while (0)
#define EVBUFFER_MEM_PINNED_ANY (EVBUFFER_MEM_PINNED_R|EVBUFFER_MEM_PINNED_W)
#define EVBUFFER_UNLOCK(buffer)						\
	do {								\
		EVLOCK_UNLOCK((buffer)->lock, 0);			\
	} while (0)
#define EVBUFFER_UNLOCK2(buffer1, buffer2)				\
	do {								\
		EVLOCK_UNLOCK2((buffer1)->lock, (buffer2)->lock, 0, 0);	\
	} while (0)
#define WSABUF_FROM_EVBUFFER_IOV(i,ei) do {		\
		(i)->buf = (ei)->iov_base;		\
		(i)->len = (unsigned long)(ei)->iov_len;	\
	} while (0)

#define mm_calloc(count, size) event_mm_calloc_((count), (size))
#define mm_free(p) event_mm_free_(p)
#define mm_malloc(sz) event_mm_malloc_(sz)
#define mm_realloc(p, sz) event_mm_realloc_((p), (sz))
#define mm_strdup(s) event_mm_strdup_(s)
#define EVBUFFER_INPUT(x)	bufferevent_get_input(x)
#define EVBUFFER_OUTPUT(x)	bufferevent_get_output(x)

#define evbuffercb bufferevent_data_cb
#define everrorcb bufferevent_event_cb

#define EV_RATE_LIMIT_MAX EV_SSIZE_MAX
#define EVBUFFER_DATA(x)	evbuffer_pullup((x), -1)
#define EVBUFFER_LENGTH(x)	evbuffer_get_length(x)

#define EVBUFFER_CB_ENABLED 1
#define EVBUFFER_FLAG_DRAINS_TO_FD 1

#define EVBUF_FS_CLOSE_ON_FREE    0x01
#define EVBUF_FS_DISABLE_LOCKING  0x08
#define EVBUF_FS_DISABLE_MMAP     0x02
#define EVBUF_FS_DISABLE_SENDFILE 0x04

#define evbuffer_iovec iovec

#define EVENT_BASE_COUNT_ACTIVE                1U
#define EVENT_BASE_COUNT_ADDED         4U
#define EVENT_BASE_COUNT_VIRTUAL       2U
#define EVENT_DBG_ALL 0xffffffffu
#define EVENT_DBG_NONE 0
#define EVENT_LOG_DEBUG 0
#define EVENT_LOG_ERR   3
#define EVENT_LOG_MSG   1
#define EVENT_LOG_WARN  2
#define EVENT_MAX_PRIORITIES 256

#define EVLOOP_NO_EXIT_ON_EMPTY 0x04
#define EV_FINALIZE     0x40
#define LIBEVENT_VERSION EVENT__VERSION
#define LIBEVENT_VERSION_NUMBER EVENT__NUMERIC_VERSION
#define _EVENT_LOG_DEBUG EVENT_LOG_DEBUG
#define _EVENT_LOG_ERR EVENT_LOG_ERR
#define _EVENT_LOG_MSG EVENT_LOG_MSG
#define _EVENT_LOG_WARN EVENT_LOG_WARN
#define event_get_signal(ev) ((int)event_get_fd(ev))
#define evsignal_add(ev, tv)		event_add((ev), (tv))
#define evsignal_assign(ev, b, x, cb, arg)			\
	event_assign((ev), (b), (x), EV_SIGNAL|EV_PERSIST, cb, (arg))
#define evsignal_del(ev)		event_del(ev)
#define evsignal_initialized(ev)	event_initialized(ev)
#define evsignal_new(b, x, cb, arg)				\
	event_new((b), (x), EV_SIGNAL|EV_PERSIST, (cb), (arg))
#define evsignal_pending(ev, tv)	event_pending((ev), EV_SIGNAL, (tv))
#define evtimer_add(ev, tv)		event_add((ev), (tv))
#define evtimer_assign(ev, b, cb, arg) \
	event_assign((ev), (b), -1, 0, (cb), (arg))
#define evtimer_del(ev)			event_del(ev)
#define evtimer_initialized(ev)		event_initialized(ev)
#define evtimer_new(b, cb, arg)	       event_new((b), -1, 0, (cb), (arg))
#define evtimer_pending(ev, tv)		event_pending((ev), EV_TIMEOUT, (tv))
