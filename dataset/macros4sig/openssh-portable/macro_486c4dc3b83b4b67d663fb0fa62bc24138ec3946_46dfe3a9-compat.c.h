

#include<stdarg.h>


#include<time.h>
#include<sys/mman.h>

#include<signal.h>




#include<netinet/in.h>




#include<stddef.h>
#include<errno.h>
#include<stdio.h>
#include<termios.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/dir.h>
#include<fnmatch.h>
#include<netinet/ip.h>



#include<pwd.h>


#include<string.h>



#include<sys/types.h>



#include<netinet/in_systm.h>





#define CURVE25519_SIZE 32

#define KEX_RSA_SHA2_256_SUPPORTED 	0x0008 
#define KEX_RSA_SHA2_512_SUPPORTED 	0x0010 

#define crypto_hash_sha512_BYTES 64U
#define crypto_kem_sntrup761_BYTES 32
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_sign_ed25519_BYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define _GNU_SOURCE 

#define NGROUPS_MAX NGROUPS

#define dirent direct
#define wait(a) posix_wait(a)
#   define VA_COPY(dest, src) __va_copy(dest, src)

#  define arc4random_stir()
# define login_getpwclass(pw) login_getclass(pw->pw_class)
# define mblen(x, y)	(1)
# define nl_langinfo(x)	""
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)


#define no_argument        0
#define optional_argument  2
#define required_argument  1
# define ALIGN(p) (((unsigned)p + ALIGNBYTES) & ~ALIGNBYTES)
# define ALIGNBYTES (sizeof(int) - 1)
#  define BIG_ENDIAN     4321
#  define BYTE_ORDER BIG_ENDIAN
#define CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= sizeof(struct cmsghdr) ? \
	 (struct cmsghdr *)(mhdr)->msg_control : \
	 (struct cmsghdr *)NULL)
# define CUSTOM_FAILED_LOGIN
# define CUSTOM_SSH_AUDIT_EVENTS
# define CUSTOM_SYS_AUTH_PASSWD 1
#define DEF_WEAK(x)	void __ssh_compat_weak_##x(void)
# define DO_LOG_SAFE_IN_SIGHAND
# define EWOULDBLOCK EAGAIN
# define FSID_TO_ULONG(f) ((f))
# define HAVE_CLOCK_T
# define HAVE_GETADDRINFO
# define HAVE_LOGIN_CAP
# define HAVE_MODE_T
# define HAVE_PID_T
# define HAVE_SA_FAMILY_T
# define HAVE_SIG_ATOMIC_T
# define HAVE_SIZE_T
# define HAVE_SSIZE_T
# define HAVE_U_CHAR
# define HAVE_U_INTXX_T 1
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#define INADDR_LOOPBACK ((u_long)0x7f000001)
#define INET6_ADDRSTRLEN 46
#  define INT32_MAX INT_MAX
#  define INT64_MAX INT_MAX
#define IPPORT_RESERVED 0
# define IPTOS_LOWCOST           0x02
# define IPTOS_LOWDELAY          0x10
# define IPTOS_MINCOST           IPTOS_LOWCOST
# define IPTOS_RELIABILITY       0x04
# define IPTOS_THROUGHPUT        0x08
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#  define LITTLE_ENDIAN  1234
#define LLONG_MAX LONG_LONG_MAX
#define LLONG_MIN LONG_LONG_MIN
#define MAP_ANON MAP_ANONYMOUS
# define MAP_FAILED ((void *)-1)
# define MAX(a,b) (((a)>(b))?(a):(b))
#  define MAXPATHLEN PATH_MAX
# define MAXSYMLINKS 5
# define MIN(a,b) (((a)<(b))?(a):(b))
# define O_NONBLOCK      00004	
# define PATH_MAX _POSIX_PATH_MAX
# define SHUT_RD   SHUT_RD
# define SHUT_RDWR SHUT_RDWR
# define SHUT_WR   SHUT_WR
#define SIZE_MAX SIZE_T_MAX
# define SIZE_T_MAX UINT_MAX
# define SSH_AUDIT_EVENTS
# define SSH_IOBUFSZ 8192
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
# define SSH_TIME_T_MAX LLONG_MAX
#define SSIZE_MAX INT_MAX
# define STDERR_FILENO   2
# define STDIN_FILENO    0
# define STDOUT_FILENO   1
# define S_IFSOCK 0
# define S_ISDIR(mode)	(((mode) & (_S_IFMT)) == (_S_IFDIR))
# define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)
# define S_ISREG(mode)	(((mode) & (_S_IFMT)) == (_S_IFREG))
# define ULLONG_MAX ((unsigned long long)-1)
#  define USE_LASTLOG
# define USE_LIBIAF
#  define USE_LOGIN
# define USE_SHADOW
# define USE_SNTRUP761X25519 1
# define USE_SYSTEM_GLOB
#    define USE_UTMP
#    define USE_UTMPX
#    define USE_WTMP
#    define USE_WTMPX
#      define UTMP_FILE CONF_UTMP_FILE
# define UT_LINESIZE 8
#      define WTMP_FILE CONF_WTMP_FILE
#    define X_UNIX_PATH "/var/spool/sockets/X11/%u"

# define _PATH_BSHELL "/bin/sh"
# define _PATH_BTMP BTMP_FILE
# define _PATH_DEVNULL "/dev/null"
# define _PATH_MAILDIR MAIL_DIRECTORY
# define _PATH_NOLOGIN "/etc/nologin"
# define _PATH_STDPATH USER_PATH
# define _PATH_TTY "/dev/tty"
#define _PATH_UNIX_X X_UNIX_PATH
#define _PATH_XAUTH XAUTH_PATH


# define __P(x) x
# define __attribute__(x)
# define __bounded__(x, y, z)
#  define __func__ __FUNCTION__
# define __nonnull__(x)
#  define __predict_false(exp)    __builtin_expect(((exp) != 0), 0)
#  define __predict_true(exp)     __builtin_expect(((exp) != 0), 1)
# define __sentinel__
# define getgroups(a,b) ((a)==0 && (b)==NULL ? NGROUPS_MAX : getgroups((a),(b)))
# define getopt(ac, av, o)  BSDgetopt(ac, av, o)
# define getpgrp() getpgrp(0)
# define howmany(x,y)	(((x)+((y)-1))/(y))
#  define krb5_get_err_text(context,code) error_message(code)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
# define offsetof(type, member) ((size_t) &((type *)0)->member)
# define optarg             BSDoptarg
# define opterr             BSDopterr
# define optind             BSDoptind
# define optopt             BSDoptopt
# define optreset           BSDoptreset
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
# define ss_family __ss_family
#define timersub(a, b, result)					\
   do {								\
      (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      if ((result)->tv_usec < 0) {				\
	 --(result)->tv_sec;					\
	 (result)->tv_usec += 1000000;				\
      }								\
   } while (0)
#define timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#  define va_copy(dest, src) (dest) = (src)



#define debug(...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_DEBUG1, NULL, __VA_ARGS__)
#define debug2(...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_DEBUG2, NULL, __VA_ARGS__)
#define debug2_f(...)		sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_DEBUG2, NULL, __VA_ARGS__)
#define debug2_fr(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#define debug2_r(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#define debug3(...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_DEBUG3, NULL, __VA_ARGS__)
#define debug3_f(...)		sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_DEBUG3, NULL, __VA_ARGS__)
#define debug3_fr(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#define debug3_r(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#define debug_f(...)		sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_DEBUG1, NULL, __VA_ARGS__)
#define debug_fr(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#define debug_r(r, ...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#define do_log2(level, ...)	sshlog("__FILE__", __func__, "__LINE__", 0, level, NULL, __VA_ARGS__)
#define do_log2_f(level, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, level, NULL, __VA_ARGS__)
#define do_log2_fr(r, level, ...) sshlog("__FILE__", __func__, "__LINE__", 1, level, ssh_err(r), __VA_ARGS__)
#define do_log2_r(r, level, ...) sshlog("__FILE__", __func__, "__LINE__", 0, level, ssh_err(r), __VA_ARGS__)
#define error(...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_ERROR, NULL, __VA_ARGS__)
#define error_f(...)		sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_ERROR, NULL, __VA_ARGS__)
#define error_fr(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define error_r(r, ...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define fatal(...)		sshfatal("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_FATAL, NULL, __VA_ARGS__)
#define fatal_f(...)		sshfatal("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_FATAL, NULL, __VA_ARGS__)
#define fatal_fr(r, ...)	sshfatal("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#define fatal_r(r, ...)		sshfatal("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#define logdie(...)		sshlogdie("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_ERROR, NULL, __VA_ARGS__)
#define logdie_f(...)		sshlogdie("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_ERROR, NULL, __VA_ARGS__)
#define logdie_fr(r, ...)	sshlogdie("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define logdie_r(r, ...)	sshlogdie("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define logit(...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_INFO, NULL, __VA_ARGS__)
#define logit_f(...)		sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_INFO, NULL, __VA_ARGS__)
#define logit_fr(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#define logit_r(r, ...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#define sigdie(...)		sshsigdie("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_ERROR, NULL, __VA_ARGS__)
#define sigdie_f(...)		sshsigdie("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_ERROR, NULL, __VA_ARGS__)
#define sigdie_fr(r, ...)	sshsigdie("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define sigdie_r(r, ...)	sshsigdie("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define verbose(...)		sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_VERBOSE, NULL, __VA_ARGS__)
#define verbose_f(...)		sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_VERBOSE, NULL, __VA_ARGS__)
#define verbose_fr(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#define verbose_r(r, ...)	sshlog("__FILE__", __func__, "__LINE__", 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)



#define LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;				\
	struct type **le_prev;		\
}
#define LIST_FOREACH(var, head, field)					\
	for((var) = LIST_FIRST(head);					\
	    (var)!= LIST_END(head);					\
	    (var) = LIST_NEXT(var, field))
#define LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;				\
}
#define LIST_HEAD_INITIALIZER(head)					\
	{ NULL }
#define LIST_INSERT_AFTER(listelm, elm, field) do {			\
	if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)	\
		(listelm)->field.le_next->field.le_prev =		\
		    &(elm)->field.le_next;				\
	(listelm)->field.le_next = (elm);				\
	(elm)->field.le_prev = &(listelm)->field.le_next;		\
} while (0)
#define LIST_INSERT_HEAD(head, elm, field) do {				\
	if (((elm)->field.le_next = (head)->lh_first) != NULL)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} while (0)
#define LIST_REMOVE(elm, field) do {					\
	if ((elm)->field.le_next != NULL)				\
		(elm)->field.le_next->field.le_prev =			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
	_Q_INVALIDATE((elm)->field.le_prev);				\
	_Q_INVALIDATE((elm)->field.le_next);				\
} while (0)
#define LIST_REPLACE(elm, elm2, field) do {				\
	if (((elm2)->field.le_next = (elm)->field.le_next) != NULL)	\
		(elm2)->field.le_next->field.le_prev =			\
		    &(elm2)->field.le_next;				\
	(elm2)->field.le_prev = (elm)->field.le_prev;			\
	*(elm2)->field.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.le_prev);				\
	_Q_INVALIDATE((elm)->field.le_next);				\
} while (0)
#define SIMPLEQ_CONCAT(head1, head2) do {				\
	if (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} while (0)
#define SIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqe_next;				\
}
#define SIMPLEQ_FOREACH(var, head, field)				\
	for((var) = SIMPLEQ_FIRST(head);				\
	    (var) != SIMPLEQ_END(head);					\
	    (var) = SIMPLEQ_NEXT(var, field))
#define SIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqh_first;				\
	struct type **sqh_last;			\
}
#define SIMPLEQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).sqh_first }
#define SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(listelm)->field.sqe_next = (elm);				\
} while (0)
#define SIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)	\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(head)->sqh_first = (elm);					\
} while (0)
#define SIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqe_next = NULL;					\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &(elm)->field.sqe_next;			\
} while (0)
#define SIMPLEQ_REMOVE_AFTER(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (elm)->field.sqe_next->field.sqe_next) \
	    == NULL)							\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
} while (0)
#define SIMPLEQ_REMOVE_HEAD(head, field) do {			\
	if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL) \
		(head)->sqh_last = &(head)->sqh_first;			\
} while (0)
#define SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;				\
}
#define SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;				\
}
#define SLIST_REMOVE(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->slh_first;		\
									\
		while (curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
	}								\
	_Q_INVALIDATE((elm)->field.sle_next);				\
} while (0)
#define TAILQ_CONCAT(head1, head2, field) do {				\
	if (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} while (0)
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;				\
	struct type **tqe_prev;		\
}
#define TAILQ_FOREACH(var, head, field)					\
	for((var) = TAILQ_FIRST(head);					\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_NEXT(var, field))
#define TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for((var) = TAILQ_LAST(head, headname);				\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_PREV(var, headname, field))
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;				\
	struct type **tqh_last;			\
}
#define TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }
#define TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} while (0)
#define TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} while (0)
#define TAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (0)
#define TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#define TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define TAILQ_REMOVE(head, elm, field) do {				\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)
#define TAILQ_REPLACE(head, elm, elm2, field) do {			\
	if (((elm2)->field.tqe_next = (elm)->field.tqe_next) != NULL)	\
		(elm2)->field.tqe_next->field.tqe_prev =		\
		    &(elm2)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm2)->field.tqe_next;		\
	(elm2)->field.tqe_prev = (elm)->field.tqe_prev;			\
	*(elm2)->field.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)
#define XSIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqx_next;				\
}
#define XSIMPLEQ_FOREACH(var, head, field)				\
	for ((var) = XSIMPLEQ_FIRST(head);				\
	    (var) != XSIMPLEQ_END(head);				\
	    (var) = XSIMPLEQ_NEXT(head, var, field))
#define XSIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqx_first;				\
	struct type **sqx_last;			\
	unsigned long sqx_cookie;					\
}
#define XSIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqx_next = (listelm)->field.sqx_next) ==	\
	    XSIMPLEQ_XOR(head, NULL))					\
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next); \
	(listelm)->field.sqx_next = XSIMPLEQ_XOR(head, (elm));		\
} while (0)
#define XSIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqx_next = (head)->sqx_first) ==		\
	    XSIMPLEQ_XOR(head, NULL))					\
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next); \
	(head)->sqx_first = XSIMPLEQ_XOR(head, (elm));			\
} while (0)
#define XSIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqx_next = XSIMPLEQ_XOR(head, NULL);		\
	*(XSIMPLEQ_XOR(head, (head)->sqx_last)) = XSIMPLEQ_XOR(head, (elm)); \
	(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next);	\
} while (0)
#define XSIMPLEQ_REMOVE_AFTER(head, elm, field) do {			\
	if (((elm)->field.sqx_next = XSIMPLEQ_XOR(head,			\
	    (elm)->field.sqx_next)->field.sqx_next)			\
	    == XSIMPLEQ_XOR(head, NULL))				\
		(head)->sqx_last = 					\
		    XSIMPLEQ_XOR(head, &(elm)->field.sqx_next);		\
} while (0)
#define XSIMPLEQ_REMOVE_HEAD(head, field) do {				\
	if (((head)->sqx_first = XSIMPLEQ_XOR(head,			\
	    (head)->sqx_first)->field.sqx_next) == XSIMPLEQ_XOR(head, NULL)) \
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(head)->sqx_first); \
} while (0)
#define XSIMPLEQ_XOR(head, ptr)	    ((__typeof(ptr))((head)->sqx_cookie ^ \
					(unsigned long)(ptr)))
#define _Q_INVALID ((void *)-1)
#define _Q_INVALIDATE(a) (a) = _Q_INVALID
