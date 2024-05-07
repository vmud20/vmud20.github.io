#include<time.h>
#include<stdarg.h>

#include<signal.h>
#include<sys/types.h>

#include<sys/mman.h>
#include<sys/dir.h>


#include<errno.h>








#include<sys/socket.h>

#include<termios.h>




#include<netinet/ip.h>




#include<stddef.h>



#include<sys/param.h>
#include<string.h>
#include<netinet/in_systm.h>










#include<netinet/in.h>


#include<pwd.h>

#include<shadow.h>
#include<stdio.h>




#define SKEY_PROMPT "\nS/Key Password: "
# define _SSH_AUDIT_H
#define LINFO_HOSTSIZE 256
#define LINFO_LINESIZE 64
#define LINFO_NAMESIZE 512
#define LINFO_PROGSIZE 64
#define LTYPE_LOGIN    7
#define LTYPE_LOGOUT   8


#define _GNU_SOURCE 


#define buffer_clear(b)		sshbuf_reset(b)
#define buffer_dump(b)		sshbuf_dump(b, stderr)
#define buffer_free(b)		sshbuf_free(b)
#define buffer_init(b)		sshbuf_init(b)
#define buffer_len(b)		((u_int) sshbuf_len(b))
#define buffer_skip_string(b) (void)buffer_get_string_ptr(b, NULL);
#define PEEK_U16(p) \
	(((u_int16_t)(((const u_char *)(p))[0]) << 8) | \
	  (u_int16_t)(((const u_char *)(p))[1]))
#define PEEK_U32(p) \
	(((u_int32_t)(((const u_char *)(p))[0]) << 24) | \
	 ((u_int32_t)(((const u_char *)(p))[1]) << 16) | \
	 ((u_int32_t)(((const u_char *)(p))[2]) << 8) | \
	  (u_int32_t)(((const u_char *)(p))[3]))
#define PEEK_U64(p) \
	(((u_int64_t)(((const u_char *)(p))[0]) << 56) | \
	 ((u_int64_t)(((const u_char *)(p))[1]) << 48) | \
	 ((u_int64_t)(((const u_char *)(p))[2]) << 40) | \
	 ((u_int64_t)(((const u_char *)(p))[3]) << 32) | \
	 ((u_int64_t)(((const u_char *)(p))[4]) << 24) | \
	 ((u_int64_t)(((const u_char *)(p))[5]) << 16) | \
	 ((u_int64_t)(((const u_char *)(p))[6]) << 8) | \
	  (u_int64_t)(((const u_char *)(p))[7]))
#define POKE_U16(p, v) \
	do { \
		const u_int16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} while (0)
#define POKE_U32(p, v) \
	do { \
		const u_int32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} while (0)
#define POKE_U64(p, v) \
	do { \
		const u_int64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} while (0)
#  define SSHBUF_ABORT()
#  define SSHBUF_DBG(x) do { \
		printf("%s:%d %s: ", "__FILE__", "__LINE__", __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} while (0)
#  define SSHBUF_TELL(what) do { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    "__FILE__", "__LINE__", __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} while (0)

#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, NULL, NULL)
#define NGROUPS_MAX NGROUPS

#define dirent direct
#define wait(a) posix_wait(a)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
#   define FD_SET(n, set)	kludge_FD_SET(n, set)

#  define arc4random_stir()
# define mblen(x, y)	(1)
# define nl_langinfo(x)	""
#  define realpath(x, y) _ssh_compat_realpath(x, y)
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)


#define no_argument        0
#define optional_argument  2
#define required_argument  1
# define ALIGN(p) (((unsigned)p + ALIGNBYTES) & ~ALIGNBYTES)
# define ALIGNBYTES (sizeof(int) - 1)
#  define BIG_ENDIAN     4321
#   define BROKEN_REALPATH 1
#  define BYTE_ORDER BIG_ENDIAN
#define CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= sizeof(struct cmsghdr) ? \
	 (struct cmsghdr *)(mhdr)->msg_control : \
	 (struct cmsghdr *)NULL)
# define CUSTOM_FAILED_LOGIN
# define CUSTOM_SSH_AUDIT_EVENTS
# define CUSTOM_SYS_AUTH_PASSWD 1
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
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#define INADDR_LOOPBACK ((u_long)0x7f000001)
#define INET6_ADDRSTRLEN 46
# define IPTOS_LOWCOST           0x02
# define IPTOS_LOWDELAY          0x10
# define IPTOS_MINCOST           IPTOS_LOWCOST
# define IPTOS_RELIABILITY       0x04
# define IPTOS_THROUGHPUT        0x08
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#  define LITTLE_ENDIAN  1234
#define MAP_ANON MAP_ANONYMOUS
# define MAP_FAILED ((void *)-1)
# define MAX(a,b) (((a)>(b))?(a):(b))
#  define MAXPATHLEN 64
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
# define _compat_skeychallenge(a,b,c,d) skeychallenge(a,b,c,d)
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
#  define va_copy(dest, src) __va_copy(dest, src)


#define fp_rep sshkey_fp_rep
#define fp_type sshkey_fp_type
#define types sshkey_types

#define COPY_MATCH_STRING_OPTS() do { \
		M_CP_STROPT(banner); \
		M_CP_STROPT(trusted_user_ca_keys); \
		M_CP_STROPT(revoked_keys_file); \
		M_CP_STROPT(authorized_keys_command); \
		M_CP_STROPT(authorized_keys_command_user); \
		M_CP_STROPT(authorized_principals_file); \
		M_CP_STROPT(authorized_principals_command); \
		M_CP_STROPT(authorized_principals_command_user); \
		M_CP_STROPT(hostbased_key_types); \
		M_CP_STROPT(pubkey_key_types); \
		M_CP_STRARRAYOPT(authorized_keys_files, num_authkeys_files); \
		M_CP_STRARRAYOPT(allow_users, num_allow_users); \
		M_CP_STRARRAYOPT(deny_users, num_deny_users); \
		M_CP_STRARRAYOPT(allow_groups, num_allow_groups); \
		M_CP_STRARRAYOPT(deny_groups, num_deny_groups); \
		M_CP_STRARRAYOPT(accept_env, num_accept_env); \
		M_CP_STRARRAYOPT(auth_methods, num_auth_methods); \
	} while (0)




#define packet_add_padding(pad) \
	sshpkt_add_padding(active_state, (pad))
#define packet_check_eom() \
	ssh_packet_check_eom(active_state)
#define packet_connection_is_on_socket() \
	ssh_packet_connection_is_on_socket(active_state)
#define packet_get_bignum(value) \
	ssh_packet_get_bignum(active_state, (value))
#define packet_get_bignum2(value) \
	ssh_packet_get_bignum2(active_state, (value))
#define packet_get_bytes(x,y) \
	ssh_packet_get_bytes(active_state, x, y)
#define packet_get_connection_in() \
	ssh_packet_get_connection_in(active_state)
#define packet_get_connection_out() \
	ssh_packet_get_connection_out(active_state)
#define packet_get_cstring(length_ptr) \
	ssh_packet_get_cstring(active_state, (length_ptr))
#define packet_get_ecpoint(c,p) \
	ssh_packet_get_ecpoint(active_state, c, p)
#define packet_get_input() \
	ssh_packet_get_input(active_state)
#define packet_get_int64() \
	ssh_packet_get_int64(active_state)
#define packet_get_maxsize() \
	ssh_packet_get_maxsize(active_state)
#define packet_get_output() \
	ssh_packet_get_output(active_state)
#define packet_get_protocol_flags() \
	ssh_packet_get_protocol_flags(active_state)
#define packet_get_raw(lenp) \
        sshpkt_ptr(active_state, lenp)
#define packet_get_rekey_timeout() \
	ssh_packet_get_rekey_timeout(active_state)
#define packet_get_state(m) \
	ssh_packet_get_state(active_state, m)
#define packet_get_string(length_ptr) \
	ssh_packet_get_string(active_state, (length_ptr))
#define packet_get_string_ptr(length_ptr) \
	ssh_packet_get_string_ptr(active_state, (length_ptr))
#define packet_have_data_to_write() \
	ssh_packet_have_data_to_write(active_state)
#define packet_inc_alive_timeouts() \
	ssh_packet_inc_alive_timeouts(active_state)
#define packet_is_interactive() \
	ssh_packet_is_interactive(active_state)
#define packet_not_very_much_data_to_write() \
	ssh_packet_not_very_much_data_to_write(active_state)
#define packet_put_bignum(value) \
	ssh_packet_put_bignum(active_state, (value))
#define packet_put_bignum2(value) \
	ssh_packet_put_bignum2(active_state, (value))
#define packet_put_char(value) \
	ssh_packet_put_char(active_state, (value))
#define packet_put_cstring(str) \
	ssh_packet_put_cstring(active_state, (str))
#define packet_put_ecpoint(c,p) \
	ssh_packet_put_ecpoint(active_state, c, p)
#define packet_put_int(value) \
	ssh_packet_put_int(active_state, (value))
#define packet_put_int64(value) \
	ssh_packet_put_int64(active_state, (value))
#define packet_put_raw(buf, len) \
	ssh_packet_put_raw(active_state, (buf), (len))
#define packet_put_string( buf, len) \
	ssh_packet_put_string(active_state, (buf), (len))
#define packet_read() \
	ssh_packet_read(active_state)
#define packet_remaining() \
	ssh_packet_remaining(active_state)
#define packet_send() \
	ssh_packet_send(active_state)
#define packet_send_ignore(nbytes) \
	ssh_packet_send_ignore(active_state, (nbytes))
#define packet_set_alive_timeouts(ka) \
	ssh_packet_set_alive_timeouts(active_state, (ka))
#define packet_set_authenticated() \
	ssh_packet_set_authenticated(active_state)
#define packet_set_compress_hooks(ctx, allocfunc, freefunc) \
	ssh_packet_set_compress_hooks(active_state, ctx, \
	    allocfunc, freefunc);
#define packet_set_encryption_key(key, keylen, number) \
	ssh_packet_set_encryption_key(active_state, (key), (keylen), (number))
#define packet_set_interactive(interactive, qos_interactive, qos_bulk) \
	ssh_packet_set_interactive(active_state, (interactive), (qos_interactive), (qos_bulk))
#define packet_set_maxsize(s) \
	ssh_packet_set_maxsize(active_state, (s))
#define packet_set_nonblocking() \
	ssh_packet_set_nonblocking(active_state)
#define packet_set_protocol_flags(protocol_flags) \
	ssh_packet_set_protocol_flags(active_state, (protocol_flags))
#define packet_set_rekey_limits(x,y) \
	ssh_packet_set_rekey_limits(active_state, x, y)
#define packet_set_server() \
	ssh_packet_set_server(active_state)
#define packet_set_state(m) \
	ssh_packet_set_state(active_state, m)
#define packet_set_timeout(timeout, count) \
	ssh_packet_set_timeout(active_state, (timeout), (count))
#define packet_start(type) \
	ssh_packet_start(active_state, (type))
#define packet_start_compression(level) \
	ssh_packet_start_compression(active_state, (level))
#define set_newkeys(mode) \
	ssh_set_newkeys(active_state, (mode))
#define ssh_packet_check_eom(ssh) \
do { \
	int _len = ssh_packet_remaining(ssh); \
	if (_len > 0) { \
		logit("Packet integrity error (%d bytes remaining) at %s:%d", \
		    _len ,"__FILE__", "__LINE__"); \
		ssh_packet_disconnect(ssh, \
		    "Packet integrity error."); \
	} \
} while (0)
#define CIRCLEQ_ENTRY(type)						\
struct {								\
	struct type *cqe_next;				\
	struct type *cqe_prev;				\
}
#define CIRCLEQ_FOREACH(var, head, field)				\
	for((var) = CIRCLEQ_FIRST(head);				\
	    (var) != CIRCLEQ_END(head);					\
	    (var) = CIRCLEQ_NEXT(var, field))
#define CIRCLEQ_FOREACH_REVERSE(var, head, field)			\
	for((var) = CIRCLEQ_LAST(head);					\
	    (var) != CIRCLEQ_END(head);					\
	    (var) = CIRCLEQ_PREV(var, field))
#define CIRCLEQ_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;				\
	struct type *cqh_last;				\
}
#define CIRCLEQ_HEAD_INITIALIZER(head)					\
	{ CIRCLEQ_END(&head), CIRCLEQ_END(&head) }
#define CIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm)->field.cqe_next;		\
	(elm)->field.cqe_prev = (listelm);				\
	if ((listelm)->field.cqe_next == CIRCLEQ_END(head))		\
		(head)->cqh_last = (elm);				\
	else								\
		(listelm)->field.cqe_next->field.cqe_prev = (elm);	\
	(listelm)->field.cqe_next = (elm);				\
} while (0)
#define CIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm);				\
	(elm)->field.cqe_prev = (listelm)->field.cqe_prev;		\
	if ((listelm)->field.cqe_prev == CIRCLEQ_END(head))		\
		(head)->cqh_first = (elm);				\
	else								\
		(listelm)->field.cqe_prev->field.cqe_next = (elm);	\
	(listelm)->field.cqe_prev = (elm);				\
} while (0)
#define CIRCLEQ_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.cqe_next = (head)->cqh_first;			\
	(elm)->field.cqe_prev = CIRCLEQ_END(head);			\
	if ((head)->cqh_last == CIRCLEQ_END(head))			\
		(head)->cqh_last = (elm);				\
	else								\
		(head)->cqh_first->field.cqe_prev = (elm);		\
	(head)->cqh_first = (elm);					\
} while (0)
#define CIRCLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.cqe_next = CIRCLEQ_END(head);			\
	(elm)->field.cqe_prev = (head)->cqh_last;			\
	if ((head)->cqh_first == CIRCLEQ_END(head))			\
		(head)->cqh_first = (elm);				\
	else								\
		(head)->cqh_last->field.cqe_next = (elm);		\
	(head)->cqh_last = (elm);					\
} while (0)
#define CIRCLEQ_REPLACE(head, elm, elm2, field) do {			\
	if (((elm2)->field.cqe_next = (elm)->field.cqe_next) ==		\
	    CIRCLEQ_END(head))						\
		(head).cqh_last = (elm2);				\
	else								\
		(elm2)->field.cqe_next->field.cqe_prev = (elm2);	\
	if (((elm2)->field.cqe_prev = (elm)->field.cqe_prev) ==		\
	    CIRCLEQ_END(head))						\
		(head).cqh_first = (elm2);				\
	else								\
		(elm2)->field.cqe_prev->field.cqe_next = (elm2);	\
	_Q_INVALIDATE((elm)->field.cqe_prev);				\
	_Q_INVALIDATE((elm)->field.cqe_next);				\
} while (0)
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
		_Q_INVALIDATE((elm)->field.sle_next);			\
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
#define _Q_INVALIDATE(a) (a) = ((void *)-1)
