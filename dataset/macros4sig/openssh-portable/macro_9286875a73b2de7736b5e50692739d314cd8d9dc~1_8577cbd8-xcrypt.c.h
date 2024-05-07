#include<time.h>
#include<stdarg.h>

#include<unistd.h>
#include<sys/types.h>
#include<sys/mman.h>
#include<sys/dir.h>

#include<errno.h>






#include<sys/socket.h>

#include<termios.h>



#include<netinet/ip.h>



#include<stddef.h>



#include<sys/param.h>
#include<netinet/in_systm.h>









#include<netinet/in.h>


#include<pwd.h>

#include<stdio.h>



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
