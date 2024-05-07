


#include<sys/types.h>


#include<signal.h>
#include<netinet/in.h>
#include<sys/unistd.h>

#include<errno.h>
#include<sys/ttydefaults.h>

#include<sys/cdefs.h>

#include<sys/wait.h>






#include<fcntl.h>
#include<pwd.h>





#include<sys/dir.h>




#include<netinet/in_systm.h>

#include<sys/signal.h>


#include<sys/mman.h>
#include<sys/stat.h>
#include<sys/sysctl.h>

#include<stdarg.h>
#include<netinet/ip.h>




#include<sys/socket.h>







#define CURVE25519_SIZE 32


#define buffer_skip_string(b) \
    do { u_int l = buffer_get_int(b); buffer_consume(b, l); } while (0)





#define ASKPASS_PROGRAM         "/usr/lib/ssh/ssh-askpass"
#  define LOGIN_PROGRAM         LOGIN_PROGRAM_FALLBACK
#define _PATH_PASSWD_PROG             "/usr/bin/passwd"
#define _PATH_UNIX_X "/tmp/.X11-unix/X%u"




#define CHACHA_MINKEYLEN 	16

#define SSH_AUTHSOCKET_ENV_NAME "SSH_AUTH_SOCK"






#define _PWF(x)		(1 << x)
#define _PW_VERSIONED(x, v)	((unsigned char)(((x) & 0xCF) | ((v)<<4)))

#define AI_MASK \
    (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | \
    AI_ADDRCONFIG | AI_ALL | AI_V4MAPPED)

#define XLOCALE_ISCTYPE(__fname, __cat) \
		_XLOCALE_INLINE int is##__fname##_l(int, locale_t); \
		_XLOCALE_INLINE int is##__fname##_l(int __c, locale_t __l)\
		{ return __sbistype_l(__c, __cat, __l); }

#define _XLOCALE_INLINE extern __inline
#define _XLOCALE_RUN_FUNCTIONS_DEFINED 1

#define _CurrentRuneLocale (__getCurrentRuneLocale())

#define _GNU_SOURCE 

#define NGROUPS_MAX NGROUPS

#define dirent direct
#define wait(a) posix_wait(a)

#  define arc4random_stir()
# define mblen(x, y)	1


#define no_argument        0
#define optional_argument  2
#define required_argument  1


#define RPP_ECHO_OFF    0x00		
#define RPP_ECHO_ON     0x01		
#define RPP_FORCELOWER  0x04		
#define RPP_FORCEUPPER  0x08		
#define RPP_REQUIRE_TTY 0x02		
#define RPP_SEVENBIT    0x10		
#define RPP_STDIN       0x20		

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
#    define USE_UTMP
#    define USE_UTMPX
#  define USE_VHANGUP
#    define USE_WTMP
#    define USE_WTMPX
#      define UTMP_FILE CONF_UTMP_FILE
# define UT_LINESIZE 8
#      define WTMP_FILE CONF_WTMP_FILE
#    define X_UNIX_PATH "/var/spool/sockets/X11/%u"

#  define _NSIG NSIG
# define _PATH_BSHELL "/bin/sh"
# define _PATH_BTMP BTMP_FILE
# define _PATH_DEVNULL "/dev/null"
# define _PATH_MAILDIR MAIL_DIRECTORY
# define _PATH_NOLOGIN "/etc/nologin"
# define _PATH_STDPATH USER_PATH
# define _PATH_TTY "/dev/tty"
#define _PATH_XAUTH XAUTH_PATH


# define __P(x) x
# define __attribute__(x)
# define __bounded__(x, y, z)
#  define __func__ __FUNCTION__
# define __nonnull__(x)
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
#define BROKEN_GLOB 1
#define BROKEN_STRNVIS 1
#define DISABLE_LASTLOG 1
#define DISABLE_UTMP 1
#define DISABLE_WTMP 1
#define DISABLE_WTMPX 1
#define ENABLE_PKCS11 
#define GETPGRP_VOID 1
#define GLOB_HAS_ALTDIRFUNC 1
#define GLOB_HAS_GL_MATCHC 1
#define HAVE_ARC4RANDOM 1
#define HAVE_ARC4RANDOM_BUF 1
#define HAVE_ARC4RANDOM_STIR 1
#define HAVE_ARC4RANDOM_UNIFORM 1
#define HAVE_ASPRINTF 1
#define HAVE_ATTRIBUTE__NONNULL__ 1
#define HAVE_BASENAME 1
#define HAVE_BCOPY 1
#define HAVE_BINDRESVPORT_SA 1
#define HAVE_BN_IS_PRIME_EX 1
#define HAVE_CAP_RIGHTS_LIMIT 1
#define HAVE_CLOCK 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_CLOSEFROM 1
#define HAVE_CONST_GAI_STRERROR_PROTO 1
#define HAVE_CONTROL_IN_MSGHDR 1
#define HAVE_CRYPT 1
#define HAVE_DAEMON 1
#define HAVE_DECL_GLOB_NOMATCH 1
#define HAVE_DECL_HOWMANY 1
#define HAVE_DECL_H_ERRNO 1
#define HAVE_DECL_MAXSYMLINKS 1
#define HAVE_DECL_NFDBITS 1
#define HAVE_DECL_OFFSETOF 1
#define HAVE_DECL_O_NONBLOCK 1
#define HAVE_DECL_SHUT_RD 1
#define HAVE_DECL_WRITEV 1
#define HAVE_DECL__GETLONG 0
#define HAVE_DECL__GETSHORT 0
#define HAVE_DES_CRYPT 1
#define HAVE_DIRENT_H 1
#define HAVE_DIRFD 1
#define HAVE_DIRNAME 1
#define HAVE_DSA_GENERATE_PARAMETERS_EX 1
#define HAVE_ELF_H 1
#define HAVE_ENDGRENT 1
#define HAVE_ENDUTXENT 1
#define HAVE_EVP_CIPHER_CTX_CTRL 1
#define HAVE_EVP_DIGESTFINAL_EX 1
#define HAVE_EVP_DIGESTINIT_EX 1
#define HAVE_EVP_MD_CTX_CLEANUP 1
#define HAVE_EVP_MD_CTX_COPY_EX 1
#define HAVE_EVP_MD_CTX_INIT 1
#define HAVE_EVP_SHA256 1
#define HAVE_FCHMOD 1
#define HAVE_FCHOWN 1
#define HAVE_FCNTL_H 1
#define HAVE_FD_MASK 1
#define HAVE_FLOATINGPOINT_H 1
#define HAVE_FREEADDRINFO 1
#define HAVE_FSBLKCNT_T 1
#define HAVE_FSFILCNT_T 1
#define HAVE_FSTATFS 1
#define HAVE_FSTATVFS 1
#define HAVE_FUTIMES 1
#define HAVE_GAI_STRERROR 1
#define HAVE_GETCWD 1
#define HAVE_GETGROUPLIST 1
#define HAVE_GETNAMEINFO 1
#define HAVE_GETOPT 1
#define HAVE_GETOPT_H 1
#define HAVE_GETOPT_OPTRESET 1
#define HAVE_GETPAGESIZE 1
#define HAVE_GETPEEREID 1
#define HAVE_GETPGID 1
#define HAVE_GETPGRP 1
#define HAVE_GETRLIMIT 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_GETTTYENT 1
#define HAVE_GETUTXENT 1
#define HAVE_GETUTXID 1
#define HAVE_GETUTXLINE 1
#define HAVE_GETUTXUSER 1
#define HAVE_GLOB 1
#define HAVE_GLOB_H 1
#define HAVE_GROUP_FROM_GID 1
#define HAVE_HEADER_AD 1
#define HAVE_HMAC_CTX_INIT 1
#define HAVE_HOST_IN_UTMPX 1
#define HAVE_ID_IN_UTMPX 1
#define HAVE_INET_ATON 1
#define HAVE_INET_NTOA 1
#define HAVE_INET_NTOP 1
#define HAVE_INNETGR 1
#define HAVE_INT64_T 1
#define HAVE_INTMAX_T 1
#define HAVE_INTTYPES_H 1
#define HAVE_INTXX_T 1
#define HAVE_IN_ADDR_T 1
#define HAVE_IN_PORT_T 1
#define HAVE_ISBLANK 1
#define HAVE_LIBGEN_H 1
#define HAVE_LIBPAM 1
#define HAVE_LIBUTIL_H 1
#define HAVE_LIBZ 1
#define HAVE_LIMITS_H 1
#define HAVE_LOCALE_H 1
#define HAVE_LOGIN_CAP_H 1
#define HAVE_LOGIN_GETCAPBOOL 1
#define HAVE_LONG_DOUBLE 1
#define HAVE_LONG_LONG 1
#define HAVE_MBLEN 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMORY_H 1
#define HAVE_MKDTEMP 1
#define HAVE_MMAP 1
#define HAVE_NANOSLEEP 1
#define HAVE_NETDB_H 1
#define HAVE_NET_IF_TUN_H 1
#define HAVE_OPENPTY 1
#define HAVE_OPENSSL 1
#define HAVE_PAM_GETENVLIST 1
#define HAVE_PAM_PUTENV 1
#define HAVE_PATHS_H 1
#define HAVE_POLL 1
#define HAVE_POLL_H 1
#define HAVE_PUTUTXLINE 1
#define HAVE_READPASSPHRASE 1
#define HAVE_READPASSPHRASE_H 1
#define HAVE_REALPATH 1
#define HAVE_RECVMSG 1
#define HAVE_RLIMIT_NPROC 
#define HAVE_RPC_TYPES_H 1
#define HAVE_RRESVPORT_AF 1
#define HAVE_RSA_GENERATE_KEY_EX 1
#define HAVE_RSA_GET_DEFAULT_METHOD 1
#define HAVE_SECURITY_PAM_APPL_H 1
#define HAVE_SENDMSG 1
#define HAVE_SETEGID 1
#define HAVE_SETENV 1
#define HAVE_SETEUID 1
#define HAVE_SETGROUPENT 1
#define HAVE_SETGROUPS 1
#define HAVE_SETLINEBUF 1
#define HAVE_SETLOGIN 1
#define HAVE_SETPASSENT 1
#define HAVE_SETPROCTITLE 1
#define HAVE_SETREGID 1
#define HAVE_SETRESGID 1
#define HAVE_SETRESUID 1
#define HAVE_SETREUID 1
#define HAVE_SETRLIMIT 1
#define HAVE_SETSID 1
#define HAVE_SETUTXDB 1
#define HAVE_SETUTXENT 1
#define HAVE_SETVBUF 1
#define HAVE_SHA256_UPDATE 1
#define HAVE_SIGACTION 1
#define HAVE_SIGVEC 1
#define HAVE_SNPRINTF 1
#define HAVE_SOCKETPAIR 1
#define HAVE_SS_FAMILY_IN_SS 1
#define HAVE_STATFS 1
#define HAVE_STATVFS 1
#define HAVE_STDDEF_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRERROR 1
#define HAVE_STRFTIME 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_STRLCAT 1
#define HAVE_STRLCPY 1
#define HAVE_STRMODE 1
#define HAVE_STRNLEN 1
#define HAVE_STRNVIS 1
#define HAVE_STRPTIME 1
#define HAVE_STRSEP 1
#define HAVE_STRTOLL 1
#define HAVE_STRTONUM 1
#define HAVE_STRTOUL 1
#define HAVE_STRTOULL 1
#define HAVE_STRUCT_ADDRINFO 1
#define HAVE_STRUCT_IN6_ADDR 1
#define HAVE_STRUCT_PASSWD_PW_CHANGE 1
#define HAVE_STRUCT_PASSWD_PW_CLASS 1
#define HAVE_STRUCT_PASSWD_PW_EXPIRE 1
#define HAVE_STRUCT_PASSWD_PW_GECOS 1
#define HAVE_STRUCT_SOCKADDR_IN6 1
#define HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID 1
#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#define HAVE_STRUCT_STAT_ST_BLKSIZE 1
#define HAVE_STRUCT_TIMESPEC 1
#define HAVE_STRUCT_TIMEVAL 1
#define HAVE_SYSCONF 1
#define HAVE_SYS_CAPABILITY_H 1
#define HAVE_SYS_CDEFS_H 1
#define HAVE_SYS_DIR_H 1
#define HAVE_SYS_ERRLIST 1
#define HAVE_SYS_MMAN_H 1
#define HAVE_SYS_MOUNT_H 1
#define HAVE_SYS_NERR 1
#define HAVE_SYS_POLL_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_STATVFS_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIMERS_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_TCGETPGRP 1
#define HAVE_TCSENDBREAK 1
#define HAVE_TIME 1
#define HAVE_TIME_H 1
#define HAVE_TRUNCATE 1
#define HAVE_TTYENT_H 1
#define HAVE_TV_IN_UTMPX 1
#define HAVE_TYPE_IN_UTMPX 1
#define HAVE_UINTMAX_T 1
#define HAVE_UINTXX_T 1
#define HAVE_UNISTD_H 1
#define HAVE_UNSETENV 1
#define HAVE_UNSIGNED_LONG_LONG 1
#define HAVE_USER_FROM_UID 1
#define HAVE_USLEEP 1
#define HAVE_UTIMES 1
#define HAVE_UTIME_H 1
#define HAVE_UTMPX_H 1
#define HAVE_U_INT 1
#define HAVE_U_INT64_T 1
#define HAVE_VASPRINTF 1
#define HAVE_VA_COPY 1
#define HAVE_VIS_H 1
#define HAVE_VSNPRINTF 1
#define HAVE_WAITPID 1
#define HAVE__GETLONG 1
#define HAVE__GETSHORT 1
#define HAVE__RES_EXTERN 1
#define HAVE___B64_NTOP 1
#define HAVE___B64_PTON 1
#define HAVE___FUNCTION__ 1
#define HAVE___PROGNAME 1
#define HAVE___VA_COPY 1
#define HAVE___func__ 1
#define LIBWRAP 1
#define LOCKED_PASSWD_PREFIX "*LOCKED*"
#define LOGIN_PROGRAM_FALLBACK "/usr/bin/login"
#define OPENSSL_HAS_ECC 1
#define OPENSSL_HAS_NISTP256 1
#define OPENSSL_HAS_NISTP384 1
#define OPENSSL_HAS_NISTP521 1
#define OPENSSL_HAVE_EVPCTR 1
#define OPENSSL_HAVE_EVPGCM 1
#define OPENSSL_PRNG_ONLY 1
#define PACKAGE_BUGREPORT "openssh-unix-dev@mindrot.org"
#define PACKAGE_NAME "OpenSSH"
#define PACKAGE_STRING "OpenSSH Portable"
#define PACKAGE_TARNAME "openssh"
#define PACKAGE_URL ""
#define PACKAGE_VERSION "Portable"
#define SANDBOX_CAPSICUM 1
#define SANDBOX_SKIP_RLIMIT_NOFILE 1
#define SIZEOF_INT 4
#define SIZEOF_LONG_INT 8
#define SIZEOF_LONG_LONG_INT 8
#define SIZEOF_SHORT_INT 2
#define SNPRINTF_CONST const
#define SSH_PRIVSEP_USER "sshd"
#define SSH_TUN_FREEBSD 1
#define STDC_HEADERS 1
#define USE_LIBEDIT 1
#define USE_OPENSSL_ENGINE 1
#define USE_PAM 1
#  define WORDS_BIGENDIAN 1
#define _PATH_SSH_PIDDIR "/var/run"
