

#include<limits.h>
#include<stdio.h>





#include<string.h>
#include<stddef.h>



#include<assert.h>





#include<stdlib.h>
#   define BN_UMULT_HIGH(a,b)	(BN_ULONG)asm("umulh %a0,%a1,%v0",(a),(b))
#  define BN_window_bits_for_ctime_exponent_size(b) \
		((b) > 937 ? 6 : \
		 (b) > 306 ? 5 : \
		 (b) >  89 ? 4 : \
		 (b) >  22 ? 3 : 1)
#define BN_window_bits_for_exponent_size(b) \
		((b) > 671 ? 6 : \
		 (b) > 239 ? 5 : \
		 (b) >  79 ? 4 : \
		 (b) >  23 ? 3 : 1)

#define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)
#define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
#define bn_clear_top2max(a) \
	{ \
	int      ind = (a)->dmax - (a)->top; \
	BN_ULONG *ftl = &(a)->d[(a)->top-1]; \
	for (; ind != 0; ind--) \
		*(++ftl) = 0x0; \
	}
#define mul(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}
#define mul_add(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (r) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}
#define sqr(r0,r1,a) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)(a)*(a); \
	(r0)=Lw(t); \
	(r1)=Hw(t); \
	}
#define BIO_FLAGS_UPLINK 0x8000
#define DECIMAL_SIZE(type)	((sizeof(type)*8+2)/3+1)

#define HEX_SIZE(type)		(sizeof(type)*2)
#define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

#define UP_clearerr (*(void (*)(void *))OPENSSL_UplinkTable[APPLINK_CLEARERR])
#define UP_close  (*(int (*)(int))OPENSSL_UplinkTable[APPLINK_CLOSE])
#define UP_fclose (*(int (*)(void *))OPENSSL_UplinkTable[APPLINK_FCLOSE])
#define UP_feof   (*(int (*)(void *))OPENSSL_UplinkTable[APPLINK_FEOF])
#define UP_ferror (*(int (*)(void *))OPENSSL_UplinkTable[APPLINK_FERROR])
#define UP_fflush (*(int (*)(void *))OPENSSL_UplinkTable[APPLINK_FFLUSH])
#define UP_fgets  (*(char *(*)(char *,int,void *))OPENSSL_UplinkTable[APPLINK_FGETS])
#define UP_fileno (*(int (*)(void *))OPENSSL_UplinkTable[APPLINK_FILENO])
#define UP_fopen  (*(void *(*)(const char *,const char *))OPENSSL_UplinkTable[APPLINK_FOPEN])
#define UP_fprintf (*(int (*)(void *,const char *,...))OPENSSL_UplinkTable[APPLINK_FPRINTF])
#define UP_fread  (*(size_t (*)(void *,size_t,size_t,void *))OPENSSL_UplinkTable[APPLINK_FREAD])
#define UP_fseek  (*(int (*)(void *,long,int))OPENSSL_UplinkTable[APPLINK_FSEEK])
#define UP_fsetmod (*(int (*)(void *,char))OPENSSL_UplinkTable[APPLINK_FSETMOD])
#define UP_ftell  (*(long (*)(void *))OPENSSL_UplinkTable[APPLINK_FTELL])
#define UP_fwrite (*(size_t (*)(const void *,size_t,size_t,void *))OPENSSL_UplinkTable[APPLINK_FWRITE])
#define UP_lseek  (*(long (*)(int,long,int))OPENSSL_UplinkTable[APPLINK_LSEEK])
#define UP_open   (*(int (*)(const char *,int,...))OPENSSL_UplinkTable[APPLINK_OPEN])
#define UP_read   (*(ssize_t (*)(int,void *,size_t))OPENSSL_UplinkTable[APPLINK_READ])
#define UP_stderr (*(void *(*)(void))OPENSSL_UplinkTable[APPLINK_STDERR])()
#define UP_stdin  (*(void *(*)(void))OPENSSL_UplinkTable[APPLINK_STDIN])()
#define UP_stdout (*(void *(*)(void))OPENSSL_UplinkTable[APPLINK_STDOUT])()
#define UP_write  (*(ssize_t (*)(int,const void *,size_t))OPENSSL_UplinkTable[APPLINK_WRITE])
#    define DEFAULT_HOME  ""
#    define DEVRANDOM "/dev/urandom\x24"
#define DEVRANDOM_EGD "/var/run/egd-pool","/dev/egd-pool","/etc/egd-pool","/etc/entropy"
#    define EXIT(n)		do { int __VMS_EXIT = n; \
                                     if (__VMS_EXIT == 0) \
				       __VMS_EXIT = 1; \
				     else \
				       __VMS_EXIT = (n << 3) | 2; \
                                     __VMS_EXIT |= 0x10000000; \
				     exit(__VMS_EXIT); } while(0)
#define FIONBIO SO_NONBLOCK
#  define GETPID_IS_MEANINGLESS

#        define INVALID_SOCKET (int)(~0)
#define IPPROTO_IP 0
#    define LIST_SEPARATOR_CHAR ','
#    define MAC_OS_pre_X
#  define MSDOS
#  define MS_CALLBACK
#  define MS_FAR
#  define MS_STATIC
#  define NO_CHMOD
#  define NO_DIRENT
#    define NO_SYSLOG
#      define NO_SYS_PARAM_H
#    define NO_SYS_TYPES_H

#    define OPENSSL_CONF   "openssl.cnf"
#  define OPENSSL_EXIT(n) return(n)
#  define OPENSSL_IMPLEMENTS_strncasecmp
#  define OPENSSL_NO_FP_API
#    define OPENSSL_NO_POSIX_IO
#      define OPENSSL_USE_IPV6 1
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#    define RFILE    ".rnd"
#      define SHUTDOWN(fd)		close(fd)
#      define SHUTDOWN2(fd)		close(fd)
#define SO_ERROR 0
#    define SSLEAY_CONF    OPENSSL_CONF
#      define SSLeay_Read(a,b,c)	(-1)
#      define SSLeay_Write(a,b,c)	(-1)
#  define SSLeay_getpid()	getpid()
#define TTY_STRUCT int
#    define VMS 1

#  define WIN32
#  define WINDOWS

#    define _O_BINARY O_BINARY
#    define _O_TEXT O_TEXT
#      define _WIN32_WINNT 0x0400
#    define _int64 __int64
#    define _kbhit kbhit
#    define _setmode setmode
#        define accept(s,f,l)	((int)accept(s,f,l))
#define clear_socket_error()	WSASetLastError(0)
#define clear_sys_error()	SetLastError(0)
#define closesocket(s)		close_s(s)
#define get_last_socket_error()	WSAGetLastError()
#define get_last_sys_error()	GetLastError()
#      define getpid GetThreadID
#        define getservbyname _masked_declaration_getservbyname
#define ioctlsocket(a,b,c)      ioctl(a,b,c)
# define memcmp OPENSSL_memcmp
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))
#      define pid_t int 
#define readsocket(s,b,n)	recv((s),(b),(n),0)
#      define setvbuf(a, b, c, d) setbuffer((a), (b), (d))
#define sleep(a) taskDelay((a) * sysClkRateGet())
#        define socket(d,t,p)	((int)socket(d,t,p))
#      define ssize_t int 
#        define stderr (&__iob_func()[2])
#        define stdin  (&__iob_func()[0])
#        define stdout (&__iob_func()[1])
#    define strcasecmp stricmp
# define strerror(errnum) \
	(((errnum)<0 || (errnum)>=sys_nerr) ? NULL : sys_errlist[errnum])
#      define strlen(s) _strlen31(s)
#    define strncasecmp strnicmp
# define strtoul(s,e,b) ((unsigned long int)strtol((s),(e),(b)))
#define writesocket(s,b,n)	send((s),(b),(n),0)

