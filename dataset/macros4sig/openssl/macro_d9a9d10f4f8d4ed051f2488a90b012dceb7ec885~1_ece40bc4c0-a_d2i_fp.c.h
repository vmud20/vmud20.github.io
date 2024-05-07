


















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
#define UP_read   (*(ossl_ssize_t (*)(int,void *,size_t))OPENSSL_UplinkTable[APPLINK_READ])
#define UP_stderr (*(void *(*)(void))OPENSSL_UplinkTable[APPLINK_STDERR])()
#define UP_stdin  (*(void *(*)(void))OPENSSL_UplinkTable[APPLINK_STDIN])()
#define UP_stdout (*(void *(*)(void))OPENSSL_UplinkTable[APPLINK_STDOUT])()
#define UP_write  (*(ossl_ssize_t (*)(int,const void *,size_t))OPENSSL_UplinkTable[APPLINK_WRITE])
#    define DEFAULT_HOME  ""
#    define DEVRANDOM "/dev/urandom\x24"
#define DEVRANDOM_EGD "/var/run/egd-pool","/dev/egd-pool","/etc/egd-pool","/etc/entropy"
#  define EXIT(n) exit(n)
#  define GETPID_IS_MEANINGLESS

#        define INVALID_SOCKET (int)(~0)
#define IPPROTO_IP 0
#  define LIST_SEPARATOR_CHAR ';'
#    define MAC_OS_pre_X
#  define MSDOS
#  define NO_CHMOD
#  define NO_DIRENT
#    define NO_SYSLOG
#  define NO_SYS_PARAM_H
#    define NO_SYS_TYPES_H

#  define OPENSSL_EXIT(n) return(n)
#  define OPENSSL_IMPLEMENTS_strncasecmp
#  define OPENSSL_NO_FP_API
#    define OPENSSL_NO_POSIX_IO
#      define OPENSSL_USE_IPV6 1
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#      define SHUTDOWN(fd)		close(fd)
#      define SHUTDOWN2(fd)		close(fd)
#define SO_ERROR 0
#      define SSLeay_Read(a,b,c)	(-1)
#      define SSLeay_Write(a,b,c)	(-1)
#define TTY_STRUCT int
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
#define get_last_socket_error()	WSAGetLastError()
#define get_last_sys_error()	GetLastError()
#define getpid taskIdSelf
#        define getservbyname _masked_declaration_getservbyname
# define memcmp OPENSSL_memcmp
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))
#define readsocket(s,b,n)	recv((s),(b),(n),0)
#define sleep(a) taskDelay((a) * sysClkRateGet())
#        define socket(d,t,p)	((int)socket(d,t,p))
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

