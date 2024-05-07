





















#include<bits/types.h>







#define OE_LOG_MESSAGE_LEN_MAX 2048U
#define OE_MAX_FILENAME_LEN 256U
#define OE_TRACE(level, ...)        \
    do                              \
    {                               \
        oe_log(level, __VA_ARGS__); \
    } while (0)
#define OE_TRACE_ERROR(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_ERROR,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        "__FILE__",                \
        __FUNCTION__,            \
        "__LINE__")
#define OE_TRACE_FATAL(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_FATAL,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        "__FILE__",                \
        __FUNCTION__,            \
        "__LINE__")
#define OE_TRACE_INFO(fmt, ...) \
    OE_TRACE(                   \
        OE_LOG_LEVEL_INFO,      \
        fmt " [%s:%s:%d]\n",    \
        ##__VA_ARGS__,          \
        "__FILE__",               \
        __FUNCTION__,           \
        "__LINE__")
#define OE_TRACE_VERBOSE(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_VERBOSE,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        "__FILE__",                  \
        __FUNCTION__,              \
        "__LINE__")
#define OE_TRACE_WARNING(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_WARNING,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        "__FILE__",                  \
        __FUNCTION__,              \
        "__LINE__")


#define OE_CHAR_BIT 8
#define OE_CHAR_MAX 127
#define OE_CHAR_MIN (-128)
#define OE_INT16_MAX (0x7fff)
#define OE_INT16_MIN (-1 - 0x7fff)
#define OE_INT32_MAX (0x7fffffff)
#define OE_INT32_MIN (-1 - 0x7fffffff)
#define OE_INT64_MAX (0x7fffffffffffffff)
#define OE_INT64_MIN (-1 - 0x7fffffffffffffff)
#define OE_INT8_MAX (0x7f)
#define OE_INT8_MIN (-1 - 0x7f)
#define OE_INT_MAX 0x7fffffff
#define OE_INT_MIN (-1 - 0x7fffffff)
#define OE_LLONG_MAX 0x7fffffffffffffffLL
#define OE_LLONG_MIN (-OE_LLONG_MAX - 1)
#define OE_LONG_MAX 0x7fffffffL
#define OE_LONG_MIN (-OE_LONG_MAX - 1)
#define OE_SCHAR_MAX 127
#define OE_SCHAR_MIN (-128)
#define OE_SHRT_MAX 0x7fff
#define OE_SHRT_MIN (-1 - 0x7fff)
#define OE_SIZE_MAX OE_UINT64_MAX
#define OE_SSIZE_MAX OE_INT64_MAX
#define OE_UCHAR_MAX 255
#define OE_UINT16_MAX (0xffff)
#define OE_UINT32_MAX (0xffffffffu)
#define OE_UINT64_MAX (0xffffffffffffffffu)
#define OE_UINT8_MAX (0xff)
#define OE_UINT_MAX 0xffffffffU
#define OE_ULLONG_MAX (2ULL * OE_LLONG_MAX + 1)
#define OE_ULONG_MAX (2UL * OE_LONG_MAX + 1)
#define OE_USHRT_MAX 0xffff

#define bool _Bool
#define false 0
#define true 1

#define NULL 0L
#define OE_ALIGNED(BYTES) __attribute__((aligned(BYTES)))
#define OE_ALWAYS_INLINE __attribute__((always_inline))
#define OE_API_VERSION 2
#define OE_CHECK_FIELD(T1, T2, F)                               \
    OE_STATIC_ASSERT(OE_OFFSETOF(T1, F) == OE_OFFSETOF(T2, F)); \
    OE_STATIC_ASSERT(sizeof(((T1*)0)->F) == sizeof(((T2*)0)->F));
#define OE_CHECK_SIZE(N, M)          \
    typedef unsigned char OE_CONCAT( \
        __OE_CHECK_SIZE, "__LINE__")[((N) == (M)) ? 1 : -1] OE_UNUSED_ATTRIBUTE
#define OE_CONCAT(X, Y) __OE_CONCAT(X, Y)
#define OE_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))
#define OE_DEPRECATED(FUNC, MSG) FUNC __attribute__((deprecated(MSG)))
#define OE_ENUM_MAX 0xffffffff
#define OE_EXPORT __attribute__((visibility("default")))
#define OE_EXPORT_CONST OE_EXPORT extern const
#define OE_EXTERNC extern "C"
#define OE_EXTERNC_BEGIN \
    extern "C"           \
    {
#define OE_EXTERNC_END }
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))
#define OE_INLINE static __inline
#define OE_NEVER_INLINE __declspec(noinline)
#define OE_NO_OPTIMIZE_BEGIN __pragma(optimize("", off))
#define OE_NO_OPTIMIZE_END __pragma(optimize("", on))
#define OE_NO_RETURN __attribute__((__noreturn__))
#define OE_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#define OE_PACK_BEGIN _Pragma("pack(push, 1)")
#define OE_PACK_END _Pragma("pack(pop)")
#define OE_PAGE_SIZE 0x1000
#define OE_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#define OE_RETURNS_TWICE __attribute__((returns_twice))
#define OE_STATIC_ASSERT(COND)       \
    typedef unsigned char OE_CONCAT( \
        __OE_STATIC_ASSERT, "__LINE__")[(COND) ? 1 : -1] OE_UNUSED_ATTRIBUTE
#define OE_UNUSED(P) (void)(P)
#define OE_UNUSED_ATTRIBUTE __attribute__((unused))
#define OE_UNUSED_FUNC __attribute__((unused))
#define OE_USED __attribute__((__used__))
#define OE_WEAK __attribute__((weak))
#define OE_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))
#define OE_ZERO_SIZED_ARRAY __pragma(warning(suppress : 4200))

#define __OE_CONCAT(X, Y) X##Y
#define OE_COND_INITIALIZER \
    {                       \
        {                   \
            0               \
        }                   \
    }
#define OE_MUTEX_INITIALIZER \
    {                        \
        {                    \
            0                \
        }                    \
    }
#define OE_ONCE_INIT 0
#define OE_ONCE_INITIALIZER 0
#define OE_RWLOCK_INITIALIZER \
    {                         \
        {                     \
            0                 \
        }                     \
    }
#define OE_SPINLOCK_INITIALIZER 0
#define OE_THREADKEY_INITIALIZER 0

#define OE_F_OK 0
#define OE_NGROUP_MAX 256
#define OE_R_OK 4
#define OE_SEEK_CUR 1
#define OE_SEEK_END 2
#define OE_SEEK_SET 0
#define OE_STDERR_FILENO 2
#define OE_STDIN_FILENO 0
#define OE_STDOUT_FILENO 1
#define OE_W_OK 2
#define OE_X_OK 1


#define oe_va_arg __builtin_va_arg
#define oe_va_copy __builtin_va_copy
#define oe_va_end __builtin_va_end
#define oe_va_list __builtin_va_list
#define oe_va_start __builtin_va_start
#define va_arg oe_va_arg
#define va_copy oe_va_copy
#define va_end oe_va_end
#define va_list oe_va_list
#define va_start oe_va_start

#define OE_TIOCGWINSZ 0x5413

#define OE_RAISE_ERRNO(ERRNO)                                  \
    do                                                         \
    {                                                          \
        int __err = ERRNO;                                     \
        oe_log(OE_LOG_LEVEL_ERROR, "oe_errno=%d [%s %s:%d]\n", \
            __err, "__FILE__", __FUNCTION__, "__LINE__");          \
        oe_errno = __err;                                      \
        goto done;                                             \
    }                                                          \
    while (0)
#define OE_RAISE_ERRNO_MSG(ERRNO, FMT, ...)                         \
    do                                                              \
    {                                                               \
        int __err = ERRNO;                                          \
        oe_log(OE_LOG_LEVEL_ERROR, FMT " oe_errno=%d [%s %s:%d]\n", \
           ##__VA_ARGS__, __err, "__FILE__", __FUNCTION__, "__LINE__"); \
        oe_errno = __err;                                           \
        goto done;                                                  \
    }                                                               \
    while (0)

#define OE_DEVICE_NAME_CONSOLE_FILE_SYSTEM "oe_console_file_system"
#define OE_DEVICE_NAME_HOST_EPOLL "oe_host_epoll"
#define OE_DEVICE_NAME_HOST_FILE_SYSTEM OE_HOST_FILE_SYSTEM
#define OE_DEVICE_NAME_HOST_SOCKET_INTERFACE "oe_host_socket_interface"
#define OE_DEVICE_NAME_SGX_FILE_SYSTEM OE_SGX_FILE_SYSTEM

#define OE_R_OR 04
#define OE_S_IFBLK 0060000
#define OE_S_IFCHR 0020000
#define OE_S_IFDIR 0040000
#define OE_S_IFIFO 0010000
#define OE_S_IFLNK 0120000
#define OE_S_IFMT 0170000
#define OE_S_IFREG 0100000
#define OE_S_IFSOCK 0140000
#define OE_S_IRGRP 0x0020
#define OE_S_IROTH 0x0004
#define OE_S_IRUSR 0x0100
#define OE_S_IRWGRP (OE_S_IRGRP | OE_S_IWGRP)
#define OE_S_IRWOTH (OE_S_IROTH | OE_S_IWOTH)
#define OE_S_IRWUSR (OE_S_IRUSR | OE_S_IWUSR)
#define OE_S_IRWXGRP (OE_S_IRGRP | OE_S_IWGRP | OE_S_IXGRP)
#define OE_S_IRWXOTH (OE_S_IROTH | OE_S_IWOTH | OE_S_IXOTH)
#define OE_S_IRWXUSR (OE_S_IRUSR | OE_S_IWUSR | OE_S_IXUSR)
#define OE_S_ISBLK(mode) (((mode)&OE_S_IFMT) == OE_S_IFBLK)
#define OE_S_ISCHR(mode) (((mode)&OE_S_IFMT) == OE_S_IFCHR)
#define OE_S_ISDIR(mode) (((mode)&OE_S_IFMT) == OE_S_IFDIR)
#define OE_S_ISFIFO(mode) (((mode)&OE_S_IFMT) == OE_S_IFIFO)
#define OE_S_ISGID 0x0400
#define OE_S_ISLNK(mode) (((mode)&OE_S_IFMT) == OE_S_IFLNK)
#define OE_S_ISREG(mode) (((mode)&OE_S_IFMT) == OE_S_IFREG)
#define OE_S_ISSOCK(mode) (((mode)&OE_S_IFMT) == OE_S_IFSOCK)
#define OE_S_ISUID 0x0800
#define OE_S_ISVTX 0x0200
#define OE_S_IWGRP 0x0010
#define OE_S_IWOTH 0x0002
#define OE_S_IWUSR 0x0080
#define OE_S_IXGRP 0x0008
#define OE_S_IXOTH 0x0001
#define OE_S_IXUSR 0x0040
#define OE_W_OR 02
#define OE_X_OR 01

#define st_atime st_atim.tv_sec
#define st_ctime st_ctim.tv_sec
#define st_mtime st_mtim.tv_sec





#define OE_AF_ALG OE_PF_ALG
#define OE_AF_APPLETALK OE_PF_APPLETALK
#define OE_AF_ASH OE_PF_ASH
#define OE_AF_ATMPVC OE_PF_ATMPVC
#define OE_AF_ATMSVC OE_PF_ATMSVC
#define OE_AF_AX25 OE_PF_AX25
#define OE_AF_BLUETOOTH OE_PF_BLUETOOTH
#define OE_AF_BRIDGE OE_PF_BRIDGE
#define OE_AF_CAIF OE_PF_CAIF
#define OE_AF_CAN OE_PF_CAN
#define OE_AF_DECnet OE_PF_DECnet
#define OE_AF_ECONET OE_PF_ECONET
#define OE_AF_FILE OE_PF_FILE
#define OE_AF_IB OE_PF_IB
#define OE_AF_IEEE802154 OE_PF_IEEE802154
#define OE_AF_INET OE_PF_INET
#define OE_AF_INET6 OE_PF_INET6
#define OE_AF_IPX OE_PF_IPX
#define OE_AF_IRDA OE_PF_IRDA
#define OE_AF_ISDN OE_PF_ISDN
#define OE_AF_IUCV OE_PF_IUCV
#define OE_AF_KCM OE_PF_KCM
#define OE_AF_KEY OE_PF_KEY
#define OE_AF_LLC OE_PF_LLC
#define OE_AF_LOCAL OE_PF_LOCAL
#define OE_AF_MAX OE_PF_MAX
#define OE_AF_MPLS OE_PF_MPLS
#define OE_AF_NETBEUI OE_PF_NETBEUI
#define OE_AF_NETLINK OE_PF_NETLINK
#define OE_AF_NETROM OE_PF_NETROM
#define OE_AF_NFC OE_PF_NFC
#define OE_AF_PACKET OE_PF_PACKET
#define OE_AF_PHONET OE_PF_PHONET
#define OE_AF_PPPOX OE_PF_PPPOX
#define OE_AF_QIPCRTR OE_PF_QIPCRTR
#define OE_AF_RDS OE_PF_RDS
#define OE_AF_ROSE OE_PF_ROSE
#define OE_AF_ROUTE OE_PF_ROUTE
#define OE_AF_RXRPC OE_PF_RXRPC
#define OE_AF_SECURITY OE_PF_SECURITY
#define OE_AF_SMC OE_PF_SMC
#define OE_AF_SNA OE_PF_SNA
#define OE_AF_TIPC OE_PF_TIPC
#define OE_AF_UNIX OE_PF_UNIX
#define OE_AF_UNSPEC OE_PF_UNSPEC
#define OE_AF_VSOCK OE_PF_VSOCK
#define OE_AF_WANPIPE OE_PF_WANPIPE
#define OE_AF_X25 OE_PF_X25
#define OE_MSG_CTRUNC 0x0008
#define OE_MSG_PEEK 0x0002
#define OE_PF_ALG 38           
#define OE_PF_APPLETALK 5   
#define OE_PF_ASH 18           
#define OE_PF_ATMPVC 8      
#define OE_PF_ATMSVC 20        
#define OE_PF_AX25 3        
#define OE_PF_BLUETOOTH 31     
#define OE_PF_BRIDGE 7      
#define OE_PF_CAIF 37          
#define OE_PF_CAN 29           
#define OE_PF_DECnet 12     
#define OE_PF_ECONET 19        
#define OE_PF_FILE PF_LOCAL 
#define OE_PF_HOST 51          
#define OE_PF_IB 27            
#define OE_PF_IEEE802154 36    
#define OE_PF_INET 2        
#define OE_PF_INET6 10      
#define OE_PF_IPX 4         
#define OE_PF_IRDA 23          
#define OE_PF_ISDN 34          
#define OE_PF_IUCV 32          
#define OE_PF_KCM 41           
#define OE_PF_KEY 15        
#define OE_PF_LLC 26           
#define OE_PF_LOCAL 1       
#define OE_PF_MAX 51           
#define OE_PF_MPLS 28          
#define OE_PF_NETBEUI 13    
#define OE_PF_NETLINK 16
#define OE_PF_NETROM 6      
#define OE_PF_NFC 39           
#define OE_PF_PACKET 17        
#define OE_PF_PHONET 35        
#define OE_PF_PPPOX 24         
#define OE_PF_QIPCRTR 42       
#define OE_PF_RDS 21           
#define OE_PF_ROSE 11       
#define OE_PF_ROUTE PF_NETLINK 
#define OE_PF_RXRPC 33         
#define OE_PF_SECURITY 14   
#define OE_PF_SMC 43           
#define OE_PF_SNA 22           
#define OE_PF_TIPC 30          
#define OE_PF_UNIX PF_LOCAL 
#define OE_PF_UNSPEC 0      
#define OE_PF_VSOCK 40         
#define OE_PF_WANPIPE 25       
#define OE_PF_X25 9         
#define OE_SHUT_RD 0
#define OE_SHUT_RDWR 2
#define OE_SHUT_WR 1
#define OE_SOL_SOCKET 1
#define OE_SO_BROADCAST 6
#define OE_SO_BSDCOMPAT 14
#define OE_SO_DEBUG 1
#define OE_SO_DONTROUTE 5
#define OE_SO_ERROR 4
#define OE_SO_KEEPALIVE 9
#define OE_SO_LINGER 13
#define OE_SO_NO_CHECK 11
#define OE_SO_OOBINLINE 10
#define OE_SO_PRIORITY 12
#define OE_SO_RCVBUF 8
#define OE_SO_RCVBUFFORCE 33
#define OE_SO_REUSEADDR 2
#define OE_SO_REUSEPORT 15
#define OE_SO_SNDBUF 7
#define OE_SO_SNDBUFFORCE 32
#define OE_SO_TYPE 3

#define __OE_IOVEC oe_iovec
#define __OE_MSGHDR oe_msghdr
#define __OE_SOCKADDR_STORAGE oe_sockaddr_storage
#define OE_EPOLL_CTL_ADD 1
#define OE_EPOLL_CTL_DEL 2
#define OE_EPOLL_CTL_MOD 3

#define OE_LLD(_X_) _X_
#define OE_LLU(_X_) _X_
#define OE_LLX(_X_) _X_


#define __OE_SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))
#define OE_HOST_FILE_SYSTEM "oe_host_file_system"

#define E2BIG OE_E2BIG
#define EACCES OE_EACCES
#define EADDRINUSE OE_EADDRINUSE
#define EADDRNOTAVAIL OE_EADDRNOTAVAIL
#define EADV OE_EADV
#define EAFNOSUPPORT OE_EAFNOSUPPORT
#define EAGAIN OE_EAGAIN
#define EALREADY OE_EALREADY
#define EBADE OE_EBADE
#define EBADF OE_EBADF
#define EBADFD OE_EBADFD
#define EBADMSG OE_EBADMSG
#define EBADR OE_EBADR
#define EBADRQC OE_EBADRQC
#define EBADSLT OE_EBADSLT
#define EBFONT OE_EBFONT
#define EBUSY OE_EBUSY
#define ECANCELED OE_ECANCELED
#define ECHILD OE_ECHILD
#define ECHRNG OE_ECHRNG
#define ECOMM OE_ECOMM
#define ECONNABORTED OE_ECONNABORTED
#define ECONNREFUSED OE_ECONNREFUSED
#define ECONNRESET OE_ECONNRESET
#define EDEADLK OE_EDEADLK
#define EDEADLOCK OE_EDEADLOCK
#define EDESTADDRREQ OE_EDESTADDRREQ
#define EDOM OE_EDOM
#define EDOTDOT OE_EDOTDOT
#define EDQUOT OE_EDQUOT
#define EEXIST OE_EEXIST
#define EFAULT OE_EFAULT
#define EFBIG OE_EFBIG
#define EHOSTDOWN OE_EHOSTDOWN
#define EHOSTUNREACH OE_EHOSTUNREACH
#define EHWPOISON OE_EHWPOISON
#define EIDRM OE_EIDRM
#define EILSEQ OE_EILSEQ
#define EINPROGRESS OE_EINPROGRESS
#define EINTR OE_EINTR
#define EINVAL OE_EINVAL
#define EIO OE_EIO
#define EISCONN OE_EISCONN
#define EISDIR OE_EISDIR
#define EISNAM OE_EISNAM
#define EKEYEXPIRED OE_EKEYEXPIRED
#define EKEYREJECTED OE_EKEYREJECTED
#define EKEYREVOKED OE_EKEYREVOKED
#define EL2HLT OE_EL2HLT
#define EL2NSYNC OE_EL2NSYNC
#define EL3HLT OE_EL3HLT
#define EL3RST OE_EL3RST
#define ELIBACC OE_ELIBACC
#define ELIBBAD OE_ELIBBAD
#define ELIBEXEC OE_ELIBEXEC
#define ELIBMAX OE_ELIBMAX
#define ELIBSCN OE_ELIBSCN
#define ELNRNG OE_ELNRNG
#define ELOOP OE_ELOOP
#define EMEDIUMTYPE OE_EMEDIUMTYPE
#define EMFILE OE_EMFILE
#define EMLINK OE_EMLINK
#define EMSGSIZE OE_EMSGSIZE
#define EMULTIHOP OE_EMULTIHOP
#define ENAMETOOLONG OE_ENAMETOOLONG
#define ENAVAIL OE_ENAVAIL
#define ENETDOWN OE_ENETDOWN
#define ENETRESET OE_ENETRESET
#define ENETUNREACH OE_ENETUNREACH
#define ENFILE OE_ENFILE
#define ENOANO OE_ENOANO
#define ENOBUFS OE_ENOBUFS
#define ENOCSI OE_ENOCSI
#define ENODATA OE_ENODATA
#define ENODEV OE_ENODEV
#define ENOENT OE_ENOENT
#define ENOEXEC OE_ENOEXEC
#define ENOKEY OE_ENOKEY
#define ENOLCK OE_ENOLCK
#define ENOLINK OE_ENOLINK
#define ENOMEDIUM OE_ENOMEDIUM
#define ENOMEM OE_ENOMEM
#define ENOMSG OE_ENOMSG
#define ENONET OE_ENONET
#define ENOPKG OE_ENOPKG
#define ENOPROTOOPT OE_ENOPROTOOPT
#define ENOSPC OE_ENOSPC
#define ENOSR OE_ENOSR
#define ENOSTR OE_ENOSTR
#define ENOSYS OE_ENOSYS
#define ENOTBLK OE_ENOTBLK
#define ENOTCONN OE_ENOTCONN
#define ENOTDIR OE_ENOTDIR
#define ENOTEMPTY OE_ENOTEMPTY
#define ENOTNAM OE_ENOTNAM
#define ENOTRECOVERABLE OE_ENOTRECOVERABLE
#define ENOTSOCK OE_ENOTSOCK
#define ENOTSUP OE_ENOTSUP
#define ENOTTY OE_ENOTTY
#define ENOTUNIQ OE_ENOTUNIQ
#define ENXIO OE_ENXIO
#define EOPNOTSUPP OE_EOPNOTSUPP
#define EOVERFLOW OE_EOVERFLOW
#define EOWNERDEAD OE_EOWNERDEAD
#define EPERM OE_EPERM
#define EPFNOSUPPORT OE_EPFNOSUPPORT
#define EPIPE OE_EPIPE
#define EPROTO OE_EPROTO
#define EPROTONOSUPPORT OE_EPROTONOSUPPORT
#define EPROTOTYPE OE_EPROTOTYPE
#define ERANGE OE_ERANGE
#define EREMCHG OE_EREMCHG
#define EREMOTE OE_EREMOTE
#define EREMOTEIO OE_EREMOTEIO
#define ERESTART OE_ERESTART
#define ERFKILL OE_ERFKILL
#define EROFS OE_EROFS
#define ESHUTDOWN OE_ESHUTDOWN
#define ESOCKTNOSUPPORT OE_ESOCKTNOSUPPORT
#define ESPIPE OE_ESPIPE
#define ESRCH OE_ESRCH
#define ESRMNT OE_ESRMNT
#define ESTALE OE_ESTALE
#define ESTRPIPE OE_ESTRPIPE
#define ETIME OE_ETIME
#define ETIMEDOUT OE_ETIMEDOUT
#define ETOOMANYREFS OE_ETOOMANYREFS
#define ETXTBSY OE_ETXTBSY
#define EUCLEAN OE_EUCLEAN
#define EUNATCH OE_EUNATCH
#define EUSERS OE_EUSERS
#define EWOULDBLOCK OE_EWOULDBLOCK
#define EXDEV OE_EXDEV
#define EXFULL OE_EXFULL
#define OE_E2BIG            7
#define OE_EACCES          13
#define OE_EADDRINUSE      98
#define OE_EADDRNOTAVAIL   99
#define OE_EADV            68
#define OE_EAFNOSUPPORT    97
#define OE_EAGAIN          11
#define OE_EALREADY        114
#define OE_EBADE           52
#define OE_EBADF            9
#define OE_EBADFD          77
#define OE_EBADMSG         74
#define OE_EBADR           53
#define OE_EBADRQC         56
#define OE_EBADSLT         57
#define OE_EBFONT          59
#define OE_EBUSY           16
#define OE_ECANCELED       125
#define OE_ECHILD          10
#define OE_ECHRNG          44
#define OE_ECOMM           70
#define OE_ECONNABORTED    103
#define OE_ECONNREFUSED    111
#define OE_ECONNRESET      104
#define OE_EDEADLK         35
#define OE_EDEADLOCK       OE_EDEADLK
#define OE_EDESTADDRREQ    89
#define OE_EDOM            33
#define OE_EDOTDOT         73
#define OE_EDQUOT          122
#define OE_EEXIST          17
#define OE_EFAULT          14
#define OE_EFBIG           27
#define OE_EHOSTDOWN       112
#define OE_EHOSTUNREACH    113
#define OE_EHWPOISON       133
#define OE_EIDRM           43
#define OE_EILSEQ          84
#define OE_EINPROGRESS     115
#define OE_EINTR            4
#define OE_EINVAL          22
#define OE_EIO              5
#define OE_EISCONN         106
#define OE_EISDIR          21
#define OE_EISNAM          120
#define OE_EKEYEXPIRED     127
#define OE_EKEYREJECTED    129
#define OE_EKEYREVOKED     128
#define OE_EL2HLT          51
#define OE_EL2NSYNC        45
#define OE_EL3HLT          46
#define OE_EL3RST          47
#define OE_ELIBACC         79
#define OE_ELIBBAD         80
#define OE_ELIBEXEC        83
#define OE_ELIBMAX         82
#define OE_ELIBSCN         81
#define OE_ELNRNG          48
#define OE_ELOOP           40
#define OE_EMEDIUMTYPE     124
#define OE_EMFILE          24
#define OE_EMLINK          31
#define OE_EMSGSIZE        90
#define OE_EMULTIHOP       72
#define OE_ENAMETOOLONG    36
#define OE_ENAVAIL         119
#define OE_ENETDOWN        100
#define OE_ENETRESET       102
#define OE_ENETUNREACH     101
#define OE_ENFILE          23
#define OE_ENOANO          55
#define OE_ENOBUFS         105
#define OE_ENOCSI          50
#define OE_ENODATA         61
#define OE_ENODEV          19
#define OE_ENOENT           2
#define OE_ENOEXEC          8
#define OE_ENOKEY          126
#define OE_ENOLCK          37
#define OE_ENOLINK         67
#define OE_ENOMEDIUM       123
#define OE_ENOMEM          12
#define OE_ENOMSG          42
#define OE_ENONET          64
#define OE_ENOPKG          65
#define OE_ENOPROTOOPT     92
#define OE_ENOSPC          28
#define OE_ENOSR           63
#define OE_ENOSTR          60
#define OE_ENOSYS          38
#define OE_ENOTBLK         15
#define OE_ENOTCONN        107
#define OE_ENOTDIR         20
#define OE_ENOTEMPTY       39
#define OE_ENOTNAM         118
#define OE_ENOTRECOVERABLE 131
#define OE_ENOTSOCK        88
#define OE_ENOTSUP         OE_EOPNOTSUPP
#define OE_ENOTTY          25
#define OE_ENOTUNIQ        76
#define OE_ENXIO            6
#define OE_EOPNOTSUPP      95
#define OE_EOVERFLOW       75
#define OE_EOWNERDEAD      130
#define OE_EPERM            1
#define OE_EPFNOSUPPORT    96
#define OE_EPIPE           32
#define OE_EPROCLIM        134
#define OE_EPROTO          71
#define OE_EPROTONOSUPPORT 93
#define OE_EPROTOTYPE      91
#define OE_ERANGE          34
#define OE_EREMCHG         78
#define OE_EREMOTE         66
#define OE_EREMOTEIO       121
#define OE_ERESTART        85
#define OE_ERFKILL         132
#define OE_EROFS           30
#define OE_ESHUTDOWN       108
#define OE_ESOCKTNOSUPPORT 94
#define OE_ESPIPE          29
#define OE_ESRCH            3
#define OE_ESRMNT          69
#define OE_ESTALE          116
#define OE_ESTRPIPE        86
#define OE_ETIME           62
#define OE_ETIMEDOUT       110
#define OE_ETOOMANYREFS    109
#define OE_ETXTBSY         26
#define OE_EUCLEAN         117
#define OE_EUNATCH         49
#define OE_EUSERS          87
#define OE_EWOULDBLOCK     OE_EAGAIN
#define OE_EXDEV           18
#define OE_EXFULL          54

#define errno oe_errno
#define oe_errno *__oe_errno_location()


#define OE_AT_FDCWD (-100)
#define OE_AT_REMOVEDIR 0x200
#define OE_F_DUPFD          0
#define OE_F_GETFD          1
#define OE_F_GETFL          3
#define OE_F_GETLK          5
#define OE_F_GETLK64       OE_F_GETLK
#define OE_F_GETOWN         9
#define OE_F_GETOWNER_UIDS 17
#define OE_F_GETOWN_EX     16
#define OE_F_GETSIG        11
#define OE_F_OFD_GETLK     36
#define OE_F_OFD_SETLK     37
#define OE_F_OFD_SETLKW    38
#define OE_F_SETFD          2
#define OE_F_SETFL          4
#define OE_F_SETLK          6
#define OE_F_SETLK64       OE_F_SETLK
#define OE_F_SETLKW         7
#define OE_F_SETLKW64      OE_F_SETLKW
#define OE_F_SETOWN         8
#define OE_F_SETOWN_EX     15
#define OE_F_SETSIG        10
#define OE_O_APPEND        000002000
#define OE_O_ASYNC         000020000
#define OE_O_CLOEXEC       002000000
#define OE_O_CREAT         000000100
#define OE_O_DIRECT        000040000
#define OE_O_DIRECTORY     000200000
#define OE_O_DSYNC         000010000
#define OE_O_EXCL          000000200
#define OE_O_LARGEFILE     000000000
#define OE_O_NDELAY        O_NONBLOCK
#define OE_O_NOATIME       001000000
#define OE_O_NOCTTY        000000400
#define OE_O_NOFOLLOW      000400000
#define OE_O_NONBLOCK      000004000
#define OE_O_PATH          010000000
#define OE_O_RDONLY        000000000
#define OE_O_RDWR          000000002
#define OE_O_RSYNC         004010000
#define OE_O_SYNC          004010000
#define OE_O_TMPFILE       020200000
#define OE_O_TRUNC         000001000
#define OE_O_WRONLY        000000001

#define oe_flock64 oe_flock


#define OE_RESTRICT restrict





#define CHAR_BIT OE_CHAR_BIT
#define CHAR_MAX OE_CHAR_MAX
#define CHAR_MIN OE_CHAR_MIN
#define INT_MAX OE_INT_MAX
#define INT_MIN OE_INT_MIN
#define IOV_MAX OE_IOV_MAX
#define LLONG_MAX OE_LLONG_MAX
#define LLONG_MIN OE_LLONG_MIN
#define LONG_MAX OE_LONG_MAX
#define LONG_MIN OE_LONG_MIN
#define NAME_MAX OE_NAME_MAX
#define NGROUPS_MAX OE_NGROUPS_MAX
#define OE_IOV_MAX 1024
#define OE_NAME_MAX 255
#define OE_NGROUPS_MAX 32
#define OE_PATH_MAX 4096
#define PATH_MAX OE_PATH_MAX
#define SCHAR_MAX OE_SCHAR_MAX
#define SCHAR_MIN OE_SCHAR_MIN
#define SHRT_MAX OE_SHRT_MAX
#define SHRT_MIN OE_SHRT_MIN
#define UCHAR_MAX OE_UCHAR_MAX
#define UINT_MAX OE_UINT_MAX
#define ULLONG_MAX OE_ULLONG_MAX
#define ULONG_MAX OE_ULONG_MAX
#define USHRT_MAX OE_USHRT_MAX

#define BUFSIZ OE_BUFSIZ
#define EOF (-1)

#define INT16_MAX OE_INT16_MAX
#define INT16_MIN OE_INT16_MIN
#define INT32_MAX OE_INT32_MAX
#define INT32_MIN OE_INT32_MIN
#define INT64_MAX OE_INT64_MAX
#define INT64_MIN OE_INT64_MIN
#define INT8_MAX OE_INT8_MAX
#define INT8_MIN OE_INT8_MIN
#define SIZE_MAX OE_SIZE_MAX
#define UINT16_MAX OE_UINT16_MAX
#define UINT32_MAX OE_UINT32_MAX
#define UINT64_MAX OE_UINT64_MAX
#define UINT8_MAX OE_UINT8_MAX

#define OE_BUFSIZ 8192
#define OE_EOF (-1)

#define stderr oe_stderr
#define stdin oe_stdin
#define stdout oe_stdout


#define oe_assert(EXPR)                                                \
    do                                                                 \
    {                                                                  \
        if (!(EXPR))                                                   \
            __oe_assert_fail(#EXPR, "__FILE__", "__LINE__", __FUNCTION__); \
    } while (0)
#define oe_get_report oe_get_report_v2
#define oe_get_seal_key oe_get_seal_key_v2
#define oe_get_seal_key_by_policy oe_get_seal_key_by_policy_v2
#define oe_get_target_info oe_get_target_info_v2
