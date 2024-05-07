



















#define OE_ATOMIC_MEMORY_BARRIER_ACQUIRE() \
    __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define OE_ATOMIC_MEMORY_BARRIER_RELEASE() \
    __atomic_thread_fence(__ATOMIC_RELEASE)
#define OE_CPU_RELAX() asm volatile("pause" ::: "memory")


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

#define SAFE_ADD(a, b, c, minz, maxz) \
    return __builtin_add_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#define SAFE_MULTIPLY(a, b, c, minz, maxz) \
    return __builtin_mul_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#define SAFE_SUBTRACT(a, b, c, minz, maxz) \
    return __builtin_sub_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;

#define __has_builtin(x) 0



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
