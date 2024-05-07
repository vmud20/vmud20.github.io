

#include<unistd.h>

#include<linux/if_tun.h>

#include<inttypes.h>
#include<error.h>









#include<sys/wait.h>
#include<sys/epoll.h>
#include<stdlib.h>






#include<sys/types.h>
#include<net/if.h>






#include<errno.h>


#include<arpa/inet.h>
#include<linux/sockios.h>
#include<sys/ioctl.h>
#include<syslog.h>
#include<ctype.h>

#include<netinet/tcp.h>

#include<stdio.h>
#include<fcntl.h>

#include<linux/types.h>


#include<signal.h>



#include<sys/stat.h>
#include<netinet/in.h>
#include<netdb.h>

#include<stdbool.h>
#include<assert.h>
#include<string.h>


#include<time.h>
#include<stdarg.h>



#include<netinet/ip.h>




#include<strings.h>
#include<sys/un.h>




#include<limits.h>
#include<pwd.h>

#include<err.h>
#include<sys/poll.h>
#include<sys/mman.h>




#include<sys/uio.h>

#include<stdint.h>


#include<sys/socket.h>
#include<netinet/in_systm.h>
#include<resolv.h>
#include<grp.h>




#include<linux/errqueue.h>
#include<libgen.h>
#include<stddef.h>

#include<sys/file.h>
#include<sys/time.h>



#define RSA_F_RSA_OSSL_PRIVATE_ENCRYPT       RSA_F_RSA_EAY_PRIVATE_ENCRYPT
#define ALLOC_ARRAY(dptr, type, n) \
    { \
        check_malloc_return((dptr) = (type *) malloc(array_mult_safe(sizeof(type), (n), 0))); \
    }
#define ALLOC_ARRAY_CLEAR(dptr, type, n) \
    { \
        ALLOC_ARRAY(dptr, type, n); \
        memset((dptr), 0, (array_mult_safe(sizeof(type), (n), 0))); \
    }
#define ALLOC_ARRAY_CLEAR_GC(dptr, type, n, gc) \
    { \
        (dptr) = (type *) gc_malloc(array_mult_safe(sizeof(type), (n), 0), true, (gc)); \
    }
#define ALLOC_ARRAY_GC(dptr, type, n, gc) \
    { \
        (dptr) = (type *) gc_malloc(array_mult_safe(sizeof(type), (n), 0), false, (gc)); \
    }
#define ALLOC_OBJ(dptr, type) \
    { \
        check_malloc_return((dptr) = (type *) malloc(sizeof(type))); \
    }
#define ALLOC_OBJ_CLEAR(dptr, type) \
    { \
        ALLOC_OBJ(dptr, type); \
        memset((dptr), 0, sizeof(type)); \
    }
#define ALLOC_OBJ_CLEAR_GC(dptr, type, gc) \
    { \
        (dptr) = (type *) gc_malloc(sizeof(type), true, (gc)); \
    }
#define ALLOC_OBJ_GC(dptr, type, gc) \
    { \
        (dptr) = (type *) gc_malloc(sizeof(type), false, (gc)); \
    }
#define ALLOC_VAR_ARRAY_CLEAR_GC(dptr, type, atype, n, gc)      \
    { \
        (dptr) = (type *) gc_malloc(array_mult_safe(sizeof(atype), (n), sizeof(type)), true, (gc)); \
    }
#define BCAP(buf)  (buf_forward_capacity(buf))
#define BDEF(buf)  (buf_defined(buf))
#define BEND(buf)  (buf_bend(buf))
#define BLAST(buf) (buf_blast(buf))
#define BLEN(buf)  (buf_len(buf))
#define BPTR(buf)  (buf_bptr(buf))
#define BSTR(buf)  (buf_str(buf))


#define BUF_SIZE_MAX 1000000
#define CC_ALNUM              (1<<2)
#define CC_ALPHA              (1<<3)
#define CC_ANY                (1<<0)
#define CC_ASCII              (1<<4)
#define CC_ASTERISK           (1<<30)
#define CC_AT                 (1<<24)
#define CC_BACKSLASH          (1<<14)
#define CC_BLANK              (1<<11)
#define CC_CNTRL              (1<<5)
#define CC_COLON              (1<<19)
#define CC_COMMA              (1<<18)
#define CC_CR                 (1<<13)
#define CC_CRLF               (CC_CR|CC_NEWLINE)
#define CC_DASH               (1<<16)
#define CC_DIGIT              (1<<6)
#define CC_DOT                (1<<17)
#define CC_DOUBLE_QUOTE       (1<<22)
#define CC_EQUAL              (1<<25)
#define CC_GREATER_THAN       (1<<27)
#define CC_LESS_THAN          (1<<26)
#define CC_NAME               (CC_ALNUM|CC_UNDERBAR)
#define CC_NEWLINE            (1<<12)
#define CC_NULL               (1<<1)
#define CC_PIPE               (1<<28)
#define CC_PRINT              (1<<7)
#define CC_PUNCT              (1<<8)
#define CC_QUESTION_MARK      (1<<29)
#define CC_REVERSE_QUOTE      (1<<23)
#define CC_SINGLE_QUOTE       (1<<21)
#define CC_SLASH              (1<<20)
#define CC_SPACE              (1<<9)
#define CC_UNDERBAR           (1<<15)
#define CC_XDIGIT             (1<<10)
#define FHE_CAPS 0x100            
#define FHE_SPACE_BREAK_MASK 0xFF 
#define PA_BRACKET (1<<0)
#define alloc_buf(size)               alloc_buf_debug(size, "__FILE__", "__LINE__")
#define alloc_buf_gc(size, gc)        alloc_buf_gc_debug(size, gc, "__FILE__", "__LINE__");
#define buf_init(buf, offset) buf_init_debug(buf, offset, "__FILE__", "__LINE__")
#define clone_buf(buf)                clone_buf_debug(buf, "__FILE__", "__LINE__");
#define gc_malloc(size, clear, arena) gc_malloc_debug(size, clear, arena, "__FILE__", "__LINE__")
#define string_alloc(str, gc)         string_alloc_debug(str, gc, "__FILE__", "__LINE__")
#define string_alloc_buf(str, gc)     string_alloc_buf_debug(str, gc, "__FILE__", "__LINE__")
#define verify_align_4(ptr) valign4(buf, "__FILE__", "__LINE__")
#define ASSERT(x) do { if (!(x)) {assert_failed("__FILE__", "__LINE__", #x);}} while (false)
#define DECODE_MUTE_LEVEL(flags) (((flags) >> MUTE_LEVEL_SHIFT) & MUTE_LEVEL_MASK)
#define ENCODE_MUTE_LEVEL(mute_level) (((mute_level) & MUTE_LEVEL_MASK) << MUTE_LEVEL_SHIFT)

#define ERR_BUF_SIZE 8192
#define EXIT_FATAL(flags) do { if ((flags) & M_FATAL) {_exit(1);}} while (false)

#define LOGLEV(log_level, mute_level, other) ((log_level) | ENCODE_MUTE_LEVEL(mute_level) | other)
#define MUTE_LEVEL_MASK 0xFF
#define MUTE_LEVEL_SHIFT 24
#define M_CLIENT  (M_MSG_VIRT_OUT | M_NOMUTE | M_NOIPREFIX)
#define M_DEBUG           (1<<7)
#define M_DEBUG_LEVEL     (0x0F)         
#define M_ERR     (M_FATAL | M_ERRNO)
#define M_ERRNO           (1<<8)         
#define M_FATAL           (1<<4)         
#define M_MSG_VIRT_OUT    (1<<14)        
#define M_NOIPREFIX       (1<<17)        
#define M_NOLF            (1<<16)        
#define M_NOMUTE          (1<<11)        
#define M_NONFATAL        (1<<5)         
#define M_NOPREFIX        (1<<12)        
#define M_OPTERR          (1<<15)        
#define M_USAGE   (M_USAGE_SMALL | M_NOPREFIX | M_OPTERR)
#define M_USAGE_SMALL     (1<<13)        
#define M_WARN            (1<<6)         
#define OPENVPN_DEBUG_FILE PACKAGE ".log"
#define OPENVPN_ERROR_FP stderr
#define OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE  1
#define OPENVPN_EXIT_STATUS_ERROR                   1
#define OPENVPN_EXIT_STATUS_GOOD                    0
#define OPENVPN_EXIT_STATUS_USAGE                   1
#define OPENVPN_MSG_FP   stdout
#define SDL_CONSTRAIN (1<<0)
#define dmsg x_msg
#define msg x_msg
#define openvpn_errno()             GetLastError()
#define openvpn_strerror(e, gc)     strerror_win32(e, gc)
#define static_assert(expr, diagnostic) \
    extern int (*__OpenVPN_static_assert_function(void)) \
    [!!sizeof(struct { int __error_if_negative : (expr) ? 2 : -1; })]
#define DEBUG_LEVEL_USEC_TIME 4
#define D_ALIGN_DEBUG        LOGLEV(7, 70, M_DEBUG)  
#define D_ALIGN_ERRORS       LOGLEV(1, 14, M_NONFATAL)   
#define D_ARGV               LOGLEV(2, 25, 0)        
#define D_ARGV_PARSE_CMD     LOGLEV(7, 70, M_DEBUG)  
#define D_AUTH               LOGLEV(3, 37, 0)        
#define D_AUTO_USERID        LOGLEV(7, 70, M_DEBUG)  
#define D_CLIENT_NAT         LOGLEV(6, 69, M_DEBUG)  
#define D_CLOSE              LOGLEV(2, 22, 0)        
#define D_COMP               LOGLEV(9, 70, M_DEBUG)  
#define D_COMP_ERRORS        LOGLEV(1, 5, M_NONFATAL)   
#define D_COMP_LOW           LOGLEV(7, 70, M_DEBUG)  
#define D_CONNECTION_LIST    LOGLEV(7, 70, M_DEBUG)  
#define D_CRYPTO_DEBUG       LOGLEV(7, 70, M_DEBUG)  
#define D_CRYPT_ERRORS       LOGLEV(1, 2, M_NONFATAL)   
#define D_DHCP_OPT           LOGLEV(4, 53, 0)        
#define D_EVENT_ERRORS       LOGLEV(1, 10, M_NONFATAL)   
#define D_EVENT_WAIT         LOGLEV(8, 70, M_DEBUG)  
#define D_FRAG_DEBUG         LOGLEV(7, 70, M_DEBUG)  
#define D_FRAG_ERRORS        LOGLEV(1, 13, M_NONFATAL)   
#define D_GENKEY             LOGLEV(3, 31, 0)        
#define D_GREMLIN            LOGLEV(3, 30, 0)        
#define D_GREMLIN_VERBOSE    LOGLEV(8, 70, M_DEBUG)  
#define D_HANDSHAKE          LOGLEV(2, 20, 0)        
#define D_HANDSHAKE_VERBOSE  LOGLEV(8, 70, M_DEBUG)  
#define D_IFCONFIG_POOL      LOGLEV(3, 35, 0)        
#define D_IMPORT_ERRORS      LOGLEV(1, 8, M_NONFATAL)    
#define D_INIT_MEDIUM        LOGLEV(4, 60, 0)        
#define D_INTERVAL           LOGLEV(8, 70, M_DEBUG)  
#define D_LINK_ERRORS        LOGLEV(1, 1, M_NONFATAL)   
#define D_LINK_RW            LOGLEV(6, 69, M_DEBUG)  
#define D_LINK_RW_VERBOSE    LOGLEV(9, 70, M_DEBUG)  
#define D_LOG_RW             LOGLEV(5, 0,  0)        
#define D_LOW                LOGLEV(4, 52, 0)        
#define D_MANAGEMENT         LOGLEV(3, 40, 0)        
#define D_MANAGEMENT_DEBUG   LOGLEV(3, 70, M_DEBUG)  
#define D_MBUF               LOGLEV(4, 54, 0)        
#define D_MSS                LOGLEV(7, 70, M_DEBUG)  
#define D_MTU_DEBUG          LOGLEV(7, 70, M_DEBUG)  
#define D_MTU_INFO           LOGLEV(4, 61, 0)        
#define D_MULTI_DEBUG        LOGLEV(7, 70, M_DEBUG)  
#define D_MULTI_DROPPED      LOGLEV(4, 57, 0)        
#define D_MULTI_ERRORS       LOGLEV(1, 9, M_NONFATAL)    
#define D_MULTI_LOW          LOGLEV(3, 38, 0)        
#define D_MULTI_MEDIUM       LOGLEV(4, 58, 0)        
#define D_MULTI_TCP          LOGLEV(8, 70, M_DEBUG)  
#define D_OPENSSL_LOCK       LOGLEV(11, 70, M_DEBUG) 
#define D_OSBUF              LOGLEV(3, 43, 0)        
#define D_PACKET_CONTENT     LOGLEV(9, 70, M_DEBUG)  
#define D_PACKET_TRUNC_DEBUG LOGLEV(7, 70, M_DEBUG)  
#define D_PACKET_TRUNC_ERR   LOGLEV(4, 55, 0)        
#define D_PF_DEBUG           LOGLEV(7, 72, M_DEBUG)  
#define D_PF_DROPPED         LOGLEV(4, 56, 0)        
#define D_PF_DROPPED_BCAST   LOGLEV(7, 71, M_DEBUG)  
#define D_PF_INFO            LOGLEV(3, 45, 0)        
#define D_PID_DEBUG          LOGLEV(7, 70, M_DEBUG)  
#define D_PID_DEBUG_LOW      LOGLEV(4, 63, 0)        
#define D_PID_DEBUG_MEDIUM   LOGLEV(4, 64, 0)        
#define D_PID_PERSIST        LOGLEV(1, 12, M_NONFATAL)   
#define D_PID_PERSIST_DEBUG  LOGLEV(9, 70, M_DEBUG)  
#define D_PING               LOGLEV(7, 70, M_DEBUG)  
#define D_PKCS11_DEBUG       LOGLEV(9, 70, M_DEBUG)  
#define D_PLUGIN             LOGLEV(3, 39, 0)        
#define D_PLUGIN_DEBUG       LOGLEV(7, 70, M_DEBUG)  
#define D_PROXY              LOGLEV(2, 24, 0)        
#define D_PS_PROXY           LOGLEV(3, 44, 0)        
#define D_PS_PROXY_DEBUG     LOGLEV(7, 70, M_DEBUG)  
#define D_PUSH               LOGLEV(3, 34, 0)        
#define D_PUSH_DEBUG         LOGLEV(7, 73, M_DEBUG)  
#define D_PUSH_ERRORS        LOGLEV(1, 11, M_NONFATAL)   
#define D_READ_WRITE         LOGLEV(9, 70, M_DEBUG)  
#define D_REGISTRY           LOGLEV(11, 70, M_DEBUG) 
#define D_REL_DEBUG          LOGLEV(8, 70, M_DEBUG)  
#define D_REL_LOW            LOGLEV(7, 70, M_DEBUG)  
#define D_REPLAY_ERRORS      LOGLEV(1, 6, M_NONFATAL)   
#define D_RESOLVE_ERRORS     LOGLEV(1, 4, M_NONFATAL)   
#define D_RESTART            LOGLEV(3, 33, 0)        
#define D_ROUTE              LOGLEV(3, 0,  0)        
#define D_ROUTE_DEBUG        LOGLEV(7, 70, M_DEBUG)  
#define D_ROUTE_QUOTA        LOGLEV(3, 42, 0)        
#define D_SCHEDULER          LOGLEV(8, 70, M_DEBUG)  
#define D_SCHED_EXIT         LOGLEV(3, 41, 0)        
#define D_SCRIPT             LOGLEV(7, 70, M_DEBUG)  
#define D_SEMAPHORE          LOGLEV(7, 70, M_DEBUG)  
#define D_SEMAPHORE_LOW      LOGLEV(7, 70, M_DEBUG)  
#define D_SHAPER_DEBUG       LOGLEV(10, 70, M_DEBUG) 
#define D_SHOW_KEYS          LOGLEV(7, 70, M_DEBUG)  
#define D_SHOW_KEY_SOURCE    LOGLEV(7, 70, M_DEBUG)  
#define D_SHOW_NET           LOGLEV(7, 70, M_DEBUG)  
#define D_SHOW_OCC           LOGLEV(4, 51, 0)        
#define D_SHOW_PARMS         LOGLEV(4, 50, 0)        
#define D_SHOW_PKCS11        LOGLEV(7, 70, M_DEBUG)  
#define D_SOCKET_DEBUG       LOGLEV(7, 70, M_DEBUG)  
#define D_STREAM_DEBUG       LOGLEV(9, 70, M_DEBUG)  
#define D_STREAM_ERRORS      LOGLEV(1, 7, M_NONFATAL)    
#define D_TAP_WIN_DEBUG      LOGLEV(6, 69, M_DEBUG)  
#define D_TEST_FILE          LOGLEV(7, 70, M_DEBUG)  
#define D_TLS_DEBUG          LOGLEV(9, 70, M_DEBUG)  
#define D_TLS_DEBUG_LOW      LOGLEV(3, 20, 0)        
#define D_TLS_DEBUG_MED      LOGLEV(8, 70, M_DEBUG)  
#define D_TLS_ERRORS         LOGLEV(1, 3, M_NONFATAL)   
#define D_TLS_KEYSELECT      LOGLEV(7, 70, M_DEBUG)  
#define D_TLS_NO_SEND_KEY    LOGLEV(9, 70, M_DEBUG)  
#define D_TLS_STATE_ERRORS   LOGLEV(7, 70, M_DEBUG)  
#define D_TUNTAP_INFO        LOGLEV(3, 32, 0)        
#define D_TUN_RW             LOGLEV(6, 69, M_DEBUG)  
#define D_WIN32_IO           LOGLEV(9, 70, M_DEBUG)  
#define D_WIN32_IO_LOW       LOGLEV(7, 70, M_DEBUG)  
#define D_X509_ATTR          LOGLEV(4, 59, 0)        


#define M_INFO               LOGLEV(1, 0, 0)         
#define M_VERB0              LOGLEV(0, 0, 0)         
#define P2P_ERROR_DELAY_MS 0

#define BOOL_CAST(x) ((x) ? (true) : (false))
#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define IPV4_NETMASK_HOST 0xffffffffU
#define SIZE(x) (sizeof(x)/sizeof(x[0]))
#define CONFIGURE_DEFINES "N/A"
#define EMPTY_ARRAY_SIZE 0
#define ENABLE_CLIENT_SERVER 1
#define ENABLE_CRYPTO 1
#define ENABLE_CRYPTO_OPENSSL 1
#define ENABLE_DEBUG 1
#define ENABLE_DEF_AUTH 1
#define ENABLE_EUREPHIA 1
#define ENABLE_FRAGMENT 1
#define ENABLE_HTTP_PROXY 1
#define ENABLE_LZ4 1
#define ENABLE_LZO 1
#define ENABLE_MANAGEMENT 1
#define ENABLE_MULTIHOME 1
#define ENABLE_PF 1
#define ENABLE_PKCS11 1
#define ENABLE_PLUGIN 1
#define ENABLE_PORT_SHARE 1
#define ENABLE_SOCKS 1
#define F_OK 0
#define HAVE_ACCEPT 1
#define HAVE_ACCESS 1
#define HAVE_BIND 1
#define HAVE_CHDIR 1
#define HAVE_CHSIZE 1
#define HAVE_CONNECT 1
#define HAVE_CPP_VARARG_MACRO_ISO 1
#define HAVE_CTIME 1
#define HAVE_CTYPE_H 1
#define HAVE_DECL_SO_MARK 0
#define HAVE_DIRECT_H 1
#define HAVE_ERRNO_H 1
#define HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH 1
#define HAVE_FCNTL_H 1
#define HAVE_GETHOSTBYNAME 1
#define HAVE_GETSOCKNAME 1
#define HAVE_GETSOCKOPT 1
#define HAVE_INET_NTOA 1


#define HAVE_IN_PKTINFO 1
#define HAVE_IO_H 1
#define HAVE_LIMITS_H 1
#define HAVE_LISTEN 1
#define HAVE_LZO_LZO1X_H 1
#define HAVE_LZO_LZOUTIL_H 1
#define HAVE_MEMSET 1
#define HAVE_OPENSSL_ENGINE 1
#define HAVE_POLL 1
#define HAVE_PUTENV 1
#define HAVE_RECV 1
#define HAVE_RECVFROM 1
#define HAVE_SELECT 1
#define HAVE_SEND 1
#define HAVE_SENDTO 1
#define HAVE_SETSOCKOPT 1
#define HAVE_SOCKET 1
#define HAVE_STAT 1
#define HAVE_STDARG_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRERROR 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYSTEM 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIME 1
#define HAVE_TIME_H 1
#define HAVE_UNLINK 1
#define HAVE_VERSIONHELPERS_H 1
#define HAVE_VSNPRINTF 1
#define HAVE_WINDOWS_H 1
#define HAVE_WINSOCK2_H 1
#define HAVE_WS2TCPIP_H 1
#define NEED_COMPAT_LZ4 1
#define PATH_SEPARATOR     '\\'
#define PATH_SEPARATOR_STR "\\"
#define R_OK 4
#define SIGHUP    1
#define SIGINT    2
#define SIGTERM   15
#define SIGUSR1   10
#define SIGUSR2   12
#define S_IRUSR 0
#define S_IWUSR 0
#define TARGET_ALIAS "Windows-MSVC"
#define TARGET_WIN32 1
#define W_OK 2
#define X_OK 1
#define in_addr_t uint32_t
#define inline __inline
#define snprintf _snprintf
#define ssize_t SSIZE_T
#define strcasecmp _stricmp
#define strncasecmp strnicmp
#define strtoull strtoul

#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))
#define MAX_CERT_DEPTH 16
#define NS_CERT_CHECK_CLIENT (1<<1)
#define NS_CERT_CHECK_NONE (0)
#define NS_CERT_CHECK_SERVER (1<<0)
#define OPENVPN_KU_REQUIRED (0xFFFF)

#define TLS_AUTHENTICATION_DEFERRED   2
#define TLS_AUTHENTICATION_FAILED     1
#define TLS_AUTHENTICATION_SUCCEEDED  0
#define TLS_AUTHENTICATION_UNDEFINED  3
#define VERIFY_X509_NONE                0
#define VERIFY_X509_SUBJECT_DN          1
#define VERIFY_X509_SUBJECT_RDN         2
#define VERIFY_X509_SUBJECT_RDN_PREFIX  3
#define XT_FULL_CHAIN (1<<0)


#define AUTO_USERID 1




#define ENABLE_FEATURE_SHAPER 1
#define ENABLE_IP_PKTINFO 1




#define EPOLL 1
#define EXTENDED_SOCKET_ERROR_CAPABILITY 1
#define HAVE_GETTIMEOFDAY_NANOSECONDS 1




#define NTLM 1
#define OS_SPECIFIC_DIRSEP '\\'
#define O_BINARY 0
#define P2MP 1
#define P2MP_SERVER 1
#define PASSTOS_CAPABILITY 1


#define POLL 1
#define PORT_SHARE 1
#define PROXY_DIGEST_AUTH 1
#define SOCKET_UNDEFINED (INVALID_SOCKET)
#define SOL_IP IPPROTO_IP

#define SYSLOG_CAPABILITY 1
#define TIME_BACKTRACK_PROTECTION 1
#define UNIX_SOCK_SUPPORT 1


#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)

#define __APPLE_USE_RFC_3542  1

#define __func__ __FUNCTION__
#define likely(x)       __builtin_expect((x),1)
#define random rand
#define sleep(x) Sleep((x)*1000)
#define srandom srand
#define unlikely(x)     __builtin_expect((x),0)

#define AUTH_TOKEN_SIZE 32      
#define KEY_SCAN_SIZE 3
#define KS_LAME_DUCK  1         
#define KS_PRIMARY    0         
#define KS_SIZE       2         
#define SHOW_TLS_CIPHER_LIST_WARNING \
    "Be aware that that whether a cipher suite in this list can actually work\n" \
    "depends on the specific setup of both peers. See the man page entries of\n" \
    "--tls-cipher and --show-tls for more details.\n\n"
#define SSLF_AUTH_USER_PASS_OPTIONAL  (1<<3)
#define SSLF_CLIENT_CERT_NOT_REQUIRED (1<<0)
#define SSLF_CLIENT_CERT_OPTIONAL     (1<<1)
#define SSLF_CRL_VERIFY_DIR           (1<<5)
#define SSLF_OPT_VERIFY               (1<<4)
#define SSLF_TLS_VERSION_MAX_MASK     0xF  
#define SSLF_TLS_VERSION_MAX_SHIFT    10
#define SSLF_TLS_VERSION_MIN_MASK     0xF  
#define SSLF_TLS_VERSION_MIN_SHIFT    6
#define SSLF_USERNAME_AS_COMMON_NAME  (1<<2)

#define S_ACTIVE          6     
#define S_ERROR          -1     
#define S_GOT_KEY         5     
#define S_INITIAL         1     
#define S_NORMAL_OP       7     
#define S_PRE_START       2     
#define S_SENT_KEY        4     
#define S_START           3     
#define S_UNDEF           0     
#define TM_ACTIVE    0          
#define TM_LAME_DUCK 2          
#define TM_SIZE      3          
#define TM_UNTRUSTED 1          
#define UP_TYPE_AUTH        "Auth"
#define UP_TYPE_PRIVATE_KEY "Private Key"
#define SSLAPI SSLAPI_OPENSSL

#define TLS_VER_1_0     1
#define TLS_VER_1_1     2
#define TLS_VER_1_2     3
#define TLS_VER_BAD    -1
#define TLS_VER_UNSPEC  0 


#define AR_INTERACT   1
#define AR_NOINTERACT 2
#define AR_NONE       0
#define CE_DISABLED (1<<0)
#define CE_MAN_QUERY_PROXY (1<<1)
#define CE_MAN_QUERY_REMOTE_ACCEPT 2
#define CE_MAN_QUERY_REMOTE_MASK   (0x07)
#define CE_MAN_QUERY_REMOTE_MOD    3
#define CE_MAN_QUERY_REMOTE_QUERY  1
#define CE_MAN_QUERY_REMOTE_SHIFT  (2)
#define CE_MAN_QUERY_REMOTE_SKIP   4
#define CE_MAN_QUERY_REMOTE_UNDEF  0
#define CONNECTION_LIST_SIZE 64
#define MAN_CLIENT_AUTH_ENABLED(opt) ((opt)->management_flags & MF_CLIENT_AUTH)
#define MAX_PARMS 16
#define MODE_POINT_TO_POINT 0
#define MODE_SERVER         1

#define OPTION_LINE_SIZE 256
#define OPTION_PARM_SIZE 256
#define OPT_P_COMP            (1<<10) 
#define OPT_P_CONFIG          (1<<18)
#define OPT_P_CONNECTION      (1<<27)
#define OPT_P_DEFAULT   (~(OPT_P_INSTANCE|OPT_P_PULL_MODE))
#define OPT_P_ECHO            (1<<20)
#define OPT_P_EXPLICIT_NOTIFY (1<<19)
#define OPT_P_GENERAL         (1<<0)
#define OPT_P_INHERIT         (1<<21)
#define OPT_P_INSTANCE        (1<<17)
#define OPT_P_IPWIN32         (1<<3)
#define OPT_P_MESSAGES        (1<<11)
#define OPT_P_MTU             (1<<14) 
#define OPT_P_NCP             (1<<12) 
#define OPT_P_NICE            (1<<15)
#define OPT_P_PEER_ID         (1<<28)
#define OPT_P_PERSIST         (1<<8)
#define OPT_P_PERSIST_IP      (1<<9)
#define OPT_P_PLUGIN          (1<<24)
#define OPT_P_PULL_MODE       (1<<23)
#define OPT_P_PUSH            (1<<16)
#define OPT_P_ROUTE           (1<<2)
#define OPT_P_ROUTE_EXTRAS    (1<<22)
#define OPT_P_SCRIPT          (1<<4)
#define OPT_P_SETENV          (1<<5)
#define OPT_P_SHAPER          (1<<6)
#define OPT_P_SOCKBUF         (1<<25)
#define OPT_P_SOCKFLAGS       (1<<26)
#define OPT_P_TIMER           (1<<7)
#define OPT_P_TLS_PARMS       (1<<13) 
#define OPT_P_UP              (1<<1)
#define PING_EXIT    1
#define PING_RESTART 2
#define PING_UNDEF   0
#define PLUGIN_OPTION_LIST(opt) ((opt)->plugin_list)
#define PULL_DEFINED(opt) ((opt)->pull)
#define PUSH_DEFINED(opt) ((opt)->push_list)
#define RH_HOST_LEN 80
#define RH_PORT_LEN 20
#define ROUTE_OPTION_FLAGS(o) ((o)->route_method & ROUTE_METHOD_MASK)
#define SF_NOPOOL (1<<0)
#define SF_NO_PUSH_ROUTE_GATEWAY (1<<2)
#define SF_TCP_NODELAY_HELPER (1<<1)
#define SHAPER_DEFINED(opt) ((opt)->shaper)
#define streq(x, y) (!strcmp((x), (y)))

#define MAX_CIPHER_KEY_LENGTH 64
#define MAX_HMAC_KEY_LENGTH 64
#define OPENVPN_AEAD_TAG_LENGTH 16
#define OPENVPN_MAX_CIPHER_BLOCK_SIZE 32
#define OPENVPN_MAX_HMAC_SIZE   64

#define DES_KEY_LENGTH 8
#define MD4_DIGEST_LENGTH       16
#define MD5_DIGEST_LENGTH       16
#define OPENVPN_MAX_IV_LENGTH   MBEDTLS_MAX_IV_LENGTH
#define OPENVPN_MODE_CBC        MBEDTLS_MODE_CBC
#define OPENVPN_MODE_CFB        MBEDTLS_MODE_CFB
#define OPENVPN_MODE_GCM        MBEDTLS_MODE_GCM
#define OPENVPN_MODE_OFB        MBEDTLS_MODE_OFB
#define OPENVPN_OP_DECRYPT      MBEDTLS_DECRYPT
#define OPENVPN_OP_ENCRYPT      MBEDTLS_ENCRYPT
#define SHA256_DIGEST_LENGTH    32
#define SHA_DIGEST_LENGTH       20
#define mbed_ok(errval) \
    mbed_log_func_line_lite(D_CRYPT_ERRORS, errval, __func__, "__LINE__")

#define crypto_msg(flags, ...) \
    do { \
        crypto_print_openssl_errors(nonfatal(flags)); \
        msg((flags), __VA_ARGS__); \
    } while (false)

#define CN_DNAT 1
#define CN_INCOMING 1
#define CN_OUTGOING 0
#define CN_SNAT 0
#define MAX_CLIENT_NAT 64

#define COMPRESS_THRESHOLD 100
#define COMP_ALGV2_INDICATOR_BYTE       0x50
#define COMP_ALGV2_LZ4      11
#define COMP_ALGV2_LZ4_BYTE             1
#define COMP_ALGV2_LZO_BYTE             2
#define COMP_ALGV2_SNAPPY_BYTE          3
#define COMP_ALGV2_UNCOMPRESSED 10
#define COMP_ALGV2_UNCOMPRESSED_BYTE    0
#define COMP_ALG_LZ4    4 
#define COMP_ALG_LZO    2 
#define COMP_ALG_SNAPPY 3 
#define COMP_ALG_STUB   1 
#define COMP_ALG_UNDEF  0
#define COMP_EXTRA_BUFFER(len) ((len)/6 + 128 + 3 + COMP_PREFIX_LEN)
#define COMP_F_ADAPTIVE   (1<<0) 
#define COMP_F_ADVERTISE_STUBS_ONLY (1<<3) 
#define COMP_F_ASYM       (1<<1) 
#define COMP_F_SWAP       (1<<2) 
#define COMP_PREFIX_LEN 1
#define LZ4_COMPRESS_BYTE 0x69
#define LZO_COMPRESS_BYTE 0x66
#define NO_COMPRESS_BYTE      0xFA
#define NO_COMPRESS_BYTE_SWAP 0xFB 


#define AC_MIN_BYTES   1000     
#define AC_OFF_SEC     60       
#define AC_SAMP_SEC    2        
#define AC_SAVE_PCT    5        
#define LZO_COMPRESS    lzo1x_1_15_compress
#define LZO_DECOMPRESS  lzo1x_decompress_safe
#define LZO_WORKSPACE   LZO1X_1_15_MEM_COMPRESS


#define STATUS_OUTPUT_READ  (1<<0)
#define STATUS_OUTPUT_WRITE (1<<1)
#define ETT_DEFAULT (-1)
#define INTERVAL_DEBUG 0

#define USEC_TIMER_MAX      60 
#define USEC_TIMER_MAX_USEC (USEC_TIMER_MAX * 1000000)

#define TV_WITHIN_SIGMA_MAX_SEC 600
#define TV_WITHIN_SIGMA_MAX_USEC (TV_WITHIN_SIGMA_MAX_SEC * 1000000)

#define BIG_TIMEOUT  (60*60*24*7)  
#define CCD_DEFAULT "DEFAULT"

#define INLINE_FILE_TAG "[[INLINE]]"
#define PUSH_BUNDLE_SIZE 1024
#define PUSH_REQUEST_INTERVAL 5
#define SCRIPT_SECURITY_WARNING "WARNING: External program may not be called unless '--script-security 2' or higher is enabled. See --help text or man page for detailed info."
#define TLS_CHANNEL_BUF_SIZE 2048
#define counter_format  "%I64u"
#define fragment_header_format  "0x%08x"
#define ptr_format              "0x%I64x"
#define time_format             "%lu"
#define BUF_SIZE(f)              (TUN_MTU_SIZE(f) + FRAME_HEADROOM_BASE(f) * 2)
#define ETHERNET_MTU       1500
#define EXPANDED_SIZE(f)         ((f)->link_mtu)
#define EXPANDED_SIZE_DYNAMIC(f) ((f)->link_mtu_dynamic)
#define EXPANDED_SIZE_MIN(f)     (TUN_MTU_MIN + TUN_LINK_DELTA(f))
#define EXTRA_FRAME(f)           ((f)->extra_frame)
#define FRAME_HEADROOM(f)          frame_headroom(f, 0)
#define FRAME_HEADROOM_ADJ(f, fm)  frame_headroom(f, fm)
#define FRAME_HEADROOM_BASE(f)     (TUN_LINK_DELTA(f) + (f)->extra_buffer + (f)->extra_link)
#define FRAME_HEADROOM_MARKER_DECRYPT     (1<<0)
#define FRAME_HEADROOM_MARKER_FRAGMENT    (1<<1)
#define FRAME_HEADROOM_MARKER_READ_LINK   (1<<2)
#define FRAME_HEADROOM_MARKER_READ_STREAM (1<<3)
#define LINK_MTU_DEFAULT   1500
#define MAX_RW_SIZE_LINK(f)      (EXPANDED_SIZE(f) + (f)->extra_link)
#define MAX_RW_SIZE_TUN(f)       (PAYLOAD_SIZE(f))
#define MSSFIX_DEFAULT     1450

#define PAYLOAD_ALIGN 4
#define PAYLOAD_SIZE(f)          ((f)->link_mtu - (f)->extra_frame)
#define PAYLOAD_SIZE_DYNAMIC(f)  ((f)->link_mtu_dynamic - (f)->extra_frame)
#define SET_MTU_TUN         (1<<0) 
#define SET_MTU_UPPER_BOUND (1<<1) 
#define TAP_MTU_EXTRA_DEFAULT  32
#define TUN_LINK_DELTA(f)        ((f)->extra_frame + (f)->extra_tun)
#define TUN_MTU_DEFAULT    1500
#define TUN_MTU_MIN        100
#define TUN_MTU_SIZE(f)          ((f)->link_mtu - TUN_LINK_DELTA(f))
#define TUN_MTU_SIZE_DYNAMIC(f)  ((f)->link_mtu_dynamic - TUN_LINK_DELTA(f))
#define HTTP_AUTH_BASIC  1
#define HTTP_AUTH_DIGEST 2
#define HTTP_AUTH_N      5 
#define HTTP_AUTH_NONE   0
#define HTTP_AUTH_NTLM   3
#define HTTP_AUTH_NTLM2  4
#define MAX_CUSTOM_HTTP_HEADER 10
#define PAR_ALL 1   
#define PAR_NCT 2   
#define PAR_NO  0   

#define COMPAT_FLAG_QUERY         0       
#define COMPAT_FLAG_SET           (1<<0)  
#define COMPAT_NAMES              (1<<1)  
#define COMPAT_NO_NAME_REMAPPING  (1<<2)  
#define CR_ECHO     (1<<0)  
#define CR_RESPONSE (1<<1)  
#define GET_USER_PASS_DYNAMIC_CHALLENGE      (1<<7) 
#define GET_USER_PASS_INLINE_CREDS (1<<10)  
#define GET_USER_PASS_MANAGEMENT    (1<<0)
#define GET_USER_PASS_NEED_OK       (1<<3)
#define GET_USER_PASS_NEED_STR      (1<<5)
#define GET_USER_PASS_NOFATAL       (1<<4)
#define GET_USER_PASS_PASSWORD_ONLY (1<<2)
#define GET_USER_PASS_PREVIOUS_CREDS_FAILED (1<<6)
#define GET_USER_PASS_STATIC_CHALLENGE       (1<<8) 
#define GET_USER_PASS_STATIC_CHALLENGE_ECHO  (1<<9) 
#define INETD_SOCKET_DESCRIPTOR 0

#define SC_ECHO     (1<<0)  
#define SSEC_BUILT_IN  1 
#define SSEC_NONE      0 
#define SSEC_PW_ENV    3 
#define SSEC_SCRIPTS   2 
#define S_FATAL  (1<<1)
#define S_SCRIPT (1<<0)
#define USER_PASS_LEN 4096
#define get_random random


#define ANDROID_KEEP_OLD_TUN 1
#define ANDROID_OPEN_AFTER_CLOSE 2
#define ANDROID_OPEN_BEFORE_CLOSE 3
#define DAF_CONNECTION_CLOSED      (1<<1)
#define DAF_CONNECTION_ESTABLISHED (1<<0)
#define DAF_INITIAL_AUTH           (1<<2)
#define EKS_INPUT   2
#define EKS_READY   3
#define EKS_SOLICIT 1
#define EKS_UNDEF   0
#define IEC_CERTIFICATE 4
#define IEC_CLIENT_AUTH 1
#define IEC_CLIENT_PF   2
#define IEC_RSA_SIGN    3
#define IEC_UNDEF       0
#define LOG_ECHO_TO_LOG        (1<<11)
#define LOG_FATAL_NOTIFY       (1<<8)
#define LOG_PRINT_CRLF         (1<<7)
#define LOG_PRINT_ECHO_PREFIX  (1<<1)
#define LOG_PRINT_INTVAL       (1<<9)
#define LOG_PRINT_INT_DATE     (1<<3)
#define LOG_PRINT_LOCAL_IP     (1<<6)
#define LOG_PRINT_LOG_PREFIX   (1<<0)
#define LOG_PRINT_MSG_FLAGS    (1<<4)
#define LOG_PRINT_REMOTE_IP    (1<<10)
#define LOG_PRINT_STATE        (1<<5)
#define LOG_PRINT_STATE_PREFIX (1<<2)
#define MANAGEMENT_ECHO_BUFFER_SIZE           100
#define MANAGEMENT_LOG_HISTORY_INITIAL_SIZE   100
#define MANAGEMENT_N_PASSWORD_RETRIES           3
#define MANAGEMENT_STATE_BUFFER_SIZE          100
#define MANAGEMENT_VERSION                      1

#define MANSIG_IGNORE_USR1_HUP  (1<<0)
#define MANSIG_MAP_USR1_TO_HUP  (1<<1)
#define MANSIG_MAP_USR1_TO_TERM (1<<2)
#define MCF_SERVER (1<<0)  
#define MF_CLIENT_AUTH       (1<<6)
#define MF_CLIENT_PF         (1<<7)
#define MF_CONNECT_AS_CLIENT (1<<5)
#define MF_EXTERNAL_CERT    (1<<13)
#define MF_EXTERNAL_KEY    (1<<9)
#define MF_FORGET_DISCONNECT (1<<4)
#define MF_HOLD              (1<<2)
#define MF_QUERY_PASSWORDS   (1<<1)
#define MF_QUERY_PROXY      (1<<12)
#define MF_QUERY_REMOTE     (1<<11)
#define MF_SERVER            (1<<0)
#define MF_SIGNAL            (1<<3)
#define MF_UNIX_SOCK       (1<<8)
#define MF_UP_DOWN          (1<<10)
#define MS_CC_WAIT_READ     2  
#define MS_CC_WAIT_WRITE    3  
#define MS_INITIAL          0  
#define MS_LISTEN           1  
#define OPENVPN_STATE_ADD_ROUTES    3  
#define OPENVPN_STATE_ASSIGN_IP     2  
#define OPENVPN_STATE_AUTH          8  
#define OPENVPN_STATE_CLIENT_BASE   7  
#define OPENVPN_STATE_CONNECTED     4  
#define OPENVPN_STATE_CONNECTING    1  
#define OPENVPN_STATE_EXITING       6  
#define OPENVPN_STATE_GET_CONFIG    9  
#define OPENVPN_STATE_INITIAL       0  
#define OPENVPN_STATE_RECONNECTING  5  
#define OPENVPN_STATE_RESOLVE       10 
#define OPENVPN_STATE_TCP_CONNECT   11 
#define OPENVPN_STATE_WAIT          7  
#define UP_QUERY_DISABLED  0
#define UP_QUERY_NEED_OK   3
#define UP_QUERY_NEED_STR  4
#define UP_QUERY_PASS      2
#define UP_QUERY_USER_PASS 1
#define IP_MCAST_NETWORK      ((in_addr_t)224<<24)
#define IP_MCAST_SUBNET_MASK  ((in_addr_t)240<<24)
#define MAPF_IA_EMPTY_IF_UNDEF (1<<1)
#define MAPF_SHOW_ARP          (1<<2)
#define MAPF_SUBNET            (1<<0)
#define MROUTE_EXTRACT_BCAST     (1<<1)
#define MROUTE_EXTRACT_IGMP      (1<<3)
#define MROUTE_EXTRACT_MCAST     (1<<2)
#define MROUTE_EXTRACT_SUCCEEDED (1<<0)

#define MROUTE_SEC_EXTRACT_BCAST     (1<<(1+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_EXTRACT_IGMP      (1<<(3+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_EXTRACT_MCAST     (1<<(2+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_EXTRACT_SUCCEEDED (1<<(0+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_SHIFT         4
#define MR_ADDR_ETHER            1
#define MR_ADDR_IPV4             2
#define MR_ADDR_IPV6             3
#define MR_ADDR_MASK             3
#define MR_ADDR_NONE             0
#define MR_ARP                   16
#define MR_HELPER_NET_LEN 129
#define MR_MAX_ADDR_LEN 20
#define MR_WITH_NETBITS          8
#define MR_WITH_PORT             4
#define eth_addr mroute_union.eth_addr
#define raw_addr mroute_union.raw_addr
#define v4 mroute_union.v4
#define v4mappedv6 mroute_union.v4mappedv6
#define v6 mroute_union.v6
#define N_ROUTE_BYPASS 8
#define RGI_ADDR_DEFINED     (1<<0)  
#define RGI_HWADDR_DEFINED   (1<<2)  
#define RGI_IFACE_DEFINED    (1<<3)  
#define RGI_NETMASK_DEFINED  (1<<1)  
#define RGI_N_ADDRESSES 8
#define RGI_ON_LINK          (1<<5)
#define RGI_OVERFLOW         (1<<4)  
#define RG_AUTO_LOCAL     (1<<6)
#define RG_BLOCK_LOCAL    (1<<7)
#define RG_BYPASS_DHCP    (1<<3)
#define RG_BYPASS_DNS     (1<<4)
#define RG_DEF1           (1<<2)
#define RG_ENABLE         (1<<0)
#define RG_LOCAL          (1<<1)
#define RG_REROUTE_GW     (1<<5)
#define RL_DID_LOCAL                    (1<<1)
#define RL_DID_REDIRECT_DEFAULT_GATEWAY (1<<0)
#define RL_ROUTES_ADDED                 (1<<2)
#define ROUTE_DELETE_FIRST  (1<<2)

#define ROUTE_METHOD_ADAPTIVE  0  
#define ROUTE_METHOD_EXE       2  
#define ROUTE_METHOD_IPAPI     1  
#define ROUTE_METHOD_MASK      3
#define ROUTE_METHOD_SERVICE   3  
#define ROUTE_REF_GW        (1<<3)
#define RTSA_DEFAULT_METRIC   (1<<2)
#define RTSA_REMOTE_ENDPOINT  (1<<0)
#define RTSA_REMOTE_HOST      (1<<1)
#define RT_ADDED          (1<<1)
#define RT_DEFINED        (1<<0)
#define RT_METRIC_DEFINED (1<<2)
#define TLA_LOCAL           2
#define TLA_NONLOCAL        1
#define TLA_NOT_IMPLEMENTED 0
#define IFCONFIG_AFTER_TUN_OPEN  1
#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_DEFAULT         IFCONFIG_AFTER_TUN_OPEN
#define IPW32_SET_ADAPTIVE     4   
#define IPW32_SET_ADAPTIVE_DELAY_WINDOW 300
#define IPW32_SET_ADAPTIVE_TRY_NETSH    20
#define IPW32_SET_DHCP_MASQ    3   
#define IPW32_SET_IPAPI        2   
#define IPW32_SET_MANUAL       0   
#define IPW32_SET_N            5
#define IPW32_SET_NETSH        1   
#define N_DHCP_ADDR 4        
#define ROUTE_AFTER_TUN 1
#define ROUTE_BEFORE_TUN 0
#define ROUTE_ORDER_DEFAULT ROUTE_AFTER_TUN
#define TUNNEL_TOPOLOGY(tt) ((tt) ? ((tt)->topology) : TOP_UNDEF)
#define TUNNEL_TYPE(tt) ((tt) ? ((tt)->type) : DEV_TYPE_UNDEF)
#define TUN_ADAPTER_INDEX_INVALID ((DWORD)-1)


#define ADD_CHECKSUM_32(acc, u32) { \
        acc += (u32) & 0xffff; \
        acc += (u32) >> 16;    \
}
#define ADJUST_CHECKSUM(acc, cksum) { \
        int _acc = acc; \
        _acc += (cksum); \
        if (_acc < 0) { \
            _acc = -_acc; \
            _acc = (_acc >> 16) + (_acc & 0xffff); \
            _acc += _acc >> 16; \
            (cksum) = (uint16_t) ~_acc; \
        } else { \
            _acc = (_acc >> 16) + (_acc & 0xffff); \
            _acc += _acc >> 16; \
            (cksum) = (uint16_t) _acc; \
        } \
}
#define ARP_MAC_ADDR_TYPE 0x0001
#define ARP_REPLY   0x0002
#define ARP_REQUEST 0x0001
#define DEV_TYPE_NULL  1
#define DEV_TYPE_TAP   3    
#define DEV_TYPE_TUN   2    
#define DEV_TYPE_UNDEF 0
#define MTU_TO_MSS(mtu) (mtu - sizeof(struct openvpn_iphdr) \
                         - sizeof(struct openvpn_tcphdr))
#define OPENVPN_ETH_ALEN 6            
#define OPENVPN_ETH_P_ARP    0x0806   
#define OPENVPN_ETH_P_IPV4   0x0800   
#define OPENVPN_ETH_P_IPV6   0x86DD   
#define OPENVPN_IPH_GET_LEN(v) (((v) & 0x0F) << 2)
#define OPENVPN_IPH_GET_VER(v) (((v) >> 4) & 0x0F)
#define OPENVPN_IPPROTO_IGMP 2  
#define OPENVPN_IPPROTO_TCP  6  
#define OPENVPN_IPPROTO_UDP 17  
#define OPENVPN_IP_OFFMASK 0x1fff
#define OPENVPN_TCPH_ACK_MASK (1<<4)
#define OPENVPN_TCPH_CWR_MASK (1<<7)
#define OPENVPN_TCPH_ECE_MASK (1<<6)
#define OPENVPN_TCPH_FIN_MASK (1<<0)
#define OPENVPN_TCPH_GET_DOFF(d) (((d) & 0xF0) >> 2)
#define OPENVPN_TCPH_PSH_MASK (1<<3)
#define OPENVPN_TCPH_RST_MASK (1<<2)
#define OPENVPN_TCPH_SYN_MASK (1<<1)
#define OPENVPN_TCPH_URG_MASK (1<<5)
#define OPENVPN_TCPOLEN_MAXSEG 4
#define OPENVPN_TCPOPT_EOL     0
#define OPENVPN_TCPOPT_MAXSEG  2
#define OPENVPN_TCPOPT_NOP     1

#define SUB_CHECKSUM_32(acc, u32) { \
        acc -= (u32) & 0xffff; \
        acc -= (u32) >> 16;    \
}
#define TOP_NET30   1
#define TOP_P2P     2
#define TOP_SUBNET  3
#define TOP_UNDEF   0

#define EVENT_METHOD_FAST         (1<<1)
#define EVENT_METHOD_US_TIMEOUT   (1<<0)
#define EVENT_READ     (1<<0)
#define EVENT_UNDEF    4
#define EVENT_WRITE    (1<<1)
#define UNDEFINED_EVENT (NULL)
#define PERF_BIO_READ_CIPHERTEXT    2
#define PERF_BIO_READ_PLAINTEXT     0
#define PERF_BIO_WRITE_CIPHERTEXT   3
#define PERF_BIO_WRITE_PLAINTEXT    1
#define PERF_EVENT_LOOP             6

#define PERF_IO_WAIT                5
#define PERF_MULTI_BCAST            10
#define PERF_MULTI_CLOSE_INSTANCE   8
#define PERF_MULTI_CREATE_INSTANCE  7
#define PERF_MULTI_MCAST            11
#define PERF_MULTI_SHOW_STATS       9
#define PERF_N                      20
#define PERF_PROC_IN_LINK           14
#define PERF_PROC_IN_TUN            16
#define PERF_PROC_OUT_LINK          17
#define PERF_PROC_OUT_TUN           18
#define PERF_PROC_OUT_TUN_MTCP      19
#define PERF_READ_IN_LINK           13
#define PERF_READ_IN_TUN            15
#define PERF_SCRIPT                 12
#define PERF_TLS_MULTI_PROCESS      4
#define STACK_N               64
#define IS_SIG(c) ((c)->sig->signal_received)

#define SIG_SOURCE_CONNECTION_FAILED 2
#define SIG_SOURCE_HARD 1
#define SIG_SOURCE_SOFT 0
#define HANDLE_DEFINED(h) ((h) != NULL && (h) != INVALID_HANDLE_VALUE)
#define IN6_ARE_ADDR_EQUAL(a,b) \
    (memcmp((const void *)(a), (const void *)(b), sizeof(struct in6_addr)) == 0)
#define IOSTATE_IMMEDIATE_RETURN 2  
#define IOSTATE_INITIAL          0
#define IOSTATE_QUEUED           1  
#define NE32_PERSIST_EVENT (1<<0)
#define NE32_WRITE_EVENT   (1<<1)
#define NETSH_PATH_SUFFIX     "\\system32\\netsh.exe"

#define SYS_PATH_ENV_VAR_NAME "SystemRoot"  
#define WIN_7 2
#define WIN_8 3
#define WIN_IPCONFIG_PATH_SUFFIX "\\system32\\ipconfig.exe"
#define WIN_NET_PATH_SUFFIX "\\system32\\net.exe"
#define WIN_ROUTE_PATH_SUFFIX "\\system32\\route.exe"
#define WIN_VISTA 1
#define WIN_XP 0
#define WSO_FORCE_CONSOLE 2
#define WSO_FORCE_SERVICE 1
#define WSO_MODE_CONSOLE 2
#define WSO_MODE_SERVICE 1
#define WSO_MODE_UNDEF   0
#define WSO_NOFORCE       0

#define hashmask(n) (hashsize(n)-1)
#define hashsize(n) ((uint32_t)1<<(n))
#define GETADDR_CACHE_MASK              (GETADDR_DATAGRAM|GETADDR_PASSIVE)
#define GETADDR_DATAGRAM              (1<<11)
#define GETADDR_FATAL                 (1<<1)
#define GETADDR_FATAL_ON_SIGNAL       (1<<4)
#define GETADDR_HOST_ORDER            (1<<2)
#define GETADDR_MENTION_RESOLVE_RETRY (1<<3)
#define GETADDR_MSG_VIRT_OUT          (1<<6)
#define GETADDR_PASSIVE               (1<<10)
#define GETADDR_RANDOMIZE             (1<<9)
#define GETADDR_RESOLVE               (1<<0)
#define GETADDR_TRY_ONCE              (1<<7)
#define GETADDR_UPDATE_MANAGEMENT_STATE (1<<8)
#define GETADDR_WARN_ON_SIGNAL        (1<<5)
#define IA_EMPTY_IF_UNDEF (1<<0)
#define IA_NET_ORDER      (1<<1)
#define INETD_NONE   0
#define INETD_NOWAIT 2
#define INETD_WAIT   1
#define IPV4_INVALID_ADDR 0xffffffff
#define IPv4_TCP_HEADER_SIZE              40
#define IPv4_UDP_HEADER_SIZE              28
#define IPv6_TCP_HEADER_SIZE              60
#define IPv6_UDP_HEADER_SIZE              48
#define LS_MODE_DEFAULT           0
#define LS_MODE_TCP_ACCEPT_FROM   2
#define LS_MODE_TCP_LISTEN        1
#define MSG_NOSIGNAL 0
#define OIA_ERROR     -1
#define OIA_HOSTNAME   0
#define OIA_IP         1
#define OPENVPN_PORT "1194"
#define PS_DISABLED 0
#define PS_DONT_SHOW_ADDR       (1<<3)
#define PS_DONT_SHOW_FAMILY     (1<<4)
#define PS_ENABLED  1
#define PS_FOREIGN  2
#define PS_SHOW_PKTINFO         (1<<2)
#define PS_SHOW_PORT            (1<<1)
#define PS_SHOW_PORT_IF_DEFINED (1<<0)
#define RESOLV_RETRY_INFINITE 1000000000
#define SA_IP_PORT        (1<<0)
#define SA_SET_IF_NONZERO (1<<1)
#define SF_GETADDRINFO_DGRAM (1<<4)
#define SF_HOST_RANDOMIZE (1<<3)
#define SF_PORT_SHARE (1<<2)
#define SF_TCP_NODELAY (1<<1)
#define SF_USE_IP_PKTINFO (1<<0)

#define htonps(x) htons(x)
#define ntohps(x) ntohs(x)
#define openvpn_close_socket(s) closesocket(s)

#define MAX_PLUGINS 16

#define CO_IGNORE_PACKET_ID     (1<<1)
#define CO_MUTE_REPLAY_WARNINGS (1<<2)
#define CO_PACKET_ID_LONG_FORM  (1<<0)

#define CRYPT_ERROR(format) \
    do { msg(D_CRYPT_ERRORS, "%s: " format, error_prefix); goto error_exit; } while (false)
#define KEY_DIRECTION_BIDIRECTIONAL 0 
#define KEY_DIRECTION_INVERSE       2 
#define KEY_DIRECTION_NORMAL        1 
#define NONCE_SECRET_LEN_MAX 64
#define NONCE_SECRET_LEN_MIN 16
#define OPENVPN_AEAD_MIN_IV_LEN (sizeof(packet_id_type) + 8)
#define PRNG_NONCE_RESET_BYTES 1024
#define RKF_INLINE       (1<<1)
#define RKF_MUST_SUCCEED (1<<0)
#define DEFAULT_SEQ_BACKTRACK 64
#define DEFAULT_TIME_BACKTRACK 15
#define MAX_SEQ_BACKTRACK 65536
#define MAX_TIME_BACKTRACK 600
#define MIN_SEQ_BACKTRACK 0
#define MIN_TIME_BACKTRACK 0

#define PACKET_ID_MAX UINT32_MAX
#define PACKET_ID_WRAP_TRIGGER 0xFF000000
#define SEQ_REAP_INTERVAL 5
#define htonpid(x) htonl(x)
#define htontime(x) htonl((net_time_t)x)
#define ntohpid(x) ntohl(x)
#define ntohtime(x) ((time_t)ntohl(x))
#define packet_id_format "%u"
#define CIRC_LIST(name, type) \
    struct name { \
        int x_head; \
        int x_size; \
        int x_cap; \
        int x_sizeof; \
        type x_list[EMPTY_ARRAY_SIZE]; \
    }
#define CIRC_LIST_ALLOC(dest, list_type, size) \
    { \
        const int so = sizeof(list_type) + sizeof((dest)->x_list[0]) * (size); \
        (dest) = (list_type *) malloc(so); \
        check_malloc_return(dest); \
        memset((dest), 0, so); \
        (dest)->x_cap = size; \
        (dest)->x_sizeof = so; \
    }
#define CIRC_LIST_FREE(dest) \
    free(dest)

#define CIRC_LIST_INDEX(obj, index) \
    modulo_add((obj)->x_head, \
               index_verify((index), (obj)->x_size, "__FILE__", "__LINE__"), \
               (obj)->x_cap)
#define CIRC_LIST_ITEM(obj, index) \
    ((obj)->x_list[CIRC_LIST_INDEX((obj), (index))])
#define CIRC_LIST_PUSH(obj, item) \
    { \
        (obj)->x_head = modulo_add((obj)->x_head, -1, (obj)->x_cap); \
        (obj)->x_list[(obj)->x_head] = (item); \
        (obj)->x_size = min_int((obj)->x_size + 1, (obj)->x_cap); \
    }
#define CIRC_LIST_RESET(obj) \
    { \
        (obj)->x_head = 0; \
        (obj)->x_size = 0; \
    }
#define CIRC_LIST_SIZE(obj) \
    ((obj)->x_size)

#define SID_SIZE (sizeof(x_session_id_zero.id))
