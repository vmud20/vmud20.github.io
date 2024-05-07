#include<netinet/in_systm.h>


#include<libgen.h>

#include<sys/stat.h>


#include<stdio.h>
#include<error.h>

#include<sys/un.h>
#include<syslog.h>
#include<sys/uio.h>
#include<linux/errqueue.h>

#include<linux/sockios.h>
#include<stdbool.h>
#include<sys/poll.h>
#include<string.h>

#include<netdb.h>
#include<sys/ioctl.h>
#include<time.h>

#include<strings.h>
#include<netinet/ip.h>


#include<grp.h>

#include<ctype.h>
#include<sys/file.h>
#include<pwd.h>
#include<net/if.h>



#include<stdlib.h>
#include<inttypes.h>
#include<sys/wait.h>
#include<errno.h>
#include<netinet/in.h>
#include<err.h>
#include<linux/if_tun.h>


#include<resolv.h>
#include<stdint.h>
#include<fcntl.h>
#include<netinet/tcp.h>
#include<stdarg.h>
#include<arpa/inet.h>
#include<limits.h>
#include<sys/mman.h>

#include<sys/types.h>
#include<assert.h>

#include<signal.h>

#include<sys/socket.h>

#include<sys/epoll.h>
#include<sys/time.h>
#include<unistd.h>


#include<linux/types.h>

#define VALGRIND_MAKE_READABLE(addr, len)
#define openvpn_dmalloc(file, line, size) dmalloc_malloc((file), (line), (size), DMALLOC_FUNC_MALLOC, 0, 0)

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
#define AUTO_USERID 1

#define EMPTY_ARRAY_SIZE 1



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
#define CONFIGURE_DEFINES "N/A"
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
#define snprintf _snprintf
#define ssize_t SSIZE_T
#define strcasecmp _stricmp
#define strncasecmp strnicmp
#define strtoull strtoul
