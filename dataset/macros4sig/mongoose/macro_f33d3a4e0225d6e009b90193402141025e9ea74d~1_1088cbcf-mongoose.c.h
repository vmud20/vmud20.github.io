



















































































#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define BIG_ENDIAN __DARWIN_BIG_ENDIAN
#define BYTE_ORDER __DARWIN_BYTE_ORDER











#define CS_ENABLE_STDIO 1

#define CS_PLATFORM CS_P_MSP432
#define CS_P_CC3100 6
#define CS_P_CC3200 4
#define CS_P_CC3220 17
#define CS_P_CUSTOM 0
#define CS_P_ESP32 15
#define CS_P_ESP8266 3
#define CS_P_MBED 7
#define CS_P_MSP432 5
#define CS_P_NRF51 12
#define CS_P_NRF52 10
#define CS_P_NXP_KINETIS 9
#define CS_P_NXP_LPC 13
#define CS_P_PIC32 11
#define CS_P_STM32 16
#define CS_P_TM4C129 14
#define CS_P_UNIX 1
#define CS_P_WINCE 8
#define CS_P_WINDOWS 2
#define DIRSEP '/'
#define DO_NOT_WARN_UNUSED __attribute__((unused))
#define EINPROGRESS WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#define INT64_FMT PRId64
#define INT64_X_FMT PRIx64
#define INVALID_SOCKET (-1)
#define LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#define LWIP_TIMEVAL_PRIVATE 0
#define MG_ENABLE_BROADCAST 1
#define MG_ENABLE_DIRECTORY_LISTING 1
#define MG_ENABLE_FILESYSTEM 1
#define MG_ENABLE_HTTP_CGI MG_ENABLE_FILESYSTEM

#define MG_HOSTS_FILE_NAME "/etc/hosts"
#define MG_LWIP 1
#define MG_MAX_HTTP_HEADERS 40
#define MG_MAX_HTTP_REQUEST_SIZE 8192
#define MG_MAX_HTTP_SEND_MBUF 4096
#define MG_NET_IF MG_NET_IF_SOCKET
#define MG_NET_IF_LWIP_LOW_LEVEL 3
#define MG_NET_IF_PIC32 4
#define MG_NET_IF_SIMPLELINK 2
#define MG_NET_IF_SOCKET 1
#define MG_RESOLV_CONF_FILE_NAME "/etc/resolv.conf"
#define MG_SSL_IF MG_SSL_IF_SIMPLELINK
#define MG_SSL_IF_MBEDTLS 2
#define MG_SSL_IF_OPENSSL 1
#define MG_SSL_IF_SIMPLELINK 3
#define MG_VERSION "6.11"
#define NOINLINE __attribute__((noinline))
#define NOINSTR __attribute__((no_instrument_function))
#define NORETURN __attribute__((noreturn))
#define PDP_ENDIAN __DARWIN_PDP_ENDIAN
#define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#define SIZE_T_FMT "u"
#define SOMAXCONN 8
#define STR(x) STRX(x)
#define STRX(x) #x
#define S_IFCHR __S_IFCHR
#define S_IFDIR __S_IFDIR
#define S_IFREG __S_IFREG
#define S_ISDIR(mode) __S_ISTYPE((mode), __S_IFDIR)
#define S_ISREG(mode) __S_ISTYPE((mode), __S_IFREG)
#define UINT16_MAX 65535
#define UINT32_MAX 4294967295
#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define WEAK __attribute__((weak))

#define _FILE_OFFSET_BITS 64

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _XOPEN_SOURCE 600


#define __S_IFCHR 0020000
#define __S_IFDIR 0040000
#define __S_IFMT 0170000
#define __S_IFREG 0100000
#define __S_ISTYPE(mode, mask) (((mode) &__S_IFMT) == (mask))

#define __func__ "__FILE__" ":" STR("__LINE__")
#define closesocket(x) close(x)
#define fileno _fileno
#define fseeko(x, y, z) _fseeki64((x), (y), (z))
#define gmtime_r(a, b) \
  do {                 \
    *(b) = *gmtime(a); \
  } while (0)
#define inet_ntop(af, src, dst, size)                                          \
  (((af) == AF_INET) ? ipaddr_ntoa_r((const ip_addr_t *) (src), (dst), (size)) \
                     : NULL)
#define inet_pton(af, src, dst) \
  (((af) == AF_INET) ? ipaddr_aton((src), (ip_addr_t *) (dst)) : 0)
#define pclose(x) _pclose(x)
#define pid_t HANDLE
#define popen(x, y) _popen((x), (y))
#define snprintf _snprintf
#define stat(a, b) _stat(a, b)
#define strdup _strdup
#define timegm _mkgmtime
#define timeval SlTimeval_t
#define to64(x) strtoll(x, NULL, 10)
#define va_copy __va_copy
#define vsnprintf _vsnprintf
