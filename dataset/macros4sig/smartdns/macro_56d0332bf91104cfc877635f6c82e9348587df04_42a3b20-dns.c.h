


#include<arpa/inet.h>
#include<stddef.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<stdarg.h>
#include<string.h>


#include<unistd.h>
#include<fcntl.h>
#include<stdio.h>
#define BASE_FILE_NAME                                                       \
    (__builtin_strrchr("__FILE__", '/') ? __builtin_strrchr("__FILE__", '/') + 1 \
                                      : "__FILE__")

#define TLOG_MAX_LINE_LEN (1024)
#define TLOG_MULTI_WRITE (1 << 2)
#define TLOG_NOCOMPRESS (1 << 0)
#define TLOG_NONBLOCK (1 << 3)
#define TLOG_SCREEN (1 << 4)
#define TLOG_SEGMENT (1 << 1)
#define TLOG_SUPPORT_FORK (1 << 5)
#define Tlog_stream(level)        \
    if (tlog_getlevel() <= level) \
    Tlog(level, BASE_FILE_NAME, "__LINE__", __func__, NULL).Stream()
#define tlog(level, format, ...) tlog_ext(level, BASE_FILE_NAME, "__LINE__", __func__, NULL, format, ##__VA_ARGS__)
#define tlog_debug Tlog_stream(TLOG_DEBUG)
#define tlog_error Tlog_stream(TLOG_ERROR)
#define tlog_fatal Tlog_stream(TLOG_FATAL)
#define tlog_info Tlog_stream(TLOG_INFO)
#define tlog_notice Tlog_stream(TLOG_NOTICE)
#define tlog_out(stream) TlogOut(stream).Stream()
#define tlog_warn Tlog_stream(TLOG_WARN)

#define DNS_ADDR_FAMILY_IP 1
#define DNS_ADDR_FAMILY_IPV6 2
#define DNS_DEFAULT_PACKET_SIZE 512
#define DNS_IN_PACKSIZE (512 * 8)
#define DNS_MAX_ALPN_LEN 32
#define DNS_MAX_CNAME_LEN 256
#define DNS_MAX_ECH_LEN 256
#define DNS_MAX_OPT_LEN 256
#define DNS_OPT_ECS_FAMILY_IPV4 1
#define DNS_OPT_ECS_FAMILY_IPV6 2
#define DNS_PACKET_DICT_SIZE 16
#define DNS_PACKSIZE (512 * 12)
#define DNS_RR_AAAA_LEN 16
#define DNS_RR_A_LEN 4

