










































#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
#define __GLIBC_USE(F)  __GLIBC_USE_ ## F
# define __GNUC_PREREQ(maj, min) \

#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
# define __OPTIMIZE_SIZE__   1
# define __need_uClibc_config_h
# define FAST_FUNC

#define config_read(parser, tokens, max, min, str, flags) \
	config_read(parser, tokens, ((flags) | (((min) & 0xFF) << 8) | ((max) & 0xFF)), str)
# define BUFSIZ __STDIO_BUFSIZ
# define EOF (-1)
# define __need_FILE
# define __need_NULL
# define __need___FILE
# define __need___va_list
# define __need_getopt
# define __need_size_t
#define clearerr(_fp)                __CLEARERR(_fp)
#define clearerr_unlocked(_fp)       __CLEARERR_UNLOCKED(_fp)
#define feof(_fp)                    __FEOF(_fp)
#define feof_unlocked(_fp)           __FEOF_UNLOCKED(_fp)
#define ferror(_fp)                  __FERROR(_fp)
#define ferror_unlocked(_fp)         __FERROR_UNLOCKED(_fp)
#define fgetc(_fp)                   __FGETC(_fp)
#define fgetc_unlocked(_fp)          __FGETC_UNLOCKED(_fp)
#define fputc(_ch, _fp)              __FPUTC(_ch, _fp)
#define fputc_unlocked(_ch, _fp)     __FPUTC_UNLOCKED(_ch, _fp)
#define getc(_fp) __GETC(_fp)
#define getc_unlocked(_fp) __GETC_UNLOCKED(_fp)


#define putc(_ch, _fp) __PUTC(_ch, _fp)
#define putc_unlocked(_ch, _fp) __PUTC_UNLOCKED(_ch, _fp)
#define putchar(_ch)                 __PUTC((_ch), __stdout)
#define putchar_unlocked(_ch)        __PUTC_UNLOCKED((_ch), __stdout)
#define stderr stderr
#define stdin stdin
#define stdout stdout
#define DEV_BSIZE       512
# define __undef_ARG_MAX
# define howmany(x, y)	(((x) + ((y) - 1)) / (y))
#define powerof2(x)	((((x) - 1) & (x)) == 0)
# define roundup(x, y)	(__builtin_constant_p (y) && powerof2 (y)	      \
			 ? (((x) + (y) - 1) & ~((y) - 1))		      \
			 : ((((x) + ((y) - 1)) / (y)) * (y)))
#  define __blkcnt_t_defined
# define __blksize_t_defined
#  define __daddr_t_defined
# define __dev_t_defined
#  define __fsblkcnt_t_defined
#  define __fsfilcnt_t_defined
# define __gid_t_defined
# define __id_t_defined
# define __ino64_t_defined
# define __ino_t_defined
#  define __int8_t_defined
# define __intN_t(N, MODE) \
  typedef int int##N##_t __attribute__ ((__mode__ (MODE)))
# define __key_t_defined
# define __mode_t_defined
# define __need_clock_t


# define __nlink_t_defined
# define __off64_t_defined
# define __off_t_defined
# define __pid_t_defined
# define __ssize_t_defined
#  define __suseconds_t_defined
#  define __u_char_defined
# define __u_intN_t(N, MODE) \
  typedef unsigned int u_int##N##_t __attribute__ ((__mode__ (MODE)))
# define __uid_t_defined
#  define __useconds_t_defined
# define __isleap(year)	\
  ((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))
# define ACCESSPERMS (S_IRWXU|S_IRWXG|S_IRWXO) 
# define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)
# define DEFFILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
# define S_IFMT		__S_IFMT
# define S_ISFIFO(mode)	 __S_ISTYPE((mode), __S_IFIFO)
# define S_ISLNK(mode)	 __S_ISTYPE((mode), __S_IFLNK)
# define S_ISSOCK(mode) __S_ISTYPE((mode), __S_IFSOCK)
# define S_TYPEISMQ(buf) __S_TYPEISMQ(buf)
# define S_TYPEISSEM(buf) __S_TYPEISSEM(buf)
# define S_TYPEISSHM(buf) __S_TYPEISSHM(buf)
#define _MKNOD_VER 0
#define _STAT_VER 0
#  define __blkcnt_t_defined
#  define __blksize_t_defined
#  define __dev_t_defined
#  define __gid_t_defined
#  define __ino_t_defined
#  define __mode_t_defined
#  define __need_time_t
#  define __need_timespec
#  define __nlink_t_defined
#  define __off_t_defined
#  define __uid_t_defined
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)	      \
		      + strlen ((ptr)->sun_path))
# define __ASMNAME(cname)  __ASMNAME2 ("__USER_LABEL_PREFIX__", cname)
# define __ASMNAME2(prefix, cname) __STRING (prefix) cname
# define __BEGIN_DECLS
# define __BEGIN_NAMESPACE_C99
# define __BEGIN_NAMESPACE_STD
#define __CONCAT(x,y)	x ## y
# define __END_DECLS
# define __END_NAMESPACE_C99
# define __END_NAMESPACE_STD
#  define __LEAF , __leaf__
#  define __LEAF_ATTR __attribute__ ((__leaf__))
#   define __NTH(fct)	__LEAF_ATTR fct throw ()
#define __P(args)	args
#define __PMT(args)	args
# define __REDIRECT(name, proto, alias) name proto __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_NTH(name, proto, alias) \
     name proto __THROW __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_NTHNL(name, proto, alias) \
     name proto __THROWNL __asm__ (__ASMNAME (#alias))
#define __STRING(x)	#x
#   define __THROW
#   define __THROWNL
# define __USING_NAMESPACE_C99(name) using __c99::name;
# define __USING_NAMESPACE_STD(name) using std::name;
# define __always_inline __inline
# define __attribute__(xyz)	
# define __attribute_aligned__(size) __attribute__ ((__aligned__ (size)))
# define __attribute_alloc_size__(params) \
  __attribute__ ((__alloc_size__ params))
# define __attribute_const__ __attribute__((__const__))
# define __attribute_deprecated__ __attribute__ ((__deprecated__))
# define __attribute_format_arg__(x) __attribute__ ((__format_arg__ (x)))
# define __attribute_format_strfmon__(a,b) \
  __attribute__ ((__format__ (__strfmon__, a, b)))
# define __attribute_malloc__ __attribute__ ((__malloc__))
# define __attribute_noinline__ __attribute__ ((__noinline__))
# define __attribute_pure__ __attribute__ ((__pure__))
# define __attribute_used__ __attribute__ ((__used__))
# define __attribute_warn_unused_result__ \
   __attribute__ ((__warn_unused_result__))
# define __errordecl(name, msg) \
  extern void name (void) __attribute__((__error__ (msg)))
#   define __extern_always_inline \
  extern __always_inline __attribute__ ((__gnu_inline__, __artificial__))
#  define __extern_inline extern __inline __attribute__ ((__gnu_inline__))
#define __long_double_t  long double
# define __nonnull(params)
#define __ptr_t void *
# define __va_arg_pack() __builtin_va_arg_pack ()
# define __va_arg_pack_len() __builtin_va_arg_pack_len ()
# define __warnattr(msg) __attribute__((__warning__ (msg)))
# define __warndecl(name, msg) \
  extern void name (void) __attribute__((__warning__ (msg)))
# define __wur 
# define SYS_NMLN  _UTSNAME_LENGTH
# define _UTSNAME_MACHINE_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_NODENAME_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_RELEASE_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_SYSNAME_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_VERSION_LENGTH _UTSNAME_LENGTH

#define NS_DSA_MAX_BYTES        405
#define NS_DSA_MIN_SIZE         213
#define NS_DSA_SIG_SIZE         41
#define NS_GET16(s, cp) do { \
	register u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += NS_INT16SZ; \
} while (0)
#define NS_GET32(l, cp) do { \
	register u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += NS_INT32SZ; \
} while (0)
#define NS_KEY_PROT_DNSSEC      3
#define NS_KEY_PROT_EMAIL       2
#define NS_KEY_PROT_IPSEC       4
#define NS_KEY_PROT_TLS         1
#define NS_KEY_RESERVED_BITMASK2 0xFFFF 
#define NS_NXT_MAX 127
#define NS_PUT16(s, cp) do { \
	register u_int16_t t_s = (u_int16_t)(s); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
} while (0)
#define NS_PUT32(l, cp) do { \
	register u_int32_t t_l = (u_int32_t)(l); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += NS_INT32SZ; \
} while (0)
#define NS_TSIG_ALG_HMAC_MD5 "HMAC-MD5.SIG-ALG.REG.INT"
#define NS_TSIG_ERROR_FORMERR -12
#define NS_TSIG_ERROR_NO_SPACE -11
#define NS_TSIG_ERROR_NO_TSIG -10
#define NS_TSIG_FUDGE 300
#define NS_TSIG_TCP_COUNT 100

#define ns_datetosecs		__ns_datetosecs
#define ns_find_tsig		__ns_find_tsig
#define ns_get16		__ns_get16
#define ns_get32		__ns_get32
#define ns_initparse		__ns_initparse
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_parserr		__ns_parserr
#define ns_put16		__ns_put16
#define ns_put32		__ns_put32
#define ns_rr_class(rr)	((ns_class)((rr).rr_class + 0))
#define ns_rr_name(rr)	(((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_rdata(rr)	((rr).rdata + 0)
#define ns_rr_rdlen(rr)	((rr).rdlength + 0)
#define ns_rr_ttl(rr)	((rr).ttl + 0)
#define ns_rr_type(rr)	((ns_type)((rr).type + 0))
#define ns_skiprr		__ns_skiprr
#define ns_t_rr_p(t) (!ns_t_qt_p(t) && !ns_t_mrr_p(t))
#define ns_t_udp_p(t) ((t) != ns_t_axfr && (t) != ns_t_zxfr)
#define ns_t_xfr_p(t) ((t) == ns_t_axfr || (t) == ns_t_ixfr || \
		       (t) == ns_t_zxfr)
#  define OFF64_HI(offset) (uint32_t)(offset >> 32)
#  define OFF64_HI_LO(offset) __LONG_LONG_PAIR(OFF64_HI(offset), OFF64_LO(offset))
#  define OFF64_LO(offset) (uint32_t)(offset & 0xffffffff)
#  define OFF_HI(offset) (offset >> 31)
#  define OFF_HI_LO(offset) __LONG_LONG_PAIR(OFF_HI(offset), OFF_LO(offset))
#  define OFF_LO(offset) (offset)
# define __FLOAT_WORD_ORDER __BYTE_ORDER
# define __LONG_LONG_PAIR(HI, LO) LO, HI
#  define be16toh(x) __bswap_16 (x)
#  define be32toh(x) __bswap_32 (x)
#  define be64toh(x) (x)
#  define htobe16(x) __bswap_16 (x)
#  define htobe32(x) __bswap_32 (x)
#  define htobe64(x) __bswap_64 (x)
#  define htole16(x) (x)
#  define htole32(x) (x)
#  define htole64(x) __bswap_64 (x)
#  define le16toh(x) (x)
#  define le32toh(x) (x)
#  define le64toh(x) __bswap_64 (x)
# define __isascii(c) (((c) & ~0x7f) == 0)
# define isascii(c) __isascii (c)
#  define EAI_ADDRFAMILY  -9	
#  define EAI_INPROGRESS  -100	
#  define EAI_NOTCANCELED -102	
#  define NI_MAXHOST      1025
#  define NI_MAXSERV      32
# define NI_NUMERICSERV 2	
# define __need_sigevent_t
#   define __set_h_errno(x) (h_errno = (x))
#    define h_errno __libc_h_errno
# define INT16_C(c)	c
# define INT32_C(c)	c
#  define INT64_C(c)	c ## L
# define INT8_C(c)	c
#  define INTMAX_C(c)	c ## L
# define UINT16_C(c)	c
# define UINT32_C(c)	c ## U
#  define UINT64_C(c)	c ## UL
# define UINT8_C(c)	c
#  define UINTMAX_C(c)	c ## UL
#  define WCHAR_MAX		__WCHAR_MAX
#  define WCHAR_MIN		__WCHAR_MIN
#  define __INT64_C(c)	c ## L
#  define __UINT64_C(c)	c ## UL
#  define __intptr_t_defined
# define __uint32_t_defined
#define GROUP_FILTER_SIZE(numsrc) (sizeof (struct group_filter) \
				   - sizeof (struct sockaddr_storage)	      \
				   + ((numsrc)				      \
				      * sizeof (struct sockaddr_storage)))
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6_ARE_ADDR_EQUAL(a,b) \
	((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0])     \
	 && (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1])  \
	 && (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2])  \
	 && (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))
#define IN6_IS_ADDR_LINKLOCAL(a) \
	((((const uint32_t *) (a))[0] & htonl (0xffc00000))		      \
	 == htonl (0xfe800000))
#define IN6_IS_ADDR_LOOPBACK(a) \
	(((const uint32_t *) (a))[0] == 0				      \
	 && ((const uint32_t *) (a))[1] == 0				      \
	 && ((const uint32_t *) (a))[2] == 0				      \
	 && ((const uint32_t *) (a))[3] == htonl (1))
#define IN6_IS_ADDR_MC_GLOBAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((const uint8_t *) (a))[1] & 0xf) == 0xe))
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((const uint8_t *) (a))[1] & 0xf) == 0x2))
#define IN6_IS_ADDR_MC_NODELOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((const uint8_t *) (a))[1] & 0xf) == 0x1))
#define IN6_IS_ADDR_MC_ORGLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((const uint8_t *) (a))[1] & 0xf) == 0x8))
#define IN6_IS_ADDR_MC_SITELOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((const uint8_t *) (a))[1] & 0xf) == 0x5))
#define IN6_IS_ADDR_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)
#define IN6_IS_ADDR_SITELOCAL(a) \
	((((const uint32_t *) (a))[0] & htonl (0xffc00000))		      \
	 == htonl (0xfec00000))
#define IN6_IS_ADDR_UNSPECIFIED(a) \
	(((const uint32_t *) (a))[0] == 0				      \
	 && ((const uint32_t *) (a))[1] == 0				      \
	 && ((const uint32_t *) (a))[2] == 0				      \
	 && ((const uint32_t *) (a))[3] == 0)
#define IN6_IS_ADDR_V4COMPAT(a) \
	((((const uint32_t *) (a))[0] == 0)				      \
	 && (((const uint32_t *) (a))[1] == 0)			      \
	 && (((const uint32_t *) (a))[2] == 0)			      \
	 && (ntohl (((const uint32_t *) (a))[3]) > 1))
#define IN6_IS_ADDR_V4MAPPED(a) \
	((((const uint32_t *) (a))[0] == 0)				      \
	 && (((const uint32_t *) (a))[1] == 0)			      \
	 && (((const uint32_t *) (a))[2] == htonl (0xffff)))
#define INADDR_ALLRTRS_GROUP    ((in_addr_t) 0xe0000002) 
#define INADDR_MAX_LOCAL_GROUP  ((in_addr_t) 0xe00000ff) 
#define INET6_ADDRSTRLEN 46
#define INET_ADDRSTRLEN 16
#define IPPROTO_AH		IPPROTO_AH
#define IPPROTO_COMP		IPPROTO_COMP
#define IPPROTO_DCCP		IPPROTO_DCCP
#define IPPROTO_DSTOPTS		IPPROTO_DSTOPTS
#define IPPROTO_EGP		IPPROTO_EGP
#define IPPROTO_ENCAP		IPPROTO_ENCAP
#define IPPROTO_ESP		IPPROTO_ESP
#define IPPROTO_GRE		IPPROTO_GRE
#define IPPROTO_HOPOPTS		IPPROTO_HOPOPTS
#define IPPROTO_ICMP		IPPROTO_ICMP
#define IPPROTO_ICMPV6		IPPROTO_ICMPV6
#define IPPROTO_IDP		IPPROTO_IDP
#define IPPROTO_IGMP		IPPROTO_IGMP
#define IPPROTO_IP		IPPROTO_IP
#define IPPROTO_IPIP		IPPROTO_IPIP
#define IPPROTO_IPV6		IPPROTO_IPV6
#define IPPROTO_MH		IPPROTO_MH
#define IPPROTO_MTP		IPPROTO_MTP
#define IPPROTO_NONE		IPPROTO_NONE
#define IPPROTO_PIM		IPPROTO_PIM
#define IPPROTO_PUP		IPPROTO_PUP
#define IPPROTO_RAW		IPPROTO_RAW
#define IPPROTO_ROUTING		IPPROTO_ROUTING
#define IPPROTO_RSVP		IPPROTO_RSVP
#define IPPROTO_SCTP		IPPROTO_SCTP
#define IPPROTO_TCP		IPPROTO_TCP
#define IPPROTO_TP		IPPROTO_TP
#define IPPROTO_UDP		IPPROTO_UDP
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
#define IP_MSFILTER_SIZE(numsrc) (sizeof (struct ip_msfilter) \
				  - sizeof (struct in_addr)		      \
				  + (numsrc) * sizeof (struct in_addr))
# define htonl(x)	(x)
# define htons(x)	(x)
# define ntohl(x)	(x)
# define ntohs(x)	(x)
#define SHUT_RD		SHUT_RD
#define SHUT_WR		SHUT_WR
# define __SOCKADDR_ALLTYPES \
  __SOCKADDR_ONETYPE (sockaddr) \
  __SOCKADDR_ONETYPE (sockaddr_at) \
  __SOCKADDR_ONETYPE (sockaddr_ax25) \
  __SOCKADDR_ONETYPE (sockaddr_dl) \
  __SOCKADDR_ONETYPE (sockaddr_eon) \
  __SOCKADDR_ONETYPE (sockaddr_in) \
  __SOCKADDR_ONETYPE (sockaddr_in6) \
  __SOCKADDR_ONETYPE (sockaddr_inarp) \
  __SOCKADDR_ONETYPE (sockaddr_ipx) \
  __SOCKADDR_ONETYPE (sockaddr_iso) \
  __SOCKADDR_ONETYPE (sockaddr_ns) \
  __SOCKADDR_ONETYPE (sockaddr_un) \
  __SOCKADDR_ONETYPE (sockaddr_x25)
# define __SOCKADDR_ONETYPE(type) struct type *__restrict __##type##__;
#define RES_PRF_CLASS   0x00000004
#define _PATH_RESCONF        "/etc/resolv.conf"
# define _RESOLV_H_
# define __res_state_defined
#     define __resp __libc_resp
#    define _res (*__resp)
#define b64_ntop		__b64_ntop
#define b64_pton		__b64_pton
#define dn_comp			__dn_comp
#define dn_expand		__dn_expand
#define dn_skipname		__dn_skipname
#define nsaddr nsaddr_list[0]		
#define res_close		__res_close
#define res_init		__res_init
#define res_mkquery		__res_mkquery
#define res_nclose		__res_nclose
#define res_ninit		__res_ninit
#define res_query		__res_query
#define res_querydomain		__res_querydomain
#define res_search		__res_search
# define F_LOCK  1	
# define F_TEST  3	
# define F_TLOCK 2	
# define F_ULOCK 0	
# define TEMP_FAILURE_RETRY(expression) \
  (__extension__							      \
    ({ long int __result;						      \
       do __result = (long int) (expression);				      \
       while (__result == -1L && errno == EINTR);			      \
       __result; }))
#  define __intptr_t_defined

# define __need_getopt
#  define __off64_t_defined
#  define __pid_t_defined
                                                    #  define __socklen_t_defined
# define __ssize_t_defined
#  define __useconds_t_defined
#define smallint_type int
# define __COMPAR_FN_T
# define __UCLIBC_MAX_ATEXIT     INT_MAX
#   define __WAIT_INT(status) \
  (__extension__ (((union { __typeof(status) __in; int __i; }) \
		   { .__in = (status) }).__i))
# define __malloc_and_calloc_defined
#define		__need_size_t
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
#define ITIMER_PROF ITIMER_PROF
#define ITIMER_REAL ITIMER_REAL
#define ITIMER_VIRTUAL ITIMER_VIRTUAL
# define TIMESPEC_TO_TIMEVAL(tv, ts) {                                   \
        (tv)->tv_sec = (ts)->tv_sec;                                    \
        (tv)->tv_usec = (ts)->tv_nsec / 1000;                           \
}
# define TIMEVAL_TO_TIMESPEC(tv, ts) {                                   \
        (ts)->tv_sec = (tv)->tv_sec;                                    \
        (ts)->tv_nsec = (tv)->tv_usec * 1000;                           \
}

# define __suseconds_t_defined
# define timeradd(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
    if ((result)->tv_usec >= 1000000)					      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_usec -= 1000000;					      \
      }									      \
  } while (0)
# define timerclear(tvp)	((tvp)->tv_sec = (tvp)->tv_usec = 0)
# define timercmp(a, b, CMP) 						      \
  (((a)->tv_sec == (b)->tv_sec) ? 					      \
   ((a)->tv_usec CMP (b)->tv_usec) : 					      \
   ((a)->tv_sec CMP (b)->tv_sec))
# define timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_usec)
# define timersub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)
# define NFDBITS		__NFDBITS
# define __FDS_BITS(set) ((set)->fds_bits)
# define __sigset_t_defined
#define __set_errno(val) (errno = (val))
# define errno _dl_errno
#define M_CHECK_ACTION      -5
# define M_GRAIN   3	
# define M_KEEP    4	
#define M_MMAP_MAX          -4
#define M_MMAP_THRESHOLD    -3
# define M_MXFAST  1	
# define M_NLBLKS  2	
#define M_PERTURB           -6
#define M_TOP_PAD           -2
#define M_TRIM_THRESHOLD    -1
#define _MALLOC_H 1
#  define __MALLOC_P(args)	args
#  define __MALLOC_PMT(args)	args
#  define __THROW
# define __attribute_malloc__
# define __malloc_ptr_t  void *
# define __malloc_ptrdiff_t ptrdiff_t
# define __malloc_size_t size_t
# define ptrdiff_t       int
# define size_t          unsigned int
# define NSIG _NSIG
#define SIGRTMAX   (__libc_current_sigrtmax())
#define SIGRTMIN   (__libc_current_sigrtmin())
#define SIG_DFL    ((__sighandler_t) 0)  
#define SIG_ERR    ((__sighandler_t) -1) 
# define SIG_HOLD  ((__sighandler_t) 2)  
#define SIG_IGN    ((__sighandler_t) 1)  
#  define _KERNEL_NSIG_WORDS (_NSIG / _MIPS_SZLONG)
# define _NSIG 65
# define _SIGNAL_H
#define __SIGRTMAX (_NSIG - 1)
# define __SIGRTMIN 32
#  define __SYSCALL_SIGSET_T_SIZE (sizeof(kernel_sigset_t))
#  define __sig_atomic_t_defined
#  define __sigset_t_defined
#  define _sys_siglist sys_siglist
# define __mempcpy(dest, src, n) __builtin_mempcpy(dest, src, n)
# define strdupa(s)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);					      \
      size_t __len = strlen (__old) + 1;				      \
      char *__new = (char *) __builtin_alloca (__len);			      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
# define strndupa(s, n)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);					      \
      size_t __len = strnlen (__old, (n));				      \
      char *__new = (char *) __builtin_alloca (__len + 1);		      \
      __new[__len] = '\0';						      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
