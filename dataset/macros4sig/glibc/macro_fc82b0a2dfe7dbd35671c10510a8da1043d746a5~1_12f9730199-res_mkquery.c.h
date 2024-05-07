
















# define explicit_bzero(buf, len) \
  __explicit_bzero_chk_internal (buf, len, __bos0 (buf))
#   define index(s, c)	(strchr ((s), (c)))
#   define rindex(s, c)	(strrchr ((s), (c)))
# define strndupa(s, n)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = __strnlen (__old, (n));				      \
      char *__new = (char *) __builtin_alloca (__len + 1);		      \
      __new[__len] = '\0';						      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
# define __CORRECT_ISO_CPP_STRING_H_PROTO

#define __mempcpy(dest, src, n) __mempcpy_inline (dest, src, n)
#define mempcpy(dest, src, n) __mempcpy_inline (dest, src, n)
# define strdupa(s)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = strlen (__old) + 1;				      \
      char *__new = (char *) __builtin_alloca (__len);			      \
      (char *) memcpy (__new, __old, __len);				      \
    }))
# define __GLIBC_USE_IEC_60559_BFP_EXT 1
# define __GLIBC_USE_IEC_60559_FUNCS_EXT 1
# define __GLIBC_USE_LIB_EXT2 1
# define _POSIX_C_SOURCE 199506L
# define _POSIX_SOURCE   1
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
#define __GLIBC_USE(F)	__GLIBC_USE_ ## F
# define __GNUC_PREREQ(maj, min) \

#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
#  define __USE_FORTIFY_LEVEL 2
# define __glibc_clang_prereq(maj, min) \
  ((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
# define __SYSMACROS_DEPRECATED_INCLUSION
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
#define __CPU_MASK_TYPE 	__ULONGWORD_TYPE




#  define __need_size_t
#  define __need_wint_t
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
#define RES_AAONLY \
  __glibc_macro_warning ("RES_AAONLY is deprecated") 0x00000004
#define RES_PRF_CLASS   0x00000004
#define RES_PRIMARY \
  __glibc_macro_warning ("RES_PRIMARY is deprecated") 0x00000010
#define _PATH_RESCONF        "/etc/resolv.conf"
# define _RESOLV_H_
# define __res_state_defined
#define _res (*__res_state())
#define GROUP_FILTER_SIZE(numsrc) (sizeof (struct group_filter) \
				   - sizeof (struct sockaddr_storage)	      \
				   + ((numsrc)				      \
				      * sizeof (struct sockaddr_storage)))
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
# define IN6_ARE_ADDR_EQUAL(a,b) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      const struct in6_addr *__b = (const struct in6_addr *) (b);	      \
      __a->__in6_u.__u6_addr32[0] == __b->__in6_u.__u6_addr32[0]	      \
      && __a->__in6_u.__u6_addr32[1] == __b->__in6_u.__u6_addr32[1]	      \
      && __a->__in6_u.__u6_addr32[2] == __b->__in6_u.__u6_addr32[2]	      \
      && __a->__in6_u.__u6_addr32[3] == __b->__in6_u.__u6_addr32[3]; }))
# define IN6_IS_ADDR_LINKLOCAL(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      (__a->__in6_u.__u6_addr32[0] & htonl (0xffc00000)) == htonl (0xfe800000); }))
# define IN6_IS_ADDR_LOOPBACK(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->__in6_u.__u6_addr32[0] == 0					      \
      && __a->__in6_u.__u6_addr32[1] == 0				      \
      && __a->__in6_u.__u6_addr32[2] == 0				      \
      && __a->__in6_u.__u6_addr32[3] == htonl (1); }))
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
# define IN6_IS_ADDR_SITELOCAL(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      (__a->__in6_u.__u6_addr32[0] & htonl (0xffc00000)) == htonl (0xfec00000); }))
# define IN6_IS_ADDR_UNSPECIFIED(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->__in6_u.__u6_addr32[0] == 0					      \
      && __a->__in6_u.__u6_addr32[1] == 0				      \
      && __a->__in6_u.__u6_addr32[2] == 0				      \
      && __a->__in6_u.__u6_addr32[3] == 0; }))
# define IN6_IS_ADDR_V4COMPAT(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->__in6_u.__u6_addr32[0] == 0					      \
      && __a->__in6_u.__u6_addr32[1] == 0				      \
      && __a->__in6_u.__u6_addr32[2] == 0				      \
      && ntohl (__a->__in6_u.__u6_addr32[3]) > 1; }))
# define IN6_IS_ADDR_V4MAPPED(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->__in6_u.__u6_addr32[0] == 0					      \
      && __a->__in6_u.__u6_addr32[1] == 0				      \
      && __a->__in6_u.__u6_addr32[2] == htonl (0xffff); }))
#define INADDR_ALLRTRS_GROUP    ((in_addr_t) 0xe0000002) 
#define INADDR_MAX_LOCAL_GROUP  ((in_addr_t) 0xe00000ff) 
#define INET6_ADDRSTRLEN 46
#define INET_ADDRSTRLEN 16
#define IP_MSFILTER_SIZE(numsrc) (sizeof (struct ip_msfilter) \
				  - sizeof (struct in_addr)		      \
				  + (numsrc) * sizeof (struct in_addr))
#   define htonl(x)	__bswap_32 (x)
#   define htons(x)	__bswap_16 (x)
#   define ntohl(x)	__bswap_32 (x)
#   define ntohs(x)	__bswap_16 (x)
#define _BITS_BYTESWAP_H 1
#  define __bswap_32(x) \
  (__extension__							      \
   ({ unsigned int __bsx = (x); __bswap_constant_32 (__bsx); }))
#  define __bswap_64(x) \
     (__extension__							      \
      ({ union { __extension__ __uint64_t __ll;				      \
		 unsigned int __l[2]; } __w, __r;			      \
	 if (__builtin_constant_p (x))					      \
	   __r.__ll = __bswap_constant_64 (x);				      \
	 else								      \
	   {								      \
	     __w.__ll = (x);						      \
	     __r.__l[0] = __bswap_32 (__w.__l[1]);			      \
	     __r.__l[1] = __bswap_32 (__w.__l[0]);			      \
	   }								      \
	 __r.__ll; }))
#define __bswap_constant_16(x) \
	((unsigned short int)((((x) >> 8) & 0xffu) | (((x) & 0xffu) << 8)))
#define __bswap_constant_32(x) \
     ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) |	      \
      (((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))
# define __bswap_constant_64(x) \
     (__extension__ ((((x) & 0xff00000000000000ull) >> 56)		      \
		     | (((x) & 0x00ff000000000000ull) >> 40)		      \
		     | (((x) & 0x0000ff0000000000ull) >> 24)		      \
		     | (((x) & 0x000000ff00000000ull) >> 8)		      \
		     | (((x) & 0x00000000ff000000ull) << 8)		      \
		     | (((x) & 0x0000000000ff0000ull) << 24)		      \
		     | (((x) & 0x000000000000ff00ull) << 40)		      \
		     | (((x) & 0x00000000000000ffull) << 56)))
# define __bswap_16(x) \
    (__extension__							      \
     ({ unsigned short int __bsx = (unsigned short int) (x);		      \
       __bswap_constant_16 (__bsx); }))
#  define BIG_ENDI 1
#   define HIGH_HALF 1
#   define LITTLE_ENDI 1
#   define  LOW_HALF 0
# define __FLOAT_WORD_ORDER __BYTE_ORDER
# define __LONG_LONG_PAIR(HI, LO) LO, HI
#  define be16toh(x) __bswap_16 (x)
#  define be32toh(x) __bswap_32 (x)
#  define be64toh(x) __bswap_64 (x)
#  define htobe16(x) __bswap_16 (x)
#  define htobe32(x) __bswap_32 (x)
#  define htobe64(x) __bswap_64 (x)
#  define htole16(x) (x)
#  define htole32(x) (x)
#  define htole64(x) (x)
#  define le16toh(x) (x)
#  define le32toh(x) (x)
#  define le64toh(x) (x)
#define IPV6_JOIN_ANYCAST      27
#define IPV6_LEAVE_ANYCAST     28
#define IPV6_MTU               24
#define IPV6_MTU_DISCOVER      23
#define IPV6_RECVERR           25
#define IPV6_ROUTER_ALERT      22
#define IPV6_V6ONLY            26
#define IP_ADD_MEMBERSHIP 12	
#define IP_DROP_MEMBERSHIP 13	
#define IP_MULTICAST_IF 9	
#define IP_MULTICAST_LOOP 11	
#define IP_MULTICAST_TTL 10	
#define __USE_KERNEL_IPV6_DEFS 0
# define SA_LEN(_x)      (_x)->sa_len
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
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
			   & (size_t) ~(sizeof (size_t) - 1))
# define CMSG_DATA(cmsg) ((cmsg)->__cmsg_data)
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr)		      \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) NULL)
#define CMSG_LEN(len)   (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr (mhdr, cmsg)
#define CMSG_SPACE(len) (CMSG_ALIGN (len) \
			 + CMSG_ALIGN (sizeof (struct cmsghdr)))
#define MSG_CTRUNC MSG_CTRUNC
#define MSG_DONTROUTE MSG_DONTROUTE
#define MSG_DONTWAIT MSG_DONTWAIT
#define MSG_EOR MSG_EOR
#define MSG_NOSIGNAL MSG_NOSIGNAL
#define MSG_OOB MSG_OOB
#define MSG_PEEK MSG_PEEK
#define MSG_TRUNC MSG_TRUNC
#define MSG_WAITALL MSG_WAITALL
#define SCM_CREDS SCM_CREDS
#define SCM_RIGHTS SCM_RIGHTS
#define SCM_TIMESTAMP SCM_TIMESTAMP
#define SOCK_CLOEXEC SOCK_CLOEXEC
#define SOCK_DGRAM SOCK_DGRAM
#define SOCK_MAX (SOCK_SEQPACKET + 1)
#define SOCK_NONBLOCK SOCK_NONBLOCK
#define SOCK_RAW SOCK_RAW
#define SOCK_RDM SOCK_RDM
#define SOCK_SEQPACKET SOCK_SEQPACKET
#define SOCK_STREAM SOCK_STREAM
#define SOCK_TYPE_MASK 0xf
#define SO_ACCEPTCONN SO_ACCEPTCONN
#define SO_BROADCAST SO_BROADCAST
#define SO_DEBUG SO_DEBUG
#define SO_DONTROUTE SO_DONTROUTE
#define SO_ERROR SO_ERROR
#define SO_KEEPALIVE SO_KEEPALIVE
#define SO_LINGER SO_LINGER
#define SO_OOBINLINE SO_OOBINLINE
#define SO_RCVBUF SO_RCVBUF
#define SO_RCVLOWAT SO_RCVLOWAT
#define SO_RCVTIMEO SO_RCVTIMEO
#define SO_REUSEADDR SO_REUSEADDR
#define SO_REUSEPORT SO_REUSEPORT
#define SO_SNDBUF SO_SNDBUF
#define SO_SNDLOWAT SO_SNDLOWAT
#define SO_SNDTIMEO SO_SNDTIMEO
#define SO_STYLE SO_STYLE
#define SO_TYPE SO_TYPE
#define SO_USELOOPBACK SO_USELOOPBACK
#  define _EXTERN_INLINE __extern_inline
#define _SS_PADSIZE \
  (_SS_SIZE - __SOCKADDR_COMMON_SIZE - sizeof (__ss_aligntype))

# define __socklen_t_defined
#define _SS_SIZE 128
#  define CHAR_WIDTH 8
#  define INT_WIDTH 32
#  define LLONG_WIDTH 64
#  define LONG_WIDTH __WORDSIZE
#  define SCHAR_WIDTH 8
#  define SHRT_WIDTH 16
#  define UCHAR_WIDTH 8
#  define UINT_WIDTH 32
#  define ULLONG_WIDTH 64
#  define ULONG_WIDTH __WORDSIZE
#  define USHRT_WIDTH 16
#   define preadv preadv64
#   define pwritev pwritev64
#  define AI_IDN_ALLOW_UNASSIGNED 0x0100 
#  define AI_IDN_USE_STD3_ASCII_RULES 0x0200 
#  define EAI_ADDRFAMILY  -9	
#  define EAI_IDN_ENCODE  -105	
#  define EAI_INPROGRESS  -100	
#  define EAI_NOTCANCELED -102	
#  define NI_IDN_ALLOW_UNASSIGNED 64 
#  define NI_IDN_USE_STD3_ASCII_RULES 128 
#  define NI_MAXHOST      1025
#  define NI_MAXSERV      32
# define NI_NUMERICSERV 2	
# define __need_sigevent_t
# define h_errno (*__h_errno_location ())
#define NS_GET16(s, cp) do { \
	const unsigned char *t_cp = (const unsigned char *)(cp); \
	(s) = ((uint16_t)t_cp[0] << 8) \
	    | ((uint16_t)t_cp[1]) \
	    ; \
	(cp) += NS_INT16SZ; \
} while (0)
#define NS_GET32(l, cp) do { \
	const unsigned char *t_cp = (const unsigned char *)(cp); \
	(l) = ((uint32_t)t_cp[0] << 24) \
	    | ((uint32_t)t_cp[1] << 16) \
	    | ((uint32_t)t_cp[2] << 8) \
	    | ((uint32_t)t_cp[3]) \
	    ; \
	(cp) += NS_INT32SZ; \
} while (0)
#define NS_OPT_DNSSEC_OK        0x8000U
#define NS_PUT16(s, cp) do { \
	uint16_t t_s = (uint16_t)(s); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
} while (0)
#define NS_PUT32(l, cp) do { \
	uint32_t t_l = (uint32_t)(l); \
	unsigned char *t_cp = (unsigned char *)(cp); \
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

#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_rr_class(rr)	((ns_class)((rr).rr_class + 0))
#define ns_rr_name(rr)	(((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_rdata(rr)	((rr).rdata + 0)
#define ns_rr_rdlen(rr)	((rr).rdlength + 0)
#define ns_rr_ttl(rr)	((rr).ttl + 0)
#define ns_rr_type(rr)	((ns_type)((rr).type + 0))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
#define _SYS_PARAM_H    1

#define clrbit(a,i)     ((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
# define howmany(x, y)  (((x) + ((y) - 1)) / (y))
#define isclr(a,i)      (((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)
#define isset(a,i)      ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define powerof2(x)     ((((x) - 1) & (x)) == 0)
# define roundup(x, y)  (__builtin_constant_p (y) && powerof2 (y)             \
                         ? (((x) + (y) - 1) & ~((y) - 1))                     \
                         : ((((x) + ((y) - 1)) / (y)) * (y)))
#define setbit(a,i)     ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define __sigemptyset(ss) \
  ({ __builtin_memset (ss, '\0', sizeof (sigset_t)); 0; })
