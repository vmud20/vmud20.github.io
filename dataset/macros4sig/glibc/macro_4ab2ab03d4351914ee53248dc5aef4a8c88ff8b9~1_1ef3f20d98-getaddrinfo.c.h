

































#define AI_DEFAULT    (AI_V4MAPPED | AI_ADDRCONFIG)
#define DECLARE_NSS_PROTOTYPES(service)					      \
extern enum nss_status _nss_ ## service ## _setprotoent (int);		      \
extern enum nss_status _nss_ ## service ## _endprotoent (void);		      \
extern enum nss_status _nss_ ## service ## _getprotoent_r		      \
		       (struct protoent *proto, char *buffer, size_t buflen,  \
			int *errnop);					      \
extern enum nss_status _nss_ ## service ## _getprotobyname_r		      \
		       (const char *name, struct protoent *proto,	      \
			char *buffer, size_t buflen, int *errnop);	      \
extern enum nss_status _nss_ ## service ## _getprotobynumber_r		      \
		       (int number, struct protoent *proto,		      \
			char *buffer, size_t buflen, int *errnop);	      \
extern enum nss_status _nss_ ## service ## _sethostent (int);		      \
extern enum nss_status _nss_ ## service ## _endhostent (void);		      \
extern enum nss_status _nss_ ## service ## _gethostent_r		      \
		       (struct hostent *host, char *buffer, size_t buflen,    \
			int *errnop, int *h_errnop);			      \
extern enum nss_status _nss_ ## service ## _gethostbyname2_r		      \
		       (const char *name, int af, struct hostent *host,	      \
			char *buffer, size_t buflen, int *errnop,	      \
			int *h_errnop);					      \
extern enum nss_status _nss_ ## service ## _gethostbyname_r		      \
		       (const char *name, struct hostent *host, char *buffer, \
			size_t buflen, int *errnop, int *h_errnop);	      \
extern enum nss_status _nss_ ## service ## _gethostbyaddr_r		      \
		       (const void *addr, socklen_t addrlen, int af,	      \
			struct hostent *host, char *buffer, size_t buflen,    \
			int *errnop, int *h_errnop);			      \
extern enum nss_status _nss_ ## service ## _setservent (int);		      \
extern enum nss_status _nss_ ## service ## _endservent (void);		      \
extern enum nss_status _nss_ ## service ## _getservent_r		      \
		       (struct servent *serv, char *buffer, size_t buflen,    \
			int *errnop);					      \
extern enum nss_status _nss_ ## service ## _getservbyname_r		      \
		       (const char *name, const char *protocol,		      \
			struct servent *serv, char *buffer, size_t buflen,    \
			int *errnop);					      \
extern enum nss_status _nss_ ## service ## _getservbyport_r		      \
		       (int port, const char *protocol, struct servent *serv, \
			char *buffer, size_t buflen, int *errnop);	      \
extern enum nss_status _nss_ ## service ## _setnetgrent			      \
		       (const char *group, struct __netgrent *result);	      \
extern enum nss_status _nss_ ## service ## _endnetgrent			      \
		       (struct __netgrent *result);			      \
extern enum nss_status _nss_ ## service ## _getnetgrent_r		      \
		       (struct __netgrent *result, char *buffer,	      \
			size_t buflen, int *errnop);			      \
extern enum nss_status _nss_ ## service ## _setnetent (int stayopen);	      \
extern enum nss_status _nss_ ## service ## _endnetent (void);		      \
extern enum nss_status _nss_ ## service ## _getnetent_r			      \
			(struct netent *net, char *buffer, size_t buflen,     \
			 int *errnop, int *herrnop);			      \
extern enum nss_status _nss_ ## service ## _getnetbyname_r		      \
			(const char *name, struct netent *net, char *buffer,  \
			 size_t buflen, int *errnop, int *herrnop);	      \
extern enum nss_status _nss_ ## service ## _getnetbyaddr_r		      \
		       (uint32_t addr, int type, struct netent *net,	      \
			char *buffer, size_t buflen, int *errnop,	      \
			int *herrnop);
# define __set_h_errno(x) (h_errno = (x))
#   define h_errno __libc_h_errno
#define DEFINE_DATABASE(arg) NSS_DBSIDX_##arg,
#define MAX_NR_ADDRS    48
#define MAX_NR_ALIASES  48
# define nss_interface_function(name)
#define nss_next_action(ni, status) ((ni)->actions[2 + status])
# define DL_CALLER RETURN_ADDRESS (0)
# define DL_CALLER_DECL 
# define __dlfcn_argc __libc_argc
# define __dlfcn_argv __libc_argv
#define __libc_dlopen(name) \
  __libc_dlopen_mode (name, RTLD_LAZY | __RTLD_DLOPEN)
#define ELFW(type)	_ElfW (ELF, __ELF_NATIVE_CLASS, type)
#  define FORCED_DYNAMIC_TLS_OFFSET -1
# define symbind symbind32
#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t
#define __ELF_NATIVE_CLASS __WORDSIZE
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
#define __CPU_MASK_TYPE 	__ULONGWORD_TYPE
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# define __GNUC_PREREQ(maj, min) \

#define __GNU_LIBRARY__ 6
# define __KERNEL_STRICT_NAMES
#  define __USE_FORTIFY_LEVEL 2
# define DT_1_SUPPORTED_MASK \
   (DF_1_NOW | DF_1_NODELETE | DF_1_INITFIRST | DF_1_NOOPEN \
    | DF_1_ORIGIN | DF_1_NODEFLIB)

# define DL_CALL_FCT(fctp, args) \
  (_dl_mcount_wrapper_check ((void *) (fctp)), (*(fctp)) args)
# define __ACTION_FN_T
# define __COMPAR_FN_T
#define RES_SET_H_ERRNO(r,x)			\
  do						\
    {						\
      (r)->res_h_errno = x;			\
      __set_h_errno(x);				\
    }						\
  while (0)
#  define __resp __libc_resp
# define _res (*__resp)
#define RES_PRF_CLASS   0x00000004
#define _PATH_RESCONF        "/etc/resolv.conf"
# define _RESOLV_H_
# define __res_state_defined
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
      __a->s6_addr32[0] == __b->s6_addr32[0]				      \
      && __a->s6_addr32[1] == __b->s6_addr32[1]				      \
      && __a->s6_addr32[2] == __b->s6_addr32[2]				      \
      && __a->s6_addr32[3] == __b->s6_addr32[3]; }))
# define IN6_IS_ADDR_LINKLOCAL(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      (__a->s6_addr32[0] & htonl (0xffc00000)) == htonl (0xfe800000); }))
# define IN6_IS_ADDR_LOOPBACK(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->s6_addr32[0] == 0						      \
      && __a->s6_addr32[1] == 0						      \
      && __a->s6_addr32[2] == 0						      \
      && __a->s6_addr32[3] == htonl (1); }))
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
      (__a->s6_addr32[0] & htonl (0xffc00000)) == htonl (0xfec00000); }))
# define IN6_IS_ADDR_UNSPECIFIED(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->s6_addr32[0] == 0						      \
      && __a->s6_addr32[1] == 0						      \
      && __a->s6_addr32[2] == 0						      \
      && __a->s6_addr32[3] == 0; }))
# define IN6_IS_ADDR_V4COMPAT(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->s6_addr32[0] == 0						      \
      && __a->s6_addr32[1] == 0						      \
      && __a->s6_addr32[2] == 0						      \
      && ntohl (__a->s6_addr32[3]) > 1; }))
# define IN6_IS_ADDR_V4MAPPED(a) \
  (__extension__							      \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);	      \
      __a->s6_addr32[0] == 0						      \
      && __a->s6_addr32[1] == 0						      \
      && __a->s6_addr32[2] == htonl (0xffff); }))
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

# define __socklen_t_defined
#   define preadv preadv64
#   define pwritev pwritev64
#define NSS_INVALID_FIELD_CHARACTERS ":\n"
# define NS_GET16(s, cp) \
  do {									      \
    const uint16_t *t_cp = (const uint16_t *) (cp);			      \
    (s) = ntohs (*t_cp);						      \
    (cp) += NS_INT16SZ;							      \
  } while (0)
# define NS_GET32(l, cp) \
  do {									      \
    const uint32_t *t_cp = (const uint32_t *) (cp);			      \
    (l) = ntohl (*t_cp);						      \
    (cp) += NS_INT32SZ;							      \
  } while (0)
# define NS_PUT16(s, cp) \
  do {									      \
    uint16_t *t_cp = (uint16_t *) (cp);					      \
    *t_cp = htons (s);							      \
    (cp) += NS_INT16SZ;							      \
  } while (0)
# define NS_PUT32(l, cp) \
  do {									      \
    uint32_t *t_cp = (uint32_t *) (cp);					      \
    *t_cp = htonl (l);							      \
    (cp) += NS_INT32SZ;							      \
  } while (0)
#define ns_msg_getflag(handle, flag) \
  (((handle)._flags & _ns_flagdata[flag].mask) >> _ns_flagdata[flag].shift)
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

#define NS_DSA_MAX_BYTES        405
#define NS_DSA_MIN_SIZE         213
#define NS_DSA_SIG_SIZE         41
#define NS_KEY_PROT_DNSSEC      3
#define NS_KEY_PROT_EMAIL       2
#define NS_KEY_PROT_IPSEC       4
#define NS_KEY_PROT_TLS         1
#define NS_KEY_RESERVED_BITMASK2 0xFFFF 
#define NS_NXT_MAX 127
#define NS_OPT_DNSSEC_OK        0x8000U
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
#define ns_t_rr_p(t) (!ns_t_qt_p(t) && !ns_t_mrr_p(t))
#define ns_t_udp_p(t) ((t) != ns_t_axfr && (t) != ns_t_zxfr)
#define ns_t_xfr_p(t) ((t) == ns_t_axfr || (t) == ns_t_ixfr || \
		       (t) == ns_t_zxfr)
#define T_UNSPEC 62321
# define __nonnull(params)
#  define _Noreturn __attribute__ ((__noreturn__))
# define _Static_assert(expr, diagnostic) \
    extern int (*__Static_assert_function (void)) \
      [!!sizeof (struct { int __error_if_negative: (expr) ? 2 : -1; })]
# define __ASMNAME(cname)  __ASMNAME2 ("__USER_LABEL_PREFIX__", cname)
# define __ASMNAME2(prefix, cname) __STRING (prefix) cname
# define __BEGIN_DECLS
# define __BEGIN_NAMESPACE_C99
# define __BEGIN_NAMESPACE_STD
#define __CONCAT(x,y)	x ## y
# define __END_DECLS
# define __END_NAMESPACE_C99
# define __END_NAMESPACE_STD
# define __LDBL_COMPAT 1
#  define __LDBL_REDIR(name, proto) \
  __LDBL_REDIR1 (name, proto, __nldbl_##name)
#  define __LDBL_REDIR1(name, proto, alias) __REDIRECT (name, proto, alias)
#  define __LDBL_REDIR1_DECL(name, alias) \
  extern __typeof (name) name __asm (__ASMNAME (#alias));
#  define __LDBL_REDIR1_NTH(name, proto, alias) __REDIRECT_NTH (name, proto, alias)
#  define __LDBL_REDIR_DECL(name) \
  extern __typeof (name) name __asm (__ASMNAME ("__nldbl_" #name));
#  define __LDBL_REDIR_NTH(name, proto) \
  __LDBL_REDIR1_NTH (name, proto, __nldbl_##name)
#  define __LEAF , __leaf__
#  define __LEAF_ATTR __attribute__ ((__leaf__))
#   define __NTH(fct)	__LEAF_ATTR fct throw ()
#define __P(args)	args
#define __PMT(args)	args
# define __REDIRECT(name, proto, alias) name proto __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_LDBL(name, proto, alias) \
  __LDBL_REDIR1 (name, proto, __nldbl_##alias)
#  define __REDIRECT_NTH(name, proto, alias) \
     name proto __THROW __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_NTHNL(name, proto, alias) \
     name proto __THROWNL __asm__ (__ASMNAME (#alias))
#  define __REDIRECT_NTH_LDBL(name, proto, alias) \
  __LDBL_REDIR1_NTH (name, proto, __nldbl_##alias)
#define __STRING(x)	#x
#   define __THROW
#   define __THROWNL
# define __USING_NAMESPACE_C99(name) using __c99::name;
# define __USING_NAMESPACE_STD(name) using std::name;
# define __always_inline __inline __attribute__ ((__always_inline__))
# define __attribute__(xyz)	
# define __attribute_alloc_size__(params) \
  __attribute__ ((__alloc_size__ params))
# define __attribute_artificial__ __attribute__ ((__artificial__))
# define __attribute_const__ __attribute__ ((__const__))
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
#define __bos(ptr) __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1)
#define __bos0(ptr) __builtin_object_size (ptr, 0)
# define __errordecl(name, msg) \
  extern void name (void) __attribute__((__error__ (msg)))
#  define __extern_always_inline \
  extern __always_inline __attribute__ ((__gnu_inline__))
#  define __extern_inline extern __inline __attribute__ ((__gnu_inline__))
# define __fortify_function __extern_always_inline __attribute_artificial__
# define __glibc_likely(cond)	__builtin_expect ((cond), 1)
# define __glibc_unlikely(cond)	__builtin_expect ((cond), 0)
#define __long_double_t  long double
#define __ptr_t void *
# define __va_arg_pack() __builtin_va_arg_pack ()
# define __va_arg_pack_len() __builtin_va_arg_pack_len ()
# define __warnattr(msg) __attribute__((__warning__ (msg)))
# define __warndecl(name, msg) \
  extern void name (void) __attribute__((__warning__ (msg)))
#  define __wur __attribute_warn_unused_result__
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
# define __need_timespec
#define _NSCD_PROTO_H 1
#  define __gid_t_defined
# define __need_FILE

#  define __uid_t_defined
#define ALIGN 16
#define MAPPING_TIMEOUT (5 * 60)
#define MAXKEYLEN 1024
#define MAX_TIMEOUT_VALUE \
  (sizeof (time_t) == sizeof (long int) ? LONG_MAX : INT_MAX)
#define NO_MAPPING ((struct mapped_database *) -1l)
#define NSCD_VERSION 2
#define _PATH_NSCDSOCKET "/var/run/nscd/socket"
#define libc_locked_map_ptr(class, name) class struct locked_map_ptr name
#define __atomic_bool_bysize(pre, post, mem, ...)			      \
  ({									      \
    int __atg2_result;							      \
    if (sizeof (*mem) == 1)						      \
      __atg2_result = pre##_8_##post (mem, __VA_ARGS__);		      \
    else if (sizeof (*mem) == 2)					      \
      __atg2_result = pre##_16_##post (mem, __VA_ARGS__);		      \
    else if (sizeof (*mem) == 4)					      \
      __atg2_result = pre##_32_##post (mem, __VA_ARGS__);		      \
    else if (sizeof (*mem) == 8)					      \
      __atg2_result = pre##_64_##post (mem, __VA_ARGS__);		      \
    else								      \
      abort ();								      \
    __atg2_result;							      \
  })
#  define __atomic_check_size(mem) \
   if ((sizeof (*mem) != 4) && (sizeof (*mem) != 8))			      \
     __atomic_link_error ();
#define __atomic_val_bysize(pre, post, mem, ...)			      \
  ({									      \
    __typeof (*mem) __atg1_result;					      \
    if (sizeof (*mem) == 1)						      \
      __atg1_result = pre##_8_##post (mem, __VA_ARGS__);		      \
    else if (sizeof (*mem) == 2)					      \
      __atg1_result = pre##_16_##post (mem, __VA_ARGS__);		      \
    else if (sizeof (*mem) == 4)					      \
      __atg1_result = pre##_32_##post (mem, __VA_ARGS__);		      \
    else if (sizeof (*mem) == 8)					      \
      __atg1_result = pre##_64_##post (mem, __VA_ARGS__);		      \
    else								      \
      abort ();								      \
    __atg1_result;							      \
  })
# define atomic_add(mem, value) (void) atomic_exchange_and_add ((mem), (value))
# define atomic_add_negative(mem, value)				      \
  ({ __typeof (value) __atg12_value = (value);				      \
     atomic_exchange_and_add (mem, __atg12_value) < -__atg12_value; })
# define atomic_add_zero(mem, value)					      \
  ({ __typeof (value) __atg13_value = (value);				      \
     atomic_exchange_and_add (mem, __atg13_value) == -__atg13_value; })
# define atomic_and(mem, mask) \
  do {									      \
    __typeof (*(mem)) __atg15_old;					      \
    __typeof (mem) __atg15_memp = (mem);				      \
    __typeof (*(mem)) __atg15_mask = (mask);				      \
									      \
    do									      \
      __atg15_old = (*__atg15_memp);					      \
    while (__builtin_expect						      \
	   (atomic_compare_and_exchange_bool_acq (__atg15_memp,		      \
						  __atg15_old & __atg15_mask, \
						  __atg15_old), 0));	      \
  } while (0)
# define atomic_and_val(mem, mask) \
  ({ __typeof (*(mem)) __atg16_old;					      \
     __typeof (mem) __atg16_memp = (mem);				      \
     __typeof (*(mem)) __atg16_mask = (mask);				      \
									      \
     do									      \
       __atg16_old = (*__atg16_memp);					      \
     while (__builtin_expect						      \
	    (atomic_compare_and_exchange_bool_acq (__atg16_memp,	      \
						   __atg16_old & __atg16_mask,\
						   __atg16_old), 0));	      \
									      \
     __atg16_old; })
# define atomic_bit_set(mem, bit) \
  (void) atomic_bit_test_set(mem, bit)
# define atomic_bit_test_set(mem, bit) \
  ({ __typeof (*(mem)) __atg14_old;					      \
     __typeof (mem) __atg14_memp = (mem);				      \
     __typeof (*(mem)) __atg14_mask = ((__typeof (*(mem))) 1 << (bit));	      \
									      \
     do									      \
       __atg14_old = (*__atg14_memp);					      \
     while (__builtin_expect						      \
	    (atomic_compare_and_exchange_bool_acq (__atg14_memp,	      \
						   __atg14_old | __atg14_mask,\
						   __atg14_old), 0));	      \
									      \
     __atg14_old & __atg14_mask; })
#  define atomic_compare_and_exchange_bool_acq(mem, newval, oldval) \
  __atomic_bool_bysize (__arch_compare_and_exchange_bool,acq,		      \
		        mem, newval, oldval)
# define atomic_compare_and_exchange_bool_rel(mem, newval, oldval) \
  atomic_compare_and_exchange_bool_acq (mem, newval, oldval)
# define atomic_compare_and_exchange_val_acq(mem, newval, oldval) \
  __atomic_val_bysize (__arch_compare_and_exchange_val,acq,		      \
		       mem, newval, oldval)
# define atomic_compare_and_exchange_val_rel(mem, newval, oldval)	      \
  atomic_compare_and_exchange_val_acq (mem, newval, oldval)
#  define atomic_compare_exchange_weak_acquire(mem, expected, desired) \
   ({ typeof (*(expected)) __atg102_expected = *(expected);		      \
   *(expected) =							      \
     atomic_compare_and_exchange_val_acq ((mem), (desired), *(expected));     \
   *(expected) == __atg102_expected; })
#  define atomic_compare_exchange_weak_relaxed(mem, expected, desired) \
   atomic_compare_exchange_weak_acquire ((mem), (expected), (desired))
#  define atomic_compare_exchange_weak_release(mem, expected, desired) \
   ({ typeof (*(expected)) __atg103_expected = *(expected);		      \
   *(expected) =							      \
     atomic_compare_and_exchange_val_rel ((mem), (desired), *(expected));     \
   *(expected) == __atg103_expected; })
# define atomic_decrement(mem) atomic_add ((mem), -1)
# define atomic_decrement_and_test(mem) \
  (atomic_exchange_and_add ((mem), -1) == 1)
# define atomic_decrement_if_positive(mem) \
  ({ __typeof (*(mem)) __atg11_oldval;					      \
     __typeof (mem) __atg11_memp = (mem);				      \
									      \
     do									      \
       {								      \
	 __atg11_oldval = *__atg11_memp;				      \
	 if (__glibc_unlikely (__atg11_oldval <= 0))			      \
	   break;							      \
       }								      \
     while (__builtin_expect						      \
	    (atomic_compare_and_exchange_bool_acq (__atg11_memp,	      \
						   __atg11_oldval - 1,	      \
						   __atg11_oldval), 0));      \
     __atg11_oldval; })
# define atomic_decrement_val(mem) (atomic_exchange_and_add ((mem), -1) - 1)
# define atomic_exchange_acq(mem, newvalue) \
  ({ __typeof (*(mem)) __atg5_oldval;					      \
     __typeof (mem) __atg5_memp = (mem);				      \
     __typeof (*(mem)) __atg5_value = (newvalue);			      \
									      \
     do									      \
       __atg5_oldval = *__atg5_memp;					      \
     while (__builtin_expect						      \
	    (atomic_compare_and_exchange_bool_acq (__atg5_memp, __atg5_value, \
						   __atg5_oldval), 0));	      \
									      \
     __atg5_oldval; })
#  define atomic_exchange_acquire(mem, val) \
   atomic_exchange_acq ((mem), (val))
# define atomic_exchange_and_add(mem, value) \
  atomic_exchange_and_add_acq(mem, value)
#  define atomic_exchange_and_add_acq(mem, value) \
  atomic_exchange_and_add (mem, value)
# define atomic_exchange_and_add_rel(mem, value) \
  atomic_exchange_and_add_acq(mem, value)
# define atomic_exchange_rel(mem, newvalue) atomic_exchange_acq (mem, newvalue)
#  define atomic_exchange_release(mem, val) \
   atomic_exchange_rel ((mem), (val))
#  define atomic_fetch_add_acq_rel(mem, operand) \
   ({ atomic_thread_fence_release ();					      \
   atomic_exchange_and_add_acq ((mem), (operand)); })
#  define atomic_fetch_add_acquire(mem, operand) \
   atomic_exchange_and_add_acq ((mem), (operand))
#  define atomic_fetch_add_relaxed(mem, operand) \
   atomic_fetch_add_acquire ((mem), (operand))
#  define atomic_fetch_add_release(mem, operand) \
   atomic_exchange_and_add_rel ((mem), (operand))
#  define atomic_fetch_and_acquire(mem, operand) \
   atomic_and_val ((mem), (operand))
#  define atomic_fetch_or_acquire(mem, operand) \
   atomic_or_val ((mem), (operand))
#  define atomic_fetch_or_relaxed(mem, operand) \
   atomic_fetch_or_acquire ((mem), (operand))
# define atomic_forced_read(x) \
  ({ __typeof (x) __x; __asm ("" : "=r" (__x) : "0" (x)); __x; })
# define atomic_full_barrier() __asm ("" ::: "memory")
# define atomic_increment(mem) atomic_add ((mem), 1)
# define atomic_increment_and_test(mem) \
  (atomic_exchange_and_add ((mem), 1) + 1 == 0)
# define atomic_increment_val(mem) (atomic_exchange_and_add ((mem), 1) + 1)
#  define atomic_load_acquire(mem) \
   ({ __typeof (*(mem)) __atg101_val = atomic_load_relaxed (mem);	      \
   atomic_thread_fence_acquire ();					      \
   __atg101_val; })
#  define atomic_load_relaxed(mem) \
   ({ __typeof (*(mem)) __atg100_val;					      \
   __asm ("" : "=r" (__atg100_val) : "0" (*(mem)));			      \
   __atg100_val; })
# define atomic_max(mem, value) \
  do {									      \
    __typeof (*(mem)) __atg8_oldval;					      \
    __typeof (mem) __atg8_memp = (mem);					      \
    __typeof (*(mem)) __atg8_value = (value);				      \
    do {								      \
      __atg8_oldval = *__atg8_memp;					      \
      if (__atg8_oldval >= __atg8_value)				      \
	break;								      \
    } while (__builtin_expect						      \
	     (atomic_compare_and_exchange_bool_acq (__atg8_memp, __atg8_value,\
						    __atg8_oldval), 0));      \
  } while (0)
# define atomic_min(mem, value) \
  do {									      \
    __typeof (*(mem)) __atg10_oldval;					      \
    __typeof (mem) __atg10_memp = (mem);				      \
    __typeof (*(mem)) __atg10_value = (value);				      \
    do {								      \
      __atg10_oldval = *__atg10_memp;					      \
      if (__atg10_oldval <= __atg10_value)				      \
	break;								      \
    } while (__builtin_expect						      \
	     (atomic_compare_and_exchange_bool_acq (__atg10_memp,	      \
						    __atg10_value,	      \
						    __atg10_oldval), 0));     \
  } while (0)
# define atomic_or(mem, mask) \
  do {									      \
    __typeof (*(mem)) __atg17_old;					      \
    __typeof (mem) __atg17_memp = (mem);				      \
    __typeof (*(mem)) __atg17_mask = (mask);				      \
									      \
    do									      \
      __atg17_old = (*__atg17_memp);					      \
    while (__builtin_expect						      \
	   (atomic_compare_and_exchange_bool_acq (__atg17_memp,		      \
						  __atg17_old | __atg17_mask, \
						  __atg17_old), 0));	      \
  } while (0)
# define atomic_or_val(mem, mask) \
  ({ __typeof (*(mem)) __atg19_old;					      \
     __typeof (mem) __atg19_memp = (mem);				      \
     __typeof (*(mem)) __atg19_mask = (mask);				      \
									      \
     do									      \
       __atg19_old = (*__atg19_memp);					      \
     while (__builtin_expect						      \
	    (atomic_compare_and_exchange_bool_acq (__atg19_memp,	      \
						   __atg19_old | __atg19_mask,\
						   __atg19_old), 0));	      \
									      \
     __atg19_old; })
# define atomic_read_barrier() atomic_full_barrier ()
#  define atomic_store_relaxed(mem, val) do { *(mem) = (val); } while (0)
#  define atomic_store_release(mem, val) \
   do {									      \
     atomic_thread_fence_release ();					      \
     atomic_store_relaxed ((mem), (val));				      \
   } while (0)
#  define atomic_thread_fence_acquire() atomic_read_barrier ()
#  define atomic_thread_fence_release() atomic_write_barrier ()
#  define atomic_thread_fence_seq_cst() atomic_full_barrier ()
# define atomic_write_barrier() atomic_full_barrier ()
# define catomic_add(mem, value) \
  (void) catomic_exchange_and_add ((mem), (value))
# define catomic_and(mem, mask) \
  do {									      \
    __typeof (*(mem)) __atg20_old;					      \
    __typeof (mem) __atg20_memp = (mem);				      \
    __typeof (*(mem)) __atg20_mask = (mask);				      \
									      \
    do									      \
      __atg20_old = (*__atg20_memp);					      \
    while (__builtin_expect						      \
	   (catomic_compare_and_exchange_bool_acq (__atg20_memp,	      \
						   __atg20_old & __atg20_mask,\
						   __atg20_old), 0));	      \
  } while (0)
#  define catomic_compare_and_exchange_bool_acq(mem, newval, oldval) \
  __atomic_bool_bysize (__arch_c_compare_and_exchange_bool,acq,		      \
		        mem, newval, oldval)
#  define catomic_compare_and_exchange_bool_rel(mem, newval, oldval)	      \
  catomic_compare_and_exchange_bool_acq (mem, newval, oldval)
#  define catomic_compare_and_exchange_val_acq(mem, newval, oldval) \
  atomic_compare_and_exchange_val_acq (mem, newval, oldval)
#  define catomic_compare_and_exchange_val_rel(mem, newval, oldval)	      \
  catomic_compare_and_exchange_val_acq (mem, newval, oldval)
# define catomic_decrement(mem) catomic_add ((mem), -1)
# define catomic_decrement_val(mem) (catomic_exchange_and_add ((mem), -1) - 1)
# define catomic_exchange_and_add(mem, value) \
  ({ __typeof (*(mem)) __atg7_oldv;					      \
     __typeof (mem) __atg7_memp = (mem);				      \
     __typeof (*(mem)) __atg7_value = (value);				      \
									      \
     do									      \
       __atg7_oldv = *__atg7_memp;					      \
     while (__builtin_expect						      \
	    (catomic_compare_and_exchange_bool_acq (__atg7_memp,	      \
						    __atg7_oldv		      \
						    + __atg7_value,	      \
						    __atg7_oldv), 0));	      \
									      \
     __atg7_oldv; })
# define catomic_increment(mem) catomic_add ((mem), 1)
# define catomic_increment_val(mem) (catomic_exchange_and_add ((mem), 1) + 1)
# define catomic_max(mem, value) \
  do {									      \
    __typeof (*(mem)) __atg9_oldv;					      \
    __typeof (mem) __atg9_memp = (mem);					      \
    __typeof (*(mem)) __atg9_value = (value);				      \
    do {								      \
      __atg9_oldv = *__atg9_memp;					      \
      if (__atg9_oldv >= __atg9_value)					      \
	break;								      \
    } while (__builtin_expect						      \
	     (catomic_compare_and_exchange_bool_acq (__atg9_memp,	      \
						     __atg9_value,	      \
						     __atg9_oldv), 0));	      \
  } while (0)
# define catomic_or(mem, mask) \
  do {									      \
    __typeof (*(mem)) __atg18_old;					      \
    __typeof (mem) __atg18_memp = (mem);				      \
    __typeof (*(mem)) __atg18_mask = (mask);				      \
									      \
    do									      \
      __atg18_old = (*__atg18_memp);					      \
    while (__builtin_expect						      \
	   (catomic_compare_and_exchange_bool_acq (__atg18_memp,	      \
						   __atg18_old | __atg18_mask,\
						   __atg18_old), 0));	      \
  } while (0)
#  define MB_CUR_MAX (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_MB_CUR_MAX))

# define WEXITSTATUS(status)	__WEXITSTATUS (status)
#  define WIFCONTINUED(status)	__WIFCONTINUED (status)
# define WIFEXITED(status)	__WIFEXITED (status)
# define WIFSIGNALED(status)	__WIFSIGNALED (status)
# define WIFSTOPPED(status)	__WIFSTOPPED (status)
# define WSTOPSIG(status)	__WSTOPSIG (status)
# define WTERMSIG(status)	__WTERMSIG (status)
# define __COMPAR_FN_T
# define __malloc_and_calloc_defined
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
# define SYS_NMLN  _UTSNAME_LENGTH
# define _UTSNAME_MACHINE_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_NODENAME_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_RELEASE_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_SYSNAME_LENGTH _UTSNAME_LENGTH
# define _UTSNAME_VERSION_LENGTH _UTSNAME_LENGTH
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)	      \
		      + strlen ((ptr)->sun_path))
#define __fstat(fd, buf) __fxstat (_STAT_VER, fd, buf)
#define __fstat64(fd, buf) __fxstat64 (_STAT_VER, fd, buf)
#define __fstatat(dfd, fname, buf, flag) \
  __fxstatat (_STAT_VER, dfd, fname, buf, flag)
#define __fstatat64(dfd, fname, buf, flag) \
  __fxstatat64 (_STAT_VER, dfd, fname, buf, flag)
#define __lstat(fname, buf)  __lxstat (_STAT_VER, fname, buf)
#define __lstat64(fname, buf)  __lxstat64 (_STAT_VER, fname, buf)
#define fstat(fd, buf) __fxstat (_STAT_VER, fd, buf)
#define fstat64(fd, buf) __fxstat64 (_STAT_VER, fd, buf)
#define lstat(fname, buf)  __lxstat (_STAT_VER, fname, buf)
#define lstat64(fname, buf)  __lxstat64 (_STAT_VER, fname, buf)
#define stat(fname, buf) __xstat (_STAT_VER, fname, buf)
#define stat64(fname, buf) __xstat64 (_STAT_VER, fname, buf)
# define ACCESSPERMS (S_IRWXU|S_IRWXG|S_IRWXO) 
# define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)
# define DEFFILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
# define S_ISFIFO(mode)	 __S_ISTYPE((mode), __S_IFIFO)
# define S_ISLNK(mode)	 __S_ISTYPE((mode), __S_IFLNK)
# define S_ISSOCK(mode) __S_ISTYPE((mode), __S_IFSOCK)
# define S_TYPEISMQ(buf) __S_TYPEISMQ(buf)
# define S_TYPEISSEM(buf) __S_TYPEISSEM(buf)
# define S_TYPEISSHM(buf) __S_TYPEISSHM(buf)
#  define __blkcnt_t_defined
#  define __blksize_t_defined
#  define __dev_t_defined
#  define __fxstat __fxstat64
#  define __gid_t_defined
#  define __ino_t_defined
#  define __lxstat __lxstat64
#  define __mode_t_defined
#  define __need_time_t
#  define __need_timespec
#  define __nlink_t_defined
#  define __off_t_defined
#  define __uid_t_defined
#  define __xstat __xstat64
#   define fstatat fstatat64
#define __S_TYPEISMQ(buf) 0
#define __S_TYPEISSEM(buf) 0
#define __S_TYPEISSHM(buf) 0
# define __socklen_t_defined
#define __fsetlocking(fp, type) \
  ({ int __result = ((fp->_flags & _IO_USER_LOCK)			\
		     ? FSETLOCKING_BYCALLER : FSETLOCKING_INTERNAL);	\
									\
     if (type != FSETLOCKING_QUERY)					\
       {								\
	 fp->_flags &= ~_IO_USER_LOCK;					\
	 if (type == FSETLOCKING_BYCALLER)				\
	   fp->_flags |= _IO_USER_LOCK;					\
       }								\
									\
     __result;								\
  })
#  define __need_size_t
#  define __need_wint_t
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
# define __set_errno(val) (errno = (val))
#   define errno __libc_errno
#   define CTYPE_EXTERN_INLINE extern inline
#   define __isdigit_l(c, l) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#   define isdigit(c) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#   define isdigit_l(c, l) ({ int __c = (c); __c >= '0' && __c <= '9'; })
#  define _ISbit(bit)	(1 << (bit))
# define __exctype_l(name) 						      \
  extern int name (int, __locale_t) __THROW
#  define __isalnum_l(c,l)	__isctype_l((c), _ISalnum, (l))
#  define __isalpha_l(c,l)	__isctype_l((c), _ISalpha, (l))
#   define __isascii_l(c,l)	((l), __isascii (c))
#  define __isblank_l(c,l)	__isctype_l((c), _ISblank, (l))
#  define __iscntrl_l(c,l)	__isctype_l((c), _IScntrl, (l))
# define __isctype(c, type) \
  ((*__ctype_b_loc ())[(int) (c)] & (unsigned short int) type)
# define __isctype_f(type) \
  __extern_inline int							      \
  is##type (int __c) __THROW						      \
  {									      \
    return (*__ctype_b_loc ())[(int) (__c)] & (unsigned short int) _IS##type; \
  }
#  define __isctype_l(c, type, locale) \
  ((locale)->__ctype_b[(int) (c)] & (unsigned short int) type)
#  define __isgraph_l(c,l)	__isctype_l((c), _ISgraph, (l))
#  define __islower_l(c,l)	__isctype_l((c), _ISlower, (l))
#  define __isprint_l(c,l)	__isctype_l((c), _ISprint, (l))
#  define __ispunct_l(c,l)	__isctype_l((c), _ISpunct, (l))
#  define __isspace_l(c,l)	__isctype_l((c), _ISspace, (l))
#  define __isupper_l(c,l)	__isctype_l((c), _ISupper, (l))
#  define __isxdigit_l(c,l)	__isctype_l((c), _ISxdigit, (l))
#   define __toascii_l(c,l)	((l), __toascii (c))
#define __tobody(c, f, a, args) \
  (__extension__							      \
   ({ int __res;							      \
      if (sizeof (c) > 1)						      \
	{								      \
	  if (__builtin_constant_p (c))					      \
	    {								      \
	      int __c = (c);						      \
	      __res = __c < -128 || __c > 255 ? __c : (a)[__c];		      \
	    }								      \
	  else								      \
	    __res = f args;						      \
	}								      \
      else								      \
	__res = (a)[(int) (c)];						      \
      __res; }))
#  define __tolower_l(c, locale) \
  __tobody (c, __tolower_l, (locale)->__ctype_tolower, (c, locale))
#  define __toupper_l(c, locale) \
  __tobody (c, __toupper_l, (locale)->__ctype_toupper, (c, locale))
#  define _tolower(c)	((int) (*__ctype_tolower_loc ())[(int) (c)])
#  define _toupper(c)	((int) (*__ctype_toupper_loc ())[(int) (c)])
#  define isalnum_l(c,l)	__isalnum_l ((c), (l))
#  define isalpha_l(c,l)	__isalpha_l ((c), (l))
#  define isascii(c)	__isascii (c)
#   define isascii_l(c,l)	__isascii_l ((c), (l))
#  define isblank_l(c,l)	__isblank_l ((c), (l))
#  define iscntrl_l(c,l)	__iscntrl_l ((c), (l))
#  define isgraph_l(c,l)	__isgraph_l ((c), (l))
#  define islower_l(c,l)	__islower_l ((c), (l))
#  define isprint_l(c,l)	__isprint_l ((c), (l))
#  define ispunct_l(c,l)	__ispunct_l ((c), (l))
#  define isspace_l(c,l)	__isspace_l ((c), (l))
#  define isupper_l(c,l)	__isupper_l ((c), (l))
#  define isxdigit_l(c,l)	__isxdigit_l ((c), (l))
#  define toascii(c)	__toascii (c)
#   define toascii_l(c,l)	__toascii_l ((c), (l))
#  define tolower(c)	__tobody (c, tolower, *__ctype_tolower_loc (), (c))
#  define tolower_l(c, locale)	__tolower_l ((c), (locale))
#  define toupper(c)	__tobody (c, toupper, *__ctype_toupper_loc (), (c))
#  define toupper_l(c, locale)	__toupper_l ((c), (locale))
# define __ASSERT_VOID_CAST static_cast<void>
# define assert(expr)		(__ASSERT_VOID_CAST (0))
#  define assert_perror(errnum)	(__ASSERT_VOID_CAST (0))
# define static_assert _Static_assert
