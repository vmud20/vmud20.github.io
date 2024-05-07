


























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
#define __CPU_MASK_TYPE 	__ULONGWORD_TYPE




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

# define __GLIBC_USE_IEC_60559_BFP_EXT 1
# define __GLIBC_USE_IEC_60559_FUNCS_EXT 1
# define __GLIBC_USE_LIB_EXT2 1
#   define preadv preadv64
#   define pwritev pwritev64
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
#define T_QUERY_A_AND_AAAA 439963904
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
#define DEPRECATED_RES_USE_INET6 0x00002000
#define _RESOLV_INTERNAL_H 1
#  define RES_SET_H_ERRNO(r,x)			\
  do						\
    {						\
      (r)->res_h_errno = x;			\
      __set_h_errno(x);				\
    }						\
  while (0)
#  define __resp __libc_resp
# define _res (*__resp)
#define RES_AAONLY \
  __glibc_macro_warning ("RES_AAONLY is deprecated") 0x00000004
#define RES_PRF_CLASS   0x00000004
#define RES_PRIMARY \
  __glibc_macro_warning ("RES_PRIMARY is deprecated") 0x00000010
#define _PATH_RESCONF        "/etc/resolv.conf"
# define _RESOLV_H_
# define __res_state_defined
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
# define DT_1_SUPPORTED_MASK \
   (DF_1_NOW | DF_1_NODELETE | DF_1_INITFIRST | DF_1_NOOPEN \
    | DF_1_ORIGIN | DF_1_NODEFLIB)
#define AT_BASE_PLATFORM 24		
#define DT_ADDRNUM 11
#define DT_ADDRTAGIDX(tag)	(DT_ADDRRNGHI - (tag))	
#define DT_AUXILIARY    0x7ffffffd      
#define DT_EXTRATAGIDX(tag)	((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
#define DT_FILTER       0x7fffffff      
#define DT_GNU_CONFLICTSZ 0x6ffffdf6	
#define DT_GNU_LIBLISTSZ 0x6ffffdf7	
#define DT_GNU_PRELINKED 0x6ffffdf5	
#define DT_MIPS_AUX_DYNAMIC  0x70000031 
#define DT_MIPS_BASE_ADDRESS 0x70000006	
#define DT_MIPS_COMPACT_SIZE 0x7000002f 
#define DT_MIPS_CONFLICT     0x70000008	
#define DT_MIPS_CONFLICTNO   0x7000000b	
#define DT_MIPS_CXX_FLAGS    0x70000022 
#define DT_MIPS_DELTA_CLASS  0x70000017	
#define DT_MIPS_DELTA_CLASSSYM 0x70000020 
#define DT_MIPS_DELTA_CLASSSYM_NO 0x70000021 
#define DT_MIPS_DELTA_CLASS_NO    0x70000018 
#define DT_MIPS_DELTA_INSTANCE    0x70000019 
#define DT_MIPS_DELTA_INSTANCE_NO 0x7000001a 
#define DT_MIPS_DELTA_RELOC  0x7000001b 
#define DT_MIPS_DELTA_RELOC_NO 0x7000001c 
#define DT_MIPS_DELTA_SYM    0x7000001d 
#define DT_MIPS_DELTA_SYM_NO 0x7000001e 
#define DT_MIPS_DYNSTR_ALIGN 0x7000002b
#define DT_MIPS_GP_VALUE     0x70000030 
#define DT_MIPS_HIDDEN_GOTIDX 0x70000027
#define DT_MIPS_HIPAGENO     0x70000014	
#define DT_MIPS_ICHECKSUM    0x70000003	
#define DT_MIPS_INTERFACE    0x7000002a 
#define DT_MIPS_INTERFACE_SIZE 0x7000002c 
#define DT_MIPS_IVERSION     0x70000004	
#define DT_MIPS_LIBLISTNO    0x70000010	
#define DT_MIPS_LOCALPAGE_GOTIDX 0x70000025
#define DT_MIPS_LOCAL_GOTIDX 0x70000026
#define DT_MIPS_LOCAL_GOTNO  0x7000000a	
#define DT_MIPS_PERF_SUFFIX  0x7000002e 
#define DT_MIPS_PIXIE_INIT   0x70000023
#define DT_MIPS_PROTECTED_GOTIDX 0x70000028
#define DT_MIPS_RLD_MAP_REL  0x70000035
#define DT_MIPS_RLD_TEXT_RESOLVE_ADDR 0x7000002d 
#define DT_MIPS_RLD_VERSION  0x70000001	
#define DT_MIPS_RWPLT        0x70000034
#define DT_MIPS_SYMBOL_LIB   0x70000024
#define DT_MIPS_SYMTABNO     0x70000011	
#define DT_MIPS_TIME_STAMP   0x70000002	
#define DT_MIPS_UNREFEXTNO   0x70000012	
#define DT_NIOS2_GP             0x70000002 
#define DT_PPC64_GLINK  (DT_LOPROC + 0)
#define DT_PPC64_NUM    4
#define DT_PREINIT_ARRAY 32		
#define DT_PREINIT_ARRAYSZ 33		
#define DT_VALNUM 12
#define DT_VALTAGIDX(tag)	(DT_VALRNGHI - (tag))	
#define DT_VERSIONTAGIDX(tag)	(DT_VERNEEDNUM - (tag))	
#define DT_VERSIONTAGNUM 16
#define EF_ARM_EABI_VERSION(flags)	((flags) & EF_ARM_EABIMASK)
#define EF_S390_HIGH_GPRS    0x00000001  
#define EI_NIDENT (16)
#define ELF32_M_INFO(sym, size)	(((sym) << 8) + (unsigned char) (size))
#define ELF32_M_SIZE(info)	((unsigned char) (info))
#define ELF32_M_SYM(info)	((info) >> 8)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))
#define ELF32_R_SYM(val)		((val) >> 8)
#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_ST_BIND(val)		(((unsigned char) (val)) >> 4)
#define ELF32_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))
#define ELF32_ST_TYPE(val)		((val) & 0xf)
#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
#define ELF64_M_INFO(sym, size)	ELF32_M_INFO (sym, size)
#define ELF64_M_SIZE(info)	ELF32_M_SIZE (info)
#define ELF64_M_SYM(info)	ELF32_M_SYM (info)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))
#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_ST_BIND(val)		ELF32_ST_BIND (val)
#define ELF64_ST_INFO(bind, type)	ELF32_ST_INFO ((bind), (type))
#define ELF64_ST_TYPE(val)		ELF32_ST_TYPE (val)
#define ELF64_ST_VISIBILITY(o)	ELF32_ST_VISIBILITY (o)
#define EM_ALTERA_NIOS2 113	
#define EM_LATTICEMICO32 138	
#define LL_IGNORE_INT_VER (1 << 1)	
#define LL_REQUIRE_MINOR  (1 << 2)
#define MIPS_AFL_EXT_LOONGSON_2E  17  
#define MIPS_AFL_EXT_LOONGSON_2F  18  
#define MIPS_AFL_EXT_LOONGSON_3A  4   
#define MIPS_AFL_FLAGS1_ODDSPREG  1  
#define PPC64_LOCAL_ENTRY_OFFSET(other)				\
 (((1 << (((other) & STO_PPC64_LOCAL_MASK) >> STO_PPC64_LOCAL_BIT)) >> 2) << 2)
#define PT_MIPS_ABIFLAGS  0x70000003	
#define RHF_GUARANTEE_START_INIT   (1 << 7)
#define RHF_NO_LIBRARY_REPLACEMENT (1 << 2)	
#define R_386_TLS_DESC     41		
#define R_386_TLS_DESC_CALL 40		
#define R_386_TLS_DTPMOD32 35		
#define R_386_TLS_DTPOFF32 36		
#define R_386_TLS_GD_CALL  26		
#define R_386_TLS_GD_POP   27		
#define R_386_TLS_GD_PUSH  25		
#define R_386_TLS_GOTDESC  39		
#define R_386_TLS_LDM_32   28		
#define R_386_TLS_LDM_CALL 30		
#define R_386_TLS_LDM_POP  31		
#define R_386_TLS_LDM_PUSH 29		
#define R_386_TLS_LDO_32   32		
#define R_386_TLS_TPOFF32  37		
#define R_390_IRELATIVE         61      
#define R_68K_TLS_DTPMOD32  40          
#define R_68K_TLS_DTPREL32  41          
#define R_68K_TLS_GD16      26          
#define R_68K_TLS_GD32      25          
#define R_68K_TLS_GD8       27          
#define R_68K_TLS_IE16      35          
#define R_68K_TLS_IE32      34          
#define R_68K_TLS_IE8       36          
#define R_68K_TLS_LDM16     29          
#define R_68K_TLS_LDM32     28          
#define R_68K_TLS_LDM8      30          
#define R_68K_TLS_LDO16     32          
#define R_68K_TLS_LDO32     31          
#define R_68K_TLS_LDO8      33          
#define R_68K_TLS_LE16      38          
#define R_68K_TLS_LE32      37          
#define R_68K_TLS_LE8       39          
#define R_68K_TLS_TPREL32   42          
#define R_AARCH64_ABS32         258	
#define R_AARCH64_ABS64         257	
#define R_AARCH64_ADD_ABS_LO12_NC 277	
#define R_AARCH64_ADR_PREL_PG_HI21 275	
#define R_AARCH64_ADR_PREL_PG_HI21_NC 276 
#define R_AARCH64_COPY         1024	
#define R_AARCH64_GLOB_DAT     1025	
#define R_AARCH64_JUMP_SLOT    1026	
#define R_AARCH64_LD64_GOTOFF_LO15 310	
#define R_AARCH64_LD64_GOTPAGE_LO15 313	
#define R_AARCH64_LD64_GOT_LO12_NC 312	
#define R_AARCH64_LDST128_ABS_LO12_NC 299 
#define R_AARCH64_LDST16_ABS_LO12_NC 284 
#define R_AARCH64_LDST32_ABS_LO12_NC 285 
#define R_AARCH64_LDST64_ABS_LO12_NC 286 
#define R_AARCH64_LDST8_ABS_LO12_NC 278	
#define R_AARCH64_MOVW_GOTOFF_G0 300	
#define R_AARCH64_MOVW_GOTOFF_G0_NC 301	
#define R_AARCH64_MOVW_GOTOFF_G1 302	
#define R_AARCH64_MOVW_GOTOFF_G1_NC 303	
#define R_AARCH64_MOVW_GOTOFF_G2 304	
#define R_AARCH64_MOVW_GOTOFF_G2_NC 305	
#define R_AARCH64_MOVW_GOTOFF_G3 306	
#define R_AARCH64_MOVW_PREL_G0_NC 288	
#define R_AARCH64_MOVW_PREL_G1_NC 290	
#define R_AARCH64_MOVW_PREL_G2_NC 292	
#define R_AARCH64_MOVW_UABS_G0_NC 264	
#define R_AARCH64_MOVW_UABS_G1_NC 266	
#define R_AARCH64_MOVW_UABS_G2_NC 268	
#define R_AARCH64_NONE            0	
#define R_AARCH64_RELATIVE     1027	
#define R_AARCH64_TLSDESC      1031	
#define R_AARCH64_TLSDESC_ADD_LO12 564	
#define R_AARCH64_TLSDESC_ADR_PAGE21 562 
#define R_AARCH64_TLSDESC_ADR_PREL21 561 
#define R_AARCH64_TLSDESC_LD64_LO12 563	
#define R_AARCH64_TLSDESC_LD_PREL19 560	
#define R_AARCH64_TLSDESC_OFF_G0_NC 566	
#define R_AARCH64_TLSDESC_OFF_G1 565	
#define R_AARCH64_TLSGD_ADD_LO12_NC 514	
#define R_AARCH64_TLSGD_ADR_PAGE21 513	
#define R_AARCH64_TLSGD_ADR_PREL21 512	
#define R_AARCH64_TLSGD_MOVW_G0_NC 516	
#define R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 541 
#define R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 542 
#define R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 543 
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC 540 
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 539 
#define R_AARCH64_TLSLD_ADD_DTPREL_HI12 528 
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12 529 
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC 530 
#define R_AARCH64_TLSLD_ADD_LO12_NC 519	
#define R_AARCH64_TLSLD_ADR_PAGE21 518	
#define R_AARCH64_TLSLD_ADR_PREL21 517	
#define R_AARCH64_TLSLD_LDST128_DTPREL_LO12 572 
#define R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC 573 
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12 533 
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC 534 
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12 535 
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC 536 
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12 537 
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC 538 
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12 531 
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC 532 
#define R_AARCH64_TLSLD_LD_PREL19 522	
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0 526 
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC 527 
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1 524 
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC 525 
#define R_AARCH64_TLSLD_MOVW_DTPREL_G2 523 
#define R_AARCH64_TLSLD_MOVW_G0_NC 521	
#define R_AARCH64_TLSLE_ADD_TPREL_HI12 549 
#define R_AARCH64_TLSLE_ADD_TPREL_LO12 550 
#define R_AARCH64_TLSLE_ADD_TPREL_LO12_NC 551 
#define R_AARCH64_TLSLE_LDST128_TPREL_LO12 570 
#define R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC 571 
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12 554 
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC 555 
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12 556 
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC 557 
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12 558 
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC 559 
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12 552 
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC 553 
#define R_AARCH64_TLSLE_MOVW_TPREL_G0 547 
#define R_AARCH64_TLSLE_MOVW_TPREL_G0_NC 548 
#define R_AARCH64_TLSLE_MOVW_TPREL_G1 545 
#define R_AARCH64_TLSLE_MOVW_TPREL_G1_NC 546 
#define R_AARCH64_TLSLE_MOVW_TPREL_G2 544 
#define R_AARCH64_TLS_DTPMOD   1028	
#define R_AARCH64_TLS_DTPREL   1029	
#define R_AARCH64_TLS_TPREL    1030	
#define R_METAG_TLS_IENONPIC_HI16 54
#define R_METAG_TLS_IENONPIC_LO16 55
#define R_MICROBLAZE_32 		1	
#define R_MICROBLAZE_64 		5	
#define R_MICROBLAZE_TLSTPREL32 	29	
#define R_MIPS_JUMP_SLOT        127
#define R_PPC64_DTPREL16_HIGHERA 104 
#define R_PPC64_DTPREL16_HIGHEST 105 
#define R_PPC64_DTPREL16_HIGHESTA 106 
#define R_PPC64_GOT_DTPREL16_LO_DS 92 
#define R_PPC64_GOT_TPREL16_LO_DS 88 
#define R_PPC64_TPREL16_HIGHESTA 100 
#define R_TILEGX_IMM16_X0_HW0_GOT 64	
#define R_TILEGX_IMM16_X0_HW0_LAST 44	
#define R_TILEGX_IMM16_X0_HW0_LAST_GOT 72 
#define R_TILEGX_IMM16_X0_HW0_LAST_PCREL 58 
#define R_TILEGX_IMM16_X0_HW0_LAST_PLT_PCREL 94 
#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_GD 86 
#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_IE 100 
#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_LE 82 
#define R_TILEGX_IMM16_X0_HW0_PCREL 50	
#define R_TILEGX_IMM16_X0_HW0_PLT_PCREL 66 
#define R_TILEGX_IMM16_X0_HW0_TLS_GD 78	
#define R_TILEGX_IMM16_X0_HW0_TLS_IE 92	
#define R_TILEGX_IMM16_X0_HW0_TLS_LE 80	
#define R_TILEGX_IMM16_X0_HW1_LAST 46	
#define R_TILEGX_IMM16_X0_HW1_LAST_GOT 74 
#define R_TILEGX_IMM16_X0_HW1_LAST_PCREL 60 
#define R_TILEGX_IMM16_X0_HW1_LAST_PLT_PCREL 96 
#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_GD 88 
#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_IE 102 
#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_LE 84 
#define R_TILEGX_IMM16_X0_HW1_PCREL 52	
#define R_TILEGX_IMM16_X0_HW1_PLT_PCREL 68 
#define R_TILEGX_IMM16_X0_HW2_LAST 48	
#define R_TILEGX_IMM16_X0_HW2_LAST_PCREL 62 
#define R_TILEGX_IMM16_X0_HW2_LAST_PLT_PCREL 98 
#define R_TILEGX_IMM16_X0_HW2_PCREL 54	
#define R_TILEGX_IMM16_X0_HW2_PLT_PCREL 70 
#define R_TILEGX_IMM16_X0_HW3_PCREL 56	
#define R_TILEGX_IMM16_X0_HW3_PLT_PCREL 76 
#define R_TILEGX_IMM16_X1_HW0_GOT 65	
#define R_TILEGX_IMM16_X1_HW0_LAST 45	
#define R_TILEGX_IMM16_X1_HW0_LAST_GOT 73 
#define R_TILEGX_IMM16_X1_HW0_LAST_PCREL 59 
#define R_TILEGX_IMM16_X1_HW0_LAST_PLT_PCREL 95 
#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_GD 87 
#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_IE 101 
#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_LE 83 
#define R_TILEGX_IMM16_X1_HW0_PCREL 51	
#define R_TILEGX_IMM16_X1_HW0_PLT_PCREL 67 
#define R_TILEGX_IMM16_X1_HW0_TLS_GD 79	
#define R_TILEGX_IMM16_X1_HW0_TLS_IE 93	
#define R_TILEGX_IMM16_X1_HW0_TLS_LE 81	
#define R_TILEGX_IMM16_X1_HW1_LAST 47	
#define R_TILEGX_IMM16_X1_HW1_LAST_GOT 75 
#define R_TILEGX_IMM16_X1_HW1_LAST_PCREL 61 
#define R_TILEGX_IMM16_X1_HW1_LAST_PLT_PCREL 97 
#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_GD 89 
#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_IE 103 
#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_LE 85 
#define R_TILEGX_IMM16_X1_HW1_PCREL 53	
#define R_TILEGX_IMM16_X1_HW1_PLT_PCREL 69 
#define R_TILEGX_IMM16_X1_HW2_LAST 49	
#define R_TILEGX_IMM16_X1_HW2_LAST_PCREL 63 
#define R_TILEGX_IMM16_X1_HW2_LAST_PLT_PCREL 99 
#define R_TILEGX_IMM16_X1_HW2_PCREL 55	
#define R_TILEGX_IMM16_X1_HW2_PLT_PCREL 71 
#define R_TILEGX_IMM16_X1_HW3_PCREL 57	
#define R_TILEGX_IMM16_X1_HW3_PLT_PCREL 77 
#define R_TILEGX_IMM8_X0_TLS_ADD 118	
#define R_TILEGX_IMM8_X0_TLS_GD_ADD 113	
#define R_TILEGX_IMM8_X1_TLS_ADD 119	
#define R_TILEGX_IMM8_X1_TLS_GD_ADD 114	
#define R_TILEGX_IMM8_Y0_TLS_ADD 120	
#define R_TILEGX_IMM8_Y0_TLS_GD_ADD 115	
#define R_TILEGX_IMM8_Y1_TLS_ADD 121	
#define R_TILEGX_IMM8_Y1_TLS_GD_ADD 116	
#define R_TILEPRO_IMM16_X0_GOT_HA 45	
#define R_TILEPRO_IMM16_X0_GOT_HI 43	
#define R_TILEPRO_IMM16_X0_GOT_LO 41	
#define R_TILEPRO_IMM16_X0_HA_PCREL 37	
#define R_TILEPRO_IMM16_X0_HI_PCREL 35	
#define R_TILEPRO_IMM16_X0_LO_PCREL 33	
#define R_TILEPRO_IMM16_X0_PCREL 31	
#define R_TILEPRO_IMM16_X0_TLS_GD 66	
#define R_TILEPRO_IMM16_X0_TLS_GD_HA 72	
#define R_TILEPRO_IMM16_X0_TLS_GD_HI 70	
#define R_TILEPRO_IMM16_X0_TLS_GD_LO 68	
#define R_TILEPRO_IMM16_X0_TLS_IE 74	
#define R_TILEPRO_IMM16_X0_TLS_IE_HA 80	
#define R_TILEPRO_IMM16_X0_TLS_IE_HI 78	
#define R_TILEPRO_IMM16_X0_TLS_IE_LO 76	
#define R_TILEPRO_IMM16_X0_TLS_LE 85	
#define R_TILEPRO_IMM16_X0_TLS_LE_HA 91	
#define R_TILEPRO_IMM16_X0_TLS_LE_HI 89	
#define R_TILEPRO_IMM16_X0_TLS_LE_LO 87	
#define R_TILEPRO_IMM16_X1_GOT_HA 46	
#define R_TILEPRO_IMM16_X1_GOT_HI 44	
#define R_TILEPRO_IMM16_X1_GOT_LO 42	
#define R_TILEPRO_IMM16_X1_HA_PCREL 38	
#define R_TILEPRO_IMM16_X1_HI_PCREL 36	
#define R_TILEPRO_IMM16_X1_LO_PCREL 34	
#define R_TILEPRO_IMM16_X1_PCREL 32	
#define R_TILEPRO_IMM16_X1_TLS_GD 67	
#define R_TILEPRO_IMM16_X1_TLS_GD_HA 73	
#define R_TILEPRO_IMM16_X1_TLS_GD_HI 71	
#define R_TILEPRO_IMM16_X1_TLS_GD_LO 69	
#define R_TILEPRO_IMM16_X1_TLS_IE 75	
#define R_TILEPRO_IMM16_X1_TLS_IE_HA 81	
#define R_TILEPRO_IMM16_X1_TLS_IE_HI 79	
#define R_TILEPRO_IMM16_X1_TLS_IE_LO 77	
#define R_TILEPRO_IMM16_X1_TLS_LE 86	
#define R_TILEPRO_IMM16_X1_TLS_LE_HA 92	
#define R_TILEPRO_IMM16_X1_TLS_LE_HI 90	
#define R_TILEPRO_IMM16_X1_TLS_LE_LO 88	
#define R_TILEPRO_IMM8_X0_TLS_GD_ADD 61	
#define R_TILEPRO_IMM8_X1_TLS_GD_ADD 62	
#define R_TILEPRO_IMM8_Y0_TLS_GD_ADD 63	
#define R_TILEPRO_IMM8_Y1_TLS_GD_ADD 64	
#define R_TILEPRO_JOFFLONG_X1_PLT 16	
#define R_X86_64_GOTPC32_TLSDESC 34	
#define R_X86_64_TLSDESC        36	
#define R_X86_64_TLSDESC_CALL   35	
#define SHF_OS_NONCONFORMING (1 << 8)	
#define SHN_MIPS_SCOMMON 	0xff03	
#define SHT_GNU_ATTRIBUTES 0x6ffffff5	
#define SHT_PREINIT_ARRAY 16		
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_SYMTAB_SHNDX  18		
#define VER_NEED_CURRENT 1		

# define DL_CALL_FCT(fctp, args) \
  (_dl_mcount_wrapper_check ((void *) (fctp)), (*(fctp)) args)
# define __ACTION_FN_T
# define __COMPAR_FN_T
#define NSS_INVALID_FIELD_CHARACTERS ":\n"
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
#define		__need_size_t
#   define mkostemp mkostemp64
#   define mkostemps mkostemps64
#   define mkstemp mkstemp64
#   define mkstemps mkstemps64
#  define __need_size_t
#  define __need_wint_t
#   define fclose(fp) _IO_new_fclose (fp)
#   define fdopen(fd, mode) _IO_new_fdopen (fd, mode)
#   define fgetpos(fp, posp) _IO_new_fgetpos (fp, posp)
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
#   define fputs(str, fp) _IO_fputs (str, fp)
#   define fsetpos(fp, posp) _IO_new_fsetpos (fp, posp)
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
#  define assert(expr)							\
    ((expr)								\
     ? __ASSERT_VOID_CAST (0)						\
     : __assert_fail (#expr, "__FILE__", "__LINE__", __ASSERT_FUNCTION))
#  define assert_perror(errnum)						\
  (!(errnum)								\
   ? __ASSERT_VOID_CAST (0)						\
   : __assert_perror_fail ((errnum), "__FILE__", "__LINE__", __ASSERT_FUNCTION))
# define static_assert _Static_assert
