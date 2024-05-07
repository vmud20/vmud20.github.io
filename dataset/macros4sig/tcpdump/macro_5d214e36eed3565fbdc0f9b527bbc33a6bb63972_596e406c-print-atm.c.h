#include<sys/types.h>
#include<inttypes.h>
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>


#include<sys/param.h>
#include<time.h>
#include<stdint.h>
#include<stdarg.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<errno.h>
#include<fcntl.h>

#include<ctype.h>

#include<netdb.h>
#include<sys/time.h>


#define LLC_IS_NR(is)	(((is) >> 9) & 0x7f)
#define LLC_I_NS(is)	(((is) >> 1) & 0x7f)
#define ATM_HDR_LEN_NOHEC 4
#define ATM_OAM_HEC     1
#define ATM_OAM_NOHEC   0
#define BUFSIZE 128
#define ip6addr_string(ndo, p) getname6(ndo, (const u_char *)(p))
#define ipaddr_string(ndo, p) getname(ndo, (const u_char *)(p))
#define EXTRACT_16BITS(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 0)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 1)) << 0)))
#define EXTRACT_24BITS(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0)))
#define EXTRACT_32BITS(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#define EXTRACT_40BITS(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0)))
#define EXTRACT_48BITS(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0)))
#define EXTRACT_56BITS(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0)))
#define EXTRACT_64BITS(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 56) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 7)) << 0)))
#define EXTRACT_LE_16BITS(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_24BITS(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_32BITS(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_64BITS(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 7)) << 56) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_8BITS(p) (*(p))
#define ND_TCHECK_16BITS(p) ND_TCHECK2(*(p), 2)
#define ND_TCHECK_24BITS(p) ND_TCHECK2(*(p), 3)
#define ND_TCHECK_32BITS(p) ND_TCHECK2(*(p), 4)
#define ND_TCHECK_40BITS(p) ND_TCHECK2(*(p), 5)
#define ND_TCHECK_48BITS(p) ND_TCHECK2(*(p), 6)
#define ND_TCHECK_56BITS(p) ND_TCHECK2(*(p), 7)
#define ND_TCHECK_64BITS(p) ND_TCHECK2(*(p), 8)
#define ND_TCHECK_8BITS(p) ND_TCHECK2(*(p), 1)
#define ND_TTEST_16BITS(p) ND_TTEST2(*(p), 2)
#define ND_TTEST_24BITS(p) ND_TTEST2(*(p), 3)
#define ND_TTEST_32BITS(p) ND_TTEST2(*(p), 4)
#define ND_TTEST_40BITS(p) ND_TTEST2(*(p), 5)
#define ND_TTEST_48BITS(p) ND_TTEST2(*(p), 6)
#define ND_TTEST_56BITS(p) ND_TTEST2(*(p), 7)
#define ND_TTEST_64BITS(p) ND_TTEST2(*(p), 8)
#define ND_TTEST_8BITS(p) ND_TTEST2(*(p), 1)
#define EDST(ep) ((ep)->ether_dhost)
#define ESRC(ep) ((ep)->ether_shost)
#define HTONL(x)	(x) = htonl(x)
#define HTONS(x)	(x) = htons(x)
#define IF_PRINTER_ARGS (netdissect_options *, const struct pcap_pkthdr *, const u_char *)
#define IS_NOT_NEGATIVE(x) (((x) > 0) || ((x) == 0))
#define IS_SRC_OR_DST_PORT(p) (sport == (p) || dport == (p))
#define ND_DEFAULTPRINT(ap, length) (*ndo->ndo_default_print)(ndo, ap, length)
#define ND_ISASCII(c)	(!((c) & 0x80))	
#define ND_ISGRAPH(c)	((c) > 0x20 && (c) <= 0x7E)
#define ND_ISPRINT(c)	((c) >= 0x20 && (c) <= 0x7E)
#define ND_PRINT(STUFF) (*ndo->ndo_printf)STUFF
#define ND_TCHECK(var) ND_TCHECK2(var, sizeof(var))
#define ND_TCHECK2(var, l) if (!ND_TTEST2(var, l)) goto trunc
#define ND_TOASCII(c)	((c) & 0x7F)
#define ND_TTEST(var) ND_TTEST2(var, sizeof(var))
#define ND_TTEST2(var, l) \
  (IS_NOT_NEGATIVE(l) && \
	((uintptr_t)ndo->ndo_snapend - (l) <= (uintptr_t)ndo->ndo_snapend && \
         (uintptr_t)&(var) <= (uintptr_t)ndo->ndo_snapend - (l)))
#define NTOHL(x)	(x) = ntohl(x)
#define NTOHS(x)	(x) = ntohs(x)
#define PLURAL_SUFFIX(n) \
	(((n) != 1) ? "s" : "")
#define UNALIGNED_MEMCMP(p, q, l)	unaligned_memcmp((p), (q), (l))
#define UNALIGNED_MEMCPY(p, q, l)	unaligned_memcpy((p), (q), (l))

#define max(a,b) ((b)>(a)?(b):(a))
#define min(a,b) ((a)>(b)?(b):(a))

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6_VERSION(ip6_hdr)	(((ip6_hdr)->ip6_vfc & 0xf0) >> 4)
#define IPV6_RTHDR_TYPE_0 0
#define IPV6_RTHDR_TYPE_2 2

#define IPOPT_RA                148             
#define IPTS_FLG(ip)	((ipt)->ipt_oflwflg & 0x0f)
#define IPTS_OFLW(ip)	(((ipt)->ipt_oflwflg & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)

#define DIAG_DO_PRAGMA(x) _Pragma (#x)
#define DIAG_JOINSTR(x,y) XSTRINGIFY(x ## y)
#    define DIAG_OFF(x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
#    define DIAG_ON(x) DIAG_PRAGMA(pop)
#  define DIAG_PRAGMA(x) DIAG_DO_PRAGMA(GCC diagnostic x)
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define FALSE 0
  #define FOPEN_READ_BIN   "rb"
  #define FOPEN_READ_TXT   "rt"
  #define FOPEN_WRITE_BIN  "wb"
  #define FOPEN_WRITE_TXT  "wt"





#define INET6_ADDRSTRLEN 46
#define INET_ADDRSTRLEN 16
#define O_RDONLY _O_RDONLY
#define RETSIGTYPE void
#define TRUE 1
#  define USES_APPLE_DEPRECATED_API DIAG_OFF(deprecated-declarations)
#  define USES_APPLE_RST DIAG_ON(deprecated-declarations)
#define XSTRINGIFY(x) #x
#define close _close
#define fstat _fstat
  #define htonl(x)  __ntohl(x)
  #define htons(x)  __ntohs(x)
#define inline __inline

  #define ntohl(x)  __ntohl(x)
  #define ntohs(x)  __ntohs(x)
#define open _open
#define read _read
#define snprintf _snprintf
#define stat _stat
#define vsnprintf _vsnprintf
