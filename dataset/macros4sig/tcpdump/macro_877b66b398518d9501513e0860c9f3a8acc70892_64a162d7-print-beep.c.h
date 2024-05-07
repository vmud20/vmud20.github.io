#include<sys/socket.h>

#include<inttypes.h>
#include<arpa/inet.h>
#include<fcntl.h>
#include<stdarg.h>
#include<time.h>

#include<ctype.h>

#include<netinet/in.h>
#include<sys/time.h>

#include<errno.h>
#include<string.h>
#include<sys/types.h>


#include<sys/param.h>
#include<netdb.h>
#include<stdint.h>
#include<unistd.h>
#include<stdio.h>

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
#  define ND_FALL_THROUGH __attribute__ ((fallthrough))
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
  #define FORMAT_STRING(p) _Printf_format_string_ p
  #define NORETURN __attribute((noreturn))
    #define NORETURN_FUNCPTR __attribute((noreturn))
  #define PRINTFLIKE(x,y) __attribute__((__format__(__printf__,x,y)))

  #define __has_attribute(x) 0

