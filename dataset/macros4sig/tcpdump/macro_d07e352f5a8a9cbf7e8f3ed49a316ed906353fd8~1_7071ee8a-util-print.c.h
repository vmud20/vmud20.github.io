
#include<fcntl.h>
#include<netdb.h>

#include<stdint.h>
#include<stdlib.h>
#include<unistd.h>
#include<ctype.h>

#include<arpa/inet.h>

#include<netinet/in.h>
#include<stdarg.h>
#include<time.h>
#include<string.h>
#include<inttypes.h>
#include<sys/socket.h>
#include<sys/param.h>


#include<errno.h>
#include<stdio.h>
#include<stddef.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/time.h>
#define _MICRO_PER_SEC 1000000
#define _NANO_PER_SEC 1000000000

#define netdissect_timevaladd(tvp, uvp, vvp, nano_prec)           \
	do {                                                      \
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;    \
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec; \
		if (nano_prec) {                                  \
			if ((vvp)->tv_usec >= _NANO_PER_SEC) {    \
				(vvp)->tv_sec++;                  \
				(vvp)->tv_usec -= _NANO_PER_SEC;  \
			}                                         \
		} else {                                          \
			if ((vvp)->tv_usec >= _MICRO_PER_SEC) {   \
				(vvp)->tv_sec++;                  \
				(vvp)->tv_usec -= _MICRO_PER_SEC; \
			}                                         \
		}                                                 \
	} while (0)
#define netdissect_timevalclear(tvp) ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define netdissect_timevalcmp(tvp, uvp, cmp)      \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?    \
	 ((tvp)->tv_usec cmp (uvp)->tv_usec) : \
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define netdissect_timevalisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)
#define netdissect_timevalsub(tvp, uvp, vvp, nano_prec)            \
	do {                                                       \
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;     \
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;  \
		if ((vvp)->tv_usec < 0) {                          \
		    (vvp)->tv_sec--;                               \
		    (vvp)->tv_usec += (nano_prec ? _NANO_PER_SEC : \
				       _MICRO_PER_SEC);            \
		}                                                  \
	} while (0)

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
