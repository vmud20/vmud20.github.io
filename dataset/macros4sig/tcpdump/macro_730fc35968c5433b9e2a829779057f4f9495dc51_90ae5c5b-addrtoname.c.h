#include<stdint.h>



#include<sys/types.h>
#include<sys/socket.h>

#include<ctype.h>
#include<stdarg.h>
#include<netinet/in.h>
#include<netinet/ether.h>
#include<stdlib.h>
#include<time.h>
#include<unistd.h>
#include<inttypes.h>
#include<netdb.h>

#include<stdio.h>

#include<net/if.h>


#include<string.h>
#include<signal.h>


#include<sys/time.h>
#include<fcntl.h>

#include<sys/param.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<errno.h>
#define OUI_APPLETALK         0x080007  
#define OUI_ATM_FORUM         0x00A03E  
#define OUI_BSN               0x5c16c7  
#define OUI_CABLE_BPDU        0x00E02F  
#define OUI_CISCO             0x00000c  
#define OUI_CISCO_90          0x0000f8  
#define OUI_DCBX              0x001B21  
#define OUI_ENCAP_ETHER       0x000000  
#define OUI_FREESCALE         0x00049f  
#define OUI_HP                0x080009  
#define OUI_HP2               0x002481  
#define OUI_HPLABS            0x0004ea  
#define OUI_IANA              0x00005E  
#define OUI_IEEE_8021_PRIVATE 0x0080c2  
#define OUI_IEEE_8023_PRIVATE 0x00120f  
#define OUI_INFOBLOX          0x748771  
#define OUI_JUNIPER           0x009069  
#define OUI_NETRONOME         0x0015ad  
#define OUI_NICIRA            0x002320  
#define OUI_NORTEL            0x000081  
#define OUI_ONLAB             0xa42305  
#define OUI_RFC2684           0x0080c2  
#define OUI_TIA               0x0012bb  
#define OUI_VELLO             0xb0d2f5  
#define SMI_3COM                     429
#define SMI_ACC                      5
#define SMI_APTIS                    2637
#define SMI_ASCEND                   529
#define SMI_BAY                      1584
#define SMI_CABLELABS                4491
#define SMI_CISCO                    9
#define SMI_CISCO_BBSM               5263
#define SMI_CISCO_VPN3000            3076
#define SMI_CISCO_VPN5000            255
#define SMI_COLUBRIS                 8744
#define SMI_COLUMBIA_UNIVERSITY      11862
#define SMI_COSINE                   3085
#define SMI_ERICSSON                 193
#define SMI_FOUNDRY                  1991
#define SMI_GEMTEK_SYSTEMS           10529
#define SMI_HEWLETT_PACKARD          11
#define SMI_IETF                     0 
#define SMI_INTERLINK                6728
#define SMI_IP_UNPLUGGED             5925
#define SMI_ISSANNI                  5948
#define SMI_JUNIPER                  2636
#define SMI_LIVINGSTON               307
#define SMI_MERIT                    61
#define SMI_MICROSOFT                311
#define SMI_NETSCREEN                3224
#define SMI_NOMADIX                  3309
#define SMI_QUINTUM                  6618
#define SMI_REDBACK                  2352
#define SMI_SHASTA                   3199
#define SMI_SHIVA                    166
#define SMI_SIEMENS                  4329
#define SMI_SUN_MICROSYSTEMS         42
#define SMI_THE3GPP                  10415
#define SMI_THE3GPP2                 5535
#define SMI_UNISPHERE                4874
#define SMI_VERSANET                 2180
#define SMI_WIFI_ALLIANCE            14122
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

  #define FORMAT_STRING(p) _Printf_format_string_ p
  #define NORETURN __attribute((noreturn))
    #define NORETURN_FUNCPTR __attribute((noreturn))
  #define PRINTFLIKE(x,y) __attribute__((__format__(__printf__,x,y)))

  #define __has_attribute(x) 0


#define LLC_IS_NR(is)	(((is) >> 9) & 0x7f)
#define LLC_I_NS(is)	(((is) >> 1) & 0x7f)
#define ETHERTYPE_AOE  		0x88a2
#define ETHERTYPE_EAPOL  	0x888e
#define ETHERTYPE_GRE_ISO       0x00FE  
#define ETHERTYPE_JUMBO         0x8870
#define ETHERTYPE_LEN           2
#define ETHERTYPE_LLDP          0x88cc
#define ETHERTYPE_RRCP  	0x8899
#define BUFSIZE 128
#define ip6addr_string(ndo, p) getname6(ndo, (const u_char *)(p))
#define ipaddr_string(ndo, p) getname(ndo, (const u_char *)(p))
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
