#include<arpa/inet.h>
#include<sys/param.h>
#include<sys/socket.h>
#include<errno.h>

#include<ctype.h>


#include<inttypes.h>
#include<sys/time.h>

#include<netinet/in.h>
#include<stdint.h>

#include<unistd.h>

#include<fcntl.h>
#include<sys/types.h>
#include<netdb.h>
#include<stdio.h>
#include<time.h>
#include<stdarg.h>


#define NFSX_FH(v3)		((v3) ? (NFSX_V3FHMAX + NFSX_UNSIGNED) : \
					NFSX_V2FH)
#define NFSX_POSTOPATTR(v3)	((v3) ? (NFSX_V3FATTR + NFSX_UNSIGNED) : 0)
#define NFSX_POSTOPORFATTR(v3)	((v3) ? (NFSX_V3FATTR + NFSX_UNSIGNED) : \
					NFSX_V2FATTR)
#define NFSX_PREOPATTR(v3)	((v3) ? (7 * NFSX_UNSIGNED) : 0)
#define NFSX_READDIR(v3)	((v3) ? (5 * NFSX_UNSIGNED) : \
					(2 * NFSX_UNSIGNED))
#define NFSX_SRVFH(v3)		((v3) ? NFSX_V3FH : NFSX_V2FH)
#define NFSX_V3COOKIEVERF 	8
#define NFSX_V3WRITEVERF 	8
#define NFSX_WCCDATA(v3)	((v3) ? NFSX_V3WCCDATA : 0)
#define NFSX_WCCORFATTR(v3)	((v3) ? NFSX_V3WCCDATA : NFSX_V2FATTR)
#define vtonfsv3_mode(m)	txdr_unsigned((m) & 07777)
#define IPPROTO_PGM             113
#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6_VERSION(ip6_hdr)	(((ip6_hdr)->ip6_vfc & 0xf0) >> 4)
#define IPV6_RTHDR_TYPE_0 0
#define IPV6_RTHDR_TYPE_2 2

#define IPOPT_RA                148             
#define IPTS_FLG(ip)	((ipt)->ipt_oflwflg & 0x0f)
#define IPTS_OFLW(ip)	(((ipt)->ipt_oflwflg & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)

#define atalk_port(p) \
	(((unsigned)((p) - 16512) < 128) || \
	 ((unsigned)((p) - 200) < 128) || \
	 ((unsigned)((p) - 768) < 128))
#define ddpEIGRP        88      
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
#define AHCP_PORT 5359		
#define AODV_PORT 654		
#define BABEL_PORT              6696  
#define BABEL_PORT_OLD          6697  
#define BFD_CONTROL_PORT        3784 
#define BFD_ECHO_PORT           3785 
#define BOOTPC_PORT 68		
#define BOOTPS_PORT 67		
#define CISCO_AUTORP_PORT 496	
#define DHCP6_CLI_PORT 547	
#define DHCP6_SERV_PORT 546	
#define GENEVE_PORT             6081  
#define HSRP_PORT 1985		
#define ISAKMP_PORT 500		
#define ISAKMP_PORT_NATT  4500  
#define ISAKMP_PORT_USER1 7500	
#define ISAKMP_PORT_USER2 8500	
#define KERBEROS_PORT 88	
#define KERBEROS_SEC_PORT 750	
#define L2TP_PORT 1701		
#define LDP_PORT 646
#define LMP_PORT                701 
#define LWAPP_CONTROL_PORT      12223 
#define LWAPP_DATA_PORT         12222 
#define MPLS_LSP_PING_PORT      3503 
#define NETBIOS_DGRAM_PORT   138
#define NETBIOS_NS_PORT   137
#define NTP_PORT 123		
#define OLSR_PORT 698           
#define OTV_PORT                8472  
#define RADIUS_ACCOUNTING_PORT 1646
#define RADIUS_COA_PORT 3799
#define RADIUS_NEW_ACCOUNTING_PORT 1813
#define RADIUS_NEW_PORT 1812
#define RADIUS_PORT 1645
#define RIPNG_PORT              521   
#define RIP_PORT 520		
#define RX_PORT_HIGH 7009	
#define RX_PORT_LOW 7000	
#define SFLOW_PORT              6343 
#define SIP_PORT 5060
#define SNMPTRAP_PORT 162	
#define SNMP_PORT 161		
#define SUNRPC_PORT 111		
#define SYSLOG_PORT 514         
#define TFTP_PORT 69		
#define TIMED_PORT 525		
#define VXLAN_PORT              4789  
#define atalk_port(p) \
	(((unsigned)((p) - 16512) < 128) || \
	 ((unsigned)((p) - 200) < 128) || \
	 ((unsigned)((p) - 768) < 128))
#define ddpEIGRP        88      
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
#  define __LOCALE_T_DECLARED
#define __ssp_bos_check2(fun, dst, src) \
    ((__ssp_bos0(dst) != (size_t)-1) ? \
    __builtin___ ## fun ## _chk(dst, src, __ssp_bos0(dst)) : \
    __ ## fun ## _ichk(dst, src))
#define __ssp_bos_check3(fun, dst, src, len) \
    ((__ssp_bos0(dst) != (size_t)-1) ? \
    __builtin___ ## fun ## _chk(dst, src, len, __ssp_bos0(dst)) : \
    __ ## fun ## _ichk(dst, src, len))
#define __ssp_bos_icheck2_restrict(fun, type1, type2) \
static __inline type1 __ ## fun ## _ichk(type1, type2); \
static __inline __attribute__((__always_inline__)) type1 \
__ ## fun ## _ichk(type1 __restrict dst, type2 __restrict src) { \
	return __builtin___ ## fun ## _chk(dst, src, __ssp_bos0(dst)); \
}
#define __ssp_bos_icheck3(fun, type1, type2) \
static __inline type1 __ ## fun ## _ichk(type1, type2, size_t); \
static __inline __attribute__((__always_inline__)) type1 \
__ ## fun ## _ichk(type1 dst, type2 src, size_t len) { \
	return __builtin___ ## fun ## _chk(dst, src, len, __ssp_bos0(dst)); \
}
#define __ssp_bos_icheck3_restrict(fun, type1, type2) \
static __inline type1 __ ## fun ## _ichk(type1 __restrict, type2 __restrict, size_t); \
static __inline __attribute__((__always_inline__)) type1 \
__ ## fun ## _ichk(type1 __restrict dst, type2 __restrict src, size_t len) { \
	return __builtin___ ## fun ## _chk(dst, src, len, __ssp_bos0(dst)); \
}
#define memcpy(dst, src, len) __ssp_bos_check3(memcpy, dst, src, len)
#define memmove(dst, src, len) __ssp_bos_check3(memmove, dst, src, len)
#define memset(dst, val, len) __ssp_bos_check3(memset, dst, val, len)
#define stpcpy(dst, src) __ssp_bos_check2(stpcpy, dst, src)
#define stpncpy(dst, src, len) __ssp_bos_check3(stpncpy, dst, src, len)
#define strcat(dst, src) __ssp_bos_check2(strcat, dst, src)
#define strcpy(dst, src) __ssp_bos_check2(strcpy, dst, src)
#define strncat(dst, src, len) __ssp_bos_check3(strncat, dst, src, len)
#define strncpy(dst, src, len) __ssp_bos_check3(strncpy, dst, src, len)
#define bcopy(src, dst, len) \
    ((__ssp_bos0(dst) != (size_t)-1) ? \
    __builtin___memmove_chk(dst, src, len, __ssp_bos0(dst)) : \
    __memmove_ichk(dst, src, len))
#define bzero(dst, len) \
    ((__ssp_bos0(dst) != (size_t)-1) ? \
    __builtin___memset_chk(dst, 0, len, __ssp_bos0(dst)) : \
    __memset_ichk(dst, 0, len))
#define BUFSIZE 128
#define ip6addr_string(ndo, p) getname6(ndo, (const u_char *)(p))
#define ipaddr_string(ndo, p) getname(ndo, (const u_char *)(p))
#define Aflag gndo->ndo_Aflag
#define Bflag gndo->ndo_Bflag
#define Cflag gndo->ndo_Cflag
#define Cflag_count gndo->ndo_Cflag_count
#define EDST(ep) ((ep)->ether_dhost)
#define ESRC(ep) ((ep)->ether_shost)
#define Gflag gndo->ndo_Gflag
#define Gflag_count gndo->ndo_Gflag_count
#define Gflag_time gndo->ndo_Gflag_time
#define HTONL(x)	(x) = htonl(x)
#define HTONS(x)	(x) = htons(x)
#define Hflag gndo->ndo_Hflag
#define Iflag gndo->ndo_Iflag
#define Kflag gndo->ndo_Kflag
#define NTOHL(x)	(x) = ntohl(x)
#define NTOHS(x)	(x) = ntohs(x)
#define Nflag gndo->ndo_Nflag
#define Oflag gndo->ndo_Oflag
#define Rflag gndo->ndo_Rflag
#define Sflag gndo->ndo_Sflag
#define TCHECK(var) TCHECK2(var, sizeof(var))
#define TCHECK2(var, l) if (!TTEST2(var, l)) goto trunc
#define TTEST(var) TTEST2(var, sizeof(var))
#define TTEST2(var, l) \
	((uintptr_t)snapend - (l) <= (uintptr_t)snapend && \
	   (uintptr_t)&(var) <= (uintptr_t)snapend - (l))
#define Uflag gndo->ndo_Uflag
#define Wflag gndo->ndo_Wflag
#define WflagChars gndo->ndo_WflagChars
#define Xflag gndo->ndo_Xflag
#define bflag gndo->ndo_bflag
#define eflag gndo->ndo_eflag
#define fflag gndo->ndo_fflag
#define jflag gndo->ndo_jflag
#define nflag gndo->ndo_nflag
#define packettype gndo->ndo_packettype
#define pflag gndo->ndo_pflag
#define qflag gndo->ndo_qflag
#define sflag gndo->ndo_sflag
#define sigsecret gndo->ndo_sigsecret
#define snapend     gndo->ndo_snapend
#define snaplen     gndo->ndo_snaplen
#define suppress_default_print gndo->ndo_suppress_default_print
#define tflag gndo->ndo_tflag
#define uflag gndo->ndo_uflag
#define vflag gndo->ndo_vflag
#define xflag gndo->ndo_xflag
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
  ((l) >= 0 && \
	((uintptr_t)ndo->ndo_snapend - (l) <= (uintptr_t)ndo->ndo_snapend && \
         (uintptr_t)&(var) <= (uintptr_t)ndo->ndo_snapend - (l)))
#define PLURAL_SUFFIX(n) \
	(((n) != 1) ? "s" : "")
#define TOKBUFSIZE 128
#define UNALIGNED_MEMCMP(p, q, l)	unaligned_memcmp((p), (q), (l))
#define UNALIGNED_MEMCPY(p, q, l)	unaligned_memcpy((p), (q), (l))
#define HAVE_ADDRINFO 1
#define HAVE_ALARM 1
#define HAVE_BPF_DUMP 1
#define HAVE_DECL_ETHER_NTOHOST 1
#define HAVE_ETHER_NTOHOST 1
#define HAVE_FCNTL_H 1
#define HAVE_FORK 1
#define HAVE_GETNAMEINFO 1
#define HAVE_GETOPT_LONG 1
#define HAVE_GETRPCBYNUMBER 1
#define HAVE_H_ERRNO 1
#define HAVE_INTTYPES_H 1
#define HAVE_LIBCRYPTO 1
#define HAVE_MEMORY_H 1
#define HAVE_NETINET_IF_ETHER_H 1
#define HAVE_NET_PFVAR_H 1
#define HAVE_OPENAT 1
#define HAVE_OPENSSL_EVP_H 1
#define HAVE_PCAP_BREAKLOOP 1
#define HAVE_PCAP_CREATE 1
#define HAVE_PCAP_DATALINK_NAME_TO_VAL 1
#define HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION 1
#define HAVE_PCAP_DEBUG 1
#define HAVE_PCAP_DUMP_FLUSH 1
#define HAVE_PCAP_DUMP_FTELL 1
#define HAVE_PCAP_FINDALLDEVS 1
#define HAVE_PCAP_FREE_DATALINKS 1
#define HAVE_PCAP_IF_T 1
#define HAVE_PCAP_LIB_VERSION 1
#define HAVE_PCAP_LIST_DATALINKS 1
#define HAVE_PCAP_SETDIRECTION 1
#define HAVE_PCAP_SET_DATALINK 1
#define HAVE_PCAP_SET_IMMEDIATE_MODE 1
#define HAVE_PCAP_SET_TSTAMP_PRECISION 1
#define HAVE_PCAP_SET_TSTAMP_TYPE 1
#define HAVE_RPC_RPCENT_H 1
#define HAVE_RPC_RPC_H 1
#define HAVE_SETLINEBUF 1
#define HAVE_SIGACTION 1
#define HAVE_SNPRINTF 1
#define HAVE_SOCKADDR_SA_LEN 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRCASECMP 1
#define HAVE_STRDUP 1
#define HAVE_STRFTIME 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_STRLCAT 1
#define HAVE_STRLCPY 1
#define HAVE_STRSEP 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UINTPTR_T 1
#define HAVE_UNISTD_H 1
#define HAVE_VFORK 1
#define HAVE_VFPRINTF 1
#define HAVE_VSNPRINTF 1
#define HAVE___ATTRIBUTE__ 1
#define INET6 1
#define LBL_ALIGN 1
#define PACKAGE_BUGREPORT ""
#define PACKAGE_NAME ""
#define PACKAGE_STRING ""
#define PACKAGE_TARNAME ""
#define PACKAGE_URL ""
#define PACKAGE_VERSION ""
#define RETSIGTYPE void
#define STDC_HEADERS 1
#define TCPDUMP_DO_SMB 1
#define TIME_WITH_SYS_TIME 1
#define USE_ETHER_NTOHOST 1
#define __ATTRIBUTE___FORMAT_OK 1
#define __ATTRIBUTE___FORMAT_OK_FOR_FUNCTION_POINTERS 1
#define __ATTRIBUTE___NORETURN_OK_FOR_FUNCTION_POINTERS 1
#define inline inline
#define infof (void)