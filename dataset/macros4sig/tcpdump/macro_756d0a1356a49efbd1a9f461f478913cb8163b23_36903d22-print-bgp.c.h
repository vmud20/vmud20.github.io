
#include<netinet/in.h>

#include<string.h>

#include<time.h>
#include<stdio.h>
#include<errno.h>
#include<fcntl.h>

#include<sys/types.h>
#include<stdarg.h>
#include<inttypes.h>
#include<setjmp.h>




#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/time.h>
#include<netdb.h>



#include<sys/param.h>
#include<unistd.h>

#define AFNUM_L2VPN     196 
#define AFNUM_VPLS      25
#define EXTRACT_BE_S_2(p) \
	((int16_t)(((uint16_t)(*((const uint8_t *)(p) + 0)) << 8) | \
	           ((uint16_t)(*((const uint8_t *)(p) + 1)) << 0)))
#define EXTRACT_BE_S_3(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0))) : \
	  ((int32_t)(0xFF000000U | \
	             ((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0))))
#define EXTRACT_BE_S_4(p) \
	((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#define EXTRACT_BE_S_5(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0))) : \
	  ((int64_t)(INT64_T_CONSTANT(0xFFFFFF0000000000U) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0))))
#define EXTRACT_BE_S_6(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	   ((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0))) : \
	  ((int64_t)(INT64_T_CONSTANT(0xFFFFFFFF00000000U) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0))))
#define EXTRACT_BE_S_7(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0))) : \
	    ((int64_t)(INT64_T_CONSTANT(0xFFFFFFFFFF000000U) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0))))
#define EXTRACT_BE_S_8(p) \
	((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 56) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 1)) << 48) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 2)) << 40) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 3)) << 32) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 4)) << 24) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 5)) << 16) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 6)) << 8) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 7)) << 0)))
#define EXTRACT_BE_U_2(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 0)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 1)) << 0)))
#define EXTRACT_BE_U_3(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0)))
#define EXTRACT_BE_U_4(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#define EXTRACT_BE_U_5(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0)))
#define EXTRACT_BE_U_6(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0)))
#define EXTRACT_BE_U_7(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0)))
#define EXTRACT_BE_U_8(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 56) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 7)) << 0)))

#define EXTRACT_IPV4_TO_HOST_ORDER(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#define EXTRACT_LE_S_2(p) \
	((int16_t)(((uint16_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint16_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_3(p) \
	((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_4(p) \
	((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_8(p) \
	((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 7)) << 56) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 6)) << 48) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_2(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_3(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_4(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_5(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_6(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_7(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 6)) << 48) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) |	\
		    ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_8(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 7)) << 56) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_S_1(p)	((int8_t)(*(p)))
#define EXTRACT_U_1(p)	((uint8_t)(*(p)))
#define GET_BE_S_2(p) get_be_s_2(ndo, (const u_char *)(p))
#define GET_BE_S_3(p) get_be_s_3(ndo, (const u_char *)(p))
#define GET_BE_S_4(p) get_be_s_4(ndo, (const u_char *)(p))
#define GET_BE_S_5(p) get_be_s_5(ndo, (const u_char *)(p))
#define GET_BE_S_6(p) get_be_s_6(ndo, (const u_char *)(p))
#define GET_BE_S_7(p) get_be_s_7(ndo, (const u_char *)(p))
#define GET_BE_S_8(p) get_be_s_8(ndo, (const u_char *)(p))
#define GET_BE_U_2(p) get_be_u_2(ndo, (const u_char *)(p))
#define GET_BE_U_3(p) get_be_u_3(ndo, (const u_char *)(p))
#define GET_BE_U_4(p) get_be_u_4(ndo, (const u_char *)(p))
#define GET_BE_U_5(p) get_be_u_5(ndo, (const u_char *)(p))
#define GET_BE_U_6(p) get_be_u_6(ndo, (const u_char *)(p))
#define GET_BE_U_7(p) get_be_u_7(ndo, (const u_char *)(p))
#define GET_BE_U_8(p) get_be_u_8(ndo, (const u_char *)(p))
#define GET_CPY_BYTES(dst, p, len) get_cpy_bytes(ndo, (u_char *)(dst), (const u_char *)(p), len)
#define GET_HE_S_2(p) get_he_s_2(ndo, (const u_char *)(p))
#define GET_HE_S_4(p) get_he_s_4(ndo, (const u_char *)(p))
#define GET_HE_U_2(p) get_he_u_2(ndo, (const u_char *)(p))
#define GET_HE_U_4(p) get_he_u_4(ndo, (const u_char *)(p))
#define GET_IPV4_TO_HOST_ORDER(p) get_ipv4_to_host_order(ndo, (const u_char *)(p))
#define GET_IPV4_TO_NETWORK_ORDER(p) get_ipv4_to_network_order(ndo, (const u_char *)(p))
#define GET_LE_S_2(p) get_le_s_2(ndo, (const u_char *)(p))
#define GET_LE_S_3(p) get_le_s_3(ndo, (const u_char *)(p))
#define GET_LE_S_4(p) get_le_s_4(ndo, (const u_char *)(p))
#define GET_LE_S_8(p) get_le_s_8(ndo, (const u_char *)(p))
#define GET_LE_U_2(p) get_le_u_2(ndo, (const u_char *)(p))
#define GET_LE_U_3(p) get_le_u_3(ndo, (const u_char *)(p))
#define GET_LE_U_4(p) get_le_u_4(ndo, (const u_char *)(p))
#define GET_LE_U_5(p) get_le_u_5(ndo, (const u_char *)(p))
#define GET_LE_U_6(p) get_le_u_6(ndo, (const u_char *)(p))
#define GET_LE_U_7(p) get_le_u_7(ndo, (const u_char *)(p))
#define GET_LE_U_8(p) get_le_u_8(ndo, (const u_char *)(p))
#define GET_S_1(p) get_s_1(ndo, (const u_char *)(p))
#define GET_U_1(p) get_u_1(ndo, (const u_char *)(p))
#define ND_TCHECK_1(p) ND_TCHECK_LEN((p), 1)
#define ND_TCHECK_16(p) ND_TCHECK_LEN((p), 16)
#define ND_TCHECK_2(p) ND_TCHECK_LEN((p), 2)
#define ND_TCHECK_3(p) ND_TCHECK_LEN((p), 3)
#define ND_TCHECK_4(p) ND_TCHECK_LEN((p), 4)
#define ND_TCHECK_5(p) ND_TCHECK_LEN((p), 5)
#define ND_TCHECK_6(p) ND_TCHECK_LEN((p), 6)
#define ND_TCHECK_7(p) ND_TCHECK_LEN((p), 7)
#define ND_TCHECK_8(p) ND_TCHECK_LEN((p), 8)
#define ND_TTEST_1(p) ND_TTEST_LEN((p), 1)
#define ND_TTEST_16(p) ND_TTEST_LEN((p), 16)
#define ND_TTEST_2(p) ND_TTEST_LEN((p), 2)
#define ND_TTEST_3(p) ND_TTEST_LEN((p), 3)
#define ND_TTEST_4(p) ND_TTEST_LEN((p), 4)
#define ND_TTEST_5(p) ND_TTEST_LEN((p), 5)
#define ND_TTEST_6(p) ND_TTEST_LEN((p), 6)
#define ND_TTEST_7(p) ND_TTEST_LEN((p), 7)
#define ND_TTEST_8(p) ND_TTEST_LEN((p), 8)

#define IF_PRINTER_ARGS (netdissect_options *, const struct pcap_pkthdr *, const u_char *)
#define IS_NOT_NEGATIVE(x) (((x) > 0) || ((x) == 0))
#define IS_SRC_OR_DST_PORT(p) (sport == (p) || dport == (p))
#define ND_BYTES_AVAILABLE_AFTER(p) ND_BYTES_BETWEEN(ndo->ndo_snapend, (p))
#define ND_BYTES_BETWEEN(p1, p2) ((u_int)(((const uint8_t *)(p1)) - (const uint8_t *)(p2)))
#define ND_DEBUG {printf(" [%s:%d %s] ", "__FILE__", "__LINE__", __FUNCTION__); fflush(stdout);}
#define ND_DEFAULTPRINT(ap, length) (*ndo->ndo_default_print)(ndo, ap, length)
#define ND_PRINT(...) (ndo->ndo_printf)(ndo, __VA_ARGS__)
#define ND_TCHECK_LEN(p, l) if (!ND_TTEST_LEN(p, l)) goto trunc
#define ND_TCHECK_SIZE(p) ND_TCHECK_LEN(p, sizeof(*(p)))
#define ND_TTEST_LEN(p, l) \
  (IS_NOT_NEGATIVE(l) && \
	((uintptr_t)ndo->ndo_snapend - (l) <= (uintptr_t)ndo->ndo_snapend && \
         (uintptr_t)(p) <= (uintptr_t)ndo->ndo_snapend - (l)))
#define ND_TTEST_SIZE(p) ND_TTEST_LEN(p, sizeof(*(p)))
#define PLURAL_SUFFIX(n) \
	(((n) != 1) ? "s" : "")
#define UNALIGNED_MEMCMP(p, q, l)	memcmp((p), (q), (l))
#define UNALIGNED_MEMCPY(p, q, l)	memcpy((p), (q), (l))
#define max(a,b) ((b)>(a)?(b):(a))
#define min(a,b) ((a)>(b)?(b):(a))

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6_VERSION(ip6_hdr)	((GET_U_1((ip6_hdr)->ip6_vfc) & 0xf0) >> 4)
#define IPV6_RTHDR_TYPE_0 0
#define IPV6_RTHDR_TYPE_2 2
#define IPV6_RTHDR_TYPE_4 4

#define IPOPT_RA                148             
#define IPTS_FLG(ip)	((ipt)->ipt_oflwflg & 0x0f)
#define IPTS_OFLW(ip)	(((ipt)->ipt_oflwflg & 0xf0) >> 4)
#define IP_HL(ip)	(GET_U_1((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	((GET_U_1((ip)->ip_vhl) & 0xf0) >> 4)


 #define FORMAT_STRING(p) _Printf_format_string_ p
  #define NORETURN __declspec(noreturn)
    #define NORETURN_FUNCPTR __attribute((noreturn))
  #define PRINTFLIKE(x,y) __attribute__((__format__(__printf__,x,y)))

  #define __has_attribute(x) 0

#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) 0
#define ND_IS_AT_LEAST_HP_C_VERSION(major,minor) 0
#define ND_IS_AT_LEAST_SUNC_VERSION(major,minor) 0
#define ND_IS_AT_LEAST_XL_C_VERSION(major,minor) 0
#define ND_SUNPRO_VERSION_TO_BCD(major, minor) \
	(((minor) >= 10) ? \
	    (((major) << 12) | (((minor)/10) << 8) | (((minor)%10) << 4)) : \
	    (((major) << 8) | ((minor) << 4)))

#define BUFSIZE 128
#define GET_IP6ADDR_STRING(p) get_ip6addr_string(ndo, (const u_char *)(p))
#define GET_IPADDR_STRING(p) get_ipaddr_string(ndo, (const u_char *)(p))
#define GET_LE64ADDR_STRING(p) get_le64addr_string(ndo, (const u_char *)(p))
#define DIAG_DO_PRAGMA(x) _Pragma (#x)
#define DIAG_JOINSTR(x,y) XSTRINGIFY(x ## y)
#    define DIAG_OFF(x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
#  define DIAG_OFF_CLANG(x) DIAG_OFF(x)
#    define DIAG_ON(x) DIAG_PRAGMA(pop)
#  define DIAG_ON_CLANG(x)  DIAG_ON(x)
#    define DIAG_PRAGMA(x) DIAG_DO_PRAGMA(clang diagnostic x)
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define FALSE 0
  #define FOPEN_READ_BIN   "rb"
  #define FOPEN_READ_TXT   "rt"
  #define FOPEN_WRITE_BIN  "wb"
  #define FOPEN_WRITE_TXT  "wt"





#define INET6_ADDRSTRLEN 46
#define INET_ADDRSTRLEN 16
  #define INT64_T_CONSTANT(constant)	(constant##LL)
#  define ND_FALL_THROUGH __attribute__ ((fallthrough))
  #define O_RDONLY _O_RDONLY
#define TRUE 1
#  define USES_APPLE_DEPRECATED_API DIAG_OFF(deprecated-declarations)
#  define USES_APPLE_RST DIAG_ON(deprecated-declarations)
#define XSTRINGIFY(x) #x
  #define close _close
  #define fstat _fstat
  #define htonl(x)  __ntohl(x)
  #define htons(x)  __ntohs(x)
#define inline __inline
  #define isatty _isatty

  #define ntohl(x)  __ntohl(x)
  #define ntohs(x)  __ntohs(x)
  #define open _open
  #define read _read
  #define stat _stat
    #define strdup _strdup
  #define _U_ __attribute__((unused))

