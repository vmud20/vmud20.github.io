



#include<netinet/in.h>




#include<inttypes.h>







#include<stdbool.h>










#include<netinet/ip.h>


#include<netinet/udp.h>
#include<net/if.h>
#include<netinet/tcp.h>












#define DNS_STREAM_WRITE_TLS_DATA 1
#define DNSTLS_STREAM_CLOSED 1
#define DNS_TRANSACTION_ATTEMPTS_MAX 24
#define DNS_TRANSACTION_IS_LIVE(state) IN_SET((state), DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_VALIDATING)
#define LLMNR_JITTER_INTERVAL_USEC (100 * USEC_PER_MSEC)
#define LLMNR_TRANSACTION_ATTEMPTS_MAX 3
#define MDNS_JITTER_MIN_USEC   (20 * USEC_PER_MSEC)
#define MDNS_JITTER_RANGE_USEC (100 * USEC_PER_MSEC)
#define MDNS_PROBING_INTERVAL_USEC (250 * USEC_PER_MSEC)
#define MDNS_TRANSACTION_ATTEMPTS_MAX 3
#define TRANSACTION_ATTEMPTS_MAX(p) (((p) == DNS_PROTOCOL_LLMNR) ? \
                                         LLMNR_TRANSACTION_ATTEMPTS_MAX : \
                                         (((p) == DNS_PROTOCOL_MDNS) ? \
                                             MDNS_TRANSACTION_ATTEMPTS_MAX : \
                                             DNS_TRANSACTION_ATTEMPTS_MAX))
#define DNS_SERVER_FEATURE_LEVEL_BEST (_DNS_SERVER_FEATURE_LEVEL_MAX - 1)
#define DNS_SERVER_FEATURE_LEVEL_IS_TLS(x) IN_SET(x, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN, DNS_SERVER_FEATURE_LEVEL_TLS_DO)
#define DNS_SERVER_FEATURE_LEVEL_WORST 0
#define EXTRA_CMSG_SPACE 1024
#define MANAGER_DNS_SERVERS_MAX 32
#define MANAGER_SEARCH_DOMAINS_MAX 32
#define LINK_DNS_SERVERS_MAX 32
#define LINK_SEARCH_DOMAINS_MAX 32
#define LLMNR_DEFAULT_TTL (30)
#define MDNS_DEFAULT_TTL (120)
#define DNSKEY_FLAG_REVOKE   (UINT16_C(1) << 7)
#define DNSKEY_FLAG_SEP      (UINT16_C(1) << 0)
#define DNSKEY_FLAG_ZONE_KEY (UINT16_C(1) << 8)
#define DNS_RESOURCE_KEY_CONST(c, t, n)                 \
        ((DnsResourceKey) {                             \
                .n_ref = (unsigned) -1,                 \
                .class = c,                             \
                .type = t,                              \
                ._name = (char*) n,                     \
        })
#define DNS_RESOURCE_KEY_STRING_MAX (_DNS_CLASS_STRING_MAX + _DNS_TYPE_STRING_MAX + DNS_HOSTNAME_MAX + 1)
#define MDNS_RR_CACHE_FLUSH  (UINT16_C(1) << 15)
#define CAA_FLAG_CRITICAL (1u << 7)
#define _DNS_CLASS_STRING_MAX (sizeof "CLASS" + DECIMAL_STR_MAX(uint16_t))
#define _DNS_TYPE_STRING_MAX (sizeof "CLASS" + DECIMAL_STR_MAX(uint16_t))
#define DNS_QUESTION_FOREACH(key, q) _DNS_QUESTION_FOREACH(UNIQ, key, q)
#define _DNS_QUESTION_FOREACH(u, key, q)                                \
        for (size_t UNIQ_T(i, u) = ({                                 \
                                (key) = ((q) && (q)->n_keys > 0) ? (q)->keys[0] : NULL; \
                                0;                                      \
                        });                                             \
             (q) && (UNIQ_T(i, u) < (q)->n_keys);                       \
             UNIQ_T(i, u)++, (key) = (UNIQ_T(i, u) < (q)->n_keys ? (q)->keys[UNIQ_T(i, u)] : NULL))
#define DNS_ANSWER_FOREACH(kk, a) _DNS_ANSWER_FOREACH(UNIQ, kk, a)
#define DNS_ANSWER_FOREACH_FLAGS(kk, flags, a) _DNS_ANSWER_FOREACH_FLAGS(UNIQ, kk, flags, a)
#define DNS_ANSWER_FOREACH_FULL(kk, ifindex, flags, a) _DNS_ANSWER_FOREACH_FULL(UNIQ, kk, ifindex, flags, a)
#define DNS_ANSWER_FOREACH_IFINDEX(kk, ifindex, a) _DNS_ANSWER_FOREACH_IFINDEX(UNIQ, kk, ifindex, a)
#define _DNS_ANSWER_FOREACH(q, kk, a)                                   \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++, (kk) = (UNIQ_T(i, q) < (a)->n_rrs ? (a)->items[UNIQ_T(i, q)].rr : NULL))
#define _DNS_ANSWER_FOREACH_FLAGS(q, kk, fl, a)                         \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (fl) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].flags : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++,                                            \
                     (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), \
                     (fl) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].flags : 0))
#define _DNS_ANSWER_FOREACH_FULL(q, kk, ifi, fl, a)                     \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (ifi) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].ifindex : 0; \
                                (fl) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].flags : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++,                                            \
                     (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), \
                     (ifi) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].ifindex : 0), \
                     (fl) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].flags : 0))
#define _DNS_ANSWER_FOREACH_IFINDEX(q, kk, ifi, a)                      \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (ifi) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].ifindex : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++,                                            \
                     (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), \
                     (ifi) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].ifindex : 0))
#define DNS_PACKET_AA(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 10) & 1)
#define DNS_PACKET_AD(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 5) & 1)
#define DNS_PACKET_ANCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->ancount)
#define DNS_PACKET_ARCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->arcount)
#define DNS_PACKET_CD(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 4) & 1)
#define DNS_PACKET_FLAG_TC (UINT16_C(1) << 9)
#define DNS_PACKET_HEADER(p) ((DnsPacketHeader*) DNS_PACKET_DATA(p))
#define DNS_PACKET_HEADER_SIZE sizeof(DnsPacketHeader)
#define DNS_PACKET_ID(p) DNS_PACKET_HEADER(p)->id
#define DNS_PACKET_LLMNR_C(p) DNS_PACKET_AA(p)
#define DNS_PACKET_LLMNR_T(p) DNS_PACKET_RD(p)
#define DNS_PACKET_MAKE_FLAGS(qr, opcode, aa, tc, rd, ra, ad, cd, rcode) \
        (((uint16_t) !!(qr) << 15) |                                    \
         ((uint16_t) ((opcode) & 15) << 11) |                           \
         ((uint16_t) !!(aa) << 10) |                   \
         ((uint16_t) !!(tc) << 9) |                                     \
         ((uint16_t) !!(rd) << 8) |                    \
         ((uint16_t) !!(ra) << 7) |                                     \
         ((uint16_t) !!(ad) << 5) |                                     \
         ((uint16_t) !!(cd) << 4) |                                     \
         ((uint16_t) ((rcode) & 15)))
#define DNS_PACKET_NSCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->nscount)
#define DNS_PACKET_OPCODE(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 11) & 15)
#define DNS_PACKET_QDCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->qdcount)
#define DNS_PACKET_QR(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 15) & 1)
#define DNS_PACKET_RA(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 7) & 1)
#define DNS_PACKET_RD(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 8) & 1)
#define DNS_PACKET_SIZE_MAX 0xFFFFu
#define DNS_PACKET_SIZE_START 512u
#define DNS_PACKET_TC(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 9) & 1)
#define DNS_PACKET_UNICAST_SIZE_LARGE_MAX 4096u
#define DNS_PACKET_UNICAST_SIZE_MAX 512u
#define LLMNR_MULTICAST_IPV4_ADDRESS ((struct in_addr) { .s_addr = htobe32(224U << 24 | 252U) })
#define LLMNR_MULTICAST_IPV6_ADDRESS ((struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 } })
#define MDNS_MULTICAST_IPV4_ADDRESS  ((struct in_addr) { .s_addr = htobe32(224U << 24 | 251U) })
#define MDNS_MULTICAST_IPV6_ADDRESS  ((struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb } })
#define UDP_PACKET_HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
#define INADDR_DNS_STUB ((in_addr_t) 0x7f000035U)
#define SD_RESOLVED_AUTHENTICATED (UINT64_C(1) << 9)
#define SD_RESOLVED_DNS           (UINT64_C(1) << 0)
#define SD_RESOLVED_LLMNR         (SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_LLMNR_IPV6)
#define SD_RESOLVED_LLMNR_IPV4    (UINT64_C(1) << 1)
#define SD_RESOLVED_LLMNR_IPV6    (UINT64_C(1) << 2)
#define SD_RESOLVED_MDNS          (SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6)
#define SD_RESOLVED_MDNS_IPV4     (UINT64_C(1) << 3)
#define SD_RESOLVED_MDNS_IPV6     (UINT64_C(1) << 4)
#define SD_RESOLVED_NO_ADDRESS    (UINT64_C(1) << 7)
#define SD_RESOLVED_NO_CNAME      (UINT64_C(1) << 5)
#define SD_RESOLVED_NO_SEARCH     (UINT64_C(1) << 8)
#define SD_RESOLVED_NO_TXT        (UINT64_C(1) << 6)
#define SD_RESOLVED_PROTOCOLS_ALL (SD_RESOLVED_MDNS|SD_RESOLVED_LLMNR|SD_RESOLVED_DNS)
#define SD_RESOLVED_QUERY_TIMEOUT_USEC (120 * USEC_PER_SEC)
#define DNSSEC_CANONICAL_HOSTNAME_MAX (DNS_HOSTNAME_MAX + 2)
#define DNSSEC_HASH_SIZE_MAX (MAX(20, 32))
