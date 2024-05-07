#include<time.h>
#include<arpa/inet.h>
#include<stdint.h>



#include<fcntl.h>
#include<stdio.h>
#include<netinet/tcp.h>

#include<inttypes.h>
#include<sys/sysinfo.h>
#include<sys/types.h>
#include<signal.h>
#include<string.h>


#include<stdbool.h>
#include<stdlib.h>

#include<linux/limits.h>
#include<pthread.h>
#include<errno.h>

#include<unwind.h>
#include<sys/time.h>
#include<sys/stat.h>


#include<unistd.h>
#include<linux/rtnetlink.h>
#include<netdb.h>

#include<linux/capability.h>
#include<stddef.h>

#include<sys/prctl.h>


#include<sys/socket.h>
#include<stdarg.h>
#include<sys/statvfs.h>
#include<libgen.h>
#include<ctype.h>
#include<linux/netlink.h>
#include<dlfcn.h>
#define BASE_FILE_NAME (__builtin_strrchr("__FILE__", '/') ? __builtin_strrchr("__FILE__", '/') + 1 : "__FILE__")
#define BUG(format, ...) bug_ext(BASE_FILE_NAME, "__LINE__", __func__, format, ##__VA_ARGS__)
#define MAX_IP_LEN 64
#define PORT_NOT_DEFINED -1

#define TCP_FASTOPEN 23
#define TCP_FASTOPEN_CONNECT 30
#define TCP_THIN_DUPACK 17
#define TCP_THIN_LINEAR_TIMEOUTS 16


#define TLOG_MAX_LINE_LEN (1024)
#define TLOG_MULTI_WRITE (1 << 2)
#define TLOG_NOCOMPRESS (1 << 0)
#define TLOG_NONBLOCK (1 << 3)
#define TLOG_SCREEN (1 << 4)
#define TLOG_SEGMENT (1 << 1)
#define TLOG_SUPPORT_FORK (1 << 5)
#define Tlog_stream(level)        \
    if (tlog_getlevel() <= level) \
    Tlog(level, BASE_FILE_NAME, "__LINE__", __func__, NULL).Stream()
#define tlog(level, format, ...) tlog_ext(level, BASE_FILE_NAME, "__LINE__", __func__, NULL, format, ##__VA_ARGS__)
#define tlog_debug Tlog_stream(TLOG_DEBUG)
#define tlog_error Tlog_stream(TLOG_ERROR)
#define tlog_fatal Tlog_stream(TLOG_FATAL)
#define tlog_info Tlog_stream(TLOG_INFO)
#define tlog_notice Tlog_stream(TLOG_NOTICE)
#define tlog_out(stream) TlogOut(stream).Stream()
#define tlog_warn Tlog_stream(TLOG_WARN)
#define BIND_FLAG_FORCE_AAAA_SOA (1 << 8)
#define BIND_FLAG_NO_CACHE (1 << 6)
#define BIND_FLAG_NO_DUALSTACK_SELECTION (1 << 7)
#define BIND_FLAG_NO_RULE_ADDR (1 << 0)
#define BIND_FLAG_NO_RULE_CNAME (1 << 9)
#define BIND_FLAG_NO_RULE_IPSET (1 << 2)
#define BIND_FLAG_NO_RULE_NAMESERVER (1 << 1)
#define BIND_FLAG_NO_RULE_SNIPROXY (1 << 3)
#define BIND_FLAG_NO_RULE_SOA (1 << 4)
#define BIND_FLAG_NO_SPEED_CHECK (1 << 5)
#define DEFAULT_DNS_HTTPS_PORT 443
#define DEFAULT_DNS_PORT 53
#define DEFAULT_DNS_TLS_PORT 853
#define DNS_CONF_USERNAME_LEN 32
#define DNS_GROUP_NAME_LEN 32
#define DNS_MAX_BIND_IP 16
#define DNS_MAX_CONF_CNAME_LEN 256
#define DNS_MAX_IPLEN 64
#define DNS_MAX_IPSET_NAMELEN 32
#define DNS_MAX_NFTSET_FAMILYLEN 8
#define DNS_MAX_NFTSET_NAMELEN 256
#define DNS_MAX_PATH 1024
#define DNS_MAX_PTR_LEN 128
#define DNS_MAX_SERVERS 64
#define DNS_MAX_SERVER_NAME_LEN 128
#define DNS_MAX_SPKI_LEN 64
#define DNS_MAX_URL_LEN 256
#define DNS_NAX_GROUP_NUMBER 16
#define DNS_PROXY_MAX_LEN 128
#define DOMAIN_FLAG_ADDR_IGN (1 << 3)
#define DOMAIN_FLAG_ADDR_IPV4_IGN (1 << 4)
#define DOMAIN_FLAG_ADDR_IPV4_SOA (1 << 1)
#define DOMAIN_FLAG_ADDR_IPV6_IGN (1 << 5)
#define DOMAIN_FLAG_ADDR_IPV6_SOA (1 << 2)
#define DOMAIN_FLAG_ADDR_SOA (1 << 0)
#define DOMAIN_FLAG_CNAME_IGN (1 << 16)
#define DOMAIN_FLAG_DUALSTACK_SELECT (1 << 10)
#define DOMAIN_FLAG_IPSET_IGN (1 << 6)
#define DOMAIN_FLAG_IPSET_IPV4_IGN (1 << 7)
#define DOMAIN_FLAG_IPSET_IPV6_IGN (1 << 8)
#define DOMAIN_FLAG_NAMESERVER_IGNORE (1 << 9)
#define DOMAIN_FLAG_NFTSET_INET_IGN (1 << 12)
#define DOMAIN_FLAG_NFTSET_IP6_IGN (1 << 14)
#define DOMAIN_FLAG_NFTSET_IP_IGN (1 << 13)
#define DOMAIN_FLAG_NO_CACHE (1 << 17)
#define DOMAIN_FLAG_NO_SERVE_EXPIRED (1 << 15)
#define DOMAIN_FLAG_SMARTDNS_DOMAIN (1 << 11)
#define PROXY_MAX_SERVERS 128
#define PROXY_NAME_LEN 32
#define SERVER_FLAG_EXCLUDE_DEFAULT (1 << 0)
#define SMARTDNS_AUDIT_FILE "/var/log/smartdns/smartdns-audit.log"
#define SMARTDNS_CACHE_FILE "/tmp/smartdns.cache"
#define SMARTDNS_CONF_FILE "/etc/smartdns/smartdns.conf"
#define SMARTDNS_DEBUG_DIR "/tmp/smartdns"
#define SMARTDNS_LOG_FILE "/var/log/smartdns/smartdns.log"

#define RADIX_MAXBITS 128
#define RADIX_WALK(Xhead, Xnode) \
	do { \
		radix_node_t *Xstack[RADIX_MAXBITS+1]; \
		radix_node_t **Xsp = Xstack; \
		radix_node_t *Xrn = (Xhead); \
		while ((Xnode = Xrn)) { \
			if (Xnode->prefix)
#define RADIX_WALK_END \
			if (Xrn->l) { \
				if (Xrn->r) { \
					*Xsp++ = Xrn->r; \
				} \
				Xrn = Xrn->l; \
			} else if (Xrn->r) { \
				Xrn = Xrn->r; \
			} else if (Xsp != Xstack) { \
				Xrn = *(--Xsp); \
			} else { \
				Xrn = (radix_node_t *) 0; \
			} \
		} \
	} while (0)

# define snprintf _snprintf
#define PROXY_MAX_IPLEN 256
#define PROXY_MAX_NAMELEN 128

#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_POISON1  ((void *) 0x100)
#define LIST_POISON2  ((void *) 0x200)

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))
#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_prev_entry(n, member))
#define list_for_each_from(pos, head) \
	for (; pos != (head); pos = pos->next)
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
#define list_safe_reset_next(pos, n, member)				\
	n = list_next_entry(pos, member)
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]
#define DEFINE_HASHTABLE(name, bits)						\
	struct hlist_head name[1 << (bits)] =					\
			{ [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }
#define HASH_BITS(name) ilog2(HASH_SIZE(name))
#define HASH_SIZE(name) (ARRAY_SIZE(name))

#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define hash_add(hashtable, node, key)						\
	hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])
#define hash_empty(hashtable) __hash_empty(hashtable, HASH_SIZE(hashtable))
#define hash_for_each(name, bkt, obj, member)				\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry(obj, &name[bkt], member)
#define hash_for_each_possible(name, obj, member, key)			\
	hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_possible_safe(name, obj, tmp, member, key)	\
	hlist_for_each_entry_safe(obj, tmp,\
		&name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_safe(name, bkt, tmp, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)
#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))
#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))
#define BITS_PER_LONG __WORDSIZE
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_32

#define __WORDSIZE (__SIZEOF_LONG__ * 8)
#define __hash_32 __hash_32_generic
#define hash_32 hash_32_generic
#define hash_64 hash_64_generic
#define hash_long(val, bits) hash_32(val, bits)
#define ilog2(n)                                                                                                       \
	(__builtin_constant_p(n) ? ((n) < 2              ? 0                                                               \
								: (n) & (1ULL << 63) ? 63                                                              \
								: (n) & (1ULL << 62) ? 62                                                              \
								: (n) & (1ULL << 61) ? 61                                                              \
								: (n) & (1ULL << 60) ? 60                                                              \
								: (n) & (1ULL << 59) ? 59                                                              \
								: (n) & (1ULL << 58) ? 58                                                              \
								: (n) & (1ULL << 57) ? 57                                                              \
								: (n) & (1ULL << 56) ? 56                                                              \
								: (n) & (1ULL << 55) ? 55                                                              \
								: (n) & (1ULL << 54) ? 54                                                              \
								: (n) & (1ULL << 53) ? 53                                                              \
								: (n) & (1ULL << 52) ? 52                                                              \
								: (n) & (1ULL << 51) ? 51                                                              \
								: (n) & (1ULL << 50) ? 50                                                              \
								: (n) & (1ULL << 49) ? 49                                                              \
								: (n) & (1ULL << 48) ? 48                                                              \
								: (n) & (1ULL << 47) ? 47                                                              \
								: (n) & (1ULL << 46) ? 46                                                              \
								: (n) & (1ULL << 45) ? 45                                                              \
								: (n) & (1ULL << 44) ? 44                                                              \
								: (n) & (1ULL << 43) ? 43                                                              \
								: (n) & (1ULL << 42) ? 42                                                              \
								: (n) & (1ULL << 41) ? 41                                                              \
								: (n) & (1ULL << 40) ? 40                                                              \
								: (n) & (1ULL << 39) ? 39                                                              \
								: (n) & (1ULL << 38) ? 38                                                              \
								: (n) & (1ULL << 37) ? 37                                                              \
								: (n) & (1ULL << 36) ? 36                                                              \
								: (n) & (1ULL << 35) ? 35                                                              \
								: (n) & (1ULL << 34) ? 34                                                              \
								: (n) & (1ULL << 33) ? 33                                                              \
								: (n) & (1ULL << 32) ? 32                                                              \
								: (n) & (1ULL << 31) ? 31                                                              \
								: (n) & (1ULL << 30) ? 30                                                              \
								: (n) & (1ULL << 29) ? 29                                                              \
								: (n) & (1ULL << 28) ? 28                                                              \
								: (n) & (1ULL << 27) ? 27                                                              \
								: (n) & (1ULL << 26) ? 26                                                              \
								: (n) & (1ULL << 25) ? 25                                                              \
								: (n) & (1ULL << 24) ? 24                                                              \
								: (n) & (1ULL << 23) ? 23                                                              \
								: (n) & (1ULL << 22) ? 22                                                              \
								: (n) & (1ULL << 21) ? 21                                                              \
								: (n) & (1ULL << 20) ? 20                                                              \
								: (n) & (1ULL << 19) ? 19                                                              \
								: (n) & (1ULL << 18) ? 18                                                              \
								: (n) & (1ULL << 17) ? 17                                                              \
								: (n) & (1ULL << 16) ? 16                                                              \
								: (n) & (1ULL << 15) ? 15                                                              \
								: (n) & (1ULL << 14) ? 14                                                              \
								: (n) & (1ULL << 13) ? 13                                                              \
								: (n) & (1ULL << 12) ? 12                                                              \
								: (n) & (1ULL << 11) ? 11                                                              \
								: (n) & (1ULL << 10) ? 10                                                              \
								: (n) & (1ULL << 9)  ? 9                                                               \
								: (n) & (1ULL << 8)  ? 8                                                               \
								: (n) & (1ULL << 7)  ? 7                                                               \
								: (n) & (1ULL << 6)  ? 6                                                               \
								: (n) & (1ULL << 5)  ? 5                                                               \
								: (n) & (1ULL << 4)  ? 4                                                               \
								: (n) & (1ULL << 3)  ? 3                                                               \
								: (n) & (1ULL << 2)  ? 2                                                               \
													 : 1)                                                               \
	 : (sizeof(n) <= 4)      ? __ilog2_u32(n)                                                                          \
							 : __ilog2_u64(n))

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}
#define jhash_mask(n)   (jhash_size(n)-1)
#define jhash_size(n)   ((uint32_t)1<<(n))
#define BITS_TO_BYTES(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_TO_U32(nr)		DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u32))
#define BITS_TO_U64(nr)		DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u64))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

#define ffz(x)  __ffs(~(x))
#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_first_zero_bit((addr), (size));       \
	     (bit) < (size);                                    \
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

# define __attribute_const__
# define __compiletime_error(message)
# define __fallthrough
# define __force
# define __init
# define __packed		__attribute__((__packed__))


#define __round_mask(x, y) ((__typeof__(x))((y)-1))

#define barrier() __asm__ __volatile__("": : :"memory")
# define likely(x)		__builtin_expect(!!(x), 1)
#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
# define noinline
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define roundup(x, y) (                                \
{                                                      \
	const typeof(y) __y = y;		       \
	(((x) + (__y - 1)) / __y) * __y;	       \
}                                                      \
)
#define uninitialized_var(x) x = *(&(x))
# define unlikely(x)		__builtin_expect(!!(x), 0)
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits)					\
(									\
	((nbits) % BITS_PER_LONG) ?					\
		(1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL		\
)
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

#define DNSSERVER_FLAG_BLACKLIST_IP (0x1 << 0)
#define DNSSERVER_FLAG_CHECK_EDNS (0x1 << 2)
#define DNSSERVER_FLAG_CHECK_TTL (0x1 << 3)
#define DNSSERVER_FLAG_WHITELIST_IP (0x1 << 1)
#define DNS_QUEY_OPTION_ECS_DNS (1 << 0)
#define DNS_QUEY_OPTION_ECS_IP (1 << 1)
#define DNS_SERVER_GROUP_DEFAULT "default"
#define DNS_SERVER_SPKI_LEN 64

#define DNS_ADDR_FAMILY_IP 1
#define DNS_ADDR_FAMILY_IPV6 2
#define DNS_DEFAULT_PACKET_SIZE 512
#define DNS_IN_PACKSIZE (512 * 8)
#define DNS_MAX_CNAME_LEN 256
#define DNS_MAX_OPT_LEN 256
#define DNS_OPT_ECS_FAMILY_IPV4 1
#define DNS_OPT_ECS_FAMILY_IPV6 2
#define DNS_PACKET_DICT_SIZE 16
#define DNS_PACKSIZE (512 * 12)
#define DNS_RR_AAAA_LEN 16
#define DNS_RR_A_LEN 4

#define CONF_CUSTOM(key, func, data)                                                                                   \
	{                                                                                                                  \
		key, conf_custom, &(struct config_item_custom)                                                                 \
		{                                                                                                              \
			.custom_data = data, .custom_func = func                                                                   \
		}                                                                                                              \
	}
#define CONF_END()                                                                                                     \
	{                                                                                                                  \
		NULL, NULL, NULL                                                                                               \
	}
#define CONF_ENUM(key, value, enum)                                                                                    \
	{                                                                                                                  \
		key, conf_enum, &(struct config_enum)                                                                          \
		{                                                                                                              \
			.data = (int *)value, .list = (struct config_enum_list *)enum                                              \
		}                                                                                                              \
	}
#define CONF_INT(key, value, min_value, max_value)                                                                     \
	{                                                                                                                  \
		key, conf_int, &(struct config_item_int)                                                                       \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value                                                          \
		}                                                                                                              \
	}
#define CONF_INT_BASE(key, value, min_value, max_value, base_value)                                                    \
	{                                                                                                                  \
		key, conf_int_base, &(struct config_item_int_base)                                                             \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value, .base = base_value                                      \
		}                                                                                                              \
	}
#define CONF_INT_MAX (~(1 << 31))
#define CONF_INT_MIN (1 << 31)
#define CONF_RET_BADCONF -4
#define CONF_RET_ERR -1
#define CONF_RET_NOENT -3
#define CONF_RET_OK 0
#define CONF_RET_WARN -2
#define CONF_SIZE(key, value, min_value, max_value)                                                                    \
	{                                                                                                                  \
		key, conf_size, &(struct config_item_size)                                                                     \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value                                                          \
		}                                                                                                              \
	}
#define CONF_SSIZE(key, value, min_value, max_value)                                                                    \
	{                                                                                                                  \
		key, conf_ssize, &(struct config_item_ssize)                                                                     \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value                                                          \
		}                                                                                                              \
	}
#define CONF_STRING(key, value, len_value)                                                                             \
	{                                                                                                                  \
		key, conf_string, &(struct config_item_string)                                                                 \
		{                                                                                                              \
			.data = value, .size = len_value                                                                           \
		}                                                                                                              \
	}
#define CONF_YESNO(key, value)                                                                                         \
	{                                                                                                                  \
		key, conf_yesno, &(struct config_item_yesno)                                                                   \
		{                                                                                                              \
			.data = value                                                                                              \
		}                                                                                                              \
	}
#define MAX_KEY_LEN 64
#define MAX_LINE_LEN 8192

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define ATOMIC_INIT(i)  { (i) }
#define READ_ONCE(x) \
({ typeof(x) ___x = ACCESS_ONCE(x); ___x; })


#  define BROKEN_GCC_C99_INLINE
#define MAX_PREFIX_LEN 10
#define NODE16  2
#define NODE256 4
#define NODE4   1
#define NODE48  3
# define art_size(t) ((t)->size)
#define destroy_art_tree(...) art_tree_destroy(__VA_ARGS__)
#define init_art_tree(...) art_tree_init(__VA_ARGS__)
