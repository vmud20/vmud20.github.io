#include<sys/queue.h>
#include<sys/types.h>

#include<sys/cdefs.h>







#include<netinet/icmp6.h>











#include<netinet/in.h>

#include<sys/uio.h>

#include<netinet/ip6.h>


#include<net/route.h>


#include<sys/time.h>
#define ACTION_SET(a, x) \
	do { \
		if ((a) != NULL) \
			*(a) = (x); \
	} while (0)
#define DIOCRCLRASTATS  _IOWR('D', 72, struct pfioc_table)
#define DIOCRCLRTSTATS  _IOWR('D', 65, struct pfioc_table)
#define DIOCSETSTATUSIF _IOWR('D', 20, struct pfioc_iface)
#define DIOCXBEGIN      _IOWR('D', 81, struct pfioc_trans)
#define DIOCXCOMMIT     _IOWR('D', 82, struct pfioc_trans)
#define DIOCXROLLBACK   _IOWR('D', 83, struct pfioc_trans)
#define LCNT_NAMES { \
	"max states per rule", \
	"max-src-states", \
	"max-src-nodes", \
	"max-src-conn", \
	"max-src-conn-rate", \
	"overload table insertion", \
	"overload flush states", \
	NULL \
}
#define PFOTHERS_NAMES { \
	"NO_TRAFFIC", \
	"SINGLE", \
	"MULTIPLE", \
	NULL \
}
#define PFRES_IPOPTIONS 8		
#define PFRES_NAMES { \
	"match", \
	"bad-offset", \
	"fragment", \
	"short", \
	"normalize", \
	"memory", \
	"bad-timestamp", \
	"congestion", \
	"ip-option", \
	"proto-cksum", \
	"state-mismatch", \
	"state-insert", \
	"state-limit", \
	"src-limit", \
	"synproxy", \
	"translate", \
	"no-route", \
	NULL \
}
#define PFRES_PROTCKSUM 9		
#define PFUDPS_NAMES { \
	"NO_TRAFFIC", \
	"SINGLE", \
	"MULTIPLE", \
	NULL \
}
#define PF_ACPY(a, b, f) \
	pf_addrcpy(a, b, f)
#define PF_AEQ(a, b, c) \
	((c == AF_INET && (a)->addr32[0] == (b)->addr32[0]) || \
	(c == AF_INET6 && \
	(a)->addr32[3] == (b)->addr32[3] && \
	(a)->addr32[2] == (b)->addr32[2] && \
	(a)->addr32[1] == (b)->addr32[1] && \
	(a)->addr32[0] == (b)->addr32[0])) \

#define PF_AINC(a, f) \
	pf_addr_inc(a, f)
#define PF_ALGNMNT(off) (((off) % 2) == 0 ? PF_HI : PF_LO)
#define PF_ANEQ(a, b, c) \
	((c == AF_INET && (a)->addr32[0] != (b)->addr32[0]) || \
	(c == AF_INET6 && \
	((a)->addr32[3] != (b)->addr32[3] || \
	(a)->addr32[2] != (b)->addr32[2] || \
	(a)->addr32[1] != (b)->addr32[1] || \
	(a)->addr32[0] != (b)->addr32[0]))) \

#define PF_AZERO(a, c) \
	((c == AF_INET && !(a)->addr32[0]) || \
	(c == AF_INET6 && \
	!(a)->addr32[0] && !(a)->addr32[1] && \
	!(a)->addr32[2] && !(a)->addr32[3] )) \

#define PF_DEBUGNAME "pf: "
#define PF_HI (true)
#define PF_LO (!PF_HI)
#define PF_MATCHA(n, a, m, b, f) \
	pf_match_addr(n, a, m, b, f)
#define PF_OSFP_ENTRY_EQ(a, b) \
    ((a)->fp_os == (b)->fp_os && \
    memcmp((a)->fp_class_nm, (b)->fp_class_nm, PF_OSFP_LEN) == 0 && \
    memcmp((a)->fp_version_nm, (b)->fp_version_nm, PF_OSFP_LEN) == 0 && \
    memcmp((a)->fp_subtype_nm, (b)->fp_subtype_nm, PF_OSFP_LEN) == 0)
#define PF_OSFP_MAX_OPTS \
    (sizeof(((struct pf_os_fingerprint *)0)->fp_tcpopts) * 8) \
    / PF_OSFP_TCPOPT_BITS
#define PF_OSFP_PACK(osfp, class, version, subtype) do { \
	(osfp) = ((class) & ((1 << _FP_CLASS_BITS) - 1)) << (_FP_VERSION_BITS \
	    + _FP_SUBTYPE_BITS); \
	(osfp) |= ((version) & ((1 << _FP_VERSION_BITS) - 1)) << \
	    _FP_SUBTYPE_BITS; \
	(osfp) |= (subtype) & ((1 << _FP_SUBTYPE_BITS) - 1); \
} while(0)
#define PF_OSFP_UNPACK(osfp, class, version, subtype) do { \
	(class) = ((osfp) >> (_FP_VERSION_BITS+_FP_SUBTYPE_BITS)) & \
	    ((1 << _FP_CLASS_BITS) - 1); \
	(version) = ((osfp) >> _FP_SUBTYPE_BITS) & \
	    ((1 << _FP_VERSION_BITS) - 1);\
	(subtype) = (osfp) & ((1 << _FP_SUBTYPE_BITS) - 1); \
} while(0)
#define PF_POOLMASK(a, b, c, d, f) \
	pf_poolmask(a, b, c, d, f)
#define PF_POOL_DYNTYPE(_o)						\
	((((_o) & PF_POOL_TYPEMASK) == PF_POOL_ROUNDROBIN) ||		\
	(((_o) & PF_POOL_TYPEMASK) == PF_POOL_LEASTSTATES) ||		\
	(((_o) & PF_POOL_TYPEMASK) == PF_POOL_RANDOM) ||		\
	(((_o) & PF_POOL_TYPEMASK) == PF_POOL_SRCHASH))
#define PF_REVERSED_KEY(key, family)				\
	((key[PF_SK_WIRE]->af != key[PF_SK_STACK]->af) &&	\
	 (key[PF_SK_WIRE]->af != (family)))
#define REASON_SET(a, x) \
	do { \
		if ((void *)(a) != NULL) { \
			*(a) = (x); \
			if (x < PFRES_MAX) \
				pf_status.counters[x]++; \
		} \
	} while (0)

#define pf_state_counter_from_pfsync(s)				\
	(((u_int64_t)(s[0])<<32) | (u_int64_t)(s[1]))
#define pf_state_counter_hton(s,d) do {				\
	d[0] = htonl((s>>32)&0xffffffff);			\
	d[1] = htonl(s&0xffffffff);				\
} while (0)
#define pf_state_counter_ntoh(s,d) do {				\
	d = ntohl(s[0]);					\
	d = d<<32;						\
	d += ntohl(s[1]);					\
} while (0)
#define pf_state_peer_hton(s,d) do {		\
	(d)->seqlo = htonl((s)->seqlo);		\
	(d)->seqhi = htonl((s)->seqhi);		\
	(d)->seqdiff = htonl((s)->seqdiff);	\
	(d)->max_win = htons((s)->max_win);	\
	(d)->mss = htons((s)->mss);		\
	(d)->state = (s)->state;		\
	(d)->wscale = (s)->wscale;		\
	if ((s)->scrub) {						\
		(d)->scrub.pfss_flags =					\
		    htons((s)->scrub->pfss_flags & PFSS_TIMESTAMP);	\
		(d)->scrub.pfss_ttl = (s)->scrub->pfss_ttl;		\
		(d)->scrub.pfss_ts_mod = htonl((s)->scrub->pfss_ts_mod);\
		(d)->scrub.scrub_flag = PFSYNC_SCRUB_FLAG_VALID;	\
	}								\
} while (0)
#define pf_state_peer_ntoh(s,d) do {		\
	(d)->seqlo = ntohl((s)->seqlo);		\
	(d)->seqhi = ntohl((s)->seqhi);		\
	(d)->seqdiff = ntohl((s)->seqdiff);	\
	(d)->max_win = ntohs((s)->max_win);	\
	(d)->mss = ntohs((s)->mss);		\
	(d)->state = (s)->state;		\
	(d)->wscale = (s)->wscale;		\
	if ((s)->scrub.scrub_flag == PFSYNC_SCRUB_FLAG_VALID &&		\
	    (d)->scrub != NULL) {					\
		(d)->scrub->pfss_flags =				\
		    ntohs((s)->scrub.pfss_flags) & PFSS_TIMESTAMP;	\
		(d)->scrub->pfss_ttl = (s)->scrub.pfss_ttl;		\
		(d)->scrub->pfss_ts_mod = ntohl((s)->scrub.pfss_ts_mod);\
	}								\
} while (0)
#define ROUTE_FILTER(m)	(1 << (m))
#define ROUTE_TABLEFILTER 2	

#define	 rtalloc_mpath(dst, s, rid) rtalloc((dst), RT_RESOLVE, (rid))

#define RWLOCK_INITIALIZER(name)	{ 0, name }
#define RWLOCK_OWNER(rwl)	((struct proc *)((rwl)->rwl_owner & ~RWLOCK_MASK))

#define rw_assert_rdlock(rwl)	((void)0)
#define rw_assert_unlocked(rwl)	((void)0)
#define rw_assert_wrlock(rwl)	((void)0)
#define rm_leaf rm_rmu.rmu_leaf		
#define rm_mask rm_rmu.rmu_mask
#define rn_dupedkey rn_u.rn_leaf.rn_Dupedkey
#define rn_key rn_u.rn_leaf.rn_Key
#define rn_l rn_u.rn_node.rn_L
#define rn_mask rn_u.rn_leaf.rn_Mask
#define rn_off rn_u.rn_node.rn_Off
#define rn_r rn_u.rn_node.rn_R
#define LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;				\
	struct type **le_prev;		\
}
#define LIST_FOREACH(var, head, field)					\
	for((var) = LIST_FIRST(head);					\
	    (var)!= LIST_END(head);					\
	    (var) = LIST_NEXT(var, field))
#define LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;				\
}
#define LIST_HEAD_INITIALIZER(head)					\
	{ NULL }
#define LIST_INSERT_AFTER(listelm, elm, field) do {			\
	if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)	\
		(listelm)->field.le_next->field.le_prev =		\
		    &(elm)->field.le_next;				\
	(listelm)->field.le_next = (elm);				\
	(elm)->field.le_prev = &(listelm)->field.le_next;		\
} while (0)
#define LIST_INSERT_HEAD(head, elm, field) do {				\
	if (((elm)->field.le_next = (head)->lh_first) != NULL)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} while (0)
#define LIST_REMOVE(elm, field) do {					\
	if ((elm)->field.le_next != NULL)				\
		(elm)->field.le_next->field.le_prev =			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
	_Q_INVALIDATE((elm)->field.le_prev);				\
	_Q_INVALIDATE((elm)->field.le_next);				\
} while (0)
#define LIST_REPLACE(elm, elm2, field) do {				\
	if (((elm2)->field.le_next = (elm)->field.le_next) != NULL)	\
		(elm2)->field.le_next->field.le_prev =			\
		    &(elm2)->field.le_next;				\
	(elm2)->field.le_prev = (elm)->field.le_prev;			\
	*(elm2)->field.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.le_prev);				\
	_Q_INVALIDATE((elm)->field.le_next);				\
} while (0)
#define SIMPLEQ_CONCAT(head1, head2) do {				\
	if (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} while (0)
#define SIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqe_next;				\
}
#define SIMPLEQ_FOREACH(var, head, field)				\
	for((var) = SIMPLEQ_FIRST(head);				\
	    (var) != SIMPLEQ_END(head);					\
	    (var) = SIMPLEQ_NEXT(var, field))
#define SIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqh_first;				\
	struct type **sqh_last;			\
}
#define SIMPLEQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).sqh_first }
#define SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(listelm)->field.sqe_next = (elm);				\
} while (0)
#define SIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)	\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(head)->sqh_first = (elm);					\
} while (0)
#define SIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqe_next = NULL;					\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &(elm)->field.sqe_next;			\
} while (0)
#define SIMPLEQ_REMOVE_AFTER(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (elm)->field.sqe_next->field.sqe_next) \
	    == NULL)							\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
} while (0)
#define SIMPLEQ_REMOVE_HEAD(head, field) do {			\
	if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL) \
		(head)->sqh_last = &(head)->sqh_first;			\
} while (0)
#define SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;				\
}
#define SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;				\
}
#define SLIST_REMOVE(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->slh_first;		\
									\
		while (curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
	}								\
	_Q_INVALIDATE((elm)->field.sle_next);				\
} while (0)
#define TAILQ_CONCAT(head1, head2, field) do {				\
	if (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} while (0)
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;				\
	struct type **tqe_prev;		\
}
#define TAILQ_FOREACH(var, head, field)					\
	for((var) = TAILQ_FIRST(head);					\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_NEXT(var, field))
#define TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for((var) = TAILQ_LAST(head, headname);				\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_PREV(var, headname, field))
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;				\
	struct type **tqh_last;			\
}
#define TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }
#define TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} while (0)
#define TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} while (0)
#define TAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (0)
#define TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#define TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define TAILQ_REMOVE(head, elm, field) do {				\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)
#define TAILQ_REPLACE(head, elm, elm2, field) do {			\
	if (((elm2)->field.tqe_next = (elm)->field.tqe_next) != NULL)	\
		(elm2)->field.tqe_next->field.tqe_prev =		\
		    &(elm2)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm2)->field.tqe_next;		\
	(elm2)->field.tqe_prev = (elm)->field.tqe_prev;			\
	*(elm2)->field.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)
#define XSIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqx_next;				\
}
#define XSIMPLEQ_FOREACH(var, head, field)				\
	for ((var) = XSIMPLEQ_FIRST(head);				\
	    (var) != XSIMPLEQ_END(head);				\
	    (var) = XSIMPLEQ_NEXT(head, var, field))
#define XSIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqx_first;				\
	struct type **sqx_last;			\
	unsigned long sqx_cookie;					\
}
#define XSIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqx_next = (listelm)->field.sqx_next) ==	\
	    XSIMPLEQ_XOR(head, NULL))					\
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next); \
	(listelm)->field.sqx_next = XSIMPLEQ_XOR(head, (elm));		\
} while (0)
#define XSIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqx_next = (head)->sqx_first) ==		\
	    XSIMPLEQ_XOR(head, NULL))					\
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next); \
	(head)->sqx_first = XSIMPLEQ_XOR(head, (elm));			\
} while (0)
#define XSIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqx_next = XSIMPLEQ_XOR(head, NULL);		\
	*(XSIMPLEQ_XOR(head, (head)->sqx_last)) = XSIMPLEQ_XOR(head, (elm)); \
	(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next);	\
} while (0)
#define XSIMPLEQ_REMOVE_AFTER(head, elm, field) do {			\
	if (((elm)->field.sqx_next = XSIMPLEQ_XOR(head,			\
	    (elm)->field.sqx_next)->field.sqx_next)			\
	    == XSIMPLEQ_XOR(head, NULL))				\
		(head)->sqx_last = 					\
		    XSIMPLEQ_XOR(head, &(elm)->field.sqx_next);		\
} while (0)
#define XSIMPLEQ_REMOVE_HEAD(head, field) do {				\
	if (((head)->sqx_first = XSIMPLEQ_XOR(head,			\
	    (head)->sqx_first)->field.sqx_next) == XSIMPLEQ_XOR(head, NULL)) \
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(head)->sqx_first); \
} while (0)
#define XSIMPLEQ_XOR(head, ptr)	    ((__typeof(ptr))((head)->sqx_cookie ^ \
					(unsigned long)(ptr)))
#define _Q_INVALIDATE(a) (a) = ((void *)-1)
#define IN_CLASSFULBROADCAST(i, b) \
				((IN_CLASSC(b) && (b | IN_CLASSC_HOST) == i) ||	\
				 (IN_CLASSB(b) && (b | IN_CLASSB_HOST) == i) ||	\
				 (IN_CLASSA(b) && (b | IN_CLASSA_HOST) == i))
#define IPCTL_IPPORT_HIFIRSTAUTO 9
#define IPCTL_IPSEC_ALLOCATIONS 18
#define IPCTL_IPSEC_AUTH_ALGORITHM 26
#define IPCTL_IPSEC_BYTES       20
#define IPCTL_IPSEC_ENC_ALGORITHM 25
#define IPCTL_IPSEC_EXPIRE_ACQUIRE 14   
#define IPCTL_IPSEC_FIRSTUSE    24
#define IPCTL_IPSEC_REQUIRE_PFS 16
#define IPCTL_IPSEC_SOFT_ALLOCATIONS            17
#define IPCTL_IPSEC_SOFT_BYTES  19
#define IPCTL_IPSEC_SOFT_FIRSTUSE 23
#define IPCTL_IPSEC_SOFT_TIMEOUT 22
#define IPCTL_IPSEC_TIMEOUT     21
#define IPSEC_AUTH_LEVEL_DEFAULT IPSEC_LEVEL_DEFAULT
#define IPSEC_ESP_NETWORK_LEVEL_DEFAULT IPSEC_LEVEL_DEFAULT
#define IPSEC_ESP_TRANS_LEVEL_DEFAULT IPSEC_LEVEL_DEFAULT
#define IPSEC_IPCOMP_LEVEL_DEFAULT IPSEC_LEVEL_DEFAULT
#define IPSEC_LEVEL_AVAIL       0x01    
#define IPSEC_LEVEL_BYPASS      0x00    
#define IPSEC_LEVEL_DEFAULT     IPSEC_LEVEL_AVAIL
#define IPSEC_LEVEL_NONE        0x00    
#define IPSEC_LEVEL_REQUIRE     0x03    
#define IPSEC_LEVEL_UNIQUE      0x04    
#define IPSEC_LEVEL_USE         0x02    


#define htonl(x)	__htobe32(x)
#define htons(x)	__htobe16(x)
#define ntohl(x)	__htobe32(x)
#define ntohs(x)	__htobe16(x)
#define CTL_IPV6PROTO_NAMES { \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, \
	{ "tcp6", CTLTYPE_NODE }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "udp6", CTLTYPE_NODE }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, \
	{ "ip6", CTLTYPE_NODE }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, \
	{ "ipsec6", CTLTYPE_NODE }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "icmp6", CTLTYPE_NODE }, \
	{ 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "divert", CTLTYPE_NODE }, \
}
#define IFA6_IS_DEPRECATED(a) \
	((a)->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_pltime)
#define IFA6_IS_INVALID(a) \
	((a)->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_vltime)
#define IN6ADDR_ANY_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IN6ADDR_INTFACELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}
#define IN6ADDR_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6_ARE_ADDR_EQUAL(a, b)			\
    (memcmp(&(a)->s6_addr[0], &(b)->s6_addr[0], sizeof(struct in6_addr)) == 0)
#define IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_LOOPBACK(a)		\
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) == __IPV6_ADDR_INT32_ONE))
#define IN6_IS_ADDR_MC_GLOBAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_GLOBAL))
#define IN6_IS_ADDR_MC_INTFACELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_INTFACELOCAL))
#define IN6_IS_ADDR_MC_LINKLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_LINKLOCAL))
#define IN6_IS_ADDR_MC_NODELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_NODELOCAL))
#define IN6_IS_ADDR_MC_ORGLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_ORGLOCAL))
#define IN6_IS_ADDR_MC_SITELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_SITELOCAL))
#define IN6_IS_ADDR_MULTICAST(a)	((a)->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#define IN6_IS_ADDR_UNSPECIFIED(a)	\
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) == 0))
#define IN6_IS_ADDR_V4COMPAT(a)		\
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) != 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) != __IPV6_ADDR_INT32_ONE))
#define IN6_IS_ADDR_V4MAPPED(a)		      \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) &&	\
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == __IPV6_ADDR_INT32_SMP))
#define IN6_IS_SCOPE_EMBED(a)	\
	((IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)) || \
	 (IN6_IS_ADDR_MC_INTFACELOCAL(a)))
#define IN6_IS_SCOPE_LINKLOCAL(a)	\
	((IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)))
#define IPV6CTL_MAXIFDEFROUTERS 47
#define IPV6CTL_NAMES { \
	{ 0, 0 }, \
	{ "forwarding", CTLTYPE_INT }, \
	{ "redirect", CTLTYPE_INT }, \
	{ "hlim", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ "forwsrcrt", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "mrtproto", CTLTYPE_INT }, \
	{ "maxfragpackets", CTLTYPE_INT }, \
	{ "sourcecheck", CTLTYPE_INT }, \
	{ "sourcecheck_logint", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "log_interval", CTLTYPE_INT }, \
	{ "hdrnestlimit", CTLTYPE_INT }, \
	{ "dad_count", CTLTYPE_INT }, \
	{ "auto_flowlabel", CTLTYPE_INT }, \
	{ "defmcasthlim", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "use_deprecated", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "maxfrags", CTLTYPE_INT }, \
	{ "mforwarding", CTLTYPE_INT }, \
	{ "multipath", CTLTYPE_INT }, \
	{ "multicast_mtudisc", CTLTYPE_INT }, \
	{ "neighborgcthresh", CTLTYPE_INT }, \
	{ "maxifprefixes", CTLTYPE_INT }, \
	{ "maxifdefrouters", CTLTYPE_INT }, \
	{ "maxdynroutes", CTLTYPE_INT }, \
	{ "dad_pending", CTLTYPE_INT }, \
	{ "mtudisctimeout", CTLTYPE_INT }, \
	{ "ifq", CTLTYPE_NODE }, \
	{ "mrtmif", CTLTYPE_STRUCT }, \
	{ "mrtmfc", CTLTYPE_STRUCT }, \
}
#define IPV6CTL_NEIGHBORGCTHRESH 45
#define IPV6CTL_SOURCECHECK_LOGINT 11	
#define IPV6CTL_VARS { \
	NULL, \
	&ip6_forwarding, \
	&ip6_sendredirects, \
	&ip6_defhlim, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	&ip6_maxfragpackets, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	&ip6_log_interval, \
	&ip6_hdrnestlimit, \
	&ip6_dad_count, \
	&ip6_auto_flowlabel, \
	&ip6_defmcasthlim, \
	NULL, \
	NULL, \
	&ip6_use_deprecated, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	&ip6_maxfrags, \
	&ip6_mforwarding, \
	&ip6_multipath, \
	&ip6_mcast_pmtu, \
	&ip6_neighborgcthresh, \
	&ip6_maxifprefixes, \
	&ip6_maxifdefrouters, \
	&ip6_maxdynroutes, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
	NULL, \
}
#define IPV6_DEFAULT_MULTICAST_HOPS 1	
#define IPV6_DEFAULT_MULTICAST_LOOP 1	

#define __IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)

#define s6_addr   __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#define s6_addr8  __u6_addr.__u6_addr8
#define __bool_true_false_are_defined 1
#define bool _Bool
#define _QUAD_HIGHWORD 1
#define _QUAD_LOWWORD 0


#define __bemtoh16(_x) __mswap16(_x)
#define __bemtoh32(_x) __mswap32(_x)
#define __bemtoh64(_x) __mswap64(_x)
#define __htobe16(x)	((__uint16_t)(x))
#define __htobe32(x)	((__uint32_t)(x))
#define __htobe64(x)	((__uint64_t)(x))
#define __htobem16(_x, _v) __swapm16((_x), (_v))
#define __htobem32(_x, _v) __swapm32((_x), (_v))
#define __htobem64(_x, _v) __swapm64((_x), (_v))
#define __htole16(x)	((__uint16_t)(x))
#define __htole32(x)	((__uint32_t)(x))
#define __htole64(x)	((__uint64_t)(x))
#define __htolem16(_x, _v) __swapm16((_x), (_v))
#define __htolem32(_x, _v) __swapm32((_x), (_v))
#define __htolem64(_x, _v) __swapm64((_x), (_v))
#define __lemtoh16(_x) __mswap16(_x)
#define __lemtoh32(_x) __mswap32(_x)
#define __lemtoh64(_x) __mswap64(_x)
#define __swap16 __swap16md
#define __swap16_multi(v, n) do {						\
	__size_t __swap16_multi_n = (n);				\
	__uint16_t *__swap16_multi_v = (v);				\
									\
	while (__swap16_multi_n) {					\
		*__swap16_multi_v = swap16(*__swap16_multi_v);		\
		__swap16_multi_v++;					\
		__swap16_multi_n--;					\
	}								\
} while (0)
#define __swap16gen(x) __statement({					\
	__uint16_t __swap16gen_x = (x);					\
									\
	(__uint16_t)((__swap16gen_x & 0xff) << 8 |			\
	    (__swap16gen_x & 0xff00) >> 8);				\
})
#define __swap32 __swap32md
#define __swap32gen(x) __statement({					\
	__uint32_t __swap32gen_x = (x);					\
									\
	(__uint32_t)((__swap32gen_x & 0xff) << 24 |			\
	    (__swap32gen_x & 0xff00) << 8 |				\
	    (__swap32gen_x & 0xff0000) >> 8 |				\
	    (__swap32gen_x & 0xff000000) >> 24);			\
})
#define __swap64 __swap64md
#define __swap64gen(x) __statement({					\
	__uint64_t __swap64gen_x = (x);					\
									\
	(__uint64_t)((__swap64gen_x & 0xff) << 56 |			\
	    (__swap64gen_x & 0xff00ULL) << 40 |				\
	    (__swap64gen_x & 0xff0000ULL) << 24 |			\
	    (__swap64gen_x & 0xff000000ULL) << 8 |			\
	    (__swap64gen_x & 0xff00000000ULL) >> 8 |			\
	    (__swap64gen_x & 0xff0000000000ULL) >> 24 |			\
	    (__swap64gen_x & 0xff000000000000ULL) >> 40 |		\
	    (__swap64gen_x & 0xff00000000000000ULL) >> 56);		\
})

#define be16toh(x)	__htobe16(x)
#define be32toh(x)	__htobe32(x)
#define be64toh(x)	__htobe64(x)
#define betoh16(x)	__htobe16(x)
#define betoh32(x)	__htobe32(x)
#define betoh64(x)	__htobe64(x)
#define htobe16(x)	__htobe16(x)
#define htobe32(x)	__htobe32(x)
#define htobe64(x)	__htobe64(x)
#define htole16(x)	__htole16(x)
#define htole32(x)	__htole32(x)
#define htole64(x)	__htole64(x)
#define le16toh(x)	__htole16(x)
#define le32toh(x)	__htole32(x)
#define le64toh(x)	__htole64(x)
#define letoh16(x)	__htole16(x)
#define letoh32(x)	__htole32(x)
#define letoh64(x)	__htole64(x)
#define swap16(x) __swap16(x)
#define swap16_multi(v, n) do {						\
	__size_t __swap16_multi_n = (n);				\
	__uint16_t *__swap16_multi_v = (v);				\
									\
	while (__swap16_multi_n) {					\
		*__swap16_multi_v = swap16(*__swap16_multi_v);		\
		__swap16_multi_v++;					\
		__swap16_multi_n--;					\
	}								\
} while (0)
#define swap32(x) __swap32(x)
#define swap64(x) __swap64(x)
#define __GNUC_PREREQ__(ma, mi) \
	(("__GNUC__" > (ma)) || ("__GNUC__" == (ma) && "__GNUC_MINOR__" >= (mi)))
# define __bounded(args)	__attribute__ ((__bounded__ args ))
#define __predict_false(exp)	__builtin_expect(((exp) != 0), 0)
#define __predict_true(exp)	__builtin_expect(((exp) != 0), 1)

#define __statement(x)	__extension__(x)
#define REFCNT_INITIALIZER()	{ .refs = 1 }

#define LOGIN_NAME_MAX          32	
#define RBT_CHECK(_name, _elm, _p)	_name##_RBT_CHECK(_elm, _p)
#define RBT_EMPTY(_name, _head)		_name##_RBT_EMPTY(_head)
#define RBT_ENTRY(_type)	struct rb_entry
#define RBT_FIND(_name, _head, _key)	_name##_RBT_FIND(_head, _key)
#define RBT_FOREACH(_e, _name, _head)					\
	for ((_e) = RBT_MIN(_name, (_head));				\
	     (_e) != NULL;						\
	     (_e) = RBT_NEXT(_name, (_e)))
#define RBT_FOREACH_REVERSE(_e, _name, _head)				\
	for ((_e) = RBT_MAX(_name, (_head));				\
	     (_e) != NULL;						\
	     (_e) = RBT_PREV(_name, (_e)))
#define RBT_FOREACH_REVERSE_SAFE(_e, _name, _head, _n)			\
	for ((_e) = RBT_MAX(_name, (_head));				\
	     (_e) != NULL && ((_n) = RBT_PREV(_name, (_e)), 1);	\
	     (_e) = (_n))
#define RBT_FOREACH_SAFE(_e, _name, _head, _n)				\
	for ((_e) = RBT_MIN(_name, (_head));				\
	     (_e) != NULL && ((_n) = RBT_NEXT(_name, (_e)), 1);	\
	     (_e) = (_n))
#define RBT_GENERATE(_name, _type, _field, _cmp)			\
    RBT_GENERATE_INTERNAL(_name, _type, _field, _cmp, NULL)
#define RBT_GENERATE_AUGMENT(_name, _type, _field, _cmp, _aug)		\
static void								\
_name##_RBT_AUGMENT(void *ptr)						\
{									\
	struct _type *p = ptr;						\
	return _aug(p);							\
}									\
RBT_GENERATE_INTERNAL(_name, _type, _field, _cmp, _name##_RBT_AUGMENT)
#define RBT_GENERATE_INTERNAL(_name, _type, _field, _cmp, _aug)		\
static int								\
_name##_RBT_COMPARE(const void *lptr, const void *rptr)			\
{									\
	const struct _type *l = lptr, *r = rptr;			\
	return _cmp(l, r);						\
}									\
static const struct rb_type _name##_RBT_INFO = {			\
	_name##_RBT_COMPARE,						\
	_aug,								\
	offsetof(struct _type, _field),					\
};									\
const struct rb_type *const _name##_RBT_TYPE = &_name##_RBT_INFO
#define RBT_HEAD(_name, _type)						\
struct _name {								\
	struct rb_tree rbh_root;					\
}
#define RBT_INIT(_name, _head)		_name##_RBT_INIT(_head)
#define RBT_INITIALIZER(_head)	{ { NULL } }
#define RBT_INSERT(_name, _head, _elm)	_name##_RBT_INSERT(_head, _elm)
#define RBT_LEFT(_name, _elm)		_name##_RBT_LEFT(_elm)
#define RBT_MAX(_name, _head)		_name##_RBT_MAX(_head)
#define RBT_MIN(_name, _head)		_name##_RBT_MIN(_head)
#define RBT_NEXT(_name, _elm)		_name##_RBT_NEXT(_elm)
#define RBT_NFIND(_name, _head, _key)	_name##_RBT_NFIND(_head, _key)
#define RBT_PARENT(_name, _elm)		_name##_RBT_PARENT(_elm)
#define RBT_POISON(_name, _elm, _p)	_name##_RBT_POISON(_elm, _p)
#define RBT_PREV(_name, _elm)		_name##_RBT_PREV(_elm)
#define RBT_PROTOTYPE(_name, _type, _field, _cmp)			\
extern const struct rb_type *const _name##_RBT_TYPE;			\
									\
__unused static inline void						\
_name##_RBT_INIT(struct _name *head)					\
{									\
	_rb_init(&head->rbh_root);					\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_INSERT(struct _name *head, struct _type *elm)		\
{									\
	return _rb_insert(_name##_RBT_TYPE, &head->rbh_root, elm);	\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_REMOVE(struct _name *head, struct _type *elm)		\
{									\
	return _rb_remove(_name##_RBT_TYPE, &head->rbh_root, elm);	\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_FIND(struct _name *head, const struct _type *key)		\
{									\
	return _rb_find(_name##_RBT_TYPE, &head->rbh_root, key);	\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_NFIND(struct _name *head, const struct _type *key)		\
{									\
	return _rb_nfind(_name##_RBT_TYPE, &head->rbh_root, key);	\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_ROOT(struct _name *head)					\
{									\
	return _rb_root(_name##_RBT_TYPE, &head->rbh_root);		\
}									\
									\
__unused static inline int						\
_name##_RBT_EMPTY(struct _name *head)					\
{									\
	return _rb_empty(&head->rbh_root);				\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_MIN(struct _name *head)					\
{									\
	return _rb_min(_name##_RBT_TYPE, &head->rbh_root);		\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_MAX(struct _name *head)					\
{									\
	return _rb_max(_name##_RBT_TYPE, &head->rbh_root);		\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_NEXT(struct _type *elm)					\
{									\
	return _rb_next(_name##_RBT_TYPE, elm);				\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_PREV(struct _type *elm)					\
{									\
	return _rb_prev(_name##_RBT_TYPE, elm);				\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_LEFT(struct _type *elm)					\
{									\
	return _rb_left(_name##_RBT_TYPE, elm);				\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_RIGHT(struct _type *elm)					\
{									\
	return _rb_right(_name##_RBT_TYPE, elm);			\
}									\
									\
__unused static inline struct _type *					\
_name##_RBT_PARENT(struct _type *elm)					\
{									\
	return _rb_parent(_name##_RBT_TYPE, elm);			\
}									\
									\
__unused static inline void						\
_name##_RBT_POISON(struct _type *elm, unsigned long poison)		\
{									\
	return _rb_poison(_name##_RBT_TYPE, elm, poison);		\
}									\
									\
__unused static inline int						\
_name##_RBT_CHECK(struct _type *elm, unsigned long poison)		\
{									\
	return _rb_check(_name##_RBT_TYPE, elm, poison);		\
}
#define RBT_REMOVE(_name, _head, _elm)	_name##_RBT_REMOVE(_head, _elm)
#define RBT_RIGHT(_name, _elm)		_name##_RBT_RIGHT(_elm)
#define RBT_ROOT(_name, _head)		_name##_RBT_ROOT(_head)
#define RB_AUGMENT(x)	do {} while (0)
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_EMPTY(head)			(RB_ROOT(head) == NULL)
#define RB_ENTRY(type)							\
struct {								\
	struct type *rbe_left;				\
	struct type *rbe_right;				\
	struct type *rbe_parent;			\
	int rbe_color;					\
}
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_FOREACH(x, name, head)					\
	for ((x) = RB_MIN(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_NEXT(x))
#define RB_FOREACH_REVERSE(x, name, head)				\
	for ((x) = RB_MAX(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_PREV(x))
#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	for ((x) = RB_MAX(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))
#define RB_FOREACH_SAFE(x, name, head, y)				\
	for ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *parent, *gparent, *tmp;				\
	while ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		if (parent == RB_LEFT(gparent, field)) {		\
			tmp = RB_RIGHT(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_RIGHT(parent, field) == elm) {		\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_RIGHT(head, gparent, tmp, field);	\
		} else {						\
			tmp = RB_LEFT(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_LEFT(parent, field) == elm) {		\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_LEFT(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_root, field) = RB_BLACK;			\
}									\
									\
attr void								\
name##_RB_REMOVE_COLOR(struct name *head, struct type *parent, struct type *elm) \
{									\
	struct type *tmp;						\
	while ((elm == NULL || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ROOT(head)) {					\
		if (RB_LEFT(parent, field) == elm) {			\
			tmp = RB_RIGHT(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = RB_RIGHT(parent, field);		\
			}						\
			if ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_RIGHT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK) {\
					struct type *oleft;		\
					if ((oleft = RB_LEFT(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_RIGHT(head, tmp, oleft, field);\
					tmp = RB_RIGHT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_RIGHT(tmp, field))		\
					RB_COLOR(RB_RIGHT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		} else {						\
			tmp = RB_LEFT(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = RB_LEFT(parent, field);		\
			}						\
			if ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_LEFT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) {\
					struct type *oright;		\
					if ((oright = RB_RIGHT(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_LEFT(head, tmp, oright, field);\
					tmp = RB_LEFT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_LEFT(tmp, field))		\
					RB_COLOR(RB_LEFT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		}							\
	}								\
	if (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr struct type *							\
name##_RB_REMOVE(struct name *head, struct type *elm)			\
{									\
	struct type *child, *parent, *old = elm;			\
	int color;							\
	if (RB_LEFT(elm, field) == NULL)				\
		child = RB_RIGHT(elm, field);				\
	else if (RB_RIGHT(elm, field) == NULL)				\
		child = RB_LEFT(elm, field);				\
	else {								\
		struct type *left;					\
		elm = RB_RIGHT(elm, field);				\
		while ((left = RB_LEFT(elm, field)))			\
			elm = left;					\
		child = RB_RIGHT(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		if (child)						\
			RB_PARENT(child, field) = parent;		\
		if (parent) {						\
			if (RB_LEFT(parent, field) == elm)		\
				RB_LEFT(parent, field) = child;		\
			else						\
				RB_RIGHT(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} else							\
			RB_ROOT(head) = child;				\
		if (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		if (RB_PARENT(old, field)) {				\
			if (RB_LEFT(RB_PARENT(old, field), field) == old)\
				RB_LEFT(RB_PARENT(old, field), field) = elm;\
			else						\
				RB_RIGHT(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} else							\
			RB_ROOT(head) = elm;				\
		RB_PARENT(RB_LEFT(old, field), field) = elm;		\
		if (RB_RIGHT(old, field))				\
			RB_PARENT(RB_RIGHT(old, field), field) = elm;	\
		if (parent) {						\
			left = parent;					\
			do {						\
				RB_AUGMENT(left);			\
			} while ((left = RB_PARENT(left, field)));	\
		}							\
		goto color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	if (child)							\
		RB_PARENT(child, field) = parent;			\
	if (parent) {							\
		if (RB_LEFT(parent, field) == elm)			\
			RB_LEFT(parent, field) = child;			\
		else							\
			RB_RIGHT(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} else								\
		RB_ROOT(head) = child;					\
color:									\
	if (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	return (old);							\
}									\
									\
					\
attr struct type *							\
name##_RB_INSERT(struct name *head, struct type *elm)			\
{									\
	struct type *tmp;						\
	struct type *parent = NULL;					\
	int comp = 0;							\
	tmp = RB_ROOT(head);						\
	while (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		if (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	if (parent != NULL) {						\
		if (comp < 0)						\
			RB_LEFT(parent, field) = elm;			\
		else							\
			RB_RIGHT(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} else								\
		RB_ROOT(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	return (NULL);							\
}									\
									\
				\
attr struct type *							\
name##_RB_FIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (NULL);							\
}									\
									\
	\
attr struct type *							\
name##_RB_NFIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *res = NULL;					\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0) {						\
			res = tmp;					\
			tmp = RB_LEFT(tmp, field);			\
		}							\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (res);							\
}									\
									\
								\
attr struct type *							\
name##_RB_NEXT(struct type *elm)					\
{									\
	if (RB_RIGHT(elm, field)) {					\
		elm = RB_RIGHT(elm, field);				\
		while (RB_LEFT(elm, field))				\
			elm = RB_LEFT(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_LEFT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}									\
									\
								\
attr struct type *							\
name##_RB_PREV(struct type *elm)					\
{									\
	if (RB_LEFT(elm, field)) {					\
		elm = RB_LEFT(elm, field);				\
		while (RB_RIGHT(elm, field))				\
			elm = RB_RIGHT(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_LEFT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}									\
									\
attr struct type *							\
name##_RB_MINMAX(struct name *head, int val)				\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *parent = NULL;					\
	while (tmp) {							\
		parent = tmp;						\
		if (val < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else							\
			tmp = RB_RIGHT(tmp, field);			\
	}								\
	return (parent);						\
}
#define RB_HEAD(name, type)						\
struct name {								\
	struct type *rbh_root; 			\
}
#define RB_INIT(root) do {						\
	(root)->rbh_root = NULL;					\
} while (0)
#define RB_INITIALIZER(root)						\
	{ NULL }
#define RB_INSERT(name, x, y)	name##_RB_INSERT(x, y)
#define RB_LEFT(elm, field)		(elm)->field.rbe_left
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr void name##_RB_INSERT_COLOR(struct name *, struct type *);		\
attr void name##_RB_REMOVE_COLOR(struct name *, struct type *, struct type *);\
attr struct type *name##_RB_REMOVE(struct name *, struct type *);	\
attr struct type *name##_RB_INSERT(struct name *, struct type *);	\
attr struct type *name##_RB_FIND(struct name *, struct type *);		\
attr struct type *name##_RB_NFIND(struct name *, struct type *);	\
attr struct type *name##_RB_NEXT(struct type *);			\
attr struct type *name##_RB_PREV(struct type *);			\
attr struct type *name##_RB_MINMAX(struct name *, int);			\
									\

#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_ROOT(head)			(head)->rbh_root
#define RB_ROTATE_LEFT(head, elm, tmp, field) do {			\
	(tmp) = RB_RIGHT(elm, field);					\
	if ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field))) {		\
		RB_PARENT(RB_LEFT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		if ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_root = (tmp);				\
	RB_LEFT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while (0)
#define RB_ROTATE_RIGHT(head, elm, tmp, field) do {			\
	(tmp) = RB_LEFT(elm, field);					\
	if ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field))) {		\
		RB_PARENT(RB_RIGHT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		if ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_root = (tmp);				\
	RB_RIGHT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while (0)
#define RB_SET(elm, parent, field) do {					\
	RB_PARENT(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = NULL;		\
	RB_COLOR(elm, field) = RB_RED;					\
} while (0)
#define RB_SET_BLACKRED(black, red, field) do {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} while (0)
#define SPLAY_ASSEMBLE(head, node, left, right, field) do {		\
	SPLAY_RIGHT(left, field) = SPLAY_LEFT((head)->sph_root, field);	\
	SPLAY_LEFT(right, field) = SPLAY_RIGHT((head)->sph_root, field);\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(node, field);	\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(node, field);	\
} while (0)
#define SPLAY_EMPTY(head)		(SPLAY_ROOT(head) == NULL)
#define SPLAY_ENTRY(type)						\
struct {								\
	struct type *spe_left; 			\
	struct type *spe_right; 			\
}
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_FOREACH(x, name, head)					\
	for ((x) = SPLAY_MIN(name, head);				\
	     (x) != NULL;						\
	     (x) = SPLAY_NEXT(name, head, x))
#define SPLAY_GENERATE(name, type, field, cmp)				\
struct type *								\
name##_SPLAY_INSERT(struct name *head, struct type *elm)		\
{									\
    if (SPLAY_EMPTY(head)) {						\
	    SPLAY_LEFT(elm, field) = SPLAY_RIGHT(elm, field) = NULL;	\
    } else {								\
	    int __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_root);			\
	    if(__comp < 0) {						\
		    SPLAY_LEFT(elm, field) = SPLAY_LEFT((head)->sph_root, field);\
		    SPLAY_RIGHT(elm, field) = (head)->sph_root;		\
		    SPLAY_LEFT((head)->sph_root, field) = NULL;		\
	    } else if (__comp > 0) {					\
		    SPLAY_RIGHT(elm, field) = SPLAY_RIGHT((head)->sph_root, field);\
		    SPLAY_LEFT(elm, field) = (head)->sph_root;		\
		    SPLAY_RIGHT((head)->sph_root, field) = NULL;	\
	    } else							\
		    return ((head)->sph_root);				\
    }									\
    (head)->sph_root = (elm);						\
    return (NULL);							\
}									\
									\
struct type *								\
name##_SPLAY_REMOVE(struct name *head, struct type *elm)		\
{									\
	struct type *__tmp;						\
	if (SPLAY_EMPTY(head))						\
		return (NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_root) == 0) {			\
		if (SPLAY_LEFT((head)->sph_root, field) == NULL) {	\
			(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);\
		} else {						\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_RIGHT((head)->sph_root, field) = __tmp;	\
		}							\
		return (elm);						\
	}								\
	return (NULL);							\
}									\
									\
void									\
name##_SPLAY(struct name *head, struct type *elm)			\
{									\
	struct type __node, *__left, *__right, *__tmp;			\
	int __comp;							\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while ((__comp = (cmp)(elm, (head)->sph_root))) {		\
		if (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				if (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				if (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}									\
									\
									\
void name##_SPLAY_MINMAX(struct name *head, int __comp) \
{									\
	struct type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while (1) {							\
		if (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp < 0){				\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				if (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp > 0) {				\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				if (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}
#define SPLAY_HEAD(name, type)						\
struct name {								\
	struct type *sph_root; 			\
}
#define SPLAY_INIT(root) do {						\
	(root)->sph_root = NULL;					\
} while (0)
#define SPLAY_INITIALIZER(root)						\
	{ NULL }
#define SPLAY_INSERT(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_LINKLEFT(head, tmp, field) do {				\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);		\
} while (0)
#define SPLAY_LINKRIGHT(head, tmp, field) do {				\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);	\
} while (0)
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
void name##_SPLAY(struct name *, struct type *);			\
void name##_SPLAY_MINMAX(struct name *, int);				\
struct type *name##_SPLAY_INSERT(struct name *, struct type *);		\
struct type *name##_SPLAY_REMOVE(struct name *, struct type *);		\
									\
				\
static __inline struct type *						\
name##_SPLAY_FIND(struct name *head, struct type *elm)			\
{									\
	if (SPLAY_EMPTY(head))						\
		return(NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_root) == 0)				\
		return (head->sph_root);				\
	return (NULL);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_NEXT(struct name *head, struct type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	if (SPLAY_RIGHT(elm, field) != NULL) {				\
		elm = SPLAY_RIGHT(elm, field);				\
		while (SPLAY_LEFT(elm, field) != NULL) {		\
			elm = SPLAY_LEFT(elm, field);			\
		}							\
	} else								\
		elm = NULL;						\
	return (elm);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_MIN_MAX(struct name *head, int val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        return (SPLAY_ROOT(head));					\
}
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_ROTATE_LEFT(head, tmp, field) do {			\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field);	\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while (0)
#define SPLAY_ROTATE_RIGHT(head, tmp, field) do {			\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field);	\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while (0)


#define ND6_IS_LLINFO_PROBREACH(n) ((n)->ln_state > ND6_LLINFO_INCOMPLETE)
#define ND6_LLINFO_PERMANENT(n)	((n)->ln_rt->rt_expire == 0)
#define ND_COMPUTE_RTIME(x) \
		(((MIN_RANDOM_FACTOR * (x >> 10)) + (arc4random() & \
		((MAX_RANDOM_FACTOR - MIN_RANDOM_FACTOR) * (x >> 10)))) /1000)
#define ND_IFINFO(ifp) \
	(((struct in6_ifextra *)(ifp)->if_afdata[AF_INET6])->nd_ifinfo)
#define RS_LHCOOKIE(ifp) \
	((struct in6_ifextra *)(ifp)->if_afdata[AF_INET6])->rs_lhcookie

#define nd6log(x)	do { if (nd6_debug) log x; } while (0)
#define TIMEOUT_INITIALIZER(_f, _a) \
	{ { NULL, NULL }, (_f), (_a), 0, TIMEOUT_INITIALIZED }

#define timeout_initialized(to) ((to)->to_flags & TIMEOUT_INITIALIZED)
#define timeout_pending(to) ((to)->to_flags & TIMEOUT_ONQUEUE)
#define timeout_triggered(to) ((to)->to_flags & TIMEOUT_TRIGGERED)
#define TASK_INITIALIZER(_f, _a)  {{ NULL, NULL }, (_f), (_a), 0 }

#define DEFROOTONLYPORTS_TCP { \
	2049, \
	0 }
#define DEFROOTONLYPORTS_UDP { \
	2049, \
	0 }
#define SL_AUTH           0             
#define SL_ESP_NETWORK    2             
#define SL_ESP_TRANS      1             
#define SL_IPCOMP         3             

#define inp_ip6_minhlim inp_ip_minttl	
#define inp_moptions inp_mou.mou_mo
#define inp_moptions6 inp_mou.mou_mo6
#define sotopf(so)  (so->so_proto->pr_domain->dom_family)
#define SipHash24(_k, _p, _l)		SipHash((_k), 2, 4, (_p), (_l))
#define SipHash24_End(_d)		SipHash_End((_d), 2, 4)
#define SipHash24_Final(_d, _c)		SipHash_Final((_d), (_c), 2, 4)
#define SipHash24_Init(_c, _k)		SipHash_Init((_c), (_k))
#define SipHash24_Update(_c, _p, _l)	SipHash_Update((_c), 2, 4, (_p), (_l))
#define SipHash48(_k, _p, _l)		SipHash((_k), 4, 8, (_p), (_l))
#define SipHash48_End(_d)		SipHash_End((_d), 4, 8)
#define SipHash48_Final(_d, _c)		SipHash_Final((_d), (_c), 4, 8)
#define SipHash48_Init(_c, _k)		SipHash_Init((_c), (_k))
#define SipHash48_Update(_c, _p, _l)	SipHash_Update((_c), 4, 8, (_p), (_l))


#define ICMP6_PARAMPROB_HEADER 	 	0	
#define ICMP6_ROUTER_RENUMBERING_COMMAND  0	
#define ICMP6_ROUTER_RENUMBERING_RESULT   1	
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME     htonl(0x40000000)
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME     htonl(0x80000000)
#define ICMP6_TIME_EXCEED_TRANSIT 	0	
#define ICMPV6CTL_NAMES { \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "redirtimeout", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "nd6_prune", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ "nd6_delay", CTLTYPE_INT }, \
	{ "nd6_umaxtries", CTLTYPE_INT }, \
	{ "nd6_mmaxtries", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
	{ "errppslimit", CTLTYPE_INT }, \
	{ "nd6_maxnudhint", CTLTYPE_INT }, \
	{ "mtudisc_hiwat", CTLTYPE_INT }, \
	{ "mtudisc_lowat", CTLTYPE_INT }, \
	{ "nd6_debug", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ 0, 0 }, \
}
#define ICMPV6CTL_VARS { \
	NULL, \
	NULL, \
	NULL, \
	&icmp6_redirtimeout, \
	NULL, \
	NULL, \
	&nd6_prune, \
	NULL, \
	&nd6_delay, \
	&nd6_umaxtries, \
	&nd6_mmaxtries, \
	NULL, \
	NULL, \
	NULL, \
	&icmp6errppslim, \
	&nd6_maxnudhint, \
	&icmp6_mtudisc_hiwat, \
	&icmp6_mtudisc_lowat, \
	&nd6_debug, \
	NULL, \
	NULL, \
}

#define icp6s_odst_unreach_addr icp6s_outerrhist.icp6errs_dst_unreach_addr
#define icp6s_odst_unreach_admin icp6s_outerrhist.icp6errs_dst_unreach_admin
#define icp6s_odst_unreach_beyondscope \
	icp6s_outerrhist.icp6errs_dst_unreach_beyondscope
#define icp6s_odst_unreach_noport icp6s_outerrhist.icp6errs_dst_unreach_noport
#define icp6s_odst_unreach_noroute \
	icp6s_outerrhist.icp6errs_dst_unreach_noroute
#define icp6s_opacket_too_big icp6s_outerrhist.icp6errs_packet_too_big
#define icp6s_oparamprob_header icp6s_outerrhist.icp6errs_paramprob_header
#define icp6s_oparamprob_nextheader \
	icp6s_outerrhist.icp6errs_paramprob_nextheader
#define icp6s_oparamprob_option icp6s_outerrhist.icp6errs_paramprob_option
#define icp6s_oredirect icp6s_outerrhist.icp6errs_redirect
#define icp6s_otime_exceed_reassembly \
	icp6s_outerrhist.icp6errs_time_exceed_reassembly
#define icp6s_otime_exceed_transit \
	icp6s_outerrhist.icp6errs_time_exceed_transit
#define icp6s_ounknown icp6s_outerrhist.icp6errs_unknown
#define rr_seqnum 	rr_hdr.icmp6_data32[0]
#define IP6_REASS_MBUF(ip6af) ((ip6af)->ip6af_m)

#define IP6OPT_JUMBO_LEN 6
#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6_EXTHDR_GET(val, typ, m, off, len)				\
do {									\
	struct mbuf *t;							\
	int tmp;							\
	if ((m)->m_len >= (off) + (len))				\
		(val) = (typ)(mtod((m), caddr_t) + (off));		\
	else {								\
		t = m_pulldown((m), (off), (len), &tmp);		\
		if (t) {						\
			if (t->m_len < tmp + (len))			\
				panic("m_pulldown malfunction");	\
			(val) = (typ)(mtod(t, caddr_t) + tmp);		\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while ( 0)

#define MLD_RANDOM_DELAY(X)	(arc4random_uniform(X) + 1)

#define IA6_DSTIN6(ia)	(&((ia)->ia_dstaddr.sin6_addr))
#define IA6_DSTSIN6(ia)	(&((ia)->ia_dstaddr))
#define IA6_IN6(ia)	(&((ia)->ia_addr.sin6_addr))
#define IA6_MASKIN6(ia)	(&((ia)->ia_prefixmask.sin6_addr))
#define IA6_SIN6(ia)	(&((ia)->ia_addr))
#define IFA_DSTIN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_dstaddr))->sin6_addr)
#define IFA_IN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_addr))->sin6_addr)
#define IN6_ARE_MASKED_ADDR_EQUAL(d, a, m)	(	\
	(((d)->s6_addr32[0] ^ (a)->s6_addr32[0]) & (m)->s6_addr32[0]) == 0 && \
	(((d)->s6_addr32[1] ^ (a)->s6_addr32[1]) & (m)->s6_addr32[1]) == 0 && \
	(((d)->s6_addr32[2] ^ (a)->s6_addr32[2]) & (m)->s6_addr32[2]) == 0 && \
	(((d)->s6_addr32[3] ^ (a)->s6_addr32[3]) & (m)->s6_addr32[3]) == 0 )
#define IN6_ARE_SCOPE_CMP(a,b) ((a)-(b))
#define IN6_ARE_SCOPE_EQUAL(a,b) ((a)==(b))
#define IN6_LOOKUP_MULTI(addr, ifp, in6m)				\
						\
						\
						\
do {									\
	struct ifmaddr *ifma;						\
									\
	(in6m) = NULL;							\
	TAILQ_FOREACH(ifma, &(ifp)->if_maddrlist, ifma_list)		\
		if (ifma->ifma_addr->sa_family == AF_INET6 &&		\
		    IN6_ARE_ADDR_EQUAL(&ifmatoin6m(ifma)->in6m_addr,	\
				       &(addr))) {			\
			(in6m) = ifmatoin6m(ifma);			\
			break;						\
		}							\
} while ( 0)
#define SIOCSIFPHYADDR_IN6       _IOW('i', 70, struct in6_aliasreq)



#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

#define NIQUEUE_INITIALIZER(_len, _isr) \
    { MBUF_QUEUE_INITIALIZER((_len), IPL_NET), (_isr) }

#define if_rxr_inuse(_r)	((_r)->rxr_alive)
#define if_rxr_put(_r, _c)	do { (_r)->rxr_alive -= (_c); } while (0)
#define niq_dechain(_q)			mq_dechain(&(_q)->ni_q)
#define niq_delist(_q, _ml)		mq_delist(&(_q)->ni_q, (_ml))
#define niq_dequeue(_q)			mq_dequeue(&(_q)->ni_q)
#define niq_drops(_q)			mq_drops(&(_q)->ni_q)
#define niq_len(_q)			mq_len(&(_q)->ni_q)
#define sysctl_niq(_n, _l, _op, _olp, _np, _nl, _niq) \
    sysctl_mq((_n), (_l), (_op), (_olp), (_np), (_nl), &(_niq)->ni_q)
#define IFQ_ASSERT_SERIALIZED(_ifq)	KASSERT(ifq_is_serialized(_ifq))

#define FROMBCD(x)      (((x) >> 4) * 10 + ((x) & 0xf))
#define POSIX_BASE_YEAR 1970
#define SECDAY          86400L
#define SECYR           (SECDAY * 365)
#define TOBCD(x)        (((x) / 10 * 16) + ((x) % 10))




#define __CLOCK_ENCODE(type,id)		((type) | ((id) << 12))
#define __CLOCK_PTID(c)			(((c) >> 12) & 0xfffff)
#define __CLOCK_TYPE(c)			((c) & 0xfff)
#define FD_CLR(n, p)	__fd_clr((n), (p))
#define FD_ISSET(n, p)	__fd_isset((n), (p))
#define FD_SET(n, p)	__fd_set((n), (p))


#define __NFDBITS ((unsigned)(sizeof(__fd_mask) * __NBBY)) 
#define howmany(x, y)	__howmany(x, y)
#define SRPL_EMPTY_LOCKED(_sl)		(SRPL_FIRST_LOCKED(_sl) == NULL)
#define SRPL_ENTRY(type)						\
struct {								\
	struct srp		se_next;				\
}
#define SRPL_FIRST(_sr, _sl)		srp_enter((_sr), &(_sl)->sl_head)
#define SRPL_FIRST_LOCKED(_sl)		srp_get_locked(&(_sl)->sl_head)
#define SRPL_FOLLOW(_sr, _e, _ENTRY)	srp_follow((_sr), &(_e)->_ENTRY.se_next)
#define SRPL_FOREACH(_c, _sr, _sl, _ENTRY)				\
	for ((_c) = SRPL_FIRST(_sr, _sl);				\
	    (_c) != NULL; 						\
	    (_c) = SRPL_FOLLOW(_sr, _c, _ENTRY))
#define SRPL_FOREACH_LOCKED(_c, _sl, _ENTRY)				\
	for ((_c) = SRPL_FIRST_LOCKED(_sl);				\
	    (_c) != NULL;						\
	    (_c) = SRPL_NEXT_LOCKED((_c), _ENTRY))
#define SRPL_FOREACH_SAFE_LOCKED(_c, _sl, _ENTRY, _tc)			\
	for ((_c) = SRPL_FIRST_LOCKED(_sl);				\
	    (_c) && ((_tc) = SRPL_NEXT_LOCKED(_c, _ENTRY), 1);		\
	    (_c) = (_tc))
#define SRPL_HEAD(name, type)		struct srpl
#define SRPL_INIT(_sl)			srp_init(&(_sl)->sl_head)
#define SRPL_INSERT_AFTER_LOCKED(_rc, _se, _e, _ENTRY) do {		\
	void *next;							\
									\
	srp_init(&(_e)->_ENTRY.se_next);				\
									\
	next = SRPL_NEXT_LOCKED(_se, _ENTRY);				\
	if (next != NULL) {						\
		(_rc)->srpl_ref(&(_rc)->srpl_cookie, next);		\
		srp_update_locked(&(_rc)->srpl_gc,			\
		    &(_e)->_ENTRY.se_next, next);	 		\
	}								\
									\
	(_rc)->srpl_ref(&(_rc)->srpl_cookie, _e);			\
	srp_update_locked(&(_rc)->srpl_gc,				\
	    &(_se)->_ENTRY.se_next, (_e));				\
} while (0)
#define SRPL_INSERT_HEAD_LOCKED(_rc, _sl, _e, _ENTRY) do {		\
	void *head;							\
									\
	srp_init(&(_e)->_ENTRY.se_next);				\
									\
	head = SRPL_FIRST_LOCKED(_sl);					\
	if (head != NULL) {						\
		(_rc)->srpl_ref(&(_rc)->srpl_cookie, head);		\
		srp_update_locked(&(_rc)->srpl_gc,			\
		    &(_e)->_ENTRY.se_next, head);	 		\
	}								\
									\
	(_rc)->srpl_ref(&(_rc)->srpl_cookie, _e);			\
	srp_update_locked(&(_rc)->srpl_gc, &(_sl)->sl_head, (_e));	\
} while (0)
#define SRPL_LEAVE(_sr)			srp_leave((_sr))
#define SRPL_NEXT(_sr, _e, _ENTRY)	srp_enter((_sr), &(_e)->_ENTRY.se_next)
#define SRPL_NEXT_LOCKED(_e, _ENTRY)					\
	srp_get_locked(&(_e)->_ENTRY.se_next)
#define SRPL_RC_INITIALIZER(_r, _u, _c) { _r, SRP_GC_INITIALIZER(_u, _c) }
#define SRPL_REMOVE_LOCKED(_rc, _sl, _e, _type, _ENTRY) do {		\
	struct srp *ref;						\
	struct _type *c, *n;						\
									\
	ref = &(_sl)->sl_head;						\
	while ((c = srp_get_locked(ref)) != (_e))			\
		ref = &c->_ENTRY.se_next;				\
									\
	n = SRPL_NEXT_LOCKED(c, _ENTRY);				\
	if (n != NULL)							\
		(_rc)->srpl_ref(&(_rc)->srpl_cookie, n);		\
	srp_update_locked(&(_rc)->srpl_gc, ref, n);			\
	srp_update_locked(&(_rc)->srpl_gc, &c->_ENTRY.se_next, NULL);	\
} while (0)
#define SRP_GC_INITIALIZER(_d, _c) { (_d), (_c), REFCNT_INITIALIZER() }
#define SRP_HAZARD_NUM 16
#define SRP_INITIALIZER() { NULL }

#define __upunused __attribute__((__unused__))
#define srp_enter(_sr, _srp)		((_srp)->ref)
#define srp_finalize(_v, _wchan)	((void)0)
#define srp_follow(_sr, _srp)		((_srp)->ref)
#define srp_leave(_sr)			do { } while (0)
#define srp_swap(_srp, _v)		srp_swap_locked((_srp), (_v))
#define srp_update(_gc, _srp, _v)	srp_update_locked((_gc), (_srp), (_v))
#define MBSTAT_COUNT           (MBSTAT_TYPES + 3)
#define MBSTAT_DRAIN           (MBSTAT_TYPES + 2)
#define MBSTAT_DROPS           (MBSTAT_TYPES + 0)
#define MBSTAT_TYPES           MT_NTYPES
#define MBSTAT_WAIT            (MBSTAT_TYPES + 1)
#define MBUF_LIST_FIRST(_ml)	((_ml)->ml_head)
#define MBUF_LIST_FOREACH(_ml, _m)					\
	for ((_m) = MBUF_LIST_FIRST(_ml);				\
	    (_m) != NULL;						\
	    (_m) = MBUF_LIST_NEXT(_m))
#define MBUF_LIST_INITIALIZER() { NULL, NULL, 0 }
#define MBUF_LIST_NEXT(_m)	((_m)->m_nextpkt)
#define MBUF_QUEUE_INITIALIZER(_maxlen, _ipl) \
    { MUTEX_INITIALIZER(_ipl), MBUF_LIST_INITIALIZER(), (_maxlen), 0 }
#define MCLGET(m, how) (void) m_clget((m), (how), MCLBYTES)
#define MCLGETI(m, how, ifp, l) m_clget((m), (how), (l))
#define MCLREFDEBUGN(m, file, line) do {				\
		(m)->m_ext.ext_nfile = (file);				\
		(m)->m_ext.ext_nline = (line);				\
	} while ( 0)
#define MCLREFDEBUGO(m, file, line) do {				\
		(m)->m_ext.ext_ofile = (file);				\
		(m)->m_ext.ext_oline = (line);				\
	} while ( 0)
#define MCS_BITS \
    ("\20\1IPV4_CSUM_OUT\2TCP_CSUM_OUT\3UDP_CSUM_OUT\4IPV4_CSUM_IN_OK" \
    "\5IPV4_CSUM_IN_BAD\6TCP_CSUM_IN_OK\7TCP_CSUM_IN_BAD\10UDP_CSUM_IN_OK" \
    "\11UDP_CSUM_IN_BAD\12ICMP_CSUM_OUT\13ICMP_CSUM_IN_OK\14ICMP_CSUM_IN_BAD")
#define MGET(m, how, type) m = m_get((how), (type))
#define MGETHDR(m, how, type) m = m_gethdr((how), (type))
#define MPF_BITS \
    ("\20\1GENERATED\3TRANSLATE_LOCALHOST\4DIVERTED\5DIVERTED_PACKET" \
    "\6REROUTE\7REFRAGMENTED\10PROCESSED")
#define MTAG_BITS \
    ("\20\1IPSEC_IN_DONE\2IPSEC_OUT_DONE\3IPSEC_IN_CRYPTO_DONE" \
    "\4IPSEC_OUT_CRYPTO_NEEDED\5IPSEC_PENDING_TDB\6BRIDGE\7GIF\10GRE\11DLT" \
    "\12PF_DIVERT\14PF_REASSEMBLED\15SRCROUTE\16TUNNEL")
#define M_BITS \
    ("\20\1M_EXT\2M_PKTHDR\3M_EOR\4M_EXTWR\5M_PROTO1\6M_VLANTAG\7M_LOOP" \
    "\10M_ACAST\11M_BCAST\12M_MCAST\13M_CONF\14M_AUTH\15M_TUNNEL" \
    "\16M_ZEROIZE\17M_COMP\20M_LINK0")
#define M_MOVE_HDR(to, from) do {					\
	(to)->m_pkthdr = (from)->m_pkthdr;				\
	(from)->m_flags &= ~M_PKTHDR;					\
	SLIST_INIT(&(from)->m_pkthdr.ph_tags);				\
	(from)->m_pkthdr.pf.statekey = NULL;				\
} while ( 0)


#define CTL_KERN_MALLOC_NAMES { \
	{ 0, 0 }, \
	{ "buckets", CTLTYPE_STRING }, \
	{ "bucket", CTLTYPE_NODE }, \
	{ "kmemnames", CTLTYPE_STRING }, \
	{ "kmemstat", CTLTYPE_NODE }, \
}
#define DEBUG_MALLOC_ASSERT_ALLOCATED(addr) 			\
	debug_malloc_assert_allocated(addr, __func__)
#define CTL_IFQ_NAMES  { \
	{ 0, 0 }, \
	{ "len", CTLTYPE_INT }, \
	{ "maxlen", CTLTYPE_INT }, \
	{ "drops", CTLTYPE_INT }, \
	{ "congestion", CTLTYPE_INT }, \
}
#define IFQCTL_CONGESTION 4
#define IFQCTL_DROPS 3
#define IFQCTL_LEN 1
#define IFQCTL_MAXID 5
#define IFQCTL_MAXLEN 2
#define LINK_STATE_DESCRIPTIONS {					\
	{ IFT_ETHER, LINK_STATE_DOWN, "no carrier" },			\
									\
	{ IFT_IEEE80211, LINK_STATE_DOWN, "no network" },		\
									\
	{ IFT_PPP, LINK_STATE_DOWN, "no carrier" },			\
									\
	{ IFT_CARP, LINK_STATE_DOWN, "backup" },			\
	{ IFT_CARP, LINK_STATE_UP, "master" },				\
	{ IFT_CARP, LINK_STATE_HALF_DUPLEX, "master" },			\
	{ IFT_CARP, LINK_STATE_FULL_DUPLEX, "master" },			\
									\
	{ 0, LINK_STATE_UP, "active" },					\
	{ 0, LINK_STATE_HALF_DUPLEX, "active" },			\
	{ 0, LINK_STATE_FULL_DUPLEX, "active" },			\
									\
	{ 0, LINK_STATE_UNKNOWN, "unknown" },				\
	{ 0, LINK_STATE_INVALID, "invalid" },				\
	{ 0, LINK_STATE_DOWN, "down" },					\
	{ 0, LINK_STATE_KALIVE_DOWN, "keepalive down" },		\
	{ 0, 0, NULL }							\
}
#define LINK_STATE_DESC_MATCH(_ifs, _t, _s)				\
	(((_ifs)->ifs_type == (_t) || (_ifs)->ifs_type == 0) &&		\
	    (_ifs)->ifs_state == (_s))
#define LINK_STATE_IS_UP(_s)	\
		((_s) >= LINK_STATE_UP || (_s) == LINK_STATE_UNKNOWN)

#define ARPHRD_ETHER 	1	
#define ARPHRD_FRELAY 	15	
#define ARPHRD_IEEE802 	6	

#define SYSLOG_DATA_INIT {0, (const char *)0, LOG_USER, 0xff}

#define isspliced(so)		((so)->so_sp && (so)->so_sp->ssp_socket)
#define issplicedback(so)	((so)->so_sp && (so)->so_sp->ssp_soback)
#define EV_SET(kevp, a, b, c, d, e, f) do {	\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
} while(0)
#define KNOTE(list, hint)	do { \
					if ((list) != NULL) \
						knote((list), (hint)); \
				} while (0)

#define AF_MAX          36
#define AF_MPLS         33              
#define CMSG_ALIGN(n)		_ALIGN(n)
#define CTL_NET_BPF_NAMES { \
	{ 0, 0 }, \
	{ "bufsize", CTLTYPE_INT }, \
	{ "maxbufsize", CTLTYPE_INT }, \
}
#define CTL_NET_KEY_NAMES { \
	{ 0, 0 }, \
	{ "sadb_dump", CTLTYPE_STRUCT }, \
	{ "spd_dump", CTLTYPE_STRUCT }, \
}
#define CTL_NET_NAMES { \
	{ 0, 0 }, \
	{ "unix", CTLTYPE_NODE }, \
	{ "inet", CTLTYPE_NODE }, \
	{ "implink", CTLTYPE_NODE }, \
	{ "pup", CTLTYPE_NODE }, \
	{ "chaos", CTLTYPE_NODE }, \
	{ "xerox_ns", CTLTYPE_NODE }, \
	{ "iso", CTLTYPE_NODE }, \
	{ "emca", CTLTYPE_NODE }, \
	{ "datakit", CTLTYPE_NODE }, \
	{ "ccitt", CTLTYPE_NODE }, \
	{ "ibm_sna", CTLTYPE_NODE }, \
	{ "decnet", CTLTYPE_NODE }, \
	{ "dec_dli", CTLTYPE_NODE }, \
	{ "lat", CTLTYPE_NODE }, \
	{ "hylink", CTLTYPE_NODE }, \
	{ "appletalk", CTLTYPE_NODE }, \
	{ "route", CTLTYPE_NODE }, \
	{ "link_layer", CTLTYPE_NODE }, \
	{ "xtp", CTLTYPE_NODE }, \
	{ "coip", CTLTYPE_NODE }, \
	{ "cnt", CTLTYPE_NODE }, \
	{ "rtip", CTLTYPE_NODE }, \
	{ "ipx", CTLTYPE_NODE }, \
	{ "inet6", CTLTYPE_NODE }, \
	{ "pip", CTLTYPE_NODE }, \
	{ "isdn", CTLTYPE_NODE }, \
	{ "natm", CTLTYPE_NODE }, \
	{ "encap", CTLTYPE_NODE }, \
	{ "sip", CTLTYPE_NODE }, \
	{ "key", CTLTYPE_NODE }, \
	{ "bpf", CTLTYPE_NODE }, \
	{ "bluetooth", CTLTYPE_NODE }, \
	{ "mpls", CTLTYPE_NODE }, \
	{ "pflow", CTLTYPE_NODE }, \
	{ "pipex", CTLTYPE_NODE }, \
}
#define CTL_NET_PFLOW_NAMES { \
	{ 0, 0 }, \
	{ "stats", CTLTYPE_STRUCT }, \
}
#define CTL_NET_RT_NAMES { \
	{ 0, 0 }, \
	{ "dump", CTLTYPE_STRUCT }, \
	{ "flags", CTLTYPE_STRUCT }, \
	{ "iflist", CTLTYPE_STRUCT }, \
	{ "stats", CTLTYPE_STRUCT }, \
	{ "table", CTLTYPE_STRUCT }, \
	{ "ifnames", CTLTYPE_STRUCT }, \
}
#define SA_LEN(x) ((x)->sa_len)

#define pseudo_AF_HDRCMPLT 31		
#define pseudo_AF_PFLOW 34		
#define pseudo_AF_PIPEX 35		
#define CTL_KERN_INTRCNT_NAMES { \
	{ 0, 0 }, \
	{ "nintrcnt", CTLTYPE_INT }, \
	{ "intrcnt", CTLTYPE_NODE }, \
	{ "intrname", CTLTYPE_NODE }, \
}
#define CTL_KERN_TIMECOUNTER_NAMES { \
	{ 0, 0 }, \
	{ "tick", CTLTYPE_INT }, \
	{ "timestepwarnings", CTLTYPE_INT }, \
	{ "hardware", CTLTYPE_STRING }, \
	{ "choice", CTLTYPE_STRING }, \
}
#define CTL_KERN_WATCHDOG_NAMES { \
	{ 0, 0 }, \
	{ "period", CTLTYPE_INT }, \
	{ "auto", CTLTYPE_INT }, \
}
#define FILL_KPROC(kp, copy_str, p, pr, uc, pg, paddr, \
    praddr, sess, vm, lim, sa, isthread, show_addresses) \
do {									\
	memset((kp), 0, sizeof(*(kp)));					\
									\
	if (show_addresses) {						\
		(kp)->p_paddr = PTRTOINT64(paddr);			\
		(kp)->p_fd = PTRTOINT64((pr)->ps_fd);			\
		(kp)->p_limit = PTRTOINT64((pr)->ps_limit);		\
		(kp)->p_vmspace = PTRTOINT64((pr)->ps_vmspace);		\
		(kp)->p_sigacts = PTRTOINT64((pr)->ps_sigacts);		\
		(kp)->p_sess = PTRTOINT64((pg)->pg_session);		\
		(kp)->p_ru = PTRTOINT64((pr)->ps_ru);			\
	}								\
	(kp)->p_stats = 0;						\
	(kp)->p_exitsig = 0;						\
	(kp)->p_flag = (p)->p_flag;					\
	(kp)->p_pid = (pr)->ps_pid;					\
	(kp)->p_psflags = (pr)->ps_flags;				\
									\
	(kp)->p__pgid = (pg)->pg_id;					\
									\
	(kp)->p_uid = (uc)->cr_uid;					\
	(kp)->p_ruid = (uc)->cr_ruid;					\
	(kp)->p_gid = (uc)->cr_gid;					\
	(kp)->p_rgid = (uc)->cr_rgid;					\
	(kp)->p_svuid = (uc)->cr_svuid;					\
	(kp)->p_svgid = (uc)->cr_svgid;					\
									\
	memcpy((kp)->p_groups, (uc)->cr_groups,				\
	    MIN(sizeof((kp)->p_groups), sizeof((uc)->cr_groups)));	\
	(kp)->p_ngroups = (uc)->cr_ngroups;				\
									\
	(kp)->p_jobc = (pg)->pg_jobc;					\
									\
	(kp)->p_estcpu = (p)->p_estcpu;					\
	if (isthread) {							\
		(kp)->p_rtime_sec = (p)->p_tu.tu_runtime.tv_sec;	\
		(kp)->p_rtime_usec = (p)->p_tu.tu_runtime.tv_nsec/1000;	\
		(kp)->p_tid = (p)->p_tid + THREAD_PID_OFFSET;		\
		(kp)->p_uticks = (p)->p_tu.tu_uticks;			\
		(kp)->p_sticks = (p)->p_tu.tu_sticks;			\
		(kp)->p_iticks = (p)->p_tu.tu_iticks;			\
	} else {							\
		(kp)->p_rtime_sec = (pr)->ps_tu.tu_runtime.tv_sec;	\
		(kp)->p_rtime_usec = (pr)->ps_tu.tu_runtime.tv_nsec/1000; \
		(kp)->p_tid = -1;					\
		(kp)->p_uticks = (pr)->ps_tu.tu_uticks;			\
		(kp)->p_sticks = (pr)->ps_tu.tu_sticks;			\
		(kp)->p_iticks = (pr)->ps_tu.tu_iticks;			\
	}								\
	(kp)->p_cpticks = (p)->p_cpticks;				\
									\
	if (show_addresses)						\
		(kp)->p_tracep = PTRTOINT64((pr)->ps_tracevp);		\
	(kp)->p_traceflag = (pr)->ps_traceflag;				\
									\
	(kp)->p_siglist = (p)->p_siglist;				\
	(kp)->p_sigmask = (p)->p_sigmask;				\
	(kp)->p_sigignore = (sa) ? (sa)->ps_sigignore : 0;		\
	(kp)->p_sigcatch = (sa) ? (sa)->ps_sigcatch : 0;		\
									\
	(kp)->p_stat = (p)->p_stat;					\
	(kp)->p_nice = (pr)->ps_nice;					\
									\
	(kp)->p_xstat = (p)->p_xstat;					\
	(kp)->p_acflag = (pr)->ps_acflag;				\
									\
		\
	copy_str((kp)->p_emul, (char *)(pr)->ps_emul +			\
	    offsetof(struct emul, e_name), sizeof((kp)->p_emul));	\
	strlcpy((kp)->p_comm, (p)->p_comm, sizeof((kp)->p_comm));	\
	strlcpy((kp)->p_login, (sess)->s_login,			\
	    MIN(sizeof((kp)->p_login), sizeof((sess)->s_login)));	\
									\
	if ((sess)->s_ttyvp)						\
		(kp)->p_eflag |= EPROC_CTTY;				\
	if ((sess)->s_leader == (praddr))				\
		(kp)->p_eflag |= EPROC_SLEADER;				\
									\
	if (((pr)->ps_flags & (PS_EMBRYO | PS_ZOMBIE)) == 0) {		\
		if ((vm) != NULL) {					\
			(kp)->p_vm_rssize = (vm)->vm_rssize;		\
			(kp)->p_vm_tsize = (vm)->vm_tsize;		\
			(kp)->p_vm_dsize = (vm)->vm_dused;		\
			(kp)->p_vm_ssize = (vm)->vm_ssize;		\
		}							\
		(kp)->p_addr = PTRTOINT64((p)->p_addr);			\
		(kp)->p_stat = (p)->p_stat;				\
		(kp)->p_slptime = (p)->p_slptime;			\
		(kp)->p_holdcnt = 1;					\
		(kp)->p_priority = (p)->p_priority;			\
		(kp)->p_usrpri = (p)->p_usrpri;				\
		if ((p)->p_wchan && (p)->p_wmesg)			\
			copy_str((kp)->p_wmesg, (p)->p_wmesg,		\
			    sizeof((kp)->p_wmesg));			\
		if (show_addresses)					\
			(kp)->p_wchan = PTRTOINT64((p)->p_wchan);	\
	}								\
									\
	if (lim)							\
		(kp)->p_rlim_rss_cur =					\
		    (lim)->pl_rlimit[RLIMIT_RSS].rlim_cur;		\
									\
	if (((pr)->ps_flags & PS_ZOMBIE) == 0) {			\
		struct timeval tv;					\
									\
		(kp)->p_uvalid = 1;					\
									\
		(kp)->p_ustart_sec = (pr)->ps_start.tv_sec;		\
		(kp)->p_ustart_usec = (pr)->ps_start.tv_nsec/1000;	\
									\
		(kp)->p_uru_maxrss = (p)->p_ru.ru_maxrss;		\
		(kp)->p_uru_ixrss = (p)->p_ru.ru_ixrss;			\
		(kp)->p_uru_idrss = (p)->p_ru.ru_idrss;			\
		(kp)->p_uru_isrss = (p)->p_ru.ru_isrss;			\
		(kp)->p_uru_minflt = (p)->p_ru.ru_minflt;		\
		(kp)->p_uru_majflt = (p)->p_ru.ru_majflt;		\
		(kp)->p_uru_nswap = (p)->p_ru.ru_nswap;			\
		(kp)->p_uru_inblock = (p)->p_ru.ru_inblock;		\
		(kp)->p_uru_oublock = (p)->p_ru.ru_oublock;		\
		(kp)->p_uru_msgsnd = (p)->p_ru.ru_msgsnd;		\
		(kp)->p_uru_msgrcv = (p)->p_ru.ru_msgrcv;		\
		(kp)->p_uru_nsignals = (p)->p_ru.ru_nsignals;		\
		(kp)->p_uru_nvcsw = (p)->p_ru.ru_nvcsw;			\
		(kp)->p_uru_nivcsw = (p)->p_ru.ru_nivcsw;		\
									\
		timeradd(&(pr)->ps_cru.ru_utime,			\
			 &(pr)->ps_cru.ru_stime, &tv);			\
		(kp)->p_uctime_sec = tv.tv_sec;				\
		(kp)->p_uctime_usec = tv.tv_usec;			\
	}								\
									\
	(kp)->p_cpuid = KI_NOCPU;					\
	(kp)->p_rtableid = (pr)->ps_rtableid;				\
} while (0)
#define KERN_TIMECOUNTER_TIMESTEPWARNINGS 2	
#define KVE_ET_COPYONWRITE 	0x00000004
#define PTRTOINT64(_x)	((u_int64_t)(u_long)(_x))
#define SCARG(p, k)	((p)->k.be.datum)	

#define curproc curcpu()->ci_curproc
#define dostartuphooks() dohooks(&startuphook_list, HOOK_REMOVE|HOOK_FREE)
#define startuphook_disestablish(vhook) \
	hook_disestablish(&startuphook_list, (vhook))
#define startuphook_establish(fn, arg) \
	hook_establish(&startuphook_list, 1, (fn), (arg))
#define wakeup_one(c) wakeup_n((c), 1)




#define __va_copy(dst, src)	__builtin_va_copy((dst),(src))
#define va_arg(ap, type)	__builtin_va_arg((ap), type)
#define va_end(ap)		__builtin_va_end((ap))
#define va_start(ap, last)	__builtin_va_start((ap), last)
#define CLR(t, f)	((t) &= ~(f))
#define ISSET(t, f)	((t) & (f))
#define OpenBSD6_0 1		
#define SET(t, f)	((t) |= (f))
#define btodb(x)        ((x) >> _DEV_BSHIFT)
#define ctod(x)         ((x) << (PAGE_SHIFT - _DEV_BSHIFT))
#define dbtob(x)        ((x) << _DEV_BSHIFT)
#define dtoc(x)         ((x) >> (PAGE_SHIFT - _DEV_BSHIFT))
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#define offsetof(s, e) __builtin_offsetof(s, e)
#define powerof2(x)	((((x)-1)&(x))==0)
#define SHRT_MIN        (-0x7fff-1)     

#define NSIG _NSIG
#define SIGTHR  32	
#define SIGUSR1 30	
#define SIGUSR2 31	
#define SIGWINCH 28	

#define sa_handler      __sigaction_u.__sa_handler
#define sa_sigaction    __sigaction_u.__sa_sigaction
#define sigmask(m)	(1U << ((m)-1))
#define SI_FROMKERNEL(sip)	((sip)->si_code > 0)
#define SI_FROMUSER(sip)	((sip)->si_code <= 0)

#define FSCRED ((struct ucred *)-2)	
#define NOCRED ((struct ucred *)-1)	
