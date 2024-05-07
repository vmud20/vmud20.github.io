

#include<pthread.h>













#define DNSCACHE_STORE_ZEROTTL 0x100000

#define PREFETCH_TTL_CALC(ttl) ((ttl) - (ttl)/10)

#define PACKED_RRSET_FIXEDTTL 0x80000000
#define PACKED_RRSET_NSEC_AT_APEX 0x1
#define PACKED_RRSET_PARENT_SIDE 0x2
#define PACKED_RRSET_SOA_NEG 0x4
#define RR_COUNT_MAX 0xffffff


#define LOCKRET(func) do {\
	int lockret_err;		\
	if( (lockret_err=(func)) != 0)		\
		log_err("%s at %d could not " #func ": %s", \
		"__FILE__", "__LINE__", strerror(lockret_err));	\
 	} while(0)
#define PTHREADCREATE(thr, stackrequired, func, arg) do {\
	pthread_attr_t attr; \
	size_t stacksize; \
	LOCKRET(pthread_attr_init(&attr)); \
	LOCKRET(pthread_attr_getstacksize(&attr, &stacksize)); \
	if (stacksize < stackrequired) { \
		LOCKRET(pthread_attr_setstacksize(&attr, stackrequired)); \
		LOCKRET(pthread_create(thr, &attr, func, arg)); \
		LOCKRET(pthread_attr_getstacksize(&attr, &stacksize)); \
		verbose(VERB_ALGO, "Thread stack size set to %u", (unsigned)stacksize); \
	} else {LOCKRET(pthread_create(thr, NULL, func, arg));} \
	} while(0)
#define PTHREADSTACKSIZE 2*1024*1024
#define THREADS_DISABLED 1
#  define USE_THREAD_DEBUG

#define checklock_start() 
#define checklock_stop() 
#define lock_basic_destroy(lock) LOCKRET(pthread_mutex_destroy(lock))
#define lock_basic_init(lock) LOCKRET(pthread_mutex_init(lock, NULL))
#define lock_basic_lock(lock) LOCKRET(pthread_mutex_lock(lock))
#define lock_basic_unlock(lock) LOCKRET(pthread_mutex_unlock(lock))
#define lock_protect(lock, area, size) 
#define lock_quick_destroy(lock) LOCKRET(pthread_mutex_destroy(lock))
#define lock_quick_init(lock) LOCKRET(pthread_mutex_init(lock, NULL))
#define lock_quick_lock(lock) LOCKRET(pthread_mutex_lock(lock))
#define lock_quick_unlock(lock) LOCKRET(pthread_mutex_unlock(lock))
#define lock_rw_destroy(lock) LOCKRET(pthread_mutex_destroy(lock))
#define lock_rw_init(lock) LOCKRET(pthread_mutex_init(lock, NULL))
#define lock_rw_rdlock(lock) LOCKRET(pthread_mutex_lock(lock))
#define lock_rw_unlock(lock) LOCKRET(pthread_mutex_unlock(lock))
#define lock_rw_wrlock(lock) LOCKRET(pthread_mutex_lock(lock))
#define lock_unprotect(lock, area) 
#define ub_thread_create(thr, func, arg) PTHREADCREATE(thr, PTHREADSTACKSIZE, func, arg)
#define ub_thread_join(thread) LOCKRET(pthread_join(thread, NULL))
#define ub_thread_key_create(key, f) LOCKRET(pthread_key_create(key, f))
#define ub_thread_key_get(key) pthread_getspecific(key)
#define ub_thread_key_set(key, v) LOCKRET(pthread_setspecific(key, v))
#define ub_thread_self() pthread_self()

#define THRDEBUG_MAX_THREADS 32 

#  define log_assert(x) \
	do { if(!(x)) \
		fatal_exit("%s:%d: %s: assertion %s failed", \
			"__FILE__", "__LINE__", __func__, #x); \
	} while(0);

#define BIT_AA 0x0400
#define BIT_AD 0x0020
#define BIT_CD 0x0010
#define BIT_QR 0x8000
#define BIT_RA 0x0080
#define BIT_RD 0x0100
#define BIT_TC 0x0200
#define BIT_Z  0x0040
#define DNSKEY_BIT_SEP 0x0001
#define DNSKEY_BIT_ZSK 0x0100
#define EDNS_ADVERTISED_VERSION         0
#define EDNS_DO 0x8000 
#define FLAGS_GET_RCODE(f) ((f) & 0xf)
#define FLAGS_SET_RCODE(f, r) (f = (((f) & 0xfff0) | (r)))
#define INET6_SIZE 16
#define INET_SIZE 4

#define TCP_AUTH_QUERY_TIMEOUT 3000
#define UDP_AUTH_QUERY_TIMEOUT 3000


#define fptr_ok(x) 
#define MESH_MAX_ACTIVATION 10000
#define MESH_MAX_SUBSUB 1024


#define MAX_KNOWN_EDNS_OPTS 256
#define MAX_MODULE 16

#define LABEL_IS_PTR(x) ( ((x)&0xc0) == 0xc0 )
#define NORR_TTL 5 
#define PARSE_TABLE_SIZE 32
#define PTR_CREATE(offset) ((uint16_t)(0xc000 | (offset)))
#define PTR_MAX_OFFSET 	0x3fff
#define PTR_OFFSET(x, y) ( ((x)&0x3f)<<8 | (y) )

#define LDNS_APL_IP4            1
#define LDNS_APL_IP6            2
#define LDNS_APL_MASK           0x7f
#define LDNS_APL_NEGATION       0x80
#define LDNS_DNSSEC_KEYPROTO    3
#define LDNS_EDNS_MASK_DO_BIT 0x8000
#define LDNS_KEY_REVOKE_KEY 0x0080 
#define LDNS_KEY_SEP_KEY    0x0001 
#define LDNS_KEY_ZONE_KEY   0x0100 
#define LDNS_MAX_DOMAINLEN    255
#define LDNS_MAX_LABELLEN     63
#define LDNS_NSEC3_VARS_OPTOUT_MASK 0x01
#define LDNS_RDATA_FIELD_DESCRIPTORS_COMMON 259
#define LDNS_RDF_SIZE_16BYTES           16
#define LDNS_RDF_SIZE_6BYTES            6
#define LDNS_RDF_SIZE_8BYTES            8
#define LDNS_RDF_SIZE_BYTE              1
#define LDNS_RDF_SIZE_DOUBLEWORD        4
#define LDNS_RDF_SIZE_WORD              2

#define LDNS_TSIG_ERROR_BADALG   21
#define LDNS_TSIG_ERROR_BADKEY   17
#define LDNS_TSIG_ERROR_BADMODE  19
#define LDNS_TSIG_ERROR_BADNAME  20
#define LDNS_TSIG_ERROR_BADSIG   16
#define LDNS_TSIG_ERROR_BADTIME  18
#define LDNS_TSIG_ERROR_NOERROR  0

#define NETEVENT_CAPSFAIL -3
#define NETEVENT_CLOSED -1
#define NETEVENT_DONE -4
#define NETEVENT_NOERROR 0
#define NETEVENT_SLOW_ACCEPT_TIME 2000
#define NETEVENT_TIMEOUT -2 

# define DNSCRYPT_BLOCK_SIZE 64U
#define DNSCRYPT_MAGIC_HEADER_LEN 8U
#define DNSCRYPT_MAGIC_RESPONSE  "r6fnvWj8"
# define DNSCRYPT_MAX_PADDING 256U
# define DNSCRYPT_MIN_PAD_LEN 8U
#define DNSCRYPT_QUERY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + crypto_box_MACBYTES)
#define DNSCRYPT_REPLY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_HALF_NONCEBYTES * 2 + crypto_box_MACBYTES)
#define DNSCRYPT_RESPONSE_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_NONCEBYTES + crypto_box_MACBYTES)

#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)
#define CERT_FILE_EXPIRE_DAYS 365
#define CERT_MAGIC_CERT "DNSC"
#define CERT_MAJOR_VERSION 1
#define CERT_MINOR_VERSION 0
#define CERT_OLD_MAGIC_HEADER "7PYqwfzt"

#define RBTREE_FOR(node, type, rbtree) \
	for(node=(type)rbtree_first(rbtree); \
		(rbnode_type*)node != RBTREE_NULL; \
		node = (type)rbtree_next((rbnode_type*)node))




