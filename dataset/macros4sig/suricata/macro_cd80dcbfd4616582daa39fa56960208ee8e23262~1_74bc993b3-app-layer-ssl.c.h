#include<unistd.h>



#include<mm_malloc.h>
#include<stdint.h>
#include<threads.h>
#include<inttypes.h>
#include<linux/if_packet.h>
#include<malloc.h>





#include<arpa/inet.h>




#include<signal.h>



#include<assert.h>


#include<netinet/in.h>





#include<ctype.h>






#include<limits.h>

#include<sys/param.h>
#include<sys/syscall.h>
#include<time.h>
#include<stdarg.h>
#include<sys/resource.h>
#include<sys/signal.h>

#include<stdio.h>
#include<fcntl.h>



#include<sys/types.h>
#include<pthread.h>

#include<sched.h>



#include<syslog.h>




#include<byteswap.h>



#include<sys/stat.h>





#include<poll.h>


#include<sys/time.h>
#include<linux/netfilter.h>

#include<errno.h>


#include<string.h>
#include<netdb.h>
#include<stdlib.h>
#include<sys/socket.h>

#include<syscall.h>

#include<sys/prctl.h>
#define BYTE_BIG_ENDIAN      0
#define BYTE_LITTLE_ENDIAN   1
#define SCByteSwap16(x) bswap16(x)
#define SCByteSwap32(x) bswap32(x)
#define SCByteSwap64(x) bswap64(x)

#define FLOW_DEFAULT_CLOSED_TIMEOUT 0
#define FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT 0
#define FLOW_DEFAULT_EMERG_EST_TIMEOUT 100
#define FLOW_DEFAULT_EMERG_NEW_TIMEOUT 10
#define FLOW_DEFAULT_EST_TIMEOUT 300
#define FLOW_DEFAULT_NEW_TIMEOUT 30
#define FLOW_EMERGENCY   0x01
#define FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_ICMP_EST_TIMEOUT 300
#define FLOW_IPPROTO_ICMP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_TCP_EST_TIMEOUT 300
#define FLOW_IPPROTO_TCP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_UDP_EST_TIMEOUT 300
#define FLOW_IPPROTO_UDP_NEW_TIMEOUT 30

#define SCAtomicAddAndFetch(addr, value) \
    __sync_add_and_fetch((addr), (value))
#define SCAtomicCompareAndSwap(addr, tv, nv) \
    __sync_bool_compare_and_swap((addr), (tv), (nv))
#define SCAtomicFetchAndAdd(addr, value) \
    __sync_fetch_and_add((addr), (value))
#define SCAtomicFetchAndAnd(addr, value) \
    __sync_fetch_and_and((addr), (value))
#define SCAtomicFetchAndNand(addr, value) \
    __sync_fetch_and_nand((addr), (value))
#define SCAtomicFetchAndOr(addr, value) \
    __sync_fetch_and_or((addr), (value))
#define SCAtomicFetchAndSub(addr, value) \
    __sync_fetch_and_sub((addr), (value))
#define SCAtomicFetchAndXor(addr, value) \
    __sync_fetch_and_xor((addr), (value))
#define SCAtomicSubAndFetch(addr, value) \
    __sync_sub_and_fetch((addr), (value))
#define SC_ATOMIC_ADD(name, val) ({\
    typeof(name ## _sc_atomic__) var; \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) += (val); \
        var = (name ## _sc_atomic__); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0); \
    var ; \
})
#define SC_ATOMIC_AND(name, val) \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) &= (val); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0)
#define SC_ATOMIC_CAS(name, cmpval, newval) ({ \
    char r = 0; \
    do { \
        SCSpinLock((name ## _sc_lock__)); \
        if (*(name ## _sc_atomic__) == (cmpval)) { \
            *(name ## _sc_atomic__) = (newval); \
            r = 1; \
        } \
        SCSpinUnlock((name ## _sc_lock__)); \
    } while(0); \
    r; \
})
#define SC_ATOMIC_DECLARE(type, name) \
    type name ## _sc_atomic__
#define SC_ATOMIC_DECL_AND_INIT(type, name) \
    type name ## _sc_atomic__ = 0

#define SC_ATOMIC_EXTERN(type, name) \
    extern type name ## _sc_atomic__
#define SC_ATOMIC_GET(name) ({ \
    typeof(name ## _sc_atomic__) var; \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        var = (name ## _sc_atomic__); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while (0); \
    var; \
})
#define SC_ATOMIC_INIT(name) \
    (name ## _sc_atomic__) = 0
#define SC_ATOMIC_NAND(name, val) \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) = ~(name ## _sc_atomic__) & (val); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0)
#define SC_ATOMIC_OR(name, val) \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) |= (val); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0)
#define SC_ATOMIC_RESET(name) \
    (name ## _sc_atomic__) = 0
#define SC_ATOMIC_SET(name, val) ({       \
    typeof(name ## _sc_atomic__) var; \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        var = (name ## _sc_atomic__) = val; \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while (0); \
    var; \
})
#define SC_ATOMIC_SUB(name, val) ({ \
    typeof(name ## _sc_atomic__) var; \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) -= (val); \
        var = (name ## _sc_atomic__); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0); \
    var ; \
})
#define SC_ATOMIC_XOR(name, val) \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) ^= (val); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0)

    #define FQLOCK_DESTROY(q) SCSpinDestroy(&(q)->s)
    #define FQLOCK_INIT(q) SCSpinInit(&(q)->s, 0)
    #define FQLOCK_LOCK(q) SCSpinLock(&(q)->s)

    #define FQLOCK_TRYLOCK(q) SCSpinTrylock(&(q)->s)
    #define FQLOCK_UNLOCK(q) SCSpinUnlock(&(q)->s)

    #define FLOWLOCK_DESTROY(fb) SCRWLockDestroy(&(fb)->r)
    #define FLOWLOCK_INIT(fb) SCRWLockInit(&(fb)->r, NULL)

    #define FLOWLOCK_RDLOCK(fb) SCRWLockRDLock(&(fb)->r)
    #define FLOWLOCK_TRYRDLOCK(fb) SCRWLockTryRDLock(&(fb)->r)
    #define FLOWLOCK_TRYWRLOCK(fb) SCRWLockTryWRLock(&(fb)->r)
    #define FLOWLOCK_UNLOCK(fb) SCRWLockUnlock(&(fb)->r)
    #define FLOWLOCK_WRLOCK(fb) SCRWLockWRLock(&(fb)->r)
#define FLOW_ACTION_DROP                  0x00000200
#define FLOW_ALPROTO_DETECT_DONE          0x00008000
#define FLOW_CLEAR_ADDR(a) do {  \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)
#define FLOW_COPY_IPV4_ADDR_TO_PACKET(fa, pa) do {      \
        (pa)->family = AF_INET;                         \
        (pa)->addr_data32[0] = (fa)->addr_data32[0];    \
    } while (0)
#define FLOW_COPY_IPV6_ADDR_TO_PACKET(fa, pa) do {      \
        (pa)->family = AF_INET;                         \
        (pa)->addr_data32[0] = (fa)->addr_data32[0];    \
        (pa)->addr_data32[1] = (fa)->addr_data32[1];    \
        (pa)->addr_data32[2] = (fa)->addr_data32[2];    \
        (pa)->addr_data32[3] = (fa)->addr_data32[3];    \
    } while (0)
#define FLOW_FILE_NO_MAGIC_TC             0x00000010
#define FLOW_FILE_NO_MAGIC_TS             0x00000008
#define FLOW_FILE_NO_MD5_TC               0x20000000
#define FLOW_FILE_NO_MD5_TS               0x10000000
#define FLOW_FILE_NO_SIZE_TC              0x80000000
#define FLOW_FILE_NO_SIZE_TS              0x40000000
#define FLOW_FILE_NO_STORE_TC             0x02000000
#define FLOW_FILE_NO_STORE_TS             0x01000000
#define FLOW_IPV4                         0x04000000
#define FLOW_IPV6                         0x08000000
#define FLOW_IS_IPV4(f) \
    (((f)->flags & FLOW_IPV4) == FLOW_IPV4)
#define FLOW_IS_IPV6(f) \
    (((f)->flags & FLOW_IPV6) == FLOW_IPV6)
#define FLOW_NOPACKET_INSPECTION          0x00000080
#define FLOW_NOPAYLOAD_INSPECTION         0x00000100
#define FLOW_NO_APPLAYER_INSPECTION       0x00010000
#define FLOW_PKT_ESTABLISHED            0x04
#define FLOW_PKT_NOSTREAM               0x40
#define FLOW_PKT_ONLYSTREAM             0x80
#define FLOW_PKT_STATELESS              0x08
#define FLOW_PKT_TOCLIENT               0x02
#define FLOW_PKT_TOCLIENT_IPONLY_SET    0x20
#define FLOW_PKT_TOSERVER               0x01
#define FLOW_PKT_TOSERVER_IPONLY_SET    0x10
#define FLOW_QUIET      TRUE
#define FLOW_SET_IPV4_DST_ADDR_FROM_PACKET(p, a) do {             \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)
#define FLOW_SET_IPV4_SRC_ADDR_FROM_PACKET(p, a) do {             \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)
#define FLOW_SET_IPV6_DST_ADDR_FROM_PACKET(p, a) do {   \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)
#define FLOW_SET_IPV6_SRC_ADDR_FROM_PACKET(p, a) do {   \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)
#define FLOW_SGH_TOCLIENT                 0x00001000
#define FLOW_SGH_TOSERVER                 0x00000800
#define FLOW_TC_PM_ALPROTO_DETECT_DONE    0x00100000
#define FLOW_TC_PM_PP_ALPROTO_DETECT_DONE 0x00400000
#define FLOW_TC_PP_ALPROTO_DETECT_DONE    0x00200000
#define FLOW_TIMEOUT_REASSEMBLY_DONE      0x00800000
#define FLOW_TOCLIENT_DROP_LOGGED         0x00004000
#define FLOW_TOCLIENT_IPONLY_SET          0x00000040
#define FLOW_TOSERVER_DROP_LOGGED         0x00002000
#define FLOW_TOSERVER_IPONLY_SET          0x00000020
#define FLOW_TO_DST_SEEN                  0x00000002
#define FLOW_TO_SRC_SEEN                  0x00000001
#define FLOW_TS_PM_ALPROTO_DETECT_DONE    0x00020000
#define FLOW_TS_PM_PP_ALPROTO_DETECT_DONE 0x00080000
#define FLOW_TS_PP_ALPROTO_DETECT_DONE    0x00040000
#define FLOW_VERBOSE    FALSE
#define FlowDeReference(src_f_ptr) do {               \
        if (*(src_f_ptr) != NULL) {                   \
            FlowDecrUsecnt(*(src_f_ptr));             \
            *(src_f_ptr) = NULL;                      \
        }                                             \
    } while (0)
#define FlowReference(dst_f_ptr, f) do {            \
        if ((f) != NULL) {                          \
            FlowIncrUsecnt((f));                    \
            *(dst_f_ptr) = f;                       \
        }                                           \
    } while (0)
#define TOCLIENT 1
#define TOSERVER 0

#define addr_data16 address.address_un_data16
#define addr_data32 address.address_un_data32
#define addr_data8  address.address_un_data8
#define DETECT_TAG_MATCH_LIMIT 10
#define DETECT_TAG_MAX_PKTS 256
#define DETECT_TAG_MAX_TAGS 50
#define TAG_ENTRY_FLAG_DIR_DST          0x02
#define TAG_ENTRY_FLAG_DIR_SRC          0x01
#define TAG_ENTRY_FLAG_SKIPPED_FIRST    0x04


#  define CONFIG_DIR "/etc/suricata"
#define DEFAULT_CONF_FILE CONFIG_DIR "/suricata.yaml"
#define DEFAULT_PID_BASENAME "suricata.pid"
#define DEFAULT_PID_DIR LOCAL_STATE_DIR "/run/"
#define DEFAULT_PID_FILENAME DEFAULT_PID_DIR DEFAULT_PID_BASENAME
#define IS_ENGINE_MODE_IDS(engine_mode)  ((engine_mode) == ENGINE_MODE_IDS)
#define IS_ENGINE_MODE_IPS(engine_mode)  ((engine_mode) == ENGINE_MODE_IPS)
#define PROG_NAME "Suricata"
#define PROG_VER "2.0dev"
#define SET_ENGINE_MODE_IDS(engine_mode) do { \
	    (engine_mode) = ENGINE_MODE_IDS; \
    } while (0)
#define SET_ENGINE_MODE_IPS(engine_mode) do { \
	    (engine_mode) = ENGINE_MODE_IPS; \
    } while (0)
#define SURICATA_DONE    (1 << 2)   
#define SURICATA_KILL    (1 << 1)   
#define SURICATA_STOP    (1 << 0)   

#define u8_tolower(c) tolower((uint8_t)(c))

#define SCCondDestroy pthread_cond_destroy
#define SCCondInit pthread_cond_init
#define SCCondSignal pthread_cond_signal
#define SCCondT pthread_cond_t
#define SCCondTimedwait pthread_cond_timedwait
#define SCCondWait SCondWait_dbg
#define SCCondWait_dbg(cond, mut) ({ \
    int ret = pthread_cond_wait(cond, mut); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid (or a SCCondT not initialized!)\n"); \
        printf("%16s(%s:%d): (thread:%"PRIuMAX") failed SCCondWait %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, retu); \
        break; \
    } \
    ret; \
})
#define SCGetThreadIdLong(...) ({ \
    long tmpthid; \
    thr_self(&tmpthid); \
    u_long tid = (u_long)tmpthid; \
    tid; \
})
#define SCMUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexDestroy pthread_mutex_destroy
#define SCMutexInit(mut, mutattrs) SCMutexInit_dbg(mut, mutattrs)
#define SCMutexInit_dbg(mut, mutattr) ({ \
    int ret; \
    ret = pthread_mutex_init(mut, mutattr); \
    if (ret != 0) { \
        switch (ret) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, ret); \
            break; \
            case EAGAIN: \
            printf("The system temporarily lacks the resources to create another mutex\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, ret); \
            break; \
            case ENOMEM: \
            printf("The process cannot allocate enough memory to create another mutex\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, ret); \
            break; \
        } \
    } \
    ret; \
})
#define SCMutexLock(mut) SCMutexLock_dbg(mut)
#define SCMutexLock_dbg(mut) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking mutex %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut); \
    int retl = pthread_mutex_lock(mut); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locked mutex %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, retl); \
    if (retl != 0) { \
        switch (retl) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            retl = pthread_mutex_init(mut, NULL); \
            if (retl != 0) \
                exit(EXIT_FAILURE); \
            retl = pthread_mutex_lock(mut); \
            break; \
            case EDEADLK: \
            printf("A deadlock would occur if the thread blocked waiting for mutex\n"); \
            break; \
        } \
    } \
    retl; \
})
#define SCMutexLock_profile(mut) ({ \
    mutex_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t mutex_lock_start = UtilCpuGetTicks(); \
    if (pthread_mutex_trylock((mut)) != 0) { \
        mutex_lock_contention++; \
        cont = 1; \
        retl = pthread_mutex_lock(mut); \
    } \
    uint64_t mutex_lock_end = UtilCpuGetTicks();                                \
    mutex_lock_wait_ticks += (uint64_t)(mutex_lock_end - mutex_lock_start);     \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)"__FILE__";                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)"__LINE__";                                  \
        locks[locks_idx].type = LOCK_MUTEX;                                     \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(mutex_lock_end - mutex_lock_start); \
        locks_idx++;                                                            \
    } \
    retl; \
})
#define SCMutexTrylock(mut) SCMutexTrylock_dbg(mut)
#define SCMutexTrylock_dbg(mut) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking mutex %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut); \
    int rett = pthread_mutex_trylock(mut); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked mutex %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, rett); \
    if (rett != 0) { \
        switch (rett) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, "__FILE__", "__LINE__"); \
            break; \
            case EBUSY: \
            printf("Mutex is already locked\n"); \
            break; \
        } \
    } \
    rett; \
})
#define SCMutexUnlock(mut) SCMutexUnlock_dbg(mut)
#define SCMutexUnlock_dbg(mut) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocking mutex %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut); \
    int retu = pthread_mutex_unlock(mut); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocked mutex %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, retu); \
    if (retu != 0) { \
        switch (retu) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, "__FILE__", "__LINE__"); \
            break; \
            case EPERM: \
            printf("The current thread does not hold a lock on mutex\n"); \
            break; \
        } \
    } \
    retu; \
})
#define SCRWLock pthread_rwlock_t
#define SCRWLockDestroy pthread_rwlock_destroy
#define SCRWLockInit(rwl, rwlattrs) SCRWLockInit_dbg(rwl, rwlattrs)
#define SCRWLockInit_dbg(rwl, rwlattr) ({ \
    int ret; \
    ret = pthread_rwlock_init(rwl, rwlattr); \
    if (ret != 0) { \
        switch (ret) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") rwlock %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, ret); \
            break; \
            case EAGAIN: \
            printf("The system temporarily lacks the resources to create another rwlock\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") rwlock %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, ret); \
            break; \
            case ENOMEM: \
            printf("The process cannot allocate enough memory to create another rwlock\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") rwlock %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, ret); \
            break; \
        } \
    } \
    ret; \
})
#define SCRWLockRDLock(rwl) SCRWLockRDLock_dbg(rwl)
#define SCRWLockRDLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking rwlock %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl); \
    int retl = pthread_rwlock_rdlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locked rwlock %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, retl); \
    if (retl != 0) { \
        switch (retl) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            retl = pthread_rwlock_init(rwl, NULL); \
            if (retl != 0) \
                exit(EXIT_FAILURE); \
            retl = pthread_rwlock_rdlock(rwl); \
            break; \
            case EDEADLK: \
            printf("A deadlock would occur if the thread blocked waiting for rwlock\n"); \
            break; \
        } \
    } \
    retl; \
})
#define SCRWLockRDLock_profile(mut) ({ \
    rwr_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t rwr_lock_start = UtilCpuGetTicks(); \
    if (pthread_rwlock_tryrdlock((mut)) != 0) { \
        rwr_lock_contention++; \
        cont = 1; \
        retl = pthread_rwlock_rdlock(mut); \
    } \
    uint64_t rwr_lock_end = UtilCpuGetTicks();                                  \
    rwr_lock_wait_ticks += (uint64_t)(rwr_lock_end - rwr_lock_start);           \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)"__FILE__";                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)"__LINE__";                                  \
        locks[locks_idx].type = LOCK_RWR;                                       \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(rwr_lock_end - rwr_lock_start);     \
        locks_idx++;                                                            \
    } \
    retl; \
})
#define SCRWLockTryRDLock(rwl) SCRWLockTryRDLock_dbg(rwl)
#define SCRWLockTryRDLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking rwlock %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl); \
    int rett = pthread_rwlock_tryrdlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked rwlock %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, rett); \
    if (rett != 0) { \
        switch (rett) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, "__FILE__", "__LINE__"); \
            break; \
            case EBUSY: \
            printf("RWLock is already locked\n"); \
            break; \
        } \
    } \
    rett; \
})
#define SCRWLockTryWRLock(rwl) SCRWLockTryWRLock_dbg(rwl)
#define SCRWLockTryWRLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking rwlock %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl); \
    int rett = pthread_rwlock_trywrlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked rwlock %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, rett); \
    if (rett != 0) { \
        switch (rett) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, "__FILE__", "__LINE__"); \
            break; \
            case EBUSY: \
            printf("RWLock is already locked\n"); \
            break; \
        } \
    } \
    rett; \
})
#define SCRWLockUnlock(rwl) SCRWLockUnlock_dbg(rwl)
#define SCRWLockUnlock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocking rwlock %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl); \
    int retu = pthread_rwlock_unlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocked rwlock %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, retu); \
    if (retu != 0) { \
        switch (retu) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, "__FILE__", "__LINE__"); \
            break; \
            case EPERM: \
            printf("The current thread does not hold a lock on rwlock\n"); \
            break; \
        } \
    } \
    retu; \
})
#define SCRWLockWRLock(rwl) SCRWLockWRLock_dbg(rwl)
#define SCRWLockWRLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking rwlock %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl); \
    int retl = pthread_rwlock_wrlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locked rwlock %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), rwl, retl); \
    if (retl != 0) { \
        switch (retl) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            retl = pthread_rwlock_init(rwl, NULL); \
            if (retl != 0) \
                exit(EXIT_FAILURE); \
            retl = pthread_rwlock_wrlock(rwl); \
            break; \
            case EDEADLK: \
            printf("A deadlock would occur if the thread blocked waiting for rwlock\n"); \
            break; \
        } \
    } \
    retl; \
})
#define SCRWLockWRLock_profile(mut) ({ \
    rww_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t rww_lock_start = UtilCpuGetTicks(); \
    if (pthread_rwlock_trywrlock((mut)) != 0) { \
        rww_lock_contention++; \
        cont = 1; \
        retl = pthread_rwlock_wrlock(mut); \
    } \
    uint64_t rww_lock_end = UtilCpuGetTicks();                                  \
    rww_lock_wait_ticks += (uint64_t)(rww_lock_end - rww_lock_start);           \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)"__FILE__";                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)"__LINE__";                                  \
        locks[locks_idx].type = LOCK_RWW;                                       \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(rww_lock_end - rww_lock_start);     \
        locks_idx++;                                                            \
    } \
    retl; \
})
#define SCSetThreadName(n) ({ \
    char tname[16] = ""; \
    if (strlen(n) > 16) \
        SCLogDebug("Thread name is too long, truncating it..."); \
    strlcpy(tname, n, 16); \
    pthread_set_name_np(pthread_self(), tname); \
    0; \
})
#define SCSpinDestroy                           SCSpinDestroy_dbg
#define SCSpinDestroy_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") condition %p waiting\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_destroy(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") condition %p passed %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EBUSY: \
        printf("A thread currently holds the lock\n"); \
        break; \
        case ENOMEM: \
        printf("The process cannot allocate enough memory to create another spin\n"); \
        break; \
        case EAGAIN: \
        printf("The system temporarily lacks the resources to create another spin\n"); \
        break; \
    } \
    ret; \
})
#define SCSpinInit                              SCSpinInit_dbg
#define SCSpinInit_dbg(spin, spin_attr) ({ \
    int ret = pthread_spin_init(spin, spin_attr); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") spinlock %p initialization returned %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EBUSY: \
        printf("A thread currently holds the lock\n"); \
        break; \
        case ENOMEM: \
        printf("The process cannot allocate enough memory to create another spin\n"); \
        break; \
        case EAGAIN: \
        printf("The system temporarily lacks the resources to create another spin\n"); \
        break; \
    } \
    ret; \
})
#define SCSpinLock                              SCSpinLock_dbg
#define SCSpinLock_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking spin %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_lock(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocked spin %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EDEADLK: \
        printf("A deadlock would occur if the thread blocked waiting for spin\n"); \
        break; \
    } \
    ret; \
})
#define SCSpinLock_profile(spin) ({ \
    spin_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t spin_lock_start = UtilCpuGetTicks(); \
    if (pthread_spin_trylock((spin)) != 0) { \
        spin_lock_contention++; \
        cont = 1;   \
        retl = pthread_spin_lock((spin)); \
    } \
    uint64_t spin_lock_end = UtilCpuGetTicks(); \
    spin_lock_wait_ticks += (uint64_t)(spin_lock_end - spin_lock_start); \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)"__FILE__";                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)"__LINE__";                                  \
        locks[locks_idx].type = LOCK_SPIN;                                      \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(spin_lock_end - spin_lock_start);   \
        locks_idx++;                                                            \
    } \
    retl; \
})
#define SCSpinTrylock                           SCSpinTrylock_dbg
#define SCSpinTrylock_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking spin %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_trylock(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked spin %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EDEADLK: \
        printf("A deadlock would occur if the thread blocked waiting for spin\n"); \
        break; \
        case EBUSY: \
        printf("A thread currently holds the lock\n"); \
        break; \
    } \
    ret; \
})
#define SCSpinUnlock                            SCSpinUnlock_dbg
#define SCSpinUnlock_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocking spin %p\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_unlock(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlockedspin %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EPERM: \
        printf("The calling thread does not hold the lock\n"); \
        break; \
    } \
    ret; \
})
#define SCSpinlock                              SCMutex
#define THREAD_NAME_LEN 16

#define PROFILING_MAX_LOCKS 64



#define CLEAR_ADDR(a) do {       \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)
#define CMP_ADDR(a1, a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1, p2) \
    ((p1) == (p2))
#define COPY_ADDRESS(a, b) do {                    \
        (b)->family = (a)->family;                 \
        (b)->addr_data32[0] = (a)->addr_data32[0]; \
        (b)->addr_data32[1] = (a)->addr_data32[1]; \
        (b)->addr_data32[2] = (a)->addr_data32[2]; \
        (b)->addr_data32[3] = (a)->addr_data32[3]; \
    } while (0)
#define COPY_PORT(a,b) ((b) = (a))

#define DEFAULT_PACKET_SIZE (1500 + ETHERNET_HEADER_LEN)
#define DLT_EN10MB 1
#define DLT_RAW     14  
#define DecodeSetNoPacketInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPACKET_INSPECTION;  \
    } while (0)
#define DecodeSetNoPayloadInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPAYLOAD_INSPECTION;  \
    } while (0)
#define ENGINE_ISSET_EVENT(p, e) ({ \
    int r = 0; \
    uint8_t u; \
    for (u = 0; u < (p)->events.cnt; u++) { \
        if ((p)->events.events[u] == (e)) { \
            r = 1; \
            break; \
        } \
    } \
    r; \
})
#define ENGINE_SET_EVENT(p, e) do { \
    SCLogDebug("p %p event %d", (p), e); \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)
#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_PKT_DATA(p) ((((p)->ext_pkt) == NULL ) ? (p)->pkt : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) ((p)->pkt)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)
#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_TCP_DST_PORT(p)  ((p)->dp)
#define GET_TCP_SRC_PORT(p)  ((p)->sp)
#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))
#define IPPROTO_DCCP 33
#define IPPROTO_SCTP 132
#define IP_GET_IPPROTO(p) \
    (p->proto ? p->proto : \
    (PKT_IS_IPV4((p))? IPV4_GET_IPPROTO((p)) : (PKT_IS_IPV6((p))? IPV6_GET_L4PROTO((p)) : 0)))
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))
#define IS_TUNNEL_PKT(p)            (((p)->flags & PKT_TUNNEL))
#define IS_TUNNEL_PKT_VERDICTED(p)  (((p)->flags & PKT_TUNNEL_VERDICTED))
#define IS_TUNNEL_ROOT_PKT(p)       (IS_TUNNEL_PKT(p) && (p)->root == NULL)
#define LINKTYPE_ETHERNET   DLT_EN10MB
#define LINKTYPE_LINUX_SLL  113
#define LINKTYPE_PPP        9
#define LINKTYPE_RAW        DLT_RAW
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
#define PACKET_ACCEPT(p) PACKET_SET_ACTION(p, ACTION_ACCEPT)
#define PACKET_ALERT(p) PACKET_SET_ACTION(p, ACTION_ALERT)
#define PACKET_ALERT_FLAG_DROP_FLOW     0x01
#define PACKET_ALERT_FLAG_STATE_MATCH   0x02
#define PACKET_ALERT_FLAG_STREAM_MATCH  0x04
#define PACKET_ALERT_MAX 15
#define PACKET_CLEANUP(p) do {                  \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
        }                                       \
        SCMutexDestroy(&(p)->tunnel_mutex);     \
    } while (0)
#define PACKET_DO_RECYCLE(p) do {               \
        CLEAR_ADDR(&(p)->src);                  \
        CLEAR_ADDR(&(p)->dst);                  \
        (p)->sp = 0;                            \
        (p)->dp = 0;                            \
        (p)->proto = 0;                         \
        (p)->recursion_level = 0;               \
        (p)->flags = (p)->flags & PKT_ALLOC;    \
        (p)->flowflags = 0;                     \
        (p)->pkt_src = 0;                       \
        (p)->vlan_id[0] = 0;                    \
        (p)->vlan_id[1] = 0;                    \
        (p)->vlan_idx = 0;                      \
        FlowDeReference(&((p)->flow));          \
        (p)->ts.tv_sec = 0;                     \
        (p)->ts.tv_usec = 0;                    \
        (p)->datalink = 0;                      \
        (p)->action = 0;                        \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
            (p)->pktvar = NULL;                 \
        }                                       \
        (p)->ethh = NULL;                       \
        if ((p)->ip4h != NULL) {                \
            CLEAR_IPV4_PACKET((p));             \
        }                                       \
        if ((p)->ip6h != NULL) {                \
            CLEAR_IPV6_PACKET((p));             \
        }                                       \
        if ((p)->tcph != NULL) {                \
            CLEAR_TCP_PACKET((p));              \
        }                                       \
        if ((p)->udph != NULL) {                \
            CLEAR_UDP_PACKET((p));              \
        }                                       \
        if ((p)->sctph != NULL) {               \
            CLEAR_SCTP_PACKET((p));             \
        }                                       \
        if ((p)->icmpv4h != NULL) {             \
            CLEAR_ICMPV4_PACKET((p));           \
        }                                       \
        if ((p)->icmpv6h != NULL) {             \
            CLEAR_ICMPV6_PACKET((p));           \
        }                                       \
        (p)->ppph = NULL;                       \
        (p)->pppoesh = NULL;                    \
        (p)->pppoedh = NULL;                    \
        (p)->greh = NULL;                       \
        (p)->vlanh[0] = NULL;                   \
        (p)->vlanh[1] = NULL;                   \
        (p)->payload = NULL;                    \
        (p)->payload_len = 0;                   \
        (p)->pktlen = 0;                        \
        (p)->alerts.cnt = 0;                    \
        HostDeReference(&((p)->host_src));      \
        HostDeReference(&((p)->host_dst));      \
        (p)->pcap_cnt = 0;                      \
        (p)->tunnel_rtv_cnt = 0;                \
        (p)->tunnel_tpr_cnt = 0;                \
        SCMutexDestroy(&(p)->tunnel_mutex);     \
        SCMutexInit(&(p)->tunnel_mutex, NULL);  \
        (p)->events.cnt = 0;                    \
        (p)->next = NULL;                       \
        (p)->prev = NULL;                       \
        (p)->root = NULL;                       \
        (p)->livedev = NULL;                    \
        PACKET_RESET_CHECKSUMS((p));            \
        PACKET_PROFILING_RESET((p));            \
    } while (0)
#define PACKET_DROP(p) PACKET_SET_ACTION(p, ACTION_DROP)
#define PACKET_ENGINE_EVENT_MAX 15
#define PACKET_INITIALIZE(p) do {                                       \
        memset((p), 0x00, SIZE_OF_PACKET);                              \
        SCMutexInit(&(p)->tunnel_mutex, NULL);                          \
        PACKET_RESET_CHECKSUMS((p));                                    \
        (p)->pkt = ((uint8_t *)(p)) + sizeof(Packet);                   \
        (p)->livedev = NULL;                                            \
        SCMutexInit(&(p)->cuda_pkt_vars.cuda_mutex, NULL);            \
        SCCondInit(&(p)->cuda_pkt_vars.cuda_cond, NULL);                \
    } while (0)
#define PACKET_PASS(p) PACKET_SET_ACTION(p, ACTION_PASS)
#define PACKET_RECYCLE(p) PACKET_DO_RECYCLE((p))
#define PACKET_REJECT(p) PACKET_SET_ACTION(p, (ACTION_REJECT|ACTION_DROP))
#define PACKET_REJECT_BOTH(p) PACKET_SET_ACTION(p, (ACTION_REJECT_BOTH|ACTION_DROP))
#define PACKET_REJECT_DST(p) PACKET_SET_ACTION(p, (ACTION_REJECT_DST|ACTION_DROP))
#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->ip4vars.comp_csum = -1;   \
        (p)->tcpvars.comp_csum = -1;      \
        (p)->udpvars.comp_csum = -1;      \
        (p)->icmpv4vars.comp_csum = -1;   \
        (p)->icmpv6vars.comp_csum = -1;   \
    } while (0)
#define PACKET_SET_ACTION(p, a) do { \
    ((p)->root ? \
     ((p)->root->action = a) : \
     ((p)->action = a)); \
} while (0)
#define PACKET_TEST_ACTION(p, a) \
    ((p)->root ? \
     ((p)->root->action & a) : \
     ((p)->action & a))
#define PACKET_UPDATE_ACTION(p, a) do { \
    ((p)->root ? \
     ((p)->root->action |= a) : \
     ((p)->action |= a)); \
} while (0)
#define PKT_ALLOC                       (1<<3)      
#define PKT_HAS_FLOW                    (1<<8)
#define PKT_HAS_TAG                     (1<<4)      
#define PKT_HOST_DST_LOOKED_UP          (1<<18)
#define PKT_HOST_SRC_LOOKED_UP          (1<<17)
#define PKT_IGNORE_CHECKSUM             (1<<15)     
#define PKT_IS_FRAGMENT                 (1<<19)     
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_PSEUDOPKT(p) ((p)->flags & PKT_PSEUDO_STREAM_END)
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_MARK_MODIFIED               (1<<11)     
#define PKT_NOPACKET_INSPECTION         (1)         
#define PKT_NOPAYLOAD_INSPECTION        (1<<2)      
#define PKT_PSEUDO_STREAM_END           (1<<9)      
#define PKT_SET_SRC(p, src_val) ((p)->pkt_src = src_val)
#define PKT_STREAM_ADD                  (1<<5)      
#define PKT_STREAM_EOF                  (1<<7)      
#define PKT_STREAM_EST                  (1<<6)      
#define PKT_STREAM_MODIFIED             (1<<10)     
#define PKT_STREAM_NOPCAPLOG            (1<<12)     
#define PKT_TUNNEL                      (1<<13)
#define PKT_TUNNEL_VERDICTED            (1<<14)
#define PKT_ZERO_COPY                   (1<<16)     
#define PPP_OVER_GRE        11
#define SET_IPV4_DST_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)
#define SET_IPV4_SRC_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)
#define SET_IPV6_DST_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)
#define SET_IPV6_SRC_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)
#define SET_PKT_LEN(p, len) do { \
    (p)->pktlen = (len); \
    } while (0)
#define SET_PORT(v, p) ((p) = (v))
#define SET_SCTP_DST_PORT(pkt, prt) do {            \
        SET_PORT(SCTP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_SCTP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(SCTP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_TCP_DST_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_TCP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_TUNNEL_PKT(p)           ((p)->flags |= PKT_TUNNEL)
#define SET_TUNNEL_PKT_VERDICTED(p) ((p)->flags |= PKT_TUNNEL_VERDICTED)
#define SET_UDP_DST_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_UDP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SIZE_OF_PACKET (default_packet_size + sizeof(Packet))
#define TUNNEL_DECR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_tpr_cnt-- : (p)->tunnel_tpr_cnt--);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)
#define TUNNEL_DECR_PKT_TPR_NOLOCK(p) do {                                          \
        ((p)->root ? (p)->root->tunnel_tpr_cnt-- : (p)->tunnel_tpr_cnt--);          \
    } while (0)
#define TUNNEL_INCR_PKT_RTV(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_rtv_cnt++ : (p)->tunnel_rtv_cnt++);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)
#define TUNNEL_INCR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_tpr_cnt++ : (p)->tunnel_tpr_cnt++);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)
#define TUNNEL_PKT_RTV(p) ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)
#define VLAN_OVER_GRE       13

#define BLOOMSIZE_HIGH          2048    
#define BLOOMSIZE_LOW           512     
#define BLOOMSIZE_MEDIUM        1024    
#define DEFAULT_MPM   MPM_AC_TILE
#define HASHSIZE_HIGH           16384   
#define HASHSIZE_HIGHER         32768   
#define HASHSIZE_LOW            4096    
#define HASHSIZE_LOWEST         2048    
#define HASHSIZE_MAX            65536   
#define HASHSIZE_MEDIUM         8192    
#define MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD 0x01
#define MPM_CTX_FACTORY_UNIQUE_CONTEXT -1
#define MPM_ENDMATCH_DEPTH      0x04    
#define MPM_ENDMATCH_NOSEARCH   0x08    
#define MPM_ENDMATCH_OFFSET     0x02    
#define MPM_ENDMATCH_SINGLE     0x01    
#define MPM_PATTERN_FLAG_DEPTH      0x04
#define MPM_PATTERN_FLAG_NEGATED    0x02
#define MPM_PATTERN_FLAG_NOCASE     0x01
#define MPM_PATTERN_FLAG_OFFSET     0x08
#define MPM_PATTERN_ONE_BYTE        0x10
#define UTIL_MPM_CUDA_BATCHING_TIMEOUT_DEFAULT 2000
#define UTIL_MPM_CUDA_CUDA_BUFFER_DBUFFER_SIZE_DEFAULT 500 * 1024 * 1024
#define UTIL_MPM_CUDA_CUDA_BUFFER_OPBUFFER_ITEMS_DEFAULT 500000
#define UTIL_MPM_CUDA_CUDA_STREAMS_DEFAULT 2
#define UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MAX_LIMIT_DEFAULT 1500
#define UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MIN_LIMIT_DEFAULT 0
#define UTIL_MPM_CUDA_DEVICE_ID_DEFAULT 0
#define UTIL_MPM_CUDA_GPU_TRANSFER_SIZE 50 * 1024 * 1024

#define BUG_ON(x) assert(!(x))
#define CLS 64

#define FALSE  0
#define PatIntId uint16_t
#define SigIntId uint16_t
#define TRUE   1

#define _WIN32_WINNT 0x0501

#define __BIG_ENDIAN BIG_ENDIAN
#define __BYTE_ORDER BYTE_ORDER
#define __LITTLE_ENDIAN LITTLE_ENDIAN


			#define __WORDSIZE 64
#define str(s) #s
#define xstr(s) str(s)



#define cc_barrier() __asm__ __volatile__("": : :"memory")
#define hw_barrier() __sync_synchronize()
#define likely(expr) __builtin_expect(!!(expr), 1)
#define unlikely(expr) __builtin_expect(!!(expr), 0)

#define ADDRESS_FLAG_ANY            0x01 
#define ADDRESS_FLAG_NOT            0x02 
#define ADDRESS_HAVEPORT            0x20 
#define ADDRESS_PORTS_COPY          0x08 
#define ADDRESS_PORTS_NOTUNIQ       0x10
#define ADDRESS_SIGGROUPHEAD_COPY   0x04 
#define COUNTER_DETECT_ALERTS 1
#define DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET 0x0001
#define DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM 0x0002
#define DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH 0x0004
#define DETECT_FILESTORE_MAX 15
#define DETECT_FLOWVAR_TYPE_ALWAYS      2
#define DETECT_FLOWVAR_TYPE_POSTMATCH   1
#define DETECT_SMSG_PMQ_NUM 256
#define DE_QUIET           0x01     
#define FILE_SIG_NEED_FILE          0x01
#define FILE_SIG_NEED_FILECONTENT   0x10
#define FILE_SIG_NEED_FILENAME      0x02
#define FILE_SIG_NEED_MAGIC         0x08    
#define FILE_SIG_NEED_MD5           0x20
#define FILE_SIG_NEED_SIZE          0x40
#define FILE_SIG_NEED_TYPE          0x04
#define FLOW_STATES 2
#define PORT_FLAG_ANY           0x01 
#define PORT_FLAG_NOT           0x02 
#define PORT_GROUP_PORTS_COPY   0x08 
#define PORT_SIGGROUPHEAD_COPY  0x04 
#define SIGMATCH_DEONLY_COMPAT  (1 << 2)
#define SIGMATCH_IPONLY_COMPAT  (1 << 1)
#define SIGMATCH_NOOPT          (1 << 0)
#define SIGMATCH_NOT_BUILT      (1 << 4)
#define SIGMATCH_PAYLOAD        (1 << 3)
#define SIG_FLAG_APPLAYER               (1<<6)  
#define SIG_FLAG_DP_ANY                 (1<<3)  
#define SIG_FLAG_DSIZE                  (1<<5)  
#define SIG_FLAG_DST_ANY                (1<<1)  
#define SIG_FLAG_FILESTORE              (1<<18) 
#define SIG_FLAG_INIT_BIDIREC        (1<<3)  
#define SIG_FLAG_INIT_DEONLY         1  
#define SIG_FLAG_INIT_FLOW           (1<<2)  
#define SIG_FLAG_INIT_PACKET         (1<<1)  
#define SIG_FLAG_INIT_PAYLOAD        (1<<4)  
#define SIG_FLAG_IPONLY                 (1<<7) 
#define SIG_FLAG_MPM_APPLAYER           (1<<15)
#define SIG_FLAG_MPM_APPLAYER_NEG       (1<<16)
#define SIG_FLAG_MPM_PACKET             (1<<11)
#define SIG_FLAG_MPM_PACKET_NEG         (1<<12)
#define SIG_FLAG_MPM_STREAM             (1<<13)
#define SIG_FLAG_MPM_STREAM_NEG         (1<<14)
#define SIG_FLAG_NOALERT                (1<<4)  
#define SIG_FLAG_REQUIRE_FLOWVAR        (1<<17) 
#define SIG_FLAG_REQUIRE_PACKET         (1<<9) 
#define SIG_FLAG_REQUIRE_STREAM         (1<<10) 
#define SIG_FLAG_SP_ANY                 (1<<2)  
#define SIG_FLAG_SRC_ANY                (1)  
#define SIG_FLAG_STATE_MATCH            (1<<8) 
#define SIG_FLAG_TLSSTORE               (1<<21)
#define SIG_FLAG_TOCLIENT               (1<<20)
#define SIG_FLAG_TOSERVER               (1<<19)
#define SIG_GROUP_HEAD_FREE             (1 << 16)
#define SIG_GROUP_HEAD_HAVEFILEMAGIC    (1 << 20)
#define SIG_GROUP_HEAD_HAVEFILEMD5      (1 << 21)
#define SIG_GROUP_HEAD_HAVEFILESIZE     (1 << 22)
#define SIG_GROUP_HEAD_MPM_COPY         (1 << 13)
#define SIG_GROUP_HEAD_MPM_DNSQUERY     (1 << 23)
#define SIG_GROUP_HEAD_MPM_HCBD         (1 << 1)
#define SIG_GROUP_HEAD_MPM_HCD          (1 << 5)
#define SIG_GROUP_HEAD_MPM_HHD          (1 << 2)
#define SIG_GROUP_HEAD_MPM_HHHD         (1 << 11)
#define SIG_GROUP_HEAD_MPM_HMD          (1 << 4)
#define SIG_GROUP_HEAD_MPM_HRHD         (1 << 3)
#define SIG_GROUP_HEAD_MPM_HRHHD        (1 << 12)
#define SIG_GROUP_HEAD_MPM_HRUD         (1 << 6)
#define SIG_GROUP_HEAD_MPM_HSBD         (1 << 7)
#define SIG_GROUP_HEAD_MPM_HSCD         (1 << 9)
#define SIG_GROUP_HEAD_MPM_HSMD         (1 << 8)
#define SIG_GROUP_HEAD_MPM_HUAD         (1 << 10)
#define SIG_GROUP_HEAD_MPM_PACKET       (1 << 17)
#define SIG_GROUP_HEAD_MPM_STREAM       (1 << 18)
#define SIG_GROUP_HEAD_MPM_STREAM_COPY  (1 << 15)
#define SIG_GROUP_HEAD_MPM_URI          (1)
#define SIG_GROUP_HEAD_MPM_URI_COPY     (1 << 14)
#define SIG_GROUP_HEAD_REFERENCED       (1 << 19) 
#define SIG_MASK_REQUIRE_DCE_STATE          (1<<6)
#define SIG_MASK_REQUIRE_ENGINE_EVENT       (1<<7)
#define SIG_MASK_REQUIRE_FLAGS_INITDEINIT   (1<<2)    
#define SIG_MASK_REQUIRE_FLAGS_UNUSUAL      (1<<3)    
#define SIG_MASK_REQUIRE_FLOW               (1<<1)
#define SIG_MASK_REQUIRE_HTTP_STATE         (1<<5)
#define SIG_MASK_REQUIRE_NO_PAYLOAD         (1<<4)
#define SIG_MASK_REQUIRE_PAYLOAD            (1<<0)
#define SignatureMask uint8_t

#define TH_ACTION_ALERT     0x01
#define TH_ACTION_DROP      0x02
#define TH_ACTION_LOG       0x08
#define TH_ACTION_PASS      0x04
#define TH_ACTION_REJECT    0x20
#define TH_ACTION_SDROP     0x10
#define TRACK_DST      1
#define TRACK_RULE     3
#define TRACK_SRC      2
#define TYPE_BOTH      2
#define TYPE_DETECTION 4
#define TYPE_LIMIT     1
#define TYPE_RATE      5
#define TYPE_SUPPRESS  6
#define TYPE_THRESHOLD 3

#define CLEAR_TCP_PACKET(p) { \
    (p)->tcph = NULL; \
    (p)->tcpvars.comp_csum = -1; \
    (p)->tcpvars.tcp_opt_cnt = 0; \
    (p)->tcpvars.ts = NULL; \
    (p)->tcpvars.sack = NULL; \
    (p)->tcpvars.sackok = NULL; \
    (p)->tcpvars.ws = NULL; \
    (p)->tcpvars.mss = NULL; \
}
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK((p)->tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT((p)->tcph)
#define TCP_GET_HLEN(p)                      (TCP_GET_OFFSET((p)) << 2)
#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET((p)->tcph)
#define TCP_GET_RAW_ACK(tcph)                ntohl((tcph)->th_ack)
#define TCP_GET_RAW_DST_PORT(tcph)           ntohs((tcph)->th_dport)
#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_SEQ(tcph)                ntohl((tcph)->th_seq)
#define TCP_GET_RAW_SRC_PORT(tcph)           ntohs((tcph)->th_sport)
#define TCP_GET_RAW_URG_POINTER(tcph)        ntohs((tcph)->th_urp)
#define TCP_GET_RAW_WINDOW(tcph)             ntohs((tcph)->th_win)
#define TCP_GET_RAW_X2(tcph)                 ((tcph)->th_offx2 & 0x0f)
#define TCP_GET_SACKOK(p)                    ((p)->tcpvars.sackok ? 1 : 0)
#define TCP_GET_SACK_CNT(p)                  ((p)->tcpvars.sack ? (((p)->tcpvars.sack->len - 2) / 8) : 0)
#define TCP_GET_SACK_PTR(p)                  (p)->tcpvars.sack ? (p)->tcpvars.sack->data : NULL
#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ((p)->tcph)
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT((p)->tcph)
#define TCP_GET_TSECR(p) \
    (uint32_t)ntohl((*(uint32_t *)((p)->tcpvars.ts->data+4)))
#define TCP_GET_TSVAL(p) \
    (uint32_t)ntohl((*(uint32_t *)(p)->tcpvars.ts->data))
#define TCP_GET_URG_POINTER(p)               TCP_GET_RAW_URG_POINTER((p)->tcph)
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW((p)->tcph)
#define TCP_GET_WSCALE(p)                    ((p)->tcpvars.ws ? (((*(uint8_t *)(p)->tcpvars.ws->data) <= TCP_WSCALE_MAX) ? (*(uint8_t *)((p)->tcpvars.ws->data)) : 0) : 0)
#define TCP_HEADER_LEN                       20
#define TCP_ISSET_FLAG_ACK(p)                ((p)->tcph->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_FIN(p)                ((p)->tcph->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_PUSH(p)               ((p)->tcph->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_RES1(p)               ((p)->tcph->th_flags & TH_RES1)
#define TCP_ISSET_FLAG_RES2(p)               ((p)->tcph->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RST(p)                ((p)->tcph->th_flags & TH_RST)
#define TCP_ISSET_FLAG_SYN(p)                ((p)->tcph->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_URG(p)                ((p)->tcph->th_flags & TH_URG)
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 
#define TCP_OPTS                             tcpvars.tcp_opts
#define TCP_OPTS_CNT                         tcpvars.tcp_opt_cnt
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_SACK_MAX_LEN                 34 
#define TCP_OPT_SACK_MIN_LEN                 10 
#define TCP_OPT_TS                           0x08
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_WS                           0x03
#define TCP_OPT_WS_LEN                       3
#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))
#define TCP_WSCALE_MAX                       14
#define TH_ACK                               0x10
#define TH_CWR                               0x80
#define TH_ECN                               0x40
#define TH_FIN                               0x01
#define TH_PUSH                              0x08
#define TH_RST                               0x04
#define TH_SYN                               0x02
#define TH_URG                               0x20

#define CLEAR_IPV4_PACKET(p) do { \
    (p)->ip4h = NULL; \
    (p)->ip4vars.comp_csum = 0; \
    (p)->ip4vars.ip_src_u32 = 0; \
    (p)->ip4vars.ip_dst_u32 = 0; \
    (p)->ip4vars.ip_opt_cnt = 0; \
    (p)->ip4vars.o_rr = NULL; \
    (p)->ip4vars.o_qs = NULL; \
    (p)->ip4vars.o_ts = NULL; \
    (p)->ip4vars.o_sec = NULL; \
    (p)->ip4vars.o_lsrr = NULL; \
    (p)->ip4vars.o_cipso = NULL; \
    (p)->ip4vars.o_sid = NULL; \
    (p)->ip4vars.o_ssrr = NULL; \
    (p)->ip4vars.o_rtralt = NULL; \
} while (0)
#define IPV4_GET_DF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x4000) >> 14)
#define IPV4_GET_HLEN(p) \
    (IPV4_GET_RAW_HLEN((p)->ip4h) << 2)
#define IPV4_GET_IPID(p) \
    (ntohs(IPV4_GET_RAW_IPID((p)->ip4h)))
#define IPV4_GET_IPLEN(p) \
    (ntohs(IPV4_GET_RAW_IPLEN((p)->ip4h)))
#define IPV4_GET_IPOFFSET(p) \
    (_IPV4_GET_IPOFFSET(p) & 0x1fff)
#define IPV4_GET_IPPROTO(p) \
    IPV4_GET_RAW_IPPROTO((p)->ip4h)
#define IPV4_GET_IPTOS(p) \
    IPV4_GET_RAW_IPTOS((p)->ip4h)
#define IPV4_GET_IPTTL(p) \
     IPV4_GET_RAW_IPTTL(p->ip4h)
#define IPV4_GET_MF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x2000) >> 13)
#define IPV4_GET_RAW_HLEN(ip4h)           ((ip4h)->ip_verhl & 0x0f)
#define IPV4_GET_RAW_IPDST(ip4h)          ((ip4h)->s_ip_dst)
#define IPV4_GET_RAW_IPDST_U32(ip4h)      (uint32_t)((ip4h)->s_ip_dst.s_addr)
#define IPV4_GET_RAW_IPID(ip4h)           ((ip4h)->ip_id)
#define IPV4_GET_RAW_IPLEN(ip4h)          ((ip4h)->ip_len)
#define IPV4_GET_RAW_IPOFFSET(ip4h)       ((ip4h)->ip_off)
#define IPV4_GET_RAW_IPPROTO(ip4h)        ((ip4h)->ip_proto)
#define IPV4_GET_RAW_IPSRC(ip4h)          ((ip4h)->s_ip_src)
#define IPV4_GET_RAW_IPSRC_U32(ip4h)      (uint32_t)((ip4h)->s_ip_src.s_addr)
#define IPV4_GET_RAW_IPTOS(ip4h)          ((ip4h)->ip_tos)
#define IPV4_GET_RAW_IPTTL(ip4h)          ((ip4h)->ip_ttl)
#define IPV4_GET_RAW_VER(ip4h)            (((ip4h)->ip_verhl & 0xf0) >> 4)
#define IPV4_GET_RF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x8000) >> 15)
#define IPV4_GET_VER(p) \
    IPV4_GET_RAW_VER((p)->ip4h)
#define IPV4_HEADER_LEN           20    
#define IPV4_OPTMAX               40    
#define IPV4_OPTS                 ip4vars.ip_opts
#define IPV4_OPTS_CNT             ip4vars.ip_opt_cnt
#define IPV4_OPT_CIPSO            0x86  
#define IPV4_OPT_CIPSO_MIN        10    
#define IPV4_OPT_EOL              0x00  
#define IPV4_OPT_LSRR             0x83  
#define IPV4_OPT_NOP              0x01  
#define IPV4_OPT_QS               0x19  
#define IPV4_OPT_QS_MIN           8     
#define IPV4_OPT_ROUTE_MIN        3     
#define IPV4_OPT_RR               0x07  
#define IPV4_OPT_RTRALT           0x94  
#define IPV4_OPT_RTRALT_LEN       4     
#define IPV4_OPT_SEC              0x82  
#define IPV4_OPT_SEC_LEN          11    
#define IPV4_OPT_SID              0x88  
#define IPV4_OPT_SID_LEN          4     
#define IPV4_OPT_SSRR             0x89  
#define IPV4_OPT_TS               0x44  
#define IPV4_OPT_TS_MIN           5     
#define IPV4_SET_RAW_HLEN(ip4h, value)    ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0xf0) | (value & 0x0f)))
#define IPV4_SET_RAW_IPLEN(ip4h, value)   ((ip4h)->ip_len = value)
#define IPV4_SET_RAW_IPPROTO(ip4h, value) ((ip4h)->ip_proto = value)
#define IPV4_SET_RAW_IPTOS(ip4h, value)   ((ip4h)->ip_tos = value)
#define IPV4_SET_RAW_VER(ip4h, value)     ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0x0f) | (value << 4)))
#define _IPV4_GET_IPOFFSET(p) \
    (ntohs(IPV4_GET_RAW_IPOFFSET((p)->ip4h)))

#define s_ip_addrs                        ip4_hdrun1.ip_addrs
#define s_ip_dst                          ip4_hdrun1.ip4_un1.ip_dst
#define s_ip_src                          ip4_hdrun1.ip4_un1.ip_src
#define AppLayerDecoderEventsFreeEvents(devents)            \
    do {                                                    \
        if ((devents) != NULL) {                            \
            if ((devents)->events != NULL)                  \
                SCFree((devents)->events);                  \
        }                                                   \
        SCFree((devents));                                  \
    } while (0)
#define AppLayerDecoderEventsResetEvents(devents)           \
    do {                                                    \
        if ((devents) != NULL) {                            \
            (devents)->cnt = 0;                             \
        }                                                   \
    } while (0)
#define AppLayerDecoderEventsSetEvent(f, event)                         \
    do {                                                                \
        AppLayerParserStateStore *parser_state_store =                  \
            (AppLayerParserStateStore *)(f)->alparser;                  \
        AppLayerDecoderEvents *devents =                                \
            parser_state_store->decoder_events;                         \
        if (devents == NULL) {                                          \
            AppLayerDecoderEvents *new_devents =                        \
                SCMalloc(sizeof(AppLayerDecoderEvents));                \
            if (new_devents == NULL)                                    \
                break;                                                  \
            memset(new_devents, 0, sizeof(AppLayerDecoderEvents));      \
            parser_state_store->decoder_events = new_devents;           \
            devents = new_devents;                                      \
        }                                                               \
        if (devents->cnt == devents->events_buffer_size) {              \
            devents->events = SCRealloc(devents->events,                \
                                        (devents->cnt +                 \
                                         DECODER_EVENTS_BUFFER_STEPS) * \
                                         sizeof(uint8_t));              \
            if (devents->events == NULL) {                              \
                devents->events_buffer_size = 0;                        \
                devents->cnt = 0;                                       \
                break;                                                  \
            }                                                           \
            devents->events_buffer_size += DECODER_EVENTS_BUFFER_STEPS; \
        }                                                               \
        devents->events[devents->cnt++] = (event);                      \
        SCLogDebug("setting app-layer-event %u", (event));              \
    } while (0)
#define AppLayerDecoderEventsSetEventRaw(sevents, event)                \
    do {                                                                \
        AppLayerDecoderEvents *devents = (sevents);                     \
        if (devents == NULL) {                                          \
            AppLayerDecoderEvents *new_devents =                        \
                SCMalloc(sizeof(AppLayerDecoderEvents));                \
            if (new_devents == NULL)                                    \
                break;                                                  \
            memset(new_devents, 0, sizeof(AppLayerDecoderEvents));      \
            (sevents) = devents = new_devents;                          \
        }                                                               \
        if (devents->cnt == devents->events_buffer_size) {              \
            devents->events = SCRealloc(devents->events,                \
                                       (devents->cnt +                  \
                                        DECODER_EVENTS_BUFFER_STEPS) *  \
                                        sizeof(uint8_t));               \
            if (devents->events == NULL) {                              \
                devents->events_buffer_size = 0;                        \
                devents->cnt = 0;                                       \
                (sevents) = NULL;                                       \
                break;                                                  \
            }                                                           \
            devents->events_buffer_size += DECODER_EVENTS_BUFFER_STEPS; \
        }                                                               \
        devents->events[devents->cnt++] = (event);                      \
    } while (0)
#define DECODER_EVENTS_BUFFER_STEPS 5


#define FILE_LOGGED     0x0010
#define FILE_MD5        0x0008
#define FILE_NOMAGIC    0x0002
#define FILE_NOMD5      0x0004
#define FILE_NOSTORE    0x0020
#define FILE_NOTRACK    0x0100 
#define FILE_STORE      0x0040
#define FILE_STORED     0x0080
#define FILE_TRUNCATED  0x0001

#define SC_RADIX_BITTEST(x, y) ((x) & (y))
#define SC_RADIX_NODE_USERDATA(node, type) \
    ((type *)(((node) != NULL) ? (((node)->prefix != NULL) ? \
                (node)->prefix->user_data_result : NULL) : NULL))



#define SCLog(x, ...)         do {                                       \
                                  char _sc_log_msg[SC_LOG_MAX_LOG_MSG_LEN] = ""; \
                                  char *_sc_log_temp = _sc_log_msg;      \
                                  if ( !(                                \
                                      (sc_log_global_log_level >= x) &&  \
                                       SCLogMessage(x, &_sc_log_temp,    \
                                                    "__FILE__",            \
                                                    "__LINE__",            \
                                                    __FUNCTION__)        \
                                       == SC_OK) )                       \
                                  { } else {                             \
                                      snprintf(_sc_log_temp,             \
                                               (SC_LOG_MAX_LOG_MSG_LEN - \
                                                (_sc_log_temp - _sc_log_msg)), \
                                               __VA_ARGS__);             \
                                      SCLogOutputBuffer(x, _sc_log_msg); \
                                  }                                      \
                              } while(0)
#define SCLogAlert(err_code, ...) SCLogErr(SC_LOG_ALERT, err_code, \
                                        __VA_ARGS__)
#define SCLogCritical(err_code, ...) SCLogErr(SC_LOG_CRITICAL, err_code, \
                                           __VA_ARGS__)
#define SCLogDebug(...)                 do { } while (0)
#define SCLogEmerg(err_code, ...) SCLogErr(SC_LOG_EMERGENCY, err_code, \
                                          __VA_ARGS__)
#define SCLogErr(x, err, ...) do {                                       \
                                  char _sc_log_err_msg[SC_LOG_MAX_LOG_MSG_LEN] = ""; \
                                  char *_sc_log_err_temp = _sc_log_err_msg; \
                                  if ( !(                                \
                                      (sc_log_global_log_level >= x) &&  \
                                       SCLogMessage(x, &_sc_log_err_temp,\
                                                    "__FILE__",            \
                                                    "__LINE__",            \
                                                    __FUNCTION__)        \
                                       == SC_OK) )                       \
                                  { } else {                             \
                                      _sc_log_err_temp =                 \
                                                _sc_log_err_temp +       \
                                                snprintf(_sc_log_err_temp, \
                                               (SC_LOG_MAX_LOG_MSG_LEN - \
                                                (_sc_log_err_temp - _sc_log_err_msg)), \
                                               "[ERRCODE: %s(%d)] - ",   \
                                               SCErrorToString(err),     \
                                               err);                     \
                                      if ((_sc_log_err_temp - _sc_log_err_msg) > \
                                          SC_LOG_MAX_LOG_MSG_LEN) {      \
                                          printf("Warning: Log message exceeded message length limit of %d\n",\
                                                 SC_LOG_MAX_LOG_MSG_LEN); \
                                          _sc_log_err_temp = _sc_log_err_msg + \
                                              SC_LOG_MAX_LOG_MSG_LEN;    \
                                      } else {                          \
                                          snprintf(_sc_log_err_temp,    \
                                                   (SC_LOG_MAX_LOG_MSG_LEN - \
                                                    (_sc_log_err_temp - _sc_log_err_msg)), \
                                                   __VA_ARGS__);        \
                                      }                                 \
                                      SCLogOutputBuffer(x, _sc_log_err_msg); \
                                  }                                      \
                              } while(0)
#define SCLogError(err_code, ...) SCLogErr(SC_LOG_ERROR, err_code, \
                                        __VA_ARGS__)
#define SCLogInfo(...) SCLog(SC_LOG_INFO, __VA_ARGS__)
#define SCLogNotice(...) SCLog(SC_LOG_NOTICE, __VA_ARGS__)
#define SCLogWarning(err_code, ...) SCLogErr(SC_LOG_WARNING, err_code, \
                                          __VA_ARGS__)
#define SCReturn                        return
#define SCReturnCT(x, type)             return x
#define SCReturnChar(x)                 return x
#define SCReturnCharPtr(x)              return x
#define SCReturnDbl(x)                  return x
#define SCReturnInt(x)                  return x
#define SCReturnPtr(x, type)            return x
#define SCReturnUInt(x)                 return x
#define SC_LOG_DEF_LOG_FILE "sc_ids_log.log"
#define SC_LOG_DEF_LOG_FORMAT "%t - <%d> - "
#define SC_LOG_DEF_LOG_LEVEL SC_LOG_INFO
#define SC_LOG_DEF_LOG_OP_IFACE SC_LOG_OP_IFACE_CONSOLE
#define SC_LOG_DEF_SYSLOG_FACILITY LOG_LOCAL0
#define SC_LOG_DEF_SYSLOG_FACILITY_STR "local0"
#define SC_LOG_ENV_LOG_FACILITY     "SC_LOG_FACILITY"
#define SC_LOG_ENV_LOG_FILE         "SC_LOG_FILE"
#define SC_LOG_ENV_LOG_FORMAT       "SC_LOG_FORMAT"
#define SC_LOG_ENV_LOG_LEVEL        "SC_LOG_LEVEL"
#define SC_LOG_ENV_LOG_OP_FILTER    "SC_LOG_OP_FILTER"
#define SC_LOG_ENV_LOG_OP_IFACE     "SC_LOG_OP_IFACE"
#define SC_LOG_FMT_FILE_NAME        'f' 
#define SC_LOG_FMT_FUNCTION         'n' 
#define SC_LOG_FMT_LINE             'l' 
#define SC_LOG_FMT_LOG_LEVEL        'd' 
#define SC_LOG_FMT_PID              'p' 
#define SC_LOG_FMT_PREFIX           '%'
#define SC_LOG_FMT_TID              'i' 
#define SC_LOG_FMT_TIME             't' 
#define SC_LOG_FMT_TM               'm' 
#define SC_LOG_MAX_LOG_FORMAT_LEN 128
#define SC_LOG_MAX_LOG_MSG_LEN 2048



#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = calloc((nm), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)a); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a)*(nm); \
    if (print_mem_flag == 1) {                                          \
        SCLogInfo("SCCalloc return at %p of size %"PRIuMAX" (nm) %"PRIuMAX, \
            ptrmem, (uintmax_t)(a), (uintmax_t)(nm)); \
    }                                                 \
    (void*)ptrmem; \
})
#define SCFree(a) ({ \
    extern uint8_t print_mem_flag; \
    if (print_mem_flag == 1) {          \
        SCLogInfo("SCFree at %p", (a)); \
    }                                   \
    free((a)); \
})
#define SCFreeAligned(a) ({ \
    _mm_free(a); \
})
#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = malloc((a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            uintmax_t scmalloc_size_ = (uintmax_t)(a); \
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), scmalloc_size_); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
	ptrmem = _mm_malloc((a), (b)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)(a), (uintmax_t)(b)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})
#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = realloc((x), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})
#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    size_t len = strlen((a)); \
    \
    ptrmem = strdup((a)); \
    if (ptrmem == NULL) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)len); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += len; \
    if (print_mem_flag == 1) {                              \
        SCLogInfo("SCStrdup return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)len); \
    }                                \
    (void*)ptrmem; \
})

#define _mm_free(a) free((a))
#define _mm_malloc(a,b) memalign((b),(a))

#define HASHLIST_NO_SIZE 0
#define HashListTableGetListData(hb) (hb)->data
#define HashListTableGetListNext(hb) (hb)->listnext

#define HASH_NO_SIZE 0


#define DETECT_PROTO_ANY            (1 << 0) 
#define DETECT_PROTO_IPV4           (1 << 3) 
#define DETECT_PROTO_IPV6           (1 << 4) 
#define DETECT_PROTO_ONLY_PKT       (1 << 1) 
#define DETECT_PROTO_ONLY_STREAM    (1 << 2) 



#define O_NOFOLLOW 0

#define bzero(s, n) memset(s, 0, n)
#define geteuid() (0)
#define index strchr
#define rindex strrchr


#define openlog(__ident, __option, __facility)
#define setlogmask (__mask)
#define syslog(__pri, __fmt, __param)
#define CUDA_HANDLER_MODULE_DATA_TYPE_CUDA_BUFFER 2
#define CUDA_HANDLER_MODULE_DATA_TYPE_MEMORY_DEVICE 1
#define CUDA_HANDLER_MODULE_DATA_TYPE_MEMORY_HOST 0

#define SC_CUDA_DEFAULT_DEVICE 0
#define SC_CUDA_DEVICE_NAME_MAX_LEN 128

#define DEFAULT_LOG_DIR "C:\\WINDOWS\\Temp"

#define CIRCLEQ_ENTRY(type)						\
struct {								\
	struct type *cqe_next;				\
	struct type *cqe_prev;				\
}
#define CIRCLEQ_FOREACH(var, head, field)				\
	for((var) = CIRCLEQ_FIRST(head);				\
	    (var) != CIRCLEQ_END(head);					\
	    (var) = CIRCLEQ_NEXT(var, field))
#define CIRCLEQ_FOREACH_REVERSE(var, head, field)			\
	for((var) = CIRCLEQ_LAST(head);					\
	    (var) != CIRCLEQ_END(head);					\
	    (var) = CIRCLEQ_PREV(var, field))
#define CIRCLEQ_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;				\
	struct type *cqh_last;				\
}
#define CIRCLEQ_HEAD_INITIALIZER(head)					\
	{ CIRCLEQ_END(&head), CIRCLEQ_END(&head) }
#define CIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm)->field.cqe_next;		\
	(elm)->field.cqe_prev = (listelm);				\
	if ((listelm)->field.cqe_next == CIRCLEQ_END(head))		\
		(head)->cqh_last = (elm);				\
	else								\
		(listelm)->field.cqe_next->field.cqe_prev = (elm);	\
	(listelm)->field.cqe_next = (elm);				\
} while (0)
#define CIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm);				\
	(elm)->field.cqe_prev = (listelm)->field.cqe_prev;		\
	if ((listelm)->field.cqe_prev == CIRCLEQ_END(head))		\
		(head)->cqh_first = (elm);				\
	else								\
		(listelm)->field.cqe_prev->field.cqe_next = (elm);	\
	(listelm)->field.cqe_prev = (elm);				\
} while (0)
#define CIRCLEQ_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.cqe_next = (head)->cqh_first;			\
	(elm)->field.cqe_prev = CIRCLEQ_END(head);			\
	if ((head)->cqh_last == CIRCLEQ_END(head))			\
		(head)->cqh_last = (elm);				\
	else								\
		(head)->cqh_first->field.cqe_prev = (elm);		\
	(head)->cqh_first = (elm);					\
} while (0)
#define CIRCLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.cqe_next = CIRCLEQ_END(head);			\
	(elm)->field.cqe_prev = (head)->cqh_last;			\
	if ((head)->cqh_first == CIRCLEQ_END(head))			\
		(head)->cqh_first = (elm);				\
	else								\
		(head)->cqh_last->field.cqe_next = (elm);		\
	(head)->cqh_last = (elm);					\
} while (0)
#define CIRCLEQ_REPLACE(head, elm, elm2, field) do {			\
	if (((elm2)->field.cqe_next = (elm)->field.cqe_next) ==		\
	    CIRCLEQ_END(head))						\
		(head).cqh_last = (elm2);				\
	else								\
		(elm2)->field.cqe_next->field.cqe_prev = (elm2);	\
	if (((elm2)->field.cqe_prev = (elm)->field.cqe_prev) ==		\
	    CIRCLEQ_END(head))						\
		(head).cqh_first = (elm2);				\
	else								\
		(elm2)->field.cqe_prev->field.cqe_next = (elm2);	\
	_Q_INVALIDATE((elm)->field.cqe_prev);				\
	_Q_INVALIDATE((elm)->field.cqe_next);				\
} while (0)
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
#define SIMPLEQ_REMOVE_HEAD(head, field) do {			\
	if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL) \
		(head)->sqh_last = &(head)->sqh_first;			\
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
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)					\
	for((var) = TAILQ_FIRST(head), \
        (tvar) = TAILQ_FIRST(head) ? TAILQ_NEXT(TAILQ_FIRST(head), field): NULL ; \
	    (var) != TAILQ_END(head);					\
	    (var = tvar), (tvar) = var ? TAILQ_NEXT(var, field): NULL)
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
#define _Q_INVALIDATE(a) ((a) = ((void *)-1))

#define ETHERNET_TYPE_VLAN          0x8100
#define GET_VLAN_CFI(vlanh)         ((ntohs((vlanh)->vlan_cfi) & 0x0100) >> 12)
#define GET_VLAN_ID(vlanh)          ((uint16_t)(ntohs((vlanh)->vlan_cfi) & 0x0FFF))
#define GET_VLAN_PRIORITY(vlanh)    ((ntohs((vlanh)->vlan_cfi) & 0xe000) >> 13)
#define GET_VLAN_PROTO(vlanh)       ((ntohs((vlanh)->protocol)))
#define VLAN_HEADER_LEN 4


#define CLEAR_SCTP_PACKET(p) { \
    (p)->sctph = NULL; \
} while (0)
#define SCTP_GET_DST_PORT(p)                  SCTP_GET_RAW_DST_PORT(p->sctph)
#define SCTP_GET_RAW_DST_PORT(sctph)          ntohs((sctph)->sh_dport)
#define SCTP_GET_RAW_SRC_PORT(sctph)          ntohs((sctph)->sh_sport)
#define SCTP_GET_SRC_PORT(p)                  SCTP_GET_RAW_SRC_PORT(p->sctph)
#define SCTP_HEADER_LEN                       12

#define CLEAR_UDP_PACKET(p) do { \
    (p)->udph = NULL; \
    (p)->udpvars.comp_csum = -1; \
} while (0)
#define UDP_GET_DST_PORT(p)                  UDP_GET_RAW_DST_PORT(p->udph)
#define UDP_GET_LEN(p)                       UDP_GET_RAW_LEN(p->udph)
#define UDP_GET_RAW_DST_PORT(udph)           ntohs((udph)->uh_dport)
#define UDP_GET_RAW_LEN(udph)                ntohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph)           ntohs((udph)->uh_sport)
#define UDP_GET_SRC_PORT(p)                  UDP_GET_RAW_SRC_PORT(p->udph)
#define UDP_HEADER_LEN         8

#define CLEAR_ICMPV6_PACKET(p) do { \
    (p)->icmpv6vars.comp_csum = -1; \
    (p)->icmpv6vars.id = 0; \
    (p)->icmpv6vars.seq = 0; \
    (p)->icmpv6vars.mtu = 0; \
    (p)->icmpv6vars.error_ptr = 0; \
    (p)->icmpv6vars.emb_ipv6h = NULL; \
    (p)->icmpv6vars.emb_tcph = NULL; \
    (p)->icmpv6vars.emb_udph = NULL; \
    (p)->icmpv6vars.emb_icmpv6h = NULL; \
    (p)->icmpv6vars.emb_ip6_src[0] = 0; \
    (p)->icmpv6vars.emb_ip6_src[1] = 0; \
    (p)->icmpv6vars.emb_ip6_src[2] = 0; \
    (p)->icmpv6vars.emb_ip6_src[3] = 0; \
    (p)->icmpv6vars.emb_ip6_proto_next = 0; \
    (p)->icmpv6vars.emb_sport = 0; \
    (p)->icmpv6vars.emb_dport = 0; \
    (p)->icmpv6h = NULL; \
} while(0)
#define ICMP6_DST_UNREACH             1
#define ICMP6_DST_UNREACH_ADDR          3 
#define ICMP6_DST_UNREACH_ADMIN         1 
#define ICMP6_DST_UNREACH_BEYONDSCOPE   2 
#define ICMP6_DST_UNREACH_FAILEDPOLICY  5 
#define ICMP6_DST_UNREACH_NOPORT        4 
#define ICMP6_DST_UNREACH_NOROUTE       0 
#define ICMP6_DST_UNREACH_REJECTROUTE   6 
#define ICMP6_ECHO_REPLY            129
#define ICMP6_ECHO_REQUEST          128
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_PARAMPROB_HEADER        0 
#define ICMP6_PARAMPROB_NEXTHEADER    1 
#define ICMP6_PARAMPROB_OPTION        2 
#define ICMP6_PARAM_PROB              4
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_TIME_EXCEED_REASSEMBLY  1 
#define ICMP6_TIME_EXCEED_TRANSIT     0 
#define ICMPV6_GET_CODE(p)      (p)->icmpv6h->code
#define ICMPV6_GET_CSUM(p)      (p)->icmpv6h->csum
#define ICMPV6_GET_EMB_IPV6(p)     (p)->icmpv6vars.emb_ipv6h
#define ICMPV6_GET_EMB_PROTO(p)    (p)->icmpv6vars.emb_ip6_proto_next
#define ICMPV6_GET_EMB_TCP(p)      (p)->icmpv6vars.emb_tcph
#define ICMPV6_GET_EMB_UDP(p)      (p)->icmpv6vars.emb_udph
#define ICMPV6_GET_EMB_icmpv6h(p)  (p)->icmpv6vars.emb_icmpv6h
#define ICMPV6_GET_ERROR_PTR(p)    (p)->icmpv6h->icmpv6b.icmpv6e.error_ptr
#define ICMPV6_GET_ID(p)        (p)->icmpv6vars.id
#define ICMPV6_GET_MTU(p)          (p)->icmpv6h->icmpv6b.icmpv6e.mtu
#define ICMPV6_GET_SEQ(p)       (p)->icmpv6vars.seq
#define ICMPV6_GET_TYPE(p)      (p)->icmpv6h->type
#define ICMPV6_GET_UNUSED(p)       (p)->icmpv6h->icmpv6b.icmpv6e.unused
#define ICMPV6_HEADER_LEN       8
#define ICMPV6_HEADER_PKT_OFFSET 8
#define MLD_LISTENER_QUERY          130
#define MLD_LISTENER_REDUCTION      132
#define MLD_LISTENER_REPORT         131

#define CLEAR_IPV6_PACKET(p) do { \
    (p)->ip6h = NULL; \
    (p)->ip6vars.ip_opts_len = 0; \
    (p)->ip6vars.l4proto = 0; \
    (p)->ip6eh.ip6fh = NULL; \
    (p)->ip6eh.fh_offset = 0; \
    (p)->ip6eh.ip6rh = NULL; \
    (p)->ip6eh.ip6eh = NULL; \
    (p)->ip6eh.ip6dh1 = NULL; \
    (p)->ip6eh.ip6dh2 = NULL; \
    (p)->ip6eh.ip6hh = NULL; \
    (p)->ip6eh.ip6_exthdrs_cnt = 0; \
} while (0)
#define IPV6OPT_HAO                   0xC9
#define IPV6OPT_JUMBO                 0xC2
#define IPV6OPT_PADN                  0x01
#define IPV6OPT_RA                    0x05
#define IPV6_EXTHDR_AH(p)             (p)->ip6eh.ip6ah
#define IPV6_EXTHDR_DH1(p)            (p)->ip6eh.ip6dh1
#define IPV6_EXTHDR_DH1_HAO(p)        (p)->ip6eh.ip6dh1_opt_hao
#define IPV6_EXTHDR_DH1_JUMBO(p)      (p)->ip6eh.ip6dh1_opt_jumbo
#define IPV6_EXTHDR_DH1_RA(p)         (p)->ip6eh.ip6dh1_opt_ra
#define IPV6_EXTHDR_DH2(p)            (p)->ip6eh.ip6dh2
#define IPV6_EXTHDR_DH2_HAO(p)        (p)->ip6eh.ip6dh2_opt_hao
#define IPV6_EXTHDR_DH2_JUMBO(p)      (p)->ip6eh.ip6dh2_opt_jumbo
#define IPV6_EXTHDR_DH2_RA(p)         (p)->ip6eh.ip6dh2_opt_ra
#define IPV6_EXTHDR_EH(p)             (p)->ip6eh.ip6eh
#define IPV6_EXTHDR_FH(p)             (p)->ip6eh.ip6fh
#define IPV6_EXTHDR_GET_DH1_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_DH1_HDRLEN((p))
#define IPV6_EXTHDR_GET_DH1_NH(p)            IPV6_EXTHDR_GET_RAW_DH1_NH((p))
#define IPV6_EXTHDR_GET_DH2_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_DH2_HDRLEN((p))
#define IPV6_EXTHDR_GET_DH2_NH(p)            IPV6_EXTHDR_GET_RAW_DH2_NH((p))
#define IPV6_EXTHDR_GET_FH_FLAG(p)          IPV6_EXTHDR_GET_RAW_FH_FLAG((p))
#define IPV6_EXTHDR_GET_FH_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_FH_HDRLEN((p))
#define IPV6_EXTHDR_GET_FH_ID(p)            IPV6_EXTHDR_GET_RAW_FH_ID((p))
#define IPV6_EXTHDR_GET_FH_NH(p)            IPV6_EXTHDR_GET_RAW_FH_NH((p))
#define IPV6_EXTHDR_GET_FH_OFFSET(p)        IPV6_EXTHDR_GET_RAW_FH_OFFSET((p))
#define IPV6_EXTHDR_GET_HH_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_HH_HDRLEN((p))
#define IPV6_EXTHDR_GET_HH_NH(p)            IPV6_EXTHDR_GET_RAW_HH_NH((p))
#define IPV6_EXTHDR_GET_RAW_DH1_HDRLEN(p)    ((p)->ip6eh.ip6dh1->ip6dh_len)
#define IPV6_EXTHDR_GET_RAW_DH1_NH(p)        ((p)->ip6eh.ip6dh1->ip6dh_nxt)
#define IPV6_EXTHDR_GET_RAW_DH2_HDRLEN(p)    ((p)->ip6eh.ip6dh2->ip6dh_len)
#define IPV6_EXTHDR_GET_RAW_DH2_NH(p)        ((p)->ip6eh.ip6dh2->ip6dh_nxt)
#define IPV6_EXTHDR_GET_RAW_FH_FLAG(p)      (ntohs((p)->ip6eh.ip6fh->ip6fh_offlg) & 0x0001)
#define IPV6_EXTHDR_GET_RAW_FH_HDRLEN(p)    sizeof(IPV6FragHdr)
#define IPV6_EXTHDR_GET_RAW_FH_ID(p)        (ntohl((p)->ip6eh.ip6fh->ip6fh_ident))
#define IPV6_EXTHDR_GET_RAW_FH_NH(p)        ((p)->ip6eh.ip6fh->ip6fh_nxt)
#define IPV6_EXTHDR_GET_RAW_FH_OFFSET(p)    (ntohs((p)->ip6eh.ip6fh->ip6fh_offlg) & 0xFFF8)
#define IPV6_EXTHDR_GET_RAW_HH_HDRLEN(p)    ((p)->ip6eh.ip6hh->ip6hh_len)
#define IPV6_EXTHDR_GET_RAW_HH_NH(p)        ((p)->ip6eh.ip6hh->ip6hh_nxt)
#define IPV6_EXTHDR_GET_RAW_RH_HDRLEN(p)    ((p)->ip6eh.ip6rh->ip6rh_len)
#define IPV6_EXTHDR_GET_RAW_RH_NH(p)        ((p)->ip6eh.ip6rh->ip6rh_nxt)
#define IPV6_EXTHDR_GET_RAW_RH_TYPE(p)      (ntohs((p)->ip6eh.ip6rh->ip6rh_type))
#define IPV6_EXTHDR_GET_RH_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_RH_HDRLEN((p))
#define IPV6_EXTHDR_GET_RH_NH(p)            IPV6_EXTHDR_GET_RAW_RH_NH((p))
#define IPV6_EXTHDR_GET_RH_TYPE(p)          IPV6_EXTHDR_GET_RAW_RH_TYPE((p))
#define IPV6_EXTHDR_HH(p)             (p)->ip6eh.ip6hh
#define IPV6_EXTHDR_HH_HAO(p)         (p)->ip6eh.ip6hh_opt_hao
#define IPV6_EXTHDR_HH_JUMBO(p)       (p)->ip6eh.ip6hh_opt_jumbo
#define IPV6_EXTHDR_HH_RA(p)          (p)->ip6eh.ip6hh_opt_ra
#define IPV6_EXTHDR_ISSET_AH(p)       (IPV6_EXTHDR_AH((p)) != NULL)
#define IPV6_EXTHDR_ISSET_DH1(p)      (IPV6_EXTHDR_DH1((p)) != NULL)
#define IPV6_EXTHDR_ISSET_DH2(p)      (IPV6_EXTHDR_DH2((p)) != NULL)
#define IPV6_EXTHDR_ISSET_EH(p)       (IPV6_EXTHDR_EH((p)) != NULL)
#define IPV6_EXTHDR_ISSET_FH(p)       (IPV6_EXTHDR_FH((p)) != NULL)
#define IPV6_EXTHDR_ISSET_HH(p)       (IPV6_EXTHDR_HH((p)) != NULL)
#define IPV6_EXTHDR_ISSET_RH(p)       (IPV6_EXTHDR_RH((p)) != NULL)
#define IPV6_EXTHDR_RH(p)             (p)->ip6eh.ip6rh
#define IPV6_EXTHDR_SET_AH(p,pkt)     IPV6_EXTHDR_AH((p)) = (IPV6AuthHdr *)pkt
#define IPV6_EXTHDR_SET_DH1(p,pkt)    IPV6_EXTHDR_DH1((p)) = (IPV6DstOptsHdr *)pkt
#define IPV6_EXTHDR_SET_DH2(p,pkt)    IPV6_EXTHDR_DH2((p)) = (IPV6DstOptsHdr *)pkt
#define IPV6_EXTHDR_SET_EH(p,pkt)     IPV6_EXTHDR_EH((p)) = (IPV6EspHdr *)pkt
#define IPV6_EXTHDR_SET_FH(p,pkt)     IPV6_EXTHDR_FH((p)) = (IPV6FragHdr *)pkt
#define IPV6_EXTHDR_SET_HH(p,pkt)     IPV6_EXTHDR_HH((p)) = (IPV6HopOptsHdr *)pkt
#define IPV6_EXTHDR_SET_RH(p,pkt)     IPV6_EXTHDR_RH((p)) = (IPV6RouteHdr *)pkt
#define IPV6_GET_CLASS(p) \
    IPV6_GET_RAW_CLASS((p)->ip6h)
#define IPV6_GET_FLOW(p) \
    IPV6_GET_RAW_FLOW((p)->ip6h)
#define IPV6_GET_HLIM(p) \
    (IPV6_GET_RAW_HLIM((p)->ip6h))
#define IPV6_GET_L4PROTO(p) \
    ((p)->ip6vars.l4proto)
#define IPV6_GET_NH(p) \
    (IPV6_GET_RAW_NH((p)->ip6h))
#define IPV6_GET_PLEN(p) \
    IPV6_GET_RAW_PLEN((p)->ip6h)
#define IPV6_GET_RAW_CLASS(ip6h)        ((ntohl((ip6h)->s_ip6_flow) & 0x0FF00000) >> 20)
#define IPV6_GET_RAW_FLOW(ip6h)         (ntohl((ip6h)->s_ip6_flow) & 0x000FFFFF)
#define IPV6_GET_RAW_HLIM(ip6h)         ((ip6h)->s_ip6_hlim)
#define IPV6_GET_RAW_NH(ip6h)           ((ip6h)->s_ip6_nxt)
#define IPV6_GET_RAW_PLEN(ip6h)         (ntohs((ip6h)->s_ip6_plen))
#define IPV6_GET_RAW_VER(ip6h)          (((ip6h)->s_ip6_vfc & 0xf0) >> 4)
#define IPV6_GET_VER(p) \
    IPV6_GET_RAW_VER((p)->ip6h)
#define IPV6_HEADER_LEN            40
#define IPV6_MAX_OPT               40
#define IPV6_SET_L4PROTO(p,proto)       (p)->ip6vars.l4proto = proto
#define IPV6_SET_RAW_NH(ip6h, value)    ((ip6h)->s_ip6_nxt = (value))
#define IPV6_SET_RAW_VER(ip6h, value)   ((ip6h)->s_ip6_vfc = (((ip6h)->s_ip6_vfc & 0x0f) | (value << 4)))

#define s_ip6_addrs                     ip6_hdrun2.ip6_addrs
#define s_ip6_dst                       ip6_hdrun2.ip6_un2.ip6_dst
#define s_ip6_flow                      ip6_hdrun.ip6_un1.ip6_un1_flow
#define s_ip6_hlim                      ip6_hdrun.ip6_un1.ip6_un1_hlim
#define s_ip6_nxt                       ip6_hdrun.ip6_un1.ip6_un1_nxt
#define s_ip6_plen                      ip6_hdrun.ip6_un1.ip6_un1_plen
#define s_ip6_src                       ip6_hdrun2.ip6_un2.ip6_src
#define s_ip6_vfc                       ip6_hdrun.ip6_un2_vfc
#define CLEAR_ICMPV4_PACKET(p) do { \
    (p)->icmpv4vars.comp_csum = -1; \
    (p)->icmpv4vars.id = 0; \
    (p)->icmpv4vars.seq = 0; \
    (p)->icmpv4vars.mtu = 0; \
    (p)->icmpv4vars.error_ptr = 0; \
    (p)->icmpv4vars.emb_ipv4h = NULL; \
    (p)->icmpv4vars.emb_tcph = NULL; \
    (p)->icmpv4vars.emb_udph = NULL; \
    (p)->icmpv4vars.emb_icmpv4h = NULL; \
    (p)->icmpv4vars.emb_ip4_src.s_addr = 0; \
    (p)->icmpv4vars.emb_ip4_dst.s_addr = 0; \
    (p)->icmpv4vars.emb_sport = 0; \
    (p)->icmpv4vars.emb_ip4_proto = 0; \
    (p)->icmpv4vars.emb_sport = 0; \
    (p)->icmpv4vars.emb_dport = 0; \
    (p)->icmpv4h = NULL; \
} while(0)
#define ICMPV4_DEST_UNREACH_IS_VALID(p) (((p)->icmpv4h != NULL) && \
    (ICMPV4_GET_TYPE((p)) == ICMP_DEST_UNREACH) && \
    (ICMPV4_GET_EMB_IPV4((p)) != NULL) && \
    ((ICMPV4_GET_EMB_TCP((p)) != NULL) || \
     (ICMPV4_GET_EMB_UDP((p)) != NULL)))
#define ICMPV4_GET_CODE(p)      (p)->icmpv4h->code
#define ICMPV4_GET_CSUM(p)      (p)->icmpv4h->csum
#define ICMPV4_GET_EMB_ICMPV4H(p)  (p)->icmpv4vars.emb_icmpv4h
#define ICMPV4_GET_EMB_IPV4(p)     (p)->icmpv4vars.emb_ipv4h
#define ICMPV4_GET_EMB_PROTO(p)    (p)->icmpv4vars.emb_ip4_proto
#define ICMPV4_GET_EMB_TCP(p)      (p)->icmpv4vars.emb_tcph
#define ICMPV4_GET_EMB_UDP(p)      (p)->icmpv4vars.emb_udph
#define ICMPV4_GET_ERROR_PTR(p)    (p)->icmpv4h->icmpv4b.icmpv4e.error_ptr
#define ICMPV4_GET_ID(p)        ((p)->icmpv4vars.id)
#define ICMPV4_GET_MTU(p)          (p)->icmpv4h->icmpv4b.icmpv4e.mtu
#define ICMPV4_GET_SEQ(p)       ((p)->icmpv4vars.seq)
#define ICMPV4_GET_TYPE(p)      (p)->icmpv4h->type
#define ICMPV4_GET_UNUSED(p)       (p)->icmpv4h->icmpv4b.icmpv4e.unused
#define ICMPV4_HEADER_LEN       8
#define ICMPV4_HEADER_PKT_OFFSET 8
#define ICMPV4_IS_ERROR_MSG(p) (ICMPV4_GET_TYPE((p)) == ICMP_DEST_UNREACH || \
        ICMPV4_GET_TYPE((p)) == ICMP_SOURCE_QUENCH || \
        ICMPV4_GET_TYPE((p)) == ICMP_REDIRECT || \
        ICMPV4_GET_TYPE((p)) == ICMP_TIME_EXCEEDED || \
        ICMPV4_GET_TYPE((p)) == ICMP_PARAMETERPROB)
#define ICMP_ADDRESS            17      
#define ICMP_ADDRESSREPLY       18      
#define ICMP_DEST_UNREACH       3       
#define ICMP_ECHO               8       
#define ICMP_ECHOREPLY          0       
#define ICMP_EXC_FRAGTIME       1       
#define ICMP_EXC_TTL            0       
#define ICMP_FRAG_NEEDED        4       
#define ICMP_HOST_ANO           10
#define ICMP_HOST_ISOLATED      8
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_UNREACH       1       
#define ICMP_HOST_UNR_TOS       12
#define ICMP_INFO_REPLY         16      
#define ICMP_INFO_REQUEST       15      
#define ICMP_NET_ANO            9
#define ICMP_NET_UNKNOWN        6
#define ICMP_NET_UNREACH        0       
#define ICMP_NET_UNR_TOS        11
#define ICMP_PARAMETERPROB      12      
#define ICMP_PKT_FILTERED       13      
#define ICMP_PORT_UNREACH       3       
#define ICMP_PREC_CUTOFF        15      
#define ICMP_PREC_VIOLATION     14      
#define ICMP_PROT_UNREACH       2       
#define ICMP_REDIRECT           5       
#define ICMP_REDIR_HOST         1       
#define ICMP_REDIR_HOSTTOS      3       
#define ICMP_REDIR_NET          0       
#define ICMP_REDIR_NETTOS       2       
#define ICMP_SOURCE_QUENCH      4       
#define ICMP_SR_FAILED          5       
#define ICMP_TIMESTAMP          13      
#define ICMP_TIMESTAMPREPLY     14      
#define ICMP_TIME_EXCEEDED      11      
#define NR_ICMP_TYPES           18
#define NR_ICMP_UNREACH         15      

#define SLL_HEADER_LEN                16

#define PPPOE_CODE_PADI 0x09
#define PPPOE_CODE_PADO 0x07
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT 0xa7
#define PPPOE_DISCOVERY_GET_TYPE(hdr) ((hdr)->pppoe_version_type & 0x0F)
#define PPPOE_DISCOVERY_GET_VERSION(hdr) ((hdr)->pppoe_version_type & 0xF0) >> 4
#define PPPOE_DISCOVERY_HEADER_MIN_LEN 6
#define PPPOE_SESSION_GET_TYPE(hdr) ((hdr)->pppoe_version_type & 0x0F)
#define PPPOE_SESSION_GET_VERSION(hdr) ((hdr)->pppoe_version_type & 0xF0) >> 4
#define PPPOE_SESSION_HEADER_LEN 8
#define PPPOE_TAG_AC_COOKIE           0x0104 
#define PPPOE_TAG_AC_NAME             0x0102 
#define PPPOE_TAG_AC_SYS_ERROR        0x0202 
#define PPPOE_TAG_END_OF_LIST         0x0000 
#define PPPOE_TAG_GEN_ERROR           0x0203 
#define PPPOE_TAG_HOST_UNIQ           0x0103 
#define PPPOE_TAG_RELAY_SESSION_ID    0x0110 
#define PPPOE_TAG_SERVICE_NAME        0x0101 
#define PPPOE_TAG_SERVICE_NAME_ERROR  0x0201 
#define PPPOE_TAG_VENDOR_SPECIFIC     0x0105 

#define THREAD_SET_AFFINITY     0x01 
#define THREAD_SET_AFFTYPE      0x04 
#define THREAD_SET_PRIORITY     0x02 
#define THV_CLOSED    (1 << 6) 
#define THV_DEINIT    (1 << 7)
#define THV_ENGINE_EXIT 0x02 
#define THV_FAILED    (1 << 5) 
#define THV_INIT_DONE (1 << 1) 
#define THV_KILL      (1 << 4) 
#define THV_MAX_RESTARTS 50
#define THV_PAUSE     (1 << 2) 
#define THV_PAUSED    (1 << 3) 
#define THV_RESTART_THREAD 0x01 
#define THV_RUNNING_DONE (1 << 8) 
#define THV_USE       1 

#define SCPerfSyncCounters(tv, reset_lc) \
    SCPerfUpdateCounterArray((tv)->sc_perf_pca, &(tv)->sc_perf_pctx, (reset_lc)); \

#define SCPerfSyncCountersIfSignalled(tv, reset_lc)                        \
    do {                                                        \
        if ((tv)->sc_perf_pctx.perf_flag == 1) {                            \
            SCPerfUpdateCounterArray((tv)->sc_perf_pca, &(tv)->sc_perf_pctx, (reset_lc)); \
        }                                                               \
    } while (0)
#define SC_PERF_MGMTT_TTS 8
#define SC_PERF_WUT_TTS 3


#define CPU_ISSET(cpu_id, new_mask) ((*(new_mask)).affinity_tag == (cpu_id + 1))
#define CPU_SET(cpu_id, new_mask) (*(new_mask)).affinity_tag = (cpu_id + 1)
#define CPU_ZERO(new_mask) (*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL

#define cpu_set_t cpuset_t
#define PPP_APPLE      0x0029       
#define PPP_APPLECP    0x8029       
#define PPP_BRPDU      0x0031       
#define PPP_CHAP       0xc223       
#define PPP_DECNET     0x0027       
#define PPP_DECNETCP   0x8027       
#define PPP_HEADER_LEN 4
#define PPP_HELLO      0x0201       
#define PPP_IP         0x0021       
#define PPP_IPCP       0x8021       
#define PPP_IPV6       0x0057       
#define PPP_IPV6CP     0x8057       
#define PPP_IPX        0x002b       
#define PPP_IPXCP      0x802b       
#define PPP_LCP        0xc021       
#define PPP_LQM        0xc025       
#define PPP_LUXCOM     0x0231       
#define PPP_MPLSCP     0x8281       
#define PPP_MPLS_MCAST 0x0283       
#define PPP_MPLS_UCAST 0x0281       
#define PPP_NS         0x0025       
#define PPP_NSCP       0x8025       
#define PPP_OSI        0x0023       
#define PPP_OSICP      0x8023       
#define PPP_PAP        0xc023       
#define PPP_SNS        0x0233       
#define PPP_STII       0x0033       
#define PPP_STIICP     0x8033       
#define PPP_VINES      0x0035       
#define PPP_VINESCP    0x8035       
#define PPP_VJ_COMP    0x002d       
#define PPP_VJ_UCOMP   0x002f       

#define GREV1_ACK_LEN           4
#define GREV1_FLAG_ISSET_ACK(r)    (r->version & 0x80)
#define GREV1_FLAG_ISSET_FLAGS(r)  (r->version & 0x78)
#define GREV1_HDR_LEN           8
#define GRE_CHKSUM_LEN          2
#define GRE_FLAG_ISSET_CHKSUM(r)    (r->flags & 0x80)
#define GRE_FLAG_ISSET_KY(r)        (r->flags & 0x20)
#define GRE_FLAG_ISSET_RECUR(r)     (r->flags & 0x07)
#define GRE_FLAG_ISSET_ROUTE(r)     (r->flags & 0x40)
#define GRE_FLAG_ISSET_SQ(r)        (r->flags & 0x10)
#define GRE_FLAG_ISSET_SSR(r)       (r->flags & 0x08)
#define GRE_GET_FLAGS(r)     (r->version & 0xF8)
#define GRE_GET_PROTO(r)     ntohs(r->ether_type)
#define GRE_GET_VERSION(r)   (r->version & 0x07)
#define GRE_HDR_LEN             4
#define GRE_KEY_LEN             4
#define GRE_OFFSET_LEN          2
#define GRE_PROTO_PPP           0x880b
#define GRE_SEQ_LEN             4
#define GRE_SRE_HDR_LEN         4
#define GRE_VERSION_0           0x0000
#define GRE_VERSION_1           0x0001
#define IPPROTO_GRE 47

#define ETHERNET_HEADER_LEN           14
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_LOOP            0x9000
#define ETHERNET_TYPE_PPPOE_DISC      0x8863 
#define ETHERNET_TYPE_PPPOE_SESS      0x8864 
#define ETHERNET_TYPE_PUP             0x0200 
#define ETHERNET_TYPE_REVARP          0x8035

#define ACTION_ALERT        0x01
#define ACTION_DROP         0x02
#define ACTION_PASS         0x20
#define ACTION_REJECT       0x04
#define ACTION_REJECT_BOTH  0x10
#define ACTION_REJECT_DST   0x08

#define MPIPE_COPY_MODE_IPS     2
#define MPIPE_COPY_MODE_NONE    0
#define MPIPE_COPY_MODE_TAP     1
#define MPIPE_FREE_PACKET(p) MpipeFreePacket((p))
#define MPIPE_IFACE_NAME_LENGTH 8

#define AFPV_CLEANUP(afpv) do {           \
    (afpv)->relptr = NULL;                \
    (afpv)->copy_mode = 0;                \
    (afpv)->peer = NULL;                  \
    (afpv)->mpeer = NULL;                 \
} while(0)
#define AFP_COPY_MODE_IPS   2
#define AFP_COPY_MODE_NONE  0
#define AFP_COPY_MODE_TAP   1
#define AFP_EMERGENCY_MODE (1<<3)
#define AFP_FILE_MAX_PKTS 256
#define AFP_IFACE_NAME_LENGTH 48
#define AFP_RING_MODE (1<<0)
#define AFP_SOCK_PROTECT (1<<2)
#define AFP_ZERO_COPY (1<<1)
#define HAVE_PACKET_FANOUT 1
#define PACKET_FANOUT                  18
#define PACKET_FANOUT_CPU              2
#define PACKET_FANOUT_FLAG_DEFRAG      0x8000
#define PACKET_FANOUT_HASH             0
#define PACKET_FANOUT_LB               1

#define LIBPCAP_COPYWAIT    500
#define LIBPCAP_PROMISC     1
#define LIBPCAP_SNAPLEN     1518
#define PCAP_IFACE_NAME_LENGTH 128

#define IPFW_MAX_QUEUE 16

#define NFQ_MAX_QUEUE 16




    #define FBLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->s)
    #define FBLOCK_INIT(fb) SCSpinInit(&(fb)->s, 0)
    #define FBLOCK_LOCK(fb) SCSpinLock(&(fb)->s)

    #define FBLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->s)
    #define FBLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->s)




#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)
#define FLOW_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(flow_memuse) + (uint64_t)(size)) <= flow_config.memcap))
#define FLOW_DESTROY(f) do { \
        SC_ATOMIC_DESTROY((f)->use_cnt); \
        \
        FLOWLOCK_DESTROY((f)); \
        FlowCleanupAppLayer((f)); \
        if ((f)->de_state != NULL) { \
            DetectEngineStateFree((f)->de_state); \
        } \
        GenericVarFree((f)->flowvar); \
        SCMutexDestroy(&(f)->de_state_m); \
        SC_ATOMIC_DESTROY((f)->autofp_tmqh_flow_qid);   \
    } while(0)
#define FLOW_INITIALIZE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        SC_ATOMIC_INIT((f)->use_cnt); \
        (f)->probing_parser_toserver_al_proto_masks = 0; \
        (f)->probing_parser_toclient_al_proto_masks = 0; \
        (f)->flags = 0; \
        (f)->lastts_sec = 0; \
        FLOWLOCK_INIT((f)); \
        (f)->protoctx = NULL; \
        (f)->alproto = 0; \
        (f)->de_ctx_id = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->de_state = NULL; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        (f)->flowvar = NULL; \
        SCMutexInit(&(f)->de_state_m, NULL); \
        (f)->hnext = NULL; \
        (f)->hprev = NULL; \
        (f)->lnext = NULL; \
        (f)->lprev = NULL; \
        SC_ATOMIC_INIT((f)->autofp_tmqh_flow_qid);  \
        (void) SC_ATOMIC_SET((f)->autofp_tmqh_flow_qid, -1);  \
        RESET_COUNTERS((f)); \
    } while (0)
#define FLOW_RECYCLE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        SC_ATOMIC_RESET((f)->use_cnt); \
        (f)->probing_parser_toserver_al_proto_masks = 0; \
        (f)->probing_parser_toclient_al_proto_masks = 0; \
        (f)->flags = 0; \
        (f)->lastts_sec = 0; \
        (f)->protoctx = NULL; \
        FlowCleanupAppLayer((f)); \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->alproto = 0; \
        (f)->de_ctx_id = 0; \
        if ((f)->de_state != NULL) { \
            DetectEngineStateReset((f)->de_state, (STREAM_TOSERVER | STREAM_TOCLIENT)); \
        } \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        GenericVarFree((f)->flowvar); \
        (f)->flowvar = NULL; \
        if (SC_ATOMIC_GET((f)->autofp_tmqh_flow_qid) != -1) {   \
            (void) SC_ATOMIC_SET((f)->autofp_tmqh_flow_qid, -1);   \
        }                                       \
        RESET_COUNTERS((f)); \
    } while(0)
#define RESET_COUNTERS(f) do { \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->bytecnt = 0; \
    } while (0)


#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH 2
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE 3
#define DETECT_ENGINE_INSPECT_SIG_MATCH 1
#define DETECT_ENGINE_INSPECT_SIG_NO_MATCH 0
#define DETECT_ENGINE_STATE_FLAG_FILE_STORE_DISABLED 0x0001
#define DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW         0x0002
#define DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW         0x0004
#define DE_STATE_CHUNK_SIZE             15
#define DE_STATE_FLAG_DNSQUERY_INSPECT    (1 << 17)
#define DE_STATE_FLAG_FILE_TC_INSPECT     (1 << 13)
#define DE_STATE_FLAG_FILE_TS_INSPECT     (1 << 14)
#define DE_STATE_FLAG_FULL_INSPECT        (1 << 15)
#define DE_STATE_FLAG_HCBD_INSPECT        (1 << 2)
#define DE_STATE_FLAG_HCD_INSPECT         (1 << 10)
#define DE_STATE_FLAG_HHD_INSPECT         (1 << 4)
#define DE_STATE_FLAG_HHHD_INSPECT        (1 << 6)
#define DE_STATE_FLAG_HMD_INSPECT         (1 << 9)
#define DE_STATE_FLAG_HRHD_INSPECT        (1 << 5)
#define DE_STATE_FLAG_HRHHD_INSPECT       (1 << 7)
#define DE_STATE_FLAG_HRUD_INSPECT        (1 << 1)
#define DE_STATE_FLAG_HSBD_INSPECT        (1 << 3)
#define DE_STATE_FLAG_HSCD_INSPECT        (1 << 12)
#define DE_STATE_FLAG_HSMD_INSPECT        (1 << 11)
#define DE_STATE_FLAG_HUAD_INSPECT        (1 << 8)
#define DE_STATE_FLAG_SIG_CANT_MATCH      (1 << 16)
#define DE_STATE_FLAG_URI_INSPECT         (1)


#define SpmNocaseSearch(text, textlen, needle, needlelen) ({\
    uint8_t *mfound; \
    if (needlelen < 4 && textlen < 512) \
          mfound = BasicSearchNocase(text, textlen, needle, needlelen); \
    else if (needlelen < 4) \
          mfound = BasicSearchNocase(text, textlen, needle, needlelen); \
    else \
          mfound = BoyerMooreNocaseSearch(text, textlen, needle, needlelen); \
    mfound; \
    })
#define SpmSearch(text, textlen, needle, needlelen) ({\
    uint8_t *mfound; \
    if (needlelen < 4 && textlen < 512) \
          mfound = BasicSearch(text, textlen, needle, needlelen); \
    else if (needlelen < 4) \
          mfound = BasicSearch(text, textlen, needle, needlelen); \
    else \
          mfound = BoyerMooreSearch(text, textlen, needle, needlelen); \
    mfound; \
    })

#define ALPHABET_SIZE 256




#define SSL_AL_FLAG_CHANGE_CIPHER_SPEC          0x0004
#define SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC   0x0002
#define SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC   0x0001
#define SSL_AL_FLAG_SSL_CLIENT_HS               0x0008
#define SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY       0x0020
#define SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED    0x0040
#define SSL_AL_FLAG_SSL_NO_SESSION_ID           0x0100
#define SSL_AL_FLAG_SSL_SERVER_HS               0x0010
#define SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED    0x0080
#define SSL_AL_FLAG_STATE_CLIENT_HELLO          0x0200
#define SSL_AL_FLAG_STATE_CLIENT_KEYX           0x0800
#define SSL_AL_FLAG_STATE_SERVER_HELLO          0x0400
#define SSL_AL_FLAG_STATE_SERVER_KEYX           0x1000
#define SSL_AL_FLAG_STATE_UNKNOWN               0x2000
#define SSL_TLS_LOG_PEM                         (1 << 0)

#define ALP_RESULT_ELMT_ALLOC 0x01
#define APP_LAYER_PARSER_DONE           0x04    
#define APP_LAYER_PARSER_EOF            0x02
#define APP_LAYER_PARSER_NO_INSPECTION  0x08    
#define APP_LAYER_PARSER_NO_REASSEMBLY  0x10    
#define APP_LAYER_PARSER_USE            0x01
#define APP_LAYER_PROBING_PARSER_PRIORITY_HIGH   1
#define APP_LAYER_PROBING_PARSER_PRIORITY_LOW    3
#define APP_LAYER_PROBING_PARSER_PRIORITY_MEDIUM 2
#define APP_LAYER_TRANSACTION_EOF       0x01    
#define APP_LAYER_TRANSACTION_TOCLIENT  0x04    
#define APP_LAYER_TRANSACTION_TOSERVER  0x02    

#define MSG_DATA_SIZE       4024 
#define STREAM_DEPTH            0x20    
#define STREAM_EOF              0x02
#define STREAM_GAP              0x10    
#define STREAM_START            0x01
#define STREAM_TOCLIENT         0x08
#define STREAM_TOSERVER         0x04

#define COUNTER_STREAMTCP_STREAMS 1
#define STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION    0x01
#define STREAM_VERBOSE    FALSE

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

#define PAWS_24DAYS         2073600         
#define PKT_IS_IN_RIGHT_DIR(ssn, p)        ((ssn)->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK ? \
                                            PKT_IS_TOSERVER(p) ? (p)->flowflags &= ~FLOW_PKT_TOSERVER \
                                            (p)->flowflags |= FLOW_PKT_TOCLIENT : (p)->flowflags &= ~FLOW_PKT_TOCLIENT \
                                            (p)->flowflags |= FLOW_PKT_TOSERVER : 0)
#define SEGMENTTCP_FLAG_APPLAYER_PROCESSED  0x02
#define SEGMENTTCP_FLAG_RAW_PROCESSED       0x01
#define SEQ_EQ(a,b)  ((int32_t)((a) - (b)) == 0)
#define SEQ_GEQ(a,b) ((int32_t)((a) - (b)) >= 0)
#define SEQ_GT(a,b)  ((int32_t)((a) - (b)) >  0)
#define SEQ_LEQ(a,b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_LT(a,b)  ((int32_t)((a) - (b)) <  0)
#define STREAMTCP_FLAG_3WHS_CONFIRMED               0x2000
#define STREAMTCP_FLAG_4WHS                         0x0080
#define STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED 0x0100
#define STREAMTCP_FLAG_ASYNC                        0x0040
#define STREAMTCP_FLAG_CLIENT_SACKOK                0x0400
#define STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT    0x0200
#define STREAMTCP_FLAG_MIDSTREAM                    0x0001
#define STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED        0x0002
#define STREAMTCP_FLAG_MIDSTREAM_SYNACK             0x0004
#define STREAMTCP_FLAG_SACKOK                       0x0800
#define STREAMTCP_FLAG_SERVER_WSCALE                0x0010
#define STREAMTCP_FLAG_TIMESTAMP                    0x0008
#define STREAMTCP_FLAG_TRIGGER_RAW_REASSEMBLY       0x1000
#define STREAMTCP_QUEUE_FLAG_SACK   0x04
#define STREAMTCP_QUEUE_FLAG_TS     0x01
#define STREAMTCP_QUEUE_FLAG_WS     0x02
#define STREAMTCP_SET_RA_BASE_SEQ(stream, seq) { \
    do { \
        (stream)->ra_raw_base_seq = (seq); \
        (stream)->ra_app_base_seq = (seq); \
    } while(0); \
}
#define STREAMTCP_STREAM_FLAG_CLOSE_INITIATED   0x10
#define STREAMTCP_STREAM_FLAG_DEPTH_REACHED     0x08
#define STREAMTCP_STREAM_FLAG_GAP               0x01
#define STREAMTCP_STREAM_FLAG_KEEPALIVE         0x04
#define STREAMTCP_STREAM_FLAG_NOREASSEMBLY      0x02
#define STREAMTCP_STREAM_FLAG_TIMESTAMP         0x20
#define STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP    0x40
#define StreamTcpSetEvent(p, e) { \
    SCLogDebug("setting event %"PRIu8" on pkt %p (%"PRIu64")", (e), p, (p)->pcap_cnt); \
    ENGINE_SET_EVENT((p), (e)); \
}


#define POOL_BUCKET_PREALLOCATED    (1 << 0)

#define ALP_DETECT_MAX 256

#define DETECT_CONTENT_DEPTH             (1 << 4)
#define DETECT_CONTENT_DEPTH_BE          (1 << 12)
#define DETECT_CONTENT_DISTANCE          (1 << 1)
#define DETECT_CONTENT_DISTANCE_BE       (1 << 13)
#define DETECT_CONTENT_FAST_PATTERN      (1 << 5)
#define DETECT_CONTENT_FAST_PATTERN_CHOP (1 << 7)
#define DETECT_CONTENT_FAST_PATTERN_ONLY (1 << 6)
#define DETECT_CONTENT_IS_SINGLE(c) (!( ((c)->flags & DETECT_CONTENT_DISTANCE) || \
                                        ((c)->flags & DETECT_CONTENT_WITHIN) || \
                                        ((c)->flags & DETECT_CONTENT_RELATIVE_NEXT) || \
                                        ((c)->flags & DETECT_CONTENT_DEPTH) || \
                                        ((c)->flags & DETECT_CONTENT_OFFSET) ))
#define DETECT_CONTENT_NEGATED           (1 << 9)
#define DETECT_CONTENT_NOCASE            (1)
#define DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED (1 << 16)
#define DETECT_CONTENT_OFFSET            (1 << 3)
#define DETECT_CONTENT_OFFSET_BE         (1 << 11)
#define DETECT_CONTENT_RAWBYTES          (1 << 8)
#define DETECT_CONTENT_RELATIVE_NEXT     (1 << 10)
#define DETECT_CONTENT_REPLACE           (1 << 15)
#define DETECT_CONTENT_WITHIN            (1 << 2)
#define DETECT_CONTENT_WITHIN_BE         (1 << 14)

#define PrintBufferData(buf, buf_offset_ptr, buf_size, ...) do {         \
        int cw = snprintf((buf) + *(buf_offset_ptr),                    \
                          (buf_size) - *(buf_offset_ptr),                \
                          __VA_ARGS__);                                 \
        if (cw >= 0) {                                                  \
            if ( (*(buf_offset_ptr) + cw) >= buf_size) {                \
                SCLogDebug("Truncating data write since it exceeded buffer " \
                           "limit of - %"PRIu32"\n", buf_size);         \
                *(buf_offset_ptr) = buf_size - 1;                       \
            } else {                                                    \
                *(buf_offset_ptr) += cw;                                \
            }                                                           \
        }                                                               \
    } while (0)


