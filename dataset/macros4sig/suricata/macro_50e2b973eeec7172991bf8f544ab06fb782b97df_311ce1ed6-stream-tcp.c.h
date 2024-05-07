#include<stdio.h>
#include<pthread.h>



#include<stddef.h>

#include<poll.h>
#include<string.h>

#include<sys/random.h>



#include<stdint.h>
#include<sys/param.h>
#include<assert.h>
#include<sys/prctl.h>


#include<threads.h>





#include<netdb.h>
#include<sys/time.h>






#include<sys/queue.h>

#include<inttypes.h>
#include<utime.h>
#include<sys/socket.h>









#include<limits.h>


#include<strings.h>



#include<sys/types.h>

#include<fcntl.h>





#include<grp.h>

#include<errno.h>




#include<time.h>
#include<pwd.h>




#include<sys/syscall.h>


#include<sys/resource.h>
#include<arpa/inet.h>

#include<signal.h>


#include<netinet/in.h>
#include<linux/if_packet.h>
#include<sys/signal.h>
#include<dirent.h>
#include<sys/mman.h>




#include<stdatomic.h>






#include<unistd.h>
#include<syscall.h>

#include<sys/stat.h>


#include<stdarg.h>



#include<stdbool.h>




#include<stdlib.h>
#include<sched.h>



#include<ctype.h>
#include<linux/netfilter.h>
#include<syslog.h>


#include<libgen.h>
#define SET_ISN(stream, setseq)                                                                    \
    (stream)->isn = (setseq);                                                                      \
    (stream)->base_seq = (setseq) + 1




#define DEBUG_VALIDATE_BUG_ON(exp) BUG_ON((exp))



#define WarnInvalidConfEntry(param_name, format, value) do {            \
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY,                    \
                     "Invalid conf entry found for "                    \
                     "\"%s\".  Using default value of \"" format "\".", \
                     param_name, value);                                \
    } while (0)


#define FLOWWORKER_PROFILING_END(p, id)                             \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((id) < PROFILE_FLOWWORKER_SIZE) {                       \
            (p)->profile->flowworker[(id)].ticks_end = UtilCpuGetTicks();  \
        }                                                           \
    }
#define FLOWWORKER_PROFILING_START(p, id)                           \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((id) < PROFILE_FLOWWORKER_SIZE) {                       \
            (p)->profile->flowworker[(id)].ticks_start = UtilCpuGetTicks();\
        }                                                           \
    }


#define KEYWORD_PROFILING_START \
    uint64_t profile_keyword_start_ = 0; \
    uint64_t profile_keyword_end_ = 0; \
    if (profiling_keyword_enabled) { \
        if (profiling_keyword_entered > 0) { \
            SCLogError(SC_ERR_FATAL, "Re-entered profiling, exiting."); \
            abort(); \
        } \
        profiling_keyword_entered++; \
        profile_keyword_start_ = UtilCpuGetTicks(); \
    }
#define PACKET_PROFILING_APP_END(dp, id)                            \
    if (profiling_packets_enabled) {                                \
        BUG_ON((id) != (dp)->alproto);                              \
        (dp)->ticks_end = UtilCpuGetTicks();                        \
        if ((dp)->ticks_start != 0 && (dp)->ticks_start < ((dp)->ticks_end)) {  \
            (dp)->ticks_spent = ((dp)->ticks_end - (dp)->ticks_start);  \
        }                                                           \
    }
#define PACKET_PROFILING_APP_PD_END(dp)                             \
    if (profiling_packets_enabled) {                                \
        (dp)->proto_detect_ticks_end = UtilCpuGetTicks();           \
        if ((dp)->proto_detect_ticks_start != 0 && (dp)->proto_detect_ticks_start < ((dp)->proto_detect_ticks_end)) {  \
            (dp)->proto_detect_ticks_spent =                        \
                ((dp)->proto_detect_ticks_end - (dp)->proto_detect_ticks_start);  \
        }                                                           \
    }
#define PACKET_PROFILING_APP_PD_START(dp)                           \
    if (profiling_packets_enabled) {                                \
        (dp)->proto_detect_ticks_start = UtilCpuGetTicks();         \
    }
#define PACKET_PROFILING_APP_RESET(dp)                              \
    if (profiling_packets_enabled) {                                \
        (dp)->ticks_start = 0;                                      \
        (dp)->ticks_end = 0;                                        \
        (dp)->ticks_spent = 0;                                      \
        (dp)->alproto = 0;                                          \
        (dp)->proto_detect_ticks_start = 0;                         \
        (dp)->proto_detect_ticks_end = 0;                           \
        (dp)->proto_detect_ticks_spent = 0;                         \
    }
#define PACKET_PROFILING_APP_START(dp, id)                          \
    if (profiling_packets_enabled) {                                \
        (dp)->ticks_start = UtilCpuGetTicks();                      \
        (dp)->alproto = (id);                                       \
    }
#define PACKET_PROFILING_APP_STORE(dp, p)                           \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((dp)->alproto < ALPROTO_MAX) {                          \
            (p)->profile->app[(dp)->alproto].ticks_spent += (dp)->ticks_spent;   \
            (p)->profile->proto_detect += (dp)->proto_detect_ticks_spent;        \
        }                                                           \
    }
#define PACKET_PROFILING_COPY_LOCKS(p, id) do {                     \
            (p)->profile->tmm[(id)].mutex_lock_cnt = mutex_lock_cnt;                \
            (p)->profile->tmm[(id)].mutex_lock_wait_ticks = mutex_lock_wait_ticks;  \
            (p)->profile->tmm[(id)].mutex_lock_contention = mutex_lock_contention;  \
            (p)->profile->tmm[(id)].spin_lock_cnt = spin_lock_cnt;                  \
            (p)->profile->tmm[(id)].spin_lock_wait_ticks = spin_lock_wait_ticks;    \
            (p)->profile->tmm[(id)].spin_lock_contention = spin_lock_contention;    \
            (p)->profile->tmm[(id)].rww_lock_cnt = rww_lock_cnt;                    \
            (p)->profile->tmm[(id)].rww_lock_wait_ticks = rww_lock_wait_ticks;      \
            (p)->profile->tmm[(id)].rww_lock_contention = rww_lock_contention;      \
            (p)->profile->tmm[(id)].rwr_lock_cnt = rwr_lock_cnt;                    \
            (p)->profile->tmm[(id)].rwr_lock_wait_ticks = rwr_lock_wait_ticks;      \
            (p)->profile->tmm[(id)].rwr_lock_contention = rwr_lock_contention;      \
        record_locks = 0;                                                           \
        SCProfilingAddPacketLocks((p));                                             \
    } while(0)
#define PACKET_PROFILING_DETECT_END(p, id)                          \
    if (profiling_packets_enabled  && (p)->profile != NULL) {       \
        if ((id) < PROF_DETECT_SIZE) {                              \
            (p)->profile->detect[(id)].ticks_end = UtilCpuGetTicks();\
            if ((p)->profile->detect[(id)].ticks_start != 0 &&       \
                    (p)->profile->detect[(id)].ticks_start < (p)->profile->detect[(id)].ticks_end) {  \
                (p)->profile->detect[(id)].ticks_spent +=            \
                ((p)->profile->detect[(id)].ticks_end - (p)->profile->detect[(id)].ticks_start);  \
            }                                                       \
        }                                                           \
    }
#define PACKET_PROFILING_DETECT_START(p, id)                        \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((id) < PROF_DETECT_SIZE) {                              \
            (p)->profile->detect[(id)].ticks_start = UtilCpuGetTicks(); \
        }                                                           \
    }
#define PACKET_PROFILING_END(p)                                     \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        (p)->profile->ticks_end = UtilCpuGetTicks();                \
        SCProfilingAddPacket((p));                                  \
    }
#define PACKET_PROFILING_LOGGER_END(p, id)                          \
    if (profiling_packets_enabled  && (p)->profile != NULL) {       \
        if ((id) < LOGGER_SIZE) {                              \
            (p)->profile->logger[(id)].ticks_end = UtilCpuGetTicks();\
            if ((p)->profile->logger[(id)].ticks_start != 0 &&       \
                    (p)->profile->logger[(id)].ticks_start < (p)->profile->logger[(id)].ticks_end) {  \
                (p)->profile->logger[(id)].ticks_spent +=            \
                ((p)->profile->logger[(id)].ticks_end - (p)->profile->logger[(id)].ticks_start);  \
            }                                                       \
        }                                                           \
    }
#define PACKET_PROFILING_LOGGER_START(p, id)                        \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((id) < LOGGER_SIZE) {                              \
            (p)->profile->logger[(id)].ticks_start = UtilCpuGetTicks(); \
        }                                                           \
    }
#define PACKET_PROFILING_RESET(p)                                   \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        SCFree((p)->profile);                                       \
        (p)->profile = NULL;                                        \
    }
#define PACKET_PROFILING_RESET_LOCKS do {                           \
        mutex_lock_cnt = 0;                                         \
        mutex_lock_wait_ticks = 0;                                  \
        mutex_lock_contention = 0;                                  \
        spin_lock_cnt = 0;                                          \
        spin_lock_wait_ticks = 0;                                   \
        spin_lock_contention = 0;                                   \
        rww_lock_cnt = 0;                                           \
        rww_lock_wait_ticks = 0;                                    \
        rww_lock_contention = 0;                                    \
        rwr_lock_cnt = 0;                                           \
        rwr_lock_wait_ticks = 0;                                    \
        rwr_lock_contention = 0;                                    \
        locks_idx = 0;                                              \
        record_locks = 1;\
    } while (0)


#define PACKET_PROFILING_TMM_END(p, id)                             \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((id) < TMM_SIZE) {                                      \
            PACKET_PROFILING_COPY_LOCKS((p), (id));                 \
            (p)->profile->tmm[(id)].ticks_end = UtilCpuGetTicks();  \
        }                                                           \
    }
#define PACKET_PROFILING_TMM_START(p, id)                           \
    if (profiling_packets_enabled && (p)->profile != NULL) {        \
        if ((id) < TMM_SIZE) {                                      \
            (p)->profile->tmm[(id)].ticks_start = UtilCpuGetTicks();\
            PACKET_PROFILING_RESET_LOCKS;                           \
        }                                                           \
    }
#define PREFILTER_PROFILING_END(ctx, profile_id) \
    if (profiling_prefilter_enabled && profiling_prefilter_entered) { \
        profile_prefilter_end_ = UtilCpuGetTicks(); \
        if (profile_prefilter_end_ > profile_prefilter_start_) \
            SCProfilingPrefilterUpdateCounter((ctx),(profile_id),(profile_prefilter_end_ - profile_prefilter_start_)); \
        profiling_prefilter_entered--; \
    }
#define PREFILTER_PROFILING_START \
    uint64_t profile_prefilter_start_ = 0; \
    uint64_t profile_prefilter_end_ = 0; \
    if (profiling_prefilter_enabled) { \
        if (profiling_prefilter_entered > 0) { \
            SCLogError(SC_ERR_FATAL, "Re-entered profiling, exiting."); \
            abort(); \
        } \
        profiling_prefilter_entered++; \
        profile_prefilter_start_ = UtilCpuGetTicks(); \
    }


#define SGH_PROFILING_RECORD(det_ctx, sgh)                          \
    if (profiling_sghs_enabled) {                                   \
        SCProfilingSghUpdateCounter((det_ctx), (sgh));              \
    }


#define PROFILING_MAX_LOCKS 64




#define SC_CAP_IPC_LOCK         0x08
#define SC_CAP_NET_ADMIN        0x10
#define SC_CAP_NET_BIND_SERVICE 0x40
#define SC_CAP_NET_BROADCAST    0x80
#define SC_CAP_NET_RAW          0x20
#define SC_CAP_NONE             0x01
#define SC_CAP_SYS_ADMIN        0x02
#define SC_CAP_SYS_RAW_IO       0x04
#define FatalError(x, ...) do {                                             \
    SCLogError(x, __VA_ARGS__);                                             \
    exit(EXIT_FAILURE);                                                     \
} while(0)
#define FatalErrorOnInit(x, ...)                                                                   \
    do {                                                                                           \
        SC_ATOMIC_EXTERN(unsigned int, engine_stage);                                              \
        int init_errors_fatal = 0;                                                                 \
        (void)ConfGetBool("engine.init-failure-fatal", &init_errors_fatal);                        \
        if (init_errors_fatal && (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT)) {                 \
            SCLogError(x, __VA_ARGS__);                                                            \
            exit(EXIT_FAILURE);                                                                    \
        }                                                                                          \
        SCLogWarning(x, __VA_ARGS__);                                                              \
    } while (0)

#define SCLogAlert(err_code, ...) SCLogErr(SC_LOG_ALERT, \
        "__FILE__", __FUNCTION__, "__LINE__", \
        err_code, __VA_ARGS__)
#define SCLogConfig(...) SCLog(SC_LOG_CONFIG, \
        "__FILE__", __FUNCTION__, "__LINE__", __VA_ARGS__)
#define SCLogCritical(err_code, ...) SCLogErr(SC_LOG_CRITICAL, \
        "__FILE__", __FUNCTION__, "__LINE__", \
        err_code, __VA_ARGS__)
#define SCLogDebug(...)                 do { } while (0)
#define SCLogEmerg(err_code, ...) SCLogErr(SC_LOG_EMERGENCY, \
        "__FILE__", __FUNCTION__, "__LINE__", \
        err_code, __VA_ARGS__)
#define SCLogError(err_code, ...) SCLogErr(SC_LOG_ERROR, \
        "__FILE__", __FUNCTION__, "__LINE__", \
        err_code, __VA_ARGS__)
#define SCLogErrorRaw(err_code, file, func, line, ...) SCLogErr(SC_LOG_ERROR, \
        (file), (func), (line), err_code, __VA_ARGS__)
#define SCLogInfo(...) SCLog(SC_LOG_INFO, \
        "__FILE__", __FUNCTION__, "__LINE__", __VA_ARGS__)
#define SCLogInfoRaw(file, func, line, ...) SCLog(SC_LOG_INFO, \
        (file), (func), (line), __VA_ARGS__)
#define SCLogNotice(...) SCLog(SC_LOG_NOTICE, \
        "__FILE__", __FUNCTION__, "__LINE__", __VA_ARGS__)
#define SCLogNoticeRaw(file, func, line, ... ) SCLog(SC_LOG_NOTICE, \
        (file), (func), (line), __VA_ARGS__)
#define SCLogPerf(...) SCLog(SC_LOG_PERF, \
        "__FILE__", __FUNCTION__, "__LINE__", __VA_ARGS__)
#define SCLogWarning(err_code, ...) SCLogErr(SC_LOG_WARNING, \
        "__FILE__", __FUNCTION__, "__LINE__", \
        err_code, __VA_ARGS__)
#define SCLogWarningRaw(err_code, file, func, line, ...) \
    SCLogErr(SC_LOG_WARNING, (file), (func), (line), err_code, __VA_ARGS__)
#define SCReturn                        return
#define SCReturnBool(x)                 return x
#define SCReturnCT(x, type)             return x
#define SCReturnChar(x)                 return x
#define SCReturnCharPtr(x)              return x
#define SCReturnDbl(x)                  return x
#define SCReturnInt(x)                  return x
#define SCReturnPtr(x, type)            return x
#define SCReturnStruct(x)                 return x
#define SCReturnUInt(x)                 return x
#define SC_LOG_DEF_LOG_FILE "suricata.log"
#define SC_LOG_DEF_LOG_FORMAT_DEV "[%i] %t - (%f:%l) <%d> (%n) -- "
#define SC_LOG_DEF_LOG_FORMAT_REL "%t - <%d> - "
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
#define SC_ATOMIC_ADD(name, val) \
    atomic_fetch_add(&(name ## _sc_atomic__), (val))
#define SC_ATOMIC_AND(name, val) \
    atomic_fetch_and(&(name ## _sc_atomic__), (val))
#define SC_ATOMIC_CAS(name, cmpval, newval) \
    atomic_compare_exchange_strong((name ## _sc_atomic__), &(cmpval), (newval))
#define SC_ATOMIC_DECLARE(type, name) \
    type name ## _sc_atomic__
#define SC_ATOMIC_DECL_AND_INIT(type, name) \
    type name ## _sc_atomic__ = 0
#define SC_ATOMIC_DECL_AND_INIT_WITH_VAL(type, name, val) type name##_sc_atomic__ = val
#define SC_ATOMIC_EXTERN(type, name) \
    extern type name ## _sc_atomic__
#define SC_ATOMIC_GET(name) \
    atomic_load(&(name ## _sc_atomic__))
#define SC_ATOMIC_INIT(name) \
    (name ## _sc_atomic__) = 0
#define SC_ATOMIC_INITPTR(name) \
    (name ## _sc_atomic__) = NULL
#define SC_ATOMIC_LOAD_EXPLICIT(name, order) \
    atomic_load_explicit(&(name ## _sc_atomic__), (order))
#define SC_ATOMIC_MEMORY_ORDER_ACQUIRE memory_order_acquire
#define SC_ATOMIC_MEMORY_ORDER_ACQ_REL memory_order_acq_rel
#define SC_ATOMIC_MEMORY_ORDER_CONSUME memory_order_consume
#define SC_ATOMIC_MEMORY_ORDER_RELAXED memory_order_relaxed
#define SC_ATOMIC_MEMORY_ORDER_RELEASE memory_order_release
#define SC_ATOMIC_MEMORY_ORDER_SEQ_CST memory_order_seq_cst
#define SC_ATOMIC_OR(name, val) \
    atomic_fetch_or(&(name ## _sc_atomic__), (val))
#define SC_ATOMIC_RESET(name) \
    (name ## _sc_atomic__) = 0
#define SC_ATOMIC_SET(name, val)    \
    atomic_store(&(name ## _sc_atomic__), (val))
#define SC_ATOMIC_SUB(name, val) \
    atomic_fetch_sub(&(name ## _sc_atomic__), (val))


#define SCCalloc calloc
#define SCFree free
#define SCFreeAligned _mm_free
#define SCMalloc malloc
#define SCMallocAligned _mm_malloc
#define SCRealloc realloc
#define SCStrdup strdup
#define SCStrndup strndup

#define SCCondDestroy pthread_cond_destroy
#define SCCondInit pthread_cond_init
#define SCCondSignal pthread_cond_signal
#define SCCondT pthread_cond_t
#define SCCondWait(cond, mut) pthread_cond_wait(cond, mut)
#define SCCtrlCondDestroy pthread_cond_destroy
#define SCCtrlCondInit pthread_cond_init
#define SCCtrlCondSignal pthread_cond_signal
#define SCCtrlCondT pthread_cond_t
#define SCCtrlCondTimedwait pthread_cond_timedwait
#define SCCtrlCondWait pthread_cond_wait
#define SCCtrlMutex pthread_mutex_t
#define SCCtrlMutexAttr pthread_mutexattr_t
#define SCCtrlMutexDestroy pthread_mutex_destroy
#define SCCtrlMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCCtrlMutexLock(mut) pthread_mutex_lock(mut)
#define SCCtrlMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCCtrlMutexUnlock(mut) pthread_mutex_unlock(mut)
#define SCGetThreadIdLong(...) ({ \
    long tmpthid; \
    thr_self(&tmpthid); \
    unsigned long _scgetthread_tid = (unsigned long)tmpthid; \
    _scgetthread_tid; \
})
#define SCMUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexDestroy pthread_mutex_destroy
#define SCMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCMutexLock(mut) pthread_mutex_lock(mut)
#define SCMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCMutexUnlock(mut) pthread_mutex_unlock(mut)
#define SCRWLock pthread_rwlock_t
#define SCRWLockDestroy pthread_rwlock_destroy
#define SCRWLockInit(rwl, rwlattr ) pthread_rwlock_init(rwl, rwlattr)
#define SCRWLockRDLock(rwl) pthread_rwlock_rdlock(rwl)
#define SCRWLockTryRDLock(rwl) pthread_rwlock_tryrdlock(rwl)
#define SCRWLockTryWRLock(rwl) pthread_rwlock_trywrlock(rwl)
#define SCRWLockUnlock(rwl) pthread_rwlock_unlock(rwl)
#define SCRWLockWRLock(rwl) pthread_rwlock_wrlock(rwl)
#define SCSetThreadName(n) ({ \
    char tname[16] = ""; \
    if (strlen(n) > 16) \
        SCLogDebug("Thread name is too long, truncating it..."); \
    strlcpy(tname, n, 16); \
    pthread_set_name_np(pthread_self(), tname); \
    0; \
})
#define SCSpinDestroy(spin)                     SCMutexDestroy((spin))
#define SCSpinInit(spin, spin_attr)             SCMutexInit((spin), NULL)
#define SCSpinLock(spin)                        SCMutexLock((spin))
#define SCSpinTrylock(spin)                     SCMutexTrylock((spin))
#define SCSpinUnlock(spin)                      SCMutexUnlock((spin))
#define SCSpinlock                              SCMutex
#define THREAD_NAME_LEN 16

#define thread_local _Thread_local
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

#define SCCondWait_dbg(cond, mut) ({ \
    int ret = pthread_cond_wait(cond, mut); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid (or a SCCondT not initialized!)\n"); \
        printf("%16s(%s:%d): (thread:%"PRIuMAX") failed SCCondWait %p ret %" PRId32 "\n", __FUNCTION__, "__FILE__", "__LINE__", (uintmax_t)pthread_self(), mut, ret); \
        break; \
    } \
    ret; \
})
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


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define ATTR_FMT_PRINTF(x, y) __attribute__((format(__MINGW_PRINTF_FORMAT, (x), (y))))
#define BIT_U16(n) ((uint16_t)(1 << (n)))
#define BIT_U32(n) (1UL  << (n))
#define BIT_U64(n) (1ULL << (n))
#define BIT_U8(n)  ((uint8_t)(1 << (n)))
    #define BUG_ON(x) if (((x))) exit(1)
#define CLS 64

#define FALSE  0
#define JSON_ESCAPE_SLASH 0
#define MAX(x, y) (((x)<(y))?(y):(x))
#define MIN(x, y) (((x)<(y))?(x):(y))
#define NAME_MAX 255
#define PatIntId uint32_t
#define SCClearErrUnlocked  clearerr
#define SCFerrorUnlocked    ferror
#define SCFflushUnlocked    fflush
#define SCFwriteUnlocked    fwrite
#define SCNtohl(x) (uint32_t)ntohl((x))
#define SCNtohs(x) (uint16_t)ntohs((x))
#define SWAP_FLAGS(flags, a, b)                     \
    do {                                            \
        if (((flags) & ((a)|(b))) == (a)) {         \
            (flags) &= ~(a);                        \
            (flags) |= (b);                         \
        } else if (((flags) & ((a)|(b))) == (b)) {  \
            (flags) &= ~(b);                        \
            (flags) |= (a);                         \
        }                                           \
    } while(0)
#define SWAP_VARS(type, a, b)           \
    do {                                \
        type t = (a);                   \
        (a) = (b);                      \
        (b) = t;                        \
    } while (0)
#define SigIntId uint32_t
#define TRUE   1
#define WARN_UNUSED __attribute__((warn_unused_result))

#define _WIN32_WINNT 0x0501

        #define __BIG_ENDIAN BIG_ENDIAN
        #define __BYTE_ORDER BYTE_ORDER
        #define __LITTLE_ENDIAN LITTLE_ENDIAN


        #define __WORDSIZE __LONG_BIT
#define str(s) #s
#define xstr(s) str(s)

#define DEFAULT_DATA_DIR "C:\\WINDOWS\\Temp"
#define DEFAULT_LOG_DIR "C:\\WINDOWS\\Temp"

#define CIRCLEQ_END(head)       ((void *)(head))
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
		(head)->cqh_last = (elm2);				\
	else								\
		(elm2)->field.cqe_next->field.cqe_prev = (elm2);	\
	if (((elm2)->field.cqe_prev = (elm)->field.cqe_prev) ==		\
	    CIRCLEQ_END(head))						\
		(head)->cqh_first = (elm2);				\
	else								\
		(elm2)->field.cqe_prev->field.cqe_next = (elm2);	\
} while (0)

#define _Q_ASSERT(a) assert((a))
    #define SCMkDir(a, b) mkdir(a, b)


#define ADDRESS_FLAG_NOT            0x01 
#define DETECT_DEFAULT_PRIO 3
#define DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH 0x0004
#define DETECT_FILESTORE_MAX 15
#define DETECT_MAX_RULE_SIZE 8192
#define DETECT_SM_LIST_NOTSET INT_MAX
#define DETECT_TRANSFORMS_MAX 16
#define DETECT_VAR_TYPE_FLOW_POSTMATCH      1
#define DETECT_VAR_TYPE_PKT_POSTMATCH       2
#define DE_QUIET           0x01     
#define ENGINE_SGH_MPM_FACTORY_CONTEXT_START_ID_RANGE (ENGINE_SGH_MPM_FACTORY_CONTEXT_AUTO + 1)
#define FILE_SIG_NEED_FILE          0x01
#define FILE_SIG_NEED_FILECONTENT   0x08
#define FILE_SIG_NEED_FILENAME      0x02
#define FILE_SIG_NEED_MAGIC         0x04    
#define FILE_SIG_NEED_MD5           0x10
#define FILE_SIG_NEED_SHA1          0x20
#define FILE_SIG_NEED_SHA256        0x40
#define FILE_SIG_NEED_SIZE          0x80
#define FLOW_STATES 2
#define PORT_FLAG_ANY           0x01 
#define PORT_FLAG_NOT           0x02 
#define PORT_SIGGROUPHEAD_COPY  0x04 
#define SIGMATCH_DEONLY_COMPAT          BIT_U16(2)
#define SIGMATCH_HANDLE_NEGATION        BIT_U16(7)
#define SIGMATCH_INFO_CONTENT_MODIFIER  BIT_U16(8)
#define SIGMATCH_INFO_DEPRECATED        BIT_U16(10)
#define SIGMATCH_INFO_STICKY_BUFFER     BIT_U16(9)
#define SIGMATCH_IPONLY_COMPAT          BIT_U16(1)
#define SIGMATCH_NOOPT                  BIT_U16(0)
#define SIGMATCH_NOT_BUILT              BIT_U16(3)
#define SIGMATCH_OPTIONAL_OPT           BIT_U16(4)
#define SIGMATCH_QUOTES_MANDATORY       BIT_U16(6)
#define SIGMATCH_QUOTES_OPTIONAL        BIT_U16(5)
#define SIGMATCH_STRICT_PARSING         BIT_U16(11)
#define SIG_FLAG_APPLAYER               BIT_U32(6)  
#define SIG_FLAG_BYPASS                 BIT_U32(22)
#define SIG_FLAG_DEST_IS_TARGET         BIT_U32(26)
#define SIG_FLAG_DP_ANY                 BIT_U32(3)  
#define SIG_FLAG_DSIZE                  BIT_U32(5)  
#define SIG_FLAG_DST_ANY                BIT_U32(1)  
#define SIG_FLAG_FILESTORE              BIT_U32(18) 
#define SIG_FLAG_FLUSH                  BIT_U32(12) 
#define SIG_FLAG_HAS_TARGET             (SIG_FLAG_DEST_IS_TARGET|SIG_FLAG_SRC_IS_TARGET)
#define SIG_FLAG_INIT_BIDIREC               BIT_U32(3)  
#define SIG_FLAG_INIT_DCERPC                BIT_U32(10) 
#define SIG_FLAG_INIT_DEONLY                BIT_U32(0)  
#define SIG_FLAG_INIT_FILEDATA              BIT_U32(9)  
#define SIG_FLAG_INIT_FIRST_IPPROTO_SEEN    BIT_U32(4)  
#define SIG_FLAG_INIT_FLOW                  BIT_U32(2)  
#define SIG_FLAG_INIT_HAS_TRANSFORM         BIT_U32(5)
#define SIG_FLAG_INIT_NEED_FLUSH            BIT_U32(7)
#define SIG_FLAG_INIT_PACKET                BIT_U32(1)  
#define SIG_FLAG_INIT_PRIO_EXPLICT          BIT_U32(8)  
#define SIG_FLAG_INIT_STATE_MATCH           BIT_U32(6)  
#define SIG_FLAG_IPONLY                 BIT_U32(7)  
#define SIG_FLAG_MPM_NEG                BIT_U32(11)
#define SIG_FLAG_NOALERT                BIT_U32(4)  
#define SIG_FLAG_PDONLY                 BIT_U32(24)
#define SIG_FLAG_PREFILTER              BIT_U32(23) 
#define SIG_FLAG_REQUIRE_FLOWVAR        BIT_U32(17) 
#define SIG_FLAG_REQUIRE_PACKET         BIT_U32(9)  
#define SIG_FLAG_REQUIRE_STREAM         BIT_U32(10) 
#define SIG_FLAG_SP_ANY                 BIT_U32(2)  
#define SIG_FLAG_SRC_ANY                BIT_U32(0)  
#define SIG_FLAG_SRC_IS_TARGET          BIT_U32(25)
#define SIG_FLAG_TLSSTORE               BIT_U32(21)
#define SIG_FLAG_TOCLIENT               BIT_U32(20)
#define SIG_FLAG_TOSERVER               BIT_U32(19)
#define SIG_GROUP_HEAD_HAVEFILEMAGIC    BIT_U32(20)
#define SIG_GROUP_HEAD_HAVEFILEMD5      BIT_U32(21)
#define SIG_GROUP_HEAD_HAVEFILESHA1     BIT_U32(23)
#define SIG_GROUP_HEAD_HAVEFILESHA256   BIT_U32(24)
#define SIG_GROUP_HEAD_HAVEFILESIZE     BIT_U32(22)
#define SIG_GROUP_HEAD_HAVERAWSTREAM    BIT_U32(0)
#define SIG_MASK_REQUIRE_DCERPC             BIT_U8(5)    
#define SIG_MASK_REQUIRE_ENGINE_EVENT       BIT_U8(7)
#define SIG_MASK_REQUIRE_FLAGS_INITDEINIT   BIT_U8(2)    
#define SIG_MASK_REQUIRE_FLAGS_UNUSUAL      BIT_U8(3)    
#define SIG_MASK_REQUIRE_FLOW               BIT_U8(1)
#define SIG_MASK_REQUIRE_NO_PAYLOAD         BIT_U8(4)
#define SIG_MASK_REQUIRE_PAYLOAD            BIT_U8(0)
#define SignatureMask uint8_t

#define sm_lists init_data->smlists
#define sm_lists_tail init_data->smlists_tail


#define TH_ACTION_ALERT     0x01
#define TH_ACTION_DROP      0x02
#define TH_ACTION_LOG       0x08
#define TH_ACTION_PASS      0x04
#define TH_ACTION_REJECT    0x20
#define TH_ACTION_SDROP     0x10
#define TRACK_BOTH     5 
#define TRACK_DST      1
#define TRACK_EITHER   4 
#define TRACK_RULE     3
#define TRACK_SRC      2
#define TYPE_BOTH      2
#define TYPE_DETECTION 4
#define TYPE_LIMIT     1
#define TYPE_RATE      5
#define TYPE_SUPPRESS  6
#define TYPE_THRESHOLD 3

#define CLEAR_TCP_PACKET(p) {   \
    (p)->level4_comp_csum = -1; \
    PACKET_CLEAR_L4VARS((p));   \
    (p)->tcph = NULL;           \
}
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK((p)->tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT((p)->tcph)
#define TCP_GET_FLAGS(p)                     (p)->tcph->th_flags
#define TCP_GET_HLEN(p)                      (TCP_GET_OFFSET((p)) << 2)
#define TCP_GET_MSS(p)                       SCNtohs(*(uint16_t *)((p)->tcpvars.mss.data))
#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET((p)->tcph)
#define TCP_GET_RAW_ACK(tcph)                SCNtohl((tcph)->th_ack)
#define TCP_GET_RAW_DST_PORT(tcph)           SCNtohs((tcph)->th_dport)
#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_SEQ(tcph)                SCNtohl((tcph)->th_seq)
#define TCP_GET_RAW_SRC_PORT(tcph)           SCNtohs((tcph)->th_sport)
#define TCP_GET_RAW_SUM(tcph)                SCNtohs((tcph)->th_sum)
#define TCP_GET_RAW_URG_POINTER(tcph)        SCNtohs((tcph)->th_urp)
#define TCP_GET_RAW_WINDOW(tcph)             SCNtohs((tcph)->th_win)
#define TCP_GET_RAW_X2(tcph)                 (unsigned char)((tcph)->th_offx2 & 0x0f)
#define TCP_GET_SACKOK(p)                    (TCP_HAS_SACKOK((p)) ? 1 : 0)
#define TCP_GET_SACK_CNT(p)                  (TCP_HAS_SACK((p)) ? (((p)->tcpvars.sack.len - 2) / 8) : 0)
#define TCP_GET_SACK_PTR(p)                  TCP_HAS_SACK((p)) ? (p)->tcpvars.sack.data : NULL
#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ((p)->tcph)
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT((p)->tcph)
#define TCP_GET_SUM(p)                       TCP_GET_RAW_SUM((p)->tcph)
#define TCP_GET_TSECR(p)                    ((p)->tcpvars.ts_ecr)
#define TCP_GET_TSVAL(p)                    ((p)->tcpvars.ts_val)
#define TCP_GET_URG_POINTER(p)               TCP_GET_RAW_URG_POINTER((p)->tcph)
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW((p)->tcph)
#define TCP_GET_WSCALE(p)                    (TCP_HAS_WSCALE((p)) ? \
                                                (((*(uint8_t *)(p)->tcpvars.ws.data) <= TCP_WSCALE_MAX) ? \
                                                  (*(uint8_t *)((p)->tcpvars.ws.data)) : 0) : 0)
#define TCP_GET_X2(p)                        TCP_GET_RAW_X2((p)->tcph)
#define TCP_HAS_MSS(p)                      ((p)->tcpvars.mss.type == TCP_OPT_MSS)
#define TCP_HAS_SACK(p)                     ((p)->tcpvars.sack.type == TCP_OPT_SACK)
#define TCP_HAS_SACKOK(p)                   ((p)->tcpvars.sackok.type == TCP_OPT_SACKOK)
#define TCP_HAS_TFO(p)                      ((p)->tcpvars.tfo.type == TCP_OPT_TFO)
#define TCP_HAS_TS(p)                       ((p)->tcpvars.ts_set)
#define TCP_HAS_WSCALE(p)                   ((p)->tcpvars.ws.type == TCP_OPT_WS)
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
#define TCP_OPT_AO                           0x1d   
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_EXP1                         0xfd   
#define TCP_OPT_EXP2                         0xfe   
#define TCP_OPT_MD5                          0x13   
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_SACK_MAX_LEN                 34 
#define TCP_OPT_SACK_MIN_LEN                 10 
#define TCP_OPT_TFO                          0x22   
#define TCP_OPT_TFO_MAX_LEN                  18 
#define TCP_OPT_TFO_MIN_LEN                  6  
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
    (p)->level3_comp_csum = -1; \
    memset(&p->ip4vars, 0x00, sizeof(p->ip4vars)); \
} while (0)
#define IPV4_GET_DF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x4000) >> 14)
#define IPV4_GET_HLEN(p) \
    (IPV4_GET_RAW_HLEN((p)->ip4h) << 2)
#define IPV4_GET_IPID(p) \
    (SCNtohs(IPV4_GET_RAW_IPID((p)->ip4h)))
#define IPV4_GET_IPLEN(p) \
    (SCNtohs(IPV4_GET_RAW_IPLEN((p)->ip4h)))
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
    (SCNtohs(IPV4_GET_RAW_IPOFFSET((p)->ip4h)))

#define s_ip_addrs                        ip4_hdrun1.ip_addrs
#define s_ip_dst                          ip4_hdrun1.ip4_un1.ip_dst
#define s_ip_src                          ip4_hdrun1.ip4_un1.ip_src
#define EVENT_IS_DECODER_PACKET_ERROR(e)    \
    ((e) < (DECODE_EVENT_PACKET_MAX))


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

#define DEFAULT_MTU 1500
#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)
#define DLT_C_HDLC 104
#define DLT_EN10MB 1
#define DLT_NULL 0
#define DLT_RAW     14  
#define DecodeSetNoPacketInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPACKET_INSPECTION;  \
    } while (0)
#define DecodeSetNoPayloadInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPAYLOAD_INSPECTION;  \
    } while (0)
#define DecodeUnsetNoPacketInspectionFlag(p) do { \
        (p)->flags &= ~PKT_NOPACKET_INSPECTION;  \
    } while (0)
#define DecodeUnsetNoPayloadInspectionFlag(p) do { \
        (p)->flags &= ~PKT_NOPAYLOAD_INSPECTION;  \
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
#define ENGINE_SET_INVALID_EVENT(p, e) do { \
    p->flags |= PKT_IS_INVALID; \
    ENGINE_SET_EVENT(p, e); \
} while(0)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)
#define GET_IPV6_DST_IN6ADDR(p) ((p)->dst.addr_in6addr)
#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_IPV6_SRC_IN6ADDR(p) ((p)->src.addr_in6addr)
#define GET_PKT_DATA(p) ((((p)->ext_pkt) == NULL ) ? (uint8_t *)((p) + 1) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) (uint8_t *)((p) + 1)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)
#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_TCP_DST_PORT(p)  ((p)->dp)
#define GET_TCP_SRC_PORT(p)  ((p)->sp)
#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))
#define IPPROTO_DCCP 33
#define IPPROTO_HIP 139
#define IPPROTO_IPIP 4
#define IPPROTO_MH 135
#define IPPROTO_SCTP 132
#define IPPROTO_SHIM6 140
#define IP_GET_IPPROTO(p) \
    (p->proto ? p->proto : \
    (PKT_IS_IPV4((p))? IPV4_GET_IPPROTO((p)) : (PKT_IS_IPV6((p))? IPV6_GET_L4PROTO((p)) : 0)))
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))
#define IS_TUNNEL_PKT(p)            (((p)->flags & PKT_TUNNEL))
#define IS_TUNNEL_PKT_VERDICTED(p)  (((p)->flags & PKT_TUNNEL_VERDICTED))
#define IS_TUNNEL_ROOT_PKT(p)       (IS_TUNNEL_PKT(p) && (p)->root == NULL)
#define LINKTYPE_CISCO_HDLC  DLT_C_HDLC
#define LINKTYPE_ETHERNET    DLT_EN10MB
#define LINKTYPE_GRE_OVER_IP 778
#define LINKTYPE_IPV4        228
#define LINKTYPE_LINUX_SLL   113
#define LINKTYPE_NULL        DLT_NULL
#define LINKTYPE_PPP         9
#define LINKTYPE_RAW         DLT_RAW
#define LINKTYPE_RAW2        101
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
#define MINIMUM_MTU 68      
#define PACKET_ACCEPT(p) PACKET_SET_ACTION(p, ACTION_ACCEPT)
#define PACKET_ALERT(p) PACKET_SET_ACTION(p, ACTION_ALERT)
#define PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW 0x1
#define PACKET_ALERT_FLAG_STATE_MATCH   0x02
#define PACKET_ALERT_FLAG_STREAM_MATCH  0x04
#define PACKET_ALERT_FLAG_TX            0x08
#define PACKET_ALERT_MAX 15
#define PACKET_ALERT_RATE_FILTER_MODIFIED   0x10
#define PACKET_CLEAR_L4VARS(p) do {                         \
        memset(&(p)->l4vars, 0x00, sizeof((p)->l4vars));    \
    } while (0)
#define PACKET_DESTRUCTOR(p) do {                  \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
        }                                       \
        PACKET_FREE_EXTDATA((p));               \
        SCMutexDestroy(&(p)->tunnel_mutex);     \
        AppLayerDecoderEventsFreeEvents(&(p)->app_layer_events); \
        PACKET_PROFILING_RESET((p));            \
    } while (0)
#define PACKET_DROP(p) PACKET_SET_ACTION(p, ACTION_DROP)
#define PACKET_ENGINE_EVENT_MAX 15
#define PACKET_FREE_EXTDATA(p) do {                 \
        if ((p)->ext_pkt) {                         \
            if (!((p)->flags & PKT_ZERO_COPY)) {    \
                SCFree((p)->ext_pkt);               \
            }                                       \
            (p)->ext_pkt = NULL;                    \
        }                                           \
    } while(0)
#define PACKET_INITIALIZE(p) {         \
    SCMutexInit(&(p)->tunnel_mutex, NULL); \
    PACKET_RESET_CHECKSUMS((p)); \
    (p)->livedev = NULL; \
}
#define PACKET_PASS(p) PACKET_SET_ACTION(p, ACTION_PASS)
#define PACKET_RECYCLE(p) do { \
        PACKET_RELEASE_REFS((p)); \
        PACKET_REINIT((p)); \
    } while (0)
#define PACKET_REINIT(p)                                                                           \
    do {                                                                                           \
        CLEAR_ADDR(&(p)->src);                                                                     \
        CLEAR_ADDR(&(p)->dst);                                                                     \
        (p)->sp = 0;                                                                               \
        (p)->dp = 0;                                                                               \
        (p)->proto = 0;                                                                            \
        (p)->recursion_level = 0;                                                                  \
        PACKET_FREE_EXTDATA((p));                                                                  \
        (p)->flags = (p)->flags & PKT_ALLOC;                                                       \
        (p)->flowflags = 0;                                                                        \
        (p)->pkt_src = 0;                                                                          \
        (p)->vlan_id[0] = 0;                                                                       \
        (p)->vlan_id[1] = 0;                                                                       \
        (p)->vlan_idx = 0;                                                                         \
        (p)->ts.tv_sec = 0;                                                                        \
        (p)->ts.tv_usec = 0;                                                                       \
        (p)->datalink = 0;                                                                         \
        (p)->action = 0;                                                                           \
        if ((p)->pktvar != NULL) {                                                                 \
            PktVarFree((p)->pktvar);                                                               \
            (p)->pktvar = NULL;                                                                    \
        }                                                                                          \
        (p)->ethh = NULL;                                                                          \
        if ((p)->ip4h != NULL) {                                                                   \
            CLEAR_IPV4_PACKET((p));                                                                \
        }                                                                                          \
        if ((p)->ip6h != NULL) {                                                                   \
            CLEAR_IPV6_PACKET((p));                                                                \
        }                                                                                          \
        if ((p)->tcph != NULL) {                                                                   \
            CLEAR_TCP_PACKET((p));                                                                 \
        }                                                                                          \
        if ((p)->udph != NULL) {                                                                   \
            CLEAR_UDP_PACKET((p));                                                                 \
        }                                                                                          \
        if ((p)->sctph != NULL) {                                                                  \
            CLEAR_SCTP_PACKET((p));                                                                \
        }                                                                                          \
        if ((p)->esph != NULL) {                                                                   \
            CLEAR_ESP_PACKET((p));                                                                 \
        }                                                                                          \
        if ((p)->icmpv4h != NULL) {                                                                \
            CLEAR_ICMPV4_PACKET((p));                                                              \
        }                                                                                          \
        if ((p)->icmpv6h != NULL) {                                                                \
            CLEAR_ICMPV6_PACKET((p));                                                              \
        }                                                                                          \
        (p)->ppph = NULL;                                                                          \
        (p)->pppoesh = NULL;                                                                       \
        (p)->pppoedh = NULL;                                                                       \
        (p)->greh = NULL;                                                                          \
        (p)->payload = NULL;                                                                       \
        (p)->payload_len = 0;                                                                      \
        (p)->BypassPacketsFlow = NULL;                                                             \
        (p)->pktlen = 0;                                                                           \
        (p)->alerts.cnt = 0;                                                                       \
        (p)->alerts.drop.action = 0;                                                               \
        (p)->pcap_cnt = 0;                                                                         \
        (p)->tunnel_rtv_cnt = 0;                                                                   \
        (p)->tunnel_tpr_cnt = 0;                                                                   \
        (p)->events.cnt = 0;                                                                       \
        AppLayerDecoderEventsResetEvents((p)->app_layer_events);                                   \
        (p)->next = NULL;                                                                          \
        (p)->prev = NULL;                                                                          \
        (p)->root = NULL;                                                                          \
        (p)->livedev = NULL;                                                                       \
        PACKET_RESET_CHECKSUMS((p));                                                               \
        PACKET_PROFILING_RESET((p));                                                               \
        p->tenant_id = 0;                                                                          \
        p->nb_decoded_layers = 0;                                                                  \
    } while (0)
#define PACKET_REJECT(p) PACKET_SET_ACTION(p, (ACTION_REJECT|ACTION_DROP))
#define PACKET_REJECT_BOTH(p) PACKET_SET_ACTION(p, (ACTION_REJECT_BOTH|ACTION_DROP))
#define PACKET_REJECT_DST(p) PACKET_SET_ACTION(p, (ACTION_REJECT_DST|ACTION_DROP))
#define PACKET_RELEASE_REFS(p) do {              \
        FlowDeReference(&((p)->flow));          \
        HostDeReference(&((p)->host_src));      \
        HostDeReference(&((p)->host_dst));      \
    } while (0)
#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->level3_comp_csum = -1;   \
        (p)->level4_comp_csum = -1;   \
    } while (0)
#define PACKET_SET_ACTION(p, a) (p)->action = (a)
#define PACKET_TEST_ACTION(p, a) (p)->action &(a)
#define PACKET_UPDATE_ACTION(p, a) (p)->action |= (a)
#define PKT_ALLOC BIT_U32(3)
#define PKT_DEFAULT_MAX_DECODED_LAYERS 16
#define PKT_DETECT_HAS_STREAMDATA                                                                  \
    BIT_U32(26) 
#define PKT_HAS_FLOW   BIT_U32(8)
#define PKT_HAS_TAG BIT_U32(4)
#define PKT_HOST_DST_LOOKED_UP BIT_U32(18)
#define PKT_HOST_SRC_LOOKED_UP BIT_U32(17)
#define PKT_IGNORE_CHECKSUM BIT_U32(15)
#define PKT_IS_FRAGMENT BIT_U32(19)
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_INVALID  BIT_U32(20)
#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_PSEUDOPKT(p) \
    ((p)->flags & (PKT_PSEUDO_STREAM_END|PKT_PSEUDO_DETECTLOG_FLUSH))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_MARK_MODIFIED BIT_U32(11)
#define PKT_NOPACKET_INSPECTION BIT_U32(0)
#define PKT_NOPAYLOAD_INSPECTION BIT_U32(2)
#define PKT_PROFILE     BIT_U32(21)
#define PKT_PROTO_DETECT_TC_DONE BIT_U32(24)
#define PKT_PROTO_DETECT_TS_DONE BIT_U32(23)
#define PKT_PSEUDO_DETECTLOG_FLUSH BIT_U32(27) 
#define PKT_PSEUDO_STREAM_END BIT_U32(9)
#define PKT_REBUILT_FRAGMENT                                                                       \
    BIT_U32(25) 
#define PKT_SET_SRC(p, src_val) ((p)->pkt_src = src_val)
#define PKT_STREAM_ADD BIT_U32(5)
#define PKT_STREAM_EOF BIT_U32(7)
#define PKT_STREAM_EST BIT_U32(6)
#define PKT_STREAM_MODIFIED BIT_U32(10)
#define PKT_STREAM_NOPCAPLOG BIT_U32(12)
#define PKT_STREAM_NO_EVENTS BIT_U32(28)
#define PKT_TUNNEL           BIT_U32(13)
#define PKT_TUNNEL_VERDICTED BIT_U32(14)
#define PKT_WANTS_FLOW BIT_U32(22)
#define PKT_ZERO_COPY BIT_U32(16)
#define PPP_OVER_GRE         11
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
#define TUNNEL_INCR_PKT_RTV_NOLOCK(p) do {                                          \
        ((p)->root ? (p)->root->tunnel_rtv_cnt++ : (p)->tunnel_rtv_cnt++);          \
    } while (0)
#define TUNNEL_INCR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_tpr_cnt++ : (p)->tunnel_tpr_cnt++);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)
#define TUNNEL_PKT_RTV(p) ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)
#define UNSET_TUNNEL_PKT(p)         ((p)->flags &= ~PKT_TUNNEL)
#define VLAN_OVER_GRE        13

#define addr_data16 address.address_un_data16
#define addr_data32 address.address_un_data32
#define addr_data8  address.address_un_data8
#define addr_in6addr    address.address_un_in6
#define icmpv4vars  l4vars.icmpv4vars
#define icmpv6vars  l4vars.icmpv6vars
#define tcpvars     l4vars.tcpvars


#define NSH_NEXT_PROTO_ETHERNET    0x3
#define NSH_NEXT_PROTO_EXPERIMENT1 0xFE
#define NSH_NEXT_PROTO_EXPERIMENT2 0xFF
#define NSH_NEXT_PROTO_IPV4        0x1
#define NSH_NEXT_PROTO_IPV6        0x2
#define NSH_NEXT_PROTO_MPLS        0x5
#define NSH_NEXT_PROTO_NSH         0x4
#define NSH_NEXT_PROTO_UNASSIGNED  0x0

#define THREAD_SET_AFFINITY     0x01 
#define THREAD_SET_AFFTYPE      0x04 
#define THREAD_SET_PRIORITY     0x02 
#define THV_CAPTURE_INJECT_PKT  BIT_U32(11)
#define THV_CLOSED              BIT_U32(6)  
#define THV_DEAD                BIT_U32(12) 
#define THV_DEINIT              BIT_U32(7)
#define THV_FAILED              BIT_U32(5)  
#define THV_FLOW_LOOP           BIT_U32(10) 
#define THV_INIT_DONE           BIT_U32(1)  
#define THV_KILL                BIT_U32(4)  
#define THV_KILL_PKTACQ         BIT_U32(9)  
#define THV_PAUSE               BIT_U32(2)  
#define THV_PAUSED              BIT_U32(3)  
#define THV_RUNNING_DONE        BIT_U32(8)  
#define THV_USE                 BIT_U32(0)  


#define StatsSyncCounters(tv) \
    StatsUpdateCounterArray(&(tv)->perf_private_ctx, &(tv)->perf_public_ctx);  \

#define StatsSyncCountersIfSignalled(tv)                                       \
    do {                                                                        \
        if ((tv)->perf_public_ctx.perf_flag == 1) {                             \
            StatsUpdateCounterArray(&(tv)->perf_private_ctx,                   \
                                     &(tv)->perf_public_ctx);                   \
        }                                                                       \
    } while (0)


#define CPU_ISSET(cpu_id, new_mask) ((*(new_mask)).affinity_tag == (cpu_id + 1))
#define CPU_SET(cpu_id, new_mask) (*(new_mask)).affinity_tag = (cpu_id + 1)
#define CPU_ZERO(new_mask) (*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL

#define cpu_set_t cpuset_t
#define ETHERNET_TYPE_MPLS_MULTICAST 0x8848
#define ETHERNET_TYPE_MPLS_UNICAST   0x8847


#define GET_VNTAG_DEST(vntagh)    ((SCNtohl((vntagh)->tag) & 0x3FFF0000) >> 16)
#define GET_VNTAG_DIR(vntagh)     ((SCNtohl((vntagh)->tag) & 0x80000000) >> 31)
#define GET_VNTAG_LOOPED(vntagh)  ((SCNtohl((vntagh)->tag) & 0x00008000) >> 15)
#define GET_VNTAG_PROTO(vntagh)   ((SCNtohs((vntagh)->protocol)))
#define GET_VNTAG_PTR(vntagh)     ((SCNtohl((vntagh)->tag) & 0x40000000) >> 30)
#define GET_VNTAG_SRC(vntagh)     ((SCNtohl((vntagh)->tag) & 0x00000FFF))
#define GET_VNTAG_VERSION(vntagh) ((SCNtohl((vntagh)->tag) & 0x00003000) >> 12)
#define VNTAG_HEADER_LEN 6

#define ETHERNET_TYPE_VLAN          0x8100
#define GET_VLAN_CFI(vlanh)         ((SCNtohs((vlanh)->vlan_cfi) & 0x0100) >> 12)
#define GET_VLAN_ID(vlanh)          ((uint16_t)(SCNtohs((vlanh)->vlan_cfi) & 0x0FFF))
#define GET_VLAN_PRIORITY(vlanh)    ((SCNtohs((vlanh)->vlan_cfi) & 0xe000) >> 13)
#define GET_VLAN_PROTO(vlanh)       ((SCNtohs((vlanh)->protocol)))
#define VLAN_GET_ID1(p)             DecodeVLANGetId((p), 0)
#define VLAN_GET_ID2(p)             DecodeVLANGetId((p), 1)
#define VLAN_HEADER_LEN 4



#define CLEAR_ESP_PACKET(p)                                                                        \
    {                                                                                              \
        (p)->esph = NULL;                                                                          \
    }                                                                                              \
    while (0)
#define ESP_GET_RAW_SEQUENCE(esph) SCNtohl((esph)->sequence)
#define ESP_GET_RAW_SPI(esph)      SCNtohl((esph)->spi)
#define ESP_GET_SEQUENCE(p) ESP_GET_RAW_SEQUENCE(p->esph)
#define ESP_GET_SPI(p) ESP_GET_RAW_SPI(p->esph)
#define ESP_HEADER_LEN 8

#define CLEAR_SCTP_PACKET(p) { \
    (p)->sctph = NULL; \
} while (0)
#define SCTP_GET_DST_PORT(p)                  SCTP_GET_RAW_DST_PORT(p->sctph)
#define SCTP_GET_RAW_DST_PORT(sctph)          SCNtohs((sctph)->sh_dport)
#define SCTP_GET_RAW_SRC_PORT(sctph)          SCNtohs((sctph)->sh_sport)
#define SCTP_GET_SRC_PORT(p)                  SCTP_GET_RAW_SRC_PORT(p->sctph)
#define SCTP_HEADER_LEN                       12

#define CLEAR_UDP_PACKET(p) do {    \
    (p)->level4_comp_csum = -1;     \
    (p)->udph = NULL;               \
} while (0)
#define UDP_GET_DST_PORT(p)                  UDP_GET_RAW_DST_PORT(p->udph)
#define UDP_GET_LEN(p)                       UDP_GET_RAW_LEN(p->udph)
#define UDP_GET_RAW_DST_PORT(udph)           SCNtohs((udph)->uh_dport)
#define UDP_GET_RAW_LEN(udph)                SCNtohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph)           SCNtohs((udph)->uh_sport)
#define UDP_GET_RAW_SUM(udph)                SCNtohs((udph)->uh_sum)
#define UDP_GET_SRC_PORT(p)                  UDP_GET_RAW_SRC_PORT(p->udph)
#define UDP_GET_SUM(p)                       UDP_GET_RAW_SUM(p->udph)
#define UDP_HEADER_LEN         8

#define CERT_PATH_ADVERT            149
#define CERT_PATH_SOLICIT           148
#define CLEAR_ICMPV6_PACKET(p) do { \
    (p)->level4_comp_csum = -1;     \
    PACKET_CLEAR_L4VARS((p));       \
    (p)->icmpv6h = NULL;            \
} while(0)
#define DUPL_ADDR_CONFIRM           158
#define DUPL_ADDR_REQUEST           157
#define FMIPV6_MSG                  154
#define HOME_AGENT_AD_REPLY         145
#define HOME_AGENT_AD_REQUEST       144
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
#define ICMP6_MOBILE_EXPERIMENTAL   150
#define ICMP6_NI_QUERY              139
#define ICMP6_NI_REPLY              140
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_PARAMPROB_HEADER        0 
#define ICMP6_PARAMPROB_NEXTHEADER    1 
#define ICMP6_PARAMPROB_OPTION        2 
#define ICMP6_PARAM_PROB              4
#define ICMP6_RR                    138
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
#define ICMPV6_GET_MTU(p)          SCNtohl((p)->icmpv6h->icmpv6b.icmpv6e.mtu)
#define ICMPV6_GET_RAW_CSUM(p)      SCNtohs((p)->icmpv6h->csum)
#define ICMPV6_GET_SEQ(p)       (p)->icmpv6vars.seq
#define ICMPV6_GET_TYPE(p)      (p)->icmpv6h->type
#define ICMPV6_GET_UNUSED(p)       (p)->icmpv6h->icmpv6b.icmpv6e.unused
#define ICMPV6_HAS_MTU(p)          ((p)->icmpv6h->type == ICMP6_PACKET_TOO_BIG)
#define ICMPV6_HEADER_LEN       8
#define ICMPV6_HEADER_PKT_OFFSET 8
#define LOCATOR_UDATE_MSG           156
#define MC_ROUTER_ADVERT            151
#define MC_ROUTER_SOLICIT           152
#define MC_ROUTER_TERMINATE         153
#define MLD_LISTENER_QUERY          130
#define MLD_LISTENER_REDUCTION      132
#define MLD_LISTENER_REPORT         131
#define MLD_V2_LIST_REPORT          143
#define MOBILE_PREFIX_ADVERT        147
#define MOBILE_PREFIX_SOLICIT       146
#define MPL_CONTROL_MSG             159
#define ND_INVERSE_ADVERT           142
#define ND_INVERSE_SOLICIT          141
#define ND_NEIGHBOR_ADVERT          136
#define ND_NEIGHBOR_SOLICIT         135
#define ND_REDIRECT                 137
#define ND_ROUTER_ADVERT            134
#define ND_ROUTER_SOLICIT           133
#define RPL_CONTROL_MSG             155

#define CLEAR_IPV6_PACKET(p) do { \
    (p)->ip6h = NULL; \
    (p)->ip6vars.l4proto = 0; \
    (p)->ip6vars.exthdrs_len = 0; \
    memset(&(p)->ip6eh, 0x00, sizeof((p)->ip6eh)); \
} while (0)
#define IPV6OPT_HAO                   0xC9
#define IPV6OPT_JUMBO                 0xC2
#define IPV6OPT_PAD1                  0x00
#define IPV6OPT_PADN                  0x01
#define IPV6OPT_RA                    0x05
#define IPV6_EXTHDR_GET_FH_FLAG(p)          (p)->ip6eh.fh_more_frags_set
#define IPV6_EXTHDR_GET_FH_ID(p)            (p)->ip6eh.fh_id
#define IPV6_EXTHDR_GET_FH_NH(p)            (p)->ip6eh.fh_nh
#define IPV6_EXTHDR_GET_FH_OFFSET(p)        (p)->ip6eh.fh_offset
#define IPV6_EXTHDR_ISSET_FH(p)     (p)->ip6eh.fh_set
#define IPV6_EXTHDR_ISSET_RH(p)     (p)->ip6eh.rh_set
#define IPV6_EXTHDR_SET_FH(p)       (p)->ip6eh.fh_set = true
#define IPV6_EXTHDR_SET_RH(p)       (p)->ip6eh.rh_set = true
#define IPV6_GET_CLASS(p) \
    IPV6_GET_RAW_CLASS((p)->ip6h)
#define IPV6_GET_EXTHDRS_LEN(p) \
    ((p)->ip6vars.exthdrs_len)
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
#define IPV6_GET_RAW_CLASS(ip6h)        ((SCNtohl((ip6h)->s_ip6_flow) & 0x0FF00000) >> 20)
#define IPV6_GET_RAW_FLOW(ip6h)         (SCNtohl((ip6h)->s_ip6_flow) & 0x000FFFFF)
#define IPV6_GET_RAW_HLIM(ip6h)         ((ip6h)->s_ip6_hlim)
#define IPV6_GET_RAW_NH(ip6h)           ((ip6h)->s_ip6_nxt)
#define IPV6_GET_RAW_PLEN(ip6h)         (SCNtohs((ip6h)->s_ip6_plen))
#define IPV6_GET_RAW_VER(ip6h)          (((ip6h)->s_ip6_vfc & 0xf0) >> 4)
#define IPV6_GET_VER(p) \
    IPV6_GET_RAW_VER((p)->ip6h)
#define IPV6_HEADER_LEN            40
#define IPV6_MAX_OPT               40
#define IPV6_SET_EXTHDRS_LEN(p,len)     (p)->ip6vars.exthdrs_len = (len)
#define IPV6_SET_L4PROTO(p,proto)       (p)->ip6vars.l4proto = (proto)
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
    (p)->level4_comp_csum = -1;     \
    PACKET_CLEAR_L4VARS((p));       \
    (p)->icmpv4h = NULL;            \
} while(0)
#define ICMPV4_DEST_UNREACH_IS_VALID(p) ( \
    (!((p)->flags & PKT_IS_INVALID)) && \
    ((p)->icmpv4h != NULL) && \
    (ICMPV4_GET_TYPE((p)) == ICMP_DEST_UNREACH) && \
    (ICMPV4_GET_EMB_IPV4((p)) != NULL) && \
    ((ICMPV4_GET_EMB_TCP((p)) != NULL) || \
     (ICMPV4_GET_EMB_UDP((p)) != NULL)))
#define ICMPV4_GET_CODE(p)      (p)->icmpv4h->code
#define ICMPV4_GET_CSUM(p)      (p)->icmpv4h->checksum
#define ICMPV4_GET_EMB_ICMPV4H(p)  (p)->icmpv4vars.emb_icmpv4h
#define ICMPV4_GET_EMB_IPV4(p)     (p)->icmpv4vars.emb_ipv4h
#define ICMPV4_GET_EMB_PROTO(p)    (p)->icmpv4vars.emb_ip4_proto
#define ICMPV4_GET_EMB_TCP(p)      (p)->icmpv4vars.emb_tcph
#define ICMPV4_GET_EMB_UDP(p)      (p)->icmpv4vars.emb_udph
#define ICMPV4_GET_HLEN_ICMPV4H(p) (p)->icmpv4vars.hlen
#define ICMPV4_GET_ID(p)        ((p)->icmpv4vars.id)
#define ICMPV4_GET_RAW_CSUM(p)  SCNtohs((p)->icmpv4h->checksum)
#define ICMPV4_GET_SEQ(p)       ((p)->icmpv4vars.seq)
#define ICMPV4_GET_TYPE(p)      (p)->icmpv4h->type
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
#define ICMP_ROUTERADVERT       9
#define ICMP_ROUTERSOLICIT      10
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
#define GRE_GET_PROTO(r)     SCNtohs(r->ether_type)
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

#define CHDLC_HEADER_LEN           4

#define ETHERNET_DCE_HEADER_LEN       (ETHERNET_HEADER_LEN + 2)
#define ETHERNET_HEADER_LEN           14
#define ETHERNET_TYPE_8021AD          0x88a8
#define ETHERNET_TYPE_8021AH          0x88e7
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_8021QINQ        0x9100
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_BRIDGE          0x6558 
#define ETHERNET_TYPE_DCE             0x8903 
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_ERSPAN          0x88BE
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_LOOP            0x9000
#define ETHERNET_TYPE_NSH 0x894F
#define ETHERNET_TYPE_PPPOE_DISC      0x8863 
#define ETHERNET_TYPE_PPPOE_SESS      0x8864 
#define ETHERNET_TYPE_PUP             0x0200 
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_VNTAG 0x8926 


#define ACTION_ALERT        0x01
#define ACTION_CONFIG       0x40
#define ACTION_DROP         0x02
#define ACTION_PASS         0x20
#define ACTION_REJECT       0x04
#define ACTION_REJECT_ANY   (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)
#define ACTION_REJECT_BOTH  0x10
#define ACTION_REJECT_DST   0x08

#define CLUSTER_FLOW 0
#define CLUSTER_FLOW_5_TUPLE 4
#define CLUSTER_ROUND_ROBIN 1
#define PFRING_CONF_FLAGS_BYPASS  (1 << 1)
#define PFRING_CONF_FLAGS_CLUSTER (1 << 0)
#define PFRING_IFACE_NAME_LENGTH 48

#define WINDIVERT_FILTER_MAXLEN 128 

#define NETMAP_IFACE_NAME_LENGTH    48

#define AFPV_CLEANUP(afpv) do {           \
    (afpv)->relptr = NULL;                \
    (afpv)->copy_mode = 0;                \
    (afpv)->peer = NULL;                  \
    (afpv)->mpeer = NULL;                 \
    (afpv)->v4_map_fd = -1;               \
    (afpv)->v6_map_fd = -1;               \
} while(0)
#define AFP_BLOCK_SIZE_DEFAULT_ORDER 3
#define AFP_BYPASS   (1<<7)
#define AFP_COPY_MODE_IPS   2
#define AFP_COPY_MODE_NONE  0
#define AFP_COPY_MODE_TAP   1
#define AFP_EMERGENCY_MODE (1<<3)
#define AFP_IFACE_NAME_LENGTH 48
#define AFP_MMAP_LOCKED (1<<6)
#define AFP_MODE_EBPF_BYPASS 2
#define AFP_MODE_XDP_BYPASS 1
#define AFP_RING_MODE (1<<0)
#define AFP_SOCK_PROTECT (1<<2)
#define AFP_TPACKET_V3 (1<<4)
#define AFP_VLAN_IN_HEADER (1<<5)
#define AFP_XDPBYPASS   (1<<8)
#define HAVE_PACKET_FANOUT 1
#define PACKET_FANOUT                  18
#define PACKET_FANOUT_CPU              2
#define PACKET_FANOUT_FLAG_DEFRAG      0x8000
#define PACKET_FANOUT_HASH             0
#define PACKET_FANOUT_LB               1
#define PACKET_FANOUT_QM               5
#define PACKET_FANOUT_RND              4
#define PACKET_FANOUT_ROLLOVER         3

#define LIBPCAP_COPYWAIT    500
#define LIBPCAP_PROMISC     1
#define PCAP_IFACE_NAME_LENGTH 128

#define IPFW_MAX_QUEUE 16

#define NFQ_MAX_QUEUE 65535

#define NFLOG_GROUP_NAME_LENGTH 48

#define HB_HIGHWATER 2048 
#define MAX_ADAPTERS 8
#define MAX_HOSTBUFFER 4
#define MAX_PORTS 80
#define MAX_STREAMS 256
    #define NAPATECH_DEBUG(...) printf(__VA_ARGS__)
#define NAPATECH_ERROR(err_type, status) {  \
    char errorBuffer[1024]; \
    NT_ExplainError((status), errorBuffer, sizeof (errorBuffer) - 1); \
    SCLogError((err_type), "Napatech Error: %s", errorBuffer);   \
    }
#define NAPATECH_FLOWTYPE_DROP 7
#define NAPATECH_FLOWTYPE_PASS 8
#define NAPATECH_KEYTYPE_IPV4 3
#define NAPATECH_KEYTYPE_IPV4_SPAN 4
#define NAPATECH_KEYTYPE_IPV6 5
#define NAPATECH_KEYTYPE_IPV6_SPAN 6
#define NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status) { \
    char errorBuffer[1024]; \
    NT_ExplainError(status, errorBuffer, sizeof (errorBuffer) - 1); \
    SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
               "     NTPL failed: %s", errorBuffer); \
    SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
               "         cmd: %s", ntpl_cmd); \
    if (strncmp(ntpl_info.u.errorData.errBuffer[0], "", 256) != 0) \
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
                   "         %s", ntpl_info.u.errorData.errBuffer[0]); \
    if (strncmp(ntpl_info.u.errorData.errBuffer[1], "", 256) != 0) \
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
                   "         %s", ntpl_info.u.errorData.errBuffer[1]); \
    if (strncmp(ntpl_info.u.errorData.errBuffer[2], "", 256) != 0) \
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
                   "         %s", ntpl_info.u.errorData.errBuffer[2]); \
}
    #define NAPATECH_PRINTIP(a) NapatechPrintIP(uint32_t address)


#define PLUGIN_VAR_SIZE 64


#define STREAM_DEPTH        BIT_U8(5)   
#define STREAM_EOF          BIT_U8(1)
#define STREAM_FLAGS_FOR_PACKET(p) PKT_IS_TOSERVER((p)) ? STREAM_TOSERVER : STREAM_TOCLIENT
#define STREAM_FLUSH        BIT_U8(7)
#define STREAM_GAP          BIT_U8(4)   
#define STREAM_MIDSTREAM    BIT_U8(6)
#define STREAM_START        BIT_U8(0)
#define STREAM_TOCLIENT     BIT_U8(3)
#define STREAM_TOSERVER     BIT_U8(2)

#define FLOWFILE_INIT                   0
#define FLOWFILE_NONE    (FLOWFILE_NONE_TS|FLOWFILE_NONE_TC)
#define FLOWFILE_NONE_TC (FLOWFILE_NO_MAGIC_TC | \
                          FLOWFILE_NO_STORE_TC | \
                          FLOWFILE_NO_MD5_TC   | \
                          FLOWFILE_NO_SHA1_TC  | \
                          FLOWFILE_NO_SHA256_TC| \
                          FLOWFILE_NO_SIZE_TC)
#define FLOWFILE_NONE_TS (FLOWFILE_NO_MAGIC_TS | \
                          FLOWFILE_NO_STORE_TS | \
                          FLOWFILE_NO_MD5_TS   | \
                          FLOWFILE_NO_SHA1_TS  | \
                          FLOWFILE_NO_SHA256_TS| \
                          FLOWFILE_NO_SIZE_TS)
#define FLOWFILE_NO_MAGIC_TC            BIT_U16(1)
#define FLOWFILE_NO_MAGIC_TS            BIT_U16(0)
#define FLOWFILE_NO_MD5_TC              BIT_U16(5)
#define FLOWFILE_NO_MD5_TS              BIT_U16(4)
#define FLOWFILE_NO_SHA1_TC             BIT_U16(7)
#define FLOWFILE_NO_SHA1_TS             BIT_U16(6)
#define FLOWFILE_NO_SHA256_TC           BIT_U16(9)
#define FLOWFILE_NO_SHA256_TS           BIT_U16(8)
#define FLOWFILE_NO_SIZE_TC             BIT_U16(11)
#define FLOWFILE_NO_SIZE_TS             BIT_U16(10)
#define FLOWFILE_NO_STORE_TC            BIT_U16(3)
#define FLOWFILE_NO_STORE_TS            BIT_U16(2)
    #define FLOWLOCK_DESTROY(fb) SCRWLockDestroy(&(fb)->r)
    #define FLOWLOCK_INIT(fb) SCRWLockInit(&(fb)->r, NULL)

    #define FLOWLOCK_RDLOCK(fb) SCRWLockRDLock(&(fb)->r)
    #define FLOWLOCK_TRYRDLOCK(fb) SCRWLockTryRDLock(&(fb)->r)
    #define FLOWLOCK_TRYWRLOCK(fb) SCRWLockTryWRLock(&(fb)->r)
    #define FLOWLOCK_UNLOCK(fb) SCRWLockUnlock(&(fb)->r)
    #define FLOWLOCK_WRLOCK(fb) SCRWLockWRLock(&(fb)->r)
#define FLOW_ACTION_DROP                BIT_U32(7)
#define FLOW_ACTION_PASS BIT_U32(28)
#define FLOW_CHANGE_PROTO               BIT_U32(24)
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
        (pa)->family = AF_INET6;                        \
        (pa)->addr_data32[0] = (fa)->addr_data32[0];    \
        (pa)->addr_data32[1] = (fa)->addr_data32[1];    \
        (pa)->addr_data32[2] = (fa)->addr_data32[2];    \
        (pa)->addr_data32[3] = (fa)->addr_data32[3];    \
    } while (0)
#define FLOW_DIR_REVERSED               BIT_U32(26)
#define FLOW_END_FLAG_EMERGENCY         0x08
#define FLOW_END_FLAG_FORCED            0x20
#define FLOW_END_FLAG_SHUTDOWN          0x40
#define FLOW_END_FLAG_STATE_BYPASSED    0x80
#define FLOW_END_FLAG_STATE_CLOSED      0x04
#define FLOW_END_FLAG_STATE_ESTABLISHED 0x02
#define FLOW_END_FLAG_STATE_NEW         0x01
#define FLOW_END_FLAG_TIMEOUT           0x10
#define FLOW_GET_DP(f)  \
    ((f)->flags & FLOW_DIR_REVERSED) ? (f)->sp : (f)->dp;
#define FLOW_GET_SP(f)  \
    ((f)->flags & FLOW_DIR_REVERSED) ? (f)->dp : (f)->sp;
#define FLOW_HAS_ALERTS                 BIT_U32(12)
#define FLOW_HAS_EXPECTATION            BIT_U32(27)
#define FLOW_IPV4                       BIT_U32(20)
#define FLOW_IPV6                       BIT_U32(21)
#define FLOW_IS_IPV4(f) \
    (((f)->flags & FLOW_IPV4) == FLOW_IPV4)
#define FLOW_IS_IPV6(f) \
    (((f)->flags & FLOW_IPV6) == FLOW_IPV6)
#define FLOW_IS_PE_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PE_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PE_ALPROTO_DETECT_DONE))
#define FLOW_IS_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_IS_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PP_ALPROTO_DETECT_DONE))
#define FLOW_NOPACKET_INSPECTION        BIT_U32(5)
#define FLOW_NOPAYLOAD_INSPECTION       BIT_U32(6)
#define FLOW_PKT_ESTABLISHED            0x04
#define FLOW_PKT_LAST_PSEUDO            0x80
#define FLOW_PKT_TOCLIENT               0x02
#define FLOW_PKT_TOCLIENT_FIRST         0x40
#define FLOW_PKT_TOCLIENT_IPONLY_SET    0x10
#define FLOW_PKT_TOSERVER               0x01
#define FLOW_PKT_TOSERVER_FIRST         0x20
#define FLOW_PKT_TOSERVER_IPONLY_SET    0x08
#define FLOW_PROTO_DETECT_TC_DONE       BIT_U32(23)
#define FLOW_PROTO_DETECT_TS_DONE       BIT_U32(22)
#define FLOW_QUIET   true
#define FLOW_RESET_PE_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PE_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PE_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PP_ALPROTO_DETECT_DONE))
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
#define FLOW_SET_PE_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PE_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PE_ALPROTO_DETECT_DONE))
#define FLOW_SET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_SET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PP_ALPROTO_DETECT_DONE))
#define FLOW_SGH_TOCLIENT               BIT_U32(9)
#define FLOW_SGH_TOSERVER               BIT_U32(8)
#define FLOW_TCP_REUSED                 BIT_U32(2)
#define FLOW_TC_PE_ALPROTO_DETECT_DONE  BIT_U32(18)
#define FLOW_TC_PM_ALPROTO_DETECT_DONE  BIT_U32(16)
#define FLOW_TC_PP_ALPROTO_DETECT_DONE  BIT_U32(17)
#define FLOW_TIMEOUT_REASSEMBLY_DONE    BIT_U32(19)
#define FLOW_TOCLIENT_DROP_LOGGED       BIT_U32(11)
#define FLOW_TOCLIENT_IPONLY_SET        BIT_U32(4)
#define FLOW_TOSERVER_DROP_LOGGED       BIT_U32(10)
#define FLOW_TOSERVER_IPONLY_SET        BIT_U32(3)
#define FLOW_TO_DST_SEEN                BIT_U32(1)
#define FLOW_TO_SRC_SEEN                BIT_U32(0)
#define FLOW_TS_PE_ALPROTO_DETECT_DONE  BIT_U32(15)
#define FLOW_TS_PM_ALPROTO_DETECT_DONE  BIT_U32(13)
#define FLOW_TS_PP_ALPROTO_DETECT_DONE  BIT_U32(14)
#define FLOW_VERBOSE false
#define FLOW_WRONG_THREAD               BIT_U32(25)
#define TOCLIENT 1
#define TOSERVER 0

    #define FQLOCK_DESTROY(q) SCSpinDestroy(&(q)->s)
    #define FQLOCK_INIT(q) SCSpinInit(&(q)->s, 0)
    #define FQLOCK_LOCK(q) SCSpinLock(&(q)->s)

    #define FQLOCK_TRYLOCK(q) SCSpinTrylock(&(q)->s)
    #define FQLOCK_UNLOCK(q) SCSpinUnlock(&(q)->s)

#define qbot priv.bot
#define qlen priv.len
#define qtop priv.top

#define cc_barrier() __asm__ __volatile__("": : :"memory")
#define hw_barrier() __sync_synchronize()



#define DETECT_TAG_MATCH_LIMIT 10
#define DETECT_TAG_MAX_PKTS 256
#define DETECT_TAG_MAX_TAGS 50
#define TAG_ENTRY_FLAG_DIR_DST          0x02
#define TAG_ENTRY_FLAG_DIR_SRC          0x01
#define TAG_ENTRY_FLAG_SKIPPED_FIRST    0x04

#define FROM_TIMEVAL(timev) { .tv_sec = (timev).tv_sec, .tv_nsec = (timev).tv_usec * 1000 }
#define TIMEVAL_DIFF_SEC(tv_new, tv_old) \
    (uint64_t)((((uint64_t)(tv_new).tv_sec * 1000000 + (tv_new).tv_usec) - \
                ((uint64_t)(tv_old).tv_sec * 1000000 + (tv_old).tv_usec)) / \
               1000000)
#define TIMEVAL_EARLIER(tv_first, tv_second) \
    (((tv_first).tv_sec < (tv_second).tv_sec) || \
     ((tv_first).tv_sec == (tv_second).tv_sec && (tv_first).tv_usec < (tv_second).tv_usec))

#  define CONFIG_DIR "/etc/suricata"
#define DEFAULT_CONF_FILE CONFIG_DIR "/suricata.yaml"
#define DEFAULT_PID_BASENAME "suricata.pid"
#define DEFAULT_PID_DIR LOCAL_STATE_DIR "/run/"
#define DEFAULT_PID_FILENAME DEFAULT_PID_DIR DEFAULT_PID_BASENAME
#define DOC_URL "https://suricata.readthedocs.io/en/"
#define IS_SURI_HOST_MODE_ROUTER(host_mode)  ((host_mode) == SURI_HOST_IS_ROUTER)
#define IS_SURI_HOST_MODE_SNIFFER_ONLY(host_mode)  ((host_mode) == SURI_HOST_IS_SNIFFER_ONLY)
#define PROG_NAME "Suricata"
#define PROG_VER PACKAGE_VERSION
#define RunmodeIsUnittests() 0
#define SURICATA_DONE    (1 << 2)   
#define SURICATA_STOP    (1 << 0)   

#define u8_tolower(c) tolower((uint8_t)(c))
#define u8_toupper(c) toupper((uint8_t)(c))














#define MAX_DEVNAME 10
#define OFFLOAD_FLAG_GRO    (1<<3)
#define OFFLOAD_FLAG_GSO    (1<<2)
#define OFFLOAD_FLAG_LRO    (1<<4)
#define OFFLOAD_FLAG_RXCSUM (1<<5)
#define OFFLOAD_FLAG_SG     (1<<0)
#define OFFLOAD_FLAG_TOE    (1<<7)
#define OFFLOAD_FLAG_TSO    (1<<1)
#define OFFLOAD_FLAG_TXCSUM (1<<6)

#define UNIX_CMD_TAKE_ARGS 1



#define SREP_MAX_CATS 60
#define SREP_MAX_VAL 127

#define HOST_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(host_memuse) + (uint64_t)(size)) <= SC_ATOMIC_GET(host_config.memcap)))
#define HOST_QUIET      1
#define HOST_VERBOSE    0
    #define HRLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->lock)
    #define HRLOCK_INIT(fb) SCSpinInit(&(fb)->lock, 0)
    #define HRLOCK_LOCK(fb) SCSpinLock(&(fb)->lock)

    #define HRLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->lock)
    #define HRLOCK_TYPE SCSpinlock
    #define HRLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->lock)
#define HostDeReference(src_h_ptr) do {               \
        if (*(src_h_ptr) != NULL) {                   \
            HostDecrUsecnt(*(src_h_ptr));             \
            *(src_h_ptr) = NULL;                      \
        }                                             \
    } while (0)
#define HostDecrUsecnt(h) \
    (void)SC_ATOMIC_SUB((h)->use_cnt, 1)
#define HostIncrUsecnt(h) \
    (void)SC_ATOMIC_ADD((h)->use_cnt, 1)
#define HostReference(dst_h_ptr, h) do {            \
        if ((h) != NULL) {                          \
            HostIncrUsecnt((h));                    \
            *(dst_h_ptr) = h;                       \
        }                                           \
    } while (0)


#define FILE_HAS_GAPS   BIT_U16(15)
#define FILE_LOGGED     BIT_U16(8)
#define FILE_MD5        BIT_U16(3)
#define FILE_NOMAGIC    BIT_U16(1)
#define FILE_NOMD5      BIT_U16(2)
#define FILE_NOSHA1     BIT_U16(4)
#define FILE_NOSHA256   BIT_U16(6)
#define FILE_NOSTORE    BIT_U16(9)
#define FILE_NOTRACK    BIT_U16(12) 
#define FILE_SHA1       BIT_U16(5)
#define FILE_SHA256     BIT_U16(7)
#define FILE_STORE      BIT_U16(10)
#define FILE_STORED     BIT_U16(11)
#define FILE_TRUNCATED  BIT_U16(0)
#define FILE_USE_DETECT BIT_U16(13) 
#define SC_MD5_LEN 16
#define SC_SHA1_LEN 20
#define SC_SHA256_LEN 32

#define STREAMING_BUFFER_AUTOSLIDE  (1<<0)
#define STREAMING_BUFFER_CONFIG_INITIALIZER { 0, 0, 0, NULL, NULL, NULL, NULL, }
#define STREAMING_BUFFER_INITIALIZER(cfg)                                                          \
    {                                                                                              \
        (cfg),                                                                                     \
        0,                                                                                         \
        NULL,                                                                                      \
        0,                                                                                         \
        0,                                                                                         \
        { NULL },                                                                                  \
        NULL,                                                                                      \
        0,                                                                                         \
    };
#define STREAMING_BUFFER_NOFLAGS     0

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
#define RB_FOREACH(x, name, head)					\
	for ((x) = RB_MIN(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_NEXT(x))
#define RB_FOREACH_FROM(x, name, y)					\
	for ((x) = (y);							\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_REVERSE(x, name, head)				\
	for ((x) = RB_MAX(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_PREV(x))
#define RB_FOREACH_REVERSE_FROM(x, name, y)				\
	for ((x) = (y);							\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	for ((x) = RB_MAX(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_SAFE(x, name, head, y)				\
	for ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), (x) != NULL);	\
	     (x) = (y))
#define RB_GENERATE_FIND(name, type, field, cmp, attr)			\
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
}
#define RB_GENERATE_INSERT(name, type, field, cmp, attr)		\
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
}
#define RB_GENERATE_INSERT_COLOR(name, type, field, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *parent, *gparent, *tmp;				\
	while ((parent = RB_PARENT(elm, field)) != NULL &&		\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		_T_ASSERT(gparent);					\
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
}
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
	RB_GENERATE_INSERT_COLOR(name, type, field, attr)		\
	RB_GENERATE_REMOVE_COLOR(name, type, field, attr)		\
	RB_GENERATE_INSERT(name, type, field, cmp, attr)		\
	RB_GENERATE_REMOVE(name, type, field, attr)			\
	RB_GENERATE_FIND(name, type, field, cmp, attr)			\
	RB_GENERATE_NFIND(name, type, field, cmp, attr)			\
	RB_GENERATE_NEXT(name, type, field, attr)			\
	RB_GENERATE_PREV(name, type, field, attr)			\
	RB_GENERATE_MINMAX(name, type, field, attr)
#define RB_GENERATE_MINMAX(name, type, field, attr)			\
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
#define RB_GENERATE_NEXT(name, type, field, attr)			\
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
}
#define RB_GENERATE_NFIND(name, type, field, cmp, attr)			\
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
}
#define RB_GENERATE_PREV(name, type, field, attr)			\
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
}
#define RB_GENERATE_REMOVE(name, type, field, attr)			\
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
		while ((left = RB_LEFT(elm, field)) != NULL)		\
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
		_T_ASSERT((old));					\
		(elm)->field = (old)->field;				\
		if (RB_PARENT(old, field)) {				\
			if (RB_LEFT(RB_PARENT(old, field), field) == old)\
				RB_LEFT(RB_PARENT(old, field), field) = elm;\
			else						\
				RB_RIGHT(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} else							\
			RB_ROOT(head) = elm;				\
		_T_ASSERT(old);						\
		_T_ASSERT(RB_LEFT(old, field));				\
		RB_PARENT(RB_LEFT(old, field), field) = elm;		\
		if (RB_RIGHT(old, field))				\
			RB_PARENT(RB_RIGHT(old, field), field) = elm;	\
		if (parent) {						\
			left = parent;					\
			do {						\
				RB_AUGMENT(left);			\
			} while ((left = RB_PARENT(left, field)) != NULL); \
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

#define RB_GENERATE_REMOVE_COLOR(name, type, field, attr)		\
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
			_T_ASSERT(tmp);					\
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
					if ((oleft = RB_LEFT(tmp, field)) \
					    != NULL)			\
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
			_T_ASSERT(tmp);					\
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
					if ((oright = RB_RIGHT(tmp, field)) \
					    != NULL)			\
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
}
#define RB_HEAD(name, type)						\
struct name {								\
	struct type *rbh_root; 			\
}
#define RB_INIT(root) do {						\
	(root)->rbh_root = NULL;					\
} while ( 0)
#define RB_INITIALIZER(root)						\
	{ NULL }
#define RB_LEFT(elm, field)		(elm)->field.rbe_left
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_PROTOTYPE_FIND(name, type, attr)				\
	attr struct type *name##_RB_FIND(struct name *, struct type *)
#define RB_PROTOTYPE_INSERT(name, type, attr)				\
	attr struct type *name##_RB_INSERT(struct name *, struct type *)
#define RB_PROTOTYPE_INSERT_COLOR(name, type, attr)			\
	attr void name##_RB_INSERT_COLOR(struct name *, struct type *)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
	RB_PROTOTYPE_INSERT_COLOR(name, type, attr);			\
	RB_PROTOTYPE_REMOVE_COLOR(name, type, attr);			\
	RB_PROTOTYPE_INSERT(name, type, attr);				\
	RB_PROTOTYPE_REMOVE(name, type, attr);				\
	RB_PROTOTYPE_FIND(name, type, attr);				\
	RB_PROTOTYPE_NFIND(name, type, attr);				\
	RB_PROTOTYPE_NEXT(name, type, attr);				\
	RB_PROTOTYPE_PREV(name, type, attr);				\
	RB_PROTOTYPE_MINMAX(name, type, attr);
#define RB_PROTOTYPE_MINMAX(name, type, attr)				\
	attr struct type *name##_RB_MINMAX(struct name *, int)
#define RB_PROTOTYPE_NEXT(name, type, attr)				\
	attr struct type *name##_RB_NEXT(struct type *)
#define RB_PROTOTYPE_NFIND(name, type, attr)				\
	attr struct type *name##_RB_NFIND(struct name *, struct type *)
#define RB_PROTOTYPE_PREV(name, type, attr)				\
	attr struct type *name##_RB_PREV(struct type *)
#define RB_PROTOTYPE_REMOVE(name, type, attr)				\
	attr struct type *name##_RB_REMOVE(struct name *, struct type *)
#define RB_PROTOTYPE_REMOVE_COLOR(name, type, attr)			\
	attr void name##_RB_REMOVE_COLOR(struct name *, struct type *, struct type *)
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_ROOT(head)			(head)->rbh_root
#define RB_ROTATE_LEFT(head, elm, tmp, field) do {			\
	(tmp) = RB_RIGHT(elm, field);					\
	if ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field)) != NULL) {	\
		RB_PARENT(RB_LEFT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field)) != NULL) {	\
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
} while ( 0)
#define RB_ROTATE_RIGHT(head, elm, tmp, field) do {			\
	(tmp) = RB_LEFT(elm, field);					\
	if ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field)) != NULL) {	\
		RB_PARENT(RB_RIGHT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field)) != NULL) {	\
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
} while ( 0)
#define RB_SET(elm, parent, field) do {					\
	RB_PARENT(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = NULL;		\
	RB_COLOR(elm, field) = RB_RED;					\
} while ( 0)
#define RB_SET_BLACKRED(black, red, field) do {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} while ( 0)
#define SPLAY_ASSEMBLE(head, node, left, right, field) do {		\
	SPLAY_RIGHT(left, field) = SPLAY_LEFT((head)->sph_root, field);	\
	SPLAY_LEFT(right, field) = SPLAY_RIGHT((head)->sph_root, field);\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(node, field);	\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(node, field);	\
} while ( 0)
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
	while ((__comp = (cmp)(elm, (head)->sph_root)) != 0) {		\
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
} while ( 0)
#define SPLAY_INITIALIZER(root)						\
	{ NULL }
#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_LINKLEFT(head, tmp, field) do {				\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);		\
} while ( 0)
#define SPLAY_LINKRIGHT(head, tmp, field) do {				\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);	\
} while ( 0)
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
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_ROTATE_LEFT(head, tmp, field) do {			\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field);	\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while ( 0)
#define SPLAY_ROTATE_RIGHT(head, tmp, field) do {			\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field);	\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while ( 0)
#define _T_ASSERT(a) assert((a))
#define SC_RADIX_BITTEST(x, y) ((x) & (y))

#define HASHLIST_NO_SIZE 0
#define HashListTableGetListData(hb) (hb)->data
#define HashListTableGetListNext(hb) (hb)->listnext

#define HASH_NO_SIZE 0

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



#define MPMCTX_FLAGS_GLOBAL     BIT_U8(0)
#define MPMCTX_FLAGS_NODEPTH    BIT_U8(1)
#define MPM_CTX_FACTORY_UNIQUE_CONTEXT -1
#define MPM_INIT_HASH_SIZE 65536
#define MPM_PATTERN_CTX_OWNS_ID     0x20
#define MPM_PATTERN_FLAG_DEPTH      0x04
#define MPM_PATTERN_FLAG_NEGATED    0x02
#define MPM_PATTERN_FLAG_NOCASE     0x01
#define MPM_PATTERN_FLAG_OFFSET     0x08
#define MPM_PATTERN_ONE_BYTE        0x10

#define PMQ_RESET(pmq) (pmq)->rule_id_array_cnt = 0


#define DETECT_PROTO_ANY            (1 << 0) 
#define DETECT_PROTO_IPV4           (1 << 3) 
#define DETECT_PROTO_IPV6           (1 << 4) 
#define DETECT_PROTO_ONLY_PKT       (1 << 1) 
#define DETECT_PROTO_ONLY_STREAM    (1 << 2) 



#define O_NOFOLLOW 0

#define geteuid() (0)


#define openlog(__ident, __option, __facility)
#define setlogmask (__mask)
#define syslog(__pri, __fmt, __param)
#define SC_HINFO_IS_IPV4 1
#define SC_HINFO_IS_IPV6 0

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

#define PAWS_24DAYS         2073600         
#define PKT_IS_IN_RIGHT_DIR(ssn, p)        ((ssn)->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK ? \
                                            PKT_IS_TOSERVER(p) ? (p)->flowflags &= ~FLOW_PKT_TOSERVER \
                                            (p)->flowflags |= FLOW_PKT_TOCLIENT : (p)->flowflags &= ~FLOW_PKT_TOCLIENT \
                                            (p)->flowflags |= FLOW_PKT_TOSERVER : 0)
#define SEG_SEQ_RIGHT_EDGE(seg) ((seg)->seq + TCP_SEG_LEN((seg)))
#define SEQ_EQ(a,b)  ((int32_t)((a) - (b)) == 0)
#define SEQ_GEQ(a,b) ((int32_t)((a) - (b)) >= 0)
#define SEQ_GT(a,b)  ((int32_t)((a) - (b)) >  0)
#define SEQ_LEQ(a,b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_LT(a,b)  ((int32_t)((a) - (b)) <  0)
#define STREAMTCP_FLAG_3WHS_CONFIRMED               0x1000
#define STREAMTCP_FLAG_4WHS                         0x0080
#define STREAMTCP_FLAG_APP_LAYER_DISABLED           0x2000
#define STREAMTCP_FLAG_ASYNC                        0x0040
#define STREAMTCP_FLAG_BYPASS                       0x4000
#define STREAMTCP_FLAG_CLIENT_SACKOK                0x0200
#define STREAMTCP_FLAG_CLOSED_BY_RST                0x0020
#define STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT    0x0100
#define STREAMTCP_FLAG_MIDSTREAM                    0x0001
#define STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED        0x0002
#define STREAMTCP_FLAG_MIDSTREAM_SYNACK             0x0004
#define STREAMTCP_FLAG_SACKOK                       0x0400
#define STREAMTCP_FLAG_SERVER_WSCALE                0x0010
#define STREAMTCP_FLAG_TCP_FAST_OPEN                0x8000
#define STREAMTCP_FLAG_TIMESTAMP                    0x0008
#define STREAMTCP_QUEUE_FLAG_SACK   0x04
#define STREAMTCP_QUEUE_FLAG_TS     0x01
#define STREAMTCP_QUEUE_FLAG_WS     0x02
#define STREAMTCP_SET_RA_BASE_SEQ(stream, seq) { \
    do { \
        (stream)->base_seq = (seq) + 1;    \
    } while(0); \
}
#define STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED  BIT_U16(7)
#define STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED    BIT_U16(8)
#define STREAMTCP_STREAM_FLAG_DEPTH_REACHED                 BIT_U16(3)
#define STREAMTCP_STREAM_FLAG_DISABLE_RAW                   BIT_U16(10)
#define STREAMTCP_STREAM_FLAG_KEEPALIVE                     BIT_U16(2)
#define STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED              BIT_U16(9)
#define STREAMTCP_STREAM_FLAG_NOREASSEMBLY                  BIT_U16(1)
#define STREAMTCP_STREAM_FLAG_RST_RECV                      BIT_U16(11)
#define STREAMTCP_STREAM_FLAG_TIMESTAMP                     BIT_U16(5)
#define STREAMTCP_STREAM_FLAG_TRIGGER_RAW                   BIT_U16(4)
#define STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP                BIT_U16(6)
#define STREAM_APP_PROGRESS(stream) (STREAM_BASE_OFFSET((stream)) + (stream)->app_progress_rel)
#define STREAM_BASE_OFFSET(stream)  ((stream)->sb.stream_offset)
#define STREAM_HAS_SEEN_DATA(stream)    (!RB_EMPTY(&(stream)->sb.sbb_tree) || (stream)->sb.stream_offset || (stream)->sb.buf_offset)
#define STREAM_LOG_PROGRESS(stream) (STREAM_BASE_OFFSET((stream)) + (stream)->log_progress_rel)
#define STREAM_RAW_PROGRESS(stream) (STREAM_BASE_OFFSET((stream)) + (stream)->raw_progress_rel)
#define STREAM_RIGHT_EDGE(stream)       (STREAM_BASE_OFFSET((stream)) + (STREAM_SEQ_RIGHT_EDGE((stream)) - (stream)->base_seq))
#define STREAM_SEQ_RIGHT_EDGE(stream)   (stream)->segs_right_edge
#define StreamTcpDisableAppLayerReassembly(ssn) do { \
        SCLogDebug("setting STREAMTCP_FLAG_APP_LAYER_DISABLED on ssn %p", ssn); \
        ((ssn)->flags |= STREAMTCP_FLAG_APP_LAYER_DISABLED); \
    } while (0);
#define StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream) \
    ((stream)->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)
#define StreamTcpResetStreamFlagAppProtoDetectionCompleted(stream) \
    ((stream)->flags &= ~STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED);
#define StreamTcpSetEvent(p, e) {                                           \
    if ((p)->flags & PKT_STREAM_NO_EVENTS) {                                \
        SCLogDebug("not setting event %d on pkt %p (%"PRIu64"), "     \
                   "stream in known bad condition", (e), p, (p)->pcap_cnt); \
    } else {                                                                \
        SCLogDebug("setting event %d on pkt %p (%"PRIu64")",          \
                    (e), p, (p)->pcap_cnt);                                 \
        ENGINE_SET_EVENT((p), (e));                                         \
    }                                                                       \
}
#define StreamTcpSetStreamFlagAppProtoDetectionCompleted(stream) \
    ((stream)->flags |= STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)
#define TCP_SEG_LEN(seg)        (seg)->payload_len
#define TCP_SEG_OFFSET(seg)     (seg)->sbseg.stream_offset


#define POOL_BUCKET_PREALLOCATED    (1 << 0)


#define APP_LAYER_ERROR (AppLayerResult) { -1, 0, 0 }
#define APP_LAYER_INCOMPLETE(c,n) (AppLayerResult) { 1, (c), (n) }
#define APP_LAYER_OK (AppLayerResult) { 0, 0, 0 }
#define APP_LAYER_PARSER_BYPASS_READY           BIT_U8(4)
#define APP_LAYER_PARSER_EOF_TC                 BIT_U8(6)
#define APP_LAYER_PARSER_EOF_TS                 BIT_U8(5)
#define APP_LAYER_PARSER_INT_STREAM_DEPTH_SET   BIT_U32(0)
#define APP_LAYER_PARSER_NO_INSPECTION          BIT_U8(1)
#define APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD  BIT_U8(3)
#define APP_LAYER_PARSER_NO_REASSEMBLY          BIT_U8(2)
#define APP_LAYER_PARSER_OPT_ACCEPT_GAPS        BIT_U32(0)
#define APP_LAYER_PARSER_OPT_UNIDIR_TXS         BIT_U32(1)
#define APP_LAYER_TX_INSPECTED_FLAG             BIT_U64(63)
#define APP_LAYER_TX_PREFILTER_MASK ~(APP_LAYER_TX_INSPECTED_FLAG | APP_LAYER_TX_RESERVED_FLAGS)
#define APP_LAYER_TX_RESERVED10_FLAG BIT_U64(57)
#define APP_LAYER_TX_RESERVED11_FLAG BIT_U64(58)
#define APP_LAYER_TX_RESERVED12_FLAG BIT_U64(59)
#define APP_LAYER_TX_RESERVED13_FLAG BIT_U64(60)
#define APP_LAYER_TX_RESERVED14_FLAG BIT_U64(61)
#define APP_LAYER_TX_RESERVED15_FLAG BIT_U64(62)
#define APP_LAYER_TX_RESERVED1_FLAG  BIT_U64(48)
#define APP_LAYER_TX_RESERVED2_FLAG  BIT_U64(49)
#define APP_LAYER_TX_RESERVED3_FLAG  BIT_U64(50)
#define APP_LAYER_TX_RESERVED4_FLAG  BIT_U64(51)
#define APP_LAYER_TX_RESERVED5_FLAG  BIT_U64(52)
#define APP_LAYER_TX_RESERVED6_FLAG  BIT_U64(53)
#define APP_LAYER_TX_RESERVED7_FLAG  BIT_U64(54)
#define APP_LAYER_TX_RESERVED8_FLAG  BIT_U64(55)
#define APP_LAYER_TX_RESERVED9_FLAG  BIT_U64(56)
#define APP_LAYER_TX_RESERVED_FLAGS                                                                \
    (APP_LAYER_TX_RESERVED1_FLAG | APP_LAYER_TX_RESERVED2_FLAG | APP_LAYER_TX_RESERVED3_FLAG |     \
            APP_LAYER_TX_RESERVED4_FLAG | APP_LAYER_TX_RESERVED5_FLAG |                            \
            APP_LAYER_TX_RESERVED6_FLAG | APP_LAYER_TX_RESERVED7_FLAG |                            \
            APP_LAYER_TX_RESERVED8_FLAG | APP_LAYER_TX_RESERVED9_FLAG |                            \
            APP_LAYER_TX_RESERVED10_FLAG | APP_LAYER_TX_RESERVED11_FLAG |                          \
            APP_LAYER_TX_RESERVED12_FLAG | APP_LAYER_TX_RESERVED13_FLAG |                          \
            APP_LAYER_TX_RESERVED14_FLAG | APP_LAYER_TX_RESERVED15_FLAG)

#define CONFIG_SCOPE_DEFAULT CONFIG_SCOPE_TX
#define CONFIG_TYPE_DEFAULT CONFIG_TYPE_TX

#define JB_SET_FALSE(jb, key) jb_set_formatted((jb), "\"" key "\":false")
#define JB_SET_STRING(jb, key, val) jb_set_formatted((jb), "\"" key "\":\"" val "\"")
#define JB_SET_TRUE(jb, key) jb_set_formatted((jb), "\"" key "\":true")
#define SC_MD5_HEX_LEN 32
#define SC_MD5_LEN    16
#define SC_SHA1_LEN   20
#define SC_SHA256_LEN 32







#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH 2
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES 3
#define DETECT_ENGINE_INSPECT_SIG_MATCH 1
#define DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES 4
#define DETECT_ENGINE_INSPECT_SIG_NO_MATCH 0
#define DETECT_ENGINE_STATE_FLAG_FILE_NEW       BIT_U8(0)
#define DE_STATE_CHUNK_SIZE             15
#define DE_STATE_FLAG_BASE                      3UL
#define DE_STATE_FLAG_FILE_INSPECT              BIT_U32(DE_STATE_ID_FILE_INSPECT)
#define DE_STATE_FLAG_FULL_INSPECT              BIT_U32(0)
#define DE_STATE_FLAG_SIG_CANT_MATCH            BIT_U32(1)
#define DE_STATE_ID_FILE_INSPECT                2UL



#define APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER \
    (~STREAM_TOSERVER & ~STREAM_TOCLIENT)





#define STREAMTCP_INIT_FLAG_BYPASS                 BIT_U8(2)
#define STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION    BIT_U8(0)
#define STREAMTCP_INIT_FLAG_DROP_INVALID           BIT_U8(1)
#define STREAMTCP_INIT_FLAG_INLINE                 BIT_U8(3)
#define STREAM_VERBOSE false

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

#define FAIL do {                                      \
        if (unittests_fatal) {                         \
            BUG_ON(1);                                 \
        } else {                                       \
            return 0;                                  \
        }                                              \
    } while (0)
#define FAIL_IF(expr) do {                             \
        if (unittests_fatal) {                         \
            BUG_ON(expr);                              \
        } else if (expr) {                             \
            return 0;                                  \
        }                                              \
    } while (0)
#define FAIL_IF_NOT(expr) do { \
        FAIL_IF(!(expr));      \
    } while (0)
#define FAIL_IF_NOT_NULL(expr) do { \
        FAIL_IF(NULL != expr);      \
    } while (0)
#define FAIL_IF_NULL(expr) do {                 \
        FAIL_IF(NULL == expr);                  \
    } while (0)
#define PASS do { \
        return 1; \
    } while (0)

#define CHECKSUM_INVALID_RATIO 10
#define CHECKSUM_SAMPLE_COUNT 1000ULL

#define SleepMsec(msec) Sleep((msec))
#define SleepUsec(usec) usleep((usec))
#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

#define TM_FLAG_COMMAND_TM      0x40
#define TM_FLAG_DECODE_TM       0x02
#define TM_FLAG_DETECT_TM       0x08
#define TM_FLAG_LOGAPI_TM       0x10 
#define TM_FLAG_MANAGEMENT_TM   0x20
#define TM_FLAG_RECEIVE_TM      0x01
#define TM_FLAG_STREAM_TM       0x04



#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)
#define FLOW_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(flow_memuse) + (uint64_t)(size)) <= SC_ATOMIC_GET(flow_config.memcap)))
#define FLOW_DESTROY(f) do { \
        FlowCleanupAppLayer((f)); \
        \
        FLOWLOCK_DESTROY((f)); \
        GenericVarFree((f)->flowvar); \
    } while(0)
#define FLOW_INITIALIZE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->proto = 0; \
        (f)->livedev = NULL; \
        (f)->timeout_at = 0; \
        (f)->timeout_policy = 0; \
        (f)->vlan_idx = 0; \
        (f)->next = NULL; \
        (f)->flow_state = 0; \
        (f)->use_cnt = 0; \
        (f)->tenant_id = 0; \
        (f)->parent_id = 0; \
        (f)->probing_parser_toserver_alproto_masks = 0; \
        (f)->probing_parser_toclient_alproto_masks = 0; \
        (f)->flags = 0; \
        (f)->file_flags = 0; \
        (f)->protodetect_dp = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        FLOWLOCK_INIT((f)); \
        (f)->protoctx = NULL; \
        (f)->flow_end_flags = 0; \
        (f)->alproto = 0; \
        (f)->alproto_ts = 0; \
        (f)->alproto_tc = 0; \
        (f)->alproto_orig = 0; \
        (f)->alproto_expect = 0; \
        (f)->de_ctx_version = 0; \
        (f)->thread_id[0] = 0; \
        (f)->thread_id[1] = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        (f)->flowvar = NULL; \
        RESET_COUNTERS((f)); \
    } while (0)
#define FLOW_RECYCLE(f) do { \
        FlowCleanupAppLayer((f)); \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->proto = 0; \
        (f)->livedev = NULL; \
        (f)->vlan_idx = 0; \
        (f)->ffr = 0; \
        (f)->next = NULL; \
        (f)->timeout_at = 0; \
        (f)->timeout_policy = 0; \
        (f)->flow_state = 0; \
        (f)->use_cnt = 0; \
        (f)->tenant_id = 0; \
        (f)->parent_id = 0; \
        (f)->probing_parser_toserver_alproto_masks = 0; \
        (f)->probing_parser_toclient_alproto_masks = 0; \
        (f)->flags = 0; \
        (f)->file_flags = 0; \
        (f)->protodetect_dp = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        (f)->protoctx = NULL; \
        (f)->flow_end_flags = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->alproto = 0; \
        (f)->alproto_ts = 0; \
        (f)->alproto_tc = 0; \
        (f)->alproto_orig = 0; \
        (f)->alproto_expect = 0; \
        (f)->de_ctx_version = 0; \
        (f)->thread_id[0] = 0; \
        (f)->thread_id[1] = 0; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        GenericVarFree((f)->flowvar); \
        (f)->flowvar = NULL; \
        if (MacSetFlowStorageEnabled()) { \
            MacSet *ms = FlowGetStorageById((f), MacSetGetFlowStorageID()); \
            if (ms != NULL) { \
                MacSetReset(ms); \
            } \
        } \
        RESET_COUNTERS((f)); \
    } while(0)
#define RESET_COUNTERS(f) do { \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->todstbytecnt = 0; \
        (f)->tosrcbytecnt = 0; \
    } while (0)



