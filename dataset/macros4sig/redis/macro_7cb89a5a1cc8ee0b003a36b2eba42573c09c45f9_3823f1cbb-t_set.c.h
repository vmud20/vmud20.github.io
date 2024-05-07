#include<signal.h>

#include<malloc.h>
#include<errno.h>

#include<stdint.h>

#include<limits.h>

#include<math.h>

#include<features.h>
#include<netinet/in.h>


#include<unistd.h>
#include<syslog.h>

#include<time.h>

#include<fcntl.h>

#include<stdlib.h>
#include<pthread.h>
#include<stdio.h>


#include<string.h>



#include<inttypes.h>
#include<sys/socket.h>
#include<stdarg.h>

#include<sys/types.h>


#include<stdatomic.h>
#define ACL_DENIED_AUTH 3 
#define ACL_DENIED_CHANNEL 4 
#define ACL_DENIED_CMD 1
#define ACL_DENIED_KEY 2
#define ACL_LOG_CTX_LUA 1
#define ACL_LOG_CTX_MODULE 3
#define ACL_LOG_CTX_MULTI 2
#define ACL_LOG_CTX_TOPLEVEL 0
#define ACL_OK 0
#define ACTIVE_EXPIRE_CYCLE_FAST 1
#define ACTIVE_EXPIRE_CYCLE_SLOW 0
#define AOF_EMPTY 2
#define AOF_FAILED 4
#define AOF_FSYNC_ALWAYS 1
#define AOF_FSYNC_EVERYSEC 2
#define AOF_FSYNC_NO 0
#define AOF_NOT_EXIST 1
#define AOF_OFF 0             
#define AOF_OK 0
#define AOF_ON 1              
#define AOF_OPEN_ERR 3
#define AOF_READ_DIFF_INTERVAL_BYTES (1024*10)
#define AOF_REWRITE_ITEMS_PER_CMD 64
#define AOF_WAIT_REWRITE 2    
#define BLOCKED_LIST 1    
#define BLOCKED_MODULE 3  
#define BLOCKED_NONE 0    
#define BLOCKED_NUM 7     
#define BLOCKED_PAUSE 6   
#define BLOCKED_STREAM 4  
#define BLOCKED_WAIT 2    
#define BLOCKED_ZSET 5    
#define CHILD_COW_DUTY_CYCLE           100
#define CHILD_TYPE_AOF 2
#define CHILD_TYPE_LDB 3
#define CHILD_TYPE_MODULE 4
#define CHILD_TYPE_NONE 0
#define CHILD_TYPE_RDB 1
#define CLIENT_ASKING (1<<9)     
#define CLIENT_BLOCKED (1<<4) 
#define CLIENT_CLOSE_AFTER_COMMAND (1ULL<<40) 
#define CLIENT_CLOSE_AFTER_REPLY (1<<6) 
#define CLIENT_CLOSE_ASAP (1<<10)
#define CLIENT_DENY_BLOCKING (1ULL<<41) 
#define CLIENT_DIRTY_CAS (1<<5) 
#define CLIENT_DIRTY_EXEC (1<<12)  
#define CLIENT_FORCE_AOF (1<<14)   
#define CLIENT_FORCE_REPL (1<<15)  
#define CLIENT_ID_AOF (UINT64_MAX) 
#define CLIENT_IN_TO_TABLE (1ULL<<38) 
#define CLIENT_LUA (1<<8) 
#define CLIENT_LUA_DEBUG (1<<25)  
#define CLIENT_LUA_DEBUG_SYNC (1<<26)  
#define CLIENT_MASTER (1<<1)  
#define CLIENT_MASTER_FORCE_REPLY (1<<13)  
#define CLIENT_MEM_USAGE_BUCKETS (1+CLIENT_MEM_USAGE_BUCKET_MAX_LOG-CLIENT_MEM_USAGE_BUCKET_MIN_LOG)
#define CLIENT_MEM_USAGE_BUCKET_MAX_LOG 33 
#define CLIENT_MEM_USAGE_BUCKET_MIN_LOG 15 
#define CLIENT_MODULE (1<<27) 
#define CLIENT_MONITOR (1<<2) 
#define CLIENT_MULTI (1<<3)   
#define CLIENT_NO_EVICT (1ULL<<43) 
#define CLIENT_PENDING_COMMAND (1<<30) 
#define CLIENT_PENDING_WRITE (1<<21) 
#define CLIENT_PREVENT_AOF_PROP (1<<19)  
#define CLIENT_PREVENT_PROP (CLIENT_PREVENT_AOF_PROP|CLIENT_PREVENT_REPL_PROP)
#define CLIENT_PREVENT_REPL_PROP (1<<20)  
#define CLIENT_PRE_PSYNC (1<<16)   
#define CLIENT_PROTECTED (1<<28) 
#define CLIENT_PROTOCOL_ERROR (1ULL<<39) 
#define CLIENT_PUBSUB (1<<18)      
#define CLIENT_READONLY (1<<17)    
#define CLIENT_REPLY_OFF (1<<22)   
#define CLIENT_REPLY_SKIP (1<<24)  
#define CLIENT_REPLY_SKIP_NEXT (1<<23)  
#define CLIENT_REPL_RDBONLY (1ULL<<42) 
#define CLIENT_SLAVE (1<<0)   
#define CLIENT_TRACKING (1ULL<<31) 
#define CLIENT_TRACKING_BCAST (1ULL<<33) 
#define CLIENT_TRACKING_BROKEN_REDIR (1ULL<<32) 
#define CLIENT_TRACKING_CACHING (1ULL<<36) 
#define CLIENT_TRACKING_NOLOOP (1ULL<<37) 
#define CLIENT_TRACKING_OPTIN (1ULL<<34)  
#define CLIENT_TRACKING_OPTOUT (1ULL<<35) 
#define CLIENT_TYPE_COUNT 4  
#define CLIENT_TYPE_MASTER 3 
#define CLIENT_TYPE_NORMAL 0 
#define CLIENT_TYPE_OBUF_COUNT 3 
#define CLIENT_TYPE_PUBSUB 2 
#define CLIENT_TYPE_SLAVE 1  
#define CLIENT_UNBLOCKED (1<<7) 
#define CLIENT_UNIX_SOCKET (1<<11) 
#define CMD_ADMIN (1ULL<<4)            
#define CMD_ASKING (1ULL<<13)          
#define CMD_CALL_FULL (CMD_CALL_SLOWLOG | CMD_CALL_STATS | CMD_CALL_PROPAGATE)
#define CMD_CALL_NONE 0
#define CMD_CALL_NOWRAP (1<<4)  
#define CMD_CALL_PROPAGATE (CMD_CALL_PROPAGATE_AOF|CMD_CALL_PROPAGATE_REPL)
#define CMD_CALL_PROPAGATE_AOF (1<<2)
#define CMD_CALL_PROPAGATE_REPL (1<<3)
#define CMD_CALL_SLOWLOG (1<<0)
#define CMD_CALL_STATS (1<<1)
#define CMD_CATEGORY_ADMIN (1ULL<<32)
#define CMD_CATEGORY_BITMAP (1ULL<<27)
#define CMD_CATEGORY_BLOCKING (1ULL<<35)
#define CMD_CATEGORY_CONNECTION (1ULL<<37)
#define CMD_CATEGORY_DANGEROUS (1ULL<<36)
#define CMD_CATEGORY_FAST (1ULL<<33)
#define CMD_CATEGORY_GEO (1ULL<<29)
#define CMD_CATEGORY_HASH (1ULL<<25)
#define CMD_CATEGORY_HYPERLOGLOG (1ULL<<28)
#define CMD_CATEGORY_KEYSPACE (1ULL<<19)
#define CMD_CATEGORY_LIST (1ULL<<24)
#define CMD_CATEGORY_PUBSUB (1ULL<<31)
#define CMD_CATEGORY_READ (1ULL<<20)
#define CMD_CATEGORY_SCRIPTING (1ULL<<39)
#define CMD_CATEGORY_SET (1ULL<<22)
#define CMD_CATEGORY_SLOW (1ULL<<34)
#define CMD_CATEGORY_SORTEDSET (1ULL<<23)
#define CMD_CATEGORY_STREAM (1ULL<<30)
#define CMD_CATEGORY_STRING (1ULL<<26)
#define CMD_CATEGORY_TRANSACTION (1ULL<<38)
#define CMD_CATEGORY_WRITE (1ULL<<21)
#define CMD_DENYOOM (1ULL<<2)          
#define CMD_FAST (1ULL<<14)            
#define CMD_KEY_INCOMPLETE (1ULL<<2)   
#define CMD_KEY_READ (1ULL<<1)         
#define CMD_KEY_WRITE (1ULL<<0)        
#define CMD_LOADING (1ULL<<9)          
#define CMD_MAY_REPLICATE (1ULL<<16)   
#define CMD_MODULE (1ULL<<3)           
#define CMD_MODULE_GETKEYS (1ULL<<17)  
#define CMD_MODULE_NO_CLUSTER (1ULL<<18) 
#define CMD_NOSCRIPT (1ULL<<6)         
#define CMD_NO_AUTH (1ULL<<15)         
#define CMD_PUBSUB (1ULL<<5)           
#define CMD_RANDOM (1ULL<<7)           
#define CMD_READONLY (1ULL<<1)         
#define CMD_SKIP_MONITOR (1ULL<<11)    
#define CMD_SKIP_SLOWLOG (1ULL<<12)    
#define CMD_SORT_FOR_SCRIPT (1ULL<<8)  
#define CMD_STALE (1ULL<<10)           
#define CMD_WRITE (1ULL<<0)            
#define CONFIG_AUTHPASS_MAX_LEN 512
#define CONFIG_BGSAVE_RETRY_DELAY 5 
#define CONFIG_BINDADDR_MAX 16
#define CONFIG_DEFAULT_BINDADDR { "*", "-::*" }
#define CONFIG_DEFAULT_BINDADDR_COUNT 2
#define CONFIG_DEFAULT_CLUSTER_CONFIG_FILE "nodes.conf"
#define CONFIG_DEFAULT_HZ        10             
#define CONFIG_DEFAULT_LOGFILE ""
#define CONFIG_DEFAULT_PID_FILE "/var/run/redis.pid"
#define CONFIG_DEFAULT_PROC_TITLE_TEMPLATE "{title} {listen-addr} {server-mode}"
#define CONFIG_DEFAULT_UNIX_SOCKET_PERM 0
#define CONFIG_FDSET_INCR (CONFIG_MIN_RESERVED_FDS+96)
#define CONFIG_MAX_HZ            500
#define CONFIG_MAX_LINE    1024
#define CONFIG_MIN_HZ            1
#define CONFIG_MIN_RESERVED_FDS 32
#define CONFIG_OOM_BGCHILD 2
#define CONFIG_OOM_COUNT 3
#define CONFIG_OOM_MASTER 0
#define CONFIG_OOM_REPLICA 1
#define CONFIG_REPL_BACKLOG_MIN_SIZE (1024*16)          
#define CONFIG_REPL_SYNCIO_TIMEOUT 5
#define CONFIG_RUN_ID_SIZE 40
#define CRON_DBS_PER_CALL 16
#define C_ERR                   -1
#define C_OK                    0
#define DISK_ERROR_TYPE_AOF 1       
#define DISK_ERROR_TYPE_NONE 0      
#define DISK_ERROR_TYPE_RDB 2       
#define EMPTYDB_ASYNC (1<<0)    
#define EMPTYDB_NO_FLAGS 0      
#define EVICT_FAIL 2
#define EVICT_OK 0
#define EVICT_RUNNING 1
#define GETKEYS_RESULT_INIT { {0}, NULL, 0, MAX_KEYS_BUFFER }
#define HASHTABLE_MAX_LOAD_FACTOR 1.618   
#define HASHTABLE_MIN_FILL        10      
#define HASH_SET_COPY 0
#define HASH_SET_TAKE_FIELD (1<<0)
#define HASH_SET_TAKE_VALUE (1<<1)
#define IO_THREADS_OP_IDLE 0
#define IO_THREADS_OP_READ 1
#define IO_THREADS_OP_WRITE 2
#define LFU_INIT_VAL 5
#define LIMIT_PENDING_QUERYBUF (4*1024*1024) 
#define LIST_HEAD 0
#define LIST_TAIL 1
#define LL_DEBUG 0
#define LL_NOTICE 2
#define LL_RAW (1<<10) 
#define LL_VERBOSE 1
#define LL_WARNING 3
#define LOG_MAX_LEN    1024 
#define LONG_STR_SIZE      21          
#define LOOKUP_NONE 0
#define LOOKUP_NONOTIFY (1<<1)
#define LOOKUP_NOTOUCH (1<<0)
#define LRU_BITS 24
#define LRU_CLOCK_MAX ((1<<LRU_BITS)-1) 
#define LRU_CLOCK_RESOLUTION 1000 
#define MAXMEMORY_ALLKEYS_LFU ((5<<8)|MAXMEMORY_FLAG_LFU|MAXMEMORY_FLAG_ALLKEYS)
#define MAXMEMORY_ALLKEYS_LRU ((4<<8)|MAXMEMORY_FLAG_LRU|MAXMEMORY_FLAG_ALLKEYS)
#define MAXMEMORY_ALLKEYS_RANDOM ((6<<8)|MAXMEMORY_FLAG_ALLKEYS)
#define MAXMEMORY_FLAG_ALLKEYS (1<<2)
#define MAXMEMORY_FLAG_LFU (1<<1)
#define MAXMEMORY_FLAG_LRU (1<<0)
#define MAXMEMORY_FLAG_NO_SHARED_INTEGERS \
    (MAXMEMORY_FLAG_LRU|MAXMEMORY_FLAG_LFU)
#define MAXMEMORY_NO_EVICTION (7<<8)
#define MAXMEMORY_VOLATILE_LFU ((1<<8)|MAXMEMORY_FLAG_LFU)
#define MAXMEMORY_VOLATILE_LRU ((0<<8)|MAXMEMORY_FLAG_LRU)
#define MAXMEMORY_VOLATILE_RANDOM (3<<8)
#define MAXMEMORY_VOLATILE_TTL (2<<8)
#define MAX_CLIENTS_PER_CLOCK_TICK 200          
#define MAX_KEYS_BUFFER 256
#define NET_ADDR_STR_LEN (NET_IP_STR_LEN+32) 
#define NET_HOST_PORT_STR_LEN (NET_HOST_STR_LEN+32) 
#define NET_HOST_STR_LEN 256 
#define NET_IP_STR_LEN 46 
#define NET_MAX_WRITES_PER_EVENT (1024*64)
#define NOTIFY_ALL (NOTIFY_GENERIC | NOTIFY_STRING | NOTIFY_LIST | NOTIFY_SET | NOTIFY_HASH | NOTIFY_ZSET | NOTIFY_EXPIRED | NOTIFY_EVICTED | NOTIFY_STREAM | NOTIFY_MODULE) 
#define NOTIFY_EVICTED (1<<9)     
#define NOTIFY_EXPIRED (1<<8)     
#define NOTIFY_GENERIC (1<<2)     
#define NOTIFY_HASH (1<<6)        
#define NOTIFY_KEYEVENT (1<<1)    
#define NOTIFY_KEYSPACE (1<<0)    
#define NOTIFY_KEY_MISS (1<<11)   
#define NOTIFY_LIST (1<<4)        
#define NOTIFY_LOADED (1<<12)     
#define NOTIFY_MODULE (1<<13)     
#define NOTIFY_SET (1<<5)         
#define NOTIFY_STREAM (1<<10)     
#define NOTIFY_STRING (1<<3)      
#define NOTIFY_ZSET (1<<7)        
#define OBJ_ENCODING_EMBSTR 8  
#define OBJ_ENCODING_HT 2      
#define OBJ_ENCODING_INT 1     
#define OBJ_ENCODING_INTSET 6  
#define OBJ_ENCODING_LINKEDLIST 4 
#define OBJ_ENCODING_LISTPACK 11 
#define OBJ_ENCODING_QUICKLIST 9 
#define OBJ_ENCODING_RAW 0     
#define OBJ_ENCODING_SKIPLIST 7  
#define OBJ_ENCODING_STREAM 10 
#define OBJ_ENCODING_ZIPLIST 5 
#define OBJ_ENCODING_ZIPMAP 3  
#define OBJ_FIRST_SPECIAL_REFCOUNT OBJ_STATIC_REFCOUNT
#define OBJ_HASH 4      
#define OBJ_HASH_KEY 1
#define OBJ_HASH_VALUE 2
#define OBJ_LIST 1      
#define OBJ_MODULE 5    
#define OBJ_SET 2       
#define OBJ_SHARED_BULKHDR_LEN 32
#define OBJ_SHARED_INTEGERS 10000
#define OBJ_SHARED_REFCOUNT INT_MAX     
#define OBJ_STATIC_REFCOUNT (INT_MAX-1) 
#define OBJ_STREAM 6    
#define OBJ_STRING 0    
#define OBJ_ZSET 3      
#define OOM_SCORE_ADJ_ABSOLUTE 2
#define OOM_SCORE_ADJ_NO 0
#define OOM_SCORE_RELATIVE 1
#define PROPAGATE_AOF 1
#define PROPAGATE_NONE 0
#define PROPAGATE_REPL 2
#define PROTO_INLINE_MAX_SIZE   (1024*64) 
#define PROTO_IOBUF_LEN         (1024*16)  
#define PROTO_MBULK_BIG_ARG     (1024*32)
#define PROTO_REPLY_CHUNK_BYTES (16*1024) 
#define PROTO_REQ_INLINE 1
#define PROTO_REQ_MULTIBULK 2
#define PROTO_RESIZE_THRESHOLD  (1024*32) 
#define PROTO_SHARED_SELECT_CMDS 10
#define RDB_CHILD_TYPE_DISK 1     
#define RDB_CHILD_TYPE_NONE 0
#define RDB_CHILD_TYPE_SOCKET 2   
#define RDB_EOF_MARK_SIZE 40
#define RDB_SAVE_INFO_INIT {-1,0,"0000000000000000000000000000000000000000",-1}
#define REDISMODULE_AUX_AFTER_RDB (1<<1)
#define REDISMODULE_AUX_BEFORE_RDB (1<<0)
#define REDISMODULE_CORE 1
#define REDISMODULE_TYPE_ENCVER(id) (id & REDISMODULE_TYPE_ENCVER_MASK)
#define REDISMODULE_TYPE_ENCVER_BITS 10
#define REDISMODULE_TYPE_ENCVER_MASK ((1<<REDISMODULE_TYPE_ENCVER_BITS)-1)
#define REDISMODULE_TYPE_SIGN(id) ((id & ~((uint64_t)REDISMODULE_TYPE_ENCVER_MASK)) >>REDISMODULE_TYPE_ENCVER_BITS)
#define REDIS_AUTOSYNC_BYTES (1024*1024*4) 
#define REPL_DISKLESS_LOAD_DISABLED 0
#define REPL_DISKLESS_LOAD_SWAPDB 2
#define REPL_DISKLESS_LOAD_WHEN_DB_EMPTY 1
#define RESTART_SERVER_CONFIG_REWRITE (1<<1) 
#define RESTART_SERVER_GRACEFULLY (1<<0)     
#define RESTART_SERVER_NONE 0
#define SANITIZE_DUMP_CLIENTS 2
#define SANITIZE_DUMP_NO 0
#define SANITIZE_DUMP_YES 1
#define SERVER_CHILD_NOERROR_RETVAL    255
#define SET_OP_DIFF 1
#define SET_OP_INTER 2
#define SET_OP_UNION 0
#define SHUTDOWN_NOFLAGS 0      
#define SHUTDOWN_NOSAVE 2       
#define SHUTDOWN_SAVE 1         
#define SLAVE_CAPA_EOF (1<<0)    
#define SLAVE_CAPA_NONE 0
#define SLAVE_CAPA_PSYNC2 (1<<1) 
#define SLAVE_STATE_ONLINE 9 
#define SLAVE_STATE_SEND_BULK 8 
#define SLAVE_STATE_WAIT_BGSAVE_END 7 
#define SLAVE_STATE_WAIT_BGSAVE_START 6 
#define SORT_OP_GET 0
#define STATIC_KEY_SPECS_NUM 4
#define STATS_METRIC_COMMAND 0      
#define STATS_METRIC_COUNT 3
#define STATS_METRIC_NET_INPUT 1    
#define STATS_METRIC_NET_OUTPUT 2   
#define STATS_METRIC_SAMPLES 16     
#define SUPERVISED_AUTODETECT 1
#define SUPERVISED_NONE 0
#define SUPERVISED_SYSTEMD 2
#define SUPERVISED_UPSTART 3
#define TLS_CLIENT_AUTH_NO 0
#define TLS_CLIENT_AUTH_OPTIONAL 2
#define TLS_CLIENT_AUTH_YES 1
#define UNIT_MILLISECONDS 1
#define UNIT_SECONDS 0
#define UNUSED(V) ((void) V)
#define USER_COMMAND_BITS_COUNT 1024    
#define USER_FLAG_ALLCHANNELS (1<<5)    
#define USER_FLAG_ALLCOMMANDS (1<<3)    
#define USER_FLAG_ALLKEYS (1<<2)        
#define USER_FLAG_DISABLED (1<<1)       
#define USER_FLAG_ENABLED (1<<0)        
#define USER_FLAG_NOPASS      (1<<4)    
#define USER_FLAG_SANITIZE_PAYLOAD (1<<6)       
#define USER_FLAG_SANITIZE_PAYLOAD_SKIP (1<<7)  
#define ZADD_IN_GT (1<<3)      
#define ZADD_IN_INCR (1<<0)    
#define ZADD_IN_LT (1<<4)      
#define ZADD_IN_NONE 0
#define ZADD_IN_NX (1<<1)      
#define ZADD_IN_XX (1<<2)      
#define ZADD_OUT_ADDED (1<<2)   
#define ZADD_OUT_NAN (1<<1)     
#define ZADD_OUT_NOP (1<<0)     
#define ZADD_OUT_UPDATED (1<<3) 
#define ZSET_MAX 1
#define ZSET_MIN 0
#define ZSKIPLIST_MAXLEVEL 32 
#define ZSKIPLIST_P 0.25      

#define initStaticStringObject(_var,_ptr) do { \
    _var.refcount = OBJ_STATIC_REFCOUNT; \
    _var.type = OBJ_STRING; \
    _var.encoding = OBJ_ENCODING_RAW; \
    _var.ptr = _ptr; \
} while(0)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define moduleInitDigestContext(mdvar) do { \
    memset(mdvar.o,0,sizeof(mdvar.o)); \
    memset(mdvar.x,0,sizeof(mdvar.x)); \
} while(0)
#define moduleInitIOContext(iovar,mtype,rioptr,keyptr,db) do { \
    iovar.rio = rioptr; \
    iovar.type = mtype; \
    iovar.bytes = 0; \
    iovar.error = 0; \
    iovar.ver = 0; \
    iovar.key = keyptr; \
    iovar.dbid = db; \
    iovar.ctx = NULL; \
} while(0)
#define redisDebug(fmt, ...) \
    printf("DEBUG %s:%d > " fmt "\n", "__FILE__", "__LINE__", __VA_ARGS__)
#define redisDebugMark() \
    printf("-- MARK %s:%d --\n", "__FILE__", "__LINE__")
#define run_with_period(_ms_) if ((_ms_ <= 1000/server.hz) || !(server.cronloops%((_ms_)/(1000/server.hz))))
#define sdsEncodedObject(objptr) (objptr->encoding == OBJ_ENCODING_RAW || objptr->encoding == OBJ_ENCODING_EMBSTR)
#define serverAssert(_e) ((_e)?(void)0 : (_serverAssert(#_e,"__FILE__","__LINE__"),redis_unreachable()))
#define serverAssertWithInfo(_c,_o,_e) ((_e)?(void)0 : (_serverAssertWithInfo(_c,_o,#_e,"__FILE__","__LINE__"),redis_unreachable()))
#define serverLog(level, ...) do {\
        if (((level)&0xff) < server.verbosity) break;\
        _serverLog(level, __VA_ARGS__);\
    } while(0)
#define serverPanic(...) _serverPanic("__FILE__","__LINE__",__VA_ARGS__),redis_unreachable()
#define RDBFLAGS_ALLOW_DUP (1<<2)       
#define RDBFLAGS_AOF_PREAMBLE (1<<0)    
#define RDBFLAGS_FEED_REPL (1<<3)       
#define RDBFLAGS_NONE 0                 
#define RDBFLAGS_REPLICATION (1<<1)     
#define RDB_14BITLEN 1
#define RDB_32BITLEN 0x80
#define RDB_64BITLEN 0x81
#define RDB_6BITLEN 0
#define RDB_ENCVAL 3
#define RDB_ENC_INT16 1       
#define RDB_ENC_INT32 2       
#define RDB_ENC_INT8 0        
#define RDB_ENC_LZF 3         
#define RDB_LENERR UINT64_MAX
#define RDB_LOAD_ENC    (1<<0)
#define RDB_LOAD_ERR_EMPTY_KEY  1   
#define RDB_LOAD_ERR_OTHER      2   
#define RDB_LOAD_NONE   0
#define RDB_LOAD_PLAIN  (1<<1)
#define RDB_LOAD_SDS    (1<<2)
#define RDB_MODULE_OPCODE_DOUBLE 4  
#define RDB_MODULE_OPCODE_EOF   0   
#define RDB_MODULE_OPCODE_FLOAT 3   
#define RDB_MODULE_OPCODE_SINT  1   
#define RDB_MODULE_OPCODE_STRING 5  
#define RDB_MODULE_OPCODE_UINT  2   
#define RDB_OPCODE_AUX        250   
#define RDB_OPCODE_EOF        255   
#define RDB_OPCODE_EXPIRETIME 253       
#define RDB_OPCODE_EXPIRETIME_MS 252    
#define RDB_OPCODE_FREQ       249   
#define RDB_OPCODE_IDLE       248   
#define RDB_OPCODE_MODULE_AUX 247   
#define RDB_OPCODE_RESIZEDB   251   
#define RDB_OPCODE_SELECTDB   254   
#define RDB_TYPE_HASH   4
#define RDB_TYPE_HASH_LISTPACK 16
#define RDB_TYPE_HASH_ZIPLIST  13
#define RDB_TYPE_HASH_ZIPMAP    9
#define RDB_TYPE_LIST   1
#define RDB_TYPE_LIST_QUICKLIST 14
#define RDB_TYPE_LIST_ZIPLIST  10
#define RDB_TYPE_MODULE 6
#define RDB_TYPE_MODULE_2 7 
#define RDB_TYPE_SET    2
#define RDB_TYPE_SET_INTSET    11
#define RDB_TYPE_STREAM_LISTPACKS 15
#define RDB_TYPE_STRING 0
#define RDB_TYPE_ZSET   3
#define RDB_TYPE_ZSET_2 5 
#define RDB_TYPE_ZSET_LISTPACK 17
#define RDB_TYPE_ZSET_ZIPLIST  12
#define RDB_VERSION 10

#define rdbIsObjectType(t) ((t >= 0 && t <= 7) || (t >= 9 && t <= 17))
#define RIO_FLAG_READ_ERROR (1<<0)
#define RIO_FLAG_WRITE_ERROR (1<<1)

#define CONN_FLAG_CLOSE_SCHEDULED   (1<<0)      
#define CONN_FLAG_WRITE_BARRIER     (1<<1)      
#define CONN_INFO_LEN   32
#define CONN_TYPE_SOCKET            1
#define CONN_TYPE_TLS               2

#define SDS_HDR(T,s) ((struct sdshdr##T *)((s)-(sizeof(struct sdshdr##T))))
#define SDS_HDR_VAR(T,s) struct sdshdr##T *sh = (void*)((s)-(sizeof(struct sdshdr##T)));
#define SDS_MAX_PREALLOC (1024*1024)
#define SDS_TYPE_16 2
#define SDS_TYPE_32 3
#define SDS_TYPE_5  0
#define SDS_TYPE_5_LEN(f) ((f)>>SDS_TYPE_BITS)
#define SDS_TYPE_64 4
#define SDS_TYPE_8  1
#define SDS_TYPE_BITS 3
#define SDS_TYPE_MASK 7

#define SCC_DEFAULT       0
#define SCC_NO_DIRTIFY    (1<<1) 
#define SCC_NO_NOTIFY     (1<<0) 
#define SLC_DEFAULT      0
#define SLC_NO_REFRESH   (1<<0) 

#define LP_AFTER 1
#define LP_BEFORE 0
#define LP_INTBUF_SIZE 21 
#define LP_REPLACE 2


#define RAX_ITER_EOF (1<<1)    
#define RAX_ITER_JUST_SEEKED (1<<0) 
#define RAX_ITER_SAFE (1<<2)   
#define RAX_ITER_STATIC_LEN 128
#define RAX_NODE_MAX_SIZE ((1<<29)-1)
#define RAX_STACK_STATIC_ITEMS 32


#define htonu64(v) (v)
#define intrev16ifbe(v) (v)
#define intrev32ifbe(v) (v)
#define intrev64ifbe(v) (v)
#define memrev16ifbe(p) ((void)(0))
#define memrev32ifbe(p) ((void)(0))
#define memrev64ifbe(p) ((void)(0))
#define ntohu64(v) (v)
#define BIG_ENDIAN __BIG_ENDIAN
#define BYTE_ORDER    LITTLE_ENDIAN
#define ESOCKTNOSUPPORT 0
#define GNUC_VERSION ("__GNUC__" * 10000 + "__GNUC_MINOR__" * 100 + "__GNUC_PATCHLEVEL__")
#define HAVE_ACCEPT4 1

#define HAVE_BACKTRACE 1
#define HAVE_EPOLL 1
#define HAVE_EVPORT 1
#define HAVE_KQUEUE 1
#define HAVE_MSG_NOSIGNAL 1
#define HAVE_PROC_MAPS 1
#define HAVE_PROC_OOM_SCORE_ADJ 1
#define HAVE_PROC_SMAPS 1
#define HAVE_PROC_SOMAXCONN 1
#define HAVE_PROC_STAT 1
#define HAVE_PSINFO 1
#define HAVE_SYNC_FILE_RANGE 1
#define HAVE_TASKINFO 1

#define LITTLE_ENDIAN __LITTLE_ENDIAN







#define likely(x) __builtin_expect(!!(x), 1)
#define rdb_fsync_range(fd,off,size) sync_file_range(fd,off,size,SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE)
#define redis_fstat fstat64
#define redis_fsync fdatasync
#define redis_set_thread_title(name) pthread_setname_np(pthread_self(), name)
#define redis_stat stat64
#define redis_unreachable __builtin_unreachable
#define unlikely(x) __builtin_expect(!!(x), 0)



#define REDISMODULE_APIVER_1 1
#define REDISMODULE_ATTR REDISMODULE_ATTR_COMMON
#        define REDISMODULE_ATTR_COMMON __attribute__((__common__))
#        define REDISMODULE_ATTR_PRINTF(idx,cnt) __attribute__((format(printf,idx,cnt)))
#        define REDISMODULE_ATTR_UNUSED __attribute__((unused))
#define REDISMODULE_CLIENTINFO_FLAG_BLOCKED (1<<2)
#define REDISMODULE_CLIENTINFO_FLAG_MULTI (1<<5)
#define REDISMODULE_CLIENTINFO_FLAG_PUBSUB (1<<1)
#define REDISMODULE_CLIENTINFO_FLAG_SSL (1<<0)
#define REDISMODULE_CLIENTINFO_FLAG_TRACKING (1<<3)
#define REDISMODULE_CLIENTINFO_FLAG_UNIXSOCKET (1<<4)
#define REDISMODULE_CLIENTINFO_VERSION 1
#define REDISMODULE_CLUSTER_FLAG_NONE 0
#define REDISMODULE_CLUSTER_FLAG_NO_FAILOVER (1<<1)
#define REDISMODULE_CLUSTER_FLAG_NO_REDIRECTION (1<<2)
#define REDISMODULE_CMDFILTER_NOSELF    (1<<0)
#define REDISMODULE_CRON_LOOP_VERSION 1
#define REDISMODULE_CTX_FLAGS_ACTIVE_CHILD (1<<18)
#define REDISMODULE_CTX_FLAGS_AOF (1<<6)
#define REDISMODULE_CTX_FLAGS_CLUSTER (1<<5)
#define REDISMODULE_CTX_FLAGS_DENY_BLOCKING (1<<21)
#define REDISMODULE_CTX_FLAGS_EVICT (1<<9)
#define REDISMODULE_CTX_FLAGS_IS_CHILD (1<<20)
#define REDISMODULE_CTX_FLAGS_LOADING (1<<13)
#define REDISMODULE_CTX_FLAGS_LUA (1<<0)
#define REDISMODULE_CTX_FLAGS_MASTER (1<<2)
#define REDISMODULE_CTX_FLAGS_MAXMEMORY (1<<8)
#define REDISMODULE_CTX_FLAGS_MULTI (1<<1)
#define REDISMODULE_CTX_FLAGS_MULTI_DIRTY (1<<19)
#define REDISMODULE_CTX_FLAGS_OOM (1<<10)
#define REDISMODULE_CTX_FLAGS_OOM_WARNING (1<<11)
#define REDISMODULE_CTX_FLAGS_RDB (1<<7)
#define REDISMODULE_CTX_FLAGS_READONLY (1<<4)
#define REDISMODULE_CTX_FLAGS_REPLICATED (1<<12)
#define REDISMODULE_CTX_FLAGS_REPLICA_IS_CONNECTING (1<<15)
#define REDISMODULE_CTX_FLAGS_REPLICA_IS_ONLINE (1<<17)
#define REDISMODULE_CTX_FLAGS_REPLICA_IS_STALE (1<<14)
#define REDISMODULE_CTX_FLAGS_REPLICA_IS_TRANSFERRING (1<<16)
#define REDISMODULE_CTX_FLAGS_RESP3 (1<<22)
#define REDISMODULE_CTX_FLAGS_SLAVE (1<<3)
#define REDISMODULE_ERR 1
#define REDISMODULE_ERRORMSG_WRONGTYPE "WRONGTYPE Operation against a key holding the wrong kind of value"
#define REDISMODULE_EVENT_CLIENT_CHANGE 4
#define REDISMODULE_EVENT_CRON_LOOP 8
#define REDISMODULE_EVENT_FLUSHDB 2
#define REDISMODULE_EVENT_FORK_CHILD 13
#define REDISMODULE_EVENT_LOADING 3
#define REDISMODULE_EVENT_LOADING_PROGRESS 10
#define REDISMODULE_EVENT_MASTER_LINK_CHANGE 7
#define REDISMODULE_EVENT_MODULE_CHANGE 9
#define REDISMODULE_EVENT_PERSISTENCE 1
#define REDISMODULE_EVENT_REPLICATION_ROLE_CHANGED 0
#define REDISMODULE_EVENT_REPLICA_CHANGE 6
#define REDISMODULE_EVENT_REPLROLECHANGED_NOW_MASTER 0
#define REDISMODULE_EVENT_REPLROLECHANGED_NOW_REPLICA 1
#define REDISMODULE_EVENT_REPL_BACKUP 12
#define REDISMODULE_EVENT_SHUTDOWN 5
#define REDISMODULE_EVENT_SWAPDB 11
#define REDISMODULE_EXPERIMENTAL_API_VERSION 3
#define REDISMODULE_FLUSHINFO_VERSION 1
#define REDISMODULE_GET_API(name) \
    RedisModule_GetApi("RedisModule_" #name, ((void **)&RedisModule_ ## name))

#define REDISMODULE_HASH_CFIELDS    (1<<2)
#define REDISMODULE_HASH_COUNT_ALL  (1<<4)
#define REDISMODULE_HASH_DELETE ((RedisModuleString*)(long)1)
#define REDISMODULE_HASH_EXISTS     (1<<3)
#define REDISMODULE_HASH_NONE       0
#define REDISMODULE_HASH_NX         (1<<0)
#define REDISMODULE_HASH_XX         (1<<1)
#define REDISMODULE_KEYTYPE_EMPTY 0
#define REDISMODULE_KEYTYPE_HASH 3
#define REDISMODULE_KEYTYPE_LIST 2
#define REDISMODULE_KEYTYPE_MODULE 6
#define REDISMODULE_KEYTYPE_SET 4
#define REDISMODULE_KEYTYPE_STREAM 7
#define REDISMODULE_KEYTYPE_STRING 1
#define REDISMODULE_KEYTYPE_ZSET 5
#define REDISMODULE_LIST_HEAD 0
#define REDISMODULE_LIST_TAIL 1
#define REDISMODULE_LOADING_PROGRESS_VERSION 1
#define REDISMODULE_LOGLEVEL_DEBUG "debug"
#define REDISMODULE_LOGLEVEL_NOTICE "notice"
#define REDISMODULE_LOGLEVEL_VERBOSE "verbose"
#define REDISMODULE_LOGLEVEL_WARNING "warning"
#define REDISMODULE_MODULE_CHANGE_VERSION 1
#define REDISMODULE_NEGATIVE_INFINITE (-1.0/0.0)
#define REDISMODULE_NODE_FAIL       (1<<4)
#define REDISMODULE_NODE_ID_LEN 40
#define REDISMODULE_NODE_MASTER     (1<<1)
#define REDISMODULE_NODE_MYSELF     (1<<0)
#define REDISMODULE_NODE_NOFAILOVER (1<<5)
#define REDISMODULE_NODE_PFAIL      (1<<3)
#define REDISMODULE_NODE_SLAVE      (1<<2)
#define REDISMODULE_NOTIFY_ALL (REDISMODULE_NOTIFY_GENERIC | REDISMODULE_NOTIFY_STRING | REDISMODULE_NOTIFY_LIST | REDISMODULE_NOTIFY_SET | REDISMODULE_NOTIFY_HASH | REDISMODULE_NOTIFY_ZSET | REDISMODULE_NOTIFY_EXPIRED | REDISMODULE_NOTIFY_EVICTED | REDISMODULE_NOTIFY_STREAM | REDISMODULE_NOTIFY_MODULE)      
#define REDISMODULE_NOTIFY_EVICTED (1<<9)     
#define REDISMODULE_NOTIFY_EXPIRED (1<<8)     
#define REDISMODULE_NOTIFY_GENERIC (1<<2)     
#define REDISMODULE_NOTIFY_HASH (1<<6)        
#define REDISMODULE_NOTIFY_KEYEVENT (1<<1)    
#define REDISMODULE_NOTIFY_KEYSPACE (1<<0)    
#define REDISMODULE_NOTIFY_KEY_MISS (1<<11)   
#define REDISMODULE_NOTIFY_LIST (1<<4)        
#define REDISMODULE_NOTIFY_LOADED (1<<12)     
#define REDISMODULE_NOTIFY_MODULE (1<<13)     
#define REDISMODULE_NOTIFY_SET (1<<5)         
#define REDISMODULE_NOTIFY_STREAM (1<<10)     
#define REDISMODULE_NOTIFY_STRING (1<<3)      
#define REDISMODULE_NOTIFY_ZSET (1<<7)        
#define REDISMODULE_NOT_USED(V) ((void) V)
#define REDISMODULE_NO_EXPIRE -1
#define REDISMODULE_OK 0
#define REDISMODULE_OPEN_KEY_NOTOUCH (1<<16)
#define REDISMODULE_OPTIONS_HANDLE_IO_ERRORS    (1<<0)
#define REDISMODULE_OPTION_NO_IMPLICIT_SIGNAL_MODIFIED (1<<1)
#define REDISMODULE_POSITIVE_INFINITE (1.0/0.0)
#define REDISMODULE_POSTPONED_ARRAY_LEN -1  
#define REDISMODULE_POSTPONED_LEN -1
#define REDISMODULE_READ (1<<0)
#define REDISMODULE_REPLICATIONINFO_VERSION 1
#define REDISMODULE_REPLY_ARRAY 3
#define REDISMODULE_REPLY_ATTRIBUTE 11
#define REDISMODULE_REPLY_BIG_NUMBER 9
#define REDISMODULE_REPLY_BOOL 7
#define REDISMODULE_REPLY_DOUBLE 8
#define REDISMODULE_REPLY_ERROR 1
#define REDISMODULE_REPLY_INTEGER 2
#define REDISMODULE_REPLY_MAP 5
#define REDISMODULE_REPLY_NULL 4
#define REDISMODULE_REPLY_SET 6
#define REDISMODULE_REPLY_STRING 0
#define REDISMODULE_REPLY_UNKNOWN -1
#define REDISMODULE_REPLY_VERBATIM_STRING 10
#define REDISMODULE_STREAM_ADD_AUTOID (1<<0)
#define REDISMODULE_STREAM_ITERATOR_EXCLUSIVE (1<<0)
#define REDISMODULE_STREAM_ITERATOR_REVERSE (1<<1)
#define REDISMODULE_STREAM_TRIM_APPROX (1<<0)
#define REDISMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED 0
#define REDISMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED 1
#define REDISMODULE_SUBEVENT_FLUSHDB_END 1
#define REDISMODULE_SUBEVENT_FLUSHDB_START 0
#define REDISMODULE_SUBEVENT_FORK_CHILD_BORN 0
#define REDISMODULE_SUBEVENT_FORK_CHILD_DIED 1
#define REDISMODULE_SUBEVENT_LOADING_AOF_START 1
#define REDISMODULE_SUBEVENT_LOADING_ENDED 3
#define REDISMODULE_SUBEVENT_LOADING_FAILED 4
#define REDISMODULE_SUBEVENT_LOADING_PROGRESS_AOF 1
#define REDISMODULE_SUBEVENT_LOADING_PROGRESS_RDB 0
#define REDISMODULE_SUBEVENT_LOADING_RDB_START 0
#define REDISMODULE_SUBEVENT_LOADING_REPL_START 2
#define REDISMODULE_SUBEVENT_MASTER_LINK_DOWN 1
#define REDISMODULE_SUBEVENT_MASTER_LINK_UP 0
#define REDISMODULE_SUBEVENT_MODULE_LOADED 0
#define REDISMODULE_SUBEVENT_MODULE_UNLOADED 1
#define REDISMODULE_SUBEVENT_PERSISTENCE_AOF_START 1
#define REDISMODULE_SUBEVENT_PERSISTENCE_ENDED 3
#define REDISMODULE_SUBEVENT_PERSISTENCE_FAILED 4
#define REDISMODULE_SUBEVENT_PERSISTENCE_RDB_START 0
#define REDISMODULE_SUBEVENT_PERSISTENCE_SYNC_RDB_START 2
#define REDISMODULE_SUBEVENT_REPLICA_CHANGE_OFFLINE 1
#define REDISMODULE_SUBEVENT_REPLICA_CHANGE_ONLINE 0
#define REDISMODULE_SUBEVENT_REPL_BACKUP_CREATE 0
#define REDISMODULE_SUBEVENT_REPL_BACKUP_DISCARD 2
#define REDISMODULE_SUBEVENT_REPL_BACKUP_RESTORE 1
#define REDISMODULE_SWAPDBINFO_VERSION 1
#define REDISMODULE_TYPE_METHOD_VERSION 4
#define REDISMODULE_WRITE (1<<1)
#define REDISMODULE_ZADD_ADDED   (1<<2)
#define REDISMODULE_ZADD_GT      (1<<5)
#define REDISMODULE_ZADD_LT      (1<<6)
#define REDISMODULE_ZADD_NOP     (1<<4)
#define REDISMODULE_ZADD_NX      (1<<1)
#define REDISMODULE_ZADD_UPDATED (1<<3)
#define REDISMODULE_ZADD_XX      (1<<0)
#define RMAPI_FUNC_SUPPORTED(func) (func != NULL)
#define RedisModuleClientInfo RedisModuleClientInfoV1
#define RedisModuleCronLoop RedisModuleCronLoopV1
#define RedisModuleFlushInfo RedisModuleFlushInfoV1
#define RedisModuleLoadingProgress RedisModuleLoadingProgressV1
#define RedisModuleModuleChange RedisModuleModuleChangeV1
#define RedisModuleReplicationInfo RedisModuleReplicationInfoV1
#define RedisModuleString robj
#define RedisModuleSwapDbInfo RedisModuleSwapDbInfoV1
#define RedisModule_Assert(_e) ((_e)?(void)0 : (RedisModule__Assert(#_e,"__FILE__","__LINE__"),exit(1)))
#define RedisModule_IsAOFClient(id) ((id) == UINT64_MAX)
#define _REDISMODULE_CTX_FLAGS_NEXT (1<<23)
#define _REDISMODULE_EVENT_NEXT 14 
#define _REDISMODULE_EVENT_REPLROLECHANGED_NEXT 2
#define _REDISMODULE_NOTIFY_NEXT (1<<14)
#define _REDISMODULE_SUBEVENT_CLIENT_CHANGE_NEXT 2
#define _REDISMODULE_SUBEVENT_CRON_LOOP_NEXT 0
#define _REDISMODULE_SUBEVENT_FLUSHDB_NEXT 2
#define _REDISMODULE_SUBEVENT_FORK_CHILD_NEXT 2
#define _REDISMODULE_SUBEVENT_LOADING_NEXT 5
#define _REDISMODULE_SUBEVENT_LOADING_PROGRESS_NEXT 2
#define _REDISMODULE_SUBEVENT_MASTER_NEXT 2
#define _REDISMODULE_SUBEVENT_MODULE_NEXT 2
#define _REDISMODULE_SUBEVENT_PERSISTENCE_NEXT 5
#define _REDISMODULE_SUBEVENT_REPLICA_CHANGE_NEXT 2
#define _REDISMODULE_SUBEVENT_REPL_BACKUP_NEXT 3
#define _REDISMODULE_SUBEVENT_SHUTDOWN_NEXT 0
#define _REDISMODULE_SUBEVENT_SWAPDB_NEXT 0
#define AL_START_HEAD 0
#define AL_START_TAIL 1
#   define QL_BM_BITS 4
#   define QL_COMP_BITS 14
#   define QL_FILL_BITS 14
#define QUICKLIST_HEAD 0
#define QUICKLIST_NOCOMPRESS 0
#define QUICKLIST_NODE_CONTAINER_NONE 1
#define QUICKLIST_NODE_CONTAINER_ZIPLIST 2
#define QUICKLIST_NODE_ENCODING_LZF 2
#define QUICKLIST_NODE_ENCODING_RAW 1
#define QUICKLIST_TAIL -1

#define quicklistNodeIsCompressed(node)                                        \
    ((node)->encoding == QUICKLIST_NODE_ENCODING_LZF)
#define SPARKLINE_FILL 1      
#define SPARKLINE_LOG_SCALE 2 
#define SPARKLINE_NO_FLAGS 0

#define LATENCY_TS_LEN 160 

#define latencyAddSampleIfNeeded(event,var) \
    if (server.latency_monitor_threshold && \
        (var) >= server.latency_monitor_threshold) \
          latencyAddSample((event),(var));
#define latencyEndMonitor(var) if (server.latency_monitor_threshold) { \
    var = mstime() - var; \
}
#define latencyRemoveNestedEvent(event_var,nested_var) \
    event_var += nested_var;
#define latencyStartMonitor(var) if (server.latency_monitor_threshold) { \
    var = mstime(); \
} else { \
    var = 0; \
}
#define MAX_LONG_DOUBLE_CHARS 5*1024

#define REDIS_VERSION "255.255.255"
#define REDIS_VERSION_NUM 0x00ffffff

#define ZIPLIST_HEAD 0
#define ZIPLIST_TAIL 1

#define AF_LOCAL AF_UNIX
#define ANET_ERR -1
#define ANET_ERR_LEN 256

#define ANET_IP_ONLY (1<<0)
#define ANET_NONE 0
#define ANET_OK 0
#define FD_TO_PEER_NAME 0
#define FD_TO_SOCK_NAME 1

#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable_size(p) zmalloc_size(p)

#define listFirst(l) ((l)->head)
#define listGetDupMethod(l) ((l)->dup)
#define listGetFreeMethod(l) ((l)->free)
#define listGetMatchMethod(l) ((l)->match)
#define listLast(l) ((l)->tail)
#define listLength(l) ((l)->len)
#define listNextNode(n) ((n)->next)
#define listNodeValue(n) ((n)->value)
#define listPrevNode(n) ((n)->prev)
#define listSetDupMethod(l,m) ((l)->dup = (m))
#define listSetFreeMethod(l,m) ((l)->free = (m))
#define listSetMatchMethod(l,m) ((l)->match = (m))
#define DICTHT_SIZE(exp) ((exp) == -1 ? 0 : (unsigned long)1<<(exp))
#define DICTHT_SIZE_MASK(exp) ((exp) == -1 ? 0 : (DICTHT_SIZE(exp))-1)
#define DICT_ERR 1
#define DICT_HT_INITIAL_EXP      2
#define DICT_HT_INITIAL_SIZE     (1<<(DICT_HT_INITIAL_EXP))
#define DICT_OK 0

#define dictCompareKeys(d, key1, key2) \
    (((d)->type->keyCompare) ? \
        (d)->type->keyCompare((d), key1, key2) : \
        (key1) == (key2))
#define dictFreeKey(d, entry) \
    if ((d)->type->keyDestructor) \
        (d)->type->keyDestructor((d), (entry)->key)
#define dictFreeVal(d, entry) \
    if ((d)->type->valDestructor) \
        (d)->type->valDestructor((d), (entry)->v.val)
#define dictGetDoubleVal(he) ((he)->v.d)
#define dictGetKey(he) ((he)->key)
#define dictGetSignedIntegerVal(he) ((he)->v.s64)
#define dictGetUnsignedIntegerVal(he) ((he)->v.u64)
#define dictGetVal(he) ((he)->v.val)
#define dictHashKey(d, key) (d)->type->hashFunction(key)
#define dictIsRehashing(d) ((d)->rehashidx != -1)
#define dictMetadata(entry) (&(entry)->metadata)
#define dictMetadataSize(d) ((d)->type->dictEntryMetadataBytes \
                             ? (d)->type->dictEntryMetadataBytes(d) : 0)
#define dictPauseRehashing(d) (d)->pauserehash++
#define dictResumeRehashing(d) (d)->pauserehash--
#define dictSetDoubleVal(entry, _val_) \
    do { (entry)->v.d = _val_; } while(0)
#define dictSetKey(d, entry, _key_) do { \
    if ((d)->type->keyDup) \
        (entry)->key = (d)->type->keyDup((d), _key_); \
    else \
        (entry)->key = (_key_); \
} while(0)
#define dictSetSignedIntegerVal(entry, _val_) \
    do { (entry)->v.s64 = _val_; } while(0)
#define dictSetUnsignedIntegerVal(entry, _val_) \
    do { (entry)->v.u64 = _val_; } while(0)
#define dictSetVal(d, entry, _val_) do { \
    if ((d)->type->valDup) \
        (entry)->v.val = (d)->type->valDup((d), _val_); \
    else \
        (entry)->v.val = (_val_); \
} while(0)
#define dictSize(d) ((d)->ht_used[0]+(d)->ht_used[1])
#define dictSlots(d) (DICTHT_SIZE((d)->ht_size_exp[0])+DICTHT_SIZE((d)->ht_size_exp[1]))
#define randomULong() ((unsigned long) genrand64_int64())

#define AE_ALL_EVENTS (AE_FILE_EVENTS|AE_TIME_EVENTS)
#define AE_BARRIER 4    
#define AE_CALL_AFTER_SLEEP (1<<4)
#define AE_CALL_BEFORE_SLEEP (1<<3)
#define AE_DELETED_EVENT_ID -1
#define AE_DONT_WAIT (1<<2)
#define AE_ERR -1
#define AE_FILE_EVENTS (1<<0)
#define AE_NOMORE -1
#define AE_NONE 0       
#define AE_NOTUSED(V) ((void) V)
#define AE_OK 0
#define AE_READABLE 1   
#define AE_TIME_EVENTS (1<<1)
#define AE_WRITABLE 2   





#define _FILE_OFFSET_BITS 64


#define _POSIX_C_SOURCE 199506L

#define _XOPEN_SOURCE 700
#define ANNOTATE_HAPPENS_AFTER(v)  ((void) v)
#define ANNOTATE_HAPPENS_BEFORE(v) ((void) v)
#define REDIS_ATOMIC_API "c11-builtin"

#define atomicDecr(var,count) __atomic_sub_fetch(&var,(count),__ATOMIC_RELAXED)
#define atomicGet(var,dstvar) do { \
    dstvar = __atomic_load_n(&var,__ATOMIC_RELAXED); \
} while(0)
#define atomicGetIncr(var,oldvalue_var,count) do { \
    oldvalue_var = __atomic_fetch_add(&var,(count),__ATOMIC_RELAXED); \
} while(0)
#define atomicGetWithSync(var,dstvar) do { \
    dstvar = atomic_load_explicit(&var,memory_order_seq_cst); \
} while(0)
#define atomicIncr(var,count) __atomic_add_fetch(&var,(count),__ATOMIC_RELAXED)
#define atomicSet(var,value) atomic_store_explicit(&var,value,memory_order_relaxed)
#define atomicSetWithSync(var,value) \
    atomic_store_explicit(&var,value,memory_order_seq_cst)
#define redisAtomic _Atomic
#define isfinite(x) \
     __extension__ ({ __typeof (x) __x_f = (x); \
     __builtin_expect(!isnan(__x_f - __x_f), 1); })
#define isinf(x) \
     __extension__ ({ __typeof (x) __x_i = (x); \
     __builtin_expect(!isnan(__x_i) && !isfinite(__x_i), 0); })
#define isnan(x) \
     __extension__({ __typeof (x) __x_a = (x); \
     __builtin_expect(__x_a != __x_a, 0); })
#define u_int uint
#define u_int32_t uint32_t
