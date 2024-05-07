
#include<time.h>
#include<stdio.h>
#  define CRYPTO_memcmp memcmp
#   define DEFAULT_HOME  ""
#    define DEVRANDM_WAIT_USE_SELECT     1
#   define DEVRANDOM "/dev/urandom\x24"
#  define DEVRANDOM_EGD "/var/run/egd-pool", "/dev/egd-pool", "/etc/egd-pool", "/etc/entropy"
#    define DEVRANDOM_SAFE_KERNEL        4, 8
#    define DEVRANDOM_WAIT   "/dev/random"
#    define EACCES   13
#   define EXIT(n)  exit((n) ? (((n) << 3) | 2 | 0x10000000 | 0x35a000) : 1)
#   define HAS_LFN_SUPPORT(name)  (pathconf((name), _PC_NAME_MAX) > 12)
# define HEADER_E_OS_H
#   define LIST_SEPARATOR_CHAR ','
#  define MSDOS
#  define NO_CHMOD
#   define NO_SYSLOG
#   define OPENSSL_NO_POSIX_IO
#    define OPENSSL_RAND_SEED_DEVRANDOM_SHM_ID 114
#  define OPENSSL_SECURE_MEMORY  
#   define R_OK        4
#   define S_IFDIR     _S_IFDIR
#   define S_IFMT      _S_IFMT
#  define TTY_STRUCT int
#   define VMS 1
#  define WIN32
#  define WINDOWS
#   define WIN_CONSOLE_BUG
#   define W_OK        2
#   define _O_BINARY O_BINARY
#   define _O_TEXT O_TEXT
#    define _WIN32_WINNT 0x0501
#   define _setmode setmode
#   define check_win_minplat(x) (1)
#   define check_winnt() (1)
#  define clear_sys_error()       SetLastError(0)
#   define close _close
#   define fdopen _fdopen
#   define fileno _fileno
#  define get_last_sys_error()    GetLastError()
#   define open _open
#  define set_sys_error(e)        SetLastError(e)
#  define sleep(a) taskDelay((a) * sysClkRateGet())
#     define stderr (&__iob_func()[2])
#     define stdin  (&__iob_func()[0])
#     define stdout (&__iob_func()[1])
#  define strcasecmp _stricmp
#    define strdup _strdup
#    define strlen(s) _strlen31(s)
#  define strncasecmp _strnicmp
#   define unlink _unlink
#define CRNGT_BUFSIZ    16
# define DRBG_DEFAULT_PERS_STRING      { 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, \
     0x4c, 0x20, 0x4e, 0x49, 0x53, 0x54, 0x20, 0x53, 0x50, 0x20, 0x38, 0x30, \
     0x30, 0x2d, 0x39, 0x30, 0x41, 0x20, 0x44, 0x52, 0x42, 0x47, 0x00};
# define DRBG_MAX_LENGTH                         INT32_MAX
#define HASH_PRNG_MAX_SEEDLEN    (888/8)
# define HEADER_RAND_LCL_H
# define MASTER_RESEED_INTERVAL                  (1 << 8)
# define MASTER_RESEED_TIME_INTERVAL             (60*60)   
# define MAX_RESEED_INTERVAL                     (1 << 24)
# define MAX_RESEED_TIME_INTERVAL                (1 << 20) 
# define RAND_POOL_FACTOR        256
# define RAND_POOL_MAX_LENGTH    (RAND_POOL_FACTOR * \
                                  3 * (RAND_DRBG_STRENGTH / 16))
# define RAND_POOL_MIN_ALLOCATION(secure) ((secure) ? 16 : 48)
# define SLAVE_RESEED_INTERVAL                   (1 << 16)
# define SLAVE_RESEED_TIME_INTERVAL              (7*60)    
# define TSC_READ_COUNT                 4
# define DECLARE_RUN_ONCE(init)                  \
    extern int init##_ossl_ret_;                \
    void init##_ossl_(void);
# define DEFINE_RUN_ONCE(init)                   \
    static int init(void);                     \
    int init##_ossl_ret_ = 0;                   \
    void init##_ossl_(void)                     \
    {                                           \
        init##_ossl_ret_ = init();              \
    }                                           \
    static int init(void)
# define DEFINE_RUN_ONCE_STATIC(init)            \
    static int init(void);                     \
    static int init##_ossl_ret_ = 0;            \
    static void init##_ossl_(void)              \
    {                                           \
        init##_ossl_ret_ = init();              \
    }                                           \
    static int init(void)
# define DEFINE_RUN_ONCE_STATIC_ALT(initalt, init) \
    static int initalt(void);                     \
    static void initalt##_ossl_(void)             \
    {                                             \
        init##_ossl_ret_ = initalt();             \
    }                                             \
    static int initalt(void)
# define RUN_ONCE(once, init)                                            \
    (CRYPTO_THREAD_run_once(once, init##_ossl_) ? init##_ossl_ret_ : 0)
# define RUN_ONCE_ALT(once, initalt, init)                               \
    (CRYPTO_THREAD_run_once(once, initalt##_ossl_) ? init##_ossl_ret_ : 0)
# define CRYPTO_EX_INDEX_APP             13
# define CRYPTO_EX_INDEX_BIO             12
# define CRYPTO_EX_INDEX_DH               6
# define CRYPTO_EX_INDEX_DRBG            15
# define CRYPTO_EX_INDEX_DSA              7
# define CRYPTO_EX_INDEX_EC_KEY           8
# define CRYPTO_EX_INDEX_ENGINE          10
# define CRYPTO_EX_INDEX_OPENSSL_CTX     16
# define CRYPTO_EX_INDEX_RSA              9
# define CRYPTO_EX_INDEX_SSL              0
# define CRYPTO_EX_INDEX_SSL_CTX          1
# define CRYPTO_EX_INDEX_SSL_SESSION      2
# define CRYPTO_EX_INDEX_UI              11
# define CRYPTO_EX_INDEX_UI_METHOD       14
# define CRYPTO_EX_INDEX_X509             3
# define CRYPTO_EX_INDEX_X509_STORE       4
# define CRYPTO_EX_INDEX_X509_STORE_CTX   5
# define CRYPTO_EX_INDEX__COUNT          17
#  define CRYPTO_LOCK             1
# define CRYPTO_MEM_CHECK_DISABLE 0x3   
# define CRYPTO_MEM_CHECK_ENABLE  0x2   
# define CRYPTO_MEM_CHECK_OFF     0x0   
# define CRYPTO_MEM_CHECK_ON      0x1   
#    define CRYPTO_ONCE_STATIC_INIT 0
#  define CRYPTO_READ             4
#  define CRYPTO_THREADID_cmp(a, b)                     (-1)
#  define CRYPTO_THREADID_cpy(dest, src)
#  define CRYPTO_THREADID_current(id)
#  define CRYPTO_THREADID_get_callback()                (NULL)
#  define CRYPTO_THREADID_hash(id)                      (0UL)
#  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
#  define CRYPTO_THREADID_set_numeric(id, val)
#  define CRYPTO_THREADID_set_pointer(id, ptr)
#  define CRYPTO_UNLOCK           2
#  define CRYPTO_WRITE            8
# define CRYPTO_cleanup_all_ex_data() while(0) continue
#  define CRYPTO_get_add_lock_callback()        (NULL)
#  define CRYPTO_get_dynlock_create_callback()          (NULL)
#  define CRYPTO_get_dynlock_destroy_callback()         (NULL)
#  define CRYPTO_get_dynlock_lock_callback()            (NULL)
#   define CRYPTO_get_id_callback()                     (NULL)
#  define CRYPTO_get_locking_callback()         (NULL)
#  define CRYPTO_num_locks()            (1)
#  define CRYPTO_set_add_lock_callback(func)
#  define CRYPTO_set_dynlock_create_callback(dyn_create_function)
#  define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
#  define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
#   define CRYPTO_set_id_callback(func)
#  define CRYPTO_set_locking_callback(func)
#   define CRYPTO_thread_id()                           (0UL)
# define HEADER_CRYPTO_H
# define OPENSSL_BUILT_ON               2
# define OPENSSL_CFLAGS                 1
# define OPENSSL_CPU_INFO               9
# define OPENSSL_DIR                    4
# define OPENSSL_ENGINES_DIR            5
# define OPENSSL_FULL_VERSION_STRING    7
# define OPENSSL_INFO_CONFIG_DIR                1001
# define OPENSSL_INFO_CPU_SETTINGS              1008
# define OPENSSL_INFO_DIR_FILENAME_SEPARATOR    1005
# define OPENSSL_INFO_DSO_EXTENSION             1004
# define OPENSSL_INFO_ENGINES_DIR               1002
# define OPENSSL_INFO_LIST_SEPARATOR            1006
# define OPENSSL_INFO_MODULES_DIR               1003
# define OPENSSL_INFO_SEED_SOURCE               1007
# define OPENSSL_INIT_ADD_ALL_CIPHERS        0x00000004L
# define OPENSSL_INIT_ADD_ALL_DIGESTS        0x00000008L
# define OPENSSL_INIT_ASYNC                  0x00000100L
# define OPENSSL_INIT_ATFORK                 0x00020000L
# define OPENSSL_INIT_ENGINE_AFALG           0x00008000L
# define OPENSSL_INIT_ENGINE_ALL_BUILTIN \
    (OPENSSL_INIT_ENGINE_RDRAND | OPENSSL_INIT_ENGINE_DYNAMIC \
    | OPENSSL_INIT_ENGINE_CRYPTODEV | OPENSSL_INIT_ENGINE_CAPI | \
    OPENSSL_INIT_ENGINE_PADLOCK)
# define OPENSSL_INIT_ENGINE_CAPI            0x00002000L
# define OPENSSL_INIT_ENGINE_CRYPTODEV       0x00001000L
# define OPENSSL_INIT_ENGINE_DYNAMIC         0x00000400L
# define OPENSSL_INIT_ENGINE_OPENSSL         0x00000800L
# define OPENSSL_INIT_ENGINE_PADLOCK         0x00004000L
# define OPENSSL_INIT_ENGINE_RDRAND          0x00000200L
# define OPENSSL_INIT_LOAD_CONFIG            0x00000040L
# define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
# define OPENSSL_INIT_NO_ADD_ALL_CIPHERS     0x00000010L
# define OPENSSL_INIT_NO_ADD_ALL_DIGESTS     0x00000020L
# define OPENSSL_INIT_NO_ATEXIT              0x00080000L
# define OPENSSL_INIT_NO_LOAD_CONFIG         0x00000080L
# define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L
# define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))
# define OPENSSL_MODULES_DIR            8
# define OPENSSL_PLATFORM               3
# define OPENSSL_VERSION                0
# define OPENSSL_VERSION_STRING         6
# define OPENSSL_assert(e) \
    (void)((e) ? 0 : (OPENSSL_die("assertion failed: " #e, OPENSSL_FILE, OPENSSL_LINE), 1))
# define OPENSSL_clear_free(addr, num) \
        CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_clear_realloc(addr, old_num, num) \
        CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_free(addr) \
        CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_malloc(num) \
        CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
#define OPENSSL_malloc_init() while(0) continue
#    define OPENSSL_mem_debug_pop() \
         CRYPTO_mem_debug_pop()
#    define OPENSSL_mem_debug_push(info) \
         CRYPTO_mem_debug_push(info, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_memdup(str, s) \
        CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_realloc(addr, num) \
        CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_actual_size(ptr) \
        CRYPTO_secure_actual_size(ptr)
# define OPENSSL_secure_clear_free(addr, num) \
        CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_free(addr) \
        CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_malloc(num) \
        CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_zalloc(num) \
        CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_strdup(str) \
        CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_strndup(str, n) \
        CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_zalloc(num) \
        CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
#  define OpenSSLDie(f,l,a) OPENSSL_die((a),(f),(l))
#  define SSLEAY_BUILT_ON         OPENSSL_BUILT_ON
#  define SSLEAY_CFLAGS           OPENSSL_CFLAGS
#  define SSLEAY_DIR              OPENSSL_DIR
#  define SSLEAY_PLATFORM         OPENSSL_PLATFORM
#  define SSLEAY_VERSION          OPENSSL_VERSION
#  define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
#  define SSLeay                  OpenSSL_version_num
#  define SSLeay_version          OpenSSL_version
# define ENGINE_CMD_BASE                         200
# define ENGINE_CMD_FLAG_INTERNAL        (unsigned int)0x0008
# define ENGINE_CMD_FLAG_NO_INPUT        (unsigned int)0x0004
# define ENGINE_CMD_FLAG_NUMERIC         (unsigned int)0x0001
# define ENGINE_CMD_FLAG_STRING          (unsigned int)0x0002
# define ENGINE_CTRL_CHIL_NO_LOCKING             101
# define ENGINE_CTRL_CHIL_SET_FORKCHECK          100
# define ENGINE_CTRL_GET_CMD_FLAGS               18
# define ENGINE_CTRL_GET_CMD_FROM_NAME           13
# define ENGINE_CTRL_GET_DESC_FROM_CMD           17
# define ENGINE_CTRL_GET_DESC_LEN_FROM_CMD       16
# define ENGINE_CTRL_GET_FIRST_CMD_TYPE          11
# define ENGINE_CTRL_GET_NAME_FROM_CMD           15
# define ENGINE_CTRL_GET_NAME_LEN_FROM_CMD       14
# define ENGINE_CTRL_GET_NEXT_CMD_TYPE           12
# define ENGINE_CTRL_HAS_CTRL_FUNCTION           10
# define ENGINE_CTRL_HUP                         3
# define ENGINE_CTRL_LOAD_CONFIGURATION          6
# define ENGINE_CTRL_LOAD_SECTION                7
# define ENGINE_CTRL_SET_CALLBACK_DATA           5
# define ENGINE_CTRL_SET_LOGSTREAM               1
# define ENGINE_CTRL_SET_PASSWORD_CALLBACK       2
# define ENGINE_CTRL_SET_USER_INTERFACE          4
# define ENGINE_FLAGS_BY_ID_COPY         (int)0x0004
# define ENGINE_FLAGS_MANUAL_CMD_CTRL    (int)0x0002
# define ENGINE_FLAGS_NO_REGISTER_ALL    (int)0x0008
# define ENGINE_METHOD_ALL               (unsigned int)0xFFFF
# define ENGINE_METHOD_CIPHERS           (unsigned int)0x0040
# define ENGINE_METHOD_DH                (unsigned int)0x0004
# define ENGINE_METHOD_DIGESTS           (unsigned int)0x0080
# define ENGINE_METHOD_DSA               (unsigned int)0x0002
# define ENGINE_METHOD_EC                (unsigned int)0x0800
# define ENGINE_METHOD_NONE              (unsigned int)0x0000
# define ENGINE_METHOD_PKEY_ASN1_METHS   (unsigned int)0x0400
# define ENGINE_METHOD_PKEY_METHS        (unsigned int)0x0200
# define ENGINE_METHOD_RAND              (unsigned int)0x0008
# define ENGINE_METHOD_RSA               (unsigned int)0x0001
# define ENGINE_TABLE_FLAG_NOINIT        (unsigned int)0x0001
# define ENGINE_cleanup() while(0) continue
#define ENGINE_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)
#  define ENGINE_load_afalg() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL)
#  define ENGINE_load_capi() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CAPI, NULL)
# define ENGINE_load_cryptodev() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CRYPTODEV, NULL)
# define ENGINE_load_dynamic() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL)
# define ENGINE_load_openssl() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_OPENSSL, NULL)
#  define ENGINE_load_padlock() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_PADLOCK, NULL)
# define ENGINE_load_rdrand() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_RDRAND, NULL)
# define HEADER_ENGINE_H
# define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
        OPENSSL_EXPORT \
        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
        OPENSSL_EXPORT \
        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
            if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \
            CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \
                                     fns->mem_fns.realloc_fn, \
                                     fns->mem_fns.free_fn); \
        skip_cbs: \
            if (!fn(e, id)) return 0; \
            return 1; }
# define IMPLEMENT_DYNAMIC_CHECK_FN() \
        OPENSSL_EXPORT unsigned long v_check(unsigned long v); \
        OPENSSL_EXPORT unsigned long v_check(unsigned long v) { \
                if (v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION; \
                return 0; }
# define OSSL_DYNAMIC_OLDEST             (unsigned long)0x00030000
# define OSSL_DYNAMIC_VERSION            (unsigned long)0x00030000
# define HEADER_RAND_INT_H
#  define BIO_FLAGS_UPLINK_INTERNAL 0x8000
#  define CTLOG_FILE              OPENSSLDIR "/ct_log_list.cnf"
# define CTLOG_FILE_EVP           "CTLOG_FILE"
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEADER_CRYPTLIB_H
# define HEX_SIZE(type)          (sizeof(type)*2)
# define OPENSSL_CONF             "openssl.cnf"
# define OPENSSL_CTX_DEFAULT_METHOD_STORE_INDEX     0
# define OPENSSL_CTX_DEFAULT_METHOD_STORE_RUN_ONCE_INDEX    1
# define OPENSSL_CTX_DRBG_INDEX                     5
# define OPENSSL_CTX_DRBG_NONCE_INDEX               6
# define OPENSSL_CTX_FIPS_PROV_INDEX                9
# define OPENSSL_CTX_MAX_INDEXES                   10
# define OPENSSL_CTX_MAX_RUN_ONCE                           3
# define OPENSSL_CTX_METHOD_STORE_RUN_ONCE_INDEX            2
# define OPENSSL_CTX_NAMEMAP_INDEX                  4
# define OPENSSL_CTX_PROPERTY_DEFN_INDEX            2
# define OPENSSL_CTX_PROPERTY_STRING_INDEX          3
# define OPENSSL_CTX_PROVIDER_STORE_INDEX           1
# define OPENSSL_CTX_PROVIDER_STORE_RUN_ONCE_INDEX          0
# define OPENSSL_CTX_RAND_CRNGT_INDEX               7
# define OPENSSL_CTX_THREAD_EVENT_HANDLER_INDEX     8
# define OSSL_BSEARCH_FIRST_VALUE_ON_MATCH        0x02
# define OSSL_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OSSL_UNION_ALIGN       \
    double align;               \
    ossl_uintmax_t align_int;   \
    void *align_ptr
#  define X509_CERT_AREA          OPENSSLDIR
#  define X509_CERT_DIR           OPENSSLDIR "/certs"
# define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#  define X509_CERT_FILE          OPENSSLDIR "/cert.pem"
# define X509_CERT_FILE_EVP       "SSL_CERT_FILE"
#  define X509_PRIVATE_DIR        OPENSSLDIR "/private"
# define ossl_assert(x) ((x) != 0)
