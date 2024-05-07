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
