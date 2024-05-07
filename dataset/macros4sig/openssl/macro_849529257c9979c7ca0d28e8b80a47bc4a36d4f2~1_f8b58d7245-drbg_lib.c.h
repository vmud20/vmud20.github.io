
#include<string.h>
# define OPENSSL_INIT_BASE_ONLY              0x00040000L
# define OPENSSL_INIT_ZLIB                   0x00010000L
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
# define OSSL_CORE_H
# define OSSL_PARAM_INTEGER              1
# define OSSL_PARAM_OCTET_PTR            7
# define OSSL_PARAM_OCTET_STRING         5
# define OSSL_PARAM_REAL                 3
# define OSSL_PARAM_UNSIGNED_INTEGER     2
# define OSSL_PARAM_UTF8_PTR             6
# define OSSL_PARAM_UTF8_STRING          4
# define HEADER_RAND_INT_H
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
# define HEADER_RAND_H
#   define RAND_cleanup() while(0) continue
# define ASN1err(f,r) ERR_raise(ERR_LIB_ASN1,(r))
# define ASYNCerr(f,r) ERR_raise(ERR_LIB_ASYNC,(r))
# define BIOerr(f,r)  ERR_raise(ERR_LIB_BIO,(r))
# define BNerr(f,r)   ERR_raise(ERR_LIB_BN,(r))
# define BUFerr(f,r)  ERR_raise(ERR_LIB_BUF,(r))
# define CMPerr(f,r) ERR_raise(ERR_LIB_CMP,(r))
# define CMSerr(f,r) ERR_raise(ERR_LIB_CMS,(r))
# define COMPerr(f,r) ERR_raise(ERR_LIB_COMP,(r))
# define CONFerr(f,r) ERR_raise(ERR_LIB_CONF,(r))
# define CRMFerr(f,r) ERR_raise(ERR_LIB_CRMF,(r))
# define CRYPTOerr(f,r) ERR_raise(ERR_LIB_CRYPTO,(r))
# define CTerr(f,r) ERR_raise(ERR_LIB_CT,(r))
# define DHerr(f,r)   ERR_raise(ERR_LIB_DH,(r))
# define DSAerr(f,r)  ERR_raise(ERR_LIB_DSA,(r))
# define DSOerr(f,r) ERR_raise(ERR_LIB_DSO,(r))
# define ECDHerr(f,r)  ERR_raise(ERR_LIB_ECDH,(r))
# define ECDSAerr(f,r)  ERR_raise(ERR_LIB_ECDSA,(r))
# define ECerr(f,r)   ERR_raise(ERR_LIB_EC,(r))
# define ENGINEerr(f,r) ERR_raise(ERR_LIB_ENGINE,(r))
#  define ERR_DBG_FILE OPENSSL_FILE
#  define ERR_DBG_FUNC OPENSSL_FUNC
#  define ERR_DBG_LINE OPENSSL_LINE
# define ERR_FATAL_ERROR(l)      (int)( (l)         & ERR_R_FATAL)
# define ERR_FLAG_CLEAR          0x02
# define ERR_FLAG_MARK           0x01
# define ERR_GET_FUNC(l)         (int)(((l) >> 12L) & 0xFFFL)
# define ERR_GET_LIB(l)          (int)(((l) >> 24L) & 0x0FFL)
# define ERR_GET_REASON(l)       (int)( (l)         & 0xFFFL)
# define ERR_LIB_ASN1            13
# define ERR_LIB_ASYNC           51
# define ERR_LIB_BIO             32
# define ERR_LIB_BN              3
# define ERR_LIB_BUF             7
# define ERR_LIB_CMP             57
# define ERR_LIB_CMS             46
# define ERR_LIB_COMP            41
# define ERR_LIB_CONF            14
# define ERR_LIB_CRMF            55
# define ERR_LIB_CRYPTO          15
# define ERR_LIB_CT              50
# define ERR_LIB_DH              5
# define ERR_LIB_DSA             10
# define ERR_LIB_DSO             37
# define ERR_LIB_EC              16
# define ERR_LIB_ECDH            43
# define ERR_LIB_ECDSA           42
# define ERR_LIB_ENGINE          38
# define ERR_LIB_ESS             53
# define ERR_LIB_EVP             6
# define ERR_LIB_FIPS            45
# define ERR_LIB_HMAC            48
# define ERR_LIB_NONE            1
# define ERR_LIB_OBJ             8
# define ERR_LIB_OCSP            39
# define ERR_LIB_OSSL_STORE      44
# define ERR_LIB_PEM             9
# define ERR_LIB_PKCS12          35
# define ERR_LIB_PKCS7           33
# define ERR_LIB_PROP            54
# define ERR_LIB_PROV            56
# define ERR_LIB_RAND            36
# define ERR_LIB_RSA             4
# define ERR_LIB_SM2             52
# define ERR_LIB_SSL             20
# define ERR_LIB_SYS             2
# define ERR_LIB_TS              47
# define ERR_LIB_UI              40
# define ERR_LIB_USER            128
# define ERR_LIB_X509            11
# define ERR_LIB_X509V3          34
#define ERR_MAX_DATA_SIZE       1024
# define ERR_NUM_ERRORS  16
# define ERR_PACK(l,f,r) ( \
        (((unsigned int)(l) & 0x0FF) << 24L) | \
        (((unsigned int)(f) & 0xFFF) << 12L) | \
        (((unsigned int)(r) & 0xFFF)       ) )
#   define ERR_PUT_error(l,f,r,fn,ln)      ERR_put_error(l,f,r,fn,ln)
# define ERR_R_ASN1_LIB  ERR_LIB_ASN1
# define ERR_R_BIO_LIB   ERR_LIB_BIO
# define ERR_R_BN_LIB    ERR_LIB_BN
# define ERR_R_BUF_LIB   ERR_LIB_BUF
# define ERR_R_DH_LIB    ERR_LIB_DH
# define ERR_R_DISABLED                          (5|ERR_R_FATAL)
# define ERR_R_DSA_LIB   ERR_LIB_DSA
# define ERR_R_ECDSA_LIB ERR_LIB_ECDSA
# define ERR_R_EC_LIB    ERR_LIB_EC
# define ERR_R_ENGINE_LIB ERR_LIB_ENGINE
# define ERR_R_EVP_LIB   ERR_LIB_EVP
# define ERR_R_FATAL                             64
# define ERR_R_INIT_FAIL                         (6|ERR_R_FATAL)
# define ERR_R_INTERNAL_ERROR                    (4|ERR_R_FATAL)
# define ERR_R_MALLOC_FAILURE                    (1|ERR_R_FATAL)
# define ERR_R_MISSING_ASN1_EOS                  63
# define ERR_R_NESTED_ASN1_ERROR                 58
# define ERR_R_OBJ_LIB   ERR_LIB_OBJ
# define ERR_R_OPERATION_FAIL                    (8|ERR_R_FATAL)
# define ERR_R_OSSL_STORE_LIB ERR_LIB_OSSL_STORE
# define ERR_R_PASSED_INVALID_ARGUMENT           (7)
# define ERR_R_PASSED_NULL_PARAMETER             (3|ERR_R_FATAL)
# define ERR_R_PEM_LIB   ERR_LIB_PEM
# define ERR_R_PKCS7_LIB ERR_LIB_PKCS7
# define ERR_R_RSA_LIB   ERR_LIB_RSA
# define ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED       (2|ERR_R_FATAL)
# define ERR_R_SYS_LIB   ERR_LIB_SYS
# define ERR_R_UI_LIB    ERR_LIB_UI
# define ERR_R_X509V3_LIB ERR_LIB_X509V3
# define ERR_R_X509_LIB  ERR_LIB_X509
# define ERR_TXT_MALLOCED        0x01
# define ERR_TXT_STRING          0x02
# define ERR_free_strings() while(0) continue
# define ERR_load_crypto_strings() \
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
#  define ERR_put_error(lib, func, reason, file, line)          \
    (ERR_new(),                                                 \
     ERR_set_debug((file), (line), NULL),                       \
     ERR_set_error((lib), (reason), NULL))
# define ERR_raise(lib, reason) ERR_raise_data((lib),(reason),NULL)
# define ERR_raise_data                                         \
    (ERR_new(),                                                 \
     ERR_set_debug(ERR_DBG_FILE,ERR_DBG_LINE,ERR_DBG_FUNC),     \
     ERR_set_error)
# define ESSerr(f,r) ERR_raise(ERR_LIB_ESS,(r))
# define EVPerr(f,r)  ERR_raise(ERR_LIB_EVP,(r))
# define FIPSerr(f,r) ERR_raise(ERR_LIB_FIPS,(r))
# define HEADER_ERR_H
# define HMACerr(f,r) ERR_raise(ERR_LIB_HMAC,(r))
# define OBJerr(f,r)  ERR_raise(ERR_LIB_OBJ,(r))
# define OCSPerr(f,r) ERR_raise(ERR_LIB_OCSP,(r))
# define OSSL_STOREerr(f,r) ERR_raise(ERR_LIB_OSSL_STORE,(r))
# define PEMerr(f,r)  ERR_raise(ERR_LIB_PEM,(r))
# define PKCS12err(f,r) ERR_raise(ERR_LIB_PKCS12,(r))
# define PKCS7err(f,r) ERR_raise(ERR_LIB_PKCS7,(r))
# define PROPerr(f,r) ERR_raise(ERR_LIB_PROP,(r))
# define PROVerr(f,r) ERR_raise(ERR_LIB_PROV,(r))
# define RANDerr(f,r) ERR_raise(ERR_LIB_RAND,(r))
# define RSAerr(f,r)  ERR_raise(ERR_LIB_RSA,(r))
# define SM2err(f,r) ERR_raise(ERR_LIB_SM2,(r))
# define SSLerr(f,r)  ERR_raise(ERR_LIB_SSL,(r))
#  define SYS_F_ACCEPT            0
#  define SYS_F_BIND              0
#  define SYS_F_CLOSE             0
#  define SYS_F_CONNECT           0
#  define SYS_F_FCNTL             0
#  define SYS_F_FFLUSH            0
#  define SYS_F_FOPEN             0
#  define SYS_F_FREAD             0
#  define SYS_F_FSTAT             0
#  define SYS_F_GETADDRINFO       0
#  define SYS_F_GETHOSTBYNAME     0
#  define SYS_F_GETNAMEINFO       0
#  define SYS_F_GETSERVBYNAME     0
#  define SYS_F_GETSOCKNAME       0
#  define SYS_F_GETSOCKOPT        0
#  define SYS_F_IOCTL             0
#  define SYS_F_IOCTLSOCKET       0
#  define SYS_F_LISTEN            0
#  define SYS_F_OPEN              0
#  define SYS_F_OPENDIR           0
#  define SYS_F_SENDFILE          0
#  define SYS_F_SETSOCKOPT        0
#  define SYS_F_SOCKET            0
#  define SYS_F_STAT              0
#  define SYS_F_WSASTARTUP        0
#  define SYSerr(f,r)  ERR_raise(ERR_LIB_SYS,(r))
# define TSerr(f,r) ERR_raise(ERR_LIB_TS,(r))
# define UIerr(f,r) ERR_raise(ERR_LIB_UI,(r))
# define X509V3err(f,r) ERR_raise(ERR_LIB_X509V3,(r))
# define X509err(f,r) ERR_raise(ERR_LIB_X509,(r))
