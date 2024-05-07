#include<assert.h>
#include<stdlib.h>


# define OSSL_TRACE(category, text) \
    OSSL_TRACEV(category, (trc_out, "%s", text))
# define OSSL_TRACE1(category, format, arg1) \
    OSSL_TRACEV(category, (trc_out, format, arg1))
# define OSSL_TRACE2(category, format, arg1, arg2) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2))
# define OSSL_TRACE3(category, format, arg1, arg2, arg3) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3))
# define OSSL_TRACE4(category, format, arg1, arg2, arg3, arg4) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4))
# define OSSL_TRACE5(category, format, arg1, arg2, arg3, arg4, arg5) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5))
# define OSSL_TRACE6(category, format, arg1, arg2, arg3, arg4, arg5, arg6) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6))
# define OSSL_TRACE7(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7))
# define OSSL_TRACE8(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8))
# define OSSL_TRACE9(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))
# define OSSL_TRACEV(category, args) \
    OSSL_TRACE_BEGIN(category) \
        BIO_printf args; \
    OSSL_TRACE_END(category)
#  define OSSL_TRACE_BEGIN(category) \
    do { \
        BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_##category); \
 \
        if (trc_out != NULL)
#  define OSSL_TRACE_CANCEL(category) \
        OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out) \

# define OSSL_TRACE_CATEGORY_ALL                 0 
# define OSSL_TRACE_CATEGORY_BN_CTX             12
# define OSSL_TRACE_CATEGORY_CONF                5
# define OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT    7
# define OSSL_TRACE_CATEGORY_ENGINE_TABLE        6
# define OSSL_TRACE_CATEGORY_INIT                2
# define OSSL_TRACE_CATEGORY_NUM                13
# define OSSL_TRACE_CATEGORY_PKCS12_DECRYPT     10
# define OSSL_TRACE_CATEGORY_PKCS12_KEYGEN       9
# define OSSL_TRACE_CATEGORY_PKCS5V2             8
# define OSSL_TRACE_CATEGORY_TLS                 3
# define OSSL_TRACE_CATEGORY_TLS_CIPHER          4
# define OSSL_TRACE_CATEGORY_TRACE               1
# define OSSL_TRACE_CATEGORY_X509V3_POLICY      11
# define OSSL_TRACE_CTRL_BEGIN  0
# define OSSL_TRACE_CTRL_END    2
# define OSSL_TRACE_CTRL_WRITE  1
#  define OSSL_TRACE_ENABLED(category) \
    OSSL_trace_enabled(OSSL_TRACE_CATEGORY_##category)
#  define OSSL_TRACE_END(category) \
        OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out); \
    } while (0)
# define OSSL_TRACE_H
# define DSO_CTRL_GET_FLAGS      1
# define DSO_CTRL_OR_FLAGS       3
# define DSO_CTRL_SET_FLAGS      2
# define DSO_FLAG_GLOBAL_SYMBOLS                 0x20
# define DSO_FLAG_NAME_TRANSLATION_EXT_ONLY      0x02
# define DSO_FLAG_NO_NAME_TRANSLATION            0x01
# define DSO_FLAG_NO_UNLOAD_ON_FREE              0x04
# define HEADER_DSO_H
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
# define DECLARE_OBJ_BSEARCH_CMP_FN(type1, type2, cmp)   \
  _DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)
# define DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)     \
  type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)
# define HEADER_OBJECTS_H
# define IMPLEMENT_OBJ_BSEARCH_CMP_FN(type1, type2, nm)  \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  static type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)
# define IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)   \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)
# define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH        0x02
# define OBJ_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OBJ_NAME_ALIAS                  0x8000
# define OBJ_NAME_TYPE_CIPHER_METH       0x02
# define OBJ_NAME_TYPE_COMP_METH         0x04
# define OBJ_NAME_TYPE_KDF_METH          0x06
# define OBJ_NAME_TYPE_MAC_METH          0x05
# define OBJ_NAME_TYPE_MD_METH           0x01
# define OBJ_NAME_TYPE_NUM               0x07
# define OBJ_NAME_TYPE_PKEY_METH         0x03
# define OBJ_NAME_TYPE_UNDEF             0x00
# define OBJ_bsearch(type1,key,type2,base,num,cmp)                              \
  ((type2 *)OBJ_bsearch_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)CHECKED_PTR_OF(type2,cmp##_type_2),     \
                          cmp##_BSEARCH_CMP_FN)))
# define OBJ_bsearch_ex(type1,key,type2,base,num,cmp,flags)                      \
  ((type2 *)OBJ_bsearch_ex_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)type_2=CHECKED_PTR_OF(type2,cmp##_type_2), \
                          cmp##_BSEARCH_CMP_FN)),flags)
# define OBJ_cleanup() while(0) continue
# define         OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)
# define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)    \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \
  static int nm##_cmp(type1 const *, type2 const *); \
  scope type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)
# define INTERNAL_ERR_INT_H
# define INTERNAL_ERR_H
#define COMP_zlib_cleanup() while(0) continue
# define HEADER_COMP_H
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
#define ASYNC_ERR      0
#define ASYNC_FINISH   3
#define ASYNC_NO_JOBS  1
#define ASYNC_PAUSE    2
#define ASYNC_STATUS_EAGAIN         3
#define ASYNC_STATUS_ERR            1
#define ASYNC_STATUS_OK             2
#define ASYNC_STATUS_UNSUPPORTED    0
# define HEADER_ASYNC_H
#define OSSL_ASYNC_FD       HANDLE
#define OSSL_BAD_ASYNC_FD   INVALID_HANDLE_VALUE
#define DEFAULT_CONF_MFLAGS \
    (CONF_MFLAGS_DEFAULT_SECTION | \
     CONF_MFLAGS_IGNORE_MISSING_FILE | \
     CONF_MFLAGS_IGNORE_RETURN_CODES)
# define HEADER_INTERNAL_CONF_H
# define CONF_MFLAGS_DEFAULT_SECTION     0x20
# define CONF_MFLAGS_IGNORE_ERRORS       0x1
# define CONF_MFLAGS_IGNORE_MISSING_FILE 0x10
# define CONF_MFLAGS_IGNORE_RETURN_CODES 0x2
# define CONF_MFLAGS_NO_DSO              0x8
# define CONF_MFLAGS_SILENT              0x4
# define CONF_modules_free() while(0) continue
# define HEADER_CONF_H
#define NCONF_get_number(c,g,n,r) NCONF_get_number_e(c,g,n,r)
# define OPENSSL_no_config() \
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
#define BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)
#define BLOCK_CIPHER_def1(cname, nmode, mode, MODE, kstruct, nid, block_size, \
                          key_len, iv_len, flags, init_key, cleanup, \
                          set_asn1, get_asn1, ctrl) \
static const EVP_CIPHER cname##_##mode = { \
        nid##_##nmode, block_size, key_len, iv_len, \
        flags | EVP_CIPH_##MODE##_MODE, \
        init_key, \
        cname##_##mode##_cipher, \
        cleanup, \
        sizeof(kstruct), \
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
}; \
const EVP_CIPHER *EVP_##cname##_##mode(void) { return &cname##_##mode; }
#define BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, \
                             iv_len, flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cbc, cbc, CBC, kstruct, nid, block_size, key_len, \
                  iv_len, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)
#define BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cfb##cbits, cfb##cbits, CFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)
#define BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, \
                             flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ecb, ecb, ECB, kstruct, nid, block_size, key_len, \
                  0, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)
#define BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ofb##cbits, ofb, OFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)
#define BLOCK_CIPHER_defs(cname, kstruct, \
                          nid, block_size, key_len, iv_len, cbits, flags, \
                          init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl)
#define BLOCK_CIPHER_ecb_loop() \
        size_t i, bl; \
        bl = EVP_CIPHER_CTX_cipher(ctx)->block_size;    \
        if (inl < bl) return 1;\
        inl -= bl; \
        for (i=0; i <= inl; i+=bl)
#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
static int cname##_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) \
            {\
            cprefix##_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx));\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
            }\
        if (inl)\
            cprefix##_cbc_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx));\
        return 1;\
}
#define BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched)  \
static int cname##_cfb##cbits##_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
    size_t chunk = EVP_MAXCHUNK;\
    if (cbits == 1)  chunk >>= 3;\
    if (inl < chunk) chunk = inl;\
    while (inl && inl >= chunk)\
    {\
        int num = EVP_CIPHER_CTX_num(ctx);\
        cprefix##_cfb##cbits##_encrypt(in, out, (long) \
            ((cbits == 1) \
                && !EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) \
                ? chunk*8 : chunk), \
            &EVP_C_DATA(kstruct, ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx),\
            &num, EVP_CIPHER_CTX_encrypting(ctx));\
        EVP_CIPHER_CTX_set_num(ctx, num);\
        inl -= chunk;\
        in += chunk;\
        out += chunk;\
        if (inl < chunk) chunk = inl;\
    }\
    return 1;\
}
#define BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
static int cname##_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        BLOCK_CIPHER_ecb_loop() \
            cprefix##_ecb_encrypt(in + i, out + i, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_encrypting(ctx)); \
        return 1;\
}
#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched) \
    static int cname##_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
        }\
        if (inl) {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
        }\
        return 1;\
}
#define ED448_KEYLEN         57
#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))
#define EVP_ENCODE_CTX_NO_NEWLINES          1
#define EVP_ENCODE_CTX_USE_SRP_ALPHABET     2
#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))
#define EVP_MD_CTX_FLAG_KEEP_PKEY_CTX   0x0400
#define EVP_PKEY_CTX_IS_DERIVE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_DERIVE)
#define EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_SIGN \
     || (ctx)->operation == EVP_PKEY_OP_SIGNCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFY \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYRECOVER)
#define EVP_PKEY_FLAG_DYNAMIC   1
#define EVP_RC4_KEY_SIZE 16
#define IMPLEMENT_BLOCK_CIPHER(cname, ksched, cprefix, kstruct, nid, \
                               block_size, key_len, iv_len, cbits, \
                               flags, init_key, \
                               cleanup, set_asn1, get_asn1, ctrl) \
        BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len, \
                          cbits, flags, init_key, cleanup, set_asn1, \
                          get_asn1, ctrl)
#define IMPLEMENT_CFBR(cipher,cprefix,kstruct,ksched,keysize,cbits,iv_len,fl) \
        BLOCK_CIPHER_func_cfb(cipher##_##keysize,cprefix,cbits,kstruct,ksched) \
        BLOCK_CIPHER_def_cfb(cipher##_##keysize,kstruct, \
                             NID_##cipher##_##keysize, keysize/8, iv_len, cbits, \
                             (fl)|EVP_CIPH_FLAG_DEFAULT_ASN1, \
                             cipher##_init_key, NULL, NULL, NULL, NULL)
#define MAX_KEYLEN  ED448_KEYLEN
# define TLS1_1_VERSION   0x0302
#define X25519_KEYLEN        32
#define X448_KEYLEN          56
# define CRYPTO_DOWN_REF(val, ret, lock) CRYPTO_atomic_add(val, -1, ret, lock)
# define CRYPTO_UP_REF(val, ret, lock) CRYPTO_atomic_add(val, 1, ret, lock)
#   define HAVE_ATOMICS 1
#   define HAVE_C11_ATOMICS
# define HEADER_INTERNAL_REFCOUNT_H
#  define REF_ASSERT_ISNT(test) \
    (void)((test) ? (OPENSSL_die("refcount error", "__FILE__", "__LINE__"), 1) : 0)
#  define REF_PRINT_COUNT(a, b) \
        fprintf(stderr, "%p:%4d:%s\n", b, b->references, a)
#     define _ARM_BARRIER_ISH _ARM64_BARRIER_ISH
#      define _InterlockedExchangeAdd InterlockedExchangeAdd
#define OSSL_CORE_MAKE_FUNC(type,name,args)                             \
    typedef type (OSSL_##name##_fn)args;                                \
    static ossl_inline \
    OSSL_##name##_fn *OSSL_get_##name(const OSSL_DISPATCH *opf)         \
    {                                                                   \
        return (OSSL_##name##_fn *)opf->function;                       \
    }
# define OSSL_CORE_NUMBERS_H
#define OSSL_FUNC_BIO_FREE                    25
#define OSSL_FUNC_BIO_NEW_FILE                22
#define OSSL_FUNC_BIO_NEW_MEMBUF              23
#define OSSL_FUNC_BIO_READ                    24
# define OSSL_FUNC_CIPHER_CIPHER                     6
# define OSSL_FUNC_CIPHER_DECRYPT_INIT               3
# define OSSL_FUNC_CIPHER_DUPCTX                     8
# define OSSL_FUNC_CIPHER_ENCRYPT_INIT               2
# define OSSL_FUNC_CIPHER_FINAL                      5
# define OSSL_FUNC_CIPHER_FREECTX                    7
# define OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS       13
# define OSSL_FUNC_CIPHER_GETTABLE_PARAMS           12
# define OSSL_FUNC_CIPHER_GET_CTX_PARAMS            10
# define OSSL_FUNC_CIPHER_GET_PARAMS                 9
# define OSSL_FUNC_CIPHER_NEWCTX                     1
# define OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS       14
# define OSSL_FUNC_CIPHER_SET_CTX_PARAMS            11
# define OSSL_FUNC_CIPHER_UPDATE                     4
# define OSSL_FUNC_CORE_GETTABLE_PARAMS        1
# define OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT    4
# define OSSL_FUNC_CORE_GET_PARAMS             2
# define OSSL_FUNC_CORE_NEW_ERROR              5
# define OSSL_FUNC_CORE_SET_ERROR_DEBUG        6
# define OSSL_FUNC_CORE_THREAD_START           3
# define OSSL_FUNC_CORE_VSET_ERROR             7
#define OSSL_FUNC_CRYPTO_CLEAR_FREE           13
#define OSSL_FUNC_CRYPTO_CLEAR_REALLOC        15
#define OSSL_FUNC_CRYPTO_FREE                 12
#define OSSL_FUNC_CRYPTO_MALLOC               10
#define OSSL_FUNC_CRYPTO_REALLOC              14
#define OSSL_FUNC_CRYPTO_SECURE_ALLOCATED     20
#define OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE    19
#define OSSL_FUNC_CRYPTO_SECURE_FREE          18
#define OSSL_FUNC_CRYPTO_SECURE_MALLOC        16
#define OSSL_FUNC_CRYPTO_SECURE_ZALLOC        17
#define OSSL_FUNC_CRYPTO_ZALLOC               11
# define OSSL_FUNC_DIGEST_DIGEST                     5
# define OSSL_FUNC_DIGEST_DUPCTX                     7
# define OSSL_FUNC_DIGEST_FINAL                      4
# define OSSL_FUNC_DIGEST_FREECTX                    6
# define OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS       13
# define OSSL_FUNC_DIGEST_GETTABLE_PARAMS           11
# define OSSL_FUNC_DIGEST_GET_CTX_PARAMS            10
# define OSSL_FUNC_DIGEST_GET_PARAMS                 8
# define OSSL_FUNC_DIGEST_INIT                       2
# define OSSL_FUNC_DIGEST_NEWCTX                     1
# define OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS       12
# define OSSL_FUNC_DIGEST_SET_CTX_PARAMS             9
# define OSSL_FUNC_DIGEST_UPDATE                     3
# define OSSL_FUNC_KDF_DERIVE                        5
# define OSSL_FUNC_KDF_DUPCTX                        2
# define OSSL_FUNC_KDF_FREECTX                       3
# define OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS           7
# define OSSL_FUNC_KDF_GETTABLE_PARAMS               6
# define OSSL_FUNC_KDF_GET_CTX_PARAMS               10
# define OSSL_FUNC_KDF_GET_PARAMS                    9
# define OSSL_FUNC_KDF_NEWCTX                        1
# define OSSL_FUNC_KDF_RESET                         4
# define OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS           8
# define OSSL_FUNC_KDF_SET_CTX_PARAMS               11
# define OSSL_FUNC_KEYEXCH_DERIVE                      3
# define OSSL_FUNC_KEYEXCH_DUPCTX                      6
# define OSSL_FUNC_KEYEXCH_FREECTX                     5
# define OSSL_FUNC_KEYEXCH_INIT                        2
# define OSSL_FUNC_KEYEXCH_NEWCTX                      1
# define OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS         8
# define OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS              7
# define OSSL_FUNC_KEYEXCH_SET_PEER                    4
# define OSSL_FUNC_KEYMGMT_EXPORTDOMPARAMS          4
# define OSSL_FUNC_KEYMGMT_EXPORTDOMPARAM_TYPES     6
# define OSSL_FUNC_KEYMGMT_EXPORTKEY               14
# define OSSL_FUNC_KEYMGMT_EXPORTKEY_TYPES         16
# define OSSL_FUNC_KEYMGMT_FREEDOMPARAMS            3
# define OSSL_FUNC_KEYMGMT_FREEKEY                 13
# define OSSL_FUNC_KEYMGMT_GENDOMPARAMS             2
# define OSSL_FUNC_KEYMGMT_GENKEY                  11
# define OSSL_FUNC_KEYMGMT_IMPORTDOMPARAMS          1
# define OSSL_FUNC_KEYMGMT_IMPORTDOMPARAM_TYPES     5
# define OSSL_FUNC_KEYMGMT_IMPORTKEY               10
# define OSSL_FUNC_KEYMGMT_IMPORTKEY_TYPES         15
# define OSSL_FUNC_KEYMGMT_LOADKEY                 12
# define OSSL_FUNC_MAC_DUPCTX                        2
# define OSSL_FUNC_MAC_FINAL                         6
# define OSSL_FUNC_MAC_FREECTX                       3
# define OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS          11
# define OSSL_FUNC_MAC_GETTABLE_PARAMS              10
# define OSSL_FUNC_MAC_GET_CTX_PARAMS                8
# define OSSL_FUNC_MAC_GET_PARAMS                    7
# define OSSL_FUNC_MAC_INIT                          4
# define OSSL_FUNC_MAC_NEWCTX                        1
# define OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS          12
# define OSSL_FUNC_MAC_SET_CTX_PARAMS                9
# define OSSL_FUNC_MAC_UPDATE                        5
#define OSSL_FUNC_OPENSSL_CLEANSE             21
# define OSSL_FUNC_PROVIDER_GETTABLE_PARAMS  1025
# define OSSL_FUNC_PROVIDER_GET_PARAMS       1026
# define OSSL_FUNC_PROVIDER_GET_REASON_STRINGS 1028
# define OSSL_FUNC_PROVIDER_QUERY_OPERATION  1027
# define OSSL_FUNC_PROVIDER_TEARDOWN         1024
# define OSSL_FUNC_SIGNATURE_DUPCTX                  9
# define OSSL_FUNC_SIGNATURE_FREECTX                 8
# define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS    11
# define OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS         10
# define OSSL_FUNC_SIGNATURE_NEWCTX                  1
# define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS    13
# define OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS         12
# define OSSL_FUNC_SIGNATURE_SIGN                    3
# define OSSL_FUNC_SIGNATURE_SIGN_INIT               2
# define OSSL_FUNC_SIGNATURE_VERIFY                  5
# define OSSL_FUNC_SIGNATURE_VERIFY_INIT             4
# define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER          7
# define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT     6
# define OSSL_OP_CIPHER                              2   
# define OSSL_OP_DIGEST                              1
# define OSSL_OP_KDF                                 4
# define OSSL_OP_KEYEXCH                            11
# define OSSL_OP_KEYMGMT                            10
# define OSSL_OP_MAC                                 3
# define OSSL_OP_SIGNATURE                          12
# define OSSL_OP__HIGHEST                           12
# define ASN1_PKEY_ALIAS         0x1
# define ASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
# define ASN1_PKEY_CTRL_CMS_RI_TYPE      0x8
# define ASN1_PKEY_CTRL_CMS_SIGN         0x5
# define ASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
# define ASN1_PKEY_CTRL_GET1_TLS_ENCPT   0xa
# define ASN1_PKEY_CTRL_PKCS7_ENCRYPT    0x2
# define ASN1_PKEY_CTRL_PKCS7_SIGN       0x1
# define ASN1_PKEY_CTRL_SET1_TLS_ENCPT   0x9
# define ASN1_PKEY_CTRL_SUPPORTS_MD_NID  0xb
# define ASN1_PKEY_DYNAMIC       0x2
# define ASN1_PKEY_SIGPARAM_NULL 0x4
# define BIO_get_cipher_ctx(b,c_pp) BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,(c_pp))
# define BIO_get_cipher_status(b)   BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)
# define BIO_get_md(b,mdp)          BIO_ctrl(b,BIO_C_GET_MD,0,(mdp))
# define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0,(mdcp))
#  define BIO_set_md(b,md)          BIO_ctrl(b,BIO_C_SET_MD,0,(void *)(md))
# define BIO_set_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0,(mdcp))
# define         EVP_AEAD_TLS1_AAD_LEN           13
# define EVP_CCM8_TLS_TAG_LEN                            8
# define EVP_CCM_TLS_EXPLICIT_IV_LEN                     8
# define EVP_CCM_TLS_FIXED_IV_LEN                        4
# define EVP_CCM_TLS_IV_LEN                              12
# define EVP_CCM_TLS_TAG_LEN                             16
# define EVP_CHACHAPOLY_TLS_TAG_LEN                      16
# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1
#  define EVP_CIPHER_CTX_cleanup(c)   EVP_CIPHER_CTX_reset(c)
#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
#  define EVP_CIPHER_CTX_init(c)      EVP_CIPHER_CTX_reset(c)
# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
# define EVP_CIPHER_CTX_name(c)         EVP_CIPHER_name(EVP_CIPHER_CTX_cipher(c))
# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
# define         EVP_CIPH_ALWAYS_CALL_INIT       0x20
# define         EVP_CIPH_CBC_MODE               0x2
# define         EVP_CIPH_CCM_MODE               0x7
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_CTRL_INIT              0x40
# define         EVP_CIPH_CTR_MODE               0x5
# define         EVP_CIPH_CUSTOM_COPY            0x400
# define         EVP_CIPH_CUSTOM_IV              0x10
# define         EVP_CIPH_CUSTOM_IV_LENGTH       0x800
# define         EVP_CIPH_CUSTOM_KEY_LENGTH      0x80
# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_FLAG_AEAD_CIPHER       0x200000
# define         EVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         EVP_CIPH_FLAG_DEFAULT_ASN1      0x1000
# define         EVP_CIPH_FLAG_FIPS              0x4000
# define         EVP_CIPH_FLAG_LENGTH_BITS       0x2000
# define         EVP_CIPH_FLAG_NON_FIPS_ALLOW    0x8000
# define         EVP_CIPH_FLAG_PIPELINE          0X800000
# define         EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
# define         EVP_CIPH_GCM_MODE               0x6
# define         EVP_CIPH_MODE                   0xF0007
# define         EVP_CIPH_NO_PADDING             0x100
# define         EVP_CIPH_OCB_MODE               0x10003
# define         EVP_CIPH_OFB_MODE               0x4
# define         EVP_CIPH_RAND_KEY               0x200
# define         EVP_CIPH_SIV_MODE               0x10004
# define         EVP_CIPH_STREAM_CIPHER          0x0
# define         EVP_CIPH_VARIABLE_LENGTH        0x8
# define         EVP_CIPH_WRAP_MODE              0x10002
# define         EVP_CIPH_XTS_MODE               0x10001
# define         EVP_CTRL_AEAD_GET_TAG           0x10
# define         EVP_CTRL_AEAD_SET_IVLEN         0x9
# define         EVP_CTRL_AEAD_SET_IV_FIXED      0x12
# define         EVP_CTRL_AEAD_SET_MAC_KEY       0x17
# define         EVP_CTRL_AEAD_SET_TAG           0x11
# define         EVP_CTRL_AEAD_TLS1_AAD          0x16
# define         EVP_CTRL_BLOCK_PADDING_MODE             0x21
# define         EVP_CTRL_CCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_CCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_CCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_CCM_SET_L              0x14
# define         EVP_CTRL_CCM_SET_MSGLEN         0x15
# define         EVP_CTRL_CCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_COPY                   0x8
# define         EVP_CTRL_GCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_GCM_IV_GEN             0x13
# define         EVP_CTRL_GCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_GCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_GCM_SET_IV_INV         0x18
# define         EVP_CTRL_GCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_GET_IV                         0x26
# define         EVP_CTRL_GET_IVLEN                      0x25
# define         EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         EVP_CTRL_GET_RC5_ROUNDS         0x4
# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_KEY_MESH                       0x20
# define         EVP_CTRL_PBE_PRF_NID            0x7
# define         EVP_CTRL_RAND_KEY               0x6
# define         EVP_CTRL_SBOX_USED                      0x1f
# define         EVP_CTRL_SET_KEY_LENGTH         0x1
# define         EVP_CTRL_SET_PIPELINE_INPUT_BUFS        0x23
# define         EVP_CTRL_SET_PIPELINE_INPUT_LENS        0x24
# define         EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS       0x22
# define         EVP_CTRL_SET_RC2_KEY_BITS       0x3
# define         EVP_CTRL_SET_RC5_ROUNDS         0x5
# define         EVP_CTRL_SET_SBOX                       0x1e
# define         EVP_CTRL_SET_SPEED                      0x27
# define         EVP_CTRL_SSL3_MASTER_SECRET             0x1d
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_AAD  0x19
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT      0x1b
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT      0x1a
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE  0x1c
# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)
# define EVP_DigestSignUpdate(a,b,c)     EVP_DigestUpdate(a,b,c)
# define EVP_DigestVerifyUpdate(a,b,c)   EVP_DigestUpdate(a,b,c)
# define EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
# define EVP_GCM_TLS_EXPLICIT_IV_LEN                     8
# define EVP_GCM_TLS_FIXED_IV_LEN                        4
# define EVP_GCM_TLS_TAG_LEN                             16
# define EVP_MAX_BLOCK_LENGTH            32
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_MD_SIZE                 64
#  define EVP_MD_CTRL_ALG_CTRL                    0x1000
#  define EVP_MD_CTRL_DIGALGID                    0x1
#  define EVP_MD_CTRL_MICALG                      0x2
#  define EVP_MD_CTRL_XOF_LEN                     0x3
# define EVP_MD_CTX_FLAG_CLEANED         0x0002
# define EVP_MD_CTX_FLAG_FINALISE        0x0200
# define EVP_MD_CTX_FLAG_NON_FIPS_ALLOW  0x0008
# define EVP_MD_CTX_FLAG_NO_INIT         0x0100
# define EVP_MD_CTX_FLAG_ONESHOT         0x0001
# define EVP_MD_CTX_FLAG_PAD_MASK        0xF0
# define EVP_MD_CTX_FLAG_PAD_PKCS1       0x00
# define EVP_MD_CTX_FLAG_PAD_PSS         0x20
# define EVP_MD_CTX_FLAG_PAD_X931        0x10
# define EVP_MD_CTX_FLAG_REUSE           0x0004
# define EVP_MD_CTX_block_size(e)        EVP_MD_block_size(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
# define EVP_MD_CTX_name(e)              EVP_MD_name(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
#  define EVP_MD_FLAG_DIGALGID_ABSENT             0x0008
#  define EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018
#  define EVP_MD_FLAG_DIGALGID_MASK               0x0018
#  define EVP_MD_FLAG_DIGALGID_NULL               0x0000
#  define EVP_MD_FLAG_FIPS        0x0400
#  define EVP_MD_FLAG_ONESHOT     0x0001
#  define EVP_MD_FLAG_XOF         0x0002
# define EVP_MD_nid(e)                   EVP_MD_type(e)
# define EVP_OpenUpdate(a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)
#define EVP_PADDING_ANSI923     3
#define EVP_PADDING_ISO10126    4
#define EVP_PADDING_ISO7816_4   2
#define EVP_PADDING_PKCS7       1
#define EVP_PADDING_ZERO        5
# define EVP_PBE_TYPE_KDF        0x2
# define EVP_PBE_TYPE_OUTER      0x0
# define EVP_PBE_TYPE_PRF        0x1
# define EVP_PKEY_ALG_CTRL               0x1000
# define EVP_PKEY_CMAC   NID_cmac
# define EVP_PKEY_CTRL_CIPHER            12
# define EVP_PKEY_CTRL_CMS_DECRYPT       10
# define EVP_PKEY_CTRL_CMS_ENCRYPT       9
# define EVP_PKEY_CTRL_CMS_SIGN          11
# define EVP_PKEY_CTRL_DIGESTINIT        7
# define EVP_PKEY_CTRL_GET_MD            13
# define EVP_PKEY_CTRL_MD                1
# define EVP_PKEY_CTRL_PEER_KEY          2
# define EVP_PKEY_CTRL_PKCS7_DECRYPT     4
# define EVP_PKEY_CTRL_PKCS7_ENCRYPT     3
# define EVP_PKEY_CTRL_PKCS7_SIGN        5
# define EVP_PKEY_CTRL_SET_DIGEST_SIZE   14
# define EVP_PKEY_CTRL_SET_IV            8
# define EVP_PKEY_CTRL_SET_MAC_KEY       6
# define  EVP_PKEY_CTX_set_mac_key(ctx, key, len)        \
                EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,  \
                                  EVP_PKEY_CTRL_SET_MAC_KEY, len, (void *)(key))
# define EVP_PKEY_DH     NID_dhKeyAgreement
# define EVP_PKEY_DHX    NID_dhpublicnumber
# define EVP_PKEY_DSA    NID_dsa
# define EVP_PKEY_DSA1   NID_dsa_2
# define EVP_PKEY_DSA2   NID_dsaWithSHA
# define EVP_PKEY_DSA3   NID_dsaWithSHA1
# define EVP_PKEY_DSA4   NID_dsaWithSHA1_2
# define EVP_PKEY_EC     NID_X9_62_id_ecPublicKey
# define EVP_PKEY_ED25519 NID_ED25519
# define EVP_PKEY_ED448 NID_ED448
# define EVP_PKEY_FLAG_AUTOARGLEN        2
# define EVP_PKEY_FLAG_SIGCTX_CUSTOM     4
# define EVP_PKEY_HKDF   NID_hkdf
# define EVP_PKEY_HMAC   NID_hmac
# define EVP_PKEY_MO_DECRYPT     0x0008
# define EVP_PKEY_MO_ENCRYPT     0x0004
# define EVP_PKEY_MO_SIGN        0x0001
# define EVP_PKEY_MO_VERIFY      0x0002
# define EVP_PKEY_NONE   NID_undef
# define EVP_PKEY_OP_DECRYPT             (1<<9)
# define EVP_PKEY_OP_DERIVE              (1<<10)
# define EVP_PKEY_OP_ENCRYPT             (1<<8)
# define EVP_PKEY_OP_KEYGEN              (1<<2)
# define EVP_PKEY_OP_PARAMGEN            (1<<1)
# define EVP_PKEY_OP_SIGN                (1<<3)
# define EVP_PKEY_OP_SIGNCTX             (1<<6)
# define EVP_PKEY_OP_TYPE_CRYPT \
        (EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT)
# define EVP_PKEY_OP_TYPE_GEN \
                (EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN)
# define EVP_PKEY_OP_TYPE_NOGEN \
        (EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_DERIVE)
# define EVP_PKEY_OP_TYPE_SIG    \
        (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER \
                | EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX)
# define EVP_PKEY_OP_UNDEFINED           0
# define EVP_PKEY_OP_VERIFY              (1<<4)
# define EVP_PKEY_OP_VERIFYCTX           (1<<7)
# define EVP_PKEY_OP_VERIFYRECOVER       (1<<5)
# define EVP_PKEY_POLY1305 NID_poly1305
# define EVP_PKEY_RSA    NID_rsaEncryption
# define EVP_PKEY_RSA2   NID_rsa
# define EVP_PKEY_RSA_PSS NID_rsassaPss
# define EVP_PKEY_SCRYPT NID_id_scrypt
# define EVP_PKEY_SIPHASH NID_siphash
# define EVP_PKEY_SM2    NID_sm2
# define EVP_PKEY_TLS1_PRF NID_tls1_prf
# define EVP_PKEY_X25519 NID_X25519
# define EVP_PKEY_X448 NID_X448
#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,(dh))
#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (dsa))
#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC,\
                                        (eckey))
#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),\
                                        EVP_PKEY_POLY1305,(polykey))
#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                        (rsa))
#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),\
                                        EVP_PKEY_SIPHASH,(shkey))
# define EVP_PKS_DSA     0x0200
# define EVP_PKS_EC      0x0400
# define EVP_PKS_RSA     0x0100
# define EVP_PKT_ENC     0x0020
# define EVP_PKT_EXCH    0x0040
# define EVP_PKT_SIGN    0x0010
# define EVP_PK_DH       0x0004
# define EVP_PK_DSA      0x0002
# define EVP_PK_EC       0x0008
# define EVP_PK_RSA      0x0001
# define EVP_SealUpdate(a,b,c,d,e)       EVP_EncryptUpdate(a,b,c,d,e)
# define EVP_SignInit(a,b)               EVP_DigestInit(a,b)
# define EVP_SignInit_ex(a,b,c)          EVP_DigestInit_ex(a,b,c)
# define EVP_SignUpdate(a,b,c)           EVP_DigestUpdate(a,b,c)
# define EVP_VerifyInit(a,b)             EVP_DigestInit(a,b)
# define EVP_VerifyInit_ex(a,b,c)        EVP_DigestInit_ex(a,b,c)
# define EVP_VerifyUpdate(a,b,c)         EVP_DigestUpdate(a,b,c)
# define EVP_add_cipher_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))
# define EVP_add_digest_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))
# define EVP_aes_128_cfb EVP_aes_128_cfb128
# define EVP_aes_192_cfb EVP_aes_192_cfb128
# define EVP_aes_256_cfb EVP_aes_256_cfb128
#  define EVP_aria_128_cfb EVP_aria_128_cfb128
#  define EVP_aria_192_cfb EVP_aria_192_cfb128
#  define EVP_aria_256_cfb EVP_aria_256_cfb128
#  define EVP_bf_cfb EVP_bf_cfb64
#  define EVP_camellia_128_cfb EVP_camellia_128_cfb128
#  define EVP_camellia_192_cfb EVP_camellia_192_cfb128
#  define EVP_camellia_256_cfb EVP_camellia_256_cfb128
#  define EVP_cast5_cfb EVP_cast5_cfb64
#  define EVP_cleanup() while(0) continue
# define EVP_delete_cipher_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
# define EVP_delete_digest_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);
#  define EVP_des_cfb EVP_des_cfb64
#  define EVP_des_ede3_cfb EVP_des_ede3_cfb64
#  define EVP_des_ede_cfb EVP_des_ede_cfb64
# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))
# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))
#  define EVP_idea_cfb EVP_idea_cfb64
#  define EVP_rc2_cfb EVP_rc2_cfb64
#  define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
#  define EVP_seed_cfb EVP_seed_cfb128
#  define EVP_sm4_cfb EVP_sm4_cfb128
# define HEADER_ENVELOPE_H
#  define OPENSSL_add_all_algorithms_conf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | OPENSSL_INIT_LOAD_CONFIG, NULL)
#  define OPENSSL_add_all_algorithms_noconf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)
#   define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_conf()
#  define OpenSSL_add_all_ciphers() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)
#  define OpenSSL_add_all_digests() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)
# define PKCS5_DEFAULT_ITER              2048
# define PKCS5_SALT_LEN                  8
# define BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG        75
# define BIO_CTRL_SET_KTLS                      72
# define BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG     74
# define BIO_FLAGS_KTLS_RX          0x2000
# define BIO_FLAGS_KTLS_TX          0x800
# define BIO_FLAGS_KTLS_TX_CTRL_MSG 0x1000
#  define BIO_clear_ktls_ctrl_msg(b) \
     BIO_ctrl(b, BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG, 0, NULL)
# define BIO_clear_ktls_ctrl_msg_flag(b) \
    BIO_clear_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
#  define BIO_set_ktls(b, keyblob, is_tx)   \
     BIO_ctrl(b, BIO_CTRL_SET_KTLS, is_tx, keyblob)
#  define BIO_set_ktls_ctrl_msg(b, record_type)   \
     BIO_ctrl(b, BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG, record_type, NULL)
# define BIO_set_ktls_ctrl_msg_flag(b) \
    BIO_set_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
# define BIO_set_ktls_flag(b, is_tx) \
    BIO_set_flags(b, (is_tx) ? BIO_FLAGS_KTLS_TX : BIO_FLAGS_KTLS_RX)
# define BIO_should_ktls_ctrl_msg_flag(b) \
    BIO_test_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
# define BIO_should_ktls_flag(b, is_tx) \
    BIO_test_flags(b, (is_tx) ? BIO_FLAGS_KTLS_TX : BIO_FLAGS_KTLS_RX)
# define HEADER_INTERNAL_BIO_H
#  define BIO_BIND_NORMAL                 0
#  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR
#  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR
# define BIO_CB_CTRL     0x06
# define BIO_CB_FREE     0x01
# define BIO_CB_GETS     0x05
# define BIO_CB_PUTS     0x04
# define BIO_CB_READ     0x02
# define BIO_CB_RETURN   0x80
# define BIO_CB_WRITE    0x03
# define BIO_CB_return(a) ((a)|BIO_CB_RETURN)
# define BIO_CLOSE               0x01
# define BIO_CTRL_DGRAM_CONNECT       31
# define BIO_CTRL_DGRAM_GET_FALLBACK_MTU   47
# define BIO_CTRL_DGRAM_GET_MTU            41
# define BIO_CTRL_DGRAM_GET_MTU_OVERHEAD   49
# define BIO_CTRL_DGRAM_GET_PEER           46
# define BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34
# define BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37
# define BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36
# define BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38
# define BIO_CTRL_DGRAM_MTU_DISCOVER       39
# define BIO_CTRL_DGRAM_MTU_EXCEEDED       43
# define BIO_CTRL_DGRAM_QUERY_MTU          40
#  define BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY                51
#  define BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD               53
#  define BIO_CTRL_DGRAM_SCTP_GET_PRINFO                  64
#  define BIO_CTRL_DGRAM_SCTP_GET_RCVINFO         62
#  define BIO_CTRL_DGRAM_SCTP_GET_SNDINFO         60
# define BIO_CTRL_DGRAM_SCTP_MSG_WAITING        78
#  define BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY               52
#  define BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN               70
#  define BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE    50
#  define BIO_CTRL_DGRAM_SCTP_SET_PRINFO                  65
#  define BIO_CTRL_DGRAM_SCTP_SET_RCVINFO         63
#  define BIO_CTRL_DGRAM_SCTP_SET_SNDINFO         61
# define BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY       77
# define BIO_CTRL_DGRAM_SET_CONNECTED 32
# define BIO_CTRL_DGRAM_SET_DONT_FRAG      48
# define BIO_CTRL_DGRAM_SET_MTU            42
# define BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   45
# define BIO_CTRL_DGRAM_SET_PEEK_MODE      71
# define BIO_CTRL_DGRAM_SET_PEER           44
# define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33
# define BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35
# define BIO_CTRL_DUP            12
# define BIO_CTRL_EOF            2
# define BIO_CTRL_FLUSH          11
# define BIO_CTRL_GET            5
# define BIO_CTRL_GET_CALLBACK   15
# define BIO_CTRL_GET_CLOSE      8
# define BIO_CTRL_GET_KTLS_RECV                 76
# define BIO_CTRL_GET_KTLS_SEND                 73
# define BIO_CTRL_INFO           3
# define BIO_CTRL_PEEK           29
# define BIO_CTRL_PENDING        10
# define BIO_CTRL_POP            7
# define BIO_CTRL_PUSH           6
# define BIO_CTRL_RESET          1
# define BIO_CTRL_SET            4
# define BIO_CTRL_SET_CALLBACK   14
# define BIO_CTRL_SET_CLOSE      9
# define BIO_CTRL_SET_FILENAME   30
# define BIO_CTRL_WPENDING       13
# define BIO_C_DESTROY_BIO_PAIR                  139
# define BIO_C_DO_STATE_MACHINE                  101
# define BIO_C_FILE_SEEK                         128
# define BIO_C_FILE_TELL                         133
# define BIO_C_GET_ACCEPT                        124
# define BIO_C_GET_BIND_MODE                     132
# define BIO_C_GET_BUFF_NUM_LINES                116
# define BIO_C_GET_BUF_MEM_PTR                   115
# define BIO_C_GET_CIPHER_CTX                    129
# define BIO_C_GET_CIPHER_STATUS                 113
# define BIO_C_GET_CONNECT                       123
# define BIO_C_GET_EX_ARG                        154
# define BIO_C_GET_FD                            105
# define BIO_C_GET_FILE_PTR                      107
# define BIO_C_GET_MD                            112
# define BIO_C_GET_MD_CTX                        120
# define BIO_C_GET_PREFIX                        150
# define BIO_C_GET_READ_REQUEST                  141
# define BIO_C_GET_SOCKS                         134
# define BIO_C_GET_SSL                           110
# define BIO_C_GET_SSL_NUM_RENEGOTIATES          126
# define BIO_C_GET_SUFFIX                        152
# define BIO_C_GET_WRITE_BUF_SIZE                137
# define BIO_C_GET_WRITE_GUARANTEE               140
# define BIO_C_MAKE_BIO_PAIR                     138
# define BIO_C_NREAD                             144
# define BIO_C_NREAD0                            143
# define BIO_C_NWRITE                            146
# define BIO_C_NWRITE0                           145
# define BIO_C_RESET_READ_REQUEST                147
# define BIO_C_SET_ACCEPT                        118
# define BIO_C_SET_BIND_MODE                     131
# define BIO_C_SET_BUFF_READ_DATA                122
# define BIO_C_SET_BUFF_SIZE                     117
# define BIO_C_SET_BUF_MEM                       114
# define BIO_C_SET_BUF_MEM_EOF_RETURN            130
# define BIO_C_SET_CONNECT                       100
# define BIO_C_SET_CONNECT_MODE                  155
# define BIO_C_SET_EX_ARG                        153
# define BIO_C_SET_FD                            104
# define BIO_C_SET_FILENAME                      108
# define BIO_C_SET_FILE_PTR                      106
# define BIO_C_SET_MD                            111
# define BIO_C_SET_MD_CTX                        148
# define BIO_C_SET_NBIO                          102
# define BIO_C_SET_PREFIX                        149
# define BIO_C_SET_SOCKS                         135
# define BIO_C_SET_SSL                           109
# define BIO_C_SET_SSL_RENEGOTIATE_BYTES         125
# define BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT       127
# define BIO_C_SET_SUFFIX                        151
# define BIO_C_SET_WRITE_BUF_SIZE                136
# define BIO_C_SHUTDOWN_WR                       142
# define BIO_C_SSL_MODE                          119
#  define BIO_FAMILY_IPANY                        256
#  define BIO_FAMILY_IPV4                         4
#  define BIO_FAMILY_IPV6                         6
# define BIO_FLAGS_BASE64_NO_NL  0x100
# define BIO_FLAGS_IO_SPECIAL    0x04
# define BIO_FLAGS_MEM_RDONLY    0x200
# define BIO_FLAGS_NONCLEAR_RST  0x400
# define BIO_FLAGS_READ          0x01
# define BIO_FLAGS_RWS (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
# define BIO_FLAGS_SHOULD_RETRY  0x08
#  define BIO_FLAGS_UPLINK       0
# define BIO_FLAGS_WRITE         0x02
# define BIO_FP_APPEND           0x08
# define BIO_FP_READ             0x02
# define BIO_FP_TEXT             0x10
# define BIO_FP_WRITE            0x04
# define BIO_NOCLOSE             0x00
# define BIO_RR_ACCEPT                   0x03
# define BIO_RR_CONNECT                  0x02
# define BIO_RR_SSL_X509_LOOKUP          0x01
#  define BIO_SOCK_KEEPALIVE    0x04
#  define BIO_SOCK_NODELAY      0x10
#  define BIO_SOCK_NONBLOCK     0x08
#  define BIO_SOCK_REUSEADDR    0x01
#  define BIO_SOCK_V6_ONLY      0x02
# define BIO_TYPE_ACCEPT         (13|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_ASN1           (22|BIO_TYPE_FILTER)
# define BIO_TYPE_BASE64         (11|BIO_TYPE_FILTER)
# define BIO_TYPE_BIO            (19|BIO_TYPE_SOURCE_SINK)
# define BIO_TYPE_BUFFER         ( 9|BIO_TYPE_FILTER)
# define BIO_TYPE_CIPHER         (10|BIO_TYPE_FILTER)
# define BIO_TYPE_COMP           (23|BIO_TYPE_FILTER)
# define BIO_TYPE_CONNECT        (12|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_DESCRIPTOR     0x0100 
# define BIO_TYPE_DGRAM          (21|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
#  define BIO_TYPE_DGRAM_SCTP    (24|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_FD             ( 4|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_FILE           ( 2|BIO_TYPE_SOURCE_SINK)
# define BIO_TYPE_FILTER         0x0200
# define BIO_TYPE_LINEBUFFER     (20|BIO_TYPE_FILTER)
# define BIO_TYPE_MD             ( 8|BIO_TYPE_FILTER)
# define BIO_TYPE_MEM            ( 1|BIO_TYPE_SOURCE_SINK)
# define BIO_TYPE_NBIO_TEST      (16|BIO_TYPE_FILTER)
# define BIO_TYPE_NONE             0
# define BIO_TYPE_NULL           ( 6|BIO_TYPE_SOURCE_SINK)
# define BIO_TYPE_NULL_FILTER    (17|BIO_TYPE_FILTER)
# define BIO_TYPE_SOCKET         ( 5|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_SOURCE_SINK    0x0400
# define BIO_TYPE_SSL            ( 7|BIO_TYPE_FILTER)
#define BIO_TYPE_START           128
# define BIO_append_filename(b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_APPEND,name)
# define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)
# define BIO_buffer_peek(b,s,l) BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))
# define BIO_cb_post(a)  ((a)&BIO_CB_RETURN)
# define BIO_cb_pre(a)   (!((a)&BIO_CB_RETURN))
# define BIO_clear_retry_flags(b) \
                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
# define BIO_ctrl_dgram_connect(b,peer)  \
                     (int)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char *)(peer))
# define BIO_ctrl_set_connected(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char *)(peer))
# define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)
# define BIO_dgram_get_mtu_overhead(b) \
         (unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, NULL)
# define BIO_dgram_get_peer(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)(peer))
# define BIO_dgram_recv_timedout(b) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)
# define BIO_dgram_send_timedout(b) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, NULL)
# define BIO_dgram_set_peer(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char *)(peer))
#  define BIO_do_accept(b)        BIO_do_handshake(b)
#  define BIO_do_connect(b)       BIO_do_handshake(b)
# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)
# define BIO_dup_state(b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char *)(ret))
# define BIO_eof(b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)
# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
#  define BIO_get_accept_ip_family(b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)
#  define BIO_get_accept_name(b)        ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))
#  define BIO_get_accept_port(b)        ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))
# define BIO_get_app_data(s)             BIO_get_ex_data(s,0)
#  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)
# define BIO_get_buffer_num_lines(b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)
# define BIO_get_close(b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)
#  define BIO_get_conn_address(b)       ((const BIO_ADDR *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))
#  define BIO_get_conn_hostname(b)      ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))
#  define BIO_get_conn_ip_family(b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)
#  define BIO_get_conn_port(b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))
#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)
# define BIO_get_fd(b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char *)(c))
# define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))
# define BIO_get_fp(b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char *)(fpp))
# define BIO_get_info_callback(b,cbp) (int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0, \
                                                   cbp)
#  define BIO_get_ktls_recv(b)         \
     (BIO_method_type(b) == BIO_TYPE_SOCKET \
      && BIO_ctrl(b, BIO_CTRL_GET_KTLS_RECV, 0, NULL))
#  define BIO_get_ktls_send(b)         \
     (BIO_method_type(b) == BIO_TYPE_SOCKET \
      && BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, NULL))
# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)(pp))
# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0, \
                                          (char *)(pp))
# define BIO_get_num_renegotiates(b) \
        BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,NULL)
#  define BIO_get_peer_name(b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))
#  define BIO_get_peer_port(b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))
# define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)
# define BIO_get_retry_flags(b) \
                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
# define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)(sslp))
# define BIO_get_write_buf_size(b,size) (size_t)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)
# define BIO_get_write_guarantee(b) (int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)
# define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)
# define BIO_pending(b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
#  define BIO_read_filename(b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_READ,(char *)(name))
# define BIO_reset(b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)
# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)
# define BIO_rw_filename(b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)
# define BIO_seek(b,ofs) (int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)
#  define BIO_set_accept_bios(b,bio)    BIO_ctrl(b,BIO_C_SET_ACCEPT,3, \
                                                 (char *)(bio))
#  define BIO_set_accept_ip_family(b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)
#  define BIO_set_accept_name(b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0, \
                                                 (char *)(name))
#  define BIO_set_accept_port(b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1, \
                                                 (char *)(port))
# define BIO_set_app_data(s,arg)         BIO_set_ex_data(s,0,arg)
#  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)
# define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)
# define BIO_set_buffer_size(b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)
# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
#  define BIO_set_conn_address(b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2, \
                                                 (char *)(addr))
#  define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0, \
                                                 (char *)(name))
#  define BIO_set_conn_ip_family(b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)
#  define BIO_set_conn_mode(b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)
#  define BIO_set_conn_port(b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1, \
                                                 (char *)(port))
# define BIO_set_fd(b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)
# define BIO_set_fp(b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char *)(fp))
# define BIO_set_info_callback(b,cb) (int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)
# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char *)(bm))
# define BIO_set_mem_eof_return(b,v) \
                                BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,NULL)
# define BIO_set_nbio(b,n)             BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)
#  define BIO_set_nbio_accept(b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(void *)"a":NULL)
# define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)
# define BIO_set_retry_read(b) \
                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_special(b) \
                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_write(b) \
                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_ssl(b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char *)(ssl))
# define BIO_set_ssl_mode(b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)
# define BIO_set_ssl_renegotiate_bytes(b,num) \
        BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,NULL)
# define BIO_set_ssl_renegotiate_timeout(b,seconds) \
        BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,NULL)
# define BIO_set_write_buf_size(b,size) (int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)
# define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)
# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)
# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)
# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)
# define BIO_shutdown_wr(b) (int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)
#  define BIO_sock_cleanup() while(0) continue
# define BIO_tell(b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)
# define BIO_wpending(b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)
# define BIO_write_filename(b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_WRITE,name)
# define HEADER_BIO_H
#   define ossl_bio__attr__ __attribute__
#    define ossl_bio__printf__ __gnu_printf__
# define HEADER_RAND_INT_H
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
