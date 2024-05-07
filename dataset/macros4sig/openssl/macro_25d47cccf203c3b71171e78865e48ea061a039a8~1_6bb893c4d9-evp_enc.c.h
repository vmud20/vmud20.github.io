
#include<stdio.h>
#include<limits.h>
#include<assert.h>
#define EVP_CTRL_RET_UNSUPPORTED -1
#define M_check_autoarg(ctx, arg, arglen, err) \
    if (ctx->pmeth->flags & EVP_PKEY_FLAG_AUTOARGLEN) {           \
        size_t pksize = (size_t)EVP_PKEY_get_size(ctx->pkey);         \
                                                                  \
        if (pksize == 0) {                                        \
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);  \
            return 0;                                             \
        }                                                         \
        if (arg == NULL) {                                        \
            *arglen = pksize;                                     \
            return 1;                                             \
        }                                                         \
        if (*arglen < pksize) {                                   \
            ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL);  \
            return 0;                                             \
        }                                                         \
    }
# define OPENSSL_CORE_H
# define OSSL_PARAM_INTEGER              1
# define OSSL_PARAM_OCTET_PTR            7
# define OSSL_PARAM_OCTET_STRING         5
# define OSSL_PARAM_REAL                 3
# define OSSL_PARAM_UNSIGNED_INTEGER     2
# define OSSL_PARAM_UTF8_PTR             6
# define OSSL_PARAM_UTF8_STRING          4
#  define ASN1_BIT_STRING         ASN1_STRING
#  define ASN1_BMPSTRING          ASN1_STRING
#  define ASN1_BOOLEAN            int
#  define ASN1_ENUMERATED         ASN1_STRING
#  define ASN1_GENERALIZEDTIME    ASN1_STRING
#  define ASN1_GENERALSTRING      ASN1_STRING
#  define ASN1_IA5STRING          ASN1_STRING
#  define ASN1_INTEGER            ASN1_STRING
#  define ASN1_NULL               int
#  define ASN1_OCTET_STRING       ASN1_STRING
#  define ASN1_PRINTABLESTRING    ASN1_STRING
#  define ASN1_T61STRING          ASN1_STRING
#  define ASN1_TIME               ASN1_STRING
#  define ASN1_UNIVERSALSTRING    ASN1_STRING
#  define ASN1_UTCTIME            ASN1_STRING
#  define ASN1_UTF8STRING         ASN1_STRING
#  define ASN1_VISIBLESTRING      ASN1_STRING
# define OPENSSL_TYPES_H
# define WINCRYPT_USE_SYMBOL_PREFIX
# define CRYPTO_DOWN_REF(val, ret, lock) CRYPTO_atomic_add(val, -1, ret, lock)
# define CRYPTO_UP_REF(val, ret, lock) CRYPTO_atomic_add(val, 1, ret, lock)
#   define HAVE_ATOMICS 1
#   define HAVE_C11_ATOMICS
# define OSSL_INTERNAL_REFCOUNT_H
#  define REF_ASSERT_ISNT(test) \
    (void)((test) ? (OPENSSL_die("refcount error", "__FILE__", "__LINE__"), 1) : 0)
# define REF_PRINT_COUNT(text, object) \
    REF_PRINT_EX(text, object->references, (void *)object)
# define REF_PRINT_EX(text, count, object) \
    OSSL_TRACE3(REF_COUNT, "%p:%4d:%s\n", (object), (count), (text));
#     define _ARM_BARRIER_ISH _ARM64_BARRIER_ISH
#      define _InterlockedExchangeAdd InterlockedExchangeAdd
# define OPENSSL_CORE_NUMBERS_H
#define OSSL_CORE_MAKE_FUNC(type,name,args)                             \
    typedef type (OSSL_FUNC_##name##_fn)args;                           \
    static ossl_unused ossl_inline \
    OSSL_FUNC_##name##_fn *OSSL_FUNC_##name(const OSSL_DISPATCH *opf)   \
    {                                                                   \
        return (OSSL_FUNC_##name##_fn *)opf->function;                  \
    }
# define OSSL_FUNC_ASYM_CIPHER_DECRYPT                 5
# define OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT            4
# define OSSL_FUNC_ASYM_CIPHER_DUPCTX                  7
# define OSSL_FUNC_ASYM_CIPHER_ENCRYPT                 3
# define OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT            2
# define OSSL_FUNC_ASYM_CIPHER_FREECTX                 6
# define OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS     9
# define OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS          8
# define OSSL_FUNC_ASYM_CIPHER_NEWCTX                  1
# define OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS    11
# define OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS         10
#define OSSL_FUNC_BIO_CTRL                    50
#define OSSL_FUNC_BIO_FREE                    45
#define OSSL_FUNC_BIO_GETS                    49
#define OSSL_FUNC_BIO_NEW_FILE                40
#define OSSL_FUNC_BIO_NEW_MEMBUF              41
#define OSSL_FUNC_BIO_PUTS                    48
#define OSSL_FUNC_BIO_READ_EX                 42
#define OSSL_FUNC_BIO_UP_REF                  44
#define OSSL_FUNC_BIO_VPRINTF                 46
#define OSSL_FUNC_BIO_VSNPRINTF               47
#define OSSL_FUNC_BIO_WRITE_EX                43
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
#define OSSL_FUNC_CLEANUP_ENTROPY            102
#define OSSL_FUNC_CLEANUP_NONCE              104
# define OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK  9
# define OSSL_FUNC_CORE_GETTABLE_PARAMS        1
# define OSSL_FUNC_CORE_GET_LIBCTX             4
# define OSSL_FUNC_CORE_GET_PARAMS             2
# define OSSL_FUNC_CORE_NEW_ERROR              5
#define OSSL_FUNC_CORE_OBJ_ADD_SIGID          11
#define OSSL_FUNC_CORE_OBJ_CREATE             12
# define OSSL_FUNC_CORE_POP_ERROR_TO_MARK     10
# define OSSL_FUNC_CORE_SET_ERROR_DEBUG        6
# define OSSL_FUNC_CORE_SET_ERROR_MARK         8
# define OSSL_FUNC_CORE_THREAD_START           3
# define OSSL_FUNC_CORE_VSET_ERROR             7
#define OSSL_FUNC_CRYPTO_CLEAR_FREE           23
#define OSSL_FUNC_CRYPTO_CLEAR_REALLOC        25
#define OSSL_FUNC_CRYPTO_FREE                 22
#define OSSL_FUNC_CRYPTO_MALLOC               20
#define OSSL_FUNC_CRYPTO_REALLOC              24
#define OSSL_FUNC_CRYPTO_SECURE_ALLOCATED     30
#define OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE    29
#define OSSL_FUNC_CRYPTO_SECURE_FREE          28
#define OSSL_FUNC_CRYPTO_SECURE_MALLOC        26
#define OSSL_FUNC_CRYPTO_SECURE_ZALLOC        27
#define OSSL_FUNC_CRYPTO_ZALLOC               21
# define OSSL_FUNC_DECODER_DECODE                     11
# define OSSL_FUNC_DECODER_DOES_SELECTION             10
# define OSSL_FUNC_DECODER_EXPORT_OBJECT              20
# define OSSL_FUNC_DECODER_FREECTX                     2
# define OSSL_FUNC_DECODER_GETTABLE_PARAMS             4
# define OSSL_FUNC_DECODER_GET_PARAMS                  3
# define OSSL_FUNC_DECODER_NEWCTX                      1
# define OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS         6
# define OSSL_FUNC_DECODER_SET_CTX_PARAMS              5
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
# define OSSL_FUNC_ENCODER_DOES_SELECTION             10
# define OSSL_FUNC_ENCODER_ENCODE                     11
# define OSSL_FUNC_ENCODER_FREECTX                     2
# define OSSL_FUNC_ENCODER_FREE_OBJECT                21
# define OSSL_FUNC_ENCODER_GETTABLE_PARAMS             4
# define OSSL_FUNC_ENCODER_GET_PARAMS                  3
# define OSSL_FUNC_ENCODER_IMPORT_OBJECT              20
# define OSSL_FUNC_ENCODER_NEWCTX                      1
# define OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS         6
# define OSSL_FUNC_ENCODER_SET_CTX_PARAMS              5
#define OSSL_FUNC_GET_ENTROPY                101
#define OSSL_FUNC_GET_NONCE                  103
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
# define OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT  13
# define OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT  12
# define OSSL_FUNC_KEM_DECAPSULATE             5
# define OSSL_FUNC_KEM_DECAPSULATE_INIT        4
# define OSSL_FUNC_KEM_DUPCTX                  7
# define OSSL_FUNC_KEM_ENCAPSULATE             3
# define OSSL_FUNC_KEM_ENCAPSULATE_INIT        2
# define OSSL_FUNC_KEM_FREECTX                 6
# define OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS     9
# define OSSL_FUNC_KEM_GET_CTX_PARAMS          8
# define OSSL_FUNC_KEM_NEWCTX                  1
# define OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS    11
# define OSSL_FUNC_KEM_SET_CTX_PARAMS         10
# define OSSL_FUNC_KEYEXCH_DERIVE                      3
# define OSSL_FUNC_KEYEXCH_DUPCTX                      6
# define OSSL_FUNC_KEYEXCH_FREECTX                     5
# define OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS        10
# define OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS              9
# define OSSL_FUNC_KEYEXCH_INIT                        2
# define OSSL_FUNC_KEYEXCH_NEWCTX                      1
# define OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS         8
# define OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS              7
# define OSSL_FUNC_KEYEXCH_SET_PEER                    4
# define OSSL_FUNC_KEYMGMT_DUP                        44
# define OSSL_FUNC_KEYMGMT_EXPORT                     42
# define OSSL_FUNC_KEYMGMT_EXPORT_TYPES               43
# define OSSL_FUNC_KEYMGMT_FREE                       10
# define OSSL_FUNC_KEYMGMT_GEN                         6
# define OSSL_FUNC_KEYMGMT_GEN_CLEANUP                 7
# define OSSL_FUNC_KEYMGMT_GEN_INIT                    2
# define OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS         5
# define OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS              4
# define OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE            3
#define OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS             12
#define OSSL_FUNC_KEYMGMT_GET_PARAMS                  11
# define OSSL_FUNC_KEYMGMT_HAS                        21
# define OSSL_FUNC_KEYMGMT_IMPORT                     40
# define OSSL_FUNC_KEYMGMT_IMPORT_TYPES               41
# define OSSL_FUNC_KEYMGMT_LOAD                        8
# define OSSL_FUNC_KEYMGMT_MATCH                      23
# define OSSL_FUNC_KEYMGMT_NEW                         1
# define OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME       20
#define OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS             14
#define OSSL_FUNC_KEYMGMT_SET_PARAMS                  13
# define OSSL_FUNC_KEYMGMT_VALIDATE                   22
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
#define OSSL_FUNC_OPENSSL_CLEANSE             31
#define OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB 106
#define OSSL_FUNC_PROVIDER_FREE                111
#define OSSL_FUNC_PROVIDER_GET0_DISPATCH       109
#define OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX   108
# define OSSL_FUNC_PROVIDER_GETTABLE_PARAMS    1025
# define OSSL_FUNC_PROVIDER_GET_CAPABILITIES   1030
# define OSSL_FUNC_PROVIDER_GET_PARAMS         1026
# define OSSL_FUNC_PROVIDER_GET_REASON_STRINGS 1029
#define OSSL_FUNC_PROVIDER_NAME                107
# define OSSL_FUNC_PROVIDER_QUERY_OPERATION    1027
#define OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB   105
# define OSSL_FUNC_PROVIDER_SELF_TEST          1031
# define OSSL_FUNC_PROVIDER_TEARDOWN           1024
# define OSSL_FUNC_PROVIDER_UNQUERY_OPERATION  1028
#define OSSL_FUNC_PROVIDER_UP_REF              110
# define OSSL_FUNC_RAND_CLEAR_SEED                   19
# define OSSL_FUNC_RAND_ENABLE_LOCKING                8
# define OSSL_FUNC_RAND_FREECTX                       2
# define OSSL_FUNC_RAND_GENERATE                      5
# define OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS          12
# define OSSL_FUNC_RAND_GETTABLE_PARAMS              11
# define OSSL_FUNC_RAND_GET_CTX_PARAMS               15
# define OSSL_FUNC_RAND_GET_PARAMS                   14
# define OSSL_FUNC_RAND_GET_SEED                     18
# define OSSL_FUNC_RAND_INSTANTIATE                   3
# define OSSL_FUNC_RAND_LOCK                          9
# define OSSL_FUNC_RAND_NEWCTX                        1
# define OSSL_FUNC_RAND_NONCE                         7
# define OSSL_FUNC_RAND_RESEED                        6
# define OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS          13
# define OSSL_FUNC_RAND_SET_CTX_PARAMS               16
# define OSSL_FUNC_RAND_UNINSTANTIATE                 4
# define OSSL_FUNC_RAND_UNLOCK                       10
# define OSSL_FUNC_RAND_VERIFY_ZEROIZATION           17
#define OSSL_FUNC_SELF_TEST_CB               100
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN            11
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL      10
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT        8
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE      9
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY          15
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL    14
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT     12
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE   13
# define OSSL_FUNC_SIGNATURE_DUPCTX                 17
# define OSSL_FUNC_SIGNATURE_FREECTX                16
# define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS 23
# define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS    19
# define OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS      22
# define OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS         18
# define OSSL_FUNC_SIGNATURE_NEWCTX                  1
# define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS 25
# define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS    21
# define OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS      24
# define OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS         20
# define OSSL_FUNC_SIGNATURE_SIGN                    3
# define OSSL_FUNC_SIGNATURE_SIGN_INIT               2
# define OSSL_FUNC_SIGNATURE_VERIFY                  5
# define OSSL_FUNC_SIGNATURE_VERIFY_INIT             4
# define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER          7
# define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT     6
#define OSSL_FUNC_STORE_ATTACH                      2
#define OSSL_FUNC_STORE_CLOSE                       7
#define OSSL_FUNC_STORE_EOF                         6
#define OSSL_FUNC_STORE_EXPORT_OBJECT               8
#define OSSL_FUNC_STORE_LOAD                        5
#define OSSL_FUNC_STORE_OPEN                        1
#define OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS         3
#define OSSL_FUNC_STORE_SET_CTX_PARAMS              4
# define OSSL_KEYMGMT_SELECT_ALL                \
    ( OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )
# define OSSL_KEYMGMT_SELECT_ALL_PARAMETERS     \
    ( OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS     \
      | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
# define OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS      0x04
# define OSSL_KEYMGMT_SELECT_KEYPAIR            \
    ( OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
# define OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS       0x80
# define OSSL_KEYMGMT_SELECT_PRIVATE_KEY            0x01
# define OSSL_KEYMGMT_SELECT_PUBLIC_KEY             0x02
# define OSSL_KEYMGMT_VALIDATE_FULL_CHECK              0
# define OSSL_KEYMGMT_VALIDATE_QUICK_CHECK             1
# define OSSL_OP_ASYM_CIPHER                        13
# define OSSL_OP_CIPHER                              2   
# define OSSL_OP_DECODER                            21
# define OSSL_OP_DIGEST                              1
# define OSSL_OP_ENCODER                            20
# define OSSL_OP_KDF                                 4
# define OSSL_OP_KEM                                14
# define OSSL_OP_KEYEXCH                            11
# define OSSL_OP_KEYMGMT                            10
# define OSSL_OP_MAC                                 3
# define OSSL_OP_RAND                                5
# define OSSL_OP_SIGNATURE                          12
# define OSSL_OP_STORE                              22
# define OSSL_OP__HIGHEST                           22
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
        EVP_ORIG_GLOBAL, \
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
        bl = EVP_CIPHER_CTX_get0_cipher(ctx)->block_size;    \
        if (inl < bl) return 1;\
        inl -= bl; \
        for (i=0; i <= inl; i+=bl)
#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
static int cname##_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) \
            {\
            cprefix##_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, ctx->iv, EVP_CIPHER_CTX_is_encrypting(ctx));\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
            }\
        if (inl)\
            cprefix##_cbc_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, ctx->iv, EVP_CIPHER_CTX_is_encrypting(ctx));\
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
        int num = EVP_CIPHER_CTX_get_num(ctx);\
        cprefix##_cfb##cbits##_encrypt(in, out, (long) \
            ((cbits == 1) \
                && !EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) \
                ? chunk*8 : chunk), \
            &EVP_C_DATA(kstruct, ctx)->ksched, ctx->iv,\
            &num, EVP_CIPHER_CTX_is_encrypting(ctx));\
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
            cprefix##_ecb_encrypt(in + i, out + i, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_is_encrypting(ctx)); \
        return 1;\
}
#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched) \
    static int cname##_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) {\
            int num = EVP_CIPHER_CTX_get_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, ctx->iv, &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
        }\
        if (inl) {\
            int num = EVP_CIPHER_CTX_get_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, ctx->iv, &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
        }\
        return 1;\
}
#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))
#define EVP_ENCODE_CTX_NO_NEWLINES          1
#define EVP_ENCODE_CTX_USE_SRP_ALPHABET     2
#define EVP_MAXCHUNK ((size_t)1 << 30)
#define EVP_MD_CTX_FLAG_KEEP_PKEY_CTX   0x0400
#define EVP_ORIG_DYNAMIC    0
#define EVP_ORIG_GLOBAL     1
#define EVP_ORIG_METH       2
#define EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_ENCRYPT \
     || (ctx)->operation == EVP_PKEY_OP_DECRYPT)
#define EVP_PKEY_CTX_IS_DERIVE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_DERIVE)
#define EVP_PKEY_CTX_IS_FROMDATA_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_FROMDATA)
#define EVP_PKEY_CTX_IS_GEN_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_PARAMGEN \
     || (ctx)->operation == EVP_PKEY_OP_KEYGEN)
#define EVP_PKEY_CTX_IS_KEM_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_ENCAPSULATE \
     || (ctx)->operation == EVP_PKEY_OP_DECAPSULATE)
#define EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_SIGN \
     || (ctx)->operation == EVP_PKEY_OP_SIGNCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFY \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYRECOVER)
#define EVP_PKEY_FLAG_DYNAMIC   1
# define EVP_PKEY_STATE_LEGACY          1
# define EVP_PKEY_STATE_PROVIDER        2
# define EVP_PKEY_STATE_UNKNOWN         0
# define EVP_RC4_KEY_SIZE 16
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
# define OSSL_CRYPTO_EVP_H
#  define TLS1_1_VERSION   0x0302
#define evp_pkey_ctx_is_legacy(ctx)                             \
    ((ctx)->keymgmt == NULL)
#define evp_pkey_ctx_is_provided(ctx)                           \
    (!evp_pkey_ctx_is_legacy(ctx))
# define evp_pkey_is_assigned(pk)                               \
    ((pk)->pkey.ptr != NULL || (pk)->keydata != NULL)
#define evp_pkey_is_blank(pk)                                   \
    ((pk)->type == EVP_PKEY_NONE && (pk)->keymgmt == NULL)
#define evp_pkey_is_legacy(pk)                                  \
    ((pk)->type != EVP_PKEY_NONE && (pk)->keymgmt == NULL)
#define evp_pkey_is_provided(pk)                                \
    ((pk)->keymgmt != NULL)
#define evp_pkey_is_typed(pk)                                   \
    ((pk)->type != EVP_PKEY_NONE || (pk)->keymgmt != NULL)
# define OSSL_INTERNAL_SAFE_MATH_H
# define OSSL_SAFE_MATH_ABSS(type_name, type, min) \
    static ossl_inline ossl_unused type safe_abs_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        if (a != min)                                                        \
            return a < 0 ? -a : a;                                           \
        *err |= 1;                                                           \
        return min;                                                          \
    }
# define OSSL_SAFE_MATH_ABSU(type_name, type) \
    static ossl_inline ossl_unused type safe_abs_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        return a;                                                            \
    }
#  define OSSL_SAFE_MATH_ADDS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_add_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }
#  define OSSL_SAFE_MATH_ADDU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_add_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a + b;                                                            \
    }
# define OSSL_SAFE_MATH_DIVS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_div_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return a < 0 ? min : max;                                        \
        }                                                                    \
        if (b == -1 && a == min) {                                           \
            *err |= 1;                                                       \
            return max;                                                      \
        }                                                                    \
        return a / b;                                                        \
    }
# define OSSL_SAFE_MATH_DIVU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_div_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b != 0)                                                          \
            return a / b;                                                    \
        *err |= 1;                                                           \
        return max;                                                        \
    }
#define OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type, max) \
    static ossl_inline ossl_unused type safe_div_round_up_ ## type_name      \
        (type a, type b, int *errp)                                          \
    {                                                                        \
        type x;                                                              \
        int *err, err_local = 0;                                             \
                                                                             \
                                  \
        err = errp != NULL ? errp : &err_local;                              \
                                               \
        if (b > 0 && a > 0) {                                                \
                                      \
            if (a < max - b)                                                 \
                return (a + b - 1) / b;                                      \
            return a / b + (a % b != 0);                                     \
        }                                                                    \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 ? 0 : max;                                         \
        }                                                                    \
        if (a == 0)                                                          \
            return 0;                                                        \
                  \
        x = safe_mod_ ## type_name(a, b, err);                               \
        return safe_add_ ## type_name(safe_div_ ## type_name(a, b, err),     \
                                      x != 0, err);                          \
    }
# define OSSL_SAFE_MATH_MAXS(type) (~OSSL_SAFE_MATH_MINS(type))
# define OSSL_SAFE_MATH_MAXU(type) (~(type)0)
# define OSSL_SAFE_MATH_MINS(type) ((type)1 << (sizeof(type) * 8 - 1))
# define OSSL_SAFE_MATH_MODS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_mod_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return 0;                                                        \
        }                                                                    \
        if (b == -1 && a == min) {                                           \
            *err |= 1;                                                       \
            return max;                                                      \
        }                                                                    \
        return a % b;                                                        \
    }
# define OSSL_SAFE_MATH_MODU(type_name, type) \
    static ossl_inline ossl_unused type safe_mod_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b != 0)                                                          \
            return a % b;                                                    \
        *err |= 1;                                                           \
        return 0;                                                            \
    }
# define OSSL_SAFE_MATH_MULDIVS(type_name, type, max) \
    static ossl_inline ossl_unused type safe_muldiv_ ## type_name(type a,    \
                                                                  type b,    \
                                                                  type c,    \
                                                                  int *err)  \
    {                                                                        \
        int e2 = 0;                                                          \
        type q, r, x, y;                                                     \
                                                                             \
        if (c == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 || b == 0 ? 0 : max;                               \
        }                                                                    \
        x = safe_mul_ ## type_name(a, b, &e2);                               \
        if (!e2)                                                             \
            return safe_div_ ## type_name(x, c, err);                        \
        if (b > a) {                                                         \
            x = b;                                                           \
            b = a;                                                           \
            a = x;                                                           \
        }                                                                    \
        q = safe_div_ ## type_name(a, c, err);                               \
        r = safe_mod_ ## type_name(a, c, err);                               \
        x = safe_mul_ ## type_name(r, b, err);                               \
        y = safe_mul_ ## type_name(q, b, err);                               \
        q = safe_div_ ## type_name(x, c, err);                               \
        return safe_add_ ## type_name(y, q, err);                            \
    }
# define OSSL_SAFE_MATH_MULDIVU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_muldiv_ ## type_name(type a,    \
                                                                  type b,    \
                                                                  type c,    \
                                                                  int *err)  \
    {                                                                        \
        int e2 = 0;                                                          \
        type x, y;                                                           \
                                                                             \
        if (c == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 || b == 0 ? 0 : max;                               \
        }                                                                    \
        x = safe_mul_ ## type_name(a, b, &e2);                               \
        if (!e2)                                                             \
            return x / c;                                                    \
        if (b > a) {                                                         \
            x = b;                                                           \
            b = a;                                                           \
            a = x;                                                           \
        }                                                                    \
        x = safe_mul_ ## type_name(a % c, b, err);                           \
        y = safe_mul_ ## type_name(a / c, b, err);                           \
        return safe_add_ ## type_name(y, x / c, err);                        \
    }
#  define OSSL_SAFE_MATH_MULS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_mul_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_mul_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return (a < 0) ^ (b < 0) ? min : max;                                \
    }
#  define OSSL_SAFE_MATH_MULU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_mul_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_mul_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a * b;                                                          \
    }
# define OSSL_SAFE_MATH_NEGS(type_name, type, min) \
    static ossl_inline ossl_unused type safe_neg_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        if (a != min)                                                        \
            return -a;                                                       \
        *err |= 1;                                                           \
        return min;                                                          \
    }
# define OSSL_SAFE_MATH_NEGU(type_name, type) \
    static ossl_inline ossl_unused type safe_neg_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        if (a == 0)                                                          \
            return a;                                                        \
        *err |= 1;                                                           \
        return 1 + ~a;                                                       \
    }
# define OSSL_SAFE_MATH_SIGNED(type_name, type)                         \
    OSSL_SAFE_MATH_ADDS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_SUBS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_MULS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_DIVS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_MODS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type,                        \
                                OSSL_SAFE_MATH_MAXS(type))              \
    OSSL_SAFE_MATH_MULDIVS(type_name, type, OSSL_SAFE_MATH_MAXS(type))  \
    OSSL_SAFE_MATH_NEGS(type_name, type, OSSL_SAFE_MATH_MINS(type))     \
    OSSL_SAFE_MATH_ABSS(type_name, type, OSSL_SAFE_MATH_MINS(type))
#  define OSSL_SAFE_MATH_SUBS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_sub_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (!((a < 0) ^ (b < 0))                                             \
                || (b > 0 && a >= min + b)                                   \
                || (b < 0 && a <= max + b)                                   \
                || b == 0)                                                   \
            return a - b;                                                    \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }
# define OSSL_SAFE_MATH_SUBU(type_name, type) \
    static ossl_inline ossl_unused type safe_sub_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b > a)                                                           \
            *err |= 1;                                                       \
        return a - b;                                                        \
    }
# define OSSL_SAFE_MATH_UNSIGNED(type_name, type) \
    OSSL_SAFE_MATH_ADDU(type_name, type, OSSL_SAFE_MATH_MAXU(type))     \
    OSSL_SAFE_MATH_SUBU(type_name, type)                                \
    OSSL_SAFE_MATH_MULU(type_name, type, OSSL_SAFE_MATH_MAXU(type))     \
    OSSL_SAFE_MATH_DIVU(type_name, type, OSSL_SAFE_MATH_MAXU(type))     \
    OSSL_SAFE_MATH_MODU(type_name, type)                                \
    OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type,                        \
                                OSSL_SAFE_MATH_MAXU(type))              \
    OSSL_SAFE_MATH_MULDIVU(type_name, type, OSSL_SAFE_MATH_MAXU(type))  \
    OSSL_SAFE_MATH_NEGU(type_name, type)                                \
    OSSL_SAFE_MATH_ABSU(type_name, type)
#   define has(func) __has_builtin(func)
# define OSSL_INTERNAL_CORE_H
# define OSSL_INTERNAL_PROVIDER_H
#  define BIO_FLAGS_UPLINK_INTERNAL 0x8000
# define OSSL_BSEARCH_FIRST_VALUE_ON_MATCH        0x02
# define OSSL_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OSSL_INTERNAL_CRYPTLIB_H
# define OSSL_LIB_CTX_BIO_CORE_INDEX                17
# define OSSL_LIB_CTX_BIO_PROV_INDEX                13
# define OSSL_LIB_CTX_CHILD_PROVIDER_INDEX          18
# define OSSL_LIB_CTX_DECODER_STORE_INDEX           11
# define OSSL_LIB_CTX_DEFAULT_METHOD_STORE_RUN_ONCE_INDEX    1
# define OSSL_LIB_CTX_DRBG_INDEX                     5
# define OSSL_LIB_CTX_DRBG_NONCE_INDEX               6
# define OSSL_LIB_CTX_ENCODER_STORE_INDEX           10
# define OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX         0
# define OSSL_LIB_CTX_FIPS_PROV_INDEX                9
# define OSSL_LIB_CTX_GLOBAL_PROPERTIES             14
# define OSSL_LIB_CTX_MAX_INDEXES                   19
# define OSSL_LIB_CTX_MAX_RUN_ONCE                           3
# define OSSL_LIB_CTX_METHOD_STORE_RUN_ONCE_INDEX            2
# define OSSL_LIB_CTX_NAMEMAP_INDEX                  4
# define OSSL_LIB_CTX_PROPERTY_DEFN_INDEX            2
# define OSSL_LIB_CTX_PROPERTY_STRING_INDEX          3
# define OSSL_LIB_CTX_PROVIDER_CONF_INDEX           16
# define OSSL_LIB_CTX_PROVIDER_STORE_INDEX           1
# define OSSL_LIB_CTX_PROVIDER_STORE_RUN_ONCE_INDEX          0
# define OSSL_LIB_CTX_RAND_CRNGT_INDEX               7
# define OSSL_LIB_CTX_SELF_TEST_CB_INDEX            12
# define OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX      15
#  define OSSL_LIB_CTX_THREAD_EVENT_HANDLER_INDEX    8
# define OPENSSL_CORE_NAMES_H
#define OSSL_ALG_PARAM_CIPHER       "cipher"    
#define OSSL_ALG_PARAM_DIGEST       "digest"    
#define OSSL_ALG_PARAM_ENGINE       "engine"    
#define OSSL_ALG_PARAM_MAC          "mac"       
#define OSSL_ALG_PARAM_PROPERTIES   "properties"
#define OSSL_ASYM_CIPHER_PARAM_DIGEST                   OSSL_PKEY_PARAM_DIGEST
#define OSSL_ASYM_CIPHER_PARAM_ENGINE                   OSSL_PKEY_PARAM_ENGINE
#define OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST              \
    OSSL_PKEY_PARAM_MGF1_DIGEST
#define OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS        \
    OSSL_PKEY_PARAM_MGF1_PROPERTIES
#define OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST              OSSL_ALG_PARAM_DIGEST
#define OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS        "digest-props"
#define OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL               "oaep-label"
#define OSSL_ASYM_CIPHER_PARAM_PAD_MODE                 OSSL_PKEY_PARAM_PAD_MODE
#define OSSL_ASYM_CIPHER_PARAM_PROPERTIES               OSSL_PKEY_PARAM_PROPERTIES
#define OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION       "tls-client-version"
#define OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION   "tls-negotiated-version"
#define OSSL_CAPABILITY_TLS_GROUP_ALG               "tls-group-alg"
#define OSSL_CAPABILITY_TLS_GROUP_ID                "tls-group-id"
#define OSSL_CAPABILITY_TLS_GROUP_IS_KEM            "tls-group-is-kem"
#define OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS          "tls-max-dtls"
#define OSSL_CAPABILITY_TLS_GROUP_MAX_TLS           "tls-max-tls"
#define OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS          "tls-min-dtls"
#define OSSL_CAPABILITY_TLS_GROUP_MIN_TLS           "tls-min-tls"
#define OSSL_CAPABILITY_TLS_GROUP_NAME              "tls-group-name"
#define OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL     "tls-group-name-internal"
#define OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS     "tls-group-sec-bits"
#define OSSL_CIPHER_CTS_MODE_CS1 "CS1"
#define OSSL_CIPHER_CTS_MODE_CS2 "CS2"
#define OSSL_CIPHER_CTS_MODE_CS3 "CS3"
#define OSSL_CIPHER_NAME_AES_128_GCM_SIV      "AES-128-GCM-SIV"
#define OSSL_CIPHER_NAME_AES_192_GCM_SIV      "AES-192-GCM-SIV"
#define OSSL_CIPHER_NAME_AES_256_GCM_SIV      "AES-256-GCM-SIV"
#define OSSL_CIPHER_PARAM_AEAD                 "aead"         
#define OSSL_CIPHER_PARAM_AEAD_IVLEN           OSSL_CIPHER_PARAM_IVLEN
#define OSSL_CIPHER_PARAM_AEAD_MAC_KEY         "mackey"       
#define OSSL_CIPHER_PARAM_AEAD_TAG             "tag"          
#define OSSL_CIPHER_PARAM_AEAD_TAGLEN          "taglen"       
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD        "tlsaad"       
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD    "tlsaadpad"    
#define OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN "tlsivgen"     
#define OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED   "tlsivfixed"   
#define OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV "tlsivinv"     
#define OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS  "alg_id_param" 
#define OSSL_CIPHER_PARAM_BLOCK_SIZE           "blocksize"    
#define OSSL_CIPHER_PARAM_CTS                  "cts"          
#define OSSL_CIPHER_PARAM_CTS_MODE             "cts_mode"     
#define OSSL_CIPHER_PARAM_CUSTOM_IV            "custom-iv"    
#define OSSL_CIPHER_PARAM_HAS_RAND_KEY         "has-randkey"  
#define OSSL_CIPHER_PARAM_IV                   "iv"           
#define OSSL_CIPHER_PARAM_IVLEN                "ivlen"        
#define OSSL_CIPHER_PARAM_KEYLEN               "keylen"       
#define OSSL_CIPHER_PARAM_MODE                 "mode"         
#define OSSL_CIPHER_PARAM_NUM                  "num"          
#define OSSL_CIPHER_PARAM_PADDING              "padding"      
#define OSSL_CIPHER_PARAM_RANDOM_KEY           "randkey"      
#define OSSL_CIPHER_PARAM_RC2_KEYBITS          "keybits"      
#define OSSL_CIPHER_PARAM_ROUNDS               "rounds"       
#define OSSL_CIPHER_PARAM_SPEED                "speed"        
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK      "tls-multi"    
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD                                  \
    "tls1multi_aad"        
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN                          \
    "tls1multi_aadpacklen" 
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC                                  \
    "tls1multi_enc"        
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN                               \
    "tls1multi_encin"      
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN                              \
    "tls1multi_enclen"     
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE                           \
    "tls1multi_interleave" 
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE                          \
    "tls1multi_maxbufsz"   
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT                    \
    "tls1multi_maxsndfrag" 
#define OSSL_CIPHER_PARAM_TLS_MAC              "tls-mac"      
#define OSSL_CIPHER_PARAM_TLS_MAC_SIZE         "tls-mac-size" 
#define OSSL_CIPHER_PARAM_TLS_VERSION          "tls-version"  
#define OSSL_CIPHER_PARAM_UPDATED_IV           "updated-iv"   
#define OSSL_CIPHER_PARAM_USE_BITS             "use-bits"     
#define OSSL_DECODER_PARAM_PROPERTIES       OSSL_ALG_PARAM_PROPERTIES
#define OSSL_DIGEST_NAME_KECCAK_KMAC128 "KECCAK-KMAC-128"
#define OSSL_DIGEST_NAME_KECCAK_KMAC256 "KECCAK-KMAC-256"
#define OSSL_DIGEST_NAME_MD2            "MD2"
#define OSSL_DIGEST_NAME_MD4            "MD4"
#define OSSL_DIGEST_NAME_MD5            "MD5"
#define OSSL_DIGEST_NAME_MD5_SHA1       "MD5-SHA1"
#define OSSL_DIGEST_NAME_MDC2           "MDC2"
#define OSSL_DIGEST_NAME_RIPEMD160      "RIPEMD160"
#define OSSL_DIGEST_NAME_SHA1           "SHA1"
#define OSSL_DIGEST_NAME_SHA2_224       "SHA2-224"
#define OSSL_DIGEST_NAME_SHA2_256       "SHA2-256"
#define OSSL_DIGEST_NAME_SHA2_384       "SHA2-384"
#define OSSL_DIGEST_NAME_SHA2_512       "SHA2-512"
#define OSSL_DIGEST_NAME_SHA2_512_224   "SHA2-512/224"
#define OSSL_DIGEST_NAME_SHA2_512_256   "SHA2-512/256"
#define OSSL_DIGEST_NAME_SHA3_224       "SHA3-224"
#define OSSL_DIGEST_NAME_SHA3_256       "SHA3-256"
#define OSSL_DIGEST_NAME_SHA3_384       "SHA3-384"
#define OSSL_DIGEST_NAME_SHA3_512       "SHA3-512"
#define OSSL_DIGEST_NAME_SM3            "SM3"
#define OSSL_DIGEST_PARAM_ALGID_ABSENT "algid-absent"  
#define OSSL_DIGEST_PARAM_BLOCK_SIZE   "blocksize"     
#define OSSL_DIGEST_PARAM_MICALG       "micalg"        
#define OSSL_DIGEST_PARAM_PAD_TYPE     "pad-type"      
#define OSSL_DIGEST_PARAM_SIZE         "size"          
#define OSSL_DIGEST_PARAM_SSL3_MS      "ssl3-ms"       
#define OSSL_DIGEST_PARAM_XOF          "xof"           
#define OSSL_DIGEST_PARAM_XOFLEN       "xoflen"        
#define OSSL_DRBG_PARAM_CIPHER                  OSSL_ALG_PARAM_CIPHER
#define OSSL_DRBG_PARAM_DIGEST                  OSSL_ALG_PARAM_DIGEST
#define OSSL_DRBG_PARAM_ENTROPY_REQUIRED        "entropy_required"
#define OSSL_DRBG_PARAM_MAC                     OSSL_ALG_PARAM_MAC
#define OSSL_DRBG_PARAM_MAX_ADINLEN             "max_adinlen"
#define OSSL_DRBG_PARAM_MAX_ENTROPYLEN          "max_entropylen"
#define OSSL_DRBG_PARAM_MAX_LENGTH              "maxium_length"
#define OSSL_DRBG_PARAM_MAX_NONCELEN            "max_noncelen"
#define OSSL_DRBG_PARAM_MAX_PERSLEN             "max_perslen"
#define OSSL_DRBG_PARAM_MIN_ENTROPYLEN          "min_entropylen"
#define OSSL_DRBG_PARAM_MIN_LENGTH              "minium_length"
#define OSSL_DRBG_PARAM_MIN_NONCELEN            "min_noncelen"
#define OSSL_DRBG_PARAM_PREDICTION_RESISTANCE   "prediction_resistance"
#define OSSL_DRBG_PARAM_PROPERTIES              OSSL_ALG_PARAM_PROPERTIES
#define OSSL_DRBG_PARAM_RANDOM_DATA             "random_data"
#define OSSL_DRBG_PARAM_RESEED_COUNTER          "reseed_counter"
#define OSSL_DRBG_PARAM_RESEED_REQUESTS         "reseed_requests"
#define OSSL_DRBG_PARAM_RESEED_TIME             "reseed_time"
#define OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL    "reseed_time_interval"
#define OSSL_DRBG_PARAM_SIZE                    "size"
#define OSSL_DRBG_PARAM_USE_DF                  "use_derivation_function"
#define OSSL_ENCODER_PARAM_CIPHER           OSSL_ALG_PARAM_CIPHER
#define OSSL_ENCODER_PARAM_ENCRYPT_LEVEL    "encrypt-level"
#define OSSL_ENCODER_PARAM_PROPERTIES       OSSL_ALG_PARAM_PROPERTIES
#define OSSL_ENCODER_PARAM_SAVE_PARAMETERS  "save-parameters" 
#define OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE "ecdh-cofactor-mode" 
#define OSSL_EXCHANGE_PARAM_KDF_DIGEST            "kdf-digest" 
#define OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS      "kdf-digest-props" 
#define OSSL_EXCHANGE_PARAM_KDF_OUTLEN            "kdf-outlen" 
#define OSSL_EXCHANGE_PARAM_KDF_TYPE              "kdf-type" 
#define OSSL_EXCHANGE_PARAM_KDF_UKM               "kdf-ukm"
#define OSSL_EXCHANGE_PARAM_PAD                   "pad" 
#define OSSL_GEN_PARAM_ITERATION            "iteration" 
#define OSSL_GEN_PARAM_POTENTIAL            "potential" 
#define OSSL_KDF_NAME_HKDF           "HKDF"
#define OSSL_KDF_NAME_KBKDF          "KBKDF"
#define OSSL_KDF_NAME_KRB5KDF        "KRB5KDF"
#define OSSL_KDF_NAME_PBKDF1         "PBKDF1"
#define OSSL_KDF_NAME_PBKDF2         "PBKDF2"
#define OSSL_KDF_NAME_SCRYPT         "SCRYPT"
#define OSSL_KDF_NAME_SSHKDF         "SSHKDF"
#define OSSL_KDF_NAME_SSKDF          "SSKDF"
#define OSSL_KDF_NAME_TLS1_3_KDF     "TLS13-KDF"
#define OSSL_KDF_NAME_TLS1_PRF       "TLS1-PRF"
#define OSSL_KDF_NAME_X942KDF_ASN1   "X942KDF-ASN1"
#define OSSL_KDF_NAME_X942KDF_CONCAT "X942KDF-CONCAT"
#define OSSL_KDF_NAME_X963KDF        "X963KDF"
#define OSSL_KDF_PARAM_CEK_ALG      "cekalg"    
#define OSSL_KDF_PARAM_CIPHER       OSSL_ALG_PARAM_CIPHER     
#define OSSL_KDF_PARAM_CONSTANT     "constant"  
#define OSSL_KDF_PARAM_DATA         "data"      
#define OSSL_KDF_PARAM_DIGEST       OSSL_ALG_PARAM_DIGEST     
#define OSSL_KDF_PARAM_INFO         "info"      
#define OSSL_KDF_PARAM_ITER         "iter"      
#define OSSL_KDF_PARAM_KBKDF_R      "r"         
#define OSSL_KDF_PARAM_KBKDF_USE_L  "use-l"             
#define OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR  "use-separator"     
#define OSSL_KDF_PARAM_KEY          "key"       
#define OSSL_KDF_PARAM_LABEL        "label"     
#define OSSL_KDF_PARAM_MAC          OSSL_ALG_PARAM_MAC        
#define OSSL_KDF_PARAM_MAC_SIZE     "maclen"    
#define OSSL_KDF_PARAM_MODE         "mode"      
#define OSSL_KDF_PARAM_PASSWORD     "pass"      
#define OSSL_KDF_PARAM_PKCS12_ID    "id"        
#define OSSL_KDF_PARAM_PKCS5        "pkcs5"     
#define OSSL_KDF_PARAM_PREFIX       "prefix"    
#define OSSL_KDF_PARAM_PROPERTIES   OSSL_ALG_PARAM_PROPERTIES 
#define OSSL_KDF_PARAM_SALT         "salt"      
#define OSSL_KDF_PARAM_SCRYPT_MAXMEM "maxmem_bytes" 
#define OSSL_KDF_PARAM_SCRYPT_N     "n"         
#define OSSL_KDF_PARAM_SCRYPT_P     "p"         
#define OSSL_KDF_PARAM_SCRYPT_R     "r"         
#define OSSL_KDF_PARAM_SECRET       "secret"    
#define OSSL_KDF_PARAM_SEED         "seed"      
#define OSSL_KDF_PARAM_SIZE         "size"      
#define OSSL_KDF_PARAM_SSHKDF_SESSION_ID "session_id" 
#define OSSL_KDF_PARAM_SSHKDF_TYPE  "type"      
#define OSSL_KDF_PARAM_SSHKDF_XCGHASH "xcghash" 
#define OSSL_KDF_PARAM_UKM          "ukm"       
#define OSSL_KDF_PARAM_X942_ACVPINFO        "acvp-info"
#define OSSL_KDF_PARAM_X942_PARTYUINFO      "partyu-info"
#define OSSL_KDF_PARAM_X942_PARTYVINFO      "partyv-info"
#define OSSL_KDF_PARAM_X942_SUPP_PRIVINFO   "supp-privinfo"
#define OSSL_KDF_PARAM_X942_SUPP_PUBINFO    "supp-pubinfo"
#define OSSL_KDF_PARAM_X942_USE_KEYBITS     "use-keybits"
#define OSSL_KEM_PARAM_IKME                 "ikme"
#define OSSL_KEM_PARAM_OPERATION            "operation"
#define OSSL_KEM_PARAM_OPERATION_DHKEM      "DHKEM"
#define OSSL_KEM_PARAM_OPERATION_RSASVE     "RSASVE"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_BLOCK_PADDING  "block_padding"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_MAX_EARLY_DATA "max_early_data"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_MAX_FRAG_LEN   "max_frag_len"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_MODE           "mode"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_OPTIONS        "options"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_READ_AHEAD     "read_ahead"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_STREAM_MAC     "stream_mac"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_TLSTREE        "tlstree"
#define OSSL_LIBSSL_RECORD_LAYER_PARAM_USE_ETM        "use_etm"
#define OSSL_LIBSSL_RECORD_LAYER_READ_BUFFER_LEN      "read_buffer_len"
#define OSSL_MAC_NAME_BLAKE2BMAC    "BLAKE2BMAC"
#define OSSL_MAC_NAME_BLAKE2SMAC    "BLAKE2SMAC"
#define OSSL_MAC_NAME_CMAC          "CMAC"
#define OSSL_MAC_NAME_GMAC          "GMAC"
#define OSSL_MAC_NAME_HMAC          "HMAC"
#define OSSL_MAC_NAME_KMAC128       "KMAC128"
#define OSSL_MAC_NAME_KMAC256       "KMAC256"
#define OSSL_MAC_NAME_POLY1305      "POLY1305"
#define OSSL_MAC_NAME_SIPHASH       "SIPHASH"
#define OSSL_MAC_PARAM_BLOCK_SIZE       "block-size"              
#define OSSL_MAC_PARAM_CIPHER           OSSL_ALG_PARAM_CIPHER     
#define OSSL_MAC_PARAM_CUSTOM         "custom"         
#define OSSL_MAC_PARAM_C_ROUNDS       "c-rounds"       
#define OSSL_MAC_PARAM_DIGEST           OSSL_ALG_PARAM_DIGEST     
#define OSSL_MAC_PARAM_DIGEST_NOINIT  "digest-noinit"  
#define OSSL_MAC_PARAM_DIGEST_ONESHOT "digest-oneshot" 
#define OSSL_MAC_PARAM_D_ROUNDS       "d-rounds"       
#define OSSL_MAC_PARAM_IV             "iv"             
#define OSSL_MAC_PARAM_KEY            "key"            
#define OSSL_MAC_PARAM_PROPERTIES       OSSL_ALG_PARAM_PROPERTIES 
#define OSSL_MAC_PARAM_SALT           "salt"           
#define OSSL_MAC_PARAM_SIZE             "size"                    
#define OSSL_MAC_PARAM_TLS_DATA_SIZE    "tls-data-size"           
#define OSSL_MAC_PARAM_XOF            "xof"            
#define OSSL_OBJECT_PARAM_DATA              "data" 
#define OSSL_OBJECT_PARAM_DATA_STRUCTURE    "data-structure" 
#define OSSL_OBJECT_PARAM_DATA_TYPE         "data-type" 
#define OSSL_OBJECT_PARAM_DESC              "desc"      
#define OSSL_OBJECT_PARAM_REFERENCE         "reference" 
#define OSSL_OBJECT_PARAM_TYPE              "type"      
#define OSSL_PASSPHRASE_PARAM_INFO      "info"
#define OSSL_PKEY_EC_ENCODING_EXPLICIT  "explicit"
#define OSSL_PKEY_EC_ENCODING_GROUP     "named_curve"
#define OSSL_PKEY_EC_GROUP_CHECK_DEFAULT     "default"
#define OSSL_PKEY_EC_GROUP_CHECK_NAMED       "named"
#define OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST  "named-nist"
#define OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED   "compressed"
#define OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID       "hybrid"
#define OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED "uncompressed"
#define OSSL_PKEY_PARAM_BITS                "bits" 
#define OSSL_PKEY_PARAM_CIPHER              OSSL_ALG_PARAM_CIPHER 
#define OSSL_PKEY_PARAM_DEFAULT_DIGEST      "default-digest" 
#define OSSL_PKEY_PARAM_DHKEM_IKM        "dhkem-ikm"
#define OSSL_PKEY_PARAM_DH_GENERATOR        "safeprime-generator"
#define OSSL_PKEY_PARAM_DH_PRIV_LEN         "priv_len"
#define OSSL_PKEY_PARAM_DIGEST              OSSL_ALG_PARAM_DIGEST
#define OSSL_PKEY_PARAM_DIGEST_SIZE         "digest-size"
#define OSSL_PKEY_PARAM_DIST_ID             "distid"
#define OSSL_PKEY_PARAM_EC_A                            "a"
#define OSSL_PKEY_PARAM_EC_B                            "b"
#define OSSL_PKEY_PARAM_EC_CHAR2_M                      "m"
#define OSSL_PKEY_PARAM_EC_CHAR2_PP_K1                  "k1"
#define OSSL_PKEY_PARAM_EC_CHAR2_PP_K2                  "k2"
#define OSSL_PKEY_PARAM_EC_CHAR2_PP_K3                  "k3"
#define OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS               "tp"
#define OSSL_PKEY_PARAM_EC_CHAR2_TYPE                   "basis-type"
#define OSSL_PKEY_PARAM_EC_COFACTOR                     "cofactor"
#define OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS "decoded-from-explicit"
#define OSSL_PKEY_PARAM_EC_ENCODING                "encoding" 
#define OSSL_PKEY_PARAM_EC_FIELD_TYPE                   "field-type"
#define OSSL_PKEY_PARAM_EC_GENERATOR                    "generator"
#define OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE        "group-check"
#define OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC          "include-public"
#define OSSL_PKEY_PARAM_EC_ORDER                        "order"
#define OSSL_PKEY_PARAM_EC_P                            "p"
#define OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT "point-format"
#define OSSL_PKEY_PARAM_EC_PUB_X     "qx"
#define OSSL_PKEY_PARAM_EC_PUB_Y     "qy"
#define OSSL_PKEY_PARAM_EC_SEED                         "seed"
#define OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY  "encoded-pub-key"
#define OSSL_PKEY_PARAM_ENGINE              OSSL_ALG_PARAM_ENGINE 
#define OSSL_PKEY_PARAM_FFC_COFACTOR        "j"
#define OSSL_PKEY_PARAM_FFC_DIGEST       OSSL_PKEY_PARAM_DIGEST
#define OSSL_PKEY_PARAM_FFC_DIGEST_PROPS OSSL_PKEY_PARAM_PROPERTIES
#define OSSL_PKEY_PARAM_FFC_G               "g"
#define OSSL_PKEY_PARAM_FFC_GINDEX          "gindex"
#define OSSL_PKEY_PARAM_FFC_H               "hindex"
#define OSSL_PKEY_PARAM_FFC_P               "p"
#define OSSL_PKEY_PARAM_FFC_PBITS        "pbits"
#define OSSL_PKEY_PARAM_FFC_PCOUNTER        "pcounter"
#define OSSL_PKEY_PARAM_FFC_Q               "q"
#define OSSL_PKEY_PARAM_FFC_QBITS        "qbits"
#define OSSL_PKEY_PARAM_FFC_SEED            "seed"
#define OSSL_PKEY_PARAM_FFC_TYPE         "type"
#define OSSL_PKEY_PARAM_FFC_VALIDATE_G      "validate-g"
#define OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY "validate-legacy"
#define OSSL_PKEY_PARAM_FFC_VALIDATE_PQ     "validate-pq"
#define OSSL_PKEY_PARAM_GROUP_NAME          "group"
#define OSSL_PKEY_PARAM_MANDATORY_DIGEST    "mandatory-digest" 
#define OSSL_PKEY_PARAM_MASKGENFUNC         "mgf"
#define OSSL_PKEY_PARAM_MAX_SIZE            "max-size" 
#define OSSL_PKEY_PARAM_MGF1_DIGEST         "mgf1-digest"
#define OSSL_PKEY_PARAM_MGF1_PROPERTIES     "mgf1-properties"
#define OSSL_PKEY_PARAM_PAD_MODE            "pad-mode"
#define OSSL_PKEY_PARAM_PRIV_KEY            "priv"
#define OSSL_PKEY_PARAM_PROPERTIES          OSSL_ALG_PARAM_PROPERTIES
#define OSSL_PKEY_PARAM_PUB_KEY             "pub"
#define OSSL_PKEY_PARAM_RSA_BITS             OSSL_PKEY_PARAM_BITS
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT "rsa-coefficient"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT1 OSSL_PKEY_PARAM_RSA_COEFFICIENT"1"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT2 OSSL_PKEY_PARAM_RSA_COEFFICIENT"2"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT3 OSSL_PKEY_PARAM_RSA_COEFFICIENT"3"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT4 OSSL_PKEY_PARAM_RSA_COEFFICIENT"4"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT5 OSSL_PKEY_PARAM_RSA_COEFFICIENT"5"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT6 OSSL_PKEY_PARAM_RSA_COEFFICIENT"6"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT7 OSSL_PKEY_PARAM_RSA_COEFFICIENT"7"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT8 OSSL_PKEY_PARAM_RSA_COEFFICIENT"8"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT9 OSSL_PKEY_PARAM_RSA_COEFFICIENT"9"
#define OSSL_PKEY_PARAM_RSA_D           "d"
#define OSSL_PKEY_PARAM_RSA_DIGEST           OSSL_PKEY_PARAM_DIGEST
#define OSSL_PKEY_PARAM_RSA_DIGEST_PROPS     OSSL_PKEY_PARAM_PROPERTIES
#define OSSL_PKEY_PARAM_RSA_E           "e"
#define OSSL_PKEY_PARAM_RSA_EXPONENT    "rsa-exponent"
#define OSSL_PKEY_PARAM_RSA_EXPONENT1    OSSL_PKEY_PARAM_RSA_EXPONENT"1"
#define OSSL_PKEY_PARAM_RSA_EXPONENT10   OSSL_PKEY_PARAM_RSA_EXPONENT"10"
#define OSSL_PKEY_PARAM_RSA_EXPONENT2    OSSL_PKEY_PARAM_RSA_EXPONENT"2"
#define OSSL_PKEY_PARAM_RSA_EXPONENT3    OSSL_PKEY_PARAM_RSA_EXPONENT"3"
#define OSSL_PKEY_PARAM_RSA_EXPONENT4    OSSL_PKEY_PARAM_RSA_EXPONENT"4"
#define OSSL_PKEY_PARAM_RSA_EXPONENT5    OSSL_PKEY_PARAM_RSA_EXPONENT"5"
#define OSSL_PKEY_PARAM_RSA_EXPONENT6    OSSL_PKEY_PARAM_RSA_EXPONENT"6"
#define OSSL_PKEY_PARAM_RSA_EXPONENT7    OSSL_PKEY_PARAM_RSA_EXPONENT"7"
#define OSSL_PKEY_PARAM_RSA_EXPONENT8    OSSL_PKEY_PARAM_RSA_EXPONENT"8"
#define OSSL_PKEY_PARAM_RSA_EXPONENT9    OSSL_PKEY_PARAM_RSA_EXPONENT"9"
#define OSSL_PKEY_PARAM_RSA_FACTOR      "rsa-factor"
#define OSSL_PKEY_PARAM_RSA_FACTOR1      OSSL_PKEY_PARAM_RSA_FACTOR"1"
#define OSSL_PKEY_PARAM_RSA_FACTOR10     OSSL_PKEY_PARAM_RSA_FACTOR"10"
#define OSSL_PKEY_PARAM_RSA_FACTOR2      OSSL_PKEY_PARAM_RSA_FACTOR"2"
#define OSSL_PKEY_PARAM_RSA_FACTOR3      OSSL_PKEY_PARAM_RSA_FACTOR"3"
#define OSSL_PKEY_PARAM_RSA_FACTOR4      OSSL_PKEY_PARAM_RSA_FACTOR"4"
#define OSSL_PKEY_PARAM_RSA_FACTOR5      OSSL_PKEY_PARAM_RSA_FACTOR"5"
#define OSSL_PKEY_PARAM_RSA_FACTOR6      OSSL_PKEY_PARAM_RSA_FACTOR"6"
#define OSSL_PKEY_PARAM_RSA_FACTOR7      OSSL_PKEY_PARAM_RSA_FACTOR"7"
#define OSSL_PKEY_PARAM_RSA_FACTOR8      OSSL_PKEY_PARAM_RSA_FACTOR"8"
#define OSSL_PKEY_PARAM_RSA_FACTOR9      OSSL_PKEY_PARAM_RSA_FACTOR"9"
#define OSSL_PKEY_PARAM_RSA_MASKGENFUNC      OSSL_PKEY_PARAM_MASKGENFUNC
#define OSSL_PKEY_PARAM_RSA_MGF1_DIGEST      OSSL_PKEY_PARAM_MGF1_DIGEST
#define OSSL_PKEY_PARAM_RSA_N           "n"
#define OSSL_PKEY_PARAM_RSA_PRIMES           "primes"
#define OSSL_PKEY_PARAM_RSA_PSS_SALTLEN      "saltlen"
#define OSSL_PKEY_PARAM_RSA_TEST_P1  "p1"
#define OSSL_PKEY_PARAM_RSA_TEST_P2  "p2"
#define OSSL_PKEY_PARAM_RSA_TEST_Q1  "q1"
#define OSSL_PKEY_PARAM_RSA_TEST_Q2  "q2"
#define OSSL_PKEY_PARAM_RSA_TEST_XP  "xp"
#define OSSL_PKEY_PARAM_RSA_TEST_XP1 "xp1"
#define OSSL_PKEY_PARAM_RSA_TEST_XP2 "xp2"
#define OSSL_PKEY_PARAM_RSA_TEST_XQ  "xq"
#define OSSL_PKEY_PARAM_RSA_TEST_XQ1 "xq1"
#define OSSL_PKEY_PARAM_RSA_TEST_XQ2 "xq2"
#define OSSL_PKEY_PARAM_SECURITY_BITS       "security-bits" 
#define OSSL_PKEY_PARAM_USE_COFACTOR_ECDH \
    OSSL_PKEY_PARAM_USE_COFACTOR_FLAG
#define OSSL_PKEY_PARAM_USE_COFACTOR_FLAG "use-cofactor-flag"
#define OSSL_PKEY_RSA_PAD_MODE_NONE    "none"
#define OSSL_PKEY_RSA_PAD_MODE_OAEP    "oaep"
#define OSSL_PKEY_RSA_PAD_MODE_PKCSV15 "pkcs1"
#define OSSL_PKEY_RSA_PAD_MODE_PSS     "pss"
#define OSSL_PKEY_RSA_PAD_MODE_X931    "x931"
#define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO   "auto"
#define OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST "digest"
#define OSSL_PKEY_RSA_PSS_SALT_LEN_MAX    "max"
#define OSSL_PROV_PARAM_BUILDINFO       "buildinfo"           
#define OSSL_PROV_PARAM_CORE_MODULE_FILENAME "module-filename" 
#define OSSL_PROV_PARAM_CORE_PROV_NAME       "provider-name"   
#define OSSL_PROV_PARAM_CORE_VERSION         "openssl-version" 
#define OSSL_PROV_PARAM_NAME            "name"                
#define OSSL_PROV_PARAM_SECURITY_CHECKS "security-checks"     
#define OSSL_PROV_PARAM_SELF_TEST_DESC   "st-desc"  
#define OSSL_PROV_PARAM_SELF_TEST_PHASE  "st-phase" 
#define OSSL_PROV_PARAM_SELF_TEST_TYPE   "st-type"  
#define OSSL_PROV_PARAM_STATUS          "status"              
#define OSSL_PROV_PARAM_VERSION         "version"             
#define OSSL_RAND_PARAM_MAX_REQUEST             "max_request"
#define OSSL_RAND_PARAM_STATE                   "state"
#define OSSL_RAND_PARAM_STRENGTH                "strength"
#define OSSL_RAND_PARAM_TEST_ENTROPY            "test_entropy"
#define OSSL_RAND_PARAM_TEST_NONCE              "test_nonce"
#define OSSL_SIGNATURE_PARAM_ALGORITHM_ID       "algorithm-id"
#define OSSL_SIGNATURE_PARAM_DIGEST             OSSL_PKEY_PARAM_DIGEST
#define OSSL_SIGNATURE_PARAM_DIGEST_SIZE        OSSL_PKEY_PARAM_DIGEST_SIZE
#define OSSL_SIGNATURE_PARAM_KAT "kat"
#define OSSL_SIGNATURE_PARAM_MGF1_DIGEST        OSSL_PKEY_PARAM_MGF1_DIGEST
#define OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES    \
    OSSL_PKEY_PARAM_MGF1_PROPERTIES
#define OSSL_SIGNATURE_PARAM_PAD_MODE           OSSL_PKEY_PARAM_PAD_MODE
#define OSSL_SIGNATURE_PARAM_PROPERTIES         OSSL_PKEY_PARAM_PROPERTIES
#define OSSL_SIGNATURE_PARAM_PSS_SALTLEN        "saltlen"
#define OSSL_STORE_PARAM_ALIAS      "alias"        
#define OSSL_STORE_PARAM_DIGEST     "digest"       
#define OSSL_STORE_PARAM_EXPECT     "expect"       
#define OSSL_STORE_PARAM_FINGERPRINT "fingerprint" 
#define OSSL_STORE_PARAM_INPUT_TYPE "input-type"   
#define OSSL_STORE_PARAM_ISSUER     "name" 
#define OSSL_STORE_PARAM_PROPERTIES "properties"   
#define OSSL_STORE_PARAM_SERIAL     "serial"       
#define OSSL_STORE_PARAM_SUBJECT    "subject" 
# define OPENSSL_PARAMS_H
# define OSSL_PARAM_BN(key, bn, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))
# define OSSL_PARAM_DEFN(key, type, addr, sz)    \
    { (key), (type), (addr), (sz), OSSL_PARAM_UNMODIFIED }
# define OSSL_PARAM_END \
    { NULL, 0, NULL, 0, 0 }
# define OSSL_PARAM_UNMODIFIED ((size_t)-1)
# define OSSL_PARAM_double(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double))
# define OSSL_PARAM_int(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int))
# define OSSL_PARAM_int32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t))
# define OSSL_PARAM_int64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t))
# define OSSL_PARAM_long(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int))
# define OSSL_PARAM_octet_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, (addr), sz)
# define OSSL_PARAM_octet_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz)
# define OSSL_PARAM_size_t(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))
# define OSSL_PARAM_time_t(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(time_t))
# define OSSL_PARAM_uint(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int))
# define OSSL_PARAM_uint32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t))
# define OSSL_PARAM_uint64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t))
# define OSSL_PARAM_ulong(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int))
# define OSSL_PARAM_utf8_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, (addr), sz)
# define OSSL_PARAM_utf8_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz)
#  define HEADER_RAND_H
# define OPENSSL_RAND_H
# define RAND_DRBG_STRENGTH             256
#   define RAND_cleanup() while(0) continue
# define ASN1_PKEY_ALIAS         0x1
# define ASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
# define ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED 0xb
# define ASN1_PKEY_CTRL_CMS_RI_TYPE      0x8
# define ASN1_PKEY_CTRL_CMS_SIGN         0x5
# define ASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
# define ASN1_PKEY_CTRL_GET1_TLS_ENCPT   0xa
# define ASN1_PKEY_CTRL_PKCS7_ENCRYPT    0x2
# define ASN1_PKEY_CTRL_PKCS7_SIGN       0x1
# define ASN1_PKEY_CTRL_SET1_TLS_ENCPT   0x9
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
# define EVP_CIPHER_CTX_block_size EVP_CIPHER_CTX_get_block_size
#  define EVP_CIPHER_CTX_cleanup(c)   EVP_CIPHER_CTX_reset(c)
# define EVP_CIPHER_CTX_encrypting EVP_CIPHER_CTX_is_encrypting
#  define EVP_CIPHER_CTX_flags(c)    EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(c))
# define EVP_CIPHER_CTX_get0_name(c) EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(c))
# define EVP_CIPHER_CTX_get_mode(c)  EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))
# define EVP_CIPHER_CTX_get_type(c)  EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c))
#  define EVP_CIPHER_CTX_init(c)      EVP_CIPHER_CTX_reset(c)
# define EVP_CIPHER_CTX_iv_length EVP_CIPHER_CTX_get_iv_length
# define EVP_CIPHER_CTX_key_length EVP_CIPHER_CTX_get_key_length
# define EVP_CIPHER_CTX_mode         EVP_CIPHER_CTX_get_mode
# define EVP_CIPHER_CTX_nid EVP_CIPHER_CTX_get_nid
# define EVP_CIPHER_CTX_num EVP_CIPHER_CTX_get_num
# define EVP_CIPHER_CTX_tag_length EVP_CIPHER_CTX_get_tag_length
# define EVP_CIPHER_CTX_type         EVP_CIPHER_CTX_get_type
# define EVP_CIPHER_block_size EVP_CIPHER_get_block_size
# define EVP_CIPHER_flags EVP_CIPHER_get_flags
# define EVP_CIPHER_iv_length EVP_CIPHER_get_iv_length
# define EVP_CIPHER_key_length EVP_CIPHER_get_key_length
# define EVP_CIPHER_mode EVP_CIPHER_get_mode
# define EVP_CIPHER_name EVP_CIPHER_get0_name
# define EVP_CIPHER_nid EVP_CIPHER_get_nid
# define EVP_CIPHER_type EVP_CIPHER_get_type
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
# define         EVP_CIPH_FLAG_CIPHER_WITH_MAC   0x2000000
# define         EVP_CIPH_FLAG_CTS               0x4000
# define         EVP_CIPH_FLAG_CUSTOM_ASN1       0x1000000
# define         EVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         EVP_CIPH_FLAG_DEFAULT_ASN1      0
# define         EVP_CIPH_FLAG_FIPS              0
# define         EVP_CIPH_FLAG_GET_WRAP_CIPHER   0x4000000
# define         EVP_CIPH_FLAG_INVERSE_CIPHER    0x8000000
# define         EVP_CIPH_FLAG_LENGTH_BITS       0x2000
# define         EVP_CIPH_FLAG_NON_FIPS_ALLOW    0
# define         EVP_CIPH_FLAG_PIPELINE          0X800000
# define         EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
# define         EVP_CIPH_GCM_MODE               0x6
# define         EVP_CIPH_GCM_SIV_MODE           0x10005
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
# define         EVP_CTRL_GET_IVLEN                      0x25
# define         EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         EVP_CTRL_GET_RC5_ROUNDS         0x4
#define          EVP_CTRL_GET_WRAP_CIPHER                0x29
# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_KEY_MESH                       0x20
# define         EVP_CTRL_PBE_PRF_NID            0x7
# define         EVP_CTRL_PROCESS_UNPROTECTED            0x28
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
#define          EVP_CTRL_TLSTREE                        0x2A
# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)
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
#  define EVP_MD_CTRL_TLSTREE                     0x4
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
# define EVP_MD_CTX_block_size EVP_MD_CTX_get_block_size
# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
# define EVP_MD_CTX_get0_name(e)       EVP_MD_get0_name(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_get_block_size(e)  EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_get_size(e)        EVP_MD_get_size(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_get_type(e)            EVP_MD_get_type(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
# define EVP_MD_CTX_md_data EVP_MD_CTX_get0_md_data
# define EVP_MD_CTX_pkey_ctx EVP_MD_CTX_get_pkey_ctx
# define EVP_MD_CTX_size               EVP_MD_CTX_get_size
# define EVP_MD_CTX_type EVP_MD_CTX_get_type
#  define EVP_MD_FLAG_DIGALGID_ABSENT             0x0008
#  define EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018
#  define EVP_MD_FLAG_DIGALGID_MASK               0x0018
#  define EVP_MD_FLAG_DIGALGID_NULL               0x0000
#  define EVP_MD_FLAG_FIPS        0x0400
#  define EVP_MD_FLAG_ONESHOT     0x0001
#  define EVP_MD_FLAG_XOF         0x0002
# define EVP_MD_block_size EVP_MD_get_block_size
# define EVP_MD_flags EVP_MD_get_flags
# define EVP_MD_name EVP_MD_get0_name
# define EVP_MD_nid EVP_MD_get_type
# define EVP_MD_pkey_type EVP_MD_get_pkey_type
# define EVP_MD_size EVP_MD_get_size
# define EVP_MD_type EVP_MD_get_type
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
#  define EVP_PKEY_CTRL_CMS_DECRYPT       10
#  define EVP_PKEY_CTRL_CMS_ENCRYPT       9
#  define EVP_PKEY_CTRL_CMS_SIGN          11
# define EVP_PKEY_CTRL_DIGESTINIT        7
# define EVP_PKEY_CTRL_GET1_ID           16
# define EVP_PKEY_CTRL_GET1_ID_LEN       17
# define EVP_PKEY_CTRL_GET_MD            13
# define EVP_PKEY_CTRL_MD                1
# define EVP_PKEY_CTRL_PEER_KEY          2
#  define EVP_PKEY_CTRL_PKCS7_DECRYPT     4
#  define EVP_PKEY_CTRL_PKCS7_ENCRYPT     3
#  define EVP_PKEY_CTRL_PKCS7_SIGN        5
# define EVP_PKEY_CTRL_SET1_ID           15
# define EVP_PKEY_CTRL_SET_DIGEST_SIZE   14
# define EVP_PKEY_CTRL_SET_IV            8
# define EVP_PKEY_CTRL_SET_MAC_KEY       6
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
# define EVP_PKEY_KEYMGMT -1
# define EVP_PKEY_KEYPAIR                                                   \
    ( EVP_PKEY_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
# define EVP_PKEY_KEY_PARAMETERS                                            \
    ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )
# define EVP_PKEY_MO_DECRYPT     0x0008
# define EVP_PKEY_MO_ENCRYPT     0x0004
# define EVP_PKEY_MO_SIGN        0x0001
# define EVP_PKEY_MO_VERIFY      0x0002
# define EVP_PKEY_NONE   NID_undef
# define EVP_PKEY_OP_DECAPSULATE         (1<<13)
# define EVP_PKEY_OP_DECRYPT             (1<<10)
# define EVP_PKEY_OP_DERIVE              (1<<11)
# define EVP_PKEY_OP_ENCAPSULATE         (1<<12)
# define EVP_PKEY_OP_ENCRYPT             (1<<9)
# define EVP_PKEY_OP_FROMDATA            (1<<3)
# define EVP_PKEY_OP_KEYGEN              (1<<2)
# define EVP_PKEY_OP_PARAMGEN            (1<<1)
# define EVP_PKEY_OP_SIGN                (1<<4)
# define EVP_PKEY_OP_SIGNCTX             (1<<7)
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
# define EVP_PKEY_OP_VERIFY              (1<<5)
# define EVP_PKEY_OP_VERIFYCTX           (1<<8)
# define EVP_PKEY_OP_VERIFYRECOVER       (1<<6)
# define EVP_PKEY_POLY1305 NID_poly1305
# define EVP_PKEY_PUBLIC_KEY                                                \
    ( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
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
#   define EVP_PKEY_assign_EC_KEY(pkey,eckey) \
        EVP_PKEY_assign((pkey), EVP_PKEY_EC, (eckey))
#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),\
                                        EVP_PKEY_POLY1305,(polykey))
#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                                         (rsa))
#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),\
                                        EVP_PKEY_SIPHASH,(shkey))
# define EVP_PKEY_base_id EVP_PKEY_get_base_id
# define EVP_PKEY_bits EVP_PKEY_get_bits
#  define EVP_PKEY_get1_tls_encodedpoint(pkey, ppt) \
          EVP_PKEY_get1_encoded_public_key((pkey), (ppt))
# define EVP_PKEY_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EVP_PKEY, l, p, newf, dupf, freef)
# define EVP_PKEY_id EVP_PKEY_get_id
# define EVP_PKEY_security_bits EVP_PKEY_get_security_bits
#  define EVP_PKEY_set1_tls_encodedpoint(pkey, pt, ptlen) \
          EVP_PKEY_set1_encoded_public_key((pkey), (pt), (ptlen))
# define EVP_PKEY_size EVP_PKEY_get_size
#  define EVP_PKS_DSA     0x0200
#  define EVP_PKS_EC      0x0400
#  define EVP_PKS_RSA     0x0100
#  define EVP_PKT_ENC     0x0020
#  define EVP_PKT_EXCH    0x0040
#  define EVP_PKT_SIGN    0x0010
#  define EVP_PK_DH       0x0004
#  define EVP_PK_DSA      0x0002
#  define EVP_PK_EC       0x0008
#  define EVP_PK_RSA      0x0001
# define EVP_RAND_STATE_ERROR            2
# define EVP_RAND_STATE_READY            1
# define EVP_RAND_STATE_UNINITIALISED    0
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
#  define HEADER_ENVELOPE_H
# define OPENSSL_EVP_H
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
