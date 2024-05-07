
#include<assert.h>

#include<string.h>
# define HEADER_RAND_H
# define RAND_F_RAND_BYTES                                100
# define RAND_R_PRNG_NOT_SEEDED                           100
# define RAND_cleanup() while(0) continue
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
                ? inl*8 : inl), \
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
#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))
#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))
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
# define TLS1_1_VERSION   0x0302
# define CRYPTO_DOWN_REF(val, ret, lock) CRYPTO_atomic_add(val, -1, ret, lock)
# define CRYPTO_UP_REF(val, ret, lock) CRYPTO_atomic_add(val, 1, ret, lock)
# define HAVE_ATOMICS 1
# define HAVE_C11_ATOMICS
# define HEADER_INTERNAL_REFCOUNT_H
# define AES_BLOCK_SIZE 16
# define AES_DECRYPT     0
# define AES_ENCRYPT     1
# define AES_MAXNR 14
# define HEADER_AES_H
# define ASN1err(f,r) ERR_PUT_error(ERR_LIB_ASN1,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ASYNCerr(f,r) ERR_PUT_error(ERR_LIB_ASYNC,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define BIOerr(f,r)  ERR_PUT_error(ERR_LIB_BIO,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define BNerr(f,r)   ERR_PUT_error(ERR_LIB_BN,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define BUFerr(f,r)  ERR_PUT_error(ERR_LIB_BUF,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define CMSerr(f,r) ERR_PUT_error(ERR_LIB_CMS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define COMPerr(f,r) ERR_PUT_error(ERR_LIB_COMP,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define CONFerr(f,r) ERR_PUT_error(ERR_LIB_CONF,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define CRYPTOerr(f,r) ERR_PUT_error(ERR_LIB_CRYPTO,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define CTerr(f,r) ERR_PUT_error(ERR_LIB_CT,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define DHerr(f,r)   ERR_PUT_error(ERR_LIB_DH,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define DSAerr(f,r)  ERR_PUT_error(ERR_LIB_DSA,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define DSOerr(f,r) ERR_PUT_error(ERR_LIB_DSO,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ECDHerr(f,r)  ERR_PUT_error(ERR_LIB_ECDH,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ECDSAerr(f,r)  ERR_PUT_error(ERR_LIB_ECDSA,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ECerr(f,r)   ERR_PUT_error(ERR_LIB_EC,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ENGINEerr(f,r) ERR_PUT_error(ERR_LIB_ENGINE,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ERR_FATAL_ERROR(l)      (int)( (l)         & ERR_R_FATAL)
# define ERR_FLAG_MARK           0x01
# define ERR_GET_FUNC(l)         (int)(((l) >> 12L) & 0xFFFL)
# define ERR_GET_LIB(l)          (int)(((l) >> 24L) & 0x0FFL)
# define ERR_GET_REASON(l)       (int)( (l)         & 0xFFFL)
# define ERR_LIB_ASN1            13
# define ERR_LIB_ASYNC           51
# define ERR_LIB_BIO             32
# define ERR_LIB_BN              3
# define ERR_LIB_BUF             7
# define ERR_LIB_CMS             46
# define ERR_LIB_COMP            41
# define ERR_LIB_CONF            14
# define ERR_LIB_CRYPTO          15
# define ERR_LIB_CT              50
# define ERR_LIB_DH              5
# define ERR_LIB_DSA             10
# define ERR_LIB_DSO             37
# define ERR_LIB_EC              16
# define ERR_LIB_ECDH            43
# define ERR_LIB_ECDSA           42
# define ERR_LIB_ENGINE          38
# define ERR_LIB_EVP             6
# define ERR_LIB_FIPS            45
# define ERR_LIB_HMAC            48
# define ERR_LIB_KDF             52
# define ERR_LIB_NONE            1
# define ERR_LIB_OBJ             8
# define ERR_LIB_OCSP            39
# define ERR_LIB_PEM             9
# define ERR_LIB_PKCS12          35
# define ERR_LIB_PKCS7           33
# define ERR_LIB_RAND            36
# define ERR_LIB_RSA             4
# define ERR_LIB_SSL             20
# define ERR_LIB_STORE           44
# define ERR_LIB_SYS             2
# define ERR_LIB_TS              47
# define ERR_LIB_UI              40
# define ERR_LIB_USER            128
# define ERR_LIB_X509            11
# define ERR_LIB_X509V3          34
# define ERR_NUM_ERRORS  16
# define ERR_PACK(l,f,r) ( \
        (((unsigned int)(l) & 0x0FF) << 24L) | \
        (((unsigned int)(f) & 0xFFF) << 12L) | \
        (((unsigned int)(r) & 0xFFF)       ) )
#  define ERR_PUT_error(a,b,c,d,e)        ERR_put_error(a,b,c,d,e)
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
# define ERR_R_PASSED_INVALID_ARGUMENT           (7)
# define ERR_R_PASSED_NULL_PARAMETER             (3|ERR_R_FATAL)
# define ERR_R_PEM_LIB   ERR_LIB_PEM
# define ERR_R_PKCS7_LIB ERR_LIB_PKCS7
# define ERR_R_RSA_LIB   ERR_LIB_RSA
# define ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED       (2|ERR_R_FATAL)
# define ERR_R_SYS_LIB   ERR_LIB_SYS
# define ERR_R_X509V3_LIB ERR_LIB_X509V3
# define ERR_R_X509_LIB  ERR_LIB_X509
# define ERR_TXT_MALLOCED        0x01
# define ERR_TXT_STRING          0x02
# define ERR_free_strings() while(0) continue
# define ERR_load_crypto_strings() \
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
# define EVPerr(f,r)  ERR_PUT_error(ERR_LIB_EVP,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define FIPSerr(f,r) ERR_PUT_error(ERR_LIB_FIPS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define HEADER_ERR_H
# define HMACerr(f,r) ERR_PUT_error(ERR_LIB_HMAC,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define KDFerr(f,r) ERR_PUT_error(ERR_LIB_KDF,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define OCSPerr(f,r) ERR_PUT_error(ERR_LIB_OCSP,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define PEMerr(f,r)  ERR_PUT_error(ERR_LIB_PEM,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define PKCS12err(f,r) ERR_PUT_error(ERR_LIB_PKCS12,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define PKCS7err(f,r) ERR_PUT_error(ERR_LIB_PKCS7,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define RANDerr(f,r) ERR_PUT_error(ERR_LIB_RAND,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define RSAerr(f,r)  ERR_PUT_error(ERR_LIB_RSA,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define SSLerr(f,r)  ERR_PUT_error(ERR_LIB_SSL,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define STOREerr(f,r) ERR_PUT_error(ERR_LIB_STORE,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define SYS_F_ACCEPT            8
# define SYS_F_BIND              6
# define SYS_F_CONNECT           2
# define SYS_F_FOPEN             1
# define SYS_F_FREAD             11
# define SYS_F_GETADDRINFO       12
# define SYS_F_GETHOSTBYNAME     17
# define SYS_F_GETNAMEINFO       13
# define SYS_F_GETSERVBYNAME     3
# define SYS_F_GETSOCKNAME       16
# define SYS_F_GETSOCKOPT        15
# define SYS_F_IOCTLSOCKET       5
# define SYS_F_LISTEN            7
# define SYS_F_OPENDIR           10
# define SYS_F_SETSOCKOPT        14
# define SYS_F_SOCKET            4
# define SYS_F_WSASTARTUP        9
# define SYSerr(f,r)  ERR_PUT_error(ERR_LIB_SYS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define TSerr(f,r) ERR_PUT_error(ERR_LIB_TS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define UIerr(f,r) ERR_PUT_error(ERR_LIB_UI,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define X509V3err(f,r) ERR_PUT_error(ERR_LIB_X509V3,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define X509err(f,r) ERR_PUT_error(ERR_LIB_X509,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define ASN1_PKEY_ALIAS         0x1
# define ASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
# define ASN1_PKEY_CTRL_CMS_RI_TYPE      0x8
# define ASN1_PKEY_CTRL_CMS_SIGN         0x5
# define ASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
# define ASN1_PKEY_CTRL_GET1_TLS_ENCPT   0xa
# define ASN1_PKEY_CTRL_PKCS7_ENCRYPT    0x2
# define ASN1_PKEY_CTRL_PKCS7_SIGN       0x1
# define ASN1_PKEY_CTRL_SET1_TLS_ENCPT   0x9
# define ASN1_PKEY_DYNAMIC       0x2
# define ASN1_PKEY_SIGPARAM_NULL 0x4
# define BIO_get_cipher_ctx(b,c_pp)      BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,(char *)c_pp)
# define BIO_get_cipher_status(b)        BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)
# define BIO_get_md(b,mdp)               BIO_ctrl(b,BIO_C_GET_MD,0,(char *)mdp)
# define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0,(char *)mdcp)
#  define BIO_set_md(b,md)               BIO_ctrl(b,BIO_C_SET_MD,0,(char *)md)
# define BIO_set_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0,(char *)mdcp)
# define         EVP_AEAD_TLS1_AAD_LEN           13
# define EVP_CCM_TLS_EXPLICIT_IV_LEN                     8
# define EVP_CCM_TLS_FIXED_IV_LEN                        4
# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1
#  define EVP_CIPHER_CTX_cleanup(c)   EVP_CIPHER_CTX_reset(c)
#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
#  define EVP_CIPHER_CTX_init(c)      EVP_CIPHER_CTX_reset(c)
# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)
# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))
# define         EVP_CIPH_ALWAYS_CALL_INIT       0x20
# define         EVP_CIPH_CBC_MODE               0x2
# define         EVP_CIPH_CCM_MODE               0x7
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_CTRL_INIT              0x40
# define         EVP_CIPH_CTR_MODE               0x5
# define         EVP_CIPH_CUSTOM_COPY            0x400
# define         EVP_CIPH_CUSTOM_IV              0x10
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
# define         EVP_CTRL_SSL3_MASTER_SECRET             0x1d
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_AAD  0x19
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT      0x1b
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT      0x1a
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE  0x1c
# define EVP_DECODE_LENGTH(l)    ((l+3)/4*3+80)
# define EVP_DigestSignUpdate(a,b,c)     EVP_DigestUpdate(a,b,c)
# define EVP_DigestVerifyUpdate(a,b,c)   EVP_DigestUpdate(a,b,c)
# define EVP_ENCODE_LENGTH(l)    (((l+2)/3*4)+(l/48+1)*2+80)
# define EVP_F_AESNI_INIT_KEY                             165
# define EVP_F_AES_INIT_KEY                               133
# define EVP_F_AES_OCB_CIPHER                             169
# define EVP_F_AES_T4_INIT_KEY                            178
# define EVP_F_AES_WRAP_CIPHER                            170
# define EVP_F_ALG_MODULE_INIT                            177
# define EVP_F_CAMELLIA_INIT_KEY                          159
# define EVP_F_CHACHA20_POLY1305_CTRL                     182
# define EVP_F_CMLL_T4_INIT_KEY                           179
# define EVP_F_DES_EDE3_WRAP_CIPHER                       171
# define EVP_F_DO_SIGVER_INIT                             161
# define EVP_F_EVP_CIPHERINIT_EX                          123
# define EVP_F_EVP_CIPHER_CTX_COPY                        163
# define EVP_F_EVP_CIPHER_CTX_CTRL                        124
# define EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH              122
# define EVP_F_EVP_DECRYPTFINAL_EX                        101
# define EVP_F_EVP_DECRYPTUPDATE                          166
# define EVP_F_EVP_DIGESTINIT_EX                          128
# define EVP_F_EVP_ENCRYPTFINAL_EX                        127
# define EVP_F_EVP_ENCRYPTUPDATE                          167
# define EVP_F_EVP_MD_CTX_COPY_EX                         110
# define EVP_F_EVP_MD_SIZE                                162
# define EVP_F_EVP_OPENINIT                               102
# define EVP_F_EVP_PBE_ALG_ADD                            115
# define EVP_F_EVP_PBE_ALG_ADD_TYPE                       160
# define EVP_F_EVP_PBE_CIPHERINIT                         116
# define EVP_F_EVP_PBE_SCRYPT                             181
# define EVP_F_EVP_PKCS82PKEY                             111
# define EVP_F_EVP_PKEY2PKCS8                             113
# define EVP_F_EVP_PKEY_COPY_PARAMETERS                   103
# define EVP_F_EVP_PKEY_CTX_CTRL                          137
# define EVP_F_EVP_PKEY_CTX_CTRL_STR                      150
# define EVP_F_EVP_PKEY_CTX_DUP                           156
# define EVP_F_EVP_PKEY_CTX_MD                            168
# define EVP_F_EVP_PKEY_DECRYPT                           104
# define EVP_F_EVP_PKEY_DECRYPT_INIT                      138
# define EVP_F_EVP_PKEY_DECRYPT_OLD                       151
# define EVP_F_EVP_PKEY_DERIVE                            153
# define EVP_F_EVP_PKEY_DERIVE_INIT                       154
# define EVP_F_EVP_PKEY_DERIVE_SET_PEER                   155
# define EVP_F_EVP_PKEY_ENCRYPT                           105
# define EVP_F_EVP_PKEY_ENCRYPT_INIT                      139
# define EVP_F_EVP_PKEY_ENCRYPT_OLD                       152
# define EVP_F_EVP_PKEY_GET0_DH                           119
# define EVP_F_EVP_PKEY_GET0_DSA                          120
# define EVP_F_EVP_PKEY_GET0_EC_KEY                       131
# define EVP_F_EVP_PKEY_GET0_HMAC                         183
# define EVP_F_EVP_PKEY_GET0_POLY1305                     184
# define EVP_F_EVP_PKEY_GET0_RSA                          121
# define EVP_F_EVP_PKEY_KEYGEN                            146
# define EVP_F_EVP_PKEY_KEYGEN_INIT                       147
# define EVP_F_EVP_PKEY_NEW                               106
# define EVP_F_EVP_PKEY_PARAMGEN                          148
# define EVP_F_EVP_PKEY_PARAMGEN_INIT                     149
# define EVP_F_EVP_PKEY_SIGN                              140
# define EVP_F_EVP_PKEY_SIGN_INIT                         141
# define EVP_F_EVP_PKEY_VERIFY                            142
# define EVP_F_EVP_PKEY_VERIFY_INIT                       143
# define EVP_F_EVP_PKEY_VERIFY_RECOVER                    144
# define EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT               145
# define EVP_F_EVP_SIGNFINAL                              107
# define EVP_F_EVP_VERIFYFINAL                            108
# define EVP_F_INT_CTX_NEW                                157
# define EVP_F_PKCS5_PBE_KEYIVGEN                         117
# define EVP_F_PKCS5_V2_PBE_KEYIVGEN                      118
# define EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN                   164
# define EVP_F_PKCS5_V2_SCRYPT_KEYIVGEN                   180
# define EVP_F_PKEY_SET_TYPE                              158
# define EVP_F_RC2_MAGIC_TO_METH                          109
# define EVP_F_RC5_CTRL                                   125
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
# define EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
#  define EVP_MD_FLAG_DIGALGID_ABSENT             0x0008
#  define EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018
#  define EVP_MD_FLAG_DIGALGID_MASK               0x0018
#  define EVP_MD_FLAG_DIGALGID_NULL               0x0000
#  define EVP_MD_FLAG_FIPS        0x0400
#  define EVP_MD_FLAG_ONESHOT     0x0001
# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))
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
# define EVP_PKEY_CTRL_SET_IV            8
# define EVP_PKEY_CTRL_SET_MAC_KEY       6
# define  EVP_PKEY_CTX_get_signature_md(ctx, pmd)        \
                EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,  \
                                        EVP_PKEY_CTRL_GET_MD, 0, (void *)pmd)
# define  EVP_PKEY_CTX_set_mac_key(ctx, key, len)        \
                EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,  \
                                  EVP_PKEY_CTRL_SET_MAC_KEY, len, (void *)key)
# define  EVP_PKEY_CTX_set_signature_md(ctx, md) \
                EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,  \
                                        EVP_PKEY_CTRL_MD, 0, (void *)md)
# define EVP_PKEY_DH     NID_dhKeyAgreement
# define EVP_PKEY_DHX    NID_dhpublicnumber
# define EVP_PKEY_DSA    NID_dsa
# define EVP_PKEY_DSA1   NID_dsa_2
# define EVP_PKEY_DSA2   NID_dsaWithSHA
# define EVP_PKEY_DSA3   NID_dsaWithSHA1
# define EVP_PKEY_DSA4   NID_dsaWithSHA1_2
# define EVP_PKEY_EC     NID_X9_62_id_ecPublicKey
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
# define EVP_PKEY_TLS1_PRF NID_tls1_prf
#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,\
                                        (char *)(dh))
#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (char *)(dsa))
#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC,\
                                        (char *)(eckey))
#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305,\
                                        (char *)(polykey))
#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                        (char *)(rsa))
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
# define EVP_R_AES_KEY_SETUP_FAILED                       143
# define EVP_R_BAD_DECRYPT                                100
# define EVP_R_BUFFER_TOO_SMALL                           155
# define EVP_R_CAMELLIA_KEY_SETUP_FAILED                  157
# define EVP_R_CIPHER_PARAMETER_ERROR                     122
# define EVP_R_COMMAND_NOT_SUPPORTED                      147
# define EVP_R_COPY_ERROR                                 173
# define EVP_R_CTRL_NOT_IMPLEMENTED                       132
# define EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED             133
# define EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH          138
# define EVP_R_DECODE_ERROR                               114
# define EVP_R_DIFFERENT_KEY_TYPES                        101
# define EVP_R_DIFFERENT_PARAMETERS                       153
# define EVP_R_ERROR_LOADING_SECTION                      165
# define EVP_R_ERROR_SETTING_FIPS_MODE                    166
# define EVP_R_EXPECTING_AN_HMAC_KEY                      174
# define EVP_R_EXPECTING_AN_RSA_KEY                       127
# define EVP_R_EXPECTING_A_DH_KEY                         128
# define EVP_R_EXPECTING_A_DSA_KEY                        129
# define EVP_R_EXPECTING_A_EC_KEY                         142
# define EVP_R_EXPECTING_A_POLY1305_KEY                   164
# define EVP_R_FIPS_MODE_NOT_SUPPORTED                    167
# define EVP_R_ILLEGAL_SCRYPT_PARAMETERS                  171
# define EVP_R_INITIALIZATION_ERROR                       134
# define EVP_R_INPUT_NOT_INITIALIZED                      111
# define EVP_R_INVALID_DIGEST                             152
# define EVP_R_INVALID_FIPS_MODE                          168
# define EVP_R_INVALID_KEY                                163
# define EVP_R_INVALID_KEY_LENGTH                         130
# define EVP_R_INVALID_OPERATION                          148
# define EVP_R_KEYGEN_FAILURE                             120
# define EVP_R_MEMORY_LIMIT_EXCEEDED                      172
# define EVP_R_MESSAGE_DIGEST_IS_NULL                     159
# define EVP_R_METHOD_NOT_SUPPORTED                       144
# define EVP_R_MISSING_PARAMETERS                         103
# define EVP_R_NO_CIPHER_SET                              131
# define EVP_R_NO_DEFAULT_DIGEST                          158
# define EVP_R_NO_DIGEST_SET                              139
# define EVP_R_NO_KEY_SET                                 154
# define EVP_R_NO_OPERATION_SET                           149
# define EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE   150
# define EVP_R_OPERATON_NOT_INITIALIZED                   151
# define EVP_R_PARTIALLY_OVERLAPPING                      162
# define EVP_R_PRIVATE_KEY_DECODE_ERROR                   145
# define EVP_R_PRIVATE_KEY_ENCODE_ERROR                   146
# define EVP_R_PUBLIC_KEY_NOT_RSA                         106
# define EVP_R_UNKNOWN_CIPHER                             160
# define EVP_R_UNKNOWN_DIGEST                             161
# define EVP_R_UNKNOWN_OPTION                             169
# define EVP_R_UNKNOWN_PBE_ALGORITHM                      121
# define EVP_R_UNSUPPORTED_ALGORITHM                      156
# define EVP_R_UNSUPPORTED_CIPHER                         107
# define EVP_R_UNSUPPORTED_KEYLENGTH                      123
# define EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION        124
# define EVP_R_UNSUPPORTED_KEY_SIZE                       108
# define EVP_R_UNSUPPORTED_NUMBER_OF_ROUNDS               135
# define EVP_R_UNSUPPORTED_PRF                            125
# define EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM          118
# define EVP_R_UNSUPPORTED_SALT_TYPE                      126
# define EVP_R_WRAP_MODE_NOT_ALLOWED                      170
# define EVP_R_WRONG_FINAL_BLOCK_LENGTH                   109
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
# define HEADER_ENVELOPE_H
#  define OPENSSL_add_all_algorithms_conf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | OPENSSL_INIT_LOAD_CONFIG, NULL)
#  define OPENSSL_add_all_algorithms_noconf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)
#   define OpenSSL_add_all_algorithms() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | OPENSSL_INIT_LOAD_CONFIG, NULL)
#  define OpenSSL_add_all_ciphers() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)
#  define OpenSSL_add_all_digests() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)
# define PKCS5_DEFAULT_ITER              2048
# define PKCS5_SALT_LEN                  8
# define CRYPTO_EX_INDEX_APP             13
# define CRYPTO_EX_INDEX_BIO             12
# define CRYPTO_EX_INDEX_DH               6
# define CRYPTO_EX_INDEX_DSA              7
# define CRYPTO_EX_INDEX_EC_KEY           8
# define CRYPTO_EX_INDEX_ENGINE          10
# define CRYPTO_EX_INDEX_RSA              9
# define CRYPTO_EX_INDEX_SSL              0
# define CRYPTO_EX_INDEX_SSL_CTX          1
# define CRYPTO_EX_INDEX_SSL_SESSION      2
# define CRYPTO_EX_INDEX_UI              11
# define CRYPTO_EX_INDEX_UI_METHOD       14
# define CRYPTO_EX_INDEX_X509             3
# define CRYPTO_EX_INDEX_X509_STORE       4
# define CRYPTO_EX_INDEX_X509_STORE_CTX   5
# define CRYPTO_EX_INDEX__COUNT          15
# define CRYPTO_F_CRYPTO_DUP_EX_DATA                      110
# define CRYPTO_F_CRYPTO_FREE_EX_DATA                     111
# define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX                 100
# define CRYPTO_F_CRYPTO_MEMDUP                           115
# define CRYPTO_F_CRYPTO_NEW_EX_DATA                      112
# define CRYPTO_F_CRYPTO_SET_EX_DATA                      102
# define CRYPTO_F_FIPS_MODE_SET                           109
# define CRYPTO_F_GET_AND_LOCK                            113
# define CRYPTO_F_OPENSSL_BUF2HEXSTR                      117
# define CRYPTO_F_OPENSSL_HEXSTR2BUF                      118
# define CRYPTO_F_OPENSSL_INIT_CRYPTO                     116
#  define CRYPTO_LOCK             1
# define CRYPTO_MEM_CHECK_DISABLE 0x3   
# define CRYPTO_MEM_CHECK_ENABLE  0x2   
# define CRYPTO_MEM_CHECK_OFF     0x0   
# define CRYPTO_MEM_CHECK_ON      0x1   
#    define CRYPTO_ONCE_STATIC_INIT 0
#  define CRYPTO_READ             4
# define CRYPTO_R_FIPS_MODE_NOT_SUPPORTED                 101
# define CRYPTO_R_ILLEGAL_HEX_DIGIT                       102
# define CRYPTO_R_ODD_NUMBER_OF_DIGITS                    103
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
# define OPENSSL_BUILT_ON         2
# define OPENSSL_CFLAGS           1
# define OPENSSL_DIR              4
# define OPENSSL_ENGINES_DIR      5
# define OPENSSL_INIT_ADD_ALL_CIPHERS        0x00000004L
# define OPENSSL_INIT_ADD_ALL_DIGESTS        0x00000008L
# define OPENSSL_INIT_ASYNC                  0x00000100L
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
# define OPENSSL_INIT_NO_LOAD_CONFIG         0x00000080L
# define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L
# define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))
# define OPENSSL_PLATFORM         3
# define OPENSSL_VERSION          0
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
#define OPENSSL_malloc_init() \
    CRYPTO_set_mem_functions(CRYPTO_malloc, CRYPTO_realloc, CRYPTO_free)
#  define OPENSSL_mem_debug_pop() \
        CRYPTO_mem_debug_pop()
#  define OPENSSL_mem_debug_push(info) \
        CRYPTO_mem_debug_push(info, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_memdup(str, s) \
        CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_realloc(addr, num) \
        CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_actual_size(ptr) \
        CRYPTO_secure_actual_size(ptr)
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
