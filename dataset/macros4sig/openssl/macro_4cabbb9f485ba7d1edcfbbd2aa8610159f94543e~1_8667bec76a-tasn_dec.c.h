#include<stddef.h>
#include<string.h>
# define HEADER_NUMBERS_H
#  define INT16_MAX __MAXINT__(int16_t)
#  define INT16_MIN __MININT__(int16_t)
#  define INT32_MAX __MAXINT__(int32_t)
#  define INT32_MIN __MININT__(int32_t)
#  define INT64_MAX __MAXINT__(int64_t)
#  define INT64_MIN __MININT__(int64_t)
#  define INT8_MAX __MAXINT__(int8_t)
#  define INT8_MIN __MININT__(int8_t)
#  define SIZE_MAX __MAXUINT__(size_t)
#  define UINT16_MAX __MAXUINT__(uint16_t)
#  define UINT32_MAX __MAXUINT__(uint32_t)
#  define UINT64_MAX __MAXUINT__(uint64_t)
#  define UINT8_MAX __MAXUINT__(uint8_t)
#  define __MAXINT__(T) ((T) ((((T) 1) << ((sizeof(T) * CHAR_BIT) - 1)) ^ __MAXUINT__(T)))
#  define __MAXUINT__(T) ((T) -1)
#  define __MININT__(T) (-__MAXINT__(T) - 1)
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
# define ERR_LIB_OSSL_STORE      44
# define ERR_LIB_PEM             9
# define ERR_LIB_PKCS12          35
# define ERR_LIB_PKCS7           33
# define ERR_LIB_RAND            36
# define ERR_LIB_RSA             4
# define ERR_LIB_SM2             53
# define ERR_LIB_SSL             20
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
# define EVPerr(f,r)  ERR_PUT_error(ERR_LIB_EVP,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define FIPSerr(f,r) ERR_PUT_error(ERR_LIB_FIPS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define HEADER_ERR_H
# define HMACerr(f,r) ERR_PUT_error(ERR_LIB_HMAC,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define KDFerr(f,r) ERR_PUT_error(ERR_LIB_KDF,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define OCSPerr(f,r) ERR_PUT_error(ERR_LIB_OCSP,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define OSSL_STOREerr(f,r) ERR_PUT_error(ERR_LIB_OSSL_STORE,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define PEMerr(f,r)  ERR_PUT_error(ERR_LIB_PEM,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define PKCS12err(f,r) ERR_PUT_error(ERR_LIB_PKCS12,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define PKCS7err(f,r) ERR_PUT_error(ERR_LIB_PKCS7,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define RANDerr(f,r) ERR_PUT_error(ERR_LIB_RAND,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define RSAerr(f,r)  ERR_PUT_error(ERR_LIB_RSA,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define SM2err(f,r) ERR_PUT_error(ERR_LIB_SM2,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define SSLerr(f,r)  ERR_PUT_error(ERR_LIB_SSL,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define SYS_F_ACCEPT            8
# define SYS_F_BIND              6
# define SYS_F_CLOSE             20
# define SYS_F_CONNECT           2
# define SYS_F_FCNTL             23
# define SYS_F_FFLUSH            18
# define SYS_F_FOPEN             1
# define SYS_F_FREAD             11
# define SYS_F_FSTAT             24
# define SYS_F_GETADDRINFO       12
# define SYS_F_GETHOSTBYNAME     17
# define SYS_F_GETNAMEINFO       13
# define SYS_F_GETSERVBYNAME     3
# define SYS_F_GETSOCKNAME       16
# define SYS_F_GETSOCKOPT        15
# define SYS_F_IOCTL             21
# define SYS_F_IOCTLSOCKET       5
# define SYS_F_LISTEN            7
# define SYS_F_OPEN              19
# define SYS_F_OPENDIR           10
# define SYS_F_SETSOCKOPT        14
# define SYS_F_SOCKET            4
# define SYS_F_STAT              22
# define SYS_F_WSASTARTUP        9
# define SYSerr(f,r)  ERR_PUT_error(ERR_LIB_SYS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define TSerr(f,r) ERR_PUT_error(ERR_LIB_TS,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define UIerr(f,r) ERR_PUT_error(ERR_LIB_UI,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define X509V3err(f,r) ERR_PUT_error(ERR_LIB_X509V3,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define X509err(f,r) ERR_PUT_error(ERR_LIB_X509,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
# define BUF_MEM_FLAG_SECURE  0x01
# define BUF_memdup(data, size) OPENSSL_memdup(data, size)
# define BUF_strdup(s) OPENSSL_strdup(s)
# define BUF_strlcat(dst, src, size) OPENSSL_strlcat(dst, src, size)
# define BUF_strlcpy(dst, src, size)  OPENSSL_strlcpy(dst, src, size)
# define BUF_strndup(s, size) OPENSSL_strndup(s, size)
# define BUF_strnlen(str, maxlen) OPENSSL_strnlen(str, maxlen)
# define HEADER_BUFFER_H
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
# define OBJ_NAME_TYPE_MD_METH           0x01
# define OBJ_NAME_TYPE_NUM               0x05
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
# define ADB_ENTRY(val, template) {val, template}
# define ASN1_ADB(name) \
        static const ASN1_ADB_TABLE name##_adbtbl[]
#  define ASN1_ADB_END(name, flags, field, adb_cb, def, none) \
        ;\
        static const ASN1_ADB name##_adb = {\
                flags,\
                offsetof(name, field),\
                adb_cb,\
                name##_adbtbl,\
                sizeof(name##_adbtbl) / sizeof(ASN1_ADB_TABLE),\
                def,\
                none\
        }
#  define ASN1_ADB_INTEGER(tblname) { ASN1_TFLG_ADB_INT, -1, 0, #tblname, (const ASN1_ITEM *)&(tblname##_adb) }
#  define ASN1_ADB_OBJECT(tblname) { ASN1_TFLG_ADB_OID, -1, 0, #tblname, (const ASN1_ITEM *)&(tblname##_adb) }
# define ASN1_ADB_TEMPLATE(name) \
        static const ASN1_TEMPLATE name##_tt
#  define ASN1_ADB_ptr(iptr) ((const ASN1_ADB *)(iptr))
# define ASN1_AFLG_BROKEN        4
# define ASN1_AFLG_ENCODING      2
# define ASN1_AFLG_REFCOUNT      1
# define ASN1_BROKEN_SEQUENCE(tname) \
        static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_BROKEN, 0, 0, 0, 0}; \
        ASN1_SEQUENCE(tname)
# define ASN1_BROKEN_SEQUENCE_END(stname) ASN1_SEQUENCE_END_ref(stname, stname)
# define ASN1_CHOICE(tname) \
        static const ASN1_TEMPLATE tname##_ch_tt[]
# define ASN1_CHOICE_END(stname) ASN1_CHOICE_END_name(stname, stname)
# define ASN1_CHOICE_END_cb(stname, tname, selname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)
# define ASN1_CHOICE_END_name(stname, tname) ASN1_CHOICE_END_selector(stname, tname, type)
# define ASN1_CHOICE_END_selector(stname, tname, selname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)
# define ASN1_CHOICE_cb(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        ASN1_CHOICE(tname)
# define ASN1_EMBED(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_EMBED,0, stname, field, type)
# define ASN1_EXP(stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, 0)
# define ASN1_EXP_EMBED(stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_EMBED)
# define ASN1_EXP_EX(stname, field, type, tag, ex) \
         ASN1_EX_TYPE(ASN1_TFLG_EXPLICIT | (ex), tag, stname, field, type)
# define ASN1_EXP_OPT(stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL)
# define ASN1_EXP_OPT_EMBED(stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED)
# define ASN1_EXP_SEQUENCE_OF(stname, field, type, tag) \
                        ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF)
# define ASN1_EXP_SEQUENCE_OF_OPT(stname, field, type, tag) \
                        ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL)
# define ASN1_EXP_SET_OF(stname, field, type, tag) \
                        ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF)
# define ASN1_EXP_SET_OF_OPT(stname, field, type, tag) \
                        ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF|ASN1_TFLG_OPTIONAL)
# define ASN1_EX_TEMPLATE_TYPE(flags, tag, name, type) { \
        (flags), (tag), 0,\
        #name, ASN1_ITEM_ref(type) }
# define ASN1_EX_TYPE(flags, tag, stname, field, type) { \
        (flags), (tag), offsetof(stname, field),\
        #field, ASN1_ITEM_ref(type) }
# define ASN1_IMP(stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, 0)
# define ASN1_IMP_EMBED(stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_EMBED)
# define ASN1_IMP_EX(stname, field, type, tag, ex) \
         ASN1_EX_TYPE(ASN1_TFLG_IMPLICIT | (ex), tag, stname, field, type)
# define ASN1_IMP_OPT(stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL)
# define ASN1_IMP_OPT_EMBED(stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED)
# define ASN1_IMP_SEQUENCE_OF(stname, field, type, tag) \
                        ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF)
# define ASN1_IMP_SEQUENCE_OF_OPT(stname, field, type, tag) \
                        ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL)
# define ASN1_IMP_SET_OF(stname, field, type, tag) \
                        ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF)
# define ASN1_IMP_SET_OF_OPT(stname, field, type, tag) \
                        ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF|ASN1_TFLG_OPTIONAL)
# define ASN1_ITEM_TEMPLATE(tname) \
        static const ASN1_TEMPLATE tname##_item_tt
# define ASN1_ITEM_TEMPLATE_END(tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_PRIMITIVE,\
                -1,\
                &tname##_item_tt,\
                0,\
                NULL,\
                0,\
                #tname \
        ASN1_ITEM_end(tname)
#  define ASN1_ITEM_end(itname)                 \
                };
#  define ASN1_ITEM_start(itname) \
        const ASN1_ITEM itname##_it = {
# define ASN1_ITYPE_CHOICE               0x2
# define ASN1_ITYPE_EXTERN               0x4
# define ASN1_ITYPE_MSTRING              0x5
# define ASN1_ITYPE_NDEF_SEQUENCE        0x6
# define ASN1_ITYPE_PRIMITIVE            0x0
# define ASN1_ITYPE_SEQUENCE             0x1
# define ASN1_NDEF_EXP(stname, field, type, tag) \
                        ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_NDEF)
# define ASN1_NDEF_EXP_OPT(stname, field, type, tag) \
                        ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL|ASN1_TFLG_NDEF)
# define ASN1_NDEF_SEQUENCE(tname) \
        ASN1_SEQUENCE(tname)
# define ASN1_NDEF_SEQUENCE_END(tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_NDEF_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(tname),\
                #tname \
        ASN1_ITEM_end(tname)
# define ASN1_NDEF_SEQUENCE_END_cb(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_NDEF_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)
# define ASN1_NDEF_SEQUENCE_cb(tname, cb) \
        ASN1_SEQUENCE_cb(tname, cb)
# define ASN1_OPT(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL, 0, stname, field, type)
# define ASN1_OPT_EMBED(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED, 0, stname, field, type)
# define ASN1_OP_D2I_POST        5
# define ASN1_OP_D2I_PRE         4
# define ASN1_OP_DETACHED_POST   13
# define ASN1_OP_DETACHED_PRE    12
# define ASN1_OP_FREE_POST       3
# define ASN1_OP_FREE_PRE        2
# define ASN1_OP_I2D_POST        7
# define ASN1_OP_I2D_PRE         6
# define ASN1_OP_NEW_POST        1
# define ASN1_OP_NEW_PRE         0
# define ASN1_OP_PRINT_POST      9
# define ASN1_OP_PRINT_PRE       8
# define ASN1_OP_STREAM_POST     11
# define ASN1_OP_STREAM_PRE      10
# define ASN1_SEQUENCE(tname) \
        static const ASN1_TEMPLATE tname##_seq_tt[]
# define ASN1_SEQUENCE_END(stname) ASN1_SEQUENCE_END_name(stname, stname)
# define ASN1_SEQUENCE_END_cb(stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)
# define ASN1_SEQUENCE_END_enc(stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)
# define ASN1_SEQUENCE_END_name(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #tname \
        ASN1_ITEM_end(tname)
# define ASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #tname \
        ASN1_ITEM_end(tname)
# define ASN1_SEQUENCE_OF(stname, field, type) \
                ASN1_EX_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, stname, field, type)
# define ASN1_SEQUENCE_OF_OPT(stname, field, type) \
                ASN1_EX_TYPE(ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL, 0, stname, field, type)
# define ASN1_SEQUENCE_cb(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        ASN1_SEQUENCE(tname)
# define ASN1_SEQUENCE_enc(tname, enc, cb) \
        static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_ENCODING, 0, 0, cb, offsetof(tname, enc)}; \
        ASN1_SEQUENCE(tname)
# define ASN1_SEQUENCE_ref(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_REFCOUNT, offsetof(tname, references), offsetof(tname, lock), cb, 0}; \
        ASN1_SEQUENCE(tname)
# define ASN1_SET_OF(stname, field, type) \
                ASN1_EX_TYPE(ASN1_TFLG_SET_OF, 0, stname, field, type)
# define ASN1_SET_OF_OPT(stname, field, type) \
                ASN1_EX_TYPE(ASN1_TFLG_SET_OF|ASN1_TFLG_OPTIONAL, 0, stname, field, type)
# define ASN1_SIMPLE(stname, field, type) ASN1_EX_TYPE(0,0, stname, field, type)
# define ASN1_TEMPLATE_adb(t) (t->item_ptr)
# define ASN1_TEMPLATE_item(t) (t->item_ptr)
# define ASN1_TFLG_ADB_INT       (0x1<<9)
# define ASN1_TFLG_ADB_MASK      (0x3<<8)
# define ASN1_TFLG_ADB_OID       (0x1<<8)
# define ASN1_TFLG_APPLICATION   (0x1<<6)
# define ASN1_TFLG_CONTEXT       (0x2<<6)
# define ASN1_TFLG_EMBED         (0x1 << 12)
# define ASN1_TFLG_EXPLICIT      (ASN1_TFLG_EXPTAG|ASN1_TFLG_CONTEXT)
# define ASN1_TFLG_EXPTAG        (0x2 << 3)
# define ASN1_TFLG_IMPLICIT      (ASN1_TFLG_IMPTAG|ASN1_TFLG_CONTEXT)
# define ASN1_TFLG_IMPTAG        (0x1 << 3)
# define ASN1_TFLG_NDEF          (0x1<<11)
# define ASN1_TFLG_OPTIONAL      (0x1)
# define ASN1_TFLG_PRIVATE       (0x3<<6)
# define ASN1_TFLG_SEQUENCE_OF   (0x2 << 1)
# define ASN1_TFLG_SET_OF        (0x1 << 1)
# define ASN1_TFLG_SET_ORDER     (0x3 << 1)
# define ASN1_TFLG_SK_MASK       (0x3 << 1)
# define ASN1_TFLG_TAG_CLASS     (0x3<<6)
# define ASN1_TFLG_TAG_MASK      (0x3 << 3)
# define ASN1_TFLG_UNIVERSAL     (0x0<<6)
# define HEADER_ASN1T_H
# define IMPLEMENT_ASN1_ALLOC_FUNCTIONS(stname) \
                IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, stname, stname)
# define IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname) \
        stname *fname##_new(void) \
        { \
                return (stname *)ASN1_item_new(ASN1_ITEM_rptr(itname)); \
        } \
        void fname##_free(stname *a) \
        { \
                ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(itname)); \
        }
# define IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname(pre, stname, itname, fname) \
        pre stname *fname##_new(void) \
        { \
                return (stname *)ASN1_item_new(ASN1_ITEM_rptr(itname)); \
        } \
        pre void fname##_free(stname *a) \
        { \
                ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(itname)); \
        }
# define IMPLEMENT_ASN1_DUP_FUNCTION(stname) \
        stname * stname##_dup(stname *x) \
        { \
        return ASN1_item_dup(ASN1_ITEM_rptr(stname), x); \
        }
# define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) \
        stname *d2i_##fname(stname **a, const unsigned char **in, long len) \
        { \
                return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(itname));\
        } \
        int i2d_##fname(const stname *a, unsigned char **out) \
        { \
                return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(itname));\
        }
# define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
        stname *d2i_##fname(stname **a, const unsigned char **in, long len) \
        { \
                return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(itname));\
        } \
        int i2d_##fname(stname *a, unsigned char **out) \
        { \
                return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(itname));\
        }
# define IMPLEMENT_ASN1_FUNCTIONS(stname) IMPLEMENT_ASN1_FUNCTIONS_fname(stname, stname, stname)
# define IMPLEMENT_ASN1_FUNCTIONS_ENCODE_name(stname, itname) \
                        IMPLEMENT_ASN1_FUNCTIONS_ENCODE_fname(stname, itname, itname)
# define IMPLEMENT_ASN1_FUNCTIONS_const(name) \
                IMPLEMENT_ASN1_FUNCTIONS_const_fname(name, name, name)
# define IMPLEMENT_ASN1_FUNCTIONS_const_fname(stname, itname, fname) \
        IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) \
        IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)
# define IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, fname) \
        IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
        IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)
# define IMPLEMENT_ASN1_FUNCTIONS_name(stname, itname) IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, itname)
# define IMPLEMENT_ASN1_MSTRING(itname, mask) \
                                ASN1_ITEM_start(itname) \
                                        ASN1_ITYPE_MSTRING, mask, NULL, 0, NULL, sizeof(ASN1_STRING), #itname \
                                ASN1_ITEM_end(itname)
# define IMPLEMENT_ASN1_NDEF_FUNCTION(stname) \
        int i2d_##stname##_NDEF(stname *a, unsigned char **out) \
        { \
                return ASN1_item_ndef_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(stname));\
        }
# define IMPLEMENT_ASN1_PRINT_FUNCTION(stname) \
        IMPLEMENT_ASN1_PRINT_FUNCTION_fname(stname, stname, stname)
# define IMPLEMENT_ASN1_PRINT_FUNCTION_fname(stname, itname, fname) \
        int fname##_print_ctx(BIO *out, stname *x, int indent, \
                                                const ASN1_PCTX *pctx) \
        { \
                return ASN1_item_print(out, (ASN1_VALUE *)x, indent, \
                        ASN1_ITEM_rptr(itname), pctx); \
        }
# define IMPLEMENT_ASN1_TYPE(stname) IMPLEMENT_ASN1_TYPE_ex(stname, stname, 0)
# define IMPLEMENT_ASN1_TYPE_ex(itname, vname, ex) \
                                ASN1_ITEM_start(itname) \
                                        ASN1_ITYPE_PRIMITIVE, V_##vname, NULL, 0, NULL, ex, #itname \
                                ASN1_ITEM_end(itname)
# define IMPLEMENT_EXTERN_ASN1(sname, tag, fptrs) \
        ASN1_ITEM_start(sname) \
                ASN1_ITYPE_EXTERN, \
                tag, \
                NULL, \
                0, \
                &fptrs, \
                0, \
                #sname \
        ASN1_ITEM_end(sname)
# define IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(stname) \
                IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname(static, stname, stname, stname)
# define IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(stname) \
        static stname *d2i_##stname(stname **a, \
                                   const unsigned char **in, long len) \
        { \
                return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, \
                                               ASN1_ITEM_rptr(stname)); \
        } \
        static int i2d_##stname(stname *a, unsigned char **out) \
        { \
                return ASN1_item_i2d((ASN1_VALUE *)a, out, \
                                     ASN1_ITEM_rptr(stname)); \
        }
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# define static_ASN1_BROKEN_SEQUENCE_END(stname) \
        static_ASN1_SEQUENCE_END_ref(stname, stname)
# define static_ASN1_CHOICE_END(stname) static_ASN1_CHOICE_END_name(stname, stname)
# define static_ASN1_CHOICE_END_name(stname, tname) static_ASN1_CHOICE_END_selector(stname, tname, type)
# define static_ASN1_CHOICE_END_selector(stname, tname, selname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)
# define static_ASN1_ITEM_TEMPLATE_END(tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_PRIMITIVE,\
                -1,\
                &tname##_item_tt,\
                0,\
                NULL,\
                0,\
                #tname \
        ASN1_ITEM_end(tname)
#  define static_ASN1_ITEM_start(itname) \
        static const ASN1_ITEM itname##_it = {
# define static_ASN1_NDEF_SEQUENCE_END(tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_NDEF_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(tname),\
                #tname \
        ASN1_ITEM_end(tname)
# define static_ASN1_SEQUENCE_END(stname) static_ASN1_SEQUENCE_END_name(stname, stname)
# define static_ASN1_SEQUENCE_END_cb(stname, tname) static_ASN1_SEQUENCE_END_ref(stname, tname)
# define static_ASN1_SEQUENCE_END_name(stname, tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)
# define static_ASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)
#  define ASN1_ITEM_ptr(iptr) (iptr)
#  define ASN1_ITEM_ref(iptr) (&(iptr##_it))
#  define ASN1_ITEM_rptr(ref) (&(ref##_it))
# define ASN1_LONG_UNDEF 0x7fffffffL
# define ASN1_PCTX_FLAGS_NO_ANY_TYPE             0x010
# define ASN1_PCTX_FLAGS_NO_FIELD_NAME           0x040
# define ASN1_PCTX_FLAGS_NO_MSTRING_TYPE         0x020
# define ASN1_PCTX_FLAGS_NO_STRUCT_NAME          0x100
# define ASN1_PCTX_FLAGS_SHOW_ABSENT             0x001
# define ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME  0x080
# define ASN1_PCTX_FLAGS_SHOW_SEQUENCE           0x002
# define ASN1_PCTX_FLAGS_SHOW_SSOF               0x004
# define ASN1_PCTX_FLAGS_SHOW_TYPE               0x008
# define ASN1_STRFLGS_DUMP_ALL           0x80
# define ASN1_STRFLGS_DUMP_DER           0x200
# define ASN1_STRFLGS_DUMP_UNKNOWN       0x100
# define ASN1_STRFLGS_ESC_2253           1
#define ASN1_STRFLGS_ESC_2254           0x400
# define ASN1_STRFLGS_ESC_CTRL           2
# define ASN1_STRFLGS_ESC_MSB            4
# define ASN1_STRFLGS_ESC_QUOTE          8
# define ASN1_STRFLGS_IGNORE_TYPE        0x20
# define ASN1_STRFLGS_RFC2253    (ASN1_STRFLGS_ESC_2253 | \
                                ASN1_STRFLGS_ESC_CTRL | \
                                ASN1_STRFLGS_ESC_MSB | \
                                ASN1_STRFLGS_UTF8_CONVERT | \
                                ASN1_STRFLGS_DUMP_UNKNOWN | \
                                ASN1_STRFLGS_DUMP_DER)
# define ASN1_STRFLGS_SHOW_TYPE          0x40
# define ASN1_STRFLGS_UTF8_CONVERT       0x10
# define ASN1_STRING_FLAG_BITS_LEFT 0x08
# define ASN1_STRING_FLAG_CONT 0x020
# define ASN1_STRING_FLAG_EMBED 0x080
# define ASN1_STRING_FLAG_MSTRING 0x040
# define ASN1_STRING_FLAG_NDEF 0x010
# define ASN1_STRING_FLAG_X509_TIME 0x100
#  define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
                          CHECKED_D2I_OF(type, d2i), \
                          in, \
                          CHECKED_PPTR_OF(type, x)))
#  define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
                        CHECKED_D2I_OF(type, d2i), \
                        in, \
                        CHECKED_PPTR_OF(type, x)))
# define ASN1_dup_of(type,i2d,d2i,x) \
    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
                     CHECKED_D2I_OF(type, d2i), \
                     CHECKED_PTR_OF(type, x)))
# define ASN1_dup_of_const(type,i2d,d2i,x) \
    ((type*)ASN1_dup(CHECKED_I2D_OF(const type, i2d), \
                     CHECKED_D2I_OF(type, d2i), \
                     CHECKED_PTR_OF(const type, x)))
#  define ASN1_i2d_bio_of(type,i2d,out,x) \
    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
                  out, \
                  CHECKED_PTR_OF(type, x)))
#  define ASN1_i2d_bio_of_const(type,i2d,out,x) \
    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
                  out, \
                  CHECKED_PTR_OF(const type, x)))
#  define ASN1_i2d_fp_of(type,i2d,out,x) \
    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
                 out, \
                 CHECKED_PTR_OF(type, x)))
#  define ASN1_i2d_fp_of_const(type,i2d,out,x) \
    (ASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
                 out, \
                 CHECKED_PTR_OF(const type, x)))
# define B_ASN1_BIT_STRING       0x0400
# define B_ASN1_BMPSTRING        0x0800
# define B_ASN1_DIRECTORYSTRING \
                        B_ASN1_PRINTABLESTRING| \
                        B_ASN1_TELETEXSTRING|\
                        B_ASN1_BMPSTRING|\
                        B_ASN1_UNIVERSALSTRING|\
                        B_ASN1_UTF8STRING
# define B_ASN1_DISPLAYTEXT \
                        B_ASN1_IA5STRING| \
                        B_ASN1_VISIBLESTRING| \
                        B_ASN1_BMPSTRING|\
                        B_ASN1_UTF8STRING
# define B_ASN1_GENERALIZEDTIME  0x8000
# define B_ASN1_GENERALSTRING    0x0080
# define B_ASN1_GRAPHICSTRING    0x0020
# define B_ASN1_IA5STRING        0x0010
# define B_ASN1_ISO64STRING      0x0040
# define B_ASN1_NUMERICSTRING    0x0001
# define B_ASN1_OCTET_STRING     0x0200
# define B_ASN1_PRINTABLE \
                        B_ASN1_NUMERICSTRING| \
                        B_ASN1_PRINTABLESTRING| \
                        B_ASN1_T61STRING| \
                        B_ASN1_IA5STRING| \
                        B_ASN1_BIT_STRING| \
                        B_ASN1_UNIVERSALSTRING|\
                        B_ASN1_BMPSTRING|\
                        B_ASN1_UTF8STRING|\
                        B_ASN1_SEQUENCE|\
                        B_ASN1_UNKNOWN
# define B_ASN1_PRINTABLESTRING  0x0002
# define B_ASN1_SEQUENCE         0x10000
# define B_ASN1_T61STRING        0x0004
# define B_ASN1_TELETEXSTRING    0x0004
# define B_ASN1_TIME \
                        B_ASN1_UTCTIME | \
                        B_ASN1_GENERALIZEDTIME
# define B_ASN1_UNIVERSALSTRING  0x0100
# define B_ASN1_UNKNOWN          0x1000
# define B_ASN1_UTCTIME          0x4000
# define B_ASN1_UTF8STRING       0x2000
# define B_ASN1_VIDEOTEXSTRING   0x0008
# define B_ASN1_VISIBLESTRING    0x0040
# define CHARTYPE_FIRST_ESC_2253         0x20
# define CHARTYPE_LAST_ESC_2253          0x40
# define CHARTYPE_PRINTABLESTRING        0x10
# define CHECKED_D2I_OF(type, d2i) \
    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
# define CHECKED_I2D_OF(type, i2d) \
    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
# define CHECKED_NEW_OF(type, xnew) \
    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
# define CHECKED_PPTR_OF(type, p) \
    ((void**) (1 ? p : (type**)0))
# define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
# define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
# define DECLARE_ASN1_ALLOC_FUNCTIONS(type) \
        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)
# define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        type *name##_new(void); \
        void name##_free(type *a);
# define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) \
        type *d2i_##name(type **a, const unsigned char **in, long len); \
        int i2d_##name(type *a, unsigned char **out); \
        DECLARE_ASN1_ITEM(itname)
# define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
        type *d2i_##name(type **a, const unsigned char **in, long len); \
        int i2d_##name(const type *a, unsigned char **out); \
        DECLARE_ASN1_ITEM(name)
# define DECLARE_ASN1_FUNCTIONS(type) DECLARE_ASN1_FUNCTIONS_name(type, type)
# define DECLARE_ASN1_FUNCTIONS_const(name) \
        DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
        DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)
# define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)
# define DECLARE_ASN1_FUNCTIONS_name(type, name) \
        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)
#  define DECLARE_ASN1_ITEM(name) \
        OPENSSL_EXTERN const ASN1_ITEM name##_it;
# define DECLARE_ASN1_NDEF_FUNCTION(name) \
        int i2d_##name##_NDEF(name *a, unsigned char **out);
# define DECLARE_ASN1_PRINT_FUNCTION(stname) \
        DECLARE_ASN1_PRINT_FUNCTION_fname(stname, stname)
# define DECLARE_ASN1_PRINT_FUNCTION_fname(stname, fname) \
        int fname##_print_ctx(BIO *out, stname *x, int indent, \
                                         const ASN1_PCTX *pctx);
# define DIRSTRING_TYPE  \
 (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING)
# define HEADER_ASN1_H
# define I2D_OF(type) int (*)(type *,unsigned char **)
# define I2D_OF_const(type) int (*)(const type *,unsigned char **)
# define MBSTRING_ASC            (MBSTRING_FLAG|1)
# define MBSTRING_BMP            (MBSTRING_FLAG|2)
# define MBSTRING_FLAG           0x1000
# define MBSTRING_UNIV           (MBSTRING_FLAG|4)
# define MBSTRING_UTF8           (MBSTRING_FLAG)
# define M_ASN1_free_of(x, type) \
                ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))
# define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
# define PKCS9STRING_TYPE (DIRSTRING_TYPE|B_ASN1_IA5STRING)
# define SMIME_CRLFEOL           0x800
# define SMIME_OLDMIME           0x400
# define SMIME_STREAM            0x1000
# define STABLE_FLAGS_CLEAR      STABLE_FLAGS_MALLOC
# define STABLE_FLAGS_MALLOC     0x01
# define STABLE_NO_MASK          0x02
# define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)
# define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
# define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
# define V_ASN1_ANY                      -4
# define V_ASN1_APPLICATION              0x40
# define V_ASN1_APP_CHOOSE               -2
# define V_ASN1_BIT_STRING               3
# define V_ASN1_BMPSTRING                30
# define V_ASN1_BOOLEAN                  1 
# define V_ASN1_CONSTRUCTED              0x20
# define V_ASN1_CONTEXT_SPECIFIC         0x80
# define V_ASN1_ENUMERATED               10
# define V_ASN1_EOC                      0
# define V_ASN1_EXTERNAL                 8
# define V_ASN1_GENERALIZEDTIME          24 
# define V_ASN1_GENERALSTRING            27 
# define V_ASN1_GRAPHICSTRING            25 
# define V_ASN1_IA5STRING                22
# define V_ASN1_INTEGER                  2
# define V_ASN1_ISO64STRING              26 
# define V_ASN1_NEG                      0x100
# define V_ASN1_NEG_ENUMERATED           (10 | V_ASN1_NEG)
# define V_ASN1_NEG_INTEGER              (2 | V_ASN1_NEG)
# define V_ASN1_NULL                     5
# define V_ASN1_NUMERICSTRING            18 
# define V_ASN1_OBJECT                   6
# define V_ASN1_OBJECT_DESCRIPTOR        7
# define V_ASN1_OCTET_STRING             4
# define V_ASN1_OTHER                    -3
# define V_ASN1_PRIMATIVE_TAG  V_ASN1_PRIMITIVE_TAG
# define V_ASN1_PRIMITIVE_TAG            0x1f
# define V_ASN1_PRINTABLESTRING          19
# define V_ASN1_PRIVATE                  0xc0
# define V_ASN1_REAL                     9
# define V_ASN1_SEQUENCE                 16
# define V_ASN1_SET                      17
# define V_ASN1_T61STRING                20
# define V_ASN1_TELETEXSTRING            20
# define V_ASN1_UNDEF                    -1
# define V_ASN1_UNIVERSAL                0x00
# define V_ASN1_UNIVERSALSTRING          28 
# define V_ASN1_UTCTIME                  23
# define V_ASN1_UTF8STRING               12
# define V_ASN1_VIDEOTEXSTRING           21 
# define V_ASN1_VISIBLESTRING            26
# define ub_common_name                  64
# define ub_email_address                128
# define ub_locality_name                128
# define ub_name                         32768
# define ub_organization_name            64
# define ub_organization_unit_name       64
# define ub_state_name                   128
# define ub_title                        64
