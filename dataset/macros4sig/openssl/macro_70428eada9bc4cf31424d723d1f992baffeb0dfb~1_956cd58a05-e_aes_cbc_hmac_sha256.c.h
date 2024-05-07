#include<string.h>


#include<stdio.h>
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
        if(inl < bl) return 1;\
        inl -= bl; \
        for(i=0; i <= inl; i+=bl)
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
        size_t chunk=EVP_MAXCHUNK;\
        if (cbits==1)  chunk>>=3;\
        if (inl<chunk) chunk=inl;\
        while(inl && inl>=chunk)\
            {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_cfb##cbits##_encrypt(in, out, (long)((cbits==1) && !EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) ?inl*8:inl), &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num, EVP_CIPHER_CTX_encrypting(ctx)); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
            inl-=chunk;\
            in +=chunk;\
            out+=chunk;\
            if(inl<chunk) chunk=inl;\
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
# define HEADER_RAND_H
# define RAND_F_FIPS_RAND                                 102
# define RAND_F_FIPS_RAND_SET_DT                          103
# define RAND_F_FIPS_SET_PRNG_SEED                        104
# define RAND_F_FIPS_SET_TEST_MODE                        105
# define RAND_F_FIPS_X931_SET_DT                          106
# define RAND_F_RAND_BYTES                                100
# define RAND_F_RAND_GET_RAND_METHOD                      101
# define RAND_R_NOT_IN_TEST_MODE                          101
# define RAND_R_NO_KEY_SET                                102
# define RAND_R_PRNG_ERROR                                103
# define RAND_R_PRNG_KEYED                                104
# define RAND_R_PRNG_NOT_SEEDED                           100
# define RAND_R_PRNG_SEED_MUST_NOT_MATCH_KEY              105
# define RAND_R_PRNG_STUCK                                106
# define RAND_cleanup() while(0) continue
# define HEADER_SHA_H
# define SHA224_DIGEST_LENGTH    28
# define SHA256_CBLOCK   (SHA_LBLOCK*4)
# define SHA256_DIGEST_LENGTH    32
# define SHA384_DIGEST_LENGTH    48
# define SHA512_CBLOCK   (SHA_LBLOCK*8)
# define SHA512_DIGEST_LENGTH    64
# define SHA_CBLOCK      (SHA_LBLOCK*4)
# define SHA_DIGEST_LENGTH 20
# define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
# define SHA_LBLOCK      16
# define SHA_LONG unsigned int
#  define SHA_LONG64 unsigned __int64
#  define U64(C)     C##UI64
# define AES_BLOCK_SIZE 16
# define AES_DECRYPT     0
# define AES_ENCRYPT     1
# define AES_MAXNR 14
# define HEADER_AES_H
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
#  define LN_OCSP_sign                    "OCSP Signing"
#  define LN_SMIMECapabilities            "S/MIME Capabilities"
#  define LN_X500                         "X500"
#  define LN_X509                         "X509"
#  define LN_ad_OCSP                      "OCSP"
#  define LN_ad_ca_issuers                "CA Issuers"
#  define LN_algorithm                    "algorithm"
#  define LN_authority_key_identifier     "X509v3 Authority Key Identifier"
#  define LN_basic_constraints            "X509v3 Basic Constraints"
#  define LN_bf_cbc                       "bf-cbc"
#  define LN_bf_cfb64                     "bf-cfb"
#  define LN_bf_ecb                       "bf-ecb"
#  define LN_bf_ofb64                     "bf-ofb"
#  define LN_cast5_cbc                    "cast5-cbc"
#  define LN_cast5_cfb64                  "cast5-cfb"
#  define LN_cast5_ecb                    "cast5-ecb"
#  define LN_cast5_ofb64                  "cast5-ofb"
#  define LN_certBag              "certBag"
#  define LN_certificate_policies         "X509v3 Certificate Policies"
#  define LN_client_auth                  "TLS Web Client Authentication"
#  define LN_code_sign                    "Code Signing"
#  define LN_commonName                   "commonName"
#  define LN_countryName                  "countryName"
#  define LN_crlBag               "crlBag"
#  define LN_crl_distribution_points      "X509v3 CRL Distribution Points"
#  define LN_crl_number                   "X509v3 CRL Number"
#  define LN_crl_reason                   "CRL Reason Code"
#  define LN_delta_crl                    "X509v3 Delta CRL Indicator"
#  define LN_des_cbc                      "des-cbc"
#  define LN_des_cfb64                    "des-cfb"
#  define LN_des_ecb                      "des-ecb"
#  define LN_des_ede                      "des-ede"
#  define LN_des_ede3                     "des-ede3"
#  define LN_des_ede3_cbc                 "des-ede3-cbc"
#  define LN_des_ede3_cfb64               "des-ede3-cfb"
#  define LN_des_ede3_ofb64               "des-ede3-ofb"
#  define LN_des_ede_cbc                  "des-ede-cbc"
#  define LN_des_ede_cfb64                "des-ede-cfb"
#  define LN_des_ede_ofb64                "des-ede-ofb"
#  define LN_des_ofb64                    "des-ofb"
#  define LN_description                  "description"
#  define LN_desx_cbc                     "desx-cbc"
#  define LN_dhKeyAgreement               "dhKeyAgreement"
#  define LN_dnQualifier                  "dnQualifier"
#  define LN_dsa                          "dsaEncryption"
#  define LN_dsaWithSHA                   "dsaWithSHA"
#  define LN_dsaWithSHA1                  "dsaWithSHA1"
#  define LN_dsaWithSHA1_2                "dsaWithSHA1-old"
#  define LN_dsa_2                        "dsaEncryption-old"
#  define LN_email_protect                "E-mail Protection"
#  define LN_ext_key_usage                "X509v3 Extended Key Usage"
#  define LN_ext_req                      "Extension Request"
#  define LN_friendlyName         "friendlyName"
#  define LN_givenName                    "givenName"
#  define LN_hmacWithSHA1         "hmacWithSHA1"
#  define LN_id_pbkdf2                    "PBKDF2"
#  define LN_id_qt_cps            "Policy Qualifier CPS"
#  define LN_id_qt_unotice        "Policy Qualifier User Notice"
#  define LN_idea_cbc                     "idea-cbc"
#  define LN_idea_cfb64                   "idea-cfb"
#  define LN_idea_ecb                     "idea-ecb"
#  define LN_idea_ofb64                   "idea-ofb"
#  define LN_info_access                  "Authority Information Access"
#  define LN_initials                     "initials"
#  define LN_invalidity_date              "Invalidity Date"
#  define LN_issuer_alt_name              "X509v3 Issuer Alternative Name"
#  define LN_keyBag               "keyBag"
#  define LN_key_usage                    "X509v3 Key Usage"
#  define LN_localKeyID           "localKeyID"
#  define LN_localityName                 "localityName"
#  define LN_md2                          "md2"
#  define LN_md2WithRSAEncryption         "md2WithRSAEncryption"
#  define LN_md5                          "md5"
#  define LN_md5WithRSA                   "md5WithRSA"
#  define LN_md5WithRSAEncryption         "md5WithRSAEncryption"
#  define LN_md5_sha1                     "md5-sha1"
#  define LN_mdc2                         "mdc2"
#  define LN_mdc2WithRSA                  "mdc2withRSA"
#  define LN_ms_code_com                  "Microsoft Commercial Code Signing"
#  define LN_ms_code_ind                  "Microsoft Individual Code Signing"
#  define LN_ms_ctl_sign                  "Microsoft Trust List Signing"
#  define LN_ms_efs                       "Microsoft Encrypted File System"
#  define LN_ms_ext_req                   "Microsoft Extension Request"
#  define LN_ms_sgc                       "Microsoft Server Gated Crypto"
#  define LN_name                         "name"
#  define LN_netscape                     "Netscape Communications Corp."
#  define LN_netscape_base_url            "Netscape Base Url"
#  define LN_netscape_ca_policy_url       "Netscape CA Policy Url"
#  define LN_netscape_ca_revocation_url   "Netscape CA Revocation Url"
#  define LN_netscape_cert_extension      "Netscape Certificate Extension"
#  define LN_netscape_cert_sequence       "Netscape Certificate Sequence"
#  define LN_netscape_cert_type           "Netscape Cert Type"
#  define LN_netscape_comment             "Netscape Comment"
#  define LN_netscape_data_type           "Netscape Data Type"
#  define LN_netscape_renewal_url         "Netscape Renewal Url"
#  define LN_netscape_revocation_url      "Netscape Revocation Url"
#  define LN_netscape_ssl_server_name     "Netscape SSL Server Name"
#  define LN_ns_sgc                       "Netscape Server Gated Crypto"
#  define LN_organizationName             "organizationName"
#  define LN_organizationalUnitName       "organizationalUnitName"
#  define LN_pbeWithMD2AndDES_CBC         "pbeWithMD2AndDES-CBC"
#  define LN_pbeWithMD2AndRC2_CBC         "pbeWithMD2AndRC2-CBC"
#  define LN_pbeWithMD5AndCast5_CBC       "pbeWithMD5AndCast5CBC"
#  define LN_pbeWithMD5AndDES_CBC         "pbeWithMD5AndDES-CBC"
#  define LN_pbeWithMD5AndRC2_CBC         "pbeWithMD5AndRC2-CBC"
#  define LN_pbeWithSHA1AndDES_CBC        "pbeWithSHA1AndDES-CBC"
#  define LN_pbeWithSHA1AndRC2_CBC        "pbeWithSHA1AndRC2-CBC"
#  define LN_pbe_WithSHA1And128BitRC2_CBC         "pbeWithSHA1And128BitRC2-CBC"
#  define LN_pbe_WithSHA1And128BitRC4     "pbeWithSHA1And128BitRC4"
#  define LN_pbe_WithSHA1And2_Key_TripleDES_CBC   "pbeWithSHA1And2-KeyTripleDES-CBC"
#  define LN_pbe_WithSHA1And3_Key_TripleDES_CBC   "pbeWithSHA1And3-KeyTripleDES-CBC"
#  define LN_pbe_WithSHA1And40BitRC2_CBC  "pbeWithSHA1And40BitRC2-CBC"
#  define LN_pbe_WithSHA1And40BitRC4      "pbeWithSHA1And40BitRC4"
#  define LN_pbes2                "PBES2"
#  define LN_pbmac1               "PBMAC1"
#  define LN_pkcs                         "pkcs"
#  define LN_pkcs3                        "pkcs3"
#  define LN_pkcs7                        "pkcs7"
#  define LN_pkcs7_data                   "pkcs7-data"
#  define LN_pkcs7_digest                 "pkcs7-digestData"
#  define LN_pkcs7_encrypted              "pkcs7-encryptedData"
#  define LN_pkcs7_enveloped              "pkcs7-envelopedData"
#  define LN_pkcs7_signed                 "pkcs7-signedData"
#  define LN_pkcs7_signedAndEnveloped     "pkcs7-signedAndEnvelopedData"
#  define LN_pkcs8ShroudedKeyBag  "pkcs8ShroudedKeyBag"
#  define LN_pkcs9                        "pkcs9"
#  define LN_pkcs9_challengePassword      "challengePassword"
#  define LN_pkcs9_contentType            "contentType"
#  define LN_pkcs9_countersignature       "countersignature"
#  define LN_pkcs9_emailAddress           "emailAddress"
#  define LN_pkcs9_extCertAttributes      "extendedCertificateAttributes"
#  define LN_pkcs9_messageDigest          "messageDigest"
#  define LN_pkcs9_signingTime            "signingTime"
#  define LN_pkcs9_unstructuredAddress    "unstructuredAddress"
#  define LN_pkcs9_unstructuredName       "unstructuredName"
#  define LN_private_key_usage_period     "X509v3 Private Key Usage Period"
#  define LN_rc2_40_cbc                   "rc2-40-cbc"
#  define LN_rc2_64_cbc                   "rc2-64-cbc"
#  define LN_rc2_cbc                      "rc2-cbc"
#  define LN_rc2_cfb64                    "rc2-cfb"
#  define LN_rc2_ecb                      "rc2-ecb"
#  define LN_rc2_ofb64                    "rc2-ofb"
#  define LN_rc4                          "rc4"
#  define LN_rc4_40                       "rc4-40"
#  define LN_rc5_cbc                      "rc5-cbc"
#  define LN_rc5_cfb64                    "rc5-cfb"
#  define LN_rc5_ecb                      "rc5-ecb"
#  define LN_rc5_ofb64                    "rc5-ofb"
#  define LN_ripemd160                    "ripemd160"
#  define LN_ripemd160WithRSA             "ripemd160WithRSA"
#  define LN_rle_compression              "run length compression"
#  define LN_rsa                          "rsa"
#  define LN_rsaEncryption                "rsaEncryption"
#  define LN_rsadsi                       "rsadsi"
#  define LN_safeContentsBag      "safeContentsBag"
#  define LN_sdsiCertificate      "sdsiCertificate"
#  define LN_secretBag            "secretBag"
#  define LN_serialNumber                 "serialNumber"
#  define LN_server_auth                  "TLS Web Server Authentication"
#  define LN_sha                          "sha"
#  define LN_sha1                         "sha1"
#  define LN_sha1WithRSA                  "sha1WithRSA"
#  define LN_sha1WithRSAEncryption        "sha1WithRSAEncryption"
#  define LN_shaWithRSAEncryption         "shaWithRSAEncryption"
#  define LN_stateOrProvinceName          "stateOrProvinceName"
#  define LN_subject_alt_name             "X509v3 Subject Alternative Name"
#  define LN_subject_key_identifier       "X509v3 Subject Key Identifier"
#  define LN_surname                      "surname"
#  define LN_sxnet                        "Strong Extranet ID"
#  define LN_time_stamp                   "Time Stamping"
#  define LN_title                        "title"
#  define LN_undef                        "undefined"
#  define LN_uniqueIdentifier             "uniqueIdentifier"
#  define LN_x509Certificate      "x509Certificate"
#  define LN_x509Crl              "x509Crl"
#  define LN_zlib_compression             "zlib compression"
#  define NID_OCSP_sign                   180
#  define NID_SMIMECapabilities           167
#  define NID_X500                        11
#  define NID_X509                        12
#  define NID_ad_OCSP                     178
#  define NID_ad_ca_issuers               179
#  define NID_algorithm                   38
#  define NID_authority_key_identifier    90
#  define NID_basic_constraints           87
#  define NID_bf_cbc                      91
#  define NID_bf_cfb64                    93
#  define NID_bf_ecb                      92
#  define NID_bf_ofb64                    94
#  define NID_cast5_cbc                   108
#  define NID_cast5_cfb64                 110
#  define NID_cast5_ecb                   109
#  define NID_cast5_ofb64                 111
#  define NID_certBag             152
#  define NID_certificate_policies        89
#  define NID_client_auth                 130
#  define NID_code_sign                   131
#  define NID_commonName                  13
#  define NID_countryName                 14
#  define NID_crlBag              153
#  define NID_crl_distribution_points     103
#  define NID_crl_number                  88
#  define NID_crl_reason                  141
#  define NID_delta_crl                   140
#  define NID_des_cbc                     31
#  define NID_des_cfb64                   30
#  define NID_des_ecb                     29
#  define NID_des_ede                     32
#  define NID_des_ede3                    33
#  define NID_des_ede3_cbc                44
#  define NID_des_ede3_cfb64              61
#  define NID_des_ede3_ofb64              63
#  define NID_des_ede_cbc                 43
#  define NID_des_ede_cfb64               60
#  define NID_des_ede_ofb64               62
#  define NID_des_ofb64                   45
#  define NID_description                 107
#  define NID_desx_cbc                    80
#  define NID_dhKeyAgreement              28
#  define NID_dnQualifier                 174
#  define NID_dsa                         116
#  define NID_dsaWithSHA                  66
#  define NID_dsaWithSHA1                 113
#  define NID_dsaWithSHA1_2               70
#  define NID_dsa_2                       67
#  define NID_email_protect               132
#  define NID_ext_key_usage               126
#  define NID_ext_req                     172
#  define NID_friendlyName        156
#  define NID_givenName                   99
#  define NID_hmacWithSHA1        163
#  define NID_id_ad                       176
#  define NID_id_ce                       81
#  define NID_id_kp                       128
#  define NID_id_pbkdf2                   69
#  define NID_id_pe                       175
#  define NID_id_pkix                     127
#  define NID_id_qt_cps           164
#  define NID_id_qt_unotice       165
#  define NID_idea_cbc                    34
#  define NID_idea_cfb64                  35
#  define NID_idea_ecb                    36
#  define NID_idea_ofb64                  46
#  define NID_info_access                 177
#  define NID_initials                    101
#  define NID_invalidity_date             142
#  define NID_issuer_alt_name             86
#  define NID_keyBag              150
#  define NID_key_usage                   83
#  define NID_localKeyID          157
#  define NID_localityName                15
#  define NID_md2                         3
#  define NID_md2WithRSAEncryption        7
#  define NID_md5                         4
#  define NID_md5WithRSA                  104
#  define NID_md5WithRSAEncryption        8
#  define NID_md5_sha1                    114
#  define NID_mdc2                        95
#  define NID_mdc2WithRSA                 96
#  define NID_ms_code_com                 135
#  define NID_ms_code_ind                 134
#  define NID_ms_ctl_sign                 136
#  define NID_ms_efs                      138
#  define NID_ms_ext_req                  171
#  define NID_ms_sgc                      137
#  define NID_name                        173
#  define NID_netscape                    57
#  define NID_netscape_base_url           72
#  define NID_netscape_ca_policy_url      76
#  define NID_netscape_ca_revocation_url  74
#  define NID_netscape_cert_extension     58
#  define NID_netscape_cert_sequence      79
#  define NID_netscape_cert_type          71
#  define NID_netscape_comment            78
#  define NID_netscape_data_type          59
#  define NID_netscape_renewal_url        75
#  define NID_netscape_revocation_url     73
#  define NID_netscape_ssl_server_name    77
#  define NID_ns_sgc                      139
#  define NID_organizationName            17
#  define NID_organizationalUnitName      18
#  define NID_pbeWithMD2AndDES_CBC        9
#  define NID_pbeWithMD2AndRC2_CBC        168
#  define NID_pbeWithMD5AndCast5_CBC      112
#  define NID_pbeWithMD5AndDES_CBC        10
#  define NID_pbeWithMD5AndRC2_CBC        169
#  define NID_pbeWithSHA1AndDES_CBC       170
#  define NID_pbeWithSHA1AndRC2_CBC       68
#  define NID_pbe_WithSHA1And128BitRC2_CBC        148
#  define NID_pbe_WithSHA1And128BitRC4    144
#  define NID_pbe_WithSHA1And2_Key_TripleDES_CBC  147
#  define NID_pbe_WithSHA1And3_Key_TripleDES_CBC  146
#  define NID_pbe_WithSHA1And40BitRC2_CBC 149
#  define NID_pbe_WithSHA1And40BitRC4     145
#  define NID_pbes2               161
#  define NID_pbmac1              162
#  define NID_pkcs                        2
#  define NID_pkcs3                       27
#  define NID_pkcs7                       20
#  define NID_pkcs7_data                  21
#  define NID_pkcs7_digest                25
#  define NID_pkcs7_encrypted             26
#  define NID_pkcs7_enveloped             23
#  define NID_pkcs7_signed                22
#  define NID_pkcs7_signedAndEnveloped    24
#  define NID_pkcs8ShroudedKeyBag 151
#  define NID_pkcs9                       47
#  define NID_pkcs9_challengePassword     54
#  define NID_pkcs9_contentType           50
#  define NID_pkcs9_countersignature      53
#  define NID_pkcs9_emailAddress          48
#  define NID_pkcs9_extCertAttributes     56
#  define NID_pkcs9_messageDigest         51
#  define NID_pkcs9_signingTime           52
#  define NID_pkcs9_unstructuredAddress   55
#  define NID_pkcs9_unstructuredName      49
#  define NID_private_key_usage_period    84
#  define NID_rc2_40_cbc                  98
#  define NID_rc2_64_cbc                  166
#  define NID_rc2_cbc                     37
#  define NID_rc2_cfb64                   39
#  define NID_rc2_ecb                     38
#  define NID_rc2_ofb64                   40
#  define NID_rc4                         5
#  define NID_rc4_40                      97
#  define NID_rc5_cbc                     120
#  define NID_rc5_cfb64                   122
#  define NID_rc5_ecb                     121
#  define NID_rc5_ofb64                   123
#  define NID_ripemd160                   117
#  define NID_ripemd160WithRSA            119
#  define NID_rle_compression             124
#  define NID_rsa                         19
#  define NID_rsaEncryption               6
#  define NID_rsadsi                      1
#  define NID_safeContentsBag     155
#  define NID_sdsiCertificate     159
#  define NID_secretBag           154
#  define NID_serialNumber                105
#  define NID_server_auth                 129
#  define NID_sha                         41
#  define NID_sha1                        64
#  define NID_sha1WithRSA                 115
#  define NID_sha1WithRSAEncryption       65
#  define NID_shaWithRSAEncryption        42
#  define NID_stateOrProvinceName         16
#  define NID_subject_alt_name            85
#  define NID_subject_key_identifier      82
#  define NID_surname                     100
#  define NID_sxnet                       143
#  define NID_time_stamp                  133
#  define NID_title                       106
#  define NID_undef                       0
#  define NID_uniqueIdentifier            102
#  define NID_x509Certificate     158
#  define NID_x509Crl             160
#  define NID_zlib_compression            125
# define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH        0x02
# define OBJ_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OBJ_F_OBJ_ADD_OBJECT                             105
# define OBJ_F_OBJ_CREATE                                 100
# define OBJ_F_OBJ_DUP                                    101
# define OBJ_F_OBJ_NAME_NEW_INDEX                         106
# define OBJ_F_OBJ_NID2LN                                 102
# define OBJ_F_OBJ_NID2OBJ                                103
# define OBJ_F_OBJ_NID2SN                                 104
# define OBJ_NAME_ALIAS                  0x8000
# define OBJ_NAME_TYPE_CIPHER_METH       0x02
# define OBJ_NAME_TYPE_COMP_METH         0x04
# define OBJ_NAME_TYPE_MD_METH           0x01
# define OBJ_NAME_TYPE_NUM               0x05
# define OBJ_NAME_TYPE_PKEY_METH         0x03
# define OBJ_NAME_TYPE_UNDEF             0x00
#  define OBJ_OCSP_sign                   OBJ_id_kp,9L
# define OBJ_R_MALLOC_FAILURE                             100
# define OBJ_R_UNKNOWN_NID                                101
#  define OBJ_SMIMECapabilities           OBJ_pkcs9,15L
#  define OBJ_X500                        2L,5L
#  define OBJ_X509                        OBJ_X500,4L
#  define OBJ_ad_OCSP                     OBJ_id_ad,1L
#  define OBJ_ad_ca_issuers               OBJ_id_ad,2L
#  define OBJ_algorithm                   1L,3L,14L,3L,2L
#  define OBJ_authority_key_identifier    OBJ_id_ce,35L
#  define OBJ_basic_constraints           OBJ_id_ce,19L
#  define OBJ_bf_cbc                      1L,3L,6L,1L,4L,1L,3029L,1L,2L
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
#  define OBJ_cast5_cbc                   1L,2L,840L,113533L,7L,66L,10L
#  define OBJ_certBag             OBJ_pkcs12_BagIds, 3L
#  define OBJ_certTypes           OBJ_pkcs9, 22L
#  define OBJ_certificate_policies        OBJ_id_ce,32L
# define OBJ_cleanup() while(0) continue
#  define OBJ_client_auth                 OBJ_id_kp,2L
#  define OBJ_code_sign                   OBJ_id_kp,3L
#  define OBJ_commonName                  OBJ_X509,3L
#  define OBJ_countryName                 OBJ_X509,6L
# define         OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)
#  define OBJ_crlBag              OBJ_pkcs12_BagIds, 4L
#  define OBJ_crlTypes            OBJ_pkcs9, 23L
#  define OBJ_crl_distribution_points     OBJ_id_ce,31L
#  define OBJ_crl_number                  OBJ_id_ce,20L
#  define OBJ_crl_reason                  OBJ_id_ce,21L
#  define OBJ_delta_crl                   OBJ_id_ce,27L
#  define OBJ_des_cbc                     OBJ_algorithm,7L
#  define OBJ_des_cfb64                   OBJ_algorithm,9L
#  define OBJ_des_ecb                     OBJ_algorithm,6L
#  define OBJ_des_ede                     OBJ_algorithm,17L
#  define OBJ_des_ede3_cbc                OBJ_rsadsi,3L,7L
#  define OBJ_des_ofb64                   OBJ_algorithm,8L
#  define OBJ_description                 OBJ_X509,13L
#  define OBJ_dhKeyAgreement              OBJ_pkcs3,1L
#  define OBJ_dnQualifier                 OBJ_X509,46L
#  define OBJ_dsa                         1L,2L,840L,10040L,4L,1L
#  define OBJ_dsaWithSHA                  OBJ_algorithm,13L
#  define OBJ_dsaWithSHA1                 1L,2L,840L,10040L,4L,3L
#  define OBJ_dsaWithSHA1_2               OBJ_algorithm,27L
#  define OBJ_dsa_2                       OBJ_algorithm,12L
#  define OBJ_email_protect               OBJ_id_kp,4L
#  define OBJ_ext_key_usage               OBJ_id_ce,37
#  define OBJ_ext_req                     OBJ_pkcs9,14L
#  define OBJ_friendlyName        OBJ_pkcs9, 20L
#  define OBJ_givenName                   OBJ_X509,42L
#  define OBJ_hmacWithSHA1        OBJ_rsadsi,2L,7L
#  define OBJ_id_ad                       OBJ_id_pkix,48L
#  define OBJ_id_ce                       2L,5L,29L
#  define OBJ_id_kp                       OBJ_id_pkix,3L
#  define OBJ_id_pbkdf2                   OBJ_pkcs,5L,12L
#  define OBJ_id_pe                       OBJ_id_pkix,1L
#  define OBJ_id_pkix                     1L,3L,6L,1L,5L,5L,7L
#  define OBJ_id_qt_cps           OBJ_id_pkix,2L,1L
#  define OBJ_id_qt_unotice       OBJ_id_pkix,2L,2L
#  define OBJ_idea_cbc                    1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L
#  define OBJ_info_access                 OBJ_id_pe,1L
#  define OBJ_initials                    OBJ_X509,43L
#  define OBJ_invalidity_date             OBJ_id_ce,24L
#  define OBJ_issuer_alt_name             OBJ_id_ce,18L
#  define OBJ_keyBag              OBJ_pkcs12_BagIds, 1L
#  define OBJ_key_usage                   OBJ_id_ce,15L
#  define OBJ_localKeyID          OBJ_pkcs9, 21L
#  define OBJ_localityName                OBJ_X509,7L
#  define OBJ_md2                         OBJ_rsadsi,2L,2L
#  define OBJ_md2WithRSAEncryption        OBJ_pkcs,1L,2L
#  define OBJ_md5                         OBJ_rsadsi,2L,5L
#  define OBJ_md5WithRSA                  OBJ_algorithm,3L
#  define OBJ_md5WithRSAEncryption        OBJ_pkcs,1L,4L
#  define OBJ_mdc2                        2L,5L,8L,3L,101L
#  define OBJ_mdc2WithRSA                 2L,5L,8L,3L,100L
#  define OBJ_ms_code_com                 1L,3L,6L,1L,4L,1L,311L,2L,1L,22L
#  define OBJ_ms_code_ind                 1L,3L,6L,1L,4L,1L,311L,2L,1L,21L
#  define OBJ_ms_ctl_sign                 1L,3L,6L,1L,4L,1L,311L,10L,3L,1L
#  define OBJ_ms_efs                      1L,3L,6L,1L,4L,1L,311L,10L,3L,4L
#  define OBJ_ms_ext_req                  1L,3L,6L,1L,4L,1L,311L,2L,1L,14L
#  define OBJ_ms_sgc                      1L,3L,6L,1L,4L,1L,311L,10L,3L,3L
#  define OBJ_name                        OBJ_X509,41L
#  define OBJ_netscape                    2L,16L,840L,1L,113730L
#  define OBJ_netscape_base_url           OBJ_netscape_cert_extension,2L
#  define OBJ_netscape_ca_policy_url      OBJ_netscape_cert_extension,8L
#  define OBJ_netscape_ca_revocation_url  OBJ_netscape_cert_extension,4L
#  define OBJ_netscape_cert_extension     OBJ_netscape,1L
#  define OBJ_netscape_cert_sequence      OBJ_netscape_data_type,5L
#  define OBJ_netscape_cert_type          OBJ_netscape_cert_extension,1L
#  define OBJ_netscape_comment            OBJ_netscape_cert_extension,13L
#  define OBJ_netscape_data_type          OBJ_netscape,2L
#  define OBJ_netscape_renewal_url        OBJ_netscape_cert_extension,7L
#  define OBJ_netscape_revocation_url     OBJ_netscape_cert_extension,3L
#  define OBJ_netscape_ssl_server_name    OBJ_netscape_cert_extension,12L
#  define OBJ_ns_sgc                      OBJ_netscape,4L,1L
#  define OBJ_organizationName            OBJ_X509,10L
#  define OBJ_organizationalUnitName      OBJ_X509,11L
#  define OBJ_pbeWithMD2AndDES_CBC        OBJ_pkcs,5L,1L
#  define OBJ_pbeWithMD2AndRC2_CBC        OBJ_pkcs,5L,4L
#  define OBJ_pbeWithMD5AndCast5_CBC      1L,2L,840L,113533L,7L,66L,12L
#  define OBJ_pbeWithMD5AndDES_CBC        OBJ_pkcs,5L,3L
#  define OBJ_pbeWithMD5AndRC2_CBC        OBJ_pkcs,5L,6L
#  define OBJ_pbeWithSHA1AndDES_CBC       OBJ_pkcs,5L,10L
#  define OBJ_pbeWithSHA1AndRC2_CBC       OBJ_pkcs,5L,11L
#  define OBJ_pbe_WithSHA1And128BitRC2_CBC        OBJ_pkcs12_pbeids, 5L
#  define OBJ_pbe_WithSHA1And128BitRC4    OBJ_pkcs12_pbeids, 1L
#  define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC  OBJ_pkcs12_pbeids, 4L
#  define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC  OBJ_pkcs12_pbeids, 3L
#  define OBJ_pbe_WithSHA1And40BitRC2_CBC OBJ_pkcs12_pbeids, 6L
#  define OBJ_pbe_WithSHA1And40BitRC4     OBJ_pkcs12_pbeids, 2L
#  define OBJ_pbes2               OBJ_pkcs,5L,13L
#  define OBJ_pbmac1              OBJ_pkcs,5L,14L
#  define OBJ_pkcs                        OBJ_rsadsi,1L
#  define OBJ_pkcs12                      OBJ_pkcs,12L
#  define OBJ_pkcs12_BagIds       OBJ_pkcs12_Version1, 1L
#  define OBJ_pkcs12_Version1     OBJ_pkcs12, 10L
#  define OBJ_pkcs12_pbeids               OBJ_pkcs12, 1
#  define OBJ_pkcs3                       OBJ_pkcs,3L
#  define OBJ_pkcs7                       OBJ_pkcs,7L
#  define OBJ_pkcs7_data                  OBJ_pkcs7,1L
#  define OBJ_pkcs7_digest                OBJ_pkcs7,5L
#  define OBJ_pkcs7_encrypted             OBJ_pkcs7,6L
#  define OBJ_pkcs7_enveloped             OBJ_pkcs7,3L
#  define OBJ_pkcs7_signed                OBJ_pkcs7,2L
#  define OBJ_pkcs7_signedAndEnveloped    OBJ_pkcs7,4L
#  define OBJ_pkcs8ShroudedKeyBag OBJ_pkcs12_BagIds, 2L
#  define OBJ_pkcs9                       OBJ_pkcs,9L
#  define OBJ_pkcs9_challengePassword     OBJ_pkcs9,7L
#  define OBJ_pkcs9_contentType           OBJ_pkcs9,3L
#  define OBJ_pkcs9_countersignature      OBJ_pkcs9,6L
#  define OBJ_pkcs9_emailAddress          OBJ_pkcs9,1L
#  define OBJ_pkcs9_extCertAttributes     OBJ_pkcs9,9L
#  define OBJ_pkcs9_messageDigest         OBJ_pkcs9,4L
#  define OBJ_pkcs9_signingTime           OBJ_pkcs9,5L
#  define OBJ_pkcs9_unstructuredAddress   OBJ_pkcs9,8L
#  define OBJ_pkcs9_unstructuredName      OBJ_pkcs9,2L
#  define OBJ_private_key_usage_period    OBJ_id_ce,16L
#  define OBJ_rc2_cbc                     OBJ_rsadsi,3L,2L
#  define OBJ_rc4                         OBJ_rsadsi,3L,4L
#  define OBJ_rc5_cbc                     OBJ_rsadsi,3L,8L
#  define OBJ_ripemd160                   1L,3L,36L,3L,2L,1L
#  define OBJ_ripemd160WithRSA            1L,3L,36L,3L,3L,1L,2L
#  define OBJ_rle_compression             1L,1L,1L,1L,666L,1L
#  define OBJ_rsa                         OBJ_X500,8L,1L,1L
#  define OBJ_rsaEncryption               OBJ_pkcs,1L,1L
#  define OBJ_rsadsi                      1L,2L,840L,113549L
#  define OBJ_safeContentsBag     OBJ_pkcs12_BagIds, 6L
#  define OBJ_sdsiCertificate     OBJ_certTypes, 2L
#  define OBJ_secretBag           OBJ_pkcs12_BagIds, 5L
#  define OBJ_serialNumber                OBJ_X509,5L
#  define OBJ_server_auth                 OBJ_id_kp,1L
#  define OBJ_sha                         OBJ_algorithm,18L
#  define OBJ_sha1                        OBJ_algorithm,26L
#  define OBJ_sha1WithRSA                 OBJ_algorithm,29L
#  define OBJ_sha1WithRSAEncryption       OBJ_pkcs,1L,5L
#  define OBJ_shaWithRSAEncryption        OBJ_algorithm,15L
#  define OBJ_stateOrProvinceName         OBJ_X509,8L
#  define OBJ_subject_alt_name            OBJ_id_ce,17L
#  define OBJ_subject_key_identifier      OBJ_id_ce,14L
#  define OBJ_surname                     OBJ_X509,4L
#  define OBJ_sxnet                       1L,3L,101L,1L,4L,1L
#  define OBJ_time_stamp                  OBJ_id_kp,8L
#  define OBJ_title                       OBJ_X509,12L
#  define OBJ_undef                       0L
#  define OBJ_uniqueIdentifier            OBJ_X509,45L
#  define OBJ_x509Certificate     OBJ_certTypes, 1L
#  define OBJ_x509Crl             OBJ_crlTypes, 1L
#  define OBJ_zlib_compression            1L,1L,1L,1L,666L,2L
#  define SN_Algorithm                    "Algorithm"
#  define SN_OCSP_sign                    "OCSPSigning"
#  define SN_SMIMECapabilities            "SMIME-CAPS"
#  define SN_ad_OCSP                      "OCSP"
#  define SN_ad_ca_issuers                "caIssuers"
#  define SN_authority_key_identifier     "authorityKeyIdentifier"
#  define SN_basic_constraints            "basicConstraints"
#  define SN_bf_cbc                       "BF-CBC"
#  define SN_bf_cfb64                     "BF-CFB"
#  define SN_bf_ecb                       "BF-ECB"
#  define SN_bf_ofb64                     "BF-OFB"
#  define SN_cast5_cbc                    "CAST5-CBC"
#  define SN_cast5_cfb64                  "CAST5-CFB"
#  define SN_cast5_ecb                    "CAST5-ECB"
#  define SN_cast5_ofb64                  "CAST5-OFB"
#  define SN_certificate_policies         "certificatePolicies"
#  define SN_client_auth                  "clientAuth"
#  define SN_code_sign                    "codeSigning"
#  define SN_commonName                   "CN"
#  define SN_countryName                  "C"
#  define SN_crl_distribution_points      "crlDistributionPoints"
#  define SN_crl_number                   "crlNumber"
#  define SN_crl_reason                   "CRLReason"
#  define SN_delta_crl                    "deltaCRL"
#  define SN_des_cbc                      "DES-CBC"
#  define SN_des_cfb64                    "DES-CFB"
#  define SN_des_ecb                      "DES-ECB"
#  define SN_des_ede                      "DES-EDE"
#  define SN_des_ede3                     "DES-EDE3"
#  define SN_des_ede3_cbc                 "DES-EDE3-CBC"
#  define SN_des_ede3_cfb64               "DES-EDE3-CFB"
#  define SN_des_ede3_ofb64               "DES-EDE3-OFB"
#  define SN_des_ede_cbc                  "DES-EDE-CBC"
#  define SN_des_ede_cfb64                "DES-EDE-CFB"
#  define SN_des_ede_ofb64                "DES-EDE-OFB"
#  define SN_des_ofb64                    "DES-OFB"
#  define SN_description                  "D"
#  define SN_desx_cbc                     "DESX-CBC"
#  define SN_dnQualifier                  "dnQualifier"
#  define SN_dsa                          "DSA"
#  define SN_dsaWithSHA                   "DSA-SHA"
#  define SN_dsaWithSHA1                  "DSA-SHA1"
#  define SN_dsaWithSHA1_2                "DSA-SHA1-old"
#  define SN_dsa_2                        "DSA-old"
#  define SN_email_protect                "emailProtection"
#  define SN_ext_key_usage                "extendedKeyUsage"
#  define SN_ext_req                      "extReq"
#  define SN_givenName                    "G"
#  define SN_id_ad                        "id-ad"
#  define SN_id_ce                        "id-ce"
#  define SN_id_kp                        "id-kp"
#  define SN_id_pe                        "id-pe"
#  define SN_id_pkix                      "PKIX"
#  define SN_id_qt_cps            "id-qt-cps"
#  define SN_id_qt_unotice        "id-qt-unotice"
#  define SN_idea_cbc                     "IDEA-CBC"
#  define SN_idea_cfb64                   "IDEA-CFB"
#  define SN_idea_ecb                     "IDEA-ECB"
#  define SN_idea_ofb64                   "IDEA-OFB"
#  define SN_info_access                  "authorityInfoAccess"
#  define SN_initials                     "I"
#  define SN_invalidity_date              "invalidityDate"
#  define SN_issuer_alt_name              "issuerAltName"
#  define SN_key_usage                    "keyUsage"
#  define SN_localityName                 "L"
#  define SN_md2                          "MD2"
#  define SN_md2WithRSAEncryption         "RSA-MD2"
#  define SN_md5                          "MD5"
#  define SN_md5WithRSA                   "RSA-NP-MD5"
#  define SN_md5WithRSAEncryption         "RSA-MD5"
#  define SN_md5_sha1                     "MD5-SHA1"
#  define SN_mdc2                         "MDC2"
#  define SN_mdc2WithRSA                  "RSA-MDC2"
#  define SN_ms_code_com                  "msCodeCom"
#  define SN_ms_code_ind                  "msCodeInd"
#  define SN_ms_ctl_sign                  "msCTLSign"
#  define SN_ms_efs                       "msEFS"
#  define SN_ms_ext_req                   "msExtReq"
#  define SN_ms_sgc                       "msSGC"
#  define SN_name                         "name"
#  define SN_netscape                     "Netscape"
#  define SN_netscape_base_url            "nsBaseUrl"
#  define SN_netscape_ca_policy_url       "nsCaPolicyUrl"
#  define SN_netscape_ca_revocation_url   "nsCaRevocationUrl"
#  define SN_netscape_cert_extension      "nsCertExt"
#  define SN_netscape_cert_sequence       "nsCertSequence"
#  define SN_netscape_cert_type           "nsCertType"
#  define SN_netscape_comment             "nsComment"
#  define SN_netscape_data_type           "nsDataType"
#  define SN_netscape_renewal_url         "nsRenewalUrl"
#  define SN_netscape_revocation_url      "nsRevocationUrl"
#  define SN_netscape_ssl_server_name     "nsSslServerName"
#  define SN_ns_sgc                       "nsSGC"
#  define SN_organizationName             "O"
#  define SN_organizationalUnitName       "OU"
#  define SN_pbeWithMD2AndDES_CBC         "PBE-MD2-DES"
#  define SN_pbeWithMD2AndRC2_CBC         "PBE-MD2-RC2-64"
#  define SN_pbeWithMD5AndDES_CBC         "PBE-MD5-DES"
#  define SN_pbeWithMD5AndRC2_CBC         "PBE-MD5-RC2-64"
#  define SN_pbeWithSHA1AndDES_CBC        "PBE-SHA1-DES"
#  define SN_pbeWithSHA1AndRC2_CBC        "PBE-SHA1-RC2-64"
#  define SN_pbe_WithSHA1And128BitRC2_CBC         "PBE-SHA1-RC2-128"
#  define SN_pbe_WithSHA1And128BitRC4     "PBE-SHA1-RC4-128"
#  define SN_pbe_WithSHA1And2_Key_TripleDES_CBC   "PBE-SHA1-2DES"
#  define SN_pbe_WithSHA1And3_Key_TripleDES_CBC   "PBE-SHA1-3DES"
#  define SN_pbe_WithSHA1And40BitRC2_CBC  "PBE-SHA1-RC2-40"
#  define SN_pbe_WithSHA1And40BitRC4      "PBE-SHA1-RC4-40"
#  define SN_pkcs9_emailAddress           "Email"
#  define SN_private_key_usage_period     "privateKeyUsagePeriod"
#  define SN_rc2_40_cbc                   "RC2-40-CBC"
#  define SN_rc2_64_cbc                   "RC2-64-CBC"
#  define SN_rc2_cbc                      "RC2-CBC"
#  define SN_rc2_cfb64                    "RC2-CFB"
#  define SN_rc2_ecb                      "RC2-ECB"
#  define SN_rc2_ofb64                    "RC2-OFB"
#  define SN_rc4                          "RC4"
#  define SN_rc4_40                       "RC4-40"
#  define SN_rc5_cbc                      "RC5-CBC"
#  define SN_rc5_cfb64                    "RC5-CFB"
#  define SN_rc5_ecb                      "RC5-ECB"
#  define SN_rc5_ofb64                    "RC5-OFB"
#  define SN_ripemd160                    "RIPEMD160"
#  define SN_ripemd160WithRSA             "RSA-RIPEMD160"
#  define SN_rle_compression              "RLE"
#  define SN_rsa                          "RSA"
#  define SN_serialNumber                 "SN"
#  define SN_server_auth                  "serverAuth"
#  define SN_sha                          "SHA"
#  define SN_sha1                         "SHA1"
#  define SN_sha1WithRSA                  "RSA-SHA1-2"
#  define SN_sha1WithRSAEncryption        "RSA-SHA1"
#  define SN_shaWithRSAEncryption         "RSA-SHA"
#  define SN_stateOrProvinceName          "ST"
#  define SN_subject_alt_name             "subjectAltName"
#  define SN_subject_key_identifier       "subjectKeyIdentifier"
#  define SN_surname                      "S"
#  define SN_sxnet                        "SXNetID"
#  define SN_time_stamp                   "timeStamping"
#  define SN_title                        "T"
#  define SN_undef                        "UNDEF"
#  define SN_uniqueIdentifier             "UID"
#  define SN_zlib_compression             "ZLIB"
# define USE_OBJ_MAC
# define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)    \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \
  static int nm##_cmp(type1 const *, type2 const *); \
  scope type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)
# define ASN1_PKEY_ALIAS         0x1
# define ASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
# define ASN1_PKEY_CTRL_CMS_RI_TYPE      0x8
# define ASN1_PKEY_CTRL_CMS_SIGN         0x5
# define ASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
# define ASN1_PKEY_CTRL_PKCS7_ENCRYPT    0x2
# define ASN1_PKEY_CTRL_PKCS7_SIGN       0x1
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
# define EVP_F_AESNI_XTS_CIPHER                           176
# define EVP_F_AES_INIT_KEY                               133
# define EVP_F_AES_T4_INIT_KEY                            178
# define EVP_F_AES_XTS                                    172
# define EVP_F_AES_XTS_CIPHER                             175
# define EVP_F_ALG_MODULE_INIT                            177
# define EVP_F_CAMELLIA_INIT_KEY                          159
# define EVP_F_CHACHA20_POLY1305_CTRL                     182
# define EVP_F_CMAC_INIT                                  173
# define EVP_F_CMLL_T4_INIT_KEY                           179
# define EVP_F_D2I_PKEY                                   100
# define EVP_F_DO_SIGVER_INIT                             161
# define EVP_F_DSAPKEY2PKCS8                              134
# define EVP_F_DSA_PKEY2PKCS8                             135
# define EVP_F_ECDSA_PKEY2PKCS8                           129
# define EVP_F_ECKEY_PKEY2PKCS8                           132
# define EVP_F_EVP_CIPHERINIT_EX                          123
# define EVP_F_EVP_CIPHER_CTX_COPY                        163
# define EVP_F_EVP_CIPHER_CTX_CTRL                        124
# define EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH              122
# define EVP_F_EVP_DECRYPTFINAL_EX                        101
# define EVP_F_EVP_DIGESTINIT_EX                          128
# define EVP_F_EVP_ENCRYPTFINAL_EX                        127
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
# define EVP_F_EVP_PKEY_GET0_ECDSA                        130
# define EVP_F_EVP_PKEY_GET0_EC_KEY                       131
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
# define EVP_F_EVP_RIJNDAEL                               126
# define EVP_F_EVP_SIGNFINAL                              107
# define EVP_F_EVP_VERIFYFINAL                            108
# define EVP_F_FIPS_CIPHERINIT                            166
# define EVP_F_FIPS_CIPHER_CTX_COPY                       170
# define EVP_F_FIPS_CIPHER_CTX_CTRL                       167
# define EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH             171
# define EVP_F_FIPS_DIGESTINIT                            168
# define EVP_F_FIPS_MD_CTX_COPY                           169
# define EVP_F_HMAC_INIT_EX                               174
# define EVP_F_INT_CTX_NEW                                157
# define EVP_F_PKCS5_PBE_KEYIVGEN                         117
# define EVP_F_PKCS5_V2_PBE_KEYIVGEN                      118
# define EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN                   164
# define EVP_F_PKCS5_V2_SCRYPT_KEYIVGEN                   180
# define EVP_F_PKCS8_SET_BROKEN                           112
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
# define EVP_PKEY_RSA    NID_rsaEncryption
# define EVP_PKEY_RSA2   NID_rsa
# define EVP_PKEY_TLS1_PRF NID_tls1_prf
#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,\
                                        (char *)(dh))
#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (char *)(dsa))
#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC,\
                                        (char *)(eckey))
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
# define EVP_R_AES_IV_SETUP_FAILED                        162
# define EVP_R_AES_KEY_SETUP_FAILED                       143
# define EVP_R_ASN1_LIB                                   140
# define EVP_R_BAD_BLOCK_LENGTH                           136
# define EVP_R_BAD_DECRYPT                                100
# define EVP_R_BAD_KEY_LENGTH                             137
# define EVP_R_BN_DECODE_ERROR                            112
# define EVP_R_BN_PUBKEY_ERROR                            113
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
# define EVP_R_DISABLED_FOR_FIPS                          163
# define EVP_R_ENCODE_ERROR                               115
# define EVP_R_ERROR_LOADING_SECTION                      165
# define EVP_R_ERROR_SETTING_FIPS_MODE                    166
# define EVP_R_EVP_PBE_CIPHERINIT_ERROR                   119
# define EVP_R_EXPECTING_AN_RSA_KEY                       127
# define EVP_R_EXPECTING_A_DH_KEY                         128
# define EVP_R_EXPECTING_A_DSA_KEY                        129
# define EVP_R_EXPECTING_A_ECDSA_KEY                      141
# define EVP_R_EXPECTING_A_EC_KEY                         142
# define EVP_R_FIPS_MODE_NOT_SUPPORTED                    167
# define EVP_R_ILLEGAL_SCRYPT_PARAMETERS                  171
# define EVP_R_INITIALIZATION_ERROR                       134
# define EVP_R_INPUT_NOT_INITIALIZED                      111
# define EVP_R_INVALID_DIGEST                             152
# define EVP_R_INVALID_FIPS_MODE                          168
# define EVP_R_INVALID_KEY_LENGTH                         130
# define EVP_R_INVALID_OPERATION                          148
# define EVP_R_IV_TOO_LARGE                               102
# define EVP_R_KEYGEN_FAILURE                             120
# define EVP_R_MEMORY_LIMIT_EXCEEDED                      172
# define EVP_R_MESSAGE_DIGEST_IS_NULL                     159
# define EVP_R_METHOD_NOT_SUPPORTED                       144
# define EVP_R_MISSING_PARAMETERS                         103
# define EVP_R_NO_CIPHER_SET                              131
# define EVP_R_NO_DEFAULT_DIGEST                          158
# define EVP_R_NO_DIGEST_SET                              139
# define EVP_R_NO_DSA_PARAMETERS                          116
# define EVP_R_NO_KEY_SET                                 154
# define EVP_R_NO_OPERATION_SET                           149
# define EVP_R_NO_SIGN_FUNCTION_CONFIGURED                104
# define EVP_R_NO_VERIFY_FUNCTION_CONFIGURED              105
# define EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE   150
# define EVP_R_OPERATON_NOT_INITIALIZED                   151
# define EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE                  117
# define EVP_R_PRIVATE_KEY_DECODE_ERROR                   145
# define EVP_R_PRIVATE_KEY_ENCODE_ERROR                   146
# define EVP_R_PUBLIC_KEY_NOT_RSA                         106
# define EVP_R_TOO_LARGE                                  164
# define EVP_R_UNKNOWN_CIPHER                             160
# define EVP_R_UNKNOWN_DIGEST                             161
# define EVP_R_UNKNOWN_OPTION                             169
# define EVP_R_UNKNOWN_PBE_ALGORITHM                      121
# define EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS                135
# define EVP_R_UNSUPPORTED_ALGORITHM                      156
# define EVP_R_UNSUPPORTED_CIPHER                         107
# define EVP_R_UNSUPPORTED_KEYLENGTH                      123
# define EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION        124
# define EVP_R_UNSUPPORTED_KEY_SIZE                       108
# define EVP_R_UNSUPPORTED_PRF                            125
# define EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM          118
# define EVP_R_UNSUPPORTED_SALT_TYPE                      126
# define EVP_R_WRAP_MODE_NOT_ALLOWED                      170
# define EVP_R_WRONG_FINAL_BLOCK_LENGTH                   109
# define EVP_R_WRONG_PUBLIC_KEY_TYPE                      110
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
