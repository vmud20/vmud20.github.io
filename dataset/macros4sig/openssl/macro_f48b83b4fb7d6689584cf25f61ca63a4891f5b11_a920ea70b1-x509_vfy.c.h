#include<stdio.h>
#include<time.h>
#include<errno.h>
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
# define ASIdOrRange_id          0
# define ASIdOrRange_range       1
# define ASIdentifierChoice_asIdsOrRanges        1
# define ASIdentifierChoice_inherit              0
# define CRLDP_ALL_REASONS       0x807f
# define CRL_REASON_AA_COMPROMISE                10
# define CRL_REASON_AFFILIATION_CHANGED          3
# define CRL_REASON_CA_COMPROMISE                2
# define CRL_REASON_CERTIFICATE_HOLD             6
# define CRL_REASON_CESSATION_OF_OPERATION       5
# define CRL_REASON_KEY_COMPROMISE               1
# define CRL_REASON_NONE                         -1
# define CRL_REASON_PRIVILEGE_WITHDRAWN          9
# define CRL_REASON_REMOVE_FROM_CRL              8
# define CRL_REASON_SUPERSEDED                   4
# define CRL_REASON_UNSPECIFIED                  0
# define CTX_TEST 0x1
# define EXFLAG_BCONS            0x1
# define EXFLAG_CA               0x10
# define EXFLAG_CRITICAL         0x200
# define EXFLAG_FRESHEST         0x1000
# define EXFLAG_INVALID          0x80
# define EXFLAG_INVALID_POLICY   0x800
# define EXFLAG_KUSAGE           0x2
# define EXFLAG_NSCERT           0x8
# define EXFLAG_PROXY            0x400
# define EXFLAG_SET              0x100
# define EXFLAG_SI               0x20
# define EXFLAG_SS               0x2000
# define EXFLAG_V1               0x40
# define EXFLAG_XKUSAGE          0x4
# define EXT_BITSTRING(nid, table) { nid, 0, ASN1_ITEM_ref(ASN1_BIT_STRING), \
                        0,0,0,0, \
                        0,0, \
                        (X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
                        (X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
                        NULL, NULL, \
                        table}
# define EXT_END { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
# define EXT_IA5STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_IA5STRING), \
                        0,0,0,0, \
                        (X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
                        (X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
                        0,0,0,0, \
                        NULL}
# define GEN_DIRNAME     4
# define GEN_DNS         2
# define GEN_EDIPARTY    5
# define GEN_EMAIL       1
# define GEN_IPADD       7
# define GEN_OTHERNAME   0
# define GEN_RID         8
# define GEN_URI         6
# define GEN_X400        3
# define HEADER_X509V3_H
# define IANA_AFI_IPV4   1
# define IANA_AFI_IPV6   2
# define IDP_INDIRECT    0x20
# define IDP_INVALID     0x2
# define IDP_ONLYATTR    0x10
# define IDP_ONLYCA      0x8
# define IDP_ONLYUSER    0x4
# define IDP_PRESENT     0x1
# define IDP_REASONS     0x40
# define IPAddressChoice_addressesOrRanges       1
# define IPAddressChoice_inherit                 0
# define IPAddressOrRange_addressPrefix  0
# define IPAddressOrRange_addressRange   1
# define KU_CRL_SIGN             0x0002
# define KU_DATA_ENCIPHERMENT    0x0010
# define KU_DECIPHER_ONLY        0x8000
# define KU_DIGITAL_SIGNATURE    0x0080
# define KU_ENCIPHER_ONLY        0x0001
# define KU_KEY_AGREEMENT        0x0008
# define KU_KEY_CERT_SIGN        0x0004
# define KU_KEY_ENCIPHERMENT     0x0020
# define KU_NON_REPUDIATION      0x0040
# define NS_ANY_CA               (NS_SSL_CA|NS_SMIME_CA|NS_OBJSIGN_CA)
# define NS_OBJSIGN              0x10
# define NS_OBJSIGN_CA           0x01
# define NS_SMIME                0x20
# define NS_SMIME_CA             0x02
# define NS_SSL_CA               0x04
# define NS_SSL_CLIENT           0x80
# define NS_SSL_SERVER           0x40
# define V3_ASID_ASNUM   0
# define V3_ASID_RDI     1
# define X509V3_ADD_APPEND               1L
# define X509V3_ADD_DEFAULT              0L
# define X509V3_ADD_DELETE               5L
# define X509V3_ADD_KEEP_EXISTING        4L
# define X509V3_ADD_OP_MASK              0xfL
# define X509V3_ADD_REPLACE              2L
# define X509V3_ADD_REPLACE_EXISTING     3L
# define X509V3_ADD_SILENT               0x10
# define X509V3_CTX_REPLACE 0x2
# define X509V3_EXT_CTX_DEP      0x2
# define X509V3_EXT_DEFAULT              0
# define X509V3_EXT_DUMP_UNKNOWN         (3L << 16)
# define X509V3_EXT_DYNAMIC      0x1
# define X509V3_EXT_ERROR_UNKNOWN        (1L << 16)
# define X509V3_EXT_MULTILINE    0x4
# define X509V3_EXT_PARSE_UNKNOWN        (2L << 16)
# define X509V3_EXT_UNKNOWN_MASK         (0xfL << 16)
# define X509V3_F_A2I_GENERAL_NAME                        164
# define X509V3_F_ASIDENTIFIERCHOICE_CANONIZE             161
# define X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL         162
# define X509V3_F_COPY_EMAIL                              122
# define X509V3_F_COPY_ISSUER                             123
# define X509V3_F_DO_DIRNAME                              144
# define X509V3_F_DO_EXT_CONF                             124
# define X509V3_F_DO_EXT_I2D                              135
# define X509V3_F_DO_EXT_NCONF                            151
# define X509V3_F_DO_I2V_NAME_CONSTRAINTS                 148
# define X509V3_F_GNAMES_FROM_SECTNAME                    156
# define X509V3_F_HEX_TO_STRING                           111
# define X509V3_F_I2S_ASN1_ENUMERATED                     121
# define X509V3_F_I2S_ASN1_IA5STRING                      149
# define X509V3_F_I2S_ASN1_INTEGER                        120
# define X509V3_F_I2V_AUTHORITY_INFO_ACCESS               138
# define X509V3_F_NOTICE_SECTION                          132
# define X509V3_F_NREF_NOS                                133
# define X509V3_F_POLICY_SECTION                          131
# define X509V3_F_PROCESS_PCI_VALUE                       150
# define X509V3_F_R2I_CERTPOL                             130
# define X509V3_F_R2I_PCI                                 155
# define X509V3_F_S2I_ASN1_IA5STRING                      100
# define X509V3_F_S2I_ASN1_INTEGER                        108
# define X509V3_F_S2I_ASN1_OCTET_STRING                   112
# define X509V3_F_S2I_ASN1_SKEY_ID                        114
# define X509V3_F_S2I_SKEY_ID                             115
# define X509V3_F_SET_DIST_POINT_NAME                     158
# define X509V3_F_STRING_TO_HEX                           113
# define X509V3_F_SXNET_ADD_ID_ASC                        125
# define X509V3_F_SXNET_ADD_ID_INTEGER                    126
# define X509V3_F_SXNET_ADD_ID_ULONG                      127
# define X509V3_F_SXNET_GET_ID_ASC                        128
# define X509V3_F_SXNET_GET_ID_ULONG                      129
# define X509V3_F_V2I_ASIDENTIFIERS                       163
# define X509V3_F_V2I_ASN1_BIT_STRING                     101
# define X509V3_F_V2I_AUTHORITY_INFO_ACCESS               139
# define X509V3_F_V2I_AUTHORITY_KEYID                     119
# define X509V3_F_V2I_BASIC_CONSTRAINTS                   102
# define X509V3_F_V2I_CRLD                                134
# define X509V3_F_V2I_EXTENDED_KEY_USAGE                  103
# define X509V3_F_V2I_GENERAL_NAMES                       118
# define X509V3_F_V2I_GENERAL_NAME_EX                     117
# define X509V3_F_V2I_IDP                                 157
# define X509V3_F_V2I_IPADDRBLOCKS                        159
# define X509V3_F_V2I_ISSUER_ALT                          153
# define X509V3_F_V2I_NAME_CONSTRAINTS                    147
# define X509V3_F_V2I_POLICY_CONSTRAINTS                  146
# define X509V3_F_V2I_POLICY_MAPPINGS                     145
# define X509V3_F_V2I_SUBJECT_ALT                         154
# define X509V3_F_V3_ADDR_VALIDATE_PATH_INTERNAL          160
# define X509V3_F_V3_GENERIC_EXTENSION                    116
# define X509V3_F_X509V3_ADD1_I2D                         140
# define X509V3_F_X509V3_ADD_VALUE                        105
# define X509V3_F_X509V3_EXT_ADD                          104
# define X509V3_F_X509V3_EXT_ADD_ALIAS                    106
# define X509V3_F_X509V3_EXT_CONF                         107
# define X509V3_F_X509V3_EXT_I2D                          136
# define X509V3_F_X509V3_EXT_NCONF                        152
# define X509V3_F_X509V3_GET_SECTION                      142
# define X509V3_F_X509V3_GET_STRING                       143
# define X509V3_F_X509V3_GET_VALUE_BOOL                   110
# define X509V3_F_X509V3_PARSE_LIST                       109
# define X509V3_F_X509_PURPOSE_ADD                        137
# define X509V3_F_X509_PURPOSE_SET                        141
# define X509V3_R_BAD_IP_ADDRESS                          118
# define X509V3_R_BAD_OBJECT                              119
# define X509V3_R_BN_DEC2BN_ERROR                         100
# define X509V3_R_BN_TO_ASN1_INTEGER_ERROR                101
# define X509V3_R_DIRNAME_ERROR                           149
# define X509V3_R_DISTPOINT_ALREADY_SET                   160
# define X509V3_R_DUPLICATE_ZONE_ID                       133
# define X509V3_R_ERROR_CONVERTING_ZONE                   131
# define X509V3_R_ERROR_CREATING_EXTENSION                144
# define X509V3_R_ERROR_IN_EXTENSION                      128
# define X509V3_R_EXPECTED_A_SECTION_NAME                 137
# define X509V3_R_EXTENSION_EXISTS                        145
# define X509V3_R_EXTENSION_NAME_ERROR                    115
# define X509V3_R_EXTENSION_NOT_FOUND                     102
# define X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED         103
# define X509V3_R_EXTENSION_VALUE_ERROR                   116
# define X509V3_R_ILLEGAL_EMPTY_EXTENSION                 151
# define X509V3_R_ILLEGAL_HEX_DIGIT                       113
# define X509V3_R_INCORRECT_POLICY_SYNTAX_TAG             152
# define X509V3_R_INVALID_ASNUMBER                        162
# define X509V3_R_INVALID_ASRANGE                         163
# define X509V3_R_INVALID_BOOLEAN_STRING                  104
# define X509V3_R_INVALID_EXTENSION_STRING                105
# define X509V3_R_INVALID_INHERITANCE                     165
# define X509V3_R_INVALID_IPADDRESS                       166
# define X509V3_R_INVALID_MULTIPLE_RDNS                   161
# define X509V3_R_INVALID_NAME                            106
# define X509V3_R_INVALID_NULL_ARGUMENT                   107
# define X509V3_R_INVALID_NULL_NAME                       108
# define X509V3_R_INVALID_NULL_VALUE                      109
# define X509V3_R_INVALID_NUMBER                          140
# define X509V3_R_INVALID_NUMBERS                         141
# define X509V3_R_INVALID_OBJECT_IDENTIFIER               110
# define X509V3_R_INVALID_OPTION                          138
# define X509V3_R_INVALID_POLICY_IDENTIFIER               134
# define X509V3_R_INVALID_PROXY_POLICY_SETTING            153
# define X509V3_R_INVALID_PURPOSE                         146
# define X509V3_R_INVALID_SAFI                            164
# define X509V3_R_INVALID_SECTION                         135
# define X509V3_R_INVALID_SYNTAX                          143
# define X509V3_R_ISSUER_DECODE_ERROR                     126
# define X509V3_R_MISSING_VALUE                           124
# define X509V3_R_NEED_ORGANIZATION_AND_NUMBERS           142
# define X509V3_R_NO_CONFIG_DATABASE                      136
# define X509V3_R_NO_ISSUER_CERTIFICATE                   121
# define X509V3_R_NO_ISSUER_DETAILS                       127
# define X509V3_R_NO_POLICY_IDENTIFIER                    139
# define X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED   154
# define X509V3_R_NO_PUBLIC_KEY                           114
# define X509V3_R_NO_SUBJECT_DETAILS                      125
# define X509V3_R_ODD_NUMBER_OF_DIGITS                    112
# define X509V3_R_OPERATION_NOT_DEFINED                   148
# define X509V3_R_OTHERNAME_ERROR                         147
# define X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED         155
# define X509V3_R_POLICY_PATH_LENGTH                      156
# define X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED      157
# define X509V3_R_POLICY_SYNTAX_NOT_CURRENTLY_SUPPORTED   158
# define X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY 159
# define X509V3_R_SECTION_NOT_FOUND                       150
# define X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS            122
# define X509V3_R_UNABLE_TO_GET_ISSUER_KEYID              123
# define X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT             111
# define X509V3_R_UNKNOWN_EXTENSION                       129
# define X509V3_R_UNKNOWN_EXTENSION_NAME                  130
# define X509V3_R_UNKNOWN_OPTION                          120
# define X509V3_R_UNSUPPORTED_OPTION                      117
# define X509V3_R_UNSUPPORTED_TYPE                        167
# define X509V3_R_USER_TOO_LONG                           132
# define X509V3_conf_err(val) ERR_add_error_data(6, "section:", val->section, \
",name:", val->name, ",value:", val->value);
# define X509V3_set_ctx_nodb(ctx) (ctx)->db = NULL;
# define X509V3_set_ctx_test(ctx) \
                        X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, CTX_TEST)
# define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    0x1
# define X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8
# define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
# define X509_CHECK_FLAG_NO_WILDCARDS    0x2
# define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10
# define X509_PURPOSE_ANY                7
# define X509_PURPOSE_CRL_SIGN           6
# define X509_PURPOSE_DYNAMIC    0x1
# define X509_PURPOSE_DYNAMIC_NAME       0x2
# define X509_PURPOSE_MAX                9
# define X509_PURPOSE_MIN                1
# define X509_PURPOSE_NS_SSL_SERVER      3
# define X509_PURPOSE_OCSP_HELPER        8
# define X509_PURPOSE_SMIME_ENCRYPT      5
# define X509_PURPOSE_SMIME_SIGN         4
# define X509_PURPOSE_SSL_CLIENT         1
# define X509_PURPOSE_SSL_SERVER         2
# define X509_PURPOSE_TIMESTAMP_SIGN     9
# define XKU_ANYEKU              0x100
# define XKU_CODE_SIGN           0x8
# define XKU_DVCS                0x80
# define XKU_OCSP_SIGN           0x20
# define XKU_SGC                 0x10
# define XKU_SMIME               0x4
# define XKU_SSL_CLIENT          0x2
# define XKU_SSL_SERVER          0x1
# define XKU_TIMESTAMP           0x40
# define _X509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000
# define HEADER_X509_H
# define PKCS8_EMBEDDED_PARAM    2
# define PKCS8_NEG_PRIVKEY       4
# define PKCS8_NO_OCTET          1
# define PKCS8_NS_DB             3
# define PKCS8_OK                0
# define         X509_CRL_get_REVOKED(x) ((x)->crl->revoked)
# define         X509_CRL_get_issuer(x) ((x)->crl->issuer)
# define         X509_CRL_get_lastUpdate(x) ((x)->crl->lastUpdate)
# define         X509_CRL_get_nextUpdate(x) ((x)->crl->nextUpdate)
# define         X509_CRL_get_version(x) ASN1_INTEGER_get((x)->crl->version)
# define X509_EXT_PACK_STRING    2
# define X509_EXT_PACK_UNKNOWN   1
# define X509_EX_V_INIT                  0x0001
# define X509_EX_V_NETSCAPE_HACK         0x8000
# define X509_FILETYPE_ASN1      2
# define X509_FILETYPE_DEFAULT   3
# define X509_FILETYPE_PEM       1
# define X509_FLAG_COMPAT                0
# define X509_FLAG_NO_ATTRIBUTES         (1L << 11)
# define X509_FLAG_NO_AUX                (1L << 10)
# define X509_FLAG_NO_EXTENSIONS         (1L << 8)
# define X509_FLAG_NO_HEADER             1L
# define X509_FLAG_NO_IDS                (1L << 12)
# define X509_FLAG_NO_ISSUER             (1L << 4)
# define X509_FLAG_NO_PUBKEY             (1L << 7)
# define X509_FLAG_NO_SERIAL             (1L << 2)
# define X509_FLAG_NO_SIGDUMP            (1L << 9)
# define X509_FLAG_NO_SIGNAME            (1L << 3)
# define X509_FLAG_NO_SUBJECT            (1L << 6)
# define X509_FLAG_NO_VALIDITY           (1L << 5)
# define X509_FLAG_NO_VERSION            (1L << 1)
# define X509_F_ADD_CERT_DIR                              100
# define X509_F_BY_FILE_CTRL                              101
# define X509_F_CHECK_POLICY                              145
# define X509_F_DIR_CTRL                                  102
# define X509_F_GET_CERT_BY_SUBJECT                       103
# define X509_F_NETSCAPE_SPKI_B64_DECODE                  129
# define X509_F_NETSCAPE_SPKI_B64_ENCODE                  130
# define X509_F_X509AT_ADD1_ATTR                          135
# define X509_F_X509V3_ADD_EXT                            104
# define X509_F_X509_ATTRIBUTE_CREATE_BY_NID              136
# define X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ              137
# define X509_F_X509_ATTRIBUTE_CREATE_BY_TXT              140
# define X509_F_X509_ATTRIBUTE_GET0_DATA                  139
# define X509_F_X509_ATTRIBUTE_SET1_DATA                  138
# define X509_F_X509_CHECK_PRIVATE_KEY                    128
# define X509_F_X509_CRL_DIFF                             105
# define X509_F_X509_CRL_PRINT_FP                         147
# define X509_F_X509_EXTENSION_CREATE_BY_NID              108
# define X509_F_X509_EXTENSION_CREATE_BY_OBJ              109
# define X509_F_X509_GET_PUBKEY_PARAMETERS                110
# define X509_F_X509_LOAD_CERT_CRL_FILE                   132
# define X509_F_X509_LOAD_CERT_FILE                       111
# define X509_F_X509_LOAD_CRL_FILE                        112
# define X509_F_X509_NAME_ADD_ENTRY                       113
# define X509_F_X509_NAME_ENTRY_CREATE_BY_NID             114
# define X509_F_X509_NAME_ENTRY_CREATE_BY_TXT             131
# define X509_F_X509_NAME_ENTRY_SET_OBJECT                115
# define X509_F_X509_NAME_ONELINE                         116
# define X509_F_X509_NAME_PRINT                           117
# define X509_F_X509_PRINT_EX_FP                          118
# define X509_F_X509_PUBKEY_GET                           119
# define X509_F_X509_PUBKEY_SET                           120
# define X509_F_X509_REQ_CHECK_PRIVATE_KEY                144
# define X509_F_X509_REQ_PRINT_EX                         121
# define X509_F_X509_REQ_PRINT_FP                         122
# define X509_F_X509_REQ_TO_X509                          123
# define X509_F_X509_STORE_ADD_CERT                       124
# define X509_F_X509_STORE_ADD_CRL                        125
# define X509_F_X509_STORE_CTX_GET1_ISSUER                146
# define X509_F_X509_STORE_CTX_INIT                       143
# define X509_F_X509_STORE_CTX_NEW                        142
# define X509_F_X509_STORE_CTX_PURPOSE_INHERIT            134
# define X509_F_X509_TO_X509_REQ                          126
# define X509_F_X509_TRUST_ADD                            133
# define X509_F_X509_TRUST_SET                            141
# define X509_F_X509_VERIFY_CERT                          127
# define         X509_REQ_extract_key(a) X509_REQ_get_pubkey(a)
# define         X509_REQ_get_subject_name(x) ((x)->req_info->subject)
# define         X509_REQ_get_version(x) ASN1_INTEGER_get((x)->req_info->version)
# define X509_R_AKID_MISMATCH                             110
# define X509_R_BAD_X509_FILETYPE                         100
# define X509_R_BASE64_DECODE_ERROR                       118
# define X509_R_CANT_CHECK_DH_KEY                         114
# define X509_R_CERT_ALREADY_IN_HASH_TABLE                101
# define X509_R_CRL_ALREADY_DELTA                         127
# define X509_R_CRL_VERIFY_FAILURE                        131
# define X509_R_ERR_ASN1_LIB                              102
# define X509_R_IDP_MISMATCH                              128
# define X509_R_INVALID_DIRECTORY                         113
# define X509_R_INVALID_FIELD_NAME                        119
# define X509_R_INVALID_TRUST                             123
# define X509_R_ISSUER_MISMATCH                           129
# define X509_R_KEY_TYPE_MISMATCH                         115
# define X509_R_KEY_VALUES_MISMATCH                       116
# define X509_R_LOADING_CERT_DIR                          103
# define X509_R_LOADING_DEFAULTS                          104
# define X509_R_METHOD_NOT_SUPPORTED                      124
# define X509_R_NEWER_CRL_NOT_NEWER                       132
# define X509_R_NO_CERT_SET_FOR_US_TO_VERIFY              105
# define X509_R_NO_CRL_NUMBER                             130
# define X509_R_PUBLIC_KEY_DECODE_ERROR                   125
# define X509_R_PUBLIC_KEY_ENCODE_ERROR                   126
# define X509_R_SHOULD_RETRY                              106
# define X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN        107
# define X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY            108
# define X509_R_UNKNOWN_KEY_TYPE                          117
# define X509_R_UNKNOWN_NID                               109
# define X509_R_UNKNOWN_PURPOSE_ID                        121
# define X509_R_UNKNOWN_TRUST_ID                          120
# define X509_R_UNSUPPORTED_ALGORITHM                     111
# define X509_R_WRONG_LOOKUP_TYPE                         112
# define X509_R_WRONG_TYPE                                122
# define X509_TRUST_COMPAT       1
# define X509_TRUST_DEFAULT      -1
# define X509_TRUST_DYNAMIC      1
# define X509_TRUST_DYNAMIC_NAME 2
# define X509_TRUST_EMAIL        4
# define X509_TRUST_MAX          8
# define X509_TRUST_MIN          1
# define X509_TRUST_OBJECT_SIGN  5
# define X509_TRUST_OCSP_REQUEST 7
# define X509_TRUST_OCSP_SIGN    6
# define X509_TRUST_REJECTED     2
# define X509_TRUST_SSL_CLIENT   2
# define X509_TRUST_SSL_SERVER   3
# define X509_TRUST_TRUSTED      1
# define X509_TRUST_TSA          8
# define X509_TRUST_UNTRUSTED    3
# define         X509_extract_key(x)     X509_get_pubkey(x)
# define         X509_get_X509_PUBKEY(x) ((x)->cert_info->key)
# define         X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)
# define         X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
# define         X509_get_signature_type(x) EVP_PKEY_type(OBJ_obj2nid((x)->sig_alg->algorithm))
# define         X509_get_version(x) ASN1_INTEGER_get((x)->cert_info->version)
# define         X509_name_cmp(a,b)      X509_NAME_cmp((a),(b))
# define X509v3_KU_CRL_SIGN              0x0002
# define X509v3_KU_DATA_ENCIPHERMENT     0x0010
# define X509v3_KU_DECIPHER_ONLY         0x8000
# define X509v3_KU_DIGITAL_SIGNATURE     0x0080
# define X509v3_KU_ENCIPHER_ONLY         0x0001
# define X509v3_KU_KEY_AGREEMENT         0x0008
# define X509v3_KU_KEY_CERT_SIGN         0x0004
# define X509v3_KU_KEY_ENCIPHERMENT      0x0020
# define X509v3_KU_NON_REPUDIATION       0x0040
# define X509v3_KU_UNDEF                 0xffff
# define XN_FLAG_COMPAT          0
# define XN_FLAG_DN_REV          (1 << 20)
# define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)
# define XN_FLAG_FN_ALIGN        (1 << 25)
# define XN_FLAG_FN_LN           (1 << 21)
# define XN_FLAG_FN_MASK         (0x3 << 21)
# define XN_FLAG_FN_NONE         (3 << 21)
# define XN_FLAG_FN_OID          (2 << 21)
# define XN_FLAG_FN_SN           0
# define XN_FLAG_MULTILINE (ASN1_STRFLGS_ESC_CTRL | \
                        ASN1_STRFLGS_ESC_MSB | \
                        XN_FLAG_SEP_MULTILINE | \
                        XN_FLAG_SPC_EQ | \
                        XN_FLAG_FN_LN | \
                        XN_FLAG_FN_ALIGN)
# define XN_FLAG_ONELINE (ASN1_STRFLGS_RFC2253 | \
                        ASN1_STRFLGS_ESC_QUOTE | \
                        XN_FLAG_SEP_CPLUS_SPC | \
                        XN_FLAG_SPC_EQ | \
                        XN_FLAG_FN_SN)
# define XN_FLAG_RFC2253 (ASN1_STRFLGS_RFC2253 | \
                        XN_FLAG_SEP_COMMA_PLUS | \
                        XN_FLAG_DN_REV | \
                        XN_FLAG_FN_SN | \
                        XN_FLAG_DUMP_UNKNOWN_FIELDS)
# define XN_FLAG_SEP_COMMA_PLUS  (1 << 16)
# define XN_FLAG_SEP_CPLUS_SPC   (2 << 16)
# define XN_FLAG_SEP_MASK        (0xf << 16)
# define XN_FLAG_SEP_MULTILINE   (4 << 16)
# define XN_FLAG_SEP_SPLUS_SPC   (3 << 16)
# define XN_FLAG_SPC_EQ          (1 << 23)
# define ASN1_F_A2D_ASN1_OBJECT                           100
# define ASN1_F_A2I_ASN1_ENUMERATED                       101
# define ASN1_F_A2I_ASN1_INTEGER                          102
# define ASN1_F_A2I_ASN1_STRING                           103
# define ASN1_F_APPEND_EXP                                176
# define ASN1_F_ASN1_BIT_STRING_SET_BIT                   183
# define ASN1_F_ASN1_CB                                   177
# define ASN1_F_ASN1_CHECK_TLEN                           104
# define ASN1_F_ASN1_COLLATE_PRIMITIVE                    105
# define ASN1_F_ASN1_COLLECT                              106
# define ASN1_F_ASN1_D2I_EX_PRIMITIVE                     108
# define ASN1_F_ASN1_D2I_FP                               109
# define ASN1_F_ASN1_D2I_READ_BIO                         107
# define ASN1_F_ASN1_DIGEST                               184
# define ASN1_F_ASN1_DO_ADB                               110
# define ASN1_F_ASN1_DUP                                  111
# define ASN1_F_ASN1_ENUMERATED_SET                       112
# define ASN1_F_ASN1_ENUMERATED_TO_BN                     113
# define ASN1_F_ASN1_EX_C2I                               204
# define ASN1_F_ASN1_FIND_END                             190
# define ASN1_F_ASN1_GENERALIZEDTIME_ADJ                  216
# define ASN1_F_ASN1_GENERALIZEDTIME_SET                  185
# define ASN1_F_ASN1_GENERATE_V3                          178
# define ASN1_F_ASN1_GET_INT64                            224
# define ASN1_F_ASN1_GET_OBJECT                           114
# define ASN1_F_ASN1_GET_UINT64                           225
# define ASN1_F_ASN1_HEADER_NEW                           115
# define ASN1_F_ASN1_I2D_BIO                              116
# define ASN1_F_ASN1_I2D_FP                               117
# define ASN1_F_ASN1_INTEGER_SET                          118
# define ASN1_F_ASN1_INTEGER_TO_BN                        119
# define ASN1_F_ASN1_ITEM_D2I_FP                          206
# define ASN1_F_ASN1_ITEM_DUP                             191
# define ASN1_F_ASN1_ITEM_EX_D2I                          120
# define ASN1_F_ASN1_ITEM_EX_NEW                          121
# define ASN1_F_ASN1_ITEM_I2D_BIO                         192
# define ASN1_F_ASN1_ITEM_I2D_FP                          193
# define ASN1_F_ASN1_ITEM_PACK                            198
# define ASN1_F_ASN1_ITEM_SIGN                            195
# define ASN1_F_ASN1_ITEM_SIGN_CTX                        220
# define ASN1_F_ASN1_ITEM_UNPACK                          199
# define ASN1_F_ASN1_ITEM_VERIFY                          197
# define ASN1_F_ASN1_MBSTRING_NCOPY                       122
# define ASN1_F_ASN1_OBJECT_NEW                           123
# define ASN1_F_ASN1_OUTPUT_DATA                          214
# define ASN1_F_ASN1_PACK_STRING                          124
# define ASN1_F_ASN1_PCTX_NEW                             205
# define ASN1_F_ASN1_PKCS5_PBE_SET                        125
# define ASN1_F_ASN1_SCTX_NEW                             221
# define ASN1_F_ASN1_SEQ_PACK                             126
# define ASN1_F_ASN1_SEQ_UNPACK                           127
# define ASN1_F_ASN1_SIGN                                 128
# define ASN1_F_ASN1_STR2TYPE                             179
# define ASN1_F_ASN1_STRING_GET_INT64                     227
# define ASN1_F_ASN1_STRING_GET_UINT64                    230
# define ASN1_F_ASN1_STRING_SET                           186
# define ASN1_F_ASN1_STRING_TABLE_ADD                     129
# define ASN1_F_ASN1_STRING_TO_BN                         228
# define ASN1_F_ASN1_STRING_TYPE_NEW                      130
# define ASN1_F_ASN1_TEMPLATE_EX_D2I                      132
# define ASN1_F_ASN1_TEMPLATE_NEW                         133
# define ASN1_F_ASN1_TEMPLATE_NOEXP_D2I                   131
# define ASN1_F_ASN1_TIME_ADJ                             217
# define ASN1_F_ASN1_TIME_SET                             175
# define ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING             134
# define ASN1_F_ASN1_TYPE_GET_OCTETSTRING                 135
# define ASN1_F_ASN1_UNPACK_STRING                        136
# define ASN1_F_ASN1_UTCTIME_ADJ                          218
# define ASN1_F_ASN1_UTCTIME_SET                          187
# define ASN1_F_ASN1_VERIFY                               137
# define ASN1_F_B64_READ_ASN1                             209
# define ASN1_F_B64_WRITE_ASN1                            210
# define ASN1_F_BIO_NEW_NDEF                              208
# define ASN1_F_BITSTR_CB                                 180
# define ASN1_F_BN_TO_ASN1_ENUMERATED                     138
# define ASN1_F_BN_TO_ASN1_INTEGER                        139
# define ASN1_F_BN_TO_ASN1_STRING                         229
# define ASN1_F_C2I_ASN1_BIT_STRING                       189
# define ASN1_F_C2I_ASN1_INTEGER                          194
# define ASN1_F_C2I_ASN1_OBJECT                           196
# define ASN1_F_C2I_IBUF                                  226
# define ASN1_F_COLLECT_DATA                              140
# define ASN1_F_D2I_ASN1_BIT_STRING                       141
# define ASN1_F_D2I_ASN1_BOOLEAN                          142
# define ASN1_F_D2I_ASN1_BYTES                            143
# define ASN1_F_D2I_ASN1_GENERALIZEDTIME                  144
# define ASN1_F_D2I_ASN1_HEADER                           145
# define ASN1_F_D2I_ASN1_INTEGER                          146
# define ASN1_F_D2I_ASN1_OBJECT                           147
# define ASN1_F_D2I_ASN1_SET                              148
# define ASN1_F_D2I_ASN1_TYPE_BYTES                       149
# define ASN1_F_D2I_ASN1_UINTEGER                         150
# define ASN1_F_D2I_ASN1_UTCTIME                          151
# define ASN1_F_D2I_AUTOPRIVATEKEY                        207
# define ASN1_F_D2I_NETSCAPE_RSA                          152
# define ASN1_F_D2I_NETSCAPE_RSA_2                        153
# define ASN1_F_D2I_PRIVATEKEY                            154
# define ASN1_F_D2I_PUBLICKEY                             155
# define ASN1_F_D2I_RSA_NET                               200
# define ASN1_F_D2I_RSA_NET_2                             201
# define ASN1_F_D2I_X509                                  156
# define ASN1_F_D2I_X509_CINF                             157
# define ASN1_F_D2I_X509_PKEY                             159
# define ASN1_F_DO_TCREATE                                222
# define ASN1_F_I2D_ASN1_BIO_STREAM                       211
# define ASN1_F_I2D_ASN1_SET                              188
# define ASN1_F_I2D_ASN1_TIME                             160
# define ASN1_F_I2D_DSA_PUBKEY                            161
# define ASN1_F_I2D_EC_PUBKEY                             181
# define ASN1_F_I2D_PRIVATEKEY                            163
# define ASN1_F_I2D_PUBLICKEY                             164
# define ASN1_F_I2D_RSA_NET                               162
# define ASN1_F_I2D_RSA_PUBKEY                            165
# define ASN1_F_LONG_C2I                                  166
# define ASN1_F_OID_MODULE_INIT                           174
# define ASN1_F_PARSE_TAGGING                             182
# define ASN1_F_PKCS5_PBE2_SET_IV                         167
# define ASN1_F_PKCS5_PBE2_SET_SCRYPT                     231
# define ASN1_F_PKCS5_PBE_SET                             202
# define ASN1_F_PKCS5_PBE_SET0_ALGOR                      215
# define ASN1_F_PKCS5_PBKDF2_SET                          219
# define ASN1_F_PKCS5_SCRYPT_SET                          232
# define ASN1_F_SMIME_READ_ASN1                           212
# define ASN1_F_SMIME_TEXT                                213
# define ASN1_F_STBL_MODULE_INIT                          223
# define ASN1_F_X509_CINF_NEW                             168
# define ASN1_F_X509_CRL_ADD0_REVOKED                     169
# define ASN1_F_X509_INFO_NEW                             170
# define ASN1_F_X509_NAME_ENCODE                          203
# define ASN1_F_X509_NAME_EX_D2I                          158
# define ASN1_F_X509_NAME_EX_NEW                          171
# define ASN1_F_X509_NEW                                  172
# define ASN1_F_X509_PKEY_NEW                             173
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
# define ASN1_R_ADDING_OBJECT                             171
# define ASN1_R_ASN1_PARSE_ERROR                          203
# define ASN1_R_ASN1_SIG_PARSE_ERROR                      204
# define ASN1_R_AUX_ERROR                                 100
# define ASN1_R_BAD_CLASS                                 101
# define ASN1_R_BAD_OBJECT_HEADER                         102
# define ASN1_R_BAD_PASSWORD_READ                         103
# define ASN1_R_BAD_TAG                                   104
# define ASN1_R_BMPSTRING_IS_WRONG_LENGTH                 214
# define ASN1_R_BN_LIB                                    105
# define ASN1_R_BOOLEAN_IS_WRONG_LENGTH                   106
# define ASN1_R_BUFFER_TOO_SMALL                          107
# define ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER           108
# define ASN1_R_CONTEXT_NOT_INITIALISED                   217
# define ASN1_R_DATA_IS_WRONG                             109
# define ASN1_R_DECODE_ERROR                              110
# define ASN1_R_DECODING_ERROR                            111
# define ASN1_R_DEPTH_EXCEEDED                            174
# define ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED         198
# define ASN1_R_ENCODE_ERROR                              112
# define ASN1_R_ERROR_GETTING_TIME                        173
# define ASN1_R_ERROR_LOADING_SECTION                     172
# define ASN1_R_ERROR_PARSING_SET_ELEMENT                 113
# define ASN1_R_ERROR_SETTING_CIPHER_PARAMS               114
# define ASN1_R_EXPECTING_AN_INTEGER                      115
# define ASN1_R_EXPECTING_AN_OBJECT                       116
# define ASN1_R_EXPECTING_A_BOOLEAN                       117
# define ASN1_R_EXPECTING_A_TIME                          118
# define ASN1_R_EXPLICIT_LENGTH_MISMATCH                  119
# define ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED              120
# define ASN1_R_FIELD_MISSING                             121
# define ASN1_R_FIRST_NUM_TOO_LARGE                       122
# define ASN1_R_HEADER_TOO_LONG                           123
# define ASN1_R_ILLEGAL_BITSTRING_FORMAT                  175
# define ASN1_R_ILLEGAL_BOOLEAN                           176
# define ASN1_R_ILLEGAL_CHARACTERS                        124
# define ASN1_R_ILLEGAL_FORMAT                            177
# define ASN1_R_ILLEGAL_HEX                               178
# define ASN1_R_ILLEGAL_IMPLICIT_TAG                      179
# define ASN1_R_ILLEGAL_INTEGER                           180
# define ASN1_R_ILLEGAL_NEGATIVE_VALUE                    226
# define ASN1_R_ILLEGAL_NESTED_TAGGING                    181
# define ASN1_R_ILLEGAL_NULL                              125
# define ASN1_R_ILLEGAL_NULL_VALUE                        182
# define ASN1_R_ILLEGAL_OBJECT                            183
# define ASN1_R_ILLEGAL_OPTIONAL_ANY                      126
# define ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE          170
# define ASN1_R_ILLEGAL_PADDING                           221
# define ASN1_R_ILLEGAL_TAGGED_ANY                        127
# define ASN1_R_ILLEGAL_TIME_VALUE                        184
# define ASN1_R_ILLEGAL_ZERO_CONTENT                      222
# define ASN1_R_INTEGER_NOT_ASCII_FORMAT                  185
# define ASN1_R_INTEGER_TOO_LARGE_FOR_LONG                128
# define ASN1_R_INVALID_BIT_STRING_BITS_LEFT              220
# define ASN1_R_INVALID_BMPSTRING_LENGTH                  129
# define ASN1_R_INVALID_DIGIT                             130
# define ASN1_R_INVALID_MIME_TYPE                         205
# define ASN1_R_INVALID_MODIFIER                          186
# define ASN1_R_INVALID_NUMBER                            187
# define ASN1_R_INVALID_OBJECT_ENCODING                   216
# define ASN1_R_INVALID_SCRYPT_PARAMETERS                 227
# define ASN1_R_INVALID_SEPARATOR                         131
# define ASN1_R_INVALID_STRING_TABLE_VALUE                218
# define ASN1_R_INVALID_TIME_FORMAT                       132
# define ASN1_R_INVALID_UNIVERSALSTRING_LENGTH            133
# define ASN1_R_INVALID_UTF8STRING                        134
# define ASN1_R_INVALID_VALUE                             219
# define ASN1_R_IV_TOO_LARGE                              135
# define ASN1_R_LENGTH_ERROR                              136
# define ASN1_R_LIST_ERROR                                188
# define ASN1_R_MIME_NO_CONTENT_TYPE                      206
# define ASN1_R_MIME_PARSE_ERROR                          207
# define ASN1_R_MIME_SIG_PARSE_ERROR                      208
# define ASN1_R_MISSING_EOC                               137
# define ASN1_R_MISSING_SECOND_NUMBER                     138
# define ASN1_R_MISSING_VALUE                             189
# define ASN1_R_MSTRING_NOT_UNIVERSAL                     139
# define ASN1_R_MSTRING_WRONG_TAG                         140
# define ASN1_R_NESTED_ASN1_STRING                        197
# define ASN1_R_NON_HEX_CHARACTERS                        141
# define ASN1_R_NOT_ASCII_FORMAT                          190
# define ASN1_R_NOT_ENOUGH_DATA                           142
# define ASN1_R_NO_CONTENT_TYPE                           209
# define ASN1_R_NO_DEFAULT_DIGEST                         201
# define ASN1_R_NO_MATCHING_CHOICE_TYPE                   143
# define ASN1_R_NO_MULTIPART_BODY_FAILURE                 210
# define ASN1_R_NO_MULTIPART_BOUNDARY                     211
# define ASN1_R_NO_SIG_CONTENT_TYPE                       212
# define ASN1_R_NULL_IS_WRONG_LENGTH                      144
# define ASN1_R_OBJECT_NOT_ASCII_FORMAT                   191
# define ASN1_R_ODD_NUMBER_OF_CHARS                       145
# define ASN1_R_PRIVATE_KEY_HEADER_MISSING                146
# define ASN1_R_SECOND_NUMBER_TOO_LARGE                   147
# define ASN1_R_SEQUENCE_LENGTH_MISMATCH                  148
# define ASN1_R_SEQUENCE_NOT_CONSTRUCTED                  149
# define ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG              192
# define ASN1_R_SHORT_LINE                                150
# define ASN1_R_SIG_INVALID_MIME_TYPE                     213
# define ASN1_R_STREAMING_NOT_SUPPORTED                   202
# define ASN1_R_STRING_TOO_LONG                           151
# define ASN1_R_STRING_TOO_SHORT                          152
# define ASN1_R_TAG_VALUE_TOO_HIGH                        153
# define ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 154
# define ASN1_R_TIME_NOT_ASCII_FORMAT                     193
# define ASN1_R_TOO_LARGE                                 223
# define ASN1_R_TOO_LONG                                  155
# define ASN1_R_TOO_SMALL                                 224
# define ASN1_R_TYPE_NOT_CONSTRUCTED                      156
# define ASN1_R_TYPE_NOT_PRIMITIVE                        195
# define ASN1_R_UNABLE_TO_DECODE_RSA_KEY                  157
# define ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY          158
# define ASN1_R_UNEXPECTED_EOC                            159
# define ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH           215
# define ASN1_R_UNKNOWN_FORMAT                            160
# define ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM          161
# define ASN1_R_UNKNOWN_OBJECT_TYPE                       162
# define ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE                   163
# define ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM               199
# define ASN1_R_UNKNOWN_TAG                               194
# define ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE           164
# define ASN1_R_UNSUPPORTED_CIPHER                        165
# define ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM          166
# define ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE               167
# define ASN1_R_UNSUPPORTED_TYPE                          196
# define ASN1_R_WRONG_INTEGER_TYPE                        225
# define ASN1_R_WRONG_PUBLIC_KEY_TYPE                     200
# define ASN1_R_WRONG_TAG                                 168
# define ASN1_R_WRONG_TYPE                                169
# define ASN1_STRFLGS_DUMP_ALL           0x80
# define ASN1_STRFLGS_DUMP_DER           0x200
# define ASN1_STRFLGS_DUMP_UNKNOWN       0x100
# define ASN1_STRFLGS_ESC_2253           1
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
# define ASN1_STRING_FLAG_MSTRING 0x040
# define ASN1_STRING_FLAG_NDEF 0x010
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
#  define OPENSSL_EXTERN OPENSSL_EXPORT
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
# define V_ASN1_PRIMATIVE_TAG            0x1f
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
# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1
# define EVP_CIPHER_CTX_mode(e)          (EVP_CIPHER_CTX_flags(e) & EVP_CIPH_MODE)
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
# define         EVP_CTRL_AEAD_SET_MAC_KEY       0x17
# define         EVP_CTRL_AEAD_SET_TAG           0x11
# define         EVP_CTRL_AEAD_TLS1_AAD          0x16
# define         EVP_CTRL_CCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_CCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_CCM_SET_L              0x14
# define         EVP_CTRL_CCM_SET_MSGLEN         0x15
# define         EVP_CTRL_CCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_COPY                   0x8
# define         EVP_CTRL_GCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_GCM_IV_GEN             0x13
# define         EVP_CTRL_GCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_GCM_SET_IV_FIXED       0x12
# define         EVP_CTRL_GCM_SET_IV_INV         0x18
# define         EVP_CTRL_GCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         EVP_CTRL_GET_RC5_ROUNDS         0x4
# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_PBE_PRF_NID            0x7
# define         EVP_CTRL_RAND_KEY               0x6
# define         EVP_CTRL_SET_KEY_LENGTH         0x1
# define         EVP_CTRL_SET_RC2_KEY_BITS       0x3
# define         EVP_CTRL_SET_RC5_ROUNDS         0x5
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
# define EVP_F_EVP_PKCS82PKEY_BROKEN                      136
# define EVP_F_EVP_PKEY2PKCS8_BROKEN                      113
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
# define EVP_F_EVP_PKEY_GET1_DH                           119
# define EVP_F_EVP_PKEY_GET1_DSA                          120
# define EVP_F_EVP_PKEY_GET1_ECDSA                        130
# define EVP_F_EVP_PKEY_GET1_EC_KEY                       131
# define EVP_F_EVP_PKEY_GET1_RSA                          121
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
# define EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
#  define EVP_MD_FLAG_DIGALGID_ABSENT             0x0008
#  define EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018
#  define EVP_MD_FLAG_DIGALGID_MASK               0x0018
#  define EVP_MD_FLAG_DIGALGID_NULL               0x0000
#  define EVP_MD_FLAG_FIPS        0x0400
#  define EVP_MD_FLAG_ONESHOT     0x0001
#  define EVP_MD_FLAG_PKEY_DIGEST 0x0002
#  define EVP_MD_FLAG_PKEY_METHOD_SIGNATURE       0x0004
# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))
# define EVP_MD_nid(e)                   EVP_MD_type(e)
# define EVP_OpenUpdate(a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)
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
#   define EVP_PKEY_DSA_method     (evp_sign_method *)DSA_sign, \
                                (evp_verify_method *)DSA_verify, \
                                {EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3, \
                                        EVP_PKEY_DSA4,0}
# define EVP_PKEY_EC     NID_X9_62_id_ecPublicKey
#   define EVP_PKEY_ECDSA_method   (evp_sign_method *)ECDSA_sign, \
                                (evp_verify_method *)ECDSA_verify, \
                                 {EVP_PKEY_EC,0,0,0}
# define EVP_PKEY_FLAG_AUTOARGLEN        2
# define EVP_PKEY_FLAG_SIGCTX_CUSTOM     4
# define EVP_PKEY_HMAC   NID_hmac
# define EVP_PKEY_MO_DECRYPT     0x0008
# define EVP_PKEY_MO_ENCRYPT     0x0004
# define EVP_PKEY_MO_SIGN        0x0001
# define EVP_PKEY_MO_VERIFY      0x0002
# define EVP_PKEY_NONE   NID_undef
#  define EVP_PKEY_NULL_method    NULL,NULL,{0,0,0,0}
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
#   define EVP_PKEY_RSA_ASN1_OCTET_STRING_method \
                                (evp_sign_method *)RSA_sign_ASN1_OCTET_STRING, \
                                (evp_verify_method *)RSA_verify_ASN1_OCTET_STRING, \
                                {EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
#   define EVP_PKEY_RSA_method     (evp_sign_method *)RSA_sign, \
                                (evp_verify_method *)RSA_verify, \
                                {EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
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
#  define EVP_aes_128_cfb EVP_aes_128_cfb128
#  define EVP_aes_192_cfb EVP_aes_192_cfb128
#  define EVP_aes_256_cfb EVP_aes_256_cfb128
#  define EVP_bf_cfb EVP_bf_cfb64
#  define EVP_camellia_128_cfb EVP_camellia_128_cfb128
#  define EVP_camellia_192_cfb EVP_camellia_192_cfb128
#  define EVP_camellia_256_cfb EVP_camellia_256_cfb128
#  define EVP_cast5_cfb EVP_cast5_cfb64
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
# define M_EVP_CIPHER_CTX_block_size(e)  ((e)->cipher->block_size)
# define M_EVP_CIPHER_CTX_cipher(e)      ((e)->cipher)
# define M_EVP_CIPHER_CTX_flags(e)       ((e)->cipher->flags)
# define M_EVP_CIPHER_CTX_iv_length(e)   ((e)->cipher->iv_len)
# define M_EVP_CIPHER_CTX_mode(e)        (M_EVP_CIPHER_CTX_flags(e) & EVP_CIPH_MODE)
# define M_EVP_CIPHER_CTX_set_flags(ctx,flgs) ((ctx)->flags|=(flgs))
# define M_EVP_CIPHER_nid(e)             ((e)->nid)
# define M_EVP_DecryptInit(ctx,ciph,key,iv) \
        (EVP_CipherInit(ctx,ciph,key,iv,0))
# define M_EVP_DecryptInit_ex(ctx,ciph,impl,key,iv) \
        (EVP_CipherInit_ex(ctx,ciph,impl,key,iv,0))
# define M_EVP_EncryptInit(ctx,ciph,key,iv) \
        (EVP_CipherInit(ctx,ciph,key,iv,1))
# define M_EVP_EncryptInit_ex(ctx,ciph,impl,key,iv) \
        (EVP_CipherInit_ex(ctx,ciph,impl,key,iv,1))
# define M_EVP_MD_CTX_clear_flags(ctx,flgs) ((ctx)->flags&=~(flgs))
# define M_EVP_MD_CTX_md(e)                      ((e)->digest)
# define M_EVP_MD_CTX_set_flags(ctx,flgs) ((ctx)->flags|=(flgs))
# define M_EVP_MD_CTX_test_flags(ctx,flgs) ((ctx)->flags&(flgs))
# define M_EVP_MD_CTX_type(e)            M_EVP_MD_type(M_EVP_MD_CTX_md(e))
# define M_EVP_MD_block_size(e)          ((e)->block_size)
# define M_EVP_MD_size(e)                ((e)->md_size)
# define M_EVP_MD_type(e)                        ((e)->type)
#  define OPENSSL_ALGORITHM_DEFINES
#  define OpenSSL_add_all_algorithms() \
                OPENSSL_add_all_algorithms_conf()
# define PKCS5_DEFAULT_ITER              2048
# define PKCS5_SALT_LEN                  8
# define SSLeay_add_all_algorithms() OpenSSL_add_all_algorithms()
# define SSLeay_add_all_ciphers() OpenSSL_add_all_ciphers()
# define SSLeay_add_all_digests() OpenSSL_add_all_digests()
# define BUF_F_BUF_MEMDUP                                 103
# define BUF_F_BUF_MEM_GROW                               100
# define BUF_F_BUF_MEM_GROW_CLEAN                         105
# define BUF_F_BUF_MEM_NEW                                101
# define BUF_F_BUF_STRDUP                                 102
# define BUF_F_BUF_STRNDUP                                104
# define HEADER_BUFFER_H
# define CHECKED_LHASH_OF(type,lh) \
  ((_LHASH *)CHECKED_PTR_OF(LHASH_OF(type),lh))
# define DECLARE_LHASH_COMP_FN(name, o_type) \
        int name##_LHASH_COMP(const void *, const void *);
# define DECLARE_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
        void name##_LHASH_DOALL_ARG(void *, void *);
# define DECLARE_LHASH_DOALL_FN(name, o_type) \
        void name##_LHASH_DOALL(void *);
# define DECLARE_LHASH_HASH_FN(name, o_type) \
        unsigned long name##_LHASH_HASH(const void *);
# define DECLARE_LHASH_OF(type) LHASH_OF(type) { int dummy; }
# define HEADER_LHASH_H
# define IMPLEMENT_LHASH_COMP_FN(name, o_type) \
        int name##_LHASH_COMP(const void *arg1, const void *arg2) { \
                const o_type *a = arg1;             \
                const o_type *b = arg2; \
                return name##_cmp(a,b); }
# define IMPLEMENT_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
        void name##_LHASH_DOALL_ARG(void *arg1, void *arg2) { \
                o_type *a = arg1; \
                a_type *b = arg2; \
                name##_doall_arg(a, b); }
# define IMPLEMENT_LHASH_DOALL_FN(name, o_type) \
        void name##_LHASH_DOALL(void *arg) { \
                o_type *a = arg; \
                name##_doall(a); }
# define IMPLEMENT_LHASH_HASH_FN(name, o_type) \
        unsigned long name##_LHASH_HASH(const void *arg) { \
                const o_type *a = arg; \
                return name##_hash(a); }
# define LHASH_COMP_FN(name) name##_LHASH_COMP
# define LHASH_DOALL_ARG_FN(name) name##_LHASH_DOALL_ARG
# define LHASH_DOALL_FN(name) name##_LHASH_DOALL
# define LHASH_HASH_FN(name) name##_LHASH_HASH
# define LHASH_OF(type) struct lhash_st_##type
# define LHM_lh_delete(type, lh, inst) \
  ((type *)lh_delete(CHECKED_LHASH_OF(type, lh),                        \
                     CHECKED_PTR_OF(type, inst)))
# define LHM_lh_doall(type, lh,fn) lh_doall(CHECKED_LHASH_OF(type, lh), fn)
# define LHM_lh_doall_arg(type, lh, fn, arg_type, arg) \
  lh_doall_arg(CHECKED_LHASH_OF(type, lh), fn, CHECKED_PTR_OF(arg_type, arg))
# define LHM_lh_down_load(type, lh) (CHECKED_LHASH_OF(type, lh)->down_load)
# define LHM_lh_error(type, lh) \
  lh_error(CHECKED_LHASH_OF(type,lh))
# define LHM_lh_free(type, lh) lh_free(CHECKED_LHASH_OF(type, lh))
# define LHM_lh_insert(type, lh, inst) \
  ((type *)lh_insert(CHECKED_LHASH_OF(type, lh), \
                     CHECKED_PTR_OF(type, inst)))
# define LHM_lh_new(type, name) \
  ((LHASH_OF(type) *)lh_new(LHASH_HASH_FN(name), LHASH_COMP_FN(name)))
# define LHM_lh_node_stats_bio(type, lh, out) \
  lh_node_stats_bio(CHECKED_LHASH_OF(type, lh), out)
# define LHM_lh_node_usage_stats_bio(type, lh, out) \
  lh_node_usage_stats_bio(CHECKED_LHASH_OF(type, lh), out)
# define LHM_lh_num_items(type, lh) lh_num_items(CHECKED_LHASH_OF(type, lh))
# define LHM_lh_retrieve(type, lh, inst) \
  ((type *)lh_retrieve(CHECKED_LHASH_OF(type, lh), \
                       CHECKED_PTR_OF(type, inst)))
# define LHM_lh_stats_bio(type, lh, out) \
  lh_stats_bio(CHECKED_LHASH_OF(type, lh), out)
# define LH_LOAD_MULT    256
# define lh_error(lh)    ((lh)->error)
# define CRYPTO_EX_INDEX_BIO             0
# define CRYPTO_EX_INDEX_COMP            14
# define CRYPTO_EX_INDEX_DH              8
# define CRYPTO_EX_INDEX_DSA             7
# define CRYPTO_EX_INDEX_ECDH            13
# define CRYPTO_EX_INDEX_ECDSA           12
# define CRYPTO_EX_INDEX_ENGINE          9
# define CRYPTO_EX_INDEX_RSA             6
# define CRYPTO_EX_INDEX_SSL             1
# define CRYPTO_EX_INDEX_SSL_CTX         2
# define CRYPTO_EX_INDEX_SSL_SESSION     3
# define CRYPTO_EX_INDEX_STORE           15
# define CRYPTO_EX_INDEX_UI              11
# define CRYPTO_EX_INDEX_USER            100
# define CRYPTO_EX_INDEX_X509            10
# define CRYPTO_EX_INDEX_X509_STORE      4
# define CRYPTO_EX_INDEX_X509_STORE_CTX  5
# define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX                 100
# define CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID                103
# define CRYPTO_F_CRYPTO_GET_NEW_LOCKID                   101
# define CRYPTO_F_CRYPTO_SET_EX_DATA                      102
# define CRYPTO_F_DEF_ADD_INDEX                           104
# define CRYPTO_F_DEF_GET_CLASS                           105
# define CRYPTO_F_FIPS_MODE_SET                           109
# define CRYPTO_F_INT_DUP_EX_DATA                         106
# define CRYPTO_F_INT_FREE_EX_DATA                        107
# define CRYPTO_F_INT_NEW_EX_DATA                         108
# define CRYPTO_LOCK             1
# define CRYPTO_LOCK_BIO                 21
# define CRYPTO_LOCK_BN                  35
# define CRYPTO_LOCK_COMP                38
# define CRYPTO_LOCK_DH                  26
# define CRYPTO_LOCK_DSA                 8
# define CRYPTO_LOCK_DSO                 28
# define CRYPTO_LOCK_DYNLOCK             29
# define CRYPTO_LOCK_EC                  33
# define CRYPTO_LOCK_ECDH                34
# define CRYPTO_LOCK_ECDSA               32
# define CRYPTO_LOCK_EC_PRE_COMP         36
# define CRYPTO_LOCK_ENGINE              30
# define CRYPTO_LOCK_ERR                 1
# define CRYPTO_LOCK_EVP_PKEY            10
# define CRYPTO_LOCK_EX_DATA             2
# define CRYPTO_LOCK_FIPS                39
# define CRYPTO_LOCK_FIPS2               40
# define CRYPTO_LOCK_GETHOSTBYNAME       22
# define CRYPTO_LOCK_GETSERVBYNAME       23
# define CRYPTO_LOCK_MALLOC              20
# define CRYPTO_LOCK_MALLOC2             27
# define CRYPTO_LOCK_RAND                18
# define CRYPTO_LOCK_RAND2               19
# define CRYPTO_LOCK_READDIR             24
# define CRYPTO_LOCK_RSA                 9
# define CRYPTO_LOCK_RSA_BLINDING        25
# define CRYPTO_LOCK_SSL                 16
# define CRYPTO_LOCK_SSL_CERT            13
# define CRYPTO_LOCK_SSL_CTX             12
# define CRYPTO_LOCK_SSL_METHOD          17
# define CRYPTO_LOCK_SSL_SESSION         14
# define CRYPTO_LOCK_SSL_SESS_CERT       15
# define CRYPTO_LOCK_STORE               37
# define CRYPTO_LOCK_UI                  31
# define CRYPTO_LOCK_X509                3
# define CRYPTO_LOCK_X509_CRL            6
# define CRYPTO_LOCK_X509_INFO           4
# define CRYPTO_LOCK_X509_PKEY           5
# define CRYPTO_LOCK_X509_REQ            7
# define CRYPTO_LOCK_X509_STORE          11
#   define CRYPTO_MDEBUG
# define CRYPTO_MEM_CHECK_DISABLE 0x3
# define CRYPTO_MEM_CHECK_ENABLE 0x2
# define CRYPTO_MEM_CHECK_OFF    0x0
# define CRYPTO_MEM_CHECK_ON     0x1
# define CRYPTO_NUM_LOCKS                41
# define CRYPTO_READ             4
# define CRYPTO_R_FIPS_MODE_NOT_SUPPORTED                 101
# define CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK              100
# define CRYPTO_UNLOCK           2
# define CRYPTO_WRITE            8
#   define CRYPTO_add(addr,amount,type)    \
        CRYPTO_add_lock(addr,amount,type,"__FILE__","__LINE__")
# define CRYPTO_malloc_debug_init()      do {\
        CRYPTO_set_mem_debug_functions(\
                CRYPTO_dbg_malloc,\
                CRYPTO_dbg_realloc,\
                CRYPTO_dbg_free,\
                CRYPTO_dbg_set_options,\
                CRYPTO_dbg_get_options);\
        } while(0)
# define CRYPTO_malloc_init()    CRYPTO_set_mem_functions(\
        malloc, realloc, free)
# define CRYPTO_push_info(info) \
        CRYPTO_push_info_(info, "__FILE__", "__LINE__");
#   define CRYPTO_r_lock(type)     \
        CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,"__FILE__","__LINE__")
#   define CRYPTO_r_unlock(type)   \
        CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,"__FILE__","__LINE__")
#   define CRYPTO_w_lock(type)     \
        CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,"__FILE__","__LINE__")
#   define CRYPTO_w_unlock(type)   \
        CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,"__FILE__","__LINE__")
# define HEADER_CRYPTO_H
# define MemCheck_off()  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
# define MemCheck_on()   CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
# define MemCheck_start() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON)
# define MemCheck_stop() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF)
# define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))
# define OPENSSL_assert(e)       (void)((e) ? 0 : (OpenSSLDie("__FILE__", "__LINE__", #e),1))
# define OPENSSL_clear_free(addr, num) CRYPTO_clear_free(addr, num)
# define OPENSSL_free(addr)      CRYPTO_free(addr)
# define OPENSSL_free_locked(addr) CRYPTO_free_locked(addr)
# define OPENSSL_ia32cap ((OPENSSL_ia32cap_loc())[0])
# define OPENSSL_malloc(num)     CRYPTO_malloc((int)num,"__FILE__","__LINE__")
# define OPENSSL_malloc_locked(num) \
        CRYPTO_malloc_locked((int)num,"__FILE__","__LINE__")
# define OPENSSL_realloc(addr,num) \
        CRYPTO_realloc((char *)addr,(int)num,"__FILE__","__LINE__")
# define OPENSSL_realloc_clean(addr,old_num,num) \
        CRYPTO_realloc_clean(addr,old_num,num,"__FILE__","__LINE__")
# define OPENSSL_remalloc(addr,num) \
        CRYPTO_remalloc((char **)addr,(int)num,"__FILE__","__LINE__")
# define OPENSSL_strdup(str)     CRYPTO_strdup((str),"__FILE__","__LINE__")
# define SSLEAY_BUILT_ON         3
# define SSLEAY_CFLAGS           2
# define SSLEAY_DIR              5
# define SSLEAY_PLATFORM         4
# define SSLEAY_VERSION          0
# define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
# define V_CRYPTO_MDEBUG_ALL (V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD)
# define V_CRYPTO_MDEBUG_THREAD  0x2
# define V_CRYPTO_MDEBUG_TIME    0x1
# define is_MemCheck_on() CRYPTO_is_mem_check_on()
#  define BIO_FLAGS_UPLINK 0x8000
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEADER_CRYPTLIB_H
# define HEX_SIZE(type)          (sizeof(type)*2)
#  define X509_CERT_AREA          OPENSSLDIR
#  define X509_CERT_DIR           OPENSSLDIR "/certs"
# define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#  define X509_CERT_FILE          OPENSSLDIR "/cert.pem"
# define X509_CERT_FILE_EVP       "SSL_CERT_FILE"
#  define X509_PRIVATE_DIR        OPENSSLDIR "/private"
