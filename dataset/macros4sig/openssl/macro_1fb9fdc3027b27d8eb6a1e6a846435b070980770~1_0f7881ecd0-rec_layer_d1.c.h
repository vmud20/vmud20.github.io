#include<stdio.h>
#include<errno.h>
#define DTLS_RECORD_LAYER_get_r_epoch(rl)       ((rl)->d->r_epoch)
#define RECORD_LAYER_clear_first_record(rl)     ((rl)->is_first_record = 0)
#define RECORD_LAYER_get_empty_record_count(rl) ((rl)->empty_record_count)
#define RECORD_LAYER_get_numrpipes(rl)          ((rl)->numrpipes)
#define RECORD_LAYER_get_rbuf(rl)               (&(rl)->rbuf)
#define RECORD_LAYER_get_read_sequence(rl)      ((rl)->read_sequence)
#define RECORD_LAYER_get_rrec(rl)               ((rl)->rrec)
#define RECORD_LAYER_get_rstate(rl)             ((rl)->rstate)
#define RECORD_LAYER_get_wbuf(rl)               ((rl)->wbuf)
#define RECORD_LAYER_get_write_sequence(rl)     ((rl)->write_sequence)
#define RECORD_LAYER_inc_empty_record_count(rl) ((rl)->empty_record_count++)
#define RECORD_LAYER_is_first_record(rl)        ((rl)->is_first_record)
#define RECORD_LAYER_reset_empty_record_count(rl) \
                                                ((rl)->empty_record_count = 0)
#define RECORD_LAYER_reset_packet_length(rl)    ((rl)->packet_length = 0)
#define RECORD_LAYER_set_first_record(rl)       ((rl)->is_first_record = 1)
#define RECORD_LAYER_set_numrpipes(rl, n)       ((rl)->numrpipes = (n))
#define RECORD_LAYER_set_packet(rl, p)          ((rl)->packet = (p))
#define RECORD_LAYER_set_rstate(rl, st)         ((rl)->rstate = (st))
#define SSL3_BUFFER_add_left(b, l)          ((b)->left += (l))
#define SSL3_BUFFER_add_offset(b, o)        ((b)->offset += (o))
#define SSL3_BUFFER_get_buf(b)              ((b)->buf)
#define SSL3_BUFFER_get_left(b)             ((b)->left)
#define SSL3_BUFFER_get_len(b)              ((b)->len)
#define SSL3_BUFFER_get_offset(b)           ((b)->offset)
#define SSL3_BUFFER_is_initialised(b)       ((b)->buf != NULL)
#define SSL3_BUFFER_set_buf(b, n)           ((b)->buf = (n))
#define SSL3_BUFFER_set_default_len(b, l)   ((b)->default_len = (l))
#define SSL3_BUFFER_set_left(b, l)          ((b)->left = (l))
#define SSL3_BUFFER_set_len(b, l)           ((b)->len = (l))
#define SSL3_BUFFER_set_offset(b, o)        ((b)->offset = (o))
#define SSL3_RECORD_add_length(r, l)            ((r)->length += (l))
#define SSL3_RECORD_add_off(r, o)               ((r)->off += (o))
#define SSL3_RECORD_get_data(r)                 ((r)->data)
#define SSL3_RECORD_get_epoch(r)                ((r)->epoch)
#define SSL3_RECORD_get_input(r)                ((r)->input)
#define SSL3_RECORD_get_length(r)               ((r)->length)
#define SSL3_RECORD_get_off(r)                  ((r)->off)
#define SSL3_RECORD_get_seq_num(r)              ((r)->seq_num)
#define SSL3_RECORD_get_type(r)                 ((r)->type)
#define SSL3_RECORD_is_read(r)                  ((r)->read)
#define SSL3_RECORD_is_sslv2_record(r) \
            ((r)->rec_version == SSL2_VERSION)
#define SSL3_RECORD_reset_input(r)              ((r)->input = (r)->data)
#define SSL3_RECORD_set_data(r, d)              ((r)->data = (d))
#define SSL3_RECORD_set_input(r, i)             ((r)->input = (i))
#define SSL3_RECORD_set_length(r, l)            ((r)->length = (l))
#define SSL3_RECORD_set_off(r, o)               ((r)->off = (o))
#define SSL3_RECORD_set_read(r)                 ((r)->read = 1)
#define SSL3_RECORD_set_type(r, t)              ((r)->type = (t))
#define SSL3_RECORD_sub_length(r, l)            ((r)->length -= (l))
# define BUF_F_BUF_MEM_GROW                               100
# define BUF_F_BUF_MEM_GROW_CLEAN                         105
# define BUF_F_BUF_MEM_NEW                                101
# define BUF_MEM_FLAG_SECURE  0x01
# define BUF_memdup(data, size) OPENSSL_memdup(data, size)
# define BUF_strdup(s) OPENSSL_strdup(s)
# define BUF_strlcat(dst, src, size) OPENSSL_strlcat(dst, src, size)
# define BUF_strlcpy(dst, src, size)  OPENSSL_strlcpy(dst, src, size)
# define BUF_strndup(s, size) OPENSSL_strndup(s, size)
# define BUF_strnlen(str, maxlen) OPENSSL_strnlen(str, maxlen)
# define HEADER_BUFFER_H
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
# define EVP_F_AES_T4_INIT_KEY                            178
# define EVP_F_ALG_MODULE_INIT                            177
# define EVP_F_CAMELLIA_INIT_KEY                          159
# define EVP_F_CHACHA20_POLY1305_CTRL                     182
# define EVP_F_CMLL_T4_INIT_KEY                           179
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
# define EVP_R_FIPS_MODE_NOT_SUPPORTED                    167
# define EVP_R_ILLEGAL_SCRYPT_PARAMETERS                  171
# define EVP_R_INITIALIZATION_ERROR                       134
# define EVP_R_INPUT_NOT_INITIALIZED                      111
# define EVP_R_INVALID_DIGEST                             152
# define EVP_R_INVALID_FIPS_MODE                          168
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
# define DEC32(a)        ((a)=((a)-1)&0xffffffffL)
# define DTLS1_MAX_MTU_OVERHEAD                   48
#  define DTLS1_SCTP_AUTH_LABEL   "EXPORTER_DTLS_OVER_SCTP"
# define DTLS1_SKIP_RECORD_HEADER                 2
# define DTLS_VERSION_GE(v1, v2) (dtls_ver_ordinal(v1) <= dtls_ver_ordinal(v2))
# define DTLS_VERSION_GT(v1, v2) (dtls_ver_ordinal(v1) < dtls_ver_ordinal(v2))
# define DTLS_VERSION_LE(v1, v2) (dtls_ver_ordinal(v1) >= dtls_ver_ordinal(v2))
# define DTLS_VERSION_LT(v1, v2) (dtls_ver_ordinal(v1) > dtls_ver_ordinal(v2))
#  define EXPLICIT_CHAR2_CURVE_TYPE  2
#  define EXPLICIT_PRIME_CURVE_TYPE  1
# define FP_ICC  (int (*)(const void *,const void *))
# define HEADER_SSL_LOCL_H
# define IMPLEMENT_dtls1_meth_func(version, flags, mask, func_name, s_accept, \
                                        s_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                flags, \
                mask, \
                dtls1_new, \
                dtls1_clear, \
                dtls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                dtls1_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                dtls1_read_bytes, \
                dtls1_write_app_data_bytes, \
                dtls1_dispatch_alert, \
                dtls1_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                dtls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
# define IMPLEMENT_ssl3_meth_func(func_name, s_accept, s_connect) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                SSL3_VERSION, \
                SSL_METHOD_NO_FIPS | SSL_METHOD_NO_SUITEB, \
                SSL_OP_NO_SSLv3, \
                ssl3_new, \
                ssl3_clear, \
                ssl3_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_read_bytes, \
                ssl3_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                ssl3_default_timeout, \
                &SSLv3_enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
# define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                flags, \
                mask, \
                tls1_new, \
                tls1_clear, \
                tls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_read_bytes, \
                ssl3_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
# define INC32(a)        ((a)=((a)+1)&0xffffffffL)
# define MAX_MAC_SIZE    20     
#  define NAMED_CURVE_TYPE           3
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# define SEC_ESC_BIT     0x40
# define SSL_3DES                0x00000002U
# define SSL_AEAD                0x00000040U
# define SSL_AES                 (SSL_AES128|SSL_AES256|SSL_AESGCM|SSL_AESCCM)
# define SSL_AES128              0x00000040U
# define SSL_AES128CCM           0x00004000U
# define SSL_AES128CCM8          0x00010000U
# define SSL_AES128GCM           0x00001000U
# define SSL_AES256              0x00000080U
# define SSL_AES256CCM           0x00008000U
# define SSL_AES256CCM8          0x00020000U
# define SSL_AES256GCM           0x00002000U
# define SSL_AESCCM              (SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8)
# define SSL_AESGCM              (SSL_AES128GCM | SSL_AES256GCM)
# define SSL_CAMELLIA            (SSL_CAMELLIA128|SSL_CAMELLIA256)
# define SSL_CAMELLIA128         0x00000100U
# define SSL_CAMELLIA256         0x00000200U
# define SSL_CERT_FLAGS_CHECK_TLS_STRICT \
        (SSL_CERT_FLAG_SUITEB_128_LOS|SSL_CERT_FLAG_TLS_STRICT)
# define SSL_CHACHA20            (SSL_CHACHA20POLY1305)
# define SSL_CHACHA20POLY1305    0x00080000U
# define SSL_CLIENT_USE_SIGALGS(s)        \
    SSL_CLIENT_USE_TLS1_2_CIPHERS(s)
# define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)        \
    ((!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION) || \
     (SSL_IS_DTLS(s) && DTLS_VERSION_GE(s->client_version, DTLS1_2_VERSION)))
# define SSL_DECRYPT     0
# define SSL_DEFAULT_MASK        0X00000020U
# define SSL_DES                 0x00000001U
# define SSL_ENCRYPT     1
# define SSL_ENC_FLAG_DTLS               0x8
# define SSL_ENC_FLAG_EXPLICIT_IV        0x1
# define SSL_ENC_FLAG_SHA256_PRF         0x4
# define SSL_ENC_FLAG_SIGALGS            0x2
# define SSL_ENC_FLAG_TLS1_2_CIPHERS     0x10
# define SSL_EXT_FLAG_RECEIVED   0x1
# define SSL_EXT_FLAG_SENT       0x2
# define SSL_FIPS                0x00000010U
# define SSL_GOST12_256          0x00000080U
# define SSL_GOST12_512          0x00000200U
# define SSL_GOST89MAC   0x00000008U
# define SSL_GOST89MAC12         0x00000100U
# define SSL_GOST94      0x00000004U
# define SSL_HANDSHAKE_MAC_DEFAULT  SSL_HANDSHAKE_MAC_MD5_SHA1
# define SSL_HANDSHAKE_MAC_GOST12_256 SSL_MD_GOST12_256_IDX
# define SSL_HANDSHAKE_MAC_GOST12_512 SSL_MD_GOST12_512_IDX
# define SSL_HANDSHAKE_MAC_GOST94 SSL_MD_GOST94_IDX
# define SSL_HANDSHAKE_MAC_MASK  0xFF
# define SSL_HANDSHAKE_MAC_MD5_SHA1 SSL_MD_MD5_SHA1_IDX
# define SSL_HANDSHAKE_MAC_SHA256   SSL_MD_SHA256_IDX
# define SSL_HANDSHAKE_MAC_SHA384   SSL_MD_SHA384_IDX
# define SSL_HIGH                0x00000008U
# define SSL_HM_HEADER_LENGTH(s) s->method->ssl3_enc->hhlen
# define SSL_IDEA                0x00000010U
# define SSL_IS_DTLS(s)  (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)
# define SSL_LOW                 0x00000002U
# define SSL_MAX_DIGEST 12
# define SSL_MD5                 0x00000001U
# define SSL_MD_GOST12_256_IDX  6
# define SSL_MD_GOST12_512_IDX  8
# define SSL_MD_GOST89MAC12_IDX 7
# define SSL_MD_GOST89MAC_IDX 3
# define SSL_MD_GOST94_IDX 2
# define SSL_MD_MD5_IDX  0
# define SSL_MD_MD5_SHA1_IDX 9
# define SSL_MD_SHA1_IDX 1
# define SSL_MD_SHA224_IDX 10
# define SSL_MD_SHA256_IDX 4
# define SSL_MD_SHA384_IDX 5
# define SSL_MD_SHA512_IDX 11
# define SSL_MEDIUM              0x00000004U
# define SSL_METHOD_NO_FIPS      (1U<<0)
# define SSL_METHOD_NO_SUITEB    (1U<<1)
# define SSL_NOT_DEFAULT         0x00000020U
# define SSL_PKEY_DSA_SIGN       2
# define SSL_PKEY_ECC            3
# define SSL_PKEY_GOST01         4
# define SSL_PKEY_GOST12_256     5
# define SSL_PKEY_GOST12_512     6
# define SSL_PKEY_GOST_EC SSL_PKEY_NUM+1
# define SSL_PKEY_NUM            7
# define SSL_PKEY_RSA_ENC        0
# define SSL_PKEY_RSA_SIGN       1
# define SSL_PSK     (SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK)
# define SSL_RC2                 0x00000008U
# define SSL_RC4                 0x00000004U
# define SSL_SEED                0x00000800U
# define SSL_SESS_FLAG_EXTMS             0x1
# define SSL_SHA1                0x00000002U
# define SSL_SHA256              0x00000010U
# define SSL_SHA384              0x00000020U
# define SSL_STRONG_MASK         0x0000001FU
# define SSL_STRONG_NONE         0x00000001U
# define SSL_USE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC)
# define SSL_USE_EXPLICIT_IV(s)  \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)
# define SSL_USE_SIGALGS(s)      \
                        (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS)
# define SSL_USE_TLS1_2_CIPHERS(s)       \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
# define SSL_aDSS                0x00000002U
# define SSL_aECDSA              0x00000008U
# define SSL_aGOST01             0x00000020U
# define SSL_aGOST12             0x00000080U
# define SSL_aNULL               0x00000004U
# define SSL_aPSK                0x00000010U
# define SSL_aRSA                0x00000001U
# define SSL_aSRP                0x00000040U
# define SSL_eGOST2814789CNT     0x00000400U
# define SSL_eGOST2814789CNT12   0x00040000U
# define SSL_eNULL               0x00000020U
# define SSL_kDHE                0x00000002U
# define SSL_kDHEPSK             0x00000100U
# define SSL_kECDHE              0x00000004U
# define SSL_kECDHEPSK           0x00000080U
# define SSL_kEDH                SSL_kDHE
# define SSL_kEECDH              SSL_kECDHE
# define SSL_kGOST               0x00000010U
# define SSL_kPSK                0x00000008U
# define SSL_kRSA                0x00000001U
# define SSL_kRSAPSK             0x00000040U
# define SSL_kSRP                0x00000020U
# define THREE_BYTE_MASK 0x3fff
# define TLS1_PRF            (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_DGST_SHIFT 8
# define TLS1_PRF_GOST12_256 (SSL_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_512 (SSL_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST94 (SSL_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA1_MD5 (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256 (SSL_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384 (SSL_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_STREAM_MAC 0x10000
# define TLSEXT_KEYNAME_LENGTH 16
# define TLS_CIPHER_LEN 2
# define TLS_CURVE_CHAR2         0x1
# define TLS_CURVE_CUSTOM        0x2
# define TLS_CURVE_PRIME         0x0
# define TLS_CURVE_TYPE          0x3
# define TWO_BYTE_BIT    0x80
# define TWO_BYTE_MASK   0x7fff
# define c2l(c,l)        (l = ((unsigned long)(*((c)++)))     , \
                         l|=(((unsigned long)(*((c)++)))<< 8), \
                         l|=(((unsigned long)(*((c)++)))<<16), \
                         l|=(((unsigned long)(*((c)++)))<<24))
# define c2ln(c,l1,l2,n) { \
                        c+=n; \
                        l1=l2=0; \
                        switch (n) { \
                        case 8: l2 =((unsigned long)(*(--(c))))<<24; \
                        case 7: l2|=((unsigned long)(*(--(c))))<<16; \
                        case 6: l2|=((unsigned long)(*(--(c))))<< 8; \
                        case 5: l2|=((unsigned long)(*(--(c))));     \
                        case 4: l1 =((unsigned long)(*(--(c))))<<24; \
                        case 3: l1|=((unsigned long)(*(--(c))))<<16; \
                        case 2: l1|=((unsigned long)(*(--(c))))<< 8; \
                        case 1: l1|=((unsigned long)(*(--(c))));     \
                                } \
                        }
#  define dtls1_process_heartbeat SSL_test_functions()->p_dtls1_process_heartbeat
# define dtls_ver_ordinal(v1) (((v1) == DTLS1_BAD_VER) ? 0xff00 : (v1))
# define l2c(l,c)        (*((c)++)=(unsigned char)(((l)    )&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff))
# define l2cn(l1,l2,c,n) { \
                        c+=n; \
                        switch (n) { \
                        case 8: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
                        case 7: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
                        case 6: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
                        case 5: *(--(c))=(unsigned char)(((l2)    )&0xff); \
                        case 4: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
                        case 3: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
                        case 2: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
                        case 1: *(--(c))=(unsigned char)(((l1)    )&0xff); \
                                } \
                        }
# define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))
# define l2n3(l,c)       (((c)[0]=(unsigned char)(((l)>>16)&0xff), \
                           (c)[1]=(unsigned char)(((l)>> 8)&0xff), \
                           (c)[2]=(unsigned char)(((l)    )&0xff)),(c)+=3)
# define l2n6(l,c)       (*((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))
# define l2n8(l,c)       (*((c)++)=(unsigned char)(((l)>>56)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>48)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))
# define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24, \
                         l|=((unsigned long)(*((c)++)))<<16, \
                         l|=((unsigned long)(*((c)++)))<< 8, \
                         l|=((unsigned long)(*((c)++))))
# define n2l3(c,l)       ((l =(((unsigned long)((c)[0]))<<16)| \
                              (((unsigned long)((c)[1]))<< 8)| \
                              (((unsigned long)((c)[2]))    )),(c)+=3)
# define n2l8(c,l)       (l =((uint64_t)(*((c)++)))<<56, \
                         l|=((uint64_t)(*((c)++)))<<48, \
                         l|=((uint64_t)(*((c)++)))<<40, \
                         l|=((uint64_t)(*((c)++)))<<32, \
                         l|=((uint64_t)(*((c)++)))<<24, \
                         l|=((uint64_t)(*((c)++)))<<16, \
                         l|=((uint64_t)(*((c)++)))<< 8, \
                         l|=((uint64_t)(*((c)++))))
# define n2s(c,s)        ((s=(((unsigned int)((c)[0]))<< 8)| \
                             (((unsigned int)((c)[1]))    )),(c)+=2)
# define s2n(s,c)        (((c)[0]=(unsigned char)(((s)>> 8)&0xff), \
                           (c)[1]=(unsigned char)(((s)    )&0xff)),(c)+=2)
# define session_ctx initial_ctx
#  define ssl3_setup_buffers SSL_test_functions()->p_ssl3_setup_buffers
# define ssl_do_write(s)  s->method->ssl3_enc->do_write(s)
# define ssl_handshake_start(s) \
        (((unsigned char *)s->init_buf->data) + s->method->ssl3_enc->hhlen)
#  define ssl_init_wbio_buffer SSL_test_functions()->p_ssl_init_wbio_buffer
# define ssl_set_handshake_header(s, htype, len) \
        s->method->ssl3_enc->set_handshake_header(s, htype, len)
# define tls1_suiteb(s)  (s->cert->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS)
