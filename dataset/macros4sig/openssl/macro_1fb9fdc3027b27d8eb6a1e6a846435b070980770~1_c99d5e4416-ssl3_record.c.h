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
# define HEADER_RAND_H
# define RAND_F_RAND_BYTES                                100
# define RAND_R_PRNG_NOT_SEEDED                           100
# define RAND_cleanup() while(0) continue
# define HEADER_CONSTANT_TIME_LOCL_H
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
