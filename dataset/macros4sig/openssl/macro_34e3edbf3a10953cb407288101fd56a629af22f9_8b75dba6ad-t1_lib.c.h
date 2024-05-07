#include<stdio.h>





# define DEC32(a)        ((a)=((a)-1)&0xffffffffL)
#  define DTLS1_MAX_MTU_OVERHEAD                   48
#   define DTLS1_SCTP_AUTH_LABEL   "EXPORTER_DTLS_OVER_SCTP"
#  define EXPLICIT_CHAR2_CURVE_TYPE  2
#  define EXPLICIT_PRIME_CURVE_TYPE  1
# define FP_ICC  (int (*)(const void *,const void *))
# define HEADER_SSL_LOCL_H
# define IMPLEMENT_dtls1_meth_func(version, func_name, s_accept, s_connect, \
                                        s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
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
                dtls1_get_message, \
                dtls1_read_bytes, \
                dtls1_write_app_data_bytes, \
                dtls1_dispatch_alert, \
                dtls1_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                dtls1_get_cipher, \
                s_get_meth, \
                dtls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
# define IMPLEMENT_ssl23_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
        TLS1_2_VERSION, \
        tls1_new, \
        tls1_clear, \
        tls1_free, \
        s_accept, \
        s_connect, \
        ssl23_read, \
        ssl23_peek, \
        ssl23_write, \
        ssl_undefined_function, \
        ssl_undefined_function, \
        ssl_ok, \
        ssl3_get_message, \
        ssl3_read_bytes, \
        ssl3_write_bytes, \
        ssl3_dispatch_alert, \
        ssl3_ctrl, \
        ssl3_ctx_ctrl, \
        ssl23_get_cipher_by_char, \
        ssl23_put_cipher_by_char, \
        ssl_undefined_const_function, \
        ssl23_num_ciphers, \
        ssl23_get_cipher, \
        s_get_meth, \
        ssl23_default_timeout, \
        &TLSv1_2_enc_data, \
        ssl_undefined_void_function, \
        ssl3_callback_ctrl, \
        ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
# define IMPLEMENT_ssl3_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                SSL3_VERSION, \
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
                ssl3_get_message, \
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
                s_get_meth, \
                ssl3_default_timeout, \
                &SSLv3_enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
# define IMPLEMENT_tls_meth_func(version, func_name, s_accept, s_connect, \
                                s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
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
                ssl3_get_message, \
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
                s_get_meth, \
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
# define SSL_3DES                0x00000002L
# define SSL_AEAD                0x00000040L
# define SSL_AES                 (SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM)
# define SSL_AES128              0x00000040L
# define SSL_AES128GCM           0x00001000L
# define SSL_AES256              0x00000080L
# define SSL_AES256GCM           0x00002000L
# define SSL_CAMELLIA            (SSL_CAMELLIA128|SSL_CAMELLIA256)
# define SSL_CAMELLIA128         0x00000100L
# define SSL_CAMELLIA256         0x00000200L
# define SSL_CERT_FLAGS_CHECK_TLS_STRICT \
        (SSL_CERT_FLAG_SUITEB_128_LOS|SSL_CERT_FLAG_TLS_STRICT)
# define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)        \
                ((SSL_IS_DTLS(s) && s->client_version <= DTLS1_2_VERSION) || \
                (!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION))
# define SSL_C_EXPORT_KEYLENGTH(c)       SSL_EXPORT_KEYLENGTH((c)->algorithm_enc, \
                                (c)->algo_strength)
# define SSL_C_EXPORT_PKEYLENGTH(c)      SSL_EXPORT_PKEYLENGTH((c)->algo_strength)
# define SSL_C_IS_EXPORT(c)      SSL_IS_EXPORT((c)->algo_strength)
# define SSL_C_IS_EXPORT40(c)    SSL_IS_EXPORT40((c)->algo_strength)
# define SSL_C_IS_EXPORT56(c)    SSL_IS_EXPORT56((c)->algo_strength)
# define SSL_DECRYPT     0
# define SSL_DES                 0x00000001L
# define SSL_ENCRYPT     1
# define SSL_ENC_FLAG_DTLS               0x8
# define SSL_ENC_FLAG_EXPLICIT_IV        0x1
# define SSL_ENC_FLAG_SHA256_PRF         0x4
# define SSL_ENC_FLAG_SIGALGS            0x2
# define SSL_ENC_FLAG_TLS1_2_CIPHERS     0x10
# define SSL_EXP40               0x00000008L
# define SSL_EXP56               0x00000010L
# define SSL_EXPORT              0x00000002L
# define SSL_EXPORT_KEYLENGTH(a,s)       (SSL_IS_EXPORT40(s) ? 5 : \
                                 (a) == SSL_DES ? 8 : 7)
# define SSL_EXPORT_PKEYLENGTH(a) (SSL_IS_EXPORT40(a) ? 512 : 1024)
# define SSL_EXP_MASK            0x00000003L
# define SSL_EXT_FLAG_RECEIVED   0x1
# define SSL_EXT_FLAG_SENT       0x2
# define SSL_FIPS                0x00000100L
# define SSL_GOST89MAC   0x00000008L
# define SSL_GOST94      0x00000004L
# define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)
# define SSL_HANDSHAKE_MAC_GOST94 0x40
# define SSL_HANDSHAKE_MAC_MD5 0x10
# define SSL_HANDSHAKE_MAC_SHA 0x20
# define SSL_HANDSHAKE_MAC_SHA256 0x80
# define SSL_HANDSHAKE_MAC_SHA384 0x100
# define SSL_HIGH                0x00000080L
# define SSL_HM_HEADER_LENGTH(s) s->method->ssl3_enc->hhlen
# define SSL_IDEA                0x00000010L
# define SSL_IS_DTLS(s)  (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)
# define SSL_IS_EXPORT(a)        ((a)&SSL_EXPORT)
# define SSL_IS_EXPORT40(a)      ((a)&SSL_EXP40)
# define SSL_IS_EXPORT56(a)      ((a)&SSL_EXP56)
# define SSL_LOW                 0x00000020L
# define SSL_MAX_DIGEST 6
# define SSL_MD5                 0x00000001L
# define SSL_MEDIUM              0x00000040L
# define SSL_MICRO               (SSL_EXP40)
# define SSL_MINI                (SSL_EXP56)
# define SSL_NOT_EXP             0x00000001L
# define SSL_PKEY_DH_DSA         4
# define SSL_PKEY_DH_RSA         3
# define SSL_PKEY_DSA_SIGN       2
# define SSL_PKEY_ECC            5
# define SSL_PKEY_GOST01         7
# define SSL_PKEY_GOST94         6
# define SSL_PKEY_NUM            8
# define SSL_PKEY_RSA_ENC        0
# define SSL_PKEY_RSA_SIGN       1
# define SSL_RC2                 0x00000008L
# define SSL_RC4                 0x00000004L
# define SSL_SEED                0x00000800L
#  define SSL_SESS_FLAG_EXTMS             0x1
# define SSL_SHA1                0x00000002L
# define SSL_SHA256              0x00000010L
# define SSL_SHA384              0x00000020L
# define SSL_SSLV3               0x00000002L
# define SSL_STRONG_MASK         0x000001fcL
# define SSL_STRONG_NONE         0x00000004L
# define SSL_TLSV1               SSL_SSLV3
# define SSL_TLSV1_2             0x00000004L
#  define SSL_USE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC)
# define SSL_USE_EXPLICIT_IV(s)  \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)
# define SSL_USE_SIGALGS(s)      \
                        (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS)
# define SSL_USE_TLS1_2_CIPHERS(s)       \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
# define SSL_aDH                 0x00000008L
# define SSL_aDSS                0x00000002L
# define SSL_aECDH               0x00000010L
# define SSL_aECDSA              0x00000040L
# define SSL_aGOST01                     0x00000200L
# define SSL_aGOST94                             0x00000100L
# define SSL_aKRB5               0x00000020L
# define SSL_aNULL               0x00000004L
# define SSL_aPSK                0x00000080L
# define SSL_aRSA                0x00000001L
# define SSL_aSRP                0x00000400L
# define SSL_eGOST2814789CNT     0x00000400L
# define SSL_eNULL               0x00000020L
# define SSL_kDHE                0x00000008L
# define SSL_kDHd                0x00000004L
# define SSL_kDHr                0x00000002L
# define SSL_kECDHE              0x00000080L
# define SSL_kECDHe              0x00000040L
# define SSL_kECDHr              0x00000020L
# define SSL_kEDH                SSL_kDHE
# define SSL_kEECDH              SSL_kECDHE
# define SSL_kGOST       0x00000200L
# define SSL_kKRB5               0x00000010L
# define SSL_kPSK                0x00000100L
# define SSL_kRSA                0x00000001L
# define SSL_kSRP        0x00000400L
# define THREE_BYTE_MASK 0x3fff
# define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)
# define TLS1_PRF_DGST_SHIFT 10
# define TLS1_PRF_GOST94 (SSL_HANDSHAKE_MAC_GOST94 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
# define TLS1_STREAM_MAC 0x04
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
# define l2n3(l,c)       ((c[0]=(unsigned char)(((l)>>16)&0xff), \
                          c[1]=(unsigned char)(((l)>> 8)&0xff), \
                          c[2]=(unsigned char)(((l)    )&0xff)),c+=3)
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
# define n2l3(c,l)       ((l =(((unsigned long)(c[0]))<<16)| \
                             (((unsigned long)(c[1]))<< 8)| \
                             (((unsigned long)(c[2]))    )),c+=3)
# define n2l6(c,l)       (l =((BN_ULLONG)(*((c)++)))<<40, \
                         l|=((BN_ULLONG)(*((c)++)))<<32, \
                         l|=((BN_ULLONG)(*((c)++)))<<24, \
                         l|=((BN_ULLONG)(*((c)++)))<<16, \
                         l|=((BN_ULLONG)(*((c)++)))<< 8, \
                         l|=((BN_ULLONG)(*((c)++))))
# define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)
# define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)
#   define session_ctx initial_ctx
#  define ssl3_setup_buffers SSL_test_functions()->p_ssl3_setup_buffers
# define ssl_do_write(s)  s->method->ssl3_enc->do_write(s)
# define ssl_handshake_start(s) \
        (((unsigned char *)s->init_buf->data) + s->method->ssl3_enc->hhlen)
#  define ssl_init_wbio_buffer SSL_test_functions()->p_ssl_init_wbio_buffer
# define ssl_put_cipher_by_char(ssl,ciph,ptr) \
                ((ssl)->method->put_cipher_by_char((ciph),(ptr)))
# define ssl_set_handshake_header(s, htype, len) \
        s->method->ssl3_enc->set_handshake_header(s, htype, len)
#  define tls1_process_heartbeat SSL_test_functions()->p_tls1_process_heartbeat
# define tls1_suiteb(s)  (s->cert->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS)
