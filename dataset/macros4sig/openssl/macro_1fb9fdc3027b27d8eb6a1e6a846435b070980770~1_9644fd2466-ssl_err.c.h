#include<stdio.h>
# define CERT_PKEY_CA_PARAM      0x80
# define CERT_PKEY_CA_SIGNATURE  0x20
# define CERT_PKEY_CERT_TYPE     0x400
# define CERT_PKEY_EE_PARAM      0x40
# define CERT_PKEY_EE_SIGNATURE  0x10
# define CERT_PKEY_EXPLICIT_SIGN 0x100
# define CERT_PKEY_ISSUER_NAME   0x200
# define CERT_PKEY_SIGN          0x2
# define CERT_PKEY_SUITEB        0x800
# define CERT_PKEY_VALID         0x1
# define DTLS_CTRL_GET_LINK_MIN_MTU              121
# define DTLS_CTRL_GET_TIMEOUT           73
# define DTLS_CTRL_HANDLE_TIMEOUT        74
# define DTLS_CTRL_SET_LINK_MTU                  120
# define DTLS_get_link_min_mtu(ssl) \
        SSL_ctrl((ssl),DTLS_CTRL_GET_LINK_MIN_MTU,0,NULL)
# define DTLS_set_link_mtu(ssl, mtu) \
        SSL_ctrl((ssl),DTLS_CTRL_SET_LINK_MTU,(mtu),NULL)
# define DTLSv1_get_timeout(ssl, arg) \
        SSL_ctrl(ssl,DTLS_CTRL_GET_TIMEOUT,0, (void *)arg)
# define DTLSv1_handle_timeout(ssl) \
        SSL_ctrl(ssl,DTLS_CTRL_HANDLE_TIMEOUT,0, NULL)
# define HEADER_SSL_H
#define OPENSSL_INIT_LOAD_SSL_STRINGS       0x00200000L
#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS    0x00100000L
#define OPENSSL_INIT_SSL_DEFAULT \
        (OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
# define OPENSSL_NPN_NEGOTIATED  1
# define OPENSSL_NPN_NO_OVERLAP  2
# define OPENSSL_NPN_UNSUPPORTED 0
# define OpenSSL_add_ssl_algorithms()    SSL_library_init()
#  define PSK_MAX_IDENTITY_LEN 128
#  define PSK_MAX_PSK_LEN 256
# define SSL_AD_ACCESS_DENIED            TLS1_AD_ACCESS_DENIED
# define SSL_AD_BAD_CERTIFICATE          SSL3_AD_BAD_CERTIFICATE
# define SSL_AD_BAD_CERTIFICATE_HASH_VALUE TLS1_AD_BAD_CERTIFICATE_HASH_VALUE
# define SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE
# define SSL_AD_BAD_RECORD_MAC           SSL3_AD_BAD_RECORD_MAC
# define SSL_AD_CERTIFICATE_EXPIRED      SSL3_AD_CERTIFICATE_EXPIRED
# define SSL_AD_CERTIFICATE_REVOKED      SSL3_AD_CERTIFICATE_REVOKED
# define SSL_AD_CERTIFICATE_UNKNOWN      SSL3_AD_CERTIFICATE_UNKNOWN
# define SSL_AD_CERTIFICATE_UNOBTAINABLE TLS1_AD_CERTIFICATE_UNOBTAINABLE
# define SSL_AD_CLOSE_NOTIFY             SSL3_AD_CLOSE_NOTIFY
# define SSL_AD_DECODE_ERROR             TLS1_AD_DECODE_ERROR
# define SSL_AD_DECOMPRESSION_FAILURE    SSL3_AD_DECOMPRESSION_FAILURE
# define SSL_AD_DECRYPTION_FAILED        TLS1_AD_DECRYPTION_FAILED
# define SSL_AD_DECRYPT_ERROR            TLS1_AD_DECRYPT_ERROR
# define SSL_AD_EXPORT_RESTRICTION       TLS1_AD_EXPORT_RESTRICTION
# define SSL_AD_HANDSHAKE_FAILURE        SSL3_AD_HANDSHAKE_FAILURE
# define SSL_AD_ILLEGAL_PARAMETER        SSL3_AD_ILLEGAL_PARAMETER
# define SSL_AD_INAPPROPRIATE_FALLBACK   TLS1_AD_INAPPROPRIATE_FALLBACK
# define SSL_AD_INSUFFICIENT_SECURITY    TLS1_AD_INSUFFICIENT_SECURITY
# define SSL_AD_INTERNAL_ERROR           TLS1_AD_INTERNAL_ERROR
# define SSL_AD_NO_APPLICATION_PROTOCOL  TLS1_AD_NO_APPLICATION_PROTOCOL
# define SSL_AD_NO_CERTIFICATE           SSL3_AD_NO_CERTIFICATE
# define SSL_AD_NO_RENEGOTIATION         TLS1_AD_NO_RENEGOTIATION
# define SSL_AD_PROTOCOL_VERSION         TLS1_AD_PROTOCOL_VERSION
# define SSL_AD_REASON_OFFSET            1000
# define SSL_AD_RECORD_OVERFLOW          TLS1_AD_RECORD_OVERFLOW
# define SSL_AD_UNEXPECTED_MESSAGE       SSL3_AD_UNEXPECTED_MESSAGE
# define SSL_AD_UNKNOWN_CA               TLS1_AD_UNKNOWN_CA
# define SSL_AD_UNKNOWN_PSK_IDENTITY     TLS1_AD_UNKNOWN_PSK_IDENTITY
# define SSL_AD_UNRECOGNIZED_NAME        TLS1_AD_UNRECOGNIZED_NAME
# define SSL_AD_UNSUPPORTED_CERTIFICATE  SSL3_AD_UNSUPPORTED_CERTIFICATE
# define SSL_AD_UNSUPPORTED_EXTENSION    TLS1_AD_UNSUPPORTED_EXTENSION
# define SSL_AD_USER_CANCELLED           TLS1_AD_USER_CANCELLED
# define SSL_ASYNC_NO_JOBS      6
# define SSL_ASYNC_PAUSED       5
# define SSL_BUILD_CHAIN_FLAG_CHECK              0x4
# define SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR        0x10
# define SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR       0x8
# define SSL_BUILD_CHAIN_FLAG_NO_ROOT            0x2
# define SSL_BUILD_CHAIN_FLAG_UNTRUSTED          0x1
# define SSL_CB_ACCEPT_EXIT              (SSL_ST_ACCEPT|SSL_CB_EXIT)
# define SSL_CB_ACCEPT_LOOP              (SSL_ST_ACCEPT|SSL_CB_LOOP)
# define SSL_CB_ALERT                    0x4000
# define SSL_CB_CONNECT_EXIT             (SSL_ST_CONNECT|SSL_CB_EXIT)
# define SSL_CB_CONNECT_LOOP             (SSL_ST_CONNECT|SSL_CB_LOOP)
# define SSL_CB_EXIT                     0x02
# define SSL_CB_HANDSHAKE_DONE           0x20
# define SSL_CB_HANDSHAKE_START          0x10
# define SSL_CB_LOOP                     0x01
# define SSL_CB_READ                     0x04
# define SSL_CB_READ_ALERT               (SSL_CB_ALERT|SSL_CB_READ)
# define SSL_CB_WRITE                    0x08
# define SSL_CB_WRITE_ALERT              (SSL_CB_ALERT|SSL_CB_WRITE)
# define SSL_CERT_FLAG_BROKEN_PROTOCOL           0x10000000
# define SSL_CERT_FLAG_SUITEB_128_LOS            0x30000
# define SSL_CERT_FLAG_SUITEB_128_LOS_ONLY       0x10000
# define SSL_CERT_FLAG_SUITEB_192_LOS            0x20000
# define SSL_CERT_FLAG_TLS_STRICT                0x00000001U
# define SSL_CERT_SET_FIRST                      1
# define SSL_CERT_SET_NEXT                       2
# define SSL_CERT_SET_SERVER                     3
# define SSL_COMP_free_compression_methods() while(0) continue
# define SSL_CONF_FLAG_CERTIFICATE       0x20
# define SSL_CONF_FLAG_CLIENT            0x4
# define SSL_CONF_FLAG_CMDLINE           0x1
# define SSL_CONF_FLAG_FILE              0x2
# define SSL_CONF_FLAG_REQUIRE_PRIVATE   0x40
# define SSL_CONF_FLAG_SERVER            0x8
# define SSL_CONF_FLAG_SHOW_ERRORS       0x10
# define SSL_CONF_TYPE_DIR               0x3
# define SSL_CONF_TYPE_FILE              0x2
# define SSL_CONF_TYPE_NONE              0x4
# define SSL_CONF_TYPE_STRING            0x1
# define SSL_CONF_TYPE_UNKNOWN           0x0
# define SSL_CTRL_BUILD_CERT_CHAIN               105
# define SSL_CTRL_CERT_FLAGS                     99
# define SSL_CTRL_CHAIN                          88
# define SSL_CTRL_CHAIN_CERT                     89
# define SSL_CTRL_CLEAR_CERT_FLAGS               100
# define SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS        83
# define SSL_CTRL_CLEAR_MODE                     78
# define SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS       11
#  define SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT               85
# define SSL_CTRL_EXTRA_CHAIN_CERT               14
# define SSL_CTRL_GET_CHAIN_CERTS                115
# define SSL_CTRL_GET_CLIENT_CERT_REQUEST        9
# define SSL_CTRL_GET_CLIENT_CERT_TYPES          103
# define SSL_CTRL_GET_CURVES                     90
#  define SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING        86
# define SSL_CTRL_GET_EC_POINT_FORMATS           111
# define SSL_CTRL_GET_EXTMS_SUPPORT              122
# define SSL_CTRL_GET_EXTRA_CHAIN_CERTS          82
# define SSL_CTRL_GET_FLAGS                      13
# define SSL_CTRL_GET_MAX_CERT_LIST              50
# define SSL_CTRL_GET_NUM_RENEGOTIATIONS         10
# define SSL_CTRL_GET_PEER_SIGNATURE_NID         108
# define SSL_CTRL_GET_RAW_CIPHERLIST             110
# define SSL_CTRL_GET_READ_AHEAD                 40
# define SSL_CTRL_GET_RI_SUPPORT                 76
# define SSL_CTRL_GET_SERVER_TMP_KEY             109
# define SSL_CTRL_GET_SESS_CACHE_MODE            45
# define SSL_CTRL_GET_SESS_CACHE_SIZE            43
# define SSL_CTRL_GET_SHARED_CURVE               93
# define SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB       128
# define SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG   129
# define SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS     66
# define SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS      68
# define SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP        70
# define SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE     127
# define SSL_CTRL_GET_TLSEXT_TICKET_KEYS         58
# define SSL_CTRL_GET_TOTAL_RENEGOTIATIONS       12
# define SSL_CTRL_MODE                           33
# define SSL_CTRL_SELECT_CURRENT_CERT            116
# define SSL_CTRL_SESS_ACCEPT                    24
# define SSL_CTRL_SESS_ACCEPT_GOOD               25
# define SSL_CTRL_SESS_ACCEPT_RENEGOTIATE        26
# define SSL_CTRL_SESS_CACHE_FULL                31
# define SSL_CTRL_SESS_CB_HIT                    28
# define SSL_CTRL_SESS_CONNECT                   21
# define SSL_CTRL_SESS_CONNECT_GOOD              22
# define SSL_CTRL_SESS_CONNECT_RENEGOTIATE       23
# define SSL_CTRL_SESS_HIT                       27
# define SSL_CTRL_SESS_MISSES                    29
# define SSL_CTRL_SESS_NUMBER                    20
# define SSL_CTRL_SESS_TIMEOUTS                  30
# define SSL_CTRL_SET_CHAIN_CERT_STORE           107
# define SSL_CTRL_SET_CLIENT_CERT_TYPES          104
# define SSL_CTRL_SET_CLIENT_SIGALGS             101
# define SSL_CTRL_SET_CLIENT_SIGALGS_LIST        102
# define SSL_CTRL_SET_CURRENT_CERT               117
# define SSL_CTRL_SET_CURVES                     91
# define SSL_CTRL_SET_CURVES_LIST                92
# define SSL_CTRL_SET_DH_AUTO                    118
#  define SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS    87
# define SSL_CTRL_SET_MAX_CERT_LIST              51
# define SSL_CTRL_SET_MAX_PIPELINES              126
# define SSL_CTRL_SET_MAX_PROTO_VERSION          124
# define SSL_CTRL_SET_MAX_SEND_FRAGMENT          52
# define SSL_CTRL_SET_MIN_PROTO_VERSION          123
# define SSL_CTRL_SET_MSG_CALLBACK               15
# define SSL_CTRL_SET_MSG_CALLBACK_ARG           16
# define SSL_CTRL_SET_MTU                17
# define SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB      79
# define SSL_CTRL_SET_READ_AHEAD                 41
# define SSL_CTRL_SET_SESS_CACHE_MODE            44
# define SSL_CTRL_SET_SESS_CACHE_SIZE            42
# define SSL_CTRL_SET_SIGALGS                    97
# define SSL_CTRL_SET_SIGALGS_LIST               98
# define SSL_CTRL_SET_SPLIT_SEND_FRAGMENT        125
# define SSL_CTRL_SET_SRP_ARG            78
# define SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB             77
# define SSL_CTRL_SET_SRP_VERIFY_PARAM_CB                76
# define SSL_CTRL_SET_TLSEXT_DEBUG_ARG           57
# define SSL_CTRL_SET_TLSEXT_DEBUG_CB            56
# define SSL_CTRL_SET_TLSEXT_HOSTNAME            55
# define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG      54
# define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB       53
# define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB       63
# define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG   64
# define SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS     67
# define SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS      69
# define SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP        71
# define SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE     65
# define SSL_CTRL_SET_TLSEXT_TICKET_KEYS         59
# define SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB       72
# define SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD               81
# define SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH               80
# define SSL_CTRL_SET_TLS_EXT_SRP_USERNAME               79
# define SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB    75
# define SSL_CTRL_SET_TMP_DH                     3
# define SSL_CTRL_SET_TMP_DH_CB                  6
# define SSL_CTRL_SET_TMP_ECDH                   4
# define SSL_CTRL_SET_VERIFY_CERT_STORE          106
# define SSL_CTX_add0_chain_cert(ctx,x509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)x509)
# define SSL_CTX_add1_chain_cert(ctx,x509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)x509)
# define SSL_CTX_add_extra_chain_cert(ctx,x509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)x509)
# define SSL_CTX_build_cert_chain(ctx, flags) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)
# define SSL_CTX_clear_cert_flags(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)
# define SSL_CTX_clear_chain_certs(ctx) \
        SSL_CTX_set0_chain(ctx,NULL)
# define SSL_CTX_clear_extra_chain_certs(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)
# define SSL_CTX_clear_mode(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)
#define SSL_CTX_disable_ct(ctx) \
        ((void) SSL_CTX_set_validation_callback((ctx), NULL, NULL))
# define SSL_CTX_get0_chain_certs(ctx,px509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)
# define SSL_CTX_get_app_data(ctx)       (SSL_CTX_get_ex_data(ctx,0))
# define SSL_CTX_get_default_read_ahead(ctx) SSL_CTX_get_read_ahead(ctx)
#define SSL_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, l, p, newf, dupf, freef)
# define SSL_CTX_get_extra_chain_certs(ctx,px509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)
# define SSL_CTX_get_extra_chain_certs_only(ctx,px509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)
# define SSL_CTX_get_max_cert_list(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_MAX_CERT_LIST,0,NULL)
# define SSL_CTX_get_mode(ctx) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,0,NULL)
# define SSL_CTX_get_read_ahead(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_READ_AHEAD,0,NULL)
# define SSL_CTX_get_session_cache_mode(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)
# define SSL_CTX_need_tmp_RSA(ctx)                0
# define SSL_CTX_select_current_cert(ctx,x509) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)x509)
# define SSL_CTX_sess_accept(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT,0,NULL)
# define SSL_CTX_sess_accept_good(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_GOOD,0,NULL)
# define SSL_CTX_sess_accept_renegotiate(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_RENEGOTIATE,0,NULL)
# define SSL_CTX_sess_cache_full(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CACHE_FULL,0,NULL)
# define SSL_CTX_sess_cb_hits(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CB_HIT,0,NULL)
# define SSL_CTX_sess_connect(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT,0,NULL)
# define SSL_CTX_sess_connect_good(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_GOOD,0,NULL)
# define SSL_CTX_sess_connect_renegotiate(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_RENEGOTIATE,0,NULL)
# define SSL_CTX_sess_get_cache_size(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)
# define SSL_CTX_sess_hits(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_HIT,0,NULL)
# define SSL_CTX_sess_misses(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_MISSES,0,NULL)
# define SSL_CTX_sess_number(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_NUMBER,0,NULL)
# define SSL_CTX_sess_set_cache_size(ctx,t) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)
# define SSL_CTX_sess_timeouts(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_TIMEOUTS,0,NULL)
# define SSL_CTX_set0_chain(ctx,sk) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)sk)
# define SSL_CTX_set0_chain_cert_store(ctx,st) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)st)
# define SSL_CTX_set0_verify_cert_store(ctx,st) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)st)
# define SSL_CTX_set1_chain(ctx,sk) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)sk)
# define SSL_CTX_set1_chain_cert_store(ctx,st) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)st)
# define SSL_CTX_set1_client_certificate_types(ctx, clist, clistlen) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)clist)
# define SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(int *)slist)
# define SSL_CTX_set1_client_sigalgs_list(ctx, s) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)s)
# define SSL_CTX_set1_curves(ctx, clist, clistlen) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURVES,clistlen,(char *)clist)
# define SSL_CTX_set1_curves_list(ctx, s) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURVES_LIST,0,(char *)s)
# define SSL_CTX_set1_sigalgs(ctx, slist, slistlen) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(int *)slist)
# define SSL_CTX_set1_sigalgs_list(ctx, s) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)s)
# define SSL_CTX_set1_verify_cert_store(ctx,st) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)st)
# define SSL_CTX_set_app_data(ctx,arg)   (SSL_CTX_set_ex_data(ctx,0,(char *)arg))
# define SSL_CTX_set_cert_flags(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_CERT_FLAGS,(op),NULL)
# define SSL_CTX_set_current_cert(ctx, op) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)
# define SSL_CTX_set_default_read_ahead(ctx,m) SSL_CTX_set_read_ahead(ctx,m)
# define SSL_CTX_set_dh_auto(ctx, onoff) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,NULL)
# define SSL_CTX_set_ecdh_auto(dummy, onoff)      ((onoff) != 0)
# define SSL_CTX_set_max_cert_list(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_CERT_LIST,m,NULL)
# define SSL_CTX_set_max_pipelines(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_PIPELINES,m,NULL)
#define SSL_CTX_set_max_proto_version(ctx, version) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
# define SSL_CTX_set_max_send_fragment(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)
#define SSL_CTX_set_min_proto_version(ctx, version) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
# define SSL_CTX_set_mode(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
# define SSL_CTX_set_msg_callback_arg(ctx, arg) SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
# define SSL_CTX_set_read_ahead(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_READ_AHEAD,m,NULL)
# define SSL_CTX_set_session_cache_mode(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)
# define SSL_CTX_set_split_send_fragment(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,m,NULL)
# define SSL_CTX_set_tmp_dh(ctx,dh) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
# define SSL_CTX_set_tmp_ecdh(ctx,ecdh) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)ecdh)
# define SSL_CTX_set_tmp_rsa(ctx,rsa)             1
# define SSL_CTX_set_tmp_rsa_callback(ctx, cb)    while(0) (cb)(NULL, 0, 0)
# define SSL_DEFAULT_CIPHER_LIST "ALL:!COMPLEMENTOFDEFAULT:!eNULL"
# define SSL_ERROR_NONE                  0
# define SSL_ERROR_SSL                   1
# define SSL_ERROR_SYSCALL               5
# define SSL_ERROR_WANT_ACCEPT           8
# define SSL_ERROR_WANT_ASYNC            9
# define SSL_ERROR_WANT_ASYNC_JOB       10
# define SSL_ERROR_WANT_CONNECT          7
# define SSL_ERROR_WANT_READ             2
# define SSL_ERROR_WANT_WRITE            3
# define SSL_ERROR_WANT_X509_LOOKUP      4
# define SSL_ERROR_ZERO_RETURN           6
# define SSL_FILETYPE_ASN1       X509_FILETYPE_ASN1
# define SSL_FILETYPE_PEM        X509_FILETYPE_PEM
# define SSL_F_CHECK_SUITEB_CIPHER_LIST                   331
# define SSL_F_CT_MOVE_SCTS                               345
# define SSL_F_CT_STRICT                                  349
# define SSL_F_D2I_SSL_SESSION                            103
# define SSL_F_DANE_CTX_ENABLE                            347
# define SSL_F_DANE_MTYPE_SET                             393
# define SSL_F_DANE_TLSA_ADD                              394
# define SSL_F_DO_DTLS1_WRITE                             245
# define SSL_F_DO_SSL3_WRITE                              104
# define SSL_F_DTLS1_BUFFER_RECORD                        247
# define SSL_F_DTLS1_CHECK_TIMEOUT_NUM                    318
# define SSL_F_DTLS1_HEARTBEAT                            305
# define SSL_F_DTLS1_PREPROCESS_FRAGMENT                  288
# define SSL_F_DTLS1_PROCESS_RECORD                       257
# define SSL_F_DTLS1_READ_BYTES                           258
# define SSL_F_DTLS1_READ_FAILED                          339
# define SSL_F_DTLS1_RETRANSMIT_MESSAGE                   390
# define SSL_F_DTLS1_WRITE_APP_DATA_BYTES                 268
# define SSL_F_DTLSV1_LISTEN                              350
# define SSL_F_DTLS_CONSTRUCT_CHANGE_CIPHER_SPEC          371
# define SSL_F_DTLS_CONSTRUCT_HELLO_VERIFY_REQUEST        385
# define SSL_F_DTLS_GET_REASSEMBLED_MESSAGE               370
# define SSL_F_DTLS_PROCESS_HELLO_VERIFY                  386
# define SSL_F_OPENSSL_INIT_SSL                           342
# define SSL_F_OSSL_STATEM_CLIENT_READ_TRANSITION         417
# define SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION         418
# define SSL_F_READ_STATE_MACHINE                         352
# define SSL_F_SSL3_CHANGE_CIPHER_STATE                   129
# define SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM              130
# define SSL_F_SSL3_CTRL                                  213
# define SSL_F_SSL3_CTX_CTRL                              133
# define SSL_F_SSL3_DIGEST_CACHED_RECORDS                 293
# define SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC                 292
# define SSL_F_SSL3_FINAL_FINISH_MAC                      285
# define SSL_F_SSL3_GENERATE_KEY_BLOCK                    238
# define SSL_F_SSL3_GENERATE_MASTER_SECRET                388
# define SSL_F_SSL3_GET_RECORD                            143
# define SSL_F_SSL3_INIT_FINISHED_MAC                     397
# define SSL_F_SSL3_OUTPUT_CERT_CHAIN                     147
# define SSL_F_SSL3_READ_BYTES                            148
# define SSL_F_SSL3_READ_N                                149
# define SSL_F_SSL3_SETUP_KEY_BLOCK                       157
# define SSL_F_SSL3_SETUP_READ_BUFFER                     156
# define SSL_F_SSL3_SETUP_WRITE_BUFFER                    291
# define SSL_F_SSL3_WRITE_BYTES                           158
# define SSL_F_SSL3_WRITE_PENDING                         159
# define SSL_F_SSL_ADD_CERT_CHAIN                         316
# define SSL_F_SSL_ADD_CERT_TO_BUF                        319
# define SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT        298
# define SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT                 277
# define SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT           307
# define SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK         215
# define SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK        216
# define SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT        299
# define SSL_F_SSL_ADD_SERVERHELLO_TLSEXT                 278
# define SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT           308
# define SSL_F_SSL_BAD_METHOD                             160
# define SSL_F_SSL_BUILD_CERT_CHAIN                       332
# define SSL_F_SSL_BYTES_TO_CIPHER_LIST                   161
# define SSL_F_SSL_CERT_ADD0_CHAIN_CERT                   346
# define SSL_F_SSL_CERT_DUP                               221
# define SSL_F_SSL_CERT_NEW                               162
# define SSL_F_SSL_CERT_SET0_CHAIN                        340
# define SSL_F_SSL_CHECK_PRIVATE_KEY                      163
# define SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT               280
# define SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG            279
# define SSL_F_SSL_CIPHER_PROCESS_RULESTR                 230
# define SSL_F_SSL_CIPHER_STRENGTH_SORT                   231
# define SSL_F_SSL_CLEAR                                  164
# define SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD            165
# define SSL_F_SSL_CONF_CMD                               334
# define SSL_F_SSL_CREATE_CIPHER_LIST                     166
# define SSL_F_SSL_CTRL                                   232
# define SSL_F_SSL_CTX_CHECK_PRIVATE_KEY                  168
# define SSL_F_SSL_CTX_ENABLE_CT                          398
# define SSL_F_SSL_CTX_MAKE_PROFILES                      309
# define SSL_F_SSL_CTX_NEW                                169
# define SSL_F_SSL_CTX_SET_ALPN_PROTOS                    343
# define SSL_F_SSL_CTX_SET_CIPHER_LIST                    269
# define SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE             290
# define SSL_F_SSL_CTX_SET_CT_VALIDATION_CALLBACK         396
# define SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT             219
# define SSL_F_SSL_CTX_SET_SSL_VERSION                    170
# define SSL_F_SSL_CTX_USE_CERTIFICATE                    171
# define SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1               172
# define SSL_F_SSL_CTX_USE_CERTIFICATE_FILE               173
# define SSL_F_SSL_CTX_USE_PRIVATEKEY                     174
# define SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1                175
# define SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE                176
# define SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT              272
# define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY                  177
# define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1             178
# define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE             179
# define SSL_F_SSL_CTX_USE_SERVERINFO                     336
# define SSL_F_SSL_CTX_USE_SERVERINFO_FILE                337
# define SSL_F_SSL_DANE_DUP                               403
# define SSL_F_SSL_DANE_ENABLE                            395
# define SSL_F_SSL_DO_CONFIG                              391
# define SSL_F_SSL_DO_HANDSHAKE                           180
# define SSL_F_SSL_DUP_CA_LIST                            408
# define SSL_F_SSL_ENABLE_CT                              402
# define SSL_F_SSL_GET_NEW_SESSION                        181
# define SSL_F_SSL_GET_PREV_SESSION                       217
# define SSL_F_SSL_GET_SERVER_CERT_INDEX                  322
# define SSL_F_SSL_GET_SIGN_PKEY                          183
# define SSL_F_SSL_INIT_WBIO_BUFFER                       184
# define SSL_F_SSL_LOAD_CLIENT_CA_FILE                    185
# define SSL_F_SSL_MODULE_INIT                            392
# define SSL_F_SSL_NEW                                    186
# define SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT      300
# define SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT               302
# define SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT         310
# define SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT      301
# define SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT               303
# define SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT         311
# define SSL_F_SSL_PEEK                                   270
# define SSL_F_SSL_READ                                   223
# define SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT                320
# define SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT                321
# define SSL_F_SSL_SESSION_DUP                            348
# define SSL_F_SSL_SESSION_NEW                            189
# define SSL_F_SSL_SESSION_PRINT_FP                       190
# define SSL_F_SSL_SESSION_SET1_ID                        423
# define SSL_F_SSL_SESSION_SET1_ID_CONTEXT                312
# define SSL_F_SSL_SET_ALPN_PROTOS                        344
# define SSL_F_SSL_SET_CERT                               191
# define SSL_F_SSL_SET_CIPHER_LIST                        271
# define SSL_F_SSL_SET_CT_VALIDATION_CALLBACK             399
# define SSL_F_SSL_SET_FD                                 192
# define SSL_F_SSL_SET_PKEY                               193
# define SSL_F_SSL_SET_RFD                                194
# define SSL_F_SSL_SET_SESSION                            195
# define SSL_F_SSL_SET_SESSION_ID_CONTEXT                 218
# define SSL_F_SSL_SET_SESSION_TICKET_EXT                 294
# define SSL_F_SSL_SET_WFD                                196
# define SSL_F_SSL_SHUTDOWN                               224
# define SSL_F_SSL_SRP_CTX_INIT                           313
# define SSL_F_SSL_START_ASYNC_JOB                        389
# define SSL_F_SSL_UNDEFINED_FUNCTION                     197
# define SSL_F_SSL_UNDEFINED_VOID_FUNCTION                244
# define SSL_F_SSL_USE_CERTIFICATE                        198
# define SSL_F_SSL_USE_CERTIFICATE_ASN1                   199
# define SSL_F_SSL_USE_CERTIFICATE_FILE                   200
# define SSL_F_SSL_USE_PRIVATEKEY                         201
# define SSL_F_SSL_USE_PRIVATEKEY_ASN1                    202
# define SSL_F_SSL_USE_PRIVATEKEY_FILE                    203
# define SSL_F_SSL_USE_PSK_IDENTITY_HINT                  273
# define SSL_F_SSL_USE_RSAPRIVATEKEY                      204
# define SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1                 205
# define SSL_F_SSL_USE_RSAPRIVATEKEY_FILE                 206
# define SSL_F_SSL_VALIDATE_CT                            400
# define SSL_F_SSL_VERIFY_CERT_CHAIN                      207
# define SSL_F_SSL_WRITE                                  208
# define SSL_F_STATE_MACHINE                              353
# define SSL_F_TLS12_CHECK_PEER_SIGALG                    333
# define SSL_F_TLS1_CHANGE_CIPHER_STATE                   209
# define SSL_F_TLS1_CHECK_DUPLICATE_EXTENSIONS            341
# define SSL_F_TLS1_ENC                                   401
# define SSL_F_TLS1_EXPORT_KEYING_MATERIAL                314
# define SSL_F_TLS1_GET_CURVELIST                         338
# define SSL_F_TLS1_PRF                                   284
# define SSL_F_TLS1_SETUP_KEY_BLOCK                       211
# define SSL_F_TLS1_SET_SERVER_SIGALGS                    335
# define SSL_F_TLS_CLIENT_KEY_EXCHANGE_POST_WORK          354
# define SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST          372
# define SSL_F_TLS_CONSTRUCT_CKE_DHE                      404
# define SSL_F_TLS_CONSTRUCT_CKE_ECDHE                    405
# define SSL_F_TLS_CONSTRUCT_CKE_GOST                     406
# define SSL_F_TLS_CONSTRUCT_CKE_PSK_PREAMBLE             407
# define SSL_F_TLS_CONSTRUCT_CKE_RSA                      409
# define SSL_F_TLS_CONSTRUCT_CKE_SRP                      410
# define SSL_F_TLS_CONSTRUCT_CLIENT_CERTIFICATE           355
# define SSL_F_TLS_CONSTRUCT_CLIENT_HELLO                 356
# define SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE          357
# define SSL_F_TLS_CONSTRUCT_CLIENT_VERIFY                358
# define SSL_F_TLS_CONSTRUCT_FINISHED                     359
# define SSL_F_TLS_CONSTRUCT_HELLO_REQUEST                373
# define SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE           374
# define SSL_F_TLS_CONSTRUCT_SERVER_DONE                  375
# define SSL_F_TLS_CONSTRUCT_SERVER_HELLO                 376
# define SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE          377
# define SSL_F_TLS_GET_MESSAGE_BODY                       351
# define SSL_F_TLS_GET_MESSAGE_HEADER                     387
# define SSL_F_TLS_POST_PROCESS_CLIENT_HELLO              378
# define SSL_F_TLS_POST_PROCESS_CLIENT_KEY_EXCHANGE       384
# define SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE             360
# define SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST            361
# define SSL_F_TLS_PROCESS_CERT_STATUS                    362
# define SSL_F_TLS_PROCESS_CERT_VERIFY                    379
# define SSL_F_TLS_PROCESS_CHANGE_CIPHER_SPEC             363
# define SSL_F_TLS_PROCESS_CKE_DHE                        411
# define SSL_F_TLS_PROCESS_CKE_ECDHE                      412
# define SSL_F_TLS_PROCESS_CKE_GOST                       413
# define SSL_F_TLS_PROCESS_CKE_PSK_PREAMBLE               414
# define SSL_F_TLS_PROCESS_CKE_RSA                        415
# define SSL_F_TLS_PROCESS_CKE_SRP                        416
# define SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE             380
# define SSL_F_TLS_PROCESS_CLIENT_HELLO                   381
# define SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE            382
# define SSL_F_TLS_PROCESS_FINISHED                       364
# define SSL_F_TLS_PROCESS_KEY_EXCHANGE                   365
# define SSL_F_TLS_PROCESS_NEW_SESSION_TICKET             366
# define SSL_F_TLS_PROCESS_NEXT_PROTO                     383
# define SSL_F_TLS_PROCESS_SERVER_CERTIFICATE             367
# define SSL_F_TLS_PROCESS_SERVER_DONE                    368
# define SSL_F_TLS_PROCESS_SERVER_HELLO                   369
# define SSL_F_TLS_PROCESS_SKE_DHE                        419
# define SSL_F_TLS_PROCESS_SKE_ECDHE                      420
# define SSL_F_TLS_PROCESS_SKE_PSK_PREAMBLE               421
# define SSL_F_TLS_PROCESS_SKE_SRP                        422
# define SSL_F_USE_CERTIFICATE_CHAIN_FILE                 220
# define SSL_MAC_FLAG_READ_MAC_STREAM 1
# define SSL_MAC_FLAG_WRITE_MAC_STREAM 2
# define SSL_MAX_CERT_LIST_DEFAULT 1024*100
# define SSL_MAX_KEY_ARG_LENGTH                  8
# define SSL_MAX_MASTER_KEY_LENGTH               48
# define SSL_MAX_PIPELINES  32
# define SSL_MAX_SID_CTX_LENGTH                  32
# define SSL_MAX_SSL_SESSION_ID_LENGTH           32
# define SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES     (512/8)
# define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002U
# define SSL_MODE_ASYNC 0x00000100U
# define SSL_MODE_AUTO_RETRY 0x00000004U
# define SSL_MODE_ENABLE_PARTIAL_WRITE       0x00000001U
# define SSL_MODE_NO_AUTO_CHAIN 0x00000008U
# define SSL_MODE_RELEASE_BUFFERS 0x00000010U
# define SSL_MODE_SEND_CLIENTHELLO_TIME 0x00000020U
# define SSL_MODE_SEND_FALLBACK_SCSV 0x00000080U
# define SSL_MODE_SEND_SERVERHELLO_TIME 0x00000040U
# define SSL_NOTHING            1
# define SSL_OP_ALL                                      0x80000BFFU
# define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        0x00040000U
# define SSL_OP_CIPHER_SERVER_PREFERENCE                 0x00400000U
#  define SSL_OP_CISCO_ANYCONNECT             0x00008000U
# define SSL_OP_COOKIE_EXCHANGE              0x00002000U
# define SSL_OP_CRYPTOPRO_TLSEXT_BUG                     0x80000000U
# define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              0x00000800U
# define SSL_OP_EPHEMERAL_RSA                            0x0
# define SSL_OP_LEGACY_SERVER_CONNECT                    0x00000004U
# define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               0x0U
# define SSL_OP_MICROSOFT_SESS_ID_BUG                    0x0
# define SSL_OP_MSIE_SSLV2_RSA_PADDING                   0x0
# define SSL_OP_NETSCAPE_CA_DN_BUG                       0x0
# define SSL_OP_NETSCAPE_CHALLENGE_BUG                   0x0
# define SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          0x0U
# define SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         0x0U
# define SSL_OP_NO_COMPRESSION                           0x00020000U
# define SSL_OP_NO_DTLS_MASK (SSL_OP_NO_DTLSv1|SSL_OP_NO_DTLSv1_2)
# define SSL_OP_NO_DTLSv1                                0x04000000U
# define SSL_OP_NO_DTLSv1_2                              0x08000000U
# define SSL_OP_NO_QUERY_MTU                 0x00001000U
# define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   0x00010000U
# define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3|\
        SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2)
# define SSL_OP_NO_SSLv2                                 0x00000000U
# define SSL_OP_NO_SSLv3                                 0x02000000U
# define SSL_OP_NO_TICKET                    0x00004000U
# define SSL_OP_NO_TLSv1                                 0x04000000U
# define SSL_OP_NO_TLSv1_1                               0x10000000U
# define SSL_OP_NO_TLSv1_2                               0x08000000U
# define SSL_OP_PKCS1_CHECK_1                            0x0
# define SSL_OP_PKCS1_CHECK_2                            0x0
# define SSL_OP_SAFARI_ECDHE_ECDSA_BUG                   0x00000040U
# define SSL_OP_SINGLE_DH_USE                            0x0
# define SSL_OP_SINGLE_ECDH_USE                          0x0
# define SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 0x0
# define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              0x0
# define SSL_OP_TLSEXT_PADDING                           0x00000010U
# define SSL_OP_TLS_BLOCK_PADDING_BUG                    0x0U
# define SSL_OP_TLS_D5_BUG                               0x0U
# define SSL_OP_TLS_ROLLBACK_BUG                         0x00800000U
# define SSL_READING            3
# define SSL_RECEIVED_SHUTDOWN   2
# define SSL_R_APP_DATA_IN_HANDSHAKE                      100
# define SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT 272
# define SSL_R_AT_LEAST_TLS_1_0_NEEDED_IN_FIPS_MODE       143
# define SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE     158
# define SSL_R_BAD_CHANGE_CIPHER_SPEC                     103
# define SSL_R_BAD_DATA                                   390
# define SSL_R_BAD_DATA_RETURNED_BY_CALLBACK              106
# define SSL_R_BAD_DECOMPRESSION                          107
# define SSL_R_BAD_DH_VALUE                               102
# define SSL_R_BAD_DIGEST_LENGTH                          111
# define SSL_R_BAD_ECC_CERT                               304
# define SSL_R_BAD_ECPOINT                                306
# define SSL_R_BAD_HANDSHAKE_LENGTH                       332
# define SSL_R_BAD_HELLO_REQUEST                          105
# define SSL_R_BAD_LENGTH                                 271
# define SSL_R_BAD_PACKET_LENGTH                          115
# define SSL_R_BAD_PROTOCOL_VERSION_NUMBER                116
# define SSL_R_BAD_RSA_ENCRYPT                            119
# define SSL_R_BAD_SIGNATURE                              123
# define SSL_R_BAD_SRP_A_LENGTH                           347
# define SSL_R_BAD_SRP_PARAMETERS                         371
# define SSL_R_BAD_SRTP_MKI_VALUE                         352
# define SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST           353
# define SSL_R_BAD_SSL_FILETYPE                           124
# define SSL_R_BAD_VALUE                                  384
# define SSL_R_BAD_WRITE_RETRY                            127
# define SSL_R_BIO_NOT_SET                                128
# define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  129
# define SSL_R_BN_LIB                                     130
# define SSL_R_CA_DN_LENGTH_MISMATCH                      131
# define SSL_R_CA_KEY_TOO_SMALL                           397
# define SSL_R_CA_MD_TOO_WEAK                             398
# define SSL_R_CCS_RECEIVED_EARLY                         133
# define SSL_R_CERTIFICATE_VERIFY_FAILED                  134
# define SSL_R_CERT_CB_ERROR                              377
# define SSL_R_CERT_LENGTH_MISMATCH                       135
# define SSL_R_CIPHER_CODE_WRONG_LENGTH                   137
# define SSL_R_CIPHER_OR_HASH_UNAVAILABLE                 138
# define SSL_R_CLIENTHELLO_TLSEXT                         226
# define SSL_R_COMPRESSED_LENGTH_TOO_LONG                 140
# define SSL_R_COMPRESSION_DISABLED                       343
# define SSL_R_COMPRESSION_FAILURE                        141
# define SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE    307
# define SSL_R_COMPRESSION_LIBRARY_ERROR                  142
# define SSL_R_CONNECTION_TYPE_NOT_SET                    144
# define SSL_R_CONTEXT_NOT_DANE_ENABLED                   167
# define SSL_R_COOKIE_GEN_CALLBACK_FAILURE                400
# define SSL_R_COOKIE_MISMATCH                            308
# define SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED       206
# define SSL_R_DANE_ALREADY_ENABLED                       172
# define SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL            173
# define SSL_R_DANE_NOT_ENABLED                           175
# define SSL_R_DANE_TLSA_BAD_CERTIFICATE                  180
# define SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE            184
# define SSL_R_DANE_TLSA_BAD_DATA_LENGTH                  189
# define SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH                192
# define SSL_R_DANE_TLSA_BAD_MATCHING_TYPE                200
# define SSL_R_DANE_TLSA_BAD_PUBLIC_KEY                   201
# define SSL_R_DANE_TLSA_BAD_SELECTOR                     202
# define SSL_R_DANE_TLSA_NULL_DATA                        203
# define SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              145
# define SSL_R_DATA_LENGTH_TOO_LONG                       146
# define SSL_R_DECRYPTION_FAILED                          147
# define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        281
# define SSL_R_DH_KEY_TOO_SMALL                           394
# define SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG            148
# define SSL_R_DIGEST_CHECK_FAILED                        149
# define SSL_R_DTLS_MESSAGE_TOO_BIG                       334
# define SSL_R_DUPLICATE_COMPRESSION_ID                   309
# define SSL_R_ECC_CERT_NOT_FOR_SIGNING                   318
# define SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE              374
# define SSL_R_EE_KEY_TOO_SMALL                           399
# define SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST         354
# define SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  150
# define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              151
# define SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN             204
# define SSL_R_EXCESSIVE_MESSAGE_SIZE                     152
# define SSL_R_EXTRA_DATA_IN_MESSAGE                      153
# define SSL_R_FAILED_TO_INIT_ASYNC                       405
# define SSL_R_FRAGMENTED_CLIENT_HELLO                    401
# define SSL_R_GOT_A_FIN_BEFORE_A_CCS                     154
# define SSL_R_HTTPS_PROXY_REQUEST                        155
# define SSL_R_HTTP_REQUEST                               156
# define SSL_R_ILLEGAL_SUITEB_DIGEST                      380
# define SSL_R_INAPPROPRIATE_FALLBACK                     373
# define SSL_R_INCONSISTENT_COMPRESSION                   340
# define SSL_R_INCONSISTENT_EXTMS                         104
# define SSL_R_INVALID_COMMAND                            280
# define SSL_R_INVALID_COMPRESSION_ALGORITHM              341
# define SSL_R_INVALID_CONFIGURATION_NAME                 113
# define SSL_R_INVALID_CT_VALIDATION_TYPE                 212
# define SSL_R_INVALID_NULL_CMD_NAME                      385
# define SSL_R_INVALID_SEQUENCE_NUMBER                    402
# define SSL_R_INVALID_SERVERINFO_DATA                    388
# define SSL_R_INVALID_SRP_USERNAME                       357
# define SSL_R_INVALID_STATUS_RESPONSE                    328
# define SSL_R_INVALID_TICKET_KEYS_LENGTH                 325
# define SSL_R_LENGTH_MISMATCH                            159
# define SSL_R_LENGTH_TOO_LONG                            404
# define SSL_R_LENGTH_TOO_SHORT                           160
# define SSL_R_LIBRARY_BUG                                274
# define SSL_R_LIBRARY_HAS_NO_CIPHERS                     161
# define SSL_R_MISSING_DSA_SIGNING_CERT                   165
# define SSL_R_MISSING_ECDSA_SIGNING_CERT                 381
# define SSL_R_MISSING_RSA_CERTIFICATE                    168
# define SSL_R_MISSING_RSA_ENCRYPTING_CERT                169
# define SSL_R_MISSING_RSA_SIGNING_CERT                   170
# define SSL_R_MISSING_SRP_PARAM                          358
# define SSL_R_MISSING_TMP_DH_KEY                         171
# define SSL_R_MISSING_TMP_ECDH_KEY                       311
# define SSL_R_NO_CERTIFICATES_RETURNED                   176
# define SSL_R_NO_CERTIFICATE_ASSIGNED                    177
# define SSL_R_NO_CERTIFICATE_SET                         179
# define SSL_R_NO_CIPHERS_AVAILABLE                       181
# define SSL_R_NO_CIPHERS_SPECIFIED                       183
# define SSL_R_NO_CIPHER_MATCH                            185
# define SSL_R_NO_CLIENT_CERT_METHOD                      331
# define SSL_R_NO_COMPRESSION_SPECIFIED                   187
# define SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER           330
# define SSL_R_NO_METHOD_SPECIFIED                        188
# define SSL_R_NO_PEM_EXTENSIONS                          389
# define SSL_R_NO_PRIVATE_KEY_ASSIGNED                    190
# define SSL_R_NO_PROTOCOLS_AVAILABLE                     191
# define SSL_R_NO_RENEGOTIATION                           339
# define SSL_R_NO_REQUIRED_DIGEST                         324
# define SSL_R_NO_SHARED_CIPHER                           193
# define SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             376
# define SSL_R_NO_SRTP_PROFILES                           359
# define SSL_R_NO_VALID_SCTS                              216
# define SSL_R_NO_VERIFY_COOKIE_CALLBACK                  403
# define SSL_R_NULL_SSL_CTX                               195
# define SSL_R_NULL_SSL_METHOD_PASSED                     196
# define SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED            197
# define SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED 344
# define SSL_R_PACKET_LENGTH_TOO_LONG                     198
# define SSL_R_PARSE_TLSEXT                               227
# define SSL_R_PATH_TOO_LONG                              270
# define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE          199
# define SSL_R_PEM_NAME_BAD_PREFIX                        391
# define SSL_R_PEM_NAME_TOO_SHORT                         392
# define SSL_R_PIPELINE_FAILURE                           406
# define SSL_R_PROTOCOL_IS_SHUTDOWN                       207
# define SSL_R_PSK_IDENTITY_NOT_FOUND                     223
# define SSL_R_PSK_NO_CLIENT_CB                           224
# define SSL_R_PSK_NO_SERVER_CB                           225
# define SSL_R_READ_BIO_NOT_SET                           211
# define SSL_R_READ_TIMEOUT_EXPIRED                       312
# define SSL_R_RECORD_LENGTH_MISMATCH                     213
# define SSL_R_RECORD_TOO_SMALL                           298
# define SSL_R_RENEGOTIATE_EXT_TOO_LONG                   335
# define SSL_R_RENEGOTIATION_ENCODING_ERR                 336
# define SSL_R_RENEGOTIATION_MISMATCH                     337
# define SSL_R_REQUIRED_CIPHER_MISSING                    215
# define SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING     342
# define SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           345
# define SSL_R_SCT_VERIFICATION_FAILED                    208
# define SSL_R_SERVERHELLO_TLSEXT                         275
# define SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED           277
# define SSL_R_SHUTDOWN_WHILE_IN_INIT                     407
# define SSL_R_SIGNATURE_ALGORITHMS_ERROR                 360
# define SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE      220
# define SSL_R_SRP_A_CALC                                 361
# define SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES           362
# define SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG      363
# define SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE            364
# define SSL_R_SSL3_EXT_INVALID_SERVERNAME                319
# define SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE           320
# define SSL_R_SSL3_SESSION_ID_TOO_LONG                   300
# define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                1042
# define SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 1020
# define SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            1045
# define SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            1044
# define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            1046
# define SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          1030
# define SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              1040
# define SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              1047
# define SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 1041
# define SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             1010
# define SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        1043
# define SSL_R_SSL_COMMAND_SECTION_EMPTY                  117
# define SSL_R_SSL_COMMAND_SECTION_NOT_FOUND              125
# define SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION         228
# define SSL_R_SSL_HANDSHAKE_FAILURE                      229
# define SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS                 230
# define SSL_R_SSL_NEGATIVE_LENGTH                        372
# define SSL_R_SSL_SECTION_EMPTY                          126
# define SSL_R_SSL_SECTION_NOT_FOUND                      136
# define SSL_R_SSL_SESSION_ID_CALLBACK_FAILED             301
# define SSL_R_SSL_SESSION_ID_CONFLICT                    302
# define SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG            273
# define SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH              303
# define SSL_R_SSL_SESSION_ID_TOO_LONG                    408
# define SSL_R_SSL_SESSION_VERSION_MISMATCH               210
# define SSL_R_TLSV1_ALERT_ACCESS_DENIED                  1049
# define SSL_R_TLSV1_ALERT_DECODE_ERROR                   1050
# define SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              1021
# define SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  1051
# define SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             1060
# define SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK         1086
# define SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          1071
# define SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 1080
# define SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               1100
# define SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               1070
# define SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                1022
# define SSL_R_TLSV1_ALERT_UNKNOWN_CA                     1048
# define SSL_R_TLSV1_ALERT_USER_CANCELLED                 1090
# define SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE           1114
# define SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE      1113
# define SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE             1111
# define SSL_R_TLSV1_UNRECOGNIZED_NAME                    1112
# define SSL_R_TLSV1_UNSUPPORTED_EXTENSION                1110
# define SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT           365
# define SSL_R_TLS_HEARTBEAT_PENDING                      366
# define SSL_R_TLS_ILLEGAL_EXPORTER_LABEL                 367
# define SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST             157
# define SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS             314
# define SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS       239
# define SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES           242
# define SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES          243
# define SSL_R_UNEXPECTED_MESSAGE                         244
# define SSL_R_UNEXPECTED_RECORD                          245
# define SSL_R_UNINITIALIZED                              276
# define SSL_R_UNKNOWN_ALERT_TYPE                         246
# define SSL_R_UNKNOWN_CERTIFICATE_TYPE                   247
# define SSL_R_UNKNOWN_CIPHER_RETURNED                    248
# define SSL_R_UNKNOWN_CIPHER_TYPE                        249
# define SSL_R_UNKNOWN_CMD_NAME                           386
# define SSL_R_UNKNOWN_COMMAND                            139
# define SSL_R_UNKNOWN_DIGEST                             368
# define SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE                  250
# define SSL_R_UNKNOWN_PKEY_TYPE                          251
# define SSL_R_UNKNOWN_PROTOCOL                           252
# define SSL_R_UNKNOWN_SSL_VERSION                        254
# define SSL_R_UNKNOWN_STATE                              255
# define SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       338
# define SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM          257
# define SSL_R_UNSUPPORTED_ELLIPTIC_CURVE                 315
# define SSL_R_UNSUPPORTED_PROTOCOL                       258
# define SSL_R_UNSUPPORTED_SSL_VERSION                    259
# define SSL_R_UNSUPPORTED_STATUS_TYPE                    329
# define SSL_R_USE_SRTP_NOT_NEGOTIATED                    369
# define SSL_R_VERSION_TOO_HIGH                           166
# define SSL_R_VERSION_TOO_LOW                            396
# define SSL_R_WRONG_CERTIFICATE_TYPE                     383
# define SSL_R_WRONG_CIPHER_RETURNED                      261
# define SSL_R_WRONG_CURVE                                378
# define SSL_R_WRONG_SIGNATURE_LENGTH                     264
# define SSL_R_WRONG_SIGNATURE_SIZE                       265
# define SSL_R_WRONG_SIGNATURE_TYPE                       370
# define SSL_R_WRONG_SSL_VERSION                          266
# define SSL_R_WRONG_VERSION_NUMBER                       267
# define SSL_R_X509_LIB                                   268
# define SSL_R_X509_VERIFICATION_SETUP_PROBLEMS           269
# define SSL_SECOP_CA_KEY                (17 | SSL_SECOP_OTHER_CERT)
# define SSL_SECOP_CA_MD                 (18 | SSL_SECOP_OTHER_CERT)
# define SSL_SECOP_CIPHER_CHECK          (3 | SSL_SECOP_OTHER_CIPHER)
# define SSL_SECOP_CIPHER_SHARED         (2 | SSL_SECOP_OTHER_CIPHER)
# define SSL_SECOP_CIPHER_SUPPORTED      (1 | SSL_SECOP_OTHER_CIPHER)
# define SSL_SECOP_COMPRESSION           (15 | SSL_SECOP_OTHER_NONE)
# define SSL_SECOP_CURVE_CHECK           (6 | SSL_SECOP_OTHER_CURVE)
# define SSL_SECOP_CURVE_SHARED          (5 | SSL_SECOP_OTHER_CURVE)
# define SSL_SECOP_CURVE_SUPPORTED       (4 | SSL_SECOP_OTHER_CURVE)
# define SSL_SECOP_EE_KEY                (16 | SSL_SECOP_OTHER_CERT)
# define SSL_SECOP_OTHER_CERT    (6 << 16)
# define SSL_SECOP_OTHER_CIPHER  (1 << 16)
# define SSL_SECOP_OTHER_CURVE   (2 << 16)
# define SSL_SECOP_OTHER_DH      (3 << 16)
# define SSL_SECOP_OTHER_NONE    0
# define SSL_SECOP_OTHER_PKEY    (4 << 16)
# define SSL_SECOP_OTHER_SIGALG  (5 << 16)
# define SSL_SECOP_OTHER_TYPE    0xffff0000
# define SSL_SECOP_PEER          0x1000
# define SSL_SECOP_PEER_CA_KEY           (SSL_SECOP_CA_KEY | SSL_SECOP_PEER)
# define SSL_SECOP_PEER_CA_MD            (SSL_SECOP_CA_MD | SSL_SECOP_PEER)
# define SSL_SECOP_PEER_EE_KEY           (SSL_SECOP_EE_KEY | SSL_SECOP_PEER)
# define SSL_SECOP_SIGALG_CHECK          (13 | SSL_SECOP_OTHER_SIGALG)
# define SSL_SECOP_SIGALG_MASK           (14 | SSL_SECOP_OTHER_SIGALG)
# define SSL_SECOP_SIGALG_SHARED         (12 | SSL_SECOP_OTHER_SIGALG)
# define SSL_SECOP_SIGALG_SUPPORTED      (11 | SSL_SECOP_OTHER_SIGALG)
# define SSL_SECOP_TICKET                (10 | SSL_SECOP_OTHER_NONE)
# define SSL_SECOP_TMP_DH                (7 | SSL_SECOP_OTHER_PKEY)
# define SSL_SECOP_VERSION               (9 | SSL_SECOP_OTHER_NONE)
# define SSL_SENT_SHUTDOWN       1
# define SSL_SESSION_ASN1_VERSION 0x0001
# define SSL_SESSION_CACHE_MAX_SIZE_DEFAULT      (1024*20)
# define SSL_SESSION_get_app_data(s)     (SSL_SESSION_get_ex_data(s,0))
#define SSL_SESSION_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_SESSION, l, p, newf, dupf, freef)
# define SSL_SESSION_set_app_data(s,a)   (SSL_SESSION_set_ex_data(s,0,(char *)a))
# define SSL_SESS_CACHE_BOTH     (SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_SERVER)
# define SSL_SESS_CACHE_CLIENT                   0x0001
# define SSL_SESS_CACHE_NO_AUTO_CLEAR            0x0080
# define SSL_SESS_CACHE_NO_INTERNAL \
        (SSL_SESS_CACHE_NO_INTERNAL_LOOKUP|SSL_SESS_CACHE_NO_INTERNAL_STORE)
# define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP       0x0100
# define SSL_SESS_CACHE_NO_INTERNAL_STORE        0x0200
# define SSL_SESS_CACHE_OFF                      0x0000
# define SSL_SESS_CACHE_SERVER                   0x0002
# define SSL_ST_ACCEPT                   0x2000
# define SSL_ST_CONNECT                  0x1000
# define SSL_ST_MASK                     0x0FFF
# define SSL_ST_READ_BODY                        0xF1
# define SSL_ST_READ_DONE                        0xF2
# define SSL_ST_READ_HEADER                      0xF0
# define SSL_TXT_3DES            "3DES"
# define SSL_TXT_ADH             "ADH"
# define SSL_TXT_AECDH           "AECDH"
# define SSL_TXT_AES             "AES"
# define SSL_TXT_AES128          "AES128"
# define SSL_TXT_AES256          "AES256"
# define SSL_TXT_AES_CCM         "AESCCM"
# define SSL_TXT_AES_CCM_8       "AESCCM8"
# define SSL_TXT_AES_GCM         "AESGCM"
# define SSL_TXT_ALL             "ALL"
# define SSL_TXT_CAMELLIA        "CAMELLIA"
# define SSL_TXT_CAMELLIA128     "CAMELLIA128"
# define SSL_TXT_CAMELLIA256     "CAMELLIA256"
# define SSL_TXT_CHACHA20        "CHACHA20"
# define SSL_TXT_CMPALL          "COMPLEMENTOFALL"
# define SSL_TXT_CMPDEF          "COMPLEMENTOFDEFAULT"
# define SSL_TXT_DES             "DES"
# define SSL_TXT_DH              "DH"
# define SSL_TXT_DHE             "DHE"
# define SSL_TXT_DSS             "DSS"
# define SSL_TXT_ECDH            "ECDH"
# define SSL_TXT_ECDHE           "ECDHE"
# define SSL_TXT_ECDSA           "ECDSA"
# define SSL_TXT_EDH             "EDH"
# define SSL_TXT_EECDH           "EECDH"
# define SSL_TXT_FIPS            "FIPS"
# define SSL_TXT_GOST            "GOST89"
# define SSL_TXT_GOST12          "GOST12"
# define SSL_TXT_GOST89MAC       "GOST89MAC"
# define SSL_TXT_GOST89MAC12     "GOST89MAC12"
# define SSL_TXT_GOST94          "GOST94"
# define SSL_TXT_HIGH            "HIGH"
# define SSL_TXT_IDEA            "IDEA"
# define SSL_TXT_LOW             "LOW"
# define SSL_TXT_MD5             "MD5"
# define SSL_TXT_MEDIUM          "MEDIUM"
# define SSL_TXT_NULL            "NULL"
# define SSL_TXT_PSK             "PSK"
# define SSL_TXT_RC2             "RC2"
# define SSL_TXT_RC4             "RC4"
# define SSL_TXT_RSA             "RSA"
# define SSL_TXT_SEED            "SEED"
# define SSL_TXT_SHA             "SHA"
# define SSL_TXT_SHA1            "SHA1"
# define SSL_TXT_SHA256          "SHA256"
# define SSL_TXT_SHA384          "SHA384"
# define SSL_TXT_SRP             "SRP"
# define SSL_TXT_SSLV3           "SSLv3"
# define SSL_TXT_TLSV1           "TLSv1"
# define SSL_TXT_TLSV1_1         "TLSv1.1"
# define SSL_TXT_TLSV1_2         "TLSv1.2"
# define SSL_TXT_aDH             "aDH"
# define SSL_TXT_aDSS            "aDSS"
# define SSL_TXT_aECDH           "aECDH"
# define SSL_TXT_aECDSA          "aECDSA"
# define SSL_TXT_aGOST           "aGOST"
# define SSL_TXT_aGOST01         "aGOST01"
# define SSL_TXT_aGOST12         "aGOST12"
# define SSL_TXT_aGOST94         "aGOST94"
# define SSL_TXT_aNULL           "aNULL"
# define SSL_TXT_aPSK            "aPSK"
# define SSL_TXT_aRSA            "aRSA"
# define SSL_TXT_aSRP            "aSRP"
# define SSL_TXT_eNULL           "eNULL"
# define SSL_TXT_kDH             "kDH"
# define SSL_TXT_kDHE            "kDHE"
# define SSL_TXT_kDHEPSK         "kDHEPSK"
# define SSL_TXT_kDHd            "kDHd"
# define SSL_TXT_kDHr            "kDHr"
# define SSL_TXT_kECDH           "kECDH"
# define SSL_TXT_kECDHE          "kECDHE"
# define SSL_TXT_kECDHEPSK       "kECDHEPSK"
# define SSL_TXT_kECDHe          "kECDHe"
# define SSL_TXT_kECDHr          "kECDHr"
# define SSL_TXT_kEDH            "kEDH"
# define SSL_TXT_kEECDH          "kEECDH"
# define SSL_TXT_kGOST           "kGOST"
# define SSL_TXT_kPSK            "kPSK"
# define SSL_TXT_kRSA            "kRSA"
# define SSL_TXT_kRSAPSK         "kRSAPSK"
# define SSL_TXT_kSRP            "kSRP"
# define SSL_VERIFY_CLIENT_ONCE          0x04
# define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
# define SSL_VERIFY_NONE                 0x00
# define SSL_VERIFY_PEER                 0x01
# define SSL_WRITING            2
# define SSL_X509_LOOKUP        4
# define SSL_add0_chain_cert(ctx,x509) \
        SSL_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)x509)
# define SSL_add1_chain_cert(ctx,x509) \
        SSL_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)x509)
# define SSL_build_cert_chain(s, flags) \
        SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)
#  define SSL_cache_hit(s) SSL_session_reused(s)
# define SSL_clear_cert_flags(s,op) \
        SSL_ctrl((s),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)
# define SSL_clear_chain_certs(ctx) \
        SSL_set0_chain(ctx,NULL)
# define SSL_clear_mode(ssl,op) \
        SSL_ctrl((ssl),SSL_CTRL_CLEAR_MODE,(op),NULL)
# define SSL_clear_num_renegotiations(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)
#define SSL_disable_ct(s) \
        ((void) SSL_set_validation_callback((s), NULL, NULL))
# define SSL_get0_certificate_types(s, clist) \
        SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)clist)
# define SSL_get0_chain_certs(ctx,px509) \
        SSL_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)
# define SSL_get0_ec_point_formats(s, plst) \
        SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst)
# define SSL_get0_raw_cipherlist(s, plst) \
        SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst)
# define SSL_get0_session SSL_get_session
# define SSL_get1_curves(ctx, s) \
        SSL_ctrl(ctx,SSL_CTRL_GET_CURVES,0,(char *)s)
# define SSL_get_app_data(s)             (SSL_get_ex_data(s,0))
# define SSL_get_cipher(s) \
                SSL_CIPHER_get_name(SSL_get_current_cipher(s))
# define SSL_get_cipher_bits(s,np) \
                SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np)
# define SSL_get_cipher_name(s) \
                SSL_CIPHER_get_name(SSL_get_current_cipher(s))
# define SSL_get_cipher_version(s) \
                SSL_CIPHER_get_version(SSL_get_current_cipher(s))
#define SSL_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, l, p, newf, dupf, freef)
# define SSL_get_extms_support(s) \
        SSL_ctrl((s),SSL_CTRL_GET_EXTMS_SUPPORT,0,NULL)
# define SSL_get_max_cert_list(ssl) \
        SSL_ctrl(ssl,SSL_CTRL_GET_MAX_CERT_LIST,0,NULL)
# define SSL_get_mode(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_MODE,0,NULL)
# define SSL_get_peer_signature_nid(s, pn) \
        SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)
# define SSL_get_secure_renegotiation_support(ssl) \
        SSL_ctrl((ssl), SSL_CTRL_GET_RI_SUPPORT, 0, NULL)
# define SSL_get_server_tmp_key(s, pk) \
        SSL_ctrl(s,SSL_CTRL_GET_SERVER_TMP_KEY,0,pk)
# define SSL_get_shared_curve(s, n) \
        SSL_ctrl(s,SSL_CTRL_GET_SHARED_CURVE,n,NULL)
# define SSL_get_time(a)         SSL_SESSION_get_time(a)
# define SSL_get_timeout(a)      SSL_SESSION_get_timeout(a)
#  define SSL_heartbeat(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT,0,NULL)
# define SSL_in_accept_init(a)           (SSL_in_init(a) && SSL_is_server(a))
# define SSL_in_connect_init(a)          (SSL_in_init(a) && !SSL_is_server(a))
# define SSL_library_init() OPENSSL_init_ssl(0, NULL)
# define SSL_load_error_strings() \
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS \
                     | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
# define SSL_need_tmp_RSA(ssl)                    0
# define SSL_num_renegotiations(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)
# define SSL_select_current_cert(ctx,x509) \
        SSL_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)x509)
# define SSL_set0_chain(ctx,sk) \
        SSL_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)sk)
# define SSL_set0_chain_cert_store(s,st) \
        SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)st)
# define SSL_set0_verify_cert_store(s,st) \
        SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)st)
# define SSL_set1_chain(ctx,sk) \
        SSL_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)sk)
# define SSL_set1_chain_cert_store(s,st) \
        SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)st)
# define SSL_set1_client_certificate_types(s, clist, clistlen) \
        SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)clist)
# define SSL_set1_client_sigalgs(ctx, slist, slistlen) \
        SSL_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,clistlen,(int *)slist)
# define SSL_set1_client_sigalgs_list(ctx, s) \
        SSL_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)s)
# define SSL_set1_curves(ctx, clist, clistlen) \
        SSL_ctrl(ctx,SSL_CTRL_SET_CURVES,clistlen,(char *)clist)
# define SSL_set1_curves_list(ctx, s) \
        SSL_ctrl(ctx,SSL_CTRL_SET_CURVES_LIST,0,(char *)s)
# define SSL_set1_sigalgs(ctx, slist, slistlen) \
        SSL_ctrl(ctx,SSL_CTRL_SET_SIGALGS,clistlen,(int *)slist)
# define SSL_set1_sigalgs_list(ctx, s) \
        SSL_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)s)
# define SSL_set1_verify_cert_store(s,st) \
        SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)st)
# define SSL_set_app_data(s,arg)         (SSL_set_ex_data(s,0,(char *)arg))
# define SSL_set_cert_flags(s,op) \
        SSL_ctrl((s),SSL_CTRL_CERT_FLAGS,(op),NULL)
# define SSL_set_current_cert(ctx,op) \
        SSL_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)
# define SSL_set_dh_auto(s, onoff) \
        SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,NULL)
# define SSL_set_ecdh_auto(dummy, onoff)          ((onoff) != 0)
# define SSL_set_max_cert_list(ssl,m) \
        SSL_ctrl(ssl,SSL_CTRL_SET_MAX_CERT_LIST,m,NULL)
# define SSL_set_max_pipelines(ssl,m) \
        SSL_ctrl(ssl,SSL_CTRL_SET_MAX_PIPELINES,m,NULL)
#define SSL_set_max_proto_version(s, version) \
        SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
# define SSL_set_max_send_fragment(ssl,m) \
        SSL_ctrl(ssl,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)
#define SSL_set_min_proto_version(s, version) \
        SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
# define SSL_set_mode(ssl,op) \
        SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL)
# define SSL_set_msg_callback_arg(ssl, arg) SSL_ctrl((ssl), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
# define SSL_set_mtu(ssl, mtu) \
        SSL_ctrl((ssl),SSL_CTRL_SET_MTU,(mtu),NULL)
# define SSL_set_split_send_fragment(ssl,m) \
        SSL_ctrl(ssl,SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,m,NULL)
# define SSL_set_time(a,b)       SSL_SESSION_set_time((a),(b))
# define SSL_set_timeout(a,b)    SSL_SESSION_set_timeout((a),(b))
# define SSL_set_tmp_dh(ssl,dh) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
# define SSL_set_tmp_ecdh(ssl,ecdh) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)ecdh)
# define SSL_set_tmp_rsa(ssl,rsa)                 1
# define SSL_set_tmp_rsa_callback(ssl, cb)        while(0) (cb)(NULL, 0, 0)
# define SSL_total_renegotiations(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)
# define SSL_want_async(s)       (SSL_want(s) == SSL_ASYNC_PAUSED)
# define SSL_want_async_job(s)   (SSL_want(s) == SSL_ASYNC_NO_JOBS)
# define SSL_want_nothing(s)     (SSL_want(s) == SSL_NOTHING)
# define SSL_want_read(s)        (SSL_want(s) == SSL_READING)
# define SSL_want_write(s)       (SSL_want(s) == SSL_WRITING)
# define SSL_want_x509_lookup(s) (SSL_want(s) == SSL_X509_LOOKUP)
#  define SSLeay_add_ssl_algorithms()    SSL_library_init()
#define SSLv23_client_method    TLS_client_method
#define SSLv23_method           TLS_method
#define SSLv23_server_method    TLS_server_method
# define d2i_SSL_SESSION_bio(bp,s_id) ASN1_d2i_bio_of(SSL_SESSION,SSL_SESSION_new,d2i_SSL_SESSION,bp,s_id)
# define i2d_SSL_SESSION_bio(bp,s_id) ASN1_i2d_bio_of(SSL_SESSION,i2d_SSL_SESSION,bp,s_id)
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
# define ERR_LIB_JPAKE           49
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
# define JPAKEerr(f,r) ERR_PUT_error(ERR_LIB_JPAKE,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
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
