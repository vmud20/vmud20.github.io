













#include<linux/socket.h>







#include<time.h>





#include<linux/limits.h>











#include<linux/string.h>

#include<sys/errno.h>







#include<stdio.h>





#include<linux/module.h>





















#include<sys/stat.h>
#include<limits.h>



#include<stdint.h>



#include<sys/socket.h>





#include<sys/uio.h>





#include<sys/ioctl.h>
#include<errno.h>









#include<stdarg.h>










#include<ctype.h>
#include<string.h>






#include<semaphore.h>




#include<sys/time.h>


#include<linux/if_alg.h>
#include<netinet/in.h>





#include<sys/types.h>















#include<zlib.h>


















#include<stdbool.h>








#include<linux/kernel.h>
























#include<linux/net.h>













#include<stddef.h>














#include<arpa/inet.h>



#include<strings.h>



#include<dirent.h>


















#include<stdlib.h>









#include<pthread.h>






#include<unistd.h>






































#include<fcntl.h>



#include<netdb.h>



#include<linux/version.h>









#define ASN1_OBJECT_free wolfSSL_ASN1_OBJECT_free
#define NID_ad_OCSP                     178
#define NID_ad_ca_issuers               179
#define OBJ_cleanup wolfSSL_OBJ_cleanup
#define OBJ_cmp     wolfSSL_OBJ_cmp
#define OBJ_create  wolfSSL_OBJ_create
#define OBJ_ln2nid  wolfSSL_OBJ_ln2nid
#define OBJ_nid2ln  wolfSSL_OBJ_nid2ln
#define OBJ_nid2obj wolfSSL_OBJ_nid2obj
#define OBJ_nid2sn  wolfSSL_OBJ_nid2sn
#define OBJ_obj2nid wolfSSL_OBJ_obj2nid
#define OBJ_obj2txt wolfSSL_OBJ_obj2txt
#define OBJ_sn2nid  wolfSSL_OBJ_sn2nid
#define OBJ_txt2nid wolfSSL_OBJ_txt2nid
#define OBJ_txt2obj wolfSSL_OBJ_txt2obj



#define CRYPTO_EX_INDEX_APP             13
#define CRYPTO_EX_INDEX_BIO             12
#define CRYPTO_EX_INDEX_DH              6
#define CRYPTO_EX_INDEX_DRBG            15
#define CRYPTO_EX_INDEX_DSA             7
#define CRYPTO_EX_INDEX_EC_KEY          8
#define CRYPTO_EX_INDEX_ENGINE          10
#define CRYPTO_EX_INDEX_RSA             9
#define CRYPTO_EX_INDEX_SSL             0
#define CRYPTO_EX_INDEX_SSL_CTX         1
#define CRYPTO_EX_INDEX_SSL_SESSION     2
#define CRYPTO_EX_INDEX_UI              11
#define CRYPTO_EX_INDEX_UI_METHOD       14
#define CRYPTO_EX_INDEX_X509            3
#define CRYPTO_EX_INDEX_X509_STORE      4
#define CRYPTO_EX_INDEX_X509_STORE_CTX  5
#define CRYPTO_EX_INDEX__COUNT          16
    #define DECLARE_STACK_OF(x) WOLF_STACK_OF(x);
#define MAX_BIO_METHOD_NAME 256


    #define PEM_BUFSIZE WOLF_PEM_BUFSIZE

    #define SSL_ALPN_NOT_FOUND WOLFSSL_ALPN_NOT_FOUND
    #define SSL_BAD_CERTTYPE WOLFSSL_BAD_CERTTYPE
    #define SSL_BAD_FILE WOLFSSL_BAD_FILE
    #define SSL_BAD_FILETYPE WOLFSSL_BAD_FILETYPE
    #define SSL_BAD_PATH WOLFSSL_BAD_PATH
    #define SSL_BAD_STAT WOLFSSL_BAD_STAT
    #define SSL_ERROR_NONE WOLFSSL_ERROR_NONE
    #define SSL_ERROR_SSL WOLFSSL_ERROR_SSL
    #define SSL_ERROR_SYSCALL WOLFSSL_ERROR_SYSCALL
    #define SSL_ERROR_WANT_ACCEPT WOLFSSL_ERROR_WANT_ACCEPT
    #define SSL_ERROR_WANT_CONNECT WOLFSSL_ERROR_WANT_CONNECT
    #define SSL_ERROR_WANT_READ WOLFSSL_ERROR_WANT_READ
    #define SSL_ERROR_WANT_WRITE WOLFSSL_ERROR_WANT_WRITE
    #define SSL_ERROR_WANT_X509_LOOKUP WOLFSSL_ERROR_WANT_X509_LOOKUP
    #define SSL_ERROR_ZERO_RETURN WOLFSSL_ERROR_ZERO_RETURN
    #define SSL_FAILURE WOLFSSL_FAILURE
    #define SSL_FATAL_ERROR WOLFSSL_FATAL_ERROR
    #define SSL_FILETYPE_ASN1 WOLFSSL_FILETYPE_ASN1
    #define SSL_FILETYPE_DEFAULT WOLFSSL_FILETYPE_DEFAULT
    #define SSL_FILETYPE_PEM WOLFSSL_FILETYPE_PEM
    #define SSL_FILETYPE_RAW WOLFSSL_FILETYPE_RAW
    #define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
#define SSL_NOTHING 1
    #define SSL_NOT_IMPLEMENTED WOLFSSL_NOT_IMPLEMENTED
#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | \
    SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3)
#define SSL_OP_NO_SSLv2   WOLFSSL_OP_NO_SSLv2
#define SSL_OP_NO_SSLv3   WOLFSSL_OP_NO_SSLv3
#define SSL_OP_NO_TLSv1   WOLFSSL_OP_NO_TLSv1
#define SSL_OP_NO_TLSv1_1 WOLFSSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_2 WOLFSSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_3 WOLFSSL_OP_NO_TLSv1_3
#define SSL_READING 3
    #define SSL_RECEIVED_SHUTDOWN WOLFSSL_RECEIVED_SHUTDOWN
    #define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE
    #define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN
    #define SSL_R_SSL_HANDSHAKE_FAILURE WOLFSSL_R_SSL_HANDSHAKE_FAILURE
    #define SSL_R_TLSV1_ALERT_UNKNOWN_CA WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA
    #define SSL_SENT_SHUTDOWN WOLFSSL_SENT_SHUTDOWN
    #define SSL_SESS_CACHE_BOTH WOLFSSL_SESS_CACHE_BOTH
    #define SSL_SESS_CACHE_CLIENT WOLFSSL_SESS_CACHE_CLIENT
    #define SSL_SESS_CACHE_NO_AUTO_CLEAR WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR
    #define SSL_SESS_CACHE_NO_INTERNAL WOLFSSL_SESS_CACHE_NO_INTERNAL
    #define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP
    #define SSL_SESS_CACHE_NO_INTERNAL_STORE WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE
    #define SSL_SESS_CACHE_OFF WOLFSSL_SESS_CACHE_OFF
    #define SSL_SESS_CACHE_SERVER WOLFSSL_SESS_CACHE_SERVER
    #define SSL_SHUTDOWN_NOT_DONE WOLFSSL_SHUTDOWN_NOT_DONE
    #define SSL_SUCCESS WOLFSSL_SUCCESS
    #define SSL_UNKNOWN WOLFSSL_UNKNOWN
    #define SSL_VERIFY_CLIENT_ONCE WOLFSSL_VERIFY_CLIENT_ONCE
    #define SSL_VERIFY_FAIL_EXCEPT_PSK WOLFSSL_VERIFY_FAIL_EXCEPT_PSK
    #define SSL_VERIFY_FAIL_IF_NO_PEER_CERT WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
    #define SSL_VERIFY_NONE WOLFSSL_VERIFY_NONE
    #define SSL_VERIFY_PEER WOLFSSL_VERIFY_PEER
#define SSL_WRITING 2


#define WOLFSSL_ASN1_BOOLEAN                int
#define WOLFSSL_ASN1_DYNAMIC 0x1
#define WOLFSSL_ASN1_DYNAMIC_DATA 0x2
#define WOLFSSL_ASN1_GENERALIZEDTIME  WOLFSSL_ASN1_TIME
#define WOLFSSL_ASN1_UTCTIME          WOLFSSL_ASN1_TIME
#define WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS     0x1
#define WOLFSSL_CIPHER_SUITE_FLAG_NONE          0x0
#define WOLFSSL_CONF_FLAG_CERTIFICATE   0x20
#define WOLFSSL_CONF_FLAG_CMDLINE       0x1
#define WOLFSSL_CONF_FLAG_FILE          0x2
#define WOLFSSL_CONF_TYPE_FILE          0x2
#define WOLFSSL_CONF_TYPE_STRING        0x1
#define WOLFSSL_CRL_MONITOR   0x01   
#define WOLFSSL_CRL_START_MON 0x02   
#define WOLFSSL_DEFAULT_CIPHER_LIST ""   
#define WOLFSSL_DH_TYPE_DEFINED 


#define WOLFSSL_EARLY_DATA_ACCEPTED    2
#define WOLFSSL_EARLY_DATA_NOT_SENT    0
#define WOLFSSL_EARLY_DATA_REJECTED    1


#define WOLFSSL_ERR_remove_thread_state wolfSSL_ERR_remove_thread_state
#define WOLFSSL_EVP_PKEY_DEFAULT EVP_PKEY_RSA 

#define WOLFSSL_HOST_NAME_MAX  256
#define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 0x00000002
#define WOLFSSL_LOAD_FLAG_IGNORE_BAD_PATH_ERR 0x00000008
#define WOLFSSL_LOAD_FLAG_IGNORE_ERR    0x00000001
#define WOLFSSL_LOAD_FLAG_IGNORE_ZEROFILE     0x00000010
#define WOLFSSL_LOAD_FLAG_NONE          0x00000000
#define WOLFSSL_LOAD_FLAG_PEM_CA_ONLY   0x00000004
#define WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS WOLFSSL_LOAD_FLAG_NONE
#define WOLFSSL_MAX_GROUP_COUNT       10
    #define WOLFSSL_MAX_IPSTR 46 
#define WOLFSSL_MAX_MASTER_KEY_LENGTH 48
#define WOLFSSL_MAX_SNAME 40

#define WOLFSSL_NO_CHECK_TIME  0x200000
#define WOLFSSL_NO_WILDCARDS   0x4


#define WOLFSSL_TICKET_IV_SZ   16
    #define WOLFSSL_TICKET_KEYS_SZ     (WOLFSSL_TICKET_NAME_SZ +    \
                                        2 * WOLFSSL_TICKET_KEY_SZ + \
                                        sizeof(word32) * 2)
        #define WOLFSSL_TICKET_KEY_SZ       CHACHA20_POLY1305_AEAD_KEYSIZE
#define WOLFSSL_TICKET_MAC_SZ  32
#define WOLFSSL_TICKET_NAME_SZ 16

#define WOLFSSL_USE_CHECK_TIME 0x2
    #define WOLFSSL_VERSION LIBWOLFSSL_VERSION_STRING
#define WOLFSSL_VPARAM_DEFAULT          0x1
#define WOLFSSL_VPARAM_LOCKED           0x8
#define WOLFSSL_VPARAM_ONCE             0x10
#define WOLFSSL_VPARAM_OVERWRITE        0x2
#define WOLFSSL_VPARAM_RESET_FLAGS      0x4


#define WOLFSSL_X509_L_ADD_DIR    0x2
#define WOLFSSL_X509_L_ADD_STORE  0x3
#define WOLFSSL_X509_L_FILE_LOAD  0x1
#define WOLFSSL_X509_L_LOAD_STORE 0x4
    #define WOLF_LHASH_OF(x) WOLFSSL_LHASH
    #define WOLF_STACK_OF(x) WOLFSSL_STACK
    #define WS_RETURN_CODE(item1,item2) \
      ((item1 < 0) ? item2 : item1)
#define X509_BUFFER_SZ 8192
#define wolfSSL_CTX_UseAsync wolfSSL_CTX_SetDevId
#define wolfSSL_CertPemToDer   wc_CertPemToDer
#define wolfSSL_FreeX509(x509) wolfSSL_X509_free((x509))
#define wolfSSL_KeyPemToDer    wc_KeyPemToDer
#define wolfSSL_PemCertToDer   wc_PemCertToDer
#define wolfSSL_PemPubKeyToDer wc_PemPubKeyToDer
#define wolfSSL_PubKeyPemToDer wc_PubKeyPemToDer
    #define wolfSSL_SSL_CTRL_SET_TMP_ECDH       4
#define wolfSSL_SSL_CTX_get_client_CA_list wolfSSL_CTX_get_client_CA_list
    #define wolfSSL_SSL_MODE_RELEASE_BUFFERS    0x00000010U
#define wolfSSL_UseAsync wolfSSL_SetDevId
#define wolfSSL_get_using_nonblock wolfSSL_dtls_get_using_nonblock
#define wolfSSL_set_using_nonblock wolfSSL_dtls_set_using_nonblock
#define OPENSSL_sk_free       wolfSSL_sk_free
#define OPENSSL_sk_new_null   wolfSSL_sk_new_null
#define OPENSSL_sk_pop_free   wolfSSL_sk_pop_free
#define OPENSSL_sk_push       wolfSSL_sk_push

#define sk_free         OPENSSL_sk_free
#define sk_new_null     OPENSSL_sk_new_null
#define sk_pop_free     OPENSSL_sk_pop_free
#define sk_push         OPENSSL_sk_push
#define CRYPTO_THREADID             WOLFSSL_CRYPTO_THREADID
#define CRYPTO_THREADID_current      wolfSSL_THREADID_current
#define CRYPTO_THREADID_hash         wolfSSL_THREADID_hash
#define CRYPTO_THREADID_set_callback wolfSSL_THREADID_set_callback
#define CRYPTO_THREADID_set_numeric wolfSSL_THREADID_set_numeric
#define CRYPTO_THREAD_lock wc_LockMutex
#define CRYPTO_THREAD_lock_free wc_FreeMutex
#define CRYPTO_THREAD_lock_new wc_InitAndAllocMutex
#define CRYPTO_THREAD_r_lock wc_LockMutex
#define CRYPTO_THREAD_read_lock wc_LockMutex
#define CRYPTO_THREAD_unlock wc_UnLockMutex
#define CRYPTO_THREAD_write_lock wc_LockMutex
#define CRYPTO_lock wc_LockMutex_ex
#define CRYPTO_malloc_init() 0 
#define CRYPTO_r_lock wc_LockMutex_ex
#define CRYPTO_set_ex_data wolfSSL_CRYPTO_set_ex_data
#define CRYPTO_set_mem_ex_functions      wolfSSL_CRYPTO_set_mem_ex_functions
#define CRYPTO_unlock wc_LockMutex_ex
#define FIPS_mode                        wolfSSL_FIPS_mode
#define FIPS_mode_set                    wolfSSL_FIPS_mode_set
#define OPENSSL_INIT_ADD_ALL_CIPHERS    0x00000004L
#define OPENSSL_INIT_ADD_ALL_DIGESTS    0x00000008L
#define OPENSSL_INIT_ENGINE_ALL_BUILTIN 0x00000001L
#define OPENSSL_INIT_LOAD_CONFIG        0x00000040L
# define OPENSSL_assert(e) \
    if (!(e)) { \
        fprintf(stderr, "%s:%d wolfSSL internal error: assertion failed: " #e, \
                "__FILE__", "__LINE__"); \
        raise(SIGABRT); \
        _exit(3); \
    }
#define OPENSSL_free wolfSSL_OPENSSL_free
#define OPENSSL_hexchar2int wolfSSL_OPENSSL_hexchar2int
#define OPENSSL_hexstr2buf wolfSSL_OPENSSL_hexstr2buf
#define OPENSSL_init_crypto wolfSSL_OPENSSL_init_crypto
#define OPENSSL_malloc wolfSSL_OPENSSL_malloc
#define OpenSSL_version_num wolfSSL_OpenSSL_version_num
    #define SSLEAY_VERSION 0x10001000L
#define SSLEAY_VERSION_NUMBER SSLEAY_VERSION
#define SSLeay wolfSSLeay
#define SSLeay_version wolfSSLeay_version

#define crypto_threadid_st          WOLFSSL_CRYPTO_THREADID
#define CONF_modules_load               wolfSSL_CONF_modules_load
#define NCONF_free                      wolfSSL_NCONF_free
#define NCONF_get_number                wolfSSL_NCONF_get_number
#define NCONF_get_section               wolfSSL_NCONF_get_section
#define NCONF_get_string                wolfSSL_NCONF_get_string
#define NCONF_load                      wolfSSL_NCONF_load
#define NCONF_new                       wolfSSL_NCONF_new

#define X509V3_EXT_nconf                wolfSSL_X509V3_EXT_nconf
#define X509V3_EXT_nconf_nid            wolfSSL_X509V3_EXT_nconf_nid
#define X509V3_conf_free                wolfSSL_X509V3_conf_free
#define _CONF_get_section               wolfSSL_CONF_get_section
#define _CONF_new_section               wolfSSL_CONF_new_section
#define lh_CONF_VALUE_insert            wolfSSL_sk_CONF_VALUE_push
#define lh_CONF_VALUE_retrieve          wolfSSL_lh_WOLFSSL_CONF_VALUE_retrieve
#define sk_CONF_VALUE_free              wolfSSL_sk_CONF_VALUE_free
#define sk_CONF_VALUE_new               wolfSSL_sk_CONF_VALUE_new
#define sk_CONF_VALUE_num               wolfSSL_sk_CONF_VALUE_num
#define sk_CONF_VALUE_pop_free(a,b)     wolfSSL_sk_CONF_VALUE_free(a)
#define sk_CONF_VALUE_value             wolfSSL_sk_CONF_VALUE_value
#define LIBWOLFSSL_VERSION_HEX 0x04008001
#define LIBWOLFSSL_VERSION_STRING "4.8.1"


        #define AES_MAX_KEY_SIZE    256




      #define CHAR_BIT 8



        #define CUSTOM_RAND_GENERATE Math_Rand
        #define CUSTOM_RAND_TYPE     RAND_NBR


            #define ECC_MIN_KEY_SZ 192




    #define EXIT_FAILURE 1
    #define FLASH_QUALIFIER __flash
            #define FP_MAX_BITS 8192

    #define FREERTOS_EADDRINUSE ( -6 )
    #define FREERTOS_EADDRNOTAVAIL ( -5 )
    #define FREERTOS_EINVAL ( -4 )
    #define FREERTOS_ENOBUFS ( -7 )
    #define FREERTOS_ENOPROTOOPT ( -8 )
    #define FREERTOS_EWOULDBLOCK ( -2 )
    #define FREERTOS_SOCKET_ERROR ( -1 )




































































    #define IO_SEEK_END  SEEK_END
    #define IO_SEEK_SET  SEEK_SET
#define ITRON_POOL_SIZE 1024*20





        #define LTC_BASE LTC0
                    #define LTC_MAX_ECC_BITS (384)
                #define LTC_MAX_INT_BYTES   (256*2)

    #define MAX_EX_DATA 5  
    #define MIN_FFDHE_FP_MAX_BITS 16384
    #define MQX_FILE_PTR FILE *
            #define NO_AES_192 

    #define NO_ASN_TIME 



































            #define PS_INT_BITS MIN_FFDHE_FP_MAX_BITS / 2
            #define RNGA_INSTANCE (0)





        #define SIZEOF_LONG 4
        #define SIZEOF_LONG_LONG 8
            #define SP_INT_BITS 4096
    #define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
    #define SSL_OP_NO_COMPRESSION    SSL_OP_NO_COMPRESSION

            #define STM32_HAL_TIMEOUT   0xFF











    #define TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY 560 
    #define TSIP_TLS_HMAC_KEY_INDEX_WORDSIZE 64
    #define TSIP_TLS_MASTERSECRET_SIZE       80   


    #define USE_CERT_BUFFERS_2048   







        #define WC_ASYNC_DEV_SIZE 168
        #define WC_RNG RNG








    #define WOLFSSL_ALERT_COUNT_MAX 5




    #define WOLFSSL_CRYPT_HW_MUTEX 1









        #define WOLFSSL_GENERAL_ALIGNMENT 16











    #define WOLFSSL_MIN_AUTH_TAG_SZ 12
        #define WOLFSSL_MMCAU_ALIGNMENT 4































    #define WOLFSSL_SMALL_STACK_STATIC static






        #define WOLFSSL_TEST_SUBROUTINE static





        #define XFREE(p, h, type)    vPortFree((p))
        #define XGEN_ALIGN __declspec(align(WOLFSSL_GENERAL_ALIGNMENT))
        #define XMALLOC(s, h, type)  pvPortMalloc((s))


        #define XMEMCMP(pmem_1, pmem_2, size)                   \
                   (((CPU_BOOLEAN)Mem_Cmp((void *)(pmem_1),     \
                                          (void *)(pmem_2),     \
                     (CPU_SIZE_T)(size))) ? DEF_NO : DEF_YES)
    #define XMEMCPY(pdest, psrc, size) ((void)Mem_Copy((void *)(pdest), \
                     (void *)(psrc), (CPU_SIZE_T)(size)))
    #define XMEMCPY_P(pdest, psrc, size) memcpy_P((pdest), (psrc), (size))
    #define XMEMMOVE XMEMCPY
    #define XMEMSET(pmem, data_val, size) \
                    ((void)Mem_Set((void *)(pmem), \
                    (CPU_INT08U) (data_val), \
                    (CPU_SIZE_T)(size)))
                #define XREALLOC(p, n, h, t) realloc((p), (n))
        #define XSNPRINTF snprintf

    #define XSTRLEN(pstr) ((CPU_SIZE_T)Str_Len((CPU_CHAR *)(pstr)))
        #define XSTRNCASECMP(s1,s2,n)  _strnicmp((s1),(s2),(n))
    #define XSTRNCAT(pstr_dest, pstr_cat, len_max) \
                    ((CPU_CHAR *)Str_Cat_N((CPU_CHAR *)(pstr_dest), \
                     (const CPU_CHAR *)(pstr_cat),(CPU_SIZE_T)(len_max)))
    #define XSTRNCMP(pstr_1, pstr_2, len_max) \
                    ((CPU_INT16S)Str_Cmp_N((CPU_CHAR *)(pstr_1), \
                     (CPU_CHAR *)(pstr_2), (CPU_SIZE_T)(len_max)))
    #define XSTRNCPY(pstr_dest, pstr_src, len_max) \
                    ((CPU_CHAR *)Str_Copy_N((CPU_CHAR *)(pstr_dest), \
                     (CPU_CHAR *)(pstr_src), (CPU_SIZE_T)(len_max)))
    #define XSTRNSTR(pstr, pstr_srch, len_max) \
                    ((CPU_CHAR *)Str_Str_N((CPU_CHAR *)(pstr), \
                     (CPU_CHAR *)(pstr_srch),(CPU_SIZE_T)(len_max)))
    #define XSTRSTR(pstr, pstr_srch) \
                    ((CPU_CHAR *)Str_Str((CPU_CHAR *)(pstr), \
                     (CPU_CHAR *)(pstr_srch)))
        #define XSTRTOK            strtok_r
        #define errno pico_err
    #define realloc   z_realloc
            #define WOLFSSL_API __declspec(dllexport)
        #define WOLFSSL_LOCAL __attribute__ ((visibility("hidden")))


            #define CYASSL_API extern __declspec(dllexport)
        #define CYASSL_LOCAL __attribute__ ((visibility("hidden")))
#define OPENSSL_VERSION                  0
     #define OPENSSL_VERSION_NUMBER 0x10100000L
#define OPENSSL_VERSION_TEXT             LIBWOLFSSL_VERSION_STRING

#define ASN1_SEQUENCE(type) \
    static type __##type##_dummy_struct;\
    static const WOLFSSL_ASN1_TEMPLATE type##_member_data[]
#define ASN1_SEQUENCE_END(type) \
    ; \
    const WOLFSSL_ASN1_ITEM type##_template_data = { \
            ASN_SEQUENCE, \
            type##_member_data, \
            sizeof(type##_member_data) / sizeof(WOLFSSL_ASN1_TEMPLATE), \
            sizeof(type) \
    };
#define ASN1_SIMPLE(type, member, member_type) \
    { (char*)&__##type##_dummy_struct.member - (char*)&__##type##_dummy_struct, \
        WOLFSSL_##member_type##_ASN1 }
# define ASN1_STRFLGS_DUMP_ALL           0x80
# define ASN1_STRFLGS_DUMP_DER           0x200
# define ASN1_STRFLGS_DUMP_UNKNOWN       0x100
# define ASN1_STRFLGS_ESC_2253           1
# define ASN1_STRFLGS_ESC_CTRL           2
# define ASN1_STRFLGS_ESC_MSB            4
# define ASN1_STRFLGS_ESC_QUOTE          8
# define ASN1_STRFLGS_IGNORE_TYPE        0x20
# define ASN1_STRFLGS_RFC2253            (ASN1_STRFLGS_ESC_2253 | \
                                          ASN1_STRFLGS_ESC_CTRL | \
                                          ASN1_STRFLGS_ESC_MSB | \
                                          ASN1_STRFLGS_UTF8_CONVERT | \
                                          ASN1_STRFLGS_DUMP_UNKNOWN | \
                                          ASN1_STRFLGS_DUMP_DER)
# define ASN1_STRFLGS_SHOW_TYPE          0x40
# define ASN1_STRFLGS_UTF8_CONVERT       0x10
#define ASN1_STRING_FLAG_BITS_LEFT       0x008
#define ASN1_STRING_FLAG_CONT            0x020
#define ASN1_STRING_FLAG_EMBED           0x080
#define ASN1_STRING_FLAG_MSTRING         0x040
#define ASN1_STRING_FLAG_NDEF            0x010
#define ASN1_STRING_free     wolfSSL_ASN1_STRING_free
#define ASN1_STRING_new      wolfSSL_ASN1_STRING_new
#define ASN1_STRING_set      wolfSSL_ASN1_STRING_set
#define ASN1_STRING_type     wolfSSL_ASN1_STRING_type
#define ASN1_STRING_type_new wolfSSL_ASN1_STRING_type_new
#define ASN1_TIME_check                 wolfSSL_ASN1_TIME_check
#define ASN1_TIME_diff                  wolfSSL_ASN1_TIME_diff
#define ASN1_TIME_set                   wolfSSL_ASN1_TIME_set
#define ASN1_TYPE_set               wolfSSL_ASN1_TYPE_set
#define ASN1_UTCTIME_print              wolfSSL_ASN1_UTCTIME_print
#define ASN1_get_object      wolfSSL_ASN1_get_object
#define BN_to_ASN1_INTEGER          wolfSSL_BN_to_ASN1_INTEGER
#define IMPLEMENT_ASN1_FUNCTIONS(type) \
    type *type##_new(void); \
    type *type##_new(void){ \
        return (type*)wolfSSL_ASN1_item_new(&type##_template_data); \
    } \
    void type##_free(type *t); \
    void type##_free(type *t){ \
        wolfSSL_ASN1_item_free(t, &type##_template_data); \
    } \
    int i2d_##type(type *src, byte **dest); \
    int i2d_##type(type *src, byte **dest) \
    { \
        return wolfSSL_ASN1_item_i2d(src, dest, &type##_template_data);\
    }
#define MBSTRING_ASC                     0x1001
#define MBSTRING_BMP                     0x1002
#define MBSTRING_UNIV                    0x1004
#define MBSTRING_UTF8                    0x1000
#define V_ASN1_BMPSTRING                30
#define V_ASN1_CONSTRUCTED              0x20
#define V_ASN1_EOC                      0
#define V_ASN1_GENERALIZEDTIME          24
#define V_ASN1_IA5STRING                22
#define V_ASN1_INTEGER                   0x02
#define V_ASN1_NEG                       0x100
#define V_ASN1_NEG_ENUMERATED            (10 | V_ASN1_NEG)
#define V_ASN1_NEG_INTEGER               (2 | V_ASN1_NEG)
#define V_ASN1_OBJECT                   6
#define V_ASN1_OCTET_STRING              0x04 
#define V_ASN1_PRINTABLESTRING          19
#define V_ASN1_SEQUENCE                 16
#define V_ASN1_SET                      17
#define V_ASN1_T61STRING                20
#define V_ASN1_UNIVERSALSTRING          28
#define V_ASN1_UTCTIME                  23
#define V_ASN1_UTF8STRING               12

#define c2i_ASN1_OBJECT      wolfSSL_c2i_ASN1_OBJECT
#define d2i_ASN1_OBJECT      wolfSSL_d2i_ASN1_OBJECT
#define ACCESS_DESCRIPTION_free         wolfSSL_ACCESS_DESCRIPTION_free
#define ASN1_BIT_STRING_free            wolfSSL_ASN1_BIT_STRING_free
#define ASN1_BIT_STRING_get_bit         wolfSSL_ASN1_BIT_STRING_get_bit
#define ASN1_BIT_STRING_new             wolfSSL_ASN1_BIT_STRING_new
#define ASN1_BIT_STRING_set_bit         wolfSSL_ASN1_BIT_STRING_set_bit
    #define ASN1_BOOLEAN                WOLFSSL_ASN1_BOOLEAN
#define ASN1_GENERALIZEDTIME WOLFSSL_ASN1_TIME
#define ASN1_GENERALIZEDTIME_free       wolfSSL_ASN1_GENERALIZEDTIME_free
#define ASN1_GENERALIZEDTIME_print      wolfSSL_ASN1_GENERALIZEDTIME_print
#define ASN1_IA5STRING                  WOLFSSL_ASN1_STRING
#define ASN1_INTEGER_cmp                wolfSSL_ASN1_INTEGER_cmp
#define ASN1_INTEGER_free               wolfSSL_ASN1_INTEGER_free
#define ASN1_INTEGER_get                wolfSSL_ASN1_INTEGER_get
#define ASN1_INTEGER_new                wolfSSL_ASN1_INTEGER_new
#define ASN1_INTEGER_set                wolfSSL_ASN1_INTEGER_set
#define ASN1_INTEGER_to_BN              wolfSSL_ASN1_INTEGER_to_BN
#define ASN1_OCTET_STRING               WOLFSSL_ASN1_STRING
#define ASN1_OCTET_STRING_free          wolfSSL_ASN1_STRING_free
#define ASN1_PRINTABLE_type(...)        V_ASN1_PRINTABLESTRING
#define ASN1_STRING_cmp                 wolfSSL_ASN1_STRING_cmp
#define ASN1_STRING_data                wolfSSL_ASN1_STRING_data
#define ASN1_STRING_get0_data           wolfSSL_ASN1_STRING_get0_data
#define ASN1_STRING_length              wolfSSL_ASN1_STRING_length
#define ASN1_STRING_print(x, y)         wolfSSL_ASN1_STRING_print ((WOLFSSL_BIO*)(x), (WOLFSSL_ASN1_STRING*)(y))
#define ASN1_STRING_print_ex            wolfSSL_ASN1_STRING_print_ex
#define ASN1_STRING_set_default_mask_asc(...) 1
#define ASN1_STRING_to_UTF8             wolfSSL_ASN1_STRING_to_UTF8
#define ASN1_TIME_adj                   wolfSSL_ASN1_TIME_adj
#define ASN1_TIME_free                  wolfSSL_ASN1_TIME_free
#define ASN1_TIME_new                   wolfSSL_ASN1_TIME_new
#define ASN1_TIME_print                 wolfSSL_ASN1_TIME_print
#define ASN1_TIME_set_string            wolfSSL_ASN1_TIME_set_string
#define ASN1_TIME_to_generalizedtime    wolfSSL_ASN1_TIME_to_generalizedtime
#define ASN1_TIME_to_string             wolfSSL_ASN1_TIME_to_string
#define ASN1_UNIVERSALSTRING_to_string  wolfSSL_ASN1_UNIVERSALSTRING_to_string
#define ASN1_UTCTIME         WOLFSSL_ASN1_TIME
#define ASN1_UTCTIME_free               wolfSSL_ASN1_TIME_free
#define ASN1_UTCTIME_new                wolfSSL_ASN1_TIME_new
#define ASN1_UTCTIME_pr                 wolfSSL_ASN1_UTCTIME_pr
#define ASN1_tag2str                    wolfSSL_ASN1_tag2str
#define AUTHORITY_INFO_ACCESS_free      wolfSSL_AUTHORITY_INFO_ACCESS_free
#define BIO_do_connect                  wolfSSL_BIO_do_connect
#define BIO_do_handshake                wolfSSL_BIO_do_handshake
#define BIO_eof                         wolfSSL_BIO_eof
#define BIO_f_base64                    wolfSSL_BIO_f_base64
#define BIO_f_buffer                    wolfSSL_BIO_f_buffer
#define BIO_f_md                        wolfSSL_BIO_f_md
#define BIO_f_ssl                       wolfSSL_BIO_f_ssl
#define BIO_flush                       wolfSSL_BIO_flush
#define BIO_free                        wolfSSL_BIO_free
#define BIO_free_all                    wolfSSL_BIO_free_all
#define BIO_get_md_ctx                  wolfSSL_BIO_get_md_ctx
#define BIO_get_mem_data                wolfSSL_BIO_get_mem_data
#define BIO_new                         wolfSSL_BIO_new
#define BIO_new_bio_pair                wolfSSL_BIO_new_bio_pair
#define BIO_new_connect                 wolfSSL_BIO_new_connect
#define BIO_new_mem_buf                 wolfSSL_BIO_new_mem_buf
#define BIO_new_socket                  wolfSSL_BIO_new_socket
#define BIO_nread                       wolfSSL_BIO_nread
#define BIO_nread0                      wolfSSL_BIO_nread0
#define BIO_nwrite                      wolfSSL_BIO_nwrite
#define BIO_nwrite0                     wolfSSL_BIO_nwrite0
#define BIO_pending                     wolfSSL_BIO_pending
#define BIO_pop                         wolfSSL_BIO_pop
#define BIO_prf                         wolfSSL_BIO_prf
#define BIO_push                        wolfSSL_BIO_push
#define BIO_read                        wolfSSL_BIO_read
#define BIO_read_filename               wolfSSL_BIO_read_filename
#define BIO_s_mem                       wolfSSL_BIO_s_mem
#define BIO_set_conn_port               wolfSSL_BIO_set_conn_port
#define BIO_set_flags                   wolfSSL_BIO_set_flags
#define BIO_set_nbio                    wolfSSL_BIO_set_nbio
#define BIO_set_ss                      wolfSSL_BIO_set_ss
#define BIO_set_ssl                     wolfSSL_BIO_set_ssl
#define BIO_set_write_buffer_size       wolfSSL_BIO_set_write_buffer_size
#define BIO_vfree                       wolfSSL_BIO_vfree
#define BIO_write                       wolfSSL_BIO_write
#define COMP_rle                        wolfSSL_COMP_rle
#define COMP_zlib                       wolfSSL_COMP_zlib
#define CONF_get1_default_config_file   wolfSSL_CONF_get1_default_config_file


#define CRYPTO_EX_DATA                  WOLFSSL_CRYPTO_EX_DATA
#define CRYPTO_EX_dup                   WOLFSSL_CRYPTO_EX_dup
#define CRYPTO_EX_free                  WOLFSSL_CRYPTO_EX_free
#define CRYPTO_EX_new                   WOLFSSL_CRYPTO_EX_new
#define CRYPTO_LOCK             0x01
#define CRYPTO_READ             0x04
#define CRYPTO_UNLOCK           0x02
#define CRYPTO_WRITE            0x08
#define CRYPTO_cleanup_all_ex_data      wolfSSL_cleanup_all_ex_data
#define CRYPTO_dynlock_value            WOLFSSL_dynlock_value
#define CRYPTO_free                     wolfSSL_CRYPTO_free
#define CRYPTO_get_ex_new_index         wolfSSL_CRYPTO_get_ex_new_index
#define CRYPTO_malloc                   wolfSSL_CRYPTO_malloc
#define CRYPTO_memcmp                   wolfSSL_CRYPTO_memcmp
#define CRYPTO_num_locks                wolfSSL_num_locks
#define CRYPTO_set_dynlock_create_callback  wolfSSL_set_dynlock_create_callback
#define CRYPTO_set_dynlock_destroy_callback wolfSSL_set_dynlock_destroy_callback
#define CRYPTO_set_dynlock_lock_callback wolfSSL_set_dynlock_lock_callback
#define CRYPTO_set_id_callback          wolfSSL_set_id_callback
#define CRYPTO_set_locking_callback     wolfSSL_set_locking_callback
#define CRYPTO_thread_id                wolfSSL_thread_id
#define DHparams_dup                    wolfSSL_DH_dup
#define DSA_bits                        wolfSSL_DSA_bits
#define DSA_dup_DH                      wolfSSL_DSA_dup_DH
#define DTLS1_2_VERSION                  0xFEFD
#define DTLS1_VERSION                    0xFEFF
#define DTLS_MAX_VERSION                 DTLS1_2_VERSION
    #define DTLS_method                 wolfDTLS_method
    #define DTLSv1_2_client_method      wolfDTLSv1_2_client_method
    #define DTLSv1_2_server_method      wolfDTLSv1_2_server_method
    #define DTLSv1_client_method        wolfDTLSv1_client_method
#define DTLSv1_get_timeout(ssl, timeleft)   wolfSSL_DTLSv1_get_timeout((ssl), (WOLFSSL_TIMEVAL*)(timeleft))
#define DTLSv1_handle_timeout               wolfSSL_DTLSv1_handle_timeout
    #define DTLSv1_server_method        wolfDTLSv1_server_method
#define DTLSv1_set_initial_timeout_duration wolfSSL_DTLSv1_set_initial_timeout_duration

#define ERR_GET_FUNC(l) (int)((((unsigned long)l) >> 12L) & 0xfffL)
#define ERR_GET_LIB                     wolfSSL_ERR_GET_LIB
#define ERR_GET_REASON                  wolfSSL_ERR_GET_REASON
#define ERR_LIB_ASN1            12
#define ERR_LIB_EVP             11
#define ERR_LIB_PEM             9
#define ERR_LIB_SSL          20
#define ERR_LIB_X509            10
#define ERR_NUM_ERRORS                  16
#define ERR_R_PEM_LIB        9
#define ERR_clear_error                 wolfSSL_ERR_clear_error
#define ERR_error_string                wolfSSL_ERR_error_string
#define ERR_error_string_n              wolfSSL_ERR_error_string_n
#define ERR_free_strings                wolfSSL_ERR_free_strings
#define ERR_func_error_string           wolfSSL_ERR_func_error_string
#define ERR_get_error                   wolfSSL_ERR_get_error
#define ERR_get_error_line              wolfSSL_ERR_get_error_line
#define ERR_get_error_line_data         wolfSSL_ERR_get_error_line_data
#define ERR_load_BIO_strings            wolfSSL_ERR_load_BIO_strings
#define ERR_peek_error                  wolfSSL_ERR_peek_error
#define ERR_peek_error_line_data        wolfSSL_ERR_peek_error_line_data
#define ERR_peek_errors_fp              wolfSSL_ERR_peek_errors_fp
#define ERR_peek_last_error             wolfSSL_ERR_peek_last_error
#define ERR_peek_last_error_line        wolfSSL_ERR_peek_last_error_line
#define ERR_print_errors                wolfSSL_ERR_print_errors
#define ERR_print_errors_cb             wolfSSL_ERR_print_errors_cb
#define ERR_print_errors_fp(file)       wolfSSL_ERR_dump_errors_fp((file))
#define ERR_put_error                   wolfSSL_ERR_put_error
#define ERR_reason_error_string         wolfSSL_ERR_reason_error_string
#define ERR_remove_state                wolfSSL_ERR_remove_state
#define ERR_remove_thread_state         wolfSSL_ERR_remove_thread_state
#define EVP_CIPHER_INFO        EncryptedInfo
#define EVP_PKEY_CTX_free               wolfSSL_EVP_PKEY_CTX_free
#define EVP_PKEY_get0_DSA               wolfSSL_EVP_PKEY_get0_DSA
#define EVP_PKEY_param_check            wolfSSL_EVP_PKEY_param_check
#define EVPerr(func, reason)            wolfSSL_ERR_put_error(ERR_LIB_EVP, \
                                        (func), (reason), "__FILE__", "__LINE__")
#define GENERAL_NAMES_free              wolfSSL_GENERAL_NAMES_free
#define GENERAL_NAME_free               wolfSSL_GENERAL_NAME_free
#define GENERAL_NAME_new                wolfSSL_GENERAL_NAME_new
#define LN_pkcs9_emailAddress           "emailAddress"
#define MD4_Final                       wolfSSL_MD4_Final
#define MD4_Init                        wolfSSL_MD4_Init
#define MD4_Update                      wolfSSL_MD4_Update
#define NID_pkcs9_emailAddress          48

#define OBJ_pkcs9_emailAddress          1L,2L,840L,113539L,1L,9L,1L
#define OCSP_parse_url                  wolfSSL_OCSP_parse_url
#define OPENSSL_CSTRING   WOLFSSL_STRING
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L
#define OPENSSL_INIT_LOAD_SSL_STRINGS    0x00200000L
#define OPENSSL_NPN_NEGOTIATED  1
#define OPENSSL_NPN_NO_OVERLAP  2
#define OPENSSL_NPN_UNSUPPORTED 0
#define OPENSSL_STACK WOLFSSL_STACK
#define OPENSSL_STRING    WOLFSSL_STRING
#define OPENSSL_cleanse                 wolfSSL_OPENSSL_cleanse
#define OPENSSL_config	                wolfSSL_OPENSSL_config
#define OPENSSL_init_ssl                wolfSSL_OPENSSL_init_ssl
#define OPENSSL_malloc_init() 0 
#define OPENSSL_memdup                  wolfSSL_OPENSSL_memdup
#define OPENSSL_sk_num                  wolfSSL_sk_num
#define OPENSSL_sk_value                wolfSSL_sk_value
#define OpenSSL_add_ssl_algorithms      wolfSSL_library_init
#define OpenSSL_version(x)              wolfSSL_OpenSSL_version(x)
#define PEM_F_PEM_DEF_CALLBACK  100
#define PEM_R_BAD_DECRYPT               (-MIN_CODE_E + 4)
#define PEM_R_BAD_PASSWORD_READ         (-MIN_CODE_E + 3)
#define PEM_R_NO_START_LINE             (-MIN_CODE_E + 1)
#define PEM_R_PROBLEMS_GETTING_PASSWORD (-MIN_CODE_E + 2)
#define PEM_X509_INFO_read_bio          wolfSSL_PEM_X509_INFO_read_bio
#define PEM_def_callback                wolfSSL_PEM_def_callback
#define PEM_do_header                   wolfSSL_PEM_do_header
#define PEM_get_EVP_CIPHER_INFO         wolfSSL_PEM_get_EVP_CIPHER_INFO
#define PEM_read                        wolfSSL_PEM_read
#define PEM_read_X509                   wolfSSL_PEM_read_X509
#define PEM_read_X509_CRL               wolfSSL_PEM_read_X509_CRL
#define PEM_read_bio_DHparams           wolfSSL_PEM_read_bio_DHparams
#define PEM_read_bio_DSAparams          wolfSSL_PEM_read_bio_DSAparams
#define PEM_read_bio_X509               wolfSSL_PEM_read_bio_X509
#define PEM_read_bio_X509_AUX           wolfSSL_PEM_read_bio_X509_AUX
#define PEM_read_bio_X509_CRL           wolfSSL_PEM_read_bio_X509_CRL
#define PEM_read_bio_X509_REQ           wolfSSL_PEM_read_bio_X509_REQ
#define PEM_write                       wolfSSL_PEM_write
#define PEM_write_bio_X509              wolfSSL_PEM_write_bio_X509
#define PEM_write_bio_X509_AUX          wolfSSL_PEM_write_bio_X509_AUX
#define PEM_write_bio_X509_REQ          wolfSSL_PEM_write_bio_X509_REQ
#define PEMerr(func, reason)            wolfSSL_ERR_put_error(ERR_LIB_PEM, \
                                        (func), (reason), "__FILE__", "__LINE__")
#define PKCS8_PRIV_KEY_INFO_free        wolfSSL_EVP_PKEY_free
#define PSK_MAX_IDENTITY_LEN            128
#define PSK_MAX_PSK_LEN                 256
#define RAND_add                        wolfSSL_RAND_add
#define RAND_bytes                      wolfSSL_RAND_bytes
#define RAND_cleanup                    wolfSSL_RAND_Cleanup
#define RAND_egd                        wolfSSL_RAND_egd
#define RAND_file_name                  wolfSSL_RAND_file_name
#define RAND_load_file                  wolfSSL_RAND_load_file
#define RAND_poll                       wolfSSL_RAND_poll
#define RAND_pseudo_bytes               wolfSSL_RAND_pseudo_bytes
#define RAND_screen                     wolfSSL_RAND_screen
#define RAND_seed                       wolfSSL_RAND_seed
#define RAND_status                     wolfSSL_RAND_status
#define RAND_write_file                 wolfSSL_RAND_write_file
#define RSA_bits                        wolfSSL_RSA_bits
#define RSA_free                        wolfSSL_RSA_free
#define RSA_generate_key                wolfSSL_RSA_generate_key
#define RSA_get_ex_new_index            wolfSSL_get_ex_new_index
#define RSA_padding_add_PKCS1_PSS       wolfSSL_RSA_padding_add_PKCS1_PSS
#define RSA_print                       wolfSSL_RSA_print
#define RSA_up_ref                      wolfSSL_RSA_up_ref
#define RSA_verify_PKCS1_PSS            wolfSSL_RSA_verify_PKCS1_PSS
#define SHA1                            wolfSSL_SHA1
#define SN_pkcs9_emailAddress           "Email"
#define SSL23_ST_SR_CLNT_HELLO_A        (0x210|0x2000)
#define SSL2_VERSION                     0x0002
#define SSL3_AD_BAD_CERTIFICATE          bad_certificate
#define SSL3_AL_FATAL                   2
#define SSL3_RANDOM_SIZE                32 
#define SSL3_ST_SR_CLNT_HELLO_A         (0x110|0x2000)
#define SSL3_VERSION                     0x0300
#define SSL_AD_BAD_CERTIFICATE           SSL3_AD_BAD_CERTIFICATE
#define SSL_AD_INTERNAL_ERROR            80
#define SSL_AD_NO_RENEGOTIATION          no_renegotiation
#define SSL_AD_UNRECOGNIZED_NAME         unrecognized_name
#define SSL_CIPHER_description          wolfSSL_CIPHER_description
#define SSL_CIPHER_get_bits             wolfSSL_CIPHER_get_bits
#define SSL_CIPHER_get_id               wolfSSL_CIPHER_get_id
#define SSL_CIPHER_get_name             wolfSSL_CIPHER_get_name
#define SSL_CIPHER_get_rfc_name         wolfSSL_CIPHER_get_name
#define SSL_CIPHER_get_version          wolfSSL_CIPHER_get_version
#define SSL_CIPHER_standard_name        wolfSSL_CIPHER_get_name
#define SSL_COMP_add_compression_method wolfSSL_COMP_add_compression_method
#define SSL_CONF_CTX_finish             wolfSSL_CONF_CTX_finish
#define SSL_CONF_CTX_free               wolfSSL_CONF_CTX_free
#define SSL_CONF_CTX_new                wolfSSL_CONF_CTX_new
#define SSL_CONF_CTX_set_flags          wolfSSL_CONF_CTX_set_flags
#define SSL_CONF_CTX_set_ssl_ctx        wolfSSL_CONF_CTX_set_ssl_ctx
#define SSL_CONF_FLAG_CERTIFICATE        WOLFSSL_CONF_FLAG_CERTIFICATE
#define SSL_CONF_FLAG_CMDLINE            WOLFSSL_CONF_FLAG_CMDLINE
#define SSL_CONF_FLAG_FILE               WOLFSSL_CONF_FLAG_FILE
#define SSL_CONF_TYPE_FILE               WOLFSSL_CONF_TYPE_FILE
#define SSL_CONF_TYPE_STRING             WOLFSSL_CONF_TYPE_STRING
#define SSL_CONF_cmd                    wolfSSL_CONF_cmd
#define SSL_CTRL_CHAIN       88
#define SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS        83
#define SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS         11
#define SSL_CTRL_EXTRA_CHAIN_CERT               14
#define SSL_CTRL_GET_EXTRA_CHAIN_CERTS          82
#define SSL_CTRL_GET_PEER_TMP_KEY                 109
#define SSL_CTRL_GET_READ_AHEAD                 40
#define SSL_CTRL_GET_SERVER_TMP_KEY               SSL_CTRL_GET_PEER_TMP_KEY
#define SSL_CTRL_GET_SESSION_REUSED             0
#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS       66
#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS        68
#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP  70
#define SSL_CTRL_GET_TOTAL_RENEGOTIATIONS         12
#define SSL_CTRL_MODE        33
#define SSL_CTRL_OPTIONS                        32
#define SSL_CTRL_SET_CURVES                       SSL_CTRL_SET_GROUPS
#define SSL_CTRL_SET_GROUPS                       91
#define SSL_CTRL_SET_MAX_PROTO_VERSION            124
#define SSL_CTRL_SET_MIN_PROTO_VERSION            123
#define SSL_CTRL_SET_READ_AHEAD                 41
#define SSL_CTRL_SET_SESS_CACHE_MODE              44
#define SSL_CTRL_SET_SESS_CACHE_SIZE            42
#define SSL_CTRL_SET_TLSEXT_DEBUG_ARG             57
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB       63
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG   64
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS       67
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS        69
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP  71
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE       65
#define SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB 72
#define SSL_CTRL_SET_TMP_DH                       3
#define SSL_CTRL_SET_TMP_ECDH                     4
#define SSL_CTX_add1_chain_cert         wolfSSL_CTX_add1_chain_cert
#define SSL_CTX_add_client_CA           wolfSSL_CTX_add_client_CA
#define SSL_CTX_add_extra_chain_cert    wolfSSL_CTX_add_extra_chain_cert
#define SSL_CTX_add_server_custom_ext(...) 0
#define SSL_CTX_add_session             wolfSSL_CTX_add_session
#define SSL_CTX_callback_ctrl           wolfSSL_CTX_callback_ctrl
#define SSL_CTX_check_private_key       wolfSSL_CTX_check_private_key
#define SSL_CTX_clear_chain_certs(ctx) SSL_CTX_set0_chain(ctx,NULL)
#define SSL_CTX_clear_extra_chain_certs wolfSSL_CTX_clear_extra_chain_certs
#define SSL_CTX_clear_options           wolfSSL_CTX_clear_options
#define SSL_CTX_ctrl                    wolfSSL_CTX_ctrl
#define SSL_CTX_flush_sessions          wolfSSL_flush_sessions
#define SSL_CTX_free                    wolfSSL_CTX_free
#define SSL_CTX_get0_certificate        wolfSSL_CTX_get0_certificate
#define SSL_CTX_get0_param              wolfSSL_CTX_get0_param
#define SSL_CTX_get0_privatekey         wolfSSL_CTX_get0_privatekey
#define SSL_CTX_get_app_data(ctx)       wolfSSL_CTX_get_ex_data(ctx,0)
#define SSL_CTX_get_cert_store(x)       wolfSSL_CTX_get_cert_store ((WOLFSSL_CTX*) (x))
#define SSL_CTX_get_client_CA_list      wolfSSL_CTX_get_client_CA_list
#define SSL_CTX_get_default_passwd_cb   wolfSSL_CTX_get_default_passwd_cb
#define SSL_CTX_get_default_passwd_cb_userdata wolfSSL_CTX_get_default_passwd_cb_userdata
#define SSL_CTX_get_ex_data             wolfSSL_CTX_get_ex_data
#define SSL_CTX_get_ex_new_index        wolfSSL_CTX_get_ex_new_index
#define SSL_CTX_get_extra_chain_certs   wolfSSL_CTX_get_extra_chain_certs
#define SSL_CTX_get_keylog_callback     wolfSSL_CTX_get_keylog_callback
#define SSL_CTX_get_min_proto_version   wolfSSL_CTX_get_min_proto_version
#define SSL_CTX_get_mode                wolfSSL_CTX_get_mode
#define SSL_CTX_get_options             wolfSSL_CTX_get_options
#define SSL_CTX_get_read_ahead          wolfSSL_CTX_get_read_ahead
#define SSL_CTX_get_security_level      wolfSSL_CTX_get_security_level
#define SSL_CTX_get_session_cache_mode(ctx) 0
#define SSL_CTX_get_timeout             wolfSSL_SSL_CTX_get_timeout
#define SSL_CTX_get_tlsext_status_cb    wolfSSL_CTX_get_tlsext_status_cb
#define SSL_CTX_get_tlsext_ticket_keys  wolfSSL_CTX_get_tlsext_ticket_keys
#define SSL_CTX_get_verify_callback     wolfSSL_CTX_get_verify_callback
#define SSL_CTX_get_verify_depth        wolfSSL_CTX_get_verify_depth
#define SSL_CTX_get_verify_mode         wolfSSL_CTX_get_verify_mode
#define SSL_CTX_keylog_cb_func          wolfSSL_CTX_keylog_cb_func
    #define SSL_CTX_load_verify_locations     wolfSSL_CTX_load_verify_locations
#define SSL_CTX_need_tmp_RSA(ctx)       0
#define SSL_CTX_new(method)             wolfSSL_CTX_new((WOLFSSL_METHOD*)(method))
#define SSL_CTX_remove_session          wolfSSL_SSL_CTX_remove_session
#define SSL_CTX_sess_accept             wolfSSL_CTX_sess_accept
#define SSL_CTX_sess_accept_good        wolfSSL_CTX_sess_accept_good
#define SSL_CTX_sess_accept_renegotiate wolfSSL_CTX_sess_accept_renegotiate
#define SSL_CTX_sess_cache_full         wolfSSL_CTX_sess_cache_full
#define SSL_CTX_sess_cb_hits            wolfSSL_CTX_sess_cb_hits
#define SSL_CTX_sess_connect            wolfSSL_CTX_sess_connect
#define SSL_CTX_sess_connect_good       wolfSSL_CTX_sess_connect_good
#define SSL_CTX_sess_connect_renegotiate wolfSSL_CTX_sess_connect_renegotiate
#define SSL_CTX_sess_get_cache_size     wolfSSL_CTX_sess_get_cache_size
#define SSL_CTX_sess_hits               wolfSSL_CTX_sess_hits
#define SSL_CTX_sess_misses             wolfSSL_CTX_sess_misses
#define SSL_CTX_sess_number             wolfSSL_CTX_sess_number
#define SSL_CTX_sess_set_cache_size     wolfSSL_CTX_sess_set_cache_size
#define SSL_CTX_sess_set_get_cb         wolfSSL_CTX_sess_set_get_cb
#define SSL_CTX_sess_set_new_cb         wolfSSL_CTX_sess_set_new_cb
#define SSL_CTX_sess_set_remove_cb      wolfSSL_CTX_sess_set_remove_cb
#define SSL_CTX_sess_timeouts           wolfSSL_CTX_sess_timeouts
#define SSL_CTX_set0_chain(ctx,sk) \
                             wolfSSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)(sk))
#define SSL_CTX_set1_curves_list        wolfSSL_CTX_set1_curves_list
#define SSL_CTX_set1_groups             wolfSSL_CTX_set1_groups
#define SSL_CTX_set1_groups_list        wolfSSL_CTX_set1_groups_list
#define SSL_CTX_set1_param              wolfSSL_CTX_set1_param
#define SSL_CTX_set1_sigalgs_list       wolfSSL_CTX_set1_sigalgs_list
#define SSL_CTX_set_alpn_protos         wolfSSL_CTX_set_alpn_protos
#define SSL_CTX_set_alpn_select_cb      wolfSSL_CTX_set_alpn_select_cb
#define SSL_CTX_set_app_data(ctx,arg)   wolfSSL_CTX_set_ex_data(ctx,0, \
                                                                  (char *)(arg))
#define SSL_CTX_set_cert_store          wolfSSL_CTX_set_cert_store
#define SSL_CTX_set_cert_verify_callback wolfSSL_CTX_set_cert_verify_callback
#define SSL_CTX_set_cipher_list         wolfSSL_CTX_set_cipher_list
#define SSL_CTX_set_ciphersuites        wolfSSL_CTX_set_cipher_list
#define SSL_CTX_set_client_CA_list      wolfSSL_CTX_set_client_CA_list
#define SSL_CTX_set_client_cert_cb      wolfSSL_CTX_set_client_cert_cb
#define SSL_CTX_set_current_time_cb(ssl, cb) ({ (void)ssl; (void)cb; })
#define SSL_CTX_set_default_passwd_cb   wolfSSL_CTX_set_default_passwd_cb
#define SSL_CTX_set_default_passwd_cb_userdata wolfSSL_CTX_set_default_passwd_cb_userdata
#define SSL_CTX_set_default_read_ahead  wolfSSL_CTX_set_default_read_ahead
#define SSL_CTX_set_default_verify_paths wolfSSL_CTX_set_default_verify_paths
#define SSL_CTX_set_ecdh_auto           wolfSSL_CTX_set_ecdh_auto
#define SSL_CTX_set_ex_data             wolfSSL_CTX_set_ex_data
#define SSL_CTX_set_info_callback       wolfSSL_CTX_set_info_callback
#define SSL_CTX_set_keylog_callback     wolfSSL_CTX_set_keylog_callback
#define SSL_CTX_set_max_proto_version   wolfSSL_CTX_set_max_proto_version
#define SSL_CTX_set_min_proto_version   wolfSSL_CTX_set_min_proto_version
#define SSL_CTX_set_mode                wolfSSL_CTX_set_mode
#define SSL_CTX_set_msg_callback        wolfSSL_CTX_set_msg_callback
#define SSL_CTX_set_msg_callback_arg    wolfSSL_CTX_set_msg_callback_arg
#define SSL_CTX_set_next_proto_select_cb wolfSSL_CTX_set_next_proto_select_cb
#define SSL_CTX_set_next_protos_advertised_cb  wolfSSL_CTX_set_next_protos_advertised_cb
#define SSL_CTX_set_options             wolfSSL_CTX_set_options
#define SSL_CTX_set_post_handshake_auth wolfSSL_CTX_set_post_handshake_auth
#define SSL_CTX_set_psk_client_callback wolfSSL_CTX_set_psk_client_callback
#define SSL_CTX_set_psk_server_callback wolfSSL_CTX_set_psk_server_callback
#define SSL_CTX_set_quiet_shutdown      wolfSSL_CTX_set_quiet_shutdown
#define SSL_CTX_set_read_ahead          wolfSSL_CTX_set_read_ahead
#define SSL_CTX_set_security_level      wolfSSL_CTX_set_security_level
#define SSL_CTX_set_session_cache_mode  wolfSSL_CTX_set_session_cache_mode
#define SSL_CTX_set_session_id_context  wolfSSL_CTX_set_session_id_context
#define SSL_CTX_set_srp_password        wolfSSL_CTX_set_srp_password
#define SSL_CTX_set_srp_strength        wolfSSL_CTX_set_srp_strength
#define SSL_CTX_set_srp_username        wolfSSL_CTX_set_srp_username
#define SSL_CTX_set_timeout(ctx, to)    \
                                 wolfSSL_CTX_set_timeout(ctx, (unsigned int) to)
#define SSL_CTX_set_tlsext_opaque_prf_input_callback_arg \
                            wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg
#define SSL_CTX_set_tlsext_servername_arg wolfSSL_CTX_set_servername_arg
#define SSL_CTX_set_tlsext_servername_callback wolfSSL_CTX_set_tlsext_servername_callback
#define SSL_CTX_set_tlsext_status_arg   wolfSSL_CTX_set_tlsext_status_arg
#define SSL_CTX_set_tlsext_status_cb    wolfSSL_CTX_set_tlsext_status_cb
#define SSL_CTX_set_tlsext_ticket_key_cb wolfSSL_CTX_set_tlsext_ticket_key_cb
#define SSL_CTX_set_tlsext_ticket_keys  wolfSSL_CTX_set_tlsext_ticket_keys
#define SSL_CTX_set_tmp_dh              wolfSSL_CTX_set_tmp_dh
#define SSL_CTX_set_tmp_ecdh            wolfSSL_SSL_CTX_set_tmp_ecdh
#define SSL_CTX_set_tmp_rsa(ctx,rsa)    1
#define SSL_CTX_set_tmp_rsa_callback    wolfSSL_CTX_set_tmp_rsa_callback
#define SSL_CTX_set_verify              wolfSSL_CTX_set_verify
#define SSL_CTX_set_verify_depth        wolfSSL_CTX_set_verify_depth
#define SSL_CTX_up_ref                  wolfSSL_CTX_up_ref
#define SSL_CTX_use_PrivateKey          wolfSSL_CTX_use_PrivateKey
#define SSL_CTX_use_PrivateKey_ASN1     wolfSSL_CTX_use_PrivateKey_ASN1
    #define SSL_CTX_use_PrivateKey_file       wolfSSL_CTX_use_PrivateKey_file
#define SSL_CTX_use_RSAPrivateKey       wolfSSL_CTX_use_RSAPrivateKey
    #define SSL_CTX_use_RSAPrivateKey_file    wolfSSL_CTX_use_RSAPrivateKey_file
#define SSL_CTX_use_certificate         wolfSSL_CTX_use_certificate
#define SSL_CTX_use_certificate_ASN1    wolfSSL_CTX_use_certificate_ASN1
    #define SSL_CTX_use_certificate_chain_file wolfSSL_CTX_use_certificate_chain_file
    #define SSL_CTX_use_certificate_file      wolfSSL_CTX_use_certificate_file
#define SSL_CTX_use_psk_identity_hint   wolfSSL_CTX_use_psk_identity_hint
#define SSL_DEFAULT_CIPHER_LIST WOLFSSL_DEFAULT_CIPHER_LIST
#define SSL_MAX_MASTER_KEY_LENGTH       WOLFSSL_MAX_MASTER_KEY_LENGTH
    #define SSL_MODE_RELEASE_BUFFERS    0x00000010U
#define SSL_OP_NO_TICKET                  SSL_OP_NO_TICKET
#define SSL_R_BAD_CHANGE_CIPHER_SPEC               LENGTH_ERROR
#define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG            BUFFER_E
#define SSL_R_CERTIFICATE_VERIFY_FAILED            VERIFY_CERT_ERROR
#define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC  ENCRYPT_ERROR
#define SSL_R_DIGEST_CHECK_FAILED                  VERIFY_MAC_ERROR
#define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST        SUITES_ERROR
#define SSL_R_EXCESSIVE_MESSAGE_SIZE               BUFFER_ERROR
#define SSL_R_HTTPS_PROXY_REQUEST                  PARSE_ERROR
#define SSL_R_HTTP_REQUEST                         PARSE_ERROR
#define SSL_R_LENGTH_MISMATCH                      LENGTH_ERROR
#define SSL_R_NO_CIPHERS_SPECIFIED                 SUITES_ERROR
#define SSL_R_NO_COMPRESSION_SPECIFIED             COMPRESSION_ERROR
#define SSL_R_NO_SHARED_CIPHER                     MATCH_SUITE_ERROR
#define SSL_R_RECORD_LENGTH_MISMATCH               HANDSHAKE_SIZE_ERROR
#define SSL_R_SHORT_READ     10
#define SSL_R_UNEXPECTED_MESSAGE                   OUT_OF_ORDER_E
#define SSL_R_UNEXPECTED_RECORD                    SANITY_MSG_E
#define SSL_R_UNKNOWN_ALERT_TYPE                   BUFFER_ERROR
#define SSL_R_UNKNOWN_PROTOCOL                     VERSION_ERROR
#define SSL_R_UNSUPPORTED_PROTOCOL                 VERSION_ERROR
#define SSL_R_WRONG_VERSION_NUMBER                 VERSION_ERROR
#define SSL_SESSION_dup                 wolfSSL_SESSION_dup
#define SSL_SESSION_free                wolfSSL_SESSION_free
#define SSL_SESSION_get0_peer           wolfSSL_SESSION_get0_peer
#define SSL_SESSION_get_ex_data         wolfSSL_SESSION_get_ex_data
#define SSL_SESSION_get_ex_new_index    wolfSSL_SESSION_get_ex_new_index
#define SSL_SESSION_get_id              wolfSSL_SESSION_get_id
#define SSL_SESSION_get_master_key      wolfSSL_SESSION_get_master_key
#define SSL_SESSION_get_master_key_length wolfSSL_SESSION_get_master_key_length
#define SSL_SESSION_get_time            wolfSSL_SESSION_get_time
#define SSL_SESSION_get_timeout         wolfSSL_SESSION_get_timeout
#define SSL_SESSION_is_resumable    wolfSSL_SESSION_is_resumable
#define SSL_SESSION_print               wolfSSL_SESSION_print
#define SSL_SESSION_set_cipher          wolfSSL_SESSION_set_cipher
#define SSL_SESSION_set_ex_data         wolfSSL_SESSION_set_ex_data
#define SSL_SESSION_set_timeout         wolfSSL_SSL_SESSION_set_timeout
#define SSL_SESSION_up_ref              wolfSSL_SESSION_up_ref
#define SSL_TLSEXT_ERR_ALERT_FATAL      fatal_return
#define SSL_TLSEXT_ERR_ALERT_WARNING    warning_return
#define SSL_TLSEXT_ERR_NOACK            noack_return
#define SSL_TLSEXT_ERR_OK               0
#define SSL_accept                      wolfSSL_accept
#define SSL_alert_desc_string           wolfSSL_alert_desc_string
#define SSL_alert_desc_string_long      wolfSSL_alert_desc_string_long
#define SSL_alert_type_string           wolfSSL_alert_type_string
#define SSL_alert_type_string_long      wolfSSL_alert_type_string_long
#define SSL_check_private_key           wolfSSL_check_private_key
#define SSL_clear                       wolfSSL_clear
#define SSL_clear_num_renegotiations    wolfSSL_clear_num_renegotiations
#define SSL_clear_options               wolfSSL_clear_options
#define SSL_connect                     wolfSSL_connect
#define SSL_ctrl                        wolfSSL_ctrl
#define SSL_do_handshake                wolfSSL_SSL_do_handshake
#define SSL_dup_CA_list                 wolfSSL_dup_CA_list
#define SSL_export_keying_material      wolfSSL_export_keying_material
#define SSL_flush_sessions              wolfSSL_flush_sessions
#define SSL_free                        wolfSSL_free
#define SSL_get0_alpn_selected          wolfSSL_get0_alpn_selected
#define SSL_get0_next_proto_negotiated  wolfSSL_get0_next_proto_negotiated
#define SSL_get0_param                  wolfSSL_get0_param
#define SSL_get0_session                wolfSSL_SSL_get0_session
#define SSL_get1_session                wolfSSL_get1_session
#define SSL_get_SSL_CTX                 wolfSSL_get_SSL_CTX
#define SSL_get_app_data                wolfSSL_get_app_data
#define SSL_get_certificate             wolfSSL_get_certificate
#define SSL_get_cipher                  wolfSSL_get_cipher_name
#define SSL_get_cipher_bits(s,np)       \
                          wolfSSL_CIPHER_get_bits(SSL_get_current_cipher(s),np)
#define SSL_get_cipher_by_value         wolfSSL_get_cipher_by_value
#define SSL_get_cipher_list(ctx,i)         wolfSSL_get_cipher_list_ex((ctx),(i))
#define SSL_get_cipher_name(ctx)           wolfSSL_get_cipher((ctx))
#define SSL_get_ciphers(x)              wolfSSL_get_ciphers_compat(x)
#define SSL_get_client_CA_list          wolfSSL_get_client_CA_list
#define SSL_get_client_random(ssl,out,outSz) \
                                  wolfSSL_get_client_random((ssl),(out),(outSz))
#define SSL_get_current_cipher          wolfSSL_get_current_cipher
#define SSL_get_default_timeout(ctx)    500
#define SSL_get_early_data_status       wolfSSL_get_early_data_status
#define SSL_get_error                   wolfSSL_get_error
#define SSL_get_ex_data                 wolfSSL_get_ex_data
#define SSL_get_ex_data_X509_STORE_CTX_idx wolfSSL_get_ex_data_X509_STORE_CTX_idx
#define SSL_get_ex_new_index            wolfSSL_get_ex_new_index
#define SSL_get_fd                      wolfSSL_get_fd
#define SSL_get_finished                wolfSSL_get_finished
#define SSL_get_hit                     wolfSSL_session_reused
#define SSL_get_keyblock_size           wolfSSL_get_keyblock_size
#define SSL_get_keys                    wolfSSL_get_keys
#define SSL_get_options                 wolfSSL_get_options
#define SSL_get_peer_cert_chain         wolfSSL_get_peer_cert_chain
#define SSL_get_peer_certificate        wolfSSL_get_peer_certificate
#define SSL_get_peer_finished           wolfSSL_get_peer_finished
#define SSL_get_privatekey              wolfSSL_get_privatekey
#define SSL_get_psk_identity            wolfSSL_get_psk_identity
#define SSL_get_psk_identity_hint       wolfSSL_get_psk_identity_hint
#define SSL_get_rbio                    wolfSSL_SSL_get_rbio
#define SSL_get_secure_renegotiation_support wolfSSL_SSL_get_secure_renegotiation_support
#define SSL_get_server_random           wolfSSL_get_server_random
#define SSL_get_server_tmp_key          wolfSSL_get_server_tmp_key
#define SSL_get_servername              wolfSSL_get_servername
#define SSL_get_session(x)              wolfSSL_get_session((WOLFSSL*) (x))
#define SSL_get_shared_ciphers(ctx,buf,len) \
                                   wolfSSL_get_shared_ciphers((ctx),(buf),(len))
#define SSL_get_shutdown                wolfSSL_get_shutdown
#define SSL_get_signature_nid           wolfSSL_get_signature_nid
#define SSL_get_srp_username            wolfSSL_get_srp_username
#define SSL_get_state                   wolfSSL_get_state
#define SSL_get_tlsext_status_exts      wolfSSL_get_tlsext_status_exts
#define SSL_get_tlsext_status_ids       wolfSSL_get_tlsext_status_ids
#define SSL_get_tlsext_status_ocsp_res  wolfSSL_get_tlsext_status_ocsp_resp
#define SSL_get_tlsext_status_ocsp_resp  wolfSSL_get_tlsext_status_ocsp_resp
#define SSL_get_verify_callback         wolfSSL_get_verify_callback
#define SSL_get_verify_depth            wolfSSL_get_verify_depth
#define SSL_get_verify_mode             wolfSSL_get_verify_mode
#define SSL_get_verify_result           wolfSSL_get_verify_result
#define SSL_get_version                 wolfSSL_get_version
#define SSL_get_wbio                    wolfSSL_SSL_get_wbio
#define SSL_in_connect_init             wolfSSL_SSL_in_connect_init
#define SSL_in_init                     wolfSSL_SSL_in_init
#define SSL_is_init_finished            wolfSSL_is_init_finished
#define SSL_is_server                   wolfSSL_is_server
#define SSL_library_init                wolfSSL_library_init
#define SSL_load_client_CA_file         wolfSSL_load_client_CA_file
#define SSL_load_error_strings          wolfSSL_load_error_strings
#define SSL_need_tmp_RSA(ssl)           0
#define SSL_new                         wolfSSL_new
#define SSL_num_renegotiations          wolfSSL_num_renegotiations
#define SSL_peek                        wolfSSL_peek
#define SSL_pending                     wolfSSL_pending
#define SSL_read                        wolfSSL_read
#define SSL_renegotiate                 wolfSSL_Rehandshake
#define SSL_renegotiate_pending         wolfSSL_SSL_renegotiate_pending
#define SSL_select_next_proto           wolfSSL_select_next_proto
#define SSL_session_reused              wolfSSL_session_reused
#define SSL_set1_curves_list            wolfSSL_set1_curves_list
#define SSL_set1_groups                 wolfSSL_set1_groups
#define SSL_set1_groups_list            wolfSSL_set1_groups_list
#define SSL_set1_sigalgs_list           wolfSSL_set1_sigalgs_list
#define SSL_set_SSL_CTX                 wolfSSL_set_SSL_CTX
#define SSL_set_accept_state            wolfSSL_set_accept_state
#define SSL_set_alpn_protos             wolfSSL_set_alpn_protos
#define SSL_set_app_data                wolfSSL_set_app_data
#define SSL_set_bio                     wolfSSL_set_bio
#define SSL_set_cipher_list             wolfSSL_set_cipher_list
#define SSL_set_connect_state           wolfSSL_set_connect_state
#define SSL_set_ex_data                 wolfSSL_set_ex_data
#define SSL_set_fd                      wolfSSL_set_fd
#define SSL_set_max_proto_version       wolfSSL_set_max_proto_version
#define SSL_set_min_proto_version       wolfSSL_set_min_proto_version
#define SSL_set_mode(ssl,op)         wolfSSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL)
#define SSL_set_msg_callback            wolfSSL_set_msg_callback
#define SSL_set_msg_callback_arg        wolfSSL_set_msg_callback_arg
#define SSL_set_options                 wolfSSL_set_options
#define SSL_set_post_handshake_auth     wolfSSL_set_post_handshake_auth
#define SSL_set_psk_client_callback     wolfSSL_set_psk_client_callback
#define SSL_set_psk_server_callback     wolfSSL_set_psk_server_callback
#define SSL_set_psk_use_session_callback    wolfSSL_set_psk_use_session_callback
#define SSL_set_quiet_shutdown          wolfSSL_set_quiet_shutdown
#define SSL_set_rfd                     wolfSSL_set_rfd
#define SSL_set_session                 wolfSSL_set_session
#define SSL_set_session_id_context      wolfSSL_set_session_id_context
#define SSL_set_shutdown                wolfSSL_set_shutdown
#define SSL_set_timeout                 wolfSSL_set_timeout
#define SSL_set_tlsext_debug_arg        wolfSSL_set_tlsext_debug_arg
#define SSL_set_tlsext_host_name        wolfSSL_set_tlsext_host_name
#define SSL_set_tlsext_status_exts      wolfSSL_set_tlsext_status_exts
#define SSL_set_tlsext_status_ids       wolfSSL_set_tlsext_status_ids
#define SSL_set_tlsext_status_ocsp_res  wolfSSL_set_tlsext_status_ocsp_resp
#define SSL_set_tlsext_status_ocsp_resp  wolfSSL_set_tlsext_status_ocsp_resp
#define SSL_set_tlsext_status_type      wolfSSL_set_tlsext_status_type
#define SSL_set_tmp_dh                  wolfSSL_set_tmp_dh
#define SSL_set_tmp_rsa(ssl,rsa)        1
#define SSL_set_verify                  wolfSSL_set_verify
#define SSL_set_verify_depth            wolfSSL_set_verify_depth
#define SSL_set_verify_result           wolfSSL_set_verify_result
#define SSL_set_wfd                     wolfSSL_set_wfd
#define SSL_shutdown                    wolfSSL_shutdown
#define SSL_state                       wolfSSL_state
#define SSL_state_string                wolfSSL_state_string
#define SSL_state_string_long           wolfSSL_state_string_long
#define SSL_total_renegotiations        wolfSSL_total_renegotiations
#define SSL_use_PrivateKey              wolfSSL_use_PrivateKey
#define SSL_use_PrivateKey_ASN1         wolfSSL_use_PrivateKey_ASN1
    #define SSL_use_PrivateKey_file           wolfSSL_use_PrivateKey_file
#define SSL_use_RSAPrivateKey_ASN1      wolfSSL_use_RSAPrivateKey_ASN1
    #define SSL_use_RSAPrivateKey_file        wolfSSL_use_RSAPrivateKey_file
#define SSL_use_certificate             wolfSSL_use_certificate
#define SSL_use_certificate_ASN1        wolfSSL_use_certificate_ASN1
    #define SSL_use_certificate_chain_file    wolfSSL_use_certificate_chain_file
    #define SSL_use_certificate_file          wolfSSL_use_certificate_file
#define SSL_use_psk_identity_hint       wolfSSL_use_psk_identity_hint
#define SSL_verify_client_post_handshake wolfSSL_verify_client_post_handshake
#define SSL_version(x)                  wolfSSL_version ((WOLFSSL*) (x))
#define SSL_want                        wolfSSL_want
#define SSL_want_read                   wolfSSL_want_read
#define SSL_want_write                  wolfSSL_want_write
#define SSL_write                       wolfSSL_write
#define SSLeay_add_all_algorithms       wolfSSL_add_all_algorithms
#define SSLeay_add_ssl_algorithms       wolfSSL_add_all_algorithms
#define SSLv23_client_method            wolfSSLv23_client_method
#define SSLv23_method                   wolfSSLv23_method
#define SSLv23_server_method            wolfSSLv23_server_method
#define SSLv2_client_method             wolfSSLv2_client_method
#define SSLv2_server_method             wolfSSLv2_server_method
#define SSLv3_client_method             wolfSSLv3_client_method
#define SSLv3_server_method             wolfSSLv3_server_method
#define STACK_OF(x) WOLFSSL_STACK
#define SYS_F_ACCEPT      WOLFSSL_SYS_ACCEPT
#define SYS_F_BIND        WOLFSSL_SYS_BIND
#define SYS_F_CONNECT     WOLFSSL_SYS_CONNECT
#define SYS_F_FOPEN       WOLFSSL_SYS_FOPEN
#define SYS_F_FREAD       WOLFSSL_SYS_FREAD
#define SYS_F_GETADDRINFO WOLFSSL_SYS_GETADDRINFO
#define SYS_F_GETHOSTBYNAME  WOLFSSL_SYS_GETHOSTBYNAME
#define SYS_F_GETNAMEINFO    WOLFSSL_SYS_GETNAMEINFO
#define SYS_F_GETSERVBYNAME  WOLFSSL_SYS_GETSERVBYNAME
#define SYS_F_GETSOCKNAME WOLFSSL_SYS_GETSOCKNAME
#define SYS_F_GETSOCKOPT  WOLFSSL_SYS_GETSOCKOPT
#define SYS_F_IOCTLSOCKET    WOLFSSL_SYS_IOCTLSOCKET
#define SYS_F_LISTEN         WOLFSSL_SYS_LISTEN
#define SYS_F_OPENDIR     WOLFSSL_SYS_OPENDIR
#define SYS_F_SETSOCKOPT  WOLFSSL_SYS_SETSOCKOPT
#define SYS_F_SOCKET      WOLFSSL_SYS_SOCKET
#define TLS1_1_VERSION                   0x0302
#define TLS1_2_VERSION                   0x0303
#define TLS1_3_VERSION                   0x0304
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          (0xc009)
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       (0xc02b)
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          (0xc00a)
#define TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
#define TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA            (0xc013)
#define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256         (0xc02f)
#define TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA            (0xc014)
#define TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   (0xcca8)
#define TLS1_VERSION                     0x0301
#define TLSEXT_NAMETYPE_host_name       WOLFSSL_SNI_HOST_NAME
#define TLSEXT_STATUSTYPE_ocsp  1
#define TLSEXT_TYPE_application_layer_protocol_negotiation    16
#define TLS_ANY_VERSION                  0x10000
#define TLS_ST_BEFORE          0 
#define TLS_client_method               wolfTLS_client_method
#define TLS_method                      wolfSSLv23_method
#define TLS_server_method               wolfTLS_server_method
#define TLSv1_1_client_method           wolfTLSv1_1_client_method
#define TLSv1_1_method                  wolfTLSv1_1_method
#define TLSv1_1_server_method           wolfTLSv1_1_server_method
#define TLSv1_2_client_method           wolfTLSv1_2_client_method
#define TLSv1_2_method                  wolfTLSv1_2_method
#define TLSv1_2_server_method           wolfTLSv1_2_server_method
#define TLSv1_3_client_method           wolfTLSv1_3_client_method
#define TLSv1_3_method                  wolfTLSv1_3_method
#define TLSv1_3_server_method           wolfTLSv1_3_server_method
#define TLSv1_client_method             wolfTLSv1_client_method
#define TLSv1_method                    wolfTLSv1_method
#define TLSv1_server_method             wolfTLSv1_server_method

#define X509V3_EXT_i2d                  wolfSSL_X509V3_EXT_i2d
#define X509_ALGOR_free                 wolfSSL_X509_ALGOR_free
#define X509_ALGOR_get0                 wolfSSL_X509_ALGOR_get0
#define X509_ALGOR_new                  wolfSSL_X509_ALGOR_new
#define X509_ALGOR_set0                 wolfSSL_X509_ALGOR_set0
#define X509_ATTRIBUTE_get0_type        wolfSSL_X509_ATTRIBUTE_get0_type
#define X509_CHECK_FLAG_NO_WILDCARDS WOLFSSL_NO_WILDCARDS
#define X509_CRL_free                   wolfSSL_X509_CRL_free
#define X509_CRL_get_REVOKED            wolfSSL_X509_CRL_get_REVOKED
#define X509_CRL_get_lastUpdate         wolfSSL_X509_CRL_get_lastUpdate
#define X509_CRL_get_nextUpdate         wolfSSL_X509_CRL_get_nextUpdate
#define X509_CRL_verify                 wolfSSL_X509_CRL_verify
    #define X509_EXTENSION_free         wolfSSL_X509_EXTENSION_free
    #define X509_EXTENSION_get_critical wolfSSL_X509_EXTENSION_get_critical
    #define X509_EXTENSION_get_data     wolfSSL_X509_EXTENSION_get_data
    #define X509_EXTENSION_get_object   wolfSSL_X509_EXTENSION_get_object
    #define X509_EXTENSION_new          wolfSSL_X509_EXTENSION_new
#define X509_FILETYPE_ASN1 SSL_FILETYPE_ASN1
#define X509_F_X509_CHECK_PRIVATE_KEY   128
#define X509_INFO_free                  wolfSSL_X509_INFO_free
#define X509_INFO_new                   wolfSSL_X509_INFO_new
#define X509_LOOKUP_add_dir             wolfSSL_X509_LOOKUP_add_dir
#define X509_LOOKUP_ctrl                wolfSSL_X509_LOOKUP_ctrl
#define X509_LOOKUP_file                wolfSSL_X509_LOOKUP_file
#define X509_LOOKUP_hash_dir            wolfSSL_X509_LOOKUP_hash_dir
#define X509_LOOKUP_load_file           wolfSSL_X509_LOOKUP_load_file
#define X509_L_ADD_DIR    WOLFSSL_X509_L_ADD_DIR
#define X509_L_ADD_STORE  WOLFSSL_X509_L_ADD_STORE
#define X509_L_FILE_LOAD  WOLFSSL_X509_L_FILE_LOAD
#define X509_L_LOAD_STORE WOLFSSL_X509_L_LOAD_STORE
#define X509_NAME_ENTRY_create_by_NID   wolfSSL_X509_NAME_ENTRY_create_by_NID
#define X509_NAME_ENTRY_create_by_txt   wolfSSL_X509_NAME_ENTRY_create_by_txt
#define X509_NAME_ENTRY_free            wolfSSL_X509_NAME_ENTRY_free
#define X509_NAME_ENTRY_get_data        wolfSSL_X509_NAME_ENTRY_get_data
#define X509_NAME_ENTRY_get_object      wolfSSL_X509_NAME_ENTRY_get_object
#define X509_NAME_ENTRY_new             wolfSSL_X509_NAME_ENTRY_new
#define X509_NAME_add_entry             wolfSSL_X509_NAME_add_entry
#define X509_NAME_add_entry_by_NID      wolfSSL_X509_NAME_add_entry_by_NID
#define X509_NAME_add_entry_by_txt      wolfSSL_X509_NAME_add_entry_by_txt
#define X509_NAME_cmp                   wolfSSL_X509_NAME_cmp
#define X509_NAME_delete_entry          wolfSSL_X509_NAME_delete_entry
#define X509_NAME_digest                wolfSSL_X509_NAME_digest
#define X509_NAME_dup                   wolfSSL_X509_NAME_dup
#define X509_NAME_entry_count           wolfSSL_X509_NAME_entry_count
#define X509_NAME_free                  wolfSSL_X509_NAME_free
#define X509_NAME_get_entry             wolfSSL_X509_NAME_get_entry
#define X509_NAME_get_index_by_NID      wolfSSL_X509_NAME_get_index_by_NID
#define X509_NAME_get_index_by_OBJ      wolfSSL_X509_NAME_get_index_by_OBJ
#define X509_NAME_get_text_by_NID       wolfSSL_X509_NAME_get_text_by_NID
#define X509_NAME_hash                  wolfSSL_X509_NAME_hash
#define X509_NAME_new                   wolfSSL_X509_NAME_new
#define X509_NAME_oneline               wolfSSL_X509_NAME_oneline
#define X509_NAME_print_ex              wolfSSL_X509_NAME_print_ex
#define X509_NAME_print_ex_fp           wolfSSL_X509_NAME_print_ex_fp
#define X509_OBJECT_free                wolfSSL_X509_OBJECT_free
#define X509_OBJECT_free_contents       wolfSSL_X509_OBJECT_free_contents
#define X509_OBJECT_get0_X509           wolfSSL_X509_OBJECT_get0_X509
#define X509_OBJECT_get0_X509_CRL       wolfSSL_X509_OBJECT_get0_X509_CRL
#define X509_OBJECT_get_type            wolfSSL_X509_OBJECT_get_type
#define X509_OBJECT_new                 wolfSSL_X509_OBJECT_new
#define X509_PUBKEY_free                wolfSSL_X509_PUBKEY_free
#define X509_PUBKEY_get                 wolfSSL_X509_PUBKEY_get
#define X509_PUBKEY_get0_param          wolfSSL_X509_PUBKEY_get0_param
#define X509_PUBKEY_new                 wolfSSL_X509_PUBKEY_new
#define X509_PUBKEY_set                 wolfSSL_X509_PUBKEY_set
#define X509_REQ_add1_attr_by_NID       wolfSSL_X509_REQ_add1_attr_by_NID
#define X509_REQ_add1_attr_by_txt       wolfSSL_X509_REQ_add1_attr_by_txt
#define X509_REQ_add_extensions         wolfSSL_X509_REQ_add_extensions
#define X509_REQ_check_private_key      wolfSSL_X509_check_private_key
#define X509_REQ_free                   wolfSSL_X509_REQ_free
#define X509_REQ_get_X509_PUBKEY        wolfSSL_X509_get_X509_PUBKEY
#define X509_REQ_get_attr               wolfSSL_X509_REQ_get_attr
#define X509_REQ_get_attr_by_NID        wolfSSL_X509_REQ_get_attr_by_NID
#define X509_REQ_get_extensions         wolfSSL_X509_REQ_get_extensions
#define X509_REQ_get_pubkey             wolfSSL_X509_get_pubkey
#define X509_REQ_get_subject_name       wolfSSL_X509_get_subject_name
#define X509_REQ_new                    wolfSSL_X509_REQ_new
#define X509_REQ_print                  wolfSSL_X509_print
#define X509_REQ_print_fp               wolfSSL_X509_print_fp
#define X509_REQ_set_pubkey             wolfSSL_X509_REQ_set_pubkey
#define X509_REQ_set_subject_name       wolfSSL_X509_REQ_set_subject_name
#define X509_REQ_set_version            wolfSSL_X509_set_version
#define X509_REQ_sign                   wolfSSL_X509_REQ_sign
#define X509_REQ_sign_ctx               wolfSSL_X509_REQ_sign_ctx
#define X509_REQ_verify                 wolfSSL_X509_REQ_verify
#define X509_STORE_CTX_cleanup          wolfSSL_X509_STORE_CTX_cleanup
#define X509_STORE_CTX_free             wolfSSL_X509_STORE_CTX_free
#define X509_STORE_CTX_get0_cert        wolfSSL_X509_STORE_CTX_get0_cert
#define X509_STORE_CTX_get0_chain       wolfSSL_X509_STORE_CTX_get_chain
#define X509_STORE_CTX_get0_current_issuer \
                                      wolfSSL_X509_STORE_CTX_get0_current_issuer
#define X509_STORE_CTX_get0_parent_ctx  wolfSSL_X509_STORE_CTX_get0_parent_ctx
#define X509_STORE_CTX_get0_store       wolfSSL_X509_STORE_CTX_get0_store
#define X509_STORE_CTX_get1_chain       wolfSSL_X509_STORE_CTX_get1_chain
#define X509_STORE_CTX_get1_issuer      wolfSSL_X509_STORE_CTX_get1_issuer
#define X509_STORE_CTX_get_chain        wolfSSL_X509_STORE_CTX_get_chain
#define X509_STORE_CTX_get_current_cert wolfSSL_X509_STORE_CTX_get_current_cert
#define X509_STORE_CTX_get_error        wolfSSL_X509_STORE_CTX_get_error
#define X509_STORE_CTX_get_error_depth  wolfSSL_X509_STORE_CTX_get_error_depth
#define X509_STORE_CTX_get_ex_data      wolfSSL_X509_STORE_CTX_get_ex_data
#define X509_STORE_CTX_init             wolfSSL_X509_STORE_CTX_init
#define X509_STORE_CTX_new              wolfSSL_X509_STORE_CTX_new
#define X509_STORE_CTX_set_depth        wolfSSL_X509_STORE_CTX_set_depth
#define X509_STORE_CTX_set_error        wolfSSL_X509_STORE_CTX_set_error
#define X509_STORE_CTX_set_error_depth  wolfSSL_X509_STORE_CTX_set_error_depth
#define X509_STORE_CTX_set_ex_data      wolfSSL_X509_STORE_CTX_set_ex_data
#define X509_STORE_CTX_set_time         wolfSSL_X509_STORE_CTX_set_time
#define X509_STORE_CTX_set_verify_cb    wolfSSL_X509_STORE_CTX_set_verify_cb
#define X509_STORE_CTX_trusted_stack    wolfSSL_X509_STORE_CTX_trusted_stack
#define X509_STORE_CTX_verify_cb        WOLFSSL_X509_STORE_CTX_verify_cb
#define X509_STORE_add_cert             wolfSSL_X509_STORE_add_cert
#define X509_STORE_add_crl              wolfSSL_X509_STORE_add_crl
#define X509_STORE_add_lookup           wolfSSL_X509_STORE_add_lookup
#define X509_STORE_free                 wolfSSL_X509_STORE_free
#define X509_STORE_get0_objects         wolfSSL_X509_STORE_get0_objects
#define X509_STORE_get1_certs           wolfSSL_X509_STORE_get1_certs
#define X509_STORE_get_by_subject       wolfSSL_X509_STORE_get_by_subject
#define X509_STORE_get_ex_data          wolfSSL_X509_STORE_get_ex_data
#define X509_STORE_load_locations       wolfSSL_X509_STORE_load_locations
#define X509_STORE_new                  wolfSSL_X509_STORE_new
#define X509_STORE_set_ex_data          wolfSSL_X509_STORE_set_ex_data
#define X509_STORE_set_flags            wolfSSL_X509_STORE_set_flags
#define X509_STORE_set_verify_cb(s, c) \
wolfSSL_X509_STORE_set_verify_cb((WOLFSSL_X509_STORE *)(s), (WOLFSSL_X509_STORE_CTX_verify_cb)(c))
#define X509_STORE_set_verify_cb_func(s, c) \
wolfSSL_X509_STORE_set_verify_cb((WOLFSSL_X509_STORE *)(s), (WOLFSSL_X509_STORE_CTX_verify_cb)(c))
#define X509_VERIFY_PARAM_clear_flags   wolfSSL_X509_VERIFY_PARAM_clear_flags
#define X509_VERIFY_PARAM_free          wolfSSL_X509_VERIFY_PARAM_free
#define X509_VERIFY_PARAM_get_flags     wolfSSL_X509_VERIFY_PARAM_get_flags
#define X509_VERIFY_PARAM_new           wolfSSL_X509_VERIFY_PARAM_new
#define X509_VERIFY_PARAM_set1          wolfSSL_X509_VERIFY_PARAM_set1
#define X509_VERIFY_PARAM_set1_host     wolfSSL_X509_VERIFY_PARAM_set1_host
#define X509_VERIFY_PARAM_set1_ip_asc   wolfSSL_X509_VERIFY_PARAM_set1_ip_asc
#define X509_VERIFY_PARAM_set_flags     wolfSSL_X509_VERIFY_PARAM_set_flags
#define X509_VERIFY_PARAM_set_hostflags wolfSSL_X509_VERIFY_PARAM_set_hostflags
#define X509_VP_FLAG_DEFAULT        WOLFSSL_VPARAM_DEFAULT
#define X509_VP_FLAG_LOCKED         WOLFSSL_VPARAM_LOCKED
#define X509_VP_FLAG_ONCE           WOLFSSL_VPARAM_ONCE
#define X509_VP_FLAG_OVERWRITE      WOLFSSL_VPARAM_OVERWRITE
#define X509_VP_FLAG_RESET_FLAGS    WOLFSSL_VPARAM_RESET_FLAGS
#define X509_V_FLAG_CRL_CHECK     WOLFSSL_CRL_CHECK
#define X509_V_FLAG_CRL_CHECK_ALL WOLFSSL_CRL_CHECKALL
#define X509_V_FLAG_NO_CHECK_TIME  WOLFSSL_NO_CHECK_TIME
#define X509_V_FLAG_USE_CHECK_TIME WOLFSSL_USE_CHECK_TIME
#define X509_add_ext                    wolfSSL_X509_add_ext
#define X509_chain_up_ref               wolfSSL_X509_chain_up_ref
#define X509_check_ca                   wolfSSL_X509_check_ca
#define X509_check_email                wolfSSL_X509_check_email
#define X509_check_host                 wolfSSL_X509_check_host
#define X509_check_ip_asc               wolfSSL_X509_check_ip_asc
#define X509_check_issued               wolfSSL_X509_check_issued
#define X509_check_private_key          wolfSSL_X509_check_private_key
#define X509_check_purpose(...)         0
    #define X509_cmp                    wolfSSL_X509_cmp
#define X509_cmp_current_time           wolfSSL_X509_cmp_current_time
#define X509_cmp_time                   wolfSSL_X509_cmp_time
#define X509_delete_ext                 wolfSSL_X509_delete_ext
#define X509_digest                     wolfSSL_X509_digest
#define X509_dup                        wolfSSL_X509_dup
#define X509_email_free                 wolfSSL_X509_email_free
#define X509_free                       wolfSSL_X509_free
#define X509_get0_extensions            wolfSSL_X509_get0_extensions
#define X509_get0_notAfter              wolfSSL_X509_get_notAfter
#define X509_get0_notBefore             wolfSSL_X509_get_notBefore
#define X509_get0_pubkey                wolfSSL_X509_get_pubkey
#define X509_get0_pubkey_bitstr         wolfSSL_X509_get0_pubkey_bitstr
#define X509_get0_signature             wolfSSL_X509_get0_signature
#define X509_get0_tbs_sigalg            wolfSSL_X509_get0_tbs_sigalg
#define X509_get1_ocsp                  wolfSSL_X509_get1_ocsp
#define X509_get_X509_PUBKEY            wolfSSL_X509_get_X509_PUBKEY
#define X509_get_ex_data                wolfSSL_X509_get_ex_data
#define X509_get_ex_new_index           wolfSSL_X509_get_ex_new_index
    #define X509_get_ext                wolfSSL_X509_get_ext
#define X509_get_ext_by_NID             wolfSSL_X509_get_ext_by_NID
    #define X509_get_ext_by_OBJ         wolfSSL_X509_get_ext_by_OBJ
#define X509_get_ext_count              wolfSSL_X509_get_ext_count
#define X509_get_ext_d2i                wolfSSL_X509_get_ext_d2i
#define X509_get_extensions             wolfSSL_X509_get0_extensions
#define X509_get_issuer_name            wolfSSL_X509_get_issuer_name
#define X509_get_notAfter               wolfSSL_X509_get_notAfter
#define X509_get_notBefore              wolfSSL_X509_get_notBefore
#define X509_get_pubkey                 wolfSSL_X509_get_pubkey
#define X509_get_serialNumber           wolfSSL_X509_get_serialNumber
#define X509_get_signature_nid          wolfSSL_X509_get_signature_nid
#define X509_get_subject_name           wolfSSL_X509_get_subject_name
#define X509_get_version                wolfSSL_X509_get_version
#define X509_getm_notAfter              wolfSSL_X509_get_notAfter
#define X509_getm_notBefore             wolfSSL_X509_get_notBefore
    #define X509_gmtime_adj             wolfSSL_X509_gmtime_adj
#define X509_issuer_name_hash           wolfSSL_X509_issuer_name_hash
#define X509_load_certificate_file      wolfSSL_X509_load_certificate_file
#define X509_load_crl_file              wolfSSL_X509_load_crl_file
#define X509_new                        wolfSSL_X509_new
#define X509_print                      wolfSSL_X509_print
#define X509_print_ex                   wolfSSL_X509_print_ex
#define X509_print_fp                   wolfSSL_X509_print_fp
#define X509_pubkey_digest              wolfSSL_X509_pubkey_digest
#define X509_set_ex_data                wolfSSL_X509_set_ex_data
#define X509_set_issuer_name            wolfSSL_X509_set_issuer_name
#define X509_set_notAfter               wolfSSL_X509_set_notAfter
#define X509_set_notBefore              wolfSSL_X509_set_notBefore
#define X509_set_pubkey                 wolfSSL_X509_set_pubkey
#define X509_set_serialNumber           wolfSSL_X509_set_serialNumber
#define X509_set_subject_name           wolfSSL_X509_set_subject_name
#define X509_set_version                wolfSSL_X509_set_version
#define X509_sign                       wolfSSL_X509_sign
#define X509_sign_ctx                   wolfSSL_X509_sign_ctx
#define X509_signature_print            wolfSSL_X509_signature_print
#define X509_subject_name_hash          wolfSSL_X509_subject_name_hash
#define X509_time_adj                   wolfSSL_X509_time_adj
#define X509_time_adj_ex                wolfSSL_X509_time_adj_ex
#define X509_to_X509_REQ                wolfSSL_X509_to_X509_REQ
#define X509_up_ref                     wolfSSL_X509_up_ref
#define X509_verify                     wolfSSL_X509_verify
#define X509_verify_cert                wolfSSL_X509_verify_cert
#define X509_verify_cert_error_string   wolfSSL_X509_verify_cert_error_string
#define _STACK OPENSSL_STACK
#define a2i_ASN1_INTEGER                wolfSSL_a2i_ASN1_INTEGER
#define b2i_PVK_bio(...)                NULL
#define b2i_PrivateKey_bio(...)         NULL
#define d2i_AutoPrivateKey              wolfSSL_d2i_AutoPrivateKey
#define d2i_DISPLAYTEXT                 wolfSSL_d2i_DISPLAYTEXT
#define d2i_PKCS12_bio                  wolfSSL_d2i_PKCS12_bio
#define d2i_PKCS12_fp                   wolfSSL_d2i_PKCS12_fp
#define d2i_PKCS8PrivateKey_bio         wolfSSL_d2i_PKCS8PrivateKey_bio
#define d2i_PKCS8_PRIV_KEY_INFO_bio     wolfSSL_d2i_PKCS8_PKEY_bio
#define d2i_PUBKEY                      wolfSSL_d2i_PUBKEY
#define d2i_PUBKEY_bio                  wolfSSL_d2i_PUBKEY_bio
#define d2i_PrivateKey                  wolfSSL_d2i_PrivateKey
#define d2i_PrivateKey_bio              wolfSSL_d2i_PrivateKey_bio
#define d2i_RSAPrivateKey               wolfSSL_d2i_RSAPrivateKey
#define d2i_RSAPrivateKey_bio           wolfSSL_d2i_RSAPrivateKey_bio
#define d2i_RSAPublicKey                wolfSSL_d2i_RSAPublicKey
#define d2i_SSL_SESSION                 wolfSSL_d2i_SSL_SESSION
#define d2i_X509                        wolfSSL_d2i_X509
#define d2i_X509_CRL                    wolfSSL_d2i_X509_CRL
#define d2i_X509_CRL_fp                 wolfSSL_d2i_X509_CRL_fp
#define d2i_X509_NAME                   wolfSSL_d2i_X509_NAME
#define d2i_X509_REQ                    wolfSSL_d2i_X509_REQ
#define d2i_X509_REQ_bio                wolfSSL_d2i_X509_REQ_bio
#define d2i_X509_bio                    wolfSSL_d2i_X509_bio
#define d2i_X509_fp                     wolfSSL_d2i_X509_fp
#define get_ex_data                     wolfSSL_CRYPTO_get_ex_data
#define i2a_ASN1_INTEGER                wolfSSL_i2a_ASN1_INTEGER
#define i2a_ASN1_OBJECT                 wolfSSL_i2a_ASN1_OBJECT
#define i2c_ASN1_INTEGER                wolfSSL_i2c_ASN1_INTEGER
#define i2d_ASN1_OBJECT                 wolfSSL_i2d_ASN1_OBJECT
#define i2d_PKCS12_bio                  wolfSSL_i2d_PKCS12_bio
#define i2d_PKCS8PrivateKey_bio         wolfSSL_PEM_write_bio_PKCS8PrivateKey
#define i2d_PUBKEY                      wolfSSL_i2d_PUBKEY
#define i2d_PrivateKey                  wolfSSL_i2d_PrivateKey
#define i2d_RSAPrivateKey               wolfSSL_i2d_RSAPrivateKey
#define i2d_RSAPublicKey                wolfSSL_i2d_RSAPublicKey
#define i2d_SSL_SESSION                 wolfSSL_i2d_SSL_SESSION
#define i2d_X509                        wolfSSL_i2d_X509
#define i2d_X509_NAME                   wolfSSL_i2d_X509_NAME
#define i2d_X509_REQ                    wolfSSL_i2d_X509_REQ
#define i2d_X509_REQ_bio                wolfSSL_i2d_X509_REQ_bio
#define i2d_X509_bio                    wolfSSL_i2d_X509_bio
#define set_ex_data                     wolfSSL_CRYPTO_set_ex_data
#define sk_ACCESS_DESCRIPTION_free      wolfSSL_sk_ACCESS_DESCRIPTION_free
#define sk_ACCESS_DESCRIPTION_num       wolfSSL_sk_ACCESS_DESCRIPTION_num
#define sk_ACCESS_DESCRIPTION_pop_free  wolfSSL_sk_ACCESS_DESCRIPTION_pop_free
#define sk_ACCESS_DESCRIPTION_value     wolfSSL_sk_ACCESS_DESCRIPTION_value
#define sk_ASN1_OBJECT_free             wolfSSL_sk_ASN1_OBJECT_free
#define sk_ASN1_OBJECT_num              wolfSSL_sk_num
#define sk_ASN1_OBJECT_pop_free         wolfSSL_sk_ASN1_OBJECT_pop_free
#define sk_ASN1_OBJECT_value            wolfSSL_sk_value
#define sk_GENERAL_NAME_free            wolfSSL_sk_GENERAL_NAME_free
#define sk_GENERAL_NAME_num             wolfSSL_sk_GENERAL_NAME_num
#define sk_GENERAL_NAME_pop_free        wolfSSL_sk_GENERAL_NAME_pop_free
#define sk_GENERAL_NAME_push            wolfSSL_sk_GENERAL_NAME_push
#define sk_GENERAL_NAME_value           wolfSSL_sk_GENERAL_NAME_value
#define sk_OPENSSL_PSTRING_num          wolfSSL_sk_WOLFSSL_STRING_num
#define sk_OPENSSL_PSTRING_value        (WOLFSSL_STRING*)wolfSSL_sk_WOLFSSL_STRING_value
#define sk_OPENSSL_STRING_free          wolfSSL_sk_free
#define sk_OPENSSL_STRING_num           wolfSSL_sk_WOLFSSL_STRING_num
#define sk_OPENSSL_STRING_value         wolfSSL_sk_WOLFSSL_STRING_value
#define sk_SSL_CIPHER_dup               wolfSSL_sk_dup
#define sk_SSL_CIPHER_find              wolfSSL_sk_SSL_CIPHER_find
#define sk_SSL_CIPHER_free              wolfSSL_sk_SSL_CIPHER_free
#define sk_SSL_CIPHER_num               wolfSSL_sk_SSL_CIPHER_num
#define sk_SSL_CIPHER_value             wolfSSL_sk_SSL_CIPHER_value
#define sk_SSL_COMP_zero                wolfSSL_sk_SSL_COMP_zero
#define sk_X509_EXTENSION_new_null      wolfSSL_sk_X509_EXTENSION_new_null
#define sk_X509_EXTENSION_num           wolfSSL_sk_X509_EXTENSION_num
#define sk_X509_EXTENSION_pop_free      wolfSSL_sk_X509_EXTENSION_pop_free
#define sk_X509_EXTENSION_push          wolfSSL_sk_X509_EXTENSION_push
#define sk_X509_EXTENSION_value         wolfSSL_sk_X509_EXTENSION_value
#define sk_X509_INFO_free               wolfSSL_sk_X509_INFO_free
#define sk_X509_INFO_new_null           wolfSSL_sk_X509_INFO_new_null
#define sk_X509_INFO_num                wolfSSL_sk_X509_INFO_num
#define sk_X509_INFO_pop                wolfSSL_sk_X509_INFO_pop
#define sk_X509_INFO_pop_free           wolfSSL_sk_X509_INFO_pop_free
#define sk_X509_INFO_push               wolfSSL_sk_X509_INFO_push
#define sk_X509_INFO_shift              wolfSSL_sk_X509_INFO_pop
#define sk_X509_INFO_value              wolfSSL_sk_X509_INFO_value
#define sk_X509_NAME_find               wolfSSL_sk_X509_NAME_find
#define sk_X509_NAME_free               wolfSSL_sk_X509_NAME_free
#define sk_X509_NAME_new                wolfSSL_sk_X509_NAME_new
#define sk_X509_NAME_new_null()         wolfSSL_sk_X509_NAME_new(NULL)
#define sk_X509_NAME_num                wolfSSL_sk_X509_NAME_num
#define sk_X509_NAME_pop                wolfSSL_sk_X509_NAME_pop
#define sk_X509_NAME_pop_free           wolfSSL_sk_X509_NAME_pop_free
#define sk_X509_NAME_push               wolfSSL_sk_X509_NAME_push
#define sk_X509_NAME_set_cmp_func       wolfSSL_sk_X509_NAME_set_cmp_func
#define sk_X509_NAME_value              wolfSSL_sk_X509_NAME_value
#define sk_X509_OBJECT_delete           wolfSSL_sk_X509_OBJECT_delete
#define sk_X509_OBJECT_free             wolfSSL_sk_X509_OBJECT_free
#define sk_X509_OBJECT_new              wolfSSL_sk_X509_OBJECT_new
#define sk_X509_OBJECT_num              wolfSSL_sk_X509_OBJECT_num
#define sk_X509_OBJECT_value            wolfSSL_sk_X509_OBJECT_value
#define sk_X509_REVOKED_num             wolfSSL_sk_X509_REVOKED_num
#define sk_X509_REVOKED_value           wolfSSL_sk_X509_REVOKED_value
#define sk_X509_dup                     wolfSSL_sk_dup
#define sk_X509_free                    wolfSSL_sk_X509_free
#define sk_X509_new                     wolfSSL_sk_X509_new
#define sk_X509_new_null                wolfSSL_sk_X509_new
#define sk_X509_num                     wolfSSL_sk_X509_num
#define sk_X509_pop                     wolfSSL_sk_X509_pop
#define sk_X509_pop_free                wolfSSL_sk_X509_pop_free
#define sk_X509_push                    wolfSSL_sk_X509_push
#define sk_X509_shift                   wolfSSL_sk_X509_shift
#define sk_X509_value                   wolfSSL_sk_X509_value
#define sk_num                          wolfSSL_sk_num
#define sk_value                        wolfSSL_sk_value


    #define wc_ErrorString(err, buf) \
        (void)err; XSTRNCPY((buf), wc_GetErrorString((err)), \
        WOLFSSL_MAX_ERROR_SZ);
    #define wc_GetErrorString(error) "no support for error strings built in"

#define CTaoCryptErrorString    wc_ErrorString
#define CTaoCryptGetErrorString wc_GetErrorString
            #define ALIGN128 __attribute__ ( (aligned (128)))
                #define ALIGN16 __attribute__ ( (aligned (16)))
            #define ALIGN256 __attribute__ ( (aligned (256)))
                #define ALIGN32 __attribute__ ( (aligned (32)))
                #define ALIGN64 __attribute__ ( (aligned (64)))
    #define CheckCtcSettings() (CTC_SETTINGS == CheckRunTimeSettings())
        #define DECLARE_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            VAR_TYPE* VAR_NAME[VAR_ITEMS]; \
            int idx##VAR_NAME, inner_idx_##VAR_NAME; \
            for (idx##VAR_NAME=0; idx##VAR_NAME<VAR_ITEMS; idx##VAR_NAME++) { \
                VAR_NAME[idx##VAR_NAME] = (VAR_TYPE*)XMALLOC(VAR_SIZE, (HEAP), DYNAMIC_TYPE_WOLF_BIGINT); \
                if (VAR_NAME[idx##VAR_NAME] == NULL) { \
                    for (inner_idx_##VAR_NAME = 0; inner_idx_##VAR_NAME < idx##VAR_NAME; inner_idx_##VAR_NAME++) { \
                        XFREE(VAR_NAME[inner_idx_##VAR_NAME], HEAP, DYNAMIC_TYPE_WOLF_BIGINT); \
                        VAR_NAME[inner_idx_##VAR_NAME] = NULL; \
                    } \
                    for (inner_idx_##VAR_NAME = idx##VAR_NAME + 1; inner_idx_##VAR_NAME < VAR_ITEMS; inner_idx_##VAR_NAME++) { \
                        VAR_NAME[inner_idx_##VAR_NAME] = NULL; \
                    } \
                    break; \
                } \
            }
        #define DECLARE_ARRAY_DYNAMIC_DEC(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            DECLARE_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP)
        #define DECLARE_ARRAY_DYNAMIC_EXE(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP)
        #define DECLARE_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP) \
            VAR_TYPE* VAR_NAME = (VAR_TYPE*)XMALLOC(sizeof(VAR_TYPE) * VAR_SIZE, (HEAP), DYNAMIC_TYPE_WOLF_BIGINT)

        #define EXIT_TEST(ret) return (void*)((size_t)(ret))
                #define FALL_THROUGH fallthrough
        #define FALSE 0

        #define FREE_ARRAY(VAR_NAME, VAR_ITEMS, HEAP) \
            for (idx##VAR_NAME=0; idx##VAR_NAME<VAR_ITEMS; idx##VAR_NAME++) { \
                XFREE(VAR_NAME[idx##VAR_NAME], (HEAP), DYNAMIC_TYPE_WOLF_BIGINT); \
            }
        #define FREE_ARRAY_DYNAMIC(VAR_NAME, VAR_ITEMS, HEAP) \
            FREE_ARRAY(VAR_NAME, VAR_ITEMS, HEAP)
        #define FREE_VAR(VAR_NAME, HEAP) \
            XFREE(VAR_NAME, (HEAP), DYNAMIC_TYPE_WOLF_BIGINT);
        #define INLINE WC_INLINE

    #define INVALID_DEVID    -2
        #define MP_16BIT  
            #define PEDANTIC_EXTENSION __extension__

        #define PRAGMA_GCC_IGNORE(str) _Pragma(str);
        #define PRAGMA_GCC_POP         _Pragma("GCC diagnostic pop");
            #define THREAD_LS_T __declspec(thread)
        #define TRUE  1

        #define W64LIT(x) x##ui64


                   #define WC_INLINE __inline__

        #define WC_NORETURN __attribute__((noreturn))


    #define WOLFSSL_MAX_16BIT 0xffffU
        #define WOLFSSL_MAX_ERROR_SZ 80
        #define WOLFSSL_PACK __attribute__ ((packed))



                #define XATOI(s)          atoi((s))
            #define XGETENV getenv
        #define XISALNUM(c)     isalnum((c))
        #define XISASCII(c)     isascii((c))
        #define XISSPACE(c)     isspace((c))
        #define XSTRCMP(s1,s2)    strcmp((s1),(s2))
            #define XSTRSEP(s1,d) wc_strsep((s1),(d))
    #define XSTR_SIZEOF(x) (sizeof(x) - 1) 
        #define XTOLOWER(c)      tolower((c))
            #define XTOUPPER(c)     toupper((c))
            #define __GNUC_PREREQ(maj, min) \
                (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
                    #define LARGEST_MEM_BUCKET 30400
            #define WOLFMEM_BUCKETS 64,128,256,512,1024,2432,3456,4544,\
                                    LARGEST_MEM_BUCKET
    #define WOLFMEM_DEF_BUCKETS  9     
            #define WOLFMEM_DIST    49,10,6,14,5,6,9,1,1
    #define WOLFMEM_GENERAL       0x01
    #define WOLFMEM_IO_POOL       0x02
    #define WOLFMEM_IO_POOL_FIXED 0x04
        #define WOLFMEM_IO_SZ        16992 
        #define WOLFMEM_MAX_BUCKETS  9
    #define WOLFMEM_TRACK_STATS   0x08

        #define WOLFSSL_STATIC_ALIGN 16
    #define WOLFSSL_STATIC_TIMEOUT 1

    #define DIR       FCL_DIR
    #define FILE_BUFFER_SIZE 1024     
    #define FUSION_IO_SEND_E FCL_EWOULDBLOCK
    #define FindFirstFileA(fn, d) FindFirstFile((LPCWSTR) fn, \
                                                (LPWIN32_FIND_DATAW) d)
    #define FindNextFileA(h, d) FindNextFile(h, (LPWIN32_FIND_DATAW) d)

    #define INT_MAX 2147483647
    #define LLONG_MAX LONG_MAX
    #define LONG_MAX 9223372036854775807L
        #define MAX_FILENAME_SZ  256 
        #define MAX_PATH 256

    #define NO_TIMEVAL 1

            #define RESTORE_VECTOR_REGISTERS() kernel_fpu_end()
            #define SAVE_VECTOR_REGISTERS() kernel_fpu_begin()
        #define SEPARATOR_CHAR ';'
    #define STAT       struct fs_dirent

    #define UCHAR_MAX 255
    #define UINT_MAX 4294967295U
    #define ULLONG_MAX ULONG_MAX
    #define ULONG_MAX 18446744073709551615UL



    #define USHRT_MAX 65535
    #define WC_ISFILEEXIST_NOFILE -1
    #define WC_READDIR_NOFILE -1

        #define WOLFSSL_CURRTIME_REMAP m2mb_xtime_bench
    #define WOLFSSL_GLOBAL CVMX_SHARED

        #define WOLFSSL_SCE_GSCE_HANDLE g_sce


    #define XBADFILE                 -1
        #define XCLOSE      close
    #define XFCLOSE                  vf_close
    #define XFDOPEN    fdopen
    #define XFGETS                  fgets
    #define XFILE                    int
        #define XFOPEN     wolfSSL_fopen
    #define XFPRINTF  FCL_FPRINTF
    #define XFPUTS    FCL_FPUTS
    #define XFREAD                  fread
    #define XFREWIND            fs_rewind
    #define XFSEEK                   ebsnet_fseek
    #define XFTELL                   vf_tell
    #define XFWRITE                 fwrite
        #define XGMTIME(c, t)   gmtime_r((c), (t))
        #define XREAD       read
    #define XREWIND                  vf_rewind
    #define XSEEK_END                VSEEK_END
    #define XSPRINTF  FCL_SPRINTF
        #define XSTAT       _stat
        #define XS_ISREG(s) (s & _S_IFREG)
        #define XTIME(tl)  time((tl))
        #define XTIME_MS(tl)    m2mb_xtime_ms((tl))
    #define XVALIDATE_DATE(d, f, t) wc_ValidateDate((d), (f), (t))
    #define XVFPRINTF FCL_VFPRINTF
    #define XVSNPRINTF _vsnprintf
        #define XWRITE      write



    #define closedir  FCL_CLOSEDIR
    #define dirent    fclDirent 
    #define free(x) kfree(x)
    #define key_update wc_key_update
    #define lkm_printf(format, args...) printk(KERN_INFO "wolfssl: %s(): " format, __func__, ## args)
    #define malloc(x) kmalloc(x, GFP_KERNEL)
    #define opendir   FCL_OPENDIR
    #define printf(...) lkm_printf(__VA_ARGS__)
    #define readdir   FCL_READDIR
    #define stat      FCL_STAT
    #define strncasecmp FCL_STRNCASECMP
#define wc_FreeMutex   FreeMutex
#define wc_InitMutex   InitMutex
#define wc_LockMutex   LockMutex
#define wc_UnLockMutex UnLockMutex
    #define wolfSSL_CryptHwMutexInit()      0 
    #define wolfSSL_CryptHwMutexLock()      0 
    #define wolfSSL_CryptHwMutexUnLock()    (void)0 
#define PEM_read_PUBKEY                 wolfSSL_PEM_read_PUBKEY
#define PEM_read_PrivateKey             wolfSSL_PEM_read_PrivateKey
#define PEM_read_RSAPublicKey           wolfSSL_PEM_read_RSAPublicKey
#define PEM_read_bio                    wolfSSL_PEM_read_bio
#define PEM_read_bio_DSAPrivateKey      wolfSSL_PEM_read_bio_DSAPrivateKey
#define PEM_read_bio_DSA_PUBKEY         wolfSSL_PEM_read_bio_DSA_PUBKEY
#define PEM_read_bio_ECPKParameters     wolfSSL_PEM_read_bio_ECPKParameters
#define PEM_read_bio_ECPrivateKey       wolfSSL_PEM_read_bio_ECPrivateKey
#define PEM_read_bio_EC_PUBKEY          wolfSSL_PEM_read_bio_EC_PUBKEY
#define PEM_read_bio_PUBKEY             wolfSSL_PEM_read_bio_PUBKEY
#define PEM_read_bio_PrivateKey         wolfSSL_PEM_read_bio_PrivateKey
#define PEM_read_bio_RSAPrivateKey      wolfSSL_PEM_read_bio_RSAPrivateKey
#define PEM_read_bio_RSA_PUBKEY         wolfSSL_PEM_read_bio_RSA_PUBKEY
#define PEM_write_DHparams              wolfSSL_PEM_write_DHparams
#define PEM_write_DSAPrivateKey         wolfSSL_PEM_write_DSAPrivateKey
#define PEM_write_DSA_PUBKEY            wolfSSL_PEM_write_DSA_PUBKEY
#define PEM_write_ECPrivateKey          wolfSSL_PEM_write_ECPrivateKey
#define PEM_write_EC_PUBKEY             wolfSSL_PEM_write_EC_PUBKEY
#define PEM_write_RSAPrivateKey         wolfSSL_PEM_write_RSAPrivateKey
#define PEM_write_RSAPublicKey          wolfSSL_PEM_write_RSAPublicKey
#define PEM_write_RSA_PUBKEY            wolfSSL_PEM_write_RSA_PUBKEY
#define PEM_write_X509                  wolfSSL_PEM_write_X509
#define PEM_write_bio                   wolfSSL_PEM_write_bio
#define PEM_write_bio_DSAPrivateKey     wolfSSL_PEM_write_bio_DSAPrivateKey
#define PEM_write_bio_DSA_PUBKEY        wolfSSL_PEM_write_bio_DSA_PUBKEY
#define PEM_write_bio_ECPKParameters(...) 0
#define PEM_write_bio_ECPrivateKey      wolfSSL_PEM_write_bio_ECPrivateKey
#define PEM_write_bio_EC_PUBKEY         wolfSSL_PEM_write_bio_EC_PUBKEY
#define PEM_write_bio_PKCS8PrivateKey   wolfSSL_PEM_write_bio_PKCS8PrivateKey
#define PEM_write_bio_PUBKEY            wolfSSL_PEM_write_bio_PUBKEY
#define PEM_write_bio_PrivateKey        wolfSSL_PEM_write_bio_PrivateKey
#define PEM_write_bio_RSAPrivateKey     wolfSSL_PEM_write_bio_RSAPrivateKey
#define PEM_write_bio_RSA_PUBKEY        wolfSSL_PEM_write_bio_RSA_PUBKEY

#define DSA_LoadDer                wolfSSL_DSA_LoadDer
#define DSA_SIG                    WOLFSSL_DSA_SIG
#define DSA_SIG_free               wolfSSL_DSA_SIG_free
#define DSA_SIG_new                wolfSSL_DSA_SIG_new
#define DSA_do_sign                wolfSSL_DSA_do_sign_ex
#define DSA_do_verify              wolfSSL_DSA_do_verify_ex
#define DSA_free wolfSSL_DSA_free
#define DSA_generate_key           wolfSSL_DSA_generate_key
#define DSA_generate_parameters    wolfSSL_DSA_generate_parameters
#define DSA_generate_parameters_ex wolfSSL_DSA_generate_parameters_ex
#define DSA_new wolfSSL_DSA_new

#define WOLFSSL_DSA_LOAD_PRIVATE 1
#define WOLFSSL_DSA_LOAD_PUBLIC  2
#define BN_CTX_free       wolfSSL_BN_CTX_free
#define BN_CTX_get wolfSSL_BN_CTX_get
#define BN_CTX_init       wolfSSL_BN_CTX_init
#define BN_CTX_new        wolfSSL_BN_CTX_new
#define BN_CTX_start wolfSSL_BN_CTX_start
#define BN_ULONG WOLFSSL_BN_ULONG
#define BN_add wolfSSL_BN_add
#define BN_add_word wolfSSL_BN_add_word
#define BN_bin2bn  wolfSSL_BN_bin2bn
#define BN_bn2bin  wolfSSL_BN_bn2bin
#define BN_bn2dec wolfSSL_BN_bn2dec
#define BN_bn2hex wolfSSL_BN_bn2hex
#define BN_clear      wolfSSL_BN_clear
#define BN_clear_bit wolfSSL_BN_clear_bit
#define BN_clear_free wolfSSL_BN_clear_free
#define BN_cmp    wolfSSL_BN_cmp
#define BN_copy wolfSSL_BN_copy
#define BN_dec2bn wolfSSL_BN_dec2bn
#define BN_dup  wolfSSL_BN_dup
#define BN_free       wolfSSL_BN_free
#define BN_get_rfc2409_prime_1024  wolfSSL_DH_1024_prime
#define BN_get_rfc2409_prime_768   wolfSSL_DH_768_prime
#define BN_get_rfc3526_prime_1536  wolfSSL_DH_1536_prime
#define BN_get_rfc3526_prime_2048  wolfSSL_DH_2048_prime
#define BN_get_rfc3526_prime_3072  wolfSSL_DH_3072_prime
#define BN_get_rfc3526_prime_4096  wolfSSL_DH_4096_prime
#define BN_get_rfc3526_prime_6144  wolfSSL_DH_6144_prime
#define BN_get_rfc3526_prime_8192  wolfSSL_DH_8192_prime
#define BN_get_word wolfSSL_BN_get_word
#define BN_hex2bn      wolfSSL_BN_hex2bn
#define BN_init       wolfSSL_BN_init
#define BN_is_bit_set  wolfSSL_BN_is_bit_set
#define BN_is_negative wolfSSL_BN_is_negative
#define BN_is_odd   wolfSSL_BN_is_odd
#define BN_is_one   wolfSSL_BN_is_one
#define BN_is_prime_ex wolfSSL_BN_is_prime_ex
#define BN_is_word  wolfSSL_BN_is_word
#define BN_is_zero  wolfSSL_BN_is_zero
#define BN_lshift wolfSSL_BN_lshift
#define BN_mask_bits wolfSSL_mask_bits
#define BN_mod       wolfSSL_BN_mod
#define BN_mod_add wolfSSL_BN_mod_add
#define BN_mod_exp   wolfSSL_BN_mod_exp
#define BN_mod_inverse wolfSSL_BN_mod_inverse
#define BN_mod_mul   wolfSSL_BN_mod_mul
#define BN_mod_word wolfSSL_BN_mod_word
#define BN_new        wolfSSL_BN_new
#define BN_num_bits  wolfSSL_BN_num_bits
#define BN_num_bytes wolfSSL_BN_num_bytes
#define BN_print_fp wolfSSL_BN_print_fp
#define BN_pseudo_rand wolfSSL_BN_pseudo_rand
#define BN_rand        wolfSSL_BN_rand
#define BN_rshift wolfSSL_BN_rshift
#define BN_set_bit wolfSSL_BN_set_bit
#define BN_set_flags(x1, x2)
#define BN_set_word wolfSSL_BN_set_word
#define BN_sub       wolfSSL_BN_sub
#define BN_value_one wolfSSL_BN_value_one

#define WOLFSSL_BN_ULONG unsigned long
#define DIGIT(m,k) ((m)->dp[(k)])
   #define DIGIT_BIT ((int)((CHAR_BIT * sizeof(mp_digit) - 1)))
#define LTM_PRIME_2MSB_ON  0x0008 
#define LTM_PRIME_BBS      0x0001 
#define LTM_PRIME_SAFE     0x0002 
        #define MAX_INVMOD_SZ 8192

#define MP_DIGIT_BIT     DIGIT_BIT
#define MP_DIGIT_MAX     MP_MASK
#define MP_EQ         0   
#define MP_GT         1   

#define MP_LT        -1   
#define MP_MASK          ((((mp_digit)1)<<((mp_digit)DIGIT_BIT))-((mp_digit)1))
#define MP_MEM        -2  
#define MP_NEG        1   
#define MP_NO         0   
#define MP_NOT_INF    -4  
#define MP_OKAY       0   
      #define MP_PREC                 32     
#define MP_RADIX_BIN  2
#define MP_RADIX_DEC  10
#define MP_RADIX_HEX  16
#define MP_RADIX_MAX  64
#define MP_RADIX_OCT  8
#define MP_RANGE      MP_NOT_INF
#define MP_VAL        -3  
#define MP_WARRAY  ((mp_word)1 << (sizeof(mp_word) * CHAR_BIT - 2 * DIGIT_BIT + 1))
#define MP_YES        1   
#define MP_ZPOS       0   
#define  OPT_CAST(x)  (x *)
   #define PRIME_SIZE      31
#define SIGN(m)    ((m)->sign)
#define USED(m)    ((m)->used)


    #define mp_dump(desc, a, verbose)
#define mp_exptmod_nct(G,X,P,Y)    mp_exptmod_fast(G,X,P,Y,0)
#define mp_iseven(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1u) == 0u)) ? MP_YES : MP_NO)
#define mp_isneg(a)  (((a)->sign != MP_ZPOS) ? MP_YES : MP_NO)
#define mp_isodd(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1u) == 1u)) ? MP_YES : MP_NO)
#define mp_isone(a) \
    (((((a)->used == 1)) && ((a)->dp[0] == 1u) && ((a)->sign == MP_ZPOS)) \
                                                               ? MP_YES : MP_NO)
#define mp_isword(a, w) \
    ((((a)->used == 1) && ((a)->dp[0] == w)) || ((w == 0) && ((a)->used == 0)) \
                                                               ? MP_YES : MP_NO)
#define mp_iszero(a) (((a)->used == 0) ? MP_YES : MP_NO)
#define mp_mag_size(mp)           mp_unsigned_bin_size(mp)
#define mp_montgomery_reduce_ex(x, n, rho, ct) mp_montgomery_reduce (x, n, rho)
#define mp_prime_random(a, t, size, bbs, cb, dat) \
   mp_prime_random_ex(a, t, ((size) * 8) + 1, (bbs==1)?LTM_PRIME_BBS:0, cb, dat)
#define mp_read_mag(mp, str, len) mp_read_unsigned_bin((mp), (str), (len))
#define mp_tobinary(M, S)  mp_toradix((M), (S), MP_RADIX_BIN)
#define mp_todecimal(M, S) mp_toradix((M), (S), MP_RADIX_DEC)
#define mp_tohex(M, S)     mp_toradix((M), (S), MP_RADIX_HEX)
#define mp_tomag(mp, str)         mp_to_unsigned_bin((mp), (str))
#define mp_tooctal(M, S)   mp_toradix((M), (S), MP_RADIX_OCT)
#define s_mp_mul(a, b, c) s_mp_mul_digs(a, b, c, (a)->used + (b)->used + 1)
   #define MAX(x,y) ((x)>(y)?(x):(y))
   #define MIN(x,y) ((x)<(y)?(x):(y))
    #define MP_API   WOLFSSL_API
    #define WC_TYPE_BLACK_KEY 3
#define WC_TYPE_HEX_STR 1
#define WC_TYPE_UNSIGNED_BIN 2




































































































































    #define DRBG_SEED_LEN (440/8)
    #define RNG WC_RNG
        #define RNG_MAX_BLOCK_LEN (0xFFFFl)
        #define WC_RESEED_INTERVAL (1000000)

#define wc_FreeRng(rng) (void)NOT_COMPILED_IN
#define wc_InitRng(rng) NOT_COMPILED_IN
#define wc_InitRngNonce(rng, n, s) NOT_COMPILED_IN
#define wc_InitRngNonce_ex(rng, n, s, h, d) NOT_COMPILED_IN
#define wc_InitRng_ex(rng, h, d) NOT_COMPILED_IN
#define wc_RNG_GenerateBlock(rng, b, s) NOT_COMPILED_IN
#define wc_RNG_GenerateByte(rng, b) NOT_COMPILED_IN
    #define SHA224             WC_SHA224
    #define SHA224_BLOCK_SIZE  WC_SHA224_BLOCK_SIZE
    #define SHA224_DIGEST_SIZE WC_SHA224_DIGEST_SIZE
    #define SHA224_PAD_SIZE    WC_SHA224_PAD_SIZE
    #define SHA256             WC_SHA256
    #define SHA256_BLOCK_SIZE  WC_SHA256_BLOCK_SIZE
    #define SHA256_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
    #define SHA256_NOINLINE __declspec(noinline)
    #define SHA256_PAD_SIZE    WC_SHA256_PAD_SIZE
    #define Sha224             wc_Sha224
    #define Sha256             wc_Sha256
        #define WC_SHA224             SHA224
        #define WC_SHA224_BLOCK_SIZE  SHA224_BLOCK_SIZE
        #define WC_SHA224_DIGEST_SIZE SHA224_DIGEST_SIZE
        #define WC_SHA224_PAD_SIZE    SHA224_PAD_SIZE

    #define WC_SHA256             SHA256
    #define WC_SHA256_BLOCK_SIZE  SHA256_BLOCK_SIZE
    #define WC_SHA256_DIGEST_SIZE SHA256_DIGEST_SIZE
    #define WC_SHA256_PAD_SIZE    SHA256_PAD_SIZE


        #define wc_Sha224             Sha224
    #define wc_Sha256             Sha256
#define TSIP_SESSIONKEY_NONCE_SIZE      8

    #define WOLFSSL_BUFFER(b, l)


        #define WOLFSSL_ERROR(x) \
            WOLFSSL_ERROR_LINE((x), __func__, "__LINE__", "__FILE__", NULL)

    #define WOLFSSL_IS_DEBUG_ON() 0
    #define WOLFSSL_LEAVE(m, r)

    #define WOLFSSL_LOG_CAT(a, m, b) #a " " m " "  #b


    #define WOLFSSL_STUB(m) \
        WOLFSSL_MSG(WOLFSSL_LOG_CAT(wolfSSL Stub, m, not implemented))

            #define __func__ NULL

#define WC_CAAM_CTXLEN 8
#define WC_CAAM_HASH_BLOCK 64
    #define WC_CAAM_MAX_DIGEST 32

    #define WOLFSSL_MAX_HASH_SIZE  64
    #define WOLFSSL_TI_INITBUFF    64




    #define CC310_MAX_LENGTH_DMA        (0xFFFF)
    #define CC310_MAX_LENGTH_DMA_AES    (0xFFF0)

    #define ESP_RSA_TIMEOUT 0xFFFFF
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#define SHA_CTX ETS_SHAContext


        #define CRYP AES1
			#define CRYP_AES_GCM CRYP_AES_GCM_GMAC
    #define HASH_ALGOMODE_HASH HASH_AlgoMode_HASH
    #define HASH_CR_SIZE 54
    #define HASH_DATATYPE_8B HASH_DataType_8b
    #define HASH_MAX_DIGEST 32
    #define MATH_INT_T struct sp_int

        	#define STM32_CRYPTO_AES_ONLY 
    #define STM32_GCM_IV_START 2

#define STM32_HASH_REG_SIZE  4

    #define STM32_HASH_TIMEOUT 0xFFFF
        #define STM_CRYPT_TYPE uint32_t



#define PIC32MZ_IF_RAM(addr) (KVA_TO_PA(addr) < 0x1D000000)
#define PIC32_ALGO_AES       0b00000100
#define PIC32_ALGO_DES       0b00000001
#define PIC32_ALGO_HMAC1     0b01000000
#define PIC32_ALGO_MD5       0b00001000
#define PIC32_ALGO_SHA1      0b00010000
#define PIC32_ALGO_SHA256    0b00100000
#define PIC32_ALGO_TDES      0b00000010
#define PIC32_BLOCKSIZE_AES     16
#define PIC32_BLOCKSIZE_DES     8
#define PIC32_BLOCKSIZE_HASH    64
#define PIC32_BLOCKSIZE_HMAC    PIC32_BLOCKSIZE_HASH
#define PIC32_BLOCKSIZE_MD5     PIC32_BLOCKSIZE_HASH
#define PIC32_BLOCKSIZE_SHA1    PIC32_BLOCKSIZE_HASH
#define PIC32_BLOCKSIZE_SHA256  PIC32_BLOCKSIZE_HASH
#define PIC32_BLOCKSIZE_TDES    24
#define PIC32_CRYPTOALGO_AES_GCM  0b1110
#define PIC32_CRYPTOALGO_CBC      0b0001
#define PIC32_CRYPTOALGO_CFB      0b0010
#define PIC32_CRYPTOALGO_ECB      0b0000
#define PIC32_CRYPTOALGO_OFB      0b0011
#define PIC32_CRYPTOALGO_RCBC     0b1001
#define PIC32_CRYPTOALGO_RCBC_MAC 0b1100
#define PIC32_CRYPTOALGO_RCFB     0b1010
#define PIC32_CRYPTOALGO_RCTR     0b1101
#define PIC32_CRYPTOALGO_RECB     0b1000
#define PIC32_CRYPTOALGO_ROFB     0b1011
#define PIC32_CRYPTOALGO_TCBC     0b0101
#define PIC32_CRYPTOALGO_TCFB     0b0110
#define PIC32_CRYPTOALGO_TECB     0b0100
#define PIC32_CRYPTOALGO_TOFB     0b0111
#define PIC32_DECRYPTION     0b0
#define PIC32_DIGEST_SIZE       32
#define PIC32_ENCRYPTION     0b1
#define PIC32_KEYSIZE_128         0b00
#define PIC32_KEYSIZE_192         0b01
#define PIC32_KEYSIZE_256         0b10
#define PIC32_NO_OUT_SWAP    ((__PIC32_FEATURE_SET0 == 'E') && \
                              (__PIC32_FEATURE_SET1 == 'C'))


    #define InitSha224   wc_InitSha224
#define InitSha256   wc_InitSha256
    #define Sha224Final  wc_Sha224Final
    #define Sha224Hash   wc_Sha224Hash
    #define Sha224Update wc_Sha224Update
#define Sha256Final  wc_Sha256Final
#define Sha256Hash   wc_Sha256Hash
#define Sha256Update wc_Sha256Update

    #define FreeRng        wc_FreeRng
    #define InitRng           wc_InitRng
    #define RNG_GenerateBlock wc_RNG_GenerateBlock
    #define RNG_GenerateByte  wc_RNG_GenerateByte
	    #define RNG_HealthTest wc_RNG_HealthTest
#define CheckFastMathSettings() (FP_SIZE == CheckRunTimeFastMath())

#define FP_DIGIT_MAX FP_MASK
#define FP_EQ         0   
#define FP_GT         1   
#define FP_LT        -1   
#define FP_MASK    (fp_digit)(-1)
#define FP_MAX_PRIME_SIZE (FP_MAX_BITS/(2*CHAR_BIT))
#define FP_MAX_SIZE           (FP_MAX_BITS+(8*DIGIT_BIT))
#define FP_MEM      -2
#define FP_NEG      1
#define FP_NO         0   
#define FP_OKAY      0
#define FP_PRIME_SIZE      256
#define FP_SIZE    (FP_MAX_SIZE/DIGIT_BIT)
#define FP_VAL      -1
#define FP_WOULDBLOCK -4
#define FP_YES        1   
#define FP_ZPOS     0

   #define SIZEOF_FP_DIGIT 2

























#define fp_abs(a, b)  { fp_copy(a, b); (b)->sign  = 0; }
#define fp_clamp(a)   { while ((a)->used && (a)->dp[(a)->used-1] == 0) --((a)->used); (a)->sign = (a)->used ? (a)->sign : FP_ZPOS; }
#define fp_iseven(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1) == 0)) ? FP_YES : FP_NO)
#define fp_isneg(a)  (((a)->sign != FP_ZPOS) ? FP_YES : FP_NO)
#define fp_isodd(a)  \
    (((a)->used > 0  && (((a)->dp[0] & 1) == 1)) ? FP_YES : FP_NO)
#define fp_isone(a) \
    ((((a)->used == 1) && ((a)->dp[0] == 1) && ((a)->sign == FP_ZPOS)) \
                                                               ? FP_YES : FP_NO)
#define fp_isword(a, w) \
    (((((a)->used == 1) && ((a)->dp[0] == w)) || \
                               ((w == 0) && ((a)->used == 0))) ? FP_YES : FP_NO)
#define fp_iszero(a) (((a)->used == 0) ? FP_YES : FP_NO)
#define fp_neg(a, b)  { fp_copy(a, b); (b)->sign ^= 1; fp_clamp(b); }
#define mp_clamp(a)   fp_clamp(a)
#define mp_grow(a,s)  MP_OKAY
#define mp_zero(a)      fp_zero(a)


#define MP_INT_NEXT(t, cnt) \
        (sp_int*)(((byte*)(t)) + MP_INT_SIZEOF(cnt))
#define MP_INT_SIZEOF(cnt) \
    (sizeof(sp_int) - (SP_INT_DIGITS - (((cnt) == 0) ? 1 : (cnt))) * \
     sizeof(sp_int_digit))
#define SP_DIGIT_MAX    SP_MASK
#define SP_HALF_MAX     (((sp_digit)1 << SP_HALF_SIZE) - 1)
#define SP_HALF_SIZE    (SP_WORD_SIZE / 2)
            #define SP_INT_DIGITS        (((6144 + SP_WORD_SIZE) / SP_WORD_SIZE) + 1)
    #define SP_INT_MAX_BITS     (SP_INT_DIGITS * SP_WORD_SIZE)
    #define SP_INT_WORD_MAX         ((1 << (SP_WORD_SIZE * 2)) - 1)
    #define SP_MASK         0xffU
    #define SP_MUL_SQR_DIGITS       (SP_INT_MAX_BITS / 2 / SP_WORD_SIZE)
    #define SP_MUL_SQR_MAX_PARTIAL  \
                                 (SP_MUL_SQR_DIGITS * ((1 << SP_WORD_SIZE) - 1))
        #define SP_PRINT_FMT       "%016lx"
    #define SP_UCHAR_BITS    8
    #define SP_UINT_BITS    32
        #define SP_ULLONG_BITS    64
    #define SP_ULONG_BITS    16
    #define SP_USHORT_BITS    16
#define SP_WORD_MASK    (SP_WORD_SIZE - 1)

    #define SP_WORD_SHIFT   3
        #define SP_WORD_SIZE 64
#define SP_WORD_SIZEOF  (SP_WORD_SIZE / 8)



#define mp_2expt                            sp_2expt
#define mp_abs                              sp_abs
#define mp_add                              sp_add
#define mp_add_d                            sp_add_d
#define mp_addmod                           sp_addmod
#define mp_addmod_ct                        sp_addmod_ct
#define mp_clear                            sp_clear
#define mp_cmp                              sp_cmp
#define mp_cmp_d                            sp_cmp_d
#define mp_cmp_mag                          sp_cmp_mag
#define mp_cnt_lsb                          sp_cnt_lsb
#define mp_cond_swap_ct                     sp_cond_swap_ct
#define mp_copy                             sp_copy
#define mp_count_bits                       sp_count_bits
#define mp_div                              sp_div
#define mp_div_2                            sp_div_2
#define mp_div_2_mod_ct                     sp_div_2_mod_ct
#define mp_div_2d                           sp_div_2d
#define mp_div_3(a, r, rem)                 sp_div_d(a, 3, r, rem)
#define mp_div_d                            sp_div_d
#define mp_exch                             sp_exch
#define mp_exptmod                          sp_exptmod
#define mp_exptmod_ex                       sp_exptmod_ex
#define mp_forcezero                        sp_forcezero
#define mp_free                             sp_free
#define mp_gcd                              sp_gcd
#define mp_init                             sp_init
#define mp_init_copy                        sp_init_copy
#define mp_init_multi                       sp_init_multi
#define mp_init_size                        sp_init_size
#define mp_invmod                           sp_invmod
#define mp_invmod_mont_ct                   sp_invmod_mont_ct
#define mp_is_bit_set(a,b)                  sp_is_bit_set(a,(unsigned int)b)
#define mp_lcm                              sp_lcm
#define mp_leading_bit                      sp_leading_bit
#define mp_lshd                             sp_lshd
#define mp_mod                              sp_mod
#define mp_mod_2d                           sp_mod_2d
#define mp_mod_d                            sp_mod_d
#define mp_montgomery_calc_normalization    sp_mont_norm
#define mp_montgomery_reduce                sp_mont_red
#define mp_montgomery_setup                 sp_mont_setup
#define mp_mul                              sp_mul
#define mp_mul_2(a, r)                      sp_mul_2d(a, 1, r)
#define mp_mul_2d                           sp_mul_2d
#define mp_mul_d                            sp_mul_d
#define mp_mulmod                           sp_mulmod
#define mp_prime_is_prime                   sp_prime_is_prime
#define mp_prime_is_prime_ex                sp_prime_is_prime_ex
#define mp_radix_size                       sp_radix_size
#define mp_rand_prime                       sp_rand_prime
#define mp_read_radix                       sp_read_radix
#define mp_read_unsigned_bin                sp_read_unsigned_bin
#define mp_rshb(A,x)                        sp_rshb(A,x,A)
#define mp_rshd                             sp_rshd
#define mp_set                              sp_set
#define mp_set_bit                          sp_set_bit
#define mp_set_int                          sp_set_int
#define mp_sqr                              sp_sqr
#define mp_sqrmod                           sp_sqrmod
#define mp_sub                              sp_sub
#define mp_sub_d                            sp_sub_d
#define mp_submod                           sp_submod
#define mp_submod_ct                        sp_submod_ct
#define mp_to_unsigned_bin                  sp_to_unsigned_bin
#define mp_to_unsigned_bin_at_pos           sp_to_unsigned_bin_at_pos
#define mp_to_unsigned_bin_len              sp_to_unsigned_bin_len
#define mp_toradix                          sp_toradix
#define mp_unsigned_bin_size                sp_unsigned_bin_size
#define sp_abs(a, b)     sp_copy(a, b)
#define sp_clamp(a)                                               \
    do {                                                          \
        int ii;                                                   \
        for (ii = a->used - 1; ii >= 0 && a->dp[ii] == 0; ii--) { \
        }                                                         \
        a->used = ii + 1;                                         \
    } while (0)
#define sp_iseven(a)     (((a)->used != 0) && (((a)->dp[0] & 1) == 0))
#define sp_isneg(a)      (0)
#define sp_isodd(a)      (((a)->used != 0) && ((a)->dp[0] & 1))
#define sp_isone(a)      (((a)->used == 1) && ((a)->dp[0] == 1))
#define sp_isword(a, d)  \
    ((((d) == 0) && sp_iszero(a)) || (((a)->used == 1) && ((a)->dp[0] == (d))))
#define sp_iszero(a)     ((a)->used == 0)
    #define sp_print(a, s)
    #define sp_print_digit(a, s)
    #define sp_print_int(a, s)
#define RSAPublicKey_dup        wolfSSL_RSAPublicKey_dup
#define RSA_F4             WOLFSSL_RSA_F4
#define RSA_FLAG_BLINDING               (1 << 4)
#define RSA_FLAG_CACHE_PRIVATE          (1 << 3)
#define RSA_FLAG_CACHE_PUBLIC           (1 << 2)
#define RSA_FLAG_EXT_PKEY               (1 << 6)
#define RSA_FLAG_NO_BLINDING            (1 << 7)
#define RSA_FLAG_NO_CONSTTIME           (1 << 8)
#define RSA_FLAG_THREAD_SAFE            (1 << 5)
#define RSA_METHOD_FLAG_NO_CHECK        (1 << 1)
#define RSA_NO_PADDING         3
#define RSA_PKCS1_OAEP_PADDING 1
#define RSA_PKCS1_PADDING      0
#define RSA_PKCS1_PSS_PADDING  2
#define RSA_PSS_SALTLEN_DIGEST   -1
#define RSA_PSS_SALTLEN_MAX      -3
#define RSA_PSS_SALTLEN_MAX_SIGN -2
#define RSA_blinding_on     wolfSSL_RSA_blinding_on
#define RSA_flags               wolfSSL_RSA_flags
#define RSA_generate_key_ex wolfSSL_RSA_generate_key_ex
#define RSA_get0_key            wolfSSL_RSA_get0_key
#define RSA_get_default_method  wolfSSL_RSA_get_default_method
#define RSA_get_ex_data        wolfSSL_RSA_get_ex_data
#define RSA_get_method          wolfSSL_RSA_get_method
#define RSA_meth_free           wolfSSL_RSA_meth_free
#define RSA_meth_new            wolfSSL_RSA_meth_new
#define RSA_meth_set0_app_data  wolfSSL_RSA_meth_set
#define RSA_meth_set_finish     wolfSSL_RSA_meth_set
#define RSA_meth_set_init       wolfSSL_RSA_meth_set
#define RSA_meth_set_priv_dec   wolfSSL_RSA_meth_set
#define RSA_meth_set_priv_enc   wolfSSL_RSA_meth_set
#define RSA_meth_set_pub_dec    wolfSSL_RSA_meth_set
#define RSA_meth_set_pub_enc    wolfSSL_RSA_meth_set
#define RSA_new  wolfSSL_RSA_new
#define RSA_private_decrypt wolfSSL_RSA_private_decrypt
#define RSA_private_encrypt wolfSSL_RSA_private_encrypt
#define RSA_public_decrypt wolfSSL_RSA_public_decrypt
#define RSA_public_encrypt  wolfSSL_RSA_public_encrypt
#define RSA_set0_key            wolfSSL_RSA_set0_key
#define RSA_set_ex_data        wolfSSL_RSA_set_ex_data
#define RSA_set_flags           wolfSSL_RSA_set_flags
#define RSA_set_method          wolfSSL_RSA_set_method
#define RSA_sign           wolfSSL_RSA_sign
#define RSA_size           wolfSSL_RSA_size
#define RSA_verify         wolfSSL_RSA_verify
#define WOLFSSL_RSA_F4           0x10001L

#define WOLFSSL_RSA_LOAD_PRIVATE 1
#define WOLFSSL_RSA_LOAD_PUBLIC  2
#define EC_F_EC_GFP_SIMPLE_POINT2OCT            4
#define EC_R_BUFFER_TOO_SMALL                   BUFFER_E
#define ECerr(f,r)   ERR_put_error(0,(f),(r),"__FILE__","__LINE__")
#define ERR_R_DISABLED                          NOT_COMPILED_IN
#define ERR_R_MALLOC_FAILURE                    MEMORY_E
#define ERR_R_PASSED_INVALID_ARGUMENT           BAD_FUNC_ARG
#define ERR_R_PASSED_NULL_PARAMETER             BAD_FUNC_ARG
#define ERR_R_SYS_LIB                           1
#define ERR_load_CRYPTO_strings          wolfSSL_ERR_load_crypto_strings
#define ERR_load_crypto_strings          wolfSSL_ERR_load_crypto_strings
#define PKCS12_R_MAC_VERIFY_FAILURE             2
#define RSA_F_RSA_OSSL_PRIVATE_ENCRYPT          1
#define RSA_R_UNKNOWN_PADDING_TYPE              RSA_PAD_E
#define RSAerr(f,r)  ERR_put_error(0,(f),(r),"__FILE__","__LINE__")
#define SSL_F_SSL_CTX_USE_CERTIFICATE_FILE      2
#define SSL_F_SSL_USE_PRIVATEKEY                3
#define SSLerr(f,r)  ERR_put_error(0,(f),(r),"__FILE__","__LINE__")

#define BIO_CB_CTRL   WOLFSSL_BIO_CB_CTRL
#define BIO_CB_FREE   WOLFSSL_BIO_CB_FREE
#define BIO_CB_GETS   WOLFSSL_BIO_CB_GETS
#define BIO_CB_PUTS   WOLFSSL_BIO_CB_PUTS
#define BIO_CB_READ   WOLFSSL_BIO_CB_READ
#define BIO_CB_RETURN WOLFSSL_BIO_CB_RETURN
#define BIO_CB_WRITE  WOLFSSL_BIO_CB_WRITE
#define BIO_CLOSE                  0x01
#define BIO_CTRL_DGRAM_QUERY_MTU   40
#define BIO_CTRL_DUP               12
#define BIO_CTRL_EOF               2
#define BIO_CTRL_FLUSH             11
#define BIO_CTRL_GET_CLOSE         8
#define BIO_CTRL_INFO              3
#define BIO_CTRL_PENDING           10
#define BIO_CTRL_POP               7
#define BIO_CTRL_PUSH              6
#define BIO_CTRL_RESET             1
#define BIO_CTRL_SET_CLOSE         9
#define BIO_CTRL_WPENDING          13
#define BIO_C_FILE_SEEK                 128
#define BIO_C_GET_BUF_MEM_PTR           115
#define BIO_C_GET_FILE_PTR              107
#define BIO_C_MAKE_BIO_PAIR             138
#define BIO_C_SET_BUF_MEM               114
#define BIO_C_SET_BUF_MEM_EOF_RETURN    130
#define BIO_C_SET_FILENAME              108
#define BIO_C_SET_FILE_PTR              106
#define BIO_C_SET_WRITE_BUF_SIZE        136
#define BIO_FLAGS_BASE64_NO_NL WOLFSSL_BIO_FLAG_BASE64_NO_NL
#define BIO_FLAGS_IO_SPECIAL   WOLFSSL_BIO_FLAG_IO_SPECIAL
#define BIO_FLAGS_READ         WOLFSSL_BIO_FLAG_READ
#define BIO_FLAGS_SHOULD_RETRY WOLFSSL_BIO_FLAG_RETRY
#define BIO_FLAGS_WRITE        WOLFSSL_BIO_FLAG_WRITE
#define BIO_FP_TEXT                0x00
#define BIO_FP_WRITE               0x04
#define BIO_NOCLOSE                0x00
#define BIO_TYPE_BASE64 WOLFSSL_BIO_BASE64
#define BIO_TYPE_BIO  WOLFSSL_BIO_BIO
#define BIO_TYPE_FILE WOLFSSL_BIO_FILE
#define BIO_TYPE_MEM  WOLFSSL_BIO_MEMORY
#define BIO_clear_flags            wolfSSL_BIO_clear_flags
#define BIO_clear_retry_flags      wolfSSL_BIO_clear_retry_flags
#define BIO_ctrl                        wolfSSL_BIO_ctrl
#define BIO_ctrl_pending                wolfSSL_BIO_ctrl_pending
#define BIO_ctrl_reset_read_request     wolfSSL_BIO_ctrl_reset_read_request
#define BIO_dump    wolfSSL_BIO_dump
#define BIO_find_type wolfSSL_BIO_find_type
#define BIO_get_callback         wolfSSL_BIO_get_callback
#define BIO_get_callback_arg     wolfSSL_BIO_get_callback_arg
#define BIO_get_data               wolfSSL_BIO_get_data
#define BIO_get_ex_data            wolfSSL_BIO_get_ex_data
#define BIO_get_fp                      wolfSSL_BIO_get_fp
#define BIO_get_mem_ptr                 wolfSSL_BIO_get_mem_ptr
#define BIO_get_shutdown           wolfSSL_BIO_get_shutdown
#define BIO_gets      wolfSSL_BIO_gets
#define BIO_int_ctrl                    wolfSSL_BIO_int_ctrl
#define BIO_make_bio_pair               wolfSSL_BIO_make_bio_pair
#define BIO_meth_free              wolfSSL_BIO_meth_free
#define BIO_meth_new               wolfSSL_BIO_meth_new
#define BIO_meth_set_create        wolfSSL_BIO_meth_set_create
#define BIO_meth_set_ctrl          wolfSSL_BIO_meth_set_ctrl
#define BIO_meth_set_destroy       wolfSSL_BIO_meth_set_destroy
#define BIO_meth_set_gets          wolfSSL_BIO_meth_set_gets
#define BIO_meth_set_puts          wolfSSL_BIO_meth_set_puts
#define BIO_meth_set_read          wolfSSL_BIO_meth_set_read
#define BIO_meth_set_write         wolfSSL_BIO_meth_set_write
#define BIO_new_fd                      wolfSSL_BIO_new_fd
#define BIO_new_file                    wolfSSL_BIO_new_file
#define BIO_new_fp                      wolfSSL_BIO_new_fp
#define BIO_next      wolfSSL_BIO_next
#define BIO_printf  wolfSSL_BIO_printf
#define BIO_puts      wolfSSL_BIO_puts
#define BIO_reset                       wolfSSL_BIO_reset
#define BIO_s_bio                       wolfSSL_BIO_s_bio
#define BIO_s_file                      wolfSSL_BIO_s_file
#define BIO_s_socket                    wolfSSL_BIO_s_socket
#define BIO_seek                        wolfSSL_BIO_seek
#define BIO_set_callback         wolfSSL_BIO_set_callback
#define BIO_set_callback_arg     wolfSSL_BIO_set_callback_arg
#define BIO_set_close                   wolfSSL_BIO_set_close
#define BIO_set_data               wolfSSL_BIO_set_data
#define BIO_set_ex_data            wolfSSL_BIO_set_ex_data
#define BIO_set_fd                      wolfSSL_BIO_set_fd
#define BIO_set_fp                      wolfSSL_BIO_set_fp
#define BIO_set_init               wolfSSL_BIO_set_init
#define BIO_set_mem_eof_return          wolfSSL_BIO_set_mem_eof_return
#define BIO_set_retry_read(bio)\
    wolfSSL_BIO_set_flags((bio), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_READ)
#define BIO_set_retry_write(bio)\
    wolfSSL_BIO_set_flags((bio), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_WRITE)
#define BIO_set_shutdown           wolfSSL_BIO_set_shutdown
#define BIO_set_write_buf_size          wolfSSL_BIO_set_write_buf_size
#define BIO_should_retry                wolfSSL_BIO_should_retry
#define BIO_snprintf               XSNPRINTF
#define BIO_tell                        wolfSSL_BIO_tell
#define BIO_vprintf wolfSSL_BIO_vprintf
#define BIO_wpending                    wolfSSL_BIO_wpending
#define BIO_write_filename              wolfSSL_BIO_write_filename

#define   BASE64_DECODE_BLOCK_SIZE  4
#define   BASE64_ENCODE_BLOCK_SIZE  48
#define   BASE64_ENCODE_RESULT_BLOCK_SIZE 64
#define EVP_BytesToKey         wolfSSL_EVP_BytesToKey
#define EVP_CIPHER_CTX_block_size  wolfSSL_EVP_CIPHER_CTX_block_size
#define EVP_CIPHER_CTX_cipher         wolfSSL_EVP_CIPHER_CTX_cipher
#define EVP_CIPHER_CTX_cleanup        wolfSSL_EVP_CIPHER_CTX_cleanup
#define EVP_CIPHER_CTX_clear_flags wolfSSL_EVP_CIPHER_CTX_clear_flags
#define EVP_CIPHER_CTX_ctrl        wolfSSL_EVP_CIPHER_CTX_ctrl
#define EVP_CIPHER_CTX_flags       wolfSSL_EVP_CIPHER_CTX_flags
#define EVP_CIPHER_CTX_free           wolfSSL_EVP_CIPHER_CTX_free
#define EVP_CIPHER_CTX_init           wolfSSL_EVP_CIPHER_CTX_init
#define EVP_CIPHER_CTX_iv_length      wolfSSL_EVP_CIPHER_CTX_iv_length
#define EVP_CIPHER_CTX_key_length     wolfSSL_EVP_CIPHER_CTX_key_length
#define EVP_CIPHER_CTX_mode           wolfSSL_EVP_CIPHER_CTX_mode
#define EVP_CIPHER_CTX_new            wolfSSL_EVP_CIPHER_CTX_new
#define EVP_CIPHER_CTX_reset          wolfSSL_EVP_CIPHER_CTX_reset
#define EVP_CIPHER_CTX_set_flags   wolfSSL_EVP_CIPHER_CTX_set_flags
#define EVP_CIPHER_CTX_set_iv      wolfSSL_EVP_CIPHER_CTX_set_iv
#define EVP_CIPHER_CTX_set_key_length wolfSSL_EVP_CIPHER_CTX_set_key_length
#define EVP_CIPHER_CTX_set_padding wolfSSL_EVP_CIPHER_CTX_set_padding
#define EVP_CIPHER_block_size      wolfSSL_EVP_CIPHER_block_size
#define EVP_CIPHER_flags           wolfSSL_EVP_CIPHER_flags
#define EVP_CIPHER_iv_length          wolfSSL_EVP_CIPHER_iv_length
#define EVP_CIPHER_key_length         wolfSSL_EVP_Cipher_key_length
#define EVP_CIPHER_mode                 WOLFSSL_EVP_CIPHER_mode
#define EVP_CIPHER_name(x)              x
#define EVP_CIPHER_nid                  wolfSSL_EVP_CIPHER_nid
#define EVP_CIPH_CBC_MODE WOLFSSL_EVP_CIPH_CBC_MODE
#define EVP_CIPH_CCM_MODE WOLFSSL_EVP_CIPH_CCM_MODE
#define EVP_CIPH_CFB_MODE WOLFSSL_EVP_CIPH_CFB_MODE
#define EVP_CIPH_CTR_MODE WOLFSSL_EVP_CIPH_CTR_MODE
#define EVP_CIPH_ECB_MODE WOLFSSL_EVP_CIPH_ECB_MODE
#define EVP_CIPH_FLAG_AEAD_CIPHER WOLFSSL_EVP_CIPH_FLAG_AEAD_CIPHER
#define EVP_CIPH_GCM_MODE WOLFSSL_EVP_CIPH_GCM_MODE
#define EVP_CIPH_OFB_MODE WOLFSSL_EVP_CIPH_OFB_MODE
#define EVP_CIPH_STREAM_CIPHER WOLFSSL_EVP_CIPH_STREAM_CIPHER
#define EVP_CIPH_VARIABLE_LENGTH          0x200
#define EVP_CIPH_XTS_MODE WOLFSSL_EVP_CIPH_XTS_MODE
#define EVP_CTRL_AEAD_GET_TAG          0x10
#define EVP_CTRL_AEAD_SET_IVLEN        0x9
#define EVP_CTRL_AEAD_SET_IV_FIXED     0x12
#define EVP_CTRL_AEAD_SET_TAG          0x11
#define EVP_CTRL_GCM_GET_TAG           EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_GCM_IV_GEN            0x13
#define EVP_CTRL_GCM_SET_IVLEN         EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_GCM_SET_IV_FIXED      EVP_CTRL_AEAD_SET_IV_FIXED
#define EVP_CTRL_GCM_SET_TAG           EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_INIT                  0x0
#define EVP_CTRL_SET_KEY_LENGTH        0x1
#define EVP_CTRL_SET_RC2_KEY_BITS      0x3  
#define EVP_Cipher                    wolfSSL_EVP_Cipher
#define EVP_CipherFinal               wolfSSL_EVP_CipherFinal
#define EVP_CipherFinal_ex            wolfSSL_EVP_CipherFinal
#define EVP_CipherInit                wolfSSL_EVP_CipherInit
#define EVP_CipherInit_ex             wolfSSL_EVP_CipherInit_ex
#define EVP_CipherUpdate              wolfSSL_EVP_CipherUpdate
#define EVP_DecodeFinal      wolfSSL_EVP_DecodeFinal
#define EVP_DecodeInit       wolfSSL_EVP_DecodeInit
#define EVP_DecodeUpdate     wolfSSL_EVP_DecodeUpdate
#define EVP_DecryptFinal              wolfSSL_EVP_CipherFinal
#define EVP_DecryptFinal_ex           wolfSSL_EVP_CipherFinal
#define EVP_DecryptInit               wolfSSL_EVP_DecryptInit
#define EVP_DecryptInit_ex            wolfSSL_EVP_DecryptInit_ex
#define EVP_DecryptUpdate             wolfSSL_EVP_CipherUpdate
#define EVP_Digest             wolfSSL_EVP_Digest
#define EVP_DigestFinal        wolfSSL_EVP_DigestFinal
#define EVP_DigestFinal_ex     wolfSSL_EVP_DigestFinal_ex
#define EVP_DigestInit         wolfSSL_EVP_DigestInit
#define EVP_DigestInit_ex      wolfSSL_EVP_DigestInit_ex
#define EVP_DigestSignFinal    wolfSSL_EVP_DigestSignFinal
#define EVP_DigestSignInit     wolfSSL_EVP_DigestSignInit
#define EVP_DigestSignUpdate   wolfSSL_EVP_DigestSignUpdate
#define EVP_DigestUpdate       wolfSSL_EVP_DigestUpdate
#define EVP_DigestVerifyFinal  wolfSSL_EVP_DigestVerifyFinal
#define EVP_DigestVerifyInit   wolfSSL_EVP_DigestVerifyInit
#define EVP_DigestVerifyUpdate wolfSSL_EVP_DigestVerifyUpdate
#define EVP_ENCODE_CTX       WOLFSSL_EVP_ENCODE_CTX
#define EVP_ENCODE_CTX_free  wolfSSL_EVP_ENCODE_CTX_free
#define EVP_ENCODE_CTX_new   wolfSSL_EVP_ENCODE_CTX_new
#define EVP_EncodeFinal      wolfSSL_EVP_EncodeFinal
#define EVP_EncodeInit       wolfSSL_EVP_EncodeInit
#define EVP_EncodeUpdate     wolfSSL_EVP_EncodeUpdate
#define EVP_EncryptFinal              wolfSSL_EVP_CipherFinal
#define EVP_EncryptFinal_ex           wolfSSL_EVP_CipherFinal
#define EVP_EncryptInit               wolfSSL_EVP_EncryptInit
#define EVP_EncryptInit_ex            wolfSSL_EVP_EncryptInit_ex
#define EVP_EncryptUpdate             wolfSSL_EVP_CipherUpdate
    #define EVP_MAX_BLOCK_LENGTH   32  
    #define EVP_MAX_IV_LENGTH       16
#define EVP_MAX_KEY_LENGTH    64
    #define EVP_MAX_MD_SIZE   64     
#define EVP_MD_CTX_block_size   wolfSSL_EVP_MD_CTX_block_size
#define EVP_MD_CTX_cleanup      wolfSSL_EVP_MD_CTX_cleanup
#define EVP_MD_CTX_copy                wolfSSL_EVP_MD_CTX_copy
#define EVP_MD_CTX_copy_ex             wolfSSL_EVP_MD_CTX_copy_ex
#define EVP_MD_CTX_create       wolfSSL_EVP_MD_CTX_new
#define EVP_MD_CTX_destroy      wolfSSL_EVP_MD_CTX_free
#define EVP_MD_CTX_free         wolfSSL_EVP_MD_CTX_free
#define EVP_MD_CTX_init         wolfSSL_EVP_MD_CTX_init
#define EVP_MD_CTX_md           wolfSSL_EVP_MD_CTX_md
#define EVP_MD_CTX_new          wolfSSL_EVP_MD_CTX_new
#define EVP_MD_CTX_reset        wolfSSL_EVP_MD_CTX_cleanup

#define EVP_MD_CTX_size         wolfSSL_EVP_MD_CTX_size
#define EVP_MD_CTX_type         wolfSSL_EVP_MD_CTX_type
#define EVP_MD_name(x)                  x
#define EVP_MD_size             wolfSSL_EVP_MD_size
#define EVP_MD_type             wolfSSL_EVP_MD_type
#define EVP_PKEY_CTX_ctrl_str          wolfSSL_EVP_PKEY_CTX_ctrl_str
#define EVP_PKEY_CTX_new               wolfSSL_EVP_PKEY_CTX_new
#define EVP_PKEY_CTX_new_id            wolfSSL_EVP_PKEY_CTX_new_id
#define EVP_PKEY_CTX_set_rsa_keygen_bits wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits
#define EVP_PKEY_CTX_set_rsa_padding   wolfSSL_EVP_PKEY_CTX_set_rsa_padding
#define EVP_PKEY_DH                     28
#define EVP_PKEY_NONE                   NID_undef
#define EVP_PKEY_OP_DECRYPT (1 << 7)
#define EVP_PKEY_OP_DERIVE  (1 << 8)
#define EVP_PKEY_OP_ENCRYPT (1 << 6)
#define EVP_PKEY_OP_SIGN    (1 << 3)
#define EVP_PKEY_PRINT_INDENT_MAX    128
#define EVP_PKEY_assign                wolfSSL_EVP_PKEY_assign
#define EVP_PKEY_assign_DH             wolfSSL_EVP_PKEY_assign_DH
#define EVP_PKEY_assign_DSA            wolfSSL_EVP_PKEY_assign_DSA
#define EVP_PKEY_assign_EC_KEY         wolfSSL_EVP_PKEY_assign_EC_KEY
#define EVP_PKEY_assign_RSA            wolfSSL_EVP_PKEY_assign_RSA
#define EVP_PKEY_base_id               wolfSSL_EVP_PKEY_base_id
#define EVP_PKEY_bits                  wolfSSL_EVP_PKEY_bits
#define EVP_PKEY_cmp                   wolfSSL_EVP_PKEY_cmp
#define EVP_PKEY_copy_parameters       wolfSSL_EVP_PKEY_copy_parameters
#define EVP_PKEY_decrypt               wolfSSL_EVP_PKEY_decrypt
#define EVP_PKEY_decrypt_init          wolfSSL_EVP_PKEY_decrypt_init
#define EVP_PKEY_derive                wolfSSL_EVP_PKEY_derive
#define EVP_PKEY_derive_init           wolfSSL_EVP_PKEY_derive_init
#define EVP_PKEY_derive_set_peer       wolfSSL_EVP_PKEY_derive_set_peer
#define EVP_PKEY_encrypt               wolfSSL_EVP_PKEY_encrypt
#define EVP_PKEY_encrypt_init          wolfSSL_EVP_PKEY_encrypt_init
#define EVP_PKEY_free                  wolfSSL_EVP_PKEY_free
#define EVP_PKEY_get0_DH               wolfSSL_EVP_PKEY_get0_DH
#define EVP_PKEY_get0_EC_KEY           wolfSSL_EVP_PKEY_get0_EC_KEY
#define EVP_PKEY_get0_RSA              wolfSSL_EVP_PKEY_get0_RSA
#define EVP_PKEY_get0_hmac             wolfSSL_EVP_PKEY_get0_hmac
#define EVP_PKEY_get1_DH               wolfSSL_EVP_PKEY_get1_DH
#define EVP_PKEY_get1_DSA              wolfSSL_EVP_PKEY_get1_DSA
#define EVP_PKEY_get1_EC_KEY           wolfSSL_EVP_PKEY_get1_EC_KEY
#define EVP_PKEY_get1_RSA              wolfSSL_EVP_PKEY_get1_RSA
#define EVP_PKEY_get_default_digest_nid wolfSSL_EVP_PKEY_get_default_digest_nid
#define EVP_PKEY_id                    wolfSSL_EVP_PKEY_id
#define EVP_PKEY_keygen                wolfSSL_EVP_PKEY_keygen
#define EVP_PKEY_keygen_init           wolfSSL_EVP_PKEY_keygen_init
#define EVP_PKEY_missing_parameters    wolfSSL_EVP_PKEY_missing_parameters
#define EVP_PKEY_new                   wolfSSL_EVP_PKEY_new
#define EVP_PKEY_new_mac_key           wolfSSL_EVP_PKEY_new_mac_key
#define EVP_PKEY_print_private(arg1, arg2, arg3, arg4)
#define EVP_PKEY_print_public           wolfSSL_EVP_PKEY_print_public
#define EVP_PKEY_set1_DH               wolfSSL_EVP_PKEY_set1_DH
#define EVP_PKEY_set1_DSA              wolfSSL_EVP_PKEY_set1_DSA
#define EVP_PKEY_set1_EC_KEY           wolfSSL_EVP_PKEY_set1_EC_KEY
#define EVP_PKEY_set1_RSA              wolfSSL_EVP_PKEY_set1_RSA
#define EVP_PKEY_sign                  wolfSSL_EVP_PKEY_sign
#define EVP_PKEY_sign_init             wolfSSL_EVP_PKEY_sign_init
#define EVP_PKEY_size                  wolfSSL_EVP_PKEY_size
#define EVP_PKEY_type                  wolfSSL_EVP_PKEY_type
#define EVP_PKEY_up_ref                wolfSSL_EVP_PKEY_up_ref
#define EVP_R_BAD_DECRYPT               (-MIN_CODE_E + 100 + 1)
#define EVP_R_BN_DECODE_ERROR           (-MIN_CODE_E + 100 + 2)
#define EVP_R_DECODE_ERROR              (-MIN_CODE_E + 100 + 3)
#define EVP_R_PRIVATE_KEY_DECODE_ERROR  (-MIN_CODE_E + 100 + 4)
#define EVP_SignFinal                  wolfSSL_EVP_SignFinal
#define EVP_SignInit                   wolfSSL_EVP_SignInit
#define EVP_SignInit_ex                wolfSSL_EVP_SignInit_ex
#define EVP_SignUpdate                 wolfSSL_EVP_SignUpdate
#define EVP_VerifyFinal                wolfSSL_EVP_VerifyFinal
#define EVP_VerifyInit                 wolfSSL_EVP_VerifyInit
#define EVP_VerifyUpdate               wolfSSL_EVP_VerifyUpdate
#define EVP_add_cipher             wolfSSL_EVP_add_cipher
#define EVP_add_digest             wolfSSL_EVP_add_digest
#define EVP_aes_128_cbc    wolfSSL_EVP_aes_128_cbc
#define EVP_aes_128_cfb1   wolfSSL_EVP_aes_128_cfb1
#define EVP_aes_128_cfb128 wolfSSL_EVP_aes_128_cfb128
#define EVP_aes_128_cfb8   wolfSSL_EVP_aes_128_cfb8
#define EVP_aes_128_ctr    wolfSSL_EVP_aes_128_ctr
#define EVP_aes_128_ecb    wolfSSL_EVP_aes_128_ecb
#define EVP_aes_128_gcm    wolfSSL_EVP_aes_128_gcm
#define EVP_aes_128_ofb    wolfSSL_EVP_aes_128_ofb
#define EVP_aes_128_xts    wolfSSL_EVP_aes_128_xts
#define EVP_aes_192_cbc    wolfSSL_EVP_aes_192_cbc
#define EVP_aes_192_cfb1   wolfSSL_EVP_aes_192_cfb1
#define EVP_aes_192_cfb128 wolfSSL_EVP_aes_192_cfb128
#define EVP_aes_192_cfb8   wolfSSL_EVP_aes_192_cfb8
#define EVP_aes_192_ctr    wolfSSL_EVP_aes_192_ctr
#define EVP_aes_192_ecb    wolfSSL_EVP_aes_192_ecb
#define EVP_aes_192_gcm    wolfSSL_EVP_aes_192_gcm
#define EVP_aes_192_ofb    wolfSSL_EVP_aes_192_ofb
#define EVP_aes_256_cbc    wolfSSL_EVP_aes_256_cbc
#define EVP_aes_256_cfb1   wolfSSL_EVP_aes_256_cfb1
#define EVP_aes_256_cfb128 wolfSSL_EVP_aes_256_cfb128
#define EVP_aes_256_cfb8   wolfSSL_EVP_aes_256_cfb8
#define EVP_aes_256_ctr    wolfSSL_EVP_aes_256_ctr
#define EVP_aes_256_ecb    wolfSSL_EVP_aes_256_ecb
#define EVP_aes_256_gcm    wolfSSL_EVP_aes_256_gcm
#define EVP_aes_256_ofb    wolfSSL_EVP_aes_256_ofb
#define EVP_aes_256_xts    wolfSSL_EVP_aes_256_xts
#define EVP_cleanup                wolfSSL_EVP_cleanup
#define EVP_dds1          wolfSSL_EVP_sha1
#define EVP_des_cbc        wolfSSL_EVP_des_cbc
#define EVP_des_ecb        wolfSSL_EVP_des_ecb
#define EVP_des_ede3_cbc   wolfSSL_EVP_des_ede3_cbc
#define EVP_des_ede3_ecb   wolfSSL_EVP_des_ede3_ecb
#define EVP_enc_null       wolfSSL_EVP_enc_null
#define EVP_get_cipherbyname          wolfSSL_EVP_get_cipherbyname
#define EVP_get_cipherbynid           wolfSSL_EVP_get_cipherbynid
#define EVP_get_digestbyname          wolfSSL_EVP_get_digestbyname
#define EVP_get_digestbynid           wolfSSL_EVP_get_digestbynid
#define EVP_idea_cbc       wolfSSL_EVP_idea_cbc
    #define EVP_md4       wolfSSL_EVP_md4
    #define EVP_md5       wolfSSL_EVP_md5
#define EVP_mdc2          wolfSSL_EVP_mdc2
#define EVP_rc2_cbc                wolfSSL_EVP_rc2_cbc
#define EVP_rc4            wolfSSL_EVP_rc4
#define EVP_read_pw_string         wolfSSL_EVP_read_pw_string
#define EVP_ripemd160     wolfSSL_EVP_ripemd160
#define EVP_set_pw_prompt wolfSSL_EVP_set_pw_prompt
#define EVP_sha1          wolfSSL_EVP_sha1
#define EVP_sha224        wolfSSL_EVP_sha224
#define EVP_sha256        wolfSSL_EVP_sha256
#define EVP_sha384        wolfSSL_EVP_sha384
#define EVP_sha3_224    wolfSSL_EVP_sha3_224
#define EVP_sha3_256    wolfSSL_EVP_sha3_256
#define EVP_sha3_384    wolfSSL_EVP_sha3_384
#define EVP_sha3_512    wolfSSL_EVP_sha3_512
#define EVP_sha512        wolfSSL_EVP_sha512

#define NID_X9_62_id_ecPublicKey EVP_PKEY_EC
#define NID_dhKeyAgreement       EVP_PKEY_DH
#define NID_dsa                  EVP_PKEY_DSA
#define NID_rsaEncryption        EVP_PKEY_RSA
#define NO_PADDING_BLOCK_SIZE      1
#define OPENSSL_add_all_algorithms        OpenSSL_add_all_algorithms
#define OPENSSL_add_all_algorithms_conf   OpenSSL_add_all_algorithms_conf
#define OPENSSL_add_all_algorithms_noconf OpenSSL_add_all_algorithms_noconf
#define OpenSSL_add_all_algorithms wolfSSL_add_all_algorithms
#define OpenSSL_add_all_algorithms_conf   wolfSSL_OpenSSL_add_all_algorithms_conf
#define OpenSSL_add_all_algorithms_noconf wolfSSL_OpenSSL_add_all_algorithms_noconf
#define OpenSSL_add_all_ciphers()  wolfSSL_EVP_init()
#define OpenSSL_add_all_digests()  wolfSSL_EVP_init()
#define PKCS5_PBKDF2_HMAC          wolfSSL_PKCS5_PBKDF2_HMAC
#define PKCS5_PBKDF2_HMAC_SHA1     wolfSSL_PKCS5_PBKDF2_HMAC_SHA1
#define WOLFSSL_EVP_BUF_SIZE 16
#define WOLFSSL_EVP_CIPH_CBC_MODE           0x2
#define WOLFSSL_EVP_CIPH_CCM_MODE           0x7
#define WOLFSSL_EVP_CIPH_CFB_MODE           0x3
#define WOLFSSL_EVP_CIPH_CTR_MODE           0x5
#define WOLFSSL_EVP_CIPH_ECB_MODE           0x1
#define WOLFSSL_EVP_CIPH_FLAG_AEAD_CIPHER  0x20
#define WOLFSSL_EVP_CIPH_GCM_MODE           0x6
#define WOLFSSL_EVP_CIPH_MODE           0x0007
#define WOLFSSL_EVP_CIPH_NO_PADDING       0x100
#define WOLFSSL_EVP_CIPH_OFB_MODE           0x4
#define WOLFSSL_EVP_CIPH_STREAM_CIPHER      0x0
#define WOLFSSL_EVP_CIPH_TYPE_INIT         0xff
#define WOLFSSL_EVP_CIPH_XTS_MODE          0x10

#define wolfSSL_OPENSSL_add_all_algorithms_conf   wolfSSL_OpenSSL_add_all_algorithms_conf
#define wolfSSL_OPENSSL_add_all_algorithms_noconf wolfSSL_OpenSSL_add_all_algorithms_noconf





    #define HMAC_BLOCK_SIZE WC_HMAC_BLOCK_SIZE
    #define WC_HMAC_BLOCK_SIZE HMAC_BLOCK_SIZE
#define WC_HMAC_INNER_HASH_KEYED_DEV    2
#define WC_HMAC_INNER_HASH_KEYED_SW     1



#define CyaSSL_GetHmacMaxSize wolfSSL_GetHmacMaxSize
    #define HKDF wc_HKDF
    #define HmacAsyncFree wc_HmacAsyncFree
    #define HmacAsyncInit wc_HmacAsyncInit
#define HmacFinal  wc_HmacFinal
#define HmacSetKey wc_HmacSetKey
#define HmacUpdate wc_HmacUpdate
    #define MAX_DIGEST_SIZE WC_MAX_DIGEST_SIZE
    #define WC_MAX_BLOCK_SIZE  WC_SHA3_224_BLOCK_SIZE 
    #define WC_MAX_DIGEST_SIZE WC_SHA3_512_DIGEST_SIZE

    #define SHA3_224             WC_SHA3_224
    #define SHA3_224_DIGEST_SIZE WC_SHA3_224_DIGEST_SIZE
    #define SHA3_256             WC_SHA3_256
    #define SHA3_256_DIGEST_SIZE WC_SHA3_256_DIGEST_SIZE
    #define SHA3_384             WC_SHA3_384
    #define SHA3_384_DIGEST_SIZE WC_SHA3_384_DIGEST_SIZE
    #define SHA3_512             WC_SHA3_512
    #define SHA3_512_DIGEST_SIZE WC_SHA3_512_DIGEST_SIZE
    #define Sha3 wc_Sha3





    #define SHA384             WC_SHA384
    #define SHA384_BLOCK_SIZE  WC_SHA384_BLOCK_SIZE
    #define SHA384_DIGEST_SIZE WC_SHA384_DIGEST_SIZE
    #define SHA384_PAD_SIZE    WC_SHA384_PAD_SIZE
    #define SHA512             WC_SHA512
    #define SHA512_BLOCK_SIZE  WC_SHA512_BLOCK_SIZE
    #define SHA512_DIGEST_SIZE WC_SHA512_DIGEST_SIZE
    #define SHA512_NOINLINE __declspec(noinline)
    #define SHA512_PAD_SIZE    WC_SHA512_PAD_SIZE
    #define Sha384             wc_Sha384
    #define Sha512             wc_Sha512
        #define WC_SHA384             SHA384
        #define WC_SHA384_BLOCK_SIZE  SHA384_BLOCK_SIZE
        #define WC_SHA384_DIGEST_SIZE SHA384_DIGEST_SIZE
        #define WC_SHA384_PAD_SIZE    SHA384_PAD_SIZE

        #define WC_SHA512             SHA512
        #define WC_SHA512_BLOCK_SIZE  SHA512_BLOCK_SIZE
        #define WC_SHA512_DIGEST_SIZE SHA512_DIGEST_SIZE
        #define WC_SHA512_PAD_SIZE    SHA512_PAD_SIZE


        #define wc_Sha384             Sha384
        #define wc_Sha512             Sha512

    #define InitSha384   wc_InitSha384
#define InitSha512   wc_InitSha512
    #define Sha384Final  wc_Sha384Final
    #define Sha384Hash   wc_Sha384Hash
    #define Sha384Update wc_Sha384Update
#define Sha512Final  wc_Sha512Final
#define Sha512Hash   wc_Sha512Hash
#define Sha512Update wc_Sha512Update
    #define SHA             WC_SHA
    #define SHA_BLOCK_SIZE  WC_SHA_BLOCK_SIZE
    #define SHA_DIGEST_SIZE WC_SHA_DIGEST_SIZE
    #define SHA_PAD_SIZE    WC_SHA_PAD_SIZE
    #define Sha             wc_Sha
#define WC_SHA             SHA
#define WC_SHA_BLOCK_SIZE  SHA_BLOCK_SIZE
#define WC_SHA_DIGEST_SIZE SHA_DIGEST_SIZE
#define WC_SHA_PAD_SIZE    SHA_PAD_SIZE


#define wc_Sha             Sha

#define InitSha   wc_InitSha
#define ShaFinal  wc_ShaFinal
#define ShaHash   wc_ShaHash
#define ShaUpdate wc_ShaUpdate
    #define MD5             WC_MD5
    #define MD5_BLOCK_SIZE  WC_MD5_BLOCK_SIZE
    #define MD5_DIGEST_SIZE WC_MD5_DIGEST_SIZE
    #define Md5             wc_Md5
    #define WC_MD5_PAD_SIZE WC_MD5_PAD_SIZE

    #define wc_InitMd5   InitMd5
    #define wc_Md5Final  Md5Final
    #define wc_Md5Hash   Md5Hash
    #define wc_Md5Update Md5Update

    #define wc_Blake2bFinal  Blake2bFinal
    #define wc_Blake2bUpdate Blake2bUpdate
    #define wc_InitBlake2b   InitBlake2b




#define DES3_IVLEN 8
#define DES3_KEYLEN 24
#define DES_IVLEN 8
#define DES_KEYLEN 8


#define wc_Des3_EcbDecrypt wc_Des3_EcbEncrypt
#define wc_Des_EcbDecrypt  wc_Des_EcbEncrypt

    #define Des3AsyncFree wc_Des3AsyncFree
    #define Des3AsyncInit wc_Des3AsyncInit
#define Des3_CbcDecrypt        wc_Des3_CbcDecrypt
#define Des3_CbcDecryptWithKey wc_Des3_CbcDecryptWithKey
#define Des3_CbcEncrypt        wc_Des3_CbcEncrypt
#define Des3_SetIV             wc_Des3_SetIV
#define Des3_SetKey            wc_Des3_SetKey
#define Des_CbcDecrypt wc_Des_CbcDecrypt
#define Des_CbcDecryptWithKey  wc_Des_CbcDecryptWithKey
#define Des_CbcEncrypt wc_Des_CbcEncrypt
#define Des_EcbEncrypt wc_Des_EcbEncrypt
#define Des_SetIV      wc_Des_SetIV
#define Des_SetKey     wc_Des_SetKey



    #define AF_ALG 38
    #define SOL_ALG 279
#define WC_SOCK_NOTSET -1

#define AesCbcDecrypt        wc_AesCbcDecrypt
#define AesCbcDecryptWithKey wc_AesCbcDecryptWithKey
#define AesCbcEncrypt        wc_AesCbcEncrypt
    #define AesCcmDecrypt wc_AesCcmDecrypt
    #define AesCcmEncrypt wc_AesCcmEncrypt
    #define AesCcmSetKey  wc_AesCcmSetKey
    #define AesCtrEncrypt wc_AesCtrEncrypt
    #define AesDecryptDirect wc_AesDecryptDirect
    #define AesEncryptDirect wc_AesEncryptDirect
    #define AesGcmDecrypt wc_AesGcmDecrypt
    #define AesGcmEncrypt wc_AesGcmEncrypt
    #define AesGcmSetKey  wc_AesGcmSetKey
#define AesSetIV             wc_AesSetIV
#define AesSetKey            wc_AesSetKey
    #define AesSetKeyDirect  wc_AesSetKeyDirect

    #define GmacSetKey    wc_GmacSetKey
    #define GmacUpdate    wc_GmacUpdate
#define DH_CHECK_INVALID_Q_VALUE        0x10
#define DH_CHECK_P_NOT_PRIME            0x01
#define DH_CHECK_P_NOT_SAFE_PRIME       0x02
#define DH_CHECK_Q_NOT_PRIME            0x11
#define DH_GENERATOR_2                  2
#define DH_NOT_SUITABLE_GENERATOR       0x08
#define DH_bits(x)      (BN_num_bits(x->p))
#define DH_check        wolfSSL_DH_check
#define DH_compute_key  wolfSSL_DH_compute_key
#define DH_free wolfSSL_DH_free
#define DH_generate_key wolfSSL_DH_generate_key
#define DH_generate_parameters    wolfSSL_DH_generate_parameters
#define DH_generate_parameters_ex wolfSSL_DH_generate_parameters_ex
#define DH_get0_pqg     wolfSSL_DH_get0_pqg
#define DH_new  wolfSSL_DH_new
#define DH_set0_pqg     wolfSSL_DH_set0_pqg
#define DH_size         wolfSSL_DH_size

#define d2i_DHparams    wolfSSL_d2i_DHparams
#define get_rfc2409_prime_1024     wolfSSL_DH_1024_prime
#define get_rfc2409_prime_768      wolfSSL_DH_768_prime
#define get_rfc3526_prime_1536     wolfSSL_DH_1536_prime
#define get_rfc3526_prime_2048     wolfSSL_DH_2048_prime
#define get_rfc3526_prime_3072     wolfSSL_DH_3072_prime
#define get_rfc3526_prime_4096     wolfSSL_DH_4096_prime
#define get_rfc3526_prime_6144     wolfSSL_DH_6144_prime
#define get_rfc3526_prime_8192     wolfSSL_DH_8192_prime
#define i2d_DHparams    wolfSSL_i2d_DHparams
#define ECDSA_sign                      wolfSSL_ECDSA_sign
#define ECDSA_size                      wolfSSL_ECDSA_size
#define ECPoint_d2i                     wolfSSL_ECPoint_d2i
#define ECPoint_i2d                     wolfSSL_ECPoint_i2d
#define EC_GROUP_cmp                    wolfSSL_EC_GROUP_cmp
#define EC_GROUP_dup                    wolfSSL_EC_GROUP_dup
#define EC_GROUP_free                   wolfSSL_EC_GROUP_free
#define EC_GROUP_get_curve_name         wolfSSL_EC_GROUP_get_curve_name
#define EC_GROUP_get_degree             wolfSSL_EC_GROUP_get_degree
#define EC_GROUP_get_order              wolfSSL_EC_GROUP_get_order
#define EC_GROUP_method_of              wolfSSL_EC_GROUP_method_of
#define EC_GROUP_new_by_curve_name      wolfSSL_EC_GROUP_new_by_curve_name
#define EC_GROUP_order_bits             wolfSSL_EC_GROUP_order_bits
#define EC_GROUP_set_asn1_flag          wolfSSL_EC_GROUP_set_asn1_flag

#define EC_KEY_dup                      wolfSSL_EC_KEY_dup
#define EC_KEY_free                     wolfSSL_EC_KEY_free
#define EC_KEY_generate_key             wolfSSL_EC_KEY_generate_key
#define EC_KEY_get0_group               wolfSSL_EC_KEY_get0_group
#define EC_KEY_get0_private_key         wolfSSL_EC_KEY_get0_private_key
#define EC_KEY_get0_public_key          wolfSSL_EC_KEY_get0_public_key
#define EC_KEY_new                      wolfSSL_EC_KEY_new
#define EC_KEY_new_by_curve_name        wolfSSL_EC_KEY_new_by_curve_name
#define EC_KEY_set_asn1_flag            wolfSSL_EC_KEY_set_asn1_flag
#define EC_KEY_set_conv_form            wolfSSL_EC_KEY_set_conv_form
#define EC_KEY_set_group                wolfSSL_EC_KEY_set_group
#define EC_KEY_set_private_key          wolfSSL_EC_KEY_set_private_key
#define EC_KEY_set_public_key           wolfSSL_EC_KEY_set_public_key
#define EC_METHOD_get_field_type        wolfSSL_EC_METHOD_get_field_type
#define EC_POINT_add                    wolfSSL_EC_POINT_add
#define EC_POINT_clear_free             wolfSSL_EC_POINT_clear_free
#define EC_POINT_cmp                    wolfSSL_EC_POINT_cmp
#define EC_POINT_copy                   wolfSSL_EC_POINT_copy
#define EC_POINT_dump                   wolfSSL_EC_POINT_dump
#define EC_POINT_free                   wolfSSL_EC_POINT_free
#define EC_POINT_get_affine_coordinates_GFp \
                                     wolfSSL_EC_POINT_get_affine_coordinates_GFp
#define EC_POINT_invert                 wolfSSL_EC_POINT_invert
#define EC_POINT_is_at_infinity         wolfSSL_EC_POINT_is_at_infinity
#define EC_POINT_is_on_curve            wolfSSL_EC_POINT_is_on_curve
#define EC_POINT_mul                    wolfSSL_EC_POINT_mul
#define EC_POINT_new                    wolfSSL_EC_POINT_new
#define EC_POINT_oct2point              wolfSSL_EC_POINT_oct2point
#define EC_POINT_point2bn               wolfSSL_EC_POINT_point2bn
    #define EC_POINT_point2hex          wolfSSL_EC_POINT_point2hex
#define EC_POINT_point2oct              wolfSSL_EC_POINT_point2oct
#define EC_POINT_set_affine_coordinates_GFp \
                                     wolfSSL_EC_POINT_set_affine_coordinates_GFp
#define EC_curve_nid2nist               wolfSSL_EC_curve_nid2nist
#define EC_curve_nist2nid               wolfSSL_EC_curve_nist2nid
#define EC_get_builtin_curves           wolfSSL_EC_get_builtin_curves


#define WOLFSSL_EC_KEY_LOAD_PRIVATE 1
#define WOLFSSL_EC_KEY_LOAD_PUBLIC  2
#define d2i_ECPrivateKey                wolfSSL_d2i_ECPrivateKey
#define i2d_ECPrivateKey                wolfSSL_i2d_ECPrivateKey
#define i2d_EC_PUBKEY                   wolfSSL_i2o_ECPublicKey
#define i2o_ECPublicKey                 wolfSSL_i2o_ECPublicKey
    #define ECC_API    WOLFSSL_API
#define ECC_CUSTOM_IDX    (-1)
    #define ECC_MAX_PAD_SZ 2
    #define FP_MAX_BITS_ECC (2 * \
        ((MAX_ECC_BITS + DIGIT_BIT - 1) / DIGIT_BIT) * DIGIT_BIT)
#define FP_SIZE_ECC    ((FP_MAX_BITS_ECC/DIGIT_BIT) + 1)
    #define MAX_ECC_BITS    1024
    #define MAX_ECC_BYTES     (MAX_ECC_BITS / 8)
#define MAX_ECC_NAME 16
#define MAX_ECC_STRING ((MAX_ECC_BYTES * 2) + 1)



#define wc_ecc_get_curve_name_from_id wc_ecc_get_name
#define wc_ecc_shared_secret_ssh wc_ecc_shared_secret

    #define ATECC_GET_ENC_KEY(enckey, keysize) atmel_get_enc_key_default((enckey), (keysize))
#define ATECC_INVALID_SLOT  (0xFF)
#define ATECC_KEY_SIZE      (32)
#define ATECC_MAX_SLOT      (0x8) 
#define ATECC_PUBKEY_SIZE   (ATECC_KEY_SIZE*2) 
#define ATECC_SIG_SIZE      (ATECC_KEY_SIZE*2) 
#define ATECC_SLOT_AUTH_PRIV      (0x0)
#define ATECC_SLOT_ECDHE_PRIV     (0x2)
        #define ATECC_SLOT_ENC_PARENT     (0x6)
        #define ATECC_SLOT_I2C_ENC        (0x06)


#define ASN_GENERALIZED_TIME_MAX 68
#define ASN_GENERALIZED_TIME_SIZE 16
#define ASN_JOI_C               0x3
#define ASN_JOI_PREFIX          "\x2b\x06\x01\x04\x01\x82\x37\x3c\x02\x01"
#define ASN_JOI_PREFIX_SZ       10
#define ASN_JOI_ST              0x2
#define ASN_NAME_MAX WC_ASN_NAME_MAX
#define ASN_UTC_TIME_SIZE 14
    #define EXTERNAL_SERIAL_SIZE 32
#define EXTKEYUSE_ANY         0x01
#define EXTKEYUSE_CLIENT_AUTH 0x04
#define EXTKEYUSE_CODESIGN    0x08
#define EXTKEYUSE_EMAILPROT   0x10
#define EXTKEYUSE_OCSP_SIGN   0x40
#define EXTKEYUSE_SERVER_AUTH 0x02
#define EXTKEYUSE_TIMESTAMP   0x20
#define EXTKEYUSE_USER        0x80
#define KEYUSE_CONTENT_COMMIT 0x0040
#define KEYUSE_CRL_SIGN       0x0002
#define KEYUSE_DATA_ENCIPHER  0x0010
#define KEYUSE_DECIPHER_ONLY  0x8000
#define KEYUSE_DIGITAL_SIG    0x0080
#define KEYUSE_ENCIPHER_ONLY  0x0001
#define KEYUSE_KEY_AGREE      0x0008
#define KEYUSE_KEY_CERT_SIGN  0x0004
#define KEYUSE_KEY_ENCIPHER   0x0020
    #define MAX_KEY_SIZE    64  
#define MAX_NAME_ENTRIES WC_MAX_NAME_ENTRIES
    #define MAX_UNICODE_SZ  256
#define MIME_HEADER_ASCII_MAX   126
#define MIME_HEADER_ASCII_MIN   33
#define OCSP_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
    #define SIGNER_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
        #define WC_ASN_NAME_MAX 300
    #define WC_MAX_NAME_ENTRIES 13
    #define WC_SHA256_DIGEST_SIZE 32
    #define WOLFSSL_ASN_API WOLFSSL_API
#define WOLFSSL_BUS_CAT          "/businessCategory="
#define WOLFSSL_COMMON_NAME      "/CN="
#define WOLFSSL_COUNTRY_NAME     "/C="
#define WOLFSSL_DOMAIN_COMPONENT "/DC="
#define WOLFSSL_EMAIL_ADDR       "/emailAddress="
#define WOLFSSL_FAVOURITE_DRINK  "/favouriteDrink="
#define WOLFSSL_JOI_C            "/jurisdictionC="
#define WOLFSSL_JOI_ST           "/jurisdictionST="
#define WOLFSSL_LN_COMMON_NAME   "/commonName="
#define WOLFSSL_LN_COUNTRY_NAME  "/countryName="
    #define WOLFSSL_LN_DNS_SRV      "SRVName"
#define WOLFSSL_LN_DOMAIN_COMPONENT "/domainComponent="
#define WOLFSSL_LN_LOCALITY_NAME "/localityName="
    #define WOLFSSL_LN_MS_UPN       "Microsoft User Principal Name"
#define WOLFSSL_LN_ORGUNIT_NAME  "/organizationalUnitName="
#define WOLFSSL_LN_ORG_NAME      "/organizationName="
#define WOLFSSL_LN_STATE_NAME    "/stateOrProvinceName="
    #define WOLFSSL_LN_TLS_FEATURE  "TLS Feature"
#define WOLFSSL_LOCALITY_NAME    "/L="
    #define WOLFSSL_MAX_PATH_LEN 127
    #define WOLFSSL_MS_UPN_SUM 265
#define WOLFSSL_ORGUNIT_NAME     "/OU="
#define WOLFSSL_ORG_NAME         "/O="
#define WOLFSSL_SERIAL_NUMBER    "/serialNumber="
    #define WOLFSSL_SN_DNS_SRV      "id-on-dnsSRV"
    #define WOLFSSL_SN_MS_UPN       "msUPN"
    #define WOLFSSL_SN_TLS_FEATURE  "tlsfeature"
#define WOLFSSL_STATE_NAME       "/ST="
#define WOLFSSL_SUR_NAME         "/SN="
    #define WOLFSSL_TLS_FEATURE_SUM 92
#define WOLFSSL_USER_ID          "/UID="

    #define CTC_MAX_ATTRIB 4
        #define CTC_MAX_EKU_NB 1
        #define CTC_MAX_EKU_OID_SZ 30
    #define WC_CTC_MAX_ALT_SIZE 16384
    #define WC_CTC_NAME_SIZE 64




#define WOLFSSL_ASN1_INTEGER_MAX 20

#define DsaKeyToDer wc_DsaKeyToDer
#define DsaPrivateKeyDecode wc_DsaPrivateKeyDecode
#define DsaPublicKeyDecode wc_DsaPublicKeyDecode
#define DsaSign wc_DsaSign
#define DsaVerify wc_DsaVerify
#define FreeDsaKey wc_FreeDsaKey
#define InitDsaKey wc_InitDsaKey



    #define CheckProbablePrime wc_CheckProbablePrime
#define FreeRsaKey       wc_FreeRsaKey
#define InitRsaKey       wc_InitRsaKey
    #define MakeRsaKey  wc_MakeRsaKey
    #define RsaAsyncFree wc_RsaAsyncFree
    #define RsaAsyncInit wc_RsaAsyncInit
#define RsaEncryptSize          wc_RsaEncryptSize
#define RsaFlattenPublicKey     wc_RsaFlattenPublicKey
    #define RsaKeyToDer wc_RsaKeyToDer
#define RsaPrivateDecrypt       wc_RsaPrivateDecrypt
#define RsaPrivateDecryptInline wc_RsaPrivateDecryptInline
#define RsaPublicEncrypt wc_RsaPublicEncrypt
#define RsaSSL_Sign             wc_RsaSSL_Sign
#define RsaSSL_Verify           wc_RsaSSL_Verify
#define RsaSSL_VerifyInline     wc_RsaSSL_VerifyInline




        #define  CYASSL_DER_LOAD
        #define  CYASSL_DTLS
        #define CYASSL_GENERAL_ALIGNMENT 16



    #define CYASSL_MMCAU_ALIGNMENT 4










    #define NO_CYASSL_DIR  












    #define MakeNtruCert wc_MakeNtruCert



#define WC_MGF1NONE   0
#define WC_MGF1SHA1   26
#define WC_MGF1SHA224 4
#define WC_MGF1SHA256 1
#define WC_MGF1SHA384 2
#define WC_MGF1SHA512 3
    #define WC_RSA_EXPONENT 65537L
#define WC_RSA_NO_PAD      3
#define WC_RSA_OAEP_PAD    1
#define WC_RSA_PKCSV15_PAD 0
#define WC_RSA_PSS_PAD     2


#define RIPEMD_Final  wolfSSL_RIPEMD_Final
#define RIPEMD_Init   wolfSSL_RIPEMD_Init
#define RIPEMD_Update wolfSSL_RIPEMD_Update

    #define SHA3_224 wolfSSL_SHA3_224
#define SHA3_224_Final  wolfSSL_SHA3_224_Final
#define SHA3_224_Init   wolfSSL_SHA3_224_Init
#define SHA3_224_Update wolfSSL_SHA3_224_Update
    #define SHA3_256 wolfSSL_SHA3_256
#define SHA3_256_Final  wolfSSL_SHA3_256_Final
#define SHA3_256_Init   wolfSSL_SHA3_256_Init
#define SHA3_256_Update wolfSSL_SHA3_256_Update
    #define SHA3_384 wolfSSL_SHA3_384
#define SHA3_384_Final  wolfSSL_SHA3_384_Final
#define SHA3_384_Init   wolfSSL_SHA3_384_Init
#define SHA3_384_Update wolfSSL_SHA3_384_Update
    #define SHA3_512 wolfSSL_SHA3_512
#define SHA3_512_Final  wolfSSL_SHA3_512_Final
#define SHA3_512_Init   wolfSSL_SHA3_512_Init
#define SHA3_512_Update wolfSSL_SHA3_512_Update

    #define SHA wolfSSL_SHA1
#define SHA1_Final wolfSSL_SHA1_Final
#define SHA1_Init wolfSSL_SHA1_Init
#define SHA1_Transform wolfSSL_SHA1_Transform
#define SHA1_Update wolfSSL_SHA1_Update
    #define SHA224 wolfSSL_SHA224
#define SHA224_Final  wolfSSL_SHA224_Final
#define SHA224_Init   wolfSSL_SHA224_Init
#define SHA224_Update wolfSSL_SHA224_Update
    #define SHA256 wolfSSL_SHA256
#define SHA256_Final  wolfSSL_SHA256_Final
#define SHA256_Init   wolfSSL_SHA256_Init
#define SHA256_Transform wolfSSL_SHA256_Transform
#define SHA256_Update wolfSSL_SHA256_Update
    #define SHA384 wolfSSL_SHA384
#define SHA384_Final  wolfSSL_SHA384_Final
#define SHA384_Init   wolfSSL_SHA384_Init
#define SHA384_Update wolfSSL_SHA384_Update
    #define SHA512 wolfSSL_SHA512
#define SHA512_Final  wolfSSL_SHA512_Final
#define SHA512_Init   wolfSSL_SHA512_Init
#define SHA512_Transform wolfSSL_SHA512_Transform
#define SHA512_Update wolfSSL_SHA512_Update
#define SHA_Final wolfSSL_SHA_Final
#define SHA_Init wolfSSL_SHA_Init
#define SHA_Transform wolfSSL_SHA_Transform
#define SHA_Update wolfSSL_SHA_Update

#define MD5(d, n, md) wc_Md5Hash((d), (n), (md))
    #define MD5Final wolfSSL_MD5_Final
    #define MD5Init wolfSSL_MD5_Init
    #define MD5Update wolfSSL_MD5_Update
#define MD5_DIGEST_LENGTH MD5_DIGEST_SIZE
#define MD5_Final wolfSSL_MD5_Final
#define MD5_Init wolfSSL_MD5_Init
#define MD5_Transform wolfSSL_MD5_Transform
#define MD5_Update wolfSSL_MD5_Update


#define X509_FLAG_COMPAT        (0UL)
#define X509_FLAG_NO_ATTRIBUTES (1UL << 11)
#define X509_FLAG_NO_AUX        (1UL << 10)
#define X509_FLAG_NO_EXTENSIONS (1UL << 8)
#define X509_FLAG_NO_HEADER     (1UL << 0)
#define X509_FLAG_NO_IDS        (1UL << 12)
#define X509_FLAG_NO_ISSUER     (1UL << 4)
#define X509_FLAG_NO_PUBKEY     (1UL << 7)
#define X509_FLAG_NO_SERIAL     (1UL << 2)
#define X509_FLAG_NO_SIGDUMP    (1UL << 9)
#define X509_FLAG_NO_SIGNAME    (1UL << 3)
#define X509_FLAG_NO_SUBJECT    (1UL << 6)
#define X509_FLAG_NO_VALIDITY   (1UL << 5)
#define X509_FLAG_NO_VERSION    (1UL << 1)
#define XN_FLAG_COMPAT          0
#define XN_FLAG_DN_REV          (1 << 20)
#define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)
#define XN_FLAG_FN_ALIGN        (1 << 25)
#define XN_FLAG_FN_LN           (1 << 21)
#define XN_FLAG_FN_MASK         (3 << 21)
#define XN_FLAG_FN_NONE         (3 << 21)
#define XN_FLAG_FN_OID          (2 << 21)
#define XN_FLAG_FN_SN           0
#define XN_FLAG_MULTILINE       0xFFFF
#define XN_FLAG_ONELINE         0
#define XN_FLAG_RFC2253         1
#define XN_FLAG_SEP_COMMA_PLUS  (1 << 16)
#define XN_FLAG_SEP_CPLUS_SPC   (2 << 16)
#define XN_FLAG_SEP_MASK        (0xF << 16)
#define XN_FLAG_SEP_MULTILINE   (4 << 16)
#define XN_FLAG_SEP_SPLUS_SPC   (3 << 16)
#define XN_FLAG_SPC_EQ          (1 << 23)
#define PEM_write_bio_PKCS7            wolfSSL_PEM_write_bio_PKCS7
#define PKCS7_NOINTERN         0x0010
#define PKCS7_NOVERIFY         0x0020
#define PKCS7_SIGNED_free              wolfSSL_PKCS7_SIGNED_free
#define PKCS7_SIGNED_new               wolfSSL_PKCS7_SIGNED_new
#define PKCS7_free                     wolfSSL_PKCS7_free
#define PKCS7_get0_signers             wolfSSL_PKCS7_get0_signers
#define PKCS7_new                      wolfSSL_PKCS7_new
#define PKCS7_verify                   wolfSSL_PKCS7_verify
#define SMIME_read_PKCS7               wolfSSL_SMIME_read_PKCS7

#define d2i_PKCS7                      wolfSSL_d2i_PKCS7
#define d2i_PKCS7_bio                  wolfSSL_d2i_PKCS7_bio
#define i2d_PKCS7_bio                  wolfSSL_i2d_PKCS7_bio
#define DEGENERATE_SID 3
    #define MAX_AUTH_ATTRIBS_SZ 7
    #define MAX_ORI_TYPE_SZ  MAX_OID_SZ
    #define MAX_ORI_VALUE_SZ 512
    #define MAX_PKCS7_CERTS 15
    #define MAX_SIGNED_ATTRIBS_SZ 7
    #define MAX_UNAUTH_ATTRIBS_SZ 7

        #define CCM_NONCE_MIN_SZ 7
        #define GCM_NONCE_MID_SZ 12
    #define WC_MAX_SYM_KEY_SIZE     (AES_MAX_KEY_SIZE/8)

#define CHACHA_CHUNK_BYTES (CHACHA_CHUNK_WORDS * sizeof(word32))
#define CHACHA_CHUNK_WORDS 16
#define CHACHA_IV_BYTES 12
#define CHACHA_IV_WORDS    3
#define CHACHA_MATRIX_CNT_IV 12


#define XCHACHA_NONCE_BYTES 24
#define ECDSA_SIG_free         wolfSSL_ECDSA_SIG_free
#define ECDSA_SIG_new          wolfSSL_ECDSA_SIG_new
#define ECDSA_do_sign          wolfSSL_ECDSA_do_sign
#define ECDSA_do_verify        wolfSSL_ECDSA_do_verify

#define d2i_ECDSA_SIG          wolfSSL_d2i_ECDSA_SIG
#define i2d_ECDSA_SIG          wolfSSL_i2d_ECDSA_SIG
#define TLS_MAX_VERSION                 TLS1_3_VERSION


        #define CloseSocket(s) closesocket(s)

            #define LWIP_PROVIDE_ERRNO 1
    #define RECV_FUNCTION net_recv
    #define SEND_FUNCTION net_send
    #define SOCKET_EAGAIN      WSAETIMEDOUT
    #define SOCKET_ECONNABORTED WSAECONNABORTED
    #define SOCKET_ECONNREFUSED WSAENOTCONN
    #define SOCKET_ECONNRESET  WSAECONNRESET
    #define SOCKET_EINTR       WSAEINTR
    #define SOCKET_EPIPE       WSAEPIPE
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
        #define SOCKET_INVALID INVALID_SOCKET
    #define StartTCP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }


    #define WOLFSSL_IP4 AF_INET
    #define WOLFSSL_IP6 AF_INET6
        #define WSAEPIPE       -12345
            #define XHTONS(a) (a)
        #define XINET_NTOP(a,b,c,d) InetNtop((a),(b),(c),(d))
        #define XINET_PTON(a,b,c)   InetPton((a),(b),(c))
            #define XNTOHS(a) (a)
            #define XSOCKLENT int
#define wolfSSL_SetIORecv wolfSSL_CTX_SetIORecv
#define wolfSSL_SetIOSend wolfSSL_CTX_SetIOSend
#define HMAC(a,b,c,d,e,f,g) wolfSSL_HMAC((a),(b),(c),(d),(e),(f),(g))
#define HMAC_CTX_cleanup wolfSSL_HMAC_CTX_cleanup
#define HMAC_CTX_copy wolfSSL_HMAC_CTX_copy
#define HMAC_CTX_free wolfSSL_HMAC_CTX_free
#define HMAC_CTX_init wolfSSL_HMAC_CTX_Init
#define HMAC_CTX_new wolfSSL_HMAC_CTX_new
#define HMAC_CTX_reset wolfSSL_HMAC_cleanup
#define HMAC_Final    wolfSSL_HMAC_Final
#define HMAC_Init     wolfSSL_HMAC_Init
#define HMAC_Init_ex  wolfSSL_HMAC_Init_ex
#define HMAC_Update   wolfSSL_HMAC_Update
#define HMAC_cleanup  wolfSSL_HMAC_cleanup
#define HMAC_size     wolfSSL_HMAC_size

    #define Timeval WOLFSSL_TIMEVAL

#define CRYPTO_CB_VER   2

#define wc_CryptoDev_RegisterDevice   wc_CryptoCb_RegisterDevice
#define wc_CryptoDev_UnRegisterDevice wc_CryptoCb_UnRegisterDevice
#define CURVE25519_KEYSIZE 32






    #define F25519_SIZE 32

#define ED25519_KEY_SIZE     32 
#define ED25519_PRV_KEY_SIZE (ED25519_PUB_KEY_SIZE+ED25519_KEY_SIZE)
#define ED25519_PUB_KEY_SIZE 32 
#define ED25519_SIG_SIZE     64



#define WC_CMAC_TAG_MAX_SZ AES_BLOCK_SIZE
#define WC_CMAC_TAG_MIN_SZ (AES_BLOCK_SIZE/4)



#define CAAM_AESCBC 0x00100100
#define CAAM_AESCCM 0x00100800
#define CAAM_AESCFB 0x00100300
#define CAAM_AESCTR 0x00100000
#define CAAM_AESECB 0x00100200
#define CAAM_AESOFB 0x00100400
#define CAAM_ALG_FINAL  0x00000008
#define CAAM_ALG_INIT   0x00000004
#define CAAM_ALG_INITF  0x0000000C
#define CAAM_ALG_UPDATE 0x00000000
#define CAAM_BLOB_DECAP 0x06000000
#define CAAM_BLOB_ENCAP 0x07000000
#define CAAM_CMAC   0x00100600
#define CAAM_DEC    0x00000000
#define CAAM_ECDSA_BRAINPOOL_P256 (0x0B << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_ECDH    0x00170000
#define CAAM_ECDSA_KEYGEN_PD 0x02000000
#define CAAM_ECDSA_KEYPAIR 0x00140000
#define CAAM_ECDSA_P192 (0x00 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P224 (0x01 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P256 (0x02 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P384 (0x03 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P521 (0x04 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_PD 0x00400000
#define CAAM_ECDSA_SIGN    0x00150000
#define CAAM_ECDSA_VERIFY  0x00160000
#define CAAM_ECDSEL_SHIFT 7
#define CAAM_ENC    0x00000001
#define CAAM_ENTROPY 0x00500001
#define CAAM_FIFO_CCM_FLAG 0x00140000
#define CAAM_FIFO_S   0x60000000
#define CAAM_FIND_PART 0xFFFFFFFF
#define CAAM_FREE_PART 0xFFFFFFFD
#define CAAM_GET_PART 0xFFFFFFFE
#define CAAM_HMAC_MD5    0x00400010
#define CAAM_HMAC_SHA    0x00410010
#define CAAM_HMAC_SHA224 0x00420010
#define CAAM_HMAC_SHA256 0x00430010
#define CAAM_HMAC_SHA384 0x00440010
#define CAAM_HMAC_SHA512 0x00450010
#define CAAM_MD5    0x00400000
#define CAAM_READ_PART 0xFFFFFFFC
#define CAAM_SHA    0x00410000
#define CAAM_SHA224 0x00420000
#define CAAM_SHA256 0x00430000
#define CAAM_SHA384 0x00440000
#define CAAM_SHA512 0x00450000
#define CAAM_WRITE_PART 0xFFFFFFFB
#define WC_CAAM_BLACK_KEYMOD_SZ 16
#define WC_CAAM_BLOB_BLACK 2
#define WC_CAAM_BLOB_RED   1
#define WC_CAAM_BLOB_SZ 48
#define WC_CAAM_MAC_SZ 16
#define WC_CAAM_MAX_ENTROPY 44
        #define WC_CAAM_READ(reg)      wc_caamReadRegister((reg))
#define WC_CAAM_RED_KEYMOD_SZ 8
        #define WC_CAAM_WRITE(reg, x)  wc_caamWriteRegister((reg), (x))

#define Boolean int
#define CAAM_ADDRESS unsigned int
#define CAAM_BASE 0x02140000
#define CAAM_FREE_INTERFACE wc_CAAMFreeInterface
#define CAAM_INIT_INTERFACE wc_CAAMInitInterface
#define CAAM_PAGE 0x00100000
#define CAAM_SEND_REQUEST(type, sz, arg, buf) \
        SynchronousSendRequest((type), (arg), (buf), (sz))
#define CAAM_WAITING -2
#define DataBuffer 0
#define Error int
#define Failure 0

#define LastBuffer 0
#define MemoryMapMayNotBeEmpty -1
#define MemoryOperationNotPerformed -1
#define NoActivityReady -1
#define ResourceNotAvailable -3
#define Success 1
#define Value int


#define WOLFSSL_CAAM_DEVID 7


#define ED448_KEY_SIZE     57   
#define ED448_PRV_KEY_SIZE (ED448_PUB_KEY_SIZE+ED448_KEY_SIZE)
#define ED448_PUB_KEY_SIZE 57   
#define ED448_SIG_SIZE     114  


    #define GE448_WORDS    56





    #define ByteReverseWord32(value) _builtin_revl(value)
    #define WC_STATIC static



        #define max max
        #define min min
    #define rotlFixed(x, y) _builtin_rotl(x, y)
    #define rotrFixed(x, y) _builtin_rotr(x, y)


