#include<inttypes.h>

#include<errno.h>





#include<assert.h>

#include<limits.h>

#include<string.h>





#include<sys/types.h>


#include<stdlib.h>


#include<stdarg.h>
#include<time.h>


#include<fcntl.h>
#include<stdio.h>

#include<ctype.h>




#include<unistd.h>

#define MAX_FILE_SIZE 65535
#define SC_ALGORITHM_EXT_EC_COMPRESS     0x00000020
#define SC_ALGORITHM_EXT_EC_ECPARAMETERS 0x00000004
#define SC_ALGORITHM_EXT_EC_F_2M         0x00000002
#define SC_ALGORITHM_EXT_EC_F_P          0x00000001
#define SC_ALGORITHM_EXT_EC_NAMEDCURVE   0x00000008
#define SC_ALGORITHM_EXT_EC_UNCOMPRESES  0x00000010
#define SC_ALGORITHM_RAW_MASK (SC_ALGORITHM_RSA_RAW | \
                               SC_ALGORITHM_GOSTR3410_RAW | \
                               SC_ALGORITHM_ECDH_CDH_RAW | \
                               SC_ALGORITHM_ECDSA_RAW)
#define SC_FORMAT_LEN_PTRDIFF_T "I"
#define SC_FORMAT_LEN_SIZE_T "I"
#define SC_IMPLEMENT_DRIVER_VERSION(a) \
	static const char *drv_version = (a); \
	const char *sc_driver_version()\
	{ \
		return drv_version; \
	}
#define SC_PIN_STATE_LOGGED_IN  1
#define SC_PIN_STATE_LOGGED_OUT 0
#define SC_READER_CAP_PACE_DESTROY_CHANNEL 0x00000010
#define SC_READER_CAP_PACE_EID             0x00000004
#define SC_READER_CAP_PACE_ESIGN           0x00000008
#define SC_READER_CAP_PACE_GENERIC         0x00000020
#define SC_READER_SHORT_APDU_MAX_RECV_SIZE 256
#define SC_READER_SHORT_APDU_MAX_SEND_SIZE 255
#define SC_SEC_ENV_TARGET_FILE_REF_PRESENT 0x0020
#define SC_SEC_OPERATION_DERIVE         0x0004

#define SM_MAX_DATA_SIZE    0xE0


#define SC_AC_IDA                       0x00000080 
#define SC_AC_SCB                       0x00000040 
#define SC_AC_SEN                       0x00000020 
#define SC_MAX_SERIALNR         32




#   define simclist_inline  inline           
#   define simclist_restrict  restrict

#define COMPRESSION_UNKNOWN (-1)
#define ENTERSAFE_AC_ALWAYS 0x10
#define ENTERSAFE_AC_CHV 0x30
#define ENTERSAFE_AC_EVERYONE 0x00
#define ENTERSAFE_AC_NEVER 0xC0
#define ENTERSAFE_AC_USER 0x04
#define ENTERSAFE_MAX_KEY_ID 0x09
#define ENTERSAFE_MIN_KEY_ID 0x01
#define ENTERSAFE_SO_PIN_ID 0x02
#define ENTERSAFE_USER_PIN_ID  0x01
#define FID_STEP 0x20
#define SC_CARDCTL_COOLKEY_ATTR_TYPE_STRING 0
#define SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG 1
#define SC_CARDCTL_COOLKEY_FIND_BY_ID       0
#define SC_CARDCTL_COOLKEY_FIND_BY_TEMPLATE 1
#define SC_ISOAPPLET_ALG_REF_EC_GEN 0xEC
#define SC_ISOAPPLET_ALG_REF_RSA_GEN_2048 0xF3
#define SC_RTECP_SEC_ATTR_SIZE 15
#define SC_RUTOKEN_ALLTYPE_GCHV          SC_RUTOKEN_TYPE_CHV	
#define SC_RUTOKEN_ALLTYPE_GOST          SC_RUTOKEN_TYPE_KEY	
#define SC_RUTOKEN_ALLTYPE_LCHV          0x11        			
#define SC_RUTOKEN_ALLTYPE_SE            SC_RUTOKEN_TYPE_SE		
#define SC_RUTOKEN_COMPACT_DO_MAX_LEN  16          
#define SC_RUTOKEN_CURTRY_MASK           0x0F        
#define SC_RUTOKEN_DEF_ID_GCHV_ADMIN       0x01      
#define SC_RUTOKEN_DEF_ID_GCHV_USER        0x02      
#define SC_RUTOKEN_DEF_LEN_DO_GOST         32
#define SC_RUTOKEN_DEF_LEN_DO_SE           6
#define SC_RUTOKEN_DO_ALL_MIN_ID       0x1         
#define SC_RUTOKEN_DO_CHV_MAX_ID       0x1F        
#define SC_RUTOKEN_DO_CHV_MAX_ID_V2       SC_RUTOKEN_DEF_ID_GCHV_USER	
#define SC_RUTOKEN_DO_HDR_LEN  32
#define SC_RUTOKEN_DO_NOCHV_MAX_ID     0x7F        
#define SC_RUTOKEN_DO_NOCHV_MAX_ID_V2     SC_RUTOKEN_DO_NOCHV_MAX_ID	
#define SC_RUTOKEN_DO_PART_BODY_LEN    199    
#define SC_RUTOKEN_FLAGS_BLEN_OPEN_DO    0x2
#define SC_RUTOKEN_FLAGS_COMPACT_DO      0x1
#define SC_RUTOKEN_FLAGS_FULL_OPEN_DO    0x6
#define SC_RUTOKEN_FLAGS_OPEN_DO_MASK    0x6
#define SC_RUTOKEN_ID_CURDF_RESID_FLAG   0x80        
#define SC_RUTOKEN_MAXTRY_MASK           0xF0        
#define SC_RUTOKEN_OPTIONS_GACCESS_ADMIN     SC_RUTOKEN_DEF_ID_GCHV_ADMIN   
#define SC_RUTOKEN_OPTIONS_GACCESS_USER      SC_RUTOKEN_DEF_ID_GCHV_USER    
#define SC_RUTOKEN_OPTIONS_GCHV_ACCESS_MASK  0x7     
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMM   0x1     
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMMOS 0x2     
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_MASK   0x7     
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_PZ     0x0     
#define SC_RUTOKEN_TYPE_CHV              0x1
#define SC_RUTOKEN_TYPE_KEY              0x2
#define SC_RUTOKEN_TYPE_MASK             0xF
#define SC_RUTOKEN_TYPE_SE               0x0
#define _CTL_PREFIX(a, b, c) (((a) << 24) | ((b) << 16) | ((c) << 8))

#define SC_ASN1_BIT_STRING              3
#define SC_ASN1_BIT_STRING_NI           128
#define SC_ASN1_BOOLEAN                 1
#define SC_ASN1_EMPTY_ALLOWED           0x00000010
#define SC_ASN1_ENUMERATED              10
#define SC_ASN1_GENERALIZEDTIME         24
#define SC_ASN1_INTEGER                 2
#define SC_ASN1_NULL                    5
#define SC_ASN1_OBJECT                  6
#define SC_ASN1_OCTET_STRING            4
#define SC_ASN1_PRINTABLESTRING         19
#define SC_ASN1_SEQUENCE                16
#define SC_ASN1_SET                     17
#define SC_ASN1_UTCTIME                 23
#define SC_ASN1_UTF8STRING              12

#define SC_PKCS15_ACCESS_RULE_MODE_ATTRIBUTE    0x10
#define SC_PKCS15_ACCESS_RULE_MODE_DELETE       0x08
#define SC_PKCS15_ACCESS_RULE_MODE_EXECUTE      0x04
#define SC_PKCS15_ACCESS_RULE_MODE_EXT_AUTH     0x400
#define SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH     0x200
#define SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS      0x20
#define SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT  0x80
#define SC_PKCS15_ACCESS_RULE_MODE_PSO_ENCRYPT  0x100
#define SC_PKCS15_ACCESS_RULE_MODE_PSO_VERIFY   0x40
#define SC_PKCS15_ACCESS_RULE_MODE_READ         0x01
#define SC_PKCS15_ACCESS_RULE_MODE_UPDATE       0x02
#define SC_PKCS15_GOSTR3410_KEYSIZE             256
#define SC_PKCS15_MAX_ACCESS_RULES      8
#define SC_PKCS15_PARAMSET_GOSTR3410_A          1
#define SC_PKCS15_PARAMSET_GOSTR3410_B          2
#define SC_PKCS15_PARAMSET_GOSTR3410_C          3
#define SC_PKCS15_TYPE_TO_CLASS(t)		(1 << ((t) >> 8))
#define SC_X509_CRL_SIGN              0x0040UL
#define SC_X509_DATA_ENCIPHERMENT     0x0008UL
#define SC_X509_DECIPHER_ONLY         0x0100UL
#define SC_X509_DIGITAL_SIGNATURE     0x0001UL
#define SC_X509_ENCIPHER_ONLY         0x0080UL
#define SC_X509_KEY_AGREEMENT         0x0010UL
#define SC_X509_KEY_CERT_SIGN         0x0020UL
#define SC_X509_KEY_ENCIPHERMENT      0x0004UL
#define SC_X509_NON_REPUDIATION       0x0002UL

#define sc_pkcs15_skey sc_pkcs15_data
#define sc_pkcs15_skey_t sc_pkcs15_data_t

#define BYTES4BITS(num)  (((num) + 7) / 8)    
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define msleep(t)	usleep((t) * 1000)
#define sc_apdu_log(ctx, data, len, is_outgoing) \
	sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, is_outgoing != 0 ? "Outgoing APDU" : "Incoming APDU", data, len)
#define ASN1_STRING_get0_data(x)	ASN1_STRING_data(x)
#define EC_POINT_get_affine_coordinates_GFp     EC_POINT_get_affine_coordinates
#define EC_POINT_set_affine_coordinates_GFp     EC_POINT_set_affine_coordinates
#define ENGINE_load_dynamic(x)     while (0) continue
#define ERR_free_strings(x)        while (0) continue
#define ERR_load_crypto_strings(x) while (0) continue
#define EVP_CIPHER_CTX_cleanup(x) EVP_CIPHER_CTX_reset(x)
#define EVP_CIPHER_CTX_init(x) EVP_CIPHER_CTX_reset(x)
#define EVP_PKEY_base_id(x)		(x->type)
#define EVP_PKEY_get0_DSA(x)		(x->pkey.dsa)
#define EVP_PKEY_get0_EC_KEY(x)		(x->pkey.ec)
#define EVP_PKEY_get0_RSA(x)		(x->pkey.rsa)
#define EVP_PKEY_up_ref(user_key)	CRYPTO_add(&user_key->references, 1, CRYPTO_LOCK_EVP_PKEY)

#define RSA_bits(R) (BN_num_bits(R->n))
#define SSL_load_error_strings(x)  while (0) continue
#define X509_get_extended_key_usage(x)	(x->ex_xkusage)
#define X509_get_extension_flags(x)	(x->ex_flags)
#define X509_get_key_usage(x)		(x->ex_kusage)
#define X509_up_ref(cert)		CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509)

#   define sc_ossl_inline inline

#define LOG_FUNC_CALLED(ctx) SC_FUNC_CALLED((ctx), SC_LOG_DEBUG_NORMAL)
#define LOG_FUNC_RETURN(ctx, r) SC_FUNC_RETURN((ctx), SC_LOG_DEBUG_NORMAL, (r))
#define LOG_TEST_GOTO_ERR(ctx, r, text) SC_TEST_GOTO_ERR((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))
#define LOG_TEST_RET(ctx, r, text) SC_TEST_RET((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))
#define SC_COLOR_FG_CYAN   		0x0020
#define SC_FUNC_CALLED(ctx, level) do { \
	 sc_do_log(ctx, level, "__FILE__", "__LINE__", __FUNCTION__, "called\n"); \
} while (0)
#define SC_FUNC_RETURN(ctx, level, r) do { \
	int _ret = r; \
	if (_ret <= 0) { \
		sc_do_log_color(ctx, level, "__FILE__", "__LINE__", __FUNCTION__, _ret ? SC_COLOR_FG_RED : 0, \
			"returning with: %d (%s)\n", _ret, sc_strerror(_ret)); \
	} else { \
		sc_do_log(ctx, level, "__FILE__", "__LINE__", __FUNCTION__, \
			"returning with: %d\n", _ret); \
	} \
	return _ret; \
} while(0)
#define SC_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#define SC_TEST_GOTO_ERR(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		sc_do_log_color(ctx, level, "__FILE__", "__LINE__", __FUNCTION__, SC_COLOR_FG_RED, \
			"%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
		goto err; \
	} \
} while(0)
#define SC_TEST_RET(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		sc_do_log_color(ctx, level, "__FILE__", "__LINE__", __FUNCTION__, SC_COLOR_FG_RED, \
			"%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
		return _ret; \
	} \
} while(0)

#define __FUNCTION__ NULL
#define sc_debug _sc_debug
#define sc_debug_hex(ctx, level, label, data, len) \
    _sc_debug_hex(ctx, level, "__FILE__", "__LINE__", __FUNCTION__, label, data, len)
#define sc_log _sc_log
#define sc_log_hex(ctx, label, data, len) \
    sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, label, data, len)
