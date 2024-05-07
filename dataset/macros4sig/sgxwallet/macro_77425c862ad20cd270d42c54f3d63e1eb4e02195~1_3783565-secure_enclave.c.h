#include<assert.h>
#include<stdbool.h>





#include<stdio.h>
#include<math.h>




#include<string.h>
#define CHECK_ARG_CLEAN(_EXPRESSION_) \
    if (!(_EXPRESSION_)) {        \
        LOG_ERROR("State check failed::");LOG_ERROR(#_EXPRESSION_); \
        LOG_ERROR("__FILE__"); LOG_ERROR(__FUNCTION__);\
        goto clean;}
#define EXTERNC extern "C"
#define RANDOM_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; get_global_random( \
(unsigned char*) __X__, __Y__);
#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);
#define SAFE_DELETE(__X__) if (__X__) {delete(__X__); __X__ = NULL;}
#define SAFE_FREE(__X__) if (__X__) {free(__X__); __X__ = NULL;}

#define NUMBER_OF_CURVES (secp521r1+1)



#define ADD_ENTROPY_SIZE 32
#define BLS_KEY_LENGTH 65
#define BUF_LEN 1024
#define DKG_BUFER_LENGTH 2496
#define DKG_MAX_SEALED_LEN 3100
#define ECDSA_BIN_LEN 33
#define ECDSA_ENCR_LEN 93
#define ECDSA_SKEY_BASE 16
#define ECDSA_SKEY_LEN 65
#define ENCRYPTED_KEY_TOO_LONG -6
#define INCORRECT_STRING_CONVERSION -5
#define MAX_COMPONENT_HEX_LENGTH MAX_COMPONENT_LENGTH * 2
#define MAX_COMPONENT_LENGTH 80
#define MAX_ENCRYPTED_KEY_LENGTH 1024
#define MAX_ERR_LEN 1024
#define MAX_KEY_LENGTH 128
#define MAX_SIG_LEN 1024
#define NULL_KEY -4
#define PLAINTEXT_KEY_TOO_LONG -2
#define SEAL_KEY_FAILED -7
#define SECRET_SHARE_NUM_BYTES 96

#define SHA_256_LEN 32
#define UNKNOWN_ERROR -1
#define UNPADDED_KEY -3



