





#include<stdio.h>




#include<string.h>
#define ERR_FUNC(func) ERR_PACK(0,func,0)
#define ERR_REASON(reason) ERR_PACK(0,0,reason)

#define UBSECerr(f,r) ERR_UBSEC_error((f),(r),"__FILE__","__LINE__")
#define MAX_CRYPTO_KEY_LENGTH 24
#define MAX_MAC_KEY_LENGTH 64
#define MAX_PUBLIC_KEY_BITS (1024)
#define MAX_PUBLIC_KEY_BYTES (1024/8)
#define SHA_BIT_SIZE  (160)
#define UBSEC_CRYPTO_DEVICE_NAME ((unsigned char *)"/dev/ubscrypt")
#define UBSEC_KEY_DEVICE_NAME ((unsigned char *)"/dev/ubskey")
#define UBSEC_MATH_MODADD 0x0001
#define UBSEC_MATH_MODEXP 0x0008
#define UBSEC_MATH_MODINV 0x0020
#define UBSEC_MATH_MODMUL 0x0004
#define UBSEC_MATH_MODREM 0x0010
#define UBSEC_MATH_MODSUB 0x0002
