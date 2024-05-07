





#include<stddef.h>

#include<inttypes.h>



#include<assert.h>
#include<pthread.h>

#include<time.h>






#include<stdbool.h>


#include<sys/timeb.h>
#include<sys/types.h>
#include<sys/time.h>
#include<unistd.h>











#include<stdint.h>


#include<sys/socket.h>

#include<netinet/in.h>



#include<string.h>




#define BUFLEN_EMPTY_BUFFER 0xFFFFFFFF
#define ROUNDUP(VAL, SIZE) \
  ( ( (VAL) + (SIZE) - 1 ) / (SIZE) ) * (SIZE)
#define STRINGIFY(x) _STRINGIFY(x)
#define TPMLIB_LogError(format, ...) \
     TPMLIB_LogPrintfA(~0, "libtpms: "format, __VA_ARGS__)
#define TPMLIB_LogTPM12Error(format, ...) \
     TPMLIB_LogPrintfA(~0, "libtpms/tpm12: "format, __VA_ARGS__)
#define TPMLIB_LogTPM2Error(format, ...) \
     TPMLIB_LogPrintfA(~0, "libtpms/tpm2: "format, __VA_ARGS__)

#define TPM_RC_BAD_PARAMETER    0x03
#define TPM_RC_BAD_VERSION      0x2e
#define _STRINGIFY(x) #x
# define ATTRIBUTE_FORMAT(STRING_IDX, FIRST_TO_CHECK) \
  __attribute__((format (printf, STRING_IDX, FIRST_TO_CHECK)))

#define    _SIMULATOR_FP_H_
#define     TCP_TPM_PROTOCOL_H
#define TPM_ACT_GET_SIGNALED        26
#define TPM_GET_COMMAND_RESPONSE_SIZES  25
#define TPM_REMOTE_HANDSHAKE        15
#define TPM_SEND_COMMAND            8
#define TPM_SESSION_END             20
#define TPM_SET_ALTERNATIVE_RESULT  16
#define TPM_SIGNAL_CANCEL_OFF       10
#define TPM_SIGNAL_CANCEL_ON        9
#define TPM_SIGNAL_HASH_DATA        6
#define TPM_SIGNAL_HASH_END         7
#define TPM_SIGNAL_HASH_START       5
#define TPM_SIGNAL_KEY_CACHE_OFF    14
#define TPM_SIGNAL_KEY_CACHE_ON     13
#define TPM_SIGNAL_NV_OFF           12
#define TPM_SIGNAL_NV_ON            11
#define TPM_SIGNAL_PHYS_PRES_OFF    4
#define TPM_SIGNAL_PHYS_PRES_ON     3
#define TPM_SIGNAL_POWER_OFF        2
#define TPM_SIGNAL_POWER_ON         1
#define TPM_SIGNAL_RESET            17
#define TPM_SIGNAL_RESTART          18
#define TPM_STOP                    21
#define TPM_TEST_FAILURE_MODE       30
#define AUTH_ADMIN      ((AUTH_ROLE)(2))
#define AUTH_DUP        ((AUTH_ROLE)(3))
#define AUTH_NONE       ((AUTH_ROLE)(0))
#define AUTH_USER       ((AUTH_ROLE)(1))
#define CLEAR_PERSISTENT(item)						\
    NvClearPersistent(offsetof(PERSISTENT_DATA, item), sizeof(gp.item))
#define COMMIT_INDEX_MASK ((UINT16)((sizeof(gr.commitArray)*8)-1))
#define CONTEXT_SLOT_MASKED(val) ((CONTEXT_SLOT)(val) & s_ContextSlotMask)	
#define CP_HASH(HASH, Hash)           TPM2B_##HASH##_DIGEST   Hash##CpHash;
#define DefineActData(N)  ACT_STATE      ACT_##N;
#define DefineActPolicySpace(N)     TPMT_HA     act_##N;
#define     EXPIRES_ON_RESET    INT32_MIN
#define     EXPIRES_ON_RESTART  (INT32_MIN + 1)
#define         GLOBAL_H
#define NV_INDEX_RAM_DATA   TPM2_ROUNDUP(NV_ORDERLY_DATA + sizeof(ORDERLY_DATA),\
                                         1024) 
#define NV_ORDERLY_DATA     (NV_STATE_CLEAR_DATA + sizeof(STATE_CLEAR_DATA))
#define NV_PERSISTENT_DATA  (0)
#define NV_READ_PERSISTENT(to, from)					\
    NvRead(&to, offsetof(PERSISTENT_DATA, from), sizeof(to))
#define     NV_REF_INIT     (NV_REF)0xFFFFFFFF
#define NV_STATE_CLEAR_DATA (NV_STATE_RESET_DATA + sizeof(STATE_RESET_DATA))
#define NV_STATE_RESET_DATA (NV_PERSISTENT_DATA + sizeof(PERSISTENT_DATA))
#define NV_SYNC_PERSISTENT(item) NV_WRITE_PERSISTENT(item, gp.item)
#define NV_USER_DYNAMIC     (NV_INDEX_RAM_DATA + sizeof(s_indexOrderlyRam))
#define NV_USER_DYNAMIC_END     NV_MEMORY_SIZE
#define NV_WRITE_PERSISTENT(to, from)					\
    NvWrite(offsetof(PERSISTENT_DATA, to), sizeof(gp.to), &from)
#define PCR_ALL_HASH(HASH, Hash)    BYTE    Hash##Pcr[HASH##_DIGEST_SIZE];
#define PCR_SAVE_SPACE(HASH, Hash)  BYTE Hash[NUM_STATIC_PCR][HASH##_DIGEST_SIZE];
#define RP_HASH(HASH, Hash)           TPM2B_##HASH##_DIGEST   Hash##RpHash;
#define     RSA_prime_flag      0x8000
#define STARTUP_LOCALITY_3   0x4000
#define STRING_INITIALIZER(value)   {{sizeof(value), {value}}}
#define SU_DA_USED_VALUE    (SU_NONE_VALUE - 1)
#define SU_NONE_VALUE           (0xFFFF)
#define     TIMEOUT_ON_RESET    UINT64_MAX
#define     TIMEOUT_ON_RESTART  (UINT64_MAX - 1)
#define TPM2B_STRING(name, value)					\
    typedef union name##_ {						\
	struct  {							\
	    UINT16  size;						\
	    BYTE    buffer[sizeof(value)];				\
	} t;								\
	TPM2B   b;							\
    } TPM2B_##name##_;							\
    EXTERN  const TPM2B_##name##_      name##_ INITIALIZER(STRING_INITIALIZER(value)); \
    EXTERN  const TPM2B               *name INITIALIZER(&name##_.b)
#define TPM_SU_DA_USED      (TPM_SU)(SU_DA_USED_VALUE)
#define TPM_SU_NONE             (TPM_SU)(SU_NONE_VALUE)
#define TPM_SU_STATE_MASK ~(PRE_STARTUP_FLAG | STARTUP_LOCALITY_3) 
#define             UNDEFINED_INDEX     (0xFFFF)
#define UNIMPLEMENTED_COMMAND_INDEX     ((COMMAND_INDEX)(~0))
#define UT_NONE     (UPDATE_TYPE)0
#define UT_NV       (UPDATE_TYPE)1
#define UT_ORDERLY  (UPDATE_TYPE)(UT_NV + 2)
#  define drbgDefault go.drbgState
#define g_rcIndexInitializer {  TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4,	\
	    TPM_RC_5, TPM_RC_6, TPM_RC_7, TPM_RC_8,			\
	    TPM_RC_9, TPM_RC_A, TPM_RC_B, TPM_RC_C,			\
	    TPM_RC_D, TPM_RC_E, TPM_RC_F }
#define g_timeEpoch      gp.timeEpoch
#define     s_lockoutTimer      go.lockoutTimer
#define     s_selfHealTimer     go.selfHealTimer
#define CASE_ACT_HANDLE(N)     case TPM_RH_ACT_##N:
#define CASE_ACT_NUMBER(N)     case 0x##N:
#define FOR_EACH_ACT(op)						\
    IF_ACT_0_IMPLEMENTED(op)						\
    IF_ACT_1_IMPLEMENTED(op)						\
    IF_ACT_2_IMPLEMENTED(op)						\
    IF_ACT_3_IMPLEMENTED(op)						\
    IF_ACT_4_IMPLEMENTED(op)						\
    IF_ACT_5_IMPLEMENTED(op)						\
    IF_ACT_6_IMPLEMENTED(op)						\
    IF_ACT_7_IMPLEMENTED(op)						\
    IF_ACT_8_IMPLEMENTED(op)						\
    IF_ACT_9_IMPLEMENTED(op)						\
    IF_ACT_A_IMPLEMENTED(op)						\
    IF_ACT_B_IMPLEMENTED(op)						\
    IF_ACT_C_IMPLEMENTED(op)						\
    IF_ACT_D_IMPLEMENTED(op)						\
    IF_ACT_E_IMPLEMENTED(op)						\
    IF_ACT_F_IMPLEMENTED(op)
#   define IF_ACT_0_IMPLEMENTED(op)
#   define IF_ACT_1_IMPLEMENTED(op)
#   define IF_ACT_2_IMPLEMENTED(op)
#   define IF_ACT_3_IMPLEMENTED(op)
#   define IF_ACT_4_IMPLEMENTED(op) op(4)
#   define IF_ACT_5_IMPLEMENTED(op)
#   define IF_ACT_6_IMPLEMENTED(op)
#   define IF_ACT_7_IMPLEMENTED(op)
#   define IF_ACT_8_IMPLEMENTED(op)
#   define IF_ACT_9_IMPLEMENTED(op)
#   define IF_ACT_A_IMPLEMENTED(op)
#   define IF_ACT_B_IMPLEMENTED(op)
#   define IF_ACT_C_IMPLEMENTED(op)
#   define IF_ACT_D_IMPLEMENTED(op)
#   define IF_ACT_E_IMPLEMENTED(op)
#   define IF_ACT_F_IMPLEMENTED(op)
#   define  RH_ACT_0 NO
#   define  RH_ACT_1 NO
#   define  RH_ACT_2 NO
#   define  RH_ACT_3 NO
#   define  RH_ACT_4 NO
#   define  RH_ACT_5 NO
#   define  RH_ACT_6 NO
#   define  RH_ACT_7 NO
#   define  RH_ACT_8 NO
#   define  RH_ACT_9 NO
#   define  RH_ACT_A NO
#   define  RH_ACT_B NO
#   define  RH_ACT_C NO
#   define  RH_ACT_D NO
#   define  RH_ACT_E NO
#   define  RH_ACT_F NO
#   define TPM_RH_ACT_1    (TPM_RH_ACT_0 + 1)
#   define TPM_RH_ACT_2    (TPM_RH_ACT_0 + 2)
#   define TPM_RH_ACT_3    (TPM_RH_ACT_0 + 3)
#   define TPM_RH_ACT_4    (TPM_RH_ACT_0 + 4)
#   define TPM_RH_ACT_5    (TPM_RH_ACT_0 + 5)
#   define TPM_RH_ACT_6    (TPM_RH_ACT_0 + 6)
#   define TPM_RH_ACT_7    (TPM_RH_ACT_0 + 7)
#   define TPM_RH_ACT_8    (TPM_RH_ACT_0 + 8)
#   define TPM_RH_ACT_9    (TPM_RH_ACT_0 + 9)
#   define TPM_RH_ACT_A    (TPM_RH_ACT_0 + 0xA)
#   define TPM_RH_ACT_B    (TPM_RH_ACT_0 + 0xB)
#   define TPM_RH_ACT_C    (TPM_RH_ACT_0 + 0xC)
#   define TPM_RH_ACT_D    (TPM_RH_ACT_0 + 0xD)
#   define TPM_RH_ACT_E    (TPM_RH_ACT_0 + 0xE)
#   define TPM_RH_ACT_F    (TPM_RH_ACT_0 + 0xF)

#define AES_128                     (ALG_AES && YES)
#define AES_192                     (ALG_AES && NO)
#define AES_256                     (ALG_AES && YES)
#define ALG_AES                         ALG_YES
#define ALG_CAMELLIA                    ALG_NO       
#define ALG_CBC                         ALG_YES
#define ALG_CFB                         ALG_YES
#define ALG_CMAC                        ALG_YES
#define ALG_CTR                         ALG_YES
#define ALG_ECB                         ALG_YES
#define ALG_ECC                         ALG_YES
#define ALG_ECDAA                       (ALG_YES && ALG_ECC)
#define ALG_ECDH                        (ALG_YES && ALG_ECC)
#define ALG_ECDSA                       (ALG_YES && ALG_ECC)
#define ALG_ECMQV                       (ALG_YES && ALG_ECC) 
#define ALG_ECSCHNORR                   (ALG_YES && ALG_ECC)
#define ALG_HMAC                        ALG_YES
#define ALG_KDF1_SP800_108              ALG_YES
#define ALG_KDF1_SP800_56A              (ALG_YES && ALG_ECC)
#define ALG_KDF2                        ALG_YES
#define ALG_KEYEDHASH                   ALG_YES
#define ALG_MGF1                        ALG_YES
#define ALG_OAEP                        (ALG_YES && ALG_RSA)
#define ALG_OFB                         ALG_YES
#define ALG_RSA                         ALG_YES
#define ALG_RSAES                       (ALG_YES && ALG_RSA)
#define ALG_RSAPSS                      (ALG_YES && ALG_RSA)
#define ALG_RSASSA                      (ALG_YES && ALG_RSA)
#define ALG_SHA                         ALG_NO      
#define ALG_SHA1                        ALG_YES
#define ALG_SHA256                      ALG_YES
#define ALG_SHA384                      ALG_YES
#define ALG_SHA3_256                    ALG_NO      
#define ALG_SHA3_384                    ALG_NO      
#define ALG_SHA3_512                    ALG_NO      
#define ALG_SHA512                      ALG_YES
#define ALG_SM2                         (ALG_YES && ALG_ECC) 
#define ALG_SM3_256                     ALG_NO      
#define ALG_SM4                         ALG_NO      
#define ALG_SYMCIPHER                   ALG_YES
#define ALG_TDES                        ALG_YES 
#define ALG_XOR                         ALG_YES
#define AUTO_ALIGN                  NO
  #define  BIG_ENDIAN_TPM       YES
#define CAMELLIA_128                (ALG_CAMELLIA && YES)
#define CAMELLIA_192                (ALG_CAMELLIA && NO)
#define CAMELLIA_256                (ALG_CAMELLIA && YES)
#define CC_ACT_SetTimeout                   CC_NO	
#define CC_AC_GetCapability                 CC_NO	
#define CC_AC_Send                          CC_NO	
#define CC_ActivateCredential               CC_YES
#define CC_Certify                          CC_YES
#define CC_CertifyCreation                  CC_YES
#define CC_CertifyX509                      CC_YES
#define CC_ChangeEPS                        CC_YES
#define CC_ChangePPS                        CC_YES
#define CC_Clear                            CC_YES
#define CC_ClearControl                     CC_YES
#define CC_ClockRateAdjust                  CC_YES
#define CC_ClockSet                         CC_YES
#define CC_Commit                           (CC_YES && ALG_ECC)
#define CC_ContextLoad                      CC_YES
#define CC_ContextSave                      CC_YES
#define CC_Create                           CC_YES
#define CC_CreateLoaded                     CC_YES
#define CC_CreatePrimary                    CC_YES
#define CC_DictionaryAttackLockReset        CC_YES
#define CC_DictionaryAttackParameters       CC_YES
#define CC_Duplicate                        CC_YES
#define CC_ECC_Decrypt                      (CC_NO && ALG_ECC)
#define CC_ECC_Encrypt                      (CC_NO && ALG_ECC)
#define CC_ECC_Parameters                   (CC_YES && ALG_ECC)
#define CC_ECDH_KeyGen                      (CC_YES && ALG_ECC)
#define CC_ECDH_ZGen                        (CC_YES && ALG_ECC)
#define CC_EC_Ephemeral                     (CC_YES && ALG_ECC)
#define CC_EncryptDecrypt                   CC_YES
#define CC_EncryptDecrypt2                  CC_YES
#define CC_EventSequenceComplete            CC_YES
#define CC_EvictControl                     CC_YES
#define CC_FieldUpgradeData                 CC_NO
#define CC_FieldUpgradeStart                CC_NO
#define CC_FirmwareRead                     CC_NO
#define CC_FlushContext                     CC_YES
#define CC_GetCapability                    CC_YES
#define CC_GetCommandAuditDigest            CC_YES
#define CC_GetRandom                        CC_YES
#define CC_GetSessionAuditDigest            CC_YES
#define CC_GetTestResult                    CC_YES
#define CC_GetTime                          CC_YES
#define CC_HMAC                             (CC_YES && !ALG_CMAC)
#define CC_HMAC_Start                       (CC_YES && !ALG_CMAC)
#define CC_Hash                             CC_YES
#define CC_HashSequenceStart                CC_YES
#define CC_HierarchyChangeAuth              CC_YES
#define CC_HierarchyControl                 CC_YES
#define CC_Import                           CC_YES
#define CC_IncrementalSelfTest              CC_YES
#define CC_Load                             CC_YES
#define CC_LoadExternal                     CC_YES
#define CC_MAC                              (CC_YES && ALG_CMAC)
#define CC_MAC_Start                        (CC_YES && ALG_CMAC)
#define CC_MakeCredential                   CC_YES
#define CC_NV_Certify                       CC_YES
#define CC_NV_ChangeAuth                    CC_YES
#define CC_NV_DefineSpace                   CC_YES
#define CC_NV_Extend                        CC_YES
#define CC_NV_GlobalWriteLock               CC_YES
#define CC_NV_Increment                     CC_YES
#define CC_NV_Read                          CC_YES
#define CC_NV_ReadLock                      CC_YES
#define CC_NV_ReadPublic                    CC_YES
#define CC_NV_SetBits                       CC_YES
#define CC_NV_UndefineSpace                 CC_YES
#define CC_NV_UndefineSpaceSpecial          CC_YES
#define CC_NV_Write                         CC_YES
#define CC_NV_WriteLock                     CC_YES
#define CC_ObjectChangeAuth                 CC_YES
#define CC_PCR_Allocate                     CC_YES
#define CC_PCR_Event                        CC_YES
#define CC_PCR_Extend                       CC_YES
#define CC_PCR_Read                         CC_YES
#define CC_PCR_Reset                        CC_YES
#define CC_PCR_SetAuthPolicy                CC_YES
#define CC_PCR_SetAuthValue                 CC_YES
#define CC_PP_Commands                      CC_YES
#define CC_PolicyAuthValue                  CC_YES
#define CC_PolicyAuthorize                  CC_YES
#define CC_PolicyAuthorizeNV                CC_YES
#define CC_PolicyCommandCode                CC_YES
#define CC_PolicyCounterTimer               CC_YES
#define CC_PolicyCpHash                     CC_YES
#define CC_PolicyDuplicationSelect          CC_YES
#define CC_PolicyGetDigest                  CC_YES
#define CC_PolicyLocality                   CC_YES
#define CC_PolicyNV                         CC_YES
#define CC_PolicyNameHash                   CC_YES
#define CC_PolicyNvWritten                  CC_YES
#define CC_PolicyOR                         CC_YES
#define CC_PolicyPCR                        CC_YES
#define CC_PolicyPassword                   CC_YES
#define CC_PolicyPhysicalPresence           CC_YES
#define CC_PolicyRestart                    CC_YES
#define CC_PolicySecret                     CC_YES
#define CC_PolicySigned                     CC_YES
#define CC_PolicyTemplate                   CC_YES
#define CC_PolicyTicket                     CC_YES
#define CC_Policy_AC_SendSelect             CC_NO	
#define CC_Quote                            CC_YES
#define CC_RSA_Decrypt                      (CC_YES && ALG_RSA)
#define CC_RSA_Encrypt                      (CC_YES && ALG_RSA)
#define CC_ReadClock                        CC_YES
#define CC_ReadPublic                       CC_YES
#define CC_Rewrap                           CC_YES
#define CC_SelfTest                         CC_YES
#define CC_SequenceComplete                 CC_YES
#define CC_SequenceUpdate                   CC_YES
#define CC_SetAlgorithmSet                  CC_YES
#define CC_SetCommandCodeAuditStatus        CC_YES
#define CC_SetPrimaryPolicy                 CC_YES
#define CC_Shutdown                         CC_YES
#define CC_Sign                             CC_YES
#define CC_StartAuthSession                 CC_YES
#define CC_Startup                          CC_YES
#define CC_StirRandom                       CC_YES
#define CC_TestParms                        CC_YES
#define CC_Unseal                           CC_YES
#define CC_Vendor_TCG_Test                  CC_NO 
#define CC_VerifySignature                  CC_YES
#define CC_ZGen_2Phase                      (CC_YES && ALG_ECC)
#define CLEAR               0
#define CONTEXT_ENCRYPT_ALGORITHM       AES
#define CONTEXT_SLOT                    UINT16   
#define CRT_FORMAT_RSA                  YES
#define DRTM_PCR                        17
#define ECC_BN_P256                     YES
#define ECC_BN_P638                     YES 
#define ECC_NIST_P192                   YES 
#define ECC_NIST_P224                   YES 
#define ECC_NIST_P256                   YES
#define ECC_NIST_P384                   YES
#define ECC_NIST_P521                   YES 
#define ECC_SM2_P256                    YES 
#define ENABLE_PCR_NO_INCREMENT         YES
#define FALSE               0
#define FIELD_UPGRADE_IMPLEMENTED       NO
#define HASH_LIB                        Ossl
#define HCRTM_PCR                       0
#define IMPLEMENTATION_PCR              24
#define LEAST_SIGNIFICANT_BIT_0     !MOST_SIGNIFICANT_BIT_0
#define LITTLE_ENDIAN_TPM           !BIG_ENDIAN_TPM
#define MATH_LIB                        Ossl
#define MAX_ACTIVE_SESSIONS             64
#define MAX_ALG_LIST_SIZE               64
#define MAX_CAP_BUFFER                  1024
#define MAX_COMMAND_SIZE                TPM2_GetBufferSize() 
#define MAX_CONTEXT_SIZE                2680    
#define MAX_DIGEST_BUFFER               1024
#define MAX_HANDLE_NUM                  3
#define MAX_LOADED_OBJECTS              3
#define MAX_LOADED_SESSIONS             3
#define MAX_NV_BUFFER_SIZE              1024
#define MAX_NV_INDEX_SIZE               2048
#define MAX_RESPONSE_SIZE               TPM2_GetBufferSize() 
#define MAX_RNG_ENTROPY_SIZE            64
#define MAX_SESSION_NUM                 3
#define MAX_SYM_DATA                    128
#define MAX_VENDOR_BUFFER_SIZE          1024
#define MIN_COUNTER_INDICES             8
#define MIN_EVICT_OBJECTS               7 
#define MOST_SIGNIFICANT_BIT_0      NO
#define NO                  0
#define NUM_AUTHVALUE_PCR_GROUP         1
#define NUM_LOCALITIES                  5
#define NUM_POLICY_PCR                  1
#define NUM_POLICY_PCR_GROUP            1
#define NUM_STATIC_PCR                  16
#define NV_CLOCK_UPDATE_INTERVAL        12
#define NV_MEMORY_SIZE                  (128 * 1024 + 65 * 704)  
#define ORDERLY_BITS                    8
#define PLATFORM_PCR                    24
#define PRIMARY_SEED_SIZE               64 
#  define RADIX_BITS                     32
#define RAM_INDEX_SPACE                 512
#define RSA_1024                    (ALG_RSA && YES)
#define RSA_16384                   (ALG_RSA && NO)
#define RSA_2048                    (ALG_RSA && YES)
#define RSA_3072                    (ALG_RSA && YES)
#define RSA_4096                    (ALG_RSA && NO)
#define RSA_DEFAULT_PUBLIC_EXPONENT     0x00010001
#define SET                 1
#define SIZE_OF_X509_SERIAL_NUMBER      20
#define SM4_128                     (ALG_SM4 && YES)
#define SYM_LIB                         Ossl
#define TDES_128                    (ALG_TDES && YES)
#define TDES_192                    (ALG_TDES && YES)
#define TRUE                1
#define VENDOR_COMMAND_COUNT            0
#define YES                 1


#   define GET_TPM_NT(attributes) GET_ATTRIBUTE(attributes, TPMA_NV, TPM_NT)
#   define GetNv_TPM_NV(attributes)					\
    (   IS_ATTRIBUTE(attributes, TPMA_NV, COUNTER)			\
	+   (IS_ATTRIBUTE(attributes, TPMA_NV, BITS) << 1)		\
	+   (IS_ATTRIBUTE(attributes, TPMA_NV, EXTEND) << 2)		\
	)
#define IS_ORDERLY(value)   (value < SU_DA_USED_VALUE)
#   define  IsNvBitsIndex(attributes)					\
    (GET_TPM_NT(attributes) == TPM_NT_BITS)
#   define  IsNvCounterIndex(attributes)				\
    (GET_TPM_NT(attributes) == TPM_NT_COUNTER)
#   define  IsNvExtendIndex(attributes)					\
    (GET_TPM_NT(attributes) == TPM_NT_EXTEND)
#   define IsNvOrdinaryIndex(attributes)				\
    (GET_TPM_NT(attributes) == TPM_NT_ORDINARY)
#   define  IsNvPinFailIndex(attributes)				\
    (GET_TPM_NT(attributes) == TPM_NT_PIN_FAIL)
#   define  IsNvPinPassIndex(attributes)				\
    (GET_TPM_NT(attributes) == TPM_NT_PIN_PASS)

#define NV_IS_AVAILABLE     (g_NvStatus == TPM_RC_SUCCESS)
#define NV_IS_ORDERLY       (IS_ORDERLY(gp.orderlyState))
#define     NV_RAM_REF_INIT         0
#define ORDERLY_RAM_ADDRESS_OK(start, offset)				\
    ((start >= RAM_ORDERLY_START) && ((start + offset - 1) < RAM_ORDERLY_END))
#define SET_NV_UPDATE(type)     g_updateNV |= (type)
#   define TPM_NT_BITS     (2)
#   define TPM_NT_COUNTER  (1)
#   define TPM_NT_EXTEND   (4)
#   define TPM_NT_ORDINARY (0)
#define     FATAL_ERROR_ALLOCATION              (1)
#define     FATAL_ERROR_COUNTER_OVERFLOW        (12)
#define     FATAL_ERROR_CRYPTO                  (7)
#define     FATAL_ERROR_DIVIDE_ZERO             (2)
#define     FATAL_ERROR_DRBG                    (10)
#define     FATAL_ERROR_ENTROPY                 (5)
#define     FATAL_ERROR_FORCED                  (666)
#define     FATAL_ERROR_INTERNAL                (3)
#define     FATAL_ERROR_MOVE_SIZE               (11)
#define     FATAL_ERROR_NV_UNRECOVERABLE        (8)
#define     FATAL_ERROR_PARAMETER               (4)
#define     FATAL_ERROR_REMANUFACTURED          (9) 
#define     FATAL_ERROR_SELF_TEST               (6)
#define     FATAL_ERROR_SUBTRACT                (13)

#define ALLOW_TRIAL         ((COMMAND_ATTRIBUTES)1 << 14)

#define DECRYPT_2           ((COMMAND_ATTRIBUTES)1 << 2)
#define DECRYPT_4           ((COMMAND_ATTRIBUTES)1 << 3)
#define ENCRYPT_2           ((COMMAND_ATTRIBUTES)1 << 0)
#define ENCRYPT_4           ((COMMAND_ATTRIBUTES)1 << 1)
#define HANDLE_1_ADMIN      ((COMMAND_ATTRIBUTES)1 << 5)
#define HANDLE_1_DUP        ((COMMAND_ATTRIBUTES)1 << 6)
#define HANDLE_1_USER       ((COMMAND_ATTRIBUTES)1 << 4)
#define HANDLE_2_USER       ((COMMAND_ATTRIBUTES)1 << 7)
#define IS_IMPLEMENTED      ((COMMAND_ATTRIBUTES)1 << 9)
#define NOT_IMPLEMENTED     (COMMAND_ATTRIBUTES)(0)
#define NO_SESSIONS         ((COMMAND_ATTRIBUTES)1 << 10)
#define NV_COMMAND          ((COMMAND_ATTRIBUTES)1 << 11)
#define PP_COMMAND          ((COMMAND_ATTRIBUTES)1 << 8)
#define PP_REQUIRED         ((COMMAND_ATTRIBUTES)1 << 12)
#define R_HANDLE            ((COMMAND_ATTRIBUTES)1 << 13)
#define  ACTIVE_SESSION_FIRST    (TPM_HC)(POLICY_SESSION_FIRST)
#define  ACTIVE_SESSION_LAST     (TPM_HC)(POLICY_SESSION_LAST)
#define  AC_FIRST                (TPM_HC)((HR_AC+0))
#define  AC_LAST                 (TPM_HC)((HR_AC+0x0000FFFF))
#define     ALG_AES_VALUE               0x0006
#define     ALG_CAMELLIA_VALUE          0x0026
#define     ALG_CBC_VALUE               0x0042
#define     ALG_CFB_VALUE               0x0043
#define     ALG_CMAC_VALUE              0x003F
#define     ALG_CTR_VALUE               0x0040
#define     ALG_ECB_VALUE               0x0044
#define     ALG_ECC_VALUE               0x0023
#define     ALG_ECDAA_VALUE             0x001A
#define     ALG_ECDH_VALUE              0x0019
#define     ALG_ECDSA_VALUE             0x0018
#define     ALG_ECMQV_VALUE             0x001D
#define     ALG_ECSCHNORR_VALUE         0x001C
#define     ALG_ERROR_VALUE             0x0000
#define     ALG_FIRST_VALUE             0x0001
#define     ALG_HMAC_VALUE              0x0005
#define     ALG_KDF1_SP800_108_VALUE    0x0022
#define     ALG_KDF1_SP800_56A_VALUE    0x0020
#define     ALG_KDF2_VALUE              0x0021
#define     ALG_KEYEDHASH_VALUE         0x0008
#define     ALG_LAST_VALUE              0x0044
#define     ALG_MGF1_VALUE              0x0007
#define     ALG_NULL_VALUE              0x0010
#define     ALG_OAEP_VALUE              0x0017
#define     ALG_OFB_VALUE               0x0041
#define     ALG_RSAES_VALUE             0x0015
#define     ALG_RSAPSS_VALUE            0x0016
#define     ALG_RSASSA_VALUE            0x0014
#define     ALG_RSA_VALUE               0x0001
#define     ALG_SHA1_VALUE              0x0004
#define     ALG_SHA256_VALUE            0x000B
#define     ALG_SHA384_VALUE            0x000C
#define     ALG_SHA3_256_VALUE          0x0027
#define     ALG_SHA3_384_VALUE          0x0028
#define     ALG_SHA3_512_VALUE          0x0029
#define     ALG_SHA512_VALUE            0x000D
#define     ALG_SHA_VALUE               0x0004
#define     ALG_SM2_VALUE               0x001B
#define     ALG_SM3_256_VALUE           0x0012
#define     ALG_SM4_VALUE               0x0013
#define     ALG_SYMCIPHER_VALUE         0x0025
#define     ALG_TDES_VALUE              0x0003
#define     ALG_XOR_VALUE               0x000A
#define BYTE_ARRAY_TO_TPMA_ACT(i, a)					\
    { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPMA_ACT(x); }
#define BYTE_ARRAY_TO_TPMA_ALGORITHM(i, a)				\
    {UINT32 x = BYTE_ARRAY_TO_UINT32(a);				\
	i = UINT32_TO_TPMA_ALGORITHM(x);				\
    }
#define BYTE_ARRAY_TO_TPMA_CC(i, a)                                                \
            { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPMA_CC(x); }
#define BYTE_ARRAY_TO_TPMA_LOCALITY(i, a)                                          \
            { UINT8 x = BYTE_ARRAY_TO_UINT8(a); i = UINT8_TO_TPMA_LOCALITY(x); }
#define BYTE_ARRAY_TO_TPMA_MEMORY(i, a)                                            \
            { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPMA_MEMORY(x); }
#define BYTE_ARRAY_TO_TPMA_MODES(i, a)                                             \
            { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPMA_MODES(x); }
#define BYTE_ARRAY_TO_TPMA_NV(i, a)                                                \
            { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPMA_NV(x); }
#define BYTE_ARRAY_TO_TPMA_OBJECT(i, a)					\
    { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPMA_OBJECT(x); }
#define BYTE_ARRAY_TO_TPMA_PERMANENT(i, a)				\
    {UINT32 x = BYTE_ARRAY_TO_UINT32(a);				\
	i = UINT32_TO_TPMA_PERMANENT(x);				\
    }
#define BYTE_ARRAY_TO_TPMA_SESSION(i, a)                                           \
            { UINT8 x = BYTE_ARRAY_TO_UINT8(a); i = UINT8_TO_TPMA_SESSION(x); }
#define BYTE_ARRAY_TO_TPMA_STARTUP_CLEAR(i, a)				\
    {UINT32 x = BYTE_ARRAY_TO_UINT32(a);				\
	i = UINT32_TO_TPMA_STARTUP_CLEAR(x);				\
    }
#define BYTE_ARRAY_TO_TPMA_X509_KEY_USAGE(i, a)				\
    {UINT32 x = BYTE_ARRAY_TO_UINT32(a);				\
	i = UINT32_TO_TPMA_X509_KEY_USAGE(x);				\
    }
#define BYTE_ARRAY_TO_TPM_NV_INDEX(i, a)                                           \
            { UINT32 x = BYTE_ARRAY_TO_UINT32(a); i = UINT32_TO_TPM_NV_INDEX(x); }
#define CC_VEND                             0x20000000
#define  HMAC_SESSION_FIRST      (TPM_HC)((HR_HMAC_SESSION+0))
#define  HMAC_SESSION_LAST       (TPM_HC)((HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS-1))
#define  HR_AC                   (TPM_HC)((TPM_HT_AC<<HR_SHIFT))
#define  HR_HANDLE_MASK          (TPM_HC)(0x00FFFFFF)
#define  HR_HMAC_SESSION         (TPM_HC)((TPM_HT_HMAC_SESSION<<HR_SHIFT))
#define  HR_NV_AC                (TPM_HC)(((TPM_HT_NV_INDEX<<HR_SHIFT)+0xD00000))
#define  HR_NV_INDEX             (TPM_HC)((TPM_HT_NV_INDEX<<HR_SHIFT))
#define  HR_PCR                  (TPM_HC)((TPM_HT_PCR<<HR_SHIFT))
#define  HR_PERMANENT            (TPM_HC)((TPM_HT_PERMANENT<<HR_SHIFT))
#define  HR_PERSISTENT           (TPM_HC)(((UINT32)TPM_HT_PERSISTENT<<HR_SHIFT)) 
#define  HR_POLICY_SESSION       (TPM_HC)((TPM_HT_POLICY_SESSION<<HR_SHIFT))
#define  HR_RANGE_MASK           (TPM_HC)(0xFF000000)
#define  HR_SHIFT                (TPM_HC)(24)
#define  HR_TRANSIENT            (TPM_HC)(((UINT32)TPM_HT_TRANSIENT<<HR_SHIFT))  
#define  LOADED_SESSION_FIRST    (TPM_HC)(HMAC_SESSION_FIRST)
#define  LOADED_SESSION_LAST     (TPM_HC)(HMAC_SESSION_LAST)
#define  NV_AC_FIRST             (TPM_HC)((HR_NV_AC+0))
#define  NV_AC_LAST              (TPM_HC)((HR_NV_AC+0x0000FFFF))
#define  NV_INDEX_FIRST          (TPM_HC)((HR_NV_INDEX+0))
#define  NV_INDEX_LAST           (TPM_HC)((NV_INDEX_FIRST+0x00FFFFFF))
#define  PCR_FIRST               (TPM_HC)((HR_PCR+0))
#define  PCR_LAST                (TPM_HC)((PCR_FIRST+IMPLEMENTATION_PCR-1))
#define  PERMANENT_FIRST         (TPM_HC)(TPM_RH_FIRST)
#define  PERMANENT_LAST          (TPM_HC)(TPM_RH_LAST)
#define  PERSISTENT_FIRST        (TPM_HC)((HR_PERSISTENT+0))
#define  PERSISTENT_LAST         (TPM_HC)((PERSISTENT_FIRST+0x00FFFFFF))
#define  PLATFORM_PERSISTENT     (TPM_HC)((PERSISTENT_FIRST+0x00800000))
#define  POLICY_SESSION_FIRST    (TPM_HC)((HR_POLICY_SESSION+0))
#define PT_FIXED                      (TPM_PT)(PT_GROUP*1)
#define PT_GROUP                      (TPM_PT)(0x00000100)
#define PT_VAR                        (TPM_PT)(PT_GROUP*2)
#define RC_FMT1                     (TPM_RC)(0x080)
#define RC_MAX_FM0                  (TPM_RC)(RC_VER1+0x07F)
#define RC_VER1                     (TPM_RC)(0x100)
#define RC_WARN                     (TPM_RC)(0x900)
#define SPEC_DAY_OF_YEAR        75
#define SPEC_FAMILY             0x322E3000
#define SPEC_LEVEL              00
#define SPEC_LEVEL_NUM          0  
#define SPEC_VERSION            164
#define SPEC_YEAR               2021
#define TPMA_ACT_INITIALIZER(signaled, preservesignaled, bits_at_2)	\
    {signaled, preservesignaled, bits_at_2}
#define TPMA_ACT_TO_BYTE_ARRAY(i, a)					\
    UINT32_TO_BYTE_ARRAY((TPMA_ACT_TO_UINT32(i)), (a))
#define TPMA_ACT_TO_UINT32(a)    (*((UINT32 *)&(a)))
#define TPMA_ACT_preserveSignaled   ((TPMA_ACT)1 << 1)
#define TPMA_ACT_signaled           ((TPMA_ACT)1 << 0)
#define TPMA_ALGORITHM_INITIALIZER(					\
				   asymmetric, symmetric,  hash,       object,     bits_at_4, \
				   signing,    encrypting, method,     bits_at_11) \
    {asymmetric, symmetric,  hash,       object,     bits_at_4,		\
	    signing,    encrypting, method,     bits_at_11}
#define TPMA_ALGORITHM_TO_BYTE_ARRAY(i, a)				\
	            UINT32_TO_BYTE_ARRAY((TPMA_ALGORITHM_TO_UINT32(i)), (a))
#define TPMA_ALGORITHM_TO_UINT32(a)  (*((UINT32 *)&(a)))
#define TPMA_ALGORITHM_asymmetric        ((TPMA_ALGORITHM)1 << 0)
#define TPMA_ALGORITHM_encrypting        ((TPMA_ALGORITHM)1 << 9)
#define TPMA_ALGORITHM_hash              ((TPMA_ALGORITHM)1 << 2)
#define TPMA_ALGORITHM_method            ((TPMA_ALGORITHM)1 << 10)
#define TPMA_ALGORITHM_object            ((TPMA_ALGORITHM)1 << 3)
#define TPMA_ALGORITHM_signing           ((TPMA_ALGORITHM)1 << 8)
#define TPMA_ALGORITHM_symmetric         ((TPMA_ALGORITHM)1 << 1)
#define TPMA_CC_INITIALIZER(						\
			    commandindex, bits_at_16,   nv,           extensive,    flushed, \
			    chandles,     rhandle,      v,            bits_at_30) \
    {commandindex, bits_at_16,   nv,           extensive,    flushed,	\
	    chandles,     rhandle,      v,            bits_at_30}
#define TPMA_CC_TO_BYTE_ARRAY(i, a)                                                \
            UINT32_TO_BYTE_ARRAY((TPMA_CC_TO_UINT32(i)), (a))
#define TPMA_CC_TO_UINT32(a)     (*((UINT32 *)&(a)))
#define TPMA_CC_V                   ((TPMA_CC)1 << 29)
#define TPMA_CC_cHandles            ((TPMA_CC)0x7 << 25)
#define TPMA_CC_cHandles_SHIFT      25
#define TPMA_CC_commandIndex        ((TPMA_CC)0xffff << 0)
#define TPMA_CC_commandIndex_SHIFT  0
#define TPMA_CC_extensive           ((TPMA_CC)1 << 23)
#define TPMA_CC_flushed             ((TPMA_CC)1 << 24)
#define TPMA_CC_nv                  ((TPMA_CC)1 << 22)
#define TPMA_CC_rHandle             ((TPMA_CC)1 << 28)
#define TPMA_LOCALITY_Extended          ((TPMA_LOCALITY)0x7 << 5)
#define TPMA_LOCALITY_Extended_SHIFT    5
#define TPMA_LOCALITY_INITIALIZER(					\
				  tpm_loc_zero,  tpm_loc_one,   tpm_loc_two,   tpm_loc_three, \
				  tpm_loc_four,  extended)		\
    {tpm_loc_zero,  tpm_loc_one,   tpm_loc_two,   tpm_loc_three,	\
	    tpm_loc_four,  extended}
#define TPMA_LOCALITY_TO_BYTE_ARRAY(i, a)                                          \
            UINT8_TO_BYTE_ARRAY((TPMA_LOCALITY_TO_UINT8(i)), (a))
#define TPMA_LOCALITY_TO_UINT8(a)    (*((UINT8 *)&(a)))
#define TPMA_LOCALITY_TPM_LOC_FOUR      ((TPMA_LOCALITY)1 << 4)
#define TPMA_LOCALITY_TPM_LOC_ONE       ((TPMA_LOCALITY)1 << 1)
#define TPMA_LOCALITY_TPM_LOC_THREE     ((TPMA_LOCALITY)1 << 3)
#define TPMA_LOCALITY_TPM_LOC_TWO       ((TPMA_LOCALITY)1 << 2)
#define TPMA_LOCALITY_TPM_LOC_ZERO      ((TPMA_LOCALITY)1 << 0)
#define TPMA_MEMORY_INITIALIZER(					\
				sharedram, sharednv, objectcopiedtoram, bits_at_3) \
    {sharedram, sharednv, objectcopiedtoram, bits_at_3}
#define TPMA_MEMORY_TO_BYTE_ARRAY(i, a)                                            \
            UINT32_TO_BYTE_ARRAY((TPMA_MEMORY_TO_UINT32(i)), (a))
#define TPMA_MEMORY_TO_UINT32(a)     (*((UINT32 *)&(a)))
#define TPMA_MEMORY_objectCopiedToRam   ((TPMA_MEMORY)1 << 2)
#define TPMA_MEMORY_sharedNV            ((TPMA_MEMORY)1 << 1)
#define TPMA_MEMORY_sharedRAM           ((TPMA_MEMORY)1 << 0)
#define TPMA_MODES_FIPS_140_2   ((TPMA_MODES)1 << 0)
#define TPMA_MODES_INITIALIZER(fips_140_2, bits_at_1) {fips_140_2, bits_at_1}
#define TPMA_MODES_TO_BYTE_ARRAY(i, a)                                             \
            UINT32_TO_BYTE_ARRAY((TPMA_MODES_TO_UINT32(i)), (a))
#define TPMA_MODES_TO_UINT32(a)  (*((UINT32 *)&(a)))
#define TPMA_NV_AUTHREAD        ((TPMA_NV)1 << 18)
#define TPMA_NV_AUTHWRITE       ((TPMA_NV)1 << 2)
#define TPMA_NV_CLEAR_STCLEAR   ((TPMA_NV)1 << 27)
#define TPMA_NV_GLOBALLOCK      ((TPMA_NV)1 << 15)
#define TPMA_NV_INITIALIZER(						\
			    ppwrite,        ownerwrite,     authwrite,      policywrite, \
			    tpm_nt,         bits_at_8,      policy_delete,  writelocked, \
			    writeall,       writedefine,    write_stclear,  globallock, \
			    ppread,         ownerread,      authread,       policyread, \
			    bits_at_20,     no_da,          orderly,        clear_stclear, \
			    readlocked,     written,        platformcreate, read_stclear) \
    {ppwrite,        ownerwrite,     authwrite,      policywrite,	\
	    tpm_nt,         bits_at_8,      policy_delete,  writelocked, \
	    writeall,       writedefine,    write_stclear,  globallock, \
	    ppread,         ownerread,      authread,       policyread, \
	    bits_at_20,     no_da,          orderly,        clear_stclear, \
	    readlocked,     written,        platformcreate, read_stclear}
#define TPMA_NV_NO_DA           ((TPMA_NV)1 << 25)
#define TPMA_NV_ORDERLY         ((TPMA_NV)1 << 26)
#define TPMA_NV_OWNERREAD       ((TPMA_NV)1 << 17)
#define TPMA_NV_OWNERWRITE      ((TPMA_NV)1 << 1)
#define TPMA_NV_PLATFORMCREATE  ((TPMA_NV)1 << 30)
#define TPMA_NV_POLICYREAD      ((TPMA_NV)1 << 19)
#define TPMA_NV_POLICYWRITE     ((TPMA_NV)1 << 3)
#define TPMA_NV_POLICY_DELETE   ((TPMA_NV)1 << 10)
#define TPMA_NV_PPREAD          ((TPMA_NV)1 << 16)
#define TPMA_NV_PPWRITE         ((TPMA_NV)1 << 0)
#define TPMA_NV_READLOCKED      ((TPMA_NV)1 << 28)
#define TPMA_NV_READ_STCLEAR    ((TPMA_NV)1 << 31)
#define TPMA_NV_RESERVED        (0x00000300 | 0x01f00000)
#define TPMA_NV_TO_BYTE_ARRAY(i, a)                                                \
            UINT32_TO_BYTE_ARRAY((TPMA_NV_TO_UINT32(i)), (a))
#define TPMA_NV_TO_UINT32(a)     (*((UINT32 *)&(a)))
#define TPMA_NV_TPM_NT          ((TPMA_NV)0xf << 4)
#define TPMA_NV_TPM_NT_SHIFT    4
#define TPMA_NV_WRITEALL        ((TPMA_NV)1 << 12)
#define TPMA_NV_WRITEDEFINE     ((TPMA_NV)1 << 13)
#define TPMA_NV_WRITELOCKED     ((TPMA_NV)1 << 11)
#define TPMA_NV_WRITE_STCLEAR   ((TPMA_NV)1 << 14)
#define TPMA_NV_WRITTEN         ((TPMA_NV)1 << 29)
#define TPMA_OBJECT_INITIALIZER(					\
				bit_at_0,             fixedtpm,             stclear, \
				bit_at_3,             fixedparent,          sensitivedataorigin, \
				userwithauth,         adminwithpolicy,      bits_at_8, \
				noda,                 encryptedduplication, bits_at_12, \
				restricted,           decrypt,              sign, \
				x509sign,             bits_at_20)	\
	   {bit_at_0,             fixedtpm,             stclear,		\
	    bit_at_3,             fixedparent,          sensitivedataorigin, \
	    userwithauth,         adminwithpolicy,      bits_at_8,	\
	    noda,                 encryptedduplication, bits_at_12,	\
	    restricted,           decrypt,              sign,		\
	    x509sign,             bits_at_20}
#define TPMA_OBJECT_Reserved_bit_at_0       ((TPMA_OBJECT)1 << 0)
#define TPMA_OBJECT_TO_BYTE_ARRAY(i, a)				\
    UINT32_TO_BYTE_ARRAY((TPMA_OBJECT_TO_UINT32(i)), (a))
#define TPMA_OBJECT_TO_UINT32(a)     (*((UINT32 *)&(a)))
#define TPMA_OBJECT_adminWithPolicy         ((TPMA_OBJECT)1 << 7)
#define TPMA_OBJECT_decrypt                 ((TPMA_OBJECT)1 << 17)
#define TPMA_OBJECT_encryptedDuplication    ((TPMA_OBJECT)1 << 11)
#define TPMA_OBJECT_fixedParent             ((TPMA_OBJECT)1 << 4)
#define TPMA_OBJECT_fixedTPM                ((TPMA_OBJECT)1 << 1)
#define TPMA_OBJECT_noDA                    ((TPMA_OBJECT)1 << 10)
#define TPMA_OBJECT_restricted              ((TPMA_OBJECT)1 << 16)
#define TPMA_OBJECT_sensitiveDataOrigin     ((TPMA_OBJECT)1 << 5)
#define TPMA_OBJECT_sign                    ((TPMA_OBJECT)1 << 18)
#define TPMA_OBJECT_stClear                 ((TPMA_OBJECT)1 << 2)
#define TPMA_OBJECT_userWithAuth            ((TPMA_OBJECT)1 << 6)
#define TPMA_OBJECT_x509sign                ((TPMA_OBJECT)1 << 19)
#define TPMA_PERMANENT_INITIALIZER(					\
				   ownerauthset,       endorsementauthset, lockoutauthset, \
				   bits_at_3,          disableclear,       inlockout, \
				   tpmgeneratedeps,    bits_at_11)	\
    {ownerauthset,       endorsementauthset, lockoutauthset,		\
	    bits_at_3,          disableclear,       inlockout,		\
	    tpmgeneratedeps,    bits_at_11}
#define TPMA_PERMANENT_TO_BYTE_ARRAY(i, a)				\
	            UINT32_TO_BYTE_ARRAY((TPMA_PERMANENT_TO_UINT32(i)), (a))
#define TPMA_PERMANENT_TO_UINT32(a)  (*((UINT32 *)&(a)))
#define TPMA_PERMANENT_disableClear         ((TPMA_PERMANENT)1 << 8)
#define TPMA_PERMANENT_endorsementAuthSet   ((TPMA_PERMANENT)1 << 1)
#define TPMA_PERMANENT_inLockout            ((TPMA_PERMANENT)1 << 9)
#define TPMA_PERMANENT_lockoutAuthSet       ((TPMA_PERMANENT)1 << 2)
#define TPMA_PERMANENT_ownerAuthSet         ((TPMA_PERMANENT)1 << 0)
#define TPMA_PERMANENT_tpmGeneratedEPS      ((TPMA_PERMANENT)1 << 10)
#define TPMA_SESSION_INITIALIZER(					\
				 continuesession, auditexclusive,  auditreset,      bits_at_3, \
				 decrypt,         encrypt,         audit) \
    {continuesession, auditexclusive,  auditreset,      bits_at_3,	\
	    decrypt,         encrypt,         audit}
#define TPMA_SESSION_TO_BYTE_ARRAY(i, a)                                           \
            UINT8_TO_BYTE_ARRAY((TPMA_SESSION_TO_UINT8(i)), (a))
#define TPMA_SESSION_TO_UINT8(a)     (*((UINT8 *)&(a)))
#define TPMA_SESSION_audit              ((TPMA_SESSION)1 << 7)
#define TPMA_SESSION_auditExclusive     ((TPMA_SESSION)1 << 1)
#define TPMA_SESSION_auditReset         ((TPMA_SESSION)1 << 2)
#define TPMA_SESSION_continueSession    ((TPMA_SESSION)1 << 0)
#define TPMA_SESSION_decrypt            ((TPMA_SESSION)1 << 5)
#define TPMA_SESSION_encrypt            ((TPMA_SESSION)1 << 6)
#define TPMA_STARTUP_CLEAR_INITIALIZER(					\
				       phenable, shenable, ehenable, phenablenv, bits_at_4, orderly) \
    {phenable, shenable, ehenable, phenablenv, bits_at_4, orderly}
#define TPMA_STARTUP_CLEAR_TO_BYTE_ARRAY(i, a)				\
    UINT32_TO_BYTE_ARRAY((TPMA_STARTUP_CLEAR_TO_UINT32(i)), (a))
#define TPMA_STARTUP_CLEAR_TO_UINT32(a)  (*((UINT32 *)&(a)))
#define TPMA_STARTUP_CLEAR_ehEnable     ((TPMA_STARTUP_CLEAR)1 << 2)
#define TPMA_STARTUP_CLEAR_orderly      ((TPMA_STARTUP_CLEAR)1 << 31)
#define TPMA_STARTUP_CLEAR_phEnable     ((TPMA_STARTUP_CLEAR)1 << 0)
#define TPMA_STARTUP_CLEAR_phEnableNV   ((TPMA_STARTUP_CLEAR)1 << 3)
#define TPMA_STARTUP_CLEAR_shEnable     ((TPMA_STARTUP_CLEAR)1 << 1)
#define TPMA_X509_KEY_USAGE_INITIALIZER(                                           \
             bits_at_0,        decipheronly,     encipheronly,                     \
             cRLSign,          keycertsign,      keyagreement,                     \
             dataencipherment, keyencipherment,  nonrepudiation,                   \
             digitalsignature)                                                     \
            {bits_at_0,        decipheronly,     encipheronly,                     \
             cRLSign,          keycertsign,      keyagreement,                     \
             dataencipherment, keyencipherment,  nonrepudiation,                   \
             digitalsignature}
#define TPMA_X509_KEY_USAGE_TO_BYTE_ARRAY(i, a)				\
    UINT32_TO_BYTE_ARRAY((TPMA_X509_KEY_USAGE_TO_UINT32(i)), (a))
#define TPMA_X509_KEY_USAGE_TO_UINT32(a)     (*((UINT32 *)&(a)))
#define TPMA_X509_KEY_USAGE_cRLSign             ((TPMA_X509_KEY_USAGE)1 << 25)
#define TPMA_X509_KEY_USAGE_dataEncipherment    ((TPMA_X509_KEY_USAGE)1 << 28)
#define TPMA_X509_KEY_USAGE_decipherOnly        ((TPMA_X509_KEY_USAGE)1 << 23)
#define TPMA_X509_KEY_USAGE_digitalSignature    ((TPMA_X509_KEY_USAGE)1 << 31)
#define TPMA_X509_KEY_USAGE_encipherOnly        ((TPMA_X509_KEY_USAGE)1 << 24)
#define TPMA_X509_KEY_USAGE_keyAgreement        ((TPMA_X509_KEY_USAGE)1 << 27)
#define TPMA_X509_KEY_USAGE_keyCertSign         ((TPMA_X509_KEY_USAGE)1 << 26)
#define TPMA_X509_KEY_USAGE_keyEncipherment     ((TPMA_X509_KEY_USAGE)1 << 29)
#define TPMA_X509_KEY_USAGE_nonrepudiation      ((TPMA_X509_KEY_USAGE)1 << 30)

#define TPM_AE_NONE         (TPM_AE)(0x00000000)
#define TPM_ALG_AES                     (TPM_ALG_ID)(ALG_AES_VALUE)
#define TPM_ALG_CAMELLIA                (TPM_ALG_ID)(ALG_CAMELLIA_VALUE)
#define TPM_ALG_CBC                     (TPM_ALG_ID)(ALG_CBC_VALUE)
#define TPM_ALG_CFB                     (TPM_ALG_ID)(ALG_CFB_VALUE)
#define TPM_ALG_CMAC                    (TPM_ALG_ID)(ALG_CMAC_VALUE)
#define TPM_ALG_CTR                     (TPM_ALG_ID)(ALG_CTR_VALUE)
#define TPM_ALG_ECB                     (TPM_ALG_ID)(ALG_ECB_VALUE)
#define TPM_ALG_ECC                     (TPM_ALG_ID)(ALG_ECC_VALUE)
#define TPM_ALG_ECDAA                   (TPM_ALG_ID)(ALG_ECDAA_VALUE)
#define TPM_ALG_ECDH                    (TPM_ALG_ID)(ALG_ECDH_VALUE)
#define TPM_ALG_ECDSA                   (TPM_ALG_ID)(ALG_ECDSA_VALUE)
#define TPM_ALG_ECMQV                   (TPM_ALG_ID)(ALG_ECMQV_VALUE)
#define TPM_ALG_ECSCHNORR               (TPM_ALG_ID)(ALG_ECSCHNORR_VALUE)
#define TPM_ALG_ERROR                   (TPM_ALG_ID)(ALG_ERROR_VALUE)
#define TPM_ALG_FIRST                   (TPM_ALG_ID)(ALG_FIRST_VALUE)
#define TPM_ALG_HMAC                    (TPM_ALG_ID)(ALG_HMAC_VALUE)
#define TPM_ALG_KDF1_SP800_108          (TPM_ALG_ID)(ALG_KDF1_SP800_108_VALUE)
#define TPM_ALG_KDF1_SP800_56A          (TPM_ALG_ID)(ALG_KDF1_SP800_56A_VALUE)
#define TPM_ALG_KDF2                    (TPM_ALG_ID)(ALG_KDF2_VALUE)
#define TPM_ALG_KEYEDHASH               (TPM_ALG_ID)(ALG_KEYEDHASH_VALUE)
#define TPM_ALG_LAST                    (TPM_ALG_ID)(ALG_LAST_VALUE)
#define TPM_ALG_MGF1                    (TPM_ALG_ID)(ALG_MGF1_VALUE)
#define TPM_ALG_NULL                    (TPM_ALG_ID)(ALG_NULL_VALUE)
#define TPM_ALG_OAEP                    (TPM_ALG_ID)(ALG_OAEP_VALUE)
#define TPM_ALG_OFB                     (TPM_ALG_ID)(ALG_OFB_VALUE)
#define TPM_ALG_RSA                     (TPM_ALG_ID)(ALG_RSA_VALUE)
#define TPM_ALG_RSAES                   (TPM_ALG_ID)(ALG_RSAES_VALUE)
#define TPM_ALG_RSAPSS                  (TPM_ALG_ID)(ALG_RSAPSS_VALUE)
#define TPM_ALG_RSASSA                  (TPM_ALG_ID)(ALG_RSASSA_VALUE)
#define TPM_ALG_SHA                     (TPM_ALG_ID)(ALG_SHA_VALUE)
#define TPM_ALG_SHA1                    (TPM_ALG_ID)(ALG_SHA1_VALUE)
#define TPM_ALG_SHA256                  (TPM_ALG_ID)(ALG_SHA256_VALUE)
#define TPM_ALG_SHA384                  (TPM_ALG_ID)(ALG_SHA384_VALUE)
#define TPM_ALG_SHA3_256                (TPM_ALG_ID)(ALG_SHA3_256_VALUE)
#define TPM_ALG_SHA3_384                (TPM_ALG_ID)(ALG_SHA3_384_VALUE)
#define TPM_ALG_SHA3_512                (TPM_ALG_ID)(ALG_SHA3_512_VALUE)
#define TPM_ALG_SHA512                  (TPM_ALG_ID)(ALG_SHA512_VALUE)
#define TPM_ALG_SM2                     (TPM_ALG_ID)(ALG_SM2_VALUE)
#define TPM_ALG_SM3_256                 (TPM_ALG_ID)(ALG_SM3_256_VALUE)
#define TPM_ALG_SM4                     (TPM_ALG_ID)(ALG_SM4_VALUE)
#define TPM_ALG_SYMCIPHER               (TPM_ALG_ID)(ALG_SYMCIPHER_VALUE)
#define TPM_ALG_TDES                    (TPM_ALG_ID)(ALG_TDES_VALUE)
#define TPM_ALG_XOR                     (TPM_ALG_ID)(ALG_XOR_VALUE)
#define TPM_AT_ANY          (TPM_AT)(0x00000000)
#define TPM_AT_ERROR        (TPM_AT)(0x00000001)
#define TPM_AT_PV1          (TPM_AT)(0x00000002)
#define TPM_AT_VEND         (TPM_AT)(0x80000000)
#define TPM_CAP_ACT 		   (TPM_CAP)(0x0000000a)
#define TPM_CAP_ALGS               (TPM_CAP)(0x00000000)
#define TPM_CAP_AUDIT_COMMANDS     (TPM_CAP)(0x00000004)
#define TPM_CAP_AUTH_POLICIES      (TPM_CAP)(0x00000009)
#define TPM_CAP_COMMANDS           (TPM_CAP)(0x00000002)
#define TPM_CAP_ECC_CURVES         (TPM_CAP)(0x00000008)
#define TPM_CAP_FIRST              (TPM_CAP)(0x00000000)
#define TPM_CAP_HANDLES            (TPM_CAP)(0x00000001)
#define TPM_CAP_LAST               (TPM_CAP)(0x0000000a)
#define TPM_CAP_PCRS               (TPM_CAP)(0x00000005)
#define TPM_CAP_PCR_PROPERTIES     (TPM_CAP)(0x00000007)
#define TPM_CAP_PP_COMMANDS        (TPM_CAP)(0x00000003)
#define TPM_CAP_TPM_PROPERTIES     (TPM_CAP)(0x00000006)
#define TPM_CAP_VENDOR_PROPERTY    (TPM_CAP)(0x00000100)
#define TPM_CC_ACT_SetTimeout               (TPM_CC)(0x00000198)
#define TPM_CC_AC_GetCapability             (TPM_CC)(0x00000194)
#define TPM_CC_AC_Send                      (TPM_CC)(0x00000195)
#define TPM_CC_ActivateCredential           (TPM_CC)(0x00000147)
#define TPM_CC_Certify                      (TPM_CC)(0x00000148)
#define TPM_CC_CertifyCreation              (TPM_CC)(0x0000014A)
#define TPM_CC_CertifyX509                  (TPM_CC)(0x00000197)
#define TPM_CC_ChangeEPS                    (TPM_CC)(0x00000124)
#define TPM_CC_ChangePPS                    (TPM_CC)(0x00000125)
#define TPM_CC_Clear                        (TPM_CC)(0x00000126)
#define TPM_CC_ClearControl                 (TPM_CC)(0x00000127)
#define TPM_CC_ClockRateAdjust              (TPM_CC)(0x00000130)
#define TPM_CC_ClockSet                     (TPM_CC)(0x00000128)
#define TPM_CC_Commit                       (TPM_CC)(0x0000018B)
#define TPM_CC_ContextLoad                  (TPM_CC)(0x00000161)
#define TPM_CC_ContextSave                  (TPM_CC)(0x00000162)
#define TPM_CC_Create                       (TPM_CC)(0x00000153)
#define TPM_CC_CreateLoaded                 (TPM_CC)(0x00000191)
#define TPM_CC_CreatePrimary                (TPM_CC)(0x00000131)
#define TPM_CC_DictionaryAttackLockReset    (TPM_CC)(0x00000139)
#define TPM_CC_DictionaryAttackParameters   (TPM_CC)(0x0000013A)
#define TPM_CC_Duplicate                    (TPM_CC)(0x0000014B)
#define TPM_CC_ECC_Parameters               (TPM_CC)(0x00000178)
#define TPM_CC_ECDH_KeyGen                  (TPM_CC)(0x00000163)
#define TPM_CC_ECDH_ZGen                    (TPM_CC)(0x00000154)
#define TPM_CC_EC_Ephemeral                 (TPM_CC)(0x0000018E)
#define TPM_CC_EncryptDecrypt               (TPM_CC)(0x00000164)
#define TPM_CC_EncryptDecrypt2              (TPM_CC)(0x00000193)
#define TPM_CC_EventSequenceComplete        (TPM_CC)(0x00000185)
#define TPM_CC_EvictControl                 (TPM_CC)(0x00000120)
#define TPM_CC_FieldUpgradeData             (TPM_CC)(0x00000141)
#define TPM_CC_FieldUpgradeStart            (TPM_CC)(0x0000012F)
#define TPM_CC_FirmwareRead                 (TPM_CC)(0x00000179)
#define TPM_CC_FlushContext                 (TPM_CC)(0x00000165)
#define TPM_CC_GetCapability                (TPM_CC)(0x0000017A)
#define TPM_CC_GetCommandAuditDigest        (TPM_CC)(0x00000133)
#define TPM_CC_GetRandom                    (TPM_CC)(0x0000017B)
#define TPM_CC_GetSessionAuditDigest        (TPM_CC)(0x0000014D)
#define TPM_CC_GetTestResult                (TPM_CC)(0x0000017C)
#define TPM_CC_GetTime                      (TPM_CC)(0x0000014C)
#define TPM_CC_HMAC                         (TPM_CC)(0x00000155)
#define TPM_CC_HMAC_Start                   (TPM_CC)(0x0000015B)
#define TPM_CC_Hash                         (TPM_CC)(0x0000017D)
#define TPM_CC_HashSequenceStart            (TPM_CC)(0x00000186)
#define TPM_CC_HierarchyChangeAuth          (TPM_CC)(0x00000129)
#define TPM_CC_HierarchyControl             (TPM_CC)(0x00000121)
#define TPM_CC_Import                       (TPM_CC)(0x00000156)
#define TPM_CC_IncrementalSelfTest          (TPM_CC)(0x00000142)
#define TPM_CC_Load                         (TPM_CC)(0x00000157)
#define TPM_CC_LoadExternal                 (TPM_CC)(0x00000167)
#define TPM_CC_MAC                          (TPM_CC)(0x00000155)
#define TPM_CC_MAC_Start                    (TPM_CC)(0x0000015B)
#define TPM_CC_MakeCredential               (TPM_CC)(0x00000168)
#define TPM_CC_NV_Certify                   (TPM_CC)(0x00000184)
#define TPM_CC_NV_ChangeAuth                (TPM_CC)(0x0000013B)
#define TPM_CC_NV_DefineSpace               (TPM_CC)(0x0000012A)
#define TPM_CC_NV_Extend                    (TPM_CC)(0x00000136)
#define TPM_CC_NV_GlobalWriteLock           (TPM_CC)(0x00000132)
#define TPM_CC_NV_Increment                 (TPM_CC)(0x00000134)
#define TPM_CC_NV_Read                      (TPM_CC)(0x0000014E)
#define TPM_CC_NV_ReadLock                  (TPM_CC)(0x0000014F)
#define TPM_CC_NV_ReadPublic                (TPM_CC)(0x00000169)
#define TPM_CC_NV_SetBits                   (TPM_CC)(0x00000135)
#define TPM_CC_NV_UndefineSpace             (TPM_CC)(0x00000122)
#define TPM_CC_NV_UndefineSpaceSpecial      (TPM_CC)(0x0000011F)
#define TPM_CC_NV_Write                     (TPM_CC)(0x00000137)
#define TPM_CC_NV_WriteLock                 (TPM_CC)(0x00000138)
#define TPM_CC_ObjectChangeAuth             (TPM_CC)(0x00000150)
#define TPM_CC_PCR_Allocate                 (TPM_CC)(0x0000012B)
#define TPM_CC_PCR_Event                    (TPM_CC)(0x0000013C)
#define TPM_CC_PCR_Extend                   (TPM_CC)(0x00000182)
#define TPM_CC_PCR_Read                     (TPM_CC)(0x0000017E)
#define TPM_CC_PCR_Reset                    (TPM_CC)(0x0000013D)
#define TPM_CC_PCR_SetAuthPolicy            (TPM_CC)(0x0000012C)
#define TPM_CC_PCR_SetAuthValue             (TPM_CC)(0x00000183)
#define TPM_CC_PP_Commands                  (TPM_CC)(0x0000012D)
#define TPM_CC_PolicyAuthValue              (TPM_CC)(0x0000016B)
#define TPM_CC_PolicyAuthorize              (TPM_CC)(0x0000016A)
#define TPM_CC_PolicyAuthorizeNV            (TPM_CC)(0x00000192)
#define TPM_CC_PolicyCommandCode            (TPM_CC)(0x0000016C)
#define TPM_CC_PolicyCounterTimer           (TPM_CC)(0x0000016D)
#define TPM_CC_PolicyCpHash                 (TPM_CC)(0x0000016E)
#define TPM_CC_PolicyDuplicationSelect      (TPM_CC)(0x00000188)
#define TPM_CC_PolicyGetDigest              (TPM_CC)(0x00000189)
#define TPM_CC_PolicyLocality               (TPM_CC)(0x0000016F)
#define TPM_CC_PolicyNV                     (TPM_CC)(0x00000149)
#define TPM_CC_PolicyNameHash               (TPM_CC)(0x00000170)
#define TPM_CC_PolicyNvWritten              (TPM_CC)(0x0000018F)
#define TPM_CC_PolicyOR                     (TPM_CC)(0x00000171)
#define TPM_CC_PolicyPCR                    (TPM_CC)(0x0000017F)
#define TPM_CC_PolicyPassword               (TPM_CC)(0x0000018C)
#define TPM_CC_PolicyPhysicalPresence       (TPM_CC)(0x00000187)
#define TPM_CC_PolicyRestart                (TPM_CC)(0x00000180)
#define TPM_CC_PolicySecret                 (TPM_CC)(0x00000151)
#define TPM_CC_PolicySigned                 (TPM_CC)(0x00000160)
#define TPM_CC_PolicyTemplate               (TPM_CC)(0x00000190)
#define TPM_CC_PolicyTicket                 (TPM_CC)(0x00000172)
#define TPM_CC_Policy_AC_SendSelect         (TPM_CC)(0x00000196)
#define TPM_CC_Quote                        (TPM_CC)(0x00000158)
#define TPM_CC_RSA_Decrypt                  (TPM_CC)(0x00000159)
#define TPM_CC_RSA_Encrypt                  (TPM_CC)(0x00000174)
#define TPM_CC_ReadClock                    (TPM_CC)(0x00000181)
#define TPM_CC_ReadPublic                   (TPM_CC)(0x00000173)
#define TPM_CC_Rewrap                       (TPM_CC)(0x00000152)
#define TPM_CC_SelfTest                     (TPM_CC)(0x00000143)
#define TPM_CC_SequenceComplete             (TPM_CC)(0x0000013E)
#define TPM_CC_SequenceUpdate               (TPM_CC)(0x0000015C)
#define TPM_CC_SetAlgorithmSet              (TPM_CC)(0x0000013F)
#define TPM_CC_SetCommandCodeAuditStatus    (TPM_CC)(0x00000140)
#define TPM_CC_SetPrimaryPolicy             (TPM_CC)(0x0000012E)
#define TPM_CC_Shutdown                     (TPM_CC)(0x00000145)
#define TPM_CC_Sign                         (TPM_CC)(0x0000015D)
#define TPM_CC_StartAuthSession             (TPM_CC)(0x00000176)
#define TPM_CC_Startup                      (TPM_CC)(0x00000144)
#define TPM_CC_StirRandom                   (TPM_CC)(0x00000146)
#define TPM_CC_TestParms                    (TPM_CC)(0x0000018A)
#define TPM_CC_Unseal                       (TPM_CC)(0x0000015E)
#define TPM_CC_Vendor_TCG_Test              (TPM_CC)(0x20000000)
#define TPM_CC_VerifySignature              (TPM_CC)(0x00000177)
#define TPM_CC_ZGen_2Phase                  (TPM_CC)(0x0000018D)
#define TPM_CLOCK_COARSE_FASTER    (TPM_CLOCK_ADJUST)(3)
#define TPM_CLOCK_COARSE_SLOWER    (TPM_CLOCK_ADJUST)(-3)
#define TPM_CLOCK_FINE_FASTER      (TPM_CLOCK_ADJUST)(1)
#define TPM_CLOCK_FINE_SLOWER      (TPM_CLOCK_ADJUST)(-1)
#define TPM_CLOCK_MEDIUM_FASTER    (TPM_CLOCK_ADJUST)(2)
#define TPM_CLOCK_MEDIUM_SLOWER    (TPM_CLOCK_ADJUST)(-2)
#define TPM_CLOCK_NO_CHANGE        (TPM_CLOCK_ADJUST)(0)
#define TPM_ECC_BN_P256     (TPM_ECC_CURVE)(0x0010)
#define TPM_ECC_BN_P638     (TPM_ECC_CURVE)(0x0011)
#define TPM_ECC_NIST_P192   (TPM_ECC_CURVE)(0x0001)
#define TPM_ECC_NIST_P224   (TPM_ECC_CURVE)(0x0002)
#define TPM_ECC_NIST_P256   (TPM_ECC_CURVE)(0x0003)
#define TPM_ECC_NIST_P384   (TPM_ECC_CURVE)(0x0004)
#define TPM_ECC_NIST_P521   (TPM_ECC_CURVE)(0x0005)
#define TPM_ECC_NONE        (TPM_ECC_CURVE)(0x0000)
#define TPM_ECC_SM2_P256    (TPM_ECC_CURVE)(0x0020)
#define TPM_EO_BITCLEAR       (TPM_EO)(0x000B)
#define TPM_EO_BITSET         (TPM_EO)(0x000A)
#define TPM_EO_EQ             (TPM_EO)(0x0000)
#define TPM_EO_NEQ            (TPM_EO)(0x0001)
#define TPM_EO_SIGNED_GE      (TPM_EO)(0x0006)
#define TPM_EO_SIGNED_GT      (TPM_EO)(0x0002)
#define TPM_EO_SIGNED_LE      (TPM_EO)(0x0008)
#define TPM_EO_SIGNED_LT      (TPM_EO)(0x0004)
#define TPM_EO_UNSIGNED_GE    (TPM_EO)(0x0007)
#define TPM_EO_UNSIGNED_GT    (TPM_EO)(0x0003)
#define TPM_EO_UNSIGNED_LE    (TPM_EO)(0x0009)
#define TPM_EO_UNSIGNED_LT    (TPM_EO)(0x0005)
#define TPM_GENERATED_VALUE     (TPM_CONSTANTS32)(0xFF544347)
#define TPM_HT_AC                (TPM_HT)(0x90)
#define TPM_HT_HMAC_SESSION      (TPM_HT)(0x02)
#define TPM_HT_LOADED_SESSION    (TPM_HT)(0x02)
#define TPM_HT_NV_INDEX          (TPM_HT)(0x01)
#define TPM_HT_PCR               (TPM_HT)(0x00)
#define TPM_HT_PERMANENT         (TPM_HT)(0x40)
#define TPM_HT_PERSISTENT        (TPM_HT)(0x81)
#define TPM_HT_POLICY_SESSION    (TPM_HT)(0x03)
#define TPM_HT_SAVED_SESSION     (TPM_HT)(0x03)
#define TPM_HT_TRANSIENT         (TPM_HT)(0x80)
#define TPM_NT_PIN_FAIL     (TPM_NT)(0x8)
#define TPM_NT_PIN_PASS     (TPM_NT)(0x9)
#define TPM_NV_INDEX_INITIALIZER(index, rh_nv) {index, rh_nv}
#define TPM_NV_INDEX_RH_NV          ((TPM_NV_INDEX)0xff << 24)
#define TPM_NV_INDEX_RH_NV_SHIFT    24
#define TPM_NV_INDEX_TO_BYTE_ARRAY(i, a)                                           \
            UINT32_TO_BYTE_ARRAY((TPM_NV_INDEX_TO_UINT32(i)), (a))
#define TPM_NV_INDEX_TO_UINT32(a)    (*((UINT32 *)&(a)))
#define TPM_NV_INDEX_index          ((TPM_NV_INDEX)0xffffff << 0)
#define TPM_NV_INDEX_index_SHIFT    0
#define TPM_PS_AUTHENTICATION    (TPM_PS)(0x00000008)
#define TPM_PS_CELL_PHONE        (TPM_PS)(0x00000003)
#define TPM_PS_EMBEDDED          (TPM_PS)(0x00000009)
#define TPM_PS_HARDCOPY          (TPM_PS)(0x0000000A)
#define TPM_PS_INFRASTRUCTURE    (TPM_PS)(0x0000000B)
#define TPM_PS_MAIN              (TPM_PS)(0x00000000)
#define TPM_PS_MULTI_TENANT      (TPM_PS)(0x0000000E)
#define TPM_PS_PC                (TPM_PS)(0x00000001)
#define TPM_PS_PDA               (TPM_PS)(0x00000002)
#define TPM_PS_PERIPHERAL        (TPM_PS)(0x00000005)
#define TPM_PS_SERVER            (TPM_PS)(0x00000004)
#define TPM_PS_STORAGE           (TPM_PS)(0x00000007)
#define TPM_PS_TC                (TPM_PS)(0x0000000F)
#define TPM_PS_TNC               (TPM_PS)(0x0000000D)
#define TPM_PS_TSS               (TPM_PS)(0x00000006)
#define TPM_PS_VIRTUALIZATION    (TPM_PS)(0x0000000C)
#define TPM_PT_ACTIVE_SESSIONS_MAX    (TPM_PT)(PT_FIXED+17)
#define TPM_PT_ALGORITHM_SET          (TPM_PT)(PT_VAR+12)
#define TPM_PT_AUDIT_COUNTER_0        (TPM_PT)(PT_VAR+19)
#define TPM_PT_AUDIT_COUNTER_1        (TPM_PT)(PT_VAR+20)
#define TPM_PT_CLOCK_UPDATE           (TPM_PT)(PT_FIXED+25)
#define TPM_PT_CONTEXT_GAP_MAX        (TPM_PT)(PT_FIXED+20)
#define TPM_PT_CONTEXT_HASH           (TPM_PT)(PT_FIXED+26)
#define TPM_PT_CONTEXT_SYM            (TPM_PT)(PT_FIXED+27)
#define TPM_PT_CONTEXT_SYM_SIZE       (TPM_PT)(PT_FIXED+28)
#define TPM_PT_DAY_OF_YEAR            (TPM_PT)(PT_FIXED+3)
#define TPM_PT_FAMILY_INDICATOR       (TPM_PT)(PT_FIXED+0)
#define TPM_PT_FIRMWARE_VERSION_1     (TPM_PT)(PT_FIXED+11)
#define TPM_PT_FIRMWARE_VERSION_2     (TPM_PT)(PT_FIXED+12)
#define TPM_PT_HR_ACTIVE              (TPM_PT)(PT_VAR+5)
#define TPM_PT_HR_ACTIVE_AVAIL        (TPM_PT)(PT_VAR+6)
#define TPM_PT_HR_LOADED              (TPM_PT)(PT_VAR+3)
#define TPM_PT_HR_LOADED_AVAIL        (TPM_PT)(PT_VAR+4)
#define TPM_PT_HR_LOADED_MIN          (TPM_PT)(PT_FIXED+16)
#define TPM_PT_HR_NV_INDEX            (TPM_PT)(PT_VAR+2)
#define TPM_PT_HR_PERSISTENT          (TPM_PT)(PT_VAR+8)
#define TPM_PT_HR_PERSISTENT_AVAIL    (TPM_PT)(PT_VAR+9)
#define TPM_PT_HR_PERSISTENT_MIN      (TPM_PT)(PT_FIXED+15)
#define TPM_PT_HR_TRANSIENT_AVAIL     (TPM_PT)(PT_VAR+7)
#define TPM_PT_HR_TRANSIENT_MIN       (TPM_PT)(PT_FIXED+14)
#define TPM_PT_INPUT_BUFFER           (TPM_PT)(PT_FIXED+13)
#define TPM_PT_LEVEL                  (TPM_PT)(PT_FIXED+1)
#define TPM_PT_LIBRARY_COMMANDS       (TPM_PT)(PT_FIXED+42)
#define TPM_PT_LOADED_CURVES          (TPM_PT)(PT_VAR+13)
#define TPM_PT_LOCKOUT_COUNTER        (TPM_PT)(PT_VAR+14)
#define TPM_PT_LOCKOUT_INTERVAL       (TPM_PT)(PT_VAR+16)
#define TPM_PT_LOCKOUT_RECOVERY       (TPM_PT)(PT_VAR+17)
#define TPM_PT_MANUFACTURER           (TPM_PT)(PT_FIXED+5)
#define TPM_PT_MAX_AUTH_FAIL          (TPM_PT)(PT_VAR+15)
#define TPM_PT_MAX_CAP_BUFFER         (TPM_PT)(PT_FIXED+46)
#define TPM_PT_MAX_COMMAND_SIZE       (TPM_PT)(PT_FIXED+30)
#define TPM_PT_MAX_DIGEST             (TPM_PT)(PT_FIXED+32)
#define TPM_PT_MAX_OBJECT_CONTEXT     (TPM_PT)(PT_FIXED+33)
#define TPM_PT_MAX_RESPONSE_SIZE      (TPM_PT)(PT_FIXED+31)
#define TPM_PT_MAX_SESSION_CONTEXT    (TPM_PT)(PT_FIXED+34)
#define TPM_PT_MEMORY                 (TPM_PT)(PT_FIXED+24)
#define TPM_PT_MODES                  (TPM_PT)(PT_FIXED+45)
#define TPM_PT_NONE                   (TPM_PT)(0x00000000)
#define TPM_PT_NV_BUFFER_MAX          (TPM_PT)(PT_FIXED+44)
#define TPM_PT_NV_COUNTERS            (TPM_PT)(PT_VAR+10)
#define TPM_PT_NV_COUNTERS_AVAIL      (TPM_PT)(PT_VAR+11)
#define TPM_PT_NV_COUNTERS_MAX        (TPM_PT)(PT_FIXED+22)
#define TPM_PT_NV_INDEX_MAX           (TPM_PT)(PT_FIXED+23)
#define TPM_PT_NV_WRITE_RECOVERY      (TPM_PT)(PT_VAR+18)
#define TPM_PT_ORDERLY_COUNT          (TPM_PT)(PT_FIXED+29)
#define TPM_PT_PCR_AUTH            (TPM_PT_PCR)(0x00000014)
#define TPM_PT_PCR_COUNT              (TPM_PT)(PT_FIXED+18)
#define TPM_PT_PCR_DRTM_RESET      (TPM_PT_PCR)(0x00000012)
#define TPM_PT_PCR_EXTEND_L0       (TPM_PT_PCR)(0x00000001)
#define TPM_PT_PCR_EXTEND_L1       (TPM_PT_PCR)(0x00000003)
#define TPM_PT_PCR_EXTEND_L2       (TPM_PT_PCR)(0x00000005)
#define TPM_PT_PCR_EXTEND_L3       (TPM_PT_PCR)(0x00000007)
#define TPM_PT_PCR_EXTEND_L4       (TPM_PT_PCR)(0x00000009)
#define TPM_PT_PCR_FIRST           (TPM_PT_PCR)(0x00000000)
#define TPM_PT_PCR_LAST            (TPM_PT_PCR)(0x00000014)
#define TPM_PT_PCR_NO_INCREMENT    (TPM_PT_PCR)(0x00000011)
#define TPM_PT_PCR_POLICY          (TPM_PT_PCR)(0x00000013)
#define TPM_PT_PCR_RESET_L0        (TPM_PT_PCR)(0x00000002)
#define TPM_PT_PCR_RESET_L1        (TPM_PT_PCR)(0x00000004)
#define TPM_PT_PCR_RESET_L2        (TPM_PT_PCR)(0x00000006)
#define TPM_PT_PCR_RESET_L3        (TPM_PT_PCR)(0x00000008)
#define TPM_PT_PCR_RESET_L4        (TPM_PT_PCR)(0x0000000A)
#define TPM_PT_PCR_SAVE            (TPM_PT_PCR)(0x00000000)
#define TPM_PT_PCR_SELECT_MIN         (TPM_PT)(PT_FIXED+19)
#define TPM_PT_PERMANENT              (TPM_PT)(PT_VAR+0)
#define TPM_PT_PS_DAY_OF_YEAR         (TPM_PT)(PT_FIXED+38)
#define TPM_PT_PS_FAMILY_INDICATOR    (TPM_PT)(PT_FIXED+35)
#define TPM_PT_PS_LEVEL               (TPM_PT)(PT_FIXED+36)
#define TPM_PT_PS_REVISION            (TPM_PT)(PT_FIXED+37)
#define TPM_PT_PS_YEAR                (TPM_PT)(PT_FIXED+39)
#define TPM_PT_REVISION               (TPM_PT)(PT_FIXED+2)
#define TPM_PT_SPLIT_MAX              (TPM_PT)(PT_FIXED+40)
#define TPM_PT_STARTUP_CLEAR          (TPM_PT)(PT_VAR+1)
#define TPM_PT_TOTAL_COMMANDS         (TPM_PT)(PT_FIXED+41)
#define TPM_PT_VENDOR_COMMANDS        (TPM_PT)(PT_FIXED+43)
#define TPM_PT_VENDOR_STRING_1        (TPM_PT)(PT_FIXED+6)
#define TPM_PT_VENDOR_STRING_2        (TPM_PT)(PT_FIXED+7)
#define TPM_PT_VENDOR_STRING_3        (TPM_PT)(PT_FIXED+8)
#define TPM_PT_VENDOR_STRING_4        (TPM_PT)(PT_FIXED+9)
#define TPM_PT_VENDOR_TPM_TYPE        (TPM_PT)(PT_FIXED+10)
#define TPM_PT_YEAR                   (TPM_PT)(PT_FIXED+4)
#define TPM_RCS_ASYMMETRIC          (TPM_RC)(RC_FMT1+0x001)
#define TPM_RCS_ATTRIBUTES          (TPM_RC)(RC_FMT1+0x002)
#define TPM_RCS_AUTH_FAIL           (TPM_RC)(RC_FMT1+0x00E)
#define TPM_RCS_BAD_AUTH            (TPM_RC)(RC_FMT1+0x022)
#define TPM_RCS_BINDING             (TPM_RC)(RC_FMT1+0x025)
#define TPM_RCS_CURVE               (TPM_RC)(RC_FMT1+0x026)
#define TPM_RCS_ECC_POINT           (TPM_RC)(RC_FMT1+0x027)
#define TPM_RCS_EXPIRED             (TPM_RC)(RC_FMT1+0x023)
#define TPM_RCS_HANDLE              (TPM_RC)(RC_FMT1+0x00B)
#define TPM_RCS_HASH                (TPM_RC)(RC_FMT1+0x003)
#define TPM_RCS_HIERARCHY           (TPM_RC)(RC_FMT1+0x005)
#define TPM_RCS_INSUFFICIENT        (TPM_RC)(RC_FMT1+0x01A)
#define TPM_RCS_INTEGRITY           (TPM_RC)(RC_FMT1+0x01F)
#define TPM_RCS_KDF                 (TPM_RC)(RC_FMT1+0x00C)
#define TPM_RCS_KEY                 (TPM_RC)(RC_FMT1+0x01C)
#define TPM_RCS_KEY_SIZE            (TPM_RC)(RC_FMT1+0x007)
#define TPM_RCS_MGF                 (TPM_RC)(RC_FMT1+0x008)
#define TPM_RCS_MODE                (TPM_RC)(RC_FMT1+0x009)
#define TPM_RCS_NONCE               (TPM_RC)(RC_FMT1+0x00F)
#define TPM_RCS_POLICY_CC           (TPM_RC)(RC_FMT1+0x024)
#define TPM_RCS_POLICY_FAIL         (TPM_RC)(RC_FMT1+0x01D)
#define TPM_RCS_PP                  (TPM_RC)(RC_FMT1+0x010)
#define TPM_RCS_RANGE               (TPM_RC)(RC_FMT1+0x00D)
#define TPM_RCS_RESERVED_BITS       (TPM_RC)(RC_FMT1+0x021)
#define TPM_RCS_SCHEME              (TPM_RC)(RC_FMT1+0x012)
#define TPM_RCS_SELECTOR            (TPM_RC)(RC_FMT1+0x018)
#define TPM_RCS_SIGNATURE           (TPM_RC)(RC_FMT1+0x01B)
#define TPM_RCS_SIZE                (TPM_RC)(RC_FMT1+0x015)
#define TPM_RCS_SYMMETRIC           (TPM_RC)(RC_FMT1+0x016)
#define TPM_RCS_TAG                 (TPM_RC)(RC_FMT1+0x017)
#define TPM_RCS_TICKET              (TPM_RC)(RC_FMT1+0x020)
#define TPM_RCS_TYPE                (TPM_RC)(RC_FMT1+0x00A)
#define TPM_RCS_VALUE               (TPM_RC)(RC_FMT1+0x004)
#define TPM_RC_1                    (TPM_RC)(0x100)
#define TPM_RC_2                    (TPM_RC)(0x200)
#define TPM_RC_3                    (TPM_RC)(0x300)
#define TPM_RC_4                    (TPM_RC)(0x400)
#define TPM_RC_5                    (TPM_RC)(0x500)
#define TPM_RC_6                    (TPM_RC)(0x600)
#define TPM_RC_7                    (TPM_RC)(0x700)
#define TPM_RC_8                    (TPM_RC)(0x800)
#define TPM_RC_9                    (TPM_RC)(0x900)
#define TPM_RC_A                    (TPM_RC)(0xA00)
#define TPM_RC_ASYMMETRIC           (TPM_RC)(RC_FMT1+0x001)
#define TPM_RC_ATTRIBUTES           (TPM_RC)(RC_FMT1+0x002)
#define TPM_RC_AUTHSIZE             (TPM_RC)(RC_VER1+0x044)
#define TPM_RC_AUTH_CONTEXT         (TPM_RC)(RC_VER1+0x045)
#define TPM_RC_AUTH_FAIL            (TPM_RC)(RC_FMT1+0x00E)
#define TPM_RC_AUTH_MISSING         (TPM_RC)(RC_VER1+0x025)
#define TPM_RC_AUTH_TYPE            (TPM_RC)(RC_VER1+0x024)
#define TPM_RC_AUTH_UNAVAILABLE     (TPM_RC)(RC_VER1+0x02F)
#define TPM_RC_B                    (TPM_RC)(0xB00)
#define TPM_RC_BAD_AUTH             (TPM_RC)(RC_FMT1+0x022)
#define TPM_RC_BAD_CONTEXT          (TPM_RC)(RC_VER1+0x050)
#define TPM_RC_BAD_TAG              (TPM_RC)(0x01E)
#define TPM_RC_BINDING              (TPM_RC)(RC_FMT1+0x025)
#define TPM_RC_C                    (TPM_RC)(0xC00)
#define TPM_RC_CANCELED             (TPM_RC)(RC_WARN+0x009)
#define TPM_RC_COMMAND_CODE         (TPM_RC)(RC_VER1+0x043)
#define TPM_RC_COMMAND_SIZE         (TPM_RC)(RC_VER1+0x042)
#define TPM_RC_CONTEXT_GAP          (TPM_RC)(RC_WARN+0x001)
#define TPM_RC_CPHASH               (TPM_RC)(RC_VER1+0x051)
#define TPM_RC_CURVE                (TPM_RC)(RC_FMT1+0x026)
#define TPM_RC_D                    (TPM_RC)(0xD00)
#define TPM_RC_DISABLED             (TPM_RC)(RC_VER1+0x020)
#define TPM_RC_E                    (TPM_RC)(0xE00)
#define TPM_RC_ECC_POINT            (TPM_RC)(RC_FMT1+0x027)
#define TPM_RC_EXCLUSIVE            (TPM_RC)(RC_VER1+0x021)
#define TPM_RC_EXPIRED              (TPM_RC)(RC_FMT1+0x023)
#define TPM_RC_F                    (TPM_RC)(0xF00)
#define TPM_RC_FAILURE              (TPM_RC)(RC_VER1+0x001)
#define TPM_RC_H                    (TPM_RC)(0x000)
#define TPM_RC_HANDLE               (TPM_RC)(RC_FMT1+0x00B)
#define TPM_RC_HASH                 (TPM_RC)(RC_FMT1+0x003)
#define TPM_RC_HIERARCHY            (TPM_RC)(RC_FMT1+0x005)
#define TPM_RC_HMAC                 (TPM_RC)(RC_VER1+0x019)
#define TPM_RC_INITIALIZE           (TPM_RC)(RC_VER1+0x000)
#define TPM_RC_INSUFFICIENT         (TPM_RC)(RC_FMT1+0x01A)
#define TPM_RC_INTEGRITY            (TPM_RC)(RC_FMT1+0x01F)
#define TPM_RC_KDF                  (TPM_RC)(RC_FMT1+0x00C)
#define TPM_RC_KEY                  (TPM_RC)(RC_FMT1+0x01C)
#define TPM_RC_KEY_SIZE             (TPM_RC)(RC_FMT1+0x007)
#define TPM_RC_LOCALITY             (TPM_RC)(RC_WARN+0x007)
#define TPM_RC_LOCKOUT              (TPM_RC)(RC_WARN+0x021)
#define TPM_RC_MEMORY               (TPM_RC)(RC_WARN+0x004)
#define TPM_RC_MGF                  (TPM_RC)(RC_FMT1+0x008)
#define TPM_RC_MODE                 (TPM_RC)(RC_FMT1+0x009)
#define TPM_RC_NEEDS_TEST           (TPM_RC)(RC_VER1+0x053)
#define TPM_RC_NONCE                (TPM_RC)(RC_FMT1+0x00F)
#define TPM_RC_NOT_USED             (TPM_RC)(RC_WARN+0x7F)
#define TPM_RC_NO_RESULT            (TPM_RC)(RC_VER1+0x054)
#define TPM_RC_NV_AUTHORIZATION     (TPM_RC)(RC_VER1+0x049)
#define TPM_RC_NV_DEFINED           (TPM_RC)(RC_VER1+0x04C)
#define TPM_RC_NV_LOCKED            (TPM_RC)(RC_VER1+0x048)
#define TPM_RC_NV_RANGE             (TPM_RC)(RC_VER1+0x046)
#define TPM_RC_NV_RATE              (TPM_RC)(RC_WARN+0x020)
#define TPM_RC_NV_SIZE              (TPM_RC)(RC_VER1+0x047)
#define TPM_RC_NV_SPACE             (TPM_RC)(RC_VER1+0x04B)
#define TPM_RC_NV_UNAVAILABLE       (TPM_RC)(RC_WARN+0x023)
#define TPM_RC_NV_UNINITIALIZED     (TPM_RC)(RC_VER1+0x04A)
#define TPM_RC_N_MASK               (TPM_RC)(0xF00)
#define TPM_RC_OBJECT_HANDLES       (TPM_RC)(RC_WARN+0x006)
#define TPM_RC_OBJECT_MEMORY        (TPM_RC)(RC_WARN+0x002)
#define TPM_RC_P                    (TPM_RC)(0x040)
#define TPM_RC_PARENT               (TPM_RC)(RC_VER1+0x052)
#define TPM_RC_PCR                  (TPM_RC)(RC_VER1+0x027)
#define TPM_RC_PCR_CHANGED          (TPM_RC)(RC_VER1+0x028)
#define TPM_RC_POLICY               (TPM_RC)(RC_VER1+0x026)
#define TPM_RC_POLICY_CC            (TPM_RC)(RC_FMT1+0x024)
#define TPM_RC_POLICY_FAIL          (TPM_RC)(RC_FMT1+0x01D)
#define TPM_RC_PP                   (TPM_RC)(RC_FMT1+0x010)
#define TPM_RC_PRIVATE              (TPM_RC)(RC_VER1+0x00B)
#define TPM_RC_RANGE                (TPM_RC)(RC_FMT1+0x00D)
#define TPM_RC_REBOOT               (TPM_RC)(RC_VER1+0x030)
#define TPM_RC_REFERENCE_H0         (TPM_RC)(RC_WARN+0x010)
#define TPM_RC_REFERENCE_H1         (TPM_RC)(RC_WARN+0x011)
#define TPM_RC_REFERENCE_H2         (TPM_RC)(RC_WARN+0x012)
#define TPM_RC_REFERENCE_H3         (TPM_RC)(RC_WARN+0x013)
#define TPM_RC_REFERENCE_H4         (TPM_RC)(RC_WARN+0x014)
#define TPM_RC_REFERENCE_H5         (TPM_RC)(RC_WARN+0x015)
#define TPM_RC_REFERENCE_H6         (TPM_RC)(RC_WARN+0x016)
#define TPM_RC_REFERENCE_S0         (TPM_RC)(RC_WARN+0x018)
#define TPM_RC_REFERENCE_S1         (TPM_RC)(RC_WARN+0x019)
#define TPM_RC_REFERENCE_S2         (TPM_RC)(RC_WARN+0x01A)
#define TPM_RC_REFERENCE_S3         (TPM_RC)(RC_WARN+0x01B)
#define TPM_RC_REFERENCE_S4         (TPM_RC)(RC_WARN+0x01C)
#define TPM_RC_REFERENCE_S5         (TPM_RC)(RC_WARN+0x01D)
#define TPM_RC_REFERENCE_S6         (TPM_RC)(RC_WARN+0x01E)
#define TPM_RC_RESERVED_BITS        (TPM_RC)(RC_FMT1+0x021)
#define TPM_RC_RETRY                (TPM_RC)(RC_WARN+0x022)
#define TPM_RC_S                    (TPM_RC)(0x800)
#define TPM_RC_SCHEME               (TPM_RC)(RC_FMT1+0x012)
#define TPM_RC_SELECTOR             (TPM_RC)(RC_FMT1+0x018)
#define TPM_RC_SENSITIVE            (TPM_RC)(RC_VER1+0x055)
#define TPM_RC_SEQUENCE             (TPM_RC)(RC_VER1+0x003)
#define TPM_RC_SESSION_HANDLES      (TPM_RC)(RC_WARN+0x005)
#define TPM_RC_SESSION_MEMORY       (TPM_RC)(RC_WARN+0x003)
#define TPM_RC_SIGNATURE            (TPM_RC)(RC_FMT1+0x01B)
#define TPM_RC_SIZE                 (TPM_RC)(RC_FMT1+0x015)
#define TPM_RC_SUCCESS              (TPM_RC)(0x000)
#define TPM_RC_SYMMETRIC            (TPM_RC)(RC_FMT1+0x016)
#define TPM_RC_TAG                  (TPM_RC)(RC_FMT1+0x017)
#define TPM_RC_TESTING              (TPM_RC)(RC_WARN+0x00A)
#define TPM_RC_TICKET               (TPM_RC)(RC_FMT1+0x020)
#define TPM_RC_TOO_MANY_CONTEXTS    (TPM_RC)(RC_VER1+0x02E)
#define TPM_RC_TYPE                 (TPM_RC)(RC_FMT1+0x00A)
#define TPM_RC_UNBALANCED           (TPM_RC)(RC_VER1+0x031)
#define TPM_RC_UPGRADE              (TPM_RC)(RC_VER1+0x02D)
#define TPM_RC_VALUE                (TPM_RC)(RC_FMT1+0x004)
#define TPM_RC_YIELDED              (TPM_RC)(RC_WARN+0x008)
#define  TPM_RH_ACT_0          (TPM_RH)(0x40000110)
#define  TPM_RH_ADMIN          (TPM_RH)(0x40000005)
#define  TPM_RH_AUTH_00        (TPM_RH)(0x40000010)
#define  TPM_RH_AUTH_FF        (TPM_RH)(0x4000010F)
#define  TPM_RH_EK             (TPM_RH)(0x40000006)
#define  TPM_RH_ENDORSEMENT    (TPM_RH)(0x4000000B)
#define  TPM_RH_FIRST          (TPM_RH)(0x40000000)
#define  TPM_RH_LAST           (TPM_RH)(0x4000011F)
#define  TPM_RH_LOCKOUT        (TPM_RH)(0x4000000A)
#define  TPM_RH_NULL           (TPM_RH)(0x40000007)
#define  TPM_RH_OPERATOR       (TPM_RH)(0x40000004)
#define  TPM_RH_OWNER          (TPM_RH)(0x40000001)
#define  TPM_RH_PLATFORM       (TPM_RH)(0x4000000C)
#define  TPM_RH_PLATFORM_NV    (TPM_RH)(0x4000000D)
#define  TPM_RH_REVOKE         (TPM_RH)(0x40000002)
#define  TPM_RH_SRK            (TPM_RH)(0x40000000)
#define  TPM_RH_TRANSPORT      (TPM_RH)(0x40000003)
#define  TPM_RH_UNASSIGNED     (TPM_RH)(0x40000008)
#define  TPM_RS_PW             (TPM_RH)(0x40000009)
#define TPM_SE_HMAC      (TPM_SE)(0x00)
#define TPM_SE_POLICY    (TPM_SE)(0x01)
#define TPM_SE_TRIAL     (TPM_SE)(0x03)
#define TPM_SPEC_DAY_OF_YEAR    (TPM_SPEC)(SPEC_DAY_OF_YEAR)
#define TPM_SPEC_FAMILY         (TPM_SPEC)(SPEC_FAMILY)
#define TPM_SPEC_LEVEL          (TPM_SPEC)(SPEC_LEVEL)
#define TPM_SPEC_VERSION        (TPM_SPEC)(SPEC_VERSION)
#define TPM_SPEC_YEAR           (TPM_SPEC)(SPEC_YEAR)
#define TPM_ST_ATTEST_CERTIFY          (TPM_ST)(0x8017)
#define TPM_ST_ATTEST_COMMAND_AUDIT    (TPM_ST)(0x8015)
#define TPM_ST_ATTEST_CREATION         (TPM_ST)(0x801A)
#define TPM_ST_ATTEST_NV               (TPM_ST)(0x8014)
#define TPM_ST_ATTEST_QUOTE            (TPM_ST)(0x8018)
#define TPM_ST_ATTEST_SESSION_AUDIT    (TPM_ST)(0x8016)
#define TPM_ST_ATTEST_TIME             (TPM_ST)(0x8019)
#define TPM_ST_AUTH_SECRET             (TPM_ST)(0x8023)
#define TPM_ST_AUTH_SIGNED             (TPM_ST)(0x8025)
#define TPM_ST_CREATION                (TPM_ST)(0x8021)
#define TPM_ST_FU_MANIFEST             (TPM_ST)(0x8029)
#define TPM_ST_HASHCHECK               (TPM_ST)(0x8024)
#define TPM_ST_NO_SESSIONS             (TPM_ST)(0x8001)
#define TPM_ST_NULL                    (TPM_ST)(0x8000)
#define TPM_ST_RSP_COMMAND             (TPM_ST)(0x00C4)
#define TPM_ST_SESSIONS                (TPM_ST)(0x8002)
#define TPM_ST_VERIFIED                (TPM_ST)(0x8022)
#define TPM_SU_CLEAR    (TPM_SU)(0x0000)
#define TPM_SU_STATE    (TPM_SU)(0x0001)
#define  TRANSIENT_FIRST         (TPM_HC)((HR_TRANSIENT+0))
#define  TRANSIENT_LAST          (TPM_HC)((TRANSIENT_FIRST+MAX_LOADED_OBJECTS-1))
#define TYPE_OF_TPMA_ACT    UINT32
#define TYPE_OF_TPMA_ALGORITHM  UINT32
#define TYPE_OF_TPMA_CC     UINT32
#define TYPE_OF_TPMA_LOCALITY   UINT8
#define TYPE_OF_TPMA_MEMORY UINT32
#define TYPE_OF_TPMA_MODES  UINT32
#define TYPE_OF_TPMA_NV     UINT32
#define TYPE_OF_TPMA_OBJECT UINT32
#define TYPE_OF_TPMA_PERMANENT              UINT32
#define TYPE_OF_TPMA_SESSION    UINT8
#define TYPE_OF_TPMA_STARTUP_CLEAR  UINT32
#define TYPE_OF_TPMA_X509_KEY_USAGE UINT32
#define TYPE_OF_TPM_AE      UINT32
#define TYPE_OF_TPM_ALGORITHM_ID    UINT32
#define TYPE_OF_TPM_ALG_ID              UINT16
#define TYPE_OF_TPM_AT      UINT32
#define TYPE_OF_TPM_AUTHORIZATION_SIZE  UINT32
#define TYPE_OF_TPM_CAP             UINT32
#define TYPE_OF_TPM_CC                      UINT32
#define TYPE_OF_TPM_CLOCK_ADJUST    UINT8
#define TYPE_OF_TPM_CONSTANTS32 UINT32
#define TYPE_OF_TPM_ECC_CURVE   UINT16
#define TYPE_OF_TPM_EO      UINT16
#define TYPE_OF_TPM_HANDLE  UINT32
#define TYPE_OF_TPM_HT          UINT8
#define TYPE_OF_TPM_KEY_BITS    UINT16
#define TYPE_OF_TPM_KEY_SIZE    UINT16
#define TYPE_OF_TPM_MODIFIER_INDICATOR  UINT32
#define TYPE_OF_TPM_NT      UINT32
#define TYPE_OF_TPM_NV_INDEX    UINT32
#define TYPE_OF_TPM_PARAMETER_SIZE  UINT32
#define TYPE_OF_TPM_PS          UINT32
#define TYPE_OF_TPM_PT              UINT32
#define TYPE_OF_TPM_PT_PCR          UINT32
#define TYPE_OF_TPM_RC              UINT32
#define TYPE_OF_TPM_SE      UINT8
#define TYPE_OF_TPM_SPEC        UINT32
#define TYPE_OF_TPM_ST                  UINT16
#define TYPE_OF_TPM_SU      UINT16
#define UINT32_TO_TPMA_ACT(a)    (*((TPMA_ACT *)&(a)))
#define UINT32_TO_TPMA_ALGORITHM(a)  (*((TPMA_ALGORITHM *)&(a)))
#define UINT32_TO_TPMA_CC(a)     (*((TPMA_CC *)&(a)))
#define UINT32_TO_TPMA_MEMORY(a)     (*((TPMA_MEMORY *)&(a)))
#define UINT32_TO_TPMA_MODES(a)  (*((TPMA_MODES *)&(a)))
#define UINT32_TO_TPMA_NV(a)     (*((TPMA_NV *)&(a)))
#define UINT32_TO_TPMA_OBJECT(a)     (*((TPMA_OBJECT *)&(a)))
#define UINT32_TO_TPMA_PERMANENT(a)  (*((TPMA_PERMANENT *)&(a)))
#define UINT32_TO_TPMA_STARTUP_CLEAR(a)  (*((TPMA_STARTUP_CLEAR *)&(a)))
#define UINT32_TO_TPMA_X509_KEY_USAGE(a)     (*((TPMA_X509_KEY_USAGE *)&(a)))
#define UINT32_TO_TPM_NV_INDEX(a)    (*((TPM_NV_INDEX *)&(a)))
#define UINT8_TO_TPMA_LOCALITY(a)    (*((TPMA_LOCALITY *)&(a)))
#define UINT8_TO_TPMA_SESSION(a)     (*((TPMA_SESSION *)&(a)))
#define    MAX_AC_CAPABILITIES  (MAX_CAP_DATA / sizeof(TPMS_AC_OUTPUT))
#define    MAX_CAP_ALGS         (MAX_CAP_DATA / sizeof(TPMS_ALG_PROPERTY))
#define    MAX_CAP_CC           (MAX_CAP_DATA / sizeof(TPM_CC))
#define    MAX_CAP_DATA         (MAX_CAP_BUFFER - sizeof(TPM_CAP)-sizeof(UINT32))
#define    MAX_CAP_HANDLES      (MAX_CAP_DATA / sizeof(TPM_HANDLE))
#define    MAX_ECC_CURVES       (MAX_CAP_DATA / sizeof(TPM_ECC_CURVE))
#define    MAX_PCR_PROPERTIES   (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PCR_SELECT))
#define    MAX_TAGGED_POLICIES  (MAX_CAP_DATA / sizeof(TPMS_TAGGED_POLICY))
#define    MAX_TPM_PROPERTIES   (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PROPERTY))
#define     _CAPABILITIES_H


#define     _TPM_H_

#define    _PLATFORM_FP_H_

#define         NULL        (0)
#define BnMod(a, b)     BnDiv(NULL, (a), (a), (b))






























#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))










#  define BITS_TO_BYTES(bits) (((bits) + 7) >> 3)
#   define CLEAR_ATTRIBUTE(a, type, b)     (a.b = CLEAR)
#define CLEAR_BIT(bit, vector) ClearBit((bit), (BYTE *)&(vector), sizeof(vector))
#define CONCAT(x,y) JOIN(x, y)
#define CONCAT3(x, y, z) JOIN3(x,y,z)
#define CONTEXT_COUNTER         UINT64
#define CONTEXT_ENCRYPT_KEY_BYTES       ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#       define CONTEXT_HASH_ALGORITHM   SHA3_512
#   define CONTEXT_INTEGRITY_HASH_ALG  CONCAT(TPM_ALG_, CONTEXT_HASH_ALGORITHM)
#define CONTEXT_INTEGRITY_HASH_SIZE CONCAT(CONTEXT_HASH_ALGORITHM, _DIGEST_SIZE)
#  define DIV_UP(var, div) ((var + div - 1) / (div))
#define     ECC_SECURITY_STRENGTH (MAX_ECC_KEY_BITS >= 521 ? 256 :	\
				  (MAX_ECC_KEY_BITS >= 384 ? 192 :	\
				  (MAX_ECC_KEY_BITS >= 256 ? 128 : 0)))
#define     ERROR_RETURN(returnCode)		\
    {						\
	retVal = returnCode;			\
	goto Exit;				\
    }
#define EXPIRATION_BIT ((UINT64)1 << 63)
#define EXTERN  extern
#   define FAIL(errorCode) (TpmFail(errorCode))
#   define FAIL_RETURN(returnCode)
#   define FUNCTION_NAME        __func__     
#   define GET_ATTRIBUTE(a, type, b)       (a.b)

#define INITIALIZER(_value_)  = _value_
#   define IS_ATTRIBUTE(a, type, b)        ((a.b) != 0)
#  define IsOdd(a)        (((a) & 1) != 0)
#define JOIN(x,y) x##y
#define JOIN3(x, y, z) x##y##z
#define LABEL_MAX_BUFFER MIN(32, MAX(MAX_ECC_KEY_BYTES, MAX_DIGEST_SIZE))
#   define LIB_EXPORT
#   define LIB_IMPORT
#   define LOG_FAILURE(errorCode) (TpmLogFailure(errorCode))
#define MAKE_OID(NAME)							\
    EXTERN  const BYTE OID##NAME[] INITIALIZER({OID##NAME##_VALUE})
#  define MAX(a, b) ((a) > (b) ? (a) : (b))
#define     MAX_HASH_SECURITY_STRENGTH  ((CONTEXT_INTEGRITY_HASH_SIZE * 8) / 2)
#define MAX_ORDERLY_COUNT       ((1 << ORDERLY_BITS) - 1)
#define     MAX_SYM_SECURITY_STRENGTH   MAX_SYM_KEY_BITS
#  define MIN(a, b) ((a) < (b) ? (a) : (b))
#   define NORETURN _Noreturn

#define NULL 0
#define PARAMETER_CHECK(condition, returnCode)		\
    REQUIRE((condition), PARAMETER, returnCode)
#define PCR_SELECT_MAX          ((IMPLEMENTATION_PCR+7)/8)
#define PCR_SELECT_MIN          ((PLATFORM_PCR+7)/8)
#   define PROOF_SIZE           COMPLIANT_PROOF_SIZE
#define REQUIRE(condition, errorCode, returnCode)		\
    {								\
	if(!!(condition))					\
	    {							\
		FAIL(FATAL_ERROR_errorCode);			\
		FAIL_RETURN(returnCode);			\
	    }							\
    }
#define RSA_MAX_PRIME           (MAX_RSA_KEY_BYTES / 2)
#define RSA_PRIVATE_SIZE        (RSA_MAX_PRIME * 5)
#define     RSA_SECURITY_STRENGTH (MAX_RSA_KEY_BITS >= 15360 ? 256 :	\
				  (MAX_RSA_KEY_BITS >=  7680 ? 192 :	\
				  (MAX_RSA_KEY_BITS >=  3072 ? 128 :	\
				  (MAX_RSA_KEY_BITS >=  2048 ? 112 :    \
				  (MAX_RSA_KEY_BITS >=  1024 ?  80 :  0)))))
#   define SET_ATTRIBUTE(a, type, b)       (a.b = SET)
#define SET_BIT(bit, vector)    SetBit((bit), (BYTE *)&(vector), sizeof(vector))
#define STD_RESPONSE_HEADER (sizeof(TPM_ST) + sizeof(UINT32) + sizeof(TPM_RC))
#   define     TEST(alg) if(TEST_BIT(alg, g_toTest)) CryptTestAlgorithm(alg, NULL)
#define TEST_BIT(bit, vector)   TestBit((bit), (BYTE *)&(vector), sizeof(vector))
#   define     TEST_HASH(alg)						\
    if(TEST_BIT(alg, g_toTest)						\
       &&  (alg != TPM_ALG_NULL))					\
	CryptTestAlgorithm(alg, NULL)
#   define TPMA_ZERO_INITIALIZER()          {0}
#   define TPM_FAIL_RETURN     NORETURN void
#define VERIFY(_X) if(!(_X)) goto Error
#   define  cAssert     pAssert
#   define pAssert(a)  ((void)0)
#define   FIRMWARE_V1         (0x20191023)
#define   FIRMWARE_V2         (0x00163636)
#define    MANUFACTURER    "IBM"

#define       VENDOR_STRING_1       "SW  "
#define       VENDOR_STRING_2       " TPM"
#define BYTE_ARRAY_TO_UINT16(b)       REVERSE_ENDIAN_16(*((uint16_t *)(b)))
#define BYTE_ARRAY_TO_UINT32(b)       REVERSE_ENDIAN_32(*((uint32_t *)(b)))
#define BYTE_ARRAY_TO_UINT64(b)       REVERSE_ENDIAN_64(*((uint64_t *)(b)))
#define BYTE_ARRAY_TO_UINT8(b)        *((uint8_t  *)(b))
#define FROM_BIG_ENDIAN_UINT16(i)   REVERSE_ENDIAN_16(i)
#define FROM_BIG_ENDIAN_UINT32(i)   REVERSE_ENDIAN_32(i)
#define FROM_BIG_ENDIAN_UINT64(i)   REVERSE_ENDIAN_64(i)

#define TO_BIG_ENDIAN_UINT16(i)     REVERSE_ENDIAN_16(i)
#define TO_BIG_ENDIAN_UINT32(i)     REVERSE_ENDIAN_32(i)
#define TO_BIG_ENDIAN_UINT64(i)     REVERSE_ENDIAN_64(i)
#define UINT16_TO_BYTE_ARRAY(i, b) {*((uint16_t *)(b)) = (i);}
#define UINT32_TO_BYTE_ARRAY(i, b) {*((uint32_t *)(b)) = (i);}
#define UINT64_TO_BYTE_ARRAY(i, b)  {*((uint64_t *)(b)) = (i);}
#define UINT8_TO_BYTE_ARRAY(i, b) {*((uint8_t *)(b)) = (i);}
#define ADD_FILL            0
#define AES_128_BLOCK_SIZE_BYTES    (AES_128 * 16)
#define AES_192_BLOCK_SIZE_BYTES    (AES_192 * 16)
#define AES_256_BLOCK_SIZE_BYTES    (AES_256 * 16)
#   define AES_MAX_BLOCK_SIZE       16
#   define AES_MAX_KEY_SIZE_BITS    256
#define CAMELLIA_128_BLOCK_SIZE_BYTES   (CAMELLIA_128 * 16)
#define CAMELLIA_192_BLOCK_SIZE_BYTES   (CAMELLIA_192 * 16)
#define CAMELLIA_256_BLOCK_SIZE_BYTES   (CAMELLIA_256 * 16)
#   define CAMELLIA_MAX_BLOCK_SIZE      16
#   define CAMELLIA_MAX_KEY_SIZE_BITS   256
#define COMMAND_COUNT       (LIBRARY_COMMAND_ARRAY_SIZE + VENDOR_COMMAND_ARRAY_SIZE)
#define LIBRARY_COMMAND_ARRAY_SIZE       (0				\
					  + (ADD_FILL || CC_NV_UndefineSpaceSpecial)               \
					  + (ADD_FILL || CC_EvictControl)                          \
					  + (ADD_FILL || CC_HierarchyControl)                      \
					  + (ADD_FILL || CC_NV_UndefineSpace)                      \
					  +  ADD_FILL                                              \
					  + (ADD_FILL || CC_ChangeEPS)                             \
					  + (ADD_FILL || CC_ChangePPS)                             \
					  + (ADD_FILL || CC_Clear)                                 \
					  + (ADD_FILL || CC_ClearControl)                          \
					  + (ADD_FILL || CC_ClockSet)                              \
					  + (ADD_FILL || CC_HierarchyChangeAuth)                   \
					  + (ADD_FILL || CC_NV_DefineSpace)                        \
					  + (ADD_FILL || CC_PCR_Allocate)                          \
					  + (ADD_FILL || CC_PCR_SetAuthPolicy)                     \
					  + (ADD_FILL || CC_PP_Commands)                           \
					  + (ADD_FILL || CC_SetPrimaryPolicy)                      \
					  + (ADD_FILL || CC_FieldUpgradeStart)                     \
					  + (ADD_FILL || CC_ClockRateAdjust)                       \
					  + (ADD_FILL || CC_CreatePrimary)                         \
					  + (ADD_FILL || CC_NV_GlobalWriteLock)                    \
					  + (ADD_FILL || CC_GetCommandAuditDigest)                 \
					  + (ADD_FILL || CC_NV_Increment)                          \
					  + (ADD_FILL || CC_NV_SetBits)                            \
					  + (ADD_FILL || CC_NV_Extend)                             \
					  + (ADD_FILL || CC_NV_Write)                              \
					  + (ADD_FILL || CC_NV_WriteLock)                          \
					  + (ADD_FILL || CC_DictionaryAttackLockReset)             \
					  + (ADD_FILL || CC_DictionaryAttackParameters)            \
					  + (ADD_FILL || CC_NV_ChangeAuth)                         \
					  + (ADD_FILL || CC_PCR_Event)                             \
					  + (ADD_FILL || CC_PCR_Reset)                             \
					  + (ADD_FILL || CC_SequenceComplete)                      \
					  + (ADD_FILL || CC_SetAlgorithmSet)                       \
					  + (ADD_FILL || CC_SetCommandCodeAuditStatus)             \
					  + (ADD_FILL || CC_FieldUpgradeData)                      \
					  + (ADD_FILL || CC_IncrementalSelfTest)                   \
					  + (ADD_FILL || CC_SelfTest)                              \
					  + (ADD_FILL || CC_Startup)                               \
					  + (ADD_FILL || CC_Shutdown)                              \
					  + (ADD_FILL || CC_StirRandom)                            \
					  + (ADD_FILL || CC_ActivateCredential)                    \
					  + (ADD_FILL || CC_Certify)                               \
					  + (ADD_FILL || CC_PolicyNV)                              \
					  + (ADD_FILL || CC_CertifyCreation)                       \
					  + (ADD_FILL || CC_Duplicate)                             \
					  + (ADD_FILL || CC_GetTime)                               \
					  + (ADD_FILL || CC_GetSessionAuditDigest)                 \
					  + (ADD_FILL || CC_NV_Read)                               \
					  + (ADD_FILL || CC_NV_ReadLock)                           \
					  + (ADD_FILL || CC_ObjectChangeAuth)                      \
					  + (ADD_FILL || CC_PolicySecret)                          \
					  + (ADD_FILL || CC_Rewrap)                                \
					  + (ADD_FILL || CC_Create)                                \
					  + (ADD_FILL || CC_ECDH_ZGen)                             \
					  + (ADD_FILL || CC_HMAC || CC_MAC)                        \
					  + (ADD_FILL || CC_Import)                                \
					  + (ADD_FILL || CC_Load)                                  \
					  + (ADD_FILL || CC_Quote)                                 \
					  + (ADD_FILL || CC_RSA_Decrypt)                           \
					  +  ADD_FILL                                              \
					  + (ADD_FILL || CC_HMAC_Start || CC_MAC_Start)            \
					  + (ADD_FILL || CC_SequenceUpdate)                        \
					  + (ADD_FILL || CC_Sign)                                  \
					  + (ADD_FILL || CC_Unseal)                                \
					  +  ADD_FILL                                              \
					  + (ADD_FILL || CC_PolicySigned)                          \
					  + (ADD_FILL || CC_ContextLoad)                           \
					  + (ADD_FILL || CC_ContextSave)                           \
					  + (ADD_FILL || CC_ECDH_KeyGen)                           \
					  + (ADD_FILL || CC_EncryptDecrypt)                        \
					  + (ADD_FILL || CC_FlushContext)                          \
					  +  ADD_FILL                                              \
					  + (ADD_FILL || CC_LoadExternal)                          \
					  + (ADD_FILL || CC_MakeCredential)                        \
					  + (ADD_FILL || CC_NV_ReadPublic)                         \
					  + (ADD_FILL || CC_PolicyAuthorize)                       \
					  + (ADD_FILL || CC_PolicyAuthValue)                       \
					  + (ADD_FILL || CC_PolicyCommandCode)                     \
					  + (ADD_FILL || CC_PolicyCounterTimer)                    \
					  + (ADD_FILL || CC_PolicyCpHash)                          \
					  + (ADD_FILL || CC_PolicyLocality)                        \
					  + (ADD_FILL || CC_PolicyNameHash)                        \
					  + (ADD_FILL || CC_PolicyOR)                              \
					  + (ADD_FILL || CC_PolicyTicket)                          \
					  + (ADD_FILL || CC_ReadPublic)                            \
					  + (ADD_FILL || CC_RSA_Encrypt)                           \
					  +  ADD_FILL                                              \
					  + (ADD_FILL || CC_StartAuthSession)                      \
					  + (ADD_FILL || CC_VerifySignature)                       \
					  + (ADD_FILL || CC_ECC_Parameters)                        \
					  + (ADD_FILL || CC_FirmwareRead)                          \
					  + (ADD_FILL || CC_GetCapability)                         \
					  + (ADD_FILL || CC_GetRandom)                             \
					  + (ADD_FILL || CC_GetTestResult)                         \
					  + (ADD_FILL || CC_Hash)                                  \
					  + (ADD_FILL || CC_PCR_Read)                              \
					  + (ADD_FILL || CC_PolicyPCR)                             \
					  + (ADD_FILL || CC_PolicyRestart)                         \
					  + (ADD_FILL || CC_ReadClock)                             \
					  + (ADD_FILL || CC_PCR_Extend)                            \
					  + (ADD_FILL || CC_PCR_SetAuthValue)                      \
					  + (ADD_FILL || CC_NV_Certify)                            \
					  + (ADD_FILL || CC_EventSequenceComplete)                 \
					  + (ADD_FILL || CC_HashSequenceStart)                     \
					  + (ADD_FILL || CC_PolicyPhysicalPresence)                \
					  + (ADD_FILL || CC_PolicyDuplicationSelect)               \
					  + (ADD_FILL || CC_PolicyGetDigest)                       \
					  + (ADD_FILL || CC_TestParms)                             \
					  + (ADD_FILL || CC_Commit)                                \
					  + (ADD_FILL || CC_PolicyPassword)                        \
					  + (ADD_FILL || CC_ZGen_2Phase)                           \
					  + (ADD_FILL || CC_EC_Ephemeral)                          \
					  + (ADD_FILL || CC_PolicyNvWritten)                       \
					  + (ADD_FILL || CC_PolicyTemplate)                        \
					  + (ADD_FILL || CC_CreateLoaded)                          \
					  + (ADD_FILL || CC_PolicyAuthorizeNV)                     \
					  + (ADD_FILL || CC_EncryptDecrypt2)                       \
					  + (ADD_FILL || CC_AC_GetCapability)                      \
					  + (ADD_FILL || CC_AC_Send)                               \
					  + (ADD_FILL || CC_Policy_AC_SendSelect)                  \
					  + (ADD_FILL || CC_CertifyX509)                           \
					  + (ADD_FILL || CC_ACT_SetTimeout)                        \
					  + (ADD_FILL || CC_ECC_Encrypt)                           \
					  + (ADD_FILL || CC_ECC_Decrypt)                           \
					  )
#define MAX_AES_BLOCK_SIZE_BYTES    AES_MAX_BLOCK_SIZE
#define MAX_AES_KEY_BITS            AES_MAX_KEY_SIZE_BITS
#define MAX_AES_KEY_BYTES           ((AES_MAX_KEY_SIZE_BITS + 7) / 8)
#define MAX_CAMELLIA_BLOCK_SIZE_BYTES   CAMELLIA_MAX_BLOCK_SIZE
#define MAX_CAMELLIA_KEY_BITS           CAMELLIA_MAX_KEY_SIZE_BITS
#define MAX_CAMELLIA_KEY_BYTES          ((CAMELLIA_MAX_KEY_SIZE_BITS + 7) / 8)
#define MAX_ECC_KEY_BYTES               BITS_TO_BYTES(MAX_ECC_KEY_BITS)
#define MAX_RSA_KEY_BITS            RSA_MAX_KEY_SIZE_BITS
#define MAX_RSA_KEY_BYTES           ((RSA_MAX_KEY_SIZE_BITS + 7) / 8)
#define MAX_SM4_BLOCK_SIZE_BYTES    SM4_MAX_BLOCK_SIZE
#define MAX_SM4_KEY_BITS            SM4_MAX_KEY_SIZE_BITS
#define MAX_SM4_KEY_BYTES           ((SM4_MAX_KEY_SIZE_BITS + 7) / 8)
#define MAX_SYM_KEY_BYTES       ((MAX_SYM_KEY_BITS + 7) / 8)
#define MAX_TDES_BLOCK_SIZE_BYTES   TDES_MAX_BLOCK_SIZE
#define MAX_TDES_KEY_BITS           TDES_MAX_KEY_SIZE_BITS
#define MAX_TDES_KEY_BYTES          ((TDES_MAX_KEY_SIZE_BITS + 7) / 8)
#define PLATFORM_DAY_OF_YEAR    TPM_SPEC_DAY_OF_YEAR
#define PLATFORM_FAMILY         TPM_SPEC_FAMILY
#define PLATFORM_LEVEL          TPM_SPEC_LEVEL
#define PLATFORM_VERSION        TPM_SPEC_VERSION
#define PLATFORM_YEAR           TPM_SPEC_YEAR
#   define RSA_MAX_KEY_SIZE_BITS    16384
#define SHA1_BLOCK_SIZE     64
#define SHA1_DIGEST_SIZE    20
#define SHA256_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32
#define SHA384_BLOCK_SIZE   128
#define SHA384_DIGEST_SIZE  48
#define SHA3_256_BLOCK_SIZE     136
#define SHA3_256_DIGEST_SIZE    32
#define SHA3_384_BLOCK_SIZE     104
#define SHA3_384_DIGEST_SIZE    48
#define SHA3_512_BLOCK_SIZE     72
#define SHA3_512_DIGEST_SIZE    64
#define SHA512_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE  64
#define SM3_256_BLOCK_SIZE      64
#define SM3_256_DIGEST_SIZE     32
#define SM4_128_BLOCK_SIZE_BYTES    (SM4_128 * 16)
#define SM4_BLOCK_SIZES             SM4_128_BLOCK_SIZE_BYTES
#define SM4_KEY_SIZES_BITS          (128 * SM4_128)
#   define SM4_MAX_BLOCK_SIZE       16
#   define SM4_MAX_KEY_SIZE_BITS    128
#define TDES_128_BLOCK_SIZE_BYTES   (TDES_128 * 8)
#define TDES_192_BLOCK_SIZE_BYTES   (TDES_192 * 8)
#define TDES_KEY_SIZES_BITS         (128 * TDES_128), (192 * TDES_192)
#   define TDES_MAX_BLOCK_SIZE      8
#   define TDES_MAX_KEY_SIZE_BITS   192
#define TPM_CC_FIRST                        0x0000011F
#define TPM_CC_LAST                         0x0000019A
#define VENDOR_COMMAND_ARRAY_SIZE   (0 + CC_Vendor_TCG_Test)


#define TPM2B_BYTE_VALUE(bytes) TPM2B_TYPE(bytes##_BYTE_VALUE, bytes)
#define TPM2B_INIT(TYPE, name)					\
    TPM2B_##TYPE    name = {sizeof(name.t.buffer), {0}}
#define TPM2B_TYPE(name, bytes)			    \
    typedef union {				    \
	struct  {					    \
	    UINT16  size;				    \
	    BYTE    buffer[(bytes)];			    \
	} t;						    \
	TPM2B   b;					    \
    } TPM2B_##name

#   define  ACCUMULATE_SELF_HEAL_TIMER      YES       
#define      ALG_NO       NO
#define      ALG_YES      YES
#define      CC_NO        NO
#define      CC_YES       YES
#   define  CERTIFYX509_DEBUG NO               
#   define  CLOCK_STOPS             NO     
#       define  COMPILER_CHECKS     NO      
#   define  COMPRESSED_LISTS        YES     
#       define  DEBUG   NO
#       define  DRBG_DEBUG_PRINT    NO      
#       define  FAIL_TRACE          YES      
#   define  FIPS_COMPLIANT      NO     
#   define  LIBRARY_COMPATIBILITY_CHECK YES     
#   define PROFILE_INCLUDE(a) PROFILE_QUOTE(a)
#   define PROFILE_QUOTE(a) #a
#       define  RSA_INSTRUMENT      NO         
#   define  RSA_KEY_SIEVE           YES         
#       define RUNTIME_SIZE_CHECKS      NO      
#   define  SELF_TEST       YES         
#   define  SIMULATION      NO     
#   define  SKIP_PROOF_ERRORS           NO       
#   define  TABLE_DRIVEN_DISPATCH   YES     
#   define  TABLE_DRIVEN_MARSHAL NO    

#   define  USE_BIT_FIELD_STRUCTURES    NO        
#   define  USE_BN_ECC_DATA     YES     
#   define  USE_DA_USED     YES         
#       define  USE_DEBUG_RNG           YES      
#           define  USE_KEY_CACHE_FILE  YES     
#   define  USE_MARSHALING_DEFINES  YES
#       define  USE_RSA_KEY_CACHE   YES   
#   define USE_RSA_KEY_CACHE_FILE   NO
#   define  USE_SPEC_COMPLIANT_PROOFS       YES       
#   define  _DRBG_STATE_SAVE        YES     

#       define REVERSE_ENDIAN_16(_Number) bswap_16(_Number)
#       define REVERSE_ENDIAN_32(_Number) bswap_32(_Number)
#       define REVERSE_ENDIAN_64(_Number) bswap_64(_Number)
#   define WINAPI
#       define _INTPTR 2
#   define _NORMAL_WARNING_LEVEL_
#   define _REDUCE_WARNING_LEVEL_(n)		\
    __pragma(warning(push, n))
#   define __pragma(x)
#define    _PLATFORM_H_
#define DEFINE_ACT(N)   EXTERN ACT_DATA ACT_##N;
#define EXTERN  extern
#   define      FILE_BACKED_NV          YES          
#   define      VTPM            NO                 

#define     CLOCK_ADJUST_COARSE     300
#define     CLOCK_ADJUST_FINE       1
#define     CLOCK_ADJUST_LIMIT      5000
#define     CLOCK_ADJUST_MEDIUM     30
#define     CLOCK_NOMINAL           30000


