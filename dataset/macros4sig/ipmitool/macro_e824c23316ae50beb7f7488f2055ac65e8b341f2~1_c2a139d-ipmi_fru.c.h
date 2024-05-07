#include<time.h>
#include<string.h>
#include<netinet/in.h>


#include<stdbool.h>

#include<arpa/inet.h>
#include<stdlib.h>
#include<sys/types.h>

#include<sys/socket.h>
#include<errno.h>

#include<stdio.h>

#include<math.h>
#include<syslog.h>
#include<inttypes.h>
#define IPMI_ASCTIME_SZ 80

#define IPMI_TIME_INIT_DONE 0x20000000u
#define IPMI_TIME_UNSPECIFIED 0xFFFFFFFFu
#define SECONDS_A_DAY (24 * 60 * 60)
#define CC_STRING(cc) val2str(cc, completion_code_vals)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define FALSE   0

# define IPMI_UID_MAX 63
# define IPMI_UID_MIN 1
#define IS_SET(v, b) ((v) & (1 << (b)))
#define TRUE    1
    #define __UNUSED__(x) x __attribute__((unused))
# define __max(a, b)  ((a) > (b) ? (a) : (b))
# define __maxlen(a, b) ({ int x=strlen(a); int y=strlen(b); (x > y) ? x : y;})
# define __min(a, b)  ((a) < (b) ? (a) : (b))
# define __minlen(a, b) ({ int x=strlen(a); int y=strlen(b); (x < y) ? x : y;})
#define ipmi_open_file_read(file)	ipmi_open_file(file, 0)
#define ipmi_open_file_write(file)	ipmi_open_file(file, 1)
#define tboolean   int
#define BRIDGE_TO_SENSOR(_intf, _addr, _chan)			\
 ( !((_chan == 0 && _intf->target_ipmb_addr &&			\
			     _intf->target_ipmb_addr == _addr)  ||	\
    (_addr == _intf->target_addr && _chan == _intf->target_channel)) )
#define GET_DEVICE_SDR           0x21
#define GET_DEVICE_SDR_INFO      0x20
#define GET_SENSOR_EVENT_ENABLE 0x29
#define GET_SENSOR_FACTORS      0x23
#define GET_SENSOR_THRESHOLDS   0x27

#define IS_EVENT_MSG_DISABLED(val)	(!((val) & EVENT_MSG_DISABLED))
#define IS_READING_UNAVAILABLE(val)	((val) & READING_UNAVAILABLE)
#define IS_SCANNING_DISABLED(val)	(!((val) & SCANNING_DISABLED))
#define IS_THRESHOLD_SENSOR(s)	((s)->event_type == 1)
#define SDR_SENSOR_L_1_X        0x07
#define SDR_SENSOR_L_CUBE       0x09
#define SDR_SENSOR_L_CUBERT     0x0b
#define SDR_SENSOR_L_E          0x04
#define SDR_SENSOR_L_EXP10      0x05
#define SDR_SENSOR_L_EXP2       0x06
#define SDR_SENSOR_L_LINEAR     0x00
#define SDR_SENSOR_L_LN         0x01
#define SDR_SENSOR_L_LOG10      0x02
#define SDR_SENSOR_L_LOG2       0x03
#define SDR_SENSOR_L_NONLINEAR  0x70
#define SDR_SENSOR_L_SQR        0x08
#define SDR_SENSOR_L_SQRT       0x0a
#define SDR_UNIT_FMT_1S_COMPL 1 
#define SDR_UNIT_FMT_2S_COMPL 2 
#define SDR_UNIT_FMT_NA 3 
#define SDR_UNIT_FMT_UNSIGNED 0 
#define SDR_UNIT_MOD_DIV 1 
#define SDR_UNIT_MOD_MUL 2 
#define SDR_UNIT_MOD_NONE 0 
#define SDR_UNIT_MOD_RSVD 3 
#define SDR_UNIT_PCT_NO 0
#define SDR_UNIT_PCT_YES 1
#define SDR_UNIT_RATE_DAY 6 
#define SDR_UNIT_RATE_HR 5 
#define SDR_UNIT_RATE_MICROSEC 1 
#define SDR_UNIT_RATE_MILLISEC 2 
#define SDR_UNIT_RATE_MIN 4 
#define SDR_UNIT_RATE_NONE 0 
#define SDR_UNIT_RATE_RSVD 7 
#define SDR_UNIT_RATE_SEC 3 
#define SENSOR_TYPE_MAX 0x2C
#define SET_SENSOR_THRESHOLDS   0x26
#define UNITS_ARE_DISCRETE(s)	((s)->unit.analog == 3)
# define __TO_ACC(bacc)     (uint32_t)(((bacc & 0x3f0000) >> 16) | ((bacc & 0xf000) >> 6))
# define __TO_ACC_EXP(bacc) (uint32_t)((bacc & 0xc00) >> 10)
# define __TO_B(bacc)       (int32_t)(tos32((((bacc & 0xff000000) >> 24) | ((bacc & 0xc00000) >> 14)), 10))
# define __TO_B_EXP(bacc)   (int32_t)(tos32((bacc & 0xf), 4))
# define __TO_M(mtol)       (int16_t)(tos32((((mtol & 0xff00) >> 8) | ((mtol & 0xc0) << 2)), 10))
# define __TO_R_EXP(bacc)   (int32_t)(tos32(((bacc & 0xf0) >> 4), 4))
# define __TO_TOL(mtol)     (uint16_t)(mtol & 0x3f)
#define tos32(val, bits)    ((val & ((1<<((bits)-1)))) ? (-((val) & (1<<((bits)-1))) | (val)) : (val))

#define ATTRIBUTE_PACKING __attribute__ ((packed))
#define IPMI_BUF_SIZE 1024

#define IPMI_MAX_MD_SIZE 0x20
#define IPMI_PAYLOAD_TYPE_IPMI               0x00
#define IPMI_PAYLOAD_TYPE_OEM                0x02
#define IPMI_PAYLOAD_TYPE_RAKP_1             0x12
#define IPMI_PAYLOAD_TYPE_RAKP_2             0x13
#define IPMI_PAYLOAD_TYPE_RAKP_3             0x14
#define IPMI_PAYLOAD_TYPE_RAKP_4             0x15
#define IPMI_PAYLOAD_TYPE_RMCP_OPEN_REQUEST  0x10
#define IPMI_PAYLOAD_TYPE_RMCP_OPEN_RESPONSE 0x11
#define IPMI_PAYLOAD_TYPE_SOL                0x01
#define IPMI_CC_CANT_RESP_BMC_INIT                 0xd2 
#define IPMI_CC_CANT_RESP_DUPLI_REQ                0xcf 
#define IPMI_CC_CANT_RESP_FIRM_UPDATE              0xd1 
#define IPMI_CC_CANT_RESP_SDRR_UPDATE              0xd0 
#define IPMI_CC_CANT_RET_NUM_REQ_BYTES             0xca 
#define IPMI_CC_DESTINATION_UNAVAILABLE            0xd3 

#define IPMI_CC_ILLEGAL_COMMAND_DISABLED           0xd6 
#define IPMI_CC_ILL_SENSOR_OR_RECORD               0xcd 
#define IPMI_CC_INSUFFICIENT_PRIVILEGES            0xd4 
#define IPMI_CC_INV_CMD                            0xc1 
#define IPMI_CC_INV_CMD_FOR_LUN                    0xc2 
#define IPMI_CC_INV_DATA_FIELD_IN_REQ              0xcc 
#define IPMI_CC_NODE_BUSY                          0xc0 
#define IPMI_CC_NOT_SUPPORTED_PRESENT_STATE        0xd5 
#define IPMI_CC_OK                                 0x00 
#define IPMI_CC_OUT_OF_SPACE                       0xc4 
#define IPMI_CC_PARAM_OUT_OF_RANGE                 0xc9 
#define IPMI_CC_REQ_DATA_FIELD_EXCEED              0xc8 
#define IPMI_CC_REQ_DATA_INV_LENGTH                0xc7 
#define IPMI_CC_REQ_DATA_NOT_PRESENT               0xcb 
#define IPMI_CC_REQ_DATA_TRUNC                     0xc6 
#define IPMI_CC_RESP_COULD_NOT_BE_PRV              0xce 
#define IPMI_CC_RES_CANCELED                       0xc5 
#define IPMI_CC_TIMEOUT                            0xc3 
#define IPMI_CC_UNSPECIFIED_ERROR                  0xff 
# define BSWAP_16(x) bswap_16(x)
# define BSWAP_32(x) bswap_32(x)

#define GUID_NODE_SZ 6
#define GUID_TIME_HI(t_hi) ((t_hi) & ~(GUID_VER_MASK << GUID_VER_SHIFT))
#define GUID_VERSION(t_hi) (((t_hi) >> GUID_VER_SHIFT) & GUID_VER_MASK)
#define GUID_VER_MASK 0x0F
#define GUID_VER_SHIFT 12
#define IPMI_GET_SYS_INFO                  0x59

#define IPMI_SET_SYS_INFO                  0x58
#define IPMI_SYSINFO_DELL_IPV6_COUNT    0xe6
#define IPMI_SYSINFO_DELL_IPV6_DESTADDR 0xf0
#define IPMI_SYSINFO_SET0_SIZE             14
#define IPMI_SYSINFO_SETN_SIZE             16
#define IPMI_WDT_ACTION_MASK    0x07
#define IPMI_WDT_ACTION_SHIFT   0
#define IPMI_WDT_GET(b, s) (((b) >> (IPMI_WDT_##s##_SHIFT)) & (IPMI_WDT_##s##_MASK))
#define IPMI_WDT_INTR_MASK      0x07 
#define IPMI_WDT_INTR_SHIFT     4
#define IPMI_WDT_USE_DONTSTOP_SHIFT 6 
#define IPMI_WDT_USE_MASK           0x07
#define IPMI_WDT_USE_NOLOG_SHIFT    7
#define IPMI_WDT_USE_RUNNING_SHIFT  6 
#define IPMI_WDT_USE_SHIFT          0
#define IPM_DEV_ADTL_SUPPORT_BITS      (8)
#define IPM_DEV_DEVICE_ID_REV_MASK     (0x0F)	
#define IPM_DEV_DEVICE_ID_SDR_MASK     (0x80)	
#define IPM_DEV_FWREV1_AVAIL_MASK      (0x80)	
#define IPM_DEV_FWREV1_MAJOR_MASK      (0x3f)	
#define IPM_DEV_IPMI_VERSION_MAJOR(x) \
	(x & IPM_DEV_IPMI_VER_MAJOR_MASK)
#define IPM_DEV_IPMI_VERSION_MINOR(x) \
	((x & IPM_DEV_IPMI_VER_MINOR_MASK) >> IPM_DEV_IPMI_VER_MINOR_SHIFT)
#define IPM_DEV_IPMI_VER_MAJOR_MASK    (0x0F)	
#define IPM_DEV_IPMI_VER_MINOR_MASK    (0xF0)	
#define IPM_DEV_IPMI_VER_MINOR_SHIFT   (4)	
#define IPM_DEV_MANUFACTURER_ID(x) ipmi24toh(x)
#define IPM_DEV_MANUFACTURER_ID_RESERVED 0x0FFFFF
#define IS_WDT_BIT(b, s) IS_SET((b), IPMI_WDT_##s##_SHIFT)
#define OEM_MFG_STRING(oem) val2str(IPM_DEV_MANUFACTURER_ID(oem),\
                                    ipmi_oem_info)
#define OEM_PROD_STRING(oem, p) oemval2str(IPM_DEV_MANUFACTURER_ID(oem),\
                                           ipmi16toh(p),\
                                           ipmi_oem_product_info)
#define FRU_BOARD_DATE_UNSPEC 0 
#define FRU_END_OF_FIELDS 0xc1
#define FRU_PICMGEXT_AMC_CHANNEL_DESC_RECORD_SIZE 3
#define FRU_PICMGEXT_AMC_LINK_DESC_RECORD_SIZE 5
#define FRU_PICMGEXT_AMC_LINK_TYPE_ADVANCED_SWITCHING1  0x03
#define FRU_PICMGEXT_AMC_LINK_TYPE_ADVANCED_SWITCHING2  0x04
#define FRU_PICMGEXT_AMC_LINK_TYPE_ETHERNET             0x05
#define FRU_PICMGEXT_AMC_LINK_TYPE_PCI_EXPRESS          0x02
#define FRU_PICMGEXT_AMC_LINK_TYPE_RAPIDIO              0x06
#define FRU_PICMGEXT_AMC_LINK_TYPE_RESERVED1            0x01
#define FRU_PICMGEXT_AMC_LINK_TYPE_STORAGE              0x07
#define FRU_PICMGEXT_CHN_DESC_RECORD_SIZE 3
#define FRU_PICMGEXT_OEM_SWFW 0x03
#define FRU_RECORD_TYPE_BASE_COMPATIBILITY 0x04
#define FRU_RECORD_TYPE_DC_LOAD 0x02
#define FRU_RECORD_TYPE_DC_OUTPUT 0x01
#define FRU_RECORD_TYPE_EXTENDED_COMPATIBILITY 0x05
#define FRU_RECORD_TYPE_MANAGEMENT_ACCESS 0x03
#define FRU_RECORD_TYPE_POWER_SUPPLY_INFORMATION 0x00
#define IPMI_CC_FRU_DEVICE_BUSY 0x81
#define IPMI_CC_FRU_WRITE_PROTECTED_OFFSET 0x80

#define OEM_SWFW_FIELD_START_OFFSET 0x06
#define OEM_SWFW_NBLOCK_OFFSET 0x05
#define IPMI_AUTHCODE_BUFFER_SIZE 20

#define IPMI_KG_BUFFER_SIZE       21 
#define IPMI_SIK_BUFFER_SIZE      IPMI_MAX_MD_SIZE
#define IPMI_1_5_AUTH_TYPE_BIT_MD2      0x02
#define IPMI_1_5_AUTH_TYPE_BIT_MD5      0x04
#define IPMI_1_5_AUTH_TYPE_BIT_NONE     0x01
#define IPMI_1_5_AUTH_TYPE_BIT_OEM      0x20
#define IPMI_1_5_AUTH_TYPE_BIT_PASSWORD 0x10
#define IPMI_ACTIVATE_PAYLOAD                   0x48
#define IPMI_AUTH_RAKP_HMAC_MD5     0x02
#define IPMI_AUTH_RAKP_HMAC_SHA1    0x01
#define IPMI_AUTH_RAKP_HMAC_SHA256  0x03
#define IPMI_AUTH_RAKP_NONE         0x00

#define IPMI_CRYPT_AES_CBC_128      0x01
#define IPMI_CRYPT_NONE             0x00
#define IPMI_CRYPT_XRC4_128         0x02
#define IPMI_CRYPT_XRC4_40          0x03
#define IPMI_DEACTIVATE_PAYLOAD                 0x49
#define IPMI_GET_SDR_REPOSITORY_INFO            0x20
#define IPMI_GET_SEL_TIME                       0x48
#define IPMI_GET_SOL_CONFIG_PARAMETERS          0x22
#define IPMI_GET_USER_ACCESS                    0x44
#define IPMI_GET_USER_NAME                      0x46
#define IPMI_INTEGRITY_HMAC_MD5_128 0x02
#define IPMI_INTEGRITY_HMAC_SHA1_96 0x01
#define IPMI_INTEGRITY_HMAC_SHA256_128 0x04
#define IPMI_INTEGRITY_MD5_128      0x03
#define IPMI_INTEGRITY_NONE         0x00
#define IPMI_SESSION_AUTHTYPE_MD2       0x1
#define IPMI_SESSION_AUTHTYPE_MD5   	0x2
#define IPMI_SESSION_AUTHTYPE_NONE      0x0
#define IPMI_SESSION_AUTHTYPE_OEM       0x5
#define IPMI_SESSION_AUTHTYPE_RMCP_PLUS 0x6
#define IPMI_SESSION_PRIV_UNSPECIFIED   0x0
#define IPMI_SET_IN_PROGRESS_COMMIT_WRITE 0x02
#define IPMI_SET_IN_PROGRESS_IN_PROGRESS  0x01
#define IPMI_SET_IN_PROGRESS_SET_COMPLETE 0x00
#define IPMI_SET_SEL_TIME                       0x49
#define IPMI_SET_SOL_CONFIG_PARAMETERS          0x21
#define IPMI_SET_USER_ACCESS                    0x43
#define IPMI_SET_USER_NAME                      0x45
#define IPMI_SET_USER_PASSWORD                  0x47
#define IPMI_SOL_ACTIVATING                     0x20
#define IPMI_SUSPEND_RESUME_PAYLOAD_ENCRYPTYION 0x55


#define LOG_WARN		LOG_WARNING
