



#include<string.h>








#include<stdbool.h>

#include<inttypes.h>





#include<time.h>
#include<stdint.h>

#include<stddef.h>





#include<stdio.h>

#define RANDOM_SALT_LEN 32
#define STORAGE_DEFAULT_SCREENSAVER_TIMEOUT (10U * 60U * 1000U) 

#define STORAGE_MIN_SCREENSAVER_TIMEOUT (30U * 1000U)           
#define STORAGE_RETRIES 3
#define STORAGE_VERSION \
  16 
#define APP_FLASH_SECT_LEN 0x20000
#define BLDR_FLASH_SECT_LEN 0x20000
#define BLDR_FLASH_SECT_START 0x08020000
#define BSTRP_FLASH_SECT_LEN 0x4000
#define BSTRP_FLASH_SECT_START 0x08000000
#define FLASH_APP_LEN (FLASH_END - FLASH_APP_START)
#define FLASH_APP_SECTOR_FIRST 7
#define FLASH_APP_SECTOR_LAST 11
#define FLASH_APP_START \
  (FLASH_META_START + FLASH_META_DESC_LEN)  
#define FLASH_BOOTSTRAP_LEN (0x4000)
#define FLASH_BOOTSTRAP_SECTOR 0
#define FLASH_BOOTSTRAP_SECTOR_FIRST 0
#define FLASH_BOOTSTRAP_SECTOR_LAST 0
#define FLASH_BOOTSTRAP_START (FLASH_ORIGIN)  
#define FLASH_BOOT_LEN (0x40000)
#define FLASH_BOOT_SECTOR_FIRST 5
#define FLASH_BOOT_SECTOR_LAST 6
#define FLASH_BOOT_START (0x08020000)  
#define FLASH_END (FLASH_ORIGIN + FLASH_TOTAL_SIZE)
#define FLASH_META_CODELEN \
  (FLASH_META_MAGIC + sizeof(((app_meta_td *)NULL)->magic))
#define FLASH_META_DESC_LEN (0x100)
#define FLASH_META_FLAGS \
  (FLASH_SIG_FLAG + sizeof(((app_meta_td *)NULL)->sig_flag))
#define FLASH_META_MAGIC (FLASH_META_START)
#define FLASH_META_RESERVE \
  (FLASH_META_FLAGS + sizeof(((app_meta_td *)NULL)->meta_flags))
#define FLASH_META_SIG1 \
  (FLASH_META_RESERVE + sizeof(((app_meta_td *)NULL)->rsv))
#define FLASH_META_SIG2 (FLASH_META_SIG1 + sizeof(((app_meta_td *)NULL)->sig1))
#define FLASH_META_SIG3 (FLASH_META_SIG2 + sizeof(((app_meta_td *)NULL)->sig2))
#define FLASH_META_SIGINDEX1 \
  (FLASH_META_CODELEN + sizeof(((app_meta_td *)NULL)->code_len))
#define FLASH_META_SIGINDEX2 \
  (FLASH_META_SIGINDEX1 + sizeof(((app_meta_td *)NULL)->sig_index1))
#define FLASH_META_SIGINDEX3 \
  (FLASH_META_SIGINDEX2 + sizeof(((app_meta_td *)NULL)->sig_index2))
#define FLASH_META_START (FLASH_BOOT_START + FLASH_BOOT_LEN)  
#define FLASH_ORIGIN (0x08000000)
#define FLASH_PTR(x) (emulator_flash_base + (x - FLASH_ORIGIN))
#define FLASH_SIG_FLAG \
  (FLASH_META_SIGINDEX3 + sizeof(((app_meta_td *)NULL)->sig_index3))
#define FLASH_STORAGE_LEN (0x4000)
#define FLASH_STORAGE_SECTOR_FIRST 1
#define FLASH_STORAGE_SECTOR_LAST 3
#define FLASH_TOTAL_SIZE (1024 * 1024)
#define FLASH_VARIANT_SECTOR_FIRST 4
#define FLASH_VARIANT_SECTOR_LAST 4

#define META_FLAGS (*(uint8_t const *)FLASH_META_FLAGS)
#define META_MAGIC_SIZE (sizeof(((app_meta_td *)NULL)->magic))
#define META_MAGIC_STR "KPKY"
#define OPTION_BYTES_1 ((uint64_t *)0x1FFFC000)
#define OPTION_BYTES_2 ((uint64_t *)0x1FFFC008)
#define OPTION_RDP 0xCCFF
#define OPTION_WRP 0xFF9E
#define OTP_BLK_LOCK(x) (0x1FFF7A00 + (x - 0x1FFF7800) / 0x20)
#define OTP_MFG_ADDR 0x1FFF7800
#define OTP_MFG_SIG 0x08012015
#define OTP_MFG_SIG_LEN 4
#define OTP_MODEL_ADDR 0x1FFF7820
#define SIG_FLAG (*(uint8_t const *)FLASH_SIG_FLAG)
#define STORAGE_PROTECT_DISABLED 0x5ac35ac3
#define STORAGE_PROTECT_ENABLED 0x00000000
#define STORAGE_PROTECT_OFF_MAGIC                                            \
  "\x31\x88\x4e\xb8\x48\x2a\x28\x09\xe3\x74\x61\xd9\x6a\xd7\xf0\xed\x8c\xdd" \
  "\x7c\xa6\x07\x3e\x68\x6a\x15\xc0\x89\xc6\x11\x89\x95\xa0"
#define STORAGE_PROTECT_ON_MAGIC                                             \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define STORAGE_SECT_DEFAULT FLASH_STORAGE1
#define STOR_FLASH_SECT_LEN 0x4000
#define UNUSED_FLASH_SECT0_LEN 0x10000
#define BTC_ADDRESS_SIZE 35
#define ENTROPY_BUF sizeof(((Entropy *)NULL)->entropy.bytes)

#define RAW_TX_ACK_VARINT_COUNT 4
#define RESP_INIT(TYPE)                                                    \
  TYPE *resp = (TYPE *)msg_resp;                                           \
  _Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
  memset(resp, 0, sizeof(TYPE));
#define STR(X) #X
#define VERSTR(X) STR(X)
#define fsm_sendFailure(code, text) \
  fsm_sendFailureDebug((code), (text), "__FILE__" ":" VERSTR("__LINE__") ":")
#define DEBUG_IN(ID, STRUCT_NAME, PROCESS_FUNC)                     \
  [ID].msg_id = (ID), [ID].type = (DEBUG_MSG), [ID].dir = (IN_MSG), \
  [ID].fields = (STRUCT_NAME##_fields), [ID].dispatch = (PARSABLE), \
  [ID].process_func = (void (*)(void *))(PROCESS_FUNC),
#define DEBUG_OUT(ID, STRUCT_NAME, PROCESS_FUNC)                     \
  [ID].msg_id = (ID), [ID].type = (DEBUG_MSG), [ID].dir = (OUT_MSG), \
  [ID].fields = (STRUCT_NAME##_fields), [ID].dispatch = (PARSABLE),  \
  [ID].process_func = (void (*)(void *))(PROCESS_FUNC),

#define MSG_IN(ID, STRUCT_NAME, PROCESS_FUNC)                        \
  [ID].msg_id = (ID), [ID].type = (NORMAL_MSG), [ID].dir = (IN_MSG), \
  [ID].fields = (STRUCT_NAME##_fields), [ID].dispatch = (PARSABLE),  \
  [ID].process_func = (void (*)(void *))(PROCESS_FUNC),
#define MSG_OUT(ID, STRUCT_NAME, PROCESS_FUNC)                        \
  [ID].msg_id = (ID), [ID].type = (NORMAL_MSG), [ID].dir = (OUT_MSG), \
  [ID].fields = (STRUCT_NAME##_fields), [ID].dispatch = (PARSABLE),   \
  [ID].process_func = (void (*)(void *))(PROCESS_FUNC),
#define MSG_TINY_BFR_SZ 64
#define MSG_TINY_TYPE_ERROR 0xFFFF
#define NO_PROCESS_FUNC 0
#define RAW_IN(ID, STRUCT_NAME, PROCESS_FUNC)                        \
  [ID].msg_id = (ID), [ID].type = (NORMAL_MSG), [ID].dir = (IN_MSG), \
  [ID].fields = (STRUCT_NAME##_fields), [ID].dispatch = (RAW),       \
  [ID].process_func = (void (*)(void *))(void *)(PROCESS_FUNC),
#define ENDPOINT_ADDRESS_DEBUG_IN (0x82)
#define ENDPOINT_ADDRESS_DEBUG_OUT (0x02)
#define ENDPOINT_ADDRESS_IN (0x81)
#define ENDPOINT_ADDRESS_OUT (0x01)
#define ENDPOINT_ADDRESS_U2F_IN (0x83)
#define ENDPOINT_ADDRESS_U2F_OUT (0x03)
#define MAX_MESSAGE_SIZE (USB_SEGMENT_SIZE * MAX_NUM_USB_SEGMENTS)
#define MAX_NUM_USB_SEGMENTS 1
#define NUM_USB_STRINGS (sizeof(usb_strings) / sizeof(usb_strings[0]))
#define USBD_CONTROL_BUFFER_SIZE 128
#define USB_GPIO_PORT GPIOA
#define USB_GPIO_PORT_PINS (GPIO11 | GPIO12)

#define USB_SEGMENT_SIZE 64
#define CAPFLAG_LOCK 0x02  
#define CAPFLAG_WINK 0x01  
#define CID_BROADCAST 0xffffffff  
#define ERR_CHANNEL_BUSY 0x06   
#define ERR_INVALID_CID 0x0b    
#define ERR_INVALID_CMD 0x01    
#define ERR_INVALID_LEN 0x03    
#define ERR_INVALID_PAR 0x02    
#define ERR_INVALID_SEQ 0x04    
#define ERR_LOCK_REQUIRED 0x0a  
#define ERR_MSG_TIMEOUT 0x05    
#define ERR_NONE 0x00           
#define ERR_OTHER 0x7f          
#define FIDO_USAGE_DATA_IN 0x20   
#define FIDO_USAGE_DATA_OUT 0x21  
#define FIDO_USAGE_PAGE 0xf1d0    
#define FIDO_USAGE_U2FHID 0x01    
#define FRAME_CMD(f) ((f).init.cmd & ~TYPE_MASK)
#define FRAME_SEQ(f) ((f).cont.seq & ~TYPE_MASK)
#define FRAME_TYPE(f) ((f).type & TYPE_MASK)
#define HID_RPT_SIZE 64  
#define INIT_NONCE_SIZE 8  
#define MSG_LEN(f) ((f).init.bcnth * 256 + (f).init.bcntl)
#define TYPE_CONT 0x00  
#define TYPE_INIT 0x80  
#define TYPE_MASK 0x80  
#define U2FHID_ERROR (TYPE_INIT | 0x3f)  
#define U2FHID_IF_VERSION 2        
#define U2FHID_INIT (TYPE_INIT | 0x06)   
#define U2FHID_LOCK (TYPE_INIT | 0x04)   
#define U2FHID_MSG (TYPE_INIT | 0x03)  
#define U2FHID_PING \
  (TYPE_INIT | 0x01)                   
#define U2FHID_SYNC (TYPE_INIT | 0x3c)   
#define U2FHID_TRANS_TIMEOUT 3000  
#define U2FHID_VENDOR_FIRST (TYPE_INIT | 0x40)  
#define U2FHID_VENDOR_LAST (TYPE_INIT | 0x7f)   
#define U2FHID_WINK (TYPE_INIT | 0x08)   


#define MAX_DECODE_SIZE (13 * 1024)
#define delete del
#define TOKENS_COUNT ((int)TokenIndexLast - (int)TokenIndexFirst)
#define X(CHAIN_ID, CONTRACT_ADDR, TICKER, DECIMALS) \
  CONCAT(TokenIndex, __COUNTER__),

#define CONCAT(A, B) CONCAT_IMPL(A, B)
#define CONCAT_IMPL(A, B) A##B

#define MAX(a, b)       \
  ({                    \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a > _b ? _a : _b;  \
  })
#define MIN(a, b)       \
  ({                    \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a < _b ? _a : _b;  \
  })

#define COINS_COUNT ((int)CoinIndexLast - (int)CoinIndexFirst)

#define COIN_FRACTION 100000000
#define ETHEREUM "Ethereum"
#define ETHEREUM_CLS "ETH Classic"
#define ETHEREUM_TST "ETH Testnet"
#define NA 0xFFFF 
#define NODE_STRING_LENGTH 50

#define CONFIRM_SIGN_IDENTITY_BODY 416
#define CONFIRM_SIGN_IDENTITY_TITLE 32

#define CONFIRM_TIMEOUT_MS 1200
#define ANIMATION_PERIOD 20
#define BODY_CHAR_MAX 352
#define BODY_COLOR 0xFF
#define BODY_FONT_LINE_PADDING 4
#define BODY_ROWS 3
#define BODY_TOP_MARGIN 7
#define BODY_WIDTH 225

#define LEFT_MARGIN 4
#define MAX_ANIMATIONS 5
#define NO_WIDTH 0;
#define ONE_LINE 1
#define TITLE_CHAR_MAX 128
#define TITLE_COLOR 0xFF
#define TITLE_FONT_LINE_PADDING 0
#define TITLE_ROWS 1
#define TITLE_WIDTH 206
#define TOP_MARGIN 7
#define TOP_MARGIN_FOR_ONE_LINE 20
#define TOP_MARGIN_FOR_THREE_LINES 0
#define TOP_MARGIN_FOR_TWO_LINES 13
#define TWO_LINES 2
#define WARNING_COLOR 0xFF
#define WARNING_FONT_LINE_PADDING 0
#define WARNING_ROWS 1


#define MODEL_ENTRY(STRING, ENUM) MODEL_##ENUM,
#define VARIANTINFO_MAGIC "KKWL"



#define UNISWAP_ROUTER_ADDRESS "\x7a\x25\x0d\x56\x30\xB4\xcF\x53\x97\x39\xdF\x2C\x5d\xAc\xb4\xc6\x59\xF2\x48\x8D"
