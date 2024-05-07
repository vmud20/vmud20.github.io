










#include<assert.h>




#include<stdbool.h>
#include<stdint.h>




#define AID_CAPABILITY_CONTAINER      "\xE1\x03"
#define AID_FIDO                      "\xa0\x00\x00\x06\x47\x2f\x00\x01"
#define AID_NDEF_MIFARE_TYPE_4        "\xD2\x76\x00\x00\x85\x01\x00"
#define AID_NDEF_TAG                  "\xE1\x04"
#define AID_NDEF_TYPE_4               "\xD2\x76\x00\x00\x85\x01\x01"
#define IS_IBLOCK(x)                  ( (((x) & 0xc0) == NFC_CMD_IBLOCK) && (((x) & 0x02) == 0x02) )
#define IS_PPSS_CMD(x)                (((x) & 0xf0) == NFC_CMD_PPSS)
#define IS_RBLOCK(x)                  ( (((x) & 0xe0) == NFC_CMD_RBLOCK) && (((x) & 0x02) == 0x02) )
#define IS_SBLOCK(x)                  ( (((x) & 0xc0) == NFC_CMD_SBLOCK) && (((x) & 0x02) == 0x02) )
#define NFC_CMD_HLTA                  0x50
#define NFC_CMD_IBLOCK                0x00
#define NFC_CMD_PPSS                  0xd0
#define NFC_CMD_RATS                  0xe0
#define NFC_CMD_RBLOCK                0xa0
#define NFC_CMD_RBLOCK_ACK            0x10
#define NFC_CMD_REQA                  0x26
#define NFC_CMD_SBLOCK                0xc0
#define NFC_CMD_WUPA                  0x52
#define NFC_SBLOCK_DESELECT           0x30
#define NFC_SBLOCK_WTX                0x30
#define WTX_TIME_DEFAULT              300

#define ATTESTATION_CONFIGURED_TAG      0xaa551e79
#define ATTESTATION_PAGE        (PAGES - 15)
#define ATTESTATION_PAGE_ADDR   (0x08000000 + ATTESTATION_PAGE*PAGE_SIZE)
#define AUTH_WORD_ADDR          (APPLICATION_END_ADDR)
#define BOOT_VERSION_ADDR    (0x08000000 + BOOT_VERSION_PAGE*FLASH_PAGE_SIZE + 8)
#define BOOT_VERSION_PAGE    (APPLICATION_END_PAGE)
#define LAST_ADDR       (APPLICATION_END_ADDR-2048 + 8)
#define LAST_PAGE       (APPLICATION_END_PAGE-1)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)     
#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)

#define FIFO_CREATE(NAME,LENGTH,BYTES)\
int __##NAME##_WRITE_PTR = 0;\
int __##NAME##_READ_PTR = 0;\
int __##NAME##_SIZE = 0;\
static uint8_t __##NAME##_WRITE_BUF[BYTES * LENGTH];\
\
int fifo_##NAME##_add(uint8_t * c)\
{\
    if (__##NAME##_SIZE < LENGTH)\
    {\
        memmove(__##NAME##_WRITE_BUF + __##NAME##_WRITE_PTR * BYTES, c, BYTES);\
        __##NAME##_WRITE_PTR ++;\
        if (__##NAME##_WRITE_PTR >= LENGTH)\
            __##NAME##_WRITE_PTR = 0;\
        __##NAME##_SIZE++;\
        return 0;\
    }\
    return -1;\
}\
\
int fifo_##NAME##_take(uint8_t * c)\
{\
    memmove(c, __##NAME##_WRITE_BUF + __##NAME##_READ_PTR * BYTES, BYTES);\
    if ( __##NAME##_SIZE > 0)\
    {\
        __##NAME##_READ_PTR ++;\
        if (__##NAME##_READ_PTR >= LENGTH)\
            __##NAME##_READ_PTR = 0;\
        __##NAME##_SIZE --;\
        return 0;\
    }\
    return -1;\
}\
\
uint32_t fifo_##NAME##_size()\
{\
    return (__##NAME##_SIZE);\
}\
uint32_t fifo_##NAME##_rhead()\
{\
    return (__##NAME##_READ_PTR);\
}\
uint32_t fifo_##NAME##_whead()\
{\
    return (__##NAME##_WRITE_PTR);\
}\

#define FIFO_CREATE_H(NAME)\
int fifo_##NAME##_add(uint8_t * c);\
int fifo_##NAME##_take(uint8_t * c);\
uint32_t fifo_##NAME##_size();\
uint32_t fifo_##NAME##_rhead();\
uint32_t fifo_##NAME##_whead();\

#define TEST_FIFO 0

#define LED_PIN_B     LL_GPIO_PIN_1
#define LED_PIN_G     LL_GPIO_PIN_0
#define LED_PIN_R     LL_GPIO_PIN_2
#define LED_PORT      GPIOA


#define FLASH_PAGE_END      127
#define FLASH_PAGE_SIZE     2048
#define FLASH_PAGE_START    0

#define flash_addr(page)    (0x08000000 + ((page)*FLASH_PAGE_SIZE))
