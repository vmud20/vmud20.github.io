#include<inttypes.h>
#include<stdint.h>
#include<string.h>
#include<stdbool.h>
#include<memory.h>
#include<stddef.h>



#define MODEL_STR_SIZE 32
#define flash_unlock(void) \
  ;                        \
  flash_lock(void);        \
  flash_unlock(void);
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
#define SVC_BUSR_RET 1
#define SVC_DIS_INTR 4
#define SVC_ENA_INTR 3
#define SVC_FIRMWARE_PRIV 8
#define SVC_FIRMWARE_UNPRIV \
  9  
#define SVC_FLASH_ERASE 5
#define SVC_FLASH_PGM_BLK 6
#define SVC_FLASH_PGM_WORD 7
#define SVC_TUSR_RET 2

