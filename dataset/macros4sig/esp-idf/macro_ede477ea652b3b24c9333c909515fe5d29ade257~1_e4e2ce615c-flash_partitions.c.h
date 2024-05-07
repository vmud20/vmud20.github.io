

#include<string.h>







#define ESP_BOOTLOADER_DIGEST_OFFSET 0x0
#define ESP_BOOTLOADER_OFFSET CONFIG_BOOTLOADER_OFFSET_IN_FLASH  
#define ESP_PARTITION_MAGIC 0x50AA
#define ESP_PARTITION_MAGIC_MD5 0xEBEB
#define ESP_PARTITION_TABLE_MAX_ENTRIES (ESP_PARTITION_TABLE_MAX_LEN / sizeof(esp_partition_info_t)) 
#define ESP_PARTITION_TABLE_MAX_LEN 0xC00 
#define ESP_PARTITION_TABLE_OFFSET CONFIG_PARTITION_TABLE_OFFSET 
#define PART_FLAG_ENCRYPTED (1<<0)
#define PART_SUBTYPE_DATA_EFUSE_EM 0x05
#define PART_SUBTYPE_DATA_NVS_KEYS 0x04
#define PART_SUBTYPE_DATA_OTA 0x00
#define PART_SUBTYPE_DATA_RF  0x01
#define PART_SUBTYPE_DATA_WIFI 0x02
#define PART_SUBTYPE_END 0xff
#define PART_SUBTYPE_FACTORY  0x00
#define PART_SUBTYPE_OTA_FLAG 0x10
#define PART_SUBTYPE_OTA_MASK 0x0f
#define PART_SUBTYPE_TEST     0x20
#define PART_TYPE_APP 0x00
#define PART_TYPE_DATA 0x01
#define PART_TYPE_END 0xff
