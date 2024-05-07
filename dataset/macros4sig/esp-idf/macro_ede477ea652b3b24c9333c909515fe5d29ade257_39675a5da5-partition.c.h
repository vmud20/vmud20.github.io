
#include<string.h>
#include<stdint.h>

#include<stdlib.h>





#include<stdbool.h>

#include<stdio.h>

#include<assert.h>

#include<sys/queue.h>
#include<stddef.h>




#define ESP_PARTITION_SUBTYPE_OTA(i) ((esp_partition_subtype_t)(ESP_PARTITION_SUBTYPE_APP_OTA_MIN + ((i) & 0xf)))

#define ESP_ERR_FLASH_OP_FAIL    (ESP_ERR_FLASH_BASE + 1)
#define ESP_ERR_FLASH_OP_TIMEOUT (ESP_ERR_FLASH_BASE + 2)

#define SPI_FLASH_CACHE2PHYS_FAIL UINT32_MAX 
#define SPI_FLASH_MMU_PAGE_SIZE 0x10000 
#define SPI_FLASH_SEC_SIZE  4096    
    #define SPI_FLASH_YIELD_REQ_SUSPEND BIT(1)
    #define SPI_FLASH_YIELD_REQ_YIELD   BIT(0)
    #define SPI_FLASH_YIELD_STA_RESUME  BIT(2)
