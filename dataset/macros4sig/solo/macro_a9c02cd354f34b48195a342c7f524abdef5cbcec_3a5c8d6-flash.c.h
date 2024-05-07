


#include<stdint.h>

#include<stdio.h>
#include<string.h>
#define FLASH_PAGE_END      127
#define FLASH_PAGE_SIZE     2048
#define FLASH_PAGE_START    0

#define flash_addr(page)    (0x08000000 + ((page)*FLASH_PAGE_SIZE))
