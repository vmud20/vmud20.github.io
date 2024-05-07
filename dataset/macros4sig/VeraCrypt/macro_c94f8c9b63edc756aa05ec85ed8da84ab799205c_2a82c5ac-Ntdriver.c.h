






















#define TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER 0x5645524142455854
#define TC_ENCRYPTION_SETUP_HEADER_UPDATE_THRESHOLD (64 * 1024 * 1024)
#define TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE (1536 * 1024)

#define TC_HIBERNATION_WRITE_BUFFER_SIZE (128 * 1024)
#define TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE (256 * 1024)
#define TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT 16
#define TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT 8

#define TC_BOOT_LOADER_AREA_SIZE (TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
#define TC_BOOT_LOADER_ARGS_OFFSET 0x10
#define TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR (TC_ORIG_BOOT_LOADER_BACKUP_SECTOR + TC_BOOT_LOADER_AREA_SECTOR_COUNT)
#define TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR_OFFSET (TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR * TC_SECTOR_SIZE_BIOS)
#define TC_BOOT_VOLUME_HEADER_SECTOR (TC_BOOT_LOADER_AREA_SECTOR_COUNT - 1)
#define TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET (TC_BOOT_VOLUME_HEADER_SECTOR * TC_SECTOR_SIZE_BIOS)
#define TC_CD_BOOTSECTOR_OFFSET 0xd000
#define TC_CD_BOOT_LOADER_SECTOR 26

#define TC_IS_BOOT_ARGUMENTS_SIGNATURE(SG)      (SG[0] == 'T' && SG[1] == 'R' && SG[2] == 'U' && SG[3] == 'E' && SG[4] == 0x11 && SG[5] == 0x23 && SG[6] == 0x45 && SG[7] == 0x66)
#define TC_MAX_EXTRA_BOOT_PARTITION_SIZE (512UL * 1024UL * 1024UL)
#define TC_MAX_MBR_BOOT_CODE_SIZE 440
#define TC_MBR_SECTOR 0
#define TC_ORIG_BOOT_LOADER_BACKUP_SECTOR TC_BOOT_LOADER_AREA_SECTOR_COUNT
#define TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET (TC_ORIG_BOOT_LOADER_BACKUP_SECTOR * TC_SECTOR_SIZE_BIOS)
#define TC_RESCUE_DISK_UPGRADE_NOTICE_MAX_VERSION 0x0113
#define TC_SET_BOOT_ARGUMENTS_SIGNATURE(SG) do { SG[0]  = 'T';   SG[1]  = 'R';   SG[2]  = 'U';   SG[3]  = 'E';   SG[4]  = 0x11;   SG[5]  = 0x23;   SG[6]  = 0x45;   SG[7]  = 0x66; } while (FALSE)

#define TC_BUG_CHECK(status) KeBugCheckEx (SECURITY_SYSTEM, "__LINE__", (ULONG_PTR) status, 0, 'VC')

#define WAIT_SECONDS(x) ((x)*10000000)

#define TC_HEX(N) 0##N##h
#define TC_UNSIGNED(N) N
#define TC__BOOT_LOADER_AREA_SECTOR_COUNT 63
#define TC__BOOT_LOADER_BACKUP_SECTOR_COUNT 30
#define TC__BOOT_LOADER_COMPRESSED_BUFFER_OFFSET (TC_COM_EXECUTABLE_OFFSET + 3072)
#define TC__BOOT_LOADER_DECOMPRESSOR_MEMORY_SIZE 32768
#define TC__BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT 4
#define TC__BOOT_LOADER_DECOMPRESSOR_START_SECTOR 2
#define TC__BOOT_LOADER_STACK_TOP (TC_BOOT_MEMORY_REQUIRED * TC_UNSIGNED (1024) - 4)
#define TC__BOOT_LOADER_START_SECTOR (TC_BOOT_LOADER_DECOMPRESSOR_START_SECTOR + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT)
#define TC__BOOT_SECTOR_CONFIG_OFFSET 439	
#define TC__BOOT_SECTOR_LOADER_CHECKSUM_OFFSET 434
#define TC__BOOT_SECTOR_LOADER_LENGTH_OFFSET 432
#define TC__BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET (TC__BOOT_SECTOR_USER_MESSAGE_OFFSET - TC__BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE)
#define TC__BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE 4
#define TC__BOOT_SECTOR_USER_CONFIG_OFFSET 438
#define TC__BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH 24
#define TC__BOOT_SECTOR_USER_MESSAGE_OFFSET (TC__BOOT_SECTOR_VERSION_OFFSET - TC__BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)
#define TC__BOOT_SECTOR_VERSION_OFFSET 430
#define TC__GZIP_HEADER_SIZE 10
#define TC__LB_SIZE 512
#define TC__MAX_BOOT_LOADER_DECOMPRESSED_SIZE ((TC_BOOT_LOADER_AREA_SECTOR_COUNT - 2) * TC_LB_SIZE)
#define TC__MAX_BOOT_LOADER_SECTOR_COUNT (TC_BOOT_LOADER_AREA_SECTOR_COUNT - TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT - 2)
