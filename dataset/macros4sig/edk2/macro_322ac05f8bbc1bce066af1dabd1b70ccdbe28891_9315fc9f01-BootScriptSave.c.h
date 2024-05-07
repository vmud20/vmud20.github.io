


















#define MAX_IO_ADDRESS 0xFFFF
#define MAX_SMBUS_BLOCK_LEN               32
#define MIN_SMBUS_BLOCK_LEN               1
#define PCI_ADDRESS_ENCODE(S, A) PCI_SEGMENT_LIB_ADDRESS( \
                                   S, \
                                   ((((UINTN)(A)) & 0xff000000) >> 24), \
                                   ((((UINTN)(A)) & 0x00ff0000) >> 16), \
                                   ((((UINTN)(A)) & 0xff00) >> 8), \
                                   ((RShiftU64 ((A), 32) & 0xfff) | ((A) & 0xff)) \
                                   )
#define  S3_BOOT_SCRIPT_LIB_LABEL_OPCODE    0xFE
#define S3_BOOT_SCRIPT_LIB_TABLE_OPCODE                  0xAA
#define S3_BOOT_SCRIPT_LIB_TERMINATE_OPCODE              0xFF

#define BOOT_SCRIPT_NODE_MAX_LENGTH   1024
#define BOOT_SCRIPT_TABLE_VERSION     0x0001

