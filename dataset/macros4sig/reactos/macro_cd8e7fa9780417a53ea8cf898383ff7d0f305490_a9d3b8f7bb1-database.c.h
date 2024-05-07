







#define AllocatePool(Size) ExAllocatePoolWithTag(PagedPool, Size, 'AtnM')
#define COLON_POSITION      0xD
#define DRIVE_LETTER_LENGTH 0x1C
#define FILE_READ_PROPERTIES  0x00000008
#define FILE_WRITE_PROPERTIES 0x00000010
#define FreePool(P)        ExFreePoolWithTag(P, 'AtnM')
#define INIT_SECTION __attribute__((section ("INIT")))
#define IsEqualGUID(rguid1, rguid2) (RtlCompareMemory(rguid1, rguid2, sizeof(GUID)) == sizeof(GUID))
#define LETTER_POSITION     0xC
#define MAX(a, b)          ((a > b) ? a : b)


