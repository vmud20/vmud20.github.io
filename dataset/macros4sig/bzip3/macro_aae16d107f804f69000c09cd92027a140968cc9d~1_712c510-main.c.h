#include<unistd.h>
#include<stdio.h>
#include<ctype.h>
#include<stdint.h>
#include<inttypes.h>

#include<stdlib.h>
#include<string.h>

#include<errno.h>
#include<stddef.h>
#include<getopt.h>
#include<fcntl.h>
#include<sys/stat.h>
#define BZ3_ERR_BWT -2
#define BZ3_ERR_CRC -3
#define BZ3_ERR_DATA_TOO_BIG -6
#define BZ3_ERR_INIT -7
#define BZ3_ERR_MALFORMED_HEADER -4
#define BZ3_ERR_OUT_OF_BOUNDS -1
#define BZ3_ERR_TRUNCATED_DATA -5
#define BZ3_OK 0
    #define BZIP3_API __declspec(dllexport) BZIP3_VISIBLE
        #define BZIP3_VISIBLE __attribute__((visibility("default")))



#define KiB(x) ((x)*1024)
#define MiB(x) ((x)*1024 * 1024)
    #define RESTRICT __restrict__



        #define bswap16(x) (_byteswap_ushort(x))
    #define prefetch(address) __builtin_prefetch((const void *)(address), 0, 0)
    #define prefetchw(address) __builtin_prefetch((const void *)(address), 1, 0)

#define no_argument 0
#define optional_argument 2
#define optpos __optpos
#define required_argument 1
