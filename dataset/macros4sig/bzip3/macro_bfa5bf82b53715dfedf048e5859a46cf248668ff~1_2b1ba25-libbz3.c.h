#include<pthread.h>
#include<limits.h>
#include<stddef.h>

#include<inttypes.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#define ALPHABET_SIZE (1 << CHAR_BIT)
#define BUCKETS_INDEX2(_c, _s) (((_c) << 1) + (_s))
#define BUCKETS_INDEX4(_c, _s) (((_c) << 2) + (_s))

#define LIBSAIS_PER_THREAD_CACHE_SIZE (24576)
#define SAINT_BIT (32)
#define SAINT_MAX INT32_MAX
#define SAINT_MIN INT32_MIN
#define SUFFIX_GROUP_BIT (SAINT_BIT - 1)
#define SUFFIX_GROUP_MARKER (((sa_sint_t)1) << (SUFFIX_GROUP_BIT - 1))
#define UNBWT_FASTBITS (17)
#define UNUSED(_x) (void)(_x)


#define KiB(x) ((x)*1024)
#define MiB(x) ((x)*1024 * 1024)
    #define RESTRICT __restrict__



        #define bswap16(x) (_byteswap_ushort(x))
    #define prefetch(address) __builtin_prefetch((const void *)(address), 0, 0)
    #define prefetchw(address) __builtin_prefetch((const void *)(address), 1, 0)
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

