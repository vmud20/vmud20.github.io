#include<pthread.h>
#include<dirent.h>
#include<time.h>
#include<stdarg.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>

#include<fcntl.h>
#include<stdlib.h>

#include<sys/stat.h>
#include<string>





#define QLZ_COMPRESSION_LEVEL 3

#define QLZ_STREAMING_BUFFER 0
#define fast_read FAST_READ_3
#define fast_write FAST_WRITE_3
#define hash_func HASH_FUNC_3
#define memcpy_up MEMCPY_UP_3
#define qlz_compress QLZ_COMPRESS_3
#define qlz_compress_core QLZ_COMPRESS_CORE_3
#define qlz_decompress QLZ_DECOMPRESS_3
#define qlz_decompress_core QLZ_DECOMPRESS_CORE_3
#define qlz_get_setting QLZ_GET_SETTING_3
#define qlz_hash_compress QLZ_HASH_COMPRESS_3
#define qlz_hash_decompress QLZ_HASH_DECOMPRESS_3
#define qlz_hash_entry QLZ_HASH_ENTRY_3
#define qlz_size_compressed QLZ_SIZE_COMPRESSED_3
#define qlz_size_decompressed QLZ_SIZE_DECOMPRESSED_3
#define reset_state RESET_STATE_3
#define update_hash UPDATE_HASH_3
#define update_hash_upto UPDATE_HASH_UPTO_3
#define CWORD_LEN 4
#define MINOFFSET 2
#define UNCOMPRESSED_END 4
#define UNCONDITIONAL_MATCHLEN 6
#define QLZ_ALIGNMENT_PADD 8
#define QLZ_BUFFER_COUNTER 8
#define QLZ_HASH_VALUES 4096

#define QLZ_POINTERS 1
#define QLZ_SCRATCH_COMPRESS (QLZ_ALIGNMENT_PADD + QLZ_BUFFER_COUNTER + QLZ_STREAMING_BUFFER + sizeof(qlz_hash_compress[QLZ_HASH_VALUES]) + QLZ_HASH_VALUES)
#define QLZ_VERSION_MAJOR 1
#define QLZ_VERSION_MINOR 4
#define QLZ_VERSION_REVISION 1

#define AIO_MAX_SECTOR_SIZE (64*1024)
