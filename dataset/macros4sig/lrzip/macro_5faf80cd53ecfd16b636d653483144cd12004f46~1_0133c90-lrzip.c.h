#include<unistd.h>
#include<utime.h>

#include<stdint.h>
#include<stdbool.h>
#include<stdlib.h>
#include<fcntl.h>
#include<stdarg.h>
#include<stdio.h>
#include<termios.h>
#include<inttypes.h>
#include<sys/types.h>
#include<sys/mman.h>
#include<semaphore.h>
#include<sys/statvfs.h>
#include<errno.h>
#include<math.h>
#include<pthread.h>
#include<sys/time.h>
#include<arpa/inet.h>


#define ARBITRARY  1000000   
#define ARBITRARY_AT_EPOCH (ARBITRARY * pow (MOORE_TIMES_PER_SECOND, -T_ZERO))
#define CBC_LEN 16
#define CTYPE_BZIP2 4
#define CTYPE_GZIP 7
#define CTYPE_LZMA 6
#define CTYPE_LZO 5
#define CTYPE_NONE 3
#define CTYPE_ZPAQ 8
#define ENCRYPT		(control->flags & FLAG_ENCRYPT)
#define FLAG_NOT_LZMA (FLAG_NO_COMPRESS | FLAG_LZO_COMPRESS | FLAG_BZIP2_COMPRESS | FLAG_ZLIB_COMPRESS | FLAG_ZPAQ_COMPRESS)
#define FLAG_VERBOSE (FLAG_VERBOSITY | FLAG_VERBOSITY_MAX)
#define HASH_LEN 64
#define INFO		(control->flags & FLAG_INFO)
#define IS_FROM_FILE ( !!(control->inFILE) && !STDIN )

#define MAX(a, b) ((a) > (b)? (a): (b))
# define MD5_DIGEST_SIZE 16
# define MD5_RELIABLE (0)
#define MIN(a, b) ((a) < (b)? (a): (b))
#define MOORE 1.835          
#define MOORE_TIMES_PER_SECOND pow (MOORE, 1.0 / SECONDS_IN_A_YEAR)
#define NUM_STREAMS 2
# define PAGE_SIZE (sysconf(_SC_PAGE_SIZE))
#define PASS_LEN 512
# define PROCESSORS (sysconf(_SC_NPROCESSORS_ONLN))
#define SALT_LEN 8
#define SECONDS_IN_A_YEAR (365*86400)
#define STDIN		(control->flags & FLAG_STDIN)
#define STDOUT		(control->flags & FLAG_STDOUT)
#define STREAM_BUFSIZE (1024 * 1024 * 10)
#define T_ZERO 1293840000    
#define VERBOSE		(control->flags & FLAG_VERBOSE)
#  define __BYTE_ORDER __BIG_ENDIAN
# define alloca __alloca
#define bswap_32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
# define bswap_64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)				      \
      | (((x) & 0x00ff000000000000ull) >> 40)				      \
      | (((x) & 0x0000ff0000000000ull) >> 24)				      \
      | (((x) & 0x000000ff00000000ull) >> 8)				      \
      | (((x) & 0x00000000ff000000ull) << 8)				      \
      | (((x) & 0x0000000000ff0000ull) << 24)				      \
      | (((x) & 0x000000000000ff00ull) << 40)				      \
      | (((x) & 0x00000000000000ffull) << 56))
#define dealloc(ptr) do { \
	free(ptr); \
	ptr = NULL; \
} while (0)
# define ffsll __builtin_ffsll
#define free(X) do { free((X)); (X) = NULL; } while (0)
#  define htole32(x) (x)
#  define htole64(x) (x)
#define int16 int
#define int32 int
#  define le32toh(x) (x)
#  define le64toh(x) (x)
#define likely(x)	__builtin_expect(!!(x), 1)
 #define mremap fake_mremap
#define one_g (1000 * 1024 * 1024)
#define print_err(...) do {\
	print_err(control, "__LINE__", "__FILE__", __func__, __VA_ARGS__); \
} while (0)
#define print_maxverbose(...)	do {\
	if (MAX_VERBOSE)	\
		print_stuff(4, __VA_ARGS__); \
} while (0)
#define print_output(...)	do {\
	print_stuff(1, __VA_ARGS__); \
} while (0)
#define print_progress(...)	do {\
	if (SHOW_PROGRESS)	\
		print_stuff(2, __VA_ARGS__); \
} while (0)
#define print_stuff(level, ...) do {\
	print_stuff(control, level, "__LINE__", "__FILE__", __func__, __VA_ARGS__); \
} while (0)
#define print_verbose(...)	do {\
	if (VERBOSE)	\
		print_stuff(3, __VA_ARGS__); \
} while (0)
# define strdupa(str) strcpy(alloca(strlen(str) + 1), str)
#define strerror(i) sys_errlist[i]
# define strndupa(str, len) strncpy(alloca(len + 1), str, len)
#define uchar unsigned char
#define uint16 unsigned int16
#define uint32 unsigned int32
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define failure(...) failure(control, "__LINE__", "__FILE__", __func__, __VA_ARGS__)
#define failure_goto(stuff, label) do { \
	failure stuff; \
	goto label; \
} while (0)
#define failure_return(stuff, ...) do { \
	failure stuff; \
	return __VA_ARGS__; \
} while (0)
#define fatal(...) fatal(control, "__LINE__", "__FILE__", __func__, __VA_ARGS__)
#define fatal_goto(stuff, label) do { \
	fatal stuff; \
	goto label; \
} while (0)
#define fatal_return(stuff, ...) do { \
	fatal stuff; \
	return __VA_ARGS__; \
} while (0)


#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16
#define _MD5_H 1
#  define __GNUC_PREREQ(maj, min)                                       \
  (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#  define __THROW       throw ()
# define __md5_buffer md5_buffer
# define __md5_finish_ctx md5_finish_ctx
# define __md5_init_ctx md5_init_ctx
# define __md5_process_block md5_process_block
# define __md5_process_bytes md5_process_bytes
# define __md5_read_ctx md5_read_ctx
# define __md5_stream md5_stream
