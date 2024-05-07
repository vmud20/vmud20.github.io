#include<sys/socket.h>
#include<stdbool.h>
#include<sys/stat.h>
#include<errno.h>





#include<assert.h>

#include<sys/types.h>
#include<zlib.h>


#include<features.h>



#include<sys/time.h>
#include<dirent.h>
#include<signal.h>

#include<fcntl.h>
#include<sys/cdefs.h>
#include<syslog.h>
#include<netinet/in.h>

#include<string.h>
#include<netdb.h>

#include<limits.h>



#include<pthread.h>



#include<unistd.h>
#include<stdint.h>
#include<execinfo.h>
#include<stdio.h>

#include<net/if.h>






#include<strings.h>
#include<sys/param.h>

#include<arpa/inet.h>

#include<stddef.h>

#include<time.h>
#include<ctype.h>
#include<stdlib.h>




#define CHECK_CLOAKING 2
#define CHECK_IMG_URL 8
#define CHECK_SSL 1
#define CLEANUP_URL 4
#define CL_PHISH_ALL_CHECKS (CLEANUP_URL | CHECK_SSL | CHECK_CLOAKING | CHECK_IMG_URL)
#define CL_PHISH_BASE 100
#define LINKTYPE_IMAGE 1


#define LIBXML_WRITER_ENABLED 1
#define MSXML_COMMENT_CB 0x8
#define MSXML_FLAG_JSON 0x1
#define MSXML_FLAG_WALK 0x2
#define MSXML_IGNORE 0x0
#define MSXML_IGNORE_ELEM 0x1
#define MSXML_JSON_ATTRIB 0x400
#define MSXML_JSON_COUNT 0x100
#define MSXML_JSON_MULTI 0x40
#define MSXML_JSON_ROOT 0x10
#define MSXML_JSON_STRLEN_MAX 128
#define MSXML_JSON_TRACK (MSXML_JSON_ROOT | MSXML_JSON_WRKPTR)
#define MSXML_JSON_VALUE 0x200
#define MSXML_JSON_WRKPTR 0x20
#define MSXML_RECLEVEL_MAX 20
#define MSXML_SCAN_B64 0x4
#define MSXML_SCAN_CB 0x2

#define CLAMAV_MIN_XMLREADER_FLAGS (XML_PARSE_NOERROR | XML_PARSE_NONET)
#define CLI_FTW_FOLLOW_DIR_SYMLINK 0x02
#define CLI_FTW_FOLLOW_FILE_SYMLINK 0x01
#define CLI_FTW_NEED_STAT 0x04
#define CLI_FTW_STD (CLI_FTW_NEED_STAT | CLI_FTW_TRIM_SLASHES)
#define CLI_FTW_TRIM_SLASHES 0x08
#define CLI_ISCONTAINED(bb, bb_size, sb, sb_size)                                           \
    (                                                                                       \
        (size_t)(bb_size) > 0 && (size_t)(sb_size) > 0 &&                                   \
        (size_t)(sb_size) <= (size_t)(bb_size) &&                                           \
        (ptrdiff_t)(sb) >= (ptrdiff_t)(bb) &&                                               \
        (ptrdiff_t)(sb) + (ptrdiff_t)(sb_size) <= (ptrdiff_t)(bb) + (ptrdiff_t)(bb_size) && \
        (ptrdiff_t)(sb) + (ptrdiff_t)(sb_size) > (ptrdiff_t)(bb) &&                         \
        (ptrdiff_t)(sb) < (ptrdiff_t)(bb) + (ptrdiff_t)(bb_size))
#define CLI_ISCONTAINED2(bb, bb_size, sb, sb_size)                                          \
    (                                                                                       \
        (size_t)(bb_size) > 0 && (size_t)(sb_size) >= 0 &&                                  \
        (size_t)(sb_size) <= (size_t)(bb_size) &&                                           \
        (ptrdiff_t)(sb) >= (ptrdiff_t)(bb) &&                                               \
        (ptrdiff_t)(sb) + (ptrdiff_t)(sb_size) <= (ptrdiff_t)(bb) + (ptrdiff_t)(bb_size) && \
        (ptrdiff_t)(sb) + (ptrdiff_t)(sb_size) >= (ptrdiff_t)(bb) &&                        \
        (ptrdiff_t)(sb) < (ptrdiff_t)(bb) + (ptrdiff_t)(bb_size))
#define CLI_MAX_ALLOCATION (182 * 1024 * 1024)
#define CLI_PWDB_COUNT 3
#define CLI_ROL(a, b) a = (a << ((b)&__SHIFTMASK(a))) | (a >> ((__SHIFTBITS(a) - (b)) & __SHIFTMASK(a)))
#define CLI_ROR(a, b) a = (a >> ((b)&__SHIFTMASK(a))) | (a << ((__SHIFTBITS(a) - (b)) & __SHIFTMASK(a)))
#define CLI_SAR(n, s) n = CLI_SRS(n, s)
#define CLI_SRS(n, s) ((n) >> (s))
#define CL_FLEVEL 120
#define CL_FLEVEL_DCONF CL_FLEVEL
#define CL_FLEVEL_SIGTOOL CL_FLEVEL
#define CONTAINER_FLAG_VALID 0x01
#define HAVE_CLI_GETPAGESIZE 1
#define LIKELY(cond) __builtin_expect(!!(cond), 1)
#define NAME_MAX MAXNAMELEN
#define SCAN_ALLMATCHES (ctx->options->general & CL_SCAN_GENERAL_ALLMATCHES)
#define SCAN_COLLECT_METADATA (ctx->options->general & CL_SCAN_GENERAL_COLLECT_METADATA)
#define SCAN_DEV_COLLECT_PERF_INFO (ctx->options->dev & CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO)
#define SCAN_DEV_COLLECT_SHA (ctx->options->dev & CL_SCAN_DEV_COLLECT_SHA)
#define SCAN_HEURISTICS (ctx->options->general & CL_SCAN_GENERAL_HEURISTICS)
#define SCAN_HEURISTIC_BROKEN (ctx->options->heuristic & CL_SCAN_HEURISTIC_BROKEN)
#define SCAN_HEURISTIC_ENCRYPTED_ARCHIVE (ctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
#define SCAN_HEURISTIC_ENCRYPTED_DOC (ctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
#define SCAN_HEURISTIC_EXCEEDS_MAX (ctx->options->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX)
#define SCAN_HEURISTIC_MACROS (ctx->options->heuristic & CL_SCAN_HEURISTIC_MACROS)
#define SCAN_HEURISTIC_PARTITION_INTXN (ctx->options->heuristic & CL_SCAN_HEURISTIC_PARTITION_INTXN)
#define SCAN_HEURISTIC_PHISHING_CLOAK (ctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_CLOAK)
#define SCAN_HEURISTIC_PHISHING_SSL_MISMATCH (ctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH)
#define SCAN_HEURISTIC_PRECEDENCE (ctx->options->general & CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE)
#define SCAN_HEURISTIC_STRUCTURED (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED)
#define SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL)
#define SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED)
#define SCAN_MAIL_PARTIAL_MESSAGE (ctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE)
#define SCAN_PARSE_ARCHIVE (ctx->options->parse & CL_SCAN_PARSE_ARCHIVE)
#define SCAN_PARSE_ELF (ctx->options->parse & CL_SCAN_PARSE_ELF)
#define SCAN_PARSE_HTML (ctx->options->parse & CL_SCAN_PARSE_HTML)
#define SCAN_PARSE_HWP3 (ctx->options->parse & CL_SCAN_PARSE_HWP3)
#define SCAN_PARSE_MAIL (ctx->options->parse & CL_SCAN_PARSE_MAIL)
#define SCAN_PARSE_OLE2 (ctx->options->parse & CL_SCAN_PARSE_OLE2)
#define SCAN_PARSE_PDF (ctx->options->parse & CL_SCAN_PARSE_PDF)
#define SCAN_PARSE_PE (ctx->options->parse & CL_SCAN_PARSE_PE)
#define SCAN_PARSE_SWF (ctx->options->parse & CL_SCAN_PARSE_SWF)
#define SCAN_PARSE_XMLDOCS (ctx->options->parse & CL_SCAN_PARSE_XMLDOCS)
#define STATS_ANON_UUID "5b585e8f-3be5-11e3-bf0b-18037319526c"
#define STATS_MAX_MEM 1024 * 1024
#define STATS_MAX_SAMPLES 50
#define UNLIKELY(cond) __builtin_expect(!!(cond), 0)

#define __SHIFTBITS(a) (sizeof(a) << 3)
#define __SHIFTMASK(a) (__SHIFTBITS(a) - 1)

#define __hot__ __attribute__((hot))
#define always_inline inline __attribute__((always_inline))
#define be16_to_host(v) cbswap16(v)
#define be32_to_host(v) cbswap32(v)
#define be64_to_host(v) cbswap64(v)
#define cbswap16(v) (((v & 0xff) << 8) | (((v) >> 8) & 0xff))
#define cbswap32(v) ((((v)&0x000000ff) << 24) | (((v)&0x0000ff00) << 8) | \
                     (((v)&0x00ff0000) >> 8) | (((v)&0xff000000) >> 24))
#define cbswap64(v) ((((v)&0x00000000000000ffULL) << 56) | \
                     (((v)&0x000000000000ff00ULL) << 40) | \
                     (((v)&0x0000000000ff0000ULL) << 24) | \
                     (((v)&0x00000000ff000000ULL) << 8) |  \
                     (((v)&0x000000ff00000000ULL) >> 8) |  \
                     (((v)&0x0000ff0000000000ULL) >> 24) | \
                     (((v)&0x00ff000000000000ULL) >> 40) | \
                     (((v)&0xff00000000000000ULL) >> 56))
#define cli_dbgmsg (!UNLIKELY(cli_debug_flag)) ? (void)0 : cli_dbgmsg_internal
#define cli_readint16(buff) (((const union unaligned_16 *)(buff))->una_s16)
#define cli_readint32(buff) (((const union unaligned_32 *)(buff))->una_s32)
#define cli_readint64(buff) (((const union unaligned_64 *)(buff))->una_s64)
#define cli_writeint32(offset, value) (((union unaligned_32 *)(offset))->una_u32 = (uint32_t)(value))
#define le16_to_host(v) (v)
#define le32_to_host(v) (v)
#define le64_to_host(v) (v)
#define never_inline __attribute__((noinline))
#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; }
#define ERROR_CALLBACK_ERROR                    28
#define ERROR_CORRUPT_FILE                      7
#define ERROR_COULD_NOT_ATTACH_TO_PROCESS       2
#define ERROR_COULD_NOT_MAP_FILE                4
#define ERROR_COULD_NOT_OPEN_FILE               3
#define ERROR_DUPLICATE_IDENTIFIER              14
#define ERROR_DUPLICATE_LOOP_IDENTIFIER         13
#define ERROR_DUPLICATE_META_IDENTIFIER         16
#define ERROR_DUPLICATE_STRING_IDENTIFIER       17
#define ERROR_DUPLICATE_TAG_IDENTIFIER          15
#define ERROR_EXEC_STACK_OVERFLOW               25
#define ERROR_INCLUDES_CIRCULAR_REFERENCE       22
#define ERROR_INCLUDE_DEPTH_EXCEEDED            23
#define ERROR_INSUFICIENT_MEMORY                1
#define ERROR_INTERNAL_FATAL_ERROR              31
#define ERROR_INVALID_ARGUMENT                  29
#define ERROR_INVALID_FIELD_NAME                33
#define ERROR_INVALID_FILE                      6
#define ERROR_INVALID_FORMAT                    38
#define ERROR_INVALID_HEX_STRING                10
#define ERROR_INVALID_REGULAR_EXPRESSION        9
#define ERROR_LOOP_NESTING_LIMIT_EXCEEDED       12
#define ERROR_MISPLACED_ANONYMOUS_STRING        21
#define ERROR_NESTED_FOR_OF_LOOP                32
#define ERROR_NOT_AN_ARRAY                      36
#define ERROR_NOT_A_FUNCTION                    37
#define ERROR_NOT_A_STRUCTURE                   35
#define ERROR_SCAN_TIMEOUT                      26
#define ERROR_SUCCESS                           0
#define ERROR_SYNTAX_ERROR                      11
#define ERROR_TOO_MANY_ARGUMENTS                39
#define ERROR_TOO_MANY_MATCHES                  30
#define ERROR_TOO_MANY_SCAN_THREADS             27
#define ERROR_UNDEFINED_IDENTIFIER              20
#define ERROR_UNDEFINED_STRING                  19
#define ERROR_UNKNOWN_MODULE                    34
#define ERROR_UNREFERENCED_STRING               18
#define ERROR_UNSUPPORTED_FILE_VERSION          8
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS         40
#define ERROR_WRONG_TYPE                        24
#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : TRUE)
#define EXTERNAL_VARIABLE_TYPE_ANY           1
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN       3
#define EXTERNAL_VARIABLE_TYPE_FIXED_STRING  4
#define EXTERNAL_VARIABLE_TYPE_INTEGER       2
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING 5
#define EXTERNAL_VARIABLE_TYPE_NULL          0
#define FAIL_ON_COMPILER_ERROR(x) { \
    compiler->last_result = (x); \
    if (compiler->last_result != ERROR_SUCCESS) { \
        if (compiler->last_result == ERROR_INSUFICIENT_MEMORY) \
            yyfatal(yyscanner, "YARA fatal error: terminating rule parse\n"); \
        return compiler->last_result; \
    } \
}
#define FAIL_ON_ERROR(x) { \
    int result = (x); \
    if (result != ERROR_SUCCESS) \
        return result; \
}
#define LEX_BUF_SIZE                    1024
#define LOOP_LOCAL_VARS                 4
#define MAX_COMPILER_ERROR_EXTRA_INFO   256
#define MAX_FUNCTION_ARGS               128
#define MAX_INCLUDE_DEPTH               16
#define MAX_LOOP_NESTING                4
#define MAX_PATH                        1024
#define META_TYPE_BOOLEAN   3
#define META_TYPE_INTEGER   1
#define META_TYPE_NULL      0
#define META_TYPE_STRING    2
#define OBJECT_COMMON_FIELDS \
    int8_t type; \
    const char* identifier; \
    void* data; \
    struct _YR_OBJECT* parent;
#define OBJECT_TYPE_ARRAY       4
#define OBJECT_TYPE_FUNCTION    5
#define OBJECT_TYPE_INTEGER     1
#define OBJECT_TYPE_REGEXP      6
#define OBJECT_TYPE_STRING      2
#define OBJECT_TYPE_STRUCTURE   3
#define PTR_TO_UINT64(x)  ((uint64_t) (size_t) x)
#define RE_FLAGS_BACKWARDS                0x04
#define RE_FLAGS_DOT_ALL                  0x80
#define RE_FLAGS_EXHAUSTIVE               0x08
#define RE_FLAGS_FAST_HEX_REGEXP          0x02
#define RE_FLAGS_NOT_AT_START             0x100
#define RE_FLAGS_NO_CASE                  0x20
#define RE_FLAGS_SCAN                     0x40
#define RE_FLAGS_WIDE                     0x10
#define RULE_ALL        2
#define RULE_ANY        1
#define RULE_EP         16
#define RULE_GFLAGS_GLOBAL               0x02
#define RULE_GFLAGS_NULL                 0x1000
#define RULE_GFLAGS_PRIVATE              0x01
#define RULE_GFLAGS_REQUIRE_EXECUTABLE   0x04
#define RULE_GFLAGS_REQUIRE_FILE         0x08
#define RULE_IS_GLOBAL(x) \
    (((x)->g_flags) & RULE_GFLAGS_GLOBAL)
#define RULE_IS_NULL(x) \
    (((x)->g_flags) & RULE_GFLAGS_NULL)
#define RULE_IS_PRIVATE(x) \
    (((x)->g_flags) & RULE_GFLAGS_PRIVATE)
#define RULE_MATCHES(x) \
    ((x)->t_flags[yr_get_tidx()] & RULE_TFLAGS_MATCH)
#define RULE_OFFSETS    32
#define RULE_ONE        4
#define RULE_TFLAGS_MATCH                0x01
#define RULE_THEM       8
#define SIZED_STRING_FLAGS_DOT_ALL  2
#define SIZED_STRING_FLAGS_NO_CASE  1
#define STRING_FITS_IN_ATOM(x) \
    (((x)->g_flags) & STRING_GFLAGS_FITS_IN_ATOM)
#define STRING_FOUND(x) \
    ((x)->matches[yr_get_tidx()].tail != NULL)
#define STRING_GFLAGS_ANONYMOUS         0x100
#define STRING_GFLAGS_ASCII             0x08
#define STRING_GFLAGS_CHAIN_PART        0x2000
#define STRING_GFLAGS_CHAIN_TAIL        0x4000
#define STRING_GFLAGS_FAST_HEX_REGEXP   0x40
#define STRING_GFLAGS_FITS_IN_ATOM      0x800
#define STRING_GFLAGS_FULL_WORD         0x80
#define STRING_GFLAGS_HEXADECIMAL       0x02
#define STRING_GFLAGS_LITERAL           0x400
#define STRING_GFLAGS_NO_CASE           0x04
#define STRING_GFLAGS_NULL              0x1000
#define STRING_GFLAGS_REFERENCED        0x01
#define STRING_GFLAGS_REGEXP            0x20
#define STRING_GFLAGS_REGEXP_DOT_ALL    0x8000
#define STRING_GFLAGS_SINGLE_MATCH      0x200
#define STRING_GFLAGS_WIDE              0x10
#define STRING_IS_ANONYMOUS(x) \
    (((x)->g_flags) & STRING_GFLAGS_ANONYMOUS)
#define STRING_IS_ASCII(x) \
    (((x)->g_flags) & STRING_GFLAGS_ASCII)
#define STRING_IS_CHAIN_PART(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_PART)
#define STRING_IS_CHAIN_TAIL(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_TAIL)
#define STRING_IS_FAST_HEX_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_FAST_HEX_REGEXP)
#define STRING_IS_FULL_WORD(x) \
    (((x)->g_flags) & STRING_GFLAGS_FULL_WORD)
#define STRING_IS_HEX(x) \
    (((x)->g_flags) & STRING_GFLAGS_HEXADECIMAL)
#define STRING_IS_LITERAL(x) \
    (((x)->g_flags) & STRING_GFLAGS_LITERAL)
#define STRING_IS_NO_CASE(x) \
    (((x)->g_flags) & STRING_GFLAGS_NO_CASE)
#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->g_flags) & STRING_GFLAGS_NULL)
#define STRING_IS_REFERENCED(x) \
    (((x)->g_flags) & STRING_GFLAGS_REFERENCED)
#define STRING_IS_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP)
#define STRING_IS_REGEXP_DOT_ALL(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP_DOT_ALL)
#define STRING_IS_SINGLE_MATCH(x) \
    (((x)->g_flags) & STRING_GFLAGS_SINGLE_MATCH)
#define STRING_IS_WIDE(x) \
    (((x)->g_flags) & STRING_GFLAGS_WIDE)
#define UINT64_TO_PTR(type, x)  ((type)(size_t) x)


#define strlcat cli_strlcat
#define strlcpy cli_strlcpy
#define xtoi cli_xtoi
#define yr_free free
#define yr_malloc cli_malloc
#define yr_realloc cli_realloc
#define yr_strdup cli_strdup
#define CLI_NOCASE(val) tolower(val)
#define CLI_NOCASEI(val) toupper(val)
#define CLI_STRCASESTR strcasestr
#define CLI_STRNDUP strndup
#define CLI_STRNLEN strnlen
#define CLI_STRNSTR strnstr
#define SIZE_T_CHARLEN ((sizeof(size_t) * CHAR_BIT + 2) / 3 + 1)

#define CLAMSTAT stat64
#define CL_COUNTSIGS_ALL                            (CL_COUNTSIGS_OFFICIAL | CL_COUNTSIGS_UNOFFICIAL)
#define CL_COUNTSIGS_OFFICIAL                       0x1
#define CL_COUNTSIGS_UNOFFICIAL                     0x2
#define CL_COUNT_PRECISION 4096
#define CL_DB_BYTECODE          0x2000
#define CL_DB_BYTECODE_STATS    0x20000
#define CL_DB_BYTECODE_UNSIGNED 0x8000
#define CL_DB_COMPILED          0x400   
#define CL_DB_CVDNOTMP          0x20    
#define CL_DB_DIRECTORY         0x800   
#define CL_DB_ENHANCED          0x40000
#define CL_DB_OFFICIAL          0x40    
#define CL_DB_OFFICIAL_ONLY     0x1000
#define CL_DB_PCRE_STATS        0x80000
#define CL_DB_PHISHING          0x2
#define CL_DB_PHISHING_URLS     0x8
#define CL_DB_PUA               0x10
#define CL_DB_PUA_EXCLUDE       0x200
#define CL_DB_PUA_INCLUDE       0x100
#define CL_DB_PUA_MODE          0x80
#define CL_DB_SIGNED            0x4000  
#define CL_DB_STDOPT (CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE)
#define CL_DB_UNSIGNED          0x10000 
#define CL_DB_YARA_EXCLUDE      0x100000
#define CL_DB_YARA_ONLY         0x200000
#define CL_INIT_DEFAULT 0x0
#define CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO        0x2 
#define CL_SCAN_DEV_COLLECT_SHA                     0x1 
#define CL_SCAN_GENERAL_ALLMATCHES                  0x1 
#define CL_SCAN_GENERAL_COLLECT_METADATA            0x2 
#define CL_SCAN_GENERAL_HEURISTICS                  0x4 
#define CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE        0x8 
#define CL_SCAN_HEURISTIC_BROKEN                    0x2   
#define CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE         0x40  
#define CL_SCAN_HEURISTIC_ENCRYPTED_DOC             0x80  
#define CL_SCAN_HEURISTIC_EXCEEDS_MAX               0x4   
#define CL_SCAN_HEURISTIC_MACROS                    0x20  
#define CL_SCAN_HEURISTIC_PARTITION_INTXN           0x100 
#define CL_SCAN_HEURISTIC_PHISHING_CLOAK            0x10  
#define CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH     0x8   
#define CL_SCAN_HEURISTIC_STRUCTURED                0x200 
#define CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL     0x400 
#define CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED   0x800 
#define CL_SCAN_MAIL_PARTIAL_MESSAGE                0x1
#define CL_SCAN_PARSE_ARCHIVE                       0x1
#define CL_SCAN_PARSE_ELF                           0x2
#define CL_SCAN_PARSE_HTML                          0x100
#define CL_SCAN_PARSE_HWP3                          0x10
#define CL_SCAN_PARSE_MAIL                          0x40
#define CL_SCAN_PARSE_OLE2                          0x80
#define CL_SCAN_PARSE_PDF                           0x4
#define CL_SCAN_PARSE_PE                            0x200
#define CL_SCAN_PARSE_SWF                           0x8
#define CL_SCAN_PARSE_XMLDOCS                       0x20
#define ENGINE_OPTIONS_DISABLE_CACHE    0x1
#define ENGINE_OPTIONS_DISABLE_PE_CERTS 0x8
#define ENGINE_OPTIONS_DISABLE_PE_STATS 0x4
#define ENGINE_OPTIONS_FORCE_TO_DISK    0x2
#define ENGINE_OPTIONS_NONE             0x0
#define ENGINE_OPTIONS_PE_DUMPCERTS     0x10
#define FSTAT fstat64
#define LSTAT lstat64
#define MD5_HASH_SIZE 16
#define SHA1_HASH_SIZE 20
#define SHA256_HASH_SIZE 32
#define SHA384_HASH_SIZE 48
#define SHA512_HASH_SIZE 64
#define STAT64_BLACKLIST 1
#define STATBUF struct stat64
#define UNUSEDPARAM(x) (void)(x)

#define safe_open open

#define LIST_SWAP(head1, head2, type, field) do {			\
	struct type *swap_tmp = LIST_FIRST((head1));			\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	struct type *swap_first = SLIST_FIRST(head1);			\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	struct type *swap_first = STAILQ_FIRST(head1);			\
	struct type **swap_last = (head1)->stqh_last;			\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)
#define CRT_RAWMAXLEN 64



#define mp_add fp_add


#define mp_cmp fp_cmp
#define mp_copy(a, b) (fp_copy(a, b), 0)
#define mp_div fp_div
#define mp_exptmod fp_exptmod
#define mp_get_int(a) ((a)->used > 0 ? (a)->dp[0] : 0)
#define mp_init(a) (fp_init(a), 0)
#define mp_init_multi(a, b, c, d) (mp_init(a), mp_init(b), mp_init(c), 0)
#define mp_mul_2d fp_mul_2d
#define mp_read_radix fp_read_radix
#define mp_read_unsigned_bin(a, b, c) (fp_read_unsigned_bin(a, b, c), 0)
#define mp_set_int(a, b) fp_set(a, b)
#define mp_to_unsigned_bin(a, b) (fp_to_unsigned_bin(a, b), 0)
#define mp_toradix_n(a, b, c, d) fp_toradix_n(a, b, c, d)
#define mp_unsigned_bin_size fp_unsigned_bin_size
#define DIGIT_BIT (int)((CHAR_BIT) * sizeof(fp_digit))

#define FP_EQ 0  
#define FP_GT 1  
#define FP_LT -1 
#define FP_MASK (fp_digit)(-1)
#define FP_MAX_SIZE (8192 + (8 * DIGIT_BIT))
#define FP_MEM 2
#define FP_NEG 1
#define FP_NO 0  
#define FP_OKAY 0
#define FP_SIZE (FP_MAX_SIZE / DIGIT_BIT)
#define FP_VAL 1
#define FP_YES 1 
#define FP_ZPOS 0
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))















#define TFM_PRIME_2MSB_OFF 0x0004 
#define TFM_PRIME_2MSB_ON 0x0008  
#define TFM_PRIME_BBS 0x0001      
#define TFM_PRIME_SAFE 0x0002     















#define fp_abs(a, b)   \
    {                  \
        fp_copy(a, b); \
        (b)->sign = 0; \
    }
#define fp_clamp(a)                                                     \
    {                                                                   \
        while ((a)->used && (a)->dp[(a)->used - 1] == 0) --((a)->used); \
        (a)->sign = (a)->used ? (a)->sign : FP_ZPOS;                    \
    }
#define fp_copy(a, b) (void)(((a) != (b)) && memcpy((b), (a), sizeof(fp_int)))
#define fp_init(a) (void)memset((a), 0, sizeof(fp_int))
#define fp_init_copy(a, b) fp_copy(b, a)
#define fp_iseven(a) (((a)->used >= 0 && (((a)->dp[0] & 1) == 0)) ? FP_YES : FP_NO)
#define fp_isodd(a) (((a)->used > 0 && (((a)->dp[0] & 1) == 1)) ? FP_YES : FP_NO)
#define fp_iszero(a) (((a)->used == 0) ? FP_YES : FP_NO)
#define fp_neg(a, b)    \
    {                   \
        fp_copy(a, b);  \
        (b)->sign ^= 1; \
        fp_clamp(b);    \
    }
#define fp_prime_random(a, t, size, bbs, cb, dat) fp_prime_random_ex(a, t, ((size)*8) + 1, (bbs == 1) ? TFM_PRIME_BBS : 0, cb, dat)
#define fp_zero(a) fp_init(a)


#define PE_INVALID_RVA 0xFFFFFFFF

#define INIT_STRFIELD(field, value)                           \
    do {                                                      \
        strncpy((char *)(field), (value), sizeof(field) - 1); \
        (field)[sizeof(field) - 1] = 0;                       \
    } while (0)
#define MAKE_VERSION(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)


#define BC_FORMAT_096 6
#define BC_FORMAT_LEVEL 7
#define BC_HEADER "ClamBC"
#define BC_START_TID 69


#define unrar_close libclamunrar_iface_LTX_unrar_close
#define unrar_extract_file libclamunrar_iface_LTX_unrar_extract_file
#define unrar_open libclamunrar_iface_LTX_unrar_open
#define unrar_peek_file_header libclamunrar_iface_LTX_unrar_peek_file_header
#define unrar_skip_file libclamunrar_iface_LTX_unrar_skip_file
#define CL_FILE_MBUFF_SIZE 1024
#define CL_PART_MBUFF_SIZE 1028
#define CL_TYPENO 500
#define MAGIC_BUFFER_SIZE 1028
#define MAX_EMBEDDED_OBJ 10

#define ARCH_CONF_7Z      0x10000
#define ARCH_CONF_APM     0x2000000
#define ARCH_CONF_ARJ     0x1000
#define ARCH_CONF_AUTOIT  0x2000
#define ARCH_CONF_BINHEX  0x200
#define ARCH_CONF_BZ      0x8
#define ARCH_CONF_CAB     0x20
#define ARCH_CONF_CHM     0x40
#define ARCH_CONF_CPIO    0x4000
#define ARCH_CONF_DMG     0x40000
#define ARCH_CONF_EGG     0x4000000
#define ARCH_CONF_GPT     0x1000000
#define ARCH_CONF_GZ      0x4
#define ARCH_CONF_HFSPLUS 0x100000
#define ARCH_CONF_ISHIELD 0x8000
#define ARCH_CONF_ISO9660 0x20000
#define ARCH_CONF_MBR     0x800000
#define ARCH_CONF_NSIS    0x800
#define ARCH_CONF_OLE2    0x80
#define ARCH_CONF_PASSWD  0x400000
#define ARCH_CONF_RAR     0x1
#define ARCH_CONF_SIS     0x400
#define ARCH_CONF_SZDD    0x10
#define ARCH_CONF_TAR     0x100
#define ARCH_CONF_XAR     0x80000
#define ARCH_CONF_XZ      0x200000
#define ARCH_CONF_ZIP     0x2
#define BYTECODE_ENGINE_MASK (BYTECODE_INTERPRETER | BYTECODE_JIT_X86 | BYTECODE_JIT_PPC | BYTECODE_JIT_ARM)
#define BYTECODE_INTERPRETER 0x1
#define BYTECODE_JIT_ARM     0x8
#define BYTECODE_JIT_PPC     0x4
#define BYTECODE_JIT_X86     0x2
#define DCONF_STATS_DISABLED            0x1
#define DCONF_STATS_PE_SECTION_DISABLED 0x2
#define DOC_CONF_HTML         0x1
#define DOC_CONF_HTML_SKIPRAW 0x10
#define DOC_CONF_HWP          0x200
#define DOC_CONF_JSNORM       0x20
#define DOC_CONF_MSXML        0x80
#define DOC_CONF_OOXML        0x100
#define DOC_CONF_PDF          0x4
#define DOC_CONF_RTF          0x2
#define DOC_CONF_SCRIPT       0x8
#define DOC_CONF_SWF          0x40
#define MAIL_CONF_MBOX 0x1
#define MAIL_CONF_TNEF 0x2
#define OTHER_CONF_CRYPTFF      0x10
#define OTHER_CONF_DLP          0x20
#define OTHER_CONF_JPEG         0x8
#define OTHER_CONF_LZW          0x400
#define OTHER_CONF_MYDOOMLOG    0x40
#define OTHER_CONF_PDFNAMEOBJ   0x100
#define OTHER_CONF_PREFILTERING 0x80
#define OTHER_CONF_PRTNINTXN    0x200
#define OTHER_CONF_RIFF         0x4
#define OTHER_CONF_SCRENC       0x2
#define OTHER_CONF_UUENC        0x1
#define PCRE_CONF_GLOBAL  0x4
#define PCRE_CONF_OPTIONS 0x2
#define PCRE_CONF_SUPPORT 0x1
#define PE_CONF_ASPACK    0x8000
#define PE_CONF_CATALOG   0x10000
#define PE_CONF_CERTS     0x20000
#define PE_CONF_FSG       0x40
#define PE_CONF_IMPTBL    0x80000
#define PE_CONF_KRIZ      0x2
#define PE_CONF_MAGISTR   0x4
#define PE_CONF_MATCHICON 0x40000
#define PE_CONF_MD5SECT   0x10
#define PE_CONF_MEW       0x2000
#define PE_CONF_NSPACK    0x1000
#define PE_CONF_PARITE    0x1
#define PE_CONF_PESPIN    0x200
#define PE_CONF_PETITE    0x100
#define PE_CONF_POLIPOS   0x8
#define PE_CONF_SWIZZOR   0x80
#define PE_CONF_UPACK     0x4000
#define PE_CONF_UPX       0x20
#define PE_CONF_WWPACK    0x800
#define PE_CONF_YC        0x400
#define PHISHING_CONF_ENGINE  0x1
#define PHISHING_CONF_ENTCONV 0x2

#define cli_mpool_dconf_init(a) cli_dconf_init(a)
#define CLI_MPOOL_HEX2STR(mpool, src) cli_mpool_hex2str(mpool, src)
#define CLI_MPOOL_HEX2UI(mpool, hex) cli_mpool_hex2ui(mpool, hex)
#define CLI_MPOOL_STRDUP(mpool, s) cli_mpool_strdup(mpool, s)
#define CLI_MPOOL_STRNDUP(mpool, s, n) cli_mpool_strndup(mpool, s, n)
#define CLI_MPOOL_VIRNAME(mpool, a, b) cli_mpool_virname(mpool, a, b)
#define MPOOL_CALLOC(a, b, c) mpool_calloc(a, b, c)
#define MPOOL_FLUSH(val) mpool_flush(val)
#define MPOOL_FREE(a, b) mpool_free(a, b)
#define MPOOL_GETSTATS(mpool, used, total) mpool_getstats(mpool, used, total)

#define MPOOL_MALLOC(a, b) mpool_malloc(a, b)
#define MPOOL_REALLOC(a, b, c) mpool_realloc(a, b, c)
#define MPOOL_REALLOC2(a, b, c) mpool_realloc2(a, b, c)
#define CLI_DBEXT(ext)                   \
    (                                    \
        cli_strbcasestr(ext, ".db") ||   \
        cli_strbcasestr(ext, ".hdb") ||  \
        cli_strbcasestr(ext, ".hdu") ||  \
        cli_strbcasestr(ext, ".fp") ||   \
        cli_strbcasestr(ext, ".mdb") ||  \
        cli_strbcasestr(ext, ".mdu") ||  \
        cli_strbcasestr(ext, ".hsb") ||  \
        cli_strbcasestr(ext, ".hsu") ||  \
        cli_strbcasestr(ext, ".sfp") ||  \
        cli_strbcasestr(ext, ".msb") ||  \
        cli_strbcasestr(ext, ".msu") ||  \
        cli_strbcasestr(ext, ".ndb") ||  \
        cli_strbcasestr(ext, ".ndu") ||  \
        cli_strbcasestr(ext, ".ldb") ||  \
        cli_strbcasestr(ext, ".ldu") ||  \
        cli_strbcasestr(ext, ".sdb") ||  \
        cli_strbcasestr(ext, ".zmd") ||  \
        cli_strbcasestr(ext, ".rmd") ||  \
        cli_strbcasestr(ext, ".pdb") ||  \
        cli_strbcasestr(ext, ".gdb") ||  \
        cli_strbcasestr(ext, ".wdb") ||  \
        cli_strbcasestr(ext, ".cbc") ||  \
        cli_strbcasestr(ext, ".ftm") ||  \
        cli_strbcasestr(ext, ".cfg") ||  \
        cli_strbcasestr(ext, ".cvd") ||  \
        cli_strbcasestr(ext, ".cld") ||  \
        cli_strbcasestr(ext, ".cud") ||  \
        cli_strbcasestr(ext, ".cdb") ||  \
        cli_strbcasestr(ext, ".cat") ||  \
        cli_strbcasestr(ext, ".crb") ||  \
        cli_strbcasestr(ext, ".idb") ||  \
        cli_strbcasestr(ext, ".ioc") ||  \
        cli_strbcasestr(ext, ".yar") ||  \
        cli_strbcasestr(ext, ".yara") || \
        cli_strbcasestr(ext, ".pwdb") || \
        cli_strbcasestr(ext, ".ign") ||  \
        cli_strbcasestr(ext, ".ign2") || \
        cli_strbcasestr(ext, ".imp"))


#define CLI_LSIG_FLAG_PRIVATE 0x01
#define CLI_LSIG_NORMAL 0
#define CLI_MATCH_CHAR        0x0000
#define CLI_MATCH_IGNORE      0x0100
#define CLI_MATCH_METADATA    0xff00
#define CLI_MATCH_NIBBLE_HIGH 0x0300
#define CLI_MATCH_NIBBLE_LOW  0x0400
#define CLI_MATCH_NOCASE      0x1000
#define CLI_MATCH_SPECIAL     0x0200
#define CLI_MATCH_WILDCARD    0x0f00
#define CLI_MAX_TARGETS 2 
#define CLI_MTARGETS 15
#define CLI_OFF_ABSOLUTE    1
#define CLI_OFF_ANY         0xffffffff
#define CLI_OFF_EOF_MINUS   2
#define CLI_OFF_EP_MINUS    4
#define CLI_OFF_EP_PLUS     3
#define CLI_OFF_MACRO       8
#define CLI_OFF_NONE        0xfffffffe
#define CLI_OFF_SE          9
#define CLI_OFF_SL_PLUS     5
#define CLI_OFF_SX_PLUS     6
#define CLI_OFF_VERSION     7
#define CLI_TDB_FTYPE       4
#define CLI_TDB_FTYPE_EXPR  5
#define CLI_TDB_RANGE       1
#define CLI_TDB_RANGE2      3
#define CLI_TDB_STR         2
#define CLI_TDB_UINT        0
#define CLI_YARA_NORMAL 1
#define CLI_YARA_OFFSET 2

#define CLI_PCREMATCH_NOOFFSETOVERRIDE -1
#define OVECCOUNT 300
#define PCRE2_CODE_UNIT_WIDTH 8

#define CLI_BCOMP_AUTO 0x0008
#define CLI_BCOMP_BE 0x0020
#define CLI_BCOMP_BIN 0x0004
#define CLI_BCOMP_DEC 0x0002
#define CLI_BCOMP_EXACT 0x0100
#define CLI_BCOMP_HEX 0x0001
#define CLI_BCOMP_LE 0x0010
#define CLI_BCOMP_MAX_BIN_BLEN 8
#define CLI_BCOMP_MAX_HEX_BLEN 18

#define CLI_PCRE_DISABLED 0x80000000 
#define CLI_PCRE_ENCOMPASS 0x00000002 
#define CLI_PCRE_GLOBAL 0x00000001    
#define CLI_PCRE_ROLLING 0x00000004   
#define PCRE_BYPASS "7374756c747a676574737265676578"
#define PCRE_SCAN_BUFF 1
#define PCRE_SCAN_FMAP 2
#define PCRE_SCAN_NONE 0

#define CLI_HASHLEN_MAX 32
#define CLI_HASHLEN_MD5 16
#define CLI_HASHLEN_SHA1 20
#define CLI_HASHLEN_SHA256 32

#define STRUCT_PROFILE PROFILE_STRUCT_ PROFILE_STRUCT;

#define cli_htu32_free(A, B) cli_htu32_free(A)
#define cli_htu32_init(A, B, C) cli_htu32_init(A, B)
#define cli_htu32_insert(A, B, C) cli_htu32_insert(A, B)
#define BM_BOUNDARY_EOL 1

#define ACPATT_ALTN_MAXNEST 15
#define ACPATT_OPTION_ASCII 0x08
#define ACPATT_OPTION_FULLWORD 0x02
#define ACPATT_OPTION_NOCASE 0x01
#define ACPATT_OPTION_NOOPTS 0x00
#define ACPATT_OPTION_ONCE 0x80
#define ACPATT_OPTION_WIDE 0x04
#define AC_CH_MAXDIST 32
#define AC_SCAN_FT 2
#define AC_SCAN_VIR 1
#define IS_FINAL(node) (!!node->list)
#define IS_LEAF(node) (!node->trans)


#define WIN_CERT_REV_2 0x0200
#define WIN_CERT_TYPE_PKCS7 0x0002


#define EBOUNDS(fieldname) __attribute__((bounds(fieldname)))
#define __has_feature(x) 0
#define JSON_KEY_FILESIZE "FileSize"
#define JSON_KEY_FILETYPE "FileType"
#define JSON_TIMEOUT_SKIP_CYCLES 3
#define JSON_VALUE_FILETYPE_EXCEL "CL_TYPE_MSXLS"
#define JSON_VALUE_FILETYPE_PDF "CL_TYPE_PDF"
#define JSON_VALUE_FILETYPE_PPT "CL_TYPE_MSPPT"
#define JSON_VALUE_FILETYPE_WORD "CL_TYPE_WORD"

#define cli_json_addowner(o, c, k, i) cli_json_nojson()
#define cli_json_delobj(obj) json_object_put(obj)
#define cli_json_delowner(o, k, i) cli_json_nojson()
#define cli_jsonarray(o, k) cli_jsonarray_nojson(k)
#define cli_jsonbool(o, n, b) cli_jsonbool_nojson(n, b)
#define cli_jsondouble(o, n, d) cli_jsondouble_nojson(n, d)
#define cli_jsonint(o, n, i) cli_jsonint_nojson(n, i)
#define cli_jsonint64(o, n, i) cli_jsonint64_nojson(n, i)
#define cli_jsonint_array(o, v) cli_jsonint_array_nojson(v)
#define cli_jsonnull(o, n) cli_jsonnull_nojson(n)
#define cli_jsonstr(o, n, s) cli_jsonstr_nojson(n, s)
#define cli_jsonstrlen(o, n, s, len) cli_jsonstrlen_nojson(n, s, len)
#define nojson_func cli_dbgmsg






#define lineGetRefCount(line) ((unsigned char)line[0])

#define TABLE_HAS_DELETED_ENTRIES 0x1
