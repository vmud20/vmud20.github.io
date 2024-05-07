
#include<stdbool.h>
#include<zlib.h>


#include<assert.h>
#include<string.h>

#include<time.h>
#include<stdio.h>

#include<stdlib.h>
#include<memory.h>

#include<sys/stat.h>

#include<stdint.h>
#include<utime.h>
#define MOBI_DEBUG 0 
#define calloc(x, y) debug_calloc(x, y, "__FILE__", "__LINE__")
#define debug_print(fmt, ...) { \
    fprintf(stderr, "%s:%d:%s(): " fmt, "__FILE__", \
    "__LINE__", __func__, __VA_ARGS__); \
}
#define free(x) debug_free(x, "__FILE__", "__LINE__")

#define malloc(x) debug_malloc(x, "__FILE__", "__LINE__")
#define realloc(x, y) debug_realloc(x, y, "__FILE__", "__LINE__")
#define MOBI_EXPORT __attribute__((visibility("default"))) __declspec(dllexport) extern
#define MOBI_NOTSET UINT32_MAX


#define CNCX_RECORD_MAXCNT 0xf 
#define INDX_INFLBUF_SIZEMAX 500 
#define INDX_INFLSTRINGS_MAX 500 
#define INDX_INFLTAG_SIZEMAX 25000 
#define INDX_LABEL_SIZEMAX 1000 
#define INDX_NAME_SIZEMAX 0xff
#define INDX_RECORD_MAXCNT 6000 
#define INDX_TAGARR_INFL_GROUPS 5 
#define INDX_TAGARR_INFL_PARTS_V1 7 
#define INDX_TAGARR_INFL_PARTS_V2 26 
#define INDX_TAGARR_ORTH_INFL 42 
#define INDX_TAGVALUES_MAX 100
#define INDX_TAG_FRAG_AID_CNCX (unsigned[]) {2, 0} 
#define INDX_TAG_FRAG_FILE_NR (unsigned[]) {3, 0} 
#define INDX_TAG_FRAG_LENGTH (unsigned[]) {6, 1} 
#define INDX_TAG_FRAG_POSITION (unsigned[]) {6, 0} 
#define INDX_TAG_FRAG_SEQUENCE_NR (unsigned[]) {4, 0} 
#define INDX_TAG_GUIDE_TITLE_CNCX (unsigned[]) {1, 0} 
#define INDX_TAG_NCX_CHILD_END (unsigned[]) {23, 0} 
#define INDX_TAG_NCX_CHILD_START (unsigned[]) {22, 0} 
#define INDX_TAG_NCX_FILEPOS (unsigned[]) {1, 0} 
#define INDX_TAG_NCX_KIND_CNCX (unsigned[]) {5, 0} 
#define INDX_TAG_NCX_LEVEL (unsigned[]) {4, 0} 
#define INDX_TAG_NCX_PARENT (unsigned[]) {21, 0} 
#define INDX_TAG_NCX_POSFID (unsigned[]) {6, 0} 
#define INDX_TAG_NCX_POSOFF (unsigned[]) {6, 1} 
#define INDX_TAG_NCX_TEXT_CNCX (unsigned[]) {3, 0} 
#define INDX_TAG_ORTH_ENDPOS (unsigned[]) {2, 0} 
#define INDX_TAG_ORTH_STARTPOS (unsigned[]) {1, 0} 
#define INDX_TAG_SKEL_COUNT (unsigned[]) {1, 0} 
#define INDX_TAG_SKEL_LENGTH (unsigned[]) {6, 1} 
#define INDX_TAG_SKEL_POSITION (unsigned[]) {6, 0} 
#define INDX_TOTAL_MAXCNT ((size_t) INDX_RECORD_MAXCNT * 0xffff) 
#define ORDT_RECORD_MAXCNT 256 


#define ARRAYSIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define AUDI_MAGIC "AUDI"
#define BOUNDARY_MAGIC "BOUNDARY"
#define CDIC_HEADER_LEN 16
#define CDIC_MAGIC "CDIC"
#define CDIC_RECORD_MAXCNT 1024
#define CMET_MAGIC "CMET"
#define EOF_MAGIC "\xe9\x8e\r\n"
#define EPOCH_MAC_DIFF 2082844800UL
#define EXTH_MAGIC "EXTH"
#define FDST_MAGIC "FDST"
#define FONT_HEADER_LEN 24
#define FONT_MAGIC "FONT"
#define FONT_SIZEMAX (50 * 1024 * 1024)
#define HUFF_CODELEN_MAX 16
#define HUFF_HEADER_LEN 24
#define HUFF_MAGIC "HUFF"
#define HUFF_RECORD_MAXCNT 1024
#define HUFF_RECORD_MINSIZE 2584
#define IDXT_MAGIC "IDXT"
#define INDX_MAGIC "INDX"
#define LIGT_MAGIC "LIGT"
#define MEDIA_HEADER_LEN 12
#define MOBI_HEADER_V2_SIZE 0x18
#define MOBI_HEADER_V3_SIZE 0x74
#define MOBI_HEADER_V4_SIZE 0xd0
#define MOBI_HEADER_V5_SIZE 0xe4
#define MOBI_HEADER_V6_EXT_SIZE 0xe8
#define MOBI_HEADER_V6_SIZE 0xe4
#define MOBI_HEADER_V7_SIZE 0xe4
#define MOBI_MAGIC "MOBI"
#define MOBI_TITLE_SIZEMAX 1024
#define M_OK MZ_OK
#define ORDT_MAGIC "ORDT"
#define PALMDB_APPINFO_DEFAULT 0
#define PALMDB_ATTRIBUTE_DEFAULT 0
#define PALMDB_CREATOR_DEFAULT "MOBI"
#define PALMDB_HEADER_LEN 78 
#define PALMDB_MODNUM_DEFAULT 0
#define PALMDB_NAME_SIZE_MAX 32 
#define PALMDB_NEXTREC_DEFAULT 0
#define PALMDB_RECORD_INFO_SIZE 8 
#define PALMDB_SORTINFO_DEFAULT 0
#define PALMDB_TYPE_DEFAULT "BOOK"
#define PALMDB_VERSION_DEFAULT 0
#define RAWTEXT_SIZEMAX 0xfffffff
#define RECORD0_FULLNAME_SIZE_MAX 1024 
#define RECORD0_HEADER_LEN 16 
#define RECORD0_HUFF_COMPRESSION 17480 
#define RECORD0_MOBI_ENCRYPTION 2 
#define RECORD0_NO_COMPRESSION 1 
#define RECORD0_NO_ENCRYPTION 0 
#define RECORD0_OLD_ENCRYPTION 1 
#define RECORD0_PALMDOC_COMPRESSION 2 
#define RECORD0_TEXT_SIZE_MAX 4096 
#define REPLICA_MAGIC "%MOP"
#define SRCS_MAGIC "SRCS"
#define TAGX_MAGIC "TAGX"
#define UNUSED(x) (void)(x)
#define VIDE_MAGIC "VIDE"

#define m_crc32 mz_crc32
#define m_uncompress mz_uncompress
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define strdup mobi_strdup







#define MAX_MEM_LEVEL         9
#define MAX_WBITS             15
#define MINIZ_HAS_64BIT_REGISTERS 1

#define MINIZ_LITTLE_ENDIAN 1
#define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 1
#define MINIZ_X86_OR_X64_CPU 1
#define MZ_ADLER32_INIT (1)
#define MZ_ASSERT(x) assert(x)
#define MZ_CLEAR_OBJ(obj) memset(&(obj), 0, sizeof(obj))
#define MZ_CRC32_INIT (0)
#define MZ_DEFAULT_WINDOW_BITS 15
#define MZ_DEFLATED 8
#define MZ_DELETE_FILE remove
#define MZ_FALSE (0)
#define MZ_FCLOSE fclose
#define MZ_FFLUSH fflush
#define MZ_FILE void *
#define MZ_FILE_STAT _stat
#define MZ_FILE_STAT_STRUCT _stat
#define MZ_FOPEN mz_fopen
#define MZ_FORCEINLINE __forceinline
#define MZ_FREAD fread
#define MZ_FREE(x) (void)x, ((void)0)
#define MZ_FREOPEN mz_freopen
#define MZ_FSEEK64 _fseeki64
#define MZ_FTELL64 _ftelli64
#define MZ_FWRITE fwrite
#define MZ_MACRO_END while (0, 0)
#define MZ_MALLOC(x) NULL
#define MZ_MAX(a,b) (((a)>(b))?(a):(b))
#define MZ_MIN(a,b) (((a)<(b))?(a):(b))
#define MZ_READ_LE16(p) *((const mz_uint16 *)(p))
#define MZ_READ_LE32(p) *((const mz_uint32 *)(p))
#define MZ_REALLOC(p, x) NULL
#define MZ_SWAP_UINT32(a, b) do { mz_uint32 t = a; a = b; b = t; } MZ_MACRO_END
#define MZ_TOLOWER(c) ((((c) >= 'A') && ((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c))
#define MZ_TRUE (1)
#define MZ_VERNUM           0x91F0
#define MZ_VERSION          "9.1.15"
#define MZ_VER_MAJOR        9
#define MZ_VER_MINOR        1
#define MZ_VER_REVISION     15
#define MZ_VER_SUBREVISION  0
#define MZ_WRITE_LE16(p, v) mz_write_le16((mz_uint8 *)(p), (mz_uint16)(v))
#define MZ_WRITE_LE32(p, v) mz_write_le32((mz_uint8 *)(p), (mz_uint32)(v))
#define MZ_ZIP_ARRAY_ELEMENT(array_ptr, element_type, index) ((element_type *)((array_ptr)->m_p))[index]
#define MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(array_ptr, element_size) (array_ptr)->m_element_size = element_size

#define TDEFL_LESS_MEMORY 0
#define TDEFL_PROBE \
next_probe_pos = d->m_next[probe_pos]; \
if ((!next_probe_pos) || ((dist = (mz_uint16)(lookahead_pos - next_probe_pos)) > max_dist)) return; \
probe_pos = next_probe_pos & TDEFL_LZ_DICT_SIZE_MASK; \
if (TDEFL_READ_UNALIGNED_WORD(&d->m_dict[probe_pos + match_len - 1]) == c01) break;
#define TDEFL_PUT_BITS(b, l) do { \
mz_uint bits = b; mz_uint len = l; MZ_ASSERT(bits <= ((1U << len) - 1U)); \
d->m_bit_buffer |= (bits << d->m_bits_in); d->m_bits_in += len; \
while (d->m_bits_in >= 8) { \
if (d->m_pOutput_buf < d->m_pOutput_buf_end) \
*d->m_pOutput_buf++ = (mz_uint8)(d->m_bit_buffer); \
d->m_bit_buffer >>= 8; \
d->m_bits_in -= 8; \
} \
} MZ_MACRO_END
#define TDEFL_PUT_BITS_FAST(b, l) { bit_buffer |= (((mz_uint64)(b)) << bits_in); bits_in += (l); }
#define TDEFL_READ_UNALIGNED_WORD(p) *(const mz_uint16*)(p)
#define TDEFL_RLE_PREV_CODE_SIZE() { if (rle_repeat_count) { \
if (rle_repeat_count < 3) { \
d->m_huff_count[2][prev_code_size] = (mz_uint16)(d->m_huff_count[2][prev_code_size] + rle_repeat_count); \
while (rle_repeat_count--) packed_code_sizes[num_packed_code_sizes++] = prev_code_size; \
} else { \
d->m_huff_count[2][16] = (mz_uint16)(d->m_huff_count[2][16] + 1); packed_code_sizes[num_packed_code_sizes++] = 16; packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_repeat_count - 3); \
} rle_repeat_count = 0; } }
#define TDEFL_RLE_ZERO_CODE_SIZE() { if (rle_z_count) { \
if (rle_z_count < 3) { \
d->m_huff_count[2][0] = (mz_uint16)(d->m_huff_count[2][0] + rle_z_count); while (rle_z_count--) packed_code_sizes[num_packed_code_sizes++] = 0; \
} else if (rle_z_count <= 10) { \
d->m_huff_count[2][17] = (mz_uint16)(d->m_huff_count[2][17] + 1); packed_code_sizes[num_packed_code_sizes++] = 17; packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_z_count - 3); \
} else { \
d->m_huff_count[2][18] = (mz_uint16)(d->m_huff_count[2][18] + 1); packed_code_sizes[num_packed_code_sizes++] = 18; packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_z_count - 11); \
} rle_z_count = 0; } }
#define TINFL_BITBUF_SIZE (64)
#define TINFL_CR_BEGIN switch(r->m_state) { case 0:
#define TINFL_CR_FINISH }
#define TINFL_CR_RETURN(state_index, result) do { status = result; r->m_state = state_index; goto common_exit; case state_index:; } MZ_MACRO_END
#define TINFL_CR_RETURN_FOREVER(state_index, result) do { for ( ; ; ) { TINFL_CR_RETURN(state_index, result); } } MZ_MACRO_END
#define TINFL_DECOMPRESS_MEM_TO_MEM_FAILED ((size_t)(-1))
#define TINFL_GET_BITS(state_index, b, n) do { if (num_bits < (mz_uint)(n)) { TINFL_NEED_BITS(state_index, n); } b = bit_buf & ((1 << (n)) - 1); bit_buf >>= (n); num_bits -= (n); } MZ_MACRO_END
#define TINFL_GET_BYTE(state_index, c) do { \
if (pIn_buf_cur >= pIn_buf_end) { \
for ( ; ; ) { \
if (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT) { \
TINFL_CR_RETURN(state_index, TINFL_STATUS_NEEDS_MORE_INPUT); \
if (pIn_buf_cur < pIn_buf_end) { \
c = *pIn_buf_cur++; \
break; \
} \
} else { \
c = 0; \
break; \
} \
} \
} else c = *pIn_buf_cur++; } MZ_MACRO_END
#define TINFL_HUFF_BITBUF_FILL(state_index, pHuff) \
do { \
temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]; \
if (temp >= 0) { \
code_len = temp >> 9; \
if ((code_len) && (num_bits >= code_len)) \
break; \
} else if (num_bits > TINFL_FAST_LOOKUP_BITS) { \
code_len = TINFL_FAST_LOOKUP_BITS; \
do { \
temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; \
} while ((temp < 0) && (num_bits >= (code_len + 1))); if (temp >= 0) break; \
} TINFL_GET_BYTE(state_index, c); bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); num_bits += 8; \
} while (num_bits < 15);
#define TINFL_HUFF_DECODE(state_index, sym, pHuff) do { \
int temp; mz_uint code_len, c; \
if (num_bits < 15) { \
if ((pIn_buf_end - pIn_buf_cur) < 2) { \
TINFL_HUFF_BITBUF_FILL(state_index, pHuff); \
} else { \
bit_buf |= (((tinfl_bit_buf_t)pIn_buf_cur[0]) << num_bits) | (((tinfl_bit_buf_t)pIn_buf_cur[1]) << (num_bits + 8)); pIn_buf_cur += 2; num_bits += 16; \
} \
} \
if ((temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0) \
code_len = temp >> 9, temp &= 511; \
else { \
code_len = TINFL_FAST_LOOKUP_BITS; do { temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; } while (temp < 0); \
} sym = temp; bit_buf >>= code_len; num_bits -= code_len; } MZ_MACRO_END
#define TINFL_LZ_DICT_SIZE 32768
#define TINFL_MEMCPY(d, s, l) memcpy(d, s, l)
#define TINFL_MEMSET(p, c, l) memset(p, c, l)
#define TINFL_NEED_BITS(state_index, n) do { mz_uint c; TINFL_GET_BYTE(state_index, c); bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); num_bits += 8; } while (num_bits < (mz_uint)(n))
#define TINFL_SKIP_BITS(state_index, n) do { if (num_bits < (mz_uint)(n)) { TINFL_NEED_BITS(state_index, n); } bit_buf >>= (n); num_bits -= (n); } MZ_MACRO_END
#define TINFL_USE_64BIT_BITBUF 1
#define ZLIB_VERNUM           MZ_VERNUM
#define ZLIB_VERSION          MZ_VERSION
#define ZLIB_VER_MAJOR        MZ_VER_MAJOR
#define ZLIB_VER_MINOR        MZ_VER_MINOR
#define ZLIB_VER_REVISION     MZ_VER_REVISION
#define ZLIB_VER_SUBREVISION  MZ_VER_SUBREVISION
#define Z_BEST_COMPRESSION    MZ_BEST_COMPRESSION
#define Z_BEST_SPEED          MZ_BEST_SPEED
#define Z_BLOCK               MZ_BLOCK
#define Z_BUF_ERROR           MZ_BUF_ERROR
#define Z_DATA_ERROR          MZ_DATA_ERROR
#define Z_DEFAULT_COMPRESSION MZ_DEFAULT_COMPRESSION
#define Z_DEFAULT_STRATEGY    MZ_DEFAULT_STRATEGY
#define Z_DEFAULT_WINDOW_BITS MZ_DEFAULT_WINDOW_BITS
#define Z_DEFLATED            MZ_DEFLATED
#define Z_ERRNO               MZ_ERRNO
#define Z_FILTERED            MZ_FILTERED
#define Z_FINISH              MZ_FINISH
#define Z_FIXED               MZ_FIXED
#define Z_FULL_FLUSH          MZ_FULL_FLUSH
#define Z_HUFFMAN_ONLY        MZ_HUFFMAN_ONLY
#define Z_MEM_ERROR           MZ_MEM_ERROR
#define Z_NEED_DICT           MZ_NEED_DICT
#define Z_NO_COMPRESSION      MZ_NO_COMPRESSION
#define Z_NO_FLUSH            MZ_NO_FLUSH
#define Z_NULL                0
#define Z_OK                  MZ_OK
#define Z_PARAM_ERROR         MZ_PARAM_ERROR
#define Z_PARTIAL_FLUSH       MZ_PARTIAL_FLUSH
#define Z_RLE                 MZ_RLE
#define Z_STREAM_END          MZ_STREAM_END
#define Z_STREAM_ERROR        MZ_STREAM_ERROR
#define Z_SYNC_FLUSH          MZ_SYNC_FLUSH
#define Z_VERSION_ERROR       MZ_VERSION_ERROR
#define adler32               mz_adler32
#define alloc_func            mz_alloc_func
#define compress              mz_compress
#define compress2             mz_compress2
#define compressBound         mz_compressBound
#define crc32                 mz_crc32
#define deflate               mz_deflate
#define deflateBound          mz_deflateBound
#define deflateEnd            mz_deflateEnd
#define deflateInit           mz_deflateInit
#define deflateInit2          mz_deflateInit2
#define deflateReset          mz_deflateReset
#define free_func             mz_free_func
#define inflate               mz_inflate
#define inflateEnd            mz_inflateEnd
#define inflateInit           mz_inflateInit
#define inflateInit2          mz_inflateInit2
#define internal_state        mz_internal_state
#define tinfl_get_adler32(r) (r)->m_check_adler32
#define tinfl_init(r) do { (r)->m_state = 0; } MZ_MACRO_END
#define uncompress            mz_uncompress
#define zError                mz_error
#define z_stream              mz_stream
#define zlibVersion           mz_version
#define zlib_version          mz_version()
#define HUFF_CODETABLE_SIZE 33 
#define MOBI_HUFFMAN_MAXDEPTH 20 
#define MOBI_INLINE 

#define MOBI_EXTH_MAXCNT 1024



