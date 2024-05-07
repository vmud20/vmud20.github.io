



#include<stdarg.h>
#include<string.h>
#include<stdio.h>



#include<stddef.h>
#include<assert.h>




#  define DEBUGF(...) nghttp2_debug_vprintf(__VA_ARGS__)








#define nghttp2_outbound_queue_size(Q) ((Q)->n)
#define nghttp2_outbound_queue_top(Q) ((Q)->head)
#define NGHTTP2_DATA_PAYLOADLEN NGHTTP2_MAX_FRAME_SIZE_MIN
#define NGHTTP2_FRAMEBUF_CHUNKLEN                                              \
  (NGHTTP2_FRAME_HDLEN + 1 + NGHTTP2_MAX_PAYLOADLEN)

#define NGHTTP2_FRAME_HDLEN 9
#define NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH 6
#define NGHTTP2_MAX_FRAME_SIZE_MAX ((1 << 24) - 1)
#define NGHTTP2_MAX_FRAME_SIZE_MIN (1 << 14)
#define NGHTTP2_MAX_HEADERSLEN 65536
#define NGHTTP2_MAX_PADLEN 256
#define NGHTTP2_MAX_PAYLOADLEN 16384
#define NGHTTP2_PRIORITY_MASK ((1u << 31) - 1)
#define NGHTTP2_PRIORITY_SPECLEN 5
#define NGHTTP2_PRI_GROUP_ID_MASK ((1u << 31) - 1)
#define NGHTTP2_SETTINGS_ID_MASK ((1 << 24) - 1)
#define NGHTTP2_STREAM_ID_MASK ((1u << 31) - 1)
#define NGHTTP2_WINDOW_SIZE_INCREMENT_MASK ((1u << 31) - 1)

#define nghttp2_buf_avail(BUF) ((size_t)((BUF)->end - (BUF)->last))
#define nghttp2_buf_cap(BUF) ((size_t)((BUF)->end - (BUF)->begin))
#define nghttp2_buf_last_offset(BUF) ((size_t)((BUF)->last - (BUF)->begin))
#define nghttp2_buf_len(BUF) ((size_t)((BUF)->last - (BUF)->pos))
#define nghttp2_buf_mark_avail(BUF) ((size_t)((BUF)->mark - (BUF)->last))
#define nghttp2_buf_pos_offset(BUF) ((size_t)((BUF)->pos - (BUF)->begin))
#define nghttp2_buf_shift_left(BUF, AMT)                                       \
  do {                                                                         \
    (BUF)->pos -= AMT;                                                         \
    (BUF)->last -= AMT;                                                        \
  } while (0)
#define nghttp2_buf_shift_right(BUF, AMT)                                      \
  do {                                                                         \
    (BUF)->pos += AMT;                                                         \
    (BUF)->last += AMT;                                                        \
  } while (0)
#define nghttp2_bufs_cur_avail(BUFS) nghttp2_buf_avail(&(BUFS)->cur->buf)
#define nghttp2_bufs_fast_addb(BUFS, B)                                        \
  do {                                                                         \
    *(BUFS)->cur->buf.last++ = B;                                              \
  } while (0)
#define nghttp2_bufs_fast_addb_hold(BUFS, B)                                   \
  do {                                                                         \
    *(BUFS)->cur->buf.last = B;                                                \
  } while (0)
#define nghttp2_bufs_fast_orb(BUFS, B)                                         \
  do {                                                                         \
    uint8_t **p = &(BUFS)->cur->buf.last;                                      \
    **p = (uint8_t)(**p | (B));                                                \
    ++(*p);                                                                    \
  } while (0)
#define nghttp2_bufs_fast_orb_hold(BUFS, B)                                    \
  do {                                                                         \
    uint8_t *p = (BUFS)->cur->buf.last;                                        \
    *p = (uint8_t)(*p | (B));                                                  \
  } while (0)
#define nghttp2_bufs_rewind(BUFS)                                              \
  do {                                                                         \
    (BUFS)->cur = (BUFS)->head;                                                \
  } while (0)
#define HD_MAP_SIZE 128
#define NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE NGHTTP2_DEFAULT_HEADER_TABLE_SIZE
#define NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE (1 << 12)
#define NGHTTP2_HD_ENTRY_OVERHEAD 32

#define NGHTTP2_HD_MAX_NV 65536
#define NGHTTP2_STATIC_TABLE_LENGTH 61


#define NGHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 0xffffffffu
#define NGHTTP2_DEFAULT_MAX_OBQ_FLOOD_ITEM 1000
#define NGHTTP2_INBOUND_BUFFER_LENGTH 16384
#define NGHTTP2_MAX_INCOMING_RESERVED_STREAMS 200
#define NGHTTP2_MIN_IDLE_STREAMS 16





#    define STIN static __inline

#define lstreq(A, B, N) ((sizeof((A)) - 1) == (N) && memcmp((A), (B), (N)) == 0)
#define nghttp2_max(A, B) ((A) > (B) ? (A) : (B))
#define nghttp2_min(A, B) ((A) < (B) ? (A) : (B))
#define nghttp2_struct_of(ptr, type, member)                                   \
  ((type *)(void *)((char *)(ptr)-offsetof(type, member)))
