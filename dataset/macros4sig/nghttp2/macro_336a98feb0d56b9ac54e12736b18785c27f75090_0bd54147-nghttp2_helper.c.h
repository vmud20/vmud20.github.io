
#include<assert.h>
#include<stddef.h>
#include<string.h>

#    define STIN static __inline

#define lstreq(A, B, N) ((sizeof((A)) - 1) == (N) && memcmp((A), (B), (N)) == 0)
#define nghttp2_max(A, B) ((A) > (B) ? (A) : (B))
#define nghttp2_min(A, B) ((A) < (B) ? (A) : (B))
#define nghttp2_struct_of(ptr, type, member)                                   \
  ((type *)(void *)((char *)(ptr)-offsetof(type, member)))

