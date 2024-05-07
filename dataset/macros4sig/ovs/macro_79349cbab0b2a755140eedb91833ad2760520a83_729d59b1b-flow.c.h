#include<netinet/ip6.h>
#include<time.h>



#include<netinet/icmp6.h>
#include<string.h>

#include<linux/genetlink.h>


#include<limits.h>

#include<stdio.h>




#include<netinet/in.h>







#include<stdatomic.h>







#include<arpa/inet.h>
#include<stdarg.h>

#include<pthread.h>


#include<stdbool.h>
#include<stddef.h>
#include<smmintrin.h>
#include<stdlib.h>





#include<errno.h>
#include<stdint.h>
#include<linux/types.h>
#include<net/if.h>








#include<sys/socket.h>


#include<threads.h>



#include<inttypes.h>

#include<sys/types.h>



#define NETDEV_NUMA_UNSPEC OVS_NUMA_UNSPEC
#define NETDEV_PROVIDER_H 1
#define SHASH_FOR_EACH(SHASH_NODE, SHASH)                               \
    HMAP_FOR_EACH_INIT (SHASH_NODE, node, &(SHASH)->map,                \
                        BUILD_ASSERT_TYPE(SHASH_NODE, struct shash_node *), \
                        BUILD_ASSERT_TYPE(SHASH, struct shash *))
#define SHASH_FOR_EACH_SAFE(SHASH_NODE, NEXT, SHASH)        \
    HMAP_FOR_EACH_SAFE_INIT (                               \
        SHASH_NODE, NEXT, node, &(SHASH)->map,              \
        BUILD_ASSERT_TYPE(SHASH_NODE, struct shash_node *), \
        BUILD_ASSERT_TYPE(NEXT, struct shash_node *),       \
        BUILD_ASSERT_TYPE(SHASH, struct shash *))
#define SHASH_H 1
#define SHASH_INITIALIZER(SHASH) { HMAP_INITIALIZER(&(SHASH)->map) }
#define ALIGNED_CAST(TYPE, ATTR) ((TYPE) (void *) (ATTR))
#define ARRAY_SIZE(ARRAY) __ARRAY_SIZE(ARRAY)
#define ASSIGN_CONTAINER(OBJECT, POINTER, MEMBER) \
    ((OBJECT) = OBJECT_CONTAINING(POINTER, OBJECT, MEMBER), (void) 0)
#define BITMAP_N_LONGS(N_BITS) DIV_ROUND_UP(N_BITS, BITMAP_ULONG_BITS)
#define BITMAP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)
#define BUILD_ASSERT_TYPE(POINTER, TYPE) \
    ((void) sizeof ((int) ((POINTER) == (TYPE) (POINTER))))
#define CONST_CAST(TYPE, POINTER)                               \
    (BUILD_ASSERT_TYPE(POINTER, TYPE),                          \
     (TYPE) (POINTER))
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) (void *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))
#define INIT_CONTAINER(OBJECT, POINTER, MEMBER) \
    ((OBJECT) = NULL, ASSIGN_CONTAINER(OBJECT, POINTER, MEMBER))
#define IS_POW2(X) ((X) && !((X) & ((X) - 1)))
#define MEMBER_SIZEOF(STRUCT, MEMBER) (sizeof(((STRUCT *) NULL)->MEMBER))
#define OBJECT_CONTAINING(POINTER, OBJECT, MEMBER)                      \
    ((OVS_TYPEOF(OBJECT)) (void *)                                      \
     ((char *) (POINTER) - OBJECT_OFFSETOF(OBJECT, MEMBER)))
#define OBJECT_OFFSETOF(OBJECT, MEMBER) offsetof(typeof(*(OBJECT)), MEMBER)
#define OFFSETOFEND(STRUCT, MEMBER) \
        (offsetof(STRUCT, MEMBER) + MEMBER_SIZEOF(STRUCT, MEMBER))
#define OPENVSWITCH_UTIL_H 1
#define OVS_SAT_MUL(X, Y)                                               \
    ((Y) == 0 ? 0                                                       \
     : (X) <= UINT_MAX / (Y) ? (unsigned int) (X) * (unsigned int) (Y)  \
     : UINT_MAX)
#define OVS_SOURCE_LOCATOR "__FILE__" ":" OVS_STRINGIZE("__LINE__")
#define OVS_STRINGIZE(ARG) OVS_STRINGIZE2(ARG)
#define OVS_STRINGIZE2(ARG) #ARG
#define OVS_TYPEOF(OBJECT) typeof(OBJECT)
#define PADDED_MEMBERS(UNIT, MEMBERS)                               \
    union {                                                         \
        struct { MEMBERS };                                         \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct { MEMBERS }), UNIT)]; \
    }
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)   \
    union {                                                         \
        OVS_CACHE_LINE_MARKER CACHELINE;                            \
        struct { MEMBERS };                                         \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct { MEMBERS }), UNIT)]; \
    }
#define PAD_ID PAD_PASTE(pad, __COUNTER__)
#define PAD_PASTE(x, y) PAD_PASTE2(x, y)
#define PAD_PASTE2(x, y) x##y
#define PAD_SIZE(X, Y) (ROUND_UP(X, Y) - (X))
#define RDP2_1(X) (RDP2_2(X) | (RDP2_2(X) >> 16))
#define RDP2_2(X) (RDP2_3(X) | (RDP2_3(X) >> 8))
#define RDP2_3(X) (RDP2_4(X) | (RDP2_4(X) >> 4))
#define RDP2_4(X) (RDP2_5(X) | (RDP2_5(X) >> 2))
#define RDP2_5(X) (      (X) | (      (X) >> 1))
#define RDP2__(X) (RDP2_1(X) - (RDP2_1(X) >> 1))
#define ROUND_DOWN(X, Y) ((X) / (Y) * (Y))
#define ROUND_DOWN_POW2(X) RDP2__(X)
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))
#define ROUND_UP_POW2(X) RUP2__(X)
#define RUP2_1(X) (RUP2_2(X) | (RUP2_2(X) >> 16))
#define RUP2_2(X) (RUP2_3(X) | (RUP2_3(X) >> 8))
#define RUP2_3(X) (RUP2_4(X) | (RUP2_4(X) >> 4))
#define RUP2_4(X) (RUP2_5(X) | (RUP2_5(X) >> 2))
#define RUP2_5(X) (RUP2_6(X) | (RUP2_6(X) >> 1))
#define RUP2_6(X) ((X) - 1)
#define RUP2__(X) (RUP2_1(X) + 1)
#define ovs_assert(CONDITION)                                           \
    (OVS_LIKELY(CONDITION)                                              \
     ? (void) 0                                                         \
     : ovs_assert_failure(OVS_SOURCE_LOCATOR, __func__, #CONDITION))
#define ETH_ADDR64_C(A,B,C,D,E,F,G,H) \
    { { { 0x##A, 0x##B, 0x##C, 0x##D, 0x##E, 0x##F, 0x##G, 0x##H } } }
#define ETH_ADDR_C(A,B,C,D,E,F) \
    { { { 0x##A, 0x##B, 0x##C, 0x##D, 0x##E, 0x##F } } }
#define ODP_PORT_C(X) ((OVS_FORCE odp_port_t) (X))
#define OFP11_PORT_C(X) ((OVS_FORCE ofp11_port_t) (X))
#define OFP_PORT_C(X) ((OVS_FORCE ofp_port_t) (X))
#define OPENVSWITCH_TYPES_H 1
#define OVS_BE16_MAX ((OVS_FORCE ovs_be16) 0xffff)
#define OVS_BE32_MAX ((OVS_FORCE ovs_be32) 0xffffffff)
#define OVS_BE64_MAX ((OVS_FORCE ovs_be64) 0xffffffffffffffffULL)
#define OVS_BITWISE __attribute__((bitwise))
#define OVS_FORCE __attribute__((force))
#define OVS_U128_ZERO OVS_U128_MIN
#define BUILD_ASSERT BOOST_STATIC_ASSERT
#define BUILD_ASSERT_DECL BOOST_STATIC_ASSERT
#define BUILD_ASSERT_DECL_GCCONLY(EXPR) BUILD_ASSERT_DECL(EXPR)
#define BUILD_ASSERT_GCCONLY(EXPR) BUILD_ASSERT(EXPR)
#define BUILD_ASSERT__(EXPR) \
        sizeof(struct { unsigned int build_assert_failed : (EXPR) ? 1 : -1; })
#define CCALL __cdecl

#define OPENVSWITCH_COMPILER_H 1
#define OVS_ACQUIRES(...) \
    __attribute__((exclusive_lock_function(__VA_ARGS__)))
#define OVS_ACQ_AFTER(...) __attribute__((acquired_after(__VA_ARGS__)))
#define OVS_ACQ_BEFORE(...) __attribute__((acquired_before(__VA_ARGS__)))
#define OVS_ACQ_RDLOCK(...) __attribute__((shared_lock_function(__VA_ARGS__)))
#define OVS_ACQ_WRLOCK(...) \
    __attribute__((exclusive_lock_function(__VA_ARGS__)))
#define OVS_ALIGNED_STRUCT(N, TAG) struct __attribute__((aligned(N))) TAG
#define OVS_ALIGNED_VAR(N) __attribute__((aligned(N)))
#define OVS_CONSTRUCTOR(f) \
    static void __cdecl f(void); \
    __declspec(allocate(".CRT$XCU")) static void (__cdecl*f##_)(void) = f; \
    static void __cdecl f(void)
#define OVS_EXCLUDED(...) __attribute__((locks_excluded(__VA_ARGS__)))
#define OVS_GUARDED __attribute__((guarded_var))
#define OVS_GUARDED_BY(...) __attribute__((guarded_by(__VA_ARGS__)))
#define OVS_LIKELY(CONDITION) __builtin_expect(!!(CONDITION), 1)
#define OVS_LOCKABLE __attribute__((lockable))
#define OVS_NO_RETURN __attribute__((__noreturn__))
#define OVS_NO_THREAD_SAFETY_ANALYSIS \
    __attribute__((no_thread_safety_analysis))
#define OVS_PACKED(DECL) DECL __attribute__((__packed__))
#define OVS_PACKED_ENUM __attribute__((__packed__))
#define OVS_PREFETCH(addr) __builtin_prefetch((addr))
#define OVS_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1)
#define OVS_PRINTF_FORMAT(FMT, ARG1) __attribute__((__format__(printf, FMT, ARG1)))
#define OVS_RELEASES(...) __attribute__((unlock_function(__VA_ARGS__)))
#define OVS_REQUIRES(...) \
    __attribute__((exclusive_locks_required(__VA_ARGS__)))
#define OVS_REQ_RDLOCK(...) __attribute__((shared_locks_required(__VA_ARGS__)))
#define OVS_REQ_WRLOCK(...) \
    __attribute__((exclusive_locks_required(__VA_ARGS__)))
#define OVS_SCANF_FORMAT(FMT, ARG1) __attribute__((__format__(scanf, FMT, ARG1)))
#define OVS_TRY_LOCK(RETVAL, ...)                                \
    __attribute__((exclusive_trylock_function(RETVAL, __VA_ARGS__)))
#define OVS_TRY_RDLOCK(RETVAL, ...)                          \
    __attribute__((shared_trylock_function(RETVAL, __VA_ARGS__)))
#define OVS_TRY_WRLOCK(RETVAL, ...)                              \
    __attribute__((exclusive_trylock_function(RETVAL, __VA_ARGS__)))
#define OVS_UNLIKELY(CONDITION) __builtin_expect(!!(CONDITION), 0)
#define OVS_UNUSED __attribute__((__unused__))
#define OVS_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
  #define __has_extension(x) 0
  #define __has_feature(x) 0
#define offsetof(type, member) \
    ((size_t)((char *)&(((type *)0)->member) - (char *)0))
#define HMAP_CONST(HMAP, N, NODE) {                                 \
        CONST_CAST(struct hmap_node **, &(HMAP)->one), NODE, 0, N }
#define HMAP_FOR_EACH(NODE, MEMBER, HMAP) \
    HMAP_FOR_EACH_INIT(NODE, MEMBER, HMAP, (void) 0)
#define HMAP_FOR_EACH_CONTINUE(NODE, MEMBER, HMAP) \
    HMAP_FOR_EACH_CONTINUE_INIT(NODE, MEMBER, HMAP, (void) 0)
#define HMAP_FOR_EACH_CONTINUE_INIT(NODE, MEMBER, HMAP, ...)            \
    for (ASSIGN_CONTAINER(NODE, hmap_next(HMAP, &(NODE)->MEMBER), MEMBER), \
         __VA_ARGS__;                                                   \
         (NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER))                \
         || ((NODE = NULL), false);                                     \
         ASSIGN_CONTAINER(NODE, hmap_next(HMAP, &(NODE)->MEMBER), MEMBER))
#define HMAP_FOR_EACH_INIT(NODE, MEMBER, HMAP, ...)                     \
    for (INIT_CONTAINER(NODE, hmap_first(HMAP), MEMBER), __VA_ARGS__;   \
         (NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER))                \
         || ((NODE = NULL), false);                                     \
         ASSIGN_CONTAINER(NODE, hmap_next(HMAP, &(NODE)->MEMBER), MEMBER))
#define HMAP_FOR_EACH_IN_BUCKET(NODE, MEMBER, HASH, HMAP)               \
    for (INIT_CONTAINER(NODE, hmap_first_in_bucket(HMAP, HASH), MEMBER); \
         (NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER))                \
         || ((NODE = NULL), false);                                     \
         ASSIGN_CONTAINER(NODE, hmap_next_in_bucket(&(NODE)->MEMBER), MEMBER))
#define HMAP_FOR_EACH_POP(NODE, MEMBER, HMAP)                               \
    for (size_t bucket__ = 0;                                               \
         INIT_CONTAINER(NODE, hmap_pop_helper__(HMAP, &bucket__), MEMBER),  \
         (NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER))                    \
         || ((NODE = NULL), false);)
#define HMAP_FOR_EACH_SAFE(NODE, NEXT, MEMBER, HMAP) \
    HMAP_FOR_EACH_SAFE_INIT(NODE, NEXT, MEMBER, HMAP, (void) 0)
#define HMAP_FOR_EACH_SAFE_INIT(NODE, NEXT, MEMBER, HMAP, ...)          \
    for (INIT_CONTAINER(NODE, hmap_first(HMAP), MEMBER), __VA_ARGS__;   \
         ((NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER))               \
          || ((NODE = NULL), false)                                     \
          ? INIT_CONTAINER(NEXT, hmap_next(HMAP, &(NODE)->MEMBER), MEMBER), 1 \
          : 0);                                                         \
         (NODE) = (NEXT))
#define HMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, HMAP)               \
    for (INIT_CONTAINER(NODE, hmap_first_with_hash(HMAP, HASH), MEMBER); \
         (NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER))                \
         || ((NODE = NULL), false);                                     \
         ASSIGN_CONTAINER(NODE, hmap_next_with_hash(&(NODE)->MEMBER),   \
                          MEMBER))
#define HMAP_H 1
#define HMAP_INITIALIZER(HMAP) \
    { (struct hmap_node **const) &(HMAP)->one, NULL, 0, 0 }
#define HMAP_NODE_NULL ((struct hmap_node *) 1)
#define HMAP_NODE_NULL_INITIALIZER { 0, HMAP_NODE_NULL }
#define hmap_expand(HMAP) hmap_expand_at(HMAP, OVS_SOURCE_LOCATOR)
#define hmap_insert(HMAP, NODE, HASH) \
    hmap_insert_at(HMAP, NODE, HASH, OVS_SOURCE_LOCATOR)
#define hmap_reserve(HMAP, CAPACITY) \
    hmap_reserve_at(HMAP, CAPACITY, OVS_SOURCE_LOCATOR)
#define hmap_shrink(HMAP) hmap_shrink_at(HMAP, OVS_SOURCE_LOCATOR)
#define LIST_FOR_EACH(ITER, MEMBER, LIST)                               \
    for (INIT_CONTAINER(ITER, (LIST)->next, MEMBER);                    \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.next, MEMBER))
#define LIST_FOR_EACH_CONTINUE(ITER, MEMBER, LIST)                      \
    for (ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.next, MEMBER);             \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.next, MEMBER))
#define LIST_FOR_EACH_POP(ITER, MEMBER, LIST)                      \
    while (!ovs_list_is_empty(LIST)                                    \
           && (INIT_CONTAINER(ITER, ovs_list_pop_front(LIST), MEMBER), 1))
#define LIST_FOR_EACH_REVERSE(ITER, MEMBER, LIST)                       \
    for (INIT_CONTAINER(ITER, (LIST)->prev, MEMBER);                    \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER))
#define LIST_FOR_EACH_REVERSE_CONTINUE(ITER, MEMBER, LIST)              \
    for (ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER);           \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER))
#define LIST_FOR_EACH_REVERSE_SAFE(ITER, PREV, MEMBER, LIST)        \
    for (INIT_CONTAINER(ITER, (LIST)->prev, MEMBER);                \
         (&(ITER)->MEMBER != (LIST)                                 \
          ? INIT_CONTAINER(PREV, (ITER)->MEMBER.prev, MEMBER), 1    \
          : 0);                                                     \
         (ITER) = (PREV))
#define LIST_FOR_EACH_SAFE(ITER, NEXT, MEMBER, LIST)               \
    for (INIT_CONTAINER(ITER, (LIST)->next, MEMBER);               \
         (&(ITER)->MEMBER != (LIST)                                \
          ? INIT_CONTAINER(NEXT, (ITER)->MEMBER.next, MEMBER), 1   \
          : 0);                                                    \
         (ITER) = (NEXT))
#define OPENVSWITCH_LIST_H 1
#define OVS_LIST_INITIALIZER(LIST) { LIST, LIST }
#define OVS_TNL_ROUTER_H 1
#define CACHE_LINE_SIZE 64
#define INT_MOD_GEQ(a,b)    ((int) ((a)-(b)) >= 0)
#define INT_MOD_GT(a,b)     ((int) ((a)-(b)) > 0)
#define INT_MOD_LEQ(a,b)    ((int) ((a)-(b)) <= 0)
#define INT_MOD_LT(a,b)     ((int) ((a)-(b)) < 0)
#define INT_MOD_MAX(a, b)   ((INT_MOD_GT(a, b)) ? (a) : (b))
#define INT_MOD_MIN(a, b)   ((INT_MOD_LT(a, b)) ? (a) : (b))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define NEED_COUNT_1BITS_8 1
#define OVS_NOT_REACHED() abort()
#define PRIXSIZE "IX"
#define PRIdSIZE "Id"
#define PRIiSIZE "Ii"
#define PRIoSIZE "Io"
#define PRIuSIZE "Iu"
#define PRIxSIZE "Ix"
#define UTIL_H 1
#define __ARRAY_CHECK(ARRAY) 					\
    !__builtin_types_compatible_p(typeof(ARRAY), typeof(&ARRAY[0]))
#define __ARRAY_FAIL(ARRAY) (sizeof(char[-2*!__ARRAY_CHECK(ARRAY)]))
#define __ARRAY_SIZE(ARRAY)					\
    __builtin_choose_expr(__ARRAY_CHECK(ARRAY),			\
        __ARRAY_SIZE_NOCHECK(ARRAY), __ARRAY_FAIL(ARRAY))
#define __ARRAY_SIZE_NOCHECK(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))
#define ovs_strlcpy_arrays(DST, SRC) \
    ovs_strlcpy(DST, SRC, MIN(ARRAY_SIZE(DST), ARRAY_SIZE(SRC)))
#define set_program_name(name) \
        ovs_set_program_name(name, OVS_PACKAGE_VERSION)
#define ALWAYS_INLINE __attribute__((always_inline))
#define BUILD_MESSAGE(x) \
    DO_PRAGMA(message(x))
#define COMPILER_H 1
#define DO_PRAGMA(x) _Pragma(#x)
#define MALLOC_LIKE __attribute__((__malloc__))
#define SENTINEL(N) __attribute__((sentinel(N)))
#define STRFTIME_FORMAT(FMT) __attribute__((__format__(__strftime__, FMT, 0)))
#define NSH_BASE_HDR_LEN  8
#define NSH_CTX_HDRS_MAX_LEN 244
#define NSH_FLAGS_MASK     0x3000
#define NSH_FLAGS_SHIFT    12
#define NSH_HDR_MAX_LEN 252
#define NSH_LEN_MASK       0x003f
#define NSH_LEN_SHIFT      0
#define NSH_MDTYPE_MASK    0x0f
#define NSH_MDTYPE_SHIFT   0
#define NSH_M_EXP1      0xFE
#define NSH_M_EXP2      0xFF
#define NSH_M_TYPE1     0x01
#define NSH_M_TYPE1_LEN   24
#define NSH_M_TYPE1_MDLEN 16
#define NSH_M_TYPE2     0x02
#define NSH_P_ETHERNET    0x03
#define NSH_P_IPV4        0x01
#define NSH_P_IPV6        0x02
#define NSH_P_MPLS        0x05
#define NSH_P_NSH         0x04
#define NSH_SI_MASK        0x000000ff
#define NSH_SI_SHIFT       0
#define NSH_SPI_MASK       0xffffff00
#define NSH_SPI_SHIFT      8
#define NSH_TTL_MASK       0x0fc0
#define NSH_TTL_SHIFT      6
#define NSH_VER_MASK       0xc000
#define NSH_VER_SHIFT      14
#define __OPENVSWITCH_NSH_H 1
#define GCC_UNALIGNED_ACCESSORS(TYPE, ABBREV)   \
struct unaligned_##ABBREV {                     \
    TYPE x __attribute__((__packed__));         \
};                                              \
static inline struct unaligned_##ABBREV *       \
unaligned_##ABBREV(const TYPE *p)               \
{                                               \
    return (struct unaligned_##ABBREV *) p;     \
}                                               \
                                                \
static inline TYPE                              \
get_unaligned_##ABBREV(const TYPE *p)           \
{                                               \
    return unaligned_##ABBREV(p)->x;            \
}                                               \
                                                \
static inline void                              \
put_unaligned_##ABBREV(TYPE *p, TYPE x)         \
{                                               \
    unaligned_##ABBREV(p)->x = x;               \
}
#define UNALIGNED_H 1
#define get_unaligned_be16 get_unaligned_u16
#define get_unaligned_be32 get_unaligned_u32
#define get_unaligned_u64(P)                                \
    (BUILD_ASSERT(sizeof *(P) == 8),                        \
     BUILD_ASSERT_GCCONLY(!TYPE_IS_SIGNED(typeof(*(P)))),   \
     (void) sizeof (*(P) % 1),                              \
     get_unaligned_u64__((const uint64_t *) (P)))
#define put_unaligned_be16 put_unaligned_u16
#define put_unaligned_be32 put_unaligned_u32
#define put_unaligned_be64 put_unaligned_u64
#define INT_STRLEN(TYPE) (TYPE_IS_SIGNED(TYPE) + TYPE_VALUE_BITS(TYPE) / 3 + 1)
#define OPENVSWITCH_TYPE_PROPS_H 1
#define TYPE_IS_BOOL(TYPE) ((TYPE) 1 == (TYPE) 2)
#define TYPE_IS_INTEGER(TYPE) ((TYPE) 1.5 == (TYPE) 1)
#define TYPE_IS_SIGNED(TYPE) ((TYPE) 1 > (TYPE) -1)
#define TYPE_MAXIMUM(TYPE) \
    ((((TYPE)1 << (TYPE_VALUE_BITS(TYPE) - 1)) - 1) * 2 + 1)
#define TYPE_MINIMUM(TYPE) (TYPE_IS_SIGNED(TYPE) ? -TYPE_MAXIMUM(TYPE) - 1 : 0)
#define TYPE_VALUE_BITS(TYPE) \
    (TYPE_IS_BOOL(TYPE) ? 1 : sizeof(TYPE) * CHAR_BIT - TYPE_IS_SIGNED(TYPE))
#define BYTE_ORDER_H 1
#define CONSTANT_HTONL(VALUE) ((OVS_FORCE ovs_be32) ((VALUE) & 0xffffffff))
#define CONSTANT_HTONLL(VALUE) \
        ((OVS_FORCE ovs_be64) ((VALUE) & UINT64_C(0xffffffffffffffff)))
#define CONSTANT_HTONS(VALUE) ((OVS_FORCE ovs_be16) ((VALUE) & 0xffff))
#define RANDOM_H 1
#define ATTR_LEN_INVALID  -1
#define ATTR_LEN_NESTED   -3
#define ATTR_LEN_VARIABLE -2
#define ODPP_LOCAL ODP_PORT_C(OVSP_LOCAL)
#define ODPP_NONE  ODP_PORT_C(UINT32_MAX)
#define ODPUTIL_FLOW_KEY_BYTES 640
#define ODP_SUPPORT_FIELD(TYPE, NAME, TITLE) TYPE NAME;
#define ODP_SUPPORT_FIELDS                                                   \
          \
    ODP_SUPPORT_FIELD(size_t, max_vlan_headers, "Max VLAN headers")          \
     \
    ODP_SUPPORT_FIELD(size_t, max_mpls_depth, "Max MPLS depth")              \
                                                            \
    ODP_SUPPORT_FIELD(bool, recirc, "Recirc")                                \
        \
    ODP_SUPPORT_FIELD(bool, ct_state, "CT state")                            \
    ODP_SUPPORT_FIELD(bool, ct_zone, "CT zone")                              \
    ODP_SUPPORT_FIELD(bool, ct_mark, "CT mark")                              \
    ODP_SUPPORT_FIELD(bool, ct_label, "CT label")                            \
                                                                             \
                                                          \
    ODP_SUPPORT_FIELD(bool, ct_state_nat, "CT state NAT")                    \
                                                                             \
               \
    ODP_SUPPORT_FIELD(bool, ct_orig_tuple, "CT orig tuple")                  \
    ODP_SUPPORT_FIELD(bool, ct_orig_tuple6, "CT orig tuple for IPv6")        \
                                                                             \
                                              \
    ODP_SUPPORT_FIELD(bool, nd_ext, "IPv6 ND Extension")
#define ODP_UTIL_H 1
#define SLOW_PATH_REASONS                                               \
    SPR(SLOW_CFM,        "cfm",        "Consists of CFM packets")       \
    SPR(SLOW_BFD,        "bfd",        "Consists of BFD packets")       \
    SPR(SLOW_LACP,       "lacp",       "Consists of LACP packets")      \
    SPR(SLOW_STP,        "stp",        "Consists of STP packets")       \
    SPR(SLOW_LLDP,       "lldp",       "Consists of LLDP packets")      \
    SPR(SLOW_ACTION,     "action",                                      \
        "Uses action(s) not supported by datapath")                     \
    SPR(SLOW_MATCH,      "match",                                       \
        "Datapath can't match specifically enough")
#define SPR(ENUM, STRING, EXPLANATION) ENUM##_INDEX,
#define OPENFLOW_OPENFLOW_H 1
#define OPENFLOW_15_H 1
#define DESC_STR_LEN   256
#define HPL_VENDOR_ID   0x000004EA 
#define INTEL_VENDOR_ID 0x0000AA01 
#define NTR_COMPAT_VENDOR_ID   0x00001540 
#define NTR_VENDOR_ID   0x0000154d 
#define NX_VENDOR_ID    0x00002320 
#define OFPPR_BITS ((1u << OFPPR_ADD) |         \
                    (1u << OFPPR_DELETE) |      \
                    (1u << OFPPR_MODIFY))
#define OFPR10_BITS                                                     \
    ((1u << OFPR_NO_MATCH) | (1u << OFPR_ACTION) | (1u << OFPR_INVALID_TTL))
#define OFPR14_ACTION_BITS                                              \
    ((1u << OFPR_ACTION_SET) | (1u << OFPR_GROUP) | (1u << OFPR_PACKET_OUT))
#define OFPR14_BITS                                                     \
    (OFPR10_BITS | OFPR14_ACTION_BITS)
#define OFPRR10_BITS                            \
    ((1u << OFPRR_IDLE_TIMEOUT) |               \
     (1u << OFPRR_HARD_TIMEOUT) |               \
     (1u << OFPRR_DELETE))
#define OFPRR13_BITS                            \
    (OFPRR10_BITS |                             \
     (1u << OFPRR_GROUP_DELETE))
#define OFPRR14_BITS                            \
    (OFPRR13_BITS |                             \
     (1u << OFPRR_METER_DELETE) |               \
     (1u << OFPRR_EVICTION))
#define OFP_ASSERT BOOST_STATIC_ASSERT
#define OFP_DEFAULT_MISS_SEND_LEN   128
#define OFP_DEFAULT_PRIORITY 0x8000
#define OFP_DL_TYPE_ETH2_CUTOFF   0x0600
#define OFP_DL_TYPE_NOT_ETH_TYPE  0x05ff
#define OFP_FLOW_PERMANENT 0
#define OFP_MAX_PORT_NAME_LEN  16
#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_OLD_PORT  6633
#define OFP_PORT  6653
#define OF_VENDOR_ID    0
#define ONF_VENDOR_ID   0x4f4e4600 
#define OPENFLOW_COMMON_H 1
#define SERIAL_NUM_LEN 32
#define OFPTR_BITS ((1u << OFPTR_VACANCY_DOWN) | (1u << OFPTR_VACANCY_UP))
#define OPENFLOW_14_H 1
#define OFPTFPT13_REQUIRED ((1u << OFPTFPT13_INSTRUCTIONS) |    \
                            (1u << OFPTFPT13_NEXT_TABLES) |     \
                            (1u << OFPTFPT13_WRITE_ACTIONS) |   \
                            (1u << OFPTFPT13_APPLY_ACTIONS) |   \
                            (1u << OFPTFPT13_MATCH) |           \
                            (1u << OFPTFPT13_WILDCARDS) |       \
                            (1u << OFPTFPT13_WRITE_SETFIELD) |  \
                            (1u << OFPTFPT13_APPLY_SETFIELD))
#define OPENFLOW_13_H 1
#define OFPET12_EXPERIMENTER 0xffff
#define OFPGT12_N_TYPES 4
#define OPENFLOW_12_H 1
#define OFP11_INSTRUCTION_ALIGN 8
#define OFPMT11_STANDARD_LENGTH 88
#define OFPP11_MAX    OFP11_PORT_C(0xffffff00)
#define OFPP11_OFFSET 0xffff0000    
#define OFPPC11_ALL \
    (OFPPC_PORT_DOWN | OFPPC_NO_RECV | OFPPC_NO_FWD | OFPPC_NO_PACKET_IN)
#define OFPPF11_ALL ((1 << 16) - 1)
#define OFPPS11_ALL (OFPPS_LINK_DOWN | OFPPS11_BLOCKED | OFPPS11_LIVE)
#define OFPP_ANY OFPP_NONE
#define OPENFLOW_11_H 1
#define OFP10_VLAN_NONE      0xffff
#define OFPFW10_ICMP_CODE OFPFW10_TP_DST
#define OFPFW10_ICMP_TYPE OFPFW10_TP_SRC
#define OFPPC10_ALL (OFPPC_PORT_DOWN | OFPPC10_NO_STP | OFPPC_NO_RECV | \
                     OFPPC10_NO_RECV_STP | OFPPC10_NO_FLOOD | OFPPC_NO_FWD | \
                     OFPPC_NO_PACKET_IN)
#define OFPPS10_ALL (OFPPS_LINK_DOWN | OFPPS10_STP_MASK)
#define OFPP_ALL        OFP_PORT_C(0xfffc) 
#define OFPP_CONTROLLER OFP_PORT_C(0xfffd) 
#define OFPP_FIRST_RESV OFP_PORT_C(0xfff7) 
#define OFPP_FLOOD      OFP_PORT_C(0xfffb) 
#define OFPP_IN_PORT    OFP_PORT_C(0xfff8) 
#define OFPP_LAST_RESV  OFP_PORT_C(0xffff) 
#define OFPP_LOCAL      OFP_PORT_C(0xfffe) 
#define OFPP_MAX        OFP_PORT_C(0xff00) 
#define OFPP_NONE       OFP_PORT_C(0xffff) 
#define OFPP_NORMAL     OFP_PORT_C(0xfffa) 
#define OFPP_TABLE      OFP_PORT_C(0xfff9) 
#define OFPP_UNSET      OFP_PORT_C(0xfff7) 
#define OFPQ_ALL      0xffffffff
#define OPENFLOW_OPENFLOW10_H 1
#define OPENVSWITCH_UUID_H 1
#define UUID_BIT 128            
#define UUID_OCTET (UUID_BIT / 8) 
#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME) OVSINST_##ENUM,
#define IPPORT_FTP  21
#define IPPORT_TFTP  69
#define MAX_OFPACT_PARSE_DEPTH 100
#define NX_CTLR_NO_METER 0
#define NX_CT_RECIRC_NONE OFPTT_ALL
#define NX_LEARN_DST_LOAD      (1 << 11) 
#define NX_LEARN_DST_MASK      (3 << 11)
#define NX_LEARN_DST_MATCH     (0 << 11) 
#define NX_LEARN_DST_OUTPUT    (2 << 11) 
#define NX_LEARN_DST_RESERVED  (3 << 11) 
#define NX_LEARN_N_BITS_MASK    0x3ff
#define NX_LEARN_SRC_FIELD     (0 << 13) 
#define NX_LEARN_SRC_IMMEDIATE (1 << 13) 
#define NX_LEARN_SRC_MASK      (1 << 13)
#define OFPACT(ENUM, STRUCT, MEMBER, NAME)                              \
    BUILD_ASSERT_DECL(offsetof(struct STRUCT, ofpact) == 0);            \
                                                                        \
     \
    BUILD_ASSERT_DECL(sizeof(struct STRUCT) % OFPACT_ALIGNTO == 0);     \
                                                                        \
                                                            \
    BUILD_ASSERT_DECL(offsetof(struct STRUCT, MEMBER)                   \
                      % OFPACT_ALIGNTO == 0);                           \
                                                                        \
                                                        \
    BUILD_ASSERT_DECL(!offsetof(struct STRUCT, MEMBER)                  \
                      || (offsetof(struct STRUCT, MEMBER)               \
                          == sizeof(struct STRUCT)));                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_get_##ENUM(const struct ofpact *ofpact)                      \
    {                                                                   \
        ovs_assert(ofpact->type == OFPACT_##ENUM);                      \
        return ALIGNED_CAST(struct STRUCT *, ofpact);                   \
    }                                                                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_get_##ENUM##_nullable(const struct ofpact *ofpact)           \
    {                                                                   \
        ovs_assert(!ofpact || ofpact->type == OFPACT_##ENUM);           \
        return ALIGNED_CAST(struct STRUCT *, ofpact);                   \
    }                                                                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_put_##ENUM(struct ofpbuf *ofpacts)                           \
    {                                                                   \
        return (struct STRUCT *) ofpact_put(ofpacts, OFPACT_##ENUM,     \
                                            sizeof(struct STRUCT));     \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    ofpact_init_##ENUM(struct STRUCT *ofpact)                           \
    {                                                                   \
        ofpact_init(&ofpact->ofpact, OFPACT_##ENUM,                     \
                    sizeof(struct STRUCT));                             \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    ofpact_finish_##ENUM(struct ofpbuf *ofpbuf, struct STRUCT **ofpactp) \
    {                                                                   \
        struct ofpact *ofpact = &(*ofpactp)->ofpact;                    \
        ovs_assert(ofpact->type == OFPACT_##ENUM);                      \
        *ofpactp = (struct STRUCT *) ofpact_finish(ofpbuf, ofpact);     \
    }
#define OFPACTS                                                         \
                                                           \
    OFPACT(OUTPUT,          ofpact_output,      ofpact, "output")       \
    OFPACT(GROUP,           ofpact_group,       ofpact, "group")        \
    OFPACT(CONTROLLER,      ofpact_controller,  userdata, "controller") \
    OFPACT(ENQUEUE,         ofpact_enqueue,     ofpact, "enqueue")      \
    OFPACT(OUTPUT_REG,      ofpact_output_reg,  ofpact, "output_reg")   \
    OFPACT(BUNDLE,          ofpact_bundle,      members, "bundle")      \
                                                                        \
                                                   \
    OFPACT(SET_FIELD,       ofpact_set_field,   ofpact, "set_field")    \
    OFPACT(SET_VLAN_VID,    ofpact_vlan_vid,    ofpact, "set_vlan_vid") \
    OFPACT(SET_VLAN_PCP,    ofpact_vlan_pcp,    ofpact, "set_vlan_pcp") \
    OFPACT(STRIP_VLAN,      ofpact_null,        ofpact, "strip_vlan")   \
    OFPACT(PUSH_VLAN,       ofpact_push_vlan,   ofpact, "push_vlan")    \
    OFPACT(SET_ETH_SRC,     ofpact_mac,         ofpact, "mod_dl_src")   \
    OFPACT(SET_ETH_DST,     ofpact_mac,         ofpact, "mod_dl_dst")   \
    OFPACT(SET_IPV4_SRC,    ofpact_ipv4,        ofpact, "mod_nw_src")   \
    OFPACT(SET_IPV4_DST,    ofpact_ipv4,        ofpact, "mod_nw_dst")   \
    OFPACT(SET_IP_DSCP,     ofpact_dscp,        ofpact, "mod_nw_tos")   \
    OFPACT(SET_IP_ECN,      ofpact_ecn,         ofpact, "mod_nw_ecn")   \
    OFPACT(SET_IP_TTL,      ofpact_ip_ttl,      ofpact, "mod_nw_ttl")   \
    OFPACT(SET_L4_SRC_PORT, ofpact_l4_port,     ofpact, "mod_tp_src")   \
    OFPACT(SET_L4_DST_PORT, ofpact_l4_port,     ofpact, "mod_tp_dst")   \
    OFPACT(REG_MOVE,        ofpact_reg_move,    ofpact, "move")         \
    OFPACT(STACK_PUSH,      ofpact_stack,       ofpact, "push")         \
    OFPACT(STACK_POP,       ofpact_stack,       ofpact, "pop")          \
    OFPACT(DEC_TTL,         ofpact_cnt_ids,     cnt_ids, "dec_ttl")     \
    OFPACT(SET_MPLS_LABEL,  ofpact_mpls_label,  ofpact, "set_mpls_label") \
    OFPACT(SET_MPLS_TC,     ofpact_mpls_tc,     ofpact, "set_mpls_tc")  \
    OFPACT(SET_MPLS_TTL,    ofpact_mpls_ttl,    ofpact, "set_mpls_ttl") \
    OFPACT(DEC_MPLS_TTL,    ofpact_null,        ofpact, "dec_mpls_ttl") \
    OFPACT(PUSH_MPLS,       ofpact_push_mpls,   ofpact, "push_mpls")    \
    OFPACT(POP_MPLS,        ofpact_pop_mpls,    ofpact, "pop_mpls")     \
    OFPACT(DEC_NSH_TTL,     ofpact_null,        ofpact, "dec_nsh_ttl")  \
    OFPACT(DELETE_FIELD,    ofpact_delete_field, ofpact, "delete_field") \
                                                                        \
                                             \
    OFPACT(ENCAP,           ofpact_encap,       props, "encap")         \
    OFPACT(DECAP,           ofpact_decap,       ofpact, "decap")        \
                                                                        \
                                                         \
    OFPACT(SET_TUNNEL,      ofpact_tunnel,      ofpact, "set_tunnel")   \
    OFPACT(SET_QUEUE,       ofpact_queue,       ofpact, "set_queue")    \
    OFPACT(POP_QUEUE,       ofpact_null,        ofpact, "pop_queue")    \
    OFPACT(FIN_TIMEOUT,     ofpact_fin_timeout, ofpact, "fin_timeout")  \
                                                                        \
                                           \
    OFPACT(RESUBMIT,        ofpact_resubmit,    ofpact, "resubmit")     \
    OFPACT(LEARN,           ofpact_learn,       specs, "learn")         \
    OFPACT(CONJUNCTION,     ofpact_conjunction, ofpact, "conjunction")  \
                                                                        \
                                                       \
    OFPACT(MULTIPATH,       ofpact_multipath,   ofpact, "multipath")    \
                                                                        \
                                                            \
    OFPACT(NOTE,            ofpact_note,        data, "note")           \
    OFPACT(EXIT,            ofpact_null,        ofpact, "exit")         \
    OFPACT(SAMPLE,          ofpact_sample,      ofpact, "sample")       \
    OFPACT(UNROLL_XLATE,    ofpact_unroll_xlate, ofpact, "unroll_xlate") \
    OFPACT(CT,              ofpact_conntrack,   ofpact, "ct")           \
    OFPACT(CT_CLEAR,        ofpact_null,        ofpact, "ct_clear")     \
    OFPACT(NAT,             ofpact_nat,         ofpact, "nat")          \
    OFPACT(OUTPUT_TRUNC,    ofpact_output_trunc,ofpact, "output_trunc") \
    OFPACT(CLONE,           ofpact_nest,        actions, "clone")       \
    OFPACT(CHECK_PKT_LARGER, ofpact_check_pkt_larger, ofpact,           \
           "check_pkt_larger")                                          \
                                                                        \
     \
    OFPACT(DEBUG_RECIRC, ofpact_null,           ofpact, "debug_recirc") \
    OFPACT(DEBUG_SLOW,   ofpact_null,           ofpact, "debug_slow")   \
                                                                        \
                    \
    OFPACT(METER,           ofpact_meter,       ofpact, "meter")        \
    OFPACT(CLEAR_ACTIONS,   ofpact_null,        ofpact, "clear_actions") \
    OFPACT(WRITE_ACTIONS,   ofpact_nest,        actions, "write_actions") \
    OFPACT(WRITE_METADATA,  ofpact_metadata,    ofpact, "write_metadata") \
    OFPACT(GOTO_TABLE,      ofpact_goto_table,  ofpact, "goto_table")
#define OFPACT_ALIGN(SIZE) ROUND_UP(SIZE, OFPACT_ALIGNTO)
#define OFPACT_ALIGNTO 8
#define OFPACT_FIND_TYPE_FLATTENED(A, TYPE, END) \
    ofpact_get_##TYPE##_nullable(                       \
        ofpact_find_type_flattened(A, OFPACT_##TYPE, END))
#define OFPACT_FOR_EACH(POS, OFPACTS, OFPACTS_LEN)                      \
    for ((POS) = (OFPACTS); (POS) < ofpact_end(OFPACTS, OFPACTS_LEN);  \
         (POS) = ofpact_next(POS))
#define OFPACT_FOR_EACH_FLATTENED(POS, OFPACTS, OFPACTS_LEN)           \
    for ((POS) = (OFPACTS); (POS) < ofpact_end(OFPACTS, OFPACTS_LEN);  \
         (POS) = ofpact_next_flattened(POS))
#define OFPACT_FOR_EACH_TYPE_FLATTENED(POS, TYPE, OFPACTS, OFPACTS_LEN) \
    for ((POS) = OFPACT_FIND_TYPE_FLATTENED(OFPACTS, TYPE,              \
                                  ofpact_end(OFPACTS, OFPACTS_LEN));    \
         (POS);                                                         \
         (POS) = OFPACT_FIND_TYPE_FLATTENED(                            \
             ofpact_next_flattened(&(POS)->ofpact), TYPE,               \
             ofpact_end(OFPACTS, OFPACTS_LEN)))
#define OFPACT_LEARN_SPEC_FOR_EACH(SPEC, LEARN) \
    for ((SPEC) = (LEARN)->specs;               \
         (SPEC) < ofpact_learn_spec_end(LEARN); \
         (SPEC) = ofpact_learn_spec_next(SPEC))
#define OFPACT_PADDED_MEMBERS(MEMBERS) PADDED_MEMBERS(OFPACT_ALIGNTO, MEMBERS)
#define OPENVSWITCH_OFP_ACTIONS_H 1
#define OVS_INSTRUCTIONS                                    \
    DEFINE_INST(OFPIT13_METER,                              \
                ofp13_instruction_meter,          false,    \
                "meter")                                    \
                                                            \
    DEFINE_INST(OFPIT11_APPLY_ACTIONS,                      \
                ofp11_instruction_actions,        true,     \
                "apply_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_CLEAR_ACTIONS,                      \
                ofp11_instruction,                false,    \
                "clear_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_WRITE_ACTIONS,                      \
                ofp11_instruction_actions,        true,     \
                "write_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_WRITE_METADATA,                     \
                ofp11_instruction_write_metadata, false,    \
                "write_metadata")                           \
                                                            \
    DEFINE_INST(OFPIT11_GOTO_TABLE,                         \
                ofp11_instruction_goto_table,     false,    \
                "goto_table")
#define ofpact_set_field_mask(SF)                               \
    ALIGNED_CAST(union mf_value *,                              \
                 (uint8_t *)(SF)->value + (SF)->field->n_bytes)
#define OPENVSWITCH_OFP_ED_PROPS_H 1
#define OFPBUF_STUB_INITIALIZER(STUB) {         \
        .base = (STUB),                         \
        .data = (STUB),                         \
        .size = 0,                              \
        .allocated = sizeof (STUB),             \
        .header = NULL,                         \
        .msg = NULL,                            \
        .list_node = OVS_LIST_POISON,           \
        .source = OFPBUF_STUB,                  \
    }
#define OPENVSWITCH_OFPBUF_H 1
#define DS_EMPTY_INITIALIZER { NULL, 0, 0 }
#define OPENVSWITCH_DYNAMIC_STRING_H 1
#define OFPERR_OFS (1 << 30)
#define OPENVSWITCH_OFP_ERRORS_H 1
#define OFPUTIL_DEFAULT_VERSIONS OFPUTIL_SUPPORTED_VERSIONS
#define OFPUTIL_P_ANY ((1 << 9) - 1)
#define OFPUTIL_P_ANY_OXM (OFPUTIL_P_OF12_OXM | \
                           OFPUTIL_P_OF13_OXM | \
                           OFPUTIL_P_OF14_OXM | \
                           OFPUTIL_P_OF15_OXM)
#define OFPUTIL_P_NONE 0
#define OFPUTIL_P_NXM_OF11_UP (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_OF11_STD | \
                               OFPUTIL_P_ANY_OXM)
#define OFPUTIL_P_NXM_OXM_ANY (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_ANY_OXM)
#define OFPUTIL_P_OF10_ANY (OFPUTIL_P_OF10_STD_ANY | OFPUTIL_P_OF10_NXM_ANY)
#define OFPUTIL_P_OF10_NXM_ANY (OFPUTIL_P_OF10_NXM | OFPUTIL_P_OF10_NXM_TID)
#define OFPUTIL_P_OF10_STD_ANY (OFPUTIL_P_OF10_STD | OFPUTIL_P_OF10_STD_TID)
#define OFPUTIL_P_OF11_UP (OFPUTIL_P_OF11_STD | OFPUTIL_P_ANY_OXM)
#define OFPUTIL_P_OF12_UP (OFPUTIL_P_OF12_OXM | OFPUTIL_P_OF13_UP)
#define OFPUTIL_P_OF13_UP (OFPUTIL_P_OF13_OXM | OFPUTIL_P_OF14_UP)
#define OFPUTIL_P_OF14_UP (OFPUTIL_P_OF14_OXM | OFPUTIL_P_OF15_UP)
#define OFPUTIL_P_OF15_UP OFPUTIL_P_OF15_OXM
#define OFPUTIL_P_TID (OFPUTIL_P_OF10_STD_TID | \
                       OFPUTIL_P_OF10_NXM_TID | \
                       OFPUTIL_P_OF11_STD |     \
                       OFPUTIL_P_ANY_OXM)
#define OFPUTIL_SUPPORTED_VERSIONS ((1u << OFP10_VERSION) | \
                                    (1u << OFP11_VERSION) | \
                                    (1u << OFP12_VERSION) | \
                                    (1u << OFP13_VERSION) | \
                                    (1u << OFP14_VERSION) | \
                                    (1u << OFP15_VERSION))
#define OPENVSWITCH_OFP_PROTOCOL_H 1
#define CASE_MFF_REGS                                             \
    case MFF_REG0: case MFF_REG1: case MFF_REG2: case MFF_REG3:   \
    case MFF_REG4: case MFF_REG5: case MFF_REG6: case MFF_REG7:   \
    case MFF_REG8: case MFF_REG9: case MFF_REG10: case MFF_REG11: \
    case MFF_REG12: case MFF_REG13: case MFF_REG14: case MFF_REG15
#define CASE_MFF_TUN_METADATA                         \
    case MFF_TUN_METADATA0: case MFF_TUN_METADATA1:   \
    case MFF_TUN_METADATA2: case MFF_TUN_METADATA3:   \
    case MFF_TUN_METADATA4: case MFF_TUN_METADATA5:   \
    case MFF_TUN_METADATA6: case MFF_TUN_METADATA7:   \
    case MFF_TUN_METADATA8: case MFF_TUN_METADATA9:   \
    case MFF_TUN_METADATA10: case MFF_TUN_METADATA11: \
    case MFF_TUN_METADATA12: case MFF_TUN_METADATA13: \
    case MFF_TUN_METADATA14: case MFF_TUN_METADATA15: \
    case MFF_TUN_METADATA16: case MFF_TUN_METADATA17: \
    case MFF_TUN_METADATA18: case MFF_TUN_METADATA19: \
    case MFF_TUN_METADATA20: case MFF_TUN_METADATA21: \
    case MFF_TUN_METADATA22: case MFF_TUN_METADATA23: \
    case MFF_TUN_METADATA24: case MFF_TUN_METADATA25: \
    case MFF_TUN_METADATA26: case MFF_TUN_METADATA27: \
    case MFF_TUN_METADATA28: case MFF_TUN_METADATA29: \
    case MFF_TUN_METADATA30: case MFF_TUN_METADATA31: \
    case MFF_TUN_METADATA32: case MFF_TUN_METADATA33: \
    case MFF_TUN_METADATA34: case MFF_TUN_METADATA35: \
    case MFF_TUN_METADATA36: case MFF_TUN_METADATA37: \
    case MFF_TUN_METADATA38: case MFF_TUN_METADATA39: \
    case MFF_TUN_METADATA40: case MFF_TUN_METADATA41: \
    case MFF_TUN_METADATA42: case MFF_TUN_METADATA43: \
    case MFF_TUN_METADATA44: case MFF_TUN_METADATA45: \
    case MFF_TUN_METADATA46: case MFF_TUN_METADATA47: \
    case MFF_TUN_METADATA48: case MFF_TUN_METADATA49: \
    case MFF_TUN_METADATA50: case MFF_TUN_METADATA51: \
    case MFF_TUN_METADATA52: case MFF_TUN_METADATA53: \
    case MFF_TUN_METADATA54: case MFF_TUN_METADATA55: \
    case MFF_TUN_METADATA56: case MFF_TUN_METADATA57: \
    case MFF_TUN_METADATA58: case MFF_TUN_METADATA59: \
    case MFF_TUN_METADATA60: case MFF_TUN_METADATA61: \
    case MFF_TUN_METADATA62: case MFF_TUN_METADATA63
#define CASE_MFF_XREGS                                              \
    case MFF_XREG0: case MFF_XREG1: case MFF_XREG2: case MFF_XREG3: \
    case MFF_XREG4: case MFF_XREG5: case MFF_XREG6: case MFF_XREG7
#define CASE_MFF_XXREGS                                              \
    case MFF_XXREG0: case MFF_XXREG1: case MFF_XXREG2: case MFF_XXREG3
#define MF_BITMAP_INITIALIZER { { [0] = 0 } }
#define OPENVSWITCH_META_FLOW_H 1
#define FLOW_NSH_F_CTX (1 << 1)
#define FLOW_NSH_F_MASK ((1 << 2) - 1)
#define FLOW_NSH_F_OAM (1 << 0)
#define FLOW_TNL_F_CSUM (1 << 2)
#define FLOW_TNL_F_DONT_FRAGMENT (1 << 1)
#define FLOW_TNL_F_KEY (1 << 3)
#define FLOW_TNL_F_MASK ((1 << 4) - 1)
#define FLOW_TNL_F_OAM (1 << 0)
#define FLOW_TNL_PUB_F_MASK ((1 << 1) - 1)
#define OPENVSWITCH_PACKETS_H 1
#define OPENVSWITCH_TUN_METADATA_H 1
#define TUN_METADATA_NUM_OPTS 64
#define TUN_METADATA_TOT_OPT_SIZE 256
#define GENEVE_CRIT_OPT_TYPE (1 << 7)
#define OPENVSWITCH_GENEVE_H 1
#define TLV_MAX_OPT_SIZE 124
#define TLV_TOT_OPT_SIZE 252
#define FLOW_DL_TYPE_NONE 0x5ff
#define FLOW_MAX_MPLS_LABELS 3
#define FLOW_MAX_SAMPLE_NESTING 10
#define FLOW_MAX_VLAN_HEADERS 2
#define FLOW_NW_FRAG_ANY   (1 << 0) 
#define FLOW_NW_FRAG_LATER (1 << 1) 
#define FLOW_NW_FRAG_MASK  (FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER)
#define FLOW_N_REGS 16
#define FLOW_N_XREGS (FLOW_N_REGS / 2)
#define FLOW_N_XXREGS (FLOW_N_REGS / 4)
#define FLOW_U64S (sizeof(struct flow) / sizeof(uint64_t))
#define FLOW_WC_SEQ 42
#define LEGACY_MAX_VLAN_HEADERS 1
#define OPENVSWITCH_FLOW_H 1
#define WC_MASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0xff, sizeof (WC)->masks.FIELD)
#define WC_MASK_FIELD_MASK(WC, FIELD, MASK)     \
    ((WC)->masks.FIELD |= (MASK))
#define WC_UNMASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0, sizeof (WC)->masks.FIELD)
#define NXET_VENDOR 0xb0c2
#define NXM_NX_MAX_REGS 16
#define NX_IP_FRAG_ANY   (1 << 0) 
#define NX_IP_FRAG_LATER (1 << 1) 
#define NX_TUN_FLAG_OAM  (1 << 0) 
#define OPENFLOW_NICIRA_EXT_H 1
#define HASH_H 1
#define HASH_AARCH64_H 1
#define CS_VALID_MASK (CS_NEW | CS_ESTABLISHED | CS_REPLY_DIR)
#define FLOWMAP_AUX_INITIALIZER(FLOWMAP) { .unit = 0, .map = (FLOWMAP) }
#define FLOWMAP_CLEAR(FM, FIELD)                                        \
    BUILD_ASSERT_DECL(FLOW_U64_OFFREM(FIELD) == 0);                     \
    BUILD_ASSERT_DECL(sizeof(((struct flow *)0)->FIELD) % sizeof(uint64_t) == 0); \
    flowmap_clear(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))
#define FLOWMAP_EMPTY_INITIALIZER { { 0 } }
#define FLOWMAP_FOR_EACH_INDEX(IDX, MAP)                            \
    for (struct flowmap_aux aux__ = FLOWMAP_AUX_INITIALIZER(MAP);   \
         flowmap_next_index(&aux__, &(IDX));)
#define FLOWMAP_FOR_EACH_MAP(MAP, FLOWMAP)                              \
    for (size_t unit__ = 0;                                       \
         unit__ < FLOWMAP_UNITS && ((MAP) = (FLOWMAP).bits[unit__], true); \
         unit__++)
#define FLOWMAP_FOR_EACH_UNIT(UNIT)                     \
    for ((UNIT) = 0; (UNIT) < FLOWMAP_UNITS; (UNIT)++)
#define FLOWMAP_HAS_FIELD(FM, FIELD)                                    \
    flowmap_are_set(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))
#define FLOWMAP_SET(FM, FIELD)                                      \
    flowmap_set(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))
#define FLOWMAP_SET__(FM, FIELD, SIZE)                  \
    flowmap_set(FM, FLOW_U64_OFFSET(FIELD),             \
                DIV_ROUND_UP(SIZE, sizeof(uint64_t)))
#define FLOWMAP_UNITS DIV_ROUND_UP(FLOW_U64S, MAP_T_BITS)
#define FLOW_FOR_EACH_IN_MAPS(VALUE, FLOW, MAPS)            \
    for (struct flow_for_each_in_maps_aux aux__             \
             = { (FLOW), FLOWMAP_AUX_INITIALIZER(MAPS) };   \
         flow_values_get_next_in_maps(&aux__, &(VALUE));)
#define FLOW_H 1
#define FLOW_MAX_PACKET_U64S (FLOW_U64S                                   \
      - FLOW_U64_SIZE(regs)                       \
                              - FLOW_U64_SIZE(metadata)                   \
                  - FLOW_U64_SIZE(nw_src)   \
                              - FLOW_U64_SIZE(mpls_lse)                   \
                      - FLOW_U64_SIZE(tp_src)                     \
                             )
#define FLOW_U64_OFFREM(FIELD)                          \
    (offsetof(struct flow, FIELD) % sizeof(uint64_t))
#define FLOW_U64_OFFSET(FIELD)                          \
    (offsetof(struct flow, FIELD) / sizeof(uint64_t))
#define FLOW_U64_SIZE(FIELD)                                            \
    DIV_ROUND_UP(FLOW_U64_OFFREM(FIELD) + MEMBER_SIZEOF(struct flow, FIELD), \
                 sizeof(uint64_t))
#define FLOW_WC_GET_AND_MASK_WC(FLOW, WC, FIELD) \
    (((WC) ? WC_MASK_FIELD(WC, FIELD) : NULL), ((FLOW)->FIELD))
#define MAP_1 (map_t)1
#define MAP_FOR_EACH_INDEX(IDX, MAP)            \
    ULLONG_FOR_EACH_1(IDX, MAP)
#define MAP_IS_SET(MAP, IDX) ((MAP) & (MAP_1 << (IDX)))
#define MAP_MAX TYPE_MAXIMUM(map_t)
#define MAP_T_BITS (sizeof(map_t) * CHAR_BIT)
#define MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, FLOW, FLOWMAP)          \
    for (struct mf_for_each_in_map_aux aux__ =                      \
        { 0, (FLOW)->map, (FLOWMAP), miniflow_get_values(FLOW) };   \
         mf_get_next_in_map(&aux__, &(VALUE));)
#define MINIFLOW_GET_BE16(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be16, FIELD)
#define MINIFLOW_GET_BE32(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be32, FIELD)
#define MINIFLOW_GET_BE64(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be64, FIELD)
#define MINIFLOW_GET_TYPE(MF, TYPE, FIELD)                              \
    (BUILD_ASSERT(sizeof(TYPE) == sizeof(((struct flow *)0)->FIELD)),   \
     BUILD_ASSERT_GCCONLY(__builtin_types_compatible_p(TYPE, typeof(((struct flow *)0)->FIELD))), \
     MINIFLOW_GET_TYPE__(MF, TYPE, FIELD))
#define MINIFLOW_GET_TYPE__(MF, TYPE, FIELD)                            \
    (MINIFLOW_IN_MAP(MF, FLOW_U64_OFFSET(FIELD))                        \
     ? ((OVS_FORCE const TYPE *)miniflow_get__(MF, FLOW_U64_OFFSET(FIELD))) \
     [FLOW_U64_OFFREM(FIELD) / sizeof(TYPE)]                            \
     : 0)
#define MINIFLOW_GET_U128(FLOW, FIELD)                                  \
    (ovs_u128) { .u64 = {                                               \
            (MINIFLOW_IN_MAP(FLOW, FLOW_U64_OFFSET(FIELD)) ?            \
             *miniflow_get__(FLOW, FLOW_U64_OFFSET(FIELD)) : 0),        \
            (MINIFLOW_IN_MAP(FLOW, FLOW_U64_OFFSET(FIELD) + 1) ?        \
             *miniflow_get__(FLOW, FLOW_U64_OFFSET(FIELD) + 1) : 0) } }
#define MINIFLOW_GET_U16(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint16_t, FIELD)
#define MINIFLOW_GET_U32(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint32_t, FIELD)
#define MINIFLOW_GET_U64(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint64_t, FIELD)
#define MINIFLOW_GET_U8(FLOW, FIELD)            \
    MINIFLOW_GET_TYPE(FLOW, uint8_t, FIELD)
#define MINIFLOW_IN_MAP(MF, IDX) flowmap_is_set(&(MF)->map, IDX)
#define MINIFLOW_VALUES_SIZE(COUNT) ((COUNT) * sizeof(uint64_t))
#define ARP_ETH_HEADER_LEN 28
#define ARP_HRD_ETHERNET 1
#define ARP_OP_RARP 3
#define ARP_OP_REPLY 2
#define ARP_OP_REQUEST 1
#define ARP_PRO_IP 0x0800
#define CS_STATE(ENUM, INDEX, NAME) \
    CS_##ENUM = 1 << INDEX, \
    CS_##ENUM##_BIT = INDEX,
#define CS_STATES                               \
    CS_STATE(NEW,         0, "new")             \
    CS_STATE(ESTABLISHED, 1, "est")             \
    CS_STATE(RELATED,     2, "rel")             \
    CS_STATE(REPLY_DIR,   3, "rpl")             \
    CS_STATE(INVALID,     4, "inv")             \
    CS_STATE(TRACKED,     5, "trk")             \
    CS_STATE(SRC_NAT,     6, "snat")            \
    CS_STATE(DST_NAT,     7, "dnat")
#define CS_UNSUPPORTED_MASK  (~(uint32_t)CS_SUPPORTED_MASK)
#define DNS_CLASS_IN            0x01
#define DNS_DEFAULT_RR_TTL      3600
#define DNS_HEADER_LEN 12
#define DNS_QUERY_TYPE_A        0x01
#define DNS_QUERY_TYPE_AAAA     0x1c
#define DNS_QUERY_TYPE_ANY      0xff
#define ERSPAN_DIR_MASK     0x0008
#define ERSPAN_GREHDR_LEN   8
#define ERSPAN_HDR(gre_base_hdr) \
    ((struct erspan_base_hdr *)((char *)gre_base_hdr + ERSPAN_GREHDR_LEN))
#define ERSPAN_HWID_MASK    0x03f0
#define ERSPAN_IDX_MASK     0xfffff 
#define ERSPAN_SID_MASK     0x03ff  
#define ERSPAN_V1_MDSIZE    4
#define ERSPAN_V2_MDSIZE    8
#define ESP_HEADER_LEN 8
#define ESP_TRAILER_LEN 2
#define ETH_ADDR64_ARGS(EA) ETH_ADDR64_BYTES_ARGS((EA).ea64)
#define ETH_ADDR64_BYTES_ARGS(EAB) \
         (EAB)[0], (EAB)[1], (EAB)[2], (EAB)[3], \
         (EAB)[4], (EAB)[5], (EAB)[6], (EAB)[7]
#define ETH_ADDR64_FMT \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":" \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR64_STRLEN 23
#define ETH_ADDR_ARGS(EA) ETH_ADDR_BYTES_ARGS((EA).ea)
#define ETH_ADDR_BYTES_ARGS(EAB) \
         (EAB)[0], (EAB)[1], (EAB)[2], (EAB)[3], (EAB)[4], (EAB)[5]
#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_LEN           6
#define ETH_ADDR_SCAN_ARGS(EA) \
    &(EA).ea[0], &(EA).ea[1], &(EA).ea[2], &(EA).ea[3], &(EA).ea[4], &(EA).ea[5]
#define ETH_ADDR_SCAN_FMT "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8
#define ETH_ADDR_STRLEN 17
#define ETH_HEADER_LEN 14
#define ETH_PAYLOAD_MAX 1500
#define ETH_PAYLOAD_MIN 46
#define ETH_TOTAL_MAX (ETH_HEADER_LEN + ETH_PAYLOAD_MAX)
#define ETH_TOTAL_MIN (ETH_HEADER_LEN + ETH_PAYLOAD_MIN)
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_ERSPAN1       0x88be   
#define ETH_TYPE_ERSPAN2       0x22eb   
#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_IPV6          0x86dd
#define ETH_TYPE_LACP          0x8809
#define ETH_TYPE_MIN           0x600
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_MPLS_MCAST    0x8848
#define ETH_TYPE_NSH           0x894f
#define ETH_TYPE_RARP          0x8035
#define ETH_TYPE_TEB           0x6558
#define ETH_TYPE_VLAN          ETH_TYPE_VLAN_8021Q
#define ETH_TYPE_VLAN_8021AD   0x88a8
#define ETH_TYPE_VLAN_8021Q    0x8100
#define ETH_VLAN_TOTAL_MAX (ETH_HEADER_LEN + VLAN_HEADER_LEN + ETH_PAYLOAD_MAX)
#define FLOW_TNL_F_UDPIF (1 << 4)
#define GRE_CSUM        0x8000
#define GRE_FLAGS       0x00F8
#define GRE_KEY         0x2000
#define GRE_REC         0x0700
#define GRE_ROUTING     0x4000
#define GRE_SEQ         0x1000
#define GRE_STRICT      0x0800
#define GRE_VERSION     0x0007
#define GTPU_DST_PORT   2152
#define GTPU_E_MASK     0x04
#define GTPU_FLAGS_DEFAULT  0x30
#define GTPU_MSGTYPE_GPDU   255 
#define GTPU_MSGTYPE_REPL   2   
#define GTPU_MSGTYPE_REQ    1   
#define GTPU_P_MASK     0x10
#define GTPU_S_MASK     0x02
#define GTPU_VER_MASK   0xe0
#define ICMP4_DST_UNREACH 3
#define ICMP4_ECHO_REPLY 0
#define ICMP4_ECHO_REQUEST 8
#define ICMP4_INFOREPLY 16
#define ICMP4_INFOREQUEST 15
#define ICMP4_PARAM_PROB 12
#define ICMP4_REDIRECT 5
#define ICMP4_SOURCEQUENCH 4
#define ICMP4_TIMESTAMP 13
#define ICMP4_TIMESTAMPREPLY 14
#define ICMP4_TIME_EXCEEDED 11
#define ICMP6_DATA_HEADER_LEN 8
#define ICMP6_HEADER_LEN 4
#define ICMP_ERROR_DATA_L4_LEN 8
#define ICMP_HEADER_LEN 8
#define IGMPV2_HOST_MEMBERSHIP_REPORT 0x16 
#define IGMPV3_ALLOW_NEW_SOURCES 5
#define IGMPV3_BLOCK_OLD_SOURCES 6
#define IGMPV3_CHANGE_TO_EXCLUDE_MODE 4
#define IGMPV3_CHANGE_TO_INCLUDE_MODE 3
#define IGMPV3_HEADER_LEN 8
#define IGMPV3_HOST_MEMBERSHIP_REPORT 0x22 
#define IGMPV3_MODE_IS_EXCLUDE 2
#define IGMPV3_MODE_IS_INCLUDE 1
#define IGMPV3_QUERY_HEADER_LEN 12
#define IGMPV3_RECORD_LEN 8
#define IGMP_HEADER_LEN 8
#define IGMP_HOST_LEAVE_MESSAGE       0x17
#define IGMP_HOST_MEMBERSHIP_QUERY    0x11 
#define IGMP_HOST_MEMBERSHIP_REPORT   0x12 
#define IN6ADDR_ALL_HOSTS_INIT { { { 0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00, \
                                     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 } } }
#define IN6ADDR_ALL_ROUTERS_INIT { { { 0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00, \
                                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02 } } }
#define IN6ADDR_EXACT_INIT { { { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff } } }
#define IPPROTO_DCCP 33
#define IPPROTO_IGMP 2
#define IPPROTO_SCTP 132
#define IPPROTO_UDPLITE 136
#define IPV6_HEADER_LEN 40
#define IPV6_LABEL_MASK 0x000fffff
#define IPV6_SCAN_FMT "%46[0123456789abcdefABCDEF:.]"
#define IPV6_SCAN_LEN 46
#define IP_ARGS(ip)                             \
    ntohl(ip) >> 24,                            \
    (ntohl(ip) >> 16) & 0xff,                   \
    (ntohl(ip) >> 8) & 0xff,                    \
    ntohl(ip) & 0xff
#define IP_DONT_FRAGMENT  0x4000 
#define IP_DSCP_CS6 0xc0
#define IP_DSCP_MASK 0xfc
#define IP_ECN_CE 0x03
#define IP_ECN_ECT_0 0x02
#define IP_ECN_ECT_1 0x01
#define IP_ECN_MASK 0x03
#define IP_ECN_NOT_ECT 0x0
#define IP_FMT "%"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32
#define IP_FRAG_OFF_MASK  0x1fff 
#define IP_HEADER_LEN 20
#define IP_IHL(ip_ihl_ver) ((ip_ihl_ver) & 15)
#define IP_IHL_VER(ihl, ver) (((ver) << 4) | (ihl))
#define IP_IS_FRAGMENT(ip_frag_off) \
        ((ip_frag_off) & htons(IP_MORE_FRAGMENTS | IP_FRAG_OFF_MASK))
#define IP_MORE_FRAGMENTS 0x2000 
#define IP_PORT_SCAN_ARGS(ip, port)                                    \
        ((void) (ovs_be32) *(ip), &((uint8_t *) ip)[0]),    \
        &((uint8_t *) ip)[1],                               \
        &((uint8_t *) ip)[2],                               \
        &((uint8_t *) ip)[3],                               \
        ((void) (ovs_be16) *(port), (uint16_t *) port)
#define IP_PORT_SCAN_FMT "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8":%"SCNu16
#define IP_SCAN_ARGS(ip)                                    \
        ((void) (ovs_be32) *(ip), &((uint8_t *) ip)[0]),    \
        &((uint8_t *) ip)[1],                               \
        &((uint8_t *) ip)[2],                               \
        &((uint8_t *) ip)[3]
#define IP_SCAN_FMT "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8
#define IP_VER(ip_ihl_ver) ((ip_ihl_ver) >> 4)
#define IP_VERSION 4
#define LLC_CNTL_SNAP 3
#define LLC_DSAP_SNAP 0xaa
#define LLC_HEADER_LEN 3
#define LLC_SNAP_HEADER_LEN (LLC_HEADER_LEN + SNAP_HEADER_LEN)
#define LLC_SSAP_SNAP 0xaa
#define MLD2_RECORD_LEN 20
#define MLD2_REPORT 143
#define MLD_DONE 132
#define MLD_HEADER_LEN 8
#define MLD_QUERY 130
#define MLD_REPORT 131
#define MPLS_BOS_MASK       0x00000100
#define MPLS_BOS_SHIFT      8
#define MPLS_HLEN           4
#define MPLS_LABEL_MASK     0xfffff000
#define MPLS_LABEL_SHIFT    12
#define MPLS_TC_MASK        0x00000e00
#define MPLS_TC_SHIFT       9
#define MPLS_TTL_MASK       0x000000ff
#define MPLS_TTL_SHIFT      0
#define ND_LLA_OPT_LEN 8
#define ND_MSG_LEN 24
#define ND_MTU_DEFAULT 0
#define ND_MTU_OPT_LEN 8
#define ND_PREFIX_OPT_LEN 32
#define ND_RA_MANAGED_ADDRESS 0x80
#define ND_RA_MAX_INTERVAL_DEFAULT 600
#define ND_RA_OTHER_CONFIG    0x40
#define ND_RSO_OVERRIDE  0x20000000
#define ND_RSO_ROUTER    0x80000000
#define ND_RSO_SOLICITED 0x40000000
#define PACKETS_H 1
#define PACKET_TYPE(NS, NS_TYPE) ((uint32_t) ((NS) << 16 | (NS_TYPE)))
#define PACKET_TYPE_BE(NS, NS_TYPE) (htonl((NS) << 16 | (NS_TYPE)))
#define RA_MSG_LEN 16
#define SCTP_HEADER_LEN 12
#define SNAP_HEADER_LEN 5
#define SNAP_ORG_ETHERNET "\0\0" 
#define STP_LLC_CNTL 0x03
#define STP_LLC_DSAP 0x42
#define STP_LLC_SSAP 0x42
#define TCP_ACK 0x010
#define TCP_CTL(flags, offset) (htons((flags) | ((offset) << 12)))
#define TCP_CWR 0x080
#define TCP_ECE 0x040
#define TCP_FIN 0x001
#define TCP_FLAGS(tcp_ctl) (ntohs(tcp_ctl) & 0x0fff)
#define TCP_FLAGS_BE16(tcp_ctl) ((tcp_ctl) & htons(0x0fff))
#define TCP_HEADER_LEN 20
#define TCP_NS  0x100
#define TCP_OFFSET(tcp_ctl) (ntohs(tcp_ctl) >> 12)
#define TCP_PSH 0x008
#define TCP_RST 0x004
#define TCP_SYN 0x002
#define TCP_URG 0x020
#define UDP_HEADER_LEN 8
#define VLAN_CFI 0x1000
#define VLAN_CFI_SHIFT 12
#define VLAN_ETH_HEADER_LEN (ETH_HEADER_LEN + VLAN_HEADER_LEN)
#define VLAN_HEADER_LEN 4
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13
#define VLAN_VID_MASK 0x0fff
#define VLAN_VID_SHIFT 0
#define VLXAN_GPE_FLAGS_P       0x04    
#define VXLAN_FLAGS 0x08000000  
#define VXLAN_F_GPE  0x4000
#define VXLAN_GPE_FLAGS_O       0x01    
#define VXLAN_GPE_FLAGS_VER     0x30    
#define VXLAN_GPE_NP_ETHERNET  0x03
#define VXLAN_GPE_NP_IPV4      0x01
#define VXLAN_GPE_NP_IPV6      0x02
#define VXLAN_GPE_NP_NSH       0x04
#define VXLAN_GPE_USED_BITS (VXLAN_HF_VER | VXLAN_HF_NP | VXLAN_HF_OAM | \
                            0xff)
#define VXLAN_HF_GPE 0x04000000
#define VXLAN_HF_NP    (1U <<26)
#define VXLAN_HF_OAM   (1U <<24)
#define VXLAN_HF_VER   ((1U <<29) | (1U <<28))
#define TIMEVAL_H 1
#define TIME_MAX TYPE_MAXIMUM(time_t)
#define TIME_MIN TYPE_MINIMUM(time_t)
#define gmtime_r(timep, result) gmtime_s(result, timep)
#define localtime_r(timep, result) localtime_s(result, timep)
#define TUN_METADATA_H 1
#define NETLINK_H 1
#define NL_ATTR_FOR_EACH(ITER, LEFT, ATTRS, ATTRS_LEN)                  \
    for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);                        \
         nl_attr_is_valid(ITER, LEFT);                                  \
         (LEFT) -= nl_attr_len_pad(ITER, LEFT), (ITER) = nl_attr_next(ITER))
#define NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, ATTRS, ATTRS_LEN)           \
    for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);                        \
         (LEFT) > 0;                                                    \
         (LEFT) -= nl_attr_len_pad(ITER, LEFT), (ITER) = nl_attr_next(ITER))
#define NL_ATTR_SIZE(PAYLOAD_SIZE) (NLA_HDRLEN + NLA_ALIGN(PAYLOAD_SIZE))
#define NL_A_BE128_SIZE NL_ATTR_SIZE(sizeof(ovs_be128))
#define NL_A_BE16_SIZE NL_ATTR_SIZE(sizeof(ovs_be16))
#define NL_A_BE32_SIZE NL_ATTR_SIZE(sizeof(ovs_be32))
#define NL_A_BE64_SIZE NL_ATTR_SIZE(sizeof(ovs_be64))
#define NL_A_FLAG_SIZE NL_ATTR_SIZE(0)
#define NL_A_IPV6_SIZE NL_ATTR_SIZE(sizeof(struct in6_addr))
#define NL_A_U128_SIZE  NL_ATTR_SIZE(sizeof(ovs_u128))
#define NL_A_U16_SIZE  NL_ATTR_SIZE(sizeof(uint16_t))
#define NL_A_U32_SIZE  NL_ATTR_SIZE(sizeof(uint32_t))
#define NL_A_U64_SIZE  NL_ATTR_SIZE(sizeof(uint64_t))
#define NL_A_U8_SIZE   NL_ATTR_SIZE(sizeof(uint8_t))
#define NL_NESTED_FOR_EACH(ITER, LEFT, A)                               \
    NL_ATTR_FOR_EACH(ITER, LEFT, nl_attr_get(A), nl_attr_get_size(A))
#define NL_NESTED_FOR_EACH_UNSAFE(ITER, LEFT, A)                        \
    NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, nl_attr_get(A), nl_attr_get_size(A))
#define NL_POLICY_FOR(TYPE) \
    .type = NL_A_UNSPEC, .min_len = sizeof(TYPE), .max_len = sizeof(TYPE)
#define CTRL_ATTR_MAX (__CTRL_ATTR_MAX - 1)
#define CTRL_ATTR_MCAST_GROUPS 7
#define CTRL_ATTR_MCAST_GRP_MAX (__CTRL_ATTR_MCAST_GRP_MAX - 1)
#define CTRL_ATTR_OP_MAX (__CTRL_ATTR_OP_MAX - 1)
#define CTRL_CMD_MAX (__CTRL_CMD_MAX - 1)
#define GENL_HDRLEN NLMSG_ALIGN(sizeof(struct genlmsghdr))
#define GENL_ID_CTRL            NLMSG_MIN_TYPE
#define GENL_MAX_ID     1023
#define GENL_MIN_ID     NLMSG_MIN_TYPE
#define MAX_LINKS               32
#define NETLINK_ADD_MEMBERSHIP 1
#define NETLINK_DROP_MEMBERSHIP 2
#define NETLINK_GENERIC         16
#define NETLINK_LISTEN_ALL_NSID 8
#define NETLINK_NETFILTER       12
#define NETLINK_PROTOCOL_H 1
#define NLA_ALIGN(SIZE) ROUND_UP(SIZE, NLA_ALIGNTO)
#define NLA_ALIGNTO 4
#define NLA_F_NESTED        (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_TYPE_MASK       ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
#define NLMSG_ALIGN(SIZE) ROUND_UP(SIZE, NLMSG_ALIGNTO)
#define NLMSG_ALIGNTO 4
#define NLMSG_DONE              3
#define NLMSG_ERROR             2
#define NLMSG_HDRLEN ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_MIN_TYPE          0x10
#define NLMSG_NOOP              1
#define NLMSG_OVERRUN           4
#define NLM_F_ACK               0x004
#define NLM_F_ATOMIC            0x400
#define NLM_F_CREATE            0x400
#define NLM_F_DUMP              (NLM_F_ROOT | NLM_F_MATCH)
#define NLM_F_ECHO              0x008
#define NLM_F_EXCL              0x200
#define NLM_F_MATCH             0x200
#define NLM_F_MULTI             0x002
#define NLM_F_REPLACE           0x100
#define NLM_F_REQUEST           0x001
#define NLM_F_ROOT              0x100
#define __UAPI_LINUX_NETLINK_WRAPPER_H 1
#define BITMAP_FOR_EACH_1(IDX, SIZE, BITMAP)        \
    BITMAP_FOR_EACH_1_RANGE(IDX, 0, SIZE, BITMAP)
#define BITMAP_FOR_EACH_1_RANGE(IDX, BEGIN, END, BITMAP)           \
    for ((IDX) = bitmap_scan(BITMAP, true, BEGIN, END); (IDX) < (END);   \
         (IDX) = bitmap_scan(BITMAP, true, (IDX) + 1, END))
#define BITMAP_H 1
#define ULLONG_FOR_EACH_1(IDX, MAP)                 \
    for (uint64_t map__ = (MAP);                    \
         map__ && (((IDX) = raw_ctz(map__)), true); \
         map__ = zero_rightmost_1bit(map__))
#define ULLONG_GET(MAP, OFFSET) !!((MAP) & (1ULL << (OFFSET)))
#define ULLONG_SET0(MAP, OFFSET) ((MAP) &= ~(1ULL << (OFFSET)))
#define ULLONG_SET1(MAP, OFFSET) ((MAP) |= 1ULL << (OFFSET))
#define DEF_OL_FLAG(NAME, DPDK_DEF, GENERIC_DEF) NAME = DPDK_DEF
#define DPBUF_H 1
#define DP_PACKET_BATCH_FOR_EACH(IDX, PACKET, BATCH)                \
    for (size_t IDX = 0; IDX < dp_packet_batch_size(BATCH); IDX++)  \
        if (PACKET = BATCH->packets[IDX], true)
#define DP_PACKET_BATCH_REFILL_FOR_EACH(IDX, SIZE, PACKET, BATCH)       \
    for (dp_packet_batch_refill_init(BATCH), IDX=0; IDX < SIZE; IDX++)  \
         if (PACKET = BATCH->packets[IDX], true)
#define DP_PACKET_CONTEXT_SIZE 64
#define DP_PACKET_OL_RX_IP_CKSUM_MASK (DP_PACKET_OL_RX_IP_CKSUM_GOOD | \
                                       DP_PACKET_OL_RX_IP_CKSUM_BAD)
#define DP_PACKET_OL_RX_L4_CKSUM_MASK (DP_PACKET_OL_RX_L4_CKSUM_GOOD | \
                                       DP_PACKET_OL_RX_L4_CKSUM_BAD)
#define DP_PACKET_OL_SUPPORTED_MASK (DP_PACKET_OL_RSS_HASH         | \
                                     DP_PACKET_OL_FLOW_MARK        | \
                                     DP_PACKET_OL_RX_L4_CKSUM_BAD  | \
                                     DP_PACKET_OL_RX_IP_CKSUM_BAD  | \
                                     DP_PACKET_OL_RX_L4_CKSUM_GOOD | \
                                     DP_PACKET_OL_RX_IP_CKSUM_GOOD | \
                                     DP_PACKET_OL_TX_TCP_SEG       | \
                                     DP_PACKET_OL_TX_IPV4          | \
                                     DP_PACKET_OL_TX_IPV6          | \
                                     DP_PACKET_OL_TX_TCP_CKSUM     | \
                                     DP_PACKET_OL_TX_UDP_CKSUM     | \
                                     DP_PACKET_OL_TX_SCTP_CKSUM)
#define DP_PACKET_OL_TX_L4_MASK (DP_PACKET_OL_TX_TCP_CKSUM | \
                                 DP_PACKET_OL_TX_UDP_CKSUM | \
                                 DP_PACKET_OL_TX_SCTP_CKSUM)

#define NETDEV_AFXDP_H 1
#define MATCH_CATCHALL_INITIALIZER { .flow = { .dl_type = 0 } }
#define MATCH_SET_FIELD_BE32(match, field, value)             \
    MATCH_SET_FIELD_MASKED(match, field, value, OVS_BE32_MAX)
#define MATCH_SET_FIELD_MASKED(match, field, value, msk)      \
    do {                                                      \
        (match)->wc.masks.field = (msk);                      \
        (match)->flow.field = (value) & (msk);                \
    } while (0)
#define MATCH_SET_FIELD_UINT8(match, field, value)            \
    MATCH_SET_FIELD_MASKED(match, field, value, UINT8_MAX)
#define OPENVSWITCH_MATCH_H 1
#define JHASH_H 1
#define CSUM_H 1
#define COVERAGE_ADD(COUNTER, AMOUNT) COUNTER##_add(AMOUNT)
#define COVERAGE_CLEAR_INTERVAL  1000
#define COVERAGE_DEFINE(COUNTER)                                        \
        DEFINE_STATIC_PER_THREAD_DATA(unsigned int,                     \
                                      counter_##COUNTER, 0);            \
        static unsigned int COUNTER##_count(void)                       \
        {                                                               \
            unsigned int *countp = counter_##COUNTER##_get();           \
            unsigned int count = *countp;                               \
            *countp = 0;                                                \
            return count;                                               \
        }                                                               \
        static inline void COUNTER##_add(unsigned int n)                \
        {                                                               \
            *counter_##COUNTER##_get() += n;                            \
        }                                                               \
        extern struct coverage_counter counter_##COUNTER;               \
        struct coverage_counter counter_##COUNTER                       \
            = { #COUNTER, COUNTER##_count, 0, 0, {0}, {0} };            \
        OVS_CONSTRUCTOR(COUNTER##_init_coverage) {                      \
            coverage_counter_register(&counter_##COUNTER);              \
        }
#define COVERAGE_H 1
#define COVERAGE_INC(COUNTER) COVERAGE_ADD(COUNTER, 1)
#define COVERAGE_RUN_INTERVAL    5000
#define HR_AVG_LEN  60
#define MIN_AVG_LEN (60000/COVERAGE_RUN_INTERVAL)
#define DECLARE_EXTERN_PER_THREAD_DATA(TYPE, NAME)                      \
    typedef TYPE NAME##_type;                                           \
    extern thread_local NAME##_type NAME##_var;                         \
                                                                        \
    static inline NAME##_type *                                         \
    NAME##_get_unsafe(void)                                             \
    {                                                                   \
        return (NAME##_type *)&NAME##_var;                              \
    }                                                                   \
                                                                        \
    static inline NAME##_type *                                         \
    NAME##_get(void)                                                    \
    {                                                                   \
        return NAME##_get_unsafe();                                     \
    }
#define DEFINE_EXTERN_PER_THREAD_DATA(NAME, ...)         \
    thread_local NAME##_type NAME##_var = __VA_ARGS__;
#define DEFINE_PER_THREAD_MALLOCED_DATA(TYPE, NAME)     \
    static pthread_key_t NAME##_key;                    \
                                                        \
    static void                                         \
    NAME##_once_init(void)                              \
    {                                                   \
        if (pthread_key_create(&NAME##_key, free)) {    \
            abort();                                    \
        }                                               \
    }                                                   \
                                                        \
    static void                                         \
    NAME##_init(void)                                   \
    {                                                   \
        static pthread_once_t once = PTHREAD_ONCE_INIT; \
        pthread_once(&once, NAME##_once_init);          \
    }                                                   \
                                                        \
    static TYPE                                         \
    NAME##_get_unsafe(void)                             \
    {                                                   \
        return pthread_getspecific(NAME##_key);         \
    }                                                   \
                                                        \
    static OVS_UNUSED TYPE                              \
    NAME##_get(void)                                    \
    {                                                   \
        NAME##_init();                                  \
        return NAME##_get_unsafe();                     \
    }                                                   \
                                                        \
    static TYPE                                         \
    NAME##_set_unsafe(TYPE value)                       \
    {                                                   \
        TYPE old_value = NAME##_get_unsafe();           \
        xpthread_setspecific(NAME##_key, value);        \
        return old_value;                               \
    }                                                   \
                                                        \
    static OVS_UNUSED TYPE                              \
    NAME##_set(TYPE value)                              \
    {                                                   \
        NAME##_init();                                  \
        return NAME##_set_unsafe(value);                \
    }
#define DEFINE_STATIC_PER_THREAD_DATA(TYPE, NAME, ...)                  \
    typedef TYPE NAME##_type;                                           \
                                                                        \
    static NAME##_type *                                                \
    NAME##_get_unsafe(void)                                             \
    {                                                                   \
        static thread_local NAME##_type var = __VA_ARGS__;              \
        return &var;                                                    \
    }                                                                   \
                                                                        \
    static NAME##_type *                                                \
    NAME##_get(void)                                                    \
    {                                                                   \
        return NAME##_get_unsafe();                                     \
    }
#define OVSTHREAD_ID_UNSET UINT_MAX
#define OVSTHREAD_STATS_FOR_EACH_BUCKET(BUCKET, IDX, STATS)             \
    for ((IDX) = ovs_thread_stats_next_bucket(STATS, 0);                \
         ((IDX) < ARRAY_SIZE((STATS)->buckets)                          \
          ? ((BUCKET) = (STATS)->buckets[IDX], true)                    \
          : false);                                                     \
         (IDX) = ovs_thread_stats_next_bucket(STATS, (IDX) + 1))
#define OVS_RWLOCK_INITIALIZER \
        { PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP, "<unlocked>" }
#define OVS_THREAD_H 1
#define assert_single_threaded() assert_single_threaded_at(OVS_SOURCE_LOCATOR)
#define ovs_rwlock_rdlock(rwlock) \
        ovs_rwlock_rdlock_at(rwlock, OVS_SOURCE_LOCATOR)
#define ovs_rwlock_tryrdlock(rwlock) \
        ovs_rwlock_tryrdlock_at(rwlock, OVS_SOURCE_LOCATOR)
#define ovs_rwlock_trywrlock(rwlock) \
    ovs_rwlock_trywrlock_at(rwlock, OVS_SOURCE_LOCATOR)
#define ovs_rwlock_wrlock(rwlock) \
        ovs_rwlock_wrlock_at(rwlock, OVS_SOURCE_LOCATOR)
#define thread_local __thread
#define xfork() xfork_at(OVS_SOURCE_LOCATOR)
#define OPENVSWITCH_THREAD_H 1
#define OVSTHREAD_ONCE_INITIALIZER              \
    {                                           \
        false,                                  \
        OVS_MUTEX_INITIALIZER,                  \
    }
#define OVS_ADAPTIVE_MUTEX_INITIALIZER                  \
    { PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP, "<unlocked>" }
#define OVS_MUTEX_INITIALIZER { PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP, \
                                "<unlocked>" }
#define ovs_mutex_lock(mutex) \
        ovs_mutex_lock_at(mutex, OVS_SOURCE_LOCATOR)
#define ovs_mutex_trylock(mutex) \
        ovs_mutex_trylock_at(mutex, OVS_SOURCE_LOCATOR)
#define ovs_spin_lock(spin) \
        ovs_spin_lock_at(spin, OVS_SOURCE_LOCATOR)
#define ovs_spin_trylock(spin) \
        ovs_spin_trylock_at(spin, OVS_SOURCE_LOCATOR)
#define ATOMIC_COUNT_INIT(VALUE) { VALUE }

#define OVS_ATOMIC_H 1
#define atomic_add_relaxed(RMW, ARG, ORIG)                              \
    atomic_add_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_and_relaxed(RMW, ARG, ORIG)                              \
    atomic_and_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_compare_exchange_strong_relaxed(DST, EXP, SRC)     \
    atomic_compare_exchange_strong_explicit(DST, EXP, SRC,        \
                                            memory_order_relaxed, \
                                            memory_order_relaxed)
#define atomic_compare_exchange_weak_relaxed(DST, EXP, SRC)       \
    atomic_compare_exchange_weak_explicit(DST, EXP, SRC,          \
                                          memory_order_relaxed,   \
                                          memory_order_relaxed)
#define atomic_flag_clear_relaxed(FLAG)                         \
    atomic_flag_clear_explicit(FLAG, memory_order_relaxed)
#define atomic_flag_test_and_set_relaxed(FLAG)                          \
    atomic_flag_test_and_set_explicit(FLAG, memory_order_relaxed)
#define atomic_or_relaxed(RMW, ARG, ORIG)                               \
    atomic_or_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_read_relaxed(VAR, DST)                                   \
    atomic_read_explicit(VAR, DST, memory_order_relaxed)
#define atomic_store_relaxed(VAR, VALUE)                        \
    atomic_store_explicit(VAR, VALUE, memory_order_relaxed)
#define atomic_sub_relaxed(RMW, ARG, ORIG)                              \
    atomic_sub_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_xor_relaxed(RMW, ARG, ORIG)                              \
    atomic_xor_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define ATOMIC(TYPE) TYPE
#define ATOMIC_BOOL_LOCK_FREE 0
#define ATOMIC_CHAR_LOCK_FREE 0
#define ATOMIC_FLAG_INIT { false }
#define ATOMIC_INT_LOCK_FREE 0
#define ATOMIC_LLONG_LOCK_FREE 0
#define ATOMIC_LONG_LOCK_FREE 0
#define ATOMIC_POINTER_LOCK_FREE 0
#define ATOMIC_SHORT_LOCK_FREE 0
#define ATOMIC_VAR_INIT(VALUE) (VALUE)
#define OVS_ATOMIC_PTHREADS_IMPL 1
#define atomic_add(RMW, ARG, ORIG) atomic_op_locked(RMW, add, ARG, ORIG)
#define atomic_add_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_add(RMW, ARG, ORIG))
#define atomic_and(RMW, ARG, ORIG) atomic_op_locked(RMW, and, ARG, ORIG)
#define atomic_and_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_and(RMW, ARG, ORIG))
#define atomic_compare_exchange_strong(DST, EXP, SRC)   \
    atomic_compare_exchange_locked(DST, EXP, SRC)
#define atomic_compare_exchange_strong_explicit(DST, EXP, SRC, ORD1, ORD2) \
    ((void) (ORD1), (void) (ORD2),                                      \
     atomic_compare_exchange_strong(DST, EXP, SRC))
#define atomic_compare_exchange_weak            \
    atomic_compare_exchange_strong
#define atomic_compare_exchange_weak_explicit   \
    atomic_compare_exchange_strong_explicit
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)
#define atomic_is_lock_free(OBJ) false
#define atomic_or( RMW, ARG, ORIG) atomic_op_locked(RMW, or, ARG, ORIG)
#define atomic_or_explicit(RMW, ARG, ORIG, ORDER)   \
    ((void) (ORDER), atomic_or(RMW, ARG, ORIG))
#define atomic_read(SRC, DST) atomic_read_locked(SRC, DST)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    ((void) (ORDER), atomic_read(SRC, DST))
#define atomic_store(DST, SRC) atomic_store_locked(DST, SRC)
#define atomic_store_explicit(DST, SRC, ORDER) \
    ((void) (ORDER), atomic_store(DST, SRC))
#define atomic_sub(RMW, ARG, ORIG) atomic_op_locked(RMW, sub, ARG, ORIG)
#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_sub(RMW, ARG, ORIG))
#define atomic_xor(RMW, ARG, ORIG) atomic_op_locked(RMW, xor, ARG, ORIG)
#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_xor(RMW, ARG, ORIG))
#define OVS_ATOMIC_LOCKED_IMPL 1
#define atomic_compare_exchange_locked(DST, EXP, SRC)   \
    (atomic_lock__(DST),                                \
     (*(DST) == *(EXP)                                  \
      ? (*(DST) = (SRC),                                \
         atomic_unlock__(DST),                          \
         true)                                          \
      : (*(EXP) = *(DST),                               \
         atomic_unlock__(DST),                          \
         false)))
#define atomic_op_locked(RMW, OP, OPERAND, ORIG)    \
    (atomic_lock__(RMW),                            \
     *(ORIG) = *(RMW),                              \
     *(RMW) atomic_op_locked_##OP (OPERAND),        \
     atomic_unlock__(RMW))
#define atomic_op_locked_add +=
#define atomic_op_locked_and &=
#define atomic_op_locked_or  |=
#define atomic_op_locked_sub -=
#define atomic_op_locked_xor ^=
#define atomic_read_locked(SRC, DST)            \
    (atomic_lock__(SRC),                        \
     *(DST) = *(SRC),                           \
     atomic_unlock__(SRC),                      \
     (void) 0)
#define atomic_store_locked(DST, SRC)           \
    (atomic_lock__(DST),                        \
     *(DST) = (SRC),                            \
     atomic_unlock__(DST),                      \
     (void) 0)
#define IS_LOCKLESS_ATOMIC(OBJECT)                      \
    (sizeof(OBJECT) <= 8 && IS_POW2(sizeof(OBJECT)))
#define _InterlockedExchange64 _InlineInterlockedExchange64
#define _InterlockedExchangeAdd64 _InlineInterlockedExchangeAdd64
#define atomic_add16(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = _InterlockedExchangeAdd16((short volatile *) (RMW),   \
                                      (short) (ARG));
#define atomic_add32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedExchangeAdd((long volatile *) (RMW),   \
                                      (long) (ARG));
#define atomic_add64(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = _InterlockedExchangeAdd64((int64_t volatile *) (RMW),   \
                                      (int64_t) (ARG));
#define atomic_add8(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = _InterlockedExchangeAdd8((char volatile *) (RMW),   \
                                      (char) (ARG));
#define atomic_and32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedAnd((int32_t volatile *) (RMW), (int32_t) (ARG));
#define atomic_and_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedAnd##X((int##X##_t volatile *) (RMW),              \
                                (int##X##_t) (ARG));
#define atomic_flag_clear(FLAG)                 \
    InterlockedBitTestAndReset(FLAG, 0)
#define atomic_flag_clear_explicit(FLAG, ORDER) \
        atomic_flag_clear()
#define atomic_flag_test_and_set(FLAG)                 \
    (bool) InterlockedBitTestAndSet(FLAG, 0)
#define atomic_flag_test_and_set_explicit(FLAG, ORDER) \
        atomic_flag_test_and_set(FLAG)
#define atomic_op(OP, X, RMW, ARG, ORIG, ORDER)                         \
    atomic_##OP##_generic(X, RMW, ARG, ORIG, ORDER)
#define atomic_or32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedOr((int32_t volatile *) (RMW), (int32_t) (ARG));
#define atomic_or_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedOr##X((int##X##_t volatile *) (RMW),              \
                               (int##X##_t) (ARG));
#define atomic_read64(SRC, DST, ORDER)                                     \
    __pragma (warning(push))                                               \
    __pragma (warning(disable:4047))                                       \
    *(DST) = InterlockedOr64((int64_t volatile *) (SRC), 0);               \
    __pragma (warning(pop))
#define atomic_readX(SRC, DST, ORDER)                                      \
    *(DST) = *(SRC);
#define atomic_store16(DST, SRC, ORDER)                                    \
    if (ORDER == memory_order_seq_cst) {                                   \
        InterlockedExchange16((short volatile *) (DST), (short) (SRC));    \
    } else {                                                               \
        *(DST) = (SRC);                                                    \
    }
#define atomic_store32(DST, SRC, ORDER)                                 \
    if (ORDER == memory_order_seq_cst) {                                \
        InterlockedExchange((long volatile *) (DST),                    \
                               (long) (SRC));                           \
    } else {                                                            \
        *(DST) = (SRC);                                                 \
    }
#define atomic_store64(DST, SRC, ORDER)                                    \
    if (ORDER == memory_order_relaxed) {                                   \
        InterlockedExchangeNoFence64((int64_t volatile *) (DST),           \
                                     (int64_t) (SRC));                     \
    } else {                                                               \
        InterlockedExchange64((int64_t volatile *) (DST), (int64_t) (SRC));\
    }
#define atomic_store8(DST, SRC, ORDER)                                     \
    if (ORDER == memory_order_seq_cst) {                                   \
        InterlockedExchange8((char volatile *) (DST), (char) (SRC));       \
    } else {                                                               \
        *(DST) = (SRC);                                                    \
    }
#define atomic_xor32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedXor((int32_t volatile *) (RMW), (int32_t) (ARG));
#define atomic_xor_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedXor##X((int##X##_t volatile *) (RMW),              \
                                (int##X##_t) (ARG));
#define OVS_ATOMIC_GCC4P_IMPL 1
#define atomic_op__(RMW, OP, ARG, ORIG)                     \
    ({                                                      \
        typeof(RMW) rmw__ = (RMW);                          \
        typeof(ARG) arg__ = (ARG);                          \
        typeof(ORIG) orig__ = (ORIG);                       \
                                                            \
        if (IS_LOCKLESS_ATOMIC(*rmw__)) {                   \
            *orig__ = __sync_fetch_and_##OP(rmw__, arg__);  \
        } else {                                            \
            atomic_op_locked(rmw__, OP, arg__, orig__);     \
        }                                                   \
        (void) 0;                                           \
    })
#define OVS_ATOMIC_I586_IMPL 1
#define atomic_add_32__(RMW, ARG, ORIG, ORDER)     \
    ({                                             \
        typeof(RMW) rmw__ = (RMW);                 \
        typeof(*(RMW)) arg__ = (ARG);              \
                                                   \
        if ((ORDER) > memory_order_consume) {      \
            atomic_add__(rmw__, arg__, "memory");  \
        } else {                                   \
            atomic_add__(rmw__, arg__, "cc");      \
        }                                          \
        *(ORIG) = arg__;                           \
    })
#define atomic_add__(RMW, ARG, CLOB)            \
    asm volatile("lock; xadd %0,%1 ; "          \
                 "# atomic_add__     "          \
                 : "+r" (ARG),           \
                   "+m" (*RMW)           \
                 :: CLOB, "cc")
#define atomic_compare_exchange_8__(DST, EXP, SRC, RES, CLOB)         \
    asm volatile("      xchgl %%ebx,%3 ;    "                         \
                 "lock; cmpxchg8b (%1) ;    "                         \
                 "      xchgl %3,%%ebx ;    "                         \
                 "      sete %0             "                         \
                 "# atomic_compare_exchange_8__"                      \
                 : "=q" (RES),                                 \
                   "+r" (DST),                                 \
                   "+A" (EXP)                                  \
                 : "r" ((uint32_t)SRC),                        \
                   "c" ((uint32_t)((uint64_t)SRC >> 32))       \
                 : CLOB, "cc")
#define atomic_compare_exchange__(DST, EXP, SRC, RES, CLOB)           \
    asm volatile("lock; cmpxchg %3,%1 ; "                             \
                 "      sete    %0      "                             \
                 "# atomic_compare_exchange__"                        \
                 : "=q" (RES),                                 \
                   "+m" (*DST),                                \
                   "+a" (EXP)                                  \
                 : "r" (SRC)                                   \
                 : CLOB, "cc")
#define atomic_exchange_8__(DST, SRC, CLOB)       \
    uint32_t temp____;                            \
                                                  \
    asm volatile("      movl %%ebx,%2 ;    "      \
                 "      movl %%eax,%%ebx ; "      \
                 "      movl %%edx,%%ecx ; "      \
                 "1:                       "      \
                 "lock; cmpxchg8b (%0);    "      \
                 "      jne 1b ;           "      \
                 "      movl %2,%%ebx ;    "      \
                 " # atomic_exchange_8__   "      \
                 : "+r" (DST),             \
                   "+A" (SRC),             \
                   "=mr" (temp____)        \
                 :: "ecx", CLOB, "cc")
#define atomic_exchange__(DST, SRC, ORDER)        \
    ({                                            \
        typeof(DST) dst___ = (DST);               \
        typeof(*(DST)) src___ = (SRC);            \
                                                  \
        if ((ORDER) > memory_order_consume) {                  \
            if (sizeof(*(DST)) == 8) {                         \
                atomic_exchange_8__(dst___, src___, "memory"); \
            } else {                                           \
                asm volatile("xchg %1,%0 ;       "             \
                             "# atomic_exchange__"             \
                             : "+r" (src___),           \
                               "+m" (*dst___)           \
                             :: "memory");                     \
            }                                                  \
        } else {                                               \
            if (sizeof(*(DST)) == 8) {                         \
                atomic_exchange_8__(dst___, src___, "cc");     \
            } else {                                           \
                asm volatile("xchg %1,%0 ;       "             \
                             "# atomic_exchange__"             \
                             : "+r" (src___),           \
                               "+m" (*dst___));         \
            }                                                  \
        }                                                      \
        src___;                                                \
    })
#define atomic_read_8__(SRC, DST)               \
    ({                                          \
        typeof(*(DST)) res__;                   \
                                                \
        asm ("movq %1,%0 ; # atomic_read_8__"   \
             : "=x" (res__)        \
             : "m" (*SRC));              \
        *(DST) = res__;                         \
    })
#define atomic_store_8__(DST, SRC)                 \
    asm volatile("movq %1,%0 ; # atomic_store_8__" \
                 : "=m" (*DST)              \
                 : "x" (SRC))    
#define compiler_barrier()  asm volatile(" " : : : "memory")
#define cpu_barrier()  asm volatile("lock; addl $0,(%%esp)" ::: "memory", "cc")
#define OVS_ATOMIC_X86_64_IMPL 1
#define atomic_signal_fence __atomic_signal_fence
#define atomic_thread_fence __atomic_thread_fence
#define OMIT_STANDARD_ATOMIC_TYPES 1
#define OVS_ATOMIC_CLANG_IMPL 1
#define COLORS_H 1
