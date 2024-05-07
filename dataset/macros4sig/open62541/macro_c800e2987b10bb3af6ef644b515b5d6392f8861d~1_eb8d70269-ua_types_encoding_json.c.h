



#include<endian.h>
#include<stddef.h>


#include<inttypes.h>
#include<math.h>

#include<limits.h>
#include<float.h>
#include<string.h>



#define l_isalpha(c)  (l_isupper(c) || l_islower(c))
#define l_isdigit(c)  ('0' <= (c) && (c) <= '9')
#define l_islower(c)  ('a' <= (c) && (c) <= 'z')
#define l_isupper(c)  ('A' <= (c) && (c) <= 'Z')
#define l_isxdigit(c) (l_isdigit(c) || ('A' <= (c) && (c) <= 'F') || ('a' <= (c) && (c) <= 'f'))

# define PRIX16        "hX"
# define PRIX32        "lX"
# define PRIX64        __PRI_64_LENGTH_MODIFIER__ "X"
# define PRIX8         __PRI_8_LENGTH_MODIFIER__ "X"
# define PRId16        "hd"
# define PRId32        "ld"
# define PRId64        __PRI_64_LENGTH_MODIFIER__ "d"
# define PRId8         __PRI_8_LENGTH_MODIFIER__ "d"
# define PRIi16        "hi"
# define PRIi32        "li"
# define PRIi64        __PRI_64_LENGTH_MODIFIER__ "i"
# define PRIi8         __PRI_8_LENGTH_MODIFIER__ "i"
# define PRIo16        "ho"
# define PRIo32        "lo"
# define PRIo64        __PRI_64_LENGTH_MODIFIER__ "o"
# define PRIo8         __PRI_8_LENGTH_MODIFIER__ "o"
# define PRIu16        "hu"
# define PRIu32        "lu"
# define PRIu64        __PRI_64_LENGTH_MODIFIER__ "u"
# define PRIu8         __PRI_8_LENGTH_MODIFIER__ "u"
# define PRIx16        "hx"
# define PRIx32        "lx"
# define PRIx64        __PRI_64_LENGTH_MODIFIER__ "x"
# define PRIx8         __PRI_8_LENGTH_MODIFIER__ "x"
# define UA_BINARY_OVERLAYABLE_FLOAT 1
# define UA_BINARY_OVERLAYABLE_INTEGER 1
# define UA_CTASTR(pre,post) UA_CTASTR2(pre,post)
# define UA_CTASTR2(pre,post) pre ## post
# define UA_DEPRECATED __attribute__((deprecated))
#   define UA_EXPORT __attribute__ ((dllexport))
# define UA_FLOAT_IEEE754 1
# define UA_FLOAT_LITTLE_ENDIAN 1
# define UA_FORMAT(X,Y) __attribute__ ((format (printf, X, Y)))
# define UA_FUNC_ATTR_CONST __attribute__((const))
# define UA_FUNC_ATTR_MALLOC __attribute__((malloc))
# define UA_FUNC_ATTR_PURE __attribute__ ((pure))
# define UA_FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
# define UA_INLINE __inline
# define UA_INTERNAL_DEPRECATED _Pragma ("GCC warning \"Macro is deprecated for internal use\"")
# define UA_INTERNAL_FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#  define UA_LITTLE_ENDIAN 1
# define UA_RESTRICT __restrict
# define UA_STATIC_ASSERT(cond,msg)                             \
    typedef struct {                                            \
        int UA_CTASTR(static_assertion_failed_,msg) : !!(cond); \
    } UA_CTASTR(static_assertion_failed_,__COUNTER__)

# define UA_assert(ignore) assert(ignore)
    #define UA_atomic_sync() _ReadWriteBarrier()
#  define __COUNTER__ "__LINE__"
# define __PRI_64_LENGTH_MODIFIER__ "ll"
# define __PRI_8_LENGTH_MODIFIER__ "hh"
#  define __bool_true_false_are_defined
#  define bool unsigned char
#  define false 0
#  define true 1

#define UA_BUILTIN_TYPES_COUNT 25U
#define UA_BYTE_MAX 255
#define UA_BYTE_MIN 0
#define UA_DATATYPEKINDS 31
#define UA_DATETIME_MSEC (UA_DATETIME_USEC * 1000LL)
#define UA_DATETIME_SEC (UA_DATETIME_MSEC * 1000LL)
#define UA_DATETIME_UNIX_EPOCH (11644473600LL * UA_DATETIME_SEC)
#define UA_DATETIME_USEC 10LL
#define UA_EMPTY_ARRAY_SENTINEL ((void*)0x01)
#define UA_FALSE false UA_INTERNAL_DEPRECATED
#define UA_INT16_MAX 32767
#define UA_INT16_MIN (-32768)
#define UA_INT32_MAX 2147483647
#define UA_INT32_MIN (-2147483648)
#define UA_INT64_MAX (int64_t)9223372036854775807LL
#define UA_INT64_MIN ((int64_t)-UA_INT64_MAX-1LL)
#define UA_SBYTE_MAX 127
#define UA_SBYTE_MIN (-128)
#define UA_STRING_ALLOC(CHARS) UA_String_fromChars(CHARS)
#define UA_STRING_STATIC(CHARS) {sizeof(CHARS)-1, (UA_Byte*)CHARS}
#define UA_TRUE true UA_INTERNAL_DEPRECATED
# define UA_TYPENAME(name) name,

#define UA_UINT16_MAX 65535
#define UA_UINT16_MIN 0
#define UA_UINT32_MAX 4294967295
#define UA_UINT32_MIN 0
#define UA_UINT64_MAX (uint64_t)18446744073709551615ULL
#define UA_UINT64_MIN (uint64_t)0
#define UA_deleteMembers(p, type) UA_clear(p, type)
#define UA_ACCESSLEVELMASK_HISTORYREAD    (0x01u << 2u)
#define UA_ACCESSLEVELMASK_HISTORYWRITE   (0x01u << 3u)
#define UA_ACCESSLEVELMASK_READ           (0x01u << 0u)
#define UA_ACCESSLEVELMASK_SEMANTICCHANGE (0x01u << 4u)
#define UA_ACCESSLEVELMASK_STATUSWRITE    (0x01u << 5u)
#define UA_ACCESSLEVELMASK_TIMESTAMPWRITE (0x01u << 6u)
#define UA_ACCESSLEVELMASK_WRITE          (0x01u << 1u)

#define UA_VALUERANK_ANY                      -2
#define UA_VALUERANK_ONE_DIMENSION             1
#define UA_VALUERANK_ONE_OR_MORE_DIMENSIONS    0
#define UA_VALUERANK_SCALAR                   -1
#define UA_VALUERANK_SCALAR_OR_ONE_DIMENSION  -3
#define UA_VALUERANK_THREE_DIMENSIONS          3
#define UA_VALUERANK_TWO_DIMENSIONS            2
#define UA_WRITEMASK_ACCESSLEVEL             (0x01u << 0u)
#define UA_WRITEMASK_ARRRAYDIMENSIONS        (0x01u << 1u)
#define UA_WRITEMASK_BROWSENAME              (0x01u << 2u)
#define UA_WRITEMASK_CONTAINSNOLOOPS         (0x01u << 3u)
#define UA_WRITEMASK_DATATYPE                (0x01u << 4u)
#define UA_WRITEMASK_DESCRIPTION             (0x01u << 5u)
#define UA_WRITEMASK_DISPLAYNAME             (0x01u << 6u)
#define UA_WRITEMASK_EVENTNOTIFIER           (0x01u << 7u)
#define UA_WRITEMASK_EXECUTABLE              (0x01u << 8u)
#define UA_WRITEMASK_HISTORIZING             (0x01u << 9u)
#define UA_WRITEMASK_INVERSENAME             (0x01u << 10u)
#define UA_WRITEMASK_ISABSTRACT              (0x01u << 11u)
#define UA_WRITEMASK_MINIMUMSAMPLINGINTERVAL (0x01u << 12u)
#define UA_WRITEMASK_NODECLASS               (0x01u << 13u)
#define UA_WRITEMASK_NODEID                  (0x01u << 14u)
#define UA_WRITEMASK_SYMMETRIC               (0x01u << 15u)
#define UA_WRITEMASK_USERACCESSLEVEL         (0x01u << 16u)
#define UA_WRITEMASK_USEREXECUTABLE          (0x01u << 17u)
#define UA_WRITEMASK_USERWRITEMASK           (0x01u << 18u)
#define UA_WRITEMASK_VALUEFORVARIABLETYPE    (0x01u << 21u)
#define UA_WRITEMASK_VALUERANK               (0x01u << 19u)
#define UA_WRITEMASK_WRITEMASK               (0x01u << 20u)

#define LDBL_EPSILON 1.0842021724855044340e-19L
#define LDBL_MANT_DIG 64
#define LDBL_MAX     1.1897314953572317650e+4932L
#define LDBL_MAX_EXP 16384
#define LDBL_MIN     3.3621031431120935063e-4932L
#define LDBL_MIN_EXP (-16381)
#define LDBL_TRUE_MIN 3.6451995318824746025e-4951L

#define DBL_HAS_SUBNORM 1
#define DBL_MANT_DIG 53
#define DBL_MAX_EXP 1024
#define DBL_MIN_EXP (-1021)

#define FLT_HAS_SUBNORM 1
#define FLT_MANT_DIG 24
#define FLT_MAX_EXP 128
#define FLT_MIN_EXP (-125)

#define UA_JSON_ENCODING_MAX_RECURSION 100
#define UA_JSON_MAXTOKENCOUNT 1000



#define UA_LOG_NODEID_WRAP(NODEID, LOG) {   \
    UA_String nodeIdStr = UA_STRING_NULL;   \
    UA_NodeId_print(NODEID, &nodeIdStr);    \
    LOG;                                    \
    UA_String_clear(&nodeIdStr);            \
}
#define UA_MACRO_EXPAND(x) x


#define UA_MAX(A,B) (A > B ? A : B)
#define UA_MIN(A,B) (A > B ? B : A)
#define UA_PRINTF_GUID_DATA(GUID) (GUID).data1, (GUID).data2, (GUID).data3, \
        (GUID).data4[0], (GUID).data4[1], (GUID).data4[2], (GUID).data4[3], \
        (GUID).data4[4], (GUID).data4[5], (GUID).data4[6], (GUID).data4[7]
#define UA_PRINTF_GUID_FORMAT "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define UA_PRINTF_STRING_DATA(STRING) (int)(STRING).length, (STRING).data
#define UA_PRINTF_STRING_FORMAT "\"%.*s\""
