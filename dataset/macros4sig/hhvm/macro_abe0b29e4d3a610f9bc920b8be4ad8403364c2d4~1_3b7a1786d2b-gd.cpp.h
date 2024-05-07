






#include<stdarg.h>
















#include<tuple>

#include<list>





#include<map>


#include<atomic>

#include<sys/types.h>
#include<sys/select.h>

#include<cstdint>








#include<ctype.h>





#include<fcntl.h>
#include<mutex>

#include<cinttypes>


#include<errno.h>
#include<climits>

#include<algorithm>

#include<linux/futex.h>



#include<string>
#include<deque>


#include<stdio.h>

#include<exception>





#include<cmath>

#include<bitset>

#include<cstdio>




#include<math.h>














#include<ostream>


#include<cstdlib>


#include<cerrno>

#include<cstring>
#include<chrono>




#include<stdexcept>




#include<cstddef>


#include<queue>

#include<string.h>

#include<iostream>
#include<unordered_map>

#include<memory>




#include<cassert>

#include<array>
#include<zlib.h>




#include<thread>







#include<stdint.h>



#include<vector>




#include<set>

#include<stack>
#include<pthread.h>
#include<inttypes.h>
#include<unordered_set>



#include<functional>

#include<cstdarg>
#include<utility>


#include<limits>





















#include<time.h>

#include<stdlib.h>
#include<syscall.h>








#include<type_traits>
#include<limits.h>


#include<initializer_list>

#include<sys/stat.h>





#define S2I_4(i)  i,
#define S2I_5(i)  S2I_4(i) S2I_4(i)
#define S2I_6(i)  S2I_5(i) S2I_5(i)
#define S2I_7(i)  S2I_6(i) S2I_6(i)
#define S2I_8(i)  S2I_7(i) S2I_7(i)
#define S2I_9(i)  S2I_8(i) S2I_8(i)

#define SIZE_CLASS(index, lg_grp, lg_delta, ndelta, lg_delta_lookup, ncontig) \
  S2I_##lg_delta_lookup(index)
#define SIZE_CLASSES \
 \
  SIZE_CLASS(  0,      4,        4,      0,  4,             128) \
  SIZE_CLASS(  1,      4,        4,      1,  4,             128) \
  SIZE_CLASS(  2,      4,        4,      2,  4,             128) \
  SIZE_CLASS(  3,      4,        4,      3,  4,              96) \
  \
  SIZE_CLASS(  4,      6,        4,      1,  4,              96) \
  SIZE_CLASS(  5,      6,        4,      2,  4,              96) \
  SIZE_CLASS(  6,      6,        4,      3,  4,              96) \
  SIZE_CLASS(  7,      6,        4,      4,  4,              64) \
  \
  SIZE_CLASS(  8,      7,        5,      1,  5,              64) \
  SIZE_CLASS(  9,      7,        5,      2,  5,              64) \
  SIZE_CLASS( 10,      7,        5,      3,  5,              64) \
  SIZE_CLASS( 11,      7,        5,      4,  5,              32) \
  \
  SIZE_CLASS( 12,      8,        6,      1,  6,              32) \
  SIZE_CLASS( 13,      8,        6,      2,  6,              32) \
  SIZE_CLASS( 14,      8,        6,      3,  6,              32) \
  SIZE_CLASS( 15,      8,        6,      4,  6,              16) \
  \
  SIZE_CLASS( 16,      9,        7,      1,  7,              16) \
  SIZE_CLASS( 17,      9,        7,      2,  7,              16) \
  SIZE_CLASS( 18,      9,        7,      3,  7,              16) \
  SIZE_CLASS( 19,      9,        7,      4,  7,               8) \
  \
  SIZE_CLASS( 20,     10,        8,      1,  8,               8) \
  SIZE_CLASS( 21,     10,        8,      2,  8,               8) \
  SIZE_CLASS( 22,     10,        8,      3,  8,               8) \
  SIZE_CLASS( 23,     10,        8,      4,  8,               4) \
  \
  SIZE_CLASS( 24,     11,        9,      1,  9,               4) \
  SIZE_CLASS( 25,     11,        9,      2,  9,               4) \
  SIZE_CLASS( 26,     11,        9,      3,  9,               4) \
  SIZE_CLASS( 27,     11,        9,      4,  9,               2) \
  \
  SIZE_CLASS( 28,     12,       10,      1, no,               2) \
  SIZE_CLASS( 29,     12,       10,      2, no,               2) \
  SIZE_CLASS( 30,     12,       10,      3, no,               2) \
  SIZE_CLASS( 31,     12,       10,      4, no,               1) \
  \
  SIZE_CLASS( 32,     13,       11,      1, no,               1) \
  SIZE_CLASS( 33,     13,       11,      2, no,               1) \
  SIZE_CLASS( 34,     13,       11,      3, no,               1) \
  SIZE_CLASS( 35,     13,       11,      4, no,               1) \
  \
  SIZE_CLASS( 36,     14,       12,      1, no,               1) \
  SIZE_CLASS( 37,     14,       12,      2, no,               1) \
  SIZE_CLASS( 38,     14,       12,      3, no,               1) \
  SIZE_CLASS( 39,     14,       12,      4, no,               1) \
  \
  SIZE_CLASS( 40,     15,       13,      1, no,               1) \
  SIZE_CLASS( 41,     15,       13,      2, no,               1) \
  SIZE_CLASS( 42,     15,       13,      3, no,               1) \
  SIZE_CLASS( 43,     15,       13,      4, no,               1) \
  \
  SIZE_CLASS( 44,     16,       14,      1, no,               1) \
  SIZE_CLASS( 45,     16,       14,      2, no,               1) \
  SIZE_CLASS( 46,     16,       14,      3, no,               1) \
  SIZE_CLASS( 47,     16,       14,      4, no,               1) \
  \
  SIZE_CLASS( 48,     17,       15,      1, no,               1) \
  SIZE_CLASS( 49,     17,       15,      2, no,               1) \
  SIZE_CLASS( 50,     17,       15,      3, no,               1) \
  SIZE_CLASS( 51,     17,       15,      4, no,               1) \
  \
  SIZE_CLASS( 52,     18,       16,      1, no,               1) \
  SIZE_CLASS( 53,     18,       16,      2, no,               1) \
  SIZE_CLASS( 54,     18,       16,      3, no,               1) \
  SIZE_CLASS( 55,     18,       16,      4, no,               1) \
  \
  SIZE_CLASS( 56,     19,       17,      1, no,               1) \
  SIZE_CLASS( 57,     19,       17,      2, no,               1) \
  SIZE_CLASS( 58,     19,       17,      3, no,               1) \
  SIZE_CLASS( 59,     19,       17,      4, no,               1) \
  \
  SIZE_CLASS( 60,     20,       18,      1, no,               1) \
  SIZE_CLASS( 61,     20,       18,      2, no,               1) \
  SIZE_CLASS( 62,     20,       18,      3, no,               1) \
  SIZE_CLASS( 63,     20,       18,      4, no,               1) \
  \
  SIZE_CLASS( 64,     21,       19,      1, no,               1) \
  SIZE_CLASS( 65,     21,       19,      2, no,               1) \
  SIZE_CLASS( 66,     21,       19,      3, no,               1) \
  SIZE_CLASS( 67,     21,       19,      4, no,               1) \
  \
  SIZE_CLASS( 68,     22,       20,      1, no,               1) \
  SIZE_CLASS( 69,     22,       20,      2, no,               1) \
  SIZE_CLASS( 70,     22,       20,      3, no,               1) \
  SIZE_CLASS( 71,     22,       20,      4, no,               1) \
  \
  SIZE_CLASS( 72,     23,       21,      1, no,               1) \
  SIZE_CLASS( 73,     23,       21,      2, no,               1) \
  SIZE_CLASS( 74,     23,       21,      3, no,               1) \
  SIZE_CLASS( 75,     23,       21,      4, no,               1) \
  \
  SIZE_CLASS( 76,     24,       22,      1, no,               1) \
  SIZE_CLASS( 77,     24,       22,      2, no,               1) \
  SIZE_CLASS( 78,     24,       22,      3, no,               1) \
  SIZE_CLASS( 79,     24,       22,      4, no,               1) \
  \
  SIZE_CLASS( 80,     25,       23,      1, no,               1) \
  SIZE_CLASS( 81,     25,       23,      2, no,               1) \
  SIZE_CLASS( 82,     25,       23,      3, no,               1) \
  SIZE_CLASS( 83,     25,       23,      4, no,               1) \
  \
  SIZE_CLASS( 84,     26,       24,      1, no,               1) \
  SIZE_CLASS( 85,     26,       24,      2, no,               1) \
  SIZE_CLASS( 86,     26,       24,      3, no,               1) \
  SIZE_CLASS( 87,     26,       24,      4, no,               1) \
  \
  SIZE_CLASS( 88,     27,       25,      1, no,               1) \
  SIZE_CLASS( 89,     27,       25,      2, no,               1) \
  SIZE_CLASS( 90,     27,       25,      3, no,               1) \
  SIZE_CLASS( 91,     27,       25,      4, no,               1) \
  \
  SIZE_CLASS( 92,     28,       26,      1, no,               1) \
  SIZE_CLASS( 93,     28,       26,      2, no,               1) \
  SIZE_CLASS( 94,     28,       26,      3, no,               1) \
  SIZE_CLASS( 95,     28,       26,      4, no,               1) \
  \
  SIZE_CLASS( 96,     29,       27,      1, no,               1) \
  SIZE_CLASS( 97,     29,       27,      2, no,               1) \
  SIZE_CLASS( 98,     29,       27,      3, no,               1) \
  SIZE_CLASS( 99,     29,       27,      4, no,               1) \
  \
  SIZE_CLASS(100,     30,       28,      1, no,               1) \
  SIZE_CLASS(101,     30,       28,      2, no,               1) \
  SIZE_CLASS(102,     30,       28,      3, no,               1) \
  SIZE_CLASS(103,     30,       28,      4, no,               1) \
  \
  SIZE_CLASS(104,     31,       29,      1, no,               1) \
  SIZE_CLASS(105,     31,       29,      2, no,               1) \
  SIZE_CLASS(106,     31,       29,      3, no,               1) \
  SIZE_CLASS(107,     31,       29,      4, no,               1) \
  \
  SIZE_CLASS(108,     32,       30,      1, no,               1) \
  SIZE_CLASS(109,     32,       30,      2, no,               1) \
  SIZE_CLASS(110,     32,       30,      3, no,               1) \
  SIZE_CLASS(111,     32,       30,      4, no,               1) \
  \
  SIZE_CLASS(112,     33,       31,      1, no,               1) \
  SIZE_CLASS(113,     33,       31,      2, no,               1) \
  SIZE_CLASS(114,     33,       31,      3, no,               1) \
  SIZE_CLASS(115,     33,       31,      4, no,               1) \
  \
  SIZE_CLASS(116,     34,       32,      1, no,               1) \
  SIZE_CLASS(117,     34,       32,      2, no,               1) \
  SIZE_CLASS(118,     34,       32,      3, no,               1) \
  SIZE_CLASS(119,     34,       32,      4, no,               1) \
  \
  SIZE_CLASS(120,     35,       33,      1, no,               1) \
  SIZE_CLASS(121,     35,       33,      2, no,               1) \
  SIZE_CLASS(122,     35,       33,      3, no,               1) \
  SIZE_CLASS(123,     35,       33,      4, no,               1) \
  \
  SIZE_CLASS(124,     36,       34,      1, no,               1) \
  SIZE_CLASS(125,     36,       34,      2, no,               1) \
  SIZE_CLASS(126,     36,       34,      3, no,               1) \
  SIZE_CLASS(127,     36,       34,      4, no,               1) \
  \
  SIZE_CLASS(128,     37,       35,      1, no,               1) \
  SIZE_CLASS(129,     37,       35,      2, no,               1) \
  SIZE_CLASS(130,     37,       35,      3, no,               1) \
  SIZE_CLASS(131,     37,       35,      4, no,               1) \
  \
  SIZE_CLASS(132,     38,       36,      1, no,               1) \
  SIZE_CLASS(133,     38,       36,      2, no,               1) \
  SIZE_CLASS(134,     38,       36,      3, no,               1) \
  SIZE_CLASS(135,     38,       36,      4, no,               1) \
  \
  SIZE_CLASS(136,     39,       37,      1, no,               1) \
  SIZE_CLASS(137,     39,       37,      2, no,               1) \
  SIZE_CLASS(138,     39,       37,      3, no,               1) \
  SIZE_CLASS(139,     39,       37,      4, no,               1) \
  \
  SIZE_CLASS(140,     40,       38,      1, no,               1) \
  SIZE_CLASS(141,     40,       38,      2, no,               1) \
  SIZE_CLASS(142,     40,       38,      3, no,               1) \
  SIZE_CLASS(143,     40,       38,      4, no,               1) \
  \
  SIZE_CLASS(144,     41,       39,      1, no,               1) \
  SIZE_CLASS(145,     41,       39,      2, no,               1) \
  SIZE_CLASS(146,     41,       39,      3, no,               1) \
  SIZE_CLASS(147,     41,       39,      4, no,               1) \
  \
  SIZE_CLASS(148,     42,       40,      1, no,               1) \
  SIZE_CLASS(149,     42,       40,      2, no,               1) \
  SIZE_CLASS(150,     42,       40,      3, no,               1) \
  SIZE_CLASS(151,     42,       40,      4, no,               1) \
  \
  SIZE_CLASS(152,     43,       41,      1, no,               1) \
  SIZE_CLASS(153,     43,       41,      2, no,               1) \
  SIZE_CLASS(154,     43,       41,      3, no,               1) \
  SIZE_CLASS(155,     43,       41,      4, no,               1) \
  \
  SIZE_CLASS(156,     44,       42,      1, no,               1) \
  SIZE_CLASS(157,     44,       42,      2, no,               1) \
  SIZE_CLASS(158,     44,       42,      3, no,               1) \
  SIZE_CLASS(159,     44,       42,      4, no,               1) \
  \
  SIZE_CLASS(160,     45,       43,      1, no,               1) \
  SIZE_CLASS(161,     45,       43,      2, no,               1) \
  SIZE_CLASS(162,     45,       43,      3, no,               1) \
  SIZE_CLASS(163,     45,       43,      4, no,               1) \
  \
  SIZE_CLASS(164,     46,       44,      1, no,               1) \
  SIZE_CLASS(165,     46,       44,      2, no,               1) \
  SIZE_CLASS(166,     46,       44,      3, no,               1) \
  SIZE_CLASS(167,     46,       44,      4, no,               1) \
  \
  SIZE_CLASS(168,     47,       45,      1, no,               1) \
  SIZE_CLASS(169,     47,       45,      2, no,               1) \
  SIZE_CLASS(170,     47,       45,      3, no,               1) \
  SIZE_CLASS(171,     47,       45,      4, no,               1) \

#define IMPLIES(a, b) (!(a) || (b))
#define SCOPE_ASSERT_DETAIL(name)           \
  auto const FB_ANONYMOUS_VARIABLE(SCOPE_ASSERT)  \
  = ::HPHP::detail::AssertDetailScopeMaker(name) + [&]()
#define always_assert(e)            assert_impl(e, assert_fail_impl(e, ""))
#define always_assert_flog(e, ...)  assert_impl(e, assert_fail_impl(e,        \
                                        ::folly::format(__VA_ARGS__).str()))
#define always_assert_log(e, l)     assert_impl(e, assert_fail_impl(e, l()))
#define assert(e) static_cast<void>(0)
#define assert_fail_impl(e, msg) \
  ::HPHP::assert_fail(#e, "__FILE__", "__LINE__", __PRETTY_FUNCTION__, msg)
#define assert_flog(e, ...) static_cast<void>(0)
#define assert_impl(cond, fail) \
  ((cond) ? static_cast<void>(0) : ((fail), static_cast<void>(0)))
#define assert_log(e, l) static_cast<void>(0)
#define assert_not_implemented(pred) do {        \
  if (! (pred) ) {                               \
    not_implemented();                           \
  }                                              \
} while(0)
#define assertx(e) always_assert(e)
#define not_implemented() do {                   \
  fprintf(stderr, "not implemented: %s:%d %s\n", \
          "__FILE__", "__LINE__", __FUNCTION__);     \
  always_assert(0);                              \
} while (0)
#define not_reached()                                                \
  do {                                                               \
    assertx(false);                                                  \
  } while (true)
#define AARCH64_WALKABLE_FRAME() asm("" ::: "memory");
# define ALWAYS_INLINE     inline
#define ASM_LOCAL_LABEL(x) "L" x
#define ATTRIBUTE_PRINTF(a1, a2)
#define ATTRIBUTE_PRINTF_STRING FOLLY_PRINTF_FORMAT
#define ATTRIBUTE_UNUSED   __attribute__((__unused__))
#define ATTRIBUTE_USED     __attribute__((__used__))
   #define  CALLEE_SAVED_BARRIER()\
     asm volatile("" : : : "r2", "r14", "r15", "r16", "r17", "r18", "r19",\
                  "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", \
                  "r28", "r29", "cr2", "cr3", "cr4", "v20", "v21", "v22", \
                  "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", \
                  "v31");
# define DEBUG_ONLY 
# define DECLARE_FRAME_POINTER(fp) \
  auto const fp = (ActRec*) __builtin_frame_address(0)
#define EXTERNALLY_VISIBLE ATTRIBUTE_USED FOLLY_EXPORT
# define FLATTEN           
# define FRAME_POINTER_IS_ACCURATE
#define HAVE_LIBBFD 1
# define HHVM_ATTRIBUTE_WEAK __attribute__((__weak__))
#define HPHP_EXIT_FAILURE 127
# define INLINE_FLATTEN    inline
# define KEEP_SECTION \
    __attribute__((__section__(".text.keep")))
# define MSVC_NO_STD_CHRONO_DURATION_DOUBLE_ADD 1
# define MSVC_REQUIRE_AUTO_TEMPLATED_OVERLOAD 1
#define NEVER_INLINE __declspec(noinline)
#define NO_OPT [[clang::optnone]]
#define PACKAGE "hhvm"
#define UNUSED             __attribute__((__unused__))
#define USE_FOLLY_SYMBOLIZER 1
# define __attribute__(x)
# define __thread __declspec(thread)
#define DEF_ALLOC_FUNCS(prefix, flag, fallback)                 \
  inline void* prefix##_malloc(size_t size) {                   \
    assert(size != 0);                                          \
    return mallocx(size, flag);                                 \
  }                                                             \
  inline void prefix##_free(void* ptr) {                        \
    assert(ptr != nullptr);                                     \
    return dallocx(ptr, flag);                                  \
  }                                                             \
  inline void* prefix##_realloc(void* ptr, size_t size) {       \
    assert(size != 0);                                          \
    return rallocx(ptr, size, flag);                            \
  }                                                             \
  inline void prefix##_sized_free(void* ptr, size_t size) {     \
    assert(ptr != nullptr);                                     \
    assert(sallocx(ptr, flag) == nallocx(size, flag));          \
    return sdallocx(ptr, size, flag);                           \
  }

#  define JEMALLOC_METADATA_1G_PAGES 1
#  define USE_JEMALLOC_EXTENT_HOOKS 1
#  define VALGRIND
#define EXCEPTION_COMMON_IMPL(cls)               \
  cls* clone() override {                        \
    return new cls(*this);                       \
  }                                              \
  void throwException() override {               \
    Deleter deleter(this);                       \
    throw *this;                                 \
  }
#define COL(name) name = uint8_t(HeaderKind::name),
#define COLLECTION_TYPES              \
  COL(Vector)                         \
  COL(Map)                            \
  COL(Set)                            \
  COL(Pair)                           \
  COL(ImmVector)                      \
  COL(ImmMap)                         \
  COL(ImmSet)
#define TYPE_SCAN_CONSERVATIVE_ALL                                      \
  static constexpr const                                                \
  HPHP::type_scan::detail::ConservativeField                            \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_CONSERVATIVE_NAME{}
#define TYPE_SCAN_CONSERVATIVE_FIELD(FIELD)                             \
  static constexpr const                                                \
  HPHP::type_scan::detail::ConservativeField                            \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_BUILD_NAME(TYPE_SCAN_CONSERVATIVE_FIELD_NAME, FIELD){}
#define TYPE_SCAN_CUSTOM(...)                                           \
  static constexpr const                                                \
  HPHP::type_scan::detail::Custom<__VA_ARGS__>                          \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_CUSTOM_GUARD_NAME{};                                      \
  void TYPE_SCAN_CUSTOM_NAME(HPHP::type_scan::Scanner& scanner) const   \
    ATTRIBUTE_USED ATTRIBUTE_UNUSED EXTERNALLY_VISIBLE
#define TYPE_SCAN_CUSTOM_BASES(...)                                     \
  static constexpr const                                                \
  HPHP::type_scan::detail::CustomBase<__VA_ARGS__>                      \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_CUSTOM_BASES_NAME{};                                      \
  void TYPE_SCAN_CUSTOM_BASES_SCANNER_NAME(                             \
    HPHP::type_scan::Scanner& scanner) const                            \
    ATTRIBUTE_USED ATTRIBUTE_UNUSED EXTERNALLY_VISIBLE
#define TYPE_SCAN_CUSTOM_FIELD(FIELD)                                   \
  void TYPE_SCAN_BUILD_NAME(TYPE_SCAN_CUSTOM_FIELD_NAME, FIELD)(        \
    HPHP::type_scan::Scanner& scanner) const                            \
    ATTRIBUTE_USED ATTRIBUTE_UNUSED EXTERNALLY_VISIBLE
#define TYPE_SCAN_FLEXIBLE_ARRAY_FIELD(FIELD)                           \
  static constexpr const                                                \
  HPHP::type_scan::detail::FlexibleArrayField                           \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_BUILD_NAME(TYPE_SCAN_FLEXIBLE_ARRAY_FIELD_NAME, FIELD){}
#define TYPE_SCAN_IGNORE_ALL                                            \
  static constexpr const                                                \
  HPHP::type_scan::detail::IgnoreField                                  \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_IGNORE_NAME{}
#define TYPE_SCAN_IGNORE_BASES(...)                                     \
  static constexpr const                                                \
  HPHP::type_scan::detail::IgnoreBase<__VA_ARGS__>                      \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_IGNORE_BASE_NAME{}
#define TYPE_SCAN_IGNORE_FIELD(FIELD)                                   \
  static constexpr const                                                \
  HPHP::type_scan::detail::IgnoreField                                  \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_BUILD_NAME(TYPE_SCAN_IGNORE_FIELD_NAME, FIELD){}
#define TYPE_SCAN_SILENCE_FORBIDDEN_BASES(...)                          \
  static constexpr const                                                \
  HPHP::type_scan::detail::SilenceForbiddenBase<__VA_ARGS__>            \
  ATTRIBUTE_USED ATTRIBUTE_UNUSED                                       \
    TYPE_SCAN_SILENCE_FORBIDDEN_BASE_NAME{}
#define TYPE_SCAN_BUILD_NAME(A,B) TYPE_SCAN_BUILD_NAME_HIDDEN(A,B)
#define TYPE_SCAN_BUILD_NAME_HIDDEN(A,B) A##B##_
#define TYPE_SCAN_CONSERVATIVE_FIELD_NAME _type_scan_conservative_field_
#define TYPE_SCAN_CONSERVATIVE_NAME _type_scan_conservative_
#define TYPE_SCAN_CUSTOM_BASES_NAME _type_scan_custom_bases_
#define TYPE_SCAN_CUSTOM_BASES_SCANNER_NAME _type_scan_custom_bases_scanner_
#define TYPE_SCAN_CUSTOM_FIELD_NAME _type_scan_custom_field_
#define TYPE_SCAN_CUSTOM_GUARD_NAME _type_scan_custom_guard_
#define TYPE_SCAN_CUSTOM_NAME _type_scan_custom_
#define TYPE_SCAN_FLEXIBLE_ARRAY_FIELD_NAME _type_scan_flexible_array_field_
#define TYPE_SCAN_IGNORE_BASE_NAME _type_scan_ignore_base_
#define TYPE_SCAN_IGNORE_FIELD_NAME _type_scan_ignore_field_
#define TYPE_SCAN_IGNORE_NAME _type_scan_ignore_
#define TYPE_SCAN_SILENCE_FORBIDDEN_BASE_NAME _type_scan_silence_forbidden_base_
#define TYPE_SCAN_STRINGIFY(X) TYPE_SCAN_STRINGIFY_HIDDEN(X)
#define TYPE_SCAN_STRINGIFY_HIDDEN(X) #X
#define AUTOLOADFLAGS() \
  N(std::string,    Query,                                        "") \
  N(std::string,    TrustedDBPath,                                "") \
  
#define E(t, n, ...) t n;
#define EVALFLAGS()                                                     \
                                         \
                                                                     \
  F(uint64_t, VMStackElms, kEvalVMStackElmsDefault)                     \
                                                                     \
  F(uint32_t, VMInitialGlobalTableSize,                                 \
    kEvalVMInitialGlobalTableSizeDefault)                               \
  F(bool, Jit,                         evalJitDefault())                \
  F(bool, JitEvaledCode,               true)                            \
  F(bool, JitRequireWriteLease,        false)                           \
  F(uint64_t, JitRelocationSize,       kJitRelocationSizeDefault)       \
  F(uint64_t, JitMatureSize,           125 << 20)                       \
  F(bool, JitMatureAfterWarmup,        false)                           \
  F(double, JitMaturityExponent,       1.)                              \
  F(bool, JitTimer,                    kJitTimerDefault)                \
  F(int, JitConcurrently,              1)                               \
  F(int, JitThreads,                   4)                               \
  F(int, JitWorkerThreads,             std::max(1, Process::GetCPUCount() / 2)) \
  F(int, JitWorkerThreadsForSerdes,    0)                               \
  F(int, JitWorkerArenas,              std::max(1, Process::GetCPUCount() / 4)) \
  F(bool, JitParallelDeserialize,      true)                            \
  F(int, JitLdimmqSpan,                8)                               \
  F(int, JitPrintOptimizedIR,          0)                               \
  F(bool, RecordSubprocessTimes,       false)                           \
  F(bool, AllowHhas,                   false)                           \
  F(bool, GenerateDocComments,         true)                            \
  F(bool, DisassemblerDocComments,     true)                            \
  F(bool, DisassemblerPropDocComments, true)                            \
  F(bool, LoadFilepathFromUnitCache,   false)                           \
  F(bool, FatalOnParserOptionMismatch, true)                            \
  F(bool, WarnOnSkipFrameLookup,       true)                            \
                                                                     \
  F(uint32_t, EnableCodeCoverage,      0)                               \
                          \
  F(bool, HackCompilerUseEmbedded,     facebook)                        \
      \
  F(bool, HackCompilerTrustExtract,    true)                            \
                                                  \
  F(string, HackCompilerExtractPath,   "/var/run/hackc_%{schema}")      \
  F(string, HackCompilerFallbackPath,  "/tmp/hackc_%{schema}_XXXXXX")   \
                       \
  F(string, HackCompilerArgs,          hackCompilerArgsDefault())       \
  \
  F(string, HackCompilerCommand,       hackCompilerCommandDefault())    \
            \
  F(uint64_t, HackCompilerWorkers,     Process::GetCPUCount())          \
                            \
  F(uint64_t, HackCompilerSecondaryWorkers, 2)                          \
                                          \
  F(uint64_t, HackCompilerMaxRetries,  0)                               \
                        \
  F(bool, LogExternCompilerPerf,       false)                           \
                                      \
  F(bool, HackCompilerVerboseErrors,   true)                            \
                                    \
  F(bool, HackCompilerInheritConfig,   true)                            \
                                                  \
  F(string, EmbeddedDataExtractPath,   "/var/run/hhvm_%{type}_%{buildid}") \
  F(string, EmbeddedDataFallbackPath,  "/tmp/hhvm_%{type}_%{buildid}_XXXXXX") \
    \
  F(bool, EmbeddedDataTrustExtract,    true)                            \
  F(bool, LogThreadCreateBacktraces,   false)                           \
  F(bool, FailJitPrologs,              false)                           \
  F(bool, UseHHBBC,                    !getenv("HHVM_DISABLE_HHBBC"))   \
     \
  F(bool, HHBBCTestCompression,        false)                           \
  F(bool, EnablePerRepoOptions,        true)                            \
  F(bool, CachePerRepoOptionsPath,     true)                            \
  F(bool, RaiseOnCaseInsensitiveLookup,true)                            \
  F(uint32_t, RaiseOnCaseInsensitiveLookupSampleRate, 1)                \
                                                                      \
  F(int32_t, CheckPropTypeHints,       1)                               \
                                                                      \
  F(int32_t, EnforceGenericsUB,        1)                               \
                                                                     \
  F(uint32_t, WarnOnTooManyArguments,  0)                               \
                                                                     \
  F(uint32_t, GetClassBadArgument,     0)                               \
                                                                     \
  F(uint32_t, WarnOnIncDecInvalidType, 0)                               \
  F(bool, EnableImplicitContext,       false)                           \
  F(bool, MoreAccurateMemStats,        true)                            \
  F(bool, AllowScopeBinding,           false)                           \
  F(bool, JitNoGdb,                    true)                            \
  F(bool, SpinOnCrash,                 false)                           \
  F(uint32_t, DumpRingBufferOnCrash,   0)                               \
  F(bool, PerfPidMap,                  true)                            \
  F(bool, PerfPidMapIncludeFilePath,   true)                            \
  F(bool, PerfJitDump,                 false)                           \
  F(string, PerfJitDumpDir,            "/tmp")                          \
  F(bool, PerfDataMap,                 false)                           \
  F(bool, KeepPerfPidMap,              false)                           \
  F(uint32_t, ThreadTCMainBufferSize,  6 << 20)                         \
  F(uint32_t, ThreadTCColdBufferSize,  6 << 20)                         \
  F(uint32_t, ThreadTCFrozenBufferSize,4 << 20)                         \
  F(uint32_t, ThreadTCDataBufferSize,  256 << 10)                       \
  F(uint32_t, JitTargetCacheSize,      64 << 20)                        \
  F(uint32_t, HHBCArenaChunkSize,      10 << 20)                        \
  F(bool, ProfileBC,                   false)                           \
  F(bool, ProfileHeapAcrossRequests,   false)                           \
  F(bool, ProfileHWEnable,             true)                            \
  F(string, ProfileHWEvents,           std::string(""))                 \
  F(bool, ProfileHWExcludeKernel,      false)                           \
  F(bool, ProfileHWFastReads,          false)                           \
  F(bool, ProfileHWStructLog,          false)                           \
  F(int32_t, ProfileHWExportInterval,  30)                              \
  F(string, ReorderProps,              reorderPropsDefault())           \
  F(bool, JitAlwaysInterpOne,          false)                           \
  F(int32_t, JitNopInterval,           0)                               \
  F(uint32_t, JitMaxTranslations,      10)                              \
  F(uint32_t, JitMaxProfileTranslations, 30)                            \
  F(uint32_t, JitTraceletGuardsLimit,  5)                               \
  F(uint64_t, JitGlobalTranslationLimit, -1)                            \
  F(int64_t, JitMaxRequestTranslationTime, -1)                          \
  F(uint32_t, JitMaxRegionInstrs,      1347)                            \
  F(uint32_t, JitMaxLiveRegionInstrs,  50)                              \
  F(uint32_t, JitMaxAwaitAllUnroll,    8)                               \
  F(bool, JitProfileWarmupRequests,    false)                           \
  F(uint32_t, JitProfileRequests,      profileRequestsDefault())        \
  F(uint32_t, JitProfileBCSize,        profileBCSizeDefault())          \
  F(uint32_t, JitResetProfCountersRequest, resetProfCountersDefault())  \
  F(uint32_t, JitRetranslateAllRequest, retranslateAllRequestDefault()) \
  F(uint32_t, JitRetranslateAllSeconds, retranslateAllSecondsDefault()) \
  F(bool,     JitPGOLayoutSplitHotCold, pgoLayoutSplitHotColdDefault()) \
  F(bool,     JitPGOVasmBlockCounters, true)                            \
  F(bool,     JitPGOVasmBlockCountersForceSaveSF, false)                \
  F(bool,     JitPGOVasmBlockCountersForceSaveGP, false)                \
  F(uint32_t, JitPGOVasmBlockCountersMaxOpMismatches, 12)               \
  F(uint32_t, JitPGOVasmBlockCountersMinEntryValue,                     \
                                       ServerExecutionMode() ? 200 : 0) \
  F(double,   JitPGOVasmBlockCountersHotWeightMultiplier, 0)            \
  F(bool, JitLayoutSeparateZeroWeightBlocks, false)                     \
  F(bool, JitLayoutPrologueSplitHotCold, layoutPrologueSplitHotColdDefault()) \
  F(bool, JitLayoutProfileSplitHotCold, true)                           \
  F(uint64_t, JitLayoutMinHotThreshold,  0)                             \
  F(uint64_t, JitLayoutMinColdThreshold, 0)                             \
  F(double,   JitLayoutHotThreshold,   0.01)                            \
  F(double,   JitLayoutColdThreshold,  0.0005)                          \
  F(int32_t,  JitLayoutMainFactor,     1000)                            \
  F(int32_t,  JitLayoutColdFactor,     5)                               \
  F(bool,     JitLayoutExtTSP,         false)                           \
  F(double,   JitLayoutMaxMergeRatio,  1000000)                         \
  F(bool,     JitAHotSizeRoundUp,      true)                            \
  F(uint32_t, GdbSyncChunks,           128)                             \
  F(bool, JitKeepDbgFiles,             false)                           \
               \
  F(bool, JitEnableRenameFunction,     EvalJitEnableRenameFunction)     \
  F(bool, JitUseVtuneAPI,              false)                           \
  F(bool, TraceCommandLineRequest,     true)                            \
                                                                        \
  F(bool, JitDisabledByHphpd,          false)                           \
  F(uint32_t, JitWarmupStatusBytes,    ((25 << 10) + 1))                \
  F(uint32_t, JitWarmupMaxCodeGenRate, 20000)                           \
  F(uint32_t, JitWarmupRateSeconds,    64)                              \
  F(uint32_t, JitWarmupMinFillFactor,  10)                              \
  F(uint32_t, JitWriteLeaseExpiration, 1500)       \
  F(int, JitRetargetJumps,             1)                               \
                           \
  F(bool, JitForceVMRegSync,           false)                           \
        \
  F(bool, LogArrayAccessProfile,      false)                            \
           \
  F(bool, LogArrayIterProfile,        false)                            \
    \
  F(double, ArrayIterSpecializationRate, 0.99)                          \
  F(bool, HHIRSimplification,          true)                            \
  F(bool, HHIRGenOpts,                 true)                            \
  F(bool, HHIRRefcountOpts,            true)                            \
  F(bool, HHIREnableGenTimeInlining,   true)                            \
  F(uint32_t, HHIRInliningCostFactorMain, 100)                          \
  F(uint32_t, HHIRInliningCostFactorCold, 32)                           \
  F(uint32_t, HHIRInliningCostFactorFrozen, 10)                         \
  F(uint32_t, HHIRInliningVasmCostLimit, 10500)                         \
  F(uint32_t, HHIRInliningMinVasmCostLimit, 10000)                      \
  F(uint32_t, HHIRInliningMaxVasmCostLimit, 40000)                      \
  F(uint32_t, HHIRAlwaysInlineVasmCostLimit, 4800)                      \
  F(uint32_t, HHIRInliningMaxDepth,    1000)                            \
  F(double,   HHIRInliningVasmCallerExp, .5)                            \
  F(double,   HHIRInliningVasmCalleeExp, .5)                            \
  F(double,   HHIRInliningDepthExp, 0)                                  \
  F(uint32_t, HHIRInliningMaxReturnDecRefs, 24)                         \
  F(uint32_t, HHIRInliningMaxReturnLocals, 40)                          \
  F(uint32_t, HHIRInliningMaxInitObjProps, 12)                          \
  F(bool,     HHIRInliningIgnoreHints, !debug)                          \
  F(bool,     HHIRInliningUseStackedCost, true)                         \
  F(bool,     HHIRInliningUseLayoutBlocks, false)                       \
  F(bool, HHIRInlineFrameOpts,         true)                            \
  F(bool, HHIRPartialInlineFrameOpts,  true)                            \
  F(bool, HHIRAlwaysInterpIgnoreHint,  !debug)                          \
  F(bool, HHIRGenerateAsserts,         false)                           \
  F(bool, HHIRDeadCodeElim,            true)                            \
  F(bool, HHIRGlobalValueNumbering,    true)                            \
  F(bool, HHIRPredictionOpts,          true)                            \
  F(bool, HHIRMemoryOpts,              true)                            \
  F(bool, AssemblerFoldDefaultValues,  true)                            \
  F(uint64_t, AssemblerMaxScalarSize,  1073741824)             \
  F(uint32_t, HHIRLoadElimMaxIters,    10)                              \
                                                            \
  F(bool, HHIRLoadEnableTeardownOpts, debug)                            \
  F(uint32_t, HHIRLoadStackTeardownMaxDecrefs, 8)                       \
  F(uint32_t, HHIRLoadThrowMaxDecrefs, 64)                              \
  F(bool, HHIRStorePRE,                true)                            \
  F(bool, HHIROutlineGenericIncDecRef, true)                            \
     \
  F(uint32_t, HHIRMaxInlineInitPackedElements, 8)                       \
  F(uint32_t, HHIRMaxInlineInitMixedElements,  4)                       \
  F(double, HHIROffsetArrayProfileThreshold, 0.85)                      \
  F(double, HHIRSmallArrayProfileThreshold, 0.8)                        \
  F(double, HHIRMissingArrayProfileThreshold, 0.8)                      \
  F(double, HHIRExitArrayProfileThreshold, 0.98)                        \
  F(double, HHIROffsetExitArrayProfileThreshold, 1.2)     \
  F(double, HHIRIsTypeStructProfileThreshold, 0.95)                     \
                                         \
  F(bool, HHIREnablePreColoring,       true)                            \
  F(bool, HHIREnableCoalescing,        true)                            \
  F(bool, HHIRAllocSIMDRegs,           true)                            \
  F(bool, HHIRStressSpill,             false)                           \
  F(bool, JitStressTestLiveness,       false)                           \
                                             \
  F(string,   JitRegionSelector,       regionSelectorDefault())         \
  F(bool,     JitPGO,                  pgoDefault())                    \
  F(string,   JitPGORegionSelector,    "hotcfg")                        \
  F(uint64_t, JitPGOThreshold,         pgoThresholdDefault())           \
  F(bool,     JitPGOOnly,              false)                           \
  F(bool,     JitPGOUsePostConditions, true)                            \
  F(bool,     JitPGOUseAddrCountedCheck, false)                         \
  F(uint32_t, JitPGOUnlikelyIncRefCountedPercent, 2)                    \
  F(uint32_t, JitPGOUnlikelyIncRefIncrementPercent, 5)                  \
  F(uint32_t, JitPGOUnlikelyDecRefReleasePercent, 5)                    \
  F(uint32_t, JitPGOUnlikelyDecRefCountedPercent, 2)                    \
  F(uint32_t, JitPGOUnlikelyDecRefPersistPercent, 5)                    \
  F(uint32_t, JitPGOUnlikelyDecRefSurvivePercent, 5)                    \
  F(uint32_t, JitPGOUnlikelyDecRefDecrementPercent, 5)                  \
  F(double,   JitPGODecRefNZReleasePercentCOW,                          \
                                       ServerExecutionMode() ? 0.5 : 0) \
  F(double,   JitPGODecRefNZReleasePercent,                             \
                                         ServerExecutionMode() ? 5 : 0) \
  F(double,   JitPGODecRefNopDecPercentCOW,                             \
                                       ServerExecutionMode() ? 0.5 : 0) \
  F(double,   JitPGODecRefNopDecPercent, ServerExecutionMode() ? 5 : 0) \
  F(bool,     JitPGOArrayGetStress,    false)                           \
  F(double,   JitPGOMinBlockCountPercent, 0.025)                        \
  F(double,   JitPGOMinArcProbability, 0.0)                             \
  F(uint32_t, JitPGOMaxFuncSizeDupBody, 80)                             \
  F(uint32_t, JitPGORelaxPercent,      100)                             \
  F(double,   JitPGOCalledFuncCheckThreshold, 50)                       \
  F(double,   JitPGOCalledFuncExitThreshold,  99.9)                     \
  F(bool,     JitPGODumpCallGraph,     false)                           \
  F(bool,     JitPGOOptCodeCallGraph,  true)                            \
  F(bool,     JitPGORacyProfiling,     false)                           \
  F(bool,     JitPGOHFSortPlus,        false)                           \
  F(uint32_t, JitLiveThreshold,       ServerExecutionMode() ? 1000 : 0) \
  F(uint32_t, JitProfileThreshold,     ServerExecutionMode() ? 200 : 0) \
  F(uint32_t, JitSrcKeyThreshold,      0)                               \
  F(uint64_t, FuncCountHint,           10000)                           \
  F(uint64_t, PGOFuncCountHint,        1000)                            \
  F(bool, RegionRelaxGuards,           true)                            \
     \
  F(int32_t, DumpBytecode,             0)                               \
         \
  F(int32_t, DumpHhas,                 0)                               \
  F(string, DumpHhasToFile,            "")                              \
  F(bool, DumpTC,                      false)                           \
  F(string, DumpTCPath,                "/tmp")                          \
  F(bool, DumpTCAnchors,               false)                           \
  F(uint32_t, DumpIR,                  0)                               \
  F(uint32_t, DumpIRJson,             0)                               \
  F(bool, DumpTCAnnotationsForAllTrans,debug)                           \
            \
  F(uint32_t, DumpInlDecision,         0)                               \
  F(uint32_t, DumpRegion,              0)                               \
  F(bool,     DumpCallTargets,         false)                           \
  F(bool,     DumpLayoutCFG,           false)                           \
  F(bool,     DumpVBC,                 false)                           \
  F(bool,     DumpArrAccProf,          false)                           \
  F(bool, DumpAst,                     false)                           \
  F(bool, DumpTargetProfiles,          false)                           \
  F(bool, MapTgtCacheHuge,             false)                           \
  F(bool, NewTHPHotText,               false)                           \
  F(bool, FileBackedColdArena,         useFileBackedArenaDefault())     \
  F(string, ColdArenaFileDir,          "/tmp")                          \
  F(uint32_t, MaxHotTextHugePages,     hotTextHugePagesDefault())       \
  F(uint32_t, MaxLowMemHugePages,      hugePagesSoundNice() ? 8 : 0)    \
  F(uint32_t, MaxHighArenaHugePages,   0)                               \
  F(uint32_t, Num1GPagesForSlabs,      0)                               \
  F(uint32_t, Num2MPagesForSlabs,      0)                               \
  F(uint32_t, Num1GPagesForReqHeap,    0)                               \
  F(uint32_t, Num2MPagesForReqHeap,    0)                               \
  F(uint32_t, NumReservedSlabs,        0)                               \
  F(uint32_t, Num1GPagesForA0,         0)                               \
  F(uint32_t, Num2MPagesForA0,         0)                               \
  F(bool, BigAllocUseLocalArena,       true)                            \
  F(bool, JsonParserUseLocalArena,     true)                            \
  F(bool, XmlParserUseLocalArena,      true)                            \
  F(bool, LowStaticArrays,             true)                            \
  F(int64_t, HeapPurgeWindowSize,      5 * 1000000)                     \
  F(uint64_t, HeapPurgeThreshold,      128 * 1024 * 1024)               \
                 \
  F(bool, EagerGC,                     eagerGcDefault())                \
  F(bool, FilterGCPoints,              true)                            \
  F(bool, Quarantine,                  eagerGcDefault())                \
  F(bool, HeapAllocSampleNativeStack,  false)                           \
  F(bool, LogKilledRequests,           true)                            \
  F(uint32_t, GCSampleRate,            0)                               \
  F(uint32_t, HeapAllocSampleRequests, 0)                               \
  F(uint32_t, HeapAllocSampleBytes,    256 * 1024)                      \
  F(uint32_t, SlabAllocAlign,          64)                              \
  F(int64_t, GCMinTrigger,             64L<<20)                         \
  F(double, GCTriggerPct,              0.5)                             \
  F(bool, TwoPhaseGC,                  false)                           \
  F(bool, EnableGC,                    enableGcDefault())               \
                                                 \
  F(bool, Verify,                      (getenv("HHVM_VERIFY") ||        \
    !EvalHackCompilerCommand.empty()))                                  \
  F(bool, VerifyOnly,                  false)                           \
  F(bool, FatalOnVerifyError,          !RepoAuthoritative)              \
  F(bool, AbortBuildOnVerifyError,     true)                            \
  F(bool, AbortBuildOnCompilerError,   true)                            \
  F(uint32_t, StaticContentsLogRate,   100)                             \
  F(uint32_t, LogUnitLoadRate,         0)                               \
  F(uint32_t, MaxDeferredErrors,       50)                              \
  F(bool, JitAlignMacroFusionPairs, alignMacroFusionPairs())            \
  F(bool, JitAlignUniqueStubs,         true)                            \
  F(uint32_t, SerDesSampleRate,            0)                           \
  F(bool, JitSerdesModeForceOff,       false)                           \
  F(bool, JitDesUnitPreload,           false)                           \
  F(std::set<std::string>, JitSerdesDebugFunctions, {})                 \
  F(uint32_t, JitSerializeOptProfSeconds, ServerExecutionMode() ? 300 : 0)\
  F(uint32_t, JitSerializeOptProfRequests, 0)                           \
  F(int, SimpleJsonMaxLength,        2 << 20)                           \
  F(uint32_t, JitSampleRate,               0)                           \
  F(uint32_t, TraceServerRequestRate,      0)                           \
                                                   \
                         \
  F(uint32_t, TracingSampleRate,              0)                        \
                          \
  F(uint32_t, TracingPerRequestCount,         0)                        \
  F(uint32_t, TracingPerRequestSampleRate,    0)                        \
                  \
  F(uint32_t, TracingFirstRequestsCount,      0)                        \
  F(uint32_t, TracingFirstRequestsSampleRate, 0)                        \
                       \
  F(std::string, ArtilleryTracePolicy, "")                              \
           \
  F(std::string, TracingTagId, "")                                      \
                                         \
  F(string,   JitLogAllInlineRegions,  "")                              \
  F(bool, JitProfileGuardTypes,        false)                           \
  F(uint32_t, JitFilterLease,          1)                               \
  F(uint32_t, PCRETableSize, kPCREInitialTableSize)                     \
  F(uint64_t, PCREExpireInterval, 2 * 60 * 60)                          \
  F(string, PCRECacheType, std::string("static"))                       \
  F(bool, EnableCompactBacktrace, true)                                 \
  F(bool, EnableNuma, (numa_num_nodes > 1) && ServerExecutionMode())    \
                               \
  F(bool, EnableArenaMetadata1GPage, false)                             \
   \
  F(bool, EnableNumaArenaMetadata1GPage, false)                         \
        \
  F(uint64_t, ArenaMetadataReservedSize, 216 << 20)                     \
  F(bool, EnableCallBuiltin, true)                                      \
  F(bool, EnableReusableTC,   reuseTCDefault())                         \
  F(bool, LogServerRestartStats, false)                                 \
   \
  F(uint32_t, ReusableTCPadding, 128)                                   \
  F(int64_t,  StressUnitCacheFreq, 0)                                   \
   \
  F(int64_t, PerfWarningSampleRate, 1)                                  \
  F(int64_t, SelectHotCFGSampleRate, 100)                               \
  F(int64_t, FunctionCallSampleRate, 0)                                 \
  F(double, InitialLoadFactor, 1.0)                                     \
         \
  F(int32_t, BespokeArrayLikeMode, 0)                                   \
  F(uint64_t, EmitLoggingArraySampleRate, 1000)                         \
  F(string, ExportLoggingArrayDataPath, "")                             \
            \
  F(bool, HackArrCompatNotices, false)                                  \
  F(bool, HackArrCompatCheckCompare, false)                             \
  F(bool, HackArrCompatFBSerializeHackArraysNotices, false)             \
    \
  F(bool, HackArrCompatIntishCastNotices, false)                        \
   \
  F(bool, HackArrCompatIsVecDictNotices, false)                         \
  F(bool, HackArrCompatSerializeNotices, false)                         \
           \
  F(bool, HackArrCompatCompactSerializeNotices, false)                  \
           \
  F(bool, HackArrCompatCastMarkedArrayNotices, false)                   \
          \
  F(bool, HackArrDVArrMark, false)                                      \
               \
  F(bool, HackArrDVArrVarExport, false)                                 \
                            \
  F(bool, HackArrDVArrs, false)                                         \
          \
  F(bool, HackArrIsShapeTupleNotices, false)                            \
                                  \
  F(bool, ArrayProvenance, false)                                       \
                     \
  F(bool, LogArrayProvenance, false)                                    \
      \
  F(uint32_t, LogArrayProvenanceSampleRatio, 1000)                      \
   \
  F(uint32_t, ArrayProvenanceLargeEnumLimit, 256)                       \
                          \
  F(uint32_t, LogArrayProvenanceDiagnosticsSampleRate, 0)               \
                \
  F(bool, DictDArrayAppendNotices, true)                                \
                                                          \
  F(bool, IsExprEnableUnresolvedWarning, false)                         \
             \
  F(bool, ClassIsStringNotices, false)                                  \
                                                            \
  F(bool, ClassStringHintNotices, false)                                \
    \
  F(bool, IsVecNotices, false)                                          \
                                             \
  F(bool, VecHintNotices, false)                                        \
                                   \
  F(bool, NoticeOnCreateDynamicProp, false)                             \
  F(bool, NoticeOnReadDynamicProp, false)                               \
  F(bool, NoticeOnImplicitInvokeToString, false)                        \
  F(bool, FatalOnConvertObjectToString, false)                          \
  F(bool, NoticeOnBuiltinDynamicCalls, false)                           \
  F(bool, RxPretendIsEnabled, false)                                    \
            \
  F(bool, RaiseClassConversionWarning, false)                           \
  F(bool, EmitClsMethPointers, true)                                    \
                             \
  F(int32_t, EmitClassPointers, 0)                                      \
          \
  F(bool, IsCompatibleClsMethType, false)                               \
       \
  F(bool, RaiseClsMethComparisonWarning, false)                         \
          \
  F(bool, RaiseClsMethConversionWarning, false)                         \
                   \
  F(bool, RaiseStrToClsConversionWarning, false)                        \
  F(bool, EmitMethCallerFuncPointers, false)                            \
                           \
  F(bool, NoticeOnMethCallerHelperUse, false)                           \
  F(bool, NoticeOnCollectionToBool, false)                              \
  F(bool, NoticeOnSimpleXMLBehavior, false)                             \
  F(bool, ForbidDivisionByZero, true)                                   \
                                             \
  F(bool, HackRecords, false)                                           \
                                                                     \
  F(int32_t, ForbidDynamicCallsToFunc, 0)                               \
  F(int32_t, ForbidDynamicCallsToClsMeth, 0)                            \
  F(int32_t, ForbidDynamicCallsToInstMeth, 0)                           \
  F(int32_t, ForbidDynamicConstructs, 0)                                \
                                                                     \
  F(bool, ForbidDynamicCallsWithAttr, false)                            \
              \
  F(bool, LogKnownMethodsAsDynamicCalls, true)                          \
                                                                     \
  F(int32_t, ForbidUnserializeIncompleteClass, 0)                       \
  F(int32_t, RxEnforceCalls, 0)                                         \
  F(int32_t, PureEnforceCalls, 0)                                       \
                                                                     \
  F(int32_t, RxVerifyBody, 0)                                           \
  F(int32_t, PureVerifyBody, 0)                                         \
  F(bool, RxIsEnabled, EvalRxPretendIsEnabled)                          \
                                                                     \
  F(int32_t, FixDefaultArgReflection, 1)                                \
  F(int32_t, ServerOOMAdj, 0)                                           \
  F(std::string, PreludePath, "")                                       \
  F(uint32_t, NonSharedInstanceMemoCaches, 10)                          \
  F(bool, UseGraphColor, true)                                          \
  F(std::vector<std::string>, IniGetHide, std::vector<std::string>())   \
  F(std::string, UseRemoteUnixServer, "no")                             \
  F(std::string, UnixServerPath, "")                                    \
  F(uint32_t, UnixServerWorkers, Process::GetCPUCount())                \
  F(bool, UnixServerQuarantineApc, false)                               \
  F(bool, UnixServerQuarantineUnits, false)                             \
  F(bool, UnixServerVerifyExeAccess, false)                             \
  F(bool, UnixServerFailWhenBusy, false)                                \
  F(std::vector<std::string>, UnixServerAllowedUsers,                   \
                                            std::vector<std::string>()) \
  F(std::vector<std::string>, UnixServerAllowedGroups,                  \
                                            std::vector<std::string>()) \
                                               \
  F(bool, TrashFillOnRequestExit, false)                                \
                                                     \
  F(bool, JitArmLse, armLseDefault())                                   \
                                                     \
                                 \
  F(uint16_t, PPC64MinTOCImmSize, 64)                                   \
                  \
                \
  F(bool, PPC64RelocationShrinkFarBranches, false)                      \
                                   \
  F(bool, PPC64RelocationRemoveFarBranchesNops, true)                   \
                                                  \
             \
  F(bool, EnableReverseDataMap, true)                                   \
           \
  F(uint32_t, PerfMemEventRequestFreq, 0)                               \
                                     \
  F(uint32_t, PerfMemEventSampleFreq, 80)                               \
                       \
  F(uint32_t, ProfBranchSampleFreq, 0)                                  \
           \
  F(uint32_t, ProfPackedArraySampleFreq, 0)                             \
  F(bool, UseXedAssembler, false)                                       \
   \
  F(uint64_t, RecordFirstUnits, 0)                                      \
   \
  F(bool, CheckUnitSHA1, true)                                          \
  F(bool, ReuseUnitsByHash, false)                                      \
                                                         \
  F(uint64_t, DynamicFunLevel, 1)                                       \
                                                         \
  F(uint64_t, DynamicClsMethLevel, 1)                                   \
  F(bool, APCSerializeFuncs, true)                                      \
                                                                     \
  F(bool, EnablePerFileCoverage, false)                                 \
  F(bool, LogOnIsArrayFunction, false)                                  \
                                          \
  F(uint32_t, UnitPrefetcherMaxThreads, 0)                              \
  F(uint32_t, UnitPrefetcherMinThreads, 0)                              \
  F(uint32_t, UnitPrefetcherIdleThreadTimeoutSecs, 60)                  \
                        \
  F(uint32_t, IdleUnitTimeoutSecs, 0)                                   \
                            \
  F(uint32_t, IdleUnitMinThreshold, 0)                                  \
  
#define F(type, name, unused) \
  static type Eval ## name;
#define H(t, n, ...) t n;
#define HAC_CHECK_OPTS                         \
  HC(Compare, compare)                         \
  HC(ArrayKeyCast, array_key_cast)
#define N(t, n, ...) t n;
#define P(t, n, ...) t n;
#define PARSERFLAGS() \
  N(StringMap,      AliasedNamespaces,                StringMap{})    \
  P(bool,           UVS,                              s_PHP7_master)  \
  P(bool,           LTRAssign,                        s_PHP7_master)  \
  H(bool,           EnableCoroutines,                 true)           \
  H(bool,           Hacksperimental,                  false)          \
  H(bool,           DisableLvalAsAnExpression,        false)          \
  H(bool,           AllowNewAttributeSyntax,          false)          \
  H(bool,           ConstDefaultFuncArgs,             false)          \
  H(bool,           ConstStaticProps,                 false)          \
  H(bool,           AbstractStaticProps,              false)          \
  H(bool,           DisableUnsetClassConst,           false)          \
  H(bool,           DisallowFuncPtrsInConstants,      false)          \
  E(bool,           EmitInstMethPointers,             false)          \
  H(bool,           AllowUnstableFeatures,            false)          \
  H(bool,           DisallowHashComments,             false)          \
  H(bool,           EnableXHPClassModifier,           true)           \
  H(bool,           DisableXHPElementMangling,        true)           \
  H(bool,           DisableArray,                     true)           \
  H(bool,           DisableArrayCast,                 true)           \
  H(bool,           DisableArrayTypehint,             true)           \
  H(bool,           EnableEnumClasses,                false)          \
  H(bool,           DisallowFunAndClsMethPseudoFuncs, false)          \
  
#define BIG_CONSTANT(x) (x##LLU)
#define ROTL64(x,y) rotl64(x,y)
#    define USE_HWCRC
#define init_null_variant tvAsCVarRef(&immutable_null_base)
#define uninit_variant    tvAsCVarRef(&immutable_uninit_base)
#define X(dt, cpp) \
template<> struct DataTypeCPPType<dt> { using type = cpp; }
# define CASE(name) case DataType##name: return "DataType" #name;
#define DATATYPES \
  DT(PersistentDArray, -14) \
  DT(DArray,           -13) \
  DT(PersistentVArray, -12) \
  DT(VArray,           -11) \
  DT(PersistentDict,   -10) \
  DT(Dict,              -9) \
  DT(PersistentVec,     -8) \
  DT(Vec,               -7) \
  DT(PersistentKeyset,  -6) \
  DT(Keyset,            -5) \
  DT(Record,            -3) \
  DT(PersistentString,  -2) \
  DT(String,            -1) \
  DT(Uninit,             0) \
   \
  DT(Null,               2) \
  DT(Object,             3) \
  DT(Boolean,            4) \
  DT(Resource,           5) \
  DT(Int64,              6) \
  DT(Double,             8) \
  DT(RFunc,              9) \
  DT(Func,              10) \
  DT(RClsMeth,          11) \
  DT(Class,             12) \
  DT(ClsMeth,           use_lowptr ? 14 : 7) \
  DT(LazyClass,         16)
#define DT(name, ...) auto constexpr KindOf##name = DataType::name;
#define DT_CATEGORIES(func)                     \
  func(Generic)                                 \
  func(IterBase)                                \
  func(CountnessInit)                           \
  func(Specific)                                \
  func(Specialized)
#define DT_UNCOUNTED_CASE   \
  case KindOfUninit:        \
  case KindOfNull:          \
  case KindOfBoolean:       \
  case KindOfInt64:         \
  case KindOfDouble:        \
  case KindOfPersistentString:  \
  case KindOfPersistentVArray:  \
  case KindOfPersistentDArray:  \
  case KindOfPersistentVec: \
  case KindOfPersistentDict: \
  case KindOfPersistentKeyset: \
  case KindOfFunc:          \
  case KindOfClass:         \
  case KindOfLazyClass
#define dt_t(t) static_cast<data_type_t>(t)
#define FORCE_HASH_AT 10
#define incl_HPHP_NEO_HDF_H_ 1
#define incl_HPHP_NEO_HASH_H_ 1
#define MIN(x,y)        (((x) < (y)) ? (x) : (y))
#define PATH_BUF_SIZE 512
#define S_IRGRP S_IRUSR
#define S_IROTH S_IRUSR
#define S_IRUSR _S_IREAD
#define S_IWGRP S_IWUSR
#define S_IWOTH S_IWUSR
#define S_IWUSR _S_IWRITE
#define S_IXGRP S_IXUSR
#define S_IXOTH S_IXUSR
#define S_IXUSR 0
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#define incl_HPHP_NEO_MISC_H_ 1
#define HAVE_DRAND48 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_GMTIME_R 1
#define HAVE_LOCALTIME_R 1
#define HAVE_MKSTEMP 1
#define HAVE_PTHREADS 1
#define HAVE_RANDOM 1
#define HAVE_SNPRINTF 1
#define HAVE_STRTOK_R 1
#define HAVE_VSNPRINTF 1
#define incl_HPHP_CS_CONFIG_H_ 1
#define INTERNAL_ERR ((NEOERR *)1)
#define INTERNAL_ERR_INT 1
#define NE_IN_USE (1<<0)
#define STATUS_OK ((NEOERR *)0)
#define STATUS_OK_INT 0
#define USE_C99_VARARG_MACROS 1
#define USE_GNUC_VARARG_MACROS 1
#define __PRETTY_FUNCTION__ "unknown_function"
#define incl_HPHP_NEO_ERR_H_ 1
#define nerr_pass(e) \
   nerr_passf(__PRETTY_FUNCTION__,"__FILE__","__LINE__",e)
#define nerr_pass_ctx(e,...) \
   nerr_pass_ctxf(__PRETTY_FUNCTION__,"__FILE__","__LINE__",e,__VA_ARGS__)
#define nerr_raise(e,...) \
   nerr_raisef(__PRETTY_FUNCTION__,"__FILE__","__LINE__",e,__VA_ARGS__)
#define nerr_raise_errno(e,...) \
   nerr_raise_errnof(__PRETTY_FUNCTION__,"__FILE__","__LINE__",e,__VA_ARGS__)
#define incl_HPHP_NEO_STR_H_ 1
#define FALSE 0
#define TRUE 1
#define incl_HPHP_NEO_BOOL_H_ 1
#define FTRACE(n, ...)                                        \
  ONTRACE(n, HPHP::Trace::trace("%s",                         \
             folly::format(__VA_ARGS__).str().c_str()))
#define FTRACE_MOD(mod, level, ...)                     \
  ONTRACE_MOD(mod, level, HPHP::Trace::trace("%s",      \
             folly::format(__VA_ARGS__).str().c_str()))

#define ITRACE(level, ...) ONTRACE((level), Trace::itraceImpl(__VA_ARGS__));
#define ITRACE_MOD(mod, level, ...)                             \
  ONTRACE_MOD(mod, level, Trace::itraceImpl(__VA_ARGS__));
#define ONTRACE(...)      do { } while (0)
#define ONTRACE_MOD(module, n, x) do {    \
  if (HPHP::Trace::moduleEnabled(module, n)) {  \
    x;                                          \
  } } while(0)
#define TM(x) \
  x,
#define TRACE(...)        do { } while (0)
#define TRACE_MOD(mod, level, ...) \
  ONTRACE_MOD(mod, level, HPHP::Trace::trace(__VA_ARGS__))
#define TRACE_MODULES \
      TM(tprefix)       \
      TM(traceAsync)   \
      TM(apc)           \
      TM(asmx64)        \
      TM(asmppc64)      \
      TM(atomicvector)  \
      TM(bcinterp)      \
      TM(bespoke)       \
      TM(bisector)      \
      TM(class_load)    \
      TM(cti)           \
      TM(datablock)     \
      TM(debugger)      \
      TM(debuggerflow)  \
      TM(debuginfo)     \
      TM(decreftype)    \
      TM(disas)         \
      TM(dispatchBB)    \
      TM(ehframe)       \
      TM(emitter)       \
      TM(extern_compiler) \
      TM(fixup)         \
      TM(fr)            \
      TM(funcorder)     \
      TM(gc)            \
      TM(heapgraph)     \
      TM(heapreport)    \
      TM(hfsort)        \
      TM(hhas)          \
      TM(hhbbc)         \
      TM(hhbbc_cfg)     \
      TM(hhbbc_dce)     \
      TM(hhbbc_dump)    \
      TM(hhbbc_parse)   \
      TM(hhbbc_emit)    \
      TM(hhbbc_iface)   \
      TM(hhbbc_index)   \
      TM(hhbbc_mem)     \
      TM(hhbbc_stats)   \
      TM(hhbbc_time)    \
      TM(hhbc)          \
      TM(hhir)          \
      TM(hhirTracelets) \
      TM(hhir_alias)    \
      TM(hhir_cfg)      \
      TM(hhir_checkhoist) \
      TM(hhir_dce)      \
      TM(hhir_fixhint)  \
      TM(hhir_fsm)      \
      TM(hhir_gvn)      \
      TM(hhir_licm)     \
      TM(hhir_load)     \
      TM(hhir_loop)     \
      TM(hhir_phi)      \
      TM(hhir_refcount) \
      TM(hhir_refineTmps) \
      TM(hhir_store)    \
      TM(hhir_unreachable) \
      TM(hhir_vanilla)  \
      TM(hhprof)        \
      TM(inlining)      \
      TM(instancebits)  \
      TM(intercept)     \
      TM(interpOne)     \
      TM(irlower)       \
      TM(jittime)       \
      TM(layout)        \
      TM(libxml)        \
      TM(logging)       \
      TM(mcg)           \
      TM(mcgstats)      \
      TM(minstr)        \
      TM(mm)            \
      TM(objprof)       \
      TM(perf_mem_event) \
      TM(pgo)           \
      TM(print_profiles)  \
      TM(printir)       \
      TM(printir_json)  \
      TM(prof_branch)   \
      TM(prof_array)    \
      TM(prof_prop)     \
      TM(rat)           \
      TM(refcount)      \
      TM(regalloc)      \
      TM(region)        \
      TM(repo_autoload) \
      TM(reusetc)       \
      TM(ringbuffer)    \
      TM(runtime)       \
      TM(servicereq)    \
      TM(simplify)      \
      TM(stat)          \
      TM(statgroups)    \
      TM(stats)         \
      TM(strobelight)   \
      TM(targetcache)   \
      TM(tcspace)       \
      TM(trans)         \
      TM(treadmill)     \
      TM(txdeps)        \
      TM(txlease)       \
      TM(typeProfile)   \
      TM(unwind)        \
      TM(ustubs)        \
      TM(vasm)          \
      TM(vasm_block_count) \
      TM(vasm_copy)     \
      TM(vasm_graph_color) \
      TM(vasm_phi)      \
      TM(watchman_autoload) \
      TM(xenon)         \
      TM(xls)           \
      TM(xls_stats)     \
      TM(pdce_inline)   \
      TM(clisrv)        \
      TM(factparse)     \
      TM(bccache)       \
      TM(idx)           \
       \
      TM(stress_txInterpPct)  \
      TM(stress_txInterpSeed) \
       \
      TM(txOpBisectLow)   \
      TM(txOpBisectHigh)  \
       \
      TM(tmp0)  TM(tmp1)  TM(tmp2)  TM(tmp3)               \
      TM(tmp4)  TM(tmp5)  TM(tmp6)  TM(tmp7)               \
      TM(tmp8)  TM(tmp9)  TM(tmp10) TM(tmp11)              \
      TM(tmp12) TM(tmp13) TM(tmp14) TM(tmp15)
#define TRACE_RB(n, ...)                                        \
  ONTRACE(n, HPHP::Trace::traceRingBufferRelease(__VA_ARGS__)); \
  TRACE(n, __VA_ARGS__);
#define TRACE_SET_MOD(name)  \
  UNUSED static const HPHP::Trace::Module TRACEMOD = HPHP::Trace::name;
#    define USE_TRACE 1
#define THREAD_LOCAL(T, f) __thread HPHP::ThreadLocal<T> f
#define THREAD_LOCAL_FLAT(T, f) __thread HPHP::ThreadLocalFlat<T> f
#define THREAD_LOCAL_NO_CHECK(T, f) __thread HPHP::ThreadLocalNoCheck<T> f

#define DECLARE_EXTERN_REQUEST_LOCAL(T,f)    \
  extern ::HPHP::rds::local::RDSLocal< \
    T, \
    ::HPHP::rds::local::Initialize::FirstUse \
  > f
#define DECLARE_RDS_LOCAL_HOTVALUE(T, f) \
  struct RLHotWrapper_ ## f { \
    RLHotWrapper_ ## f& operator=(T&& v) { \
      ::HPHP::rds::local::detail::rl_hotSection.f = v; \
      return *this; \
    } \
    operator T&() { \
      return ::HPHP::rds::local::detail::rl_hotSection.f; \
    } \
  } f;
#define DECLARE_STATIC_REQUEST_LOCAL(T,f)    \
  static ::HPHP::rds::local::RDSLocal< \
    T, \
    ::HPHP::rds::local::Initialize::FirstUse \
  > f
#define IMPLEMENT_RDS_LOCAL_HOTVALUE(T, f) \
  RLHotWrapper_ ## f f;
#define IMPLEMENT_REQUEST_LOCAL(T,f)     \
  ::HPHP::rds::local::RDSLocal<T, ::HPHP::rds::local::Initialize::FirstUse> f
#define IMPLEMENT_STATIC_REQUEST_LOCAL(T,f)     \
  static ::HPHP::rds::local::RDSLocal< \
    T, \
    ::HPHP::rds::local::Initialize::FirstUse \
  > f
#define RDS_LOCAL(T, f) \
  ::HPHP::rds::local::RDSLocal<T, ::HPHP::rds::local::Initialize::FirstUse> f
#define RDS_LOCAL_NO_CHECK(T, f) \
  ::HPHP::rds::local::RDSLocal<T, ::HPHP::rds::local::Initialize::Explicitly> f


#define GDHELPERS_H 1
#define gdCalloc(nmemb, size) HPHP::req::calloc_noptrs(nmemb, size)
#define gdFree(ptr)           HPHP::req::free(ptr)
#define gdMalloc(size)        HPHP::req::malloc_noptrs(size)
#define gdMutexDeclare(x) pthread_mutex_t x
#define gdMutexLock(x) pthread_mutex_lock(&x)
#define gdMutexSetup(x) pthread_mutex_init(&x, 0)
#define gdMutexShutdown(x) pthread_mutex_destroy(&x)
#define gdMutexUnlock(x) pthread_mutex_unlock(&x)
#define gdPEstrdup(ptr)       strdup(ptr)
#define gdPFree(ptr)          free(ptr)
#define gdPMalloc(ptr)        malloc(ptr)
#define gdRealloc(ptr, size)  HPHP::req::realloc_noptrs(ptr, size)
#define DEFAULT_FONTPATH "sys:/java/nwgfx/lib/x11/fonts/ttf;."
#define E_ERROR        (1<<0L)
#define E_NOTICE       (1<<3L)
#define E_WARNING      (1<<1L)
#define GD2_CHUNKSIZE           128
#define GD2_CHUNKSIZE_MAX       4096
#define GD2_CHUNKSIZE_MIN 64
#define GD2_FMT_COMPRESSED      2
#define GD2_FMT_RAW             1
#define GD2_ID                  "gd2"
#define GD2_VERS                2
#define GD_CMP_BACKGROUND 64  
#define GD_CMP_COLOR    4 
#define GD_CMP_IMAGE    1 
#define GD_CMP_INTERLACE  128 
#define GD_CMP_NUM_COLORS 2 
#define GD_CMP_SIZE_X   8 
#define GD_CMP_SIZE_Y   16  
#define GD_CMP_TRANSPARENT  32  
#define GD_CMP_TRUECOLOR  256 
#define GD_EPSILON 1e-6
#define GD_EXTRA_VERSION ""
#define GD_FALSE 0
#define GD_FLIP_BOTH 3
#define GD_FLIP_HORINZONTAL 1
#define GD_FLIP_VERTICAL 2
#define GD_H 1
#define GD_MAJOR_VERSION 2
#define GD_MINOR_VERSION 0
#define GD_RELEASE_VERSION 35
#define GD_RESOLUTION           96      
#define GD_TRUE 1
#define GD_VERSION_STRING "2.0.35"
#define PATHSEPARATOR ";"
#define gdAlphaMax 127
#define gdAlphaOpaque 0
#define gdAlphaTransparent 127
#define gdAntiAliased (-7)
#define gdArc   0
#define gdBlueMax 255
#define gdBrushed (-3)
#define gdChord 1
#define gdDashSize 4
#define gdEdged 4
#define gdEffectAlphaBlend 1
#define gdEffectNormal 2
#define gdEffectOverlay 3
#define gdEffectReplace 0
#define gdFTEX_Big5 2
#define gdFTEX_CHARMAP 2
#define gdFTEX_LINESPACE 1
#define gdFTEX_MacRoman 3
#define gdFTEX_RESOLUTION 4
#define gdFTEX_Shift_JIS 1
#define gdFTEX_Unicode 0
#define gdGreenMax 255
#define gdImageAlpha(im, c) ((im)->trueColor ? gdTrueColorGetAlpha(c) : \
  (im)->alpha[(c)])
#define gdImageBlue(im, c) ((im)->trueColor ? gdTrueColorGetBlue(c) : \
  (im)->blue[(c)])
#define gdImageBoundsSafe(im, x, y) (!((((y) < (im)->cy1) || ((y) > (im)->cy2)) || (((x) < (im)->cx1) || ((x) > (im)->cx2))))
#define gdImageColorsTotal(im) ((im)->colorsTotal)
#define gdImageCreatePalette gdImageCreate
#define gdImageGetInterlaced(im) ((im)->interlace)
#define gdImageGetTransparent(im) ((im)->transparent)
#define gdImageGreen(im, c) ((im)->trueColor ? gdTrueColorGetGreen(c) : \
  (im)->green[(c)])
#define gdImagePalettePixel(im, x, y) (im)->pixels[(y)][(x)]
#define gdImageRed(im, c) ((im)->trueColor ? gdTrueColorGetRed(c) : \
  (im)->red[(c)])
#define gdImageSX(im) ((im)->sx)
#define gdImageSY(im) ((im)->sy)
#define gdImageTrueColor(im) ((im)->trueColor)
#define gdImageTrueColorPixel(im, x, y) (im)->tpixels[(y)][(x)]
#define gdMaxColors 256
#define gdNoFill 2
#define gdPie   gdArc
#define gdRedMax 255
#define gdStyled (-2)
#define gdStyledBrushed (-4)
#define gdTiled (-5)
#define gdTransparent (-6)
#define gdTrueColor(r, g, b) ((((r) & 0xff) << 16) +    \
                              (((g) & 0xff) << 8) +     \
                              ((b) & 0xff))
#define gdTrueColorAlpha(r, g, b, a) ((((a) & 0xff) << 24) +    \
                                      (((r) & 0xff) << 16) +    \
                                      (((g) & 0xff) << 8) +     \
                                      ((b) & 0xff))
#define gdTrueColorGetAlpha(c) (((c) & 0x7F000000) >> 24)
#define gdTrueColorGetBlue(c) ((c) & 0x0000FF)
#define gdTrueColorGetGreen(c) (((c) & 0x00FF00) >> 8)
#define gdTrueColorGetRed(c) (((c) & 0xFF0000) >> 16)
#define GD_IO_H 1
#define Putchar gdPutchar
#define APC_MMAP 1
#define APC_PTHREADMUTEX_LOCKS 1
#define APC_REQFILES 1
#define COOKIE_IO_FUNCTIONS_T cookie_io_functions_t
#define COOKIE_SEEKER_USES_OFF64_T 1
#define DEFAULT_SHORT_OPEN_TAG "1"
#define HAVE_ACOSH 1
#define HAVE_ALLOCA 1
#define HAVE_ALLOCA_H 1
#define HAVE_ALPHASORT 1
#define HAVE_APACHE 1
#define HAVE_APC 1
#define HAVE_AP_COMPAT_H 1
#define HAVE_AP_CONFIG_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_ARPA_NAMESER_H 1
#define HAVE_ASCTIME_R 1
#define HAVE_ASINH 1
#define HAVE_ASSERT_H 1
#define HAVE_ATANH 1
#define HAVE_ATOF_ACCEPTS_INF 1
#define HAVE_ATOF_ACCEPTS_NAN 1
#define HAVE_ATOLL 1
#define HAVE_BCMATH 1
#define HAVE_BROKEN_GLIBC_FOPEN_APPEND 1
#define HAVE_BUILD_DEFS_H 1
#define HAVE_BUNDLED_PCRE 1
#define HAVE_CHROOT 1
#define HAVE_CMSGHDR 1
#define HAVE_COLORCLOSESTHWB 1
#define HAVE_CRYPT 1
#define HAVE_CRYPT_H 1
#define HAVE_CTIME_R 1
#define HAVE_CTYPE 1
#define HAVE_CURL 1
#define HAVE_CURL_EASY_STRERROR 1
#define HAVE_CURL_MULTI_STRERROR 1
#define HAVE_CURL_OPENSSL 1
#define HAVE_CURL_SSL 1
#define HAVE_CURL_VERSION_INFO 1
#define HAVE_CUSERID 1
#define HAVE_DECLARED_TIMEZONE 1
#define HAVE_DEV_URANDOM 1
#define HAVE_DIRENT_H 1
#define HAVE_DLFCN_H 1
#define HAVE_DLOPEN 1
#define HAVE_DN_EXPAND 1
#define HAVE_DN_SKIPNAME 1
#define HAVE_DOM 1
#define HAVE_ERRNO_H 1
#define HAVE_EXIF 1
#define HAVE_FABSF 1
#define HAVE_FCNTL_H 1
#define HAVE_FINITE 1
#define HAVE_FLOCK 1
#define HAVE_FLOORF 1
#define HAVE_FNMATCH 1
#define HAVE_FOPENCOOKIE 1
#define HAVE_FORK 1
#define HAVE_FTOK 1
#define HAVE_GAI_STRERROR 1
#define HAVE_GCVT 1
#define HAVE_GDIMAGECOLORRESOLVE 1
#define HAVE_GD_BUNDLED 1
#define HAVE_GD_DYNAMIC_CTX_EX 1
#define HAVE_GD_FONTCACHESHUTDOWN 1
#define HAVE_GD_FONTMUTEX 1
#define HAVE_GD_GD2 1
#define HAVE_GD_GIF_CREATE 1
#define HAVE_GD_GIF_CTX 1
#define HAVE_GD_GIF_READ 1
#define HAVE_GD_IMAGEELLIPSE 1
#define HAVE_GD_IMAGESETBRUSH 1
#define HAVE_GD_IMAGESETTILE 1
#define HAVE_GD_STRINGFT 1
#define HAVE_GD_STRINGFTEX 1
#define HAVE_GD_WBMP 1
#define HAVE_GD_XBM 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETCWD 1
#define HAVE_GETGRNAM_R 1
#define HAVE_GETHOSTBYADDR 1
#define HAVE_GETHOSTBYNAME2 1
#define HAVE_GETHOSTNAME 1
#define HAVE_GETLOADAVG 1
#define HAVE_GETLOGIN 1
#define HAVE_GETOPT 1
#define HAVE_GETPID 1
#define HAVE_GETPROTOBYNAME 1
#define HAVE_GETPROTOBYNUMBER 1
#define HAVE_GETPWNAM_R 1
#define HAVE_GETPWUID_R 1
#define HAVE_GETRUSAGE 1
#define HAVE_GETSERVBYNAME 1
#define HAVE_GETSERVBYPORT 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_GETWD 1
#define HAVE_GLIBC_ICONV 1
#define HAVE_GLOB 1
#define HAVE_GMTIME_R 1
#define HAVE_GRANTPT 1
#define HAVE_GRP_H 1
#define HAVE_HASH_EXT 1
#define HAVE_HSTRERROR 1
#define HAVE_HTONL 1
#define HAVE_HUGE_VAL_INF 1
#define HAVE_HUGE_VAL_NAN 1
#define HAVE_HYPOT 1
#define HAVE_ICONV 1
#define HAVE_IF_INDEXTONAME 1
#define HAVE_IF_NAMETOINDEX 1
#define HAVE_INET_ATON 1
#define HAVE_INET_NTOA 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_INT32_T 1
#define HAVE_INTTYPES_H 1
#define HAVE_IPV6 1
#define HAVE_ISASCII 1
  #define HAVE_ISFINITE 1
  #define HAVE_ISINF 1
  #define HAVE_ISNAN 1
#define HAVE_JSON 1
#define HAVE_KILL 1
#define HAVE_LANGINFO_H 1
#define HAVE_LCHOWN 1
#define HAVE_LIBDL 1
#define HAVE_LIBEXPAT 1
#define HAVE_LIBGD 1
#define HAVE_LIBGD13 1
#define HAVE_LIBGD15 1
#define HAVE_LIBGD20 1
#define HAVE_LIBGD204 1
#define HAVE_LIBM 1
#define HAVE_LIBMCRYPT 1
#define HAVE_LIBNSL 1
#define HAVE_LIBRESOLV 1
#define HAVE_LIBRT 1
#define HAVE_LIBXML 1
#define HAVE_LIMITS_H 1
#define HAVE_LINK 1
#define HAVE_LOCALECONV 1
#define HAVE_LOCALE_H 1
#define HAVE_LOCALTIME_R 1
#define HAVE_LOCKF 1
#define HAVE_LOG1P 1
#define HAVE_LRAND48 1
#define HAVE_MALLOC_H 1
#define HAVE_MBLEN 1
#define HAVE_MBRLEN 1
#define HAVE_MBSINIT 1
#define HAVE_MBSTATE_T 1
#define HAVE_MEMCPY 1
#define HAVE_MEMMOVE 1
#define HAVE_MEM_MMAP_ANON 1
#define HAVE_MEM_MMAP_ZERO 1
#define HAVE_MKSTEMP 1
#define HAVE_MMAP 1
#define HAVE_MONETARY_H 1
#define HAVE_MREMAP 1
#define HAVE_MYSQL 1
#define HAVE_NANOSLEEP 1
#define HAVE_NETDB_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_NICE 1
#define HAVE_NL_LANGINFO 1
#define HAVE_PACKED_OBJECT_VALUE 0
#define HAVE_PERROR 1
#define HAVE_POLL 1
#define HAVE_POSIX_READDIR_R 1
#define HAVE_PTSNAME 1
#define HAVE_PUTENV 1
#define HAVE_PWD_H 1
#define HAVE_RANDOM 1
#define HAVE_RAND_R 1
#define HAVE_REALPATH 1
#define HAVE_REFLECTION 1
#define HAVE_REGCOMP 1
#define HAVE_REGEX_T_RE_MAGIC 1
#define HAVE_RESOLV_H 1
#define HAVE_RES_NMKQUERY 1
#define HAVE_RES_NSEND 1
#define HAVE_RES_SEARCH 1
#define HAVE_SCANDIR 1
#define HAVE_SEMUN 0
#define HAVE_SENDMAIL 1
#define HAVE_SETENV 1
#define HAVE_SETITIMER 1
#define HAVE_SETLOCALE 1
#define HAVE_SETPGID 1
#define HAVE_SETSOCKOPT 1
#define HAVE_SETVBUF 1
#define HAVE_SHUTDOWN 1
#define HAVE_SIGNAL_H 1
#define HAVE_SIMPLEXML 1
#define HAVE_SIN 1
#define HAVE_SNPRINTF 1
#define HAVE_SOAP 1
#define HAVE_SOCKADDR_STORAGE 1
#define HAVE_SOCKET 1
#define HAVE_SOCKETPAIR 1
#define HAVE_SOCKETS 1
#define HAVE_SOCKLEN_T 1
#define HAVE_SPL 1
#define HAVE_SRAND48 1
#define HAVE_SRANDOM 1
#define HAVE_STATFS 1
#define HAVE_STATVFS 1
#define HAVE_STDARG_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRCASECMP 1
#define HAVE_STRCOLL 1
#define HAVE_STRDUP 1
#define HAVE_STRERROR 1
#define HAVE_STRFMON 1
#define HAVE_STRFTIME 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_STRPBRK 1
#define HAVE_STRPTIME 1
#define HAVE_STRSTR 1
#define HAVE_STRTOD 1
#define HAVE_STRTOK_R 1
#define HAVE_STRTOL 1
#define HAVE_STRTOLL 1
#define HAVE_STRTOUL 1
#define HAVE_STRTOULL 1
#define HAVE_STRUCT_FLOCK 1
#define HAVE_STRUCT_TM_TM_ZONE 1
#define HAVE_SYMLINK 1
#define HAVE_SYSEXITS_H 1
#define HAVE_SYSLOG_H 1
#define HAVE_SYS_FILE_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_IPC_H 1
#define HAVE_SYS_MMAN_H 1
#define HAVE_SYS_MOUNT_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_POLL_H 1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STATFS_H 1
#define HAVE_SYS_STATVFS_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_SYS_UTSNAME_H 1
#define HAVE_SYS_VFS_H 1
#define HAVE_SYS_WAIT_H 1
#define HAVE_TEMPNAM 1
#define HAVE_TERMIOS_H 1
#define HAVE_TM_GMTOFF 1
#define HAVE_TM_ZONE 1
#define HAVE_TZSET 1
#define HAVE_UINT32_T 1
#define HAVE_UNISTD_H 1
#define HAVE_UNLOCKPT 1
#define HAVE_UNSETENV 1
#define HAVE_USLEEP 1
#define HAVE_UTIME 1
#define HAVE_UTIME_H 1
#define HAVE_VPRINTF 1
#define HAVE_VSNPRINTF 1
#define HAVE_WCHAR_H 1
#define HAVE_XML 1
#define HAVE_XMLREADER 1
#define HAVE_XMLRPC 1
#define HAVE_XMLWRITER 1
#define HAVE_YP_GET_DEFAULT_DOMAIN 1
#define HAVE_ZLIB 1
#define HSREGEX 1
#define ICONV_SUPPORTS_ERRNO 1
#define MAGIC_QUOTES 0
#define MEMORY_LIMIT 0
#define MISSING_FCLOSE_DECL 0
#define PACKAGE_BUGREPORT ""
#define PHP_APACHE_HAVE_CLIENT_FD 1
#define PHP_BLOWFISH_CRYPT 0
#define PHP_BUILD_DATE "2008-01-09"
#define PHP_CAN_SUPPORT_PROC_OPEN 1
#define PHP_EXT_DES_CRYPT 0
#define PHP_ICONV_H_PATH </usr/include/iconv.h>
#define PHP_ICONV_IMPL "glibc"
#define PHP_MD5_CRYPT 1
#define PHP_OS "Linux"
#define PHP_SAFE_MODE 0
#define PHP_SAFE_MODE_EXEC_DIR "/usr/local/php/bin"
#define PHP_SIGCHILD 0
#define PHP_STD_DES_CRYPT 1
#define PHP_WRITE_STDOUT 1
#define REGEX 1
#define RETSIGTYPE void
#define SIZEOF_CHAR 1
#define SIZEOF_INT 4
#define SIZEOF_INTMAX_T 8
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define SIZEOF_LONG_LONG_INT 8
#define SIZEOF_PTRDIFF_T 8
#define SIZEOF_SHORT 2
#define SIZEOF_SIZE_T 8
#define SIZEOF_SSIZE_T 8
#define STDC_HEADERS 1
#define TIME_WITH_SYS_TIME 1

#define USE_GD_IMGSTRTTF 1

#define YYTEXT_POINTER 1

#define ZEND_BROKEN_SPRINTF 0
#define ZEND_DEBUG 0


#define ZEND_MM_ALIGNMENT 8
#define ZEND_MM_ALIGNMENT_LOG2 3
#define ZEND_VM_KIND ZEND_VM_KIND_CALL
#define zend_finite(a) finite(a)
#define zend_isinf(a) isinf(a)
#define zend_isnan(a) isnan(a)
# define zend_sprintf sprintf
#define NUM_BUF_SIZE 500


#define ARRPROV_HERE() ([&]{                            \
    static auto const file = makeStaticString(          \
        "__FILE__" ":" ARRPROV_STR("__LINE__"));            \
    return ::HPHP::arrprov::Tag::RuntimeLocation(file); \
  }())
#define ARRPROV_HERE_POISON() ([&]{                           \
    static auto const file = makeStaticString(                \
        "__FILE__" ":" ARRPROV_STR("__LINE__"));                  \
    return ::HPHP::arrprov::Tag::RuntimeLocationPoison(file); \
  }())
#define ARRPROV_STR(X) ARRPROV_STR_IMPL(X)
#define ARRPROV_STR_IMPL(X) #X
#define ARRPROV_USE_POISONED_LOCATION() \
  ::HPHP::arrprov::TagOverride ap_override(ARRPROV_HERE_POISON())
#define ARRPROV_USE_RUNTIME_LOCATION() \
  ::HPHP::arrprov::TagOverride ap_override(ARRPROV_HERE())
#define ARRPROV_USE_RUNTIME_LOCATION_FORCE()      \
  ::HPHP::arrprov::TagOverride ap_override(       \
      ARRPROV_HERE(),                             \
      ::HPHP::arrprov::TagOverride::ForceTag{}    \
  )
#define ARRPROV_USE_VMPC() \
  ::HPHP::arrprov::TagOverride ap_override({})
#define RDS_FIXED_PERSISTENT_BASE 1
#define PR(T) T,
#define RDS_PROFILE_SYMBOLS   \
  PR(ArrayAccessProfile)  \
  PR(ArrayIterProfile)    \
  PR(CallTargetProfile)   \
  PR(ClsCnsProfile)       \
  PR(DecRefProfile)       \
  PR(IsTypeStructProfile) \
  PR(IncRefProfile)       \
  PR(MethProfile)         \
  PR(SwitchProfile)       \
  PR(TypeProfile)
#define NO_M_DATA 1
#define SD_DATA   16
#define SD_HASH   12
#define SD_LEN    8
#define C(key_t, name, ret_t, cns) \
  ret_t name(key_t, Flags = Flags::None) cns;
  #define COPY_BODY(meth, def)                                          \
    if (!m_arr) return def;                                             \
    auto new_arr = m_arr->meth;                                         \
    return new_arr != m_arr ? Array{new_arr, NoIncRef{}} : Array{*this};
#define D(key_t, name, ret_t, cns) \
  ret_t name(key_t, Flags = Flags::None) cns = delete;
#define FOR_EACH_KEY_TYPE(...)    \
  C(TypedValue, __VA_ARGS__)            \
  I(int, __VA_ARGS__)             \
  I(int64_t, __VA_ARGS__)         \
  V(const String&, __VA_ARGS__)   \
  V(const Variant&, __VA_ARGS__)  \
  D(double, __VA_ARGS__)
#define I V
#define V C

#define DECLARE_RESOURCE_ALLOCATION(T)                          \
  DECLARE_RESOURCE_ALLOCATION_NO_SWEEP(T)                       \
  void sweep() override;
#define DECLARE_RESOURCE_ALLOCATION_NO_SWEEP(T)                 \
  public:                                                       \
  ALWAYS_INLINE void operator delete(void* p) {                 \
    static_assert(std::is_base_of<ResourceData,T>::value, "");  \
    constexpr auto size = sizeof(ResourceHdr) + sizeof(T);      \
    auto h = static_cast<ResourceData*>(p)->hdr();              \
    assertx(h->heapSize() == size);                              \
    tl_heap->objFree(h, size);                                  \
  }
#define IMPLEMENT_RESOURCE_ALLOCATION(T)  \
  IMPLEMENT_RESOURCE_ALLOCATION_NS(HPHP, T)
#define IMPLEMENT_RESOURCE_ALLOCATION_NS(NS, T)                        \
  static_assert(std::is_base_of<HPHP::ResourceData,NS::T>::value, ""); \
  void NS::T::sweep() { this->~T(); }
#define CLASSNAME_IS(str)                                               \
  static const auto& GetClassName() { return str; }                     \
  static const StaticString& classnameof() {                            \
    return InstantStatic<const StaticString,                            \
                         decltype(GetClassName()),                      \
                         GetClassName>::value;                          \
  }
#define RESOURCENAME_IS(str)                                            \
  static const auto& GetResourceName() { return str; }                  \
  static const StaticString& resourcenameof() {                         \
    return InstantStatic<const StaticString,                            \
                         decltype(GetResourceName()),                   \
                         GetResourceName>::value;                       \
  }
#define DECLARE_CLASS_NO_SWEEP(originalName)                           \
  public:                                                              \
  CLASSNAME_IS(#originalName)                                          \
  friend ObjectData* new_##originalName##_Instance(Class*);            \
  friend void delete_##originalName(ObjectData*, const Class*);        \
  static HPHP::LowPtr<Class> s_classOf;                                \
  static inline HPHP::LowPtr<Class>& classof() {                       \
    return s_classOf;                                                  \
  }
#define IMPLEMENT_CLASS_NO_SWEEP(cls)                                  \
  HPHP::LowPtr<Class> c_##cls::s_classOf;
#define INVOKE_FEW_ARGS(kind,num) \
  INVOKE_FEW_ARGS_HELPER(INVOKE_FEW_ARGS_##kind,num)
#define INVOKE_FEW_ARGS_COUNT 6
#define INVOKE_FEW_ARGS_DECL10                       \
  INVOKE_FEW_ARGS_DECL6,                             \
  const Variant& a6 = uninit_variant,                \
  const Variant& a7 = uninit_variant,                \
  const Variant& a8 = uninit_variant,                \
  const Variant& a9 = uninit_variant
#define INVOKE_FEW_ARGS_DECL3                        \
  const Variant& a0 = uninit_variant,                \
  const Variant& a1 = uninit_variant,                \
  const Variant& a2 = uninit_variant
#define INVOKE_FEW_ARGS_DECL6                        \
  INVOKE_FEW_ARGS_DECL3,                             \
  const Variant& a3 = uninit_variant,                \
  const Variant& a4 = uninit_variant,                \
  const Variant& a5 = uninit_variant
#define INVOKE_FEW_ARGS_DECL_ARGS INVOKE_FEW_ARGS(DECL,INVOKE_FEW_ARGS_COUNT)
#define INVOKE_FEW_ARGS_HELPER(kind,num) kind##num

#define DECLARE_SYSTEMLIB_CLASS(cls)       \
extern Class* s_ ## cls ## Class;
#define DECLARE_SYSTEMLIB_HH_CLASS(cls) \
extern Class* s_HH_ ## cls ## Class;
#define SYSTEMLIB_CLASSES(x)                    \
  x(stdclass)                                   \
  x(Exception)                                  \
  x(BadMethodCallException)                     \
  x(InvalidArgumentException)                   \
  x(TypeAssertionException)                     \
  x(RuntimeException)                           \
  x(OutOfBoundsException)                       \
  x(InvalidOperationException)                  \
  x(pinitSentinel)                              \
  x(resource)                                   \
  x(Directory)                                  \
  x(SplFileInfo)                                \
  x(SplFileObject)                              \
  x(DateTimeInterface)                          \
  x(DateTimeImmutable)                          \
  x(DOMException)                               \
  x(PDOException)                               \
  x(SoapFault)                                  \
  x(Serializable)                               \
  x(ArrayAccess)                                \
  x(ArrayIterator)                              \
  x(IteratorAggregate)                          \
  x(Countable)                                  \
  x(LazyKVZipIterable)                          \
  x(LazyIterableView)                           \
  x(LazyKeyedIterableView)                      \
  x(CURLFile)                                   \
  x(__PHP_Incomplete_Class)                     \
  x(APCIterator)                                \
  x(DivisionByZeroException)
#define SYSTEMLIB_HH_CLASSES(x) \
  x(Traversable)                \
  x(Iterator)                   \
  x(Elt)                        \


#define OFF(f)                          \
  static constexpr ptrdiff_t f##Off() { \
    return offsetof(Class, m_##f);      \
  }

#define HC(Opt, opt) void raise_hac_##opt##_notice(const std::string& msg);
#define DEF_ACCESSORS(Type, TypeName, fields, Fields)                         \
  Type const* fields() const      { return m_##fields.accessList(); }         \
  Type*       mutable##Fields()   { return m_##fields.mutableAccessList(); }  \
  size_t      num##Fields() const { return m_##fields.size(); }               \
  using TypeName##Range = folly::Range<Type const*>;                          \
  TypeName##Range all##Fields() const {                                       \
    return TypeName##Range(fields(), m_##fields.size());                      \
  }


#define ARGTYPE(name, type) name,
#define ARGTYPES                                                               \
  ARGTYPE(NA,     void*)                                           \
  ARGTYPEVEC(BLA, Offset)                \
  ARGTYPEVEC(SLA, Id)                        \
  ARGTYPE(IVA,    uint32_t)               \
  ARGTYPE(I64A,   int64_t)                                 \
  ARGTYPE(LA,     int32_t)                         \
  ARGTYPE(NLA,    NamedLocal)           \
  ARGTYPE(ILA,    int32_t)                   \
  ARGTYPE(IA,     int32_t)                   \
  ARGTYPE(DA,     double)                                          \
  ARGTYPE(SA,     Id)                                    \
  ARGTYPE(AA,     Id)                                     \
  ARGTYPE(RATA,   RepoAuthType)          \
  ARGTYPE(BA,     Offset)                                 \
  ARGTYPE(OA,     unsigned char)                      \
  ARGTYPE(KA,     MemberKey)           \
  ARGTYPE(LAR,    LocalRange)                  \
  ARGTYPE(ITA,    IterArgs)                            \
  ARGTYPE(FCA,    FCallArgs)                              \
  ARGTYPEVEC(VSA, Id)            
#define ARGTYPEVEC(name, type) name,
#define BARETHIS_OP(x) x,
#define BARETHIS_OPS    \
  BARETHIS_OP(Notice)   \
  BARETHIS_OP(NoNotice) \
  BARETHIS_OP(NeverNull)
#define CONT_CHECK_OP(name) name,
#define CONT_CHECK_OPS                            \
  CONT_CHECK_OP(IgnoreStarted)                    \
  CONT_CHECK_OP(CheckStarted)
#define CUD_OP(name) name,
#define CUD_OPS                                 \
  CUD_OP(IgnoreIter)                            \
  CUD_OP(FreeIter)
#define FATAL_OP(x) x,
#define FATAL_OPS                               \
  FATAL_OP(Runtime)                             \
  FATAL_OP(Parse)                               \
  FATAL_OP(RuntimeOmitFrame)
#define HIGH_OPCODES \
  O(FuncPrologue) \
  O(TraceletGuard)
#define INCDEC_OP(incDecOp) incDecOp,
#define INCDEC_OPS    \
  INCDEC_OP(PreInc)   \
  INCDEC_OP(PostInc)  \
  INCDEC_OP(PreDec)   \
  INCDEC_OP(PostDec)  \
                      \
  INCDEC_OP(PreIncO)  \
  INCDEC_OP(PostIncO) \
  INCDEC_OP(PreDecO)  \
  INCDEC_OP(PostDecO) \

#define INITPROP_OP(op) op,
#define INITPROP_OPS    \
  INITPROP_OP(Static)   \
  INITPROP_OP(NonStatic)
#define ISTYPE_OP(op) op,
#define ISTYPE_OPS                             \
  ISTYPE_OP(Null)                              \
  ISTYPE_OP(Bool)                              \
  ISTYPE_OP(Int)                               \
  ISTYPE_OP(Dbl)                               \
  ISTYPE_OP(Str)                               \
  ISTYPE_OP(Vec)                               \
  ISTYPE_OP(Dict)                              \
  ISTYPE_OP(Keyset)                            \
  ISTYPE_OP(Obj)                               \
  ISTYPE_OP(Scalar)                            \
  ISTYPE_OP(ArrLike)                           \
  ISTYPE_OP(LegacyArrLike)                     \
  ISTYPE_OP(Res)                               \
  ISTYPE_OP(VArray)                            \
  ISTYPE_OP(DArray)                            \
  ISTYPE_OP(ClsMeth)                           \
  ISTYPE_OP(Func)                              \
  ISTYPE_OP(PHPArr)                            \
  ISTYPE_OP(Class)
#define IS_LOG_AS_DYNAMIC_CALL_OP(name) name,
#define IS_LOG_AS_DYNAMIC_CALL_OPS                  \
  IS_LOG_AS_DYNAMIC_CALL_OP(LogAsDynamicCall)       \
  IS_LOG_AS_DYNAMIC_CALL_OP(DontLogAsDynamicCall)
#define KIND(x) x,
#define MODE(name) name,
#define M_OP_MODES                                 \
  MODE(None)                                       \
  MODE(Warn)                                       \
  MODE(Define)                                     \
  MODE(Unset)                                      \
                            \
  MODE(InOut)
#define O(unusedName, unusedImm, unusedPop, unusedPush, flags) flags,
#define OBJMETHOD_OP(x) x,
#define OBJMETHOD_OPS                             \
  OBJMETHOD_OP(NullThrows)                        \
  OBJMETHOD_OP(NullSafe)
#define OO_DECL_EXISTS_OP(x) x,
#define OO_DECL_EXISTS_OPS                             \
  OO_DECL_EXISTS_OP(Class)                             \
  OO_DECL_EXISTS_OP(Interface)                         \
  OO_DECL_EXISTS_OP(Trait)
#define OP(name) name,
#define OPCODES \
  O(Nop,             NA,               NOV,             NOV,        NF) \
  O(EntryNop,        NA,               NOV,             NOV,        NF) \
  O(BreakTraceHint,  NA,               NOV,             NOV,        NF) \
  O(PopC,            NA,               ONE(CV),         NOV,        NF) \
  O(PopU,            NA,               ONE(UV),         NOV,        NF) \
  O(PopU2,           NA,               TWO(CV,UV),      ONE(CV),    NF) \
  O(PopFrame,        ONE(IVA),         CMANY_U2,        CMANY,      NF) \
  O(PopL,            ONE(LA),          ONE(CV),         NOV,        NF) \
  O(Dup,             NA,               ONE(CV),         TWO(CV,CV), NF) \
  O(CGetCUNop,       NA,               ONE(CUV),        ONE(CV),    NF) \
  O(UGetCUNop,       NA,               ONE(CUV),        ONE(UV),    NF) \
  O(Null,            NA,               NOV,             ONE(CV),    NF) \
  O(NullUninit,      NA,               NOV,             ONE(UV),    NF) \
  O(True,            NA,               NOV,             ONE(CV),    NF) \
  O(False,           NA,               NOV,             ONE(CV),    NF) \
  O(FuncCred,        NA,               NOV,             ONE(CV),    NF) \
  O(Int,             ONE(I64A),        NOV,             ONE(CV),    NF) \
  O(Double,          ONE(DA),          NOV,             ONE(CV),    NF) \
  O(String,          ONE(SA),          NOV,             ONE(CV),    NF) \
  O(Array,           ONE(AA),          NOV,             ONE(CV),    NF) \
  O(Dict,            ONE(AA),          NOV,             ONE(CV),    NF) \
  O(Keyset,          ONE(AA),          NOV,             ONE(CV),    NF) \
  O(Vec,             ONE(AA),          NOV,             ONE(CV),    NF) \
  O(NewDictArray,    ONE(IVA),         NOV,             ONE(CV),    NF) \
  O(NewStructDArray, ONE(VSA),         SMANY,           ONE(CV),    NF) \
  O(NewStructDict,   ONE(VSA),         SMANY,           ONE(CV),    NF) \
  O(NewVec,          ONE(IVA),         CMANY,           ONE(CV),    NF) \
  O(NewKeysetArray,  ONE(IVA),         CMANY,           ONE(CV),    NF) \
  O(NewVArray,       ONE(IVA),         CMANY,           ONE(CV),    NF) \
  O(NewDArray,       ONE(IVA),         NOV,             ONE(CV),    NF) \
  O(NewRecord,       TWO(SA,VSA),      SMANY,           ONE(CV),    NF) \
  O(AddElemC,        NA,               THREE(CV,CV,CV), ONE(CV),    NF) \
  O(AddNewElemC,     NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(NewCol,          ONE(OA(CollectionType)),                           \
                                       NOV,             ONE(CV),    NF) \
  O(NewPair,         NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(ColFromArray,    ONE(OA(CollectionType)),                           \
                                       ONE(CV),         ONE(CV),    NF) \
  O(CnsE,            ONE(SA),          NOV,             ONE(CV),    NF) \
  O(ClsCns,          ONE(SA),          ONE(CV),         ONE(CV),    NF) \
  O(ClsCnsD,         TWO(SA,SA),       NOV,             ONE(CV),    NF) \
  O(ClsCnsL,         ONE(LA),          ONE(CV),         ONE(CV),    NF) \
  O(ClassName,       NA,               ONE(CV),         ONE(CV),    NF) \
  O(File,            NA,               NOV,             ONE(CV),    NF) \
  O(Dir,             NA,               NOV,             ONE(CV),    NF) \
  O(Method,          NA,               NOV,             ONE(CV),    NF) \
  O(Concat,          NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(ConcatN,         ONE(IVA),         CMANY,           ONE(CV),    NF) \
  O(Add,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Sub,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Mul,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(AddO,            NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(SubO,            NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(MulO,            NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Div,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Mod,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Pow,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Xor,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Not,             NA,               ONE(CV),         ONE(CV),    NF) \
  O(Same,            NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(NSame,           NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Eq,              NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Neq,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Lt,              NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Lte,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Gt,              NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Gte,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Cmp,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(BitAnd,          NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(BitOr,           NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(BitXor,          NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(BitNot,          NA,               ONE(CV),         ONE(CV),    NF) \
  O(Shl,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(Shr,             NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(CastBool,        NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastInt,         NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastDouble,      NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastString,      NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastDict,        NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastKeyset,      NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastVec,         NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastVArray,      NA,               ONE(CV),         ONE(CV),    NF) \
  O(CastDArray,      NA,               ONE(CV),         ONE(CV),    NF) \
  O(DblAsBits,       NA,               ONE(CV),         ONE(CV),    NF) \
  O(InstanceOf,      NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(InstanceOfD,     ONE(SA),          ONE(CV),         ONE(CV),    NF) \
  O(IsLateBoundCls,  NA,               ONE(CV),         ONE(CV),    NF) \
  O(IsTypeStructC,   ONE(OA(TypeStructResolveOp)),                      \
                                       TWO(CV,CV),      ONE(CV),    NF) \
  O(ThrowAsTypeStructException,                                         \
                     NA,               TWO(CV,CV),      NOV,        TF) \
  O(CombineAndResolveTypeStruct,                                        \
                     ONE(IVA),         CMANY,           ONE(CV),    NF) \
  O(Select,          NA,               THREE(CV,CV,CV), ONE(CV),    NF) \
  O(Print,           NA,               ONE(CV),         ONE(CV),    NF) \
  O(Clone,           NA,               ONE(CV),         ONE(CV),    NF) \
  O(Exit,            NA,               ONE(CV),         ONE(CV),    TF) \
  O(Fatal,           ONE(OA(FatalOp)), ONE(CV),         NOV,        TF) \
  O(Jmp,             ONE(BA),          NOV,             NOV,        CF_TF) \
  O(JmpNS,           ONE(BA),          NOV,             NOV,        CF_TF) \
  O(JmpZ,            ONE(BA),          ONE(CV),         NOV,        CF) \
  O(JmpNZ,           ONE(BA),          ONE(CV),         NOV,        CF) \
  O(Switch,          THREE(OA(SwitchKind),I64A,BLA),                    \
                                       ONE(CV),         NOV,        CF_TF) \
  O(SSwitch,         ONE(SLA),         ONE(CV),         NOV,        CF_TF) \
  O(RetC,            NA,               ONE(CV),         NOV,        CF_TF) \
  O(RetM,            ONE(IVA),         CMANY,           NOV,        CF_TF) \
  O(RetCSuspended,   NA,               ONE(CV),         NOV,        CF_TF) \
  O(Throw,           NA,               ONE(CV),         NOV,        CF_TF) \
  O(CGetL,           ONE(NLA),         NOV,             ONE(CV),    NF) \
  O(CGetQuietL,      ONE(LA),          NOV,             ONE(CV),    NF) \
  O(CUGetL,          ONE(LA),          NOV,             ONE(CUV),   NF) \
  O(CGetL2,          ONE(NLA),         ONE(CV),         TWO(CV,CV), NF) \
  O(PushL,           ONE(LA),          NOV,             ONE(CV),    NF) \
  O(CGetG,           NA,               ONE(CV),         ONE(CV),    NF) \
  O(CGetS,           NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(ClassGetC,       NA,               ONE(CV),         ONE(CV),    NF) \
  O(ClassGetTS,      NA,               ONE(CV),         TWO(CV,CV), NF) \
  O(GetMemoKeyL,     ONE(NLA),         NOV,             ONE(CV),    NF) \
  O(AKExists,        NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(IssetL,          ONE(LA),          NOV,             ONE(CV),    NF) \
  O(IssetG,          NA,               ONE(CV),         ONE(CV),    NF) \
  O(IssetS,          NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(IsUnsetL,        ONE(LA),          NOV,             ONE(CV),    NF) \
  O(IsTypeC,         ONE(OA(IsTypeOp)),ONE(CV),         ONE(CV),    NF) \
  O(IsTypeL,         TWO(NLA,                                           \
                       OA(IsTypeOp)),  NOV,             ONE(CV),    NF) \
  O(AssertRATL,      TWO(ILA,RATA),    NOV,             NOV,        NF) \
  O(AssertRATStk,    TWO(IVA,RATA),    NOV,             NOV,        NF) \
  O(SetL,            ONE(LA),          ONE(CV),         ONE(CV),    NF) \
  O(SetG,            NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(SetS,            NA,               THREE(CV,CV,CV), ONE(CV),    NF) \
  O(SetOpL,          TWO(LA,                                            \
                       OA(SetOpOp)),   ONE(CV),         ONE(CV),    NF) \
  O(SetOpG,          ONE(OA(SetOpOp)), TWO(CV,CV),      ONE(CV),    NF) \
  O(SetOpS,          ONE(OA(SetOpOp)), THREE(CV,CV,CV), ONE(CV),    NF) \
  O(IncDecL,         TWO(NLA,                                           \
                       OA(IncDecOp)),  NOV,             ONE(CV),    NF) \
  O(IncDecG,         ONE(OA(IncDecOp)),ONE(CV),         ONE(CV),    NF) \
  O(IncDecS,         ONE(OA(IncDecOp)),TWO(CV,CV),      ONE(CV),    NF) \
  O(UnsetL,          ONE(LA),          NOV,             NOV,        NF) \
  O(UnsetG,          NA,               ONE(CV),         NOV,        NF) \
                                                                        \
  O(ResolveFunc,     ONE(SA),          NOV,             ONE(CV),    NF) \
  O(ResolveMethCaller,ONE(SA),         NOV,             ONE(CV),    NF) \
  O(ResolveRFunc,    ONE(SA),          ONE(CV),         ONE(CV),    NF) \
  O(ResolveObjMethod,NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(ResolveClsMethod,ONE(SA),          ONE(CV),         ONE(CV),    NF) \
  O(ResolveClsMethodD,                                                  \
                     TWO(SA,SA),       NOV,             ONE(CV),    NF) \
  O(ResolveClsMethodS,                                                  \
                     TWO(OA(SpecialClsRef),SA),                         \
                                       NOV,             ONE(CV),    NF) \
  O(ResolveRClsMethod,                                                  \
                     ONE(SA),          TWO(CV,CV),      ONE(CV),    NF) \
  O(ResolveRClsMethodD,                                                 \
                     TWO(SA,SA),       ONE(CV),         ONE(CV),    NF) \
  O(ResolveRClsMethodS,                                                 \
                     TWO(OA(SpecialClsRef),SA),                         \
                                       ONE(CV),         ONE(CV),    NF) \
  O(ResolveClass,    ONE(SA),          NOV,             ONE(CV),    NF) \
  O(LazyClass,       ONE(SA),          NOV,             ONE(CV),    NF) \
  O(NewObj,          NA,               ONE(CV),         ONE(CV),    NF) \
  O(NewObjR,         NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(NewObjD,         ONE(SA),          NOV,             ONE(CV),    NF) \
  O(NewObjRD,        ONE(SA),          ONE(CV),         ONE(CV),    NF) \
  O(NewObjS,         ONE(OA(SpecialClsRef)),                            \
                                       NOV,             ONE(CV),    NF) \
  O(LockObj,         NA,               ONE(CV),         ONE(CV),    NF) \
  O(FCallClsMethod,  THREE(FCA,SA,OA(IsLogAsDynamicCallOp)),            \
                                       FCALL(2, 0),     FCALL,      CF) \
  O(FCallClsMethodD, FOUR(FCA,SA,SA,SA),                                \
                                       FCALL(0, 0),     FCALL,      CF) \
  O(FCallClsMethodS, THREE(FCA,SA,OA(SpecialClsRef)),                   \
                                       FCALL(1, 0),     FCALL,      CF) \
  O(FCallClsMethodSD,FOUR(FCA,SA,OA(SpecialClsRef),SA),                 \
                                       FCALL(0, 0),     FCALL,      CF) \
  O(FCallCtor,       TWO(FCA,SA),      FCALL(0, 1),     FCALL,      CF) \
  O(FCallFunc,       ONE(FCA),         FCALL(1, 0),     FCALL,      CF) \
  O(FCallFuncD,      TWO(FCA,SA),      FCALL(0, 0),     FCALL,      CF) \
  O(FCallObjMethod,  THREE(FCA,SA,OA(ObjMethodOp)),                     \
                                       FCALL(1, 1),     FCALL,      CF) \
  O(FCallObjMethodD, FOUR(FCA,SA,OA(ObjMethodOp),SA),                   \
                                       FCALL(0, 1),     FCALL,      CF) \
  O(FCallBuiltin,    FOUR(IVA,IVA,IVA,SA),CALLNATIVE,   CALLNATIVE, NF) \
  O(IterInit,        TWO(ITA,BA),      ONE(CV),         NOV,        CF) \
  O(LIterInit,       THREE(ITA,LA,BA), NOV,             NOV,        CF) \
  O(IterNext,        TWO(ITA,BA),      NOV,             NOV,        CF) \
  O(LIterNext,       THREE(ITA,LA,BA), NOV,             NOV,        CF) \
  O(IterFree,        ONE(IA),          NOV,             NOV,        NF) \
  O(LIterFree,       TWO(IA,LA),       NOV,             NOV,        NF) \
  O(Incl,            NA,               ONE(CV),         ONE(CV),    CF) \
  O(InclOnce,        NA,               ONE(CV),         ONE(CV),    CF) \
  O(Req,             NA,               ONE(CV),         ONE(CV),    CF) \
  O(ReqOnce,         NA,               ONE(CV),         ONE(CV),    CF) \
  O(ReqDoc,          NA,               ONE(CV),         ONE(CV),    CF) \
  O(Eval,            NA,               ONE(CV),         ONE(CV),    CF) \
  O(This,            NA,               NOV,             ONE(CV),    NF) \
  O(BareThis,        ONE(OA(BareThisOp)),                               \
                                       NOV,             ONE(CV),    NF) \
  O(CheckThis,       NA,               NOV,             NOV,        NF) \
  O(ChainFaults,     NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(OODeclExists,    ONE(OA(OODeclExistsOp)),                           \
                                       TWO(CV,CV),      ONE(CV),    NF) \
  O(VerifyOutType,   ONE(IVA),         ONE(CV),         ONE(CV),    NF) \
  O(VerifyParamType, ONE(ILA),         NOV,             NOV,        NF) \
  O(VerifyParamTypeTS, ONE(ILA),       ONE(CV),         NOV,        NF) \
  O(VerifyRetTypeC,  NA,               ONE(CV),         ONE(CV),    NF) \
  O(VerifyRetTypeTS, NA,               TWO(CV,CV),      ONE(CV),    NF) \
  O(VerifyRetNonNullC, NA,             ONE(CV),         ONE(CV),    NF) \
  O(Self,            NA,               NOV,             ONE(CV),    NF) \
  O(Parent,          NA,               NOV,             ONE(CV),    NF) \
  O(LateBoundCls,    NA,               NOV,             ONE(CV),    NF) \
  O(RecordReifiedGeneric, NA,          ONE(CV),         ONE(CV),    NF) \
  O(CheckReifiedGenericMismatch, NA,   ONE(CV),         NOV,        NF) \
  O(NativeImpl,      NA,               NOV,             NOV,        CF_TF) \
  O(CreateCl,        TWO(IVA,IVA),     CUMANY,          ONE(CV),    NF) \
  O(CreateCont,      NA,               NOV,             ONE(CV),    CF) \
  O(ContEnter,       NA,               ONE(CV),         ONE(CV),    CF) \
  O(ContRaise,       NA,               ONE(CV),         ONE(CV),    CF) \
  O(Yield,           NA,               ONE(CV),         ONE(CV),    CF) \
  O(YieldK,          NA,               TWO(CV,CV),      ONE(CV),    CF) \
  O(ContCheck,       ONE(OA(ContCheckOp)), NOV,         NOV,        NF) \
  O(ContValid,       NA,               NOV,             ONE(CV),    NF) \
  O(ContKey,         NA,               NOV,             ONE(CV),    NF) \
  O(ContCurrent,     NA,               NOV,             ONE(CV),    NF) \
  O(ContGetReturn,   NA,               NOV,             ONE(CV),    NF) \
  O(WHResult,        NA,               ONE(CV),         ONE(CV),    NF) \
  O(Await,           NA,               ONE(CV),         ONE(CV),    CF) \
  O(AwaitAll,        ONE(LAR),         NOV,             ONE(CV),    CF) \
  O(Idx,             NA,               THREE(CV,CV,CV), ONE(CV),    NF) \
  O(ArrayIdx,        NA,               THREE(CV,CV,CV), ONE(CV),    NF) \
  O(ArrayMarkLegacy,    NA,            TWO(CV,CV),      ONE(CV),    NF) \
  O(ArrayUnmarkLegacy,  NA,            TWO(CV,CV),      ONE(CV),    NF) \
  O(TagProvenanceHere,  NA,            TWO(CV,CV),      ONE(CV),    NF) \
  O(CheckProp,       ONE(SA),          NOV,             ONE(CV),    NF) \
  O(InitProp,        TWO(SA,                                            \
                       OA(InitPropOp)),ONE(CV),         NOV,        NF) \
  O(Silence,         TWO(LA,OA(SilenceOp)),                             \
                                       NOV,             NOV,        NF) \
  O(ThrowNonExhaustiveSwitch, NA,      NOV,             NOV,        NF) \
  O(RaiseClassStringConversionWarning,                                  \
                              NA,      NOV,             NOV,        NF) \
  O(BaseGC,          TWO(IVA, OA(MOpMode)),                             \
                                       NOV,             NOV,        NF) \
  O(BaseGL,          TWO(LA, OA(MOpMode)),                              \
                                       NOV,             NOV,        NF) \
  O(BaseSC,          THREE(IVA, IVA, OA(MOpMode)),                      \
                                       NOV,             NOV,        NF) \
  O(BaseL,           TWO(NLA, OA(MOpMode)),                             \
                                       NOV,             NOV,        NF) \
  O(BaseC,           TWO(IVA, OA(MOpMode)),                             \
                                       NOV,             NOV,        NF) \
  O(BaseH,           NA,               NOV,             NOV,        NF) \
  O(Dim,             TWO(OA(MOpMode), KA),                              \
                                       NOV,             NOV,        NF) \
  O(QueryM,          THREE(IVA, OA(QueryMOp), KA),                      \
                                       MFINAL,          ONE(CV),    NF) \
  O(SetM,            TWO(IVA, KA),     C_MFINAL(1),     ONE(CV),    NF) \
  O(SetRangeM,       THREE(IVA, OA(SetRangeOp), IVA),                   \
                                       C_MFINAL(3),     NOV,        NF) \
  O(IncDecM,         THREE(IVA, OA(IncDecOp), KA),                      \
                                       MFINAL,          ONE(CV),    NF) \
  O(SetOpM,          THREE(IVA, OA(SetOpOp), KA),                       \
                                       C_MFINAL(1),     ONE(CV),    NF) \
  O(UnsetM,          TWO(IVA, KA),     MFINAL,          NOV,        NF) \
  O(MemoGet,         TWO(BA, LAR),     NOV,             ONE(CV),    CF) \
  O(MemoGetEager,    THREE(BA, BA, LAR),                                \
                                       NOV,             ONE(CV),    CF) \
  O(MemoSet,         ONE(LAR),         ONE(CV),         ONE(CV),    NF) \
  O(MemoSetEager,    ONE(LAR),         ONE(CV),         ONE(CV),    NF)
#define QUERY_M_OPS                               \
  OP(CGet)                                        \
  OP(CGetQuiet)                                   \
  OP(Isset)                                       \
  OP(InOut)
#define REF(name) name,
#define SETOP_OP(setOpOp, bcOp) setOpOp,
#define SETOP_OPS \
  SETOP_OP(PlusEqual,   OpAdd) \
  SETOP_OP(MinusEqual,  OpSub) \
  SETOP_OP(MulEqual,    OpMul) \
  SETOP_OP(ConcatEqual, OpConcat) \
  SETOP_OP(DivEqual,    OpDiv) \
  SETOP_OP(PowEqual,    OpPow) \
  SETOP_OP(ModEqual,    OpMod) \
  SETOP_OP(AndEqual,    OpBitAnd) \
  SETOP_OP(OrEqual,     OpBitOr) \
  SETOP_OP(XorEqual,    OpBitXor) \
  SETOP_OP(SlEqual,     OpShl) \
  SETOP_OP(SrEqual,     OpShr)  \
  SETOP_OP(PlusEqualO,  OpAddO) \
  SETOP_OP(MinusEqualO, OpSubO) \
  SETOP_OP(MulEqualO,   OpMulO) \

#define SET_RANGE_OPS \
  OP(Forward)         \
  OP(Reverse)
#define SILENCE_OP(x) x,
#define SILENCE_OPS \
  SILENCE_OP(Start) \
  SILENCE_OP(End)
#define SPECIAL_CLS_REFS                        \
  REF(Self)                                     \
  REF(Static)                                   \
  REF(Parent)
#define SWITCH_KINDS                            \
  KIND(Unbounded)                               \
  KIND(Bounded)
#define TYPE_STRUCT_RESOLVE_OPS \
  OP(Resolve)                  \
  OP(DontResolve)
#define REPO_AUTH_TYPE_TAGS                       \
    TAG(Uninit)                                   \
    TAG(InitNull)                                 \
    TAG(Null)                                     \
    TAG(Int)                                      \
    TAG(OptInt)                                   \
    TAG(Dbl)                                      \
    TAG(OptDbl)                                   \
    TAG(Res)                                      \
    TAG(OptRes)                                   \
    TAG(Bool)                                     \
    TAG(OptBool)                                  \
    TAG(SStr)                                     \
    TAG(OptSStr)                                  \
    TAG(Str)                                      \
    TAG(OptStr)                                   \
    TAG(Obj)                                      \
    TAG(OptObj)                                   \
    TAG(Func)                                     \
    TAG(OptFunc)                                  \
    TAG(Cls)                                      \
    TAG(OptCls)                                   \
    TAG(ClsMeth)                                  \
    TAG(OptClsMeth)                               \
    TAG(Record)                                   \
    TAG(OptRecord)                                \
    TAG(LazyCls)                                  \
    TAG(OptLazyCls)                               \
    TAG(InitUnc)                                  \
    TAG(Unc)                                      \
    TAG(UncArrKey)                                \
    TAG(ArrKey)                                   \
    TAG(OptUncArrKey)                             \
    TAG(OptArrKey)                                \
    TAG(UncStrLike)                               \
    TAG(StrLike)                                  \
    TAG(OptUncStrLike)                            \
    TAG(OptStrLike)                               \
    TAG(UncArrKeyCompat)                          \
    TAG(ArrKeyCompat)                             \
    TAG(OptUncArrKeyCompat)                       \
    TAG(OptArrKeyCompat)                          \
    TAG(InitCell)                                 \
    TAG(Cell)                                     \
        \
    TAG(ArrCompat)                                \
    TAG(OptArrCompat)                             \
    TAG(VArrCompat)                               \
    TAG(VecCompat)                                \
    TAG(OptVArrCompat)                            \
    TAG(OptVecCompat)                             \
    TAG(SArr)                                     \
    TAG(OptSArr)                                  \
    TAG(Arr)                                      \
    TAG(OptArr)                                   \
    TAG(SVArr)                                    \
    TAG(OptSVArr)                                 \
    TAG(VArr)                                     \
    TAG(OptVArr)                                  \
    TAG(SDArr)                                    \
    TAG(OptSDArr)                                 \
    TAG(DArr)                                     \
    TAG(OptDArr)                                  \
    TAG(SVec)                                     \
    TAG(OptSVec)                                  \
    TAG(Vec)                                      \
    TAG(OptVec)                                   \
    TAG(SDict)                                    \
    TAG(OptSDict)                                 \
    TAG(Dict)                                     \
    TAG(OptDict)                                  \
    TAG(SKeyset)                                  \
    TAG(OptSKeyset)                               \
    TAG(Keyset)                                   \
    TAG(OptKeyset)                                \
     \
    TAG(ExactObj)                                 \
    TAG(SubObj)                                   \
    TAG(OptExactObj)                              \
    TAG(OptSubObj)                                \
    TAG(ExactCls)                                 \
    TAG(SubCls)                                   \
    TAG(OptExactCls)                              \
    TAG(OptSubCls)                                \
     \
    TAG(ExactRecord)                              \
    TAG(SubRecord)                                \
    TAG(OptExactRecord)                           \
    TAG(OptSubRecord)                             \

   #define TAG(x) \
    static_assert((static_cast<uint16_t>(Tag::x) & kRATPtrBit) == 0, "");



#define checkRank(r) do { } while(0)
#define currentRank() RankBase
#define insertRank(r) do { } while(0)
#define popRank(r) do { } while(0)
#define pushRank(r) do { } while(0)
#define AFWHOFF(nm) int(offsetof(c_AsyncFunctionWaitHandle, nm))
#define AROFF(nm) int(offsetof(ActRec, nm))
#define DO(KIND) + 1
#define GENDATAOFF(nm) int(offsetof(Generator, nm))
#define TRANS_KINDS \
    DO(Anchor)      \
    DO(Interp)      \
    DO(Live)        \
    DO(Profile)     \
    DO(Optimize)    \
    DO(LivePrologue)\
    DO(ProfPrologue)\
    DO(OptPrologue) \
    DO(Invalid)     \

#define TVOFF(nm) int(offsetof(TypedValue, nm))
#define Y(kind) \
template<typename T, IntishCast IC = IntishCast::None> \
enable_if_lval_t<T, void> tvCastTo##kind##InPlace(T tv);

#define ASSERT_LEVEL(attr, rl) \
  static_assert(static_cast<RxLevel>(attr >> kRxAttrShift) == RxLevel::rl, "")

#define OFF(f)                          \
  static constexpr ptrdiff_t f##Off() { \
    return offsetof(Func, m_##f);       \
  }




# define htonq(a) (a)
# define ntohq(a) (a)

#define HASH_TABLE_CHECK_OFFSETS(ArrayType, ElmType) \
  static_assert(ArrayType::dataOff() == ArrayType ## _DATA, ""); \
  static_assert(ArrayType::scaleOff() == ArrayType ## _SCALE, ""); \
  static_assert(ElmType::keyOff() == ElmType ## _KEY, ""); \
  static_assert(ElmType::hashOff() == ElmType ## _HASH, ""); \
  static_assert(ElmType::dataOff() == ElmType ## _DATA, ""); \
  static_assert(ElmType::typeOff() == ElmType ## _TYPE, ""); \
  static_assert(sizeof(ElmType) == ElmType ## _QUADWORDS * 8, "");
#define MixedArrayElm_DATA      0
#define MixedArrayElm_HASH      12
#define MixedArrayElm_KEY       16
#define MixedArrayElm_QUADWORDS 3
#define MixedArrayElm_TYPE      8
#define MixedArray_DATA         32
#define MixedArray_SCALE        16
#define SetArrayElm_DATA      0
#define SetArrayElm_HASH      12
#define SetArrayElm_KEY       0
#define SetArrayElm_QUADWORDS 2
#define SetArrayElm_TYPE      8
#define SetArray_DATA         32
#define SetArray_SCALE        16
#define IMPLEMENT_LOGLEVEL(LEVEL)                       \
  template<typename... Args>                            \
  void Logger::F##LEVEL(Args&&... args) {               \
    if (LogLevel < Log##LEVEL) return;                  \
    LEVEL(folly::sformat(std::forward<Args>(args)...)); \
  }
#define PHP_DIR_SEPARATOR '/'
#define CRONO_DEBUG(msg_n_args)  \
do { if (debug_file) print_debug_msg  msg_n_args; } while (0)
#define FAR_DISTANT_FUTURE  LONG_MAX
#define EVAL_FILENAME_SUFFIX ") : eval()'d code"
#define tvReturn(x)                                                     \
  ([&] {                                                                \
    TypedValue val_;                                                    \
    new (&val_) Variant(x);                                             \
    assertx(val_.m_type != KindOfUninit);                               \
    return val_;                                                        \
  }())
#define INITIAL_CAPACITY  4
#define CODING_DEFLATE  2
#define CODING_GZIP     1
#define HHVM_DSO_VERSION 20150223L
#define HHVM_GET_MODULE(name) \
static ExtensionBuildInfo s_##name##_extension_build_info = { \
  HHVM_DSO_VERSION, \
  HHVM_VERSION_BRANCH, \
}; \
extern "C" ExtensionBuildInfo* getModuleBuildInfo() { \
  return &s_##name##_extension_build_info; \
} \
extern "C" Extension* getModule() { \
  return &s_##name##_extension; \
}
#define IMPLEMENT_DEFAULT_EXTENSION_VERSION(name, v)    \
  static class name ## Extension final : public Extension {   \
  public:                                               \
    name ## Extension() : Extension(#name, #v) {}       \
  } s_ ## name ## _extension
#define NO_EXTENSION_VERSION_YET "\0"
#define HHVM_VERSION (HHVM_VERSION_C_STRING_LITERALS)
#define HHVM_VERSION_BRANCH ((HHVM_VERSION_MAJOR << 16) | \
                             (HHVM_VERSION_MINOR <<  8))
#define HHVM_VERSION_C_STRING_LITERALS \
  HHVM_VERSION_STRINGIFY(HHVM_VERSION_MAJOR) "." \
  HHVM_VERSION_STRINGIFY(HHVM_VERSION_MINOR) "." \
  HHVM_VERSION_STRINGIFY(HHVM_VERSION_PATCH) HHVM_VERSION_SUFFIX
#define HHVM_VERSION_ID (HHVM_VERSION_BRANCH | HHVM_VERSION_PATCH)
# define HHVM_VERSION_MAJOR 4
# define HHVM_VERSION_MINOR 84
# define HHVM_VERSION_PATCH 0
#define HHVM_VERSION_STRINGIFY(x) HHVM_VERSION_STRINGIFY_HELPER(x)
#define HHVM_VERSION_STRINGIFY_HELPER(x) #x
# define HHVM_VERSION_SUFFIX "-dev"
#define HHVM_FALIAS(fn, falias)\
  HHVM_NAMED_FE_STR(#fn, HHVM_FN(falias), nativeFuncs())
#define HHVM_FE(fn) \
  HHVM_NAMED_FE_STR(#fn, HHVM_FN(fn), nativeFuncs())
#define HHVM_FN(fn) f_ ## fn
#define HHVM_FUNCTION(fn, ...) \
        HHVM_FN(fn)(__VA_ARGS__)
#define HHVM_MALIAS(cn,fn,calias,falias) \
  HHVM_NAMED_ME(cn,fn,HHVM_MN(calias,falias))
#define HHVM_ME(cn,fn) HHVM_NAMED_ME(cn,fn, HHVM_MN(cn,fn))
#define HHVM_METHOD(cn, fn, ...) \
        HHVM_MN(cn,fn)(ObjectData* const this_, ##__VA_ARGS__)
#define HHVM_MN(cn,fn) c_ ## cn ## _ni_ ## fn
#define HHVM_NAMED_FE(fn, fimpl)\
  HHVM_NAMED_FE_STR(#fn, fimpl, nativeFuncs())
#define HHVM_NAMED_FE_STR(fn, fimpl, functable) \
        do { \
          String name{makeStaticString(fn)}; \
          registerExtensionFunction(name); \
          Native::registerNativeFunc(functable, name, fimpl); \
        } while(0)
#define HHVM_NAMED_ME(cn,fn,mimpl) \
        Native::registerNativeFunc(nativeFuncs(), #cn "->" #fn, mimpl)
#define HHVM_NAMED_STATIC_ME(cn,fn,mimpl) \
        Native::registerNativeFunc(nativeFuncs(), #cn "::" #fn, mimpl)
#define HHVM_NAMED_SYS_ME(cn,fn,mimpl) Native::registerNativeFunc(\
    Native::s_systemNativeFuncs, #cn "->" #fn, mimpl)
#define HHVM_RCC_BOOL(class_name, const_name, const_value)           \
  Native::registerClassConstant<KindOfBoolean>(s_##class_name.get(), \
    makeStaticString(#const_name), bool{const_value});
#define HHVM_RCC_DBL(class_name, const_name, const_value)            \
  Native::registerClassConstant<KindOfDouble>(s_##class_name.get(),  \
    makeStaticString(#const_name), double{const_value});
#define HHVM_RCC_INT(class_name, const_name, const_value)            \
  Native::registerClassConstant<KindOfInt64>(s_##class_name.get(),   \
    makeStaticString(#const_name), int64_t{const_value});
#define HHVM_RCC_STR(class_name, const_name, const_value)            \
  Native::registerClassConstant<KindOfString>(s_##class_name.get(),  \
    makeStaticString(#const_name), makeStaticString(const_value));
#define HHVM_RC_BOOL(const_name, const_value)                        \
  Native::registerConstant<KindOfBoolean>(                           \
    makeStaticString(#const_name), bool{const_value});
#define HHVM_RC_BOOL_SAME(const_name)                                \
  Native::registerConstant<KindOfBoolean>(                           \
    makeStaticString(#const_name), bool{const_name});
#define HHVM_RC_DBL(const_name, const_value)                         \
  Native::registerConstant<KindOfDouble>(                            \
    makeStaticString(#const_name), double{const_value});
#define HHVM_RC_DBL_SAME(const_name)                                 \
  Native::registerConstant<KindOfDouble>(                            \
    makeStaticString(#const_name), double{const_name});
#define HHVM_RC_DYNAMIC(const_name, const_value_cell)           \
  Native::registerConstant(makeStaticString(#const_name),       \
                           const_value_cell, true);
#define HHVM_RC_INT(const_name, const_value)                         \
  Native::registerConstant<KindOfInt64>(                             \
    makeStaticString(#const_name), int64_t{const_value});
#define HHVM_RC_INT_SAME(const_name)                                 \
  Native::registerConstant<KindOfInt64>(                             \
    makeStaticString(#const_name), int64_t{const_name});
#define HHVM_RC_STR(const_name, const_value)                         \
  Native::registerConstant<KindOfString>(                            \
    makeStaticString(#const_name), makeStaticString(const_value));
#define HHVM_RC_STR_SAME(const_name)                                 \
  Native::registerConstant<KindOfString>(                            \
    makeStaticString(#const_name), makeStaticString(const_name));
#define HHVM_STATIC_MALIAS(cn,fn,calias,falias) \
  HHVM_NAMED_STATIC_ME(cn,fn,HHVM_STATIC_MN(calias,falias))
#define HHVM_STATIC_ME(cn,fn) HHVM_NAMED_STATIC_ME(cn,fn,HHVM_STATIC_MN(cn,fn))
#define HHVM_STATIC_METHOD(cn, fn, ...) \
        HHVM_STATIC_MN(cn,fn)(const Class *self_, ##__VA_ARGS__)
#define HHVM_STATIC_MN(cn,fn) c_ ## cn ## _ns_ ## fn
#define HHVM_SYS_FE(fn)\
  HHVM_NAMED_FE_STR(#fn, HHVM_FN(fn), Native::s_systemNativeFuncs)
#define HHVM_SYS_ME(cn,fn) HHVM_NAMED_SYS_ME(cn,fn, HHVM_MN(cn,fn))
#define NATIVE_TYPES                                  \
    \
  X(Int32,      int32_t,              int32_t)        \
  X(Int64,      int64_t,              int64_t)        \
  X(Double,     double,               double)         \
  X(Bool,       bool,                 bool)           \
  X(Object,     const Object&,        Object)         \
  X(String,     const String&,        String)         \
  X(Array,      const Array&,         Array)          \
  X(Resource,   const Resource&,      Resource)       \
  X(Func,       Func*,                Func*)          \
  X(Class,      const Class*,         const Class*)   \
  X(ClsMeth,    ClsMethDataRef,       ClsMethDataRef) \
  X(Mixed,      const Variant&,       Variant)        \
  X(ObjectArg,  ObjectArg,            ObjectArg)      \
  X(StringArg,  StringArg,            StringArg)      \
  X(ArrayArg,   ArrayArg,             ArrayArg)       \
  X(ResourceArg,ResourceArg,          ResourceArg)    \
  X(MixedTV,    TypedValue,           TypedValue)     \
  X(This,       ObjectData*,          ObjectData*)    \
  X(Void,       void,                 void)           \
  X(IntIO,      int64_t&,             int64_t&)       \
  X(DoubleIO,   double&,              double&)        \
  X(BoolIO,     bool&,                bool&)          \
  X(ObjectIO,   Object&,              Object&)        \
  X(StringIO,   String&,              String&)        \
  X(ArrayIO,    Array&,               Array&)         \
  X(ResourceIO, Resource&,            Resource&)      \
  X(FuncIO,     Func*&,               Func*&)         \
  X(ClassIO,    Class*&,              Class*&)        \
  X(ClsMethIO,  ClsMethDataRef&,      ClsMethDataRef&)\
  X(MixedIO,    Variant&,             Variant&)       \
  
#define COLLECTIONS_ALL_TYPES(MACRO) \
  MACRO(Pair) \
  COLLECTIONS_PAIRED_TYPES(MACRO)
#define COLLECTIONS_PAIRED_TYPES(MACRO) \
  MACRO(Vector) MACRO(ImmVector) \
  MACRO(Map)    MACRO(ImmMap) \
  MACRO(Set)    MACRO(ImmSet)

#define PREG_FB_HACK_ARRAYS         (1<<30)
#define PREG_FB__PRIVATE__HSL_IMPL  (1<<29)
#define PREG_GREP_INVERT            (1<<0)
#define PREG_OFFSET_CAPTURE         (1<<8)
#define PREG_PATTERN_ORDER          1
#define PREG_REPLACE_EVAL           (1<<0)
#define PREG_SET_ORDER              2
#define PREG_SPLIT_DELIM_CAPTURE    (1<<1)
#define PREG_SPLIT_NO_EMPTY         (1<<0)
#define PREG_SPLIT_OFFSET_CAPTURE   (1<<2)
