#include<cassert>



#include<cinttypes>
#include<vector>
#include<limits.h>



#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<string>




#include<time.h>
#include<exception>
#include<functional>
#include<cstdint>
#include<utility>

#include<thread>

#include<pthread.h>
#include<type_traits>

#define checkRank(r) do { } while(0)
#define currentRank() RankBase
#define insertRank(r) do { } while(0)
#define popRank(r) do { } while(0)
#define pushRank(r) do { } while(0)
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
#define DEBUG_NOEXCEPT noexcept
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

