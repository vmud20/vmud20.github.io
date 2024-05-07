#include<stdarg.h>







#include<tuple>
#include<sys/wait.h>
#include<signal.h>
#include<map>

#include<atomic>
#include<sys/types.h>

#include<cstdint>

#include<ctype.h>

#include<fcntl.h>

#include<sys/socket.h>
#include<mutex>
#include<errno.h>

#include<algorithm>
#include<linux/futex.h>
#include<string>
#include<stdio.h>
#include<exception>


#include<cstdio>






#include<cstdlib>
#include<cerrno>

#include<cstring>
#include<chrono>

#include<stdexcept>

#include<cstddef>
#include<string.h>
#include<iostream>
#include<memory>

#include<cassert>

#include<array>
#include<thread>
#include<grp.h>


#include<stdint.h>
#include<vector>

#include<set>
#include<pthread.h>
#include<functional>
#include<cstdarg>

#include<utility>






#include<time.h>
#include<pwd.h>
#include<stdlib.h>
#include<syscall.h>

#include<type_traits>
#include<limits.h>

#include<unistd.h>
#include<sys/stat.h>
#define EXCEPTION_COMMON_IMPL(cls)               \
  cls* clone() override {                        \
    return new cls(*this);                       \
  }                                              \
  void throwException() override {               \
    Deleter deleter(this);                       \
    throw *this;                                 \
  }
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
#define PHP_DIR_SEPARATOR '/'
#define IMPLEMENT_LOGLEVEL(LEVEL)                       \
  template<typename... Args>                            \
  void Logger::F##LEVEL(Args&&... args) {               \
    if (LogLevel < Log##LEVEL) return;                  \
    LEVEL(folly::sformat(std::forward<Args>(args)...)); \
  }
#define THREAD_LOCAL(T, f) __thread HPHP::ThreadLocal<T> f
#define THREAD_LOCAL_FLAT(T, f) __thread HPHP::ThreadLocalFlat<T> f
#define THREAD_LOCAL_NO_CHECK(T, f) __thread HPHP::ThreadLocalNoCheck<T> f

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
#define CRONO_DEBUG(msg_n_args)  \
do { if (debug_file) print_debug_msg  msg_n_args; } while (0)
#define FAR_DISTANT_FUTURE  LONG_MAX
#define BIG_CONSTANT(x) (x##LLU)
#define ROTL64(x,y) rotl64(x,y)
#    define USE_HWCRC
#define checkRank(r) do { } while(0)
#define currentRank() RankBase
#define insertRank(r) do { } while(0)
#define popRank(r) do { } while(0)
#define pushRank(r) do { } while(0)
