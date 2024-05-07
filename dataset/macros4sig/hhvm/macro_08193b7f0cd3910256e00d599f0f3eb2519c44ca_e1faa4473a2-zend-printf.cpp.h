
#include<cmath>
#include<limits.h>
#include<string.h>

#include<cstdlib>
#include<cstdarg>
#include<cstring>
#include<sys/types.h>
#include<string>


#include<stdint.h>
#include<cstdint>
#include<stdarg.h>
#include<locale.h>
#include<stdio.h>
#include<ctype.h>
#include<stdexcept>


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
#define NUM_BUF_SIZE 500

