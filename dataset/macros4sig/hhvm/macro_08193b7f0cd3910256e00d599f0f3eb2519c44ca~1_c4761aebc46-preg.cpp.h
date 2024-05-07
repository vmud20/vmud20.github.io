







#include<stdarg.h>



#include<cassert>
#include<stdlib.h>
#include<algorithm>







#include<atomic>



#include<errno.h>












#include<cstdio>
#include<initializer_list>
#include<cstdlib>









#include<syscall.h>



#include<cstddef>














#include<fcntl.h>
#include<ctype.h>






#include<iostream>

#include<chrono>


#include<stdint.h>














#include<list>
#include<mutex>










#include<pthread.h>




#include<langinfo.h>









#include<time.h>


#include<functional>





#include<map>









#include<cstring>









#include<iosfwd>





#include<sys/stat.h>

#include<cinttypes>


#include<string>









#include<deque>





#include<memory>


#include<fstream>

#include<cstdarg>









#include<unordered_set>
#include<random>
#include<type_traits>
#include<bitset>










#include<signal.h>



#include<limits>

#include<inttypes.h>
#include<stdio.h>




#include<stddef.h>

#include<assert.h>








#include<unordered_map>








#include<limits.h>


#include<sys/types.h>

#include<array>
#include<ostream>
#include<exception>
#include<cerrno>
#include<queue>






#include<string.h>



#include<new>




#include<thread>


#include<zlib.h>

#include<stack>
#include<stdexcept>

#include<linux/futex.h>





#include<cstdint>
#include<tuple>


#include<set>






#include<vector>






#include<utility>




#include<climits>






#define BIG_CONSTANT(x) (x##LLU)
#define ROTL64(x,y) rotl64(x,y)
#    define USE_HWCRC
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
#define EXCEPTION_COMMON_IMPL(cls)               \
  cls* clone() override {                        \
    return new cls(*this);                       \
  }                                              \
  void throwException() override {               \
    Deleter deleter(this);                       \
    throw *this;                                 \
  }
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
#define PHP_DIR_SEPARATOR '/'
#define CRONO_DEBUG(msg_n_args)  \
do { if (debug_file) print_debug_msg  msg_n_args; } while (0)
#define FAR_DISTANT_FUTURE  LONG_MAX
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
#define init_null_variant tvAsCVarRef(&immutable_null_base)
#define uninit_variant    tvAsCVarRef(&immutable_uninit_base)
#define SKTRACE(level, sk, ...) \
  ONTRACE(level, sktrace(sk, __VA_ARGS__))
#define OFF(f)                          \
  static constexpr ptrdiff_t f##Off() { \
    return offsetof(Func, m_##f);       \
  }


#define HC(Opt, opt) void raise_hac_##opt##_notice(const std::string& msg);
#define HAC_CHECK_OPTS                         \
  HC(Compare, compare)                         \
  HC(ArrayKeyCast, array_key_cast)
# define CASE(name) case DataType##name: return "DataType" #name;
#define DATATYPES \
  DT(PersistentDArray, udt(0,  false)) \
  DT(DArray,           udt(0,  true))  \
  DT(PersistentVArray, udt(1,  false)) \
  DT(VArray,           udt(1,  true))  \
  DT(PersistentDict,   udt(2,  false)) \
  DT(Dict,             udt(2,  true))  \
  DT(PersistentVec,    udt(3,  false)) \
  DT(Vec,              udt(3,  true))  \
  DT(PersistentKeyset, udt(4,  false)) \
  DT(Keyset,           udt(4,  true))  \
  DT(Record,           udt(5,  true))  \
  DT(PersistentString, udt(6,  false)) \
  DT(String,           udt(6,  true))  \
  DT(Object,           udt(7,  true))  \
  DT(Resource,         udt(8,  true))  \
  DT(RFunc,            udt(9,  true))  \
  DT(RClsMeth,         udt(10, true))  \
  DT(ClsMeth,          udt(11, !use_lowptr)) \
  DT(Boolean,          udt(12, false)) \
  DT(Int64,            udt(13, false)) \
  DT(Double,           udt(14, false)) \
  DT(Func,             udt(15, false)) \
  DT(Class,            udt(16, false)) \
  DT(LazyClass,        udt(17, false)) \
  DT(Uninit,           udt(18, false)) \
  DT(Null,             udt(19, false))
#define DT(name, value) name = value,
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
#define ut_t(t) static_cast<std::make_unsigned<data_type_t>::type>(t)
#define DEF_ACCESSORS(Type, TypeName, fields, Fields)                         \
  Type const* fields() const      { return m_##fields.accessList(); }         \
  Type*       mutable##Fields()   { return m_##fields.mutableAccessList(); }  \
  size_t      num##Fields() const { return m_##fields.size(); }               \
  using TypeName##Range = folly::Range<Type const*>;                          \
  TypeName##Range all##Fields() const {                                       \
    return TypeName##Range(fields(), m_##fields.size());                      \
  }


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
  O(CGetS,           ONE(OA(ReadOnlyOp)),                               \
                     TWO(CV,CV),      ONE(CV),    NF) \
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
  O(SetS,            ONE(OA(ReadOnlyOp)),                               \
                                       THREE(CV,CV,CV), ONE(CV),    NF) \
  O(SetOpL,          TWO(LA,                                            \
                       OA(SetOpOp)),   ONE(CV),         ONE(CV),    NF) \
  O(SetOpG,          ONE(OA(SetOpOp)), TWO(CV,CV),      ONE(CV),    NF) \
  O(SetOpS,          TWO(OA(SetOpOp), OA(ReadOnlyOp)),                  \
                                       THREE(CV,CV,CV), ONE(CV),    NF) \
  O(IncDecL,         TWO(NLA, OA(IncDecOp)),                            \
                                       NOV,             ONE(CV),    NF) \
  O(IncDecG,         ONE(OA(IncDecOp)),ONE(CV),         ONE(CV),    NF) \
  O(IncDecS,         TWO(OA(IncDecOp), OA(ReadOnlyOp)),                 \
                                       TWO(CV,CV),      ONE(CV),    NF) \
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
  O(InitProp,        THREE(SA, OA(InitPropOp), OA(ReadOnlyOp)),         \
                                       ONE(CV),         NOV,        NF) \
  O(Silence,         TWO(LA,OA(SilenceOp)),                             \
                                       NOV,             NOV,        NF) \
  O(ThrowNonExhaustiveSwitch, NA,      NOV,             NOV,        NF) \
  O(RaiseClassStringConversionWarning,                                  \
                              NA,      NOV,             NOV,        NF) \
  O(BaseGC,          TWO(IVA, OA(MOpMode)),                             \
                                       NOV,             NOV,        NF) \
  O(BaseGL,          TWO(LA, OA(MOpMode)),                              \
                                       NOV,             NOV,        NF) \
  O(BaseSC,          FOUR(IVA, IVA, OA(MOpMode), OA(ReadOnlyOp)),       \
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
  O(SetRangeM,       FOUR(IVA, IVA, OA(SetRangeOp), OA(ReadOnlyOp)),    \
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
#define READONLY_OPS    \
  OP(Any)               \
  OP(ReadOnly)          \
  OP(Mutable)                  
#define COL(name) name = uint8_t(HeaderKind::name),
#define COLLECTION_TYPES              \
  COL(Vector)                         \
  COL(Map)                            \
  COL(Set)                            \
  COL(Pair)                           \
  COL(ImmVector)                      \
  COL(ImmMap)                         \
  COL(ImmSet)
#define X(dt, cpp) \
template<> struct DataTypeCPPType<dt> { using type = cpp; }
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
    TAG(SVecish)                                  \
    TAG(OptSVecish)                               \
    TAG(Vecish)                                   \
    TAG(OptVecish)                                \
    TAG(SDictish)                                 \
    TAG(OptSDictish)                              \
    TAG(Dictish)                                  \
    TAG(OptDictish)                               \
    TAG(SArrLike)                                 \
    TAG(OptSArrLike)                              \
    TAG(ArrLike)                                  \
    TAG(OptArrLike)                               \
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


#define SIZE_CLASS(index, lg_grp, lg_delta, ndelta, lg_delta_lookup, ncontig) \
  sizeClassParams2StringCapacity(lg_grp, lg_delta, ndelta),
#define NO_M_DATA 1
#define SD_DATA   16
#define SD_HASH   12
#define SD_LEN    8
#define S2I_4(i)  i,
#define S2I_5(i)  S2I_4(i) S2I_4(i)
#define S2I_6(i)  S2I_5(i) S2I_5(i)
#define S2I_7(i)  S2I_6(i) S2I_6(i)
#define S2I_8(i)  S2I_7(i) S2I_7(i)
#define S2I_9(i)  S2I_8(i) S2I_8(i)

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
  F(bool, HackCompilerUseCompilerPool, true)                            \
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
  F(uint32_t, RDSSize,                 64 << 20)                        \
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
  F(bool,     JitLayoutExtTSP,         true)                            \
  F(double,   JitLayoutMaxMergeRatio,  1000000)                         \
  F(bool,     JitLayoutPruneCatchArcs, true)                            \
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
  F(uint64_t, AssemblerMaxScalarSize,  2147483648)             \
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
  F(uint32_t, LowArenaMinAddr,         1u << 30)                        \
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
  F(uint32_t, MemTrackStart,           3500)                            \
  F(uint32_t, MemTrackEnd,             3700)                            \
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
  F(uint64_t, BespokeEscalationSampleRate, 0)                           \
  F(uint64_t, EmitLoggingArraySampleRate, 1000)                         \
  F(string, ExportLoggingArrayDataPath, "")                             \
              \
  F(int32_t, BespokeArraySpecializationMode, 0)                         \
          \
  F(double, BespokeArraySourceSpecializationThreshold, 95.0)            \
  F(double, BespokeArraySinkSpecializationThreshold,   99.0)            \
            \
  F(bool, HackArrCompatNotices, false)                                  \
  F(bool, HackArrCompatCheckCompare, false)                             \
  F(bool, HackArrCompatFBSerializeHackArraysNotices, false)             \
    \
  F(bool, HackArrCompatIntishCastNotices, false)                        \
       \
  F(bool, HackArrCompatArraySliceIntishCastNotices, true)               \
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
  F(bool, RaiseArraySerializationNotices, false)                        \
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
  F(bool, FoldLazyClassKeys, true)                                      \
                             \
  F(int32_t, EmitClassPointers, 0)                                      \
                     \
  F(bool, ClassAsStringVarDump, true)                                   \
                          \
  F(bool, ClassAsStringGetType, true)                                   \
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
                                             \
  F(bool, HackRecords, false)                                           \
                                                                     \
  F(int32_t, ForbidDynamicCallsToFunc, 0)                               \
  F(int32_t, ForbidDynamicCallsToClsMeth, 0)                            \
  F(int32_t, ForbidDynamicCallsToInstMeth, 0)                           \
  F(int32_t, ForbidDynamicConstructs, 0)                                \
                                                                     \
  F(bool, ForbidDynamicCallsWithAttr, true)                             \
              \
  F(bool, LogKnownMethodsAsDynamicCalls, true)                          \
                                                                     \
  F(int32_t, ForbidUnserializeIncompleteClass, 0)                       \
                                                                     \
  F(StringToIntMap, CoeffectEnforcementLevels, {})                      \
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
  F(bool, StressUnitSerde, false)                                       \
                                                         \
  F(uint64_t, DynamicFunLevel, 1)                                       \
                                                         \
  F(uint64_t, DynamicClsMethLevel, 1)                                   \
                                                         \
  F(uint64_t, DynamicMethCallerLevel, 1)                                \
  F(bool, APCSerializeFuncs, true)                                      \
  F(bool, APCSerializeClsMeth, true)                                    \
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
                                      \
  F(int32_t, NoticeOnCoerceForStrConcat, 0)                             \
  
#define F(type, name, unused) \
  static type Eval ## name;
#define H(t, n, ...) t n;
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
  H(bool,           DisallowDynamicMethCallerArgs,    false)          \
  H(bool,           DisallowInstMeth,                 false)          \
  
# define htonq(a) (a)
# define ntohq(a) (a)
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
      TM(coeffects)     \
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
#define ARRPROV_HERE() ([&]{                                           \
    static auto const tag = ::HPHP::arrprov::Tag::RuntimeLocation(     \
        ::HPHP::makeStaticString("__FILE__" ":" ARRPROV_STR("__LINE__"))); \
    return tag;                                                        \
  }())
#define ARRPROV_HERE_POISON() ([&]{                                      \
    static auto const tag = ::HPHP::arrprov::Tag::RuntimeLocationPoison( \
        ::HPHP::makeStaticString("__FILE__" ":" ARRPROV_STR("__LINE__")));   \
    return tag;                                                          \
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


#define checkRank(r) do { } while(0)
#define currentRank() RankBase
#define insertRank(r) do { } while(0)
#define popRank(r) do { } while(0)
#define pushRank(r) do { } while(0)




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
  x(DivisionByZeroException)                    \
  x(InvalidForeachArgumentException)            \
  x(UndefinedPropertyException)                 \
  x(UndefinedVariableException)
#define SYSTEMLIB_HH_CLASSES(x) \
  x(Traversable)                \
  x(Iterator)                   \
  x(SwitchableClass)            \


#define X(kind) \
template<typename T> \
enable_if_lval_t<T, void> tvCastTo##kind##InPlace(T tv);
#define Y(kind) \
template<typename T, IntishCast IC = IntishCast::None> \
enable_if_lval_t<T, void> tvCastTo##kind##InPlace(T tv);

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
#define SYNC_VM_REGS_SCOPED() \
  HPHP::VMRegAnchor _anchorUnused
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
# define HHVM_VERSION_MINOR 98
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
  

#define ARCH_SWITCH_CALL(func, ...)                                   \
  ([&]() -> decltype(x64::func(__VA_ARGS__)) {                        \
    switch (arch()) {                                                 \
      case Arch::X64:                                                 \
        return x64::MSVC_GLUE(func, (__VA_ARGS__));                   \
      case Arch::ARM:                                                 \
        return arm::MSVC_GLUE(func, (__VA_ARGS__));                   \
      case Arch::PPC64:                                               \
        return ppc64::MSVC_GLUE(func, (__VA_ARGS__));                 \
    }                                                                 \
    not_reached();                                                    \
  }())
#define MSVC_GLUE(x, y) x y
#define BYTE_LOAD_OP(name)                                    \
  virtual void name##b(MemoryRef m, Reg8 r) = 0;
#define BYTE_REG_OP(name)                                     \
  virtual void name##b(Reg8 r1, Reg8 r2)     = 0;             \
  virtual void name##b(Immed i, Reg8 r)      = 0;
#define BYTE_STORE_OP(name)                                   \
  virtual void name##b(Reg8 r, MemoryRef m)  = 0;             \
  virtual void name##b(Immed i, MemoryRef m) = 0;
#define CC(nm, code)                                                        \
  inline void X64AssemblerBase::j##nm(Label& l) { l.jcc(*this, code); }     \
  inline void X64AssemblerBase::j##nm##8(Label& l) { l.jcc8(*this, code); }
#define CCS \
  CC(o,   CC_O)         \
  CC(no,  CC_NO)        \
  CC(nae, CC_NAE)       \
  CC(ae,  CC_AE)        \
  CC(nb,  CC_NB)        \
  CC(e,   CC_E)         \
  CC(z,   CC_Z)         \
  CC(ne,  CC_NE)        \
  CC(nz,  CC_NZ)        \
  CC(b,   CC_B)         \
  CC(be,  CC_BE)        \
  CC(nbe, CC_NBE)       \
  CC(s,   CC_S)         \
  CC(ns,  CC_NS)        \
  CC(p,   CC_P)         \
  CC(np,  CC_NP)        \
  CC(nge, CC_NGE)       \
  CC(g,   CC_G)         \
  CC(l,   CC_L)         \
  CC(ge,  CC_GE)        \
  CC(nl,  CC_NL)        \
  CC(ng,  CC_NG)        \
  CC(le,  CC_LE)        \
  CC(nle, CC_NLE)
#define FULL_OP(name)                                         \
  LOAD_OP(name)                                               \
  STORE_OP(name)                                              \
  REG_OP(name)                                                \
  IMM64_STORE_OP(name)                                        \
  IMM64R_OP(name)
#define IMM64R_OP(name)                                       \
  virtual void name##q(Immed imm, Reg64 r) = 0;
#define IMM64_STORE_OP(name)                                  \
  virtual void name##q(Immed i, MemoryRef m) = 0;
#define LOAD_OP(name)                                         \
  virtual void name##q(MemoryRef m, Reg64 r) = 0;             \
  virtual void name##l(MemoryRef m, Reg32 r) = 0;             \
  virtual void name##w(MemoryRef m, Reg16 r) = 0;             \
  virtual void name##q(RIPRelativeRef m, Reg64 r) = 0;        \
  BYTE_LOAD_OP(name)
#define NEW_X64_ASM(var, cb)                                      \
  std::unique_ptr<X64AssemblerBase> _assembler(                   \
    RuntimeOption::EvalUseXedAssembler ?                          \
    (X64AssemblerBase*)new XedAssembler(cb) :                     \
    (X64AssemblerBase*)new X64Assembler(cb));                     \
  X64AssemblerBase& var = *_assembler
#define REG_OP(name)                                          \
  virtual void name##q(Reg64 r1, Reg64 r2) = 0;               \
  virtual void name##l(Reg32 r1, Reg32 r2) = 0;               \
  virtual void name##w(Reg16 r1, Reg16 r2) = 0;               \
  virtual void name##l(Immed i, Reg32 r)   = 0;               \
  virtual void name##w(Immed i, Reg16 r)   = 0;               \
  BYTE_REG_OP(name)
#define SIMPLE_REGTYPE(What)                                        \
  struct What {                                                     \
    explicit constexpr What(int rn) : rn(rn) {}                     \
    explicit constexpr operator int() const { return rn; }          \
    constexpr bool operator==(What o) const { return rn == o.rn; }  \
    constexpr bool operator!=(What o) const { return rn != o.rn; }  \
  private:                                                          \
    int rn;                                                         \
  }
#define STORE_OP(name)                                        \
  virtual void name##w(Immed i, MemoryRef m) = 0;             \
  virtual void name##l(Immed i, MemoryRef m) = 0;             \
  virtual void name##w(Reg16 r, MemoryRef m) = 0;             \
  virtual void name##l(Reg32 r, MemoryRef m) = 0;             \
  virtual void name##q(Reg64 r, MemoryRef m) = 0;             \
  BYTE_STORE_OP(name)
#define TRACEMOD ::HPHP::Trace::asmx64
#define X(x) if (r == x) return "%"#x
#define UMR(m) rn(m.r.base), rn(m.r.index), m.r.scale, m.r.disp
#define URIP(m) noreg, noreg, sz::byte, m.r.disp
#define CC_TO_XED_ARRAY(xed_instr) {                            \
    XED_ICLASS_##xed_instr##O,        \
    XED_ICLASS_##xed_instr##NO,       \
    XED_ICLASS_##xed_instr##B,        \
    XED_ICLASS_##xed_instr##NB,       \
    XED_ICLASS_##xed_instr##Z,        \
    XED_ICLASS_##xed_instr##NZ,       \
    XED_ICLASS_##xed_instr##BE,       \
    XED_ICLASS_##xed_instr##NBE,      \
    XED_ICLASS_##xed_instr##S,        \
    XED_ICLASS_##xed_instr##NS,       \
    XED_ICLASS_##xed_instr##P,        \
    XED_ICLASS_##xed_instr##NP,       \
    XED_ICLASS_##xed_instr##L,        \
    XED_ICLASS_##xed_instr##NL,       \
    XED_ICLASS_##xed_instr##LE,       \
    XED_ICLASS_##xed_instr##NLE       \
  }
#define IMMPROP(size, allsizes) size
#define XED_INSTIR_WRAPPER_IMPL(bitsize)                            \
  ALWAYS_INLINE                                                     \
  void xedInstrIR(xed_iclass_enum_t instr, const Immed& i,          \
                  const Reg##bitsize& r,                            \
                  int immSize = bitsToBytes(bitsize)) {             \
    xedEmit(instr, toXedOperand(r), toXedOperand(i, immSize),       \
            bitsize);                                               \
  }                                                                 \

#define XED_INSTMR_WRAPPER_IMPL(bitsize)                                \
  ALWAYS_INLINE                                                         \
  void xedInstrMR(xed_iclass_enum_t instr, const MemoryRef& m,          \
                  const Reg##bitsize& r,                                \
                  int memSize = bitsToBytes(bitsize)) {                 \
    xedEmit(instr, toXedOperand(r), toXedOperand(m, memSize), bitsize); \
  }                                                                     \
                                                                        \
  ALWAYS_INLINE                                                         \
  void xedInstrMR(xed_iclass_enum_t instr, RIPRelativeRef m,            \
                  const Reg##bitsize& r) {                              \
    static XedLenCache lenCache;                                        \
    auto instrLen = xedCacheLen(                                        \
                      &lenCache,                                        \
                      [&] {                                             \
                        return xedEmit(                                 \
                                instr, toXedOperand(r),                 \
                                toXedOperand(nullrip,                   \
                                             bitsToBytes(bitsize)),     \
                                bitsize, dest());                       \
                      }, xedLenCacheKey(instr, 0));                     \
    m.r.disp -= ((int64_t)frontier() + (int64_t)instrLen);              \
    xedEmit(instr, toXedOperand(r),                                     \
            toXedOperand(m, bitsToBytes(bitsize)), bitsize);            \
  }
#define XED_INSTRM_WRAPPER_IMPL(bitsize)                            \
  ALWAYS_INLINE                                                     \
  void xedInstrRM(xed_iclass_enum_t instr, const Reg##bitsize& r,   \
                  const MemoryRef& m) {                             \
    xedEmit(instr, toXedOperand(m, bitsToBytes(bitsize)),           \
            toXedOperand(r), bitsize);                              \
  }
#define XED_INSTRR_WRAPPER_IMPL(bitsize)                            \
  ALWAYS_INLINE                                                     \
  void xedInstrRR(xed_iclass_enum_t instr, const Reg##bitsize& r1,  \
                  const Reg##bitsize& r2) {                         \
    xedEmit(instr, toXedOperand(r2), toXedOperand(r1), bitsize);    \
  }
#define XED_INSTR_WRAPPER_IMPL(bitsize)                             \
  ALWAYS_INLINE                                                     \
  void xedInstrR(xed_iclass_enum_t instr, const Reg##bitsize& r) {  \
    xedEmit(instr, toXedOperand(r), bitsize);                       \
  }
#define XED_WRAP_IMPL() \
  XED_WRAP_X(64)        \
  XED_WRAP_X(32)        \
  XED_WRAP_X(16)        \
  XED_WRAP_X(8)
#define XED_WRAP_X XED_INSTR_WRAPPER_IMPL
#define DECLARE_VNUM(Vnum, type, check, prefix)           \
struct Vnum {                                             \
  Vnum() {}                                               \
  explicit Vnum(size_t n) : n(safe_cast<type>(n)) {}      \
                                                          \
   operator size_t() const {                \
    if (check) assertx(n != kInvalidId);                  \
    return n;                                             \
  }                                                       \
                                                          \
  bool isValid() const {                                  \
    return n != kInvalidId;                               \
  }                                                       \
                                                          \
  std::string toString() const {                          \
    if (n == kInvalidId) return prefix "?";               \
    return folly::to<std::string>(prefix, n);             \
  }                                                       \
                                                          \
private:                                                  \
  static constexpr type kInvalidId =                      \
    static_cast<type>(0xffffffff);                        \
  type n{kInvalidId};                                     \
}
#define DEFINE_FPREGISTERS(N)  \
const FPRegister s##N(N, kSRegSize);  \
const FPRegister d##N(N, kDRegSize);  \
const FPRegister v##N(N, kVRegSize);
#define DEFINE_REGISTERS(N)  \
const Register w##N(N, kWRegSize);  \
const Register x##N(N, kXRegSize);

  #define DEFINE_GETTER(Name, HighBit, LowBit, Func)             \
  inline int64_t Name() const { return Func(HighBit, LowBit); }

  #define ADD_SUB_EXTENDED(A)           \
  A##_w_ext = AddSubExtendedFixed | A,  \
  A##_x_ext = AddSubExtendedFixed | A | SixtyFourBits
  #define ADD_SUB_IMMEDIATE(A)           \
  A##_w_imm = AddSubImmediateFixed | A,  \
  A##_x_imm = AddSubImmediateFixed | A | SixtyFourBits
#define ADD_SUB_OP_LIST(V)  \
  V(ADD),                   \
  V(ADDS),                  \
  V(SUB),                   \
  V(SUBS)
  #define ADD_SUB_SHIFTED(A)             \
  A##_w_shift = AddSubShiftedFixed | A,  \
  A##_x_shift = AddSubShiftedFixed | A | SixtyFourBits
#define DECLARE_FIELDS_OFFSETS(Name, HighBit, LowBit, X)                       \
const int Name##_offset = LowBit;                                              \
const int Name##_width = HighBit - LowBit + 1;                                 \
const uint32_t Name##_mask = ((1 << Name##_width) - 1) << LowBit;
#define INSTRUCTION_FIELDS_LIST(V_)                                            \
                                                          \
V_(Rd, 4, 0, Bits)                              \
V_(Rn, 9, 5, Bits)                              \
V_(Rm, 20, 16, Bits)                            \
V_(Ra, 14, 10, Bits)                            \
V_(Rt, 4, 0, Bits)                              \
V_(Rt2, 14, 10, Bits)                           \
V_(Rs, 20, 16, Bits)                            \
V_(PrefetchMode, 4, 0, Bits)                                                   \
                                                                               \
                                                              \
V_(SixtyFourBits, 31, 31, Bits)                                                \
V_(FlagsUpdate, 29, 29, Bits)                                                  \
                                                                               \
                                                   \
V_(ImmPCRelHi, 23, 5, SignedBits)                                              \
V_(ImmPCRelLo, 30, 29, Bits)                                                   \
                                                                               \
                                      \
V_(ShiftDP, 23, 22, Bits)                                                      \
V_(ImmDPShift, 15, 10, Bits)                                                   \
                                                                               \
                                                   \
V_(ImmAddSub, 21, 10, Bits)                                                    \
V_(ShiftAddSub, 23, 22, Bits)                                                  \
                                                                               \
                                                     \
V_(ImmExtendShift, 12, 10, Bits)                                               \
V_(ExtendMode, 15, 13, Bits)                                                   \
                                                                               \
                                                                \
V_(ImmMoveWide, 20, 5, Bits)                                                   \
V_(ShiftMoveWide, 22, 21, Bits)                                                \
                                                                               \
                                  \
V_(BitN, 22, 22, Bits)                                                         \
V_(ImmRotate, 21, 16, Bits)                                                    \
V_(ImmSetBits, 15, 10, Bits)                                                   \
V_(ImmR, 21, 16, Bits)                                                         \
V_(ImmS, 15, 10, Bits)                                                         \
                                                                               \
                                                \
V_(ImmTestBranch, 18, 5, SignedBits)                                           \
V_(ImmTestBranchBit40, 23, 19, Bits)                                           \
V_(ImmTestBranchBit5, 31, 31, Bits)                                            \
                                                                               \
                                                             \
V_(Condition, 15, 12, Bits)                                                    \
V_(ConditionBranch, 3, 0, Bits)                                                \
V_(Nzcv, 3, 0, Bits)                                                           \
V_(ImmCondCmp, 20, 16, Bits)                                                   \
V_(ImmCondBranch, 23, 5, SignedBits)                                           \
                                                                               \
                                                           \
V_(FPType, 23, 22, Bits)                                                       \
V_(ImmFP, 20, 13, Bits)                                                        \
V_(FPScale, 15, 10, Bits)                                                      \
                                                                               \
                                                               \
V_(ImmLS, 20, 12, SignedBits)                                                  \
V_(ImmLSUnsigned, 21, 10, Bits)                                                \
V_(ImmLSPair, 21, 15, SignedBits)                                              \
V_(SizeLS, 31, 30, Bits)                                                       \
V_(ImmShiftLS, 12, 12, Bits)                                                   \
                                                                               \
                                                         \
V_(ImmUncondBranch, 25, 0, SignedBits)                                         \
V_(ImmCmpBranch, 23, 5, SignedBits)                                            \
V_(ImmLLiteral, 23, 5, SignedBits)                                             \
V_(ImmException, 20, 5, Bits)                                                  \
V_(ImmHint, 11, 5, Bits)                                                       \
                                                                               \
                                                        \
V_(ImmSystemRegister, 19, 5, Bits)                                             \
V_(SysO0, 19, 19, Bits)                                                        \
V_(SysOp1, 18, 16, Bits)                                                       \
V_(SysOp2, 7, 5, Bits)                                                         \
V_(CRn, 15, 12, Bits)                                                          \
V_(CRm, 11, 8, Bits)                                                           \
                                                                               \
                                                   \
V_(Ar, 23, 22, Bits)                                                           \
V_(Opc, 14, 12, Bits)                                                          \

  #define LOAD_STORE(A, B, C, D)  \
  A##B##_##C = D
#define LOAD_STORE_OP_LIST(V)     \
  V(ST, RB, w,  0x00000000),  \
  V(ST, RH, w,  0x40000000),  \
  V(ST, R, w,   0x80000000),  \
  V(ST, R, x,   0xC0000000),  \
  V(LD, RB, w,  0x00400000),  \
  V(LD, RH, w,  0x40400000),  \
  V(LD, R, w,   0x80400000),  \
  V(LD, R, x,   0xC0400000),  \
  V(LD, RSB, x, 0x00800000),  \
  V(LD, RSH, x, 0x40800000),  \
  V(LD, RSW, x, 0x80800000),  \
  V(LD, RSB, w, 0x00C00000),  \
  V(LD, RSH, w, 0x40C00000),  \
  V(ST, R, s,   0x84000000),  \
  V(ST, R, d,   0xC4000000),  \
  V(LD, R, s,   0x84400000),  \
  V(LD, R, d,   0xC4400000)
  #define LOAD_STORE_PAIR(A, B, C) \
  A##_##B = C
  #define LOAD_STORE_PAIR_OFFSET(A, B, C)  \
  A##_##B##_off = LoadStorePairOffsetFixed | A##_##B
#define LOAD_STORE_PAIR_OP_LIST(V)  \
  V(STP, w,   0x00000000),          \
  V(LDP, w,   0x00400000),          \
  V(LDPSW, x, 0x40400000),          \
  V(STP, x,   0x80000000),          \
  V(LDP, x,   0x80400000),          \
  V(STP, s,   0x04000000),          \
  V(LDP, s,   0x04400000),          \
  V(STP, d,   0x44000000),          \
  V(LDP, d,   0x44400000)
  #define LOAD_STORE_PAIR_POST_INDEX(A, B, C)  \
  A##_##B##_post = LoadStorePairPostIndexFixed | A##_##B
  #define LOAD_STORE_PAIR_PRE_INDEX(A, B, C)  \
  A##_##B##_pre = LoadStorePairPreIndexFixed | A##_##B
  #define LOAD_STORE_POST_INDEX(A, B, C, D)  \
  A##B##_##C##_post = LoadStorePostIndexFixed | D
  #define LOAD_STORE_PRE_INDEX(A, B, C, D)  \
  A##B##_##C##_pre = LoadStorePreIndexFixed | D
  #define LOAD_STORE_REGISTER_OFFSET(A, B, C, D) \
  A##B##_##C##_reg = LoadStoreRegisterOffsetFixed | D
  #define LOAD_STORE_UNSCALED(A, B, C, D)  \
  A##U##B##_##C = LoadStoreUnscaledOffsetFixed | D
  #define LOAD_STORE_UNSIGNED_OFFSET(A, B, C, D) \
  A##B##_##C##_unsigned = LoadStoreUnsignedOffsetFixed | D
  #define LSELD(A)       \
  LSELD_##A##_b   = LseLdOpFixed | LSESizeB | LSEAquireReleaseN  | LSE_LD##A, \
  LSELD_##A##_ab  = LseLdOpFixed | LSESizeB | LSEAquireReleaseA  | LSE_LD##A, \
  LSELD_##A##_lb  = LseLdOpFixed | LSESizeB | LSEAquireReleaseL  | LSE_LD##A, \
  LSELD_##A##_alb = LseLdOpFixed | LSESizeB | LSEAquireReleaseAL | LSE_LD##A, \
  LSELD_##A##_h   = LseLdOpFixed | LSESizeH | LSEAquireReleaseN  | LSE_LD##A, \
  LSELD_##A##_ah  = LseLdOpFixed | LSESizeH | LSEAquireReleaseA  | LSE_LD##A, \
  LSELD_##A##_lh  = LseLdOpFixed | LSESizeH | LSEAquireReleaseL  | LSE_LD##A, \
  LSELD_##A##_alh = LseLdOpFixed | LSESizeH | LSEAquireReleaseAL | LSE_LD##A, \
  LSELD_##A##_w   = LseLdOpFixed | LSESizeW | LSEAquireReleaseN  | LSE_LD##A, \
  LSELD_##A##_aw  = LseLdOpFixed | LSESizeW | LSEAquireReleaseA  | LSE_LD##A, \
  LSELD_##A##_lw  = LseLdOpFixed | LSESizeW | LSEAquireReleaseL  | LSE_LD##A, \
  LSELD_##A##_alw = LseLdOpFixed | LSESizeW | LSEAquireReleaseAL | LSE_LD##A, \
  LSELD_##A##_x   = LseLdOpFixed | LSESizeX | LSEAquireReleaseN  | LSE_LD##A, \
  LSELD_##A##_ax  = LseLdOpFixed | LSESizeX | LSEAquireReleaseA  | LSE_LD##A, \
  LSELD_##A##_lx  = LseLdOpFixed | LSESizeX | LSEAquireReleaseL  | LSE_LD##A, \
  LSELD_##A##_alx = LseLdOpFixed | LSESizeX | LSEAquireReleaseAL | LSE_LD##A
#define LSELD_OP_LIST(V) \
  V(ADD),                \
  V(BIC),                \
  V(EOR),                \
  V(ORR),                \
  V(SMAX),               \
  V(SMIN),               \
  V(UMAX),               \
  V(UMIN)
#define NOTHING(A, B)
#define REGISTER_CODE_LIST(R)                                                  \
R(0)  R(1)  R(2)  R(3)  R(4)  R(5)  R(6)  R(7)                                 \
R(8)  R(9)  R(10) R(11) R(12) R(13) R(14) R(15)                                \
R(16) R(17) R(18) R(19) R(20) R(21) R(22) R(23)                                \
R(24) R(25) R(26) R(27) R(28) R(29) R(30) R(31)
#define SYSTEM_REGISTER_FIELDS_LIST(V_, M_)                                    \
                                                                     \
V_(Flags, 31, 28, Bits)                                                        \
V_(N, 31, 31, Bits)                                                            \
V_(Z, 30, 30, Bits)                                                            \
V_(C, 29, 29, Bits)                                                            \
V_(V, 28, 28, Bits)                                                            \
M_(NZCV, Flags_mask)                                                           \
                                                                               \
                                                                     \
V_(AHP, 26, 26, Bits)                                                          \
V_(DN, 25, 25, Bits)                                                           \
V_(FZ, 24, 24, Bits)                                                           \
V_(RMode, 23, 22, Bits)                                                        \
M_(FPCR, AHP_mask | DN_mask | FZ_mask | RMode_mask)

#define DECLARE_IS_INT_N(N)                                                    \
inline bool is_int##N(int64_t x) { return is_intn(N, x); }
#define DECLARE_IS_UINT_N(N)                                                   \
inline bool is_uint##N(int64_t x) { return is_uintn(N, x); }
#define DECLARE_TRUNCATE_TO_INT_N(N)                                           \
inline int truncate_to_int##N(int x) { return truncate_to_intn(N, x); }
#define INT_1_TO_63_LIST(V)                                                    \
V(1)  V(2)  V(3)  V(4)  V(5)  V(6)  V(7)  V(8)                                 \
V(9)  V(10) V(11) V(12) V(13) V(14) V(15) V(16)                                \
V(17) V(18) V(19) V(20) V(21) V(22) V(23) V(24)                                \
V(25) V(26) V(27) V(28) V(29) V(30) V(31) V(32)                                \
V(33) V(34) V(35) V(36) V(37) V(38) V(39) V(40)                                \
V(41) V(42) V(43) V(44) V(45) V(46) V(47) V(48)                                \
V(49) V(50) V(51) V(52) V(53) V(54) V(55) V(56)                                \
V(57) V(58) V(59) V(60) V(61) V(62) V(63)

#define ALIGNMENT_EXCEPTION() printf("ALIGNMENT EXCEPTION\t"); abort()

#define O(name, imms, uses, defs) name,
#define TRAP_REASON Reason{"__FILE__", "__LINE__"
#define VASM_OPCODES\
  \
  O(bindjmp, I(target) I(spOff), U(args), Dn)\
  O(bindjcc, I(cc) I(target) I(spOff), U(sf) U(args), Dn)\
  O(bindaddr, I(addr) I(target) I(spOff), Un, Dn)\
  O(fallback, I(target) I(spOff), U(args), Dn)\
  O(fallbackcc, I(cc) I(target) I(spOff), U(sf) U(args), Dn)\
  O(retransopt, I(sk) I(spOff), U(args), Dn)\
  \
  O(copy, Inone, UH(s,d), DH(d,s))\
  O(copy2, Inone, UH(s0,d0) UH(s1,d1), DH(d0,s0) DH(d1,s1))\
  O(copyargs, Inone, UH(s,d), DH(d,s))\
  O(debugtrap, Inone, Un, Dn)\
  O(fallthru, Inone, U(args), Dn)\
  O(ldimmb, I(s), Un, D(d))\
  O(ldimmw, I(s), Un, D(d))\
  O(ldimml, I(s), Un, D(d))\
  O(ldimmq, I(s), Un, D(d))\
  O(ldundefq, Inone, Un, D(d))\
  O(movqs, I(s) I(addr), Un, D(d))\
  O(load, Inone, U(s), D(d))\
  O(store, Inone, U(s) UW(d), Dn)\
  O(mcprep, Inone, Un, D(d))\
  O(phidef, Inone, Un, D(defs))\
  O(phijmp, Inone, U(uses), Dn)\
  O(conjure, Inone, Un, D(c))\
  O(conjureuse, Inone, U(c), Dn)\
  O(inlinestart, Inone, Un, Dn)\
  O(inlineend, Inone, Un, Dn)\
  O(pushframe, Inone, Un, Dn)\
  O(popframe, Inone, Un, Dn)\
  O(recordstack, Inone, Un, Dn)\
  O(recordbasenativesp, Inone, Un, Dn)\
  O(spill, Inone, U(s), D(d))\
  O(spillbi, I(s), Un, D(d))\
  O(spillli, I(s), Un, D(d))\
  O(spillqi, I(s), Un, D(d))\
  O(spillundefq, Inone, Un, D(d))\
  O(reload, Inone, U(s), D(d))\
  O(ssaalias, Inone, U(s), D(d))\
  \
  O(vcall, I(call) I(destType) I(fixup), U(args), D(d))\
  O(vinvoke, I(call) I(destType) I(fixup), U(args), D(d))\
  O(call, I(target), U(args), Dn)\
  O(callm, Inone, U(target) U(args), Dn)\
  O(callr, Inone, U(target) U(args), Dn)\
  O(calls, I(target), U(args), Dn)\
  O(ret, Inone, U(args), Dn)\
  \
  O(stublogue, Inone, Un, Dn)\
  O(unstublogue, Inone, Un, Dn)\
  O(stubret, Inone, U(args), Dn)\
  O(callstub, I(target), U(args), Dn)\
  O(callfaststub, I(fix), U(args), Dn)\
  O(tailcallstub, I(target), U(args), Dn)\
  O(tailcallstubr, Inone, U(target) U(args), Dn)\
  O(stubunwind, Inone, Un, D(d))\
  O(stubtophp, Inone, Un, Dn)\
  O(loadstubret, Inone, Un, D(d))\
  \
  O(defvmsp, Inone, Un, D(d))\
  O(defvmfp, Inone, Un, D(d))\
  O(pushvmfp, Inone, U(s), Dn)\
  O(popvmfp, Inone, U(s), Dn)\
  O(syncvmsp, Inone, U(s), Dn)\
  O(defvmretdata, Inone, Un, D(data))\
  O(defvmrettype, Inone, Un, D(type))\
  O(syncvmret, Inone, U(data) U(type), Dn)\
  O(syncvmrettype, Inone, U(type), Dn)\
  O(phplogue, Inone, U(fp), Dn)\
  O(phpret, Inone, U(fp) U(args), Dn)\
  O(callphp, I(target), U(args), Dn)\
  O(callphpr, Inone, U(target) U(args), Dn)\
  O(callphps, I(target), U(args), Dn)\
  O(contenter, Inone, U(fp) U(target) U(args), Dn)\
  \
  O(resumetc, Inone, U(target) U(args), Dn)\
  O(inittc, Inone, Un, Dn)\
  O(leavetc, Inone, U(args), Dn)\
  \
  O(landingpad, Inone, Un, Dn)\
  O(nothrow, Inone, Un, Dn)\
  O(syncpoint, I(fix), Un, Dn)\
  O(unwind, Inone, Un, Dn)\
  \
  O(nop, Inone, Un, Dn)\
  O(trap, I(reason), Un, Dn)\
  \
  O(vregrestrict, Inone, Un, Dn)\
  O(vregunrestrict, Inone, Un, Dn)\
  \
  O(addwm, I(fl), U(s0) UM(m), D(sf)) \
  O(addl, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))    \
  O(addli, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(addlm, I(fl), U(s0) UM(m), D(sf)) \
  O(addlim, I(s0) I(fl), UM(m), D(sf)) \
  O(addq, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))     \
  O(addqmr, I(fl), UA(m) UH(s1,d), DH(d,s1) D(sf))  \
  O(addqrm, I(fl), U(s1) UM(m), D(sf)) \
  O(addqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(addqim, I(s0) I(fl), UM(m), D(sf)) \
  O(addsd, Inone, U(s0) U(s1), D(d))\
  O(andb, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))    \
  O(andbi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(andbim, I(s) I(fl), UM(m), D(sf)) \
  O(andw, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))     \
  O(andwi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(andl, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))     \
  O(andli, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(andq, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))     \
  O(andqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(andqi64, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(decl, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(declm, I(fl), UM(m), D(sf))\
  O(decq, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(decqm, I(fl), UM(m), D(sf))\
  O(decqmlock, I(fl), UM(m), D(sf))\
  O(incw, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(incwm, I(fl), UM(m), D(sf))\
  O(incl, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(inclm, I(fl), UM(m), D(sf))\
  O(incq, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(incqm, I(fl), UM(m), D(sf))\
  O(imul, I(fl), U(s0) U(s1), D(d) D(sf))\
  O(divint, Inone, U(s0) U(s1), D(d))\
  O(srem, Inone, U(s0) U(s1), D(d))\
  O(neg, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(notb, Inone, UH(s,d), DH(d,s))\
  O(not, Inone, UH(s,d), DH(d,s))\
  O(orbi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(orbim, I(s0) I(fl), UM(m), D(sf))\
  O(orwim, I(s0) I(fl), UM(m), D(sf))\
  O(orwi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(orli, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(orlim, I(s0) I(fl), UM(m), D(sf))\
  O(orq, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))    \
  O(orqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf)) \
  O(orqim, I(s0) I(fl), UM(m), D(sf))\
  O(sar, I(fl), U(s0) U(s1), D(d) D(sf))\
  O(shl, I(fl), U(s0) U(s1), D(d) D(sf))\
  O(shr, I(fl), U(s0) U(s1), D(d) D(sf))\
  O(sarqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(shlli, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(shlqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(shrli, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(shrqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(subl, I(fl), UA(s0) UH(s1,d), DH(d,s1) D(sf))         \
  O(subli, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(subq, I(fl), UA(s0) UH(s1,d), DH(d,s1) D(sf))         \
  O(subqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(subsd, Inone, UA(s0) U(s1), D(d))\
  O(xorb, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))          \
  O(xorbi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(xorw, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))          \
  O(xorwi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  O(xorl, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))   \
  O(xorq, I(fl), U(s0) UH(s1,d), DH(d,s1) D(sf))     \
  O(xorqi, I(s0) I(fl), UH(s1,d), DH(d,s1) D(sf))\
  \
  O(cmpb, I(fl), U(s0) U(s1), D(sf))\
  O(cmpbi, I(s0) I(fl), U(s1), D(sf))\
  O(cmpbim, I(s0) I(fl), U(s1), D(sf))\
  O(cmpbm, I(fl), U(s0) U(s1), D(sf))\
  O(cmpw, I(fl), U(s0) U(s1), D(sf))\
  O(cmpwi, I(s0) I(fl), U(s1), D(sf))\
  O(cmpwim, I(s0) I(fl), U(s1), D(sf))\
  O(cmpwm, I(fl), U(s0) U(s1), D(sf))\
  O(cmpl, I(fl), U(s0) U(s1), D(sf))\
  O(cmpli, I(s0) I(fl), U(s1), D(sf))\
  O(cmplm, I(fl), U(s0) U(s1), D(sf))\
  O(cmplim, I(s0) I(fl), U(s1), D(sf))\
  O(cmpq, I(fl), U(s0) U(s1), D(sf))\
  O(cmpqi, I(s0) I(fl), U(s1), D(sf))\
  O(cmpqm, I(fl), U(s0) U(s1), D(sf))\
  O(cmpqim, I(s0) I(fl), U(s1), D(sf))\
  O(cmpsd, I(pred), UA(s0) U(s1), D(d))\
  O(ucomisd, I(fl), U(s0) U(s1), D(sf))\
  O(testb, I(fl), U(s0) U(s1), D(sf))\
  O(testbi, I(s0) I(fl), U(s1), D(sf))\
  O(testbim, I(s0) I(fl), U(s1), D(sf))\
  O(testbm, I(fl), U(s0) U(s1), D(sf))  \
  O(testw, I(fl), U(s0) U(s1), D(sf))\
  O(testwi, I(s0) I(fl), U(s1), D(sf))\
  O(testwim, I(s0) I(fl), U(s1), D(sf))\
  O(testwm, I(fl), U(s0) U(s1), D(sf))  \
  O(testl, I(fl), U(s0) U(s1), D(sf))\
  O(testli, I(s0) I(fl), U(s1), D(sf))\
  O(testlim, I(s0) I(fl), U(s1), D(sf))\
  O(testlm, I(fl), U(s0) U(s1), D(sf))  \
  O(testq, I(fl), U(s0) U(s1), D(sf))\
  O(testqi, I(s0) I(fl), U(s1), D(sf))\
  O(testqm, I(fl), U(s0) U(s1), D(sf))\
  O(testqim, I(s0) I(fl), U(s1), D(sf))\
  \
  O(cloadq, I(cc), U(sf) U(f) U(t), D(d))\
  O(cmovb, I(cc), U(sf) UH(f,d) U(t), DH(d,f))\
  O(cmovw, I(cc), U(sf) UH(f,d) U(t), DH(d,f))\
  O(cmovl, I(cc), U(sf) UH(f,d) U(t), DH(d,f))\
  O(cmovq, I(cc), U(sf) UH(f,d) U(t), DH(d,f))\
  O(setcc, I(cc), U(sf), D(d))\
  \
  O(lea, Inone, U(s), D(d))\
  O(leap, I(s), Un, D(d))\
  O(leav, I(s), Un, D(d))\
  O(lead, I(s), Un, D(d))\
  \
  O(movb, Inone, UH(s,d), DH(d,s))\
  O(movw, Inone, UH(s,d), DH(d,s))\
  O(movl, Inone, UH(s,d), DH(d,s))\
  O(movzbw, Inone, UH(s,d), DH(d,s))\
  O(movzbl, Inone, UH(s,d), DH(d,s))\
  O(movzbq, Inone, UH(s,d), DH(d,s))\
  O(movzwl, Inone, UH(s,d), DH(d,s))\
  O(movzwq, Inone, UH(s,d), DH(d,s))\
  O(movzlq, Inone, UH(s,d), DH(d,s))\
  O(movtdb, Inone, UH(s,d), DH(d,s))\
  O(movtdq, Inone, UH(s,d), DH(d,s))\
  O(movtqb, Inone, UH(s,d), DH(d,s))\
  O(movtqw, Inone, UH(s,d), DH(d,s))\
  O(movtql, Inone, UH(s,d), DH(d,s))\
  O(movsbl, Inone, UH(s,d), DH(d,s))\
  O(movswl, Inone, UH(s,d), DH(d,s))\
  O(movsbq, Inone, UH(s,d), DH(d,s))\
  O(movswq, Inone, UH(s,d), DH(d,s))\
  O(movslq, Inone, UH(s,d), DH(d,s))\
  \
  O(loadb, Inone, U(s), D(d))\
  O(loadw, Inone, U(s), D(d))\
  O(loadl, Inone, U(s), D(d))\
  O(loadqp, I(s), Un, D(d))\
  O(loadqd, I(s), Un, D(d))\
  O(loadups, Inone, U(s), D(d))\
  O(loadsd, Inone, U(s), D(d))\
  O(loadzbl, Inone, U(s), D(d))\
  O(loadzbq, Inone, U(s), D(d))\
  O(loadsbl, Inone, U(s), D(d))\
  O(loadsbq, Inone, U(s), D(d))\
  O(loadzwq, Inone, U(s), D(d))\
  O(loadzlq, Inone, U(s), D(d))\
  O(loadtqb, Inone, U(s), D(d))\
  O(loadtql, Inone, U(s), D(d))\
  O(storeb, Inone, U(s) UW(m), Dn)\
  O(storebi, I(s), UW(m), Dn)\
  O(storew, Inone, U(s) UW(m), Dn)\
  O(storewi, I(s), UW(m), Dn)\
  O(storel, Inone, U(s) UW(m), Dn)\
  O(storeli, I(s), UW(m), Dn)\
  O(storeqi, I(s), UW(m), Dn)\
  O(storeups, Inone, U(s) UW(m), Dn)\
  O(storesd, Inone, U(s) UW(m), Dn)\
  \
  O(jcc, I(cc), U(sf), Dn)\
  O(jcci, I(cc), U(sf), Dn)\
  O(jmp, Inone, Un, Dn)\
  O(jmps, I(jmp_addr) I(taken_addr), Un, Dn)\
  O(jmpr, Inone, U(target) U(args), Dn)\
  O(jmpm, Inone, U(target) U(args), Dn)\
  O(jmpi, I(target), U(args), Dn)\
  \
  O(pop, Inone, Un, D(d))\
  O(popf, Inone, Un, D(d))\
  O(popm, Inone, UW(d), Dn)\
  O(popp, Inone, Un, D(d0) D(d1))\
  O(poppm, Inone, UW(d0) UW(d1), Dn)\
  O(push, Inone, U(s), Dn)\
  O(pushf, Inone, U(s), Dn)\
  O(pushm, Inone, U(s), Dn)\
  O(pushp, Inone, U(s0) U(s1), Dn)\
  O(pushpm, Inone, U(s0) U(s1), Dn)\
  \
  O(cvttsd2siq, Inone, U(s), D(d))\
  O(cvtsi2sd, Inone, U(s), D(d))\
  O(cvtsi2sdm, Inone, U(s), D(d))\
  O(unpcklpd, Inone, UA(s0) U(s1), D(d))\
  \
  O(absdbl, Inone, UH(s,d), DH(d,s))\
  O(divsd, Inone, UA(s0) UH(s1,d), DH(d,s1))      \
  O(mulsd, Inone, U(s0) UH(s1,d), DH(d,s1))        \
  O(roundsd, I(dir), U(s), D(d))\
  O(sqrtsd, Inone, U(s), D(d))\
  \
  O(cqo, Inone, Un, Dn)\
  O(idiv, I(fl), U(s), D(sf))\
  O(sarq, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(shlq, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(shrq, I(fl), UH(s,d), DH(d,s) D(sf))\
  O(crc32q, Inone, UA(s0) UH(s1,d), DH(d,s1))\
  \
  O(csincb, I(cc), U(sf) U(f) U(t), D(d))\
  O(csincw, I(cc), U(sf) U(f) U(t), D(d))\
  O(csincl, I(cc), U(sf) U(f) U(t), D(d))\
  O(csincq, I(cc), U(sf) U(f) U(t), D(d))\
  O(fcvtzs, Inone, U(s), D(d))\
  O(mrs, I(s), Un, D(r))\
  O(msr, I(s), U(r), Dn)\
  O(ubfmli, I(mr) I(ms), U(s), D(d))\
  \
  O(fcmpo, Inone, U(s0) U(s1), D(sf))\
  O(fcmpu, Inone, U(s0) U(s1), D(sf))\
  O(fctidz, Inone, U(s), D(d) D(sf))\
  O(mflr, Inone, Un, D(d))\
  O(mtlr, Inone, U(s), Dn)\
  
#define CPP_TYPES                \
  T(ActRec*, TFramePtr)          \
  T(AsioBlockableChain, TABC)    \
  T(Class*, TCls)                \
  T(Func*, TFunc)                \
  T(RFuncData*, TRFunc)          \
  T(ClsMethDataRef, TClsMeth)    \
  T(RClsMethData*, TRClsMeth)    \
  T(NamedEntity*, TNamedEntity)  \
  T(ResourceHdr*, TRes)          \
  T(StringData*, TStr)           \
  T(TCA, TTCA)                   \
  T(TypedValue&, TPtrToCell)     \
  T(TypedValue*, TPtrToCell)     \
  T(TypedValue, TCell)           \
  T(bool, TBool)                 \
  T(double, TDbl)                \
  T(int, TInt)                   \
  T(long, TInt)                  \
  T(long long, TInt)             \
  T(unsigned long, TInt)         \
  T(unsigned long long, TInt)    \
  T(unsigned int, U(Int, RDSHandle)) \
  T(tv_lval, TLvalToCell)        \
  T(tv_rval, TLvalToCell)
#define T(native_t, jit_t)                         \
  template<> struct jit_cpp_type<native_t> {       \
    static auto constexpr type() { return jit_t; } \
  };
#define U(t1, t2) Type(Type::k##t1 | Type::k##t2, Ptr::NotPtr, Mem::NotMem)
#define COUNTED_INIT_UNION \
  kCountedStr|kCountedArr|kCountedVec|kCountedDict|kCountedKeyset|kObj|kRes| \
  kRecord|kRFunc|kRClsMeth
#define INIT_CELL_UNION kUncountedInit|kStr|kArrLike|kObj|kRes|kRecord| \
                        kRFunc|kRClsMeth
#define IRT(name, bits)       static constexpr bits_t k##name = (bits);
#define IRTL(name, ptr, bits)
#define IRTL_FROM_PTR(ptr, ptr_bits, name)                    \
  IRTL(LvalTo##ptr##name, ptr, k##name)
#define IRTM(name, ptr, bits)
#define IRTM_FROM_PTR(ptr, ptr_bits, name)                    \
  IRTM(MemTo##ptr##name, ptr, k##name)
#define IRTP(name, ptr, bits)
#define IRTP_FROM_PTR(ptr, ptr_bits, name)                    \
  IRTP(PtrTo##ptr##name, ptr, k##name)
#define IRTX(name, ptr, bits)
#define IRT_PHP(c)                                                      \
  c(Uninit,          bits_t::bit<0>())                                  \
  c(InitNull,        bits_t::bit<1>())                                  \
  c(Bool,            bits_t::bit<2>())                                  \
  c(Int,             bits_t::bit<3>())                                  \
  c(Dbl,             bits_t::bit<4>())                                  \
  c(StaticStr,       bits_t::bit<5>())                                  \
  c(UncountedStr,    bits_t::bit<6>())                                  \
  c(CountedStr,      bits_t::bit<7>())                                  \
  c(StaticVec,       bits_t::bit<8>())                                  \
  c(UncountedVec,    bits_t::bit<9>())                                  \
  c(CountedVec,      bits_t::bit<10>())                                 \
  c(StaticDict,      bits_t::bit<11>())                                 \
  c(UncountedDict,   bits_t::bit<12>())                                 \
  c(CountedDict,     bits_t::bit<13>())                                 \
  c(StaticKeyset,    bits_t::bit<14>())                                 \
  c(UncountedKeyset, bits_t::bit<15>())                                 \
  c(CountedKeyset,   bits_t::bit<16>())                                 \
  c(Obj,             bits_t::bit<17>())                                 \
  c(Res,             bits_t::bit<18>())                                 \
  c(Func,            bits_t::bit<19>())                                 \
  c(Cls,             bits_t::bit<20>())                                 \
  c(ClsMeth,         bits_t::bit<21>())                                 \
  c(Record,          bits_t::bit<22>())                                 \
  c(RecDesc,         bits_t::bit<23>())                                 \
  c(RFunc,           bits_t::bit<24>())                                 \
  c(StaticVArr,      bits_t::bit<25>())                                 \
  c(UncountedVArr,   bits_t::bit<26>())                                 \
  c(CountedVArr,     bits_t::bit<27>())                                 \
  c(StaticDArr,      bits_t::bit<28>())                                 \
  c(UncountedDArr,   bits_t::bit<29>())                                 \
  c(CountedDArr,     bits_t::bit<30>())                                 \
  c(RClsMeth,        bits_t::bit<31>())                                 \
  c(LazyCls,         bits_t::bit<32>())                                 \

#define IRT_PHP_UNIONS(c)                                               \
  c(Null,                kUninit|kInitNull)                             \
  c(PersistentStr,       kStaticStr|kUncountedStr)                      \
  c(Str,                 kPersistentStr|kCountedStr)                    \
  c(PersistentVArr,      kStaticVArr|kUncountedVArr)                    \
  c(VArr,                kPersistentVArr|kCountedVArr)                  \
  c(PersistentDArr,      kStaticDArr|kUncountedDArr)                    \
  c(DArr,                kPersistentDArr|kCountedDArr)                  \
  c(StaticArr,           kStaticVArr|kStaticDArr)                       \
  c(UncountedArr,        kUncountedVArr|kUncountedDArr)                 \
  c(CountedArr,          kCountedVArr|kCountedDArr)                     \
  c(PersistentArr,       kStaticArr|kUncountedArr)                      \
  c(Arr,                 kPersistentArr|kCountedArr)                    \
  c(PersistentVec,       kStaticVec|kUncountedVec)                      \
  c(Vec,                 kPersistentVec|kCountedVec)                    \
  c(PersistentDict,      kStaticDict|kUncountedDict)                    \
  c(Dict,                kPersistentDict|kCountedDict)                  \
  c(PersistentKeyset,    kStaticKeyset|kUncountedKeyset)                \
  c(Keyset,              kPersistentKeyset|kCountedKeyset)              \
  c(PersistentArrLike,   kPersistentArr|kPersistentVec|kPersistentDict|kPersistentKeyset) \
  c(ArrLike,             kArr|kVec|kDict|kKeyset)                       \
  c(NullableObj,         kObj|kInitNull|kUninit)                        \
  c(Persistent,          kPersistentStr|kPersistentArrLike)             \
  c(UncountedInit,       UNCCOUNTED_INIT_UNION)                         \
  c(Uncounted,           kUninit|kUncountedInit)                        \
  c(InitCell,            INIT_CELL_UNION)                               \
  c(Cell,                kUninit|kInitCell)                             \
  c(FuncLike,            kFunc|kRFunc)                                  \
  c(ClsMethLike,         kClsMeth|kRClsMeth)
#define IRT_PRIMITIVE IRT_PHP(IRT_PTRS_LVALS) IRT_RUNTIME
#define IRT_PTRS_LVALS(name, bits)                            \
  IRT(name,               (bits))                             \
  IRTP(PtrTo##name,       Ptr, k##name)                       \
  PTR_TYPES(IRTP_FROM_PTR, name)                              \
  IRTL(LvalTo##name,      Ptr, k##name)                       \
  PTR_TYPES(IRTL_FROM_PTR, name)                              \
  IRTM(MemTo##name,       Ptr, k##name)                       \
  PTR_TYPES(IRTM_FROM_PTR, name)                              \

#define IRT_RUNTIME                                                     \
  IRT(NamedEntity, bits_t::bit<kRuntime>())                             \
  IRT(RetAddr,     bits_t::bit<kRuntime+1>())       \
  IRT(StkPtr,      bits_t::bit<kRuntime+2>())        \
  IRT(FramePtr,    bits_t::bit<kRuntime+3>())        \
  IRT(TCA,         bits_t::bit<kRuntime+4>())                           \
  IRT(ABC,         bits_t::bit<kRuntime+5>())   \
  IRT(RDSHandle,   bits_t::bit<kRuntime+6>())          \
  IRT(Nullptr,     bits_t::bit<kRuntime+7>())                           \
  IRT(Smashable,   bits_t::bit<kRuntime+8>())   \
  
#define IRT_SPECIAL                                           \
    \
  IRTX(Bottom,         Bottom, kBottom)                       \
  IRTX(Top,            Top,    kTop)                          \
  IRT(Counted,                 COUNTED_INIT_UNION)            \
  IRTP(PtrToCounted,   Ptr,    kCounted)                      \
  IRTL(LvalToCounted,  Ptr,    kCounted)                      \
  IRTM(MemToCounted,   Ptr,    kCounted)                      \

#define IR_TYPES                  \
  IRT_PHP(IRT_PTRS_LVALS)         \
  IRT_PHP_UNIONS(IRT_PTRS_LVALS)  \
  IRT_RUNTIME                     \
  IRT_SPECIAL
#define PTRT(name, bits, ...) name = (bits),
#define PTR_PRIMITIVE(f,...)                             \
  f(ClsInit,  1U << 0, __VA_ARGS__)                      \
  f(ClsCns,   1U << 1, __VA_ARGS__)                      \
  f(Frame, 1U << 2, __VA_ARGS__)                         \
  f(Stk,   1U << 3, __VA_ARGS__)                         \
  f(Gbl,   1U << 4, __VA_ARGS__)                         \
  f(Prop,  1U << 5, __VA_ARGS__)                         \
  f(Elem,  1U << 6, __VA_ARGS__)                         \
  f(SProp, 1U << 7, __VA_ARGS__)                         \
  f(MIS,   1U << 8, __VA_ARGS__)                         \
  f(MMisc, 1U << 9, __VA_ARGS__)                         \
  f(Other, 1U << 10, __VA_ARGS__)                        \
  f(Field, 1U << 11, __VA_ARGS__)                        \
  
#define PTR_TYPES(f, ...)                                \
  PTR_PRIMITIVE(f, __VA_ARGS__)                          \
  f(Memb, Prop | Elem | MIS | MMisc | Other | Field, __VA_ARGS__)
#define UNCCOUNTED_INIT_UNION \
        kInitNull|kBool|kInt|kDbl|kPersistent|kFunc|kCls|kRecDesc|kLazyCls| \
        kClsMeth

#define IMPLEMENT_CNS_VAL(TypeName, name, valtype)      \
  inline valtype Type::name##Val() const {              \
    assertx(hasConstVal(TypeName));                      \
    return m_##name##Val;                               \
  }

#define EMIT_TEMPLATE(b, T) EMIT_TEMPLATE_##b(T)

#define EMIT_TEMPLATE_true(T) template<typename T>
#define IMPLEMENT_SPEC_OPERS(Spec, is_template, ...)      \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline uintptr_t Spec::bits() const {                   \
    return m_bits;                                        \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  constexpr Spec Spec::Top() {                            \
    return Spec{};                                        \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  constexpr Spec Spec::Bottom() {                         \
    return Spec{BottomTag{}};                             \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline Spec::operator bool() const {                    \
    return *this != Top() && *this != Bottom();           \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline bool Spec::operator==(const Spec& rhs) const {   \
    return m_bits == rhs.m_bits;                          \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline bool Spec::operator!=(const Spec& rhs) const {   \
    return !(*this == rhs);                               \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline bool Spec::operator>=(const Spec& rhs) const {   \
    return rhs <= *this;                                  \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline bool Spec::operator<(const Spec& rhs) const {    \
    return *this <= rhs && *this != rhs;                  \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline bool Spec::operator>(const Spec& rhs) const {    \
    return *this >= rhs && *this != rhs;                  \
  }                                                       \
  EMIT_TEMPLATE(is_template, __VA_ARGS__)                 \
  inline Spec Spec::operator-(const Spec& rhs) const {    \
    return *this <= rhs ? Bottom() : *this;               \
  }


#define ASSERT_REASON AssertReason{Reason{"__FILE__", "__LINE__"
#define RBTYPE(x) RBType ## x,
#define RBTYPES \
  RBTYPE(Uninit) \
  RBTYPE(Msg) \
  RBTYPE(SideExit) \
  RBTYPE(EnterTC) \
  RBTYPE(ResumeTC) \
  RBTYPE(TraceletBody) \
  RBTYPE(TraceletGuards) \
  RBTYPE(FuncEntry) \
  RBTYPE(FuncExit) \
  RBTYPE(FuncPrologue) \
  RBTYPE(BytecodeStart) \
  RBTYPE(ServiceReq) \
  RBTYPE(DispatchBB) \
  RBTYPE(InterpOne) \
  RBTYPE(Generic)
#define COLLECTIONS_ALL_TYPES(MACRO) \
  MACRO(Pair) \
  COLLECTIONS_PAIRED_TYPES(MACRO)
#define COLLECTIONS_PAIRED_TYPES(MACRO) \
  MACRO(Vector) MACRO(ImmVector) \
  MACRO(Map)    MACRO(ImmMap) \
  MACRO(Set)    MACRO(ImmSet)
#define ARRAY_OPS \
  X(Scan,               true)  \
  X(EscalateToVanilla,  true)  \
  X(ConvertToUncounted, true)  \
  X(ReleaseUncounted,   true)  \
  X(Release,            true)  \
  X(IsVectorData,       true)  \
  X(GetInt,             true)  \
  X(GetStr,             true)  \
  X(GetIntPos,          true)  \
  X(GetStrPos,          true)  \
  X(LvalInt,            false) \
  X(LvalStr,            false) \
  X(ElemInt,            false) \
  X(ElemStr,            false) \
  X(SetInt,             false) \
  X(SetStr,             false) \
  X(ConstructInt,       false) \
  X(ConstructStr,       false) \
  X(RemoveInt,          false) \
  X(RemoveStr,          false) \
  X(IterBegin,          true)  \
  X(IterLast,           true)  \
  X(IterEnd,            true)  \
  X(IterAdvance,        true)  \
  X(IterRewind,         true)  \
  X(Append,             false) \
  X(Pop,                false) \
  X(ToDVArray,          true)  \
  X(ToHackArr,          true)  \
  X(PreSort,            true)  \
  X(PostSort,           true)  \
  X(SetLegacyArray,     true)



#define punt() do { \
  throw TranslationFailedExc("__FILE__", "__LINE__"); \
} while(0)
#define throwUnknownInput() do { \
  throw UnknownInputExc("__FILE__", "__LINE__"); \
} while(0);

#define DEBUGGER_ATTACHED_ONLY(code) do {                             \
  if (isDebuggerAttached()) {                                         \
    code;                                                             \
  }                                                                   \
} while(0)                                                            \

#define DEBUGGER_FORCE_INTR (RID().getDebuggerForceIntr())

#define NUM_BUF_SIZE 500

#define string_to_upper(s)        \
  string_to_case((s), [] (int i) -> int { return toupper(i); })


#define U_USING_ICU_NAMESPACE 0



#define LIBDWARF_CALLBACK_NAME_TYPE const char*

#define DW_CFA_def_cfa 0
#define DW_CFA_offset 0
#define DW_CFA_offset_extended_sf 0
#define DW_CFA_same_value 0
#define DW_CFA_set_loc 0
#define DW_EH_PE_absptr 0


    #define QS(STYLE, VAL)  \
      if (is_set(flags, QuoteStyle::STYLE)) { return QuoteStyle::STYLE; }
  #define QUOTE_STYLES    \
      \
    QS(FBUtf8Only, 65536) \
    QS(FBUtf8, 32768)     \
      \
    QS(Xhtml, 32)  \
    QS(Xml1, 16)   \
    QS(Substitute, 8)  \
    QS(Ignore, 4)  \
    QS(Both, 3)     \
    QS(Double, 2)    \
    QS(No, 0)       \

#define DECLARE_COLLECTIONS_CLASS(name)                     \
  DECLARE_COLLECTIONS_CLASS_NOCTOR(name)                    \
  static ObjectData* instanceCtor(Class* cls) {             \
    assertx(cls == classof());                              \
    return req::make<c_##name>().detach();                  \
  }
#define DECLARE_COLLECTIONS_CLASS_NOCTOR(name)              \
  static Class* s_cls;                                      \
                                                            \
  static Class* classof() {                                 \
    assertx(s_cls);                                         \
    return s_cls;                                           \
  }                                                         \
                                                            \
  static void instanceDtor(ObjectData* obj, const Class*) { \
    assertx(obj->getVMClass() == c_##name::classof());      \
    auto coll = static_cast<c_##name*>(obj);                \
    coll->~c_##name();                                      \
    tl_heap->objFree(obj, sizeof(c_##name));                \
  }
#define CHECK_ACCESSOR(accesor, opstr, classname, propname)                    \
  if (!accesor) {                                                              \
    raise_error("Cannot directly %s the property %s::$%s",                     \
                 opstr, classname->data(), propname.data());                   \
  }
#define CHECK_NATIVE_PROP_SUPPORTED(name, op)                                  \
  if (!T::isPropSupported(name, op)) {                                         \
    return Native::prop_not_handled();                                         \
  }

#define SIZE_CLASS(index, lg_grp, lg_delta, ndelta, lg_delta_lookup, ncontig) \
  sizeClassParams2PackedArrayCapacity(index, lg_grp, lg_delta, ndelta),
#define IMPL_ADD(KeyType)                                           \
  MixedPHPArrayInitBase& add(KeyType name, const Variant& v,        \
                             bool keyConverted = false) {           \
    return add(name, *v.asTypedValue(), keyConverted);              \
  }
#define IMPL_SET(KeyType)                           \
  MixedPHPArrayInitBase& set(KeyType name, const Variant& v) {  \
    return set(name, *v.asTypedValue());            \
  }
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
