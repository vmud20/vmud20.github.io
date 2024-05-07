













#include<string>


#include<string.h>



#include<assert.h>







#include<complex>
#include<iosfwd>

#include<any>








#include<stdio.h>




#include<string_view>








#include<limits>

#include<condition_variable>










#include<mutex>


#include<ostream>
#include<functional>






#include<unordered_map>
#include<random>









#include<iostream>






#include<numeric>














#include<cstring>



#include<unordered_set>














#include<stdlib.h>












#include<typeinfo>









#include<optional>



#include<stddef.h>


#include<vector>









#include<chrono>


#include<iterator>
#include<typeindex>






#include<initializer_list>
#include<atomic>

#include<stack>
























#include<unistd.h>





#include<cstdint>

#include<new>




#include<algorithm>




#include<limits.h>









#include<map>

#include<sys/time.h>
#include<cmath>


#include<type_traits>












#include<set>
#include<tuple>



#include<execinfo.h>

#include<sstream>




#include<stdint.h>
#include<array>


#include<list>




#include<cstddef>

#include<dlfcn.h>
















#include<utility>






#include<memory>














#include<deque>




#include<variant>




























#define TF_TSTRING_LITTLE_ENDIAN 1
#define TF_le32toh(x) x


#define TF_CORD_SUPPORT 1

























#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#define __ORDER_BIG_ENDIAN__ 0x10e1
#define __ORDER_LITTLE_ENDIAN__ 0x4d2




#define TF_ANNOTATE_BENIGN_RACE(ptr, description) \
  do {                                            \
  } while (0)
#define TF_ANNOTATE_MEMORY_IS_INITIALIZED(ptr, bytes) \
  do {                                                \
  } while (0)




#define LANG_CXX11 1

#define TF_ARRAYSIZE(a)         \
  ((sizeof(a) / sizeof(*(a))) / \
   static_cast<size_t>(!(sizeof(a) % sizeof(*(a)))))
#define TF_ATTRIBUTE_ALWAYS_INLINE __attribute__((always_inline))
#define TF_ATTRIBUTE_ANNOTATE(str) [[clang::annotate(str)]]
#define TF_ATTRIBUTE_COLD __attribute__((cold))
#define TF_ATTRIBUTE_NOINLINE __attribute__((noinline))
#define TF_ATTRIBUTE_NORETURN __attribute__((noreturn))
#define TF_ATTRIBUTE_UNUSED __attribute__((unused))
#define TF_ATTRIBUTE_WEAK __attribute__((weak))
#define TF_CONST_INIT [[clang::require_constant_initialization]]
#define TF_DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete;         \
  void operator=(const TypeName&) = delete
#define TF_EXPORT __declspec(dllexport)
#define TF_FALLTHROUGH_INTENDED [[clang::fallthrough]]  
#define TF_HAS_BUILTIN(x) __has_builtin(x)
#define TF_HAS_CPP_ATTRIBUTE(n) __has_cpp_attribute(n)
#define TF_MUST_USE_RESULT __attribute__((warn_unused_result))
#define TF_PACKED __attribute__((packed))
#define TF_PREDICT_FALSE(x) (__builtin_expect(x, 0))
#define TF_PREDICT_TRUE(x) (__builtin_expect(!!(x), 1))
#define TF_PRINTF_ATTRIBUTE(string_index, first_to_check) \
  __attribute__((__format__(__printf__, string_index, first_to_check)))
#define TF_SCANF_ATTRIBUTE(string_index, first_to_check) \
  __attribute__((__format__(__scanf__, string_index, first_to_check)))
#define TF_UNUSED_VARIABLE(x) \
  tensorflow::internal::remove_unused_variable_compiler_warning(x)





#define TF_CHECK_OK(val) TF_DO_CHECK_OK(val, FATAL)
#define TF_DCHECK_OK(val) TF_CHECK_OK(val)
#define TF_DO_CHECK_OK(val, level)                          \
  while (auto* _result = ::tsl::TfCheckOpHelper(val, #val)) \
  LOG(level) << *(_result)
#define TF_QCHECK_OK(val) TF_DO_CHECK_OK(val, QFATAL)

#define TF_INTERNAL_HAVE_BUILTIN_LINE_FILE 1


#define CHECK(condition)              \
  if (TF_PREDICT_FALSE(!(condition))) \
  LOG(FATAL) << "Check failed: " #condition " "
#define CHECK_EQ(val1, val2) CHECK_OP(Check_EQ, ==, val1, val2)
#define CHECK_GE(val1, val2) CHECK_OP(Check_GE, >=, val1, val2)
#define CHECK_GT(val1, val2) CHECK_OP(Check_GT, >, val1, val2)
#define CHECK_LE(val1, val2) CHECK_OP(Check_LE, <=, val1, val2)
#define CHECK_LT(val1, val2) CHECK_OP(Check_LT, <, val1, val2)
#define CHECK_NE(val1, val2) CHECK_OP(Check_NE, !=, val1, val2)
#define CHECK_NOTNULL(val)                          \
  ::tsl::internal::CheckNotNull("__FILE__", "__LINE__", \
                                "'" #val "' Must be non NULL", (val))
#define CHECK_OP(name, op, val1, val2) CHECK_OP_LOG(name, op, val1, val2)
#define CHECK_OP_LOG(name, op, val1, val2)                                     \
  while (::tsl::internal::CheckOpString _result{::tsl::internal::name##Impl(   \
      ::tsl::internal::GetReferenceableValue(val1),                            \
      ::tsl::internal::GetReferenceableValue(val2), #val1 " " #op " " #val2)}) \
  ::tsl::internal::LogMessageFatal("__FILE__", "__LINE__") << *(_result.str_)
#define DCHECK(condition) CHECK(condition)
#define DCHECK_EQ(val1, val2) CHECK_EQ(val1, val2)
#define DCHECK_GE(val1, val2) CHECK_GE(val1, val2)
#define DCHECK_GT(val1, val2) CHECK_GT(val1, val2)
#define DCHECK_LE(val1, val2) CHECK_LE(val1, val2)
#define DCHECK_LT(val1, val2) CHECK_LT(val1, val2)
#define DCHECK_NE(val1, val2) CHECK_NE(val1, val2)
#define DVLOG VLOG
#define LOG(severity) _TF_LOG_##severity
#define LOGGING_INTERNAL_STATEFUL_CONDITION(kind, condition, arg)   \
  for (bool logging_internal_stateful_condition_do_log(condition);  \
       logging_internal_stateful_condition_do_log;                  \
       logging_internal_stateful_condition_do_log = false)          \
    for (static ::tsl::internal::Log##kind##State                   \
             logging_internal_stateful_condition_state;             \
         logging_internal_stateful_condition_do_log &&              \
         logging_internal_stateful_condition_state.ShouldLog(arg);  \
         logging_internal_stateful_condition_do_log = false)        \
      for (const uint32_t COUNTER ABSL_ATTRIBUTE_UNUSED =           \
               logging_internal_stateful_condition_state.counter(); \
           logging_internal_stateful_condition_do_log;              \
           logging_internal_stateful_condition_do_log = false)
#define LOG_EVERY_N(severity, n)                       \
  LOGGING_INTERNAL_STATEFUL_CONDITION(EveryN, true, n) \
  LOG(severity)
#define LOG_EVERY_N_SEC(severity, n_seconds)                      \
  LOGGING_INTERNAL_STATEFUL_CONDITION(EveryNSec, true, n_seconds) \
  LOG(severity)
#define LOG_EVERY_POW_2(severity)                         \
  LOGGING_INTERNAL_STATEFUL_CONDITION(EveryPow2, true, 0) \
  LOG(severity)
#define LOG_FIRST_N(severity, n)                       \
  LOGGING_INTERNAL_STATEFUL_CONDITION(FirstN, true, n) \
  LOG(severity)
#define QCHECK(condition) CHECK(condition)
#define QCHECK_EQ(x, y) CHECK_EQ(x, y)
#define QCHECK_GE(x, y) CHECK_GE(x, y)
#define QCHECK_GT(x, y) CHECK_GT(x, y)
#define QCHECK_LE(x, y) CHECK_LE(x, y)
#define QCHECK_LT(x, y) CHECK_LT(x, y)
#define QCHECK_NE(x, y) CHECK_NE(x, y)

#define TF_DEFINE_CHECK_OP_IMPL(name, op)                           \
  template <typename T1, typename T2>                               \
  inline string* name##Impl(const T1& v1, const T2& v2,             \
                            const char* exprtext) {                 \
    if (TF_PREDICT_TRUE(v1 op v2))                                  \
      return NULL;                                                  \
    else                                                            \
      return ::tsl::internal::MakeCheckOpString(v1, v2, exprtext);  \
  }                                                                 \
  inline string* name##Impl(int v1, int v2, const char* exprtext) { \
    return name##Impl<int, int>(v1, v2, exprtext);                  \
  }
#define VLOG(level)                   \
  TF_PREDICT_TRUE(!VLOG_IS_ON(level)) \
  ? (void)0                           \
  : ::tsl::internal::Voidifier() &    \
          ::tsl::internal::LogMessage("__FILE__", "__LINE__", tsl::INFO)
#define VLOG_IS_ON(lvl) ((lvl) <= 0)
#define _TF_DCHECK_NOP(x, y) \
  while (false && ((void)(x), (void)(y), 0)) LOG(FATAL)
#define _TF_LOG_ERROR \
  ::tsl::internal::LogMessage("__FILE__", "__LINE__", ::tsl::ERROR)
#define _TF_LOG_FATAL ::tsl::internal::LogMessageFatal("__FILE__", "__LINE__")
#define _TF_LOG_INFO \
  ::tsl::internal::LogMessage("__FILE__", "__LINE__", ::tsl::INFO)
#define _TF_LOG_QFATAL _TF_LOG_FATAL
#define _TF_LOG_WARNING \
  ::tsl::internal::LogMessage("__FILE__", "__LINE__", ::tsl::WARNING)





#define GUARDED_VAR  

#define TF_ACQUIRE(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(acquire_capability(__VA_ARGS__))
#define TF_ACQUIRED_AFTER(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(acquired_after(__VA_ARGS__))
#define TF_ACQUIRED_BEFORE(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(acquired_before(__VA_ARGS__))
#define TF_ACQUIRE_SHARED(...)             \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE( \
      acquire_shared_capability(__VA_ARGS__))
#define TF_ASSERT_EXCLUSIVE_LOCK(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(assert_exclusive_lock(__VA_ARGS__))
#define TF_ASSERT_SHARED_LOCK(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(assert_shared_lock(__VA_ARGS__))
#define TF_EXCLUSIVE_LOCKS_REQUIRED(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(exclusive_locks_required(__VA_ARGS__))
#define TF_EXCLUSIVE_LOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(exclusive_lock_function(__VA_ARGS__))
#define TF_EXCLUSIVE_TRYLOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE( \
      exclusive_trylock_function(__VA_ARGS__))
#define TF_GUARDED_BY(x) TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(guarded_by(x))
#define TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(x) __attribute__((x))
#define TF_LOCKABLE TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(lockable)
#define TF_LOCKS_EXCLUDED(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(locks_excluded(__VA_ARGS__))
#define TF_LOCK_RETURNED(x) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(lock_returned(x))
#define TF_NO_THREAD_SAFETY_ANALYSIS \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(no_thread_safety_analysis)
#define TF_PT_GUARDED_BY(x) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(pt_guarded_by(x))
#define TF_PT_GUARDED_VAR  
#define TF_RELEASE(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(release_capability(__VA_ARGS__))
#define TF_SCOPED_LOCKABLE \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(scoped_lockable)
#define TF_SHARED_LOCKS_REQUIRED(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(shared_locks_required(__VA_ARGS__))
#define TF_SHARED_LOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(shared_lock_function(__VA_ARGS__))
#define TF_SHARED_TRYLOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(shared_trylock_function(__VA_ARGS__))
#define TF_TS_UNCHECKED(x) ""
#define TF_UNLOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(unlock_function(__VA_ARGS__))

#define mutex_lock(x) static_assert(0, "mutex_lock_decl_missing_var_name");
#define tf_shared_lock(x) \
  static_assert(0, "tf_shared_lock_decl_missing_var_name");




#define MATCH_TYPE_AND_ENUM(TYPE, ENUM)                 \
  template <>                                           \
  struct DataTypeToEnum<TYPE> {                         \
    static DataType v() { return ENUM; }                \
    static DataType ref() { return MakeRefType(ENUM); } \
    static constexpr DataType value = ENUM;             \
  };                                                    \
  template <>                                           \
  struct IsValidDataType<TYPE> {                        \
    static constexpr bool value = true;                 \
  };                                                    \
  template <>                                           \
  struct EnumToDataType<ENUM> {                         \
    typedef TYPE Type;                                  \
  }










#define TF_ASSERT_OK_AND_ASSIGN(lhs, rexpr)                             \
  TF_ASSERT_OK_AND_ASSIGN_IMPL(                                         \
      TF_STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, \
      rexpr);
#define TF_ASSERT_OK_AND_ASSIGN_IMPL(statusor, lhs, rexpr)  \
  auto statusor = (rexpr);                                  \
  ASSERT_TRUE(statusor.status().ok()) << statusor.status(); \
  lhs = std::move(statusor).value()
#define TF_ASSIGN_OR_RETURN(lhs, rexpr) \
  TF_ASSIGN_OR_RETURN_IMPL(             \
      TF_STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, rexpr)
#define TF_ASSIGN_OR_RETURN_IMPL(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                             \
  if (TF_PREDICT_FALSE(!statusor.ok())) {              \
    return statusor.status();                          \
  }                                                    \
  lhs = std::move(statusor).value()
#define TF_STATUS_MACROS_CONCAT_IMPL(x, y) x##y
#define TF_STATUS_MACROS_CONCAT_NAME(x, y) TF_STATUS_MACROS_CONCAT_IMPL(x, y)


#define TF_RETURN_IF_ERROR(...)                          \
  do {                                                   \
    ::tsl::Status _status = (__VA_ARGS__);               \
    if (TF_PREDICT_FALSE(!_status.ok())) return _status; \
  } while (0)
#define TF_RETURN_WITH_CONTEXT_IF_ERROR(expr, ...)           \
  do {                                                       \
    ::tsl::Status _status = (expr);                          \
    if (TF_PREDICT_FALSE(!_status.ok())) {                   \
      ::tsl::errors::AppendToMessage(&_status, __VA_ARGS__); \
      return _status;                                        \
    }                                                        \
  } while (0)






























#define TF_CALL_ALL_TYPES(m) \
  TF_CALL_POD_TYPES(m) TF_CALL_tstring(m) TF_CALL_resource(m) TF_CALL_variant(m)
#define TF_CALL_COMPLEX_TYPES(m) TF_CALL_complex64(m) TF_CALL_complex128(m)
#define TF_CALL_FLOAT_TYPES(m) \
  TF_CALL_half(m) TF_CALL_bfloat16(m) TF_CALL_float(m) TF_CALL_double(m)
#define TF_CALL_GPU_ALL_TYPES(m) \
  TF_CALL_GPU_NUMBER_TYPES(m) TF_CALL_COMPLEX_TYPES(m) TF_CALL_bool(m)
#define TF_CALL_GPU_NUMBER_TYPES(m) \
  TF_CALL_half(m) TF_CALL_bfloat16(m) TF_CALL_float(m) TF_CALL_double(m)
#define TF_CALL_GPU_NUMBER_TYPES_NO_HALF(m) TF_CALL_float(m) TF_CALL_double(m)
#define TF_CALL_INTEGRAL_TYPES(m) \
  TF_CALL_INTEGRAL_TYPES_NO_INT32(m) TF_CALL_int32(m)
#define TF_CALL_INTEGRAL_TYPES_NO_INT32(m)                               \
  TF_CALL_uint64(m) TF_CALL_int64(m) TF_CALL_uint32(m) TF_CALL_uint16(m) \
      TF_CALL_int16(m) TF_CALL_uint8(m) TF_CALL_int8(m)
#define TF_CALL_NUMBER_TYPES(m) \
  TF_CALL_REAL_NUMBER_TYPES(m) TF_CALL_COMPLEX_TYPES(m)
#define TF_CALL_NUMBER_TYPES_NO_INT32(m) \
  TF_CALL_REAL_NUMBER_TYPES_NO_INT32(m) TF_CALL_COMPLEX_TYPES(m)
#define TF_CALL_POD_STRING_TYPES(m) TF_CALL_POD_TYPES(m) TF_CALL_tstring(m)
#define TF_CALL_POD_TYPES(m) TF_CALL_NUMBER_TYPES(m) TF_CALL_bool(m)
#define TF_CALL_QUANTIZED_TYPES(m) \
  TF_CALL_qint8(m) TF_CALL_quint8(m) TF_CALL_qint32(m)
#define TF_CALL_REAL_NUMBER_TYPES(m) \
  TF_CALL_INTEGRAL_TYPES(m) TF_CALL_FLOAT_TYPES(m)
#define TF_CALL_REAL_NUMBER_TYPES_NO_BFLOAT16(m) \
  TF_CALL_INTEGRAL_TYPES(m) TF_CALL_half(m) TF_CALL_float(m) TF_CALL_double(m)
#define TF_CALL_REAL_NUMBER_TYPES_NO_INT32(m)                            \
  TF_CALL_half(m) TF_CALL_bfloat16(m) TF_CALL_float(m) TF_CALL_double(m) \
      TF_CALL_INTEGRAL_TYPES_NO_INT32(m)
#define TF_CALL_SAVE_RESTORE_TYPES(m)      \
  TF_CALL_REAL_NUMBER_TYPES_NO_BFLOAT16(m) \
  TF_CALL_COMPLEX_TYPES(m)                 \
  TF_CALL_QUANTIZED_TYPES(m) TF_CALL_bool(m) TF_CALL_tstring(m)

#define TF_CALL_bool(m) m(bool)



#define TF_CALL_float(m) m(float)


#define TF_CALL_half(m) m(Eigen::half)

#define TF_CALL_int32(m) m(::tensorflow::int32)
#define TF_CALL_int64(m) m(::int64_t)

#define TF_CALL_qint16(m) m(::tensorflow::qint16)
#define TF_CALL_qint32(m) m(::tensorflow::qint32)
#define TF_CALL_qint8(m) m(::tensorflow::qint8)
#define TF_CALL_quint16(m) m(::tensorflow::quint16)
#define TF_CALL_quint8(m) m(::tensorflow::quint8)

#define TF_CALL_string(m) m(::tensorflow::tstring)
#define TF_CALL_tstring(m) m(::tensorflow::tstring)







#define LOG_KERNEL_SOURCES(name) \
  LOG(INFO) << "Kernel found: " << name << " " << "__FILE__" << "\n";
#define REGISTER_KERNEL_BUILDER(kernel_builder, ...) \
  TF_ATTRIBUTE_ANNOTATE("tf:kernel")                 \
  REGISTER_KERNEL_BUILDER_IMPL(kernel_builder, false, __VA_ARGS__)
#define REGISTER_KERNEL_BUILDER_IMPL(kernel_builder, is_system_kernel, ...) \
  TF_EXTRACT_KERNEL_NAME(REGISTER_KERNEL_BUILDER_IMPL_2, kernel_builder,    \
                         is_system_kernel, __VA_ARGS__)
#define REGISTER_KERNEL_BUILDER_IMPL_2(op_name, kernel_builder_expr, \
                                       is_system_kernel, ...)        \
  TF_NEW_ID_FOR_INIT(REGISTER_KERNEL_BUILDER_IMPL_3, op_name,        \
                     kernel_builder_expr, is_system_kernel, __VA_ARGS__)
#define REGISTER_KERNEL_BUILDER_IMPL_3(ctr, op_name, kernel_builder_expr,   \
                                       is_system_kernel, ...)               \
  static ::tensorflow::InitOnStartupMarker const register_kernel_##ctr      \
      TF_ATTRIBUTE_UNUSED =                                                 \
          TF_INIT_ON_STARTUP_IF(is_system_kernel ||                         \
                                (SHOULD_REGISTER_OP_KERNEL(#__VA_ARGS__) && \
                                 SHOULD_REGISTER_OP(op_name)))              \
          << ([](::tensorflow::KernelDef const* kernel_def) {               \
               ::tensorflow::kernel_factory::OpKernelRegistrar registrar(   \
                   kernel_def, #__VA_ARGS__,                                \
                   [](::tensorflow::OpKernelConstruction* context)          \
                       -> ::tensorflow::OpKernel* {                         \
                     return new __VA_ARGS__(context);                       \
                   });                                                      \
               (void)registrar;                                             \
               LOG_KERNEL_SOURCES(op_name)                                  \
               return ::tensorflow::InitOnStartupMarker{};                  \
             })(kernel_builder_expr.Build());
#define REGISTER_SYSTEM_KERNEL_BUILDER(kernel_builder, ...) \
  TF_ATTRIBUTE_ANNOTATE("tf:kernel")                        \
  TF_ATTRIBUTE_ANNOTATE("tf:kernel:system")                 \
  REGISTER_KERNEL_BUILDER_IMPL(kernel_builder, true, __VA_ARGS__)

#define TF_EXTRACT_KERNEL_NAME(m, kernel_builder, ...)                    \
  TF_EXTRACT_KERNEL_NAME_IMPL(m, TF_EXTRACT_KERNEL_NAME_##kernel_builder, \
                              __VA_ARGS__)
#define TF_EXTRACT_KERNEL_NAME_IMPL(m, ...) m(__VA_ARGS__)
#define TF_EXTRACT_KERNEL_NAME_Name(name_str) \
  name_str, ::tensorflow::register_kernel::Name(name_str)





#define REGISTER_FILE_SYSTEM(scheme, factory) \
  REGISTER_FILE_SYSTEM_ENV(::tsl::Env::Default(), scheme, factory, false);
#define REGISTER_FILE_SYSTEM_ENV(env, scheme, factory, modular) \
  REGISTER_FILE_SYSTEM_UNIQ_HELPER(__COUNTER__, env, scheme, factory, modular)
#define REGISTER_FILE_SYSTEM_UNIQ(ctr, env, scheme, factory, modular)    \
  static ::tsl::register_file_system::Register<factory> register_ff##ctr \
      TF_ATTRIBUTE_UNUSED =                                              \
          ::tsl::register_file_system::Register<factory>(env, scheme, modular)
#define REGISTER_FILE_SYSTEM_UNIQ_HELPER(ctr, env, scheme, factory, modular) \
  REGISTER_FILE_SYSTEM_UNIQ(ctr, env, scheme, factory, modular)
#define REGISTER_LEGACY_FILE_SYSTEM(scheme, factory) \
  REGISTER_FILE_SYSTEM_ENV(::tsl::Env::Default(), scheme, factory, true);


#define TF_USE_FILESYSTEM_METHODS_WITH_NO_TRANSACTION_SUPPORT \
  using FileSystem::NewRandomAccessFile;                      \
  using FileSystem::NewWritableFile;                          \
  using FileSystem::NewAppendableFile;                        \
  using FileSystem::NewReadOnlyMemoryRegionFromFile;          \
  using FileSystem::FileExists;                               \
  using FileSystem::GetChildren;                              \
  using FileSystem::GetMatchingPaths;                         \
  using FileSystem::Stat;                                     \
  using FileSystem::DeleteFile;                               \
  using FileSystem::RecursivelyCreateDir;                     \
  using FileSystem::DeleteDir;                                \
  using FileSystem::DeleteRecursively;                        \
  using FileSystem::GetFileSize;                              \
  using FileSystem::RenameFile;                               \
  using FileSystem::CopyFile;                                 \
  using FileSystem::IsDirectory;                              \
  using FileSystem::FlushCaches






#define TF_LIB_GTL_ALIGNED_CHAR_ARRAY(T, Size)                          \
  typename tensorflow::gtl::internal::AlignType<TF_LIB_GTL_ALIGN_OF(T), \
                                                sizeof(T) * Size>::result
#define TF_LIB_GTL_ALIGNTYPE_TEMPLATE(X)                     \
  template <int size>                                        \
  struct AlignType<X, size> {                                \
    typedef TF_LIB_GTL_ALIGN_ATTRIBUTE(X) char result[size]; \
  }
#define TF_LIB_GTL_ALIGN_ATTRIBUTE(X) __declspec(align(X))
#define TF_LIB_GTL_ALIGN_OF(T) __alignof(T)

























#define SHOULD_REGISTER_OP(op) true
#define SHOULD_REGISTER_OP_GRADIENT true
#define SHOULD_REGISTER_OP_KERNEL(clz) true

#define TF_INIT_ON_STARTUP_IF(cond)                \
  (::std::integral_constant<bool, !(cond)>::value) \
      ? ::tensorflow::InitOnStartupMarker{}        \
      : ::tensorflow::InitOnStartupMarker {}
#define TF_NEW_ID_FOR_INIT(m, ...) \
  TF_NEW_ID_FOR_INIT_1(m, __COUNTER__, __VA_ARGS__)
#define TF_NEW_ID_FOR_INIT_1(m, c, ...) TF_NEW_ID_FOR_INIT_2(m, c, __VA_ARGS__)
#define TF_NEW_ID_FOR_INIT_2(m, c, ...) m(c, __VA_ARGS__)
#define OP_REQUIRES(CTX, EXP, STATUS)                     \
  do {                                                    \
    if (!TF_PREDICT_TRUE(EXP)) {                          \
      CheckNotInComputeAsync((CTX), "OP_REQUIRES_ASYNC"); \
      (CTX)->CtxFailure("__FILE__", "__LINE__", (STATUS));    \
      return;                                             \
    }                                                     \
  } while (0)
#define OP_REQUIRES_ASYNC(CTX, EXP, STATUS, CALLBACK)  \
  do {                                                 \
    if (!TF_PREDICT_TRUE(EXP)) {                       \
      (CTX)->CtxFailure("__FILE__", "__LINE__", (STATUS)); \
      (CALLBACK)();                                    \
      return;                                          \
    }                                                  \
  } while (0)
#define OP_REQUIRES_OK(CTX, ...)                             \
  do {                                                       \
    ::tensorflow::Status _s(__VA_ARGS__);                    \
    if (!TF_PREDICT_TRUE(_s.ok())) {                         \
      CheckNotInComputeAsync((CTX), "OP_REQUIRES_OK_ASYNC"); \
      (CTX)->CtxFailureWithWarning("__FILE__", "__LINE__", _s);  \
      return;                                                \
    }                                                        \
  } while (0)
#define OP_REQUIRES_OK_ASYNC(CTX, STATUS, CALLBACK)         \
  do {                                                      \
    const ::tensorflow::Status& _s(STATUS);                 \
    if (!TF_PREDICT_TRUE(_s.ok())) {                        \
      (CTX)->CtxFailureWithWarning("__FILE__", "__LINE__", _s); \
      (CALLBACK)();                                         \
      return;                                               \
    }                                                       \
  } while (0)
#define OP_REQUIRES_OK_OR_SET_PAYLOAD(CTX, PAYLOAD_KEY, PAYLOAD_VALUE, STATUS) \
  do {                                                                         \
    if (!TF_PREDICT_TRUE(STATUS.ok())) {                                       \
      CheckNotInComputeAsync((CTX), "OP_REQUIRES_OK_ASYNC");                   \
      if (!PAYLOAD_VALUE.empty()) {                                            \
        STATUS.SetPayload(PAYLOAD_KEY, absl::Cord(PAYLOAD_VALUE));             \
      }                                                                        \
      (CTX)->CtxFailureWithWarning("__FILE__", "__LINE__", STATUS);                \
      return;                                                                  \
    }                                                                          \
  } while (0)
#define OP_REQUIRES_VALUE(lhs, ctx, rexpr)                                   \
  OP_REQUIRES_VALUE_IMPL(                                                    \
      TF_STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, ctx, \
      rexpr)
#define OP_REQUIRES_VALUE_IMPL(statusor, lhs, ctx, rexpr) \
  auto statusor = (rexpr);                                \
  OP_REQUIRES_OK(ctx, statusor.status());                 \
  lhs = std::move(statusor.value())

#define REGISTER_OP(name)        \
  TF_ATTRIBUTE_ANNOTATE("tf:op") \
  TF_NEW_ID_FOR_INIT(REGISTER_OP_IMPL, name, false)
#define REGISTER_OP_IMPL(ctr, name, is_system_op)                         \
  static ::tensorflow::InitOnStartupMarker const register_op##ctr         \
      TF_ATTRIBUTE_UNUSED =                                               \
          TF_INIT_ON_STARTUP_IF(is_system_op || SHOULD_REGISTER_OP(name)) \
          << ::tensorflow::register_op::OpDefBuilderWrapper(name)
#define REGISTER_SYSTEM_OP(name)        \
  TF_ATTRIBUTE_ANNOTATE("tf:op")        \
  TF_ATTRIBUTE_ANNOTATE("tf:op:system") \
  TF_NEW_ID_FOR_INIT(REGISTER_OP_IMPL, name, true)
















#define XLA_FATAL_LOG(X)          \
  XLA_LOG_LINES(::tsl::ERROR, X); \
  LOG(FATAL) << "Aborting in " << __FUNCTION__ << " due to previous errors.";
#define XLA_LOG_LINES(SEV, STRING) \
  ::xla::LogLines(SEV, STRING, "__FILE__", "__LINE__")
#define XLA_SCOPED_LOGGING_TIMER(label) \
  XLA_SCOPED_LOGGING_TIMER_HELPER(label, 1, __COUNTER__)
#define XLA_SCOPED_LOGGING_TIMER_HELPER(label, level, counter) \
  XLA_SCOPED_LOGGING_TIMER_HELPER2(label, level, counter)
#define XLA_SCOPED_LOGGING_TIMER_HELPER2(label, level, counter)      \
  static ::xla::TimerStats XLA_TimerStats##counter;                  \
  ::xla::ScopedLoggingTimer XLA_ScopedLoggingTimerInstance##counter( \
      label, VLOG_IS_ON(level), "__FILE__", "__LINE__",      \
      &XLA_TimerStats##counter);
#define XLA_SCOPED_LOGGING_TIMER_LEVEL(label, level) \
  XLA_SCOPED_LOGGING_TIMER_HELPER(label, level, __COUNTER__)
#define XLA_VLOG_LINES(LEVEL, STRING)                          \
  do {                                                         \
    if (VLOG_IS_ON(LEVEL)) XLA_LOG_LINES(::tsl::INFO, STRING); \
  } while (false);


#define TF_RET_CHECK(condition)                                      \
  while (ABSL_PREDICT_FALSE(!(condition)))                           \
  return xla::status_macros::MakeErrorStream("__FILE__", "__LINE__",     \
                                             ::tsl::error::INTERNAL) \
      .with_log_stack_trace()                                        \
      .add_ret_check_failure(#condition)






















#define DECLARE_ENUM(enum_name, opcode_name, ...) enum_name,
#define HLO_COUNT_ONE(...) +1
#define HLO_OPCODE_LIST(V)                                                     \
                                                     \
  V(kAbs, "abs", 1)                                                            \
  V(kAdd, "add", 2)                                                            \
  V(kAddDependency, "add-dependency", 2)                                       \
  V(kAfterAll, "after-all", kHloOpcodeIsVariadic)                              \
  V(kAllGather, "all-gather", kHloOpcodeIsVariadic)                            \
  V(kAllGatherDone, "all-gather-done", 1)                                      \
  V(kAllGatherStart, "all-gather-start", kHloOpcodeIsVariadic)                 \
  V(kAllReduce, "all-reduce", kHloOpcodeIsVariadic)                            \
  V(kAllReduceDone, "all-reduce-done", 1)                                      \
  V(kAllReduceStart, "all-reduce-start", kHloOpcodeIsVariadic)                 \
  V(kAllToAll, "all-to-all", kHloOpcodeIsVariadic)                             \
  V(kAnd, "and", 2)                                                            \
  V(kAsyncDone, "async-done", 1)                                               \
  V(kAsyncStart, "async-start", kHloOpcodeIsVariadic)                          \
  V(kAsyncUpdate, "async-update", 1)                                           \
  V(kAtan2, "atan2", 2)                                                        \
  V(kBatchNormGrad, "batch-norm-grad", 5)                                      \
  V(kBatchNormInference, "batch-norm-inference", 5)                            \
  V(kBatchNormTraining, "batch-norm-training", 3)                              \
  V(kBitcast, "bitcast", 1)                                                    \
  V(kBitcastConvert, "bitcast-convert", 1)                                     \
  V(kBroadcast, "broadcast", 1)                                                \
  V(kCall, "call", kHloOpcodeIsVariadic)                                       \
  V(kCbrt, "cbrt", 1)                                                          \
  V(kCeil, "ceil", 1)                                                          \
  V(kCholesky, "cholesky", 1)                                                  \
  V(kClamp, "clamp", 3)                                                        \
  V(kClz, "count-leading-zeros", 1)                                            \
  V(kCollectivePermute, "collective-permute", kHloOpcodeIsVariadic)            \
  V(kCollectivePermuteDone, "collective-permute-done", 1)                      \
  V(kCollectivePermuteStart, "collective-permute-start", kHloOpcodeIsVariadic) \
  V(kCompare, "compare", 2)                                                    \
  V(kComplex, "complex", 2)                                                    \
  V(kConcatenate, "concatenate", kHloOpcodeIsVariadic)                         \
  V(kConditional, "conditional", kHloOpcodeIsVariadic)                         \
  V(kConstant, "constant", 0)                                                  \
  V(kConvert, "convert", 1)                                                    \
  V(kConvolution, "convolution", 2)                                            \
  V(kCopy, "copy", 1)                                                          \
  V(kCopyDone, "copy-done", 1)                                                 \
  V(kCopyStart, "copy-start", 1)                                               \
  V(kCos, "cosine", 1)                                                         \
  V(kCustomCall, "custom-call", kHloOpcodeIsVariadic)                          \
  V(kDivide, "divide", 2)                                                      \
  V(kDomain, "domain", 1)                                                      \
  V(kDot, "dot", 2)                                                            \
  V(kDynamicReshape, "dynamic-reshape", kHloOpcodeIsVariadic)                  \
  V(kDynamicSlice, "dynamic-slice", kHloOpcodeIsVariadic)                      \
  V(kDynamicUpdateSlice, "dynamic-update-slice", kHloOpcodeIsVariadic)         \
  V(kExp, "exponential", 1)                                                    \
  V(kExpm1, "exponential-minus-one", 1)                                        \
  V(kFft, "fft", 1)                                                            \
  V(kFloor, "floor", 1)                                                        \
  V(kFusion, "fusion", kHloOpcodeIsVariadic)                                   \
  V(kGather, "gather", 2)                                                      \
  V(kGetDimensionSize, "get-dimension-size", 1)                                \
  V(kGetTupleElement, "get-tuple-element", 1)                                  \
  V(kImag, "imag", 1)                                                          \
  V(kInfeed, "infeed", 1)                                                      \
  V(kIota, "iota", 0)                                                          \
  V(kIsFinite, "is-finite", 1)                                                 \
  V(kLog, "log", 1)                                                            \
  V(kLog1p, "log-plus-one", 1)                                                 \
  V(kLogistic, "logistic", 1)                                                  \
  V(kMap, "map", kHloOpcodeIsVariadic)                                         \
  V(kMaximum, "maximum", 2)                                                    \
  V(kMinimum, "minimum", 2)                                                    \
  V(kMultiply, "multiply", 2)                                                  \
  V(kNegate, "negate", 1)                                                      \
  V(kNot, "not", 1)                                                            \
  V(kOptimizationBarrier, "opt-barrier", 1)                                    \
  V(kOr, "or", 2)                                                              \
  V(kOutfeed, "outfeed", 2)                                                    \
  V(kPad, "pad", 2)                                                            \
  V(kParameter, "parameter", 0)                                                \
  V(kPartitionId, "partition-id", 0)                                           \
  V(kPopulationCount, "popcnt", 1)                                             \
  V(kPower, "power", 2)                                                        \
  V(kReal, "real", 1)                                                          \
  V(kRecv, "recv", 1)                                                          \
  V(kRecvDone, "recv-done", 1)                                                 \
  V(kReduce, "reduce", kHloOpcodeIsVariadic)                                   \
  V(kReducePrecision, "reduce-precision", 1)                                   \
  V(kReduceScatter, "reduce-scatter", kHloOpcodeIsVariadic)                    \
  V(kReduceWindow, "reduce-window", kHloOpcodeIsVariadic)                      \
  V(kRemainder, "remainder", 2)                                                \
  V(kReplicaId, "replica-id", 0)                                               \
  V(kReshape, "reshape", 1)                                                    \
  V(kReverse, "reverse", 1)                                                    \
  V(kRng, "rng", kHloOpcodeIsVariadic)                                         \
  V(kRngBitGenerator, "rng-bit-generator", 1)                                  \
  V(kRngGetAndUpdateState, "rng-get-and-update-state", 0)                      \
  V(kRoundNearestAfz, "round-nearest-afz", 1)                                  \
  V(kRoundNearestEven, "round-nearest-even", 1)                                \
  V(kRsqrt, "rsqrt", 1)                                                        \
  V(kScatter, "scatter", kHloOpcodeIsVariadic)                                 \
  V(kSelect, "select", 3)                                                      \
  V(kSelectAndScatter, "select-and-scatter", 3)                                \
  V(kSend, "send", 2)                                                          \
  V(kSendDone, "send-done", 1)                                                 \
  V(kSetDimensionSize, "set-dimension-size", 2)                                \
  V(kShiftLeft, "shift-left", 2)                                               \
  V(kShiftRightArithmetic, "shift-right-arithmetic", 2)                        \
  V(kShiftRightLogical, "shift-right-logical", 2)                              \
  V(kSign, "sign", 1)                                                          \
  V(kSin, "sine", 1)                                                           \
  V(kSlice, "slice", 1)                                                        \
  V(kSort, "sort", kHloOpcodeIsVariadic)                                       \
  V(kSqrt, "sqrt", 1)                                                          \
  V(kStochasticConvert, "stochastic-convert", 2)                               \
  V(kSubtract, "subtract", 2)                                                  \
  V(kTan, "tan", 1)                                                            \
  V(kTanh, "tanh", 1)                                                          \
  V(kTranspose, "transpose", 1)                                                \
  V(kTriangularSolve, "triangular-solve", 2)                                   \
  V(kTuple, "tuple", kHloOpcodeIsVariadic)                                     \
  V(kWhile, "while", 1)                                                        \
  V(kXor, "xor", 2)                                                            \
  
#define HLO_XLIST_LENGTH(list) list(HLO_COUNT_ONE)








#define REGISTER_XLA_BACKEND(NAME, ...) \
  REGISTER_XLA_BACKEND_UNIQ_HELPER(__COUNTER__, NAME, __VA_ARGS__)
#define REGISTER_XLA_BACKEND_UNIQ(CTR, NAME, ...) \
  static ::tensorflow::XlaBackendRegistrar        \
      xla_backend_registrar__body__##CTR##__object(NAME, __VA_ARGS__);
#define REGISTER_XLA_BACKEND_UNIQ_HELPER(COUNTER, NAME, ...) \
  REGISTER_XLA_BACKEND_UNIQ(COUNTER, NAME, __VA_ARGS__)
#define REGISTER_XLA_CONV_OP(BUILDER, OP)                                      \
  REGISTER_XLA_OP(BUILDER.TypeConstraint("T", GetXlaConvTypesForNonGpu()), OP) \
  REGISTER_XLA_OP(BUILDER.TypeConstraint("T", GetXlaConvTypesForGpu())         \
                      .Device(DEVICE_GPU_XLA_JIT),                             \
                  OP)
#define REGISTER_XLA_OP(NAME, OP) \
  REGISTER_XLA_OP_UNIQ_HELPER(__COUNTER__, NAME, OP)
#define REGISTER_XLA_OP_UNIQ(CTR, BUILDER, OP)                                 \
  static ::tensorflow::XlaOpRegistrar xla_op_registrar__body__##CTR##__object( \
      ::tensorflow::XlaOpRegistrationBuilder::BUILDER.Build(                   \
          [](::tensorflow::OpKernelConstruction* context)                      \
              -> ::tensorflow::OpKernel* { return new OP(context); }));
#define REGISTER_XLA_OP_UNIQ_HELPER(COUNTER, BUILDER, OP) \
  REGISTER_XLA_OP_UNIQ(COUNTER, BUILDER, OP)







#define INT_TYPE_ARITHMETIC_OP(op)                                        \
  template <typename IntTypeName, typename ValueType>                     \
  static inline constexpr IntType<IntTypeName, ValueType> operator op(    \
      IntType<IntTypeName, ValueType> id_1,                               \
      IntType<IntTypeName, ValueType> id_2) {                             \
    return IntType<IntTypeName, ValueType>(id_1.value() op id_2.value()); \
  }                                                                       \
  template <typename IntTypeName, typename ValueType>                     \
  static inline constexpr IntType<IntTypeName, ValueType> operator op(    \
      IntType<IntTypeName, ValueType> id,                                 \
      typename IntType<IntTypeName, ValueType>::ValueType arg_val) {      \
    return IntType<IntTypeName, ValueType>(id.value() op arg_val);        \
  }                                                                       \
  template <typename IntTypeName, typename ValueType>                     \
  static inline constexpr IntType<IntTypeName, ValueType> operator op(    \
      typename IntType<IntTypeName, ValueType>::ValueType arg_val,        \
      IntType<IntTypeName, ValueType> id) {                               \
    return IntType<IntTypeName, ValueType>(arg_val op id.value());        \
  }
#define INT_TYPE_ASSIGNMENT_OP(op)                   \
  ThisType& operator op(const ThisType& arg_value) { \
    value_ op arg_value.value();                     \
    return *this;                                    \
  }                                                  \
  ThisType& operator op(ValueType arg_value) {       \
    value_ op arg_value;                             \
    return *this;                                    \
  }
#define INT_TYPE_COMPARISON_OP(op)                               \
  template <typename IntTypeName, typename ValueType>            \
  static inline constexpr bool operator op(                      \
      IntType<IntTypeName, ValueType> id_1,                      \
      IntType<IntTypeName, ValueType> id_2) {                    \
    return id_1.value() op id_2.value();                         \
  }                                                              \
  template <typename IntTypeName, typename ValueType>            \
  static inline constexpr bool operator op(                      \
      IntType<IntTypeName, ValueType> id,                        \
      typename IntType<IntTypeName, ValueType>::ValueType val) { \
    return id.value() op val;                                    \
  }                                                              \
  template <typename IntTypeName, typename ValueType>            \
  static inline constexpr bool operator op(                      \
      typename IntType<IntTypeName, ValueType>::ValueType val,   \
      IntType<IntTypeName, ValueType> id) {                      \
    return val op id.value();                                    \
  }

#define TSL_LIB_GTL_DEFINE_INT_TYPE(int_type_name, value_type) \
  struct int_type_name##_tag_ {};                              \
  typedef ::tsl::gtl::IntType<int_type_name##_tag_, value_type> int_type_name;






#define GET_ATTR(T)                                          \
  extern template Status FunctionLibraryDefinition::GetAttr( \
      const Node&, const string&, T*) const;                 \
  extern template Status FunctionLibraryDefinition::GetAttr( \
      const NodeDef&, const string&, T*) const;
#define REGISTER_OP_GRADIENT(name, fn) \
  REGISTER_OP_GRADIENT_UNIQ_HELPER(__COUNTER__, name, fn)
#define REGISTER_OP_GRADIENT_UNIQ(ctr, name, fn)      \
  static bool unused_grad_##ctr TF_ATTRIBUTE_UNUSED = \
      SHOULD_REGISTER_OP_GRADIENT &&                  \
      ::tensorflow::gradient::RegisterOp(name, fn)
#define REGISTER_OP_GRADIENT_UNIQ_HELPER(ctr, name, fn) \
  REGISTER_OP_GRADIENT_UNIQ(ctr, name, fn)
#define REGISTER_OP_NO_GRADIENT(name) \
  REGISTER_OP_GRADIENT_UNIQ_HELPER(__COUNTER__, name, nullptr)




#define REGISTER_RESOURCE_HANDLE_KERNEL(Type)                        \
  REGISTER_KERNEL_BUILDER(Name(#Type "HandleOp").Device(DEVICE_CPU), \
                          ResourceHandleOp<Type>)
#define REGISTER_RESOURCE_HANDLE_OP(Type) \
  REGISTER_OP(#Type "HandleOp")           \
      .Attr("container: string = ''")     \
      .Attr("shared_name: string = ''")   \
      .Output("resource: resource")       \
      .SetIsStateful()                    \
      .SetShapeFn(tensorflow::shape_inference::ScalarShape)





#define INTERNAL_REGISTER_LOCAL_DEVICE_FACTORY(device_type, device_factory, \
                                               ctr, ...)                    \
  static ::tensorflow::dfactory::Registrar<device_factory>                  \
  INTERNAL_REGISTER_LOCAL_DEVICE_FACTORY_NAME(ctr)(device_type, ##__VA_ARGS__)
#define INTERNAL_REGISTER_LOCAL_DEVICE_FACTORY_NAME(ctr) ___##ctr##__object_
#define REGISTER_LOCAL_DEVICE_FACTORY(device_type, device_factory, ...) \
  INTERNAL_REGISTER_LOCAL_DEVICE_FACTORY(device_type, device_factory,   \
                                         __COUNTER__, ##__VA_ARGS__)























#define PLATFORM_DEFINE_ID(ID_VAR_NAME) \
  namespace {                           \
  int plugin_id_value;                  \
  }                                     \
  const ::stream_executor::Platform::Id ID_VAR_NAME = &plugin_id_value;



#define SE_DISALLOW_COPY_AND_ASSIGN TF_DISALLOW_COPY_AND_ASSIGN
#define SE_FALLTHROUGH_INTENDED TF_FALLTHROUGH_INTENDED
#define SE_MUST_USE_RESULT TF_MUST_USE_RESULT
#define SE_PREDICT_FALSE TF_PREDICT_FALSE
#define SE_PREDICT_TRUE TF_PREDICT_TRUE




#define PLUGIN_REGISTRY_DEFINE_PLUGIN_ID(ID_VAR_NAME) \
  namespace {                                         \
  int plugin_id_value;                                \
  }                                                   \
  const PluginId ID_VAR_NAME = &plugin_id_value;


#define PCHECK(invocation) CHECK(invocation)

























#define TF_CHECKPOINT_VERSION 1
#define TF_CHECKPOINT_VERSION_MIN_CONSUMER 0
#define TF_CHECKPOINT_VERSION_MIN_PRODUCER 0
#define TF_GRAPH_DEF_VERSION 1394  
#define TF_GRAPH_DEF_VERSION_MIN_CONSUMER 0
#define TF_GRAPH_DEF_VERSION_MIN_PRODUCER 0
#define TF_MAJOR_VERSION 2
#define TF_MINOR_VERSION 12
#define TF_PATCH_VERSION 0
#define TF_STR(x) TF_STR_HELPER(x)
#define TF_STR_HELPER(x) #x
#define TF_VERSION_STRING                                            \
  (TF_STR(TF_MAJOR_VERSION) "." TF_STR(TF_MINOR_VERSION) "." TF_STR( \
      TF_PATCH_VERSION) TF_VERSION_SUFFIX)
#define TF_VERSION_SUFFIX ""





















#define DECLARE_PLUGIN_SPECIALIZATIONS(FACTORY_TYPE)                         \
  template <>                                                                \
  tsl::Status PluginRegistry::RegisterFactory<PluginRegistry::FACTORY_TYPE>( \
      Platform::Id platform_id, PluginId plugin_id, const std::string& name, \
      PluginRegistry::FACTORY_TYPE factory);                                 \
  template <>                                                                \
  tsl::StatusOr<PluginRegistry::FACTORY_TYPE> PluginRegistry::GetFactory(    \
      Platform::Id platform_id, PluginId plugin_id);                         \
  template <>                                                                \
  tsl::StatusOr<PluginRegistry::FACTORY_TYPE> PluginRegistry::GetFactory(    \
      PlatformKind platform_kind, PluginId plugin_id)



#define TENSORFLOW_STREAM_EXECUTOR_GPU_FFT_SUPPORT_OVERRIDES                   \
  std::unique_ptr<fft::Plan> Create1dPlan(Stream *stream, uint64_t num_x,      \
                                          fft::Type type, bool in_place_fft)   \
      override;                                                                \
  std::unique_ptr<fft::Plan> Create2dPlan(Stream *stream, uint64_t num_x,      \
                                          uint64_t num_y, fft::Type type,      \
                                          bool in_place_fft) override;         \
  std::unique_ptr<fft::Plan> Create3dPlan(                                     \
      Stream *stream, uint64_t num_x, uint64 num_y, uint64 num_z,              \
      fft::Type type, bool in_place_fft) override;                             \
  std::unique_ptr<fft::Plan> Create1dPlanWithScratchAllocator(                 \
      Stream *stream, uint64_t num_x, fft::Type type, bool in_place_fft,       \
      ScratchAllocator *scratch_allocator) override;                           \
  std::unique_ptr<fft::Plan> Create2dPlanWithScratchAllocator(                 \
      Stream *stream, uint64_t num_x, uint64 num_y, fft::Type type,            \
      bool in_place_fft, ScratchAllocator *scratch_allocator) override;        \
  std::unique_ptr<fft::Plan> Create3dPlanWithScratchAllocator(                 \
      Stream *stream, uint64_t num_x, uint64 num_y, uint64 num_z,              \
      fft::Type type, bool in_place_fft, ScratchAllocator *scratch_allocator)  \
      override;                                                                \
  std::unique_ptr<fft::Plan> CreateBatchedPlan(                                \
      Stream *stream, int rank, uint64_t *elem_count, uint64 *input_embed,     \
      uint64_t input_stride, uint64 input_distance, uint64 *output_embed,      \
      uint64_t output_stride, uint64 output_distance, fft::Type type,          \
      bool in_place_fft, int batch_count) override;                            \
  std::unique_ptr<fft::Plan> CreateBatchedPlanWithScratchAllocator(            \
      Stream *stream, int rank, uint64_t *elem_count, uint64 *input_embed,     \
      uint64_t input_stride, uint64 input_distance, uint64 *output_embed,      \
      uint64_t output_stride, uint64 output_distance, fft::Type type,          \
      bool in_place_fft, int batch_count, ScratchAllocator *scratch_allocator) \
      override;                                                                \
  void UpdatePlanWithScratchAllocator(Stream *stream, fft::Plan *plan,         \
                                      ScratchAllocator *scratch_allocator)     \
      override;                                                                \
  bool DoFft(Stream *stream, fft::Plan *plan,                                  \
             const DeviceMemory<std::complex<float>> &input,                   \
             DeviceMemory<std::complex<float>> *output) override;              \
  bool DoFft(Stream *stream, fft::Plan *plan,                                  \
             const DeviceMemory<std::complex<double>> &input,                  \
             DeviceMemory<std::complex<double>> *output) override;             \
  bool DoFft(Stream *stream, fft::Plan *plan,                                  \
             const DeviceMemory<float> &input,                                 \
             DeviceMemory<std::complex<float>> *output) override;              \
  bool DoFft(Stream *stream, fft::Plan *plan,                                  \
             const DeviceMemory<double> &input,                                \
             DeviceMemory<std::complex<double>> *output) override;             \
  bool DoFft(Stream *stream, fft::Plan *plan,                                  \
             const DeviceMemory<std::complex<float>> &input,                   \
             DeviceMemory<float> *output) override;                            \
  bool DoFft(Stream *stream, fft::Plan *plan,                                  \
             const DeviceMemory<std::complex<double>> &input,                  \
             DeviceMemory<double> *output) override;



#define TENSORFLOW_STREAM_EXECUTOR_GPU_BLAS_SUPPORT_OVERRIDES                  \
  bool DoBlasAxpy(Stream *stream, uint64_t elem_count, float alpha,            \
                  const DeviceMemory<float> &x, int incx,                      \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasAxpy(Stream *stream, uint64_t elem_count, double alpha,           \
                  const DeviceMemory<double> &x, int incx,                     \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasAxpy(Stream *stream, uint64_t elem_count,                         \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasAxpy(Stream *stream, uint64_t elem_count,                         \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasCopy(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<float> &x, int incx,                      \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasCopy(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<double> &x, int incx,                     \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasCopy(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasCopy(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasScal(Stream *stream, uint64_t elem_count, float alpha,            \
                  DeviceMemory<float> *x, int incx) override;                  \
  bool DoBlasScal(Stream *stream, uint64_t elem_count, double alpha,           \
                  DeviceMemory<double> *x, int incx) override;                 \
  bool DoBlasScal(Stream *stream, uint64_t elem_count, float alpha,            \
                  DeviceMemory<std::complex<float>> *x, int incx) override;    \
  bool DoBlasScal(Stream *stream, uint64_t elem_count, double alpha,           \
                  DeviceMemory<std::complex<double>> *x, int incx) override;   \
  bool DoBlasScal(Stream *stream, uint64_t elem_count,                         \
                  std::complex<float> alpha,                                   \
                  DeviceMemory<std::complex<float>> *x, int incx) override;    \
  bool DoBlasScal(Stream *stream, uint64_t elem_count,                         \
                  std::complex<double> alpha,                                  \
                  DeviceMemory<std::complex<double>> *x, int incx) override;   \
  bool DoBlasGemv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  float alpha, const DeviceMemory<float> &a, int lda,          \
                  const DeviceMemory<float> &x, int incx, float beta,          \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasGemv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  double alpha, const DeviceMemory<double> &a, int lda,        \
                  const DeviceMemory<double> &x, int incx, double beta,        \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasGemv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasGemv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasGemvWithProfiling(                                                \
      Stream *stream, blas::Transpose trans, uint64_t m, uint64 n,             \
      float alpha, const DeviceMemory<float> &a, int lda,                      \
      const DeviceMemory<float> &x, int incx, float beta,                      \
      DeviceMemory<float> *y, int incy,                                        \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemvWithProfiling(                                                \
      Stream *stream, blas::Transpose trans, uint64_t m, uint64 n,             \
      double alpha, const DeviceMemory<double> &a, int lda,                    \
      const DeviceMemory<double> &x, int incx, double beta,                    \
      DeviceMemory<double> *y, int incy,                                       \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemvWithProfiling(                                                \
      Stream *stream, blas::Transpose trans, uint64_t m, uint64 n,             \
      std::complex<float> alpha, const DeviceMemory<std::complex<float>> &a,   \
      int lda, const DeviceMemory<std::complex<float>> &x, int incx,           \
      std::complex<float> beta, DeviceMemory<std::complex<float>> *y,          \
      int incy, blas::ProfileResult *output_profile_result) override;          \
  bool DoBlasGemvWithProfiling(                                                \
      Stream *stream, blas::Transpose trans, uint64_t m, uint64 n,             \
      std::complex<double> alpha, const DeviceMemory<std::complex<double>> &a, \
      int lda, const DeviceMemory<std::complex<double>> &x, int incx,          \
      std::complex<double> beta, DeviceMemory<std::complex<double>> *y,        \
      int incy, blas::ProfileResult *output_profile_result) override;          \
  bool DoBlasSbmv(Stream *stream, blas::UpperLower uplo, uint64_t n, uint64 k, \
                  float alpha, const DeviceMemory<float> &a, int lda,          \
                  const DeviceMemory<float> &x, int incx, float beta,          \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasSbmv(Stream *stream, blas::UpperLower uplo, uint64_t n, uint64 k, \
                  double alpha, const DeviceMemory<double> &a, int lda,        \
                  const DeviceMemory<double> &x, int incx, double beta,        \
                  DeviceMemory<double> *y, int incy) override;                 \
  tsl::Status DoBlasGemm(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, blas::DataType dtype, const void *alpha, \
      const DeviceMemoryBase &a, int lda, const DeviceMemoryBase &b, int ldb,  \
      const void *beta, DeviceMemoryBase *c, int ldc,                          \
      blas::ComputePrecision precision) override;                              \
  bool DoBlasGemmWithProfiling(                                                \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha,                             \
      const DeviceMemory<Eigen::half> &a, int lda,                             \
      const DeviceMemory<Eigen::half> &b, int ldb, float beta,                 \
      DeviceMemory<Eigen::half> *c, int ldc,                                   \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemmWithProfiling(                                                \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha,                             \
      const DeviceMemory<float> &a, int lda, const DeviceMemory<float> &b,     \
      int ldb, float beta, DeviceMemory<float> *c, int ldc,                    \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemmWithProfiling(                                                \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, double alpha,                            \
      const DeviceMemory<double> &a, int lda, const DeviceMemory<double> &b,   \
      int ldb, double beta, DeviceMemory<double> *c, int ldc,                  \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemmWithProfiling(                                                \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, std::complex<float> alpha,               \
      const DeviceMemory<std::complex<float>> &a, int lda,                     \
      const DeviceMemory<std::complex<float>> &b, int ldb,                     \
      std::complex<float> beta, DeviceMemory<std::complex<float>> *c, int ldc, \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemmWithProfiling(                                                \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, std::complex<double> alpha,              \
      const DeviceMemory<std::complex<double>> &a, int lda,                    \
      const DeviceMemory<std::complex<double>> &b, int ldb,                    \
      std::complex<double> beta, DeviceMemory<std::complex<double>> *c,        \
      int ldc, blas::ProfileResult *output_profile_result) override;           \
  bool GetBlasGemmAlgorithms(Stream *stream,                                   \
                             std::vector<blas::AlgorithmType> *out_algorithms) \
      override;                                                                \
  tsl::Status DoBlasGemmWithAlgorithm(                                         \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, const void *alpha,                       \
      const DeviceMemoryBase &a, blas::DataType type_a, int lda,               \
      const DeviceMemoryBase &b, blas::DataType type_b, int ldb,               \
      const void *beta, DeviceMemoryBase *c, blas::DataType type_c, int ldc,   \
      blas::ComputationType computation_type, blas::AlgorithmType algorithm,   \
      blas::ComputePrecision precision,                                        \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha,                             \
      DeviceMemorySlice<Eigen::half> a, int lda,                               \
      DeviceMemorySlice<Eigen::half> b, int ldb, float beta,                   \
      DeviceMemorySlice<Eigen::half> c, int ldc, int batch_count,              \
      ScratchAllocator *scratch_allocator) override;                           \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha,                             \
      DeviceMemorySlice<Eigen::bfloat16> a, int lda,                           \
      DeviceMemorySlice<Eigen::bfloat16> b, int ldb, float beta,               \
      DeviceMemorySlice<Eigen::bfloat16> c, int ldc, int batch_count,          \
      ScratchAllocator *scratch_allocator) override;                           \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha, DeviceMemorySlice<float> a, \
      int lda, DeviceMemorySlice<float> b, int ldb, float beta,                \
      DeviceMemorySlice<float> c, int ldc, int batch_count,                    \
      ScratchAllocator *scratch_allocator) override;                           \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, double alpha,                            \
      DeviceMemorySlice<double> a, int lda, DeviceMemorySlice<double> b,       \
      int ldb, double beta, DeviceMemorySlice<double> c, int ldc,              \
      int batch_count, ScratchAllocator *scratch_allocator) override;          \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, std::complex<float> alpha,               \
      DeviceMemorySlice<std::complex<float>> a, int lda,                       \
      DeviceMemorySlice<std::complex<float>> b, int ldb,                       \
      std::complex<float> beta, DeviceMemorySlice<std::complex<float>> c,      \
      int ldc, int batch_count, ScratchAllocator *scratch_allocator) override; \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, std::complex<double> alpha,              \
      DeviceMemorySlice<std::complex<double>> a, int lda,                      \
      DeviceMemorySlice<std::complex<double>> b, int ldb,                      \
      std::complex<double> beta, DeviceMemorySlice<std::complex<double>> c,    \
      int ldc, int batch_count, ScratchAllocator *scratch_allocator) override; \
  tsl::Status DoBlasGemmStridedBatched(                                        \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, blas::DataType dtype, const void *alpha, \
      const DeviceMemoryBase &a, int lda, int64_t stride_a,                    \
      const DeviceMemoryBase &b, int ldb, int64_t stride_b, const void *beta,  \
      DeviceMemoryBase *c, int ldc, int64_t stride_c, int batch_count,         \
      blas::ComputePrecision precision) override;                              \
  tsl::Status DoBlasGemmStridedBatchedWithAlgorithm(                           \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, const void *alpha,                       \
      const DeviceMemoryBase &a, blas::DataType type_a, int lda,               \
      int64_t stride_a, const DeviceMemoryBase &b, blas::DataType type_b,      \
      int ldb, int64_t stride_b, const void *beta, DeviceMemoryBase *c,        \
      blas::DataType type_c, int ldc, int64_t stride_c, int batch_count,       \
      blas::ComputationType computation_type, blas::AlgorithmType algorithm,   \
      blas::ComputePrecision precision,                                        \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasTrsm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, float alpha, const DeviceMemory<float> &a,       \
                  int lda, DeviceMemory<float> *b, int ldb) override;          \
  bool DoBlasTrsm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, double alpha, const DeviceMemory<double> &a,     \
                  int lda, DeviceMemory<double> *b, int ldb) override;         \
  bool DoBlasTrsm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, std::complex<float> alpha,                       \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  DeviceMemory<std::complex<float>> *b, int ldb) override;     \
  bool DoBlasTrsm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, std::complex<double> alpha,                      \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  DeviceMemory<std::complex<double>> *b, int ldb) override;    \
  bool DoBlasTrsmBatched(                                                      \
      Stream *stream, blas::Side side, blas::UpperLower uplo,                  \
      blas::Transpose transa, blas::Diagonal diag, uint64_t m, uint64 n,       \
      float alpha, const DeviceMemory<float *> &as, int lda,                   \
      DeviceMemory<float *> *bs, int ldb, int batch_count) override;           \
  bool DoBlasTrsmBatched(                                                      \
      Stream *stream, blas::Side side, blas::UpperLower uplo,                  \
      blas::Transpose transa, blas::Diagonal diag, uint64_t m, uint64 n,       \
      double alpha, const DeviceMemory<double *> &as, int lda,                 \
      DeviceMemory<double *> *bs, int ldb, int batch_count) override;          \
  bool DoBlasTrsmBatched(Stream *stream, blas::Side side,                      \
                         blas::UpperLower uplo, blas::Transpose transa,        \
                         blas::Diagonal diag, uint64_t m, uint64 n,            \
                         std::complex<float> alpha,                            \
                         const DeviceMemory<std::complex<float> *> &as,        \
                         int lda, DeviceMemory<std::complex<float> *> *bs,     \
                         int ldb, int batch_count) override;                   \
  bool DoBlasTrsmBatched(Stream *stream, blas::Side side,                      \
                         blas::UpperLower uplo, blas::Transpose transa,        \
                         blas::Diagonal diag, uint64_t m, uint64 n,            \
                         std::complex<double> alpha,                           \
                         const DeviceMemory<std::complex<double> *> &as,       \
                         int lda, DeviceMemory<std::complex<double> *> *bs,    \
                         int ldb, int batch_count) override;                   \
  tsl::Status GetVersion(std::string *version) override;










#define DECLARE_INITIALIZER(type, name) \
  extern ::stream_executor::port::Initializer google_initializer_##type##_##name
#define DECLARE_MODULE_INITIALIZER(name) DECLARE_INITIALIZER(module, name)
#define REGISTER_INITIALIZER(type, name, body)                             \
  static void google_init_##type##_##name() { body; }                      \
  ::stream_executor::port::Initializer google_initializer_##type##_##name( \
      google_init_##type##_##name)
#define REGISTER_MODULE_INITIALIZER(name, body) \
  REGISTER_INITIALIZER(module, name, body)
#define REGISTER_MODULE_INITIALIZER_SEQUENCE(name1, name2)










































