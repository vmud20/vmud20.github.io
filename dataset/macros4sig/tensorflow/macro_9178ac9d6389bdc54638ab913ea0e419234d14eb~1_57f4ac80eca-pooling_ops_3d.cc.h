





#include<array>

#include<tuple>



#include<unordered_set>







#include<iostream>









#include<functional>


#include<iosfwd>

#include<assert.h>
#include<limits.h>












#include<map>







#include<chrono>









#include<stddef.h>


#include<cstdint>










#include<unordered_map>


#include<atomic>


#include<utility>


#include<initializer_list>


















#include<complex>





#include<mutex>
#include<sys/time.h>



#include<typeinfo>


#include<string>


#include<set>












#include<ostream>



#include<type_traits>

#include<string.h>


#include<memory>
#include<stdlib.h>




#include<iterator>
#include<algorithm>
#include<vector>







#include<stdint.h>







#include<condition_variable>



#include<new>




#include<cstddef>






#include<sstream>
#include<limits>









#define TF_TSTRING_LITTLE_ENDIAN 1
#define TF_le32toh(x) x


#define TF_CORD_SUPPORT 1














#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#define __ORDER_BIG_ENDIAN__ 0x10e1
#define __ORDER_LITTLE_ENDIAN__ 0x4d2

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





#define TF_ANNOTATE_BENIGN_RACE(ptr, description) \
  do {                                            \
  } while (0)
#define TF_ANNOTATE_MEMORY_IS_INITIALIZED(ptr, bytes) \
  do {                                                \
  } while (0)


#define CHECK(condition)              \
  if (TF_PREDICT_FALSE(!(condition))) \
  LOG(FATAL) << "Check failed: " #condition " "
#define CHECK_EQ(val1, val2) CHECK_OP(Check_EQ, ==, val1, val2)
#define CHECK_GE(val1, val2) CHECK_OP(Check_GE, >=, val1, val2)
#define CHECK_GT(val1, val2) CHECK_OP(Check_GT, >, val1, val2)
#define CHECK_LE(val1, val2) CHECK_OP(Check_LE, <=, val1, val2)
#define CHECK_LT(val1, val2) CHECK_OP(Check_LT, <, val1, val2)
#define CHECK_NE(val1, val2) CHECK_OP(Check_NE, !=, val1, val2)
#define CHECK_NOTNULL(val)                                 \
  ::tensorflow::internal::CheckNotNull("__FILE__", "__LINE__", \
                                       "'" #val "' Must be non NULL", (val))
#define CHECK_OP(name, op, val1, val2) CHECK_OP_LOG(name, op, val1, val2)
#define CHECK_OP_LOG(name, op, val1, val2)                     \
  while (::tensorflow::internal::CheckOpString _result{        \
      ::tensorflow::internal::name##Impl(                      \
          ::tensorflow::internal::GetReferenceableValue(val1), \
          ::tensorflow::internal::GetReferenceableValue(val2), \
          #val1 " " #op " " #val2)})                           \
  ::tensorflow::internal::LogMessageFatal("__FILE__", "__LINE__") << *(_result.str_)
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
    for (static ::tensorflow::internal::Log##kind##State            \
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

#define TF_DEFINE_CHECK_OP_IMPL(name, op)                                 \
  template <typename T1, typename T2>                                     \
  inline string* name##Impl(const T1& v1, const T2& v2,                   \
                            const char* exprtext) {                       \
    if (TF_PREDICT_TRUE(v1 op v2))                                        \
      return NULL;                                                        \
    else                                                                  \
      return ::tensorflow::internal::MakeCheckOpString(v1, v2, exprtext); \
  }                                                                       \
  inline string* name##Impl(int v1, int v2, const char* exprtext) {       \
    return name##Impl<int, int>(v1, v2, exprtext);                        \
  }
#define VLOG(level)                                              \
  TF_PREDICT_TRUE(!VLOG_IS_ON(level))                            \
  ? (void)0                                                      \
  : ::tensorflow::internal::Voidifier() &                        \
          ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", \
                                             tensorflow::INFO)
#define VLOG_IS_ON(lvl) ((lvl) <= 0)
#define _TF_DCHECK_NOP(x, y) \
  while (false && ((void)(x), (void)(y), 0)) LOG(FATAL)
#define _TF_LOG_ERROR \
  ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", ::tensorflow::ERROR)
#define _TF_LOG_FATAL \
  ::tensorflow::internal::LogMessageFatal("__FILE__", "__LINE__")
#define _TF_LOG_INFO \
  ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", ::tensorflow::INFO)
#define _TF_LOG_QFATAL _TF_LOG_FATAL
#define _TF_LOG_WARNING \
  ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", ::tensorflow::WARNING)



#define TF_CHECK_OK(val) TF_DO_CHECK_OK(val, FATAL)
#define TF_DCHECK_OK(val) TF_CHECK_OK(val)
#define TF_DO_CHECK_OK(val, level)                                \
  while (auto _result = ::tensorflow::TfCheckOpHelper(val, #val)) \
  LOG(level) << *(_result)
#define TF_INTERNAL_HAVE_BUILTIN_LINE_FILE 1
#define TF_QCHECK_OK(val) TF_DO_CHECK_OK(val, QFATAL)



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
  lhs = std::move(statusor).ValueOrDie()
#define TF_ASSIGN_OR_RETURN(lhs, rexpr) \
  TF_ASSIGN_OR_RETURN_IMPL(             \
      TF_STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, rexpr)
#define TF_ASSIGN_OR_RETURN_IMPL(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                             \
  if (TF_PREDICT_FALSE(!statusor.ok())) {              \
    return statusor.status();                          \
  }                                                    \
  lhs = std::move(statusor).ValueOrDie()
#define TF_STATUS_MACROS_CONCAT_IMPL(x, y) x##y
#define TF_STATUS_MACROS_CONCAT_NAME(x, y) TF_STATUS_MACROS_CONCAT_IMPL(x, y)








#define TF_RETURN_IF_ERROR(...)                          \
  do {                                                   \
    ::tensorflow::Status _status = (__VA_ARGS__);        \
    if (TF_PREDICT_FALSE(!_status.ok())) return _status; \
  } while (0)
#define TF_RETURN_WITH_CONTEXT_IF_ERROR(expr, ...)                  \
  do {                                                              \
    ::tensorflow::Status _status = (expr);                          \
    if (TF_PREDICT_FALSE(!_status.ok())) {                          \
      ::tensorflow::errors::AppendToMessage(&_status, __VA_ARGS__); \
      return _status;                                               \
    }                                                               \
  } while (0)
















#define SE_DISALLOW_COPY_AND_ASSIGN TF_DISALLOW_COPY_AND_ASSIGN
#define SE_FALLTHROUGH_INTENDED TF_FALLTHROUGH_INTENDED
#define SE_MUST_USE_RESULT TF_MUST_USE_RESULT
#define SE_PREDICT_FALSE TF_PREDICT_FALSE
#define SE_PREDICT_TRUE TF_PREDICT_TRUE





#define DECLARE_PLUGIN_SPECIALIZATIONS(FACTORY_TYPE)                          \
  template <>                                                                 \
  port::Status PluginRegistry::RegisterFactory<PluginRegistry::FACTORY_TYPE>( \
      Platform::Id platform_id, PluginId plugin_id, const std::string& name,  \
      PluginRegistry::FACTORY_TYPE factory);                                  \
  template <>                                                                 \
  port::StatusOr<PluginRegistry::FACTORY_TYPE> PluginRegistry::GetFactory(    \
      Platform::Id platform_id, PluginId plugin_id);                          \
  template <>                                                                 \
  port::StatusOr<PluginRegistry::FACTORY_TYPE> PluginRegistry::GetFactory(    \
      PlatformKind platform_kind, PluginId plugin_id)


#define PCHECK(invocation) CHECK(invocation)

#define PLUGIN_REGISTRY_DEFINE_PLUGIN_ID(ID_VAR_NAME) \
  namespace {                                         \
  int plugin_id_value;                                \
  }                                                   \
  const PluginId ID_VAR_NAME = &plugin_id_value;

#define PLATFORM_DEFINE_ID(ID_VAR_NAME) \
  namespace {                           \
  int plugin_id_value;                  \
  }                                     \
  const ::stream_executor::Platform::Id ID_VAR_NAME = &plugin_id_value;


#define SE_ASSERT_OK(val) \
  ASSERT_EQ(::stream_executor::port::Status::OK(), (val))
#define SE_CHECK_OK(val) TF_CHECK_OK(val)










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
  bool DoBlasAsum(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<float> &x, int incx,                      \
                  DeviceMemory<float> *result) override;                       \
  bool DoBlasAsum(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<double> &x, int incx,                     \
                  DeviceMemory<double> *result) override;                      \
  bool DoBlasAsum(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  DeviceMemory<float> *result) override;                       \
  bool DoBlasAsum(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  DeviceMemory<double> *result) override;                      \
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
  bool DoBlasDot(Stream *stream, uint64_t elem_count,                          \
                 const DeviceMemory<float> &x, int incx,                       \
                 const DeviceMemory<float> &y, int incy,                       \
                 DeviceMemory<float> *result) override;                        \
  bool DoBlasDot(Stream *stream, uint64_t elem_count,                          \
                 const DeviceMemory<double> &x, int incx,                      \
                 const DeviceMemory<double> &y, int incy,                      \
                 DeviceMemory<double> *result) override;                       \
  bool DoBlasDotc(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  const DeviceMemory<std::complex<float>> &y, int incy,        \
                  DeviceMemory<std::complex<float>> *result) override;         \
  bool DoBlasDotc(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  const DeviceMemory<std::complex<double>> &y, int incy,       \
                  DeviceMemory<std::complex<double>> *result) override;        \
  bool DoBlasDotu(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  const DeviceMemory<std::complex<float>> &y, int incy,        \
                  DeviceMemory<std::complex<float>> *result) override;         \
  bool DoBlasDotu(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  const DeviceMemory<std::complex<double>> &y, int incy,       \
                  DeviceMemory<std::complex<double>> *result) override;        \
  bool DoBlasNrm2(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<float> &x, int incx,                      \
                  DeviceMemory<float> *result) override;                       \
  bool DoBlasNrm2(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<double> &x, int incx,                     \
                  DeviceMemory<double> *result) override;                      \
  bool DoBlasNrm2(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  DeviceMemory<float> *result) override;                       \
  bool DoBlasNrm2(Stream *stream, uint64_t elem_count,                         \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  DeviceMemory<double> *result) override;                      \
  bool DoBlasRot(Stream *stream, uint64_t elem_count, DeviceMemory<float> *x,  \
                 int incx, DeviceMemory<float> *y, int incy, float c, float s) \
      override;                                                                \
  bool DoBlasRot(Stream *stream, uint64_t elem_count, DeviceMemory<double> *x, \
                 int incx, DeviceMemory<double> *y, int incy, double c,        \
                 double s) override;                                           \
  bool DoBlasRot(Stream *stream, uint64_t elem_count,                          \
                 DeviceMemory<std::complex<float>> *x, int incx,               \
                 DeviceMemory<std::complex<float>> *y, int incy, float c,      \
                 float s) override;                                            \
  bool DoBlasRot(Stream *stream, uint64_t elem_count,                          \
                 DeviceMemory<std::complex<double>> *x, int incx,              \
                 DeviceMemory<std::complex<double>> *y, int incy, double c,    \
                 double s) override;                                           \
  bool DoBlasRotg(Stream *stream, DeviceMemory<float> *a,                      \
                  DeviceMemory<float> *b, DeviceMemory<float> *c,              \
                  DeviceMemory<float> *s) override;                            \
  bool DoBlasRotg(Stream *stream, DeviceMemory<double> *a,                     \
                  DeviceMemory<double> *b, DeviceMemory<double> *c,            \
                  DeviceMemory<double> *s) override;                           \
  bool DoBlasRotg(Stream *stream, DeviceMemory<std::complex<float>> *a,        \
                  DeviceMemory<std::complex<float>> *b,                        \
                  DeviceMemory<float> *c,                                      \
                  DeviceMemory<std::complex<float>> *s) override;              \
  bool DoBlasRotg(Stream *stream, DeviceMemory<std::complex<double>> *a,       \
                  DeviceMemory<std::complex<double>> *b,                       \
                  DeviceMemory<double> *c,                                     \
                  DeviceMemory<std::complex<double>> *s) override;             \
  bool DoBlasRotm(Stream *stream, uint64_t elem_count, DeviceMemory<float> *x, \
                  int incx, DeviceMemory<float> *y, int incy,                  \
                  const DeviceMemory<float> &param) override;                  \
  bool DoBlasRotm(Stream *stream, uint64_t elem_count,                         \
                  DeviceMemory<double> *x, int incx, DeviceMemory<double> *y,  \
                  int incy, const DeviceMemory<double> &param) override;       \
  bool DoBlasRotmg(Stream *stream, DeviceMemory<float> *d1,                    \
                   DeviceMemory<float> *d2, DeviceMemory<float> *x1,           \
                   const DeviceMemory<float> &y1, DeviceMemory<float> *param)  \
      override;                                                                \
  bool DoBlasRotmg(Stream *stream, DeviceMemory<double> *d1,                   \
                   DeviceMemory<double> *d2, DeviceMemory<double> *x1,         \
                   const DeviceMemory<double> &y1,                             \
                   DeviceMemory<double> *param) override;                      \
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
  bool DoBlasSwap(Stream *stream, uint64_t elem_count, DeviceMemory<float> *x, \
                  int incx, DeviceMemory<float> *y, int incy) override;        \
  bool DoBlasSwap(Stream *stream, uint64_t elem_count,                         \
                  DeviceMemory<double> *x, int incx, DeviceMemory<double> *y,  \
                  int incy) override;                                          \
  bool DoBlasSwap(Stream *stream, uint64_t elem_count,                         \
                  DeviceMemory<std::complex<float>> *x, int incx,              \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasSwap(Stream *stream, uint64_t elem_count,                         \
                  DeviceMemory<std::complex<double>> *x, int incx,             \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasIamax(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<float> &x, int incx,                     \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamax(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<double> &x, int incx,                    \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamax(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<std::complex<float>> &x, int incx,       \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamax(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<std::complex<double>> &x, int incx,      \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamin(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<float> &x, int incx,                     \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamin(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<double> &x, int incx,                    \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamin(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<std::complex<float>> &x, int incx,       \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasIamin(Stream *stream, uint64_t elem_count,                        \
                   const DeviceMemory<std::complex<double>> &x, int incx,      \
                   DeviceMemory<int> *result) override;                        \
  bool DoBlasGbmv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  uint64_t kl, uint64 ku, float alpha,                         \
                  const DeviceMemory<float> &a, int lda,                       \
                  const DeviceMemory<float> &x, int incx, float beta,          \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasGbmv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  uint64_t kl, uint64 ku, double alpha,                        \
                  const DeviceMemory<double> &a, int lda,                      \
                  const DeviceMemory<double> &x, int incx, double beta,        \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasGbmv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  uint64_t kl, uint64 ku, std::complex<float> alpha,           \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasGbmv(Stream *stream, blas::Transpose trans, uint64_t m, uint64 n, \
                  uint64_t kl, uint64 ku, std::complex<double> alpha,          \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
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
  bool DoBlasGer(Stream *stream, uint64_t m, uint64 n, float alpha,            \
                 const DeviceMemory<float> &x, int incx,                       \
                 const DeviceMemory<float> &y, int incy,                       \
                 DeviceMemory<float> *a, int lda) override;                    \
  bool DoBlasGer(Stream *stream, uint64_t m, uint64 n, double alpha,           \
                 const DeviceMemory<double> &x, int incx,                      \
                 const DeviceMemory<double> &y, int incy,                      \
                 DeviceMemory<double> *a, int lda) override;                   \
  bool DoBlasGerc(Stream *stream, uint64_t m, uint64 n,                        \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  const DeviceMemory<std::complex<float>> &y, int incy,        \
                  DeviceMemory<std::complex<float>> *a, int lda) override;     \
  bool DoBlasGerc(Stream *stream, uint64_t m, uint64 n,                        \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  const DeviceMemory<std::complex<double>> &y, int incy,       \
                  DeviceMemory<std::complex<double>> *a, int lda) override;    \
  bool DoBlasGeru(Stream *stream, uint64_t m, uint64 n,                        \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  const DeviceMemory<std::complex<float>> &y, int incy,        \
                  DeviceMemory<std::complex<float>> *a, int lda) override;     \
  bool DoBlasGeru(Stream *stream, uint64_t m, uint64 n,                        \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  const DeviceMemory<std::complex<double>> &y, int incy,       \
                  DeviceMemory<std::complex<double>> *a, int lda) override;    \
  bool DoBlasHbmv(Stream *stream, blas::UpperLower uplo, uint64_t n, uint64 k, \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasHbmv(Stream *stream, blas::UpperLower uplo, uint64_t n, uint64 k, \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasHemv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasHemv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasHer(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 float alpha, const DeviceMemory<std::complex<float>> &x,      \
                 int incx, DeviceMemory<std::complex<float>> *a, int lda)      \
      override;                                                                \
  bool DoBlasHer(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 double alpha, const DeviceMemory<std::complex<double>> &x,    \
                 int incx, DeviceMemory<std::complex<double>> *a, int lda)     \
      override;                                                                \
  bool DoBlasHer2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  const DeviceMemory<std::complex<float>> &y, int incy,        \
                  DeviceMemory<std::complex<float>> *a, int lda) override;     \
  bool DoBlasHer2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  const DeviceMemory<std::complex<double>> &y, int incy,       \
                  DeviceMemory<std::complex<double>> *a, int lda) override;    \
  bool DoBlasHpmv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &ap,                 \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *y, int incy) override;    \
  bool DoBlasHpmv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &ap,                \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *y, int incy) override;   \
  bool DoBlasHpr(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 float alpha, const DeviceMemory<std::complex<float>> &x,      \
                 int incx, DeviceMemory<std::complex<float>> *ap) override;    \
  bool DoBlasHpr(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 double alpha, const DeviceMemory<std::complex<double>> &x,    \
                 int incx, DeviceMemory<std::complex<double>> *ap) override;   \
  bool DoBlasHpr2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &x, int incx,        \
                  const DeviceMemory<std::complex<float>> &y, int incy,        \
                  DeviceMemory<std::complex<float>> *ap) override;             \
  bool DoBlasHpr2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &x, int incx,       \
                  const DeviceMemory<std::complex<double>> &y, int incy,       \
                  DeviceMemory<std::complex<double>> *ap) override;            \
  bool DoBlasSbmv(Stream *stream, blas::UpperLower uplo, uint64_t n, uint64 k, \
                  float alpha, const DeviceMemory<float> &a, int lda,          \
                  const DeviceMemory<float> &x, int incx, float beta,          \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasSbmv(Stream *stream, blas::UpperLower uplo, uint64_t n, uint64 k, \
                  double alpha, const DeviceMemory<double> &a, int lda,        \
                  const DeviceMemory<double> &x, int incx, double beta,        \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasSpmv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  float alpha, const DeviceMemory<float> &ap,                  \
                  const DeviceMemory<float> &x, int incx, float beta,          \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasSpmv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  double alpha, const DeviceMemory<double> &ap,                \
                  const DeviceMemory<double> &x, int incx, double beta,        \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasSpr(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 float alpha, const DeviceMemory<float> &x, int incx,          \
                 DeviceMemory<float> *ap) override;                            \
  bool DoBlasSpr(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 double alpha, const DeviceMemory<double> &x, int incx,        \
                 DeviceMemory<double> *ap) override;                           \
  bool DoBlasSpr2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  float alpha, const DeviceMemory<float> &x, int incx,         \
                  const DeviceMemory<float> &y, int incy,                      \
                  DeviceMemory<float> *ap) override;                           \
  bool DoBlasSpr2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  double alpha, const DeviceMemory<double> &x, int incx,       \
                  const DeviceMemory<double> &y, int incy,                     \
                  DeviceMemory<double> *ap) override;                          \
  bool DoBlasSymv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  float alpha, const DeviceMemory<float> &a, int lda,          \
                  const DeviceMemory<float> &x, int incx, float beta,          \
                  DeviceMemory<float> *y, int incy) override;                  \
  bool DoBlasSymv(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  double alpha, const DeviceMemory<double> &a, int lda,        \
                  const DeviceMemory<double> &x, int incx, double beta,        \
                  DeviceMemory<double> *y, int incy) override;                 \
  bool DoBlasSyr(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 float alpha, const DeviceMemory<float> &x, int incx,          \
                 DeviceMemory<float> *a, int lda) override;                    \
  bool DoBlasSyr(Stream *stream, blas::UpperLower uplo, uint64_t n,            \
                 double alpha, const DeviceMemory<double> &x, int incx,        \
                 DeviceMemory<double> *a, int lda) override;                   \
  bool DoBlasSyr2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  float alpha, const DeviceMemory<float> &x, int incx,         \
                  const DeviceMemory<float> &y, int incy,                      \
                  DeviceMemory<float> *a, int lda) override;                   \
  bool DoBlasSyr2(Stream *stream, blas::UpperLower uplo, uint64_t n,           \
                  double alpha, const DeviceMemory<double> &x, int incx,       \
                  const DeviceMemory<double> &y, int incy,                     \
                  DeviceMemory<double> *a, int lda) override;                  \
  bool DoBlasTbmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<float> &a, int lda,           \
                  DeviceMemory<float> *x, int incx) override;                  \
  bool DoBlasTbmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<double> &a, int lda,          \
                  DeviceMemory<double> *x, int incx) override;                 \
  bool DoBlasTbmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<std::complex<float>> &a,      \
                  int lda, DeviceMemory<std::complex<float>> *x, int incx)     \
      override;                                                                \
  bool DoBlasTbmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<std::complex<double>> &a,     \
                  int lda, DeviceMemory<std::complex<double>> *x, int incx)    \
      override;                                                                \
  bool DoBlasTbsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<float> &a, int lda,           \
                  DeviceMemory<float> *x, int incx) override;                  \
  bool DoBlasTbsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<double> &a, int lda,          \
                  DeviceMemory<double> *x, int incx) override;                 \
  bool DoBlasTbsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<std::complex<float>> &a,      \
                  int lda, DeviceMemory<std::complex<float>> *x, int incx)     \
      override;                                                                \
  bool DoBlasTbsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  uint64_t k, const DeviceMemory<std::complex<double>> &a,     \
                  int lda, DeviceMemory<std::complex<double>> *x, int incx)    \
      override;                                                                \
  bool DoBlasTpmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<float> &ap, DeviceMemory<float> *x,       \
                  int incx) override;                                          \
  bool DoBlasTpmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<double> &ap, DeviceMemory<double> *x,     \
                  int incx) override;                                          \
  bool DoBlasTpmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<float>> &ap,                 \
                  DeviceMemory<std::complex<float>> *x, int incx) override;    \
  bool DoBlasTpmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<double>> &ap,                \
                  DeviceMemory<std::complex<double>> *x, int incx) override;   \
  bool DoBlasTpsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<float> &ap, DeviceMemory<float> *x,       \
                  int incx) override;                                          \
  bool DoBlasTpsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<double> &ap, DeviceMemory<double> *x,     \
                  int incx) override;                                          \
  bool DoBlasTpsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<float>> &ap,                 \
                  DeviceMemory<std::complex<float>> *x, int incx) override;    \
  bool DoBlasTpsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<double>> &ap,                \
                  DeviceMemory<std::complex<double>> *x, int incx) override;   \
  bool DoBlasTrmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<float> &a, int lda,                       \
                  DeviceMemory<float> *x, int incx) override;                  \
  bool DoBlasTrmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<double> &a, int lda,                      \
                  DeviceMemory<double> *x, int incx) override;                 \
  bool DoBlasTrmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  DeviceMemory<std::complex<float>> *x, int incx) override;    \
  bool DoBlasTrmv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  DeviceMemory<std::complex<double>> *x, int incx) override;   \
  bool DoBlasTrsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<float> &a, int lda,                       \
                  DeviceMemory<float> *x, int incx) override;                  \
  bool DoBlasTrsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<double> &a, int lda,                      \
                  DeviceMemory<double> *x, int incx) override;                 \
  bool DoBlasTrsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  DeviceMemory<std::complex<float>> *x, int incx) override;    \
  bool DoBlasTrsv(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, blas::Diagonal diag, uint64_t n,      \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  DeviceMemory<std::complex<double>> *x, int incx) override;   \
  port::Status DoBlasGemm(                                                     \
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
  port::Status DoBlasGemmWithAlgorithm(                                        \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, const void *alpha,                       \
      const DeviceMemoryBase &a, blas::DataType type_a, int lda,               \
      const DeviceMemoryBase &b, blas::DataType type_b, int ldb,               \
      const void *beta, DeviceMemoryBase *c, blas::DataType type_c, int ldc,   \
      blas::ComputationType computation_type, blas::AlgorithmType algorithm,   \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha,                             \
      const port::ArraySlice<DeviceMemory<Eigen::half> *> &a, int lda,         \
      const port::ArraySlice<DeviceMemory<Eigen::half> *> &b, int ldb,         \
      float beta, const port::ArraySlice<DeviceMemory<Eigen::half> *> &c,      \
      int ldc, int batch_count, ScratchAllocator *scratch_allocator) override; \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, float alpha,                             \
      const port::ArraySlice<DeviceMemory<float> *> &a, int lda,               \
      const port::ArraySlice<DeviceMemory<float> *> &b, int ldb, float beta,   \
      const port::ArraySlice<DeviceMemory<float> *> &c, int ldc,               \
      int batch_count, ScratchAllocator *scratch_allocator) override;          \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, double alpha,                            \
      const port::ArraySlice<DeviceMemory<double> *> &a, int lda,              \
      const port::ArraySlice<DeviceMemory<double> *> &b, int ldb, double beta, \
      const port::ArraySlice<DeviceMemory<double> *> &c, int ldc,              \
      int batch_count, ScratchAllocator *scratch_allocator) override;          \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, std::complex<float> alpha,               \
      const port::ArraySlice<DeviceMemory<std::complex<float>> *> &a, int lda, \
      const port::ArraySlice<DeviceMemory<std::complex<float>> *> &b, int ldb, \
      std::complex<float> beta,                                                \
      const port::ArraySlice<DeviceMemory<std::complex<float>> *> &c, int ldc, \
      int batch_count, ScratchAllocator *scratch_allocator) override;          \
  bool DoBlasGemmBatched(                                                      \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, std::complex<double> alpha,              \
      const port::ArraySlice<DeviceMemory<std::complex<double>> *> &a,         \
      int lda,                                                                 \
      const port::ArraySlice<DeviceMemory<std::complex<double>> *> &b,         \
      int ldb, std::complex<double> beta,                                      \
      const port::ArraySlice<DeviceMemory<std::complex<double>> *> &c,         \
      int ldc, int batch_count, ScratchAllocator *scratch_allocator) override; \
  port::Status DoBlasGemmStridedBatched(                                       \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, blas::DataType dtype, const void *alpha, \
      const DeviceMemoryBase &a, int lda, int64_t stride_a,                    \
      const DeviceMemoryBase &b, int ldb, int64_t stride_b, const void *beta,  \
      DeviceMemoryBase *c, int ldc, int64_t stride_c, int batch_count);        \
  port::Status DoBlasGemmStridedBatchedWithAlgorithm(                          \
      Stream *stream, blas::Transpose transa, blas::Transpose transb,          \
      uint64_t m, uint64 n, uint64 k, const void *alpha,                       \
      const DeviceMemoryBase &a, blas::DataType type_a, int lda,               \
      int64_t stride_a, const DeviceMemoryBase &b, blas::DataType type_b,      \
      int ldb, int64_t stride_b, const void *beta, DeviceMemoryBase *c,        \
      blas::DataType type_c, int ldc, int64_t stride_c, int batch_count,       \
      blas::ComputationType computation_type, blas::AlgorithmType algorithm,   \
      blas::ProfileResult *output_profile_result) override;                    \
  bool DoBlasHemm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  uint64_t m, uint64 n, std::complex<float> alpha,             \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  const DeviceMemory<std::complex<float>> &b, int ldb,         \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *c, int ldc) override;     \
  bool DoBlasHemm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  uint64_t m, uint64 n, std::complex<double> alpha,            \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  const DeviceMemory<std::complex<double>> &b, int ldb,        \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *c, int ldc) override;    \
  bool DoBlasHerk(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, uint64_t n, uint64 k, float alpha,    \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  float beta, DeviceMemory<std::complex<float>> *c, int ldc)   \
      override;                                                                \
  bool DoBlasHerk(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, uint64_t n, uint64 k, double alpha,   \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  double beta, DeviceMemory<std::complex<double>> *c, int ldc) \
      override;                                                                \
  bool DoBlasHer2k(                                                            \
      Stream *stream, blas::UpperLower uplo, blas::Transpose trans,            \
      uint64_t n, uint64_t k, std::complex<float> alpha,                       \
      const DeviceMemory<std::complex<float>> &a, int lda,                     \
      const DeviceMemory<std::complex<float>> &b, int ldb, float beta,         \
      DeviceMemory<std::complex<float>> *c, int ldc) override;                 \
  bool DoBlasHer2k(                                                            \
      Stream *stream, blas::UpperLower uplo, blas::Transpose trans,            \
      uint64_t n, uint64_t k, std::complex<double> alpha,                      \
      const DeviceMemory<std::complex<double>> &a, int lda,                    \
      const DeviceMemory<std::complex<double>> &b, int ldb, double beta,       \
      DeviceMemory<std::complex<double>> *c, int ldc) override;                \
  bool DoBlasSymm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  uint64_t m, uint64 n, float alpha,                           \
                  const DeviceMemory<float> &a, int lda,                       \
                  const DeviceMemory<float> &b, int ldb, float beta,           \
                  DeviceMemory<float> *c, int ldc) override;                   \
  bool DoBlasSymm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  uint64_t m, uint64 n, double alpha,                          \
                  const DeviceMemory<double> &a, int lda,                      \
                  const DeviceMemory<double> &b, int ldb, double beta,         \
                  DeviceMemory<double> *c, int ldc) override;                  \
  bool DoBlasSymm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  uint64_t m, uint64 n, std::complex<float> alpha,             \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  const DeviceMemory<std::complex<float>> &b, int ldb,         \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *c, int ldc) override;     \
  bool DoBlasSymm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  uint64_t m, uint64 n, std::complex<double> alpha,            \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  const DeviceMemory<std::complex<double>> &b, int ldb,        \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *c, int ldc) override;    \
  bool DoBlasSyrk(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, uint64_t n, uint64 k, float alpha,    \
                  const DeviceMemory<float> &a, int lda, float beta,           \
                  DeviceMemory<float> *c, int ldc) override;                   \
  bool DoBlasSyrk(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, uint64_t n, uint64 k, double alpha,   \
                  const DeviceMemory<double> &a, int lda, double beta,         \
                  DeviceMemory<double> *c, int ldc) override;                  \
  bool DoBlasSyrk(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, uint64_t n, uint64 k,                 \
                  std::complex<float> alpha,                                   \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  std::complex<float> beta,                                    \
                  DeviceMemory<std::complex<float>> *c, int ldc) override;     \
  bool DoBlasSyrk(Stream *stream, blas::UpperLower uplo,                       \
                  blas::Transpose trans, uint64_t n, uint64 k,                 \
                  std::complex<double> alpha,                                  \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  std::complex<double> beta,                                   \
                  DeviceMemory<std::complex<double>> *c, int ldc) override;    \
  bool DoBlasSyr2k(Stream *stream, blas::UpperLower uplo,                      \
                   blas::Transpose trans, uint64_t n, uint64 k, float alpha,   \
                   const DeviceMemory<float> &a, int lda,                      \
                   const DeviceMemory<float> &b, int ldb, float beta,          \
                   DeviceMemory<float> *c, int ldc) override;                  \
  bool DoBlasSyr2k(Stream *stream, blas::UpperLower uplo,                      \
                   blas::Transpose trans, uint64_t n, uint64 k, double alpha,  \
                   const DeviceMemory<double> &a, int lda,                     \
                   const DeviceMemory<double> &b, int ldb, double beta,        \
                   DeviceMemory<double> *c, int ldc) override;                 \
  bool DoBlasSyr2k(Stream *stream, blas::UpperLower uplo,                      \
                   blas::Transpose trans, uint64_t n, uint64 k,                \
                   std::complex<float> alpha,                                  \
                   const DeviceMemory<std::complex<float>> &a, int lda,        \
                   const DeviceMemory<std::complex<float>> &b, int ldb,        \
                   std::complex<float> beta,                                   \
                   DeviceMemory<std::complex<float>> *c, int ldc) override;    \
  bool DoBlasSyr2k(Stream *stream, blas::UpperLower uplo,                      \
                   blas::Transpose trans, uint64_t n, uint64 k,                \
                   std::complex<double> alpha,                                 \
                   const DeviceMemory<std::complex<double>> &a, int lda,       \
                   const DeviceMemory<std::complex<double>> &b, int ldb,       \
                   std::complex<double> beta,                                  \
                   DeviceMemory<std::complex<double>> *c, int ldc) override;   \
  bool DoBlasTrmm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, float alpha, const DeviceMemory<float> &a,       \
                  int lda, DeviceMemory<float> *b, int ldb) override;          \
  bool DoBlasTrmm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, double alpha, const DeviceMemory<double> &a,     \
                  int lda, DeviceMemory<double> *b, int ldb) override;         \
  bool DoBlasTrmm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, std::complex<float> alpha,                       \
                  const DeviceMemory<std::complex<float>> &a, int lda,         \
                  DeviceMemory<std::complex<float>> *b, int ldb) override;     \
  bool DoBlasTrmm(Stream *stream, blas::Side side, blas::UpperLower uplo,      \
                  blas::Transpose transa, blas::Diagonal diag, uint64_t m,     \
                  uint64_t n, std::complex<double> alpha,                      \
                  const DeviceMemory<std::complex<double>> &a, int lda,        \
                  DeviceMemory<std::complex<double>> *b, int ldb) override;    \
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
  port::Status GetVersion(std::string *version) override;









#define REGISTER_FILE_SYSTEM(scheme, factory)                             \
  REGISTER_FILE_SYSTEM_ENV(::tensorflow::Env::Default(), scheme, factory, \
                           false);
#define REGISTER_FILE_SYSTEM_ENV(env, scheme, factory, modular) \
  REGISTER_FILE_SYSTEM_UNIQ_HELPER(__COUNTER__, env, scheme, factory, modular)
#define REGISTER_FILE_SYSTEM_UNIQ(ctr, env, scheme, factory, modular)        \
  static ::tensorflow::register_file_system::Register<factory>               \
      register_ff##ctr TF_ATTRIBUTE_UNUSED =                                 \
          ::tensorflow::register_file_system::Register<factory>(env, scheme, \
                                                                modular)
#define REGISTER_FILE_SYSTEM_UNIQ_HELPER(ctr, env, scheme, factory, modular) \
  REGISTER_FILE_SYSTEM_UNIQ(ctr, env, scheme, factory, modular)
#define REGISTER_LEGACY_FILE_SYSTEM(scheme, factory) \
  REGISTER_FILE_SYSTEM_ENV(::tensorflow::Env::Default(), scheme, factory, true);


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
        STATUS.SetPayload(PAYLOAD_KEY, PAYLOAD_VALUE);                         \
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
  lhs = std::move(statusor.ValueOrDie())

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
















#define pequal(a, b)   \
  _mm512_castsi512_ps( \
      _mm512_maskz_set1_epi32(_mm512_cmp_ps_mask(a, b, _CMP_EQ_UQ), -1))
#define psel(a, b, false_mask)                        \
  _mm512_castsi512_ps(_mm512_ternarylogic_epi32(      \
      _mm512_castps_si512(a), _mm512_castps_si512(b), \
      _mm512_castps_si512(false_mask), 0xd8))


#define TF_CALL_ALL_TYPES(m) \
  TF_CALL_POD_TYPES(m) TF_CALL_tstring(m) TF_CALL_resource(m) TF_CALL_variant(m)
#define TF_CALL_COMPLEX_TYPES(m) TF_CALL_complex64(m) TF_CALL_complex128(m)
#define TF_CALL_FLOAT_TYPES(m) \
  TF_CALL_half(m) TF_CALL_bfloat16(m) TF_CALL_float(m) TF_CALL_double(m)
#define TF_CALL_GPU_ALL_TYPES(m) \
  TF_CALL_GPU_NUMBER_TYPES(m) TF_CALL_COMPLEX_TYPES(m) TF_CALL_bool(m)
#define TF_CALL_GPU_NUMBER_TYPES(m) \
  TF_CALL_half(m) TF_CALL_float(m) TF_CALL_double(m)
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







#define NDIM_CASE(NDIMS)                                                       \
  case NDIMS: {                                                                \
    static_cast<CHILD*>(this)->template Operate<NDIMS>(context, a, b, output); \
    break;                                                                     \
  }



