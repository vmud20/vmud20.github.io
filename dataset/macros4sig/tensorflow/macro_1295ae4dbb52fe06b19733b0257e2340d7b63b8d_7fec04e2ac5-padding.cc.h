



#include<type_traits>
#include<vector>




#include<assert.h>

#include<unordered_map>



#include<atomic>
#include<utility>
#include<set>
#include<string>
#include<stdint.h>




#include<memory>
#include<cstddef>


#include<cstdint>


#include<iosfwd>

#include<functional>

#include<limits>


#include<limits.h>

#include<algorithm>




#include<string.h>

#include<array>

#include<stdlib.h>

#include<complex>

#include<sstream>

#include<ostream>

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






#define TF_TSTRING_LITTLE_ENDIAN 1
#define TF_le32toh(x) x


#define TF_CORD_SUPPORT 1
















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




#define TF_CHECK_OK(val) TF_DO_CHECK_OK(val, FATAL)
#define TF_DCHECK_OK(val) TF_CHECK_OK(val)
#define TF_DO_CHECK_OK(val, level)                          \
  while (auto* _result = ::tsl::TfCheckOpHelper(val, #val)) \
  LOG(level) << *(_result)
#define TF_QCHECK_OK(val) TF_DO_CHECK_OK(val, QFATAL)

#define TF_INTERNAL_HAVE_BUILTIN_LINE_FILE 1


#define TF_RET_CHECK(condition)                                      \
  while (ABSL_PREDICT_FALSE(!(condition)))                           \
  return xla::status_macros::MakeErrorStream("__FILE__", "__LINE__",     \
                                             ::tsl::error::INTERNAL) \
      .with_log_stack_trace()                                        \
      .add_ret_check_failure(#condition)


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




