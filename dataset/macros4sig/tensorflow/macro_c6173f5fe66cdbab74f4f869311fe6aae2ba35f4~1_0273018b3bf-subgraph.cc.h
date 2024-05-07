#include<string>
#include<stdarg.h>

#include<cstring>
#include<algorithm>

#include<stdint.h>
#include<vector>
#include<memory>
#include<cstdint>
#include<utility>

#include<iterator>


#include<unordered_map>
#include<cstdarg>
#include<cstdlib>

#include<cstdio>
#include<initializer_list>

#include<stddef.h>

#include<map>


#include<stdbool.h>



#define TF_LITE_ENSURE(context, a)                                      \
  do {                                                                  \
    if (!(a)) {                                                         \
      TF_LITE_KERNEL_LOG((context), "%s:%d %s was not true.", "__FILE__", \
                         "__LINE__", #a);                                 \
      return kTfLiteError;                                              \
    }                                                                   \
  } while (0)
#define TF_LITE_ENSURE_EQ(context, a, b)                                   \
  do {                                                                     \
    if ((a) != (b)) {                                                      \
      TF_LITE_KERNEL_LOG((context), "%s:%d %s != %s (%d != %d)", "__FILE__", \
                         "__LINE__", #a, #b, (a), (b));                      \
      return kTfLiteError;                                                 \
    }                                                                      \
  } while (0)
#define TF_LITE_ENSURE_MSG(context, value, msg)        \
  do {                                                 \
    if (!(value)) {                                    \
      TF_LITE_KERNEL_LOG((context), "__FILE__" " " msg); \
      return kTfLiteError;                             \
    }                                                  \
  } while (0)
#define TF_LITE_ENSURE_NEAR(context, a, b, epsilon)                          \
  do {                                                                       \
    auto delta = ((a) > (b)) ? ((a) - (b)) : ((b) - (a));                    \
    if (delta > epsilon) {                                                   \
      TF_LITE_KERNEL_LOG((context), "%s:%d %s not near %s (%f != %f)",       \
                         "__FILE__", "__LINE__", #a, #b, static_cast<double>(a), \
                         static_cast<double>(b));                            \
      return kTfLiteError;                                                   \
    }                                                                        \
  } while (0)
#define TF_LITE_ENSURE_OK(context, status) \
  do {                                     \
    const TfLiteStatus s = (status);       \
    if ((s) != kTfLiteOk) {                \
      return s;                            \
    }                                      \
  } while (0)
#define TF_LITE_ENSURE_STATUS(a) \
  do {                           \
    const TfLiteStatus s = (a);  \
    if (s != kTfLiteOk) {        \
      return s;                  \
    }                            \
  } while (0)
#define TF_LITE_ENSURE_TYPES_EQ(context, a, b)                             \
  do {                                                                     \
    if ((a) != (b)) {                                                      \
      TF_LITE_KERNEL_LOG((context), "%s:%d %s != %s (%s != %s)", "__FILE__", \
                         "__LINE__", #a, #b, TfLiteTypeGetName(a),           \
                         TfLiteTypeGetName(b));                            \
      return kTfLiteError;                                                 \
    }                                                                      \
  } while (0)
#define TF_LITE_KERNEL_LOG(context, ...)            \
  do {                                              \
    (context)->ReportError((context), __VA_ARGS__); \
  } while (false)
#define TF_LITE_MAYBE_KERNEL_LOG(context, ...)        \
  do {                                                \
    if ((context) != nullptr) {                       \
      (context)->ReportError((context), __VA_ARGS__); \
    }                                                 \
  } while (false)
#define kTfLiteOptionalTensor (-1)




#define TFLITE_LOG TFLITE_LOG_PROD
#define TFLITE_LOG_ONCE TFLITE_LOG_PROD_ONCE
#define TFLITE_LOG_PROD(severity, format, ...) \
  tflite::logging_internal::MinimalLogger::Log(severity, format, ##__VA_ARGS__);
#define TFLITE_LOG_PROD_ONCE(severity, format, ...)    \
  do {                                                 \
    static const bool s_logged = [&] {                 \
      TFLITE_LOG_PROD(severity, format, ##__VA_ARGS__) \
      return true;                                     \
    }();                                               \
    (void)s_logged;                                    \
  } while (false);




#define TFLITE_ATTRIBUTE_WEAK __attribute__((weak))
#define TFLITE_EXPECT_FALSE(cond) __builtin_expect(cond, false)
#define TFLITE_EXPECT_TRUE(cond) __builtin_expect(!!(cond), true)
#define TFLITE_HAS_ATTRIBUTE(x) __has_attribute(x)
#define TFLITE_HAS_ATTRIBUTE_WEAK 1
#define TFLITE_HAS_BUILTIN(x) __has_builtin(x)


#define TFLITE_ADD_RUNTIME_INSTRUMENTATION_EVENT(                          \
    profiler, tag, event_metadata1, event_metadata2)                       \
  do {                                                                     \
    if (profiler) {                                                        \
      const auto handle = profiler->BeginEvent(                            \
          tag, Profiler::EventType::GENERAL_RUNTIME_INSTRUMENTATION_EVENT, \
          event_metadata1, event_metadata2);                               \
      profiler->EndEvent(handle);                                          \
    }                                                                      \
  } while (false);
#define TFLITE_SCOPED_DELEGATE_OPERATOR_PROFILE(profiler, tag, node_index) \
  tflite::ScopedDelegateOperatorProfile TFLITE_VARNAME_UNIQ(               \
      _profile_, __COUNTER__)((profiler), (tag), (node_index))
#define TFLITE_SCOPED_TAGGED_DEFAULT_PROFILE(profiler, tag)          \
  tflite::ScopedProfile TFLITE_VARNAME_UNIQ(_profile_, __COUNTER__)( \
      (profiler), (tag))
#define TFLITE_SCOPED_TAGGED_OPERATOR_PROFILE(profiler, tag, node_index)     \
  tflite::ScopedOperatorProfile TFLITE_VARNAME_UNIQ(_profile_, __COUNTER__)( \
      (profiler), (tag), (node_index))
#define TFLITE_VARNAME_UNIQ(name, ctr) TFLITE_VARNAME_UNIQ_IMPL(name, ctr)
#define TFLITE_VARNAME_UNIQ_IMPL(name, ctr) name##ctr

#define TF_LITE_REPORT_ERROR(reporter, ...)                             \
  do {                                                                  \
    static_cast<tflite::ErrorReporter*>(reporter)->Report(__VA_ARGS__); \
  } while (false)






