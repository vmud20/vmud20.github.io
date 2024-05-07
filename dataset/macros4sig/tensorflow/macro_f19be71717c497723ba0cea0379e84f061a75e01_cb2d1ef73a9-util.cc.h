#include<cstring>
#include<stdbool.h>
#include<stdint.h>
#include<complex>
#include<vector>
#include<algorithm>
#include<string>
#include<memory>


#include<stddef.h>
#include<initializer_list>


#define TFLITE_ATTRIBUTE_WEAK __attribute__((weak))
#define TFLITE_EXPECT_FALSE(cond) __builtin_expect(cond, false)
#define TFLITE_EXPECT_TRUE(cond) __builtin_expect(!!(cond), true)
#define TFLITE_HAS_ATTRIBUTE(x) __has_attribute(x)
#define TFLITE_HAS_ATTRIBUTE_WEAK 1
#define TFLITE_HAS_BUILTIN(x) __has_builtin(x)

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




