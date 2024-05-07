#include<cstdio>
#include<stdbool.h>
#include<cstdint>
#include<algorithm>

#include<limits>



#include<stddef.h>
#include<initializer_list>
#include<cstdlib>
#include<cstring>
#include<stdint.h>



#define TFLITE_CHECK(condition) (condition) ? (void)0 : TFLITE_ABORT
#define TFLITE_CHECK_EQ(x, y) ((x) == (y)) ? (void)0 : TFLITE_ABORT
#define TFLITE_CHECK_GE(x, y) ((x) >= (y)) ? (void)0 : TFLITE_ABORT
#define TFLITE_CHECK_GT(x, y) ((x) > (y)) ? (void)0 : TFLITE_ABORT
#define TFLITE_CHECK_LE(x, y) ((x) <= (y)) ? (void)0 : TFLITE_ABORT
#define TFLITE_CHECK_LT(x, y) ((x) < (y)) ? (void)0 : TFLITE_ABORT
#define TFLITE_CHECK_NE(x, y) ((x) != (y)) ? (void)0 : TFLITE_ABORT
#define TFLITE_DCHECK(condition) (condition) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DCHECK_EQ(x, y) ((x) == (y)) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DCHECK_GE(x, y) ((x) >= (y)) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DCHECK_GT(x, y) ((x) > (y)) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DCHECK_LE(x, y) ((x) <= (y)) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DCHECK_LT(x, y) ((x) < (y)) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DCHECK_NE(x, y) ((x) != (y)) ? (void)0 : TFLITE_ASSERT_FALSE
#define TFLITE_DEPRECATED(message) __attribute__((deprecated(message)))
#define DEBUG_LOG(x) \
  do {               \
    DebugLog(x);     \
  } while (0)

#define TFLITE_ABORT InfiniteLoop();
#define TFLITE_ASSERT_FALSE (static_cast<void>(0))
#define TF_LITE_ASSERT(x)        \
  do {                           \
    if (!(x)) TF_LITE_FATAL(#x); \
  } while (0)
#define TF_LITE_ASSERT_EQ(x, y)                            \
  do {                                                     \
    if ((x) != (y)) TF_LITE_FATAL(#x " didn't equal " #y); \
  } while (0)
#define TF_LITE_FATAL(msg)  \
  do {                      \
    DEBUG_LOG(msg);         \
    DEBUG_LOG("\nFATAL\n"); \
    TFLITE_ABORT;           \
  } while (0)
#define TF_LITE_UNSUPPORTED_TYPE(context, type, op_name)                    \
  do {                                                                      \
    TF_LITE_KERNEL_LOG((context), "%s:%d Type %s is unsupported by op %s.", \
                       "__FILE__", "__LINE__", TfLiteTypeGetName(type),         \
                       (op_name));                                          \
    return kTfLiteError;                                                    \
  } while (0)


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



#define TFLITE_RESHAPE_PARAMS_MAX_DIMENSION_COUNT 8


