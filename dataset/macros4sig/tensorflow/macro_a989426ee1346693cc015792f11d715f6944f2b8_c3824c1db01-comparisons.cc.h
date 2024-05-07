

#include<iterator>

#include<cstring>

#include<sys/types.h>
#include<stdbool.h>
#include<string>

#include<functional>
#include<initializer_list>

#include<type_traits>
#include<cstdint>

#include<algorithm>


#include<limits.h>
#include<cstdio>
#include<cstdlib>
#include<stdint.h>

#include<memory>

#include<vector>



#include<stddef.h>

#include<limits>

#include<cmath>





#include<cstddef>



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

#define TFLITE_ABORT abort()
#define TFLITE_ASSERT_FALSE (static_cast<void>(0))
#define TF_LITE_ASSERT(x)        \
  do {                           \
    if (!(x)) TF_LITE_FATAL(#x); \
  } while (0)
#define TF_LITE_ASSERT_EQ(x, y)                            \
  do {                                                     \
    if ((x) != (y)) TF_LITE_FATAL(#x " didn't equal " #y); \
  } while (0)
#define TF_LITE_FATAL(msg)          \
  do {                              \
    fprintf(stderr, "%s\n", (msg)); \
    TFLITE_ABORT;                   \
  } while (0)
#define TF_LITE_UNSUPPORTED_TYPE(context, type, op_name)                    \
  do {                                                                      \
    TF_LITE_KERNEL_LOG((context), "%s:%d Type %s is unsupported by op %s.", \
                       "__FILE__", "__LINE__", TfLiteTypeGetName(type),         \
                       (op_name));                                          \
    return kTfLiteError;                                                    \
  } while (0)








#define NEON_OR_PORTABLE(funcname, ...) Neon##funcname(__VA_ARGS__)


#define DECLARE_STD_GLOBAL_SWITCH1(tf_name, std_name) \
  template <class T>                                  \
  inline T tf_name(const T x) {                       \
    return TF_LITE_GLOBAL_STD_PREFIX::std_name(x);    \
  }







#define TFLITE_COMPARISON_OP(name)                                             \
  inline void name(const ComparisonParams& op_params,                          \
                   const RuntimeShape& input1_shape, const float* input1_data, \
                   const RuntimeShape& input2_shape, const float* input2_data, \
                   const RuntimeShape& output_shape, bool* output_data) {      \
    Comparison<name##Fn>(op_params, input1_shape, input1_data, input2_shape,   \
                         input2_data, output_shape, output_data);              \
  }                                                                            \
  template <typename T>                                                        \
  inline void name##NoScaling(                                                 \
      const ComparisonParams& op_params, const RuntimeShape& input1_shape,     \
      const T* input1_data, const RuntimeShape& input2_shape,                  \
      const T* input2_data, const RuntimeShape& output_shape,                  \
      bool* output_data) {                                                     \
    ComparisonImpl<T, name##Fn>(op_params, input1_shape, input1_data,          \
                                input2_shape, input2_data, output_shape,       \
                                output_data);                                  \
  }                                                                            \
  template <typename T>                                                        \
  inline void name##WithScaling(                                               \
      const ComparisonParams& op_params, const RuntimeShape& input1_shape,     \
      const T* input1_data, const RuntimeShape& input2_shape,                  \
      const T* input2_data, const RuntimeShape& output_shape,                  \
      bool* output_data) {                                                     \
    ComparisonWithScaling<T, name##Fn>(op_params, input1_shape, input1_data,   \
                                       input2_shape, input2_data,              \
                                       output_shape, output_data);             \
  }                                                                            \
  template <typename T>                                                        \
  inline void Broadcast4DSlow##name##NoScaling(                                \
      const ComparisonParams& op_params, const RuntimeShape& input1_shape,     \
      const T* input1_data, const RuntimeShape& input2_shape,                  \
      const T* input2_data, const RuntimeShape& output_shape,                  \
      bool* output_data) {                                                     \
    BroadcastComparison4DSlowImpl<T, name##Fn>(                                \
        op_params, input1_shape, input1_data, input2_shape, input2_data,       \
        output_shape, output_data);                                            \
  }                                                                            \
  inline void Broadcast4DSlow##name(                                           \
      const ComparisonParams& op_params, const RuntimeShape& input1_shape,     \
      const float* input1_data, const RuntimeShape& input2_shape,              \
      const float* input2_data, const RuntimeShape& output_shape,              \
      bool* output_data) {                                                     \
    BroadcastComparison4DSlow<name##Fn>(op_params, input1_shape, input1_data,  \
                                        input2_shape, input2_data,             \
                                        output_shape, output_data);            \
  }                                                                            \
  template <typename T>                                                        \
  inline void Broadcast4DSlow##name##WithScaling(                              \
      const ComparisonParams& op_params, const RuntimeShape& input1_shape,     \
      const T* input1_data, const RuntimeShape& input2_shape,                  \
      const T* input2_data, const RuntimeShape& output_shape,                  \
      bool* output_data) {                                                     \
    BroadcastComparison4DSlowWithScaling<T, name##Fn>(                         \
        op_params, input1_shape, input1_data, input2_shape, input2_data,       \
        output_shape, output_data);                                            \
  }














































#define __restrict__ __restrict



