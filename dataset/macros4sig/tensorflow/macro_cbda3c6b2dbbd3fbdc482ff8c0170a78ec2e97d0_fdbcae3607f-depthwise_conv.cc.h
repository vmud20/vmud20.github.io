#include<limits>
#include<stddef.h>
#include<cstdlib>


#include<type_traits>



#include<cassert>

#include<functional>

#include<initializer_list>
#include<cstdint>


#include<cmath>








#include<assert.h>
#include<string.h>
#include<limits.h>
#include<stdbool.h>


#include<memory>


#include<vector>


#include<cstdio>




#include<utility>


#include<sys/types.h>





#include<cstddef>



#include<string>

#include<x86intrin.h>
#include<cstring>


#include<stdint.h>
#include<algorithm>




#include<tuple>



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


#define TFLITE_RESHAPE_PARAMS_MAX_DIMENSION_COUNT 8

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




#define __restrict__ __restrict









#define NEON_OR_PORTABLE(funcname, ...) Neon##funcname(__VA_ARGS__)


#define DECLARE_STD_GLOBAL_SWITCH1(tf_name, std_name) \
  template <class T>                                  \
  inline T tf_name(const T x) {                       \
    return TF_LITE_GLOBAL_STD_PREFIX::std_name(x);    \
  }






#define TFMINI_USE_DEPTHWISECONV_KERNEL(ALLOW_STRIDED, FIXED_INPUT_DEPTH, \
                                        FIXED_DEPTH_MULTIPLIER)           \
  if (!row_accum_func && (stride_width == 1 || ALLOW_STRIDED) &&          \
      (input_depth == FIXED_INPUT_DEPTH || FIXED_INPUT_DEPTH == 0) &&     \
      depth_multiplier == FIXED_DEPTH_MULTIPLIER) {                       \
    row_accum_func =                                                      \
        QuantizedDepthwiseConvAccumRow<ALLOW_STRIDED, FIXED_INPUT_DEPTH,  \
                                       FIXED_DEPTH_MULTIPLIER>;           \
  }
#define DEPTHWISECONV_LABEL_DEPTH_8_AFTER_LOOP "2"
#define DEPTHWISECONV_LABEL_DEPTH_8_LOOP "1"
#define DEPTHWISECONV_LABEL_HEIGHT_1 "7"
#define DEPTHWISECONV_LABEL_HEIGHT_1_END "11"
#define DEPTHWISECONV_LABEL_HEIGHT_1_WIDTH_1_LEFTOVER "9"
#define DEPTHWISECONV_LABEL_HEIGHT_1_WIDTH_2_LEFTOVER "10"
#define DEPTHWISECONV_LABEL_HEIGHT_1_WIDTH_2_LOOP "8"
#define DEPTHWISECONV_LABEL_HEIGHT_2_AFTER_LOOP "6"
#define DEPTHWISECONV_LABEL_HEIGHT_2_LOOP "1"
#define DEPTHWISECONV_LABEL_HEIGHT_2_WIDTH_1_LEFTOVER "3"
#define DEPTHWISECONV_LABEL_HEIGHT_2_WIDTH_2_AFTER_LOOP "5"
#define DEPTHWISECONV_LABEL_HEIGHT_2_WIDTH_2_LEFTOVER "4"
#define DEPTHWISECONV_LABEL_HEIGHT_2_WIDTH_2_LOOP "2"
#define OFFSET_FILTER_ROW_SIZE 32
#define OFFSET_FLOAT_OUTPUT_ACTIVATION_MAX 96
#define OFFSET_FLOAT_OUTPUT_ACTIVATION_MIN 92
#define OFFSET_INPUT_DEPTH 0
#define OFFSET_INPUT_HEIGHT 72
#define OFFSET_INPUT_OFFSET 40
#define OFFSET_INPUT_ROW_SIZE 8
#define OFFSET_INPUT_WIDTH 68
#define OFFSET_OUTPUT_ACTIVATION_MAX 60
#define OFFSET_OUTPUT_ACTIVATION_MIN 56
#define OFFSET_OUTPUT_DEPTH 16
#define OFFSET_OUTPUT_HEIGHT 88
#define OFFSET_OUTPUT_MULTIPLIER 52
#define OFFSET_OUTPUT_OFFSET 44
#define OFFSET_OUTPUT_RIGHT_SHIFT 64
#define OFFSET_OUTPUT_ROW_SIZE 24
#define OFFSET_OUTPUT_WIDTH 84
#define OFFSET_STRIDE_HEIGHT 80
#define OFFSET_STRIDE_WIDTH 76
#define STR(s) STR_UNEXPANDED(s)
#define STR_UNEXPANDED(s) #s




#define AVGPOOL_DIVIDING_BY(FILTER_COUNT)                               \
  if (filter_count == FILTER_COUNT) {                                   \
    for (; channel <= tranche_depth - 8; channel += 8) {                \
      uint16 buf[8];                                                    \
      for (int i = 0; i < 8; i++) {                                     \
        buf[i] = (acc[channel + i] + FILTER_COUNT / 2) / FILTER_COUNT;  \
      }                                                                 \
      uint8x8_t buf8 = vqmovn_u16(vld1q_u16(buf));                      \
      buf8 = vmin_u8(buf8, vdup_n_u8(params.quantized_activation_max)); \
      buf8 = vmax_u8(buf8, vdup_n_u8(params.quantized_activation_min)); \
      vst1_u8(output_ptr + channel, buf8);                              \
    }                                                                   \
  }

#define TFLITE_SHUFFLED_FC_ACCUM(B)                                           \
  local_accum0 = vmull_s8(vget_low_s8(weights0), vget_low_s8(input##B));      \
  local_accum1 = vmull_s8(vget_low_s8(weights1), vget_low_s8(input##B));      \
  local_accum2 = vmull_s8(vget_low_s8(weights2), vget_low_s8(input##B));      \
  local_accum3 = vmull_s8(vget_low_s8(weights3), vget_low_s8(input##B));      \
  local_accum0 =                                                              \
      vmlal_s8(local_accum0, vget_high_s8(weights0), vget_high_s8(input##B)); \
  local_accum1 =                                                              \
      vmlal_s8(local_accum1, vget_high_s8(weights1), vget_high_s8(input##B)); \
  local_accum2 =                                                              \
      vmlal_s8(local_accum2, vget_high_s8(weights2), vget_high_s8(input##B)); \
  local_accum3 =                                                              \
      vmlal_s8(local_accum3, vget_high_s8(weights3), vget_high_s8(input##B)); \
  row_accum0##B = vpadalq_s16(row_accum0##B, local_accum0);                   \
  row_accum1##B = vpadalq_s16(row_accum1##B, local_accum1);                   \
  row_accum2##B = vpadalq_s16(row_accum2##B, local_accum2);                   \
  row_accum3##B = vpadalq_s16(row_accum3##B, local_accum3);
#define TFLITE_SHUFFLED_FC_STORE(B)                                           \
  {                                                                           \
    int32x2_t pairwise_reduced_acc_0, pairwise_reduced_acc_1,                 \
        pairwise_reduced_acc_2, pairwise_reduced_acc_3;                       \
    pairwise_reduced_acc_0 =                                                  \
        vpadd_s32(vget_low_s32(row_accum0##B), vget_high_s32(row_accum0##B)); \
    pairwise_reduced_acc_1 =                                                  \
        vpadd_s32(vget_low_s32(row_accum1##B), vget_high_s32(row_accum1##B)); \
    pairwise_reduced_acc_2 =                                                  \
        vpadd_s32(vget_low_s32(row_accum2##B), vget_high_s32(row_accum2##B)); \
    pairwise_reduced_acc_3 =                                                  \
        vpadd_s32(vget_low_s32(row_accum3##B), vget_high_s32(row_accum3##B)); \
    const int32x2_t reduced_lo =                                              \
        vpadd_s32(pairwise_reduced_acc_0, pairwise_reduced_acc_1);            \
    const int32x2_t reduced_hi =                                              \
        vpadd_s32(pairwise_reduced_acc_2, pairwise_reduced_acc_3);            \
    int32x4_t reduced = vcombine_s32(reduced_lo, reduced_hi);                 \
    int32x4_t bias_vec = vld1q_s32(bias_data + c);                            \
    reduced = vaddq_s32(reduced, bias_vec);                                   \
    reduced = vshlq_s32(reduced, vdupq_n_s32(left_shift));                    \
    reduced = vqrdmulhq_n_s32(reduced, output_multiplier);                    \
    using gemmlowp::RoundingDivideByPOT;                                      \
    reduced = RoundingDivideByPOT(reduced, right_shift);                      \
    const int16x4_t res16 = vqmovn_s32(reduced);                              \
    vst1_s16(output_data + c + B * output_stride, res16);                     \
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


























































#define DC_KERNEL_MULT_1 "1"
#define DC_KERNEL_MULT_10 "10"
#define DC_KERNEL_MULT_11 "11"
#define DC_KERNEL_MULT_12 "12"
#define DC_KERNEL_MULT_13 "13"
#define DC_KERNEL_MULT_14 "14"
#define DC_KERNEL_MULT_15 "15"
#define DC_KERNEL_MULT_16 "16"
#define DC_KERNEL_MULT_17 "17"
#define DC_KERNEL_MULT_18 "18"
#define DC_KERNEL_MULT_19 "19"
#define DC_KERNEL_MULT_2 "2"
#define DC_KERNEL_MULT_20 "20"
#define DC_KERNEL_MULT_21 "21"
#define DC_KERNEL_MULT_22 "22"
#define DC_KERNEL_MULT_23 "23"
#define DC_KERNEL_MULT_3 "3"
#define DC_KERNEL_MULT_4 "4"
#define DC_KERNEL_MULT_5 "5"
#define DC_KERNEL_MULT_6 "6"
#define DC_KERNEL_MULT_7 "7"
#define DC_KERNEL_MULT_8 "8"
#define DC_KERNEL_MULT_9 "9"
#define DC_KERNEL_MULT_STRIDE_1 "1"
#define DC_KERNEL_MULT_STRIDE_10 "10"
#define DC_KERNEL_MULT_STRIDE_11 "11"
#define DC_KERNEL_MULT_STRIDE_12 "12"
#define DC_KERNEL_MULT_STRIDE_13 "13"
#define DC_KERNEL_MULT_STRIDE_14 "14"
#define DC_KERNEL_MULT_STRIDE_15 "15"
#define DC_KERNEL_MULT_STRIDE_16 "16"
#define DC_KERNEL_MULT_STRIDE_17 "17"
#define DC_KERNEL_MULT_STRIDE_18 "18"
#define DC_KERNEL_MULT_STRIDE_2 "2"
#define DC_KERNEL_MULT_STRIDE_3 "3"
#define DC_KERNEL_MULT_STRIDE_4 "4"
#define DC_KERNEL_MULT_STRIDE_5 "5"
#define DC_KERNEL_MULT_STRIDE_6 "6"
#define DC_KERNEL_MULT_STRIDE_7 "7"
#define DC_KERNEL_MULT_STRIDE_8 "8"
#define DC_KERNEL_MULT_STRIDE_9 "9"
#define DC_KERNEL_NO_MULT_1 "1"
#define DC_KERNEL_NO_MULT_10 "10"
#define DC_KERNEL_NO_MULT_11 "11"
#define DC_KERNEL_NO_MULT_12 "12"
#define DC_KERNEL_NO_MULT_13 "13"
#define DC_KERNEL_NO_MULT_14 "14"
#define DC_KERNEL_NO_MULT_15 "15"
#define DC_KERNEL_NO_MULT_16 "16"
#define DC_KERNEL_NO_MULT_17 "17"
#define DC_KERNEL_NO_MULT_18 "18"
#define DC_KERNEL_NO_MULT_19 "19"
#define DC_KERNEL_NO_MULT_2 "2"
#define DC_KERNEL_NO_MULT_20 "20"
#define DC_KERNEL_NO_MULT_21 "21"
#define DC_KERNEL_NO_MULT_22 "22"
#define DC_KERNEL_NO_MULT_23 "23"
#define DC_KERNEL_NO_MULT_24 "24"
#define DC_KERNEL_NO_MULT_25 "25"
#define DC_KERNEL_NO_MULT_26 "26"
#define DC_KERNEL_NO_MULT_27 "27"
#define DC_KERNEL_NO_MULT_28 "28"
#define DC_KERNEL_NO_MULT_29 "29"
#define DC_KERNEL_NO_MULT_3 "3"
#define DC_KERNEL_NO_MULT_30 "30"
#define DC_KERNEL_NO_MULT_31 "31"
#define DC_KERNEL_NO_MULT_32 "32"
#define DC_KERNEL_NO_MULT_33 "33"
#define DC_KERNEL_NO_MULT_34 "34"
#define DC_KERNEL_NO_MULT_35 "35"
#define DC_KERNEL_NO_MULT_4 "4"
#define DC_KERNEL_NO_MULT_5 "5"
#define DC_KERNEL_NO_MULT_6 "6"
#define DC_KERNEL_NO_MULT_7 "7"
#define DC_KERNEL_NO_MULT_8 "8"
#define DC_KERNEL_NO_MULT_9 "9"
#define DC_KERNEL_NO_MULT_STRIDE_1 "1"
#define DC_KERNEL_NO_MULT_STRIDE_10 "10"
#define DC_KERNEL_NO_MULT_STRIDE_11 "11"
#define DC_KERNEL_NO_MULT_STRIDE_12 "12"
#define DC_KERNEL_NO_MULT_STRIDE_13 "13"
#define DC_KERNEL_NO_MULT_STRIDE_14 "14"
#define DC_KERNEL_NO_MULT_STRIDE_15 "15"
#define DC_KERNEL_NO_MULT_STRIDE_16 "16"
#define DC_KERNEL_NO_MULT_STRIDE_17 "17"
#define DC_KERNEL_NO_MULT_STRIDE_18 "18"
#define DC_KERNEL_NO_MULT_STRIDE_19 "19"
#define DC_KERNEL_NO_MULT_STRIDE_2 "2"
#define DC_KERNEL_NO_MULT_STRIDE_20 "20"
#define DC_KERNEL_NO_MULT_STRIDE_21 "21"
#define DC_KERNEL_NO_MULT_STRIDE_22 "22"
#define DC_KERNEL_NO_MULT_STRIDE_23 "23"
#define DC_KERNEL_NO_MULT_STRIDE_24 "24"
#define DC_KERNEL_NO_MULT_STRIDE_25 "25"
#define DC_KERNEL_NO_MULT_STRIDE_26 "26"
#define DC_KERNEL_NO_MULT_STRIDE_27 "27"
#define DC_KERNEL_NO_MULT_STRIDE_28 "28"
#define DC_KERNEL_NO_MULT_STRIDE_29 "29"
#define DC_KERNEL_NO_MULT_STRIDE_3 "3"
#define DC_KERNEL_NO_MULT_STRIDE_30 "30"
#define DC_KERNEL_NO_MULT_STRIDE_31 "31"
#define DC_KERNEL_NO_MULT_STRIDE_32 "32"
#define DC_KERNEL_NO_MULT_STRIDE_33 "33"
#define DC_KERNEL_NO_MULT_STRIDE_34 "34"
#define DC_KERNEL_NO_MULT_STRIDE_35 "35"
#define DC_KERNEL_NO_MULT_STRIDE_4 "4"
#define DC_KERNEL_NO_MULT_STRIDE_5 "5"
#define DC_KERNEL_NO_MULT_STRIDE_6 "6"
#define DC_KERNEL_NO_MULT_STRIDE_7 "7"
#define DC_KERNEL_NO_MULT_STRIDE_8 "8"
#define DC_KERNEL_NO_MULT_STRIDE_9 "9"
#define DC_PER_DEPTH_1 "1"
#define DC_PER_DEPTH_2 "2"
#define DC_PER_DEPTH_3 "3"
#define DP_OFFSET_BIAS_INCREMENT DP_OFFSET_STRIDE + 4
#define DP_OFFSET_DEPTH_MICRO_REPEATS DP_OFFSET_PADDING_BOTTOM + 4
#define DP_OFFSET_FOUR_OVER_STRIDE DP_OFFSET_WORKSPACE_HEIGHT_STRIDE + 4
#define DP_OFFSET_HEIGHT_MACRO_COUNT 100
#define DP_OFFSET_INBOUND_BLOCK_HEIGHT DP_OFFSET_HEIGHT_MACRO_COUNT + 4
#define DP_OFFSET_INPUT_DEPTH 0
#define DP_OFFSET_INPUT_HEIGHT_STRIDE DP_OFFSET_OUTBOUND_BLOCK_HEIGHT + 4
#define DP_OFFSET_INPUT_OFFSET 24
#define DP_OFFSET_INPUT_WIDTH_MICRO_REPEATS \
  DP_OFFSET_INPUT_WIDTH_OVERALL_MICRO_REPEATS + 4
#define DP_OFFSET_INPUT_WIDTH_OVERALL_MICRO_REPEATS \
  DP_OFFSET_WIDTH_MACRO_COUNT + 4
#define DP_OFFSET_OUTBOUND_BLOCK_HEIGHT DP_OFFSET_INBOUND_BLOCK_HEIGHT + 4
#define DP_OFFSET_OUTPUT_DEPTH DP_OFFSET_INPUT_DEPTH + 8
#define DP_OFFSET_OUTPUT_HEIGHT_STRIDE DP_OFFSET_INPUT_HEIGHT_STRIDE + 4
#define DP_OFFSET_OUTPUT_MULTIPLIER DP_OFFSET_OUTPUT_OFFSET + 4
#define DP_OFFSET_OUTPUT_MULTPLIPLIER_PER_CHANNEL DP_OFFSET_FOUR_OVER_STRIDE + 4
#define DP_OFFSET_OUTPUT_OFFSET DP_OFFSET_INPUT_OFFSET + 4
#define DP_OFFSET_OUTPUT_RESIDUAL_WIDTH DP_OFFSET_OUTPUT_WIDTH_MICRO_REPEATS + 4
#define DP_OFFSET_OUTPUT_SHIFT DP_OFFSET_OUTPUT_MULTIPLIER + 4
#define DP_OFFSET_OUTPUT_SHIFT_PER_CHANNEL \
  DP_OFFSET_OUTPUT_MULTPLIPLIER_PER_CHANNEL + 8
#define DP_OFFSET_OUTPUT_WIDTH_MICRO_REPEATS \
  DP_OFFSET_OUTPUT_WIDTH_OVERALL_MICRO_REPEATS + 4
#define DP_OFFSET_OUTPUT_WIDTH_OVERALL_MICRO_REPEATS \
  DP_OFFSET_RESIDUAL_WIDTH + 4
#define DP_OFFSET_PADDING_BOTTOM DP_OFFSET_PADDING_TOP + 4
#define DP_OFFSET_PADDING_LEFT 48
#define DP_OFFSET_PADDING_RIGHT DP_OFFSET_PADDING_LEFT + 4
#define DP_OFFSET_PADDING_TOP DP_OFFSET_PADDING_RIGHT + 4
#define DP_OFFSET_QUANTIZED_ACTIVATION_MAX \
  DP_OFFSET_QUANTIZED_ACTIVATION_MIN + 4
#define DP_OFFSET_QUANTIZED_ACTIVATION_MIN DP_OFFSET_OUTPUT_SHIFT + 4
#define DP_OFFSET_RESIDUAL_WIDTH DP_OFFSET_INPUT_WIDTH_MICRO_REPEATS + 4
#define DP_OFFSET_STRIDE DP_OFFSET_OUTPUT_DEPTH + 8
#define DP_OFFSET_WIDTH_MACRO_COUNT 68
#define DP_OFFSET_WORKSPACE_HEIGHT_STRIDE DP_OFFSET_OUTPUT_HEIGHT_STRIDE + 4
#define DP_OFFSET_WORKSPACE_WIDTH_MICRO_REPEATS \
  DP_OFFSET_OUTPUT_RESIDUAL_WIDTH + 4
#define OFFSET_FILTER_OFFSET 48

#define vld1_lane_8x4(src, reg, lane_num)                                \
  vreinterpret_s8_s32(vld1_lane_s32(reinterpret_cast<const int32*>(src), \
                                    vreinterpret_s32_s8(reg), lane_num))
#define vld1q_dup_s8x4(src) vld1q_dup_s32(reinterpret_cast<const int32*>(src))
#define vld1q_lane_8x4(src, reg, lane_num) \
  vld1q_lane_s32(reinterpret_cast<const int32*>(src), reg, lane_num)
#define vld1q_lane_s8x8(src, reg, lane_num)                                  \
  vreinterpretq_s8_s64(vld1q_lane_s64(reinterpret_cast<const int64_t*>(src), \
                                      vreinterpretq_s64_s8(reg), lane_num))
#define vst1_lane_8x4(dst, reg, lane_num)                                  \
  TFLITE_DCHECK_EQ(reinterpret_cast<std::uintptr_t>(dst) % 4, 0);          \
  vst1_lane_s32(reinterpret_cast<int32_t*>(dst), vreinterpret_s32_s8(reg), \
                lane_num)
#define vst1q_lane_8x4(dst, reg, lane_num)                        \
  TFLITE_DCHECK_EQ(reinterpret_cast<std::uintptr_t>(dst) % 4, 0); \
  vst1q_lane_u32(reinterpret_cast<uint32_t*>(dst), reg, lane_num)



