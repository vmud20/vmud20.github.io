

















namespace {








void ColMeanAndVariance(const uint8_t* input, const uint32_t rows, const uint32_t cols, float* mean, float* variance) {
  
  
  for (uint32_t col_offset = 0; col_offset < cols; col_offset += 16) {
    
    
    uint32x4_t sum[4] = {0};

    float nA = 0.0f;
    
    float32x4_t xA[4] = {0.0f};
    float32x4_t M2A[4] = {0.0f};

    const uint8_t* inp_ptr = input + col_offset;
    
    
    for (uint32_t row = 0; row < rows; row += 256) {
      
      uint32x4_t sub_sum[4] = {0};
      uint32x4_t sub_sq_sum[4] = {0};
      const uint32_t limit = std::min(rows, row + 256);
      const float nB = limit - row;
      for (uint32_t subrow = row; subrow < limit; ++subrow) {
        const uint8x16_t v = vld1q_u8(inp_ptr);
        inp_ptr += cols;

        const uint8x8_t v_high = vget_high_u8(v);
        const uint8x8_t v_low = vget_low_u8(v);

        const uint16x8_t v_high_u16 = vmovl_u8(v_high);
        const uint16x8_t v_low_u16 = vmovl_u8(v_low);

        const uint16x4_t v_high_high = vget_high_u16(v_high_u16);
        const uint16x4_t v_high_low = vget_low_u16(v_high_u16);
        const uint16x4_t v_low_high = vget_high_u16(v_low_u16);
        const uint16x4_t v_low_low = vget_low_u16(v_low_u16);

        sub_sum[0] = vaddw_u16(sub_sum[0], v_high_high);
        sub_sum[1] = vaddw_u16(sub_sum[1], v_high_low);
        sub_sum[2] = vaddw_u16(sub_sum[2], v_low_high);
        sub_sum[3] = vaddw_u16(sub_sum[3], v_low_low);

        sub_sq_sum[0] = vmlal_u16(sub_sq_sum[0], v_high_high, v_high_high);
        sub_sq_sum[1] = vmlal_u16(sub_sq_sum[1], v_high_low, v_high_low);
        sub_sq_sum[2] = vmlal_u16(sub_sq_sum[2], v_low_high, v_low_high);
        sub_sq_sum[3] = vmlal_u16(sub_sq_sum[3], v_low_low, v_low_low);
      }

      
      for (int i = 0; i < 4; ++i) {
        sum[i] = vaddq_u32(sum[i], sub_sum[i]);
        const float nX = nA + nB;
        
        const float32x4_t xB = vmulq_n_f32(vcvtq_f32_u32(sub_sum[i]), 1.0f / nB);

        
        const float32x4_t delta = vsubq_f32(xB, xA[i]);
        
        xA[i] = vmulq_n_f32( vaddq_f32(vmulq_n_f32(xA[i], nA), vmulq_n_f32(xB, nB)), 1.0f / nX);

        const float32x4_t sub_sum_f32 = vcvtq_f32_u32(sub_sum[i]);
        const float32x4_t sub_sum_sq = vmulq_f32(sub_sum_f32, sub_sum_f32);

        
        const float32x4_t M2B = vsubq_f32(vcvtq_f32_u32(sub_sq_sum[i]), vmulq_n_f32(sub_sum_sq, 1.0f / nB));
        const float32x4_t last_term = vmulq_n_f32(vmulq_f32(delta, delta), nA * nB / nX);
        
        M2A[i] = vaddq_f32(vaddq_f32(M2A[i], M2B), last_term);
      }
      nA += limit;
    }

    
    const float inv_rows = 1.0f / static_cast<float>(rows);
    vst1q_f32(mean + col_offset, vmulq_n_f32(vcvtq_f32_u32(sum[3]), inv_rows));
    vst1q_f32(mean + col_offset + 4, vmulq_n_f32(vcvtq_f32_u32(sum[2]), inv_rows));
    vst1q_f32(mean + col_offset + 8, vmulq_n_f32(vcvtq_f32_u32(sum[1]), inv_rows));
    vst1q_f32(mean + col_offset + 12, vmulq_n_f32(vcvtq_f32_u32(sum[0]), inv_rows));

    vst1q_f32(variance + col_offset, vmulq_n_f32(M2A[3], inv_rows));
    vst1q_f32(variance + col_offset + 4, vmulq_n_f32(M2A[2], inv_rows));
    vst1q_f32(variance + col_offset + 8, vmulq_n_f32(M2A[1], inv_rows));
    vst1q_f32(variance + col_offset + 12, vmulq_n_f32(M2A[0], inv_rows));
  }
}




void MinAndMax(const uint8_t* input, const uint32_t rows, const uint32_t cols, const float* mean_ptr, const float* variance_ptr, float variance_epsilon, float* minimum, float* maximum) {

  float v_maximum = std::numeric_limits<float>::min();
  float v_minimum = std::numeric_limits<float>::max();
  const float32x4_t eps = vdupq_n_f32(variance_epsilon);

  for (uint32_t col_offset = 0; col_offset < cols; col_offset += 16) {
    const float32x4_t mean[4] = {vld1q_f32(mean_ptr + col_offset), vld1q_f32(mean_ptr + col_offset + 4), vld1q_f32(mean_ptr + col_offset + 8), vld1q_f32(mean_ptr + col_offset + 12)};


    const float32x4_t variance[4] = {vld1q_f32(variance_ptr + col_offset), vld1q_f32(variance_ptr + col_offset + 4), vld1q_f32(variance_ptr + col_offset + 8), vld1q_f32(variance_ptr + col_offset + 12)};


    const float32x4_t inv_stddev[4] = {
        vrsqrteq_f32(vaddq_f32(variance[0], eps)), vrsqrteq_f32(vaddq_f32(variance[1], eps)), vrsqrteq_f32(vaddq_f32(variance[2], eps)), vrsqrteq_f32(vaddq_f32(variance[3], eps))};



    const uint8_t* inp_ptr = input + col_offset;
    for (uint32_t row = 0; row < rows; ++row) {
      const uint8x16_t v = vld1q_u8(inp_ptr);
      inp_ptr += cols;

      const uint16x8_t v_high = vmovl_u8(vget_high_u8(v));
      const uint16x8_t v_low = vmovl_u8(vget_low_u8(v));

      const float32x4_t v_float[4] = {
          vcvtq_f32_u32(vmovl_u16(vget_high_u16(v_high))), vcvtq_f32_u32(vmovl_u16(vget_low_u16(v_high))), vcvtq_f32_u32(vmovl_u16(vget_high_u16(v_low))), vcvtq_f32_u32(vmovl_u16(vget_low_u16(v_low)))};



      for (int i = 0; i < 4; ++i) {
        const float32x4_t normed = vmulq_f32(vsubq_f32(v_float[i], mean[i]), inv_stddev[i]);
        const float32x2_t high = vget_high_f32(normed);
        const float32x2_t low = vget_low_f32(normed);
        float32x2_t tmp_max = vpmax_f32(low, high);
        tmp_max = vpmax_f32(tmp_max, tmp_max);
        v_maximum = std::max(v_maximum, vget_lane_f32(tmp_max, 0));
        float32x2_t tmp_min = vpmin_f32(low, high);
        tmp_min = vpmin_f32(tmp_min, tmp_min);
        v_minimum = std::min(v_minimum, vget_lane_f32(tmp_min, 0));
      }
    }
  }
  *minimum = v_minimum;
  *maximum = v_maximum;
}



void InstanceNorm(const uint8_t* input, const uint32_t rows, const uint32_t cols, const float* mean_ptr, const float* variance_ptr, float variance_epsilon, float minimum, float maximum, uint8_t* output) {


  const float32x4_t eps = vdupq_n_f32(variance_epsilon);
  const float32x4_t out_min = vdupq_n_f32(minimum);
  const float out_scale = 255.0f / (maximum - minimum);

  for (uint32_t col_offset = 0; col_offset < cols; col_offset += 16) {
    const float32x4_t mean[4] = {vld1q_f32(mean_ptr + col_offset + 12), vld1q_f32(mean_ptr + col_offset + 8), vld1q_f32(mean_ptr + col_offset + 4), vld1q_f32(mean_ptr + col_offset)};


    const float32x4_t variance[4] = {vld1q_f32(variance_ptr + col_offset + 12), vld1q_f32(variance_ptr + col_offset + 8), vld1q_f32(variance_ptr + col_offset + 4), vld1q_f32(variance_ptr + col_offset)};


    const float32x4_t inv_stddev[4] = {
        vrsqrteq_f32(vaddq_f32(variance[0], eps)), vrsqrteq_f32(vaddq_f32(variance[1], eps)), vrsqrteq_f32(vaddq_f32(variance[2], eps)), vrsqrteq_f32(vaddq_f32(variance[3], eps))};


    const uint8_t* inp_ptr = input + col_offset;
    uint8_t* out_ptr = output + col_offset;
    for (uint32_t row = 0; row < rows; ++row) {
      const uint8x16_t v = vld1q_u8(inp_ptr);
      inp_ptr += cols;
      const uint16x8_t v_high = vmovl_u8(vget_high_u8(v));
      const uint16x8_t v_low = vmovl_u8(vget_low_u8(v));

      const float32x4_t v_float[4] = {
          vcvtq_f32_u32(vmovl_u16(vget_high_u16(v_high))), vcvtq_f32_u32(vmovl_u16(vget_low_u16(v_high))), vcvtq_f32_u32(vmovl_u16(vget_high_u16(v_low))), vcvtq_f32_u32(vmovl_u16(vget_low_u16(v_low)))};



      uint16x4_t normed_uint16[4];
      for (int i = 0; i < 4; ++i) {
        const float32x4_t normed = vmulq_f32(vsubq_f32(v_float[i], mean[i]), inv_stddev[i]);
        const int32x4_t normed_int32 = vcvtq_s32_f32(vmulq_n_f32(vsubq_f32(normed, out_min), out_scale));
        normed_uint16[i] = vqmovun_s32(normed_int32);
      }
      vst1_u8(out_ptr, vqmovn_u16(vcombine_u16(normed_uint16[3], normed_uint16[2])));
      vst1_u8(out_ptr + 8, vqmovn_u16(vcombine_u16(normed_uint16[1], normed_uint16[0])));
      out_ptr += cols;
    }
  }
}

}  


namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;

class QuantizedInstanceNorm : public OpKernel {
 public:
  explicit QuantizedInstanceNorm(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("variance_epsilon", &variance_epsilon_));
    OP_REQUIRES_OK(context, context->GetAttr("min_separation", &min_separation_));
    OP_REQUIRES_OK( context, context->GetAttr("output_range_given", &output_range_given_));
    if (output_range_given_) {
      OP_REQUIRES_OK(context, context->GetAttr("given_y_min", &given_y_min_));
      OP_REQUIRES_OK(context, context->GetAttr("given_y_max", &given_y_max_));
      OP_REQUIRES(context, given_y_min_ < given_y_max_, errors::InvalidArgument( "given_y_min must be less than given_y_max : ", given_y_min_, " >= ", given_y_max_));


    }
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);

    float input_min = context->input(1).flat<float>()(0);
    float input_max = context->input(2).flat<float>()(0);
    float input_scale = (input_max - input_min) / 255.0f;

    OP_REQUIRES(context, input_min < input_max, errors::InvalidArgument( "input_min must be less than input_max : ", input_min, " >= ", input_max));



    auto input_tensor = input.tensor<quint8, 4>();
    auto N = input_tensor.dimension(0);
    auto H = input_tensor.dimension(1);
    auto W = input_tensor.dimension(2);
    auto C = input_tensor.dimension(3);

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, input.shape(), &output));

    Tensor* output_min = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(1, {}, &output_min));
    Tensor* output_max = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(2, {}, &output_max));

    typedef TTypes<float>::Tensor::Index Index;

    const Eigen::IndexList<Eigen::type2index<1>, Eigen::type2index<2>> reduction_indices;
    Eigen::IndexList<Eigen::type2index<1>, Index, Index, Eigen::type2index<1>> broadcast_spec;
    broadcast_spec.set(1, H);
    broadcast_spec.set(2, W);
    Eigen::IndexList<Index, Eigen::type2index<1>, Eigen::type2index<1>, Index> expand_spec;
    expand_spec.set(0, N);
    expand_spec.set(3, C);

    Eigen::Tensor<float, 2, Eigen::RowMajor> float_mean(N, C);
    Eigen::Tensor<float, 2, Eigen::RowMajor> float_variance(N, C);


    if (N == 1 && (C % 16 == 0)) {
      VLOG(2) << "Calling optimized";
      ColMeanAndVariance(reinterpret_cast<const uint8_t*>(input_tensor.data()), H * W, C, float_mean.data(), float_variance.data());

      float minimum = given_y_min_, maximum = given_y_max_;
      if (!output_range_given_) {
        MinAndMax(reinterpret_cast<const uint8_t*>(input_tensor.data()), H * W, C, float_mean.data(), float_variance.data(), variance_epsilon_, &minimum, &maximum);

      }

      if (maximum - minimum < min_separation_) {
        maximum = minimum + min_separation_;
      }

      InstanceNorm(reinterpret_cast<const uint8_t*>(input_tensor.data()), H * W, C, float_mean.data(), float_variance.data(), variance_epsilon_, minimum, maximum, reinterpret_cast<uint8_t*>(output->flat<quint8>().data()));


      output_min->scalar<float>()() = minimum;
      output_max->scalar<float>()() = maximum;
    } else    {

      VLOG(2) << "Calling unoptimized";
      float_mean = input_tensor.cast<float>().reduce( reduction_indices, Eigen::internal::MeanReducer<float>());

      float_variance = (input_scale * ((input_tensor.cast<float>() - float_mean.reshape(expand_spec).broadcast(broadcast_spec))))


              .square()
              .reduce(reduction_indices, Eigen::internal::MeanReducer<float>());

      Eigen::Tensor<float, 4, Eigen::RowMajor> instance_normed = input_scale * (input_tensor.cast<float>() - float_mean.reshape(expand_spec).broadcast(broadcast_spec)) * (float_variance + variance_epsilon_)



              .rsqrt()
              .reshape(expand_spec)
              .broadcast(broadcast_spec);

      Eigen::Tensor<float, 0, Eigen::RowMajor> normed_min;
      Eigen::Tensor<float, 0, Eigen::RowMajor> normed_max;

      if (!output_range_given_) {
        normed_min = instance_normed.minimum();
        normed_max = instance_normed.maximum();
      } else {
        normed_min() = given_y_min_;
        normed_max() = given_y_max_;
      }

      if (normed_max() - normed_min() < min_separation_) {
        normed_max() = normed_min() + min_separation_;
      }

      FloatToQuantizedStruct<quint8> output_f2q(normed_min(), normed_max());
      auto instance_normed_quantized = QUANTIZE_WITH_EIGEN(instance_normed, output_f2q, quint8);

      output->tensor<quint8, 4>().device( context->template eigen_device<CPUDevice>()) = instance_normed_quantized;

      output_min->flat<float>()(0) = normed_min();
      output_max->flat<float>()(0) = normed_max();
    }
  }

 private:
  float variance_epsilon_;
  float min_separation_;
  bool output_range_given_;
  float given_y_min_;
  float given_y_max_;
};

REGISTER_KERNEL_BUILDER(Name("QuantizedInstanceNorm")
                            .Device(DEVICE_CPU)
                            .TypeConstraint<quint8>("T"), QuantizedInstanceNorm);

}  
