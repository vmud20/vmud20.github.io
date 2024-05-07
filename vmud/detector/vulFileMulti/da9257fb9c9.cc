

















namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;






template <typename Device, typename T> class QuantizeAndDequantizeV2Op : public OpKernel {
 public:
  explicit QuantizeAndDequantizeV2Op(OpKernelConstruction* ctx)
      : OpKernel(ctx) {
    OP_REQUIRES_OK(ctx, ctx->GetAttr("signed_input", &signed_input_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("axis", &axis_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("num_bits", &num_bits_));
    OP_REQUIRES(ctx, num_bits_ > 0 && num_bits_ < (signed_input_ ? 62 : 63), errors::InvalidArgument("num_bits is out of range: ", num_bits_, " with signed_input_ ", signed_input_));

    OP_REQUIRES_OK(ctx, ctx->GetAttr("range_given", &range_given_));

    string round_mode_string;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("round_mode", &round_mode_string));
    OP_REQUIRES( ctx, (round_mode_string == "HALF_UP" || round_mode_string == "HALF_TO_EVEN"), errors::InvalidArgument("Round mode string must be " "'HALF_UP' or " "'HALF_TO_EVEN', is '" + round_mode_string + "'"));





    if (round_mode_string == "HALF_UP") {
      round_mode_ = ROUND_HALF_UP;
    } else if (round_mode_string == "HALF_TO_EVEN") {
      round_mode_ = ROUND_HALF_TO_EVEN;
    }
    OP_REQUIRES_OK(ctx, ctx->GetAttr("narrow_range", &narrow_range_));
  }

  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);
    OP_REQUIRES( ctx, axis_ >= -1, errors::InvalidArgument("Axis must be at least -1. Found ", axis_));

    OP_REQUIRES( ctx, (axis_ == -1 || axis_ < input.shape().dims()), errors::InvalidArgument("Shape must be at least rank ", axis_ + 1, " but is rank ", input.shape().dims()));


    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_);
    Tensor input_min_tensor;
    Tensor input_max_tensor;
    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, input.shape(), &output));
    if (range_given_) {
      input_min_tensor = ctx->input(1);
      input_max_tensor = ctx->input(2);
      if (axis_ == -1) {
        auto min_val = input_min_tensor.scalar<T>()();
        auto max_val = input_max_tensor.scalar<T>()();
        OP_REQUIRES(ctx, min_val <= max_val, errors::InvalidArgument("Invalid range: input_min ", min_val, " > input_max ", max_val));

      } else {
        OP_REQUIRES(ctx, input_min_tensor.dim_size(0) == depth, errors::InvalidArgument( "input_min_tensor has incorrect size, was ", input_min_tensor.dim_size(0), " expected ", depth, " to match dim ", axis_, " of the input ", input_min_tensor.shape()));




        OP_REQUIRES(ctx, input_max_tensor.dim_size(0) == depth, errors::InvalidArgument( "input_max_tensor has incorrect size, was ", input_max_tensor.dim_size(0), " expected ", depth, " to match dim ", axis_, " of the input ", input_max_tensor.shape()));




      }
    } else {
      auto range_shape = (axis_ == -1) ? TensorShape({}) : TensorShape({depth});
      OP_REQUIRES_OK(ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, range_shape, &input_min_tensor));
      OP_REQUIRES_OK(ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, range_shape, &input_max_tensor));
    }

    if (axis_ == -1) {
      functor::QuantizeAndDequantizeOneScaleFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), input.flat<T>(), signed_input_, num_bits_, range_given_, &input_min_tensor, &input_max_tensor, round_mode_, narrow_range_, output->flat<T>());

    } else {
      functor::QuantizeAndDequantizePerChannelFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), input.template flat_inner_outer_dims<T, 3>(axis_ - 1), signed_input_, num_bits_, range_given_, &input_min_tensor, &input_max_tensor, round_mode_, narrow_range_, output->template flat_inner_outer_dims<T, 3>(axis_ - 1));



    }
  }

 private:
  int num_bits_;
  int axis_;
  QuantizerRoundMode round_mode_;
  bool signed_input_;
  bool range_given_;
  bool narrow_range_;
};






template <typename Device, typename T> class QuantizeAndDequantizeV4GradientOp : public OpKernel {
 public:
  explicit QuantizeAndDequantizeV4GradientOp(OpKernelConstruction* ctx)
      : OpKernel::OpKernel(ctx) {
    OP_REQUIRES_OK(ctx, ctx->GetAttr("axis", &axis_));
  }

  void Compute(OpKernelContext* ctx) override {
    const Tensor& gradient = ctx->input(0);
    const Tensor& input = ctx->input(1);
    Tensor* input_backprop = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, input.shape(), &input_backprop));
    OP_REQUIRES( ctx, axis_ >= -1, errors::InvalidArgument("Axis must be at least -1. Found ", axis_));

    OP_REQUIRES(ctx, (axis_ == -1 || axis_ < input.shape().dims()), errors::InvalidArgument( "Axis should be -1 or 0 or a positive value less than ", input.shape().dims(), "but given axis value was ", axis_));



    OP_REQUIRES( ctx, input.IsSameSize(gradient), errors::InvalidArgument("gradient and input must be the same size"));

    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_);
    const Tensor& input_min_tensor = ctx->input(2);
    OP_REQUIRES(ctx, input_min_tensor.dims() == 0 || input_min_tensor.dims() == 1, errors::InvalidArgument( "Input min tensor must have dimension 0 or 1. Received ", input_min_tensor.dims(), "."));



    const Tensor& input_max_tensor = ctx->input(3);
    OP_REQUIRES(ctx, input_max_tensor.dims() == 0 || input_max_tensor.dims() == 1, errors::InvalidArgument( "Input max tensor must have dimension 0 or 1. Received ", input_max_tensor.dims(), "."));



    if (axis_ != -1) {
      OP_REQUIRES( ctx, input_min_tensor.dim_size(0) == depth, errors::InvalidArgument("min has incorrect size, expected ", depth, " was ", input_min_tensor.dim_size(0)));


      OP_REQUIRES( ctx, input_max_tensor.dim_size(0) == depth, errors::InvalidArgument("max has incorrect size, expected ", depth, " was ", input_max_tensor.dim_size(0)));


    }

    TensorShape min_max_shape(input_min_tensor.shape());
    Tensor* input_min_backprop;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(1, min_max_shape, &input_min_backprop));

    Tensor* input_max_backprop;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(2, min_max_shape, &input_max_backprop));

    if (axis_ == -1) {
      OP_REQUIRES(ctx, TensorShapeUtils::IsScalar(input_min_tensor.shape()), errors::InvalidArgument( "input_min must be a scalar if axis is unspecified"));

      OP_REQUIRES(ctx, TensorShapeUtils::IsScalar(input_max_tensor.shape()), errors::InvalidArgument( "input_max must be a scalar if axis is unspecified"));

      functor::QuantizeAndDequantizeOneScaleGradientFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), gradient.template flat<T>(), input.template flat<T>(), input_min_tensor.scalar<T>(), input_max_tensor.scalar<T>(), input_backprop->template flat<T>(), input_min_backprop->template scalar<T>(), input_max_backprop->template scalar<T>());



    } else {
      functor::QuantizeAndDequantizePerChannelGradientFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), gradient.template flat_inner_outer_dims<T, 3>(axis_ - 1), input.template flat_inner_outer_dims<T, 3>(axis_ - 1), &input_min_tensor, &input_max_tensor, input_backprop->template flat_inner_outer_dims<T, 3>(axis_ - 1), input_min_backprop->template flat<T>(), input_max_backprop->template flat<T>());





    }
  }

 private:
  int axis_;
};








template <typename Device, typename T> class QuantizeAndDequantizeV3Op : public OpKernel {
 public:
  explicit QuantizeAndDequantizeV3Op(OpKernelConstruction* ctx)
      : OpKernel(ctx) {
    OP_REQUIRES_OK(ctx, ctx->GetAttr("signed_input", &signed_input_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("range_given", &range_given_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("narrow_range", &narrow_range_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("axis", &axis_));
  }

  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);
    OP_REQUIRES(ctx, axis_ < input.dims(), errors::InvalidArgument( "Axis requested is larger than input dimensions. Axis: ", axis_, " Input Dimensions: ", input.dims()));


    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_);
    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, input.shape(), &output));

    Tensor num_bits_tensor;
    num_bits_tensor = ctx->input(3);
    int num_bits_val = num_bits_tensor.scalar<int32>()();

    OP_REQUIRES( ctx, num_bits_val > 0 && num_bits_val < (signed_input_ ? 62 : 63), errors::InvalidArgument("num_bits is out of range: ", num_bits_val, " with signed_input_ ", signed_input_));



    Tensor input_min_tensor;
    Tensor input_max_tensor;
    if (range_given_) {
      input_min_tensor = ctx->input(1);
      input_max_tensor = ctx->input(2);
      if (axis_ == -1) {
        auto min_val = input_min_tensor.scalar<T>()();
        auto max_val = input_max_tensor.scalar<T>()();
        OP_REQUIRES(ctx, min_val <= max_val, errors::InvalidArgument("Invalid range: input_min ", min_val, " > input_max ", max_val));

      } else {
        OP_REQUIRES(ctx, input_min_tensor.dim_size(0) == depth, errors::InvalidArgument( "input_min_tensor has incorrect size, was ", input_min_tensor.dim_size(0), " expected ", depth, " to match dim ", axis_, " of the input ", input_min_tensor.shape()));




        OP_REQUIRES(ctx, input_max_tensor.dim_size(0) == depth, errors::InvalidArgument( "input_max_tensor has incorrect size, was ", input_max_tensor.dim_size(0), " expected ", depth, " to match dim ", axis_, " of the input ", input_max_tensor.shape()));




      }
    } else {
      auto range_shape = (axis_ == -1) ? TensorShape({}) : TensorShape({depth});
      OP_REQUIRES_OK(ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, range_shape, &input_min_tensor));
      OP_REQUIRES_OK(ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, range_shape, &input_max_tensor));
    }

    if (axis_ == -1) {
      functor::QuantizeAndDequantizeOneScaleFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), input.flat<T>(), signed_input_, num_bits_val, range_given_, &input_min_tensor, &input_max_tensor, ROUND_HALF_TO_EVEN, narrow_range_, output->flat<T>());

    } else {
      functor::QuantizeAndDequantizePerChannelFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), input.template flat_inner_outer_dims<T, 3>(axis_ - 1), signed_input_, num_bits_val, range_given_, &input_min_tensor, &input_max_tensor, ROUND_HALF_TO_EVEN, narrow_range_, output->template flat_inner_outer_dims<T, 3>(axis_ - 1));



    }
  }

 private:
  int axis_;
  bool signed_input_;
  bool range_given_;
  bool narrow_range_;
};


template <typename Device, typename T> class QuantizeAndDequantizeOp : public OpKernel {
 public:
  explicit QuantizeAndDequantizeOp(OpKernelConstruction* ctx) : OpKernel(ctx) {
    OP_REQUIRES_OK(ctx, ctx->GetAttr("signed_input", &signed_input_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("num_bits", &num_bits_));
    OP_REQUIRES(ctx, num_bits_ > 0 && num_bits_ < (signed_input_ ? 62 : 63), errors::InvalidArgument("num_bits is out of range: ", num_bits_, " with signed_input_ ", signed_input_));

    OP_REQUIRES_OK(ctx, ctx->GetAttr("range_given", &range_given_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("input_min", &input_min_));
    OP_REQUIRES_OK(ctx, ctx->GetAttr("input_max", &input_max_));
    if (range_given_) {
      OP_REQUIRES( ctx, input_min_ <= input_max_, errors::InvalidArgument("Invalid range: input_min ", input_min_, " > input_max ", input_max_));


    }
  }

  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);

    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, input.shape(), &output));

    
    Tensor input_min_tensor(DataTypeToEnum<T>::value, TensorShape());
    Tensor input_max_tensor(DataTypeToEnum<T>::value, TensorShape());
    
    input_min_tensor.template scalar<T>()() = static_cast<T>(input_min_);
    input_max_tensor.template scalar<T>()() = static_cast<T>(input_max_);

    functor::QuantizeAndDequantizeOneScaleFunctor<Device, T> functor;
    functor(ctx->eigen_device<Device>(), input.flat<T>(), signed_input_, num_bits_, range_given_, &input_min_tensor, &input_max_tensor, ROUND_HALF_TO_EVEN, false, output->flat<T>());

  }

 private:
  bool signed_input_;
  int num_bits_;
  bool range_given_;
  float input_min_;
  float input_max_;
};



namespace functor {
template <typename T> struct QuantizeAndDequantizeOneScaleFunctor<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T>::ConstVec input, const bool signed_input, const int num_bits, const bool range_given, Tensor* input_min_tensor, Tensor* input_max_tensor, QuantizerRoundMode round_mode, bool narrow_range, typename TTypes<T>::Vec out) {



    QuantizeAndDequantizeOneScaleImpl<CPUDevice, T>::Compute( d, input, signed_input, num_bits, range_given, input_min_tensor, input_max_tensor, round_mode, narrow_range, out);

  }
};

template <typename T> struct QuantizeAndDequantizePerChannelFunctor<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T, 3>::ConstTensor input, bool signed_input, int num_bits, bool range_given, Tensor* input_min_tensor, Tensor* input_max_tensor, QuantizerRoundMode round_mode, bool narrow_range, typename TTypes<T, 3>::Tensor out) {



    QuantizeAndDequantizePerChannelImpl<CPUDevice, T>::Compute( d, input, signed_input, num_bits, range_given, input_min_tensor, input_max_tensor, round_mode, narrow_range, out);

  }
};

template <typename T> struct QuantizeAndDequantizeOneScaleGradientFunctor<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T>::ConstFlat gradient, typename TTypes<T>::ConstFlat input, typename TTypes<T>::ConstScalar input_min_tensor, typename TTypes<T>::ConstScalar input_max_tensor, typename TTypes<T>::Flat input_backprop, typename TTypes<T>::Scalar input_min_backprop, typename TTypes<T>::Scalar input_max_backprop) {





    QuantizeAndDequantizeOneScaleGradientImpl<CPUDevice, T>::Compute( d, gradient, input, input_min_tensor, input_max_tensor, input_backprop, input_min_backprop, input_max_backprop);

  }
};

template <typename T> struct QuantizeAndDequantizePerChannelGradientFunctor<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T, 3>::ConstTensor gradient, typename TTypes<T, 3>::ConstTensor input, const Tensor* input_min_tensor, const Tensor* input_max_tensor, typename TTypes<T, 3>::Tensor input_backprop, typename TTypes<T>::Flat input_min_backprop, typename TTypes<T>::Flat input_max_backprop) {






    QuantizeAndDequantizePerChannelGradientImpl<CPUDevice, T>::Compute( d, gradient, input, input_min_tensor, input_max_tensor, input_backprop, input_min_backprop, input_max_backprop);

  }
};

template struct functor::QuantizeAndDequantizeOneScaleGradientFunctor<CPUDevice, float>;
template struct functor::QuantizeAndDequantizePerChannelGradientFunctor< CPUDevice, double>;

}  




















TF_CALL_float(REGISTER_CPU_KERNEL);
TF_CALL_double(REGISTER_CPU_KERNEL);































TF_CALL_float(REGISTER_GPU_KERNEL);
TF_CALL_double(REGISTER_GPU_KERNEL);


}  
