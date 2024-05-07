



















namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;

template <typename Device, typename T> class QuantizedAvgPoolingOp : public OpKernel {
 public:
  explicit QuantizedAvgPoolingOp(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    PoolParameters params{context, ksize_, stride_, padding_, , FORMAT_NHWC, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    const float min_input = context->input(1).flat<float>()(0);
    const float max_input = context->input(2).flat<float>()(0);

    OP_REQUIRES(context, params.depth_window == 1, errors::Unimplemented("Non-spatial pooling is not " "yet supported. Volunteers? :)"));


    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional"));

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output( 0, params.forward_output_shape(), &output));
    const int32_t highest = static_cast<int32>(Eigen::NumTraits<T>::highest());
    const int32_t lowest = static_cast<int32>(Eigen::NumTraits<T>::lowest());

    
    
    Tensor int32_output(DT_INT32, params.forward_output_shape());
    
    Tensor int32_input(DT_INT32, tensor_in.shape());
    int32_input.flat<int32>() = tensor_in.flat<T>().template cast<int32>();
    SpatialAvgPool<Device, int32>(context, &int32_output, int32_input, params, padding_);

    
    output->flat<T>() = int32_output.flat<int32>()
                            .cwiseMax(lowest)
                            .cwiseMin(highest)
                            .template cast<T>();

    Tensor* output_min = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(1, {}, &output_min));
    output_min->flat<float>()(0) = min_input;
    Tensor* output_max = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(2, {}, &output_max));
    output_max->flat<float>()(0) = max_input;
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
};

template <typename Device, typename T> class QuantizedMaxPoolingOp : public MaxPoolingOp<Device, T> {
 public:
  explicit QuantizedMaxPoolingOp(OpKernelConstruction* context)
      : MaxPoolingOp<Device, T>(context) {}

  void Compute(OpKernelContext* context) override {
    auto min_input_tensor = context->input(1);
    auto max_input_tensor = context->input(2);
    OP_REQUIRES( context, min_input_tensor.NumElements() == 1, errors::InvalidArgument( "min_input must be a scalar float value, got tensor with shape ", min_input_tensor.shape()));



    OP_REQUIRES( context, max_input_tensor.NumElements() == 1, errors::InvalidArgument( "max_input must be a scalar float value, got tensor with shape ", max_input_tensor.shape()));



    const float min_input = context->input(1).flat<float>()(0);
    const float max_input = context->input(2).flat<float>()(0);
    MaxPoolingOp<Device, T>::Compute(context);
    Tensor* output_min = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(1, {}, &output_min));
    output_min->flat<float>()(0) = min_input;
    Tensor* output_max = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(2, {}, &output_max));
    output_max->flat<float>()(0) = max_input;
  }
};

REGISTER_KERNEL_BUILDER( Name("QuantizedAvgPool").Device(DEVICE_CPU).TypeConstraint<quint8>("T"), QuantizedAvgPoolingOp<CPUDevice, quint8>);


REGISTER_KERNEL_BUILDER( Name("QuantizedMaxPool").Device(DEVICE_CPU).TypeConstraint<quint8>("T"), QuantizedMaxPoolingOp<CPUDevice, quint8>);



REGISTER_KERNEL_BUILDER( Name("QuantizedAvgPool").Device(DEVICE_CPU).TypeConstraint<qint8>("T"), QuantizedAvgPoolingOp<CPUDevice, qint8>);


REGISTER_KERNEL_BUILDER( Name("QuantizedMaxPool").Device(DEVICE_CPU).TypeConstraint<qint8>("T"), QuantizedMaxPoolingOp<CPUDevice, qint8>);



}  
