



































namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

template <typename Device, typename T> class AvgPoolingOp : public UnaryOp<T> {
 public:
  explicit AvgPoolingOp(OpKernelConstruction* context) : UnaryOp<T>(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument("Default AvgPoolingOp only supports NHWC ", "on device type ", DeviceTypeString(context->device_type())));



    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));


    for (int i = 0; i < ksize_.size(); ++i) {
      OP_REQUIRES(context, ksize_[i] != 0, errors::InvalidArgument("ksize cannot be zero"));
    }
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    PoolParameters params{context, ksize_, stride_, padding_, , data_format_, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }
    OP_REQUIRES(context, params.depth_window == 1, errors::Unimplemented("Non-spatial pooling is not " "yet supported. Volunteers? :)"));


    
    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional"));

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output( 0, params.forward_output_shape(), &output));

    SpatialAvgPool<Device, T>(context, output, tensor_in, params, padding_);
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};

REGISTER_KERNEL_BUILDER( Name("AvgPool").Device(DEVICE_CPU).TypeConstraint<double>("T"), AvgPoolingOp<CPUDevice, double>);

REGISTER_KERNEL_BUILDER( Name("AvgPool").Device(DEVICE_CPU).TypeConstraint<float>("T"), AvgPoolingOp<CPUDevice, float>);

REGISTER_KERNEL_BUILDER( Name("AvgPool").Device(DEVICE_CPU).TypeConstraint<Eigen::half>("T"), AvgPoolingOp<CPUDevice, Eigen::half>);



template <typename T> class AvgPoolingOp<GPUDevice, T> : public UnaryOp<T> {
 public:
  typedef GPUDevice Device;
  explicit AvgPoolingOp(OpKernelConstruction* context) : UnaryOp<T>(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));


    for (int i = 0; i < ksize_.size(); ++i) {
      OP_REQUIRES(context, ksize_[i] != 0, errors::InvalidArgument("ksize cannot be zero"));
    }
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    PoolParameters params{context, ksize_, stride_, padding_, , data_format_, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }
    OP_REQUIRES(context, params.depth_window == 1, errors::Unimplemented("Non-spatial pooling is not " "yet supported. Volunteers? :)"));


    
    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional"));

    TensorShape output_shape = params.forward_output_shape();
    if (output_shape.num_elements() == 0) {
      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));
      return;
    }


    DnnPoolingOp<T>::Compute(context, se::dnn::PoolingMode::kAverage, ksize_, stride_, padding_, , data_format_, tensor_in, output_shape, false);



    if (data_format_ == FORMAT_NCHW) {
      DnnPoolingOp<T>::Compute(context, se::dnn::PoolingMode::kAverage, ksize_, stride_, padding_, , data_format_, tensor_in, output_shape, false);


    } else {
      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));
      Eigen::PaddingType pt = BrainPadding2EigenPadding(padding_);
      functor::SpatialAvgPooling<Device, T>()( context->eigen_device<Device>(), output->tensor<T, 4>(), tensor_in.tensor<T, 4>(), params.window_rows, params.window_cols, params.row_stride, params.col_stride, pt);


    }

  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};


namespace functor {








DECLARE_GPU_SPEC(Eigen::half);
DECLARE_GPU_SPEC(float);
DECLARE_GPU_SPEC(double);

}  

REGISTER_KERNEL_BUILDER( Name("AvgPool").Device(DEVICE_GPU).TypeConstraint<Eigen::half>("T"), AvgPoolingOp<GPUDevice, Eigen::half>);

REGISTER_KERNEL_BUILDER( Name("AvgPool").Device(DEVICE_GPU).TypeConstraint<float>("T"), AvgPoolingOp<GPUDevice, float>);

REGISTER_KERNEL_BUILDER( Name("AvgPool").Device(DEVICE_GPU).TypeConstraint<double>("T"), AvgPoolingOp<GPUDevice, double>);








template <typename Device, class T> class AvgPoolingGradOp : public OpKernel {
 public:
  explicit AvgPoolingGradOp(OpKernelConstruction* context) : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument("Default AvgPoolingGradOp only supports NHWC ", "on device type ", DeviceTypeString(context->device_type())));



    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in_shape = context->input(0);
    const Tensor& out_backprop = context->input(1);
    
    OP_REQUIRES( context, tensor_in_shape.dims() == 1 && tensor_in_shape.NumElements() == 4, errors::InvalidArgument("out_backprop must be 1-dimensional and 4 " "elements"));



    
    OP_REQUIRES(context, out_backprop.dims() == 4, errors::InvalidArgument("out_backprop must be 4-dimensional"));
    const int64_t out_backprop_batch = out_backprop.dim_size(0);
    const int64_t out_backprop_rows = out_backprop.dim_size(1);
    const int64_t out_backprop_cols = out_backprop.dim_size(2);
    const int64_t out_backprop_depth = out_backprop.dim_size(3);

    TensorShape output_shape;
    auto shape_vec = tensor_in_shape.vec<int32>();
    for (int64_t i = 0; i < tensor_in_shape.NumElements(); ++i) {
      output_shape.AddDim(shape_vec(i));
    }
    const int64_t in_rows = output_shape.dim_size(1);
    const int64_t in_cols = output_shape.dim_size(2);

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));
    output->flat<T>().setZero();

    if (output_shape.num_elements() == 0) {
      return;
    }
    const int window_rows = ksize_[1];
    const int window_cols = ksize_[2];
    const int depth_window = ksize_[3];

    const int row_stride = stride_[1];
    const int col_stride = stride_[2];

    
    
    
    
    OP_REQUIRES(context, depth_window == 1, errors::Unimplemented("Non-spatial pooling is not " "yet supported. Volunteers? :)"));


    int64_t out_height, out_width, pad_rows, pad_cols;
    OP_REQUIRES_OK(context, GetWindowedOutputSize(in_rows, window_rows, row_stride, padding_, &out_height, &pad_rows));

    OP_REQUIRES_OK(context, GetWindowedOutputSize(in_cols, window_cols, col_stride, padding_, &out_width, &pad_cols));


    const T* out_backprop_ptr = out_backprop.flat<T>().data();
    T* input_backprop_ptr = output->flat<T>().data();

    auto shard = [context, out_backprop_ptr, input_backprop_ptr, out_backprop_rows, out_backprop_cols, out_backprop_depth, in_rows, in_cols, window_rows, window_cols, row_stride, col_stride, pad_rows, pad_cols](int64_t start, int64_t limit) {



      for (int64_t b = start; b < limit; ++b) {
        for (int64_t r = 0; r < out_backprop_rows; ++r) {
          
          
          
          
          
          int rindex, rsize;
          OP_REQUIRES_OK(context, GetBroadcastSize(r, in_rows, window_rows, row_stride, pad_rows, &rindex, &rsize));

          for (int64_t c = 0; c < out_backprop_cols; ++c) {
            
            
            
            
            
            int cindex, csize;
            OP_REQUIRES_OK(context, GetBroadcastSize(c, in_cols, window_cols, col_stride, pad_cols, &cindex, &csize));


            T divide_coeff(1.0 / (rsize * csize));
            int64_t output_index = (b * out_backprop_rows + r) * out_backprop_cols + c;
            for (int64_t r_dst = rindex; r_dst < rindex + rsize; ++r_dst) {
              for (int64_t c_dst = cindex; c_dst < cindex + csize; ++c_dst) {
                int64_t input_index = (b * in_rows + r_dst) * in_cols + c_dst;
                const T* output_offset = out_backprop_ptr + output_index * out_backprop_depth;
                T* input_offset = input_backprop_ptr + input_index * out_backprop_depth;
                for (int64_t d = 0; d < out_backprop_depth; ++d) {
                  *input_offset += *output_offset * divide_coeff;
                  ++output_offset;
                  ++input_offset;
                }
              }
            }
          }
        }
      }
    };

    const DeviceBase::CpuWorkerThreads& worker_threads = *(context->device()->tensorflow_cpu_worker_threads());
    const int64_t shard_cost = window_rows * window_cols * depth_window * in_rows * in_rows * in_cols;
    Shard(worker_threads.num_threads, worker_threads.workers, out_backprop_batch, shard_cost, shard);
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};







TF_CALL_float(REGISTER_CPU_KERNEL);
TF_CALL_double(REGISTER_CPU_KERNEL);
TF_CALL_half(REGISTER_CPU_KERNEL);





template <class T> class AvgPoolingGradOp<GPUDevice, T> : public OpKernel {
 public:
  typedef GPUDevice Device;

  explicit AvgPoolingGradOp(OpKernelConstruction* context) : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in_shape = context->input(0);
    const Tensor& out_backprop = context->input(1);
    
    OP_REQUIRES( context, tensor_in_shape.dims() == 1 && tensor_in_shape.NumElements() == 4, errors::InvalidArgument("out_backprop must be 1-dimensional and 4 " "elements"));



    
    OP_REQUIRES(context, out_backprop.dims() == 4, errors::InvalidArgument("out_backprop must be 4-dimensional"));

    TensorShape output_shape;
    auto shape_vec = tensor_in_shape.vec<int32>();
    for (int64_t i = 0; i < tensor_in_shape.NumElements(); ++i) {
      output_shape.AddDim(shape_vec(i));
    }

    if (output_shape.num_elements() == 0) {
      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));
      return;
    }

    DnnPoolingGradOp<T>::Compute( context, se::dnn::PoolingMode::kAverage, ksize_, stride_, padding_, , data_format_, nullptr, nullptr, out_backprop, output_shape, false);


  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};

REGISTER_KERNEL_BUILDER(Name("AvgPoolGrad")
                            .Device(DEVICE_GPU)
                            .TypeConstraint<double>("T")
                            .HostMemory("orig_input_shape")
                            .Label("cudnn"), AvgPoolingGradOp<GPUDevice, double>);
REGISTER_KERNEL_BUILDER(Name("AvgPoolGrad")
                            .Device(DEVICE_GPU)
                            .TypeConstraint<float>("T")
                            .HostMemory("orig_input_shape")
                            .Label("cudnn"), AvgPoolingGradOp<GPUDevice, float>);
REGISTER_KERNEL_BUILDER(Name("AvgPoolGrad")
                            .Device(DEVICE_GPU)
                            .TypeConstraint<Eigen::half>("T")
                            .HostMemory("orig_input_shape")
                            .Label("cudnn"), AvgPoolingGradOp<GPUDevice, Eigen::half>);



template <class T> class AvgPoolingGradOpCustomGPUKernel : public OpKernel {
 public:
  typedef GPUDevice Device;

  explicit AvgPoolingGradOpCustomGPUKernel(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in_shape = context->input(0);
    const Tensor& out_backprop = context->input(1);
    
    OP_REQUIRES( context, tensor_in_shape.dims() == 1 && tensor_in_shape.NumElements() == 4, errors::InvalidArgument("out_backprop must be 1-dimensional and 4 " "elements"));



    
    OP_REQUIRES(context, out_backprop.dims() == 4, errors::InvalidArgument("out_backprop must be 4-dimensional"));
    TensorShape output_shape;
    auto shape_vec = tensor_in_shape.vec<int32>();
    for (int64_t i = 0; i < tensor_in_shape.NumElements(); ++i) {
      output_shape.AddDim(shape_vec(i));
    }
    if (output_shape.num_elements() == 0) {
      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));
      return;
    }


    DnnPoolingGradOp<T>::Compute(context, se::dnn::PoolingMode::kAverage, ksize_, stride_, padding_, , data_format_, nullptr, nullptr, out_backprop, output_shape, false);




    if (data_format_ == FORMAT_NHWC) {
      const int64 out_backprop_batch = out_backprop.dim_size(0);
      const int64 out_backprop_rows = out_backprop.dim_size(1);
      const int64 out_backprop_cols = out_backprop.dim_size(2);
      const int64 out_backprop_depth = out_backprop.dim_size(3);

      const int64 in_rows = output_shape.dim_size(1);
      const int64 in_cols = output_shape.dim_size(2);
      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));

      const int window_rows = ksize_[1];
      const int window_cols = ksize_[2];
      const int depth_window = ksize_[3];

      const int row_stride = stride_[1];
      const int col_stride = stride_[2];

      
      
      
      
      OP_REQUIRES(context, depth_window == 1, errors::Unimplemented("Non-spatial pooling is not " "yet supported. Volunteers? :)"));


      int64 out_height, out_width, pad_rows, pad_cols;
      OP_REQUIRES_OK(context, GetWindowedOutputSize(in_rows, window_rows, row_stride, padding_, &out_height, &pad_rows));

      OP_REQUIRES_OK(context, GetWindowedOutputSize(in_cols, window_cols, col_stride, padding_, &out_width, &pad_cols));


      RunAvePoolBackwardNHWC<T>(out_backprop.flat<T>().data(),   out_backprop_batch, in_rows, in_cols, out_backprop_depth, out_backprop_rows, out_backprop_cols, window_rows, window_cols, row_stride, col_stride, pad_rows, pad_cols, output->flat<T>().data(), context->eigen_gpu_device());













    } else {
      DnnPoolingGradOp<T>::Compute(context, se::dnn::PoolingMode::kAverage, ksize_, stride_, padding_, , data_format_, nullptr, nullptr, out_backprop, output_shape, false);



    }

  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};

REGISTER_KERNEL_BUILDER(Name("AvgPoolGrad")
                            .Device(DEVICE_GPU)
                            .TypeConstraint<float>("T")
                            .HostMemory("orig_input_shape"), AvgPoolingGradOpCustomGPUKernel<float>);
REGISTER_KERNEL_BUILDER(Name("AvgPoolGrad")
                            .Device(DEVICE_GPU)
                            .TypeConstraint<double>("T")
                            .HostMemory("orig_input_shape"), AvgPoolingGradOpCustomGPUKernel<double>);
REGISTER_KERNEL_BUILDER(Name("AvgPoolGrad")
                            .Device(DEVICE_GPU)
                            .TypeConstraint<Eigen::half>("T")
                            .HostMemory("orig_input_shape"), AvgPoolingGradOpCustomGPUKernel<Eigen::half>);



}  
