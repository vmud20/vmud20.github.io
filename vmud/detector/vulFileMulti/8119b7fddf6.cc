







































namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

const int kInvalidMaxPoolingIndex = -1;

template <typename Device, typename T, typename Targmax> static void SpatialMaxPoolWithArgMaxHelper( OpKernelContext* context, Tensor* output, Tensor* output_arg_max, Tensor* input_backprop, const Tensor& tensor_in, const Tensor& out_backprop, const PoolParameters& params, const bool include_batch_in_index) {



  if (input_backprop != nullptr) {
    OP_REQUIRES( context, include_batch_in_index, errors::Internal( "SpatialMaxPoolWithArgMaxHelper requires include_batch_in_index " "to be True when input_backprop != nullptr"));



    OP_REQUIRES( context, (std::is_same<Targmax, int64>::value), errors::Internal("SpatialMaxPoolWithArgMaxHelper requires Targmax " "to be int64 when input_backprop != nullptr"));


  }

  typedef Eigen::Map<const Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> ConstEigenMatrixMap;
  typedef Eigen::Map<Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> EigenMatrixMap;
  typedef Eigen::Map<Eigen::Matrix<Targmax, Eigen::Dynamic, Eigen::Dynamic>> EigenIndexMatrixMap;

  ConstEigenMatrixMap in_mat( tensor_in.flat<T>().data(), params.depth, params.tensor_in_cols * params.tensor_in_rows * params.tensor_in_batch);

  EigenMatrixMap out_mat( output->flat<T>().data(), params.depth, params.out_width * params.out_height * params.tensor_in_batch);

  EigenIndexMatrixMap out_arg_max_mat( output_arg_max->flat<Targmax>().data(), params.depth, params.out_width * params.out_height * params.tensor_in_batch);


  const DeviceBase::CpuWorkerThreads& worker_threads = *(context->device()->tensorflow_cpu_worker_threads());

  
  
  
  
  
  
  
  
  
  
  auto shard = [&params, &in_mat, &out_mat, &out_arg_max_mat, &input_backprop, &output_arg_max, &out_backprop, include_batch_in_index](int64_t start, int64_t limit) {

    const int32_t depth = params.depth;
    const int32_t in_rows = params.tensor_in_rows;
    const int32_t in_cols = params.tensor_in_cols;
    const int32_t pad_top = params.pad_top;
    const int32_t pad_left = params.pad_left;
    const int32_t window_rows = params.window_rows;
    const int32_t window_cols = params.window_cols;
    const int32_t row_stride = params.row_stride;
    const int32_t col_stride = params.col_stride;
    const int32_t out_height = params.out_height;
    const int32_t out_width = params.out_width;

    {
      
      const int32_t output_image_size = out_height * out_width * depth;
      EigenMatrixMap out_shard(out_mat.data() + start * output_image_size, 1, (limit - start) * output_image_size);
      out_shard.setConstant(Eigen::NumTraits<T>::lowest());
      EigenIndexMatrixMap out_arg_max_shard( out_arg_max_mat.data() + start * output_image_size, 1, (limit - start) * output_image_size);

      out_arg_max_shard.setConstant(kInvalidMaxPoolingIndex);
    }

    for (int64_t b = start; b < limit; ++b) {
      for (int h = 0; h < in_rows; ++h) {
        for (int w = 0; w < in_cols; ++w) {
          
          
          const int hpad = h + pad_top;
          const int wpad = w + pad_left;
          const int h_start = (hpad < window_rows) ? 0 : (hpad - window_rows) / row_stride + 1;
          const int h_end = std::min(hpad / row_stride + 1, out_height);
          const int w_start = (wpad < window_cols) ? 0 : (wpad - window_cols) / col_stride + 1;
          const int w_end = std::min(wpad / col_stride + 1, out_width);
          
          const int64_t in_index = (b * in_rows + h) * in_cols + w;
          for (int ph = h_start; ph < h_end; ++ph) {
            const int64_t out_index_base = (b * out_height + ph) * out_width;
            for (int pw = w_start; pw < w_end; ++pw) {
              const int64_t out_index = out_index_base + pw;
              
              
              for (int d = 0; d < depth; ++d) {
                const T& input_ref = in_mat.coeffRef(d, in_index);
                T& output_ref = out_mat.coeffRef(d, out_index);
                Targmax& out_arg_max_ref = out_arg_max_mat.coeffRef(d, out_index);
                if (output_ref < input_ref || out_arg_max_ref == kInvalidMaxPoolingIndex) {
                  output_ref = input_ref;
                  if (include_batch_in_index) {
                    out_arg_max_ref = in_index * depth + d;
                  } else {
                    out_arg_max_ref = (h * in_cols + w) * depth + d;
                  }
                }
              }
            }
          }
        }
      }
    }

    if (input_backprop != nullptr) {
      auto input_backprop_flat = input_backprop->flat<T>();
      auto out_arg_max_flat = output_arg_max->flat<int64>();
      auto out_backprop_flat = out_backprop.flat<T>();

      
      const int64_t in_size = in_rows * in_cols * depth;
      const int64_t in_start = start * in_size;
      const int64_t in_end = limit * in_size;
      EigenMatrixMap in_shard(input_backprop_flat.data() + in_start, 1, in_end - in_start);
      in_shard.setConstant(T(0));

      
      const int out_size = out_height * out_width * depth;
      const int out_start = start * out_size;
      const int out_end = limit * out_size;
      for (int index = out_start; index < out_end; ++index) {
        int input_backprop_index = out_arg_max_flat(index);
        
        
        
        
        
        FastBoundsCheck(input_backprop_index - in_start, in_end - in_start);
        if (index < out_backprop.NumElements()) {
          input_backprop_flat(input_backprop_index) += out_backprop_flat(index);
        }
      }
    }
  };

  const int64_t shard_cost = params.tensor_in_rows * params.tensor_in_cols * params.depth * params.window_rows * params.window_cols;

  Shard(worker_threads.num_threads, worker_threads.workers, params.tensor_in_batch, shard_cost, shard);
}







template <class Device, class T> class MaxPoolingGradOp : public OpKernel {
 public:
  explicit MaxPoolingGradOp(OpKernelConstruction* context) : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument("Default MaxPoolingGradOp only supports NHWC ", "on device type ", DeviceTypeString(context->device_type())));




    if (context->num_inputs() == 3) {
      OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
      OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

      OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
      OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

      OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

      OP_REQUIRES( context, ksize_[3] == 1 && stride_[3] == 1, errors::Unimplemented( "MaxPoolingGrad is not yet supported on the depth dimension."));


    }

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));

    if (padding_ == Padding::EXPLICIT) {
      OP_REQUIRES_OK( context, context->GetAttr("explicit_paddings", &explicit_paddings_));
      OP_REQUIRES_OK(context, CheckValidPadding(padding_, explicit_paddings_, 4, data_format_));
    }
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    const Tensor& tensor_out = context->input(1);
    const Tensor& out_backprop = context->input(2);

    
    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional"));
    OP_REQUIRES(context, tensor_out.dims() == 4, errors::InvalidArgument("tensor_out must be 4-dimensional"));
    
    OP_REQUIRES(context, out_backprop.dims() == 4, errors::InvalidArgument("out_backprop must be 4-dimensional"));

    const TensorShape& output_shape = tensor_in.shape();

    Tensor tensor_out_dup;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_temp( {1}, DataTypeToEnum<T>::v(), tensor_out.shape(), &tensor_out_dup));

    Tensor tensor_out_arg_max;
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<int64>::v(), tensor_out.shape(), &tensor_out_arg_max));

    std::vector<int32> ksize = ksize_;
    std::vector<int32> stride = stride_;
    if (context->num_inputs() == 5) {
      const Tensor& tensor_ksize = context->input(3);
      auto value_ksize = tensor_ksize.flat<int32>();
      ksize.resize(tensor_ksize.shape().num_elements());
      std::copy_n(&value_ksize(0), ksize.size(), ksize.begin());

      const Tensor& tensor_stride = context->input(4);
      auto value_stride = tensor_stride.flat<int32>();
      stride.resize(tensor_stride.shape().num_elements());
      std::copy_n(&value_stride(0), stride.size(), stride.begin());
    }

    OP_REQUIRES(context, ksize.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES(context, stride.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    OP_REQUIRES(context, ksize[0] == 1 && stride[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    OP_REQUIRES( context, ksize[3] == 1 && stride[3] == 1, errors::Unimplemented( "MaxPoolingGrad is not yet supported on the depth dimension."));



    PoolParameters params{context, ksize, stride, padding_, explicit_paddings_, FORMAT_NHWC, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_output( {0}, 0, output_shape, &output));

    SpatialMaxPoolWithArgMaxHelper<CPUDevice, T, int64>( context, &tensor_out_dup, &tensor_out_arg_max, output, tensor_in, out_backprop, params, true);

  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  std::vector<int64> explicit_paddings_;
  TensorFormat data_format_;
};



template <class T> class MaxPoolingGradOp<Eigen::GpuDevice, T> : public OpKernel {
 public:
  typedef Eigen::GpuDevice Device;

  explicit MaxPoolingGradOp(OpKernelConstruction* context) : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    if (context->num_inputs() == 3) {
      OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
      OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

      OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
      OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

      const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
      const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
      OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    }
    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    if (padding_ == Padding::EXPLICIT) {
      OP_REQUIRES_OK( context, context->GetAttr("explicit_paddings", &explicit_paddings_));
      OP_REQUIRES_OK(context, CheckValidPadding(padding_, explicit_paddings_, 4, data_format_));
    }
    TF_CHECK_OK(ReadBoolFromEnvVar("TF_ENABLE_MAXPOOL_NANPROP", false, &propagate_nans_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    const Tensor& tensor_out = context->input(1);
    const Tensor& out_backprop = context->input(2);

    
    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional 4"));
    OP_REQUIRES(context, tensor_out.dims() == 4, errors::InvalidArgument("tensor_out must be 4-dimensional"));
    
    OP_REQUIRES(context, out_backprop.dims() == 4, errors::InvalidArgument("out_backprop must be 4-dimensional"));

    TensorShape output_shape = tensor_in.shape();

    std::vector<int32> ksize = ksize_;
    std::vector<int32> stride = stride_;
    if (context->num_inputs() == 5) {
      const Tensor& tensor_ksize = context->input(3);
      auto value_ksize = tensor_ksize.flat<int32>();
      ksize.resize(tensor_ksize.shape().num_elements());
      std::copy_n(&value_ksize(0), ksize.size(), ksize.begin());

      const Tensor& tensor_stride = context->input(4);
      auto value_stride = tensor_stride.flat<int32>();
      stride.resize(tensor_stride.shape().num_elements());
      std::copy_n(&value_stride(0), stride.size(), stride.begin());
    }
    OP_REQUIRES(context, ksize.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES(context, stride.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    const int32_t ksize_n = GetTensorDim(ksize, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    int64_t pad_top, pad_bottom, pad_left, pad_right;
    if (padding_ == Padding::EXPLICIT) {
      GetExplicitPaddingForDim(explicit_paddings_, data_format_, 'H', &pad_top, &pad_bottom);

      GetExplicitPaddingForDim(explicit_paddings_, data_format_, 'W', &pad_left, &pad_right);

    }
    DnnPoolingGradOp<T>::Compute(context, se::dnn::PoolingMode::kMaximum, ksize, stride, padding_, explicit_paddings_, data_format_, &tensor_in, &tensor_out, out_backprop, output_shape, propagate_nans_);


  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  std::vector<int64> explicit_paddings_;
  TensorFormat data_format_;
  bool propagate_nans_;
};









template <class Device, class T> class MaxPoolingGradGradOp : public OpKernel {
 public:
  explicit MaxPoolingGradGradOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Default MaxPoolingGradGradOp only supports NHWC ", "on device type ", DeviceTypeString(context->device_type())));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));

    if (context->num_inputs() == 3) {
      OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
      OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

      OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
      OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

      OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

      OP_REQUIRES(context, ksize_[3] == 1 && stride_[3] == 1, errors::Unimplemented("MaxPoolingGradGrad is not yet " "supported on the depth dimension."));

    }
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    const Tensor& tensor_out = context->input(1);
    const Tensor& out_grad_backprop = context->input(2);

    
    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional"));
    OP_REQUIRES(context, tensor_out.dims() == 4, errors::InvalidArgument("tensor_out must be 4-dimensional"));
    
    OP_REQUIRES( context, out_grad_backprop.dims() == 4, errors::InvalidArgument("out_grad_backprop must be 4-dimensional"));


    std::vector<int32> ksize = ksize_;
    std::vector<int32> stride = stride_;
    if (context->num_inputs() == 5) {
      const Tensor& tensor_ksize = context->input(3);
      auto value_ksize = tensor_ksize.flat<int32>();
      ksize.resize(tensor_ksize.shape().num_elements());
      std::copy_n(&value_ksize(0), ksize.size(), ksize.begin());

      const Tensor& tensor_stride = context->input(4);
      auto value_stride = tensor_stride.flat<int32>();
      stride.resize(tensor_stride.shape().num_elements());
      std::copy_n(&value_stride(0), stride.size(), stride.begin());
    }

    OP_REQUIRES(context, ksize.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES(context, stride.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    OP_REQUIRES(context, ksize[0] == 1 && stride[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    OP_REQUIRES( context, ksize[3] == 1 && stride[3] == 1, errors::Unimplemented( "MaxPoolingGrad is not yet supported on the depth dimension."));



    PoolParameters params{context, ksize, stride, padding_, , FORMAT_NHWC, tensor_in.shape()};





    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_output( {2}, 0, tensor_out.shape(), &output));

    SpatialMaxPoolGradGrad(context, output, tensor_in, tensor_out, out_grad_backprop, params, padding_);
  }

 private:
  void SpatialMaxPoolGradGrad(OpKernelContext* context, Tensor* bottom_diff, const Tensor& tensor_in, const Tensor& tensor_out, const Tensor& top_diff, const PoolParameters& params, const Padding& padding) {



    typedef Eigen::Map<const Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> ConstEigenMatrixMap;
    typedef Eigen::Map<Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> EigenMatrixMap;

    ConstEigenMatrixMap in_mat( tensor_in.flat<T>().data(), params.depth, params.tensor_in_cols * params.tensor_in_rows * params.tensor_in_batch);

    ConstEigenMatrixMap out_mat( tensor_out.flat<T>().data(), params.depth, params.out_width * params.out_height * params.tensor_in_batch);

    ConstEigenMatrixMap top_diff_mat( top_diff.flat<T>().data(), params.depth, params.tensor_in_cols * params.tensor_in_rows * params.tensor_in_batch);

    EigenMatrixMap bottom_diff_mat( bottom_diff->flat<T>().data(), params.depth, params.out_width * params.out_height * params.tensor_in_batch);


    const DeviceBase::CpuWorkerThreads& worker_threads = *(context->device()->tensorflow_cpu_worker_threads());

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    auto shard = [&params, &in_mat, &out_mat, &top_diff_mat, &bottom_diff_mat]( int64_t start, int64_t limit) {
      const int32_t depth = params.depth;
      const int32_t in_rows = params.tensor_in_rows;
      const int32_t in_cols = params.tensor_in_cols;
      const int32_t pad_top = params.pad_top;
      const int32_t pad_left = params.pad_left;
      const int32_t window_rows = params.window_rows;
      const int32_t window_cols = params.window_cols;
      const int32_t row_stride = params.row_stride;
      const int32_t col_stride = params.col_stride;
      const int32_t out_height = params.out_height;
      const int32_t out_width = params.out_width;

      {
        
        const int32_t output_image_size = out_height * out_width * params.depth;
        EigenMatrixMap bottom_diff_shard( bottom_diff_mat.data() + start * output_image_size, 1, (limit - start) * output_image_size);

        bottom_diff_shard.setZero();
      }

      for (int b = start; b < limit; ++b) {
        for (int ph = 0; ph < out_height; ++ph) {
          for (int pw = 0; pw < out_width; ++pw) {
            
            
            int h_start = ph * row_stride - pad_top;
            const int h_end = std::min(h_start + window_rows, in_rows);
            int w_start = pw * col_stride - pad_left;
            const int w_end = std::min(w_start + window_cols, in_cols);
            h_start = std::max(h_start, 0);
            w_start = std::max(w_start, 0);
            const int out_index = (b * out_height + ph) * out_width + pw;
            
            for (int d = 0; d < depth; ++d) {
              const T& output_ref = out_mat.coeffRef(d, out_index);
              bool should_stop = false;
              for (int h = h_start; h < h_end && !should_stop; ++h) {
                for (int w = w_start; w < w_end && !should_stop; ++w) {
                  const int in_index = (b * in_rows + h) * in_cols + w;
                  const T& input_ref = in_mat.coeffRef(d, in_index);
                  if (output_ref == input_ref) {
                    T& bottom_diff_ref = bottom_diff_mat.coeffRef(d, out_index);
                    bottom_diff_ref = top_diff_mat.coeffRef(d, in_index);
                    should_stop = true;
                  }
                }
              }
            }
          }
        }
      }
    };

    const int64_t shard_cost = params.out_width * params.out_height * params.depth * params.window_rows * params.window_cols;

    Shard(worker_threads.num_threads, worker_threads.workers, params.tensor_in_batch, shard_cost, shard);
  }

  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};



template <class T> class MaxPoolingGradGradOp<Eigen::GpuDevice, T> : public OpKernel {
 public:
  typedef Eigen::GpuDevice Device;

  explicit MaxPoolingGradGradOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    if (context->num_inputs() == 3) {
      OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
      OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

      OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
      OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

      const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
      const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
      OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    }
    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    const Tensor& tensor_out = context->input(1);
    const Tensor& out_grad_backprop = context->input(2);

    
    OP_REQUIRES(context, tensor_in.dims() == 4, errors::InvalidArgument("tensor_in must be 4-dimensional 4"));
    OP_REQUIRES(context, tensor_out.dims() == 4, errors::InvalidArgument("tensor_out must be 4-dimensional"));
    
    OP_REQUIRES( context, out_grad_backprop.dims() == 4, errors::InvalidArgument("out_grad_backprop must be 4-dimensional"));


    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, tensor_out.shape(), &output));

    std::vector<int32> ksize = ksize_;
    std::vector<int32> stride = stride_;
    if (context->num_inputs() == 5) {
      const Tensor& tensor_ksize = context->input(3);
      auto value_ksize = tensor_ksize.flat<int32>();
      ksize.resize(tensor_ksize.shape().num_elements());
      std::copy_n(&value_ksize(0), ksize.size(), ksize.begin());

      const Tensor& tensor_stride = context->input(4);
      auto value_stride = tensor_stride.flat<int32>();
      stride.resize(tensor_stride.shape().num_elements());
      std::copy_n(&value_stride(0), stride.size(), stride.begin());
    }

    OP_REQUIRES(context, ksize.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES(context, stride.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

    const int32_t ksize_n = GetTensorDim(ksize, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));


    PoolParameters params{context, ksize, stride, padding_, , data_format_, tensor_in.shape()};






    functor::MaxPoolGradBackwardNoMask<T>()( data_format_, tensor_in.flat<T>().data(), tensor_out.flat<T>().data(), params.tensor_in_batch, params.out_height, params.out_width, params.depth, params.tensor_in_rows, params.tensor_in_cols, params.window_rows, params.window_cols, params.row_stride, params.col_stride, params.pad_top, params.pad_left, out_grad_backprop.flat<T>().data(), output->flat<T>().data(), context->eigen_device<Eigen::GpuDevice>());






  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool use_dnn_;
};



template <typename Device, typename T> struct LaunchMaxPoolingNoMask;

template <typename Device, typename T> class MaxPoolingNoMaskOp : public OpKernel {
 public:
  explicit MaxPoolingNoMaskOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Default MaxPoolingNoMaskOp only supports NHWC on device type ", DeviceTypeString(context->device_type())));



    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    OP_REQUIRES( context, padding_ != EXPLICIT, errors::Unimplemented( "Explicit padding is not supported for MaxPoolingNoMaskOp."));


  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);

    PoolParameters params{context, ksize_, stride_, padding_, , data_format_, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape({params.tensor_in_batch, params.out_height, params.out_width, params.depth});
    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));

    LaunchMaxPoolingNoMask<Device, T>::launch(context, params, tensor_in, output);
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};

template <typename Device, typename T> class MaxPoolingNoMaskV2Op : public OpKernel {
 public:
  explicit MaxPoolingNoMaskV2Op(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Default MaxPoolingNoMaskOp only supports NHWC on device type ", DeviceTypeString(context->device_type())));



    if (context->num_inputs() == 1) {
      OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
      OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

      OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
      OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

      OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    }
    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);

    std::vector<int32> ksize = ksize_;
    std::vector<int32> stride = stride_;

    if (context->num_inputs() != 1) {
      const Tensor& tensor_ksize = context->input(1);
      auto value_ksize = tensor_ksize.flat<int32>();
      ksize.resize(tensor_ksize.shape().num_elements());
      std::copy_n(&value_ksize(0), ksize.size(), ksize.begin());

      const Tensor& tensor_stride = context->input(2);
      auto value_stride = tensor_stride.flat<int32>();
      stride.resize(tensor_stride.shape().num_elements());
      std::copy_n(&value_stride(0), stride.size(), stride.begin());
    }
    OP_REQUIRES(context, ksize.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES(context, stride.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES(context, ksize[0] == 1 && stride[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    PoolParameters params{context, ksize, stride, padding_, , data_format_, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape({params.tensor_in_batch, params.out_height, params.out_width, params.depth});
    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));

    LaunchMaxPoolingNoMask<Device, T>::launch(context, params, tensor_in, output);
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
};

template <typename Device, typename T, typename Targmax> struct LaunchMaxPoolingWithArgmax;

template <typename T, typename Targmax> struct LaunchMaxPoolingWithArgmax<CPUDevice, T, Targmax> {
  static void launch(OpKernelContext* context, const PoolParameters& params, const Tensor& input, Tensor* output, Tensor* argmax, bool propagate_nans, bool include_batch_in_index) {

    Tensor unused;
    SpatialMaxPoolWithArgMaxHelper<CPUDevice, T, Targmax>( context, output, argmax, nullptr, input, unused, params, include_batch_in_index);

  }
};

template <typename Device, typename T, typename Targmax> class MaxPoolingWithArgmaxOp : public OpKernel {
 public:
  explicit MaxPoolingWithArgmaxOp(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    OP_REQUIRES_OK(context, context->GetAttr("include_batch_in_index", &include_batch_in_index_));
    TF_CHECK_OK(ReadBoolFromEnvVar("TF_ENABLE_MAXPOOL_NANPROP", false, &propagate_nans_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);

    PoolParameters params{context, ksize_, stride_, padding_, , FORMAT_NHWC, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape({params.tensor_in_batch, params.out_height, params.out_width, params.depth});
    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));
    Tensor* argmax = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(1, out_shape, &argmax));

    LaunchMaxPoolingWithArgmax<Device, T, Targmax>::launch( context, params, tensor_in, output, argmax, propagate_nans_, include_batch_in_index_);

  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  bool propagate_nans_;
  bool include_batch_in_index_;
};

template <typename Device, typename T> struct LaunchMaxPoolingGradWithArgmax;

template <typename T> struct LaunchMaxPoolingGradWithArgmax<CPUDevice, T> {
  typedef Eigen::Map<Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> EigenMatrixMap;

  static void launch(OpKernelContext* context, const PoolParameters& params, const Tensor& grad_in, const Tensor& argmax, Tensor* grad_out, const bool include_batch_in_index) {

    const DeviceBase::CpuWorkerThreads& worker_threads = *(context->device()->tensorflow_cpu_worker_threads());

    auto shard = [&grad_in, &argmax, &grad_out, include_batch_in_index]( int64_t start, int64_t limit) {
      const int64_t batch_size = GetTensorDim(grad_out->shape(), FORMAT_NHWC, 'N');
      const int64_t output_size_per_batch = grad_out->NumElements() / batch_size;
      const int64_t input_size_per_batch = grad_in.NumElements() / batch_size;

      {
        auto grad_out_flat = grad_out->flat<T>();
        auto argmax_flat = argmax.flat<int64>();
        auto grad_in_flat = grad_in.flat<T>();

        const int64_t output_start = start * output_size_per_batch;
        const int64_t output_end = limit * output_size_per_batch;
        EigenMatrixMap inputShard(grad_out_flat.data() + output_start, 1, output_end - output_start);
        inputShard.setConstant(T(0));

        const int input_start = start * input_size_per_batch;
        const int input_end = limit * input_size_per_batch;
        for (int64_t index = input_start; index < input_end; index++) {
          if (index >= argmax.NumElements()) {
            break;
          }
          int64_t grad_out_index = argmax_flat(index);
          if (!include_batch_in_index) {
            const int64_t cur_batch = index / input_size_per_batch;
            grad_out_index += cur_batch * output_size_per_batch;
          }
          CHECK(grad_out_index >= output_start && grad_out_index < output_end)
              << "Invalid output gradient index: " << grad_out_index << ", " << output_start << ", " << output_end;
          grad_out_flat(grad_out_index) += grad_in_flat(index);
        }
      }
    };

    const int64_t batch_size = GetTensorDim(grad_out->shape(), FORMAT_NHWC, 'N');
    const int64_t shard_cost = grad_out->NumElements() / batch_size;
    Shard(worker_threads.num_threads, worker_threads.workers, batch_size, shard_cost, shard);
  }
};


template <typename Device, typename T> class MaxPoolingGradWithArgmaxOp : public OpKernel {
 public:
  explicit MaxPoolingGradWithArgmaxOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format_str;
    auto status = context->GetAttr("data_format", &data_format_str);
    if (status.ok()) {
      OP_REQUIRES(context, FormatFromString(data_format_str, &data_format_), errors::InvalidArgument("Invalid data format"));
    }

    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    OP_REQUIRES_OK(context, context->GetAttr("include_batch_in_index", &include_batch_in_index_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    const Tensor& grad_in = context->input(1);
    const Tensor& argmax = context->input(2);

    PoolParameters params{context, ksize_, stride_, padding_, , FORMAT_NHWC, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape({params.tensor_in_batch, params.tensor_in_rows, params.tensor_in_cols, params.depth});
    Tensor* grad_out = nullptr;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_output( {0}, 0, out_shape, &grad_out));

    if (out_shape.num_elements() == 0) return;  

    LaunchMaxPoolingGradWithArgmax<Device, T>::launch( context, params, grad_in, argmax, grad_out, include_batch_in_index_);
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool include_batch_in_index_;
};

template <typename Device, typename T> struct LaunchMaxPoolingGradGradWithArgmax;

template <typename Device, typename T> class MaxPoolingGradGradWithArgmaxOp : public OpKernel {
 public:
  explicit MaxPoolingGradGradWithArgmaxOp(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES(context, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    OP_REQUIRES_OK(context, context->GetAttr("include_batch_in_index", &include_batch_in_index_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);
    const Tensor& grad_in = context->input(1);
    const Tensor& argmax = context->input(2);

    PoolParameters params{context, ksize_, stride_, padding_, , FORMAT_NHWC, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape({params.tensor_in_batch, params.out_height, params.out_width, params.depth});

    Tensor* grad_out = nullptr;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_output( {0}, 0, out_shape, &grad_out));

    LaunchMaxPoolingGradGradWithArgmax<Device, T>::launch( context, params, grad_in, argmax, grad_out, include_batch_in_index_);
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  bool include_batch_in_index_;
};


template <typename T> class MaxPoolingNoMaskOp<GPUDevice, T> : public OpKernel {
 public:
  typedef GPUDevice Device;
  explicit MaxPoolingNoMaskOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
    OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    OP_REQUIRES_OK(context, context->GetAttr("explicit_paddings", &explicit_paddings_));
    const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));


    TF_CHECK_OK(ReadBoolFromEnvVar("TF_ENABLE_MAXPOOL_NANPROP", false, &propagate_nans_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);

    PoolParameters params{
        context,      ksize_,           stride_, padding_, explicit_paddings_, data_format_, tensor_in.shape()};
    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape = ShapeFromFormat(data_format_, params.tensor_in_batch, params.out_height, params.out_width, params.depth);


    
    constexpr bool is_int8x4 = std::is_same<T, qint8>::value;
    OP_REQUIRES(context, (is_int8x4 == (data_format_ == FORMAT_NCHW_VECT_C)), errors::InvalidArgument( "qint8 should be used with data_format NCHW_VECT_C."));



    DnnPoolingOp<T>::Compute(context, se::dnn::PoolingMode::kMaximum, ksize_, stride_, padding_, explicit_paddings_, data_format_, tensor_in, out_shape, propagate_nans_);



    
    if (!is_int8x4 && data_format_ == FORMAT_NCHW) {
      DnnPoolingOp<T>::Compute(context, se::dnn::PoolingMode::kMaximum, ksize_, stride_, padding_, explicit_paddings_, data_format_, tensor_in, out_shape, propagate_nans_);


    } else {

      OP_REQUIRES(context, padding_ != EXPLICIT, errors::Unimplemented("Explicit padding is not supported ", "when CUDNN is not enabled."));


      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));
      if (is_int8x4) {
        LaunchMaxPoolingNoMask_NCHW_VECT_C<Device>::launch(context, params, tensor_in, output);
      } else if (data_format_ == FORMAT_NHWC) {
        LaunchMaxPoolingNoMask<Device, T>::launch(context, params, tensor_in, output, propagate_nans_);
      } else {
        LOG(FATAL) << "MaxPool currently only supports the following (layout, " "type) combinations: (NHWC, non-qint8), " "(NCHW, non-qint8) or (NCHW_VECT_C, qint8). The " "requested combination (" << ToString(data_format_) << ", " << DataTypeString(DataTypeToEnum<T>::v())




                   << ") is not supported.";
      }
    }

  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  std::vector<int64> explicit_paddings_;
  TensorFormat data_format_;
  bool propagate_nans_;
};

template <typename T> class MaxPoolingNoMaskV2Op<GPUDevice, T> : public OpKernel {
 public:
  typedef GPUDevice Device;
  explicit MaxPoolingNoMaskV2Op(OpKernelConstruction* context)
      : OpKernel(context) {
    string data_format;
    OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
    OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    if (context->num_inputs() == 1) {
      OP_REQUIRES_OK(context, context->GetAttr("ksize", &ksize_));
      OP_REQUIRES(context, ksize_.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

      OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
      OP_REQUIRES(context, stride_.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

      const int32_t ksize_n = GetTensorDim(ksize_, data_format_, 'N');
      const int32_t stride_n = GetTensorDim(stride_, data_format_, 'N');
      OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));

    }
    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    TF_CHECK_OK(ReadBoolFromEnvVar("TF_ENABLE_MAXPOOL_NANPROP", false, &propagate_nans_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);

    std::vector<int32> ksize = ksize_;
    std::vector<int32> stride = stride_;

    if (context->num_inputs() != 1) {
      const Tensor& tensor_ksize = context->input(1);
      auto value_ksize = tensor_ksize.flat<int32>();
      ksize.resize(tensor_ksize.shape().num_elements());
      std::copy_n(&value_ksize(0), ksize.size(), ksize.begin());

      const Tensor& tensor_stride = context->input(2);
      auto value_stride = tensor_stride.flat<int32>();
      stride.resize(tensor_stride.shape().num_elements());
      std::copy_n(&value_stride(0), stride.size(), stride.begin());
    }
    OP_REQUIRES(context, ksize.size() == 4, errors::InvalidArgument("Sliding window ksize field must " "specify 4 dimensions"));

    OP_REQUIRES(context, stride.size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

    const int32_t ksize_n = GetTensorDim(ksize, data_format_, 'N');
    const int32_t stride_n = GetTensorDim(stride, data_format_, 'N');
    OP_REQUIRES(context, ksize_n == 1 && stride_n == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));


    PoolParameters params{context, ksize, stride, padding_, , data_format_, tensor_in.shape()};





    if (!context->status().ok()) {
      return;
    }

    TensorShape out_shape = ShapeFromFormat(data_format_, params.tensor_in_batch, params.out_height, params.out_width, params.depth);

    if (data_format_ == FORMAT_NCHW) {
      DnnPoolingOp<T>::Compute(context, se::dnn::PoolingMode::kMaximum, ksize, stride, padding_, explicit_paddings_, data_format_, tensor_in, out_shape, propagate_nans_);


    } else {
      CHECK(data_format_ == FORMAT_NHWC)
          << "MaxPool only supports NCHW or NHWC format";
      Tensor* output = nullptr;
      OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));
      LaunchMaxPoolingNoMask<Device, T>::launch(context, params, tensor_in, output, propagate_nans_);
    }
  }

 private:
  std::vector<int32> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  std::vector<int64> explicit_paddings_;
  TensorFormat data_format_;
  bool propagate_nans_;
};

template <typename T> struct LaunchMaxPoolingNoMask<Eigen::GpuDevice, T> {
  static void launch(OpKernelContext* context, const PoolParameters& params, const Tensor& input, Tensor* output, bool propagate_nans) {
    bool status = functor::MaxPoolForwardWithOptionalArgmax<T>()( input.flat<T>().data(), params.tensor_in_batch, params.tensor_in_rows, params.tensor_in_cols, params.depth, params.out_height, params.out_width, params.window_rows, params.window_cols, params.row_stride, params.col_stride, params.pad_top, params.pad_left, output->flat<T>().data(), nullptr, context->eigen_gpu_device(), propagate_nans, false);





    if (!status) {
      context->SetStatus( errors::Internal("Failed launching MaxPoolForwardNoMask"));
    }
  }
};

template <typename T> struct LaunchMaxPoolingWithArgmax<Eigen::GpuDevice, T, int64> {
  static void launch(OpKernelContext* context, const PoolParameters& params, const Tensor& input, Tensor* output, Tensor* argmax, bool propagate_nans, bool include_batch_in_index) {

    bool status = functor::MaxPoolForwardWithOptionalArgmax<T>()( input.flat<T>().data(), params.tensor_in_batch, params.tensor_in_rows, params.tensor_in_cols, params.depth, params.out_height, params.out_width, params.window_rows, params.window_cols, params.row_stride, params.col_stride, params.pad_top, params.pad_left, output->flat<T>().data(), reinterpret_cast<int64*>(argmax->flat<int64>().data()), context->eigen_gpu_device(), propagate_nans, include_batch_in_index);






    if (!status) {
      context->SetStatus( errors::Internal("Failed launching MaxPoolForwardWithArgmax"));
    }
  }
};

template <typename T> struct LaunchMaxPoolingGradWithArgmax<Eigen::GpuDevice, T> {
  static void launch(OpKernelContext* context, const PoolParameters& params, const Tensor& grad_in, const Tensor& argmax, Tensor* grad_out, const bool include_batch_in_index) {

    const int input_size = params.tensor_in_batch * params.tensor_in_rows * params.tensor_in_cols * params.depth;
    const int output_size = params.tensor_in_batch * params.out_height * params.out_width * params.depth;
    const int top_offset = params.out_height * params.out_width * params.depth;
    const int bottom_offset = params.tensor_in_rows * params.tensor_in_cols * params.depth;
    bool status = functor::MaxPoolBackwardWithArgmax<T>()( output_size, input_size, grad_in.flat<T>().data(), reinterpret_cast<const int64*>(argmax.flat<int64>().data()), top_offset, bottom_offset, grad_out->flat<T>().data(), context->eigen_gpu_device(), include_batch_in_index);



    if (!status) {
      context->SetStatus( errors::Internal("Failed launching MaxPoolBackwardWithArgmax"));
    }
  }
};

template <typename T> struct LaunchMaxPoolingGradGradWithArgmax<Eigen::GpuDevice, T> {
  static void launch(OpKernelContext* context, const PoolParameters& params, const Tensor& grad_in, const Tensor& argmax, Tensor* grad_out, const bool include_batch_in_index) {

    const int input_size = params.tensor_in_batch * params.tensor_in_rows * params.tensor_in_cols * params.depth;
    const int output_size = params.tensor_in_batch * params.out_height * params.out_width * params.depth;
    const int top_offset = params.tensor_in_rows * params.tensor_in_cols * params.depth;
    const int bottom_offset = params.out_width * params.out_height * params.depth;
    bool status = functor::MaxPoolGradBackwardWithArgmax<T>()( output_size, input_size, grad_in.flat<T>().data(), reinterpret_cast<const int64*>(argmax.flat<int64>().data()), top_offset, bottom_offset, grad_out->flat<T>().data(), context->eigen_gpu_device(), include_batch_in_index);



    if (!status) {
      context->SetStatus( errors::Internal("Failed launching MaxPoolGradBackwardWithArgmax"));
    }
  }
};












































TF_CALL_REAL_NUMBER_TYPES(REGISTER_CPU_ONLY_POOL_KERNELS);



TF_CALL_REAL_NUMBER_TYPES(REGISTER_CPU_MAX_POOL_KERNELS);





namespace functor {








TF_CALL_GPU_NUMBER_TYPES(DECLARE_GPU_SPEC);

}  


TF_CALL_GPU_NUMBER_TYPES(REGISTER_GPU_MAX_POOL_KERNELS);

































TF_CALL_GPU_NUMBER_TYPES(REGISTER_GPU_ONLY_POOL_KERNELS);



REGISTER_KERNEL_BUILDER( Name("MaxPool").Device(DEVICE_GPU).TypeConstraint<qint8>("T"), MaxPoolingNoMaskOp<GPUDevice, qint8>);


REGISTER_KERNEL_BUILDER(Name("MaxPoolV2")
                            .Device(DEVICE_GPU)
                            .HostMemory("ksize")
                            .HostMemory("strides")
                            .TypeConstraint<qint8>("T"), MaxPoolingV2Op<GPUDevice, qint8>);

REGISTER_KERNEL_BUILDER(Name("MaxPoolV2")
                            .Device(DEVICE_GPU)
                            .HostMemory("ksize")
                            .HostMemory("strides")
                            .TypeConstraint<qint8>("T")
                            .Label("eigen_tensor"), MaxPoolingV2Op<GPUDevice, qint8>);








}  
