























namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

void ParseAttributes(OpKernelConstruction* context, std::vector<int32>* strides, std::vector<int32>* rates, Padding* padding) {
  OP_REQUIRES_OK(context, context->GetAttr("strides", strides));
  OP_REQUIRES(context, strides->size() == 4, errors::InvalidArgument("Sliding window stride field must " "specify 4 dimensions"));

  OP_REQUIRES(context, (*strides)[0] == 1 && (*strides)[3] == 1, errors::Unimplemented( "Stride is only supported across spatial dimensions."));


  OP_REQUIRES_OK(context, context->GetAttr("rates", rates));
  OP_REQUIRES(context, rates->size() == 4, errors::InvalidArgument("Input stride (atrous rate) field " "must specify 4 dimensions"));

  OP_REQUIRES(context, (*rates)[0] == 1 && (*rates)[3] == 1, errors::Unimplemented( "Rate is only supported across spatial dimensions."));


  OP_REQUIRES_OK(context, context->GetAttr("padding", padding));
}

void ParseSizes(OpKernelContext* context, const std::vector<int32>& strides, const std::vector<int32>& rates, const Padding& padding, int* stride_rows, int* stride_cols, int* rate_rows, int* rate_cols, int64* pad_top, int64* pad_left, int64* out_rows, int64* out_cols) {



  
  
  const Tensor& input = context->input(0);
  OP_REQUIRES(context, input.dims() == 4, errors::InvalidArgument("input must be 4-dimensional", input.shape().DebugString()));

  const int input_rows = input.dim_size(1);
  const int input_cols = input.dim_size(2);
  const int depth = input.dim_size(3);

  
  
  *stride_rows = strides[1];
  *stride_cols = strides[2];
  *rate_rows = rates[1];
  *rate_cols = rates[2];

  
  
  const Tensor& filter = context->input(1);
  OP_REQUIRES(context, filter.dims() == 3, errors::InvalidArgument("filter must be 3-dimensional: ", filter.shape().DebugString()));

  const int filter_rows = filter.dim_size(0);
  const int filter_cols = filter.dim_size(1);
  OP_REQUIRES(context, depth == filter.dim_size(2), errors::InvalidArgument( "input and filter must have the same depth: ", depth, " vs ", filter.dim_size(2)));



  
  
  const int filter_rows_eff = filter_rows + (filter_rows - 1) * (*rate_rows - 1);
  const int filter_cols_eff = filter_cols + (filter_cols - 1) * (*rate_cols - 1);

  OP_REQUIRES_OK( context, GetWindowedOutputSize(input_rows, filter_rows_eff, *stride_rows, padding, out_rows, pad_top));

  OP_REQUIRES_OK( context, GetWindowedOutputSize(input_cols, filter_cols_eff, *stride_cols, padding, out_cols, pad_left));

}

template <typename Device, typename T> class DilationOp : public OpKernel {
 public:
  explicit DilationOp(OpKernelConstruction* context) : OpKernel(context) {
    ParseAttributes(context, &strides_, &rates_, &padding_);
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const Tensor& filter = context->input(1);

    
    int stride_rows = 0, stride_cols = 0;
    int rate_rows = 0, rate_cols = 0;
    int64 pad_top = 0, pad_left = 0;
    int64 out_rows = 0, out_cols = 0;
    ParseSizes(context, strides_, rates_, padding_, &stride_rows, &stride_cols, &rate_rows, &rate_cols, &pad_top, &pad_left, &out_rows, &out_cols);


    
    
    const int batch = input.dim_size(0);
    const int depth = input.dim_size(3);
    const std::vector<int64> out_sizes = {batch, out_rows, out_cols, depth};
    TensorShape out_shape(out_sizes);

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));

    
    if (out_shape.num_elements() == 0) {
      return;
    }

    functor::Dilation<Device, T>()( context->eigen_device<Device>(), input.tensor<T, 4>(), filter.tensor<T, 3>(), stride_rows, stride_cols, rate_rows, rate_cols, pad_top, pad_left, output->tensor<T, 4>());


  }

  std::vector<int32> strides_;
  std::vector<int32> rates_;
  Padding padding_;
};


namespace functor {
template <typename T> struct Dilation<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T, 4>::ConstTensor input, typename TTypes<T, 3>::ConstTensor filter, int stride_rows, int stride_cols, int rate_rows, int rate_cols, int pad_top, int pad_left, typename TTypes<T, 4>::Tensor output) {


    const int batch = input.dimension(0);
    const int input_rows = input.dimension(1);
    const int input_cols = input.dimension(2);
    const int depth = input.dimension(3);

    const int filter_rows = filter.dimension(0);
    const int filter_cols = filter.dimension(1);

    const int output_rows = output.dimension(1);
    const int output_cols = output.dimension(2);

    
    
    for (int b = 0; b < batch; ++b) {
      for (int h_out = 0; h_out < output_rows; ++h_out) {
        int h_beg = h_out * stride_rows - pad_top;
        for (int w_out = 0; w_out < output_cols; ++w_out) {
          int w_beg = w_out * stride_cols - pad_left;
          for (int d = 0; d < depth; ++d) {
            T cur_val = Eigen::NumTraits<T>::lowest();
            for (int h = 0; h < filter_rows; ++h) {
              const int h_in = h_beg + h * rate_rows;
              if (h_in >= 0 && h_in < input_rows) {
                for (int w = 0; w < filter_cols; ++w) {
                  const int w_in = w_beg + w * rate_cols;
                  if (w_in >= 0 && w_in < input_cols) {
                    const T val = input(b, h_in, w_in, d) + filter(h, w, d);
                    if (val > cur_val) {
                      cur_val = val;
                    }
                  }
                }
              }
            }
            output(b, h_out, w_out, d) = cur_val;
          }
        }
      }
    }
  }
};
}  

template <typename Device, typename T> class DilationBackpropInputOp : public OpKernel {
 public:
  explicit DilationBackpropInputOp(OpKernelConstruction* context)
      : OpKernel(context) {
    ParseAttributes(context, &strides_, &rates_, &padding_);
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const Tensor& filter = context->input(1);
    const Tensor& out_backprop = context->input(2);

    
    int stride_rows = 0, stride_cols = 0;
    int rate_rows = 0, rate_cols = 0;
    int64 pad_top = 0, pad_left = 0;
    int64 out_rows = 0, out_cols = 0;
    ParseSizes(context, strides_, rates_, padding_, &stride_rows, &stride_cols, &rate_rows, &rate_cols, &pad_top, &pad_left, &out_rows, &out_cols);


    
    
    const int batch = input.dim_size(0);
    const int depth = input.dim_size(3);
    OP_REQUIRES(context, batch == out_backprop.dim_size(0) && out_rows == out_backprop.dim_size(1) && out_cols == out_backprop.dim_size(2) && depth == out_backprop.dim_size(3), errors::InvalidArgument("out_backprop has incompatible size."));





    
    
    Tensor* in_backprop = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, input.shape(), &in_backprop));

    
    if (input.shape().num_elements() == 0) {
      return;
    }

    functor::DilationBackpropInput<Device, T>()( context->eigen_device<Device>(), input.tensor<T, 4>(), filter.tensor<T, 3>(), out_backprop.tensor<T, 4>(), stride_rows, stride_cols, rate_rows, rate_cols, pad_top, pad_left, in_backprop->tensor<T, 4>());



  }

  std::vector<int32> strides_;
  std::vector<int32> rates_;
  Padding padding_;
};


namespace functor {
template <typename T> struct DilationBackpropInput<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T, 4>::ConstTensor input, typename TTypes<T, 3>::ConstTensor filter, typename TTypes<T, 4>::ConstTensor out_backprop, int stride_rows, int stride_cols, int rate_rows, int rate_cols, int pad_top, int pad_left, typename TTypes<T, 4>::Tensor in_backprop) {




    const int batch = input.dimension(0);
    const int input_rows = input.dimension(1);
    const int input_cols = input.dimension(2);
    const int depth = input.dimension(3);

    const int filter_rows = filter.dimension(0);
    const int filter_cols = filter.dimension(1);

    const int output_rows = out_backprop.dimension(1);
    const int output_cols = out_backprop.dimension(2);

    
    in_backprop.setZero();

    
    
    
    
    
    for (int b = 0; b < batch; ++b) {
      for (int h_out = 0; h_out < output_rows; ++h_out) {
        int h_beg = h_out * stride_rows - pad_top;
        for (int w_out = 0; w_out < output_cols; ++w_out) {
          int w_beg = w_out * stride_cols - pad_left;
          for (int d = 0; d < depth; ++d) {
            T cur_val = Eigen::NumTraits<T>::lowest();
            int h_in_max = (h_beg < 0) ? 0 : h_beg;
            int w_in_max = (w_beg < 0) ? 0 : w_beg;
            for (int h = 0; h < filter_rows; ++h) {
              const int h_in = h_beg + h * rate_rows;
              if (h_in >= 0 && h_in < input_rows) {
                for (int w = 0; w < filter_cols; ++w) {
                  const int w_in = w_beg + w * rate_cols;
                  if (w_in >= 0 && w_in < input_cols) {
                    const T val = input(b, h_in, w_in, d) + filter(h, w, d);
                    if (val > cur_val) {
                      cur_val = val;
                      h_in_max = h_in;
                      w_in_max = w_in;
                    }
                  }
                }
              }
            }
            in_backprop(b, h_in_max, w_in_max, d) += out_backprop(b, h_out, w_out, d);
          }
        }
      }
    }
  }
};
}  

template <typename Device, typename T> class DilationBackpropFilterOp : public OpKernel {
 public:
  explicit DilationBackpropFilterOp(OpKernelConstruction* context)
      : OpKernel(context) {
    ParseAttributes(context, &strides_, &rates_, &padding_);
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const Tensor& filter = context->input(1);
    const Tensor& out_backprop = context->input(2);

    
    int stride_rows = 0, stride_cols = 0;
    int rate_rows = 0, rate_cols = 0;
    int64 pad_top = 0, pad_left = 0;
    int64 out_rows = 0, out_cols = 0;
    ParseSizes(context, strides_, rates_, padding_, &stride_rows, &stride_cols, &rate_rows, &rate_cols, &pad_top, &pad_left, &out_rows, &out_cols);


    
    
    const int batch = input.dim_size(0);
    const int depth = input.dim_size(3);
    OP_REQUIRES(context, batch == out_backprop.dim_size(0) && out_rows == out_backprop.dim_size(1) && out_cols == out_backprop.dim_size(2) && depth == out_backprop.dim_size(3), errors::InvalidArgument("out_backprop has incompatible size."));





    
    
    Tensor* filter_backprop = nullptr;
    OP_REQUIRES_OK( context, context->allocate_output(0, filter.shape(), &filter_backprop));

    
    if (filter.shape().num_elements() == 0) {
      return;
    }

    functor::DilationBackpropFilter<Device, T>()( context->eigen_device<Device>(), input.tensor<T, 4>(), filter.tensor<T, 3>(), out_backprop.tensor<T, 4>(), stride_rows, stride_cols, rate_rows, rate_cols, pad_top, pad_left, filter_backprop->tensor<T, 3>());



  }

  std::vector<int32> strides_;
  std::vector<int32> rates_;
  Padding padding_;
};


namespace functor {
template <typename T> struct DilationBackpropFilter<CPUDevice, T> {
  void operator()(const CPUDevice& d, typename TTypes<T, 4>::ConstTensor input, typename TTypes<T, 3>::ConstTensor filter, typename TTypes<T, 4>::ConstTensor out_backprop, int stride_rows, int stride_cols, int rate_rows, int rate_cols, int pad_top, int pad_left, typename TTypes<T, 3>::Tensor filter_backprop) {




    const int batch = input.dimension(0);
    const int input_rows = input.dimension(1);
    const int input_cols = input.dimension(2);
    const int depth = input.dimension(3);

    const int filter_rows = filter.dimension(0);
    const int filter_cols = filter.dimension(1);

    const int output_rows = out_backprop.dimension(1);
    const int output_cols = out_backprop.dimension(2);

    
    filter_backprop.setZero();

    
    
    
    
    
    for (int b = 0; b < batch; ++b) {
      for (int h_out = 0; h_out < output_rows; ++h_out) {
        int h_beg = h_out * stride_rows - pad_top;
        for (int w_out = 0; w_out < output_cols; ++w_out) {
          int w_beg = w_out * stride_cols - pad_left;
          for (int d = 0; d < depth; ++d) {
            T cur_val = Eigen::NumTraits<T>::lowest();
            int h_max = 0;
            int w_max = 0;
            for (int h = 0; h < filter_rows; ++h) {
              const int h_in = h_beg + h * rate_rows;
              if (h_in >= 0 && h_in < input_rows) {
                for (int w = 0; w < filter_cols; ++w) {
                  const int w_in = w_beg + w * rate_cols;
                  if (w_in >= 0 && w_in < input_cols) {
                    const T val = input(b, h_in, w_in, d) + filter(h, w, d);
                    if (val > cur_val) {
                      cur_val = val;
                      h_max = h;
                      w_max = w;
                    }
                  }
                }
              }
            }
            filter_backprop(h_max, w_max, d) += out_backprop(b, h_out, w_out, d);
          }
        }
      }
    }
  }
};
}  















TF_CALL_REAL_NUMBER_TYPES(REGISTER);



















TF_CALL_GPU_NUMBER_TYPES(REGISTER);





}  
