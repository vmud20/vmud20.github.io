


















namespace tensorflow {
typedef Eigen::ThreadPoolDevice CPUDevice;

template <typename T> class FractionalMaxPoolOp : public OpKernel {
 public:
  explicit FractionalMaxPoolOp(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("pooling_ratio", &pooling_ratio_));
    OP_REQUIRES_OK(context, context->GetAttr("pseudo_random", &pseudo_random_));
    OP_REQUIRES_OK(context, context->GetAttr("overlapping", &overlapping_));

    OP_REQUIRES(context, pooling_ratio_.size() == 4, errors::InvalidArgument("pooling_ratio field must " "specify 4 dimensions"));

    for (std::size_t i = 0; i < pooling_ratio_.size(); ++i) {
      OP_REQUIRES(context, pooling_ratio_[i] >= 1, errors::InvalidArgument( "pooling_ratio cannot be smaller than 1, got: ", pooling_ratio_[i]));


    }

    OP_REQUIRES( context, pooling_ratio_[0] == 1 || pooling_ratio_[3] == 1, errors::Unimplemented("Fractional max pooling is not yet " "supported on the batch nor channel dimension."));



    OP_REQUIRES_OK(context, context->GetAttr("deterministic", &deterministic_));
    OP_REQUIRES_OK(context, context->GetAttr("seed", &seed_));
    OP_REQUIRES_OK(context, context->GetAttr("seed2", &seed2_));
    if (deterministic_) {
      
      if ((seed_ == 0) && (seed2_ == 0)) {
        seed_ = random::New64();
        seed2_ = random::New64();
      }
    } else {
      OP_REQUIRES( context, (seed_ == 0) && (seed2_ == 0), errors::InvalidArgument( "Both seed and seed2 should be 0 if deterministic is false."));


    }
  }

  void Compute(OpKernelContext* context) override {
    typedef Eigen::Map<const Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> ConstEigenMatrixMap;
    typedef Eigen::Map<Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> EigenMatrixMap;

    constexpr int tensor_in_and_out_dims = 4;

    const Tensor& tensor_in = context->input(0);
    OP_REQUIRES(context, tensor_in.dims() == tensor_in_and_out_dims, errors::InvalidArgument("tensor_in must be 4-dimensional"));

    std::vector<int> input_size(tensor_in_and_out_dims);
    std::vector<int> output_size(tensor_in_and_out_dims);
    for (int i = 0; i < tensor_in_and_out_dims; ++i) {
      input_size[i] = tensor_in.dim_size(i);

      OP_REQUIRES( context, input_size[i] >= pooling_ratio_[i], errors::InvalidArgument("Pooling ratio is higher than input " "dimension size for dimension ", i, ". Input dim size: ", input_size[i], " pooling ratio: ", pooling_ratio_[i]));




    }
    
    for (int i = 0; i < tensor_in_and_out_dims; ++i) {
      
      
      output_size[i] = static_cast<int>(std::floor(input_size[i] / pooling_ratio_[i]));
      DCHECK_GT(output_size[i], 0);
    }

    
    std::vector<int64_t> height_cum_seq;
    std::vector<int64_t> width_cum_seq;
    GuardedPhiloxRandom generator;
    generator.Init(seed_, seed2_);
    height_cum_seq = GeneratePoolingSequence(input_size[1], output_size[1], &generator, pseudo_random_);
    width_cum_seq = GeneratePoolingSequence(input_size[2], output_size[2], &generator, pseudo_random_);

    
    Tensor* output_tensor = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output( 0, TensorShape({output_size[0], output_size[1], output_size[2], output_size[3]}), &output_tensor));



    Tensor* output_height_seq_tensor = nullptr;
    OP_REQUIRES_OK( context, context->allocate_output( 1, TensorShape({static_cast<int64_t>(height_cum_seq.size())}), &output_height_seq_tensor));



    Tensor* output_width_seq_tensor = nullptr;
    OP_REQUIRES_OK( context, context->allocate_output( 2, TensorShape({static_cast<int64_t>(width_cum_seq.size())}), &output_width_seq_tensor));




    ConstEigenMatrixMap in_mat(tensor_in.flat<T>().data(), input_size[3], input_size[2] * input_size[1] * input_size[0]);

    EigenMatrixMap out_mat(output_tensor->flat<T>().data(), output_size[3], output_size[2] * output_size[1] * output_size[0]);

    
    output_tensor->flat<T>().setConstant(Eigen::NumTraits<T>::lowest());

    auto output_height_seq_flat = output_height_seq_tensor->flat<int64_t>();
    auto output_width_seq_flat = output_width_seq_tensor->flat<int64_t>();

    
    for (int i = 0; i < height_cum_seq.size(); ++i) {
      output_height_seq_flat(i) = height_cum_seq[i];
    }

    for (int i = 0; i < width_cum_seq.size(); ++i) {
      output_width_seq_flat(i) = width_cum_seq[i];
    }

    
    
    
    
    
    const int64_t height_max = input_size[1] - 1;
    const int64_t width_max = input_size[2] - 1;
    for (int64_t b = 0; b < input_size[0]; ++b) {
      
      for (int64_t hs = 0; hs < height_cum_seq.size() - 1; ++hs) {
        
        const int64_t height_start = height_cum_seq[hs];
        int64_t height_end = overlapping_ ? height_cum_seq[hs + 1] : height_cum_seq[hs + 1] - 1;
        height_end = std::min(height_end, height_max);

        
        for (int64_t ws = 0; ws < width_cum_seq.size() - 1; ++ws) {
          const int64_t out_offset = (b * output_size[1] + hs) * output_size[2] + ws;
          
          const int64_t width_start = width_cum_seq[ws];
          int64_t width_end = overlapping_ ? width_cum_seq[ws + 1] : width_cum_seq[ws + 1] - 1;
          width_end = std::min(width_end, width_max);
          for (int64_t h = height_start; h <= height_end; ++h) {
            for (int64_t w = width_start; w <= width_end; ++w) {
              const int64_t in_offset = (b * input_size[1] + h) * input_size[2] + w;
              out_mat.col(out_offset) = out_mat.col(out_offset).cwiseMax(in_mat.col(in_offset));
            }
          }
        }
      }
    }
  }

 private:
  bool deterministic_;
  int64_t seed_;
  int64_t seed2_;
  std::vector<float> pooling_ratio_;
  bool pseudo_random_;
  bool overlapping_;
};





REGISTER_FRACTIONALMAXPOOL(int32);
REGISTER_FRACTIONALMAXPOOL(int64_t);
REGISTER_FRACTIONALMAXPOOL(float);
REGISTER_FRACTIONALMAXPOOL(double);



static const int kInvalidMaxPoolingIndex = -1;

template <class T> class FractionalMaxPoolGradOp : public OpKernel {
 public:
  explicit FractionalMaxPoolGradOp(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("overlapping", &overlapping_));
  }

  void Compute(OpKernelContext* context) override {
    
    
    
    
    
    
    
    typedef Eigen::Map<const Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> ConstEigenMatrixMap;
    typedef Eigen::Map<Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>> EigenMatrixMap;
    typedef Eigen::Map<Eigen::Matrix<int64, Eigen::Dynamic, Eigen::Dynamic>> EigenIndexMatrixMap;

    const Tensor& tensor_in = context->input(0);
    const Tensor& tensor_out = context->input(1);
    const Tensor& out_backprop = context->input(2);
    const Tensor& height_seq_tensor = context->input(3);
    const Tensor& width_seq_tensor = context->input(4);

    
    constexpr int tensor_in_and_out_dims = 4;
    OP_REQUIRES( context, tensor_in.dims() == tensor_in_and_out_dims, errors::InvalidArgument("orig_input should be a tensor of rank 4, got ", tensor_in.DebugString()));


    OP_REQUIRES(context, tensor_in.NumElements() > 0, errors::InvalidArgument("orig_input must not be empty, got ", tensor_in.DebugString()));

    OP_REQUIRES(context, tensor_out.dims() == tensor_in_and_out_dims, errors::InvalidArgument( "orig_output should be a tensor of rank 4, got ", tensor_out.DebugString()));


    OP_REQUIRES(context, tensor_out.NumElements() > 0, errors::InvalidArgument("orig_output must not be empty, got ", tensor_out.DebugString()));

    OP_REQUIRES( context, height_seq_tensor.NumElements() * width_seq_tensor.NumElements() <= tensor_in.NumElements(), errors::InvalidArgument( "Pooling region has more elements than the input tensor. " "row_pooling_sequence: ", height_seq_tensor.DebugString(), "col_pooling_sequence: ", width_seq_tensor.DebugString(), "orig_input: ", tensor_in.DebugString()));









    
    std::vector<int64_t> input_size(tensor_in_and_out_dims);
    std::vector<int64_t> output_size(tensor_in_and_out_dims);
    for (int i = 0; i < tensor_in_and_out_dims; ++i) {
      input_size[i] = tensor_in.dim_size(i);
    }
    for (int i = 0; i < tensor_in_and_out_dims; ++i) {
      output_size[i] = tensor_out.dim_size(i);
    }

    
    
    
    Tensor tensor_out_dup;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_temp( {1}, DataTypeToEnum<T>::v(), tensor_out.shape(), &tensor_out_dup));

    Tensor tensor_out_arg_max;
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<int64_t>::v(), tensor_out.shape(), &tensor_out_arg_max));

    
    ConstEigenMatrixMap tensor_in_mat( tensor_in.flat<T>().data(), input_size[3], input_size[2] * input_size[1] * input_size[0]);

    EigenMatrixMap tensor_out_dup_mat( tensor_out_dup.flat<T>().data(), output_size[3], output_size[2] * output_size[1] * output_size[0]);

    EigenIndexMatrixMap tensor_out_arg_max_mat( tensor_out_arg_max.flat<int64_t>().data(), output_size[3], output_size[2] * output_size[1] * output_size[0]);


    tensor_out_arg_max.flat<int64_t>().setConstant(kInvalidMaxPoolingIndex);
    
    tensor_out_dup.flat<T>().setConstant(Eigen::NumTraits<T>::lowest());

    auto height_seq_tensor_flat = height_seq_tensor.flat<int64_t>();
    auto width_seq_tensor_flat = width_seq_tensor.flat<int64_t>();

    
    
    
    
    
    
    const int64_t height_max = input_size[1] - 1;
    const int64_t width_max = input_size[2] - 1;
    for (int64_t b = 0; b < input_size[0]; ++b) {
      
      for (int64_t hs = 0; hs < height_seq_tensor.dim_size(0) - 1; ++hs) {
        
        const int64_t height_start = height_seq_tensor_flat(hs);
        int64_t height_end = overlapping_ ? height_seq_tensor_flat(hs + 1)
                                          : height_seq_tensor_flat(hs + 1) - 1;
        height_end = std::min(height_end, height_max);

        
        for (int64_t ws = 0; ws < width_seq_tensor.dim_size(0) - 1; ++ws) {
          const int64_t out_index = (b * output_size[1] + hs) * output_size[2] + ws;
          
          const int64_t width_start = width_seq_tensor_flat(ws);
          int64_t width_end = overlapping_ ? width_seq_tensor_flat(ws + 1)
                                           : width_seq_tensor_flat(ws + 1) - 1;
          width_end = std::min(width_end, width_max);
          for (int64_t h = height_start; h <= height_end; ++h) {
            for (int64_t w = width_start; w <= width_end; ++w) {
              const int64_t in_index = (b * input_size[1] + h) * input_size[2] + w;
              
              for (int64_t d = 0; d < input_size[3]; ++d) {
                const T& input_ref = tensor_in_mat.coeffRef(d, in_index);
                T& output_ref = tensor_out_dup_mat.coeffRef(d, out_index);
                int64_t& out_arg_max_ref = tensor_out_arg_max_mat.coeffRef(d, out_index);
                if (output_ref < input_ref || out_arg_max_ref == kInvalidMaxPoolingIndex) {
                  output_ref = input_ref;
                  int input_offset = in_index * input_size[3] + d;
                  out_arg_max_ref = input_offset;
                }
              }
            }
          }
        }
      }
    }

    
    ConstEigenMatrixMap tensor_out_mat( tensor_out.flat<T>().data(), output_size[3], output_size[2] * output_size[1] * output_size[0]);

    const int64_t num_reshaped_cols = output_size[2] * output_size[1] * output_size[0];
    for (int64_t i = 0; i < num_reshaped_cols; ++i) {
      for (int64_t j = 0; j < output_size[3]; ++j) {
        OP_REQUIRES(context, tensor_out_dup_mat(j, i) == tensor_out_mat(j, i), errors::InvalidArgument( "tensor_out_dup is not the same as tensor_out"));

      }
    }

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->forward_input_or_allocate_output( {0}, 0, tensor_in.shape(), &output));
    output->flat<T>().setZero();

    auto out_backprop_flat = out_backprop.flat<T>();
    auto input_backprop_flat = output->flat<T>();
    auto out_arg_max_flat = tensor_out_arg_max.flat<int64_t>();
    int num_total_outputs = out_backprop_flat.size();
    int num_total_inputs = input_backprop_flat.size();

    for (int index = 0; index < num_total_outputs; ++index) {
      int input_backprop_index = out_arg_max_flat(index);
      OP_REQUIRES( context, input_backprop_index >= 0 && input_backprop_index < num_total_inputs, errors::InvalidArgument( "Invalid input backprop index: ", input_backprop_index, ", ", num_total_inputs));




      input_backprop_flat(input_backprop_index) += out_backprop_flat(index);
    }
  }

 private:
  bool overlapping_;
};






REGISTER_FRACTIONALMAXPOOLGRAD(int32);
REGISTER_FRACTIONALMAXPOOLGRAD(int64_t);
REGISTER_FRACTIONALMAXPOOLGRAD(float);
REGISTER_FRACTIONALMAXPOOLGRAD(double);


}  
