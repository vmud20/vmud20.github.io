










namespace tensorflow {

using errors::InvalidArgument;

template <typename SPLITS_TYPE> class RaggedTensorToSparseOp : public OpKernel {
 public:
  using OpKernel::OpKernel;
  using ConstFlatSplits = typename TTypes<SPLITS_TYPE>::ConstFlat;

  void Compute(OpKernelContext* context) override {
    
    OpInputList rt_nested_splits_in;
    OP_REQUIRES_OK( context, context->input_list("rt_nested_splits", &rt_nested_splits_in));
    const int rt_nested_splits_len = rt_nested_splits_in.size();
    DCHECK_GT(rt_nested_splits_len, 0);  
    std::vector<ConstFlatSplits> rt_nested_splits;
    rt_nested_splits.reserve(rt_nested_splits_len);
    for (int i = 0; i < rt_nested_splits_len; ++i) {
      rt_nested_splits.push_back(rt_nested_splits_in[i].flat<SPLITS_TYPE>());
    }

    
    const Tensor& rt_dense_values_in = context->input(rt_nested_splits_len);
    OP_REQUIRES_OK(context, ValidateInputs(rt_nested_splits, rt_dense_values_in));

    
    
    
    
    
    std::vector<int64> index_prefix(rt_nested_splits_len);
    std::vector<std::vector<int64>> index_suffixes = MakeIndexSuffixes(rt_dense_values_in.shape());

    
    const int64_t nvals = (rt_nested_splits.back()(rt_nested_splits.back().size() - 1) * index_suffixes.size());

    const int64_t indices_len = rt_nested_splits_len + rt_dense_values_in.dims();
    Tensor* sparse_indices_out = nullptr;
    OP_REQUIRES_OK( context, context->allocate_output(0, TensorShape({nvals, indices_len}), &sparse_indices_out));

    auto sparse_indices = sparse_indices_out->tensor<int64, 2>();

    
    
    std::vector<int64> pos(rt_nested_splits_len);
    int64& final_pos = pos[rt_nested_splits_len - 1];

    
    
    
    int next_index = 0;
    int max_final_pos = rt_nested_splits.back().size() - 1;
    for (; final_pos < max_final_pos; ++final_pos) {
      
      
      for (int dim = rt_nested_splits_len - 2; dim >= 0; --dim) {
        while (IsCompleted(pos, dim, rt_nested_splits)) {
          pos[dim] += 1;
        }
      }

      
      for (int dim = 0; dim < index_prefix.size(); ++dim) {
        int start = dim > 0 ? rt_nested_splits[dim - 1](pos[dim - 1]) : 0;
        index_prefix[dim] = pos[dim] - start;
      }

      
      const auto& final_splits = rt_nested_splits[rt_nested_splits_len - 1];
      int64_t slice_len = final_splits(final_pos + 1) - final_splits(final_pos);

      
      for (int64_t i = 0; i < slice_len; ++i) {
        for (const auto& index_suffix : index_suffixes) {
          int dim = 0;
          for (int64_t index : index_prefix) {  
            sparse_indices(next_index, dim++) = index;
          }
          sparse_indices(next_index, dim++) = i;  
          for (int64_t index : index_suffix) {    
            sparse_indices(next_index, dim++) = index;
          }
          DCHECK_EQ(dim, indices_len);
          ++next_index;
        }
      }
    }
    DCHECK_EQ(next_index, nvals);

    
    if (rt_dense_values_in.dims() == 1) {
      context->set_output(1, rt_dense_values_in);
    } else {
      Tensor sparse_values_out(rt_dense_values_in.dtype());
      bool shapes_match = sparse_values_out.CopyFrom( rt_dense_values_in, {rt_dense_values_in.NumElements()});
      DCHECK(shapes_match);
      context->set_output(1, sparse_values_out);
    }

    
    int64_t ndims = rt_nested_splits_len + rt_dense_values_in.dims();
    Tensor* sparse_dense_shape_out = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(2, TensorShape({ndims}), &sparse_dense_shape_out));
    auto sparse_dense_shape = sparse_dense_shape_out->vec<int64>();
    sparse_dense_shape(0) = rt_nested_splits_in[0].dim_size(0) - 1;
    for (int dim = 0; dim < rt_nested_splits_len; ++dim) {
      const auto& splits = rt_nested_splits[dim];
      SPLITS_TYPE max_width = 0;
      for (int i = 1; i < splits.size(); ++i) {
        max_width = std::max(max_width, splits(i) - splits(i - 1));
      }
      sparse_dense_shape(dim + 1) = max_width;
    }
    for (int dim = 1; dim < rt_dense_values_in.dims(); ++dim) {
      sparse_dense_shape(dim + rt_nested_splits_len) = rt_dense_values_in.dim_size(dim);
    }
  }

 private:
  
  static ::tensorflow::Status ValidateInputs( std::vector<ConstFlatSplits> rt_nested_splits, const Tensor& rt_dense_values_in) {

    for (int i = 0; i < rt_nested_splits.size(); ++i) {
      if (rt_nested_splits[i].size() == 0) {
        return InvalidArgument("ragged splits may not be empty.");
      }
      if (rt_nested_splits[i](0) != 0) {
        return InvalidArgument("First value of ragged splits must be 0.");
      }
      if (i > 0) {
        SPLITS_TYPE last_split = rt_nested_splits[i - 1](rt_nested_splits[i - 1].size() - 1);
        if (rt_nested_splits[i].size() != last_split + 1) {
          return InvalidArgument( "Final value of ragged splits must match the length " "the corresponding ragged values.");

        }
      }
    }
    if (rt_dense_values_in.dim_size(0) != rt_nested_splits.back()(rt_nested_splits.back().size() - 1)) {
      return InvalidArgument( "Final value of ragged splits must match the length " "the corresponding ragged values.");

    }
    return ::tensorflow::Status::OK();
  }

  
  
  
  
  
  
  
  static std::vector<std::vector<int64>> MakeIndexSuffixes( const TensorShape& values_shape) {
    std::vector<std::vector<int64>> suffixes{{}};
    for (int dim = 1; dim < values_shape.dims(); ++dim) {
      std::vector<std::vector<int64>> new_suffixes;
      for (const auto& suffix : suffixes) {
        for (int i = 0; i < values_shape.dim_size(dim); ++i) {
          new_suffixes.push_back(suffix);
          new_suffixes.back().push_back(i);
        }
      }
      suffixes.swap(new_suffixes);
    }
    return suffixes;
  }

  
  
  
  static bool IsCompleted( const std::vector<int64>& pos, int dim, const std::vector<ConstFlatSplits>& rt_nested_splits) {

    int64_t current_child = pos[dim + 1];
    int64_t limit_child = rt_nested_splits[dim](pos[dim] + 1);
    return current_child >= limit_child;
  }
};

REGISTER_KERNEL_BUILDER(Name("RaggedTensorToSparse")
                            .Device(DEVICE_CPU)
                            .TypeConstraint<int32>("Tsplits"), RaggedTensorToSparseOp<int32>);

REGISTER_KERNEL_BUILDER(Name("RaggedTensorToSparse")
                            .Device(DEVICE_CPU)
                            .TypeConstraint<int64>("Tsplits"), RaggedTensorToSparseOp<int64>);

}  
