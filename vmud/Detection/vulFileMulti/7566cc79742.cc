















namespace tensorflow {
namespace {

class DynamicStitchOp : public XlaOpKernel {
 public:
  explicit DynamicStitchOp(OpKernelConstruction* ctx) : XlaOpKernel(ctx) {
    OP_REQUIRES( ctx, ctx->num_inputs() > 0, errors::InvalidArgument("DynamicStitchOp: Must have some inputs"));

    OP_REQUIRES(ctx, ctx->num_inputs() % 2 == 0, errors::InvalidArgument( "DynamicStitchOp: Must have even number of arguments"));

    
    const int n = ctx->num_inputs() / 2;
    const DataType dt = ctx->input_type(n);
    DataTypeVector expected;
    for (int i = 0; i < n; i++) {
      expected.push_back(DT_INT32);
    }
    for (int i = 0; i < n; i++) {
      expected.push_back(dt);
    }
    OP_REQUIRES_OK(ctx, ctx->MatchSignature(expected, {dt}));
  }

  void Compile(XlaOpKernelContext* ctx) override {
    
    std::vector<xla::Literal> indices_input;
    OP_REQUIRES_OK(ctx, ctx->ConstantInputList("indices", &indices_input));

    std::vector<xla::XlaOp> data;
    std::vector<TensorShape> data_shapes;
    OP_REQUIRES_OK(ctx, ctx->InputList("data", &data, &data_shapes));

    std::vector<xla::Literal> indices(indices_input.size());

    const TensorShape& data0_shape = data_shapes[0];
    TensorShape indices0_shape;
    OP_REQUIRES_OK( ctx, XLAShapeToTensorShape(indices_input[0].shape(), &indices0_shape));
    for (int input_num = 0; input_num < indices_input.size(); input_num++) {
      TensorShape indices_shape;
      OP_REQUIRES_OK(ctx, XLAShapeToTensorShape(indices_input[input_num].shape(), &indices_shape));

      TensorShape& data_shape = data_shapes[input_num];
      if (!TensorShapeUtils::StartsWith(data_shape, indices_shape)) {
        
        
        
        for (int64_t i = 0; i < indices_shape.dims(); ++i) {
          data_shape.set_dim(i, indices_shape.dim_size(i));
          data[input_num] = xla::SliceInDim(data[input_num], 0, indices_shape.dim_size(i), 1, i);
        }
      }
      OP_REQUIRES( ctx, TensorShapeUtils::StartsWith(data_shape, indices_shape), errors::InvalidArgument("data[", input_num, "].shape = ", data_shape.DebugString(), " does not start with indices[", input_num, "].shape = ", indices_shape.DebugString()));




      OP_REQUIRES( ctx, input_num == 0 || SameExtraShape(data0_shape, indices0_shape, data_shape, indices_shape), errors::InvalidArgument( "Need data[0].shape[", indices0_shape.dims(), ":] = data[", input_num, "].shape[", indices_shape.dims(), ":], got data[0].shape = ", data0_shape.DebugString(), ", data[", input_num, "].shape = ", data_shape.DebugString(), ", indices[0].shape = ", indices0_shape.DebugString(), ", indices[", input_num, "].shape = ", indices_shape.DebugString()));











      OP_REQUIRES_OK(ctx, XlaHelpers::ReshapeLiteral(indices_input[input_num], {indices_shape.num_elements()}, &indices[input_num]));


    }

    
    
    
    
    
    
    
    
    int max_index = -1;
    for (int input_num = 0; input_num < indices.size(); input_num++) {
      for (int i = 0; i < indices[input_num].shape().dimensions(0); ++i) {
        max_index = std::max(max_index, indices[input_num].Get<int>({i}));
      }
    }
    int number_of_indices = max_index + 1;
    int64_t result_rank = 1 + data0_shape.dims() - indices0_shape.dims();
    if (number_of_indices == 0) {
      std::vector<int64_t> result_shape(result_rank);
      for (int d = indices0_shape.dims(); d < data0_shape.dims(); d++) {
        result_shape[d - indices0_shape.dims() + 1] = data0_shape.dim_size(d);
      }
      xla::PrimitiveType element_type = ctx->input_xla_type(ctx->num_inputs() - 1);
      xla::Literal empty_literal = xla::Literal::CreateFromShape( xla::ShapeUtil::MakeShape(element_type, result_shape));
      ctx->SetOutput(0, xla::ConstantLiteral(ctx->builder(), empty_literal));
      return;
    }

    
    
    std::vector<int32> src_input_vector(number_of_indices);
    std::vector<int32> src_slice_vector(number_of_indices);
    std::vector<bool> src_index_used(number_of_indices);
    int index_used_count = 0;
    for (int input_num = 0; input_num < indices.size(); input_num++) {
      for (int i = 0; i < indices[input_num].shape().dimensions(0); ++i) {
        int index = indices[input_num].Get<int>({i});
        src_input_vector[index] = input_num;
        src_slice_vector[index] = i;
        if (!src_index_used[index]) {
          src_index_used[index] = true;
          ++index_used_count;
        }
      }
    }
    OP_REQUIRES(ctx, index_used_count == number_of_indices, errors::InvalidArgument("not all indices are used"));

    
    
    std::vector<xla::XlaOp> input(indices.size());
    for (int input_num = 0; input_num < indices.size(); input_num++) {
      TensorShape new_shape;
      
      new_shape.AddDim(indices[input_num].shape().dimensions(0));
      
      for (int d = indices0_shape.dims(); d < data0_shape.dims(); d++) {
        new_shape.AddDim(data0_shape.dim_size(d));
      }
      
      auto handle = data[input_num];
      if (new_shape == data_shapes[input_num]) {
        input[input_num] = handle;
      } else {
        input[input_num] = xla::Reshape(handle, new_shape.dim_sizes());
      }
    }

    
    
    std::vector<int64_t> slice_start(result_rank);
    std::vector<int64_t> slice_limit(result_rank);
    std::vector<int64_t> stride(result_rank, 1);
    for (int d = indices0_shape.dims(); d < data0_shape.dims(); d++) {
      slice_limit[1 + d - indices0_shape.dims()] = data0_shape.dim_size(d);
    }
    std::vector<xla::XlaOp> to_concat(number_of_indices);
    for (int index_num = 0; index_num < number_of_indices; index_num++) {
      const auto& expression = input[src_input_vector[index_num]];
      
      slice_start[0] = src_slice_vector[index_num];
      slice_limit[0] = src_slice_vector[index_num] + 1;
      
      
      to_concat[index_num] = xla::Slice(expression, slice_start, slice_limit, stride);
    }

    ctx->SetOutput(0, xla::ConcatInDim(ctx->builder(), to_concat, 0));
  }

 private:
  
  static bool SameExtraShape(const TensorShape& data0_shape, const TensorShape& indices0, const TensorShape& data1_shape, const TensorShape& indices1) {


    const int extra0 = data0_shape.dims() - indices0.dims();
    const int extra1 = data1_shape.dims() - indices1.dims();
    if (extra0 != extra1) return false;
    for (int i = 0; i < extra0; i++) {
      if (data0_shape.dim_size(indices0.dims() + i) != data1_shape.dim_size(indices1.dims() + i)) {
        return false;
      }
    }
    return true;
  }
};

REGISTER_XLA_OP(Name("DynamicStitch").CompileTimeConstantInput("indices"), DynamicStitchOp);
REGISTER_XLA_OP( Name("ParallelDynamicStitch").CompileTimeConstantInput("indices"), DynamicStitchOp);


}  
}  
