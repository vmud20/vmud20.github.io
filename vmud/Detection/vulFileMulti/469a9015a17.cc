









namespace tensorflow {

TEST(NNOpsTest, TopK_ShapeFn) {
  ShapeInferenceTestOp op("TopK");
  auto set_k = [&op](int k) {
    TF_ASSERT_OK(NodeDefBuilder("test", "Pack")
                     .Input({{"a", 0, DT_FLOAT}})
                     .Attr("k", k)
                     .Finalize(&op.node_def));
  };

  set_k(20);
  
  INFER_OK(op, "?", "?;?");
  
  INFER_OK(op, "[20]", "[20];[20]");
  INFER_OK(op, "[21]", "[20];[20]");

  
  INFER_OK(op, "[1,?,21]", "[d0_0,d0_1,20];[d0_0,d0_1,20]");
  
  INFER_OK(op, "[1,?,21,?]", "[d0_0,d0_1,d0_2,20];[d0_0,d0_1,d0_2,20]");

  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[]");
  INFER_ERROR("input must have last dimension >= k = 20 but is 1", op, "[1]");
  INFER_ERROR("input must have last dimension >= k = 20 but is 4", op, "[1,2,3,4]");
  set_k(-1);
  INFER_ERROR("Need k >= 0, got -1", op, "[1,2,3,4]");
}

TEST(NNOpsTest, TopKV2_ShapeFn) {
  ShapeInferenceTestOp op("TopKV2");
  op.input_tensors.resize(2);

  Tensor k_t;
  op.input_tensors[1] = &k_t;

  k_t = test::AsScalar<int32>(20);
  
  INFER_OK(op, "?;[]", "?;?");
  
  INFER_OK(op, "[20];[]", "[20];[20]");

  
  INFER_OK(op, "[1,?,21];[]", "[d0_0,d0_1,20];[d0_0,d0_1,20]");
  
  INFER_OK(op, "[1,?,21,?];[]", "[d0_0,d0_1,d0_2,20];[d0_0,d0_1,d0_2,20]");

  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[];[]");
  INFER_ERROR("input must have last dimension >= k = 20 but is 1", op, "[1];[]");
  INFER_ERROR("input must have last dimension >= k = 20 but is 4", op, "[1,2,3,4];[]");
  k_t = test::AsScalar<int32>(-1);
  INFER_ERROR( "Dimension size, given by scalar input 1, must be non-negative but is -1", op, "[1,2,3,4];[]");

}

TEST(NNOpsTest, NthElement_ShapeFn) {
  ShapeInferenceTestOp op("NthElement");
  op.input_tensors.resize(2);

  Tensor n_t;
  op.input_tensors[1] = &n_t;
  n_t = test::AsScalar<int32>(20);

  INFER_OK(op, "?;[]", "?");
  INFER_OK(op, "[21];[]", "[]");
  INFER_OK(op, "[2,?,?];[]", "[d0_0,d0_1]");
  INFER_OK(op, "[?,3,?,21];[]", "[d0_0,d0_1,d0_2]");

  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[];[]");
  INFER_ERROR("Input must have last dimension > n = 20 but is 1", op, "[1];[]");
  INFER_ERROR("Input must have last dimension > n = 20 but is 20", op, "[1,2,3,20];[]");
  n_t = test::AsScalar<int32>(-1);
  INFER_ERROR( "Dimension size, given by scalar input 1, must be non-negative but is -1", op, "[1,2,3,4];[]");

}

TEST(NNOpsTest, BatchNormWithGlobalNormalization_ShapeFn) {
  ShapeInferenceTestOp op("BatchNormWithGlobalNormalization");

  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;[1,2,3]");

  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,?,?,d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,?,?,d2_0]");
  INFER_OK(op, "?;?;?;[1];?", "[?,?,?,d3_0]");
  INFER_OK(op, "?;?;?;?;[1]", "[?,?,?,d4_0]");
  INFER_OK(op, "[1,2,3,4];[4];[4];[4];[4]", "[d0_0,d0_1,d0_2,d0_3|d1_0|d2_0|d3_0|d4_0]");
}

TEST(NNOpsTest, QuantizedBatchNormWithGlobalNormalization_ShapeFn) {
  
  

  ShapeInferenceTestOp op("QuantizedBatchNormWithGlobalNormalization");

  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?;?;?;?;?;?;?;?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?;?;?;?;?;?;?;?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;?;?;[1,2,3];?;?;?;?;?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;?;?;?;?;?;[1,2,3];?;?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;?;?;?;?;?;?;?;?;[1,2,3];?;?");

  
  INFER_OK(op, "?;[];[];?;[];[];?;[];[];?;[];[];?;[];[]", "[?,?,?,?];[];[]");
  INFER_OK(op, "?;[];[];[1];[];[];?;[];[];?;[];[];?;[];[]", "[?,?,?,d3_0];[];[]");
  INFER_OK(op, "?;[];[];?;[];[];[1];[];[];?;[];[];?;[];[]", "[?,?,?,d6_0];[];[]");
  INFER_OK(op, "?;[];[];?;[];[];?;[];[];[1];[];[];?;[];[]", "[?,?,?,d9_0];[];[]");
  INFER_OK(op, "?;[];[];?;[];[];?;[];[];?;[];[];[1];[];[]", "[?,?,?,d12_0];[];[]");
  INFER_OK(op, "[1,2,3,4];[];[];[4];[];[];[4];[];[];[4];[];[];[4];[];[]", "[d0_0,d0_1,d0_2,d0_3|d3_0|d6_0|d9_0|d12_0];[];[]");
}

TEST(NNOpsTest, BatchNormWithGlobalNormalizationGrad_ShapeFn) {
  ShapeInferenceTestOp op("BatchNormWithGlobalNormalizationGrad");

  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?");
  INFER_ERROR("Shapes must be equal rank, but are 4 and 3", op, "?;?;?;?;[1,2,3]");

  
  
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[?];[?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,?,?,d1_0];[d1_0];[d1_0];[d1_0];[d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,?,?,d2_0];[d2_0];[d2_0];[d2_0];[d2_0]");
  INFER_OK(op, "?;?;?;[1];?", "[?,?,?,d3_0];[d3_0];[d3_0];[d3_0];[d3_0]");
  INFER_OK(op, "[1,?,3,?];[?];[?];[?];[?,2,?,4]", "[d0_0,d4_1,d0_2,d4_3];[d4_3];[d4_3];[d4_3];[d4_3]");
}

TEST(NNOpsTest, FusedBatchNorm_ShapeFn) {
  ShapeInferenceTestOp op("FusedBatchNorm");

  auto set_op = [&op](bool is_training, float exponential_avg_factor, string data_format) {
    TF_ASSERT_OK(NodeDefBuilder("test", "FusedBatchNorm")
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Attr("data_format", data_format)
                     .Attr("is_training", is_training)
                     .Attr("exponential_avg_factor", exponential_avg_factor)
                     .Finalize(&op.node_def));
  };

  set_op(true, 1.0, "NHWC");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[?];[?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,?,?,d1_0];[d1_0];[d1_0];[d1_0];[d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,?,?,d2_0];[d2_0];[d2_0];[d2_0];[d2_0]");
  INFER_OK(op, "[1,2,3,4];[4];[4];?;?", "[d0_0,d0_1,d0_2,d0_3|d1_0|d2_0];" "[d0_3|d1_0|d2_0];[d0_3|d1_0|d2_0];" "[d0_3|d1_0|d2_0];[d0_3|d1_0|d2_0]");



  set_op(true, 0.5, "NHWC");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[?];[?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,?,?,d1_0];[d1_0];[d1_0];[d1_0];[d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,?,?,d2_0];[d2_0];[d2_0];[d2_0];[d2_0]");
  INFER_OK(op, "[1,2,3,4];[4];[4];?;?", "[d0_0,d0_1,d0_2,d0_3|d1_0|d2_0];" "[d0_3|d1_0|d2_0];[d0_3|d1_0|d2_0];" "[d0_3|d1_0|d2_0];[d0_3|d1_0|d2_0]");



  set_op(true, 1.0, "NCHW");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[?];[?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,d1_0,?,?];[d1_0];[d1_0];[d1_0];[d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,d2_0,?,?];[d2_0];[d2_0];[d2_0];[d2_0]");
  INFER_OK(op, "[1,4,2,3];[4];[4];?;?", "[d0_0,d0_1|d1_0|d2_0,d0_2,d0_3];" "[d0_1|d1_0|d2_0];[d0_1|d1_0|d2_0];" "[d0_1|d1_0|d2_0];[d0_1|d1_0|d2_0]");



  set_op(false, 1.0, "NHWC");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;[1,2,3]");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[?];[?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,?,?,d1_0];[d1_0];[d1_0];[d1_0];[d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,?,?,d2_0];[d2_0];[d2_0];[d2_0];[d2_0]");
  INFER_OK(op, "?;?;?;[1];?", "[?,?,?,d3_0];[d3_0];[d3_0];[d3_0];[d3_0]");
  INFER_OK(op, "?;?;?;?;[1]", "[?,?,?,d4_0];[d4_0];[d4_0];[d4_0];[d4_0]");
  INFER_OK(op, "[1,2,3,4];[4];[4];[4];[4]", "[d0_0,d0_1,d0_2,d0_3|d1_0|d2_0|d3_0|d4_0];" "[d0_3|d1_0|d2_0|d3_0|d4_0];[d0_3|d1_0|d2_0|d3_0|d4_0];" "[d0_3|d1_0|d2_0|d3_0|d4_0];[d0_3|d1_0|d2_0|d3_0|d4_0]");



  set_op(false, 1.0, "NCHW");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;[1,2,3]");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[?];[?]");
  INFER_OK(op, "?;[1];?;?;?", "[?,d1_0,?,?];[d1_0];[d1_0];[d1_0];[d1_0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,d2_0,?,?];[d2_0];[d2_0];[d2_0];[d2_0]");
  INFER_OK(op, "?;?;?;[1];?", "[?,d3_0,?,?];[d3_0];[d3_0];[d3_0];[d3_0]");
  INFER_OK(op, "?;?;?;?;[1]", "[?,d4_0,?,?];[d4_0];[d4_0];[d4_0];[d4_0]");
  INFER_OK(op, "[1,4,2,3];[4];[4];[4];[4]", "[d0_0,d0_1|d1_0|d2_0|d3_0|d4_0,d0_2,d0_3];" "[d0_1|d1_0|d2_0|d3_0|d4_0];[d0_1|d1_0|d2_0|d3_0|d4_0];" "[d0_1|d1_0|d2_0|d3_0|d4_0];[d0_1|d1_0|d2_0|d3_0|d4_0]");


}

TEST(NNOpsTest, FusedBatchNormGrad_ShapeFn) {
  ShapeInferenceTestOp op("FusedBatchNormGrad");
  auto set_op = [&op](string data_format) {
    TF_ASSERT_OK(NodeDefBuilder("test", "FusedBatchNormGrad")
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Attr("data_format", data_format)
                     .Finalize(&op.node_def));
  };

  set_op("NCHW");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;[1,2,3]");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[0];[0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,d2_0,?,?];[d2_0];[d2_0];[0];[0]");
  INFER_OK(op, "?;?;?;[1];?", "[?,d3_0,?,?];[d3_0];[d3_0];[0];[0]");
  INFER_OK(op, "?;?;?;?;[1]", "[?,d4_0,?,?];[d4_0];[d4_0];[0];[0]");
  INFER_OK(op, "[1,4,2,3];[1,4,2,3];[4];[4];[4]", "[d0_0,d0_1|d2_0|d3_0|d4_0,d0_2,d0_3];" "[d0_1|d2_0|d3_0|d4_0];[d0_1|d2_0|d3_0|d4_0];[0];[0]");


  set_op("NHWC");
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?;?;?");
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "?;[1,2,3];?;?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;[1,2,3];?;?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 3", op, "?;?;?;?;[1,2,3]");
  
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?];[?];[?];[0];[0]");
  INFER_OK(op, "?;?;[1];?;?", "[?,?,?,d2_0];[d2_0];[d2_0];[0];[0]");
  INFER_OK(op, "?;?;?;[1];?", "[?,?,?,d3_0];[d3_0];[d3_0];[0];[0]");
  INFER_OK(op, "?;?;?;?;[1]", "[?,?,?,d4_0];[d4_0];[d4_0];[0];[0]");
  INFER_OK(op, "[1,2,3,4];[1,2,3,4];[4];[4];[4]", "[d0_0,d0_1,d0_2,d0_3|d2_0|d3_0|d4_0];" "[d0_3|d2_0|d3_0|d4_0];[d0_3|d2_0|d3_0|d4_0];[0];[0]");

}

TEST(NNOpsTest, Conv2DBackpropInput_ShapeFn) {
  ShapeInferenceTestOp op("Conv2DBackpropInput");

  
  INFER_ERROR("input_sizes to contain 4 values or 2 values", op, "[3];[?,?,?,?];[?,?,?,?]");
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[4];[?,?,?,?];[?,?,?]");

  
  
  
  
  INFER_OK(op, "[4];[?,?,2,?];[1,?,?,?]", "[d2_0,?,?,?]");
  
  
  INFER_OK(op, "[2];[?,?,2,?];[1,?,?,?]", "[d2_0,?,?,d1_2]");
}

TEST(NNOpsTest, Conv3DBackpropInput_ShapeFn) {
  ShapeInferenceTestOp op("Conv3DBackpropInput");

  
  INFER_ERROR("Shape must be rank 5 but is rank 3", op, "[1,2,3];?;?");

  
  INFER_OK(op, "?;?;?", "[?,?,?,?,?]");
  INFER_OK(op, "[?,?,?,?,?];?;?", "in0");
  INFER_OK(op, "[?,2,?,4,?];?;?", "in0");
}

TEST(NNOpsTest, Conv3DBackpropFilter_ShapeFn) {
  ShapeInferenceTestOp op("Conv3DBackpropFilter");

  
  INFER_ERROR("Shape must be rank 5 but is rank 3", op, "?;[1,2,3];?");

  
  INFER_OK(op, "?;?;?", "[?,?,?,?,?]");
  INFER_OK(op, "?;[?,?,?,?,?];?", "in1");
  INFER_OK(op, "?;[?,2,?,4,?];?", "in1");
}

TEST(NNOpsTest, MaxPool3DGrad_ShapeFn) {
  ShapeInferenceTestOp op("MaxPool3DGrad");

  
  INFER_ERROR("Shape must be rank 5 but is rank 3", op, "[1,2,3];?;?");

  
  INFER_OK(op, "?;?;?", "[?,?,?,?,?]");
  INFER_OK(op, "[?,?,?,?,?];?;?", "in0");
  INFER_OK(op, "[?,2,?,4,?];?;?", "in0");
}

TEST(NNOpsTest, LRNGrad_ShapeFn) {
  ShapeInferenceTestOp op("LRNGrad");

  
  INFER_OK(op, "[1,?,?,4];[?,2,?,?];[?,?,3,?]", "[d0_0,d1_1,d2_2,d0_3]");

  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?");
  INFER_ERROR("Shapes must be equal rank, but are 4 and 3", op, "?;[1,2,3];?");
  INFER_ERROR("Shapes must be equal rank, but are 4 and 3", op, "?;?;[1,2,3]");
}

TEST(NNOpsTest, MaxPoolGrad_ShapeFn) {
  for (const char* op_name : {"MaxPoolGrad", "MaxPoolGradWithArgmax") {
    ShapeInferenceTestOp op(op_name);

    
    INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];?;?");

    
    INFER_OK(op, "?;?;?", "[?,?,?,?]");
    INFER_OK(op, "[?,?,?,?];?;?", "in0");
    INFER_OK(op, "[?,2,?,4];?;?", "in0");
  }
}

TEST(NNOpsTest, Dilation2DBackpropInput_ShapeFn) {
  ShapeInferenceTestOp op("Dilation2DBackpropInput");

  
  INFER_OK(op, "?;?;?", "in0");
  INFER_OK(op, "?;[?,?,?,?,?];?", "in0");
  INFER_OK(op, "?;[?,2,?,4,?];?", "in0");
}

TEST(NNOpsTest, Dilation2DBackpropFilter_ShapeFn) {
  ShapeInferenceTestOp op("Dilation2DBackpropFilter");

  
  INFER_OK(op, "?;?;?", "in1");
  INFER_OK(op, "?;[?,?,?,?,?];?", "in1");
  INFER_OK(op, "?;[?,2,?,4,?];?", "in1");
}

TEST(NNOpsTest, MergeBothInputs_ShapeFn) {
  for (const char* op_name : {"ReluGrad", "Relu6Grad", "EluGrad", "SeluGrad", "SoftplusGrad", "SoftsignGrad") {
    ShapeInferenceTestOp op(op_name);

    INFER_OK(op, "?;?", "in0|in1");
    INFER_OK(op, "?;[1,?,3]", "in1");
    INFER_OK(op, "[1,?,3];?", "in0");
    INFER_OK(op, "[1,?];[?,2]", "[d0_0,d1_1]");
    INFER_ERROR("Dimension 1 in both shapes must be equal, but are 3 and 2", op, "[1,3];[?,2]");
  }
}

TEST(NNOpsTest, SoftmaxCrossEntropyWithLogits_ShapeFn) {
  ShapeInferenceTestOp op("SoftmaxCrossEntropyWithLogits");

  
  
  
  INFER_OK(op, "?;?", "[?];[?,?]");
  INFER_OK(op, "[?,?];[?,?]", "[d0_0|d1_0];in0|in1");
  INFER_OK(op, "[1,2];[?,2]", "[d0_0];in0");
  INFER_OK(op, "[1,?];[?,2]", "[d0_0];[d0_0,d0_1|d1_1]");
  INFER_OK(op, "[?,2];[1,2]", "[d1_0];in1");

  INFER_ERROR("Shape must be broadcasted with rank 2", op, "[1,2,3];?");
  INFER_ERROR("Shape must be broadcasted with rank 2", op, "?;[1,2,3]");

  
  
  INFER_OK(op, "[1,4];[2,4]", "[d1_0];[d1_0,d0_1|d1_1]");
  
  INFER_OK(op, "[2,4];[2,1]", "[d0_0];[d0_0|d1_0,d0_1]");
  
  INFER_OK(op, "[1,?];[2,4]", "[d1_0];[d1_0,d0_1|d1_1]");
  
  INFER_OK(op, "[2,4];[?,1]", "[d0_0];[d0_0|d1_0,d0_1]");
}

TEST(NNOpsTest, SparseSoftmaxCrossEntropyWithLogits_ShapeFn) {
  ShapeInferenceTestOp op("SparseSoftmaxCrossEntropyWithLogits");

  
  
  INFER_OK(op, "?;?", "[?];[?,?]");
  INFER_OK(op, "[?,?];[?]", "[d0_0|d1_0];[d0_0|d1_0,d0_1]");
  INFER_OK(op, "[1,2];[1]", "[d0_0|d1_0];[d0_0|d1_0,d0_1]");
  INFER_OK(op, "[?,2];[1]", "[d1_0];[d1_0,d0_1]");

  INFER_ERROR("Dimensions must be equal, but are 1 and 2", op, "[1,?];[2]");
  INFER_ERROR("Shape must be rank 2 but is rank 3", op, "[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[1,2]");
}

TEST(NNOpsTest, InTopK_ShapeFn) {
  ShapeInferenceTestOp op("InTopK");

  
  INFER_OK(op, "?;?", "[?]");
  INFER_OK(op, "[?,?];[?]", "[d0_0|d1_0]");
  INFER_OK(op, "[1,2];[1]", "[d0_0|d1_0]");
  INFER_OK(op, "[?,2];[1]", "[d1_0]");

  INFER_ERROR("Dimensions must be equal, but are 1 and 2", op, "[1,?];[2]");
  INFER_ERROR("Shape must be rank 2 but is rank 3", op, "[1,2,3];?");
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[1,2]");
}

TEST(NNOpsTest, Dilation2DShapeTest) {
  ShapeInferenceTestOp op("Dilation2D");
  auto set_op = [&op](const std::vector<int32>& strides, const std::vector<int32>& rates, const string& padding) {
    TF_ASSERT_OK(NodeDefBuilder("test", "Dilation2D")
                     .Input("input", 0, DT_FLOAT)
                     .Input("filter", 0, DT_FLOAT)
                     .Attr("strides", strides)
                     .Attr("rates", rates)
                     .Attr("padding", padding)
                     .Finalize(&op.node_def));
  };

  
  
  set_op({1, 1, 1, 1}, {1, 1, 1, 1}, "VALID");
  INFER_OK(op, "[1,2,2,2];[1,1,2]", "[d0_0,2,2,d1_2]");

  
  
  
  set_op({1, 1, 1, 1}, {1, 2, 2, 1}, "VALID");
  INFER_OK(op, "[1,7,7,2];[2,2,2]", "[d0_0,5,5,d1_2]");
}

TEST(NNOpsTest, FractionalPool_ShapeFn) {
  for (const char* op_name : {"FractionalAvgPool", "FractionalMaxPool") {
    ShapeInferenceTestOp op(op_name);
    auto set_op = [&op, op_name](const std::vector<float>& pooling_ratio) {
      TF_ASSERT_OK(NodeDefBuilder("test", op_name)
                       .Input("input", 0, DT_FLOAT)
                       .Attr("pooling_ratio", pooling_ratio)
                       .Finalize(&op.node_def));
    };

    set_op(std::vector<float>{2.0f, 1, 1 / 1.5f, 1 / 2.0f});

    
    INFER_ERROR("must be rank 4", op, "[?,?,?]");

    
    INFER_OK(op, "?", "[?,?,?,?];[?];[?]");
    INFER_OK(op, "[?,?,?,?]", "[?,?,?,?];[?];[?]");

    INFER_OK(op, "[10,20,30,40]", "[5,20,45,80];[20];[45]");
    INFER_OK(op, "[?,20,30,40]", "[?,20,45,80];[20];[45]");
    INFER_OK(op, "[10,?,30,40]", "[5,?,45,80];[?];[45]");
    INFER_OK(op, "[10,20,?,40]", "[5,20,?,80];[20];[?]");
    INFER_OK(op, "[10,20,30,?]", "[5,20,45,?];[20];[45]");

    
    set_op(std::vector<float>{.5, 1.0, 1.5});
    INFER_ERROR("pooling_ratio field", op, "?");
    set_op(std::vector<float>{1, 2, 3, 4, 5});
    INFER_ERROR("pooling_ratio field", op, "?");

    
    set_op(std::vector<float>{-1, 2, 3, 4});
    INFER_ERROR("is negative", op, "[1,2,3,4]");
  }
}

TEST(NNOpsTest, FractionalMaxPoolGrad) {
  ShapeInferenceTestOp op("FractionalMaxPoolGrad");

  
  INFER_ERROR("must be rank 4", op, "[?,?,?];?;?;?;?");
  INFER_OK(op, "?;?;?;?;?", "[?,?,?,?]");
  INFER_OK(op, "[?,?,3,4];?;?;?;?", "in0");
}

TEST(NNOpsTest, FractionalAvgPoolGrad) {
  ShapeInferenceTestOp op("FractionalAvgPoolGrad");
  op.input_tensors.resize(1);

  
  INFER_OK(op, "?;?;?;?", "[?,?,?,?]");

  
  std::vector<int32> shape{1, 2, 3, 4};
  Tensor shape_t = test::AsTensor<int32>(shape);
  op.input_tensors[0] = &shape_t;
  INFER_OK(op, "[5];?;?;?", "[1,2,3,4]");
}

}  
