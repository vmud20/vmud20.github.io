












namespace tensorflow {
namespace {

class RaggedRangeOpTest : public ::tensorflow::OpsTestBase {
 protected:
  
  static constexpr int kSplitsOutput = 0;
  static constexpr int kValuesOutput = 1;

  
  template <typename T> void BuildRaggedRangeGraph() {
    const auto& dtype = DataTypeToEnum<T>::v();
    TF_ASSERT_OK(NodeDefBuilder("tested_op", "RaggedRange")
                     .Input(FakeInput(dtype))  
                     .Input(FakeInput(dtype))  
                     .Input(FakeInput(dtype))  
                     .Attr("T", dtype)
                     .Finalize(node_def()));
    TF_ASSERT_OK(InitOp());
  }
};

TEST_F(RaggedRangeOpTest, IntValues) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({4}), {0, 5, 8, 5});   
  AddInputFromArray<int>(TensorShape({4}), {8, 7, 8, 1});   
  AddInputFromArray<int>(TensorShape({4}), {2, 1, 1, -1});  
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 4, 6, 6, 10}));
  test::ExpectTensorEqual<int>( *GetOutput(kValuesOutput), test::AsTensor<int>({0, 2, 4, 6, 5, 6, 5, 4, 3, 2}));

}

TEST_F(RaggedRangeOpTest, FloatValues) {
  BuildRaggedRangeGraph<float>();
  AddInputFromArray<float>(TensorShape({4}), {0, 5, 8, 5});   
  AddInputFromArray<float>(TensorShape({4}), {8, 7, 8, 1});   
  AddInputFromArray<float>(TensorShape({4}), {2, 1, 1, -1});  
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 4, 6, 6, 10}));
  test::ExpectTensorNear<float>( *GetOutput(kValuesOutput), test::AsTensor<float>({0, 2, 4, 6, 5, 6, 5, 4, 3, 2}), 0.1);

}

TEST_F(RaggedRangeOpTest, BroadcastDeltas) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({3}), {0, 5, 8});  
  AddInputFromArray<int>(TensorShape({3}), {8, 7, 8});  
  AddInputFromArray<int>(TensorShape({}), {1});         
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 8, 10, 10}));
  test::ExpectTensorEqual<int>( *GetOutput(kValuesOutput), test::AsTensor<int>({0, 1, 2, 3, 4, 5, 6, 7, 5, 6}));

}

TEST_F(RaggedRangeOpTest, BroadcastLimitsAndDeltas) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({}), {0});         
  AddInputFromArray<int>(TensorShape({3}), {3, 0, 2});  
  AddInputFromArray<int>(TensorShape({}), {1});         
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 3, 3, 5}));
  test::ExpectTensorEqual<int>(*GetOutput(kValuesOutput), test::AsTensor<int>({0, 1, 2, 0, 1}));
}

TEST_F(RaggedRangeOpTest, BroadcastStartsAndLimits) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({}), {0});         
  AddInputFromArray<int>(TensorShape({}), {12});        
  AddInputFromArray<int>(TensorShape({3}), {3, 4, 5});  
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 4, 7, 10}));
  test::ExpectTensorEqual<int>( *GetOutput(kValuesOutput), test::AsTensor<int>({0, 3, 6, 9, 0, 4, 8, 0, 5, 10}));

}

TEST_F(RaggedRangeOpTest, AllScalarInputs) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({}), {0});  
  AddInputFromArray<int>(TensorShape({}), {5});  
  AddInputFromArray<int>(TensorShape({}), {1});  
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 5}));
  test::ExpectTensorEqual<int>(*GetOutput(kValuesOutput), test::AsTensor<int>({0, 1, 2, 3, 4}));
}

TEST_F(RaggedRangeOpTest, InvalidArgsStarts) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({4, 1}), {0, 5, 8, 5});  
  AddInputFromArray<int>(TensorShape({4}), {8, 7, 8, 1});     
  AddInputFromArray<int>(TensorShape({4}), {2, 1, 1, -1});    
  EXPECT_EQ("starts must be a scalar or vector", RunOpKernel().error_message());
}

TEST_F(RaggedRangeOpTest, InvalidArgsLimits) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({4}), {0, 5, 8, 5});     
  AddInputFromArray<int>(TensorShape({4, 1}), {8, 7, 8, 1});  
  AddInputFromArray<int>(TensorShape({4}), {2, 1, 1, -1});    
  EXPECT_EQ("limits must be a scalar or vector", RunOpKernel().error_message());
}

TEST_F(RaggedRangeOpTest, InvalidArgsDeltas) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({4}), {0, 5, 8, 5});      
  AddInputFromArray<int>(TensorShape({4}), {8, 7, 8, 1});      
  AddInputFromArray<int>(TensorShape({4, 1}), {2, 1, 1, -1});  
  EXPECT_EQ("deltas must be a scalar or vector", RunOpKernel().error_message());
}

TEST_F(RaggedRangeOpTest, InvalidArgsShapeMismatch) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({4}), {0, 5, 8, 5});   
  AddInputFromArray<int>(TensorShape({3}), {7, 8, 1});      
  AddInputFromArray<int>(TensorShape({4}), {2, 1, 1, -1});  
  EXPECT_EQ("starts, limits, and deltas must have the same shape", RunOpKernel().error_message());
}

TEST_F(RaggedRangeOpTest, InvalidArgsZeroDelta) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({4}), {0, 5, 8, 5});   
  AddInputFromArray<int>(TensorShape({4}), {7, 8, 8, 1});   
  AddInputFromArray<int>(TensorShape({4}), {2, 1, 0, -1});  
  EXPECT_EQ("Requires delta != 0", RunOpKernel().error_message());
}

TEST_F(RaggedRangeOpTest, EmptyRangePositiveDelta) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({2}), {0, 5});  
  AddInputFromArray<int>(TensorShape({2}), {5, 0});  
  AddInputFromArray<int>(TensorShape({}), {2});      
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 3, 3}));
  test::ExpectTensorEqual<int>(*GetOutput(kValuesOutput), test::AsTensor<int>({0, 2, 4}));
}

TEST_F(RaggedRangeOpTest, EmptyRangeNegativeDelta) {
  BuildRaggedRangeGraph<int>();
  AddInputFromArray<int>(TensorShape({2}), {0, 5});  
  AddInputFromArray<int>(TensorShape({2}), {5, 0});  
  AddInputFromArray<int>(TensorShape({}), {-2});     
  TF_ASSERT_OK(RunOpKernel());

  
  test::ExpectTensorEqual<int64_t>(*GetOutput(kSplitsOutput), test::AsTensor<int64_t>({0, 0, 3}));
  test::ExpectTensorEqual<int>(*GetOutput(kValuesOutput), test::AsTensor<int>({5, 3, 1}));
}

TEST_F(RaggedRangeOpTest, ShapeFn) {
  
  ShapeInferenceTestOp op("RaggedRange");
  INFER_OK(op, "?;?;?", "[?];[?]");
  INFER_OK(op, "[3];[3];[3]", "[4];[?]");
  INFER_OK(op, "[3];[3];[]", "[4];[?]");  
  INFER_OK(op, "[3];[];[3]", "[4];[?]");  
  INFER_OK(op, "[];[3];[3]", "[4];[?]");  
  INFER_OK(op, "[];[];[]", "[2];[?]");    
  INFER_ERROR("Shape must be at most rank 1 but is rank 2", op, "[5,5];[5];[5]");
  INFER_ERROR("Shape must be at most rank 1 but is rank 2", op, "[5];[5,5];[5]");
  INFER_ERROR("Shape must be at most rank 1 but is rank 2", op, "[5];[5];[5,5]");
  INFER_ERROR("Dimensions must be equal, but are 4 and 3", op, "[3];[4];[3]");
}

}  
}  
