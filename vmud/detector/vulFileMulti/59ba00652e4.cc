

































inline bool operator==(const TfLiteRegistration& a, const TfLiteRegistration& b) {
  return a.invoke == b.invoke && a.init == b.init && a.prepare == b.prepare && a.free == b.free;
}

namespace tflite {


namespace {
void* dummy_init(TfLiteContext*, const char*, size_t) { return nullptr; }
void dummy_free(TfLiteContext*, void*) {}
TfLiteStatus dummy_resize(TfLiteContext*, TfLiteNode*) { return kTfLiteOk; }
TfLiteStatus dummy_invoke(TfLiteContext*, TfLiteNode*) { return kTfLiteOk; }
TfLiteRegistration dummy_reg = {dummy_init, dummy_free, dummy_resize, dummy_invoke};
}  



class TrivialResolver : public OpResolver {
 public:
  explicit TrivialResolver(TfLiteRegistration* constant_return = nullptr)
      : constant_return_(constant_return) {}
  
  const TfLiteRegistration* FindOp(tflite::BuiltinOperator op, int version) const override {
    return constant_return_;
  }
  
  const TfLiteRegistration* FindOp(const char* op, int version) const override {
    return constant_return_;
  }

 private:
  TfLiteRegistration* constant_return_;
};

TEST(BasicFlatBufferModel, TestNonExistentFiles) {
  ASSERT_TRUE(!FlatBufferModel::BuildFromFile("/tmp/tflite_model_1234"));
}

TEST(BasicFlatBufferModel, TestBufferAlignment) {
  
  
  const uintptr_t kAlignment = 4;
  const uintptr_t kAlignmentBits = kAlignment - 1;

  
  
  std::ifstream fp("tensorflow/lite/testdata/empty_model.bin");
  ASSERT_TRUE(fp.good());
  std::string empty_model_data((std::istreambuf_iterator<char>(fp)), std::istreambuf_iterator<char>());
  auto free_chars = [](char* p) { free(p); };
  std::unique_ptr<char, decltype(free_chars)> buffer( reinterpret_cast<char*>(malloc(empty_model_data.size() + kAlignment)), free_chars);


  
  char* aligned = reinterpret_cast<char*>( (reinterpret_cast<uintptr_t>(buffer.get()) + kAlignment) & ~kAlignmentBits);

  memcpy(aligned, empty_model_data.c_str(), empty_model_data.size());
  EXPECT_TRUE( FlatBufferModel::BuildFromBuffer(aligned, empty_model_data.size()));

  
  char* unaligned = reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(buffer.get()) | 0x1);
  memcpy(unaligned, empty_model_data.c_str(), empty_model_data.size());

  EXPECT_FALSE( FlatBufferModel::BuildFromBuffer(unaligned, empty_model_data.size()));

  EXPECT_TRUE( FlatBufferModel::BuildFromBuffer(unaligned, empty_model_data.size()));

}


TEST(BasicFlatBufferModel, TestEmptyModels) {
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/empty_model.bin");
  ASSERT_TRUE(model);
  
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(InterpreterBuilder(*model, TrivialResolver())(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
}

TEST(BasicFlatBufferModel, TestNullDestination) {
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/empty_model.bin");
  ASSERT_TRUE(model);
  
  ASSERT_NE(InterpreterBuilder(*model, TrivialResolver())(nullptr), kTfLiteOk);
}



TEST(BasicFlatBufferModel, TestZeroSubgraphs) {
  auto m = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/0_subgraphs.bin");
  ASSERT_TRUE(m);
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_NE(InterpreterBuilder(*m, TrivialResolver())(&interpreter), kTfLiteOk);
}

TEST(BasicFlatBufferModel, TestMultipleSubgraphs) {
  auto m = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/2_subgraphs.bin");
  ASSERT_TRUE(m);
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(InterpreterBuilder(*m, TrivialResolver())(&interpreter), kTfLiteOk);
  EXPECT_EQ(interpreter->subgraphs_size(), 2);
}

TEST(BasicFlatBufferModel, TestSubgraphName) {
  auto m = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/" "2_subgraphs_dont_delegate_name.bin");

  ASSERT_TRUE(m);
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(InterpreterBuilder(*m, TrivialResolver())(&interpreter), kTfLiteOk);
  EXPECT_EQ(interpreter->subgraphs_size(), 2);
  EXPECT_EQ(interpreter->subgraph(0)->GetName(), "");
  EXPECT_EQ(interpreter->subgraph(1)->GetName(), "VALIDATION:main");
}


TEST(BasicFlatBufferModel, TestModelWithoutNullRegistrations) {
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_model.bin");
  ASSERT_TRUE(model);
  
  std::unique_ptr<Interpreter> interpreter(new Interpreter);
  ASSERT_NE(InterpreterBuilder(*model, TrivialResolver(nullptr))(&interpreter), kTfLiteOk);
  ASSERT_EQ(interpreter, nullptr);
}


TEST(BasicFlatBufferModel, TestModelInInterpreter) {
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_model.bin");
  ASSERT_TRUE(model);
  
  std::unique_ptr<Interpreter> interpreter(new Interpreter);
  ASSERT_EQ( InterpreterBuilder(*model, TrivialResolver(&dummy_reg))(&interpreter), kTfLiteOk);

  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->tensors_size(), 4);
  ASSERT_EQ(interpreter->nodes_size(), 2);
  std::vector<int> inputs = {0, 1};
  std::vector<int> outputs = {2, 3};
  ASSERT_EQ(interpreter->inputs(), inputs);
  ASSERT_EQ(interpreter->outputs(), outputs);

  EXPECT_EQ(std::string(interpreter->GetInputName(0)), "input0");
  EXPECT_EQ(std::string(interpreter->GetInputName(1)), "input1");
  EXPECT_EQ(std::string(interpreter->GetOutputName(0)), "out1");
  EXPECT_EQ(std::string(interpreter->GetOutputName(1)), "out2");

  
  TfLiteTensor* i0 = interpreter->tensor(0);
  ASSERT_EQ(i0->type, kTfLiteFloat32);
  ASSERT_NE(i0->data.raw, nullptr);  
  ASSERT_EQ(i0->allocation_type, kTfLiteMmapRo);
  TfLiteTensor* i1 = interpreter->tensor(1);
  ASSERT_EQ(i1->type, kTfLiteFloat32);
  ASSERT_EQ(i1->data.raw, nullptr);
  ASSERT_EQ(i1->allocation_type, kTfLiteArenaRw);
  TfLiteTensor* o0 = interpreter->tensor(2);
  ASSERT_EQ(o0->type, kTfLiteFloat32);
  ASSERT_EQ(o0->data.raw, nullptr);
  ASSERT_EQ(o0->allocation_type, kTfLiteArenaRw);
  TfLiteTensor* o1 = interpreter->tensor(3);
  ASSERT_EQ(o1->type, kTfLiteFloat32);
  ASSERT_EQ(o1->data.raw, nullptr);
  ASSERT_EQ(o1->allocation_type, kTfLiteArenaRw);

  
  {
    const std::pair<TfLiteNode, TfLiteRegistration>* node_and_reg0 = interpreter->node_and_registration(0);
    ASSERT_NE(node_and_reg0, nullptr);
    const TfLiteNode& node0 = node_and_reg0->first;
    const TfLiteRegistration& reg0 = node_and_reg0->second;
    TfLiteIntArray* desired_inputs = TfLiteIntArrayCreate(2);
    desired_inputs->data[0] = 0;
    desired_inputs->data[1] = 1;
    TfLiteIntArray* desired_outputs = TfLiteIntArrayCreate(1);
    desired_outputs->data[0] = 2;
    ASSERT_TRUE(TfLiteIntArrayEqual(node0.inputs, desired_inputs));
    ASSERT_TRUE(TfLiteIntArrayEqual(node0.outputs, desired_outputs));
    TfLiteIntArrayFree(desired_inputs);
    TfLiteIntArrayFree(desired_outputs);
    ASSERT_EQ(reg0, dummy_reg);
  }

  
  {
    const std::pair<TfLiteNode, TfLiteRegistration>* node_and_reg1 = interpreter->node_and_registration(1);
    ASSERT_NE(node_and_reg1, nullptr);
    const TfLiteNode& node1 = node_and_reg1->first;
    const TfLiteRegistration& reg1 = node_and_reg1->second;
    TfLiteIntArray* desired_inputs = TfLiteIntArrayCreate(1);
    TfLiteIntArray* desired_outputs = TfLiteIntArrayCreate(1);
    desired_inputs->data[0] = 2;
    desired_outputs->data[0] = 3;
    ASSERT_TRUE(TfLiteIntArrayEqual(node1.inputs, desired_inputs));
    ASSERT_TRUE(TfLiteIntArrayEqual(node1.outputs, desired_outputs));
    TfLiteIntArrayFree(desired_inputs);
    TfLiteIntArrayFree(desired_outputs);
    ASSERT_EQ(reg1, dummy_reg);
  }
}

TEST(BasicFlatBufferModel, TestWithNumThreads) {
  TestErrorReporter reporter;
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_model.bin", &reporter);
  ASSERT_TRUE(model);
  TrivialResolver resolver(&dummy_reg);
  InterpreterBuilder builder(*model, resolver);

  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(builder(&interpreter, 42), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->subgraph(0)->context()->recommended_num_threads, 42);

  interpreter.reset();
  ASSERT_EQ(builder(&interpreter, 0), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->subgraph(0)->context()->recommended_num_threads, 1);

  interpreter.reset();
  ASSERT_EQ(builder(&interpreter, -1), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->subgraph(0)->context()->recommended_num_threads, -1);

  ASSERT_EQ(reporter.num_calls(), 0);
  interpreter.reset(new Interpreter);
  ASSERT_EQ(builder(&interpreter, -2), kTfLiteError);
  ASSERT_EQ(interpreter, nullptr);
  ASSERT_EQ(reporter.num_calls(), 1);
  ASSERT_PRED_FORMAT2(testing::IsSubstring, "num_threads should be >= 0 or just -1", reporter.error_messages());

}

TEST(BasicFlatBufferModel, TestSetNumThreads) {
  TestErrorReporter reporter;
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_model.bin", &reporter);
  ASSERT_TRUE(model);
  std::unique_ptr<Interpreter> interpreter;
  TrivialResolver resolver(&dummy_reg);
  InterpreterBuilder builder(*model, resolver);

  ASSERT_EQ(builder.SetNumThreads(42), kTfLiteOk);
  interpreter.reset();
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);

  ASSERT_EQ(builder.SetNumThreads(0), kTfLiteOk);
  interpreter.reset();
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);

  ASSERT_EQ(builder.SetNumThreads(-1), kTfLiteOk);
  interpreter.reset();
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);

  ASSERT_EQ(reporter.num_calls(), 0);
  ASSERT_EQ(builder.SetNumThreads(-2), kTfLiteError);
  interpreter.reset();
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(reporter.num_calls(), 1);
  ASSERT_PRED_FORMAT2(testing::IsSubstring, "num_threads should be >= 0 or just -1", reporter.error_messages());

}



TEST(FlexModel, FailureWithoutFlexDelegate) {
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/multi_add_flex.bin");
  ASSERT_TRUE(model);

  
  
  
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(InterpreterBuilder(*model, ops::builtin::BuiltinOpResolver{})(&interpreter), kTfLiteOk);

  ASSERT_TRUE(interpreter);

  
  
  ASSERT_EQ(interpreter->AllocateTensors(), kTfLiteError);
}



TEST(BasicFlatBufferModel, TestBrokenMmap) {
  ASSERT_FALSE(FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_model_broken.bin"));
}

TEST(BasicFlatBufferModel, TestNullModel) {
  
  std::unique_ptr<Interpreter> interpreter(new Interpreter);
  ASSERT_NE( InterpreterBuilder(nullptr, TrivialResolver(&dummy_reg))(&interpreter), kTfLiteOk);

  ASSERT_EQ(interpreter.get(), nullptr);
}


class FakeVerifier : public tflite::TfLiteVerifier {
 public:
  explicit FakeVerifier(bool result) : result_(result) {}
  bool Verify(const char* data, int length, tflite::ErrorReporter* reporter) override {
    return result_;
  }

 private:
  bool result_;
};

TEST(BasicFlatBufferModel, TestWithTrueVerifier) {
  FakeVerifier verifier(true);
  ASSERT_TRUE(FlatBufferModel::VerifyAndBuildFromFile( "tensorflow/lite/testdata/test_model.bin", &verifier));
}

TEST(BasicFlatBufferModel, TestWithFalseVerifier) {
  FakeVerifier verifier(false);
  ASSERT_FALSE(FlatBufferModel::VerifyAndBuildFromFile( "tensorflow/lite/testdata/test_model.bin", &verifier));
}

TEST(BasicFlatBufferModel, TestWithNullVerifier) {
  ASSERT_TRUE(FlatBufferModel::VerifyAndBuildFromFile( "tensorflow/lite/testdata/test_model.bin", nullptr));
}



TEST(BasicFlatBufferModel, TestCustomErrorReporter) {
  TestErrorReporter reporter;
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/empty_model.bin", &reporter);
  ASSERT_TRUE(model);

  std::unique_ptr<Interpreter> interpreter;
  TrivialResolver resolver;
  InterpreterBuilder(*model, resolver)(&interpreter);
  ASSERT_NE(interpreter->Invoke(), kTfLiteOk);
  ASSERT_EQ(reporter.num_calls(), 1);
}



TEST(BasicFlatBufferModel, TestNullErrorReporter) {
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/empty_model.bin", nullptr);
  ASSERT_TRUE(model);

  std::unique_ptr<Interpreter> interpreter;
  TrivialResolver resolver;
  InterpreterBuilder(*model, resolver)(&interpreter);
  ASSERT_NE(interpreter->Invoke(), kTfLiteOk);
}


TEST(BasicFlatBufferModel, TestBuildFromModel) {
  TestErrorReporter reporter;
  FileCopyAllocation model_allocation( "tensorflow/lite/testdata/test_model.bin", &reporter);
  ASSERT_TRUE(model_allocation.valid());
  ::flatbuffers::Verifier verifier( reinterpret_cast<const uint8_t*>(model_allocation.base()), model_allocation.bytes());

  ASSERT_TRUE(VerifyModelBuffer(verifier));
  const Model* model_fb = ::tflite::GetModel(model_allocation.base());

  auto model = FlatBufferModel::BuildFromModel(model_fb);
  ASSERT_TRUE(model);

  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ( InterpreterBuilder(*model, TrivialResolver(&dummy_reg))(&interpreter), kTfLiteOk);

  ASSERT_NE(interpreter, nullptr);
}


TEST(BasicFlatBufferModel, TestBuildFromAllocation) {
  TestErrorReporter reporter;
  std::unique_ptr<Allocation> model_allocation(new FileCopyAllocation( "tensorflow/lite/testdata/test_model.bin", &reporter));
  ASSERT_TRUE(model_allocation->valid());

  auto model = FlatBufferModel::BuildFromAllocation(std::move(model_allocation));
  ASSERT_TRUE(model);

  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ( InterpreterBuilder(*model, TrivialResolver(&dummy_reg))(&interpreter), kTfLiteOk);

  ASSERT_NE(interpreter, nullptr);
}

TEST(BasicFlatBufferModel, TestBuildFromNullAllocation) {
  TestErrorReporter reporter;
  std::unique_ptr<Allocation> model_allocation;

  auto model = FlatBufferModel::BuildFromAllocation(std::move(model_allocation));
  ASSERT_FALSE(model);
}

TEST(BasicFlatBufferModel, TestBuildFromInvalidAllocation) {
  TestErrorReporter reporter;
  std::unique_ptr<Allocation> model_allocation( new MemoryAllocation(nullptr, 0, nullptr));

  auto model = FlatBufferModel::BuildFromAllocation(std::move(model_allocation));
  ASSERT_FALSE(model);
}


TEST(BasicFlatBufferModel, TestReadRuntimeVersionFromModel) {
  
  auto model1 = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_model.bin");
  ASSERT_TRUE(model1);
  ASSERT_EQ(model1->GetMinimumRuntime(), "");

  
  auto model2 = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/test_min_runtime.bin");
  ASSERT_TRUE(model2);
  
  ASSERT_EQ(model2->GetMinimumRuntime(), "1.5.0");
}








TEST(BasicFlatBufferModel, TestParseModelWithSparseTensor) {
  
  auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/sparse_tensor.bin");
  ASSERT_TRUE(model);

  std::unique_ptr<Interpreter> interpreter(new Interpreter);
  ASSERT_EQ(InterpreterBuilder(*model, TrivialResolver())(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->tensors_size(), 2);
  TfLiteTensor* t1 = interpreter->tensor(0);
  ASSERT_EQ(t1->allocation_type, kTfLiteMmapRo);

  TfLiteIntArray* traversal_order = TfLiteIntArrayCreate(4);
  traversal_order->data[0] = 0;
  traversal_order->data[1] = 1;
  traversal_order->data[2] = 2;
  traversal_order->data[3] = 3;
  ASSERT_TRUE( TfLiteIntArrayEqual(t1->sparsity->traversal_order, traversal_order));
  TfLiteIntArrayFree(traversal_order);

  TfLiteIntArray* block_map = TfLiteIntArrayCreate(2);
  block_map->data[0] = 0;
  block_map->data[1] = 1;
  ASSERT_TRUE(TfLiteIntArrayEqual(t1->sparsity->block_map, block_map));
  TfLiteIntArrayFree(block_map);

  ASSERT_EQ(t1->sparsity->dim_metadata_size, 4);

  ASSERT_EQ(t1->sparsity->dim_metadata[0].format, kTfLiteDimDense);
  ASSERT_EQ(t1->sparsity->dim_metadata[0].dense_size, 2);
  ASSERT_EQ(t1->sparsity->dim_metadata[0].array_segments, nullptr);
  ASSERT_EQ(t1->sparsity->dim_metadata[0].array_indices, nullptr);

  ASSERT_EQ(t1->sparsity->dim_metadata[1].format, kTfLiteDimSparseCSR);
  ASSERT_EQ(t1->sparsity->dim_metadata[1].dense_size, 0);
  TfLiteIntArray* array_segments = TfLiteIntArrayCreate(3);
  array_segments->data[0] = 0;
  array_segments->data[1] = 2;
  array_segments->data[2] = 3;
  ASSERT_TRUE(TfLiteIntArrayEqual(t1->sparsity->dim_metadata[1].array_segments, array_segments));
  TfLiteIntArrayFree(array_segments);

  TfLiteIntArray* array_indices = TfLiteIntArrayCreate(3);
  array_indices->data[0] = 0;
  array_indices->data[1] = 1;
  array_indices->data[2] = 1;
  ASSERT_TRUE(TfLiteIntArrayEqual(t1->sparsity->dim_metadata[1].array_indices, array_indices));
  TfLiteIntArrayFree(array_indices);

  ASSERT_EQ(t1->sparsity->dim_metadata[2].format, kTfLiteDimDense);
  ASSERT_EQ(t1->sparsity->dim_metadata[2].dense_size, 2);
  ASSERT_EQ(t1->sparsity->dim_metadata[2].array_segments, nullptr);
  ASSERT_EQ(t1->sparsity->dim_metadata[2].array_indices, nullptr);

  ASSERT_EQ(t1->sparsity->dim_metadata[3].format, kTfLiteDimDense);
  ASSERT_EQ(t1->sparsity->dim_metadata[3].dense_size, 2);
  ASSERT_EQ(t1->sparsity->dim_metadata[3].array_segments, nullptr);
  ASSERT_EQ(t1->sparsity->dim_metadata[3].array_indices, nullptr);
}








TEST(BasicFlatBufferModel, TestHandleMalformedModelReuseTensor) {
  const auto model_path = "tensorflow/lite/testdata/add_shared_tensors.bin";

  std::unique_ptr<tflite::FlatBufferModel> model = FlatBufferModel::BuildFromFile(model_path);
  ASSERT_NE(model, nullptr);

  tflite::ops::builtin::BuiltinOpResolver resolver;
  InterpreterBuilder builder(*model, resolver);
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_NE(interpreter->AllocateTensors(), kTfLiteOk);
}






TEST(BasicFlatBufferModel, TestHandleMalformedModelInvalidBuffer) {
  const auto model_path = "tensorflow/lite/testdata/segment_sum_invalid_buffer.bin";

  std::unique_ptr<tflite::FlatBufferModel> model = FlatBufferModel::BuildFromFile(model_path);
  ASSERT_NE(model, nullptr);

  tflite::ops::builtin::BuiltinOpResolver resolver;
  InterpreterBuilder builder(*model, resolver);
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->AllocateTensors(), kTfLiteOk);
  ASSERT_NE(interpreter->Invoke(), kTfLiteOk);
}

TEST(TestAddDelegateOwnership, AddDelegateDoesNotTakeOwnership) {
  class TestDelegate : public TfLiteDelegate {
   public:
    TestDelegate(bool* destroyed, bool* prepared)
        : TfLiteDelegate(TfLiteDelegateCreate()), destroyed_(destroyed), prepared_(prepared) {

      flags = kTfLiteDelegateFlagsNone;
      Prepare = [](TfLiteContext*, TfLiteDelegate* delegate) -> TfLiteStatus {
        *(static_cast<TestDelegate*>(delegate)->prepared_) = true;
        return kTfLiteOk;
      };
    }
    ~TestDelegate() { *destroyed_ = true; }

   private:
    bool* destroyed_;
    bool* prepared_;
  };

  
  bool destroyed = false;
  bool prepared = false;
  {
    std::unique_ptr<TestDelegate> delegate( new TestDelegate(&destroyed, &prepared));
    {
      
      auto model = FlatBufferModel::BuildFromFile( "tensorflow/lite/testdata/empty_model.bin");
      ASSERT_TRUE(model);
      
      std::unique_ptr<Interpreter> interpreter;
      InterpreterBuilder builder(*model, TrivialResolver());
      builder.AddDelegate(delegate.get());  
      
      for (int i = 0; i < 3; i++) {
        prepared = false;
        ASSERT_EQ(builder(&interpreter), kTfLiteOk);
        ASSERT_NE(interpreter, nullptr);

        
        EXPECT_TRUE(prepared);
        EXPECT_FALSE(destroyed);

        
        interpreter->AllocateTensors();
        interpreter->Invoke();
        EXPECT_FALSE(destroyed);
      }
    }
    EXPECT_NE(delegate, nullptr);
    EXPECT_FALSE(destroyed);
  }
  
  
  EXPECT_TRUE(destroyed);
}





TEST(BasicFlatBufferModel, TestHandleModelWithWhileOpContainsForwardingInput) {
  const auto model_path = "tensorflow/lite/testdata/while_op_with_forwarding_input.bin";

  std::unique_ptr<tflite::FlatBufferModel> model = FlatBufferModel::BuildFromFile(model_path);
  ASSERT_NE(model, nullptr);

  tflite::ops::builtin::BuiltinOpResolver resolver;
  InterpreterBuilder builder(*model, resolver);
  std::unique_ptr<Interpreter> interpreter;
  ASSERT_EQ(builder(&interpreter), kTfLiteOk);
  ASSERT_NE(interpreter, nullptr);
  ASSERT_EQ(interpreter->AllocateTensors(), kTfLiteOk);

  int32_t* tensor_data = interpreter->typed_tensor<int32_t>(0);
  tensor_data[0] = 20;

  auto tensor = interpreter->tensor(1);
  DynamicBuffer buf;
  buf.AddString("a", 1);
  buf.WriteToTensor(tensor, nullptr);

  ASSERT_EQ(interpreter->Invoke(), kTfLiteOk);
}





}  

int main(int argc, char** argv) {
  ::tflite::LogToStderr();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
