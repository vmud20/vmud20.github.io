














namespace tensorflow {

class RequantizeTest : public OpsTestBase {
 protected:
  void ConfigureRequantize() {
    TF_ASSERT_OK(NodeDefBuilder("requantize", "Requantize")
                     .Input(FakeInput(DT_QINT32))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Input(FakeInput(DT_FLOAT))
                     .Attr("Tinput", DataTypeToEnum<qint32>::v())
                     .Attr("out_type", DataTypeToEnum<quint8>::v())
                     .Finalize(node_def()));
    TF_ASSERT_OK(InitOp());
  }
};



TEST_F(RequantizeTest, HandCraftedRequantize) {
  ConfigureRequantize();
  const int value_count = 3;

  
  AddInputFromArray<qint32>(TensorShape({value_count}), {-(1 << 23), 0, (1 << 23)});
  AddInputFromArray<float>(TensorShape({1}), {-256.0f});
  AddInputFromArray<float>(TensorShape({1}), {256.0f});
  AddInputFromArray<float>(TensorShape({1}), {-1.0f});
  AddInputFromArray<float>(TensorShape({1}), {1.0f});
  TF_ASSERT_OK(RunOpKernel());
  Tensor expected(allocator(), DT_QUINT8, TensorShape({value_count}));
  test::FillValues<quint8>(&expected, {0, 128, 255});
  test::ExpectTensorEqual<quint8>(expected, *GetOutput(0));
  test::ExpectTensorEqual<float>(test::AsScalar<float>(-1.0f), *GetOutput(1));
  test::ExpectTensorEqual<float>(test::AsScalar<float>(1.0f), *GetOutput(2));
}

TEST_F(RequantizeTest, InvalidOutputMin) {
  ConfigureRequantize();
  const int value_count = 3;

  AddInputFromArray<qint32>(TensorShape({value_count}), {-(1 << 23), 0, (1 << 23)});
  AddInputFromArray<float>(TensorShape({1}), {-256.0f});
  AddInputFromArray<float>(TensorShape({1}), {256.0f});
  AddInputFromArray<float>(TensorShape({1}), {0.01f});
  AddInputFromArray<float>(TensorShape({1}), {1.0f});
  EXPECT_EQ("requested_output_min must be <= 0, but got 0.01", RunOpKernel().error_message());
}

TEST_F(RequantizeTest, InvalidOutputMax) {
  ConfigureRequantize();
  const int value_count = 3;

  AddInputFromArray<qint32>(TensorShape({value_count}), {-(1 << 23), 0, (1 << 23)});
  AddInputFromArray<float>(TensorShape({1}), {-256.0f});
  AddInputFromArray<float>(TensorShape({1}), {256.0f});
  AddInputFromArray<float>(TensorShape({1}), {-10.0f});
  AddInputFromArray<float>(TensorShape({1}), {-11.0f});
  EXPECT_EQ( "requested_output_max must be >= requested_output_min, but got -11 and " "-10", RunOpKernel().error_message());


}

}  
