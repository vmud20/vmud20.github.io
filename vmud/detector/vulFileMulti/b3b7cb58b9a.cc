

















namespace tensorflow {

class QuantizedActivationsTest : public OpsTestBase {
 protected:
};

TEST_F(QuantizedActivationsTest, TestRelu) {
  TF_ASSERT_OK(NodeDefBuilder("quantized_relu_op", "QuantizedRelu")
                   .Input(FakeInput(DT_QUINT8))
                   .Input(FakeInput(DT_FLOAT))
                   .Input(FakeInput(DT_FLOAT))
                   .Finalize(node_def()));
  TF_ASSERT_OK(InitOp());
  const float input_min = -128.0f;
  const float input_max = 127.0f;
  const int input_width = 2;
  const int input_height = 4;
  Tensor input_float(DT_FLOAT, {input_height, input_width});
  test::FillValues<float>(&input_float, {-100, -1, 0, 1, 3, 6, 7, 100});
  Tensor input_quantized = FloatTensorToQuantized<quint8>(input_float, input_min, input_max);
  Tensor expected_float(DT_FLOAT, {input_height, input_width});
  test::FillValues<float>(&expected_float, {0, 0, 0, 1, 3, 6, 7, 100});

  AddInputFromArray<quint8>(input_quantized.shape(), input_quantized.flat<quint8>());
  AddInputFromArray<float>(TensorShape({1}), {input_min});
  AddInputFromArray<float>(TensorShape({1}), {input_max});
  TF_ASSERT_OK(RunOpKernel());
  const Tensor& output_quantized = *GetOutput(0);
  const float output_min = GetOutput(1)->flat<float>()(0);
  const float output_max = GetOutput(2)->flat<float>()(0);
  Tensor output_float = QuantizedTensorToFloat<quint8>(output_quantized, output_min, output_max);
  test::ExpectTensorNear<float>(expected_float, output_float, 0.2);
}

TEST_F(QuantizedActivationsTest, TestRelu6) {
  TF_ASSERT_OK(NodeDefBuilder("quantized_relu6_op", "QuantizedRelu6")
                   .Input(FakeInput(DT_QUINT8))
                   .Input(FakeInput(DT_FLOAT))
                   .Input(FakeInput(DT_FLOAT))
                   .Finalize(node_def()));
  TF_ASSERT_OK(InitOp());
  const float input_min = -128.0f;
  const float input_max = 127.0f;
  const int input_width = 2;
  const int input_height = 4;
  Tensor input_float(DT_FLOAT, {input_height, input_width});
  test::FillValues<float>(&input_float, {-100, -1, 0, 1, 3, 6, 7, 100});
  Tensor input_quantized = FloatTensorToQuantized<quint8>(input_float, input_min, input_max);
  Tensor expected_float(DT_FLOAT, {input_height, input_width});
  test::FillValues<float>(&expected_float, {0, 0, 0, 1, 3, 6, 6, 6});

  AddInputFromArray<quint8>(input_quantized.shape(), input_quantized.flat<quint8>());
  AddInputFromArray<float>(TensorShape({1}), {input_min});
  AddInputFromArray<float>(TensorShape({1}), {input_max});
  TF_ASSERT_OK(RunOpKernel());
  const Tensor& output_quantized = *GetOutput(0);
  const float output_min = GetOutput(1)->flat<float>()(0);
  const float output_max = GetOutput(2)->flat<float>()(0);
  Tensor output_float = QuantizedTensorToFloat<quint8>(output_quantized, output_min, output_max);
  test::ExpectTensorNear<float>(expected_float, output_float, 0.2);
}

}  
