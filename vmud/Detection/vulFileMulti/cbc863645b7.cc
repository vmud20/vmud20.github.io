















namespace tflite {
namespace {



void RunOneAveragePoolTest(const PoolParams& params, const RuntimeShape& input_shape, const int8* input_data, const RuntimeShape& output_shape) {


  const int buffer_size = output_shape.FlatSize();
  std::vector<int8> optimized_averagePool_output(buffer_size);
  std::vector<int8> reference_averagePool_output(buffer_size);

  reference_integer_ops::AveragePool(params, input_shape, input_data, output_shape, reference_averagePool_output.data());

  optimized_integer_ops::AveragePool(params, input_shape, input_data, output_shape, optimized_averagePool_output.data());


  for (int i = 0; i < buffer_size; i++) {
    EXPECT_TRUE(reference_averagePool_output[i] == optimized_averagePool_output[i]);
  }
}







void CreateDataAndRunAveragePool(bool padding_same) {
  const int batch = UniformRandomInt(1, 2);
  const int input_depth = UniformRandomInt(1, 700);
  const int output_depth = input_depth;
  const int input_width_offset = UniformRandomInt(1, 30);
  const int input_height_offset = UniformRandomInt(1, 30);
  const int stride_width = UniformRandomInt(1, 10);
  const int stride_height = UniformRandomInt(1, 10);
  const int filter_width = UniformRandomInt(1, 10);
  const int filter_height = UniformRandomInt(1, 10);
  const int input_width = input_width_offset + filter_width;
  const int input_height = input_height_offset + filter_height;
  const int output_width = padding_same ? (input_width + stride_width - 1) / stride_width : (input_width - filter_width + stride_width) / stride_width;

  const int output_height = padding_same ? (input_height + stride_height - 1) / stride_height : (input_height - filter_height + stride_height) / stride_height;



  auto input_shape = RuntimeShape({batch, input_height, input_width, input_depth});
  auto output_shape = RuntimeShape({batch, output_height, output_width, output_depth});
  const int buffer_size = input_shape.FlatSize();
  std::vector<int8> input_data(buffer_size);
  FillRandom(&input_data);

  PoolParams params;
  params.stride_height = stride_height;
  params.stride_width = stride_width;
  params.filter_height = filter_height;
  params.filter_width = filter_width;
  params.quantized_activation_min = static_cast<int8_t>(std::numeric_limits<int8_t>::lowest());
  params.quantized_activation_max = static_cast<int8_t>(std::numeric_limits<int8_t>::max());
  auto compute_padding = [](int stride, int in_size, int filter_size, int out_size) {
    int padding = ((out_size - 1) * stride + filter_size - in_size) / 2;
    return padding > 0 ? padding : 0;
  };
  params.padding_values.width = compute_padding(stride_width, input_width, filter_width, output_width);
  params.padding_values.height = compute_padding(stride_height, input_height, filter_height, output_height);
  RunOneAveragePoolTest(params, input_shape, input_data.data(), output_shape);
}

TEST(TestAveragePool, SymmetricQuantAveragePool) {
  const int kTestsToRun = 10;
  for (int i = 0; i < kTestsToRun; i++) {
    CreateDataAndRunAveragePool(true);
    CreateDataAndRunAveragePool(false);
  }
}







void CreateExtremalDataAndRunAveragePool(bool padding_same) {
  const int batch = UniformRandomInt(1, 2);
  const int input_depth = UniformRandomInt(1, 700);
  const int output_depth = input_depth;
  const int input_width_offset = UniformRandomInt(1, 30);
  const int input_height_offset = UniformRandomInt(1, 30);
  const int stride_width = UniformRandomInt(1, 128);
  const int stride_height = UniformRandomInt(1, 128);
  const int filter_width = UniformRandomInt(1, 28);
  const int filter_height = UniformRandomInt(1, 28);
  if (filter_width * filter_height > 64) {
    std::cout << "should test 32 version" << std::endl;
  }
  const int input_width = input_width_offset + filter_width;
  const int input_height = input_height_offset + filter_height;
  const int output_width = padding_same ? (input_width + stride_width - 1) / stride_width : (input_width - filter_width + stride_width) / stride_width;

  const int output_height = padding_same ? (input_height + stride_height - 1) / stride_height : (input_height - filter_height + stride_height) / stride_height;



  auto input_shape = RuntimeShape({batch, input_height, input_width, input_depth});
  auto output_shape = RuntimeShape({batch, output_height, output_width, output_depth});

  PoolParams params;
  params.stride_height = stride_height;
  params.stride_width = stride_width;
  params.filter_height = filter_height;
  params.filter_width = filter_width;
  params.quantized_activation_min = static_cast<int8_t>(std::numeric_limits<int8_t>::lowest());
  params.quantized_activation_max = static_cast<int8_t>(std::numeric_limits<int8_t>::max());
  auto compute_padding = [](int stride, int in_size, int filter_size, int out_size) {
    int padding = ((out_size - 1) * stride + filter_size - in_size) / 2;
    return padding > 0 ? padding : 0;
  };
  params.padding_values.width = compute_padding(stride_width, input_width, filter_width, output_width);
  params.padding_values.height = compute_padding(stride_height, input_height, filter_height, output_height);

  const int buffer_size = input_shape.FlatSize();
  std::vector<int8> input_data(buffer_size);

  
  int8 min = std::numeric_limits<int8>::min();
  int8 max = std::numeric_limits<int8>::min() + 10;
  FillRandom(&input_data, min, max);
  RunOneAveragePoolTest(params, input_shape, input_data.data(), output_shape);

  
  min = std::numeric_limits<int8>::max() - 10;
  max = std::numeric_limits<int8>::max();
  FillRandom(&input_data, min, max);
  RunOneAveragePoolTest(params, input_shape, input_data.data(), output_shape);
}

TEST(TestAveragePool, SymmetricQuantExtremalAveragePool) {
  CreateExtremalDataAndRunAveragePool(true);
  CreateExtremalDataAndRunAveragePool(false);
}

}  
}  
