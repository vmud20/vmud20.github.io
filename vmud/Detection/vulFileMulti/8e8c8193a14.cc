










namespace tensorflow {

TEST(CudnnRNNOpsTest, ParamsSize_ShapeFn) {
  ShapeInferenceTestOp op("CudnnRNNParamsSize");
  INFER_OK(op, "[];[];[]", "[1]");
  INFER_OK(op, "?;[];[]", "[1]");
  INFER_OK(op, "[];?;[]", "[1]");
  INFER_OK(op, "[];[];?", "[1]");
  INFER_OK(op, "[];?;?", "[1]");
  INFER_OK(op, "?;?;?", "[1]");

  INFER_ERROR("Shape must be rank 0 ", op, "[1,2];?;[]");
  INFER_ERROR("Shape must be rank 0 ", op, "?;[2];[]");
  INFER_ERROR("Shape must be rank 0 ", op, "?;?;[1]");
}

TEST(CudnnRNNOpsTest, ForwardLstm_ShapeFn) {
  int seq_length = 2;
  int batch_size = 3;
  int num_units = 4;
  int num_layers = 5;
  int dir_count = 1;
  std::vector<int> input_shape = {seq_length, batch_size, num_units};
  std::vector<int> input_h_shape = {num_layers * dir_count, batch_size, num_units};
  std::vector<int> output_shape = {seq_length, batch_size, num_units * dir_count};
  auto shape_to_str = [](const std::vector<int>& v) {
    return strings::StrCat("[", absl::StrJoin(v, ","), "]");
  };
  string input_shapes_desc = strings::StrCat( shape_to_str(input_shape), ";", shape_to_str(input_h_shape), ";", shape_to_str(input_h_shape), ";", "[?]");

  string output_shapes_desc = "[d0_0,d0_1,d1_2];in1;in1;?";

  ShapeInferenceTestOp op("CudnnRNN");
  TF_ASSERT_OK(NodeDefBuilder("test", "CudnnRNN")
                   .Input({"input", 0, DT_FLOAT})
                   .Input({"input_h", 0, DT_FLOAT})
                   .Input({"input_c", 0, DT_FLOAT})
                   .Input({"params", 0, DT_FLOAT})
                   .Attr("rnn_mode", "lstm")
                   .Attr("input_mode", "auto_select")
                   .Attr("direction", "unidirectional")
                   .Finalize(&op.node_def));
  INFER_OK(op, input_shapes_desc, output_shapes_desc);
}

TEST(CudnnRNNOpsTest, ForwardV2Lstm_ShapeFn) {
  int seq_length = 2;
  int batch_size = 3;
  int num_units = 4;
  int num_layers = 5;
  int dir_count = 1;
  std::vector<int> input_shape = {seq_length, batch_size, num_units};
  std::vector<int> input_h_shape = {num_layers * dir_count, batch_size, num_units};
  std::vector<int> output_shape = {seq_length, batch_size, num_units * dir_count};
  auto shape_to_str = [](const std::vector<int>& v) {
    return strings::StrCat("[", absl::StrJoin(v, ","), "]");
  };
  string input_shapes_desc = strings::StrCat( shape_to_str(input_shape), ";", shape_to_str(input_h_shape), ";", shape_to_str(input_h_shape), ";", "[?]");

  string output_shapes_desc = "[d0_0,d0_1,d1_2];in1;in1;?;?";

  ShapeInferenceTestOp op("CudnnRNNV2");
  TF_ASSERT_OK(NodeDefBuilder("test", "CudnnRNNV2")
                   .Input({"input", 0, DT_FLOAT})
                   .Input({"input_h", 0, DT_FLOAT})
                   .Input({"input_c", 0, DT_FLOAT})
                   .Input({"params", 0, DT_FLOAT})
                   .Attr("rnn_mode", "lstm")
                   .Attr("input_mode", "auto_select")
                   .Attr("direction", "unidirectional")
                   .Finalize(&op.node_def));
  INFER_OK(op, input_shapes_desc, output_shapes_desc);
}

TEST(CudnnRNNOpsTest, ForwardV3Lstm_ShapeFn) {
  int max_seq_length = 2;
  int batch_size = 3;
  int num_units = 4;
  int num_layers = 5;
  int dir_count = 1;
  std::vector<int> input_shape = {max_seq_length, batch_size, num_units};
  std::vector<int> input_h_shape = {num_layers * dir_count, batch_size, num_units};
  std::vector<int> input_c_shape = {num_layers * dir_count, batch_size, num_units};
  std::vector<int> output_shape = {max_seq_length, batch_size, num_units * dir_count};
  std::vector<int> seq_lengths_shape = {batch_size};
  auto shape_to_str = [](const std::vector<int>& v) {
    return strings::StrCat("[", absl::StrJoin(v, ","), "]");
  };
  string input_shapes_desc = strings::StrCat( shape_to_str(input_shape), ";", shape_to_str(input_h_shape), ";", shape_to_str(input_c_shape), ";", "[?]", ";", shape_to_str(seq_lengths_shape));


  string output_shapes_desc = "[d0_0,d0_1,d1_2];in1;in2;?;?";

  ShapeInferenceTestOp op("CudnnRNNV3");
  TF_ASSERT_OK(NodeDefBuilder("test", "CudnnRNNV3")
                   .Input({"input", 0, DT_FLOAT})
                   .Input({"input_h", 0, DT_FLOAT})
                   .Input({"input_c", 0, DT_FLOAT})
                   .Input({"params", 0, DT_FLOAT})
                   .Input({"sequence_lengths", 0, DT_INT32})
                   .Attr("rnn_mode", "lstm")
                   .Attr("input_mode", "auto_select")
                   .Attr("direction", "unidirectional")
                   .Finalize(&op.node_def));
  INFER_OK(op, input_shapes_desc, output_shapes_desc);
}

}  
