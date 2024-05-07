













namespace tensorflow {

TEST(ArrayOpsTest, TensorScatterUpdate_ShapeFn) {
  ShapeInferenceTestOp op("TensorScatterUpdate");

  INFER_OK(op, "[4,3];[8,2];[8]", "in0");
  INFER_OK(op, "[?,?];[?,2];[?]", "in0");
  INFER_OK(op, "[?];[?];[?]", "in0");

  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[];[?,2];[?]");
  INFER_ERROR("Indices and updates specified for empty input", op, "[0,2,2];[8,2];[8]");
  INFER_ERROR( "Dimensions [0,1) of indices[shape=[8,2]] = [8] must match " "dimensions [0,1) of updates[shape=[9]] = [9]", op, "[?,?];[8,2];[9]");


  INFER_ERROR( "Dimensions [2,2) of input[shape=[?,?]] = [] must match " "dimensions [1,2) of updates[shape=[?,1]] = [1]", op, "[?,?];[?,2];[?,1]");


}

TEST(ArrayOpsTest, ScatterNd_ShapeFn) {
  ShapeInferenceTestOp op("ScatterNd");

  INFER_OK(op, "[8,2];[8];[2]", "[?,?]");

  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[?,2];[?];[]");
  INFER_ERROR( "Dimensions [0,1) of indices[shape=[8,2]] = [8] must match " "dimensions [0,1) of updates[shape=[9]] = [9]", op, "[8,2];[9];[?]");


}

TEST(ArrayOpsTest, UnravelIndex_ShapeFn) {
  ShapeInferenceTestOp op("UnravelIndex");

  INFER_OK(op, "?;?", "?");

  INFER_OK(op, "[];[?]", "[d1_0]");

  INFER_OK(op, "[4,5];[?]", "[d1_0,20]");
  INFER_OK(op, "[2,3,4];[?]", "[d1_0,24]");
  INFER_OK(op, "?;[?]", "?");
  INFER_OK(op, "[?];[?]", "[d1_0,?]");

  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[1,1]");
}

TEST(ArrayOpsTest, Pack_ShapeFn) {
  ShapeInferenceTestOp op("Pack");
  auto set_axis = [&op](int axis) {
    int n = 3;
    std::vector<NodeDefBuilder::NodeOut> src_list;
    src_list.reserve(n);
    for (int i = 0; i < n; ++i) src_list.emplace_back("a", 0, DT_FLOAT);
    TF_ASSERT_OK(NodeDefBuilder("test", "Pack")
                     .Input(src_list)
                     .Attr("N", n)
                     .Attr("axis", axis)
                     .Finalize(&op.node_def));
  };

  set_axis(0);
  INFER_OK(op, "?;?;?", "?");

  for (int axis : {0, -3}) {
    set_axis(axis);
    INFER_OK(op, "?;?;?", "?");
    INFER_OK(op, "[1,3];[1,3];?", "[3,d0_0|d1_0,d0_1|d1_1]");
    INFER_OK(op, "[?,3];[1,3];?", "[3,d1_0,d0_1|d1_1]");
    INFER_OK(op, "[?,?];[1,3];?", "[3,d1_0,d1_1]");
  }
  for (int axis : {1, -2}) {
    set_axis(axis);
    INFER_OK(op, "?;?;?", "?");
    INFER_OK(op, "[1,3];[1,3];?", "[d0_0|d1_0,3,d0_1|d1_1]");
    INFER_OK(op, "[?,3];[1,3];?", "[d1_0,3,d0_1|d1_1]");
    INFER_OK(op, "[?,?];[1,3];?", "[d1_0,3,d1_1]");
  }
  for (int axis : {2, -1}) {
    set_axis(axis);
    INFER_OK(op, "?;?;?", "?");
    INFER_OK(op, "[1,3];[1,3];?", "[d0_0|d1_0,d0_1|d1_1,3]");
    INFER_OK(op, "[?,3];[1,3];?", "[d1_0,d0_1|d1_1,3]");
    INFER_OK(op, "[?,?];[1,3];?", "[d1_0,d1_1,3]");
  }

  set_axis(-4);
  INFER_ERROR("Invalid axis: -4; must be in [-3,3)", op, "[1,3];[1,3];?");
  set_axis(3);
  INFER_ERROR("Invalid axis: 3; must be in [-3,3)", op, "[1,3];[1,3];?");

  set_axis(0);

  
  INFER_ERROR("Shapes must be equal rank, but are 3 and 2", op, "[1,2,3];?;[1,4]");
  INFER_ERROR("From merging shape 0 with other shapes.", op, "[1,2,3];?;[1,4]");
}

TEST(ArrayOpsTest, UnPack_ShapeFn) {
  ShapeInferenceTestOp op("Unpack");
  auto set_axis_and_num = [&op](int axis, int num) {
    TF_ASSERT_OK(NodeDefBuilder("test", "Unpack")
                     .Input("a", 0, DT_FLOAT)
                     .Attr("axis", axis)
                     .Attr("num", num)
                     .Finalize(&op.node_def));
  };

  set_axis_and_num(0, 1);
  INFER_OK(op, "?", "?");

  for (int axis : {0, -3}) {
    set_axis_and_num(axis, 1);
    INFER_OK(op, "?", "?");
    INFER_OK(op, "[1,2,3]", "[d0_1,d0_2]");
    INFER_OK(op, "[?,?,?]", "[d0_1,d0_2]");
  }
  for (int axis : {1, -2}) {
    set_axis_and_num(axis, 2);
    INFER_OK(op, "[1,2,3]", "[d0_0,d0_2];[d0_0,d0_2]");
    INFER_OK(op, "[?,?,?]", "[d0_0,d0_2];[d0_0,d0_2]");
  }
  for (int axis : {2, -1}) {
    set_axis_and_num(axis, 3);
    INFER_OK(op, "[1,2,3]", "[d0_0,d0_1];[d0_0,d0_1];[d0_0,d0_1]");
    INFER_OK(op, "[?,?,?]", "[d0_0,d0_1];[d0_0,d0_1];[d0_0,d0_1]");
  }

  set_axis_and_num(2, 2);
  INFER_ERROR("Dimension must be 2 but is 3", op, "[1,2,3]");

  set_axis_and_num(-4, 3);
  INFER_ERROR("Invalid axis: -4; must be in [-3,3)", op, "[1,2,3]");
  set_axis_and_num(3, 3);
  INFER_ERROR("Invalid axis: 3; must be in [-3,3)", op, "[1,2,3]");
}

TEST(ArrayOpsTest, Const_ShapeFn) {
  ShapeInferenceTestOp op("Const");
  TensorProto tensor_proto;
  auto* shape_proto = tensor_proto.mutable_tensor_shape();
  auto rebuild_node_def = [&op, &tensor_proto]() {
    TF_ASSERT_OK(NodeDefBuilder("test", "Const")
                     .Attr("value", tensor_proto)
                     .Finalize(&op.node_def));
  };

  TensorShape{}.AsProto(shape_proto);
  rebuild_node_def();
  INFER_OK(op, "", "[]");
  TensorShape{1, 2, 3, 4}.AsProto(shape_proto);
  rebuild_node_def();
  INFER_OK(op, "", "[1,2,3,4]");

  shape_proto->add_dim()->set_size(-1);
  rebuild_node_def();
  INFER_ERROR("Shape [1,2,3,4,?] is not fully defined", op, "");
}

TEST(ArrayOpsTest, UnchangedShapes_ShapeFn) {
  for (const char* op_name : {
           "CheckNumerics", "Identity", "RefIdentity", "QuantizeAndDequantize", "StopGradient", "ZerosLike", "OnesLike", }) {






    ShapeInferenceTestOp op(op_name);
    INFER_OK(op, "?", "in0");
    INFER_OK(op, "[]", "in0");
    INFER_OK(op, "[1,2,?,4,5]", "in0");
  }

  
  ShapeInferenceTestOp op("MatrixBandPart");
  INFER_OK(op, "?;?;?", "in0");
  INFER_OK(op, "[];?;?", "in0");
  INFER_OK(op, "[1,2,?,4,5];?;?", "in0");
}

TEST(ArrayOpsTest, GuaranteeConst_ShapeFn) {
  ShapeInferenceTestOp op("GuaranteeConst");
  INFER_OK(op, "?", "in0");
  INFER_OK(op, "[]", "in0");
  INFER_OK(op, "[1,2,?,4,5]", "in0");
}

TEST(ArrayOpsTest, Identity_ShapeFnHandles) {
  const char* op_name = "Identity";
  ShapeInferenceTestOp op(op_name);
  
  const OpRegistrationData* op_reg_data;
  TF_ASSERT_OK(OpRegistry::Global()->LookUp(op.name, &op_reg_data));
  std::vector< std::unique_ptr<std::vector<std::pair<PartialTensorShape, DataType>>>> handle_data;

  handle_data.emplace_back( new std::vector<std::pair<PartialTensorShape, DataType>>( {{PartialTensorShape(), DT_BOOL}}));

  shape_inference::InferenceContext c( TF_GRAPH_DEF_VERSION, op.node_def, op_reg_data->op_def, {PartialTensorShape()}, {}, {}, handle_data);

  TF_ASSERT_OK(c.construction_status());
  ASSERT_TRUE(op_reg_data->shape_inference_fn != nullptr);
  TF_ASSERT_OK(c.Run(op_reg_data->shape_inference_fn));

  const auto* shapes_and_types = c.output_handle_shapes_and_types(0);
  ASSERT_TRUE(shapes_and_types != nullptr);
  ASSERT_EQ(1, shapes_and_types->size());
  EXPECT_EQ((*shapes_and_types)[0].dtype, DT_BOOL);
}

TEST(ArrayOpsTest, Diag_ShapeFn) {
  ShapeInferenceTestOp op("Diag");
  INFER_OK(op, "?", "?");
  INFER_OK(op, "[1,?,3]", "[d0_0,d0_1,d0_2,d0_0,d0_1,d0_2]");
  INFER_OK(op, "[?,1,2,3]", "[d0_0,d0_1,d0_2,d0_3,d0_0,d0_1,d0_2,d0_3]");
  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[]");
}

TEST(ArrayOpsTest, DiagPart_ShapeFn) {
  ShapeInferenceTestOp op("DiagPart");
  INFER_OK(op, "?", "?");
  INFER_OK(op, "[1,?,?,4]", "[d0_0,d0_3]");
  INFER_OK(op, "[1,?,3,?,4,3]", "[d0_0,d0_4,d0_2|d0_5]");
  INFER_OK(op, "[1,2,3,?,?,?,?,4]", "[d0_0,d0_1,d0_2,d0_7]");
  INFER_ERROR("Input must have even and non-zero rank", op, "[]");
  INFER_ERROR("Input must have even and non-zero rank", op, "[?]");
  INFER_ERROR("Input must have even and non-zero rank", op, "[1,2,3]");
  INFER_ERROR("Dimensions must be equal, but are 2 and 10", op, "[1,2,?,10]");
}

TEST(ArrayOpsTest, MatrixDiag_ShapeFn) {
  ShapeInferenceTestOp op("MatrixDiag");
  INFER_OK(op, "?", "?");
  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[]");
  INFER_OK(op, "[?]", "[d0_0,d0_0]");
  INFER_OK(op, "[1,?,?,4]", "[d0_0,d0_1,d0_2,d0_3,d0_3]");
}

TEST(ArrayOpsTest, MatrixDiagPart_ShapeFn) {
  ShapeInferenceTestOp op("MatrixDiagPart");
  INFER_OK(op, "?", "?");
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[?]");
  INFER_OK(op, "[?,1,2,2]", "[d0_0,d0_1,d0_2|d0_3]");
  INFER_OK(op, "[?,1,2,3]", "[d0_0,d0_1,d0_2]");
  INFER_OK(op, "[?,1,3,2]", "[d0_0,d0_1,d0_3]");
}

TEST(ArrayOpsTest, Reverse_ShapeFn) {
  ShapeInferenceTestOp op("Reverse");
  INFER_OK(op, "?;?", "in0");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "?;[]");
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[?,2]");
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];[4]");
  INFER_ERROR("reverse does not work on tensors with more than 8 dimensions", op, "[1,2,3,4,5,6,7,8,9];[9]");
  INFER_OK(op, "[1,2,3,?];[4]", "in0");
  INFER_OK(op, "[1,2,3,?,5,6,7,8];[8]", "in0");
}

TEST(ArrayOpsTest, ReverseV2_ShapeFn) {
  ShapeInferenceTestOp op("ReverseV2");
  INFER_OK(op, "?;?", "in0");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "?;[]");
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[?,2]");
  INFER_OK(op, "[1,2,3];[2]", "in0");
  INFER_ERROR("reverse does not work on tensors with more than 8 dimensions", op, "[1,2,3,4,5,6,7,8,9];[9]");
  INFER_OK(op, "[1,2,3,?];[4]", "in0");
  INFER_OK(op, "[1,2,3,?,5,6,7,8];[8]", "in0");
}

TEST(ArrayOpsTest, Fill_ShapeFn) {
  ShapeInferenceTestOp op("Fill");
  AddNodeAttr("index_type", DT_INT32, &op.node_def);
  op.input_tensors.resize(2);
  INFER_OK(op, "?;?", "?");
  INFER_OK(op, "[?];?", "?");
  INFER_OK(op, "[4];?", "[?,?,?,?]");

  Tensor in_t = test::AsTensor<int32>({1, 2, 3, 4});
  op.input_tensors[0] = &in_t;
  INFER_OK(op, "[4];?", "[1,2,3,4]");
}

TEST(ArrayOpsTest, Gather_ShapeFn) {
  ShapeInferenceTestOp op("Gather");
  INFER_OK(op, "?;?", "?");
  INFER_OK(op, "[1,?,2];[3]", "[d1_0,d0_1,d0_2]");
  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[];[1,2,3]");
}

TEST(ArrayOpsTest, GatherV2_ShapeFn) {
  ShapeInferenceTestOp op("GatherV2");
  AddNodeAttr("batch_dims", 0, &op.node_def);

  
  INFER_OK(op, "?;?;?", "?");
  INFER_OK(op, "[1,2,3];[3];[]", "[?,?,?]");
  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[];[1,2,3];[]");

  
  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "[1];[1,2,3];[1]");

  
  Tensor axis_dim_t;
  op.input_tensors.resize(3);
  op.input_tensors[2] = &axis_dim_t;

  
  axis_dim_t = test::AsScalar(1);
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[1];[1,2];[]");

  
  axis_dim_t = test::AsScalar(0);
  INFER_OK(op, "[1,2,3];[];[]", "[d0_1,d0_2]");
  axis_dim_t = test::AsScalar(1);
  INFER_OK(op, "[1,2,3];[];[]", "[d0_0,d0_2]");
  axis_dim_t = test::AsScalar(2);
  INFER_OK(op, "[1,2,3];[];[]", "[d0_0,d0_1]");

  
  axis_dim_t = test::AsScalar(0);
  INFER_OK(op, "[1,2,3];[5];[]", "[d1_0,d0_1,d0_2]");
  axis_dim_t = test::AsScalar(1);
  INFER_OK(op, "[1,2,3];[5];[]", "[d0_0,d1_0,d0_2]");
  axis_dim_t = test::AsScalar(2);
  INFER_OK(op, "[1,2,3];[5];[]", "[d0_0,d0_1,d1_0]");

  
  axis_dim_t = test::AsScalar(0);
  INFER_OK(op, "[1,2,3];[5,6];[]", "[d1_0,d1_1,d0_1,d0_2]");
  axis_dim_t = test::AsScalar(1);
  INFER_OK(op, "[1,2,3];[5,6];[]", "[d0_0,d1_0,d1_1,d0_2]");
  axis_dim_t = test::AsScalar(2);
  INFER_OK(op, "[1,2,3];[5,6];[]", "[d0_0,d0_1,d1_0,d1_1]");

  
  axis_dim_t = test::AsScalar(-3);
  INFER_OK(op, "[1,2,3];[5,6];[]", "[d1_0,d1_1,d0_1,d0_2]");
  axis_dim_t = test::AsScalar(-2);
  INFER_OK(op, "[1,2,3];[5,6];[]", "[d0_0,d1_0,d1_1,d0_2]");
  axis_dim_t = test::AsScalar(-1);
  INFER_OK(op, "[1,2,3];[5,6];[]", "[d0_0,d0_1,d1_0,d1_1]");

  
  
  ShapeInferenceTestOp batch_op("GatherV2");
  AddNodeAttr("batch_dims", 1, &batch_op.node_def);
  INFER_OK(batch_op, "[1,4800,8];[1,28400];[]", "[?,?,?]");

  ShapeInferenceTestOp batch_op_2("GatherV2");
  AddNodeAttr("batch_dims", 2, &batch_op_2.node_def);
  INFER_OK(batch_op_2, "[1,2,3,4,5];[1,2,3];[]", "[?,?,?,?,?]");
}

TEST(ArrayOpsTest, GatherNd_ShapeFn) {
  ShapeInferenceTestOp op("GatherNd");

  
  INFER_OK(op, "?;?", "?");
  INFER_OK(op, "[1,?,3,?];[?,0]", "[d1_0,d0_0,d0_1,d0_2,d0_3]");
  INFER_OK(op, "[1,?,3,?];[?,4]", "[d1_0]");

  
  INFER_ERROR("indices.shape[-1] must be <= params.rank", op, "[1,2,3];[4]");
}

TEST(ArrayOpsTest, Shape_ShapeFn) {
  ShapeInferenceTestOp op("Shape");
  INFER_OK(op, "?", "[?]");
  INFER_OK(op, "[?]", "[1]");
  INFER_OK(op, "[?,2,3,4,5]", "[5]");
}

TEST(ArrayOpsTest, ShapeN_ShapeFn) {
  ShapeInferenceTestOp op("ShapeN");
  int n = 3;
  std::vector<NodeDefBuilder::NodeOut> src_list;
  src_list.reserve(n);
  for (int i = 0; i < n; ++i) src_list.emplace_back("a", 0, DT_FLOAT);
  TF_ASSERT_OK(NodeDefBuilder("test", "ShapeN")
                   .Input(src_list)
                   .Attr("N", n)
                   .Finalize(&op.node_def));
  INFER_OK(op, "?;?;?", "[?];[?];[?]");
  INFER_OK(op, "[?];[?];[?]", "[1];[1];[1]");
  INFER_OK(op, "[?,2,3,4,5];?;[1,?,3]", "[5];[?];[3]");
}

TEST(ArrayOpsTest, Unique_ShapeFn) {
  ShapeInferenceTestOp op("Unique");
  INFER_OK(op, "?", "[?];in0");
  INFER_OK(op, "[5]", "[?];in0");
  INFER_ERROR("Shape must be rank 1 but is rank 5", op, "[1,2,3,?,5]");
}

TEST(ArrayOpsTest, UniqueWithCounts_ShapeFn) {
  ShapeInferenceTestOp op("UniqueWithCounts");
  INFER_OK(op, "?", "[?];in0;[?]");
  INFER_OK(op, "[1,2,3,?,5]", "[?];in0;[?]");
}

TEST(ArrayOpsTest, InvertPermutation_ShapeFn) {
  ShapeInferenceTestOp op("InvertPermutation");
  INFER_OK(op, "?", "[?]");
  INFER_OK(op, "[1]", "in0");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[]");
}

TEST(ArrayOpsTest, PadD_ShapeFn) {
  for (const char* op_name : {"Pad", "MirrorPad") {
    ShapeInferenceTestOp op(op_name);
    op.input_tensors.resize(2);

    

    INFER_OK(op, "?;?", "?");

    
    INFER_ERROR("Shape must be rank 2 but is rank 3", op, "?;[1,2,3]");
    INFER_ERROR("Dimension must be 2 but is 4", op, "?;[1,4]");

    
    
    INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];[4,2]");
    INFER_OK(op, "[1,2,3];?", "[?,?,?]");
    INFER_OK(op, "?;[3,2]", "[?,?,?]");

    
    
    
    Tensor paddings_t(DT_INT64, TensorShape{3, 2});
    test::FillValues<int64_t>(&paddings_t, {1, 10, 2, 20, 3, 30});
    op.input_tensors[1] = &paddings_t;
    INFER_OK(op, "[100,200,300];[3,2]", "[111,222,333]");
    INFER_OK(op, "[100,?,300];[3,2]", "[111,?,333]");
    INFER_OK(op, "?;[3,2]", "[?,?,?]");
    INFER_OK(op, "?;?", "[?,?,?]");
  }
}

TEST(ArrayOpsTest, PadV2_ShapeFn) {
  ShapeInferenceTestOp op("PadV2");
  op.input_tensors.resize(3);

  

  INFER_OK(op, "?;?;?", "?");

  
  INFER_ERROR("Shape must be rank 2 but is rank 3", op, "?;[1,2,3];?");
  INFER_ERROR("Dimension must be 2 but is 4", op, "?;[1,4];?");

  
  
  INFER_ERROR("Shape must be rank 4 but is rank 3", op, "[1,2,3];[4,2];[]");
  INFER_OK(op, "[1,2,3];?;[]", "[?,?,?]");
  INFER_OK(op, "?;[3,2];[]", "[?,?,?]");

  
  
  
  Tensor paddings_t(DT_INT64, TensorShape{3, 2});
  test::FillValues<int64_t>(&paddings_t, {1, 10, 2, 20, 3, 30});
  op.input_tensors[1] = &paddings_t;
  INFER_OK(op, "[100,200,300];[3,2];[]", "[111,222,333]");
  INFER_OK(op, "[100,?,300];[3,2];[]", "[111,?,333]");
  INFER_OK(op, "?;[3,2];[]", "[?,?,?]");
  INFER_OK(op, "?;?;[]", "[?,?,?]");
}

TEST(ArrayOpsTest, MirrorPadGrad_ShapeFn) {
  ShapeInferenceTestOp op("MirrorPadGrad");
  op.input_tensors.resize(2);

  
  INFER_OK(op, "?;?", "?");

  
  INFER_OK(op, "?;[?,4]", "?");

  
  INFER_ERROR("must be rank 3 but is rank 2", op, "[?,?];[3,2]");

  
  INFER_ERROR("Dimension 1 in both shapes must be equal, but are 3 and 2", op, "[?,?,?];[3,3]");

  
  
  INFER_OK(op, "[?,?,?];[3,2]", "[?,?,?]");

  
  
  
  Tensor paddings_t(DT_INT64, TensorShape{3, 2});
  test::FillValues<int64_t>(&paddings_t, {1, 10, 2, 20, 3, 30});
  op.input_tensors[1] = &paddings_t;

  INFER_OK(op, "[111,222,333];[3,2]", "[100,200,300]");
  INFER_OK(op, "[111,?,333];[3,2]", "[100,?,300]");
}

TEST(ArrayOpsTest, BroadcastArgs_ShapeFn) {
  ShapeInferenceTestOp op("BroadcastArgs");
  INFER_OK(op, "?;?", "[?]");
  INFER_OK(op, "[123];[1]", "[123]");
  INFER_OK(op, "[1];[123]", "[123]");
  INFER_OK(op, "[123];[121]", "[123]");

  
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[];?");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "?;[]");
}

TEST(ArrayOpsTest, BroadcastTo_ShapeFn) {
  ShapeInferenceTestOp op("BroadcastTo");
  op.input_tensors.resize(2);

  INFER_OK(op, "?;[?]", "?");
  INFER_OK(op, "[];[1]", "[?]");
  INFER_OK(op, "[1];[1]", "[?]");
  INFER_OK(op, "[1];[2]", "[?,?]");
  INFER_OK(op, "[2,2];[3]", "[?,d0_0,d0_1]");

  
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[?,?]");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[2];[]");
  INFER_ERROR("Shape must be at most rank 1 but is rank 2", op, "[2,2];[1]");

  Tensor shape_t(DT_INT64, TensorShape{3});
  test::FillValues<int64_t>(&shape_t, {2, 10, 3});
  op.input_tensors[1] = &shape_t;
  INFER_OK(op, "[1,?,1];[3]", "[2,10,3]");
  INFER_OK(op, "[1,1,1];[3]", "[2,10,3]");
  INFER_OK(op, "[10,1];[3]", "[2,d0_0,3]");
  INFER_ERROR("Dimensions must be equal, but are 3 and 2 for", op, "[3,1,1];[3]");
  INFER_ERROR("Dimensions must be equal, but are 2 and 10 for", op, "[2,2,1];[3]");
}

TEST(ArrayOpsTest, BroadcastGradientArgs_ShapeFn) {
  ShapeInferenceTestOp op("BroadcastGradientArgs");
  
  INFER_OK(op, "?;?", "[?];[?]");
  INFER_OK(op, "[123];[456]", "[?];[?]");

  
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[];?");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "?;[]");
}

TEST(ArrayOpsTest, ListDiff_ShapeFn) {
  ShapeInferenceTestOp op("BroadcastGradientArgs");
  
  INFER_OK(op, "?;?", "[?];[?]");
  INFER_OK(op, "[123];[456]", "[?];[?]");

  
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[];?");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "?;[]");
}

TEST(ArrayOpsTest, MatrixSetDiag_ShapeFn) {
  ShapeInferenceTestOp op("MatrixSetDiag");

  

  
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[1];?");
  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "?;[]");
  INFER_ERROR("Shape must be at least rank 1 but is rank 0", op, "[2,2];[]");
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "[2,2];[2,2]");

  
  INFER_ERROR("Dimensions must be equal, but are 2 and 3", op, "[2,3];[3]");

  
  INFER_OK(op, "?;?", "in0");
  INFER_OK(op, "[1,2,2];[1,2]", "in0");
  INFER_OK(op, "[1,2,3];?", "in0");
  INFER_OK(op, "[1,3,2];?", "in0");
  INFER_OK(op, "[1,?,2];[?,?]", "in0");
  INFER_OK(op, "[1,?,?];[?,2]", "in0");

  
  INFER_OK(op, "?;[1,2]", "[d1_0,?,?]");
  INFER_OK(op, "[?,?,3];[1,2]", "[d1_0,d0_1,d0_2]");
  INFER_OK(op, "[?,3,?];[1,2]", "[d1_0,d0_1,d0_2]");
  INFER_OK(op, "[?,3,2];[1,2]", "[d1_0,d0_1,d0_2]");
}

TEST(ArrayOpsTest, ExpandDims_ShapeFn) {
  ShapeInferenceTestOp op("ExpandDims");
  op.input_tensors.resize(2);

  
  INFER_OK(op, "?;?", "?");
  Tensor dim_t;
  op.input_tensors[1] = &dim_t;

  
  for (int32_t idx : {0, -4}) {
    dim_t = test::AsScalar<int32>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[1,d0_0,d0_1,d0_2]");
  }

  
  for (int32_t idx : {1, -3}) {
    dim_t = test::AsScalar<int32>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[d0_0,1,d0_1,d0_2]");

    
    dim_t = test::AsScalar<int64_t>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[d0_0,1,d0_1,d0_2]");
  }
  for (int32_t idx : {2, -2}) {
    dim_t = test::AsScalar<int32>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[d0_0,d0_1,1,d0_2]");

    
    dim_t = test::AsScalar<int64_t>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[d0_0,d0_1,1,d0_2]");
  }

  for (int32_t idx : {3, -1}) {
    
    dim_t = test::AsScalar<int32>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[d0_0,d0_1,d0_2,1]");

    
    dim_t = test::AsScalar<int64_t>(idx);
    INFER_OK(op, "?;?", "?");
    INFER_OK(op, "[5,?,7];?", "[d0_0,d0_1,d0_2,1]");
  }
  for (int32_t idx : {4, -5}) {
    
    dim_t = test::AsScalar<int32>(idx);
    INFER_ERROR("not in the interval [-4, 3]", op, "[5,?,7];?");
    dim_t = test::AsScalar<int64_t>(idx);
    INFER_ERROR("not in the interval [-4, 3]", op, "[5,?,7];?");
  }

  
  std::vector<int32> dims;
  dims.push_back(0);
  dim_t = test::AsTensor<int32>(dims);
  INFER_OK(op, "?;?", "?");
  INFER_OK(op, "[5,?,7];?", "[1,d0_0,d0_1,d0_2]");

  
  dims.push_back(1);
  dim_t = test::AsTensor<int32>(dims);
  INFER_ERROR("'dim' input must be a tensor with a single", op, "?;?");
  INFER_ERROR("'dim' input must be a tensor with a single", op, "[5,6,7];?");

  
  dim_t = test::AsScalar<int32>(0);
  INFER_OK(op, "[2];[]", "[1,d0_0]");
  dim_t = test::AsScalar<int32>(1);
  INFER_OK(op, "[2];[]", "[d0_0,1]");
  dim_t = test::AsScalar<int32>(-1);
  INFER_OK(op, "[2];[]", "[d0_0,1]");
}

TEST(ArrayOpsTest, ImmutableConst_ShapeFn) {
  ShapeInferenceTestOp op("ImmutableConst");

  TF_ASSERT_OK(NodeDefBuilder("test", "ImmutableConst")
                   .Attr("dtype", DT_FLOAT)
                   .Attr("shape", TensorShape({1, 2, 3}))
                   .Attr("memory_region_name", "test_region")
                   .Finalize(&op.node_def));
  INFER_OK(op, "", "[1,2,3]");

  TF_ASSERT_OK(NodeDefBuilder("test", "ImmutableConst")
                   .Attr("dtype", DT_FLOAT)
                   .Attr("shape", TensorShape({}))
                   .Attr("memory_region_name", "test_region")
                   .Finalize(&op.node_def));
  INFER_OK(op, "", "[]");

  TF_ASSERT_OK(NodeDefBuilder("test", "ImmutableConst")
                   .Attr("dtype", DT_FLOAT)
                   .Attr("shape", "invalid")
                   .Attr("memory_region_name", "test_region")
                   .Finalize(&op.node_def));
  INFER_ERROR("AttrValue had value with type 'string' when 'shape' expected", op, "");
}

TEST(ArrayOpsTest, Concat_ShapeFn) {
  ShapeInferenceTestOp op("Concat");
  auto set_n = [&op](int n) {
    std::vector<NodeDefBuilder::NodeOut> src_list;
    src_list.reserve(n);
    for (int i = 0; i < n; ++i) src_list.emplace_back("a", 0, DT_FLOAT);
    TF_ASSERT_OK(NodeDefBuilder("test", "Concat")
                     .Input({"concat_dim", 0, DT_INT32})
                     .Input(src_list)
                     .Attr("n", n)
                     .Finalize(&op.node_def));
  };

  
  set_n(2);
  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "[1];?;?");

  
  
  set_n(7);
  INFER_OK(op, "?;?;?;?;[1,2,3];?;[3,2,1];?", "[?,?,?]");
  set_n(4);
  INFER_OK(op, "?;?;?;[1,2,3,4];[4,3,2,1]", "[?,?,?,?]");
  INFER_OK(op, "?;?;?;?;?", "?");  
  INFER_ERROR("Can't concatenate scalars (use tf.stack instead)", op, "?;?;?;[];[]");
  INFER_ERROR("Shape must be rank 2 but is rank 3", op, "?;?;?;[1,2];[1,2,3]");

  
  
  Tensor concat_dim_t;
  op.input_tensors.push_back(&concat_dim_t);
  set_n(2);

  
  for (int concat_dim : {0, -3}) {
    concat_dim_t = test::AsScalar(concat_dim);
    INFER_OK(op, "[];[100,2,?];[10,?,3]", "[110,d1_1,d2_2]");
    INFER_ERROR("Dimension 1 in both shapes must be equal, but are 5 and 3", op, "[];[100,2,5];[10,?,3]");
    
    INFER_OK(op, "[];[100,2,?];[?,?,3]", "[?,d1_1,d2_2]");
    INFER_OK(op, "[];[?,2,?];[10,?,3]", "[?,d1_1,d2_2]");
  }

  
  for (bool use_negative : {false, true}) {
    concat_dim_t = test::AsScalar(use_negative ? -2 : 1);
    INFER_OK(op, "[];[1,100,?];[?,10,3]", "[d1_0,110,d2_2]");
    concat_dim_t = test::AsScalar(use_negative ? -1 : 1);
    INFER_OK(op, "[];[1,100];[?,10]", "[d1_0,110]");
    INFER_OK(op, "[];[?,100];[1,10]", "[d2_0,110]");

    
    concat_dim_t = test::AsScalar(use_negative ? -2 : 1);
    INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[];[100];[10,?]");
    INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[];[100,5];[10]");
  }

  
  concat_dim_t = test::AsScalar(-2);
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[];[100];[10,?]");
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[];[100,5];[10]");

  
  set_n(5);
  concat_dim_t = test::AsScalar(1);
  INFER_OK(op, "[];?;[1,100,?];[?,?,?];[?,10,3];?", "[d2_0,?,d4_2]");
}

TEST(ArrayOpsTest, ConcatV2_ShapeFn) {
  ShapeInferenceTestOp op("ConcatV2");
  auto set_n = [&op](int n) {
    std::vector<NodeDefBuilder::NodeOut> src_list;
    src_list.reserve(n);
    for (int i = 0; i < n; ++i) src_list.emplace_back("a", 0, DT_FLOAT);
    TF_ASSERT_OK(NodeDefBuilder("test", "ConcatV2")
                     .Input(src_list)
                     .Input({"axis", 0, DT_INT32})
                     .Attr("n", n)
                     .Finalize(&op.node_def));
  };

  
  set_n(2);
  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "?;?;[1]");

  
  
  set_n(7);
  INFER_OK(op, "?;?;?;?;[1,2,3];?;[3,2,1];?", "[?,?,?]");
  set_n(4);
  INFER_OK(op, "?;?;[1,2,3,4];[4,3,2,1];?", "[?,?,?,?]");
  INFER_OK(op, "?;?;?;?;?", "?");  
  INFER_ERROR("Can't concatenate scalars (use tf.stack instead)", op, "?;?;[];[];?");
  INFER_ERROR("Shape must be rank 2 but is rank 3", op, "?;?;[1,2];[1,2,3];?");

  
  
  Tensor concat_dim_t;
  op.input_tensors.resize(3);
  op.input_tensors[2] = &concat_dim_t;

  set_n(2);

  
  
  

  
  concat_dim_t = test::AsScalar(0);
  INFER_OK(op, "[100,2,?];[10,?,3];[]", "[110,d0_1,d1_2]");
  INFER_ERROR("Dimension 1 in both shapes must be equal, but are 5 and 3", op, "[100,2,5];[10,?,3];[]");
  
  INFER_OK(op, "[100,2,?];[?,?,3];[]", "[?,d0_1,d1_2]");
  INFER_OK(op, "[?,2,?];[10,?,3];[]", "[?,d0_1,d1_2]");

  
  concat_dim_t = test::AsScalar(1);
  INFER_OK(op, "[1,100,?];[?,10,3];[]", "[d0_0,110,d1_2]");
  INFER_OK(op, "[1,100];[?,10];[]", "[d0_0,110]");
  INFER_OK(op, "[?,100];[1,10];[]", "[d1_0,110]");
  
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[100];[10,?];[]");
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[100,5];[10];[]");
  
  concat_dim_t = test::AsScalar(-2);
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[100];[10,?];[]");
  INFER_ERROR("Shape must be at least rank 2 but is rank 1", op, "[100,5];[10];[]");

  
  op.input_tensors.resize(6);
  op.input_tensors[3] = nullptr;
  op.input_tensors[5] = &concat_dim_t;
  concat_dim_t = test::AsScalar(1);

  set_n(5);
  INFER_OK(op, "?;[1,100,?];[?,?,?];[?,10,3];?;[]", "[d1_0,?,d3_2]");
}

TEST(ArrayOpsTest, ConcatOffset_ShapeFn) {
  ShapeInferenceTestOp op("ConcatOffset");

  const int n = 4;
  std::vector<NodeDefBuilder::NodeOut> src_list;
  src_list.reserve(n);
  for (int i = 0; i < n; ++i) src_list.emplace_back("a", 0, DT_INT32);
  TF_ASSERT_OK(NodeDefBuilder("test", "ConcatOffset")
                   .Input({"concat_dim", 0, DT_INT32})
                   .Input(src_list)
                   .Attr("n", n)
                   .Finalize(&op.node_def));
  INFER_OK(op, "?;?;?;?;?", "in1;in2;in3;in4");
}

TEST(ArrayOpsTest, Reshape_ShapeFn) {
  ShapeInferenceTestOp op("Reshape");
  op.input_tensors.resize(2);

  
  INFER_OK(op, "?;?", "?");
  INFER_OK(op, "[?];?", "?");
  INFER_OK(op, "?;[?]", "?");
  INFER_OK(op, "[?];[?]", "?");
  INFER_OK(op, "[4];[?]", "?");

  
  Tensor new_shape = test::AsTensor<int32>({1, 2, 3});
  op.input_tensors[1] = &new_shape;
  INFER_OK(op, "?;[3]", "[1,2,3]");
  INFER_OK(op, "[?];[3]", "[1,2,3]");
  INFER_OK(op, "[6];[3]", "[1,2,3]");
  
  INFER_ERROR( "Cannot reshape a tensor with 12 elements to shape [1,2,3] (6 elements)", op, "[3,4];[3]");


  
  
  new_shape = test::AsTensor<int32>({-1});
  INFER_OK(op, "?;[1]", "[?]");
  INFER_OK(op, "[?];[1]", "[d0_0]");
  INFER_OK(op, "[2,2];[1]", "[4]");
  
  new_shape = test::AsTensor<int32>({2, -1});
  INFER_OK(op, "[3,4];[2]", "[2,6]");
  
  
  INFER_ERROR("Dimension size must be evenly divisible by 2 but is 7", op, "[7];[2]");
  
  new_shape = test::AsTensor<int32>({-1, -1, 2});
  INFER_OK(op, "[8];[3]", "[?,?,2]");
  INFER_OK(op, "?;[3]", "[?,?,2]");

  
  new_shape = test::AsTensor<int32>({-1, 2, 3});
  INFER_OK(op, "[?,2,3];[3]", "[d0_0,2,3]");

  
  new_shape = test::AsTensor<int32>({});
  INFER_OK(op, "[1];[0]", "[]");
  INFER_ERROR( "Cannot reshape a tensor with 2 elements to shape [] (1 elements)", op, "[1,2];[0]");


  
  new_shape = test::AsTensor<int32>({-1});
  INFER_OK(op, "[0];[1]", "[0]");
  new_shape = test::AsTensor<int32>({-1, 6});
  INFER_OK(op, "[0,2];[1]", "[0,6]");
  new_shape = test::AsTensor<int32>({0, -1});
  INFER_OK(op, "[0,2];[1]", "[0,?]");
}

TEST(ArrayOpsTest, QuantizedReshape_ShapeFn) {
  ShapeInferenceTestOp op("QuantizedReshape");
  op.input_tensors.resize(2);

  
  
  INFER_OK(op, "?;?;?;?", "?;[];[]");
  INFER_OK(op, "[?];?;?;?", "?;[];[]");
  INFER_OK(op, "[?];[?];?;?", "?;[];[]");
  INFER_OK(op, "[4];[?];?;?", "?;[];[]");
  Tensor new_shape = test::AsTensor<int32>({1, 2, 3});
  op.input_tensors[1] = &new_shape;
  INFER_OK(op, "[?];[3];?;?", "[1,2,3];[];[]");
  INFER_OK(op, "[6];[3];?;?", "[1,2,3];[];[]");
  INFER_ERROR( "Cannot reshape a tensor with 12 elements to shape [1,2,3] (6 elements)", op, "[3,4];[3];?;?");


  
  INFER_ERROR("must be rank 0", op, "?;?;[1];?");
  INFER_ERROR("must be rank 0", op, "?;?;?;[1]");
}

TEST(ArrayOpsTest, Placeholder_ShapeFn) {
  {
    
    ShapeInferenceTestOp op("Placeholder");
    TensorShape shape({1, 2});
    TF_ASSERT_OK(NodeDefBuilder("test", "Placeholder")
                     .Attr("shape", shape)
                     .Attr("dtype", DT_FLOAT)
                     .Finalize(&op.node_def));
    INFER_OK(op, "", "[1,2]");
  }

  {
    
    ShapeInferenceTestOp op("Placeholder");
    TensorShape shape({});
    TF_ASSERT_OK(NodeDefBuilder("test", "Placeholder")
                     .Attr("shape", shape)
                     .Attr("dtype", DT_FLOAT)
                     .Finalize(&op.node_def));
    INFER_OK(op, "", "[]");
  }

  {
    
    ShapeInferenceTestOp op("Placeholder");
    const int64_t dims[2] = {1, -1};
    PartialTensorShape shape;
    TF_ASSERT_OK(PartialTensorShape::MakePartialShape(dims, 2, &shape));
    TF_ASSERT_OK(NodeDefBuilder("test", "Placeholder")
                     .Attr("shape", shape)
                     .Attr("dtype", DT_FLOAT)
                     .Finalize(&op.node_def));
    INFER_OK(op, "", "[1,?]");
  }

  {
    
    ShapeInferenceTestOp op("Placeholder");
    PartialTensorShape shape;
    TF_ASSERT_OK(NodeDefBuilder("test", "Placeholder")
                     .Attr("shape", shape)
                     .Attr("dtype", DT_FLOAT)
                     .Finalize(&op.node_def));
    INFER_OK(op, "", "?");
  }
}

TEST(ArrayOpsTest, Transpose_ShapeFn) {
  ShapeInferenceTestOp op("Transpose");
  op.input_tensors.resize(2);

  
  INFER_OK(op, "?;?", "?");
  INFER_OK(op, "?;[?]", "?");
  INFER_OK(op, "?;[2]", "[?,?]");
  INFER_OK(op, "[?];?", "[?]");
  INFER_OK(op, "[?,?];[2]", "[?,?]");
  INFER_ERROR("Dimension must be 3 but is 2", op, "[1,2,3];[2]");
  Tensor perm = test::AsTensor<int32>({0});
  op.input_tensors[1] = &perm;
  INFER_OK(op, "[?];[?]", "[d0_0]");
  perm = test::AsTensor<int32>({1, 0});
  INFER_OK(op, "?;[2]", "[?,?]");
  INFER_OK(op, "[?,?];[2]", "[d0_1,d0_0]");
  INFER_OK(op, "[1,?];[2]", "[d0_1,d0_0]");
  INFER_OK(op, "?;[0]", "in0");

  
  perm = test::AsTensor<int32>({1, 2});
  INFER_ERROR("perm dim 2 is out of range of input rank 2", op, "[1,2];[2]");
  perm = test::AsTensor<int32>({0});
  INFER_ERROR("Dimension must be 2 but is 1", op, "[1,2];[1]");

  
  perm = test::AsTensor<int32>({1, 0, 3, 4, 2});
  INFER_OK(op, "[0,1,2,3,4];[5]", "[d0_1,d0_0,d0_3,d0_4,d0_2]");
  INFER_OK(op, "[0,?,2,3,4];[5]", "[d0_1,d0_0,d0_3,d0_4,d0_2]");
}

TEST(ArrayOpsTest, Bitcast_ShapeFn) {
  ShapeInferenceTestOp op("Bitcast");
  auto rebuild_node_def = [&op](DataType input_type, DataType output_type) {
    TF_ASSERT_OK(NodeDefBuilder("test", "Bitcast")
                     .Input("input", 0, input_type)
                     .Attr("type", output_type)
                     .Finalize(&op.node_def));
  };

  rebuild_node_def(DT_FLOAT, DT_INT32);
  
  INFER_OK(op, "?", "?");

  
  INFER_OK(op, "[1,2]", "in0");

  
  rebuild_node_def(DT_INT32, DT_INT64);
  INFER_OK(op, "[1,2]", "[d0_0]");  
  
  INFER_OK(op, "[1,?]", "[d0_0]");
  
  
  INFER_ERROR("does not match", op, "[1,4]");
  INFER_ERROR("does not match", op, "[1,3]");

  
  rebuild_node_def(DT_INT64, DT_INT32);
  INFER_OK(op, "[4,5]", "[d0_0,d0_1,2]");
  rebuild_node_def(DT_COMPLEX128, DT_INT32);
  INFER_OK(op, "[4,5]", "[d0_0,d0_1,4]");
  rebuild_node_def(DT_COMPLEX128, DT_HALF);
  INFER_OK(op, "[4,5]", "[d0_0,d0_1,8]");
  rebuild_node_def(DT_COMPLEX128, DT_INT8);
  INFER_OK(op, "[4,5]", "[d0_0,d0_1,16]");

  
  rebuild_node_def(DT_STRING, DT_INT32);
  INFER_ERROR("one of the type sizes is zero", op, "[1,2,3]");
  rebuild_node_def(DT_INT32, DT_STRING);
  INFER_ERROR("one of the type sizes is zero", op, "[1,2,3]");
}

TEST(ArrayOpsTest, Squeeze_ShapeFn) {
  ShapeInferenceTestOp op("Squeeze");

  auto rebuild_node_def = [&op](const std::vector<int32>& squeeze_dims) {
    TF_ASSERT_OK(NodeDefBuilder("test", "Squeeze")
                     .Input("input", 0, DT_FLOAT)
                     .Attr("squeeze_dims", squeeze_dims)
                     .Finalize(&op.node_def));
  };

  
  rebuild_node_def({});

  
  INFER_OK(op, "?", "?");

  INFER_OK(op, "[1,4,1,5,1]", "[d0_1,d0_3]");

  
  INFER_OK(op, "[1,?,1,?,1]", "?");

  
  rebuild_node_def({1});
  INFER_OK(op, "[4,1,5]", "[d0_0,d0_2]");
  
  INFER_OK(op, "[4,?,5]", "[d0_0,d0_2]");

  
  INFER_ERROR("Can not squeeze dim[1]", op, "[4,6,5]");

  
  rebuild_node_def({1, 2});
  INFER_OK(op, "[4,1,1,5]", "[d0_0,d0_3]");
  rebuild_node_def({1, -2});
  INFER_OK(op, "[4,1,1,5]", "[d0_0,d0_3]");

  
  rebuild_node_def({-2});
  INFER_OK(op, "[4,1,5]", "[d0_0,d0_2]");

  
  rebuild_node_def({-4});
  INFER_ERROR("not in [-3,3)", op, "[1,2,3]");
  rebuild_node_def({3});
  INFER_ERROR("not in [-3,3)", op, "[1,2,3]");
}

TEST(ArrayOpsTest, ReverseSequence_ShapeFn) {
  ShapeInferenceTestOp op("ReverseSequence");
  auto rebuild_node_def = [&op](const int32_t seq_dim, const int32_t batch_dim) {
    TF_ASSERT_OK(NodeDefBuilder("test", "ReverseSequence")
                     .Input("input", 0, DT_FLOAT)
                     .Input("seq_lengths", 1, DT_INT64)
                     .Attr("seq_dim", seq_dim)
                     .Attr("batch_dim", batch_dim)
                     .Finalize(&op.node_def));
  };

  rebuild_node_def(1, 2);
  
  INFER_OK(op, "?;[10]", "?");

  
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "?;[10,10]");

  
  rebuild_node_def(1, 4);
  INFER_ERROR("batch_dim must be < input rank", op, "[1,2,3];[3]");
  rebuild_node_def(4, 1);
  INFER_ERROR("seq_dim must be < input rank", op, "[1,2,3];[3]");

  rebuild_node_def(1, 2);
  INFER_OK(op, "[1,2,3];[3]", "[d0_0,d0_1,d0_2]");
  
  INFER_OK(op, "[1,2,?];[3]", "[d0_0,d0_1,d1_0]");
  INFER_OK(op, "[1,2,3];[?]", "[d0_0,d0_1,d0_2]");
}

TEST(ArrayOpsTest, Split_ShapeFn) {
  ShapeInferenceTestOp op("Split");
  op.input_tensors.resize(2);

  
  TF_ASSERT_OK(NodeDefBuilder("test", "Split")
                   .Input("split_dim", 0, DT_INT32)
                   .Input("value", 1, DT_FLOAT)
                   .Attr("num_split", 2)
                   .Finalize(&op.node_def));
  INFER_OK(op, "?;?", "?;?");
  
  INFER_OK(op, "?;[?,?]", "[?,?];[?,?]");

  
  INFER_OK(op, "?;[1,4]", "[?,?];[?,?]");

  
  Tensor split_dim = test::AsTensor<int32>({1, 2});
  op.input_tensors[0] = &split_dim;
  INFER_ERROR("Input must be scalar but has rank 1", op, "[?];[?,?]");
  split_dim = test::AsScalar<int32>(1);
  INFER_OK(op, "?;?", "?;?");
  INFER_OK(op, "?;[?,?]", "[d1_0,?];[d1_0,?]");
  INFER_OK(op, "?;[1,4]", "[d1_0,2];[d1_0,2]");
  INFER_OK(op, "?;[1,?]", "[d1_0,?];[d1_0,?]");
  INFER_ERROR("Dimension size must be evenly divisible by 2 but is 5", op, "?;[1,5]");

  
  split_dim = test::AsScalar<int32>(3);
  INFER_ERROR( "Dimension size, given by scalar input 3 must be in range [-3, 3)", op, "?;[1,4,8]");


  
  split_dim = test::AsScalar<int32>(-1);
  INFER_OK(op, "?;?", "?;?");
  INFER_OK(op, "?;[?,?]", "[d1_0,?];[d1_0,?]");
  INFER_OK(op, "?;[1,?]", "[d1_0,?];[d1_0,?]");
  INFER_OK(op, "?;[1,4]", "[d1_0,2];[d1_0,2]");
  INFER_OK(op, "?;[1,4,8]", "[d1_0,d1_1,4];[d1_0,d1_1,4]");
  split_dim = test::AsScalar<int32>(-2);
  INFER_OK(op, "?;[1,4,8]", "[d1_0,2,d1_2];[d1_0,2,d1_2]");
  split_dim = test::AsScalar<int32>(-4);
  INFER_ERROR( "Dimension size, given by scalar input -4 must be in range [-3, 3)", op, "?;[1,4,8]");

}

TEST(ArrayOpsTest, Tile_ShapeFn) {
  ShapeInferenceTestOp op("Tile");
  op.input_tensors.resize(2);

  
  TF_ASSERT_OK(NodeDefBuilder("test", "Tile")
                   .Input("input", 0, DT_FLOAT)
                   .Input("multiples", 1, DT_INT32)
                   .Finalize(&op.node_def));

  
  INFER_OK(op, "?;?", "?");

  
  INFER_OK(op, "[2,3,1,4];?", "[?,?,?,?]");

  
  INFER_ERROR("Shape must be rank 1 but is rank 2", op, "[2,3,1,4];[4,1]");

  
  INFER_OK(op, "?;[4]", "[?,?,?,?]");

  
  Tensor multiples = test::AsTensor<int32>({2, 3, 4, 5});
  op.input_tensors[1] = &multiples;
  INFER_OK(op, "[2,3,1,4];[4]", "[4,9,4,20]");
  
  multiples = test::AsTensor<int64_t>({2, 3, 4, 5});
  INFER_OK(op, "[2,3,1,4];[4]", "[4,9,4,20]");
}

TEST(ArrayOpsTest, EditDistance_ShapeFn) {
  ShapeInferenceTestOp op("EditDistance");
  op.input_tensors.resize(6);

  
  INFER_OK(op, "[?,?];[?];[4];[?,?];[?];[4]", "?");

  Tensor hypothesis_shape = test::AsTensor<int64_t>({2, 30, 4, 50});
  op.input_tensors[2] = &hypothesis_shape;
  Tensor truth_shape = test::AsTensor<int64_t>({20, 3, 40, 5});
  op.input_tensors[5] = &truth_shape;
  INFER_OK(op, "[?,?];[?];[4];[?,?];[?];[4]", "[20,30,40]");

  
  hypothesis_shape = test::AsTensor<int64_t>({2});
  op.input_tensors[2] = &hypothesis_shape;
  INFER_ERROR("Num elements of hypothesis_shape does not match truth_shape", op, "[?,?];[?];[1];[?,?];[?];[4]");
}

TEST(ArrayOpsTest, OneHot_ShapeFn) {
  ShapeInferenceTestOp op("OneHot");
  op.input_tensors.resize(4);
  auto set_axis = [&op](int axis) {
    TF_ASSERT_OK(NodeDefBuilder("test", "OneHot")
                     .Input("indices", 0, DT_FLOAT)
                     .Input("depth", 1, DT_INT32)
                     .Input("on_value", 2, DT_FLOAT)
                     .Input("off_value", 3, DT_FLOAT)
                     .Attr("axis", axis)
                     .Finalize(&op.node_def));
  };

  
  set_axis(-2);
  INFER_ERROR("axis must be >= -1", op, "?;?;?;?");
  set_axis(1);

  
  INFER_OK(op, "?;[];?;?", "?");

  
  Tensor depth = test::AsTensor<int32>({1, 2});
  op.input_tensors[1] = &depth;
  INFER_ERROR("Input must be scalar but has rank 1", op, "?;[2];?;?");

  
  depth = test::AsScalar<int32>(2);
  INFER_OK(op, "[1,3,4];[];?;?", "[d0_0,2,d0_1,d0_2]");
  set_axis(-1);
  INFER_OK(op, "[1,3,4];[];?;?", "[d0_0,d0_1,d0_2,2]");
}

TEST(ArrayOpsTest, ExtractImagePatchesShapeTest) {
  ShapeInferenceTestOp op("ExtractImagePatches");
  auto set_op = [&op](const std::vector<int32>& ksizes, const std::vector<int32>& strides, const std::vector<int32>& rates, const string& padding) {

    TF_ASSERT_OK(NodeDefBuilder("test", "ExtractImagePatches")
                     .Input("input", 0, DT_FLOAT)
                     .Attr("ksizes", ksizes)
                     .Attr("strides", strides)
                     .Attr("rates", rates)
                     .Attr("padding", padding)
                     .Finalize(&op.node_def));
  };

  
  
  
  
  
  
  
  set_op({1, 2, 2, 1}, {1, 1, 1, 1}, {1, 2, 2, 1}, "VALID");
  INFER_OK(op, "[1,7,7,2]", "[d0_0,5,5,8]");
  
  
  set_op({1, 1, 1, 1}, {1, 1, 1, 1}, {1, 2, 2, 1}, "VALID");
  INFER_OK(op, "[1,7,7,2]", "[d0_0,7,7,d0_3]");

  
  set_op({1, 2, 2, 1, 1}, {1, 1, 1, 1}, {1, 2, 2, 1}, "VALID");
  INFER_ERROR( "ExtractImagePatches requires the ksizes attribute to contain 4 values, " "but got: 5", op, "[1,7,7,2]");


}

TEST(ArrayOpsTest, QuantizeAndDequantizeV2_ShapeFn) {
  ShapeInferenceTestOp op("QuantizeAndDequantizeV2");
  op.input_tensors.resize(3);
  TF_ASSERT_OK(NodeDefBuilder("test", "QuantizeAndDequantizeV2")
                   .Input("input", 0, DT_FLOAT)
                   .Input("input_min", 1, DT_FLOAT)
                   .Input("input_max", 2, DT_FLOAT)
                   .Attr("signed_input", true)
                   .Attr("num_bits", 8)
                   .Attr("range_given", false)
                   .Attr("narrow_range", false)
                   .Attr("axis", -1)
                   .Finalize(&op.node_def));
  INFER_OK(op, "?;?;?", "in0");
  INFER_OK(op, "[];?;?", "in0");
  INFER_OK(op, "[1,2,?,4,5];?;?", "in0");

  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "[1,2,?,4,5];[1];[]");
  INFER_ERROR("Shapes must be equal rank, but are 1 and 0", op, "[1,2,?,4,5];[];[1]");
  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "[1,2,?,4,5];[1];[1]");
}

TEST(ArrayOpsTest, SpaceToBatch_ShapeFn) {
  ShapeInferenceTestOp op("SpaceToBatch");
  op.input_tensors.resize(2);
  TF_ASSERT_OK(NodeDefBuilder("test", "SpaceToBatch")
                   .Input("input", 0, DT_FLOAT)
                   .Input("paddings", 1, DT_INT32)
                   .Attr("block_size", 2)
                   .Finalize(&op.node_def));

  
  INFER_OK(op, "[1,10,10,3];[2,2]", "[4,?,?,d0_3]");

  
  INFER_OK(op, "[1,10,10,3];?", "[4,?,?,d0_3]");

  
  INFER_ERROR("rank", op, "[1,10,10,3];[4]");
  INFER_ERROR("3 and 2", op, "[1,10,10,3];[2,3]");

  Tensor paddings = test::AsTensor<int32>({4, 2, 2, 4}, {{2, 2}});
  op.input_tensors[1] = &paddings;
  INFER_OK(op, "[1,10,10,3];[2,2]", "[4,8,8,d0_3]");
  paddings = test::AsTensor<int64_t>({4, 2, 2, 4}, {{2, 2}});
  INFER_OK(op, "[1,10,10,3];[2,2]", "[4,8,8,d0_3]");

  
  paddings = test::AsTensor<int32>({1, 2, 3, 4}, {{2, 2}});
  op.input_tensors[1] = &paddings;
  INFER_ERROR("Dimension size must be evenly divisible by 2 but is 13", op, "[1,10,10,3];[2,2]");

  
  paddings = test::AsTensor<int32>({1, -2, 3, 4}, {{2, 2}});
  op.input_tensors[1] = &paddings;
  INFER_ERROR("cannot be negative", op, "[1,10,10,3];[2,2]");
}

TEST(ArrayOpsTest, SpaceToBatchND_ShapeFn) {
  ShapeInferenceTestOp op("SpaceToBatchND");
  op.input_tensors.resize(3);
  TF_ASSERT_OK(NodeDefBuilder("test", "SpaceToBatchND")
                   .Input("input", 0, DT_FLOAT)
                   .Input("block_shape", 1, DT_INT32)
                   .Input("paddings", 2, DT_INT32)
                   .Finalize(&op.node_def));

  
  INFER_OK(op, "?;[2];?", "?");

  
  INFER_OK(op, "[?,?,?,?];[2];?", "[?,?,?,d0_3]");

  
  INFER_OK(op, "[?,?,?,2];[2];?", "[?,?,?,d0_3]");

  {
    
    Tensor block_shape = test::AsTensor<int32>({2, 3});
    op.input_tensors[1] = &block_shape;
    INFER_OK(op, "[3,?,?,2];[2];?", "[18,?,?,d0_3]");

    
    {
      Tensor paddings = test::AsTensor<int32>({1, 1, 0, 1}, {{2, 2}});
      op.input_tensors[2] = &paddings;
      INFER_OK(op, "[3,?,2,2];[2];[2,2]", "[18,?,1,d0_3]");
      op.input_tensors[2] = nullptr;
    }

    
    {
      Tensor paddings = test::AsTensor<int32>({1, 1, 0, 0}, {{2, 2}});
      op.input_tensors[2] = &paddings;
      INFER_OK(op, "[3,2,3,2];[2];[2,2]", "[18,2,1,d0_3]");
      op.input_tensors[2] = nullptr;
    }

    op.input_tensors[1] = nullptr;
  }

  INFER_ERROR("block_shape must have rank 1", op, "?;[1,1];?");
  INFER_ERROR("block_shape must have known size", op, "?;[?];?");

  {
    Tensor block_shape = test::AsTensor<int32>({0, 2});
    op.input_tensors[1] = &block_shape;
    INFER_ERROR("block_shape must be positive", op, "[1,2,2];[2];[2,2]");
    op.input_tensors[1] = nullptr;
  }

  {
    Tensor block_shape = test::AsTensor<int32>({1, 1});
    op.input_tensors[1] = &block_shape;
    Tensor paddings = test::AsTensor<int32>({0, -1, 0, 0}, {{2, 2}});
    op.input_tensors[2] = &paddings;
    INFER_ERROR("paddings cannot be negative", op, "[1,2,2];[2];[2,2]");
    op.input_tensors[1] = nullptr;
    op.input_tensors[2] = nullptr;
  }

  {
    Tensor block_shape = test::AsTensor<int32>({3, 3});
    op.input_tensors[1] = &block_shape;
    Tensor paddings = test::AsTensor<int32>({0, 0, 0, 0}, {{2, 2}});
    op.input_tensors[2] = &paddings;
    INFER_ERROR("divisible", op, "[1,2,3,1];[2];[2,2]");
    op.input_tensors[1] = nullptr;
    op.input_tensors[2] = nullptr;
  }

  {
    Tensor block_shape = test::AsTensor<int32>({});
    op.input_tensors[1] = &block_shape;
    Tensor paddings = test::AsTensor<int32>({});
    op.input_tensors[2] = &paddings;
    INFER_OK(op, "?;[0];[0,2]", "?");
    op.input_tensors[1] = nullptr;
    op.input_tensors[2] = nullptr;
  }

  INFER_ERROR("rank", op, "[1,3,3,1];[2];[1]");
  INFER_ERROR("shape", op, "[1,3,3,1];[2];[1,2]");
}

TEST(ArrayOpsTest, BatchToSpace_ShapeFn) {
  ShapeInferenceTestOp op("BatchToSpace");
  op.input_tensors.resize(2);
  TF_ASSERT_OK(NodeDefBuilder("test", "BatchToSpace")
                   .Input("input", 0, DT_FLOAT)
                   .Input("crops", 1, DT_INT32)
                   .Attr("block_size", 2)
                   .Finalize(&op.node_def));

  
  INFER_OK(op, "[4,8,8,3];[2,2]", "[1,?,?,d0_3]");

  
  INFER_ERROR("Dimension size must be evenly divisible by", op, "[5,8,8,3];[2,2]");

  
  INFER_OK(op, "[4,8,8,3];?", "[1,?,?,d0_3]");

  
  INFER_ERROR("rank", op, "[4,8,8,3];[4]");
  INFER_ERROR("3 and 2", op, "[4,8,8,3];[2,3]");

  Tensor croppings = test::AsTensor<int64_t>({4, 2, 2, 4}, {{2, 2}});
  op.input_tensors[1] = &croppings;
  INFER_OK(op, "[4,8,8,3];[2,2]", "[1,10,10,d0_3]");

  
  croppings = test::AsTensor<int32>({100, 2, 3, 4}, {{2, 2}});
  op.input_tensors[1] = &croppings;
  INFER_ERROR("Negative dimension size caused by subtracting", op, "[4,8,8,3];[2,2]");
  croppings = test::AsTensor<int32>({1, 2, 3, 400}, {{2, 2}});
  op.input_tensors[1] = &croppings;
  INFER_ERROR("Negative dimension size caused by subtracting", op, "[4,8,8,3];[2,2]");

  
  croppings = test::AsTensor<int32>({1, -2, 3, 4}, {{2, 2}});
  op.input_tensors[1] = &croppings;
  INFER_ERROR("cannot be negative", op, "[4,8,8,3];[2,2]");
}

TEST(ArrayOpsTest, BatchToSpaceND_ShapeFn) {
  ShapeInferenceTestOp op("BatchToSpaceND");
  op.input_tensors.resize(3);
  TF_ASSERT_OK(NodeDefBuilder("test", "BatchToSpaceND")
                   .Input("input", 0, DT_FLOAT)
                   .Input("block_shape", 1, DT_INT32)
                   .Input("crops", 2, DT_INT32)
                   .Finalize(&op.node_def));

  
  INFER_OK(op, "?;[2];?", "?");

  
  INFER_OK(op, "[?,?,?,?];[2];?", "[?,?,?,d0_3]");

  {
    
    Tensor block_shape = test::AsTensor<int32>({2, 3});
    op.input_tensors[1] = &block_shape;
    INFER_OK(op, "[?,?,?,2];[2];?", "[?,?,?,d0_3]");

    INFER_OK(op, "[18,?,?,2];[2];?", "[3,?,?,d0_3]");

    
    {
      Tensor crops = test::AsTensor<int32>({1, 1, 0, 1}, {{2, 2}});
      op.input_tensors[2] = &crops;
      INFER_OK(op, "[18,?,2,2];[2];[2,2]", "[3,?,5,d0_3]");
      op.input_tensors[2] = nullptr;
    }

    
    {
      Tensor crops = test::AsTensor<int32>({1, 1, 0, 0}, {{2, 2}});
      op.input_tensors[2] = &crops;
      INFER_OK(op, "[18,2,1,2];[2];[2,2]", "[3,2,3,d0_3]");
      op.input_tensors[2] = nullptr;
    }

    op.input_tensors[1] = nullptr;
  }

  INFER_ERROR("block_shape must have rank 1", op, "?;[1,1];?");
  INFER_ERROR("block_shape must have known size", op, "?;[?];?");
  INFER_ERROR("rank", op, "[2,2];[2];[2,2]");
  INFER_ERROR("rank", op, "[2,2,3];[3];[3,2]");

  {
    Tensor block_shape = test::AsTensor<int32>({0, 2});
    op.input_tensors[1] = &block_shape;
    INFER_ERROR("block_shape must be positive", op, "[1,2,2];[2];[2,2]");
    op.input_tensors[1] = nullptr;
  }

  {
    Tensor block_shape = test::AsTensor<int32>({1, 1});
    op.input_tensors[1] = &block_shape;
    Tensor paddings = test::AsTensor<int32>({0, -1, 0, 0}, {{2, 2}});
    op.input_tensors[2] = &paddings;
    INFER_ERROR("crops cannot be negative", op, "[1,2,2];[2];[2,2]");
    op.input_tensors[1] = nullptr;
    op.input_tensors[2] = nullptr;
  }

  
  {
    Tensor block_shape = test::AsTensor<int32>({2, 2});
    op.input_tensors[1] = &block_shape;
    Tensor crops = test::AsTensor<int32>({3, 2, 0, 0}, {{2, 2}});
    op.input_tensors[2] = &crops;
    INFER_ERROR("Negative", op, "[4,2,3,1];[2];[2,2]");
    op.input_tensors[1] = nullptr;
    op.input_tensors[2] = nullptr;
  }

  
  {
    Tensor block_shape = test::AsTensor<int32>({2, 3});
    op.input_tensors[1] = &block_shape;
    INFER_ERROR("divisible", op, "[3,1,1,1];[2];[2,2]");
    op.input_tensors[1] = nullptr;
  }
}

TEST(ArrayOpsTest, SpaceToDepth_ShapeFn) {
  ShapeInferenceTestOp op("SpaceToDepth");
  TF_ASSERT_OK(NodeDefBuilder("test", "SpaceToDepth")
                   .Input("input", 0, DT_FLOAT)
                   .Attr("block_size", 2)
                   .Finalize(&op.node_def));

  INFER_OK(op, "[1,2,4,4]", "[d0_0,1,2,16]");

  
  INFER_ERROR("Dimension size must be evenly divisible by 2 but is 3", op, "[1,3,8,4]");
  INFER_ERROR("Dimension size must be evenly divisible by 2 but is 5", op, "[1,2,5,4]");

  
  INFER_OK(op, "[1,2,4,?]", "[d0_0,1,2,?]");
}

TEST(ArrayOpsTest, DepthToSpace_ShapeFn) {
  ShapeInferenceTestOp op("DepthToSpace");
  TF_ASSERT_OK(NodeDefBuilder("test", "DepthToSpace")
                   .Input("input", 0, DT_FLOAT)
                   .Attr("block_size", 2)
                   .Finalize(&op.node_def));

  INFER_OK(op, "[1,1,2,16]", "[d0_0,2,4,4]");

  
  INFER_ERROR("Dimension size must be evenly divisible by 4 but is 15", op, "[1,1,2,15]");

  
  INFER_OK(op, "[1,2,4,?]", "[d0_0,4,8,?]");

  
  TF_ASSERT_OK(NodeDefBuilder("test", "DepthToSpace")
                   .Input("input", 0, DT_FLOAT)
                   .Attr("block_size", 10)
                   .Finalize(&op.node_def));
  INFER_OK(op, "[1,1,2,200]", "[d0_0,10,20,2]");
}

TEST(ArrayOpsTest, Slice_ShapeFn) {
  ShapeInferenceTestOp op("Slice");
  TF_ASSERT_OK(NodeDefBuilder("test", "Slice")
                   .Input("input", 0, DT_FLOAT)
                   .Input("begin", 1, DT_INT64)
                   .Input("sizes", 2, DT_INT64)
                   .Finalize(&op.node_def));

  
  
  INFER_OK(op, "[2,3,4,5];[4];[4]", "[?,?,?,?]");

  
  INFER_OK(op, "[2,3,4,5];[?];[?]", "[?,?,?,?]");
  
  INFER_OK(op, "?;[?];[?]", "?");
  
  INFER_OK(op, "?;[4];[?]", "[?,?,?,?]");

  
  INFER_ERROR("must be rank 1", op, "[2,3,4,5];[2,3];[3]");
  INFER_ERROR("must be rank 1", op, "[2,3,4,5];[2];[3,4]");
  
  INFER_ERROR("must be rank 2", op, "[2,3,4,5];[2];[2]");

  
  op.input_tensors.resize(3);
  Tensor begin = test::AsTensor<int32>({0, 1, 2, 1});
  Tensor sizes = test::AsTensor<int32>({1, 2, 1, 3});
  op.input_tensors[1] = &begin;
  op.input_tensors[2] = &sizes;
  INFER_OK(op, "[2,3,4,5];[4];[4]", "[1,2,1,3]");

  
  sizes = test::AsTensor<int32>({-1, -1, 1, -1});
  INFER_OK(op, "[2,3,4,5];[4];[4]", "[d0_0,2,1,4]");

  begin = test::AsTensor<int32>({0, 1, 2, 6});
  sizes = test::AsTensor<int32>({-1, -1, -1, -1});
  INFER_ERROR("Negative dimension size", op, "[2,3,4,5];[4];[4]");

  begin = test::AsTensor<int32>({0, 1, 2, 5});
  sizes = test::AsTensor<int32>({-1, -1, -1, -2});
  INFER_ERROR("cannot be < -1", op, "[2,3,4,5];[4];[4]");
}

TEST(ArrayOpsTest, StridedSlice_ShapeFn) {
  ShapeInferenceTestOp op("StridedSlice");
  TF_ASSERT_OK(NodeDefBuilder("test", "StridedSlice")
                   .Input("input", 0, DT_FLOAT)
                   .Input("begin", 1, DT_INT32)
                   .Input("end", 2, DT_INT32)
                   .Input("strides", 3, DT_INT32)
                   .Attr("shrink_axis_mask", 1)
                   .Finalize(&op.node_def));
  op.input_tensors.resize(4);
  Tensor strides = test::AsTensor<int32>({1});
  op.input_tensors[3] = &strides;
  
  INFER_OK(op, "[2,3,4,5];[1];[1];[1]", "[3,4,5]");
  
  INFER_OK(op, "[2,0,3,4];[1];[1];[1]", "[0,3,4]");
}

TEST(ArrayOpsTest, StridedSliceGrad_ShapeFn) {
  ShapeInferenceTestOp op("StridedSliceGrad");
  op.input_tensors.resize(5);
  INFER_OK(op, "?;?;?;?;?", "?");
  INFER_OK(op, "[?];?;?;?;?", "?");
  INFER_OK(op, "[4];?;?;?;?", "[?,?,?,?]");

  Tensor in_t = test::AsTensor<int32>({1, 2, 3, 4});
  op.input_tensors[0] = &in_t;
  INFER_OK(op, "[4];?;?;?;?", "[1,2,3,4]");
}

TEST(ArrayOpsTest, UnchangedWithQuantizationScalars_ShapeFn) {
  for (const char* op_name : {"Dequantize", "FakeQuantWithMinMaxVars") {
    ShapeInferenceTestOp op(op_name);
    if (op_name[0] == 'D') {
      TF_ASSERT_OK(NodeDefBuilder("test", "Dequantize")
                       .Input("input", 0, DT_QINT8)
                       .Input("input_min", 1, DT_FLOAT)
                       .Input("input_max", 2, DT_FLOAT)
                       .Attr("T", DataTypeToEnum<qint8>::v())
                       .Attr("mode", "SCALED")
                       .Attr("axis", -1)
                       .Finalize(&op.node_def));
    }
    INFER_OK(op, "?;?;?", "in0");
    INFER_OK(op, "[1,?,3];[];[]", "in0");

    
    INFER_ERROR("be rank 0", op, "[1,?,3];[1];[]");
    INFER_ERROR("be rank 0", op, "[1,?,3];[];[1]");
  }
}

TEST(ArrayOpsTest, FakeQuantWithMinMaxVarsPerChannel) {
  ShapeInferenceTestOp op("FakeQuantWithMinMaxVarsPerChannel");

  INFER_OK(op, "?;?;?", "in0");
  INFER_OK(op, "[?];?;?", "in0");
  INFER_OK(op, "[1,?,3];[3];[3]", "in0");
  INFER_OK(op, "[3];[3];[3]", "in0");

  
  INFER_ERROR("be rank 1", op, "[1,?,3];[1];[]");
  INFER_ERROR("be rank 1", op, "[1,?,3];[];[1]");

  
  INFER_ERROR("must be equal", op, "[1,?,3];[2];[?]");
  INFER_ERROR("must be equal", op, "[1,?,3];[?];[2]");
  INFER_ERROR("must be equal", op, "[1,?,?];[1];[2]");
  INFER_ERROR("must be equal", op, "[5];[4];[?]");
}

TEST(ArrayOpsTest, FakeQuantWithMinMaxVarsPerChannelGradient) {
  ShapeInferenceTestOp op("FakeQuantWithMinMaxVarsPerChannelGradient");

  INFER_OK(op, "?;?;?;?", "in0;[?];[?]");
  INFER_OK(op, "[3];[3];[3];[3]", "in0;in3;in3");
  INFER_OK(op, "[1,3];[1,3];[3];[3]", "in0;in3;in3");
  INFER_OK(op, "[1,2,3,4];[1,2,3,4];[4];[4]", "in0;in3;in3");

  
  INFER_ERROR("be equal rank", op, "[1,?,3];[1,?,3];[3];[]");
  INFER_ERROR("be rank 1", op, "[1,?,3];[1,?,3];[];[3]");
  INFER_ERROR("be at least rank 1", op, "[];[];[1];[1]");
  INFER_ERROR("be at most rank 4", op, "[1,2,3,4,5];[1,2,3,4,5];[1];[1]");

  
  INFER_ERROR("must be equal", op, "[1,3];[1,3];[2];[3]");
  INFER_ERROR("must be equal", op, "[1,3];[1,3];[3];[2]");
}

TEST(ArrayOpsTest, QuantizedConcat_ShapeFn) {
  ShapeInferenceTestOp op("QuantizedConcat");
  auto set_n = [&op](int n) {
    std::vector<NodeDefBuilder::NodeOut> src_list;
    std::vector<NodeDefBuilder::NodeOut> limit_list;
    for (int i = 0; i < n; ++i) {
      src_list.emplace_back("a", 0, DT_QUINT8);
      limit_list.emplace_back("b", 0, DT_FLOAT);
    }
    TF_ASSERT_OK(NodeDefBuilder("test", "QuantizedConcat")
                     .Input({"concat_dim", 0, DT_INT32})
                     .Input(src_list)
                     .Input(limit_list)
                     .Input(limit_list)
                     .Attr("N", n)
                     .Finalize(&op.node_def));
  };

  
  set_n(1);
  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "[1];?;?;?");

  
  set_n(2);
  INFER_ERROR("must be rank 0", op, "[];?;?;?;?;?;[1]");
  INFER_ERROR("must be rank 0", op, "[];?;?;?;?;[1];?");
  INFER_ERROR("must be rank 0", op, "[];?;?;?;[1];?;?");
  INFER_ERROR("must be rank 0", op, "[];?;?;[1];?;?;?");

  
  set_n(2);
  INFER_ERROR("must be rank 2", op, "[];[1,2];[1,2,3];?;?;?;?");
  INFER_OK(op, "[];[1,2];[1,3];?;?;?;?", "[?,?];[];[]");

  
  
  Tensor concat_dim_t;
  op.input_tensors.push_back(&concat_dim_t);
  set_n(2);
  concat_dim_t = test::AsScalar(0);  
  INFER_OK(op, "[];[100,2,?];[10,?,3];?;?;?;?", "[110,d1_1,d2_2];[];[]");
  INFER_ERROR("Dimension 1 in both shapes must be equal, but are 5 and 3", op, "[];[100,2,5];[10,?,3];?;?;?;?");
  
}

TEST(StateOpsTest, _ParallelConcatStart_ShapeFn) {
  ShapeInferenceTestOp op("_ParallelConcatStart");
  TensorShape shape({1, 2, 3});
  TensorShapeProto shape_proto;
  shape.AsProto(&shape_proto);
  TF_ASSERT_OK(NodeDefBuilder("test", "_ParallelConcatStart")
                   .Attr("shape", shape_proto)
                   .Attr("dtype", DT_FLOAT)
                   .Finalize(&op.node_def));
  INFER_OK(op, "", "[1,2,3]");
}

}  
