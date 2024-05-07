










namespace tflite {
namespace {

using ::testing::ElementsAreArray;

class ScatterNdOpModel : public SingleOpModel {
 public:
  ScatterNdOpModel(const TensorData& indices, const TensorData& updates, const TensorData& shape) {
    indices_ = AddInput(indices);
    updates_ = AddInput(updates);
    shape_ = AddInput(shape);
    output_ = AddOutput(updates.type);
    SetBuiltinOp(BuiltinOperator_SCATTER_ND, BuiltinOptions_ScatterNdOptions, CreateScatterNdOptions(builder_).Union());
    BuildInterpreter( {GetShape(indices_), GetShape(updates_), GetShape(shape_)});
  }

  template <typename T> void SetIndices(std::initializer_list<T> data) {
    PopulateTensor<T>(indices_, data);
  }

  template <typename T> void SetUpdates(std::initializer_list<T> data) {
    PopulateTensor<T>(updates_, data);
  }

  template <typename T> void SetShape(std::initializer_list<T> data) {
    PopulateTensor<T>(shape_, data);
  }

  template <typename T> std::vector<T> GetOutput() {
    return ExtractVector<T>(output_);
  }

  std::vector<int> GetOutputShape() { return GetTensorShape(output_); }

 protected:
  int indices_;
  int updates_;
  int shape_;
  int output_;
};

TEST(ScatterNdOpTest, ScatterElementIntoVector) {
  ScatterNdOpModel m({TensorType_INT32, {4, 1}}, {TensorType_FLOAT32, {4}}, {TensorType_INT32, {1}});
  m.SetIndices<int32_t>({4, 3, 1, 7});
  m.SetUpdates<float>({9, 10, 11, 12});
  m.SetShape<int32_t>({8});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({8}));
  EXPECT_THAT(m.GetOutput<float>(), ElementsAreArray({0, 11, 0, 10, 9, 0, 0, 12}));
}

TEST(ScatterNdOpTest, ScatterMatrixIntoRank3Tensor) {
  ScatterNdOpModel m({TensorType_INT32, {2, 1}}, {TensorType_FLOAT32, {2, 4, 4}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({0, 2});
  m.SetUpdates<float>({5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8});
  m.SetShape<int32_t>({4, 4, 4});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({4, 4, 4}));
  EXPECT_THAT( m.GetOutput<float>(), ElementsAreArray({5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));




}

TEST(ScatterNdOpTest, ScatterVectorIntoMatrix) {
  ScatterNdOpModel m({TensorType_INT32, {4, 1}}, {TensorType_FLOAT32, {4, 4}}, {TensorType_INT32, {2}});
  m.SetIndices<int32_t>({ 9,  8,  0,  1});
  m.SetUpdates<float>({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});


  m.SetShape<int32_t>({10, 4});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({10, 4}));
  EXPECT_THAT(m.GetOutput<float>(), ElementsAreArray({ 9,  10, 11, 12, 13, 14, 15, 16, 0,  0,  0,  0, 0,  0,  0,  0, 0,  0,  0,  0, 0,  0,  0,  0, 0,  0,  0,  0, 0,  0,  0,  0, 5,  6,  7,  8, 1,  2,  3,  4}));









}

TEST(ScatterNdOpTest, ScatterMatricesIntoRank4Tensor) {
  ScatterNdOpModel m({TensorType_INT32, {2, 2, 2}}, {TensorType_FLOAT32, {2, 2, 2, 2}}, {TensorType_INT32, {4}});

  m.SetIndices<int32_t>( { 1, 1,  0, 1,  0, 0,  1, 0});
  m.SetUpdates<float>({ 1, 2, 3, 4,  5, 6, 7, 8, 9, 10, 11, 12,  13, 14, 15, 16});
  m.SetShape<int32_t>({2, 2, 2, 2});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 2, 2, 2}));
  EXPECT_THAT(m.GetOutput<float>(), ElementsAreArray({ 9, 10, 11, 12, 5, 6, 7, 8, 13, 14, 15, 16, 1, 2, 3, 4}));


}

TEST(ScatterNdOpTest, ScatterVectorIntoRank4Tensor) {
  ScatterNdOpModel m({TensorType_INT32, {2, 2, 3}}, {TensorType_FLOAT32, {2, 2, 5}}, {TensorType_INT32, {4}});
  m.SetIndices<int32_t>( { 2, 2, 2,  1, 0, 1,  0, 2, 0,  2, 2, 0});
  m.SetUpdates<float>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({3, 3, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({3, 3, 3, 5}));
  EXPECT_THAT(m.GetOutput<float>(), ElementsAreArray({
                   0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20, 0,  0,  0,  0,  0, 1,  2,  3,  4,  5, }));


























}

TEST(ScatterNdOpTest, ScatterVectorIntoRank3Tensor) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_FLOAT32, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 0, 0,  1, 0,  0, 2,  1, 2});
  m.SetUpdates<float>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<float>(), ElementsAreArray({ 1,  2,  3,  4,  5, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20}));





}

TEST(ScatterNdOpTest, OverlappedIndicesSummed) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_FLOAT32, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 1, 0,  0, 2,  0, 2,  1, 0});
  m.SetUpdates<float>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<float>(), ElementsAreArray({ 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 17, 19, 21, 23, 25, 17, 19, 21, 23, 25, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0}));





}

TEST(ScatterNdOpTest, Int32IndicesUint8Updates) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_UINT8, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 0, 0,  1, 0,  0, 2,  1, 2});
  m.SetUpdates<uint8_t>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<uint8_t>(), ElementsAreArray({ 1,  2,  3,  4,  5, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20}));





}

TEST(ScatterNdOpTest, Int32IndicesInt8Updates) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_INT8, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 0, 0,  1, 0,  0, 2,  1, 2});
  m.SetUpdates<int8_t>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<int8_t>(), ElementsAreArray({ 1,  2,  3,  4,  5, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20}));





}

TEST(ScatterNdOpTest, Int32IndicesInt32Updates) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_INT32, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 0, 0,  1, 0,  0, 2,  1, 2});
  m.SetUpdates<int32_t>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<int32_t>(), ElementsAreArray({ 1,  2,  3,  4,  5, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20}));





}

TEST(ScatterNdOpTest, Int32IndicesInt64Updates) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_INT64, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 0, 0,  1, 0,  0, 2,  1, 2});
  m.SetUpdates<int64_t>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<int64_t>(), ElementsAreArray({ 1,  2,  3,  4,  5, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20}));





}

TEST(ScatterNdOpTest, Int32IndicesBoolUpdates) {
  ScatterNdOpModel m({TensorType_INT32, {4, 1}}, {TensorType_BOOL, {4}}, {TensorType_INT32, {1}});
  m.SetIndices<int32_t>({4, 3, 1, 7});
  m.SetUpdates<bool>({true, false, true, false});
  m.SetShape<int32_t>({8});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({8}));
  EXPECT_THAT( m.GetOutput<bool>(), ElementsAreArray({false, true, false, false, true, false, false, false}));

}

TEST(ScatterNdOpTest, DynamicShape) {
  ScatterNdOpModel m({TensorType_INT32, {4, 2}}, {TensorType_INT64, {4, 5}}, {TensorType_INT32, {3}});
  m.SetIndices<int32_t>({ 0, 0,  1, 0,  0, 2,  1, 2});
  m.SetUpdates<int64_t>( { 1,  2,  3,  4,  5,   6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16, 17, 18, 19, 20});

  m.SetShape<int32_t>({2, 3, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({2, 3, 5}));
  EXPECT_THAT(m.GetOutput<int64_t>(), ElementsAreArray({ 1,  2,  3,  4,  5, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20}));






  m.SetIndices<int32_t>({ 2, 3,  1, 0,  2, 0,  1, 2});
  m.SetShape<int32_t>({3, 4, 5});
  ASSERT_EQ(m.Invoke(), kTfLiteOk);

  EXPECT_THAT(m.GetOutputShape(), ElementsAreArray({3, 4, 5}));
  EXPECT_THAT(m.GetOutput<int64_t>(), ElementsAreArray({ 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 6,  7,  8,  9,  10, 0,  0,  0,  0,  0, 16, 17, 18, 19, 20, 0,  0,  0,  0,  0, 11, 12, 13, 14, 15, 0,  0,  0,  0,  0, 0,  0,  0,  0,  0, 1,  2,  3,  4,  5}));











}

}  
}  
