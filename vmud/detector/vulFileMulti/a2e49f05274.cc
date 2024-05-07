













namespace tflite {
namespace {

TEST(ConvertVectorToTfLiteIntArray, TestWithVector) {
  std::vector<int> input = {1, 2};
  TfLiteIntArray* output = ConvertVectorToTfLiteIntArray(input);
  ASSERT_NE(output, nullptr);
  EXPECT_EQ(output->size, 2);
  EXPECT_EQ(output->data[0], 1);
  EXPECT_EQ(output->data[1], 2);
  TfLiteIntArrayFree(output);
}

TEST(ConvertVectorToTfLiteIntArray, TestWithEmptyVector) {
  std::vector<int> input;
  TfLiteIntArray* output = ConvertVectorToTfLiteIntArray(input);
  ASSERT_NE(output, nullptr);
  EXPECT_EQ(output->size, 0);
  TfLiteIntArrayFree(output);
}

TEST(UtilTest, IsFlexOp) {
  EXPECT_TRUE(IsFlexOp("Flex"));
  EXPECT_TRUE(IsFlexOp("FlexOp"));
  EXPECT_FALSE(IsFlexOp("flex"));
  EXPECT_FALSE(IsFlexOp("Fle"));
  EXPECT_FALSE(IsFlexOp("OpFlex"));
  EXPECT_FALSE(IsFlexOp(nullptr));
  EXPECT_FALSE(IsFlexOp(""));
}

TEST(EqualArrayAndTfLiteIntArray, TestWithTFLiteArrayEmpty) {
  int input[] = {1, 2, 3, 4};
  EXPECT_FALSE(EqualArrayAndTfLiteIntArray(nullptr, 4, input));
}

TEST(EqualArrayAndTfLiteIntArray, TestWithTFLiteArrayWrongSize) {
  int input[] = {1, 2, 3, 4};
  TfLiteIntArray* output = ConvertArrayToTfLiteIntArray(4, input);
  EXPECT_FALSE(EqualArrayAndTfLiteIntArray(output, 3, input));
  free(output);
}

TEST(EqualArrayAndTfLiteIntArray, TestMismatch) {
  int input[] = {1, 2, 3, 4};
  TfLiteIntArray* output = ConvertVectorToTfLiteIntArray({1, 2, 2, 4});
  EXPECT_FALSE(EqualArrayAndTfLiteIntArray(output, 4, input));
  free(output);
}

TEST(EqualArrayAndTfLiteIntArray, TestMatch) {
  int input[] = {1, 2, 3, 4};
  TfLiteIntArray* output = ConvertArrayToTfLiteIntArray(4, input);
  EXPECT_TRUE(EqualArrayAndTfLiteIntArray(output, 4, input));
  free(output);
}

TEST(CombineHashes, TestHashOutputsEquals) {
  size_t output1 = CombineHashes({1, 2, 3, 4});
  size_t output2 = CombineHashes({1, 2, 3, 4});
  EXPECT_EQ(output1, output2);
}

TEST(CombineHashes, TestHashOutputsDifferent) {
  size_t output1 = CombineHashes({1, 2, 3, 4});
  size_t output2 = CombineHashes({1, 2, 2, 4});
  EXPECT_NE(output1, output2);
}

TEST(GetOpNameByRegistration, ValidBuiltinCode) {
  TfLiteRegistration registration;
  registration.builtin_code = tflite::BuiltinOperator_ADD;
  const auto op_name = GetOpNameByRegistration(registration);
  EXPECT_EQ("ADD", op_name);
}

TEST(GetOpNameByRegistration, InvalidBuiltinCode) {
  TfLiteRegistration registration;
  registration.builtin_code = -1;
  const auto op_name = GetOpNameByRegistration(registration);
  EXPECT_EQ("", op_name);
}

TEST(GetOpNameByRegistration, CustomName) {
  TfLiteRegistration registration;
  registration.builtin_code = tflite::BuiltinOperator_CUSTOM;
  registration.custom_name = "TestOp";
  auto op_name = GetOpNameByRegistration(registration);
  EXPECT_EQ("CUSTOM TestOp", op_name);

  registration.builtin_code = tflite::BuiltinOperator_DELEGATE;
  registration.custom_name = "TestDelegate";
  op_name = GetOpNameByRegistration(registration);
  EXPECT_EQ("DELEGATE TestDelegate", op_name);
}

TEST(ValidationSubgraph, NameIsDetected) {
  EXPECT_FALSE(IsValidationSubgraph(nullptr));
  EXPECT_FALSE(IsValidationSubgraph(""));
  EXPECT_FALSE(IsValidationSubgraph("a name"));
  EXPECT_FALSE(IsValidationSubgraph("VALIDATIONfoo"));
  EXPECT_TRUE(IsValidationSubgraph("VALIDATION:"));
  EXPECT_TRUE(IsValidationSubgraph("VALIDATION:main"));
}

}  
}  
