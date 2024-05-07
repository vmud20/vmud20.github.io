














namespace tensorflow {
namespace text {

using tensorflow::FakeInput;
using tensorflow::NodeDefBuilder;
using tensorflow::Status;
using tensorflow::TensorShape;

class NgramKernelTest : public tensorflow::OpsTestBase {
 public:
  void MakeOp(string separator, std::vector<int> ngram_width, string left_pad, string right_pad, int pad_width, bool preserve) {
    TF_ASSERT_OK(NodeDefBuilder("tested_op", "StringNGrams")
                     .Attr("separator", separator)
                     .Attr("ngram_widths", ngram_width)
                     .Attr("left_pad", left_pad)
                     .Attr("right_pad", right_pad)
                     .Attr("pad_width", pad_width)
                     .Attr("preserve_short_sequences", preserve)
                     .Input(FakeInput())
                     .Input(FakeInput())
                     .Finalize(node_def()));
    TF_ASSERT_OK(InitOp());
  }

  void assert_string_equal(const std::vector<tstring> &expected, const Tensor &value) {
    Tensor expected_tensor(allocator(), DT_STRING, TensorShape({static_cast<int64>(expected.size())}));
    test::FillValues<tstring>(&expected_tensor, expected);
    test::ExpectTensorEqual<tstring>(expected_tensor, value);
  }
  void assert_int64_equal(const std::vector<int64> &expected, const Tensor &value) {
    Tensor expected_tensor(allocator(), DT_INT64, TensorShape({static_cast<int64>(expected.size())}));
    test::FillValues<int64>(&expected_tensor, expected);
    test::ExpectTensorEqual<int64>(expected_tensor, value);
  }
};

TEST_F(NgramKernelTest, TestPaddedTrigrams) {
  MakeOp("|", {3}, "LP", "RP", -1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(                              {"LP|LP|a", "LP|a|b", "a|b|c", "b|c|d", "c|d|RP", "d|RP|RP", "LP|LP|e", "LP|e|f", "e|f|RP", "f|RP|RP");

  std::vector<int64> expected_splits({0, 6, 10});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestPaddedBigramsAndTrigrams) {
  MakeOp("|", {2, 3}, "LP", "RP", -1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values( {"LP|a", "a|b", "b|c", "c|d", "d|RP", "LP|LP|a", "LP|a|b", "a|b|c", "b|c|d", "c|d|RP", "d|RP|RP", "LP|e", "e|f", "f|RP", "LP|LP|e", "LP|e|f", "e|f|RP", "f|RP|RP");


  std::vector<int64> expected_splits({0, 11, 18});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestPaddedBigrams) {
  MakeOp("|", {2}, "LP", "RP", -1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(       {"LP|a", "a|b", "b|c", "c|d", "d|RP", "LP|e", "e|f", "f|RP");

  std::vector<int64> expected_splits({0, 5, 8});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestPaddingIsAtMostNGramSizeMinus1) {
  MakeOp("|", {2}, "LP", "RP", 4, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(       {"LP|a", "a|b", "b|c", "c|d", "d|RP", "LP|e", "e|f", "f|RP");

  std::vector<int64> expected_splits({0, 5, 8});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestPaddedUnigramAndBigrams) {
  MakeOp("|", {1, 2}, "LP", "RP", -1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(                           {"a", "b", "c", "d", "LP|a", "a|b", "b|c", "c|d", "d|RP", "e", "f", "LP|e", "e|f", "f|RP");

  std::vector<int64> expected_splits({0, 9, 14});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestOverlappingPaddedNGrams) {
  
  
  MakeOp("|", {3}, "LP", "RP", -1, false);
  
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 1, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(                     {"LP|LP|a", "LP|a|RP", "a|RP|RP", "LP|LP|b", "LP|b|c", "b|c|d", "c|d|RP", "d|RP|RP", "LP|LP|e", "LP|e|f", "e|f|RP", "f|RP|RP");


  std::vector<int64> expected_splits({0, 3, 8, 12});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestOverlappingPaddedMultiCharNGrams) {
  MakeOp("|", {3}, "LP", "RP", -1, false);
  
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"aa", "bb", "cc", "dd", "ee", "ff");
  AddInputFromArray<int64>(TensorShape({4}), {0, 1, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(                              {"LP|LP|aa", "LP|aa|RP", "aa|RP|RP", "LP|LP|bb", "LP|bb|cc", "bb|cc|dd", "cc|dd|RP", "dd|RP|RP", "LP|LP|ee", "LP|ee|ff", "ee|ff|RP", "ff|RP|RP");


  std::vector<int64> expected_splits({0, 3, 8, 12});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestMultiOverlappingPaddedNGrams) {
  
  
  MakeOp("|", {5}, "LP", "RP", -1, false);
  
  
  AddInputFromArray<tstring>(TensorShape({1}), {"a");
  AddInputFromArray<int64>(TensorShape({2}), {0, 1});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"LP|LP|LP|LP|a", "LP|LP|LP|a|RP", "LP|LP|a|RP|RP", "LP|a|RP|RP|RP", "a|RP|RP|RP|RP");

  std::vector<int64> expected_splits({0, 5});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedTrigrams) {
  MakeOp("|", {3}, "", "", 0, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a|b|c", "b|c|d");
  std::vector<int64> expected_splits({0, 2, 2});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedTrigramsWithEmptySequence) {
  MakeOp("|", {3}, "", "", 0, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 4, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a|b|c", "b|c|d");
  std::vector<int64> expected_splits({0, 2, 2, 2});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedTrigramsWithPreserveShort) {
  MakeOp("|", {3}, "", "", 0, true);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a|b|c", "b|c|d", "e|f");
  std::vector<int64> expected_splits({0, 2, 3});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedTrigramsWithPreserveShortAndEmptySequence) {
  MakeOp("|", {3}, "", "", 0, true);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 4, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a|b|c", "b|c|d", "e|f");
  std::vector<int64> expected_splits({0, 2, 2, 3});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedTrigramsAndQuadgramsWithPreserveShort) {
  MakeOp("|", {4, 3}, "", "", 0, true);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a|b|c|d", "a|b|c", "b|c|d", "e|f");
  std::vector<int64> expected_splits({0, 3, 4});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedBigramsAndTrigrams) {
  MakeOp("|", {2, 3}, "", "", 0, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values( {"a|b", "b|c", "c|d", "a|b|c", "b|c|d", "e|f");
  std::vector<int64> expected_splits({0, 5, 6});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedBigramsAndTrigramsWithPreserveShort) {
  MakeOp("|", {2, 3}, "", "", 0, true);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  
  
  std::vector<tstring> expected_values( {"a|b", "b|c", "c|d", "a|b|c", "b|c|d", "e|f");
  std::vector<int64> expected_splits({0, 5, 6});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedTrigramsAndBigramsWithPreserveShort) {
  MakeOp("|", {3, 2}, "", "", 0, true);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  
  
  std::vector<tstring> expected_values( {"a|b|c", "b|c|d", "a|b", "b|c", "c|d", "e|f");
  std::vector<int64> expected_splits({0, 5, 6});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestUnpaddedBigrams) {
  MakeOp("|", {2}, "", "", 0, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a|b", "b|c", "c|d", "e|f");
  std::vector<int64> expected_splits({0, 3, 4});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestOverlappingUnpaddedNGrams) {
  MakeOp("|", {3}, "", "", 0, false);
  
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 1, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"b|c|d");
  std::vector<int64> expected_splits({0, 0, 1, 1});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestOverlappingUnpaddedNGramsNoOutput) {
  MakeOp("|", {5}, "", "", 0, false);
  
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 1, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({});
  std::vector<int64> expected_splits({0, 0, 0, 0});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestSinglyPaddedTrigrams) {
  MakeOp("|", {3}, "LP", "RP", 1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"LP|a|b", "a|b|c", "b|c|d", "c|d|RP", "LP|e|f", "e|f|RP");

  std::vector<int64> expected_splits({0, 4, 6});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestSinglyPaddedBigrams) {
  MakeOp("|", {2}, "LP", "RP", 1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"LP|a", "a|b", "b|c", "c|d", "d|RP",   "LP|e", "e|f", "f|RP");
  std::vector<int64> expected_splits({0, 5, 8});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestSinglyPaddedBigramsAnd5grams) {
  MakeOp("|", {2, 5}, "LP", "RP", 1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(                                   {"LP|a", "a|b", "b|c", "c|d", "d|RP", "LP|a|b|c|d", "a|b|c|d|RP", "LP|e", "e|f", "f|RP");

  std::vector<int64> expected_splits({0, 7, 10});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestSinglyPadded5gramsWithPreserveShort) {
  MakeOp("|", {5}, "LP", "RP", 1, true);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values(   {"LP|a|b|c|d", "a|b|c|d|RP", "LP|e|f|RP");

  std::vector<int64> expected_splits({0, 2, 3});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestOverlappingSinglyPaddedNGrams) {
  MakeOp("|", {3}, "LP", "RP", 1, false);
  
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 1, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values( {"LP|a|RP", "LP|b|c", "b|c|d", "c|d|RP", "LP|e|f", "e|f|RP");


  std::vector<int64> expected_splits({0, 1, 4, 6});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestOverlappingSinglyPaddedNGramsNoOutput) {
  MakeOp("|", {5}, "LP", "RP", 1, false);
  
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({4}), {0, 1, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"LP|b|c|d|RP");
  std::vector<int64> expected_splits({0, 0, 1, 1});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestSinglyPaddedUnigrams) {
  MakeOp("|", {1}, "LP", "RP", 1, false);
  
  
  
  AddInputFromArray<tstring>(TensorShape({6}), {"a", "b", "c", "d", "e", "f");
  AddInputFromArray<int64>(TensorShape({3}), {0, 4, 6});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({"a", "b", "c", "d", "e", "f");
  std::vector<int64> expected_splits({0, 4, 6});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, TestEmptyInput) {
  MakeOp("|", {1}, "LP", "RP", 3, false);
  AddInputFromArray<tstring>(TensorShape({0}), {});
  AddInputFromArray<int64>(TensorShape({0}), {});
  TF_ASSERT_OK(RunOpKernel());

  std::vector<tstring> expected_values({});
  std::vector<int64> expected_splits({});

  assert_string_equal(expected_values, *GetOutput(0));
  assert_int64_equal(expected_splits, *GetOutput(1));
}

TEST_F(NgramKernelTest, ShapeFn) {
  ShapeInferenceTestOp op("StringNGrams");
  INFER_OK(op, "?;?", "[?];[?]");
  INFER_OK(op, "[1];?", "[?];[?]");
  INFER_OK(op, "[1];[2]", "[?];in1");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "[];?");
  INFER_ERROR("Shape must be rank 1 but is rank 0", op, "?;[]");
}

}  
}  
