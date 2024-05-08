


















namespace tensorflow {

namespace checkpoint {

class TensorSliceWriteTestHelper {
 public:
  static void CheckEntries(const string& fname);
  static void GetData(TensorSliceReader::Table* table, const string& name, const TensorSlice& slice, SavedSlice* ss);
};

namespace {


void ExpectIdenticalFloatArrays(const float* expected, int size, const float* actual) {
  
  
  
  for (int i = 0; i < size; ++i) {
    EXPECT_NEAR(expected[i], actual[i], 1e-6);
  }
}

template <typename T, typename U> void ExpectIdenticalIntArrays(const T* expected, int size, const U* actual) {
  for (int i = 0; i < size; ++i) {
    EXPECT_EQ(expected[i], static_cast<T>(actual[i]));
  }
}


template <typename T, unsigned SIZE> inline size_t ArraySize(const T (&v)[SIZE]) {
  return SIZE;
}




TEST(TensorSliceWriteTest, SimpleWrite) {
  const string filename = io::JoinPath(testing::TmpDir(), "checkpoint");

  TensorSliceWriter writer(filename, CreateTableTensorSliceBuilder);

  
  {
    TensorShape shape({5, 10});
    TensorSlice slice = TensorSlice::ParseOrDie("-:0,1");
    const int32 data[] = {0, 1, 2, 3, 4};
    TF_CHECK_OK(writer.Add("test", shape, slice, data));
  }

  
  {
    TensorShape shape({5, 10});
    TensorSlice slice = TensorSlice::ParseOrDie("-:3,1");
    const int32 data[] = {10, 11, 12, 13, 14};
    TF_CHECK_OK(writer.Add("test", shape, slice, data));
  }

  
  
  {
    TensorShape shape({3, 2});
    TensorSlice slice = TensorSlice::ParseOrDie("-:-");
    const float data[] = {1.2, 1.3, 1.4, 2.1, 2.2, 2.3};
    TF_CHECK_OK(writer.Add("AA", shape, slice, data));
  }

  
  {
    TensorShape shape({5, 10});
    TensorSlice slice = TensorSlice::ParseOrDie("-:3,1");
    const int64_t data[] = {10, 11, 12, 13, 14};
    TF_CHECK_OK(writer.Add("int64", shape, slice, data));
  }

  
  {
    TensorShape shape({5, 10});
    TensorSlice slice = TensorSlice::ParseOrDie("-:3,1");
    const int16 data[] = {10, 11, 12, 13, 14};
    TF_CHECK_OK(writer.Add("int16", shape, slice, data));
  }

  TF_CHECK_OK(writer.Finish());

  
  TensorSliceWriteTestHelper::CheckEntries(filename);
}

}  

void TensorSliceWriteTestHelper::GetData(TensorSliceReader::Table* table, const string& name, const TensorSlice& slice, SavedSlice* ss) {


  string key = EncodeTensorNameSlice(name, slice);
  string value;
  EXPECT_TRUE(table->Get(key, &value));
  SavedTensorSlices sts;
  EXPECT_TRUE(ParseProtoUnlimited(&sts, value));
  EXPECT_FALSE(sts.has_meta());
  *ss = sts.data();
  EXPECT_EQ(name, ss->name());
  TensorSlice slice2(ss->slice());
  EXPECT_EQ(slice.DebugString(), slice2.DebugString());
}

void TensorSliceWriteTestHelper::CheckEntries(const string& fname) {
  TensorSliceReader::Table* tptr;
  TF_CHECK_OK(OpenTableTensorSliceReader(fname, &tptr));
  std::unique_ptr<TensorSliceReader::Table> table(tptr);
  CHECK_NOTNULL(table.get());

  
  string value;
  ASSERT_TRUE(table->Get(kSavedTensorSlicesKey, &value));
  {
    SavedTensorSlices sts;
    EXPECT_TRUE(ParseProtoUnlimited(&sts, value));
    
    EXPECT_TRUE(sts.has_meta());
    EXPECT_EQ(4, sts.meta().tensor_size());
    
    EXPECT_LT(0, TF_CHECKPOINT_VERSION);
    EXPECT_EQ(TF_CHECKPOINT_VERSION, sts.meta().versions().producer());
    EXPECT_EQ(TF_CHECKPOINT_VERSION_MIN_CONSUMER, sts.meta().versions().min_consumer());
    
    EXPECT_FALSE(sts.has_data());
    
    
    {
      
      const SavedSliceMeta& ssm = sts.meta().tensor(0);
      EXPECT_EQ("test", ssm.name());
      TensorShapeProto expected_shape_proto;
      protobuf::TextFormat::ParseFromString( "dim { size: 5 } " "dim { size: 10 }", &expected_shape_proto);


      EXPECT_EQ(ssm.shape().ShortDebugString(), expected_shape_proto.ShortDebugString());
      EXPECT_EQ(DT_INT32, ssm.type());
      EXPECT_EQ(2, ssm.slice_size());
      TensorSlice s0(ssm.slice(0));
      TensorSlice s1(ssm.slice(1));
      EXPECT_EQ("-:0,1", s0.DebugString());
      EXPECT_EQ("-:3,1", s1.DebugString());
    }
    {
      
      const SavedSliceMeta& ssm = sts.meta().tensor(1);
      EXPECT_EQ("AA", ssm.name());
      TensorShapeProto expected_shape_proto;
      protobuf::TextFormat::ParseFromString( "dim { size: 3 } " "dim { size: 2 }", &expected_shape_proto);


      EXPECT_EQ(ssm.shape().ShortDebugString(), expected_shape_proto.ShortDebugString());
      EXPECT_EQ(DT_FLOAT, ssm.type());
      EXPECT_EQ(1, ssm.slice_size());
      TensorSlice s0(ssm.slice(0));
      EXPECT_EQ("-:-", s0.DebugString());
    }
    {
      
      const SavedSliceMeta& ssm = sts.meta().tensor(2);
      EXPECT_EQ("int64", ssm.name());
      TensorShapeProto expected_shape_proto;
      protobuf::TextFormat::ParseFromString( "dim { size: 5 } " "dim { size: 10 }", &expected_shape_proto);


      EXPECT_EQ(ssm.shape().ShortDebugString(), expected_shape_proto.ShortDebugString());
      EXPECT_EQ(DT_INT64, ssm.type());
      EXPECT_EQ(1, ssm.slice_size());
      TensorSlice s0(ssm.slice(0));
      EXPECT_EQ("-:3,1", s0.DebugString());
    }
    {
      
      const SavedSliceMeta& ssm = sts.meta().tensor(3);
      EXPECT_EQ("int16", ssm.name());
      TensorShapeProto expected_shape_proto;
      protobuf::TextFormat::ParseFromString( "dim { size: 5 } " "dim { size: 10 }", &expected_shape_proto);


      EXPECT_EQ(ssm.shape().ShortDebugString(), expected_shape_proto.ShortDebugString());
      EXPECT_EQ(DT_INT16, ssm.type());
      EXPECT_EQ(1, ssm.slice_size());
      TensorSlice s0(ssm.slice(0));
      EXPECT_EQ("-:3,1", s0.DebugString());
    }
  }

  
  {
    
    SavedSlice ss;
    GetData(table.get(), "AA", TensorSlice(2), &ss);
    const float data[] = {1.2, 1.3, 1.4, 2.1, 2.2, 2.3};
    EXPECT_EQ(ArraySize(data), ss.data().float_val_size());
    ExpectIdenticalFloatArrays(data, ArraySize(data), ss.data().float_val().data());
  }

  {
    
    SavedSlice ss;
    GetData(table.get(), "test", TensorSlice({{0, -1}, {0, 1}}), &ss);
    const int32 data[] = {0, 1, 2, 3, 4};
    EXPECT_EQ(ArraySize(data), ss.data().int_val_size());
    ExpectIdenticalIntArrays(data, ArraySize(data), ss.data().int_val().data());
  }

  {
    
    SavedSlice ss;
    GetData(table.get(), "test", TensorSlice({{0, -1}, {3, 1}}), &ss);
    const int32 data[] = {10, 11, 12, 13, 14};
    EXPECT_EQ(ArraySize(data), ss.data().int_val_size());
    ExpectIdenticalIntArrays(data, ArraySize(data), ss.data().int_val().data());
  }

  {
    
    SavedSlice ss;
    GetData(table.get(), "int64", TensorSlice({{0, -1}, {3, 1}}), &ss);
    const int64_t data[] = {10, 11, 12, 13, 14};
    EXPECT_EQ(ArraySize(data), ss.data().int64_val_size());
    ExpectIdenticalIntArrays(data, ArraySize(data), ss.data().int64_val().data());
  }

  {
    
    SavedSlice ss;
    GetData(table.get(), "int16", TensorSlice({{0, -1}, {3, 1}}), &ss);
    const int16 data[] = {10, 11, 12, 13, 14};
    EXPECT_EQ(ArraySize(data), ss.data().int_val_size());
    ExpectIdenticalIntArrays(data, ArraySize(data), ss.data().int_val().data());
  }
}

template <typename DT> size_t BytesPerElementHelper(DT value) {
  SavedSlice ss;
  std::array<DT, 1> lo_data;
  std::fill(lo_data.begin(), lo_data.end(), value);
  TF_EXPECT_OK( TensorSliceWriter::SaveData(lo_data.data(), lo_data.size(), &ss));
  size_t lo_byte_size = ss.ByteSizeLong();

  std::array<DT, 1001> hi_data;
  std::fill(hi_data.begin(), hi_data.end(), value);
  TF_EXPECT_OK( TensorSliceWriter::SaveData(hi_data.data(), hi_data.size(), &ss));
  size_t hi_byte_size = ss.ByteSizeLong();

  return (hi_byte_size - lo_byte_size) / (hi_data.size() - lo_data.size());
}

TEST(TensorSliceWriteTest, CheckpointSize) {
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_BOOL), BytesPerElementHelper<bool>(false));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_BOOL), BytesPerElementHelper<bool>(true));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_FLOAT), BytesPerElementHelper<float>(-1.0));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_DOUBLE), BytesPerElementHelper<double>(-1.0));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_COMPLEX64), BytesPerElementHelper<complex64>(-1.0));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_COMPLEX128), BytesPerElementHelper<complex128>(-1.0));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_INT32), BytesPerElementHelper<int32>(-1));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_INT64), BytesPerElementHelper<int64_t>(-1));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_UINT16), BytesPerElementHelper<uint16>(std::numeric_limits<uint16>::max()));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_UINT8), BytesPerElementHelper<uint8>(std::numeric_limits<uint8>::max()));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_INT8), BytesPerElementHelper<int8>(-1));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_INT16), BytesPerElementHelper<int16>(-1));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_QINT8), BytesPerElementHelper<qint8>(-1));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_QUINT8), BytesPerElementHelper<quint8>(std::numeric_limits<uint8>::max()));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_QINT32), BytesPerElementHelper<qint32>(-1));
  EXPECT_EQ(TensorSliceWriter::MaxBytesPerElement(DT_HALF), BytesPerElementHelper<Eigen::half>(Eigen::half(-1.0)));
}

TEST(TensorSliceWriteTest, SizeErrors) {
  const string filename = io::JoinPath(testing::TmpDir(), "checkpoint");

  TensorSliceWriter writer(filename, CreateTableTensorSliceBuilder);

  
  {
    TensorShape shape({300, 1000000});
    TensorSlice slice = TensorSlice::ParseOrDie("-:-");
    const std::vector<int8> data(300000000, -1);
    Status s = writer.Add("test1", shape, slice, data.data());
    EXPECT_EQ(s.code(), error::INVALID_ARGUMENT);
    EXPECT_TRUE(absl::StrContains(s.error_message(), "Tensor slice is too large to serialize"));
  }

  
  {
    TensorShape shape({256, 1024});
    TensorSlice slice = TensorSlice::ParseOrDie("-:-");
    const std::vector<tstring> data(256 * 1024, std::string(8192, 'f'));
    Status s = writer.Add("test2", shape, slice, data.data());
    EXPECT_EQ(s.code(), error::INVALID_ARGUMENT);
    EXPECT_TRUE(absl::StrContains(s.error_message(), "Tensor slice is too large to serialize"));
  }
}

}  

}  
