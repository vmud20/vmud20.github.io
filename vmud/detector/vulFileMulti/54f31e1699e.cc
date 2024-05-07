








namespace tensorflow {

TEST(MfccMelFilterbankTest, AgreesWithPythonGoldenValues) {
  
  
  MfccMelFilterbank filterbank;

  std::vector<double> input;
  const int kSampleCount = 513;
  input.reserve(kSampleCount);
  for (int i = 0; i < kSampleCount; ++i) {
    input.push_back(i + 1);
  }
  const int kChannelCount = 20;
  filterbank.Initialize( input.size(), 22050 , kChannelCount , 20.0 , 4000.0 );


  std::vector<double> output;
  filterbank.Compute(input, &output);

  std::vector<double> expected = {
      7.38894574,   10.30330648, 13.72703292,  17.24158686,  21.35253118, 25.77781089,  31.30624108, 37.05877236,  43.9436536,   51.80306637, 60.79867148,  71.14363376, 82.90910141,  96.50069158,  112.08428368, 129.96721968, 150.4277597, 173.74997634, 200.86037462, 231.59802942};



  ASSERT_EQ(output.size(), kChannelCount);

  for (int i = 0; i < kChannelCount; ++i) {
    EXPECT_NEAR(output[i], expected[i], 1e-04);
  }
}

TEST(MfccMelFilterbankTest, IgnoresExistingContentOfOutputVector) {
  
  
  MfccMelFilterbank filterbank;

  const int kSampleCount = 513;
  std::vector<double> input;
  std::vector<double> output;

  filterbank.Initialize(kSampleCount, 22050 , 20 , 20.0 , 4000.0 );


  
  
  input.assign(kSampleCount, 1.0);
  filterbank.Compute(input, &output);
  for (const double value : output) {
    EXPECT_LE(0.0, value);
  }

  
  
  
  input.assign(kSampleCount, 0.0);
  filterbank.Compute(input, &output);
  for (const double value : output) {
    EXPECT_EQ(0.0, value);
  }
}

}  
