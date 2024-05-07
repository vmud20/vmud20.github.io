























namespace tflite {
namespace ops {
namespace builtin {
namespace fully_connected {

namespace {
bool SupportedSparsityFormat(const TfLiteSparsity& sparsity) {
  if (sparsity.dim_metadata[0].format == kTfLiteDimDense && sparsity.dim_metadata[1].format == kTfLiteDimSparseCSR) {
    return true;
  }

  return false;
}

static const int kDimMetadataSizeRandomSparse = 2;
static const int kDimMetadataSizeBlockSparse = 3;

TfLiteStatus CreateLedgerTensor(const TfLiteSparsity* sparsity, TfLiteContext* context, TfLiteTensor* ledger) {
  TF_LITE_ENSURE(context, sparsity != nullptr);
  ledger->type = kTfLiteUInt8;
  ledger->allocation_type = kTfLiteArenaRwPersistent;
  TfLiteIntArray* ledger_size = TfLiteIntArrayCreate(1);
  ledger_size->data[0] = sparsity->dim_metadata[1].array_indices->size + sparsity->dim_metadata[1].array_segments->size - 1;
  return context->ResizeTensor(context, ledger, ledger_size);
}

TfLiteStatus PopulateLedgerData(const TfLiteSparsity* sparsity, TfLiteContext* context, uint8_t* ledger_data) {
  TF_LITE_ENSURE(context, sparsity != nullptr);
  const auto* array_segments = sparsity->dim_metadata[1].array_segments;
  const auto* array_indices = sparsity->dim_metadata[1].array_indices;
  int output_data_ptr = 0;

  for (int i = 0; i < array_segments->size - 1; i++) {
    int row_start = array_segments->data[i];
    int row_end = array_segments->data[i + 1];
    if (row_end - row_start > UINT8_MAX) {
      return kTfLiteError;
    }
    
    ledger_data[output_data_ptr] = static_cast<uint8_t>(row_end - row_start);
    output_data_ptr++;

    for (int j = row_start; j < row_end; j++) {
      if (array_indices->data[j] > UINT8_MAX) {
        return kTfLiteError;
      }
      
      ledger_data[output_data_ptr] = static_cast<uint8_t>(array_indices->data[j]);
      output_data_ptr++;
    }
  }
  return kTfLiteOk;
}

}  


enum KernelType {
  kReference, kGenericOptimized, kLegacyPie, };



struct OpData {
  
  
  int32_t output_multiplier;
  int output_shift;
  
  
  int32_t output_activation_min;
  int32_t output_activation_max;
  
  int scratch_tensor_index;
  bool compute_row_sums = false;
  
  bool ledger_initialized;
};

constexpr int kInputTensor = 0;
constexpr int kWeightsTensor = 1;
constexpr int kBiasTensor = 2;
constexpr int kOutputTensor = 0;
constexpr int kShuffledInputWorkspaceTensor = 1;

inline TfLiteStatus CheckTypes(TfLiteContext* context, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output, TfLiteFullyConnectedParams* params) {



  const bool is_quantized = ((filter->type == kTfLiteUInt8) || (filter->type == kTfLiteInt8));
  const bool is_hybrid = is_quantized && (input->type == kTfLiteFloat32);
  const bool is_shuffled = is_quantized && (params->weights_format == kTfLiteFullyConnectedWeightsFormatShuffled4x16Int8);


  
  const bool is_optional_bias_float = !bias || (bias->type == kTfLiteFloat32);
  const bool is_optional_bias_int = !bias || (bias->type == kTfLiteInt32) || (bias->type == kTfLiteInt64);

  if (is_quantized) {
    if (is_shuffled) {
      TF_LITE_ENSURE_TYPES_EQ(context, input->type, kTfLiteUInt8);
      TF_LITE_ENSURE_TYPES_EQ(context, filter->type, kTfLiteUInt8);
      TF_LITE_ENSURE_TYPES_EQ(context, output->type, kTfLiteInt16);
      TF_LITE_ENSURE_EQ(context, is_optional_bias_int, true);
    } else if (is_hybrid) {
      TF_LITE_ENSURE_TYPES_EQ(context, input->type, kTfLiteFloat32);
      TF_LITE_ENSURE_TYPES_EQ(context, output->type, kTfLiteFloat32);
      TF_LITE_ENSURE_EQ(context, is_optional_bias_float, true);
    } else {
      TF_LITE_ENSURE(context, input->type == kTfLiteUInt8 || input->type == kTfLiteInt8 || input->type == kTfLiteInt16);

      TF_LITE_ENSURE(context, output->type == kTfLiteUInt8 || output->type == kTfLiteInt8 || output->type == kTfLiteInt16);

      TF_LITE_ENSURE_EQ(context, is_optional_bias_int, true);
    }
  } else {
    
    TF_LITE_ENSURE_TYPES_EQ(context, input->type, kTfLiteFloat32);
    TF_LITE_ENSURE_TYPES_EQ(context, output->type, kTfLiteFloat32);
    TF_LITE_ENSURE_TYPES_EQ(context, filter->type, kTfLiteFloat32);
    TF_LITE_ENSURE_EQ(context, is_optional_bias_float, true);
  }

  return kTfLiteOk;
}

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  
  
  
  auto* op_data = new OpData();
  context->AddTensors(context, 6, &op_data->scratch_tensor_index);
  return op_data;
}

void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<OpData*>(buffer);
}

TfLiteStatus PrepareImpl(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteFullyConnectedParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);
  
  TF_LITE_ENSURE(context, node->inputs->size == 2 || node->inputs->size == 3);
  
  const int expected_outputs_count = params->weights_format == kTfLiteFullyConnectedWeightsFormatDefault ? 1 : 2;

  TF_LITE_ENSURE_EQ(context, node->outputs->size, expected_outputs_count);

  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInputTensor, &input));
  const TfLiteTensor* filter;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kWeightsTensor, &filter));
  const TfLiteTensor* bias = (node->inputs->size == 3)
          ? GetOptionalInputTensor(context, node, kBiasTensor)
          : nullptr;
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, kOutputTensor, &output));

  
  TF_LITE_ENSURE_STATUS( CheckTypes(context, input, filter, bias, output, params));

  
  
  int input_size = 1;
  for (int i = 0; i < input->dims->size; i++) {
    input_size *= input->dims->data[i];
  }

  TF_LITE_ENSURE_EQ(context, NumDimensions(filter), 2);
  TF_LITE_ENSURE(context, filter->dims->data[1] != 0);
  const int batch_size = input_size / filter->dims->data[1];
  const int num_units = filter->dims->data[0];

  if (bias) {
    TF_LITE_ENSURE_EQ(context, NumElements(bias), SizeOfDimension(filter, 0));
  }

  
  
  if (input->type == kTfLiteUInt8 || input->type == kTfLiteInt8 || input->type == kTfLiteInt16) {
    double real_multiplier = 0.0;
    TF_LITE_ENSURE_STATUS(GetQuantizedConvolutionMultipler( context, input, filter, bias, output, &real_multiplier));
    int exponent;
    QuantizeMultiplier(real_multiplier, &data->output_multiplier, &exponent);
    data->output_shift = exponent;
    TF_LITE_ENSURE_STATUS(CalculateActivationRangeQuantized( context, params->activation, output, &data->output_activation_min, &data->output_activation_max));

  }

  if (input->type == kTfLiteInt16 && output->type == kTfLiteInt16) {
    TF_LITE_ENSURE_EQ(context, input->params.zero_point, 0);
    TF_LITE_ENSURE_EQ(context, output->params.zero_point, 0);
  }

  
  
  
  
  
  const bool is_hybrid = (input->type == kTfLiteFloat32 && (filter->type == kTfLiteUInt8 || filter->type == kTfLiteInt8));

  const bool is_sparse = filter->sparsity != nullptr;
  if (is_hybrid) {
    TfLiteIntArrayFree(node->temporaries);
    data->compute_row_sums = true;
    if (is_sparse) {
      node->temporaries = TfLiteIntArrayCreate(6);
    } else {
      node->temporaries = TfLiteIntArrayCreate(5);
    }
    node->temporaries->data[0] = data->scratch_tensor_index;

    TfLiteTensor* input_quantized;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 0, &input_quantized));
    input_quantized->type = filter->type;
    input_quantized->allocation_type = kTfLiteArenaRw;

    TfLiteIntArray* input_quantized_size = TfLiteIntArrayCopy(input->dims);
    TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, input_quantized, input_quantized_size));

    node->temporaries->data[1] = data->scratch_tensor_index + 1;
    TfLiteTensor* scaling_factors;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 1, &scaling_factors));
    scaling_factors->type = kTfLiteFloat32;
    scaling_factors->allocation_type = kTfLiteArenaRw;

    int scaling_dims[1] = {batch_size};
    if (!TfLiteIntArrayEqualsArray(scaling_factors->dims, 1, scaling_dims)) {
      TfLiteIntArray* scaling_factors_size = TfLiteIntArrayCreate(1);
      scaling_factors_size->data[0] = batch_size;
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, scaling_factors, scaling_factors_size));
    }

    node->temporaries->data[2] = data->scratch_tensor_index + 2;
    TfLiteTensor* accum_scratch;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 2, &accum_scratch));
    accum_scratch->type = kTfLiteInt32;
    accum_scratch->allocation_type = kTfLiteArenaRw;
    int accum_scratch_dims[2] = {num_units, batch_size};
    if (!TfLiteIntArrayEqualsArray(accum_scratch->dims, 2, accum_scratch_dims)) {
      TfLiteIntArray* accum_size = TfLiteIntArrayCreate(2);
      accum_size->data[0] = num_units;
      accum_size->data[1] = batch_size;
      TF_LITE_ENSURE_OK( context, context->ResizeTensor(context, accum_scratch, accum_size));
    }

    node->temporaries->data[3] = data->scratch_tensor_index + 3;
    TfLiteTensor* input_offsets;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 3, &input_offsets));
    input_offsets->type = kTfLiteInt32;
    input_offsets->allocation_type = kTfLiteArenaRw;
    if (!TfLiteIntArrayEqualsArray(input_offsets->dims, 1, scaling_dims)) {
      TfLiteIntArray* input_offsets_size = TfLiteIntArrayCreate(1);
      input_offsets_size->data[0] = batch_size;
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, input_offsets, input_offsets_size));
    }
    node->temporaries->data[4] = data->scratch_tensor_index + 4;
    TfLiteTensor* row_sums;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 4, &row_sums));
    row_sums->type = kTfLiteInt32;
    row_sums->allocation_type = kTfLiteArenaRwPersistent;
    int row_sums_dims[1] = {num_units};
    if (!TfLiteIntArrayEqualsArray(row_sums->dims, 1, row_sums_dims)) {
      TfLiteIntArray* row_sums_size = TfLiteIntArrayCreate(1);
      row_sums_size->data[0] = row_sums_dims[0];
      TF_LITE_ENSURE_OK( context, context->ResizeTensor(context, row_sums, row_sums_size));
    }

    if (is_sparse) {
      data->ledger_initialized = false;
      node->temporaries->data[5] = data->scratch_tensor_index + 5;
      TfLiteTensor* filter_ledger = &context->tensors[node->temporaries->data[5]];
      auto status = CreateLedgerTensor(filter->sparsity, context, filter_ledger);
      if (status != kTfLiteOk) return status;
    }
  }

  
  TfLiteIntArray* output_size_array = nullptr;
  if (params->keep_num_dims) {
    
    
    
    
    TF_LITE_ENSURE_EQ(context, input->dims->data[input->dims->size - 1], SizeOfDimension(filter, 1));
    output_size_array = TfLiteIntArrayCopy(input->dims);
    output_size_array->data[output_size_array->size - 1] = num_units;
  } else {
    
    output_size_array = TfLiteIntArrayCreate(2);
    output_size_array->data[0] = batch_size;
    output_size_array->data[1] = num_units;
  }
  TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, output, output_size_array));

  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  
  auto* params = reinterpret_cast<TfLiteFullyConnectedParams*>(node->builtin_data);
  const TfLiteTensor* filter;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kWeightsTensor, &filter));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInputTensor, &input));
  const bool is_quantized = ((filter->type == kTfLiteUInt8) || (filter->type == kTfLiteInt8));
  const bool is_hybrid = is_quantized && (input->type == kTfLiteFloat32);
  const bool is_pie = kernel_type == kLegacyPie;

  
  
  if (!is_pie && !is_hybrid) {
    TF_LITE_ENSURE(context, params->activation == kTfLiteActNone || params->activation == kTfLiteActRelu || params->activation == kTfLiteActReluN1To1 || params->activation == kTfLiteActRelu6);


  }
  return PrepareImpl(context, node);
}

TfLiteStatus EvalPie(TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output) {


  int total_input_size = 1;
  for (int i = 0; i < input->dims->size; i++) {
    total_input_size *= input->dims->data[i];
  }

  int input_size = filter->dims->data[1];
  const int batch_size = total_input_size / filter->dims->data[1];
  const int num_units = filter->dims->data[0];

  
  if (bias) {
    tensor_utils::VectorBatchVectorAssign(GetTensorData<float>(bias), num_units, batch_size, GetTensorData<float>(output));

  } else {
    std::fill_n(GetTensorData<float>(output), batch_size * num_units, 0.0f);
  }

  
  tensor_utils::MatrixBatchVectorMultiplyAccumulate( GetTensorData<float>(filter), num_units, input_size, GetTensorData<float>(input), batch_size, GetTensorData<float>(output));


  
  tensor_utils::ApplyActivationToVector( GetTensorData<float>(output), batch_size * num_units, params->activation, GetTensorData<float>(output));


  return kTfLiteOk;
}

TfLiteStatus EvalHybridDense( TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* input_quantized, TfLiteTensor* scaling_factors, TfLiteTensor* accum_scratch, TfLiteTensor* row_sums, TfLiteTensor* input_offsets, TfLiteTensor* output) {





  int total_input_size = 1;
  for (int i = 0; i < input->dims->size; i++) {
    total_input_size *= input->dims->data[i];
  }

  const int input_size = filter->dims->data[1];
  const int batch_size = total_input_size / filter->dims->data[1];
  const int num_units = filter->dims->data[0];

  
  if (bias) {
    tensor_utils::VectorBatchVectorAssign(GetTensorData<float>(bias), num_units, batch_size, GetTensorData<float>(output));

  } else {
    std::fill_n(GetTensorData<float>(output), batch_size * num_units, 0.0f);
  }

  
  if (tensor_utils::IsZeroVector(GetTensorData<float>(input), total_input_size)) {
    tensor_utils::ApplyActivationToVector( GetTensorData<float>(output), batch_size * num_units, params->activation, GetTensorData<float>(output));

    return kTfLiteOk;
  }

  
  float* scaling_factors_ptr = GetTensorData<float>(scaling_factors);
  int32_t* input_offset_ptr = nullptr;
  int32_t* row_sums_ptr = nullptr;
  if (params->asymmetric_quantize_inputs) {
    input_offset_ptr = GetTensorData<int32_t>(input_offsets);
    row_sums_ptr = GetTensorData<int32_t>(row_sums);
  }
  int8_t* quant_data = GetTensorData<int8_t>(input_quantized);
  const int8_t* filter_data = GetTensorData<int8_t>(filter);
  const float* input_ptr = GetTensorData<float>(input);
  tensor_utils::BatchQuantizeFloats( input_ptr, batch_size, input_size, quant_data, scaling_factors_ptr, input_offset_ptr, params->asymmetric_quantize_inputs);

  for (int b = 0; b < batch_size; ++b) {
    
    scaling_factors_ptr[b] *= filter->params.scale;
  }

  
  int32_t* scratch = GetTensorData<int32_t>(accum_scratch);
  tensor_utils::MatrixBatchVectorMultiplyAccumulate( filter_data, num_units, input_size, quant_data, scaling_factors_ptr, batch_size, GetTensorData<float>(output), nullptr, input_offset_ptr, scratch, row_sums_ptr, &data->compute_row_sums, CpuBackendContext::GetFromContext(context));




  
  tensor_utils::ApplyActivationToVector( GetTensorData<float>(output), batch_size * num_units, params->activation, GetTensorData<float>(output));

  return kTfLiteOk;
}

void EvalSparseHybridImpl(TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, int thread_start, int thread_end, TfLiteTensor* input_quantized, TfLiteTensor* scaling_factors, TfLiteTensor* accum_scratch, TfLiteTensor* row_sums, TfLiteTensor* input_offsets, TfLiteTensor* output) {






  ruy::profiler::ScopeLabel label("FullyConnected");
  ruy::profiler::ScopeLabel inner_label("Sparse Hybrid Kernel");
  const auto& input_shape = GetTensorShape(input);
  const auto& output_shape = GetTensorShape(output);
  const auto& filter_shape = GetTensorShape(filter);
  const int input_dims_count = input_shape.DimensionsCount();
  const int output_dims_count = output_shape.DimensionsCount();
  const int filter_dims_count = filter_shape.DimensionsCount();
  const int batch_size = thread_end - thread_start;
  const int input_depth = MatchingDim(filter_shape, filter_dims_count - 1, input_shape, input_dims_count - 1);
  const int output_depth = MatchingDim(filter_shape, filter_dims_count - 2, output_shape, output_dims_count - 1);
  const int per_thread_input_size = batch_size * input_depth;

  const float* per_thread_input = GetTensorData<float>(input) + thread_start * input_depth;
  float* per_thread_output = GetTensorData<float>(output) + thread_start * output_depth;

  
  if (bias) {
    tensor_utils::VectorBatchVectorAssign(GetTensorData<float>(bias), output_depth, batch_size, per_thread_output);

  } else {
    std::fill_n(per_thread_output, batch_size * output_depth, 0.0f);
  }

  
  if (tensor_utils::IsZeroVector(per_thread_input, per_thread_input_size)) {
    tensor_utils::ApplyActivationToVector( per_thread_output, batch_size * output_depth, params->activation, per_thread_output);

    return;
  }

  
  float* scaling_factors_ptr = GetTensorData<float>(scaling_factors) + thread_start;
  int32_t* input_offset_ptr = nullptr;
  int32_t* row_sums_ptr = nullptr;
  if (params->asymmetric_quantize_inputs) {
    input_offset_ptr = GetTensorData<int32_t>(input_offsets) + thread_start;
    row_sums_ptr = GetTensorData<int32_t>(row_sums);
  }
  int8_t* quant_data = GetTensorData<int8_t>(input_quantized) + thread_start * input_depth;
  tensor_utils::BatchQuantizeFloats(per_thread_input, batch_size, input_depth, quant_data, scaling_factors_ptr, input_offset_ptr, params->asymmetric_quantize_inputs);


  for (int b = 0; b < batch_size; ++b) {
    
    scaling_factors_ptr[b] *= filter->params.scale;
  }

  if (params->asymmetric_quantize_inputs) {
    float* per_thread_output_ptr = per_thread_output;
    for (int b = 0; b < batch_size; ++b) {
      const float scaled_zp = scaling_factors_ptr[b] * input_offset_ptr[b];
      for (int row = 0; row < output_depth; ++row) {
        *per_thread_output_ptr++ -= scaled_zp * row_sums_ptr[row];
      }
    }
  }

  
  TfLiteTensor* filter_ledger = &context->tensors[node->temporaries->data[5]];
  tensor_utils::SparseMatrixBatchVectorMultiplyAccumulate( GetTensorData<int8_t>(filter), GetTensorData<uint8_t>(filter_ledger), output_depth, input_depth, quant_data, scaling_factors_ptr, batch_size, per_thread_output);



  
  tensor_utils::ApplyActivationToVector(per_thread_output, batch_size * output_depth, params->activation, per_thread_output);

}

struct SparseHybridFullyConnectedTask : cpu_backend_threadpool::Task {
  SparseHybridFullyConnectedTask( TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, const int thread_start, const int thread_end, TfLiteTensor* input_quantized, TfLiteTensor* scaling_factors, TfLiteTensor* accum_scratch, TfLiteTensor* row_sums, TfLiteTensor* input_offsets, TfLiteTensor* output)






      : context(context), node(node), params(params), data(data), input(input), filter(filter), bias(bias), thread_start(thread_start), thread_end(thread_end), input_quantized(input_quantized), scaling_factors(scaling_factors), accum_scratch(accum_scratch), row_sums(row_sums), input_offsets(input_offsets), output(output) {}














  void Run() override {
    EvalSparseHybridImpl(context, node, params, data, input, filter, bias, thread_start, thread_end, input_quantized, scaling_factors, accum_scratch, row_sums, input_offsets, output);


  }

 private:
  TfLiteContext* context;
  TfLiteNode* node;
  TfLiteFullyConnectedParams* params;
  OpData* data;
  const TfLiteTensor* input;
  const TfLiteTensor* filter;
  const TfLiteTensor* bias;
  const int thread_start;
  const int thread_end;
  TfLiteTensor* input_quantized;
  TfLiteTensor* scaling_factors;
  TfLiteTensor* accum_scratch;
  TfLiteTensor* row_sums;
  TfLiteTensor* input_offsets;
  TfLiteTensor* output;
};

TfLiteStatus EvalHybrid(TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* input_quantized, TfLiteTensor* scaling_factors, TfLiteTensor* accum_scratch, TfLiteTensor* row_sums, TfLiteTensor* input_offsets, TfLiteTensor* output) {





  const auto& output_shape = GetTensorShape(output);
  CpuBackendContext* cpu_backend_context = CpuBackendContext::GetFromContext(context);
  const bool is_dense = filter->sparsity == nullptr;
  if (is_dense) {
    return EvalHybridDense(context, node, params, data, input, filter, bias, input_quantized, scaling_factors, accum_scratch, row_sums, input_offsets, output);

  }

  TfLiteTensor* filter_ledger = &context->tensors[node->temporaries->data[5]];
  if (!data->ledger_initialized) {
    PopulateLedgerData(filter->sparsity, context, GetTensorData<uint8_t>(filter_ledger));
    data->ledger_initialized = true;
  }

  
  
  
  
  
  const int max_threads = cpu_backend_context->max_num_threads();
  const int batches = FlatSizeSkipDim(output_shape, output_shape.DimensionsCount() - 1);
  const int thread_count = std::max(1, std::min(batches, max_threads));
  if (params->asymmetric_quantize_inputs && data->compute_row_sums) {
    
    static const int kBlockSize = 16;
    const uint8_t* ledger_ptr = GetTensorData<uint8_t>(filter_ledger);
    const int8_t* row_ptr = GetTensorData<int8_t>(filter);
    const int output_depth = filter->dims->data[0];
    int32_t* row_sums_ptr = GetTensorData<int32_t>(row_sums);
    for (int row = 0; row < output_depth; ++row) {
      int32_t row_sum = 0;
      int num_nonzero_blocks = *ledger_ptr++;
      for (int i = 0; i < num_nonzero_blocks; ++i, ++ledger_ptr) {
        for (int c = 0; c < kBlockSize; c++) {
          row_sum += (*row_ptr++);
        }
      }
      row_sums_ptr[row] = row_sum;
    }
    data->compute_row_sums = false;
  }
  std::vector<SparseHybridFullyConnectedTask> tasks;
  tasks.reserve(thread_count);
  int thread_start = 0;
  for (int i = 0; i < thread_count; ++i) {
    
    
    
    int thread_end = thread_start + batches / thread_count;
    if (i < batches % thread_count) thread_end++;

    tasks.emplace_back(context, node, params, data, input, filter, bias, thread_start, thread_end, input_quantized, scaling_factors, accum_scratch, row_sums, input_offsets, output);


    thread_start = thread_end;
  }
  cpu_backend_threadpool::Execute(tasks.size(), tasks.data(), cpu_backend_context);
  return kTfLiteOk;
}

namespace {
template <KernelType kernel_type> void FullyConnectedInt8(const OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output, CpuBackendContext* cpu_backend_context) {



  FullyConnectedParams op_params;
  op_params.input_offset = -input->params.zero_point;
  op_params.weights_offset = -filter->params.zero_point;
  op_params.output_offset = output->params.zero_point;
  op_params.output_multiplier = data->output_multiplier;
  op_params.output_shift = data->output_shift;
  op_params.quantized_activation_min = data->output_activation_min;
  op_params.quantized_activation_max = data->output_activation_max;
  op_params.lhs_cacheable = IsConstantTensor(filter);
  op_params.rhs_cacheable = IsConstantTensor(input);
  if (kernel_type == kReference) {
    reference_integer_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<int8_t>(input), GetTensorShape(filter), GetTensorData<int8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<int8_t>(output));



  } else {
    optimized_integer_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<int8_t>(input), GetTensorShape(filter), GetTensorData<int8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<int8_t>(output), cpu_backend_context);




  }
}
}  

namespace {
template <KernelType kernel_type> void FullyConnectedInt16(const OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output) {


  FullyConnectedParams op_params;
  op_params.weights_offset = -filter->params.zero_point;
  op_params.output_multiplier = data->output_multiplier;
  op_params.output_shift = data->output_shift;
  op_params.quantized_activation_min = data->output_activation_min;
  op_params.quantized_activation_max = data->output_activation_max;
  reference_integer_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<int16_t>(input), GetTensorShape(filter), GetTensorData<int8_t>(filter), GetTensorShape(bias), GetTensorData<int64_t>(bias), GetTensorShape(output), GetTensorData<int16_t>(output));



}
}  

template <KernelType kernel_type> TfLiteStatus EvalQuantized(TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output) {




  int32_t input_offset = -input->params.zero_point;
  int32_t filter_offset = -filter->params.zero_point;
  int32_t output_offset = output->params.zero_point;
  
  if (input->type == kTfLiteFloat32) {
    TfLiteTensor* input_quantized;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 0, &input_quantized));
    TfLiteTensor* scaling_factors;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 1, &scaling_factors));
    TfLiteTensor* accum_scratch;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 2, &accum_scratch));
    TfLiteTensor* input_offsets;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 3, &input_offsets));
    TfLiteTensor* row_sums;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 4, &row_sums));
    return EvalHybrid(context, node, params, data, input, filter, bias, input_quantized, scaling_factors, accum_scratch, row_sums, input_offsets, output);

  } else {
    FullyConnectedParams op_params;
    op_params.input_offset = input_offset;
    op_params.weights_offset = filter_offset;
    op_params.output_offset = output_offset;
    op_params.output_multiplier = data->output_multiplier;
    op_params.output_shift = data->output_shift;
    op_params.quantized_activation_min = data->output_activation_min;
    op_params.quantized_activation_max = data->output_activation_max;
    op_params.lhs_cacheable = IsConstantTensor(filter);
    op_params.rhs_cacheable = IsConstantTensor(input);
    switch (output->type) {
      case kTfLiteUInt8:
        if (kernel_type == kReference) {
          reference_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<uint8_t>(output));



        } else {
          optimized_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<uint8_t>(output), CpuBackendContext::GetFromContext(context));




        }
        break;
      case kTfLiteInt8:
        FullyConnectedInt8<kernel_type>( data, input, filter, bias, output, CpuBackendContext::GetFromContext(context));

        break;
      case kTfLiteInt16:
        if (input->type == kTfLiteInt16) {
          
          
          bool has_non_zero_point = input->params.zero_point || filter->params.zero_point || output->params.zero_point;

          if (kernel_type == kReference || has_non_zero_point) {
            FullyConnectedInt16<kernel_type>(data, input, filter, bias, output);
          } else {
            
            
            optimized_integer_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<int16_t>(input), GetTensorShape(filter), GetTensorData<int8_t>(filter), RuntimeShape(), nullptr, GetTensorShape(output), GetTensorData<int16_t>(output), CpuBackendContext::GetFromContext(context));




            if (bias) {
              reference_ops::AddBiasToOutput( op_params, GetTensorData<int64_t>(bias), GetTensorShape(output), GetTensorData<int16_t>(output));

            }
          }
        } else if (kernel_type == kReference) {
          reference_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<int16_t>(output));



        } else {
          optimized_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<int16_t>(output), CpuBackendContext::GetFromContext(context));




        }
        break;
      default:
        context->ReportError(context, "Quantized FullyConnected expects output data " "type uint8, int8 or int16");

        return kTfLiteError;
    }
  }

  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus EvalShuffledQuantized(TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output, TfLiteTensor* shuffled_input_workspace) {






  
  
  if (shuffled_input_workspace->type != kTfLiteUInt8) {
    context->ReportError(context, "Unexpected data type");
    return kTfLiteError;
  }










  FullyConnectedParams op_params;
  op_params.output_multiplier = data->output_multiplier;
  op_params.output_shift = data->output_shift;
  op_params.quantized_activation_min = data->output_activation_min;
  op_params.quantized_activation_max = data->output_activation_max;
  op_params.lhs_cacheable = IsConstantTensor(filter);
  op_params.rhs_cacheable = IsConstantTensor(input);
  if (kernel_type == kReference) {
    reference_ops::ShuffledFullyConnected( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<int16_t>(output), GetTensorData<uint8_t>(shuffled_input_workspace));




  } else {
    optimized_ops::ShuffledFullyConnected( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<int16_t>(output), GetTensorData<uint8_t>(shuffled_input_workspace), CpuBackendContext::GetFromContext(context));





  }


  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus EvalFloat(TfLiteContext* context, TfLiteNode* node, TfLiteFullyConnectedParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output) {



  float output_activation_min, output_activation_max;
  CalculateActivationRange(params->activation, &output_activation_min, &output_activation_max);
  if (kernel_type == kReference) {
    FullyConnectedParams op_params;
    op_params.float_activation_min = output_activation_min;
    op_params.float_activation_max = output_activation_max;
    if (filter->sparsity != nullptr) {
      const auto& sparsity = *filter->sparsity;
      reference_ops::FullyConnectedSparseWeight( sparsity, op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output));




    } else {
      reference_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output));



    }
  } else if (kernel_type == kLegacyPie) {
    return EvalPie(context, node, params, data, input, filter, bias, output);
  } else {
    FullyConnectedParams op_params;
    op_params.float_activation_min = output_activation_min;
    op_params.float_activation_max = output_activation_max;
    if (filter->sparsity != nullptr) {
      const auto& sparsity = *filter->sparsity;
      if (!SupportedSparsityFormat(sparsity)) {
        TF_LITE_KERNEL_LOG(context, "Unsupported sparse fully-connected weight format.");
        return kTfLiteError;
      }

      if (sparsity.dim_metadata_size == kDimMetadataSizeRandomSparse) {
        
        optimized_ops::FullyConnectedSparseWeight( sparsity, op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output));




      } else if (sparsity.dim_metadata_size == kDimMetadataSizeBlockSparse && sparsity.dim_metadata[2].dense_size == 4) {
        
        optimized_ops::FullyConnectedSparseWeight1x4( sparsity, op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), CpuBackendContext::GetFromContext(context));





      } else {
        TF_LITE_KERNEL_LOG(context, "Unsupported sparse fully-connected weight format.");
        return kTfLiteError;
      }

    } else {
      op_params.lhs_cacheable = IsConstantTensor(filter);
      op_params.rhs_cacheable = IsConstantTensor(input);
      optimized_ops::FullyConnected( op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), CpuBackendContext::GetFromContext(context));




    }
  }

  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteFullyConnectedParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInputTensor, &input));
  const TfLiteTensor* filter;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kWeightsTensor, &filter));
  const TfLiteTensor* bias = (node->inputs->size == 3)
          ? GetOptionalInputTensor(context, node, kBiasTensor)
          : nullptr;
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, kOutputTensor, &output));
  
  if (NumElements(output) == 0) {
    return kTfLiteOk;
  }

  switch (filter->type) {
    case kTfLiteFloat32:
      return EvalFloat<kernel_type>(context, node, params, data, input, filter, bias, output);
    case kTfLiteUInt8:
      if (params->weights_format == kTfLiteFullyConnectedWeightsFormatShuffled4x16Int8) {
        TfLiteTensor* shuffled_input_workspace;
        TF_LITE_ENSURE_OK( context, GetOutputSafe(context, node, kShuffledInputWorkspaceTensor, &shuffled_input_workspace));

        return EvalShuffledQuantized<kernel_type>(context, node, params, data, input, filter, bias, output, shuffled_input_workspace);

      } else if (params->weights_format == kTfLiteFullyConnectedWeightsFormatDefault) {
        return EvalQuantized<kernel_type>(context, node, params, data, input, filter, bias, output);
      } else {
        context->ReportError(context, "Unhandled fully-connected weights format");
        return kTfLiteError;
      }
    case kTfLiteInt8:
      if (params->weights_format == kTfLiteFullyConnectedWeightsFormatDefault) {
        return EvalQuantized<kernel_type>(context, node, params, data, input, filter, bias, output);
      } else {
        context->ReportError(context, "Unhandled fully-connected weights format");
        return kTfLiteError;
      }
    default:
      context->ReportError(context, "Filter data type %s currently not supported.", TfLiteTypeGetName(filter->type));

      return kTfLiteError;
  }
  return kTfLiteOk;
}

}  

TfLiteRegistration* Register_FULLY_CONNECTED_REF() {
  static TfLiteRegistration r = {
      fully_connected::Init, fully_connected::Free, fully_connected::Prepare<fully_connected::kReference>, fully_connected::Eval<fully_connected::kReference>};

  return &r;
}

TfLiteRegistration* Register_FULLY_CONNECTED_GENERIC_OPT() {
  static TfLiteRegistration r = {
      fully_connected::Init, fully_connected::Free, fully_connected::Prepare<fully_connected::kGenericOptimized>, fully_connected::Eval<fully_connected::kGenericOptimized>};

  return &r;
}


TfLiteRegistration* Register_FULLY_CONNECTED_PIE() {
  static TfLiteRegistration r = {
      fully_connected::Init, fully_connected::Free, fully_connected::Prepare<fully_connected::kLegacyPie>, fully_connected::Eval<fully_connected::kLegacyPie>};

  return &r;
}

TfLiteRegistration* Register_FULLY_CONNECTED() {
  return Register_FULLY_CONNECTED_GENERIC_OPT();
}

}  
}  
}  
