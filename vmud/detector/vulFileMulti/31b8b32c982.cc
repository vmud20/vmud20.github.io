


















namespace tflite {
namespace ops {
namespace builtin {
namespace svdf {

namespace {

struct OpData {
  int scratch_tensor_index;
  bool float_weights_time_initialized;
  int32 effective_scale_1_a;
  int effective_scale_1_b;
  int32 effective_scale_2_a;
  int effective_scale_2_b;
  bool compute_row_sums = false;
};

}  


constexpr int kInputTensor = 0;
constexpr int kWeightsFeatureTensor = 1;
constexpr int kWeightsTimeTensor = 2;
constexpr int kBiasTensor = 3;

constexpr int kStateTensor = 4;


constexpr int kOutputTensor = 0;

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  auto* op_data = new OpData();
  op_data->float_weights_time_initialized = false;
  
  context->AddTensors(context, 6, &op_data->scratch_tensor_index);
  return op_data;
}

void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<OpData*>(buffer);
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  const auto* params = reinterpret_cast<TfLiteSVDFParams*>(node->builtin_data);
  OpData* op_data = reinterpret_cast<OpData*>(node->user_data);
  int scratch_tensor_index = op_data->scratch_tensor_index;

  
  TF_LITE_ENSURE_EQ(context, node->outputs->size, 1);
  TF_LITE_ENSURE_EQ(context, node->inputs->size, 5);

  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInputTensor, &input));
  const TfLiteTensor* weights_feature;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kWeightsFeatureTensor, &weights_feature));
  const TfLiteTensor* weights_time;
  TF_LITE_ENSURE_OK( context, GetInputSafe(context, node, kWeightsTimeTensor, &weights_time));

  TF_LITE_ENSURE(context, input->type == kTfLiteFloat32 || input->type == kTfLiteInt8);

  
  
  const int rank = params->rank;
  const int batch_size = input->dims->data[0];
  const int num_filters = weights_feature->dims->data[0];
  TF_LITE_ENSURE(context, rank != 0);
  TF_LITE_ENSURE_EQ(context, num_filters % rank, 0);
  const int num_units = num_filters / rank;
  const int memory_size = weights_time->dims->data[1];
  TF_LITE_ENSURE_EQ(context, input->dims->data[1], weights_feature->dims->data[1]);
  TF_LITE_ENSURE_EQ(context, weights_time->dims->data[0], num_filters);

  const TfLiteTensor* bias = GetOptionalInputTensor(context, node, kBiasTensor);
  if (bias) {
    TF_LITE_ENSURE_EQ(context, bias->dims->data[0], num_units);
  }

  const TfLiteTensor* state;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kStateTensor, &state));
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, kOutputTensor, &output));

  
  TF_LITE_ENSURE_EQ(context, NumDimensions(state), 2);
  TF_LITE_ENSURE_EQ(context, SizeOfDimension(state, 0), batch_size);
  TF_LITE_ENSURE_EQ(context, SizeOfDimension(state, 1), memory_size * num_filters);

  
  TfLiteIntArray* output_size_array = TfLiteIntArrayCreate(2);
  output_size_array->data[0] = batch_size;
  output_size_array->data[1] = num_units;
  TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, output, output_size_array));

  
  const bool is_hybrid_op = IsHybridOp(input, weights_feature);
  const bool is_full_integer = input->type == kTfLiteInt8;

  
  TfLiteIntArrayFree(node->temporaries);
  if (is_hybrid_op) {
    node->temporaries = TfLiteIntArrayCreate(6);
  } else if (is_full_integer) {
    node->temporaries = TfLiteIntArrayCreate(2);
  } else {
    node->temporaries = TfLiteIntArrayCreate(1);
  }
  node->temporaries->data[0] = scratch_tensor_index;

  TfLiteIntArray* scratch_size_array = TfLiteIntArrayCreate(2);
  scratch_size_array->data[0] = batch_size;
  scratch_size_array->data[1] = num_filters;

  TfLiteTensor* scratch_tensor;
  TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 0, &scratch_tensor));

  
  
  if (is_full_integer) {
    scratch_tensor->type = kTfLiteInt32;
  } else {
    scratch_tensor->type = kTfLiteFloat32;
  }
  scratch_tensor->allocation_type = kTfLiteArenaRw;
  TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, scratch_tensor, scratch_size_array));

  if (is_hybrid_op) {
    op_data->compute_row_sums = true;
    
    
    node->temporaries->data[1] = scratch_tensor_index + 1;
    TfLiteTensor* input_quantized;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 1, &input_quantized));
    input_quantized->type = weights_feature->type;
    input_quantized->allocation_type = kTfLiteArenaRw;
    if (!TfLiteIntArrayEqual(input_quantized->dims, input->dims)) {
      TfLiteIntArray* input_quantized_size = TfLiteIntArrayCopy(input->dims);
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, input_quantized, input_quantized_size));
    }

    
    node->temporaries->data[2] = scratch_tensor_index + 2;
    TfLiteTensor* scaling_factors;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 2, &scaling_factors));
    scaling_factors->type = kTfLiteFloat32;
    scaling_factors->allocation_type = kTfLiteArenaRw;
    int scaling_dims[1] = {batch_size};
    if (!TfLiteIntArrayEqualsArray(scaling_factors->dims, 1, scaling_dims)) {
      TfLiteIntArray* scaling_factors_size = TfLiteIntArrayCreate(1);
      scaling_factors_size->data[0] = batch_size;
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, scaling_factors, scaling_factors_size));
    }

    
    
    node->temporaries->data[3] = scratch_tensor_index + 3;
    TfLiteTensor* float_weights_time;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 3, &float_weights_time));
    float_weights_time->type = kTfLiteFloat32;
    
    float_weights_time->allocation_type = kTfLiteArenaRwPersistent;
    if (!TfLiteIntArrayEqual(float_weights_time->dims, weights_time->dims)) {
      TfLiteIntArray* float_weights_time_size = TfLiteIntArrayCopy(weights_time->dims);
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, float_weights_time, float_weights_time_size));

    }

    node->temporaries->data[4] = scratch_tensor_index + 4;
    TfLiteTensor* zero_points;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 4, &zero_points));
    zero_points->type = kTfLiteFloat32;
    zero_points->allocation_type = kTfLiteArenaRw;
    int zero_points_dims[1] = {batch_size};
    if (!TfLiteIntArrayEqualsArray(zero_points->dims, 1, zero_points_dims)) {
      TfLiteIntArray* zero_points_size = TfLiteIntArrayCreate(1);
      zero_points_size->data[0] = zero_points_dims[0];
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, zero_points, zero_points_size));
    }

    node->temporaries->data[5] = scratch_tensor_index + 5;
    TfLiteTensor* row_sums;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 5, &row_sums));
    row_sums->type = kTfLiteFloat32;
    row_sums->allocation_type = kTfLiteArenaRwPersistent;
    int row_sums_dims[1] = {num_filters};
    if (!TfLiteIntArrayEqualsArray(row_sums->dims, 1, row_sums_dims)) {
      TfLiteIntArray* row_sums_size = TfLiteIntArrayCreate(1);
      row_sums_size->data[0] = row_sums_dims[0];
      TF_LITE_ENSURE_OK( context, context->ResizeTensor(context, row_sums, row_sums_size));
    }
  }
  if (is_full_integer) {
    
    TfLiteIntArray* output_temp_size_array = TfLiteIntArrayCreate(2);
    output_temp_size_array->data[0] = num_units;
    output_temp_size_array->data[1] = batch_size;
    node->temporaries->data[1] = scratch_tensor_index + 1;
    TfLiteTensor* output_temp;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 1, &output_temp));
    output_temp->type = kTfLiteInt32;
    output_temp->allocation_type = kTfLiteArenaRw;
    TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, output_temp, output_temp_size_array));

    
    auto* input_params = reinterpret_cast<TfLiteAffineQuantization*>(input->quantization.params);
    auto* weights_feature_params = reinterpret_cast<TfLiteAffineQuantization*>( weights_feature->quantization.params);
    auto* state_params = reinterpret_cast<TfLiteAffineQuantization*>(state->quantization.params);
    auto* weight_time_params = reinterpret_cast<TfLiteAffineQuantization*>( weights_time->quantization.params);
    auto* output_params = reinterpret_cast<TfLiteAffineQuantization*>( output->quantization.params);
    const double effective_scale_1 = input_params->scale->data[0] * weights_feature_params->scale->data[0] / state_params->scale->data[0];

    const double effective_scale_2 = state_params->scale->data[0] * weight_time_params->scale->data[0] / output_params->scale->data[0];

    QuantizeMultiplier(effective_scale_1, &op_data->effective_scale_1_a, &op_data->effective_scale_1_b);
    QuantizeMultiplier(effective_scale_2, &op_data->effective_scale_2_a, &op_data->effective_scale_2_b);
  }
  return kTfLiteOk;
}

TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteSVDFParams*>(node->builtin_data);
  OpData* op_data = reinterpret_cast<OpData*>(node->user_data);

  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInputTensor, &input));
  const TfLiteTensor* weights_feature;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kWeightsFeatureTensor, &weights_feature));
  const TfLiteTensor* weights_time;
  TF_LITE_ENSURE_OK( context, GetInputSafe(context, node, kWeightsTimeTensor, &weights_time));
  const TfLiteTensor* bias = GetOptionalInputTensor(context, node, kBiasTensor);

  TfLiteTensor* scratch;
  TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 0, &scratch));

  TfLiteTensor* state = GetVariableInput(context, node, kStateTensor);
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, kOutputTensor, &output));

  switch (weights_feature->type) {
    case kTfLiteFloat32: {
      reference_ops::EvalFloatSVDF( params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(weights_feature), GetTensorData<float>(weights_feature), GetTensorShape(weights_time), GetTensorData<float>(weights_time), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorData<float>(scratch), GetTensorData<float>(state), GetTensorShape(output), GetTensorData<float>(output));






      return kTfLiteOk;
    }
    case kTfLiteUInt8:
    case kTfLiteInt8: {
      if (input->type == kTfLiteFloat32) {
        TfLiteTensor* input_quantized;
        TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 1, &input_quantized));
        TfLiteTensor* scaling_factors;
        TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 2, &scaling_factors));
        TfLiteTensor* float_weights_time;
        TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 3, &float_weights_time));
        TfLiteTensor* zero_points;
        TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, 4, &zero_points));
        TfLiteTensor* row_sums;
        TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 5, &row_sums));
        
        
        
        
        
        
        if (!op_data->float_weights_time_initialized) {
          const float dequantization_scale = weights_time->params.scale;
          const int8_t* weights_time_ptr = GetTensorData<int8_t>(weights_time);
          float* float_weights_time_ptr = GetTensorData<float>(float_weights_time);
          for (int i = 0; i < NumElements(float_weights_time); ++i) {
            float_weights_time_ptr[i] = weights_time_ptr[i] * dequantization_scale;
          }
          op_data->float_weights_time_initialized = true;
        }

        int32_t* zero_points_ptr = nullptr;
        int32_t* row_sums_ptr = nullptr;
        if (params->asymmetric_quantize_inputs && row_sums != nullptr) {
          zero_points_ptr = GetTensorData<int32_t>(zero_points);
          row_sums_ptr = GetTensorData<int32_t>(row_sums);
        }

        reference_ops::EvalHybridSVDF( params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(weights_feature), GetTensorData<int8_t>(weights_feature), weights_feature->params.scale, GetTensorShape(float_weights_time), GetTensorData<float>(float_weights_time), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorData<float>(scratch), GetTensorData<float>(scaling_factors), GetTensorData<int8_t>(input_quantized), GetTensorData<float>(state), GetTensorShape(output), GetTensorData<float>(output), zero_points_ptr, row_sums_ptr, &op_data->compute_row_sums);









        return kTfLiteOk;
      }
      auto* input_params = reinterpret_cast<TfLiteAffineQuantization*>( input->quantization.params);
      auto* output_params = reinterpret_cast<TfLiteAffineQuantization*>( output->quantization.params);
      TfLiteTensor* output_temp;
      TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, 1, &output_temp));

      
      
      TF_LITE_ENSURE_EQ(context, params->activation, kTfLiteActRelu);

      reference_ops::EvalIntegerSVDF( params, GetTensorShape(input), GetTensorData<int8_t>(input), GetTensorShape(weights_feature), GetTensorData<int8_t>(weights_feature), GetTensorShape(weights_time), GetTensorData<int16_t>(weights_time), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorData<int16_t>(state), GetTensorShape(output), GetTensorData<int8_t>(output), GetTensorData<int32_t>(scratch), GetTensorData<int32_t>(output_temp), op_data->effective_scale_1_a, op_data->effective_scale_1_b, op_data->effective_scale_2_a, op_data->effective_scale_2_b, input_params->zero_point->data[0], output_params->zero_point->data[0]);










      return kTfLiteOk;
    }
    default:
      context->ReportError(context, "Type %s not currently supported.", TfLiteTypeGetName(weights_feature->type));
      return kTfLiteError;
  }
}

}  

TfLiteRegistration* Register_SVDF() {
  static TfLiteRegistration r = {svdf::Init, svdf::Free, svdf::Prepare, svdf::Eval};
  return &r;
}

}  
}  
}  
