







namespace tflite {
namespace {

constexpr int kParams = 0;
constexpr int kIndices = 1;
constexpr int kOutputTensor = 0;
constexpr int MAX_INDICES_ND = 5;

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  MicroContext* micro_context = GetMicroContext(context);

  TF_LITE_ENSURE_EQ(context, NumInputs(node), 2);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);

  TfLiteTensor* params = micro_context->AllocateTempInputTensor(node, kParams);
  TF_LITE_ENSURE(context, params != nullptr);
  TfLiteTensor* indices = micro_context->AllocateTempInputTensor(node, kIndices);
  TF_LITE_ENSURE(context, indices != nullptr);
  TfLiteTensor* output = micro_context->AllocateTempOutputTensor(node, kOutputTensor);
  TF_LITE_ENSURE(context, output != nullptr);

  switch (params->type) {
    case kTfLiteFloat32:
    case kTfLiteInt8:
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Params of type '%s' are not supported by gather_nd.", TfLiteTypeGetName(params->type));

      return kTfLiteError;
      break;
  }
  switch (indices->type) {
    case kTfLiteInt32:
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Indices of type '%s' are not supported by gather_nd.", TfLiteTypeGetName(indices->type));

      return kTfLiteError;
  }

  const int params_rank = NumDimensions(params);
  const int indices_rank = NumDimensions(indices);
  const int indices_nd = SizeOfDimension(indices, indices_rank - 1);
  if (params_rank < 1) {
    TF_LITE_KERNEL_LOG(context, "Params must be at least a vector.");
    return kTfLiteError;
  }
  if (indices_rank < 1) {
    TF_LITE_KERNEL_LOG(context, "Indices must be at least a vector.");
    return kTfLiteError;
  }
  if (indices_nd > params_rank) {
    TF_LITE_KERNEL_LOG( context, "Index innermost dimension length must be <= params rank.");
    return kTfLiteError;
  }
  if (indices_nd > MAX_INDICES_ND) {
    TF_LITE_KERNEL_LOG(context, "Index innermost dimension length must not exceed %d.", MAX_INDICES_ND);

    return kTfLiteError;
  }

  
  output->type = params->type;

  
  
  
  TfLiteIntArray* output_shape = output->dims;
  int output_index = 0;
  for (int i = 0; i < indices_rank - 1; ++i) {
    output_shape->data[output_index++] = indices->dims->data[i];
  }
  for (int i = indices_nd; i < params_rank; ++i) {
    output_shape->data[output_index++] = params->dims->data[i];
  }
  output_shape->size = output_index;

  micro_context->DeallocateTempTfLiteTensor(params);
  micro_context->DeallocateTempTfLiteTensor(indices);
  micro_context->DeallocateTempTfLiteTensor(output);
  return kTfLiteOk;
}

template <typename ParamsT, typename IndicesT> TfLiteStatus GatherNd(const TfLiteEvalTensor* params, const TfLiteEvalTensor* indices, TfLiteEvalTensor* output) {


  const int indices_dims = indices->dims->size;
  const int indices_nd = indices->dims->data[indices_dims - 1];
  const int params_dims = params->dims->size;
  const IndicesT* index_data = tflite::micro::GetTensorData<IndicesT>(indices);
  const ParamsT* param_data = tflite::micro::GetTensorData<ParamsT>(params);
  ParamsT* output_data = tflite::micro::GetTensorData<ParamsT>(output);

  int n_slices = 1;
  for (int i = 0; i < indices_dims - 1; ++i) {
    n_slices *= indices->dims->data[i];
  }

  
  
  int slice_size = 1;
  for (int i = indices_nd; i < params_dims; ++i) {
    slice_size *= params->dims->data[i];
  }

  int remain_flat_size = ElementCount(*params->dims);

  
  int dims_to_count[MAX_INDICES_ND];
  for (int i = 0; i < indices_nd; ++i) {
    dims_to_count[i] = remain_flat_size / params->dims->data[i];
    remain_flat_size = dims_to_count[i];
  }

  for (int i = 0; i < n_slices; ++i) {
    int from_pos = 0;
    for (int j = 0; j < indices_nd; ++j) {
      int offset = i * indices_nd + j;
      IndicesT index = index_data[offset];
      from_pos += index * dims_to_count[j];
    }
    std::memcpy(output_data + i * slice_size, param_data + from_pos, sizeof(ParamsT) * slice_size);
  }
  return kTfLiteOk;
}

template <typename IndicesT> TfLiteStatus EvalGatherNd(TfLiteContext* context, const TfLiteEvalTensor* params, const TfLiteEvalTensor* indices, TfLiteEvalTensor* output) {



  switch (params->type) {
    case kTfLiteFloat32:
      return GatherNd<float, IndicesT>(params, indices, output);
      break;
    case kTfLiteInt8:
      return GatherNd<int8_t, IndicesT>(params, indices, output);
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Params type '%s' are not supported by gather_nd.", TfLiteTypeGetName(params->type));

      return kTfLiteError;
  }
}

TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  const TfLiteEvalTensor* params = tflite::micro::GetEvalInput(context, node, kParams);
  const TfLiteEvalTensor* indices = tflite::micro::GetEvalInput(context, node, kIndices);
  TfLiteEvalTensor* output = tflite::micro::GetEvalOutput(context, node, kOutputTensor);

  switch (indices->type) {
    case kTfLiteInt32:
      return EvalGatherNd<int32_t>(context, params, indices, output);
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Indices of type '%s' are not supported by gather_nd.", TfLiteTypeGetName(indices->type));

      return kTfLiteError;
  }
}
}  

TfLiteRegistration Register_GATHER_ND() {
  return tflite::micro::RegisterOp(nullptr, Prepare, Eval);
}

}  
