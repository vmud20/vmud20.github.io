




#include<climits>

#include<tuple>
#include<iostream>
#include<initializer_list>
#include<cstring>



#include<fstream>
#include<unordered_map>

#include<functional>




#include<string>
#include<sstream>


#include<ctype.h>
#include<iterator>

#include<memory>
#include<sys/stat.h>

#include<limits>


#include<ostream>
#include<vector>

#include<unordered_set>
#include<mutex>
#include<stdexcept>

#include<set>

#define ONNX_API ONNX_EXPORT
#define ONNX_EXPORT __declspec(dllexport)
#define ONNX_IMPORT __declspec(dllimport)

#define ATTR_SETTER_WITH_DEFAULT_VALUE(TypeName)                                                                    \
  OpSchema& Attr(                                                                                                   \
      std::string name, std::string description, AttributeProto::AttributeType type, const TypeName& defaultValue); \
                                                                         \
  OpSchema& Attr(                                                                                                   \
      const char* name, const char* description, AttributeProto::AttributeType type, const TypeName& defaultValue); \
  OpSchema& Attr(                                                                                                   \
      std::string name,                                                                                             \
      std::string description,                                                                                      \
      AttributeProto::AttributeType type,                                                                           \
      const std::vector<TypeName>& defaultValue);
#define GET_OP_DOC_STR(doc_str) (doc_str)
#define ONNX_DBG_GET_COUNT_IN_OPSETS() DbgOperatorSetTracker::Instance().GetCount()
#define ONNX_DBG_INCREMENT_COUNT_IN_OPSETS() 0
#define ONNX_ML_OPERATOR_SET_SCHEMA(name, ver, impl) \
  ONNX_OPERATOR_SET_SCHEMA_EX(name, OnnxML, AI_ONNX_ML_DOMAIN, ver, true, impl)
#define ONNX_OPERATOR_SCHEMA(name) ONNX_OPERATOR_SCHEMA_UNIQ_HELPER(__COUNTER__, name)
#define ONNX_OPERATOR_SCHEMA_UNIQ(Counter, name)                                                                      \
  static ONNX_NAMESPACE::OpSchemaRegistry::OpSchemaRegisterOnce(op_schema_register_once##name##Counter) ONNX_UNUSED = \
      OpSchema(#name, "__FILE__", "__LINE__")
#define ONNX_OPERATOR_SCHEMA_UNIQ_HELPER(Counter, name) ONNX_OPERATOR_SCHEMA_UNIQ(Counter, name)
#define ONNX_OPERATOR_SET_SCHEMA(name, ver, impl) ONNX_OPERATOR_SET_SCHEMA_EX(name, Onnx, ONNX_DOMAIN, ver, true, impl)
#define ONNX_OPERATOR_SET_SCHEMA_CLASS_NAME(domain, ver, name) name##_##domain##_ver##ver
#define ONNX_OPERATOR_SET_SCHEMA_EX(name, domain, domain_str, ver, dbg_included_in_static_opset, impl)  \
  class ONNX_OPERATOR_SET_SCHEMA_CLASS_NAME(domain, ver, name);                                         \
  template <>                                                                                           \
  OpSchema GetOpSchema<ONNX_OPERATOR_SET_SCHEMA_CLASS_NAME(domain, ver, name)>() {                      \
    return impl.SetName(#name).SetDomain(domain_str).SinceVersion(ver).SetLocation("__FILE__", "__LINE__"); \
  }                                                                                                     \
  size_t dbg_count_check_##name##_##domain##_ver##ver =                                                 \
      (dbg_included_in_static_opset) ? ONNX_DBG_INCREMENT_COUNT_IN_OPSETS() : 0;
#define ONNX_PREVIEW_OPERATOR_SET_SCHEMA_CLASS_NAME(ver, name) \
  ONNX_OPERATOR_SET_SCHEMA_CLASS_NAME(OnnxPreview, ver, name)
#define ONNX_PREVIEW_TRAINING_OPERATOR_SET_SCHEMA(name, ver, impl) \
  ONNX_OPERATOR_SET_SCHEMA_EX(name, OnnxPreview, AI_ONNX_PREVIEW_TRAINING_DOMAIN, ver, true, impl)
#define ONNX_TRAINING_OPERATOR_SET_SCHEMA(name, ver, impl) \
  ONNX_OPERATOR_SET_SCHEMA_EX(name, OnnxTraining, AI_ONNX_TRAINING_DOMAIN, ver, true, impl)
#define ONNX_UNUSED __attribute__((__unused__))
#define POPULATE_OP_DOC_STR(DocPopulatorCode) \
  do {                                        \
    DocPopulatorCode                          \
  } while (0)
#define fail_schema(...) ONNX_THROW_EX(ONNX_NAMESPACE::SchemaError(ONNX_NAMESPACE::MakeString(__VA_ARGS__)));
#define fail_shape_inference(...) \
  ONNX_THROW_EX(ONNX_NAMESPACE::InferenceError(ONNX_NAMESPACE::MakeString("[ShapeInferenceError] ", __VA_ARGS__)));
#define fail_type_inference(...) \
  ONNX_THROW_EX(ONNX_NAMESPACE::InferenceError(ONNX_NAMESPACE::MakeString("[TypeInferenceError] ", __VA_ARGS__)));

#define ONNX_CATCH(x) else if (false)

#define ONNX_THROW(...)                                   \
  do {                                                    \
    std::cerr << ONNX_NAMESPACE::MakeString(__VA_ARGS__); \
    abort();                                              \
  } while (false)
#define ONNX_THROW_EX(ex)                \
  do {                                   \
    std::cerr << ex.what() << std::endl; \
    abort();                             \
  } while (false)
#define ONNX_TRY if (true)
#define ONNX_UNUSED_PARAMETER(x) (void)(x)
#define CHECK_PARSER_STATUS(status) \
  {                                 \
    auto local_status_ = status;    \
    if (!local_status_.IsOK())      \
      return local_status_;         \
  }
#define fail_check(...) \
  ONNX_THROW_EX(ONNX_NAMESPACE::checker::ValidationError(ONNX_NAMESPACE::MakeString(__VA_ARGS__)));
