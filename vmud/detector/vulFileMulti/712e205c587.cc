




















namespace tensorflow {
namespace {


constexpr int kMaxAttrValueTensorByteSize = 32 * 1024 * 1024;  



int64 TensorByteSize(const TensorProto& t) {
  
  int64 num_elems = TensorShape(t.tensor_shape()).num_elements();
  return num_elems < 0 ? -1 : num_elems * DataTypeSize(t.dtype());
}





uint64 TensorProtoHash(const TensorProto& tp) {
  Tensor tensor(tp.dtype());
  bool success = tensor.FromProto(tp);
  DCHECK(success);
  TensorProto p;
  tensor.AsProtoTensorContent(&p);
  return DeterministicProtoHash64(p);
}





uint64 FastTensorProtoHash(const TensorProto& tp) {
  if (TensorByteSize(tp) > kMaxAttrValueTensorByteSize) {
    return DeterministicProtoHash64(tp);
  } else {
    return TensorProtoHash(tp);
  }
}






bool AreTensorProtosEqual(const TensorProto& lhs, const TensorProto& rhs) {
  Tensor lhs_t(lhs.dtype());
  bool success = lhs_t.FromProto(lhs);
  DCHECK(success);

  Tensor rhs_t(rhs.dtype());
  success = rhs_t.FromProto(rhs);
  DCHECK(success);

  TensorProto lhs_tp;
  lhs_t.AsProtoTensorContent(&lhs_tp);

  TensorProto rhs_tp;
  rhs_t.AsProtoTensorContent(&rhs_tp);

  return AreSerializedProtosEqual(lhs_tp, rhs_tp);
}




bool FastAreTensorProtosEqual(const TensorProto& lhs, const TensorProto& rhs) {
  
  
  
  
  const int64 lhs_tensor_bytes = TensorByteSize(lhs);
  const int64 rhs_tensor_bytes = TensorByteSize(rhs);
  if (lhs_tensor_bytes != rhs_tensor_bytes) {
    return false;
  }

  
  
  
  if (lhs_tensor_bytes > kMaxAttrValueTensorByteSize) {
    return AreSerializedProtosEqual(lhs, rhs);
  }

  
  
  const int64 lhs_proto_bytes = lhs.ByteSizeLong();
  const bool large_expansion = (lhs_proto_bytes < 512 && lhs_tensor_bytes > 4096);
  if (large_expansion && AreSerializedProtosEqual(lhs, rhs)) {
    return true;
  }

  
  return AreTensorProtosEqual(lhs, rhs);
}

using TensorProtoHasher = std::function<uint64(const TensorProto&)>;

uint64 AttrValueHash(const AttrValue& a, const TensorProtoHasher& tensor_hash) {
  if (a.has_tensor()) return tensor_hash(a.tensor());

  if (a.has_func()) {
    const NameAttrList& func = a.func();
    uint64 h = Hash64(func.name());
    std::map<string, AttrValue> map(func.attr().begin(), func.attr().end());
    for (const auto& pair : map) {
      h = Hash64(pair.first.data(), pair.first.size(), h);
      h = Hash64Combine(AttrValueHash(pair.second, tensor_hash), h);
    }
    return h;
  }

  
  return DeterministicProtoHash64(a);
}

template <typename TensorProtosEquality> bool AreAttrValuesEqual(const AttrValue& a, const AttrValue& b, TensorProtosEquality tensor_equality) {

  if (a.type() != b.type()) {
    return false;
  } else if (a.type() != DT_INVALID && b.type() != DT_INVALID) {
    return a.type() == b.type();
  }

  if (a.has_tensor() != b.has_tensor()) {
    return false;
  } else if (a.has_tensor() && b.has_tensor()) {
    return tensor_equality(a.tensor(), b.tensor());
  }

  
  
  if (a.has_func() != b.has_func()) {
    return false;
  } else if (a.has_func() && b.has_func()) {
    const NameAttrList& af = a.func();
    const NameAttrList& bf = b.func();
    if (af.name() != bf.name()) return false;
    std::unordered_map<string, AttrValue> am(af.attr().begin(), af.attr().end());
    for (const auto& bm_pair : bf.attr()) {
      const auto& iter = am.find(bm_pair.first);
      if (iter == am.end()) return false;
      if (!AreAttrValuesEqual(iter->second, bm_pair.second, tensor_equality))
        return false;
      am.erase(iter);
    }
    if (!am.empty()) return false;
    return true;
  }

  
  
  return AreSerializedProtosEqual(a, b);
}

string SummarizeString(const string& str) {
  string escaped = absl::CEscape(str);

  
  constexpr int kMaxStringSummarySize = 80;
  if (escaped.size() >= kMaxStringSummarySize) {
    StringPiece prefix(escaped);
    StringPiece suffix = prefix;
    prefix.remove_suffix(escaped.size() - 10);
    suffix.remove_prefix(escaped.size() - 10);
    return strings::StrCat("\"", prefix, "...", suffix, "\"");
  } else {
    return strings::StrCat("\"", escaped, "\"");
  }
}

string SummarizeTensor(const TensorProto& tensor_proto) {
  Tensor t;
  if (!t.FromProto(tensor_proto)) {
    return strings::StrCat( "<Invalid TensorProto: ", tensor_proto.ShortDebugString(), ">");
  }
  return t.DebugString();
}

string SummarizeFunc(const NameAttrList& func) {
  std::vector<string> entries;
  for (const auto& p : func.attr()) {
    entries.push_back( strings::StrCat(p.first, "=", SummarizeAttrValue(p.second)));
  }
  std::sort(entries.begin(), entries.end());
  return strings::StrCat(func.name(), "[", absl::StrJoin(entries, ", "), "]");
}

}  

string SummarizeAttrValue(const AttrValue& attr_value) {
  switch (attr_value.value_case()) {
    case AttrValue::kS:
      return SummarizeString(attr_value.s());
    case AttrValue::kI:
      return strings::StrCat(attr_value.i());
    case AttrValue::kF:
      return strings::StrCat(attr_value.f());
    case AttrValue::kB:
      return attr_value.b() ? "true" : "false";
    case AttrValue::kType:
      return EnumName_DataType(attr_value.type());
    case AttrValue::kShape:
      return PartialTensorShape::DebugString(attr_value.shape());
    case AttrValue::kTensor:
      return SummarizeTensor(attr_value.tensor());
    case AttrValue::kList: {
      std::vector<string> pieces;
      if (attr_value.list().s_size() > 0) {
        for (int i = 0; i < attr_value.list().s_size(); ++i) {
          pieces.push_back(SummarizeString(attr_value.list().s(i)));
        }
      } else if (attr_value.list().i_size() > 0) {
        for (int i = 0; i < attr_value.list().i_size(); ++i) {
          pieces.push_back(strings::StrCat(attr_value.list().i(i)));
        }
      } else if (attr_value.list().f_size() > 0) {
        for (int i = 0; i < attr_value.list().f_size(); ++i) {
          pieces.push_back(strings::StrCat(attr_value.list().f(i)));
        }
      } else if (attr_value.list().b_size() > 0) {
        for (int i = 0; i < attr_value.list().b_size(); ++i) {
          pieces.push_back(attr_value.list().b(i) ? "true" : "false");
        }
      } else if (attr_value.list().type_size() > 0) {
        for (int i = 0; i < attr_value.list().type_size(); ++i) {
          pieces.push_back(EnumName_DataType(attr_value.list().type(i)));
        }
      } else if (attr_value.list().shape_size() > 0) {
        for (int i = 0; i < attr_value.list().shape_size(); ++i) {
          pieces.push_back( TensorShape::DebugString(attr_value.list().shape(i)));
        }
      } else if (attr_value.list().tensor_size() > 0) {
        for (int i = 0; i < attr_value.list().tensor_size(); ++i) {
          pieces.push_back(SummarizeTensor(attr_value.list().tensor(i)));
        }
      } else if (attr_value.list().func_size() > 0) {
        for (int i = 0; i < attr_value.list().func_size(); ++i) {
          pieces.push_back(SummarizeFunc(attr_value.list().func(i)));
        }
      }
      constexpr int kMaxListSummarySize = 50;
      if (pieces.size() >= kMaxListSummarySize) {
        pieces.erase(pieces.begin() + 5, pieces.begin() + (pieces.size() - 6));
        pieces[5] = "...";
      }
      return strings::StrCat("[", absl::StrJoin(pieces, ", "), "]");
    }
    case AttrValue::kFunc: {
      return SummarizeFunc(attr_value.func());
    }
    case AttrValue::kPlaceholder:
      return strings::StrCat("$", attr_value.placeholder());
    case AttrValue::VALUE_NOT_SET:
      return "<Unknown AttrValue type>";
  }
  return "<Unknown AttrValue type>";  
}

Status AttrValueHasType(const AttrValue& attr_value, StringPiece type) {
  int num_set = 0;





















  VALIDATE_FIELD(s, "string", kS);
  VALIDATE_FIELD(i, "int", kI);
  VALIDATE_FIELD(f, "float", kF);
  VALIDATE_FIELD(b, "bool", kB);
  VALIDATE_FIELD(type, "type", kType);
  VALIDATE_FIELD(shape, "shape", kShape);
  VALIDATE_FIELD(tensor, "tensor", kTensor);
  VALIDATE_FIELD(func, "func", kFunc);



  if (attr_value.value_case() == AttrValue::kPlaceholder) {
    return errors::InvalidArgument( "AttrValue had value with unexpected type 'placeholder'");
  }

  
  
  
  
  
  
  if (absl::StartsWith(type, "list(") && !attr_value.has_list()) {
    if (num_set) {
      return errors::InvalidArgument( "AttrValue missing value with expected type '", type, "'");
    } else {
      
      ++num_set;
    }
  }

  
  if (num_set == 0 && !absl::StartsWith(type, "list(")) {
    return errors::InvalidArgument( "AttrValue missing value with expected type '", type, "'");
  }

  
  
  if (type == "type") {
    if (!DataType_IsValid(attr_value.type())) {
      return errors::InvalidArgument("AttrValue has invalid DataType enum: ", attr_value.type());
    }
    if (IsRefType(attr_value.type())) {
      return errors::InvalidArgument( "AttrValue must not have reference type value of ", DataTypeString(attr_value.type()));

    }
    if (attr_value.type() == DT_INVALID) {
      return errors::InvalidArgument("AttrValue has invalid DataType");
    }
  } else if (type == "list(type)") {
    for (auto as_int : attr_value.list().type()) {
      const DataType dtype = static_cast<DataType>(as_int);
      if (!DataType_IsValid(dtype)) {
        return errors::InvalidArgument("AttrValue has invalid DataType enum: ", as_int);
      }
      if (IsRefType(dtype)) {
        return errors::InvalidArgument( "AttrValue must not have reference type value of ", DataTypeString(dtype));

      }
      if (dtype == DT_INVALID) {
        return errors::InvalidArgument("AttrValue contains invalid DataType");
      }
    }
  }

  return Status::OK();
}

bool ParseAttrValue(StringPiece type, StringPiece text, AttrValue* out) {
  
  string field_name;
  bool is_list = absl::ConsumePrefix(&type, "list(");
  if (absl::ConsumePrefix(&type, "string")) {
    field_name = "s";
  } else if (absl::ConsumePrefix(&type, "int")) {
    field_name = "i";
  } else if (absl::ConsumePrefix(&type, "float")) {
    field_name = "f";
  } else if (absl::ConsumePrefix(&type, "bool")) {
    field_name = "b";
  } else if (absl::ConsumePrefix(&type, "type")) {
    field_name = "type";
  } else if (absl::ConsumePrefix(&type, "shape")) {
    field_name = "shape";
  } else if (absl::ConsumePrefix(&type, "tensor")) {
    field_name = "tensor";
  } else if (absl::ConsumePrefix(&type, "func")) {
    field_name = "func";
  } else if (absl::ConsumePrefix(&type, "placeholder")) {
    field_name = "placeholder";
  } else {
    return false;
  }
  if (is_list && !absl::ConsumePrefix(&type, ")")) {
    return false;
  }

  
  string to_parse;
  if (is_list) {
    
    
    StringPiece cleaned = text;
    str_util::RemoveLeadingWhitespace(&cleaned);
    str_util::RemoveTrailingWhitespace(&cleaned);
    if (cleaned.size() < 2 || cleaned[0] != '[' || cleaned[cleaned.size() - 1] != ']') {
      return false;
    }
    cleaned.remove_prefix(1);
    str_util::RemoveLeadingWhitespace(&cleaned);
    if (cleaned.size() == 1) {
      
      
      out->Clear();
      out->mutable_list();
      return true;
    }
    to_parse = strings::StrCat("list { ", field_name, ": ", text, " }");
  } else {
    to_parse = strings::StrCat(field_name, ": ", text);
  }

  return ProtoParseFromString(to_parse, out);
}

void SetAttrValue(const AttrValue& value, AttrValue* out) { *out = value; }













DEFINE_SET_ATTR_VALUE_ONE(const string&, s)
DEFINE_SET_ATTR_VALUE_LIST(gtl::ArraySlice<string>, s)
DEFINE_SET_ATTR_VALUE_BOTH(const char*, s)
DEFINE_SET_ATTR_VALUE_BOTH(int64, i)
DEFINE_SET_ATTR_VALUE_BOTH(int32, i)
DEFINE_SET_ATTR_VALUE_BOTH(float, f)
DEFINE_SET_ATTR_VALUE_BOTH(double, f)
DEFINE_SET_ATTR_VALUE_BOTH(bool, b)
DEFINE_SET_ATTR_VALUE_LIST(const std::vector<bool>&, b)
DEFINE_SET_ATTR_VALUE_LIST(std::initializer_list<bool>, b)
DEFINE_SET_ATTR_VALUE_BOTH(DataType, type)

void SetAttrValue(const tstring& value, AttrValue* out) {
  out->set_s(value.data(), value.size());
}

void SetAttrValue(gtl::ArraySlice<tstring> value, AttrValue* out) {
  out->mutable_list()->Clear();
  for (const auto& v : value) {
    out->mutable_list()->add_s(v.data(), v.size());
  }
}

void SetAttrValue(StringPiece value, AttrValue* out) {
  out->set_s(value.data(), value.size());
}

void SetAttrValue(const gtl::ArraySlice<StringPiece> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    out->mutable_list()->add_s(v.data(), v.size());
  }
}

void MoveAttrValue(std::vector<string>&& value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (auto& v : value) {
    out->mutable_list()->add_s(std::move(v));
  }
}

void SetAttrValue(const TensorShape& value, AttrValue* out) {
  value.AsProto(out->mutable_shape());
}

void SetAttrValue(const TensorShapeProto& value, AttrValue* out) {
  *out->mutable_shape() = value;
}

void SetAttrValue(const PartialTensorShape& value, AttrValue* out) {
  value.AsProto(out->mutable_shape());
}

void SetAttrValue(const gtl::ArraySlice<TensorShape> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    v.AsProto(out->mutable_list()->add_shape());
  }
}

void SetAttrValue(gtl::ArraySlice<TensorShapeProto> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    *out->mutable_list()->add_shape() = v;
  }
}

void SetAttrValue(const gtl::ArraySlice<PartialTensorShape> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    v.AsProto(out->mutable_list()->add_shape());
  }
}

void SetAttrValue(const Tensor& value, AttrValue* out) {
  if (value.NumElements() > 1) {
    value.AsProtoTensorContent(out->mutable_tensor());
  } else {
    value.AsProtoField(out->mutable_tensor());
  }
}

void SetAttrValue(const gtl::ArraySlice<Tensor> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    if (v.NumElements() > 1) {
      v.AsProtoTensorContent(out->mutable_list()->add_tensor());
    } else {
      v.AsProtoField(out->mutable_list()->add_tensor());
    }
  }
}

void SetAttrValue(const TensorProto& value, AttrValue* out) {
  *out->mutable_tensor() = value;
}

void SetAttrValue(const gtl::ArraySlice<TensorProto> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    *out->mutable_list()->add_tensor() = v;
  }
}

void SetAttrValue(const NameAttrList& value, AttrValue* out) {
  *out->mutable_func() = value;
}

void SetAttrValue(gtl::ArraySlice<NameAttrList> value, AttrValue* out) {
  out->mutable_list()->Clear();  
  for (const auto& v : value) {
    *out->mutable_list()->add_func() = v;
  }
}

bool AreAttrValuesEqual(const AttrValue& a, const AttrValue& b) {
  return AreAttrValuesEqual(a, b, AreTensorProtosEqual);
}

uint64 AttrValueHash(const AttrValue& a) {
  return AttrValueHash(a, TensorProtoHash);
}

bool FastAreAttrValuesEqual(const AttrValue& a, const AttrValue& b) {
  return AreAttrValuesEqual(a, b, FastAreTensorProtosEqual);
}

uint64 FastAttrValueHash(const AttrValue& a) {
  return AttrValueHash(a, FastTensorProtoHash);
}

bool HasPlaceHolder(const AttrValue& val) {
  switch (val.value_case()) {
    case AttrValue::kList: {
      for (const NameAttrList& func : val.list().func()) {
        for (const auto& p : func.attr()) {
          if (HasPlaceHolder(p.second)) {
            return true;
          }
        }
      }
      break;
    }
    case AttrValue::kFunc:
      for (const auto& p : val.func().attr()) {
        if (HasPlaceHolder(p.second)) {
          return true;
        }
      }
      break;
    case AttrValue::kPlaceholder:
      return true;
    default:
      break;
  }
  return false;
}

bool SubstitutePlaceholders(const SubstituteFunc& substitute, AttrValue* value) {
  switch (value->value_case()) {
    case AttrValue::kList: {
      for (NameAttrList& func : *value->mutable_list()->mutable_func()) {
        for (auto& p : *func.mutable_attr()) {
          if (!SubstitutePlaceholders(substitute, &p.second)) {
            return false;
          }
        }
      }
      break;
    }
    case AttrValue::kFunc:
      for (auto& p : *(value->mutable_func()->mutable_attr())) {
        if (!SubstitutePlaceholders(substitute, &p.second)) {
          return false;
        }
      }
      break;
    case AttrValue::kPlaceholder:
      return substitute(value->placeholder(), value);
    case AttrValue::VALUE_NOT_SET:
      return false;
    default:
      break;
  }
  return true;
}

}  
