








#include<map>





#include<functional>





#include<iterator>




#include<cstddef>



#include<x86intrin.h>





#include<tuple>


#include<condition_variable>

#include<malloc.h>












#include<algorithm>

#include<deque>
#include<signal.h>






#include<vector>
#include<cstdlib>
#include<utility>
#include<thread>









#include<system_error>



#include<limits>






#include<cstring>




#include<chrono>




#include<atomic>









#include<new>

#include<cstdint>





#include<optional>



#include<memory>
#include<mutex>




#include<random>

#include<type_traits>



#include<string>
#include<cmath>









#include<bitset>








#include<future>





#include<sstream>






#include<list>

#include<cassert>





#include<unistd.h>





#include<array>











#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))


#define TsanBenignRaceSized(address, size, description)


#define TsanIgnoreWritesBegin() AnnotateIgnoreWritesBegin("__FILE__", "__LINE__")
#define TsanIgnoreWritesEnd() AnnotateIgnoreWritesEnd("__FILE__", "__LINE__")
#define TsanThreadName(name) AnnotateThreadName("__FILE__", "__LINE__", name)

#define HERMESVM_CRASH_TRACE 0

#define PROP_CACHE_IDS(V) V(RegExpLastIndex, Predefined::lastIndex)
#define RUNTIME_HV_FIELD(name) PinnedHermesValue name{};
#define RUNTIME_HV_FIELD_INSTANCE(name) RUNTIME_HV_FIELD(name)
#define RUNTIME_HV_FIELD_PROTOTYPE(name) RUNTIME_HV_FIELD(name)
#define RUNTIME_HV_FIELD_RUNTIMEMODULE(name) RUNTIME_HV_FIELD(name)
#define V(id, predef) id,









#define HERMES_VM_GCOBJECT(name) \
  class name;                    \
  template <>                    \
  struct IsGCObject<name> : public std::true_type {}

#define CELL_KIND(name) name##Kind,
#define CELL_RANGE(rangeName, first, last) \
  rangeName##Kind_first = first##Kind, rangeName##Kind_last = last##Kind,













#define ROOT_SECTION(name) name,




#define V8_EDGE_FIELD(label, type) +1
#define V8_EDGE_TYPE(enumerand, label) enumerand,
#define V8_LOCATION_FIELD(label) +1
#define V8_NODE_FIELD(label, type) +1
#define V8_NODE_TYPE(enumerand, label) enumerand,
#define V8_SAMPLE_FIELD(label) +1
#define V8_SNAPSHOT_SECTION(enumerand, label) enumerand,



#define GC_KIND(kind)          \
  case GCBase::HeapKind::kind: \
    return f(llvh::cast<kind>(this));

#define ROOT_SECTION(name) name,
#define RUNTIME_GC_KINDS GC_KIND(HadesGC)




#define SLOT_TYPE(type)              \
  for (; i < offsets.end##type; ++i) \
    visitSlot<type>(base + offsets.fields[i]);






#define STDERR_FILENO 2
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

#define HERMES_EXTRA_DEBUG(x) x


#define DEFINE_OPCODE(name) name,
#define DEFINE_OPCODE_0(name) LLVM_PACKED(struct name##Inst { OpCode opCode; });
#define DEFINE_OPCODE_1(name, op1type) \
  LLVM_PACKED(struct name##Inst {      \
    OpCode opCode;                     \
    Operand##op1type op1;              \
  });
#define DEFINE_OPCODE_2(name, op1type, op2type) \
  LLVM_PACKED(struct name##Inst {               \
    OpCode opCode;                              \
    Operand##op1type op1;                       \
    Operand##op2type op2;                       \
  });
#define DEFINE_OPCODE_3(name, op1type, op2type, op3type) \
  LLVM_PACKED(struct name##Inst {                        \
    OpCode opCode;                                       \
    Operand##op1type op1;                                \
    Operand##op2type op2;                                \
    Operand##op3type op3;                                \
  });
#define DEFINE_OPCODE_4(name, op1type, op2type, op3type, op4type) \
  LLVM_PACKED(struct name##Inst {                                 \
    OpCode opCode;                                                \
    Operand##op1type op1;                                         \
    Operand##op2type op2;                                         \
    Operand##op3type op3;                                         \
    Operand##op4type op4;                                         \
  });
#define DEFINE_OPCODE_5(name, op1type, op2type, op3type, op4type, op5type) \
  LLVM_PACKED(struct name##Inst {                                          \
    OpCode opCode;                                                         \
    Operand##op1type op1;                                                  \
    Operand##op2type op2;                                                  \
    Operand##op3type op3;                                                  \
    Operand##op4type op4;                                                  \
    Operand##op5type op5;                                                  \
  });
#define DEFINE_OPCODE_6(                                        \
    name, op1type, op2type, op3type, op4type, op5type, op6type) \
  LLVM_PACKED(struct name##Inst {                               \
    OpCode opCode;                                              \
    Operand##op1type op1;                                       \
    Operand##op2type op2;                                       \
    Operand##op3type op3;                                       \
    Operand##op4type op4;                                       \
    Operand##op5type op5;                                       \
    Operand##op6type op6;                                       \
  });
#define DEFINE_OPERAND_TYPE(name, type) typedef type Operand##name;



#define _HERMESVM_DEFINE_STACKFRAME_REF(name) \
  LLVM_ATTRIBUTE_ALWAYS_INLINE                \
  QualifiedHV &get##name##Ref() const {       \
    return frame_[StackFrameLayout::name];    \
  }

#define HERMESVM_DEBUG_MAX_GCSCOPE_HANDLES 48



















#define HERMES_SLOW_ASSERT(x) assert(x)

#define SLOW_DEBUG(x) LLVM_DEBUG(x)





#define HERMESVM_RDTSC() __rdtsc()

#define INC_OPCODE_COUNT ++runtime.opcodeCount
#define INIT_OPCODE_PROFILER      \
  uint64_t startTime = __rdtsc(); \
  unsigned curOpcode = (unsigned)OpCode::Call;


#define RECORD_OPCODE_START_TIME               \
  curOpcode = (unsigned)ip->opCode;            \
  runtime.opcodeExecuteFrequency[curOpcode]++; \
  startTime = __rdtsc();
#define UPDATE_OPCODE_TIME_SPENT \
  runtime.timeSpent[curOpcode] += __rdtsc() - startTime
#define HEADER_FIELD_ACCESSOR(api_type, store_type, name, bits) \
  api_type name() const {                                       \
    if (LLVM_UNLIKELY(isLarge()))                               \
      return asLarge()->name;                                   \
    else                                                        \
      return asSmall()->name;                                   \
  }













#define PUNCTUATOR(name, str) \
  case TokenKind::name:       \
    return true;
#define TOK(name, str) name,






#define WARNING_CATEGORY_HIDDEN(name, specifier, description) name,

#define HERMES_PARSE_FLOW 0
#define HERMES_PARSE_JSX 0
#define HERMES_PARSE_TS 0





#define CHECK_COPY_FIELD(api_type, store_type, name, bits) \
  if (large.name > (1U << bits) - 1) {                     \
    setLargeHeaderOffset(large.infoOffset);                \
    return;                                                \
  }                                                        \
  name = large.name;
#define DECLARE_BITFIELD(api_type, store_type, name, bits) \
  store_type name : bits;
#define DECLARE_FIELD(api_type, store_type, name, bits) api_type name;
#define FUNC_HEADER_FIELDS(V)                    \
                                 \
  V(uint32_t, uint32_t, offset, 25)              \
  V(uint32_t, uint32_t, paramCount, 7)           \
                                \
  V(uint32_t, uint32_t, bytecodeSizeInBytes, 15) \
  V(uint32_t, uint32_t, functionName, 17)        \
                                 \
  V(uint32_t, uint32_t, infoOffset, 25)          \
  V(uint32_t, uint32_t, frameSize, 7)            \
              \
  V(uint32_t, uint8_t, environmentSize, 8)       \
  V(uint8_t, uint8_t, highestReadCacheIndex, 8)  \
  V(uint8_t, uint8_t, highestWriteCacheIndex, 8)






#define HERMESVM_SAMPLING_PROFILER_AVAILABLE 0




#define NAMED_PROP(name) InternalProperty##name,
#define PROP(i) InternalProperty##i,
#define STR(name, string) name,
#define SYM(name, desc) name,




#define GC_KIND(kind) sizeof(kind),




#define DEFINE_OPCODE(name) name##Op,
#define DEFINE_OPCODE_0(name)        \
  offset_t emit##name() {            \
    auto loc = emitOpcode(name##Op); \
    return loc;                      \
  };
#define DEFINE_OPCODE_1(name, t1)    \
  offset_t emit##name(param_t p1) {  \
    auto loc = emitOpcode(name##Op); \
    emit##t1(p1);                    \
    return loc;                      \
  };
#define DEFINE_OPCODE_2(name, t1, t2)           \
  offset_t emit##name(param_t p1, param_t p2) { \
    auto loc = emitOpcode(name##Op);            \
    emit##t1(p1);                               \
    emit##t2(p2);                               \
    return loc;                                 \
  };
#define DEFINE_OPCODE_3(name, t1, t2, t3)                   \
  offset_t emit##name(param_t p1, param_t p2, param_t p3) { \
    auto loc = emitOpcode(name##Op);                        \
    emit##t1(p1);                                           \
    emit##t2(p2);                                           \
    emit##t3(p3);                                           \
    return loc;                                             \
  };
#define DEFINE_OPCODE_4(name, t1, t2, t3, t4)                           \
  offset_t emit##name(param_t p1, param_t p2, param_t p3, param_t p4) { \
    auto loc = emitOpcode(name##Op);                                    \
    emit##t1(p1);                                                       \
    emit##t2(p2);                                                       \
    emit##t3(p3);                                                       \
    emit##t4(p4);                                                       \
    return loc;                                                         \
  };
#define DEFINE_OPCODE_5(name, t1, t2, t3, t4, t5)                   \
  offset_t emit##name(                                              \
      param_t p1, param_t p2, param_t p3, param_t p4, param_t p5) { \
    auto loc = emitOpcode(name##Op);                                \
    emit##t1(p1);                                                   \
    emit##t2(p2);                                                   \
    emit##t3(p3);                                                   \
    emit##t4(p4);                                                   \
    emit##t5(p5);                                                   \
    return loc;                                                     \
  };
#define DEFINE_OPCODE_6(name, t1, t2, t3, t4, t5, t6) \
  offset_t emit##name(                                \
      param_t p1,                                     \
      param_t p2,                                     \
      param_t p3,                                     \
      param_t p4,                                     \
      param_t p5,                                     \
      param_t p6) {                                   \
    auto loc = emitOpcode(name##Op);                  \
    emit##t1(p1);                                     \
    emit##t2(p2);                                     \
    emit##t3(p3);                                     \
    emit##t4(p4);                                     \
    emit##t5(p5);                                     \
    emit##t6(p6);                                     \
    return loc;                                       \
  };
#define DEFINE_OPERAND_TYPE(name, ctype)                  \
  void emit##name(param_t value) {                        \
    encodingError_ |= ((param_t)(ctype)value) != value && \
        !std::is_floating_point<ctype>::value;            \
    emitOperand(value, sizeof(ctype));                    \
  }






#define HERMES_VM__LIST_OwnKeysFlags(FLAG) \
  FLAG(IncludeSymbols)                     \
  FLAG(IncludeNonSymbols)                  \
  FLAG(IncludeNonEnumerable)
#define HERMES_VM__LIST_PropOpFlags(FLAG) \
  FLAG(ThrowOnError)                      \
  FLAG(MustExist)                         \
  FLAG(InternalForce)

#define HERMES_VM__DECLARE_FLAGS_CLASS(ClassName, listMacro) \
  union ClassName {                                          \
   private:                                                  \
    struct {                                                 \
      listMacro(_HERMES_VM__DECL_FLAG)                       \
    };                                                       \
    unsigned flags_ = 0;                                     \
                                                             \
   public:                                                   \
    typedef ClassName Self;                                  \
    unsigned getRaw() const {                                \
      return flags_;                                         \
    }                                                        \
    listMacro(_HERMES_VM__IMPL_FLAG)                         \
  }
#define _HERMES_VM__DECL_FLAG(name) bool f##name##_ : 1;
#define _HERMES_VM__IMPL_FLAG(name) \
  Self plus##name() const {         \
    auto r(*this);                  \
    r.f##name##_ = true;            \
    return r;                       \
  }                                 \
  Self minus##name() const {        \
    auto r(*this);                  \
    r.f##name##_ = false;           \
    return r;                       \
  }                                 \
  Self set##name(bool v) const {    \
    auto r(*this);                  \
    r.f##name##_ = v;               \
    return r;                       \
  }                                 \
  bool get##name() const {          \
    return f##name##_;              \
  }




















#define REOP(code) code,











#define BUILTIN_METHOD(object, name) object##_##name,

#define JS_BUILTIN(name) PRIVATE_BUILTIN(name)
#define MARK_FIRST_JS_BUILTIN(name) _firstJS = JS_BUILTIN(name)
#define MARK_FIRST_PRIVATE_BUILTIN(name) _firstPrivate = PRIVATE_BUILTIN(name)
#define PRIVATE_BUILTIN(name) BUILTIN_METHOD(HermesBuiltin, name)

#define ALL_ERROR_TYPE(name) \
  Handle<JSObject> create##name##Constructor(Runtime &runtime);

#define TYPED_ARRAY(name, type) \
  Handle<JSObject> create##name##ArrayConstructor(Runtime &runtime);



#define NATIVE_FUNCTION(func) \
  CallResult<HermesValue> func(void *, Runtime &, NativeArgs);




