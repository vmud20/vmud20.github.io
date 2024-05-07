#include<map>
#include<optional>

#include<cstddef>


#include<cassert>


#include<system_error>





#include<memory>



#include<cmath>



#include<array>








#include<climits>









#include<functional>




#include<sstream>
#include<unordered_map>

#include<cstdlib>
#include<signal.h>

#include<string>
#include<atomic>









#include<cstdint>




#include<utility>





#include<algorithm>
#include<vector>


#include<cstring>

#include<malloc.h>



#include<limits>









#include<thread>




#include<iterator>





#include<chrono>







#include<unistd.h>

#include<type_traits>
#include<deque>
#define HERMES_SLOW_STATISTIC(Name, Desc) STATISTIC(Name, Desc)

#define STATISTIC(Name, Desc) static hermes::DummyCounter Name;

#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))


#define TsanBenignRaceSized(address, size, description)


#define TsanIgnoreWritesBegin() AnnotateIgnoreWritesBegin("__FILE__", "__LINE__")
#define TsanIgnoreWritesEnd() AnnotateIgnoreWritesEnd("__FILE__", "__LINE__")
#define TsanThreadName(name) AnnotateThreadName("__FILE__", "__LINE__", name)



#define STDERR_FILENO 2
#define STDIN_FILENO 0
#define STDOUT_FILENO 1







#define PUNCTUATOR(name, str) \
  case TokenKind::name:       \
    return true;
#define TOK(name, str) name,





#define HERMES_EXTRA_DEBUG(x) x



#define WARNING_CATEGORY_HIDDEN(name, specifier, description) name,

#define HERMES_PARSE_FLOW 0
#define HERMES_PARSE_JSX 0
#define HERMES_PARSE_TS 0

#define BIT_TO_VAL(XX) (1 << TypeKind::XX)
#define DEF_VALUE(CLASS, PARENT) CLASS##Kind,


#define IS_VAL(XX) (bitmask_ == (1 << TypeKind::XX))
#define MARK_FIRST(CLASS) First_##CLASS##Kind,
#define MARK_LAST(CLASS) Last_##CLASS##Kind,
#define MARK_VALUE(CLASS) CLASS##Kind,
#define NUM_BIT_TO_VAL(XX) (1 << NumTypeKind::XX)
#define NUM_IS_VAL(XX) (numBitmask_ == (1 << NumTypeKind::XX))
#define ESTREE_FIRST(NAME, ...) class NAME##Node;
#define ESTREE_LAST(NAME) _##NAME##_Last,
#define ESTREE_NODE_0_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_1_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_2_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_3_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_4_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_5_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_6_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_7_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_8_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;









#define WASM_INTRINSICS(name, numArgs) __uasm##_##name,
#define BUILTIN_METHOD(object, name) object##_##name,

#define JS_BUILTIN(name) PRIVATE_BUILTIN(name)
#define MARK_FIRST_JS_BUILTIN(name) _firstJS = JS_BUILTIN(name)
#define MARK_FIRST_PRIVATE_BUILTIN(name) _firstPrivate = PRIVATE_BUILTIN(name)
#define PRIVATE_BUILTIN(name) BUILTIN_METHOD(HermesBuiltin, name)






#define HEADER_FIELD_ACCESSOR(api_type, store_type, name, bits) \
  api_type name() const {                                       \
    if (LLVM_UNLIKELY(isLarge()))                               \
      return asLarge()->name;                                   \
    else                                                        \
      return asSmall()->name;                                   \
  }











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

#define DEFINE_JUMP_LONG_VARIANT(shortName, longName) \
  case longName##Op:                                  \
    opcodes_[loc] = shortName##Op;                    \
    break;




#define DEBUG_TYPE "passmanager"

#define PASS(ID, NAME, DESCRIPTION) \
  void add##ID() {                  \
    Pass *P = hermes::create##ID(); \
    pipeline.push_back(P);          \
  }


#define DEF_VALUE(CLASS, PARENT) \
  void generate##CLASS(CLASS *Inst, BasicBlock *next);





