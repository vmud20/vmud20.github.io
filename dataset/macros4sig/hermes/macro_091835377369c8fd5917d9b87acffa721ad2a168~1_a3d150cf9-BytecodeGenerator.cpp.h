#include<cassert>




#include<unordered_map>


#include<cstddef>
#include<deque>






#include<malloc.h>

#include<climits>


#include<iterator>
#include<atomic>
#include<cstdint>


#include<map>
#include<signal.h>
#include<memory>

#include<utility>


#include<locale>
#include<system_error>


#include<vector>








#include<cstdlib>
#include<functional>

#include<cstring>
#include<algorithm>

#include<array>


#include<unistd.h>



#include<thread>




#include<string>





#include<cmath>


#include<sstream>



#include<chrono>







#include<type_traits>












#define STDERR_FILENO 2
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define BUILTIN_METHOD(object, name) object##_##name,

#define MARK_FIRST_PRIVATE_BUILTIN(name) _firstPrivate = PRIVATE_BUILTIN(name)
#define PRIVATE_BUILTIN(name) BUILTIN_METHOD(HermesBuiltin, name)




#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))


#define TsanBenignRaceSized(address, size, description)
#define TsanIgnoreReadsBegin() AnnotateIgnoreReadsBegin("__FILE__", "__LINE__")


#define DEFINE_JUMP_LONG_VARIANT(shortName, longName) \
  case longName##Op:                                  \
    opcodes_[loc] = shortName##Op;                    \
    break;



#define BIT_TO_VAL(XX) (1 << TypeKind::XX)
#define DEF_VALUE(CLASS, PARENT) CLASS##Kind,


#define IS_VAL(XX) (bitmask_ == (1 << TypeKind::XX))
#define MARK_FIRST(CLASS) First_##CLASS##Kind,
#define MARK_LAST(CLASS) Last_##CLASS##Kind,
#define MARK_VALUE(CLASS) CLASS##Kind,
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




#define HERMES_EXTRA_DEBUG(x) x














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
#define DEFINE_OPERAND_TYPE(name, ctype)          \
  void emit##name(param_t value) {                \
    assert(                                       \
        (((param_t)(ctype)value) == value ||      \
         std::is_floating_point<ctype>::value) && \
        "Value does not fit in " #ctype);         \
    emitOperand(value, sizeof(ctype));            \
  }

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

#define HERMES_PARSE_FLOW 0
#define HERMES_PARSE_JSX 0







