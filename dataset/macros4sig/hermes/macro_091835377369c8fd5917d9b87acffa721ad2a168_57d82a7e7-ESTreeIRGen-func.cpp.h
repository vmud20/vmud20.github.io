
#include<cassert>






#include<memory>

#include<unordered_map>
#include<utility>



#include<system_error>


#include<deque>







#include<vector>






#include<string>





#include<type_traits>



#include<cstdlib>


#include<climits>






#include<cstdint>
#define DEBUG_TYPE "irgen"




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





#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))


#define TsanBenignRaceSized(address, size, description)
#define TsanIgnoreReadsBegin() AnnotateIgnoreReadsBegin("__FILE__", "__LINE__")






#define BUILTIN_METHOD(object, name) object##_##name,

#define MARK_FIRST_PRIVATE_BUILTIN(name) _firstPrivate = PRIVATE_BUILTIN(name)
#define PRIVATE_BUILTIN(name) BUILTIN_METHOD(HermesBuiltin, name)



