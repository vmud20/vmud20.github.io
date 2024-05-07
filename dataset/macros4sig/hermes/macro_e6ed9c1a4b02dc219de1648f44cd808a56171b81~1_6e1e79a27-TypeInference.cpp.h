
#include<cassert>











#include<memory>








#include<string>

#include<cstdint>

#include<vector>
#include<limits>





#include<cstdlib>



#include<climits>
#include<deque>



#include<system_error>



#include<type_traits>


#include<utility>




#include<unordered_map>




#define HERMES_SLOW_STATISTIC(Name, Desc) STATISTIC(Name, Desc)

#define STATISTIC(Name, Desc) static hermes::DummyCounter Name;




#define WASM_INTRINSICS(name, numArgs) __uasm##_##name,
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
#define ESTREE_NODE_9_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;




#define HERMES_EXTRA_DEBUG(x) x




#define WARNING_CATEGORY_HIDDEN(name, specifier, description) name,


#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))
#define HERMES_EMPTY_BASES __declspec(empty_bases)


#define TsanBenignRaceSized(address, size, description) \
  AnnotateBenignRaceSized("__FILE__", "__LINE__", address, size, description)


#define TsanIgnoreWritesBegin() AnnotateIgnoreWritesBegin("__FILE__", "__LINE__")
#define TsanIgnoreWritesEnd() AnnotateIgnoreWritesEnd("__FILE__", "__LINE__")
#define TsanThreadName(name) AnnotateThreadName("__FILE__", "__LINE__", name)







#define BUILTIN_METHOD(object, name) object##_##name,

#define JS_BUILTIN(name) PRIVATE_BUILTIN(name)
#define MARK_FIRST_JS_BUILTIN(name) _firstJS = JS_BUILTIN(name)
#define MARK_FIRST_PRIVATE_BUILTIN(name) _firstPrivate = PRIVATE_BUILTIN(name)
#define PRIVATE_BUILTIN(name) BUILTIN_METHOD(HermesBuiltin, name)





#define PASS(ID, NAME, DESCRIPTION) std::unique_ptr<Pass> create##ID();
