#include<optional>
#include<type_traits>


#include<string>
#include<vector>



#include<deque>


#include<cassert>


#include<cmath>



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

