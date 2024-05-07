

#include<stdint.h>




#include<string>






#define STEAM_ARRAY_COUNT(COUNTER) STEAM_CLANG_ATTR( "array_count:" #COUNTER ";" )
#define STEAM_ARRAY_COUNT_D(COUNTER, DESC) STEAM_CLANG_ATTR( "array_count:" #COUNTER ";desc:" #DESC )
#define STEAM_BUFFER_COUNT(COUNTER) STEAM_CLANG_ATTR( "buffer_count:" #COUNTER ";" )
#define STEAM_CALL_BACK(RESULT_TYPE) STEAM_CLANG_ATTR("callback:" #RESULT_TYPE ";")
#define STEAM_CALL_RESULT(RESULT_TYPE) STEAM_CLANG_ATTR("callresult:" #RESULT_TYPE ";")
# define STEAM_CLANG_ATTR(ATTR) __attribute__((annotate( ATTR )))
#define STEAM_DESC(DESC) STEAM_CLANG_ATTR("desc:" #DESC ";")
#define STEAM_IGNOREATTR() STEAM_CLANG_ATTR( "ignore" )
#define STEAM_METHOD_DESC(DESC) STEAM_CLANG_ATTR( "desc:" #DESC ";" )
#define STEAM_OUT_ARRAY_CALL(COUNTER,FUNCTION,PARAMS) STEAM_CLANG_ATTR( "out_array_call:" #COUNTER "," #FUNCTION "," #PARAMS ";" )
#define STEAM_OUT_ARRAY_COUNT(COUNTER, DESC) STEAM_CLANG_ATTR( "out_array_count:" #COUNTER  ";desc:" #DESC )
#define STEAM_OUT_BUFFER_COUNT(COUNTER) STEAM_CLANG_ATTR( "out_buffer_count:" #COUNTER ";" )
#define STEAM_OUT_STRING() STEAM_CLANG_ATTR( "out_string: ;" )
#define STEAM_OUT_STRING_COUNT(COUNTER) STEAM_CLANG_ATTR( "out_string_count:" #COUNTER ";" )
#define STEAM_OUT_STRUCT() STEAM_CLANG_ATTR( "out_struct: ;" )
#define S_CALLTYPE __cdecl


