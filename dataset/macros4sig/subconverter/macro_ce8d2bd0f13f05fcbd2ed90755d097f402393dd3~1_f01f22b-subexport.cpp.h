
#include<iostream>

#include<functional>
#include<variant>


#include<vector>
#include<climits>
#include<algorithm>

#include<cassert>
#include<stdexcept>

#include<limits.h>



#include<string.h>


#include<memory>
#include<string_view>


#include<sstream>
#include<numeric>
#include<map>
#include<tuple>

#include<string>
#include<optional>


#include<../string.h>
#include<future>



#include<typeinfo>
#include<cmath>



#include<cstddef>





#define HTTP_DEFAULT_GROUP "HTTPProvider"

#define SNELL_DEFAULT_GROUP "SnellProvider"
#define SOCKS_DEFAULT_GROUP "SocksProvider"
#define SSR_DEFAULT_GROUP "SSRProvider"
#define SS_DEFAULT_GROUP "SSProvider"
#define TROJAN_DEFAULT_GROUP "TrojanProvider"
#define V2RAY_DEFAULT_GROUP "V2RayProvider"


#define QJSPP_TYPENAME(...) (typeid(__VA_ARGS__).name())




#define RAPIDJSON_ASSERT(x) exception_thrower(x)





#define GETBIT(x,n) (((int)x < 1) ? 0 : ((x >> (n - 1)) & 1))
#define SETBIT(x,n,v) x ^= (-v ^ x) & (1UL << (n - 1))

#define CONCAT(a,b) a ## b

#define DO_CONCAT(a,b) CONCAT(a,b)
#define defer(x) __defer_struct DO_CONCAT(__defer_deleter,"__LINE__") ([&](...){x;});








