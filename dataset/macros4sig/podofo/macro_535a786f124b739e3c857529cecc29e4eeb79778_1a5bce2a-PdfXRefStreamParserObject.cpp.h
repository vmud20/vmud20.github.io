#include<cstdlib>

#include<cstring>

#include<cmath>

#include<vector>


#include<cstddef>




#include<string_view>
#include<exception>

#include<limits>
#include<unordered_set>

#include<ios>
#include<deque>
#include<string>


#include<iostream>
#include<queue>
#include<unordered_map>


#include<fstream>
#include<list>
#include<memory>
#include<ctime>



#include<cinttypes>

#include<cstdio>
#include<istream>
#include<map>

#include<set>
#include<array>

#include<stdexcept>


#include<cstdint>
#include<climits>


#include<functional>
#include<typeinfo>


#include<cassert>

#include<algorithm>






#define FORWARD_DECLARE_FCONFIG()\
extern "C" {\
    struct _FcConfig;\
    typedef struct _FcConfig FcConfig;\
}
#define FORWARD_DECLARE_FREETYPE()\
extern "C"\
{\
    struct FT_FaceRec_;\
    typedef struct FT_FaceRec_* FT_Face;\
}


#define PODOFO_EXCEPTION_API_DOXYGEN PODOFO_EXCEPTION_API(PODOFO_API)

#define PODOFO_API PODOFO_EXPORT

    #define PODOFO_DEPRECATED __attribute__((__deprecated__))
  #define PODOFO_EXCEPTION_API(api) api
    #define PODOFO_EXPORT __declspec(dllexport)
    #define PODOFO_HAS_GCC_ATTRIBUTE_DEPRECATED 1
    #define PODOFO_IMPORT __declspec(dllimport)


#define PODOFO_MAKE_VERSION(M,m,p) PODOFO_MAKE_VERSION_REAL(M,m,p)
#define PODOFO_MAKE_VERSION_REAL(M,m,p) ( (M<<16)+(m<<8)+(p) )
#define PODOFO_MAKE_VERSION_STR(M,m,p) PODOFO_XSTR(PODOFO_MAKE_VERSION_STR_REAL(M,m,p))
#define PODOFO_MAKE_VERSION_STR_REAL(M,m,p) M ## . ## m ## . ## p
#define PODOFO_STR(x) #x "\0"
#define PODOFO_VERSION PODOFO_MAKE_VERSION(PODOFO_VERSION_MAJOR, PODOFO_VERSION_MINOR, PODOFO_VERSION_PATCH)

#define PODOFO_VERSION_STRING PODOFO_MAKE_VERSION_STR(PODOFO_VERSION_MAJOR, PODOFO_VERSION_MINOR, PODOFO_VERSION_PATCH)
#define PODOFO_XSTR(x) PODOFO_STR(x)


















#define AS_BIG_ENDIAN(n) utls::ByteSwap(n)
#define CMAP_REGISTRY_NAME "PoDoFo"

#define FROM_BIG_ENDIAN(n) utls::ByteSwap(n)

#define PODOFO_ASSERT(x) assert(x);



#define PODOFO_PUSH_FRAME(err) err.AddToCallStack("__FILE__", "__LINE__")
#define PODOFO_PUSH_FRAME_INFO(err, msg, ...) err.AddToCallStack("__FILE__", "__LINE__", COMMON_FORMAT(msg, ##__VA_ARGS__))
#define PODOFO_RAISE_ERROR(code) throw ::PoDoFo::PdfError(code, "__FILE__", "__LINE__")
#define PODOFO_RAISE_ERROR_INFO(code, msg, ...) throw ::PoDoFo::PdfError(code, "__FILE__", "__LINE__", COMMON_FORMAT(msg, ##__VA_ARGS__))
#define PODOFO_RAISE_LOGIC_IF(cond, msg, ...) {\
    if (cond)\
        throw ::PoDoFo::PdfError(PdfErrorCode::InternalLogic, "__FILE__", "__LINE__", COMMON_FORMAT(msg, ##__VA_ARGS__));\
};
#define PODOFO_UNIT_TEST(classname) friend class classname

