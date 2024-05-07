

#include<stdio.h>


#include<new>
#include<string.h>
#include<inttypes.h>

#include<string>
#include<stdint.h>
#include<stdlib.h>

#include<vector>

#include<limits>


    #define type1MaxBlueValues 14 
    #define type1MaxOtherBlues 10 
    #define type1MaxStemSnap   12

    #define CFF_STANDARD_STRINGS_COUNT 391 

#define ADDREFINTERFACE(pinterface)\
{\
    if (pinterface!=NULL)\
    {\
        pinterface->AddRef();\
    }\
}
			#define BOOL int
#define FALSE               0
#define FLT_EPSILON     1.192092896e-07F        
#define NULL    0
#define RELEASEARRAYOBJECTS(pobject)\
{\
	if (pobject!=NULL)\
	{\
		delete []pobject;\
		pobject=NULL;\
	}\
}
#define RELEASEINTERFACE(pinterface)\
{\
    if (pinterface!=NULL)\
    {\
        pinterface->Release();\
        pinterface=NULL;\
    }\
}
#define RELEASEMEM(pobject)\
{\
	if (pobject!=NULL)\
	{\
		free(pobject);\
		pobject=NULL;\
	}\
}
#define RELEASEOBJECT(pobject)\
{\
	if (pobject!=NULL)\
	{\
		delete pobject;\
		pobject=NULL;\
	}\
}
        #define S_FALSE                                ((HRESULT)0x00000001L)
        #define S_OK                                   ((HRESULT)0x00000000L)
#define TRUE                1


    #define MAX_PATH 1024
    #define NS_FILE_MAX_PATH 32768
#define UTF8_TO_U(val) NSFile::CUtf8Converter::GetUnicodeStringFromUTF8((BYTE*)val.c_str(), (LONG)val.length())
#define U_TO_UTF8(val) NSFile::CUtf8Converter::GetUtf8StringFromUnicode2(val.c_str(), (LONG)val.length())

#define KERNEL_DECL Q_DECL_EXPORT


#define Q_DECL_EXPORT     __declspec(dllexport)
#define Q_DECL_IMPORT     __declspec(dllimport)



