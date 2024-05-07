#include<assert.h>
#include<stdarg.h>
#include<stdlib.h>
#include<stdio.h>
#include<sys/wait.h>
#include<regex.h>

#include<errno.h>
#include<sys/stat.h>
#include<inttypes.h>
#include<ctype.h>
#include<sys/time.h>

#include<stdbool.h>

#include<limits.h>
#include<stdint.h>
#include<signal.h>
#include<time.h>
#include<unistd.h>
#include<string.h>
#include<dirent.h>
#include<float.h>
#include<features.h>
#define ALLOC_MOD_SIZE 16      
#define Assert(n) assert(n)
#define DECL_VALINIT(n) Jsi_Value n = VALINIT
#define JSI_HAS_SIG 
#define JSI_HAS___PROTO__ 1  
#define JSI_IS64BIT 1
#define JSI_MAX_ALLOC_BUF  100000000 
#define JSI_MAX_SCOPE (JSI_BUFSIZ/2)

#define JSI_NOWARN(v) v=v
#define JSI_OMIT_BASE64 1
#define JSI_OMIT_CDATA 1
#define JSI_OMIT_DEBUG 1
#define JSI_OMIT_ENCRYPT 1
#define JSI_OMIT_EVENT 1
#define JSI_OMIT_LOAD 1
#define JSI_OMIT_MATH 1
#define JSI_OMIT_MD5 1
#define JSI_OMIT_SHA1 1
#define JSI_OMIT_SHA256 1



#define JSI_SMALL_HASH_TABLE 0x10
#define JSI_VERFMT_LEN "6"
#define JSI_VFS_DIR "/vfs"
#define JSI_ZVFS_DIR "/zvfs"
#define JSI__CDATA 1
#define JSI__DEBUG 1
#define JSI__EVENT 1
#define JSI__FILESYS 1
#define JSI__INFO 1
#define JSI__LOAD 1

#define JSI__MATH 1
#define JSI__MINIZ 1
#define JSI__READLINE 1

#define JSI__SIGNAL 1
#define JSI__SOCKET 1
#define JSI__SQLITE 1
#define JSI__STUBS 1
#define JSI__THREADS 1
#define JSI__UTF8 1
#define JSI__WEBSOCKET 1
#define JSI__ZVFS 1
#define JSMN_FREE(p) Jsi_Free(p)
#define JSMN_MALLOC(l) Jsi_Malloc(l)
#define JSMN_REALLOC(p,l) Jsi_Realloc(p,l)
#define Jsi_Calloc(nm, sz) calloc(nm,sz)
#define Jsi_Free(ptr) free(ptr)
#define Jsi_LogType(fmt,...) Jsi_LogMsg(interp, (interp->typeCheck.strict || interp->typeCheck.error)?JSI_LOG_ERROR:JSI_LOG_WARN, fmt, ##__VA_ARGS__)
#define Jsi_Malloc(sz) malloc(sz)
#define Jsi_ObjNew(interp) jsi_ObjNew(interp, "__FILE__", "__LINE__",__PRETTY_FUNCTION__)
#define Jsi_Realloc(ptr, sz) realloc(ptr,sz)
#define Jsi_ValueDup(interp,v) jsi_ValueDup(interp, v,"__FILE__", "__LINE__",__PRETTY_FUNCTION__)
#define Jsi_ValueNew(interp) jsi_ValueNew(interp, "__FILE__", "__LINE__",__PRETTY_FUNCTION__)
#define Jsi_ValueNew1(interp) jsi_ValueNew1(interp, "__FILE__", "__LINE__",__PRETTY_FUNCTION__)
#define MAX_ARRAY_LIST 100000  
#define MAX_LOOP_COUNT 10000000 
#define MAX_SUBREGEX    256

#define RES_BREAK       2
#define RES_CONTINUE    1

#define SIGASSERTDO(s, ret) assert(s);
#define SIGASSERTMASK(s,n,m) assert((s) && ((s)->sig&(~(m))) == (uint)JSI_SIG_##n);
#define SIGASSERTRET(s,n,ret) SIGASSERTDO((s) && (s)->sig == (uint)JSI_SIG_##n, ret);
#define SIGASSERTV(s,n) SIGASSERTRET(s, n, );
#define SIGINIT(s,n) (s)->sig = JSI_SIG_##n;
#define UCHAR(s) (unsigned char)(s)

#define VALINIT { __VALSIG__ .refCnt=1, .vt=JSI_VT_UNDEF, .f={.flag=JSI_OM_ISSTATIC}, .d={}, .next=NULL, .prev=NULL, .VD={.fname="__FILE__", .line="__LINE__",.func=__PRETTY_FUNCTION__}  }



#define _JSICASTINT(s) (int)(s)

#define __DBL_DECIMAL_DIG__ 17


#define __VALSIG__ .sig=JSI_SIG_VALUE,


#define jsi_DebugValueCallIdx() ++interp->dbPtr->memDebugCallIdx
#define jsi_IIOF .flags=JSI_OPT_INIT_ONLY
#define jsi_IIRO .flags=JSI_OPT_READ_ONLY
#define jsi_PrefixMatch(str, cstr) (!Jsi_Strncmp(str, cstr, sizeof(cstr)-1))
#define jsi_Stderr (jsiIntData.stdChans+2)
#define jsi_Stdin jsiIntData.stdChans
#define jsi_Stdout (jsiIntData.stdChans+1)


#define jsi_ValueDebugUpdate(interp, vd, v, tbl, file, line, func)
#define jsi_ValueString(pv) (pv->vt == JSI_VT_STRING ? &pv->d.s : \
  ((pv->vt == JSI_VT_OBJECT && pv->d.obj->ot == JSI_OT_STRING) ? &pv->d.obj->d.s : NULL))
# define YYDEBUG 0
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
# define YYTOKENTYPE
# define YY_YY_SRC_PARSER_H_INCLUDED
#define JSISTUBCALL(ptr,func) ptr->func
#define  JSI_CDATA_OPTION_CHANGED(name) \
        (vrPtr->spec && Jsi_OptionsChanged(interp, vrPtr->spec, #name, NULL))
#define  JSI_CDATA_OPTION_RESET(name) \
        (cmdPtr->queryOpts.mode && !options->name && JSI_CDATA_OPTION_CHANGED(name))
#define JSI_DATE_JULIAN2UNIX(d)  (Jsi_Number)(((Jsi_Number)d - 2440587.5)*86400.0)
#define JSI_DATE_UNIX2JULIAN(d)  (Jsi_Number)((Jsi_Number)d/86400.0+2440587.5)
#define JSI_DBDATA_FIELDS \
    Jsi_StructSpec *sf;      \
    void *data;              \
    uint arrSize;            \
    char prefix;             \
    Jsi_StructSpec* slKey;   \
    int (*callback)(Jsi_Interp *interp, struct Jsi_CDataDb* obPtr, void *data);  \
    uint maxSize;            \
    bool noAuto;             \
    bool isPtrs;             \
    bool isPtr2;             \
    bool isMap;              \
    bool memClear;           \
    bool memFree;            \
    bool dirtyOnly;          \
    bool noBegin;            \
    bool noCache;            \
    bool noStatic;           \
    intptr_t reserved[4];   
#define JSI_DSTRING_DECL_FIELDS(siz) \
    const char *strA;  \
    uint len;        \
    uint spaceAvl;   \
    uint staticSize; \
    char Str[siz];  
#define JSI_DSTRING_STATIC_SIZE 200
#define JSI_DSTRING_VAR(namPtr, siz) \
    struct { JSI_DSTRING_DECL_FIELDS(siz) } _STATIC_##namPtr; \
    Jsi_DString *namPtr = (Jsi_DString *)&_STATIC_##namPtr; \
    namPtr->staticSize = siz; namPtr->strA=0; \
    namPtr->Str[0] = 0; namPtr->spaceAvl = namPtr->len = 0

#define JSI_EXTERN extern
#define JSI_INFO(n) NULL
#define JSI_JSON_DECLARE(p, tokens, maxsz) \
    Jsi_JsonParser p = {0}; \
    Jsi_JsonTok tokens[maxsz>0?maxsz:JSI_JSON_STATIC_DEFAULT]; \
    Jsi_JsonInit(&p, tokens, maxsz>0?maxsz:JSI_JSON_STATIC_DEFAULT)
#define JSI_MAP_DEFN(Prefix, keyType, valType) \
Jsi_MapEntry *Prefix ## _Set(Jsi_Map *mapPtr, keyType key, valType value) { return Jsi_MapSet(mapPtr, (void*)key, (void*)value); } \
valType Prefix ## _Get(Jsi_Map *mapPtr, keyType key) { return (valType)Jsi_MapGet(mapPtr, (void*)key); } \
keyType Prefix ## _KeyGet(Jsi_MapEntry *h) { return (keyType)Jsi_MapKeyGet(h); } \
Jsi_MapEntry* Prefix ## _EntryFind (Jsi_Map *mapPtr, keyType key) { return  Jsi_MapEntryFind(mapPtr, (void*)key); } \
Jsi_MapEntry* Prefix ## _EntryNew (Jsi_Map *mapPtr, keyType key, int *isNew) { return  Jsi_MapEntryNew(mapPtr, (void*)key, isNew); }
#define JSI_MAP_EXTN(Prefix, keyType, valType) \
JSI_EXTERN Jsi_MapEntry *Prefix ## _Set(Jsi_Map *mapPtr, keyType key, valType value); \
JSI_EXTERN valType Prefix ## _Get(Jsi_Map *mapPtr, keyType key); \
JSI_EXTERN keyType Prefix ## _KeyGet(Jsi_MapEntry *h); \
JSI_EXTERN Jsi_MapEntry* Prefix ## _EntryFind (Jsi_Map *mapPtr, keyType key); \
JSI_EXTERN Jsi_MapEntry* Prefix ## _EntryNew (Jsi_Map *mapPtr, keyType key, int *isNew);
#define JSI_NOTUSED(n) (void)n 
#define JSI_NUMEFMT JSI_NUMLMOD "e"
#define JSI_NUMFFMT JSI_NUMLMOD "f"
#define JSI_NUMGFMT JSI_NUMLMOD "g"
#define JSI_NUMLMOD "L"
#define JSI_OPT(typ, strct, nam, ...) JSI_OPT_(JSI_SIG_OPTS, typ, strct, nam, ##__VA_ARGS__) 
#define JSI_OPT_(s, typ, strct, nam, ...) \
    { .sig=s, .id=JSI_OPTION_##typ, .name=#nam, .offset=Jsi_Offset(strct, nam), .size=sizeof(((strct *) 0)->nam), \
      .init={.typ=(&((strct *) 0)->nam)}, ##__VA_ARGS__ }
#define JSI_OPT_BITS(strct, nam, hlp, flgs, bsget, fidx, tnam, bdata) JSI_OPT_BITS_(JSI_SIG_OPTS, strct, nam, hlp, flgs, bsget, fidx, tnam, bdata)
#define JSI_OPT_BITS_(s, strct, nam, hlp, flgs, bsget, fidx, tnam, bdata) \
    { .sig=s, .id=JSI_OPTION_CUSTOM, .name=#nam, .offset=0, .size=0, \
        .init={.OPT_BITS=&bsget}, .help=hlp, .flags=flgs, .custom=Jsi_Opt_SwitchBitfield, .data=bdata,\
        .info=0, .tname=#nam, .value=0, .bits=0, .boffset=0, .idx=fidx }
#define JSI_OPT_CARRAY(strct, nam, hlp, flgs, aropt, asiz, tnam, sinit) JSI_OPT_CARRAY_(JSI_SIG_OPTS, strct, nam, hlp, flgs, aropt, asiz, tnam, sinit)
#define JSI_OPT_CARRAY_(s, strct, nam, hlp, flgs, aropt, asiz, tnam, sinit) \
    { .sig=s, .id=JSI_OPTION_CUSTOM, .name=#nam, .offset=Jsi_Offset(strct, nam), .size=sizeof(((strct *) 0)->nam), \
        .init={.OPT_CARRAY=aropt}, .help=hlp, .flags=flgs, .custom=Jsi_Opt_SwitchCArray, .data=0,\
        .info=0, .tname=tnam, .value=0, .bits=0, .boffset=0, .idx=0, .ssig=0, .crc=0, .arrSize=asiz, .extData=sinit, .extra=0 }
#define JSI_OPT_CARRAY_ITEM(typ, strct, nam, ...) JSI_OPT_CARRAY_ITEM_(JSI_SIG_OPTS, typ, strct, nam, ##__VA_ARGS__)
#define JSI_OPT_CARRAY_ITEM_(s, typ, strct, nam, ...) \
    { .sig=s, .id=JSI_OPTION_##typ, .name=#nam, .offset=0, .size=sizeof(((strct *) 0)->nam), \
      .init={.typ=(&((strct *) 0)->nam[0])}, ##__VA_ARGS__ }
#define JSI_OPT_END(strct, ...) JSI_OPT_END_(JSI_SIG_OPTS, strct, ##__VA_ARGS__)
#define JSI_OPT_END_(s, strct, ...) { .sig=s, .id=JSI_OPTION_END, .name=#strct, .offset="__LINE__", .size=sizeof(strct), \
      .init={.CUSTOM=(void*)"__FILE__", ##__VA_ARGS__}
#define JSI_OPT_END_IDX(opt) ((sizeof(opt)/sizeof(opt[0]))-1)
#define JSI_STUBS_STRUCTSIZES (sizeof(Jsi_MapSearch)+sizeof(Jsi_TreeSearch) \
    +sizeof(Jsi_HashSearch)+sizeof(Jsi_Filesystem)+sizeof(Jsi_Chan)+sizeof(Jsi_Event) \
    +sizeof(Jsi_CDataDb)+sizeof(Jsi_Stack)+sizeof(Jsi_OptionSpec)+sizeof(Jsi_CmdSpec) \
    +sizeof(Jsi_UserObjReg)+sizeof(Jsi_String) + sizeof(Jsi_PkgOpts))
#define JSI_VERSION (JSI_VERSION_MAJOR + ((Jsi_Number)JSI_VERSION_MINOR/100.0) + ((Jsi_Number)JSI_VERSION_RELEASE/10000.0))
#define JSI_VERSION_MAJOR   3
#define JSI_VERSION_MINOR   0
#define JSI_VERSION_RELEASE 6
#define JSI_WORDKEY_CAST (void*)(uintptr_t)
#define Jsi_CmdProcDecl(name,...) Jsi_RC name(Jsi_Interp *interp, Jsi_Value *args, \
    Jsi_Value *_this, Jsi_Value **ret, Jsi_Func *funcPtr, ##__VA_ARGS__)
#define Jsi_ListEntryNext(entry)        (entry)->next 
#define Jsi_ListEntryPrev(entry)        (entry)->prev
#define Jsi_ListGetBack(list)           (list)->tail
#define Jsi_ListGetFront(list)          (list)->head
#define Jsi_ListPopBack(list)           Jsi_ListPop(list, list->tail)
#define Jsi_ListPopFront(list)          Jsi_ListPop(list, list->head)
#define Jsi_ListPushBack(list,entry)    Jsi_ListPush(list, entry, NULL)
#define Jsi_ListPushBackNew(list,v)     Jsi_ListEntryNew(list, v, NULL)
#define Jsi_ListPushFront(list,entry)   Jsi_ListPush(list, entry, list->head)
#define Jsi_ListPushFrontNew(list,v)    Jsi_ListEntryNew(list, v, list->head)
#define Jsi_LogBug(fmt,...) Jsi_LogMsg(interp, JSI_LOG_BUG, fmt, ##__VA_ARGS__)
#define Jsi_LogDebug(fmt,...) Jsi_LogMsg(interp, JSI_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define Jsi_LogError(fmt,...) Jsi_LogMsg(interp, JSI_LOG_ERROR, fmt, ##__VA_ARGS__)
#define Jsi_LogInfo(fmt,...) Jsi_LogMsg(interp, JSI_LOG_INFO, fmt, ##__VA_ARGS__)
#define Jsi_LogParse(fmt,...) Jsi_LogMsg(interp, JSI_LOG_PARSE, fmt, ##__VA_ARGS__)
#define Jsi_LogTest(fmt,...) Jsi_LogMsg(interp, JSI_LOG_TEST, fmt, ##__VA_ARGS__)
#define Jsi_LogTrace(fmt,...) Jsi_LogMsg(interp, JSI_LOG_TRACE, fmt, ##__VA_ARGS__)
#define Jsi_LogWarn(fmt,...) Jsi_LogMsg(interp, JSI_LOG_WARN, fmt, ##__VA_ARGS__)
#define Jsi_Offset(type, field) ((long) offsetof(type, field))
#define Jsi_Opt_SwitchBitfield      (Jsi_OptionCustom*)0x4 
#define Jsi_Opt_SwitchBitset        (Jsi_OptionCustom*)0x2 
#define Jsi_Opt_SwitchCArray        (Jsi_OptionCustom*)0x6 
#define Jsi_Opt_SwitchEnum          (Jsi_OptionCustom*)0x1 
#define Jsi_Opt_SwitchNull          (Jsi_OptionCustom*)0x7 
#define Jsi_Opt_SwitchParentFunc    (Jsi_OptionCustom*)0x8 
#define Jsi_Opt_SwitchSuboption     (Jsi_OptionCustom*)0x3 
#define Jsi_Opt_SwitchValueVerify   (Jsi_OptionCustom*)0x5 
#define Jsi_PkgProvide(i,n,v,p) Jsi_PkgProvideEx(i,n,v,p,NULL)
#define Jsi_PkgRequire(i,n,v) Jsi_PkgRequireEx(i,n,v,NULL)
#define Jsi_StubsInit(i,f) JSI_OK
#define Jsi_Stzcpy(buf,src) Jsi_Strncpy(buf, src, sizeof(buf))
#define Jsi_ValueArraySet(interp, dest, value, index) Jsi_ObjArraySet(interp, Jsi_ValueGetObj(interp, dest), value, index)
#define Jsi_ValueInsertFixed(i,t,k,v) Jsi_ValueInsert(i,t,k,v,JSI_OM_READONLY | JSI_OM_DONTDEL | JSI_OM_DONTENUM)
#define Jsi_ValueMakeStringDup(interp, v, s) Jsi_ValueMakeString(interp, v, Jsi_Strdup(s))
#define Jsi_ValueNewArrayObj(interp, items, count, copy) Jsi_ValueNewObj(interp, Jsi_ObjNewArray(interp, items, count, copy))
#define Jsi_ValueNewBlobString(interp, s) Jsi_ValueNewBlob(interp, (uchar*)s, Jsi_Strlen(s))

#define __USE_MINGW_ANSI_STDIO 1


#define JSI_STUBS_BLDFLAGS 1
#define JSI_STUBS_MD5 "d32d2f3a25ef2f1bb91a706989687883"
#define Jsi_Access(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Access(n0,n1,n2))
#define Jsi_AddAutoFiles(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_AddAutoFiles(n0,n1))
#define Jsi_Base64(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Base64(n0,n1,n2,n3))
#define Jsi_CDataLookup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_CDataLookup(n0,n1))
#define Jsi_CDataRegister(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_CDataRegister(n0,n1))
#define Jsi_CDataStruct(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_CDataStruct(n0,n1))
#define Jsi_CDataStructInit(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_CDataStructInit(n0,n1,n2))
#define Jsi_Chdir(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Chdir(n0,n1))
#define Jsi_Chmod(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Chmod(n0,n1,n2))
#define Jsi_Close(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Close(n0,n1))
#define Jsi_CommandCreate(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_CommandCreate(n0,n1,n2,n3))
#define Jsi_CommandCreateSpecs(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_CommandCreateSpecs(n0,n1,n2,n3,n4))
#define Jsi_CommandDelete(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_CommandDelete(n0,n1))
#define Jsi_CommandInvoke(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_CommandInvoke(n0,n1,n2,n3))
#define Jsi_CommandInvokeJSON(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_CommandInvokeJSON(n0,n1,n2,n3))
#define Jsi_CommandNewObj(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_CommandNewObj(n0,n1,n2,n3,n4))
#define Jsi_Crc32(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Crc32(n0,n1,n2))
#define Jsi_CryptoHash(n0,n1,n2,n3,n4,n5,n6) JSISTUBCALL(jsiStubsPtr, _Jsi_CryptoHash(n0,n1,n2,n3,n4,n5,n6))
#define Jsi_CurrentThread(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_CurrentThread(n0))
#define Jsi_DSAppend(n0,n1,...) JSISTUBCALL(jsiStubsPtr, _Jsi_DSAppend(n0,n1,##__VA_ARGS__))
#define Jsi_DSAppendLen(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_DSAppendLen(n0,n1,n2))
#define Jsi_DSFree(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_DSFree(n0))
#define Jsi_DSFreeDup(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_DSFreeDup(n0))
#define Jsi_DSInit(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_DSInit(n0))
#define Jsi_DSLength(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_DSLength(n0))
#define Jsi_DSPrintf(n0,n1,...) JSISTUBCALL(jsiStubsPtr, _Jsi_DSPrintf(n0,n1,##__VA_ARGS__))
#define Jsi_DSSet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DSSet(n0,n1))
#define Jsi_DSSetLength(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DSSetLength(n0,n1))
#define Jsi_DSValue(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_DSValue(n0))
#define Jsi_DateTime(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_DateTime(n0))
#define Jsi_DatetimeFormat(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_DatetimeFormat(n0,n1,n2,n3,n4))
#define Jsi_DatetimeParse(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_DatetimeParse(n0,n1,n2,n3,n4,n5))
#define Jsi_DbHandle(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DbHandle(n0,n1))
#define Jsi_DbNew(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DbNew(n0,n1))
#define Jsi_DbQuery(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_DbQuery(n0,n1,n2))
#define Jsi_DecrRefCount(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DecrRefCount(n0,n1))
#define Jsi_DeleteData(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DeleteData(n0,n1))
#define Jsi_DictionaryCompare(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_DictionaryCompare(n0,n1))
#define Jsi_DllLookup(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_DllLookup(n0,n1,n2,n3))
#define Jsi_Encrypt(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_Encrypt(n0,n1,n2,n3,n4))
#define Jsi_Eof(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Eof(n0,n1))
#define Jsi_EvalCmdJSON(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_EvalCmdJSON(n0,n1,n2,n3,n4))
#define Jsi_EvalFile(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_EvalFile(n0,n1,n2))
#define Jsi_EvalString(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_EvalString(n0,n1,n2))
#define Jsi_EvalZip(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_EvalZip(n0,n1,n2,n3))
#define Jsi_EventFree(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_EventFree(n0,n1))
#define Jsi_EventNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_EventNew(n0,n1,n2))
#define Jsi_EventProcess(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_EventProcess(n0,n1))
#define Jsi_EventuallyFree(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_EventuallyFree(n0,n1,n2))
#define Jsi_Executable(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_Executable(n0))
#define Jsi_FSNameToChannel(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_FSNameToChannel(n0,n1))
#define Jsi_FSNative(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_FSNative(n0,n1))
#define Jsi_FSRegister(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_FSRegister(n0,n1))
#define Jsi_FSUnregister(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_FSUnregister(n0))
#define Jsi_FileRead(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_FileRead(n0,n1,n2))
#define Jsi_FileRealpath(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_FileRealpath(n0,n1,n2))
#define Jsi_FileRealpathStr(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_FileRealpathStr(n0,n1,n2))
#define Jsi_Flush(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Flush(n0,n1))
#define Jsi_FormatString(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_FormatString(n0,n1,n2))
#define Jsi_FuncObjToString(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_FuncObjToString(n0,n1,n2,n3))
#define Jsi_FunctionApply(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionApply(n0,n1,n2,n3))
#define Jsi_FunctionArguments(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionArguments(n0,n1,n2))
#define Jsi_FunctionGetSpecs(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionGetSpecs(n0))
#define Jsi_FunctionInvoke(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionInvoke(n0,n1,n2,n3,n4))
#define Jsi_FunctionInvokeBool(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionInvokeBool(n0,n1,n2))
#define Jsi_FunctionInvokeJSON(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionInvokeJSON(n0,n1,n2,n3))
#define Jsi_FunctionInvokeString(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionInvokeString(n0,n1,n2,n3))
#define Jsi_FunctionIsConstructor(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionIsConstructor(n0))
#define Jsi_FunctionPrivData(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionPrivData(n0))
#define Jsi_FunctionReturnIgnored(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_FunctionReturnIgnored(n0,n1))
#define Jsi_GetBool(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetBool(n0,n1,n2))
#define Jsi_GetBoolFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetBoolFromValue(n0,n1,n2))
#define Jsi_GetCwd(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_GetCwd(n0,n1))
#define Jsi_GetDouble(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetDouble(n0,n1,n2))
#define Jsi_GetDoubleFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetDoubleFromValue(n0,n1,n2))
#define Jsi_GetIndex(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_GetIndex(n0,n1,n2,n3,n4,n5))
#define Jsi_GetInt(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_GetInt(n0,n1,n2,n3))
#define Jsi_GetIntFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetIntFromValue(n0,n1,n2))
#define Jsi_GetIntFromValueBase(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_GetIntFromValueBase(n0,n1,n2,n3,n4))
#define Jsi_GetLongFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetLongFromValue(n0,n1,n2))
#define Jsi_GetNumberFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetNumberFromValue(n0,n1,n2))
#define Jsi_GetStdChannel(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_GetStdChannel(n0,n1))
#define Jsi_GetStringFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetStringFromValue(n0,n1,n2))
#define Jsi_GetWide(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_GetWide(n0,n1,n2,n3))
#define Jsi_GetWideFromValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GetWideFromValue(n0,n1,n2))
#define Jsi_Getc(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Getc(n0,n1))
#define Jsi_Gets(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Gets(n0,n1,n2,n3))
#define Jsi_GlobMatch(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_GlobMatch(n0,n1,n2))
#define Jsi_HashClear(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashClear(n0))
#define Jsi_HashConf(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_HashConf(n0,n1,n2))
#define Jsi_HashDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashDelete(n0))
#define Jsi_HashEntryDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashEntryDelete(n0))
#define Jsi_HashEntryFind(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_HashEntryFind(n0,n1))
#define Jsi_HashEntryNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_HashEntryNew(n0,n1,n2))
#define Jsi_HashGet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_HashGet(n0,n1,n2))
#define Jsi_HashKeyGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashKeyGet(n0))
#define Jsi_HashKeysDump(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_HashKeysDump(n0,n1,n2,n3))
#define Jsi_HashNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_HashNew(n0,n1,n2))
#define Jsi_HashSearchFirst(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_HashSearchFirst(n0,n1))
#define Jsi_HashSearchNext(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashSearchNext(n0))
#define Jsi_HashSet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_HashSet(n0,n1,n2))
#define Jsi_HashSize(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashSize(n0))
#define Jsi_HashUnset(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_HashUnset(n0,n1))
#define Jsi_HashValueGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_HashValueGet(n0))
#define Jsi_HashValueSet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_HashValueSet(n0,n1))
#define Jsi_HexStr(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_HexStr(n0,n1,n2,n3))
#define Jsi_IncrRefCount(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_IncrRefCount(n0,n1))
#define Jsi_Interactive(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Interactive(n0,n1))
#define Jsi_InterpAccess(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpAccess(n0,n1,n2))
#define Jsi_InterpDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpDelete(n0))
#define Jsi_InterpFreeData(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpFreeData(n0,n1))
#define Jsi_InterpGetData(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpGetData(n0,n1,n2))
#define Jsi_InterpGone(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpGone(n0))
#define Jsi_InterpLastError(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpLastError(n0,n1,n2))
#define Jsi_InterpNew(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpNew(n0))
#define Jsi_InterpOnDelete(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpOnDelete(n0,n1,n2))
#define Jsi_InterpResult(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpResult(n0))
#define Jsi_InterpSafe(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpSafe(n0))
#define Jsi_InterpSetData(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpSetData(n0,n1,n2,n3))
#define Jsi_InterpThread(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_InterpThread(n0))
#define Jsi_IsReserved(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_IsReserved(n0,n1,n2))
#define Jsi_IsShared(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_IsShared(n0,n1))
#define Jsi_IterGetKeys(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_IterGetKeys(n0,n1,n2,n3))
#define Jsi_IterObjFree(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_IterObjFree(n0))
#define Jsi_IterObjNew(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_IterObjNew(n0,n1))
#define Jsi_JSONParse(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_JSONParse(n0,n1,n2,n3))
#define Jsi_JSONParseFmt(n0,n1,n2,...) JSISTUBCALL(jsiStubsPtr, _Jsi_JSONParseFmt(n0,n1,n2,##__VA_ARGS__))
#define Jsi_JSONQuote(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_JSONQuote(n0,n1,n2,n3))
#define Jsi_JsonDump(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonDump(n0,n1))
#define Jsi_JsonFree(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonFree(n0))
#define Jsi_JsonGetErrname(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonGetErrname(n0))
#define Jsi_JsonGetToken(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonGetToken(n0,n1))
#define Jsi_JsonGetTokstr(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonGetTokstr(n0,n1,n2,n3))
#define Jsi_JsonGetType(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonGetType(n0,n1))
#define Jsi_JsonGetTypename(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonGetTypename(n0))
#define Jsi_JsonInit(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonInit(n0,n1,n2))
#define Jsi_JsonParse(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonParse(n0,n1))
#define Jsi_JsonReset(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonReset(n0))
#define Jsi_JsonTokLen(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_JsonTokLen(n0,n1))
#define Jsi_KeyAdd(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_KeyAdd(n0,n1))
#define Jsi_KeyLookup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_KeyLookup(n0,n1))
#define Jsi_Link(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Link(n0,n1,n2,n3))
#define Jsi_ListClear(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ListClear(n0))
#define Jsi_ListConf(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ListConf(n0,n1,n2))
#define Jsi_ListDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ListDelete(n0))
#define Jsi_ListEntryDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ListEntryDelete(n0))
#define Jsi_ListEntryNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ListEntryNew(n0,n1,n2))
#define Jsi_ListNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ListNew(n0,n1,n2))
#define Jsi_ListPop(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ListPop(n0,n1))
#define Jsi_ListPush(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ListPush(n0,n1,n2))
#define Jsi_ListSearchFirst(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ListSearchFirst(n0,n1,n2))
#define Jsi_ListSearchNext(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ListSearchNext(n0))
#define Jsi_ListSize(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ListSize(n0))
#define Jsi_ListValueGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ListValueGet(n0))
#define Jsi_ListValueSet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ListValueSet(n0,n1))
#define Jsi_LoadLibrary(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_LoadLibrary(n0,n1,n2))
#define Jsi_LogMsg(n0,n1,n2,...) JSISTUBCALL(jsiStubsPtr, _Jsi_LogMsg(n0,n1,n2,##__VA_ARGS__))
#define Jsi_Lstat(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Lstat(n0,n1,n2))
#define Jsi_Main(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_Main(n0))
#define Jsi_MapClear(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapClear(n0))
#define Jsi_MapConf(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_MapConf(n0,n1,n2))
#define Jsi_MapDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapDelete(n0))
#define Jsi_MapEntryDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapEntryDelete(n0))
#define Jsi_MapEntryFind(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_MapEntryFind(n0,n1))
#define Jsi_MapEntryNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_MapEntryNew(n0,n1,n2))
#define Jsi_MapGet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_MapGet(n0,n1,n2))
#define Jsi_MapKeyGet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_MapKeyGet(n0,n1))
#define Jsi_MapKeysDump(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_MapKeysDump(n0,n1,n2,n3))
#define Jsi_MapNew(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_MapNew(n0,n1,n2,n3))
#define Jsi_MapSearchDone(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapSearchDone(n0))
#define Jsi_MapSearchFirst(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_MapSearchFirst(n0,n1,n2))
#define Jsi_MapSearchNext(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapSearchNext(n0))
#define Jsi_MapSet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_MapSet(n0,n1,n2))
#define Jsi_MapSize(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapSize(n0))
#define Jsi_MapValueGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_MapValueGet(n0))
#define Jsi_MapValueSet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_MapValueSet(n0,n1))
#define Jsi_Mount(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Mount(n0,n1,n2,n3))
#define Jsi_MutexDelete(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_MutexDelete(n0,n1))
#define Jsi_MutexLock(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_MutexLock(n0,n1))
#define Jsi_MutexNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_MutexNew(n0,n1,n2))
#define Jsi_MutexUnlock(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_MutexUnlock(n0,n1))
#define Jsi_NameLookup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_NameLookup(n0,n1))
#define Jsi_NameLookup2(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_NameLookup2(n0,n1,n2))
#define Jsi_NormalPath(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_NormalPath(n0,n1,n2))
#define Jsi_NumUtfBytes(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumUtfBytes(n0))
#define Jsi_NumUtfChars(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_NumUtfChars(n0,n1))
#define Jsi_NumberDtoA(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberDtoA(n0,n1,n2,n3,n4))
#define Jsi_NumberInfinity(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberInfinity(n0))
#define Jsi_NumberIsEqual(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsEqual(n0,n1))
#define Jsi_NumberIsFinite(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsFinite(n0))
#define Jsi_NumberIsInfinity(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsInfinity(n0))
#define Jsi_NumberIsInteger(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsInteger(n0))
#define Jsi_NumberIsNaN(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsNaN(n0))
#define Jsi_NumberIsNormal(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsNormal(n0))
#define Jsi_NumberIsSubnormal(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsSubnormal(n0))
#define Jsi_NumberIsWide(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberIsWide(n0))
#define Jsi_NumberItoA10(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberItoA10(n0,n1,n2))
#define Jsi_NumberNaN(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberNaN(n0))
#define Jsi_NumberToString(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberToString(n0,n1,n2,n3))
#define Jsi_NumberUtoA10(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_NumberUtoA10(n0,n1,n2))
#define Jsi_ObjArrayAdd(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjArrayAdd(n0,n1,n2))
#define Jsi_ObjArraySet(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjArraySet(n0,n1,n2,n3))
#define Jsi_ObjArraySizer(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjArraySizer(n0,n1,n2))
#define Jsi_ObjDecrRefCount(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjDecrRefCount(n0,n1))
#define Jsi_ObjFree(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjFree(n0,n1))
#define Jsi_ObjFromDS(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjFromDS(n0,n1))
#define Jsi_ObjGetLength(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjGetLength(n0,n1))
#define Jsi_ObjIncrRefCount(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjIncrRefCount(n0,n1))
#define Jsi_ObjInsert(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjInsert(n0,n1,n2,n3,n4))
#define Jsi_ObjIsArray(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjIsArray(n0,n1))
#define Jsi_ObjListifyArray(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjListifyArray(n0,n1))
#define Jsi_ObjNewArray(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjNewArray(n0,n1,n2,n3))
#define Jsi_ObjNewObj(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjNewObj(n0,n1,n2))
#define Jsi_ObjNewType(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjNewType(n0,n1))
#define Jsi_ObjSetLength(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjSetLength(n0,n1,n2))
#define Jsi_ObjTypeGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjTypeGet(n0))
#define Jsi_ObjTypeStr(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ObjTypeStr(n0,n1))
#define Jsi_Open(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Open(n0,n1,n2))
#define Jsi_OptionCustomBuiltin(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionCustomBuiltin(n0))
#define Jsi_OptionSpecsCached(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionSpecsCached(n0,n1))
#define Jsi_OptionTypeInfo(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionTypeInfo(n0))
#define Jsi_OptionsChanged(n0,n1,n2,...) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsChanged(n0,n1,n2,##__VA_ARGS__))
#define Jsi_OptionsConf(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsConf(n0,n1,n2,n3,n4,n5))
#define Jsi_OptionsCustomPrint(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsCustomPrint(n0,n1,n2,n3,n4))
#define Jsi_OptionsDump(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsDump(n0,n1,n2,n3,n4))
#define Jsi_OptionsDup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsDup(n0,n1))
#define Jsi_OptionsFind(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsFind(n0,n1,n2,n3))
#define Jsi_OptionsFree(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsFree(n0,n1,n2,n3))
#define Jsi_OptionsGet(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsGet(n0,n1,n2,n3,n4,n5))
#define Jsi_OptionsProcess(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsProcess(n0,n1,n2,n3,n4))
#define Jsi_OptionsProcessJSON(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsProcessJSON(n0,n1,n2,n3,n4))
#define Jsi_OptionsSet(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsSet(n0,n1,n2,n3,n4,n5))
#define Jsi_OptionsValid(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_OptionsValid(n0,n1))
#define Jsi_PathNormalize(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_PathNormalize(n0,n1))
#define Jsi_PkgProvideEx(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_PkgProvideEx(n0,n1,n2,n3,n4))
#define Jsi_PkgRequireEx(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_PkgRequireEx(n0,n1,n2,n3))
#define Jsi_PkgVersion(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_PkgVersion(n0,n1,n2))
#define Jsi_Preserve(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Preserve(n0,n1))
#define Jsi_Printf(n0,n1,n2,...) JSISTUBCALL(jsiStubsPtr, _Jsi_Printf(n0,n1,n2,##__VA_ARGS__))
#define Jsi_PrototypeDefine(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_PrototypeDefine(n0,n1,n2))
#define Jsi_PrototypeGet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_PrototypeGet(n0,n1))
#define Jsi_PrototypeObjSet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_PrototypeObjSet(n0,n1,n2))
#define Jsi_Puts(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Puts(n0,n1,n2,n3))
#define Jsi_Read(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Read(n0,n1,n2,n3))
#define Jsi_Readlink(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Readlink(n0,n1,n2,n3))
#define Jsi_Realpath(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Realpath(n0,n1,n2))
#define Jsi_RegExpFree(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_RegExpFree(n0))
#define Jsi_RegExpMatch(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_RegExpMatch(n0,n1,n2,n3,n4))
#define Jsi_RegExpMatches(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_RegExpMatches(n0,n1,n2,n3,n4))
#define Jsi_RegExpNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_RegExpNew(n0,n1,n2))
#define Jsi_Release(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Release(n0,n1))
#define Jsi_Remove(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Remove(n0,n1,n2))
#define Jsi_Rename(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Rename(n0,n1,n2))
#define Jsi_ReturnValue(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ReturnValue(n0))
#define Jsi_Rewind(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Rewind(n0,n1))
#define Jsi_Scandir(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_Scandir(n0,n1,n2,n3,n4))
#define Jsi_Seek(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Seek(n0,n1,n2,n3))
#define Jsi_SetChannelOption(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_SetChannelOption(n0,n1,n2,n3))
#define Jsi_ShiftArgs(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ShiftArgs(n0,n1))
#define Jsi_Sleep(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Sleep(n0,n1))
#define Jsi_SplitStr(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_SplitStr(n0,n1,n2,n3,n4))
#define Jsi_SqlObjBinds(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_SqlObjBinds(n0,n1,n2,n3,n4,n5))
#define Jsi_StackFree(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackFree(n0))
#define Jsi_StackFreeElements(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_StackFreeElements(n0,n1,n2))
#define Jsi_StackHead(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackHead(n0))
#define Jsi_StackNew(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackNew(n0))
#define Jsi_StackPeek(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackPeek(n0))
#define Jsi_StackPop(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackPop(n0))
#define Jsi_StackPush(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_StackPush(n0,n1))
#define Jsi_StackSize(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackSize(n0))
#define Jsi_StackUnshift(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StackUnshift(n0))
#define Jsi_Stat(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Stat(n0,n1,n2))
#define Jsi_StrIsAlnum(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_StrIsAlnum(n0))
#define Jsi_Strchr(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Strchr(n0,n1))
#define Jsi_Strcmp(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Strcmp(n0,n1))
#define Jsi_StrcmpDict(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_StrcmpDict(n0,n1,n2,n3))
#define Jsi_Strcpy(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Strcpy(n0,n1))
#define Jsi_Strdup(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_Strdup(n0))
#define Jsi_StrdupLen(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_StrdupLen(n0,n1))
#define Jsi_StringSplit(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_StringSplit(n0,n1,n2))
#define Jsi_Strlen(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_Strlen(n0))
#define Jsi_StrlenSet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_StrlenSet(n0,n1))
#define Jsi_Strncasecmp(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Strncasecmp(n0,n1,n2))
#define Jsi_Strncmp(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Strncmp(n0,n1,n2))
#define Jsi_Strncpy(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Strncpy(n0,n1,n2))
#define Jsi_Strpos(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Strpos(n0,n1,n2,n3))
#define Jsi_Strrchr(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Strrchr(n0,n1))
#define Jsi_Strrpos(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Strrpos(n0,n1,n2,n3))
#define Jsi_Strrstr(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Strrstr(n0,n1))
#define Jsi_Strstr(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Strstr(n0,n1))
#define Jsi_StubLookup(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_StubLookup(n0,n1,n2))
#define Jsi_Tell(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_Tell(n0,n1))
#define Jsi_ThisDataGet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ThisDataGet(n0,n1))
#define Jsi_ThisDataSet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ThisDataSet(n0,n1,n2))
#define Jsi_TreeClear(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeClear(n0))
#define Jsi_TreeConf(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeConf(n0,n1,n2))
#define Jsi_TreeDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeDelete(n0))
#define Jsi_TreeEntryDelete(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeEntryDelete(n0))
#define Jsi_TreeEntryFind(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeEntryFind(n0,n1))
#define Jsi_TreeEntryNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeEntryNew(n0,n1,n2))
#define Jsi_TreeFromValue(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeFromValue(n0,n1))
#define Jsi_TreeGet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeGet(n0,n1,n2))
#define Jsi_TreeKeyGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeKeyGet(n0))
#define Jsi_TreeKeysDump(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeKeysDump(n0,n1,n2,n3))
#define Jsi_TreeNew(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeNew(n0,n1,n2))
#define Jsi_TreeObjGetValue(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeObjGetValue(n0,n1,n2))
#define Jsi_TreeObjSetValue(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeObjSetValue(n0,n1,n2,n3))
#define Jsi_TreeSearchDone(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeSearchDone(n0))
#define Jsi_TreeSearchFirst(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeSearchFirst(n0,n1,n2,n3))
#define Jsi_TreeSearchNext(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeSearchNext(n0))
#define Jsi_TreeSet(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeSet(n0,n1,n2))
#define Jsi_TreeSize(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeSize(n0))
#define Jsi_TreeUnset(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeUnset(n0,n1))
#define Jsi_TreeValueGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeValueGet(n0))
#define Jsi_TreeValueSet(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeValueSet(n0,n1))
#define Jsi_TreeWalk(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_TreeWalk(n0,n1,n2,n3))
#define Jsi_Truncate(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Truncate(n0,n1,n2))
#define Jsi_TypeLookup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_TypeLookup(n0,n1))
#define Jsi_Ungetc(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_Ungetc(n0,n1,n2))
#define Jsi_UniCharToUtf(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UniCharToUtf(n0,n1))
#define Jsi_UserObjDataFromVar(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UserObjDataFromVar(n0,n1))
#define Jsi_UserObjGetData(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_UserObjGetData(n0,n1,n2))
#define Jsi_UserObjName(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_UserObjName(n0,n1,n2))
#define Jsi_UserObjNew(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_UserObjNew(n0,n1,n2,n3))
#define Jsi_UserObjRegister(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UserObjRegister(n0,n1))
#define Jsi_UserObjUnregister(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UserObjUnregister(n0,n1))
#define Jsi_UtfAtIndex(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfAtIndex(n0,n1))
#define Jsi_UtfDecode(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfDecode(n0,n1))
#define Jsi_UtfEncode(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfEncode(n0,n1))
#define Jsi_UtfGetIndex(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfGetIndex(n0,n1,n2))
#define Jsi_UtfIndexToOffset(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfIndexToOffset(n0,n1))
#define Jsi_UtfSubstr(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfSubstr(n0,n1,n2,n3))
#define Jsi_UtfToUniChar(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfToUniChar(n0,n1))
#define Jsi_UtfToUniCharCase(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_UtfToUniCharCase(n0,n1,n2))
#define Jsi_ValueArrayConcat(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayConcat(n0,n1,n2))
#define Jsi_ValueArrayIndex(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayIndex(n0,n1,n2))
#define Jsi_ValueArrayIndexToStr(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayIndexToStr(n0,n1,n2,n3))
#define Jsi_ValueArrayPop(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayPop(n0,n1))
#define Jsi_ValueArrayPush(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayPush(n0,n1,n2))
#define Jsi_ValueArrayShift(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayShift(n0,n1))
#define Jsi_ValueArraySort(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArraySort(n0,n1,n2))
#define Jsi_ValueArrayUnshift(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueArrayUnshift(n0,n1))
#define Jsi_ValueBlob(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueBlob(n0,n1,n2))
#define Jsi_ValueCmp(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueCmp(n0,n1,n2,n3))
#define Jsi_ValueCopy(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueCopy(n0,n1,n2))
#define Jsi_ValueDup2(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueDup2(n0,n1,n2))
#define Jsi_ValueDupJSON(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueDupJSON(n0,n1))
#define Jsi_ValueFree(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueFree(n0,n1))
#define Jsi_ValueFromDS(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueFromDS(n0,n1,n2))
#define Jsi_ValueGetBoolean(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetBoolean(n0,n1,n2))
#define Jsi_ValueGetDString(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetDString(n0,n1,n2,n3))
#define Jsi_ValueGetIndex(n0,n1,n2,n3,n4,n5) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetIndex(n0,n1,n2,n3,n4,n5))
#define Jsi_ValueGetKeys(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetKeys(n0,n1,n2))
#define Jsi_ValueGetLength(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetLength(n0,n1))
#define Jsi_ValueGetNumber(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetNumber(n0,n1,n2))
#define Jsi_ValueGetObj(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetObj(n0,n1))
#define Jsi_ValueGetStringLen(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueGetStringLen(n0,n1,n2))
#define Jsi_ValueInsert(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueInsert(n0,n1,n2,n3,n4))
#define Jsi_ValueInsertArray(n0,n1,n2,n3,n4) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueInsertArray(n0,n1,n2,n3,n4))
#define Jsi_ValueInstanceOf(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueInstanceOf(n0,n1,n2))
#define Jsi_ValueIsArray(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsArray(n0,n1))
#define Jsi_ValueIsBoolean(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsBoolean(n0,n1))
#define Jsi_ValueIsEqual(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsEqual(n0,n1,n2))
#define Jsi_ValueIsFalse(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsFalse(n0,n1))
#define Jsi_ValueIsFunction(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsFunction(n0,n1))
#define Jsi_ValueIsNull(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsNull(n0,n1))
#define Jsi_ValueIsNumber(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsNumber(n0,n1))
#define Jsi_ValueIsObjType(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsObjType(n0,n1,n2))
#define Jsi_ValueIsString(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsString(n0,n1))
#define Jsi_ValueIsStringKey(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsStringKey(n0,n1))
#define Jsi_ValueIsTrue(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsTrue(n0,n1))
#define Jsi_ValueIsType(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsType(n0,n1,n2))
#define Jsi_ValueIsUndef(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueIsUndef(n0,n1))
#define Jsi_ValueKeyPresent(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueKeyPresent(n0,n1,n2,n3))
#define Jsi_ValueMakeArrayObject(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeArrayObject(n0,n1,n2))
#define Jsi_ValueMakeBlob(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeBlob(n0,n1,n2,n3))
#define Jsi_ValueMakeBool(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeBool(n0,n1,n2))
#define Jsi_ValueMakeDStringObject(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeDStringObject(n0,n1,n2))
#define Jsi_ValueMakeNull(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeNull(n0,n1))
#define Jsi_ValueMakeNumber(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeNumber(n0,n1,n2))
#define Jsi_ValueMakeObject(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeObject(n0,n1,n2))
#define Jsi_ValueMakeString(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeString(n0,n1,n2))
#define Jsi_ValueMakeStringKey(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeStringKey(n0,n1,n2))
#define Jsi_ValueMakeUndef(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMakeUndef(n0,n1))
#define Jsi_ValueMove(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueMove(n0,n1,n2))
#define Jsi_ValueNewArray(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewArray(n0,n1,n2))
#define Jsi_ValueNewBlob(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewBlob(n0,n1,n2))
#define Jsi_ValueNewBoolean(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewBoolean(n0,n1))
#define Jsi_ValueNewNull(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewNull(n0))
#define Jsi_ValueNewNumber(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewNumber(n0,n1))
#define Jsi_ValueNewObj(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewObj(n0,n1))
#define Jsi_ValueNewString(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewString(n0,n1,n2))
#define Jsi_ValueNewStringConst(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewStringConst(n0,n1,n2))
#define Jsi_ValueNewStringDup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewStringDup(n0,n1))
#define Jsi_ValueNewStringKey(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNewStringKey(n0,n1))
#define Jsi_ValueNormalPath(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueNormalPath(n0,n1,n2))
#define Jsi_ValueObjLookup(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueObjLookup(n0,n1,n2,n3))
#define Jsi_ValueReplace(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueReplace(n0,n1,n2))
#define Jsi_ValueReset(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueReset(n0,n1))
#define Jsi_ValueString(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueString(n0,n1,n2))
#define Jsi_ValueStrlen(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueStrlen(n0))
#define Jsi_ValueToBool(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueToBool(n0,n1))
#define Jsi_ValueToNumber(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueToNumber(n0,n1))
#define Jsi_ValueToNumberInt(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueToNumberInt(n0,n1,n2))
#define Jsi_ValueToObject(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueToObject(n0,n1))
#define Jsi_ValueToString(n0,n1,n2) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueToString(n0,n1,n2))
#define Jsi_ValueTypeGet(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueTypeGet(n0))
#define Jsi_ValueTypeStr(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_ValueTypeStr(n0,n1))
#define Jsi_VarLookup(n0,n1) JSISTUBCALL(jsiStubsPtr, _Jsi_VarLookup(n0,n1))
#define Jsi_Version(n0) JSISTUBCALL(jsiStubsPtr, _Jsi_Version(n0))
#define Jsi_Write(n0,n1,n2,n3) JSISTUBCALL(jsiStubsPtr, _Jsi_Write(n0,n1,n2,n3))

#define __JSI_STUBS_INIT__\
    JSI_STUBS_SIG,    "jsi",    sizeof(Jsi_Stubs),     JSI_STUBS_BLDFLAGS,    JSI_STUBS_MD5,    NULL,\
    Jsi_Stubs__initialize,\
    Jsi_InterpNew,\
    Jsi_InterpDelete,\
    Jsi_InterpOnDelete,\
    Jsi_Interactive,\
    Jsi_InterpGone,\
    Jsi_InterpResult,\
    Jsi_InterpLastError,\
    Jsi_InterpGetData,\
    Jsi_InterpSetData,\
    Jsi_InterpFreeData,\
    Jsi_InterpSafe,\
    Jsi_InterpAccess,\
    Jsi_Main,\
    Jsi_Malloc,\
    Jsi_Calloc,\
    Jsi_Realloc,\
    Jsi_Free,\
    Jsi_ObjIncrRefCount,\
    Jsi_ObjDecrRefCount,\
    Jsi_IncrRefCount,\
    Jsi_DecrRefCount,\
    Jsi_IsShared,\
    Jsi_DeleteData,\
    Jsi_Strlen,\
    Jsi_StrlenSet,\
    Jsi_Strcmp,\
    Jsi_Strncmp,\
    Jsi_Strncasecmp,\
    Jsi_StrcmpDict,\
    Jsi_Strcpy,\
    Jsi_Strncpy,\
    Jsi_Strdup,\
    Jsi_Strrchr,\
    Jsi_Strstr,\
    Jsi_ObjArraySizer,\
    Jsi_Strchr,\
    Jsi_Strpos,\
    Jsi_Strrpos,\
    Jsi_DSAppendLen,\
    Jsi_DSAppend,\
    Jsi_DSFree,\
    Jsi_DSFreeDup,\
    Jsi_DSInit,\
    Jsi_DSLength,\
    Jsi_DSPrintf,\
    Jsi_DSSet,\
    Jsi_DSSetLength,\
    Jsi_DSValue,\
    Jsi_CommandCreate,\
    Jsi_CommandCreateSpecs,\
    Jsi_CommandNewObj,\
    Jsi_CommandInvokeJSON,\
    Jsi_CommandInvoke,\
    Jsi_CommandDelete,\
    Jsi_FunctionGetSpecs,\
    Jsi_FunctionIsConstructor,\
    Jsi_FunctionReturnIgnored,\
    Jsi_FunctionPrivData,\
    Jsi_FunctionArguments,\
    Jsi_FunctionApply,\
    Jsi_FunctionInvoke,\
    Jsi_FunctionInvokeJSON,\
    Jsi_FunctionInvokeBool,\
    Jsi_FunctionInvokeString,\
    Jsi_VarLookup,\
    Jsi_NameLookup,\
    Jsi_NameLookup2,\
    Jsi_PkgProvideEx,\
    Jsi_PkgRequireEx,\
    Jsi_PkgVersion,\
    Jsi_NumUtfBytes,\
    Jsi_NumUtfChars,\
    Jsi_UtfGetIndex,\
    Jsi_UtfAtIndex,\
    Jsi_UniCharToUtf,\
    Jsi_UtfToUniChar,\
    Jsi_UtfToUniCharCase,\
    Jsi_UtfDecode,\
    Jsi_UtfEncode,\
    Jsi_UtfSubstr,\
    Jsi_UtfIndexToOffset,\
    Jsi_ObjNew,\
    Jsi_ObjNewType,\
    Jsi_ObjFree,\
    Jsi_ObjNewObj,\
    Jsi_ObjNewArray,\
    Jsi_ObjIsArray,\
    Jsi_ObjSetLength,\
    Jsi_ObjGetLength,\
    Jsi_ObjTypeStr,\
    Jsi_ObjTypeGet,\
    Jsi_ObjListifyArray,\
    Jsi_ObjArraySet,\
    Jsi_ObjArrayAdd,\
    Jsi_ObjInsert,\
    Jsi_ObjFromDS,\
    Jsi_ValueNew,\
    Jsi_ValueNew1,\
    Jsi_ValueFree,\
    Jsi_ValueNewNull,\
    Jsi_ValueNewBoolean,\
    Jsi_ValueNewNumber,\
    Jsi_ValueNewBlob,\
    Jsi_ValueNewString,\
    Jsi_ValueNewStringKey,\
    Jsi_ValueNewStringDup,\
    Jsi_ValueNewArray,\
    Jsi_ValueNewObj,\
    Jsi_GetStringFromValue,\
    Jsi_GetNumberFromValue,\
    Jsi_GetBoolFromValue,\
    Jsi_GetIntFromValue,\
    Jsi_GetLongFromValue,\
    Jsi_GetWideFromValue,\
    Jsi_GetDoubleFromValue,\
    Jsi_GetIntFromValueBase,\
    Jsi_ValueGetBoolean,\
    Jsi_ValueGetNumber,\
    Jsi_ValueIsType,\
    Jsi_ValueIsObjType,\
    Jsi_ValueIsTrue,\
    Jsi_ValueIsFalse,\
    Jsi_ValueIsNumber,\
    Jsi_ValueIsArray,\
    Jsi_ValueIsBoolean,\
    Jsi_ValueIsNull,\
    Jsi_ValueIsUndef,\
    Jsi_ValueIsFunction,\
    Jsi_ValueIsString,\
    Jsi_ValueMakeObject,\
    Jsi_ValueMakeArrayObject,\
    Jsi_ValueMakeNumber,\
    Jsi_ValueMakeBool,\
    Jsi_ValueMakeString,\
    Jsi_ValueMakeStringKey,\
    Jsi_ValueMakeBlob,\
    Jsi_ValueMakeNull,\
    Jsi_ValueMakeUndef,\
    Jsi_ValueMakeDStringObject,\
    Jsi_ValueIsStringKey,\
    Jsi_ValueToString,\
    Jsi_ValueToBool,\
    Jsi_ValueToNumber,\
    Jsi_ValueToNumberInt,\
    Jsi_ValueToObject,\
    Jsi_ValueReset,\
    Jsi_ValueGetDString,\
    Jsi_ValueString,\
    Jsi_ValueBlob,\
    Jsi_ValueGetStringLen,\
    Jsi_ValueStrlen,\
    Jsi_ValueFromDS,\
    Jsi_ValueInstanceOf,\
    Jsi_ValueGetObj,\
    Jsi_ValueTypeGet,\
    Jsi_ValueTypeStr,\
    Jsi_ValueCmp,\
    Jsi_ValueGetIndex,\
    Jsi_ValueArraySort,\
    Jsi_ValueArrayConcat,\
    Jsi_ValueArrayPush,\
    Jsi_ValueArrayPop,\
    Jsi_ValueArrayShift,\
    Jsi_ValueArrayUnshift,\
    Jsi_ValueArrayIndex,\
    Jsi_ValueArrayIndexToStr,\
    Jsi_ValueInsert,\
    Jsi_ValueGetLength,\
    Jsi_ValueObjLookup,\
    Jsi_ValueKeyPresent,\
    Jsi_ValueGetKeys,\
    Jsi_ValueCopy,\
    Jsi_ValueReplace,\
    Jsi_ValueDup2,\
    Jsi_ValueDupJSON,\
    Jsi_ValueMove,\
    Jsi_ValueIsEqual,\
    Jsi_UserObjRegister,\
    Jsi_UserObjUnregister,\
    Jsi_UserObjNew,\
    Jsi_UserObjGetData,\
    Jsi_NumberToString,\
    Jsi_Version,\
    Jsi_ReturnValue,\
    Jsi_Mount,\
    Jsi_Executable,\
    Jsi_RegExpNew,\
    Jsi_RegExpFree,\
    Jsi_RegExpMatch,\
    Jsi_RegExpMatches,\
    Jsi_GlobMatch,\
    Jsi_FileRealpath,\
    Jsi_FileRealpathStr,\
    Jsi_NormalPath,\
    Jsi_ValueNormalPath,\
    Jsi_JSONParse,\
    Jsi_JSONParseFmt,\
    Jsi_JSONQuote,\
    Jsi_EvalString,\
    Jsi_EvalFile,\
    Jsi_EvalCmdJSON,\
    Jsi_EvalZip,\
    Jsi_DictionaryCompare,\
    Jsi_GetBool,\
    Jsi_GetInt,\
    Jsi_GetWide,\
    Jsi_GetDouble,\
    Jsi_FormatString,\
    Jsi_SplitStr,\
    Jsi_Sleep,\
    Jsi_Preserve,\
    Jsi_Release,\
    Jsi_EventuallyFree,\
    Jsi_ShiftArgs,\
    Jsi_StringSplit,\
    Jsi_GetIndex,\
    Jsi_PrototypeGet,\
    Jsi_PrototypeDefine,\
    Jsi_PrototypeObjSet,\
    Jsi_ThisDataSet,\
    Jsi_ThisDataGet,\
    Jsi_FuncObjToString,\
    Jsi_UserObjDataFromVar,\
    Jsi_KeyAdd,\
    Jsi_KeyLookup,\
    Jsi_DatetimeFormat,\
    Jsi_DatetimeParse,\
    Jsi_DateTime,\
    Jsi_Encrypt,\
    Jsi_CryptoHash,\
    Jsi_Base64,\
    Jsi_HexStr,\
    Jsi_Strrstr,\
    Jsi_Crc32,\
    Jsi_NumberIsInfinity,\
    Jsi_NumberIsEqual,\
    Jsi_NumberIsFinite,\
    Jsi_NumberIsInteger,\
    Jsi_NumberIsNaN,\
    Jsi_NumberIsNormal,\
    Jsi_NumberIsSubnormal,\
    Jsi_NumberIsWide,\
    Jsi_NumberInfinity,\
    Jsi_NumberNaN,\
    Jsi_NumberDtoA,\
    Jsi_NumberItoA10,\
    Jsi_NumberUtoA10,\
    Jsi_HashNew,\
    Jsi_HashConf,\
    Jsi_HashDelete,\
    Jsi_HashClear,\
    Jsi_HashSet,\
    Jsi_HashGet,\
    Jsi_HashUnset,\
    Jsi_HashKeyGet,\
    Jsi_HashKeysDump,\
    Jsi_HashValueGet,\
    Jsi_HashValueSet,\
    Jsi_HashEntryFind,\
    Jsi_HashEntryNew,\
    Jsi_HashEntryDelete,\
    Jsi_HashSearchFirst,\
    Jsi_HashSearchNext,\
    Jsi_HashSize,\
    Jsi_TreeNew,\
    Jsi_TreeConf,\
    Jsi_TreeDelete,\
    Jsi_TreeClear,\
    Jsi_TreeObjSetValue,\
    Jsi_TreeObjGetValue,\
    Jsi_TreeValueGet,\
    Jsi_TreeValueSet,\
    Jsi_TreeKeyGet,\
    Jsi_TreeEntryFind,\
    Jsi_TreeEntryNew,\
    Jsi_TreeEntryDelete,\
    Jsi_TreeSearchFirst,\
    Jsi_TreeSearchNext,\
    Jsi_TreeSearchDone,\
    Jsi_TreeWalk,\
    Jsi_TreeSet,\
    Jsi_TreeGet,\
    Jsi_TreeUnset,\
    Jsi_TreeSize,\
    Jsi_TreeFromValue,\
    Jsi_TreeKeysDump,\
    Jsi_ListNew,\
    Jsi_ListConf,\
    Jsi_ListDelete,\
    Jsi_ListClear,\
    Jsi_ListValueGet,\
    Jsi_ListValueSet,\
    Jsi_ListEntryNew,\
    Jsi_ListEntryDelete,\
    Jsi_ListSearchFirst,\
    Jsi_ListSearchNext,\
    Jsi_ListSize,\
    Jsi_ListPush,\
    Jsi_ListPop,\
    Jsi_StackNew,\
    Jsi_StackFree,\
    Jsi_StackSize,\
    Jsi_StackPush,\
    Jsi_StackPop,\
    Jsi_StackPeek,\
    Jsi_StackUnshift,\
    Jsi_StackHead,\
    Jsi_StackFreeElements,\
    Jsi_MapNew,\
    Jsi_MapConf,\
    Jsi_MapDelete,\
    Jsi_MapClear,\
    Jsi_MapSet,\
    Jsi_MapGet,\
    Jsi_MapKeyGet,\
    Jsi_MapKeysDump,\
    Jsi_MapValueGet,\
    Jsi_MapValueSet,\
    Jsi_MapEntryFind,\
    Jsi_MapEntryNew,\
    Jsi_MapEntryDelete,\
    Jsi_MapSearchFirst,\
    Jsi_MapSearchNext,\
    Jsi_MapSearchDone,\
    Jsi_MapSize,\
    Jsi_OptionTypeInfo,\
    Jsi_TypeLookup,\
    Jsi_OptionsProcess,\
    Jsi_OptionsProcessJSON,\
    Jsi_OptionsConf,\
    Jsi_OptionsFree,\
    Jsi_OptionsGet,\
    Jsi_OptionsSet,\
    Jsi_OptionsDump,\
    Jsi_OptionsChanged,\
    Jsi_OptionsValid,\
    Jsi_OptionsFind,\
    Jsi_OptionsCustomPrint,\
    Jsi_OptionCustomBuiltin,\
    Jsi_OptionsDup,\
    Jsi_OptionSpecsCached,\
    Jsi_MutexLock,\
    Jsi_MutexUnlock,\
    Jsi_MutexDelete,\
    Jsi_MutexNew,\
    Jsi_CurrentThread,\
    Jsi_InterpThread,\
    Jsi_LogMsg,\
    Jsi_EventNew,\
    Jsi_EventFree,\
    Jsi_EventProcess,\
    Jsi_JsonInit,\
    Jsi_JsonReset,\
    Jsi_JsonFree,\
    Jsi_JsonParse,\
    Jsi_JsonGetToken,\
    Jsi_JsonGetType,\
    Jsi_JsonTokLen,\
    Jsi_JsonGetTokstr,\
    Jsi_JsonGetTypename,\
    Jsi_JsonGetErrname,\
    Jsi_JsonDump,\
    Jsi_FSRegister,\
    Jsi_FSUnregister,\
    Jsi_FSNameToChannel,\
    Jsi_GetCwd,\
    Jsi_Lstat,\
    Jsi_Stat,\
    Jsi_Access,\
    Jsi_Remove,\
    Jsi_Rename,\
    Jsi_Chdir,\
    Jsi_Open,\
    Jsi_Eof,\
    Jsi_Close,\
    Jsi_Read,\
    Jsi_Write,\
    Jsi_Seek,\
    Jsi_Tell,\
    Jsi_Truncate,\
    Jsi_Rewind,\
    Jsi_Flush,\
    Jsi_Getc,\
    Jsi_Printf,\
    Jsi_Ungetc,\
    Jsi_Gets,\
    Jsi_Puts,\
    Jsi_Scandir,\
    Jsi_SetChannelOption,\
    Jsi_Realpath,\
    Jsi_Readlink,\
    Jsi_GetStdChannel,\
    Jsi_FSNative,\
    Jsi_Link,\
    Jsi_Chmod,\
    Jsi_StubLookup,\
    Jsi_AddAutoFiles,\
    Jsi_DbNew,\
    Jsi_DbHandle,\
    Jsi_DbQuery,\
    Jsi_CDataLookup,\
    Jsi_CDataRegister,\
    Jsi_CDataStructInit,\
    Jsi_DllLookup,\
    Jsi_LoadLibrary,\
    Jsi_CDataStruct,\
    Jsi_StrdupLen,\
    Jsi_FileRead,\
    Jsi_ValueNewStringConst,\
    Jsi_PathNormalize,\
    Jsi_ValueInsertArray,\
    Jsi_IterObjNew,\
    Jsi_IterObjFree,\
    Jsi_IterGetKeys,\
    Jsi_IsReserved,\
    Jsi_StrIsAlnum,\
    Jsi_SqlObjBinds,\
    Jsi_UserObjName,\
    NULL



#define JSI_WIDE_MAX LLONG_MAX
#define JSI_WIDE_MIN LLONG_MIN
#define JSI_WIDE_MODIFIER "I64d"

    #define LLONG_MAX    9223372036854775807I64
    #define LLONG_MIN    (-LLONG_MAX - 1I64)
#define MAXNAMLEN FILENAME_MAX 
#define jsi_wide _int64
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strtoull _strtoui64
#define CHARCLASS_NAME_MAX 14
#define REG_BADBR       10
#define REG_BADPAT      2
#define REG_BADRPT      13
#define REG_EBRACE      9
#define REG_EBRACK      7
#define REG_ECOLLATE    3
#define REG_ECTYPE      4
#define REG_EESCAPE     5
#define REG_ENOSYS      -1
#define REG_EPAREN      8
#define REG_ERANGE      11
#define REG_ESPACE      12
#define REG_ESUBREG     6
#define REG_EXTENDED    1
#define REG_ICASE       2
#define REG_NEWLINE     4
#define REG_NOMATCH     1
#define REG_NOSUB       8
#define REG_NOTBOL      1
#define REG_NOTEOL      2
#define REG_OK          0
#define RE_DUP_MAX 255



#define regoff_t int
