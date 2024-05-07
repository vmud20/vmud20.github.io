









#include<time.h>



#include<string.h>










#include<assert.h>
#define IMP_LUA_SK(TYPE,type)   \
TAB2SK(TYPE,type);              \
SK2TAB(TYPE,type)
#define REF_OR_DUP(TYPE, x)  CRYPTO_add(&x->references,1,CRYPTO_LOCK_##TYPE)
#define SK2TAB(TYPE,type)  int openssl_sk_##type##_totable(lua_State* L,const STACK_OF(TYPE) *sk)  {  \
  int i=0, n=0;                                                                           \
  lua_newtable(L);                                                                        \
  n = SKM_sk_num(TYPE, sk);                                                               \
  for(i=0;i<n;i++) {                                                                      \
    TYPE *x =  SKM_sk_value(TYPE, sk, i);                                                 \
    REF_OR_DUP(TYPE, x);                                                                  \
    PUSH_OBJECT(x,"openssl."#type);                                                       \
    lua_rawseti(L,-2, i+1);                                                               \
  }                                                                                       \
  return 1;                                                                               \
}
#define TAB2SK(TYPE, type)                                        \
STACK_OF(TYPE)* openssl_sk_##type##_fromtable(lua_State*L, int idx) {     \
  STACK_OF(TYPE) * sk;                                            \
  luaL_argcheck(L, lua_istable(L, idx),  idx,                     \
         "must be a table as array or nil");                      \
  sk = SKM_sk_new_null(TYPE);                                     \
  if (lua_istable(L,idx)) {                                       \
    int n = lua_rawlen(L, idx);                                   \
    int i;                                                        \
    for ( i=0; i<n; i++ ) {                                       \
      TYPE *x;                                                    \
      lua_rawgeti(L, idx, i+1);                                   \
      x = CHECK_OBJECT(-1,TYPE,"openssl." #type);                 \
      REF_OR_DUP(TYPE, x);                                        \
      SKM_sk_push(TYPE, sk, x);                                   \
      lua_pop(L,1);                                               \
    }                                                             \
  }                                                               \
  return sk;                                                      \
}
#define CHECK_GROUP(n,type,name)  *(type**)auxiliar_checkgroup(L,name,n)
#define CHECK_OBJECT(n,type,name) *(type**)auxiliar_checkclass(L,name,n)
#define FREE_OBJECT(i)  (*(void**)lua_touserdata(L, i) = NULL)
#define GET_GROUP(n,type,name)  ((type*)openssl_getgroup(L,name,n))
#define GET_OBJECT(n,type,name) ((type*)openssl_getclass(L,name,n))
#define LHASH LHASH_OF(CONF_VALUE)
#define LOPENSSL_VERSION  "0.7.7"
#define LOPENSSL_VERSION_NUM  0x0070700f

#define LUA_FUNCTION(X) int X(lua_State *L)
#define MAX_PATH 260
#define MULTI_LINE_MACRO_BEGIN do {
#define MULTI_LINE_MACRO_END  \
__pragma(warning(push))   \
__pragma(warning(disable:4127)) \
} while(0)      \
__pragma(warning(pop))

#define PUSH_OBJECT(o, tname)                                   \
  MULTI_LINE_MACRO_BEGIN                                        \
  if(o) {                                                       \
  *(void **)(lua_newuserdata(L, sizeof(void *))) = (void*)(o);  \
  auxiliar_setclass(L,tname,-1);                                \
  } else lua_pushnil(L);                                        \
  MULTI_LINE_MACRO_END
#  define inline __inline
#define snprintf _snprintf
#define strcasecmp stricmp
#define timezone _timezone  
#define AUXILIAR_SETOBJECT(L, cval, ltype, idx, lvar) \
  do {                                                \
  int n = (idx < 0)?idx-1:idx;                        \
  PUSH_OBJECT(cval,ltype);                            \
  lua_setfield(L, n, lvar);                           \
  } while(0)
#define CONSTIFY_OPENSSL const
#define CONSTIFY_X509_get0 CONSTIFY_OPENSSL

#define OPENSSL_PKEY_GET_BN(bn, _name)    \
  if (bn != NULL) {                       \
  BIGNUM* b = BN_dup(bn);                 \
  PUSH_OBJECT(b,"openssl.bn");            \
  lua_setfield(L,-2,#_name);              \
  }
#define OPENSSL_PKEY_SET_BN(n, _type, _name)  {             \
  lua_getfield(L,n,#_name);                                 \
  if(lua_isstring(L,-1)) {                                  \
  size_t l = 0;                                             \
  const char* bn = luaL_checklstring(L,-1,&l);              \
  if(_type->_name==NULL)  _type->_name = BN_new();          \
  BN_bin2bn((const unsigned char *)bn,l,_type->_name);      \
  }else if(auxiliar_getclassudata(L,"openssl.bn",-1)) {           \
  const BIGNUM* bn = CHECK_OBJECT(-1,BIGNUM,"openssl.bn");  \
  if(_type->_name==NULL)  _type->_name = BN_new();          \
  BN_copy(_type->_name, bn);                                \
  }else if(!lua_isnil(L,-1))                                \
  luaL_error(L,"arg #%d must have \"%s\" field string or openssl.bn",n,#_name);   \
  lua_pop(L,1);                                             \
}


#define PUSH_ASN1_INTEGER(L, i)           openssl_push_asn1(L, (ASN1_STRING*)(i),  V_ASN1_INTEGER)
#define PUSH_ASN1_OCTET_STRING(L, s)      openssl_push_asn1(L, (ASN1_STRING*)(s),  V_ASN1_OCTET_STRING)
#define PUSH_ASN1_STRING(L, s)            openssl_push_asn1(L, (ASN1_STRING*)(s),  V_ASN1_UNDEF)
#define PUSH_ASN1_TIME(L, tm)             openssl_push_asn1(L, (ASN1_STRING*)(tm), V_ASN1_UTCTIME)
#define PUSH_BN(x)                                      \
  *(void **)(lua_newuserdata(L, sizeof(void *))) = (x); \
  luaL_getmetatable(L,"openssl.bn");                    \
  lua_setmetatable(L,-2)
#define luaG_registerlibfuncs( L, _funcs) luaL_setfuncs( L, _funcs, 0)
#define luaL_checkint(L,n) ((int)luaL_checkinteger(L, (n)))
#define luaL_checklong(L,n) ((long)luaL_checkinteger(L, (n)))
#define luaL_checktable(L, n) luaL_checktype(L, n, LUA_TTABLE)
#define luaL_optint(L,n,d) ((int)luaL_optinteger(L, (n), (d)))
#define luaL_optlong(L,n,d) ((long)luaL_optinteger(L, (n), (d)))
#define lua_equal( L, a, b) lua_compare( L, a, b, LUA_OPEQ)
#define lua_lessthan( L, a, b) lua_compare( L, a, b, LUA_OPLT)
