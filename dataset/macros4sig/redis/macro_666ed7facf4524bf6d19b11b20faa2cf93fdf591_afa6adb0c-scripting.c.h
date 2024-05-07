

#include<stddef.h>
#include<ctype.h>
#include<unistd.h>
#include<stdarg.h>

#include<assert.h>
#include<stdio.h>


#include<math.h>


#include<limits.h>


#define lua_assert(x)	((void)0)

#define LUA_AUTHORS 	"R. Ierusalimschy, L. H. de Figueiredo & W. Celes"
#define LUA_HOOKTAILRET 4
#define lua_getgccount(L)	lua_gc(L, LUA_GCCOUNT, 0)
#define lua_getglobal(L,s)	lua_getfield(L, LUA_GLOBALSINDEX, (s))
#define lua_getregistry(L)	lua_pushvalue(L, LUA_REGISTRYINDEX)

#define lua_isboolean(L,n)	(lua_type(L, (n)) == LUA_TBOOLEAN)
#define lua_isfunction(L,n)	(lua_type(L, (n)) == LUA_TFUNCTION)
#define lua_islightuserdata(L,n)	(lua_type(L, (n)) == LUA_TLIGHTUSERDATA)
#define lua_isnil(L,n)		(lua_type(L, (n)) == LUA_TNIL)
#define lua_isnone(L,n)		(lua_type(L, (n)) == LUA_TNONE)
#define lua_isnoneornil(L, n)	(lua_type(L, (n)) <= 0)
#define lua_istable(L,n)	(lua_type(L, (n)) == LUA_TTABLE)
#define lua_isthread(L,n)	(lua_type(L, (n)) == LUA_TTHREAD)
#define lua_newtable(L)		lua_createtable(L, 0, 0)
#define lua_open()	luaL_newstate()
#define lua_pop(L,n)		lua_settop(L, -(n)-1)
#define lua_pushcfunction(L,f)	lua_pushcclosure(L, (f), 0)
#define lua_pushliteral(L, s)	\
	lua_pushlstring(L, "" s, (sizeof(s)/sizeof(char))-1)
#define lua_register(L,n,f) (lua_pushcfunction(L, (f)), lua_setglobal(L, (n)))
#define lua_setglobal(L,s)	lua_setfield(L, LUA_GLOBALSINDEX, (s))
#define lua_strlen(L,i)		lua_objlen(L, (i))
#define lua_tostring(L,i)	lua_tolstring(L, (i), NULL)
#define lua_upvalueindex(i)	(LUA_GLOBALSINDEX-(i))
#define LUAI_THROW(L,c)	throw(c)
#define LUAI_TRY(L,c,a)	try { a } catch(...) \
	{ if ((c)->status == 0) (c)->status = -1; }

#define LUA_API __declspec(dllexport)




#define LUA_CPATH       "LUA_CPATH"
#define LUA_CPATH_DEFAULT \
	"./?.so;"  LUA_CDIR"?.so;" LUA_CDIR"loadall.so"



#define LUA_PATH        "LUA_PATH"
#define LUA_PATH_DEFAULT  \
		"./?.lua;"  LUA_LDIR"?.lua;"  LUA_LDIR"?/init.lua;" \
		            LUA_CDIR"?.lua;"  LUA_CDIR"?/init.lua"
#define LUA_QL(x)	"'" x "'"







#define lua_freeline(L,b)	((void)L, free(b))
#define lua_number2int(i,d)   __asm fld d   __asm fistp i
#define lua_number2integer(i,n)		lua_number2int(i, n)
#define lua_number2str(s,n)	sprintf((s), LUA_NUMBER_FMT, (n))
#define lua_pclose(L,file)	((void)L, (pclose(file) != -1))
#define lua_popen(L,c,m)	((void)L, fflush(NULL), popen(c,m))
#define lua_readline(L,b,p)	((void)L, ((b)=readline(p)) != NULL)
#define lua_saveline(L,idx) \
	if (lua_strlen(L,idx) > 0)   \
	  add_history(lua_tostring(L, idx));  
#define lua_stdin_is_tty()	isatty(0)
#define lua_str2number(s,p)	strtod((s), (p))
#define lua_tmpnam(b,e)	{ \
	strcpy(b, "/tmp/lua_XXXXXX"); \
	e = mkstemp(b); \
	if (e != -1) close(e); \
	e = (e == -1); }
#define luai_apicheck(L,o)	{ (void)L; assert(o); }
#define luai_numadd(a,b)	((a)+(b))
#define luai_numdiv(a,b)	((a)/(b))
#define luai_numeq(a,b)		((a)==(b))
#define luai_numisnan(a)	(!luai_numeq((a), (a)))
#define luai_numle(a,b)		((a)<=(b))
#define luai_numlt(a,b)		((a)<(b))
#define luai_nummod(a,b)	((a) - floor((a)/(b))*(b))
#define luai_nummul(a,b)	((a)*(b))
#define luai_numpow(a,b)	(pow(a,b))
#define luai_numsub(a,b)	((a)-(b))
#define luai_numunm(a)		(-(a))
#define luai_userstateclose(L)		((void)L)
#define luai_userstatefree(L)		((void)L)
#define luai_userstateopen(L)		((void)L)
#define luai_userstateresume(L,n)	((void)L)
#define luai_userstatethread(L,L1)	((void)L)
#define luai_userstateyield(L,n)	((void)L)
#define LUA_ERRFILE     (LUA_ERRERR+1)
#define LUA_NOREF       (-2)
#define LUA_REFNIL      (-1)

#define luaL_addchar(B,c) \
  ((void)((B)->p < ((B)->buffer+LUAL_BUFFERSIZE) || luaL_prepbuffer(B)), \
   (*(B)->p++ = (char)(c)))
#define luaL_addsize(B,n)	((B)->p += (n))
#define luaL_argcheck(L, cond,numarg,extramsg)	\
		((void)((cond) || luaL_argerror(L, (numarg), (extramsg))))
#define luaL_checklong(L,n)	((long)luaL_checkinteger(L, (n)))
#define luaL_checkstring(L,n)	(luaL_checklstring(L, (n), NULL))
#define luaL_dofile(L, fn) \
	(luaL_loadfile(L, fn) || lua_pcall(L, 0, LUA_MULTRET, 0))
#define luaL_dostring(L, s) \
	(luaL_loadstring(L, s) || lua_pcall(L, 0, LUA_MULTRET, 0))
#define luaL_getmetatable(L,n)	(lua_getfield(L, LUA_REGISTRYINDEX, (n)))
#define luaL_getn(L,i)          ((int)lua_objlen(L, i))
#define luaL_opt(L,f,n,d)	(lua_isnoneornil(L,(n)) ? (d) : f(L,(n)))
#define luaL_optlong(L,n,d)	((long)luaL_optinteger(L, (n), (d)))
#define luaL_optstring(L,n,d)	(luaL_optlstring(L, (n), (d), NULL))
#define luaL_putchar(B,c)	luaL_addchar(B,c)
#define luaL_setn(L,i,j)        ((void)0)  
#define luaL_typename(L,i)	lua_typename(L, lua_type(L,(i)))
#define lua_getref(L,ref)       lua_rawgeti(L, LUA_REGISTRYINDEX, (ref))
#define lua_ref(L,lock) ((lock) ? luaL_ref(L, LUA_REGISTRYINDEX) : \
      (lua_pushstring(L, "unlocked references are obsolete"), lua_error(L), 0))
#define lua_unref(L,ref)        luaL_unref(L, LUA_REGISTRYINDEX, (ref))
