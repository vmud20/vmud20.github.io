#include<float.h>

#include<math.h>
#include<stdint.h>

#include<assert.h>
#include<stdarg.h>
#include<stdlib.h>
#include<string.h>
#include<stddef.h>


#include<signal.h>



#include<stdio.h>
#include<limits.h>


#define vmcase(l)     L_##l:
#define vmdispatch(x)     goto *disptab[x];
#define cvt2num(o)	ttisstring(o)
#define cvt2str(o)	ttisnumber(o)
#define intop(op,v1,v2) l_castU2S(l_castS2U(v1) op l_castS2U(v2))
#define luaV_fastget(L,t,k,slot,f) \
  (!ttistable(t)  \
   ? (slot = NULL, 0)    \
   : (slot = f(hvalue(t), k),    \
      !isempty(slot)))  
#define luaV_fastgeti(L,t,k,slot) \
  (!ttistable(t)  \
   ? (slot = NULL, 0)    \
   : (slot = (l_castS2U(k) - 1u < hvalue(t)->alimit) \
              ? &hvalue(t)->array[k - 1] : luaH_getint(hvalue(t), k), \
      !isempty(slot)))  
#define luaV_finishfastset(L,t,slot,v) \
    { setobj2t(L, cast(TValue *,slot), v); \
      luaC_barrierback(L, gcvalue(t), v); }
#define luaV_rawequalobj(t1,t2)		luaV_equalobj(NULL,t1,t2)

#define tointeger(o,i) \
  (ttisinteger(o) ? (*(i) = ivalue(o), 1) : luaV_tointeger(o,i,LUA_FLOORN2I))
#define tointegerns(o,i) \
  (ttisinteger(o) ? (*(i) = ivalue(o), 1) : luaV_tointegerns(o,i,LUA_FLOORN2I))
#define tonumber(o,n) \
	(ttisfloat(o) ? (*(n) = fltvalue(o), 1) : luaV_tonumber_(o,n))
#define tonumberns(o,n) \
	(ttisfloat(o) ? ((n) = fltvalue(o), 1) : \
	(ttisinteger(o) ? ((n) = cast_num(ivalue(o)), 1) : 0))
#define gfasttm(g,et,e) ((et) == NULL ? NULL : \
  ((et)->flags & (1u<<(e))) ? NULL : luaT_gettm(et, e, (g)->tmname[e]))

#define notm(tm)	ttisnil(tm)
#define ttypename(x)	luaT_typenames_[(x) + 1]
#define ClosureHeader \
	CommonHeader; lu_byte nupvalues; GCObject *gclist
#define checkliveness(L,obj) \
	((void)L, lua_longassert(!iscollectable(obj) || \
		(righttt(obj) && (L == NULL || !isdead(G(L),gcvalue(obj))))))
#define checktag(o,t)		(rawtt(o) == (t))
#define checktype(o,t)		(ttype(o) == (t))
#define chgfltvalue(obj,x) \
  { TValue *io=(obj); lua_assert(ttisfloat(io)); val_(io).n=(x); }
#define chgivalue(obj,x) \
  { TValue *io=(obj); lua_assert(ttisinteger(io)); val_(io).i=(x); }
#define clCvalue(o)	check_exp(ttisCclosure(o), gco2ccl(val_(o).gc))
#define clLvalue(o)	check_exp(ttisLclosure(o), gco2lcl(val_(o).gc))
#define clvalue(o)	check_exp(ttisclosure(o), gco2cl(val_(o).gc))
#define ctb(t)			((t) | BIT_ISCOLLECTABLE)
#define fltvalue(o)	check_exp(ttisfloat(o), val_(o).n)
#define fltvalueraw(v)	((v).n)
#define fvalue(o)	check_exp(ttislcf(o), val_(o).f)
#define fvalueraw(v)	((v).f)
#define gckey(n)	(keyval(n).gc)
#define gckeyN(n)	(keyiscollectable(n) ? gckey(n) : NULL)
#define gcvalue(o)	check_exp(iscollectable(o), val_(o).gc)
#define gcvalueraw(v)	((v).gc)
#define getnodekey(L,obj,node) \
	{ TValue *io_=(obj); const Node *n_=(node); \
	  io_->value_ = n_->u.key_val; io_->tt_ = n_->u.key_tt; \
	  checkliveness(L,io_); }
#define getproto(o)	(clLvalue(o)->p)
#define getstr(ts)  ((ts)->contents)
#define getudatamem(u)	(cast_charp(u) + udatamemoffset((u)->nuvalue))
#define hvalue(o)	check_exp(ttistable(o), gco2t(val_(o).gc))
#define isLfunction(o)	ttisLclosure(o)
#define isabstkey(v)		checktag((v), LUA_VABSTKEY)
#define iscollectable(o)	(rawtt(o) & BIT_ISCOLLECTABLE)
#define isempty(v)		ttisnil(v)
#define isnonstrictnil(v)	(ttisnil(v) && !ttisstrictnil(v))
#define isrealasize(t)		(!((t)->marked & BITRAS))
#define ivalue(o)	check_exp(ttisinteger(o), val_(o).i)
#define ivalueraw(v)	((v).i)
#define keyiscollectable(n)	(keytt(n) & BIT_ISCOLLECTABLE)
#define keyisinteger(node)	(keytt(node) == LUA_VNUMINT)
#define keyisnil(node)		(keytt(node) == LUA_TNIL)
#define keyisshrstr(node)	(keytt(node) == ctb(LUA_VSHRSTR))
#define keyival(node)		(keyval(node).i)
#define keystrval(node)		(gco2ts(keyval(node).gc))
#define keytt(node)		((node)->u.key_tt)
#define keyval(node)		((node)->u.key_val)
#define l_isfalse(o)	(ttisfalse(o) || ttisnil(o))
#define lmod(s,size) \
	(check_exp((size&(size-1))==0, (cast_int((s) & ((size)-1)))))

#define makevariant(t,v)	((t) | ((v) << 4))
#define novariant(t)	((t) & 0x0F)
#define nvalue(o)	check_exp(ttisnumber(o), \
	(ttisinteger(o) ? cast_num(ivalue(o)) : fltvalue(o)))
#define pvalue(o)	check_exp(ttislightuserdata(o), val_(o).p)
#define pvalueraw(v)	((v).p)
#define rawtt(o)	((o)->tt_)
#define righttt(obj)		(ttypetag(obj) == gcvalue(obj)->tt)
#define s2v(o)	(&(o)->val)
#define setbfvalue(obj)		settt_(obj, LUA_VFALSE)
#define setbtvalue(obj)		settt_(obj, LUA_VTRUE)
#define setclCvalue(L,obj,x) \
  { TValue *io = (obj); CClosure *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_VCCL)); \
    checkliveness(L,io); }
#define setclLvalue(L,obj,x) \
  { TValue *io = (obj); LClosure *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_VLCL)); \
    checkliveness(L,io); }
#define setclLvalue2s(L,o,cl)	setclLvalue(L,s2v(o),cl)
#define setdeadkey(n)	(keytt(n) = LUA_TTABLE, gckey(n) = NULL)
#define setempty(v)		settt_(v, LUA_VEMPTY)
#define setfltvalue(obj,x) \
  { TValue *io=(obj); val_(io).n=(x); settt_(io, LUA_VNUMFLT); }
#define setfvalue(obj,x) \
  { TValue *io=(obj); val_(io).f=(x); settt_(io, LUA_VLCF); }
#define setgcovalue(L,obj,x) \
  { TValue *io = (obj); GCObject *i_g=(x); \
    val_(io).gc = i_g; settt_(io, ctb(i_g->tt)); }
#define sethvalue(L,obj,x) \
  { TValue *io = (obj); Table *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_VTABLE)); \
    checkliveness(L,io); }
#define sethvalue2s(L,o,h)	sethvalue(L,s2v(o),h)
#define setivalue(obj,x) \
  { TValue *io=(obj); val_(io).i=(x); settt_(io, LUA_VNUMINT); }
#define setnilkey(node)		(keytt(node) = LUA_TNIL)
#define setnilvalue(obj) settt_(obj, LUA_VNIL)
#define setnodekey(L,node,obj) \
	{ Node *n_=(node); const TValue *io_=(obj); \
	  n_->u.key_val = io_->value_; n_->u.key_tt = io_->tt_; \
	  checkliveness(L,io_); }
#define setnorealasize(t)	((t)->marked |= BITRAS)
#define setobj(L,obj1,obj2) \
	{ TValue *io1=(obj1); const TValue *io2=(obj2); \
          io1->value_ = io2->value_; settt_(io1, io2->tt_); \
	  checkliveness(L,io1); lua_assert(!isnonstrictnil(io1)); }
#define setobj2s(L,o1,o2)	setobj(L,s2v(o1),o2)
#define setobjs2s(L,o1,o2)	setobj(L,s2v(o1),s2v(o2))
#define setpvalue(obj,x) \
  { TValue *io=(obj); val_(io).p=(x); settt_(io, LUA_VLIGHTUSERDATA); }
#define setrealasize(t)		((t)->marked &= cast_byte(~BITRAS))
#define setsvalue(L,obj,x) \
  { TValue *io = (obj); TString *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(x_->tt)); \
    checkliveness(L,io); }
#define setsvalue2s(L,o,s)	setsvalue(L,s2v(o),s)
#define setthvalue(L,obj,x) \
  { TValue *io = (obj); lua_State *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_VTHREAD)); \
    checkliveness(L,io); }
#define setthvalue2s(L,o,t)	setthvalue(L,s2v(o),t)
#define settt_(o,t)	((o)->tt_=(t))
#define setuvalue(L,obj,x) \
  { TValue *io = (obj); Udata *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_VUSERDATA)); \
    checkliveness(L,io); }
#define sizeudata(nuv,nb)	(udatamemoffset(nuv) + (nb))
#define svalue(o)       getstr(tsvalue(o))
#define thvalue(o)	check_exp(ttisthread(o), gco2th(val_(o).gc))
#define tsslen(s)	((s)->tt == LUA_VSHRSTR ? (s)->shrlen : (s)->u.lnglen)
#define tsvalue(o)	check_exp(ttisstring(o), gco2ts(val_(o).gc))
#define tsvalueraw(v)	(gco2ts((v).gc))
#define ttisCclosure(o)		checktag((o), ctb(LUA_VCCL))
#define ttisLclosure(o)		checktag((o), ctb(LUA_VLCL))
#define ttisboolean(o)		checktype((o), LUA_TBOOLEAN)
#define ttisclosure(o)		((rawtt(o) & 0x1F) == LUA_VLCL)
#define ttisfalse(o)		checktag((o), LUA_VFALSE)
#define ttisfloat(o)		checktag((o), LUA_VNUMFLT)
#define ttisfulluserdata(o)	checktag((o), ctb(LUA_VUSERDATA))
#define ttisfunction(o)		checktype(o, LUA_TFUNCTION)
#define ttisinteger(o)		checktag((o), LUA_VNUMINT)
#define ttislcf(o)		checktag((o), LUA_VLCF)
#define ttislightuserdata(o)	checktag((o), LUA_VLIGHTUSERDATA)
#define ttislngstring(o)	checktag((o), ctb(LUA_VLNGSTR))
#define ttisnil(v)		checktype((v), LUA_TNIL)
#define ttisnumber(o)		checktype((o), LUA_TNUMBER)
#define ttisshrstring(o)	checktag((o), ctb(LUA_VSHRSTR))
#define ttisstrictnil(o)	checktag((o), LUA_VNIL)
#define ttisstring(o)		checktype((o), LUA_TSTRING)
#define ttistable(o)		checktag((o), ctb(LUA_VTABLE))
#define ttisthread(o)		checktag((o), ctb(LUA_VTHREAD))
#define ttistrue(o)		checktag((o), LUA_VTRUE)
#define ttype(o)	(novariant(rawtt(o)))
#define ttypetag(o)	withvariant(rawtt(o))
#define twoto(x)	(1<<(x))
#define udatamemoffset(nuv) \
	((nuv) == 0 ? offsetof(Udata0, bindata)  \
                    : offsetof(Udata, uv) + (sizeof(UValue) * (nuv)))
#define uvalue(o)	check_exp(ttisfulluserdata(o), gco2u(val_(o).gc))
#define val_(o)		((o)->value_)
#define valraw(o)	(&val_(o))
#define vslen(o)	tsslen(tsvalue(o))
#define withvariant(t)	((t) & 0x3F)
#define LUA_HOOKTAILCALL 4
#define lua_call(L,n,r)		lua_callk(L, (n), (r), 0, NULL)
#define lua_getextraspace(L)	((void *)((char *)(L) - LUA_EXTRASPACE))
#define lua_getuservalue(L,idx)	lua_getiuservalue(L,idx,1)

#define lua_insert(L,idx)	lua_rotate(L, (idx), 1)
#define lua_isboolean(L,n)	(lua_type(L, (n)) == LUA_TBOOLEAN)
#define lua_isfunction(L,n)	(lua_type(L, (n)) == LUA_TFUNCTION)
#define lua_islightuserdata(L,n)	(lua_type(L, (n)) == LUA_TLIGHTUSERDATA)
#define lua_isnil(L,n)		(lua_type(L, (n)) == LUA_TNIL)
#define lua_isnone(L,n)		(lua_type(L, (n)) == LUA_TNONE)
#define lua_isnoneornil(L, n)	(lua_type(L, (n)) <= 0)
#define lua_istable(L,n)	(lua_type(L, (n)) == LUA_TTABLE)
#define lua_isthread(L,n)	(lua_type(L, (n)) == LUA_TTHREAD)
#define lua_newtable(L)		lua_createtable(L, 0, 0)
#define lua_pop(L,n)		lua_settop(L, -(n)-1)
#define lua_pushcfunction(L,f)	lua_pushcclosure(L, (f), 0)
#define lua_pushglobaltable(L)  \
	((void)lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS))
#define lua_pushliteral(L, s)	lua_pushstring(L, "" s)
#define lua_pushunsigned(L,n)	lua_pushinteger(L, (lua_Integer)(n))
#define lua_register(L,n,f) (lua_pushcfunction(L, (f)), lua_setglobal(L, (n)))
#define lua_remove(L,idx)	(lua_rotate(L, (idx), -1), lua_pop(L, 1))
#define lua_replace(L,idx)	(lua_copy(L, -1, (idx)), lua_pop(L, 1))
#define lua_setuservalue(L,idx)	lua_setiuservalue(L,idx,1)
#define lua_tostring(L,i)	lua_tolstring(L, (i), NULL)
#define lua_tounsignedx(L,i,is)	((lua_Unsigned)lua_tointegerx(L,i,is))
#define lua_upvalueindex(i)	(LUA_REGISTRYINDEX - (i))
#define lua_yield(L,n)		lua_yieldk(L, (n), 0, NULL)
#define LUAI_DDEC(dec)	LUAI_FUNC dec
#define LUAI_MAXALIGN  lua_Number n; double u; void *s; lua_Integer i; long l
#define LUAL_BUFFERSIZE   ((int)(16 * sizeof(void*) * sizeof(lua_Number)))
#define LUA_API __declspec(dllexport)




#define LUA_CPATH_DEFAULT \
		LUA_CDIR"?.dll;" \
		LUA_CDIR"..\\lib\\lua\\" LUA_VDIR "\\?.dll;" \
		LUA_CDIR"loadall.dll;" ".\\?.dll"
#define LUA_EXEC_DIR            "!"
#define LUA_PATH_DEFAULT  \
		LUA_LDIR"?.lua;"  LUA_LDIR"?\\init.lua;" \
		LUA_CDIR"?.lua;"  LUA_CDIR"?\\init.lua;" \
		LUA_SHRDIR"?.lua;" LUA_SHRDIR"?\\init.lua;" \
		".\\?.lua;" ".\\?\\init.lua"
#define LUA_PATH_MARK           "?"
#define LUA_PATH_SEP            ";"

#define LUA_USE_WINDOWS  
#define l_floatatt(n)		(FLT_##n)
#define l_floor(x)		(l_mathop(floor)(x))
#define l_mathop(op)		op##f
#define l_sprintf(s,sz,f,i)	snprintf(s,sz,f,i)
#define lua_equal(L,idx1,idx2)		lua_compare(L,(idx1),(idx2),LUA_OPEQ)
#define lua_getlocaledecpoint()		(localeconv()->decimal_point[0])
#define lua_integer2str(s,sz,n)  \
	l_sprintf((s), sz, LUA_INTEGER_FMT, (LUAI_UACINT)(n))
#define lua_lessthan(L,idx1,idx2)	lua_compare(L,(idx1),(idx2),LUA_OPLT)
#define lua_number2str(s,sz,n)  \
	l_sprintf((s), sz, LUA_NUMBER_FMT, (LUAI_UACNUMBER)(n))
#define lua_number2strx(L,b,sz,f,n)  \
	((void)L, l_sprintf(b,sz,f,(LUAI_UACNUMBER)(n)))
#define lua_numbertointeger(n,p) \
  ((n) >= (LUA_NUMBER)(LUA_MININTEGER) && \
   (n) < -(LUA_NUMBER)(LUA_MININTEGER) && \
      (*(p) = (LUA_INTEGER)(n), 1))
#define lua_objlen(L,i)		lua_rawlen(L, (i))
#define lua_pointer2str(buff,sz,p)	l_sprintf(buff,sz,"%p",p)
#define lua_str2number(s,p)	strtof((s), (p))
#define lua_strlen(L,i)		lua_rawlen(L, (i))
#define lua_strx2number(s,p)		lua_str2number(s,p)

#define luai_apicheck(l,e)	assert(e)
#define LL(x)   (sizeof(x)/sizeof(char) - 1)
#define UNUSED(x)	((void)(x))
#define api_check(l,e,msg)	luai_apicheck(l,(e) && msg)
#define cast(t, exp)	((t)(exp))
#define cast_byte(i)	cast(lu_byte, (i))
#define cast_char(i)	cast(char, (i))
#define cast_charp(i)	cast(char *, (i))
#define cast_int(i)	cast(int, (i))
#define cast_num(i)	cast(lua_Number, (i))
#define cast_sizet(i)	cast(size_t, (i))
#define cast_uchar(i)	cast(unsigned char, (i))
#define cast_uint(i)	cast(unsigned int, (i))
#define cast_void(i)	cast(void, (i))
#define cast_voidp(i)	cast(void *, (i))
#define check_exp(c,e)		(lua_assert(c), (e))
#define condchangemem(L,pre,pos)	((void)0)
#define condmovestack(L,pre,pos)	((void)0)
#define ispow2(x)	(((x) & ((x) - 1)) == 0)
#define l_castS2U(i)	((lua_Unsigned)(i))
#define l_castU2S(i)	((lua_Integer)(i))
#define likely(x)	(__builtin_expect(((x) != 0), 1))

#define log2maxs(t)	(sizeof(t) * 8 - 2)
#define lua_assert(c)		((void)0)
#define lua_lock(L)	((void) 0)
#define lua_longassert(c)	((c) ? (void)0 : lua_assert(0))
#define lua_unlock(L)	((void) 0)
#define luai_apicheck(l,e)	((void)l, lua_assert(e))
#define luai_numadd(L,a,b)      ((a)+(b))
#define luai_numdiv(L,a,b)      ((a)/(b))
#define luai_numeq(a,b)         ((a)==(b))
#define luai_numge(a,b)         ((a)>=(b))
#define luai_numgt(a,b)         ((a)>(b))
#define luai_numidiv(L,a,b)     ((void)L, l_floor(luai_numdiv(L,a,b)))
#define luai_numisnan(a)        (!luai_numeq((a), (a)))
#define luai_numle(a,b)         ((a)<=(b))
#define luai_numlt(a,b)         ((a)<(b))
#define luai_nummod(L,a,b,m)  \
  { (void)L; (m) = l_mathop(fmod)(a,b); \
    if (((m) > 0) ? (b) < 0 : ((m) < 0 && (b) > 0)) (m) += (b); }
#define luai_nummul(L,a,b)      ((a)*(b))
#define luai_numpow(L,a,b)      ((void)L, l_mathop(pow)(a,b))
#define luai_numsub(L,a,b)      ((a)-(b))
#define luai_numunm(L,a)        (-(a))
#define luai_threadyield(L)	{lua_unlock(L); lua_lock(L);}
#define luai_userstateclose(L)		((void)L)
#define luai_userstatefree(L,L1)	((void)L)
#define luai_userstateopen(L)		((void)L)
#define luai_userstateresume(L,n)	((void)L)
#define luai_userstatethread(L,L1)	((void)L)
#define luai_userstateyield(L,n)	((void)L)
#define point2uint(p)	((unsigned int)((size_t)(p) & UINT_MAX))
#define unlikely(x)	(__builtin_expect(((x) != 0), 0))
#define checkstackGC(L,fsize)  \
	luaD_checkstackaux(L, (fsize), (void)0, luaC_checkGC(L))
#define checkstackp(L,n,p)  \
  luaD_checkstackaux(L, n, \
    ptrdiff_t t__ = savestack(L, p);   \
    luaC_checkGC(L),   \
    p = restorestack(L, t__))  

#define luaD_checkstackaux(L,n,pre,pos)  \
	if (L->stack_last - L->top <= (n)) \
	  { pre; luaD_growstack(L, n, 1); pos; } \
        else { condmovestack(L,pre,pos); }
#define restorestack(L,n)	((StkId)((char *)L->stack + (n)))
#define savestack(L,p)		((char *)(p) - (char *)L->stack)
#define luaZ_buffer(buff)	((buff)->buffer)
#define luaZ_bufflen(buff)	((buff)->n)
#define luaZ_buffremove(buff,i)	((buff)->n -= (i))
#define luaZ_freebuffer(L, buff)	luaZ_resizebuffer(L, buff, 0)
#define luaZ_initbuffer(L, buff) ((buff)->buffer = NULL, (buff)->buffsize = 0)
#define luaZ_resetbuffer(buff) ((buff)->n = 0)
#define luaZ_resizebuffer(L, buff, size) \
	((buff)->buffer = luaM_reallocvchar(L, (buff)->buffer, \
				(buff)->buffsize, size), \
	(buff)->buffsize = size)
#define luaZ_sizebuffer(buff)	((buff)->buffsize)

#define zgetc(z)  (((z)->n--)>0 ?  cast_uchar(*(z)->p++) : luaZ_fill(z))

#define luaM_checksize(L,n,e)  \
	(luaM_testsize(n,e) ? luaM_toobig(L) : cast_void(0))
#define luaM_error(L)	luaD_throw(L, LUA_ERRMEM)
#define luaM_free(L, b)		luaM_free_(L, (b), sizeof(*(b)))
#define luaM_freearray(L, b, n)   luaM_free_(L, (b), (n)*sizeof(*(b)))
#define luaM_freemem(L, b, s)	luaM_free_(L, (b), (s))
#define luaM_growvector(L,v,nelems,size,t,limit,e) \
	((v)=cast(t *, luaM_growaux_(L,v,nelems,&(size),sizeof(t), \
                         luaM_limitN(limit,t),e)))
#define luaM_limitN(n,t)  \
  ((cast_sizet(n) <= MAX_SIZET/sizeof(t)) ? (n) :  \
     cast_uint((MAX_SIZET/sizeof(t))))
#define luaM_new(L,t)		cast(t*, luaM_malloc_(L, sizeof(t), 0))
#define luaM_newobject(L,tag,s)	luaM_malloc_(L, (s), tag)
#define luaM_newvector(L,n,t)	cast(t*, luaM_malloc_(L, (n)*sizeof(t), 0))
#define luaM_newvectorchecked(L,n,t) \
  (luaM_checksize(L,n,sizeof(t)), luaM_newvector(L,n,t))
#define luaM_reallocvchar(L,b,on,n)  \
  cast_charp(luaM_saferealloc_(L, (b), (on)*sizeof(char), (n)*sizeof(char)))
#define luaM_reallocvector(L, v,oldn,n,t) \
   (cast(t *, luaM_realloc_(L, v, cast_sizet(oldn) * sizeof(t), \
                                  cast_sizet(n) * sizeof(t))))
#define luaM_shrinkvector(L,v,size,fs,t) \
   ((v)=cast(t *, luaM_shrinkvector_(L, v, &(size), fs, sizeof(t))))
#define luaM_testsize(n,e)  \
	(sizeof(n) >= sizeof(size_t) && cast_sizet((n)) + 1 > MAX_SIZET/(e))
#define BASIC_STACK_SIZE        (2*LUA_MINSTACK)
#define EXTRA_STACK   5
#define cast_u(o)	cast(union GCUnion *, (o))
#define decXCcalls(L)	((L)->nCcalls -= 0x10000 - CSTACKCF)
#define decnny(L)	((L)->nCcalls -= 0x10000)
#define gco2ccl(o)  check_exp((o)->tt == LUA_VCCL, &((cast_u(o))->cl.c))
#define gco2cl(o)  \
	check_exp(novariant((o)->tt) == LUA_TFUNCTION, &((cast_u(o))->cl))
#define gco2lcl(o)  check_exp((o)->tt == LUA_VLCL, &((cast_u(o))->cl.l))
#define gco2p(o)  check_exp((o)->tt == LUA_VPROTO, &((cast_u(o))->p))
#define gco2t(o)  check_exp((o)->tt == LUA_VTABLE, &((cast_u(o))->h))
#define gco2th(o)  check_exp((o)->tt == LUA_VTHREAD, &((cast_u(o))->th))
#define gco2ts(o)  \
	check_exp(novariant((o)->tt) == LUA_TSTRING, &((cast_u(o))->ts))
#define gco2u(o)  check_exp((o)->tt == LUA_VUSERDATA, &((cast_u(o))->u))
#define gco2upv(o)	check_exp((o)->tt == LUA_VUPVAL, &((cast_u(o))->upv))
#define getCcalls(L)	((L)->nCcalls & 0xffff)
#define getoah(st)	((st) & CIST_OAH)
#define gettotalbytes(g)	cast(lu_mem, (g)->totalbytes + (g)->GCdebt)
#define incXCcalls(L)	((L)->nCcalls += 0x10000 - CSTACKCF)
#define incnny(L)	((L)->nCcalls += 0x10000)
#define isLua(ci)	(!((ci)->callstatus & CIST_C))
#define isLuacode(ci)	(!((ci)->callstatus & (CIST_C | CIST_HOOKED)))

#define luaE_exitCcall(L)	((L)->nCcalls++)
#define obj2gco(v)	check_exp((v)->tt >= LUA_TSTRING, &(cast_u(v)->gc))
#define setoah(st,v)	((st) = ((st) & ~CIST_OAH) | (v))
#define yieldable(L)		(((L)->nCcalls & 0xffff0000) == 0)
#define allocsizenode(t)	(isdummy(t) ? 0 : sizenode(t))
#define gnext(n)	((n)->u.next)
#define gnode(t,i)	(&(t)->node[i])
#define gval(n)		(&(n)->i_val)
#define invalidateTMcache(t)	((t)->flags = 0)
#define isdummy(t)		((t)->lastfree == NULL)

#define nodefromval(v)	cast(Node *, (v))
#define MEMERRMSG       "not enough memory"
#define eqshrstr(a,b)	check_exp((a)->tt == LUA_VSHRSTR, (a) == (b))
#define isreserved(s)	((s)->tt == LUA_VSHRSTR && (s)->extra > 0)

#define luaS_newliteral(L, s)	(luaS_newlstr(L, "" s, \
                                 (sizeof(s)/sizeof(char))-1))
#define sizelstring(l)  (offsetof(TString, contents) + ((l) + 1) * sizeof(char))
#define LUAI_GCMUL      100
#define LUAI_GCPAUSE    200
#define LUAI_GCSTEPSIZE 13      
#define LUAI_GENMAJORMUL         100
#define LUAI_GENMINORMUL         20
#define bit2mask(b1,b2)		(bitmask(b1) | bitmask(b2))
#define bitmask(b)		(1<<(b))
#define changeage(o,f,t)  \
	check_exp(getage(o) == (f), (o)->marked ^= ((f)^(t)))
#define changewhite(x)	((x)->marked ^= WHITEBITS)
#define getage(o)	((o)->marked & AGEBITS)
#define getgcparam(p)	((p) * 4)
#define gray2black(x)	l_setbit((x)->marked, BLACKBIT)
#define isblack(x)      testbit((x)->marked, BLACKBIT)
#define isdeadm(ow,m)	((m) & (ow))
#define isdecGCmodegen(g)	(g->gckind == KGC_GEN || g->lastatomic != 0)
#define isgray(x)    \
	(!testbits((x)->marked, WHITEBITS | bitmask(BLACKBIT)))
#define isold(o)	(getage(o) > G_SURVIVAL)
#define issweepphase(g)  \
	(GCSswpallgc <= (g)->gcstate && (g)->gcstate <= GCSswpend)
#define iswhite(x)      testbits((x)->marked, WHITEBITS)
#define keepinvariant(g)	((g)->gcstate <= GCSatomic)
#define l_setbit(x,b)		setbits(x, bitmask(b))

#define luaC_barrier(L,p,v) (  \
	(iscollectable(v) && isblack(p) && iswhite(gcvalue(v))) ?  \
	luaC_barrier_(L,obj2gco(p),gcvalue(v)) : cast_void(0))
#define luaC_barrierback(L,p,v) (  \
	(iscollectable(v) && isblack(p) && iswhite(gcvalue(v))) ? \
	luaC_barrierback_(L,p) : cast_void(0))
#define luaC_checkGC(L)		luaC_condGC(L,(void)0,(void)0)
#define luaC_condGC(L,pre,pos) \
	{ if (G(L)->GCdebt > 0) { pre; luaC_step(L); pos;}; \
	  condchangemem(L,pre,pos); }
#define luaC_objbarrier(L,p,o) (  \
	(isblack(p) && iswhite(o)) ? \
	luaC_barrier_(L,obj2gco(p),obj2gco(o)) : cast_void(0))
#define luaC_white(g)	cast_byte((g)->currentwhite & WHITEBITS)
#define otherwhite(g)	((g)->currentwhite ^ WHITEBITS)
#define resetbit(x,b)		resetbits(x, bitmask(b))
#define resetbits(x,m)		((x) &= cast_byte(~(m)))
#define setage(o,a)  ((o)->marked = cast_byte(((o)->marked & (~AGEBITS)) | a))
#define setbits(x,m)		((x) |= (m))
#define setgcparam(p,v)	((p) = (v) / 4)
#define testbit(x,b)		testbits(x, bitmask(b))
#define testbits(x,m)		((x) & (m))
#define tofinalize(x)	testbit((x)->marked, FINALIZEDBIT)
#define CREATE_ABCk(o,a,b,c,k)	((cast(Instruction, o)<<POS_OP) \
			| (cast(Instruction, a)<<POS_A) \
			| (cast(Instruction, b)<<POS_B) \
			| (cast(Instruction, c)<<POS_C) \
			| (cast(Instruction, k)<<POS_k))
#define CREATE_ABx(o,a,bc)	((cast(Instruction, o)<<POS_OP) \
			| (cast(Instruction, a)<<POS_A) \
			| (cast(Instruction, bc)<<POS_Bx))
#define CREATE_Ax(o,a)		((cast(Instruction, o)<<POS_OP) \
			| (cast(Instruction, a)<<POS_Ax))
#define CREATE_sJ(o,j,k)	((cast(Instruction, o) << POS_OP) \
			| (cast(Instruction, j) << POS_sJ) \
			| (cast(Instruction, k) << POS_k))
#define GETARG_A(i)	getarg(i, POS_A, SIZE_A)
#define GETARG_Ax(i)	check_exp(checkopm(i, iAx), getarg(i, POS_Ax, SIZE_Ax))
#define GETARG_B(i)	check_exp(checkopm(i, iABC), getarg(i, POS_B, SIZE_B))
#define GETARG_Bx(i)	check_exp(checkopm(i, iABx), getarg(i, POS_Bx, SIZE_Bx))
#define GETARG_C(i)	check_exp(checkopm(i, iABC), getarg(i, POS_C, SIZE_C))
#define GETARG_k(i)	check_exp(checkopm(i, iABC), getarg(i, POS_k, 1))
#define GETARG_sB(i)	sC2int(GETARG_B(i))
#define GETARG_sBx(i)  \
	check_exp(checkopm(i, iAsBx), getarg(i, POS_Bx, SIZE_Bx) - OFFSET_sBx)
#define GETARG_sC(i)	sC2int(GETARG_C(i))
#define GETARG_sJ(i)  \
	check_exp(checkopm(i, isJ), getarg(i, POS_sJ, SIZE_sJ) - OFFSET_sJ)
#define GET_OPCODE(i)	(cast(OpCode, ((i)>>POS_OP) & MASK1(SIZE_OP,0)))
#define L_INTHASBITS(b)		((UINT_MAX >> ((b) - 1)) >= 1)
#define MASK0(n,p)	(~MASK1(n,p))
#define MASK1(n,p)	((~((~(Instruction)0)<<(n)))<<(p))
#define SETARG_A(i,v)	setarg(i, v, POS_A, SIZE_A)
#define SETARG_Ax(i,v)	setarg(i, v, POS_Ax, SIZE_Ax)
#define SETARG_B(i,v)	setarg(i, v, POS_B, SIZE_B)
#define SETARG_Bx(i,v)	setarg(i, v, POS_Bx, SIZE_Bx)
#define SETARG_C(i,v)	setarg(i, v, POS_C, SIZE_C)
#define SETARG_k(i,v)	setarg(i, v, POS_k, 1)
#define SETARG_sBx(i,b)	SETARG_Bx((i),cast_uint((b)+OFFSET_sBx))
#define SETARG_sJ(i,j) \
	setarg(i, cast_uint((j)+OFFSET_sJ), POS_sJ, SIZE_sJ)
#define SET_OPCODE(i,o)	((i) = (((i)&MASK0(SIZE_OP,POS_OP)) | \
		((cast(Instruction, o)<<POS_OP)&MASK1(SIZE_OP,POS_OP))))
#define TESTARG_k(i)	check_exp(checkopm(i, iABC), (cast_int(((i) & (1u << POS_k)))))
#define checkopm(i,m)	(getOpMode(GET_OPCODE(i)) == m)
#define getOpMode(m)	(cast(enum OpMode, luaP_opmodes[m] & 7))
#define getarg(i,pos,size)	(cast_int(((i)>>(pos)) & MASK1(size,0)))
#define int2sC(i)	((i) + OFFSET_sC)
#define isIT(i)		(testITMode(GET_OPCODE(i)) && GETARG_B(i) == 0)
#define isOT(i)  \
	((testOTMode(GET_OPCODE(i)) && GETARG_C(i) == 0) || \
          GET_OPCODE(i) == OP_TAILCALL)

#define opmode(mm,ot,it,t,a,m)  \
    (((mm) << 7) | ((ot) << 6) | ((it) << 5) | ((t) << 4) | ((a) << 3) | (m))
#define sC2int(i)	((i) - OFFSET_sC)
#define setarg(i,v,pos,size)	((i) = (((i)&MASK0(size,pos)) | \
                ((cast(Instruction, v)<<pos)&MASK1(size,pos))))
#define testAMode(m)	(luaP_opmodes[m] & (1 << 3))
#define testITMode(m)	(luaP_opmodes[m] & (1 << 5))
#define testMMMode(m)	(luaP_opmodes[m] & (1 << 7))
#define testOTMode(m)	(luaP_opmodes[m] & (1 << 6))
#define testTMode(m)	(luaP_opmodes[m] & (1 << 4))
#define isintwups(L)	(L->twups != L)

#define sizeCclosure(n)	(cast_int(offsetof(CClosure, upvalue)) + \
                         cast_int(sizeof(TValue)) * (n))
#define sizeLclosure(n)	(cast_int(offsetof(LClosure, upvals)) + \
                         cast_int(sizeof(TValue *)) * (n))
#define upisopen(up)	((up)->v != &(up)->u.value)
#define uplevel(up)	check_exp(upisopen(up), cast(StkId, (up)->v))

#define pcRel(pc, p)	(cast_int((pc) - (p)->code) - 1)
#define resethookcount(L)	(L->hookcount = L->basehookcount)
#define _CRT_SECURE_NO_WARNINGS  
#define _FILE_OFFSET_BITS       64
#define _LARGEFILE_SOURCE       1
#define _XOPEN_SOURCE           600

