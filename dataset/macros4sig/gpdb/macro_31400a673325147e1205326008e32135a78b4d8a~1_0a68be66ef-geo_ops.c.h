
#include<sys/stat.h>

#include<fcntl.h>
#include<stdio.h>
#include<pwd.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<math.h>
#include<float.h>
#include<sys/types.h>
#include<stdlib.h>
#include<locale.h>
#include<errno.h>
#include<libintl.h>
#include<stdarg.h>


#include<ctype.h>
#include<netdb.h>

#include<string.h>

#include<limits.h>

#include<stddef.h>
#include<stdint.h>


#include<setjmp.h>
#include<assert.h>
#include<strings.h>

#define BoxPGetDatum(X)    PointerGetDatum(X)
#define CirclePGetDatum(X)	  PointerGetDatum(X)
#define DatumGetBoxP(X)    ((BOX *) DatumGetPointer(X))
#define DatumGetCircleP(X)	  ((CIRCLE *) DatumGetPointer(X))
#define DatumGetLineP(X)	((LINE *) DatumGetPointer(X))
#define DatumGetLsegP(X)	((LSEG *) DatumGetPointer(X))
#define DatumGetPathP(X)		 ((PATH *) PG_DETOAST_DATUM(X))
#define DatumGetPathPCopy(X)	 ((PATH *) PG_DETOAST_DATUM_COPY(X))
#define DatumGetPointP(X)	 ((Point *) DatumGetPointer(X))
#define DatumGetPolygonP(X)			((POLYGON *) PG_DETOAST_DATUM(X))
#define DatumGetPolygonPCopy(X)		((POLYGON *) PG_DETOAST_DATUM_COPY(X))
#define FPeq(A,B)				(fabs((A) - (B)) <= EPSILON)
#define FPge(A,B)				((B) - (A) <= EPSILON)
#define FPgt(A,B)				((A) - (B) > EPSILON)
#define FPle(A,B)				((A) - (B) <= EPSILON)
#define FPlt(A,B)				((B) - (A) > EPSILON)
#define FPne(A,B)				(fabs((A) - (B)) > EPSILON)
#define FPzero(A)				(fabs(A) <= EPSILON)

#define HYPOT(A, B)				pg_hypot(A, B)
#define LinePGetDatum(X)	PointerGetDatum(X)
#define LsegPGetDatum(X)	PointerGetDatum(X)
#define PG_GETARG_BOX_P(n) DatumGetBoxP(PG_GETARG_DATUM(n))
#define PG_GETARG_CIRCLE_P(n) DatumGetCircleP(PG_GETARG_DATUM(n))
#define PG_GETARG_LINE_P(n) DatumGetLineP(PG_GETARG_DATUM(n))
#define PG_GETARG_LSEG_P(n) DatumGetLsegP(PG_GETARG_DATUM(n))
#define PG_GETARG_PATH_P(n)		 DatumGetPathP(PG_GETARG_DATUM(n))
#define PG_GETARG_PATH_P_COPY(n) DatumGetPathPCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_POINT_P(n) DatumGetPointP(PG_GETARG_DATUM(n))
#define PG_GETARG_POLYGON_P(n)		DatumGetPolygonP(PG_GETARG_DATUM(n))
#define PG_GETARG_POLYGON_P_COPY(n) DatumGetPolygonPCopy(PG_GETARG_DATUM(n))
#define PG_RETURN_BOX_P(x) return BoxPGetDatum(x)
#define PG_RETURN_CIRCLE_P(x) return CirclePGetDatum(x)
#define PG_RETURN_LINE_P(x) return LinePGetDatum(x)
#define PG_RETURN_LSEG_P(x) return LsegPGetDatum(x)
#define PG_RETURN_PATH_P(x)		 return PathPGetDatum(x)
#define PG_RETURN_POINT_P(x) return PointPGetDatum(x)
#define PG_RETURN_POLYGON_P(x)		return PolygonPGetDatum(x)
#define PathPGetDatum(X)		 PointerGetDatum(X)
#define PointPGetDatum(X)	 PointerGetDatum(X)
#define PolygonPGetDatum(X)			PointerGetDatum(X)
#define DatumGetBpCharP(X)			((BpChar *) PG_DETOAST_DATUM(X))
#define DatumGetBpCharPCopy(X)		((BpChar *) PG_DETOAST_DATUM_COPY(X))
#define DatumGetBpCharPP(X)			((BpChar *) PG_DETOAST_DATUM_PACKED(X))
#define DatumGetBpCharPSlice(X,m,n) ((BpChar *) PG_DETOAST_DATUM_SLICE(X,m,n))
#define DatumGetByteaP(X)			((bytea *) PG_DETOAST_DATUM(X))
#define DatumGetByteaPCopy(X)		((bytea *) PG_DETOAST_DATUM_COPY(X))
#define DatumGetByteaPP(X)			((bytea *) PG_DETOAST_DATUM_PACKED(X))
#define DatumGetByteaPSlice(X,m,n)	((bytea *) PG_DETOAST_DATUM_SLICE(X,m,n))
#define DatumGetHeapTupleHeader(X)	((HeapTupleHeader) PG_DETOAST_DATUM(X))
#define DatumGetHeapTupleHeaderCopy(X)	((HeapTupleHeader) PG_DETOAST_DATUM_COPY(X))
#define DatumGetTextP(X)			((text *) PG_DETOAST_DATUM(X))
#define DatumGetTextPCopy(X)		((text *) PG_DETOAST_DATUM_COPY(X))
#define DatumGetTextPP(X)			((text *) PG_DETOAST_DATUM_PACKED(X))
#define DatumGetTextPSlice(X,m,n)	((text *) PG_DETOAST_DATUM_SLICE(X,m,n))
#define DatumGetVarCharP(X)			((VarChar *) PG_DETOAST_DATUM(X))
#define DatumGetVarCharPCopy(X)		((VarChar *) PG_DETOAST_DATUM_COPY(X))
#define DatumGetVarCharPP(X)		((VarChar *) PG_DETOAST_DATUM_PACKED(X))
#define DatumGetVarCharPSlice(X,m,n) ((VarChar *) PG_DETOAST_DATUM_SLICE(X,m,n))
#define DirectFunctionCall1(func, arg1) \
	DirectFunctionCall1Coll(func, InvalidOid, arg1)
#define DirectFunctionCall2(func, arg1, arg2) \
	DirectFunctionCall2Coll(func, InvalidOid, arg1, arg2)
#define DirectFunctionCall3(func, arg1, arg2, arg3) \
	DirectFunctionCall3Coll(func, InvalidOid, arg1, arg2, arg3)
#define DirectFunctionCall4(func, arg1, arg2, arg3, arg4) \
	DirectFunctionCall4Coll(func, InvalidOid, arg1, arg2, arg3, arg4)
#define DirectFunctionCall5(func, arg1, arg2, arg3, arg4, arg5) \
	DirectFunctionCall5Coll(func, InvalidOid, arg1, arg2, arg3, arg4, arg5)
#define DirectFunctionCall6(func, arg1, arg2, arg3, arg4, arg5, arg6) \
	DirectFunctionCall6Coll(func, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6)
#define DirectFunctionCall7(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
	DirectFunctionCall7Coll(func, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
#define DirectFunctionCall8(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
	DirectFunctionCall8Coll(func, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
#define DirectFunctionCall9(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) \
	DirectFunctionCall9Coll(func, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)

#define FmgrHookIsNeeded(fn_oid)							\
	(!needs_fmgr_hook ? false : (*needs_fmgr_hook)(fn_oid))
#define FunctionCall1(flinfo, arg1) \
	FunctionCall1Coll(flinfo, InvalidOid, arg1)
#define FunctionCall2(flinfo, arg1, arg2) \
	FunctionCall2Coll(flinfo, InvalidOid, arg1, arg2)
#define FunctionCall3(flinfo, arg1, arg2, arg3) \
	FunctionCall3Coll(flinfo, InvalidOid, arg1, arg2, arg3)
#define FunctionCall4(flinfo, arg1, arg2, arg3, arg4) \
	FunctionCall4Coll(flinfo, InvalidOid, arg1, arg2, arg3, arg4)
#define FunctionCall5(flinfo, arg1, arg2, arg3, arg4, arg5) \
	FunctionCall5Coll(flinfo, InvalidOid, arg1, arg2, arg3, arg4, arg5)
#define FunctionCall6(flinfo, arg1, arg2, arg3, arg4, arg5, arg6) \
	FunctionCall6Coll(flinfo, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6)
#define FunctionCall7(flinfo, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
	FunctionCall7Coll(flinfo, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
#define FunctionCall8(flinfo, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
	FunctionCall8Coll(flinfo, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
#define FunctionCall9(flinfo, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) \
	FunctionCall9Coll(flinfo, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)
#define FunctionCallInvoke(fcinfo)	((* (fcinfo)->flinfo->fn_addr) (fcinfo))
#define InitFunctionCallInfoData(Fcinfo, Flinfo, Nargs, Collation, Context, Resultinfo) \
	do { \
		(Fcinfo).flinfo = (Flinfo); \
		(Fcinfo).context = (Context); \
		(Fcinfo).resultinfo = (Resultinfo); \
		(Fcinfo).fncollation = (Collation); \
		(Fcinfo).isnull = false; \
		(Fcinfo).nargs = (Nargs); \
	} while (0)
#define OidFunctionCall0(functionId) \
	OidFunctionCall0Coll(functionId, InvalidOid)
#define OidFunctionCall1(functionId, arg1) \
	OidFunctionCall1Coll(functionId, InvalidOid, arg1)
#define OidFunctionCall2(functionId, arg1, arg2) \
	OidFunctionCall2Coll(functionId, InvalidOid, arg1, arg2)
#define OidFunctionCall3(functionId, arg1, arg2, arg3) \
	OidFunctionCall3Coll(functionId, InvalidOid, arg1, arg2, arg3)
#define OidFunctionCall4(functionId, arg1, arg2, arg3, arg4) \
	OidFunctionCall4Coll(functionId, InvalidOid, arg1, arg2, arg3, arg4)
#define OidFunctionCall5(functionId, arg1, arg2, arg3, arg4, arg5) \
	OidFunctionCall5Coll(functionId, InvalidOid, arg1, arg2, arg3, arg4, arg5)
#define OidFunctionCall6(functionId, arg1, arg2, arg3, arg4, arg5, arg6) \
	OidFunctionCall6Coll(functionId, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6)
#define OidFunctionCall7(functionId, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
	OidFunctionCall7Coll(functionId, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
#define OidFunctionCall8(functionId, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
	OidFunctionCall8Coll(functionId, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
#define OidFunctionCall9(functionId, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) \
	OidFunctionCall9Coll(functionId, InvalidOid, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)
#define PG_ARGISNULL(n)  (fcinfo->argnull[n])
#define PG_DETOAST_DATUM(datum) \
	pg_detoast_datum((struct varlena *) DatumGetPointer(datum))
#define PG_DETOAST_DATUM_COPY(datum) \
	pg_detoast_datum_copy((struct varlena *) DatumGetPointer(datum))
#define PG_DETOAST_DATUM_PACKED(datum) \
	pg_detoast_datum_packed((struct varlena *) DatumGetPointer(datum))
#define PG_DETOAST_DATUM_SLICE(datum,f,c) \
		pg_detoast_datum_slice((struct varlena *) DatumGetPointer(datum), \
		(int32) (f), (int32) (c))
#define PG_FREE_IF_COPY(ptr,n) \
	do { \
		if ((Pointer) (ptr) != PG_GETARG_POINTER(n)) \
			pfree(ptr); \
	} while (0)
#define PG_FUNCTION_INFO_V1(funcname) \
extern PGDLLEXPORT const Pg_finfo_record * CppConcat(pg_finfo_,funcname)(void); \
const Pg_finfo_record * \
CppConcat(pg_finfo_,funcname) (void) \
{ \
	static const Pg_finfo_record my_finfo = { 1 }; \
	return &my_finfo; \
} \
extern int no_such_variable
#define PG_GETARG_BOOL(n)	 DatumGetBool(PG_GETARG_DATUM(n))
#define PG_GETARG_BPCHAR_P(n)		DatumGetBpCharP(PG_GETARG_DATUM(n))
#define PG_GETARG_BPCHAR_PP(n)		DatumGetBpCharPP(PG_GETARG_DATUM(n))
#define PG_GETARG_BPCHAR_P_COPY(n)	DatumGetBpCharPCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_BPCHAR_P_SLICE(n,a,b) DatumGetBpCharPSlice(PG_GETARG_DATUM(n),a,b)
#define PG_GETARG_BYTEA_P(n)		DatumGetByteaP(PG_GETARG_DATUM(n))
#define PG_GETARG_BYTEA_PP(n)		DatumGetByteaPP(PG_GETARG_DATUM(n))
#define PG_GETARG_BYTEA_P_COPY(n)	DatumGetByteaPCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_BYTEA_P_SLICE(n,a,b) DatumGetByteaPSlice(PG_GETARG_DATUM(n),a,b)
#define PG_GETARG_CHAR(n)	 DatumGetChar(PG_GETARG_DATUM(n))
#define PG_GETARG_CSTRING(n) DatumGetCString(PG_GETARG_DATUM(n))
#define PG_GETARG_DATUM(n)	 (fcinfo->arg[n])
#define PG_GETARG_FLOAT4(n)  DatumGetFloat4(PG_GETARG_DATUM(n))
#define PG_GETARG_FLOAT8(n)  DatumGetFloat8(PG_GETARG_DATUM(n))
#define PG_GETARG_HEAPTUPLEHEADER(n)	DatumGetHeapTupleHeader(PG_GETARG_DATUM(n))
#define PG_GETARG_HEAPTUPLEHEADER_COPY(n)	DatumGetHeapTupleHeaderCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_INT16(n)	 DatumGetInt16(PG_GETARG_DATUM(n))
#define PG_GETARG_INT32(n)	 DatumGetInt32(PG_GETARG_DATUM(n))
#define PG_GETARG_INT64(n)	 DatumGetInt64(PG_GETARG_DATUM(n))
#define PG_GETARG_NAME(n)	 DatumGetName(PG_GETARG_DATUM(n))
#define PG_GETARG_OID(n)	 DatumGetObjectId(PG_GETARG_DATUM(n))
#define PG_GETARG_POINTER(n) DatumGetPointer(PG_GETARG_DATUM(n))
#define PG_GETARG_RAW_VARLENA_P(n)	((struct varlena *) PG_GETARG_POINTER(n))
#define PG_GETARG_TEXT_P(n)			DatumGetTextP(PG_GETARG_DATUM(n))
#define PG_GETARG_TEXT_PP(n)		DatumGetTextPP(PG_GETARG_DATUM(n))
#define PG_GETARG_TEXT_P_COPY(n)	DatumGetTextPCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_TEXT_P_SLICE(n,a,b)  DatumGetTextPSlice(PG_GETARG_DATUM(n),a,b)
#define PG_GETARG_UINT16(n)  DatumGetUInt16(PG_GETARG_DATUM(n))
#define PG_GETARG_UINT32(n)  DatumGetUInt32(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_P(n)		DatumGetVarCharP(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_PP(n)		DatumGetVarCharPP(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_P_COPY(n) DatumGetVarCharPCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_P_SLICE(n,a,b) DatumGetVarCharPSlice(PG_GETARG_DATUM(n),a,b)
#define PG_GETARG_VARLENA_P(n) PG_DETOAST_DATUM(PG_GETARG_DATUM(n))
#define PG_GETARG_VARLENA_PP(n) PG_DETOAST_DATUM_PACKED(PG_GETARG_DATUM(n))
#define PG_GET_COLLATION()	(fcinfo->fncollation)
#define PG_MAGIC_FUNCTION_NAME Pg_magic_func
#define PG_MAGIC_FUNCTION_NAME_STRING "Pg_magic_func"
#define PG_MODULE_MAGIC \
extern PGDLLEXPORT const Pg_magic_struct *PG_MAGIC_FUNCTION_NAME(void); \
const Pg_magic_struct * \
PG_MAGIC_FUNCTION_NAME(void) \
{ \
	static const Pg_magic_struct Pg_magic_data = PG_MODULE_MAGIC_DATA; \
	return &Pg_magic_data; \
} \
extern int no_such_variable
#define PG_MODULE_MAGIC_DATA \
{ \
	sizeof(Pg_magic_struct), \
	PG_VERSION_NUM / 100, \
	FUNC_MAX_ARGS, \
	INDEX_MAX_KEYS, \
	NAMEDATALEN, \
	FLOAT4PASSBYVAL, \
	FLOAT8PASSBYVAL \
}
#define PG_NARGS() (fcinfo->nargs)
#define PG_RETURN_BOOL(x)	 return BoolGetDatum(x)
#define PG_RETURN_BPCHAR_P(x)  PG_RETURN_POINTER(x)
#define PG_RETURN_BYTEA_P(x)   PG_RETURN_POINTER(x)
#define PG_RETURN_CHAR(x)	 return CharGetDatum(x)
#define PG_RETURN_CSTRING(x) return CStringGetDatum(x)
#define PG_RETURN_DATUM(x)	 return (x)
#define PG_RETURN_FLOAT4(x)  return Float4GetDatum(x)
#define PG_RETURN_FLOAT8(x)  return Float8GetDatum(x)
#define PG_RETURN_HEAPTUPLEHEADER(x)  PG_RETURN_POINTER(x)
#define PG_RETURN_INT16(x)	 return Int16GetDatum(x)
#define PG_RETURN_INT32(x)	 return Int32GetDatum(x)
#define PG_RETURN_INT64(x)	 return Int64GetDatum(x)
#define PG_RETURN_NAME(x)	 return NameGetDatum(x)
#define PG_RETURN_NULL()  \
	do { fcinfo->isnull = true; return (Datum) 0; } while (0)
#define PG_RETURN_OID(x)	 return ObjectIdGetDatum(x)
#define PG_RETURN_POINTER(x) return PointerGetDatum(x)
#define PG_RETURN_TEXT_P(x)    PG_RETURN_POINTER(x)
#define PG_RETURN_UINT32(x)  return UInt32GetDatum(x)
#define PG_RETURN_VARCHAR_P(x) PG_RETURN_POINTER(x)
#define PG_RETURN_VOID()	 return (Datum) 0
#define fmgr_info_set_expr(expr, finfo) \
	((finfo)->fn_expr = (expr))

#define CStringGetTextDatum(s) PointerGetDatum(cstring_to_text(s))
#define TextDatumGetCString(d) text_to_cstring((text *) DatumGetPointer(d))
#define ACL_CREATE_TEMP (1<<10) 
#define CURSOR_OPT_GENERIC_PLAN 0x0040	
#define FRAMEOPTION_DEFAULTS \
	(FRAMEOPTION_RANGE | FRAMEOPTION_START_UNBOUNDED_PRECEDING | \
	 FRAMEOPTION_END_CURRENT_ROW)
#define FRAMEOPTION_END_VALUE \
	(FRAMEOPTION_END_VALUE_PRECEDING | FRAMEOPTION_END_VALUE_FOLLOWING)
#define FRAMEOPTION_START_VALUE \
	(FRAMEOPTION_START_VALUE_PRECEDING | FRAMEOPTION_START_VALUE_FOLLOWING)
#define GetCTETargetList(cte) \
	(AssertMacro(IsA((cte)->ctequery, Query)), \
	 ((Query *) (cte)->ctequery)->commandType == CMD_SELECT ? \
	 ((Query *) (cte)->ctequery)->targetList : \
	 ((Query *) (cte)->ctequery)->returningList)


#define floatVal(v)		atof(((Value *)(v))->val.str)
#define intVal(v)		(((Value *)(v))->val.ival)
#define strVal(v)		(((Value *)(v))->val.str)
#define IS_OUTER_JOIN(jointype) \
	(((1 << (jointype)) & \
	  ((1 << JOIN_LEFT) | \
	   (1 << JOIN_FULL) | \
	   (1 << JOIN_RIGHT) | \
	   (1 << JOIN_ANTI))) != 0)
#define IsA(nodeptr,_type_)		(nodeTag(nodeptr) == T_##_type_)

#define NodeSetTag(nodeptr,t)	(((Node*)(nodeptr))->type = (t))
#define makeNode(_type_)		((_type_ *) newNode(sizeof(_type_),T_##_type_))
#define newNode(size, tag) \
({	Node   *_result; \
	AssertMacro((size) >= sizeof(Node));		 \
	_result = (Node *) palloc0fast(size); \
	_result->type = (tag); \
	_result; \
})
#define nodeTag(nodeptr)		(((const Node*)(nodeptr))->type)
#define IS_SPECIAL_VARNO(varno)		((varno) >= INNER_VAR)

#define LispRemove(elem, list)		list_delete(list, elem)

#define equali(l1, l2)				equal(l1, l2)
#define equalo(l1, l2)				equal(l1, l2)
#define for_each_cell(cell, initcell)	\
	for ((cell) = (initcell); (cell) != NULL; (cell) = lnext(cell))
#define forboth(cell1, list1, cell2, list2)							\
	for ((cell1) = list_head(list1), (cell2) = list_head(list2);	\
		 (cell1) != NULL && (cell2) != NULL;						\
		 (cell1) = lnext(cell1), (cell2) = lnext(cell2))
#define foreach(cell, l)	\
	for ((cell) = list_head(l); (cell) != NULL; (cell) = lnext(cell))
#define forthree(cell1, list1, cell2, list2, cell3, list3)			\
	for ((cell1) = list_head(list1), (cell2) = list_head(list2), (cell3) = list_head(list3); \
		 (cell1) != NULL && (cell2) != NULL && (cell3) != NULL;		\
		 (cell1) = lnext(cell1), (cell2) = lnext(cell2), (cell3) = lnext(cell3))
#define freeList(list)				list_free(list)
#define intMember(datum, list)		list_member_int(list, datum)
#define lappendi(list, datum)		lappend_int(list, datum)
#define lappendo(list, datum)		lappend_oid(list, datum)
#define lconsi(datum, list)			lcons_int(datum, list)
#define lconso(datum, list)			lcons_oid(datum, list)
#define lfirst(lc)				((lc)->data.ptr_value)
#define lfirst_int(lc)			((lc)->data.int_value)
#define lfirst_oid(lc)			((lc)->data.oid_value)
#define lfirsti(lc)					lfirst_int(lc)
#define lfirsto(lc)					lfirst_oid(lc)
#define lfourth(l)				lfirst(lnext(lnext(lnext(list_head(l)))))
#define lfourth_int(l)			lfirst_int(lnext(lnext(lnext(list_head(l)))))
#define lfourth_oid(l)			lfirst_oid(lnext(lnext(lnext(list_head(l)))))
#define linitial(l)				lfirst(list_head(l))
#define linitial_int(l)			lfirst_int(list_head(l))
#define linitial_oid(l)			lfirst_oid(list_head(l))
#define listCopy(list)				list_copy(list)
#define list_make1(x1)				lcons(x1, NIL)
#define list_make1_int(x1)			lcons_int(x1, NIL)
#define list_make1_oid(x1)			lcons_oid(x1, NIL)
#define list_make2(x1,x2)			lcons(x1, list_make1(x2))
#define list_make2_int(x1,x2)		lcons_int(x1, list_make1_int(x2))
#define list_make2_oid(x1,x2)		lcons_oid(x1, list_make1_oid(x2))
#define list_make3(x1,x2,x3)		lcons(x1, list_make2(x2, x3))
#define list_make3_int(x1,x2,x3)	lcons_int(x1, list_make2_int(x2, x3))
#define list_make3_oid(x1,x2,x3)	lcons_oid(x1, list_make2_oid(x2, x3))
#define list_make4(x1,x2,x3,x4)		lcons(x1, list_make3(x2, x3, x4))
#define list_make4_int(x1,x2,x3,x4) lcons_int(x1, list_make3_int(x2, x3, x4))
#define list_make4_oid(x1,x2,x3,x4) lcons_oid(x1, list_make3_oid(x2, x3, x4))
#define llast(l)				lfirst(list_tail(l))
#define llast_int(l)			lfirst_int(list_tail(l))
#define llast_oid(l)			lfirst_oid(list_tail(l))
#define lnext(lc)				((lc)->next)
#define lremove(elem, list)			list_delete_ptr(list, elem)
#define lremovei(elem, list)		list_delete_int(list, elem)
#define lremoveo(elem, list)		list_delete_oid(list, elem)
#define lsecond(l)				lfirst(lnext(list_head(l)))
#define lsecond_int(l)			lfirst_int(lnext(list_head(l)))
#define lsecond_oid(l)			lfirst_oid(lnext(list_head(l)))
#define lthird(l)				lfirst(lnext(lnext(list_head(l))))
#define lthird_int(l)			lfirst_int(lnext(lnext(list_head(l))))
#define lthird_oid(l)			lfirst_oid(lnext(lnext(list_head(l))))
#define ltruncate(n, list)			list_truncate(list, n)
#define makeList1(x1)				list_make1(x1)
#define makeList2(x1, x2)			list_make2(x1, x2)
#define makeList3(x1, x2, x3)		list_make3(x1, x2, x3)
#define makeList4(x1, x2, x3, x4)	list_make4(x1, x2, x3, x4)
#define makeListi1(x1)				list_make1_int(x1)
#define makeListi2(x1, x2)			list_make2_int(x1, x2)
#define makeListo1(x1)				list_make1_oid(x1)
#define makeListo2(x1, x2)			list_make2_oid(x1, x2)
#define member(datum, list)			list_member(list, datum)
#define nconc(l1, l2)				list_concat(l1, l2)
#define nth(n, list)				list_nth(list, n)
#define oidMember(datum, list)		list_member_oid(list, datum)
#define ptrMember(datum, list)		list_member_ptr(list, datum)
#define set_difference(l1, l2)		list_difference(l1, l2)
#define set_differenceo(l1, l2)		list_difference_oid(l1, l2)
#define set_ptrDifference(l1, l2)	list_difference_ptr(l1, l2)
#define set_ptrUnion(l1, l2)		list_union_ptr(l1, l2)
#define set_union(l1, l2)			list_union(l1, l2)
#define set_uniono(l1, l2)			list_union_oid(l1, l2)

#define AttrNumberGetAttrOffset(attNum) \
( \
	AssertMacro(AttrNumberIsForUserDefinedAttr(attNum)), \
	((attNum) - 1) \
)
#define AttrNumberIsForUserDefinedAttr(attributeNumber) \
	((bool) ((attributeNumber) > 0))
#define AttrOffsetGetAttrNumber(attributeOffset) \
	 ((AttrNumber) (1 + (attributeOffset)))
#define AttributeNumberIsValid(attributeNumber) \
	((bool) ((attributeNumber) != InvalidAttrNumber))

#define BITS_PER_BITMAPWORD 32


#define appendStringInfoCharMacro(str,ch) \
	(((str)->len + 1 >= (str)->maxlen) ? \
	 appendStringInfoChar(str, ch) : \
	 (void)((str)->data[(str)->len] = (ch), (str)->data[++(str)->len] = '\0'))
#define BoolGetDatum(X) ((Datum) ((X) ? 1 : 0))
#define CStringGetDatum(X) PointerGetDatum(X)
#define CharGetDatum(X) ((Datum) SET_1_BYTE(X))
#define CommandIdGetDatum(X) ((Datum) SET_4_BYTES(X))
#define DatumGetBool(X) ((bool) (((bool) (X)) != 0))
#define DatumGetCString(X) ((char *) DatumGetPointer(X))
#define DatumGetChar(X) ((char) GET_1_BYTE(X))
#define DatumGetCommandId(X) ((CommandId) GET_4_BYTES(X))
#define DatumGetFloat4(X) (* ((float4 *) DatumGetPointer(X)))
#define DatumGetFloat8(X) (* ((float8 *) DatumGetPointer(X)))
#define DatumGetInt16(X) ((int16) GET_2_BYTES(X))
#define DatumGetInt32(X) ((int32) GET_4_BYTES(X))
#define DatumGetInt64(X) ((int64) GET_8_BYTES(X))
#define DatumGetName(X) ((Name) DatumGetPointer(X))
#define DatumGetObjectId(X) ((Oid) GET_4_BYTES(X))
#define DatumGetPointer(X) ((Pointer) (X))
#define DatumGetTransactionId(X) ((TransactionId) GET_4_BYTES(X))
#define DatumGetUInt16(X) ((uint16) GET_2_BYTES(X))
#define DatumGetUInt32(X) ((uint32) GET_4_BYTES(X))
#define DatumGetUInt8(X) ((uint8) GET_1_BYTE(X))
#define Float4GetDatumFast(X) Float4GetDatum(X)
#define Float8GetDatumFast(X) Float8GetDatum(X)
#define GET_1_BYTE(datum)	(((Datum) (datum)) & 0x000000ff)
#define GET_2_BYTES(datum)	(((Datum) (datum)) & 0x0000ffff)
#define GET_4_BYTES(datum)	(((Datum) (datum)) & 0xffffffff)
#define GET_8_BYTES(datum)	((Datum) (datum))
#define Int16GetDatum(X) ((Datum) SET_2_BYTES(X))
#define Int32GetDatum(X) ((Datum) SET_4_BYTES(X))
#define Int64GetDatum(X) ((Datum) SET_8_BYTES(X))
#define Int64GetDatumFast(X)  Int64GetDatum(X)
#define Int8GetDatum(X) ((Datum) SET_1_BYTE(X))
#define MultiXactIdGetDatum(X) ((Datum) SET_4_BYTES((X)))
#define NameGetDatum(X) PointerGetDatum(X)
#define ObjectIdGetDatum(X) ((Datum) SET_4_BYTES(X))

#define PointerGetDatum(X) ((Datum) (X))
#define SET_1_BYTE(value)	(((Datum) (value)) & 0x000000ff)
#define SET_2_BYTES(value)	(((Datum) (value)) & 0x0000ffff)
#define SET_4_BYTES(value)	(((Datum) (value)) & 0xffffffff)
#define SET_8_BYTES(value)	((Datum) (value))
#define SET_VARSIZE(PTR, len)				SET_VARSIZE_4B(PTR, len)
#define SET_VARSIZE_1B(PTR,len) \
	(((varattrib_1b *) (PTR))->va_header = (len) | 0x80)
#define SET_VARSIZE_4B(PTR,len) \
	(((varattrib_4b *) (PTR))->va_4byte.va_header = (len) & 0x3FFFFFFF)
#define SET_VARSIZE_4B_C(PTR,len) \
	(((varattrib_4b *) (PTR))->va_4byte.va_header = ((len) & 0x3FFFFFFF) | 0x40000000)
#define SET_VARSIZE_COMPRESSED(PTR, len)	SET_VARSIZE_4B_C(PTR, len)
#define SET_VARSIZE_SHORT(PTR, len)			SET_VARSIZE_1B(PTR, len)
#define SET_VARTAG_1B_E(PTR,tag) \
	(((varattrib_1b_e *) (PTR))->va_header = 0x80, \
	 ((varattrib_1b_e *) (PTR))->va_tag = (tag))
#define SET_VARTAG_EXTERNAL(PTR, tag)		SET_VARTAG_1B_E(PTR, tag)
#define SIZEOF_DATUM SIZEOF_VOID_P
#define TransactionIdGetDatum(X) ((Datum) SET_4_BYTES((X)))
#define UInt16GetDatum(X) ((Datum) SET_2_BYTES(X))
#define UInt32GetDatum(X) ((Datum) SET_4_BYTES(X))
#define UInt8GetDatum(X) ((Datum) SET_1_BYTE(X))
#define VARATT_CAN_MAKE_SHORT(PTR) \
	(VARATT_IS_4B_U(PTR) && \
	 (VARSIZE(PTR) - VARHDRSZ + VARHDRSZ_SHORT) <= VARATT_SHORT_MAX)
#define VARATT_CONVERTED_SHORT_SIZE(PTR) \
	(VARSIZE(PTR) - VARHDRSZ + VARHDRSZ_SHORT)
#define VARATT_IS_1B(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0x80) == 0x80)
#define VARATT_IS_1B_E(PTR) \
	((((varattrib_1b *) (PTR))->va_header) == 0x80)
#define VARATT_IS_4B(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0x80) == 0x00)
#define VARATT_IS_4B_C(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0xC0) == 0x40)
#define VARATT_IS_4B_U(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0xC0) == 0x00)
#define VARATT_IS_COMPRESSED(PTR)			VARATT_IS_4B_C(PTR)
#define VARATT_IS_EXTENDED(PTR)				(!VARATT_IS_4B_U(PTR))
#define VARATT_IS_EXTERNAL(PTR)				VARATT_IS_1B_E(PTR)
#define VARATT_IS_EXTERNAL_INDIRECT(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_INDIRECT)
#define VARATT_IS_EXTERNAL_ONDISK(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_ONDISK)
#define VARATT_IS_SHORT(PTR)				VARATT_IS_1B(PTR)
#define VARATT_NOT_PAD_BYTE(PTR) \
	(*((uint8 *) (PTR)) != 0)
#define VARDATA(PTR)						VARDATA_4B(PTR)
#define VARDATA_1B(PTR)		(((varattrib_1b *) (PTR))->va_data)
#define VARDATA_1B_E(PTR)	(((varattrib_1b_e *) (PTR))->va_data)
#define VARDATA_4B(PTR)		(((varattrib_4b *) (PTR))->va_4byte.va_data)
#define VARDATA_4B_C(PTR)	(((varattrib_4b *) (PTR))->va_compressed.va_data)
#define VARDATA_ANY(PTR) \
	 (VARATT_IS_1B(PTR) ? VARDATA_1B(PTR) : VARDATA_4B(PTR))
#define VARDATA_EXTERNAL(PTR)				VARDATA_1B_E(PTR)
#define VARDATA_SHORT(PTR)					VARDATA_1B(PTR)
#define VARRAWSIZE_4B_C(PTR) \
	(((varattrib_4b *) (PTR))->va_compressed.va_rawsize)
#define VARSIZE(PTR)						VARSIZE_4B(PTR)
#define VARSIZE_1B(PTR) \
	(((varattrib_1b *) (PTR))->va_header & 0x7F)
#define VARSIZE_4B(PTR) \
	(((varattrib_4b *) (PTR))->va_4byte.va_header & 0x3FFFFFFF)
#define VARSIZE_ANY(PTR) \
	(VARATT_IS_1B_E(PTR) ? VARSIZE_EXTERNAL(PTR) : \
	 (VARATT_IS_1B(PTR) ? VARSIZE_1B(PTR) : \
	  VARSIZE_4B(PTR)))
#define VARSIZE_ANY_EXHDR(PTR) \
	(VARATT_IS_1B_E(PTR) ? VARSIZE_EXTERNAL(PTR)-VARHDRSZ_EXTERNAL : \
	 (VARATT_IS_1B(PTR) ? VARSIZE_1B(PTR)-VARHDRSZ_SHORT : \
	  VARSIZE_4B(PTR)-VARHDRSZ))
#define VARSIZE_EXTERNAL(PTR)				(VARHDRSZ_EXTERNAL + VARTAG_SIZE(VARTAG_EXTERNAL(PTR)))
#define VARSIZE_SHORT(PTR)					VARSIZE_1B(PTR)
#define VARTAG_1B_E(PTR) \
	(((varattrib_1b_e *) (PTR))->va_tag)
#define VARTAG_EXTERNAL(PTR)				VARTAG_1B_E(PTR)
#define VARTAG_SIZE(tag) \
	((tag) == VARTAG_INDIRECT ? sizeof(varatt_indirect) :		\
	 (tag) == VARTAG_ONDISK ? sizeof(varatt_external) : \
	 TrapMacro(true, "unknown vartag"))

#define palloc0fast(sz) \
	( MemSetTest(0, sz) ? \
		MemoryContextAllocZeroAligned(CurrentMemoryContext, sz) : \
		MemoryContextAllocZero(CurrentMemoryContext, sz) )

#define ERRCODE_IS_CATEGORY(ec)  (((ec) & ~((1 << 12) - 1)) == 0)
#define ERRCODE_TO_CATEGORY(ec)  ((ec) & ((1 << 12) - 1))
#define LOG_DESTINATION_EVENTLOG 4
#define MAKE_SQLSTATE(ch1,ch2,ch3,ch4,ch5)	\
	(PGSIXBIT(ch1) + (PGSIXBIT(ch2) << 6) + (PGSIXBIT(ch3) << 12) + \
	 (PGSIXBIT(ch4) << 18) + (PGSIXBIT(ch5) << 24))
#define PGSIXBIT(ch)	(((ch) - '0') & 0x3F)
#define PGUNSIXBIT(val) (((val) & 0x3F) + '0')
#define PG_CATCH()	\
		} \
		else \
		{ \
			PG_exception_stack = save_exception_stack; \
			error_context_stack = save_context_stack
#define PG_END_TRY()  \
		} \
		PG_exception_stack = save_exception_stack; \
		error_context_stack = save_context_stack; \
	} while (0)
#define PG_RE_THROW()  \
	pg_re_throw()
#define PG_TRY()  \
	do { \
		sigjmp_buf *save_exception_stack = PG_exception_stack; \
		ErrorContextCallback *save_context_stack = error_context_stack; \
		sigjmp_buf local_sigjmp_buf; \
		if (sigsetjmp(local_sigjmp_buf, 0) == 0) \
		{ \
			PG_exception_stack = &local_sigjmp_buf
#define TEXTDOMAIN NULL
#define elog  \
	elog_start("__FILE__", "__LINE__", PG_FUNCNAME_MACRO), \
	elog_finish
#define ereport(elevel, rest)	\
	ereport_domain(elevel, TEXTDOMAIN, rest)
#define ereport_domain(elevel, domain, rest)	\
	do { \
		if (errstart(elevel, "__FILE__", "__LINE__", PG_FUNCNAME_MACRO, domain)) \
			errfinish rest; \
		if (__builtin_constant_p(elevel) && (elevel) >= ERROR) \
			pg_unreachable(); \
	} while(0)
#define Abs(x)			((x) >= 0 ? (x) : -(x))


#define AssertMacro(condition)	((void)true)

#define AssertVariableIsOfType(varname, typename) \
	StaticAssertStmt(__builtin_types_compatible_p(__typeof__(varname), typename), \
	CppAsString(varname) " does not have type " CppAsString(typename))
#define AssertVariableIsOfTypeMacro(varname, typename) \
	((void) StaticAssertExpr(__builtin_types_compatible_p(__typeof__(varname), typename), \
	 CppAsString(varname) " does not have type " CppAsString(typename)))
#define BUFFERALIGN(LEN)		TYPEALIGN(ALIGNOF_BUFFER, (LEN))
#define BoolIsValid(boolean)	((boolean) == false || (boolean) == true)

#define CppAsString(identifier) #identifier
#define CppAsString2(x) CppAsString(x)
#define CppConcat(x, y)			x##y
#define DOUBLEALIGN(LEN)		TYPEALIGN(ALIGNOF_DOUBLE, (LEN))
#define DOUBLEALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_DOUBLE, (LEN))

#define HAVE_STRTOLL 1
#define HAVE_STRTOULL 1
#define INT64CONST(x)  ((int64) x##LL)
#define INTALIGN(LEN)			TYPEALIGN(ALIGNOF_INT, (LEN))
#define INTALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_INT, (LEN))
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)
#define LONGALIGN(LEN)			TYPEALIGN(ALIGNOF_LONG, (LEN))
#define LONGALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_LONG, (LEN))
#define LONG_ALIGN_MASK (sizeof(long) - 1)
#define MAXALIGN(LEN)			TYPEALIGN(MAXIMUM_ALIGNOF, (LEN))
#define MAXALIGN64(LEN)			TYPEALIGN64(MAXIMUM_ALIGNOF, (LEN))
#define MAXALIGN_DOWN(LEN)		TYPEALIGN_DOWN(MAXIMUM_ALIGNOF, (LEN))
#define MAXDIM 6
#define Max(x, y)		((x) > (y) ? (x) : (y))
#define MemSet(start, val, len) \
	do \
	{ \
		 \
		void   *_vstart = (void *) (start); \
		int		_val = (val); \
		Size	_len = (len); \
\
		if ((((uintptr_t) _vstart) & LONG_ALIGN_MASK) == 0 && \
			(_len & LONG_ALIGN_MASK) == 0 && \
			_val == 0 && \
			_len <= MEMSET_LOOP_LIMIT && \
			 \
			MEMSET_LOOP_LIMIT != 0) \
		{ \
			long *_start = (long *) _vstart; \
			long *_stop = (long *) ((char *) _start + _len); \
			while (_start < _stop) \
				*_start++ = 0; \
		} \
		else \
			memset(_vstart, _val, _len); \
	} while (0)
#define MemSetAligned(start, val, len) \
	do \
	{ \
		long   *_start = (long *) (start); \
		int		_val = (val); \
		Size	_len = (len); \
\
		if ((_len & LONG_ALIGN_MASK) == 0 && \
			_val == 0 && \
			_len <= MEMSET_LOOP_LIMIT && \
			MEMSET_LOOP_LIMIT != 0) \
		{ \
			long *_stop = (long *) ((char *) _start + _len); \
			while (_start < _stop) \
				*_start++ = 0; \
		} \
		else \
			memset(_start, _val, _len); \
	} while (0)
#define MemSetLoop(start, val, len) \
	do \
	{ \
		long * _start = (long *) (start); \
		long * _stop = (long *) ((char *) _start + (Size) (len)); \
	\
		while (_start < _stop) \
			*_start++ = 0; \
	} while (0)
#define MemSetTest(val, len) \
	( ((len) & LONG_ALIGN_MASK) == 0 && \
	(len) <= MEMSET_LOOP_LIMIT && \
	MEMSET_LOOP_LIMIT != 0 && \
	(val) == 0 )
#define Min(x, y)		((x) < (y) ? (x) : (y))
#define NON_EXEC_STATIC static
#define NameStr(name)	((name).data)
#define OidIsValid(objectId)  ((bool) ((objectId) != InvalidOid))


#define PG_BINARY_A "ab"
#define PG_BINARY_R "rb"
#define PG_BINARY_W "wb"
#define PG_TEXTDOMAIN(domain) (domain CppAsString2(SO_MAJOR_VERSION) "-" PG_MAJORVERSION)
#define PG_USED_FOR_ASSERTS_ONLY __attribute__((unused))
#define PointerIsAligned(pointer, type) \
		(((uintptr_t)(pointer) % (sizeof (type))) == 0)
#define PointerIsValid(pointer) ((const void*)(pointer) != NULL)
#define RegProcedureIsValid(p)	OidIsValid(p)
#define SHORTALIGN(LEN)			TYPEALIGN(ALIGNOF_SHORT, (LEN))
#define SHORTALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_SHORT, (LEN))
#define SIGNAL_ARGS  int postgres_signal_arg
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
#define STATIC_IF_INLINE static inline
#define StaticAssertExpr(condition, errmessage) \
	({ StaticAssertStmt(condition, errmessage); true; })
#define StaticAssertStmt(condition, errmessage) \
	do { _Static_assert(condition, errmessage); } while(0)
#define StrNCpy(dst,src,len) \
	do \
	{ \
		char * _dst = (dst); \
		Size _len = (len); \
\
		if (_len > 0) \
		{ \
			strncpy(_dst, (src), _len); \
			_dst[_len-1] = '\0'; \
		} \
	} while (0)
#define TYPEALIGN(ALIGNVAL,LEN)  \
	(((uintptr_t) (LEN) + ((ALIGNVAL) - 1)) & ~((uintptr_t) ((ALIGNVAL) - 1)))
#define TYPEALIGN64(ALIGNVAL,LEN)  \
	(((uint64) (LEN) + ((ALIGNVAL) - 1)) & ~((uint64) ((ALIGNVAL) - 1)))
#define TYPEALIGN_DOWN(ALIGNVAL,LEN)  \
	(((uintptr_t) (LEN)) & ~((uintptr_t) ((ALIGNVAL) - 1)))
#define Trap(condition, errorType)
#define TrapMacro(condition, errorType)	(true)
#define UINT64CONST(x) ((uint64) x##ULL)


#define _(x) gettext(x)

#define dgettext(d,x) (x)
#define dngettext(d,s,p,n) ((n) == 1 ? (s) : (p))
#define endof(array)	(&(array)[lengthof(array)])
#define errcode __msvc_errcode
#define gettext(x) (x)
#define gettext_noop(x) (x)
#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define memmove(d, s, c)		bcopy(s, d, c)
#define ngettext(s,p,n) ((n) == 1 ? (s) : (p))
#define offsetof(type, field)	((long) &((type *)0)->field)
#define pg_unreachable() __builtin_unreachable()
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll strtoq
#define strtoull strtouq
#define DEVNULL "nul"
#define EXE ".exe"
#define IS_DIR_SEP(ch)	((ch) == '/')
#define PGINVALID_SOCKET (-1)

#define PG_SIGNAL_COUNT 32
#define SYSTEMQUOTE "\""
#define TIMEZONE_GLOBAL timezone
#define TZNAME_GLOBAL tzname
#define closesocket close
#define		fopen(a,b) pgwin32_fopen(a,b)
#define fprintf(...)	pg_fprintf(__VA_ARGS__)
#define fseeko(a, b, c) fseek(a, b, c)
#define ftello(a)		ftell(a)
#define is_absolute_path(filename) \
( \
	IS_DIR_SEP((filename)[0]) \
)
#define kill(pid,sig)	pgkill(pid,sig)
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pgoff_t off_t
#define popen(a,b) _popen(a,b)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define readlink(path, buf, size)	pgreadlink(path, buf, size)
#define rename(from, to)		pgrename(from, to)
#define setlocale(a,b) pgwin32_setlocale(a,b)
#define snprintf(...)	pg_snprintf(__VA_ARGS__)
#define sprintf(...)	pg_sprintf(__VA_ARGS__)
#define stat(a,b) pgwin32_safestat(a,b)
#define symlink(oldpath, newpath)	pgsymlink(oldpath, newpath)
#define unlink(path)			pgunlink(path)
#define vfprintf(...)	pg_vfprintf(__VA_ARGS__)
#define vsnprintf(...)	pg_vsnprintf(__VA_ARGS__)
#define OID_MAX  UINT_MAX
#define PG_DIAG_CONSTRAINT_NAME 'n'
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

