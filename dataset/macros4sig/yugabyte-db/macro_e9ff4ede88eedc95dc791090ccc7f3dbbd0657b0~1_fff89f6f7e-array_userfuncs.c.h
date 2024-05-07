#include<fcntl.h>






#include<sys/types.h>
#include<sys/stat.h>
#include<errno.h>


#include<locale.h>



#include<netdb.h>


#include<string.h>

#include<strings.h>
#include<arpa/inet.h>

#include<stdint.h>







#include<signal.h>
#include<stddef.h>

#include<stdio.h>
#include<netinet/in.h>

#include<pwd.h>


#include<stdlib.h>
#include<assert.h>
#include<setjmp.h>


#include<math.h>
#include<stdbool.h>


#include<ctype.h>
#include<stdarg.h>
#include<libintl.h>
#include<limits.h>

#define INVALID_TUPLEDESC_IDENTIFIER ((uint64) 1)


#define DSA_POINTER_FORMAT "%08x"
#define DsaPointerIsValid(x) ((x) != InvalidDsaPointer)
#define InvalidDsaPointer ((dsa_pointer) 0)
#define SIZEOF_DSA_POINTER 4
#define dsa_allocate(area, size) \
	dsa_allocate_extended(area, size, 0)
#define dsa_allocate0(area, size) \
	dsa_allocate_extended(area, size, DSA_ALLOC_ZERO)
#define dsa_pointer_atomic_compare_exchange pg_atomic_compare_exchange_u32
#define dsa_pointer_atomic_fetch_add pg_atomic_fetch_add_u32
#define dsa_pointer_atomic_init pg_atomic_init_u32
#define dsa_pointer_atomic_read pg_atomic_read_u32
#define dsa_pointer_atomic_write pg_atomic_write_u32

#define DSM_HANDLE_INVALID 0







#define pg_compiler_barrier()	pg_compiler_barrier_impl()
#define pg_memory_barrier() pg_memory_barrier_impl()
#define pg_read_barrier()	pg_read_barrier_impl()
#define pg_spin_delay() pg_spin_delay_impl()
#define pg_write_barrier()	pg_write_barrier_impl()



























#define pg_spin_delay_impl()	((void)0)









#define pg_compiler_barrier_impl pg_extern_compiler_barrier
#define pg_memory_barrier_impl pg_spinlock_barrier
#define MINOR_FENCE (_Asm_fence) (_UP_CALL_FENCE | _UP_SYS_FENCE | \
								 _DOWN_CALL_FENCE | _DOWN_SYS_FENCE )
#		define pg_read_barrier_impl()		__atomic_thread_fence(__ATOMIC_ACQUIRE)
#		define pg_write_barrier_impl()		__atomic_thread_fence(__ATOMIC_RELEASE)


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
#define FIELDNO_FUNCTIONCALLINFODATA_ARGS 6
#define FIELDNO_FUNCTIONCALLINFODATA_ISNULL 4

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
#define LOCAL_FCINFO(name, nargs) \
	 \
	union \
	{ \
		FunctionCallInfoBaseData fcinfo; \
		 \
		char fcinfo_data[SizeForFunctionCallInfo(nargs)]; \
	} name##data; \
	FunctionCallInfo name = &name##data.fcinfo
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
#define PG_ARGISNULL(n)  (fcinfo->args[n].isnull)
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
extern Datum funcname(PG_FUNCTION_ARGS); \
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
#define PG_GETARG_DATUM(n)	 (fcinfo->args[n].value)
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
#define PG_RETURN_HEAPTUPLEHEADER(x)  return HeapTupleHeaderGetDatum(x)
#define PG_RETURN_INT16(x)	 return Int16GetDatum(x)
#define PG_RETURN_INT32(x)	 return Int32GetDatum(x)
#define PG_RETURN_INT64(x)	 return Int64GetDatum(x)
#define PG_RETURN_NAME(x)	 return NameGetDatum(x)
#define PG_RETURN_NULL()  \
	do { fcinfo->isnull = true; return (Datum) 0; } while (0)
#define PG_RETURN_OID(x)	 return ObjectIdGetDatum(x)
#define PG_RETURN_POINTER(x) return PointerGetDatum(x)
#define PG_RETURN_TEXT_P(x)    PG_RETURN_POINTER(x)
#define PG_RETURN_UINT16(x)  return UInt16GetDatum(x)
#define PG_RETURN_UINT32(x)  return UInt32GetDatum(x)
#define PG_RETURN_UINT64(x)  return UInt64GetDatum(x)
#define PG_RETURN_VARCHAR_P(x) PG_RETURN_POINTER(x)
#define PG_RETURN_VOID()	 return (Datum) 0
#define SizeForFunctionCallInfo(nargs) \
	(offsetof(FunctionCallInfoBaseData, args) + \
	 sizeof(NullableDatum) * (nargs))
#define fmgr_info_set_expr(expr, finfo) \
	((finfo)->fn_expr = (expr))
#define PinTupleDesc(tupdesc) \
	do { \
		if ((tupdesc)->tdrefcount >= 0) \
			IncrTupleDescRefCount(tupdesc); \
	} while (0)
#define ReleaseTupleDesc(tupdesc) \
	do { \
		if ((tupdesc)->tdrefcount >= 0) \
			DecrTupleDescRefCount(tupdesc); \
	} while (0)

#define TupleDescAttr(tupdesc, i) (&(tupdesc)->attrs[(i)])
#define TupleDescSize(src) \
	(offsetof(struct tupleDesc, attrs) + \
	 (src)->natts * sizeof(FormData_pg_attribute))
#define LispRemove(elem, list)		list_delete(list, elem)

#define equali(l1, l2)				equal(l1, l2)
#define equalo(l1, l2)				equal(l1, l2)
#define for_both_cell(cell1, initcell1, cell2, initcell2)	\
	for ((cell1) = (initcell1), (cell2) = (initcell2);		\
		 (cell1) != NULL && (cell2) != NULL;				\
		 (cell1) = lnext(cell1), (cell2) = lnext(cell2))
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
#define lfirst_node(type,lc)	castNode(type, lfirst(lc))
#define lfirst_oid(lc)			((lc)->data.oid_value)
#define lfirsti(lc)					lfirst_int(lc)
#define lfirsto(lc)					lfirst_oid(lc)
#define lfourth(l)				lfirst(lnext(lnext(lnext(list_head(l)))))
#define lfourth_int(l)			lfirst_int(lnext(lnext(lnext(list_head(l)))))
#define lfourth_node(type,l)	castNode(type, lfourth(l))
#define lfourth_oid(l)			lfirst_oid(lnext(lnext(lnext(list_head(l)))))
#define linitial(l)				lfirst(list_head(l))
#define linitial_int(l)			lfirst_int(list_head(l))
#define linitial_node(type,l)	castNode(type, linitial(l))
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
#define list_make5(x1,x2,x3,x4,x5)	lcons(x1, list_make4(x2, x3, x4, x5))
#define list_make5_int(x1,x2,x3,x4,x5)	lcons_int(x1, list_make4_int(x2, x3, x4, x5))
#define list_make5_oid(x1,x2,x3,x4,x5)	lcons_oid(x1, list_make4_oid(x2, x3, x4, x5))
#define list_nth_node(type,list,n)	castNode(type, list_nth(list, n))
#define llast(l)				lfirst(list_tail(l))
#define llast_int(l)			lfirst_int(list_tail(l))
#define llast_node(type,l)		castNode(type, llast(l))
#define llast_oid(l)			lfirst_oid(list_tail(l))
#define lnext(lc)				((lc)->next)
#define lremove(elem, list)			list_delete_ptr(list, elem)
#define lremovei(elem, list)		list_delete_int(list, elem)
#define lremoveo(elem, list)		list_delete_oid(list, elem)
#define lsecond(l)				lfirst(lnext(list_head(l)))
#define lsecond_int(l)			lfirst_int(lnext(list_head(l)))
#define lsecond_node(type,l)	castNode(type, lsecond(l))
#define lsecond_oid(l)			lfirst_oid(lnext(list_head(l)))
#define lthird(l)				lfirst(lnext(lnext(list_head(l))))
#define lthird_int(l)			lfirst_int(lnext(lnext(list_head(l))))
#define lthird_node(type,l)		castNode(type, lthird(l))
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
#define DO_AGGSPLIT_COMBINE(as)		(((as) & AGGSPLITOP_COMBINE) != 0)
#define DO_AGGSPLIT_DESERIALIZE(as) (((as) & AGGSPLITOP_DESERIALIZE) != 0)
#define DO_AGGSPLIT_SERIALIZE(as)	(((as) & AGGSPLITOP_SERIALIZE) != 0)
#define DO_AGGSPLIT_SKIPFINAL(as)	(((as) & AGGSPLITOP_SKIPFINAL) != 0)
#define IS_OUTER_JOIN(jointype) \
	(((1 << (jointype)) & \
	  ((1 << JOIN_LEFT) | \
	   (1 << JOIN_FULL) | \
	   (1 << JOIN_RIGHT) | \
	   (1 << JOIN_ANTI))) != 0)
#define IsA(nodeptr,_type_)		(nodeTag(nodeptr) == T_##_type_)

#define NodeSetTag(nodeptr,t)	(((Node*)(nodeptr))->type = (t))
#define castNode(_type_, nodeptr) ((_type_ *) castNodeImpl(T_##_type_, nodeptr))
#define copyObject(obj) ((typeof(obj)) copyObjectImpl(obj))
#define makeNode(_type_)		((_type_ *) newNode(sizeof(_type_),T_##_type_))
#define newNode(size, tag) \
({	Node   *_result; \
	AssertMacro((size) >= sizeof(Node));		 \
	_result = (Node *) palloc0fast(size); \
	_result->type = (tag); \
	_result; \
})
#define nodeTag(nodeptr)		(((const Node*)(nodeptr))->type)
#define ATTRIBUTE_FIXED_PART_SIZE \
	(offsetof(FormData_pg_attribute,attcollation) + sizeof(Oid))
#define		  ATTRIBUTE_IDENTITY_BY_DEFAULT 'd'











#define CATALOG(name,oid,oidmacro)	typedef struct CppConcat(FormData_,name)


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

#define TypeIsToastable(typid)	(get_typstorage(typid) != 'p')
#define type_is_array(typid)  (get_element_type(typid) != InvalidOid)
#define type_is_array_domain(typid)  (get_base_element_type(typid) != InvalidOid)
#define FIELDNO_HEAPTUPLEDATA_DATA 3
#define HEAPTUPLE_COPY_YBCTID(src, dest)                            \
    do {                                                            \
        if (IsYugaByteEnabled()) {                                  \
            dest = (src == 0) ? 0 :                                 \
                PointerGetDatum(cstring_to_text_with_len(VARDATA_ANY(src), \
                                                         VARSIZE_ANY_EXHDR(src))); \
        } else {                                                    \
            dest = 0;                                               \
        }                                                           \
    } while (false)

#define HeapTupleIsValid(tuple) PointerIsValid(tuple)

#define ItemPointerCopy(fromPointer, toPointer) \
( \
	AssertMacro(PointerIsValid(toPointer)), \
	AssertMacro(PointerIsValid(fromPointer)), \
	*(toPointer) = *(fromPointer) \
)
#define ItemPointerGetBlockNumber(pointer) \
( \
	AssertMacro(ItemPointerIsValid(pointer)), \
	ItemPointerGetBlockNumberNoCheck(pointer) \
)
#define ItemPointerGetBlockNumberNoCheck(pointer) \
( \
	BlockIdGetBlockNumber(&(pointer)->ip_blkid) \
)
#define ItemPointerGetOffsetNumber(pointer) \
( \
	AssertMacro(ItemPointerIsValid(pointer)), \
	ItemPointerGetOffsetNumberNoCheck(pointer) \
)
#define ItemPointerGetOffsetNumberNoCheck(pointer) \
( \
	(pointer)->ip_posid \
)
#define ItemPointerIndicatesMovedPartitions(pointer) \
( \
	ItemPointerGetOffsetNumber(pointer) == MovedPartitionsOffsetNumber && \
	ItemPointerGetBlockNumberNoCheck(pointer) == MovedPartitionsBlockNumber \
)
#define ItemPointerIsValid(pointer) \
	((bool) (PointerIsValid(pointer) && ((pointer)->ip_posid != 0)))
#define ItemPointerSet(pointer, blockNumber, offNum) \
( \
	AssertMacro(PointerIsValid(pointer)), \
	BlockIdSet(&((pointer)->ip_blkid), blockNumber), \
	(pointer)->ip_posid = offNum \
)
#define ItemPointerSetBlockNumber(pointer, blockNumber) \
( \
	AssertMacro(PointerIsValid(pointer)), \
	BlockIdSet(&((pointer)->ip_blkid), blockNumber) \
)
#define ItemPointerSetInvalid(pointer) \
( \
	AssertMacro(PointerIsValid(pointer)), \
	BlockIdSet(&((pointer)->ip_blkid), InvalidBlockNumber), \
	(pointer)->ip_posid = InvalidOffsetNumber \
)
#define ItemPointerSetMovedPartitions(pointer) \
	ItemPointerSet((pointer), MovedPartitionsBlockNumber, MovedPartitionsOffsetNumber)
#define ItemPointerSetOffsetNumber(pointer, offsetNumber) \
( \
	AssertMacro(PointerIsValid(pointer)), \
	(pointer)->ip_posid = (offsetNumber) \
)
#define MovedPartitionsOffsetNumber 0xfffd

#define OffsetNumberIsValid(offsetNumber) \
	((bool) ((offsetNumber != InvalidOffsetNumber) && \
			 (offsetNumber <= MaxOffsetNumber)))
#define OffsetNumberNext(offsetNumber) \
	((OffsetNumber) (1 + (offsetNumber)))
#define OffsetNumberPrev(offsetNumber) \
	((OffsetNumber) (-1 + (offsetNumber)))

#define ItemIdGetFlags(itemId) \
   ((itemId)->lp_flags)
#define ItemIdGetLength(itemId) \
   ((itemId)->lp_len)
#define ItemIdGetOffset(itemId) \
   ((itemId)->lp_off)
#define ItemIdGetRedirect(itemId) \
   ((itemId)->lp_off)
#define ItemIdHasStorage(itemId) \
	((itemId)->lp_len != 0)
#define ItemIdIsDead(itemId) \
	((itemId)->lp_flags == LP_DEAD)
#define ItemIdIsNormal(itemId) \
	((itemId)->lp_flags == LP_NORMAL)
#define ItemIdIsRedirected(itemId) \
	((itemId)->lp_flags == LP_REDIRECT)
#define ItemIdIsUsed(itemId) \
	((itemId)->lp_flags != LP_UNUSED)
#define ItemIdIsValid(itemId)	PointerIsValid(itemId)
#define ItemIdMarkDead(itemId) \
( \
	(itemId)->lp_flags = LP_DEAD \
)
#define ItemIdSetDead(itemId) \
( \
	(itemId)->lp_flags = LP_DEAD, \
	(itemId)->lp_off = 0, \
	(itemId)->lp_len = 0 \
)
#define ItemIdSetNormal(itemId, off, len) \
( \
	(itemId)->lp_flags = LP_NORMAL, \
	(itemId)->lp_off = (off), \
	(itemId)->lp_len = (len) \
)
#define ItemIdSetRedirect(itemId, link) \
( \
	(itemId)->lp_flags = LP_REDIRECT, \
	(itemId)->lp_off = (link), \
	(itemId)->lp_len = 0 \
)
#define ItemIdSetUnused(itemId) \
( \
	(itemId)->lp_flags = LP_UNUSED, \
	(itemId)->lp_off = 0, \
	(itemId)->lp_len = 0 \
)

#define BlockIdCopy(toBlockId, fromBlockId) \
( \
	AssertMacro(PointerIsValid(toBlockId)), \
	AssertMacro(PointerIsValid(fromBlockId)), \
	(toBlockId)->bi_hi = (fromBlockId)->bi_hi, \
	(toBlockId)->bi_lo = (fromBlockId)->bi_lo \
)
#define BlockIdEquals(blockId1, blockId2) \
	((blockId1)->bi_hi == (blockId2)->bi_hi && \
	 (blockId1)->bi_lo == (blockId2)->bi_lo)
#define BlockIdGetBlockNumber(blockId) \
( \
	AssertMacro(BlockIdIsValid(blockId)), \
	(BlockNumber) (((blockId)->bi_hi << 16) | ((uint16) (blockId)->bi_lo)) \
)
#define BlockIdIsValid(blockId) \
	((bool) PointerIsValid(blockId))
#define BlockIdSet(blockId, blockNumber) \
( \
	AssertMacro(PointerIsValid(blockId)), \
	(blockId)->bi_hi = (blockNumber) >> 16, \
	(blockId)->bi_lo = (blockNumber) & 0xffff \
)
#define BlockNumberIsValid(blockNumber) \
	((bool) ((BlockNumber) (blockNumber) != InvalidBlockNumber))

#define CStringGetTextDatum(s) PointerGetDatum(cstring_to_text(s))
#define TextDatumGetCString(d) text_to_cstring((text *) DatumGetPointer(d))
#define AARR_DIMS(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? (a)->xpn.dims : ARR_DIMS(&(a)->flt))
#define AARR_ELEMTYPE(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? (a)->xpn.element_type : ARR_ELEMTYPE(&(a)->flt))
#define AARR_HASNULL(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? \
	 ((a)->xpn.dvalues != NULL ? (a)->xpn.dnulls != NULL : ARR_HASNULL((a)->xpn.fvalue)) : \
	 ARR_HASNULL(&(a)->flt))
#define AARR_LBOUND(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? (a)->xpn.lbound : ARR_LBOUND(&(a)->flt))
#define AARR_NDIM(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? (a)->xpn.ndims : ARR_NDIM(&(a)->flt))

#define ARR_DATA_OFFSET(a) \
		(ARR_HASNULL(a) ? (a)->dataoffset : ARR_OVERHEAD_NONULLS(ARR_NDIM(a)))
#define ARR_DATA_PTR(a) \
		(((char *) (a)) + ARR_DATA_OFFSET(a))
#define ARR_DIMS(a) \
		((int *) (((char *) (a)) + sizeof(ArrayType)))
#define ARR_ELEMTYPE(a)			((a)->elemtype)
#define ARR_HASNULL(a)			((a)->dataoffset != 0)
#define ARR_LBOUND(a) \
		((int *) (((char *) (a)) + sizeof(ArrayType) + \
				  sizeof(int) * ARR_NDIM(a)))
#define ARR_NDIM(a)				((a)->ndim)
#define ARR_NULLBITMAP(a) \
		(ARR_HASNULL(a) ? \
		 (bits8 *) (((char *) (a)) + sizeof(ArrayType) + \
					2 * sizeof(int) * ARR_NDIM(a)) \
		 : (bits8 *) NULL)
#define ARR_OVERHEAD_NONULLS(ndims) \
		MAXALIGN(sizeof(ArrayType) + 2 * sizeof(int) * (ndims))
#define ARR_OVERHEAD_WITHNULLS(ndims, nitems) \
		MAXALIGN(sizeof(ArrayType) + 2 * sizeof(int) * (ndims) + \
				 ((nitems) + 7) / 8)
#define ARR_SIZE(a)				VARSIZE(a)
#define DatumGetArrayTypeP(X)		  ((ArrayType *) PG_DETOAST_DATUM(X))
#define DatumGetArrayTypePCopy(X)	  ((ArrayType *) PG_DETOAST_DATUM_COPY(X))
#define EA_MAGIC 689375833		
#define PG_GETARG_ANY_ARRAY_P(n)	DatumGetAnyArrayP(PG_GETARG_DATUM(n))
#define PG_GETARG_ARRAYTYPE_P(n)	  DatumGetArrayTypeP(PG_GETARG_DATUM(n))
#define PG_GETARG_ARRAYTYPE_P_COPY(n) DatumGetArrayTypePCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_EXPANDED_ARRAY(n)  DatumGetExpandedArray(PG_GETARG_DATUM(n))
#define PG_GETARG_EXPANDED_ARRAYX(n, metacache) \
	DatumGetExpandedArrayX(PG_GETARG_DATUM(n), metacache)
#define PG_RETURN_ARRAYTYPE_P(x)	  PG_RETURN_POINTER(x)
#define PG_RETURN_EXPANDED_ARRAY(x)  PG_RETURN_DATUM(EOHPGetRWDatum(&(x)->hdr))
#define DatumIsReadWriteExpandedObject(d, isnull, typlen) \
	(((isnull) || (typlen) != -1) ? false : \
	 VARATT_IS_EXTERNAL_EXPANDED_RW(DatumGetPointer(d)))
#define EOHPGetRODatum(eohptr)	PointerGetDatum((eohptr)->eoh_ro_ptr)
#define EOHPGetRWDatum(eohptr)	PointerGetDatum((eohptr)->eoh_rw_ptr)
#define EOH_HEADER_MAGIC (-1)

#define EXPANDED_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_expanded))
#define MakeExpandedObjectReadOnly(d, isnull, typlen) \
	(((isnull) || (typlen) != -1) ? (d) : \
	 MakeExpandedObjectReadOnlyInternal(d))
#define VARATT_IS_EXPANDED_HEADER(PTR) \
	(((ExpandedObjectHeader *) (PTR))->vl_len_ == EOH_HEADER_MAGIC)

#define IsPolymorphicType(typid)  \
	((typid) == ANYELEMENTOID || \
	 (typid) == ANYARRAYOID || \
	 (typid) == ANYNONARRAYOID || \
	 (typid) == ANYENUMOID || \
	 (typid) == ANYRANGEOID)

#define  TYPCATEGORY_PSEUDOTYPE 'P'

#define ObjectAddressSet(addr, class_id, object_id) \
	ObjectAddressSubSet(addr, class_id, object_id, 0)
#define ObjectAddressSubSet(addr, class_id, object_id, object_sub_id) \
	do { \
		(addr).classId = (class_id); \
		(addr).objectId = (object_id); \
		(addr).objectSubId = (object_sub_id); \
	} while (0)


#define BITS_PER_BITMAPWORD 32
#define ACLITEM_GET_GOPTIONS(item) (((item).ai_privs >> 16) & 0xFFFF)
#define ACLITEM_GET_PRIVS(item)    ((item).ai_privs & 0xFFFF)
#define ACLITEM_GET_RIGHTS(item)   ((item).ai_privs)
#define ACLITEM_SET_GOPTIONS(item,goptions) \
  ((item).ai_privs = ((item).ai_privs & ~(((AclMode) 0xFFFF) << 16)) | \
					 (((AclMode) (goptions) & 0xFFFF) << 16))
#define ACLITEM_SET_PRIVS(item,privs) \
  ((item).ai_privs = ((item).ai_privs & ~((AclMode) 0xFFFF)) | \
					 ((AclMode) (privs) & 0xFFFF))
#define ACLITEM_SET_PRIVS_GOPTIONS(item,privs,goptions) \
  ((item).ai_privs = ((AclMode) (privs) & 0xFFFF) | \
					 (((AclMode) (goptions) & 0xFFFF) << 16))
#define ACLITEM_SET_RIGHTS(item,rights) \
  ((item).ai_privs = (AclMode) (rights))
#define ACL_ALL_RIGHTS_FOREIGN_SERVER (ACL_USAGE)
#define ACL_DAT(ACL)			((AclItem *) ARR_DATA_PTR(ACL))
#define ACL_GRANT_OPTION_FOR(privs) (((AclMode) (privs) & 0xFFFF) << 16)

#define ACL_NUM(ACL)			(ARR_DIMS(ACL)[0])
#define ACL_N_SIZE(N)			(ARR_OVERHEAD_NONULLS(1) + ((N) * sizeof(AclItem)))
#define ACL_OPTION_TO_PRIVS(privs)	(((AclMode) (privs) >> 16) & 0xFFFF)
#define ACL_SIZE(ACL)			ARR_SIZE(ACL)
#define DatumGetAclItemP(X)		   ((AclItem *) DatumGetPointer(X))
#define DatumGetAclP(X)			   ((Acl *) PG_DETOAST_DATUM(X))
#define DatumGetAclPCopy(X)		   ((Acl *) PG_DETOAST_DATUM_COPY(X))
#define PG_GETARG_ACLITEM_P(n)	   DatumGetAclItemP(PG_GETARG_DATUM(n))
#define PG_GETARG_ACL_P(n)		   DatumGetAclP(PG_GETARG_DATUM(n))
#define PG_GETARG_ACL_P_COPY(n)    DatumGetAclPCopy(PG_GETARG_DATUM(n))
#define PG_RETURN_ACLITEM_P(x)	   PG_RETURN_POINTER(x)
#define PG_RETURN_ACL_P(x)		   PG_RETURN_POINTER(x)


#define BufferIsInvalid(buffer) ((buffer) == InvalidBuffer)
#define BufferIsLocal(buffer)	((buffer) < 0)

#define pairingheap_const_container(type, membername, ptr) \
	(AssertVariableIsOfTypeMacro(ptr, const pairingheap_node *), \
	 AssertVariableIsOfTypeMacro(((type *) NULL)->membername, pairingheap_node),  \
	 ((const type *) ((const char *) (ptr) - offsetof(type, membername))))
#define pairingheap_container(type, membername, ptr) \
	(AssertVariableIsOfTypeMacro(ptr, pairingheap_node *), \
	 AssertVariableIsOfTypeMacro(((type *) NULL)->membername, pairingheap_node),  \
	 ((type *) ((char *) (ptr) - offsetof(type, membername))))
#define pairingheap_is_empty(h)			((h)->ph_root == NULL)
#define pairingheap_is_singular(h) \
	((h)->ph_root && (h)->ph_root->first_child == NULL)
#define pairingheap_reset(h)			((h)->ph_root = NULL)

#define appendStringInfoCharMacro(str,ch) \
	(((str)->len + 1 >= (str)->maxlen) ? \
	 appendStringInfoChar(str, ch) : \
	 (void)((str)->data[(str)->len] = (ch), (str)->data[++(str)->len] = '\0'))

#define DATETIME_MIN_JULIAN (0)
#define DATE_END_JULIAN (2147483494)	
#define IS_VALID_DATE(d) \
	((DATETIME_MIN_JULIAN - POSTGRES_EPOCH_JDATE) <= (d) && \
	 (d) < (DATE_END_JULIAN - POSTGRES_EPOCH_JDATE))
#define IS_VALID_JULIAN(y,m,d) \
	(((y) > JULIAN_MINYEAR || \
	  ((y) == JULIAN_MINYEAR && ((m) >= JULIAN_MINMONTH))) && \
	 ((y) < JULIAN_MAXYEAR || \
	  ((y) == JULIAN_MAXYEAR && ((m) < JULIAN_MAXMONTH))))
#define IS_VALID_TIMESTAMP(t)  (MIN_TIMESTAMP <= (t) && (t) < END_TIMESTAMP)
#define JULIAN_MAXDAY (3)
#define JULIAN_MAXMONTH (6)
#define JULIAN_MAXYEAR (5874898)
#define JULIAN_MINDAY (24)
#define JULIAN_MINMONTH (11)
#define JULIAN_MINYEAR (-4713)
#define MAX_INTERVAL_PRECISION 6
#define MAX_TIMESTAMP_PRECISION 6
#define MONTHS_PER_YEAR 12
#define SECS_PER_MINUTE 60
#define TIMESTAMP_END_JULIAN (109203528)	
#define TIMESTAMP_IS_NOBEGIN(j) ((j) == DT_NOBEGIN)
#define TIMESTAMP_IS_NOEND(j)	((j) == DT_NOEND)
#define TIMESTAMP_NOBEGIN(j)	\
	do {(j) = DT_NOBEGIN;} while (0)
#define TIMESTAMP_NOEND(j)		\
	do {(j) = DT_NOEND;} while (0)
#define TIMESTAMP_NOT_FINITE(j) (TIMESTAMP_IS_NOBEGIN(j) || TIMESTAMP_IS_NOEND(j))
#define TSROUND(j) (rint(((double) (j)) * TS_PREC_INV) / TS_PREC_INV)
#define TS_PREC_INV 1000000.0
#define USECS_PER_MINUTE INT64CONST(60000000)

#define XLogRecPtrIsInvalid(r)	((r) == InvalidXLogRecPtr)


#define ACL_CREATE_TEMP (1<<10) 
#define CURSOR_OPT_GENERIC_PLAN 0x0040	
#define FRAMEOPTION_DEFAULTS \
	(FRAMEOPTION_RANGE | FRAMEOPTION_START_UNBOUNDED_PRECEDING | \
	 FRAMEOPTION_END_CURRENT_ROW)
#define FRAMEOPTION_END_OFFSET \
	(FRAMEOPTION_END_OFFSET_PRECEDING | FRAMEOPTION_END_OFFSET_FOLLOWING)
#define FRAMEOPTION_EXCLUSION \
	(FRAMEOPTION_EXCLUDE_CURRENT_ROW | FRAMEOPTION_EXCLUDE_GROUP | \
	 FRAMEOPTION_EXCLUDE_TIES)
#define FRAMEOPTION_START_OFFSET \
	(FRAMEOPTION_START_OFFSET_PRECEDING | FRAMEOPTION_START_OFFSET_FOLLOWING)
#define GetCTETargetList(cte) \
	(AssertMacro(IsA((cte)->ctequery, Query)), \
	 ((Query *) (cte)->ctequery)->commandType == CMD_SELECT ? \
	 ((Query *) (cte)->ctequery)->targetList : \
	 ((Query *) (cte)->ctequery)->returningList)

#define REINDEXOPT_VERBOSE 1 << 0	


#define floatVal(v)		atof(((Value *)(v))->val.str)
#define intVal(v)		(((Value *)(v))->val.ival)
#define strVal(v)		(((Value *)(v))->val.str)
#define IS_SPECIAL_VARNO(varno)		((varno) >= INNER_VAR)



#define ShareUpdateExclusiveLock 4	
#define BoolGetDatum(X) ((Datum) ((X) ? 1 : 0))
#define CStringGetDatum(X) PointerGetDatum(X)
#define CharGetDatum(X) ((Datum) (X))
#define CommandIdGetDatum(X) ((Datum) (X))
#define DatumGetBool(X) ((bool) ((X) != 0))
#define DatumGetCString(X) ((char *) DatumGetPointer(X))
#define DatumGetChar(X) ((char) (X))
#define DatumGetCommandId(X) ((CommandId) (X))
#define DatumGetFloat4(X) (* ((float4 *) DatumGetPointer(X)))
#define DatumGetFloat8(X) (* ((float8 *) DatumGetPointer(X)))
#define DatumGetInt16(X) ((int16) (X))
#define DatumGetInt32(X) ((int32) (X))
#define DatumGetInt64(X) ((int64) (X))
#define DatumGetName(X) ((Name) DatumGetPointer(X))
#define DatumGetObjectId(X) ((Oid) (X))
#define DatumGetPointer(X) ((Pointer) (X))
#define DatumGetTransactionId(X) ((TransactionId) (X))
#define DatumGetUInt16(X) ((uint16) (X))
#define DatumGetUInt32(X) ((uint32) (X))
#define DatumGetUInt64(X) ((uint64) (X))
#define DatumGetUInt8(X) ((uint8) (X))
#define FIELDNO_NULLABLE_DATUM_DATUM 0
#define FIELDNO_NULLABLE_DATUM_ISNULL 1
#define Float4GetDatumFast(X) Float4GetDatum(X)
#define Float8GetDatumFast(X) Float8GetDatum(X)
#define Int16GetDatum(X) ((Datum) (X))
#define Int32GetDatum(X) ((Datum) (X))
#define Int64GetDatum(X) ((Datum) (X))
#define Int64GetDatumFast(X)  Int64GetDatum(X)
#define Int8GetDatum(X) ((Datum) (X))
#define MultiXactIdGetDatum(X) ((Datum) (X))
#define NameGetDatum(X) CStringGetDatum(NameStr(*(X)))
#define ObjectIdGetDatum(X) ((Datum) (X))

#define PointerGetDatum(X) ((Datum) (X))
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
#define TransactionIdGetDatum(X) ((Datum) (X))
#define UInt16GetDatum(X) ((Datum) (X))
#define UInt32GetDatum(X) ((Datum) (X))
#define UInt64GetDatum(X) ((Datum) (X))
#define UInt8GetDatum(X) ((Datum) (X))
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
#define VARATT_IS_EXTERNAL_EXPANDED(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_IS_EXPANDED(VARTAG_EXTERNAL(PTR)))
#define VARATT_IS_EXTERNAL_EXPANDED_RO(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_EXPANDED_RO)
#define VARATT_IS_EXTERNAL_EXPANDED_RW(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_EXPANDED_RW)
#define VARATT_IS_EXTERNAL_INDIRECT(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_INDIRECT)
#define VARATT_IS_EXTERNAL_NON_EXPANDED(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && !VARTAG_IS_EXPANDED(VARTAG_EXTERNAL(PTR)))
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
#define VARTAG_IS_EXPANDED(tag) \
	(((tag) & ~1) == VARTAG_EXPANDED_RO)
#define VARTAG_SIZE(tag) \
	((tag) == VARTAG_INDIRECT ? sizeof(varatt_indirect) : \
	 VARTAG_IS_EXPANDED(tag) ? sizeof(varatt_expanded) : \
	 (tag) == VARTAG_ONDISK ? sizeof(varatt_external) : \
	 TrapMacro(true, "unrecognized TOAST vartag"))

#define palloc0fast(sz) \
	( MemSetTest(0, sz) ? \
		MemoryContextAllocZeroAligned(GetCurrentMemoryContext(), sz) : \
		MemoryContextAllocZero(GetCurrentMemoryContext(), sz) )

#define ERRCODE_IS_CATEGORY(ec)  (((ec) & ~((1 << 12) - 1)) == 0)
#define ERRCODE_TO_CATEGORY(ec)  ((ec) & ((1 << 12) - 1))
#define LOG_DESTINATION_EVENTLOG 4
#define LOG_SERVER_ONLY 16		
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
		if (IsMultiThreadedMode()) { \
		   yb_pgbackend_ereport_dummy rest; \
		   yb_pgbackend_ereport(elevel, NULL); \
		} \
		if (errstart(elevel, "__FILE__", "__LINE__", PG_FUNCNAME_MACRO, domain)) \
			errfinish rest; \
		if (__builtin_constant_p(elevel) && (elevel) >= ERROR) \
			pg_unreachable(); \
	} while(0)
#define CHECKED_YBCSTATUS __attribute__ ((warn_unused_result)) YBCStatus
#define YBC_DEBUG_LOG_ERROR(...) YBC_LOG_ERROR(__VA_ARGS__)
#define YBC_DEBUG_LOG_FATAL(...) YBC_LOG_FATAL(__VA_ARGS__)

#define YBC_DEBUG_LOG_WARNING(...) YBC_LOG_WARNING(__VA_ARGS__)
#define YBC_LOG_ERROR(...) \
    YBCLogImpl( 2, "__FILE__", "__LINE__",  false, __VA_ARGS__)
#define YBC_LOG_ERROR_STACK_TRACE(...) \
    YBCLogImpl( 2, "__FILE__", "__LINE__",  true, __VA_ARGS__)
#define YBC_LOG_FATAL(...) \
    YBCLogImpl( 3, "__FILE__", "__LINE__",  false, __VA_ARGS__)
#define YBC_LOG_INFO(...) \
    YBCLogImpl( 0, "__FILE__", "__LINE__",  false, __VA_ARGS__)
#define YBC_LOG_INFO_STACK_TRACE(...) \
    YBCLogImpl( 0, "__FILE__", "__LINE__",  true, __VA_ARGS__)
#define YBC_LOG_WARNING(...) \
    YBCLogImpl( 1, "__FILE__", "__LINE__",  false, __VA_ARGS__)
#define YBC_LOG_WARNING_STACK_TRACE(...) \
    YBCLogImpl( 1, "__FILE__", "__LINE__",  true, __VA_ARGS__)

#define Abs(x)			((x) >= 0 ? (x) : -(x))
#define Assert(condition)	((void)true)
#define AssertArg(condition)	((void)true)
#define AssertMacro(condition)	((void)true)
#define AssertPointerAlignment(ptr, bndr)	((void)true)
#define AssertState(condition)	((void)true)
#define AssertVariableIsOfType(varname, typename) \
	StaticAssertStmt(__builtin_types_compatible_p(__typeof__(varname), typename), \
	CppAsString(varname) " does not have type " CppAsString(typename))
#define AssertVariableIsOfTypeMacro(varname, typename) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof__(varname), typename), \
	 CppAsString(varname) " does not have type " CppAsString(typename)))
#define BUFFERALIGN(LEN)		TYPEALIGN(ALIGNOF_BUFFER, (LEN))
#define BUFFERALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_BUFFER, (LEN))
#define BoolIsValid(boolean)	((boolean) == false || (boolean) == true)
#define CACHELINEALIGN(LEN)		TYPEALIGN(PG_CACHE_LINE_SIZE, (LEN))

#define CppAsString(identifier) #identifier
#define CppAsString2(x)			CppAsString(x)
#define CppConcat(x, y)			x##y
#define DOUBLEALIGN(LEN)		TYPEALIGN(ALIGNOF_DOUBLE, (LEN))
#define DOUBLEALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_DOUBLE, (LEN))
#define HAVE_INT128 1

#define HAVE_PG_ATTRIBUTE_NORETURN 1
#define HAVE_STRTOLL 1
#define HAVE_STRTOULL 1
#define INT64CONST(x)  (x##L)
#define INT64_FORMAT "%" INT64_MODIFIER "d"
#define INTALIGN(LEN)			TYPEALIGN(ALIGNOF_INT, (LEN))
#define INTALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_INT, (LEN))
#define INVERT_COMPARE_RESULT(var) \
	((var) = ((var) < 0) ? 1 : -(var))
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
#define OffsetToPointer(base, offset) \
		((void *)((char *) base + offset))
#define OidIsValid(objectId)  ((bool) ((objectId) != InvalidOid))


#define PG_BINARY_A "ab"
#define PG_BINARY_R "rb"
#define PG_BINARY_W "wb"
#define PG_TEXTDOMAIN(domain) (domain CppAsString2(SO_MAJOR_VERSION) "-" PG_MAJORVERSION)
#define PG_USED_FOR_ASSERTS_ONLY pg_attribute_unused()
#define PointerIsAligned(pointer, type) \
		(((uintptr_t)(pointer) % (sizeof (type))) == 0)
#define PointerIsValid(pointer) ((const void*)(pointer) != NULL)
#define RegProcedureIsValid(p)	OidIsValid(p)
#define SHORTALIGN(LEN)			TYPEALIGN(ALIGNOF_SHORT, (LEN))
#define SHORTALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_SHORT, (LEN))
#define SIGNAL_ARGS  int postgres_signal_arg
#define SIZE_MAX PG_UINT64_MAX
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
#define StaticAssertExpr(condition, errmessage) \
	((void) ({ StaticAssertStmt(condition, errmessage); true; }))
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
#define Trap(condition, errorType)	((void)true)
#define TrapMacro(condition, errorType) (true)
#define UINT64CONST(x) (x##UL)
#define UINT64_FORMAT "%" INT64_MODIFIER "u"
#define USE_STDBOOL 1
#define _(x) gettext(x)
#define dgettext(d,x) (x)
#define dngettext(d,s,p,n) ((n) == 1 ? (s) : (p))
#define gettext(x) (x)
#define gettext_noop(x) (x)

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define likely(x)	__builtin_expect((x) != 0, 1)
#define memmove(d, s, c)		bcopy(s, d, c)
#define ngettext(s,p,n) ((n) == 1 ? (s) : (p))
#define offsetof(type, field)	((long) &((type *)0)->field)
#define pg_attribute_aligned(a) __attribute__((aligned(a)))
#define pg_attribute_always_inline __attribute__((always_inline)) inline
#define pg_attribute_format_arg(a) __attribute__((format_arg(a)))
#define pg_attribute_no_sanitize_alignment() __attribute__((no_sanitize("alignment")))
#define pg_attribute_noreturn() __attribute__((noreturn))
#define pg_attribute_packed() __attribute__((packed))
#define pg_attribute_printf(f,a) __attribute__((format(PG_PRINTF_ATTRIBUTE, f, a)))
#define pg_attribute_unused() __attribute__((unused))
#define pg_noinline __attribute__((noinline))
#define pg_unreachable() __builtin_unreachable()
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll __strtoll
#define strtoull __strtoull

#define unconstify(underlying_type, expr) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof(expr), const underlying_type), \
					  "wrong cast"), \
	 (underlying_type) (expr))
#define unlikely(x) __builtin_expect((x) != 0, 0)
#define unvolatize(underlying_type, expr) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof(expr), volatile underlying_type), \
					  "wrong cast"), \
	 (underlying_type) (expr))
#define DEVNULL "nul"
#define EXE ".exe"
#define IS_DIR_SEP(ch)	((ch) == '/')
#define PGINVALID_SOCKET (-1)
#define PG_BACKEND_VERSIONSTR "postgres (PostgreSQL) " PG_VERSION "\n"

#define SSL_get_current_compression(x) 0
#define TIMEZONE_GLOBAL _timezone
#define TZNAME_GLOBAL _tzname
#define closesocket close
#define		fopen(a,b) pgwin32_fopen(a,b)
#define fprintf(...)	pg_fprintf(__VA_ARGS__)
#define fseeko(a, b, c) fseek(a, b, c)
#define ftello(a)		ftell(a)
#define is_absolute_path(filename) \
( \
	IS_DIR_SEP((filename)[0]) \
)
#define isinf __builtin_isinf
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pgoff_t off_t
#define popen(a,b) pgwin32_popen(a,b)
#define pqsignal_no_restart(signo, func) pqsignal(signo, func)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define readlink(path, buf, size)	pgreadlink(path, buf, size)
#define rename(from, to)		pgrename(from, to)
#define snprintf(...)	pg_snprintf(__VA_ARGS__)
#define sprintf(...)	pg_sprintf(__VA_ARGS__)
#define symlink(oldpath, newpath)	pgsymlink(oldpath, newpath)
#define system(a) pgwin32_system(a)
#define unlink(path)			pgunlink(path)
#define vfprintf(...)	pg_vfprintf(__VA_ARGS__)
#define vsnprintf(...)	pg_vsnprintf(__VA_ARGS__)
#define DLSUFFIX ".dll"
#define EACCESS 2048
#define EADDRINUSE WSAEADDRINUSE
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define EAGAIN WSAEWOULDBLOCK
#define ECONNABORTED WSAECONNABORTED
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET WSAECONNRESET
#define EHOSTUNREACH WSAEHOSTUNREACH
#define EIDRM 4096
#define EINPROGRESS WSAEINPROGRESS
#define EINTR WSAEINTR
#define EISCONN WSAEISCONN
#define EMSGSIZE WSAEMSGSIZE
#define ENABLE_SSPI 1
#define ENOBUFS WSAENOBUFS
#define ENOTCONN WSAENOTCONN
#define ENOTSOCK WSAENOTSOCK
#define EOPNOTSUPP WSAEOPNOTSUPP
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#define EWOULDBLOCK WSAEWOULDBLOCK

#define F_OK 0
#define GETNCNT 16384
#define GETPID 262144
#define GETVAL 65536

#define HAVE_UNION_SEMUN 1
#define IPC_CREAT 512
#define IPC_EXCL 1024
#define IPC_PRIVATE 234564
#define IPC_RMID 256
#define IPC_STAT 4096
#define ITIMER_REAL 0
#define O_DSYNC 0x0080
#define PG_SIGNAL_COUNT 32

#define R_OK 4
#define SETALL 8192
#define SETVAL 131072
#define SIG_DFL ((pqsigfunc)0)
#define SIG_ERR ((pqsigfunc)-1)
#define SIG_IGN ((pqsigfunc)1)
#define S_IRGRP 0
#define S_IROTH 0
#define S_IRUSR _S_IREAD
#define S_IRWXG 0
#define S_IRWXO 0
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_IWGRP 0
#define S_IWOTH 0
#define S_IWUSR _S_IWRITE
#define S_IXGRP 0
#define S_IXOTH 0
#define S_IXUSR _S_IEXEC
#define UNBLOCKED_SIGNAL_QUEUE()	(pg_signal_queue & ~pg_signal_mask)

#define WEXITSTATUS(w)	(w)
#define WIFEXITED(w)	(((w) & 0XFFFFFF00) == 0)
#define WIFSIGNALED(w)	(!WIFEXITED(w))
#define WTERMSIG(w)		(w)
#define W_OK 2


#define accept(s, addr, addrlen) pgwin32_accept(s, addr, addrlen)
#define bind(s, addr, addrlen) pgwin32_bind(s, addr, addrlen)
#define connect(s, name, namelen) pgwin32_connect(s, name, namelen)
#define fsync(fd) _commit(fd)
#define ftruncate(a,b)	chsize(a,b)
#define isalnum_l _isalnum_l
#define isalpha_l _isalpha_l
#define isdigit_l _isdigit_l
#define isgraph_l _isgraph_l
#define islower_l _islower_l
#define isnan(x) _isnan(x)
#define isprint_l _isprint_l
#define ispunct_l _ispunct_l
#define isspace_l _isspace_l
#define isupper_l _isupper_l
#define iswalnum_l _iswalnum_l
#define iswalpha_l _iswalpha_l
#define iswdigit_l _iswdigit_l
#define iswgraph_l _iswgraph_l
#define iswlower_l _iswlower_l
#define iswprint_l _iswprint_l
#define iswpunct_l _iswpunct_l
#define iswspace_l _iswspace_l
#define iswupper_l _iswupper_l
#define kill(pid,sig)	pgkill(pid,sig)
#define listen(s, backlog) pgwin32_listen(s, backlog)
#define locale_t _locale_t
#define lstat(path, sb) stat(path, sb)
#define mbstowcs_l _mbstowcs_l
#define mkdir(a,b)	mkdir(a)
#define putenv(x) pgwin32_putenv(x)
#define recv(s, buf, len, flags) pgwin32_recv(s, buf, len, flags)
#define select(n, r, w, e, timeout) pgwin32_select(n, r, w, e, timeout)
#define send(s, buf, len, flags) pgwin32_send(s, buf, len, flags)
#define setlocale(a,b) pgwin32_setlocale(a,b)
#define sigmask(sig) ( 1 << ((sig)-1) )
#define socket(af, type, protocol) pgwin32_socket(af, type, protocol)
#define stat(a,b) pgwin32_safestat(a,b)
#define strcoll_l _strcoll_l
#define strxfrm_l _strxfrm_l
#define tolower_l _tolower_l
#define toupper_l _toupper_l
#define towlower_l _towlower_l
#define towupper_l _towupper_l
#define unsetenv(x) pgwin32_unsetenv(x)
#define wcscoll_l _wcscoll_l
#define wcstombs_l _wcstombs_l
#define OID_MAX  UINT_MAX
#define PG_DIAG_CONSTRAINT_NAME 'n'
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SEVERITY_NONLOCALIZED 'V'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

#define atooid(x) ((Oid) strtoul((x), NULL, 10))
