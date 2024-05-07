#include<arpa/inet.h>






#include<signal.h>

#include<sys/wait.h>
#include<stdlib.h>

#include<pwd.h>
#include<fcntl.h>





#include<sys/types.h>


#include<sys/select.h>


#include<time.h>


#include<ctype.h>








#include<getopt.h>

#include<string.h>
#include<setjmp.h>

#include<locale.h>



#include<pthread.h>




#include<math.h>
#include<limits.h>
#include<sys/stat.h>
#include<sys/un.h>




#include<unistd.h>

#include<errno.h>
#include<netinet/tcp.h>



#include<netdb.h>
#include<dirent.h>



#include<stdarg.h>
#include<sys/time.h>


#include<sys/param.h>
#include<stdio.h>







#include<strings.h>




#include<sys/socket.h>


#include<assert.h>
#include<sys/prctl.h>



#include<stdint.h>

#include<netinet/in.h>
#include<libintl.h>


#include<stdbool.h>



#include<stddef.h>

#define SpinLockAcquire(lock) S_LOCK(lock)
#define SpinLockFree(lock)	S_LOCK_FREE(lock)
#define SpinLockInit(lock)	S_INIT_LOCK(lock)
#define SpinLockRelease(lock) S_UNLOCK(lock)

#define DEFAULT_SPINS_PER_DELAY  100


#define SPIN_DELAY()	((void) 0)
#define S_INIT_LOCK(lock)	S_UNLOCK(lock)
#define S_LOCK(lock) \
	(TAS(lock) ? s_lock((lock), "__FILE__", "__LINE__", PG_FUNCNAME_MACRO) : 0)
#define S_LOCK_FREE(lock)	(*TAS_ACTIVE_WORD(lock) != 0)

#define S_UNLOCK(lock)		s_unlock(lock)
#define TAS(lock)		tas(lock)
#define TAS_ACTIVE_WORD(lock)	((volatile int *) (((uintptr_t) (lock) + 15) & ~15))
#define TAS_SPIN(lock)	TAS(lock)

#define init_local_spin_delay(status) init_spin_delay(status, "__FILE__", "__LINE__", PG_FUNCNAME_MACRO)


#define AssertPendingSyncs_RelationCache() do {} while (0)


#define BITS_PER_BITMAPWORD 64
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
	(offsetof(struct TupleDescData, attrs) + \
	 (src)->natts * sizeof(FormData_pg_attribute))

#define for_both_cell(cell1, list1, initcell1, cell2, list2, initcell2)	\
	for (ForBothCellState cell1##__state = \
			 for_both_cell_setup(list1, initcell1, list2, initcell2); \
		 multi_for_advance_cell(cell1, cell1##__state, l1, i1), \
		 multi_for_advance_cell(cell2, cell1##__state, l2, i2), \
		 (cell1 != NULL && cell2 != NULL); \
		 cell1##__state.i1++, cell1##__state.i2++)
#define for_each_cell(cell, lst, initcell)	\
	for (ForEachState cell##__state = for_each_cell_setup(lst, initcell); \
		 (cell##__state.l != NIL && \
		  cell##__state.i < cell##__state.l->length) ? \
		 (cell = &cell##__state.l->elements[cell##__state.i], true) : \
		 (cell = NULL, false); \
		 cell##__state.i++)
#define for_each_from(cell, lst, N)	\
	for (ForEachState cell##__state = for_each_from_setup(lst, N); \
		 (cell##__state.l != NIL && \
		  cell##__state.i < cell##__state.l->length) ? \
		 (cell = &cell##__state.l->elements[cell##__state.i], true) : \
		 (cell = NULL, false); \
		 cell##__state.i++)
#define forboth(cell1, list1, cell2, list2)							\
	for (ForBothState cell1##__state = {(list1), (list2), 0}; \
		 multi_for_advance_cell(cell1, cell1##__state, l1, i), \
		 multi_for_advance_cell(cell2, cell1##__state, l2, i), \
		 (cell1 != NULL && cell2 != NULL); \
		 cell1##__state.i++)
#define foreach(cell, lst)	\
	for (ForEachState cell##__state = {(lst), 0}; \
		 (cell##__state.l != NIL && \
		  cell##__state.i < cell##__state.l->length) ? \
		 (cell = &cell##__state.l->elements[cell##__state.i], true) : \
		 (cell = NULL, false); \
		 cell##__state.i++)
#define foreach_current_index(cell)  (cell##__state.i)
#define foreach_delete_current(lst, cell)	\
	(cell##__state.i--, \
	 (List *) (cell##__state.l = list_delete_cell(lst, cell)))
#define forfive(cell1, list1, cell2, list2, cell3, list3, cell4, list4, cell5, list5) \
	for (ForFiveState cell1##__state = {(list1), (list2), (list3), (list4), (list5), 0}; \
		 multi_for_advance_cell(cell1, cell1##__state, l1, i), \
		 multi_for_advance_cell(cell2, cell1##__state, l2, i), \
		 multi_for_advance_cell(cell3, cell1##__state, l3, i), \
		 multi_for_advance_cell(cell4, cell1##__state, l4, i), \
		 multi_for_advance_cell(cell5, cell1##__state, l5, i), \
		 (cell1 != NULL && cell2 != NULL && cell3 != NULL && \
		  cell4 != NULL && cell5 != NULL); \
		 cell1##__state.i++)
#define forfour(cell1, list1, cell2, list2, cell3, list3, cell4, list4) \
	for (ForFourState cell1##__state = {(list1), (list2), (list3), (list4), 0}; \
		 multi_for_advance_cell(cell1, cell1##__state, l1, i), \
		 multi_for_advance_cell(cell2, cell1##__state, l2, i), \
		 multi_for_advance_cell(cell3, cell1##__state, l3, i), \
		 multi_for_advance_cell(cell4, cell1##__state, l4, i), \
		 (cell1 != NULL && cell2 != NULL && cell3 != NULL && cell4 != NULL); \
		 cell1##__state.i++)
#define forthree(cell1, list1, cell2, list2, cell3, list3) \
	for (ForThreeState cell1##__state = {(list1), (list2), (list3), 0}; \
		 multi_for_advance_cell(cell1, cell1##__state, l1, i), \
		 multi_for_advance_cell(cell2, cell1##__state, l2, i), \
		 multi_for_advance_cell(cell3, cell1##__state, l3, i), \
		 (cell1 != NULL && cell2 != NULL && cell3 != NULL); \
		 cell1##__state.i++)
#define lfirst(lc)				((lc)->ptr_value)
#define lfirst_int(lc)			((lc)->int_value)
#define lfirst_node(type,lc)	castNode(type, lfirst(lc))
#define lfirst_oid(lc)			((lc)->oid_value)
#define lfourth(l)				lfirst(list_nth_cell(l, 3))
#define lfourth_int(l)			lfirst_int(list_nth_cell(l, 3))
#define lfourth_node(type,l)	castNode(type, lfourth(l))
#define lfourth_oid(l)			lfirst_oid(list_nth_cell(l, 3))
#define linitial(l)				lfirst(list_nth_cell(l, 0))
#define linitial_int(l)			lfirst_int(list_nth_cell(l, 0))
#define linitial_node(type,l)	castNode(type, linitial(l))
#define linitial_oid(l)			lfirst_oid(list_nth_cell(l, 0))
#define list_make1(x1) \
	list_make1_impl(T_List, list_make_ptr_cell(x1))
#define list_make1_int(x1) \
	list_make1_impl(T_IntList, list_make_int_cell(x1))
#define list_make1_oid(x1) \
	list_make1_impl(T_OidList, list_make_oid_cell(x1))
#define list_make2(x1,x2) \
	list_make2_impl(T_List, list_make_ptr_cell(x1), list_make_ptr_cell(x2))
#define list_make2_int(x1,x2) \
	list_make2_impl(T_IntList, list_make_int_cell(x1), list_make_int_cell(x2))
#define list_make2_oid(x1,x2) \
	list_make2_impl(T_OidList, list_make_oid_cell(x1), list_make_oid_cell(x2))
#define list_make3(x1,x2,x3) \
	list_make3_impl(T_List, list_make_ptr_cell(x1), list_make_ptr_cell(x2), \
					list_make_ptr_cell(x3))
#define list_make3_int(x1,x2,x3) \
	list_make3_impl(T_IntList, list_make_int_cell(x1), list_make_int_cell(x2), \
					list_make_int_cell(x3))
#define list_make3_oid(x1,x2,x3) \
	list_make3_impl(T_OidList, list_make_oid_cell(x1), list_make_oid_cell(x2), \
					list_make_oid_cell(x3))
#define list_make4(x1,x2,x3,x4) \
	list_make4_impl(T_List, list_make_ptr_cell(x1), list_make_ptr_cell(x2), \
					list_make_ptr_cell(x3), list_make_ptr_cell(x4))
#define list_make4_int(x1,x2,x3,x4) \
	list_make4_impl(T_IntList, list_make_int_cell(x1), list_make_int_cell(x2), \
					list_make_int_cell(x3), list_make_int_cell(x4))
#define list_make4_oid(x1,x2,x3,x4) \
	list_make4_impl(T_OidList, list_make_oid_cell(x1), list_make_oid_cell(x2), \
					list_make_oid_cell(x3), list_make_oid_cell(x4))
#define list_make5(x1,x2,x3,x4,x5) \
	list_make5_impl(T_List, list_make_ptr_cell(x1), list_make_ptr_cell(x2), \
					list_make_ptr_cell(x3), list_make_ptr_cell(x4), \
					list_make_ptr_cell(x5))
#define list_make5_int(x1,x2,x3,x4,x5) \
	list_make5_impl(T_IntList, list_make_int_cell(x1), list_make_int_cell(x2), \
					list_make_int_cell(x3), list_make_int_cell(x4), \
					list_make_int_cell(x5))
#define list_make5_oid(x1,x2,x3,x4,x5) \
	list_make5_impl(T_OidList, list_make_oid_cell(x1), list_make_oid_cell(x2), \
					list_make_oid_cell(x3), list_make_oid_cell(x4), \
					list_make_oid_cell(x5))
#define list_make_int_cell(v)	((ListCell) {.int_value = (v)})
#define list_make_oid_cell(v)	((ListCell) {.oid_value = (v)})
#define list_make_ptr_cell(v)	((ListCell) {.ptr_value = (v)})
#define list_nth_node(type,list,n)	castNode(type, list_nth(list, n))
#define llast(l)				lfirst(list_last_cell(l))
#define llast_int(l)			lfirst_int(list_last_cell(l))
#define llast_node(type,l)		castNode(type, llast(l))
#define llast_oid(l)			lfirst_oid(list_last_cell(l))
#define lsecond(l)				lfirst(list_nth_cell(l, 1))
#define lsecond_int(l)			lfirst_int(list_nth_cell(l, 1))
#define lsecond_node(type,l)	castNode(type, lsecond(l))
#define lsecond_oid(l)			lfirst_oid(list_nth_cell(l, 1))
#define lthird(l)				lfirst(list_nth_cell(l, 2))
#define lthird_int(l)			lfirst_int(list_nth_cell(l, 2))
#define lthird_node(type,l)		castNode(type, lthird(l))
#define lthird_oid(l)			lfirst_oid(list_nth_cell(l, 2))
#define multi_for_advance_cell(cell, state, l, i) \
	(cell = (state.l != NIL && state.i < state.l->length) ? \
	 &state.l->elements[state.i] : NULL)
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
#define castNode(_type_, nodeptr) ((_type_ *) (nodeptr))
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
#define DECLARE_ARRAY_FOREIGN_KEY(cols,reftbl,refcols) extern int no_such_variable
#define DECLARE_ARRAY_FOREIGN_KEY_OPT(cols,reftbl,refcols) extern int no_such_variable
#define DECLARE_FOREIGN_KEY(cols,reftbl,refcols) extern int no_such_variable
#define DECLARE_FOREIGN_KEY_OPT(cols,reftbl,refcols) extern int no_such_variable
#define DECLARE_INDEX(name,oid,oidmacro,decl) extern int no_such_variable
#define DECLARE_TOAST(name,toastoid,indexoid) extern int no_such_variable
#define DECLARE_UNIQUE_INDEX(name,oid,oidmacro,decl) extern int no_such_variable
#define DECLARE_UNIQUE_INDEX_PKEY(name,oid,oidmacro,decl) extern int no_such_variable


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
#define DatumGetIntervalP(X)  ((Interval *) DatumGetPointer(X))
#define DatumGetTimestamp(X)  ((Timestamp) DatumGetInt64(X))
#define DatumGetTimestampTz(X)	((TimestampTz) DatumGetInt64(X))
#define INTERVAL_FULL_PRECISION (0xFFFF)
#define INTERVAL_FULL_RANGE (0x7FFF)
#define INTERVAL_MASK(b) (1 << (b))
#define INTERVAL_PRECISION(t) ((t) & INTERVAL_PRECISION_MASK)
#define INTERVAL_PRECISION_MASK (0xFFFF)
#define INTERVAL_RANGE(t) (((t) >> 16) & INTERVAL_RANGE_MASK)
#define INTERVAL_RANGE_MASK (0x7FFF)
#define INTERVAL_TYPMOD(p,r) ((((r) & INTERVAL_RANGE_MASK) << 16) | ((p) & INTERVAL_PRECISION_MASK))
#define IntervalPGetDatum(X) PointerGetDatum(X)
#define PG_GETARG_INTERVAL_P(n) DatumGetIntervalP(PG_GETARG_DATUM(n))
#define PG_GETARG_TIMESTAMP(n) DatumGetTimestamp(PG_GETARG_DATUM(n))
#define PG_GETARG_TIMESTAMPTZ(n) DatumGetTimestampTz(PG_GETARG_DATUM(n))
#define PG_RETURN_INTERVAL_P(x) return IntervalPGetDatum(x)
#define PG_RETURN_TIMESTAMP(x) return TimestampGetDatum(x)
#define PG_RETURN_TIMESTAMPTZ(x) return TimestampTzGetDatum(x)

#define TIMESTAMP_MASK(b) (1 << (b))
#define TimestampGetDatum(X) Int64GetDatum(X)
#define TimestampTzGetDatum(X) Int64GetDatum(X)
#define TimestampTzPlusMilliseconds(tz,ms) ((tz) + ((ms) * (int64) 1000))
#define timestamptz_cmp_internal(dt1,dt2)	timestamp_cmp_internal(dt1, dt2)
#define TZ_STRLEN_MAX 255

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
#define PG_GETARG_TRANSACTIONID(n)	DatumGetTransactionId(PG_GETARG_DATUM(n))
#define PG_GETARG_UINT16(n)  DatumGetUInt16(PG_GETARG_DATUM(n))
#define PG_GETARG_UINT32(n)  DatumGetUInt32(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_P(n)		DatumGetVarCharP(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_PP(n)		DatumGetVarCharPP(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_P_COPY(n) DatumGetVarCharPCopy(PG_GETARG_DATUM(n))
#define PG_GETARG_VARCHAR_P_SLICE(n,a,b) DatumGetVarCharPSlice(PG_GETARG_DATUM(n),a,b)
#define PG_GETARG_VARLENA_P(n) PG_DETOAST_DATUM(PG_GETARG_DATUM(n))
#define PG_GETARG_VARLENA_PP(n) PG_DETOAST_DATUM_PACKED(PG_GETARG_DATUM(n))
#define PG_GET_COLLATION()	(fcinfo->fncollation)
#define PG_GET_OPCLASS_OPTIONS()	get_fn_opclass_options(fcinfo->flinfo)
#define PG_HAS_OPCLASS_OPTIONS()	has_fn_opclass_options(fcinfo->flinfo)
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
#define PG_RETURN_TRANSACTIONID(x)	return TransactionIdGetDatum(x)
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


#define ACL_CREATE_TEMP (1<<10) 
#define CURSOR_OPT_GENERIC_PLAN 0x0200	
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



#define floatVal(v)		atof(castNode(Float, v)->val)
#define intVal(v)		(castNode(Integer, v)->val)
#define strVal(v)		(castNode(String, v)->val)
#define IS_SPECIAL_VARNO(varno)		((int) (varno) < 0)




#define ALLOCSET_DEFAULT_INITSIZE  (8 * 1024)
#define ALLOCSET_DEFAULT_MAXSIZE   (8 * 1024 * 1024)
#define ALLOCSET_DEFAULT_MINSIZE   0
#define ALLOCSET_DEFAULT_SIZES \
	ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE
#define ALLOCSET_SEPARATE_THRESHOLD  8192
#define ALLOCSET_SMALL_INITSIZE  (1 * 1024)
#define ALLOCSET_SMALL_SIZES \
	ALLOCSET_SMALL_MINSIZE, ALLOCSET_SMALL_INITSIZE, ALLOCSET_SMALL_MAXSIZE
#define ALLOCSET_START_SMALL_SIZES \
	ALLOCSET_SMALL_MINSIZE, ALLOCSET_SMALL_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE
#define AllocHugeSizeIsValid(size)	((Size) (size) <= MaxAllocHugeSize)
#define AllocSetContextCreate \
	AllocSetContextCreateInternal
#define AllocSizeIsValid(size)	((Size) (size) <= MaxAllocSize)

#define MemoryContextCopyAndSetIdentifier(cxt, id) \
	MemoryContextSetIdentifier(cxt, MemoryContextStrdup(cxt, id))
#define MemoryContextResetAndDeleteChildren(ctx) MemoryContextReset(ctx)

#define MemoryContextIsValid(context) \
	((context) != NULL && \
	 (IsA((context), AllocSetContext) || \
	  IsA((context), SlabContext) || \
	  IsA((context), GenerationContext)))

#define DTERR_INTERVAL_OVERFLOW (-4)
#define DTERR_MD_FIELD_OVERFLOW (-3)	
#define DTK_M(t)		(0x01 << (t))
#define FMODULO(t,q,u) \
do { \
	(q) = (((t) < 0) ? ceil((t) / (u)) : floor((t) / (u))); \
	if ((q) != 0) (t) -= rint((q) * (u)); \
} while(0)
#define ISODATE 22
#define ISOTIME 23
#define MICROSECOND 14
#define MILLISECOND 13
#define TMODULO(t,q,u) \
do { \
	(q) = ((t) / (u)); \
	if ((q) != 0) (t) -= ((q) * (u)); \
} while(0)
#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

#define CStringGetTextDatum(s) PointerGetDatum(cstring_to_text(s))
#define MAXINT8LEN 20
#define TextDatumGetCString(d) text_to_cstring((text *) DatumGetPointer(d))
#define STACK_DEPTH_SLOP (512 * 1024L)


#define GUC_DISALLOW_IN_AUTO_FILE 0x0800	

#define GUC_QUALIFIER_SEPARATOR '.'
#define GUC_RUNTIME_COMPUTED  0x200000
#define GUC_UNIT				(GUC_UNIT_MEMORY | GUC_UNIT_TIME)
#define GUC_check_errdetail \
	pre_format_elog_string(errno, TEXTDOMAIN), \
	GUC_check_errdetail_string = format_elog_string
#define GUC_check_errhint \
	pre_format_elog_string(errno, TEXTDOMAIN), \
	GUC_check_errhint_string = format_elog_string
#define GUC_check_errmsg \
	pre_format_elog_string(errno, TEXTDOMAIN), \
	GUC_check_errmsg_string = format_elog_string
#define AARR_DIMS(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? \
	 (a)->xpn.dims : ARR_DIMS((ArrayType *) (a)))
#define AARR_ELEMTYPE(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? \
	 (a)->xpn.element_type : ARR_ELEMTYPE((ArrayType *) (a)))
#define AARR_HASNULL(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? \
	 ((a)->xpn.dvalues != NULL ? (a)->xpn.dnulls != NULL : ARR_HASNULL((a)->xpn.fvalue)) : \
	 ARR_HASNULL((ArrayType *) (a)))
#define AARR_LBOUND(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? \
	 (a)->xpn.lbound : ARR_LBOUND((ArrayType *) (a)))
#define AARR_NDIM(a) \
	(VARATT_IS_EXPANDED_HEADER(a) ? \
	 (a)->xpn.ndims : ARR_NDIM((ArrayType *) (a)))

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
#define MAXDIM 6
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
	(((varattrib_4b *) (PTR))->va_4byte.va_header == (uint32) EOH_HEADER_MAGIC)


#define PG_CMDTAG(tag, name, evtrgok, rwrok, rowcnt) \
	tag,
#define FIELDNO_HEAPTUPLETABLESLOT_OFF 2
#define FIELDNO_HEAPTUPLETABLESLOT_TUPLE 1
#define FIELDNO_MINIMALTUPLETABLESLOT_OFF 4
#define FIELDNO_MINIMALTUPLETABLESLOT_TUPLE 1
#define FIELDNO_TUPLETABLESLOT_FLAGS 1
#define FIELDNO_TUPLETABLESLOT_ISNULL 6
#define FIELDNO_TUPLETABLESLOT_NVALID 2
#define FIELDNO_TUPLETABLESLOT_TUPLEDESCRIPTOR 4
#define FIELDNO_TUPLETABLESLOT_VALUES 5
#define TTS_EMPTY(slot)	(((slot)->tts_flags & TTS_FLAG_EMPTY) != 0)
#define TTS_FIXED(slot) (((slot)->tts_flags & TTS_FLAG_FIXED) != 0)
#define TTS_IS_BUFFERTUPLE(slot) ((slot)->tts_ops == &TTSOpsBufferHeapTuple)
#define TTS_IS_HEAPTUPLE(slot) ((slot)->tts_ops == &TTSOpsHeapTuple)
#define TTS_IS_MINIMALTUPLE(slot) ((slot)->tts_ops == &TTSOpsMinimalTuple)
#define TTS_IS_VIRTUAL(slot) ((slot)->tts_ops == &TTSOpsVirtual)
#define TTS_SHOULDFREE(slot) (((slot)->tts_flags & TTS_FLAG_SHOULDFREE) != 0)
#define TTS_SLOW(slot) (((slot)->tts_flags & TTS_FLAG_SLOW) != 0)

#define TupIsNull(slot) \
	((slot) == NULL || TTS_EMPTY(slot))

#define BufferIsInvalid(buffer) ((buffer) == InvalidBuffer)
#define BufferIsLocal(buffer)	((buffer) < 0)

#define BITMAPLEN(NATTS)	(((int)(NATTS) + 7) / 8)
#define FIELDNO_HEAPTUPLEHEADERDATA_BITS 5
#define FIELDNO_HEAPTUPLEHEADERDATA_HOFF 4
#define FIELDNO_HEAPTUPLEHEADERDATA_INFOMASK 3
#define FIELDNO_HEAPTUPLEHEADERDATA_INFOMASK2 2
#define GETSTRUCT(TUP) ((char *) ((TUP)->t_data) + (TUP)->t_data->t_hoff)
#define HEAP_LOCKED_UPGRADED(infomask) \
( \
	 ((infomask) & HEAP_XMAX_IS_MULTI) != 0 && \
	 ((infomask) & HEAP_XMAX_LOCK_ONLY) != 0 && \
	 (((infomask) & (HEAP_XMAX_EXCL_LOCK | HEAP_XMAX_KEYSHR_LOCK)) == 0) \
)
#define HEAP_MOVED (HEAP_MOVED_OFF | HEAP_MOVED_IN)
#define HEAP_XMAX_BITS (HEAP_XMAX_COMMITTED | HEAP_XMAX_INVALID | \
						HEAP_XMAX_IS_MULTI | HEAP_LOCK_MASK | HEAP_XMAX_LOCK_ONLY)
#define HEAP_XMAX_IS_EXCL_LOCKED(infomask) \
	(((infomask) & HEAP_LOCK_MASK) == HEAP_XMAX_EXCL_LOCK)
#define HEAP_XMAX_IS_KEYSHR_LOCKED(infomask) \
	(((infomask) & HEAP_LOCK_MASK) == HEAP_XMAX_KEYSHR_LOCK)
#define HEAP_XMAX_IS_LOCKED_ONLY(infomask) \
	(((infomask) & HEAP_XMAX_LOCK_ONLY) || \
	 (((infomask) & (HEAP_XMAX_IS_MULTI | HEAP_LOCK_MASK)) == HEAP_XMAX_EXCL_LOCK))
#define HEAP_XMAX_IS_SHR_LOCKED(infomask) \
	(((infomask) & HEAP_LOCK_MASK) == HEAP_XMAX_SHR_LOCK)

#define HeapTupleAllFixed(tuple) \
		(!((tuple)->t_data->t_infomask & HEAP_HASVARWIDTH))
#define HeapTupleClearHeapOnly(tuple) \
		HeapTupleHeaderClearHeapOnly((tuple)->t_data)
#define HeapTupleClearHotUpdated(tuple) \
		HeapTupleHeaderClearHotUpdated((tuple)->t_data)
#define HeapTupleHasExternal(tuple) \
		(((tuple)->t_data->t_infomask & HEAP_HASEXTERNAL) != 0)
#define HeapTupleHasNulls(tuple) \
		(((tuple)->t_data->t_infomask & HEAP_HASNULL) != 0)
#define HeapTupleHasVarWidth(tuple) \
		(((tuple)->t_data->t_infomask & HEAP_HASVARWIDTH) != 0)
#define HeapTupleHeaderClearHeapOnly(tup) \
( \
  (tup)->t_infomask2 &= ~HEAP_ONLY_TUPLE \
)
#define HeapTupleHeaderClearHotUpdated(tup) \
( \
	(tup)->t_infomask2 &= ~HEAP_HOT_UPDATED \
)
#define HeapTupleHeaderClearMatch(tup) \
( \
  (tup)->t_infomask2 &= ~HEAP_TUPLE_HAS_MATCH \
)
#define HeapTupleHeaderGetDatumLength(tup) \
	VARSIZE(tup)
#define HeapTupleHeaderGetNatts(tup) \
	((tup)->t_infomask2 & HEAP_NATTS_MASK)
#define HeapTupleHeaderGetRawCommandId(tup) \
( \
	(tup)->t_choice.t_heap.t_field3.t_cid \
)
#define HeapTupleHeaderGetRawXmax(tup) \
( \
	(tup)->t_choice.t_heap.t_xmax \
)
#define HeapTupleHeaderGetRawXmin(tup) \
( \
	(tup)->t_choice.t_heap.t_xmin \
)
#define HeapTupleHeaderGetSpeculativeToken(tup) \
( \
	AssertMacro(HeapTupleHeaderIsSpeculative(tup)), \
	ItemPointerGetBlockNumber(&(tup)->t_ctid) \
)
#define HeapTupleHeaderGetTypMod(tup) \
( \
	(tup)->t_choice.t_datum.datum_typmod \
)
#define HeapTupleHeaderGetTypeId(tup) \
( \
	(tup)->t_choice.t_datum.datum_typeid \
)
#define HeapTupleHeaderGetUpdateXid(tup) \
( \
	(!((tup)->t_infomask & HEAP_XMAX_INVALID) && \
	 ((tup)->t_infomask & HEAP_XMAX_IS_MULTI) && \
	 !((tup)->t_infomask & HEAP_XMAX_LOCK_ONLY)) ? \
		HeapTupleGetUpdateXid(tup) \
	: \
		HeapTupleHeaderGetRawXmax(tup) \
)
#define HeapTupleHeaderGetXmin(tup) \
( \
	HeapTupleHeaderXminFrozen(tup) ? \
		FrozenTransactionId : HeapTupleHeaderGetRawXmin(tup) \
)
#define HeapTupleHeaderGetXvac(tup) \
( \
	((tup)->t_infomask & HEAP_MOVED) ? \
		(tup)->t_choice.t_heap.t_field3.t_xvac \
	: \
		InvalidTransactionId \
)
#define HeapTupleHeaderHasExternal(tup) \
		(((tup)->t_infomask & HEAP_HASEXTERNAL) != 0)
#define HeapTupleHeaderHasMatch(tup) \
( \
  ((tup)->t_infomask2 & HEAP_TUPLE_HAS_MATCH) != 0 \
)
#define HeapTupleHeaderIndicatesMovedPartitions(tup) \
	ItemPointerIndicatesMovedPartitions(&(tup)->t_ctid)
#define HeapTupleHeaderIsHeapOnly(tup) \
( \
  ((tup)->t_infomask2 & HEAP_ONLY_TUPLE) != 0 \
)
#define HeapTupleHeaderIsHotUpdated(tup) \
( \
	((tup)->t_infomask2 & HEAP_HOT_UPDATED) != 0 && \
	((tup)->t_infomask & HEAP_XMAX_INVALID) == 0 && \
	!HeapTupleHeaderXminInvalid(tup) \
)
#define HeapTupleHeaderIsSpeculative(tup) \
( \
	(ItemPointerGetOffsetNumberNoCheck(&(tup)->t_ctid) == SpecTokenOffsetNumber) \
)
#define HeapTupleHeaderSetCmax(tup, cid, iscombo) \
do { \
	Assert(!((tup)->t_infomask & HEAP_MOVED)); \
	(tup)->t_choice.t_heap.t_field3.t_cid = (cid); \
	if (iscombo) \
		(tup)->t_infomask |= HEAP_COMBOCID; \
	else \
		(tup)->t_infomask &= ~HEAP_COMBOCID; \
} while (0)
#define HeapTupleHeaderSetCmin(tup, cid) \
do { \
	Assert(!((tup)->t_infomask & HEAP_MOVED)); \
	(tup)->t_choice.t_heap.t_field3.t_cid = (cid); \
	(tup)->t_infomask &= ~HEAP_COMBOCID; \
} while (0)
#define HeapTupleHeaderSetDatumLength(tup, len) \
	SET_VARSIZE(tup, len)
#define HeapTupleHeaderSetHeapOnly(tup) \
( \
  (tup)->t_infomask2 |= HEAP_ONLY_TUPLE \
)
#define HeapTupleHeaderSetHotUpdated(tup) \
( \
	(tup)->t_infomask2 |= HEAP_HOT_UPDATED \
)
#define HeapTupleHeaderSetMatch(tup) \
( \
  (tup)->t_infomask2 |= HEAP_TUPLE_HAS_MATCH \
)
#define HeapTupleHeaderSetMovedPartitions(tup) \
	ItemPointerSetMovedPartitions(&(tup)->t_ctid)
#define HeapTupleHeaderSetNatts(tup, natts) \
( \
	(tup)->t_infomask2 = ((tup)->t_infomask2 & ~HEAP_NATTS_MASK) | (natts) \
)
#define HeapTupleHeaderSetSpeculativeToken(tup, token)	\
( \
	ItemPointerSet(&(tup)->t_ctid, token, SpecTokenOffsetNumber) \
)
#define HeapTupleHeaderSetTypMod(tup, typmod) \
( \
	(tup)->t_choice.t_datum.datum_typmod = (typmod) \
)
#define HeapTupleHeaderSetTypeId(tup, typeid) \
( \
	(tup)->t_choice.t_datum.datum_typeid = (typeid) \
)
#define HeapTupleHeaderSetXmax(tup, xid) \
( \
	(tup)->t_choice.t_heap.t_xmax = (xid) \
)
#define HeapTupleHeaderSetXmin(tup, xid) \
( \
	(tup)->t_choice.t_heap.t_xmin = (xid) \
)
#define HeapTupleHeaderSetXminCommitted(tup) \
( \
	AssertMacro(!HeapTupleHeaderXminInvalid(tup)), \
	((tup)->t_infomask |= HEAP_XMIN_COMMITTED) \
)
#define HeapTupleHeaderSetXminFrozen(tup) \
( \
	AssertMacro(!HeapTupleHeaderXminInvalid(tup)), \
	((tup)->t_infomask |= HEAP_XMIN_FROZEN) \
)
#define HeapTupleHeaderSetXminInvalid(tup) \
( \
	AssertMacro(!HeapTupleHeaderXminCommitted(tup)), \
	((tup)->t_infomask |= HEAP_XMIN_INVALID) \
)
#define HeapTupleHeaderSetXvac(tup, xid) \
do { \
	Assert((tup)->t_infomask & HEAP_MOVED); \
	(tup)->t_choice.t_heap.t_field3.t_xvac = (xid); \
} while (0)
#define HeapTupleHeaderXminCommitted(tup) \
( \
	((tup)->t_infomask & HEAP_XMIN_COMMITTED) != 0 \
)
#define HeapTupleHeaderXminFrozen(tup) \
( \
	((tup)->t_infomask & (HEAP_XMIN_FROZEN)) == HEAP_XMIN_FROZEN \
)
#define HeapTupleHeaderXminInvalid(tup) \
( \
	((tup)->t_infomask & (HEAP_XMIN_COMMITTED|HEAP_XMIN_INVALID)) == \
		HEAP_XMIN_INVALID \
)
#define HeapTupleIsHeapOnly(tuple) \
		HeapTupleHeaderIsHeapOnly((tuple)->t_data)
#define HeapTupleIsHotUpdated(tuple) \
		HeapTupleHeaderIsHotUpdated((tuple)->t_data)
#define HeapTupleNoNulls(tuple) \
		(!((tuple)->t_data->t_infomask & HEAP_HASNULL))
#define HeapTupleSetHeapOnly(tuple) \
		HeapTupleHeaderSetHeapOnly((tuple)->t_data)
#define HeapTupleSetHotUpdated(tuple) \
		HeapTupleHeaderSetHotUpdated((tuple)->t_data)
#define MINIMAL_TUPLE_DATA_OFFSET \
	offsetof(MinimalTupleData, t_infomask2)
#define MINIMAL_TUPLE_OFFSET \
	((offsetof(HeapTupleHeaderData, t_infomask2) - sizeof(uint32)) / MAXIMUM_ALIGNOF * MAXIMUM_ALIGNOF)
#define MINIMAL_TUPLE_PADDING \
	((offsetof(HeapTupleHeaderData, t_infomask2) - sizeof(uint32)) % MAXIMUM_ALIGNOF)
#define MaxHeapTupleSize  (BLCKSZ - MAXALIGN(SizeOfPageHeaderData + sizeof(ItemIdData)))
#define MaxTupleAttributeNumber 1664	
#define MinHeapTupleSize  MAXALIGN(SizeofHeapTupleHeader)
#define SizeofHeapTupleHeader offsetof(HeapTupleHeaderData, t_bits)
#define SizeofMinimalTupleHeader offsetof(MinimalTupleData, t_bits)
#define fastgetattr(tup, attnum, tupleDesc, isnull)					\
(																	\
	AssertMacro((attnum) > 0),										\
	(*(isnull) = false),											\
	HeapTupleNoNulls(tup) ?											\
	(																\
		TupleDescAttr((tupleDesc), (attnum)-1)->attcacheoff >= 0 ?	\
		(															\
			fetchatt(TupleDescAttr((tupleDesc), (attnum)-1),		\
				(char *) (tup)->t_data + (tup)->t_data->t_hoff +	\
				TupleDescAttr((tupleDesc), (attnum)-1)->attcacheoff)\
		)															\
		:															\
			nocachegetattr((tup), (attnum), (tupleDesc))			\
	)																\
	:																\
	(																\
		att_isnull((attnum)-1, (tup)->t_data->t_bits) ?				\
		(															\
			(*(isnull) = true),										\
			(Datum)NULL												\
		)															\
		:															\
		(															\
			nocachegetattr((tup), (attnum), (tupleDesc))			\
		)															\
	)																\
)
#define heap_getattr(tup, attnum, tupleDesc, isnull) \
	( \
		((attnum) > 0) ? \
		( \
			((attnum) > (int) HeapTupleHeaderGetNatts((tup)->t_data)) ? \
				getmissingattr((tupleDesc), (attnum), (isnull)) \
			: \
				fastgetattr((tup), (attnum), (tupleDesc), (isnull)) \
		) \
		: \
			heap_getsysattr((tup), (attnum), (tupleDesc), (isnull)) \
	)

#define PageAddItem(page, item, size, offsetNumber, overwrite, is_heap) \
	PageAddItemExtended(page, item, size, offsetNumber, \
						((overwrite) ? PAI_OVERWRITE : 0) | \
						((is_heap) ? PAI_IS_HEAP : 0))
#define PageClearAllVisible(page) \
	(((PageHeader) (page))->pd_flags &= ~PD_ALL_VISIBLE)
#define PageClearFull(page) \
	(((PageHeader) (page))->pd_flags &= ~PD_PAGE_FULL)
#define PageClearHasFreeLinePointers(page) \
	(((PageHeader) (page))->pd_flags &= ~PD_HAS_FREE_LINES)
#define PageClearPrunable(page) \
	(((PageHeader) (page))->pd_prune_xid = InvalidTransactionId)
#define PageGetContents(page) \
	((char *) (page) + MAXALIGN(SizeOfPageHeaderData))
#define PageGetItem(page, itemId) \
( \
	AssertMacro(PageIsValid(page)), \
	AssertMacro(ItemIdHasStorage(itemId)), \
	(Item)(((char *)(page)) + ItemIdGetOffset(itemId)) \
)
#define PageGetItemId(page, offsetNumber) \
	((ItemId) (&((PageHeader) (page))->pd_linp[(offsetNumber) - 1]))
#define PageGetLSN(page) \
	PageXLogRecPtrGet(((PageHeader) (page))->pd_lsn)
#define PageGetMaxOffsetNumber(page) \
	(((PageHeader) (page))->pd_lower <= SizeOfPageHeaderData ? 0 : \
	 ((((PageHeader) (page))->pd_lower - SizeOfPageHeaderData) \
	  / sizeof(ItemIdData)))
#define PageGetPageLayoutVersion(page) \
	(((PageHeader) (page))->pd_pagesize_version & 0x00FF)
#define PageGetPageSize(page) \
	((Size) (((PageHeader) (page))->pd_pagesize_version & (uint16) 0xFF00))
#define PageGetSpecialPointer(page) \
( \
	AssertMacro(PageValidateSpecialPointer(page)), \
	(char *) ((char *) (page) + ((PageHeader) (page))->pd_special) \
)
#define PageGetSpecialSize(page) \
	((uint16) (PageGetPageSize(page) - ((PageHeader)(page))->pd_special))
#define PageHasFreeLinePointers(page) \
	(((PageHeader) (page))->pd_flags & PD_HAS_FREE_LINES)
#define PageIsAllVisible(page) \
	(((PageHeader) (page))->pd_flags & PD_ALL_VISIBLE)
#define PageIsEmpty(page) \
	(((PageHeader) (page))->pd_lower <= SizeOfPageHeaderData)
#define PageIsFull(page) \
	(((PageHeader) (page))->pd_flags & PD_PAGE_FULL)
#define PageIsNew(page) (((PageHeader) (page))->pd_upper == 0)
#define PageIsValid(page) PointerIsValid(page)
#define PageIsVerified(page, blkno) \
	PageIsVerifiedExtended(page, blkno, \
						   PIV_LOG_WARNING | PIV_REPORT_STAT)
#define PageSetAllVisible(page) \
	(((PageHeader) (page))->pd_flags |= PD_ALL_VISIBLE)
#define PageSetFull(page) \
	(((PageHeader) (page))->pd_flags |= PD_PAGE_FULL)
#define PageSetHasFreeLinePointers(page) \
	(((PageHeader) (page))->pd_flags |= PD_HAS_FREE_LINES)
#define PageSetLSN(page, lsn) \
	PageXLogRecPtrSet(((PageHeader) (page))->pd_lsn, lsn)
#define PageSetPageSizeAndVersion(page, size, version) \
( \
	AssertMacro(((size) & 0xFF00) == (size)), \
	AssertMacro(((version) & 0x00FF) == (version)), \
	((PageHeader) (page))->pd_pagesize_version = (size) | (version) \
)
#define PageSetPrunable(page, xid) \
do { \
	Assert(TransactionIdIsNormal(xid)); \
	if (!TransactionIdIsValid(((PageHeader) (page))->pd_prune_xid) || \
		TransactionIdPrecedes(xid, ((PageHeader) (page))->pd_prune_xid)) \
		((PageHeader) (page))->pd_prune_xid = (xid); \
} while (0)
#define PageSizeIsValid(pageSize) ((pageSize) == BLCKSZ)
#define PageXLogRecPtrGet(val) \
	((uint64) (val).xlogid << 32 | (val).xrecoff)
#define PageXLogRecPtrSet(ptr, lsn) \
	((ptr).xlogid = (uint32) ((lsn) >> 32), (ptr).xrecoff = (uint32) (lsn))
#define SizeOfPageHeaderData (offsetof(PageHeaderData, pd_linp))

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
#define DEFAULT_SYNC_METHOD		PLATFORM_DEFAULT_SYNC_METHOD
#define LSN_FORMAT_ARGS(lsn) (AssertVariableIsOfTypeMacro((lsn), XLogRecPtr), (uint32) ((lsn) >> 32)), ((uint32) (lsn))

#define XLogRecPtrIsInvalid(r)	((r) == InvalidXLogRecPtr)

#define att_addlength_datum(cur_offset, attlen, attdatum) \
	att_addlength_pointer(cur_offset, attlen, DatumGetPointer(attdatum))
#define att_addlength_pointer(cur_offset, attlen, attptr) \
( \
	((attlen) > 0) ? \
	( \
		(cur_offset) + (attlen) \
	) \
	: (((attlen) == -1) ? \
	( \
		(cur_offset) + VARSIZE_ANY(attptr) \
	) \
	: \
	( \
		AssertMacro((attlen) == -2), \
		(cur_offset) + (strlen((char *) (attptr)) + 1) \
	)) \
)
#define att_align_datum(cur_offset, attalign, attlen, attdatum) \
( \
	((attlen) == -1 && VARATT_IS_SHORT(DatumGetPointer(attdatum))) ? \
	(uintptr_t) (cur_offset) : \
	att_align_nominal(cur_offset, attalign) \
)
#define att_align_nominal(cur_offset, attalign) \
( \
	((attalign) == TYPALIGN_INT) ? INTALIGN(cur_offset) : \
	 (((attalign) == TYPALIGN_CHAR) ? (uintptr_t) (cur_offset) : \
	  (((attalign) == TYPALIGN_DOUBLE) ? DOUBLEALIGN(cur_offset) : \
	   ( \
			AssertMacro((attalign) == TYPALIGN_SHORT), \
			SHORTALIGN(cur_offset) \
	   ))) \
)
#define att_align_pointer(cur_offset, attalign, attlen, attptr) \
( \
	((attlen) == -1 && VARATT_NOT_PAD_BYTE(attptr)) ? \
	(uintptr_t) (cur_offset) : \
	att_align_nominal(cur_offset, attalign) \
)
#define att_isnull(ATT, BITS) (!((BITS)[(ATT) >> 3] & (1 << ((ATT) & 0x07))))
#define fetch_att(T,attbyval,attlen) \
( \
	(attbyval) ? \
	( \
		(attlen) == (int) sizeof(Datum) ? \
			*((Datum *)(T)) \
		: \
	  ( \
		(attlen) == (int) sizeof(int32) ? \
			Int32GetDatum(*((int32 *)(T))) \
		: \
		( \
			(attlen) == (int) sizeof(int16) ? \
				Int16GetDatum(*((int16 *)(T))) \
			: \
			( \
				AssertMacro((attlen) == 1), \
				CharGetDatum(*((char *)(T))) \
			) \
		) \
	  ) \
	) \
	: \
	PointerGetDatum((char *) (T)) \
)
#define fetchatt(A,T) fetch_att(T, (A)->attbyval, (A)->attlen)
#define store_att_byval(T,newdatum,attlen) \
	do { \
		switch (attlen) \
		{ \
			case sizeof(char): \
				*(char *) (T) = DatumGetChar(newdatum); \
				break; \
			case sizeof(int16): \
				*(int16 *) (T) = DatumGetInt16(newdatum); \
				break; \
			case sizeof(int32): \
				*(int32 *) (T) = DatumGetInt32(newdatum); \
				break; \
			case sizeof(Datum): \
				*(Datum *) (T) = (newdatum); \
				break; \
			default: \
				elog(ERROR, "unsupported byval length: %d", \
					 (int) (attlen)); \
				break; \
		} \
	} while (0)
#define AssertTransactionIdInAllowableRange(xid) ((void)true)
#define EpochFromFullTransactionId(x)	((uint32) ((x).value >> 32))
#define FullTransactionIdEquals(a, b)	((a).value == (b).value)
#define FullTransactionIdFollows(a, b) ((a).value > (b).value)
#define FullTransactionIdFollowsOrEquals(a, b) ((a).value >= (b).value)
#define FullTransactionIdIsNormal(x)	FullTransactionIdFollowsOrEquals(x, FirstNormalFullTransactionId)
#define FullTransactionIdIsValid(x)		TransactionIdIsValid(XidFromFullTransactionId(x))
#define FullTransactionIdPrecedes(a, b)	((a).value < (b).value)
#define FullTransactionIdPrecedesOrEquals(a, b) ((a).value <= (b).value)
#define NormalTransactionIdFollows(id1, id2) \
	(AssertMacro(TransactionIdIsNormal(id1) && TransactionIdIsNormal(id2)), \
	(int32) ((id1) - (id2)) > 0)
#define NormalTransactionIdPrecedes(id1, id2) \
	(AssertMacro(TransactionIdIsNormal(id1) && TransactionIdIsNormal(id2)), \
	(int32) ((id1) - (id2)) < 0)
#define StoreInvalidTransactionId(dest) (*(dest) = InvalidTransactionId)

#define TransactionIdAdvance(dest)	\
	do { \
		(dest)++; \
		if ((dest) < FirstNormalTransactionId) \
			(dest) = FirstNormalTransactionId; \
	} while(0)
#define TransactionIdEquals(id1, id2)	((id1) == (id2))
#define TransactionIdIsNormal(xid)		((xid) >= FirstNormalTransactionId)
#define TransactionIdIsValid(xid)		((xid) != InvalidTransactionId)
#define TransactionIdRetreat(dest)	\
	do { \
		(dest)--; \
	} while ((dest) < FirstNormalTransactionId)
#define TransactionIdStore(xid, dest)	(*(dest) = (xid))
#define U64FromFullTransactionId(x)		((x).value)
#define XidFromFullTransactionId(x)		((uint32) (x).value)
#define FIELDNO_HEAPTUPLEDATA_DATA 3

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


#define BackendIdForTempRelations() \
	(ParallelLeaderBackendId == InvalidBackendId ? MyBackendId : ParallelLeaderBackendId)

#define RowMarkRequiresRowShareLock(marktype)  ((marktype) <= ROW_MARK_KEYSHARE)
#define exec_subplan_get_plan(plannedstmt, subplan) \
	((Plan *) list_nth((plannedstmt)->subplans, (subplan)->plan_id - 1))
#define innerPlan(node)			(((Plan *)(node))->righttree)
#define outerPlan(node)			(((Plan *)(node))->lefttree)

#define appendStringInfoCharMacro(str,ch) \
	(((str)->len + 1 >= (str)->maxlen) ? \
	 appendStringInfoChar(str, ch) : \
	 (void)((str)->data[(str)->len] = (ch), (str)->data[++(str)->len] = '\0'))
#define InvalidStrategy ((StrategyNumber) 0)


#define ScanDirectionIsBackward(direction) \
	((bool) ((direction) == BackwardScanDirection))
#define ScanDirectionIsForward(direction) \
	((bool) ((direction) == ForwardScanDirection))
#define ScanDirectionIsNoMovement(direction) \
	((bool) ((direction) == NoMovementScanDirection))
#define ScanDirectionIsValid(direction) \
	((bool) (BackwardScanDirection <= (direction) && \
			 (direction) <= ForwardScanDirection))

#define		FP_LOCK_SLOTS_PER_BACKEND 16
#define GetPGProcByNumber(n) (&ProcGlobal->allProcs[(n)])
#define PGPROC_MAX_CACHED_SUBXIDS 64	
#define		PROC_VACUUM_STATE_MASK \
	(PROC_IN_VACUUM | PROC_IN_SAFE_IC | PROC_VACUUM_FOR_WRAPAROUND)


#define GET_VXID_FROM_PGPROC(vxid, proc) \
	((vxid).backendId = (proc).backendId, \
	 (vxid).localTransactionId = (proc).lxid)
#define LOCALLOCK_LOCKMETHOD(llock) ((llock).tag.lock.locktag_lockmethodid)
#define LOCALLOCK_LOCKTAG(llock) ((LockTagType) (llock).tag.lock.locktag_type)
#define LOCKBIT_OFF(lockmode) (~(1 << (lockmode)))
#define LOCKBIT_ON(lockmode) (1 << (lockmode))

#define LOCK_LOCKMETHOD(lock) ((LOCKMETHODID) (lock).tag.locktag_lockmethodid)
#define LOCK_LOCKTAG(lock) ((LockTagType) (lock).tag.locktag_type)
#define LocalTransactionIdIsValid(lxid) ((lxid) != InvalidLocalTransactionId)
#define LockHashPartition(hashcode) \
	((hashcode) % NUM_LOCK_PARTITIONS)
#define LockHashPartitionLock(hashcode) \
	(&MainLWLockArray[LOCK_MANAGER_LWLOCK_OFFSET + \
		LockHashPartition(hashcode)].lock)
#define LockHashPartitionLockByIndex(i) \
	(&MainLWLockArray[LOCK_MANAGER_LWLOCK_OFFSET + (i)].lock)
#define LockHashPartitionLockByProc(leader_pgproc) \
	LockHashPartitionLock((leader_pgproc)->pgprocno)
#define PROCLOCK_LOCKMETHOD(proclock) \
	LOCK_LOCKMETHOD(*((proclock).tag.myLock))
#define SET_LOCKTAG_ADVISORY(locktag,id1,id2,id3,id4) \
	((locktag).locktag_field1 = (id1), \
	 (locktag).locktag_field2 = (id2), \
	 (locktag).locktag_field3 = (id3), \
	 (locktag).locktag_field4 = (id4), \
	 (locktag).locktag_type = LOCKTAG_ADVISORY, \
	 (locktag).locktag_lockmethodid = USER_LOCKMETHOD)
#define SET_LOCKTAG_DATABASE_FROZEN_IDS(locktag,dboid) \
	((locktag).locktag_field1 = (dboid), \
	 (locktag).locktag_field2 = 0, \
	 (locktag).locktag_field3 = 0, \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_DATABASE_FROZEN_IDS, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_OBJECT(locktag,dboid,classoid,objoid,objsubid) \
	((locktag).locktag_field1 = (dboid), \
	 (locktag).locktag_field2 = (classoid), \
	 (locktag).locktag_field3 = (objoid), \
	 (locktag).locktag_field4 = (objsubid), \
	 (locktag).locktag_type = LOCKTAG_OBJECT, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_PAGE(locktag,dboid,reloid,blocknum) \
	((locktag).locktag_field1 = (dboid), \
	 (locktag).locktag_field2 = (reloid), \
	 (locktag).locktag_field3 = (blocknum), \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_PAGE, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_RELATION(locktag,dboid,reloid) \
	((locktag).locktag_field1 = (dboid), \
	 (locktag).locktag_field2 = (reloid), \
	 (locktag).locktag_field3 = 0, \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_RELATION, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_RELATION_EXTEND(locktag,dboid,reloid) \
	((locktag).locktag_field1 = (dboid), \
	 (locktag).locktag_field2 = (reloid), \
	 (locktag).locktag_field3 = 0, \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_RELATION_EXTEND, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_SPECULATIVE_INSERTION(locktag,xid,token) \
	((locktag).locktag_field1 = (xid), \
	 (locktag).locktag_field2 = (token),		\
	 (locktag).locktag_field3 = 0, \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_SPECULATIVE_TOKEN, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_TRANSACTION(locktag,xid) \
	((locktag).locktag_field1 = (xid), \
	 (locktag).locktag_field2 = 0, \
	 (locktag).locktag_field3 = 0, \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_TRANSACTION, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_TUPLE(locktag,dboid,reloid,blocknum,offnum) \
	((locktag).locktag_field1 = (dboid), \
	 (locktag).locktag_field2 = (reloid), \
	 (locktag).locktag_field3 = (blocknum), \
	 (locktag).locktag_field4 = (offnum), \
	 (locktag).locktag_type = LOCKTAG_TUPLE, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SET_LOCKTAG_VIRTUALTRANSACTION(locktag,vxid) \
	((locktag).locktag_field1 = (vxid).backendId, \
	 (locktag).locktag_field2 = (vxid).localTransactionId, \
	 (locktag).locktag_field3 = 0, \
	 (locktag).locktag_field4 = 0, \
	 (locktag).locktag_type = LOCKTAG_VIRTUALTRANSACTION, \
	 (locktag).locktag_lockmethodid = DEFAULT_LOCKMETHOD)
#define SetInvalidVirtualTransactionId(vxid) \
	((vxid).backendId = InvalidBackendId, \
	 (vxid).localTransactionId = InvalidLocalTransactionId)
#define VirtualTransactionIdEquals(vxid1, vxid2) \
	((vxid1).backendId == (vxid2).backendId && \
	 (vxid1).localTransactionId == (vxid2).localTransactionId)
#define VirtualTransactionIdIsRecoveredPreparedXact(vxid) \
	((vxid).backendId == InvalidBackendId)
#define VirtualTransactionIdIsValid(vxid) \
	(LocalTransactionIdIsValid((vxid).localTransactionId))

#define HASH_FIXED_SIZE 0x2000	
#define HASH_SHARED_MEM 0x0800	

#define LOG2_NUM_LOCK_PARTITIONS  4
#define LOG2_NUM_PREDICATELOCK_PARTITIONS  4

#define NUM_BUFFER_PARTITIONS  128
#define NUM_FIXED_LWLOCKS \
	(PREDICATELOCK_MANAGER_LWLOCK_OFFSET + NUM_PREDICATELOCK_PARTITIONS)
#define NUM_LOCK_PARTITIONS  (1 << LOG2_NUM_LOCK_PARTITIONS)
#define NUM_PREDICATELOCK_PARTITIONS  (1 << LOG2_NUM_PREDICATELOCK_PARTITIONS)
#define PREDICATELOCK_MANAGER_LWLOCK_OFFSET \
	(LOCK_MANAGER_LWLOCK_OFFSET + NUM_LOCK_PARTITIONS)


#define pg_memory_barrier() pg_memory_barrier_impl()
#define pg_spin_delay() pg_spin_delay_impl()



























#define pg_spin_delay_impl()	((void)0)









#define pg_compiler_barrier_impl pg_extern_compiler_barrier
#define pg_memory_barrier_impl pg_spinlock_barrier
#define MINOR_FENCE (_Asm_fence) (_UP_CALL_FENCE | _UP_SYS_FENCE | \
								 _DOWN_CALL_FENCE | _DOWN_SYS_FENCE )
#		define pg_read_barrier_impl()		__atomic_thread_fence(__ATOMIC_ACQUIRE)
#		define pg_write_barrier_impl()		__atomic_thread_fence(__ATOMIC_RELEASE)



#define ShareUpdateExclusiveLock 4	

#define WL_POSTMASTER_DEATH  (1 << 4)
#define WL_SOCKET_CONNECTED  (1 << 6)
#define WL_SOCKET_WRITEABLE  (1 << 2)
#define DLIST_STATIC_INIT(name) {{&(name).head, &(name).head}}

#define SLIST_STATIC_INIT(name) {{NULL}}
#define dlist_check(head)	((void) (head))
#define dlist_container(type, membername, ptr)								\
	(AssertVariableIsOfTypeMacro(ptr, dlist_node *),						\
	 AssertVariableIsOfTypeMacro(((type *) NULL)->membername, dlist_node),	\
	 ((type *) ((char *) (ptr) - offsetof(type, membername))))
#define dlist_foreach(iter, lhead)											\
	for (AssertVariableIsOfTypeMacro(iter, dlist_iter),						\
		 AssertVariableIsOfTypeMacro(lhead, dlist_head *),					\
		 (iter).end = &(lhead)->head,										\
		 (iter).cur = (iter).end->next ? (iter).end->next : (iter).end;		\
		 (iter).cur != (iter).end;											\
		 (iter).cur = (iter).cur->next)
#define dlist_foreach_modify(iter, lhead)									\
	for (AssertVariableIsOfTypeMacro(iter, dlist_mutable_iter),				\
		 AssertVariableIsOfTypeMacro(lhead, dlist_head *),					\
		 (iter).end = &(lhead)->head,										\
		 (iter).cur = (iter).end->next ? (iter).end->next : (iter).end,		\
		 (iter).next = (iter).cur->next;									\
		 (iter).cur != (iter).end;											\
		 (iter).cur = (iter).next, (iter).next = (iter).cur->next)
#define dlist_head_element(type, membername, lhead)							\
	(AssertVariableIsOfTypeMacro(((type *) NULL)->membername, dlist_node),	\
	 (type *) dlist_head_element_off(lhead, offsetof(type, membername)))
#define dlist_reverse_foreach(iter, lhead)									\
	for (AssertVariableIsOfTypeMacro(iter, dlist_iter),						\
		 AssertVariableIsOfTypeMacro(lhead, dlist_head *),					\
		 (iter).end = &(lhead)->head,										\
		 (iter).cur = (iter).end->prev ? (iter).end->prev : (iter).end;		\
		 (iter).cur != (iter).end;											\
		 (iter).cur = (iter).cur->prev)
#define dlist_tail_element(type, membername, lhead)							\
	(AssertVariableIsOfTypeMacro(((type *) NULL)->membername, dlist_node),	\
	 ((type *) dlist_tail_element_off(lhead, offsetof(type, membername))))
#define slist_check(head)	((void) (head))
#define slist_container(type, membername, ptr)								\
	(AssertVariableIsOfTypeMacro(ptr, slist_node *),						\
	 AssertVariableIsOfTypeMacro(((type *) NULL)->membername, slist_node),	\
	 ((type *) ((char *) (ptr) - offsetof(type, membername))))
#define slist_foreach(iter, lhead)											\
	for (AssertVariableIsOfTypeMacro(iter, slist_iter),						\
		 AssertVariableIsOfTypeMacro(lhead, slist_head *),					\
		 (iter).cur = (lhead)->head.next;									\
		 (iter).cur != NULL;												\
		 (iter).cur = (iter).cur->next)
#define slist_foreach_modify(iter, lhead)									\
	for (AssertVariableIsOfTypeMacro(iter, slist_mutable_iter),				\
		 AssertVariableIsOfTypeMacro(lhead, slist_head *),					\
		 (iter).prev = &(lhead)->head,										\
		 (iter).cur = (iter).prev->next,									\
		 (iter).next = (iter).cur ? (iter).cur->next : NULL;				\
		 (iter).cur != NULL;												\
		 (iter).prev = (iter).cur,											\
		 (iter).cur = (iter).next,											\
		 (iter).next = (iter).next ? (iter).next->next : NULL)
#define slist_head_element(type, membername, lhead)							\
	(AssertVariableIsOfTypeMacro(((type *) NULL)->membername, slist_node),	\
	 (type *) slist_head_element_off(lhead, offsetof(type, membername)))



#define RelFileNodeBackendEquals(node1, node2) \
	((node1).node.relNode == (node2).node.relNode && \
	 (node1).node.dbNode == (node2).node.dbNode && \
	 (node1).backend == (node2).backend && \
	 (node1).node.spcNode == (node2).node.spcNode)
#define RelFileNodeBackendIsTemp(rnode) \
	((rnode).backend != InvalidBackendId)
#define RelFileNodeEquals(node1, node2) \
	((node1).relNode == (node2).relNode && \
	 (node1).dbNode == (node2).dbNode && \
	 (node1).spcNode == (node2).spcNode)

#define relpath(rnode, forknum) \
	relpathbackend((rnode).node, (rnode).backend, forknum)
#define relpathbackend(rnode, backend, forknum) \
	GetRelationPath((rnode).dbNode, (rnode).spcNode, (rnode).relNode, \
					backend, forknum)
#define relpathperm(rnode, forknum) \
	relpathbackend(rnode, InvalidBackendId, forknum)


#define XL_ROUTINE(...) &(XLogReaderRoutine){__VA_ARGS__}
#define XLogRecBlockImageApply(decoder, block_id) \
	((decoder)->blocks[block_id].apply_image)
#define XLogRecGetData(decoder) ((decoder)->main_data)
#define XLogRecGetDataLen(decoder) ((decoder)->main_data_len)
#define XLogRecGetInfo(decoder) ((decoder)->decoded_record->xl_info)
#define XLogRecGetOrigin(decoder) ((decoder)->record_origin)
#define XLogRecGetPrev(decoder) ((decoder)->decoded_record->xl_prev)
#define XLogRecGetRmid(decoder) ((decoder)->decoded_record->xl_rmid)
#define XLogRecGetTopXid(decoder) ((decoder)->toplevel_xid)
#define XLogRecGetTotalLen(decoder) ((decoder)->decoded_record->xl_tot_len)
#define XLogRecGetXid(decoder) ((decoder)->decoded_record->xl_xid)
#define XLogRecHasAnyBlockRefs(decoder) ((decoder)->max_block_id >= 0)
#define XLogRecHasBlockImage(decoder, block_id) \
	((decoder)->blocks[block_id].has_image)
#define XLogRecHasBlockRef(decoder, block_id) \
	((decoder)->blocks[block_id].in_use)
#define MaxSizeOfXLogRecordBlockHeader \
	(SizeOfXLogRecordBlockHeader + \
	 SizeOfXLogRecordBlockImageHeader + \
	 SizeOfXLogRecordBlockCompressHeader + \
	 sizeof(RelFileNode) + \
	 sizeof(BlockNumber))
#define SizeOfXLogRecordBlockCompressHeader \
	sizeof(XLogRecordBlockCompressHeader)
#define SizeOfXLogRecordBlockHeader (offsetof(XLogRecordBlockHeader, data_length) + sizeof(uint16))
#define SizeOfXLogRecordDataHeaderLong (sizeof(uint8) + sizeof(uint32))
#define SizeOfXLogRecordDataHeaderShort (sizeof(uint8) * 2)

#define COMP_CRC32C(crc, data, len) \
	((crc) = pg_comp_crc32c_sse42((crc), (data), (len)))
#define EQ_CRC32C(c1, c2) ((c1) == (c2))
#define FIN_CRC32C(crc) ((crc) ^= 0xFFFFFFFF)
#define INIT_CRC32C(crc) ((crc) = 0xFFFFFFFF)

#define		DatumBigEndianToNative(x)	(x)

#define pg_bswap16(x) __builtin_bswap16(x)
#define pg_bswap32(x) __builtin_bswap32(x)
#define pg_bswap64(x) __builtin_bswap64(x)
#define pg_hton16(x)		(x)
#define pg_hton32(x)		(x)
#define pg_hton64(x)		(x)
#define pg_ntoh16(x)		(x)
#define pg_ntoh32(x)		(x)
#define pg_ntoh64(x)		(x)
#define PG_RMGR(symname,name,redo,desc,identify,startup,cleanup,mask) \
	symname,


#define PostmasterIsAlive() PostmasterIsAliveInternal()

#define DEFAULT_SHARED_MEMORY_TYPE SHMEM_TYPE_MMAP
#define PGShmemMagic  679834894







#define PG_END_ENSURE_ERROR_CLEANUP(cleanup_function, arg)	\
		cancel_before_shmem_exit(cleanup_function, arg); \
		PG_CATCH(); \
		{ \
			cancel_before_shmem_exit(cleanup_function, arg); \
			cleanup_function (0, arg); \
			PG_RE_THROW(); \
		} \
		PG_END_TRY(); \
	} while (0)
#define PG_ENSURE_ERROR_CLEANUP(cleanup_function, arg)	\
	do { \
		before_shmem_exit(cleanup_function, arg); \
		PG_TRY()

#define FILE_POSSIBLY_DELETED(err)	((err) == ENOENT)
#define		PG_O_DIRECT O_DIRECT
#define		PG_O_DIRECT_USE_F_NOCACHE
#define PG_TEMP_FILES_DIR "pgsql_tmp"
#define PG_TEMP_FILE_PREFIX "pgsql_tmp"
#define WalSndWakeupProcessRequests()		\
	do										\
	{										\
		if (wake_wal_senders)				\
		{									\
			wake_wal_senders = false;		\
			if (max_wal_senders > 0)		\
				WalSndWakeup();				\
		}									\
	} while (0)
#define WalSndWakeupRequest() \
	do { wake_wal_senders = true; } while (0)


#define LOG_METAINFO_DATAFILE  "current_logfiles"
#define LOG_METAINFO_DATAFILE_TMP  LOG_METAINFO_DATAFILE ".tmp"
#define PIPE_CHUNK_SIZE  65536
#define PIPE_HEADER_SIZE  offsetof(PipeProtoHeader, data)
#define PIPE_MAX_PAYLOAD  ((int) (PIPE_CHUNK_SIZE - PIPE_HEADER_SIZE))


#define VALID_XFN_CHARS "0123456789ABCDEF.history.backup.partial"




#define MAX_PARALLEL_WORKER_LIMIT 1024
#define BGWORKER_BYPASS_ALLOWCONN 1


#define AmArchiverProcess()			(MyAuxProcType == ArchiverProcess)
#define AmBackgroundWriterProcess() (MyAuxProcType == BgWriterProcess)
#define AmCheckpointerProcess()		(MyAuxProcType == CheckpointerProcess)
#define AmStartupProcess()			(MyAuxProcType == StartupProcess)
#define AmWalReceiverProcess()		(MyAuxProcType == WalReceiverProcess)
#define AmWalWriterProcess()		(MyAuxProcType == WalWriterProcess)
#define CHECK_FOR_INTERRUPTS() \
do { \
	if (INTERRUPTS_PENDING_CONDITION()) \
		ProcessInterrupts(); \
} while(0)
#define END_CRIT_SECTION() \
do { \
	Assert(CritSectionCount > 0); \
	CritSectionCount--; \
} while(0)
#define GetProcessingMode() Mode
#define HOLD_CANCEL_INTERRUPTS()  (QueryCancelHoldoffCount++)
#define HOLD_INTERRUPTS()  (InterruptHoldoffCount++)
#define INTERRUPTS_CAN_BE_PROCESSED() \
	(InterruptHoldoffCount == 0 && CritSectionCount == 0 && \
	 QueryCancelHoldoffCount == 0)
#define INTERRUPTS_PENDING_CONDITION() \
	(unlikely(InterruptPending))
#define IsBootstrapProcessingMode() (Mode == BootstrapProcessing)
#define IsInitProcessingMode()		(Mode == InitProcessing)
#define IsNormalProcessingMode()	(Mode == NormalProcessing)

#define RESUME_CANCEL_INTERRUPTS() \
do { \
	Assert(QueryCancelHoldoffCount > 0); \
	QueryCancelHoldoffCount--; \
} while(0)
#define RESUME_INTERRUPTS() \
do { \
	Assert(InterruptHoldoffCount > 0); \
	InterruptHoldoffCount--; \
} while(0)
#define START_CRIT_SECTION()  (CritSectionCount++)
#define SetProcessingMode(mode) \
	do { \
		AssertArg((mode) == BootstrapProcessing || \
				  (mode) == InitProcessing || \
				  (mode) == NormalProcessing); \
		Mode = (mode); \
	} while(0)

#define IsAnyAutoVacuumProcess() \
	(IsAutoVacuumLauncherProcess() || IsAutoVacuumWorkerProcess())

#define PGSTAT_MAX_MSG_SIZE 1000
#define PGSTAT_NUM_FUNCPURGE  \
	((PGSTAT_MSG_PAYLOAD - sizeof(Oid) - sizeof(int))  \
	 / sizeof(Oid))
#define PGSTAT_NUM_TABENTRIES  \
	((PGSTAT_MSG_PAYLOAD - sizeof(Oid) - 3 * sizeof(int) - 5 * sizeof(PgStat_Counter)) \
	 / sizeof(PgStat_TableEntry))
#define PGSTAT_NUM_TABPURGE  \
	((PGSTAT_MSG_PAYLOAD - sizeof(Oid) - sizeof(int))  \
	 / sizeof(Oid))
#define pgstat_count_buffer_hit(rel)								\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_blocks_hit++;			\
	} while (0)
#define pgstat_count_buffer_read(rel)								\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_blocks_fetched++;		\
	} while (0)
#define pgstat_count_buffer_read_time(n)							\
	(pgStatBlockReadTime += (n))
#define pgstat_count_buffer_write_time(n)							\
	(pgStatBlockWriteTime += (n))
#define pgstat_count_conn_active_time(n)							\
	(pgStatActiveTime += (n))
#define pgstat_count_conn_txn_idle_time(n)							\
	(pgStatTransactionIdleTime += (n))
#define pgstat_count_heap_fetch(rel)								\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_tuples_fetched++;		\
	} while (0)
#define pgstat_count_heap_getnext(rel)								\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_tuples_returned++;		\
	} while (0)
#define pgstat_count_heap_scan(rel)									\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_numscans++;				\
	} while (0)
#define pgstat_count_index_scan(rel)								\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_numscans++;				\
	} while (0)
#define pgstat_count_index_tuples(rel, n)							\
	do {															\
		if ((rel)->pgstat_info != NULL)								\
			(rel)->pgstat_info->t_counts.t_tuples_returned += (n);	\
	} while (0)

#define INSTR_TIME_ACCUM_DIFF(x,y,z) \
	do { \
		(x).tv_sec += (y).tv_sec - (z).tv_sec; \
		(x).tv_nsec += (y).tv_nsec - (z).tv_nsec; \
		 \
		while ((x).tv_nsec < 0) \
		{ \
			(x).tv_nsec += 1000000000; \
			(x).tv_sec--; \
		} \
		while ((x).tv_nsec >= 1000000000) \
		{ \
			(x).tv_nsec -= 1000000000; \
			(x).tv_sec++; \
		} \
	} while (0)
#define INSTR_TIME_ADD(x,y) \
	do { \
		(x).tv_sec += (y).tv_sec; \
		(x).tv_usec += (y).tv_usec; \
		 \
		while ((x).tv_usec >= 1000000) \
		{ \
			(x).tv_usec -= 1000000; \
			(x).tv_sec++; \
		} \
	} while (0)
#define INSTR_TIME_GET_DOUBLE(t) \
	(((double) (t).tv_sec) + ((double) (t).tv_nsec) / 1000000000.0)
#define INSTR_TIME_GET_MICROSEC(t) \
	(((uint64) (t).tv_sec * (uint64) 1000000) + (uint64) ((t).tv_nsec / 1000))
#define INSTR_TIME_GET_MILLISEC(t) \
	(((double) (t).tv_sec * 1000.0) + ((double) (t).tv_nsec) / 1000000.0)

#define INSTR_TIME_IS_ZERO(t)	((t).tv_usec == 0 && (t).tv_sec == 0)
#define INSTR_TIME_SET_CURRENT(t)	gettimeofday(&(t), NULL)
#define INSTR_TIME_SET_CURRENT_LAZY(t) \
	(INSTR_TIME_IS_ZERO(t) ? INSTR_TIME_SET_CURRENT(t), true : false)
#define INSTR_TIME_SET_ZERO(t)	((t).tv_sec = 0, (t).tv_usec = 0)
#define INSTR_TIME_SUBTRACT(x,y) \
	do { \
		(x).tv_sec -= (y).tv_sec; \
		(x).tv_nsec -= (y).tv_nsec; \
		 \
		while ((x).tv_nsec < 0) \
		{ \
			(x).tv_nsec += 1000000000; \
			(x).tv_sec--; \
		} \
	} while (0)

#define PG_SETMASK(mask)	sigprocmask(SIG_SETMASK, mask, NULL)

#define sigaddset(set, signum)	(*(set) |= (sigmask(signum)))
#define sigdelset(set, signum)	(*(set) &= ~(sigmask(signum)))
#define sigemptyset(set)		(*(set) = 0)
#define sigfillset(set)			(*(set) = ~0)

#define CHECK_ENCODING_CONVERSION_ARGS(srcencoding,destencoding) \
	check_encoding_conversion_args(PG_GETARG_INT32(0), \
								   PG_GETARG_INT32(1), \
								   PG_GETARG_INT32(4), \
								   (srcencoding), \
								   (destencoding))
#define ISSJISHEAD(c) (((c) >= 0x81 && (c) <= 0x9f) || ((c) >= 0xe0 && (c) <= 0xfc))
#define ISSJISTAIL(c) (((c) >= 0x40 && (c) <= 0x7e) || ((c) >= 0x80 && (c) <= 0xfc))
#define IS_LC1(c)	((unsigned char)(c) >= 0x81 && (unsigned char)(c) <= 0x8d)
#define IS_LC2(c)	((unsigned char)(c) >= 0x90 && (unsigned char)(c) <= 0x99)
#define IS_LCPRV1(c)	((unsigned char)(c) == LCPRV1_A || (unsigned char)(c) == LCPRV1_B)
#define IS_LCPRV1_A_RANGE(c)	\
	((unsigned char)(c) >= 0xa0 && (unsigned char)(c) <= 0xdf)
#define IS_LCPRV1_B_RANGE(c)	\
	((unsigned char)(c) >= 0xe0 && (unsigned char)(c) <= 0xef)
#define IS_LCPRV2(c)	((unsigned char)(c) == LCPRV2_A || (unsigned char)(c) == LCPRV2_B)
#define IS_LCPRV2_A_RANGE(c)	\
	((unsigned char)(c) >= 0xf0 && (unsigned char)(c) <= 0xf4)
#define IS_LCPRV2_B_RANGE(c)	\
	((unsigned char)(c) >= 0xf5 && (unsigned char)(c) <= 0xfe)
#define LC_TIBETAN_1_COLUMN 0xf1	
#define LC_UNICODE_SUBSET_2 0xf2	
#define LC_UNICODE_SUBSET_3 0xf3	
#define MAX_CONVERSION_GROWTH  4
#define PG_ENCODING_BE_LAST PG_KOI8U
#define PG_ENCODING_IS_CLIENT_ONLY(_enc) \
		((_enc) > PG_ENCODING_BE_LAST && (_enc) < _PG_LAST_ENCODING_)
#define PG_VALID_BE_ENCODING(_enc) \
		((_enc) >= 0 && (_enc) <= PG_ENCODING_BE_LAST)
#define PG_VALID_ENCODING(_enc) \
		((_enc) >= 0 && (_enc) < _PG_LAST_ENCODING_)
#define PG_VALID_FE_ENCODING(_enc)	PG_VALID_ENCODING(_enc)

#define SS2 0x8e				
#define SS3 0x8f				
#define FeBeWaitSetLatchPos 1
#define FeBeWaitSetSocketPos 0

#define pq_comm_reset() (PqCommMethods->comm_reset())
#define pq_flush() (PqCommMethods->flush())
#define pq_flush_if_writable() (PqCommMethods->flush_if_writable())
#define pq_is_send_pending() (PqCommMethods->is_send_pending())
#define pq_putmessage(msgtype, s, len) \
	(PqCommMethods->putmessage(msgtype, s, len))
#define pq_putmessage_noblock(msgtype, s, len) \
	(PqCommMethods->putmessage_noblock(msgtype, s, len))
#define FILE_DH2048 \
"-----BEGIN DH PARAMETERS-----\n\
MIIBCAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\n\
IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft\n\
awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\n\
mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\n\
fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\n\
5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAg==\n\
-----END DH PARAMETERS-----\n"



#define AUTH_REQ_SASL_CONT 11	
#define AUTH_REQ_SASL_FIN  12	
#define CANCEL_REQUEST_CODE PG_PROTOCOL(1234,5678)
#define HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN 1
#define MAX_STARTUP_PACKET_LENGTH 10000
#define NEGOTIATE_GSS_CODE PG_PROTOCOL(1234,5680)
#define NEGOTIATE_SSL_CODE PG_PROTOCOL(1234,5679)
#define PG_PROTOCOL(m,n)	(((m) << 16) | (n))
#define PG_PROTOCOL_MAJOR(v)	((v) >> 16)
#define PG_PROTOCOL_MINOR(v)	((v) & 0x0000ffff)

#define UNIXSOCK_PATH(path, port, sockdir) \
	   (AssertMacro(sockdir), \
		AssertMacro(*(sockdir) != '\0'), \
		snprintf(path, sizeof(path), "%s/.s.PGSQL.%d", \
				 (sockdir), (port)))
#define UNIXSOCK_PATH_BUFLEN sizeof(((struct sockaddr_un *) NULL)->sun_path)
#define ss_family __ss_family
#define ss_len __ss_len

#define USER_AUTH_LAST uaPeer	
#define REG_BOSONLY 002000		
#define REG_ECOLORS 20			
#define REG_EESCAPE  5			
#define REG_ESUBREG  6			
#define REG_ETOOBIG 19			
#define REG_NEWLINE 000300		
#define REG_NOMATCH  1			



#define IS_AF_UNIX(fam) ((fam) == AF_UNIX)



#define XLogArchiveCommandSet() (XLogArchiveCommand[0] != '\0')
#define XLogArchivingActive() \
	(AssertMacro(XLogArchiveMode == ARCHIVE_MODE_OFF || wal_level >= WAL_LEVEL_REPLICA), XLogArchiveMode > ARCHIVE_MODE_OFF)
#define XLogArchivingAlways() \
	(AssertMacro(XLogArchiveMode == ARCHIVE_MODE_OFF || wal_level >= WAL_LEVEL_REPLICA), XLogArchiveMode == ARCHIVE_MODE_ALWAYS)
#define XLogHintBitIsNeeded() (DataChecksumsEnabled() || wal_log_hints)
#define XLogIsNeeded() (wal_level >= WAL_LEVEL_REPLICA)
#define XLogLogicalInfoActive() (wal_level >= WAL_LEVEL_LOGICAL)
#define XLogStandbyInfoActive() (wal_level >= WAL_LEVEL_REPLICA)

#define BoolGetDatum(X) ((Datum) ((X) ? 1 : 0))
#define CStringGetDatum(X) PointerGetDatum(X)
#define CharGetDatum(X) ((Datum) (X))
#define CommandIdGetDatum(X) ((Datum) (X))
#define DatumGetBool(X) ((bool) ((X) != 0))
#define DatumGetCString(X) ((char *) DatumGetPointer(X))
#define DatumGetChar(X) ((char) (X))
#define DatumGetCommandId(X) ((CommandId) (X))
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
#define VARATT_EXTERNAL_GET_COMPRESS_METHOD(toast_pointer) \
	((toast_pointer).va_extinfo >> VARLENA_EXTSIZE_BITS)
#define VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer) \
	((toast_pointer).va_extinfo & VARLENA_EXTSIZE_MASK)
#define VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer) \
	(VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer) < \
	 (toast_pointer).va_rawsize - VARHDRSZ)
#define VARATT_EXTERNAL_SET_SIZE_AND_COMPRESS_METHOD(toast_pointer, len, cm) \
	do { \
		Assert((cm) == TOAST_PGLZ_COMPRESSION_ID || \
			   (cm) == TOAST_LZ4_COMPRESSION_ID); \
		((toast_pointer).va_extinfo = \
			(len) | ((uint32) (cm) << VARLENA_EXTSIZE_BITS)); \
	} while (0)
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
#define VARDATA_COMPRESSED_GET_COMPRESS_METHOD(PTR) \
	(((varattrib_4b *) (PTR))->va_compressed.va_tcinfo >> VARLENA_EXTSIZE_BITS)
#define VARDATA_COMPRESSED_GET_EXTSIZE(PTR) \
	(((varattrib_4b *) (PTR))->va_compressed.va_tcinfo & VARLENA_EXTSIZE_MASK)
#define VARDATA_EXTERNAL(PTR)				VARDATA_1B_E(PTR)
#define VARDATA_SHORT(PTR)					VARDATA_1B(PTR)
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
		MemoryContextAllocZeroAligned(CurrentMemoryContext, sz) : \
		MemoryContextAllocZero(CurrentMemoryContext, sz) )

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
			PG_exception_stack = _save_exception_stack; \
			error_context_stack = _save_context_stack
#define PG_END_TRY()  \
		} \
		if (_do_rethrow) \
				PG_RE_THROW(); \
		PG_exception_stack = _save_exception_stack; \
		error_context_stack = _save_context_stack; \
	} while (0)
#define PG_FINALLY() \
		} \
		else \
			_do_rethrow = true; \
		{ \
			PG_exception_stack = _save_exception_stack; \
			error_context_stack = _save_context_stack
#define PG_RE_THROW()  \
	pg_re_throw()
#define PG_TRY()  \
	do { \
		sigjmp_buf *_save_exception_stack = PG_exception_stack; \
		ErrorContextCallback *_save_context_stack = error_context_stack; \
		sigjmp_buf _local_sigjmp_buf; \
		bool _do_rethrow = false; \
		if (sigsetjmp(_local_sigjmp_buf, 0) == 0) \
		{ \
			PG_exception_stack = &_local_sigjmp_buf
#define TEXTDOMAIN NULL
#define elog(elevel, ...)  \
	ereport(elevel, errmsg_internal(__VA_ARGS__))
#define ereport(elevel, ...)	\
	ereport_domain(elevel, TEXTDOMAIN, __VA_ARGS__)
#define ereport_domain(elevel, domain, ...)	\
	do { \
		pg_prevent_errno_in_scope(); \
		if (__builtin_constant_p(elevel) && (elevel) >= ERROR ? \
			errstart_cold(elevel, domain) : \
			errstart(elevel, domain)) \
			__VA_ARGS__, errfinish("__FILE__", "__LINE__", PG_FUNCNAME_MACRO); \
		if (__builtin_constant_p(elevel) && (elevel) >= ERROR) \
			pg_unreachable(); \
	} while(0)
#define pg_prevent_errno_in_scope() int __errno_location pg_attribute_unused()
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
#define FLOAT4_FITS_IN_INT16(num) \
	((num) >= (float4) PG_INT16_MIN && (num) < -((float4) PG_INT16_MIN))
#define FLOAT4_FITS_IN_INT32(num) \
	((num) >= (float4) PG_INT32_MIN && (num) < -((float4) PG_INT32_MIN))
#define FLOAT4_FITS_IN_INT64(num) \
	((num) >= (float4) PG_INT64_MIN && (num) < -((float4) PG_INT64_MIN))
#define FLOAT8PASSBYVAL true
#define FLOAT8_FITS_IN_INT16(num) \
	((num) >= (float8) PG_INT16_MIN && (num) < -((float8) PG_INT16_MIN))
#define FLOAT8_FITS_IN_INT32(num) \
	((num) >= (float8) PG_INT32_MIN && (num) < -((float8) PG_INT32_MIN))
#define FLOAT8_FITS_IN_INT64(num) \
	((num) >= (float8) PG_INT64_MIN && (num) < -((float8) PG_INT64_MIN))
#define HAVE_INT128 1

#define HAVE_PG_ATTRIBUTE_NORETURN 1
#define HAVE_STRTOLL 1
#define HAVE_STRTOULL 1
#define HAVE_UNIX_SOCKETS 1
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
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
#define StaticAssertDecl(condition, errmessage) \
	_Static_assert(condition, errmessage)
#define StaticAssertExpr(condition, errmessage) \
	((void) ({ StaticAssertStmt(condition, errmessage); true; }))
#define StaticAssertStmt(condition, errmessage) \
	do { _Static_assert(condition, errmessage); } while(0)
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
#define VA_ARGS_NARGS(...) \
	VA_ARGS_NARGS_(__VA_ARGS__, \
				   63,62,61,60,                   \
				   59,58,57,56,55,54,53,52,51,50, \
				   49,48,47,46,45,44,43,42,41,40, \
				   39,38,37,36,35,34,33,32,31,30, \
				   29,28,27,26,25,24,23,22,21,20, \
				   19,18,17,16,15,14,13,12,11,10, \
				   9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define VA_ARGS_NARGS_( \
	_01,_02,_03,_04,_05,_06,_07,_08,_09,_10, \
	_11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
	_21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
	_31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
	_41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
	_51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
	_61,_62,_63,  N, ...) \
	(N)
#define _(x) gettext(x)
#define __has_attribute(attribute) 0
#define dgettext(d,x) (x)
#define dngettext(d,s,p,n) ((n) == 1 ? (s) : (p))
#define gettext(x) (x)
#define gettext_noop(x) (x)

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define likely(x)	__builtin_expect((x) != 0, 1)
#define ngettext(s,p,n) ((n) == 1 ? (s) : (p))
#define offsetof(type, field)	((long) &((type *)0)->field)
#define pg_attribute_aligned(a) __attribute__((aligned(a)))
#define pg_attribute_always_inline __attribute__((always_inline)) inline
#define pg_attribute_cold __attribute__((cold))
#define pg_attribute_format_arg(a) __attribute__((format_arg(a)))
#define pg_attribute_hot __attribute__((hot))
#define pg_attribute_no_sanitize_alignment() __attribute__((no_sanitize("alignment")))
#define pg_attribute_noreturn() __attribute__((noreturn))
#define pg_attribute_packed() __attribute__((packed))
#define pg_attribute_printf(f,a) __attribute__((format(PG_PRINTF_ATTRIBUTE, f, a)))
#define pg_attribute_unused() __attribute__((unused))
#define pg_nodiscard __attribute__((warn_unused_result))
#define pg_noinline __attribute__((noinline))
#define pg_unreachable() __builtin_unreachable()
#define sigjmp_buf jmp_buf
#define siglongjmp __builtin_longjmp
#define sigsetjmp(x,y) __builtin_setjmp(x)
#define strtoll strtoq
#define strtoull strtouq
#define unconstify(underlying_type, expr) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof(expr), const underlying_type), \
					  "wrong cast"), \
	 (underlying_type) (expr))
#define unlikely(x) __builtin_expect((x) != 0, 0)
#define unvolatize(underlying_type, expr) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof(expr), volatile underlying_type), \
					  "wrong cast"), \
	 (underlying_type) (expr))
#define ALL_CONNECTION_FAILURE_ERRNOS \
	EPIPE: \
	case ECONNRESET: \
	case ECONNABORTED: \
	case EHOSTDOWN: \
	case EHOSTUNREACH: \
	case ENETDOWN: \
	case ENETRESET: \
	case ENETUNREACH: \
	case ETIMEDOUT
#define DEVNULL "nul"
#define EXE ".exe"
#define IS_DIR_SEP(ch)	((ch) == '/')
#define PGINVALID_SOCKET (-1)
#define PG_BACKEND_VERSIONSTR "postgres (PostgreSQL) " PG_VERSION "\n"

#define PG_STRERROR_R_BUFLEN 256	
#define RTLD_GLOBAL 0
#define RTLD_NOW 1
#define TIMEZONE_GLOBAL _timezone
#define TZNAME_GLOBAL _tzname
#define USE_REPL_SNPRINTF 1
#define closesocket close
#define		fopen(a,b) pgwin32_fopen(a,b)
#define fprintf			pg_fprintf
#define is_absolute_path(filename) \
( \
	IS_DIR_SEP((filename)[0]) \
)
#define isinf __builtin_isinf
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pg_backend_random pg_strong_random
#define pg_pread pread
#define pg_pwrite pwrite
#define pgoff_t off_t
#define popen(a,b) pgwin32_popen(a,b)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define rename(from, to)		pgrename(from, to)
#define snprintf		pg_snprintf
#define sprintf			pg_sprintf
#define strerror pg_strerror
#define strerror_r pg_strerror_r
#define strtof(a,b) (pg_strtof((a),(b)))
#define system(a) pgwin32_system(a)
#define unlink(path)			pgunlink(path)
#define vfprintf		pg_vfprintf
#define vprintf			pg_vprintf
#define vsnprintf		pg_vsnprintf
#define vsprintf		pg_vsprintf
#define DLSUFFIX ".dll"
#define EACCESS 2048
#define EADDRINUSE WSAEADDRINUSE
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define EAGAIN WSAEWOULDBLOCK
#define ECONNABORTED WSAECONNABORTED
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET WSAECONNRESET
#define EHOSTDOWN WSAEHOSTDOWN
#define EHOSTUNREACH WSAEHOSTUNREACH
#define EIDRM 4096
#define EINPROGRESS WSAEINPROGRESS
#define EINTR WSAEINTR
#define EISCONN WSAEISCONN
#define EMSGSIZE WSAEMSGSIZE
#define ENABLE_SSPI 1
#define ENETDOWN WSAENETDOWN
#define ENETRESET WSAENETRESET
#define ENETUNREACH WSAENETUNREACH
#define ENOBUFS WSAENOBUFS
#define ENOTCONN WSAENOTCONN
#define ENOTSOCK WSAENOTSOCK
#define EOPNOTSUPP WSAEOPNOTSUPP
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#define ETIMEDOUT WSAETIMEDOUT
#define EWOULDBLOCK WSAEWOULDBLOCK

#define F_OK 0
#define GETNCNT 16384
#define GETPID 262144
#define GETVAL 65536
#define HAVE_BUGGY_STRTOF 1

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
#define fseeko(stream, offset, origin) _fseeki64(stream, offset, origin)
#define fstat microsoft_native_fstat
#define fsync(fd) _commit(fd)
#define ftello(stream) _ftelli64(stream)
#define ftruncate(a,b)	chsize(a,b)
#define isalnum_l _isalnum_l
#define isalpha_l _isalpha_l
#define isdigit_l _isdigit_l
#define isgraph_l _isgraph_l
#define islower_l _islower_l
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
#define listen(s, backlog) pgwin32_listen(s, backlog)
#define locale_t _locale_t
#define lstat(path, sb)		_pgstat64(path, sb)
#define mbstowcs_l _mbstowcs_l
#define putenv(x) pgwin32_putenv(x)
#define recv(s, buf, len, flags) pgwin32_recv(s, buf, len, flags)
#define select(n, r, w, e, timeout) pgwin32_select(n, r, w, e, timeout)
#define send(s, buf, len, flags) pgwin32_send(s, buf, len, flags)
#define setenv(x,y,z) pgwin32_setenv(x,y,z)
#define setlocale(a,b) pgwin32_setlocale(a,b)
#define sigmask(sig) ( 1 << ((sig)-1) )
#define socket(af, type, protocol) pgwin32_socket(af, type, protocol)
#define stat microsoft_native_stat
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
