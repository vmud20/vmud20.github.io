#include<errno.h>

#include<stdlib.h>






#include<stdio.h>




#include<locale.h>







#include<pwd.h>
#include<stdint.h>

#include<ctype.h>
#include<sys/time.h>

#include<time.h>






#include<sys/stat.h>
#include<arpa/inet.h>


#include<strings.h>



#include<stdarg.h>
#include<string.h>


#include<signal.h>



#include<assert.h>


#include<dirent.h>




#include<netinet/in.h>









#include<setjmp.h>
#include<netdb.h>
#include<fcntl.h>


#include<libintl.h>
#include<limits.h>
#include<stddef.h>
#include<sys/types.h>







#define InvalidRelation ((Relation) NULL)
#define RELATION_IS_LOCAL(relation) \
	((relation)->rd_islocaltemp || \
	 (relation)->rd_createSubid != InvalidSubTransactionId)
#define RELATION_IS_OTHER_TEMP(relation) \
	((relation)->rd_rel->relpersistence == RELPERSISTENCE_TEMP && \
	 !(relation)->rd_islocaltemp)

#define RelationCloseSmgr(relation) \
	do { \
		if ((relation)->rd_smgr != NULL) \
		{ \
			smgrclose((relation)->rd_smgr); \
			Assert((relation)->rd_smgr == NULL); \
		} \
	} while (0)
#define RelationGetDescr(relation) ((relation)->rd_att)
#define RelationGetFillFactor(relation, defaultff) \
	((relation)->rd_options ? \
	 ((StdRdOptions *) (relation)->rd_options)->fillfactor : (defaultff))
#define RelationGetForm(relation) ((relation)->rd_rel)
#define RelationGetNamespace(relation) \
	((relation)->rd_rel->relnamespace)
#define RelationGetNumberOfAttributes(relation) ((relation)->rd_rel->relnatts)
#define RelationGetParallelWorkers(relation, defaultpw) \
	((relation)->rd_options ? \
	 ((StdRdOptions *) (relation)->rd_options)->parallel_workers : (defaultpw))
#define RelationGetPartitionDesc(relation) ((relation)->rd_partdesc)
#define RelationGetPartitionKey(relation) ((relation)->rd_partkey)
#define RelationGetRelationName(relation) \
	(NameStr((relation)->rd_rel->relname))
#define RelationGetRelid(relation) ((relation)->rd_id)
#define RelationGetTargetBlock(relation) \
	( (relation)->rd_smgr != NULL ? (relation)->rd_smgr->smgr_targblock : InvalidBlockNumber )
#define RelationGetTargetPageFreeSpace(relation, defaultff) \
	(BLCKSZ * (100 - RelationGetFillFactor(relation, defaultff)) / 100)
#define RelationGetTargetPageUsage(relation, defaultff) \
	(BLCKSZ * RelationGetFillFactor(relation, defaultff) / 100)
#define RelationHasCascadedCheckOption(relation)							\
	((relation)->rd_options &&												\
	 ((ViewOptions *) (relation)->rd_options)->check_option_offset != 0 ?	\
	 strcmp((char *) (relation)->rd_options +								\
			((ViewOptions *) (relation)->rd_options)->check_option_offset,	\
			"cascaded") == 0 : false)
#define RelationHasCheckOption(relation)									\
	((relation)->rd_options &&												\
	 ((ViewOptions *) (relation)->rd_options)->check_option_offset != 0)
#define RelationHasLocalCheckOption(relation)								\
	((relation)->rd_options &&												\
	 ((ViewOptions *) (relation)->rd_options)->check_option_offset != 0 ?	\
	 strcmp((char *) (relation)->rd_options +								\
			((ViewOptions *) (relation)->rd_options)->check_option_offset,	\
			"local") == 0 : false)
#define RelationHasReferenceCountZero(relation) \
		((bool)((relation)->rd_refcnt == 0))
#define RelationIsAccessibleInLogicalDecoding(relation) \
	(XLogLogicalInfoActive() && \
	 RelationNeedsWAL(relation) && \
	 (IsCatalogRelation(relation) || RelationIsUsedAsCatalogTable(relation)))
#define RelationIsLogicallyLogged(relation) \
	(XLogLogicalInfoActive() && \
	 RelationNeedsWAL(relation) && \
	 !IsCatalogRelation(relation))
#define RelationIsMapped(relation) \
	((relation)->rd_rel->relfilenode == InvalidOid)
#define RelationIsPopulated(relation) ((relation)->rd_rel->relispopulated)
#define RelationIsScannable(relation) ((relation)->rd_rel->relispopulated)
#define RelationIsSecurityView(relation)	\
	((relation)->rd_options ?				\
	 ((ViewOptions *) (relation)->rd_options)->security_barrier : false)
#define RelationIsUsedAsCatalogTable(relation)	\
	((relation)->rd_options && \
	 ((relation)->rd_rel->relkind == RELKIND_RELATION || \
	  (relation)->rd_rel->relkind == RELKIND_MATVIEW) ? \
	 ((StdRdOptions *) (relation)->rd_options)->user_catalog_table : false)
#define RelationIsValid(relation) PointerIsValid(relation)
#define RelationNeedsWAL(relation) \
	((relation)->rd_rel->relpersistence == RELPERSISTENCE_PERMANENT)
#define RelationOpenSmgr(relation) \
	do { \
		if ((relation)->rd_smgr == NULL) \
			smgrsetowner(&((relation)->rd_smgr), smgropen((relation)->rd_node, (relation)->rd_backend)); \
	} while (0)
#define RelationSetTargetBlock(relation, targblock) \
	do { \
		RelationOpenSmgr(relation); \
		(relation)->rd_smgr->smgr_targblock = (targblock); \
	} while (0)
#define RelationUsesLocalBuffers(relation) \
	((relation)->rd_rel->relpersistence == RELPERSISTENCE_TEMP)



#define BITS_PER_BITMAPWORD 32
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
#define Anum_pg_attribute_attfdwoptions 22
#define Anum_pg_attribute_attstattarget 4
#define AttributeRelationId  1249
#define AttributeRelation_Rowtype_Id  75








#define CATALOG(name,oid)	typedef struct CppConcat(FormData_,name)
#define DATA(x)   extern int no_such_variable
#define DESCR(x)  extern int no_such_variable

#define SHDESCR(x) extern int no_such_variable

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

#define BackendIdForTempRelations() \
	(ParallelMasterBackendId == InvalidBackendId ? MyBackendId : ParallelMasterBackendId)

#define relpath(rnode, forknum) \
	relpathbackend((rnode).node, (rnode).backend, forknum)
#define relpathbackend(rnode, backend, forknum) \
	GetRelationPath((rnode).dbNode, (rnode).spcNode, (rnode).relNode, \
					backend, forknum)
#define relpathperm(rnode, forknum) \
	relpathbackend(rnode, InvalidBackendId, forknum)

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
#define fmgr_info_set_expr(expr, finfo) \
	((finfo)->fn_expr = (expr))


#define ObjectAddressSet(addr, class_id, object_id) \
	ObjectAddressSubSet(addr, class_id, object_id, 0)
#define ObjectAddressSubSet(addr, class_id, object_id, object_sub_id) \
	do { \
		(addr).classId = (class_id); \
		(addr).objectId = (object_id); \
		(addr).objectSubId = (object_sub_id); \
	} while (0)
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
#define ItemPointerSetOffsetNumber(pointer, offsetNumber) \
( \
	AssertMacro(PointerIsValid(pointer)), \
	(pointer)->ip_posid = (offsetNumber) \
)

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

#define REINDEXOPT_VERBOSE 1 << 0	

#define floatVal(v)		atof(((Value *)(v))->val.str)
#define intVal(v)		(((Value *)(v))->val.ival)
#define strVal(v)		(((Value *)(v))->val.str)
#define IS_SPECIAL_VARNO(varno)		((varno) >= INNER_VAR)



#define ShareUpdateExclusiveLock 4	
#define IndexIsLive(indexForm)	((indexForm)->indislive)
#define IndexIsReady(indexForm) ((indexForm)->indisready)
#define IndexIsValid(indexForm) ((indexForm)->indisvalid)
#define IndexRelationId  2610

#define CLASS_TUPLE_SIZE \
	 (offsetof(FormData_pg_class,relminmxid) + sizeof(TransactionId))

#define		  RELKIND_COMPOSITE_TYPE  'c'	
#define		  RELKIND_FOREIGN_TABLE   'f'	
#define		  RELKIND_PARTITIONED_TABLE 'p' 
#define RelationRelation_Rowtype_Id  83
#define InHotStandby (standbyState >= STANDBY_SNAPSHOT_PENDING)

#define XLogArchiveCommandSet() (XLogArchiveCommand[0] != '\0')
#define XLogArchivingActive() \
	(AssertMacro(XLogArchiveMode == ARCHIVE_MODE_OFF || wal_level >= WAL_LEVEL_REPLICA), XLogArchiveMode > ARCHIVE_MODE_OFF)
#define XLogArchivingAlways() \
	(AssertMacro(XLogArchiveMode == ARCHIVE_MODE_OFF || wal_level >= WAL_LEVEL_REPLICA), XLogArchiveMode == ARCHIVE_MODE_ALWAYS)
#define XLogHintBitIsNeeded() (DataChecksumsEnabled() || wal_log_hints)
#define XLogIsNeeded() (wal_level >= WAL_LEVEL_REPLICA)
#define XLogLogicalInfoActive() (wal_level >= WAL_LEVEL_LOGICAL)
#define XLogStandbyInfoActive() (wal_level >= WAL_LEVEL_REPLICA)

#define PG_TEMP_FILES_DIR "pgsql_tmp"
#define PG_TEMP_FILE_PREFIX "pgsql_tmp"

#define XLogRecBlockImageApply(decoder, block_id) \
	((decoder)->blocks[block_id].apply_image)
#define XLogRecGetData(decoder) ((decoder)->main_data)
#define XLogRecGetDataLen(decoder) ((decoder)->main_data_len)
#define XLogRecGetInfo(decoder) ((decoder)->decoded_record->xl_info)
#define XLogRecGetOrigin(decoder) ((decoder)->record_origin)
#define XLogRecGetPrev(decoder) ((decoder)->decoded_record->xl_prev)
#define XLogRecGetRmid(decoder) ((decoder)->decoded_record->xl_rmid)
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



#define TypeIsToastable(typid)	(get_typstorage(typid) != 'p')
#define type_is_array(typid)  (get_element_type(typid) != InvalidOid)
#define type_is_array_domain(typid)  (get_base_element_type(typid) != InvalidOid)
#define GUC_DISALLOW_IN_AUTO_FILE 0x0800	

#define GUC_QUALIFIER_SEPARATOR '.'
#define GUC_check_errdetail \
	pre_format_elog_string(errno, TEXTDOMAIN), \
	GUC_check_errdetail_string = format_elog_string
#define GUC_check_errhint \
	pre_format_elog_string(errno, TEXTDOMAIN), \
	GUC_check_errhint_string = format_elog_string
#define GUC_check_errmsg \
	pre_format_elog_string(errno, TEXTDOMAIN), \
	GUC_check_errmsg_string = format_elog_string

#define TTS_HAS_PHYSICAL_TUPLE(slot)  \
	((slot)->tts_tuple != NULL && (slot)->tts_tuple != &((slot)->tts_minhdr))

#define TupIsNull(slot) \
	((slot) == NULL || (slot)->tts_isempty)

#define ISCOMPLEX(typeid) (typeOrDomainTypeRelid(typeid) != InvalidOid)






#define RangeVarGetRelid(relation, lockmode, missing_ok) \
	RangeVarGetRelidExtended(relation, lockmode, missing_ok, false, NULL, NULL)
#define GET_VXID_FROM_PGPROC(vxid, proc) \
	((vxid).backendId = (proc).backendId, \
	 (vxid).localTransactionId = (proc).lxid)
#define LOCALLOCK_LOCKMETHOD(llock) ((llock).tag.lock.locktag_lockmethodid)
#define LOCKBIT_OFF(lockmode) (~(1 << (lockmode)))
#define LOCKBIT_ON(lockmode) (1 << (lockmode))

#define LOCK_LOCKMETHOD(lock) ((LOCKMETHODID) (lock).tag.locktag_lockmethodid)
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
#define VirtualTransactionIdIsValid(vxid) \
	(((vxid).backendId != InvalidBackendId) && \
	 LocalTransactionIdIsValid((vxid).localTransactionId))

#define HASH_FIXED_SIZE 0x2000	
#define HASH_SHARED_MEM 0x0800	

#define oid_hash uint32_hash	
#define LOG2_NUM_LOCK_PARTITIONS  4
#define LOG2_NUM_PREDICATELOCK_PARTITIONS  4

#define LWLOCK_MINIMAL_SIZE (sizeof(LWLock) <= 32 ? 32 : 64)
#define NUM_BUFFER_PARTITIONS  128
#define NUM_FIXED_LWLOCKS \
	(PREDICATELOCK_MANAGER_LWLOCK_OFFSET + NUM_PREDICATELOCK_PARTITIONS)
#define NUM_LOCK_PARTITIONS  (1 << LOG2_NUM_LOCK_PARTITIONS)
#define NUM_PREDICATELOCK_PARTITIONS  (1 << LOG2_NUM_PREDICATELOCK_PARTITIONS)
#define PREDICATELOCK_MANAGER_LWLOCK_OFFSET \
	(LOCK_MANAGER_LWLOCK_OFFSET + NUM_LOCK_PARTITIONS)


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


#define DEFAULT_SPINS_PER_DELAY  100

#define SPIN_DELAY() spin_delay()
#define S_INIT_LOCK(lock) \
	do { \
		volatile slock_t *lock_ = (lock); \
		lock_->sema[0] = -1; \
		lock_->sema[1] = -1; \
		lock_->sema[2] = -1; \
		lock_->sema[3] = -1; \
	} while (0)
#define S_LOCK(lock) \
	(TAS(lock) ? s_lock((lock), "__FILE__", "__LINE__", PG_FUNCNAME_MACRO) : 0)
#define S_LOCK_FREE(lock)	(*TAS_ACTIVE_WORD(lock) != 0)

#define S_UNLOCK(lock)	\
	do { __memory_barrier(); *(lock) = 0; } while (0)
#define TAS(lock) tas(lock)
#define TAS_ACTIVE_WORD(lock)	((volatile int *) (((uintptr_t) (lock) + 15) & ~15))
#define TAS_SPIN(lock)    (*(lock) ? 1 : TAS(lock))

#define init_local_spin_delay(status) init_spin_delay(status, "__FILE__", "__LINE__", PG_FUNCNAME_MACRO)







#define getrelid(rangeindex,rangetable) \
	(rt_fetch(rangeindex, rangetable)->relid)
#define rt_fetch(rangetable_index, rangetable) \
	((RangeTblEntry *) list_nth(rangetable, (rangetable_index)-1))

#define PVC_INCLUDE_WINDOWFUNCS 0x0004	
#define PVC_RECURSE_WINDOWFUNCS 0x0008	

#define EC_MUST_BE_REDUNDANT(eclass)  \
	((eclass)->ec_has_const && !(eclass)->ec_below_outer_join)
#define IS_DUMMY_PATH(p) \
	(IsA((p), AppendPath) && ((AppendPath *) (p))->subpaths == NIL)
#define IS_DUMMY_REL(r) \
	((r)->cheapest_total_path != NULL && \
	 IS_DUMMY_PATH((r)->cheapest_total_path))
#define IS_JOIN_REL(rel)	\
	((rel)->reloptkind == RELOPT_JOINREL || \
	 (rel)->reloptkind == RELOPT_OTHER_JOINREL)
#define IS_OTHER_REL(rel) \
	((rel)->reloptkind == RELOPT_OTHER_MEMBER_REL || \
	 (rel)->reloptkind == RELOPT_OTHER_JOINREL)
#define IS_PARTITIONED_REL(rel) \
	((rel)->part_scheme && (rel)->boundinfo && (rel)->nparts > 0)
#define IS_SIMPLE_REL(rel) \
	((rel)->reloptkind == RELOPT_BASEREL || \
	 (rel)->reloptkind == RELOPT_OTHER_MEMBER_REL)
#define IS_UPPER_REL(rel) ((rel)->reloptkind == RELOPT_UPPER_REL)
#define PATH_REQ_OUTER(path)  \
	((path)->param_info ? (path)->param_info->ppi_req_outer : (Relids) NULL)

#define REL_HAS_ALL_PART_PROPS(rel)	\
	((rel)->part_scheme && (rel)->boundinfo && (rel)->nparts > 0 && \
	 (rel)->part_rels && (rel)->partexprs && (rel)->nullable_partexprs)
#define get_pathtarget_sortgroupref(target, colno) \
	((target)->sortgrouprefs ? (target)->sortgrouprefs[colno] : (Index) 0)
#define planner_rt_fetch(rti, root) \
	((root)->simple_rte_array ? (root)->simple_rte_array[rti] : \
	 rt_fetch(rti, (root)->parse->rtable))
#define planner_subplan_get_plan(root, subplan) \
	((Plan *) list_nth((root)->glob->subplans, (subplan)->plan_id - 1))


#define ScanDirectionIsBackward(direction) \
	((bool) ((direction) == BackwardScanDirection))
#define ScanDirectionIsForward(direction) \
	((bool) ((direction) == ForwardScanDirection))
#define ScanDirectionIsNoMovement(direction) \
	((bool) ((direction) == NoMovementScanDirection))
#define ScanDirectionIsValid(direction) \
	((bool) (BackwardScanDirection <= (direction) && \
			 (direction) <= ForwardScanDirection))

#define create_pathtarget(root, tlist) \
	set_pathtarget_cost_width(root, make_pathtarget_from_tlist(tlist))



#define CASHOID 790
#define CIDOID 29
#define CIDROID 650
#define FLOAT4ARRAYOID 1021
#define FLOAT4OID 700
#define FLOAT8OID 701
#define INDEX_AM_HANDLEROID 325
#define INETOID 869
#define IsPolymorphicType(typid)  \
	((typid) == ANYELEMENTOID || \
	 (typid) == ANYARRAYOID || \
	 (typid) == ANYNONARRAYOID || \
	 (typid) == ANYENUMOID || \
	 (typid) == ANYRANGEOID)
#define JSONBOID 3802
#define JSONOID 114
#define MACADDR8OID 774
#define MACADDROID 829
#define PGDDLCOMMANDOID 32

#define REGPROCEDUREOID 2202
#define REGTYPEARRAYOID 2211
#define  TYPCATEGORY_PSEUDOTYPE 'P'
#define TypeRelation_Rowtype_Id  71
#define UUIDOID 2950
#define XIDOID 28
#define XMLOID 142


#define Anum_pg_collation_collnamespace 2
#define CollationRelationId  3456

#define BRIN_AM_OID 3580
#define BTREE_AM_OID 403
#define GIN_AM_OID 2742
#define GIST_AM_OID 783
#define HASH_AM_OID 405

#define SPGIST_AM_OID 4000

#define AccessMethodOperatorIndexId  2654
#define AccessMethodProcedureIndexId  2655
#define AccessMethodProcedureOidIndexId  2757
#define AccessMethodStrategyIndexId  2653
#define AggregateFnoidIndexId  2650
#define AmNameIndexId  2651
#define AmOidIndexId  2652
#define AttrDefaultOidIndexId  2657
#define AttributeRelidNameIndexId  2658
#define AttributeRelidNumIndexId  2659

#define CastSourceTargetIndexId  2661
#define ClassNameNspIndexId  2663
#define ClassOidIndexId  2662
#define ClassTblspcRelfilenodeIndexId  3455
#define CollationNameEncNspIndexId 3164
#define CollationOidIndexId  3085
#define ConstraintNameNspIndexId  2664
#define ConstraintOidIndexId  2667
#define ConversionDefaultIndexId  2668
#define ConversionNameNspIndexId  2669
#define ConversionOidIndexId  2670
#define DECLARE_INDEX(name,oid,decl) extern int no_such_variable
#define DECLARE_UNIQUE_INDEX(name,oid,decl) extern int no_such_variable
#define DatabaseNameIndexId  2671
#define DefaultAclRoleNspObjIndexId 827
#define DependDependerIndexId  2673
#define DescriptionObjIndexId  2675
#define EnumTypIdLabelIndexId 3503
#define EnumTypIdSortOrderIndexId 3534
#define EventTriggerNameIndexId  3467
#define ExtensionNameIndexId 3081
#define ExtensionOidIndexId 3080
#define ForeignServerOidIndexId 113
#define ForeignTableRelidIndexId 3119

#define IndexIndrelidIndexId  2678
#define IndexRelidIndexId  2679
#define InheritsParentIndexId  2187
#define InheritsRelidSeqnoIndexId  2680
#define InitPrivsObjIndexId  3395
#define LanguageNameIndexId  2681
#define LargeObjectLOidPNIndexId  2683
#define NamespaceNameIndexId  2684
#define NamespaceOidIndexId  2685
#define OpclassAmNameNspIndexId  2686
#define OpclassOidIndexId  2687
#define OpfamilyAmNameNspIndexId  2754
#define PLTemplateNameIndexId  1137
#define ProcedureNameArgsNspIndexId  2691
#define ProcedureOidIndexId  2690
#define PublicationNameIndexId 6111
#define PublicationObjectIndexId 6110
#define PublicationRelObjectIndexId 6112
#define PublicationRelPrrelidPrpubidIndexId 6113
#define ReplicationOriginIdentIndex 6001
#define ReplicationOriginNameIndex 6002
#define RewriteOidIndexId  2692
#define RewriteRelRulenameIndexId  2693
#define SharedDescriptionObjIndexId 2397
#define StatisticExtNameIndexId 3997
#define StatisticExtRelidIndexId 3379
#define SubscriptionNameIndexId 6115
#define SubscriptionObjectIndexId 6114
#define SubscriptionRelSrrelidSrsubidIndexId 6117
#define TablespaceNameIndexId  2698
#define TablespaceOidIndexId  2697
#define TransformOidIndexId 3574
#define TransformTypeLangIndexId  3575
#define TriggerConstraintIndexId  2699
#define TriggerOidIndexId  2702
#define TriggerRelidNameIndexId  2701




#define InitTupleHashIterator(htable, iter) \
	tuplehash_start_iterate(htable->hashtab, iter)
#define InstrCountFiltered1(node, delta) \
	do { \
		if (((PlanState *)(node))->instrument) \
			((PlanState *)(node))->instrument->nfiltered1 += (delta); \
	} while(0)
#define InstrCountFiltered2(node, delta) \
	do { \
		if (((PlanState *)(node))->instrument) \
			((PlanState *)(node))->instrument->nfiltered2 += (delta); \
	} while(0)
#define ResetTupleHashIterator(htable, iter) \
	InitTupleHashIterator(htable, iter)

#define SH_ELEMENT_TYPE TupleHashEntryData
#define SH_KEY_TYPE MinimalTuple
#define SH_PREFIX tuplehash
#define SH_SCOPE extern
#define ScanTupleHashTable(htable, iter) \
	tuplehash_iterate(htable->hashtab, iter)
#define TermTupleHashIterator(iter) \
	((void) 0)
#define innerPlanState(node)		(((PlanState *)(node))->righttree)
#define outerPlanState(node)		(((PlanState *)(node))->lefttree)
#define SH_ALLOCATE SH_MAKE_NAME(allocate)
#define SH_COMPARE_KEYS(tb, ahash, akey, b) (ahash == SH_GET_HASH(tb, b) && SH_EQUAL(tb, b->SH_KEY, akey))
#define SH_COMPUTE_PARAMETERS SH_MAKE_NAME(compute_parameters)
#define SH_CREATE SH_MAKE_NAME(create)
#define SH_DELETE SH_MAKE_NAME(delete)
#define SH_DESTROY SH_MAKE_NAME(destroy)
#define SH_DISTANCE_FROM_OPTIMAL SH_MAKE_NAME(distance)
#define SH_ENTRY_HASH SH_MAKE_NAME(entry_hash)
#define SH_FILLFACTOR (0.9)
#define SH_FREE SH_MAKE_NAME(free)
#define SH_GROW SH_MAKE_NAME(grow)
#define SH_GROW_MAX_DIB 25
#define SH_GROW_MAX_MOVE 150
#define SH_INITIAL_BUCKET SH_MAKE_NAME(initial_bucket)
#define SH_INSERT SH_MAKE_NAME(insert)
#define SH_ITERATE SH_MAKE_NAME(iterate)
#define SH_ITERATOR SH_MAKE_NAME(iterator)
#define SH_LOOKUP SH_MAKE_NAME(lookup)
#define SH_MAKE_NAME(name) SH_MAKE_NAME_(SH_MAKE_PREFIX(SH_PREFIX),name)
#define SH_MAKE_NAME_(a,b) CppConcat(a,b)
#define SH_MAKE_PREFIX(a) CppConcat(a,_)
#define SH_MAX_FILLFACTOR (0.98)
#define SH_MAX_SIZE (((uint64) PG_UINT32_MAX) + 1)
#define SH_NEXT SH_MAKE_NAME(next)
#define SH_PREV SH_MAKE_NAME(prev)
#define SH_START_ITERATE SH_MAKE_NAME(start_iterate)
#define SH_START_ITERATE_AT SH_MAKE_NAME(start_iterate_at)
#define SH_STAT SH_MAKE_NAME(stat)
#define SH_STATUS SH_MAKE_NAME(status)
#define SH_STATUS_EMPTY SH_MAKE_NAME(EMPTY)
#define SH_STATUS_IN_USE SH_MAKE_NAME(IN_USE)
#define SH_TYPE SH_MAKE_NAME(hash)
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
#define AllocSizeIsValid(size)	((Size) (size) <= MaxAllocSize)

#define MemoryContextResetAndDeleteChildren(ctx) MemoryContextReset(ctx)

#define MemoryContextIsValid(context) \
	((context) != NULL && \
	 (IsA((context), AllocSetContext) || IsA((context), SlabContext)))



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






#define INDEX_NULL_MASK 0x8000
#define INDEX_SIZE_MASK 0x1FFF

#define IndexInfoFindDataOffset(t_info) \
( \
	(!((t_info) & INDEX_NULL_MASK)) ? \
	( \
		(Size)MAXALIGN(sizeof(IndexTupleData)) \
	) \
	: \
	( \
		(Size)MAXALIGN(sizeof(IndexTupleData) + sizeof(IndexAttributeBitMapData)) \
	) \
)
#define IndexTupleDSize(itup)		((Size) ((itup).t_info & INDEX_SIZE_MASK))
#define IndexTupleHasNulls(itup)	((((IndexTuple) (itup))->t_info & INDEX_NULL_MASK))
#define IndexTupleHasVarwidths(itup) ((((IndexTuple) (itup))->t_info & INDEX_VAR_MASK))
#define IndexTupleSize(itup)		((Size) (((IndexTuple) (itup))->t_info & INDEX_SIZE_MASK))
#define MinIndexTupleSize MAXALIGN(sizeof(IndexTupleData) + 1)
#define index_getattr(tup, attnum, tupleDesc, isnull) \
( \
	AssertMacro(PointerIsValid(isnull) && (attnum) > 0), \
	*(isnull) = false, \
	!IndexTupleHasNulls(tup) ? \
	( \
		TupleDescAttr((tupleDesc), (attnum)-1)->attcacheoff >= 0 ? \
		( \
			fetchatt(TupleDescAttr((tupleDesc), (attnum)-1), \
			(char *) (tup) + IndexInfoFindDataOffset((tup)->t_info) \
			+ TupleDescAttr((tupleDesc), (attnum)-1)->attcacheoff) \
		) \
		: \
			nocache_index_getattr((tup), (attnum), (tupleDesc)) \
	) \
	: \
	( \
		(att_isnull((attnum)-1, (char *)(tup) + sizeof(IndexTupleData))) ? \
		( \
			*(isnull) = true, \
			(Datum)NULL \
		) \
		: \
		( \
			nocache_index_getattr((tup), (attnum), (tupleDesc)) \
		) \
	) \
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
#define PageIsPrunable(page, oldestxmin) \
( \
	AssertMacro(TransactionIdIsNormal(oldestxmin)), \
	TransactionIdIsValid(((PageHeader) (page))->pd_prune_xid) && \
	TransactionIdPrecedes(((PageHeader) (page))->pd_prune_xid, oldestxmin) \
)
#define PageIsValid(page) PointerIsValid(page)
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
	((attalign) == 'i') ? INTALIGN(cur_offset) : \
	 (((attalign) == 'c') ? (uintptr_t) (cur_offset) : \
	  (((attalign) == 'd') ? DOUBLEALIGN(cur_offset) : \
	   ( \
			AssertMacro((attalign) == 's'), \
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

#define tuplestore_donestoring(state)	((void) 0)


#define RowMarkRequiresRowShareLock(marktype)  ((marktype) <= ROW_MARK_KEYSHARE)
#define exec_subplan_get_plan(plannedstmt, subplan) \
	((Plan *) list_nth((plannedstmt)->subplans, (subplan)->plan_id - 1))
#define innerPlan(node)			(((Plan *)(node))->righttree)
#define outerPlan(node)			(((Plan *)(node))->lefttree)

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


#define HEAP_INSERT_SPECULATIVE 0x0008
#define HeapScanIsValid(scan) PointerIsValid(scan)
#define heap_close(r,l)  relation_close(r,l)

#define InvalidStrategy ((StrategyNumber) 0)


#define IndexScanIsValid(scan) PointerIsValid(scan)
#define AmBackgroundWriterProcess() (MyAuxProcType == BgWriterProcess)
#define AmBootstrapProcess()		(MyAuxProcType == BootstrapProcess)
#define AmCheckpointerProcess()		(MyAuxProcType == CheckpointerProcess)
#define AmStartupProcess()			(MyAuxProcType == StartupProcess)
#define AmWalReceiverProcess()		(MyAuxProcType == WalReceiverProcess)
#define AmWalWriterProcess()		(MyAuxProcType == WalWriterProcess)
#define CHECK_FOR_INTERRUPTS() \
do { \
	if (UNBLOCKED_SIGNAL_QUEUE()) \
		pgwin32_dispatch_queued_signals(); \
	if (InterruptPending) \
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
#define BoolGetDatum(X) ((Datum) ((X) ? 1 : 0))
#define CStringGetDatum(X) PointerGetDatum(X)
#define CharGetDatum(X) ((Datum) SET_1_BYTE(X))
#define CommandIdGetDatum(X) ((Datum) SET_4_BYTES(X))
#define DatumGetBool(X) ((bool) (GET_1_BYTE(X) != 0))
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
#define DatumGetUInt64(X) ((uint64) GET_8_BYTES(X))
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
#define NameGetDatum(X) CStringGetDatum(NameStr(*(X)))
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
#define UInt64GetDatum(X) ((Datum) SET_8_BYTES(X))
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
#define VARATT_IS_EXTERNAL_EXPANDED(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_IS_EXPANDED(VARTAG_EXTERNAL(PTR)))
#define VARATT_IS_EXTERNAL_EXPANDED_RO(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_EXPANDED_RO)
#define VARATT_IS_EXTERNAL_EXPANDED_RW(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_EXPANDED_RW)
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
#define Assert(condition)	((void)true)
#define AssertArg(condition)	((void)true)
#define AssertMacro(condition)	((void)true)
#define AssertPointerAlignment(ptr, bndr)	((void)true)
#define AssertState(condition)	((void)true)
#define AssertVariableIsOfType(varname, typename) \
	StaticAssertStmt(__builtin_types_compatible_p(__typeof__(varname), typename), \
	CppAsString(varname) " does not have type " CppAsString(typename))
#define AssertVariableIsOfTypeMacro(varname, typename) \
	((void) StaticAssertExpr(__builtin_types_compatible_p(__typeof__(varname), typename), \
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


#define HAVE_PG_ATTRIBUTE_NORETURN 1
#define HAVE_STRTOLL 1
#define HAVE_STRTOULL 1
#define INT64CONST(x)  (x##L)
#define INT64_FORMAT "%" INT64_MODIFIER "d"
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
#define Trap(condition, errorType)	((void)true)
#define TrapMacro(condition, errorType) (true)
#define UINT64CONST(x) (x##UL)
#define UINT64_FORMAT "%" INT64_MODIFIER "u"

#define _(x) gettext(x)
#define dgettext(d,x) (x)
#define dngettext(d,s,p,n) ((n) == 1 ? (s) : (p))
#define errcode __msvc_errcode
#define gettext(x) (x)
#define gettext_noop(x) (x)

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define likely(x)	__builtin_expect((x) != 0, 1)
#define memmove(d, s, c)		bcopy(s, d, c)
#define ngettext(s,p,n) ((n) == 1 ? (s) : (p))
#define offsetof(type, field)	((long) &((type *)0)->field)
#define pg_attribute_aligned(a) __attribute__((aligned(a)))
#define pg_attribute_format_arg(a) __attribute__((format_arg(a)))
#define pg_attribute_noreturn() __attribute__((noreturn))
#define pg_attribute_packed() __attribute__((packed))
#define pg_attribute_printf(f,a) __attribute__((format(PG_PRINTF_ATTRIBUTE, f, a)))
#define pg_attribute_unused() __attribute__((unused))
#define pg_noinline __attribute__((noinline))
#define pg_unreachable() __builtin_unreachable()
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll strtoq
#define strtoull strtouq
#define unlikely(x) __builtin_expect((x) != 0, 0)
#define DEVNULL "nul"
#define EXE ".exe"
#define IS_DIR_SEP(ch)	((ch) == '/')
#define PGINVALID_SOCKET (-1)
#define PG_BACKEND_VERSIONSTR "postgres (PostgreSQL) " PG_VERSION "\n"

#define PG_SIGNAL_COUNT 32
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
#define kill(pid,sig)	pgkill(pid,sig)
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pgoff_t off_t
#define popen(a,b) pgwin32_popen(a,b)
#define pqsignal_no_restart(signo, func) pqsignal(signo, func)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define readlink(path, buf, size)	pgreadlink(path, buf, size)
#define rename(from, to)		pgrename(from, to)
#define setlocale(a,b) pgwin32_setlocale(a,b)
#define snprintf(...)	pg_snprintf(__VA_ARGS__)
#define sprintf(...)	pg_sprintf(__VA_ARGS__)
#define stat(a,b) pgwin32_safestat(a,b)
#define symlink(oldpath, newpath)	pgsymlink(oldpath, newpath)
#define system(a) pgwin32_system(a)
#define unlink(path)			pgunlink(path)
#define vfprintf(...)	pg_vfprintf(__VA_ARGS__)
#define vsnprintf(...)	pg_vsnprintf(__VA_ARGS__)
#define OID_MAX  UINT_MAX
#define PG_DIAG_CONSTRAINT_NAME 'n'
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SEVERITY_NONLOCALIZED 'V'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

#define atooid(x) ((Oid) strtoul((x), NULL, 10))
