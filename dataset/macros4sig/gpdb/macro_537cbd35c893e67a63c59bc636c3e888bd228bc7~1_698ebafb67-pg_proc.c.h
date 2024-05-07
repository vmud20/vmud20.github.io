



#include<arpa/inet.h>


#include<math.h>


#include<libintl.h>

#include<stdio.h>

#include<float.h>


#include<locale.h>

#include<sys/stat.h>





#include<stdarg.h>

#include<ctype.h>

#include<pwd.h>




#include<setjmp.h>


#include<netdb.h>
#include<strings.h>
#include<netinet/in.h>







#include<stdlib.h>


#include<stddef.h>
#include<string.h>

#include<limits.h>


#include<errno.h>
#include<fcntl.h>


#include<assert.h>

#include<sys/types.h>
#include<stdint.h>


#include<sys/time.h>



#define GetSysCacheHashValue1(cacheId, key1) \
	GetSysCacheHashValue(cacheId, key1, 0, 0, 0)
#define GetSysCacheHashValue2(cacheId, key1, key2) \
	GetSysCacheHashValue(cacheId, key1, key2, 0, 0)
#define GetSysCacheHashValue3(cacheId, key1, key2, key3) \
	GetSysCacheHashValue(cacheId, key1, key2, key3, 0)
#define GetSysCacheHashValue4(cacheId, key1, key2, key3, key4) \
	GetSysCacheHashValue(cacheId, key1, key2, key3, key4)
#define GetSysCacheOid1(cacheId, key1) \
	GetSysCacheOid(cacheId, key1, 0, 0, 0)
#define GetSysCacheOid2(cacheId, key1, key2) \
	GetSysCacheOid(cacheId, key1, key2, 0, 0)
#define GetSysCacheOid3(cacheId, key1, key2, key3) \
	GetSysCacheOid(cacheId, key1, key2, key3, 0)
#define GetSysCacheOid4(cacheId, key1, key2, key3, key4) \
	GetSysCacheOid(cacheId, key1, key2, key3, key4)
#define ReleaseSysCacheList(x)	ReleaseCatCacheList(x)

#define SearchSysCache1(cacheId, key1) \
	SearchSysCache(cacheId, key1, 0, 0, 0)
#define SearchSysCache2(cacheId, key1, key2) \
	SearchSysCache(cacheId, key1, key2, 0, 0)
#define SearchSysCache3(cacheId, key1, key2, key3) \
	SearchSysCache(cacheId, key1, key2, key3, 0)
#define SearchSysCache4(cacheId, key1, key2, key3, key4) \
	SearchSysCache(cacheId, key1, key2, key3, key4)
#define SearchSysCacheCopy1(cacheId, key1) \
	SearchSysCacheCopy(cacheId, key1, 0, 0, 0)
#define SearchSysCacheCopy2(cacheId, key1, key2) \
	SearchSysCacheCopy(cacheId, key1, key2, 0, 0)
#define SearchSysCacheCopy3(cacheId, key1, key2, key3) \
	SearchSysCacheCopy(cacheId, key1, key2, key3, 0)
#define SearchSysCacheCopy4(cacheId, key1, key2, key3, key4) \
	SearchSysCacheCopy(cacheId, key1, key2, key3, key4)
#define SearchSysCacheExists1(cacheId, key1) \
	SearchSysCacheExists(cacheId, key1, 0, 0, 0)
#define SearchSysCacheExists2(cacheId, key1, key2) \
	SearchSysCacheExists(cacheId, key1, key2, 0, 0)
#define SearchSysCacheExists3(cacheId, key1, key2, key3) \
	SearchSysCacheExists(cacheId, key1, key2, key3, 0)
#define SearchSysCacheExists4(cacheId, key1, key2, key3, key4) \
	SearchSysCacheExists(cacheId, key1, key2, key3, key4)
#define SearchSysCacheList1(cacheId, key1) \
	SearchSysCacheList(cacheId, 1, key1, 0, 0, 0)
#define SearchSysCacheList2(cacheId, key1, key2) \
	SearchSysCacheList(cacheId, 2, key1, key2, 0, 0)
#define SearchSysCacheList3(cacheId, key1, key2, key3) \
	SearchSysCacheList(cacheId, 3, key1, key2, key3, 0)
#define SearchSysCacheList4(cacheId, key1, key2, key3, key4) \
	SearchSysCacheList(cacheId, 4, key1, key2, key3, key4)

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
	BlockIdGetBlockNumber(&(pointer)->ip_blkid) \
)
#define ItemPointerGetOffsetNumber(pointer) \
( \
	AssertMacro(ItemPointerIsValid(pointer)), \
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
	 ((StdRdOptions *) (relation)->rd_options)->check_option_offset != 0 ?	\
	 strcmp((char *) (relation)->rd_options +								\
			((StdRdOptions *) (relation)->rd_options)->check_option_offset,	\
			"cascaded") == 0 : false)
#define RelationHasCheckOption(relation)									\
	((relation)->rd_options &&												\
	 ((StdRdOptions *) (relation)->rd_options)->check_option_offset != 0)
#define RelationHasLocalCheckOption(relation)								\
	((relation)->rd_options &&												\
	 ((StdRdOptions *) (relation)->rd_options)->check_option_offset != 0 ?	\
	 strcmp((char *) (relation)->rd_options +								\
			((StdRdOptions *) (relation)->rd_options)->check_option_offset,	\
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
	 ((StdRdOptions *) (relation)->rd_options)->security_barrier : false)
#define RelationIsUsedAsCatalogTable(relation)	\
	((relation)->rd_options ?				\
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
#define ATTRIBUTE_FIXED_PART_SIZE \
	(offsetof(FormData_pg_attribute,attcollation) + sizeof(Oid))
#define Anum_pg_attribute_attfdwoptions 21
#define Anum_pg_attribute_attstattarget 4
#define AttributeRelationId  1249
#define AttributeRelation_Rowtype_Id  75






#define CATALOG(name,oid)	typedef struct CppConcat(FormData_,name)
#define DATA(x)   extern int no_such_variable
#define DESCR(x)  extern int no_such_variable

#define SHDESCR(x) extern int no_such_variable

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
#define IndexIsLive(indexForm)	((indexForm)->indislive)
#define IndexIsReady(indexForm) ((indexForm)->indisready)
#define IndexIsValid(indexForm) ((indexForm)->indisvalid)
#define IndexRelationId  2610

#define CLASS_TUPLE_SIZE \
	 (offsetof(FormData_pg_class,relminmxid) + sizeof(TransactionId))

#define		  RELKIND_COMPOSITE_TYPE  'c'		
#define		  RELKIND_FOREIGN_TABLE   'f'		
#define RelationRelation_Rowtype_Id  83
#define BTREE_AM_OID 403
#define GIN_AM_OID 2742
#define GIST_AM_OID 783
#define HASH_AM_OID 405

#define SPGIST_AM_OID 4000

#define TypeIsToastable(typid)	(get_typstorage(typid) != 'p')
#define type_is_array(typid)  (get_element_type(typid) != InvalidOid)
#define type_is_array_domain(typid)  (get_base_element_type(typid) != InvalidOid)

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
#define IS_SPECIAL_VARNO(varno)		((varno) >= INNER_VAR)

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
#define PG_GETARG_ARRAYTYPE_P(n)	  DatumGetArrayTypeP(PG_GETARG_DATUM(n))
#define PG_GETARG_ARRAYTYPE_P_COPY(n) DatumGetArrayTypePCopy(PG_GETARG_DATUM(n))
#define PG_RETURN_ARRAYTYPE_P(x)	  PG_RETURN_POINTER(x)
#define STACK_DEPTH_SLOP (512 * 1024L)


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


#define RowMarkRequiresRowShareLock(marktype)  ((marktype) <= ROW_MARK_KEYSHARE)
#define exec_subplan_get_plan(plannedstmt, subplan) \
	((Plan *) list_nth((plannedstmt)->subplans, (subplan)->plan_id - 1))
#define innerPlan(node)			(((Plan *)(node))->righttree)
#define outerPlan(node)			(((Plan *)(node))->lefttree)

#define ScanDirectionIsBackward(direction) \
	((bool) ((direction) == BackwardScanDirection))
#define ScanDirectionIsForward(direction) \
	((bool) ((direction) == ForwardScanDirection))
#define ScanDirectionIsNoMovement(direction) \
	((bool) ((direction) == NoMovementScanDirection))
#define ScanDirectionIsValid(direction) \
	((bool) (BackwardScanDirection <= (direction) && \
			 (direction) <= ForwardScanDirection))



#define PortalGetHeapMemory(portal) ((portal)->heap)
#define PortalGetPrimaryStmt(portal) PortalListGetPrimaryStmt((portal)->stmts)
#define PortalGetQueryDesc(portal)	((portal)->queryDesc)
#define PortalIsValid(p) PointerIsValid(p)




#define InitTupleHashIterator(htable, iter) \
	hash_seq_init(iter, (htable)->hashtab)
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
	do { \
		hash_freeze((htable)->hashtab); \
		hash_seq_init(iter, (htable)->hashtab); \
	} while (0)
#define ScanTupleHashTable(iter) \
	((TupleHashEntry) hash_seq_search(iter))
#define TermTupleHashIterator(iter) \
	hash_seq_term(iter)
#define innerPlanState(node)		(((PlanState *)(node))->righttree)
#define outerPlanState(node)		(((PlanState *)(node))->lefttree)

#define tuplestore_donestoring(state)	((void) 0)


#define INSTR_TIME_ACCUM_DIFF(x,y,z) \
	((x).QuadPart += (y).QuadPart - (z).QuadPart)
#define INSTR_TIME_ADD(x,y) \
	((x).QuadPart += (y).QuadPart)
#define INSTR_TIME_GET_DOUBLE(t) \
	(((double) (t).tv_sec) + ((double) (t).tv_usec) / 1000000.0)
#define INSTR_TIME_GET_MICROSEC(t) \
	(((uint64) (t).tv_sec * (uint64) 1000000) + (uint64) (t).tv_usec)
#define INSTR_TIME_GET_MILLISEC(t) \
	(((double) (t).tv_sec * 1000.0) + ((double) (t).tv_usec) / 1000.0)

#define INSTR_TIME_IS_ZERO(t)	((t).QuadPart == 0)
#define INSTR_TIME_SET_CURRENT(t)	QueryPerformanceCounter(&(t))
#define INSTR_TIME_SET_ZERO(t)	((t).QuadPart = 0)
#define INSTR_TIME_SUBTRACT(x,y) \
	((x).QuadPart -= (y).QuadPart)

#define HeapScanIsValid(scan) PointerIsValid(scan)
#define heap_close(r,l)  relation_close(r,l)
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
#define ShareUpdateExclusiveLock 4		
#define VirtualTransactionIdEquals(vxid1, vxid2) \
	((vxid1).backendId == (vxid2).backendId && \
	 (vxid1).localTransactionId == (vxid2).localTransactionId)
#define VirtualTransactionIdIsValid(vxid) \
	(((vxid).backendId != InvalidBackendId) && \
	 LocalTransactionIdIsValid((vxid).localTransactionId))

#define HASH_FIXED_SIZE 0x1000	
#define HASH_SHARED_MEM 0x040	

#define LOG2_NUM_LOCK_PARTITIONS  4
#define LOG2_NUM_PREDICATELOCK_PARTITIONS  4

#define NUM_BUFFER_PARTITIONS  16
#define NUM_FIXED_LWLOCKS \
	(PREDICATELOCK_MANAGER_LWLOCK_OFFSET + NUM_PREDICATELOCK_PARTITIONS)
#define NUM_LOCK_PARTITIONS  (1 << LOG2_NUM_LOCK_PARTITIONS)
#define NUM_PREDICATELOCK_PARTITIONS  (1 << LOG2_NUM_PREDICATELOCK_PARTITIONS)
#define DEFAULT_SPINS_PER_DELAY  100

#define SPIN_DELAY() spin_delay()
#define S_INIT_LOCK(lock)  (*(lock) = 0)
#define S_LOCK(lock) \
	(TAS(lock) ? s_lock((lock), "__FILE__", "__LINE__") : 0)
#define S_LOCK_FREE(lock)	(*TAS_ACTIVE_WORD(lock) != 0)

#define S_UNLOCK(lock) __sync_lock_release(lock)
#define TAS(lock) tas(lock)
#define TAS_ACTIVE_WORD(lock)	((volatile int *) (((uintptr_t) (lock) + 15) & ~15))
#define TAS_SPIN(lock)    (*(lock) ? 1 : TAS(lock))

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
	AssertMacro(PageIsValid(page)), \
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


#define XLogRecPtrIsInvalid(r)	((r) == InvalidXLogRecPtr)
#define InvalidStrategy ((StrategyNumber) 0)


#define IndexScanIsValid(scan) PointerIsValid(scan)


#define IS_VALID_JULIAN(y,m,d) \
	(((y) > JULIAN_MINYEAR \
	  || ((y) == JULIAN_MINYEAR && \
		  ((m) > JULIAN_MINMONTH \
		   || ((m) == JULIAN_MINMONTH && (d) >= JULIAN_MINDAY)))) \
	 && (y) < JULIAN_MAXYEAR)
#define JULIAN_MAX (2147483494) 
#define JULIAN_MAXYEAR (5874898)
#define JULIAN_MINDAY (24)
#define JULIAN_MINMONTH (11)
#define JULIAN_MINYEAR (-4713)
#define MAX_INTERVAL_PRECISION 6
#define MAX_TIMESTAMP_PRECISION 6
#define MONTHS_PER_YEAR 12
#define SECS_PER_MINUTE 60
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
#define ISCOMPLEX(typeid) (typeidTypeRelid(typeid) != InvalidOid)



#define AmBackgroundWriterProcess() (MyAuxProcType == BgWriterProcess)
#define AmBootstrapProcess()		(MyAuxProcType == BootstrapProcess)
#define AmCheckpointerProcess()		(MyAuxProcType == CheckpointerProcess)
#define AmStartupProcess()			(MyAuxProcType == StartupProcess)
#define AmWalReceiverProcess()		(MyAuxProcType == WalReceiverProcess)
#define AmWalWriterProcess()		(MyAuxProcType == WalWriterProcess)
#define CHECK_FOR_INTERRUPTS() \
do { \
	if (InterruptPending) \
		ProcessInterrupts(); \
} while(0)
#define END_CRIT_SECTION() \
do { \
	Assert(CritSectionCount > 0); \
	CritSectionCount--; \
} while(0)
#define GetProcessingMode() Mode
#define HOLD_INTERRUPTS()  (InterruptHoldoffCount++)
#define IsBootstrapProcessingMode() (Mode == BootstrapProcessing)
#define IsInitProcessingMode()		(Mode == InitProcessing)
#define IsNormalProcessingMode()	(Mode == NormalProcessing)

#define PG_BACKEND_VERSIONSTR "postgres (PostgreSQL) " PG_VERSION "\n"
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

#define HeapTupleGetDatum(_tuple)		PointerGetDatum((_tuple)->t_data)
#define SRF_FIRSTCALL_INIT() init_MultiFuncCall(fcinfo)
#define SRF_IS_FIRSTCALL() (fcinfo->flinfo->fn_extra == NULL)
#define SRF_PERCALL_SETUP() per_MultiFuncCall(fcinfo)
#define  SRF_RETURN_DONE(_funcctx) \
	do { \
		ReturnSetInfo	   *rsi; \
		end_MultiFuncCall(fcinfo, _funcctx); \
		rsi = (ReturnSetInfo *) fcinfo->resultinfo; \
		rsi->isDone = ExprEndResult; \
		PG_RETURN_NULL(); \
	} while (0)
#define SRF_RETURN_NEXT(_funcctx, _result) \
	do { \
		ReturnSetInfo	   *rsi; \
		(_funcctx)->call_cntr++; \
		rsi = (ReturnSetInfo *) fcinfo->resultinfo; \
		rsi->isDone = ExprMultipleResult; \
		PG_RETURN_DATUM(_result); \
	} while (0)
#define TupleGetDatum(_slot, _tuple)	PointerGetDatum((_tuple)->t_data)

#define EXEC_FLAG_SKIP_TRIGGERS 0x0010	
#define EvalPlanQualSetSlot(epqstate, slot)  ((epqstate)->origslot = (slot))
#define ExecEvalExpr(expr, econtext, isNull, isDone) \
	((*(expr)->evalfunc) (expr, econtext, isNull, isDone))
#define GetPerTupleExprContext(estate) \
	((estate)->es_per_tuple_exprcontext ? \
	 (estate)->es_per_tuple_exprcontext : \
	 MakePerTupleExprContext(estate))
#define GetPerTupleMemoryContext(estate) \
	(GetPerTupleExprContext(estate)->ecxt_per_tuple_memory)
#define ResetExprContext(econtext) \
	MemoryContextReset((econtext)->ecxt_per_tuple_memory)
#define ResetPerTupleExprContext(estate) \
	do { \
		if ((estate)->es_per_tuple_exprcontext) \
			ResetExprContext((estate)->es_per_tuple_exprcontext); \
	} while (0)
#define do_text_output_oneline(tstate, str_to_emit) \
	do { \
		Datum	values_[1]; \
		bool	isnull_[1]; \
		values_[0] = PointerGetDatum(cstring_to_text(str_to_emit)); \
		isnull_[0] = false; \
		do_tup_output(tstate, values_, isnull_); \
		pfree(DatumGetPointer(values_[0])); \
	} while (0)

#define CASHOID 790
#define CIDOID 29
#define CIDROID 650
#define FLOAT4ARRAYOID 1021
#define FLOAT4OID 700
#define FLOAT8OID 701
#define INETOID 869
#define IsPolymorphicType(typid)  \
	((typid) == ANYELEMENTOID || \
	 (typid) == ANYARRAYOID || \
	 (typid) == ANYNONARRAYOID || \
	 (typid) == ANYENUMOID || \
	 (typid) == ANYRANGEOID)
#define JSONOID 114
#define MACADDROID 829

#define REGPROCEDUREOID 2202
#define REGTYPEARRAYOID 2211
#define  TYPCATEGORY_PSEUDOTYPE 'P'
#define TypeRelation_Rowtype_Id  71
#define UUIDOID 2950
#define XIDOID 28
#define XMLOID 142


#define PROARGMODE_VARIADIC 'v'
#define ProcedureRelationId  1255
#define ProcedureRelation_Rowtype_Id  81
#define NamespaceRelationId  2615
#define PG_CATALOG_NAMESPACE 11

#define PG_PUBLIC_NAMESPACE 2200
#define PG_TOAST_NAMESPACE 99
#define ClanguageId 13
#define INTERNALlanguageId 12

#define SQLlanguageId 14
#define InvokeFunctionExecuteHook(objectId)		\
	do {										\
		if (object_access_hook)					\
			RunFunctionExecuteHook(objectId);	\
	} while(0)
#define InvokeNamespaceSearchHook(objectId, ereport_on_violation)	\
	(!object_access_hook											\
	 ? true															\
	 : RunNamespaceSearchHook((objectId), (ereport_on_violation)))
#define InvokeObjectDropHook(classId,objectId,subId)				\
	InvokeObjectDropHookArg((classId),(objectId),(subId),0)
#define InvokeObjectDropHookArg(classId,objectId,subId,dropflags)	\
	do {															\
		if (object_access_hook)										\
			RunObjectDropHook((classId),(objectId),(subId),			\
							  (dropflags));							\
	} while(0)
#define InvokeObjectPostAlterHook(classId,objectId,subId)			\
	InvokeObjectPostAlterHookArg((classId),(objectId),(subId),		\
								 InvalidOid,false)
#define InvokeObjectPostAlterHookArg(classId,objectId,subId,		\
									 auxiliaryId,is_internal)		\
	do {															\
		if (object_access_hook)										\
			RunObjectPostAlterHook((classId),(objectId),(subId),	\
								   (auxiliaryId),(is_internal));	\
	} while(0)
#define InvokeObjectPostCreateHook(classId,objectId,subId)			\
	InvokeObjectPostCreateHookArg((classId),(objectId),(subId),false)
#define InvokeObjectPostCreateHookArg(classId,objectId,subId,is_internal) \
	do {															\
		if (object_access_hook)										\
			RunObjectPostCreateHook((classId),(objectId),(subId),	\
									(is_internal));					\
	} while(0)

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
#define RewriteOidIndexId  2692
#define RewriteRelRulenameIndexId  2693
#define SharedDescriptionObjIndexId 2397
#define TablespaceNameIndexId  2698
#define TablespaceOidIndexId  2697
#define TriggerConstraintIndexId  2699
#define TriggerOidIndexId  2702
#define TriggerRelidNameIndexId  2701


#define IsolationIsSerializable() (XactIsoLevel == XACT_SERIALIZABLE)
#define IsolationUsesXactSnapshot() (XactIsoLevel >= XACT_REPEATABLE_READ)
#define MinSizeOfXactAbort offsetof(xl_xact_abort, xnodes)
#define MinSizeOfXactAbortPrepared offsetof(xl_xact_abort_prepared, arec.xnodes)
#define MinSizeOfXactAssignment offsetof(xl_xact_assignment, xsub)
#define MinSizeOfXactCommit offsetof(xl_xact_commit, xnodes)
#define MinSizeOfXactCommitCompact offsetof(xl_xact_commit_compact, subxacts)
#define MinSizeOfXactCommitPrepared offsetof(xl_xact_commit_prepared, crec.xnodes)

#define XactCompletionForceSyncCommit(xinfo)		(xinfo & XACT_COMPLETION_FORCE_SYNC_COMMIT)
#define XactCompletionRelcacheInitFileInval(xinfo)	(xinfo & XACT_COMPLETION_UPDATE_RELCACHE_FILE)
#define InHotStandby (standbyState >= STANDBY_SNAPSHOT_PENDING)

#define XLR_BKP_BLOCK(iblk)		(0x08 >> (iblk))		
#define XLogArchiveCommandSet() (XLogArchiveCommand[0] != '\0')
#define XLogArchivingActive()	(XLogArchiveMode && wal_level >= WAL_LEVEL_ARCHIVE)
#define XLogHintBitIsNeeded() (DataChecksumsEnabled() || wal_log_hints)
#define XLogIsNeeded() (wal_level >= WAL_LEVEL_ARCHIVE)
#define XLogLogicalInfoActive() (wal_level >= WAL_LEVEL_LOGICAL)
#define XLogRecGetData(record)	((char*) (record) + SizeOfXLogRecord)
#define XLogStandbyInfoActive() (wal_level >= WAL_LEVEL_HOT_STANDBY)
#define COMP_CRC32(crc, data, len)	\
do { \
	const unsigned char *__data = (const unsigned char *) (data); \
	uint32		__len = (len); \
\
	while (__len-- > 0) \
	{ \
		int		__tab_index = ((int) ((crc) >> 24) ^ *__data++) & 0xFF; \
		(crc) = pg_crc32_table[__tab_index] ^ ((crc) << 8); \
	} \
} while (0)
#define COMP_CRC64(crc, data, len)	\
do { \
	uint64		__crc0 = (crc).crc0; \
	unsigned char *__data = (unsigned char *) (data); \
	uint32		__len = (len); \
\
	while (__len-- > 0) \
	{ \
		int		__tab_index = ((int) (__crc0 >> 56) ^ *__data++) & 0xFF; \
		__crc0 = pg_crc64_table[__tab_index] ^ (__crc0 << 8); \
	} \
	(crc).crc0 = __crc0; \
} while (0)
#define CRCDLLIMPORT PGDLLIMPORT
#define EQ_CRC32(c1,c2)  ((c1) == (c2))
#define EQ_CRC64(c1,c2)  ((c1).crc0 == (c2).crc0 && (c1).crc1 == (c2).crc1)
#define FIN_CRC32(crc)	((crc) ^= 0xFFFFFFFF)
#define FIN_CRC64(crc)	((crc).crc0 ^= UINT64CONST(0xffffffffffffffff))
#define INIT_CRC32(crc) ((crc) = 0xFFFFFFFF)
#define INIT_CRC64(crc) ((crc).crc0 = UINT64CONST(0xffffffffffffffff))


#define appendStringInfoCharMacro(str,ch) \
	(((str)->len + 1 >= (str)->maxlen) ? \
	 appendStringInfoChar(str, ch) : \
	 (void)((str)->data[(str)->len] = (ch), (str)->data[++(str)->len] = '\0'))
#define PG_RMGR(symname,name,redo,desc,startup,cleanup,restartpoint) \
	symname,

#define BITMAPLEN(NATTS)	(((int)(NATTS) + 7) / 8)
#define GETSTRUCT(TUP) ((char *) ((TUP)->t_data) + (TUP)->t_data->t_hoff)
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
#define HeapTupleGetOid(tuple) \
		HeapTupleHeaderGetOid((tuple)->t_data)
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
#define HeapTupleHeaderGetOid(tup) \
( \
	((tup)->t_infomask & HEAP_HASOID) ? \
		*((Oid *) ((char *)(tup) + (tup)->t_hoff - sizeof(Oid))) \
	: \
		InvalidOid \
)
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
#define HeapTupleHeaderHasMatch(tup) \
( \
  (tup)->t_infomask2 & HEAP_TUPLE_HAS_MATCH \
)
#define HeapTupleHeaderIsHeapOnly(tup) \
( \
  (tup)->t_infomask2 & HEAP_ONLY_TUPLE \
)
#define HeapTupleHeaderIsHotUpdated(tup) \
( \
	((tup)->t_infomask2 & HEAP_HOT_UPDATED) != 0 && \
	((tup)->t_infomask & HEAP_XMAX_INVALID) == 0 && \
	!HeapTupleHeaderXminInvalid(tup) \
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
#define HeapTupleHeaderSetNatts(tup, natts) \
( \
	(tup)->t_infomask2 = ((tup)->t_infomask2 & ~HEAP_NATTS_MASK) | (natts) \
)
#define HeapTupleHeaderSetOid(tup, oid) \
do { \
	Assert((tup)->t_infomask & HEAP_HASOID); \
	*((Oid *) ((char *)(tup) + (tup)->t_hoff - sizeof(Oid))) = (oid); \
} while (0)
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
	(tup)->t_infomask & HEAP_XMIN_COMMITTED \
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
#define HeapTupleSetOid(tuple, oid) \
		HeapTupleHeaderSetOid((tuple)->t_data, (oid))
#define MINIMAL_TUPLE_DATA_OFFSET \
	offsetof(MinimalTupleData, t_infomask2)
#define MINIMAL_TUPLE_OFFSET \
	((offsetof(HeapTupleHeaderData, t_infomask2) - sizeof(uint32)) / MAXIMUM_ALIGNOF * MAXIMUM_ALIGNOF)
#define MINIMAL_TUPLE_PADDING \
	((offsetof(HeapTupleHeaderData, t_infomask2) - sizeof(uint32)) % MAXIMUM_ALIGNOF)
#define MaxHeapTupleSize  (BLCKSZ - MAXALIGN(SizeOfPageHeaderData + sizeof(ItemIdData)))
#define MaxTupleAttributeNumber 1664	
#define fastgetattr(tup, attnum, tupleDesc, isnull)					\
(																	\
	AssertMacro((attnum) > 0),										\
	(*(isnull) = false),											\
	HeapTupleNoNulls(tup) ?											\
	(																\
		(tupleDesc)->attrs[(attnum)-1]->attcacheoff >= 0 ?			\
		(															\
			fetchatt((tupleDesc)->attrs[(attnum)-1],				\
				(char *) (tup)->t_data + (tup)->t_data->t_hoff +	\
					(tupleDesc)->attrs[(attnum)-1]->attcacheoff)	\
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
			( \
				(*(isnull) = true), \
				(Datum)NULL \
			) \
			: \
				fastgetattr((tup), (attnum), (tupleDesc), (isnull)) \
		) \
		: \
			heap_getsysattr((tup), (attnum), (tupleDesc), (isnull)) \
	)
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

