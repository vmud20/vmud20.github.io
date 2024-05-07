#include<locale.h>

#include<netinet/in.h>


#include<float.h>












#include<stddef.h>


#include<errno.h>


#include<limits.h>


#include<stdlib.h>
#include<unistd.h>
#include<math.h>

#include<sys/types.h>



#include<ctype.h>
#include<fcntl.h>
#include<strings.h>

#include<libintl.h>

#include<netdb.h>

#include<stdarg.h>
#include<stdio.h>

#include<time.h>






#include<string.h>




#include<pwd.h>


#include<setjmp.h>
#include<arpa/inet.h>




#define TupIsNull(slot) \
	((slot) == NULL || (slot)->tts_isempty)

#define BufferIsInvalid(buffer) ((buffer) == InvalidBuffer)
#define BufferIsLocal(buffer)	((buffer) < 0)
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
#define freeList(list)				list_free(list)
#define intMember(datum, list)		list_member_int(list, datum)
#define lappend_xid(list, datum)	lappend_oid(list, (Oid) (datum))
#define lappendi(list, datum)		lappend_int(list, datum)
#define lappendo(list, datum)		lappend_oid(list, datum)
#define lconsi(datum, list)			lcons_int(datum, list)
#define lconso(datum, list)			lcons_oid(datum, list)
#define lfirst(lc)				((lc)->data.ptr_value)
#define lfirst_int(lc)			((lc)->data.int_value)
#define lfirst_oid(lc)			((lc)->data.oid_value)
#define lfirst_xid(lc)				((TransactionId) lfirst_oid(lc))
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
	((jointype) == JOIN_LEFT || \
	 (jointype) == JOIN_FULL || \
	 (jointype) == JOIN_RIGHT)
#define IsA(nodeptr,_type_)		(nodeTag(nodeptr) == T_##_type_)

#define NodeSetTag(nodeptr,t)	(((Node*)(nodeptr))->type = (t))
#define makeNode(_type_)		((_type_ *) newNode(sizeof(_type_),T_##_type_))
#define newNode(size, tag) \
( \
	AssertMacro((size) >= sizeof(Node)),		 \
	newNodeMacroHolder = (Node *) palloc0fast(size), \
	newNodeMacroHolder->type = (tag), \
	newNodeMacroHolder \
)
#define nodeTag(nodeptr)		(((Node*)(nodeptr))->type)
#define ATTRIBUTE_TUPLE_SIZE \
	(offsetof(FormData_pg_attribute,attinhcount) + sizeof(int4))
#define Anum_pg_attribute_attstattarget 4
#define AttributeRelationId  1249

#define Schema_pg_attribute \
{ 1249, {"attrelid",	  26, -1,	4,	1, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"attname",	  19, -1, NAMEDATALEN,	2, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"atttypid",	  26, -1,	4,	3, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"attstattarget", 23, -1,	4,	4, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"attlen",		  21, -1,	2,	5, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1249, {"attnum",		  21, -1,	2,	6, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1249, {"attndims",	  23, -1,	4,	7, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"attcacheoff",  23, -1,	4,	8, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"atttypmod",	  23, -1,	4,	9, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1249, {"attbyval",	  16, -1,	1, 10, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"attstorage",   18, -1,	1, 11, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"attalign",	  18, -1,	1, 12, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"attnotnull",   16, -1,	1, 13, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"atthasdef",	  16, -1,	1, 14, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"attisdropped", 16, -1,	1, 15, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"attislocal",   16, -1,	1, 16, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1249, {"attinhcount",  23, -1,	4, 17, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }
#define Schema_pg_class \
{ 1259, {"relname",	   19, -1, NAMEDATALEN, 1, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relnamespace",  26, -1,	4,	2, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"reltype",	   26, -1,	4,	3, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relowner",	   26, -1,	4,	4, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relam",		   26, -1,	4,	5, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relfilenode",   26, -1,	4,	6, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"reltablespace", 26, -1,	4,	7, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relpages",	   23, -1,	4,	8, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"reltuples",	   700, -1, 4,	9, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"reltoastrelid", 26, -1,	4, 10, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"reltoastidxid", 26, -1,	4, 11, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relhasindex",   16, -1,	1, 12, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relisshared",   16, -1,	1, 13, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relkind",	   18, -1,	1, 14, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relnatts",	   21, -1,	2, 15, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1259, {"relchecks",	   21, -1,	2, 16, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1259, {"reltriggers",   21, -1,	2, 17, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1259, {"relukeys",	   21, -1,	2, 18, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1259, {"relfkeys",	   21, -1,	2, 19, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1259, {"relrefs",	   21, -1,	2, 20, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1259, {"relhasoids",    16, -1,	1, 21, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relhaspkey",    16, -1,	1, 22, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relhasrules",   16, -1,	1, 23, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relhassubclass",16, -1,	1, 24, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1259, {"relfrozenxid",  28, -1,	4, 25, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1259, {"relacl",		 1034, -1, -1, 26, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1259, {"reloptions",  1009, -1, -1, 27, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }
#define Schema_pg_index \
{ 0, {"indexrelid",		26, -1, 4, 1, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 0, {"indrelid",			26, -1, 4, 2, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 0, {"indnatts",			21, -1, 2, 3, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 0, {"indisunique",		16, -1, 1, 4, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 0, {"indisprimary",		16, -1, 1, 5, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 0, {"indisclustered",	16, -1, 1, 6, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 0, {"indisvalid",		16, -1, 1, 7, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 0, {"indcheckxmin",		16, -1, 1, 8, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 0, {"indisready",		16, -1, 1, 9, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 0, {"indkey",			22, -1, -1, 10, 1, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 0, {"indclass",			30, -1, -1, 11, 1, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 0, {"indoption",			22, -1, -1, 12, 1, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 0, {"indexprs",			25, -1, -1, 13, 0, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 0, {"indpred",			25, -1, -1, 14, 0, -1, -1, false, 'x', 'i', false, false, false, true, 0 }
#define Schema_pg_proc \
{ 1255, {"proname",			19, -1, NAMEDATALEN,  1, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"pronamespace",		26, -1, 4,	2, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"proowner",			26, -1, 4,	3, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"prolang",			26, -1, 4,	4, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"procost",		   700, -1, 4,	5, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"prorows",		   700, -1, 4,	6, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"proisagg",			16, -1, 1,	7, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1255, {"prosecdef",			16, -1, 1,	8, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1255, {"proisstrict",		16, -1, 1,	9, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1255, {"proretset",			16, -1, 1, 10, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1255, {"provolatile",		18, -1, 1, 11, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1255, {"pronargs",			21, -1, 2, 12, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1255, {"prorettype",			26, -1, 4, 13, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"proargtypes",		30, -1, -1, 14, 1, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1255, {"proallargtypes",   1028, -1, -1, 15, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1255, {"proargmodes",	  1002, -1, -1, 16, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1255, {"proargnames",	  1009, -1, -1, 17, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1255, {"prosrc",				25, -1, -1, 18, 0, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1255, {"probin",				17, -1, -1, 19, 0, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1255, {"proconfig",		  1009, -1, -1, 20, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1255, {"proacl",			  1034, -1, -1, 21, 1, -1, -1, false, 'x', 'i', false, false, false, true, 0 }
#define Schema_pg_type \
{ 1247, {"typname",	   19, -1, NAMEDATALEN, 1, 0, -1, -1, false, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typnamespace",  26, -1,	4,	2, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typowner",	   26, -1,	4,	3, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typlen",		   21, -1,	2,	4, 0, -1, -1, true, 'p', 's', true, false, false, true, 0 }, \
{ 1247, {"typbyval",	   16, -1,	1,	5, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typtype",	   18, -1,	1,	6, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typisdefined",  16, -1,	1,	7, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typdelim",	   18, -1,	1,	8, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typrelid",	   26, -1,	4,	9, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typelem",	   26, -1,	4, 10, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typarray",	   26, -1,	4, 11, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typinput",	   24, -1,	4, 12, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typoutput",	   24, -1,	4, 13, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typreceive",    24, -1,	4, 14, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typsend",	   24, -1,	4, 15, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typmodin",	   24, -1,	4, 16, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typmodout",	   24, -1,	4, 17, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typanalyze",    24, -1,	4, 18, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typalign",	   18, -1,	1, 19, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typstorage",    18, -1,	1, 20, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typnotnull",    16, -1,	1, 21, 0, -1, -1, true, 'p', 'c', true, false, false, true, 0 }, \
{ 1247, {"typbasetype",   26, -1,	4, 22, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typtypmod",	   23, -1,	4, 23, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typndims",	   23, -1,	4, 24, 0, -1, -1, true, 'p', 'i', true, false, false, true, 0 }, \
{ 1247, {"typdefaultbin", 25, -1, -1, 25, 0, -1, -1, false, 'x', 'i', false, false, false, true, 0 }, \
{ 1247, {"typdefault",    25, -1, -1, 26, 0, -1, -1, false, 'x', 'i', false, false, false, true, 0 }

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
#define BITMAPLEN(NATTS)	(((int)(NATTS) + 7) / 8)
#define GETSTRUCT(TUP) ((char *) ((TUP)->t_data) + (TUP)->t_data->t_hoff)
#define HEAP_MOVED (HEAP_MOVED_OFF | HEAP_MOVED_IN)

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
#define HeapTupleHeaderGetTypMod(tup) \
( \
	(tup)->t_choice.t_datum.datum_typmod \
)
#define HeapTupleHeaderGetTypeId(tup) \
( \
	(tup)->t_choice.t_datum.datum_typeid \
)
#define HeapTupleHeaderGetXmax(tup) \
( \
	(tup)->t_choice.t_heap.t_xmax \
)
#define HeapTupleHeaderGetXmin(tup) \
( \
	(tup)->t_choice.t_heap.t_xmin \
)
#define HeapTupleHeaderGetXvac(tup) \
( \
	((tup)->t_infomask & HEAP_MOVED) ? \
		(tup)->t_choice.t_heap.t_field3.t_xvac \
	: \
		InvalidTransactionId \
)
#define HeapTupleHeaderIsHeapOnly(tup) \
( \
  (tup)->t_infomask2 & HEAP_ONLY_TUPLE \
)
#define HeapTupleHeaderIsHotUpdated(tup) \
( \
	((tup)->t_infomask2 & HEAP_HOT_UPDATED) != 0 && \
	((tup)->t_infomask & (HEAP_XMIN_INVALID | HEAP_XMAX_INVALID)) == 0 \
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
#define HeapTupleHeaderSetXvac(tup, xid) \
do { \
	Assert((tup)->t_infomask & HEAP_MOVED); \
	(tup)->t_choice.t_heap.t_field3.t_xvac = (xid); \
} while (0)
#define HeapTupleIsHeapOnly(tuple) \
		HeapTupleHeaderIsHeapOnly((tuple)->t_data)
#define HeapTupleIsHotUpdated(tuple) \
		HeapTupleHeaderIsHotUpdated((tuple)->t_data)
#define HeapTupleIsValid(tuple) PointerIsValid(tuple)
#define HeapTupleNoNulls(tuple) \
		(!((tuple)->t_data->t_infomask & HEAP_HASNULL))
#define HeapTupleSetHeapOnly(tuple) \
		HeapTupleHeaderSetHeapOnly((tuple)->t_data)
#define HeapTupleSetHotUpdated(tuple) \
		HeapTupleHeaderSetHotUpdated((tuple)->t_data)
#define HeapTupleSetOid(tuple, oid) \
		HeapTupleHeaderSetOid((tuple)->t_data, (oid))
#define MINIMAL_TUPLE_OFFSET \
	((offsetof(HeapTupleHeaderData, t_infomask2) - sizeof(uint32)) / MAXIMUM_ALIGNOF * MAXIMUM_ALIGNOF)
#define MINIMAL_TUPLE_PADDING \
	((offsetof(HeapTupleHeaderData, t_infomask2) - sizeof(uint32)) % MAXIMUM_ALIGNOF)
#define MaxHeapTupleSize  (BLCKSZ - MAXALIGN(sizeof(PageHeaderData)))
#define MaxTupleAttributeNumber 1664	
#define SizeOfHeapClean (offsetof(xl_heap_clean, ndead) + sizeof(uint16))
#define SizeOfHeapFreeze (offsetof(xl_heap_freeze, cutoff_xid) + sizeof(TransactionId))

#define RelFileNodeEquals(node1, node2) \
	((node1).relNode == (node2).relNode && \
	 (node1).dbNode == (node2).dbNode && \
	 (node1).spcNode == (node2).spcNode)

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
#define index_getattr(tup, attnum, tupleDesc, isnull) \
( \
	AssertMacro(PointerIsValid(isnull) && (attnum) > 0), \
	*(isnull) = false, \
	!IndexTupleHasNulls(tup) ? \
	( \
		(tupleDesc)->attrs[(attnum)-1]->attcacheoff >= 0 ? \
		( \
			fetchatt((tupleDesc)->attrs[(attnum)-1], \
			(char *) (tup) + IndexInfoFindDataOffset((tup)->t_info) \
			+ (tupleDesc)->attrs[(attnum)-1]->attcacheoff) \
		) \
		: \
			nocache_index_getattr((tup), (attnum), (tupleDesc), (isnull)) \
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
			nocache_index_getattr((tup), (attnum), (tupleDesc), (isnull)) \
		) \
	) \
)

#define BufferGetPage(buffer) ((Page)BufferGetBlock(buffer))
#define BufferGetPageSize(buffer) \
( \
	AssertMacro(BufferIsValid(buffer)), \
	(Size)BLCKSZ \
)
#define PageClearFull(page) \
	(((PageHeader) (page))->pd_flags &= ~PD_PAGE_FULL)
#define PageClearHasFreeLinePointers(page) \
	(((PageHeader) (page))->pd_flags &= ~PD_HAS_FREE_LINES)
#define PageClearPrunable(page) \
	(((PageHeader) (page))->pd_prune_xid = InvalidTransactionId)
#define PageGetContents(page) \
	((char *) (&((PageHeader) (page))->pd_linp[0]))
#define PageGetItem(page, itemId) \
( \
	AssertMacro(PageIsValid(page)), \
	AssertMacro(ItemIdHasStorage(itemId)), \
	(Item)(((char *)(page)) + ItemIdGetOffset(itemId)) \
)
#define PageGetItemId(page, offsetNumber) \
	((ItemId) (&((PageHeader) (page))->pd_linp[(offsetNumber) - 1]))
#define PageGetLSN(page) \
	(((PageHeader) (page))->pd_lsn)
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
#define PageGetTLI(page) \
	(((PageHeader) (page))->pd_tli)
#define PageHasFreeLinePointers(page) \
	(((PageHeader) (page))->pd_flags & PD_HAS_FREE_LINES)
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
#define PageSetFull(page) \
	(((PageHeader) (page))->pd_flags |= PD_PAGE_FULL)
#define PageSetHasFreeLinePointers(page) \
	(((PageHeader) (page))->pd_flags |= PD_HAS_FREE_LINES)
#define PageSetLSN(page, lsn) \
	(((PageHeader) (page))->pd_lsn = (lsn))
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
#define PageSetTLI(page, tli) \
	(((PageHeader) (page))->pd_tli = (uint16) (tli))
#define PageSizeIsValid(pageSize) ((pageSize) == BLCKSZ)
#define SizeOfPageHeaderData (offsetof(PageHeaderData, pd_linp[0]))

#define XLR_SET_BKP_BLOCK(iblk) (0x08 >> (iblk))
#define XLogArchiveCommandSet() (XLogArchiveCommand[0] != '\0')
#define XLogArchivingActive()	(XLogArchiveMode)
#define XLogRecGetData(record)	((char*) (record) + SizeOfXLogRecord)
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
#define MAX_INTERVAL_PRECISION 6
#define MAX_TIMESTAMP_PRECISION 6
#define MONTHS_PER_YEAR 12
#define PG_GETARG_INTERVAL_P(n) DatumGetIntervalP(PG_GETARG_DATUM(n))
#define PG_GETARG_TIMESTAMP(n) PG_GETARG_INT64(n)
#define PG_GETARG_TIMESTAMPTZ(n) PG_GETARG_INT64(n)
#define PG_RETURN_INTERVAL_P(x) return IntervalPGetDatum(x)
#define PG_RETURN_TIMESTAMP(x) PG_RETURN_INT64(x)
#define PG_RETURN_TIMESTAMPTZ(x) PG_RETURN_INT64(x)
#define SECS_PER_MINUTE 60

#define TIMESTAMP_IS_NOBEGIN(j) ((j) == DT_NOBEGIN)
#define TIMESTAMP_IS_NOEND(j)	((j) == DT_NOEND)
#define TIMESTAMP_MASK(b) (1 << (b))
#define TIMESTAMP_NOBEGIN(j)	\
	do {(j) = DT_NOBEGIN;} while (0)
#define TIMESTAMP_NOEND(j)		\
	do {(j) = DT_NOEND;} while (0)
#define TIMESTAMP_NOT_FINITE(j) (TIMESTAMP_IS_NOBEGIN(j) || TIMESTAMP_IS_NOEND(j))
#define TSROUND(j) (rint(((double) (j)) * TS_PREC_INV) / TS_PREC_INV)
#define TS_PREC_INV 1000000.0
#define TimestampGetDatum(X) Int64GetDatum(X)
#define TimestampTzGetDatum(X) Int64GetDatum(X)
#define TimestampTzPlusMilliseconds(tz,ms) ((tz) + ((ms) * 1000))
#define USECS_PER_MINUTE INT64CONST(60000000)
#define timestamptz_cmp_internal(dt1,dt2)	timestamp_cmp_internal(dt1, dt2)

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

#define FunctionCallInvoke(fcinfo)	((* (fcinfo)->flinfo->fn_addr) (fcinfo))
#define InitFunctionCallInfoData(Fcinfo, Flinfo, Nargs, Context, Resultinfo) \
	do { \
		(Fcinfo).flinfo = (Flinfo); \
		(Fcinfo).context = (Context); \
		(Fcinfo).resultinfo = (Resultinfo); \
		(Fcinfo).isnull = false; \
		(Fcinfo).nargs = (Nargs); \
	} while (0)
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
extern PGDLLIMPORT const Pg_finfo_record * CppConcat(pg_finfo_,funcname)(void); \
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
#define PG_MAGIC_FUNCTION_NAME Pg_magic_func
#define PG_MAGIC_FUNCTION_NAME_STRING "Pg_magic_func"
#define PG_MODULE_MAGIC \
extern PGDLLIMPORT const Pg_magic_struct *PG_MAGIC_FUNCTION_NAME(void); \
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
	NAMEDATALEN \
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
#define TZ_STRLEN_MAX 255

#define COMP_CRC32(crc, data, len)	\
do { \
	unsigned char *__data = (unsigned char *) (data); \
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
#define DEFAULT_SYNC_METHOD_STR "open_datasync"
#define XLByteEQ(a, b)		\
			((a).xlogid == (b).xlogid && (a).xrecoff == (b).xrecoff)
#define XLByteLE(a, b)		\
			((a).xlogid < (b).xlogid || \
			 ((a).xlogid == (b).xlogid && (a).xrecoff <= (b).xrecoff))
#define XLByteLT(a, b)		\
			((a).xlogid < (b).xlogid || \
			 ((a).xlogid == (b).xlogid && (a).xrecoff < (b).xrecoff))

#define XLogRecPtrIsInvalid(r)	((r).xrecoff == 0)



#define BufferGetBlock(buffer) \
( \
	AssertMacro(BufferIsValid(buffer)), \
	BufferIsLocal(buffer) ? \
		LocalBufferBlockPointers[-(buffer) - 1] \
	: \
		(Block) (BufferBlocks + ((Size) ((buffer) - 1)) * BLCKSZ) \
)
#define BufferIsPinned(bufnum) \
( \
	!BufferIsValid(bufnum) ? \
		false \
	: \
		BufferIsLocal(bufnum) ? \
			(LocalRefCount[-(bufnum) - 1] > 0) \
		: \
			(PrivateRefCount[(bufnum) - 1] > 0) \
)
#define BufferIsValid(bufnum) \
( \
	(bufnum) != InvalidBuffer && \
	(bufnum) >= -NLocBuffer && \
	(bufnum) <= NBuffers \
)
#define InvalidRelation ((Relation) NULL)
#define RELATION_IS_LOCAL(relation) \
	((relation)->rd_istemp || \
	 (relation)->rd_createSubid != InvalidSubTransactionId)

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
#define RelationGetTargetPageFreeSpace(relation, defaultff) \
	(BLCKSZ * (100 - RelationGetFillFactor(relation, defaultff)) / 100)
#define RelationGetTargetPageUsage(relation, defaultff) \
	(BLCKSZ * RelationGetFillFactor(relation, defaultff) / 100)
#define RelationHasReferenceCountZero(relation) \
		((bool)((relation)->rd_refcnt == 0))
#define RelationIsValid(relation) PointerIsValid(relation)
#define RelationOpenSmgr(relation) \
	do { \
		if ((relation)->rd_smgr == NULL) \
			smgrsetowner(&((relation)->rd_smgr), smgropen((relation)->rd_node)); \
	} while (0)
#define TRIGGER_NUM_EVENT_CLASSES  3


#define BITS_PER_BITMAPWORD 32
#define IndexRelationId  2610

#define CLASS_TUPLE_SIZE \
	 (offsetof(FormData_pg_class,relfrozenxid) + sizeof(TransactionId))

#define		  RELKIND_COMPOSITE_TYPE  'c'		
#define BTREE_AM_OID 403
#define GIN_AM_OID 2742
#define GIST_AM_OID 783
#define HASH_AM_OID 405


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
	((attlen) == -1 && VARATT_IS_SHORT(DatumGetPointer(attdatum))) ? (long) (cur_offset) : \
	att_align_nominal(cur_offset, attalign) \
)
#define att_align_nominal(cur_offset, attalign) \
( \
	((attalign) == 'i') ? INTALIGN(cur_offset) : \
	 (((attalign) == 'c') ? (long) (cur_offset) : \
	  (((attalign) == 'd') ? DOUBLEALIGN(cur_offset) : \
	   ( \
			AssertMacro((attalign) == 's'), \
			SHORTALIGN(cur_offset) \
	   ))) \
)
#define att_align_pointer(cur_offset, attalign, attlen, attptr) \
( \
	((attlen) == -1 && VARATT_NOT_PAD_BYTE(attptr)) ? (long) (cur_offset) : \
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
#define ReleaseSysCacheList(x)	ReleaseCatCacheList(x)


#define CL_MAGIC   0x52765103
#define CT_MAGIC   0x57261502
#define DLE_VAL(elem)	((elem)->dle_val)
#define DLGetHead(list)  ((list)->dll_head)
#define DLGetListHdr(elem)	((elem)->dle_list)
#define DLGetPred(elem)  ((elem)->dle_prev)
#define DLGetSucc(elem)  ((elem)->dle_next)
#define DLGetTail(list)  ((list)->dll_tail)

#define InvalidStrategy ((StrategyNumber) 0)


#define ALLOCSET_DEFAULT_INITSIZE  (8 * 1024)
#define ALLOCSET_DEFAULT_MAXSIZE   (8 * 1024 * 1024)
#define ALLOCSET_DEFAULT_MINSIZE   0
#define ALLOCSET_SMALL_INITSIZE  (1 * 1024)
#define AllocSizeIsValid(size)	((Size) (size) <= MaxAllocSize)

#define STANDARDCHUNKHEADERSIZE  MAXALIGN(sizeof(StandardChunkHeader))

#define MemoryContextIsValid(context) \
	((context) != NULL && \
	 (IsA((context), AllocSetContext)))

#define TypeIsToastable(typid)	(get_typstorage(typid) != 'p')
#define type_is_array(typid)  (get_element_type(typid) != InvalidOid)


#define ACL_CREATE_TEMP (1<<10) 


#define floatVal(v)		atof(((Value *)(v))->val.str)
#define intVal(v)		(((Value *)(v))->val.ival)
#define strVal(v)		(((Value *)(v))->val.str)



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
	((LWLockId) (FirstLockMgrLock + LockHashPartition(hashcode)))
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
#define ShareUpdateExclusiveLock 4		
#define VirtualTransactionIdIsValid(vxid) \
	(((vxid).backendId != InvalidBackendId) && \
	 LocalTransactionIdIsValid((vxid).localTransactionId))
#define MAKE_OFFSET(xx_ptr)\
  ((SHMEM_OFFSET) (((unsigned long)(xx_ptr))-ShmemBase))
#define MAKE_PTR(xx_offs)\
  (ShmemBase+((unsigned long)(xx_offs)))

#define SHM_OFFSET_VALID(xx_offs)\
  (((xx_offs) != 0) && ((xx_offs) != INVALID_OFFSET))
#define SHM_PTR_VALID(xx_ptr)\
  (((unsigned long)(xx_ptr)) > ShmemBase)
#define HASH_SHARED_MEM 0x040	

#define LOG2_NUM_LOCK_PARTITIONS  4

#define NUM_BUFFER_PARTITIONS  16
#define NUM_LOCK_PARTITIONS  (1 << LOG2_NUM_LOCK_PARTITIONS)





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

#define is_funcclause(clause)	((clause) != NULL && IsA(clause, FuncExpr))
#define is_opclause(clause)		((clause) != NULL && IsA(clause, OpExpr))
#define is_subplan(clause)		((clause) != NULL && IsA(clause, SubPlan))
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
#define IsBootstrapProcessingMode() ((bool)(Mode == BootstrapProcessing))
#define IsInitProcessingMode() ((bool)(Mode == InitProcessing))
#define IsNormalProcessingMode() ((bool)(Mode == NormalProcessing))

#define PG_VERSIONSTR "postgres (PostgreSQL) " PG_VERSION "\n"
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
#define do_text_output_oneline(tstate, text_to_emit) \
	do { \
		char *values_[1]; \
		values_[0] = (text_to_emit); \
		do_tup_output(tstate, values_); \
	} while (0)



#define exec_subplan_get_plan(plannedstmt, subplan) \
	((Plan *) list_nth((plannedstmt)->subplans, (subplan)->plan_id - 1))
#define innerPlan(node)			(((Plan *)(node))->righttree)
#define outerPlan(node)			(((Plan *)(node))->lefttree)

#define InitTupleHashIterator(htable, iter) \
	hash_seq_init(iter, (htable)->hashtab)
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

#define HeapScanIsValid(scan) PointerIsValid(scan)
#define IndexScanIsValid(scan) PointerIsValid(scan)

#define HeapTupleSatisfiesVisibility(tuple, snapshot, buffer) \
	((*(snapshot)->satisfies) ((tuple)->t_data, snapshot, buffer))
#define InitDirtySnapshot(snapshotdata)  \
	((snapshotdata).satisfies = HeapTupleSatisfiesDirty)
#define IsMVCCSnapshot(snapshot)  \
	((snapshot)->satisfies == HeapTupleSatisfiesMVCC)

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
	 (typid) == ANYENUMOID)
#define MACADDROID 829
#define PG_ATTRIBUTE_RELTYPE_OID 75
#define PG_CLASS_RELTYPE_OID 83
#define PG_PROC_RELTYPE_OID 81

#define PG_TYPE_RELTYPE_OID 71
#define REGPROCEDUREOID 2202
#define REGTYPEARRAYOID 2211
#define XIDOID 28
#define XMLOID 142
#define DEFAULTTABLESPACE_OID 1663
#define GLOBALTABLESPACE_OID 1664

#define TableSpaceRelationId  1213
#define INT2_BTREE_OPS_OID 1979
#define INT4_BTREE_OPS_OID 1978
#define OID_BTREE_OPS_OID 1981
#define OperatorClassRelationId  2616

#define ARRAY_EQ_OP 1070
#define ARRAY_GT_OP 1073
#define ARRAY_LT_OP 1072
#define BooleanEqualOperator   91

#define TIDEqualOperator   387
#define TIDLessOperator    2799
#define ConstraintRelationId  2606

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
#define ConstraintNameNspIndexId  2664
#define ConstraintOidIndexId  2667
#define ConversionDefaultIndexId  2668
#define ConversionNameNspIndexId  2669
#define ConversionOidIndexId  2670
#define DECLARE_INDEX(name,oid,decl) extern int no_such_variable
#define DECLARE_UNIQUE_INDEX(name,oid,decl) extern int no_such_variable
#define DatabaseNameIndexId  2671
#define DependDependerIndexId  2673
#define DescriptionObjIndexId  2675
#define EnumTypIdLabelIndexId 3503

#define IndexIndrelidIndexId  2678
#define IndexRelidIndexId  2679
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
#define StatisticRelidAttnumIndexId  2696
#define TablespaceNameIndexId  2698
#define TablespaceOidIndexId  2697
#define TriggerConstrNameIndexId  2699
#define TriggerOidIndexId  2702
#define TriggerRelidNameIndexId  2701





#define MAXATTR 40
#define IsXactIsoLevelSerializable (XactIsoLevel >= XACT_REPEATABLE_READ)
#define MinSizeOfXactAbort offsetof(xl_xact_abort, xnodes)
#define MinSizeOfXactAbortPrepared offsetof(xl_xact_abort_prepared, arec.xnodes)
#define MinSizeOfXactCommit offsetof(xl_xact_commit, xnodes)
#define MinSizeOfXactCommitPrepared offsetof(xl_xact_commit_prepared, crec.xnodes)

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

#define fastgetattr(tup, attnum, tupleDesc, isnull)					\
(																	\
	AssertMacro((attnum) > 0),										\
	(((isnull) != NULL) ? (*(isnull) = false) : (dummyret)NULL),				\
	HeapTupleNoNulls(tup) ?											\
	(																\
		(tupleDesc)->attrs[(attnum)-1]->attcacheoff >= 0 ?			\
		(															\
			fetchatt((tupleDesc)->attrs[(attnum)-1],				\
				(char *) (tup)->t_data + (tup)->t_data->t_hoff +	\
					(tupleDesc)->attrs[(attnum)-1]->attcacheoff)	\
		)															\
		:															\
			nocachegetattr((tup), (attnum), (tupleDesc), (isnull))	\
	)																\
	:																\
	(																\
		att_isnull((attnum)-1, (tup)->t_data->t_bits) ?				\
		(															\
			(((isnull) != NULL) ? (*(isnull) = true) : (dummyret)NULL),		\
			(Datum)NULL												\
		)															\
		:															\
		(															\
			nocachegetattr((tup), (attnum), (tupleDesc), (isnull))	\
		)															\
	)																\
)
#define heap_close(r,l)  relation_close(r,l)
#define heap_getattr(tup, attnum, tupleDesc, isnull) \
( \
	AssertMacro((tup) != NULL), \
	( \
		((attnum) > 0) ? \
		( \
			((attnum) > (int) HeapTupleHeaderGetNatts((tup)->t_data)) ? \
			( \
				(((isnull) != NULL) ? (*(isnull) = true) : (dummyret)NULL), \
				(Datum)NULL \
			) \
			: \
				fastgetattr((tup), (attnum), (tupleDesc), (isnull)) \
		) \
		: \
			heap_getsysattr((tup), (attnum), (tupleDesc), (isnull)) \
	) \
)





#define AssertMacro(condition)	((void)true)




#define BoolGetDatum(X) ((Datum) ((X) ? 1 : 0))
#define CATALOG(name,oid)	typedef struct CppConcat(FormData_,name)
#define CStringGetDatum(X) PointerGetDatum(X)
#define CharGetDatum(X) ((Datum) SET_1_BYTE(X))
#define CommandIdGetDatum(X) ((Datum) SET_4_BYTES(X))
#define DATA(x)   extern int no_such_variable
#define DESCR(x)  extern int no_such_variable
#define DatumGetBool(X) ((bool) (((bool) (X)) != 0))
#define DatumGetCString(X) ((char *) DatumGetPointer(X))
#define DatumGetChar(X) ((char) GET_1_BYTE(X))
#define DatumGetCommandId(X) ((CommandId) GET_4_BYTES(X))
#define DatumGetFloat32(X) ((float32) DatumGetPointer(X))
#define DatumGetFloat4(X) (* ((float4 *) DatumGetPointer(X)))
#define DatumGetFloat64(X) ((float64) DatumGetPointer(X))
#define DatumGetFloat8(X) (* ((float8 *) DatumGetPointer(X)))
#define DatumGetInt16(X) ((int16) GET_2_BYTES(X))
#define DatumGetInt32(X) ((int32) GET_4_BYTES(X))
#define DatumGetInt64(X) (* ((int64 *) DatumGetPointer(X)))
#define DatumGetName(X) ((Name) DatumGetPointer(X))
#define DatumGetObjectId(X) ((Oid) GET_4_BYTES(X))
#define DatumGetPointer(X) ((Pointer) (X))
#define DatumGetTransactionId(X) ((TransactionId) GET_4_BYTES(X))
#define DatumGetUInt16(X) ((uint16) GET_2_BYTES(X))
#define DatumGetUInt32(X) ((uint32) GET_4_BYTES(X))
#define DatumGetUInt8(X) ((uint8) GET_1_BYTE(X))
#define Float32GetDatum(X) PointerGetDatum(X)
#define Float4GetDatumFast(X) PointerGetDatum(&(X))
#define Float64GetDatum(X) PointerGetDatum(X)
#define Float8GetDatumFast(X) PointerGetDatum(&(X))
#define GET_1_BYTE(datum)	(((Datum) (datum)) & 0x000000ff)
#define GET_2_BYTES(datum)	(((Datum) (datum)) & 0x0000ffff)
#define GET_4_BYTES(datum)	(((Datum) (datum)) & 0xffffffff)
#define Int16GetDatum(X) ((Datum) SET_2_BYTES(X))
#define Int32GetDatum(X) ((Datum) SET_4_BYTES(X))
#define Int64GetDatumFast(X)  PointerGetDatum(&(X))
#define Int8GetDatum(X) ((Datum) SET_1_BYTE(X))
#define NameGetDatum(X) PointerGetDatum(X)
#define ObjectIdGetDatum(X) ((Datum) SET_4_BYTES(X))

#define PointerGetDatum(X) ((Datum) (X))
#define SET_1_BYTE(value)	(((Datum) (value)) & 0x000000ff)
#define SET_2_BYTES(value)	(((Datum) (value)) & 0x0000ffff)
#define SET_4_BYTES(value)	(((Datum) (value)) & 0xffffffff)
#define SET_VARSIZE(PTR, len)				SET_VARSIZE_4B(PTR, len)
#define SET_VARSIZE_1B(PTR,len) \
	(((varattrib_1b *) (PTR))->va_header = (len) | 0x80)
#define SET_VARSIZE_1B_E(PTR,len) \
	(((varattrib_1b_e *) (PTR))->va_header = 0x80, \
	 ((varattrib_1b_e *) (PTR))->va_len_1be = (len))
#define SET_VARSIZE_4B(PTR,len) \
	(((varattrib_4b *) (PTR))->va_4byte.va_header = (len) & 0x3FFFFFFF)
#define SET_VARSIZE_4B_C(PTR,len) \
	(((varattrib_4b *) (PTR))->va_4byte.va_header = ((len) & 0x3FFFFFFF) | 0x40000000)
#define SET_VARSIZE_COMPRESSED(PTR, len)	SET_VARSIZE_4B_C(PTR, len)
#define SET_VARSIZE_EXTERNAL(PTR, len)		SET_VARSIZE_1B_E(PTR, len)
#define SET_VARSIZE_SHORT(PTR, len)			SET_VARSIZE_1B(PTR, len)
#define SHDESCR(x) extern int no_such_variable
#define SIZEOF_DATUM SIZEOF_UNSIGNED_LONG
#define TransactionIdGetDatum(X) ((Datum) SET_4_BYTES((X)))
#define Trap(condition, errorType) \
	do { \
		if ((assert_enabled) && (condition)) \
			ExceptionalCondition(CppAsString(condition), (errorType), \
								 "__FILE__", "__LINE__"); \
	} while (0)
#define TrapMacro(condition, errorType) \
	((bool) ((! assert_enabled) || ! (condition) || \
			 (ExceptionalCondition(CppAsString(condition), (errorType), \
								   "__FILE__", "__LINE__"))))
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
#define VARSIZE_1B_E(PTR) \
	(((varattrib_1b_e *) (PTR))->va_len_1be)
#define VARSIZE_4B(PTR) \
	(((varattrib_4b *) (PTR))->va_4byte.va_header & 0x3FFFFFFF)
#define VARSIZE_ANY(PTR) \
	(VARATT_IS_1B_E(PTR) ? VARSIZE_1B_E(PTR) : \
	 (VARATT_IS_1B(PTR) ? VARSIZE_1B(PTR) : \
	  VARSIZE_4B(PTR)))
#define VARSIZE_ANY_EXHDR(PTR) \
	(VARATT_IS_1B_E(PTR) ? VARSIZE_1B_E(PTR)-VARHDRSZ_EXTERNAL : \
	 (VARATT_IS_1B(PTR) ? VARSIZE_1B(PTR)-VARHDRSZ_SHORT : \
	  VARSIZE_4B(PTR)-VARHDRSZ))
#define VARSIZE_EXTERNAL(PTR)				VARSIZE_1B_E(PTR)
#define VARSIZE_SHORT(PTR)					VARSIZE_1B(PTR)

#define palloc(sz)	MemoryContextAlloc(CurrentMemoryContext, (sz))
#define palloc0(sz) MemoryContextAllocZero(CurrentMemoryContext, (sz))
#define palloc0fast(sz) \
	( MemSetTest(0, sz) ? \
		MemoryContextAllocZeroAligned(CurrentMemoryContext, sz) : \
		MemoryContextAllocZero(CurrentMemoryContext, sz) )
#define pstrdup(str)  MemoryContextStrdup(CurrentMemoryContext, (str))

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
#define ereport(elevel, rest)  \
	(errstart(elevel, "__FILE__", "__LINE__", PG_FUNCNAME_MACRO) ? \
	 (errfinish rest) : (void) 0)
#define ERRCODE_CHARACTER_NOT_IN_REPERTOIRE MAKE_SQLSTATE('2','2', '0','2','1')
#define ERRCODE_DATETIME_VALUE_OUT_OF_RANGE ERRCODE_DATETIME_FIELD_OVERFLOW
#define ERRCODE_INVALID_ARGUMENT_FOR_POWER_FUNCTION MAKE_SQLSTATE('2','2', '0', '1', 'F')
#define ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION MAKE_SQLSTATE('2','8', '0','0','0')
#define ERRCODE_INVALID_DATABASE_DEFINITION MAKE_SQLSTATE('4','2', 'P','1','2')
#define ERRCODE_INVALID_FUNCTION_DEFINITION MAKE_SQLSTATE('4','2', 'P','1','3')
#define ERRCODE_INVALID_TEXT_REPRESENTATION MAKE_SQLSTATE('2','2', 'P','0','2')
#define ERRCODE_MOST_SPECIFIC_TYPE_MISMATCH MAKE_SQLSTATE('2','2', '0','0','G')
#define ERRCODE_STRING_DATA_LENGTH_MISMATCH MAKE_SQLSTATE('2','2', '0','2','6')
#define ERRCODE_S_R_E_FUNCTION_EXECUTED_NO_RETURN_STATEMENT MAKE_SQLSTATE('2','F', '0','0','5')
#define ERRCODE_WITH_CHECK_OPTION_VIOLATION MAKE_SQLSTATE('4','4', '0','0','0')
#define Abs(x)			((x) >= 0 ? (x) : -(x))
#define BUFFERALIGN(LEN)		TYPEALIGN(ALIGNOF_BUFFER, (LEN))
#define BoolIsValid(boolean)	((boolean) == false || (boolean) == true)

#define CppAsString(identifier) #identifier
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
		if ((((long) _vstart) & LONG_ALIGN_MASK) == 0 && \
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
#define PointerIsAligned(pointer, type) \
		(((long)(pointer) % (sizeof (type))) == 0)
#define PointerIsValid(pointer) ((void*)(pointer) != NULL)
#define RegProcedureIsValid(p)	OidIsValid(p)
#define SHORTALIGN(LEN)			TYPEALIGN(ALIGNOF_SHORT, (LEN))
#define SHORTALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_SHORT, (LEN))
#define SIGNAL_ARGS  int postgres_signal_arg
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
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
	(((long) (LEN) + ((ALIGNVAL) - 1)) & ~((long) ((ALIGNVAL) - 1)))
#define TYPEALIGN_DOWN(ALIGNVAL,LEN)  \
	(((long) (LEN)) & ~((long) ((ALIGNVAL) - 1)))
#define UINT64CONST(x) ((uint64) x##ULL)
#define _(x) gettext((x))


#define endof(array)	(&(array)[lengthof(array)])
#define errcode __msvc_errcode
#define gettext(x) (x)
#define gettext_noop(x) (x)
#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define memmove(d, s, c)		bcopy(s, d, c)
#define offsetof(type, field)	((long) &((type *)0)->field)
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll strtoq
#define strtoull strtouq
#define DEVNULL "nul"
#define DEVTTY "/dev/tty"
#define EXE ".exe"

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
	((filename)[0] == '/') \
)
#define kill(pid,sig)	pgkill(pid,sig)
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pgpipe(a)			pipe(a)
#define piperead(a,b,c)		read(a,b,c)
#define pipewrite(a,b,c)	write(a,b,c)
#define popen(a,b) _popen(a,b)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define rename(from, to)		pgrename(from, to)
#define snprintf(...)	pg_snprintf(__VA_ARGS__)
#define sprintf(...)	pg_sprintf(__VA_ARGS__)
#define symlink(oldpath, newpath)	pgsymlink(oldpath, newpath)
#define unlink(path)			pgunlink(path)
#define vfprintf(...)	pg_vfprintf(__VA_ARGS__)
#define vsnprintf(...)	pg_vsnprintf(__VA_ARGS__)
#define PG_TRACE(name) \
	DTRACE_PROBE(postgresql, name)
#define PG_TRACE1(name, arg1) \
	DTRACE_PROBE1(postgresql, name, arg1)
#define PG_TRACE2(name, arg1, arg2) \
	DTRACE_PROBE2(postgresql, name, arg1, arg2)
#define PG_TRACE3(name, arg1, arg2, arg3) \
	DTRACE_PROBE3(postgresql, name, arg1, arg2, arg3)
#define PG_TRACE4(name, arg1, arg2, arg3, arg4) \
	DTRACE_PROBE4(postgresql, name, arg1, arg2, arg3, arg4)
#define PG_TRACE5(name, arg1, arg2, arg3, arg4, arg5) \
	DTRACE_PROBE5(postgresql, name, arg1, arg2, arg3, arg4, arg5)

#define OID_MAX  UINT_MAX
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

