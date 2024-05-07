









































static void CheckPredicate(Expr *predicate);
static void ComputeIndexAttrs(IndexInfo *indexInfo, Oid *typeOidP, Oid *collationOidP, Oid *classOidP, int16 *colOptionP, List *attList, List *exclusionOpNames, Oid relId, char *accessMethodName, Oid accessMethodId, bool amcanorder, bool isconstraint);









static Oid GetIndexOpClass(List *opclass, Oid attrType, char *accessMethodName, Oid accessMethodId);
static char *ChooseIndexName(const char *tabname, Oid namespaceId, List *colnames, List *exclusionOpNames, bool primary, bool isconstraint);

static char *ChooseIndexNameAddition(List *colnames);
static List *ChooseIndexColumnNames(List *indexElems);
static void RangeVarCallbackForReindexIndex(const RangeVar *relation, Oid relId, Oid oldRelId, void *arg);


bool CheckIndexCompatible(Oid oldId, RangeVar *heapRelation, char *accessMethodName, List *attributeList, List *exclusionOpNames)




{
	bool		isconstraint;
	Oid		   *typeObjectId;
	Oid		   *collationObjectId;
	Oid		   *classObjectId;
	Oid			accessMethodId;
	Oid			relationId;
	HeapTuple	tuple;
	Form_pg_index indexForm;
	Form_pg_am	accessMethodForm;
	bool		amcanorder;
	int16	   *coloptions;
	IndexInfo  *indexInfo;
	int			numberOfAttributes;
	int			old_natts;
	bool		isnull;
	bool		ret = true;
	oidvector  *old_indclass;
	oidvector  *old_indcollation;
	Relation	irel;
	int			i;
	Datum		d;

	
	relationId = RangeVarGetRelid(heapRelation, NoLock, false);

	
	isconstraint = false;

	numberOfAttributes = list_length(attributeList);
	Assert(numberOfAttributes > 0);
	Assert(numberOfAttributes <= INDEX_MAX_KEYS);

	
	tuple = SearchSysCache1(AMNAME, PointerGetDatum(accessMethodName));
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("access method \"%s\" does not exist", accessMethodName)));


	accessMethodId = HeapTupleGetOid(tuple);
	accessMethodForm = (Form_pg_am) GETSTRUCT(tuple);
	amcanorder = accessMethodForm->amcanorder;
	ReleaseSysCache(tuple);

	
	indexInfo = makeNode(IndexInfo);
	indexInfo->ii_Expressions = NIL;
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NIL;
	indexInfo->ii_ExclusionOps = NULL;
	indexInfo->ii_ExclusionProcs = NULL;
	indexInfo->ii_ExclusionStrats = NULL;
	typeObjectId = (Oid *) palloc(numberOfAttributes * sizeof(Oid));
	collationObjectId = (Oid *) palloc(numberOfAttributes * sizeof(Oid));
	classObjectId = (Oid *) palloc(numberOfAttributes * sizeof(Oid));
	coloptions = (int16 *) palloc(numberOfAttributes * sizeof(int16));
	ComputeIndexAttrs(indexInfo, typeObjectId, collationObjectId, classObjectId, coloptions, attributeList, exclusionOpNames, relationId, accessMethodName, accessMethodId, amcanorder, isconstraint);






	
	tuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(oldId));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for index %u", oldId);
	indexForm = (Form_pg_index) GETSTRUCT(tuple);

	
	if (!(heap_attisnull(tuple, Anum_pg_index_indpred) && heap_attisnull(tuple, Anum_pg_index_indexprs) && IndexIsValid(indexForm)))

	{
		ReleaseSysCache(tuple);
		return false;
	}

	
	old_natts = indexForm->indnatts;
	Assert(old_natts == numberOfAttributes);

	d = SysCacheGetAttr(INDEXRELID, tuple, Anum_pg_index_indcollation, &isnull);
	Assert(!isnull);
	old_indcollation = (oidvector *) DatumGetPointer(d);

	d = SysCacheGetAttr(INDEXRELID, tuple, Anum_pg_index_indclass, &isnull);
	Assert(!isnull);
	old_indclass = (oidvector *) DatumGetPointer(d);

	ret = (memcmp(old_indclass->values, classObjectId, old_natts * sizeof(Oid)) == 0 && memcmp(old_indcollation->values, collationObjectId, old_natts * sizeof(Oid)) == 0);



	ReleaseSysCache(tuple);

	if (!ret)
		return false;

	
	irel = index_open(oldId, AccessShareLock);	
	for (i = 0; i < old_natts; i++)
	{
		if (IsPolymorphicType(get_opclass_input_type(classObjectId[i])) && irel->rd_att->attrs[i]->atttypid != typeObjectId[i])
		{
			ret = false;
			break;
		}
	}

	
	if (ret && indexInfo->ii_ExclusionOps != NULL)
	{
		Oid		   *old_operators, *old_procs;
		uint16	   *old_strats;

		RelationGetExclusionInfo(irel, &old_operators, &old_procs, &old_strats);
		ret = memcmp(old_operators, indexInfo->ii_ExclusionOps, old_natts * sizeof(Oid)) == 0;

		
		if (ret)
		{
			for (i = 0; i < old_natts && ret; i++)
			{
				Oid			left, right;

				op_input_types(indexInfo->ii_ExclusionOps[i], &left, &right);
				if ((IsPolymorphicType(left) || IsPolymorphicType(right)) && irel->rd_att->attrs[i]->atttypid != typeObjectId[i])
				{
					ret = false;
					break;
				}
			}
		}
	}

	index_close(irel, NoLock);
	return ret;
}


Oid DefineIndex(IndexStmt *stmt, Oid indexRelationId, bool is_alter_table, bool check_rights, bool skip_build, bool quiet)





{
	char	   *indexRelationName;
	char	   *accessMethodName;
	Oid		   *typeObjectId;
	Oid		   *collationObjectId;
	Oid		   *classObjectId;
	Oid			accessMethodId;
	Oid			relationId;
	Oid			namespaceId;
	Oid			tablespaceId;
	List	   *indexColNames;
	Relation	rel;
	Relation	indexRelation;
	HeapTuple	tuple;
	Form_pg_am	accessMethodForm;
	bool		amcanorder;
	RegProcedure amoptions;
	Datum		reloptions;
	int16	   *coloptions;
	IndexInfo  *indexInfo;
	int			numberOfAttributes;
	TransactionId limitXmin;
	VirtualTransactionId *old_snapshots;
	int			n_old_snapshots;
	LockRelId	heaprelid;
	LOCKTAG		heaplocktag;
	Snapshot	snapshot;
	int			i;

	
	numberOfAttributes = list_length(stmt->indexParams);
	if (numberOfAttributes <= 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("must specify at least one column")));

	if (numberOfAttributes > INDEX_MAX_KEYS)
		ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("cannot use more than %d columns in an index", INDEX_MAX_KEYS)));



	
	rel = heap_openrv(stmt->relation, (stmt->concurrent ? ShareUpdateExclusiveLock : ShareLock));

	relationId = RelationGetRelid(rel);
	namespaceId = RelationGetNamespace(rel);

	if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_MATVIEW)
	{
		if (rel->rd_rel->relkind == RELKIND_FOREIGN_TABLE)

			
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot create index on foreign table \"%s\"", RelationGetRelationName(rel))));


		else ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or materialized view", RelationGetRelationName(rel))));



	}

	
	if (RELATION_IS_OTHER_TEMP(rel))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot create indexes on temporary tables of other sessions")));


	
	if (check_rights && !IsBootstrapProcessingMode())
	{
		AclResult	aclresult;

		aclresult = pg_namespace_aclcheck(namespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(namespaceId));
	}

	
	if (stmt->tableSpace)
	{
		tablespaceId = get_tablespace_oid(stmt->tableSpace, false);
	}
	else {
		tablespaceId = GetDefaultTablespace(rel->rd_rel->relpersistence);
		
	}

	
	if (OidIsValid(tablespaceId) && tablespaceId != MyDatabaseTableSpace)
	{
		AclResult	aclresult;

		aclresult = pg_tablespace_aclcheck(tablespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE, get_tablespace_name(tablespaceId));
	}

	
	if (rel->rd_rel->relisshared)
		tablespaceId = GLOBALTABLESPACE_OID;
	else if (tablespaceId == GLOBALTABLESPACE_OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("only shared relations can be placed in pg_global tablespace")));


	
	indexColNames = ChooseIndexColumnNames(stmt->indexParams);

	
	indexRelationName = stmt->idxname;
	if (indexRelationName == NULL)
		indexRelationName = ChooseIndexName(RelationGetRelationName(rel), namespaceId, indexColNames, stmt->excludeOpNames, stmt->primary, stmt->isconstraint);





	
	accessMethodName = stmt->accessMethod;
	tuple = SearchSysCache1(AMNAME, PointerGetDatum(accessMethodName));
	if (!HeapTupleIsValid(tuple))
	{
		
		if (strcmp(accessMethodName, "rtree") == 0)
		{
			ereport(NOTICE, (errmsg("substituting access method \"gist\" for obsolete method \"rtree\"")));
			accessMethodName = "gist";
			tuple = SearchSysCache1(AMNAME, PointerGetDatum(accessMethodName));
		}

		if (!HeapTupleIsValid(tuple))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("access method \"%s\" does not exist", accessMethodName)));


	}
	accessMethodId = HeapTupleGetOid(tuple);
	accessMethodForm = (Form_pg_am) GETSTRUCT(tuple);

	if (stmt->unique && !accessMethodForm->amcanunique)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("access method \"%s\" does not support unique indexes", accessMethodName)));


	if (numberOfAttributes > 1 && !accessMethodForm->amcanmulticol)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("access method \"%s\" does not support multicolumn indexes", accessMethodName)));


	if (stmt->excludeOpNames && !OidIsValid(accessMethodForm->amgettuple))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("access method \"%s\" does not support exclusion constraints", accessMethodName)));



	amcanorder = accessMethodForm->amcanorder;
	amoptions = accessMethodForm->amoptions;

	ReleaseSysCache(tuple);

	
	if (stmt->whereClause)
		CheckPredicate((Expr *) stmt->whereClause);

	
	reloptions = transformRelOptions((Datum) 0, stmt->options, NULL, NULL, false, false);

	(void) index_reloptions(amoptions, reloptions, true);

	
	indexInfo = makeNode(IndexInfo);
	indexInfo->ii_NumIndexAttrs = numberOfAttributes;
	indexInfo->ii_Expressions = NIL;	
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_Predicate = make_ands_implicit((Expr *) stmt->whereClause);
	indexInfo->ii_PredicateState = NIL;
	indexInfo->ii_ExclusionOps = NULL;
	indexInfo->ii_ExclusionProcs = NULL;
	indexInfo->ii_ExclusionStrats = NULL;
	indexInfo->ii_Unique = stmt->unique;
	
	indexInfo->ii_ReadyForInserts = !stmt->concurrent;
	indexInfo->ii_Concurrent = stmt->concurrent;
	indexInfo->ii_BrokenHotChain = false;

	typeObjectId = (Oid *) palloc(numberOfAttributes * sizeof(Oid));
	collationObjectId = (Oid *) palloc(numberOfAttributes * sizeof(Oid));
	classObjectId = (Oid *) palloc(numberOfAttributes * sizeof(Oid));
	coloptions = (int16 *) palloc(numberOfAttributes * sizeof(int16));
	ComputeIndexAttrs(indexInfo, typeObjectId, collationObjectId, classObjectId, coloptions, stmt->indexParams, stmt->excludeOpNames, relationId, accessMethodName, accessMethodId, amcanorder, stmt->isconstraint);





	
	if (stmt->primary)
		index_check_primary_key(rel, indexInfo, is_alter_table);

	
	if (stmt->isconstraint && !quiet)
	{
		const char *constraint_type;

		if (stmt->primary)
			constraint_type = "PRIMARY KEY";
		else if (stmt->unique)
			constraint_type = "UNIQUE";
		else if (stmt->excludeOpNames != NIL)
			constraint_type = "EXCLUDE";
		else {
			elog(ERROR, "unknown constraint type");
			constraint_type = NULL;		
		}

		ereport(DEBUG1, (errmsg("%s %s will create implicit index \"%s\" for table \"%s\"", is_alter_table ? "ALTER TABLE / ADD" : "CREATE TABLE /", constraint_type, indexRelationName, RelationGetRelationName(rel))));



	}

	
	Assert(!OidIsValid(stmt->oldNode) || (skip_build && !stmt->concurrent));

	
	indexRelationId = index_create(rel, indexRelationName, indexRelationId, stmt->oldNode, indexInfo, indexColNames, accessMethodId, tablespaceId, collationObjectId, classObjectId, coloptions, reloptions, stmt->primary, stmt->isconstraint, stmt->deferrable, stmt->initdeferred, allowSystemTableMods, skip_build || stmt->concurrent, stmt->concurrent, !check_rights);









	
	if (stmt->idxcomment != NULL)
		CreateComments(indexRelationId, RelationRelationId, 0, stmt->idxcomment);

	if (!stmt->concurrent)
	{
		
		heap_close(rel, NoLock);
		return indexRelationId;
	}

	
	heaprelid = rel->rd_lockInfo.lockRelId;
	SET_LOCKTAG_RELATION(heaplocktag, heaprelid.dbId, heaprelid.relId);
	heap_close(rel, NoLock);

	
	LockRelationIdForSession(&heaprelid, ShareUpdateExclusiveLock);

	PopActiveSnapshot();
	CommitTransactionCommand();
	StartTransactionCommand();

	
	WaitForLockers(heaplocktag, ShareLock);

	

	
	rel = heap_openrv(stmt->relation, ShareUpdateExclusiveLock);

	
	indexRelation = index_open(indexRelationId, RowExclusiveLock);

	
	PushActiveSnapshot(GetTransactionSnapshot());

	
	indexInfo = BuildIndexInfo(indexRelation);
	Assert(!indexInfo->ii_ReadyForInserts);
	indexInfo->ii_Concurrent = true;
	indexInfo->ii_BrokenHotChain = false;

	
	index_build(rel, indexRelation, indexInfo, stmt->primary, false);

	
	heap_close(rel, NoLock);
	index_close(indexRelation, NoLock);

	
	index_set_state_flags(indexRelationId, INDEX_CREATE_SET_READY);

	
	PopActiveSnapshot();

	
	CommitTransactionCommand();
	StartTransactionCommand();

	
	WaitForLockers(heaplocktag, ShareLock);

	
	snapshot = RegisterSnapshot(GetTransactionSnapshot());
	PushActiveSnapshot(snapshot);

	
	validate_index(relationId, indexRelationId, snapshot);

	
	limitXmin = snapshot->xmin;

	PopActiveSnapshot();
	UnregisterSnapshot(snapshot);

	
	old_snapshots = GetCurrentVirtualXIDs(limitXmin, true, false, PROC_IS_AUTOVACUUM | PROC_IN_VACUUM, &n_old_snapshots);


	for (i = 0; i < n_old_snapshots; i++)
	{
		if (!VirtualTransactionIdIsValid(old_snapshots[i]))
			continue;			

		if (i > 0)
		{
			
			VirtualTransactionId *newer_snapshots;
			int			n_newer_snapshots;
			int			j;
			int			k;

			newer_snapshots = GetCurrentVirtualXIDs(limitXmin, true, false, PROC_IS_AUTOVACUUM | PROC_IN_VACUUM, &n_newer_snapshots);


			for (j = i; j < n_old_snapshots; j++)
			{
				if (!VirtualTransactionIdIsValid(old_snapshots[j]))
					continue;	
				for (k = 0; k < n_newer_snapshots; k++)
				{
					if (VirtualTransactionIdEquals(old_snapshots[j], newer_snapshots[k]))
						break;
				}
				if (k >= n_newer_snapshots)		
					SetInvalidVirtualTransactionId(old_snapshots[j]);
			}
			pfree(newer_snapshots);
		}

		if (VirtualTransactionIdIsValid(old_snapshots[i]))
			VirtualXactLock(old_snapshots[i], true);
	}

	
	index_set_state_flags(indexRelationId, INDEX_CREATE_SET_VALID);

	
	CacheInvalidateRelcacheByRelid(heaprelid.relId);

	
	UnlockRelationIdForSession(&heaprelid, ShareUpdateExclusiveLock);

	return indexRelationId;
}



static bool CheckMutability(Expr *expr)
{
	
	expr = expression_planner(expr);

	
	return contain_mutable_functions((Node *) expr);
}



static void CheckPredicate(Expr *predicate)
{
	

	
	if (CheckMutability(predicate))
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("functions in index predicate must be marked IMMUTABLE")));

}


static void ComputeIndexAttrs(IndexInfo *indexInfo, Oid *typeOidP, Oid *collationOidP, Oid *classOidP, int16 *colOptionP, List *attList, List *exclusionOpNames, Oid relId, char *accessMethodName, Oid accessMethodId, bool amcanorder, bool isconstraint)











{
	ListCell   *nextExclOp;
	ListCell   *lc;
	int			attn;

	
	if (exclusionOpNames)
	{
		int			ncols = list_length(attList);

		Assert(list_length(exclusionOpNames) == ncols);
		indexInfo->ii_ExclusionOps = (Oid *) palloc(sizeof(Oid) * ncols);
		indexInfo->ii_ExclusionProcs = (Oid *) palloc(sizeof(Oid) * ncols);
		indexInfo->ii_ExclusionStrats = (uint16 *) palloc(sizeof(uint16) * ncols);
		nextExclOp = list_head(exclusionOpNames);
	}
	else nextExclOp = NULL;

	
	attn = 0;
	foreach(lc, attList)
	{
		IndexElem  *attribute = (IndexElem *) lfirst(lc);
		Oid			atttype;
		Oid			attcollation;

		
		if (attribute->name != NULL)
		{
			
			HeapTuple	atttuple;
			Form_pg_attribute attform;

			Assert(attribute->expr == NULL);
			atttuple = SearchSysCacheAttName(relId, attribute->name);
			if (!HeapTupleIsValid(atttuple))
			{
				
				if (isconstraint)
					ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" named in key does not exist", attribute->name)));


				else ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" does not exist", attribute->name)));



			}
			attform = (Form_pg_attribute) GETSTRUCT(atttuple);
			indexInfo->ii_KeyAttrNumbers[attn] = attform->attnum;
			atttype = attform->atttypid;
			attcollation = attform->attcollation;
			ReleaseSysCache(atttuple);
		}
		else {
			
			Node	   *expr = attribute->expr;

			Assert(expr != NULL);
			atttype = exprType(expr);
			attcollation = exprCollation(expr);

			
			while (IsA(expr, CollateExpr))
				expr = (Node *) ((CollateExpr *) expr)->arg;

			if (IsA(expr, Var) && ((Var *) expr)->varattno != InvalidAttrNumber)
			{
				
				indexInfo->ii_KeyAttrNumbers[attn] = ((Var *) expr)->varattno;
			}
			else {
				indexInfo->ii_KeyAttrNumbers[attn] = 0; 
				indexInfo->ii_Expressions = lappend(indexInfo->ii_Expressions, expr);

				

				
				if (CheckMutability((Expr *) expr))
					ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("functions in index expression must be marked IMMUTABLE")));

			}
		}

		typeOidP[attn] = atttype;

		
		if (attribute->collation)
			attcollation = get_collation_oid(attribute->collation, false);

		
		if (type_is_collatable(atttype))
		{
			if (!OidIsValid(attcollation))
				ereport(ERROR, (errcode(ERRCODE_INDETERMINATE_COLLATION), errmsg("could not determine which collation to use for index expression"), errhint("Use the COLLATE clause to set the collation explicitly.")));


		}
		else {
			if (OidIsValid(attcollation))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("collations are not supported by type %s", format_type_be(atttype))));


		}

		collationOidP[attn] = attcollation;

		
		classOidP[attn] = GetIndexOpClass(attribute->opclass, atttype, accessMethodName, accessMethodId);



		
		if (nextExclOp)
		{
			List	   *opname = (List *) lfirst(nextExclOp);
			Oid			opid;
			Oid			opfamily;
			int			strat;

			
			opid = compatible_oper_opid(opname, atttype, atttype, false);

			
			if (get_commutator(opid) != opid)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("operator %s is not commutative", format_operator(opid)), errdetail("Only commutative operators can be used in exclusion constraints.")));




			
			opfamily = get_opclass_family(classOidP[attn]);
			strat = get_op_opfamily_strategy(opid, opfamily);
			if (strat == 0)
			{
				HeapTuple	opftuple;
				Form_pg_opfamily opfform;

				
				opftuple = SearchSysCache1(OPFAMILYOID, ObjectIdGetDatum(opfamily));
				if (!HeapTupleIsValid(opftuple))
					elog(ERROR, "cache lookup failed for opfamily %u", opfamily);
				opfform = (Form_pg_opfamily) GETSTRUCT(opftuple);

				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("operator %s is not a member of operator family \"%s\"", format_operator(opid), NameStr(opfform->opfname)), errdetail("The exclusion operator must be related to the index operator class for the constraint.")));




			}

			indexInfo->ii_ExclusionOps[attn] = opid;
			indexInfo->ii_ExclusionProcs[attn] = get_opcode(opid);
			indexInfo->ii_ExclusionStrats[attn] = strat;
			nextExclOp = lnext(nextExclOp);
		}

		
		colOptionP[attn] = 0;
		if (amcanorder)
		{
			
			if (attribute->ordering == SORTBY_DESC)
				colOptionP[attn] |= INDOPTION_DESC;
			
			if (attribute->nulls_ordering == SORTBY_NULLS_DEFAULT)
			{
				if (attribute->ordering == SORTBY_DESC)
					colOptionP[attn] |= INDOPTION_NULLS_FIRST;
			}
			else if (attribute->nulls_ordering == SORTBY_NULLS_FIRST)
				colOptionP[attn] |= INDOPTION_NULLS_FIRST;
		}
		else {
			
			if (attribute->ordering != SORTBY_DEFAULT)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("access method \"%s\" does not support ASC/DESC options", accessMethodName)));


			if (attribute->nulls_ordering != SORTBY_NULLS_DEFAULT)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("access method \"%s\" does not support NULLS FIRST/LAST options", accessMethodName)));


		}

		attn++;
	}
}


static Oid GetIndexOpClass(List *opclass, Oid attrType, char *accessMethodName, Oid accessMethodId)

{
	char	   *schemaname;
	char	   *opcname;
	HeapTuple	tuple;
	Oid			opClassId, opInputType;

	
	if (list_length(opclass) == 1)
	{
		char	   *claname = strVal(linitial(opclass));

		if (strcmp(claname, "network_ops") == 0 || strcmp(claname, "timespan_ops") == 0 || strcmp(claname, "datetime_ops") == 0 || strcmp(claname, "lztext_ops") == 0 || strcmp(claname, "timestamp_ops") == 0 || strcmp(claname, "bigbox_ops") == 0)




			opclass = NIL;
	}

	if (opclass == NIL)
	{
		
		opClassId = GetDefaultOpClass(attrType, accessMethodId);
		if (!OidIsValid(opClassId))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("data type %s has no default operator class for access method \"%s\"", format_type_be(attrType), accessMethodName), errhint("You must specify an operator class for the index or define a default operator class for the data type.")));



		return opClassId;
	}

	

	
	DeconstructQualifiedName(opclass, &schemaname, &opcname);

	if (schemaname)
	{
		
		Oid			namespaceId;

		namespaceId = LookupExplicitNamespace(schemaname, false);
		tuple = SearchSysCache3(CLAAMNAMENSP, ObjectIdGetDatum(accessMethodId), PointerGetDatum(opcname), ObjectIdGetDatum(namespaceId));


	}
	else {
		
		opClassId = OpclassnameGetOpcid(accessMethodId, opcname);
		if (!OidIsValid(opClassId))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("operator class \"%s\" does not exist for access method \"%s\"", opcname, accessMethodName)));


		tuple = SearchSysCache1(CLAOID, ObjectIdGetDatum(opClassId));
	}

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("operator class \"%s\" does not exist for access method \"%s\"", NameListToString(opclass), accessMethodName)));



	
	opClassId = HeapTupleGetOid(tuple);
	opInputType = ((Form_pg_opclass) GETSTRUCT(tuple))->opcintype;

	if (!IsBinaryCoercible(attrType, opInputType))
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("operator class \"%s\" does not accept data type %s", NameListToString(opclass), format_type_be(attrType))));



	ReleaseSysCache(tuple);

	return opClassId;
}


Oid GetDefaultOpClass(Oid type_id, Oid am_id)
{
	Oid			result = InvalidOid;
	int			nexact = 0;
	int			ncompatible = 0;
	int			ncompatiblepreferred = 0;
	Relation	rel;
	ScanKeyData skey[1];
	SysScanDesc scan;
	HeapTuple	tup;
	TYPCATEGORY tcategory;

	
	type_id = getBaseType(type_id);

	tcategory = TypeCategory(type_id);

	
	rel = heap_open(OperatorClassRelationId, AccessShareLock);

	ScanKeyInit(&skey[0], Anum_pg_opclass_opcmethod, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(am_id));



	scan = systable_beginscan(rel, OpclassAmNameNspIndexId, true, NULL, 1, skey);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_opclass opclass = (Form_pg_opclass) GETSTRUCT(tup);

		
		if (!opclass->opcdefault)
			continue;
		if (opclass->opcintype == type_id)
		{
			nexact++;
			result = HeapTupleGetOid(tup);
		}
		else if (nexact == 0 && IsBinaryCoercible(type_id, opclass->opcintype))
		{
			if (IsPreferredType(tcategory, opclass->opcintype))
			{
				ncompatiblepreferred++;
				result = HeapTupleGetOid(tup);
			}
			else if (ncompatiblepreferred == 0)
			{
				ncompatible++;
				result = HeapTupleGetOid(tup);
			}
		}
	}

	systable_endscan(scan);

	heap_close(rel, AccessShareLock);

	
	if (nexact > 1)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("there are multiple default operator classes for data type %s", format_type_be(type_id))));



	if (nexact == 1 || ncompatiblepreferred == 1 || (ncompatiblepreferred == 0 && ncompatible == 1))

		return result;

	return InvalidOid;
}


char * makeObjectName(const char *name1, const char *name2, const char *label)
{
	char	   *name;
	int			overhead = 0;	
	int			availchars;		
	int			name1chars;		
	int			name2chars;		
	int			ndx;

	name1chars = strlen(name1);
	if (name2)
	{
		name2chars = strlen(name2);
		overhead++;				
	}
	else name2chars = 0;
	if (label)
		overhead += strlen(label) + 1;

	availchars = NAMEDATALEN - 1 - overhead;
	Assert(availchars > 0);		

	
	while (name1chars + name2chars > availchars)
	{
		if (name1chars > name2chars)
			name1chars--;
		else name2chars--;
	}

	name1chars = pg_mbcliplen(name1, name1chars, name1chars);
	if (name2)
		name2chars = pg_mbcliplen(name2, name2chars, name2chars);

	
	name = palloc(name1chars + name2chars + overhead + 1);
	memcpy(name, name1, name1chars);
	ndx = name1chars;
	if (name2)
	{
		name[ndx++] = '_';
		memcpy(name + ndx, name2, name2chars);
		ndx += name2chars;
	}
	if (label)
	{
		name[ndx++] = '_';
		strcpy(name + ndx, label);
	}
	else name[ndx] = '\0';

	return name;
}


char * ChooseRelationName(const char *name1, const char *name2, const char *label, Oid namespaceid)

{
	int			pass = 0;
	char	   *relname = NULL;
	char		modlabel[NAMEDATALEN];

	
	StrNCpy(modlabel, label, sizeof(modlabel));

	for (;;)
	{
		relname = makeObjectName(name1, name2, modlabel);

		if (!OidIsValid(get_relname_relid(relname, namespaceid)))
			break;

		
		pfree(relname);
		snprintf(modlabel, sizeof(modlabel), "%s%d", label, ++pass);
	}

	return relname;
}


static char * ChooseIndexName(const char *tabname, Oid namespaceId, List *colnames, List *exclusionOpNames, bool primary, bool isconstraint)


{
	char	   *indexname;

	if (primary)
	{
		
		indexname = ChooseRelationName(tabname, NULL, "pkey", namespaceId);


	}
	else if (exclusionOpNames != NIL)
	{
		indexname = ChooseRelationName(tabname, ChooseIndexNameAddition(colnames), "excl", namespaceId);


	}
	else if (isconstraint)
	{
		indexname = ChooseRelationName(tabname, ChooseIndexNameAddition(colnames), "key", namespaceId);


	}
	else {
		indexname = ChooseRelationName(tabname, ChooseIndexNameAddition(colnames), "idx", namespaceId);


	}

	return indexname;
}


static char * ChooseIndexNameAddition(List *colnames)
{
	char		buf[NAMEDATALEN * 2];
	int			buflen = 0;
	ListCell   *lc;

	buf[0] = '\0';
	foreach(lc, colnames)
	{
		const char *name = (const char *) lfirst(lc);

		if (buflen > 0)
			buf[buflen++] = '_';	

		
		strlcpy(buf + buflen, name, NAMEDATALEN);
		buflen += strlen(buf + buflen);
		if (buflen >= NAMEDATALEN)
			break;
	}
	return pstrdup(buf);
}


static List * ChooseIndexColumnNames(List *indexElems)
{
	List	   *result = NIL;
	ListCell   *lc;

	foreach(lc, indexElems)
	{
		IndexElem  *ielem = (IndexElem *) lfirst(lc);
		const char *origname;
		const char *curname;
		int			i;
		char		buf[NAMEDATALEN];

		
		if (ielem->indexcolname)
			origname = ielem->indexcolname;		
		else if (ielem->name)
			origname = ielem->name;		
		else origname = "expr";

		
		curname = origname;
		for (i = 1;; i++)
		{
			ListCell   *lc2;
			char		nbuf[32];
			int			nlen;

			foreach(lc2, result)
			{
				if (strcmp(curname, (char *) lfirst(lc2)) == 0)
					break;
			}
			if (lc2 == NULL)
				break;			

			sprintf(nbuf, "%d", i);

			
			nlen = pg_mbcliplen(origname, strlen(origname), NAMEDATALEN - 1 - strlen(nbuf));
			memcpy(buf, origname, nlen);
			strcpy(buf + nlen, nbuf);
			curname = buf;
		}

		
		result = lappend(result, pstrdup(curname));
	}
	return result;
}


Oid ReindexIndex(RangeVar *indexRelation)
{
	Oid			indOid;
	Oid			heapOid = InvalidOid;

	
	indOid = RangeVarGetRelidExtended(indexRelation, AccessExclusiveLock, false, false, RangeVarCallbackForReindexIndex, (void *) &heapOid);



	reindex_index(indOid, false);

	return indOid;
}


static void RangeVarCallbackForReindexIndex(const RangeVar *relation, Oid relId, Oid oldRelId, void *arg)

{
	char		relkind;
	Oid		   *heapOid = (Oid *) arg;

	
	if (relId != oldRelId && OidIsValid(oldRelId))
	{
		
		UnlockRelationOid(*heapOid, ShareLock);
		*heapOid = InvalidOid;
	}

	
	if (!OidIsValid(relId))
		return;

	
	relkind = get_rel_relkind(relId);
	if (!relkind)
		return;
	if (relkind != RELKIND_INDEX)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not an index", relation->relname)));


	
	if (!pg_class_ownercheck(relId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, relation->relname);

	
	if (relId != oldRelId)
	{
		
		*heapOid = IndexGetRelation(relId, true);
		if (OidIsValid(*heapOid))
			LockRelationOid(*heapOid, ShareLock);
	}
}


Oid ReindexTable(RangeVar *relation)
{
	Oid			heapOid;

	
	heapOid = RangeVarGetRelidExtended(relation, ShareLock, false, false, RangeVarCallbackOwnsTable, NULL);

	if (!reindex_relation(heapOid, REINDEX_REL_PROCESS_TOAST | REINDEX_REL_CHECK_CONSTRAINTS))

		ereport(NOTICE, (errmsg("table \"%s\" has no indexes", relation->relname)));


	return heapOid;
}


Oid ReindexDatabase(const char *databaseName, bool do_system, bool do_user)
{
	Relation	relationRelation;
	HeapScanDesc scan;
	HeapTuple	tuple;
	MemoryContext private_context;
	MemoryContext old;
	List	   *relids = NIL;
	ListCell   *l;

	AssertArg(databaseName);

	if (strcmp(databaseName, get_database_name(MyDatabaseId)) != 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("can only reindex the currently open database")));


	if (!pg_database_ownercheck(MyDatabaseId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE, databaseName);

	
	private_context = AllocSetContextCreate(PortalContext, "ReindexDatabase", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);




	
	if (do_system)
	{
		old = MemoryContextSwitchTo(private_context);
		relids = lappend_oid(relids, RelationRelationId);
		MemoryContextSwitchTo(old);
	}

	
	relationRelation = heap_open(RelationRelationId, AccessShareLock);
	scan = heap_beginscan_catalog(relationRelation, 0, NULL);
	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_class classtuple = (Form_pg_class) GETSTRUCT(tuple);
		Oid			relid = HeapTupleGetOid(tuple);

		if (classtuple->relkind != RELKIND_RELATION && classtuple->relkind != RELKIND_MATVIEW)
			continue;

		
		if (classtuple->relpersistence == RELPERSISTENCE_TEMP && !isTempNamespace(classtuple->relnamespace))
			continue;

		
		if (IsSystemClass(relid, classtuple))
		{
			if (!do_system)
				continue;
		}
		else {
			if (!do_user)
				continue;
		}

		if (HeapTupleGetOid(tuple) == RelationRelationId)
			continue;			

		old = MemoryContextSwitchTo(private_context);
		relids = lappend_oid(relids, relid);
		MemoryContextSwitchTo(old);
	}
	heap_endscan(scan);
	heap_close(relationRelation, AccessShareLock);

	
	PopActiveSnapshot();
	CommitTransactionCommand();
	foreach(l, relids)
	{
		Oid			relid = lfirst_oid(l);

		StartTransactionCommand();
		
		PushActiveSnapshot(GetTransactionSnapshot());
		if (reindex_relation(relid, REINDEX_REL_PROCESS_TOAST | REINDEX_REL_CHECK_CONSTRAINTS))

			ereport(NOTICE, (errmsg("table \"%s.%s\" was reindexed", get_namespace_name(get_rel_namespace(relid)), get_rel_name(relid))));


		PopActiveSnapshot();
		CommitTransactionCommand();
	}
	StartTransactionCommand();

	MemoryContextDelete(private_context);

	return MyDatabaseId;
}
