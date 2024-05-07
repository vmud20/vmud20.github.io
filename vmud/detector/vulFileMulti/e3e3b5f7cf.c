





































typedef struct {
	Tuplesortstate *tuplesort;	
	
	double		htups, itups, tups_inserted;

} v_i_state;


static TupleDesc ConstructTupleDescriptor(Relation heapRelation, IndexInfo *indexInfo, Oid *classObjectId);

static void InitializeAttributeOids(Relation indexRelation, int numatts, Oid indexoid);
static void AppendAttributeTuples(Relation indexRelation, int numatts);
static void UpdateIndexRelation(Oid indexoid, Oid heapoid, IndexInfo *indexInfo, Oid *classOids, int16 *coloptions, bool primary, bool isvalid);




static void index_update_stats(Relation rel, bool hasindex, bool isprimary, Oid reltoastidxid, double reltuples);
static bool validate_index_callback(ItemPointer itemptr, void *opaque);
static void validate_index_heapscan(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, Snapshot snapshot, v_i_state *state);



static Oid	IndexGetRelation(Oid indexId);



static TupleDesc ConstructTupleDescriptor(Relation heapRelation, IndexInfo *indexInfo, Oid *classObjectId)


{
	int			numatts = indexInfo->ii_NumIndexAttrs;
	ListCell   *indexpr_item = list_head(indexInfo->ii_Expressions);
	TupleDesc	heapTupDesc;
	TupleDesc	indexTupDesc;
	int			natts;			
	int			i;

	heapTupDesc = RelationGetDescr(heapRelation);
	natts = RelationGetForm(heapRelation)->relnatts;

	
	indexTupDesc = CreateTemplateTupleDesc(numatts, false);

	
	for (i = 0; i < numatts; i++)
	{
		AttrNumber	atnum = indexInfo->ii_KeyAttrNumbers[i];
		Form_pg_attribute to = indexTupDesc->attrs[i];
		HeapTuple	tuple;
		Form_pg_type typeTup;
		Oid			keyType;

		if (atnum != 0)
		{
			
			Form_pg_attribute from;

			if (atnum < 0)
			{
				
				from = SystemAttributeDefinition(atnum, heapRelation->rd_rel->relhasoids);
			}
			else {
				
				if (atnum > natts)		
					elog(ERROR, "invalid column number %d", atnum);
				from = heapTupDesc->attrs[AttrNumberGetAttrOffset(atnum)];
			}

			
			memcpy(to, from, ATTRIBUTE_TUPLE_SIZE);

			
			to->attnum = i + 1;

			to->attstattarget = -1;
			to->attcacheoff = -1;
			to->attnotnull = false;
			to->atthasdef = false;
			to->attislocal = true;
			to->attinhcount = 0;
		}
		else {
			
			Node	   *indexkey;

			MemSet(to, 0, ATTRIBUTE_TUPLE_SIZE);

			if (indexpr_item == NULL)	
				elog(ERROR, "too few entries in indexprs list");
			indexkey = (Node *) lfirst(indexpr_item);
			indexpr_item = lnext(indexpr_item);

			
			sprintf(NameStr(to->attname), "pg_expression_%d", i + 1);

			
			keyType = exprType(indexkey);
			tuple = SearchSysCache(TYPEOID, ObjectIdGetDatum(keyType), 0, 0, 0);

			if (!HeapTupleIsValid(tuple))
				elog(ERROR, "cache lookup failed for type %u", keyType);
			typeTup = (Form_pg_type) GETSTRUCT(tuple);

			
			to->attnum = i + 1;
			to->atttypid = keyType;
			to->attlen = typeTup->typlen;
			to->attbyval = typeTup->typbyval;
			to->attstorage = typeTup->typstorage;
			to->attalign = typeTup->typalign;
			to->attstattarget = -1;
			to->attcacheoff = -1;
			to->atttypmod = -1;
			to->attislocal = true;

			ReleaseSysCache(tuple);
		}

		
		to->attrelid = InvalidOid;

		
		tuple = SearchSysCache(CLAOID, ObjectIdGetDatum(classObjectId[i]), 0, 0, 0);

		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for opclass %u", classObjectId[i]);
		keyType = ((Form_pg_opclass) GETSTRUCT(tuple))->opckeytype;
		ReleaseSysCache(tuple);

		if (OidIsValid(keyType) && keyType != to->atttypid)
		{
			
			tuple = SearchSysCache(TYPEOID, ObjectIdGetDatum(keyType), 0, 0, 0);

			if (!HeapTupleIsValid(tuple))
				elog(ERROR, "cache lookup failed for type %u", keyType);
			typeTup = (Form_pg_type) GETSTRUCT(tuple);

			to->atttypid = keyType;
			to->atttypmod = -1;
			to->attlen = typeTup->typlen;
			to->attbyval = typeTup->typbyval;
			to->attalign = typeTup->typalign;
			to->attstorage = typeTup->typstorage;

			ReleaseSysCache(tuple);
		}
	}

	return indexTupDesc;
}


static void InitializeAttributeOids(Relation indexRelation, int numatts, Oid indexoid)


{
	TupleDesc	tupleDescriptor;
	int			i;

	tupleDescriptor = RelationGetDescr(indexRelation);

	for (i = 0; i < numatts; i += 1)
		tupleDescriptor->attrs[i]->attrelid = indexoid;
}


static void AppendAttributeTuples(Relation indexRelation, int numatts)
{
	Relation	pg_attribute;
	CatalogIndexState indstate;
	TupleDesc	indexTupDesc;
	HeapTuple	new_tuple;
	int			i;

	
	pg_attribute = heap_open(AttributeRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(pg_attribute);

	
	indexTupDesc = RelationGetDescr(indexRelation);

	for (i = 0; i < numatts; i++)
	{
		
		Assert(indexTupDesc->attrs[i]->attnum == i + 1);
		Assert(indexTupDesc->attrs[i]->attcacheoff == -1);

		new_tuple = heap_addheader(Natts_pg_attribute, false, ATTRIBUTE_TUPLE_SIZE, (void *) indexTupDesc->attrs[i]);



		simple_heap_insert(pg_attribute, new_tuple);

		CatalogIndexInsert(indstate, new_tuple);

		heap_freetuple(new_tuple);
	}

	CatalogCloseIndexes(indstate);

	heap_close(pg_attribute, RowExclusiveLock);
}


static void UpdateIndexRelation(Oid indexoid, Oid heapoid, IndexInfo *indexInfo, Oid *classOids, int16 *coloptions, bool primary, bool isvalid)






{
	int2vector *indkey;
	oidvector  *indclass;
	int2vector *indoption;
	Datum		exprsDatum;
	Datum		predDatum;
	Datum		values[Natts_pg_index];
	char		nulls[Natts_pg_index];
	Relation	pg_index;
	HeapTuple	tuple;
	int			i;

	
	indkey = buildint2vector(NULL, indexInfo->ii_NumIndexAttrs);
	for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
		indkey->values[i] = indexInfo->ii_KeyAttrNumbers[i];
	indclass = buildoidvector(classOids, indexInfo->ii_NumIndexAttrs);
	indoption = buildint2vector(coloptions, indexInfo->ii_NumIndexAttrs);

	
	if (indexInfo->ii_Expressions != NIL)
	{
		char	   *exprsString;

		exprsString = nodeToString(indexInfo->ii_Expressions);
		exprsDatum = DirectFunctionCall1(textin, CStringGetDatum(exprsString));
		pfree(exprsString);
	}
	else exprsDatum = (Datum) 0;

	
	if (indexInfo->ii_Predicate != NIL)
	{
		char	   *predString;

		predString = nodeToString(make_ands_explicit(indexInfo->ii_Predicate));
		predDatum = DirectFunctionCall1(textin, CStringGetDatum(predString));
		pfree(predString);
	}
	else predDatum = (Datum) 0;

	
	pg_index = heap_open(IndexRelationId, RowExclusiveLock);

	
	MemSet(nulls, ' ', sizeof(nulls));

	values[Anum_pg_index_indexrelid - 1] = ObjectIdGetDatum(indexoid);
	values[Anum_pg_index_indrelid - 1] = ObjectIdGetDatum(heapoid);
	values[Anum_pg_index_indnatts - 1] = Int16GetDatum(indexInfo->ii_NumIndexAttrs);
	values[Anum_pg_index_indisunique - 1] = BoolGetDatum(indexInfo->ii_Unique);
	values[Anum_pg_index_indisprimary - 1] = BoolGetDatum(primary);
	values[Anum_pg_index_indisclustered - 1] = BoolGetDatum(false);
	values[Anum_pg_index_indisvalid - 1] = BoolGetDatum(isvalid);
	values[Anum_pg_index_indcheckxmin - 1] = BoolGetDatum(false);
	
	values[Anum_pg_index_indisready - 1] = BoolGetDatum(isvalid);
	values[Anum_pg_index_indkey - 1] = PointerGetDatum(indkey);
	values[Anum_pg_index_indclass - 1] = PointerGetDatum(indclass);
	values[Anum_pg_index_indoption - 1] = PointerGetDatum(indoption);
	values[Anum_pg_index_indexprs - 1] = exprsDatum;
	if (exprsDatum == (Datum) 0)
		nulls[Anum_pg_index_indexprs - 1] = 'n';
	values[Anum_pg_index_indpred - 1] = predDatum;
	if (predDatum == (Datum) 0)
		nulls[Anum_pg_index_indpred - 1] = 'n';

	tuple = heap_formtuple(RelationGetDescr(pg_index), values, nulls);

	
	simple_heap_insert(pg_index, tuple);

	
	CatalogUpdateIndexes(pg_index, tuple);

	
	heap_close(pg_index, RowExclusiveLock);
	heap_freetuple(tuple);
}



Oid index_create(Oid heapRelationId, const char *indexRelationName, Oid indexRelationId, IndexInfo *indexInfo, Oid accessMethodObjectId, Oid tableSpaceId, Oid *classObjectId, int16 *coloptions, Datum reloptions, bool isprimary, bool isconstraint, bool allow_system_table_mods, bool skip_build, bool concurrent)













{
	Relation	pg_class;
	Relation	heapRelation;
	Relation	indexRelation;
	TupleDesc	indexTupDesc;
	bool		shared_relation;
	Oid			namespaceId;
	int			i;

	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	
	heapRelation = heap_open(heapRelationId, (concurrent ? ShareUpdateExclusiveLock : ShareLock));

	
	namespaceId = RelationGetNamespace(heapRelation);
	shared_relation = heapRelation->rd_rel->relisshared;

	
	if (indexInfo->ii_NumIndexAttrs < 1)
		elog(ERROR, "must index at least one column");

	if (!allow_system_table_mods && IsSystemRelation(heapRelation) && IsNormalProcessingMode())

		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("user-defined indexes on system catalog tables are not supported")));


	
	if (concurrent && IsSystemRelation(heapRelation))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("concurrent index creation on system catalog tables is not supported")));


	
	if (shared_relation && !IsBootstrapProcessingMode())
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("shared indexes cannot be created after initdb")));


	
	if (shared_relation)
	{
		if (tableSpaceId != GLOBALTABLESPACE_OID)
			
			elog(ERROR, "shared relations must be placed in pg_global tablespace");
	}
	else {
		if (tableSpaceId == GLOBALTABLESPACE_OID)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("only shared relations can be placed in pg_global tablespace")));

	}

	if (get_relname_relid(indexRelationName, namespaceId))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists", indexRelationName)));



	
	indexTupDesc = ConstructTupleDescriptor(heapRelation, indexInfo, classObjectId);


	
	if (!OidIsValid(indexRelationId))
		indexRelationId = GetNewRelFileNode(tableSpaceId, shared_relation, pg_class);

	
	indexRelation = heap_create(indexRelationName, namespaceId, tableSpaceId, indexRelationId, indexTupDesc, RELKIND_INDEX, shared_relation, allow_system_table_mods);







	Assert(indexRelationId == RelationGetRelid(indexRelation));

	
	LockRelation(indexRelation, AccessExclusiveLock);

	
	indexRelation->rd_rel->relowner = heapRelation->rd_rel->relowner;
	indexRelation->rd_rel->relam = accessMethodObjectId;
	indexRelation->rd_rel->relkind = RELKIND_INDEX;
	indexRelation->rd_rel->relhasoids = false;

	
	InsertPgClassTuple(pg_class, indexRelation, RelationGetRelid(indexRelation), reloptions);


	
	heap_close(pg_class, RowExclusiveLock);

	
	InitializeAttributeOids(indexRelation, indexInfo->ii_NumIndexAttrs, indexRelationId);


	
	AppendAttributeTuples(indexRelation, indexInfo->ii_NumIndexAttrs);

	
	UpdateIndexRelation(indexRelationId, heapRelationId, indexInfo, classObjectId, coloptions, isprimary, !concurrent);

	
	if (!IsBootstrapProcessingMode())
	{
		ObjectAddress myself, referenced;

		myself.classId = RelationRelationId;
		myself.objectId = indexRelationId;
		myself.objectSubId = 0;

		if (isconstraint)
		{
			char		constraintType;
			Oid			conOid;

			if (isprimary)
				constraintType = CONSTRAINT_PRIMARY;
			else if (indexInfo->ii_Unique)
				constraintType = CONSTRAINT_UNIQUE;
			else {
				elog(ERROR, "constraint must be PRIMARY or UNIQUE");
				constraintType = 0;		
			}

			
			if (indexInfo->ii_Expressions)
				elog(ERROR, "constraints cannot have index expressions");

			conOid = CreateConstraintEntry(indexRelationName, namespaceId, constraintType, false, false, heapRelationId, indexInfo->ii_KeyAttrNumbers, indexInfo->ii_NumIndexAttrs, InvalidOid, InvalidOid, NULL, NULL, NULL, NULL, 0, ' ', ' ', ' ', InvalidOid, NULL, NULL, NULL);





















			referenced.classId = ConstraintRelationId;
			referenced.objectId = conOid;
			referenced.objectSubId = 0;

			recordDependencyOn(&myself, &referenced, DEPENDENCY_INTERNAL);
		}
		else {
			bool		have_simple_col = false;

			
			for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
			{
				if (indexInfo->ii_KeyAttrNumbers[i] != 0)
				{
					referenced.classId = RelationRelationId;
					referenced.objectId = heapRelationId;
					referenced.objectSubId = indexInfo->ii_KeyAttrNumbers[i];

					recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);

					have_simple_col = true;
				}
			}

			
			if (!have_simple_col && !contain_vars_of_level((Node *) indexInfo->ii_Expressions, 0) && !contain_vars_of_level((Node *) indexInfo->ii_Predicate, 0))

			{
				referenced.classId = RelationRelationId;
				referenced.objectId = heapRelationId;
				referenced.objectSubId = 0;

				recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);
			}
		}

		
		for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
		{
			referenced.classId = OperatorClassRelationId;
			referenced.objectId = classObjectId[i];
			referenced.objectSubId = 0;

			recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
		}

		
		if (indexInfo->ii_Expressions)
		{
			recordDependencyOnSingleRelExpr(&myself, (Node *) indexInfo->ii_Expressions, heapRelationId, DEPENDENCY_NORMAL, DEPENDENCY_AUTO);



		}

		
		if (indexInfo->ii_Predicate)
		{
			recordDependencyOnSingleRelExpr(&myself, (Node *) indexInfo->ii_Predicate, heapRelationId, DEPENDENCY_NORMAL, DEPENDENCY_AUTO);



		}
	}

	
	CommandCounterIncrement();

	
	if (IsBootstrapProcessingMode())
		RelationInitIndexAccessInfo(indexRelation);
	else Assert(indexRelation->rd_indexcxt != NULL);

	
	if (IsBootstrapProcessingMode())
	{
		index_register(heapRelationId, indexRelationId, indexInfo);
	}
	else if (skip_build)
	{
		
		index_update_stats(heapRelation, true, isprimary, InvalidOid, heapRelation->rd_rel->reltuples);



		
		CommandCounterIncrement();
	}
	else {
		index_build(heapRelation, indexRelation, indexInfo, isprimary);
	}

	
	index_close(indexRelation, NoLock);
	heap_close(heapRelation, NoLock);

	return indexRelationId;
}


void index_drop(Oid indexId)
{
	Oid			heapId;
	Relation	userHeapRelation;
	Relation	userIndexRelation;
	Relation	indexRelation;
	HeapTuple	tuple;
	bool		hasexprs;

	
	heapId = IndexGetRelation(indexId);
	userHeapRelation = heap_open(heapId, AccessExclusiveLock);

	userIndexRelation = index_open(indexId, AccessExclusiveLock);

	
	RelationOpenSmgr(userIndexRelation);
	smgrscheduleunlink(userIndexRelation->rd_smgr, userIndexRelation->rd_istemp);

	
	index_close(userIndexRelation, NoLock);

	RelationForgetRelation(indexId);

	
	indexRelation = heap_open(IndexRelationId, RowExclusiveLock);

	tuple = SearchSysCache(INDEXRELID, ObjectIdGetDatum(indexId), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for index %u", indexId);

	hasexprs = !heap_attisnull(tuple, Anum_pg_index_indexprs);

	simple_heap_delete(indexRelation, &tuple->t_self);

	ReleaseSysCache(tuple);
	heap_close(indexRelation, RowExclusiveLock);

	
	if (hasexprs)
		RemoveStatistics(indexId, 0);

	
	DeleteAttributeTuples(indexId);

	
	DeleteRelationTuple(indexId);

	
	CacheInvalidateRelcache(userHeapRelation);

	
	heap_close(userHeapRelation, NoLock);
}




IndexInfo * BuildIndexInfo(Relation index)
{
	IndexInfo  *ii = makeNode(IndexInfo);
	Form_pg_index indexStruct = index->rd_index;
	int			i;
	int			numKeys;

	
	numKeys = indexStruct->indnatts;
	if (numKeys < 1 || numKeys > INDEX_MAX_KEYS)
		elog(ERROR, "invalid indnatts %d for index %u", numKeys, RelationGetRelid(index));
	ii->ii_NumIndexAttrs = numKeys;
	for (i = 0; i < numKeys; i++)
		ii->ii_KeyAttrNumbers[i] = indexStruct->indkey.values[i];

	
	ii->ii_Expressions = RelationGetIndexExpressions(index);
	ii->ii_ExpressionsState = NIL;

	
	ii->ii_Predicate = RelationGetIndexPredicate(index);
	ii->ii_PredicateState = NIL;

	
	ii->ii_Unique = indexStruct->indisunique;
	ii->ii_ReadyForInserts = indexStruct->indisready;

	
	ii->ii_Concurrent = false;
	ii->ii_BrokenHotChain = false;

	return ii;
}


void FormIndexDatum(IndexInfo *indexInfo, TupleTableSlot *slot, EState *estate, Datum *values, bool *isnull)




{
	ListCell   *indexpr_item;
	int			i;

	if (indexInfo->ii_Expressions != NIL && indexInfo->ii_ExpressionsState == NIL)
	{
		
		indexInfo->ii_ExpressionsState = (List *)
			ExecPrepareExpr((Expr *) indexInfo->ii_Expressions, estate);
		
		Assert(GetPerTupleExprContext(estate)->ecxt_scantuple == slot);
	}
	indexpr_item = list_head(indexInfo->ii_ExpressionsState);

	for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
	{
		int			keycol = indexInfo->ii_KeyAttrNumbers[i];
		Datum		iDatum;
		bool		isNull;

		if (keycol != 0)
		{
			
			iDatum = slot_getattr(slot, keycol, &isNull);
		}
		else {
			
			if (indexpr_item == NULL)
				elog(ERROR, "wrong number of index expressions");
			iDatum = ExecEvalExprSwitchContext((ExprState *) lfirst(indexpr_item), GetPerTupleExprContext(estate), &isNull, NULL);


			indexpr_item = lnext(indexpr_item);
		}
		values[i] = iDatum;
		isnull[i] = isNull;
	}

	if (indexpr_item != NULL)
		elog(ERROR, "wrong number of index expressions");
}



static void index_update_stats(Relation rel, bool hasindex, bool isprimary, Oid reltoastidxid, double reltuples)

{
	BlockNumber relpages = RelationGetNumberOfBlocks(rel);
	Oid			relid = RelationGetRelid(rel);
	Relation	pg_class;
	HeapTuple	tuple;
	Form_pg_class rd_rel;
	bool		dirty;

	

	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	
	if (IsBootstrapProcessingMode() || ReindexIsProcessingHeap(RelationRelationId))
	{
		
		HeapScanDesc pg_class_scan;
		ScanKeyData key[1];

		ScanKeyInit(&key[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));



		pg_class_scan = heap_beginscan(pg_class, SnapshotNow, 1, key);
		tuple = heap_getnext(pg_class_scan, ForwardScanDirection);
		tuple = heap_copytuple(tuple);
		heap_endscan(pg_class_scan);
	}
	else {
		
		tuple = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);

	}

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for relation %u", relid);
	rd_rel = (Form_pg_class) GETSTRUCT(tuple);

	

	dirty = false;
	if (rd_rel->relhasindex != hasindex)
	{
		rd_rel->relhasindex = hasindex;
		dirty = true;
	}
	if (isprimary)
	{
		if (!rd_rel->relhaspkey)
		{
			rd_rel->relhaspkey = true;
			dirty = true;
		}
	}
	if (OidIsValid(reltoastidxid))
	{
		Assert(rd_rel->relkind == RELKIND_TOASTVALUE);
		if (rd_rel->reltoastidxid != reltoastidxid)
		{
			rd_rel->reltoastidxid = reltoastidxid;
			dirty = true;
		}
	}
	if (rd_rel->reltuples != (float4) reltuples)
	{
		rd_rel->reltuples = (float4) reltuples;
		dirty = true;
	}
	if (rd_rel->relpages != (int32) relpages)
	{
		rd_rel->relpages = (int32) relpages;
		dirty = true;
	}

	
	if (dirty)
	{
		heap_inplace_update(pg_class, tuple);
		
	}
	else {
		
		CacheInvalidateRelcacheByTuple(tuple);
	}

	heap_freetuple(tuple);

	heap_close(pg_class, RowExclusiveLock);
}


void setNewRelfilenode(Relation relation, TransactionId freezeXid)
{
	Oid			newrelfilenode;
	RelFileNode newrnode;
	SMgrRelation srel;
	Relation	pg_class;
	HeapTuple	tuple;
	Form_pg_class rd_rel;

	
	Assert(!relation->rd_isnailed || relation->rd_rel->relkind == RELKIND_INDEX);
	
	Assert(!relation->rd_rel->relisshared);
	
	Assert((relation->rd_rel->relkind == RELKIND_INDEX && freezeXid == InvalidTransactionId) || TransactionIdIsNormal(freezeXid));


	
	newrelfilenode = GetNewRelFileNode(relation->rd_rel->reltablespace, relation->rd_rel->relisshared, NULL);


	
	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(RelationGetRelid(relation)), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for relation %u", RelationGetRelid(relation));
	rd_rel = (Form_pg_class) GETSTRUCT(tuple);

	
	
	newrnode = relation->rd_node;
	newrnode.relNode = newrelfilenode;

	srel = smgropen(newrnode);
	smgrcreate(srel, relation->rd_istemp, false);
	smgrclose(srel);

	
	RelationOpenSmgr(relation);
	smgrscheduleunlink(relation->rd_smgr, relation->rd_istemp);

	
	rd_rel->relfilenode = newrelfilenode;
	rd_rel->relpages = 0;		
	rd_rel->reltuples = 0;
	rd_rel->relfrozenxid = freezeXid;
	simple_heap_update(pg_class, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_class, tuple);

	heap_freetuple(tuple);

	heap_close(pg_class, RowExclusiveLock);

	
	CommandCounterIncrement();

	
	RelationCacheMarkNewRelfilenode(relation);
}



void index_build(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, bool isprimary)



{
	RegProcedure procedure;
	IndexBuildResult *stats;

	
	Assert(RelationIsValid(indexRelation));
	Assert(PointerIsValid(indexRelation->rd_am));

	procedure = indexRelation->rd_am->ambuild;
	Assert(RegProcedureIsValid(procedure));

	
	stats = (IndexBuildResult *)
		DatumGetPointer(OidFunctionCall3(procedure, PointerGetDatum(heapRelation), PointerGetDatum(indexRelation), PointerGetDatum(indexInfo)));


	Assert(PointerIsValid(stats));

	
	if (indexInfo->ii_BrokenHotChain)
	{
		Oid			indexId = RelationGetRelid(indexRelation);
		Relation	pg_index;
		HeapTuple	indexTuple;
		Form_pg_index indexForm;

		pg_index = heap_open(IndexRelationId, RowExclusiveLock);

		indexTuple = SearchSysCacheCopy(INDEXRELID, ObjectIdGetDatum(indexId), 0, 0, 0);

		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexId);
		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

		indexForm->indcheckxmin = true;
		simple_heap_update(pg_index, &indexTuple->t_self, indexTuple);
		CatalogUpdateIndexes(pg_index, indexTuple);

		heap_freetuple(indexTuple);
		heap_close(pg_index, RowExclusiveLock);
	}

	
	index_update_stats(heapRelation, true, isprimary, (heapRelation->rd_rel->relkind == RELKIND_TOASTVALUE) ? RelationGetRelid(indexRelation) : InvalidOid, stats->heap_tuples);





	index_update_stats(indexRelation, false, false, InvalidOid, stats->index_tuples);




	
	CommandCounterIncrement();
}



double IndexBuildHeapScan(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, IndexBuildCallback callback, void *callback_state)




{
	HeapScanDesc scan;
	HeapTuple	heapTuple;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];
	double		reltuples;
	List	   *predicate;
	TupleTableSlot *slot;
	EState	   *estate;
	ExprContext *econtext;
	Snapshot	snapshot;
	TransactionId OldestXmin;
	BlockNumber root_blkno = InvalidBlockNumber;
	OffsetNumber root_offsets[MaxHeapTuplesPerPage];

	
	Assert(OidIsValid(indexRelation->rd_rel->relam));

	
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(heapRelation));

	
	econtext->ecxt_scantuple = slot;

	
	predicate = (List *)
		ExecPrepareExpr((Expr *) indexInfo->ii_Predicate, estate);

	
	if (IsBootstrapProcessingMode())
	{
		snapshot = SnapshotNow;
		OldestXmin = InvalidTransactionId;		
	}
	else if (indexInfo->ii_Concurrent)
	{
		snapshot = CopySnapshot(GetTransactionSnapshot());
		OldestXmin = InvalidTransactionId;		
	}
	else {
		snapshot = SnapshotAny;
		
		OldestXmin = GetOldestXmin(heapRelation->rd_rel->relisshared, true);
	}

	scan = heap_beginscan(heapRelation,  snapshot, 0, NULL);



	reltuples = 0;

	
	while ((heapTuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		bool		tupleIsAlive;

		CHECK_FOR_INTERRUPTS();

		
		if (scan->rs_cblock != root_blkno)
		{
			Page		page = BufferGetPage(scan->rs_cbuf);

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
			heap_get_root_tuples(page, root_offsets);
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			root_blkno = scan->rs_cblock;
		}

		if (snapshot == SnapshotAny)
		{
			
			bool		indexIt;

	recheck:

			
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

			switch (HeapTupleSatisfiesVacuum(heapTuple->t_data, OldestXmin, scan->rs_cbuf))
			{
				case HEAPTUPLE_DEAD:
					
					indexIt = false;
					tupleIsAlive = false;
					break;
				case HEAPTUPLE_LIVE:
					
					indexIt = true;
					tupleIsAlive = true;
					break;
				case HEAPTUPLE_RECENTLY_DEAD:

					
					if (HeapTupleIsHotUpdated(heapTuple))
					{
						indexIt = false;
						
						indexInfo->ii_BrokenHotChain = true;
					}
					else if (indexInfo->ii_BrokenHotChain)
						indexIt = false;
					else indexIt = true;
					
					tupleIsAlive = false;
					break;
				case HEAPTUPLE_INSERT_IN_PROGRESS:

					
					if (!TransactionIdIsCurrentTransactionId( HeapTupleHeaderGetXmin(heapTuple->t_data)))
					{
						if (!IsSystemRelation(heapRelation))
							elog(ERROR, "concurrent insert in progress");
						else {
							
							TransactionId xwait = HeapTupleHeaderGetXmin(heapTuple->t_data);

							LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
							XactLockTableWait(xwait);
							goto recheck;
						}
					}

					
					indexIt = true;
					tupleIsAlive = true;
					break;
				case HEAPTUPLE_DELETE_IN_PROGRESS:

					
					Assert(!(heapTuple->t_data->t_infomask & HEAP_XMAX_IS_MULTI));
					if (!TransactionIdIsCurrentTransactionId( HeapTupleHeaderGetXmax(heapTuple->t_data)))
					{
						if (!IsSystemRelation(heapRelation))
							elog(ERROR, "concurrent delete in progress");
						else {
							
							TransactionId xwait = HeapTupleHeaderGetXmax(heapTuple->t_data);

							LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
							XactLockTableWait(xwait);
							goto recheck;
						}
					}

					
					if (HeapTupleIsHotUpdated(heapTuple))
					{
						indexIt = false;
						
						indexInfo->ii_BrokenHotChain = true;
					}
					else if (indexInfo->ii_BrokenHotChain)
						indexIt = false;
					else indexIt = true;
					
					tupleIsAlive = false;
					break;
				default:
					elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
					indexIt = tupleIsAlive = false;		
					break;
			}

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			if (!indexIt)
				continue;
		}
		else {
			
			tupleIsAlive = true;
		}

		reltuples += 1;

		MemoryContextReset(econtext->ecxt_per_tuple_memory);

		
		ExecStoreTuple(heapTuple, slot, InvalidBuffer, false);

		
		if (predicate != NIL)
		{
			if (!ExecQual(predicate, econtext, false))
				continue;
		}

		
		FormIndexDatum(indexInfo, slot, estate, values, isnull);




		

		if (HeapTupleIsHeapOnly(heapTuple))
		{
			
			HeapTupleData rootTuple;
			OffsetNumber offnum;

			rootTuple = *heapTuple;
			offnum = ItemPointerGetOffsetNumber(&heapTuple->t_self);

			Assert(OffsetNumberIsValid(root_offsets[offnum - 1]));

			ItemPointerSetOffsetNumber(&rootTuple.t_self, root_offsets[offnum - 1]);

			
			callback(indexRelation, &rootTuple, values, isnull, tupleIsAlive, callback_state);
		}
		else {
			
			callback(indexRelation, heapTuple, values, isnull, tupleIsAlive, callback_state);
		}
	}

	heap_endscan(scan);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NIL;

	return reltuples;
}



void validate_index(Oid heapId, Oid indexId, Snapshot snapshot)
{
	Relation	heapRelation, indexRelation;
	IndexInfo  *indexInfo;
	IndexVacuumInfo ivinfo;
	v_i_state	state;

	
	heapRelation = heap_open(heapId, ShareUpdateExclusiveLock);
	
	indexRelation = index_open(indexId, RowExclusiveLock);

	
	indexInfo = BuildIndexInfo(indexRelation);

	
	indexInfo->ii_Concurrent = true;

	
	ivinfo.index = indexRelation;
	ivinfo.vacuum_full = false;
	ivinfo.message_level = DEBUG2;
	ivinfo.num_heap_tuples = -1;
	ivinfo.strategy = NULL;

	state.tuplesort = tuplesort_begin_datum(TIDOID, TIDLessOperator, false, maintenance_work_mem, false);


	state.htups = state.itups = state.tups_inserted = 0;

	(void) index_bulk_delete(&ivinfo, NULL, validate_index_callback, (void *) &state);

	
	tuplesort_performsort(state.tuplesort);

	
	validate_index_heapscan(heapRelation, indexRelation, indexInfo, snapshot, &state);




	
	tuplesort_end(state.tuplesort);

	elog(DEBUG2, "validate_index found %.0f heap tuples, %.0f index tuples; inserted %.0f missing tuples", state.htups, state.itups, state.tups_inserted);


	
	index_close(indexRelation, NoLock);
	heap_close(heapRelation, NoLock);
}


static bool validate_index_callback(ItemPointer itemptr, void *opaque)
{
	v_i_state  *state = (v_i_state *) opaque;

	tuplesort_putdatum(state->tuplesort, PointerGetDatum(itemptr), false);
	state->itups += 1;
	return false;				
}


static void validate_index_heapscan(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, Snapshot snapshot, v_i_state *state)




{
	HeapScanDesc scan;
	HeapTuple	heapTuple;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];
	List	   *predicate;
	TupleTableSlot *slot;
	EState	   *estate;
	ExprContext *econtext;
	BlockNumber root_blkno = InvalidBlockNumber;
	OffsetNumber root_offsets[MaxHeapTuplesPerPage];
	bool		in_index[MaxHeapTuplesPerPage];

	
	ItemPointer indexcursor = NULL;
	bool		tuplesort_empty = false;

	
	Assert(OidIsValid(indexRelation->rd_rel->relam));

	
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(heapRelation));

	
	econtext->ecxt_scantuple = slot;

	
	predicate = (List *)
		ExecPrepareExpr((Expr *) indexInfo->ii_Predicate, estate);

	
	scan = heap_beginscan(heapRelation,  snapshot, 0, NULL);



	
	while ((heapTuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		ItemPointer heapcursor = &heapTuple->t_self;
		ItemPointerData rootTuple;
		OffsetNumber root_offnum;

		CHECK_FOR_INTERRUPTS();

		state->htups += 1;

		
		if (scan->rs_cblock != root_blkno)
		{
			Page		page = BufferGetPage(scan->rs_cbuf);

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
			heap_get_root_tuples(page, root_offsets);
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			memset(in_index, 0, sizeof(in_index));

			root_blkno = scan->rs_cblock;
		}

		
		rootTuple = *heapcursor;
		root_offnum = ItemPointerGetOffsetNumber(heapcursor);

		if (HeapTupleIsHeapOnly(heapTuple))
		{
			root_offnum = root_offsets[root_offnum - 1];
			Assert(OffsetNumberIsValid(root_offnum));
			ItemPointerSetOffsetNumber(&rootTuple, root_offnum);
		}

		
		while (!tuplesort_empty && (!indexcursor || ItemPointerCompare(indexcursor, &rootTuple) < 0))

		{
			Datum		ts_val;
			bool		ts_isnull;

			if (indexcursor)
			{
				
				if (ItemPointerGetBlockNumber(indexcursor) == root_blkno)
					in_index[ItemPointerGetOffsetNumber(indexcursor) - 1] = true;
				pfree(indexcursor);
			}

			tuplesort_empty = !tuplesort_getdatum(state->tuplesort, true, &ts_val, &ts_isnull);
			Assert(tuplesort_empty || !ts_isnull);
			indexcursor = (ItemPointer) DatumGetPointer(ts_val);
		}

		
		if ((tuplesort_empty || ItemPointerCompare(indexcursor, &rootTuple) > 0) && !in_index[root_offnum - 1])

		{
			MemoryContextReset(econtext->ecxt_per_tuple_memory);

			
			ExecStoreTuple(heapTuple, slot, InvalidBuffer, false);

			
			if (predicate != NIL)
			{
				if (!ExecQual(predicate, econtext, false))
					continue;
			}

			
			FormIndexDatum(indexInfo, slot, estate, values, isnull);




			

			

			index_insert(indexRelation, values, isnull, &rootTuple, heapRelation, indexInfo->ii_Unique);





			state->tups_inserted += 1;
		}
	}

	heap_endscan(scan);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NIL;
}



static Oid IndexGetRelation(Oid indexId)
{
	HeapTuple	tuple;
	Form_pg_index index;
	Oid			result;

	tuple = SearchSysCache(INDEXRELID, ObjectIdGetDatum(indexId), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for index %u", indexId);
	index = (Form_pg_index) GETSTRUCT(tuple);
	Assert(index->indexrelid == indexId);

	result = index->indrelid;
	ReleaseSysCache(tuple);
	return result;
}


void reindex_index(Oid indexId)
{
	Relation	iRel, heapRelation, pg_index;

	Oid			heapId;
	bool		inplace;
	HeapTuple	indexTuple;
	Form_pg_index indexForm;

	
	heapId = IndexGetRelation(indexId);
	heapRelation = heap_open(heapId, ShareLock);

	
	iRel = index_open(indexId, AccessExclusiveLock);

	
	inplace = iRel->rd_rel->relisshared;

	if (inplace && IsUnderPostmaster)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("shared index \"%s\" can only be reindexed in stand-alone mode", RelationGetRelationName(iRel))));



	PG_TRY();
	{
		IndexInfo  *indexInfo;

		
		SetReindexProcessing(heapId, indexId);

		
		indexInfo = BuildIndexInfo(iRel);

		if (inplace)
		{
			
			RelationTruncate(iRel, 0);
		}
		else {
			
			setNewRelfilenode(iRel, InvalidTransactionId);
		}

		
		
		index_build(heapRelation, iRel, indexInfo, false);
	}
	PG_CATCH();
	{
		
		ResetReindexProcessing();
		PG_RE_THROW();
	}
	PG_END_TRY();
	ResetReindexProcessing();

	
	pg_index = heap_open(IndexRelationId, RowExclusiveLock);

	indexTuple = SearchSysCacheCopy(INDEXRELID, ObjectIdGetDatum(indexId), 0, 0, 0);

	if (!HeapTupleIsValid(indexTuple))
		elog(ERROR, "cache lookup failed for index %u", indexId);
	indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

	if (!indexForm->indisvalid || !indexForm->indisready)
	{
		indexForm->indisvalid = true;
		indexForm->indisready = true;
		simple_heap_update(pg_index, &indexTuple->t_self, indexTuple);
		CatalogUpdateIndexes(pg_index, indexTuple);
	}
	heap_close(pg_index, RowExclusiveLock);

	
	index_close(iRel, NoLock);
	heap_close(heapRelation, NoLock);
}


bool reindex_relation(Oid relid, bool toast_too)
{
	Relation	rel;
	Oid			toast_relid;
	bool		is_pg_class;
	bool		result;
	List	   *indexIds, *doneIndexes;
	ListCell   *indexId;

	
	rel = heap_open(relid, ShareLock);

	toast_relid = rel->rd_rel->reltoastrelid;

	
	indexIds = RelationGetIndexList(rel);

	
	is_pg_class = (RelationGetRelid(rel) == RelationRelationId);
	doneIndexes = NIL;

	
	foreach(indexId, indexIds)
	{
		Oid			indexOid = lfirst_oid(indexId);

		if (is_pg_class)
			RelationSetIndexList(rel, doneIndexes, InvalidOid);

		reindex_index(indexOid);

		CommandCounterIncrement();

		if (is_pg_class)
			doneIndexes = lappend_oid(doneIndexes, indexOid);
	}

	if (is_pg_class)
		RelationSetIndexList(rel, indexIds, ClassOidIndexId);

	
	heap_close(rel, NoLock);

	result = (indexIds != NIL);

	
	if (toast_too && OidIsValid(toast_relid))
		result |= reindex_relation(toast_relid, false);

	return result;
}
