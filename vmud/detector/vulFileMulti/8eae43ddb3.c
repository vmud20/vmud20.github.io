



















































Oid			binary_upgrade_next_index_pg_class_oid = InvalidOid;


typedef struct {
	Tuplesortstate *tuplesort;	
	
	double		htups, itups, tups_inserted;

} v_i_state;


static bool relationHasPrimaryKey(Relation rel);
static TupleDesc ConstructTupleDescriptor(Relation heapRelation, IndexInfo *indexInfo, List *indexColNames, Oid accessMethodObjectId, Oid *collationObjectId, Oid *classObjectId);




static void InitializeAttributeOids(Relation indexRelation, int numatts, Oid indexoid);
static void AppendAttributeTuples(Relation indexRelation, int numatts);
static void UpdateIndexRelation(Oid indexoid, Oid heapoid, IndexInfo *indexInfo, Oid *collationOids, Oid *classOids, int16 *coloptions, bool primary, bool isexclusion, bool immediate, bool isvalid);







static void index_update_stats(Relation rel, bool hasindex, bool isprimary, double reltuples);

static void IndexCheckExclusion(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo);

static bool validate_index_callback(ItemPointer itemptr, void *opaque);
static void validate_index_heapscan(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, Snapshot snapshot, v_i_state *state);



static bool ReindexIsCurrentlyProcessingIndex(Oid indexOid);
static void SetReindexProcessing(Oid heapOid, Oid indexOid);
static void ResetReindexProcessing(void);
static void SetReindexPending(List *indexes);
static void RemoveReindexPending(Oid indexOid);
static void ResetReindexPending(void);



static bool relationHasPrimaryKey(Relation rel)
{
	bool		result = false;
	List	   *indexoidlist;
	ListCell   *indexoidscan;

	
	indexoidlist = RelationGetIndexList(rel);

	foreach(indexoidscan, indexoidlist)
	{
		Oid			indexoid = lfirst_oid(indexoidscan);
		HeapTuple	indexTuple;

		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexoid));
		if (!HeapTupleIsValid(indexTuple))		
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		result = ((Form_pg_index) GETSTRUCT(indexTuple))->indisprimary;
		ReleaseSysCache(indexTuple);
		if (result)
			break;
	}

	list_free(indexoidlist);

	return result;
}


void index_check_primary_key(Relation heapRel, IndexInfo *indexInfo, bool is_alter_table)


{
	List	   *cmds;
	int			i;

	
	if (is_alter_table && relationHasPrimaryKey(heapRel))
	{
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("multiple primary keys for table \"%s\" are not allowed", RelationGetRelationName(heapRel))));


	}

	
	cmds = NIL;
	for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
	{
		AttrNumber	attnum = indexInfo->ii_KeyAttrNumbers[i];
		HeapTuple	atttuple;
		Form_pg_attribute attform;

		if (attnum == 0)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("primary keys cannot be expressions")));


		
		if (attnum < 0)
			continue;

		atttuple = SearchSysCache2(ATTNUM, ObjectIdGetDatum(RelationGetRelid(heapRel)), Int16GetDatum(attnum));

		if (!HeapTupleIsValid(atttuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u", attnum, RelationGetRelid(heapRel));
		attform = (Form_pg_attribute) GETSTRUCT(atttuple);

		if (!attform->attnotnull)
		{
			
			AlterTableCmd *cmd = makeNode(AlterTableCmd);

			cmd->subtype = AT_SetNotNull;
			cmd->name = pstrdup(NameStr(attform->attname));
			cmds = lappend(cmds, cmd);
		}

		ReleaseSysCache(atttuple);
	}

	
	if (cmds)
		AlterTableInternal(RelationGetRelid(heapRel), cmds, false);
}


static TupleDesc ConstructTupleDescriptor(Relation heapRelation, IndexInfo *indexInfo, List *indexColNames, Oid accessMethodObjectId, Oid *collationObjectId, Oid *classObjectId)





{
	int			numatts = indexInfo->ii_NumIndexAttrs;
	ListCell   *colnames_item = list_head(indexColNames);
	ListCell   *indexpr_item = list_head(indexInfo->ii_Expressions);
	HeapTuple	amtuple;
	Form_pg_am	amform;
	TupleDesc	heapTupDesc;
	TupleDesc	indexTupDesc;
	int			natts;			
	int			i;

	
	amtuple = SearchSysCache1(AMOID, ObjectIdGetDatum(accessMethodObjectId));
	if (!HeapTupleIsValid(amtuple))
		elog(ERROR, "cache lookup failed for access method %u", accessMethodObjectId);
	amform = (Form_pg_am) GETSTRUCT(amtuple);

	
	heapTupDesc = RelationGetDescr(heapRelation);
	natts = RelationGetForm(heapRelation)->relnatts;

	
	indexTupDesc = CreateTemplateTupleDesc(numatts, false);

	
	for (i = 0; i < numatts; i++)
	{
		AttrNumber	atnum = indexInfo->ii_KeyAttrNumbers[i];
		Form_pg_attribute to = indexTupDesc->attrs[i];
		HeapTuple	tuple;
		Form_pg_type typeTup;
		Form_pg_opclass opclassTup;
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

			
			memcpy(to, from, ATTRIBUTE_FIXED_PART_SIZE);

			
			to->attnum = i + 1;

			to->attstattarget = -1;
			to->attcacheoff = -1;
			to->attnotnull = false;
			to->atthasdef = false;
			to->attislocal = true;
			to->attinhcount = 0;
			to->attcollation = collationObjectId[i];
		}
		else {
			
			Node	   *indexkey;

			MemSet(to, 0, ATTRIBUTE_FIXED_PART_SIZE);

			if (indexpr_item == NULL)	
				elog(ERROR, "too few entries in indexprs list");
			indexkey = (Node *) lfirst(indexpr_item);
			indexpr_item = lnext(indexpr_item);

			
			keyType = exprType(indexkey);
			tuple = SearchSysCache1(TYPEOID, ObjectIdGetDatum(keyType));
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
			to->attcollation = collationObjectId[i];

			ReleaseSysCache(tuple);

			
			CheckAttributeType(NameStr(to->attname), to->atttypid, to->attcollation, NIL, false);

		}

		
		to->attrelid = InvalidOid;

		
		if (colnames_item == NULL)		
			elog(ERROR, "too few entries in colnames list");
		namestrcpy(&to->attname, (const char *) lfirst(colnames_item));
		colnames_item = lnext(colnames_item);

		
		tuple = SearchSysCache1(CLAOID, ObjectIdGetDatum(classObjectId[i]));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for opclass %u", classObjectId[i]);
		opclassTup = (Form_pg_opclass) GETSTRUCT(tuple);
		if (OidIsValid(opclassTup->opckeytype))
			keyType = opclassTup->opckeytype;
		else keyType = amform->amkeytype;
		ReleaseSysCache(tuple);

		if (OidIsValid(keyType) && keyType != to->atttypid)
		{
			
			tuple = SearchSysCache1(TYPEOID, ObjectIdGetDatum(keyType));
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

	ReleaseSysCache(amtuple);

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
	int			i;

	
	pg_attribute = heap_open(AttributeRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(pg_attribute);

	
	indexTupDesc = RelationGetDescr(indexRelation);

	for (i = 0; i < numatts; i++)
	{
		
		Assert(indexTupDesc->attrs[i]->attnum == i + 1);
		Assert(indexTupDesc->attrs[i]->attcacheoff == -1);

		InsertPgAttributeTuple(pg_attribute, indexTupDesc->attrs[i], indstate);
	}

	CatalogCloseIndexes(indstate);

	heap_close(pg_attribute, RowExclusiveLock);
}


static void UpdateIndexRelation(Oid indexoid, Oid heapoid, IndexInfo *indexInfo, Oid *collationOids, Oid *classOids, int16 *coloptions, bool primary, bool isexclusion, bool immediate, bool isvalid)









{
	int2vector *indkey;
	oidvector  *indcollation;
	oidvector  *indclass;
	int2vector *indoption;
	Datum		exprsDatum;
	Datum		predDatum;
	Datum		values[Natts_pg_index];
	bool		nulls[Natts_pg_index];
	Relation	pg_index;
	HeapTuple	tuple;
	int			i;

	
	indkey = buildint2vector(NULL, indexInfo->ii_NumIndexAttrs);
	for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
		indkey->values[i] = indexInfo->ii_KeyAttrNumbers[i];
	indcollation = buildoidvector(collationOids, indexInfo->ii_NumIndexAttrs);
	indclass = buildoidvector(classOids, indexInfo->ii_NumIndexAttrs);
	indoption = buildint2vector(coloptions, indexInfo->ii_NumIndexAttrs);

	
	if (indexInfo->ii_Expressions != NIL)
	{
		char	   *exprsString;

		exprsString = nodeToString(indexInfo->ii_Expressions);
		exprsDatum = CStringGetTextDatum(exprsString);
		pfree(exprsString);
	}
	else exprsDatum = (Datum) 0;

	
	if (indexInfo->ii_Predicate != NIL)
	{
		char	   *predString;

		predString = nodeToString(make_ands_explicit(indexInfo->ii_Predicate));
		predDatum = CStringGetTextDatum(predString);
		pfree(predString);
	}
	else predDatum = (Datum) 0;

	
	pg_index = heap_open(IndexRelationId, RowExclusiveLock);

	
	MemSet(nulls, false, sizeof(nulls));

	values[Anum_pg_index_indexrelid - 1] = ObjectIdGetDatum(indexoid);
	values[Anum_pg_index_indrelid - 1] = ObjectIdGetDatum(heapoid);
	values[Anum_pg_index_indnatts - 1] = Int16GetDatum(indexInfo->ii_NumIndexAttrs);
	values[Anum_pg_index_indisunique - 1] = BoolGetDatum(indexInfo->ii_Unique);
	values[Anum_pg_index_indisprimary - 1] = BoolGetDatum(primary);
	values[Anum_pg_index_indisexclusion - 1] = BoolGetDatum(isexclusion);
	values[Anum_pg_index_indimmediate - 1] = BoolGetDatum(immediate);
	values[Anum_pg_index_indisclustered - 1] = BoolGetDatum(false);
	values[Anum_pg_index_indisvalid - 1] = BoolGetDatum(isvalid);
	values[Anum_pg_index_indcheckxmin - 1] = BoolGetDatum(false);
	
	values[Anum_pg_index_indisready - 1] = BoolGetDatum(isvalid);
	values[Anum_pg_index_indislive - 1] = BoolGetDatum(true);
	values[Anum_pg_index_indisreplident - 1] = BoolGetDatum(false);
	values[Anum_pg_index_indkey - 1] = PointerGetDatum(indkey);
	values[Anum_pg_index_indcollation - 1] = PointerGetDatum(indcollation);
	values[Anum_pg_index_indclass - 1] = PointerGetDatum(indclass);
	values[Anum_pg_index_indoption - 1] = PointerGetDatum(indoption);
	values[Anum_pg_index_indexprs - 1] = exprsDatum;
	if (exprsDatum == (Datum) 0)
		nulls[Anum_pg_index_indexprs - 1] = true;
	values[Anum_pg_index_indpred - 1] = predDatum;
	if (predDatum == (Datum) 0)
		nulls[Anum_pg_index_indpred - 1] = true;

	tuple = heap_form_tuple(RelationGetDescr(pg_index), values, nulls);

	
	simple_heap_insert(pg_index, tuple);

	
	CatalogUpdateIndexes(pg_index, tuple);

	
	heap_close(pg_index, RowExclusiveLock);
	heap_freetuple(tuple);
}



Oid index_create(Relation heapRelation, const char *indexRelationName, Oid indexRelationId, Oid relFileNode, IndexInfo *indexInfo, List *indexColNames, Oid accessMethodObjectId, Oid tableSpaceId, Oid *collationObjectId, Oid *classObjectId, int16 *coloptions, Datum reloptions, bool isprimary, bool isconstraint, bool deferrable, bool initdeferred, bool allow_system_table_mods, bool skip_build, bool concurrent, bool is_internal)



















{
	Oid			heapRelationId = RelationGetRelid(heapRelation);
	Relation	pg_class;
	Relation	indexRelation;
	TupleDesc	indexTupDesc;
	bool		shared_relation;
	bool		mapped_relation;
	bool		is_exclusion;
	Oid			namespaceId;
	int			i;
	char		relpersistence;

	is_exclusion = (indexInfo->ii_ExclusionOps != NULL);

	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	
	namespaceId = RelationGetNamespace(heapRelation);
	shared_relation = heapRelation->rd_rel->relisshared;
	mapped_relation = RelationIsMapped(heapRelation);
	relpersistence = heapRelation->rd_rel->relpersistence;

	
	if (indexInfo->ii_NumIndexAttrs < 1)
		elog(ERROR, "must index at least one column");

	if (!allow_system_table_mods && IsSystemRelation(heapRelation) && IsNormalProcessingMode())

		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("user-defined indexes on system catalog tables are not supported")));


	
	if (concurrent && IsSystemRelation(heapRelation))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("concurrent index creation on system catalog tables is not supported")));


	
	if (concurrent && is_exclusion)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg_internal("concurrent index creation for exclusion constraints is not supported")));


	
	if (shared_relation && !IsBootstrapProcessingMode())
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("shared indexes cannot be created after initdb")));


	
	if (shared_relation && tableSpaceId != GLOBALTABLESPACE_OID)
		elog(ERROR, "shared relations must be placed in pg_global tablespace");

	if (get_relname_relid(indexRelationName, namespaceId))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists", indexRelationName)));



	
	indexTupDesc = ConstructTupleDescriptor(heapRelation, indexInfo, indexColNames, accessMethodObjectId, collationObjectId, classObjectId);





	
	if (!OidIsValid(indexRelationId))
	{
		
		if (IsBinaryUpgrade && OidIsValid(binary_upgrade_next_index_pg_class_oid))
		{
			indexRelationId = binary_upgrade_next_index_pg_class_oid;
			binary_upgrade_next_index_pg_class_oid = InvalidOid;
		}
		else {
			indexRelationId = GetNewRelFileNode(tableSpaceId, pg_class, relpersistence);
		}
	}

	
	indexRelation = heap_create(indexRelationName, namespaceId, tableSpaceId, indexRelationId, relFileNode, indexTupDesc, RELKIND_INDEX, relpersistence, shared_relation, mapped_relation, allow_system_table_mods);










	Assert(indexRelationId == RelationGetRelid(indexRelation));

	
	LockRelation(indexRelation, AccessExclusiveLock);

	
	indexRelation->rd_rel->relowner = heapRelation->rd_rel->relowner;
	indexRelation->rd_rel->relam = accessMethodObjectId;
	indexRelation->rd_rel->relhasoids = false;

	
	InsertPgClassTuple(pg_class, indexRelation, RelationGetRelid(indexRelation), (Datum) 0, reloptions);



	
	heap_close(pg_class, RowExclusiveLock);

	
	InitializeAttributeOids(indexRelation, indexInfo->ii_NumIndexAttrs, indexRelationId);


	
	AppendAttributeTuples(indexRelation, indexInfo->ii_NumIndexAttrs);

	
	UpdateIndexRelation(indexRelationId, heapRelationId, indexInfo, collationObjectId, classObjectId, coloptions, isprimary, is_exclusion, !deferrable, !concurrent);




	
	if (!IsBootstrapProcessingMode())
	{
		ObjectAddress myself, referenced;

		myself.classId = RelationRelationId;
		myself.objectId = indexRelationId;
		myself.objectSubId = 0;

		if (isconstraint)
		{
			char		constraintType;

			if (isprimary)
				constraintType = CONSTRAINT_PRIMARY;
			else if (indexInfo->ii_Unique)
				constraintType = CONSTRAINT_UNIQUE;
			else if (is_exclusion)
				constraintType = CONSTRAINT_EXCLUSION;
			else {
				elog(ERROR, "constraint must be PRIMARY, UNIQUE or EXCLUDE");
				constraintType = 0;		
			}

			index_constraint_create(heapRelation, indexRelationId, indexInfo, indexRelationName, constraintType, deferrable, initdeferred, false, false, false, allow_system_table_mods, is_internal);










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

			
			if (!have_simple_col)
			{
				referenced.classId = RelationRelationId;
				referenced.objectId = heapRelationId;
				referenced.objectSubId = 0;

				recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);
			}

			
			Assert(!deferrable);
			Assert(!initdeferred);
		}

		
		
		for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
		{
			if (OidIsValid(collationObjectId[i]) && collationObjectId[i] != DEFAULT_COLLATION_OID)
			{
				referenced.classId = CollationRelationId;
				referenced.objectId = collationObjectId[i];
				referenced.objectSubId = 0;

				recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
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
	else {
		
		Assert(!isconstraint);
		Assert(!deferrable);
		Assert(!initdeferred);
	}

	
	InvokeObjectPostCreateHookArg(RelationRelationId, indexRelationId, 0, is_internal);

	
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
		
		index_update_stats(heapRelation, true, isprimary, -1.0);


		
		CommandCounterIncrement();
	}
	else {
		index_build(heapRelation, indexRelation, indexInfo, isprimary, false);
	}

	
	index_close(indexRelation, NoLock);

	return indexRelationId;
}


void index_constraint_create(Relation heapRelation, Oid indexRelationId, IndexInfo *indexInfo, const char *constraintName, char constraintType, bool deferrable, bool initdeferred, bool mark_as_primary, bool update_pgindex, bool remove_old_dependencies, bool allow_system_table_mods, bool is_internal)











{
	Oid			namespaceId = RelationGetNamespace(heapRelation);
	ObjectAddress myself, referenced;
	Oid			conOid;

	
	Assert(!IsBootstrapProcessingMode());

	
	if (!allow_system_table_mods && IsSystemRelation(heapRelation) && IsNormalProcessingMode())

		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("user-defined indexes on system catalog tables are not supported")));


	
	if (indexInfo->ii_Expressions && constraintType != CONSTRAINT_EXCLUSION)
		elog(ERROR, "constraints cannot have index expressions");

	
	if (remove_old_dependencies)
		deleteDependencyRecordsForClass(RelationRelationId, indexRelationId, RelationRelationId, DEPENDENCY_AUTO);

	
	conOid = CreateConstraintEntry(constraintName, namespaceId, constraintType, deferrable, initdeferred, true, RelationGetRelid(heapRelation), indexInfo->ii_KeyAttrNumbers, indexInfo->ii_NumIndexAttrs, InvalidOid, indexRelationId, InvalidOid, NULL, NULL, NULL, NULL, 0, ' ', ' ', ' ', indexInfo->ii_ExclusionOps, NULL, NULL, NULL, true, 0, true, is_internal);



























	
	myself.classId = RelationRelationId;
	myself.objectId = indexRelationId;
	myself.objectSubId = 0;

	referenced.classId = ConstraintRelationId;
	referenced.objectId = conOid;
	referenced.objectSubId = 0;

	recordDependencyOn(&myself, &referenced, DEPENDENCY_INTERNAL);

	
	if (deferrable)
	{
		RangeVar   *heapRel;
		CreateTrigStmt *trigger;

		heapRel = makeRangeVar(get_namespace_name(namespaceId), pstrdup(RelationGetRelationName(heapRelation)), -1);


		trigger = makeNode(CreateTrigStmt);
		trigger->trigname = (constraintType == CONSTRAINT_PRIMARY) ? "PK_ConstraintTrigger" :
			"Unique_ConstraintTrigger";
		trigger->relation = heapRel;
		trigger->funcname = SystemFuncName("unique_key_recheck");
		trigger->args = NIL;
		trigger->row = true;
		trigger->timing = TRIGGER_TYPE_AFTER;
		trigger->events = TRIGGER_TYPE_INSERT | TRIGGER_TYPE_UPDATE;
		trigger->columns = NIL;
		trigger->whenClause = NULL;
		trigger->isconstraint = true;
		trigger->deferrable = true;
		trigger->initdeferred = initdeferred;
		trigger->constrrel = NULL;

		(void) CreateTrigger(trigger, NULL, conOid, indexRelationId, true);
	}

	
	if (mark_as_primary)
		index_update_stats(heapRelation, true, true, -1.0);



	
	if (update_pgindex && (mark_as_primary || deferrable))
	{
		Relation	pg_index;
		HeapTuple	indexTuple;
		Form_pg_index indexForm;
		bool		dirty = false;

		pg_index = heap_open(IndexRelationId, RowExclusiveLock);

		indexTuple = SearchSysCacheCopy1(INDEXRELID, ObjectIdGetDatum(indexRelationId));
		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexRelationId);
		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

		if (mark_as_primary && !indexForm->indisprimary)
		{
			indexForm->indisprimary = true;
			dirty = true;
		}

		if (deferrable && indexForm->indimmediate)
		{
			indexForm->indimmediate = false;
			dirty = true;
		}

		if (dirty)
		{
			simple_heap_update(pg_index, &indexTuple->t_self, indexTuple);
			CatalogUpdateIndexes(pg_index, indexTuple);

			InvokeObjectPostAlterHookArg(IndexRelationId, indexRelationId, 0, InvalidOid, is_internal);
		}

		heap_freetuple(indexTuple);
		heap_close(pg_index, RowExclusiveLock);
	}
}


void index_drop(Oid indexId, bool concurrent)
{
	Oid			heapId;
	Relation	userHeapRelation;
	Relation	userIndexRelation;
	Relation	indexRelation;
	HeapTuple	tuple;
	bool		hasexprs;
	LockRelId	heaprelid, indexrelid;
	LOCKTAG		heaplocktag;
	LOCKMODE	lockmode;

	
	heapId = IndexGetRelation(indexId, false);
	lockmode = concurrent ? ShareUpdateExclusiveLock : AccessExclusiveLock;
	userHeapRelation = heap_open(heapId, lockmode);
	userIndexRelation = index_open(indexId, lockmode);

	
	CheckTableNotInUse(userIndexRelation, "DROP INDEX");

	
	if (concurrent)
	{
		
		if (GetTopTransactionIdIfAny() != InvalidTransactionId)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("DROP INDEX CONCURRENTLY must be first action in transaction")));


		
		index_set_state_flags(indexId, INDEX_DROP_CLEAR_VALID);

		
		CacheInvalidateRelcache(userHeapRelation);

		
		heaprelid = userHeapRelation->rd_lockInfo.lockRelId;
		SET_LOCKTAG_RELATION(heaplocktag, heaprelid.dbId, heaprelid.relId);
		indexrelid = userIndexRelation->rd_lockInfo.lockRelId;

		heap_close(userHeapRelation, NoLock);
		index_close(userIndexRelation, NoLock);

		
		LockRelationIdForSession(&heaprelid, ShareUpdateExclusiveLock);
		LockRelationIdForSession(&indexrelid, ShareUpdateExclusiveLock);

		PopActiveSnapshot();
		CommitTransactionCommand();
		StartTransactionCommand();

		
		WaitForLockers(heaplocktag, AccessExclusiveLock);

		
		userHeapRelation = heap_open(heapId, ShareUpdateExclusiveLock);
		userIndexRelation = index_open(indexId, ShareUpdateExclusiveLock);
		TransferPredicateLocksToHeapRelation(userIndexRelation);

		
		index_set_state_flags(indexId, INDEX_DROP_SET_DEAD);

		
		CacheInvalidateRelcache(userHeapRelation);

		
		heap_close(userHeapRelation, NoLock);
		index_close(userIndexRelation, NoLock);

		
		CommitTransactionCommand();
		StartTransactionCommand();

		
		WaitForLockers(heaplocktag, AccessExclusiveLock);

		
		userHeapRelation = heap_open(heapId, ShareUpdateExclusiveLock);
		userIndexRelation = index_open(indexId, AccessExclusiveLock);
	}
	else {
		
		TransferPredicateLocksToHeapRelation(userIndexRelation);
	}

	
	RelationDropStorage(userIndexRelation);

	
	index_close(userIndexRelation, NoLock);

	RelationForgetRelation(indexId);

	
	indexRelation = heap_open(IndexRelationId, RowExclusiveLock);

	tuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexId));
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

	
	if (concurrent)
	{
		UnlockRelationIdForSession(&heaprelid, ShareUpdateExclusiveLock);
		UnlockRelationIdForSession(&indexrelid, ShareUpdateExclusiveLock);
	}
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

	
	if (indexStruct->indisexclusion)
	{
		RelationGetExclusionInfo(index, &ii->ii_ExclusionOps, &ii->ii_ExclusionProcs, &ii->ii_ExclusionStrats);


	}
	else {
		ii->ii_ExclusionOps = NULL;
		ii->ii_ExclusionProcs = NULL;
		ii->ii_ExclusionStrats = NULL;
	}

	
	ii->ii_Unique = indexStruct->indisunique;
	ii->ii_ReadyForInserts = IndexIsReady(indexStruct);

	
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



static void index_update_stats(Relation rel, bool hasindex, bool isprimary, double reltuples)



{
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



		pg_class_scan = heap_beginscan_catalog(pg_class, 1, key);
		tuple = heap_getnext(pg_class_scan, ForwardScanDirection);
		tuple = heap_copytuple(tuple);
		heap_endscan(pg_class_scan);
	}
	else {
		
		tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(relid));
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

	if (reltuples >= 0)
	{
		BlockNumber relpages = RelationGetNumberOfBlocks(rel);
		BlockNumber relallvisible;

		if (rd_rel->relkind != RELKIND_INDEX)
			relallvisible = visibilitymap_count(rel);
		else	 relallvisible = 0;

		if (rd_rel->relpages != (int32) relpages)
		{
			rd_rel->relpages = (int32) relpages;
			dirty = true;
		}
		if (rd_rel->reltuples != (float4) reltuples)
		{
			rd_rel->reltuples = (float4) reltuples;
			dirty = true;
		}
		if (rd_rel->relallvisible != (int32) relallvisible)
		{
			rd_rel->relallvisible = (int32) relallvisible;
			dirty = true;
		}
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



void index_build(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, bool isprimary, bool isreindex)




{
	RegProcedure procedure;
	IndexBuildResult *stats;
	Oid			save_userid;
	int			save_sec_context;
	int			save_nestlevel;

	
	Assert(RelationIsValid(indexRelation));
	Assert(PointerIsValid(indexRelation->rd_am));

	procedure = indexRelation->rd_am->ambuild;
	Assert(RegProcedureIsValid(procedure));

	ereport(DEBUG1, (errmsg("building index \"%s\" on table \"%s\"", RelationGetRelationName(indexRelation), RelationGetRelationName(heapRelation))));



	
	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	SetUserIdAndSecContext(heapRelation->rd_rel->relowner, save_sec_context | SECURITY_RESTRICTED_OPERATION);
	save_nestlevel = NewGUCNestLevel();

	
	stats = (IndexBuildResult *)
		DatumGetPointer(OidFunctionCall3(procedure, PointerGetDatum(heapRelation), PointerGetDatum(indexRelation), PointerGetDatum(indexInfo)));


	Assert(PointerIsValid(stats));

	
	if (heapRelation->rd_rel->relpersistence == RELPERSISTENCE_UNLOGGED && !smgrexists(indexRelation->rd_smgr, INIT_FORKNUM))
	{
		RegProcedure ambuildempty = indexRelation->rd_am->ambuildempty;

		RelationOpenSmgr(indexRelation);
		smgrcreate(indexRelation->rd_smgr, INIT_FORKNUM, false);
		OidFunctionCall1(ambuildempty, PointerGetDatum(indexRelation));
	}

	
	if (indexInfo->ii_BrokenHotChain && !isreindex && !indexInfo->ii_Concurrent)
	{
		Oid			indexId = RelationGetRelid(indexRelation);
		Relation	pg_index;
		HeapTuple	indexTuple;
		Form_pg_index indexForm;

		pg_index = heap_open(IndexRelationId, RowExclusiveLock);

		indexTuple = SearchSysCacheCopy1(INDEXRELID, ObjectIdGetDatum(indexId));
		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexId);
		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

		
		Assert(!indexForm->indcheckxmin);

		indexForm->indcheckxmin = true;
		simple_heap_update(pg_index, &indexTuple->t_self, indexTuple);
		CatalogUpdateIndexes(pg_index, indexTuple);

		heap_freetuple(indexTuple);
		heap_close(pg_index, RowExclusiveLock);
	}

	
	index_update_stats(heapRelation, true, isprimary, stats->heap_tuples);



	index_update_stats(indexRelation, false, false, stats->index_tuples);



	
	CommandCounterIncrement();

	
	if (indexInfo->ii_ExclusionOps != NULL)
		IndexCheckExclusion(heapRelation, indexRelation, indexInfo);

	
	AtEOXact_GUC(false, save_nestlevel);

	
	SetUserIdAndSecContext(save_userid, save_sec_context);
}



double IndexBuildHeapScan(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo, bool allow_sync, IndexBuildCallback callback, void *callback_state)





{
	bool		is_system_catalog;
	bool		checking_uniqueness;
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

	
	is_system_catalog = IsSystemRelation(heapRelation);

	
	checking_uniqueness = (indexInfo->ii_Unique || indexInfo->ii_ExclusionOps != NULL);

	
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(heapRelation));

	
	econtext->ecxt_scantuple = slot;

	
	predicate = (List *)
		ExecPrepareExpr((Expr *) indexInfo->ii_Predicate, estate);

	
	if (IsBootstrapProcessingMode() || indexInfo->ii_Concurrent)
	{
		snapshot = RegisterSnapshot(GetTransactionSnapshot());
		OldestXmin = InvalidTransactionId;		
	}
	else {
		snapshot = SnapshotAny;
		
		OldestXmin = GetOldestXmin(heapRelation->rd_rel->relisshared, true);
	}

	scan = heap_beginscan_strat(heapRelation,	 snapshot, 0, NULL, true, allow_sync);





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
			TransactionId xwait;

	recheck:

			
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

			switch (HeapTupleSatisfiesVacuum(heapTuple, OldestXmin, scan->rs_cbuf))
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
					else indexIt = true;
					
					tupleIsAlive = false;
					break;
				case HEAPTUPLE_INSERT_IN_PROGRESS:

					
					xwait = HeapTupleHeaderGetXmin(heapTuple->t_data);
					if (!TransactionIdIsCurrentTransactionId(xwait))
					{
						if (!is_system_catalog)
							elog(WARNING, "concurrent insert in progress within table \"%s\"", RelationGetRelationName(heapRelation));

						
						if (checking_uniqueness)
						{
							
							LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
							XactLockTableWait(xwait);
							goto recheck;
						}
					}

					
					indexIt = true;
					tupleIsAlive = true;
					break;
				case HEAPTUPLE_DELETE_IN_PROGRESS:

					
					xwait = HeapTupleHeaderGetUpdateXid(heapTuple->t_data);
					if (!TransactionIdIsCurrentTransactionId(xwait))
					{
						if (!is_system_catalog)
							elog(WARNING, "concurrent delete in progress within table \"%s\"", RelationGetRelationName(heapRelation));

						
						if (checking_uniqueness || HeapTupleIsHotUpdated(heapTuple))
						{
							
							LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
							XactLockTableWait(xwait);
							goto recheck;
						}

						
						indexIt = true;
					}
					else if (HeapTupleIsHotUpdated(heapTuple))
					{
						
						indexIt = false;
						
						indexInfo->ii_BrokenHotChain = true;
					}
					else {
						
						indexIt = true;
					}
					
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

	
	if (IsBootstrapProcessingMode() || indexInfo->ii_Concurrent)
		UnregisterSnapshot(snapshot);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NIL;

	return reltuples;
}



static void IndexCheckExclusion(Relation heapRelation, Relation indexRelation, IndexInfo *indexInfo)


{
	HeapScanDesc scan;
	HeapTuple	heapTuple;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];
	List	   *predicate;
	TupleTableSlot *slot;
	EState	   *estate;
	ExprContext *econtext;
	Snapshot	snapshot;

	
	if (ReindexIsCurrentlyProcessingIndex(RelationGetRelid(indexRelation)))
		ResetReindexProcessing();

	
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(heapRelation));

	
	econtext->ecxt_scantuple = slot;

	
	predicate = (List *)
		ExecPrepareExpr((Expr *) indexInfo->ii_Predicate, estate);

	
	snapshot = RegisterSnapshot(GetLatestSnapshot());
	scan = heap_beginscan_strat(heapRelation,	 snapshot, 0, NULL, true, true);





	while ((heapTuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		CHECK_FOR_INTERRUPTS();

		MemoryContextReset(econtext->ecxt_per_tuple_memory);

		
		ExecStoreTuple(heapTuple, slot, InvalidBuffer, false);

		
		if (predicate != NIL)
		{
			if (!ExecQual(predicate, econtext, false))
				continue;
		}

		
		FormIndexDatum(indexInfo, slot, estate, values, isnull);




		
		check_exclusion_constraint(heapRelation, indexRelation, indexInfo, &(heapTuple->t_self), values, isnull, estate, true, false);


	}

	heap_endscan(scan);
	UnregisterSnapshot(snapshot);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NIL;
}



void validate_index(Oid heapId, Oid indexId, Snapshot snapshot)
{
	Relation	heapRelation, indexRelation;
	IndexInfo  *indexInfo;
	IndexVacuumInfo ivinfo;
	v_i_state	state;
	Oid			save_userid;
	int			save_sec_context;
	int			save_nestlevel;

	
	heapRelation = heap_open(heapId, ShareUpdateExclusiveLock);
	
	indexRelation = index_open(indexId, RowExclusiveLock);

	
	indexInfo = BuildIndexInfo(indexRelation);

	
	indexInfo->ii_Concurrent = true;

	
	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	SetUserIdAndSecContext(heapRelation->rd_rel->relowner, save_sec_context | SECURITY_RESTRICTED_OPERATION);
	save_nestlevel = NewGUCNestLevel();

	
	ivinfo.index = indexRelation;
	ivinfo.analyze_only = false;
	ivinfo.estimated_count = true;
	ivinfo.message_level = DEBUG2;
	ivinfo.num_heap_tuples = heapRelation->rd_rel->reltuples;
	ivinfo.strategy = NULL;

	state.tuplesort = tuplesort_begin_datum(TIDOID, TIDLessOperator, InvalidOid, false, maintenance_work_mem, false);


	state.htups = state.itups = state.tups_inserted = 0;

	(void) index_bulk_delete(&ivinfo, NULL, validate_index_callback, (void *) &state);

	
	tuplesort_performsort(state.tuplesort);

	
	validate_index_heapscan(heapRelation, indexRelation, indexInfo, snapshot, &state);




	
	tuplesort_end(state.tuplesort);

	elog(DEBUG2, "validate_index found %.0f heap tuples, %.0f index tuples; inserted %.0f missing tuples", state.htups, state.itups, state.tups_inserted);


	
	AtEOXact_GUC(false, save_nestlevel);

	
	SetUserIdAndSecContext(save_userid, save_sec_context);

	
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

	
	scan = heap_beginscan_strat(heapRelation,	 snapshot, 0, NULL, true, false);





	
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




			

			

			index_insert(indexRelation, values, isnull, &rootTuple, heapRelation, indexInfo->ii_Unique ? UNIQUE_CHECK_YES : UNIQUE_CHECK_NO);






			state->tups_inserted += 1;
		}
	}

	heap_endscan(scan);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NIL;
}



void index_set_state_flags(Oid indexId, IndexStateFlagsAction action)
{
	Relation	pg_index;
	HeapTuple	indexTuple;
	Form_pg_index indexForm;

	
	Assert(GetTopTransactionIdIfAny() == InvalidTransactionId);

	
	pg_index = heap_open(IndexRelationId, RowExclusiveLock);

	indexTuple = SearchSysCacheCopy1(INDEXRELID, ObjectIdGetDatum(indexId));
	if (!HeapTupleIsValid(indexTuple))
		elog(ERROR, "cache lookup failed for index %u", indexId);
	indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

	
	switch (action)
	{
		case INDEX_CREATE_SET_READY:
			
			Assert(indexForm->indislive);
			Assert(!indexForm->indisready);
			Assert(!indexForm->indisvalid);
			indexForm->indisready = true;
			break;
		case INDEX_CREATE_SET_VALID:
			
			Assert(indexForm->indislive);
			Assert(indexForm->indisready);
			Assert(!indexForm->indisvalid);
			indexForm->indisvalid = true;
			break;
		case INDEX_DROP_CLEAR_VALID:

			
			indexForm->indisvalid = false;
			indexForm->indisclustered = false;
			break;
		case INDEX_DROP_SET_DEAD:

			
			Assert(!indexForm->indisvalid);
			indexForm->indisready = false;
			indexForm->indislive = false;
			break;
	}

	
	heap_inplace_update(pg_index, indexTuple);

	heap_close(pg_index, RowExclusiveLock);
}



Oid IndexGetRelation(Oid indexId, bool missing_ok)
{
	HeapTuple	tuple;
	Form_pg_index index;
	Oid			result;

	tuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexId));
	if (!HeapTupleIsValid(tuple))
	{
		if (missing_ok)
			return InvalidOid;
		elog(ERROR, "cache lookup failed for index %u", indexId);
	}
	index = (Form_pg_index) GETSTRUCT(tuple);
	Assert(index->indexrelid == indexId);

	result = index->indrelid;
	ReleaseSysCache(tuple);
	return result;
}


void reindex_index(Oid indexId, bool skip_constraint_checks)
{
	Relation	iRel, heapRelation;
	Oid			heapId;
	IndexInfo  *indexInfo;
	volatile bool skipped_constraint = false;

	
	heapId = IndexGetRelation(indexId, false);
	heapRelation = heap_open(heapId, ShareLock);

	
	iRel = index_open(indexId, AccessExclusiveLock);

	
	if (RELATION_IS_OTHER_TEMP(iRel))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot reindex temporary tables of other sessions")));


	
	CheckTableNotInUse(iRel, "REINDEX INDEX");

	
	TransferPredicateLocksToHeapRelation(iRel);

	PG_TRY();
	{
		
		SetReindexProcessing(heapId, indexId);

		
		indexInfo = BuildIndexInfo(iRel);

		
		if (skip_constraint_checks)
		{
			if (indexInfo->ii_Unique || indexInfo->ii_ExclusionOps != NULL)
				skipped_constraint = true;
			indexInfo->ii_Unique = false;
			indexInfo->ii_ExclusionOps = NULL;
			indexInfo->ii_ExclusionProcs = NULL;
			indexInfo->ii_ExclusionStrats = NULL;
		}

		
		RelationSetNewRelfilenode(iRel, InvalidTransactionId, InvalidMultiXactId);

		
		
		index_build(heapRelation, iRel, indexInfo, false, true);
	}
	PG_CATCH();
	{
		
		ResetReindexProcessing();
		PG_RE_THROW();
	}
	PG_END_TRY();
	ResetReindexProcessing();

	
	if (!skipped_constraint)
	{
		Relation	pg_index;
		HeapTuple	indexTuple;
		Form_pg_index indexForm;
		bool		index_bad;

		pg_index = heap_open(IndexRelationId, RowExclusiveLock);

		indexTuple = SearchSysCacheCopy1(INDEXRELID, ObjectIdGetDatum(indexId));
		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexId);
		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

		index_bad = (!indexForm->indisvalid || !indexForm->indisready || !indexForm->indislive);

		if (index_bad || (indexForm->indcheckxmin && !indexInfo->ii_BrokenHotChain))
		{
			if (!indexInfo->ii_BrokenHotChain)
				indexForm->indcheckxmin = false;
			else if (index_bad)
				indexForm->indcheckxmin = true;
			indexForm->indisvalid = true;
			indexForm->indisready = true;
			indexForm->indislive = true;
			simple_heap_update(pg_index, &indexTuple->t_self, indexTuple);
			CatalogUpdateIndexes(pg_index, indexTuple);

			
			CacheInvalidateRelcache(heapRelation);
		}

		heap_close(pg_index, RowExclusiveLock);
	}

	
	index_close(iRel, NoLock);
	heap_close(heapRelation, NoLock);
}


bool reindex_relation(Oid relid, int flags)
{
	Relation	rel;
	Oid			toast_relid;
	List	   *indexIds;
	bool		is_pg_class;
	bool		result;

	
	rel = heap_open(relid, ShareLock);

	toast_relid = rel->rd_rel->reltoastrelid;

	
	indexIds = RelationGetIndexList(rel);

	
	is_pg_class = (RelationGetRelid(rel) == RelationRelationId);

	
	if (is_pg_class)
		(void) RelationGetIndexAttrBitmap(rel, INDEX_ATTR_BITMAP_ALL);

	PG_TRY();
	{
		List	   *doneIndexes;
		ListCell   *indexId;

		if (flags & REINDEX_REL_SUPPRESS_INDEX_USE)
		{
			
			SetReindexPending(indexIds);

			
			CommandCounterIncrement();
		}

		
		doneIndexes = NIL;
		foreach(indexId, indexIds)
		{
			Oid			indexOid = lfirst_oid(indexId);

			if (is_pg_class)
				RelationSetIndexList(rel, doneIndexes, InvalidOid);

			reindex_index(indexOid, !(flags & REINDEX_REL_CHECK_CONSTRAINTS));

			CommandCounterIncrement();

			
			Assert(!ReindexIsProcessingIndex(indexOid));

			if (is_pg_class)
				doneIndexes = lappend_oid(doneIndexes, indexOid);
		}
	}
	PG_CATCH();
	{
		
		ResetReindexPending();
		PG_RE_THROW();
	}
	PG_END_TRY();
	ResetReindexPending();

	if (is_pg_class)
		RelationSetIndexList(rel, indexIds, ClassOidIndexId);

	
	heap_close(rel, NoLock);

	result = (indexIds != NIL);

	
	if ((flags & REINDEX_REL_PROCESS_TOAST) && OidIsValid(toast_relid))
		result |= reindex_relation(toast_relid, flags);

	return result;
}




static Oid	currentlyReindexedHeap = InvalidOid;
static Oid	currentlyReindexedIndex = InvalidOid;
static List *pendingReindexedIndexes = NIL;


bool ReindexIsProcessingHeap(Oid heapOid)
{
	return heapOid == currentlyReindexedHeap;
}


static bool ReindexIsCurrentlyProcessingIndex(Oid indexOid)
{
	return indexOid == currentlyReindexedIndex;
}


bool ReindexIsProcessingIndex(Oid indexOid)
{
	return indexOid == currentlyReindexedIndex || list_member_oid(pendingReindexedIndexes, indexOid);
}


static void SetReindexProcessing(Oid heapOid, Oid indexOid)
{
	Assert(OidIsValid(heapOid) && OidIsValid(indexOid));
	
	if (OidIsValid(currentlyReindexedHeap))
		elog(ERROR, "cannot reindex while reindexing");
	currentlyReindexedHeap = heapOid;
	currentlyReindexedIndex = indexOid;
	
	RemoveReindexPending(indexOid);
}


static void ResetReindexProcessing(void)
{
	currentlyReindexedHeap = InvalidOid;
	currentlyReindexedIndex = InvalidOid;
}


static void SetReindexPending(List *indexes)
{
	
	if (pendingReindexedIndexes)
		elog(ERROR, "cannot reindex while reindexing");
	pendingReindexedIndexes = list_copy(indexes);
}


static void RemoveReindexPending(Oid indexOid)
{
	pendingReindexedIndexes = list_delete_oid(pendingReindexedIndexes, indexOid);
}


static void ResetReindexPending(void)
{
	pendingReindexedIndexes = NIL;
}
