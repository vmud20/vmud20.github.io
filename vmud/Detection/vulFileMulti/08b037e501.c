















































































typedef struct OnCommitItem {
	Oid			relid;			
	OnCommitAction oncommit;	

	
	SubTransactionId creating_subid;
	SubTransactionId deleting_subid;
} OnCommitItem;

static List *on_commits = NIL;

















typedef struct AlteredTableInfo {
	
	Oid			relid;			
	char		relkind;		
	TupleDesc	oldDesc;		
	
	List	   *subcmds[AT_NUM_PASSES]; 
	
	List	   *constraints;	
	List	   *newvals;		
	bool		new_notnull;	
	bool		rewrite;		
	Oid			newTableSpace;	
	
	List	   *changedConstraintOids;	
	List	   *changedConstraintDefs;	
	List	   *changedIndexOids;		
	List	   *changedIndexDefs;		
} AlteredTableInfo;



typedef struct NewConstraint {
	char	   *name;			
	ConstrType	contype;		
	Oid			refrelid;		
	Oid			refindid;		
	Oid			conid;			
	Node	   *qual;			
	List	   *qualstate;		
} NewConstraint;


typedef struct NewColumnValue {
	AttrNumber	attnum;			
	Expr	   *expr;			
	ExprState  *exprstate;		
} NewColumnValue;


struct dropmsgstrings {
	char		kind;
	int			nonexistent_code;
	const char *nonexistent_msg;
	const char *skipping_msg;
	const char *nota_msg;
	const char *drophint_msg;
};

static const struct dropmsgstrings dropmsgstringarray[] = {
	{RELKIND_RELATION, ERRCODE_UNDEFINED_TABLE, gettext_noop("table \"%s\" does not exist"), gettext_noop("table \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not a table"), gettext_noop("Use DROP TABLE to remove a table.")}, {RELKIND_SEQUENCE, ERRCODE_UNDEFINED_TABLE, gettext_noop("sequence \"%s\" does not exist"), gettext_noop("sequence \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not a sequence"), gettext_noop("Use DROP SEQUENCE to remove a sequence.")}, {RELKIND_VIEW, ERRCODE_UNDEFINED_TABLE, gettext_noop("view \"%s\" does not exist"), gettext_noop("view \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not a view"), gettext_noop("Use DROP VIEW to remove a view.")}, {RELKIND_MATVIEW, ERRCODE_UNDEFINED_TABLE, gettext_noop("materialized view \"%s\" does not exist"), gettext_noop("materialized view \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not a materialized view"), gettext_noop("Use DROP MATERIALIZED VIEW to remove a materialized view.")}, {RELKIND_INDEX, ERRCODE_UNDEFINED_OBJECT, gettext_noop("index \"%s\" does not exist"), gettext_noop("index \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not an index"), gettext_noop("Use DROP INDEX to remove an index.")}, {RELKIND_COMPOSITE_TYPE, ERRCODE_UNDEFINED_OBJECT, gettext_noop("type \"%s\" does not exist"), gettext_noop("type \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not a type"), gettext_noop("Use DROP TYPE to remove a type.")}, {RELKIND_FOREIGN_TABLE, ERRCODE_UNDEFINED_OBJECT, gettext_noop("foreign table \"%s\" does not exist"), gettext_noop("foreign table \"%s\" does not exist, skipping"), gettext_noop("\"%s\" is not a foreign table"), gettext_noop("Use DROP FOREIGN TABLE to remove a foreign table.")}, {'\0', 0, NULL, NULL, NULL, NULL}









































};

struct DropRelationCallbackState {
	char		relkind;
	Oid			heapOid;
	bool		concurrent;
};









static void truncate_check_rel(Relation rel);
static List *MergeAttributes(List *schema, List *supers, char relpersistence, List **supOids, List **supconstr, int *supOidCount);
static bool MergeCheckConstraint(List *constraints, char *name, Node *expr);
static void MergeAttributesIntoExisting(Relation child_rel, Relation parent_rel);
static void MergeConstraintsIntoExisting(Relation child_rel, Relation parent_rel);
static void StoreCatalogInheritance(Oid relationId, List *supers);
static void StoreCatalogInheritance1(Oid relationId, Oid parentOid, int16 seqNumber, Relation inhRelation);
static int	findAttrByName(const char *attributeName, List *schema);
static void AlterIndexNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid, ObjectAddresses *objsMoved);
static void AlterSeqNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid, ObjectAddresses *objsMoved, LOCKMODE lockmode);

static void ATExecAlterConstraint(Relation rel, AlterTableCmd *cmd, bool recurse, bool recursing, LOCKMODE lockmode);
static void ATExecValidateConstraint(Relation rel, char *constrName, bool recurse, bool recursing, LOCKMODE lockmode);
static int transformColumnNameList(Oid relId, List *colList, int16 *attnums, Oid *atttypids);
static int transformFkeyGetPrimaryKey(Relation pkrel, Oid *indexOid, List **attnamelist, int16 *attnums, Oid *atttypids, Oid *opclasses);


static Oid transformFkeyCheckAttrs(Relation pkrel, int numattrs, int16 *attnums, Oid *opclasses);

static void checkFkeyPermissions(Relation rel, int16 *attnums, int natts);
static CoercionPathType findFkeyCast(Oid targetTypeId, Oid sourceTypeId, Oid *funcid);
static void validateCheckConstraint(Relation rel, HeapTuple constrtup);
static void validateForeignKeyConstraint(char *conname, Relation rel, Relation pkrel, Oid pkindOid, Oid constraintOid);

static void createForeignKeyTriggers(Relation rel, Constraint *fkconstraint, Oid constraintOid, Oid indexOid);
static void ATController(Relation rel, List *cmds, bool recurse, LOCKMODE lockmode);
static void ATPrepCmd(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse, bool recursing, LOCKMODE lockmode);
static void ATRewriteCatalogs(List **wqueue, LOCKMODE lockmode);
static void ATExecCmd(List **wqueue, AlteredTableInfo *tab, Relation rel, AlterTableCmd *cmd, LOCKMODE lockmode);
static void ATRewriteTables(List **wqueue, LOCKMODE lockmode);
static void ATRewriteTable(AlteredTableInfo *tab, Oid OIDNewHeap, LOCKMODE lockmode);
static AlteredTableInfo *ATGetQueueEntry(List **wqueue, Relation rel);
static void ATSimplePermissions(Relation rel, int allowed_targets);
static void ATWrongRelkindError(Relation rel, int allowed_targets);
static void ATSimpleRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse, LOCKMODE lockmode);
static void ATTypedTableRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd, LOCKMODE lockmode);
static List *find_typed_table_dependencies(Oid typeOid, const char *typeName, DropBehavior behavior);
static void ATPrepAddColumn(List **wqueue, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd, LOCKMODE lockmode);
static void ATExecAddColumn(List **wqueue, AlteredTableInfo *tab, Relation rel, ColumnDef *colDef, bool isOid, bool recurse, bool recursing, LOCKMODE lockmode);

static void check_for_column_name_collision(Relation rel, const char *colname);
static void add_column_datatype_dependency(Oid relid, int32 attnum, Oid typid);
static void add_column_collation_dependency(Oid relid, int32 attnum, Oid collid);
static void ATPrepAddOids(List **wqueue, Relation rel, bool recurse, AlterTableCmd *cmd, LOCKMODE lockmode);
static void ATExecDropNotNull(Relation rel, const char *colName, LOCKMODE lockmode);
static void ATExecSetNotNull(AlteredTableInfo *tab, Relation rel, const char *colName, LOCKMODE lockmode);
static void ATExecColumnDefault(Relation rel, const char *colName, Node *newDefault, LOCKMODE lockmode);
static void ATPrepSetStatistics(Relation rel, const char *colName, Node *newValue, LOCKMODE lockmode);
static void ATExecSetStatistics(Relation rel, const char *colName, Node *newValue, LOCKMODE lockmode);
static void ATExecSetOptions(Relation rel, const char *colName, Node *options, bool isReset, LOCKMODE lockmode);
static void ATExecSetStorage(Relation rel, const char *colName, Node *newValue, LOCKMODE lockmode);
static void ATPrepDropColumn(List **wqueue, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd, LOCKMODE lockmode);
static void ATExecDropColumn(List **wqueue, Relation rel, const char *colName, DropBehavior behavior, bool recurse, bool recursing, bool missing_ok, LOCKMODE lockmode);


static void ATExecAddIndex(AlteredTableInfo *tab, Relation rel, IndexStmt *stmt, bool is_rebuild, LOCKMODE lockmode);
static void ATExecAddConstraint(List **wqueue, AlteredTableInfo *tab, Relation rel, Constraint *newConstraint, bool recurse, bool is_readd, LOCKMODE lockmode);


static void ATExecAddIndexConstraint(AlteredTableInfo *tab, Relation rel, IndexStmt *stmt, LOCKMODE lockmode);
static void ATAddCheckConstraint(List **wqueue, AlteredTableInfo *tab, Relation rel, Constraint *constr, bool recurse, bool recursing, bool is_readd, LOCKMODE lockmode);



static void ATAddForeignKeyConstraint(AlteredTableInfo *tab, Relation rel, Constraint *fkconstraint, LOCKMODE lockmode);
static void ATExecDropConstraint(Relation rel, const char *constrName, DropBehavior behavior, bool recurse, bool recursing, bool missing_ok, LOCKMODE lockmode);


static void ATPrepAlterColumnType(List **wqueue, AlteredTableInfo *tab, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd, LOCKMODE lockmode);


static bool ATColumnChangeRequiresRewrite(Node *expr, AttrNumber varattno);
static void ATExecAlterColumnType(AlteredTableInfo *tab, Relation rel, AlterTableCmd *cmd, LOCKMODE lockmode);
static void ATExecAlterColumnGenericOptions(Relation rel, const char *colName, List *options, LOCKMODE lockmode);
static void ATPostAlterTypeCleanup(List **wqueue, AlteredTableInfo *tab, LOCKMODE lockmode);
static void ATPostAlterTypeParse(Oid oldId, char *cmd, List **wqueue, LOCKMODE lockmode, bool rewrite);
static void TryReuseIndex(Oid oldId, IndexStmt *stmt);
static void TryReuseForeignKey(Oid oldId, Constraint *con);
static void change_owner_fix_column_acls(Oid relationOid, Oid oldOwnerId, Oid newOwnerId);
static void change_owner_recurse_to_sequences(Oid relationOid, Oid newOwnerId, LOCKMODE lockmode);
static void ATExecClusterOn(Relation rel, const char *indexName, LOCKMODE lockmode);
static void ATExecDropCluster(Relation rel, LOCKMODE lockmode);
static void ATPrepSetTableSpace(AlteredTableInfo *tab, Relation rel, char *tablespacename, LOCKMODE lockmode);
static void ATExecSetTableSpace(Oid tableOid, Oid newTableSpace, LOCKMODE lockmode);
static void ATExecSetRelOptions(Relation rel, List *defList, AlterTableType operation, LOCKMODE lockmode);

static void ATExecEnableDisableTrigger(Relation rel, char *trigname, char fires_when, bool skip_system, LOCKMODE lockmode);
static void ATExecEnableDisableRule(Relation rel, char *rulename, char fires_when, LOCKMODE lockmode);
static void ATPrepAddInherit(Relation child_rel);
static void ATExecAddInherit(Relation child_rel, RangeVar *parent, LOCKMODE lockmode);
static void ATExecDropInherit(Relation rel, RangeVar *parent, LOCKMODE lockmode);
static void drop_parent_dependency(Oid relid, Oid refclassid, Oid refobjid);
static void ATExecAddOf(Relation rel, const TypeName *ofTypename, LOCKMODE lockmode);
static void ATExecDropOf(Relation rel, LOCKMODE lockmode);
static void ATExecReplicaIdentity(Relation rel, ReplicaIdentityStmt *stmt, LOCKMODE lockmode);
static void ATExecGenericOptions(Relation rel, List *options);

static void copy_relation_data(SMgrRelation rel, SMgrRelation dst, ForkNumber forkNum, char relpersistence);
static const char *storage_name(char c);

static void RangeVarCallbackForDropRelation(const RangeVar *rel, Oid relOid, Oid oldRelOid, void *arg);
static void RangeVarCallbackForAlterRelation(const RangeVar *rv, Oid relid, Oid oldrelid, void *arg);



Oid DefineRelation(CreateStmt *stmt, char relkind, Oid ownerId)
{
	char		relname[NAMEDATALEN];
	Oid			namespaceId;
	List	   *schema = stmt->tableElts;
	Oid			relationId;
	Oid			tablespaceId;
	Relation	rel;
	TupleDesc	descriptor;
	List	   *inheritOids;
	List	   *old_constraints;
	bool		localHasOids;
	int			parentOidCount;
	List	   *rawDefaults;
	List	   *cookedDefaults;
	Datum		reloptions;
	ListCell   *listptr;
	AttrNumber	attnum;
	static char *validnsps[] = HEAP_RELOPT_NAMESPACES;
	Oid			ofTypeId;

	
	StrNCpy(relname, stmt->relation->relname, NAMEDATALEN);

	
	if (stmt->oncommit != ONCOMMIT_NOOP && stmt->relation->relpersistence != RELPERSISTENCE_TEMP)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("ON COMMIT can only be used on temporary tables")));

	if (stmt->constraints != NIL && relkind == RELKIND_FOREIGN_TABLE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("constraints are not supported on foreign tables")));


	
	namespaceId = RangeVarGetAndCheckCreationNamespace(stmt->relation, NoLock, NULL);

	
	if (stmt->relation->relpersistence == RELPERSISTENCE_TEMP && InSecurityRestrictedOperation())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("cannot create temporary table within security-restricted operation")));


	
	if (stmt->tablespacename)
	{
		tablespaceId = get_tablespace_oid(stmt->tablespacename, false);
	}
	else {
		tablespaceId = GetDefaultTablespace(stmt->relation->relpersistence);
		
	}

	
	if (OidIsValid(tablespaceId) && tablespaceId != MyDatabaseTableSpace)
	{
		AclResult	aclresult;

		aclresult = pg_tablespace_aclcheck(tablespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE, get_tablespace_name(tablespaceId));
	}

	
	if (tablespaceId == GLOBALTABLESPACE_OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("only shared relations can be placed in pg_global tablespace")));


	
	if (!OidIsValid(ownerId))
		ownerId = GetUserId();

	
	reloptions = transformRelOptions((Datum) 0, stmt->options, NULL, validnsps, true, false);

	(void) heap_reloptions(relkind, reloptions, true);

	if (stmt->ofTypename)
	{
		AclResult	aclresult;

		ofTypeId = typenameTypeId(NULL, stmt->ofTypename);

		aclresult = pg_type_aclcheck(ofTypeId, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error_type(aclresult, ofTypeId);
	}
	else ofTypeId = InvalidOid;

	
	schema = MergeAttributes(schema, stmt->inhRelations, stmt->relation->relpersistence, &inheritOids, &old_constraints, &parentOidCount);


	
	descriptor = BuildDescForRelation(schema);

	localHasOids = interpretOidsOption(stmt->options, (relkind == RELKIND_RELATION || relkind == RELKIND_FOREIGN_TABLE));

	descriptor->tdhasoid = (localHasOids || parentOidCount > 0);

	
	rawDefaults = NIL;
	cookedDefaults = NIL;
	attnum = 0;

	foreach(listptr, schema)
	{
		ColumnDef  *colDef = lfirst(listptr);

		attnum++;

		if (colDef->raw_default != NULL)
		{
			RawColumnDefault *rawEnt;

			Assert(colDef->cooked_default == NULL);

			rawEnt = (RawColumnDefault *) palloc(sizeof(RawColumnDefault));
			rawEnt->attnum = attnum;
			rawEnt->raw_default = colDef->raw_default;
			rawDefaults = lappend(rawDefaults, rawEnt);
			descriptor->attrs[attnum - 1]->atthasdef = true;
		}
		else if (colDef->cooked_default != NULL)
		{
			CookedConstraint *cooked;

			cooked = (CookedConstraint *) palloc(sizeof(CookedConstraint));
			cooked->contype = CONSTR_DEFAULT;
			cooked->name = NULL;
			cooked->attnum = attnum;
			cooked->expr = colDef->cooked_default;
			cooked->skip_validation = false;
			cooked->is_local = true;	
			cooked->inhcount = 0;		
			cooked->is_no_inherit = false;
			cookedDefaults = lappend(cookedDefaults, cooked);
			descriptor->attrs[attnum - 1]->atthasdef = true;
		}
	}

	
	relationId = heap_create_with_catalog(relname, namespaceId, tablespaceId, InvalidOid, InvalidOid, ofTypeId, ownerId, descriptor, list_concat(cookedDefaults, old_constraints), relkind, stmt->relation->relpersistence, false, false, localHasOids, parentOidCount, stmt->oncommit, reloptions, true, allowSystemTableMods, false);




















	
	StoreCatalogInheritance(relationId, inheritOids);

	
	CommandCounterIncrement();

	
	rel = relation_open(relationId, AccessExclusiveLock);

	
	if (rawDefaults || stmt->constraints)
		AddRelationNewConstraints(rel, rawDefaults, stmt->constraints, true, true, false);

	
	relation_close(rel, NoLock);

	return relationId;
}


static void DropErrorMsgNonExistent(RangeVar *rel, char rightkind, bool missing_ok)
{
	const struct dropmsgstrings *rentry;

	if (rel->schemaname != NULL && !OidIsValid(LookupNamespaceNoError(rel->schemaname)))
	{
		if (!missing_ok)
		{
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("schema \"%s\" does not exist", rel->schemaname)));

		}
		else {
			ereport(NOTICE, (errmsg("schema \"%s\" does not exist, skipping", rel->schemaname)));

		}
		return;
	}

	for (rentry = dropmsgstringarray; rentry->kind != '\0'; rentry++)
	{
		if (rentry->kind == rightkind)
		{
			if (!missing_ok)
			{
				ereport(ERROR, (errcode(rentry->nonexistent_code), errmsg(rentry->nonexistent_msg, rel->relname)));

			}
			else {
				ereport(NOTICE, (errmsg(rentry->skipping_msg, rel->relname)));
				break;
			}
		}
	}

	Assert(rentry->kind != '\0');		
}


static void DropErrorMsgWrongType(const char *relname, char wrongkind, char rightkind)
{
	const struct dropmsgstrings *rentry;
	const struct dropmsgstrings *wentry;

	for (rentry = dropmsgstringarray; rentry->kind != '\0'; rentry++)
		if (rentry->kind == rightkind)
			break;
	Assert(rentry->kind != '\0');

	for (wentry = dropmsgstringarray; wentry->kind != '\0'; wentry++)
		if (wentry->kind == wrongkind)
			break;
	

	ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg(rentry->nota_msg, relname), (wentry->kind != '\0') ? errhint("%s", _(wentry->drophint_msg)) : 0));


}


void RemoveRelations(DropStmt *drop)
{
	ObjectAddresses *objects;
	char		relkind;
	ListCell   *cell;
	int			flags = 0;
	LOCKMODE	lockmode = AccessExclusiveLock;

	
	if (drop->concurrent)
	{
		flags |= PERFORM_DELETION_CONCURRENTLY;
		lockmode = ShareUpdateExclusiveLock;
		Assert(drop->removeType == OBJECT_INDEX);
		if (list_length(drop->objects) != 1)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("DROP INDEX CONCURRENTLY does not support dropping multiple objects")));

		if (drop->behavior == DROP_CASCADE)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("DROP INDEX CONCURRENTLY does not support CASCADE")));

	}

	

	
	switch (drop->removeType)
	{
		case OBJECT_TABLE:
			relkind = RELKIND_RELATION;
			break;

		case OBJECT_INDEX:
			relkind = RELKIND_INDEX;
			break;

		case OBJECT_SEQUENCE:
			relkind = RELKIND_SEQUENCE;
			break;

		case OBJECT_VIEW:
			relkind = RELKIND_VIEW;
			break;

		case OBJECT_MATVIEW:
			relkind = RELKIND_MATVIEW;
			break;

		case OBJECT_FOREIGN_TABLE:
			relkind = RELKIND_FOREIGN_TABLE;
			break;

		default:
			elog(ERROR, "unrecognized drop object type: %d", (int) drop->removeType);
			relkind = 0;		
			break;
	}

	
	objects = new_object_addresses();

	foreach(cell, drop->objects)
	{
		RangeVar   *rel = makeRangeVarFromNameList((List *) lfirst(cell));
		Oid			relOid;
		ObjectAddress obj;
		struct DropRelationCallbackState state;

		
		AcceptInvalidationMessages();

		
		state.relkind = relkind;
		state.heapOid = InvalidOid;
		state.concurrent = drop->concurrent;
		relOid = RangeVarGetRelidExtended(rel, lockmode, true, false, RangeVarCallbackForDropRelation, (void *) &state);



		
		if (!OidIsValid(relOid))
		{
			DropErrorMsgNonExistent(rel, relkind, drop->missing_ok);
			continue;
		}

		
		obj.classId = RelationRelationId;
		obj.objectId = relOid;
		obj.objectSubId = 0;

		add_exact_object_address(&obj, objects);
	}

	performMultipleDeletions(objects, drop->behavior, flags);

	free_object_addresses(objects);
}


static void RangeVarCallbackForDropRelation(const RangeVar *rel, Oid relOid, Oid oldRelOid, void *arg)

{
	HeapTuple	tuple;
	struct DropRelationCallbackState *state;
	char		relkind;
	Form_pg_class classform;
	LOCKMODE	heap_lockmode;

	state = (struct DropRelationCallbackState *) arg;
	relkind = state->relkind;
	heap_lockmode = state->concurrent ? ShareUpdateExclusiveLock : AccessExclusiveLock;

	
	if (relOid != oldRelOid && OidIsValid(state->heapOid))
	{
		UnlockRelationOid(state->heapOid, heap_lockmode);
		state->heapOid = InvalidOid;
	}

	
	if (!OidIsValid(relOid))
		return;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));
	if (!HeapTupleIsValid(tuple))
		return;					
	classform = (Form_pg_class) GETSTRUCT(tuple);

	if (classform->relkind != relkind)
		DropErrorMsgWrongType(rel->relname, classform->relkind, relkind);

	
	if (!pg_class_ownercheck(relOid, GetUserId()) && !pg_namespace_ownercheck(classform->relnamespace, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, rel->relname);

	if (!allowSystemTableMods && IsSystemClass(relOid, classform))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", rel->relname)));



	ReleaseSysCache(tuple);

	
	if (relkind == RELKIND_INDEX && relOid != oldRelOid)
	{
		state->heapOid = IndexGetRelation(relOid, true);
		if (OidIsValid(state->heapOid))
			LockRelationOid(state->heapOid, heap_lockmode);
	}
}


void ExecuteTruncate(TruncateStmt *stmt)
{
	List	   *rels = NIL;
	List	   *relids = NIL;
	List	   *seq_relids = NIL;
	EState	   *estate;
	ResultRelInfo *resultRelInfos;
	ResultRelInfo *resultRelInfo;
	SubTransactionId mySubid;
	ListCell   *cell;

	
	foreach(cell, stmt->relations)
	{
		RangeVar   *rv = lfirst(cell);
		Relation	rel;
		bool		recurse = interpretInhOption(rv->inhOpt);
		Oid			myrelid;

		rel = heap_openrv(rv, AccessExclusiveLock);
		myrelid = RelationGetRelid(rel);
		
		if (list_member_oid(relids, myrelid))
		{
			heap_close(rel, AccessExclusiveLock);
			continue;
		}
		truncate_check_rel(rel);
		rels = lappend(rels, rel);
		relids = lappend_oid(relids, myrelid);

		if (recurse)
		{
			ListCell   *child;
			List	   *children;

			children = find_all_inheritors(myrelid, AccessExclusiveLock, NULL);

			foreach(child, children)
			{
				Oid			childrelid = lfirst_oid(child);

				if (list_member_oid(relids, childrelid))
					continue;

				
				rel = heap_open(childrelid, NoLock);
				truncate_check_rel(rel);
				rels = lappend(rels, rel);
				relids = lappend_oid(relids, childrelid);
			}
		}
	}

	
	if (stmt->behavior == DROP_CASCADE)
	{
		for (;;)
		{
			List	   *newrelids;

			newrelids = heap_truncate_find_FKs(relids);
			if (newrelids == NIL)
				break;			

			foreach(cell, newrelids)
			{
				Oid			relid = lfirst_oid(cell);
				Relation	rel;

				rel = heap_open(relid, AccessExclusiveLock);
				ereport(NOTICE, (errmsg("truncate cascades to table \"%s\"", RelationGetRelationName(rel))));

				truncate_check_rel(rel);
				rels = lappend(rels, rel);
				relids = lappend_oid(relids, relid);
			}
		}
	}

	

	heap_truncate_check_FKs(rels, false);

	if (stmt->behavior == DROP_RESTRICT)
		heap_truncate_check_FKs(rels, false);


	
	if (stmt->restart_seqs)
	{
		foreach(cell, rels)
		{
			Relation	rel = (Relation) lfirst(cell);
			List	   *seqlist = getOwnedSequences(RelationGetRelid(rel));
			ListCell   *seqcell;

			foreach(seqcell, seqlist)
			{
				Oid			seq_relid = lfirst_oid(seqcell);
				Relation	seq_rel;

				seq_rel = relation_open(seq_relid, AccessExclusiveLock);

				
				if (!pg_class_ownercheck(seq_relid, GetUserId()))
					aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(seq_rel));

				seq_relids = lappend_oid(seq_relids, seq_relid);

				relation_close(seq_rel, NoLock);
			}
		}
	}

	
	AfterTriggerBeginQuery();

	
	estate = CreateExecutorState();
	resultRelInfos = (ResultRelInfo *)
		palloc(list_length(rels) * sizeof(ResultRelInfo));
	resultRelInfo = resultRelInfos;
	foreach(cell, rels)
	{
		Relation	rel = (Relation) lfirst(cell);

		InitResultRelInfo(resultRelInfo, rel, 0, 0);


		resultRelInfo++;
	}
	estate->es_result_relations = resultRelInfos;
	estate->es_num_result_relations = list_length(rels);

	
	resultRelInfo = resultRelInfos;
	foreach(cell, rels)
	{
		estate->es_result_relation_info = resultRelInfo;
		ExecBSTruncateTriggers(estate, resultRelInfo);
		resultRelInfo++;
	}

	
	mySubid = GetCurrentSubTransactionId();

	foreach(cell, rels)
	{
		Relation	rel = (Relation) lfirst(cell);

		
		if (rel->rd_createSubid == mySubid || rel->rd_newRelfilenodeSubid == mySubid)
		{
			
			heap_truncate_one_rel(rel);
		}
		else {
			Oid			heap_relid;
			Oid			toast_relid;
			MultiXactId minmulti;

			
			CheckTableForSerializableConflictIn(rel);

			minmulti = GetOldestMultiXactId();

			
			RelationSetNewRelfilenode(rel, RecentXmin, minmulti);
			if (rel->rd_rel->relpersistence == RELPERSISTENCE_UNLOGGED)
				heap_create_init_fork(rel);

			heap_relid = RelationGetRelid(rel);
			toast_relid = rel->rd_rel->reltoastrelid;

			
			if (OidIsValid(toast_relid))
			{
				rel = relation_open(toast_relid, AccessExclusiveLock);
				RelationSetNewRelfilenode(rel, RecentXmin, minmulti);
				if (rel->rd_rel->relpersistence == RELPERSISTENCE_UNLOGGED)
					heap_create_init_fork(rel);
				heap_close(rel, NoLock);
			}

			
			reindex_relation(heap_relid, REINDEX_REL_PROCESS_TOAST);
		}
	}

	
	foreach(cell, seq_relids)
	{
		Oid			seq_relid = lfirst_oid(cell);

		ResetSequence(seq_relid);
	}

	
	resultRelInfo = resultRelInfos;
	foreach(cell, rels)
	{
		estate->es_result_relation_info = resultRelInfo;
		ExecASTruncateTriggers(estate, resultRelInfo);
		resultRelInfo++;
	}

	
	AfterTriggerEndQuery(estate);

	
	FreeExecutorState(estate);

	
	foreach(cell, rels)
	{
		Relation	rel = (Relation) lfirst(cell);

		heap_close(rel, NoLock);
	}
}


static void truncate_check_rel(Relation rel)
{
	AclResult	aclresult;

	
	if (rel->rd_rel->relkind != RELKIND_RELATION)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table", RelationGetRelationName(rel))));



	
	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(), ACL_TRUNCATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(rel));

	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));



	
	if (RELATION_IS_OTHER_TEMP(rel))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot truncate temporary tables of other sessions")));


	
	CheckTableNotInUse(rel, "TRUNCATE");
}


static const char * storage_name(char c)
{
	switch (c)
	{
		case 'p':
			return "PLAIN";
		case 'm':
			return "MAIN";
		case 'x':
			return "EXTENDED";
		case 'e':
			return "EXTERNAL";
		default:
			return "???";
	}
}


static List * MergeAttributes(List *schema, List *supers, char relpersistence, List **supOids, List **supconstr, int *supOidCount)

{
	ListCell   *entry;
	List	   *inhSchema = NIL;
	List	   *parentOids = NIL;
	List	   *constraints = NIL;
	int			parentsWithOids = 0;
	bool		have_bogus_defaults = false;
	int			child_attno;
	static Node bogus_marker = {0};		

	
	if (list_length(schema) > MaxHeapAttributeNumber)
		ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("tables can have at most %d columns", MaxHeapAttributeNumber)));



	
	foreach(entry, schema)
	{
		ColumnDef  *coldef = lfirst(entry);
		ListCell   *rest = lnext(entry);
		ListCell   *prev = entry;

		if (coldef->typeName == NULL)

			
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" does not exist", coldef->colname)));



		while (rest != NULL)
		{
			ColumnDef  *restdef = lfirst(rest);
			ListCell   *next = lnext(rest);		

			if (strcmp(coldef->colname, restdef->colname) == 0)
			{
				if (coldef->is_from_type)
				{
					
					coldef->is_not_null = restdef->is_not_null;
					coldef->raw_default = restdef->raw_default;
					coldef->cooked_default = restdef->cooked_default;
					coldef->constraints = restdef->constraints;
					coldef->is_from_type = false;
					list_delete_cell(schema, rest, prev);
				}
				else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" specified more than once", coldef->colname)));



			}
			prev = rest;
			rest = next;
		}
	}

	
	child_attno = 0;
	foreach(entry, supers)
	{
		RangeVar   *parent = (RangeVar *) lfirst(entry);
		Relation	relation;
		TupleDesc	tupleDesc;
		TupleConstr *constr;
		AttrNumber *newattno;
		AttrNumber	parent_attno;

		
		relation = heap_openrv(parent, ShareUpdateExclusiveLock);

		if (relation->rd_rel->relkind != RELKIND_RELATION)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table", parent->relname)));


		
		if (relpersistence != RELPERSISTENCE_TEMP && relation->rd_rel->relpersistence == RELPERSISTENCE_TEMP)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit from temporary relation \"%s\"", parent->relname)));



		
		if (relation->rd_rel->relpersistence == RELPERSISTENCE_TEMP && !relation->rd_islocaltemp)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit from temporary relation of another session")));


		
		if (!pg_class_ownercheck(RelationGetRelid(relation), GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(relation));

		
		if (list_member_oid(parentOids, RelationGetRelid(relation)))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" would be inherited from more than once", parent->relname)));



		parentOids = lappend_oid(parentOids, RelationGetRelid(relation));

		if (relation->rd_rel->relhasoids)
			parentsWithOids++;

		tupleDesc = RelationGetDescr(relation);
		constr = tupleDesc->constr;

		
		newattno = (AttrNumber *)
			palloc0(tupleDesc->natts * sizeof(AttrNumber));

		for (parent_attno = 1; parent_attno <= tupleDesc->natts;
			 parent_attno++)
		{
			Form_pg_attribute attribute = tupleDesc->attrs[parent_attno - 1];
			char	   *attributeName = NameStr(attribute->attname);
			int			exist_attno;
			ColumnDef  *def;

			
			if (attribute->attisdropped)
				continue;		

			
			exist_attno = findAttrByName(attributeName, inhSchema);
			if (exist_attno > 0)
			{
				Oid			defTypeId;
				int32		deftypmod;
				Oid			defCollId;

				
				ereport(NOTICE, (errmsg("merging multiple inherited definitions of column \"%s\"", attributeName)));

				def = (ColumnDef *) list_nth(inhSchema, exist_attno - 1);
				typenameTypeIdAndMod(NULL, def->typeName, &defTypeId, &deftypmod);
				if (defTypeId != attribute->atttypid || deftypmod != attribute->atttypmod)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("inherited column \"%s\" has a type conflict", attributeName), errdetail("%s versus %s", TypeNameToString(def->typeName), format_type_be(attribute->atttypid))));





				defCollId = GetColumnDefCollation(NULL, def, defTypeId);
				if (defCollId != attribute->attcollation)
					ereport(ERROR, (errcode(ERRCODE_COLLATION_MISMATCH), errmsg("inherited column \"%s\" has a collation conflict", attributeName), errdetail("\"%s\" versus \"%s\"", get_collation_name(defCollId), get_collation_name(attribute->attcollation))));






				
				if (def->storage == 0)
					def->storage = attribute->attstorage;
				else if (def->storage != attribute->attstorage)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("inherited column \"%s\" has a storage parameter conflict", attributeName), errdetail("%s versus %s", storage_name(def->storage), storage_name(attribute->attstorage))));






				def->inhcount++;
				
				def->is_not_null |= attribute->attnotnull;
				
				newattno[parent_attno - 1] = exist_attno;
			}
			else {
				
				def = makeNode(ColumnDef);
				def->colname = pstrdup(attributeName);
				def->typeName = makeTypeNameFromOid(attribute->atttypid, attribute->atttypmod);
				def->inhcount = 1;
				def->is_local = false;
				def->is_not_null = attribute->attnotnull;
				def->is_from_type = false;
				def->storage = attribute->attstorage;
				def->raw_default = NULL;
				def->cooked_default = NULL;
				def->collClause = NULL;
				def->collOid = attribute->attcollation;
				def->constraints = NIL;
				def->location = -1;
				inhSchema = lappend(inhSchema, def);
				newattno[parent_attno - 1] = ++child_attno;
			}

			
			if (attribute->atthasdef)
			{
				Node	   *this_default = NULL;
				AttrDefault *attrdef;
				int			i;

				
				Assert(constr != NULL);
				attrdef = constr->defval;
				for (i = 0; i < constr->num_defval; i++)
				{
					if (attrdef[i].adnum == parent_attno)
					{
						this_default = stringToNode(attrdef[i].adbin);
						break;
					}
				}
				Assert(this_default != NULL);

				
				Assert(def->raw_default == NULL);
				if (def->cooked_default == NULL)
					def->cooked_default = this_default;
				else if (!equal(def->cooked_default, this_default))
				{
					def->cooked_default = &bogus_marker;
					have_bogus_defaults = true;
				}
			}
		}

		
		if (constr && constr->num_check > 0)
		{
			ConstrCheck *check = constr->check;
			int			i;

			for (i = 0; i < constr->num_check; i++)
			{
				char	   *name = check[i].ccname;
				Node	   *expr;
				bool		found_whole_row;

				
				if (check[i].ccnoinherit)
					continue;

				
				expr = map_variable_attnos(stringToNode(check[i].ccbin), 1, 0, newattno, tupleDesc->natts, &found_whole_row);



				
				if (found_whole_row)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Constraint \"%s\" contains a whole-row reference to table \"%s\".", name, RelationGetRelationName(relation))));





				
				if (!MergeCheckConstraint(constraints, name, expr))
				{
					
					CookedConstraint *cooked;

					cooked = (CookedConstraint *) palloc(sizeof(CookedConstraint));
					cooked->contype = CONSTR_CHECK;
					cooked->name = pstrdup(name);
					cooked->attnum = 0; 
					cooked->expr = expr;
					cooked->skip_validation = false;
					cooked->is_local = false;
					cooked->inhcount = 1;
					cooked->is_no_inherit = false;
					constraints = lappend(constraints, cooked);
				}
			}
		}

		pfree(newattno);

		
		heap_close(relation, NoLock);
	}

	
	if (inhSchema != NIL)
	{
		foreach(entry, schema)
		{
			ColumnDef  *newdef = lfirst(entry);
			char	   *attributeName = newdef->colname;
			int			exist_attno;

			
			exist_attno = findAttrByName(attributeName, inhSchema);
			if (exist_attno > 0)
			{
				ColumnDef  *def;
				Oid			defTypeId, newTypeId;
				int32		deftypmod, newtypmod;
				Oid			defcollid, newcollid;

				
				ereport(NOTICE, (errmsg("merging column \"%s\" with inherited definition", attributeName)));

				def = (ColumnDef *) list_nth(inhSchema, exist_attno - 1);
				typenameTypeIdAndMod(NULL, def->typeName, &defTypeId, &deftypmod);
				typenameTypeIdAndMod(NULL, newdef->typeName, &newTypeId, &newtypmod);
				if (defTypeId != newTypeId || deftypmod != newtypmod)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("column \"%s\" has a type conflict", attributeName), errdetail("%s versus %s", TypeNameToString(def->typeName), TypeNameToString(newdef->typeName))));





				defcollid = GetColumnDefCollation(NULL, def, defTypeId);
				newcollid = GetColumnDefCollation(NULL, newdef, newTypeId);
				if (defcollid != newcollid)
					ereport(ERROR, (errcode(ERRCODE_COLLATION_MISMATCH), errmsg("column \"%s\" has a collation conflict", attributeName), errdetail("\"%s\" versus \"%s\"", get_collation_name(defcollid), get_collation_name(newcollid))));






				
				if (def->storage == 0)
					def->storage = newdef->storage;
				else if (newdef->storage != 0 && def->storage != newdef->storage)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("column \"%s\" has a storage parameter conflict", attributeName), errdetail("%s versus %s", storage_name(def->storage), storage_name(newdef->storage))));






				
				def->is_local = true;
				
				def->is_not_null |= newdef->is_not_null;
				
				if (newdef->raw_default != NULL)
				{
					def->raw_default = newdef->raw_default;
					def->cooked_default = newdef->cooked_default;
				}
			}
			else {
				
				inhSchema = lappend(inhSchema, newdef);
			}
		}

		schema = inhSchema;

		
		if (list_length(schema) > MaxHeapAttributeNumber)
			ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("tables can have at most %d columns", MaxHeapAttributeNumber)));


	}

	
	if (have_bogus_defaults)
	{
		foreach(entry, schema)
		{
			ColumnDef  *def = lfirst(entry);

			if (def->cooked_default == &bogus_marker)
				ereport(ERROR, (errcode(ERRCODE_INVALID_COLUMN_DEFINITION), errmsg("column \"%s\" inherits conflicting default values", def->colname), errhint("To resolve the conflict, specify a default explicitly.")));



		}
	}

	*supOids = parentOids;
	*supconstr = constraints;
	*supOidCount = parentsWithOids;
	return schema;
}



static bool MergeCheckConstraint(List *constraints, char *name, Node *expr)
{
	ListCell   *lc;

	foreach(lc, constraints)
	{
		CookedConstraint *ccon = (CookedConstraint *) lfirst(lc);

		Assert(ccon->contype == CONSTR_CHECK);

		
		if (strcmp(ccon->name, name) != 0)
			continue;

		if (equal(expr, ccon->expr))
		{
			
			ccon->inhcount++;
			return true;
		}

		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("check constraint name \"%s\" appears multiple times but with different expressions", name)));


	}

	return false;
}



static void StoreCatalogInheritance(Oid relationId, List *supers)
{
	Relation	relation;
	int16		seqNumber;
	ListCell   *entry;

	
	AssertArg(OidIsValid(relationId));

	if (supers == NIL)
		return;

	
	relation = heap_open(InheritsRelationId, RowExclusiveLock);

	seqNumber = 1;
	foreach(entry, supers)
	{
		Oid			parentOid = lfirst_oid(entry);

		StoreCatalogInheritance1(relationId, parentOid, seqNumber, relation);
		seqNumber++;
	}

	heap_close(relation, RowExclusiveLock);
}


static void StoreCatalogInheritance1(Oid relationId, Oid parentOid, int16 seqNumber, Relation inhRelation)

{
	TupleDesc	desc = RelationGetDescr(inhRelation);
	Datum		values[Natts_pg_inherits];
	bool		nulls[Natts_pg_inherits];
	ObjectAddress childobject, parentobject;
	HeapTuple	tuple;

	
	values[Anum_pg_inherits_inhrelid - 1] = ObjectIdGetDatum(relationId);
	values[Anum_pg_inherits_inhparent - 1] = ObjectIdGetDatum(parentOid);
	values[Anum_pg_inherits_inhseqno - 1] = Int16GetDatum(seqNumber);

	memset(nulls, 0, sizeof(nulls));

	tuple = heap_form_tuple(desc, values, nulls);

	simple_heap_insert(inhRelation, tuple);

	CatalogUpdateIndexes(inhRelation, tuple);

	heap_freetuple(tuple);

	
	parentobject.classId = RelationRelationId;
	parentobject.objectId = parentOid;
	parentobject.objectSubId = 0;
	childobject.classId = RelationRelationId;
	childobject.objectId = relationId;
	childobject.objectSubId = 0;

	recordDependencyOn(&childobject, &parentobject, DEPENDENCY_NORMAL);

	
	InvokeObjectPostAlterHookArg(InheritsRelationId, relationId, 0, parentOid, false);


	
	SetRelationHasSubclass(parentOid, true);
}


static int findAttrByName(const char *attributeName, List *schema)
{
	ListCell   *s;
	int			i = 1;

	foreach(s, schema)
	{
		ColumnDef  *def = lfirst(s);

		if (strcmp(attributeName, def->colname) == 0)
			return i;

		i++;
	}
	return 0;
}



void SetRelationHasSubclass(Oid relationId, bool relhassubclass)
{
	Relation	relationRelation;
	HeapTuple	tuple;
	Form_pg_class classtuple;

	
	relationRelation = heap_open(RelationRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(relationId));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relationId);
	classtuple = (Form_pg_class) GETSTRUCT(tuple);

	if (classtuple->relhassubclass != relhassubclass)
	{
		classtuple->relhassubclass = relhassubclass;
		simple_heap_update(relationRelation, &tuple->t_self, tuple);

		
		CatalogUpdateIndexes(relationRelation, tuple);
	}
	else {
		
		CacheInvalidateRelcacheByTuple(tuple);
	}

	heap_freetuple(tuple);
	heap_close(relationRelation, RowExclusiveLock);
}


static void renameatt_check(Oid myrelid, Form_pg_class classform, bool recursing)
{
	char		relkind = classform->relkind;

	if (classform->reloftype && !recursing)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot rename column of typed table")));


	
	if (relkind != RELKIND_RELATION && relkind != RELKIND_VIEW && relkind != RELKIND_MATVIEW && relkind != RELKIND_COMPOSITE_TYPE && relkind != RELKIND_INDEX && relkind != RELKIND_FOREIGN_TABLE)




		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, materialized view, composite type, index, or foreign table", NameStr(classform->relname))));



	
	if (!pg_class_ownercheck(myrelid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, NameStr(classform->relname));
	if (!allowSystemTableMods && IsSystemClass(myrelid, classform))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", NameStr(classform->relname))));


}


static void renameatt_internal(Oid myrelid, const char *oldattname, const char *newattname, bool recurse, bool recursing, int expected_parents, DropBehavior behavior)






{
	Relation	targetrelation;
	Relation	attrelation;
	HeapTuple	atttup;
	Form_pg_attribute attform;
	int			attnum;

	
	targetrelation = relation_open(myrelid, AccessExclusiveLock);
	renameatt_check(myrelid, RelationGetForm(targetrelation), recursing);

	
	if (recurse)
	{
		List	   *child_oids, *child_numparents;
		ListCell   *lo, *li;

		
		child_oids = find_all_inheritors(myrelid, AccessExclusiveLock, &child_numparents);

		
		forboth(lo, child_oids, li, child_numparents)
		{
			Oid			childrelid = lfirst_oid(lo);
			int			numparents = lfirst_int(li);

			if (childrelid == myrelid)
				continue;
			
			renameatt_internal(childrelid, oldattname, newattname, false, true, numparents, behavior);
		}
	}
	else {
		
		if (expected_parents == 0 && find_inheritance_children(myrelid, NoLock) != NIL)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("inherited column \"%s\" must be renamed in child tables too", oldattname)));


	}

	
	if (targetrelation->rd_rel->relkind == RELKIND_COMPOSITE_TYPE)
	{
		List	   *child_oids;
		ListCell   *lo;

		child_oids = find_typed_table_dependencies(targetrelation->rd_rel->reltype, RelationGetRelationName(targetrelation), behavior);


		foreach(lo, child_oids)
			renameatt_internal(lfirst_oid(lo), oldattname, newattname, true, true, 0, behavior);
	}

	attrelation = heap_open(AttributeRelationId, RowExclusiveLock);

	atttup = SearchSysCacheCopyAttName(myrelid, oldattname);
	if (!HeapTupleIsValid(atttup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" does not exist", oldattname)));


	attform = (Form_pg_attribute) GETSTRUCT(atttup);

	attnum = attform->attnum;
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rename system column \"%s\"", oldattname)));



	
	if (attform->attinhcount > expected_parents)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot rename inherited column \"%s\"", oldattname)));



	
	check_for_column_name_collision(targetrelation, newattname);

	
	namestrcpy(&(attform->attname), newattname);

	simple_heap_update(attrelation, &atttup->t_self, atttup);

	
	CatalogUpdateIndexes(attrelation, atttup);

	InvokeObjectPostAlterHook(RelationRelationId, myrelid, attnum);

	heap_freetuple(atttup);

	heap_close(attrelation, RowExclusiveLock);

	relation_close(targetrelation, NoLock);		
}


static void RangeVarCallbackForRenameAttribute(const RangeVar *rv, Oid relid, Oid oldrelid, void *arg)

{
	HeapTuple	tuple;
	Form_pg_class form;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		return;					
	form = (Form_pg_class) GETSTRUCT(tuple);
	renameatt_check(relid, form, false);
	ReleaseSysCache(tuple);
}


Oid renameatt(RenameStmt *stmt)
{
	Oid			relid;

	
	relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock, stmt->missing_ok, false, RangeVarCallbackForRenameAttribute, NULL);



	if (!OidIsValid(relid))
	{
		ereport(NOTICE, (errmsg("relation \"%s\" does not exist, skipping", stmt->relation->relname)));

		return InvalidOid;
	}

	renameatt_internal(relid, stmt->subname, stmt->newname, interpretInhOption(stmt->relation->inhOpt), false, 0, stmt->behavior);






	
	return relid;
}



static Oid rename_constraint_internal(Oid myrelid, Oid mytypid, const char *oldconname, const char *newconname, bool recurse, bool recursing, int expected_parents)






{
	Relation	targetrelation = NULL;
	Oid			constraintOid;
	HeapTuple	tuple;
	Form_pg_constraint con;

	AssertArg(!myrelid || !mytypid);

	if (mytypid)
	{
		constraintOid = get_domain_constraint_oid(mytypid, oldconname, false);
	}
	else {
		targetrelation = relation_open(myrelid, AccessExclusiveLock);

		
		renameatt_check(myrelid, RelationGetForm(targetrelation), false);

		constraintOid = get_relation_constraint_oid(myrelid, oldconname, false);
	}

	tuple = SearchSysCache1(CONSTROID, ObjectIdGetDatum(constraintOid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for constraint %u", constraintOid);
	con = (Form_pg_constraint) GETSTRUCT(tuple);

	if (myrelid && con->contype == CONSTRAINT_CHECK && !con->connoinherit)
	{
		if (recurse)
		{
			List	   *child_oids, *child_numparents;
			ListCell   *lo, *li;

			child_oids = find_all_inheritors(myrelid, AccessExclusiveLock, &child_numparents);

			forboth(lo, child_oids, li, child_numparents)
			{
				Oid			childrelid = lfirst_oid(lo);
				int			numparents = lfirst_int(li);

				if (childrelid == myrelid)
					continue;

				rename_constraint_internal(childrelid, InvalidOid, oldconname, newconname, false, true, numparents);
			}
		}
		else {
			if (expected_parents == 0 && find_inheritance_children(myrelid, NoLock) != NIL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("inherited constraint \"%s\" must be renamed in child tables too", oldconname)));


		}

		if (con->coninhcount > expected_parents)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot rename inherited constraint \"%s\"", oldconname)));


	}

	if (con->conindid && (con->contype == CONSTRAINT_PRIMARY || con->contype == CONSTRAINT_UNIQUE || con->contype == CONSTRAINT_EXCLUSION))


		
		RenameRelationInternal(con->conindid, newconname, false);
	else RenameConstraintById(constraintOid, newconname);

	ReleaseSysCache(tuple);

	if (targetrelation)
		relation_close(targetrelation, NoLock); 

	return constraintOid;
}

Oid RenameConstraint(RenameStmt *stmt)
{
	Oid			relid = InvalidOid;
	Oid			typid = InvalidOid;

	if (stmt->relationType == OBJECT_DOMAIN)
	{
		Relation	rel;
		HeapTuple	tup;

		typid = typenameTypeId(NULL, makeTypeNameFromNameList(stmt->object));
		rel = heap_open(TypeRelationId, RowExclusiveLock);
		tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typid));
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for type %u", typid);
		checkDomainOwner(tup);
		ReleaseSysCache(tup);
		heap_close(rel, NoLock);
	}
	else {
		
		relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock, false, false, RangeVarCallbackForRenameAttribute, NULL);


	}

	return rename_constraint_internal(relid, typid, stmt->subname, stmt->newname, stmt->relation ? interpretInhOption(stmt->relation->inhOpt) : false, false, 0  );






}


Oid RenameRelation(RenameStmt *stmt)
{
	Oid			relid;

	
	relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock, stmt->missing_ok, false, RangeVarCallbackForAlterRelation, (void *) stmt);



	if (!OidIsValid(relid))
	{
		ereport(NOTICE, (errmsg("relation \"%s\" does not exist, skipping", stmt->relation->relname)));

		return InvalidOid;
	}

	
	RenameRelationInternal(relid, stmt->newname, false);

	return relid;
}


void RenameRelationInternal(Oid myrelid, const char *newrelname, bool is_internal)
{
	Relation	targetrelation;
	Relation	relrelation;	
	HeapTuple	reltup;
	Form_pg_class relform;
	Oid			namespaceId;

	
	targetrelation = relation_open(myrelid, AccessExclusiveLock);
	namespaceId = RelationGetNamespace(targetrelation);

	
	relrelation = heap_open(RelationRelationId, RowExclusiveLock);

	reltup = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(myrelid));
	if (!HeapTupleIsValid(reltup))		
		elog(ERROR, "cache lookup failed for relation %u", myrelid);
	relform = (Form_pg_class) GETSTRUCT(reltup);

	if (get_relname_relid(newrelname, namespaceId) != InvalidOid)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists", newrelname)));



	
	namestrcpy(&(relform->relname), newrelname);

	simple_heap_update(relrelation, &reltup->t_self, reltup);

	
	CatalogUpdateIndexes(relrelation, reltup);

	InvokeObjectPostAlterHookArg(RelationRelationId, myrelid, 0, InvalidOid, is_internal);

	heap_freetuple(reltup);
	heap_close(relrelation, RowExclusiveLock);

	
	if (OidIsValid(targetrelation->rd_rel->reltype))
		RenameTypeInternal(targetrelation->rd_rel->reltype, newrelname, namespaceId);

	
	if (targetrelation->rd_rel->relkind == RELKIND_INDEX)
	{
		Oid			constraintId = get_index_constraint(myrelid);

		if (OidIsValid(constraintId))
			RenameConstraintById(constraintId, newrelname);
	}

	
	relation_close(targetrelation, NoLock);
}


void CheckTableNotInUse(Relation rel, const char *stmt)
{
	int			expected_refcnt;

	expected_refcnt = rel->rd_isnailed ? 2 : 1;
	if (rel->rd_refcnt != expected_refcnt)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_IN_USE),  errmsg("cannot %s \"%s\" because " "it is being used by active queries in this session", stmt, RelationGetRelationName(rel))));





	if (rel->rd_rel->relkind != RELKIND_INDEX && AfterTriggerPendingOnRel(RelationGetRelid(rel)))
		ereport(ERROR, (errcode(ERRCODE_OBJECT_IN_USE),  errmsg("cannot %s \"%s\" because " "it has pending trigger events", stmt, RelationGetRelationName(rel))));




}


Oid AlterTableLookupRelation(AlterTableStmt *stmt, LOCKMODE lockmode)
{
	return RangeVarGetRelidExtended(stmt->relation, lockmode, stmt->missing_ok, false, RangeVarCallbackForAlterRelation, (void *) stmt);

}


void AlterTable(Oid relid, LOCKMODE lockmode, AlterTableStmt *stmt)
{
	Relation	rel;

	
	rel = relation_open(relid, NoLock);

	CheckTableNotInUse(rel, "ALTER TABLE");

	ATController(rel, stmt->cmds, interpretInhOption(stmt->relation->inhOpt), lockmode);
}


void AlterTableInternal(Oid relid, List *cmds, bool recurse)
{
	Relation	rel;
	LOCKMODE	lockmode = AlterTableGetLockLevel(cmds);

	rel = relation_open(relid, lockmode);

	ATController(rel, cmds, recurse, lockmode);
}


LOCKMODE AlterTableGetLockLevel(List *cmds)
{
	

	ListCell   *lcmd;
	LOCKMODE	lockmode = ShareUpdateExclusiveLock;

	foreach(lcmd, cmds)
	{
		AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);
		LOCKMODE	cmd_lockmode = AccessExclusiveLock; 

		switch (cmd->subtype)
		{
				
			case AT_AddColumn:	
			case AT_DropColumn:	
			case AT_AddColumnToView:	
			case AT_AlterColumnType:	
			case AT_DropConstraint:		
			case AT_AddOids:	
			case AT_DropOids:	
			case AT_EnableAlwaysRule:	
			case AT_EnableReplicaRule:	
			case AT_EnableRule:	
			case AT_DisableRule:		
			case AT_ChangeOwner:		
			case AT_SetTableSpace:		
			case AT_DropNotNull:		
			case AT_SetNotNull:
			case AT_GenericOptions:
			case AT_AlterColumnGenericOptions:
				cmd_lockmode = AccessExclusiveLock;
				break;

				
			case AT_ColumnDefault:
			case AT_ProcessedConstraint:		
			case AT_AddConstraintRecurse:		
			case AT_ReAddConstraint:	
			case AT_EnableTrig:
			case AT_EnableAlwaysTrig:
			case AT_EnableReplicaTrig:
			case AT_EnableTrigAll:
			case AT_EnableTrigUser:
			case AT_DisableTrig:
			case AT_DisableTrigAll:
			case AT_DisableTrigUser:
			case AT_AddIndex:	
			case AT_AddIndexConstraint:
			case AT_ReplicaIdentity:
				cmd_lockmode = ShareRowExclusiveLock;
				break;

			case AT_AddConstraint:
				if (IsA(cmd->def, Constraint))
				{
					Constraint *con = (Constraint *) cmd->def;

					switch (con->contype)
					{
						case CONSTR_EXCLUSION:
						case CONSTR_PRIMARY:
						case CONSTR_UNIQUE:

							
							cmd_lockmode = ShareRowExclusiveLock;
							break;
						case CONSTR_FOREIGN:

							
							cmd_lockmode = ShareRowExclusiveLock;
							break;

						default:
							cmd_lockmode = ShareRowExclusiveLock;
					}
				}
				break;

				
			case AT_AddInherit:
			case AT_DropInherit:
				cmd_lockmode = ShareUpdateExclusiveLock;
				break;

				
			case AT_AddOf:
			case AT_DropOf:
				cmd_lockmode = ShareUpdateExclusiveLock;

				
			case AT_SetStatistics:
			case AT_ClusterOn:
			case AT_DropCluster:
			case AT_SetRelOptions:
			case AT_ResetRelOptions:
			case AT_ReplaceRelOptions:
			case AT_SetOptions:
			case AT_ResetOptions:
			case AT_SetStorage:
			case AT_AlterConstraint:
			case AT_ValidateConstraint:
				cmd_lockmode = ShareUpdateExclusiveLock;
				break;

			default:			
				elog(ERROR, "unrecognized alter table type: %d", (int) cmd->subtype);
				break;
		}

		
		if (cmd_lockmode > lockmode)
			lockmode = cmd_lockmode;
	}

	LOCKMODE	lockmode = AccessExclusiveLock;


	return lockmode;
}

static void ATController(Relation rel, List *cmds, bool recurse, LOCKMODE lockmode)
{
	List	   *wqueue = NIL;
	ListCell   *lcmd;

	
	foreach(lcmd, cmds)
	{
		AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);

		ATPrepCmd(&wqueue, rel, cmd, recurse, false, lockmode);
	}

	
	relation_close(rel, NoLock);

	
	ATRewriteCatalogs(&wqueue, lockmode);

	
	ATRewriteTables(&wqueue, lockmode);
}


static void ATPrepCmd(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse, bool recursing, LOCKMODE lockmode)

{
	AlteredTableInfo *tab;
	int			pass = AT_PASS_UNSET;

	
	tab = ATGetQueueEntry(wqueue, rel);

	
	cmd = copyObject(cmd);

	
	switch (cmd->subtype)
	{
		case AT_AddColumn:		
			ATSimplePermissions(rel, ATT_TABLE | ATT_COMPOSITE_TYPE | ATT_FOREIGN_TABLE);
			ATPrepAddColumn(wqueue, rel, recurse, recursing, cmd, lockmode);
			
			pass = AT_PASS_ADD_COL;
			break;
		case AT_AddColumnToView:		
			ATSimplePermissions(rel, ATT_VIEW);
			ATPrepAddColumn(wqueue, rel, recurse, recursing, cmd, lockmode);
			
			pass = AT_PASS_ADD_COL;
			break;
		case AT_ColumnDefault:	

			
			ATSimplePermissions(rel, ATT_TABLE | ATT_VIEW | ATT_FOREIGN_TABLE);
			ATSimpleRecursion(wqueue, rel, cmd, recurse, lockmode);
			
			pass = cmd->def ? AT_PASS_ADD_CONSTR : AT_PASS_DROP;
			break;
		case AT_DropNotNull:	
			ATSimplePermissions(rel, ATT_TABLE | ATT_FOREIGN_TABLE);
			ATSimpleRecursion(wqueue, rel, cmd, recurse, lockmode);
			
			pass = AT_PASS_DROP;
			break;
		case AT_SetNotNull:		
			ATSimplePermissions(rel, ATT_TABLE | ATT_FOREIGN_TABLE);
			ATSimpleRecursion(wqueue, rel, cmd, recurse, lockmode);
			
			pass = AT_PASS_ADD_CONSTR;
			break;
		case AT_SetStatistics:	
			ATSimpleRecursion(wqueue, rel, cmd, recurse, lockmode);
			
			ATPrepSetStatistics(rel, cmd->name, cmd->def, lockmode);
			pass = AT_PASS_MISC;
			break;
		case AT_SetOptions:		
		case AT_ResetOptions:	
			ATSimplePermissions(rel, ATT_TABLE | ATT_MATVIEW | ATT_INDEX | ATT_FOREIGN_TABLE);
			
			pass = AT_PASS_MISC;
			break;
		case AT_SetStorage:		
			ATSimplePermissions(rel, ATT_TABLE | ATT_MATVIEW);
			ATSimpleRecursion(wqueue, rel, cmd, recurse, lockmode);
			
			pass = AT_PASS_MISC;
			break;
		case AT_DropColumn:		
			ATSimplePermissions(rel, ATT_TABLE | ATT_COMPOSITE_TYPE | ATT_FOREIGN_TABLE);
			ATPrepDropColumn(wqueue, rel, recurse, recursing, cmd, lockmode);
			
			pass = AT_PASS_DROP;
			break;
		case AT_AddIndex:		
			ATSimplePermissions(rel, ATT_TABLE);
			
			
			pass = AT_PASS_ADD_INDEX;
			break;
		case AT_AddConstraint:	
			ATSimplePermissions(rel, ATT_TABLE);
			
			
			if (recurse)
				cmd->subtype = AT_AddConstraintRecurse;
			pass = AT_PASS_ADD_CONSTR;
			break;
		case AT_AddIndexConstraint:		
			ATSimplePermissions(rel, ATT_TABLE);
			
			
			pass = AT_PASS_ADD_CONSTR;
			break;
		case AT_DropConstraint:	
			ATSimplePermissions(rel, ATT_TABLE);
			
			
			if (recurse)
				cmd->subtype = AT_DropConstraintRecurse;
			pass = AT_PASS_DROP;
			break;
		case AT_AlterColumnType:		
			ATSimplePermissions(rel, ATT_TABLE | ATT_COMPOSITE_TYPE | ATT_FOREIGN_TABLE);
			
			ATPrepAlterColumnType(wqueue, tab, rel, recurse, recursing, cmd, lockmode);
			pass = AT_PASS_ALTER_TYPE;
			break;
		case AT_AlterColumnGenericOptions:
			ATSimplePermissions(rel, ATT_FOREIGN_TABLE);
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_ChangeOwner:	
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_ClusterOn:		
		case AT_DropCluster:	
			ATSimplePermissions(rel, ATT_TABLE | ATT_MATVIEW);
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_AddOids:		
			ATSimplePermissions(rel, ATT_TABLE);
			if (!rel->rd_rel->relhasoids || recursing)
				ATPrepAddOids(wqueue, rel, recurse, cmd, lockmode);
			
			pass = AT_PASS_ADD_COL;
			break;
		case AT_DropOids:		
			ATSimplePermissions(rel, ATT_TABLE);
			
			if (rel->rd_rel->relhasoids)
			{
				AlterTableCmd *dropCmd = makeNode(AlterTableCmd);

				dropCmd->subtype = AT_DropColumn;
				dropCmd->name = pstrdup("oid");
				dropCmd->behavior = cmd->behavior;
				ATPrepCmd(wqueue, rel, dropCmd, recurse, false, lockmode);
			}
			pass = AT_PASS_DROP;
			break;
		case AT_SetTableSpace:	
			ATSimplePermissions(rel, ATT_TABLE | ATT_MATVIEW | ATT_INDEX);
			
			ATPrepSetTableSpace(tab, rel, cmd->name, lockmode);
			pass = AT_PASS_MISC;	
			break;
		case AT_SetRelOptions:	
		case AT_ResetRelOptions:		
		case AT_ReplaceRelOptions:		
			ATSimplePermissions(rel, ATT_TABLE | ATT_VIEW | ATT_MATVIEW | ATT_INDEX);
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_AddInherit:		
			ATSimplePermissions(rel, ATT_TABLE);
			
			ATPrepAddInherit(rel);
			pass = AT_PASS_MISC;
			break;
		case AT_AlterConstraint:		
			ATSimplePermissions(rel, ATT_TABLE);
			pass = AT_PASS_MISC;
			break;
		case AT_ValidateConstraint:		
			ATSimplePermissions(rel, ATT_TABLE);
			
			
			if (recurse)
				cmd->subtype = AT_ValidateConstraintRecurse;
			pass = AT_PASS_MISC;
			break;
		case AT_ReplicaIdentity: 
			ATSimplePermissions(rel, ATT_TABLE | ATT_MATVIEW);
			pass = AT_PASS_MISC;
			
			
			break;
		case AT_EnableTrig:		
		case AT_EnableAlwaysTrig:
		case AT_EnableReplicaTrig:
		case AT_EnableTrigAll:
		case AT_EnableTrigUser:
		case AT_DisableTrig:	
		case AT_DisableTrigAll:
		case AT_DisableTrigUser:
		case AT_EnableRule:		
		case AT_EnableAlwaysRule:
		case AT_EnableReplicaRule:
		case AT_DisableRule:
		case AT_DropInherit:	
		case AT_AddOf:			
		case AT_DropOf: 
			ATSimplePermissions(rel, ATT_TABLE);
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_GenericOptions:
			ATSimplePermissions(rel, ATT_FOREIGN_TABLE);
			
			pass = AT_PASS_MISC;
			break;
		default:				
			elog(ERROR, "unrecognized alter table type: %d", (int) cmd->subtype);
			pass = AT_PASS_UNSET;		
			break;
	}
	Assert(pass > AT_PASS_UNSET);

	
	tab->subcmds[pass] = lappend(tab->subcmds[pass], cmd);
}


static void ATRewriteCatalogs(List **wqueue, LOCKMODE lockmode)
{
	int			pass;
	ListCell   *ltab;

	
	for (pass = 0; pass < AT_NUM_PASSES; pass++)
	{
		
		foreach(ltab, *wqueue)
		{
			AlteredTableInfo *tab = (AlteredTableInfo *) lfirst(ltab);
			List	   *subcmds = tab->subcmds[pass];
			Relation	rel;
			ListCell   *lcmd;

			if (subcmds == NIL)
				continue;

			
			rel = relation_open(tab->relid, NoLock);

			foreach(lcmd, subcmds)
				ATExecCmd(wqueue, tab, rel, (AlterTableCmd *) lfirst(lcmd), lockmode);

			
			if (pass == AT_PASS_ALTER_TYPE)
				ATPostAlterTypeCleanup(wqueue, tab, lockmode);

			relation_close(rel, NoLock);
		}
	}

	
	foreach(ltab, *wqueue)
	{
		AlteredTableInfo *tab = (AlteredTableInfo *) lfirst(ltab);

		if (tab->relkind == RELKIND_RELATION || tab->relkind == RELKIND_MATVIEW)
			AlterTableCreateToastTable(tab->relid, (Datum) 0);
	}
}


static void ATExecCmd(List **wqueue, AlteredTableInfo *tab, Relation rel, AlterTableCmd *cmd, LOCKMODE lockmode)

{
	switch (cmd->subtype)
	{
		case AT_AddColumn:		
		case AT_AddColumnToView:		
			ATExecAddColumn(wqueue, tab, rel, (ColumnDef *) cmd->def, false, false, false, lockmode);
			break;
		case AT_AddColumnRecurse:
			ATExecAddColumn(wqueue, tab, rel, (ColumnDef *) cmd->def, false, true, false, lockmode);
			break;
		case AT_ColumnDefault:	
			ATExecColumnDefault(rel, cmd->name, cmd->def, lockmode);
			break;
		case AT_DropNotNull:	
			ATExecDropNotNull(rel, cmd->name, lockmode);
			break;
		case AT_SetNotNull:		
			ATExecSetNotNull(tab, rel, cmd->name, lockmode);
			break;
		case AT_SetStatistics:	
			ATExecSetStatistics(rel, cmd->name, cmd->def, lockmode);
			break;
		case AT_SetOptions:		
			ATExecSetOptions(rel, cmd->name, cmd->def, false, lockmode);
			break;
		case AT_ResetOptions:	
			ATExecSetOptions(rel, cmd->name, cmd->def, true, lockmode);
			break;
		case AT_SetStorage:		
			ATExecSetStorage(rel, cmd->name, cmd->def, lockmode);
			break;
		case AT_DropColumn:		
			ATExecDropColumn(wqueue, rel, cmd->name, cmd->behavior, false, false, cmd->missing_ok, lockmode);
			break;
		case AT_DropColumnRecurse:		
			ATExecDropColumn(wqueue, rel, cmd->name, cmd->behavior, true, false, cmd->missing_ok, lockmode);
			break;
		case AT_AddIndex:		
			ATExecAddIndex(tab, rel, (IndexStmt *) cmd->def, false, lockmode);
			break;
		case AT_ReAddIndex:		
			ATExecAddIndex(tab, rel, (IndexStmt *) cmd->def, true, lockmode);
			break;
		case AT_AddConstraint:	
			ATExecAddConstraint(wqueue, tab, rel, (Constraint *) cmd->def, false, false, lockmode);
			break;
		case AT_AddConstraintRecurse:	
			ATExecAddConstraint(wqueue, tab, rel, (Constraint *) cmd->def, true, false, lockmode);
			break;
		case AT_ReAddConstraint:		
			ATExecAddConstraint(wqueue, tab, rel, (Constraint *) cmd->def, false, true, lockmode);
			break;
		case AT_AddIndexConstraint:		
			ATExecAddIndexConstraint(tab, rel, (IndexStmt *) cmd->def, lockmode);
			break;
		case AT_AlterConstraint:		
			ATExecAlterConstraint(rel, cmd, false, false, lockmode);
			break;
		case AT_ValidateConstraint:		
			ATExecValidateConstraint(rel, cmd->name, false, false, lockmode);
			break;
		case AT_ValidateConstraintRecurse:		
			ATExecValidateConstraint(rel, cmd->name, true, false, lockmode);
			break;
		case AT_DropConstraint:	
			ATExecDropConstraint(rel, cmd->name, cmd->behavior, false, false, cmd->missing_ok, lockmode);

			break;
		case AT_DropConstraintRecurse:	
			ATExecDropConstraint(rel, cmd->name, cmd->behavior, true, false, cmd->missing_ok, lockmode);

			break;
		case AT_AlterColumnType:		
			ATExecAlterColumnType(tab, rel, cmd, lockmode);
			break;
		case AT_AlterColumnGenericOptions:		
			ATExecAlterColumnGenericOptions(rel, cmd->name, (List *) cmd->def, lockmode);
			break;
		case AT_ChangeOwner:	
			ATExecChangeOwner(RelationGetRelid(rel), get_role_oid(cmd->name, false), false, lockmode);

			break;
		case AT_ClusterOn:		
			ATExecClusterOn(rel, cmd->name, lockmode);
			break;
		case AT_DropCluster:	
			ATExecDropCluster(rel, lockmode);
			break;
		case AT_AddOids:		
			
			if (cmd->def != NULL)
				ATExecAddColumn(wqueue, tab, rel, (ColumnDef *) cmd->def, true, false, false, lockmode);
			break;
		case AT_AddOidsRecurse:	
			
			if (cmd->def != NULL)
				ATExecAddColumn(wqueue, tab, rel, (ColumnDef *) cmd->def, true, true, false, lockmode);
			break;
		case AT_DropOids:		

			
			break;
		case AT_SetTableSpace:	

			
			break;
		case AT_SetRelOptions:	
		case AT_ResetRelOptions:		
		case AT_ReplaceRelOptions:		
			ATExecSetRelOptions(rel, (List *) cmd->def, cmd->subtype, lockmode);
			break;
		case AT_EnableTrig:		
			ATExecEnableDisableTrigger(rel, cmd->name, TRIGGER_FIRES_ON_ORIGIN, false, lockmode);
			break;
		case AT_EnableAlwaysTrig:		
			ATExecEnableDisableTrigger(rel, cmd->name, TRIGGER_FIRES_ALWAYS, false, lockmode);
			break;
		case AT_EnableReplicaTrig:		
			ATExecEnableDisableTrigger(rel, cmd->name, TRIGGER_FIRES_ON_REPLICA, false, lockmode);
			break;
		case AT_DisableTrig:	
			ATExecEnableDisableTrigger(rel, cmd->name, TRIGGER_DISABLED, false, lockmode);
			break;
		case AT_EnableTrigAll:	
			ATExecEnableDisableTrigger(rel, NULL, TRIGGER_FIRES_ON_ORIGIN, false, lockmode);
			break;
		case AT_DisableTrigAll:	
			ATExecEnableDisableTrigger(rel, NULL, TRIGGER_DISABLED, false, lockmode);
			break;
		case AT_EnableTrigUser:	
			ATExecEnableDisableTrigger(rel, NULL, TRIGGER_FIRES_ON_ORIGIN, true, lockmode);
			break;
		case AT_DisableTrigUser:		
			ATExecEnableDisableTrigger(rel, NULL, TRIGGER_DISABLED, true, lockmode);
			break;

		case AT_EnableRule:		
			ATExecEnableDisableRule(rel, cmd->name, RULE_FIRES_ON_ORIGIN, lockmode);
			break;
		case AT_EnableAlwaysRule:		
			ATExecEnableDisableRule(rel, cmd->name, RULE_FIRES_ALWAYS, lockmode);
			break;
		case AT_EnableReplicaRule:		
			ATExecEnableDisableRule(rel, cmd->name, RULE_FIRES_ON_REPLICA, lockmode);
			break;
		case AT_DisableRule:	
			ATExecEnableDisableRule(rel, cmd->name, RULE_DISABLED, lockmode);
			break;

		case AT_AddInherit:
			ATExecAddInherit(rel, (RangeVar *) cmd->def, lockmode);
			break;
		case AT_DropInherit:
			ATExecDropInherit(rel, (RangeVar *) cmd->def, lockmode);
			break;
		case AT_AddOf:
			ATExecAddOf(rel, (TypeName *) cmd->def, lockmode);
			break;
		case AT_DropOf:
			ATExecDropOf(rel, lockmode);
			break;
		case AT_ReplicaIdentity:
			ATExecReplicaIdentity(rel, (ReplicaIdentityStmt *) cmd->def, lockmode);
			break;
		case AT_GenericOptions:
			ATExecGenericOptions(rel, (List *) cmd->def);
			break;
		default:				
			elog(ERROR, "unrecognized alter table type: %d", (int) cmd->subtype);
			break;
	}

	
	CommandCounterIncrement();
}


static void ATRewriteTables(List **wqueue, LOCKMODE lockmode)
{
	ListCell   *ltab;

	
	foreach(ltab, *wqueue)
	{
		AlteredTableInfo *tab = (AlteredTableInfo *) lfirst(ltab);

		
		if (tab->relkind == RELKIND_FOREIGN_TABLE)
			continue;

		
		if (tab->newvals != NIL || tab->rewrite)
		{
			Relation	rel;

			rel = heap_open(tab->relid, NoLock);
			find_composite_type_dependencies(rel->rd_rel->reltype, rel, NULL);
			heap_close(rel, NoLock);
		}

		
		if (tab->rewrite)
		{
			
			Relation	OldHeap;
			Oid			OIDNewHeap;
			Oid			NewTableSpace;

			OldHeap = heap_open(tab->relid, NoLock);

			
			if (IsSystemRelation(OldHeap))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rewrite system relation \"%s\"", RelationGetRelationName(OldHeap))));



			if (RelationIsUsedAsCatalogTable(OldHeap))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rewrite table \"%s\" used as a catalog table", RelationGetRelationName(OldHeap))));



			
			if (RELATION_IS_OTHER_TEMP(OldHeap))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rewrite temporary tables of other sessions")));


			
			if (tab->newTableSpace)
				NewTableSpace = tab->newTableSpace;
			else NewTableSpace = OldHeap->rd_rel->reltablespace;

			heap_close(OldHeap, NoLock);

			
			OIDNewHeap = make_new_heap(tab->relid, NewTableSpace, false, AccessExclusiveLock);

			
			ATRewriteTable(tab, OIDNewHeap, lockmode);

			
			finish_heap_swap(tab->relid, OIDNewHeap, false, false, true, !OidIsValid(tab->newTableSpace), RecentXmin, ReadNextMultiXactId());



		}
		else {
			
			if (tab->constraints != NIL || tab->new_notnull)
				ATRewriteTable(tab, InvalidOid, lockmode);

			
			if (tab->newTableSpace)
				ATExecSetTableSpace(tab->relid, tab->newTableSpace, lockmode);
		}
	}

	
	foreach(ltab, *wqueue)
	{
		AlteredTableInfo *tab = (AlteredTableInfo *) lfirst(ltab);
		Relation	rel = NULL;
		ListCell   *lcon;

		foreach(lcon, tab->constraints)
		{
			NewConstraint *con = lfirst(lcon);

			if (con->contype == CONSTR_FOREIGN)
			{
				Constraint *fkconstraint = (Constraint *) con->qual;
				Relation	refrel;

				if (rel == NULL)
				{
					
					rel = heap_open(tab->relid, NoLock);
				}

				refrel = heap_open(con->refrelid, RowShareLock);

				validateForeignKeyConstraint(fkconstraint->conname, rel, refrel, con->refindid, con->conid);


				

				heap_close(refrel, NoLock);
			}
		}

		if (rel)
			heap_close(rel, NoLock);
	}
}


static void ATRewriteTable(AlteredTableInfo *tab, Oid OIDNewHeap, LOCKMODE lockmode)
{
	Relation	oldrel;
	Relation	newrel;
	TupleDesc	oldTupDesc;
	TupleDesc	newTupDesc;
	bool		needscan = false;
	List	   *notnull_attrs;
	int			i;
	ListCell   *l;
	EState	   *estate;
	CommandId	mycid;
	BulkInsertState bistate;
	int			hi_options;

	
	oldrel = heap_open(tab->relid, NoLock);
	oldTupDesc = tab->oldDesc;
	newTupDesc = RelationGetDescr(oldrel);		

	if (OidIsValid(OIDNewHeap))
		newrel = heap_open(OIDNewHeap, lockmode);
	else newrel = NULL;

	
	if (newrel)
	{
		mycid = GetCurrentCommandId(true);
		bistate = GetBulkInsertState();

		hi_options = HEAP_INSERT_SKIP_FSM;
		if (!XLogIsNeeded())
			hi_options |= HEAP_INSERT_SKIP_WAL;
	}
	else {
		
		mycid = 0;
		bistate = NULL;
		hi_options = 0;
	}

	

	estate = CreateExecutorState();

	
	foreach(l, tab->constraints)
	{
		NewConstraint *con = lfirst(l);

		switch (con->contype)
		{
			case CONSTR_CHECK:
				needscan = true;
				con->qualstate = (List *)
					ExecPrepareExpr((Expr *) con->qual, estate);
				break;
			case CONSTR_FOREIGN:
				
				break;
			default:
				elog(ERROR, "unrecognized constraint type: %d", (int) con->contype);
		}
	}

	foreach(l, tab->newvals)
	{
		NewColumnValue *ex = lfirst(l);

		
		ex->exprstate = ExecInitExpr((Expr *) ex->expr, NULL);
	}

	notnull_attrs = NIL;
	if (newrel || tab->new_notnull)
	{
		
		for (i = 0; i < newTupDesc->natts; i++)
		{
			if (newTupDesc->attrs[i]->attnotnull && !newTupDesc->attrs[i]->attisdropped)
				notnull_attrs = lappend_int(notnull_attrs, i);
		}
		if (notnull_attrs)
			needscan = true;
	}

	if (newrel || needscan)
	{
		ExprContext *econtext;
		Datum	   *values;
		bool	   *isnull;
		TupleTableSlot *oldslot;
		TupleTableSlot *newslot;
		HeapScanDesc scan;
		HeapTuple	tuple;
		MemoryContext oldCxt;
		List	   *dropped_attrs = NIL;
		ListCell   *lc;
		Snapshot	snapshot;

		if (newrel)
			ereport(DEBUG1, (errmsg("rewriting table \"%s\"", RelationGetRelationName(oldrel))));

		else ereport(DEBUG1, (errmsg("verifying table \"%s\"", RelationGetRelationName(oldrel))));



		if (newrel)
		{
			
			TransferPredicateLocksToHeapRelation(oldrel);
		}

		econtext = GetPerTupleExprContext(estate);

		
		oldslot = MakeSingleTupleTableSlot(oldTupDesc);
		newslot = MakeSingleTupleTableSlot(newTupDesc);

		
		i = Max(newTupDesc->natts, oldTupDesc->natts);
		values = (Datum *) palloc(i * sizeof(Datum));
		isnull = (bool *) palloc(i * sizeof(bool));
		memset(values, 0, i * sizeof(Datum));
		memset(isnull, true, i * sizeof(bool));

		
		for (i = 0; i < newTupDesc->natts; i++)
		{
			if (newTupDesc->attrs[i]->attisdropped)
				dropped_attrs = lappend_int(dropped_attrs, i);
		}

		
		snapshot = RegisterSnapshot(GetLatestSnapshot());
		scan = heap_beginscan(oldrel, snapshot, 0, NULL);

		
		oldCxt = MemoryContextSwitchTo(GetPerTupleMemoryContext(estate));

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			if (tab->rewrite)
			{
				Oid			tupOid = InvalidOid;

				
				heap_deform_tuple(tuple, oldTupDesc, values, isnull);
				if (oldTupDesc->tdhasoid)
					tupOid = HeapTupleGetOid(tuple);

				
				foreach(lc, dropped_attrs)
					isnull[lfirst_int(lc)] = true;

				
				ExecStoreTuple(tuple, oldslot, InvalidBuffer, false);
				econtext->ecxt_scantuple = oldslot;

				foreach(l, tab->newvals)
				{
					NewColumnValue *ex = lfirst(l);

					values[ex->attnum - 1] = ExecEvalExpr(ex->exprstate, econtext, &isnull[ex->attnum - 1], NULL);


				}

				
				tuple = heap_form_tuple(newTupDesc, values, isnull);

				
				if (newTupDesc->tdhasoid)
					HeapTupleSetOid(tuple, tupOid);

				
				tuple->t_tableOid = RelationGetRelid(oldrel);
			}

			
			ExecStoreTuple(tuple, newslot, InvalidBuffer, false);
			econtext->ecxt_scantuple = newslot;

			foreach(l, notnull_attrs)
			{
				int			attn = lfirst_int(l);

				if (heap_attisnull(tuple, attn + 1))
					ereport(ERROR, (errcode(ERRCODE_NOT_NULL_VIOLATION), errmsg("column \"%s\" contains null values", NameStr(newTupDesc->attrs[attn]->attname)), errtablecol(oldrel, attn + 1)));



			}

			foreach(l, tab->constraints)
			{
				NewConstraint *con = lfirst(l);

				switch (con->contype)
				{
					case CONSTR_CHECK:
						if (!ExecQual(con->qualstate, econtext, true))
							ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("check constraint \"%s\" is violated by some row", con->name), errtableconstraint(oldrel, con->name)));



						break;
					case CONSTR_FOREIGN:
						
						break;
					default:
						elog(ERROR, "unrecognized constraint type: %d", (int) con->contype);
				}
			}

			
			if (newrel)
				heap_insert(newrel, tuple, mycid, hi_options, bistate);

			ResetExprContext(econtext);

			CHECK_FOR_INTERRUPTS();
		}

		MemoryContextSwitchTo(oldCxt);
		heap_endscan(scan);
		UnregisterSnapshot(snapshot);

		ExecDropSingleTupleTableSlot(oldslot);
		ExecDropSingleTupleTableSlot(newslot);
	}

	FreeExecutorState(estate);

	heap_close(oldrel, NoLock);
	if (newrel)
	{
		FreeBulkInsertState(bistate);

		
		if (hi_options & HEAP_INSERT_SKIP_WAL)
			heap_sync(newrel);

		heap_close(newrel, NoLock);
	}
}


static AlteredTableInfo * ATGetQueueEntry(List **wqueue, Relation rel)
{
	Oid			relid = RelationGetRelid(rel);
	AlteredTableInfo *tab;
	ListCell   *ltab;

	foreach(ltab, *wqueue)
	{
		tab = (AlteredTableInfo *) lfirst(ltab);
		if (tab->relid == relid)
			return tab;
	}

	
	tab = (AlteredTableInfo *) palloc0(sizeof(AlteredTableInfo));
	tab->relid = relid;
	tab->relkind = rel->rd_rel->relkind;
	tab->oldDesc = CreateTupleDescCopy(RelationGetDescr(rel));

	*wqueue = lappend(*wqueue, tab);

	return tab;
}


static void ATSimplePermissions(Relation rel, int allowed_targets)
{
	int			actual_target;

	switch (rel->rd_rel->relkind)
	{
		case RELKIND_RELATION:
			actual_target = ATT_TABLE;
			break;
		case RELKIND_VIEW:
			actual_target = ATT_VIEW;
			break;
		case RELKIND_MATVIEW:
			actual_target = ATT_MATVIEW;
			break;
		case RELKIND_INDEX:
			actual_target = ATT_INDEX;
			break;
		case RELKIND_COMPOSITE_TYPE:
			actual_target = ATT_COMPOSITE_TYPE;
			break;
		case RELKIND_FOREIGN_TABLE:
			actual_target = ATT_FOREIGN_TABLE;
			break;
		default:
			actual_target = 0;
			break;
	}

	
	if ((actual_target & allowed_targets) == 0)
		ATWrongRelkindError(rel, allowed_targets);

	
	if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(rel));

	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));


}


static void ATWrongRelkindError(Relation rel, int allowed_targets)
{
	char	   *msg;

	switch (allowed_targets)
	{
		case ATT_TABLE:
			msg = _("\"%s\" is not a table");
			break;
		case ATT_TABLE | ATT_VIEW:
			msg = _("\"%s\" is not a table or view");
			break;
		case ATT_TABLE | ATT_VIEW | ATT_MATVIEW | ATT_INDEX:
			msg = _("\"%s\" is not a table, view, materialized view, or index");
			break;
		case ATT_TABLE | ATT_MATVIEW:
			msg = _("\"%s\" is not a table or materialized view");
			break;
		case ATT_TABLE | ATT_MATVIEW | ATT_INDEX:
			msg = _("\"%s\" is not a table, materialized view, or index");
			break;
		case ATT_TABLE | ATT_FOREIGN_TABLE:
			msg = _("\"%s\" is not a table or foreign table");
			break;
		case ATT_TABLE | ATT_COMPOSITE_TYPE | ATT_FOREIGN_TABLE:
			msg = _("\"%s\" is not a table, composite type, or foreign table");
			break;
		case ATT_TABLE | ATT_MATVIEW | ATT_INDEX | ATT_FOREIGN_TABLE:
			msg = _("\"%s\" is not a table, materialized view, composite type, or foreign table");
			break;
		case ATT_VIEW:
			msg = _("\"%s\" is not a view");
			break;
		case ATT_FOREIGN_TABLE:
			msg = _("\"%s\" is not a foreign table");
			break;
		default:
			
			msg = _("\"%s\" is of the wrong type");
			break;
	}

	ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg(msg, RelationGetRelationName(rel))));

}


static void ATSimpleRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse, LOCKMODE lockmode)

{
	
	if (recurse && rel->rd_rel->relkind == RELKIND_RELATION)
	{
		Oid			relid = RelationGetRelid(rel);
		ListCell   *child;
		List	   *children;

		children = find_all_inheritors(relid, lockmode, NULL);

		
		foreach(child, children)
		{
			Oid			childrelid = lfirst_oid(child);
			Relation	childrel;

			if (childrelid == relid)
				continue;
			
			childrel = relation_open(childrelid, NoLock);
			CheckTableNotInUse(childrel, "ALTER TABLE");
			ATPrepCmd(wqueue, childrel, cmd, false, true, lockmode);
			relation_close(childrel, NoLock);
		}
	}
}


static void ATTypedTableRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd, LOCKMODE lockmode)

{
	ListCell   *child;
	List	   *children;

	Assert(rel->rd_rel->relkind == RELKIND_COMPOSITE_TYPE);

	children = find_typed_table_dependencies(rel->rd_rel->reltype, RelationGetRelationName(rel), cmd->behavior);


	foreach(child, children)
	{
		Oid			childrelid = lfirst_oid(child);
		Relation	childrel;

		childrel = relation_open(childrelid, lockmode);
		CheckTableNotInUse(childrel, "ALTER TABLE");
		ATPrepCmd(wqueue, childrel, cmd, true, true, lockmode);
		relation_close(childrel, NoLock);
	}
}



void find_composite_type_dependencies(Oid typeOid, Relation origRelation, const char *origTypeName)

{
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc depScan;
	HeapTuple	depTup;
	Oid			arrayOid;

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(TypeRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typeOid));



	depScan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(depTup = systable_getnext(depScan)))
	{
		Form_pg_depend pg_depend = (Form_pg_depend) GETSTRUCT(depTup);
		Relation	rel;
		Form_pg_attribute att;

		
		
		if (pg_depend->classid != RelationRelationId || pg_depend->objsubid <= 0)
			continue;

		rel = relation_open(pg_depend->objid, AccessShareLock);
		att = rel->rd_att->attrs[pg_depend->objsubid - 1];

		if (rel->rd_rel->relkind == RELKIND_RELATION || rel->rd_rel->relkind == RELKIND_MATVIEW)
		{
			if (origTypeName)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter type \"%s\" because column \"%s.%s\" uses it", origTypeName, RelationGetRelationName(rel), NameStr(att->attname))));




			else if (origRelation->rd_rel->relkind == RELKIND_COMPOSITE_TYPE)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter type \"%s\" because column \"%s.%s\" uses it", RelationGetRelationName(origRelation), RelationGetRelationName(rel), NameStr(att->attname))));




			else if (origRelation->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter foreign table \"%s\" because column \"%s.%s\" uses its row type", RelationGetRelationName(origRelation), RelationGetRelationName(rel), NameStr(att->attname))));




			else ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter table \"%s\" because column \"%s.%s\" uses its row type", RelationGetRelationName(origRelation), RelationGetRelationName(rel), NameStr(att->attname))));





		}
		else if (OidIsValid(rel->rd_rel->reltype))
		{
			
			find_composite_type_dependencies(rel->rd_rel->reltype, origRelation, origTypeName);
		}

		relation_close(rel, AccessShareLock);
	}

	systable_endscan(depScan);

	relation_close(depRel, AccessShareLock);

	
	arrayOid = get_array_type(typeOid);
	if (OidIsValid(arrayOid))
		find_composite_type_dependencies(arrayOid, origRelation, origTypeName);
}



static List * find_typed_table_dependencies(Oid typeOid, const char *typeName, DropBehavior behavior)
{
	Relation	classRel;
	ScanKeyData key[1];
	HeapScanDesc scan;
	HeapTuple	tuple;
	List	   *result = NIL;

	classRel = heap_open(RelationRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_class_reloftype, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typeOid));



	scan = heap_beginscan_catalog(classRel, 1, key);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		if (behavior == DROP_RESTRICT)
			ereport(ERROR, (errcode(ERRCODE_DEPENDENT_OBJECTS_STILL_EXIST), errmsg("cannot alter type \"%s\" because it is the type of a typed table", typeName), errhint("Use ALTER ... CASCADE to alter the typed tables too.")));



		else result = lappend_oid(result, HeapTupleGetOid(tuple));
	}

	heap_endscan(scan);
	heap_close(classRel, AccessShareLock);

	return result;
}



void check_of_type(HeapTuple typetuple)
{
	Form_pg_type typ = (Form_pg_type) GETSTRUCT(typetuple);
	bool		typeOk = false;

	if (typ->typtype == TYPTYPE_COMPOSITE)
	{
		Relation	typeRelation;

		Assert(OidIsValid(typ->typrelid));
		typeRelation = relation_open(typ->typrelid, AccessShareLock);
		typeOk = (typeRelation->rd_rel->relkind == RELKIND_COMPOSITE_TYPE);

		
		relation_close(typeRelation, NoLock);
	}
	if (!typeOk)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("type %s is not a composite type", format_type_be(HeapTupleGetOid(typetuple)))));


}



static void ATPrepAddColumn(List **wqueue, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd, LOCKMODE lockmode)

{
	if (rel->rd_rel->reloftype && !recursing)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot add column to typed table")));


	if (rel->rd_rel->relkind == RELKIND_COMPOSITE_TYPE)
		ATTypedTableRecursion(wqueue, rel, cmd, lockmode);

	if (recurse)
		cmd->subtype = AT_AddColumnRecurse;
}

static void ATExecAddColumn(List **wqueue, AlteredTableInfo *tab, Relation rel, ColumnDef *colDef, bool isOid, bool recurse, bool recursing, LOCKMODE lockmode)


{
	Oid			myrelid = RelationGetRelid(rel);
	Relation	pgclass, attrdesc;
	HeapTuple	reltup;
	FormData_pg_attribute attribute;
	int			newattnum;
	char		relkind;
	HeapTuple	typeTuple;
	Oid			typeOid;
	int32		typmod;
	Oid			collOid;
	Form_pg_type tform;
	Expr	   *defval;
	List	   *children;
	ListCell   *child;
	AclResult	aclresult;

	
	if (recursing)
		ATSimplePermissions(rel, ATT_TABLE);

	attrdesc = heap_open(AttributeRelationId, RowExclusiveLock);

	
	if (colDef->inhcount > 0)
	{
		HeapTuple	tuple;

		
		tuple = SearchSysCacheCopyAttName(myrelid, colDef->colname);
		if (HeapTupleIsValid(tuple))
		{
			Form_pg_attribute childatt = (Form_pg_attribute) GETSTRUCT(tuple);
			Oid			ctypeId;
			int32		ctypmod;
			Oid			ccollid;

			
			typenameTypeIdAndMod(NULL, colDef->typeName, &ctypeId, &ctypmod);
			if (ctypeId != childatt->atttypid || ctypmod != childatt->atttypmod)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table \"%s\" has different type for column \"%s\"", RelationGetRelationName(rel), colDef->colname)));


			ccollid = GetColumnDefCollation(NULL, colDef, ctypeId);
			if (ccollid != childatt->attcollation)
				ereport(ERROR, (errcode(ERRCODE_COLLATION_MISMATCH), errmsg("child table \"%s\" has different collation for column \"%s\"", RelationGetRelationName(rel), colDef->colname), errdetail("\"%s\" versus \"%s\"", get_collation_name(ccollid), get_collation_name(childatt->attcollation))));






			
			if (isOid && childatt->attnum != ObjectIdAttributeNumber)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table \"%s\" has a conflicting \"%s\" column", RelationGetRelationName(rel), colDef->colname)));



			
			childatt->attinhcount++;
			simple_heap_update(attrdesc, &tuple->t_self, tuple);
			CatalogUpdateIndexes(attrdesc, tuple);

			heap_freetuple(tuple);

			
			ereport(NOTICE, (errmsg("merging definition of column \"%s\" for child \"%s\"", colDef->colname, RelationGetRelationName(rel))));


			heap_close(attrdesc, RowExclusiveLock);
			return;
		}
	}

	pgclass = heap_open(RelationRelationId, RowExclusiveLock);

	reltup = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(myrelid));
	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "cache lookup failed for relation %u", myrelid);
	relkind = ((Form_pg_class) GETSTRUCT(reltup))->relkind;

	
	check_for_column_name_collision(rel, colDef->colname);

	
	if (isOid)
		newattnum = ObjectIdAttributeNumber;
	else {
		newattnum = ((Form_pg_class) GETSTRUCT(reltup))->relnatts + 1;
		if (newattnum > MaxHeapAttributeNumber)
			ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("tables can have at most %d columns", MaxHeapAttributeNumber)));


	}

	typeTuple = typenameType(NULL, colDef->typeName, &typmod);
	tform = (Form_pg_type) GETSTRUCT(typeTuple);
	typeOid = HeapTupleGetOid(typeTuple);

	aclresult = pg_type_aclcheck(typeOid, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, typeOid);

	collOid = GetColumnDefCollation(NULL, colDef, typeOid);

	
	CheckAttributeType(colDef->colname, typeOid, collOid, list_make1_oid(rel->rd_rel->reltype), false);


	
	attribute.attrelid = myrelid;
	namestrcpy(&(attribute.attname), colDef->colname);
	attribute.atttypid = typeOid;
	attribute.attstattarget = (newattnum > 0) ? -1 : 0;
	attribute.attlen = tform->typlen;
	attribute.attcacheoff = -1;
	attribute.atttypmod = typmod;
	attribute.attnum = newattnum;
	attribute.attbyval = tform->typbyval;
	attribute.attndims = list_length(colDef->typeName->arrayBounds);
	attribute.attstorage = tform->typstorage;
	attribute.attalign = tform->typalign;
	attribute.attnotnull = colDef->is_not_null;
	attribute.atthasdef = false;
	attribute.attisdropped = false;
	attribute.attislocal = colDef->is_local;
	attribute.attinhcount = colDef->inhcount;
	attribute.attcollation = collOid;
	

	ReleaseSysCache(typeTuple);

	InsertPgAttributeTuple(attrdesc, &attribute, NULL);

	heap_close(attrdesc, RowExclusiveLock);

	
	if (isOid)
		((Form_pg_class) GETSTRUCT(reltup))->relhasoids = true;
	else ((Form_pg_class) GETSTRUCT(reltup))->relnatts = newattnum;

	simple_heap_update(pgclass, &reltup->t_self, reltup);

	
	CatalogUpdateIndexes(pgclass, reltup);

	heap_freetuple(reltup);

	
	InvokeObjectPostCreateHook(RelationRelationId, myrelid, newattnum);

	heap_close(pgclass, RowExclusiveLock);

	
	CommandCounterIncrement();

	
	if (colDef->raw_default)
	{
		RawColumnDefault *rawEnt;

		rawEnt = (RawColumnDefault *) palloc(sizeof(RawColumnDefault));
		rawEnt->attnum = attribute.attnum;
		rawEnt->raw_default = copyObject(colDef->raw_default);

		
		AddRelationNewConstraints(rel, list_make1(rawEnt), NIL, false, true, false);

		
		CommandCounterIncrement();
	}

	
	if (relkind != RELKIND_VIEW && relkind != RELKIND_COMPOSITE_TYPE && relkind != RELKIND_FOREIGN_TABLE && attribute.attnum > 0)
	{
		defval = (Expr *) build_column_default(rel, attribute.attnum);

		if (!defval && GetDomainConstraints(typeOid) != NIL)
		{
			Oid			baseTypeId;
			int32		baseTypeMod;
			Oid			baseTypeColl;

			baseTypeMod = typmod;
			baseTypeId = getBaseTypeAndTypmod(typeOid, &baseTypeMod);
			baseTypeColl = get_typcollation(baseTypeId);
			defval = (Expr *) makeNullConst(baseTypeId, baseTypeMod, baseTypeColl);
			defval = (Expr *) coerce_to_target_type(NULL, (Node *) defval, baseTypeId, typeOid, typmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST, -1);






			if (defval == NULL) 
				elog(ERROR, "failed to coerce base type to domain");
		}

		if (defval)
		{
			NewColumnValue *newval;

			newval = (NewColumnValue *) palloc0(sizeof(NewColumnValue));
			newval->attnum = attribute.attnum;
			newval->expr = expression_planner(defval);

			tab->newvals = lappend(tab->newvals, newval);
			tab->rewrite = true;
		}

		
		tab->new_notnull |= colDef->is_not_null;
	}

	
	if (isOid)
		tab->rewrite = true;

	
	add_column_datatype_dependency(myrelid, newattnum, attribute.atttypid);
	add_column_collation_dependency(myrelid, newattnum, attribute.attcollation);

	
	children = find_inheritance_children(RelationGetRelid(rel), lockmode);

	
	if (children && !recurse)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("column must be added to child tables too")));


	
	if (!recursing)
	{
		colDef = copyObject(colDef);
		colDef->inhcount = 1;
		colDef->is_local = false;
	}

	foreach(child, children)
	{
		Oid			childrelid = lfirst_oid(child);
		Relation	childrel;
		AlteredTableInfo *childtab;

		
		childrel = heap_open(childrelid, NoLock);
		CheckTableNotInUse(childrel, "ALTER TABLE");

		
		childtab = ATGetQueueEntry(wqueue, childrel);

		
		ATExecAddColumn(wqueue, childtab, childrel, colDef, isOid, recurse, true, lockmode);

		heap_close(childrel, NoLock);
	}
}


static void check_for_column_name_collision(Relation rel, const char *colname)
{
	HeapTuple	attTuple;
	int			attnum;

	
	attTuple = SearchSysCache2(ATTNAME, ObjectIdGetDatum(RelationGetRelid(rel)), PointerGetDatum(colname));

	if (!HeapTupleIsValid(attTuple))
		return;

	attnum = ((Form_pg_attribute) GETSTRUCT(attTuple))->attnum;
	ReleaseSysCache(attTuple);

	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column name \"%s\" conflicts with a system column name", colname)));


	else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" of relation \"%s\" already exists", colname, RelationGetRelationName(rel))));



}


static void add_column_datatype_dependency(Oid relid, int32 attnum, Oid typid)
{
	ObjectAddress myself, referenced;

	myself.classId = RelationRelationId;
	myself.objectId = relid;
	myself.objectSubId = attnum;
	referenced.classId = TypeRelationId;
	referenced.objectId = typid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
}


static void add_column_collation_dependency(Oid relid, int32 attnum, Oid collid)
{
	ObjectAddress myself, referenced;

	
	if (OidIsValid(collid) && collid != DEFAULT_COLLATION_OID)
	{
		myself.classId = RelationRelationId;
		myself.objectId = relid;
		myself.objectSubId = attnum;
		referenced.classId = CollationRelationId;
		referenced.objectId = collid;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}
}


static void ATPrepAddOids(List **wqueue, Relation rel, bool recurse, AlterTableCmd *cmd, LOCKMODE lockmode)
{
	
	if (cmd->def == NULL)
	{
		ColumnDef  *cdef = makeNode(ColumnDef);

		cdef->colname = pstrdup("oid");
		cdef->typeName = makeTypeNameFromOid(OIDOID, -1);
		cdef->inhcount = 0;
		cdef->is_local = true;
		cdef->is_not_null = true;
		cdef->storage = 0;
		cdef->location = -1;
		cmd->def = (Node *) cdef;
	}
	ATPrepAddColumn(wqueue, rel, recurse, false, cmd, lockmode);

	if (recurse)
		cmd->subtype = AT_AddOidsRecurse;
}


static void ATExecDropNotNull(Relation rel, const char *colName, LOCKMODE lockmode)
{
	HeapTuple	tuple;
	AttrNumber	attnum;
	Relation	attr_rel;
	List	   *indexoidlist;
	ListCell   *indexoidscan;

	
	attr_rel = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));



	attnum = ((Form_pg_attribute) GETSTRUCT(tuple))->attnum;

	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	

	
	indexoidlist = RelationGetIndexList(rel);

	foreach(indexoidscan, indexoidlist)
	{
		Oid			indexoid = lfirst_oid(indexoidscan);
		HeapTuple	indexTuple;
		Form_pg_index indexStruct;
		int			i;

		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexoid));
		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		indexStruct = (Form_pg_index) GETSTRUCT(indexTuple);

		
		if (indexStruct->indisprimary)
		{
			
			for (i = 0; i < indexStruct->indnatts; i++)
			{
				if (indexStruct->indkey.values[i] == attnum)
					ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("column \"%s\" is in a primary key", colName)));


			}
		}

		ReleaseSysCache(indexTuple);
	}

	list_free(indexoidlist);

	
	if (((Form_pg_attribute) GETSTRUCT(tuple))->attnotnull)
	{
		((Form_pg_attribute) GETSTRUCT(tuple))->attnotnull = FALSE;

		simple_heap_update(attr_rel, &tuple->t_self, tuple);

		
		CatalogUpdateIndexes(attr_rel, tuple);
	}

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), attnum);

	heap_close(attr_rel, RowExclusiveLock);
}


static void ATExecSetNotNull(AlteredTableInfo *tab, Relation rel, const char *colName, LOCKMODE lockmode)

{
	HeapTuple	tuple;
	AttrNumber	attnum;
	Relation	attr_rel;

	
	attr_rel = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));



	attnum = ((Form_pg_attribute) GETSTRUCT(tuple))->attnum;

	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	if (!((Form_pg_attribute) GETSTRUCT(tuple))->attnotnull)
	{
		((Form_pg_attribute) GETSTRUCT(tuple))->attnotnull = TRUE;

		simple_heap_update(attr_rel, &tuple->t_self, tuple);

		
		CatalogUpdateIndexes(attr_rel, tuple);

		
		tab->new_notnull = true;
	}

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), attnum);

	heap_close(attr_rel, RowExclusiveLock);
}


static void ATExecColumnDefault(Relation rel, const char *colName, Node *newDefault, LOCKMODE lockmode)

{
	AttrNumber	attnum;

	
	attnum = get_attnum(RelationGetRelid(rel), colName);
	if (attnum == InvalidAttrNumber)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));



	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	RemoveAttrDefault(RelationGetRelid(rel), attnum, DROP_RESTRICT, false, newDefault == NULL ? false : true);

	if (newDefault)
	{
		
		RawColumnDefault *rawEnt;

		rawEnt = (RawColumnDefault *) palloc(sizeof(RawColumnDefault));
		rawEnt->attnum = attnum;
		rawEnt->raw_default = newDefault;

		
		AddRelationNewConstraints(rel, list_make1(rawEnt), NIL, false, true, false);
	}
}


static void ATPrepSetStatistics(Relation rel, const char *colName, Node *newValue, LOCKMODE lockmode)
{
	
	if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_MATVIEW && rel->rd_rel->relkind != RELKIND_INDEX && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE)


		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, materialized view, index, or foreign table", RelationGetRelationName(rel))));



	
	if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(rel));
}

static void ATExecSetStatistics(Relation rel, const char *colName, Node *newValue, LOCKMODE lockmode)
{
	int			newtarget;
	Relation	attrelation;
	HeapTuple	tuple;
	Form_pg_attribute attrtuple;

	Assert(IsA(newValue, Integer));
	newtarget = intVal(newValue);

	
	if (newtarget < -1)
	{
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("statistics target %d is too low", newtarget)));


	}
	else if (newtarget > 10000)
	{
		newtarget = 10000;
		ereport(WARNING, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("lowering statistics target to %d", newtarget)));


	}

	attrelation = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	if (attrtuple->attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	attrtuple->attstattarget = newtarget;

	simple_heap_update(attrelation, &tuple->t_self, tuple);

	
	CatalogUpdateIndexes(attrelation, tuple);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), attrtuple->attnum);

	heap_freetuple(tuple);

	heap_close(attrelation, RowExclusiveLock);
}

static void ATExecSetOptions(Relation rel, const char *colName, Node *options, bool isReset, LOCKMODE lockmode)

{
	Relation	attrelation;
	HeapTuple	tuple, newtuple;
	Form_pg_attribute attrtuple;
	Datum		datum, newOptions;
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];

	attrelation = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheAttName(RelationGetRelid(rel), colName);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	if (attrtuple->attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	Assert(IsA(options, List));
	datum = SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attoptions, &isnull);
	newOptions = transformRelOptions(isnull ? (Datum) 0 : datum, (List *) options, NULL, NULL, false, isReset);

	
	(void) attribute_reloptions(newOptions, true);

	
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));
	if (newOptions != (Datum) 0)
		repl_val[Anum_pg_attribute_attoptions - 1] = newOptions;
	else repl_null[Anum_pg_attribute_attoptions - 1] = true;
	repl_repl[Anum_pg_attribute_attoptions - 1] = true;
	newtuple = heap_modify_tuple(tuple, RelationGetDescr(attrelation), repl_val, repl_null, repl_repl);

	
	simple_heap_update(attrelation, &newtuple->t_self, newtuple);
	CatalogUpdateIndexes(attrelation, newtuple);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), attrtuple->attnum);

	heap_freetuple(newtuple);

	ReleaseSysCache(tuple);

	heap_close(attrelation, RowExclusiveLock);
}


static void ATExecSetStorage(Relation rel, const char *colName, Node *newValue, LOCKMODE lockmode)
{
	char	   *storagemode;
	char		newstorage;
	Relation	attrelation;
	HeapTuple	tuple;
	Form_pg_attribute attrtuple;

	Assert(IsA(newValue, String));
	storagemode = strVal(newValue);

	if (pg_strcasecmp(storagemode, "plain") == 0)
		newstorage = 'p';
	else if (pg_strcasecmp(storagemode, "external") == 0)
		newstorage = 'e';
	else if (pg_strcasecmp(storagemode, "extended") == 0)
		newstorage = 'x';
	else if (pg_strcasecmp(storagemode, "main") == 0)
		newstorage = 'm';
	else {
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid storage type \"%s\"", storagemode)));


		newstorage = 0;			
	}

	attrelation = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	if (attrtuple->attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	if (newstorage == 'p' || TypeIsToastable(attrtuple->atttypid))
		attrtuple->attstorage = newstorage;
	else ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("column data type %s can only have storage PLAIN", format_type_be(attrtuple->atttypid))));




	simple_heap_update(attrelation, &tuple->t_self, tuple);

	
	CatalogUpdateIndexes(attrelation, tuple);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), attrtuple->attnum);


	heap_freetuple(tuple);

	heap_close(attrelation, RowExclusiveLock);
}



static void ATPrepDropColumn(List **wqueue, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd, LOCKMODE lockmode)

{
	if (rel->rd_rel->reloftype && !recursing)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot drop column from typed table")));


	if (rel->rd_rel->relkind == RELKIND_COMPOSITE_TYPE)
		ATTypedTableRecursion(wqueue, rel, cmd, lockmode);

	if (recurse)
		cmd->subtype = AT_DropColumnRecurse;
}

static void ATExecDropColumn(List **wqueue, Relation rel, const char *colName, DropBehavior behavior, bool recurse, bool recursing, bool missing_ok, LOCKMODE lockmode)



{
	HeapTuple	tuple;
	Form_pg_attribute targetatt;
	AttrNumber	attnum;
	List	   *children;
	ObjectAddress object;

	
	if (recursing)
		ATSimplePermissions(rel, ATT_TABLE);

	
	tuple = SearchSysCacheAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
	{
		if (!missing_ok)
		{
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


		}
		else {
			ereport(NOTICE, (errmsg("column \"%s\" of relation \"%s\" does not exist, skipping", colName, RelationGetRelationName(rel))));

			return;
		}
	}
	targetatt = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = targetatt->attnum;

	
	if (attnum <= 0 && attnum != ObjectIdAttributeNumber)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot drop system column \"%s\"", colName)));



	
	if (targetatt->attinhcount > 0 && !recursing)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot drop inherited column \"%s\"", colName)));



	ReleaseSysCache(tuple);

	
	children = find_inheritance_children(RelationGetRelid(rel), lockmode);

	if (children)
	{
		Relation	attr_rel;
		ListCell   *child;

		attr_rel = heap_open(AttributeRelationId, RowExclusiveLock);
		foreach(child, children)
		{
			Oid			childrelid = lfirst_oid(child);
			Relation	childrel;
			Form_pg_attribute childatt;

			
			childrel = heap_open(childrelid, NoLock);
			CheckTableNotInUse(childrel, "ALTER TABLE");

			tuple = SearchSysCacheCopyAttName(childrelid, colName);
			if (!HeapTupleIsValid(tuple))		
				elog(ERROR, "cache lookup failed for attribute \"%s\" of relation %u", colName, childrelid);
			childatt = (Form_pg_attribute) GETSTRUCT(tuple);

			if (childatt->attinhcount <= 0)		
				elog(ERROR, "relation %u has non-inherited attribute \"%s\"", childrelid, colName);

			if (recurse)
			{
				
				if (childatt->attinhcount == 1 && !childatt->attislocal)
				{
					
					ATExecDropColumn(wqueue, childrel, colName, behavior, true, true, false, lockmode);

				}
				else {
					
					childatt->attinhcount--;

					simple_heap_update(attr_rel, &tuple->t_self, tuple);

					
					CatalogUpdateIndexes(attr_rel, tuple);

					
					CommandCounterIncrement();
				}
			}
			else {
				
				childatt->attinhcount--;
				childatt->attislocal = true;

				simple_heap_update(attr_rel, &tuple->t_self, tuple);

				
				CatalogUpdateIndexes(attr_rel, tuple);

				
				CommandCounterIncrement();
			}

			heap_freetuple(tuple);

			heap_close(childrel, NoLock);
		}
		heap_close(attr_rel, RowExclusiveLock);
	}

	
	object.classId = RelationRelationId;
	object.objectId = RelationGetRelid(rel);
	object.objectSubId = attnum;

	performDeletion(&object, behavior, 0);

	
	if (attnum == ObjectIdAttributeNumber)
	{
		Relation	class_rel;
		Form_pg_class tuple_class;
		AlteredTableInfo *tab;

		class_rel = heap_open(RelationRelationId, RowExclusiveLock);

		tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(RelationGetRelid(rel)));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation %u", RelationGetRelid(rel));
		tuple_class = (Form_pg_class) GETSTRUCT(tuple);

		tuple_class->relhasoids = false;
		simple_heap_update(class_rel, &tuple->t_self, tuple);

		
		CatalogUpdateIndexes(class_rel, tuple);

		heap_close(class_rel, RowExclusiveLock);

		
		tab = ATGetQueueEntry(wqueue, rel);

		
		tab->rewrite = true;
	}
}


static void ATExecAddIndex(AlteredTableInfo *tab, Relation rel, IndexStmt *stmt, bool is_rebuild, LOCKMODE lockmode)

{
	bool		check_rights;
	bool		skip_build;
	bool		quiet;
	Oid			new_index;

	Assert(IsA(stmt, IndexStmt));
	Assert(!stmt->concurrent);

	
	check_rights = !is_rebuild;
	
	skip_build = tab->rewrite || OidIsValid(stmt->oldNode);
	
	quiet = is_rebuild;

	

	new_index = DefineIndex(stmt, InvalidOid, true, check_rights, skip_build, quiet);





	
	if (OidIsValid(stmt->oldNode))
	{
		Relation	irel = index_open(new_index, NoLock);

		RelationPreserveStorage(irel->rd_node, true);
		index_close(irel, NoLock);
	}
}


static void ATExecAddIndexConstraint(AlteredTableInfo *tab, Relation rel, IndexStmt *stmt, LOCKMODE lockmode)

{
	Oid			index_oid = stmt->indexOid;
	Relation	indexRel;
	char	   *indexName;
	IndexInfo  *indexInfo;
	char	   *constraintName;
	char		constraintType;

	Assert(IsA(stmt, IndexStmt));
	Assert(OidIsValid(index_oid));
	Assert(stmt->isconstraint);

	indexRel = index_open(index_oid, AccessShareLock);

	indexName = pstrdup(RelationGetRelationName(indexRel));

	indexInfo = BuildIndexInfo(indexRel);

	
	if (!indexInfo->ii_Unique)
		elog(ERROR, "index \"%s\" is not unique", indexName);

	
	constraintName = stmt->idxname;
	if (constraintName == NULL)
		constraintName = indexName;
	else if (strcmp(constraintName, indexName) != 0)
	{
		ereport(NOTICE, (errmsg("ALTER TABLE / ADD CONSTRAINT USING INDEX will rename index \"%s\" to \"%s\"", indexName, constraintName)));

		RenameRelationInternal(index_oid, constraintName, false);
	}

	
	if (stmt->primary)
		index_check_primary_key(rel, indexInfo, true);

	
	if (stmt->primary)
		constraintType = CONSTRAINT_PRIMARY;
	else constraintType = CONSTRAINT_UNIQUE;

	
	index_constraint_create(rel, index_oid, indexInfo, constraintName, constraintType, stmt->deferrable, stmt->initdeferred, stmt->primary, true, true, allowSystemTableMods, false);











	index_close(indexRel, NoLock);
}


static void ATExecAddConstraint(List **wqueue, AlteredTableInfo *tab, Relation rel, Constraint *newConstraint, bool recurse, bool is_readd, LOCKMODE lockmode)


{
	Assert(IsA(newConstraint, Constraint));

	
	switch (newConstraint->contype)
	{
		case CONSTR_CHECK:
			ATAddCheckConstraint(wqueue, tab, rel, newConstraint, recurse, false, is_readd, lockmode);

			break;

		case CONSTR_FOREIGN:

			
			if (newConstraint->conname)
			{
				if (ConstraintNameIsUsed(CONSTRAINT_RELATION, RelationGetRelid(rel), RelationGetNamespace(rel), newConstraint->conname))


					ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("constraint \"%s\" for relation \"%s\" already exists", newConstraint->conname, RelationGetRelationName(rel))));



			}
			else newConstraint->conname = ChooseConstraintName(RelationGetRelationName(rel), strVal(linitial(newConstraint->fk_attrs)), "fkey", RelationGetNamespace(rel), NIL);






			ATAddForeignKeyConstraint(tab, rel, newConstraint, lockmode);
			break;

		default:
			elog(ERROR, "unrecognized constraint type: %d", (int) newConstraint->contype);
	}
}


static void ATAddCheckConstraint(List **wqueue, AlteredTableInfo *tab, Relation rel, Constraint *constr, bool recurse, bool recursing, bool is_readd, LOCKMODE lockmode)


{
	List	   *newcons;
	ListCell   *lcon;
	List	   *children;
	ListCell   *child;

	
	if (recursing)
		ATSimplePermissions(rel, ATT_TABLE);

	
	newcons = AddRelationNewConstraints(rel, NIL, list_make1(copyObject(constr)), recursing, !recursing, is_readd);




	
	foreach(lcon, newcons)
	{
		CookedConstraint *ccon = (CookedConstraint *) lfirst(lcon);

		if (!ccon->skip_validation)
		{
			NewConstraint *newcon;

			newcon = (NewConstraint *) palloc0(sizeof(NewConstraint));
			newcon->name = ccon->name;
			newcon->contype = ccon->contype;
			
			newcon->qual = (Node *) make_ands_implicit((Expr *) ccon->expr);

			tab->constraints = lappend(tab->constraints, newcon);
		}

		
		if (constr->conname == NULL)
			constr->conname = ccon->name;
	}

	
	Assert(constr->conname != NULL);

	
	CommandCounterIncrement();

	
	if (newcons == NIL)
		return;

	
	if (constr->is_no_inherit || is_readd)
		return;

	
	children = find_inheritance_children(RelationGetRelid(rel), lockmode);

	
	if (!recurse && children != NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("constraint must be added to child tables too")));


	foreach(child, children)
	{
		Oid			childrelid = lfirst_oid(child);
		Relation	childrel;
		AlteredTableInfo *childtab;

		
		childrel = heap_open(childrelid, NoLock);
		CheckTableNotInUse(childrel, "ALTER TABLE");

		
		childtab = ATGetQueueEntry(wqueue, childrel);

		
		ATAddCheckConstraint(wqueue, childtab, childrel, constr, recurse, true, is_readd, lockmode);

		heap_close(childrel, NoLock);
	}
}


static void ATAddForeignKeyConstraint(AlteredTableInfo *tab, Relation rel, Constraint *fkconstraint, LOCKMODE lockmode)

{
	Relation	pkrel;
	int16		pkattnum[INDEX_MAX_KEYS];
	int16		fkattnum[INDEX_MAX_KEYS];
	Oid			pktypoid[INDEX_MAX_KEYS];
	Oid			fktypoid[INDEX_MAX_KEYS];
	Oid			opclasses[INDEX_MAX_KEYS];
	Oid			pfeqoperators[INDEX_MAX_KEYS];
	Oid			ppeqoperators[INDEX_MAX_KEYS];
	Oid			ffeqoperators[INDEX_MAX_KEYS];
	int			i;
	int			numfks, numpks;
	Oid			indexOid;
	Oid			constrOid;
	bool		old_check_ok;
	ListCell   *old_pfeqop_item = list_head(fkconstraint->old_conpfeqop);

	
	pkrel = heap_openrv(fkconstraint->pktable, AccessExclusiveLock);

	
	if (pkrel->rd_rel->relkind != RELKIND_RELATION)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("referenced relation \"%s\" is not a table", RelationGetRelationName(pkrel))));



	if (!allowSystemTableMods && IsSystemRelation(pkrel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(pkrel))));



	
	switch (rel->rd_rel->relpersistence)
	{
		case RELPERSISTENCE_PERMANENT:
			if (pkrel->rd_rel->relpersistence != RELPERSISTENCE_PERMANENT)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("constraints on permanent tables may reference only permanent tables")));

			break;
		case RELPERSISTENCE_UNLOGGED:
			if (pkrel->rd_rel->relpersistence != RELPERSISTENCE_PERMANENT && pkrel->rd_rel->relpersistence != RELPERSISTENCE_UNLOGGED)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("constraints on unlogged tables may reference only permanent or unlogged tables")));

			break;
		case RELPERSISTENCE_TEMP:
			if (pkrel->rd_rel->relpersistence != RELPERSISTENCE_TEMP)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("constraints on temporary tables may reference only temporary tables")));

			if (!pkrel->rd_islocaltemp || !rel->rd_islocaltemp)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("constraints on temporary tables must involve temporary tables of this session")));

			break;
	}

	
	MemSet(pkattnum, 0, sizeof(pkattnum));
	MemSet(fkattnum, 0, sizeof(fkattnum));
	MemSet(pktypoid, 0, sizeof(pktypoid));
	MemSet(fktypoid, 0, sizeof(fktypoid));
	MemSet(opclasses, 0, sizeof(opclasses));
	MemSet(pfeqoperators, 0, sizeof(pfeqoperators));
	MemSet(ppeqoperators, 0, sizeof(ppeqoperators));
	MemSet(ffeqoperators, 0, sizeof(ffeqoperators));

	numfks = transformColumnNameList(RelationGetRelid(rel), fkconstraint->fk_attrs, fkattnum, fktypoid);


	
	if (fkconstraint->pk_attrs == NIL)
	{
		numpks = transformFkeyGetPrimaryKey(pkrel, &indexOid, &fkconstraint->pk_attrs, pkattnum, pktypoid, opclasses);


	}
	else {
		numpks = transformColumnNameList(RelationGetRelid(pkrel), fkconstraint->pk_attrs, pkattnum, pktypoid);

		
		indexOid = transformFkeyCheckAttrs(pkrel, numpks, pkattnum, opclasses);
	}

	
	checkFkeyPermissions(pkrel, pkattnum, numpks);
	checkFkeyPermissions(rel, fkattnum, numfks);

	
	if (numfks != numpks)
		ereport(ERROR, (errcode(ERRCODE_INVALID_FOREIGN_KEY), errmsg("number of referencing and referenced columns for foreign key disagree")));


	
	old_check_ok = (fkconstraint->old_conpfeqop != NIL);
	Assert(!old_check_ok || numfks == list_length(fkconstraint->old_conpfeqop));

	for (i = 0; i < numpks; i++)
	{
		Oid			pktype = pktypoid[i];
		Oid			fktype = fktypoid[i];
		Oid			fktyped;
		HeapTuple	cla_ht;
		Form_pg_opclass cla_tup;
		Oid			amid;
		Oid			opfamily;
		Oid			opcintype;
		Oid			pfeqop;
		Oid			ppeqop;
		Oid			ffeqop;
		int16		eqstrategy;
		Oid			pfeqop_right;

		
		cla_ht = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclasses[i]));
		if (!HeapTupleIsValid(cla_ht))
			elog(ERROR, "cache lookup failed for opclass %u", opclasses[i]);
		cla_tup = (Form_pg_opclass) GETSTRUCT(cla_ht);
		amid = cla_tup->opcmethod;
		opfamily = cla_tup->opcfamily;
		opcintype = cla_tup->opcintype;
		ReleaseSysCache(cla_ht);

		
		if (amid != BTREE_AM_OID)
			elog(ERROR, "only b-tree indexes are supported for foreign keys");
		eqstrategy = BTEqualStrategyNumber;

		
		ppeqop = get_opfamily_member(opfamily, opcintype, opcintype, eqstrategy);

		if (!OidIsValid(ppeqop))
			elog(ERROR, "missing operator %d(%u,%u) in opfamily %u", eqstrategy, opcintype, opcintype, opfamily);

		
		fktyped = getBaseType(fktype);

		pfeqop = get_opfamily_member(opfamily, opcintype, fktyped, eqstrategy);
		if (OidIsValid(pfeqop))
		{
			pfeqop_right = fktyped;
			ffeqop = get_opfamily_member(opfamily, fktyped, fktyped, eqstrategy);
		}
		else {
			
			pfeqop_right = InvalidOid;
			ffeqop = InvalidOid;
		}

		if (!(OidIsValid(pfeqop) && OidIsValid(ffeqop)))
		{
			
			Oid			input_typeids[2];
			Oid			target_typeids[2];

			input_typeids[0] = pktype;
			input_typeids[1] = fktype;
			target_typeids[0] = opcintype;
			target_typeids[1] = opcintype;
			if (can_coerce_type(2, input_typeids, target_typeids, COERCION_IMPLICIT))
			{
				pfeqop = ffeqop = ppeqop;
				pfeqop_right = opcintype;
			}
		}

		if (!(OidIsValid(pfeqop) && OidIsValid(ffeqop)))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("foreign key constraint \"%s\" " "cannot be implemented", fkconstraint->conname), errdetail("Key columns \"%s\" and \"%s\" " "are of incompatible types: %s and %s.", strVal(list_nth(fkconstraint->fk_attrs, i)), strVal(list_nth(fkconstraint->pk_attrs, i)), format_type_be(fktype), format_type_be(pktype))));










		if (old_check_ok)
		{
			
			old_check_ok = (pfeqop == lfirst_oid(old_pfeqop_item));
			old_pfeqop_item = lnext(old_pfeqop_item);
		}
		if (old_check_ok)
		{
			Oid			old_fktype;
			Oid			new_fktype;
			CoercionPathType old_pathtype;
			CoercionPathType new_pathtype;
			Oid			old_castfunc;
			Oid			new_castfunc;

			
			old_fktype = tab->oldDesc->attrs[fkattnum[i] - 1]->atttypid;
			new_fktype = fktype;
			old_pathtype = findFkeyCast(pfeqop_right, old_fktype, &old_castfunc);
			new_pathtype = findFkeyCast(pfeqop_right, new_fktype, &new_castfunc);

			
			old_check_ok = (new_pathtype == old_pathtype && new_castfunc == old_castfunc && (!IsPolymorphicType(pfeqop_right) || new_fktype == old_fktype));



		}

		pfeqoperators[i] = pfeqop;
		ppeqoperators[i] = ppeqop;
		ffeqoperators[i] = ffeqop;
	}

	
	constrOid = CreateConstraintEntry(fkconstraint->conname, RelationGetNamespace(rel), CONSTRAINT_FOREIGN, fkconstraint->deferrable, fkconstraint->initdeferred, fkconstraint->initially_valid, RelationGetRelid(rel), fkattnum, numfks, InvalidOid, indexOid, RelationGetRelid(pkrel), pkattnum, pfeqoperators, ppeqoperators, ffeqoperators, numpks, fkconstraint->fk_upd_action, fkconstraint->fk_del_action, fkconstraint->fk_matchtype, NULL, NULL, NULL, NULL, true, 0, true, false);



























	
	createForeignKeyTriggers(rel, fkconstraint, constrOid, indexOid);

	
	if (!old_check_ok && !fkconstraint->skip_validation)
	{
		NewConstraint *newcon;

		newcon = (NewConstraint *) palloc0(sizeof(NewConstraint));
		newcon->name = fkconstraint->conname;
		newcon->contype = CONSTR_FOREIGN;
		newcon->refrelid = RelationGetRelid(pkrel);
		newcon->refindid = indexOid;
		newcon->conid = constrOid;
		newcon->qual = (Node *) fkconstraint;

		tab->constraints = lappend(tab->constraints, newcon);
	}

	
	heap_close(pkrel, NoLock);
}


static void ATExecAlterConstraint(Relation rel, AlterTableCmd *cmd, bool recurse, bool recursing, LOCKMODE lockmode)

{
	Relation	conrel;
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	contuple;
	Form_pg_constraint currcon = NULL;
	Constraint	*cmdcon = NULL;
	bool		found = false;

	Assert(IsA(cmd->def, Constraint));
	cmdcon = (Constraint *) cmd->def;

	conrel = heap_open(ConstraintRelationId, RowExclusiveLock);

	
	ScanKeyInit(&key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(conrel, ConstraintRelidIndexId, true, NULL, 1, &key);

	while (HeapTupleIsValid(contuple = systable_getnext(scan)))
	{
		currcon = (Form_pg_constraint) GETSTRUCT(contuple);
		if (strcmp(NameStr(currcon->conname), cmdcon->conname) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" of relation \"%s\" does not exist", cmdcon->conname, RelationGetRelationName(rel))));



	if (currcon->contype != CONSTRAINT_FOREIGN)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("constraint \"%s\" of relation \"%s\" is not a foreign key constraint", cmdcon->conname, RelationGetRelationName(rel))));



	if (currcon->condeferrable != cmdcon->deferrable || currcon->condeferred != cmdcon->initdeferred)
	{
		HeapTuple	copyTuple;
		HeapTuple	tgtuple;
		Form_pg_constraint copy_con;
		Form_pg_trigger copy_tg;
		ScanKeyData tgkey;
		SysScanDesc tgscan;
		Relation	tgrel;

		
		copyTuple = heap_copytuple(contuple);
		copy_con = (Form_pg_constraint) GETSTRUCT(copyTuple);
		copy_con->condeferrable = cmdcon->deferrable;
		copy_con->condeferred = cmdcon->initdeferred;
		simple_heap_update(conrel, &copyTuple->t_self, copyTuple);
		CatalogUpdateIndexes(conrel, copyTuple);

		InvokeObjectPostAlterHook(ConstraintRelationId, HeapTupleGetOid(contuple), 0);

		heap_freetuple(copyTuple);

		
		tgrel = heap_open(TriggerRelationId, RowExclusiveLock);

		ScanKeyInit(&tgkey, Anum_pg_trigger_tgconstraint, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(HeapTupleGetOid(contuple)));



		tgscan = systable_beginscan(tgrel, TriggerConstraintIndexId, true, NULL, 1, &tgkey);

		while (HeapTupleIsValid(tgtuple = systable_getnext(tgscan)))
		{
			copyTuple = heap_copytuple(tgtuple);
			copy_tg = (Form_pg_trigger) GETSTRUCT(copyTuple);
			copy_tg->tgdeferrable = cmdcon->deferrable;
			copy_tg->tginitdeferred = cmdcon->initdeferred;
			simple_heap_update(tgrel, &copyTuple->t_self, copyTuple);
			CatalogUpdateIndexes(tgrel, copyTuple);

			InvokeObjectPostAlterHook(TriggerRelationId, HeapTupleGetOid(tgtuple), 0);

			heap_freetuple(copyTuple);
		}

		systable_endscan(tgscan);

		heap_close(tgrel, RowExclusiveLock);

		
		CacheInvalidateRelcache(rel);
	}

	systable_endscan(scan);

	heap_close(conrel, RowExclusiveLock);
}


static void ATExecValidateConstraint(Relation rel, char *constrName, bool recurse, bool recursing, LOCKMODE lockmode)

{
	Relation	conrel;
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	tuple;
	Form_pg_constraint con = NULL;
	bool		found = false;

	conrel = heap_open(ConstraintRelationId, RowExclusiveLock);

	
	ScanKeyInit(&key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(conrel, ConstraintRelidIndexId, true, NULL, 1, &key);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		con = (Form_pg_constraint) GETSTRUCT(tuple);
		if (strcmp(NameStr(con->conname), constrName) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" of relation \"%s\" does not exist", constrName, RelationGetRelationName(rel))));



	if (con->contype != CONSTRAINT_FOREIGN && con->contype != CONSTRAINT_CHECK)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("constraint \"%s\" of relation \"%s\" is not a foreign key or check constraint", constrName, RelationGetRelationName(rel))));



	if (!con->convalidated)
	{
		HeapTuple	copyTuple;
		Form_pg_constraint copy_con;

		if (con->contype == CONSTRAINT_FOREIGN)
		{
			Oid			conid = HeapTupleGetOid(tuple);
			Relation	refrel;

			
			refrel = heap_open(con->confrelid, RowShareLock);

			validateForeignKeyConstraint(constrName, rel, refrel, con->conindid, conid);

			heap_close(refrel, NoLock);

			
		}
		else if (con->contype == CONSTRAINT_CHECK)
		{
			List	   *children = NIL;
			ListCell   *child;

			
			if (!recursing)
				children = find_all_inheritors(RelationGetRelid(rel), lockmode, NULL);

			
			foreach(child, children)
			{
				Oid			childoid = lfirst_oid(child);
				Relation	childrel;

				if (childoid == RelationGetRelid(rel))
					continue;

				
				if (!recurse)
					ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("constraint must be validated on child tables too")));


				
				childrel = heap_open(childoid, NoLock);

				ATExecValidateConstraint(childrel, constrName, false, true, lockmode);
				heap_close(childrel, NoLock);
			}

			validateCheckConstraint(rel, tuple);

			
			CacheInvalidateRelcache(rel);
		}

		
		copyTuple = heap_copytuple(tuple);
		copy_con = (Form_pg_constraint) GETSTRUCT(copyTuple);
		copy_con->convalidated = true;
		simple_heap_update(conrel, &copyTuple->t_self, copyTuple);
		CatalogUpdateIndexes(conrel, copyTuple);

		InvokeObjectPostAlterHook(ConstraintRelationId, HeapTupleGetOid(tuple), 0);

		heap_freetuple(copyTuple);
	}

	systable_endscan(scan);

	heap_close(conrel, RowExclusiveLock);
}



static int transformColumnNameList(Oid relId, List *colList, int16 *attnums, Oid *atttypids)

{
	ListCell   *l;
	int			attnum;

	attnum = 0;
	foreach(l, colList)
	{
		char	   *attname = strVal(lfirst(l));
		HeapTuple	atttuple;

		atttuple = SearchSysCacheAttName(relId, attname);
		if (!HeapTupleIsValid(atttuple))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" referenced in foreign key constraint does not exist", attname)));


		if (attnum >= INDEX_MAX_KEYS)
			ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("cannot have more than %d keys in a foreign key", INDEX_MAX_KEYS)));


		attnums[attnum] = ((Form_pg_attribute) GETSTRUCT(atttuple))->attnum;
		atttypids[attnum] = ((Form_pg_attribute) GETSTRUCT(atttuple))->atttypid;
		ReleaseSysCache(atttuple);
		attnum++;
	}

	return attnum;
}


static int transformFkeyGetPrimaryKey(Relation pkrel, Oid *indexOid, List **attnamelist, int16 *attnums, Oid *atttypids, Oid *opclasses)



{
	List	   *indexoidlist;
	ListCell   *indexoidscan;
	HeapTuple	indexTuple = NULL;
	Form_pg_index indexStruct = NULL;
	Datum		indclassDatum;
	bool		isnull;
	oidvector  *indclass;
	int			i;

	
	*indexOid = InvalidOid;

	indexoidlist = RelationGetIndexList(pkrel);

	foreach(indexoidscan, indexoidlist)
	{
		Oid			indexoid = lfirst_oid(indexoidscan);

		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexoid));
		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		indexStruct = (Form_pg_index) GETSTRUCT(indexTuple);
		if (indexStruct->indisprimary && IndexIsValid(indexStruct))
		{
			
			if (!indexStruct->indimmediate)
				ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("cannot use a deferrable primary key for referenced table \"%s\"", RelationGetRelationName(pkrel))));



			*indexOid = indexoid;
			break;
		}
		ReleaseSysCache(indexTuple);
	}

	list_free(indexoidlist);

	
	if (!OidIsValid(*indexOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("there is no primary key for referenced table \"%s\"", RelationGetRelationName(pkrel))));



	
	indclassDatum = SysCacheGetAttr(INDEXRELID, indexTuple, Anum_pg_index_indclass, &isnull);
	Assert(!isnull);
	indclass = (oidvector *) DatumGetPointer(indclassDatum);

	
	*attnamelist = NIL;
	for (i = 0; i < indexStruct->indnatts; i++)
	{
		int			pkattno = indexStruct->indkey.values[i];

		attnums[i] = pkattno;
		atttypids[i] = attnumTypeId(pkrel, pkattno);
		opclasses[i] = indclass->values[i];
		*attnamelist = lappend(*attnamelist, makeString(pstrdup(NameStr(*attnumAttName(pkrel, pkattno)))));
	}

	ReleaseSysCache(indexTuple);

	return i;
}


static Oid transformFkeyCheckAttrs(Relation pkrel, int numattrs, int16 *attnums, Oid *opclasses)


{
	Oid			indexoid = InvalidOid;
	bool		found = false;
	bool		found_deferrable = false;
	List	   *indexoidlist;
	ListCell   *indexoidscan;

	
	indexoidlist = RelationGetIndexList(pkrel);

	foreach(indexoidscan, indexoidlist)
	{
		HeapTuple	indexTuple;
		Form_pg_index indexStruct;
		int			i, j;

		indexoid = lfirst_oid(indexoidscan);
		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexoid));
		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		indexStruct = (Form_pg_index) GETSTRUCT(indexTuple);

		
		if (indexStruct->indnatts == numattrs && indexStruct->indisunique && IndexIsValid(indexStruct) && heap_attisnull(indexTuple, Anum_pg_index_indpred) && heap_attisnull(indexTuple, Anum_pg_index_indexprs))



		{
			
			Datum		indclassDatum;
			bool		isnull;
			oidvector  *indclass;

			indclassDatum = SysCacheGetAttr(INDEXRELID, indexTuple, Anum_pg_index_indclass, &isnull);
			Assert(!isnull);
			indclass = (oidvector *) DatumGetPointer(indclassDatum);

			
			for (i = 0; i < numattrs; i++)
			{
				found = false;
				for (j = 0; j < numattrs; j++)
				{
					if (attnums[i] == indexStruct->indkey.values[j])
					{
						found = true;
						break;
					}
				}
				if (!found)
					break;
			}
			if (found)
			{
				for (i = 0; i < numattrs; i++)
				{
					found = false;
					for (j = 0; j < numattrs; j++)
					{
						if (attnums[j] == indexStruct->indkey.values[i])
						{
							opclasses[j] = indclass->values[i];
							found = true;
							break;
						}
					}
					if (!found)
						break;
				}
			}

			
			if (found && !indexStruct->indimmediate)
			{
				
				found_deferrable = true;
				found = false;
			}
		}
		ReleaseSysCache(indexTuple);
		if (found)
			break;
	}

	if (!found)
	{
		if (found_deferrable)
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("cannot use a deferrable unique constraint for referenced table \"%s\"", RelationGetRelationName(pkrel))));


		else ereport(ERROR, (errcode(ERRCODE_INVALID_FOREIGN_KEY), errmsg("there is no unique constraint matching given keys for referenced table \"%s\"", RelationGetRelationName(pkrel))));



	}

	list_free(indexoidlist);

	return indexoid;
}


static CoercionPathType findFkeyCast(Oid targetTypeId, Oid sourceTypeId, Oid *funcid)
{
	CoercionPathType ret;

	if (targetTypeId == sourceTypeId)
	{
		ret = COERCION_PATH_RELABELTYPE;
		*funcid = InvalidOid;
	}
	else {
		ret = find_coercion_pathway(targetTypeId, sourceTypeId, COERCION_IMPLICIT, funcid);
		if (ret == COERCION_PATH_NONE)
			
			elog(ERROR, "could not find cast from %u to %u", sourceTypeId, targetTypeId);
	}

	return ret;
}


static void checkFkeyPermissions(Relation rel, int16 *attnums, int natts)
{
	Oid			roleid = GetUserId();
	AclResult	aclresult;
	int			i;

	
	aclresult = pg_class_aclcheck(RelationGetRelid(rel), roleid, ACL_REFERENCES);
	if (aclresult == ACLCHECK_OK)
		return;
	
	for (i = 0; i < natts; i++)
	{
		aclresult = pg_attribute_aclcheck(RelationGetRelid(rel), attnums[i], roleid, ACL_REFERENCES);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(rel));
	}
}


static void validateCheckConstraint(Relation rel, HeapTuple constrtup)
{
	EState	   *estate;
	Datum		val;
	char	   *conbin;
	Expr	   *origexpr;
	List	   *exprstate;
	TupleDesc	tupdesc;
	HeapScanDesc scan;
	HeapTuple	tuple;
	ExprContext *econtext;
	MemoryContext oldcxt;
	TupleTableSlot *slot;
	Form_pg_constraint constrForm;
	bool		isnull;
	Snapshot	snapshot;

	constrForm = (Form_pg_constraint) GETSTRUCT(constrtup);

	estate = CreateExecutorState();

	
	val = SysCacheGetAttr(CONSTROID, constrtup, Anum_pg_constraint_conbin, &isnull);
	if (isnull)
		elog(ERROR, "null conbin for constraint %u", HeapTupleGetOid(constrtup));
	conbin = TextDatumGetCString(val);
	origexpr = (Expr *) stringToNode(conbin);
	exprstate = (List *)
		ExecPrepareExpr((Expr *) make_ands_implicit(origexpr), estate);

	econtext = GetPerTupleExprContext(estate);
	tupdesc = RelationGetDescr(rel);
	slot = MakeSingleTupleTableSlot(tupdesc);
	econtext->ecxt_scantuple = slot;

	snapshot = RegisterSnapshot(GetLatestSnapshot());
	scan = heap_beginscan(rel, snapshot, 0, NULL);

	
	oldcxt = MemoryContextSwitchTo(GetPerTupleMemoryContext(estate));

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		ExecStoreTuple(tuple, slot, InvalidBuffer, false);

		if (!ExecQual(exprstate, econtext, true))
			ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("check constraint \"%s\" is violated by some row", NameStr(constrForm->conname)), errtableconstraint(rel, NameStr(constrForm->conname))));




		ResetExprContext(econtext);
	}

	MemoryContextSwitchTo(oldcxt);
	heap_endscan(scan);
	UnregisterSnapshot(snapshot);
	ExecDropSingleTupleTableSlot(slot);
	FreeExecutorState(estate);
}


static void validateForeignKeyConstraint(char *conname, Relation rel, Relation pkrel, Oid pkindOid, Oid constraintOid)




{
	HeapScanDesc scan;
	HeapTuple	tuple;
	Trigger		trig;
	Snapshot	snapshot;

	ereport(DEBUG1, (errmsg("validating foreign key constraint \"%s\"", conname)));

	
	MemSet(&trig, 0, sizeof(trig));
	trig.tgoid = InvalidOid;
	trig.tgname = conname;
	trig.tgenabled = TRIGGER_FIRES_ON_ORIGIN;
	trig.tgisinternal = TRUE;
	trig.tgconstrrelid = RelationGetRelid(pkrel);
	trig.tgconstrindid = pkindOid;
	trig.tgconstraint = constraintOid;
	trig.tgdeferrable = FALSE;
	trig.tginitdeferred = FALSE;
	

	
	if (RI_Initial_Check(&trig, rel, pkrel))
		return;

	
	snapshot = RegisterSnapshot(GetLatestSnapshot());
	scan = heap_beginscan(rel, snapshot, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		FunctionCallInfoData fcinfo;
		TriggerData trigdata;

		
		MemSet(&fcinfo, 0, sizeof(fcinfo));

		
		trigdata.type = T_TriggerData;
		trigdata.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_ROW;
		trigdata.tg_relation = rel;
		trigdata.tg_trigtuple = tuple;
		trigdata.tg_newtuple = NULL;
		trigdata.tg_trigger = &trig;
		trigdata.tg_trigtuplebuf = scan->rs_cbuf;
		trigdata.tg_newtuplebuf = InvalidBuffer;

		fcinfo.context = (Node *) &trigdata;

		RI_FKey_check_ins(&fcinfo);
	}

	heap_endscan(scan);
	UnregisterSnapshot(snapshot);
}

static void CreateFKCheckTrigger(RangeVar *myRel, Constraint *fkconstraint, Oid constraintOid, Oid indexOid, bool on_insert)

{
	CreateTrigStmt *fk_trigger;

	
	fk_trigger = makeNode(CreateTrigStmt);
	fk_trigger->trigname = "RI_ConstraintTrigger_c";
	fk_trigger->relation = myRel;
	fk_trigger->row = true;
	fk_trigger->timing = TRIGGER_TYPE_AFTER;

	
	if (on_insert)
	{
		fk_trigger->funcname = SystemFuncName("RI_FKey_check_ins");
		fk_trigger->events = TRIGGER_TYPE_INSERT;
	}
	else {
		fk_trigger->funcname = SystemFuncName("RI_FKey_check_upd");
		fk_trigger->events = TRIGGER_TYPE_UPDATE;
	}

	fk_trigger->columns = NIL;
	fk_trigger->whenClause = NULL;
	fk_trigger->isconstraint = true;
	fk_trigger->deferrable = fkconstraint->deferrable;
	fk_trigger->initdeferred = fkconstraint->initdeferred;
	fk_trigger->constrrel = fkconstraint->pktable;
	fk_trigger->args = NIL;

	(void) CreateTrigger(fk_trigger, NULL, constraintOid, indexOid, true);

	
	CommandCounterIncrement();
}


static void createForeignKeyTriggers(Relation rel, Constraint *fkconstraint, Oid constraintOid, Oid indexOid)

{
	RangeVar   *myRel;
	CreateTrigStmt *fk_trigger;

	
	myRel = makeRangeVar(get_namespace_name(RelationGetNamespace(rel)), pstrdup(RelationGetRelationName(rel)), -1);


	
	CommandCounterIncrement();

	
	fk_trigger = makeNode(CreateTrigStmt);
	fk_trigger->trigname = "RI_ConstraintTrigger_a";
	fk_trigger->relation = fkconstraint->pktable;
	fk_trigger->row = true;
	fk_trigger->timing = TRIGGER_TYPE_AFTER;
	fk_trigger->events = TRIGGER_TYPE_DELETE;
	fk_trigger->columns = NIL;
	fk_trigger->whenClause = NULL;
	fk_trigger->isconstraint = true;
	fk_trigger->constrrel = myRel;
	switch (fkconstraint->fk_del_action)
	{
		case FKCONSTR_ACTION_NOACTION:
			fk_trigger->deferrable = fkconstraint->deferrable;
			fk_trigger->initdeferred = fkconstraint->initdeferred;
			fk_trigger->funcname = SystemFuncName("RI_FKey_noaction_del");
			break;
		case FKCONSTR_ACTION_RESTRICT:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_restrict_del");
			break;
		case FKCONSTR_ACTION_CASCADE:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_cascade_del");
			break;
		case FKCONSTR_ACTION_SETNULL:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_setnull_del");
			break;
		case FKCONSTR_ACTION_SETDEFAULT:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_setdefault_del");
			break;
		default:
			elog(ERROR, "unrecognized FK action type: %d", (int) fkconstraint->fk_del_action);
			break;
	}
	fk_trigger->args = NIL;

	(void) CreateTrigger(fk_trigger, NULL, constraintOid, indexOid, true);

	
	CommandCounterIncrement();

	
	fk_trigger = makeNode(CreateTrigStmt);
	fk_trigger->trigname = "RI_ConstraintTrigger_a";
	fk_trigger->relation = fkconstraint->pktable;
	fk_trigger->row = true;
	fk_trigger->timing = TRIGGER_TYPE_AFTER;
	fk_trigger->events = TRIGGER_TYPE_UPDATE;
	fk_trigger->columns = NIL;
	fk_trigger->whenClause = NULL;
	fk_trigger->isconstraint = true;
	fk_trigger->constrrel = myRel;
	switch (fkconstraint->fk_upd_action)
	{
		case FKCONSTR_ACTION_NOACTION:
			fk_trigger->deferrable = fkconstraint->deferrable;
			fk_trigger->initdeferred = fkconstraint->initdeferred;
			fk_trigger->funcname = SystemFuncName("RI_FKey_noaction_upd");
			break;
		case FKCONSTR_ACTION_RESTRICT:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_restrict_upd");
			break;
		case FKCONSTR_ACTION_CASCADE:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_cascade_upd");
			break;
		case FKCONSTR_ACTION_SETNULL:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_setnull_upd");
			break;
		case FKCONSTR_ACTION_SETDEFAULT:
			fk_trigger->deferrable = false;
			fk_trigger->initdeferred = false;
			fk_trigger->funcname = SystemFuncName("RI_FKey_setdefault_upd");
			break;
		default:
			elog(ERROR, "unrecognized FK action type: %d", (int) fkconstraint->fk_upd_action);
			break;
	}
	fk_trigger->args = NIL;

	(void) CreateTrigger(fk_trigger, NULL, constraintOid, indexOid, true);

	
	CommandCounterIncrement();

	
	CreateFKCheckTrigger(myRel, fkconstraint, constraintOid, indexOid, true);
	CreateFKCheckTrigger(myRel, fkconstraint, constraintOid, indexOid, false);
}


static void ATExecDropConstraint(Relation rel, const char *constrName, DropBehavior behavior, bool recurse, bool recursing, bool missing_ok, LOCKMODE lockmode)



{
	List	   *children;
	ListCell   *child;
	Relation	conrel;
	Form_pg_constraint con;
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	tuple;
	bool		found = false;
	bool		is_no_inherit_constraint = false;

	
	if (recursing)
		ATSimplePermissions(rel, ATT_TABLE);

	conrel = heap_open(ConstraintRelationId, RowExclusiveLock);

	
	ScanKeyInit(&key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(conrel, ConstraintRelidIndexId, true, NULL, 1, &key);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		ObjectAddress conobj;

		con = (Form_pg_constraint) GETSTRUCT(tuple);

		if (strcmp(NameStr(con->conname), constrName) != 0)
			continue;

		
		if (con->coninhcount > 0 && !recursing)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot drop inherited constraint \"%s\" of relation \"%s\"", constrName, RelationGetRelationName(rel))));



		is_no_inherit_constraint = con->connoinherit;

		
		conobj.classId = ConstraintRelationId;
		conobj.objectId = HeapTupleGetOid(tuple);
		conobj.objectSubId = 0;

		performDeletion(&conobj, behavior, 0);

		found = true;

		
		break;
	}

	systable_endscan(scan);

	if (!found)
	{
		if (!missing_ok)
		{
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" of relation \"%s\" does not exist", constrName, RelationGetRelationName(rel))));


		}
		else {
			ereport(NOTICE, (errmsg("constraint \"%s\" of relation \"%s\" does not exist, skipping", constrName, RelationGetRelationName(rel))));

			heap_close(conrel, RowExclusiveLock);
			return;
		}
	}

	
	if (!is_no_inherit_constraint)
		children = find_inheritance_children(RelationGetRelid(rel), lockmode);
	else children = NIL;

	foreach(child, children)
	{
		Oid			childrelid = lfirst_oid(child);
		Relation	childrel;
		HeapTuple	copy_tuple;

		
		childrel = heap_open(childrelid, NoLock);
		CheckTableNotInUse(childrel, "ALTER TABLE");

		ScanKeyInit(&key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(childrelid));


		scan = systable_beginscan(conrel, ConstraintRelidIndexId, true, NULL, 1, &key);

		
		while (HeapTupleIsValid(tuple = systable_getnext(scan)))
		{
			con = (Form_pg_constraint) GETSTRUCT(tuple);

			
			if (con->contype != CONSTRAINT_CHECK)
				continue;

			if (strcmp(NameStr(con->conname), constrName) == 0)
				break;
		}

		if (!HeapTupleIsValid(tuple))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" of relation \"%s\" does not exist", constrName, RelationGetRelationName(childrel))));




		copy_tuple = heap_copytuple(tuple);

		systable_endscan(scan);

		con = (Form_pg_constraint) GETSTRUCT(copy_tuple);

		if (con->coninhcount <= 0)		
			elog(ERROR, "relation %u has non-inherited constraint \"%s\"", childrelid, constrName);

		if (recurse)
		{
			
			if (con->coninhcount == 1 && !con->conislocal)
			{
				
				ATExecDropConstraint(childrel, constrName, behavior, true, true, false, lockmode);

			}
			else {
				
				con->coninhcount--;
				simple_heap_update(conrel, &copy_tuple->t_self, copy_tuple);
				CatalogUpdateIndexes(conrel, copy_tuple);

				
				CommandCounterIncrement();
			}
		}
		else {
			
			con->coninhcount--;
			con->conislocal = true;

			simple_heap_update(conrel, &copy_tuple->t_self, copy_tuple);
			CatalogUpdateIndexes(conrel, copy_tuple);

			
			CommandCounterIncrement();
		}

		heap_freetuple(copy_tuple);

		heap_close(childrel, NoLock);
	}

	heap_close(conrel, RowExclusiveLock);
}


static void ATPrepAlterColumnType(List **wqueue, AlteredTableInfo *tab, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd, LOCKMODE lockmode)



{
	char	   *colName = cmd->name;
	ColumnDef  *def = (ColumnDef *) cmd->def;
	TypeName   *typeName = def->typeName;
	Node	   *transform = def->raw_default;
	HeapTuple	tuple;
	Form_pg_attribute attTup;
	AttrNumber	attnum;
	Oid			targettype;
	int32		targettypmod;
	Oid			targetcollid;
	NewColumnValue *newval;
	ParseState *pstate = make_parsestate(NULL);
	AclResult	aclresult;

	if (rel->rd_rel->reloftype && !recursing)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot alter column type of typed table")));


	
	tuple = SearchSysCacheAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	attTup = (Form_pg_attribute) GETSTRUCT(tuple);
	attnum = attTup->attnum;

	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	if (attTup->attinhcount > 0 && !recursing)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot alter inherited column \"%s\"", colName)));



	
	typenameTypeIdAndMod(NULL, typeName, &targettype, &targettypmod);

	aclresult = pg_type_aclcheck(targettype, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, targettype);

	
	targetcollid = GetColumnDefCollation(NULL, def, targettype);

	
	CheckAttributeType(colName, targettype, targetcollid, list_make1_oid(rel->rd_rel->reltype), false);


	if (tab->relkind == RELKIND_RELATION)
	{
		
		if (transform)
		{
			RangeTblEntry *rte;

			
			rte = addRangeTableEntryForRelation(pstate, rel, NULL, false, true);



			addRTEtoQuery(pstate, rte, false, true, true);

			transform = transformExpr(pstate, transform, EXPR_KIND_ALTER_COL_TRANSFORM);

			
			if (expression_returns_set(transform))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("transform expression must not return a set")));

		}
		else {
			transform = (Node *) makeVar(1, attnum, attTup->atttypid, attTup->atttypmod, attTup->attcollation, 0);


		}

		transform = coerce_to_target_type(pstate, transform, exprType(transform), targettype, targettypmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST, -1);




		if (transform == NULL)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("column \"%s\" cannot be cast automatically to type %s", colName, format_type_be(targettype)), errhint("Specify a USING expression to perform the conversion.")));




		
		assign_expr_collations(pstate, transform);

		
		transform = (Node *) expression_planner((Expr *) transform);

		
		newval = (NewColumnValue *) palloc0(sizeof(NewColumnValue));
		newval->attnum = attnum;
		newval->expr = (Expr *) transform;

		tab->newvals = lappend(tab->newvals, newval);
		if (ATColumnChangeRequiresRewrite(transform, attnum))
			tab->rewrite = true;
	}
	else if (transform)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table", RelationGetRelationName(rel))));



	if (tab->relkind == RELKIND_COMPOSITE_TYPE || tab->relkind == RELKIND_FOREIGN_TABLE)
	{
		
		find_composite_type_dependencies(rel->rd_rel->reltype, rel, NULL);
	}

	ReleaseSysCache(tuple);

	
	if (recurse)
		ATSimpleRecursion(wqueue, rel, cmd, recurse, lockmode);
	else if (!recursing && find_inheritance_children(RelationGetRelid(rel), NoLock) != NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("type of inherited column \"%s\" must be changed in child tables too", colName)));



	if (tab->relkind == RELKIND_COMPOSITE_TYPE)
		ATTypedTableRecursion(wqueue, rel, cmd, lockmode);
}


static bool ATColumnChangeRequiresRewrite(Node *expr, AttrNumber varattno)
{
	Assert(expr != NULL);

	for (;;)
	{
		
		if (IsA(expr, Var) &&((Var *) expr)->varattno == varattno)
			return false;
		else if (IsA(expr, RelabelType))
			expr = (Node *) ((RelabelType *) expr)->arg;
		else if (IsA(expr, CoerceToDomain))
		{
			CoerceToDomain *d = (CoerceToDomain *) expr;

			if (GetDomainConstraints(d->resulttype) != NIL)
				return true;
			expr = (Node *) d->arg;
		}
		else return true;
	}
}

static void ATExecAlterColumnType(AlteredTableInfo *tab, Relation rel, AlterTableCmd *cmd, LOCKMODE lockmode)

{
	char	   *colName = cmd->name;
	ColumnDef  *def = (ColumnDef *) cmd->def;
	TypeName   *typeName = def->typeName;
	HeapTuple	heapTup;
	Form_pg_attribute attTup;
	AttrNumber	attnum;
	HeapTuple	typeTuple;
	Form_pg_type tform;
	Oid			targettype;
	int32		targettypmod;
	Oid			targetcollid;
	Node	   *defaultexpr;
	Relation	attrelation;
	Relation	depRel;
	ScanKeyData key[3];
	SysScanDesc scan;
	HeapTuple	depTup;

	attrelation = heap_open(AttributeRelationId, RowExclusiveLock);

	
	heapTup = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(heapTup))		
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	attTup = (Form_pg_attribute) GETSTRUCT(heapTup);
	attnum = attTup->attnum;

	
	if (attTup->atttypid != tab->oldDesc->attrs[attnum - 1]->atttypid || attTup->atttypmod != tab->oldDesc->attrs[attnum - 1]->atttypmod)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter type of column \"%s\" twice", colName)));



	
	typeTuple = typenameType(NULL, typeName, &targettypmod);
	tform = (Form_pg_type) GETSTRUCT(typeTuple);
	targettype = HeapTupleGetOid(typeTuple);
	
	targetcollid = GetColumnDefCollation(NULL, def, targettype);

	
	if (attTup->atthasdef)
	{
		defaultexpr = build_column_default(rel, attnum);
		Assert(defaultexpr);
		defaultexpr = strip_implicit_coercions(defaultexpr);
		defaultexpr = coerce_to_target_type(NULL,		 defaultexpr, exprType(defaultexpr), targettype, targettypmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST, -1);




		if (defaultexpr == NULL)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("default for column \"%s\" cannot be cast automatically to type %s", colName, format_type_be(targettype))));


	}
	else defaultexpr = NULL;

	
	depRel = heap_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	ScanKeyInit(&key[2], Anum_pg_depend_refobjsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum((int32) attnum));



	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 3, key);

	while (HeapTupleIsValid(depTup = systable_getnext(scan)))
	{
		Form_pg_depend foundDep = (Form_pg_depend) GETSTRUCT(depTup);
		ObjectAddress foundObject;

		
		if (foundDep->deptype == DEPENDENCY_PIN)
			elog(ERROR, "cannot alter type of a pinned column");

		foundObject.classId = foundDep->classid;
		foundObject.objectId = foundDep->objid;
		foundObject.objectSubId = foundDep->objsubid;

		switch (getObjectClass(&foundObject))
		{
			case OCLASS_CLASS:
				{
					char		relKind = get_rel_relkind(foundObject.objectId);

					if (relKind == RELKIND_INDEX)
					{
						Assert(foundObject.objectSubId == 0);
						if (!list_member_oid(tab->changedIndexOids, foundObject.objectId))
						{
							tab->changedIndexOids = lappend_oid(tab->changedIndexOids, foundObject.objectId);
							tab->changedIndexDefs = lappend(tab->changedIndexDefs, pg_get_indexdef_string(foundObject.objectId));
						}
					}
					else if (relKind == RELKIND_SEQUENCE)
					{
						
						Assert(foundObject.objectSubId == 0);
					}
					else {
						
						elog(ERROR, "unexpected object depending on column: %s", getObjectDescription(&foundObject));
					}
					break;
				}

			case OCLASS_CONSTRAINT:
				Assert(foundObject.objectSubId == 0);
				if (!list_member_oid(tab->changedConstraintOids, foundObject.objectId))
				{
					char	   *defstring = pg_get_constraintdef_string(foundObject.objectId);

					
					if (foundDep->deptype == DEPENDENCY_NORMAL)
					{
						tab->changedConstraintOids = lcons_oid(foundObject.objectId, tab->changedConstraintOids);

						tab->changedConstraintDefs = lcons(defstring, tab->changedConstraintDefs);

					}
					else {
						tab->changedConstraintOids = lappend_oid(tab->changedConstraintOids, foundObject.objectId);

						tab->changedConstraintDefs = lappend(tab->changedConstraintDefs, defstring);

					}
				}
				break;

			case OCLASS_REWRITE:
				
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter type of a column used by a view or rule"), errdetail("%s depends on column \"%s\"", getObjectDescription(&foundObject), colName)));




				break;

			case OCLASS_TRIGGER:

				
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter type of a column used in a trigger definition"), errdetail("%s depends on column \"%s\"", getObjectDescription(&foundObject), colName)));




				break;

			case OCLASS_DEFAULT:

				
				Assert(defaultexpr);
				break;

			case OCLASS_PROC:
			case OCLASS_TYPE:
			case OCLASS_CAST:
			case OCLASS_COLLATION:
			case OCLASS_CONVERSION:
			case OCLASS_LANGUAGE:
			case OCLASS_LARGEOBJECT:
			case OCLASS_OPERATOR:
			case OCLASS_OPCLASS:
			case OCLASS_OPFAMILY:
			case OCLASS_AMOP:
			case OCLASS_AMPROC:
			case OCLASS_SCHEMA:
			case OCLASS_TSPARSER:
			case OCLASS_TSDICT:
			case OCLASS_TSTEMPLATE:
			case OCLASS_TSCONFIG:
			case OCLASS_ROLE:
			case OCLASS_DATABASE:
			case OCLASS_TBLSPACE:
			case OCLASS_FDW:
			case OCLASS_FOREIGN_SERVER:
			case OCLASS_USER_MAPPING:
			case OCLASS_DEFACL:
			case OCLASS_EXTENSION:

				
				elog(ERROR, "unexpected object depending on column: %s", getObjectDescription(&foundObject));
				break;

			default:
				elog(ERROR, "unrecognized object class: %u", foundObject.classId);
		}
	}

	systable_endscan(scan);

	
	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	ScanKeyInit(&key[2], Anum_pg_depend_objsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum((int32) attnum));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 3, key);

	while (HeapTupleIsValid(depTup = systable_getnext(scan)))
	{
		Form_pg_depend foundDep = (Form_pg_depend) GETSTRUCT(depTup);

		if (foundDep->deptype != DEPENDENCY_NORMAL)
			elog(ERROR, "found unexpected dependency type '%c'", foundDep->deptype);
		if (!(foundDep->refclassid == TypeRelationId && foundDep->refobjid == attTup->atttypid) && !(foundDep->refclassid == CollationRelationId && foundDep->refobjid == attTup->attcollation))


			elog(ERROR, "found unexpected dependency for column");

		simple_heap_delete(depRel, &depTup->t_self);
	}

	systable_endscan(scan);

	heap_close(depRel, RowExclusiveLock);

	
	attTup->atttypid = targettype;
	attTup->atttypmod = targettypmod;
	attTup->attcollation = targetcollid;
	attTup->attndims = list_length(typeName->arrayBounds);
	attTup->attlen = tform->typlen;
	attTup->attbyval = tform->typbyval;
	attTup->attalign = tform->typalign;
	attTup->attstorage = tform->typstorage;

	ReleaseSysCache(typeTuple);

	simple_heap_update(attrelation, &heapTup->t_self, heapTup);

	
	CatalogUpdateIndexes(attrelation, heapTup);

	heap_close(attrelation, RowExclusiveLock);

	
	add_column_datatype_dependency(RelationGetRelid(rel), attnum, targettype);
	add_column_collation_dependency(RelationGetRelid(rel), attnum, targetcollid);

	
	RemoveStatistics(RelationGetRelid(rel), attnum);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), attnum);

	
	if (defaultexpr)
	{
		
		CommandCounterIncrement();

		
		RemoveAttrDefault(RelationGetRelid(rel), attnum, DROP_RESTRICT, true, true);

		StoreAttrDefault(rel, attnum, defaultexpr, true);
	}

	
	heap_freetuple(heapTup);
}

static void ATExecAlterColumnGenericOptions(Relation rel, const char *colName, List *options, LOCKMODE lockmode)



{
	Relation	ftrel;
	Relation	attrel;
	ForeignServer *server;
	ForeignDataWrapper *fdw;
	HeapTuple	tuple;
	HeapTuple	newtuple;
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	Datum		datum;
	Form_pg_foreign_table fttableform;
	Form_pg_attribute atttableform;

	if (options == NIL)
		return;

	
	ftrel = heap_open(ForeignTableRelationId, AccessShareLock);
	tuple = SearchSysCache1(FOREIGNTABLEREL, rel->rd_id);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("foreign table \"%s\" does not exist", RelationGetRelationName(rel))));


	fttableform = (Form_pg_foreign_table) GETSTRUCT(tuple);
	server = GetForeignServer(fttableform->ftserver);
	fdw = GetForeignDataWrapper(server->fdwid);

	heap_close(ftrel, AccessShareLock);
	ReleaseSysCache(tuple);

	attrel = heap_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));



	
	atttableform = (Form_pg_attribute) GETSTRUCT(tuple);
	if (atttableform->attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	
	datum = SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attfdwoptions, &isnull);


	if (isnull)
		datum = PointerGetDatum(NULL);

	
	datum = transformGenericOptions(AttributeRelationId, datum, options, fdw->fdwvalidator);



	if (PointerIsValid(DatumGetPointer(datum)))
		repl_val[Anum_pg_attribute_attfdwoptions - 1] = datum;
	else repl_null[Anum_pg_attribute_attfdwoptions - 1] = true;

	repl_repl[Anum_pg_attribute_attfdwoptions - 1] = true;

	

	newtuple = heap_modify_tuple(tuple, RelationGetDescr(attrel), repl_val, repl_null, repl_repl);

	simple_heap_update(attrel, &newtuple->t_self, newtuple);
	CatalogUpdateIndexes(attrel, newtuple);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), atttableform->attnum);


	ReleaseSysCache(tuple);

	heap_close(attrel, RowExclusiveLock);

	heap_freetuple(newtuple);
}


static void ATPostAlterTypeCleanup(List **wqueue, AlteredTableInfo *tab, LOCKMODE lockmode)
{
	ObjectAddress obj;
	ListCell   *def_item;
	ListCell   *oid_item;

	
	forboth(oid_item, tab->changedConstraintOids, def_item, tab->changedConstraintDefs)
		ATPostAlterTypeParse(lfirst_oid(oid_item), (char *) lfirst(def_item), wqueue, lockmode, tab->rewrite);
	forboth(oid_item, tab->changedIndexOids, def_item, tab->changedIndexDefs)
		ATPostAlterTypeParse(lfirst_oid(oid_item), (char *) lfirst(def_item), wqueue, lockmode, tab->rewrite);

	
	foreach(oid_item, tab->changedConstraintOids)
	{
		obj.classId = ConstraintRelationId;
		obj.objectId = lfirst_oid(oid_item);
		obj.objectSubId = 0;
		performDeletion(&obj, DROP_RESTRICT, PERFORM_DELETION_INTERNAL);
	}

	foreach(oid_item, tab->changedIndexOids)
	{
		obj.classId = RelationRelationId;
		obj.objectId = lfirst_oid(oid_item);
		obj.objectSubId = 0;
		performDeletion(&obj, DROP_RESTRICT, PERFORM_DELETION_INTERNAL);
	}

	
}

static void ATPostAlterTypeParse(Oid oldId, char *cmd, List **wqueue, LOCKMODE lockmode, bool rewrite)

{
	List	   *raw_parsetree_list;
	List	   *querytree_list;
	ListCell   *list_item;

	
	raw_parsetree_list = raw_parser(cmd);
	querytree_list = NIL;
	foreach(list_item, raw_parsetree_list)
	{
		Node	   *stmt = (Node *) lfirst(list_item);

		if (IsA(stmt, IndexStmt))
			querytree_list = lappend(querytree_list, transformIndexStmt((IndexStmt *) stmt, cmd));

		else if (IsA(stmt, AlterTableStmt))
			querytree_list = list_concat(querytree_list, transformAlterTableStmt((AlterTableStmt *) stmt, cmd));

		else querytree_list = lappend(querytree_list, stmt);
	}

	
	foreach(list_item, querytree_list)
	{
		Node	   *stm = (Node *) lfirst(list_item);
		Relation	rel;
		AlteredTableInfo *tab;

		switch (nodeTag(stm))
		{
			case T_IndexStmt:
				{
					IndexStmt  *stmt = (IndexStmt *) stm;
					AlterTableCmd *newcmd;

					if (!rewrite)
						TryReuseIndex(oldId, stmt);

					rel = relation_openrv(stmt->relation, lockmode);
					tab = ATGetQueueEntry(wqueue, rel);
					newcmd = makeNode(AlterTableCmd);
					newcmd->subtype = AT_ReAddIndex;
					newcmd->def = (Node *) stmt;
					tab->subcmds[AT_PASS_OLD_INDEX] = lappend(tab->subcmds[AT_PASS_OLD_INDEX], newcmd);
					relation_close(rel, NoLock);
					break;
				}
			case T_AlterTableStmt:
				{
					AlterTableStmt *stmt = (AlterTableStmt *) stm;
					ListCell   *lcmd;

					rel = relation_openrv(stmt->relation, lockmode);
					tab = ATGetQueueEntry(wqueue, rel);
					foreach(lcmd, stmt->cmds)
					{
						AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);
						Constraint *con;

						switch (cmd->subtype)
						{
							case AT_AddIndex:
								Assert(IsA(cmd->def, IndexStmt));
								if (!rewrite)
									TryReuseIndex(get_constraint_index(oldId), (IndexStmt *) cmd->def);
								cmd->subtype = AT_ReAddIndex;
								tab->subcmds[AT_PASS_OLD_INDEX] = lappend(tab->subcmds[AT_PASS_OLD_INDEX], cmd);
								break;
							case AT_AddConstraint:
								Assert(IsA(cmd->def, Constraint));
								con = (Constraint *) cmd->def;
								
								if (con->contype == CONSTR_FOREIGN && !rewrite && !tab->rewrite)
									TryReuseForeignKey(oldId, con);
								cmd->subtype = AT_ReAddConstraint;
								tab->subcmds[AT_PASS_OLD_CONSTR] = lappend(tab->subcmds[AT_PASS_OLD_CONSTR], cmd);
								break;
							default:
								elog(ERROR, "unexpected statement type: %d", (int) cmd->subtype);
						}
					}
					relation_close(rel, NoLock);
					break;
				}
			default:
				elog(ERROR, "unexpected statement type: %d", (int) nodeTag(stm));
		}
	}
}


static void TryReuseIndex(Oid oldId, IndexStmt *stmt)
{
	if (CheckIndexCompatible(oldId, stmt->relation, stmt->accessMethod, stmt->indexParams, stmt->excludeOpNames))



	{
		Relation	irel = index_open(oldId, NoLock);

		stmt->oldNode = irel->rd_node.relNode;
		index_close(irel, NoLock);
	}
}


static void TryReuseForeignKey(Oid oldId, Constraint *con)
{
	HeapTuple	tup;
	Datum		adatum;
	bool		isNull;
	ArrayType  *arr;
	Oid		   *rawarr;
	int			numkeys;
	int			i;

	Assert(con->contype == CONSTR_FOREIGN);
	Assert(con->old_conpfeqop == NIL);	

	tup = SearchSysCache1(CONSTROID, ObjectIdGetDatum(oldId));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for constraint %u", oldId);

	adatum = SysCacheGetAttr(CONSTROID, tup, Anum_pg_constraint_conpfeqop, &isNull);
	if (isNull)
		elog(ERROR, "null conpfeqop for constraint %u", oldId);
	arr = DatumGetArrayTypeP(adatum);	
	numkeys = ARR_DIMS(arr)[0];
	
	if (ARR_NDIM(arr) != 1 || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != OIDOID)

		elog(ERROR, "conpfeqop is not a 1-D Oid array");
	rawarr = (Oid *) ARR_DATA_PTR(arr);

	
	for (i = 0; i < numkeys; i++)
		con->old_conpfeqop = lcons_oid(rawarr[i], con->old_conpfeqop);

	ReleaseSysCache(tup);
}


void ATExecChangeOwner(Oid relationOid, Oid newOwnerId, bool recursing, LOCKMODE lockmode)
{
	Relation	target_rel;
	Relation	class_rel;
	HeapTuple	tuple;
	Form_pg_class tuple_class;

	
	target_rel = relation_open(relationOid, lockmode);

	
	class_rel = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relationOid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relationOid);
	tuple_class = (Form_pg_class) GETSTRUCT(tuple);

	
	switch (tuple_class->relkind)
	{
		case RELKIND_RELATION:
		case RELKIND_VIEW:
		case RELKIND_MATVIEW:
		case RELKIND_FOREIGN_TABLE:
			
			break;
		case RELKIND_INDEX:
			if (!recursing)
			{
				
				if (tuple_class->relowner != newOwnerId)
					ereport(WARNING, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot change owner of index \"%s\"", NameStr(tuple_class->relname)), errhint("Change the ownership of the index's table, instead.")));



				
				newOwnerId = tuple_class->relowner;
			}
			break;
		case RELKIND_SEQUENCE:
			if (!recursing && tuple_class->relowner != newOwnerId)
			{
				
				Oid			tableId;
				int32		colId;

				if (sequenceIsOwned(relationOid, &tableId, &colId))
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot change owner of sequence \"%s\"", NameStr(tuple_class->relname)), errdetail("Sequence \"%s\" is linked to table \"%s\".", NameStr(tuple_class->relname), get_rel_name(tableId))));





			}
			break;
		case RELKIND_COMPOSITE_TYPE:
			if (recursing)
				break;
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a composite type", NameStr(tuple_class->relname)), errhint("Use ALTER TYPE instead.")));



			break;
		case RELKIND_TOASTVALUE:
			if (recursing)
				break;
			
		default:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, sequence, or foreign table", NameStr(tuple_class->relname))));


	}

	
	if (tuple_class->relowner != newOwnerId)
	{
		Datum		repl_val[Natts_pg_class];
		bool		repl_null[Natts_pg_class];
		bool		repl_repl[Natts_pg_class];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isNull;
		HeapTuple	newtuple;

		
		if (!recursing)
		{
			
			if (!superuser())
			{
				Oid			namespaceOid = tuple_class->relnamespace;
				AclResult	aclresult;

				
				if (!pg_class_ownercheck(relationOid, GetUserId()))
					aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(target_rel));

				
				check_is_member_of_role(GetUserId(), newOwnerId);

				
				aclresult = pg_namespace_aclcheck(namespaceOid, newOwnerId, ACL_CREATE);
				if (aclresult != ACLCHECK_OK)
					aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(namespaceOid));
			}
		}

		memset(repl_null, false, sizeof(repl_null));
		memset(repl_repl, false, sizeof(repl_repl));

		repl_repl[Anum_pg_class_relowner - 1] = true;
		repl_val[Anum_pg_class_relowner - 1] = ObjectIdGetDatum(newOwnerId);

		
		aclDatum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_relacl, &isNull);

		if (!isNull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum), tuple_class->relowner, newOwnerId);
			repl_repl[Anum_pg_class_relacl - 1] = true;
			repl_val[Anum_pg_class_relacl - 1] = PointerGetDatum(newAcl);
		}

		newtuple = heap_modify_tuple(tuple, RelationGetDescr(class_rel), repl_val, repl_null, repl_repl);

		simple_heap_update(class_rel, &newtuple->t_self, newtuple);
		CatalogUpdateIndexes(class_rel, newtuple);

		heap_freetuple(newtuple);

		
		change_owner_fix_column_acls(relationOid, tuple_class->relowner, newOwnerId);


		
		if (tuple_class->relkind != RELKIND_COMPOSITE_TYPE && tuple_class->relkind != RELKIND_INDEX && tuple_class->relkind != RELKIND_TOASTVALUE)

			changeDependencyOnOwner(RelationRelationId, relationOid, newOwnerId);

		
		if (tuple_class->relkind != RELKIND_INDEX)
			AlterTypeOwnerInternal(tuple_class->reltype, newOwnerId, tuple_class->relkind == RELKIND_COMPOSITE_TYPE);

		
		if (tuple_class->relkind == RELKIND_RELATION || tuple_class->relkind == RELKIND_MATVIEW || tuple_class->relkind == RELKIND_TOASTVALUE)

		{
			List	   *index_oid_list;
			ListCell   *i;

			
			index_oid_list = RelationGetIndexList(target_rel);

			
			foreach(i, index_oid_list)
				ATExecChangeOwner(lfirst_oid(i), newOwnerId, true, lockmode);

			list_free(index_oid_list);
		}

		if (tuple_class->relkind == RELKIND_RELATION || tuple_class->relkind == RELKIND_MATVIEW)
		{
			
			if (tuple_class->reltoastrelid != InvalidOid)
				ATExecChangeOwner(tuple_class->reltoastrelid, newOwnerId, true, lockmode);

			
			change_owner_recurse_to_sequences(relationOid, newOwnerId, lockmode);
		}
	}

	InvokeObjectPostAlterHook(RelationRelationId, relationOid, 0);

	ReleaseSysCache(tuple);
	heap_close(class_rel, RowExclusiveLock);
	relation_close(target_rel, NoLock);
}


static void change_owner_fix_column_acls(Oid relationOid, Oid oldOwnerId, Oid newOwnerId)
{
	Relation	attRelation;
	SysScanDesc scan;
	ScanKeyData key[1];
	HeapTuple	attributeTuple;

	attRelation = heap_open(AttributeRelationId, RowExclusiveLock);
	ScanKeyInit(&key[0], Anum_pg_attribute_attrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relationOid));


	scan = systable_beginscan(attRelation, AttributeRelidNumIndexId, true, NULL, 1, key);
	while (HeapTupleIsValid(attributeTuple = systable_getnext(scan)))
	{
		Form_pg_attribute att = (Form_pg_attribute) GETSTRUCT(attributeTuple);
		Datum		repl_val[Natts_pg_attribute];
		bool		repl_null[Natts_pg_attribute];
		bool		repl_repl[Natts_pg_attribute];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isNull;
		HeapTuple	newtuple;

		
		if (att->attisdropped)
			continue;

		aclDatum = heap_getattr(attributeTuple, Anum_pg_attribute_attacl, RelationGetDescr(attRelation), &isNull);


		
		if (isNull)
			continue;

		memset(repl_null, false, sizeof(repl_null));
		memset(repl_repl, false, sizeof(repl_repl));

		newAcl = aclnewowner(DatumGetAclP(aclDatum), oldOwnerId, newOwnerId);
		repl_repl[Anum_pg_attribute_attacl - 1] = true;
		repl_val[Anum_pg_attribute_attacl - 1] = PointerGetDatum(newAcl);

		newtuple = heap_modify_tuple(attributeTuple, RelationGetDescr(attRelation), repl_val, repl_null, repl_repl);


		simple_heap_update(attRelation, &newtuple->t_self, newtuple);
		CatalogUpdateIndexes(attRelation, newtuple);

		heap_freetuple(newtuple);
	}
	systable_endscan(scan);
	heap_close(attRelation, RowExclusiveLock);
}


static void change_owner_recurse_to_sequences(Oid relationOid, Oid newOwnerId, LOCKMODE lockmode)
{
	Relation	depRel;
	SysScanDesc scan;
	ScanKeyData key[2];
	HeapTuple	tup;

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relationOid));


	

	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend depForm = (Form_pg_depend) GETSTRUCT(tup);
		Relation	seqRel;

		
		if (depForm->refobjsubid == 0 || depForm->classid != RelationRelationId || depForm->objsubid != 0 || depForm->deptype != DEPENDENCY_AUTO)


			continue;

		
		seqRel = relation_open(depForm->objid, lockmode);

		
		if (RelationGetForm(seqRel)->relkind != RELKIND_SEQUENCE)
		{
			
			relation_close(seqRel, lockmode);
			continue;
		}

		
		ATExecChangeOwner(depForm->objid, newOwnerId, true, lockmode);

		
		relation_close(seqRel, NoLock);
	}

	systable_endscan(scan);

	relation_close(depRel, AccessShareLock);
}


static void ATExecClusterOn(Relation rel, const char *indexName, LOCKMODE lockmode)
{
	Oid			indexOid;

	indexOid = get_relname_relid(indexName, rel->rd_rel->relnamespace);

	if (!OidIsValid(indexOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("index \"%s\" for table \"%s\" does not exist", indexName, RelationGetRelationName(rel))));



	
	check_index_is_clusterable(rel, indexOid, false, lockmode);

	
	mark_index_clustered(rel, indexOid, false);
}


static void ATExecDropCluster(Relation rel, LOCKMODE lockmode)
{
	mark_index_clustered(rel, InvalidOid, false);
}


static void ATPrepSetTableSpace(AlteredTableInfo *tab, Relation rel, char *tablespacename, LOCKMODE lockmode)
{
	Oid			tablespaceId;

	
	tablespaceId = get_tablespace_oid(tablespacename, false);

	
	if (OidIsValid(tablespaceId) && tablespaceId != MyDatabaseTableSpace)
	{
		AclResult	aclresult;

		aclresult = pg_tablespace_aclcheck(tablespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE, tablespacename);
	}

	
	if (OidIsValid(tab->newTableSpace))
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("cannot have multiple SET TABLESPACE subcommands")));


	tab->newTableSpace = tablespaceId;
}


static void ATExecSetRelOptions(Relation rel, List *defList, AlterTableType operation, LOCKMODE lockmode)

{
	Oid			relid;
	Relation	pgclass;
	HeapTuple	tuple;
	HeapTuple	newtuple;
	Datum		datum;
	bool		isnull;
	Datum		newOptions;
	Datum		repl_val[Natts_pg_class];
	bool		repl_null[Natts_pg_class];
	bool		repl_repl[Natts_pg_class];
	static char *validnsps[] = HEAP_RELOPT_NAMESPACES;

	if (defList == NIL && operation != AT_ReplaceRelOptions)
		return;					

	pgclass = heap_open(RelationRelationId, RowExclusiveLock);

	
	relid = RelationGetRelid(rel);
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relid);

	if (operation == AT_ReplaceRelOptions)
	{
		
		datum = (Datum) 0;
		isnull = true;
	}
	else {
		
		datum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_reloptions, &isnull);
	}

	
	newOptions = transformRelOptions(isnull ? (Datum) 0 : datum, defList, NULL, validnsps, false, operation == AT_ResetRelOptions);


	
	switch (rel->rd_rel->relkind)
	{
		case RELKIND_RELATION:
		case RELKIND_TOASTVALUE:
		case RELKIND_VIEW:
		case RELKIND_MATVIEW:
			(void) heap_reloptions(rel->rd_rel->relkind, newOptions, true);
			break;
		case RELKIND_INDEX:
			(void) index_reloptions(rel->rd_am->amoptions, newOptions, true);
			break;
		default:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, materialized view, index, or TOAST table", RelationGetRelationName(rel))));


			break;
	}

	
	if (rel->rd_rel->relkind == RELKIND_VIEW)
	{
		Query	   *view_query = get_view_query(rel);
		List	   *view_options = untransformRelOptions(newOptions);
		ListCell   *cell;
		bool		check_option = false;
		bool		security_barrier = false;

		foreach(cell, view_options)
		{
			DefElem    *defel = (DefElem *) lfirst(cell);

			if (pg_strcasecmp(defel->defname, "check_option") == 0)
				check_option = true;
			if (pg_strcasecmp(defel->defname, "security_barrier") == 0)
				security_barrier = defGetBoolean(defel);
		}

		
		if (check_option)
		{
			const char *view_updatable_error = view_query_is_auto_updatable(view_query, security_barrier, true);


			if (view_updatable_error)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("WITH CHECK OPTION is supported only on auto-updatable views"), errhint("%s", view_updatable_error)));


		}
	}

	
	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	if (newOptions != (Datum) 0)
		repl_val[Anum_pg_class_reloptions - 1] = newOptions;
	else repl_null[Anum_pg_class_reloptions - 1] = true;

	repl_repl[Anum_pg_class_reloptions - 1] = true;

	newtuple = heap_modify_tuple(tuple, RelationGetDescr(pgclass), repl_val, repl_null, repl_repl);

	simple_heap_update(pgclass, &newtuple->t_self, newtuple);

	CatalogUpdateIndexes(pgclass, newtuple);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), 0);

	heap_freetuple(newtuple);

	ReleaseSysCache(tuple);

	
	if (OidIsValid(rel->rd_rel->reltoastrelid))
	{
		Relation	toastrel;
		Oid			toastid = rel->rd_rel->reltoastrelid;

		toastrel = heap_open(toastid, lockmode);

		
		tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(toastid));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation %u", toastid);

		if (operation == AT_ReplaceRelOptions)
		{
			
			datum = (Datum) 0;
			isnull = true;
		}
		else {
			
			datum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_reloptions, &isnull);
		}

		newOptions = transformRelOptions(isnull ? (Datum) 0 : datum, defList, "toast", validnsps, false, operation == AT_ResetRelOptions);


		(void) heap_reloptions(RELKIND_TOASTVALUE, newOptions, true);

		memset(repl_val, 0, sizeof(repl_val));
		memset(repl_null, false, sizeof(repl_null));
		memset(repl_repl, false, sizeof(repl_repl));

		if (newOptions != (Datum) 0)
			repl_val[Anum_pg_class_reloptions - 1] = newOptions;
		else repl_null[Anum_pg_class_reloptions - 1] = true;

		repl_repl[Anum_pg_class_reloptions - 1] = true;

		newtuple = heap_modify_tuple(tuple, RelationGetDescr(pgclass), repl_val, repl_null, repl_repl);

		simple_heap_update(pgclass, &newtuple->t_self, newtuple);

		CatalogUpdateIndexes(pgclass, newtuple);

		InvokeObjectPostAlterHookArg(RelationRelationId, RelationGetRelid(toastrel), 0, InvalidOid, true);


		heap_freetuple(newtuple);

		ReleaseSysCache(tuple);

		heap_close(toastrel, NoLock);
	}

	heap_close(pgclass, RowExclusiveLock);
}


static void ATExecSetTableSpace(Oid tableOid, Oid newTableSpace, LOCKMODE lockmode)
{
	Relation	rel;
	Oid			oldTableSpace;
	Oid			reltoastrelid;
	Oid			newrelfilenode;
	RelFileNode newrnode;
	SMgrRelation dstrel;
	Relation	pg_class;
	HeapTuple	tuple;
	Form_pg_class rd_rel;
	ForkNumber	forkNum;
	List	   *reltoastidxids = NIL;
	ListCell   *lc;

	
	rel = relation_open(tableOid, lockmode);

	
	oldTableSpace = rel->rd_rel->reltablespace;
	if (newTableSpace == oldTableSpace || (newTableSpace == MyDatabaseTableSpace && oldTableSpace == 0))
	{
		InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), 0);

		relation_close(rel, NoLock);
		return;
	}

	
	if (RelationIsMapped(rel))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move system relation \"%s\"", RelationGetRelationName(rel))));



	
	if (newTableSpace == GLOBALTABLESPACE_OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("only shared relations can be placed in pg_global tablespace")));


	
	if (RELATION_IS_OTHER_TEMP(rel))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move temporary tables of other sessions")));


	reltoastrelid = rel->rd_rel->reltoastrelid;
	
	if (OidIsValid(reltoastrelid))
	{
		Relation toastRel = relation_open(reltoastrelid, lockmode);
		reltoastidxids = RelationGetIndexList(toastRel);
		relation_close(toastRel, lockmode);
	}

	
	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(tableOid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", tableOid);
	rd_rel = (Form_pg_class) GETSTRUCT(tuple);

	
	FlushRelationBuffers(rel);

	
	newrelfilenode = GetNewRelFileNode(newTableSpace, NULL, rel->rd_rel->relpersistence);

	
	newrnode = rel->rd_node;
	newrnode.relNode = newrelfilenode;
	newrnode.spcNode = newTableSpace;
	dstrel = smgropen(newrnode, rel->rd_backend);

	RelationOpenSmgr(rel);

	
	RelationCreateStorage(newrnode, rel->rd_rel->relpersistence);

	
	copy_relation_data(rel->rd_smgr, dstrel, MAIN_FORKNUM, rel->rd_rel->relpersistence);

	
	for (forkNum = MAIN_FORKNUM + 1; forkNum <= MAX_FORKNUM; forkNum++)
	{
		if (smgrexists(rel->rd_smgr, forkNum))
		{
			smgrcreate(dstrel, forkNum, false);
			copy_relation_data(rel->rd_smgr, dstrel, forkNum, rel->rd_rel->relpersistence);
		}
	}

	
	RelationDropStorage(rel);
	smgrclose(dstrel);

	
	rd_rel->reltablespace = (newTableSpace == MyDatabaseTableSpace) ? InvalidOid : newTableSpace;
	rd_rel->relfilenode = newrelfilenode;
	simple_heap_update(pg_class, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_class, tuple);

	InvokeObjectPostAlterHook(RelationRelationId, RelationGetRelid(rel), 0);

	heap_freetuple(tuple);

	heap_close(pg_class, RowExclusiveLock);

	relation_close(rel, NoLock);

	
	CommandCounterIncrement();

	
	if (OidIsValid(reltoastrelid))
		ATExecSetTableSpace(reltoastrelid, newTableSpace, lockmode);
	foreach(lc, reltoastidxids)
		ATExecSetTableSpace(lfirst_oid(lc), newTableSpace, lockmode);

	
	list_free(reltoastidxids);
}


static void copy_relation_data(SMgrRelation src, SMgrRelation dst, ForkNumber forkNum, char relpersistence)

{
	char	   *buf;
	Page		page;
	bool		use_wal;
	BlockNumber nblocks;
	BlockNumber blkno;

	
	buf = (char *) palloc(BLCKSZ);
	page = (Page) buf;

	
	use_wal = XLogIsNeeded() && relpersistence == RELPERSISTENCE_PERMANENT;

	nblocks = smgrnblocks(src, forkNum);

	for (blkno = 0; blkno < nblocks; blkno++)
	{
		
		CHECK_FOR_INTERRUPTS();

		smgrread(src, forkNum, blkno, buf);

		if (!PageIsVerified(page, blkno))
			ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED), errmsg("invalid page in block %u of relation %s", blkno, relpathbackend(src->smgr_rnode.node, src->smgr_rnode.backend, forkNum))));






		
		if (use_wal)
			log_newpage(&dst->smgr_rnode.node, forkNum, blkno, page, false);

		PageSetChecksumInplace(page, blkno);

		
		smgrextend(dst, forkNum, blkno, buf, true);
	}

	pfree(buf);

	
	if (relpersistence == RELPERSISTENCE_PERMANENT)
		smgrimmedsync(dst, forkNum);
}


static void ATExecEnableDisableTrigger(Relation rel, char *trigname, char fires_when, bool skip_system, LOCKMODE lockmode)

{
	EnableDisableTrigger(rel, trigname, fires_when, skip_system);
}


static void ATExecEnableDisableRule(Relation rel, char *trigname, char fires_when, LOCKMODE lockmode)

{
	EnableDisableRule(rel, trigname, fires_when);
}


static void ATPrepAddInherit(Relation child_rel)
{
	if (child_rel->rd_rel->reloftype)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot change inheritance of typed table")));

}

static void ATExecAddInherit(Relation child_rel, RangeVar *parent, LOCKMODE lockmode)
{
	Relation	parent_rel, catalogRelation;
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	inheritsTuple;
	int32		inhseqno;
	List	   *children;

	
	parent_rel = heap_openrv(parent, ShareUpdateExclusiveLock);

	
	ATSimplePermissions(parent_rel, ATT_TABLE);

	
	if (parent_rel->rd_rel->relpersistence == RELPERSISTENCE_TEMP && child_rel->rd_rel->relpersistence != RELPERSISTENCE_TEMP)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit from temporary relation \"%s\"", RelationGetRelationName(parent_rel))));



	
	if (parent_rel->rd_rel->relpersistence == RELPERSISTENCE_TEMP && !parent_rel->rd_islocaltemp)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit from temporary relation of another session")));


	
	if (child_rel->rd_rel->relpersistence == RELPERSISTENCE_TEMP && !child_rel->rd_islocaltemp)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit to temporary relation of another session")));


	
	catalogRelation = heap_open(InheritsRelationId, RowExclusiveLock);
	ScanKeyInit(&key, Anum_pg_inherits_inhrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(child_rel)));


	scan = systable_beginscan(catalogRelation, InheritsRelidSeqnoIndexId, true, NULL, 1, &key);

	
	inhseqno = 0;
	while (HeapTupleIsValid(inheritsTuple = systable_getnext(scan)))
	{
		Form_pg_inherits inh = (Form_pg_inherits) GETSTRUCT(inheritsTuple);

		if (inh->inhparent == RelationGetRelid(parent_rel))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" would be inherited from more than once", RelationGetRelationName(parent_rel))));


		if (inh->inhseqno > inhseqno)
			inhseqno = inh->inhseqno;
	}
	systable_endscan(scan);

	
	children = find_all_inheritors(RelationGetRelid(child_rel), AccessShareLock, NULL);

	if (list_member_oid(children, RelationGetRelid(parent_rel)))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("circular inheritance not allowed"), errdetail("\"%s\" is already a child of \"%s\".", parent->relname, RelationGetRelationName(child_rel))));





	
	if (parent_rel->rd_rel->relhasoids && !child_rel->rd_rel->relhasoids)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("table \"%s\" without OIDs cannot inherit from table \"%s\" with OIDs", RelationGetRelationName(child_rel), RelationGetRelationName(parent_rel))));




	
	MergeAttributesIntoExisting(child_rel, parent_rel);

	
	MergeConstraintsIntoExisting(child_rel, parent_rel);

	
	StoreCatalogInheritance1(RelationGetRelid(child_rel), RelationGetRelid(parent_rel), inhseqno + 1, catalogRelation);



	
	heap_close(catalogRelation, RowExclusiveLock);

	
	heap_close(parent_rel, NoLock);
}


static char * decompile_conbin(HeapTuple contup, TupleDesc tupdesc)
{
	Form_pg_constraint con;
	bool		isnull;
	Datum		attr;
	Datum		expr;

	con = (Form_pg_constraint) GETSTRUCT(contup);
	attr = heap_getattr(contup, Anum_pg_constraint_conbin, tupdesc, &isnull);
	if (isnull)
		elog(ERROR, "null conbin for constraint %u", HeapTupleGetOid(contup));

	expr = DirectFunctionCall2(pg_get_expr, attr, ObjectIdGetDatum(con->conrelid));
	return TextDatumGetCString(expr);
}


static bool constraints_equivalent(HeapTuple a, HeapTuple b, TupleDesc tupleDesc)
{
	Form_pg_constraint acon = (Form_pg_constraint) GETSTRUCT(a);
	Form_pg_constraint bcon = (Form_pg_constraint) GETSTRUCT(b);

	if (acon->condeferrable != bcon->condeferrable || acon->condeferred != bcon->condeferred || strcmp(decompile_conbin(a, tupleDesc), decompile_conbin(b, tupleDesc)) != 0)


		return false;
	else return true;
}


static void MergeAttributesIntoExisting(Relation child_rel, Relation parent_rel)
{
	Relation	attrrel;
	AttrNumber	parent_attno;
	int			parent_natts;
	TupleDesc	tupleDesc;
	HeapTuple	tuple;

	attrrel = heap_open(AttributeRelationId, RowExclusiveLock);

	tupleDesc = RelationGetDescr(parent_rel);
	parent_natts = tupleDesc->natts;

	for (parent_attno = 1; parent_attno <= parent_natts; parent_attno++)
	{
		Form_pg_attribute attribute = tupleDesc->attrs[parent_attno - 1];
		char	   *attributeName = NameStr(attribute->attname);

		
		if (attribute->attisdropped)
			continue;

		
		tuple = SearchSysCacheCopyAttName(RelationGetRelid(child_rel), attributeName);
		if (HeapTupleIsValid(tuple))
		{
			
			Form_pg_attribute childatt = (Form_pg_attribute) GETSTRUCT(tuple);

			if (attribute->atttypid != childatt->atttypid || attribute->atttypmod != childatt->atttypmod)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table \"%s\" has different type for column \"%s\"", RelationGetRelationName(child_rel), attributeName)));




			if (attribute->attcollation != childatt->attcollation)
				ereport(ERROR, (errcode(ERRCODE_COLLATION_MISMATCH), errmsg("child table \"%s\" has different collation for column \"%s\"", RelationGetRelationName(child_rel), attributeName)));




			
			if (attribute->attnotnull && !childatt->attnotnull)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("column \"%s\" in child table must be marked NOT NULL", attributeName)));



			
			childatt->attinhcount++;
			simple_heap_update(attrrel, &tuple->t_self, tuple);
			CatalogUpdateIndexes(attrrel, tuple);
			heap_freetuple(tuple);
		}
		else {
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table is missing column \"%s\"", attributeName)));


		}
	}

	heap_close(attrrel, RowExclusiveLock);
}


static void MergeConstraintsIntoExisting(Relation child_rel, Relation parent_rel)
{
	Relation	catalog_relation;
	TupleDesc	tuple_desc;
	SysScanDesc parent_scan;
	ScanKeyData parent_key;
	HeapTuple	parent_tuple;

	catalog_relation = heap_open(ConstraintRelationId, RowExclusiveLock);
	tuple_desc = RelationGetDescr(catalog_relation);

	
	ScanKeyInit(&parent_key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(parent_rel)));


	parent_scan = systable_beginscan(catalog_relation, ConstraintRelidIndexId, true, NULL, 1, &parent_key);

	while (HeapTupleIsValid(parent_tuple = systable_getnext(parent_scan)))
	{
		Form_pg_constraint parent_con = (Form_pg_constraint) GETSTRUCT(parent_tuple);
		SysScanDesc child_scan;
		ScanKeyData child_key;
		HeapTuple	child_tuple;
		bool		found = false;

		if (parent_con->contype != CONSTRAINT_CHECK)
			continue;

		
		if (parent_con->connoinherit)
			continue;

		
		ScanKeyInit(&child_key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(child_rel)));


		child_scan = systable_beginscan(catalog_relation, ConstraintRelidIndexId, true, NULL, 1, &child_key);

		while (HeapTupleIsValid(child_tuple = systable_getnext(child_scan)))
		{
			Form_pg_constraint child_con = (Form_pg_constraint) GETSTRUCT(child_tuple);
			HeapTuple	child_copy;

			if (child_con->contype != CONSTRAINT_CHECK)
				continue;

			if (strcmp(NameStr(parent_con->conname), NameStr(child_con->conname)) != 0)
				continue;

			if (!constraints_equivalent(parent_tuple, child_tuple, tuple_desc))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table \"%s\" has different definition for check constraint \"%s\"", RelationGetRelationName(child_rel), NameStr(parent_con->conname))));




			
			if (child_con->connoinherit)
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("constraint \"%s\" conflicts with non-inherited constraint on child table \"%s\"", NameStr(child_con->conname), RelationGetRelationName(child_rel))));




			
			child_copy = heap_copytuple(child_tuple);
			child_con = (Form_pg_constraint) GETSTRUCT(child_copy);
			child_con->coninhcount++;
			simple_heap_update(catalog_relation, &child_copy->t_self, child_copy);
			CatalogUpdateIndexes(catalog_relation, child_copy);
			heap_freetuple(child_copy);

			found = true;
			break;
		}

		systable_endscan(child_scan);

		if (!found)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table is missing constraint \"%s\"", NameStr(parent_con->conname))));


	}

	systable_endscan(parent_scan);
	heap_close(catalog_relation, RowExclusiveLock);
}


static void ATExecDropInherit(Relation rel, RangeVar *parent, LOCKMODE lockmode)
{
	Relation	parent_rel;
	Relation	catalogRelation;
	SysScanDesc scan;
	ScanKeyData key[3];
	HeapTuple	inheritsTuple, attributeTuple, constraintTuple;

	List	   *connames;
	bool		found = false;

	
	parent_rel = heap_openrv(parent, AccessShareLock);

	

	
	catalogRelation = heap_open(InheritsRelationId, RowExclusiveLock);
	ScanKeyInit(&key[0], Anum_pg_inherits_inhrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(catalogRelation, InheritsRelidSeqnoIndexId, true, NULL, 1, key);

	while (HeapTupleIsValid(inheritsTuple = systable_getnext(scan)))
	{
		Oid			inhparent;

		inhparent = ((Form_pg_inherits) GETSTRUCT(inheritsTuple))->inhparent;
		if (inhparent == RelationGetRelid(parent_rel))
		{
			simple_heap_delete(catalogRelation, &inheritsTuple->t_self);
			found = true;
			break;
		}
	}

	systable_endscan(scan);
	heap_close(catalogRelation, RowExclusiveLock);

	if (!found)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_TABLE), errmsg("relation \"%s\" is not a parent of relation \"%s\"", RelationGetRelationName(parent_rel), RelationGetRelationName(rel))));




	
	catalogRelation = heap_open(AttributeRelationId, RowExclusiveLock);
	ScanKeyInit(&key[0], Anum_pg_attribute_attrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(catalogRelation, AttributeRelidNumIndexId, true, NULL, 1, key);
	while (HeapTupleIsValid(attributeTuple = systable_getnext(scan)))
	{
		Form_pg_attribute att = (Form_pg_attribute) GETSTRUCT(attributeTuple);

		
		if (att->attisdropped)
			continue;
		if (att->attinhcount <= 0)
			continue;

		if (SearchSysCacheExistsAttName(RelationGetRelid(parent_rel), NameStr(att->attname)))
		{
			
			HeapTuple	copyTuple = heap_copytuple(attributeTuple);
			Form_pg_attribute copy_att = (Form_pg_attribute) GETSTRUCT(copyTuple);

			copy_att->attinhcount--;
			if (copy_att->attinhcount == 0)
				copy_att->attislocal = true;

			simple_heap_update(catalogRelation, &copyTuple->t_self, copyTuple);
			CatalogUpdateIndexes(catalogRelation, copyTuple);
			heap_freetuple(copyTuple);
		}
	}
	systable_endscan(scan);
	heap_close(catalogRelation, RowExclusiveLock);

	
	catalogRelation = heap_open(ConstraintRelationId, RowExclusiveLock);
	ScanKeyInit(&key[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(parent_rel)));


	scan = systable_beginscan(catalogRelation, ConstraintRelidIndexId, true, NULL, 1, key);

	connames = NIL;

	while (HeapTupleIsValid(constraintTuple = systable_getnext(scan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(constraintTuple);

		if (con->contype == CONSTRAINT_CHECK)
			connames = lappend(connames, pstrdup(NameStr(con->conname)));
	}

	systable_endscan(scan);

	
	ScanKeyInit(&key[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(catalogRelation, ConstraintRelidIndexId, true, NULL, 1, key);

	while (HeapTupleIsValid(constraintTuple = systable_getnext(scan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(constraintTuple);
		bool		match;
		ListCell   *lc;

		if (con->contype != CONSTRAINT_CHECK)
			continue;

		match = false;
		foreach(lc, connames)
		{
			if (strcmp(NameStr(con->conname), (char *) lfirst(lc)) == 0)
			{
				match = true;
				break;
			}
		}

		if (match)
		{
			
			HeapTuple	copyTuple = heap_copytuple(constraintTuple);
			Form_pg_constraint copy_con = (Form_pg_constraint) GETSTRUCT(copyTuple);

			if (copy_con->coninhcount <= 0)		
				elog(ERROR, "relation %u has non-inherited constraint \"%s\"", RelationGetRelid(rel), NameStr(copy_con->conname));

			copy_con->coninhcount--;
			if (copy_con->coninhcount == 0)
				copy_con->conislocal = true;

			simple_heap_update(catalogRelation, &copyTuple->t_self, copyTuple);
			CatalogUpdateIndexes(catalogRelation, copyTuple);
			heap_freetuple(copyTuple);
		}
	}

	systable_endscan(scan);
	heap_close(catalogRelation, RowExclusiveLock);

	drop_parent_dependency(RelationGetRelid(rel), RelationRelationId, RelationGetRelid(parent_rel));


	
	InvokeObjectPostAlterHookArg(InheritsRelationId, RelationGetRelid(rel), 0, RelationGetRelid(parent_rel), false);


	
	heap_close(parent_rel, NoLock);
}


static void drop_parent_dependency(Oid relid, Oid refclassid, Oid refobjid)
{
	Relation	catalogRelation;
	SysScanDesc scan;
	ScanKeyData key[3];
	HeapTuple	depTuple;

	catalogRelation = heap_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&key[2], Anum_pg_depend_objsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum(0));



	scan = systable_beginscan(catalogRelation, DependDependerIndexId, true, NULL, 3, key);

	while (HeapTupleIsValid(depTuple = systable_getnext(scan)))
	{
		Form_pg_depend dep = (Form_pg_depend) GETSTRUCT(depTuple);

		if (dep->refclassid == refclassid && dep->refobjid == refobjid && dep->refobjsubid == 0 && dep->deptype == DEPENDENCY_NORMAL)


			simple_heap_delete(catalogRelation, &depTuple->t_self);
	}

	systable_endscan(scan);
	heap_close(catalogRelation, RowExclusiveLock);
}


static void ATExecAddOf(Relation rel, const TypeName *ofTypename, LOCKMODE lockmode)
{
	Oid			relid = RelationGetRelid(rel);
	Type		typetuple;
	Oid			typeid;
	Relation	inheritsRelation, relationRelation;
	SysScanDesc scan;
	ScanKeyData key;
	AttrNumber	table_attno, type_attno;
	TupleDesc	typeTupleDesc, tableTupleDesc;
	ObjectAddress tableobj, typeobj;
	HeapTuple	classtuple;

	
	typetuple = typenameType(NULL, ofTypename, NULL);
	check_of_type(typetuple);
	typeid = HeapTupleGetOid(typetuple);

	
	inheritsRelation = heap_open(InheritsRelationId, AccessShareLock);
	ScanKeyInit(&key, Anum_pg_inherits_inhrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	scan = systable_beginscan(inheritsRelation, InheritsRelidSeqnoIndexId, true, NULL, 1, &key);
	if (HeapTupleIsValid(systable_getnext(scan)))
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("typed tables cannot inherit")));

	systable_endscan(scan);
	heap_close(inheritsRelation, AccessShareLock);

	
	typeTupleDesc = lookup_rowtype_tupdesc(typeid, -1);
	tableTupleDesc = RelationGetDescr(rel);
	table_attno = 1;
	for (type_attno = 1; type_attno <= typeTupleDesc->natts; type_attno++)
	{
		Form_pg_attribute type_attr, table_attr;
		const char *type_attname, *table_attname;

		
		type_attr = typeTupleDesc->attrs[type_attno - 1];
		if (type_attr->attisdropped)
			continue;
		type_attname = NameStr(type_attr->attname);

		
		do {
			if (table_attno > tableTupleDesc->natts)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table is missing column \"%s\"", type_attname)));


			table_attr = tableTupleDesc->attrs[table_attno++ - 1];
		} while (table_attr->attisdropped);
		table_attname = NameStr(table_attr->attname);

		
		if (strncmp(table_attname, type_attname, NAMEDATALEN) != 0)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table has column \"%s\" where type requires \"%s\"", table_attname, type_attname)));



		
		if (table_attr->atttypid != type_attr->atttypid || table_attr->atttypmod != type_attr->atttypmod || table_attr->attcollation != type_attr->attcollation)

			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table \"%s\" has different type for column \"%s\"", RelationGetRelationName(rel), type_attname)));


	}
	DecrTupleDescRefCount(typeTupleDesc);

	
	for (; table_attno <= tableTupleDesc->natts; table_attno++)
	{
		Form_pg_attribute table_attr = tableTupleDesc->attrs[table_attno - 1];

		if (!table_attr->attisdropped)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table has extra column \"%s\"", NameStr(table_attr->attname))));


	}

	
	if (rel->rd_rel->reloftype)
		drop_parent_dependency(relid, TypeRelationId, rel->rd_rel->reloftype);

	
	tableobj.classId = RelationRelationId;
	tableobj.objectId = relid;
	tableobj.objectSubId = 0;
	typeobj.classId = TypeRelationId;
	typeobj.objectId = typeid;
	typeobj.objectSubId = 0;
	recordDependencyOn(&tableobj, &typeobj, DEPENDENCY_NORMAL);

	
	relationRelation = heap_open(RelationRelationId, RowExclusiveLock);
	classtuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(classtuple))
		elog(ERROR, "cache lookup failed for relation %u", relid);
	((Form_pg_class) GETSTRUCT(classtuple))->reloftype = typeid;
	simple_heap_update(relationRelation, &classtuple->t_self, classtuple);
	CatalogUpdateIndexes(relationRelation, classtuple);

	InvokeObjectPostAlterHook(RelationRelationId, relid, 0);

	heap_freetuple(classtuple);
	heap_close(relationRelation, RowExclusiveLock);

	ReleaseSysCache(typetuple);
}


static void ATExecDropOf(Relation rel, LOCKMODE lockmode)
{
	Oid			relid = RelationGetRelid(rel);
	Relation	relationRelation;
	HeapTuple	tuple;

	if (!OidIsValid(rel->rd_rel->reloftype))
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a typed table", RelationGetRelationName(rel))));



	

	drop_parent_dependency(relid, TypeRelationId, rel->rd_rel->reloftype);

	
	relationRelation = heap_open(RelationRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relid);
	((Form_pg_class) GETSTRUCT(tuple))->reloftype = InvalidOid;
	simple_heap_update(relationRelation, &tuple->t_self, tuple);
	CatalogUpdateIndexes(relationRelation, tuple);

	InvokeObjectPostAlterHook(RelationRelationId, relid, 0);

	heap_freetuple(tuple);
	heap_close(relationRelation, RowExclusiveLock);
}


static void relation_mark_replica_identity(Relation rel, char ri_type, Oid indexOid, bool is_internal)

{
	Relation	pg_index;
	Relation	pg_class;
	HeapTuple	pg_class_tuple;
	HeapTuple	pg_index_tuple;
	Form_pg_class pg_class_form;
	Form_pg_index pg_index_form;

	ListCell   *index;

	
	pg_class = heap_open(RelationRelationId, RowExclusiveLock);
	pg_class_tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(RelationGetRelid(rel)));
	if (!HeapTupleIsValid(pg_class_tuple))
		elog(ERROR, "cache lookup failed for relation \"%s\"", RelationGetRelationName(rel));
	pg_class_form = (Form_pg_class) GETSTRUCT(pg_class_tuple);
	if (pg_class_form->relreplident != ri_type)
	{
		pg_class_form->relreplident = ri_type;
		simple_heap_update(pg_class, &pg_class_tuple->t_self, pg_class_tuple);
		CatalogUpdateIndexes(pg_class, pg_class_tuple);
	}
	heap_close(pg_class, RowExclusiveLock);
	heap_freetuple(pg_class_tuple);

	
	if (OidIsValid(indexOid))
	{
		Assert(ri_type == REPLICA_IDENTITY_INDEX);

		pg_index_tuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexOid));
		if (!HeapTupleIsValid(pg_index_tuple))
			elog(ERROR, "cache lookup failed for index %u", indexOid);
		pg_index_form = (Form_pg_index) GETSTRUCT(pg_index_tuple);

		if (pg_index_form->indisreplident)
		{
			ReleaseSysCache(pg_index_tuple);
			return;
		}
		ReleaseSysCache(pg_index_tuple);
	}

	
	pg_index = heap_open(IndexRelationId, RowExclusiveLock);
	foreach(index, RelationGetIndexList(rel))
	{
		Oid			thisIndexOid = lfirst_oid(index);
		bool		dirty = false;

		pg_index_tuple = SearchSysCacheCopy1(INDEXRELID, ObjectIdGetDatum(thisIndexOid));
		if (!HeapTupleIsValid(pg_index_tuple))
			elog(ERROR, "cache lookup failed for index %u", thisIndexOid);
		pg_index_form = (Form_pg_index) GETSTRUCT(pg_index_tuple);

		
		if (pg_index_form->indisreplident)
		{
			dirty = true;
			pg_index_form->indisreplident = false;
		}
		else if (thisIndexOid == indexOid)
		{
			dirty = true;
			pg_index_form->indisreplident = true;
		}

		if (dirty)
		{
			simple_heap_update(pg_index, &pg_index_tuple->t_self, pg_index_tuple);
			CatalogUpdateIndexes(pg_index, pg_index_tuple);
			InvokeObjectPostAlterHookArg(IndexRelationId, thisIndexOid, 0, InvalidOid, is_internal);
		}
		heap_freetuple(pg_index_tuple);
	}

	heap_close(pg_index, RowExclusiveLock);
}


static void ATExecReplicaIdentity(Relation rel, ReplicaIdentityStmt *stmt, LOCKMODE lockmode)
{
	Oid			indexOid;
	Relation	indexRel;
	int			key;

	if (stmt->identity_type == REPLICA_IDENTITY_DEFAULT)
	{
		relation_mark_replica_identity(rel, stmt->identity_type, InvalidOid, true);
		return;
	}
	else if (stmt->identity_type == REPLICA_IDENTITY_FULL)
	{
		relation_mark_replica_identity(rel, stmt->identity_type, InvalidOid, true);
		return;
	}
	else if (stmt->identity_type == REPLICA_IDENTITY_NOTHING)
	{
		relation_mark_replica_identity(rel, stmt->identity_type, InvalidOid, true);
		return;
	}
	else if (stmt->identity_type == REPLICA_IDENTITY_INDEX)
	{
		;
	}
	else elog(ERROR, "unexpected identity type %u", stmt->identity_type);


	
	indexOid = get_relname_relid(stmt->name, rel->rd_rel->relnamespace);
	if (!OidIsValid(indexOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("index \"%s\" for table \"%s\" does not exist", stmt->name, RelationGetRelationName(rel))));



	indexRel = index_open(indexOid, ShareLock);

	
	if (indexRel->rd_index == NULL || indexRel->rd_index->indrelid != RelationGetRelid(rel))
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not an index for table \"%s\"", RelationGetRelationName(indexRel), RelationGetRelationName(rel))));



	
	if (!indexRel->rd_am->amcanunique || !indexRel->rd_index->indisunique)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot use non-unique index \"%s\" as replica identity", RelationGetRelationName(indexRel))));


	
	if (!indexRel->rd_index->indimmediate)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use non-immediate index \"%s\" as replica identity", RelationGetRelationName(indexRel))));


	
	if (RelationGetIndexExpressions(indexRel) != NIL)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use expression index \"%s\" as replica identity", RelationGetRelationName(indexRel))));


	
	if (RelationGetIndexPredicate(indexRel) != NIL)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use partial index \"%s\" as replica identity", RelationGetRelationName(indexRel))));


	
	if (!IndexIsValid(indexRel->rd_index))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use invalid index \"%s\" as replica identity", RelationGetRelationName(indexRel))));



	
	for (key = 0; key < indexRel->rd_index->indnatts; key++)
	{
		int16 attno = indexRel->rd_index->indkey.values[key];
		Form_pg_attribute attr;

		
		if (attno <= 0 && attno != ObjectIdAttributeNumber)
			elog(ERROR, "internal column %u in unique index \"%s\"", attno, RelationGetRelationName(indexRel));

		attr = rel->rd_att->attrs[attno - 1];
		if (!attr->attnotnull)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" cannot be used as replica identity because column \"%s\" is nullable", RelationGetRelationName(indexRel), NameStr(attr->attname))));



	}

	
	relation_mark_replica_identity(rel, stmt->identity_type, indexOid, true);

	index_close(indexRel, NoLock);
}


static void ATExecGenericOptions(Relation rel, List *options)
{
	Relation	ftrel;
	ForeignServer *server;
	ForeignDataWrapper *fdw;
	HeapTuple	tuple;
	bool		isnull;
	Datum		repl_val[Natts_pg_foreign_table];
	bool		repl_null[Natts_pg_foreign_table];
	bool		repl_repl[Natts_pg_foreign_table];
	Datum		datum;
	Form_pg_foreign_table tableform;

	if (options == NIL)
		return;

	ftrel = heap_open(ForeignTableRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy1(FOREIGNTABLEREL, rel->rd_id);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("foreign table \"%s\" does not exist", RelationGetRelationName(rel))));


	tableform = (Form_pg_foreign_table) GETSTRUCT(tuple);
	server = GetForeignServer(tableform->ftserver);
	fdw = GetForeignDataWrapper(server->fdwid);

	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	
	datum = SysCacheGetAttr(FOREIGNTABLEREL, tuple, Anum_pg_foreign_table_ftoptions, &isnull);


	if (isnull)
		datum = PointerGetDatum(NULL);

	
	datum = transformGenericOptions(ForeignTableRelationId, datum, options, fdw->fdwvalidator);



	if (PointerIsValid(DatumGetPointer(datum)))
		repl_val[Anum_pg_foreign_table_ftoptions - 1] = datum;
	else repl_null[Anum_pg_foreign_table_ftoptions - 1] = true;

	repl_repl[Anum_pg_foreign_table_ftoptions - 1] = true;

	

	tuple = heap_modify_tuple(tuple, RelationGetDescr(ftrel), repl_val, repl_null, repl_repl);

	simple_heap_update(ftrel, &tuple->t_self, tuple);
	CatalogUpdateIndexes(ftrel, tuple);

	InvokeObjectPostAlterHook(ForeignTableRelationId, RelationGetRelid(rel), 0);

	heap_close(ftrel, RowExclusiveLock);

	heap_freetuple(tuple);
}


Oid AlterTableNamespace(AlterObjectSchemaStmt *stmt)
{
	Relation	rel;
	Oid			relid;
	Oid			oldNspOid;
	Oid			nspOid;
	RangeVar   *newrv;
	ObjectAddresses *objsMoved;

	relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock, stmt->missing_ok, false, RangeVarCallbackForAlterRelation, (void *) stmt);



	if (!OidIsValid(relid))
	{
		ereport(NOTICE, (errmsg("relation \"%s\" does not exist, skipping", stmt->relation->relname)));

		return InvalidOid;
	}

	rel = relation_open(relid, NoLock);

	oldNspOid = RelationGetNamespace(rel);

	
	if (rel->rd_rel->relkind == RELKIND_SEQUENCE)
	{
		Oid			tableId;
		int32		colId;

		if (sequenceIsOwned(relid, &tableId, &colId))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move an owned sequence into another schema"), errdetail("Sequence \"%s\" is linked to table \"%s\".", RelationGetRelationName(rel), get_rel_name(tableId))));




	}

	
	newrv = makeRangeVar(stmt->newschema, RelationGetRelationName(rel), -1);
	nspOid = RangeVarGetAndCheckCreationNamespace(newrv, NoLock, NULL);

	
	CheckSetNamespace(oldNspOid, nspOid, RelationRelationId, relid);

	objsMoved = new_object_addresses();
	AlterTableNamespaceInternal(rel, oldNspOid, nspOid, objsMoved);
	free_object_addresses(objsMoved);

	
	relation_close(rel, NoLock);

	return relid;
}


void AlterTableNamespaceInternal(Relation rel, Oid oldNspOid, Oid nspOid, ObjectAddresses *objsMoved)

{
	Relation	classRel;

	Assert(objsMoved != NULL);

	
	classRel = heap_open(RelationRelationId, RowExclusiveLock);

	AlterRelationNamespaceInternal(classRel, RelationGetRelid(rel), oldNspOid, nspOid, true, objsMoved);

	
	AlterTypeNamespaceInternal(rel->rd_rel->reltype, nspOid, false, false, objsMoved);

	
	if (rel->rd_rel->relkind == RELKIND_RELATION || rel->rd_rel->relkind == RELKIND_MATVIEW)
	{
		AlterIndexNamespaces(classRel, rel, oldNspOid, nspOid, objsMoved);
		AlterSeqNamespaces(classRel, rel, oldNspOid, nspOid, objsMoved, AccessExclusiveLock);
		AlterConstraintNamespaces(RelationGetRelid(rel), oldNspOid, nspOid, false, objsMoved);
	}

	heap_close(classRel, RowExclusiveLock);
}


void AlterRelationNamespaceInternal(Relation classRel, Oid relOid, Oid oldNspOid, Oid newNspOid, bool hasDependEntry, ObjectAddresses *objsMoved)



{
	HeapTuple	classTup;
	Form_pg_class classForm;
	ObjectAddress thisobj;

	classTup = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(relOid));
	if (!HeapTupleIsValid(classTup))
		elog(ERROR, "cache lookup failed for relation %u", relOid);
	classForm = (Form_pg_class) GETSTRUCT(classTup);

	Assert(classForm->relnamespace == oldNspOid);

	thisobj.classId = RelationRelationId;
	thisobj.objectId = relOid;
	thisobj.objectSubId = 0;

	
	if (!object_address_present(&thisobj, objsMoved))
	{
		
		if (get_relname_relid(NameStr(classForm->relname), newNspOid) != InvalidOid)
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists in schema \"%s\"", NameStr(classForm->relname), get_namespace_name(newNspOid))));




		
		classForm->relnamespace = newNspOid;

		simple_heap_update(classRel, &classTup->t_self, classTup);
		CatalogUpdateIndexes(classRel, classTup);

		
		if (hasDependEntry && changeDependencyFor(RelationRelationId, relOid, NamespaceRelationId, oldNspOid, newNspOid) != 1)




			elog(ERROR, "failed to change schema dependency for relation \"%s\"", NameStr(classForm->relname));

		add_exact_object_address(&thisobj, objsMoved);

		InvokeObjectPostAlterHook(RelationRelationId, relOid, 0);
	}

	heap_freetuple(classTup);
}


static void AlterIndexNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid, ObjectAddresses *objsMoved)

{
	List	   *indexList;
	ListCell   *l;

	indexList = RelationGetIndexList(rel);

	foreach(l, indexList)
	{
		Oid			indexOid = lfirst_oid(l);
		ObjectAddress thisobj;

		thisobj.classId = RelationRelationId;
		thisobj.objectId = indexOid;
		thisobj.objectSubId = 0;

		
		if (!object_address_present(&thisobj, objsMoved))
		{
			AlterRelationNamespaceInternal(classRel, indexOid, oldNspOid, newNspOid, false, objsMoved);

			add_exact_object_address(&thisobj, objsMoved);
		}
	}

	list_free(indexList);
}


static void AlterSeqNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid, ObjectAddresses *objsMoved, LOCKMODE lockmode)


{
	Relation	depRel;
	SysScanDesc scan;
	ScanKeyData key[2];
	HeapTuple	tup;

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	

	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend depForm = (Form_pg_depend) GETSTRUCT(tup);
		Relation	seqRel;

		
		if (depForm->refobjsubid == 0 || depForm->classid != RelationRelationId || depForm->objsubid != 0 || depForm->deptype != DEPENDENCY_AUTO)


			continue;

		
		seqRel = relation_open(depForm->objid, lockmode);

		
		if (RelationGetForm(seqRel)->relkind != RELKIND_SEQUENCE)
		{
			
			relation_close(seqRel, lockmode);
			continue;
		}

		
		AlterRelationNamespaceInternal(classRel, depForm->objid, oldNspOid, newNspOid, true, objsMoved);


		
		AlterTypeNamespaceInternal(RelationGetForm(seqRel)->reltype, newNspOid, false, false, objsMoved);

		
		relation_close(seqRel, NoLock);
	}

	systable_endscan(scan);

	relation_close(depRel, AccessShareLock);
}





void register_on_commit_action(Oid relid, OnCommitAction action)
{
	OnCommitItem *oc;
	MemoryContext oldcxt;

	
	if (action == ONCOMMIT_NOOP || action == ONCOMMIT_PRESERVE_ROWS)
		return;

	oldcxt = MemoryContextSwitchTo(CacheMemoryContext);

	oc = (OnCommitItem *) palloc(sizeof(OnCommitItem));
	oc->relid = relid;
	oc->oncommit = action;
	oc->creating_subid = GetCurrentSubTransactionId();
	oc->deleting_subid = InvalidSubTransactionId;

	on_commits = lcons(oc, on_commits);

	MemoryContextSwitchTo(oldcxt);
}


void remove_on_commit_action(Oid relid)
{
	ListCell   *l;

	foreach(l, on_commits)
	{
		OnCommitItem *oc = (OnCommitItem *) lfirst(l);

		if (oc->relid == relid)
		{
			oc->deleting_subid = GetCurrentSubTransactionId();
			break;
		}
	}
}


void PreCommit_on_commit_actions(void)
{
	ListCell   *l;
	List	   *oids_to_truncate = NIL;

	foreach(l, on_commits)
	{
		OnCommitItem *oc = (OnCommitItem *) lfirst(l);

		
		if (oc->deleting_subid != InvalidSubTransactionId)
			continue;

		switch (oc->oncommit)
		{
			case ONCOMMIT_NOOP:
			case ONCOMMIT_PRESERVE_ROWS:
				
				break;
			case ONCOMMIT_DELETE_ROWS:

				
				if (MyXactAccessedTempRel)
					oids_to_truncate = lappend_oid(oids_to_truncate, oc->relid);
				break;
			case ONCOMMIT_DROP:
				{
					ObjectAddress object;

					object.classId = RelationRelationId;
					object.objectId = oc->relid;
					object.objectSubId = 0;

					
					performDeletion(&object, DROP_CASCADE, PERFORM_DELETION_INTERNAL);

					
					Assert(oc->deleting_subid != InvalidSubTransactionId);
					break;
				}
		}
	}
	if (oids_to_truncate != NIL)
	{
		heap_truncate(oids_to_truncate);
		CommandCounterIncrement();		
	}
}


void AtEOXact_on_commit_actions(bool isCommit)
{
	ListCell   *cur_item;
	ListCell   *prev_item;

	prev_item = NULL;
	cur_item = list_head(on_commits);

	while (cur_item != NULL)
	{
		OnCommitItem *oc = (OnCommitItem *) lfirst(cur_item);

		if (isCommit ? oc->deleting_subid != InvalidSubTransactionId :
			oc->creating_subid != InvalidSubTransactionId)
		{
			
			on_commits = list_delete_cell(on_commits, cur_item, prev_item);
			pfree(oc);
			if (prev_item)
				cur_item = lnext(prev_item);
			else cur_item = list_head(on_commits);
		}
		else {
			
			oc->creating_subid = InvalidSubTransactionId;
			oc->deleting_subid = InvalidSubTransactionId;
			prev_item = cur_item;
			cur_item = lnext(prev_item);
		}
	}
}


void AtEOSubXact_on_commit_actions(bool isCommit, SubTransactionId mySubid, SubTransactionId parentSubid)

{
	ListCell   *cur_item;
	ListCell   *prev_item;

	prev_item = NULL;
	cur_item = list_head(on_commits);

	while (cur_item != NULL)
	{
		OnCommitItem *oc = (OnCommitItem *) lfirst(cur_item);

		if (!isCommit && oc->creating_subid == mySubid)
		{
			
			on_commits = list_delete_cell(on_commits, cur_item, prev_item);
			pfree(oc);
			if (prev_item)
				cur_item = lnext(prev_item);
			else cur_item = list_head(on_commits);
		}
		else {
			
			if (oc->creating_subid == mySubid)
				oc->creating_subid = parentSubid;
			if (oc->deleting_subid == mySubid)
				oc->deleting_subid = isCommit ? parentSubid : InvalidSubTransactionId;
			prev_item = cur_item;
			cur_item = lnext(prev_item);
		}
	}
}


void RangeVarCallbackOwnsTable(const RangeVar *relation, Oid relId, Oid oldRelId, void *arg)

{
	char		relkind;

	
	if (!OidIsValid(relId))
		return;

	
	relkind = get_rel_relkind(relId);
	if (!relkind)
		return;
	if (relkind != RELKIND_RELATION && relkind != RELKIND_TOASTVALUE && relkind != RELKIND_MATVIEW)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or materialized view", relation->relname)));


	
	if (!pg_class_ownercheck(relId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, relation->relname);
}


static void RangeVarCallbackForAlterRelation(const RangeVar *rv, Oid relid, Oid oldrelid, void *arg)

{
	Node	   *stmt = (Node *) arg;
	ObjectType	reltype;
	HeapTuple	tuple;
	Form_pg_class classform;
	AclResult	aclresult;
	char		relkind;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		return;					
	classform = (Form_pg_class) GETSTRUCT(tuple);
	relkind = classform->relkind;

	
	if (!pg_class_ownercheck(relid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, rv->relname);

	
	if (!allowSystemTableMods && IsSystemClass(relid, classform))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", rv->relname)));



	
	if (IsA(stmt, RenameStmt))
	{
		aclresult = pg_namespace_aclcheck(classform->relnamespace, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(classform->relnamespace));
		reltype = ((RenameStmt *) stmt)->renameType;
	}
	else if (IsA(stmt, AlterObjectSchemaStmt))
		reltype = ((AlterObjectSchemaStmt *) stmt)->objectType;

	else if (IsA(stmt, AlterTableStmt))
		reltype = ((AlterTableStmt *) stmt)->relkind;
	else {
		reltype = OBJECT_TABLE; 
		elog(ERROR, "unrecognized node type: %d", (int) nodeTag(stmt));
	}

	
	if (reltype == OBJECT_SEQUENCE && relkind != RELKIND_SEQUENCE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a sequence", rv->relname)));


	if (reltype == OBJECT_VIEW && relkind != RELKIND_VIEW)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a view", rv->relname)));


	if (reltype == OBJECT_MATVIEW && relkind != RELKIND_MATVIEW)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a materialized view", rv->relname)));


	if (reltype == OBJECT_FOREIGN_TABLE && relkind != RELKIND_FOREIGN_TABLE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a foreign table", rv->relname)));


	if (reltype == OBJECT_TYPE && relkind != RELKIND_COMPOSITE_TYPE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a composite type", rv->relname)));


	if (reltype == OBJECT_INDEX && relkind != RELKIND_INDEX && !IsA(stmt, RenameStmt))
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not an index", rv->relname)));


	
	if (reltype != OBJECT_TYPE && relkind == RELKIND_COMPOSITE_TYPE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a composite type", rv->relname), errhint("Use ALTER TYPE instead.")));



	
	if (IsA(stmt, AlterObjectSchemaStmt) && relkind != RELKIND_RELATION && relkind != RELKIND_VIEW && relkind != RELKIND_MATVIEW && relkind != RELKIND_SEQUENCE && relkind != RELKIND_FOREIGN_TABLE)




		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, materialized view, sequence, or foreign table", rv->relname)));



	ReleaseSysCache(tuple);
}
