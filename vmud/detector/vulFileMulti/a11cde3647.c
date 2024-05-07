





















































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
	Node	   *qual;			
	List	   *qualstate;		
} NewConstraint;


typedef struct NewColumnValue {
	AttrNumber	attnum;			
	Expr	   *expr;			
	ExprState  *exprstate;		
} NewColumnValue;


static void truncate_check_rel(Relation rel);
static List *MergeAttributes(List *schema, List *supers, bool istemp, List **supOids, List **supconstr, int *supOidCount);
static void MergeConstraintsIntoExisting(Relation child_rel, Relation parent_rel);
static void MergeAttributesIntoExisting(Relation child_rel, Relation parent_rel);
static void add_nonduplicate_constraint(Constraint *cdef, ConstrCheck *check, int *ncheck);
static bool change_varattnos_walker(Node *node, const AttrNumber *newattno);
static void StoreCatalogInheritance(Oid relationId, List *supers);
static void StoreCatalogInheritance1(Oid relationId, Oid parentOid, int16 seqNumber, Relation inhRelation);
static int	findAttrByName(const char *attributeName, List *schema);
static void setRelhassubclassInRelation(Oid relationId, bool relhassubclass);
static void AlterIndexNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid);
static void AlterSeqNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid, const char *newNspName);

static int transformColumnNameList(Oid relId, List *colList, int16 *attnums, Oid *atttypids);
static int transformFkeyGetPrimaryKey(Relation pkrel, Oid *indexOid, List **attnamelist, int16 *attnums, Oid *atttypids, Oid *opclasses);


static Oid transformFkeyCheckAttrs(Relation pkrel, int numattrs, int16 *attnums, Oid *opclasses);

static void validateForeignKeyConstraint(FkConstraint *fkconstraint, Relation rel, Relation pkrel);
static void createForeignKeyTriggers(Relation rel, FkConstraint *fkconstraint, Oid constrOid);
static char *fkMatchTypeToString(char match_type);
static void ATController(Relation rel, List *cmds, bool recurse);
static void ATPrepCmd(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse, bool recursing);
static void ATRewriteCatalogs(List **wqueue);
static void ATExecCmd(AlteredTableInfo *tab, Relation rel, AlterTableCmd *cmd);
static void ATRewriteTables(List **wqueue);
static void ATRewriteTable(AlteredTableInfo *tab, Oid OIDNewHeap);
static AlteredTableInfo *ATGetQueueEntry(List **wqueue, Relation rel);
static void ATSimplePermissions(Relation rel, bool allowView);
static void ATSimplePermissionsRelationOrIndex(Relation rel);
static void ATSimpleRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse);
static void ATOneLevelRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd);
static void find_composite_type_dependencies(Oid typeOid, const char *origTblName);
static void ATPrepAddColumn(List **wqueue, Relation rel, bool recurse, AlterTableCmd *cmd);
static void ATExecAddColumn(AlteredTableInfo *tab, Relation rel, ColumnDef *colDef);
static void add_column_datatype_dependency(Oid relid, int32 attnum, Oid typid);
static void ATExecDropNotNull(Relation rel, const char *colName);
static void ATExecSetNotNull(AlteredTableInfo *tab, Relation rel, const char *colName);
static void ATExecColumnDefault(Relation rel, const char *colName, Node *newDefault);
static void ATPrepSetStatistics(Relation rel, const char *colName, Node *flagValue);
static void ATExecSetStatistics(Relation rel, const char *colName, Node *newValue);
static void ATExecSetStorage(Relation rel, const char *colName, Node *newValue);
static void ATExecDropColumn(Relation rel, const char *colName, DropBehavior behavior, bool recurse, bool recursing);

static void ATExecAddIndex(AlteredTableInfo *tab, Relation rel, IndexStmt *stmt, bool is_rebuild);
static void ATExecAddConstraint(AlteredTableInfo *tab, Relation rel, Node *newConstraint);
static void ATAddForeignKeyConstraint(AlteredTableInfo *tab, Relation rel, FkConstraint *fkconstraint);
static void ATPrepDropConstraint(List **wqueue, Relation rel, bool recurse, AlterTableCmd *cmd);
static void ATExecDropConstraint(Relation rel, const char *constrName, DropBehavior behavior, bool quiet);
static void ATPrepAlterColumnType(List **wqueue, AlteredTableInfo *tab, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd);


static void ATExecAlterColumnType(AlteredTableInfo *tab, Relation rel, const char *colName, TypeName *typename);
static void ATPostAlterTypeCleanup(List **wqueue, AlteredTableInfo *tab);
static void ATPostAlterTypeParse(char *cmd, List **wqueue);
static void change_owner_recurse_to_sequences(Oid relationOid, Oid newOwnerId);
static void ATExecClusterOn(Relation rel, const char *indexName);
static void ATExecDropCluster(Relation rel);
static void ATPrepSetTableSpace(AlteredTableInfo *tab, Relation rel, char *tablespacename);
static void ATExecSetTableSpace(Oid tableOid, Oid newTableSpace);
static void ATExecSetRelOptions(Relation rel, List *defList, bool isReset);
static void ATExecEnableDisableTrigger(Relation rel, char *trigname, bool enable, bool skip_system);
static void ATExecAddInherit(Relation rel, RangeVar *parent);
static void ATExecDropInherit(Relation rel, RangeVar *parent);
static void copy_relation_data(Relation rel, SMgrRelation dst);
static void update_ri_trigger_args(Oid relid, const char *oldname, const char *newname, bool fk_scan, bool update_relname);






Oid DefineRelation(CreateStmt *stmt, char relkind)
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
	Datum		reloptions;
	ListCell   *listptr;
	AttrNumber	attnum;

	
	StrNCpy(relname, stmt->relation->relname, NAMEDATALEN);

	
	if (stmt->oncommit != ONCOMMIT_NOOP && !stmt->relation->istemp)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("ON COMMIT can only be used on temporary tables")));


	
	namespaceId = RangeVarGetCreationNamespace(stmt->relation);

	if (!IsBootstrapProcessingMode())
	{
		AclResult	aclresult;

		aclresult = pg_namespace_aclcheck(namespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(namespaceId));
	}

	
	if (stmt->tablespacename)
	{
		tablespaceId = get_tablespace_oid(stmt->tablespacename);
		if (!OidIsValid(tablespaceId))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("tablespace \"%s\" does not exist", stmt->tablespacename)));


	}
	else if (stmt->relation->istemp)
	{
		tablespaceId = GetTempTablespace();
	}
	else {
		tablespaceId = GetDefaultTablespace();
		
	}

	
	reloptions = transformRelOptions((Datum) 0, stmt->options, true, false);

	(void) heap_reloptions(relkind, reloptions, true);

	
	if (OidIsValid(tablespaceId))
	{
		AclResult	aclresult;

		aclresult = pg_tablespace_aclcheck(tablespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE, get_tablespace_name(tablespaceId));
	}

	
	schema = MergeAttributes(schema, stmt->inhRelations, stmt->relation->istemp, &inheritOids, &old_constraints, &parentOidCount);


	
	descriptor = BuildDescForRelation(schema);

	localHasOids = interpretOidsOption(stmt->options);
	descriptor->tdhasoid = (localHasOids || parentOidCount > 0);

	if (old_constraints || stmt->constraints)
	{
		ConstrCheck *check;
		int			ncheck = 0;

		
		check = (ConstrCheck *)
			palloc((list_length(old_constraints) + list_length(stmt->constraints)) * sizeof(ConstrCheck));
		
		foreach(listptr, old_constraints)
		{
			Constraint *cdef = (Constraint *) lfirst(listptr);

			if (cdef->contype == CONSTR_CHECK)
				add_nonduplicate_constraint(cdef, check, &ncheck);
		}
		
		foreach(listptr, stmt->constraints)
		{
			Constraint *cdef = (Constraint *) lfirst(listptr);

			if (cdef->contype == CONSTR_CHECK && cdef->cooked_expr != NULL)
				add_nonduplicate_constraint(cdef, check, &ncheck);
		}
		
		if (ncheck > 0)
		{
			if (descriptor->constr == NULL)
			{
				descriptor->constr = (TupleConstr *) palloc(sizeof(TupleConstr));
				descriptor->constr->defval = NULL;
				descriptor->constr->num_defval = 0;
				descriptor->constr->has_not_null = false;
			}
			descriptor->constr->num_check = ncheck;
			descriptor->constr->check = check;
		}
	}

	relationId = heap_create_with_catalog(relname, namespaceId, tablespaceId, InvalidOid, GetUserId(), descriptor, relkind, false, localHasOids, parentOidCount, stmt->oncommit, reloptions, allowSystemTableMods);












	StoreCatalogInheritance(relationId, inheritOids);

	
	CommandCounterIncrement();

	
	rel = relation_open(relationId, AccessExclusiveLock);

	
	rawDefaults = NIL;
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
		}
	}

	
	if (rawDefaults || stmt->constraints)
		AddRelationRawConstraints(rel, rawDefaults, stmt->constraints);

	
	relation_close(rel, NoLock);

	return relationId;
}


void RemoveRelation(const RangeVar *relation, DropBehavior behavior)
{
	Oid			relOid;
	ObjectAddress object;

	relOid = RangeVarGetRelid(relation, false);

	object.classId = RelationRelationId;
	object.objectId = relOid;
	object.objectSubId = 0;

	performDeletion(&object, behavior);
}


void ExecuteTruncate(TruncateStmt *stmt)
{
	List	   *rels = NIL;
	List	   *relids = NIL;
	ListCell   *cell;

	
	foreach(cell, stmt->relations)
	{
		RangeVar   *rv = lfirst(cell);
		Relation	rel;

		rel = heap_openrv(rv, AccessExclusiveLock);
		truncate_check_rel(rel);
		rels = lappend(rels, rel);
		relids = lappend_oid(relids, RelationGetRelid(rel));
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


	
	AfterTriggerCheckTruncate(relids);

	
	foreach(cell, rels)
	{
		Relation	rel = (Relation) lfirst(cell);
		Oid			heap_relid;
		Oid			toast_relid;

		
		setNewRelfilenode(rel);

		heap_relid = RelationGetRelid(rel);
		toast_relid = rel->rd_rel->reltoastrelid;

		heap_close(rel, NoLock);

		
		if (OidIsValid(toast_relid))
		{
			rel = relation_open(toast_relid, AccessExclusiveLock);
			setNewRelfilenode(rel);
			heap_close(rel, NoLock);
		}

		
		reindex_relation(heap_relid, true);
	}
}


static void truncate_check_rel(Relation rel)
{
	
	if (rel->rd_rel->relkind != RELKIND_RELATION)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table", RelationGetRelationName(rel))));



	
	if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(rel));

	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));



	
	if (rel->rd_rel->relisshared || rel->rd_isnailed)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot truncate system relation \"%s\"", RelationGetRelationName(rel))));



	
	if (isOtherTempNamespace(RelationGetNamespace(rel)))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot truncate temporary tables of other sessions")));

}


static List * MergeAttributes(List *schema, List *supers, bool istemp, List **supOids, List **supconstr, int *supOidCount)

{
	ListCell   *entry;
	List	   *inhSchema = NIL;
	List	   *parentOids = NIL;
	List	   *constraints = NIL;
	int			parentsWithOids = 0;
	bool		have_bogus_defaults = false;
	char	   *bogus_marker = "Bogus!";		
	int			child_attno;

	
	if (list_length(schema) > MaxHeapAttributeNumber)
		ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("tables can have at most %d columns", MaxHeapAttributeNumber)));



	
	foreach(entry, schema)
	{
		ColumnDef  *coldef = lfirst(entry);
		ListCell   *rest;

		for_each_cell(rest, lnext(entry))
		{
			ColumnDef  *restdef = lfirst(rest);

			if (strcmp(coldef->colname, restdef->colname) == 0)
				ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" duplicated", coldef->colname)));


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

		relation = heap_openrv(parent, AccessShareLock);

		if (relation->rd_rel->relkind != RELKIND_RELATION)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table", parent->relname)));


		
		if (!istemp && isTempNamespace(RelationGetNamespace(relation)))
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit from temporary relation \"%s\"", parent->relname)));



		
		if (!pg_class_ownercheck(RelationGetRelid(relation), GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(relation));

		
		if (list_member_oid(parentOids, RelationGetRelid(relation)))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("inherited relation \"%s\" duplicated", parent->relname)));



		parentOids = lappend_oid(parentOids, RelationGetRelid(relation));

		if (relation->rd_rel->relhasoids)
			parentsWithOids++;

		tupleDesc = RelationGetDescr(relation);
		constr = tupleDesc->constr;

		
		newattno = (AttrNumber *)
			palloc(tupleDesc->natts * sizeof(AttrNumber));

		for (parent_attno = 1; parent_attno <= tupleDesc->natts;
			 parent_attno++)
		{
			Form_pg_attribute attribute = tupleDesc->attrs[parent_attno - 1];
			char	   *attributeName = NameStr(attribute->attname);
			int			exist_attno;
			ColumnDef  *def;

			
			if (attribute->attisdropped)
			{
				
				newattno[parent_attno - 1] = 0;
				continue;
			}

			
			exist_attno = findAttrByName(attributeName, inhSchema);
			if (exist_attno > 0)
			{
				Oid		defTypeId;
				int32	deftypmod;

				
				ereport(NOTICE, (errmsg("merging multiple inherited definitions of column \"%s\"", attributeName)));

				def = (ColumnDef *) list_nth(inhSchema, exist_attno - 1);
				defTypeId = typenameTypeId(NULL, def->typename);
				deftypmod = typenameTypeMod(NULL, def->typename, defTypeId);
				if (defTypeId != attribute->atttypid || deftypmod != attribute->atttypmod)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("inherited column \"%s\" has a type conflict", attributeName), errdetail("%s versus %s", TypeNameToString(def->typename), format_type_be(attribute->atttypid))));





				def->inhcount++;
				
				def->is_not_null |= attribute->attnotnull;
				
				newattno[parent_attno - 1] = exist_attno;
			}
			else {
				
				def = makeNode(ColumnDef);
				def->colname = pstrdup(attributeName);
				def->typename = makeTypeNameFromOid(attribute->atttypid, attribute->atttypmod);
				def->inhcount = 1;
				def->is_local = false;
				def->is_not_null = attribute->attnotnull;
				def->raw_default = NULL;
				def->cooked_default = NULL;
				def->constraints = NIL;
				inhSchema = lappend(inhSchema, def);
				newattno[parent_attno - 1] = ++child_attno;
			}

			
			if (attribute->atthasdef)
			{
				char	   *this_default = NULL;
				AttrDefault *attrdef;
				int			i;

				
				Assert(constr != NULL);
				attrdef = constr->defval;
				for (i = 0; i < constr->num_defval; i++)
				{
					if (attrdef[i].adnum == parent_attno)
					{
						this_default = attrdef[i].adbin;
						break;
					}
				}
				Assert(this_default != NULL);

				
				Assert(def->raw_default == NULL);
				if (def->cooked_default == NULL)
					def->cooked_default = pstrdup(this_default);
				else if (strcmp(def->cooked_default, this_default) != 0)
				{
					def->cooked_default = bogus_marker;
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
				Constraint *cdef = makeNode(Constraint);
				Node	   *expr;

				cdef->contype = CONSTR_CHECK;
				cdef->name = pstrdup(check[i].ccname);
				cdef->raw_expr = NULL;
				
				expr = stringToNode(check[i].ccbin);
				change_varattnos_of_a_node(expr, newattno);
				cdef->cooked_expr = nodeToString(expr);
				constraints = lappend(constraints, cdef);
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
				Oid	defTypeId, newTypeId;
				int32 deftypmod, newtypmod;

				
				ereport(NOTICE, (errmsg("merging column \"%s\" with inherited definition", attributeName)));

				def = (ColumnDef *) list_nth(inhSchema, exist_attno - 1);
				defTypeId = typenameTypeId(NULL, def->typename);
				deftypmod = typenameTypeMod(NULL, def->typename, defTypeId);
				newTypeId = typenameTypeId(NULL, newdef->typename);
				newtypmod = typenameTypeMod(NULL, newdef->typename, newTypeId);
				if (defTypeId != newTypeId || deftypmod != newtypmod)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("column \"%s\" has a type conflict", attributeName), errdetail("%s versus %s", TypeNameToString(def->typename), TypeNameToString(newdef->typename))));





				
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

			if (def->cooked_default == bogus_marker)
				ereport(ERROR, (errcode(ERRCODE_INVALID_COLUMN_DEFINITION), errmsg("column \"%s\" inherits conflicting default values", def->colname), errhint("To resolve the conflict, specify a default explicitly.")));



		}
	}

	*supOids = parentOids;
	*supconstr = constraints;
	*supOidCount = parentsWithOids;
	return schema;
}



static void add_nonduplicate_constraint(Constraint *cdef, ConstrCheck *check, int *ncheck)
{
	int			i;

	
	Assert(cdef->contype == CONSTR_CHECK);
	Assert(cdef->name != NULL);
	Assert(cdef->raw_expr == NULL && cdef->cooked_expr != NULL);

	for (i = 0; i < *ncheck; i++)
	{
		if (strcmp(check[i].ccname, cdef->name) != 0)
			continue;
		if (strcmp(check[i].ccbin, cdef->cooked_expr) == 0)
			return;				
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("duplicate check constraint name \"%s\"", cdef->name)));


	}
	
	check[*ncheck].ccname = cdef->name;
	check[*ncheck].ccbin = pstrdup(cdef->cooked_expr);
	(*ncheck)++;
}



void change_varattnos_of_a_node(Node *node, const AttrNumber *newattno)
{
	
	(void) change_varattnos_walker(node, newattno);
}

static bool change_varattnos_walker(Node *node, const AttrNumber *newattno)
{
	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		Var		   *var = (Var *) node;

		if (var->varlevelsup == 0 && var->varno == 1 && var->varattno > 0)
		{
			
			Assert(newattno[var->varattno - 1] > 0);
			var->varattno = newattno[var->varattno - 1];
		}
		return false;
	}
	return expression_tree_walker(node, change_varattnos_walker, (void *) newattno);
}


AttrNumber * varattnos_map(TupleDesc old, TupleDesc new)
{
	AttrNumber *attmap;
	int			i, j;

	attmap = (AttrNumber *) palloc0(sizeof(AttrNumber) * old->natts);
	for (i = 1; i <= old->natts; i++)
	{
		if (old->attrs[i - 1]->attisdropped)
			continue;			

		for (j = 1; j <= new->natts; j++)
		{
			if (strcmp(NameStr(old->attrs[i - 1]->attname), NameStr(new->attrs[j - 1]->attname)) == 0)
			{
				attmap[i - 1] = j;
				break;
			}
		}
	}
	return attmap;
}


AttrNumber * varattnos_map_schema(TupleDesc old, List *schema)
{
	AttrNumber *attmap;
	int			i;

	attmap = (AttrNumber *) palloc0(sizeof(AttrNumber) * old->natts);
	for (i = 1; i <= old->natts; i++)
	{
		if (old->attrs[i - 1]->attisdropped)
			continue;			

		attmap[i - 1] = findAttrByName(NameStr(old->attrs[i - 1]->attname), schema);
	}
	return attmap;
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
	Datum		datum[Natts_pg_inherits];
	char		nullarr[Natts_pg_inherits];
	ObjectAddress childobject, parentobject;
	HeapTuple	tuple;

	
	datum[0] = ObjectIdGetDatum(relationId);	
	datum[1] = ObjectIdGetDatum(parentOid);		
	datum[2] = Int16GetDatum(seqNumber);		

	nullarr[0] = ' ';
	nullarr[1] = ' ';
	nullarr[2] = ' ';

	tuple = heap_formtuple(desc, datum, nullarr);

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

	
	setRelhassubclassInRelation(parentOid, true);
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


static void setRelhassubclassInRelation(Oid relationId, bool relhassubclass)
{
	Relation	relationRelation;
	HeapTuple	tuple;
	Form_pg_class classtuple;

	
	relationRelation = heap_open(RelationRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(relationId), 0, 0, 0);

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



void renameatt(Oid myrelid, const char *oldattname, const char *newattname, bool recurse, bool recursing)




{
	Relation	targetrelation;
	Relation	attrelation;
	HeapTuple	atttup;
	Form_pg_attribute attform;
	int			attnum;
	List	   *indexoidlist;
	ListCell   *indexoidscan;

	
	targetrelation = relation_open(myrelid, AccessExclusiveLock);

	
	if (!pg_class_ownercheck(myrelid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(targetrelation));
	if (!allowSystemTableMods && IsSystemRelation(targetrelation))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(targetrelation))));



	
	if (recurse)
	{
		ListCell   *child;
		List	   *children;

		
		children = find_all_inheritors(myrelid);

		
		foreach(child, children)
		{
			Oid			childrelid = lfirst_oid(child);

			if (childrelid == myrelid)
				continue;
			
			renameatt(childrelid, oldattname, newattname, false, true);
		}
	}
	else {
		
		if (!recursing && find_inheritance_children(myrelid) != NIL)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("inherited column \"%s\" must be renamed in child tables too", oldattname)));


	}

	attrelation = heap_open(AttributeRelationId, RowExclusiveLock);

	atttup = SearchSysCacheCopyAttName(myrelid, oldattname);
	if (!HeapTupleIsValid(atttup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" does not exist", oldattname)));


	attform = (Form_pg_attribute) GETSTRUCT(atttup);

	attnum = attform->attnum;
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rename system column \"%s\"", oldattname)));



	
	if (attform->attinhcount > 0 && !recursing)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot rename inherited column \"%s\"", oldattname)));



	
	
	if (SearchSysCacheExists(ATTNAME, ObjectIdGetDatum(myrelid), PointerGetDatum(newattname), 0, 0))


		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" of relation \"%s\" already exists", newattname, RelationGetRelationName(targetrelation))));



	namestrcpy(&(attform->attname), newattname);

	simple_heap_update(attrelation, &atttup->t_self, atttup);

	
	CatalogUpdateIndexes(attrelation, atttup);

	heap_freetuple(atttup);

	
	indexoidlist = RelationGetIndexList(targetrelation);

	foreach(indexoidscan, indexoidlist)
	{
		Oid			indexoid = lfirst_oid(indexoidscan);
		HeapTuple	indextup;
		Form_pg_index indexform;
		int			i;

		
		indextup = SearchSysCache(INDEXRELID, ObjectIdGetDatum(indexoid), 0, 0, 0);

		if (!HeapTupleIsValid(indextup))
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		indexform = (Form_pg_index) GETSTRUCT(indextup);

		for (i = 0; i < indexform->indnatts; i++)
		{
			if (attnum != indexform->indkey.values[i])
				continue;

			
			atttup = SearchSysCacheCopy(ATTNUM, ObjectIdGetDatum(indexoid), Int16GetDatum(i + 1), 0, 0);


			if (!HeapTupleIsValid(atttup))
				continue;		

			
			namestrcpy(&(((Form_pg_attribute) GETSTRUCT(atttup))->attname), newattname);

			simple_heap_update(attrelation, &atttup->t_self, atttup);

			
			CatalogUpdateIndexes(attrelation, atttup);

			heap_freetuple(atttup);
		}

		ReleaseSysCache(indextup);
	}

	list_free(indexoidlist);

	heap_close(attrelation, RowExclusiveLock);

	
	if (targetrelation->rd_rel->reltriggers > 0)
	{
		
		update_ri_trigger_args(RelationGetRelid(targetrelation), oldattname, newattname, false, false);

		
		update_ri_trigger_args(RelationGetRelid(targetrelation), oldattname, newattname, true, false);

	}

	relation_close(targetrelation, NoLock);		
}


void renamerel(Oid myrelid, const char *newrelname)
{
	Relation	targetrelation;
	Relation	relrelation;	
	HeapTuple	reltup;
	Oid			namespaceId;
	char	   *oldrelname;
	char		relkind;
	bool		relhastriggers;

	
	targetrelation = relation_open(myrelid, AccessExclusiveLock);

	oldrelname = pstrdup(RelationGetRelationName(targetrelation));
	namespaceId = RelationGetNamespace(targetrelation);

	if (!allowSystemTableMods && IsSystemRelation(targetrelation))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(targetrelation))));



	relkind = targetrelation->rd_rel->relkind;
	relhastriggers = (targetrelation->rd_rel->reltriggers > 0);

	
	relrelation = heap_open(RelationRelationId, RowExclusiveLock);

	reltup = SearchSysCacheCopy(RELOID, PointerGetDatum(myrelid), 0, 0, 0);

	if (!HeapTupleIsValid(reltup))		
		elog(ERROR, "cache lookup failed for relation %u", myrelid);

	if (get_relname_relid(newrelname, namespaceId) != InvalidOid)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists", newrelname)));



	
	namestrcpy(&(((Form_pg_class) GETSTRUCT(reltup))->relname), newrelname);

	simple_heap_update(relrelation, &reltup->t_self, reltup);

	
	CatalogUpdateIndexes(relrelation, reltup);

	heap_freetuple(reltup);
	heap_close(relrelation, RowExclusiveLock);

	
	if (relkind != RELKIND_INDEX)
		TypeRename(oldrelname, namespaceId, newrelname);

	
	if (relhastriggers)
	{
		
		update_ri_trigger_args(myrelid, oldrelname, newrelname, false, true);


		
		update_ri_trigger_args(myrelid, oldrelname, newrelname, true, true);


	}

	
	relation_close(targetrelation, NoLock);
}


static void update_ri_trigger_args(Oid relid, const char *oldname, const char *newname, bool fk_scan, bool update_relname)




{
	Relation	tgrel;
	ScanKeyData skey[1];
	SysScanDesc trigscan;
	HeapTuple	tuple;
	Datum		values[Natts_pg_trigger];
	char		nulls[Natts_pg_trigger];
	char		replaces[Natts_pg_trigger];

	tgrel = heap_open(TriggerRelationId, RowExclusiveLock);
	if (fk_scan)
	{
		ScanKeyInit(&skey[0], Anum_pg_trigger_tgconstrrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


		trigscan = systable_beginscan(tgrel, TriggerConstrRelidIndexId, true, SnapshotNow, 1, skey);

	}
	else {
		ScanKeyInit(&skey[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


		trigscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, SnapshotNow, 1, skey);

	}

	while ((tuple = systable_getnext(trigscan)) != NULL)
	{
		Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(tuple);
		bytea	   *val;
		bytea	   *newtgargs;
		bool		isnull;
		int			tg_type;
		bool		examine_pk;
		bool		changed;
		int			tgnargs;
		int			i;
		int			newlen;
		const char *arga[RI_MAX_ARGUMENTS];
		const char *argp;

		tg_type = RI_FKey_trigger_type(pg_trigger->tgfoid);
		if (tg_type == RI_TRIGGER_NONE)
		{
			
			continue;
		}

		
		tgnargs = pg_trigger->tgnargs;
		val = DatumGetByteaP(fastgetattr(tuple, Anum_pg_trigger_tgargs, tgrel->rd_att, &isnull));

		if (isnull || tgnargs < RI_FIRST_ATTNAME_ARGNO || tgnargs > RI_MAX_ARGUMENTS)
		{
			
			continue;
		}
		argp = (const char *) VARDATA(val);
		for (i = 0; i < tgnargs; i++)
		{
			arga[i] = argp;
			argp += strlen(argp) + 1;
		}

		
		examine_pk = (tg_type == RI_TRIGGER_PK) == (!fk_scan);

		changed = false;
		if (update_relname)
		{
			
			i = examine_pk ? RI_PK_RELNAME_ARGNO : RI_FK_RELNAME_ARGNO;
			if (strcmp(arga[i], oldname) == 0)
			{
				arga[i] = newname;
				changed = true;
			}
		}
		else {
			
			i = examine_pk ? RI_FIRST_ATTNAME_ARGNO + RI_KEYPAIR_PK_IDX :
				RI_FIRST_ATTNAME_ARGNO + RI_KEYPAIR_FK_IDX;
			for (; i < tgnargs; i += 2)
			{
				if (strcmp(arga[i], oldname) == 0)
				{
					arga[i] = newname;
					changed = true;
				}
			}
		}

		if (!changed)
		{
			
			continue;
		}

		
		newlen = VARHDRSZ;
		for (i = 0; i < tgnargs; i++)
			newlen += strlen(arga[i]) + 1;
		newtgargs = (bytea *) palloc(newlen);
		VARATT_SIZEP(newtgargs) = newlen;
		newlen = VARHDRSZ;
		for (i = 0; i < tgnargs; i++)
		{
			strcpy(((char *) newtgargs) + newlen, arga[i]);
			newlen += strlen(arga[i]) + 1;
		}

		
		for (i = 0; i < Natts_pg_trigger; i++)
		{
			values[i] = (Datum) 0;
			replaces[i] = ' ';
			nulls[i] = ' ';
		}
		values[Anum_pg_trigger_tgargs - 1] = PointerGetDatum(newtgargs);
		replaces[Anum_pg_trigger_tgargs - 1] = 'r';

		tuple = heap_modifytuple(tuple, RelationGetDescr(tgrel), values, nulls, replaces);

		
		simple_heap_update(tgrel, &tuple->t_self, tuple);

		CatalogUpdateIndexes(tgrel, tuple);

		
		pg_trigger = (Form_pg_trigger) GETSTRUCT(tuple);
		if (pg_trigger->tgrelid != relid)
			CacheInvalidateRelcacheByRelid(pg_trigger->tgrelid);

		
		pfree(newtgargs);
		heap_freetuple(tuple);
	}

	systable_endscan(trigscan);

	heap_close(tgrel, RowExclusiveLock);

	
	CommandCounterIncrement();
}


void AlterTable(AlterTableStmt *stmt)
{
	ATController(relation_openrv(stmt->relation, AccessExclusiveLock), stmt->cmds, interpretInhOption(stmt->relation->inhOpt));

}


void AlterTableInternal(Oid relid, List *cmds, bool recurse)
{
	ATController(relation_open(relid, AccessExclusiveLock), cmds, recurse);

}

static void ATController(Relation rel, List *cmds, bool recurse)
{
	List	   *wqueue = NIL;
	ListCell   *lcmd;

	
	foreach(lcmd, cmds)
	{
		AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);

		ATPrepCmd(&wqueue, rel, cmd, recurse, false);
	}

	
	relation_close(rel, NoLock);

	
	ATRewriteCatalogs(&wqueue);

	
	ATRewriteTables(&wqueue);
}


static void ATPrepCmd(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse, bool recursing)

{
	AlteredTableInfo *tab;
	int			pass;

	
	tab = ATGetQueueEntry(wqueue, rel);

	
	cmd = copyObject(cmd);

	
	switch (cmd->subtype)
	{
		case AT_AddColumn:		
			ATSimplePermissions(rel, false);
			
			ATPrepAddColumn(wqueue, rel, recurse, cmd);
			pass = AT_PASS_ADD_COL;
			break;
		case AT_ColumnDefault:	

			
			ATSimplePermissions(rel, true);
			ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			pass = cmd->def ? AT_PASS_ADD_CONSTR : AT_PASS_DROP;
			break;
		case AT_DropNotNull:	
			ATSimplePermissions(rel, false);
			ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			pass = AT_PASS_DROP;
			break;
		case AT_SetNotNull:		
			ATSimplePermissions(rel, false);
			ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			pass = AT_PASS_ADD_CONSTR;
			break;
		case AT_SetStatistics:	
			ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			ATPrepSetStatistics(rel, cmd->name, cmd->def);
			pass = AT_PASS_COL_ATTRS;
			break;
		case AT_SetStorage:		
			ATSimplePermissions(rel, false);
			ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			pass = AT_PASS_COL_ATTRS;
			break;
		case AT_DropColumn:		
			ATSimplePermissions(rel, false);
			
			
			if (recurse)
				cmd->subtype = AT_DropColumnRecurse;
			pass = AT_PASS_DROP;
			break;
		case AT_AddIndex:		
			ATSimplePermissions(rel, false);
			
			
			pass = AT_PASS_ADD_INDEX;
			break;
		case AT_AddConstraint:	
			ATSimplePermissions(rel, false);

			
			if (IsA(cmd->def, Constraint))
				ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			pass = AT_PASS_ADD_CONSTR;
			break;
		case AT_DropConstraint:	
			ATSimplePermissions(rel, false);
			
			ATPrepDropConstraint(wqueue, rel, recurse, cmd);
			pass = AT_PASS_DROP;
			break;
		case AT_DropConstraintQuietly:	
			ATSimplePermissions(rel, false);
			ATSimpleRecursion(wqueue, rel, cmd, recurse);
			
			pass = AT_PASS_DROP;
			break;
		case AT_AlterColumnType:		
			ATSimplePermissions(rel, false);
			
			ATPrepAlterColumnType(wqueue, tab, rel, recurse, recursing, cmd);
			pass = AT_PASS_ALTER_TYPE;
			break;
		case AT_ChangeOwner:	
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_ClusterOn:		
		case AT_DropCluster:	
			ATSimplePermissions(rel, false);
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_DropOids:		
			ATSimplePermissions(rel, false);
			
			if (rel->rd_rel->relhasoids)
			{
				AlterTableCmd *dropCmd = makeNode(AlterTableCmd);

				dropCmd->subtype = AT_DropColumn;
				dropCmd->name = pstrdup("oid");
				dropCmd->behavior = cmd->behavior;
				ATPrepCmd(wqueue, rel, dropCmd, recurse, false);
			}
			pass = AT_PASS_DROP;
			break;
		case AT_SetTableSpace:	
			ATSimplePermissionsRelationOrIndex(rel);
			
			ATPrepSetTableSpace(tab, rel, cmd->name);
			pass = AT_PASS_MISC;	
			break;
		case AT_SetRelOptions:	
		case AT_ResetRelOptions:		
			ATSimplePermissionsRelationOrIndex(rel);
			
			
			pass = AT_PASS_MISC;
			break;
		case AT_EnableTrig:		
		case AT_EnableTrigAll:
		case AT_EnableTrigUser:
		case AT_DisableTrig:	
		case AT_DisableTrigAll:
		case AT_DisableTrigUser:
		case AT_AddInherit:		
		case AT_DropInherit:
			ATSimplePermissions(rel, false);
			
			
			pass = AT_PASS_MISC;
			break;
		default:				
			elog(ERROR, "unrecognized alter table type: %d", (int) cmd->subtype);
			pass = 0;			
			break;
	}

	
	tab->subcmds[pass] = lappend(tab->subcmds[pass], cmd);
}


static void ATRewriteCatalogs(List **wqueue)
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
				ATExecCmd(tab, rel, (AlterTableCmd *) lfirst(lcmd));

			
			if (pass == AT_PASS_ALTER_TYPE)
				ATPostAlterTypeCleanup(wqueue, tab);

			relation_close(rel, NoLock);
		}
	}

	
	foreach(ltab, *wqueue)
	{
		AlteredTableInfo *tab = (AlteredTableInfo *) lfirst(ltab);

		if (tab->relkind == RELKIND_RELATION && (tab->subcmds[AT_PASS_ADD_COL] || tab->subcmds[AT_PASS_ALTER_TYPE] || tab->subcmds[AT_PASS_COL_ATTRS]))


			AlterTableCreateToastTable(tab->relid);
	}
}


static void ATExecCmd(AlteredTableInfo *tab, Relation rel, AlterTableCmd *cmd)
{
	switch (cmd->subtype)
	{
		case AT_AddColumn:		
			ATExecAddColumn(tab, rel, (ColumnDef *) cmd->def);
			break;
		case AT_ColumnDefault:	
			ATExecColumnDefault(rel, cmd->name, cmd->def);
			break;
		case AT_DropNotNull:	
			ATExecDropNotNull(rel, cmd->name);
			break;
		case AT_SetNotNull:		
			ATExecSetNotNull(tab, rel, cmd->name);
			break;
		case AT_SetStatistics:	
			ATExecSetStatistics(rel, cmd->name, cmd->def);
			break;
		case AT_SetStorage:		
			ATExecSetStorage(rel, cmd->name, cmd->def);
			break;
		case AT_DropColumn:		
			ATExecDropColumn(rel, cmd->name, cmd->behavior, false, false);
			break;
		case AT_DropColumnRecurse:		
			ATExecDropColumn(rel, cmd->name, cmd->behavior, true, false);
			break;
		case AT_AddIndex:		
			ATExecAddIndex(tab, rel, (IndexStmt *) cmd->def, false);
			break;
		case AT_ReAddIndex:		
			ATExecAddIndex(tab, rel, (IndexStmt *) cmd->def, true);
			break;
		case AT_AddConstraint:	
			ATExecAddConstraint(tab, rel, cmd->def);
			break;
		case AT_DropConstraint:	
			ATExecDropConstraint(rel, cmd->name, cmd->behavior, false);
			break;
		case AT_DropConstraintQuietly:	
			ATExecDropConstraint(rel, cmd->name, cmd->behavior, true);
			break;
		case AT_AlterColumnType:		
			ATExecAlterColumnType(tab, rel, cmd->name, (TypeName *) cmd->def);
			break;
		case AT_ChangeOwner:	
			ATExecChangeOwner(RelationGetRelid(rel), get_roleid_checked(cmd->name), false);

			break;
		case AT_ClusterOn:		
			ATExecClusterOn(rel, cmd->name);
			break;
		case AT_DropCluster:	
			ATExecDropCluster(rel);
			break;
		case AT_DropOids:		

			
			break;
		case AT_SetTableSpace:	

			
			break;
		case AT_SetRelOptions:	
			ATExecSetRelOptions(rel, (List *) cmd->def, false);
			break;
		case AT_ResetRelOptions:		
			ATExecSetRelOptions(rel, (List *) cmd->def, true);
			break;
		case AT_EnableTrig:		
			ATExecEnableDisableTrigger(rel, cmd->name, true, false);
			break;
		case AT_DisableTrig:	
			ATExecEnableDisableTrigger(rel, cmd->name, false, false);
			break;
		case AT_EnableTrigAll:	
			ATExecEnableDisableTrigger(rel, NULL, true, false);
			break;
		case AT_DisableTrigAll:	
			ATExecEnableDisableTrigger(rel, NULL, false, false);
			break;
		case AT_EnableTrigUser:	
			ATExecEnableDisableTrigger(rel, NULL, true, true);
			break;
		case AT_DisableTrigUser:		
			ATExecEnableDisableTrigger(rel, NULL, false, true);
			break;
		case AT_AddInherit:
			ATExecAddInherit(rel, (RangeVar *) cmd->def);
			break;
		case AT_DropInherit:
			ATExecDropInherit(rel, (RangeVar *) cmd->def);
			break;
		default:				
			elog(ERROR, "unrecognized alter table type: %d", (int) cmd->subtype);
			break;
	}

	
	CommandCounterIncrement();
}


static void ATRewriteTables(List **wqueue)
{
	ListCell   *ltab;

	
	foreach(ltab, *wqueue)
	{
		AlteredTableInfo *tab = (AlteredTableInfo *) lfirst(ltab);

		
		if (tab->newvals != NIL)
		{
			
			Oid			OIDNewHeap;
			char		NewHeapName[NAMEDATALEN];
			Oid			NewTableSpace;
			Relation	OldHeap;
			ObjectAddress object;

			OldHeap = heap_open(tab->relid, NoLock);

			
			if (OldHeap->rd_rel->relisshared || OldHeap->rd_isnailed)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rewrite system relation \"%s\"", RelationGetRelationName(OldHeap))));



			
			if (isOtherTempNamespace(RelationGetNamespace(OldHeap)))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot rewrite temporary tables of other sessions")));


			
			if (tab->newTableSpace)
				NewTableSpace = tab->newTableSpace;
			else NewTableSpace = OldHeap->rd_rel->reltablespace;

			heap_close(OldHeap, NoLock);

			
			snprintf(NewHeapName, sizeof(NewHeapName), "pg_temp_%u", tab->relid);

			OIDNewHeap = make_new_heap(tab->relid, NewHeapName, NewTableSpace);

			
			ATRewriteTable(tab, OIDNewHeap);

			
			swap_relation_files(tab->relid, OIDNewHeap);

			CommandCounterIncrement();

			
			object.classId = RelationRelationId;
			object.objectId = OIDNewHeap;
			object.objectSubId = 0;

			
			performDeletion(&object, DROP_RESTRICT);
			

			
			reindex_relation(tab->relid, false);
		}
		else {
			
			if (tab->constraints != NIL || tab->new_notnull)
				ATRewriteTable(tab, InvalidOid);

			
			if (tab->newTableSpace)
				ATExecSetTableSpace(tab->relid, tab->newTableSpace);
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
				FkConstraint *fkconstraint = (FkConstraint *) con->qual;
				Relation	refrel;

				if (rel == NULL)
				{
					
					rel = heap_open(tab->relid, NoLock);
				}

				refrel = heap_open(con->refrelid, RowShareLock);

				validateForeignKeyConstraint(fkconstraint, rel, refrel);

				heap_close(refrel, NoLock);
			}
		}

		if (rel)
			heap_close(rel, NoLock);
	}
}


static void ATRewriteTable(AlteredTableInfo *tab, Oid OIDNewHeap)
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

	
	oldrel = heap_open(tab->relid, NoLock);
	oldTupDesc = tab->oldDesc;
	newTupDesc = RelationGetDescr(oldrel);		

	if (OidIsValid(OIDNewHeap))
		newrel = heap_open(OIDNewHeap, AccessExclusiveLock);
	else newrel = NULL;

	
	if (newrel)
		find_composite_type_dependencies(oldrel->rd_rel->reltype, RelationGetRelationName(oldrel));

	

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

		needscan = true;

		ex->exprstate = ExecPrepareExpr((Expr *) ex->expr, estate);
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

	if (needscan)
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

		
		scan = heap_beginscan(oldrel, SnapshotNow, 0, NULL);

		
		oldCxt = MemoryContextSwitchTo(GetPerTupleMemoryContext(estate));

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			if (newrel)
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
			}

			
			ExecStoreTuple(tuple, newslot, InvalidBuffer, false);
			econtext->ecxt_scantuple = newslot;

			foreach(l, notnull_attrs)
			{
				int			attn = lfirst_int(l);

				if (heap_attisnull(tuple, attn + 1))
					ereport(ERROR, (errcode(ERRCODE_NOT_NULL_VIOLATION), errmsg("column \"%s\" contains null values", NameStr(newTupDesc->attrs[attn]->attname))));


			}

			foreach(l, tab->constraints)
			{
				NewConstraint *con = lfirst(l);

				switch (con->contype)
				{
					case CONSTR_CHECK:
						if (!ExecQual(con->qualstate, econtext, true))
							ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("check constraint \"%s\" is violated by some row", con->name)));


						break;
					case CONSTR_FOREIGN:
						
						break;
					default:
						elog(ERROR, "unrecognized constraint type: %d", (int) con->contype);
				}
			}

			
			if (newrel)
				simple_heap_insert(newrel, tuple);

			ResetExprContext(econtext);

			CHECK_FOR_INTERRUPTS();
		}

		MemoryContextSwitchTo(oldCxt);
		heap_endscan(scan);

		ExecDropSingleTupleTableSlot(oldslot);
		ExecDropSingleTupleTableSlot(newslot);
	}

	FreeExecutorState(estate);

	heap_close(oldrel, NoLock);
	if (newrel)
		heap_close(newrel, NoLock);
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


static void ATSimplePermissions(Relation rel, bool allowView)
{
	if (rel->rd_rel->relkind != RELKIND_RELATION)
	{
		if (allowView)
		{
			if (rel->rd_rel->relkind != RELKIND_VIEW)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or view", RelationGetRelationName(rel))));


		}
		else ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table", RelationGetRelationName(rel))));



	}

	
	if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(rel));

	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));


}


static void ATSimplePermissionsRelationOrIndex(Relation rel)
{
	if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_INDEX)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or index", RelationGetRelationName(rel))));



	
	if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(rel));

	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));


}


static void ATSimpleRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd, bool recurse)

{
	
	if (recurse && rel->rd_rel->relkind == RELKIND_RELATION)
	{
		Oid			relid = RelationGetRelid(rel);
		ListCell   *child;
		List	   *children;

		
		children = find_all_inheritors(relid);

		
		foreach(child, children)
		{
			Oid			childrelid = lfirst_oid(child);
			Relation	childrel;

			if (childrelid == relid)
				continue;
			childrel = relation_open(childrelid, AccessExclusiveLock);
			ATPrepCmd(wqueue, childrel, cmd, false, true);
			relation_close(childrel, NoLock);
		}
	}
}


static void ATOneLevelRecursion(List **wqueue, Relation rel, AlterTableCmd *cmd)

{
	Oid			relid = RelationGetRelid(rel);
	ListCell   *child;
	List	   *children;

	
	children = find_inheritance_children(relid);

	foreach(child, children)
	{
		Oid			childrelid = lfirst_oid(child);
		Relation	childrel;

		childrel = relation_open(childrelid, AccessExclusiveLock);
		ATPrepCmd(wqueue, childrel, cmd, true, true);
		relation_close(childrel, NoLock);
	}
}



static void find_composite_type_dependencies(Oid typeOid, const char *origTblName)
{
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc depScan;
	HeapTuple	depTup;

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(TypeRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typeOid));



	depScan = systable_beginscan(depRel, DependReferenceIndexId, true, SnapshotNow, 2, key);

	while (HeapTupleIsValid(depTup = systable_getnext(depScan)))
	{
		Form_pg_depend pg_depend = (Form_pg_depend) GETSTRUCT(depTup);
		Relation	rel;
		Form_pg_attribute att;

		
		
		if (pg_depend->classid != RelationRelationId || pg_depend->objsubid <= 0)
			continue;

		rel = relation_open(pg_depend->objid, AccessShareLock);
		att = rel->rd_att->attrs[pg_depend->objsubid - 1];

		if (rel->rd_rel->relkind == RELKIND_RELATION)
		{
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter table \"%s\" because column \"%s\".\"%s\" uses its rowtype", origTblName, RelationGetRelationName(rel), NameStr(att->attname))));




		}
		else if (OidIsValid(rel->rd_rel->reltype))
		{
			
			find_composite_type_dependencies(rel->rd_rel->reltype, origTblName);
		}

		relation_close(rel, AccessShareLock);
	}

	systable_endscan(depScan);

	relation_close(depRel, AccessShareLock);
}



static void ATPrepAddColumn(List **wqueue, Relation rel, bool recurse, AlterTableCmd *cmd)

{
	
	if (recurse)
	{
		AlterTableCmd *childCmd = copyObject(cmd);
		ColumnDef  *colDefChild = (ColumnDef *) childCmd->def;

		
		colDefChild->inhcount = 1;
		colDefChild->is_local = false;

		ATOneLevelRecursion(wqueue, rel, childCmd);
	}
	else {
		
		if (find_inheritance_children(RelationGetRelid(rel)) != NIL)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("column must be added to child tables too")));

	}
}

static void ATExecAddColumn(AlteredTableInfo *tab, Relation rel, ColumnDef *colDef)

{
	Oid			myrelid = RelationGetRelid(rel);
	Relation	pgclass, attrdesc;
	HeapTuple	reltup;
	HeapTuple	attributeTuple;
	Form_pg_attribute attribute;
	FormData_pg_attribute attributeD;
	int			i;
	int			minattnum, maxatts;
	HeapTuple	typeTuple;
	Oid			typeOid;
	int32		typmod;
	Form_pg_type tform;
	Expr	   *defval;

	attrdesc = heap_open(AttributeRelationId, RowExclusiveLock);

	
	if (colDef->inhcount > 0)
	{
		HeapTuple	tuple;

		
		tuple = SearchSysCacheCopyAttName(myrelid, colDef->colname);
		if (HeapTupleIsValid(tuple))
		{
			Form_pg_attribute childatt = (Form_pg_attribute) GETSTRUCT(tuple);
			Oid		ctypeId;
			int32 	ctypmod;

			
			ctypeId = typenameTypeId(NULL, colDef->typename);
			ctypmod = typenameTypeMod(NULL, colDef->typename, ctypeId);
			if (ctypeId != childatt->atttypid || ctypmod != childatt->atttypmod)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table \"%s\" has different type for column \"%s\"", RelationGetRelationName(rel), colDef->colname)));



			
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

	reltup = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(myrelid), 0, 0, 0);

	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "cache lookup failed for relation %u", myrelid);

	
	if (SearchSysCacheExists(ATTNAME, ObjectIdGetDatum(myrelid), PointerGetDatum(colDef->colname), 0, 0))


		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" of relation \"%s\" already exists", colDef->colname, RelationGetRelationName(rel))));



	minattnum = ((Form_pg_class) GETSTRUCT(reltup))->relnatts;
	maxatts = minattnum + 1;
	if (maxatts > MaxHeapAttributeNumber)
		ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("tables can have at most %d columns", MaxHeapAttributeNumber)));


	i = minattnum + 1;

	typeTuple = typenameType(NULL, colDef->typename);
	tform = (Form_pg_type) GETSTRUCT(typeTuple);
	typeOid = HeapTupleGetOid(typeTuple);
	typmod = typenameTypeMod(NULL, colDef->typename, typeOid);

	
	CheckAttributeType(colDef->colname, typeOid);

	attributeTuple = heap_addheader(Natts_pg_attribute, false, ATTRIBUTE_TUPLE_SIZE, (void *) &attributeD);



	attribute = (Form_pg_attribute) GETSTRUCT(attributeTuple);

	attribute->attrelid = myrelid;
	namestrcpy(&(attribute->attname), colDef->colname);
	attribute->atttypid = typeOid;
	attribute->attstattarget = -1;
	attribute->attlen = tform->typlen;
	attribute->attcacheoff = -1;
	attribute->atttypmod = typmod;
	attribute->attnum = i;
	attribute->attbyval = tform->typbyval;
	attribute->attndims = list_length(colDef->typename->arrayBounds);
	attribute->attstorage = tform->typstorage;
	attribute->attalign = tform->typalign;
	attribute->attnotnull = colDef->is_not_null;
	attribute->atthasdef = false;
	attribute->attisdropped = false;
	attribute->attislocal = colDef->is_local;
	attribute->attinhcount = colDef->inhcount;

	ReleaseSysCache(typeTuple);

	simple_heap_insert(attrdesc, attributeTuple);

	
	CatalogUpdateIndexes(attrdesc, attributeTuple);

	heap_close(attrdesc, RowExclusiveLock);

	
	((Form_pg_class) GETSTRUCT(reltup))->relnatts = maxatts;

	simple_heap_update(pgclass, &reltup->t_self, reltup);

	
	CatalogUpdateIndexes(pgclass, reltup);

	heap_freetuple(reltup);

	heap_close(pgclass, RowExclusiveLock);

	
	CommandCounterIncrement();

	
	if (colDef->raw_default)
	{
		RawColumnDefault *rawEnt;

		rawEnt = (RawColumnDefault *) palloc(sizeof(RawColumnDefault));
		rawEnt->attnum = attribute->attnum;
		rawEnt->raw_default = copyObject(colDef->raw_default);

		
		AddRelationRawConstraints(rel, list_make1(rawEnt), NIL);

		
		CommandCounterIncrement();
	}

	
	defval = (Expr *) build_column_default(rel, attribute->attnum);

	if (!defval && GetDomainConstraints(typeOid) != NIL)
	{
		Oid			basetype = getBaseType(typeOid);

		defval = (Expr *) makeNullConst(basetype);
		defval = (Expr *) coerce_to_target_type(NULL, (Node *) defval, basetype, typeOid, typmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST);





		if (defval == NULL)		
			elog(ERROR, "failed to coerce base type to domain");
	}

	if (defval)
	{
		NewColumnValue *newval;

		newval = (NewColumnValue *) palloc0(sizeof(NewColumnValue));
		newval->attnum = attribute->attnum;
		newval->expr = defval;

		tab->newvals = lappend(tab->newvals, newval);
	}

	
	add_column_datatype_dependency(myrelid, i, attribute->atttypid);
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


static void ATExecDropNotNull(Relation rel, const char *colName)
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

		indexTuple = SearchSysCache(INDEXRELID, ObjectIdGetDatum(indexoid), 0, 0, 0);

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

	heap_close(attr_rel, RowExclusiveLock);
}


static void ATExecSetNotNull(AlteredTableInfo *tab, Relation rel, const char *colName)

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

	heap_close(attr_rel, RowExclusiveLock);
}


static void ATExecColumnDefault(Relation rel, const char *colName, Node *newDefault)

{
	AttrNumber	attnum;

	
	attnum = get_attnum(RelationGetRelid(rel), colName);
	if (attnum == InvalidAttrNumber)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));



	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	RemoveAttrDefault(RelationGetRelid(rel), attnum, DROP_RESTRICT, false);

	if (newDefault)
	{
		
		RawColumnDefault *rawEnt;

		rawEnt = (RawColumnDefault *) palloc(sizeof(RawColumnDefault));
		rawEnt->attnum = attnum;
		rawEnt->raw_default = newDefault;

		
		AddRelationRawConstraints(rel, list_make1(rawEnt), NIL);
	}
}


static void ATPrepSetStatistics(Relation rel, const char *colName, Node *flagValue)
{
	
	if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_INDEX)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or index", RelationGetRelationName(rel))));



	
	if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, RelationGetRelationName(rel));
}

static void ATExecSetStatistics(Relation rel, const char *colName, Node *newValue)
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
	else if (newtarget > 1000)
	{
		newtarget = 1000;
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

	heap_freetuple(tuple);

	heap_close(attrelation, RowExclusiveLock);
}


static void ATExecSetStorage(Relation rel, const char *colName, Node *newValue)
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

	heap_freetuple(tuple);

	heap_close(attrelation, RowExclusiveLock);
}



static void ATExecDropColumn(Relation rel, const char *colName, DropBehavior behavior, bool recurse, bool recursing)


{
	HeapTuple	tuple;
	Form_pg_attribute targetatt;
	AttrNumber	attnum;
	List	   *children;
	ObjectAddress object;

	
	if (recursing)
		ATSimplePermissions(rel, false);

	
	tuple = SearchSysCacheAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	targetatt = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = targetatt->attnum;

	
	if (attnum <= 0 && attnum != ObjectIdAttributeNumber)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot drop system column \"%s\"", colName)));



	
	if (targetatt->attinhcount > 0 && !recursing)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot drop inherited column \"%s\"", colName)));



	ReleaseSysCache(tuple);

	
	children = find_inheritance_children(RelationGetRelid(rel));

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

			childrel = heap_open(childrelid, AccessExclusiveLock);

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
					
					ATExecDropColumn(childrel, colName, behavior, true, true);
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

	performDeletion(&object, behavior);

	
	if (attnum == ObjectIdAttributeNumber)
	{
		Relation	class_rel;
		Form_pg_class tuple_class;

		class_rel = heap_open(RelationRelationId, RowExclusiveLock);

		tuple = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(RelationGetRelid(rel)), 0, 0, 0);

		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation %u", RelationGetRelid(rel));
		tuple_class = (Form_pg_class) GETSTRUCT(tuple);

		tuple_class->relhasoids = false;
		simple_heap_update(class_rel, &tuple->t_self, tuple);

		
		CatalogUpdateIndexes(class_rel, tuple);

		heap_close(class_rel, RowExclusiveLock);
	}
}


static void ATExecAddIndex(AlteredTableInfo *tab, Relation rel, IndexStmt *stmt, bool is_rebuild)

{
	bool		check_rights;
	bool		skip_build;
	bool		quiet;

	Assert(IsA(stmt, IndexStmt));

	
	check_rights = !is_rebuild;
	
	skip_build = (tab->newvals != NIL);
	
	quiet = is_rebuild;

	DefineIndex(stmt->relation,  stmt->idxname, InvalidOid, stmt->accessMethod, stmt->tableSpace, stmt->indexParams, (Expr *) stmt->whereClause, stmt->rangetable, stmt->options, stmt->unique, stmt->primary, stmt->isconstraint, true, check_rights, skip_build, quiet, false);















}


static void ATExecAddConstraint(AlteredTableInfo *tab, Relation rel, Node *newConstraint)
{
	switch (nodeTag(newConstraint))
	{
		case T_Constraint:
			{
				Constraint *constr = (Constraint *) newConstraint;

				
				switch (constr->contype)
				{
					case CONSTR_CHECK:
						{
							List	   *newcons;
							ListCell   *lcon;

							
							newcons = AddRelationRawConstraints(rel, NIL, list_make1(constr));
							
							foreach(lcon, newcons)
							{
								CookedConstraint *ccon = (CookedConstraint *) lfirst(lcon);
								NewConstraint *newcon;

								newcon = (NewConstraint *) palloc0(sizeof(NewConstraint));
								newcon->name = ccon->name;
								newcon->contype = ccon->contype;
								
								newcon->qual = (Node *)
									make_ands_implicit((Expr *) ccon->expr);

								tab->constraints = lappend(tab->constraints, newcon);
							}
							break;
						}
					default:
						elog(ERROR, "unrecognized constraint type: %d", (int) constr->contype);
				}
				break;
			}
		case T_FkConstraint:
			{
				FkConstraint *fkconstraint = (FkConstraint *) newConstraint;

				
				if (fkconstraint->constr_name)
				{
					if (ConstraintNameIsUsed(CONSTRAINT_RELATION, RelationGetRelid(rel), RelationGetNamespace(rel), fkconstraint->constr_name))


						ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("constraint \"%s\" for relation \"%s\" already exists", fkconstraint->constr_name, RelationGetRelationName(rel))));



				}
				else fkconstraint->constr_name = ChooseConstraintName(RelationGetRelationName(rel), strVal(linitial(fkconstraint->fk_attrs)), "fkey", RelationGetNamespace(rel), NIL);






				ATAddForeignKeyConstraint(tab, rel, fkconstraint);

				break;
			}
		default:
			elog(ERROR, "unrecognized node type: %d", (int) nodeTag(newConstraint));
	}
}


static void ATAddForeignKeyConstraint(AlteredTableInfo *tab, Relation rel, FkConstraint *fkconstraint)

{
	Relation	pkrel;
	AclResult	aclresult;
	int16		pkattnum[INDEX_MAX_KEYS];
	int16		fkattnum[INDEX_MAX_KEYS];
	Oid			pktypoid[INDEX_MAX_KEYS];
	Oid			fktypoid[INDEX_MAX_KEYS];
	Oid			opclasses[INDEX_MAX_KEYS];
	int			i;
	int			numfks, numpks;
	Oid			indexOid;
	Oid			constrOid;

	
	pkrel = heap_openrv(fkconstraint->pktable, AccessExclusiveLock);

	
	if (pkrel->rd_rel->relkind != RELKIND_RELATION)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("referenced relation \"%s\" is not a table", RelationGetRelationName(pkrel))));



	aclresult = pg_class_aclcheck(RelationGetRelid(pkrel), GetUserId(), ACL_REFERENCES);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(pkrel));

	if (!allowSystemTableMods && IsSystemRelation(pkrel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(pkrel))));



	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(), ACL_REFERENCES);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(rel));

	
	if (isTempNamespace(RelationGetNamespace(pkrel)))
	{
		if (!isTempNamespace(RelationGetNamespace(rel)))
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot reference temporary table from permanent table constraint")));

	}
	else {
		if (isTempNamespace(RelationGetNamespace(rel)))
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot reference permanent table from temporary table constraint")));

	}

	
	MemSet(pkattnum, 0, sizeof(pkattnum));
	MemSet(fkattnum, 0, sizeof(fkattnum));
	MemSet(pktypoid, 0, sizeof(pktypoid));
	MemSet(fktypoid, 0, sizeof(fktypoid));
	MemSet(opclasses, 0, sizeof(opclasses));

	numfks = transformColumnNameList(RelationGetRelid(rel), fkconstraint->fk_attrs, fkattnum, fktypoid);


	
	if (fkconstraint->pk_attrs == NIL)
	{
		numpks = transformFkeyGetPrimaryKey(pkrel, &indexOid, &fkconstraint->pk_attrs, pkattnum, pktypoid, opclasses);


	}
	else {
		numpks = transformColumnNameList(RelationGetRelid(pkrel), fkconstraint->pk_attrs, pkattnum, pktypoid);

		
		indexOid = transformFkeyCheckAttrs(pkrel, numpks, pkattnum, opclasses);
	}

	
	if (numfks != numpks)
		ereport(ERROR, (errcode(ERRCODE_INVALID_FOREIGN_KEY), errmsg("number of referencing and referenced columns for foreign key disagree")));


	for (i = 0; i < numpks; i++)
	{
		
		Operator	o = oper(NULL, list_make1(makeString("=")), pktypoid[i], fktypoid[i], true, -1);


		if (o == NULL)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("foreign key constraint \"%s\" " "cannot be implemented", fkconstraint->constr_name), errdetail("Key columns \"%s\" and \"%s\" " "are of incompatible types: %s and %s.", strVal(list_nth(fkconstraint->fk_attrs, i)), strVal(list_nth(fkconstraint->pk_attrs, i)), format_type_be(fktypoid[i]), format_type_be(pktypoid[i]))));










		
		if (!op_in_opfamily(oprid(o), get_opclass_family(opclasses[i])))
			ereport(WARNING, (errmsg("foreign key constraint \"%s\" " "will require costly sequential scans", fkconstraint->constr_name), errdetail("Key columns \"%s\" and \"%s\" " "are of different types: %s and %s.", strVal(list_nth(fkconstraint->fk_attrs, i)), strVal(list_nth(fkconstraint->pk_attrs, i)), format_type_be(fktypoid[i]), format_type_be(pktypoid[i]))));









		ReleaseSysCache(o);
	}

	
	if (!fkconstraint->skip_validation)
	{
		NewConstraint *newcon;

		newcon = (NewConstraint *) palloc0(sizeof(NewConstraint));
		newcon->name = fkconstraint->constr_name;
		newcon->contype = CONSTR_FOREIGN;
		newcon->refrelid = RelationGetRelid(pkrel);
		newcon->qual = (Node *) fkconstraint;

		tab->constraints = lappend(tab->constraints, newcon);
	}

	
	constrOid = CreateConstraintEntry(fkconstraint->constr_name, RelationGetNamespace(rel), CONSTRAINT_FOREIGN, fkconstraint->deferrable, fkconstraint->initdeferred, RelationGetRelid(rel), fkattnum, numfks, InvalidOid, RelationGetRelid(pkrel), pkattnum, numpks, fkconstraint->fk_upd_action, fkconstraint->fk_del_action, fkconstraint->fk_matchtype, indexOid, NULL, NULL, NULL);


















	
	createForeignKeyTriggers(rel, fkconstraint, constrOid);

	
	heap_close(pkrel, NoLock);
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

		indexTuple = SearchSysCache(INDEXRELID, ObjectIdGetDatum(indexoid), 0, 0, 0);

		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		indexStruct = (Form_pg_index) GETSTRUCT(indexTuple);
		if (indexStruct->indisprimary)
		{
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
	List	   *indexoidlist;
	ListCell   *indexoidscan;

	
	indexoidlist = RelationGetIndexList(pkrel);

	foreach(indexoidscan, indexoidlist)
	{
		HeapTuple	indexTuple;
		Form_pg_index indexStruct;
		int			i, j;

		indexoid = lfirst_oid(indexoidscan);
		indexTuple = SearchSysCache(INDEXRELID, ObjectIdGetDatum(indexoid), 0, 0, 0);

		if (!HeapTupleIsValid(indexTuple))
			elog(ERROR, "cache lookup failed for index %u", indexoid);
		indexStruct = (Form_pg_index) GETSTRUCT(indexTuple);

		
		if (indexStruct->indnatts == numattrs && indexStruct->indisunique && heap_attisnull(indexTuple, Anum_pg_index_indpred) && heap_attisnull(indexTuple, Anum_pg_index_indexprs))


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
		}
		ReleaseSysCache(indexTuple);
		if (found)
			break;
	}

	if (!found)
		ereport(ERROR, (errcode(ERRCODE_INVALID_FOREIGN_KEY), errmsg("there is no unique constraint matching given keys for referenced table \"%s\"", RelationGetRelationName(pkrel))));



	list_free(indexoidlist);

	return indexoid;
}


static void validateForeignKeyConstraint(FkConstraint *fkconstraint, Relation rel, Relation pkrel)


{
	HeapScanDesc scan;
	HeapTuple	tuple;
	Trigger		trig;
	ListCell   *list;
	int			count;

	
	if (RI_Initial_Check(fkconstraint, rel, pkrel))
		return;

	
	MemSet(&trig, 0, sizeof(trig));
	trig.tgoid = InvalidOid;
	trig.tgname = fkconstraint->constr_name;
	trig.tgenabled = TRUE;
	trig.tgisconstraint = TRUE;
	trig.tgconstrrelid = RelationGetRelid(pkrel);
	trig.tgdeferrable = FALSE;
	trig.tginitdeferred = FALSE;

	trig.tgargs = (char **) palloc(sizeof(char *) * (4 + list_length(fkconstraint->fk_attrs)
									+ list_length(fkconstraint->pk_attrs)));

	trig.tgargs[0] = trig.tgname;
	trig.tgargs[1] = RelationGetRelationName(rel);
	trig.tgargs[2] = RelationGetRelationName(pkrel);
	trig.tgargs[3] = fkMatchTypeToString(fkconstraint->fk_matchtype);
	count = 4;
	foreach(list, fkconstraint->fk_attrs)
	{
		char	   *fk_at = strVal(lfirst(list));

		trig.tgargs[count] = fk_at;
		count += 2;
	}
	count = 5;
	foreach(list, fkconstraint->pk_attrs)
	{
		char	   *pk_at = strVal(lfirst(list));

		trig.tgargs[count] = pk_at;
		count += 2;
	}
	trig.tgnargs = count - 1;

	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

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

	pfree(trig.tgargs);
}

static void CreateFKCheckTrigger(RangeVar *myRel, FkConstraint *fkconstraint, ObjectAddress *constrobj, ObjectAddress *trigobj, bool on_insert)


{
	CreateTrigStmt *fk_trigger;
	ListCell   *fk_attr;
	ListCell   *pk_attr;

	fk_trigger = makeNode(CreateTrigStmt);
	fk_trigger->trigname = fkconstraint->constr_name;
	fk_trigger->relation = myRel;
	fk_trigger->before = false;
	fk_trigger->row = true;

	
	if (on_insert)
	{
		fk_trigger->funcname = SystemFuncName("RI_FKey_check_ins");
		fk_trigger->actions[0] = 'i';
	}
	else {
		fk_trigger->funcname = SystemFuncName("RI_FKey_check_upd");
		fk_trigger->actions[0] = 'u';
	}
	fk_trigger->actions[1] = '\0';

	fk_trigger->isconstraint = true;
	fk_trigger->deferrable = fkconstraint->deferrable;
	fk_trigger->initdeferred = fkconstraint->initdeferred;
	fk_trigger->constrrel = fkconstraint->pktable;

	fk_trigger->args = NIL;
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkconstraint->constr_name));
	fk_trigger->args = lappend(fk_trigger->args, makeString(myRel->relname));
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkconstraint->pktable->relname));
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkMatchTypeToString(fkconstraint->fk_matchtype)));
	if (list_length(fkconstraint->fk_attrs) != list_length(fkconstraint->pk_attrs))
		ereport(ERROR, (errcode(ERRCODE_INVALID_FOREIGN_KEY), errmsg("number of referencing and referenced columns for foreign key disagree")));


	forboth(fk_attr, fkconstraint->fk_attrs, pk_attr, fkconstraint->pk_attrs)
	{
		fk_trigger->args = lappend(fk_trigger->args, lfirst(fk_attr));
		fk_trigger->args = lappend(fk_trigger->args, lfirst(pk_attr));
	}

	trigobj->objectId = CreateTrigger(fk_trigger, true);

	
	recordDependencyOn(trigobj, constrobj, DEPENDENCY_INTERNAL);

	
	CommandCounterIncrement();
}


static void createForeignKeyTriggers(Relation rel, FkConstraint *fkconstraint, Oid constrOid)

{
	RangeVar   *myRel;
	CreateTrigStmt *fk_trigger;
	ListCell   *fk_attr;
	ListCell   *pk_attr;
	ObjectAddress trigobj, constrobj;

	
	myRel = makeRangeVar(get_namespace_name(RelationGetNamespace(rel)), pstrdup(RelationGetRelationName(rel)));

	
	constrobj.classId = ConstraintRelationId;
	constrobj.objectId = constrOid;
	constrobj.objectSubId = 0;
	trigobj.classId = TriggerRelationId;
	trigobj.objectSubId = 0;

	
	CommandCounterIncrement();

	
	CreateFKCheckTrigger(myRel, fkconstraint, &constrobj, &trigobj, true);
	CreateFKCheckTrigger(myRel, fkconstraint, &constrobj, &trigobj, false);

	
	fk_trigger = makeNode(CreateTrigStmt);
	fk_trigger->trigname = fkconstraint->constr_name;
	fk_trigger->relation = fkconstraint->pktable;
	fk_trigger->before = false;
	fk_trigger->row = true;
	fk_trigger->actions[0] = 'd';
	fk_trigger->actions[1] = '\0';

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
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkconstraint->constr_name));
	fk_trigger->args = lappend(fk_trigger->args, makeString(myRel->relname));
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkconstraint->pktable->relname));
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkMatchTypeToString(fkconstraint->fk_matchtype)));
	forboth(fk_attr, fkconstraint->fk_attrs, pk_attr, fkconstraint->pk_attrs)
	{
		fk_trigger->args = lappend(fk_trigger->args, lfirst(fk_attr));
		fk_trigger->args = lappend(fk_trigger->args, lfirst(pk_attr));
	}

	trigobj.objectId = CreateTrigger(fk_trigger, true);

	
	recordDependencyOn(&trigobj, &constrobj, DEPENDENCY_INTERNAL);

	
	CommandCounterIncrement();

	
	fk_trigger = makeNode(CreateTrigStmt);
	fk_trigger->trigname = fkconstraint->constr_name;
	fk_trigger->relation = fkconstraint->pktable;
	fk_trigger->before = false;
	fk_trigger->row = true;
	fk_trigger->actions[0] = 'u';
	fk_trigger->actions[1] = '\0';
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
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkconstraint->constr_name));
	fk_trigger->args = lappend(fk_trigger->args, makeString(myRel->relname));
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkconstraint->pktable->relname));
	fk_trigger->args = lappend(fk_trigger->args, makeString(fkMatchTypeToString(fkconstraint->fk_matchtype)));
	forboth(fk_attr, fkconstraint->fk_attrs, pk_attr, fkconstraint->pk_attrs)
	{
		fk_trigger->args = lappend(fk_trigger->args, lfirst(fk_attr));
		fk_trigger->args = lappend(fk_trigger->args, lfirst(pk_attr));
	}

	trigobj.objectId = CreateTrigger(fk_trigger, true);

	
	recordDependencyOn(&trigobj, &constrobj, DEPENDENCY_INTERNAL);
}


static char * fkMatchTypeToString(char match_type)
{
	switch (match_type)
	{
		case FKCONSTR_MATCH_FULL:
			return pstrdup("FULL");
		case FKCONSTR_MATCH_PARTIAL:
			return pstrdup("PARTIAL");
		case FKCONSTR_MATCH_UNSPECIFIED:
			return pstrdup("UNSPECIFIED");
		default:
			elog(ERROR, "unrecognized match type: %d", (int) match_type);
	}
	return NULL;				
}


static void ATPrepDropConstraint(List **wqueue, Relation rel, bool recurse, AlterTableCmd *cmd)

{
	
	if (recurse)
	{
		AlterTableCmd *childCmd = copyObject(cmd);

		childCmd->subtype = AT_DropConstraintQuietly;
		ATSimpleRecursion(wqueue, rel, childCmd, recurse);
	}
}

static void ATExecDropConstraint(Relation rel, const char *constrName, DropBehavior behavior, bool quiet)

{
	int			deleted;

	deleted = RemoveRelConstraints(rel, constrName, behavior);

	if (!quiet)
	{
		
		if (deleted == 0)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" does not exist", constrName)));


		
		else if (deleted > 1)
			ereport(NOTICE, (errmsg("multiple constraints named \"%s\" were dropped", constrName)));

	}
}


static void ATPrepAlterColumnType(List **wqueue, AlteredTableInfo *tab, Relation rel, bool recurse, bool recursing, AlterTableCmd *cmd)



{
	char	   *colName = cmd->name;
	TypeName   *typename = (TypeName *) cmd->def;
	HeapTuple	tuple;
	Form_pg_attribute attTup;
	AttrNumber	attnum;
	Oid			targettype;
	int32		targettypmod;
	Node	   *transform;
	NewColumnValue *newval;
	ParseState *pstate = make_parsestate(NULL);

	
	tuple = SearchSysCacheAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", colName, RelationGetRelationName(rel))));


	attTup = (Form_pg_attribute) GETSTRUCT(tuple);
	attnum = attTup->attnum;

	
	if (attnum <= 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot alter system column \"%s\"", colName)));



	
	if (attTup->attinhcount > 0 && !recursing)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot alter inherited column \"%s\"", colName)));



	
	targettype = typenameTypeId(NULL, typename);
	targettypmod = typenameTypeMod(NULL, typename, targettype);

	
	CheckAttributeType(colName, targettype);

	
	if (cmd->transform)
	{
		RangeTblEntry *rte;

		
		rte = addRangeTableEntryForRelation(pstate, rel, NULL, false, true);



		addRTEtoQuery(pstate, rte, false, true, true);

		transform = transformExpr(pstate, cmd->transform);

		
		if (expression_returns_set(transform))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("transform expression must not return a set")));


		
		if (pstate->p_hasSubLinks)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use subquery in transform expression")));

		if (pstate->p_hasAggs)
			ereport(ERROR, (errcode(ERRCODE_GROUPING_ERROR), errmsg("cannot use aggregate function in transform expression")));

	}
	else {
		transform = (Node *) makeVar(1, attnum, attTup->atttypid, attTup->atttypmod, 0);

	}

	transform = coerce_to_target_type(pstate, transform, exprType(transform), targettype, targettypmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST);



	if (transform == NULL)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("column \"%s\" cannot be cast to type \"%s\"", colName, TypeNameToString(typename))));



	
	newval = (NewColumnValue *) palloc0(sizeof(NewColumnValue));
	newval->attnum = attnum;
	newval->expr = (Expr *) transform;

	tab->newvals = lappend(tab->newvals, newval);

	ReleaseSysCache(tuple);

	
	if (recurse)
		ATSimpleRecursion(wqueue, rel, cmd, recurse);
	else if (!recursing && find_inheritance_children(RelationGetRelid(rel)) != NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("type of inherited column \"%s\" must be changed in child tables too", colName)));


}

static void ATExecAlterColumnType(AlteredTableInfo *tab, Relation rel, const char *colName, TypeName *typename)

{
	HeapTuple	heapTup;
	Form_pg_attribute attTup;
	AttrNumber	attnum;
	HeapTuple	typeTuple;
	Form_pg_type tform;
	Oid			targettype;
	int32		targettypmod;
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



	
	typeTuple = typenameType(NULL, typename);
	tform = (Form_pg_type) GETSTRUCT(typeTuple);
	targettype = HeapTupleGetOid(typeTuple);
	targettypmod = typenameTypeMod(NULL, typename, targettype);

	
	if (attTup->atthasdef)
	{
		defaultexpr = build_column_default(rel, attnum);
		Assert(defaultexpr);
		defaultexpr = strip_implicit_coercions(defaultexpr);
		defaultexpr = coerce_to_target_type(NULL,		 defaultexpr, exprType(defaultexpr), targettype, targettypmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST);



		if (defaultexpr == NULL)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("default for column \"%s\" cannot be cast to type \"%s\"", colName, TypeNameToString(typename))));


	}
	else defaultexpr = NULL;

	
	depRel = heap_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	ScanKeyInit(&key[2], Anum_pg_depend_refobjsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum((int32) attnum));



	scan = systable_beginscan(depRel, DependReferenceIndexId, true, SnapshotNow, 3, key);

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

			case OCLASS_DEFAULT:

				
				Assert(defaultexpr);
				break;

			case OCLASS_PROC:
			case OCLASS_TYPE:
			case OCLASS_CAST:
			case OCLASS_CONVERSION:
			case OCLASS_LANGUAGE:
			case OCLASS_OPERATOR:
			case OCLASS_OPCLASS:
			case OCLASS_TRIGGER:
			case OCLASS_SCHEMA:

				
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



	scan = systable_beginscan(depRel, DependDependerIndexId, true, SnapshotNow, 3, key);

	while (HeapTupleIsValid(depTup = systable_getnext(scan)))
	{
		Form_pg_depend foundDep = (Form_pg_depend) GETSTRUCT(depTup);

		if (foundDep->deptype != DEPENDENCY_NORMAL)
			elog(ERROR, "found unexpected dependency type '%c'", foundDep->deptype);
		if (foundDep->refclassid != TypeRelationId || foundDep->refobjid != attTup->atttypid)
			elog(ERROR, "found unexpected dependency for column");

		simple_heap_delete(depRel, &depTup->t_self);
	}

	systable_endscan(scan);

	heap_close(depRel, RowExclusiveLock);

	
	attTup->atttypid = targettype;
	attTup->atttypmod = targettypmod;
	attTup->attndims = list_length(typename->arrayBounds);
	attTup->attlen = tform->typlen;
	attTup->attbyval = tform->typbyval;
	attTup->attalign = tform->typalign;
	attTup->attstorage = tform->typstorage;

	ReleaseSysCache(typeTuple);

	simple_heap_update(attrelation, &heapTup->t_self, heapTup);

	
	CatalogUpdateIndexes(attrelation, heapTup);

	heap_close(attrelation, RowExclusiveLock);

	
	add_column_datatype_dependency(RelationGetRelid(rel), attnum, targettype);

	
	RemoveStatistics(RelationGetRelid(rel), attnum);

	
	if (defaultexpr)
	{
		
		CommandCounterIncrement();

		
		RemoveAttrDefault(RelationGetRelid(rel), attnum, DROP_RESTRICT, true);

		StoreAttrDefault(rel, attnum, nodeToString(defaultexpr));
	}

	
	heap_freetuple(heapTup);
}


static void ATPostAlterTypeCleanup(List **wqueue, AlteredTableInfo *tab)
{
	ObjectAddress obj;
	ListCell   *l;

	
	foreach(l, tab->changedIndexDefs)
		ATPostAlterTypeParse((char *) lfirst(l), wqueue);
	foreach(l, tab->changedConstraintDefs)
		ATPostAlterTypeParse((char *) lfirst(l), wqueue);

	
	foreach(l, tab->changedConstraintOids)
	{
		obj.classId = ConstraintRelationId;
		obj.objectId = lfirst_oid(l);
		obj.objectSubId = 0;
		performDeletion(&obj, DROP_RESTRICT);
	}

	foreach(l, tab->changedIndexOids)
	{
		obj.classId = RelationRelationId;
		obj.objectId = lfirst_oid(l);
		obj.objectSubId = 0;
		performDeletion(&obj, DROP_RESTRICT);
	}

	
}

static void ATPostAlterTypeParse(char *cmd, List **wqueue)
{
	List	   *raw_parsetree_list;
	List	   *querytree_list;
	ListCell   *list_item;

	
	raw_parsetree_list = raw_parser(cmd);
	querytree_list = NIL;
	foreach(list_item, raw_parsetree_list)
	{
		Node	   *parsetree = (Node *) lfirst(list_item);

		querytree_list = list_concat(querytree_list, parse_analyze(parsetree, cmd, NULL, 0));
	}

	
	foreach(list_item, querytree_list)
	{
		Query	   *query = (Query *) lfirst(list_item);
		Relation	rel;
		AlteredTableInfo *tab;

		Assert(IsA(query, Query));
		Assert(query->commandType == CMD_UTILITY);
		switch (nodeTag(query->utilityStmt))
		{
			case T_IndexStmt:
				{
					IndexStmt  *stmt = (IndexStmt *) query->utilityStmt;
					AlterTableCmd *newcmd;

					rel = relation_openrv(stmt->relation, AccessExclusiveLock);
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
					AlterTableStmt *stmt = (AlterTableStmt *) query->utilityStmt;
					ListCell   *lcmd;

					rel = relation_openrv(stmt->relation, AccessExclusiveLock);
					tab = ATGetQueueEntry(wqueue, rel);
					foreach(lcmd, stmt->cmds)
					{
						AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);

						switch (cmd->subtype)
						{
							case AT_AddIndex:
								cmd->subtype = AT_ReAddIndex;
								tab->subcmds[AT_PASS_OLD_INDEX] = lappend(tab->subcmds[AT_PASS_OLD_INDEX], cmd);
								break;
							case AT_AddConstraint:
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
				elog(ERROR, "unexpected statement type: %d", (int) nodeTag(query->utilityStmt));
		}
	}
}



void ATExecChangeOwner(Oid relationOid, Oid newOwnerId, bool recursing)
{
	Relation	target_rel;
	Relation	class_rel;
	HeapTuple	tuple;
	Form_pg_class tuple_class;

	
	target_rel = relation_open(relationOid, AccessExclusiveLock);

	
	class_rel = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relationOid), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relationOid);
	tuple_class = (Form_pg_class) GETSTRUCT(tuple);

	
	switch (tuple_class->relkind)
	{
		case RELKIND_RELATION:
		case RELKIND_VIEW:
			
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
		case RELKIND_TOASTVALUE:
			if (recursing)
				break;
			
		default:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, or sequence", NameStr(tuple_class->relname))));


	}

	
	if (tuple_class->relowner != newOwnerId)
	{
		Datum		repl_val[Natts_pg_class];
		char		repl_null[Natts_pg_class];
		char		repl_repl[Natts_pg_class];
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

		memset(repl_null, ' ', sizeof(repl_null));
		memset(repl_repl, ' ', sizeof(repl_repl));

		repl_repl[Anum_pg_class_relowner - 1] = 'r';
		repl_val[Anum_pg_class_relowner - 1] = ObjectIdGetDatum(newOwnerId);

		
		aclDatum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_relacl, &isNull);

		if (!isNull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum), tuple_class->relowner, newOwnerId);
			repl_repl[Anum_pg_class_relacl - 1] = 'r';
			repl_val[Anum_pg_class_relacl - 1] = PointerGetDatum(newAcl);
		}

		newtuple = heap_modifytuple(tuple, RelationGetDescr(class_rel), repl_val, repl_null, repl_repl);

		simple_heap_update(class_rel, &newtuple->t_self, newtuple);
		CatalogUpdateIndexes(class_rel, newtuple);

		heap_freetuple(newtuple);

		
		changeDependencyOnOwner(RelationRelationId, relationOid, newOwnerId);

		
		if (tuple_class->relkind != RELKIND_INDEX)
			AlterTypeOwnerInternal(tuple_class->reltype, newOwnerId);

		
		if (tuple_class->relkind == RELKIND_RELATION || tuple_class->relkind == RELKIND_TOASTVALUE)
		{
			List	   *index_oid_list;
			ListCell   *i;

			
			index_oid_list = RelationGetIndexList(target_rel);

			
			foreach(i, index_oid_list)
				ATExecChangeOwner(lfirst_oid(i), newOwnerId, true);

			list_free(index_oid_list);
		}

		if (tuple_class->relkind == RELKIND_RELATION)
		{
			
			if (tuple_class->reltoastrelid != InvalidOid)
				ATExecChangeOwner(tuple_class->reltoastrelid, newOwnerId, true);

			
			change_owner_recurse_to_sequences(relationOid, newOwnerId);
		}
	}

	ReleaseSysCache(tuple);
	heap_close(class_rel, RowExclusiveLock);
	relation_close(target_rel, NoLock);
}


static void change_owner_recurse_to_sequences(Oid relationOid, Oid newOwnerId)
{
	Relation	depRel;
	SysScanDesc scan;
	ScanKeyData key[2];
	HeapTuple	tup;

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relationOid));


	

	scan = systable_beginscan(depRel, DependReferenceIndexId, true, SnapshotNow, 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend depForm = (Form_pg_depend) GETSTRUCT(tup);
		Relation	seqRel;

		
		if (depForm->refobjsubid == 0 || depForm->classid != RelationRelationId || depForm->objsubid != 0 || depForm->deptype != DEPENDENCY_AUTO)


			continue;

		
		seqRel = relation_open(depForm->objid, AccessExclusiveLock);

		
		if (RelationGetForm(seqRel)->relkind != RELKIND_SEQUENCE)
		{
			
			relation_close(seqRel, AccessExclusiveLock);
			continue;
		}

		
		ATExecChangeOwner(depForm->objid, newOwnerId, true);

		
		relation_close(seqRel, NoLock);
	}

	systable_endscan(scan);

	relation_close(depRel, AccessShareLock);
}


static void ATExecClusterOn(Relation rel, const char *indexName)
{
	Oid			indexOid;

	indexOid = get_relname_relid(indexName, rel->rd_rel->relnamespace);

	if (!OidIsValid(indexOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("index \"%s\" for table \"%s\" does not exist", indexName, RelationGetRelationName(rel))));



	
	check_index_is_clusterable(rel, indexOid, false);

	
	mark_index_clustered(rel, indexOid);
}


static void ATExecDropCluster(Relation rel)
{
	mark_index_clustered(rel, InvalidOid);
}


static void ATPrepSetTableSpace(AlteredTableInfo *tab, Relation rel, char *tablespacename)
{
	Oid			tablespaceId;
	AclResult	aclresult;

	
	tablespaceId = get_tablespace_oid(tablespacename);
	if (!OidIsValid(tablespaceId))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("tablespace \"%s\" does not exist", tablespacename)));


	
	aclresult = pg_tablespace_aclcheck(tablespaceId, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_TABLESPACE, tablespacename);

	
	if (OidIsValid(tab->newTableSpace))
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("cannot have multiple SET TABLESPACE subcommands")));

	tab->newTableSpace = tablespaceId;
}


static void ATExecSetRelOptions(Relation rel, List *defList, bool isReset)
{
	Oid			relid;
	Relation	pgclass;
	HeapTuple	tuple;
	HeapTuple	newtuple;
	Datum		datum;
	bool		isnull;
	Datum		newOptions;
	Datum		repl_val[Natts_pg_class];
	char		repl_null[Natts_pg_class];
	char		repl_repl[Natts_pg_class];

	if (defList == NIL)
		return;					

	pgclass = heap_open(RelationRelationId, RowExclusiveLock);

	
	relid = RelationGetRelid(rel);
	tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relid);

	datum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_reloptions, &isnull);

	
	newOptions = transformRelOptions(isnull ? (Datum) 0 : datum, defList, false, isReset);

	
	switch (rel->rd_rel->relkind)
	{
		case RELKIND_RELATION:
		case RELKIND_TOASTVALUE:
			(void) heap_reloptions(rel->rd_rel->relkind, newOptions, true);
			break;
		case RELKIND_INDEX:
			(void) index_reloptions(rel->rd_am->amoptions, newOptions, true);
			break;
		default:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, index, or TOAST table", RelationGetRelationName(rel))));


			break;
	}

	
	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, ' ', sizeof(repl_null));
	memset(repl_repl, ' ', sizeof(repl_repl));

	if (newOptions != (Datum) 0)
		repl_val[Anum_pg_class_reloptions - 1] = newOptions;
	else repl_null[Anum_pg_class_reloptions - 1] = 'n';

	repl_repl[Anum_pg_class_reloptions - 1] = 'r';

	newtuple = heap_modifytuple(tuple, RelationGetDescr(pgclass), repl_val, repl_null, repl_repl);

	simple_heap_update(pgclass, &newtuple->t_self, newtuple);

	CatalogUpdateIndexes(pgclass, newtuple);

	heap_freetuple(newtuple);

	ReleaseSysCache(tuple);

	heap_close(pgclass, RowExclusiveLock);
}


static void ATExecSetTableSpace(Oid tableOid, Oid newTableSpace)
{
	Relation	rel;
	Oid			oldTableSpace;
	Oid			reltoastrelid;
	Oid			reltoastidxid;
	RelFileNode newrnode;
	SMgrRelation dstrel;
	Relation	pg_class;
	HeapTuple	tuple;
	Form_pg_class rd_rel;

	
	rel = relation_open(tableOid, AccessExclusiveLock);

	
	if (rel->rd_rel->relisshared || rel->rd_isnailed)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move system relation \"%s\"", RelationGetRelationName(rel))));



	
	if (isOtherTempNamespace(RelationGetNamespace(rel)))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move temporary tables of other sessions")));


	
	oldTableSpace = rel->rd_rel->reltablespace;
	if (newTableSpace == oldTableSpace || (newTableSpace == MyDatabaseTableSpace && oldTableSpace == 0))
	{
		relation_close(rel, NoLock);
		return;
	}

	reltoastrelid = rel->rd_rel->reltoastrelid;
	reltoastidxid = rel->rd_rel->reltoastidxid;

	
	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(tableOid), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", tableOid);
	rd_rel = (Form_pg_class) GETSTRUCT(tuple);

	
	
	newrnode = rel->rd_node;
	newrnode.spcNode = newTableSpace;

	dstrel = smgropen(newrnode);
	smgrcreate(dstrel, rel->rd_istemp, false);

	
	copy_relation_data(rel, dstrel);

	
	RelationOpenSmgr(rel);
	smgrscheduleunlink(rel->rd_smgr, rel->rd_istemp);

	
	smgrclose(dstrel);

	
	rd_rel->reltablespace = (newTableSpace == MyDatabaseTableSpace) ? InvalidOid : newTableSpace;
	simple_heap_update(pg_class, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_class, tuple);

	heap_freetuple(tuple);

	heap_close(pg_class, RowExclusiveLock);

	relation_close(rel, NoLock);

	
	CommandCounterIncrement();

	
	if (OidIsValid(reltoastrelid))
		ATExecSetTableSpace(reltoastrelid, newTableSpace);
	if (OidIsValid(reltoastidxid))
		ATExecSetTableSpace(reltoastidxid, newTableSpace);
}


static void copy_relation_data(Relation rel, SMgrRelation dst)
{
	SMgrRelation src;
	bool		use_wal;
	BlockNumber nblocks;
	BlockNumber blkno;
	char		buf[BLCKSZ];
	Page		page = (Page) buf;

	
	FlushRelationBuffers(rel);

	
	use_wal = XLogArchivingActive() && !rel->rd_istemp;

	nblocks = RelationGetNumberOfBlocks(rel);
	
	src = rel->rd_smgr;

	for (blkno = 0; blkno < nblocks; blkno++)
	{
		smgrread(src, blkno, buf);

		
		if (use_wal)
		{
			xl_heap_newpage xlrec;
			XLogRecPtr	recptr;
			XLogRecData rdata[2];

			
			START_CRIT_SECTION();

			xlrec.node = dst->smgr_rnode;
			xlrec.blkno = blkno;

			rdata[0].data = (char *) &xlrec;
			rdata[0].len = SizeOfHeapNewpage;
			rdata[0].buffer = InvalidBuffer;
			rdata[0].next = &(rdata[1]);

			rdata[1].data = (char *) page;
			rdata[1].len = BLCKSZ;
			rdata[1].buffer = InvalidBuffer;
			rdata[1].next = NULL;

			recptr = XLogInsert(RM_HEAP_ID, XLOG_HEAP_NEWPAGE, rdata);

			PageSetLSN(page, recptr);
			PageSetTLI(page, ThisTimeLineID);

			END_CRIT_SECTION();
		}

		
		smgrextend(dst, blkno, buf, true);
	}

	
	if (!rel->rd_istemp)
		smgrimmedsync(dst);
}


static void ATExecEnableDisableTrigger(Relation rel, char *trigname, bool enable, bool skip_system)

{
	EnableDisableTrigger(rel, trigname, enable, skip_system);
}


static void ATExecAddInherit(Relation child_rel, RangeVar *parent)
{
	Relation	parent_rel, catalogRelation;
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	inheritsTuple;
	int32		inhseqno;
	List	   *children;

	
	parent_rel = heap_openrv(parent, AccessShareLock);

	
	ATSimplePermissions(parent_rel, false);

	
	if (!isTempNamespace(RelationGetNamespace(child_rel)) && isTempNamespace(RelationGetNamespace(parent_rel)))
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot inherit from temporary relation \"%s\"", RelationGetRelationName(parent_rel))));



	
	catalogRelation = heap_open(InheritsRelationId, RowExclusiveLock);
	ScanKeyInit(&key, Anum_pg_inherits_inhrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(child_rel)));


	scan = systable_beginscan(catalogRelation, InheritsRelidSeqnoIndexId, true, SnapshotNow, 1, &key);

	
	inhseqno = 0;
	while (HeapTupleIsValid(inheritsTuple = systable_getnext(scan)))
	{
		Form_pg_inherits inh = (Form_pg_inherits) GETSTRUCT(inheritsTuple);

		if (inh->inhparent == RelationGetRelid(parent_rel))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("inherited relation \"%s\" duplicated", RelationGetRelationName(parent_rel))));


		if (inh->inhseqno > inhseqno)
			inhseqno = inh->inhseqno;
	}
	systable_endscan(scan);

	
	children = find_all_inheritors(RelationGetRelid(child_rel));

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
	return DatumGetCString(DirectFunctionCall1(textout, expr));
}


static void MergeAttributesIntoExisting(Relation child_rel, Relation parent_rel)
{
	Relation	attrrel;
	AttrNumber	parent_attno;
	int			parent_natts;
	TupleDesc	tupleDesc;
	TupleConstr *constr;
	HeapTuple	tuple;

	attrrel = heap_open(AttributeRelationId, RowExclusiveLock);

	tupleDesc = RelationGetDescr(parent_rel);
	parent_natts = tupleDesc->natts;
	constr = tupleDesc->constr;

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
	Relation	catalogRelation;
	TupleDesc	tupleDesc;
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	constraintTuple;
	ListCell   *elem;
	List	   *constraints;

	
	catalogRelation = heap_open(ConstraintRelationId, AccessShareLock);
	tupleDesc = RelationGetDescr(catalogRelation);

	ScanKeyInit(&key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(child_rel)));


	scan = systable_beginscan(catalogRelation, ConstraintRelidIndexId, true, SnapshotNow, 1, &key);

	constraints = NIL;
	while (HeapTupleIsValid(constraintTuple = systable_getnext(scan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(constraintTuple);

		if (con->contype != CONSTRAINT_CHECK)
			continue;

		constraints = lappend(constraints, heap_copytuple(constraintTuple));
	}

	systable_endscan(scan);

	
	ScanKeyInit(&key, Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(parent_rel)));


	scan = systable_beginscan(catalogRelation, ConstraintRelidIndexId, true, SnapshotNow, 1, &key);

	while (HeapTupleIsValid(constraintTuple = systable_getnext(scan)))
	{
		Form_pg_constraint parent_con = (Form_pg_constraint) GETSTRUCT(constraintTuple);
		bool		found = false;
		Form_pg_constraint child_con = NULL;
		HeapTuple	child_contuple = NULL;

		if (parent_con->contype != CONSTRAINT_CHECK)
			continue;

		foreach(elem, constraints)
		{
			child_contuple = (HeapTuple) lfirst(elem);
			child_con = (Form_pg_constraint) GETSTRUCT(child_contuple);
			if (strcmp(NameStr(parent_con->conname), NameStr(child_con->conname)) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("child table is missing constraint \"%s\"", NameStr(parent_con->conname))));



		if (parent_con->condeferrable != child_con->condeferrable || parent_con->condeferred != child_con->condeferred || strcmp(decompile_conbin(constraintTuple, tupleDesc), decompile_conbin(child_contuple, tupleDesc)) != 0)


			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("constraint definition for check constraint \"%s\" does not match", NameStr(parent_con->conname))));



		
	}

	systable_endscan(scan);
	heap_close(catalogRelation, AccessShareLock);
}


static void ATExecDropInherit(Relation rel, RangeVar *parent)
{
	Relation	parent_rel;
	Relation	catalogRelation;
	SysScanDesc scan;
	ScanKeyData key[3];
	HeapTuple	inheritsTuple, attributeTuple, depTuple;

	bool		found = false;

	
	parent_rel = heap_openrv(parent, AccessShareLock);

	

	
	catalogRelation = heap_open(InheritsRelationId, RowExclusiveLock);
	ScanKeyInit(&key[0], Anum_pg_inherits_inhrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	scan = systable_beginscan(catalogRelation, InheritsRelidSeqnoIndexId, true, SnapshotNow, 1, key);

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


	scan = systable_beginscan(catalogRelation, AttributeRelidNumIndexId, true, SnapshotNow, 1, key);
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

	
	catalogRelation = heap_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	ScanKeyInit(&key[2], Anum_pg_depend_objsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum(0));



	scan = systable_beginscan(catalogRelation, DependDependerIndexId, true, SnapshotNow, 3, key);

	while (HeapTupleIsValid(depTuple = systable_getnext(scan)))
	{
		Form_pg_depend dep = (Form_pg_depend) GETSTRUCT(depTuple);

		if (dep->refclassid == RelationRelationId && dep->refobjid == RelationGetRelid(parent_rel) && dep->refobjsubid == 0 && dep->deptype == DEPENDENCY_NORMAL)


			simple_heap_delete(catalogRelation, &depTuple->t_self);
	}

	systable_endscan(scan);
	heap_close(catalogRelation, RowExclusiveLock);

	
	heap_close(parent_rel, NoLock);
}



void AlterTableNamespace(RangeVar *relation, const char *newschema)
{
	Relation	rel;
	Oid			relid;
	Oid			oldNspOid;
	Oid			nspOid;
	Relation	classRel;

	rel = heap_openrv(relation, AccessExclusiveLock);

	relid = RelationGetRelid(rel);
	oldNspOid = RelationGetNamespace(rel);

	
	if (rel->rd_rel->relkind == RELKIND_TOASTVALUE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a TOAST relation", RelationGetRelationName(rel))));



	
	if (rel->rd_rel->relkind == RELKIND_SEQUENCE)
	{
		Oid			tableId;
		int32		colId;

		if (sequenceIsOwned(relid, &tableId, &colId))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move an owned sequence into another schema"), errdetail("Sequence \"%s\" is linked to table \"%s\".", RelationGetRelationName(rel), get_rel_name(tableId))));




	}

	
	nspOid = LookupCreationNamespace(newschema);

	if (oldNspOid == nspOid)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" is already in schema \"%s\"", RelationGetRelationName(rel), newschema)));




	
	if (isAnyTempNamespace(nspOid) || isAnyTempNamespace(oldNspOid))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move objects into or out of temporary schemas")));


	
	if (nspOid == PG_TOAST_NAMESPACE || oldNspOid == PG_TOAST_NAMESPACE)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot move objects into or out of TOAST schema")));


	
	classRel = heap_open(RelationRelationId, RowExclusiveLock);

	AlterRelationNamespaceInternal(classRel, relid, oldNspOid, nspOid, true);

	
	AlterTypeNamespaceInternal(rel->rd_rel->reltype, nspOid, false);

	
	if (rel->rd_rel->relkind == RELKIND_RELATION)
	{
		AlterIndexNamespaces(classRel, rel, oldNspOid, nspOid);
		AlterSeqNamespaces(classRel, rel, oldNspOid, nspOid, newschema);
		AlterConstraintNamespaces(relid, oldNspOid, nspOid, false);
	}

	heap_close(classRel, RowExclusiveLock);

	
	relation_close(rel, NoLock);
}


void AlterRelationNamespaceInternal(Relation classRel, Oid relOid, Oid oldNspOid, Oid newNspOid, bool hasDependEntry)


{
	HeapTuple	classTup;
	Form_pg_class classForm;

	classTup = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(relOid), 0, 0, 0);

	if (!HeapTupleIsValid(classTup))
		elog(ERROR, "cache lookup failed for relation %u", relOid);
	classForm = (Form_pg_class) GETSTRUCT(classTup);

	Assert(classForm->relnamespace == oldNspOid);

	
	if (get_relname_relid(NameStr(classForm->relname), newNspOid) != InvalidOid)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists in schema \"%s\"", NameStr(classForm->relname), get_namespace_name(newNspOid))));




	
	classForm->relnamespace = newNspOid;

	simple_heap_update(classRel, &classTup->t_self, classTup);
	CatalogUpdateIndexes(classRel, classTup);

	
	if (hasDependEntry && changeDependencyFor(RelationRelationId, relOid, NamespaceRelationId, oldNspOid, newNspOid) != 1)

		elog(ERROR, "failed to change schema dependency for relation \"%s\"", NameStr(classForm->relname));

	heap_freetuple(classTup);
}


static void AlterIndexNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid)

{
	List	   *indexList;
	ListCell   *l;

	indexList = RelationGetIndexList(rel);

	foreach(l, indexList)
	{
		Oid			indexOid = lfirst_oid(l);

		
		AlterRelationNamespaceInternal(classRel, indexOid, oldNspOid, newNspOid, false);

	}

	list_free(indexList);
}


static void AlterSeqNamespaces(Relation classRel, Relation rel, Oid oldNspOid, Oid newNspOid, const char *newNspName)

{
	Relation	depRel;
	SysScanDesc scan;
	ScanKeyData key[2];
	HeapTuple	tup;

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	

	scan = systable_beginscan(depRel, DependReferenceIndexId, true, SnapshotNow, 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend depForm = (Form_pg_depend) GETSTRUCT(tup);
		Relation	seqRel;

		
		if (depForm->refobjsubid == 0 || depForm->classid != RelationRelationId || depForm->objsubid != 0 || depForm->deptype != DEPENDENCY_AUTO)


			continue;

		
		seqRel = relation_open(depForm->objid, AccessExclusiveLock);

		
		if (RelationGetForm(seqRel)->relkind != RELKIND_SEQUENCE)
		{
			
			relation_close(seqRel, AccessExclusiveLock);
			continue;
		}

		
		AlterRelationNamespaceInternal(classRel, depForm->objid, oldNspOid, newNspOid, true);


		
		AlterTypeNamespaceInternal(RelationGetForm(seqRel)->reltype, newNspOid, false);

		
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
				oids_to_truncate = lappend_oid(oids_to_truncate, oc->relid);
				break;
			case ONCOMMIT_DROP:
				{
					ObjectAddress object;

					object.classId = RelationRelationId;
					object.objectId = oc->relid;
					object.objectSubId = 0;
					performDeletion(&object, DROP_CASCADE);

					
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
