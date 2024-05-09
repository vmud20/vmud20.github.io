








































typedef struct {
	ParseState *pstate;			
	const char *stmtType;		
	RangeVar   *relation;		
	Relation	rel;			
	List	   *inhRelations;	
	bool		isforeign;		
	bool		isalter;		
	bool		hasoids;		
	List	   *columns;		
	List	   *ckconstraints;	
	List	   *fkconstraints;	
	List	   *ixconstraints;	
	List	   *inh_indexes;	
	List	   *blist;			
	List	   *alist;			
	IndexStmt  *pkey;			
} CreateStmtContext;


typedef struct {
	const char *stmtType;		
	char	   *schemaname;		
	char	   *authid;			
	List	   *sequences;		
	List	   *tables;			
	List	   *views;			
	List	   *indexes;		
	List	   *triggers;		
	List	   *grants;			
} CreateSchemaStmtContext;


static void transformColumnDefinition(CreateStmtContext *cxt, ColumnDef *column);
static void transformTableConstraint(CreateStmtContext *cxt, Constraint *constraint);
static void transformTableLikeClause(CreateStmtContext *cxt, TableLikeClause *table_like_clause);
static void transformOfType(CreateStmtContext *cxt, TypeName *ofTypename);
static IndexStmt *generateClonedIndexStmt(CreateStmtContext *cxt, Relation source_idx, const AttrNumber *attmap, int attmap_length);

static List *get_collation(Oid collation, Oid actual_datatype);
static List *get_opclass(Oid opclass, Oid actual_datatype);
static void transformIndexConstraints(CreateStmtContext *cxt);
static IndexStmt *transformIndexConstraint(Constraint *constraint, CreateStmtContext *cxt);
static void transformFKConstraints(CreateStmtContext *cxt, bool skipValidation, bool isAddConstraint);

static void transformConstraintAttrs(CreateStmtContext *cxt, List *constraintList);
static void transformColumnType(CreateStmtContext *cxt, ColumnDef *column);
static void setSchemaName(char *context_schema, char **stmt_schema_name);



List * transformCreateStmt(CreateStmt *stmt, const char *queryString)
{
	ParseState *pstate;
	CreateStmtContext cxt;
	List	   *result;
	List	   *save_alist;
	ListCell   *elements;
	Oid			namespaceid;
	Oid			existing_relid;

	
	stmt = (CreateStmt *) copyObject(stmt);

	
	namespaceid = RangeVarGetAndCheckCreationNamespace(stmt->relation, NoLock, &existing_relid);


	
	if (stmt->if_not_exists && OidIsValid(existing_relid))
	{
		ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists, skipping", stmt->relation->relname)));


		return NIL;
	}

	
	if (stmt->relation->schemaname == NULL && stmt->relation->relpersistence != RELPERSISTENCE_TEMP)
		stmt->relation->schemaname = get_namespace_name(namespaceid);

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	cxt.pstate = pstate;
	if (IsA(stmt, CreateForeignTableStmt))
	{
		cxt.stmtType = "CREATE FOREIGN TABLE";
		cxt.isforeign = true;
	}
	else {
		cxt.stmtType = "CREATE TABLE";
		cxt.isforeign = false;
	}
	cxt.relation = stmt->relation;
	cxt.rel = NULL;
	cxt.inhRelations = stmt->inhRelations;
	cxt.isalter = false;
	cxt.columns = NIL;
	cxt.ckconstraints = NIL;
	cxt.fkconstraints = NIL;
	cxt.ixconstraints = NIL;
	cxt.inh_indexes = NIL;
	cxt.blist = NIL;
	cxt.alist = NIL;
	cxt.pkey = NULL;
	cxt.hasoids = interpretOidsOption(stmt->options, true);

	Assert(!stmt->ofTypename || !stmt->inhRelations);	

	if (stmt->ofTypename)
		transformOfType(&cxt, stmt->ofTypename);

	
	foreach(elements, stmt->tableElts)
	{
		Node	   *element = lfirst(elements);

		switch (nodeTag(element))
		{
			case T_ColumnDef:
				transformColumnDefinition(&cxt, (ColumnDef *) element);
				break;

			case T_Constraint:
				transformTableConstraint(&cxt, (Constraint *) element);
				break;

			case T_TableLikeClause:
				transformTableLikeClause(&cxt, (TableLikeClause *) element);
				break;

			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(element));
				break;
		}
	}

	
	save_alist = cxt.alist;
	cxt.alist = NIL;

	Assert(stmt->constraints == NIL);

	
	transformIndexConstraints(&cxt);

	
	transformFKConstraints(&cxt, true, false);

	
	stmt->tableElts = cxt.columns;
	stmt->constraints = cxt.ckconstraints;

	result = lappend(cxt.blist, stmt);
	result = list_concat(result, cxt.alist);
	result = list_concat(result, save_alist);

	return result;
}


static void transformColumnDefinition(CreateStmtContext *cxt, ColumnDef *column)
{
	bool		is_serial;
	bool		saw_nullable;
	bool		saw_default;
	Constraint *constraint;
	ListCell   *clist;

	cxt->columns = lappend(cxt->columns, column);

	
	is_serial = false;
	if (column->typeName && list_length(column->typeName->names) == 1 && !column->typeName->pct_type)

	{
		char	   *typname = strVal(linitial(column->typeName->names));

		if (strcmp(typname, "smallserial") == 0 || strcmp(typname, "serial2") == 0)
		{
			is_serial = true;
			column->typeName->names = NIL;
			column->typeName->typeOid = INT2OID;
		}
		else if (strcmp(typname, "serial") == 0 || strcmp(typname, "serial4") == 0)
		{
			is_serial = true;
			column->typeName->names = NIL;
			column->typeName->typeOid = INT4OID;
		}
		else if (strcmp(typname, "bigserial") == 0 || strcmp(typname, "serial8") == 0)
		{
			is_serial = true;
			column->typeName->names = NIL;
			column->typeName->typeOid = INT8OID;
		}

		
		if (is_serial && column->typeName->arrayBounds != NIL)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("array of serial is not implemented"), parser_errposition(cxt->pstate, column->typeName->location)));



	}

	
	if (column->typeName)
		transformColumnType(cxt, column);

	
	if (is_serial)
	{
		Oid			snamespaceid;
		char	   *snamespace;
		char	   *sname;
		char	   *qstring;
		A_Const    *snamenode;
		TypeCast   *castnode;
		FuncCall   *funccallnode;
		CreateSeqStmt *seqstmt;
		AlterSeqStmt *altseqstmt;
		List	   *attnamelist;

		
		if (cxt->rel)
			snamespaceid = RelationGetNamespace(cxt->rel);
		else {
			snamespaceid = RangeVarGetCreationNamespace(cxt->relation);
			RangeVarAdjustRelationPersistence(cxt->relation, snamespaceid);
		}
		snamespace = get_namespace_name(snamespaceid);
		sname = ChooseRelationName(cxt->relation->relname, column->colname, "seq", snamespaceid);



		ereport(DEBUG1, (errmsg("%s will create implicit sequence \"%s\" for serial column \"%s.%s\"", cxt->stmtType, sname, cxt->relation->relname, column->colname)));



		
		seqstmt = makeNode(CreateSeqStmt);
		seqstmt->sequence = makeRangeVar(snamespace, sname, -1);
		seqstmt->options = NIL;

		
		if (cxt->rel)
			seqstmt->ownerId = cxt->rel->rd_rel->relowner;
		else seqstmt->ownerId = InvalidOid;

		cxt->blist = lappend(cxt->blist, seqstmt);

		
		altseqstmt = makeNode(AlterSeqStmt);
		altseqstmt->sequence = makeRangeVar(snamespace, sname, -1);
		attnamelist = list_make3(makeString(snamespace), makeString(cxt->relation->relname), makeString(column->colname));

		altseqstmt->options = list_make1(makeDefElem("owned_by", (Node *) attnamelist));

		cxt->alist = lappend(cxt->alist, altseqstmt);

		
		qstring = quote_qualified_identifier(snamespace, sname);
		snamenode = makeNode(A_Const);
		snamenode->val.type = T_String;
		snamenode->val.val.str = qstring;
		snamenode->location = -1;
		castnode = makeNode(TypeCast);
		castnode->typeName = SystemTypeName("regclass");
		castnode->arg = (Node *) snamenode;
		castnode->location = -1;
		funccallnode = makeFuncCall(SystemFuncName("nextval"), list_make1(castnode), -1);

		constraint = makeNode(Constraint);
		constraint->contype = CONSTR_DEFAULT;
		constraint->location = -1;
		constraint->raw_expr = (Node *) funccallnode;
		constraint->cooked_expr = NULL;
		column->constraints = lappend(column->constraints, constraint);

		constraint = makeNode(Constraint);
		constraint->contype = CONSTR_NOTNULL;
		constraint->location = -1;
		column->constraints = lappend(column->constraints, constraint);
	}

	
	transformConstraintAttrs(cxt, column->constraints);

	saw_nullable = false;
	saw_default = false;

	foreach(clist, column->constraints)
	{
		constraint = lfirst(clist);
		Assert(IsA(constraint, Constraint));

		switch (constraint->contype)
		{
			case CONSTR_NULL:
				if (saw_nullable && column->is_not_null)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting NULL/NOT NULL declarations for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->is_not_null = FALSE;
				saw_nullable = true;
				break;

			case CONSTR_NOTNULL:
				if (saw_nullable && !column->is_not_null)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting NULL/NOT NULL declarations for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->is_not_null = TRUE;
				saw_nullable = true;
				break;

			case CONSTR_DEFAULT:
				if (saw_default)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple default values specified for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->raw_default = constraint->raw_expr;
				Assert(constraint->cooked_expr == NULL);
				saw_default = true;
				break;

			case CONSTR_CHECK:
				if (cxt->isforeign)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



				cxt->ckconstraints = lappend(cxt->ckconstraints, constraint);
				break;

			case CONSTR_PRIMARY:
			case CONSTR_UNIQUE:
				if (cxt->isforeign)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



				if (constraint->keys == NIL)
					constraint->keys = list_make1(makeString(column->colname));
				cxt->ixconstraints = lappend(cxt->ixconstraints, constraint);
				break;

			case CONSTR_EXCLUSION:
				
				elog(ERROR, "column exclusion constraints are not supported");
				break;

			case CONSTR_FOREIGN:
				if (cxt->isforeign)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));




				
				constraint->fk_attrs = list_make1(makeString(column->colname));
				cxt->fkconstraints = lappend(cxt->fkconstraints, constraint);
				break;

			case CONSTR_ATTR_DEFERRABLE:
			case CONSTR_ATTR_NOT_DEFERRABLE:
			case CONSTR_ATTR_DEFERRED:
			case CONSTR_ATTR_IMMEDIATE:
				
				break;

			default:
				elog(ERROR, "unrecognized constraint type: %d", constraint->contype);
				break;
		}
	}

	
	if (column->fdwoptions != NIL)
	{
		AlterTableStmt *stmt;
		AlterTableCmd *cmd;

		cmd = makeNode(AlterTableCmd);
		cmd->subtype = AT_AlterColumnGenericOptions;
		cmd->name = column->colname;
		cmd->def = (Node *) column->fdwoptions;
		cmd->behavior = DROP_RESTRICT;
		cmd->missing_ok = false;

		stmt = makeNode(AlterTableStmt);
		stmt->relation = cxt->relation;
		stmt->cmds = NIL;
		stmt->relkind = OBJECT_FOREIGN_TABLE;
		stmt->cmds = lappend(stmt->cmds, cmd);

		cxt->alist = lappend(cxt->alist, stmt);
	}
}


static void transformTableConstraint(CreateStmtContext *cxt, Constraint *constraint)
{
	if (cxt->isforeign)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));




	switch (constraint->contype)
	{
		case CONSTR_PRIMARY:
		case CONSTR_UNIQUE:
		case CONSTR_EXCLUSION:
			cxt->ixconstraints = lappend(cxt->ixconstraints, constraint);
			break;

		case CONSTR_CHECK:
			cxt->ckconstraints = lappend(cxt->ckconstraints, constraint);
			break;

		case CONSTR_FOREIGN:
			cxt->fkconstraints = lappend(cxt->fkconstraints, constraint);
			break;

		case CONSTR_NULL:
		case CONSTR_NOTNULL:
		case CONSTR_DEFAULT:
		case CONSTR_ATTR_DEFERRABLE:
		case CONSTR_ATTR_NOT_DEFERRABLE:
		case CONSTR_ATTR_DEFERRED:
		case CONSTR_ATTR_IMMEDIATE:
			elog(ERROR, "invalid context for constraint type %d", constraint->contype);
			break;

		default:
			elog(ERROR, "unrecognized constraint type: %d", constraint->contype);
			break;
	}
}


static void transformTableLikeClause(CreateStmtContext *cxt, TableLikeClause *table_like_clause)
{
	AttrNumber	parent_attno;
	Relation	relation;
	TupleDesc	tupleDesc;
	TupleConstr *constr;
	AttrNumber *attmap;
	AclResult	aclresult;
	char	   *comment;
	ParseCallbackState pcbstate;

	setup_parser_errposition_callback(&pcbstate, cxt->pstate, table_like_clause->relation->location);

	
	if (cxt->isforeign)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("LIKE is not supported for creating foreign tables")));


	relation = relation_openrv(table_like_clause->relation, AccessShareLock);

	if (relation->rd_rel->relkind != RELKIND_RELATION && relation->rd_rel->relkind != RELKIND_VIEW && relation->rd_rel->relkind != RELKIND_MATVIEW && relation->rd_rel->relkind != RELKIND_COMPOSITE_TYPE && relation->rd_rel->relkind != RELKIND_FOREIGN_TABLE)



		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, materialized view, composite type, or foreign table", RelationGetRelationName(relation))));



	cancel_parser_errposition_callback(&pcbstate);

	
	if (relation->rd_rel->relkind == RELKIND_COMPOSITE_TYPE)
	{
		aclresult = pg_type_aclcheck(relation->rd_rel->reltype, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TYPE, RelationGetRelationName(relation));
	}
	else {
		aclresult = pg_class_aclcheck(RelationGetRelid(relation), GetUserId(), ACL_SELECT);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(relation));
	}

	tupleDesc = RelationGetDescr(relation);
	constr = tupleDesc->constr;

	
	attmap = (AttrNumber *) palloc0(sizeof(AttrNumber) * tupleDesc->natts);

	
	for (parent_attno = 1; parent_attno <= tupleDesc->natts;
		 parent_attno++)
	{
		Form_pg_attribute attribute = tupleDesc->attrs[parent_attno - 1];
		char	   *attributeName = NameStr(attribute->attname);
		ColumnDef  *def;

		
		if (attribute->attisdropped)
			continue;

		
		def = makeNode(ColumnDef);
		def->colname = pstrdup(attributeName);
		def->typeName = makeTypeNameFromOid(attribute->atttypid, attribute->atttypmod);
		def->inhcount = 0;
		def->is_local = true;
		def->is_not_null = attribute->attnotnull;
		def->is_from_type = false;
		def->storage = 0;
		def->raw_default = NULL;
		def->cooked_default = NULL;
		def->collClause = NULL;
		def->collOid = attribute->attcollation;
		def->constraints = NIL;
		def->location = -1;

		
		cxt->columns = lappend(cxt->columns, def);

		attmap[parent_attno - 1] = list_length(cxt->columns);

		
		if (attribute->atthasdef && (table_like_clause->options & CREATE_TABLE_LIKE_DEFAULTS))
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

			

			def->cooked_default = this_default;
		}

		
		if (table_like_clause->options & CREATE_TABLE_LIKE_STORAGE)
			def->storage = attribute->attstorage;
		else def->storage = 0;

		
		if ((table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS) && (comment = GetComment(attribute->attrelid, RelationRelationId, attribute->attnum)) != NULL)


		{
			CommentStmt *stmt = makeNode(CommentStmt);

			stmt->objtype = OBJECT_COLUMN;
			stmt->objname = list_make3(makeString(cxt->relation->schemaname), makeString(cxt->relation->relname), makeString(def->colname));

			stmt->objargs = NIL;
			stmt->comment = comment;

			cxt->alist = lappend(cxt->alist, stmt);
		}
	}

	
	if ((table_like_clause->options & CREATE_TABLE_LIKE_CONSTRAINTS) && tupleDesc->constr)
	{
		int			ccnum;

		for (ccnum = 0; ccnum < tupleDesc->constr->num_check; ccnum++)
		{
			char	   *ccname = tupleDesc->constr->check[ccnum].ccname;
			char	   *ccbin = tupleDesc->constr->check[ccnum].ccbin;
			Constraint *n = makeNode(Constraint);
			Node	   *ccbin_node;
			bool		found_whole_row;

			ccbin_node = map_variable_attnos(stringToNode(ccbin), 1, 0, attmap, tupleDesc->natts, &found_whole_row);



			
			if (found_whole_row)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Constraint \"%s\" contains a whole-row reference to table \"%s\".", ccname, RelationGetRelationName(relation))));





			n->contype = CONSTR_CHECK;
			n->location = -1;
			n->conname = pstrdup(ccname);
			n->raw_expr = NULL;
			n->cooked_expr = nodeToString(ccbin_node);
			cxt->ckconstraints = lappend(cxt->ckconstraints, n);

			
			if ((table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS) && (comment = GetComment(get_relation_constraint_oid(RelationGetRelid(relation), n->conname, false), ConstraintRelationId, 0)) != NULL)



			{
				CommentStmt *stmt = makeNode(CommentStmt);

				stmt->objtype = OBJECT_CONSTRAINT;
				stmt->objname = list_make3(makeString(cxt->relation->schemaname), makeString(cxt->relation->relname), makeString(n->conname));

				stmt->objargs = NIL;
				stmt->comment = comment;

				cxt->alist = lappend(cxt->alist, stmt);
			}
		}
	}

	
	if ((table_like_clause->options & CREATE_TABLE_LIKE_INDEXES) && relation->rd_rel->relhasindex)
	{
		List	   *parent_indexes;
		ListCell   *l;

		parent_indexes = RelationGetIndexList(relation);

		foreach(l, parent_indexes)
		{
			Oid			parent_index_oid = lfirst_oid(l);
			Relation	parent_index;
			IndexStmt  *index_stmt;

			parent_index = index_open(parent_index_oid, AccessShareLock);

			
			index_stmt = generateClonedIndexStmt(cxt, parent_index, attmap, tupleDesc->natts);

			
			if (table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS)
			{
				comment = GetComment(parent_index_oid, RelationRelationId, 0);

				
				index_stmt->idxcomment = comment;
			}

			
			cxt->inh_indexes = lappend(cxt->inh_indexes, index_stmt);

			index_close(parent_index, AccessShareLock);
		}
	}

	
	heap_close(relation, NoLock);
}

static void transformOfType(CreateStmtContext *cxt, TypeName *ofTypename)
{
	HeapTuple	tuple;
	TupleDesc	tupdesc;
	int			i;
	Oid			ofTypeId;

	AssertArg(ofTypename);

	tuple = typenameType(NULL, ofTypename, NULL);
	check_of_type(tuple);
	ofTypeId = HeapTupleGetOid(tuple);
	ofTypename->typeOid = ofTypeId;		

	tupdesc = lookup_rowtype_tupdesc(ofTypeId, -1);
	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = tupdesc->attrs[i];
		ColumnDef  *n;

		if (attr->attisdropped)
			continue;

		n = makeNode(ColumnDef);
		n->colname = pstrdup(NameStr(attr->attname));
		n->typeName = makeTypeNameFromOid(attr->atttypid, attr->atttypmod);
		n->inhcount = 0;
		n->is_local = true;
		n->is_not_null = false;
		n->is_from_type = true;
		n->storage = 0;
		n->raw_default = NULL;
		n->cooked_default = NULL;
		n->collClause = NULL;
		n->collOid = attr->attcollation;
		n->constraints = NIL;
		n->location = -1;
		cxt->columns = lappend(cxt->columns, n);
	}
	DecrTupleDescRefCount(tupdesc);

	ReleaseSysCache(tuple);
}


static IndexStmt * generateClonedIndexStmt(CreateStmtContext *cxt, Relation source_idx, const AttrNumber *attmap, int attmap_length)

{
	Oid			source_relid = RelationGetRelid(source_idx);
	Form_pg_attribute *attrs = RelationGetDescr(source_idx)->attrs;
	HeapTuple	ht_idxrel;
	HeapTuple	ht_idx;
	Form_pg_class idxrelrec;
	Form_pg_index idxrec;
	Form_pg_am	amrec;
	oidvector  *indcollation;
	oidvector  *indclass;
	IndexStmt  *index;
	List	   *indexprs;
	ListCell   *indexpr_item;
	Oid			indrelid;
	int			keyno;
	Oid			keycoltype;
	Datum		datum;
	bool		isnull;

	
	ht_idxrel = SearchSysCache1(RELOID, ObjectIdGetDatum(source_relid));
	if (!HeapTupleIsValid(ht_idxrel))
		elog(ERROR, "cache lookup failed for relation %u", source_relid);
	idxrelrec = (Form_pg_class) GETSTRUCT(ht_idxrel);

	
	ht_idx = source_idx->rd_indextuple;
	idxrec = (Form_pg_index) GETSTRUCT(ht_idx);
	indrelid = idxrec->indrelid;

	
	amrec = source_idx->rd_am;

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indcollation, &isnull);
	Assert(!isnull);
	indcollation = (oidvector *) DatumGetPointer(datum);

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indclass, &isnull);
	Assert(!isnull);
	indclass = (oidvector *) DatumGetPointer(datum);

	
	index = makeNode(IndexStmt);
	index->relation = cxt->relation;
	index->accessMethod = pstrdup(NameStr(amrec->amname));
	if (OidIsValid(idxrelrec->reltablespace))
		index->tableSpace = get_tablespace_name(idxrelrec->reltablespace);
	else index->tableSpace = NULL;
	index->excludeOpNames = NIL;
	index->idxcomment = NULL;
	index->indexOid = InvalidOid;
	index->oldNode = InvalidOid;
	index->unique = idxrec->indisunique;
	index->primary = idxrec->indisprimary;
	index->concurrent = false;

	
	index->idxname = NULL;

	
	if (index->primary || index->unique || idxrec->indisexclusion)
	{
		Oid			constraintId = get_index_constraint(source_relid);

		if (OidIsValid(constraintId))
		{
			HeapTuple	ht_constr;
			Form_pg_constraint conrec;

			ht_constr = SearchSysCache1(CONSTROID, ObjectIdGetDatum(constraintId));
			if (!HeapTupleIsValid(ht_constr))
				elog(ERROR, "cache lookup failed for constraint %u", constraintId);
			conrec = (Form_pg_constraint) GETSTRUCT(ht_constr);

			index->isconstraint = true;
			index->deferrable = conrec->condeferrable;
			index->initdeferred = conrec->condeferred;

			
			if (idxrec->indisexclusion)
			{
				Datum	   *elems;
				int			nElems;
				int			i;

				Assert(conrec->contype == CONSTRAINT_EXCLUSION);
				
				datum = SysCacheGetAttr(CONSTROID, ht_constr, Anum_pg_constraint_conexclop, &isnull);

				if (isnull)
					elog(ERROR, "null conexclop for constraint %u", constraintId);

				deconstruct_array(DatumGetArrayTypeP(datum), OIDOID, sizeof(Oid), true, 'i', &elems, NULL, &nElems);


				for (i = 0; i < nElems; i++)
				{
					Oid			operid = DatumGetObjectId(elems[i]);
					HeapTuple	opertup;
					Form_pg_operator operform;
					char	   *oprname;
					char	   *nspname;
					List	   *namelist;

					opertup = SearchSysCache1(OPEROID, ObjectIdGetDatum(operid));
					if (!HeapTupleIsValid(opertup))
						elog(ERROR, "cache lookup failed for operator %u", operid);
					operform = (Form_pg_operator) GETSTRUCT(opertup);
					oprname = pstrdup(NameStr(operform->oprname));
					
					nspname = get_namespace_name(operform->oprnamespace);
					namelist = list_make2(makeString(nspname), makeString(oprname));
					index->excludeOpNames = lappend(index->excludeOpNames, namelist);
					ReleaseSysCache(opertup);
				}
			}

			ReleaseSysCache(ht_constr);
		}
		else index->isconstraint = false;
	}
	else index->isconstraint = false;

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indexprs, &isnull);
	if (!isnull)
	{
		char	   *exprsString;

		exprsString = TextDatumGetCString(datum);
		indexprs = (List *) stringToNode(exprsString);
	}
	else indexprs = NIL;

	
	index->indexParams = NIL;

	indexpr_item = list_head(indexprs);
	for (keyno = 0; keyno < idxrec->indnatts; keyno++)
	{
		IndexElem  *iparam;
		AttrNumber	attnum = idxrec->indkey.values[keyno];
		int16		opt = source_idx->rd_indoption[keyno];

		iparam = makeNode(IndexElem);

		if (AttributeNumberIsValid(attnum))
		{
			
			char	   *attname;

			attname = get_relid_attribute_name(indrelid, attnum);
			keycoltype = get_atttype(indrelid, attnum);

			iparam->name = attname;
			iparam->expr = NULL;
		}
		else {
			
			Node	   *indexkey;
			bool		found_whole_row;

			if (indexpr_item == NULL)
				elog(ERROR, "too few entries in indexprs list");
			indexkey = (Node *) lfirst(indexpr_item);
			indexpr_item = lnext(indexpr_item);

			
			indexkey = map_variable_attnos(indexkey, 1, 0, attmap, attmap_length, &found_whole_row);



			
			if (found_whole_row)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Index \"%s\" contains a whole-row table reference.", RelationGetRelationName(source_idx))));




			iparam->name = NULL;
			iparam->expr = indexkey;

			keycoltype = exprType(indexkey);
		}

		
		iparam->indexcolname = pstrdup(NameStr(attrs[keyno]->attname));

		
		iparam->collation = get_collation(indcollation->values[keyno], keycoltype);

		
		iparam->opclass = get_opclass(indclass->values[keyno], keycoltype);

		iparam->ordering = SORTBY_DEFAULT;
		iparam->nulls_ordering = SORTBY_NULLS_DEFAULT;

		
		if (amrec->amcanorder)
		{
			
			if (opt & INDOPTION_DESC)
			{
				iparam->ordering = SORTBY_DESC;
				if ((opt & INDOPTION_NULLS_FIRST) == 0)
					iparam->nulls_ordering = SORTBY_NULLS_LAST;
			}
			else {
				if (opt & INDOPTION_NULLS_FIRST)
					iparam->nulls_ordering = SORTBY_NULLS_FIRST;
			}
		}

		index->indexParams = lappend(index->indexParams, iparam);
	}

	
	datum = SysCacheGetAttr(RELOID, ht_idxrel, Anum_pg_class_reloptions, &isnull);
	if (!isnull)
		index->options = untransformRelOptions(datum);

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indpred, &isnull);
	if (!isnull)
	{
		char	   *pred_str;
		Node	   *pred_tree;
		bool		found_whole_row;

		
		pred_str = TextDatumGetCString(datum);
		pred_tree = (Node *) stringToNode(pred_str);

		
		pred_tree = map_variable_attnos(pred_tree, 1, 0, attmap, attmap_length, &found_whole_row);



		
		if (found_whole_row)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Index \"%s\" contains a whole-row table reference.", RelationGetRelationName(source_idx))));




		index->whereClause = pred_tree;
	}

	
	ReleaseSysCache(ht_idxrel);

	return index;
}


static List * get_collation(Oid collation, Oid actual_datatype)
{
	List	   *result;
	HeapTuple	ht_coll;
	Form_pg_collation coll_rec;
	char	   *nsp_name;
	char	   *coll_name;

	if (!OidIsValid(collation))
		return NIL;				
	if (collation == get_typcollation(actual_datatype))
		return NIL;				

	ht_coll = SearchSysCache1(COLLOID, ObjectIdGetDatum(collation));
	if (!HeapTupleIsValid(ht_coll))
		elog(ERROR, "cache lookup failed for collation %u", collation);
	coll_rec = (Form_pg_collation) GETSTRUCT(ht_coll);

	
	nsp_name = get_namespace_name(coll_rec->collnamespace);
	coll_name = pstrdup(NameStr(coll_rec->collname));
	result = list_make2(makeString(nsp_name), makeString(coll_name));

	ReleaseSysCache(ht_coll);
	return result;
}


static List * get_opclass(Oid opclass, Oid actual_datatype)
{
	List	   *result = NIL;
	HeapTuple	ht_opc;
	Form_pg_opclass opc_rec;

	ht_opc = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclass));
	if (!HeapTupleIsValid(ht_opc))
		elog(ERROR, "cache lookup failed for opclass %u", opclass);
	opc_rec = (Form_pg_opclass) GETSTRUCT(ht_opc);

	if (GetDefaultOpClass(actual_datatype, opc_rec->opcmethod) != opclass)
	{
		
		char	   *nsp_name = get_namespace_name(opc_rec->opcnamespace);
		char	   *opc_name = pstrdup(NameStr(opc_rec->opcname));

		result = list_make2(makeString(nsp_name), makeString(opc_name));
	}

	ReleaseSysCache(ht_opc);
	return result;
}



static void transformIndexConstraints(CreateStmtContext *cxt)
{
	IndexStmt  *index;
	List	   *indexlist = NIL;
	ListCell   *lc;

	
	foreach(lc, cxt->ixconstraints)
	{
		Constraint *constraint = (Constraint *) lfirst(lc);

		Assert(IsA(constraint, Constraint));
		Assert(constraint->contype == CONSTR_PRIMARY || constraint->contype == CONSTR_UNIQUE || constraint->contype == CONSTR_EXCLUSION);


		index = transformIndexConstraint(constraint, cxt);

		indexlist = lappend(indexlist, index);
	}

	
	foreach(lc, cxt->inh_indexes)
	{
		index = (IndexStmt *) lfirst(lc);

		if (index->primary)
		{
			if (cxt->pkey != NULL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("multiple primary keys for table \"%s\" are not allowed", cxt->relation->relname)));


			cxt->pkey = index;
		}

		indexlist = lappend(indexlist, index);
	}

	
	Assert(cxt->alist == NIL);
	if (cxt->pkey != NULL)
	{
		
		cxt->alist = list_make1(cxt->pkey);
	}

	foreach(lc, indexlist)
	{
		bool		keep = true;
		ListCell   *k;

		index = lfirst(lc);

		
		if (index == cxt->pkey)
			continue;

		foreach(k, cxt->alist)
		{
			IndexStmt  *priorindex = lfirst(k);

			if (equal(index->indexParams, priorindex->indexParams) && equal(index->whereClause, priorindex->whereClause) && equal(index->excludeOpNames, priorindex->excludeOpNames) && strcmp(index->accessMethod, priorindex->accessMethod) == 0 && index->deferrable == priorindex->deferrable && index->initdeferred == priorindex->initdeferred)




			{
				priorindex->unique |= index->unique;

				
				if (priorindex->idxname == NULL)
					priorindex->idxname = index->idxname;
				keep = false;
				break;
			}
		}

		if (keep)
			cxt->alist = lappend(cxt->alist, index);
	}
}


static IndexStmt * transformIndexConstraint(Constraint *constraint, CreateStmtContext *cxt)
{
	IndexStmt  *index;
	ListCell   *lc;

	index = makeNode(IndexStmt);

	index->unique = (constraint->contype != CONSTR_EXCLUSION);
	index->primary = (constraint->contype == CONSTR_PRIMARY);
	if (index->primary)
	{
		if (cxt->pkey != NULL)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("multiple primary keys for table \"%s\" are not allowed", cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));



		cxt->pkey = index;

		
	}
	index->isconstraint = true;
	index->deferrable = constraint->deferrable;
	index->initdeferred = constraint->initdeferred;

	if (constraint->conname != NULL)
		index->idxname = pstrdup(constraint->conname);
	else index->idxname = NULL;

	index->relation = cxt->relation;
	index->accessMethod = constraint->access_method ? constraint->access_method : DEFAULT_INDEX_TYPE;
	index->options = constraint->options;
	index->tableSpace = constraint->indexspace;
	index->whereClause = constraint->where_clause;
	index->indexParams = NIL;
	index->excludeOpNames = NIL;
	index->idxcomment = NULL;
	index->indexOid = InvalidOid;
	index->oldNode = InvalidOid;
	index->concurrent = false;

	
	if (constraint->indexname != NULL)
	{
		char	   *index_name = constraint->indexname;
		Relation	heap_rel = cxt->rel;
		Oid			index_oid;
		Relation	index_rel;
		Form_pg_index index_form;
		oidvector  *indclass;
		Datum		indclassDatum;
		bool		isnull;
		int			i;

		
		Assert(constraint->keys == NIL);

		
		Assert(constraint->contype == CONSTR_PRIMARY || constraint->contype == CONSTR_UNIQUE);

		
		if (!cxt->isalter)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use an existing index in CREATE TABLE"), parser_errposition(cxt->pstate, constraint->location)));



		
		index_oid = get_relname_relid(index_name, RelationGetNamespace(heap_rel));

		if (!OidIsValid(index_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("index \"%s\" does not exist", index_name), parser_errposition(cxt->pstate, constraint->location)));



		
		index_rel = index_open(index_oid, AccessShareLock);
		index_form = index_rel->rd_index;

		
		if (OidIsValid(get_index_constraint(index_oid)))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("index \"%s\" is already associated with a constraint", index_name), parser_errposition(cxt->pstate, constraint->location)));




		
		if (index_form->indrelid != RelationGetRelid(heap_rel))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("index \"%s\" does not belong to table \"%s\"", index_name, RelationGetRelationName(heap_rel)), parser_errposition(cxt->pstate, constraint->location)));




		if (!IndexIsValid(index_form))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("index \"%s\" is not valid", index_name), parser_errposition(cxt->pstate, constraint->location)));



		if (!index_form->indisunique)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a unique index", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




		if (RelationGetIndexExpressions(index_rel) != NIL)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" contains expressions", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




		if (RelationGetIndexPredicate(index_rel) != NIL)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a partial index", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




		
		if (!index_form->indimmediate && !constraint->deferrable)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a deferrable index", index_name), errdetail("Cannot create a non-deferrable constraint using a deferrable index."), parser_errposition(cxt->pstate, constraint->location)));




		
		if (index_rel->rd_rel->relam != get_am_oid(DEFAULT_INDEX_TYPE, false))
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" is not a btree", index_name), parser_errposition(cxt->pstate, constraint->location)));



		
		indclassDatum = SysCacheGetAttr(INDEXRELID, index_rel->rd_indextuple, Anum_pg_index_indclass, &isnull);
		Assert(!isnull);
		indclass = (oidvector *) DatumGetPointer(indclassDatum);

		for (i = 0; i < index_form->indnatts; i++)
		{
			int16		attnum = index_form->indkey.values[i];
			Form_pg_attribute attform;
			char	   *attname;
			Oid			defopclass;

			
			if (attnum > 0)
			{
				Assert(attnum <= heap_rel->rd_att->natts);
				attform = heap_rel->rd_att->attrs[attnum - 1];
			}
			else attform = SystemAttributeDefinition(attnum, heap_rel->rd_rel->relhasoids);

			attname = pstrdup(NameStr(attform->attname));

			
			defopclass = GetDefaultOpClass(attform->atttypid, index_rel->rd_rel->relam);
			if (indclass->values[i] != defopclass || index_rel->rd_indoption[i] != 0)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" does not have default sorting behavior", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




			constraint->keys = lappend(constraint->keys, makeString(attname));
		}

		
		relation_close(index_rel, NoLock);

		index->indexOid = index_oid;
	}

	
	if (constraint->contype == CONSTR_EXCLUSION)
	{
		foreach(lc, constraint->exclusions)
		{
			List	   *pair = (List *) lfirst(lc);
			IndexElem  *elem;
			List	   *opname;

			Assert(list_length(pair) == 2);
			elem = (IndexElem *) linitial(pair);
			Assert(IsA(elem, IndexElem));
			opname = (List *) lsecond(pair);
			Assert(IsA(opname, List));

			index->indexParams = lappend(index->indexParams, elem);
			index->excludeOpNames = lappend(index->excludeOpNames, opname);
		}

		return index;
	}

	
	foreach(lc, constraint->keys)
	{
		char	   *key = strVal(lfirst(lc));
		bool		found = false;
		ColumnDef  *column = NULL;
		ListCell   *columns;
		IndexElem  *iparam;

		foreach(columns, cxt->columns)
		{
			column = (ColumnDef *) lfirst(columns);
			Assert(IsA(column, ColumnDef));
			if (strcmp(column->colname, key) == 0)
			{
				found = true;
				break;
			}
		}
		if (found)
		{
			
			if (constraint->contype == CONSTR_PRIMARY)
				column->is_not_null = TRUE;
		}
		else if (SystemAttributeByName(key, cxt->hasoids) != NULL)
		{
			
			found = true;
		}
		else if (cxt->inhRelations)
		{
			
			ListCell   *inher;

			foreach(inher, cxt->inhRelations)
			{
				RangeVar   *inh = (RangeVar *) lfirst(inher);
				Relation	rel;
				int			count;

				Assert(IsA(inh, RangeVar));
				rel = heap_openrv(inh, AccessShareLock);
				if (rel->rd_rel->relkind != RELKIND_RELATION)
					ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table", inh->relname)));


				for (count = 0; count < rel->rd_att->natts; count++)
				{
					Form_pg_attribute inhattr = rel->rd_att->attrs[count];
					char	   *inhname = NameStr(inhattr->attname);

					if (inhattr->attisdropped)
						continue;
					if (strcmp(key, inhname) == 0)
					{
						found = true;

						
						break;
					}
				}
				heap_close(rel, NoLock);
				if (found)
					break;
			}
		}

		
		if (!found && !cxt->isalter)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" named in key does not exist", key), parser_errposition(cxt->pstate, constraint->location)));



		
		foreach(columns, index->indexParams)
		{
			iparam = (IndexElem *) lfirst(columns);
			if (iparam->name && strcmp(key, iparam->name) == 0)
			{
				if (index->primary)
					ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" appears twice in primary key constraint", key), parser_errposition(cxt->pstate, constraint->location)));



				else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" appears twice in unique constraint", key), parser_errposition(cxt->pstate, constraint->location)));




			}
		}

		
		iparam = makeNode(IndexElem);
		iparam->name = pstrdup(key);
		iparam->expr = NULL;
		iparam->indexcolname = NULL;
		iparam->collation = NIL;
		iparam->opclass = NIL;
		iparam->ordering = SORTBY_DEFAULT;
		iparam->nulls_ordering = SORTBY_NULLS_DEFAULT;
		index->indexParams = lappend(index->indexParams, iparam);
	}

	return index;
}


static void transformFKConstraints(CreateStmtContext *cxt, bool skipValidation, bool isAddConstraint)

{
	ListCell   *fkclist;

	if (cxt->fkconstraints == NIL)
		return;

	
	if (skipValidation)
	{
		foreach(fkclist, cxt->fkconstraints)
		{
			Constraint *constraint = (Constraint *) lfirst(fkclist);

			constraint->skip_validation = true;
			constraint->initially_valid = true;
		}
	}

	
	if (!isAddConstraint)
	{
		AlterTableStmt *alterstmt = makeNode(AlterTableStmt);

		alterstmt->relation = cxt->relation;
		alterstmt->cmds = NIL;
		alterstmt->relkind = OBJECT_TABLE;

		foreach(fkclist, cxt->fkconstraints)
		{
			Constraint *constraint = (Constraint *) lfirst(fkclist);
			AlterTableCmd *altercmd = makeNode(AlterTableCmd);

			altercmd->subtype = AT_ProcessedConstraint;
			altercmd->name = NULL;
			altercmd->def = (Node *) constraint;
			alterstmt->cmds = lappend(alterstmt->cmds, altercmd);
		}

		cxt->alist = lappend(cxt->alist, alterstmt);
	}
}


IndexStmt * transformIndexStmt(IndexStmt *stmt, const char *queryString)
{
	Relation	rel;
	ParseState *pstate;
	RangeTblEntry *rte;
	ListCell   *l;

	
	stmt = (IndexStmt *) copyObject(stmt);

	
	rel = heap_openrv(stmt->relation, (stmt->concurrent ? ShareUpdateExclusiveLock : ShareLock));

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	
	rte = addRangeTableEntry(pstate, stmt->relation, NULL, false, true);

	
	addRTEtoQuery(pstate, rte, false, true, true);

	
	if (stmt->whereClause)
	{
		stmt->whereClause = transformWhereClause(pstate, stmt->whereClause, EXPR_KIND_INDEX_PREDICATE, "WHERE");


		
		assign_expr_collations(pstate, stmt->whereClause);
	}

	
	foreach(l, stmt->indexParams)
	{
		IndexElem  *ielem = (IndexElem *) lfirst(l);

		if (ielem->expr)
		{
			
			if (ielem->indexcolname == NULL)
				ielem->indexcolname = FigureIndexColname(ielem->expr);

			
			ielem->expr = transformExpr(pstate, ielem->expr, EXPR_KIND_INDEX_EXPRESSION);

			
			assign_expr_collations(pstate, ielem->expr);

			
			if (expression_returns_set(ielem->expr))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("index expression cannot return a set")));

		}
	}

	
	if (list_length(pstate->p_rtable) != 1)
		ereport(ERROR, (errcode(ERRCODE_INVALID_COLUMN_REFERENCE), errmsg("index expressions and predicates can refer only to the table being indexed")));


	free_parsestate(pstate);

	
	heap_close(rel, NoLock);

	return stmt;
}



void transformRuleStmt(RuleStmt *stmt, const char *queryString, List **actions, Node **whereClause)

{
	Relation	rel;
	ParseState *pstate;
	RangeTblEntry *oldrte;
	RangeTblEntry *newrte;

	
	rel = heap_openrv(stmt->relation, AccessExclusiveLock);

	if (rel->rd_rel->relkind == RELKIND_MATVIEW)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("rules on materialized views are not supported")));


	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	
	oldrte = addRangeTableEntryForRelation(pstate, rel, makeAlias("old", NIL), false, false);

	newrte = addRangeTableEntryForRelation(pstate, rel, makeAlias("new", NIL), false, false);

	
	oldrte->requiredPerms = 0;
	newrte->requiredPerms = 0;

	
	switch (stmt->event)
	{
		case CMD_SELECT:
			addRTEtoQuery(pstate, oldrte, false, true, true);
			break;
		case CMD_UPDATE:
			addRTEtoQuery(pstate, oldrte, false, true, true);
			addRTEtoQuery(pstate, newrte, false, true, true);
			break;
		case CMD_INSERT:
			addRTEtoQuery(pstate, newrte, false, true, true);
			break;
		case CMD_DELETE:
			addRTEtoQuery(pstate, oldrte, false, true, true);
			break;
		default:
			elog(ERROR, "unrecognized event type: %d", (int) stmt->event);
			break;
	}

	
	*whereClause = transformWhereClause(pstate, (Node *) copyObject(stmt->whereClause), EXPR_KIND_WHERE, "WHERE");


	
	assign_expr_collations(pstate, *whereClause);

	
	if (list_length(pstate->p_rtable) != 2)		
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("rule WHERE condition cannot contain references to other relations")));


	
	if (stmt->actions == NIL)
	{
		Query	   *nothing_qry = makeNode(Query);

		nothing_qry->commandType = CMD_NOTHING;
		nothing_qry->rtable = pstate->p_rtable;
		nothing_qry->jointree = makeFromExpr(NIL, NULL);		

		*actions = list_make1(nothing_qry);
	}
	else {
		ListCell   *l;
		List	   *newactions = NIL;

		
		foreach(l, stmt->actions)
		{
			Node	   *action = (Node *) lfirst(l);
			ParseState *sub_pstate = make_parsestate(NULL);
			Query	   *sub_qry, *top_subqry;
			bool		has_old, has_new;

			
			sub_pstate->p_sourcetext = queryString;

			
			oldrte = addRangeTableEntryForRelation(sub_pstate, rel, makeAlias("old", NIL), false, false);

			newrte = addRangeTableEntryForRelation(sub_pstate, rel, makeAlias("new", NIL), false, false);

			oldrte->requiredPerms = 0;
			newrte->requiredPerms = 0;
			addRTEtoQuery(sub_pstate, oldrte, false, true, false);
			addRTEtoQuery(sub_pstate, newrte, false, true, false);

			
			top_subqry = transformStmt(sub_pstate, (Node *) copyObject(action));

			
			if (top_subqry->commandType == CMD_UTILITY && *whereClause != NULL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("rules with WHERE conditions can only have SELECT, INSERT, UPDATE, or DELETE actions")));


			
			sub_qry = getInsertSelectQuery(top_subqry, NULL);

			
			if (sub_qry->setOperations != NULL && *whereClause != NULL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("conditional UNION/INTERSECT/EXCEPT statements are not implemented")));


			
			has_old = rangeTableEntry_used((Node *) sub_qry, PRS2_OLD_VARNO, 0) || rangeTableEntry_used(*whereClause, PRS2_OLD_VARNO, 0);

			has_new = rangeTableEntry_used((Node *) sub_qry, PRS2_NEW_VARNO, 0) || rangeTableEntry_used(*whereClause, PRS2_NEW_VARNO, 0);


			switch (stmt->event)
			{
				case CMD_SELECT:
					if (has_old)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON SELECT rule cannot use OLD")));

					if (has_new)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON SELECT rule cannot use NEW")));

					break;
				case CMD_UPDATE:
					
					break;
				case CMD_INSERT:
					if (has_old)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON INSERT rule cannot use OLD")));

					break;
				case CMD_DELETE:
					if (has_new)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON DELETE rule cannot use NEW")));

					break;
				default:
					elog(ERROR, "unrecognized event type: %d", (int) stmt->event);
					break;
			}

			
			if (rangeTableEntry_used((Node *) top_subqry->cteList, PRS2_OLD_VARNO, 0) || rangeTableEntry_used((Node *) sub_qry->cteList, PRS2_OLD_VARNO, 0))


				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot refer to OLD within WITH query")));

			if (rangeTableEntry_used((Node *) top_subqry->cteList, PRS2_NEW_VARNO, 0) || rangeTableEntry_used((Node *) sub_qry->cteList, PRS2_NEW_VARNO, 0))


				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot refer to NEW within WITH query")));


			
			if (has_old || (has_new && stmt->event == CMD_UPDATE))
			{
				
				if (sub_qry->setOperations != NULL)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("conditional UNION/INTERSECT/EXCEPT statements are not implemented")));

				
				sub_pstate->p_rtable = sub_qry->rtable;
				sub_pstate->p_joinlist = sub_qry->jointree->fromlist;
				addRTEtoQuery(sub_pstate, oldrte, true, false, false);
				sub_qry->jointree->fromlist = sub_pstate->p_joinlist;
			}

			newactions = lappend(newactions, top_subqry);

			free_parsestate(sub_pstate);
		}

		*actions = newactions;
	}

	free_parsestate(pstate);

	
	heap_close(rel, NoLock);
}



List * transformAlterTableStmt(AlterTableStmt *stmt, const char *queryString)
{
	Relation	rel;
	ParseState *pstate;
	CreateStmtContext cxt;
	List	   *result;
	List	   *save_alist;
	ListCell   *lcmd, *l;
	List	   *newcmds = NIL;
	bool		skipValidation = true;
	AlterTableCmd *newcmd;
	LOCKMODE	lockmode;

	
	stmt = (AlterTableStmt *) copyObject(stmt);

	
	lockmode = AlterTableGetLockLevel(stmt->cmds);

	
	rel = relation_openrv_extended(stmt->relation, lockmode, stmt->missing_ok);
	if (rel == NULL)
	{
		
		ereport(NOTICE, (errmsg("relation \"%s\" does not exist, skipping", stmt->relation->relname)));

		return NIL;
	}

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	cxt.pstate = pstate;
	if (stmt->relkind == OBJECT_FOREIGN_TABLE)
	{
		cxt.stmtType = "ALTER FOREIGN TABLE";
		cxt.isforeign = true;
	}
	else {
		cxt.stmtType = "ALTER TABLE";
		cxt.isforeign = false;
	}
	cxt.relation = stmt->relation;
	cxt.rel = rel;
	cxt.inhRelations = NIL;
	cxt.isalter = true;
	cxt.hasoids = false;		
	cxt.columns = NIL;
	cxt.ckconstraints = NIL;
	cxt.fkconstraints = NIL;
	cxt.ixconstraints = NIL;
	cxt.inh_indexes = NIL;
	cxt.blist = NIL;
	cxt.alist = NIL;
	cxt.pkey = NULL;

	
	foreach(lcmd, stmt->cmds)
	{
		AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);

		switch (cmd->subtype)
		{
			case AT_AddColumn:
			case AT_AddColumnToView:
				{
					ColumnDef  *def = (ColumnDef *) cmd->def;

					Assert(IsA(def, ColumnDef));
					transformColumnDefinition(&cxt, def);

					
					if (def->raw_default != NULL)
						skipValidation = false;

					
					def->constraints = NIL;

					newcmds = lappend(newcmds, cmd);
					break;
				}
			case AT_AddConstraint:

				
				if (IsA(cmd->def, Constraint))
				{
					transformTableConstraint(&cxt, (Constraint *) cmd->def);
					if (((Constraint *) cmd->def)->contype == CONSTR_FOREIGN)
						skipValidation = false;
				}
				else elog(ERROR, "unrecognized node type: %d", (int) nodeTag(cmd->def));

				break;

			case AT_ProcessedConstraint:

				
				cmd->subtype = AT_AddConstraint;
				newcmds = lappend(newcmds, cmd);
				break;

			default:
				newcmds = lappend(newcmds, cmd);
				break;
		}
	}

	
	save_alist = cxt.alist;
	cxt.alist = NIL;

	
	transformIndexConstraints(&cxt);

	transformFKConstraints(&cxt, skipValidation, true);

	
	foreach(l, cxt.alist)
	{
		IndexStmt  *idxstmt = (IndexStmt *) lfirst(l);

		Assert(IsA(idxstmt, IndexStmt));
		idxstmt = transformIndexStmt(idxstmt, queryString);
		newcmd = makeNode(AlterTableCmd);
		newcmd->subtype = OidIsValid(idxstmt->indexOid) ? AT_AddIndexConstraint : AT_AddIndex;
		newcmd->def = (Node *) idxstmt;
		newcmds = lappend(newcmds, newcmd);
	}
	cxt.alist = NIL;

	
	foreach(l, cxt.ckconstraints)
	{
		newcmd = makeNode(AlterTableCmd);
		newcmd->subtype = AT_AddConstraint;
		newcmd->def = (Node *) lfirst(l);
		newcmds = lappend(newcmds, newcmd);
	}
	foreach(l, cxt.fkconstraints)
	{
		newcmd = makeNode(AlterTableCmd);
		newcmd->subtype = AT_AddConstraint;
		newcmd->def = (Node *) lfirst(l);
		newcmds = lappend(newcmds, newcmd);
	}

	
	relation_close(rel, NoLock);

	
	stmt->cmds = newcmds;

	result = lappend(cxt.blist, stmt);
	result = list_concat(result, cxt.alist);
	result = list_concat(result, save_alist);

	return result;
}



static void transformConstraintAttrs(CreateStmtContext *cxt, List *constraintList)
{
	Constraint *lastprimarycon = NULL;
	bool		saw_deferrability = false;
	bool		saw_initially = false;
	ListCell   *clist;







	foreach(clist, constraintList)
	{
		Constraint *con = (Constraint *) lfirst(clist);

		if (!IsA(con, Constraint))
			elog(ERROR, "unrecognized node type: %d", (int) nodeTag(con));
		switch (con->contype)
		{
			case CONSTR_ATTR_DEFERRABLE:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced DEFERRABLE clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_deferrability)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple DEFERRABLE/NOT DEFERRABLE clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_deferrability = true;
				lastprimarycon->deferrable = true;
				break;

			case CONSTR_ATTR_NOT_DEFERRABLE:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced NOT DEFERRABLE clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_deferrability)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple DEFERRABLE/NOT DEFERRABLE clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_deferrability = true;
				lastprimarycon->deferrable = false;
				if (saw_initially && lastprimarycon->initdeferred)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("constraint declared INITIALLY DEFERRED must be DEFERRABLE"), parser_errposition(cxt->pstate, con->location)));


				break;

			case CONSTR_ATTR_DEFERRED:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced INITIALLY DEFERRED clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_initially)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple INITIALLY IMMEDIATE/DEFERRED clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_initially = true;
				lastprimarycon->initdeferred = true;

				
				if (!saw_deferrability)
					lastprimarycon->deferrable = true;
				else if (!lastprimarycon->deferrable)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("constraint declared INITIALLY DEFERRED must be DEFERRABLE"), parser_errposition(cxt->pstate, con->location)));


				break;

			case CONSTR_ATTR_IMMEDIATE:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced INITIALLY IMMEDIATE clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_initially)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple INITIALLY IMMEDIATE/DEFERRED clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_initially = true;
				lastprimarycon->initdeferred = false;
				break;

			default:
				
				lastprimarycon = con;
				
				saw_deferrability = false;
				saw_initially = false;
				break;
		}
	}
}


static void transformColumnType(CreateStmtContext *cxt, ColumnDef *column)
{
	
	Type		ctype = typenameType(cxt->pstate, column->typeName, NULL);

	if (column->collClause)
	{
		Form_pg_type typtup = (Form_pg_type) GETSTRUCT(ctype);

		LookupCollation(cxt->pstate, column->collClause->collname, column->collClause->location);

		
		if (!OidIsValid(typtup->typcollation))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("collations are not supported by type %s", format_type_be(HeapTupleGetOid(ctype))), parser_errposition(cxt->pstate, column->collClause->location)));




	}

	ReleaseSysCache(ctype);
}



List * transformCreateSchemaStmt(CreateSchemaStmt *stmt)
{
	CreateSchemaStmtContext cxt;
	List	   *result;
	ListCell   *elements;

	cxt.stmtType = "CREATE SCHEMA";
	cxt.schemaname = stmt->schemaname;
	cxt.authid = stmt->authid;
	cxt.sequences = NIL;
	cxt.tables = NIL;
	cxt.views = NIL;
	cxt.indexes = NIL;
	cxt.triggers = NIL;
	cxt.grants = NIL;

	
	foreach(elements, stmt->schemaElts)
	{
		Node	   *element = lfirst(elements);

		switch (nodeTag(element))
		{
			case T_CreateSeqStmt:
				{
					CreateSeqStmt *elp = (CreateSeqStmt *) element;

					setSchemaName(cxt.schemaname, &elp->sequence->schemaname);
					cxt.sequences = lappend(cxt.sequences, element);
				}
				break;

			case T_CreateStmt:
				{
					CreateStmt *elp = (CreateStmt *) element;

					setSchemaName(cxt.schemaname, &elp->relation->schemaname);

					
					cxt.tables = lappend(cxt.tables, element);
				}
				break;

			case T_ViewStmt:
				{
					ViewStmt   *elp = (ViewStmt *) element;

					setSchemaName(cxt.schemaname, &elp->view->schemaname);

					
					cxt.views = lappend(cxt.views, element);
				}
				break;

			case T_IndexStmt:
				{
					IndexStmt  *elp = (IndexStmt *) element;

					setSchemaName(cxt.schemaname, &elp->relation->schemaname);
					cxt.indexes = lappend(cxt.indexes, element);
				}
				break;

			case T_CreateTrigStmt:
				{
					CreateTrigStmt *elp = (CreateTrigStmt *) element;

					setSchemaName(cxt.schemaname, &elp->relation->schemaname);
					cxt.triggers = lappend(cxt.triggers, element);
				}
				break;

			case T_GrantStmt:
				cxt.grants = lappend(cxt.grants, element);
				break;

			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(element));
		}
	}

	result = NIL;
	result = list_concat(result, cxt.sequences);
	result = list_concat(result, cxt.tables);
	result = list_concat(result, cxt.views);
	result = list_concat(result, cxt.indexes);
	result = list_concat(result, cxt.triggers);
	result = list_concat(result, cxt.grants);

	return result;
}


static void setSchemaName(char *context_schema, char **stmt_schema_name)
{
	if (*stmt_schema_name == NULL)
		*stmt_schema_name = context_schema;
	else if (strcmp(context_schema, *stmt_schema_name) != 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_SCHEMA_DEFINITION), errmsg("CREATE specifies a schema (%s) " "different from the one being created (%s)", *stmt_schema_name, context_schema)));



}
