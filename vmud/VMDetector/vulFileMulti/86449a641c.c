















































int			SessionReplicationRole = SESSION_REPLICATION_ROLE_ORIGIN;


static int	MyTriggerDepth = 0;




static void ConvertTriggerToFK(CreateTrigStmt *stmt, Oid funcoid);
static void SetTriggerFlags(TriggerDesc *trigdesc, Trigger *trigger);
static HeapTuple GetTupleForTrigger(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tid, LockTupleMode lockmode, TupleTableSlot **newSlot);




static bool TriggerEnabled(EState *estate, ResultRelInfo *relinfo, Trigger *trigger, TriggerEvent event, Bitmapset *modifiedCols, HeapTuple oldtup, HeapTuple newtup);


static HeapTuple ExecCallTriggerFunc(TriggerData *trigdata, int tgindx, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context);



static void AfterTriggerSaveEvent(EState *estate, ResultRelInfo *relinfo, int event, bool row_trigger, HeapTuple oldtup, HeapTuple newtup, List *recheckIndexes, Bitmapset *modifiedCols);





Oid CreateTrigger(CreateTrigStmt *stmt, const char *queryString, Oid constraintOid, Oid indexOid, bool isInternal)


{
	int16		tgtype;
	int			ncolumns;
	int16	   *columns;
	int2vector *tgattr;
	Node	   *whenClause;
	List	   *whenRtable;
	char	   *qual;
	Datum		values[Natts_pg_trigger];
	bool		nulls[Natts_pg_trigger];
	Relation	rel;
	AclResult	aclresult;
	Relation	tgrel;
	SysScanDesc tgscan;
	ScanKeyData key;
	Relation	pgrel;
	HeapTuple	tuple;
	Oid			fargtypes[1];	
	Oid			funcoid;
	Oid			funcrettype;
	Oid			trigoid;
	char		internaltrigname[NAMEDATALEN];
	char	   *trigname;
	Oid			constrrelid = InvalidOid;
	ObjectAddress myself, referenced;

	rel = heap_openrv(stmt->relation, AccessExclusiveLock);

	
	if (rel->rd_rel->relkind == RELKIND_RELATION)
	{
		
		if (stmt->timing != TRIGGER_TYPE_BEFORE && stmt->timing != TRIGGER_TYPE_AFTER)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a table", RelationGetRelationName(rel)), errdetail("Tables cannot have INSTEAD OF triggers.")));



	}
	else if (rel->rd_rel->relkind == RELKIND_VIEW)
	{
		
		if (stmt->timing != TRIGGER_TYPE_INSTEAD && stmt->row)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a view", RelationGetRelationName(rel)), errdetail("Views cannot have row-level BEFORE or AFTER triggers.")));



		
		if (TRIGGER_FOR_TRUNCATE(stmt->events))
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a view", RelationGetRelationName(rel)), errdetail("Views cannot have TRUNCATE triggers.")));



	}
	else ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or view", RelationGetRelationName(rel))));




	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));



	if (stmt->isconstraint && stmt->constrrel != NULL)
	{
		
		constrrelid = RangeVarGetRelid(stmt->constrrel, AccessShareLock, false);
	}

	
	if (!isInternal)
	{
		aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(), ACL_TRIGGER);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(rel));

		if (OidIsValid(constrrelid))
		{
			aclresult = pg_class_aclcheck(constrrelid, GetUserId(), ACL_TRIGGER);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(constrrelid));
		}
	}

	
	TRIGGER_CLEAR_TYPE(tgtype);
	if (stmt->row)
		TRIGGER_SETT_ROW(tgtype);
	tgtype |= stmt->timing;
	tgtype |= stmt->events;

	
	if (TRIGGER_FOR_ROW(tgtype) && TRIGGER_FOR_TRUNCATE(tgtype))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("TRUNCATE FOR EACH ROW triggers are not supported")));


	
	if (TRIGGER_FOR_INSTEAD(tgtype))
	{
		if (!TRIGGER_FOR_ROW(tgtype))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INSTEAD OF triggers must be FOR EACH ROW")));

		if (stmt->whenClause)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INSTEAD OF triggers cannot have WHEN conditions")));

		if (stmt->columns != NIL)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INSTEAD OF triggers cannot have column lists")));

	}

	
	if (stmt->whenClause)
	{
		ParseState *pstate;
		RangeTblEntry *rte;
		List	   *varList;
		ListCell   *lc;

		
		pstate = make_parsestate(NULL);
		pstate->p_sourcetext = queryString;

		
		rte = addRangeTableEntryForRelation(pstate, rel, makeAlias("old", NIL), false, false);

		addRTEtoQuery(pstate, rte, false, true, true);
		rte = addRangeTableEntryForRelation(pstate, rel, makeAlias("new", NIL), false, false);

		addRTEtoQuery(pstate, rte, false, true, true);

		
		whenClause = transformWhereClause(pstate, copyObject(stmt->whenClause), EXPR_KIND_TRIGGER_WHEN, "WHEN");


		
		assign_expr_collations(pstate, whenClause);

		
		varList = pull_var_clause(whenClause, PVC_REJECT_AGGREGATES, PVC_REJECT_PLACEHOLDERS);

		foreach(lc, varList)
		{
			Var		   *var = (Var *) lfirst(lc);

			switch (var->varno)
			{
				case PRS2_OLD_VARNO:
					if (!TRIGGER_FOR_ROW(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("statement trigger's WHEN condition cannot reference column values"), parser_errposition(pstate, var->location)));


					if (TRIGGER_FOR_INSERT(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("INSERT trigger's WHEN condition cannot reference OLD values"), parser_errposition(pstate, var->location)));


					
					break;
				case PRS2_NEW_VARNO:
					if (!TRIGGER_FOR_ROW(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("statement trigger's WHEN condition cannot reference column values"), parser_errposition(pstate, var->location)));


					if (TRIGGER_FOR_DELETE(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("DELETE trigger's WHEN condition cannot reference NEW values"), parser_errposition(pstate, var->location)));


					if (var->varattno < 0 && TRIGGER_FOR_BEFORE(tgtype))
						ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("BEFORE trigger's WHEN condition cannot reference NEW system columns"), parser_errposition(pstate, var->location)));


					break;
				default:
					
					elog(ERROR, "trigger WHEN condition cannot contain references to other relations");
					break;
			}
		}

		
		whenRtable = pstate->p_rtable;

		qual = nodeToString(whenClause);

		free_parsestate(pstate);
	}
	else {
		whenClause = NULL;
		whenRtable = NIL;
		qual = NULL;
	}

	
	funcoid = LookupFuncName(stmt->funcname, 0, fargtypes, false);
	if (!isInternal)
	{
		aclresult = pg_proc_aclcheck(funcoid, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, NameListToString(stmt->funcname));
	}
	funcrettype = get_func_rettype(funcoid);
	if (funcrettype != TRIGGEROID)
	{
		
		if (funcrettype == OPAQUEOID)
		{
			ereport(WARNING, (errmsg("changing return type of function %s from \"opaque\" to \"trigger\"", NameListToString(stmt->funcname))));

			SetFunctionReturnType(funcoid, TRIGGEROID);
		}
		else ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("function %s must return type \"trigger\"", NameListToString(stmt->funcname))));



	}

	
	if (stmt->isconstraint && !isInternal && list_length(stmt->args) >= 6 && (list_length(stmt->args) % 2) == 0 && RI_FKey_trigger_type(funcoid) != RI_TRIGGER_NONE)


	{
		
		heap_close(rel, NoLock);

		ConvertTriggerToFK(stmt, funcoid);

		return InvalidOid;
	}

	
	if (stmt->isconstraint && !OidIsValid(constraintOid))
	{
		
		Assert(!isInternal);
		constraintOid = CreateConstraintEntry(stmt->trigname, RelationGetNamespace(rel), CONSTRAINT_TRIGGER, stmt->deferrable, stmt->initdeferred, true, RelationGetRelid(rel), NULL, 0, InvalidOid, InvalidOid, InvalidOid, NULL, NULL, NULL, NULL, 0, ' ', ' ', ' ', NULL, NULL, NULL, NULL, true, 0, true, isInternal);


























	}

	
	tgrel = heap_open(TriggerRelationId, RowExclusiveLock);

	trigoid = GetNewOid(tgrel);

	
	if (isInternal)
	{
		snprintf(internaltrigname, sizeof(internaltrigname), "%s_%u", stmt->trigname, trigoid);
		trigname = internaltrigname;
	}
	else {
		
		trigname = stmt->trigname;
	}

	
	if (!isInternal)
	{
		ScanKeyInit(&key, Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


		tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 1, &key);
		while (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
		{
			Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(tuple);

			if (namestrcmp(&(pg_trigger->tgname), trigname) == 0)
				ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("trigger \"%s\" for relation \"%s\" already exists", trigname, stmt->relation->relname)));


		}
		systable_endscan(tgscan);
	}

	
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_trigger_tgrelid - 1] = ObjectIdGetDatum(RelationGetRelid(rel));
	values[Anum_pg_trigger_tgname - 1] = DirectFunctionCall1(namein, CStringGetDatum(trigname));
	values[Anum_pg_trigger_tgfoid - 1] = ObjectIdGetDatum(funcoid);
	values[Anum_pg_trigger_tgtype - 1] = Int16GetDatum(tgtype);
	values[Anum_pg_trigger_tgenabled - 1] = CharGetDatum(TRIGGER_FIRES_ON_ORIGIN);
	values[Anum_pg_trigger_tgisinternal - 1] = BoolGetDatum(isInternal);
	values[Anum_pg_trigger_tgconstrrelid - 1] = ObjectIdGetDatum(constrrelid);
	values[Anum_pg_trigger_tgconstrindid - 1] = ObjectIdGetDatum(indexOid);
	values[Anum_pg_trigger_tgconstraint - 1] = ObjectIdGetDatum(constraintOid);
	values[Anum_pg_trigger_tgdeferrable - 1] = BoolGetDatum(stmt->deferrable);
	values[Anum_pg_trigger_tginitdeferred - 1] = BoolGetDatum(stmt->initdeferred);

	if (stmt->args)
	{
		ListCell   *le;
		char	   *args;
		int16		nargs = list_length(stmt->args);
		int			len = 0;

		foreach(le, stmt->args)
		{
			char	   *ar = strVal(lfirst(le));

			len += strlen(ar) + 4;
			for (; *ar; ar++)
			{
				if (*ar == '\\')
					len++;
			}
		}
		args = (char *) palloc(len + 1);
		args[0] = '\0';
		foreach(le, stmt->args)
		{
			char	   *s = strVal(lfirst(le));
			char	   *d = args + strlen(args);

			while (*s)
			{
				if (*s == '\\')
					*d++ = '\\';
				*d++ = *s++;
			}
			strcpy(d, "\\000");
		}
		values[Anum_pg_trigger_tgnargs - 1] = Int16GetDatum(nargs);
		values[Anum_pg_trigger_tgargs - 1] = DirectFunctionCall1(byteain, CStringGetDatum(args));
	}
	else {
		values[Anum_pg_trigger_tgnargs - 1] = Int16GetDatum(0);
		values[Anum_pg_trigger_tgargs - 1] = DirectFunctionCall1(byteain, CStringGetDatum(""));
	}

	
	ncolumns = list_length(stmt->columns);
	if (ncolumns == 0)
		columns = NULL;
	else {
		ListCell   *cell;
		int			i = 0;

		columns = (int16 *) palloc(ncolumns * sizeof(int16));
		foreach(cell, stmt->columns)
		{
			char	   *name = strVal(lfirst(cell));
			int16		attnum;
			int			j;

			
			attnum = attnameAttNum(rel, name, false);
			if (attnum == InvalidAttrNumber)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", name, RelationGetRelationName(rel))));



			
			for (j = i - 1; j >= 0; j--)
			{
				if (columns[j] == attnum)
					ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" specified more than once", name)));


			}

			columns[i++] = attnum;
		}
	}
	tgattr = buildint2vector(columns, ncolumns);
	values[Anum_pg_trigger_tgattr - 1] = PointerGetDatum(tgattr);

	
	if (qual)
		values[Anum_pg_trigger_tgqual - 1] = CStringGetTextDatum(qual);
	else nulls[Anum_pg_trigger_tgqual - 1] = true;

	tuple = heap_form_tuple(tgrel->rd_att, values, nulls);

	
	HeapTupleSetOid(tuple, trigoid);

	
	simple_heap_insert(tgrel, tuple);

	CatalogUpdateIndexes(tgrel, tuple);

	heap_freetuple(tuple);
	heap_close(tgrel, RowExclusiveLock);

	pfree(DatumGetPointer(values[Anum_pg_trigger_tgname - 1]));
	pfree(DatumGetPointer(values[Anum_pg_trigger_tgargs - 1]));
	pfree(DatumGetPointer(values[Anum_pg_trigger_tgattr - 1]));

	
	pgrel = heap_open(RelationRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(RelationGetRelid(rel)));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", RelationGetRelid(rel));

	((Form_pg_class) GETSTRUCT(tuple))->relhastriggers = true;

	simple_heap_update(pgrel, &tuple->t_self, tuple);

	CatalogUpdateIndexes(pgrel, tuple);

	heap_freetuple(tuple);
	heap_close(pgrel, RowExclusiveLock);

	

	
	myself.classId = TriggerRelationId;
	myself.objectId = trigoid;
	myself.objectSubId = 0;

	referenced.classId = ProcedureRelationId;
	referenced.objectId = funcoid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	if (isInternal && OidIsValid(constraintOid))
	{
		
		referenced.classId = ConstraintRelationId;
		referenced.objectId = constraintOid;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_INTERNAL);
	}
	else {
		
		referenced.classId = RelationRelationId;
		referenced.objectId = RelationGetRelid(rel);
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);
		if (OidIsValid(constrrelid))
		{
			referenced.classId = RelationRelationId;
			referenced.objectId = constrrelid;
			referenced.objectSubId = 0;
			recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);
		}
		
		Assert(!OidIsValid(indexOid));

		
		if (OidIsValid(constraintOid))
		{
			referenced.classId = ConstraintRelationId;
			referenced.objectId = constraintOid;
			referenced.objectSubId = 0;
			recordDependencyOn(&referenced, &myself, DEPENDENCY_INTERNAL);
		}
	}

	
	if (columns != NULL)
	{
		int			i;

		referenced.classId = RelationRelationId;
		referenced.objectId = RelationGetRelid(rel);
		for (i = 0; i < ncolumns; i++)
		{
			referenced.objectSubId = columns[i];
			recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
		}
	}

	
	if (whenClause != NULL)
		recordDependencyOnExpr(&myself, whenClause, whenRtable, DEPENDENCY_NORMAL);

	
	InvokeObjectPostCreateHookArg(TriggerRelationId, trigoid, 0, isInternal);

	
	heap_close(rel, NoLock);

	return trigoid;
}



typedef struct {
	List	   *args;			
	Oid			funcoids[3];	
	
} OldTriggerInfo;

static void ConvertTriggerToFK(CreateTrigStmt *stmt, Oid funcoid)
{
	static List *info_list = NIL;

	static const char *const funcdescr[3] = {
		gettext_noop("Found referenced table's UPDATE trigger."), gettext_noop("Found referenced table's DELETE trigger."), gettext_noop("Found referencing table's trigger.")

	};

	char	   *constr_name;
	char	   *fk_table_name;
	char	   *pk_table_name;
	char		fk_matchtype = FKCONSTR_MATCH_SIMPLE;
	List	   *fk_attrs = NIL;
	List	   *pk_attrs = NIL;
	StringInfoData buf;
	int			funcnum;
	OldTriggerInfo *info = NULL;
	ListCell   *l;
	int			i;

	
	constr_name = strVal(linitial(stmt->args));
	fk_table_name = strVal(lsecond(stmt->args));
	pk_table_name = strVal(lthird(stmt->args));
	i = 0;
	foreach(l, stmt->args)
	{
		Value	   *arg = (Value *) lfirst(l);

		i++;
		if (i < 4)				
			continue;
		if (i == 4)				
		{
			if (strcmp(strVal(arg), "FULL") == 0)
				fk_matchtype = FKCONSTR_MATCH_FULL;
			else fk_matchtype = FKCONSTR_MATCH_SIMPLE;
			continue;
		}
		if (i % 2)
			fk_attrs = lappend(fk_attrs, arg);
		else pk_attrs = lappend(pk_attrs, arg);
	}

	
	initStringInfo(&buf);
	appendStringInfo(&buf, "FOREIGN KEY %s(", quote_identifier(fk_table_name));
	i = 0;
	foreach(l, fk_attrs)
	{
		Value	   *arg = (Value *) lfirst(l);

		if (i++ > 0)
			appendStringInfoChar(&buf, ',');
		appendStringInfoString(&buf, quote_identifier(strVal(arg)));
	}
	appendStringInfo(&buf, ") REFERENCES %s(", quote_identifier(pk_table_name));
	i = 0;
	foreach(l, pk_attrs)
	{
		Value	   *arg = (Value *) lfirst(l);

		if (i++ > 0)
			appendStringInfoChar(&buf, ',');
		appendStringInfoString(&buf, quote_identifier(strVal(arg)));
	}
	appendStringInfoChar(&buf, ')');

	
	switch (funcoid)
	{
		case F_RI_FKEY_CASCADE_UPD:
		case F_RI_FKEY_RESTRICT_UPD:
		case F_RI_FKEY_SETNULL_UPD:
		case F_RI_FKEY_SETDEFAULT_UPD:
		case F_RI_FKEY_NOACTION_UPD:
			funcnum = 0;
			break;

		case F_RI_FKEY_CASCADE_DEL:
		case F_RI_FKEY_RESTRICT_DEL:
		case F_RI_FKEY_SETNULL_DEL:
		case F_RI_FKEY_SETDEFAULT_DEL:
		case F_RI_FKEY_NOACTION_DEL:
			funcnum = 1;
			break;

		default:
			funcnum = 2;
			break;
	}

	
	foreach(l, info_list)
	{
		info = (OldTriggerInfo *) lfirst(l);
		if (info->funcoids[funcnum] == InvalidOid && equal(info->args, stmt->args))
		{
			info->funcoids[funcnum] = funcoid;
			break;
		}
	}

	if (l == NULL)
	{
		
		MemoryContext oldContext;

		ereport(NOTICE, (errmsg("ignoring incomplete trigger group for constraint \"%s\" %s", constr_name, buf.data), errdetail_internal("%s", _(funcdescr[funcnum]))));


		oldContext = MemoryContextSwitchTo(TopMemoryContext);
		info = (OldTriggerInfo *) palloc0(sizeof(OldTriggerInfo));
		info->args = copyObject(stmt->args);
		info->funcoids[funcnum] = funcoid;
		info_list = lappend(info_list, info);
		MemoryContextSwitchTo(oldContext);
	}
	else if (info->funcoids[0] == InvalidOid || info->funcoids[1] == InvalidOid || info->funcoids[2] == InvalidOid)

	{
		
		ereport(NOTICE, (errmsg("ignoring incomplete trigger group for constraint \"%s\" %s", constr_name, buf.data), errdetail_internal("%s", _(funcdescr[funcnum]))));


	}
	else {
		
		AlterTableStmt *atstmt = makeNode(AlterTableStmt);
		AlterTableCmd *atcmd = makeNode(AlterTableCmd);
		Constraint *fkcon = makeNode(Constraint);

		ereport(NOTICE, (errmsg("converting trigger group into constraint \"%s\" %s", constr_name, buf.data), errdetail_internal("%s", _(funcdescr[funcnum]))));


		fkcon->contype = CONSTR_FOREIGN;
		fkcon->location = -1;
		if (funcnum == 2)
		{
			
			atstmt->relation = stmt->relation;
			if (stmt->constrrel)
				fkcon->pktable = stmt->constrrel;
			else {
				
				fkcon->pktable = makeRangeVar(NULL, pk_table_name, -1);
			}
		}
		else {
			
			fkcon->pktable = stmt->relation;
			if (stmt->constrrel)
				atstmt->relation = stmt->constrrel;
			else {
				
				atstmt->relation = makeRangeVar(NULL, fk_table_name, -1);
			}
		}
		atstmt->cmds = list_make1(atcmd);
		atstmt->relkind = OBJECT_TABLE;
		atcmd->subtype = AT_AddConstraint;
		atcmd->def = (Node *) fkcon;
		if (strcmp(constr_name, "<unnamed>") == 0)
			fkcon->conname = NULL;
		else fkcon->conname = constr_name;
		fkcon->fk_attrs = fk_attrs;
		fkcon->pk_attrs = pk_attrs;
		fkcon->fk_matchtype = fk_matchtype;
		switch (info->funcoids[0])
		{
			case F_RI_FKEY_NOACTION_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_NOACTION;
				break;
			case F_RI_FKEY_CASCADE_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_CASCADE;
				break;
			case F_RI_FKEY_RESTRICT_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_RESTRICT;
				break;
			case F_RI_FKEY_SETNULL_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_SETNULL;
				break;
			case F_RI_FKEY_SETDEFAULT_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_SETDEFAULT;
				break;
			default:
				
				elog(ERROR, "confused about RI update function");
		}
		switch (info->funcoids[1])
		{
			case F_RI_FKEY_NOACTION_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_NOACTION;
				break;
			case F_RI_FKEY_CASCADE_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_CASCADE;
				break;
			case F_RI_FKEY_RESTRICT_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_RESTRICT;
				break;
			case F_RI_FKEY_SETNULL_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_SETNULL;
				break;
			case F_RI_FKEY_SETDEFAULT_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_SETDEFAULT;
				break;
			default:
				
				elog(ERROR, "confused about RI delete function");
		}
		fkcon->deferrable = stmt->deferrable;
		fkcon->initdeferred = stmt->initdeferred;
		fkcon->skip_validation = false;
		fkcon->initially_valid = true;

		
		ProcessUtility((Node *) atstmt, "(generated ALTER TABLE ADD FOREIGN KEY command)", PROCESS_UTILITY_SUBCOMMAND, NULL, None_Receiver, NULL);



		
		info_list = list_delete_ptr(info_list, info);
		pfree(info);
		
	}
}


void RemoveTriggerById(Oid trigOid)
{
	Relation	tgrel;
	SysScanDesc tgscan;
	ScanKeyData skey[1];
	HeapTuple	tup;
	Oid			relid;
	Relation	rel;

	tgrel = heap_open(TriggerRelationId, RowExclusiveLock);

	
	ScanKeyInit(&skey[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(trigOid));



	tgscan = systable_beginscan(tgrel, TriggerOidIndexId, true, NULL, 1, skey);

	tup = systable_getnext(tgscan);
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "could not find tuple for trigger %u", trigOid);

	
	relid = ((Form_pg_trigger) GETSTRUCT(tup))->tgrelid;

	rel = heap_open(relid, AccessExclusiveLock);

	if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_VIEW)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or view", RelationGetRelationName(rel))));



	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));



	
	simple_heap_delete(tgrel, &tup->t_self);

	systable_endscan(tgscan);
	heap_close(tgrel, RowExclusiveLock);

	
	CacheInvalidateRelcache(rel);

	
	heap_close(rel, NoLock);
}


Oid get_trigger_oid(Oid relid, const char *trigname, bool missing_ok)
{
	Relation	tgrel;
	ScanKeyData skey[2];
	SysScanDesc tgscan;
	HeapTuple	tup;
	Oid			oid;

	
	tgrel = heap_open(TriggerRelationId, AccessShareLock);

	ScanKeyInit(&skey[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&skey[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(trigname));



	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 2, skey);

	tup = systable_getnext(tgscan);

	if (!HeapTupleIsValid(tup))
	{
		if (!missing_ok)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("trigger \"%s\" for table \"%s\" does not exist", trigname, get_rel_name(relid))));


		oid = InvalidOid;
	}
	else {
		oid = HeapTupleGetOid(tup);
	}

	systable_endscan(tgscan);
	heap_close(tgrel, AccessShareLock);
	return oid;
}


static void RangeVarCallbackForRenameTrigger(const RangeVar *rv, Oid relid, Oid oldrelid, void *arg)

{
	HeapTuple	tuple;
	Form_pg_class form;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		return;					
	form = (Form_pg_class) GETSTRUCT(tuple);

	
	if (form->relkind != RELKIND_RELATION && form->relkind != RELKIND_VIEW)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or view", rv->relname)));


	
	if (!pg_class_ownercheck(relid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, rv->relname);
	if (!allowSystemTableMods && IsSystemClass(relid, form))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", rv->relname)));



	ReleaseSysCache(tuple);
}


Oid renametrig(RenameStmt *stmt)
{
	Oid			tgoid;
	Relation	targetrel;
	Relation	tgrel;
	HeapTuple	tuple;
	SysScanDesc tgscan;
	ScanKeyData key[2];
	Oid			relid;

	
	relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock, false, false, RangeVarCallbackForRenameTrigger, NULL);



	
	targetrel = relation_open(relid, NoLock);

	
	tgrel = heap_open(TriggerRelationId, RowExclusiveLock);

	
	ScanKeyInit(&key[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&key[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, PointerGetDatum(stmt->newname));


	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 2, key);
	if (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("trigger \"%s\" for relation \"%s\" already exists", stmt->newname, RelationGetRelationName(targetrel))));


	systable_endscan(tgscan);

	
	ScanKeyInit(&key[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&key[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, PointerGetDatum(stmt->subname));


	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 2, key);
	if (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
	{
		tgoid = HeapTupleGetOid(tuple);

		
		tuple = heap_copytuple(tuple);	

		namestrcpy(&((Form_pg_trigger) GETSTRUCT(tuple))->tgname, stmt->newname);

		simple_heap_update(tgrel, &tuple->t_self, tuple);

		
		CatalogUpdateIndexes(tgrel, tuple);

		InvokeObjectPostAlterHook(TriggerRelationId, HeapTupleGetOid(tuple), 0);

		
		CacheInvalidateRelcache(targetrel);
	}
	else {
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("trigger \"%s\" for table \"%s\" does not exist", stmt->subname, RelationGetRelationName(targetrel))));


	}

	systable_endscan(tgscan);

	heap_close(tgrel, RowExclusiveLock);

	
	relation_close(targetrel, NoLock);

	return tgoid;
}



void EnableDisableTrigger(Relation rel, const char *tgname, char fires_when, bool skip_system)

{
	Relation	tgrel;
	int			nkeys;
	ScanKeyData keys[2];
	SysScanDesc tgscan;
	HeapTuple	tuple;
	bool		found;
	bool		changed;

	
	tgrel = heap_open(TriggerRelationId, RowExclusiveLock);

	ScanKeyInit(&keys[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	if (tgname)
	{
		ScanKeyInit(&keys[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(tgname));


		nkeys = 2;
	}
	else nkeys = 1;

	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, nkeys, keys);

	found = changed = false;

	while (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
	{
		Form_pg_trigger oldtrig = (Form_pg_trigger) GETSTRUCT(tuple);

		if (oldtrig->tgisinternal)
		{
			
			if (skip_system)
				continue;
			if (!superuser())
				ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system trigger", NameStr(oldtrig->tgname))));


		}

		found = true;

		if (oldtrig->tgenabled != fires_when)
		{
			
			HeapTuple	newtup = heap_copytuple(tuple);
			Form_pg_trigger newtrig = (Form_pg_trigger) GETSTRUCT(newtup);

			newtrig->tgenabled = fires_when;

			simple_heap_update(tgrel, &newtup->t_self, newtup);

			
			CatalogUpdateIndexes(tgrel, newtup);

			heap_freetuple(newtup);

			changed = true;
		}

		InvokeObjectPostAlterHook(TriggerRelationId, HeapTupleGetOid(tuple), 0);
	}

	systable_endscan(tgscan);

	heap_close(tgrel, RowExclusiveLock);

	if (tgname && !found)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("trigger \"%s\" for table \"%s\" does not exist", tgname, RelationGetRelationName(rel))));



	
	if (changed)
		CacheInvalidateRelcache(rel);
}



void RelationBuildTriggers(Relation relation)
{
	TriggerDesc *trigdesc;
	int			numtrigs;
	int			maxtrigs;
	Trigger    *triggers;
	Relation	tgrel;
	ScanKeyData skey;
	SysScanDesc tgscan;
	HeapTuple	htup;
	MemoryContext oldContext;
	int			i;

	
	maxtrigs = 16;
	triggers = (Trigger *) palloc(maxtrigs * sizeof(Trigger));
	numtrigs = 0;

	
	ScanKeyInit(&skey, Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(relation)));



	tgrel = heap_open(TriggerRelationId, AccessShareLock);
	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 1, &skey);

	while (HeapTupleIsValid(htup = systable_getnext(tgscan)))
	{
		Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(htup);
		Trigger    *build;
		Datum		datum;
		bool		isnull;

		if (numtrigs >= maxtrigs)
		{
			maxtrigs *= 2;
			triggers = (Trigger *) repalloc(triggers, maxtrigs * sizeof(Trigger));
		}
		build = &(triggers[numtrigs]);

		build->tgoid = HeapTupleGetOid(htup);
		build->tgname = DatumGetCString(DirectFunctionCall1(nameout, NameGetDatum(&pg_trigger->tgname)));
		build->tgfoid = pg_trigger->tgfoid;
		build->tgtype = pg_trigger->tgtype;
		build->tgenabled = pg_trigger->tgenabled;
		build->tgisinternal = pg_trigger->tgisinternal;
		build->tgconstrrelid = pg_trigger->tgconstrrelid;
		build->tgconstrindid = pg_trigger->tgconstrindid;
		build->tgconstraint = pg_trigger->tgconstraint;
		build->tgdeferrable = pg_trigger->tgdeferrable;
		build->tginitdeferred = pg_trigger->tginitdeferred;
		build->tgnargs = pg_trigger->tgnargs;
		
		build->tgnattr = pg_trigger->tgattr.dim1;
		if (build->tgnattr > 0)
		{
			build->tgattr = (int16 *) palloc(build->tgnattr * sizeof(int16));
			memcpy(build->tgattr, &(pg_trigger->tgattr.values), build->tgnattr * sizeof(int16));
		}
		else build->tgattr = NULL;
		if (build->tgnargs > 0)
		{
			bytea	   *val;
			char	   *p;

			val = DatumGetByteaP(fastgetattr(htup, Anum_pg_trigger_tgargs, tgrel->rd_att, &isnull));

			if (isnull)
				elog(ERROR, "tgargs is null in trigger for relation \"%s\"", RelationGetRelationName(relation));
			p = (char *) VARDATA(val);
			build->tgargs = (char **) palloc(build->tgnargs * sizeof(char *));
			for (i = 0; i < build->tgnargs; i++)
			{
				build->tgargs[i] = pstrdup(p);
				p += strlen(p) + 1;
			}
		}
		else build->tgargs = NULL;
		datum = fastgetattr(htup, Anum_pg_trigger_tgqual, tgrel->rd_att, &isnull);
		if (!isnull)
			build->tgqual = TextDatumGetCString(datum);
		else build->tgqual = NULL;

		numtrigs++;
	}

	systable_endscan(tgscan);
	heap_close(tgrel, AccessShareLock);

	
	if (numtrigs == 0)
	{
		pfree(triggers);
		return;
	}

	
	trigdesc = (TriggerDesc *) palloc0(sizeof(TriggerDesc));
	trigdesc->triggers = triggers;
	trigdesc->numtriggers = numtrigs;
	for (i = 0; i < numtrigs; i++)
		SetTriggerFlags(trigdesc, &(triggers[i]));

	
	oldContext = MemoryContextSwitchTo(CacheMemoryContext);
	relation->trigdesc = CopyTriggerDesc(trigdesc);
	MemoryContextSwitchTo(oldContext);

	
	FreeTriggerDesc(trigdesc);
}


static void SetTriggerFlags(TriggerDesc *trigdesc, Trigger *trigger)
{
	int16		tgtype = trigger->tgtype;

	trigdesc->trig_insert_before_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_after_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_instead_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_INSERT);

	trigdesc->trig_update_before_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_after_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_instead_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_delete_before_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_after_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_instead_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_DELETE);

	
	trigdesc->trig_truncate_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_TRUNCATE);

	trigdesc->trig_truncate_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_TRUNCATE);

}


TriggerDesc * CopyTriggerDesc(TriggerDesc *trigdesc)
{
	TriggerDesc *newdesc;
	Trigger    *trigger;
	int			i;

	if (trigdesc == NULL || trigdesc->numtriggers <= 0)
		return NULL;

	newdesc = (TriggerDesc *) palloc(sizeof(TriggerDesc));
	memcpy(newdesc, trigdesc, sizeof(TriggerDesc));

	trigger = (Trigger *) palloc(trigdesc->numtriggers * sizeof(Trigger));
	memcpy(trigger, trigdesc->triggers, trigdesc->numtriggers * sizeof(Trigger));
	newdesc->triggers = trigger;

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		trigger->tgname = pstrdup(trigger->tgname);
		if (trigger->tgnattr > 0)
		{
			int16	   *newattr;

			newattr = (int16 *) palloc(trigger->tgnattr * sizeof(int16));
			memcpy(newattr, trigger->tgattr, trigger->tgnattr * sizeof(int16));
			trigger->tgattr = newattr;
		}
		if (trigger->tgnargs > 0)
		{
			char	  **newargs;
			int16		j;

			newargs = (char **) palloc(trigger->tgnargs * sizeof(char *));
			for (j = 0; j < trigger->tgnargs; j++)
				newargs[j] = pstrdup(trigger->tgargs[j]);
			trigger->tgargs = newargs;
		}
		if (trigger->tgqual)
			trigger->tgqual = pstrdup(trigger->tgqual);
		trigger++;
	}

	return newdesc;
}


void FreeTriggerDesc(TriggerDesc *trigdesc)
{
	Trigger    *trigger;
	int			i;

	if (trigdesc == NULL)
		return;

	trigger = trigdesc->triggers;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		pfree(trigger->tgname);
		if (trigger->tgnattr > 0)
			pfree(trigger->tgattr);
		if (trigger->tgnargs > 0)
		{
			while (--(trigger->tgnargs) >= 0)
				pfree(trigger->tgargs[trigger->tgnargs]);
			pfree(trigger->tgargs);
		}
		if (trigger->tgqual)
			pfree(trigger->tgqual);
		trigger++;
	}
	pfree(trigdesc->triggers);
	pfree(trigdesc);
}



bool equalTriggerDescs(TriggerDesc *trigdesc1, TriggerDesc *trigdesc2)
{
	int			i, j;

	
	if (trigdesc1 != NULL)
	{
		if (trigdesc2 == NULL)
			return false;
		if (trigdesc1->numtriggers != trigdesc2->numtriggers)
			return false;
		for (i = 0; i < trigdesc1->numtriggers; i++)
		{
			Trigger    *trig1 = trigdesc1->triggers + i;
			Trigger    *trig2 = trigdesc2->triggers + i;

			if (trig1->tgoid != trig2->tgoid)
				return false;
			if (strcmp(trig1->tgname, trig2->tgname) != 0)
				return false;
			if (trig1->tgfoid != trig2->tgfoid)
				return false;
			if (trig1->tgtype != trig2->tgtype)
				return false;
			if (trig1->tgenabled != trig2->tgenabled)
				return false;
			if (trig1->tgisinternal != trig2->tgisinternal)
				return false;
			if (trig1->tgconstrrelid != trig2->tgconstrrelid)
				return false;
			if (trig1->tgconstrindid != trig2->tgconstrindid)
				return false;
			if (trig1->tgconstraint != trig2->tgconstraint)
				return false;
			if (trig1->tgdeferrable != trig2->tgdeferrable)
				return false;
			if (trig1->tginitdeferred != trig2->tginitdeferred)
				return false;
			if (trig1->tgnargs != trig2->tgnargs)
				return false;
			if (trig1->tgnattr != trig2->tgnattr)
				return false;
			if (trig1->tgnattr > 0 && memcmp(trig1->tgattr, trig2->tgattr, trig1->tgnattr * sizeof(int16)) != 0)

				return false;
			for (j = 0; j < trig1->tgnargs; j++)
				if (strcmp(trig1->tgargs[j], trig2->tgargs[j]) != 0)
					return false;
			if (trig1->tgqual == NULL && trig2->tgqual == NULL)
				  ;
			else if (trig1->tgqual == NULL || trig2->tgqual == NULL)
				return false;
			else if (strcmp(trig1->tgqual, trig2->tgqual) != 0)
				return false;
		}
	}
	else if (trigdesc2 != NULL)
		return false;
	return true;
}



static HeapTuple ExecCallTriggerFunc(TriggerData *trigdata, int tgindx, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context)




{
	FunctionCallInfoData fcinfo;
	PgStat_FunctionCallUsage fcusage;
	Datum		result;
	MemoryContext oldContext;

	finfo += tgindx;

	
	if (finfo->fn_oid == InvalidOid)
		fmgr_info(trigdata->tg_trigger->tgfoid, finfo);

	Assert(finfo->fn_oid == trigdata->tg_trigger->tgfoid);

	
	if (instr)
		InstrStartNode(instr + tgindx);

	
	oldContext = MemoryContextSwitchTo(per_tuple_context);

	
	InitFunctionCallInfoData(fcinfo, finfo, 0, InvalidOid, (Node *) trigdata, NULL);

	pgstat_init_function_usage(&fcinfo, &fcusage);

	MyTriggerDepth++;
	PG_TRY();
	{
		result = FunctionCallInvoke(&fcinfo);
	}
	PG_CATCH();
	{
		MyTriggerDepth--;
		PG_RE_THROW();
	}
	PG_END_TRY();
	MyTriggerDepth--;

	pgstat_end_function_usage(&fcusage, true);

	MemoryContextSwitchTo(oldContext);

	
	if (fcinfo.isnull)
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("trigger function %u returned null value", fcinfo.flinfo->fn_oid)));



	
	if (instr)
		InstrStopNode(instr + tgindx, 1);

	return (HeapTuple) DatumGetPointer(result);
}

void ExecBSInsertTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_insert_before_statement)
		return;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASInsertTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_insert_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_INSERT, false, NULL, NULL, NIL, NULL);
}

TupleTableSlot * ExecBRInsertTriggers(EState *estate, ResultRelInfo *relinfo, TupleTableSlot *slot)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	HeapTuple	slottuple = ExecMaterializeSlot(slot);
	HeapTuple	newtuple = slottuple;
	HeapTuple	oldtuple;
	TriggerData LocTriggerData;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_ROW | TRIGGER_EVENT_BEFORE;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, newtuple))
			continue;

		LocTriggerData.tg_trigtuple = oldtuple = newtuple;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (oldtuple != newtuple && oldtuple != slottuple)
			heap_freetuple(oldtuple);
		if (newtuple == NULL)
			return NULL;		
	}

	if (newtuple != slottuple)
	{
		
		TupleTableSlot *newslot = estate->es_trig_tuple_slot;
		TupleDesc	tupdesc = RelationGetDescr(relinfo->ri_RelationDesc);

		if (newslot->tts_tupleDescriptor != tupdesc)
			ExecSetSlotDescriptor(newslot, tupdesc);
		ExecStoreTuple(newtuple, newslot, InvalidBuffer, false);
		slot = newslot;
	}
	return slot;
}

void ExecARInsertTriggers(EState *estate, ResultRelInfo *relinfo, HeapTuple trigtuple, List *recheckIndexes)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_insert_after_row)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_INSERT, true, NULL, trigtuple, recheckIndexes, NULL);
}

TupleTableSlot * ExecIRInsertTriggers(EState *estate, ResultRelInfo *relinfo, TupleTableSlot *slot)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	HeapTuple	slottuple = ExecMaterializeSlot(slot);
	HeapTuple	newtuple = slottuple;
	HeapTuple	oldtuple;
	TriggerData LocTriggerData;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_ROW | TRIGGER_EVENT_INSTEAD;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_INSERT))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, newtuple))
			continue;

		LocTriggerData.tg_trigtuple = oldtuple = newtuple;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (oldtuple != newtuple && oldtuple != slottuple)
			heap_freetuple(oldtuple);
		if (newtuple == NULL)
			return NULL;		
	}

	if (newtuple != slottuple)
	{
		
		TupleTableSlot *newslot = estate->es_trig_tuple_slot;
		TupleDesc	tupdesc = RelationGetDescr(relinfo->ri_RelationDesc);

		if (newslot->tts_tupleDescriptor != tupdesc)
			ExecSetSlotDescriptor(newslot, tupdesc);
		ExecStoreTuple(newtuple, newslot, InvalidBuffer, false);
		slot = newslot;
	}
	return slot;
}

void ExecBSDeleteTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_delete_before_statement)
		return;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_DELETE | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASDeleteTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_delete_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_DELETE, false, NULL, NULL, NIL, NULL);
}

bool ExecBRDeleteTriggers(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tupleid)


{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	bool		result = true;
	TriggerData LocTriggerData;
	HeapTuple	trigtuple;
	HeapTuple	newtuple;
	TupleTableSlot *newSlot;
	int			i;

	trigtuple = GetTupleForTrigger(estate, epqstate, relinfo, tupleid, LockTupleExclusive, &newSlot);
	if (trigtuple == NULL)
		return false;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_DELETE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_BEFORE;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, trigtuple, NULL))
			continue;

		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (newtuple == NULL)
		{
			result = false;		
			break;
		}
		if (newtuple != trigtuple)
			heap_freetuple(newtuple);
	}
	heap_freetuple(trigtuple);

	return result;
}

void ExecARDeleteTriggers(EState *estate, ResultRelInfo *relinfo, ItemPointer tupleid)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_delete_after_row)
	{
		HeapTuple	trigtuple = GetTupleForTrigger(estate, NULL, relinfo, tupleid, LockTupleExclusive, NULL);





		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_DELETE, true, trigtuple, NULL, NIL, NULL);
		heap_freetuple(trigtuple);
	}
}

bool ExecIRDeleteTriggers(EState *estate, ResultRelInfo *relinfo, HeapTuple trigtuple)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	TriggerData LocTriggerData;
	HeapTuple	rettuple;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_DELETE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_INSTEAD;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_DELETE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, trigtuple, NULL))
			continue;

		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
		LocTriggerData.tg_trigger = trigger;
		rettuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (rettuple == NULL)
			return false;		
		if (rettuple != trigtuple)
			heap_freetuple(rettuple);
	}
	return true;
}

void ExecBSUpdateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;
	Bitmapset  *modifiedCols;

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_update_before_statement)
		return;

	modifiedCols = GetModifiedColumns(relinfo, estate);

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_UPDATE | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, modifiedCols, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASUpdateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_update_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_UPDATE, false, NULL, NULL, NIL, GetModifiedColumns(relinfo, estate));

}

TupleTableSlot * ExecBRUpdateTriggers(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tupleid, TupleTableSlot *slot)


{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	HeapTuple	slottuple = ExecMaterializeSlot(slot);
	HeapTuple	newtuple = slottuple;
	TriggerData LocTriggerData;
	HeapTuple	trigtuple;
	HeapTuple	oldtuple;
	TupleTableSlot *newSlot;
	int			i;
	Bitmapset  *modifiedCols;
	Bitmapset  *keyCols;
	LockTupleMode lockmode;

	
	modifiedCols = GetModifiedColumns(relinfo, estate);
	keyCols = RelationGetIndexAttrBitmap(relinfo->ri_RelationDesc, INDEX_ATTR_BITMAP_KEY);
	if (bms_overlap(keyCols, modifiedCols))
		lockmode = LockTupleExclusive;
	else lockmode = LockTupleNoKeyExclusive;

	
	trigtuple = GetTupleForTrigger(estate, epqstate, relinfo, tupleid, lockmode, &newSlot);
	if (trigtuple == NULL)
		return NULL;			

	
	if (newSlot != NULL)
	{
		slot = ExecFilterJunk(relinfo->ri_junkFilter, newSlot);
		slottuple = ExecMaterializeSlot(slot);
		newtuple = slottuple;
	}


	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_UPDATE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_BEFORE;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, modifiedCols, trigtuple, newtuple))
			continue;

		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_newtuple = oldtuple = newtuple;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
		LocTriggerData.tg_newtuplebuf = InvalidBuffer;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (oldtuple != newtuple && oldtuple != slottuple)
			heap_freetuple(oldtuple);
		if (newtuple == NULL)
		{
			heap_freetuple(trigtuple);
			return NULL;		
		}
	}
	heap_freetuple(trigtuple);

	if (newtuple != slottuple)
	{
		
		TupleTableSlot *newslot = estate->es_trig_tuple_slot;
		TupleDesc	tupdesc = RelationGetDescr(relinfo->ri_RelationDesc);

		if (newslot->tts_tupleDescriptor != tupdesc)
			ExecSetSlotDescriptor(newslot, tupdesc);
		ExecStoreTuple(newtuple, newslot, InvalidBuffer, false);
		slot = newslot;
	}
	return slot;
}

void ExecARUpdateTriggers(EState *estate, ResultRelInfo *relinfo, ItemPointer tupleid, HeapTuple newtuple, List *recheckIndexes)


{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_update_after_row)
	{
		HeapTuple	trigtuple = GetTupleForTrigger(estate, NULL, relinfo, tupleid, LockTupleExclusive, NULL);





		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_UPDATE, true, trigtuple, newtuple, recheckIndexes, GetModifiedColumns(relinfo, estate));

		heap_freetuple(trigtuple);
	}
}

TupleTableSlot * ExecIRUpdateTriggers(EState *estate, ResultRelInfo *relinfo, HeapTuple trigtuple, TupleTableSlot *slot)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	HeapTuple	slottuple = ExecMaterializeSlot(slot);
	HeapTuple	newtuple = slottuple;
	TriggerData LocTriggerData;
	HeapTuple	oldtuple;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_UPDATE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_INSTEAD;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_UPDATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, trigtuple, newtuple))
			continue;

		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_newtuple = oldtuple = newtuple;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
		LocTriggerData.tg_newtuplebuf = InvalidBuffer;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (oldtuple != newtuple && oldtuple != slottuple)
			heap_freetuple(oldtuple);
		if (newtuple == NULL)
			return NULL;		
	}

	if (newtuple != slottuple)
	{
		
		TupleTableSlot *newslot = estate->es_trig_tuple_slot;
		TupleDesc	tupdesc = RelationGetDescr(relinfo->ri_RelationDesc);

		if (newslot->tts_tupleDescriptor != tupdesc)
			ExecSetSlotDescriptor(newslot, tupdesc);
		ExecStoreTuple(newtuple, newslot, InvalidBuffer, false);
		slot = newslot;
	}
	return slot;
}

void ExecBSTruncateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_truncate_before_statement)
		return;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_TRUNCATE | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
	LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_TRUNCATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASTruncateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_truncate_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_TRUNCATE, false, NULL, NULL, NIL, NULL);
}


static HeapTuple GetTupleForTrigger(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tid, LockTupleMode lockmode, TupleTableSlot **newSlot)





{
	Relation	relation = relinfo->ri_RelationDesc;
	HeapTupleData tuple;
	HeapTuple	result;
	Buffer		buffer;

	if (newSlot != NULL)
	{
		HTSU_Result test;
		HeapUpdateFailureData hufd;

		*newSlot = NULL;

		
		Assert(epqstate != NULL);

		
ltrmark:;
		tuple.t_self = *tid;
		test = heap_lock_tuple(relation, &tuple, estate->es_output_cid, lockmode, false  , false, &buffer, &hufd);


		switch (test)
		{
			case HeapTupleSelfUpdated:

				
				if (hufd.cmax != estate->es_output_cid)
					ereport(ERROR, (errcode(ERRCODE_TRIGGERED_DATA_CHANGE_VIOLATION), errmsg("tuple to be updated was already modified by an operation triggered by the current command"), errhint("Consider using an AFTER trigger instead of a BEFORE trigger to propagate changes to other rows.")));



				
				ReleaseBuffer(buffer);
				return NULL;

			case HeapTupleMayBeUpdated:
				break;

			case HeapTupleUpdated:
				ReleaseBuffer(buffer);
				if (IsolationUsesXactSnapshot())
					ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("could not serialize access due to concurrent update")));

				if (!ItemPointerEquals(&hufd.ctid, &tuple.t_self))
				{
					
					TupleTableSlot *epqslot;

					epqslot = EvalPlanQual(estate, epqstate, relation, relinfo->ri_RangeTableIndex, lockmode, &hufd.ctid, hufd.xmax);





					if (!TupIsNull(epqslot))
					{
						*tid = hufd.ctid;
						*newSlot = epqslot;

						
						goto ltrmark;
					}
				}

				
				return NULL;

			default:
				ReleaseBuffer(buffer);
				elog(ERROR, "unrecognized heap_lock_tuple status: %u", test);
				return NULL;	
		}
	}
	else {
		Page		page;
		ItemId		lp;

		buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

		
		LockBuffer(buffer, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buffer);
		lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));

		Assert(ItemIdIsNormal(lp));

		tuple.t_data = (HeapTupleHeader) PageGetItem(page, lp);
		tuple.t_len = ItemIdGetLength(lp);
		tuple.t_self = *tid;
		tuple.t_tableOid = RelationGetRelid(relation);

		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	}

	result = heap_copytuple(&tuple);
	ReleaseBuffer(buffer);

	return result;
}


static bool TriggerEnabled(EState *estate, ResultRelInfo *relinfo, Trigger *trigger, TriggerEvent event, Bitmapset *modifiedCols, HeapTuple oldtup, HeapTuple newtup)



{
	
	if (SessionReplicationRole == SESSION_REPLICATION_ROLE_REPLICA)
	{
		if (trigger->tgenabled == TRIGGER_FIRES_ON_ORIGIN || trigger->tgenabled == TRIGGER_DISABLED)
			return false;
	}
	else	 {
		if (trigger->tgenabled == TRIGGER_FIRES_ON_REPLICA || trigger->tgenabled == TRIGGER_DISABLED)
			return false;
	}

	
	if (trigger->tgnattr > 0 && TRIGGER_FIRED_BY_UPDATE(event))
	{
		int			i;
		bool		modified;

		modified = false;
		for (i = 0; i < trigger->tgnattr; i++)
		{
			if (bms_is_member(trigger->tgattr[i] - FirstLowInvalidHeapAttributeNumber, modifiedCols))
			{
				modified = true;
				break;
			}
		}
		if (!modified)
			return false;
	}

	
	if (trigger->tgqual)
	{
		TupleDesc	tupdesc = RelationGetDescr(relinfo->ri_RelationDesc);
		List	  **predicate;
		ExprContext *econtext;
		TupleTableSlot *oldslot = NULL;
		TupleTableSlot *newslot = NULL;
		MemoryContext oldContext;
		int			i;

		Assert(estate != NULL);

		
		i = trigger - relinfo->ri_TrigDesc->triggers;
		predicate = &relinfo->ri_TrigWhenExprs[i];

		
		if (*predicate == NIL)
		{
			Node	   *tgqual;

			oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
			tgqual = stringToNode(trigger->tgqual);
			
			ChangeVarNodes(tgqual, PRS2_OLD_VARNO, INNER_VAR, 0);
			ChangeVarNodes(tgqual, PRS2_NEW_VARNO, OUTER_VAR, 0);
			
			tgqual = (Node *) make_ands_implicit((Expr *) tgqual);
			*predicate = (List *) ExecPrepareExpr((Expr *) tgqual, estate);
			MemoryContextSwitchTo(oldContext);
		}

		
		econtext = GetPerTupleExprContext(estate);

		
		if (HeapTupleIsValid(oldtup))
		{
			if (estate->es_trig_oldtup_slot == NULL)
			{
				oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
				estate->es_trig_oldtup_slot = ExecInitExtraTupleSlot(estate);
				MemoryContextSwitchTo(oldContext);
			}
			oldslot = estate->es_trig_oldtup_slot;
			if (oldslot->tts_tupleDescriptor != tupdesc)
				ExecSetSlotDescriptor(oldslot, tupdesc);
			ExecStoreTuple(oldtup, oldslot, InvalidBuffer, false);
		}
		if (HeapTupleIsValid(newtup))
		{
			if (estate->es_trig_newtup_slot == NULL)
			{
				oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
				estate->es_trig_newtup_slot = ExecInitExtraTupleSlot(estate);
				MemoryContextSwitchTo(oldContext);
			}
			newslot = estate->es_trig_newtup_slot;
			if (newslot->tts_tupleDescriptor != tupdesc)
				ExecSetSlotDescriptor(newslot, tupdesc);
			ExecStoreTuple(newtup, newslot, InvalidBuffer, false);
		}

		
		econtext->ecxt_innertuple = oldslot;
		econtext->ecxt_outertuple = newslot;
		if (!ExecQual(*predicate, econtext, false))
			return false;
	}

	return true;
}





typedef struct SetConstraintTriggerData {
	Oid			sct_tgoid;
	bool		sct_tgisdeferred;
} SetConstraintTriggerData;

typedef struct SetConstraintTriggerData *SetConstraintTrigger;


typedef struct SetConstraintStateData {
	bool		all_isset;
	bool		all_isdeferred;
	int			numstates;		
	int			numalloc;		
	SetConstraintTriggerData trigstates[1];		
} SetConstraintStateData;

typedef SetConstraintStateData *SetConstraintState;



typedef uint32 TriggerFlags;






typedef struct AfterTriggerSharedData *AfterTriggerShared;

typedef struct AfterTriggerSharedData {
	TriggerEvent ats_event;		
	Oid			ats_tgoid;		
	Oid			ats_relid;		
	CommandId	ats_firing_id;	
} AfterTriggerSharedData;

typedef struct AfterTriggerEventData *AfterTriggerEvent;

typedef struct AfterTriggerEventData {
	TriggerFlags ate_flags;		
	ItemPointerData ate_ctid1;	
	ItemPointerData ate_ctid2;	
} AfterTriggerEventData;


typedef struct AfterTriggerEventDataOneCtid {
	TriggerFlags ate_flags;		
	ItemPointerData ate_ctid1;	
}	AfterTriggerEventDataOneCtid;







typedef struct AfterTriggerEventChunk {
	struct AfterTriggerEventChunk *next;		
	char	   *freeptr;		
	char	   *endfree;		
	char	   *endptr;			
	
} AfterTriggerEventChunk;




typedef struct AfterTriggerEventList {
	AfterTriggerEventChunk *head;
	AfterTriggerEventChunk *tail;
	char	   *tailfree;		
} AfterTriggerEventList;











typedef struct AfterTriggersData {
	CommandId	firing_counter; 
	SetConstraintState state;	
	AfterTriggerEventList events;		
	int			query_depth;	
	AfterTriggerEventList *query_stack; 
	int			maxquerydepth;	
	MemoryContext event_cxt;	

	

	SetConstraintState *state_stack;	
	AfterTriggerEventList *events_stack;		
	int		   *depth_stack;	
	CommandId  *firing_stack;	
	int			maxtransdepth;	
} AfterTriggersData;

typedef AfterTriggersData *AfterTriggers;

static AfterTriggers afterTriggers;


static void AfterTriggerExecute(AfterTriggerEvent event, Relation rel, TriggerDesc *trigdesc, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context);



static SetConstraintState SetConstraintStateCreate(int numalloc);
static SetConstraintState SetConstraintStateCopy(SetConstraintState state);
static SetConstraintState SetConstraintStateAddItem(SetConstraintState state, Oid tgoid, bool tgisdeferred);



static bool afterTriggerCheckState(AfterTriggerShared evtshared)
{
	Oid			tgoid = evtshared->ats_tgoid;
	SetConstraintState state = afterTriggers->state;
	int			i;

	
	if ((evtshared->ats_event & AFTER_TRIGGER_DEFERRABLE) == 0)
		return false;

	
	for (i = 0; i < state->numstates; i++)
	{
		if (state->trigstates[i].sct_tgoid == tgoid)
			return state->trigstates[i].sct_tgisdeferred;
	}

	
	if (state->all_isset)
		return state->all_isdeferred;

	
	return ((evtshared->ats_event & AFTER_TRIGGER_INITDEFERRED) != 0);
}



static void afterTriggerAddEvent(AfterTriggerEventList *events, AfterTriggerEvent event, AfterTriggerShared evtshared)

{
	Size		eventsize = SizeofTriggerEvent(event);
	Size		needed = eventsize + sizeof(AfterTriggerSharedData);
	AfterTriggerEventChunk *chunk;
	AfterTriggerShared newshared;
	AfterTriggerEvent newevent;

	
	chunk = events->tail;
	if (chunk == NULL || chunk->endfree - chunk->freeptr < needed)
	{
		Size		chunksize;

		
		if (afterTriggers->event_cxt == NULL)
			afterTriggers->event_cxt = AllocSetContextCreate(TopTransactionContext, "AfterTriggerEvents", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);





		







		if (chunk == NULL)
			chunksize = MIN_CHUNK_SIZE;
		else {
			
			chunksize = chunk->endptr - (char *) chunk;
			
			if ((chunk->endptr - chunk->endfree) <= (100 * sizeof(AfterTriggerSharedData)))
				chunksize *= 2; 
			else chunksize /= 2;
			chunksize = Min(chunksize, MAX_CHUNK_SIZE);
		}
		chunk = MemoryContextAlloc(afterTriggers->event_cxt, chunksize);
		chunk->next = NULL;
		chunk->freeptr = CHUNK_DATA_START(chunk);
		chunk->endptr = chunk->endfree = (char *) chunk + chunksize;
		Assert(chunk->endfree - chunk->freeptr >= needed);

		if (events->head == NULL)
			events->head = chunk;
		else events->tail->next = chunk;
		events->tail = chunk;
		
	}

	
	for (newshared = ((AfterTriggerShared) chunk->endptr) - 1;
		 (char *) newshared >= chunk->endfree;
		 newshared--)
	{
		if (newshared->ats_tgoid == evtshared->ats_tgoid && newshared->ats_relid == evtshared->ats_relid && newshared->ats_event == evtshared->ats_event && newshared->ats_firing_id == 0)


			break;
	}
	if ((char *) newshared < chunk->endfree)
	{
		*newshared = *evtshared;
		newshared->ats_firing_id = 0;	
		chunk->endfree = (char *) newshared;
	}

	
	newevent = (AfterTriggerEvent) chunk->freeptr;
	memcpy(newevent, event, eventsize);
	
	newevent->ate_flags &= ~AFTER_TRIGGER_OFFSET;
	newevent->ate_flags |= (char *) newshared - (char *) newevent;

	chunk->freeptr += eventsize;
	events->tailfree = chunk->freeptr;
}


static void afterTriggerFreeEventList(AfterTriggerEventList *events)
{
	AfterTriggerEventChunk *chunk;
	AfterTriggerEventChunk *next_chunk;

	for (chunk = events->head; chunk != NULL; chunk = next_chunk)
	{
		next_chunk = chunk->next;
		pfree(chunk);
	}
	events->head = NULL;
	events->tail = NULL;
	events->tailfree = NULL;
}


static void afterTriggerRestoreEventList(AfterTriggerEventList *events, const AfterTriggerEventList *old_events)

{
	AfterTriggerEventChunk *chunk;
	AfterTriggerEventChunk *next_chunk;

	if (old_events->tail == NULL)
	{
		
		afterTriggerFreeEventList(events);
	}
	else {
		*events = *old_events;
		
		for (chunk = events->tail->next; chunk != NULL; chunk = next_chunk)
		{
			next_chunk = chunk->next;
			pfree(chunk);
		}
		
		events->tail->next = NULL;
		events->tail->freeptr = events->tailfree;

		
	}
}



static void AfterTriggerExecute(AfterTriggerEvent event, Relation rel, TriggerDesc *trigdesc, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context)



{
	AfterTriggerShared evtshared = GetTriggerSharedData(event);
	Oid			tgoid = evtshared->ats_tgoid;
	TriggerData LocTriggerData;
	HeapTupleData tuple1;
	HeapTupleData tuple2;
	HeapTuple	rettuple;
	Buffer		buffer1 = InvalidBuffer;
	Buffer		buffer2 = InvalidBuffer;
	int			tgindx;

	
	LocTriggerData.tg_trigger = NULL;
	for (tgindx = 0; tgindx < trigdesc->numtriggers; tgindx++)
	{
		if (trigdesc->triggers[tgindx].tgoid == tgoid)
		{
			LocTriggerData.tg_trigger = &(trigdesc->triggers[tgindx]);
			break;
		}
	}
	if (LocTriggerData.tg_trigger == NULL)
		elog(ERROR, "could not find trigger %u", tgoid);

	
	if (instr)
		InstrStartNode(instr + tgindx);

	
	if (ItemPointerIsValid(&(event->ate_ctid1)))
	{
		ItemPointerCopy(&(event->ate_ctid1), &(tuple1.t_self));
		if (!heap_fetch(rel, SnapshotAny, &tuple1, &buffer1, false, NULL))
			elog(ERROR, "failed to fetch tuple1 for AFTER trigger");
		LocTriggerData.tg_trigtuple = &tuple1;
		LocTriggerData.tg_trigtuplebuf = buffer1;
	}
	else {
		LocTriggerData.tg_trigtuple = NULL;
		LocTriggerData.tg_trigtuplebuf = InvalidBuffer;
	}

	
	if ((event->ate_flags & AFTER_TRIGGER_2CTIDS) && ItemPointerIsValid(&(event->ate_ctid2)))
	{
		ItemPointerCopy(&(event->ate_ctid2), &(tuple2.t_self));
		if (!heap_fetch(rel, SnapshotAny, &tuple2, &buffer2, false, NULL))
			elog(ERROR, "failed to fetch tuple2 for AFTER trigger");
		LocTriggerData.tg_newtuple = &tuple2;
		LocTriggerData.tg_newtuplebuf = buffer2;
	}
	else {
		LocTriggerData.tg_newtuple = NULL;
		LocTriggerData.tg_newtuplebuf = InvalidBuffer;
	}

	
	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = evtshared->ats_event & (TRIGGER_EVENT_OPMASK | TRIGGER_EVENT_ROW);
	LocTriggerData.tg_relation = rel;

	MemoryContextReset(per_tuple_context);

	
	rettuple = ExecCallTriggerFunc(&LocTriggerData, tgindx, finfo, NULL, per_tuple_context);



	if (rettuple != NULL && rettuple != &tuple1 && rettuple != &tuple2)
		heap_freetuple(rettuple);

	
	if (buffer1 != InvalidBuffer)
		ReleaseBuffer(buffer1);
	if (buffer2 != InvalidBuffer)
		ReleaseBuffer(buffer2);

	
	if (instr)
		InstrStopNode(instr + tgindx, 1);
}



static bool afterTriggerMarkEvents(AfterTriggerEventList *events, AfterTriggerEventList *move_list, bool immediate_only)


{
	bool		found = false;
	AfterTriggerEvent event;
	AfterTriggerEventChunk *chunk;

	for_each_event_chunk(event, chunk, *events)
	{
		AfterTriggerShared evtshared = GetTriggerSharedData(event);
		bool		defer_it = false;

		if (!(event->ate_flags & (AFTER_TRIGGER_DONE | AFTER_TRIGGER_IN_PROGRESS)))
		{
			
			if (immediate_only && afterTriggerCheckState(evtshared))
			{
				defer_it = true;
			}
			else {
				
				evtshared->ats_firing_id = afterTriggers->firing_counter;
				event->ate_flags |= AFTER_TRIGGER_IN_PROGRESS;
				found = true;
			}
		}

		
		if (defer_it && move_list != NULL)
		{
			
			afterTriggerAddEvent(move_list, event, evtshared);
			
			event->ate_flags |= AFTER_TRIGGER_DONE;
		}
	}

	return found;
}


static bool afterTriggerInvokeEvents(AfterTriggerEventList *events, CommandId firing_id, EState *estate, bool delete_ok)



{
	bool		all_fired = true;
	AfterTriggerEventChunk *chunk;
	MemoryContext per_tuple_context;
	bool		local_estate = false;
	Relation	rel = NULL;
	TriggerDesc *trigdesc = NULL;
	FmgrInfo   *finfo = NULL;
	Instrumentation *instr = NULL;

	
	if (estate == NULL)
	{
		estate = CreateExecutorState();
		local_estate = true;
	}

	
	per_tuple_context = AllocSetContextCreate(CurrentMemoryContext, "AfterTriggerTupleContext", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);





	for_each_chunk(chunk, *events)
	{
		AfterTriggerEvent event;
		bool		all_fired_in_chunk = true;

		for_each_event(event, chunk)
		{
			AfterTriggerShared evtshared = GetTriggerSharedData(event);

			
			if ((event->ate_flags & AFTER_TRIGGER_IN_PROGRESS) && evtshared->ats_firing_id == firing_id)
			{
				
				if (rel == NULL || RelationGetRelid(rel) != evtshared->ats_relid)
				{
					ResultRelInfo *rInfo;

					rInfo = ExecGetTriggerResultRel(estate, evtshared->ats_relid);
					rel = rInfo->ri_RelationDesc;
					trigdesc = rInfo->ri_TrigDesc;
					finfo = rInfo->ri_TrigFunctions;
					instr = rInfo->ri_TrigInstrument;
					if (trigdesc == NULL)		
						elog(ERROR, "relation %u has no triggers", evtshared->ats_relid);
				}

				
				AfterTriggerExecute(event, rel, trigdesc, finfo, instr, per_tuple_context);

				
				event->ate_flags &= ~AFTER_TRIGGER_IN_PROGRESS;
				event->ate_flags |= AFTER_TRIGGER_DONE;
			}
			else if (!(event->ate_flags & AFTER_TRIGGER_DONE))
			{
				
				all_fired = all_fired_in_chunk = false;
			}
		}

		
		if (delete_ok && all_fired_in_chunk)
		{
			chunk->freeptr = CHUNK_DATA_START(chunk);
			chunk->endfree = chunk->endptr;

			
			if (chunk == events->tail)
				events->tailfree = chunk->freeptr;
		}
	}

	
	MemoryContextDelete(per_tuple_context);

	if (local_estate)
	{
		ListCell   *l;

		foreach(l, estate->es_trig_target_relations)
		{
			ResultRelInfo *resultRelInfo = (ResultRelInfo *) lfirst(l);

			
			ExecCloseIndices(resultRelInfo);
			heap_close(resultRelInfo->ri_RelationDesc, NoLock);
		}
		FreeExecutorState(estate);
	}

	return all_fired;
}



void AfterTriggerBeginXact(void)
{
	Assert(afterTriggers == NULL);

	
	afterTriggers = (AfterTriggers)
		MemoryContextAlloc(TopTransactionContext, sizeof(AfterTriggersData));

	afterTriggers->firing_counter = (CommandId) 1;		
	afterTriggers->state = SetConstraintStateCreate(8);
	afterTriggers->events.head = NULL;
	afterTriggers->events.tail = NULL;
	afterTriggers->events.tailfree = NULL;
	afterTriggers->query_depth = -1;

	
	afterTriggers->query_stack = (AfterTriggerEventList *)
		MemoryContextAlloc(TopTransactionContext, 8 * sizeof(AfterTriggerEventList));
	afterTriggers->maxquerydepth = 8;

	
	afterTriggers->event_cxt = NULL;

	
	afterTriggers->state_stack = NULL;
	afterTriggers->events_stack = NULL;
	afterTriggers->depth_stack = NULL;
	afterTriggers->firing_stack = NULL;
	afterTriggers->maxtransdepth = 0;
}



void AfterTriggerBeginQuery(void)
{
	AfterTriggerEventList *events;

	
	Assert(afterTriggers != NULL);

	
	afterTriggers->query_depth++;

	
	if (afterTriggers->query_depth >= afterTriggers->maxquerydepth)
	{
		
		int			new_alloc = afterTriggers->maxquerydepth * 2;

		afterTriggers->query_stack = (AfterTriggerEventList *)
			repalloc(afterTriggers->query_stack, new_alloc * sizeof(AfterTriggerEventList));
		afterTriggers->maxquerydepth = new_alloc;
	}

	
	events = &afterTriggers->query_stack[afterTriggers->query_depth];
	events->head = NULL;
	events->tail = NULL;
	events->tailfree = NULL;
}



void AfterTriggerEndQuery(EState *estate)
{
	AfterTriggerEventList *events;

	
	Assert(afterTriggers != NULL);

	
	Assert(afterTriggers->query_depth >= 0);

	
	for (;;)
	{
		events = &afterTriggers->query_stack[afterTriggers->query_depth];
		if (afterTriggerMarkEvents(events, &afterTriggers->events, true))
		{
			CommandId	firing_id = afterTriggers->firing_counter++;

			
			if (afterTriggerInvokeEvents(events, firing_id, estate, true))
				break;			
		}
		else break;
	}

	
	afterTriggerFreeEventList(&afterTriggers->query_stack[afterTriggers->query_depth]);

	afterTriggers->query_depth--;
}



void AfterTriggerFireDeferred(void)
{
	AfterTriggerEventList *events;
	bool		snap_pushed = false;

	
	Assert(afterTriggers != NULL);

	
	Assert(afterTriggers->query_depth == -1);

	
	events = &afterTriggers->events;
	if (events->head != NULL)
	{
		PushActiveSnapshot(GetTransactionSnapshot());
		snap_pushed = true;
	}

	
	while (afterTriggerMarkEvents(events, NULL, false))
	{
		CommandId	firing_id = afterTriggers->firing_counter++;

		if (afterTriggerInvokeEvents(events, firing_id, NULL, true))
			break;				
	}

	

	if (snap_pushed)
		PopActiveSnapshot();
}



void AfterTriggerEndXact(bool isCommit)
{
	
	if (afterTriggers && afterTriggers->event_cxt)
		MemoryContextDelete(afterTriggers->event_cxt);

	afterTriggers = NULL;
}


void AfterTriggerBeginSubXact(void)
{
	int			my_level = GetCurrentTransactionNestLevel();

	
	if (afterTriggers == NULL)
		return;

	
	while (my_level >= afterTriggers->maxtransdepth)
	{
		if (afterTriggers->maxtransdepth == 0)
		{
			MemoryContext old_cxt;

			old_cxt = MemoryContextSwitchTo(TopTransactionContext);


			afterTriggers->state_stack = (SetConstraintState *)
				palloc(DEFTRIG_INITALLOC * sizeof(SetConstraintState));
			afterTriggers->events_stack = (AfterTriggerEventList *)
				palloc(DEFTRIG_INITALLOC * sizeof(AfterTriggerEventList));
			afterTriggers->depth_stack = (int *)
				palloc(DEFTRIG_INITALLOC * sizeof(int));
			afterTriggers->firing_stack = (CommandId *)
				palloc(DEFTRIG_INITALLOC * sizeof(CommandId));
			afterTriggers->maxtransdepth = DEFTRIG_INITALLOC;

			MemoryContextSwitchTo(old_cxt);
		}
		else {
			
			int			new_alloc = afterTriggers->maxtransdepth * 2;

			afterTriggers->state_stack = (SetConstraintState *)
				repalloc(afterTriggers->state_stack, new_alloc * sizeof(SetConstraintState));
			afterTriggers->events_stack = (AfterTriggerEventList *)
				repalloc(afterTriggers->events_stack, new_alloc * sizeof(AfterTriggerEventList));
			afterTriggers->depth_stack = (int *)
				repalloc(afterTriggers->depth_stack, new_alloc * sizeof(int));
			afterTriggers->firing_stack = (CommandId *)
				repalloc(afterTriggers->firing_stack, new_alloc * sizeof(CommandId));
			afterTriggers->maxtransdepth = new_alloc;
		}
	}

	
	afterTriggers->state_stack[my_level] = NULL;
	afterTriggers->events_stack[my_level] = afterTriggers->events;
	afterTriggers->depth_stack[my_level] = afterTriggers->query_depth;
	afterTriggers->firing_stack[my_level] = afterTriggers->firing_counter;
}


void AfterTriggerEndSubXact(bool isCommit)
{
	int			my_level = GetCurrentTransactionNestLevel();
	SetConstraintState state;
	AfterTriggerEvent event;
	AfterTriggerEventChunk *chunk;
	CommandId	subxact_firing_id;

	
	if (afterTriggers == NULL)
		return;

	
	if (isCommit)
	{
		Assert(my_level < afterTriggers->maxtransdepth);
		
		state = afterTriggers->state_stack[my_level];
		if (state != NULL)
			pfree(state);
		
		afterTriggers->state_stack[my_level] = NULL;
		Assert(afterTriggers->query_depth == afterTriggers->depth_stack[my_level]);
	}
	else {
		
		if (my_level >= afterTriggers->maxtransdepth)
			return;

		
		while (afterTriggers->query_depth > afterTriggers->depth_stack[my_level])
		{
			afterTriggerFreeEventList(&afterTriggers->query_stack[afterTriggers->query_depth]);
			afterTriggers->query_depth--;
		}
		Assert(afterTriggers->query_depth == afterTriggers->depth_stack[my_level]);

		
		afterTriggerRestoreEventList(&afterTriggers->events, &afterTriggers->events_stack[my_level]);

		
		state = afterTriggers->state_stack[my_level];
		if (state != NULL)
		{
			pfree(afterTriggers->state);
			afterTriggers->state = state;
		}
		
		afterTriggers->state_stack[my_level] = NULL;

		
		subxact_firing_id = afterTriggers->firing_stack[my_level];
		for_each_event_chunk(event, chunk, afterTriggers->events)
		{
			AfterTriggerShared evtshared = GetTriggerSharedData(event);

			if (event->ate_flags & (AFTER_TRIGGER_DONE | AFTER_TRIGGER_IN_PROGRESS))
			{
				if (evtshared->ats_firing_id >= subxact_firing_id)
					event->ate_flags &= ~(AFTER_TRIGGER_DONE | AFTER_TRIGGER_IN_PROGRESS);
			}
		}
	}
}


static SetConstraintState SetConstraintStateCreate(int numalloc)
{
	SetConstraintState state;

	
	if (numalloc <= 0)
		numalloc = 1;

	
	state = (SetConstraintState)
		MemoryContextAllocZero(TopTransactionContext, sizeof(SetConstraintStateData) + (numalloc - 1) *sizeof(SetConstraintTriggerData));


	state->numalloc = numalloc;

	return state;
}


static SetConstraintState SetConstraintStateCopy(SetConstraintState origstate)
{
	SetConstraintState state;

	state = SetConstraintStateCreate(origstate->numstates);

	state->all_isset = origstate->all_isset;
	state->all_isdeferred = origstate->all_isdeferred;
	state->numstates = origstate->numstates;
	memcpy(state->trigstates, origstate->trigstates, origstate->numstates * sizeof(SetConstraintTriggerData));

	return state;
}


static SetConstraintState SetConstraintStateAddItem(SetConstraintState state, Oid tgoid, bool tgisdeferred)

{
	if (state->numstates >= state->numalloc)
	{
		int			newalloc = state->numalloc * 2;

		newalloc = Max(newalloc, 8);	
		state = (SetConstraintState)
			repalloc(state, sizeof(SetConstraintStateData) + (newalloc - 1) *sizeof(SetConstraintTriggerData));

		state->numalloc = newalloc;
		Assert(state->numstates < state->numalloc);
	}

	state->trigstates[state->numstates].sct_tgoid = tgoid;
	state->trigstates[state->numstates].sct_tgisdeferred = tgisdeferred;
	state->numstates++;

	return state;
}


void AfterTriggerSetState(ConstraintsSetStmt *stmt)
{
	int			my_level = GetCurrentTransactionNestLevel();

	
	if (afterTriggers == NULL)
		return;

	
	if (my_level > 1 && afterTriggers->state_stack[my_level] == NULL)
	{
		afterTriggers->state_stack[my_level] = SetConstraintStateCopy(afterTriggers->state);
	}

	
	if (stmt->constraints == NIL)
	{
		
		afterTriggers->state->numstates = 0;

		
		afterTriggers->state->all_isset = true;
		afterTriggers->state->all_isdeferred = stmt->deferred;
	}
	else {
		Relation	conrel;
		Relation	tgrel;
		List	   *conoidlist = NIL;
		List	   *tgoidlist = NIL;
		ListCell   *lc;

		
		conrel = heap_open(ConstraintRelationId, AccessShareLock);

		foreach(lc, stmt->constraints)
		{
			RangeVar   *constraint = lfirst(lc);
			bool		found;
			List	   *namespacelist;
			ListCell   *nslc;

			if (constraint->catalogname)
			{
				if (strcmp(constraint->catalogname, get_database_name(MyDatabaseId)) != 0)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cross-database references are not implemented: \"%s.%s.%s\"", constraint->catalogname, constraint->schemaname, constraint->relname)));



			}

			
			if (constraint->schemaname)
			{
				Oid			namespaceId = LookupExplicitNamespace(constraint->schemaname, false);

				namespacelist = list_make1_oid(namespaceId);
			}
			else {
				namespacelist = fetch_search_path(true);
			}

			found = false;
			foreach(nslc, namespacelist)
			{
				Oid			namespaceId = lfirst_oid(nslc);
				SysScanDesc conscan;
				ScanKeyData skey[2];
				HeapTuple	tup;

				ScanKeyInit(&skey[0], Anum_pg_constraint_conname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(constraint->relname));


				ScanKeyInit(&skey[1], Anum_pg_constraint_connamespace, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(namespaceId));



				conscan = systable_beginscan(conrel, ConstraintNameNspIndexId, true, NULL, 2, skey);

				while (HeapTupleIsValid(tup = systable_getnext(conscan)))
				{
					Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tup);

					if (con->condeferrable)
						conoidlist = lappend_oid(conoidlist, HeapTupleGetOid(tup));
					else if (stmt->deferred)
						ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("constraint \"%s\" is not deferrable", constraint->relname)));


					found = true;
				}

				systable_endscan(conscan);

				
				if (found)
					break;
			}

			list_free(namespacelist);

			
			if (!found)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" does not exist", constraint->relname)));


		}

		heap_close(conrel, AccessShareLock);

		
		tgrel = heap_open(TriggerRelationId, AccessShareLock);

		foreach(lc, conoidlist)
		{
			Oid			conoid = lfirst_oid(lc);
			bool		found;
			ScanKeyData skey;
			SysScanDesc tgscan;
			HeapTuple	htup;

			found = false;

			ScanKeyInit(&skey, Anum_pg_trigger_tgconstraint, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(conoid));



			tgscan = systable_beginscan(tgrel, TriggerConstraintIndexId, true, NULL, 1, &skey);

			while (HeapTupleIsValid(htup = systable_getnext(tgscan)))
			{
				Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(htup);

				
				if (pg_trigger->tgdeferrable)
					tgoidlist = lappend_oid(tgoidlist, HeapTupleGetOid(htup));

				found = true;
			}

			systable_endscan(tgscan);

			
			if (!found)
				elog(ERROR, "no triggers found for constraint with OID %u", conoid);
		}

		heap_close(tgrel, AccessShareLock);

		
		foreach(lc, tgoidlist)
		{
			Oid			tgoid = lfirst_oid(lc);
			SetConstraintState state = afterTriggers->state;
			bool		found = false;
			int			i;

			for (i = 0; i < state->numstates; i++)
			{
				if (state->trigstates[i].sct_tgoid == tgoid)
				{
					state->trigstates[i].sct_tgisdeferred = stmt->deferred;
					found = true;
					break;
				}
			}
			if (!found)
			{
				afterTriggers->state = SetConstraintStateAddItem(state, tgoid, stmt->deferred);
			}
		}
	}

	
	if (!stmt->deferred)
	{
		AfterTriggerEventList *events = &afterTriggers->events;
		bool		snapshot_set = false;

		while (afterTriggerMarkEvents(events, NULL, true))
		{
			CommandId	firing_id = afterTriggers->firing_counter++;

			
			if (!snapshot_set)
			{
				PushActiveSnapshot(GetTransactionSnapshot());
				snapshot_set = true;
			}

			
			if (afterTriggerInvokeEvents(events, firing_id, NULL, !IsSubTransaction()))
				break;			
		}

		if (snapshot_set)
			PopActiveSnapshot();
	}
}


bool AfterTriggerPendingOnRel(Oid relid)
{
	AfterTriggerEvent event;
	AfterTriggerEventChunk *chunk;
	int			depth;

	
	if (afterTriggers == NULL)
		return false;

	
	for_each_event_chunk(event, chunk, afterTriggers->events)
	{
		AfterTriggerShared evtshared = GetTriggerSharedData(event);

		
		if (event->ate_flags & AFTER_TRIGGER_DONE)
			continue;

		if (evtshared->ats_relid == relid)
			return true;
	}

	
	for (depth = 0; depth <= afterTriggers->query_depth; depth++)
	{
		for_each_event_chunk(event, chunk, afterTriggers->query_stack[depth])
		{
			AfterTriggerShared evtshared = GetTriggerSharedData(event);

			if (event->ate_flags & AFTER_TRIGGER_DONE)
				continue;

			if (evtshared->ats_relid == relid)
				return true;
		}
	}

	return false;
}



static void AfterTriggerSaveEvent(EState *estate, ResultRelInfo *relinfo, int event, bool row_trigger, HeapTuple oldtup, HeapTuple newtup, List *recheckIndexes, Bitmapset *modifiedCols)



{
	Relation	rel = relinfo->ri_RelationDesc;
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	AfterTriggerEventData new_event;
	AfterTriggerSharedData new_shared;
	int			tgtype_event;
	int			tgtype_level;
	int			i;

	
	if (afterTriggers == NULL)
		elog(ERROR, "AfterTriggerSaveEvent() called outside of transaction");
	if (afterTriggers->query_depth < 0)
		elog(ERROR, "AfterTriggerSaveEvent() called outside of query");

	
	new_event.ate_flags = 0;
	switch (event)
	{
		case TRIGGER_EVENT_INSERT:
			tgtype_event = TRIGGER_TYPE_INSERT;
			if (row_trigger)
			{
				Assert(oldtup == NULL);
				Assert(newtup != NULL);
				ItemPointerCopy(&(newtup->t_self), &(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			else {
				Assert(oldtup == NULL);
				Assert(newtup == NULL);
				ItemPointerSetInvalid(&(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			break;
		case TRIGGER_EVENT_DELETE:
			tgtype_event = TRIGGER_TYPE_DELETE;
			if (row_trigger)
			{
				Assert(oldtup != NULL);
				Assert(newtup == NULL);
				ItemPointerCopy(&(oldtup->t_self), &(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			else {
				Assert(oldtup == NULL);
				Assert(newtup == NULL);
				ItemPointerSetInvalid(&(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			break;
		case TRIGGER_EVENT_UPDATE:
			tgtype_event = TRIGGER_TYPE_UPDATE;
			if (row_trigger)
			{
				Assert(oldtup != NULL);
				Assert(newtup != NULL);
				ItemPointerCopy(&(oldtup->t_self), &(new_event.ate_ctid1));
				ItemPointerCopy(&(newtup->t_self), &(new_event.ate_ctid2));
				new_event.ate_flags |= AFTER_TRIGGER_2CTIDS;
			}
			else {
				Assert(oldtup == NULL);
				Assert(newtup == NULL);
				ItemPointerSetInvalid(&(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			break;
		case TRIGGER_EVENT_TRUNCATE:
			tgtype_event = TRIGGER_TYPE_TRUNCATE;
			Assert(oldtup == NULL);
			Assert(newtup == NULL);
			ItemPointerSetInvalid(&(new_event.ate_ctid1));
			ItemPointerSetInvalid(&(new_event.ate_ctid2));
			break;
		default:
			elog(ERROR, "invalid after-trigger event code: %d", event);
			tgtype_event = 0;	
			break;
	}

	tgtype_level = (row_trigger ? TRIGGER_TYPE_ROW : TRIGGER_TYPE_STATEMENT);

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, tgtype_level, TRIGGER_TYPE_AFTER, tgtype_event))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, event, modifiedCols, oldtup, newtup))
			continue;

		
		if (TRIGGER_FIRED_BY_UPDATE(event))
		{
			switch (RI_FKey_trigger_type(trigger->tgfoid))
			{
				case RI_TRIGGER_PK:
					
					if (!RI_FKey_pk_upd_check_required(trigger, rel, oldtup, newtup))
					{
						
						continue;
					}
					break;

				case RI_TRIGGER_FK:
					
					if (!RI_FKey_fk_upd_check_required(trigger, rel, oldtup, newtup))
					{
						
						continue;
					}
					break;

				case RI_TRIGGER_NONE:
					
					break;
			}
		}

		
		if (trigger->tgfoid == F_UNIQUE_KEY_RECHECK)
		{
			if (!list_member_oid(recheckIndexes, trigger->tgconstrindid))
				continue;		
		}

		
		new_shared.ats_event = (event & TRIGGER_EVENT_OPMASK) | (row_trigger ? TRIGGER_EVENT_ROW : 0) | (trigger->tgdeferrable ? AFTER_TRIGGER_DEFERRABLE : 0) | (trigger->tginitdeferred ? AFTER_TRIGGER_INITDEFERRED : 0);



		new_shared.ats_tgoid = trigger->tgoid;
		new_shared.ats_relid = RelationGetRelid(rel);
		new_shared.ats_firing_id = 0;

		afterTriggerAddEvent(&afterTriggers->query_stack[afterTriggers->query_depth], &new_event, &new_shared);
	}
}

Datum pg_trigger_depth(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(MyTriggerDepth);
}
