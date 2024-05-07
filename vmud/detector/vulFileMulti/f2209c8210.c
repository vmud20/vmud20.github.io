






















Oid CreateConstraintEntry(const char *constraintName, Oid constraintNamespace, char constraintType, bool isDeferrable, bool isDeferred, bool isValidated, Oid relId, const int16 *constraintKey, int constraintNKeys, Oid domainId, Oid indexRelId, Oid foreignRelId, const int16 *foreignKey, const Oid *pfEqOp, const Oid *ppEqOp, const Oid *ffEqOp, int foreignNKeys, char foreignUpdateType, char foreignDeleteType, char foreignMatchType, const Oid *exclOp, Node *conExpr, const char *conBin, const char *conSrc, bool conIsLocal, int conInhCount, bool conNoInherit, bool is_internal)



























{
	Relation	conDesc;
	Oid			conOid;
	HeapTuple	tup;
	bool		nulls[Natts_pg_constraint];
	Datum		values[Natts_pg_constraint];
	ArrayType  *conkeyArray;
	ArrayType  *confkeyArray;
	ArrayType  *conpfeqopArray;
	ArrayType  *conppeqopArray;
	ArrayType  *conffeqopArray;
	ArrayType  *conexclopArray;
	NameData	cname;
	int			i;
	ObjectAddress conobject;

	conDesc = heap_open(ConstraintRelationId, RowExclusiveLock);

	Assert(constraintName);
	namestrcpy(&cname, constraintName);

	
	if (constraintNKeys > 0)
	{
		Datum	   *conkey;

		conkey = (Datum *) palloc(constraintNKeys * sizeof(Datum));
		for (i = 0; i < constraintNKeys; i++)
			conkey[i] = Int16GetDatum(constraintKey[i]);
		conkeyArray = construct_array(conkey, constraintNKeys, INT2OID, 2, true, 's');
	}
	else conkeyArray = NULL;

	if (foreignNKeys > 0)
	{
		Datum	   *fkdatums;

		fkdatums = (Datum *) palloc(foreignNKeys * sizeof(Datum));
		for (i = 0; i < foreignNKeys; i++)
			fkdatums[i] = Int16GetDatum(foreignKey[i]);
		confkeyArray = construct_array(fkdatums, foreignNKeys, INT2OID, 2, true, 's');
		for (i = 0; i < foreignNKeys; i++)
			fkdatums[i] = ObjectIdGetDatum(pfEqOp[i]);
		conpfeqopArray = construct_array(fkdatums, foreignNKeys, OIDOID, sizeof(Oid), true, 'i');
		for (i = 0; i < foreignNKeys; i++)
			fkdatums[i] = ObjectIdGetDatum(ppEqOp[i]);
		conppeqopArray = construct_array(fkdatums, foreignNKeys, OIDOID, sizeof(Oid), true, 'i');
		for (i = 0; i < foreignNKeys; i++)
			fkdatums[i] = ObjectIdGetDatum(ffEqOp[i]);
		conffeqopArray = construct_array(fkdatums, foreignNKeys, OIDOID, sizeof(Oid), true, 'i');
	}
	else {
		confkeyArray = NULL;
		conpfeqopArray = NULL;
		conppeqopArray = NULL;
		conffeqopArray = NULL;
	}

	if (exclOp != NULL)
	{
		Datum	   *opdatums;

		opdatums = (Datum *) palloc(constraintNKeys * sizeof(Datum));
		for (i = 0; i < constraintNKeys; i++)
			opdatums[i] = ObjectIdGetDatum(exclOp[i]);
		conexclopArray = construct_array(opdatums, constraintNKeys, OIDOID, sizeof(Oid), true, 'i');
	}
	else conexclopArray = NULL;

	
	for (i = 0; i < Natts_pg_constraint; i++)
	{
		nulls[i] = false;
		values[i] = (Datum) NULL;
	}

	values[Anum_pg_constraint_conname - 1] = NameGetDatum(&cname);
	values[Anum_pg_constraint_connamespace - 1] = ObjectIdGetDatum(constraintNamespace);
	values[Anum_pg_constraint_contype - 1] = CharGetDatum(constraintType);
	values[Anum_pg_constraint_condeferrable - 1] = BoolGetDatum(isDeferrable);
	values[Anum_pg_constraint_condeferred - 1] = BoolGetDatum(isDeferred);
	values[Anum_pg_constraint_convalidated - 1] = BoolGetDatum(isValidated);
	values[Anum_pg_constraint_conrelid - 1] = ObjectIdGetDatum(relId);
	values[Anum_pg_constraint_contypid - 1] = ObjectIdGetDatum(domainId);
	values[Anum_pg_constraint_conindid - 1] = ObjectIdGetDatum(indexRelId);
	values[Anum_pg_constraint_confrelid - 1] = ObjectIdGetDatum(foreignRelId);
	values[Anum_pg_constraint_confupdtype - 1] = CharGetDatum(foreignUpdateType);
	values[Anum_pg_constraint_confdeltype - 1] = CharGetDatum(foreignDeleteType);
	values[Anum_pg_constraint_confmatchtype - 1] = CharGetDatum(foreignMatchType);
	values[Anum_pg_constraint_conislocal - 1] = BoolGetDatum(conIsLocal);
	values[Anum_pg_constraint_coninhcount - 1] = Int32GetDatum(conInhCount);
	values[Anum_pg_constraint_connoinherit - 1] = BoolGetDatum(conNoInherit);

	if (conkeyArray)
		values[Anum_pg_constraint_conkey - 1] = PointerGetDatum(conkeyArray);
	else nulls[Anum_pg_constraint_conkey - 1] = true;

	if (confkeyArray)
		values[Anum_pg_constraint_confkey - 1] = PointerGetDatum(confkeyArray);
	else nulls[Anum_pg_constraint_confkey - 1] = true;

	if (conpfeqopArray)
		values[Anum_pg_constraint_conpfeqop - 1] = PointerGetDatum(conpfeqopArray);
	else nulls[Anum_pg_constraint_conpfeqop - 1] = true;

	if (conppeqopArray)
		values[Anum_pg_constraint_conppeqop - 1] = PointerGetDatum(conppeqopArray);
	else nulls[Anum_pg_constraint_conppeqop - 1] = true;

	if (conffeqopArray)
		values[Anum_pg_constraint_conffeqop - 1] = PointerGetDatum(conffeqopArray);
	else nulls[Anum_pg_constraint_conffeqop - 1] = true;

	if (conexclopArray)
		values[Anum_pg_constraint_conexclop - 1] = PointerGetDatum(conexclopArray);
	else nulls[Anum_pg_constraint_conexclop - 1] = true;

	
	if (conBin)
		values[Anum_pg_constraint_conbin - 1] = CStringGetTextDatum(conBin);
	else nulls[Anum_pg_constraint_conbin - 1] = true;

	
	if (conSrc)
		values[Anum_pg_constraint_consrc - 1] = CStringGetTextDatum(conSrc);
	else nulls[Anum_pg_constraint_consrc - 1] = true;

	tup = heap_form_tuple(RelationGetDescr(conDesc), values, nulls);

	conOid = simple_heap_insert(conDesc, tup);

	
	CatalogUpdateIndexes(conDesc, tup);

	conobject.classId = ConstraintRelationId;
	conobject.objectId = conOid;
	conobject.objectSubId = 0;

	heap_close(conDesc, RowExclusiveLock);

	if (OidIsValid(relId))
	{
		
		ObjectAddress relobject;

		relobject.classId = RelationRelationId;
		relobject.objectId = relId;
		if (constraintNKeys > 0)
		{
			for (i = 0; i < constraintNKeys; i++)
			{
				relobject.objectSubId = constraintKey[i];

				recordDependencyOn(&conobject, &relobject, DEPENDENCY_AUTO);
			}
		}
		else {
			relobject.objectSubId = 0;

			recordDependencyOn(&conobject, &relobject, DEPENDENCY_AUTO);
		}
	}

	if (OidIsValid(domainId))
	{
		
		ObjectAddress domobject;

		domobject.classId = TypeRelationId;
		domobject.objectId = domainId;
		domobject.objectSubId = 0;

		recordDependencyOn(&conobject, &domobject, DEPENDENCY_AUTO);
	}

	if (OidIsValid(foreignRelId))
	{
		
		ObjectAddress relobject;

		relobject.classId = RelationRelationId;
		relobject.objectId = foreignRelId;
		if (foreignNKeys > 0)
		{
			for (i = 0; i < foreignNKeys; i++)
			{
				relobject.objectSubId = foreignKey[i];

				recordDependencyOn(&conobject, &relobject, DEPENDENCY_NORMAL);
			}
		}
		else {
			relobject.objectSubId = 0;

			recordDependencyOn(&conobject, &relobject, DEPENDENCY_NORMAL);
		}
	}

	if (OidIsValid(indexRelId) && constraintType == CONSTRAINT_FOREIGN)
	{
		
		ObjectAddress relobject;

		relobject.classId = RelationRelationId;
		relobject.objectId = indexRelId;
		relobject.objectSubId = 0;

		recordDependencyOn(&conobject, &relobject, DEPENDENCY_NORMAL);
	}

	if (foreignNKeys > 0)
	{
		
		ObjectAddress oprobject;

		oprobject.classId = OperatorRelationId;
		oprobject.objectSubId = 0;

		for (i = 0; i < foreignNKeys; i++)
		{
			oprobject.objectId = pfEqOp[i];
			recordDependencyOn(&conobject, &oprobject, DEPENDENCY_NORMAL);
			if (ppEqOp[i] != pfEqOp[i])
			{
				oprobject.objectId = ppEqOp[i];
				recordDependencyOn(&conobject, &oprobject, DEPENDENCY_NORMAL);
			}
			if (ffEqOp[i] != pfEqOp[i])
			{
				oprobject.objectId = ffEqOp[i];
				recordDependencyOn(&conobject, &oprobject, DEPENDENCY_NORMAL);
			}
		}
	}

	

	if (conExpr != NULL)
	{
		
		recordDependencyOnSingleRelExpr(&conobject, conExpr, relId, DEPENDENCY_NORMAL, DEPENDENCY_NORMAL);

	}

	
	InvokeObjectPostCreateHookArg(ConstraintRelationId, conOid, 0, is_internal);

	return conOid;
}



bool ConstraintNameIsUsed(ConstraintCategory conCat, Oid objId, Oid objNamespace, const char *conname)

{
	bool		found;
	Relation	conDesc;
	SysScanDesc conscan;
	ScanKeyData skey[2];
	HeapTuple	tup;

	conDesc = heap_open(ConstraintRelationId, AccessShareLock);

	found = false;

	ScanKeyInit(&skey[0], Anum_pg_constraint_conname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(conname));



	ScanKeyInit(&skey[1], Anum_pg_constraint_connamespace, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(objNamespace));



	conscan = systable_beginscan(conDesc, ConstraintNameNspIndexId, true, NULL, 2, skey);

	while (HeapTupleIsValid(tup = systable_getnext(conscan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tup);

		if (conCat == CONSTRAINT_RELATION && con->conrelid == objId)
		{
			found = true;
			break;
		}
		else if (conCat == CONSTRAINT_DOMAIN && con->contypid == objId)
		{
			found = true;
			break;
		}
	}

	systable_endscan(conscan);
	heap_close(conDesc, AccessShareLock);

	return found;
}


char * ChooseConstraintName(const char *name1, const char *name2, const char *label, Oid namespaceid, List *others)


{
	int			pass = 0;
	char	   *conname = NULL;
	char		modlabel[NAMEDATALEN];
	Relation	conDesc;
	SysScanDesc conscan;
	ScanKeyData skey[2];
	bool		found;
	ListCell   *l;

	conDesc = heap_open(ConstraintRelationId, AccessShareLock);

	
	StrNCpy(modlabel, label, sizeof(modlabel));

	for (;;)
	{
		conname = makeObjectName(name1, name2, modlabel);

		found = false;

		foreach(l, others)
		{
			if (strcmp((char *) lfirst(l), conname) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found)
		{
			ScanKeyInit(&skey[0], Anum_pg_constraint_conname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(conname));



			ScanKeyInit(&skey[1], Anum_pg_constraint_connamespace, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(namespaceid));



			conscan = systable_beginscan(conDesc, ConstraintNameNspIndexId, true, NULL, 2, skey);

			found = (HeapTupleIsValid(systable_getnext(conscan)));

			systable_endscan(conscan);
		}

		if (!found)
			break;

		
		pfree(conname);
		snprintf(modlabel, sizeof(modlabel), "%s%d", label, ++pass);
	}

	heap_close(conDesc, AccessShareLock);

	return conname;
}


void RemoveConstraintById(Oid conId)
{
	Relation	conDesc;
	HeapTuple	tup;
	Form_pg_constraint con;

	conDesc = heap_open(ConstraintRelationId, RowExclusiveLock);

	tup = SearchSysCache1(CONSTROID, ObjectIdGetDatum(conId));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for constraint %u", conId);
	con = (Form_pg_constraint) GETSTRUCT(tup);

	
	if (OidIsValid(con->conrelid))
	{
		Relation	rel;

		
		rel = heap_open(con->conrelid, AccessExclusiveLock);

		
		if (con->contype == CONSTRAINT_CHECK)
		{
			Relation	pgrel;
			HeapTuple	relTup;
			Form_pg_class classForm;

			pgrel = heap_open(RelationRelationId, RowExclusiveLock);
			relTup = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(con->conrelid));
			if (!HeapTupleIsValid(relTup))
				elog(ERROR, "cache lookup failed for relation %u", con->conrelid);
			classForm = (Form_pg_class) GETSTRUCT(relTup);

			if (classForm->relchecks == 0)		
				elog(ERROR, "relation \"%s\" has relchecks = 0", RelationGetRelationName(rel));
			classForm->relchecks--;

			simple_heap_update(pgrel, &relTup->t_self, relTup);

			CatalogUpdateIndexes(pgrel, relTup);

			heap_freetuple(relTup);

			heap_close(pgrel, RowExclusiveLock);
		}

		
		heap_close(rel, NoLock);
	}
	else if (OidIsValid(con->contypid))
	{
		
	}
	else elog(ERROR, "constraint %u is not of a known type", conId);

	
	simple_heap_delete(conDesc, &tup->t_self);

	
	ReleaseSysCache(tup);
	heap_close(conDesc, RowExclusiveLock);
}


void RenameConstraintById(Oid conId, const char *newname)
{
	Relation	conDesc;
	HeapTuple	tuple;
	Form_pg_constraint con;

	conDesc = heap_open(ConstraintRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy1(CONSTROID, ObjectIdGetDatum(conId));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for constraint %u", conId);
	con = (Form_pg_constraint) GETSTRUCT(tuple);

	
	if (OidIsValid(con->conrelid) && ConstraintNameIsUsed(CONSTRAINT_RELATION, con->conrelid, con->connamespace, newname))



		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("constraint \"%s\" for relation \"%s\" already exists", newname, get_rel_name(con->conrelid))));


	if (OidIsValid(con->contypid) && ConstraintNameIsUsed(CONSTRAINT_DOMAIN, con->contypid, con->connamespace, newname))



		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("constraint \"%s\" for domain %s already exists", newname, format_type_be(con->contypid))));



	
	namestrcpy(&(con->conname), newname);

	simple_heap_update(conDesc, &tuple->t_self, tuple);

	
	CatalogUpdateIndexes(conDesc, tuple);

	InvokeObjectPostAlterHook(ConstraintRelationId, conId, 0);

	heap_freetuple(tuple);
	heap_close(conDesc, RowExclusiveLock);
}


void AlterConstraintNamespaces(Oid ownerId, Oid oldNspId, Oid newNspId, bool isType, ObjectAddresses *objsMoved)

{
	Relation	conRel;
	ScanKeyData key[1];
	SysScanDesc scan;
	HeapTuple	tup;

	conRel = heap_open(ConstraintRelationId, RowExclusiveLock);

	if (isType)
	{
		ScanKeyInit(&key[0], Anum_pg_constraint_contypid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(ownerId));



		scan = systable_beginscan(conRel, ConstraintTypidIndexId, true, NULL, 1, key);
	}
	else {
		ScanKeyInit(&key[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(ownerId));



		scan = systable_beginscan(conRel, ConstraintRelidIndexId, true, NULL, 1, key);
	}

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_constraint conform = (Form_pg_constraint) GETSTRUCT(tup);
		ObjectAddress thisobj;

		thisobj.classId = ConstraintRelationId;
		thisobj.objectId = HeapTupleGetOid(tup);
		thisobj.objectSubId = 0;

		if (object_address_present(&thisobj, objsMoved))
			continue;

		if (conform->connamespace == oldNspId)
		{
			tup = heap_copytuple(tup);
			conform = (Form_pg_constraint) GETSTRUCT(tup);

			conform->connamespace = newNspId;

			simple_heap_update(conRel, &tup->t_self, tup);
			CatalogUpdateIndexes(conRel, tup);

			
		}

		InvokeObjectPostAlterHook(ConstraintRelationId, thisobj.objectId, 0);

		add_exact_object_address(&thisobj, objsMoved);
	}

	systable_endscan(scan);

	heap_close(conRel, RowExclusiveLock);
}


Oid get_relation_constraint_oid(Oid relid, const char *conname, bool missing_ok)
{
	Relation	pg_constraint;
	HeapTuple	tuple;
	SysScanDesc scan;
	ScanKeyData skey[1];
	Oid			conOid = InvalidOid;

	
	pg_constraint = heap_open(ConstraintRelationId, AccessShareLock);

	ScanKeyInit(&skey[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));



	scan = systable_beginscan(pg_constraint, ConstraintRelidIndexId, true, NULL, 1, skey);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tuple);

		if (strcmp(NameStr(con->conname), conname) == 0)
		{
			if (OidIsValid(conOid))
				ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("table \"%s\" has multiple constraints named \"%s\"", get_rel_name(relid), conname)));


			conOid = HeapTupleGetOid(tuple);
		}
	}

	systable_endscan(scan);

	
	if (!OidIsValid(conOid) && !missing_ok)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" for table \"%s\" does not exist", conname, get_rel_name(relid))));



	heap_close(pg_constraint, AccessShareLock);

	return conOid;
}


Oid get_domain_constraint_oid(Oid typid, const char *conname, bool missing_ok)
{
	Relation	pg_constraint;
	HeapTuple	tuple;
	SysScanDesc scan;
	ScanKeyData skey[1];
	Oid			conOid = InvalidOid;

	
	pg_constraint = heap_open(ConstraintRelationId, AccessShareLock);

	ScanKeyInit(&skey[0], Anum_pg_constraint_contypid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typid));



	scan = systable_beginscan(pg_constraint, ConstraintTypidIndexId, true, NULL, 1, skey);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tuple);

		if (strcmp(NameStr(con->conname), conname) == 0)
		{
			if (OidIsValid(conOid))
				ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("domain \"%s\" has multiple constraints named \"%s\"", format_type_be(typid), conname)));


			conOid = HeapTupleGetOid(tuple);
		}
	}

	systable_endscan(scan);

	
	if (!OidIsValid(conOid) && !missing_ok)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" for domain \"%s\" does not exist", conname, format_type_be(typid))));



	heap_close(pg_constraint, AccessShareLock);

	return conOid;
}


bool check_functional_grouping(Oid relid, Index varno, Index varlevelsup, List *grouping_columns, List **constraintDeps)



{
	bool		result = false;
	Relation	pg_constraint;
	HeapTuple	tuple;
	SysScanDesc scan;
	ScanKeyData skey[1];

	
	pg_constraint = heap_open(ConstraintRelationId, AccessShareLock);

	ScanKeyInit(&skey[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));



	scan = systable_beginscan(pg_constraint, ConstraintRelidIndexId, true, NULL, 1, skey);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tuple);
		Datum		adatum;
		bool		isNull;
		ArrayType  *arr;
		int16	   *attnums;
		int			numkeys;
		int			i;
		bool		found_col;

		
		if (con->contype != CONSTRAINT_PRIMARY)
			continue;
		
		if (con->condeferrable)
			continue;

		
		adatum = heap_getattr(tuple, Anum_pg_constraint_conkey, RelationGetDescr(pg_constraint), &isNull);
		if (isNull)
			elog(ERROR, "null conkey for constraint %u", HeapTupleGetOid(tuple));
		arr = DatumGetArrayTypeP(adatum);		
		numkeys = ARR_DIMS(arr)[0];
		if (ARR_NDIM(arr) != 1 || numkeys < 0 || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != INT2OID)


			elog(ERROR, "conkey is not a 1-D smallint array");
		attnums = (int16 *) ARR_DATA_PTR(arr);

		found_col = false;
		for (i = 0; i < numkeys; i++)
		{
			AttrNumber	attnum = attnums[i];
			ListCell   *gl;

			found_col = false;
			foreach(gl, grouping_columns)
			{
				Var		   *gvar = (Var *) lfirst(gl);

				if (IsA(gvar, Var) && gvar->varno == varno && gvar->varlevelsup == varlevelsup && gvar->varattno == attnum)


				{
					found_col = true;
					break;
				}
			}
			if (!found_col)
				break;
		}

		if (found_col)
		{
			
			*constraintDeps = lappend_oid(*constraintDeps, HeapTupleGetOid(tuple));
			result = true;
			break;
		}
	}

	systable_endscan(scan);

	heap_close(pg_constraint, AccessShareLock);

	return result;
}
