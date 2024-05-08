




















static void AlterSchemaOwner_internal(HeapTuple tup, Relation rel, Oid newOwnerId);


void CreateSchemaCommand(CreateSchemaStmt *stmt, const char *queryString)
{
	const char *schemaName = stmt->schemaname;
	const char *authId = stmt->authid;
	Oid			namespaceId;
	OverrideSearchPath *overridePath;
	List	   *parsetree_list;
	ListCell   *parsetree_item;
	Oid			owner_uid;
	Oid			saved_uid;
	AclResult	aclresult;

	saved_uid = GetUserId();

	
	if (authId)
		owner_uid = get_roleid_checked(authId);
	else owner_uid = saved_uid;

	
	aclresult = pg_database_aclcheck(MyDatabaseId, saved_uid, ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE, get_database_name(MyDatabaseId));

	check_is_member_of_role(saved_uid, owner_uid);

	
	if (!allowSystemTableMods && IsReservedName(schemaName))
		ereport(ERROR, (errcode(ERRCODE_RESERVED_NAME), errmsg("unacceptable schema name \"%s\"", schemaName), errdetail("The prefix \"pg_\" is reserved for system schemas.")));



	
	if (saved_uid != owner_uid)
		SetUserId(owner_uid);

	
	namespaceId = NamespaceCreate(schemaName, owner_uid);

	
	CommandCounterIncrement();

	
	overridePath = GetOverrideSearchPath(CurrentMemoryContext);
	overridePath->schemas = lcons_oid(namespaceId, overridePath->schemas);
	
	PushOverrideSearchPath(overridePath);

	
	parsetree_list = transformCreateSchemaStmt(stmt);

	
	foreach(parsetree_item, parsetree_list)
	{
		Node	   *stmt = (Node *) lfirst(parsetree_item);

		
		ProcessUtility(stmt, queryString, NULL, false, None_Receiver, NULL);




		
		CommandCounterIncrement();
	}

	
	PopOverrideSearchPath();

	
	SetUserId(saved_uid);
}



void RemoveSchema(List *names, DropBehavior behavior, bool missing_ok)
{
	char	   *namespaceName;
	Oid			namespaceId;
	ObjectAddress object;

	if (list_length(names) != 1)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("schema name cannot be qualified")));

	namespaceName = strVal(linitial(names));

	namespaceId = GetSysCacheOid(NAMESPACENAME, CStringGetDatum(namespaceName), 0, 0, 0);

	if (!OidIsValid(namespaceId))
	{
		if (!missing_ok)
		{
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("schema \"%s\" does not exist", namespaceName)));

		}
		else {
			ereport(NOTICE, (errmsg("schema \"%s\" does not exist, skipping", namespaceName)));

		}

		return;
	}

	
	if (!pg_namespace_ownercheck(namespaceId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE, namespaceName);

	
	object.classId = NamespaceRelationId;
	object.objectId = namespaceId;
	object.objectSubId = 0;

	performDeletion(&object, behavior);
}



void RemoveSchemaById(Oid schemaOid)
{
	Relation	relation;
	HeapTuple	tup;

	relation = heap_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCache(NAMESPACEOID, ObjectIdGetDatum(schemaOid), 0, 0, 0);

	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for namespace %u", schemaOid);

	simple_heap_delete(relation, &tup->t_self);

	ReleaseSysCache(tup);

	heap_close(relation, RowExclusiveLock);
}



void RenameSchema(const char *oldname, const char *newname)
{
	HeapTuple	tup;
	Relation	rel;
	AclResult	aclresult;

	rel = heap_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy(NAMESPACENAME, CStringGetDatum(oldname), 0, 0, 0);

	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("schema \"%s\" does not exist", oldname)));


	
	if (HeapTupleIsValid( SearchSysCache(NAMESPACENAME, CStringGetDatum(newname), 0, 0, 0)))


		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_SCHEMA), errmsg("schema \"%s\" already exists", newname)));


	
	if (!pg_namespace_ownercheck(HeapTupleGetOid(tup), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE, oldname);

	
	aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE, get_database_name(MyDatabaseId));

	if (!allowSystemTableMods && IsReservedName(newname))
		ereport(ERROR, (errcode(ERRCODE_RESERVED_NAME), errmsg("unacceptable schema name \"%s\"", newname), errdetail("The prefix \"pg_\" is reserved for system schemas.")));



	
	namestrcpy(&(((Form_pg_namespace) GETSTRUCT(tup))->nspname), newname);
	simple_heap_update(rel, &tup->t_self, tup);
	CatalogUpdateIndexes(rel, tup);

	heap_close(rel, NoLock);
	heap_freetuple(tup);
}

void AlterSchemaOwner_oid(Oid oid, Oid newOwnerId)
{
	HeapTuple	tup;
	Relation	rel;

	rel = heap_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCache(NAMESPACEOID, ObjectIdGetDatum(oid), 0, 0, 0);

	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for schema %u", oid);

	AlterSchemaOwner_internal(tup, rel, newOwnerId);

	ReleaseSysCache(tup);

	heap_close(rel, RowExclusiveLock);
}



void AlterSchemaOwner(const char *name, Oid newOwnerId)
{
	HeapTuple	tup;
	Relation	rel;

	rel = heap_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCache(NAMESPACENAME, CStringGetDatum(name), 0, 0, 0);

	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("schema \"%s\" does not exist", name)));


	AlterSchemaOwner_internal(tup, rel, newOwnerId);

	ReleaseSysCache(tup);

	heap_close(rel, RowExclusiveLock);
}

static void AlterSchemaOwner_internal(HeapTuple tup, Relation rel, Oid newOwnerId)
{
	Form_pg_namespace nspForm;

	Assert(tup->t_tableOid == NamespaceRelationId);
	Assert(RelationGetRelid(rel) == NamespaceRelationId);

	nspForm = (Form_pg_namespace) GETSTRUCT(tup);

	
	if (nspForm->nspowner != newOwnerId)
	{
		Datum		repl_val[Natts_pg_namespace];
		char		repl_null[Natts_pg_namespace];
		char		repl_repl[Natts_pg_namespace];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isNull;
		HeapTuple	newtuple;
		AclResult	aclresult;

		
		if (!pg_namespace_ownercheck(HeapTupleGetOid(tup), GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE, NameStr(nspForm->nspname));

		
		check_is_member_of_role(GetUserId(), newOwnerId);

		
		aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_DATABASE, get_database_name(MyDatabaseId));

		memset(repl_null, ' ', sizeof(repl_null));
		memset(repl_repl, ' ', sizeof(repl_repl));

		repl_repl[Anum_pg_namespace_nspowner - 1] = 'r';
		repl_val[Anum_pg_namespace_nspowner - 1] = ObjectIdGetDatum(newOwnerId);

		
		aclDatum = SysCacheGetAttr(NAMESPACENAME, tup, Anum_pg_namespace_nspacl, &isNull);

		if (!isNull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum), nspForm->nspowner, newOwnerId);
			repl_repl[Anum_pg_namespace_nspacl - 1] = 'r';
			repl_val[Anum_pg_namespace_nspacl - 1] = PointerGetDatum(newAcl);
		}

		newtuple = heap_modifytuple(tup, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

		simple_heap_update(rel, &newtuple->t_self, newtuple);
		CatalogUpdateIndexes(rel, newtuple);

		heap_freetuple(newtuple);

		
		changeDependencyOnOwner(NamespaceRelationId, HeapTupleGetOid(tup), newOwnerId);
	}

}
