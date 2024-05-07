




















































ProcessUtility_hook_type ProcessUtility_hook = NULL;


static void ProcessUtilitySlow(Node *parsetree, const char *queryString, ProcessUtilityContext context, ParamListInfo params, DestReceiver *dest, char *completionTag);




static void ExecDropStmt(DropStmt *stmt, bool isTopLevel);



void CheckRelationOwnership(RangeVar *rel, bool noCatalogs)
{
	Oid			relOid;
	HeapTuple	tuple;

	
	relOid = RangeVarGetRelid(rel, NoLock, false);

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));
	if (!HeapTupleIsValid(tuple))		
		elog(ERROR, "cache lookup failed for relation %u", relOid);

	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, rel->relname);

	if (noCatalogs)
	{
		if (!allowSystemTableMods && IsSystemClass(relOid, (Form_pg_class) GETSTRUCT(tuple)))
			ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", rel->relname)));


	}

	ReleaseSysCache(tuple);
}



bool CommandIsReadOnly(Node *parsetree)
{
	if (IsA(parsetree, PlannedStmt))
	{
		PlannedStmt *stmt = (PlannedStmt *) parsetree;

		switch (stmt->commandType)
		{
			case CMD_SELECT:
				if (stmt->rowMarks != NIL)
					return false;		
				else if (stmt->hasModifyingCTE)
					return false;		
				else return true;
			case CMD_UPDATE:
			case CMD_INSERT:
			case CMD_DELETE:
				return false;
			default:
				elog(WARNING, "unrecognized commandType: %d", (int) stmt->commandType);
				break;
		}
	}
	
	return false;
}


static void check_xact_readonly(Node *parsetree)
{
	if (!XactReadOnly)
		return;

	

	switch (nodeTag(parsetree))
	{
		case T_AlterDatabaseStmt:
		case T_AlterDatabaseSetStmt:
		case T_AlterDomainStmt:
		case T_AlterFunctionStmt:
		case T_AlterRoleStmt:
		case T_AlterRoleSetStmt:
		case T_AlterObjectSchemaStmt:
		case T_AlterOwnerStmt:
		case T_AlterSeqStmt:
		case T_AlterTableStmt:
		case T_RenameStmt:
		case T_CommentStmt:
		case T_DefineStmt:
		case T_CreateCastStmt:
		case T_CreateEventTrigStmt:
		case T_AlterEventTrigStmt:
		case T_CreateConversionStmt:
		case T_CreatedbStmt:
		case T_CreateDomainStmt:
		case T_CreateFunctionStmt:
		case T_CreateRoleStmt:
		case T_IndexStmt:
		case T_CreatePLangStmt:
		case T_CreateOpClassStmt:
		case T_CreateOpFamilyStmt:
		case T_AlterOpFamilyStmt:
		case T_RuleStmt:
		case T_CreateSchemaStmt:
		case T_CreateSeqStmt:
		case T_CreateStmt:
		case T_CreateTableAsStmt:
		case T_RefreshMatViewStmt:
		case T_CreateTableSpaceStmt:
		case T_CreateTrigStmt:
		case T_CompositeTypeStmt:
		case T_CreateEnumStmt:
		case T_CreateRangeStmt:
		case T_AlterEnumStmt:
		case T_ViewStmt:
		case T_DropStmt:
		case T_DropdbStmt:
		case T_DropTableSpaceStmt:
		case T_DropRoleStmt:
		case T_GrantStmt:
		case T_GrantRoleStmt:
		case T_AlterDefaultPrivilegesStmt:
		case T_TruncateStmt:
		case T_DropOwnedStmt:
		case T_ReassignOwnedStmt:
		case T_AlterTSDictionaryStmt:
		case T_AlterTSConfigurationStmt:
		case T_CreateExtensionStmt:
		case T_AlterExtensionStmt:
		case T_AlterExtensionContentsStmt:
		case T_CreateFdwStmt:
		case T_AlterFdwStmt:
		case T_CreateForeignServerStmt:
		case T_AlterForeignServerStmt:
		case T_CreateUserMappingStmt:
		case T_AlterUserMappingStmt:
		case T_DropUserMappingStmt:
		case T_AlterTableSpaceOptionsStmt:
		case T_AlterTableSpaceMoveStmt:
		case T_CreateForeignTableStmt:
		case T_SecLabelStmt:
			PreventCommandIfReadOnly(CreateCommandTag(parsetree));
			break;
		default:
			
			break;
	}
}


void PreventCommandIfReadOnly(const char *cmdname)
{
	if (XactReadOnly)
		ereport(ERROR, (errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),  errmsg("cannot execute %s in a read-only transaction", cmdname)));



}


void PreventCommandDuringRecovery(const char *cmdname)
{
	if (RecoveryInProgress())
		ereport(ERROR, (errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),  errmsg("cannot execute %s during recovery", cmdname)));



}


static void CheckRestrictedOperation(const char *cmdname)
{
	if (InSecurityRestrictedOperation())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),  errmsg("cannot execute %s within security-restricted operation", cmdname)));



}



void ProcessUtility(Node *parsetree, const char *queryString, ProcessUtilityContext context, ParamListInfo params, DestReceiver *dest, char *completionTag)





{
	Assert(queryString != NULL);	

	
	if (ProcessUtility_hook)
		(*ProcessUtility_hook) (parsetree, queryString, context, params, dest, completionTag);

	else standard_ProcessUtility(parsetree, queryString, context, params, dest, completionTag);


}


void standard_ProcessUtility(Node *parsetree, const char *queryString, ProcessUtilityContext context, ParamListInfo params, DestReceiver *dest, char *completionTag)





{
	bool		isTopLevel = (context == PROCESS_UTILITY_TOPLEVEL);

	check_xact_readonly(parsetree);

	if (completionTag)
		completionTag[0] = '\0';

	switch (nodeTag(parsetree))
	{
			
		case T_TransactionStmt:
			{
				TransactionStmt *stmt = (TransactionStmt *) parsetree;

				switch (stmt->kind)
				{
						
					case TRANS_STMT_BEGIN:
					case TRANS_STMT_START:
						{
							ListCell   *lc;

							BeginTransactionBlock();
							foreach(lc, stmt->options)
							{
								DefElem    *item = (DefElem *) lfirst(lc);

								if (strcmp(item->defname, "transaction_isolation") == 0)
									SetPGVariable("transaction_isolation", list_make1(item->arg), true);

								else if (strcmp(item->defname, "transaction_read_only") == 0)
									SetPGVariable("transaction_read_only", list_make1(item->arg), true);

								else if (strcmp(item->defname, "transaction_deferrable") == 0)
									SetPGVariable("transaction_deferrable", list_make1(item->arg), true);

							}
						}
						break;

					case TRANS_STMT_COMMIT:
						if (!EndTransactionBlock())
						{
							
							if (completionTag)
								strcpy(completionTag, "ROLLBACK");
						}
						break;

					case TRANS_STMT_PREPARE:
						PreventCommandDuringRecovery("PREPARE TRANSACTION");
						if (!PrepareTransactionBlock(stmt->gid))
						{
							
							if (completionTag)
								strcpy(completionTag, "ROLLBACK");
						}
						break;

					case TRANS_STMT_COMMIT_PREPARED:
						PreventTransactionChain(isTopLevel, "COMMIT PREPARED");
						PreventCommandDuringRecovery("COMMIT PREPARED");
						FinishPreparedTransaction(stmt->gid, true);
						break;

					case TRANS_STMT_ROLLBACK_PREPARED:
						PreventTransactionChain(isTopLevel, "ROLLBACK PREPARED");
						PreventCommandDuringRecovery("ROLLBACK PREPARED");
						FinishPreparedTransaction(stmt->gid, false);
						break;

					case TRANS_STMT_ROLLBACK:
						UserAbortTransactionBlock();
						break;

					case TRANS_STMT_SAVEPOINT:
						{
							ListCell   *cell;
							char	   *name = NULL;

							RequireTransactionChain(isTopLevel, "SAVEPOINT");

							foreach(cell, stmt->options)
							{
								DefElem    *elem = lfirst(cell);

								if (strcmp(elem->defname, "savepoint_name") == 0)
									name = strVal(elem->arg);
							}

							Assert(PointerIsValid(name));

							DefineSavepoint(name);
						}
						break;

					case TRANS_STMT_RELEASE:
						RequireTransactionChain(isTopLevel, "RELEASE SAVEPOINT");
						ReleaseSavepoint(stmt->options);
						break;

					case TRANS_STMT_ROLLBACK_TO:
						RequireTransactionChain(isTopLevel, "ROLLBACK TO SAVEPOINT");
						RollbackToSavepoint(stmt->options);

						
						break;
				}
			}
			break;

			
		case T_PlannedStmt:
			{
				PlannedStmt *stmt = (PlannedStmt *) parsetree;

				if (stmt->utilityStmt == NULL || !IsA(stmt->utilityStmt, DeclareCursorStmt))
					elog(ERROR, "non-DECLARE CURSOR PlannedStmt passed to ProcessUtility");
				PerformCursorOpen(stmt, params, queryString, isTopLevel);
			}
			break;

		case T_ClosePortalStmt:
			{
				ClosePortalStmt *stmt = (ClosePortalStmt *) parsetree;

				CheckRestrictedOperation("CLOSE");
				PerformPortalClose(stmt->portalname);
			}
			break;

		case T_FetchStmt:
			PerformPortalFetch((FetchStmt *) parsetree, dest, completionTag);
			break;

		case T_DoStmt:
			ExecuteDoStmt((DoStmt *) parsetree);
			break;

		case T_CreateTableSpaceStmt:
			
			PreventTransactionChain(isTopLevel, "CREATE TABLESPACE");
			CreateTableSpace((CreateTableSpaceStmt *) parsetree);
			break;

		case T_DropTableSpaceStmt:
			
			PreventTransactionChain(isTopLevel, "DROP TABLESPACE");
			DropTableSpace((DropTableSpaceStmt *) parsetree);
			break;

		case T_AlterTableSpaceOptionsStmt:
			
			AlterTableSpaceOptions((AlterTableSpaceOptionsStmt *) parsetree);
			break;

		case T_AlterTableSpaceMoveStmt:
			
			AlterTableSpaceMove((AlterTableSpaceMoveStmt *) parsetree);
			break;

		case T_TruncateStmt:
			ExecuteTruncate((TruncateStmt *) parsetree);
			break;

		case T_CommentStmt:
			CommentObject((CommentStmt *) parsetree);
			break;

		case T_SecLabelStmt:
			ExecSecLabelStmt((SecLabelStmt *) parsetree);
			break;

		case T_CopyStmt:
			{
				uint64		processed;

				DoCopy((CopyStmt *) parsetree, queryString, &processed);
				if (completionTag)
					snprintf(completionTag, COMPLETION_TAG_BUFSIZE, "COPY " UINT64_FORMAT, processed);
			}
			break;

		case T_PrepareStmt:
			CheckRestrictedOperation("PREPARE");
			PrepareQuery((PrepareStmt *) parsetree, queryString);
			break;

		case T_ExecuteStmt:
			ExecuteQuery((ExecuteStmt *) parsetree, NULL, queryString, params, dest, completionTag);

			break;

		case T_DeallocateStmt:
			CheckRestrictedOperation("DEALLOCATE");
			DeallocateQuery((DeallocateStmt *) parsetree);
			break;

		case T_GrantStmt:
			
			ExecuteGrantStmt((GrantStmt *) parsetree);
			break;

		case T_GrantRoleStmt:
			
			GrantRole((GrantRoleStmt *) parsetree);
			break;

		case T_CreatedbStmt:
			
			PreventTransactionChain(isTopLevel, "CREATE DATABASE");
			createdb((CreatedbStmt *) parsetree);
			break;

		case T_AlterDatabaseStmt:
			
			AlterDatabase((AlterDatabaseStmt *) parsetree, isTopLevel);
			break;

		case T_AlterDatabaseSetStmt:
			
			AlterDatabaseSet((AlterDatabaseSetStmt *) parsetree);
			break;

		case T_DropdbStmt:
			{
				DropdbStmt *stmt = (DropdbStmt *) parsetree;

				
				PreventTransactionChain(isTopLevel, "DROP DATABASE");
				dropdb(stmt->dbname, stmt->missing_ok);
			}
			break;

			
		case T_NotifyStmt:
			{
				NotifyStmt *stmt = (NotifyStmt *) parsetree;

				PreventCommandDuringRecovery("NOTIFY");
				Async_Notify(stmt->conditionname, stmt->payload);
			}
			break;

		case T_ListenStmt:
			{
				ListenStmt *stmt = (ListenStmt *) parsetree;

				PreventCommandDuringRecovery("LISTEN");
				CheckRestrictedOperation("LISTEN");
				Async_Listen(stmt->conditionname);
			}
			break;

		case T_UnlistenStmt:
			{
				UnlistenStmt *stmt = (UnlistenStmt *) parsetree;

				PreventCommandDuringRecovery("UNLISTEN");
				CheckRestrictedOperation("UNLISTEN");
				if (stmt->conditionname)
					Async_Unlisten(stmt->conditionname);
				else Async_UnlistenAll();
			}
			break;

		case T_LoadStmt:
			{
				LoadStmt   *stmt = (LoadStmt *) parsetree;

				closeAllVfds(); 
				
				load_file(stmt->filename, !superuser());
			}
			break;

		case T_ClusterStmt:
			
			PreventCommandDuringRecovery("CLUSTER");
			cluster((ClusterStmt *) parsetree, isTopLevel);
			break;

		case T_VacuumStmt:
			{
				VacuumStmt *stmt = (VacuumStmt *) parsetree;

				
				PreventCommandDuringRecovery((stmt->options & VACOPT_VACUUM) ? "VACUUM" : "ANALYZE");
				vacuum(stmt, InvalidOid, true, NULL, false, isTopLevel);
			}
			break;

		case T_ExplainStmt:
			ExplainQuery((ExplainStmt *) parsetree, queryString, params, dest);
			break;

		case T_AlterSystemStmt:
			PreventTransactionChain(isTopLevel, "ALTER SYSTEM");
			AlterSystemSetConfigFile((AlterSystemStmt *) parsetree);
			break;

		case T_VariableSetStmt:
			ExecSetVariableStmt((VariableSetStmt *) parsetree, isTopLevel);
			break;

		case T_VariableShowStmt:
			{
				VariableShowStmt *n = (VariableShowStmt *) parsetree;

				GetPGVariable(n->name, dest);
			}
			break;

		case T_DiscardStmt:
			
			CheckRestrictedOperation("DISCARD");
			DiscardCommand((DiscardStmt *) parsetree, isTopLevel);
			break;

		case T_CreateEventTrigStmt:
			
			CreateEventTrigger((CreateEventTrigStmt *) parsetree);
			break;

		case T_AlterEventTrigStmt:
			
			AlterEventTrigger((AlterEventTrigStmt *) parsetree);
			break;

			
		case T_CreateRoleStmt:
			
			CreateRole((CreateRoleStmt *) parsetree);
			break;

		case T_AlterRoleStmt:
			
			AlterRole((AlterRoleStmt *) parsetree);
			break;

		case T_AlterRoleSetStmt:
			
			AlterRoleSet((AlterRoleSetStmt *) parsetree);
			break;

		case T_DropRoleStmt:
			
			DropRole((DropRoleStmt *) parsetree);
			break;

		case T_ReassignOwnedStmt:
			
			ReassignOwnedObjects((ReassignOwnedStmt *) parsetree);
			break;

		case T_LockStmt:

			
			RequireTransactionChain(isTopLevel, "LOCK TABLE");
			LockTableCommand((LockStmt *) parsetree);
			break;

		case T_ConstraintsSetStmt:
			WarnNoTransactionChain(isTopLevel, "SET CONSTRAINTS");
			AfterTriggerSetState((ConstraintsSetStmt *) parsetree);
			break;

		case T_CheckPointStmt:
			if (!superuser())
				ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to do CHECKPOINT")));


			
			RequestCheckpoint(CHECKPOINT_IMMEDIATE | CHECKPOINT_WAIT | (RecoveryInProgress() ? 0 : CHECKPOINT_FORCE));
			break;

		case T_ReindexStmt:
			{
				ReindexStmt *stmt = (ReindexStmt *) parsetree;

				
				PreventCommandDuringRecovery("REINDEX");
				switch (stmt->kind)
				{
					case OBJECT_INDEX:
						ReindexIndex(stmt->relation);
						break;
					case OBJECT_TABLE:
					case OBJECT_MATVIEW:
						ReindexTable(stmt->relation);
						break;
					case OBJECT_DATABASE:

						
						PreventTransactionChain(isTopLevel, "REINDEX DATABASE");
						ReindexDatabase(stmt->name, stmt->do_system, stmt->do_user);
						break;
					default:
						elog(ERROR, "unrecognized object type: %d", (int) stmt->kind);
						break;
				}
			}
			break;

			

		case T_DropStmt:
			{
				DropStmt   *stmt = (DropStmt *) parsetree;

				if (EventTriggerSupportsObjectType(stmt->removeType))
					ProcessUtilitySlow(parsetree, queryString, context, params, dest, completionTag);

				else ExecDropStmt(stmt, isTopLevel);
			}
			break;

		case T_RenameStmt:
			{
				RenameStmt *stmt = (RenameStmt *) parsetree;

				if (EventTriggerSupportsObjectType(stmt->renameType))
					ProcessUtilitySlow(parsetree, queryString, context, params, dest, completionTag);

				else ExecRenameStmt(stmt);
			}
			break;

		case T_AlterObjectSchemaStmt:
			{
				AlterObjectSchemaStmt *stmt = (AlterObjectSchemaStmt *) parsetree;

				if (EventTriggerSupportsObjectType(stmt->objectType))
					ProcessUtilitySlow(parsetree, queryString, context, params, dest, completionTag);

				else ExecAlterObjectSchemaStmt(stmt);
			}
			break;

		case T_AlterOwnerStmt:
			{
				AlterOwnerStmt *stmt = (AlterOwnerStmt *) parsetree;

				if (EventTriggerSupportsObjectType(stmt->objectType))
					ProcessUtilitySlow(parsetree, queryString, context, params, dest, completionTag);

				else ExecAlterOwnerStmt(stmt);
			}
			break;

		default:
			
			ProcessUtilitySlow(parsetree, queryString, context, params, dest, completionTag);

			break;
	}
}


static void ProcessUtilitySlow(Node *parsetree, const char *queryString, ProcessUtilityContext context, ParamListInfo params, DestReceiver *dest, char *completionTag)





{
	bool		isTopLevel = (context == PROCESS_UTILITY_TOPLEVEL);
	bool		isCompleteQuery = (context <= PROCESS_UTILITY_QUERY);
	bool		needCleanup;

	
	needCleanup = isCompleteQuery && EventTriggerBeginCompleteQuery();

	
	PG_TRY();
	{
		if (isCompleteQuery)
			EventTriggerDDLCommandStart(parsetree);

		switch (nodeTag(parsetree))
		{
				
			case T_CreateSchemaStmt:
				CreateSchemaCommand((CreateSchemaStmt *) parsetree, queryString);
				break;

			case T_CreateStmt:
			case T_CreateForeignTableStmt:
				{
					List	   *stmts;
					ListCell   *l;
					Oid			relOid;

					
					stmts = transformCreateStmt((CreateStmt *) parsetree, queryString);

					
					foreach(l, stmts)
					{
						Node	   *stmt = (Node *) lfirst(l);

						if (IsA(stmt, CreateStmt))
						{
							Datum		toast_options;
							static char *validnsps[] = HEAP_RELOPT_NAMESPACES;

							
							relOid = DefineRelation((CreateStmt *) stmt, RELKIND_RELATION, InvalidOid);


							
							CommandCounterIncrement();

							
							toast_options = transformRelOptions((Datum) 0, ((CreateStmt *) stmt)->options, "toast", validnsps, true, false);




							(void) heap_reloptions(RELKIND_TOASTVALUE, toast_options, true);


							AlterTableCreateToastTable(relOid, toast_options);
						}
						else if (IsA(stmt, CreateForeignTableStmt))
						{
							
							relOid = DefineRelation((CreateStmt *) stmt, RELKIND_FOREIGN_TABLE, InvalidOid);

							CreateForeignTable((CreateForeignTableStmt *) stmt, relOid);
						}
						else {
							
							ProcessUtility(stmt, queryString, PROCESS_UTILITY_SUBCOMMAND, params, None_Receiver, NULL);




						}

						
						if (lnext(l) != NULL)
							CommandCounterIncrement();
					}
				}
				break;

			case T_AlterTableStmt:
				{
					AlterTableStmt *atstmt = (AlterTableStmt *) parsetree;
					Oid			relid;
					List	   *stmts;
					ListCell   *l;
					LOCKMODE	lockmode;

					
					lockmode = AlterTableGetLockLevel(atstmt->cmds);
					relid = AlterTableLookupRelation(atstmt, lockmode);

					if (OidIsValid(relid))
					{
						
						stmts = transformAlterTableStmt(atstmt, queryString);

						
						foreach(l, stmts)
						{
							Node	   *stmt = (Node *) lfirst(l);

							if (IsA(stmt, AlterTableStmt))
							{
								
								AlterTable(relid, lockmode, (AlterTableStmt *) stmt);
							}
							else {
								
								ProcessUtility(stmt, queryString, PROCESS_UTILITY_SUBCOMMAND, params, None_Receiver, NULL);




							}

							
							if (lnext(l) != NULL)
								CommandCounterIncrement();
						}
					}
					else ereport(NOTICE, (errmsg("relation \"%s\" does not exist, skipping", atstmt->relation->relname)));


				}
				break;

			case T_AlterDomainStmt:
				{
					AlterDomainStmt *stmt = (AlterDomainStmt *) parsetree;

					
					switch (stmt->subtype)
					{
						case 'T':		

							
							AlterDomainDefault(stmt->typeName, stmt->def);
							break;
						case 'N':		
							AlterDomainNotNull(stmt->typeName, false);
							break;
						case 'O':		
							AlterDomainNotNull(stmt->typeName, true);
							break;
						case 'C':		
							AlterDomainAddConstraint(stmt->typeName, stmt->def);
							break;
						case 'X':		
							AlterDomainDropConstraint(stmt->typeName, stmt->name, stmt->behavior, stmt->missing_ok);


							break;
						case 'V':		
							AlterDomainValidateConstraint(stmt->typeName, stmt->name);
							break;
						default:		
							elog(ERROR, "unrecognized alter domain type: %d", (int) stmt->subtype);
							break;
					}
				}
				break;

				
			case T_DefineStmt:
				{
					DefineStmt *stmt = (DefineStmt *) parsetree;

					switch (stmt->kind)
					{
						case OBJECT_AGGREGATE:
							DefineAggregate(stmt->defnames, stmt->args, stmt->oldstyle, stmt->definition, queryString);

							break;
						case OBJECT_OPERATOR:
							Assert(stmt->args == NIL);
							DefineOperator(stmt->defnames, stmt->definition);
							break;
						case OBJECT_TYPE:
							Assert(stmt->args == NIL);
							DefineType(stmt->defnames, stmt->definition);
							break;
						case OBJECT_TSPARSER:
							Assert(stmt->args == NIL);
							DefineTSParser(stmt->defnames, stmt->definition);
							break;
						case OBJECT_TSDICTIONARY:
							Assert(stmt->args == NIL);
							DefineTSDictionary(stmt->defnames, stmt->definition);
							break;
						case OBJECT_TSTEMPLATE:
							Assert(stmt->args == NIL);
							DefineTSTemplate(stmt->defnames, stmt->definition);
							break;
						case OBJECT_TSCONFIGURATION:
							Assert(stmt->args == NIL);
							DefineTSConfiguration(stmt->defnames, stmt->definition);
							break;
						case OBJECT_COLLATION:
							Assert(stmt->args == NIL);
							DefineCollation(stmt->defnames, stmt->definition);
							break;
						default:
							elog(ERROR, "unrecognized define stmt type: %d", (int) stmt->kind);
							break;
					}
				}
				break;

			case T_IndexStmt:	
				{
					IndexStmt  *stmt = (IndexStmt *) parsetree;

					if (stmt->concurrent)
						PreventTransactionChain(isTopLevel, "CREATE INDEX CONCURRENTLY");

					CheckRelationOwnership(stmt->relation, true);

					
					stmt = transformIndexStmt(stmt, queryString);

					
					DefineIndex(stmt, InvalidOid, false, true, false, false);




				}
				break;

			case T_CreateExtensionStmt:
				CreateExtension((CreateExtensionStmt *) parsetree);
				break;

			case T_AlterExtensionStmt:
				ExecAlterExtensionStmt((AlterExtensionStmt *) parsetree);
				break;

			case T_AlterExtensionContentsStmt:
				ExecAlterExtensionContentsStmt((AlterExtensionContentsStmt *) parsetree);
				break;

			case T_CreateFdwStmt:
				CreateForeignDataWrapper((CreateFdwStmt *) parsetree);
				break;

			case T_AlterFdwStmt:
				AlterForeignDataWrapper((AlterFdwStmt *) parsetree);
				break;

			case T_CreateForeignServerStmt:
				CreateForeignServer((CreateForeignServerStmt *) parsetree);
				break;

			case T_AlterForeignServerStmt:
				AlterForeignServer((AlterForeignServerStmt *) parsetree);
				break;

			case T_CreateUserMappingStmt:
				CreateUserMapping((CreateUserMappingStmt *) parsetree);
				break;

			case T_AlterUserMappingStmt:
				AlterUserMapping((AlterUserMappingStmt *) parsetree);
				break;

			case T_DropUserMappingStmt:
				RemoveUserMapping((DropUserMappingStmt *) parsetree);
				break;

			case T_CompositeTypeStmt:	
				{
					CompositeTypeStmt *stmt = (CompositeTypeStmt *) parsetree;

					DefineCompositeType(stmt->typevar, stmt->coldeflist);
				}
				break;

			case T_CreateEnumStmt:		
				DefineEnum((CreateEnumStmt *) parsetree);
				break;

			case T_CreateRangeStmt:		
				DefineRange((CreateRangeStmt *) parsetree);
				break;

			case T_AlterEnumStmt:		
				AlterEnum((AlterEnumStmt *) parsetree, isTopLevel);
				break;

			case T_ViewStmt:	
				DefineView((ViewStmt *) parsetree, queryString);
				break;

			case T_CreateFunctionStmt:	
				CreateFunction((CreateFunctionStmt *) parsetree, queryString);
				break;

			case T_AlterFunctionStmt:	
				AlterFunction((AlterFunctionStmt *) parsetree);
				break;

			case T_RuleStmt:	
				DefineRule((RuleStmt *) parsetree, queryString);
				break;

			case T_CreateSeqStmt:
				DefineSequence((CreateSeqStmt *) parsetree);
				break;

			case T_AlterSeqStmt:
				AlterSequence((AlterSeqStmt *) parsetree);
				break;

			case T_CreateTableAsStmt:
				ExecCreateTableAs((CreateTableAsStmt *) parsetree, queryString, params, completionTag);
				break;

			case T_RefreshMatViewStmt:
				ExecRefreshMatView((RefreshMatViewStmt *) parsetree, queryString, params, completionTag);
				break;

			case T_CreateTrigStmt:
				(void) CreateTrigger((CreateTrigStmt *) parsetree, queryString, InvalidOid, InvalidOid, false);
				break;

			case T_CreatePLangStmt:
				CreateProceduralLanguage((CreatePLangStmt *) parsetree);
				break;

			case T_CreateDomainStmt:
				DefineDomain((CreateDomainStmt *) parsetree);
				break;

			case T_CreateConversionStmt:
				CreateConversionCommand((CreateConversionStmt *) parsetree);
				break;

			case T_CreateCastStmt:
				CreateCast((CreateCastStmt *) parsetree);
				break;

			case T_CreateOpClassStmt:
				DefineOpClass((CreateOpClassStmt *) parsetree);
				break;

			case T_CreateOpFamilyStmt:
				DefineOpFamily((CreateOpFamilyStmt *) parsetree);
				break;

			case T_AlterOpFamilyStmt:
				AlterOpFamily((AlterOpFamilyStmt *) parsetree);
				break;

			case T_AlterTSDictionaryStmt:
				AlterTSDictionary((AlterTSDictionaryStmt *) parsetree);
				break;

			case T_AlterTSConfigurationStmt:
				AlterTSConfiguration((AlterTSConfigurationStmt *) parsetree);
				break;

			case T_DropStmt:
				ExecDropStmt((DropStmt *) parsetree, isTopLevel);
				break;

			case T_RenameStmt:
				ExecRenameStmt((RenameStmt *) parsetree);
				break;

			case T_AlterObjectSchemaStmt:
				ExecAlterObjectSchemaStmt((AlterObjectSchemaStmt *) parsetree);
				break;

			case T_AlterOwnerStmt:
				ExecAlterOwnerStmt((AlterOwnerStmt *) parsetree);
				break;

			case T_DropOwnedStmt:
				DropOwnedObjects((DropOwnedStmt *) parsetree);
				break;

			case T_AlterDefaultPrivilegesStmt:
				ExecAlterDefaultPrivilegesStmt((AlterDefaultPrivilegesStmt *) parsetree);
				break;

			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(parsetree));
				break;
		}

		if (isCompleteQuery)
		{
			EventTriggerSQLDrop(parsetree);
			EventTriggerDDLCommandEnd(parsetree);
		}
	}
	PG_CATCH();
	{
		if (needCleanup)
			EventTriggerEndCompleteQuery();
		PG_RE_THROW();
	}
	PG_END_TRY();

	if (needCleanup)
		EventTriggerEndCompleteQuery();
}


static void ExecDropStmt(DropStmt *stmt, bool isTopLevel)
{
	switch (stmt->removeType)
	{
		case OBJECT_INDEX:
			if (stmt->concurrent)
				PreventTransactionChain(isTopLevel, "DROP INDEX CONCURRENTLY");
			

		case OBJECT_TABLE:
		case OBJECT_SEQUENCE:
		case OBJECT_VIEW:
		case OBJECT_MATVIEW:
		case OBJECT_FOREIGN_TABLE:
			RemoveRelations(stmt);
			break;
		default:
			RemoveObjects(stmt);
			break;
	}
}



bool UtilityReturnsTuples(Node *parsetree)
{
	switch (nodeTag(parsetree))
	{
		case T_FetchStmt:
			{
				FetchStmt  *stmt = (FetchStmt *) parsetree;
				Portal		portal;

				if (stmt->ismove)
					return false;
				portal = GetPortalByName(stmt->portalname);
				if (!PortalIsValid(portal))
					return false;		
				return portal->tupDesc ? true : false;
			}

		case T_ExecuteStmt:
			{
				ExecuteStmt *stmt = (ExecuteStmt *) parsetree;
				PreparedStatement *entry;

				entry = FetchPreparedStatement(stmt->name, false);
				if (!entry)
					return false;		
				if (entry->plansource->resultDesc)
					return true;
				return false;
			}

		case T_ExplainStmt:
			return true;

		case T_VariableShowStmt:
			return true;

		default:
			return false;
	}
}


TupleDesc UtilityTupleDescriptor(Node *parsetree)
{
	switch (nodeTag(parsetree))
	{
		case T_FetchStmt:
			{
				FetchStmt  *stmt = (FetchStmt *) parsetree;
				Portal		portal;

				if (stmt->ismove)
					return NULL;
				portal = GetPortalByName(stmt->portalname);
				if (!PortalIsValid(portal))
					return NULL;	
				return CreateTupleDescCopy(portal->tupDesc);
			}

		case T_ExecuteStmt:
			{
				ExecuteStmt *stmt = (ExecuteStmt *) parsetree;
				PreparedStatement *entry;

				entry = FetchPreparedStatement(stmt->name, false);
				if (!entry)
					return NULL;	
				return FetchPreparedStatementResultDesc(entry);
			}

		case T_ExplainStmt:
			return ExplainResultDesc((ExplainStmt *) parsetree);

		case T_VariableShowStmt:
			{
				VariableShowStmt *n = (VariableShowStmt *) parsetree;

				return GetPGVariableResultDesc(n->name);
			}

		default:
			return NULL;
	}
}




bool QueryReturnsTuples(Query *parsetree)
{
	switch (parsetree->commandType)
	{
		case CMD_SELECT:
			
			if (parsetree->utilityStmt == NULL)
				return true;
			break;
		case CMD_INSERT:
		case CMD_UPDATE:
		case CMD_DELETE:
			
			if (parsetree->returningList)
				return true;
			break;
		case CMD_UTILITY:
			return UtilityReturnsTuples(parsetree->utilityStmt);
		case CMD_UNKNOWN:
		case CMD_NOTHING:
			
			break;
	}
	return false;				
}




Query * UtilityContainsQuery(Node *parsetree)
{
	Query	   *qry;

	switch (nodeTag(parsetree))
	{
		case T_ExplainStmt:
			qry = (Query *) ((ExplainStmt *) parsetree)->query;
			Assert(IsA(qry, Query));
			if (qry->commandType == CMD_UTILITY)
				return UtilityContainsQuery(qry->utilityStmt);
			return qry;

		case T_CreateTableAsStmt:
			qry = (Query *) ((CreateTableAsStmt *) parsetree)->query;
			Assert(IsA(qry, Query));
			if (qry->commandType == CMD_UTILITY)
				return UtilityContainsQuery(qry->utilityStmt);
			return qry;

		default:
			return NULL;
	}
}



static const char * AlterObjectTypeCommandTag(ObjectType objtype)
{
	const char *tag;

	switch (objtype)
	{
		case OBJECT_AGGREGATE:
			tag = "ALTER AGGREGATE";
			break;
		case OBJECT_ATTRIBUTE:
			tag = "ALTER TYPE";
			break;
		case OBJECT_CAST:
			tag = "ALTER CAST";
			break;
		case OBJECT_COLLATION:
			tag = "ALTER COLLATION";
			break;
		case OBJECT_COLUMN:
			tag = "ALTER TABLE";
			break;
		case OBJECT_CONSTRAINT:
			tag = "ALTER TABLE";
			break;
		case OBJECT_CONVERSION:
			tag = "ALTER CONVERSION";
			break;
		case OBJECT_DATABASE:
			tag = "ALTER DATABASE";
			break;
		case OBJECT_DOMAIN:
			tag = "ALTER DOMAIN";
			break;
		case OBJECT_EXTENSION:
			tag = "ALTER EXTENSION";
			break;
		case OBJECT_FDW:
			tag = "ALTER FOREIGN DATA WRAPPER";
			break;
		case OBJECT_FOREIGN_SERVER:
			tag = "ALTER SERVER";
			break;
		case OBJECT_FOREIGN_TABLE:
			tag = "ALTER FOREIGN TABLE";
			break;
		case OBJECT_FUNCTION:
			tag = "ALTER FUNCTION";
			break;
		case OBJECT_INDEX:
			tag = "ALTER INDEX";
			break;
		case OBJECT_LANGUAGE:
			tag = "ALTER LANGUAGE";
			break;
		case OBJECT_LARGEOBJECT:
			tag = "ALTER LARGE OBJECT";
			break;
		case OBJECT_OPCLASS:
			tag = "ALTER OPERATOR CLASS";
			break;
		case OBJECT_OPERATOR:
			tag = "ALTER OPERATOR";
			break;
		case OBJECT_OPFAMILY:
			tag = "ALTER OPERATOR FAMILY";
			break;
		case OBJECT_ROLE:
			tag = "ALTER ROLE";
			break;
		case OBJECT_RULE:
			tag = "ALTER RULE";
			break;
		case OBJECT_SCHEMA:
			tag = "ALTER SCHEMA";
			break;
		case OBJECT_SEQUENCE:
			tag = "ALTER SEQUENCE";
			break;
		case OBJECT_TABLE:
			tag = "ALTER TABLE";
			break;
		case OBJECT_TABLESPACE:
			tag = "ALTER TABLESPACE";
			break;
		case OBJECT_TRIGGER:
			tag = "ALTER TRIGGER";
			break;
		case OBJECT_EVENT_TRIGGER:
			tag = "ALTER EVENT TRIGGER";
			break;
		case OBJECT_TSCONFIGURATION:
			tag = "ALTER TEXT SEARCH CONFIGURATION";
			break;
		case OBJECT_TSDICTIONARY:
			tag = "ALTER TEXT SEARCH DICTIONARY";
			break;
		case OBJECT_TSPARSER:
			tag = "ALTER TEXT SEARCH PARSER";
			break;
		case OBJECT_TSTEMPLATE:
			tag = "ALTER TEXT SEARCH TEMPLATE";
			break;
		case OBJECT_TYPE:
			tag = "ALTER TYPE";
			break;
		case OBJECT_VIEW:
			tag = "ALTER VIEW";
			break;
		case OBJECT_MATVIEW:
			tag = "ALTER MATERIALIZED VIEW";
			break;
		default:
			tag = "???";
			break;
	}

	return tag;
}


const char * CreateCommandTag(Node *parsetree)
{
	const char *tag;

	switch (nodeTag(parsetree))
	{
			
		case T_InsertStmt:
			tag = "INSERT";
			break;

		case T_DeleteStmt:
			tag = "DELETE";
			break;

		case T_UpdateStmt:
			tag = "UPDATE";
			break;

		case T_SelectStmt:
			tag = "SELECT";
			break;

			
		case T_TransactionStmt:
			{
				TransactionStmt *stmt = (TransactionStmt *) parsetree;

				switch (stmt->kind)
				{
					case TRANS_STMT_BEGIN:
						tag = "BEGIN";
						break;

					case TRANS_STMT_START:
						tag = "START TRANSACTION";
						break;

					case TRANS_STMT_COMMIT:
						tag = "COMMIT";
						break;

					case TRANS_STMT_ROLLBACK:
					case TRANS_STMT_ROLLBACK_TO:
						tag = "ROLLBACK";
						break;

					case TRANS_STMT_SAVEPOINT:
						tag = "SAVEPOINT";
						break;

					case TRANS_STMT_RELEASE:
						tag = "RELEASE";
						break;

					case TRANS_STMT_PREPARE:
						tag = "PREPARE TRANSACTION";
						break;

					case TRANS_STMT_COMMIT_PREPARED:
						tag = "COMMIT PREPARED";
						break;

					case TRANS_STMT_ROLLBACK_PREPARED:
						tag = "ROLLBACK PREPARED";
						break;

					default:
						tag = "???";
						break;
				}
			}
			break;

		case T_DeclareCursorStmt:
			tag = "DECLARE CURSOR";
			break;

		case T_ClosePortalStmt:
			{
				ClosePortalStmt *stmt = (ClosePortalStmt *) parsetree;

				if (stmt->portalname == NULL)
					tag = "CLOSE CURSOR ALL";
				else tag = "CLOSE CURSOR";
			}
			break;

		case T_FetchStmt:
			{
				FetchStmt  *stmt = (FetchStmt *) parsetree;

				tag = (stmt->ismove) ? "MOVE" : "FETCH";
			}
			break;

		case T_CreateDomainStmt:
			tag = "CREATE DOMAIN";
			break;

		case T_CreateSchemaStmt:
			tag = "CREATE SCHEMA";
			break;

		case T_CreateStmt:
			tag = "CREATE TABLE";
			break;

		case T_CreateTableSpaceStmt:
			tag = "CREATE TABLESPACE";
			break;

		case T_DropTableSpaceStmt:
			tag = "DROP TABLESPACE";
			break;

		case T_AlterTableSpaceOptionsStmt:
			tag = "ALTER TABLESPACE";
			break;

		case T_AlterTableSpaceMoveStmt:
			tag = "ALTER TABLESPACE";
			break;

		case T_CreateExtensionStmt:
			tag = "CREATE EXTENSION";
			break;

		case T_AlterExtensionStmt:
			tag = "ALTER EXTENSION";
			break;

		case T_AlterExtensionContentsStmt:
			tag = "ALTER EXTENSION";
			break;

		case T_CreateFdwStmt:
			tag = "CREATE FOREIGN DATA WRAPPER";
			break;

		case T_AlterFdwStmt:
			tag = "ALTER FOREIGN DATA WRAPPER";
			break;

		case T_CreateForeignServerStmt:
			tag = "CREATE SERVER";
			break;

		case T_AlterForeignServerStmt:
			tag = "ALTER SERVER";
			break;

		case T_CreateUserMappingStmt:
			tag = "CREATE USER MAPPING";
			break;

		case T_AlterUserMappingStmt:
			tag = "ALTER USER MAPPING";
			break;

		case T_DropUserMappingStmt:
			tag = "DROP USER MAPPING";
			break;

		case T_CreateForeignTableStmt:
			tag = "CREATE FOREIGN TABLE";
			break;

		case T_DropStmt:
			switch (((DropStmt *) parsetree)->removeType)
			{
				case OBJECT_TABLE:
					tag = "DROP TABLE";
					break;
				case OBJECT_SEQUENCE:
					tag = "DROP SEQUENCE";
					break;
				case OBJECT_VIEW:
					tag = "DROP VIEW";
					break;
				case OBJECT_MATVIEW:
					tag = "DROP MATERIALIZED VIEW";
					break;
				case OBJECT_INDEX:
					tag = "DROP INDEX";
					break;
				case OBJECT_TYPE:
					tag = "DROP TYPE";
					break;
				case OBJECT_DOMAIN:
					tag = "DROP DOMAIN";
					break;
				case OBJECT_COLLATION:
					tag = "DROP COLLATION";
					break;
				case OBJECT_CONVERSION:
					tag = "DROP CONVERSION";
					break;
				case OBJECT_SCHEMA:
					tag = "DROP SCHEMA";
					break;
				case OBJECT_TSPARSER:
					tag = "DROP TEXT SEARCH PARSER";
					break;
				case OBJECT_TSDICTIONARY:
					tag = "DROP TEXT SEARCH DICTIONARY";
					break;
				case OBJECT_TSTEMPLATE:
					tag = "DROP TEXT SEARCH TEMPLATE";
					break;
				case OBJECT_TSCONFIGURATION:
					tag = "DROP TEXT SEARCH CONFIGURATION";
					break;
				case OBJECT_FOREIGN_TABLE:
					tag = "DROP FOREIGN TABLE";
					break;
				case OBJECT_EXTENSION:
					tag = "DROP EXTENSION";
					break;
				case OBJECT_FUNCTION:
					tag = "DROP FUNCTION";
					break;
				case OBJECT_AGGREGATE:
					tag = "DROP AGGREGATE";
					break;
				case OBJECT_OPERATOR:
					tag = "DROP OPERATOR";
					break;
				case OBJECT_LANGUAGE:
					tag = "DROP LANGUAGE";
					break;
				case OBJECT_CAST:
					tag = "DROP CAST";
					break;
				case OBJECT_TRIGGER:
					tag = "DROP TRIGGER";
					break;
				case OBJECT_EVENT_TRIGGER:
					tag = "DROP EVENT TRIGGER";
					break;
				case OBJECT_RULE:
					tag = "DROP RULE";
					break;
				case OBJECT_FDW:
					tag = "DROP FOREIGN DATA WRAPPER";
					break;
				case OBJECT_FOREIGN_SERVER:
					tag = "DROP SERVER";
					break;
				case OBJECT_OPCLASS:
					tag = "DROP OPERATOR CLASS";
					break;
				case OBJECT_OPFAMILY:
					tag = "DROP OPERATOR FAMILY";
					break;
				default:
					tag = "???";
			}
			break;

		case T_TruncateStmt:
			tag = "TRUNCATE TABLE";
			break;

		case T_CommentStmt:
			tag = "COMMENT";
			break;

		case T_SecLabelStmt:
			tag = "SECURITY LABEL";
			break;

		case T_CopyStmt:
			tag = "COPY";
			break;

		case T_RenameStmt:
			tag = AlterObjectTypeCommandTag(((RenameStmt *) parsetree)->renameType);
			break;

		case T_AlterObjectSchemaStmt:
			tag = AlterObjectTypeCommandTag(((AlterObjectSchemaStmt *) parsetree)->objectType);
			break;

		case T_AlterOwnerStmt:
			tag = AlterObjectTypeCommandTag(((AlterOwnerStmt *) parsetree)->objectType);
			break;

		case T_AlterTableStmt:
			tag = AlterObjectTypeCommandTag(((AlterTableStmt *) parsetree)->relkind);
			break;

		case T_AlterDomainStmt:
			tag = "ALTER DOMAIN";
			break;

		case T_AlterFunctionStmt:
			tag = "ALTER FUNCTION";
			break;

		case T_GrantStmt:
			{
				GrantStmt  *stmt = (GrantStmt *) parsetree;

				tag = (stmt->is_grant) ? "GRANT" : "REVOKE";
			}
			break;

		case T_GrantRoleStmt:
			{
				GrantRoleStmt *stmt = (GrantRoleStmt *) parsetree;

				tag = (stmt->is_grant) ? "GRANT ROLE" : "REVOKE ROLE";
			}
			break;

		case T_AlterDefaultPrivilegesStmt:
			tag = "ALTER DEFAULT PRIVILEGES";
			break;

		case T_DefineStmt:
			switch (((DefineStmt *) parsetree)->kind)
			{
				case OBJECT_AGGREGATE:
					tag = "CREATE AGGREGATE";
					break;
				case OBJECT_OPERATOR:
					tag = "CREATE OPERATOR";
					break;
				case OBJECT_TYPE:
					tag = "CREATE TYPE";
					break;
				case OBJECT_TSPARSER:
					tag = "CREATE TEXT SEARCH PARSER";
					break;
				case OBJECT_TSDICTIONARY:
					tag = "CREATE TEXT SEARCH DICTIONARY";
					break;
				case OBJECT_TSTEMPLATE:
					tag = "CREATE TEXT SEARCH TEMPLATE";
					break;
				case OBJECT_TSCONFIGURATION:
					tag = "CREATE TEXT SEARCH CONFIGURATION";
					break;
				case OBJECT_COLLATION:
					tag = "CREATE COLLATION";
					break;
				default:
					tag = "???";
			}
			break;

		case T_CompositeTypeStmt:
			tag = "CREATE TYPE";
			break;

		case T_CreateEnumStmt:
			tag = "CREATE TYPE";
			break;

		case T_CreateRangeStmt:
			tag = "CREATE TYPE";
			break;

		case T_AlterEnumStmt:
			tag = "ALTER TYPE";
			break;

		case T_ViewStmt:
			tag = "CREATE VIEW";
			break;

		case T_CreateFunctionStmt:
			tag = "CREATE FUNCTION";
			break;

		case T_IndexStmt:
			tag = "CREATE INDEX";
			break;

		case T_RuleStmt:
			tag = "CREATE RULE";
			break;

		case T_CreateSeqStmt:
			tag = "CREATE SEQUENCE";
			break;

		case T_AlterSeqStmt:
			tag = "ALTER SEQUENCE";
			break;

		case T_DoStmt:
			tag = "DO";
			break;

		case T_CreatedbStmt:
			tag = "CREATE DATABASE";
			break;

		case T_AlterDatabaseStmt:
			tag = "ALTER DATABASE";
			break;

		case T_AlterDatabaseSetStmt:
			tag = "ALTER DATABASE";
			break;

		case T_DropdbStmt:
			tag = "DROP DATABASE";
			break;

		case T_NotifyStmt:
			tag = "NOTIFY";
			break;

		case T_ListenStmt:
			tag = "LISTEN";
			break;

		case T_UnlistenStmt:
			tag = "UNLISTEN";
			break;

		case T_LoadStmt:
			tag = "LOAD";
			break;

		case T_ClusterStmt:
			tag = "CLUSTER";
			break;

		case T_VacuumStmt:
			if (((VacuumStmt *) parsetree)->options & VACOPT_VACUUM)
				tag = "VACUUM";
			else tag = "ANALYZE";
			break;

		case T_ExplainStmt:
			tag = "EXPLAIN";
			break;

		case T_CreateTableAsStmt:
			switch (((CreateTableAsStmt *) parsetree)->relkind)
			{
				case OBJECT_TABLE:
					if (((CreateTableAsStmt *) parsetree)->is_select_into)
						tag = "SELECT INTO";
					else tag = "CREATE TABLE AS";
					break;
				case OBJECT_MATVIEW:
					tag = "CREATE MATERIALIZED VIEW";
					break;
				default:
					tag = "???";
			}
			break;

		case T_RefreshMatViewStmt:
			tag = "REFRESH MATERIALIZED VIEW";
			break;

		case T_AlterSystemStmt:
			tag = "ALTER SYSTEM";
			break;

		case T_VariableSetStmt:
			switch (((VariableSetStmt *) parsetree)->kind)
			{
				case VAR_SET_VALUE:
				case VAR_SET_CURRENT:
				case VAR_SET_DEFAULT:
				case VAR_SET_MULTI:
					tag = "SET";
					break;
				case VAR_RESET:
				case VAR_RESET_ALL:
					tag = "RESET";
					break;
				default:
					tag = "???";
			}
			break;

		case T_VariableShowStmt:
			tag = "SHOW";
			break;

		case T_DiscardStmt:
			switch (((DiscardStmt *) parsetree)->target)
			{
				case DISCARD_ALL:
					tag = "DISCARD ALL";
					break;
				case DISCARD_PLANS:
					tag = "DISCARD PLANS";
					break;
				case DISCARD_TEMP:
					tag = "DISCARD TEMP";
					break;
				case DISCARD_SEQUENCES:
					tag = "DISCARD SEQUENCES";
					break;
				default:
					tag = "???";
			}
			break;

		case T_CreateTrigStmt:
			tag = "CREATE TRIGGER";
			break;

		case T_CreateEventTrigStmt:
			tag = "CREATE EVENT TRIGGER";
			break;

		case T_AlterEventTrigStmt:
			tag = "ALTER EVENT TRIGGER";
			break;

		case T_CreatePLangStmt:
			tag = "CREATE LANGUAGE";
			break;

		case T_CreateRoleStmt:
			tag = "CREATE ROLE";
			break;

		case T_AlterRoleStmt:
			tag = "ALTER ROLE";
			break;

		case T_AlterRoleSetStmt:
			tag = "ALTER ROLE";
			break;

		case T_DropRoleStmt:
			tag = "DROP ROLE";
			break;

		case T_DropOwnedStmt:
			tag = "DROP OWNED";
			break;

		case T_ReassignOwnedStmt:
			tag = "REASSIGN OWNED";
			break;

		case T_LockStmt:
			tag = "LOCK TABLE";
			break;

		case T_ConstraintsSetStmt:
			tag = "SET CONSTRAINTS";
			break;

		case T_CheckPointStmt:
			tag = "CHECKPOINT";
			break;

		case T_ReindexStmt:
			tag = "REINDEX";
			break;

		case T_CreateConversionStmt:
			tag = "CREATE CONVERSION";
			break;

		case T_CreateCastStmt:
			tag = "CREATE CAST";
			break;

		case T_CreateOpClassStmt:
			tag = "CREATE OPERATOR CLASS";
			break;

		case T_CreateOpFamilyStmt:
			tag = "CREATE OPERATOR FAMILY";
			break;

		case T_AlterOpFamilyStmt:
			tag = "ALTER OPERATOR FAMILY";
			break;

		case T_AlterTSDictionaryStmt:
			tag = "ALTER TEXT SEARCH DICTIONARY";
			break;

		case T_AlterTSConfigurationStmt:
			tag = "ALTER TEXT SEARCH CONFIGURATION";
			break;

		case T_PrepareStmt:
			tag = "PREPARE";
			break;

		case T_ExecuteStmt:
			tag = "EXECUTE";
			break;

		case T_DeallocateStmt:
			{
				DeallocateStmt *stmt = (DeallocateStmt *) parsetree;

				if (stmt->name == NULL)
					tag = "DEALLOCATE ALL";
				else tag = "DEALLOCATE";
			}
			break;

			
		case T_PlannedStmt:
			{
				PlannedStmt *stmt = (PlannedStmt *) parsetree;

				switch (stmt->commandType)
				{
					case CMD_SELECT:

						
						if (stmt->utilityStmt != NULL)
						{
							Assert(IsA(stmt->utilityStmt, DeclareCursorStmt));
							tag = "DECLARE CURSOR";
						}
						else if (stmt->rowMarks != NIL)
						{
							
							switch (((PlanRowMark *) linitial(stmt->rowMarks))->markType)
							{
								case ROW_MARK_EXCLUSIVE:
									tag = "SELECT FOR UPDATE";
									break;
								case ROW_MARK_NOKEYEXCLUSIVE:
									tag = "SELECT FOR NO KEY UPDATE";
									break;
								case ROW_MARK_SHARE:
									tag = "SELECT FOR SHARE";
									break;
								case ROW_MARK_KEYSHARE:
									tag = "SELECT FOR KEY SHARE";
									break;
								case ROW_MARK_REFERENCE:
								case ROW_MARK_COPY:
									tag = "SELECT";
									break;
								default:
									tag = "???";
									break;
							}
						}
						else tag = "SELECT";
						break;
					case CMD_UPDATE:
						tag = "UPDATE";
						break;
					case CMD_INSERT:
						tag = "INSERT";
						break;
					case CMD_DELETE:
						tag = "DELETE";
						break;
					default:
						elog(WARNING, "unrecognized commandType: %d", (int) stmt->commandType);
						tag = "???";
						break;
				}
			}
			break;

			
		case T_Query:
			{
				Query	   *stmt = (Query *) parsetree;

				switch (stmt->commandType)
				{
					case CMD_SELECT:

						
						if (stmt->utilityStmt != NULL)
						{
							Assert(IsA(stmt->utilityStmt, DeclareCursorStmt));
							tag = "DECLARE CURSOR";
						}
						else if (stmt->rowMarks != NIL)
						{
							
							switch (((RowMarkClause *) linitial(stmt->rowMarks))->strength)
							{
								case LCS_FORKEYSHARE:
									tag = "SELECT FOR KEY SHARE";
									break;
								case LCS_FORSHARE:
									tag = "SELECT FOR SHARE";
									break;
								case LCS_FORNOKEYUPDATE:
									tag = "SELECT FOR NO KEY UPDATE";
									break;
								case LCS_FORUPDATE:
									tag = "SELECT FOR UPDATE";
									break;
								default:
									tag = "???";
									break;
							}
						}
						else tag = "SELECT";
						break;
					case CMD_UPDATE:
						tag = "UPDATE";
						break;
					case CMD_INSERT:
						tag = "INSERT";
						break;
					case CMD_DELETE:
						tag = "DELETE";
						break;
					case CMD_UTILITY:
						tag = CreateCommandTag(stmt->utilityStmt);
						break;
					default:
						elog(WARNING, "unrecognized commandType: %d", (int) stmt->commandType);
						tag = "???";
						break;
				}
			}
			break;

		default:
			elog(WARNING, "unrecognized node type: %d", (int) nodeTag(parsetree));
			tag = "???";
			break;
	}

	return tag;
}



LogStmtLevel GetCommandLogLevel(Node *parsetree)
{
	LogStmtLevel lev;

	switch (nodeTag(parsetree))
	{
			
		case T_InsertStmt:
		case T_DeleteStmt:
		case T_UpdateStmt:
			lev = LOGSTMT_MOD;
			break;

		case T_SelectStmt:
			if (((SelectStmt *) parsetree)->intoClause)
				lev = LOGSTMT_DDL;		
			else lev = LOGSTMT_ALL;
			break;

			
		case T_TransactionStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_DeclareCursorStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_ClosePortalStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_FetchStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_CreateSchemaStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateStmt:
		case T_CreateForeignTableStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateTableSpaceStmt:
		case T_DropTableSpaceStmt:
		case T_AlterTableSpaceOptionsStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterTableSpaceMoveStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateExtensionStmt:
		case T_AlterExtensionStmt:
		case T_AlterExtensionContentsStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateFdwStmt:
		case T_AlterFdwStmt:
		case T_CreateForeignServerStmt:
		case T_AlterForeignServerStmt:
		case T_CreateUserMappingStmt:
		case T_AlterUserMappingStmt:
		case T_DropUserMappingStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_DropStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_TruncateStmt:
			lev = LOGSTMT_MOD;
			break;

		case T_CommentStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_SecLabelStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CopyStmt:
			if (((CopyStmt *) parsetree)->is_from)
				lev = LOGSTMT_MOD;
			else lev = LOGSTMT_ALL;
			break;

		case T_PrepareStmt:
			{
				PrepareStmt *stmt = (PrepareStmt *) parsetree;

				
				lev = GetCommandLogLevel(stmt->query);
			}
			break;

		case T_ExecuteStmt:
			{
				ExecuteStmt *stmt = (ExecuteStmt *) parsetree;
				PreparedStatement *ps;

				
				ps = FetchPreparedStatement(stmt->name, false);
				if (ps)
					lev = GetCommandLogLevel(ps->plansource->raw_parse_tree);
				else lev = LOGSTMT_ALL;
			}
			break;

		case T_DeallocateStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_RenameStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterObjectSchemaStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterOwnerStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterTableStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterDomainStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_GrantStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_GrantRoleStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterDefaultPrivilegesStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_DefineStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CompositeTypeStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateEnumStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateRangeStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterEnumStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_ViewStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateFunctionStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterFunctionStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_IndexStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_RuleStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateSeqStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterSeqStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_DoStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_CreatedbStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterDatabaseStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterDatabaseSetStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_DropdbStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_NotifyStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_ListenStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_UnlistenStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_LoadStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_ClusterStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_VacuumStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_ExplainStmt:
			{
				ExplainStmt *stmt = (ExplainStmt *) parsetree;
				bool		analyze = false;
				ListCell   *lc;

				
				foreach(lc, stmt->options)
				{
					DefElem    *opt = (DefElem *) lfirst(lc);

					if (strcmp(opt->defname, "analyze") == 0)
						analyze = defGetBoolean(opt);
					
				}
				if (analyze)
					return GetCommandLogLevel(stmt->query);

				
				lev = LOGSTMT_ALL;
			}
			break;

		case T_CreateTableAsStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_RefreshMatViewStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterSystemStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_VariableSetStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_VariableShowStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_DiscardStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_CreateTrigStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateEventTrigStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterEventTrigStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreatePLangStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateDomainStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateRoleStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterRoleStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterRoleSetStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_DropRoleStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_DropOwnedStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_ReassignOwnedStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_LockStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_ConstraintsSetStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_CheckPointStmt:
			lev = LOGSTMT_ALL;
			break;

		case T_ReindexStmt:
			lev = LOGSTMT_ALL;	
			break;

		case T_CreateConversionStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateCastStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateOpClassStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_CreateOpFamilyStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterOpFamilyStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterTSDictionaryStmt:
			lev = LOGSTMT_DDL;
			break;

		case T_AlterTSConfigurationStmt:
			lev = LOGSTMT_DDL;
			break;

			
		case T_PlannedStmt:
			{
				PlannedStmt *stmt = (PlannedStmt *) parsetree;

				switch (stmt->commandType)
				{
					case CMD_SELECT:
						lev = LOGSTMT_ALL;
						break;

					case CMD_UPDATE:
					case CMD_INSERT:
					case CMD_DELETE:
						lev = LOGSTMT_MOD;
						break;

					default:
						elog(WARNING, "unrecognized commandType: %d", (int) stmt->commandType);
						lev = LOGSTMT_ALL;
						break;
				}
			}
			break;

			
		case T_Query:
			{
				Query	   *stmt = (Query *) parsetree;

				switch (stmt->commandType)
				{
					case CMD_SELECT:
						lev = LOGSTMT_ALL;
						break;

					case CMD_UPDATE:
					case CMD_INSERT:
					case CMD_DELETE:
						lev = LOGSTMT_MOD;
						break;

					case CMD_UTILITY:
						lev = GetCommandLogLevel(stmt->utilityStmt);
						break;

					default:
						elog(WARNING, "unrecognized commandType: %d", (int) stmt->commandType);
						lev = LOGSTMT_ALL;
						break;
				}

			}
			break;

		default:
			elog(WARNING, "unrecognized node type: %d", (int) nodeTag(parsetree));
			lev = LOGSTMT_ALL;
			break;
	}

	return lev;
}
