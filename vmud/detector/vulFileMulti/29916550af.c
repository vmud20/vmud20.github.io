
























typedef struct evalPlanQual {
	Index		rti;
	EState	   *estate;
	PlanState  *planstate;
	struct evalPlanQual *next;	
	struct evalPlanQual *free;	
} evalPlanQual;


static void InitPlan(QueryDesc *queryDesc, int eflags);
static void initResultRelInfo(ResultRelInfo *resultRelInfo, Index resultRelationIndex, List *rangeTable, CmdType operation, bool doInstrument);



static TupleTableSlot *ExecutePlan(EState *estate, PlanState *planstate, CmdType operation, long numberTuples, ScanDirection direction, DestReceiver *dest);



static void ExecSelect(TupleTableSlot *slot, DestReceiver *dest, EState *estate);
static void ExecInsert(TupleTableSlot *slot, ItemPointer tupleid, TupleTableSlot *planSlot, DestReceiver *dest, EState *estate);

static void ExecDelete(ItemPointer tupleid, TupleTableSlot *planSlot, DestReceiver *dest, EState *estate);

static void ExecUpdate(TupleTableSlot *slot, ItemPointer tupleid, TupleTableSlot *planSlot, DestReceiver *dest, EState *estate);

static void ExecProcessReturning(ProjectionInfo *projectReturning, TupleTableSlot *tupleSlot, TupleTableSlot *planSlot, DestReceiver *dest);


static TupleTableSlot *EvalPlanQualNext(EState *estate);
static void EndEvalPlanQual(EState *estate);
static void ExecCheckRTEPerms(RangeTblEntry *rte);
static void ExecCheckXactReadOnly(Query *parsetree);
static void EvalPlanQualStart(evalPlanQual *epq, EState *estate, evalPlanQual *priorepq);
static void EvalPlanQualStop(evalPlanQual *epq);
static void OpenIntoRel(QueryDesc *queryDesc);
static void CloseIntoRel(QueryDesc *queryDesc);
static void intorel_startup(DestReceiver *self, int operation, TupleDesc typeinfo);
static void intorel_receive(TupleTableSlot *slot, DestReceiver *self);
static void intorel_shutdown(DestReceiver *self);
static void intorel_destroy(DestReceiver *self);





void ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	EState	   *estate;
	MemoryContext oldcontext;

	
	Assert(queryDesc != NULL);
	Assert(queryDesc->estate == NULL);

	
	if (XactReadOnly && !(eflags & EXEC_FLAG_EXPLAIN_ONLY))
		ExecCheckXactReadOnly(queryDesc->parsetree);

	
	estate = CreateExecutorState();
	queryDesc->estate = estate;

	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	
	estate->es_param_list_info = queryDesc->params;

	if (queryDesc->plantree->nParamExec > 0)
		estate->es_param_exec_vals = (ParamExecData *)
			palloc0(queryDesc->plantree->nParamExec * sizeof(ParamExecData));

	
	estate->es_snapshot = queryDesc->snapshot;
	estate->es_crosscheck_snapshot = queryDesc->crosscheck_snapshot;
	estate->es_instrument = queryDesc->doInstrument;

	
	InitPlan(queryDesc, eflags);

	MemoryContextSwitchTo(oldcontext);
}


TupleTableSlot * ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, long count)

{
	EState	   *estate;
	CmdType		operation;
	DestReceiver *dest;
	bool		sendTuples;
	TupleTableSlot *result;
	MemoryContext oldcontext;

	
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);

	
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	
	operation = queryDesc->operation;
	dest = queryDesc->dest;

	
	estate->es_processed = 0;
	estate->es_lastoid = InvalidOid;

	sendTuples = (operation == CMD_SELECT || queryDesc->parsetree->returningList);

	if (sendTuples)
		(*dest->rStartup) (dest, operation, queryDesc->tupDesc);

	
	if (ScanDirectionIsNoMovement(direction))
		result = NULL;
	else result = ExecutePlan(estate, queryDesc->planstate, operation, count, direction, dest);






	
	if (sendTuples)
		(*dest->rShutdown) (dest);

	MemoryContextSwitchTo(oldcontext);

	return result;
}


void ExecutorEnd(QueryDesc *queryDesc)
{
	EState	   *estate;
	MemoryContext oldcontext;

	
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);

	
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	ExecEndPlan(queryDesc->planstate, estate);

	
	if (estate->es_select_into)
		CloseIntoRel(queryDesc);

	
	MemoryContextSwitchTo(oldcontext);

	
	FreeExecutorState(estate);

	
	queryDesc->tupDesc = NULL;
	queryDesc->estate = NULL;
	queryDesc->planstate = NULL;
}


void ExecutorRewind(QueryDesc *queryDesc)
{
	EState	   *estate;
	MemoryContext oldcontext;

	
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);

	
	Assert(queryDesc->operation == CMD_SELECT);

	
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	
	ExecReScan(queryDesc->planstate, NULL);

	MemoryContextSwitchTo(oldcontext);
}



void ExecCheckRTPerms(List *rangeTable)
{
	ListCell   *l;

	foreach(l, rangeTable)
	{
		RangeTblEntry *rte = lfirst(l);

		ExecCheckRTEPerms(rte);
	}
}


static void ExecCheckRTEPerms(RangeTblEntry *rte)
{
	AclMode		requiredPerms;
	Oid			relOid;
	Oid			userid;

	
	if (rte->rtekind != RTE_RELATION)
		return;

	
	requiredPerms = rte->requiredPerms;
	if (requiredPerms == 0)
		return;

	relOid = rte->relid;

	
	userid = rte->checkAsUser ? rte->checkAsUser : GetUserId();

	
	if (pg_class_aclmask(relOid, userid, requiredPerms, ACLMASK_ALL)
		!= requiredPerms)
		aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS, get_rel_name(relOid));
}


static void ExecCheckXactReadOnly(Query *parsetree)
{
	ListCell   *l;

	
	if (parsetree->into != NULL)
		goto fail;

	
	foreach(l, parsetree->rtable)
	{
		RangeTblEntry *rte = lfirst(l);

		if (rte->rtekind == RTE_SUBQUERY)
		{
			ExecCheckXactReadOnly(rte->subquery);
			continue;
		}

		if (rte->rtekind != RTE_RELATION)
			continue;

		if ((rte->requiredPerms & (~ACL_SELECT)) == 0)
			continue;

		if (isTempNamespace(get_rel_namespace(rte->relid)))
			continue;

		goto fail;
	}

	return;

fail:
	ereport(ERROR, (errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION), errmsg("transaction is read-only")));

}



static void InitPlan(QueryDesc *queryDesc, int eflags)
{
	CmdType		operation = queryDesc->operation;
	Query	   *parseTree = queryDesc->parsetree;
	Plan	   *plan = queryDesc->plantree;
	EState	   *estate = queryDesc->estate;
	PlanState  *planstate;
	List	   *rangeTable;
	TupleDesc	tupType;
	ListCell   *l;

	
	ExecCheckRTPerms(parseTree->rtable);

	
	rangeTable = parseTree->rtable;

	
	estate->es_range_table = rangeTable;

	
	if (parseTree->resultRelation)
	{
		List	   *resultRelations = parseTree->resultRelations;
		int			numResultRelations;
		ResultRelInfo *resultRelInfos;

		if (resultRelations != NIL)
		{
			
			ResultRelInfo *resultRelInfo;

			numResultRelations = list_length(resultRelations);
			resultRelInfos = (ResultRelInfo *)
				palloc(numResultRelations * sizeof(ResultRelInfo));
			resultRelInfo = resultRelInfos;
			foreach(l, resultRelations)
			{
				initResultRelInfo(resultRelInfo, lfirst_int(l), rangeTable, operation, estate->es_instrument);



				resultRelInfo++;
			}
		}
		else {
			
			numResultRelations = 1;
			resultRelInfos = (ResultRelInfo *) palloc(sizeof(ResultRelInfo));
			initResultRelInfo(resultRelInfos, parseTree->resultRelation, rangeTable, operation, estate->es_instrument);



		}

		estate->es_result_relations = resultRelInfos;
		estate->es_num_result_relations = numResultRelations;
		
		estate->es_result_relation_info = resultRelInfos;
	}
	else {
		
		estate->es_result_relations = NULL;
		estate->es_num_result_relations = 0;
		estate->es_result_relation_info = NULL;
	}

	
	estate->es_select_into = false;
	if (operation == CMD_SELECT && parseTree->into != NULL)
	{
		estate->es_select_into = true;
		estate->es_into_oids = interpretOidsOption(parseTree->intoOptions);
	}

	
	estate->es_rowMarks = NIL;
	foreach(l, parseTree->rowMarks)
	{
		RowMarkClause *rc = (RowMarkClause *) lfirst(l);
		Oid			relid = getrelid(rc->rti, rangeTable);
		Relation	relation;
		ExecRowMark *erm;

		relation = heap_open(relid, RowShareLock);
		erm = (ExecRowMark *) palloc(sizeof(ExecRowMark));
		erm->relation = relation;
		erm->rti = rc->rti;
		erm->forUpdate = rc->forUpdate;
		erm->noWait = rc->noWait;
		
		erm->ctidAttNo = InvalidAttrNumber;
		estate->es_rowMarks = lappend(estate->es_rowMarks, erm);
	}

	
	{
		int			nSlots = ExecCountSlotsNode(plan);

		if (parseTree->resultRelations != NIL)
			nSlots += list_length(parseTree->resultRelations);
		else nSlots += 1;
		if (operation != CMD_SELECT)
			nSlots++;			
		if (parseTree->returningLists)
			nSlots++;			

		estate->es_tupleTable = ExecCreateTupleTable(nSlots);

		if (operation != CMD_SELECT)
			estate->es_trig_tuple_slot = ExecAllocTableSlot(estate->es_tupleTable);
	}

	
	estate->es_topPlan = plan;
	estate->es_evalPlanQual = NULL;
	estate->es_evTupleNull = NULL;
	estate->es_evTuple = NULL;
	estate->es_useEvalPlan = false;

	
	planstate = ExecInitNode(plan, estate, eflags);

	
	tupType = ExecGetResultType(planstate);

	
	{
		bool		junk_filter_needed = false;
		ListCell   *tlist;

		switch (operation)
		{
			case CMD_SELECT:
			case CMD_INSERT:
				foreach(tlist, plan->targetlist)
				{
					TargetEntry *tle = (TargetEntry *) lfirst(tlist);

					if (tle->resjunk)
					{
						junk_filter_needed = true;
						break;
					}
				}
				if (!junk_filter_needed && (operation == CMD_INSERT || estate->es_select_into) && ExecMayReturnRawTuples(planstate))

					junk_filter_needed = true;
				break;
			case CMD_UPDATE:
			case CMD_DELETE:
				junk_filter_needed = true;
				break;
			default:
				break;
		}

		if (junk_filter_needed)
		{
			
			if (parseTree->resultRelations != NIL)
			{
				PlanState **appendplans;
				int			as_nplans;
				ResultRelInfo *resultRelInfo;
				int			i;

				
				Assert(IsA(plan, Append));
				Assert(((Append *) plan)->isTarget);
				Assert(IsA(planstate, AppendState));
				appendplans = ((AppendState *) planstate)->appendplans;
				as_nplans = ((AppendState *) planstate)->as_nplans;
				Assert(as_nplans == estate->es_num_result_relations);
				resultRelInfo = estate->es_result_relations;
				for (i = 0; i < as_nplans; i++)
				{
					PlanState  *subplan = appendplans[i];
					JunkFilter *j;

					j = ExecInitJunkFilter(subplan->plan->targetlist, resultRelInfo->ri_RelationDesc->rd_att->tdhasoid, ExecAllocTableSlot(estate->es_tupleTable));

					
					j->jf_junkAttNo = ExecFindJunkAttribute(j, "ctid");
					if (!AttributeNumberIsValid(j->jf_junkAttNo))
						elog(ERROR, "could not find junk ctid column");
					resultRelInfo->ri_junkFilter = j;
					resultRelInfo++;
				}

				
				estate->es_junkFilter = estate->es_result_relation_info->ri_junkFilter;
			}
			else {
				
				JunkFilter *j;

				j = ExecInitJunkFilter(planstate->plan->targetlist, tupType->tdhasoid, ExecAllocTableSlot(estate->es_tupleTable));

				estate->es_junkFilter = j;
				if (estate->es_result_relation_info)
					estate->es_result_relation_info->ri_junkFilter = j;

				if (operation == CMD_SELECT)
				{
					
					tupType = j->jf_cleanTupType;
					
					foreach(l, estate->es_rowMarks)
					{
						ExecRowMark *erm = (ExecRowMark *) lfirst(l);
						char		resname[32];

						snprintf(resname, sizeof(resname), "ctid%u", erm->rti);
						erm->ctidAttNo = ExecFindJunkAttribute(j, resname);
						if (!AttributeNumberIsValid(erm->ctidAttNo))
							elog(ERROR, "could not find junk \"%s\" column", resname);
					}
				}
				else if (operation == CMD_UPDATE || operation == CMD_DELETE)
				{
					
					j->jf_junkAttNo = ExecFindJunkAttribute(j, "ctid");
					if (!AttributeNumberIsValid(j->jf_junkAttNo))
						elog(ERROR, "could not find junk ctid column");
				}
			}
		}
		else estate->es_junkFilter = NULL;
	}

	
	if (parseTree->returningLists)
	{
		TupleTableSlot *slot;
		ExprContext *econtext;
		ResultRelInfo *resultRelInfo;

		
		tupType = ExecTypeFromTL((List *) linitial(parseTree->returningLists), false);

		
		slot = ExecAllocTableSlot(estate->es_tupleTable);
		ExecSetSlotDescriptor(slot, tupType);
		
		econtext = CreateExprContext(estate);

		
		Assert(list_length(parseTree->returningLists) == estate->es_num_result_relations);
		resultRelInfo = estate->es_result_relations;
		foreach(l, parseTree->returningLists)
		{
			List	   *rlist = (List *) lfirst(l);
			List	   *rliststate;

			rliststate = (List *) ExecInitExpr((Expr *) rlist, planstate);
			resultRelInfo->ri_projectReturning = ExecBuildProjectionInfo(rliststate, econtext, slot);
			resultRelInfo++;
		}

		
		foreach(l, planstate->subPlan)
		{
			SubPlanState *sstate = (SubPlanState *) lfirst(l);

			Assert(IsA(sstate, SubPlanState));
			if (sstate->planstate == NULL)		
				ExecInitSubPlan(sstate, estate, eflags);
		}
	}

	queryDesc->tupDesc = tupType;
	queryDesc->planstate = planstate;

	
	if (estate->es_select_into && !(eflags & EXEC_FLAG_EXPLAIN_ONLY))
		OpenIntoRel(queryDesc);
}


static void initResultRelInfo(ResultRelInfo *resultRelInfo, Index resultRelationIndex, List *rangeTable, CmdType operation, bool doInstrument)




{
	Oid			resultRelationOid;
	Relation	resultRelationDesc;

	resultRelationOid = getrelid(resultRelationIndex, rangeTable);
	resultRelationDesc = heap_open(resultRelationOid, RowExclusiveLock);

	switch (resultRelationDesc->rd_rel->relkind)
	{
		case RELKIND_SEQUENCE:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot change sequence \"%s\"", RelationGetRelationName(resultRelationDesc))));


			break;
		case RELKIND_TOASTVALUE:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot change TOAST relation \"%s\"", RelationGetRelationName(resultRelationDesc))));


			break;
		case RELKIND_VIEW:
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot change view \"%s\"", RelationGetRelationName(resultRelationDesc))));


			break;
	}

	MemSet(resultRelInfo, 0, sizeof(ResultRelInfo));
	resultRelInfo->type = T_ResultRelInfo;
	resultRelInfo->ri_RangeTableIndex = resultRelationIndex;
	resultRelInfo->ri_RelationDesc = resultRelationDesc;
	resultRelInfo->ri_NumIndices = 0;
	resultRelInfo->ri_IndexRelationDescs = NULL;
	resultRelInfo->ri_IndexRelationInfo = NULL;
	
	resultRelInfo->ri_TrigDesc = CopyTriggerDesc(resultRelationDesc->trigdesc);
	if (resultRelInfo->ri_TrigDesc)
	{
		int			n = resultRelInfo->ri_TrigDesc->numtriggers;

		resultRelInfo->ri_TrigFunctions = (FmgrInfo *)
			palloc0(n * sizeof(FmgrInfo));
		if (doInstrument)
			resultRelInfo->ri_TrigInstrument = InstrAlloc(n);
		else resultRelInfo->ri_TrigInstrument = NULL;
	}
	else {
		resultRelInfo->ri_TrigFunctions = NULL;
		resultRelInfo->ri_TrigInstrument = NULL;
	}
	resultRelInfo->ri_ConstraintExprs = NULL;
	resultRelInfo->ri_junkFilter = NULL;
	resultRelInfo->ri_projectReturning = NULL;

	
	if (resultRelationDesc->rd_rel->relhasindex && operation != CMD_DELETE)
		ExecOpenIndices(resultRelInfo);
}


bool ExecContextForcesOids(PlanState *planstate, bool *hasoids)
{
	if (planstate->state->es_select_into)
	{
		*hasoids = planstate->state->es_into_oids;
		return true;
	}
	else {
		ResultRelInfo *ri = planstate->state->es_result_relation_info;

		if (ri != NULL)
		{
			Relation	rel = ri->ri_RelationDesc;

			if (rel != NULL)
			{
				*hasoids = rel->rd_rel->relhasoids;
				return true;
			}
		}
	}

	return false;
}


void ExecEndPlan(PlanState *planstate, EState *estate)
{
	ResultRelInfo *resultRelInfo;
	int			i;
	ListCell   *l;

	
	if (estate->es_evalPlanQual != NULL)
		EndEvalPlanQual(estate);

	
	ExecEndNode(planstate);

	
	ExecDropTupleTable(estate->es_tupleTable, true);
	estate->es_tupleTable = NULL;

	
	resultRelInfo = estate->es_result_relations;
	for (i = estate->es_num_result_relations; i > 0; i--)
	{
		
		ExecCloseIndices(resultRelInfo);
		heap_close(resultRelInfo->ri_RelationDesc, NoLock);
		resultRelInfo++;
	}

	
	foreach(l, estate->es_rowMarks)
	{
		ExecRowMark *erm = lfirst(l);

		heap_close(erm->relation, NoLock);
	}
}


static TupleTableSlot * ExecutePlan(EState *estate, PlanState *planstate, CmdType operation, long numberTuples, ScanDirection direction, DestReceiver *dest)





{
	JunkFilter *junkfilter;
	TupleTableSlot *planSlot;
	TupleTableSlot *slot;
	ItemPointer tupleid = NULL;
	ItemPointerData tuple_ctid;
	long		current_tuple_count;
	TupleTableSlot *result;

	
	current_tuple_count = 0;
	result = NULL;

	
	estate->es_direction = direction;

	
	switch (operation)
	{
		case CMD_UPDATE:
			ExecBSUpdateTriggers(estate, estate->es_result_relation_info);
			break;
		case CMD_DELETE:
			ExecBSDeleteTriggers(estate, estate->es_result_relation_info);
			break;
		case CMD_INSERT:
			ExecBSInsertTriggers(estate, estate->es_result_relation_info);
			break;
		default:
			
			break;
	}

	

	for (;;)
	{
		
		ResetPerTupleExprContext(estate);

		
lnext:	;
		if (estate->es_useEvalPlan)
		{
			planSlot = EvalPlanQualNext(estate);
			if (TupIsNull(planSlot))
				planSlot = ExecProcNode(planstate);
		}
		else planSlot = ExecProcNode(planstate);

		
		if (TupIsNull(planSlot))
		{
			result = NULL;
			break;
		}
		slot = planSlot;

		
		if ((junkfilter = estate->es_junkFilter) != NULL)
		{
			Datum		datum;
			bool		isNull;

			
			if (operation == CMD_UPDATE || operation == CMD_DELETE)
			{
				datum = ExecGetJunkAttribute(slot, junkfilter->jf_junkAttNo, &isNull);
				
				if (isNull)
					elog(ERROR, "ctid is NULL");

				tupleid = (ItemPointer) DatumGetPointer(datum);
				tuple_ctid = *tupleid;	
				tupleid = &tuple_ctid;
			}

			
			else if (estate->es_rowMarks != NIL)
			{
				ListCell   *l;

		lmark:	;
				foreach(l, estate->es_rowMarks)
				{
					ExecRowMark *erm = lfirst(l);
					HeapTupleData tuple;
					Buffer		buffer;
					ItemPointerData update_ctid;
					TransactionId update_xmax;
					TupleTableSlot *newSlot;
					LockTupleMode lockmode;
					HTSU_Result test;

					datum = ExecGetJunkAttribute(slot, erm->ctidAttNo, &isNull);

					
					if (isNull)
						elog(ERROR, "ctid is NULL");

					tuple.t_self = *((ItemPointer) DatumGetPointer(datum));

					if (erm->forUpdate)
						lockmode = LockTupleExclusive;
					else lockmode = LockTupleShared;

					test = heap_lock_tuple(erm->relation, &tuple, &buffer, &update_ctid, &update_xmax, estate->es_snapshot->curcid, lockmode, erm->noWait);


					ReleaseBuffer(buffer);
					switch (test)
					{
						case HeapTupleSelfUpdated:
							
							goto lnext;

						case HeapTupleMayBeUpdated:
							break;

						case HeapTupleUpdated:
							if (IsXactIsoLevelSerializable)
								ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("could not serialize access due to concurrent update")));

							if (!ItemPointerEquals(&update_ctid, &tuple.t_self))
							{
								
								newSlot = EvalPlanQual(estate, erm->rti, &update_ctid, update_xmax, estate->es_snapshot->curcid);



								if (!TupIsNull(newSlot))
								{
									slot = planSlot = newSlot;
									estate->es_useEvalPlan = true;
									goto lmark;
								}
							}

							
							goto lnext;

						default:
							elog(ERROR, "unrecognized heap_lock_tuple status: %u", test);
							return NULL;
					}
				}
			}

			
			if (operation != CMD_DELETE)
				slot = ExecFilterJunk(junkfilter, slot);
		}

		
		switch (operation)
		{
			case CMD_SELECT:
				ExecSelect(slot, dest, estate);
				result = slot;
				break;

			case CMD_INSERT:
				ExecInsert(slot, tupleid, planSlot, dest, estate);
				result = NULL;
				break;

			case CMD_DELETE:
				ExecDelete(tupleid, planSlot, dest, estate);
				result = NULL;
				break;

			case CMD_UPDATE:
				ExecUpdate(slot, tupleid, planSlot, dest, estate);
				result = NULL;
				break;

			default:
				elog(ERROR, "unrecognized operation code: %d", (int) operation);
				result = NULL;
				break;
		}

		
		current_tuple_count++;
		if (numberTuples && numberTuples == current_tuple_count)
			break;
	}

	
	switch (operation)
	{
		case CMD_UPDATE:
			ExecASUpdateTriggers(estate, estate->es_result_relation_info);
			break;
		case CMD_DELETE:
			ExecASDeleteTriggers(estate, estate->es_result_relation_info);
			break;
		case CMD_INSERT:
			ExecASInsertTriggers(estate, estate->es_result_relation_info);
			break;
		default:
			
			break;
	}

	
	return result;
}


static void ExecSelect(TupleTableSlot *slot, DestReceiver *dest, EState *estate)


{
	(*dest->receiveSlot) (slot, dest);
	IncrRetrieved();
	(estate->es_processed)++;
}


static void ExecInsert(TupleTableSlot *slot, ItemPointer tupleid, TupleTableSlot *planSlot, DestReceiver *dest, EState *estate)




{
	HeapTuple	tuple;
	ResultRelInfo *resultRelInfo;
	Relation	resultRelationDesc;
	Oid			newId;

	
	tuple = ExecMaterializeSlot(slot);

	
	resultRelInfo = estate->es_result_relation_info;
	resultRelationDesc = resultRelInfo->ri_RelationDesc;

	
	if (resultRelInfo->ri_TrigDesc && resultRelInfo->ri_TrigDesc->n_before_row[TRIGGER_EVENT_INSERT] > 0)
	{
		HeapTuple	newtuple;

		newtuple = ExecBRInsertTriggers(estate, resultRelInfo, tuple);

		if (newtuple == NULL)	
			return;

		if (newtuple != tuple)	
		{
			
			TupleTableSlot *newslot = estate->es_trig_tuple_slot;

			if (newslot->tts_tupleDescriptor != slot->tts_tupleDescriptor)
				ExecSetSlotDescriptor(newslot, slot->tts_tupleDescriptor);
			ExecStoreTuple(newtuple, newslot, InvalidBuffer, false);
			slot = newslot;
			tuple = newtuple;
		}
	}

	
	if (resultRelationDesc->rd_att->constr)
		ExecConstraints(resultRelInfo, slot, estate);

	
	newId = heap_insert(resultRelationDesc, tuple, estate->es_snapshot->curcid, true, true);


	IncrAppended();
	(estate->es_processed)++;
	estate->es_lastoid = newId;
	setLastTid(&(tuple->t_self));

	
	if (resultRelInfo->ri_NumIndices > 0)
		ExecInsertIndexTuples(slot, &(tuple->t_self), estate, false);

	
	ExecARInsertTriggers(estate, resultRelInfo, tuple);

	
	if (resultRelInfo->ri_projectReturning)
		ExecProcessReturning(resultRelInfo->ri_projectReturning, slot, planSlot, dest);
}


static void ExecDelete(ItemPointer tupleid, TupleTableSlot *planSlot, DestReceiver *dest, EState *estate)



{
	ResultRelInfo *resultRelInfo;
	Relation	resultRelationDesc;
	HTSU_Result result;
	ItemPointerData update_ctid;
	TransactionId update_xmax;

	
	resultRelInfo = estate->es_result_relation_info;
	resultRelationDesc = resultRelInfo->ri_RelationDesc;

	
	if (resultRelInfo->ri_TrigDesc && resultRelInfo->ri_TrigDesc->n_before_row[TRIGGER_EVENT_DELETE] > 0)
	{
		bool		dodelete;

		dodelete = ExecBRDeleteTriggers(estate, resultRelInfo, tupleid, estate->es_snapshot->curcid);

		if (!dodelete)			
			return;
	}

	
ldelete:;
	result = heap_delete(resultRelationDesc, tupleid, &update_ctid, &update_xmax, estate->es_snapshot->curcid, estate->es_crosscheck_snapshot, true  );



	switch (result)
	{
		case HeapTupleSelfUpdated:
			
			return;

		case HeapTupleMayBeUpdated:
			break;

		case HeapTupleUpdated:
			if (IsXactIsoLevelSerializable)
				ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("could not serialize access due to concurrent update")));

			else if (!ItemPointerEquals(tupleid, &update_ctid))
			{
				TupleTableSlot *epqslot;

				epqslot = EvalPlanQual(estate, resultRelInfo->ri_RangeTableIndex, &update_ctid, update_xmax, estate->es_snapshot->curcid);



				if (!TupIsNull(epqslot))
				{
					*tupleid = update_ctid;
					goto ldelete;
				}
			}
			
			return;

		default:
			elog(ERROR, "unrecognized heap_delete status: %u", result);
			return;
	}

	IncrDeleted();
	(estate->es_processed)++;

	

	
	ExecARDeleteTriggers(estate, resultRelInfo, tupleid);

	
	if (resultRelInfo->ri_projectReturning)
	{
		
		TupleTableSlot *slot = estate->es_trig_tuple_slot;
		HeapTupleData deltuple;
		Buffer		delbuffer;

		deltuple.t_self = *tupleid;
		if (!heap_fetch(resultRelationDesc, SnapshotAny, &deltuple, &delbuffer, false, NULL))
			elog(ERROR, "failed to fetch deleted tuple for DELETE RETURNING");

		if (slot->tts_tupleDescriptor != RelationGetDescr(resultRelationDesc))
			ExecSetSlotDescriptor(slot, RelationGetDescr(resultRelationDesc));
		ExecStoreTuple(&deltuple, slot, InvalidBuffer, false);

		ExecProcessReturning(resultRelInfo->ri_projectReturning, slot, planSlot, dest);

		ExecClearTuple(slot);
		ReleaseBuffer(delbuffer);
	}
}


static void ExecUpdate(TupleTableSlot *slot, ItemPointer tupleid, TupleTableSlot *planSlot, DestReceiver *dest, EState *estate)




{
	HeapTuple	tuple;
	ResultRelInfo *resultRelInfo;
	Relation	resultRelationDesc;
	HTSU_Result result;
	ItemPointerData update_ctid;
	TransactionId update_xmax;

	
	if (IsBootstrapProcessingMode())
		elog(ERROR, "cannot UPDATE during bootstrap");

	
	tuple = ExecMaterializeSlot(slot);

	
	resultRelInfo = estate->es_result_relation_info;
	resultRelationDesc = resultRelInfo->ri_RelationDesc;

	
	if (resultRelInfo->ri_TrigDesc && resultRelInfo->ri_TrigDesc->n_before_row[TRIGGER_EVENT_UPDATE] > 0)
	{
		HeapTuple	newtuple;

		newtuple = ExecBRUpdateTriggers(estate, resultRelInfo, tupleid, tuple, estate->es_snapshot->curcid);


		if (newtuple == NULL)	
			return;

		if (newtuple != tuple)	
		{
			
			TupleTableSlot *newslot = estate->es_trig_tuple_slot;

			if (newslot->tts_tupleDescriptor != slot->tts_tupleDescriptor)
				ExecSetSlotDescriptor(newslot, slot->tts_tupleDescriptor);
			ExecStoreTuple(newtuple, newslot, InvalidBuffer, false);
			slot = newslot;
			tuple = newtuple;
		}
	}

	
lreplace:;
	if (resultRelationDesc->rd_att->constr)
		ExecConstraints(resultRelInfo, slot, estate);

	
	result = heap_update(resultRelationDesc, tupleid, tuple, &update_ctid, &update_xmax, estate->es_snapshot->curcid, estate->es_crosscheck_snapshot, true  );



	switch (result)
	{
		case HeapTupleSelfUpdated:
			
			return;

		case HeapTupleMayBeUpdated:
			break;

		case HeapTupleUpdated:
			if (IsXactIsoLevelSerializable)
				ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("could not serialize access due to concurrent update")));

			else if (!ItemPointerEquals(tupleid, &update_ctid))
			{
				TupleTableSlot *epqslot;

				epqslot = EvalPlanQual(estate, resultRelInfo->ri_RangeTableIndex, &update_ctid, update_xmax, estate->es_snapshot->curcid);



				if (!TupIsNull(epqslot))
				{
					*tupleid = update_ctid;
					slot = ExecFilterJunk(estate->es_junkFilter, epqslot);
					tuple = ExecMaterializeSlot(slot);
					goto lreplace;
				}
			}
			
			return;

		default:
			elog(ERROR, "unrecognized heap_update status: %u", result);
			return;
	}

	IncrReplaced();
	(estate->es_processed)++;

	

	
	if (resultRelInfo->ri_NumIndices > 0)
		ExecInsertIndexTuples(slot, &(tuple->t_self), estate, false);

	
	ExecARUpdateTriggers(estate, resultRelInfo, tupleid, tuple);

	
	if (resultRelInfo->ri_projectReturning)
		ExecProcessReturning(resultRelInfo->ri_projectReturning, slot, planSlot, dest);
}


static const char * ExecRelCheck(ResultRelInfo *resultRelInfo, TupleTableSlot *slot, EState *estate)

{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	int			ncheck = rel->rd_att->constr->num_check;
	ConstrCheck *check = rel->rd_att->constr->check;
	ExprContext *econtext;
	MemoryContext oldContext;
	List	   *qual;
	int			i;

	
	if (resultRelInfo->ri_ConstraintExprs == NULL)
	{
		oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
		resultRelInfo->ri_ConstraintExprs = (List **) palloc(ncheck * sizeof(List *));
		for (i = 0; i < ncheck; i++)
		{
			
			qual = make_ands_implicit(stringToNode(check[i].ccbin));
			resultRelInfo->ri_ConstraintExprs[i] = (List *)
				ExecPrepareExpr((Expr *) qual, estate);
		}
		MemoryContextSwitchTo(oldContext);
	}

	
	econtext = GetPerTupleExprContext(estate);

	
	econtext->ecxt_scantuple = slot;

	
	for (i = 0; i < ncheck; i++)
	{
		qual = resultRelInfo->ri_ConstraintExprs[i];

		
		if (!ExecQual(qual, econtext, true))
			return check[i].ccname;
	}

	
	return NULL;
}

void ExecConstraints(ResultRelInfo *resultRelInfo, TupleTableSlot *slot, EState *estate)

{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	TupleConstr *constr = rel->rd_att->constr;

	Assert(constr);

	if (constr->has_not_null)
	{
		int			natts = rel->rd_att->natts;
		int			attrChk;

		for (attrChk = 1; attrChk <= natts; attrChk++)
		{
			if (rel->rd_att->attrs[attrChk - 1]->attnotnull && slot_attisnull(slot, attrChk))
				ereport(ERROR, (errcode(ERRCODE_NOT_NULL_VIOLATION), errmsg("null value in column \"%s\" violates not-null constraint", NameStr(rel->rd_att->attrs[attrChk - 1]->attname))));


		}
	}

	if (constr->num_check > 0)
	{
		const char *failed;

		if ((failed = ExecRelCheck(resultRelInfo, slot, estate)) != NULL)
			ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("new row for relation \"%s\" violates check constraint \"%s\"", RelationGetRelationName(rel), failed)));


	}
}


static void ExecProcessReturning(ProjectionInfo *projectReturning, TupleTableSlot *tupleSlot, TupleTableSlot *planSlot, DestReceiver *dest)



{
	ExprContext *econtext = projectReturning->pi_exprContext;
	TupleTableSlot *retSlot;

	
	ResetExprContext(econtext);

	
	econtext->ecxt_scantuple = tupleSlot;
	econtext->ecxt_outertuple = planSlot;

	
	retSlot = ExecProject(projectReturning, NULL);

	
	(*dest->receiveSlot) (retSlot, dest);

	ExecClearTuple(retSlot);
}


TupleTableSlot * EvalPlanQual(EState *estate, Index rti, ItemPointer tid, TransactionId priorXmax, CommandId curCid)

{
	evalPlanQual *epq;
	EState	   *epqstate;
	Relation	relation;
	HeapTupleData tuple;
	HeapTuple	copyTuple = NULL;
	bool		endNode;

	Assert(rti != 0);

	
	if (estate->es_result_relation_info != NULL && estate->es_result_relation_info->ri_RangeTableIndex == rti)
		relation = estate->es_result_relation_info->ri_RelationDesc;
	else {
		ListCell   *l;

		relation = NULL;
		foreach(l, estate->es_rowMarks)
		{
			if (((ExecRowMark *) lfirst(l))->rti == rti)
			{
				relation = ((ExecRowMark *) lfirst(l))->relation;
				break;
			}
		}
		if (relation == NULL)
			elog(ERROR, "could not find RowMark for RT index %u", rti);
	}

	
	tuple.t_self = *tid;
	for (;;)
	{
		Buffer		buffer;

		if (heap_fetch(relation, SnapshotDirty, &tuple, &buffer, true, NULL))
		{
			
			if (!TransactionIdEquals(HeapTupleHeaderGetXmin(tuple.t_data), priorXmax))
			{
				ReleaseBuffer(buffer);
				return NULL;
			}

			
			if (TransactionIdIsValid(SnapshotDirty->xmin))
				elog(ERROR, "t_xmin is uncommitted in tuple to be updated");

			
			if (TransactionIdIsValid(SnapshotDirty->xmax))
			{
				ReleaseBuffer(buffer);
				XactLockTableWait(SnapshotDirty->xmax);
				continue;		
			}

			
			if (TransactionIdIsCurrentTransactionId(priorXmax) && HeapTupleHeaderGetCmin(tuple.t_data) >= curCid)
			{
				ReleaseBuffer(buffer);
				return NULL;
			}

			
			copyTuple = heap_copytuple(&tuple);
			ReleaseBuffer(buffer);
			break;
		}

		
		if (tuple.t_data == NULL)
		{
			ReleaseBuffer(buffer);
			return NULL;
		}

		
		if (!TransactionIdEquals(HeapTupleHeaderGetXmin(tuple.t_data), priorXmax))
		{
			ReleaseBuffer(buffer);
			return NULL;
		}

		
		if (ItemPointerEquals(&tuple.t_self, &tuple.t_data->t_ctid))
		{
			
			ReleaseBuffer(buffer);
			return NULL;
		}

		
		tuple.t_self = tuple.t_data->t_ctid;
		
		priorXmax = HeapTupleHeaderGetXmax(tuple.t_data);
		ReleaseBuffer(buffer);
		
	}

	
	*tid = tuple.t_self;

	
	epq = estate->es_evalPlanQual;
	endNode = true;

	if (epq != NULL && epq->rti == 0)
	{
		
		Assert(!(estate->es_useEvalPlan) && epq->next == NULL);
		epq->rti = rti;
		endNode = false;
	}

	
	if (epq != NULL && epq->rti != rti && epq->estate->es_evTuple[rti - 1] != NULL)
	{
		do {
			evalPlanQual *oldepq;

			
			EvalPlanQualStop(epq);
			
			oldepq = epq->next;
			Assert(oldepq && oldepq->rti != 0);
			
			oldepq->free = epq;
			epq = oldepq;
			estate->es_evalPlanQual = epq;
		} while (epq->rti != rti);
	}

	
	if (epq == NULL || epq->rti != rti)
	{
		
		evalPlanQual *newepq = (epq != NULL) ? epq->free : NULL;

		if (newepq == NULL)		
		{
			newepq = (evalPlanQual *) palloc0(sizeof(evalPlanQual));
			newepq->free = NULL;
			newepq->estate = NULL;
			newepq->planstate = NULL;
		}
		else {
			
			Assert(newepq->estate == NULL);
			epq->free = NULL;
		}
		
		newepq->next = epq;
		epq = newepq;
		estate->es_evalPlanQual = epq;
		epq->rti = rti;
		endNode = false;
	}

	Assert(epq->rti == rti);

	
	if (endNode)
	{
		
		EvalPlanQualStop(epq);
	}

	
	EvalPlanQualStart(epq, estate, epq->next);

	
	epqstate = epq->estate;
	if (epqstate->es_evTuple[rti - 1] != NULL)
		heap_freetuple(epqstate->es_evTuple[rti - 1]);
	epqstate->es_evTuple[rti - 1] = copyTuple;

	return EvalPlanQualNext(estate);
}

static TupleTableSlot * EvalPlanQualNext(EState *estate)
{
	evalPlanQual *epq = estate->es_evalPlanQual;
	MemoryContext oldcontext;
	TupleTableSlot *slot;

	Assert(epq->rti != 0);

lpqnext:;
	oldcontext = MemoryContextSwitchTo(epq->estate->es_query_cxt);
	slot = ExecProcNode(epq->planstate);
	MemoryContextSwitchTo(oldcontext);

	
	if (TupIsNull(slot))
	{
		evalPlanQual *oldepq;

		
		EvalPlanQualStop(epq);
		
		oldepq = epq->next;
		if (oldepq == NULL)
		{
			
			epq->rti = 0;
			estate->es_useEvalPlan = false;
			
			return NULL;
		}
		Assert(oldepq->rti != 0);
		
		oldepq->free = epq;
		epq = oldepq;
		estate->es_evalPlanQual = epq;
		goto lpqnext;
	}

	return slot;
}

static void EndEvalPlanQual(EState *estate)
{
	evalPlanQual *epq = estate->es_evalPlanQual;

	if (epq->rti == 0)			
	{
		Assert(epq->next == NULL);
		return;
	}

	for (;;)
	{
		evalPlanQual *oldepq;

		
		EvalPlanQualStop(epq);
		
		oldepq = epq->next;
		if (oldepq == NULL)
		{
			
			epq->rti = 0;
			estate->es_useEvalPlan = false;
			break;
		}
		Assert(oldepq->rti != 0);
		
		oldepq->free = epq;
		epq = oldepq;
		estate->es_evalPlanQual = epq;
	}
}


static void EvalPlanQualStart(evalPlanQual *epq, EState *estate, evalPlanQual *priorepq)
{
	EState	   *epqstate;
	int			rtsize;
	MemoryContext oldcontext;

	rtsize = list_length(estate->es_range_table);

	
	epq->estate = epqstate = CreateExecutorState();

	oldcontext = MemoryContextSwitchTo(epqstate->es_query_cxt);

	
	epqstate->es_direction = ForwardScanDirection;
	epqstate->es_snapshot = estate->es_snapshot;
	epqstate->es_crosscheck_snapshot = estate->es_crosscheck_snapshot;
	epqstate->es_range_table = estate->es_range_table;
	epqstate->es_result_relations = estate->es_result_relations;
	epqstate->es_num_result_relations = estate->es_num_result_relations;
	epqstate->es_result_relation_info = estate->es_result_relation_info;
	epqstate->es_junkFilter = estate->es_junkFilter;
	epqstate->es_into_relation_descriptor = estate->es_into_relation_descriptor;
	epqstate->es_into_relation_use_wal = estate->es_into_relation_use_wal;
	epqstate->es_param_list_info = estate->es_param_list_info;
	if (estate->es_topPlan->nParamExec > 0)
		epqstate->es_param_exec_vals = (ParamExecData *)
			palloc0(estate->es_topPlan->nParamExec * sizeof(ParamExecData));
	epqstate->es_rowMarks = estate->es_rowMarks;
	epqstate->es_instrument = estate->es_instrument;
	epqstate->es_select_into = estate->es_select_into;
	epqstate->es_into_oids = estate->es_into_oids;
	epqstate->es_topPlan = estate->es_topPlan;

	
	epqstate->es_evTupleNull = (bool *) palloc0(rtsize * sizeof(bool));
	if (priorepq == NULL)
		
		epqstate->es_evTuple = (HeapTuple *)
			palloc0(rtsize * sizeof(HeapTuple));
	else  epqstate->es_evTuple = priorepq->estate->es_evTuple;


	epqstate->es_tupleTable = ExecCreateTupleTable(estate->es_tupleTable->size);

	epq->planstate = ExecInitNode(estate->es_topPlan, epqstate, 0);

	MemoryContextSwitchTo(oldcontext);
}


static void EvalPlanQualStop(evalPlanQual *epq)
{
	EState	   *epqstate = epq->estate;
	MemoryContext oldcontext;

	oldcontext = MemoryContextSwitchTo(epqstate->es_query_cxt);

	ExecEndNode(epq->planstate);

	ExecDropTupleTable(epqstate->es_tupleTable, true);
	epqstate->es_tupleTable = NULL;

	if (epqstate->es_evTuple[epq->rti - 1] != NULL)
	{
		heap_freetuple(epqstate->es_evTuple[epq->rti - 1]);
		epqstate->es_evTuple[epq->rti - 1] = NULL;
	}

	MemoryContextSwitchTo(oldcontext);

	FreeExecutorState(epqstate);

	epq->estate = NULL;
	epq->planstate = NULL;
}




typedef struct {
	DestReceiver pub;			
	EState	   *estate;			
} DR_intorel;


static void OpenIntoRel(QueryDesc *queryDesc)
{
	Query	   *parseTree = queryDesc->parsetree;
	EState	   *estate = queryDesc->estate;
	Relation	intoRelationDesc;
	char	   *intoName;
	Oid			namespaceId;
	Oid			tablespaceId;
	Datum		reloptions;
	AclResult	aclresult;
	Oid			intoRelationId;
	TupleDesc	tupdesc;
	DR_intorel *myState;

	
	if (parseTree->intoOnCommit != ONCOMMIT_NOOP && !parseTree->into->istemp)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("ON COMMIT can only be used on temporary tables")));


	
	intoName = parseTree->into->relname;
	namespaceId = RangeVarGetCreationNamespace(parseTree->into);

	aclresult = pg_namespace_aclcheck(namespaceId, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(namespaceId));

	
	if (parseTree->intoTableSpaceName)
	{
		tablespaceId = get_tablespace_oid(parseTree->intoTableSpaceName);
		if (!OidIsValid(tablespaceId))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("tablespace \"%s\" does not exist", parseTree->intoTableSpaceName)));


	}
	else if (parseTree->into->istemp)
	{
		tablespaceId = GetTempTablespace();
	}
	else {
		tablespaceId = GetDefaultTablespace();
		
	}

	
	if (OidIsValid(tablespaceId))
	{
		AclResult	aclresult;

		aclresult = pg_tablespace_aclcheck(tablespaceId, GetUserId(), ACL_CREATE);

		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE, get_tablespace_name(tablespaceId));
	}

	
	reloptions = transformRelOptions((Datum) 0, parseTree->intoOptions, true, false);


	(void) heap_reloptions(RELKIND_RELATION, reloptions, true);

	
	tupdesc = CreateTupleDescCopy(queryDesc->tupDesc);

	
	intoRelationId = heap_create_with_catalog(intoName, namespaceId, tablespaceId, InvalidOid, GetUserId(), tupdesc, RELKIND_RELATION, false, true, 0, parseTree->intoOnCommit, reloptions, allowSystemTableMods);












	FreeTupleDesc(tupdesc);

	
	CommandCounterIncrement();

	
	AlterTableCreateToastTable(intoRelationId);

	
	intoRelationDesc = heap_open(intoRelationId, AccessExclusiveLock);

	
	Assert(intoRelationDesc->rd_targblock == InvalidBlockNumber);

	
	estate->es_into_relation_use_wal = XLogArchivingActive();
	estate->es_into_relation_descriptor = intoRelationDesc;

	
	queryDesc->dest = CreateDestReceiver(DestIntoRel, NULL);
	myState = (DR_intorel *) queryDesc->dest;
	Assert(myState->pub.mydest == DestIntoRel);
	myState->estate = estate;
}


static void CloseIntoRel(QueryDesc *queryDesc)
{
	EState	   *estate = queryDesc->estate;

	
	if (estate->es_into_relation_descriptor)
	{
		
		if (!estate->es_into_relation_use_wal && !estate->es_into_relation_descriptor->rd_istemp)
			heap_sync(estate->es_into_relation_descriptor);

		
		heap_close(estate->es_into_relation_descriptor, NoLock);

		estate->es_into_relation_descriptor = NULL;
	}
}


DestReceiver * CreateIntoRelDestReceiver(void)
{
	DR_intorel *self = (DR_intorel *) palloc(sizeof(DR_intorel));

	self->pub.receiveSlot = intorel_receive;
	self->pub.rStartup = intorel_startup;
	self->pub.rShutdown = intorel_shutdown;
	self->pub.rDestroy = intorel_destroy;
	self->pub.mydest = DestIntoRel;

	self->estate = NULL;

	return (DestReceiver *) self;
}


static void intorel_startup(DestReceiver *self, int operation, TupleDesc typeinfo)
{
	
}


static void intorel_receive(TupleTableSlot *slot, DestReceiver *self)
{
	DR_intorel *myState = (DR_intorel *) self;
	EState	   *estate = myState->estate;
	HeapTuple	tuple;

	tuple = ExecCopySlotTuple(slot);

	heap_insert(estate->es_into_relation_descriptor, tuple, estate->es_snapshot->curcid, estate->es_into_relation_use_wal, false);




	

	heap_freetuple(tuple);

	IncrAppended();
}


static void intorel_shutdown(DestReceiver *self)
{
	
}


static void intorel_destroy(DestReceiver *self)
{
	pfree(self);
}
