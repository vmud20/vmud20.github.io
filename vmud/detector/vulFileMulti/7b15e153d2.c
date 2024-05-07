














int			NTupleProcessed;
int			NTupleRetrieved;
int			NTupleReplaced;
int			NTupleAppended;
int			NTupleDeleted;
int			NIndexTupleInserted;
int			NIndexTupleProcessed;


static EState *InternalCreateExecutorState(MemoryContext qcontext, bool is_subquery);
static void ShutdownExprContext(ExprContext *econtext);






void ResetTupleCount(void)
{
	NTupleProcessed = 0;
	NTupleRetrieved = 0;
	NTupleAppended = 0;
	NTupleDeleted = 0;
	NTupleReplaced = 0;
	NIndexTupleProcessed = 0;
}




void DisplayTupleCount(FILE *statfp)
{
	if (NTupleProcessed > 0)
		fprintf(statfp, "!\t%d tuple%s processed, ", NTupleProcessed, (NTupleProcessed == 1) ? "" : "s");
	else {
		fprintf(statfp, "!\tno tuples processed.\n");
		return;
	}
	if (NIndexTupleProcessed > 0)
		fprintf(statfp, "%d indextuple%s processed, ", NIndexTupleProcessed, (NIndexTupleProcessed == 1) ? "" : "s");
	if (NIndexTupleInserted > 0)
		fprintf(statfp, "%d indextuple%s inserted, ", NIndexTupleInserted, (NIndexTupleInserted == 1) ? "" : "s");
	if (NTupleRetrieved > 0)
		fprintf(statfp, "%d tuple%s retrieved. ", NTupleRetrieved, (NTupleRetrieved == 1) ? "" : "s");
	if (NTupleAppended > 0)
		fprintf(statfp, "%d tuple%s appended. ", NTupleAppended, (NTupleAppended == 1) ? "" : "s");
	if (NTupleDeleted > 0)
		fprintf(statfp, "%d tuple%s deleted. ", NTupleDeleted, (NTupleDeleted == 1) ? "" : "s");
	if (NTupleReplaced > 0)
		fprintf(statfp, "%d tuple%s replaced. ", NTupleReplaced, (NTupleReplaced == 1) ? "" : "s");
	fprintf(statfp, "\n");
}






EState * CreateExecutorState(void)
{
	MemoryContext qcontext;

	
	qcontext = AllocSetContextCreate(CurrentMemoryContext, "ExecutorState", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);




	return InternalCreateExecutorState(qcontext, false);
}


EState * CreateSubExecutorState(EState *parent_estate)
{
	return InternalCreateExecutorState(parent_estate->es_query_cxt, true);
}


static EState * InternalCreateExecutorState(MemoryContext qcontext, bool is_subquery)
{
	EState	   *estate;
	MemoryContext oldcontext;

	
	oldcontext = MemoryContextSwitchTo(qcontext);

	estate = makeNode(EState);

	
	estate->es_direction = ForwardScanDirection;
	estate->es_snapshot = SnapshotNow;
	estate->es_crosscheck_snapshot = InvalidSnapshot;	
	estate->es_range_table = NIL;

	estate->es_result_relations = NULL;
	estate->es_num_result_relations = 0;
	estate->es_result_relation_info = NULL;

	estate->es_junkFilter = NULL;

	estate->es_trig_tuple_slot = NULL;

	estate->es_into_relation_descriptor = NULL;
	estate->es_into_relation_use_wal = false;

	estate->es_param_list_info = NULL;
	estate->es_param_exec_vals = NULL;

	estate->es_query_cxt = qcontext;

	estate->es_tupleTable = NULL;

	estate->es_processed = 0;
	estate->es_lastoid = InvalidOid;
	estate->es_rowMarks = NIL;

	estate->es_is_subquery = is_subquery;

	estate->es_instrument = false;
	estate->es_select_into = false;
	estate->es_into_oids = false;

	estate->es_exprcontexts = NIL;

	estate->es_per_tuple_exprcontext = NULL;

	estate->es_topPlan = NULL;
	estate->es_evalPlanQual = NULL;
	estate->es_evTupleNull = NULL;
	estate->es_evTuple = NULL;
	estate->es_useEvalPlan = false;

	
	MemoryContextSwitchTo(oldcontext);

	return estate;
}


void FreeExecutorState(EState *estate)
{
	
	while (estate->es_exprcontexts)
	{
		
		FreeExprContext((ExprContext *) linitial(estate->es_exprcontexts));
		
	}

	
	if (!estate->es_is_subquery)
		MemoryContextDelete(estate->es_query_cxt);
}


ExprContext * CreateExprContext(EState *estate)
{
	ExprContext *econtext;
	MemoryContext oldcontext;

	
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	econtext = makeNode(ExprContext);

	
	econtext->ecxt_scantuple = NULL;
	econtext->ecxt_innertuple = NULL;
	econtext->ecxt_outertuple = NULL;

	econtext->ecxt_per_query_memory = estate->es_query_cxt;

	
	econtext->ecxt_per_tuple_memory = AllocSetContextCreate(estate->es_query_cxt, "ExprContext", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);





	econtext->ecxt_param_exec_vals = estate->es_param_exec_vals;
	econtext->ecxt_param_list_info = estate->es_param_list_info;

	econtext->ecxt_aggvalues = NULL;
	econtext->ecxt_aggnulls = NULL;

	econtext->caseValue_datum = (Datum) 0;
	econtext->caseValue_isNull = true;

	econtext->domainValue_datum = (Datum) 0;
	econtext->domainValue_isNull = true;

	econtext->ecxt_estate = estate;

	econtext->ecxt_callbacks = NULL;

	
	estate->es_exprcontexts = lcons(econtext, estate->es_exprcontexts);

	MemoryContextSwitchTo(oldcontext);

	return econtext;
}


ExprContext * CreateStandaloneExprContext(void)
{
	ExprContext *econtext;

	
	econtext = makeNode(ExprContext);

	
	econtext->ecxt_scantuple = NULL;
	econtext->ecxt_innertuple = NULL;
	econtext->ecxt_outertuple = NULL;

	econtext->ecxt_per_query_memory = CurrentMemoryContext;

	
	econtext->ecxt_per_tuple_memory = AllocSetContextCreate(CurrentMemoryContext, "ExprContext", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);





	econtext->ecxt_param_exec_vals = NULL;
	econtext->ecxt_param_list_info = NULL;

	econtext->ecxt_aggvalues = NULL;
	econtext->ecxt_aggnulls = NULL;

	econtext->caseValue_datum = (Datum) 0;
	econtext->caseValue_isNull = true;

	econtext->domainValue_datum = (Datum) 0;
	econtext->domainValue_isNull = true;

	econtext->ecxt_estate = NULL;

	econtext->ecxt_callbacks = NULL;

	return econtext;
}


void FreeExprContext(ExprContext *econtext)
{
	EState	   *estate;

	
	ShutdownExprContext(econtext);
	
	MemoryContextDelete(econtext->ecxt_per_tuple_memory);
	
	estate = econtext->ecxt_estate;
	if (estate)
		estate->es_exprcontexts = list_delete_ptr(estate->es_exprcontexts, econtext);
	
	pfree(econtext);
}


void ReScanExprContext(ExprContext *econtext)
{
	
	ShutdownExprContext(econtext);
	
	MemoryContextReset(econtext->ecxt_per_tuple_memory);
}


ExprContext * MakePerTupleExprContext(EState *estate)
{
	if (estate->es_per_tuple_exprcontext == NULL)
		estate->es_per_tuple_exprcontext = CreateExprContext(estate);

	return estate->es_per_tuple_exprcontext;
}





void ExecAssignExprContext(EState *estate, PlanState *planstate)
{
	planstate->ps_ExprContext = CreateExprContext(estate);
}


void ExecAssignResultType(PlanState *planstate, TupleDesc tupDesc)
{
	TupleTableSlot *slot = planstate->ps_ResultTupleSlot;

	ExecSetSlotDescriptor(slot, tupDesc);
}


void ExecAssignResultTypeFromTL(PlanState *planstate)
{
	bool		hasoid;
	TupleDesc	tupDesc;

	if (ExecContextForcesOids(planstate, &hasoid))
	{
		
	}
	else {
		
		hasoid = false;
	}

	
	tupDesc = ExecTypeFromTL(planstate->plan->targetlist, hasoid);
	ExecAssignResultType(planstate, tupDesc);
}


TupleDesc ExecGetResultType(PlanState *planstate)
{
	TupleTableSlot *slot = planstate->ps_ResultTupleSlot;

	return slot->tts_tupleDescriptor;
}


ProjectionInfo * ExecBuildProjectionInfo(List *targetList, ExprContext *econtext, TupleTableSlot *slot)


{
	ProjectionInfo *projInfo = makeNode(ProjectionInfo);
	int			len;
	bool		isVarList;
	ListCell   *tl;

	len = ExecTargetListLength(targetList);

	projInfo->pi_targetlist = targetList;
	projInfo->pi_exprContext = econtext;
	projInfo->pi_slot = slot;

	
	isVarList = true;
	foreach(tl, targetList)
	{
		GenericExprState *gstate = (GenericExprState *) lfirst(tl);
		Var		   *variable = (Var *) gstate->arg->expr;

		if (variable == NULL || !IsA(variable, Var) || variable->varattno <= 0)

		{
			isVarList = false;
			break;
		}
	}
	projInfo->pi_isVarList = isVarList;

	if (isVarList)
	{
		int		   *varSlotOffsets;
		int		   *varNumbers;
		AttrNumber	lastInnerVar = 0;
		AttrNumber	lastOuterVar = 0;
		AttrNumber	lastScanVar = 0;

		projInfo->pi_itemIsDone = NULL; 
		projInfo->pi_varSlotOffsets = varSlotOffsets = (int *)
			palloc0(len * sizeof(int));
		projInfo->pi_varNumbers = varNumbers = (int *)
			palloc0(len * sizeof(int));

		
		foreach(tl, targetList)
		{
			GenericExprState *gstate = (GenericExprState *) lfirst(tl);
			Var		   *variable = (Var *) gstate->arg->expr;
			AttrNumber	attnum = variable->varattno;
			TargetEntry *tle = (TargetEntry *) gstate->xprstate.expr;
			AttrNumber	resind = tle->resno - 1;

			Assert(resind >= 0 && resind < len);
			varNumbers[resind] = attnum;

			switch (variable->varno)
			{
				case INNER:
					varSlotOffsets[resind] = offsetof(ExprContext, ecxt_innertuple);
					lastInnerVar = Max(lastInnerVar, attnum);
					break;

				case OUTER:
					varSlotOffsets[resind] = offsetof(ExprContext, ecxt_outertuple);
					lastOuterVar = Max(lastOuterVar, attnum);
					break;

				default:
					varSlotOffsets[resind] = offsetof(ExprContext, ecxt_scantuple);
					lastScanVar = Max(lastScanVar, attnum);
					break;
			}
		}
		projInfo->pi_lastInnerVar = lastInnerVar;
		projInfo->pi_lastOuterVar = lastOuterVar;
		projInfo->pi_lastScanVar = lastScanVar;
	}
	else {
		projInfo->pi_itemIsDone = (ExprDoneCond *)
			palloc(len * sizeof(ExprDoneCond));
		projInfo->pi_varSlotOffsets = NULL;
		projInfo->pi_varNumbers = NULL;
	}

	return projInfo;
}


void ExecAssignProjectionInfo(PlanState *planstate)
{
	planstate->ps_ProjInfo = ExecBuildProjectionInfo(planstate->targetlist, planstate->ps_ExprContext, planstate->ps_ResultTupleSlot);


}



void ExecFreeExprContext(PlanState *planstate)
{
	
	planstate->ps_ExprContext = NULL;
}




TupleDesc ExecGetScanType(ScanState *scanstate)
{
	TupleTableSlot *slot = scanstate->ss_ScanTupleSlot;

	return slot->tts_tupleDescriptor;
}


void ExecAssignScanType(ScanState *scanstate, TupleDesc tupDesc)
{
	TupleTableSlot *slot = scanstate->ss_ScanTupleSlot;

	ExecSetSlotDescriptor(slot, tupDesc);
}


void ExecAssignScanTypeFromOuterPlan(ScanState *scanstate)
{
	PlanState  *outerPlan;
	TupleDesc	tupDesc;

	outerPlan = outerPlanState(scanstate);
	tupDesc = ExecGetResultType(outerPlan);

	ExecAssignScanType(scanstate, tupDesc);
}





bool ExecRelationIsTargetRelation(EState *estate, Index scanrelid)
{
	ResultRelInfo *resultRelInfos;
	int			i;

	resultRelInfos = estate->es_result_relations;
	for (i = 0; i < estate->es_num_result_relations; i++)
	{
		if (resultRelInfos[i].ri_RangeTableIndex == scanrelid)
			return true;
	}
	return false;
}


Relation ExecOpenScanRelation(EState *estate, Index scanrelid)
{
	RangeTblEntry *rtentry;
	Oid			reloid;
	LOCKMODE	lockmode;
	ResultRelInfo *resultRelInfos;
	int			i;

	
	lockmode = AccessShareLock;
	resultRelInfos = estate->es_result_relations;
	for (i = 0; i < estate->es_num_result_relations; i++)
	{
		if (resultRelInfos[i].ri_RangeTableIndex == scanrelid)
		{
			lockmode = NoLock;
			break;
		}
	}

	if (lockmode == AccessShareLock)
	{
		ListCell   *l;

		foreach(l, estate->es_rowMarks)
		{
			ExecRowMark *erm = lfirst(l);

			if (erm->rti == scanrelid)
			{
				lockmode = NoLock;
				break;
			}
		}
	}

	
	rtentry = rt_fetch(scanrelid, estate->es_range_table);
	reloid = rtentry->relid;

	return heap_open(reloid, lockmode);
}


void ExecCloseScanRelation(Relation scanrel)
{
	heap_close(scanrel, NoLock);
}





void ExecOpenIndices(ResultRelInfo *resultRelInfo)
{
	Relation	resultRelation = resultRelInfo->ri_RelationDesc;
	List	   *indexoidlist;
	ListCell   *l;
	int			len, i;
	RelationPtr relationDescs;
	IndexInfo **indexInfoArray;

	resultRelInfo->ri_NumIndices = 0;

	
	if (!RelationGetForm(resultRelation)->relhasindex)
		return;

	
	indexoidlist = RelationGetIndexList(resultRelation);
	len = list_length(indexoidlist);
	if (len == 0)
		return;

	
	relationDescs = (RelationPtr) palloc(len * sizeof(Relation));
	indexInfoArray = (IndexInfo **) palloc(len * sizeof(IndexInfo *));

	resultRelInfo->ri_NumIndices = len;
	resultRelInfo->ri_IndexRelationDescs = relationDescs;
	resultRelInfo->ri_IndexRelationInfo = indexInfoArray;

	
	i = 0;
	foreach(l, indexoidlist)
	{
		Oid			indexOid = lfirst_oid(l);
		Relation	indexDesc;
		IndexInfo  *ii;

		indexDesc = index_open(indexOid, RowExclusiveLock);

		
		ii = BuildIndexInfo(indexDesc);

		relationDescs[i] = indexDesc;
		indexInfoArray[i] = ii;
		i++;
	}

	list_free(indexoidlist);
}


void ExecCloseIndices(ResultRelInfo *resultRelInfo)
{
	int			i;
	int			numIndices;
	RelationPtr indexDescs;

	numIndices = resultRelInfo->ri_NumIndices;
	indexDescs = resultRelInfo->ri_IndexRelationDescs;

	for (i = 0; i < numIndices; i++)
	{
		if (indexDescs[i] == NULL)
			continue;			

		
		index_close(indexDescs[i], RowExclusiveLock);
	}

	
}


void ExecInsertIndexTuples(TupleTableSlot *slot, ItemPointer tupleid, EState *estate, bool is_vacuum)



{
	ResultRelInfo *resultRelInfo;
	int			i;
	int			numIndices;
	RelationPtr relationDescs;
	Relation	heapRelation;
	IndexInfo **indexInfoArray;
	ExprContext *econtext;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];

	
	resultRelInfo = estate->es_result_relation_info;
	numIndices = resultRelInfo->ri_NumIndices;
	relationDescs = resultRelInfo->ri_IndexRelationDescs;
	indexInfoArray = resultRelInfo->ri_IndexRelationInfo;
	heapRelation = resultRelInfo->ri_RelationDesc;

	
	econtext = GetPerTupleExprContext(estate);

	
	econtext->ecxt_scantuple = slot;

	
	for (i = 0; i < numIndices; i++)
	{
		IndexInfo  *indexInfo;

		if (relationDescs[i] == NULL)
			continue;

		indexInfo = indexInfoArray[i];

		
		if (indexInfo->ii_Predicate != NIL)
		{
			List	   *predicate;

			
			predicate = indexInfo->ii_PredicateState;
			if (predicate == NIL)
			{
				predicate = (List *)
					ExecPrepareExpr((Expr *) indexInfo->ii_Predicate, estate);
				indexInfo->ii_PredicateState = predicate;
			}

			
			if (!ExecQual(predicate, econtext, false))
				continue;
		}

		
		FormIndexDatum(indexInfo, slot, estate, values, isnull);




		
		index_insert(relationDescs[i],	 values, isnull, tupleid, heapRelation, relationDescs[i]->rd_index->indisunique && !is_vacuum);





		
		IncrIndexInserted();
	}
}


void UpdateChangedParamSet(PlanState *node, Bitmapset *newchg)
{
	Bitmapset  *parmset;

	
	parmset = bms_intersect(node->plan->allParam, newchg);

	
	if (!bms_is_empty(parmset))
		node->chgParam = bms_join(node->chgParam, parmset);
	else bms_free(parmset);
}


void RegisterExprContextCallback(ExprContext *econtext, ExprContextCallbackFunction function, Datum arg)


{
	ExprContext_CB *ecxt_callback;

	
	ecxt_callback = (ExprContext_CB *)
		MemoryContextAlloc(econtext->ecxt_per_query_memory, sizeof(ExprContext_CB));

	ecxt_callback->function = function;
	ecxt_callback->arg = arg;

	
	ecxt_callback->next = econtext->ecxt_callbacks;
	econtext->ecxt_callbacks = ecxt_callback;
}


void UnregisterExprContextCallback(ExprContext *econtext, ExprContextCallbackFunction function, Datum arg)


{
	ExprContext_CB **prev_callback;
	ExprContext_CB *ecxt_callback;

	prev_callback = &econtext->ecxt_callbacks;

	while ((ecxt_callback = *prev_callback) != NULL)
	{
		if (ecxt_callback->function == function && ecxt_callback->arg == arg)
		{
			*prev_callback = ecxt_callback->next;
			pfree(ecxt_callback);
		}
		else prev_callback = &ecxt_callback->next;
	}
}


static void ShutdownExprContext(ExprContext *econtext)
{
	ExprContext_CB *ecxt_callback;
	MemoryContext oldcontext;

	
	if (econtext->ecxt_callbacks == NULL)
		return;

	
	oldcontext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	
	while ((ecxt_callback = econtext->ecxt_callbacks) != NULL)
	{
		econtext->ecxt_callbacks = ecxt_callback->next;
		(*ecxt_callback->function) (ecxt_callback->arg);
		pfree(ecxt_callback);
	}

	MemoryContextSwitchTo(oldcontext);
}
