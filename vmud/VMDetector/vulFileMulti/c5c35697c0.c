















static Datum ExecHashSubPlan(SubPlanState *node, ExprContext *econtext, bool *isNull);

static Datum ExecScanSubPlan(SubPlanState *node, ExprContext *econtext, bool *isNull);

static void buildSubPlanHash(SubPlanState *node);
static bool findPartialMatch(TupleHashTable hashtable, TupleTableSlot *slot);
static bool slotAllNulls(TupleTableSlot *slot);
static bool slotNoNulls(TupleTableSlot *slot);



Datum ExecSubPlan(SubPlanState *node, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;

	
	*isNull = false;
	if (isDone)
		*isDone = ExprSingleResult;

	if (subplan->setParam != NIL)
		elog(ERROR, "cannot set parent params from subquery");

	if (subplan->useHashTable)
		return ExecHashSubPlan(node, econtext, isNull);
	else return ExecScanSubPlan(node, econtext, isNull);
}


static Datum ExecHashSubPlan(SubPlanState *node, ExprContext *econtext, bool *isNull)


{
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;
	PlanState  *planstate = node->planstate;
	ExprContext *innerecontext = node->innerecontext;
	TupleTableSlot *slot;

	
	if (subplan->parParam != NIL || node->args != NIL)
		elog(ERROR, "hashed subplan with direct correlation not supported");

	
	if (node->hashtable == NULL || planstate->chgParam != NULL)
		buildSubPlanHash(node);

	
	*isNull = false;
	if (!node->havehashrows && !node->havenullrows)
		return BoolGetDatum(false);

	
	node->projLeft->pi_exprContext = econtext;
	slot = ExecProject(node->projLeft, NULL);

	

	
	ResetExprContext(innerecontext);

	
	if (slotNoNulls(slot))
	{
		if (node->havehashrows && LookupTupleHashEntry(node->hashtable, slot, NULL) != NULL)
		{
			ExecClearTuple(slot);
			return BoolGetDatum(true);
		}
		if (node->havenullrows && findPartialMatch(node->hashnulls, slot))
		{
			ExecClearTuple(slot);
			*isNull = true;
			return BoolGetDatum(false);
		}
		ExecClearTuple(slot);
		return BoolGetDatum(false);
	}

	
	if (node->hashnulls == NULL)
	{
		ExecClearTuple(slot);
		return BoolGetDatum(false);
	}
	if (slotAllNulls(slot))
	{
		ExecClearTuple(slot);
		*isNull = true;
		return BoolGetDatum(false);
	}
	
	if (node->havenullrows && findPartialMatch(node->hashnulls, slot))
	{
		ExecClearTuple(slot);
		*isNull = true;
		return BoolGetDatum(false);
	}
	if (node->havehashrows && findPartialMatch(node->hashtable, slot))
	{
		ExecClearTuple(slot);
		*isNull = true;
		return BoolGetDatum(false);
	}
	ExecClearTuple(slot);
	return BoolGetDatum(false);
}


static Datum ExecScanSubPlan(SubPlanState *node, ExprContext *econtext, bool *isNull)


{
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;
	PlanState  *planstate = node->planstate;
	SubLinkType subLinkType = subplan->subLinkType;
	MemoryContext oldcontext;
	TupleTableSlot *slot;
	Datum		result;
	bool		found = false;	
	ListCell   *pvar;
	ListCell   *l;
	ArrayBuildState *astate = NULL;

	
	oldcontext = MemoryContextSwitchTo(node->sub_estate->es_query_cxt);

	
	Assert(list_length(subplan->parParam) == list_length(node->args));

	forboth(l, subplan->parParam, pvar, node->args)
	{
		int			paramid = lfirst_int(l);
		ParamExecData *prm = &(econtext->ecxt_param_exec_vals[paramid]);

		prm->value = ExecEvalExprSwitchContext((ExprState *) lfirst(pvar), econtext, &(prm->isnull), NULL);


		planstate->chgParam = bms_add_member(planstate->chgParam, paramid);
	}

	ExecReScan(planstate, NULL);

	
	result = BoolGetDatum(subLinkType == ALL_SUBLINK);
	*isNull = false;

	for (slot = ExecProcNode(planstate);
		 !TupIsNull(slot);
		 slot = ExecProcNode(planstate))
	{
		TupleDesc	tdesc = slot->tts_tupleDescriptor;
		Datum		rowresult;
		bool		rownull;
		int			col;
		ListCell   *plst;

		if (subLinkType == EXISTS_SUBLINK)
		{
			found = true;
			result = BoolGetDatum(true);
			break;
		}

		if (subLinkType == EXPR_SUBLINK)
		{
			
			if (found)
				ereport(ERROR, (errcode(ERRCODE_CARDINALITY_VIOLATION), errmsg("more than one row returned by a subquery used as an expression")));

			found = true;

			
			MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
			if (node->curTuple)
				heap_freetuple(node->curTuple);
			node->curTuple = ExecCopySlotTuple(slot);
			MemoryContextSwitchTo(node->sub_estate->es_query_cxt);

			result = heap_getattr(node->curTuple, 1, tdesc, isNull);
			
			continue;
		}

		if (subLinkType == ARRAY_SUBLINK)
		{
			Datum		dvalue;
			bool		disnull;

			found = true;
			
			dvalue = slot_getattr(slot, 1, &disnull);
			astate = accumArrayResult(astate, dvalue, disnull, tdesc->attrs[0]->atttypid, oldcontext);

			
			continue;
		}

		
		if (subLinkType == ROWCOMPARE_SUBLINK && found)
			ereport(ERROR, (errcode(ERRCODE_CARDINALITY_VIOLATION), errmsg("more than one row returned by a subquery used as an expression")));


		found = true;

		
		col = 1;
		foreach(plst, subplan->paramIds)
		{
			int			paramid = lfirst_int(plst);
			ParamExecData *prmdata;

			prmdata = &(econtext->ecxt_param_exec_vals[paramid]);
			Assert(prmdata->execPlan == NULL);
			prmdata->value = slot_getattr(slot, col, &(prmdata->isnull));
			col++;
		}

		rowresult = ExecEvalExprSwitchContext(node->testexpr, econtext, &rownull, NULL);

		if (subLinkType == ANY_SUBLINK)
		{
			
			if (rownull)
				*isNull = true;
			else if (DatumGetBool(rowresult))
			{
				result = BoolGetDatum(true);
				*isNull = false;
				break;			
			}
		}
		else if (subLinkType == ALL_SUBLINK)
		{
			
			if (rownull)
				*isNull = true;
			else if (!DatumGetBool(rowresult))
			{
				result = BoolGetDatum(false);
				*isNull = false;
				break;			
			}
		}
		else {
			
			result = rowresult;
			*isNull = rownull;
		}
	}

	if (!found)
	{
		
		if (subLinkType == EXPR_SUBLINK || subLinkType == ARRAY_SUBLINK || subLinkType == ROWCOMPARE_SUBLINK)

		{
			result = (Datum) 0;
			*isNull = true;
		}
	}
	else if (subLinkType == ARRAY_SUBLINK)
	{
		Assert(astate != NULL);
		
		result = makeArrayResult(astate, oldcontext);
	}

	MemoryContextSwitchTo(oldcontext);

	return result;
}


static void buildSubPlanHash(SubPlanState *node)
{
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;
	PlanState  *planstate = node->planstate;
	int			ncols = list_length(subplan->paramIds);
	ExprContext *innerecontext = node->innerecontext;
	MemoryContext tempcxt = innerecontext->ecxt_per_tuple_memory;
	MemoryContext oldcontext;
	int			nbuckets;
	TupleTableSlot *slot;

	Assert(subplan->subLinkType == ANY_SUBLINK);

	
	MemoryContextReset(node->tablecxt);
	node->hashtable = NULL;
	node->hashnulls = NULL;
	node->havehashrows = false;
	node->havenullrows = false;

	nbuckets = (int) ceil(planstate->plan->plan_rows);
	if (nbuckets < 1)
		nbuckets = 1;

	node->hashtable = BuildTupleHashTable(ncols, node->keyColIdx, node->eqfunctions, node->hashfunctions, nbuckets, sizeof(TupleHashEntryData), node->tablecxt, tempcxt);







	if (!subplan->unknownEqFalse)
	{
		if (ncols == 1)
			nbuckets = 1;		
		else {
			nbuckets /= 16;
			if (nbuckets < 1)
				nbuckets = 1;
		}
		node->hashnulls = BuildTupleHashTable(ncols, node->keyColIdx, node->eqfunctions, node->hashfunctions, nbuckets, sizeof(TupleHashEntryData), node->tablecxt, tempcxt);






	}

	
	oldcontext = MemoryContextSwitchTo(node->sub_estate->es_query_cxt);

	
	ExecReScan(planstate, NULL);

	
	for (slot = ExecProcNode(planstate);
		 !TupIsNull(slot);
		 slot = ExecProcNode(planstate))
	{
		int			col = 1;
		ListCell   *plst;
		bool		isnew;

		
		foreach(plst, subplan->paramIds)
		{
			int			paramid = lfirst_int(plst);
			ParamExecData *prmdata;

			prmdata = &(innerecontext->ecxt_param_exec_vals[paramid]);
			Assert(prmdata->execPlan == NULL);
			prmdata->value = slot_getattr(slot, col, &(prmdata->isnull));
			col++;
		}
		slot = ExecProject(node->projRight, NULL);

		
		if (slotNoNulls(slot))
		{
			(void) LookupTupleHashEntry(node->hashtable, slot, &isnew);
			node->havehashrows = true;
		}
		else if (node->hashnulls)
		{
			(void) LookupTupleHashEntry(node->hashnulls, slot, &isnew);
			node->havenullrows = true;
		}

		
		ResetExprContext(innerecontext);
	}

	
	ExecClearTuple(node->projRight->pi_slot);

	MemoryContextSwitchTo(oldcontext);
}


static bool findPartialMatch(TupleHashTable hashtable, TupleTableSlot *slot)
{
	int			numCols = hashtable->numCols;
	AttrNumber *keyColIdx = hashtable->keyColIdx;
	TupleHashIterator hashiter;
	TupleHashEntry entry;

	ResetTupleHashIterator(hashtable, &hashiter);
	while ((entry = ScanTupleHashTable(&hashiter)) != NULL)
	{
		ExecStoreMinimalTuple(entry->firstTuple, hashtable->tableslot, false);
		if (!execTuplesUnequal(hashtable->tableslot, slot, numCols, keyColIdx, hashtable->eqfunctions, hashtable->tempcxt))


			return true;
	}
	return false;
}


static bool slotAllNulls(TupleTableSlot *slot)
{
	int			ncols = slot->tts_tupleDescriptor->natts;
	int			i;

	for (i = 1; i <= ncols; i++)
	{
		if (!slot_attisnull(slot, i))
			return false;
	}
	return true;
}


static bool slotNoNulls(TupleTableSlot *slot)
{
	int			ncols = slot->tts_tupleDescriptor->natts;
	int			i;

	for (i = 1; i <= ncols; i++)
	{
		if (slot_attisnull(slot, i))
			return false;
	}
	return true;
}


void ExecInitSubPlan(SubPlanState *node, EState *estate, int eflags)
{
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;
	EState	   *sp_estate;

	
	ExecCheckRTPerms(subplan->rtable);

	
	node->needShutdown = false;
	node->curTuple = NULL;
	node->projLeft = NULL;
	node->projRight = NULL;
	node->hashtable = NULL;
	node->hashnulls = NULL;
	node->tablecxt = NULL;
	node->innerecontext = NULL;
	node->keyColIdx = NULL;
	node->eqfunctions = NULL;
	node->hashfunctions = NULL;

	
	sp_estate = CreateSubExecutorState(estate);
	node->sub_estate = sp_estate;

	sp_estate->es_range_table = subplan->rtable;
	sp_estate->es_param_list_info = estate->es_param_list_info;
	sp_estate->es_param_exec_vals = estate->es_param_exec_vals;
	sp_estate->es_tupleTable = ExecCreateTupleTable(ExecCountSlotsNode(subplan->plan) + 10);
	sp_estate->es_snapshot = estate->es_snapshot;
	sp_estate->es_crosscheck_snapshot = estate->es_crosscheck_snapshot;
	sp_estate->es_instrument = estate->es_instrument;

	
	eflags &= EXEC_FLAG_EXPLAIN_ONLY;
	if (subplan->parParam == NIL && subplan->setParam == NIL)
		eflags |= EXEC_FLAG_REWIND;

	node->planstate = ExecInitNode(subplan->plan, sp_estate, eflags);

	node->needShutdown = true;	

	
	if (subplan->setParam != NIL)
	{
		ListCell   *lst;

		foreach(lst, subplan->setParam)
		{
			int			paramid = lfirst_int(lst);
			ParamExecData *prm = &(estate->es_param_exec_vals[paramid]);

			prm->execPlan = node;
		}
	}

	
	if (subplan->useHashTable)
	{
		int			ncols, i;
		TupleDesc	tupDesc;
		TupleTable	tupTable;
		TupleTableSlot *slot;
		List	   *oplist, *lefttlist, *righttlist, *leftptlist, *rightptlist;



		ListCell   *l;

		
		node->tablecxt = AllocSetContextCreate(CurrentMemoryContext, "Subplan HashTable Context", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);




		
		node->innerecontext = CreateExprContext(estate);
		
		ncols = list_length(subplan->paramIds);
		node->keyColIdx = (AttrNumber *) palloc(ncols * sizeof(AttrNumber));
		for (i = 0; i < ncols; i++)
			node->keyColIdx[i] = i + 1;

		
		if (IsA(node->testexpr->expr, OpExpr))
		{
			
			oplist = list_make1(node->testexpr);
		}
		else if (and_clause((Node *) node->testexpr->expr))
		{
			
			Assert(IsA(node->testexpr, BoolExprState));
			oplist = ((BoolExprState *) node->testexpr)->args;
		}
		else {
			
			elog(ERROR, "unrecognized testexpr type: %d", (int) nodeTag(node->testexpr->expr));
			oplist = NIL;		
		}
		Assert(list_length(oplist) == ncols);

		lefttlist = righttlist = NIL;
		leftptlist = rightptlist = NIL;
		node->eqfunctions = (FmgrInfo *) palloc(ncols * sizeof(FmgrInfo));
		node->hashfunctions = (FmgrInfo *) palloc(ncols * sizeof(FmgrInfo));
		i = 1;
		foreach(l, oplist)
		{
			FuncExprState *fstate = (FuncExprState *) lfirst(l);
			OpExpr	   *opexpr = (OpExpr *) fstate->xprstate.expr;
			ExprState  *exstate;
			Expr	   *expr;
			TargetEntry *tle;
			GenericExprState *tlestate;
			Oid			left_hashfn;
			Oid			right_hashfn;

			Assert(IsA(fstate, FuncExprState));
			Assert(IsA(opexpr, OpExpr));
			Assert(list_length(fstate->args) == 2);

			
			exstate = (ExprState *) linitial(fstate->args);
			expr = exstate->expr;
			tle = makeTargetEntry(expr, i, NULL, false);


			tlestate = makeNode(GenericExprState);
			tlestate->xprstate.expr = (Expr *) tle;
			tlestate->xprstate.evalfunc = NULL;
			tlestate->arg = exstate;
			lefttlist = lappend(lefttlist, tlestate);
			leftptlist = lappend(leftptlist, tle);

			
			exstate = (ExprState *) lsecond(fstate->args);
			expr = exstate->expr;
			tle = makeTargetEntry(expr, i, NULL, false);


			tlestate = makeNode(GenericExprState);
			tlestate->xprstate.expr = (Expr *) tle;
			tlestate->xprstate.evalfunc = NULL;
			tlestate->arg = exstate;
			righttlist = lappend(righttlist, tlestate);
			rightptlist = lappend(rightptlist, tle);

			
			fmgr_info(opexpr->opfuncid, &node->eqfunctions[i - 1]);
			node->eqfunctions[i - 1].fn_expr = (Node *) opexpr;

			
			if (!get_op_hash_functions(opexpr->opno, &left_hashfn, &right_hashfn))
				elog(ERROR, "could not find hash function for hash operator %u", opexpr->opno);
			
			Assert(left_hashfn == right_hashfn);
			fmgr_info(right_hashfn, &node->hashfunctions[i - 1]);

			i++;
		}

		
		tupTable = ExecCreateTupleTable(2);

		
		tupDesc = ExecTypeFromTL(leftptlist, false);
		slot = ExecAllocTableSlot(tupTable);
		ExecSetSlotDescriptor(slot, tupDesc);
		node->projLeft = ExecBuildProjectionInfo(lefttlist, NULL, slot);


		tupDesc = ExecTypeFromTL(rightptlist, false);
		slot = ExecAllocTableSlot(tupTable);
		ExecSetSlotDescriptor(slot, tupDesc);
		node->projRight = ExecBuildProjectionInfo(righttlist, node->innerecontext, slot);

	}
}


void ExecSetParamPlan(SubPlanState *node, ExprContext *econtext)
{
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;
	PlanState  *planstate = node->planstate;
	SubLinkType subLinkType = subplan->subLinkType;
	MemoryContext oldcontext;
	TupleTableSlot *slot;
	ListCell   *l;
	bool		found = false;
	ArrayBuildState *astate = NULL;

	
	oldcontext = MemoryContextSwitchTo(node->sub_estate->es_query_cxt);

	if (subLinkType == ANY_SUBLINK || subLinkType == ALL_SUBLINK)
		elog(ERROR, "ANY/ALL subselect unsupported as initplan");

	if (planstate->chgParam != NULL)
		ExecReScan(planstate, NULL);

	for (slot = ExecProcNode(planstate);
		 !TupIsNull(slot);
		 slot = ExecProcNode(planstate))
	{
		TupleDesc	tdesc = slot->tts_tupleDescriptor;
		int			i = 1;

		if (subLinkType == EXISTS_SUBLINK)
		{
			
			int			paramid = linitial_int(subplan->setParam);
			ParamExecData *prm = &(econtext->ecxt_param_exec_vals[paramid]);

			prm->execPlan = NULL;
			prm->value = BoolGetDatum(true);
			prm->isnull = false;
			found = true;
			break;
		}

		if (subLinkType == ARRAY_SUBLINK)
		{
			Datum		dvalue;
			bool		disnull;

			found = true;
			
			dvalue = slot_getattr(slot, 1, &disnull);
			astate = accumArrayResult(astate, dvalue, disnull, tdesc->attrs[0]->atttypid, oldcontext);

			
			continue;
		}

		if (found && (subLinkType == EXPR_SUBLINK || subLinkType == ROWCOMPARE_SUBLINK))

			ereport(ERROR, (errcode(ERRCODE_CARDINALITY_VIOLATION), errmsg("more than one row returned by a subquery used as an expression")));


		found = true;

		
		MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
		if (node->curTuple)
			heap_freetuple(node->curTuple);
		node->curTuple = ExecCopySlotTuple(slot);
		MemoryContextSwitchTo(node->sub_estate->es_query_cxt);

		
		foreach(l, subplan->setParam)
		{
			int			paramid = lfirst_int(l);
			ParamExecData *prm = &(econtext->ecxt_param_exec_vals[paramid]);

			prm->execPlan = NULL;
			prm->value = heap_getattr(node->curTuple, i, tdesc, &(prm->isnull));
			i++;
		}
	}

	if (!found)
	{
		if (subLinkType == EXISTS_SUBLINK)
		{
			
			int			paramid = linitial_int(subplan->setParam);
			ParamExecData *prm = &(econtext->ecxt_param_exec_vals[paramid]);

			prm->execPlan = NULL;
			prm->value = BoolGetDatum(false);
			prm->isnull = false;
		}
		else {
			foreach(l, subplan->setParam)
			{
				int			paramid = lfirst_int(l);
				ParamExecData *prm = &(econtext->ecxt_param_exec_vals[paramid]);

				prm->execPlan = NULL;
				prm->value = (Datum) 0;
				prm->isnull = true;
			}
		}
	}
	else if (subLinkType == ARRAY_SUBLINK)
	{
		
		int			paramid = linitial_int(subplan->setParam);
		ParamExecData *prm = &(econtext->ecxt_param_exec_vals[paramid]);

		Assert(astate != NULL);
		prm->execPlan = NULL;
		
		prm->value = makeArrayResult(astate, econtext->ecxt_per_query_memory);
		prm->isnull = false;
	}

	MemoryContextSwitchTo(oldcontext);
}


void ExecEndSubPlan(SubPlanState *node)
{
	if (node->needShutdown)
	{
		ExecEndPlan(node->planstate, node->sub_estate);
		FreeExecutorState(node->sub_estate);
		node->sub_estate = NULL;
		node->planstate = NULL;
		node->needShutdown = false;
	}
}


void ExecReScanSetParamPlan(SubPlanState *node, PlanState *parent)
{
	PlanState  *planstate = node->planstate;
	SubPlan    *subplan = (SubPlan *) node->xprstate.expr;
	EState	   *estate = parent->state;
	ListCell   *l;

	
	if (subplan->parParam != NIL)
		elog(ERROR, "direct correlated subquery unsupported as initplan");
	if (subplan->setParam == NIL)
		elog(ERROR, "setParam list of initplan is empty");
	if (bms_is_empty(planstate->plan->extParam))
		elog(ERROR, "extParam set of initplan is empty");

	

	
	foreach(l, subplan->setParam)
	{
		int			paramid = lfirst_int(l);
		ParamExecData *prm = &(estate->es_param_exec_vals[paramid]);

		prm->execPlan = node;
		parent->chgParam = bms_add_member(parent->chgParam, paramid);
	}
}
