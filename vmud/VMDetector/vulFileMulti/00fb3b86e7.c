

























typedef struct AggStatePerAggData {
	

	
	AggrefExprState *aggrefstate;
	Aggref	   *aggref;

	
	int			numArguments;

	
	Oid			transfn_oid;
	Oid			finalfn_oid;	

	
	FmgrInfo	transfn;
	FmgrInfo	finalfn;

	
	Oid			inputType;
	Oid			sortOperator;

	
	FmgrInfo	equalfn;

	
	Datum		initValue;
	bool		initValueIsNull;

	
	int16		inputtypeLen, resulttypeLen, transtypeLen;

	bool		inputtypeByVal, resulttypeByVal, transtypeByVal;


	

	Tuplesortstate *sortstate;	
} AggStatePerAggData;


typedef struct AggStatePerGroupData {
	Datum		transValue;		
	bool		transValueIsNull;

	bool		noTransValue;	

	
} AggStatePerGroupData;


typedef struct AggHashEntryData *AggHashEntry;

typedef struct AggHashEntryData {
	TupleHashEntryData shared;	
	
	AggStatePerGroupData pergroup[1];	
} AggHashEntryData;				


static void initialize_aggregates(AggState *aggstate, AggStatePerAgg peragg, AggStatePerGroup pergroup);

static void advance_transition_function(AggState *aggstate, AggStatePerAgg peraggstate, AggStatePerGroup pergroupstate, FunctionCallInfoData *fcinfo);


static void advance_aggregates(AggState *aggstate, AggStatePerGroup pergroup);
static void process_sorted_aggregate(AggState *aggstate, AggStatePerAgg peraggstate, AggStatePerGroup pergroupstate);

static void finalize_aggregate(AggState *aggstate, AggStatePerAgg peraggstate, AggStatePerGroup pergroupstate, Datum *resultVal, bool *resultIsNull);


static Bitmapset *find_unaggregated_cols(AggState *aggstate);
static bool find_unaggregated_cols_walker(Node *node, Bitmapset **colnos);
static void build_hash_table(AggState *aggstate);
static AggHashEntry lookup_hash_entry(AggState *aggstate, TupleTableSlot *inputslot);
static TupleTableSlot *agg_retrieve_direct(AggState *aggstate);
static void agg_fill_hash_table(AggState *aggstate);
static TupleTableSlot *agg_retrieve_hash_table(AggState *aggstate);
static Datum GetAggInitVal(Datum textInitVal, Oid transtype);



static void initialize_aggregates(AggState *aggstate, AggStatePerAgg peragg, AggStatePerGroup pergroup)


{
	int			aggno;

	for (aggno = 0; aggno < aggstate->numaggs; aggno++)
	{
		AggStatePerAgg peraggstate = &peragg[aggno];
		AggStatePerGroup pergroupstate = &pergroup[aggno];
		Aggref	   *aggref = peraggstate->aggref;

		
		if (aggref->aggdistinct)
		{
			
			if (peraggstate->sortstate)
				tuplesort_end(peraggstate->sortstate);

			peraggstate->sortstate = tuplesort_begin_datum(peraggstate->inputType, peraggstate->sortOperator, false, work_mem, false);


		}

		
		if (!peraggstate->transtypeByVal && !pergroupstate->transValueIsNull && DatumGetPointer(pergroupstate->transValue) != NULL)

			pfree(DatumGetPointer(pergroupstate->transValue));

		
		if (peraggstate->initValueIsNull)
			pergroupstate->transValue = peraggstate->initValue;
		else {
			MemoryContext oldContext;

			oldContext = MemoryContextSwitchTo(aggstate->aggcontext);
			pergroupstate->transValue = datumCopy(peraggstate->initValue, peraggstate->transtypeByVal, peraggstate->transtypeLen);

			MemoryContextSwitchTo(oldContext);
		}
		pergroupstate->transValueIsNull = peraggstate->initValueIsNull;

		
		pergroupstate->noTransValue = peraggstate->initValueIsNull;
	}
}


static void advance_transition_function(AggState *aggstate, AggStatePerAgg peraggstate, AggStatePerGroup pergroupstate, FunctionCallInfoData *fcinfo)



{
	int			numArguments = peraggstate->numArguments;
	MemoryContext oldContext;
	Datum		newVal;
	int			i;

	if (peraggstate->transfn.fn_strict)
	{
		
		for (i = 1; i <= numArguments; i++)
		{
			if (fcinfo->argnull[i])
				return;
		}
		if (pergroupstate->noTransValue)
		{
			
			oldContext = MemoryContextSwitchTo(aggstate->aggcontext);
			pergroupstate->transValue = datumCopy(fcinfo->arg[1], peraggstate->transtypeByVal, peraggstate->transtypeLen);

			pergroupstate->transValueIsNull = false;
			pergroupstate->noTransValue = false;
			MemoryContextSwitchTo(oldContext);
			return;
		}
		if (pergroupstate->transValueIsNull)
		{
			
			return;
		}
	}

	
	oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);

	
	InitFunctionCallInfoData(*fcinfo, &(peraggstate->transfn), numArguments + 1, (void *) aggstate, NULL);

	fcinfo->arg[0] = pergroupstate->transValue;
	fcinfo->argnull[0] = pergroupstate->transValueIsNull;

	newVal = FunctionCallInvoke(fcinfo);

	
	if (!peraggstate->transtypeByVal && DatumGetPointer(newVal) != DatumGetPointer(pergroupstate->transValue))
	{
		if (!fcinfo->isnull)
		{
			MemoryContextSwitchTo(aggstate->aggcontext);
			newVal = datumCopy(newVal, peraggstate->transtypeByVal, peraggstate->transtypeLen);

		}
		if (!pergroupstate->transValueIsNull)
			pfree(DatumGetPointer(pergroupstate->transValue));
	}

	pergroupstate->transValue = newVal;
	pergroupstate->transValueIsNull = fcinfo->isnull;

	MemoryContextSwitchTo(oldContext);
}


static void advance_aggregates(AggState *aggstate, AggStatePerGroup pergroup)
{
	ExprContext *econtext = aggstate->tmpcontext;
	int			aggno;

	for (aggno = 0; aggno < aggstate->numaggs; aggno++)
	{
		AggStatePerAgg peraggstate = &aggstate->peragg[aggno];
		AggStatePerGroup pergroupstate = &pergroup[aggno];
		AggrefExprState *aggrefstate = peraggstate->aggrefstate;
		Aggref	   *aggref = peraggstate->aggref;
		FunctionCallInfoData fcinfo;
		int			i;
		ListCell   *arg;
		MemoryContext oldContext;

		
		oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

		
		
		i = 1;
		foreach(arg, aggrefstate->args)
		{
			ExprState  *argstate = (ExprState *) lfirst(arg);

			fcinfo.arg[i] = ExecEvalExpr(argstate, econtext, fcinfo.argnull + i, NULL);
			i++;
		}

		
		MemoryContextSwitchTo(oldContext);

		if (aggref->aggdistinct)
		{
			
			
			if (fcinfo.argnull[1])
				continue;
			tuplesort_putdatum(peraggstate->sortstate, fcinfo.arg[1], fcinfo.argnull[1]);
		}
		else {
			advance_transition_function(aggstate, peraggstate, pergroupstate, &fcinfo);
		}
	}
}


static void process_sorted_aggregate(AggState *aggstate, AggStatePerAgg peraggstate, AggStatePerGroup pergroupstate)


{
	Datum		oldVal = (Datum) 0;
	bool		haveOldVal = false;
	MemoryContext workcontext = aggstate->tmpcontext->ecxt_per_tuple_memory;
	MemoryContext oldContext;
	Datum	   *newVal;
	bool	   *isNull;
	FunctionCallInfoData fcinfo;

	tuplesort_performsort(peraggstate->sortstate);

	newVal = fcinfo.arg + 1;
	isNull = fcinfo.argnull + 1;

	

	while (tuplesort_getdatum(peraggstate->sortstate, true, newVal, isNull))
	{
		
		if (*isNull)
			continue;

		
		MemoryContextReset(workcontext);
		oldContext = MemoryContextSwitchTo(workcontext);

		if (haveOldVal && DatumGetBool(FunctionCall2(&peraggstate->equalfn, oldVal, *newVal)))

		{
			
			if (!peraggstate->inputtypeByVal)
				pfree(DatumGetPointer(*newVal));
		}
		else {
			advance_transition_function(aggstate, peraggstate, pergroupstate, &fcinfo);
			
			if (haveOldVal && !peraggstate->inputtypeByVal)
				pfree(DatumGetPointer(oldVal));
			
			oldVal = *newVal;
			haveOldVal = true;
		}

		MemoryContextSwitchTo(oldContext);
	}

	if (haveOldVal && !peraggstate->inputtypeByVal)
		pfree(DatumGetPointer(oldVal));

	tuplesort_end(peraggstate->sortstate);
	peraggstate->sortstate = NULL;
}


static void finalize_aggregate(AggState *aggstate, AggStatePerAgg peraggstate, AggStatePerGroup pergroupstate, Datum *resultVal, bool *resultIsNull)



{
	MemoryContext oldContext;

	oldContext = MemoryContextSwitchTo(aggstate->ss.ps.ps_ExprContext->ecxt_per_tuple_memory);

	
	if (OidIsValid(peraggstate->finalfn_oid))
	{
		FunctionCallInfoData fcinfo;

		InitFunctionCallInfoData(fcinfo, &(peraggstate->finalfn), 1, (void *) aggstate, NULL);
		fcinfo.arg[0] = pergroupstate->transValue;
		fcinfo.argnull[0] = pergroupstate->transValueIsNull;
		if (fcinfo.flinfo->fn_strict && pergroupstate->transValueIsNull)
		{
			
			*resultVal = (Datum) 0;
			*resultIsNull = true;
		}
		else {
			*resultVal = FunctionCallInvoke(&fcinfo);
			*resultIsNull = fcinfo.isnull;
		}
	}
	else {
		*resultVal = pergroupstate->transValue;
		*resultIsNull = pergroupstate->transValueIsNull;
	}

	
	if (!peraggstate->resulttypeByVal && !*resultIsNull && !MemoryContextContains(CurrentMemoryContext, DatumGetPointer(*resultVal)))

		*resultVal = datumCopy(*resultVal, peraggstate->resulttypeByVal, peraggstate->resulttypeLen);


	MemoryContextSwitchTo(oldContext);
}


static Bitmapset * find_unaggregated_cols(AggState *aggstate)
{
	Agg		   *node = (Agg *) aggstate->ss.ps.plan;
	Bitmapset  *colnos;

	colnos = NULL;
	(void) find_unaggregated_cols_walker((Node *) node->plan.targetlist, &colnos);
	(void) find_unaggregated_cols_walker((Node *) node->plan.qual, &colnos);
	return colnos;
}

static bool find_unaggregated_cols_walker(Node *node, Bitmapset **colnos)
{
	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		Var		   *var = (Var *) node;

		
		Assert(var->varno == 0);
		Assert(var->varlevelsup == 0);
		*colnos = bms_add_member(*colnos, var->varattno);
		return false;
	}
	if (IsA(node, Aggref))		
		return false;
	return expression_tree_walker(node, find_unaggregated_cols_walker, (void *) colnos);
}


static void build_hash_table(AggState *aggstate)
{
	Agg		   *node = (Agg *) aggstate->ss.ps.plan;
	MemoryContext tmpmem = aggstate->tmpcontext->ecxt_per_tuple_memory;
	Size		entrysize;
	Bitmapset  *colnos;
	List	   *collist;
	int			i;

	Assert(node->aggstrategy == AGG_HASHED);
	Assert(node->numGroups > 0);

	entrysize = sizeof(AggHashEntryData) + (aggstate->numaggs - 1) *sizeof(AggStatePerGroupData);

	aggstate->hashtable = BuildTupleHashTable(node->numCols, node->grpColIdx, aggstate->eqfunctions, aggstate->hashfunctions, node->numGroups, entrysize, aggstate->aggcontext, tmpmem);







	

	
	colnos = find_unaggregated_cols(aggstate);
	
	for (i = 0; i < node->numCols; i++)
		colnos = bms_add_member(colnos, node->grpColIdx[i]);
	
	collist = NIL;
	while ((i = bms_first_member(colnos)) >= 0)
		collist = lcons_int(i, collist);
	aggstate->hash_needed = collist;
}


Size hash_agg_entry_size(int numAggs)
{
	Size		entrysize;

	
	entrysize = sizeof(AggHashEntryData) + (numAggs - 1) *sizeof(AggStatePerGroupData);
	entrysize = MAXALIGN(entrysize);
	
	entrysize += 3 * sizeof(void *);
	return entrysize;
}


static AggHashEntry lookup_hash_entry(AggState *aggstate, TupleTableSlot *inputslot)
{
	TupleTableSlot *hashslot = aggstate->hashslot;
	ListCell   *l;
	AggHashEntry entry;
	bool		isnew;

	
	if (hashslot->tts_tupleDescriptor == NULL)
	{
		ExecSetSlotDescriptor(hashslot, inputslot->tts_tupleDescriptor);
		
		ExecStoreAllNullTuple(hashslot);
	}

	
	slot_getsomeattrs(inputslot, linitial_int(aggstate->hash_needed));
	foreach(l, aggstate->hash_needed)
	{
		int			varNumber = lfirst_int(l) - 1;

		hashslot->tts_values[varNumber] = inputslot->tts_values[varNumber];
		hashslot->tts_isnull[varNumber] = inputslot->tts_isnull[varNumber];
	}

	
	entry = (AggHashEntry) LookupTupleHashEntry(aggstate->hashtable, hashslot, &isnew);


	if (isnew)
	{
		
		initialize_aggregates(aggstate, aggstate->peragg, entry->pergroup);
	}

	return entry;
}


TupleTableSlot * ExecAgg(AggState *node)
{
	if (node->agg_done)
		return NULL;

	if (((Agg *) node->ss.ps.plan)->aggstrategy == AGG_HASHED)
	{
		if (!node->table_filled)
			agg_fill_hash_table(node);
		return agg_retrieve_hash_table(node);
	}
	else return agg_retrieve_direct(node);
}


static TupleTableSlot * agg_retrieve_direct(AggState *aggstate)
{
	Agg		   *node = (Agg *) aggstate->ss.ps.plan;
	PlanState  *outerPlan;
	ExprContext *econtext;
	ExprContext *tmpcontext;
	ProjectionInfo *projInfo;
	Datum	   *aggvalues;
	bool	   *aggnulls;
	AggStatePerAgg peragg;
	AggStatePerGroup pergroup;
	TupleTableSlot *outerslot;
	TupleTableSlot *firstSlot;
	int			aggno;

	
	outerPlan = outerPlanState(aggstate);
	
	econtext = aggstate->ss.ps.ps_ExprContext;
	aggvalues = econtext->ecxt_aggvalues;
	aggnulls = econtext->ecxt_aggnulls;
	
	tmpcontext = aggstate->tmpcontext;
	projInfo = aggstate->ss.ps.ps_ProjInfo;
	peragg = aggstate->peragg;
	pergroup = aggstate->pergroup;
	firstSlot = aggstate->ss.ss_ScanTupleSlot;

	
	while (!aggstate->agg_done)
	{
		
		if (aggstate->grp_firstTuple == NULL)
		{
			outerslot = ExecProcNode(outerPlan);
			if (!TupIsNull(outerslot))
			{
				
				aggstate->grp_firstTuple = ExecCopySlotTuple(outerslot);
			}
			else {
				
				aggstate->agg_done = true;
				
				if (node->aggstrategy != AGG_PLAIN)
					return NULL;
			}
		}

		
		ResetExprContext(econtext);

		
		initialize_aggregates(aggstate, peragg, pergroup);

		if (aggstate->grp_firstTuple != NULL)
		{
			
			ExecStoreTuple(aggstate->grp_firstTuple, firstSlot, InvalidBuffer, true);


			aggstate->grp_firstTuple = NULL;	

			
			tmpcontext->ecxt_scantuple = firstSlot;

			
			for (;;)
			{
				advance_aggregates(aggstate, pergroup);

				
				ResetExprContext(tmpcontext);

				outerslot = ExecProcNode(outerPlan);
				if (TupIsNull(outerslot))
				{
					
					aggstate->agg_done = true;
					break;
				}
				
				tmpcontext->ecxt_scantuple = outerslot;

				
				if (node->aggstrategy == AGG_SORTED)
				{
					if (!execTuplesMatch(firstSlot, outerslot, node->numCols, node->grpColIdx, aggstate->eqfunctions, tmpcontext->ecxt_per_tuple_memory))



					{
						
						aggstate->grp_firstTuple = ExecCopySlotTuple(outerslot);
						break;
					}
				}
			}
		}

		
		for (aggno = 0; aggno < aggstate->numaggs; aggno++)
		{
			AggStatePerAgg peraggstate = &peragg[aggno];
			AggStatePerGroup pergroupstate = &pergroup[aggno];

			if (peraggstate->aggref->aggdistinct)
				process_sorted_aggregate(aggstate, peraggstate, pergroupstate);

			finalize_aggregate(aggstate, peraggstate, pergroupstate, &aggvalues[aggno], &aggnulls[aggno]);
		}

		
		econtext->ecxt_scantuple = firstSlot;

		
		if (ExecQual(aggstate->ss.ps.qual, econtext, false))
		{
			
			return ExecProject(projInfo, NULL);
		}
	}

	
	return NULL;
}


static void agg_fill_hash_table(AggState *aggstate)
{
	PlanState  *outerPlan;
	ExprContext *tmpcontext;
	AggHashEntry entry;
	TupleTableSlot *outerslot;

	
	outerPlan = outerPlanState(aggstate);
	
	tmpcontext = aggstate->tmpcontext;

	
	for (;;)
	{
		outerslot = ExecProcNode(outerPlan);
		if (TupIsNull(outerslot))
			break;
		
		tmpcontext->ecxt_scantuple = outerslot;

		
		entry = lookup_hash_entry(aggstate, outerslot);

		
		advance_aggregates(aggstate, entry->pergroup);

		
		ResetExprContext(tmpcontext);
	}

	aggstate->table_filled = true;
	
	ResetTupleHashIterator(aggstate->hashtable, &aggstate->hashiter);
}


static TupleTableSlot * agg_retrieve_hash_table(AggState *aggstate)
{
	ExprContext *econtext;
	ProjectionInfo *projInfo;
	Datum	   *aggvalues;
	bool	   *aggnulls;
	AggStatePerAgg peragg;
	AggStatePerGroup pergroup;
	AggHashEntry entry;
	TupleTableSlot *firstSlot;
	int			aggno;

	
	
	econtext = aggstate->ss.ps.ps_ExprContext;
	aggvalues = econtext->ecxt_aggvalues;
	aggnulls = econtext->ecxt_aggnulls;
	projInfo = aggstate->ss.ps.ps_ProjInfo;
	peragg = aggstate->peragg;
	firstSlot = aggstate->ss.ss_ScanTupleSlot;

	
	while (!aggstate->agg_done)
	{
		
		entry = (AggHashEntry) ScanTupleHashTable(&aggstate->hashiter);
		if (entry == NULL)
		{
			
			aggstate->agg_done = TRUE;
			return NULL;
		}

		
		ResetExprContext(econtext);

		
		ExecStoreMinimalTuple(entry->shared.firstTuple, firstSlot, false);


		pergroup = entry->pergroup;

		
		for (aggno = 0; aggno < aggstate->numaggs; aggno++)
		{
			AggStatePerAgg peraggstate = &peragg[aggno];
			AggStatePerGroup pergroupstate = &pergroup[aggno];

			Assert(!peraggstate->aggref->aggdistinct);
			finalize_aggregate(aggstate, peraggstate, pergroupstate, &aggvalues[aggno], &aggnulls[aggno]);
		}

		
		econtext->ecxt_scantuple = firstSlot;

		
		if (ExecQual(aggstate->ss.ps.qual, econtext, false))
		{
			
			return ExecProject(projInfo, NULL);
		}
	}

	
	return NULL;
}


AggState * ExecInitAgg(Agg *node, EState *estate, int eflags)
{
	AggState   *aggstate;
	AggStatePerAgg peragg;
	Plan	   *outerPlan;
	ExprContext *econtext;
	int			numaggs, aggno;
	ListCell   *l;

	
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));

	
	aggstate = makeNode(AggState);
	aggstate->ss.ps.plan = (Plan *) node;
	aggstate->ss.ps.state = estate;

	aggstate->aggs = NIL;
	aggstate->numaggs = 0;
	aggstate->eqfunctions = NULL;
	aggstate->hashfunctions = NULL;
	aggstate->peragg = NULL;
	aggstate->agg_done = false;
	aggstate->pergroup = NULL;
	aggstate->grp_firstTuple = NULL;
	aggstate->hashtable = NULL;

	
	ExecAssignExprContext(estate, &aggstate->ss.ps);
	aggstate->tmpcontext = aggstate->ss.ps.ps_ExprContext;
	ExecAssignExprContext(estate, &aggstate->ss.ps);

	
	aggstate->aggcontext = AllocSetContextCreate(CurrentMemoryContext, "AggContext", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);







	
	ExecInitScanTupleSlot(estate, &aggstate->ss);
	ExecInitResultTupleSlot(estate, &aggstate->ss.ps);
	aggstate->hashslot = ExecInitExtraTupleSlot(estate);

	
	aggstate->ss.ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->plan.targetlist, (PlanState *) aggstate);
	aggstate->ss.ps.qual = (List *)
		ExecInitExpr((Expr *) node->plan.qual, (PlanState *) aggstate);

	
	if (node->aggstrategy == AGG_HASHED)
		eflags &= ~EXEC_FLAG_REWIND;
	outerPlan = outerPlan(node);
	outerPlanState(aggstate) = ExecInitNode(outerPlan, estate, eflags);

	
	ExecAssignScanTypeFromOuterPlan(&aggstate->ss);

	
	ExecAssignResultTypeFromTL(&aggstate->ss.ps);
	ExecAssignProjectionInfo(&aggstate->ss.ps);

	
	numaggs = aggstate->numaggs;
	Assert(numaggs == list_length(aggstate->aggs));
	if (numaggs <= 0)
	{
		
		numaggs = 1;
	}

	
	if (node->numCols > 0)
	{
		if (node->aggstrategy == AGG_HASHED)
			execTuplesHashPrepare(node->numCols, node->grpOperators, &aggstate->eqfunctions, &aggstate->hashfunctions);


		else aggstate->eqfunctions = execTuplesMatchPrepare(node->numCols, node->grpOperators);


	}

	
	econtext = aggstate->ss.ps.ps_ExprContext;
	econtext->ecxt_aggvalues = (Datum *) palloc0(sizeof(Datum) * numaggs);
	econtext->ecxt_aggnulls = (bool *) palloc0(sizeof(bool) * numaggs);

	peragg = (AggStatePerAgg) palloc0(sizeof(AggStatePerAggData) * numaggs);
	aggstate->peragg = peragg;

	if (node->aggstrategy == AGG_HASHED)
	{
		build_hash_table(aggstate);
		aggstate->table_filled = false;
	}
	else {
		AggStatePerGroup pergroup;

		pergroup = (AggStatePerGroup) palloc0(sizeof(AggStatePerGroupData) * numaggs);
		aggstate->pergroup = pergroup;
	}

	
	aggno = -1;
	foreach(l, aggstate->aggs)
	{
		AggrefExprState *aggrefstate = (AggrefExprState *) lfirst(l);
		Aggref	   *aggref = (Aggref *) aggrefstate->xprstate.expr;
		AggStatePerAgg peraggstate;
		Oid			inputTypes[FUNC_MAX_ARGS];
		int			numArguments;
		HeapTuple	aggTuple;
		Form_pg_aggregate aggform;
		Oid			aggtranstype;
		AclResult	aclresult;
		Oid			transfn_oid, finalfn_oid;
		Expr	   *transfnexpr, *finalfnexpr;
		Datum		textInitVal;
		int			i;
		ListCell   *lc;

		
		Assert(aggref->agglevelsup == 0);

		
		for (i = 0; i <= aggno; i++)
		{
			if (equal(aggref, peragg[i].aggref) && !contain_volatile_functions((Node *) aggref))
				break;
		}
		if (i <= aggno)
		{
			
			aggrefstate->aggno = i;
			continue;
		}

		
		peraggstate = &peragg[++aggno];

		
		aggrefstate->aggno = aggno;

		
		peraggstate->aggrefstate = aggrefstate;
		peraggstate->aggref = aggref;
		numArguments = list_length(aggref->args);
		peraggstate->numArguments = numArguments;

		
		i = 0;
		foreach(lc, aggref->args)
		{
			inputTypes[i++] = exprType((Node *) lfirst(lc));
		}

		aggTuple = SearchSysCache(AGGFNOID, ObjectIdGetDatum(aggref->aggfnoid), 0, 0, 0);

		if (!HeapTupleIsValid(aggTuple))
			elog(ERROR, "cache lookup failed for aggregate %u", aggref->aggfnoid);
		aggform = (Form_pg_aggregate) GETSTRUCT(aggTuple);

		
		aclresult = pg_proc_aclcheck(aggref->aggfnoid, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(aggref->aggfnoid));

		peraggstate->transfn_oid = transfn_oid = aggform->aggtransfn;
		peraggstate->finalfn_oid = finalfn_oid = aggform->aggfinalfn;

		
		{
			HeapTuple	procTuple;
			Oid			aggOwner;

			procTuple = SearchSysCache(PROCOID, ObjectIdGetDatum(aggref->aggfnoid), 0, 0, 0);

			if (!HeapTupleIsValid(procTuple))
				elog(ERROR, "cache lookup failed for function %u", aggref->aggfnoid);
			aggOwner = ((Form_pg_proc) GETSTRUCT(procTuple))->proowner;
			ReleaseSysCache(procTuple);

			aclresult = pg_proc_aclcheck(transfn_oid, aggOwner, ACL_EXECUTE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(transfn_oid));
			if (OidIsValid(finalfn_oid))
			{
				aclresult = pg_proc_aclcheck(finalfn_oid, aggOwner, ACL_EXECUTE);
				if (aclresult != ACLCHECK_OK)
					aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(finalfn_oid));
			}
		}

		
		aggtranstype = aggform->aggtranstype;
		if (aggtranstype == ANYARRAYOID || aggtranstype == ANYELEMENTOID)
		{
			
			Oid		   *declaredArgTypes;
			int			agg_nargs;

			(void) get_func_signature(aggref->aggfnoid, &declaredArgTypes, &agg_nargs);
			Assert(agg_nargs == numArguments);
			aggtranstype = enforce_generic_type_consistency(inputTypes, declaredArgTypes, agg_nargs, aggtranstype);


			pfree(declaredArgTypes);
		}

		
		build_aggregate_fnexprs(inputTypes, numArguments, aggtranstype, aggref->aggtype, transfn_oid, finalfn_oid, &transfnexpr, &finalfnexpr);







		fmgr_info(transfn_oid, &peraggstate->transfn);
		peraggstate->transfn.fn_expr = (Node *) transfnexpr;

		if (OidIsValid(finalfn_oid))
		{
			fmgr_info(finalfn_oid, &peraggstate->finalfn);
			peraggstate->finalfn.fn_expr = (Node *) finalfnexpr;
		}

		get_typlenbyval(aggref->aggtype, &peraggstate->resulttypeLen, &peraggstate->resulttypeByVal);

		get_typlenbyval(aggtranstype, &peraggstate->transtypeLen, &peraggstate->transtypeByVal);


		
		textInitVal = SysCacheGetAttr(AGGFNOID, aggTuple, Anum_pg_aggregate_agginitval, &peraggstate->initValueIsNull);


		if (peraggstate->initValueIsNull)
			peraggstate->initValue = (Datum) 0;
		else peraggstate->initValue = GetAggInitVal(textInitVal, aggtranstype);


		
		if (peraggstate->transfn.fn_strict && peraggstate->initValueIsNull)
		{
			if (numArguments < 1 || !IsBinaryCoercible(inputTypes[0], aggtranstype))
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("aggregate %u needs to have compatible input type and transition type", aggref->aggfnoid)));


		}

		if (aggref->aggdistinct)
		{
			Oid			eq_function;

			
			Assert(node->aggstrategy != AGG_HASHED);

			
			if (numArguments != 1)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("DISTINCT is supported only for single-argument aggregates")));


			peraggstate->inputType = inputTypes[0];
			get_typlenbyval(inputTypes[0], &peraggstate->inputtypeLen, &peraggstate->inputtypeByVal);


			
			eq_function = equality_oper_funcid(inputTypes[0]);
			fmgr_info(eq_function, &(peraggstate->equalfn));
			peraggstate->sortOperator = ordering_oper_opid(inputTypes[0]);
			peraggstate->sortstate = NULL;
		}

		ReleaseSysCache(aggTuple);
	}

	
	aggstate->numaggs = aggno + 1;

	return aggstate;
}

static Datum GetAggInitVal(Datum textInitVal, Oid transtype)
{
	Oid			typinput, typioparam;
	char	   *strInitVal;
	Datum		initVal;

	getTypeInputInfo(transtype, &typinput, &typioparam);
	strInitVal = DatumGetCString(DirectFunctionCall1(textout, textInitVal));
	initVal = OidInputFunctionCall(typinput, strInitVal, typioparam, -1);
	pfree(strInitVal);
	return initVal;
}

int ExecCountSlotsAgg(Agg *node)
{
	return ExecCountSlotsNode(outerPlan(node)) + ExecCountSlotsNode(innerPlan(node)) + AGG_NSLOTS;

}

void ExecEndAgg(AggState *node)
{
	PlanState  *outerPlan;
	int			aggno;

	
	for (aggno = 0; aggno < node->numaggs; aggno++)
	{
		AggStatePerAgg peraggstate = &node->peragg[aggno];

		if (peraggstate->sortstate)
			tuplesort_end(peraggstate->sortstate);
	}

	
	ExecFreeExprContext(&node->ss.ps);
	node->ss.ps.ps_ExprContext = node->tmpcontext;
	ExecFreeExprContext(&node->ss.ps);

	
	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	MemoryContextDelete(node->aggcontext);

	outerPlan = outerPlanState(node);
	ExecEndNode(outerPlan);
}

void ExecReScanAgg(AggState *node, ExprContext *exprCtxt)
{
	ExprContext *econtext = node->ss.ps.ps_ExprContext;
	int			aggno;

	node->agg_done = false;

	if (((Agg *) node->ss.ps.plan)->aggstrategy == AGG_HASHED)
	{
		
		if (!node->table_filled)
			return;

		
		if (((PlanState *) node)->lefttree->chgParam == NULL)
		{
			ResetTupleHashIterator(node->hashtable, &node->hashiter);
			return;
		}
	}

	
	for (aggno = 0; aggno < node->numaggs; aggno++)
	{
		AggStatePerAgg peraggstate = &node->peragg[aggno];

		if (peraggstate->sortstate)
			tuplesort_end(peraggstate->sortstate);
		peraggstate->sortstate = NULL;
	}

	
	if (node->grp_firstTuple != NULL)
	{
		heap_freetuple(node->grp_firstTuple);
		node->grp_firstTuple = NULL;
	}

	
	MemSet(econtext->ecxt_aggvalues, 0, sizeof(Datum) * node->numaggs);
	MemSet(econtext->ecxt_aggnulls, 0, sizeof(bool) * node->numaggs);

	
	MemoryContextReset(node->aggcontext);

	if (((Agg *) node->ss.ps.plan)->aggstrategy == AGG_HASHED)
	{
		
		build_hash_table(node);
		node->table_filled = false;
	}
	else {
		
		MemSet(node->pergroup, 0, sizeof(AggStatePerGroupData) * node->numaggs);
	}

	
	if (((PlanState *) node)->lefttree->chgParam == NULL)
		ExecReScan(((PlanState *) node)->lefttree, exprCtxt);
}


Datum aggregate_dummy(PG_FUNCTION_ARGS)
{
	elog(ERROR, "aggregate function %u called as normal function", fcinfo->flinfo->fn_oid);
	return (Datum) 0;			
}
