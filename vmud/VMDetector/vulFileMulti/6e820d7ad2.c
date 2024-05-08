
















typedef struct MergeJoinClauseData {
	
	ExprState  *lexpr;			
	ExprState  *rexpr;			

	
	Datum		ldatum;			
	Datum		rdatum;			
	bool		lisnull;		
	bool		risnull;

	
	bool		reverse;		
	bool		nulls_first;	
	FmgrInfo	cmpfinfo;
} MergeJoinClauseData;






static MergeJoinClause MJExamineQuals(List *mergeclauses, Oid *mergefamilies, int *mergestrategies, bool *mergenullsfirst, PlanState *parent)




{
	MergeJoinClause clauses;
	int			nClauses = list_length(mergeclauses);
	int			iClause;
	ListCell   *cl;

	clauses = (MergeJoinClause) palloc0(nClauses * sizeof(MergeJoinClauseData));

	iClause = 0;
	foreach(cl, mergeclauses)
	{
		OpExpr	   *qual = (OpExpr *) lfirst(cl);
		MergeJoinClause clause = &clauses[iClause];
		Oid			opfamily = mergefamilies[iClause];
		StrategyNumber opstrategy = mergestrategies[iClause];
		bool		nulls_first = mergenullsfirst[iClause];
		int			op_strategy;
		Oid			op_lefttype;
		Oid			op_righttype;
		bool		op_recheck;
		RegProcedure cmpproc;
		AclResult	aclresult;

		if (!IsA(qual, OpExpr))
			elog(ERROR, "mergejoin clause is not an OpExpr");

		
		clause->lexpr = ExecInitExpr((Expr *) linitial(qual->args), parent);
		clause->rexpr = ExecInitExpr((Expr *) lsecond(qual->args), parent);

		
		get_op_opfamily_properties(qual->opno, opfamily, &op_strategy, &op_lefttype, &op_righttype, &op_recheck);



		if (op_strategy != BTEqualStrategyNumber)	
			elog(ERROR, "cannot merge using non-equality operator %u", qual->opno);
		Assert(!op_recheck);	

		
		cmpproc = get_opfamily_proc(opfamily, op_lefttype, op_righttype, BTORDER_PROC);


		if (!RegProcedureIsValid(cmpproc))			
			elog(ERROR, "missing support function %d(%u,%u) in opfamily %u", BTORDER_PROC, op_lefttype, op_righttype, opfamily);

		
		aclresult = pg_proc_aclcheck(cmpproc, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(cmpproc));

		
		fmgr_info(cmpproc, &(clause->cmpfinfo));

		
		if (opstrategy == BTLessStrategyNumber)
			clause->reverse = false;
		else if (opstrategy == BTGreaterStrategyNumber)
			clause->reverse = true;
		else					 elog(ERROR, "unsupported mergejoin strategy %d", opstrategy);

		clause->nulls_first = nulls_first;

		iClause++;
	}

	return clauses;
}


static bool MJEvalOuterValues(MergeJoinState *mergestate)
{
	ExprContext *econtext = mergestate->mj_OuterEContext;
	bool		canmatch = true;
	int			i;
	MemoryContext oldContext;

	ResetExprContext(econtext);

	oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	econtext->ecxt_outertuple = mergestate->mj_OuterTupleSlot;

	for (i = 0; i < mergestate->mj_NumClauses; i++)
	{
		MergeJoinClause clause = &mergestate->mj_Clauses[i];

		clause->ldatum = ExecEvalExpr(clause->lexpr, econtext, &clause->lisnull, NULL);
		if (clause->lisnull)
			canmatch = false;
	}

	MemoryContextSwitchTo(oldContext);

	return canmatch;
}


static bool MJEvalInnerValues(MergeJoinState *mergestate, TupleTableSlot *innerslot)
{
	ExprContext *econtext = mergestate->mj_InnerEContext;
	bool		canmatch = true;
	int			i;
	MemoryContext oldContext;

	ResetExprContext(econtext);

	oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	econtext->ecxt_innertuple = innerslot;

	for (i = 0; i < mergestate->mj_NumClauses; i++)
	{
		MergeJoinClause clause = &mergestate->mj_Clauses[i];

		clause->rdatum = ExecEvalExpr(clause->rexpr, econtext, &clause->risnull, NULL);
		if (clause->risnull)
			canmatch = false;
	}

	MemoryContextSwitchTo(oldContext);

	return canmatch;
}


static int32 MJCompare(MergeJoinState *mergestate)
{
	int32		result = 0;
	bool		nulleqnull = false;
	ExprContext *econtext = mergestate->js.ps.ps_ExprContext;
	int			i;
	MemoryContext oldContext;
	FunctionCallInfoData fcinfo;

	
	ResetExprContext(econtext);

	oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	for (i = 0; i < mergestate->mj_NumClauses; i++)
	{
		MergeJoinClause clause = &mergestate->mj_Clauses[i];
		Datum		fresult;

		
		if (clause->lisnull)
		{
			if (clause->risnull)
			{
				nulleqnull = true;				
				continue;
			}
			if (clause->nulls_first)
				result = -1;					
			else result = 1;
			break;
		}
		if (clause->risnull)
		{
			if (clause->nulls_first)
				result = 1;						
			else result = -1;
			break;
		}

		
		InitFunctionCallInfoData(fcinfo, &(clause->cmpfinfo), 2, NULL, NULL);
		fcinfo.arg[0] = clause->ldatum;
		fcinfo.arg[1] = clause->rdatum;
		fcinfo.argnull[0] = false;
		fcinfo.argnull[1] = false;
		fresult = FunctionCallInvoke(&fcinfo);
		if (fcinfo.isnull)
		{
			nulleqnull = true;					
			continue;
		}
		result = DatumGetInt32(fresult);

		if (clause->reverse)
			result = -result;

		if (result != 0)
			break;
	}

	
	if (nulleqnull && result == 0)
		result = 1;

	MemoryContextSwitchTo(oldContext);

	return result;
}



static TupleTableSlot * MJFillOuter(MergeJoinState *node)
{
	ExprContext *econtext = node->js.ps.ps_ExprContext;
	List	   *otherqual = node->js.ps.qual;

	ResetExprContext(econtext);

	econtext->ecxt_outertuple = node->mj_OuterTupleSlot;
	econtext->ecxt_innertuple = node->mj_NullInnerTupleSlot;

	if (ExecQual(otherqual, econtext, false))
	{
		
		TupleTableSlot *result;
		ExprDoneCond isDone;

		MJ_printf("ExecMergeJoin: returning outer fill tuple\n");

		result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

		if (isDone != ExprEndResult)
		{
			node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
			return result;
		}
	}

	return NULL;
}


static TupleTableSlot * MJFillInner(MergeJoinState *node)
{
	ExprContext *econtext = node->js.ps.ps_ExprContext;
	List	   *otherqual = node->js.ps.qual;

	ResetExprContext(econtext);

	econtext->ecxt_outertuple = node->mj_NullOuterTupleSlot;
	econtext->ecxt_innertuple = node->mj_InnerTupleSlot;

	if (ExecQual(otherqual, econtext, false))
	{
		
		TupleTableSlot *result;
		ExprDoneCond isDone;

		MJ_printf("ExecMergeJoin: returning inner fill tuple\n");

		result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

		if (isDone != ExprEndResult)
		{
			node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
			return result;
		}
	}

	return NULL;
}





static void ExecMergeTupleDumpOuter(MergeJoinState *mergestate)
{
	TupleTableSlot *outerSlot = mergestate->mj_OuterTupleSlot;

	printf("==== outer tuple ====\n");
	if (TupIsNull(outerSlot))
		printf("(nil)\n");
	else MJ_debugtup(outerSlot);
}

static void ExecMergeTupleDumpInner(MergeJoinState *mergestate)
{
	TupleTableSlot *innerSlot = mergestate->mj_InnerTupleSlot;

	printf("==== inner tuple ====\n");
	if (TupIsNull(innerSlot))
		printf("(nil)\n");
	else MJ_debugtup(innerSlot);
}

static void ExecMergeTupleDumpMarked(MergeJoinState *mergestate)
{
	TupleTableSlot *markedSlot = mergestate->mj_MarkedTupleSlot;

	printf("==== marked tuple ====\n");
	if (TupIsNull(markedSlot))
		printf("(nil)\n");
	else MJ_debugtup(markedSlot);
}

static void ExecMergeTupleDump(MergeJoinState *mergestate)
{
	printf("******** ExecMergeTupleDump ********\n");

	ExecMergeTupleDumpOuter(mergestate);
	ExecMergeTupleDumpInner(mergestate);
	ExecMergeTupleDumpMarked(mergestate);

	printf("******** \n");
}



TupleTableSlot * ExecMergeJoin(MergeJoinState *node)
{
	EState	   *estate;
	List	   *joinqual;
	List	   *otherqual;
	bool		qualResult;
	int32		compareResult;
	PlanState  *innerPlan;
	TupleTableSlot *innerTupleSlot;
	PlanState  *outerPlan;
	TupleTableSlot *outerTupleSlot;
	ExprContext *econtext;
	bool		doFillOuter;
	bool		doFillInner;

	
	estate = node->js.ps.state;
	innerPlan = innerPlanState(node);
	outerPlan = outerPlanState(node);
	econtext = node->js.ps.ps_ExprContext;
	joinqual = node->js.joinqual;
	otherqual = node->js.ps.qual;
	doFillOuter = node->mj_FillOuter;
	doFillInner = node->mj_FillInner;

	
	if (node->js.ps.ps_TupFromTlist)
	{
		TupleTableSlot *result;
		ExprDoneCond isDone;

		result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);
		if (isDone == ExprMultipleResult)
			return result;
		
		node->js.ps.ps_TupFromTlist = false;
	}

	
	ResetExprContext(econtext);

	
	for (;;)
	{
		MJ_dump(node);

		
		switch (node->mj_JoinState)
		{
				
			case EXEC_MJ_INITIALIZE_OUTER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_INITIALIZE_OUTER\n");

				outerTupleSlot = ExecProcNode(outerPlan);
				node->mj_OuterTupleSlot = outerTupleSlot;
				if (TupIsNull(outerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: nothing in outer subplan\n");
					if (doFillInner)
					{
						
						node->mj_JoinState = EXEC_MJ_ENDOUTER;
						node->mj_MatchedInner = true;
						break;
					}
					
					return NULL;
				}

				
				if (MJEvalOuterValues(node))
				{
					
					node->mj_JoinState = EXEC_MJ_INITIALIZE_INNER;
				}
				else {
					
					if (doFillOuter)
					{
						
						TupleTableSlot *result;

						result = MJFillOuter(node);
						if (result)
							return result;
					}
				}
				break;

			case EXEC_MJ_INITIALIZE_INNER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_INITIALIZE_INNER\n");

				innerTupleSlot = ExecProcNode(innerPlan);
				node->mj_InnerTupleSlot = innerTupleSlot;
				if (TupIsNull(innerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: nothing in inner subplan\n");
					if (doFillOuter)
					{
						
						node->mj_JoinState = EXEC_MJ_ENDINNER;
						node->mj_MatchedOuter = false;
						break;
					}
					
					return NULL;
				}

				
				if (MJEvalInnerValues(node, innerTupleSlot))
				{
					
					node->mj_JoinState = EXEC_MJ_SKIP_TEST;
				}
				else {
					
					if (doFillInner)
					{
						
						TupleTableSlot *result;

						result = MJFillInner(node);
						if (result)
							return result;
					}
				}
				break;

				
			case EXEC_MJ_JOINTUPLES:
				MJ_printf("ExecMergeJoin: EXEC_MJ_JOINTUPLES\n");

				
				node->mj_JoinState = EXEC_MJ_NEXTINNER;

				
				outerTupleSlot = node->mj_OuterTupleSlot;
				econtext->ecxt_outertuple = outerTupleSlot;
				innerTupleSlot = node->mj_InnerTupleSlot;
				econtext->ecxt_innertuple = innerTupleSlot;

				if (node->js.jointype == JOIN_IN && node->mj_MatchedOuter)
					qualResult = false;
				else {
					qualResult = (joinqual == NIL || ExecQual(joinqual, econtext, false));
					MJ_DEBUG_QUAL(joinqual, qualResult);
				}

				if (qualResult)
				{
					node->mj_MatchedOuter = true;
					node->mj_MatchedInner = true;

					qualResult = (otherqual == NIL || ExecQual(otherqual, econtext, false));
					MJ_DEBUG_QUAL(otherqual, qualResult);

					if (qualResult)
					{
						
						TupleTableSlot *result;
						ExprDoneCond isDone;

						MJ_printf("ExecMergeJoin: returning tuple\n");

						result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

						if (isDone != ExprEndResult)
						{
							node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
							return result;
						}
					}
				}
				break;

				
			case EXEC_MJ_NEXTINNER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_NEXTINNER\n");

				if (doFillInner && !node->mj_MatchedInner)
				{
					
					TupleTableSlot *result;

					node->mj_MatchedInner = true;		

					result = MJFillInner(node);
					if (result)
						return result;
				}

				
				innerTupleSlot = ExecProcNode(innerPlan);
				node->mj_InnerTupleSlot = innerTupleSlot;
				MJ_DEBUG_PROC_NODE(innerTupleSlot);
				node->mj_MatchedInner = false;

				if (TupIsNull(innerTupleSlot))
				{
					node->mj_JoinState = EXEC_MJ_NEXTOUTER;
					break;
				}

				
				if (!MJEvalInnerValues(node, innerTupleSlot))
				{
					node->mj_JoinState = EXEC_MJ_NEXTOUTER;
					break;
				}

				
				compareResult = MJCompare(node);
				MJ_DEBUG_COMPARE(compareResult);

				if (compareResult == 0)
					node->mj_JoinState = EXEC_MJ_JOINTUPLES;
				else {
					Assert(compareResult < 0);
					node->mj_JoinState = EXEC_MJ_NEXTOUTER;
				}
				break;

				
			case EXEC_MJ_NEXTOUTER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_NEXTOUTER\n");

				if (doFillOuter && !node->mj_MatchedOuter)
				{
					
					TupleTableSlot *result;

					node->mj_MatchedOuter = true;		

					result = MJFillOuter(node);
					if (result)
						return result;
				}

				
				outerTupleSlot = ExecProcNode(outerPlan);
				node->mj_OuterTupleSlot = outerTupleSlot;
				MJ_DEBUG_PROC_NODE(outerTupleSlot);
				node->mj_MatchedOuter = false;

				
				if (TupIsNull(outerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: end of outer subplan\n");
					innerTupleSlot = node->mj_InnerTupleSlot;
					if (doFillInner && !TupIsNull(innerTupleSlot))
					{
						
						node->mj_JoinState = EXEC_MJ_ENDOUTER;
						break;
					}
					
					return NULL;
				}

				
				if (MJEvalOuterValues(node))
				{
					
					node->mj_JoinState = EXEC_MJ_TESTOUTER;
				}
				else {
					
					node->mj_JoinState = EXEC_MJ_NEXTOUTER;
				}
				break;

				
			case EXEC_MJ_TESTOUTER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_TESTOUTER\n");

				
				innerTupleSlot = node->mj_MarkedTupleSlot;
				(void) MJEvalInnerValues(node, innerTupleSlot);

				compareResult = MJCompare(node);
				MJ_DEBUG_COMPARE(compareResult);

				if (compareResult == 0)
				{
					
					ExecRestrPos(innerPlan);

					
					node->mj_InnerTupleSlot = innerTupleSlot;
					

					node->mj_JoinState = EXEC_MJ_JOINTUPLES;
				}
				else {
					
					Assert(compareResult > 0);
					innerTupleSlot = node->mj_InnerTupleSlot;
					if (TupIsNull(innerTupleSlot))
					{
						if (doFillOuter)
						{
							
							node->mj_JoinState = EXEC_MJ_ENDINNER;
							break;
						}
						
						return NULL;
					}

					
					if (MJEvalInnerValues(node, innerTupleSlot))
					{
						
						node->mj_JoinState = EXEC_MJ_SKIP_TEST;
					}
					else {
						
						node->mj_JoinState = EXEC_MJ_SKIPINNER_ADVANCE;
					}
				}
				break;

				
			case EXEC_MJ_SKIP_TEST:
				MJ_printf("ExecMergeJoin: EXEC_MJ_SKIP_TEST\n");

				
				compareResult = MJCompare(node);
				MJ_DEBUG_COMPARE(compareResult);

				if (compareResult == 0)
				{
					ExecMarkPos(innerPlan);

					MarkInnerTuple(node->mj_InnerTupleSlot, node);

					node->mj_JoinState = EXEC_MJ_JOINTUPLES;
				}
				else if (compareResult < 0)
					node->mj_JoinState = EXEC_MJ_SKIPOUTER_ADVANCE;
				else  node->mj_JoinState = EXEC_MJ_SKIPINNER_ADVANCE;

				break;

				
			case EXEC_MJ_SKIPOUTER_ADVANCE:
				MJ_printf("ExecMergeJoin: EXEC_MJ_SKIPOUTER_ADVANCE\n");

				if (doFillOuter && !node->mj_MatchedOuter)
				{
					
					TupleTableSlot *result;

					node->mj_MatchedOuter = true;		

					result = MJFillOuter(node);
					if (result)
						return result;
				}

				
				outerTupleSlot = ExecProcNode(outerPlan);
				node->mj_OuterTupleSlot = outerTupleSlot;
				MJ_DEBUG_PROC_NODE(outerTupleSlot);
				node->mj_MatchedOuter = false;

				
				if (TupIsNull(outerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: end of outer subplan\n");
					innerTupleSlot = node->mj_InnerTupleSlot;
					if (doFillInner && !TupIsNull(innerTupleSlot))
					{
						
						node->mj_JoinState = EXEC_MJ_ENDOUTER;
						break;
					}
					
					return NULL;
				}

				
				if (MJEvalOuterValues(node))
				{
					
					node->mj_JoinState = EXEC_MJ_SKIP_TEST;
				}
				else {
					
					node->mj_JoinState = EXEC_MJ_SKIPOUTER_ADVANCE;
				}
				break;

				
			case EXEC_MJ_SKIPINNER_ADVANCE:
				MJ_printf("ExecMergeJoin: EXEC_MJ_SKIPINNER_ADVANCE\n");

				if (doFillInner && !node->mj_MatchedInner)
				{
					
					TupleTableSlot *result;

					node->mj_MatchedInner = true;		

					result = MJFillInner(node);
					if (result)
						return result;
				}

				
				innerTupleSlot = ExecProcNode(innerPlan);
				node->mj_InnerTupleSlot = innerTupleSlot;
				MJ_DEBUG_PROC_NODE(innerTupleSlot);
				node->mj_MatchedInner = false;

				
				if (TupIsNull(innerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: end of inner subplan\n");
					outerTupleSlot = node->mj_OuterTupleSlot;
					if (doFillOuter && !TupIsNull(outerTupleSlot))
					{
						
						node->mj_JoinState = EXEC_MJ_ENDINNER;
						break;
					}
					
					return NULL;
				}

				
				if (MJEvalInnerValues(node, innerTupleSlot))
				{
					
					node->mj_JoinState = EXEC_MJ_SKIP_TEST;
				}
				else {
					
					node->mj_JoinState = EXEC_MJ_SKIPINNER_ADVANCE;
				}
				break;

				
			case EXEC_MJ_ENDOUTER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_ENDOUTER\n");

				Assert(doFillInner);

				if (!node->mj_MatchedInner)
				{
					
					TupleTableSlot *result;

					node->mj_MatchedInner = true;		

					result = MJFillInner(node);
					if (result)
						return result;
				}

				
				innerTupleSlot = ExecProcNode(innerPlan);
				node->mj_InnerTupleSlot = innerTupleSlot;
				MJ_DEBUG_PROC_NODE(innerTupleSlot);
				node->mj_MatchedInner = false;

				if (TupIsNull(innerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: end of inner subplan\n");
					return NULL;
				}

				
				break;

				
			case EXEC_MJ_ENDINNER:
				MJ_printf("ExecMergeJoin: EXEC_MJ_ENDINNER\n");

				Assert(doFillOuter);

				if (!node->mj_MatchedOuter)
				{
					
					TupleTableSlot *result;

					node->mj_MatchedOuter = true;		

					result = MJFillOuter(node);
					if (result)
						return result;
				}

				
				outerTupleSlot = ExecProcNode(outerPlan);
				node->mj_OuterTupleSlot = outerTupleSlot;
				MJ_DEBUG_PROC_NODE(outerTupleSlot);
				node->mj_MatchedOuter = false;

				if (TupIsNull(outerTupleSlot))
				{
					MJ_printf("ExecMergeJoin: end of outer subplan\n");
					return NULL;
				}

				
				break;

				
			default:
				elog(ERROR, "unrecognized mergejoin state: %d", (int) node->mj_JoinState);
		}
	}
}


MergeJoinState * ExecInitMergeJoin(MergeJoin *node, EState *estate, int eflags)
{
	MergeJoinState *mergestate;

	
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));

	MJ1_printf("ExecInitMergeJoin: %s\n", "initializing node");

	
	mergestate = makeNode(MergeJoinState);
	mergestate->js.ps.plan = (Plan *) node;
	mergestate->js.ps.state = estate;

	
	ExecAssignExprContext(estate, &mergestate->js.ps);

	
	mergestate->mj_OuterEContext = CreateExprContext(estate);
	mergestate->mj_InnerEContext = CreateExprContext(estate);

	
	mergestate->js.ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->join.plan.targetlist, (PlanState *) mergestate);
	mergestate->js.ps.qual = (List *)
		ExecInitExpr((Expr *) node->join.plan.qual, (PlanState *) mergestate);
	mergestate->js.jointype = node->join.jointype;
	mergestate->js.joinqual = (List *)
		ExecInitExpr((Expr *) node->join.joinqual, (PlanState *) mergestate);
	

	
	outerPlanState(mergestate) = ExecInitNode(outerPlan(node), estate, eflags);
	innerPlanState(mergestate) = ExecInitNode(innerPlan(node), estate, eflags | EXEC_FLAG_MARK);



	
	ExecInitResultTupleSlot(estate, &mergestate->js.ps);

	mergestate->mj_MarkedTupleSlot = ExecInitExtraTupleSlot(estate);
	ExecSetSlotDescriptor(mergestate->mj_MarkedTupleSlot, ExecGetResultType(innerPlanState(mergestate)));

	switch (node->join.jointype)
	{
		case JOIN_INNER:
		case JOIN_IN:
			mergestate->mj_FillOuter = false;
			mergestate->mj_FillInner = false;
			break;
		case JOIN_LEFT:
			mergestate->mj_FillOuter = true;
			mergestate->mj_FillInner = false;
			mergestate->mj_NullInnerTupleSlot = ExecInitNullTupleSlot(estate, ExecGetResultType(innerPlanState(mergestate)));

			break;
		case JOIN_RIGHT:
			mergestate->mj_FillOuter = false;
			mergestate->mj_FillInner = true;
			mergestate->mj_NullOuterTupleSlot = ExecInitNullTupleSlot(estate, ExecGetResultType(outerPlanState(mergestate)));


			
			if (node->join.joinqual != NIL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("RIGHT JOIN is only supported with merge-joinable join conditions")));

			break;
		case JOIN_FULL:
			mergestate->mj_FillOuter = true;
			mergestate->mj_FillInner = true;
			mergestate->mj_NullOuterTupleSlot = ExecInitNullTupleSlot(estate, ExecGetResultType(outerPlanState(mergestate)));

			mergestate->mj_NullInnerTupleSlot = ExecInitNullTupleSlot(estate, ExecGetResultType(innerPlanState(mergestate)));


			
			if (node->join.joinqual != NIL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("FULL JOIN is only supported with merge-joinable join conditions")));

			break;
		default:
			elog(ERROR, "unrecognized join type: %d", (int) node->join.jointype);
	}

	
	ExecAssignResultTypeFromTL(&mergestate->js.ps);
	ExecAssignProjectionInfo(&mergestate->js.ps);

	
	mergestate->mj_NumClauses = list_length(node->mergeclauses);
	mergestate->mj_Clauses = MJExamineQuals(node->mergeclauses, node->mergeFamilies, node->mergeStrategies, node->mergeNullsFirst, (PlanState *) mergestate);




	
	mergestate->mj_JoinState = EXEC_MJ_INITIALIZE_OUTER;
	mergestate->js.ps.ps_TupFromTlist = false;
	mergestate->mj_MatchedOuter = false;
	mergestate->mj_MatchedInner = false;
	mergestate->mj_OuterTupleSlot = NULL;
	mergestate->mj_InnerTupleSlot = NULL;

	
	MJ1_printf("ExecInitMergeJoin: %s\n", "node initialized");

	return mergestate;
}

int ExecCountSlotsMergeJoin(MergeJoin *node)
{
	return ExecCountSlotsNode(outerPlan((Plan *) node)) + ExecCountSlotsNode(innerPlan((Plan *) node)) + MERGEJOIN_NSLOTS;

}


void ExecEndMergeJoin(MergeJoinState *node)
{
	MJ1_printf("ExecEndMergeJoin: %s\n", "ending node processing");

	
	ExecFreeExprContext(&node->js.ps);

	
	ExecClearTuple(node->js.ps.ps_ResultTupleSlot);
	ExecClearTuple(node->mj_MarkedTupleSlot);

	
	ExecEndNode(innerPlanState(node));
	ExecEndNode(outerPlanState(node));

	MJ1_printf("ExecEndMergeJoin: %s\n", "node processing ended");
}

void ExecReScanMergeJoin(MergeJoinState *node, ExprContext *exprCtxt)
{
	ExecClearTuple(node->mj_MarkedTupleSlot);

	node->mj_JoinState = EXEC_MJ_INITIALIZE_OUTER;
	node->js.ps.ps_TupFromTlist = false;
	node->mj_MatchedOuter = false;
	node->mj_MatchedInner = false;
	node->mj_OuterTupleSlot = NULL;
	node->mj_InnerTupleSlot = NULL;

	
	if (((PlanState *) node)->lefttree->chgParam == NULL)
		ExecReScan(((PlanState *) node)->lefttree, exprCtxt);
	if (((PlanState *) node)->righttree->chgParam == NULL)
		ExecReScan(((PlanState *) node)->righttree, exprCtxt);

}
