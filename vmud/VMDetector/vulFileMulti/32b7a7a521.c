









TupleTableSlot * ExecResult(ResultState *node)
{
	TupleTableSlot *outerTupleSlot;
	TupleTableSlot *resultSlot;
	PlanState  *outerPlan;
	ExprContext *econtext;
	ExprDoneCond isDone;

	econtext = node->ps.ps_ExprContext;

	
	if (node->rs_checkqual)
	{
		bool		qualResult = ExecQual((List *) node->resconstantqual, econtext, false);


		node->rs_checkqual = false;
		if (!qualResult)
		{
			node->rs_done = true;
			return NULL;
		}
	}

	
	if (node->ps.ps_TupFromTlist)
	{
		resultSlot = ExecProject(node->ps.ps_ProjInfo, &isDone);
		if (isDone == ExprMultipleResult)
			return resultSlot;
		
		node->ps.ps_TupFromTlist = false;
	}

	
	ResetExprContext(econtext);

	
	while (!node->rs_done)
	{
		outerPlan = outerPlanState(node);

		if (outerPlan != NULL)
		{
			
			outerTupleSlot = ExecProcNode(outerPlan);

			if (TupIsNull(outerTupleSlot))
				return NULL;

			node->ps.ps_OuterTupleSlot = outerTupleSlot;

			
			econtext->ecxt_outertuple = outerTupleSlot;
			econtext->ecxt_scantuple = outerTupleSlot;
		}
		else {
			
			node->rs_done = true;
		}

		
		resultSlot = ExecProject(node->ps.ps_ProjInfo, &isDone);

		if (isDone != ExprEndResult)
		{
			node->ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
			return resultSlot;
		}
	}

	return NULL;
}


ResultState * ExecInitResult(Result *node, EState *estate, int eflags)
{
	ResultState *resstate;

	
	Assert(!(eflags & EXEC_FLAG_MARK));
	Assert(!(eflags & EXEC_FLAG_BACKWARD) || outerPlan(node) != NULL);

	
	resstate = makeNode(ResultState);
	resstate->ps.plan = (Plan *) node;
	resstate->ps.state = estate;

	resstate->rs_done = false;
	resstate->rs_checkqual = (node->resconstantqual == NULL) ? false : true;

	
	ExecAssignExprContext(estate, &resstate->ps);

	resstate->ps.ps_TupFromTlist = false;



	
	ExecInitResultTupleSlot(estate, &resstate->ps);

	
	resstate->ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->plan.targetlist, (PlanState *) resstate);
	resstate->ps.qual = (List *)
		ExecInitExpr((Expr *) node->plan.qual, (PlanState *) resstate);
	resstate->resconstantqual = ExecInitExpr((Expr *) node->resconstantqual, (PlanState *) resstate);

	
	outerPlanState(resstate) = ExecInitNode(outerPlan(node), estate, eflags);

	
	Assert(innerPlan(node) == NULL);

	
	ExecAssignResultTypeFromTL(&resstate->ps);
	ExecAssignProjectionInfo(&resstate->ps);

	return resstate;
}

int ExecCountSlotsResult(Result *node)
{
	return ExecCountSlotsNode(outerPlan(node)) + RESULT_NSLOTS;
}


void ExecEndResult(ResultState *node)
{
	
	ExecFreeExprContext(&node->ps);

	
	ExecClearTuple(node->ps.ps_ResultTupleSlot);

	
	ExecEndNode(outerPlanState(node));
}

void ExecReScanResult(ResultState *node, ExprContext *exprCtxt)
{
	node->rs_done = false;
	node->ps.ps_TupFromTlist = false;
	node->rs_checkqual = (node->resconstantqual == NULL) ? false : true;

	
	if (((PlanState *) node)->lefttree && ((PlanState *) node)->lefttree->chgParam == NULL)
		ExecReScan(((PlanState *) node)->lefttree, exprCtxt);
}
