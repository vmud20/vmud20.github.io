










TupleTableSlot * ExecNestLoop(NestLoopState *node)
{
	PlanState  *innerPlan;
	PlanState  *outerPlan;
	TupleTableSlot *outerTupleSlot;
	TupleTableSlot *innerTupleSlot;
	List	   *joinqual;
	List	   *otherqual;
	ExprContext *econtext;

	
	ENL1_printf("getting info from node");

	joinqual = node->js.joinqual;
	otherqual = node->js.ps.qual;
	outerPlan = outerPlanState(node);
	innerPlan = innerPlanState(node);
	econtext = node->js.ps.ps_ExprContext;

	
	outerTupleSlot = node->js.ps.ps_OuterTupleSlot;
	econtext->ecxt_outertuple = outerTupleSlot;

	
	if (node->js.ps.ps_TupFromTlist)
	{
		TupleTableSlot *result;
		ExprDoneCond isDone;

		result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);
		if (isDone == ExprMultipleResult)
			return result;
		
		node->js.ps.ps_TupFromTlist = false;
	}

	
	if (node->js.jointype == JOIN_IN && node->nl_MatchedOuter)
		node->nl_NeedNewOuter = true;

	
	ResetExprContext(econtext);

	
	ENL1_printf("entering main loop");

	for (;;)
	{
		
		if (node->nl_NeedNewOuter)
		{
			ENL1_printf("getting new outer tuple");
			outerTupleSlot = ExecProcNode(outerPlan);

			
			if (TupIsNull(outerTupleSlot))
			{
				ENL1_printf("no outer tuple, ending join");
				return NULL;
			}

			ENL1_printf("saving new outer tuple information");
			node->js.ps.ps_OuterTupleSlot = outerTupleSlot;
			econtext->ecxt_outertuple = outerTupleSlot;
			node->nl_NeedNewOuter = false;
			node->nl_MatchedOuter = false;

			
			ENL1_printf("rescanning inner plan");

			
			ExecReScan(innerPlan, econtext);
		}

		
		ENL1_printf("getting new inner tuple");

		innerTupleSlot = ExecProcNode(innerPlan);
		econtext->ecxt_innertuple = innerTupleSlot;

		if (TupIsNull(innerTupleSlot))
		{
			ENL1_printf("no inner tuple, need new outer tuple");

			node->nl_NeedNewOuter = true;

			if (!node->nl_MatchedOuter && node->js.jointype == JOIN_LEFT)
			{
				
				econtext->ecxt_innertuple = node->nl_NullInnerTupleSlot;

				ENL1_printf("testing qualification for outer-join tuple");

				if (ExecQual(otherqual, econtext, false))
				{
					
					TupleTableSlot *result;
					ExprDoneCond isDone;

					ENL1_printf("qualification succeeded, projecting tuple");

					result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

					if (isDone != ExprEndResult)
					{
						node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
						return result;
					}
				}
			}

			
			continue;
		}

		
		ENL1_printf("testing qualification");

		if (ExecQual(joinqual, econtext, false))
		{
			node->nl_MatchedOuter = true;

			if (otherqual == NIL || ExecQual(otherqual, econtext, false))
			{
				
				TupleTableSlot *result;
				ExprDoneCond isDone;

				ENL1_printf("qualification succeeded, projecting tuple");

				result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

				if (isDone != ExprEndResult)
				{
					node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
					return result;
				}
			}

			
			if (node->js.jointype == JOIN_IN)
				node->nl_NeedNewOuter = true;
		}

		
		ResetExprContext(econtext);

		ENL1_printf("qualification failed, looping");
	}
}


NestLoopState * ExecInitNestLoop(NestLoop *node, EState *estate, int eflags)
{
	NestLoopState *nlstate;

	
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));

	NL1_printf("ExecInitNestLoop: %s\n", "initializing node");

	
	nlstate = makeNode(NestLoopState);
	nlstate->js.ps.plan = (Plan *) node;
	nlstate->js.ps.state = estate;

	
	ExecAssignExprContext(estate, &nlstate->js.ps);

	
	nlstate->js.ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->join.plan.targetlist, (PlanState *) nlstate);
	nlstate->js.ps.qual = (List *)
		ExecInitExpr((Expr *) node->join.plan.qual, (PlanState *) nlstate);
	nlstate->js.jointype = node->join.jointype;
	nlstate->js.joinqual = (List *)
		ExecInitExpr((Expr *) node->join.joinqual, (PlanState *) nlstate);

	
	outerPlanState(nlstate) = ExecInitNode(outerPlan(node), estate, eflags);
	innerPlanState(nlstate) = ExecInitNode(innerPlan(node), estate, eflags | EXEC_FLAG_REWIND);



	
	ExecInitResultTupleSlot(estate, &nlstate->js.ps);

	switch (node->join.jointype)
	{
		case JOIN_INNER:
		case JOIN_IN:
			break;
		case JOIN_LEFT:
			nlstate->nl_NullInnerTupleSlot = ExecInitNullTupleSlot(estate, ExecGetResultType(innerPlanState(nlstate)));

			break;
		default:
			elog(ERROR, "unrecognized join type: %d", (int) node->join.jointype);
	}

	
	ExecAssignResultTypeFromTL(&nlstate->js.ps);
	ExecAssignProjectionInfo(&nlstate->js.ps);

	
	nlstate->js.ps.ps_OuterTupleSlot = NULL;
	nlstate->js.ps.ps_TupFromTlist = false;
	nlstate->nl_NeedNewOuter = true;
	nlstate->nl_MatchedOuter = false;

	NL1_printf("ExecInitNestLoop: %s\n", "node initialized");

	return nlstate;
}

int ExecCountSlotsNestLoop(NestLoop *node)
{
	return ExecCountSlotsNode(outerPlan(node)) + ExecCountSlotsNode(innerPlan(node)) + NESTLOOP_NSLOTS;

}


void ExecEndNestLoop(NestLoopState *node)
{
	NL1_printf("ExecEndNestLoop: %s\n", "ending node processing");

	
	ExecFreeExprContext(&node->js.ps);

	
	ExecClearTuple(node->js.ps.ps_ResultTupleSlot);

	
	ExecEndNode(outerPlanState(node));
	ExecEndNode(innerPlanState(node));

	NL1_printf("ExecEndNestLoop: %s\n", "node processing ended");
}


void ExecReScanNestLoop(NestLoopState *node, ExprContext *exprCtxt)
{
	PlanState  *outerPlan = outerPlanState(node);

	
	if (outerPlan->chgParam == NULL)
		ExecReScan(outerPlan, exprCtxt);

	
	node->js.ps.ps_OuterTupleSlot = NULL;
	node->js.ps.ps_TupFromTlist = false;
	node->nl_NeedNewOuter = true;
	node->nl_MatchedOuter = false;
}
