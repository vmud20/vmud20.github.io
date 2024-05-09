








TupleTableSlot * ExecGroup(GroupState *node)
{
	ExprContext *econtext;
	int			numCols;
	AttrNumber *grpColIdx;
	TupleTableSlot *firsttupleslot;
	TupleTableSlot *outerslot;

	
	if (node->grp_done)
		return NULL;
	econtext = node->ss.ps.ps_ExprContext;
	numCols = ((Group *) node->ss.ps.plan)->numCols;
	grpColIdx = ((Group *) node->ss.ps.plan)->grpColIdx;

	
	firsttupleslot = node->ss.ss_ScanTupleSlot;

	

	
	if (TupIsNull(firsttupleslot))
	{
		outerslot = ExecProcNode(outerPlanState(node));
		if (TupIsNull(outerslot))
		{
			
			node->grp_done = TRUE;
			return NULL;
		}
		
		ExecCopySlot(firsttupleslot, outerslot);
		econtext->ecxt_scantuple = firsttupleslot;

		
		if (ExecQual(node->ss.ps.qual, econtext, false))
		{
			
			return ExecProject(node->ss.ps.ps_ProjInfo, NULL);
		}
	}

	
	for (;;)
	{
		
		for (;;)
		{
			outerslot = ExecProcNode(outerPlanState(node));
			if (TupIsNull(outerslot))
			{
				
				node->grp_done = TRUE;
				return NULL;
			}

			
			if (!execTuplesMatch(firsttupleslot, outerslot, numCols, grpColIdx, node->eqfunctions, econtext->ecxt_per_tuple_memory))


				break;
		}

		
		
		ExecCopySlot(firsttupleslot, outerslot);
		econtext->ecxt_scantuple = firsttupleslot;

		
		if (ExecQual(node->ss.ps.qual, econtext, false))
		{
			
			return ExecProject(node->ss.ps.ps_ProjInfo, NULL);
		}
	}

	
	return NULL;
}


GroupState * ExecInitGroup(Group *node, EState *estate, int eflags)
{
	GroupState *grpstate;

	
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));

	
	grpstate = makeNode(GroupState);
	grpstate->ss.ps.plan = (Plan *) node;
	grpstate->ss.ps.state = estate;
	grpstate->grp_done = FALSE;

	
	ExecAssignExprContext(estate, &grpstate->ss.ps);



	
	ExecInitScanTupleSlot(estate, &grpstate->ss);
	ExecInitResultTupleSlot(estate, &grpstate->ss.ps);

	
	grpstate->ss.ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->plan.targetlist, (PlanState *) grpstate);
	grpstate->ss.ps.qual = (List *)
		ExecInitExpr((Expr *) node->plan.qual, (PlanState *) grpstate);

	
	outerPlanState(grpstate) = ExecInitNode(outerPlan(node), estate, eflags);

	
	ExecAssignScanTypeFromOuterPlan(&grpstate->ss);

	
	ExecAssignResultTypeFromTL(&grpstate->ss.ps);
	ExecAssignProjectionInfo(&grpstate->ss.ps);

	
	grpstate->eqfunctions = execTuplesMatchPrepare(node->numCols, node->grpOperators);


	return grpstate;
}

int ExecCountSlotsGroup(Group *node)
{
	return ExecCountSlotsNode(outerPlan(node)) + GROUP_NSLOTS;
}


void ExecEndGroup(GroupState *node)
{
	PlanState  *outerPlan;

	ExecFreeExprContext(&node->ss.ps);

	
	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	outerPlan = outerPlanState(node);
	ExecEndNode(outerPlan);
}

void ExecReScanGroup(GroupState *node, ExprContext *exprCtxt)
{
	node->grp_done = FALSE;
	
	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	if (((PlanState *) node)->lefttree && ((PlanState *) node)->lefttree->chgParam == NULL)
		ExecReScan(((PlanState *) node)->lefttree, exprCtxt);
}
