







static bool tlist_matches_tupdesc(PlanState *ps, List *tlist, Index varno, TupleDesc tupdesc);



TupleTableSlot * ExecScan(ScanState *node, ExecScanAccessMtd accessMtd)

{
	ExprContext *econtext;
	List	   *qual;
	ProjectionInfo *projInfo;
	ExprDoneCond isDone;
	TupleTableSlot *resultSlot;

	
	qual = node->ps.qual;
	projInfo = node->ps.ps_ProjInfo;

	
	if (!qual && !projInfo)
		return (*accessMtd) (node);

	
	if (node->ps.ps_TupFromTlist)
	{
		Assert(projInfo);		
		resultSlot = ExecProject(projInfo, &isDone);
		if (isDone == ExprMultipleResult)
			return resultSlot;
		
		node->ps.ps_TupFromTlist = false;
	}

	
	econtext = node->ps.ps_ExprContext;
	ResetExprContext(econtext);

	
	for (;;)
	{
		TupleTableSlot *slot;

		CHECK_FOR_INTERRUPTS();

		slot = (*accessMtd) (node);

		
		if (TupIsNull(slot))
		{
			if (projInfo)
				return ExecClearTuple(projInfo->pi_slot);
			else return slot;
		}

		
		econtext->ecxt_scantuple = slot;

		
		if (!qual || ExecQual(qual, econtext, false))
		{
			
			if (projInfo)
			{
				
				resultSlot = ExecProject(projInfo, &isDone);
				if (isDone != ExprEndResult)
				{
					node->ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
					return resultSlot;
				}
			}
			else {
				
				return slot;
			}
		}

		
		ResetExprContext(econtext);
	}
}


void ExecAssignScanProjectionInfo(ScanState *node)
{
	Scan	   *scan = (Scan *) node->ps.plan;

	if (tlist_matches_tupdesc(&node->ps, scan->plan.targetlist, scan->scanrelid, node->ss_ScanTupleSlot->tts_tupleDescriptor))


		node->ps.ps_ProjInfo = NULL;
	else ExecAssignProjectionInfo(&node->ps);
}

static bool tlist_matches_tupdesc(PlanState *ps, List *tlist, Index varno, TupleDesc tupdesc)
{
	int			numattrs = tupdesc->natts;
	int			attrno;
	bool		hasoid;
	ListCell   *tlist_item = list_head(tlist);

	
	for (attrno = 1; attrno <= numattrs; attrno++)
	{
		Form_pg_attribute att_tup = tupdesc->attrs[attrno - 1];
		Var		   *var;

		if (tlist_item == NULL)
			return false;		
		var = (Var *) ((TargetEntry *) lfirst(tlist_item))->expr;
		if (!var || !IsA(var, Var))
			return false;		
		Assert(var->varno == varno);
		Assert(var->varlevelsup == 0);
		if (var->varattno != attrno)
			return false;		
		if (att_tup->attisdropped)
			return false;		
		
		Assert(var->vartype == att_tup->atttypid);
		Assert(var->vartypmod == att_tup->atttypmod || var->vartypmod == -1);

		tlist_item = lnext(tlist_item);
	}

	if (tlist_item)
		return false;			

	
	if (ExecContextForcesOids(ps, &hasoid) && hasoid != tupdesc->tdhasoid)
		return false;

	return true;
}
