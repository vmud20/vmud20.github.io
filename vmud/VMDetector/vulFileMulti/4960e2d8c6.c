










static TupleTableSlot *ExecHashJoinOuterGetTuple(PlanState *outerNode, HashJoinState *hjstate, uint32 *hashvalue);

static TupleTableSlot *ExecHashJoinGetSavedTuple(HashJoinState *hjstate, BufFile *file, uint32 *hashvalue, TupleTableSlot *tupleSlot);


static int	ExecHashJoinNewBatch(HashJoinState *hjstate);



TupleTableSlot *				 ExecHashJoin(HashJoinState *node)
{
	EState	   *estate;
	PlanState  *outerNode;
	HashState  *hashNode;
	List	   *joinqual;
	List	   *otherqual;
	TupleTableSlot *inntuple;
	ExprContext *econtext;
	ExprDoneCond isDone;
	HashJoinTable hashtable;
	HashJoinTuple curtuple;
	TupleTableSlot *outerTupleSlot;
	uint32		hashvalue;
	int			batchno;

	
	estate = node->js.ps.state;
	joinqual = node->js.joinqual;
	otherqual = node->js.ps.qual;
	hashNode = (HashState *) innerPlanState(node);
	outerNode = outerPlanState(node);

	
	hashtable = node->hj_HashTable;
	econtext = node->js.ps.ps_ExprContext;

	
	if (node->js.ps.ps_TupFromTlist)
	{
		TupleTableSlot *result;

		result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);
		if (isDone == ExprMultipleResult)
			return result;
		
		node->js.ps.ps_TupFromTlist = false;
	}

	
	if (node->js.jointype == JOIN_IN && node->hj_MatchedOuter)
		node->hj_NeedNewOuter = true;

	
	ResetExprContext(econtext);

	
	if (hashtable == NULL)
	{
		
		if (node->js.jointype == JOIN_LEFT || (outerNode->plan->startup_cost < hashNode->ps.plan->total_cost && !node->hj_OuterNotEmpty))

		{
			node->hj_FirstOuterTupleSlot = ExecProcNode(outerNode);
			if (TupIsNull(node->hj_FirstOuterTupleSlot))
			{
				node->hj_OuterNotEmpty = false;
				return NULL;
			}
			else node->hj_OuterNotEmpty = true;
		}
		else node->hj_FirstOuterTupleSlot = NULL;

		
		hashtable = ExecHashTableCreate((Hash *) hashNode->ps.plan, node->hj_HashOperators);
		node->hj_HashTable = hashtable;

		
		hashNode->hashtable = hashtable;
		(void) MultiExecProcNode((PlanState *) hashNode);

		
		if (hashtable->totalTuples == 0 && node->js.jointype != JOIN_LEFT)
			return NULL;

		
		hashtable->nbatch_outstart = hashtable->nbatch;

		
		node->hj_OuterNotEmpty = false;
	}

	
	for (;;)
	{
		
		if (node->hj_NeedNewOuter)
		{
			outerTupleSlot = ExecHashJoinOuterGetTuple(outerNode, node, &hashvalue);

			if (TupIsNull(outerTupleSlot))
			{
				
				return NULL;
			}

			node->js.ps.ps_OuterTupleSlot = outerTupleSlot;
			econtext->ecxt_outertuple = outerTupleSlot;
			node->hj_NeedNewOuter = false;
			node->hj_MatchedOuter = false;

			
			node->hj_CurHashValue = hashvalue;
			ExecHashGetBucketAndBatch(hashtable, hashvalue, &node->hj_CurBucketNo, &batchno);
			node->hj_CurTuple = NULL;

			
			if (batchno != hashtable->curbatch)
			{
				
				Assert(batchno > hashtable->curbatch);
				ExecHashJoinSaveTuple(ExecFetchSlotMinimalTuple(outerTupleSlot), hashvalue, &hashtable->outerBatchFile[batchno]);

				node->hj_NeedNewOuter = true;
				continue;		
			}
		}

		
		for (;;)
		{
			curtuple = ExecScanHashBucket(node, econtext);
			if (curtuple == NULL)
				break;			

			
			inntuple = ExecStoreMinimalTuple(HJTUPLE_MINTUPLE(curtuple), node->hj_HashTupleSlot, false);

			econtext->ecxt_innertuple = inntuple;

			
			ResetExprContext(econtext);

			
			if (joinqual == NIL || ExecQual(joinqual, econtext, false))
			{
				node->hj_MatchedOuter = true;

				if (otherqual == NIL || ExecQual(otherqual, econtext, false))
				{
					TupleTableSlot *result;

					result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

					if (isDone != ExprEndResult)
					{
						node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
						return result;
					}
				}

				
				if (node->js.jointype == JOIN_IN)
				{
					node->hj_NeedNewOuter = true;
					break;		
				}
			}
		}

		
		node->hj_NeedNewOuter = true;

		if (!node->hj_MatchedOuter && node->js.jointype == JOIN_LEFT)
		{
			
			econtext->ecxt_innertuple = node->hj_NullInnerTupleSlot;

			if (ExecQual(otherqual, econtext, false))
			{
				
				TupleTableSlot *result;

				result = ExecProject(node->js.ps.ps_ProjInfo, &isDone);

				if (isDone != ExprEndResult)
				{
					node->js.ps.ps_TupFromTlist = (isDone == ExprMultipleResult);
					return result;
				}
			}
		}
	}
}


HashJoinState * ExecInitHashJoin(HashJoin *node, EState *estate, int eflags)
{
	HashJoinState *hjstate;
	Plan	   *outerNode;
	Hash	   *hashNode;
	List	   *lclauses;
	List	   *rclauses;
	List	   *hoperators;
	ListCell   *l;

	
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));

	
	hjstate = makeNode(HashJoinState);
	hjstate->js.ps.plan = (Plan *) node;
	hjstate->js.ps.state = estate;

	
	ExecAssignExprContext(estate, &hjstate->js.ps);

	
	hjstate->js.ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->join.plan.targetlist, (PlanState *) hjstate);
	hjstate->js.ps.qual = (List *)
		ExecInitExpr((Expr *) node->join.plan.qual, (PlanState *) hjstate);
	hjstate->js.jointype = node->join.jointype;
	hjstate->js.joinqual = (List *)
		ExecInitExpr((Expr *) node->join.joinqual, (PlanState *) hjstate);
	hjstate->hashclauses = (List *)
		ExecInitExpr((Expr *) node->hashclauses, (PlanState *) hjstate);

	
	outerNode = outerPlan(node);
	hashNode = (Hash *) innerPlan(node);

	outerPlanState(hjstate) = ExecInitNode(outerNode, estate, eflags);
	innerPlanState(hjstate) = ExecInitNode((Plan *) hashNode, estate, eflags);



	
	ExecInitResultTupleSlot(estate, &hjstate->js.ps);
	hjstate->hj_OuterTupleSlot = ExecInitExtraTupleSlot(estate);

	switch (node->join.jointype)
	{
		case JOIN_INNER:
		case JOIN_IN:
			break;
		case JOIN_LEFT:
			hjstate->hj_NullInnerTupleSlot = ExecInitNullTupleSlot(estate, ExecGetResultType(innerPlanState(hjstate)));

			break;
		default:
			elog(ERROR, "unrecognized join type: %d", (int) node->join.jointype);
	}

	
	{
		HashState  *hashstate = (HashState *) innerPlanState(hjstate);
		TupleTableSlot *slot = hashstate->ps.ps_ResultTupleSlot;

		hjstate->hj_HashTupleSlot = slot;
	}

	
	ExecAssignResultTypeFromTL(&hjstate->js.ps);
	ExecAssignProjectionInfo(&hjstate->js.ps);

	ExecSetSlotDescriptor(hjstate->hj_OuterTupleSlot, ExecGetResultType(outerPlanState(hjstate)));

	
	hjstate->hj_HashTable = NULL;
	hjstate->hj_FirstOuterTupleSlot = NULL;

	hjstate->hj_CurHashValue = 0;
	hjstate->hj_CurBucketNo = 0;
	hjstate->hj_CurTuple = NULL;

	
	lclauses = NIL;
	rclauses = NIL;
	hoperators = NIL;
	foreach(l, hjstate->hashclauses)
	{
		FuncExprState *fstate = (FuncExprState *) lfirst(l);
		OpExpr	   *hclause;

		Assert(IsA(fstate, FuncExprState));
		hclause = (OpExpr *) fstate->xprstate.expr;
		Assert(IsA(hclause, OpExpr));
		lclauses = lappend(lclauses, linitial(fstate->args));
		rclauses = lappend(rclauses, lsecond(fstate->args));
		hoperators = lappend_oid(hoperators, hclause->opno);
	}
	hjstate->hj_OuterHashKeys = lclauses;
	hjstate->hj_InnerHashKeys = rclauses;
	hjstate->hj_HashOperators = hoperators;
	
	((HashState *) innerPlanState(hjstate))->hashkeys = rclauses;

	hjstate->js.ps.ps_OuterTupleSlot = NULL;
	hjstate->js.ps.ps_TupFromTlist = false;
	hjstate->hj_NeedNewOuter = true;
	hjstate->hj_MatchedOuter = false;
	hjstate->hj_OuterNotEmpty = false;

	return hjstate;
}

int ExecCountSlotsHashJoin(HashJoin *node)
{
	return ExecCountSlotsNode(outerPlan(node)) + ExecCountSlotsNode(innerPlan(node)) + HASHJOIN_NSLOTS;

}


void ExecEndHashJoin(HashJoinState *node)
{
	
	if (node->hj_HashTable)
	{
		ExecHashTableDestroy(node->hj_HashTable);
		node->hj_HashTable = NULL;
	}

	
	ExecFreeExprContext(&node->js.ps);

	
	ExecClearTuple(node->js.ps.ps_ResultTupleSlot);
	ExecClearTuple(node->hj_OuterTupleSlot);
	ExecClearTuple(node->hj_HashTupleSlot);

	
	ExecEndNode(outerPlanState(node));
	ExecEndNode(innerPlanState(node));
}


static TupleTableSlot * ExecHashJoinOuterGetTuple(PlanState *outerNode, HashJoinState *hjstate, uint32 *hashvalue)


{
	HashJoinTable hashtable = hjstate->hj_HashTable;
	int			curbatch = hashtable->curbatch;
	TupleTableSlot *slot;

	if (curbatch == 0)			
	{
		
		slot = hjstate->hj_FirstOuterTupleSlot;
		if (!TupIsNull(slot))
			hjstate->hj_FirstOuterTupleSlot = NULL;
		else slot = ExecProcNode(outerNode);

		while (!TupIsNull(slot))
		{
			
			ExprContext *econtext = hjstate->js.ps.ps_ExprContext;

			econtext->ecxt_outertuple = slot;
			if (ExecHashGetHashValue(hashtable, econtext, hjstate->hj_OuterHashKeys, true, (hjstate->js.jointype == JOIN_LEFT), hashvalue))



			{
				
				hjstate->hj_OuterNotEmpty = true;

				return slot;
			}

			
			slot = ExecProcNode(outerNode);
		}

		
		curbatch = ExecHashJoinNewBatch(hjstate);
	}

	
	while (curbatch < hashtable->nbatch)
	{
		slot = ExecHashJoinGetSavedTuple(hjstate, hashtable->outerBatchFile[curbatch], hashvalue, hjstate->hj_OuterTupleSlot);


		if (!TupIsNull(slot))
			return slot;
		curbatch = ExecHashJoinNewBatch(hjstate);
	}

	
	return NULL;
}


static int ExecHashJoinNewBatch(HashJoinState *hjstate)
{
	HashJoinTable hashtable = hjstate->hj_HashTable;
	int			nbatch;
	int			curbatch;
	BufFile    *innerFile;
	TupleTableSlot *slot;
	uint32		hashvalue;

start_over:
	nbatch = hashtable->nbatch;
	curbatch = hashtable->curbatch;

	if (curbatch > 0)
	{
		
		if (hashtable->outerBatchFile[curbatch])
			BufFileClose(hashtable->outerBatchFile[curbatch]);
		hashtable->outerBatchFile[curbatch] = NULL;
	}

	
	curbatch++;
	while (curbatch < nbatch && (hashtable->outerBatchFile[curbatch] == NULL || hashtable->innerBatchFile[curbatch] == NULL))

	{
		if (hashtable->outerBatchFile[curbatch] && hjstate->js.jointype == JOIN_LEFT)
			break;				
		if (hashtable->innerBatchFile[curbatch] && nbatch != hashtable->nbatch_original)
			break;				
		if (hashtable->outerBatchFile[curbatch] && nbatch != hashtable->nbatch_outstart)
			break;				
		
		
		if (hashtable->innerBatchFile[curbatch])
			BufFileClose(hashtable->innerBatchFile[curbatch]);
		hashtable->innerBatchFile[curbatch] = NULL;
		if (hashtable->outerBatchFile[curbatch])
			BufFileClose(hashtable->outerBatchFile[curbatch]);
		hashtable->outerBatchFile[curbatch] = NULL;
		curbatch++;
	}

	if (curbatch >= nbatch)
		return curbatch;		

	hashtable->curbatch = curbatch;

	
	ExecHashTableReset(hashtable);

	innerFile = hashtable->innerBatchFile[curbatch];

	if (innerFile != NULL)
	{
		if (BufFileSeek(innerFile, 0, 0L, SEEK_SET))
			ereport(ERROR, (errcode_for_file_access(), errmsg("could not rewind hash-join temporary file: %m")));


		while ((slot = ExecHashJoinGetSavedTuple(hjstate, innerFile, &hashvalue, hjstate->hj_HashTupleSlot)))


		{
			
			ExecHashTableInsert(hashtable, slot, hashvalue);
		}

		
		BufFileClose(innerFile);
		hashtable->innerBatchFile[curbatch] = NULL;
	}

	
	if (hashtable->outerBatchFile[curbatch] == NULL)
		goto start_over;

	
	if (BufFileSeek(hashtable->outerBatchFile[curbatch], 0, 0L, SEEK_SET))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not rewind hash-join temporary file: %m")));


	return curbatch;
}


void ExecHashJoinSaveTuple(MinimalTuple tuple, uint32 hashvalue, BufFile **fileptr)

{
	BufFile    *file = *fileptr;
	size_t		written;

	if (file == NULL)
	{
		
		file = BufFileCreateTemp(false);
		*fileptr = file;
	}

	written = BufFileWrite(file, (void *) &hashvalue, sizeof(uint32));
	if (written != sizeof(uint32))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not write to hash-join temporary file: %m")));


	written = BufFileWrite(file, (void *) tuple, tuple->t_len);
	if (written != tuple->t_len)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not write to hash-join temporary file: %m")));

}


static TupleTableSlot * ExecHashJoinGetSavedTuple(HashJoinState *hjstate, BufFile *file, uint32 *hashvalue, TupleTableSlot *tupleSlot)



{
	uint32		header[2];
	size_t		nread;
	MinimalTuple tuple;

	
	nread = BufFileRead(file, (void *) header, sizeof(header));
	if (nread == 0)				
	{
		ExecClearTuple(tupleSlot);
		return NULL;
	}
	if (nread != sizeof(header))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not read from hash-join temporary file: %m")));

	*hashvalue = header[0];
	tuple = (MinimalTuple) palloc(header[1]);
	tuple->t_len = header[1];
	nread = BufFileRead(file, (void *) ((char *) tuple + sizeof(uint32)), header[1] - sizeof(uint32));

	if (nread != header[1] - sizeof(uint32))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not read from hash-join temporary file: %m")));

	return ExecStoreMinimalTuple(tuple, tupleSlot, true);
}


void ExecReScanHashJoin(HashJoinState *node, ExprContext *exprCtxt)
{
	
	if (node->hj_HashTable != NULL)
	{
		if (node->hj_HashTable->nbatch == 1 && ((PlanState *) node)->righttree->chgParam == NULL)
		{
			
			node->hj_OuterNotEmpty = false;
		}
		else {
			
			ExecHashTableDestroy(node->hj_HashTable);
			node->hj_HashTable = NULL;

			
			if (((PlanState *) node)->righttree->chgParam == NULL)
				ExecReScan(((PlanState *) node)->righttree, exprCtxt);
		}
	}

	
	node->hj_CurHashValue = 0;
	node->hj_CurBucketNo = 0;
	node->hj_CurTuple = NULL;

	node->js.ps.ps_OuterTupleSlot = NULL;
	node->js.ps.ps_TupFromTlist = false;
	node->hj_NeedNewOuter = true;
	node->hj_MatchedOuter = false;
	node->hj_FirstOuterTupleSlot = NULL;

	
	if (((PlanState *) node)->lefttree->chgParam == NULL)
		ExecReScan(((PlanState *) node)->lefttree, exprCtxt);
}
