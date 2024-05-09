
























static Datum ExecEvalArrayRef(ArrayRefExprState *astate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalAggref(AggrefExprState *aggref, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalVar(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalWholeRowVar(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalConst(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalParam(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static void ShutdownFuncExpr(Datum arg);
static TupleDesc get_cached_rowtype(Oid type_id, int32 typmod, TupleDesc *cache_field, ExprContext *econtext);
static void ShutdownTupleDescRef(Datum arg);
static ExprDoneCond ExecEvalFuncArgs(FunctionCallInfo fcinfo, List *argList, ExprContext *econtext);
static Datum ExecMakeFunctionResultNoSets(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalFunc(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalOper(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalDistinct(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalScalarArrayOp(ScalarArrayOpExprState *sstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalNot(BoolExprState *notclause, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalOr(BoolExprState *orExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalAnd(BoolExprState *andExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalConvertRowtype(ConvertRowtypeExprState *cstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalCase(CaseExprState *caseExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalCaseTestExpr(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalArray(ArrayExprState *astate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalRow(RowExprState *rstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalRowCompare(RowCompareExprState *rstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalCoalesce(CoalesceExprState *coalesceExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalMinMax(MinMaxExprState *minmaxExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalXml(XmlExprState *xmlExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);
static Datum ExecEvalNullIf(FuncExprState *nullIfExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalNullTest(NullTestState *nstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalBooleanTest(GenericExprState *bstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalCoerceToDomain(CoerceToDomainState *cstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalCoerceToDomainValue(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalFieldSelect(FieldSelectState *fstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalFieldStore(FieldStoreState *fstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);

static Datum ExecEvalRelabelType(GenericExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone);







static Datum ExecEvalArrayRef(ArrayRefExprState *astate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	ArrayRef   *arrayRef = (ArrayRef *) astate->xprstate.expr;
	ArrayType  *array_source;
	ArrayType  *resultArray;
	bool		isAssignment = (arrayRef->refassgnexpr != NULL);
	bool		eisnull;
	ListCell   *l;
	int			i = 0, j = 0;
	IntArray	upper, lower;
	int		   *lIndex;

	array_source = (ArrayType *)
		DatumGetPointer(ExecEvalExpr(astate->refexpr, econtext, isNull, isDone));



	
	if (*isNull)
	{
		if (isDone && *isDone == ExprEndResult)
			return (Datum) NULL;	
		if (!isAssignment)
			return (Datum) NULL;
	}

	foreach(l, astate->refupperindexpr)
	{
		ExprState  *eltstate = (ExprState *) lfirst(l);

		if (i >= MAXDIM)
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", i, MAXDIM)));



		upper.indx[i++] = DatumGetInt32(ExecEvalExpr(eltstate, econtext, &eisnull, NULL));


		
		if (eisnull)
		{
			if (isAssignment)
				ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("array subscript in assignment must not be null")));

			*isNull = true;
			return (Datum) NULL;
		}
	}

	if (astate->reflowerindexpr != NIL)
	{
		foreach(l, astate->reflowerindexpr)
		{
			ExprState  *eltstate = (ExprState *) lfirst(l);

			if (j >= MAXDIM)
				ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", i, MAXDIM)));



			lower.indx[j++] = DatumGetInt32(ExecEvalExpr(eltstate, econtext, &eisnull, NULL));


			
			if (eisnull)
			{
				if (isAssignment)
					ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("array subscript in assignment must not be null")));

				*isNull = true;
				return (Datum) NULL;
			}
		}
		
		if (i != j)
			elog(ERROR, "upper and lower index lists are not same length");
		lIndex = lower.indx;
	}
	else lIndex = NULL;

	if (isAssignment)
	{
		Datum		sourceData;

		
		sourceData = ExecEvalExpr(astate->refassgnexpr, econtext, &eisnull, NULL);



		
		if (astate->refattrlength > 0)	
			if (eisnull || *isNull)
				return PointerGetDatum(array_source);

		
		if (*isNull)
		{
			array_source = construct_empty_array(arrayRef->refelemtype);
			*isNull = false;
		}

		if (lIndex == NULL)
			resultArray = array_set(array_source, i, upper.indx, sourceData, eisnull, astate->refattrlength, astate->refelemlength, astate->refelembyval, astate->refelemalign);






		else resultArray = array_set_slice(array_source, i, upper.indx, lower.indx, (ArrayType *) DatumGetPointer(sourceData), eisnull, astate->refattrlength, astate->refelemlength, astate->refelembyval, astate->refelemalign);







		return PointerGetDatum(resultArray);
	}

	if (lIndex == NULL)
		return array_ref(array_source, i, upper.indx, astate->refattrlength, astate->refelemlength, astate->refelembyval, astate->refelemalign, isNull);




	else {
		resultArray = array_get_slice(array_source, i, upper.indx, lower.indx, astate->refattrlength, astate->refelemlength, astate->refelembyval, astate->refelemalign);




		return PointerGetDatum(resultArray);
	}
}



static Datum ExecEvalAggref(AggrefExprState *aggref, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	if (isDone)
		*isDone = ExprSingleResult;

	if (econtext->ecxt_aggvalues == NULL)		
		elog(ERROR, "no aggregates in this expression context");

	*isNull = econtext->ecxt_aggnulls[aggref->aggno];
	return econtext->ecxt_aggvalues[aggref->aggno];
}


static Datum ExecEvalVar(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	Var		   *variable = (Var *) exprstate->expr;
	TupleTableSlot *slot;
	AttrNumber	attnum;

	if (isDone)
		*isDone = ExprSingleResult;

	
	attnum = variable->varattno;

	switch (variable->varno)
	{
		case INNER:				
			slot = econtext->ecxt_innertuple;
			Assert(attnum > 0);
			break;

		case OUTER:				
			slot = econtext->ecxt_outertuple;
			Assert(attnum > 0);
			break;

		default:				
			slot = econtext->ecxt_scantuple;
			break;
	}



	
	if (attnum > 0)
	{
		TupleDesc	tuple_type = slot->tts_tupleDescriptor;

		
		Assert(attnum <= tuple_type->natts);

		
		Assert(variable->vartype == tuple_type->attrs[attnum - 1]->atttypid || tuple_type->attrs[attnum - 1]->attisdropped);
	}


	return slot_getattr(slot, attnum, isNull);
}


static Datum ExecEvalWholeRowVar(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	Var		   *variable = (Var *) exprstate->expr;
	TupleTableSlot *slot;
	HeapTuple	tuple;
	TupleDesc	tupleDesc;
	HeapTupleHeader dtuple;

	if (isDone)
		*isDone = ExprSingleResult;
	*isNull = false;

	Assert(variable->varattno == InvalidAttrNumber);

	
	Assert(variable->varno != INNER);
	Assert(variable->varno != OUTER);
	slot = econtext->ecxt_scantuple;

	tuple = ExecFetchSlotTuple(slot);
	tupleDesc = slot->tts_tupleDescriptor;

	
	dtuple = (HeapTupleHeader) palloc(tuple->t_len);
	memcpy((char *) dtuple, (char *) tuple->t_data, tuple->t_len);

	HeapTupleHeaderSetDatumLength(dtuple, tuple->t_len);

	
	if (variable->vartype != RECORDOID)
	{
		HeapTupleHeaderSetTypeId(dtuple, variable->vartype);
		HeapTupleHeaderSetTypMod(dtuple, variable->vartypmod);
	}
	else {
		if (tupleDesc->tdtypeid == RECORDOID && tupleDesc->tdtypmod < 0)
			assign_record_type_typmod(tupleDesc);
		HeapTupleHeaderSetTypeId(dtuple, tupleDesc->tdtypeid);
		HeapTupleHeaderSetTypMod(dtuple, tupleDesc->tdtypmod);
	}

	return PointerGetDatum(dtuple);
}


static Datum ExecEvalConst(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	Const	   *con = (Const *) exprstate->expr;

	if (isDone)
		*isDone = ExprSingleResult;

	*isNull = con->constisnull;
	return con->constvalue;
}


static Datum ExecEvalParam(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	Param	   *expression = (Param *) exprstate->expr;
	int			thisParamId = expression->paramid;

	if (isDone)
		*isDone = ExprSingleResult;

	if (expression->paramkind == PARAM_EXEC)
	{
		
		ParamExecData *prm;

		prm = &(econtext->ecxt_param_exec_vals[thisParamId]);
		if (prm->execPlan != NULL)
		{
			
			ExecSetParamPlan(prm->execPlan, econtext);
			
			Assert(prm->execPlan == NULL);
		}
		*isNull = prm->isnull;
		return prm->value;
	}
	else {
		
		ParamListInfo paramInfo = econtext->ecxt_param_list_info;

		Assert(expression->paramkind == PARAM_EXTERN);
		if (paramInfo && thisParamId > 0 && thisParamId <= paramInfo->numParams)
		{
			ParamExternData *prm = &paramInfo->params[thisParamId - 1];

			if (OidIsValid(prm->ptype))
			{
				Assert(prm->ptype == expression->paramtype);
				*isNull = prm->isnull;
				return prm->value;
			}
		}
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("no value found for parameter %d", thisParamId)));

		return (Datum) 0;		
	}
}





Datum GetAttributeByNum(HeapTupleHeader tuple, AttrNumber attrno, bool *isNull)


{
	Datum		result;
	Oid			tupType;
	int32		tupTypmod;
	TupleDesc	tupDesc;
	HeapTupleData tmptup;

	if (!AttributeNumberIsValid(attrno))
		elog(ERROR, "invalid attribute number %d", attrno);

	if (isNull == NULL)
		elog(ERROR, "a NULL isNull pointer was passed");

	if (tuple == NULL)
	{
		
		*isNull = true;
		return (Datum) 0;
	}

	tupType = HeapTupleHeaderGetTypeId(tuple);
	tupTypmod = HeapTupleHeaderGetTypMod(tuple);
	tupDesc = lookup_rowtype_tupdesc(tupType, tupTypmod);

	
	tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
	ItemPointerSetInvalid(&(tmptup.t_self));
	tmptup.t_tableOid = InvalidOid;
	tmptup.t_data = tuple;

	result = heap_getattr(&tmptup, attrno, tupDesc, isNull);



	ReleaseTupleDesc(tupDesc);

	return result;
}

Datum GetAttributeByName(HeapTupleHeader tuple, const char *attname, bool *isNull)
{
	AttrNumber	attrno;
	Datum		result;
	Oid			tupType;
	int32		tupTypmod;
	TupleDesc	tupDesc;
	HeapTupleData tmptup;
	int			i;

	if (attname == NULL)
		elog(ERROR, "invalid attribute name");

	if (isNull == NULL)
		elog(ERROR, "a NULL isNull pointer was passed");

	if (tuple == NULL)
	{
		
		*isNull = true;
		return (Datum) 0;
	}

	tupType = HeapTupleHeaderGetTypeId(tuple);
	tupTypmod = HeapTupleHeaderGetTypMod(tuple);
	tupDesc = lookup_rowtype_tupdesc(tupType, tupTypmod);

	attrno = InvalidAttrNumber;
	for (i = 0; i < tupDesc->natts; i++)
	{
		if (namestrcmp(&(tupDesc->attrs[i]->attname), attname) == 0)
		{
			attrno = tupDesc->attrs[i]->attnum;
			break;
		}
	}

	if (attrno == InvalidAttrNumber)
		elog(ERROR, "attribute \"%s\" does not exist", attname);

	
	tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
	ItemPointerSetInvalid(&(tmptup.t_self));
	tmptup.t_tableOid = InvalidOid;
	tmptup.t_data = tuple;

	result = heap_getattr(&tmptup, attrno, tupDesc, isNull);



	ReleaseTupleDesc(tupDesc);

	return result;
}


void init_fcache(Oid foid, FuncExprState *fcache, MemoryContext fcacheCxt)
{
	AclResult	aclresult;

	
	aclresult = pg_proc_aclcheck(foid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(foid));

	
	if (list_length(fcache->args) > FUNC_MAX_ARGS)
		ereport(ERROR, (errcode(ERRCODE_TOO_MANY_ARGUMENTS), errmsg("cannot pass more than %d arguments to a function", FUNC_MAX_ARGS)));



	
	fmgr_info_cxt(foid, &(fcache->func), fcacheCxt);

	
	fcache->setArgsValid = false;
	fcache->shutdown_reg = false;
	fcache->func.fn_expr = (Node *) fcache->xprstate.expr;
}


static void ShutdownFuncExpr(Datum arg)
{
	FuncExprState *fcache = (FuncExprState *) DatumGetPointer(arg);

	
	fcache->setArgsValid = false;

	
	fcache->shutdown_reg = false;
}


static TupleDesc get_cached_rowtype(Oid type_id, int32 typmod, TupleDesc *cache_field, ExprContext *econtext)

{
	TupleDesc	tupDesc = *cache_field;

	
	if (tupDesc == NULL || type_id != tupDesc->tdtypeid || typmod != tupDesc->tdtypmod)

	{
		tupDesc = lookup_rowtype_tupdesc(type_id, typmod);

		if (*cache_field)
		{
			
			ReleaseTupleDesc(*cache_field);
		}
		else {
			
			RegisterExprContextCallback(econtext, ShutdownTupleDescRef, PointerGetDatum(cache_field));

		}
		*cache_field = tupDesc;
	}
	return tupDesc;
}


static void ShutdownTupleDescRef(Datum arg)
{
	TupleDesc  *cache_field = (TupleDesc *) DatumGetPointer(arg);

	if (*cache_field)
		ReleaseTupleDesc(*cache_field);
	*cache_field = NULL;
}


static ExprDoneCond ExecEvalFuncArgs(FunctionCallInfo fcinfo, List *argList, ExprContext *econtext)


{
	ExprDoneCond argIsDone;
	int			i;
	ListCell   *arg;

	argIsDone = ExprSingleResult;		

	i = 0;
	foreach(arg, argList)
	{
		ExprState  *argstate = (ExprState *) lfirst(arg);
		ExprDoneCond thisArgIsDone;

		fcinfo->arg[i] = ExecEvalExpr(argstate, econtext, &fcinfo->argnull[i], &thisArgIsDone);



		if (thisArgIsDone != ExprSingleResult)
		{
			
			if (argIsDone != ExprSingleResult)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("functions and operators can take at most one set argument")));

			argIsDone = thisArgIsDone;
		}
		i++;
	}

	fcinfo->nargs = i;

	return argIsDone;
}


Datum ExecMakeFunctionResult(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	List	   *arguments = fcache->args;
	Datum		result;
	FunctionCallInfoData fcinfo;
	ReturnSetInfo rsinfo;		
	ExprDoneCond argDone;
	bool		hasSetArg;
	int			i;

	
	check_stack_depth();

	
	if (!fcache->setArgsValid)
	{
		
		InitFunctionCallInfoData(fcinfo, &(fcache->func), 0, NULL, NULL);
		argDone = ExecEvalFuncArgs(&fcinfo, arguments, econtext);
		if (argDone == ExprEndResult)
		{
			
			*isNull = true;
			if (isDone)
				*isDone = ExprEndResult;
			else ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));


			return (Datum) 0;
		}
		hasSetArg = (argDone != ExprSingleResult);
	}
	else {
		
		memcpy(&fcinfo, &fcache->setArgs, sizeof(fcinfo));
		hasSetArg = fcache->setHasSetArg;
		
		fcache->setArgsValid = false;
	}

	
	if (fcache->func.fn_retset)
	{
		fcinfo.resultinfo = (Node *) &rsinfo;
		rsinfo.type = T_ReturnSetInfo;
		rsinfo.econtext = econtext;
		rsinfo.expectedDesc = NULL;
		rsinfo.allowedModes = (int) SFRM_ValuePerCall;
		rsinfo.returnMode = SFRM_ValuePerCall;
		
		rsinfo.setResult = NULL;
		rsinfo.setDesc = NULL;
	}

	
	if (fcache->func.fn_retset || hasSetArg)
	{
		
		if (isDone == NULL)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));


		
		for (;;)
		{
			
			bool		callit = true;

			if (fcache->func.fn_strict)
			{
				for (i = 0; i < fcinfo.nargs; i++)
				{
					if (fcinfo.argnull[i])
					{
						callit = false;
						break;
					}
				}
			}

			if (callit)
			{
				fcinfo.isnull = false;
				rsinfo.isDone = ExprSingleResult;
				result = FunctionCallInvoke(&fcinfo);
				*isNull = fcinfo.isnull;
				*isDone = rsinfo.isDone;
			}
			else {
				result = (Datum) 0;
				*isNull = true;
				*isDone = ExprEndResult;
			}

			if (*isDone != ExprEndResult)
			{
				
				if (fcache->func.fn_retset && *isDone == ExprMultipleResult)
				{
					memcpy(&fcache->setArgs, &fcinfo, sizeof(fcinfo));
					fcache->setHasSetArg = hasSetArg;
					fcache->setArgsValid = true;
					
					if (!fcache->shutdown_reg)
					{
						RegisterExprContextCallback(econtext, ShutdownFuncExpr, PointerGetDatum(fcache));

						fcache->shutdown_reg = true;
					}
				}

				
				if (hasSetArg)
					*isDone = ExprMultipleResult;
				break;
			}

			
			if (!hasSetArg)
				break;			

			
			argDone = ExecEvalFuncArgs(&fcinfo, arguments, econtext);

			if (argDone != ExprMultipleResult)
			{
				
				*isNull = true;
				*isDone = ExprEndResult;
				result = (Datum) 0;
				break;
			}

			
		}
	}
	else {
		
		fcache->xprstate.evalfunc = (ExprStateEvalFunc) ExecMakeFunctionResultNoSets;

		if (isDone)
			*isDone = ExprSingleResult;

		
		if (fcache->func.fn_strict)
		{
			for (i = 0; i < fcinfo.nargs; i++)
			{
				if (fcinfo.argnull[i])
				{
					*isNull = true;
					return (Datum) 0;
				}
			}
		}
		fcinfo.isnull = false;
		result = FunctionCallInvoke(&fcinfo);
		*isNull = fcinfo.isnull;
	}

	return result;
}


static Datum ExecMakeFunctionResultNoSets(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	ListCell   *arg;
	Datum		result;
	FunctionCallInfoData fcinfo;
	int			i;

	
	check_stack_depth();

	if (isDone)
		*isDone = ExprSingleResult;

	
	i = 0;
	foreach(arg, fcache->args)
	{
		ExprState  *argstate = (ExprState *) lfirst(arg);

		fcinfo.arg[i] = ExecEvalExpr(argstate, econtext, &fcinfo.argnull[i], NULL);


		i++;
	}

	InitFunctionCallInfoData(fcinfo, &(fcache->func), i, NULL, NULL);

	
	if (fcache->func.fn_strict)
	{
		while (--i >= 0)
		{
			if (fcinfo.argnull[i])
			{
				*isNull = true;
				return (Datum) 0;
			}
		}
	}
		
	result = FunctionCallInvoke(&fcinfo);
	*isNull = fcinfo.isnull;

	return result;
}



Tuplestorestate * ExecMakeTableFunctionResult(ExprState *funcexpr, ExprContext *econtext, TupleDesc expectedDesc, TupleDesc *returnDesc)



{
	Tuplestorestate *tupstore = NULL;
	TupleDesc	tupdesc = NULL;
	Oid			funcrettype;
	bool		returnsTuple;
	bool		returnsSet = false;
	FunctionCallInfoData fcinfo;
	ReturnSetInfo rsinfo;
	HeapTupleData tmptup;
	MemoryContext callerContext;
	MemoryContext oldcontext;
	bool		direct_function_call;
	bool		first_time = true;

	callerContext = CurrentMemoryContext;

	funcrettype = exprType((Node *) funcexpr->expr);

	returnsTuple = type_is_rowtype(funcrettype);

	
	InitFunctionCallInfoData(fcinfo, NULL, 0, NULL, (Node *) &rsinfo);
	rsinfo.type = T_ReturnSetInfo;
	rsinfo.econtext = econtext;
	rsinfo.expectedDesc = expectedDesc;
	rsinfo.allowedModes = (int) (SFRM_ValuePerCall | SFRM_Materialize);
	rsinfo.returnMode = SFRM_ValuePerCall;
	
	rsinfo.setResult = NULL;
	rsinfo.setDesc = NULL;

	
	if (funcexpr && IsA(funcexpr, FuncExprState) && IsA(funcexpr->expr, FuncExpr))
	{
		FuncExprState *fcache = (FuncExprState *) funcexpr;
		ExprDoneCond argDone;

		
		direct_function_call = true;

		
		if (fcache->func.fn_oid == InvalidOid)
		{
			FuncExpr   *func = (FuncExpr *) fcache->xprstate.expr;

			init_fcache(func->funcid, fcache, econtext->ecxt_per_query_memory);
		}
		returnsSet = fcache->func.fn_retset;

		
		fcinfo.flinfo = &(fcache->func);
		argDone = ExecEvalFuncArgs(&fcinfo, fcache->args, econtext);
		
		if (argDone != ExprSingleResult)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));


		
		if (fcache->func.fn_strict)
		{
			int			i;

			for (i = 0; i < fcinfo.nargs; i++)
			{
				if (fcinfo.argnull[i])
					goto no_function_result;
			}
		}
	}
	else {
		
		direct_function_call = false;
	}

	
	MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	
	for (;;)
	{
		Datum		result;
		HeapTuple	tuple;

		CHECK_FOR_INTERRUPTS();

		
		ResetExprContext(econtext);

		
		if (direct_function_call)
		{
			fcinfo.isnull = false;
			rsinfo.isDone = ExprSingleResult;
			result = FunctionCallInvoke(&fcinfo);
		}
		else {
			result = ExecEvalExpr(funcexpr, econtext, &fcinfo.isnull, &rsinfo.isDone);
		}

		
		if (rsinfo.returnMode == SFRM_ValuePerCall)
		{
			
			if (rsinfo.isDone == ExprEndResult)
				break;

			
			if (returnsTuple && fcinfo.isnull)
			{
				if (!returnsSet)
					break;
				ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("function returning set of rows cannot return null value")));

			}

			
			if (first_time)
			{
				oldcontext = MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
				if (returnsTuple)
				{
					
					HeapTupleHeader td;

					td = DatumGetHeapTupleHeader(result);
					tupdesc = lookup_rowtype_tupdesc_copy(HeapTupleHeaderGetTypeId(td), HeapTupleHeaderGetTypMod(td));
				}
				else {
					
					tupdesc = CreateTemplateTupleDesc(1, false);
					TupleDescInitEntry(tupdesc, (AttrNumber) 1, "column", funcrettype, -1, 0);




				}
				tupstore = tuplestore_begin_heap(true, false, work_mem);
				MemoryContextSwitchTo(oldcontext);
				rsinfo.setResult = tupstore;
				rsinfo.setDesc = tupdesc;
			}

			
			if (returnsTuple)
			{
				HeapTupleHeader td;

				td = DatumGetHeapTupleHeader(result);

				
				tmptup.t_len = HeapTupleHeaderGetDatumLength(td);
				tmptup.t_data = td;
				tuple = &tmptup;
			}
			else {
				tuple = heap_form_tuple(tupdesc, &result, &fcinfo.isnull);
			}

			oldcontext = MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
			tuplestore_puttuple(tupstore, tuple);
			MemoryContextSwitchTo(oldcontext);

			
			if (rsinfo.isDone != ExprMultipleResult)
				break;
		}
		else if (rsinfo.returnMode == SFRM_Materialize)
		{
			
			if (!first_time || rsinfo.isDone != ExprSingleResult)
				ereport(ERROR, (errcode(ERRCODE_E_R_I_E_SRF_PROTOCOL_VIOLATED), errmsg("table-function protocol for materialize mode was not followed")));

			
			break;
		}
		else ereport(ERROR, (errcode(ERRCODE_E_R_I_E_SRF_PROTOCOL_VIOLATED), errmsg("unrecognized table-function returnMode: %d", (int) rsinfo.returnMode)));




		first_time = false;
	}

no_function_result:

	
	if (rsinfo.setResult == NULL)
	{
		MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
		tupstore = tuplestore_begin_heap(true, false, work_mem);
		rsinfo.setResult = tupstore;
		if (!returnsSet)
		{
			int			natts = expectedDesc->natts;
			Datum	   *nulldatums;
			bool	   *nullflags;
			HeapTuple	tuple;

			MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
			nulldatums = (Datum *) palloc0(natts * sizeof(Datum));
			nullflags = (bool *) palloc(natts * sizeof(bool));
			memset(nullflags, true, natts * sizeof(bool));
			tuple = heap_form_tuple(expectedDesc, nulldatums, nullflags);
			MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
			tuplestore_puttuple(tupstore, tuple);
		}
	}

	MemoryContextSwitchTo(callerContext);

	
	*returnDesc = rsinfo.setDesc;
	return rsinfo.setResult;
}





static Datum ExecEvalFunc(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	
	FuncExpr   *func = (FuncExpr *) fcache->xprstate.expr;

	
	init_fcache(func->funcid, fcache, econtext->ecxt_per_query_memory);

	
	fcache->xprstate.evalfunc = (ExprStateEvalFunc) ExecMakeFunctionResult;

	return ExecMakeFunctionResult(fcache, econtext, isNull, isDone);
}


static Datum ExecEvalOper(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	
	OpExpr	   *op = (OpExpr *) fcache->xprstate.expr;

	
	init_fcache(op->opfuncid, fcache, econtext->ecxt_per_query_memory);

	
	fcache->xprstate.evalfunc = (ExprStateEvalFunc) ExecMakeFunctionResult;

	return ExecMakeFunctionResult(fcache, econtext, isNull, isDone);
}


static Datum ExecEvalDistinct(FuncExprState *fcache, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	Datum		result;
	FunctionCallInfoData fcinfo;
	ExprDoneCond argDone;
	List	   *argList;

	
	*isNull = false;
	if (isDone)
		*isDone = ExprSingleResult;

	
	if (fcache->func.fn_oid == InvalidOid)
	{
		DistinctExpr *op = (DistinctExpr *) fcache->xprstate.expr;

		init_fcache(op->opfuncid, fcache, econtext->ecxt_per_query_memory);
		Assert(!fcache->func.fn_retset);
	}

	
	argList = fcache->args;

	
	InitFunctionCallInfoData(fcinfo, &(fcache->func), 0, NULL, NULL);
	argDone = ExecEvalFuncArgs(&fcinfo, argList, econtext);
	if (argDone != ExprSingleResult)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("IS DISTINCT FROM does not support set arguments")));

	Assert(fcinfo.nargs == 2);

	if (fcinfo.argnull[0] && fcinfo.argnull[1])
	{
		
		result = BoolGetDatum(FALSE);
	}
	else if (fcinfo.argnull[0] || fcinfo.argnull[1])
	{
		
		result = BoolGetDatum(TRUE);
	}
	else {
		fcinfo.isnull = false;
		result = FunctionCallInvoke(&fcinfo);
		*isNull = fcinfo.isnull;
		
		result = BoolGetDatum(!DatumGetBool(result));
	}

	return result;
}


static Datum ExecEvalScalarArrayOp(ScalarArrayOpExprState *sstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	ScalarArrayOpExpr *opexpr = (ScalarArrayOpExpr *) sstate->fxprstate.xprstate.expr;
	bool		useOr = opexpr->useOr;
	ArrayType  *arr;
	int			nitems;
	Datum		result;
	bool		resultnull;
	FunctionCallInfoData fcinfo;
	ExprDoneCond argDone;
	int			i;
	int16		typlen;
	bool		typbyval;
	char		typalign;
	char	   *s;
	bits8	   *bitmap;
	int			bitmask;

	
	*isNull = false;
	if (isDone)
		*isDone = ExprSingleResult;

	
	if (sstate->fxprstate.func.fn_oid == InvalidOid)
	{
		init_fcache(opexpr->opfuncid, &sstate->fxprstate, econtext->ecxt_per_query_memory);
		Assert(!sstate->fxprstate.func.fn_retset);
	}

	
	InitFunctionCallInfoData(fcinfo, &(sstate->fxprstate.func), 0, NULL, NULL);
	argDone = ExecEvalFuncArgs(&fcinfo, sstate->fxprstate.args, econtext);
	if (argDone != ExprSingleResult)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("op ANY/ALL (array) does not support set arguments")));

	Assert(fcinfo.nargs == 2);

	
	if (fcinfo.argnull[1])
	{
		*isNull = true;
		return (Datum) 0;
	}
	
	arr = DatumGetArrayTypeP(fcinfo.arg[1]);

	
	nitems = ArrayGetNItems(ARR_NDIM(arr), ARR_DIMS(arr));
	if (nitems <= 0)
		return BoolGetDatum(!useOr);

	
	if (fcinfo.argnull[0] && sstate->fxprstate.func.fn_strict)
	{
		*isNull = true;
		return (Datum) 0;
	}

	
	if (sstate->element_type != ARR_ELEMTYPE(arr))
	{
		get_typlenbyvalalign(ARR_ELEMTYPE(arr), &sstate->typlen, &sstate->typbyval, &sstate->typalign);


		sstate->element_type = ARR_ELEMTYPE(arr);
	}
	typlen = sstate->typlen;
	typbyval = sstate->typbyval;
	typalign = sstate->typalign;

	result = BoolGetDatum(!useOr);
	resultnull = false;

	
	s = (char *) ARR_DATA_PTR(arr);
	bitmap = ARR_NULLBITMAP(arr);
	bitmask = 1;

	for (i = 0; i < nitems; i++)
	{
		Datum		elt;
		Datum		thisresult;

		
		if (bitmap && (*bitmap & bitmask) == 0)
		{
			fcinfo.arg[1] = (Datum) 0;
			fcinfo.argnull[1] = true;
		}
		else {
			elt = fetch_att(s, typbyval, typlen);
			s = att_addlength(s, typlen, PointerGetDatum(s));
			s = (char *) att_align(s, typalign);
			fcinfo.arg[1] = elt;
			fcinfo.argnull[1] = false;
		}

		
		if (fcinfo.argnull[1] && sstate->fxprstate.func.fn_strict)
		{
			fcinfo.isnull = true;
			thisresult = (Datum) 0;
		}
		else {
			fcinfo.isnull = false;
			thisresult = FunctionCallInvoke(&fcinfo);
		}

		
		if (fcinfo.isnull)
			resultnull = true;
		else if (useOr)
		{
			if (DatumGetBool(thisresult))
			{
				result = BoolGetDatum(true);
				resultnull = false;
				break;			
			}
		}
		else {
			if (!DatumGetBool(thisresult))
			{
				result = BoolGetDatum(false);
				resultnull = false;
				break;			
			}
		}

		
		if (bitmap)
		{
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				bitmap++;
				bitmask = 1;
			}
		}
	}

	*isNull = resultnull;
	return result;
}


static Datum ExecEvalNot(BoolExprState *notclause, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	ExprState  *clause = linitial(notclause->args);
	Datum		expr_value;

	if (isDone)
		*isDone = ExprSingleResult;

	expr_value = ExecEvalExpr(clause, econtext, isNull, NULL);

	
	if (*isNull)
		return expr_value;

	
	return BoolGetDatum(!DatumGetBool(expr_value));
}


static Datum ExecEvalOr(BoolExprState *orExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	List	   *clauses = orExpr->args;
	ListCell   *clause;
	bool		AnyNull;

	if (isDone)
		*isDone = ExprSingleResult;

	AnyNull = false;

	
	foreach(clause, clauses)
	{
		ExprState  *clausestate = (ExprState *) lfirst(clause);
		Datum		clause_value;

		clause_value = ExecEvalExpr(clausestate, econtext, isNull, NULL);

		
		if (*isNull)
			AnyNull = true;		
		else if (DatumGetBool(clause_value))
			return clause_value;
	}

	
	*isNull = AnyNull;
	return BoolGetDatum(false);
}


static Datum ExecEvalAnd(BoolExprState *andExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	List	   *clauses = andExpr->args;
	ListCell   *clause;
	bool		AnyNull;

	if (isDone)
		*isDone = ExprSingleResult;

	AnyNull = false;

	

	foreach(clause, clauses)
	{
		ExprState  *clausestate = (ExprState *) lfirst(clause);
		Datum		clause_value;

		clause_value = ExecEvalExpr(clausestate, econtext, isNull, NULL);

		
		if (*isNull)
			AnyNull = true;		
		else if (!DatumGetBool(clause_value))
			return clause_value;
	}

	
	*isNull = AnyNull;
	return BoolGetDatum(!AnyNull);
}


static Datum ExecEvalConvertRowtype(ConvertRowtypeExprState *cstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	ConvertRowtypeExpr *convert = (ConvertRowtypeExpr *) cstate->xprstate.expr;
	HeapTuple	result;
	Datum		tupDatum;
	HeapTupleHeader tuple;
	HeapTupleData tmptup;
	AttrNumber *attrMap;
	Datum	   *invalues;
	bool	   *inisnull;
	Datum	   *outvalues;
	bool	   *outisnull;
	int			i;
	int			outnatts;

	tupDatum = ExecEvalExpr(cstate->arg, econtext, isNull, isDone);

	
	if (*isNull)
		return tupDatum;

	tuple = DatumGetHeapTupleHeader(tupDatum);

	
	if (cstate->indesc == NULL)
		get_cached_rowtype(exprType((Node *) convert->arg), -1, &cstate->indesc, econtext);
	if (cstate->outdesc == NULL)
		get_cached_rowtype(convert->resulttype, -1, &cstate->outdesc, econtext);

	Assert(HeapTupleHeaderGetTypeId(tuple) == cstate->indesc->tdtypeid);
	Assert(HeapTupleHeaderGetTypMod(tuple) == cstate->indesc->tdtypmod);

	
	if (cstate->attrMap == NULL)
	{
		MemoryContext old_cxt;
		int			n;

		
		old_cxt = MemoryContextSwitchTo(econtext->ecxt_per_query_memory);

		
		n = cstate->outdesc->natts;
		cstate->attrMap = (AttrNumber *) palloc0(n * sizeof(AttrNumber));
		for (i = 0; i < n; i++)
		{
			Form_pg_attribute att = cstate->outdesc->attrs[i];
			char	   *attname;
			Oid			atttypid;
			int32		atttypmod;
			int			j;

			if (att->attisdropped)
				continue;		
			attname = NameStr(att->attname);
			atttypid = att->atttypid;
			atttypmod = att->atttypmod;
			for (j = 0; j < cstate->indesc->natts; j++)
			{
				att = cstate->indesc->attrs[j];
				if (att->attisdropped)
					continue;
				if (strcmp(attname, NameStr(att->attname)) == 0)
				{
					
					if (atttypid != att->atttypid || atttypmod != att->atttypmod)
						elog(ERROR, "attribute \"%s\" of type %s does not match corresponding attribute of type %s", attname, format_type_be(cstate->indesc->tdtypeid), format_type_be(cstate->outdesc->tdtypeid));


					cstate->attrMap[i] = (AttrNumber) (j + 1);
					break;
				}
			}
			if (cstate->attrMap[i] == 0)
				elog(ERROR, "attribute \"%s\" of type %s does not exist", attname, format_type_be(cstate->indesc->tdtypeid));

		}
		
		n = cstate->indesc->natts + 1;	
		cstate->invalues = (Datum *) palloc(n * sizeof(Datum));
		cstate->inisnull = (bool *) palloc(n * sizeof(bool));
		n = cstate->outdesc->natts;
		cstate->outvalues = (Datum *) palloc(n * sizeof(Datum));
		cstate->outisnull = (bool *) palloc(n * sizeof(bool));

		MemoryContextSwitchTo(old_cxt);
	}

	attrMap = cstate->attrMap;
	invalues = cstate->invalues;
	inisnull = cstate->inisnull;
	outvalues = cstate->outvalues;
	outisnull = cstate->outisnull;
	outnatts = cstate->outdesc->natts;

	
	tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
	tmptup.t_data = tuple;

	
	heap_deform_tuple(&tmptup, cstate->indesc, invalues + 1, inisnull + 1);
	invalues[0] = (Datum) 0;
	inisnull[0] = true;

	
	for (i = 0; i < outnatts; i++)
	{
		int			j = attrMap[i];

		outvalues[i] = invalues[j];
		outisnull[i] = inisnull[j];
	}

	
	result = heap_form_tuple(cstate->outdesc, outvalues, outisnull);

	return HeapTupleGetDatum(result);
}


static Datum ExecEvalCase(CaseExprState *caseExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	List	   *clauses = caseExpr->args;
	ListCell   *clause;
	Datum		save_datum;
	bool		save_isNull;

	if (isDone)
		*isDone = ExprSingleResult;

	
	save_datum = econtext->caseValue_datum;
	save_isNull = econtext->caseValue_isNull;

	if (caseExpr->arg)
	{
		econtext->caseValue_datum = ExecEvalExpr(caseExpr->arg, econtext, &econtext->caseValue_isNull, NULL);


	}

	
	foreach(clause, clauses)
	{
		CaseWhenState *wclause = lfirst(clause);
		Datum		clause_value;

		clause_value = ExecEvalExpr(wclause->expr, econtext, isNull, NULL);



		
		if (DatumGetBool(clause_value) && !*isNull)
		{
			econtext->caseValue_datum = save_datum;
			econtext->caseValue_isNull = save_isNull;
			return ExecEvalExpr(wclause->result, econtext, isNull, isDone);


		}
	}

	econtext->caseValue_datum = save_datum;
	econtext->caseValue_isNull = save_isNull;

	if (caseExpr->defresult)
	{
		return ExecEvalExpr(caseExpr->defresult, econtext, isNull, isDone);


	}

	*isNull = true;
	return (Datum) 0;
}


static Datum ExecEvalCaseTestExpr(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	if (isDone)
		*isDone = ExprSingleResult;
	*isNull = econtext->caseValue_isNull;
	return econtext->caseValue_datum;
}


static Datum ExecEvalArray(ArrayExprState *astate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	ArrayExpr  *arrayExpr = (ArrayExpr *) astate->xprstate.expr;
	ArrayType  *result;
	ListCell   *element;
	Oid			element_type = arrayExpr->element_typeid;
	int			ndims = 0;
	int			dims[MAXDIM];
	int			lbs[MAXDIM];

	
	*isNull = false;
	if (isDone)
		*isDone = ExprSingleResult;

	if (!arrayExpr->multidims)
	{
		
		int			nelems;
		Datum	   *dvalues;
		bool	   *dnulls;
		int			i = 0;

		ndims = 1;
		nelems = list_length(astate->elements);

		
		if (nelems == 0)
			return PointerGetDatum(construct_empty_array(element_type));

		dvalues = (Datum *) palloc(nelems * sizeof(Datum));
		dnulls = (bool *) palloc(nelems * sizeof(bool));

		
		foreach(element, astate->elements)
		{
			ExprState  *e = (ExprState *) lfirst(element);

			dvalues[i] = ExecEvalExpr(e, econtext, &dnulls[i], NULL);
			i++;
		}

		
		dims[0] = nelems;
		lbs[0] = 1;

		result = construct_md_array(dvalues, dnulls, ndims, dims, lbs, element_type, astate->elemlength, astate->elembyval, astate->elemalign);



	}
	else {
		
		int			nbytes = 0;
		int			nitems = 0;
		int			outer_nelems = 0;
		int			elem_ndims = 0;
		int		   *elem_dims = NULL;
		int		   *elem_lbs = NULL;
		bool		firstone = true;
		bool		havenulls = false;
		bool		haveempty = false;
		char	  **subdata;
		bits8	  **subbitmaps;
		int		   *subbytes;
		int		   *subnitems;
		int			i;
		int32		dataoffset;
		char	   *dat;
		int			iitem;

		i = list_length(astate->elements);
		subdata = (char **) palloc(i * sizeof(char *));
		subbitmaps = (bits8 **) palloc(i * sizeof(bits8 *));
		subbytes = (int *) palloc(i * sizeof(int));
		subnitems = (int *) palloc(i * sizeof(int));

		
		foreach(element, astate->elements)
		{
			ExprState  *e = (ExprState *) lfirst(element);
			bool		eisnull;
			Datum		arraydatum;
			ArrayType  *array;
			int			this_ndims;

			arraydatum = ExecEvalExpr(e, econtext, &eisnull, NULL);
			
			if (eisnull)
			{
				haveempty = true;
				continue;
			}

			array = DatumGetArrayTypeP(arraydatum);

			
			if (element_type != ARR_ELEMTYPE(array))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("cannot merge incompatible arrays"), errdetail("Array with element type %s cannot be " "included in ARRAY construct with element type %s.", format_type_be(ARR_ELEMTYPE(array)), format_type_be(element_type))));






			this_ndims = ARR_NDIM(array);
			
			if (this_ndims <= 0)
			{
				haveempty = true;
				continue;
			}

			if (firstone)
			{
				
				elem_ndims = this_ndims;
				ndims = elem_ndims + 1;
				if (ndims <= 0 || ndims > MAXDIM)
					ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds "  "the maximum allowed (%d)", ndims, MAXDIM)))


				elem_dims = (int *) palloc(elem_ndims * sizeof(int));
				memcpy(elem_dims, ARR_DIMS(array), elem_ndims * sizeof(int));
				elem_lbs = (int *) palloc(elem_ndims * sizeof(int));
				memcpy(elem_lbs, ARR_LBOUND(array), elem_ndims * sizeof(int));

				firstone = false;
			}
			else {
				
				if (elem_ndims != this_ndims || memcmp(elem_dims, ARR_DIMS(array), elem_ndims * sizeof(int)) != 0 || memcmp(elem_lbs, ARR_LBOUND(array), elem_ndims * sizeof(int)) != 0)



					ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("multidimensional arrays must have array " "expressions with matching dimensions")));


			}

			subdata[outer_nelems] = ARR_DATA_PTR(array);
			subbitmaps[outer_nelems] = ARR_NULLBITMAP(array);
			subbytes[outer_nelems] = ARR_SIZE(array) - ARR_DATA_OFFSET(array);
			nbytes += subbytes[outer_nelems];
			subnitems[outer_nelems] = ArrayGetNItems(this_ndims, ARR_DIMS(array));
			nitems += subnitems[outer_nelems];
			havenulls |= ARR_HASNULL(array);
			outer_nelems++;
		}

		
		if (haveempty)
		{
			if (ndims == 0)		
				return PointerGetDatum(construct_empty_array(element_type));
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("multidimensional arrays must have array " "expressions with matching dimensions")));


		}

		
		dims[0] = outer_nelems;
		lbs[0] = 1;
		for (i = 1; i < ndims; i++)
		{
			dims[i] = elem_dims[i - 1];
			lbs[i] = elem_lbs[i - 1];
		}

		if (havenulls)
		{
			dataoffset = ARR_OVERHEAD_WITHNULLS(ndims, nitems);
			nbytes += dataoffset;
		}
		else {
			dataoffset = 0;		
			nbytes += ARR_OVERHEAD_NONULLS(ndims);
		}

		result = (ArrayType *) palloc(nbytes);
		result->size = nbytes;
		result->ndim = ndims;
		result->dataoffset = dataoffset;
		result->elemtype = element_type;
		memcpy(ARR_DIMS(result), dims, ndims * sizeof(int));
		memcpy(ARR_LBOUND(result), lbs, ndims * sizeof(int));

		dat = ARR_DATA_PTR(result);
		iitem = 0;
		for (i = 0; i < outer_nelems; i++)
		{
			memcpy(dat, subdata[i], subbytes[i]);
			dat += subbytes[i];
			if (havenulls)
				array_bitmap_copy(ARR_NULLBITMAP(result), iitem, subbitmaps[i], 0, subnitems[i]);

			iitem += subnitems[i];
		}
	}

	return PointerGetDatum(result);
}


static Datum ExecEvalRow(RowExprState *rstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	HeapTuple	tuple;
	Datum	   *values;
	bool	   *isnull;
	int			natts;
	ListCell   *arg;
	int			i;

	
	*isNull = false;
	if (isDone)
		*isDone = ExprSingleResult;

	
	natts = rstate->tupdesc->natts;
	values = (Datum *) palloc0(natts * sizeof(Datum));
	isnull = (bool *) palloc(natts * sizeof(bool));

	
	memset(isnull, true, natts * sizeof(bool));

	
	i = 0;
	foreach(arg, rstate->args)
	{
		ExprState  *e = (ExprState *) lfirst(arg);

		values[i] = ExecEvalExpr(e, econtext, &isnull[i], NULL);
		i++;
	}

	tuple = heap_form_tuple(rstate->tupdesc, values, isnull);

	pfree(values);
	pfree(isnull);

	return HeapTupleGetDatum(tuple);
}


static Datum ExecEvalRowCompare(RowCompareExprState *rstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	bool		result;
	RowCompareType rctype = ((RowCompareExpr *) rstate->xprstate.expr)->rctype;
	int32		cmpresult = 0;
	ListCell   *l;
	ListCell   *r;
	int			i;

	if (isDone)
		*isDone = ExprSingleResult;
	*isNull = true;				

	i = 0;
	forboth(l, rstate->largs, r, rstate->rargs)
	{
		ExprState  *le = (ExprState *) lfirst(l);
		ExprState  *re = (ExprState *) lfirst(r);
		FunctionCallInfoData locfcinfo;

		InitFunctionCallInfoData(locfcinfo, &(rstate->funcs[i]), 2, NULL, NULL);
		locfcinfo.arg[0] = ExecEvalExpr(le, econtext, &locfcinfo.argnull[0], NULL);
		locfcinfo.arg[1] = ExecEvalExpr(re, econtext, &locfcinfo.argnull[1], NULL);
		if (rstate->funcs[i].fn_strict && (locfcinfo.argnull[0] || locfcinfo.argnull[1]))
			return (Datum) 0;	
		locfcinfo.isnull = false;
		cmpresult = DatumGetInt32(FunctionCallInvoke(&locfcinfo));
		if (locfcinfo.isnull)
			return (Datum) 0;	
		if (cmpresult != 0)
			break;				
		i++;
	}

	switch (rctype)
	{
			
		case ROWCOMPARE_LT:
			result = (cmpresult < 0);
			break;
		case ROWCOMPARE_LE:
			result = (cmpresult <= 0);
			break;
		case ROWCOMPARE_GE:
			result = (cmpresult >= 0);
			break;
		case ROWCOMPARE_GT:
			result = (cmpresult > 0);
			break;
		default:
			elog(ERROR, "unrecognized RowCompareType: %d", (int) rctype);
			result = 0;			
			break;
	}

	*isNull = false;
	return BoolGetDatum(result);
}


static Datum ExecEvalCoalesce(CoalesceExprState *coalesceExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	ListCell   *arg;

	if (isDone)
		*isDone = ExprSingleResult;

	
	foreach(arg, coalesceExpr->args)
	{
		ExprState  *e = (ExprState *) lfirst(arg);
		Datum		value;

		value = ExecEvalExpr(e, econtext, isNull, NULL);
		if (!*isNull)
			return value;
	}

	
	*isNull = true;
	return (Datum) 0;
}


static Datum ExecEvalMinMax(MinMaxExprState *minmaxExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	Datum		result = (Datum) 0;
	MinMaxOp	op = ((MinMaxExpr *) minmaxExpr->xprstate.expr)->op;
	FunctionCallInfoData locfcinfo;
	ListCell   *arg;

	if (isDone)
		*isDone = ExprSingleResult;
	*isNull = true;				

	InitFunctionCallInfoData(locfcinfo, &minmaxExpr->cfunc, 2, NULL, NULL);
	locfcinfo.argnull[0] = false;
	locfcinfo.argnull[1] = false;

	foreach(arg, minmaxExpr->args)
	{
		ExprState  *e = (ExprState *) lfirst(arg);
		Datum		value;
		bool		valueIsNull;
		int32		cmpresult;

		value = ExecEvalExpr(e, econtext, &valueIsNull, NULL);
		if (valueIsNull)
			continue;			

		if (*isNull)
		{
			
			result = value;
			*isNull = false;
		}
		else {
			
			locfcinfo.arg[0] = result;
			locfcinfo.arg[1] = value;
			locfcinfo.isnull = false;
			cmpresult = DatumGetInt32(FunctionCallInvoke(&locfcinfo));
			if (locfcinfo.isnull)		
				continue;
			if (cmpresult > 0 && op == IS_LEAST)
				result = value;
			else if (cmpresult < 0 && op == IS_GREATEST)
				result = value;
		}
	}

	return result;
}


static Datum ExecEvalXml(XmlExprState *xmlExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	XmlExpr		   *xexpr = (XmlExpr *) xmlExpr->xprstate.expr;
	text 		   *result;
	StringInfoData 	buf;
	Datum			value;
	bool 			isnull;
	ListCell 	   *arg;
	ListCell   *narg;
	int 			i;

	if (isDone)
		*isDone = ExprSingleResult;
	*isNull = true;				

	switch (xexpr->op)
	{
		case IS_XMLCONCAT:
			{
				List *values = NIL;

				foreach(arg, xmlExpr->args)
				{
					ExprState 	*e = (ExprState *) lfirst(arg);

					value = ExecEvalExpr(e, econtext, &isnull, NULL);
					if (!isnull)
						values = lappend(values, DatumGetPointer(value));
				}

				if (list_length(values) > 0)
				{
					*isNull = false;
					return PointerGetDatum(xmlconcat(values));
				}
			}
			break;

		case IS_XMLFOREST:
			initStringInfo(&buf);
			i = 0;
			forboth(arg, xmlExpr->named_args, narg, xexpr->arg_names)
			{
				ExprState 	*e = (ExprState *) lfirst(arg);
				char	*argname = strVal(lfirst(narg));

				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (!isnull)
				{
					appendStringInfo(&buf, "<%s>%s</%s>", argname, map_sql_value_to_xml_value(value, exprType((Node *) e->expr)), argname);


					*isNull = false;
				}
				i++;
			}
			break;

			
		case IS_XMLELEMENT:
			*isNull = false;
			return PointerGetDatum(xmlelement(xmlExpr, econtext));
			break;

		case IS_XMLPARSE:
			{
				ExprState 	*e;
				text	    *data;
				bool		is_document;
				bool		preserve_whitespace;

				
				Assert(list_length(xmlExpr->args) == 3);

				e = (ExprState *) linitial(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (isnull)
					return (Datum) 0;
				data = DatumGetTextP(value);

				e = (ExprState *) lsecond(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (isnull)		
					return (Datum) 0;
				is_document = DatumGetBool(value);

				e = (ExprState *) lthird(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (isnull)		
					return (Datum) 0;
				preserve_whitespace = DatumGetBool(value);

				*isNull = false;

				return PointerGetDatum(xmlparse(data, is_document, preserve_whitespace));

			}
			break;

		case IS_XMLPI:
			{
				ExprState 	*e;
				text	    *arg;

				
				Assert(list_length(xmlExpr->args) <= 1);

				if (xmlExpr->args)
				{
					e = (ExprState *) linitial(xmlExpr->args);
					value = ExecEvalExpr(e, econtext, &isnull, NULL);
					if (isnull)
						arg = NULL;
					else arg = DatumGetTextP(value);
				}
				else {
					arg = NULL;
					isnull = false;
				}

				return PointerGetDatum(xmlpi(xexpr->name, arg, isnull, isNull));
			}
			break;

		case IS_XMLROOT:
			{
				ExprState 	*e;
				xmltype		*data;
				text		*version;
				int			standalone;

				
				Assert(list_length(xmlExpr->args) == 3);

				e = (ExprState *) linitial(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (isnull)
					return (Datum) 0;
				data = DatumGetXmlP(value);

				e = (ExprState *) lsecond(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (isnull)
					version = NULL;
				else version = DatumGetTextP(value);

				e = (ExprState *) lthird(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				standalone = DatumGetInt32(value);

				*isNull = false;

				return PointerGetDatum(xmlroot(data, version, standalone));

			}
			break;

		case IS_DOCUMENT:
			{
				ExprState 	*e;

				
				Assert(list_length(xmlExpr->args) == 1);

				e = (ExprState *) linitial(xmlExpr->args);
				value = ExecEvalExpr(e, econtext, &isnull, NULL);
				if (isnull)
					return (Datum) 0;
				else {
					*isNull = false;
					return BoolGetDatum(xml_is_document(DatumGetXmlP(value)));
				}
			}
			break;
	}

	if (*isNull)
		result = NULL;
	else {
		int		len = buf.len + VARHDRSZ;

		result = palloc(len);
		VARATT_SIZEP(result) = len;
		memcpy(VARDATA(result), buf.data, buf.len);
	}

	pfree(buf.data);
	return PointerGetDatum(result);
}


static Datum ExecEvalNullIf(FuncExprState *nullIfExpr, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	Datum		result;
	FunctionCallInfoData fcinfo;
	ExprDoneCond argDone;
	List	   *argList;

	if (isDone)
		*isDone = ExprSingleResult;

	
	if (nullIfExpr->func.fn_oid == InvalidOid)
	{
		NullIfExpr *op = (NullIfExpr *) nullIfExpr->xprstate.expr;

		init_fcache(op->opfuncid, nullIfExpr, econtext->ecxt_per_query_memory);
		Assert(!nullIfExpr->func.fn_retset);
	}

	
	argList = nullIfExpr->args;

	
	InitFunctionCallInfoData(fcinfo, &(nullIfExpr->func), 0, NULL, NULL);
	argDone = ExecEvalFuncArgs(&fcinfo, argList, econtext);
	if (argDone != ExprSingleResult)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("NULLIF does not support set arguments")));

	Assert(fcinfo.nargs == 2);

	
	if (!fcinfo.argnull[0] && !fcinfo.argnull[1])
	{
		fcinfo.isnull = false;
		result = FunctionCallInvoke(&fcinfo);
		
		if (!fcinfo.isnull && DatumGetBool(result))
		{
			*isNull = true;
			return (Datum) 0;
		}
	}

	
	*isNull = fcinfo.argnull[0];
	return fcinfo.arg[0];
}


static Datum ExecEvalNullTest(NullTestState *nstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	NullTest   *ntest = (NullTest *) nstate->xprstate.expr;
	Datum		result;

	result = ExecEvalExpr(nstate->arg, econtext, isNull, isDone);

	if (isDone && *isDone == ExprEndResult)
		return result;			

	if (nstate->argisrow && !(*isNull))
	{
		HeapTupleHeader tuple;
		Oid			tupType;
		int32		tupTypmod;
		TupleDesc	tupDesc;
		HeapTupleData tmptup;
		int			att;

		tuple = DatumGetHeapTupleHeader(result);

		tupType = HeapTupleHeaderGetTypeId(tuple);
		tupTypmod = HeapTupleHeaderGetTypMod(tuple);

		
		tupDesc = get_cached_rowtype(tupType, tupTypmod, &nstate->argdesc, econtext);

		
		tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
		tmptup.t_data = tuple;

		for (att = 1; att <= tupDesc->natts; att++)
		{
			
			if (tupDesc->attrs[att - 1]->attisdropped)
				continue;
			if (heap_attisnull(&tmptup, att))
			{
				
				if (ntest->nulltesttype == IS_NOT_NULL)
					return BoolGetDatum(false);
			}
			else {
				
				if (ntest->nulltesttype == IS_NULL)
					return BoolGetDatum(false);
			}
		}

		return BoolGetDatum(true);
	}
	else {
		
		switch (ntest->nulltesttype)
		{
			case IS_NULL:
				if (*isNull)
				{
					*isNull = false;
					return BoolGetDatum(true);
				}
				else return BoolGetDatum(false);
			case IS_NOT_NULL:
				if (*isNull)
				{
					*isNull = false;
					return BoolGetDatum(false);
				}
				else return BoolGetDatum(true);
			default:
				elog(ERROR, "unrecognized nulltesttype: %d", (int) ntest->nulltesttype);
				return (Datum) 0;		
		}
	}
}


static Datum ExecEvalBooleanTest(GenericExprState *bstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	BooleanTest *btest = (BooleanTest *) bstate->xprstate.expr;
	Datum		result;

	result = ExecEvalExpr(bstate->arg, econtext, isNull, isDone);

	if (isDone && *isDone == ExprEndResult)
		return result;			

	switch (btest->booltesttype)
	{
		case IS_TRUE:
			if (*isNull)
			{
				*isNull = false;
				return BoolGetDatum(false);
			}
			else if (DatumGetBool(result))
				return BoolGetDatum(true);
			else return BoolGetDatum(false);
		case IS_NOT_TRUE:
			if (*isNull)
			{
				*isNull = false;
				return BoolGetDatum(true);
			}
			else if (DatumGetBool(result))
				return BoolGetDatum(false);
			else return BoolGetDatum(true);
		case IS_FALSE:
			if (*isNull)
			{
				*isNull = false;
				return BoolGetDatum(false);
			}
			else if (DatumGetBool(result))
				return BoolGetDatum(false);
			else return BoolGetDatum(true);
		case IS_NOT_FALSE:
			if (*isNull)
			{
				*isNull = false;
				return BoolGetDatum(true);
			}
			else if (DatumGetBool(result))
				return BoolGetDatum(true);
			else return BoolGetDatum(false);
		case IS_UNKNOWN:
			if (*isNull)
			{
				*isNull = false;
				return BoolGetDatum(true);
			}
			else return BoolGetDatum(false);
		case IS_NOT_UNKNOWN:
			if (*isNull)
			{
				*isNull = false;
				return BoolGetDatum(false);
			}
			else return BoolGetDatum(true);
		default:
			elog(ERROR, "unrecognized booltesttype: %d", (int) btest->booltesttype);
			return (Datum) 0;	
	}
}


static Datum ExecEvalCoerceToDomain(CoerceToDomainState *cstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)

{
	CoerceToDomain *ctest = (CoerceToDomain *) cstate->xprstate.expr;
	Datum		result;
	ListCell   *l;

	result = ExecEvalExpr(cstate->arg, econtext, isNull, isDone);

	if (isDone && *isDone == ExprEndResult)
		return result;			

	foreach(l, cstate->constraints)
	{
		DomainConstraintState *con = (DomainConstraintState *) lfirst(l);

		switch (con->constrainttype)
		{
			case DOM_CONSTRAINT_NOTNULL:
				if (*isNull)
					ereport(ERROR, (errcode(ERRCODE_NOT_NULL_VIOLATION), errmsg("domain %s does not allow null values", format_type_be(ctest->resulttype))));


				break;
			case DOM_CONSTRAINT_CHECK:
				{
					Datum		conResult;
					bool		conIsNull;
					Datum		save_datum;
					bool		save_isNull;

					
					save_datum = econtext->domainValue_datum;
					save_isNull = econtext->domainValue_isNull;

					econtext->domainValue_datum = result;
					econtext->domainValue_isNull = *isNull;

					conResult = ExecEvalExpr(con->check_expr, econtext, &conIsNull, NULL);

					if (!conIsNull && !DatumGetBool(conResult))
						ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("value for domain %s violates check constraint \"%s\"", format_type_be(ctest->resulttype), con->name)));



					econtext->domainValue_datum = save_datum;
					econtext->domainValue_isNull = save_isNull;

					break;
				}
			default:
				elog(ERROR, "unrecognized constraint type: %d", (int) con->constrainttype);
				break;
		}
	}

	
	return result;
}


static Datum ExecEvalCoerceToDomainValue(ExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	if (isDone)
		*isDone = ExprSingleResult;
	*isNull = econtext->domainValue_isNull;
	return econtext->domainValue_datum;
}


static Datum ExecEvalFieldSelect(FieldSelectState *fstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	FieldSelect *fselect = (FieldSelect *) fstate->xprstate.expr;
	Datum		result;
	Datum		tupDatum;
	HeapTupleHeader tuple;
	Oid			tupType;
	int32		tupTypmod;
	TupleDesc	tupDesc;
	HeapTupleData tmptup;

	tupDatum = ExecEvalExpr(fstate->arg, econtext, isNull, isDone);

	
	if (*isNull)
		return tupDatum;

	tuple = DatumGetHeapTupleHeader(tupDatum);

	tupType = HeapTupleHeaderGetTypeId(tuple);
	tupTypmod = HeapTupleHeaderGetTypMod(tuple);

	
	tupDesc = get_cached_rowtype(tupType, tupTypmod, &fstate->argdesc, econtext);

	
	tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
	ItemPointerSetInvalid(&(tmptup.t_self));
	tmptup.t_tableOid = InvalidOid;
	tmptup.t_data = tuple;

	result = heap_getattr(&tmptup, fselect->fieldnum, tupDesc, isNull);


	return result;
}


static Datum ExecEvalFieldStore(FieldStoreState *fstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	FieldStore *fstore = (FieldStore *) fstate->xprstate.expr;
	HeapTuple	tuple;
	Datum		tupDatum;
	TupleDesc	tupDesc;
	Datum	   *values;
	bool	   *isnull;
	Datum		save_datum;
	bool		save_isNull;
	ListCell   *l1, *l2;

	tupDatum = ExecEvalExpr(fstate->arg, econtext, isNull, isDone);

	if (isDone && *isDone == ExprEndResult)
		return tupDatum;

	
	tupDesc = get_cached_rowtype(fstore->resulttype, -1, &fstate->argdesc, econtext);

	
	values = (Datum *) palloc(tupDesc->natts * sizeof(Datum));
	isnull = (bool *) palloc(tupDesc->natts * sizeof(bool));

	if (!*isNull)
	{
		
		HeapTupleHeader tuphdr;
		HeapTupleData tmptup;

		tuphdr = DatumGetHeapTupleHeader(tupDatum);
		tmptup.t_len = HeapTupleHeaderGetDatumLength(tuphdr);
		ItemPointerSetInvalid(&(tmptup.t_self));
		tmptup.t_tableOid = InvalidOid;
		tmptup.t_data = tuphdr;

		heap_deform_tuple(&tmptup, tupDesc, values, isnull);
	}
	else {
		
		memset(isnull, true, tupDesc->natts * sizeof(bool));
	}

	
	*isNull = false;

	save_datum = econtext->caseValue_datum;
	save_isNull = econtext->caseValue_isNull;

	forboth(l1, fstate->newvals, l2, fstore->fieldnums)
	{
		ExprState  *newval = (ExprState *) lfirst(l1);
		AttrNumber	fieldnum = lfirst_int(l2);

		Assert(fieldnum > 0 && fieldnum <= tupDesc->natts);

		
		econtext->caseValue_datum = values[fieldnum - 1];
		econtext->caseValue_isNull = isnull[fieldnum - 1];

		values[fieldnum - 1] = ExecEvalExpr(newval, econtext, &isnull[fieldnum - 1], NULL);


	}

	econtext->caseValue_datum = save_datum;
	econtext->caseValue_isNull = save_isNull;

	tuple = heap_form_tuple(tupDesc, values, isnull);

	pfree(values);
	pfree(isnull);

	return HeapTupleGetDatum(tuple);
}


static Datum ExecEvalRelabelType(GenericExprState *exprstate, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)


{
	return ExecEvalExpr(exprstate->arg, econtext, isNull, isDone);
}



Datum ExecEvalExprSwitchContext(ExprState *expression, ExprContext *econtext, bool *isNull, ExprDoneCond *isDone)



{
	Datum		retDatum;
	MemoryContext oldContext;

	oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
	retDatum = ExecEvalExpr(expression, econtext, isNull, isDone);
	MemoryContextSwitchTo(oldContext);
	return retDatum;
}



ExprState * ExecInitExpr(Expr *node, PlanState *parent)
{
	ExprState  *state;

	if (node == NULL)
		return NULL;

	
	check_stack_depth();

	switch (nodeTag(node))
	{
		case T_Var:
			{
				Var		   *var = (Var *) node;

				state = (ExprState *) makeNode(ExprState);
				if (var->varattno != InvalidAttrNumber)
					state->evalfunc = ExecEvalVar;
				else state->evalfunc = ExecEvalWholeRowVar;
			}
			break;
		case T_Const:
			state = (ExprState *) makeNode(ExprState);
			state->evalfunc = ExecEvalConst;
			break;
		case T_Param:
			state = (ExprState *) makeNode(ExprState);
			state->evalfunc = ExecEvalParam;
			break;
		case T_CoerceToDomainValue:
			state = (ExprState *) makeNode(ExprState);
			state->evalfunc = ExecEvalCoerceToDomainValue;
			break;
		case T_CaseTestExpr:
			state = (ExprState *) makeNode(ExprState);
			state->evalfunc = ExecEvalCaseTestExpr;
			break;
		case T_Aggref:
			{
				Aggref	   *aggref = (Aggref *) node;
				AggrefExprState *astate = makeNode(AggrefExprState);

				astate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalAggref;
				if (parent && IsA(parent, AggState))
				{
					AggState   *aggstate = (AggState *) parent;
					int			naggs;

					aggstate->aggs = lcons(astate, aggstate->aggs);
					naggs = ++aggstate->numaggs;

					astate->args = (List *) ExecInitExpr((Expr *) aggref->args, parent);

					
					if (naggs != aggstate->numaggs)
						ereport(ERROR, (errcode(ERRCODE_GROUPING_ERROR), errmsg("aggregate function calls cannot be nested")));

				}
				else {
					
					elog(ERROR, "aggref found in non-Agg plan node");
				}
				state = (ExprState *) astate;
			}
			break;
		case T_ArrayRef:
			{
				ArrayRef   *aref = (ArrayRef *) node;
				ArrayRefExprState *astate = makeNode(ArrayRefExprState);

				astate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalArrayRef;
				astate->refupperindexpr = (List *)
					ExecInitExpr((Expr *) aref->refupperindexpr, parent);
				astate->reflowerindexpr = (List *)
					ExecInitExpr((Expr *) aref->reflowerindexpr, parent);
				astate->refexpr = ExecInitExpr(aref->refexpr, parent);
				astate->refassgnexpr = ExecInitExpr(aref->refassgnexpr, parent);
				
				astate->refattrlength = get_typlen(aref->refarraytype);
				get_typlenbyvalalign(aref->refelemtype, &astate->refelemlength, &astate->refelembyval, &astate->refelemalign);


				state = (ExprState *) astate;
			}
			break;
		case T_FuncExpr:
			{
				FuncExpr   *funcexpr = (FuncExpr *) node;
				FuncExprState *fstate = makeNode(FuncExprState);

				fstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalFunc;
				fstate->args = (List *)
					ExecInitExpr((Expr *) funcexpr->args, parent);
				fstate->func.fn_oid = InvalidOid;		
				state = (ExprState *) fstate;
			}
			break;
		case T_OpExpr:
			{
				OpExpr	   *opexpr = (OpExpr *) node;
				FuncExprState *fstate = makeNode(FuncExprState);

				fstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalOper;
				fstate->args = (List *)
					ExecInitExpr((Expr *) opexpr->args, parent);
				fstate->func.fn_oid = InvalidOid;		
				state = (ExprState *) fstate;
			}
			break;
		case T_DistinctExpr:
			{
				DistinctExpr *distinctexpr = (DistinctExpr *) node;
				FuncExprState *fstate = makeNode(FuncExprState);

				fstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalDistinct;
				fstate->args = (List *)
					ExecInitExpr((Expr *) distinctexpr->args, parent);
				fstate->func.fn_oid = InvalidOid;		
				state = (ExprState *) fstate;
			}
			break;
		case T_ScalarArrayOpExpr:
			{
				ScalarArrayOpExpr *opexpr = (ScalarArrayOpExpr *) node;
				ScalarArrayOpExprState *sstate = makeNode(ScalarArrayOpExprState);

				sstate->fxprstate.xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalScalarArrayOp;
				sstate->fxprstate.args = (List *)
					ExecInitExpr((Expr *) opexpr->args, parent);
				sstate->fxprstate.func.fn_oid = InvalidOid;		
				sstate->element_type = InvalidOid;		
				state = (ExprState *) sstate;
			}
			break;
		case T_BoolExpr:
			{
				BoolExpr   *boolexpr = (BoolExpr *) node;
				BoolExprState *bstate = makeNode(BoolExprState);

				switch (boolexpr->boolop)
				{
					case AND_EXPR:
						bstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalAnd;
						break;
					case OR_EXPR:
						bstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalOr;
						break;
					case NOT_EXPR:
						bstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalNot;
						break;
					default:
						elog(ERROR, "unrecognized boolop: %d", (int) boolexpr->boolop);
						break;
				}
				bstate->args = (List *)
					ExecInitExpr((Expr *) boolexpr->args, parent);
				state = (ExprState *) bstate;
			}
			break;
		case T_SubPlan:
			{
				
				SubPlan    *subplan = (SubPlan *) node;
				SubPlanState *sstate = makeNode(SubPlanState);

				sstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecSubPlan;

				if (!parent)
					elog(ERROR, "SubPlan found with no parent plan");

				
				parent->subPlan = lcons(sstate, parent->subPlan);
				sstate->sub_estate = NULL;
				sstate->planstate = NULL;

				sstate->testexpr = ExecInitExpr((Expr *) subplan->testexpr, parent);
				sstate->args = (List *)
					ExecInitExpr((Expr *) subplan->args, parent);

				state = (ExprState *) sstate;
			}
			break;
		case T_FieldSelect:
			{
				FieldSelect *fselect = (FieldSelect *) node;
				FieldSelectState *fstate = makeNode(FieldSelectState);

				fstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalFieldSelect;
				fstate->arg = ExecInitExpr(fselect->arg, parent);
				fstate->argdesc = NULL;
				state = (ExprState *) fstate;
			}
			break;
		case T_FieldStore:
			{
				FieldStore *fstore = (FieldStore *) node;
				FieldStoreState *fstate = makeNode(FieldStoreState);

				fstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalFieldStore;
				fstate->arg = ExecInitExpr(fstore->arg, parent);
				fstate->newvals = (List *) ExecInitExpr((Expr *) fstore->newvals, parent);
				fstate->argdesc = NULL;
				state = (ExprState *) fstate;
			}
			break;
		case T_RelabelType:
			{
				RelabelType *relabel = (RelabelType *) node;
				GenericExprState *gstate = makeNode(GenericExprState);

				gstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalRelabelType;
				gstate->arg = ExecInitExpr(relabel->arg, parent);
				state = (ExprState *) gstate;
			}
			break;
		case T_ConvertRowtypeExpr:
			{
				ConvertRowtypeExpr *convert = (ConvertRowtypeExpr *) node;
				ConvertRowtypeExprState *cstate = makeNode(ConvertRowtypeExprState);

				cstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalConvertRowtype;
				cstate->arg = ExecInitExpr(convert->arg, parent);
				state = (ExprState *) cstate;
			}
			break;
		case T_CaseExpr:
			{
				CaseExpr   *caseexpr = (CaseExpr *) node;
				CaseExprState *cstate = makeNode(CaseExprState);
				List	   *outlist = NIL;
				ListCell   *l;

				cstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalCase;
				cstate->arg = ExecInitExpr(caseexpr->arg, parent);
				foreach(l, caseexpr->args)
				{
					CaseWhen   *when = (CaseWhen *) lfirst(l);
					CaseWhenState *wstate = makeNode(CaseWhenState);

					Assert(IsA(when, CaseWhen));
					wstate->xprstate.evalfunc = NULL;	
					wstate->xprstate.expr = (Expr *) when;
					wstate->expr = ExecInitExpr(when->expr, parent);
					wstate->result = ExecInitExpr(when->result, parent);
					outlist = lappend(outlist, wstate);
				}
				cstate->args = outlist;
				cstate->defresult = ExecInitExpr(caseexpr->defresult, parent);
				state = (ExprState *) cstate;
			}
			break;
		case T_ArrayExpr:
			{
				ArrayExpr  *arrayexpr = (ArrayExpr *) node;
				ArrayExprState *astate = makeNode(ArrayExprState);
				List	   *outlist = NIL;
				ListCell   *l;

				astate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalArray;
				foreach(l, arrayexpr->elements)
				{
					Expr	   *e = (Expr *) lfirst(l);
					ExprState  *estate;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
				}
				astate->elements = outlist;
				
				get_typlenbyvalalign(arrayexpr->element_typeid, &astate->elemlength, &astate->elembyval, &astate->elemalign);


				state = (ExprState *) astate;
			}
			break;
		case T_RowExpr:
			{
				RowExpr    *rowexpr = (RowExpr *) node;
				RowExprState *rstate = makeNode(RowExprState);
				Form_pg_attribute *attrs;
				List	   *outlist = NIL;
				ListCell   *l;
				int			i;

				rstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalRow;
				
				if (rowexpr->row_typeid == RECORDOID)
				{
					
					rstate->tupdesc = ExecTypeFromExprList(rowexpr->args);
					BlessTupleDesc(rstate->tupdesc);
					
				}
				else {
					
					rstate->tupdesc = lookup_rowtype_tupdesc_copy(rowexpr->row_typeid, -1);
				}
				
				Assert(list_length(rowexpr->args) <= rstate->tupdesc->natts);
				attrs = rstate->tupdesc->attrs;
				i = 0;
				foreach(l, rowexpr->args)
				{
					Expr	   *e = (Expr *) lfirst(l);
					ExprState  *estate;

					if (!attrs[i]->attisdropped)
					{
						
						if (exprType((Node *) e) != attrs[i]->atttypid)
							ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("ROW() column has type %s instead of type %s", format_type_be(exprType((Node *) e)), format_type_be(attrs[i]->atttypid))));



					}
					else {
						
						e = (Expr *) makeNullConst(INT4OID);
					}
					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
					i++;
				}
				rstate->args = outlist;
				state = (ExprState *) rstate;
			}
			break;
		case T_RowCompareExpr:
			{
				RowCompareExpr *rcexpr = (RowCompareExpr *) node;
				RowCompareExprState *rstate = makeNode(RowCompareExprState);
				int			nopers = list_length(rcexpr->opnos);
				List	   *outlist;
				ListCell   *l;
				ListCell   *l2;
				int			i;

				rstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalRowCompare;
				Assert(list_length(rcexpr->largs) == nopers);
				outlist = NIL;
				foreach(l, rcexpr->largs)
				{
					Expr	   *e = (Expr *) lfirst(l);
					ExprState  *estate;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
				}
				rstate->largs = outlist;
				Assert(list_length(rcexpr->rargs) == nopers);
				outlist = NIL;
				foreach(l, rcexpr->rargs)
				{
					Expr	   *e = (Expr *) lfirst(l);
					ExprState  *estate;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
				}
				rstate->rargs = outlist;
				Assert(list_length(rcexpr->opfamilies) == nopers);
				rstate->funcs = (FmgrInfo *) palloc(nopers * sizeof(FmgrInfo));
				i = 0;
				forboth(l, rcexpr->opnos, l2, rcexpr->opfamilies)
				{
					Oid			opno = lfirst_oid(l);
					Oid			opfamily = lfirst_oid(l2);
					int			strategy;
					Oid			lefttype;
					Oid			righttype;
					bool		recheck;
					Oid			proc;

					get_op_opfamily_properties(opno, opfamily, &strategy, &lefttype, &righttype, &recheck);



					proc = get_opfamily_proc(opfamily, lefttype, righttype, BTORDER_PROC);



					
					fmgr_info(proc, &(rstate->funcs[i]));
					i++;
				}
				state = (ExprState *) rstate;
			}
			break;
		case T_CoalesceExpr:
			{
				CoalesceExpr *coalesceexpr = (CoalesceExpr *) node;
				CoalesceExprState *cstate = makeNode(CoalesceExprState);
				List	   *outlist = NIL;
				ListCell   *l;

				cstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalCoalesce;
				foreach(l, coalesceexpr->args)
				{
					Expr	   *e = (Expr *) lfirst(l);
					ExprState  *estate;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
				}
				cstate->args = outlist;
				state = (ExprState *) cstate;
			}
			break;
		case T_MinMaxExpr:
			{
				MinMaxExpr *minmaxexpr = (MinMaxExpr *) node;
				MinMaxExprState *mstate = makeNode(MinMaxExprState);
				List	   *outlist = NIL;
				ListCell   *l;
				TypeCacheEntry *typentry;

				mstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalMinMax;
				foreach(l, minmaxexpr->args)
				{
					Expr	   *e = (Expr *) lfirst(l);
					ExprState  *estate;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
				}
				mstate->args = outlist;
				
				typentry = lookup_type_cache(minmaxexpr->minmaxtype, TYPECACHE_CMP_PROC);
				if (!OidIsValid(typentry->cmp_proc))
					ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify a comparison function for type %s", format_type_be(minmaxexpr->minmaxtype))));



				
				fmgr_info(typentry->cmp_proc, &(mstate->cfunc));
				state = (ExprState *) mstate;
			}
			break;
		case T_XmlExpr:
			{
				XmlExpr			*xexpr = (XmlExpr *) node;
				XmlExprState	*xstate = makeNode(XmlExprState);
				List			*outlist;
				ListCell		*arg;
				int				i;

				xstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalXml;
				xstate->named_outfuncs = (FmgrInfo *)
					palloc0(list_length(xexpr->named_args) * sizeof(FmgrInfo));
				outlist = NIL;
				i = 0;
				foreach(arg, xexpr->named_args)
				{
					Expr		*e = (Expr *) lfirst(arg);
					ExprState	*estate;
					Oid			typOutFunc;
					bool		typIsVarlena;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);

					getTypeOutputInfo(exprType((Node *) e), &typOutFunc, &typIsVarlena);
					fmgr_info(typOutFunc, &xstate->named_outfuncs[i]);
					i++;
				}
				xstate->named_args = outlist;

				outlist = NIL;
				foreach(arg, xexpr->args)
				{
					Expr		*e = (Expr *) lfirst(arg);
					ExprState	*estate;

					estate = ExecInitExpr(e, parent);
					outlist = lappend(outlist, estate);
				}
				xstate->args = outlist;

				state = (ExprState *) xstate;
			}
			break;
		case T_NullIfExpr:
			{
				NullIfExpr *nullifexpr = (NullIfExpr *) node;
				FuncExprState *fstate = makeNode(FuncExprState);

				fstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalNullIf;
				fstate->args = (List *)
					ExecInitExpr((Expr *) nullifexpr->args, parent);
				fstate->func.fn_oid = InvalidOid;		
				state = (ExprState *) fstate;
			}
			break;
		case T_NullTest:
			{
				NullTest   *ntest = (NullTest *) node;
				NullTestState *nstate = makeNode(NullTestState);

				nstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalNullTest;
				nstate->arg = ExecInitExpr(ntest->arg, parent);
				nstate->argisrow = type_is_rowtype(exprType((Node *) ntest->arg));
				nstate->argdesc = NULL;
				state = (ExprState *) nstate;
			}
			break;
		case T_BooleanTest:
			{
				BooleanTest *btest = (BooleanTest *) node;
				GenericExprState *gstate = makeNode(GenericExprState);

				gstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalBooleanTest;
				gstate->arg = ExecInitExpr(btest->arg, parent);
				state = (ExprState *) gstate;
			}
			break;
		case T_CoerceToDomain:
			{
				CoerceToDomain *ctest = (CoerceToDomain *) node;
				CoerceToDomainState *cstate = makeNode(CoerceToDomainState);

				cstate->xprstate.evalfunc = (ExprStateEvalFunc) ExecEvalCoerceToDomain;
				cstate->arg = ExecInitExpr(ctest->arg, parent);
				cstate->constraints = GetDomainConstraints(ctest->resulttype);
				state = (ExprState *) cstate;
			}
			break;
		case T_TargetEntry:
			{
				TargetEntry *tle = (TargetEntry *) node;
				GenericExprState *gstate = makeNode(GenericExprState);

				gstate->xprstate.evalfunc = NULL;		
				gstate->arg = ExecInitExpr(tle->expr, parent);
				state = (ExprState *) gstate;
			}
			break;
		case T_List:
			{
				List	   *outlist = NIL;
				ListCell   *l;

				foreach(l, (List *) node)
				{
					outlist = lappend(outlist, ExecInitExpr((Expr *) lfirst(l), parent));

				}
				
				return (ExprState *) outlist;
			}
		default:
			elog(ERROR, "unrecognized node type: %d", (int) nodeTag(node));
			state = NULL;		
			break;
	}

	
	state->expr = node;

	return state;
}


SubPlanState * ExecInitExprInitPlan(SubPlan *node, PlanState *parent)
{
	SubPlanState *sstate = makeNode(SubPlanState);

	if (!parent)
		elog(ERROR, "SubPlan found with no parent plan");

	
	sstate->sub_estate = NULL;
	sstate->planstate = NULL;

	sstate->testexpr = ExecInitExpr((Expr *) node->testexpr, parent);
	sstate->args = (List *) ExecInitExpr((Expr *) node->args, parent);

	sstate->xprstate.expr = (Expr *) node;

	return sstate;
}


ExprState * ExecPrepareExpr(Expr *node, EState *estate)
{
	ExprState  *result;
	MemoryContext oldcontext;

	fix_opfuncids((Node *) node);

	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	result = ExecInitExpr(node, NULL);

	MemoryContextSwitchTo(oldcontext);

	return result;
}





bool ExecQual(List *qual, ExprContext *econtext, bool resultForNull)
{
	bool		result;
	MemoryContext oldContext;
	ListCell   *l;

	
	EV_printf("ExecQual: qual is ");
	EV_nodeDisplay(qual);
	EV_printf("\n");

	IncrProcessed();

	
	oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	
	result = true;

	foreach(l, qual)
	{
		ExprState  *clause = (ExprState *) lfirst(l);
		Datum		expr_value;
		bool		isNull;

		expr_value = ExecEvalExpr(clause, econtext, &isNull, NULL);

		if (isNull)
		{
			if (resultForNull == false)
			{
				result = false; 
				break;
			}
		}
		else {
			if (!DatumGetBool(expr_value))
			{
				result = false; 
				break;
			}
		}
	}

	MemoryContextSwitchTo(oldContext);

	return result;
}


int ExecTargetListLength(List *targetlist)
{
	
	return list_length(targetlist);
}


int ExecCleanTargetListLength(List *targetlist)
{
	int			len = 0;
	ListCell   *tl;

	foreach(tl, targetlist)
	{
		TargetEntry *curTle = (TargetEntry *) lfirst(tl);

		Assert(IsA(curTle, TargetEntry));
		if (!curTle->resjunk)
			len++;
	}
	return len;
}


static bool ExecTargetList(List *targetlist, ExprContext *econtext, Datum *values, bool *isnull, ExprDoneCond *itemIsDone, ExprDoneCond *isDone)





{
	MemoryContext oldContext;
	ListCell   *tl;
	bool		haveDoneSets;

	
	oldContext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);

	
	if (isDone)
		*isDone = ExprSingleResult;		

	haveDoneSets = false;		

	foreach(tl, targetlist)
	{
		GenericExprState *gstate = (GenericExprState *) lfirst(tl);
		TargetEntry *tle = (TargetEntry *) gstate->xprstate.expr;
		AttrNumber	resind = tle->resno - 1;

		values[resind] = ExecEvalExpr(gstate->arg, econtext, &isnull[resind], &itemIsDone[resind]);



		if (itemIsDone[resind] != ExprSingleResult)
		{
			
			if (isDone == NULL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));

			if (itemIsDone[resind] == ExprMultipleResult)
			{
				
				*isDone = ExprMultipleResult;
			}
			else {
				
				haveDoneSets = true;
			}
		}
	}

	if (haveDoneSets)
	{
		
		if (*isDone == ExprSingleResult)
		{
			
			*isDone = ExprEndResult;
			MemoryContextSwitchTo(oldContext);
			return false;
		}
		else {
			
			foreach(tl, targetlist)
			{
				GenericExprState *gstate = (GenericExprState *) lfirst(tl);
				TargetEntry *tle = (TargetEntry *) gstate->xprstate.expr;
				AttrNumber	resind = tle->resno - 1;

				if (itemIsDone[resind] == ExprEndResult)
				{
					values[resind] = ExecEvalExpr(gstate->arg, econtext, &isnull[resind], &itemIsDone[resind]);



					if (itemIsDone[resind] == ExprEndResult)
					{
						
						*isDone = ExprEndResult;
						break;
					}
				}
			}

			
			if (*isDone == ExprEndResult)
			{
				foreach(tl, targetlist)
				{
					GenericExprState *gstate = (GenericExprState *) lfirst(tl);
					TargetEntry *tle = (TargetEntry *) gstate->xprstate.expr;
					AttrNumber	resind = tle->resno - 1;

					while (itemIsDone[resind] == ExprMultipleResult)
					{
						values[resind] = ExecEvalExpr(gstate->arg, econtext, &isnull[resind], &itemIsDone[resind]);


					}
				}

				MemoryContextSwitchTo(oldContext);
				return false;
			}
		}
	}

	
	MemoryContextSwitchTo(oldContext);

	return true;
}


static void ExecVariableList(ProjectionInfo *projInfo, Datum *values, bool *isnull)


{
	ExprContext *econtext = projInfo->pi_exprContext;
	int		   *varSlotOffsets = projInfo->pi_varSlotOffsets;
	int		   *varNumbers = projInfo->pi_varNumbers;
	int			i;

	
	if (projInfo->pi_lastInnerVar > 0)
		slot_getsomeattrs(econtext->ecxt_innertuple, projInfo->pi_lastInnerVar);
	if (projInfo->pi_lastOuterVar > 0)
		slot_getsomeattrs(econtext->ecxt_outertuple, projInfo->pi_lastOuterVar);
	if (projInfo->pi_lastScanVar > 0)
		slot_getsomeattrs(econtext->ecxt_scantuple, projInfo->pi_lastScanVar);

	
	for (i = list_length(projInfo->pi_targetlist) - 1; i >= 0; i--)
	{
		char	   *slotptr = ((char *) econtext) + varSlotOffsets[i];
		TupleTableSlot *varSlot = *((TupleTableSlot **) slotptr);
		int			varNumber = varNumbers[i] - 1;

		values[i] = varSlot->tts_values[varNumber];
		isnull[i] = varSlot->tts_isnull[varNumber];
	}
}


TupleTableSlot * ExecProject(ProjectionInfo *projInfo, ExprDoneCond *isDone)
{
	TupleTableSlot *slot;

	
	Assert(projInfo != NULL);

	
	slot = projInfo->pi_slot;

	
	ExecClearTuple(slot);

	
	if (projInfo->pi_isVarList)
	{
		
		if (isDone)
			*isDone = ExprSingleResult;
		ExecVariableList(projInfo, slot->tts_values, slot->tts_isnull);

		ExecStoreVirtualTuple(slot);
	}
	else {
		if (ExecTargetList(projInfo->pi_targetlist, projInfo->pi_exprContext, slot->tts_values, slot->tts_isnull, projInfo->pi_itemIsDone, isDone))




			ExecStoreVirtualTuple(slot);
	}

	return slot;
}
