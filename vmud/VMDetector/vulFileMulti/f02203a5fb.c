













PG_MODULE_MAGIC;


static const struct config_enum_entry variable_conflict_options[] = {
	{"error", PLPGSQL_RESOLVE_ERROR, false}, {"use_variable", PLPGSQL_RESOLVE_VARIABLE, false}, {"use_column", PLPGSQL_RESOLVE_COLUMN, false}, {NULL, 0, false}


};

int			plpgsql_variable_conflict = PLPGSQL_RESOLVE_ERROR;

bool		plpgsql_print_strict_params = false;


PLpgSQL_plugin **plugin_ptr = NULL;



void _PG_init(void)
{
	
	static bool inited = false;

	if (inited)
		return;

	pg_bindtextdomain(TEXTDOMAIN);

	DefineCustomEnumVariable("plpgsql.variable_conflict", gettext_noop("Sets handling of conflicts between PL/pgSQL variable names and table column names."), NULL, &plpgsql_variable_conflict, PLPGSQL_RESOLVE_ERROR, variable_conflict_options, PGC_SUSET, 0, NULL, NULL, NULL);







	DefineCustomBoolVariable("plpgsql.print_strict_params", gettext_noop("Print information about parameters in the DETAIL part of the error messages generated on INTO .. STRICT failures."), NULL, &plpgsql_print_strict_params, false, PGC_USERSET, 0, NULL, NULL, NULL);






	EmitWarningsOnPlaceholders("plpgsql");

	plpgsql_HashTableInit();
	RegisterXactCallback(plpgsql_xact_cb, NULL);
	RegisterSubXactCallback(plpgsql_subxact_cb, NULL);

	
	plugin_ptr = (PLpgSQL_plugin **) find_rendezvous_variable("PLpgSQL_plugin");

	inited = true;
}


PG_FUNCTION_INFO_V1(plpgsql_call_handler);

Datum plpgsql_call_handler(PG_FUNCTION_ARGS)
{
	PLpgSQL_function *func;
	PLpgSQL_execstate *save_cur_estate;
	Datum		retval;
	int			rc;

	
	if ((rc = SPI_connect()) != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed: %s", SPI_result_code_string(rc));

	
	func = plpgsql_compile(fcinfo, false);

	
	save_cur_estate = func->cur_estate;

	
	func->use_count++;

	PG_TRY();
	{
		
		if (CALLED_AS_TRIGGER(fcinfo))
			retval = PointerGetDatum(plpgsql_exec_trigger(func, (TriggerData *) fcinfo->context));
		else if (CALLED_AS_EVENT_TRIGGER(fcinfo))
		{
			plpgsql_exec_event_trigger(func, (EventTriggerData *) fcinfo->context);
			retval = (Datum) 0;
		}
		else retval = plpgsql_exec_function(func, fcinfo, NULL);
	}
	PG_CATCH();
	{
		
		func->use_count--;
		func->cur_estate = save_cur_estate;
		PG_RE_THROW();
	}
	PG_END_TRY();

	func->use_count--;

	func->cur_estate = save_cur_estate;

	
	if ((rc = SPI_finish()) != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed: %s", SPI_result_code_string(rc));

	return retval;
}


PG_FUNCTION_INFO_V1(plpgsql_inline_handler);

Datum plpgsql_inline_handler(PG_FUNCTION_ARGS)
{
	InlineCodeBlock *codeblock = (InlineCodeBlock *) DatumGetPointer(PG_GETARG_DATUM(0));
	PLpgSQL_function *func;
	FunctionCallInfoData fake_fcinfo;
	FmgrInfo	flinfo;
	EState	   *simple_eval_estate;
	Datum		retval;
	int			rc;

	Assert(IsA(codeblock, InlineCodeBlock));

	
	if ((rc = SPI_connect()) != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed: %s", SPI_result_code_string(rc));

	
	func = plpgsql_compile_inline(codeblock->source_text);

	
	func->use_count++;

	
	MemSet(&fake_fcinfo, 0, sizeof(fake_fcinfo));
	MemSet(&flinfo, 0, sizeof(flinfo));
	fake_fcinfo.flinfo = &flinfo;
	flinfo.fn_oid = InvalidOid;
	flinfo.fn_mcxt = CurrentMemoryContext;

	
	simple_eval_estate = CreateExecutorState();

	
	PG_TRY();
	{
		retval = plpgsql_exec_function(func, &fake_fcinfo, simple_eval_estate);
	}
	PG_CATCH();
	{
		
		plpgsql_subxact_cb(SUBXACT_EVENT_ABORT_SUB, GetCurrentSubTransactionId(), 0, NULL);


		
		FreeExecutorState(simple_eval_estate);

		
		func->use_count--;
		Assert(func->use_count == 0);

		
		plpgsql_free_function_memory(func);

		
		PG_RE_THROW();
	}
	PG_END_TRY();

	
	FreeExecutorState(simple_eval_estate);

	
	func->use_count--;
	Assert(func->use_count == 0);

	
	plpgsql_free_function_memory(func);

	
	if ((rc = SPI_finish()) != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed: %s", SPI_result_code_string(rc));

	return retval;
}


PG_FUNCTION_INFO_V1(plpgsql_validator);

Datum plpgsql_validator(PG_FUNCTION_ARGS)
{
	Oid			funcoid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Form_pg_proc proc;
	char		functyptype;
	int			numargs;
	Oid		   *argtypes;
	char	  **argnames;
	char	   *argmodes;
	bool		is_dml_trigger = false;
	bool		is_event_trigger = false;
	int			i;

	
	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcoid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", funcoid);
	proc = (Form_pg_proc) GETSTRUCT(tuple);

	functyptype = get_typtype(proc->prorettype);

	
	
	if (functyptype == TYPTYPE_PSEUDO)
	{
		
		if (proc->prorettype == TRIGGEROID || (proc->prorettype == OPAQUEOID && proc->pronargs == 0))
			is_dml_trigger = true;
		else if (proc->prorettype == EVTTRIGGEROID)
			is_event_trigger = true;
		else if (proc->prorettype != RECORDOID && proc->prorettype != VOIDOID && !IsPolymorphicType(proc->prorettype))

			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("PL/pgSQL functions cannot return type %s", format_type_be(proc->prorettype))));


	}

	
	
	numargs = get_func_arg_info(tuple, &argtypes, &argnames, &argmodes);
	for (i = 0; i < numargs; i++)
	{
		if (get_typtype(argtypes[i]) == TYPTYPE_PSEUDO)
		{
			if (!IsPolymorphicType(argtypes[i]))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("PL/pgSQL functions cannot accept type %s", format_type_be(argtypes[i]))));


		}
	}

	
	if (check_function_bodies)
	{
		FunctionCallInfoData fake_fcinfo;
		FmgrInfo	flinfo;
		int			rc;
		TriggerData trigdata;
		EventTriggerData etrigdata;

		
		if ((rc = SPI_connect()) != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed: %s", SPI_result_code_string(rc));

		
		MemSet(&fake_fcinfo, 0, sizeof(fake_fcinfo));
		MemSet(&flinfo, 0, sizeof(flinfo));
		fake_fcinfo.flinfo = &flinfo;
		flinfo.fn_oid = funcoid;
		flinfo.fn_mcxt = CurrentMemoryContext;
		if (is_dml_trigger)
		{
			MemSet(&trigdata, 0, sizeof(trigdata));
			trigdata.type = T_TriggerData;
			fake_fcinfo.context = (Node *) &trigdata;
		}
		else if (is_event_trigger)
		{
			MemSet(&etrigdata, 0, sizeof(etrigdata));
			etrigdata.type = T_EventTriggerData;
			fake_fcinfo.context = (Node *) &etrigdata;
		}

		
		plpgsql_compile(&fake_fcinfo, true);

		
		if ((rc = SPI_finish()) != SPI_OK_FINISH)
			elog(ERROR, "SPI_finish failed: %s", SPI_result_code_string(rc));
	}

	ReleaseSysCache(tuple);

	PG_RETURN_VOID();
}
