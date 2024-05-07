


































extern void _PG_init(void);
extern Datum plpython_validator(PG_FUNCTION_ARGS);
extern Datum plpython_call_handler(PG_FUNCTION_ARGS);
extern Datum plpython_inline_handler(PG_FUNCTION_ARGS);



extern Datum plpython2_validator(PG_FUNCTION_ARGS);
extern Datum plpython2_call_handler(PG_FUNCTION_ARGS);
extern Datum plpython2_inline_handler(PG_FUNCTION_ARGS);


PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(plpython_validator);
PG_FUNCTION_INFO_V1(plpython_call_handler);
PG_FUNCTION_INFO_V1(plpython_inline_handler);


PG_FUNCTION_INFO_V1(plpython2_validator);
PG_FUNCTION_INFO_V1(plpython2_call_handler);
PG_FUNCTION_INFO_V1(plpython2_inline_handler);



static bool PLy_procedure_is_trigger(Form_pg_proc procStruct);
static void plpython_error_callback(void *arg);
static void plpython_inline_error_callback(void *arg);
static void PLy_init_interp(void);

static PLyExecutionContext *PLy_push_execution_context(void);
static void PLy_pop_execution_context(void);

static const int plpython_python_version = PY_MAJOR_VERSION;


PyObject   *PLy_interp_globals = NULL;


static PLyExecutionContext *PLy_execution_contexts = NULL;


void _PG_init(void)
{
	
	static bool inited = false;
	const int **version_ptr;

	if (inited)
		return;

	
	version_ptr = (const int **) find_rendezvous_variable("plpython_python_version");
	if (!(*version_ptr))
		*version_ptr = &plpython_python_version;
	else {
		if (**version_ptr != plpython_python_version)
			ereport(FATAL, (errmsg("Python major version mismatch in session"), errdetail("This session has previously used Python major version %d, and it is now attempting to use Python major version %d.", **version_ptr, plpython_python_version), errhint("Start a new session to use a different Python major version.")));



	}

	pg_bindtextdomain(TEXTDOMAIN);


	PyImport_AppendInittab("plpy", PyInit_plpy);

	Py_Initialize();

	PyImport_ImportModule("plpy");

	PLy_init_interp();
	PLy_init_plpy();
	if (PyErr_Occurred())
		PLy_elog(FATAL, "untrapped error in initialization");

	init_procedure_caches();

	explicit_subtransactions = NIL;

	PLy_execution_contexts = NULL;

	inited = true;
}


void PLy_init_interp(void)
{
	static PyObject *PLy_interp_safe_globals = NULL;
	PyObject   *mainmod;

	mainmod = PyImport_AddModule("__main__");
	if (mainmod == NULL || PyErr_Occurred())
		PLy_elog(ERROR, "could not import \"__main__\" module");
	Py_INCREF(mainmod);
	PLy_interp_globals = PyModule_GetDict(mainmod);
	PLy_interp_safe_globals = PyDict_New();
	if (PLy_interp_safe_globals == NULL)
		PLy_elog(ERROR, "could not create globals");
	PyDict_SetItemString(PLy_interp_globals, "GD", PLy_interp_safe_globals);
	Py_DECREF(mainmod);
	if (PLy_interp_globals == NULL || PyErr_Occurred())
		PLy_elog(ERROR, "could not initialize globals");
}

Datum plpython_validator(PG_FUNCTION_ARGS)
{
	Oid			funcoid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Form_pg_proc procStruct;
	bool		is_trigger;

	if (!check_function_bodies)
	{
		PG_RETURN_VOID();
	}

	
	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcoid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", funcoid);
	procStruct = (Form_pg_proc) GETSTRUCT(tuple);

	is_trigger = PLy_procedure_is_trigger(procStruct);

	ReleaseSysCache(tuple);

	
	PLy_procedure_get(funcoid, InvalidOid, is_trigger);

	PG_RETURN_VOID();
}


Datum plpython2_validator(PG_FUNCTION_ARGS)
{
	return plpython_validator(fcinfo);
}


Datum plpython_call_handler(PG_FUNCTION_ARGS)
{
	Datum		retval;
	PLyExecutionContext *exec_ctx;
	ErrorContextCallback plerrcontext;

	
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed");

	
	exec_ctx = PLy_push_execution_context();

	
	plerrcontext.callback = plpython_error_callback;
	plerrcontext.previous = error_context_stack;
	error_context_stack = &plerrcontext;

	PG_TRY();
	{
		Oid			funcoid = fcinfo->flinfo->fn_oid;
		PLyProcedure *proc;

		if (CALLED_AS_TRIGGER(fcinfo))
		{
			Relation	tgrel = ((TriggerData *) fcinfo->context)->tg_relation;
			HeapTuple	trv;

			proc = PLy_procedure_get(funcoid, RelationGetRelid(tgrel), true);
			exec_ctx->curr_proc = proc;
			trv = PLy_exec_trigger(fcinfo, proc);
			retval = PointerGetDatum(trv);
		}
		else {
			proc = PLy_procedure_get(funcoid, InvalidOid, false);
			exec_ctx->curr_proc = proc;
			retval = PLy_exec_function(fcinfo, proc);
		}
	}
	PG_CATCH();
	{
		PLy_pop_execution_context();
		PyErr_Clear();
		PG_RE_THROW();
	}
	PG_END_TRY();

	
	error_context_stack = plerrcontext.previous;
	
	PLy_pop_execution_context();

	return retval;
}


Datum plpython2_call_handler(PG_FUNCTION_ARGS)
{
	return plpython_call_handler(fcinfo);
}


Datum plpython_inline_handler(PG_FUNCTION_ARGS)
{
	InlineCodeBlock *codeblock = (InlineCodeBlock *) DatumGetPointer(PG_GETARG_DATUM(0));
	FunctionCallInfoData fake_fcinfo;
	FmgrInfo	flinfo;
	PLyProcedure proc;
	PLyExecutionContext *exec_ctx;
	ErrorContextCallback plerrcontext;

	
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed");

	MemSet(&fake_fcinfo, 0, sizeof(fake_fcinfo));
	MemSet(&flinfo, 0, sizeof(flinfo));
	fake_fcinfo.flinfo = &flinfo;
	flinfo.fn_oid = InvalidOid;
	flinfo.fn_mcxt = CurrentMemoryContext;

	MemSet(&proc, 0, sizeof(PLyProcedure));
	proc.pyname = PLy_strdup("__plpython_inline_block");
	proc.result.out.d.typoid = VOIDOID;

	
	exec_ctx = PLy_push_execution_context();

	
	plerrcontext.callback = plpython_inline_error_callback;
	plerrcontext.previous = error_context_stack;
	error_context_stack = &plerrcontext;

	PG_TRY();
	{
		PLy_procedure_compile(&proc, codeblock->source_text);
		exec_ctx->curr_proc = &proc;
		PLy_exec_function(&fake_fcinfo, &proc);
	}
	PG_CATCH();
	{
		PLy_pop_execution_context();
		PLy_procedure_delete(&proc);
		PyErr_Clear();
		PG_RE_THROW();
	}
	PG_END_TRY();

	
	error_context_stack = plerrcontext.previous;
	
	PLy_pop_execution_context();

	
	PLy_procedure_delete(&proc);

	PG_RETURN_VOID();
}


Datum plpython2_inline_handler(PG_FUNCTION_ARGS)
{
	return plpython_inline_handler(fcinfo);
}


static bool PLy_procedure_is_trigger(Form_pg_proc procStruct)
{
	return (procStruct->prorettype == TRIGGEROID || (procStruct->prorettype == OPAQUEOID && procStruct->pronargs == 0));

}

static void plpython_error_callback(void *arg)
{
	PLyExecutionContext *exec_ctx = PLy_current_execution_context();

	if (exec_ctx->curr_proc)
		errcontext("PL/Python function \"%s\"", PLy_procedure_name(exec_ctx->curr_proc));
}

static void plpython_inline_error_callback(void *arg)
{
	errcontext("PL/Python anonymous code block");
}

PLyExecutionContext * PLy_current_execution_context(void)
{
	if (PLy_execution_contexts == NULL)
		elog(ERROR, "no Python function is currently executing");

	return PLy_execution_contexts;
}

static PLyExecutionContext * PLy_push_execution_context(void)
{
	PLyExecutionContext *context = PLy_malloc(sizeof(PLyExecutionContext));

	context->curr_proc = NULL;
	context->scratch_ctx = AllocSetContextCreate(TopTransactionContext, "PL/Python scratch context", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);



	context->next = PLy_execution_contexts;
	PLy_execution_contexts = context;
	return context;
}

static void PLy_pop_execution_context(void)
{
	PLyExecutionContext *context = PLy_execution_contexts;

	if (context == NULL)
		elog(ERROR, "no Python function is currently executing");

	PLy_execution_contexts = context->next;

	MemoryContextDelete(context->scratch_ctx);
	PLy_free(context);
}
