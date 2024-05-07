



















PGDLLIMPORT needs_fmgr_hook_type needs_fmgr_hook = NULL;
PGDLLIMPORT fmgr_hook_type fmgr_hook = NULL;



typedef int32 (*func_ptr) ();

typedef char *(*func_ptr) ();



typedef struct {
	func_ptr	func;			
	bool		arg_toastable[FUNC_MAX_ARGS];	
} Oldstyle_fnextra;


typedef struct {
	
	Oid			fn_oid;			
	TransactionId fn_xmin;		
	ItemPointerData fn_tid;
	PGFunction	user_fn;		
	const Pg_finfo_record *inforec;		
} CFuncHashTabEntry;

static HTAB *CFuncHash = NULL;


static void fmgr_info_cxt_security(Oid functionId, FmgrInfo *finfo, MemoryContext mcxt, bool ignore_security);
static void fmgr_info_C_lang(Oid functionId, FmgrInfo *finfo, HeapTuple procedureTuple);
static void fmgr_info_other_lang(Oid functionId, FmgrInfo *finfo, HeapTuple procedureTuple);
static CFuncHashTabEntry *lookup_C_func(HeapTuple procedureTuple);
static void record_C_func(HeapTuple procedureTuple, PGFunction user_fn, const Pg_finfo_record *inforec);
static Datum fmgr_oldstyle(PG_FUNCTION_ARGS);
static Datum fmgr_security_definer(PG_FUNCTION_ARGS);




static const FmgrBuiltin * fmgr_isbuiltin(Oid id)
{
	int			low = 0;
	int			high = fmgr_nbuiltins - 1;

	
	while (low <= high)
	{
		int			i = (high + low) / 2;
		const FmgrBuiltin *ptr = &fmgr_builtins[i];

		if (id == ptr->foid)
			return ptr;
		else if (id > ptr->foid)
			low = i + 1;
		else high = i - 1;
	}
	return NULL;
}


static const FmgrBuiltin * fmgr_lookupByName(const char *name)
{
	int			i;

	for (i = 0; i < fmgr_nbuiltins; i++)
	{
		if (strcmp(name, fmgr_builtins[i].funcName) == 0)
			return fmgr_builtins + i;
	}
	return NULL;
}


void fmgr_info(Oid functionId, FmgrInfo *finfo)
{
	fmgr_info_cxt_security(functionId, finfo, CurrentMemoryContext, false);
}


void fmgr_info_cxt(Oid functionId, FmgrInfo *finfo, MemoryContext mcxt)
{
	fmgr_info_cxt_security(functionId, finfo, mcxt, false);
}


static void fmgr_info_cxt_security(Oid functionId, FmgrInfo *finfo, MemoryContext mcxt, bool ignore_security)

{
	const FmgrBuiltin *fbp;
	HeapTuple	procedureTuple;
	Form_pg_proc procedureStruct;
	Datum		prosrcdatum;
	bool		isnull;
	char	   *prosrc;

	
	finfo->fn_oid = InvalidOid;
	finfo->fn_extra = NULL;
	finfo->fn_mcxt = mcxt;
	finfo->fn_expr = NULL;		

	if ((fbp = fmgr_isbuiltin(functionId)) != NULL)
	{
		
		finfo->fn_nargs = fbp->nargs;
		finfo->fn_strict = fbp->strict;
		finfo->fn_retset = fbp->retset;
		finfo->fn_stats = TRACK_FUNC_ALL;		
		finfo->fn_addr = fbp->func;
		finfo->fn_oid = functionId;
		return;
	}

	
	procedureTuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(functionId));
	if (!HeapTupleIsValid(procedureTuple))
		elog(ERROR, "cache lookup failed for function %u", functionId);
	procedureStruct = (Form_pg_proc) GETSTRUCT(procedureTuple);

	finfo->fn_nargs = procedureStruct->pronargs;
	finfo->fn_strict = procedureStruct->proisstrict;
	finfo->fn_retset = procedureStruct->proretset;

	
	if (!ignore_security && (procedureStruct->prosecdef || !heap_attisnull(procedureTuple, Anum_pg_proc_proconfig) || FmgrHookIsNeeded(functionId)))


	{
		finfo->fn_addr = fmgr_security_definer;
		finfo->fn_stats = TRACK_FUNC_ALL;		
		finfo->fn_oid = functionId;
		ReleaseSysCache(procedureTuple);
		return;
	}

	switch (procedureStruct->prolang)
	{
		case INTERNALlanguageId:

			
			prosrcdatum = SysCacheGetAttr(PROCOID, procedureTuple, Anum_pg_proc_prosrc, &isnull);
			if (isnull)
				elog(ERROR, "null prosrc");
			prosrc = TextDatumGetCString(prosrcdatum);
			fbp = fmgr_lookupByName(prosrc);
			if (fbp == NULL)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("internal function \"%s\" is not in internal lookup table", prosrc)));


			pfree(prosrc);
			
			finfo->fn_addr = fbp->func;
			
			finfo->fn_stats = TRACK_FUNC_ALL;	
			break;

		case ClanguageId:
			fmgr_info_C_lang(functionId, finfo, procedureTuple);
			finfo->fn_stats = TRACK_FUNC_PL;	
			break;

		case SQLlanguageId:
			finfo->fn_addr = fmgr_sql;
			finfo->fn_stats = TRACK_FUNC_PL;	
			break;

		default:
			fmgr_info_other_lang(functionId, finfo, procedureTuple);
			finfo->fn_stats = TRACK_FUNC_OFF;	
			break;
	}

	finfo->fn_oid = functionId;
	ReleaseSysCache(procedureTuple);
}


static void fmgr_info_C_lang(Oid functionId, FmgrInfo *finfo, HeapTuple procedureTuple)
{
	Form_pg_proc procedureStruct = (Form_pg_proc) GETSTRUCT(procedureTuple);
	CFuncHashTabEntry *hashentry;
	PGFunction	user_fn;
	const Pg_finfo_record *inforec;
	Oldstyle_fnextra *fnextra;
	bool		isnull;
	int			i;

	
	hashentry = lookup_C_func(procedureTuple);
	if (hashentry)
	{
		user_fn = hashentry->user_fn;
		inforec = hashentry->inforec;
	}
	else {
		Datum		prosrcattr, probinattr;
		char	   *prosrcstring, *probinstring;
		void	   *libraryhandle;

		
		prosrcattr = SysCacheGetAttr(PROCOID, procedureTuple, Anum_pg_proc_prosrc, &isnull);
		if (isnull)
			elog(ERROR, "null prosrc for C function %u", functionId);
		prosrcstring = TextDatumGetCString(prosrcattr);

		probinattr = SysCacheGetAttr(PROCOID, procedureTuple, Anum_pg_proc_probin, &isnull);
		if (isnull)
			elog(ERROR, "null probin for C function %u", functionId);
		probinstring = TextDatumGetCString(probinattr);

		
		user_fn = load_external_function(probinstring, prosrcstring, true, &libraryhandle);

		
		inforec = fetch_finfo_record(libraryhandle, prosrcstring);

		
		record_C_func(procedureTuple, user_fn, inforec);

		pfree(prosrcstring);
		pfree(probinstring);
	}

	switch (inforec->api_version)
	{
		case 0:
			
			finfo->fn_addr = fmgr_oldstyle;
			fnextra = (Oldstyle_fnextra *)
				MemoryContextAllocZero(finfo->fn_mcxt, sizeof(Oldstyle_fnextra));
			finfo->fn_extra = (void *) fnextra;
			fnextra->func = (func_ptr) user_fn;
			for (i = 0; i < procedureStruct->pronargs; i++)
			{
				fnextra->arg_toastable[i] = TypeIsToastable(procedureStruct->proargtypes.values[i]);
			}
			break;
		case 1:
			
			finfo->fn_addr = user_fn;
			break;
		default:
			
			elog(ERROR, "unrecognized function API version: %d", inforec->api_version);
			break;
	}
}


static void fmgr_info_other_lang(Oid functionId, FmgrInfo *finfo, HeapTuple procedureTuple)
{
	Form_pg_proc procedureStruct = (Form_pg_proc) GETSTRUCT(procedureTuple);
	Oid			language = procedureStruct->prolang;
	HeapTuple	languageTuple;
	Form_pg_language languageStruct;
	FmgrInfo	plfinfo;

	languageTuple = SearchSysCache1(LANGOID, ObjectIdGetDatum(language));
	if (!HeapTupleIsValid(languageTuple))
		elog(ERROR, "cache lookup failed for language %u", language);
	languageStruct = (Form_pg_language) GETSTRUCT(languageTuple);

	
	fmgr_info_cxt_security(languageStruct->lanplcallfoid, &plfinfo, CurrentMemoryContext, true);
	finfo->fn_addr = plfinfo.fn_addr;

	
	if (plfinfo.fn_extra != NULL)
		elog(ERROR, "language %u has old-style handler", language);

	ReleaseSysCache(languageTuple);
}


const Pg_finfo_record * fetch_finfo_record(void *filehandle, char *funcname)
{
	char	   *infofuncname;
	PGFInfoFunction infofunc;
	const Pg_finfo_record *inforec;
	static Pg_finfo_record default_inforec = {0};

	infofuncname = psprintf("pg_finfo_%s", funcname);

	
	infofunc = (PGFInfoFunction) lookup_external_function(filehandle, infofuncname);
	if (infofunc == NULL)
	{
		
		pfree(infofuncname);
		return &default_inforec;
	}

	
	inforec = (*infofunc) ();

	
	if (inforec == NULL)
		elog(ERROR, "null result from info function \"%s\"", infofuncname);
	switch (inforec->api_version)
	{
		case 0:
		case 1:
			
			break;
		default:
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("unrecognized API version %d reported by info function \"%s\"", inforec->api_version, infofuncname)));


			break;
	}

	pfree(infofuncname);
	return inforec;
}





static CFuncHashTabEntry * lookup_C_func(HeapTuple procedureTuple)
{
	Oid			fn_oid = HeapTupleGetOid(procedureTuple);
	CFuncHashTabEntry *entry;

	if (CFuncHash == NULL)
		return NULL;			
	entry = (CFuncHashTabEntry *)
		hash_search(CFuncHash, &fn_oid, HASH_FIND, NULL);


	if (entry == NULL)
		return NULL;			
	if (entry->fn_xmin == HeapTupleHeaderGetRawXmin(procedureTuple->t_data) && ItemPointerEquals(&entry->fn_tid, &procedureTuple->t_self))
		return entry;			
	return NULL;				
}


static void record_C_func(HeapTuple procedureTuple, PGFunction user_fn, const Pg_finfo_record *inforec)

{
	Oid			fn_oid = HeapTupleGetOid(procedureTuple);
	CFuncHashTabEntry *entry;
	bool		found;

	
	if (CFuncHash == NULL)
	{
		HASHCTL		hash_ctl;

		MemSet(&hash_ctl, 0, sizeof(hash_ctl));
		hash_ctl.keysize = sizeof(Oid);
		hash_ctl.entrysize = sizeof(CFuncHashTabEntry);
		hash_ctl.hash = oid_hash;
		CFuncHash = hash_create("CFuncHash", 100, &hash_ctl, HASH_ELEM | HASH_FUNCTION);


	}

	entry = (CFuncHashTabEntry *)
		hash_search(CFuncHash, &fn_oid, HASH_ENTER, &found);


	
	entry->fn_xmin = HeapTupleHeaderGetRawXmin(procedureTuple->t_data);
	entry->fn_tid = procedureTuple->t_self;
	entry->user_fn = user_fn;
	entry->inforec = inforec;
}


void clear_external_function_hash(void *filehandle)
{
	if (CFuncHash)
		hash_destroy(CFuncHash);
	CFuncHash = NULL;
}



void fmgr_info_copy(FmgrInfo *dstinfo, FmgrInfo *srcinfo, MemoryContext destcxt)

{
	memcpy(dstinfo, srcinfo, sizeof(FmgrInfo));
	dstinfo->fn_mcxt = destcxt;
	if (dstinfo->fn_addr == fmgr_oldstyle)
	{
		
		Oldstyle_fnextra *fnextra;

		fnextra = (Oldstyle_fnextra *)
			MemoryContextAlloc(destcxt, sizeof(Oldstyle_fnextra));
		memcpy(fnextra, srcinfo->fn_extra, sizeof(Oldstyle_fnextra));
		dstinfo->fn_extra = (void *) fnextra;
	}
	else dstinfo->fn_extra = NULL;
}



Oid fmgr_internal_function(const char *proname)
{
	const FmgrBuiltin *fbp = fmgr_lookupByName(proname);

	if (fbp == NULL)
		return InvalidOid;
	return fbp->foid;
}



static Datum fmgr_oldstyle(PG_FUNCTION_ARGS)
{
	Oldstyle_fnextra *fnextra;
	int			n_arguments = fcinfo->nargs;
	int			i;
	bool		isnull;
	func_ptr	user_fn;
	char	   *returnValue;

	if (fcinfo->flinfo == NULL || fcinfo->flinfo->fn_extra == NULL)
		elog(ERROR, "fmgr_oldstyle received NULL pointer");
	fnextra = (Oldstyle_fnextra *) fcinfo->flinfo->fn_extra;

	
	isnull = false;
	for (i = 0; i < n_arguments; i++)
	{
		if (PG_ARGISNULL(i))
			isnull = true;
		else if (fnextra->arg_toastable[i])
			fcinfo->arg[i] = PointerGetDatum(PG_DETOAST_DATUM(fcinfo->arg[i]));
	}
	fcinfo->isnull = isnull;

	user_fn = fnextra->func;

	switch (n_arguments)
	{
		case 0:
			returnValue = (char *) (*user_fn) ();
			break;
		case 1:

			
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], &fcinfo->isnull);
			break;
		case 2:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1]);
			break;
		case 3:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2]);

			break;
		case 4:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3]);


			break;
		case 5:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4]);



			break;
		case 6:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5]);




			break;
		case 7:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6]);





			break;
		case 8:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7]);






			break;
		case 9:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8]);







			break;
		case 10:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9]);








			break;
		case 11:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9], fcinfo->arg[10]);









			break;
		case 12:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9], fcinfo->arg[10], fcinfo->arg[11]);










			break;
		case 13:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9], fcinfo->arg[10], fcinfo->arg[11], fcinfo->arg[12]);











			break;
		case 14:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9], fcinfo->arg[10], fcinfo->arg[11], fcinfo->arg[12], fcinfo->arg[13]);












			break;
		case 15:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9], fcinfo->arg[10], fcinfo->arg[11], fcinfo->arg[12], fcinfo->arg[13], fcinfo->arg[14]);













			break;
		case 16:
			returnValue = (char *) (*user_fn) (fcinfo->arg[0], fcinfo->arg[1], fcinfo->arg[2], fcinfo->arg[3], fcinfo->arg[4], fcinfo->arg[5], fcinfo->arg[6], fcinfo->arg[7], fcinfo->arg[8], fcinfo->arg[9], fcinfo->arg[10], fcinfo->arg[11], fcinfo->arg[12], fcinfo->arg[13], fcinfo->arg[14], fcinfo->arg[15]);














			break;
		default:

			
			ereport(ERROR, (errcode(ERRCODE_TOO_MANY_ARGUMENTS), errmsg("function %u has too many arguments (%d, maximum is %d)", fcinfo->flinfo->fn_oid, n_arguments, 16)));


			returnValue = NULL; 
			break;
	}

	return PointerGetDatum(returnValue);
}



struct fmgr_security_definer_cache {
	FmgrInfo	flinfo;			
	Oid			userid;			
	ArrayType  *proconfig;		
	Datum		arg;			
};


static Datum fmgr_security_definer(PG_FUNCTION_ARGS)
{
	Datum		result;
	struct fmgr_security_definer_cache *volatile fcache;
	FmgrInfo   *save_flinfo;
	Oid			save_userid;
	int			save_sec_context;
	volatile int save_nestlevel;
	PgStat_FunctionCallUsage fcusage;

	if (!fcinfo->flinfo->fn_extra)
	{
		HeapTuple	tuple;
		Form_pg_proc procedureStruct;
		Datum		datum;
		bool		isnull;
		MemoryContext oldcxt;

		fcache = MemoryContextAllocZero(fcinfo->flinfo->fn_mcxt, sizeof(*fcache));

		fmgr_info_cxt_security(fcinfo->flinfo->fn_oid, &fcache->flinfo, fcinfo->flinfo->fn_mcxt, true);
		fcache->flinfo.fn_expr = fcinfo->flinfo->fn_expr;

		tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(fcinfo->flinfo->fn_oid));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for function %u", fcinfo->flinfo->fn_oid);
		procedureStruct = (Form_pg_proc) GETSTRUCT(tuple);

		if (procedureStruct->prosecdef)
			fcache->userid = procedureStruct->proowner;

		datum = SysCacheGetAttr(PROCOID, tuple, Anum_pg_proc_proconfig, &isnull);
		if (!isnull)
		{
			oldcxt = MemoryContextSwitchTo(fcinfo->flinfo->fn_mcxt);
			fcache->proconfig = DatumGetArrayTypePCopy(datum);
			MemoryContextSwitchTo(oldcxt);
		}

		ReleaseSysCache(tuple);

		fcinfo->flinfo->fn_extra = fcache;
	}
	else fcache = fcinfo->flinfo->fn_extra;

	
	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	if (fcache->proconfig)		
		save_nestlevel = NewGUCNestLevel();
	else save_nestlevel = 0;

	if (OidIsValid(fcache->userid))
		SetUserIdAndSecContext(fcache->userid, save_sec_context | SECURITY_LOCAL_USERID_CHANGE);

	if (fcache->proconfig)
	{
		ProcessGUCArray(fcache->proconfig, (superuser() ? PGC_SUSET : PGC_USERSET), PGC_S_SESSION, GUC_ACTION_SAVE);


	}

	
	if (fmgr_hook)
		(*fmgr_hook) (FHET_START, &fcache->flinfo, &fcache->arg);

	
	save_flinfo = fcinfo->flinfo;

	PG_TRY();
	{
		fcinfo->flinfo = &fcache->flinfo;

		
		pgstat_init_function_usage(fcinfo, &fcusage);

		result = FunctionCallInvoke(fcinfo);

		
		pgstat_end_function_usage(&fcusage, (fcinfo->resultinfo == NULL || !IsA(fcinfo->resultinfo, ReturnSetInfo) || ((ReturnSetInfo *) fcinfo->resultinfo)->isDone != ExprMultipleResult));


	}
	PG_CATCH();
	{
		fcinfo->flinfo = save_flinfo;
		if (fmgr_hook)
			(*fmgr_hook) (FHET_ABORT, &fcache->flinfo, &fcache->arg);
		PG_RE_THROW();
	}
	PG_END_TRY();

	fcinfo->flinfo = save_flinfo;

	if (fcache->proconfig)
		AtEOXact_GUC(true, save_nestlevel);
	if (OidIsValid(fcache->userid))
		SetUserIdAndSecContext(save_userid, save_sec_context);
	if (fmgr_hook)
		(*fmgr_hook) (FHET_END, &fcache->flinfo, &fcache->arg);

	return result;
}





Datum DirectFunctionCall1Coll(PGFunction func, Oid collation, Datum arg1)
{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 1, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.argnull[0] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall2Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2)
{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 2, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall3Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3)

{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 3, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall4Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4)

{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 4, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall5Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5)

{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 5, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall6Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6)


{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 6, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall7Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7)


{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 7, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall8Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7, Datum arg8)


{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 8, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.arg[7] = arg8;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;
	fcinfo.argnull[7] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}

Datum DirectFunctionCall9Coll(PGFunction func, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7, Datum arg8, Datum arg9)



{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, NULL, 9, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.arg[7] = arg8;
	fcinfo.arg[8] = arg9;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;
	fcinfo.argnull[7] = false;
	fcinfo.argnull[8] = false;

	result = (*func) (&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %p returned NULL", (void *) func);

	return result;
}



Datum FunctionCall1Coll(FmgrInfo *flinfo, Oid collation, Datum arg1)
{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 1, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.argnull[0] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall2Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2)
{
	
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 2, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall3Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3)

{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 3, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall4Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4)

{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 4, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall5Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5)

{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 5, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall6Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6)


{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 6, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall7Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7)


{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 7, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall8Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7, Datum arg8)


{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 8, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.arg[7] = arg8;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;
	fcinfo.argnull[7] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}

Datum FunctionCall9Coll(FmgrInfo *flinfo, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7, Datum arg8, Datum arg9)



{
	FunctionCallInfoData fcinfo;
	Datum		result;

	InitFunctionCallInfoData(fcinfo, flinfo, 9, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.arg[7] = arg8;
	fcinfo.arg[8] = arg9;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;
	fcinfo.argnull[7] = false;
	fcinfo.argnull[8] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", fcinfo.flinfo->fn_oid);

	return result;
}



Datum OidFunctionCall0Coll(Oid functionId, Oid collation)
{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 0, collation, NULL, NULL);

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall1Coll(Oid functionId, Oid collation, Datum arg1)
{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 1, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.argnull[0] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall2Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2)
{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 2, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall3Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3)

{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 3, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall4Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4)

{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 4, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall5Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5)

{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 5, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall6Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6)


{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 6, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall7Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7)


{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 7, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall8Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7, Datum arg8)


{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 8, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.arg[7] = arg8;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;
	fcinfo.argnull[7] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}

Datum OidFunctionCall9Coll(Oid functionId, Oid collation, Datum arg1, Datum arg2, Datum arg3, Datum arg4, Datum arg5, Datum arg6, Datum arg7, Datum arg8, Datum arg9)



{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	fmgr_info(functionId, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 9, collation, NULL, NULL);

	fcinfo.arg[0] = arg1;
	fcinfo.arg[1] = arg2;
	fcinfo.arg[2] = arg3;
	fcinfo.arg[3] = arg4;
	fcinfo.arg[4] = arg5;
	fcinfo.arg[5] = arg6;
	fcinfo.arg[6] = arg7;
	fcinfo.arg[7] = arg8;
	fcinfo.arg[8] = arg9;
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;
	fcinfo.argnull[3] = false;
	fcinfo.argnull[4] = false;
	fcinfo.argnull[5] = false;
	fcinfo.argnull[6] = false;
	fcinfo.argnull[7] = false;
	fcinfo.argnull[8] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return result;
}





Datum InputFunctionCall(FmgrInfo *flinfo, char *str, Oid typioparam, int32 typmod)
{
	FunctionCallInfoData fcinfo;
	Datum		result;
	bool		pushed;

	if (str == NULL && flinfo->fn_strict)
		return (Datum) 0;		

	pushed = SPI_push_conditional();

	InitFunctionCallInfoData(fcinfo, flinfo, 3, InvalidOid, NULL, NULL);

	fcinfo.arg[0] = CStringGetDatum(str);
	fcinfo.arg[1] = ObjectIdGetDatum(typioparam);
	fcinfo.arg[2] = Int32GetDatum(typmod);
	fcinfo.argnull[0] = (str == NULL);
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (str == NULL)
	{
		if (!fcinfo.isnull)
			elog(ERROR, "input function %u returned non-NULL", fcinfo.flinfo->fn_oid);
	}
	else {
		if (fcinfo.isnull)
			elog(ERROR, "input function %u returned NULL", fcinfo.flinfo->fn_oid);
	}

	SPI_pop_conditional(pushed);

	return result;
}


char * OutputFunctionCall(FmgrInfo *flinfo, Datum val)
{
	char	   *result;
	bool		pushed;

	pushed = SPI_push_conditional();

	result = DatumGetCString(FunctionCall1(flinfo, val));

	SPI_pop_conditional(pushed);

	return result;
}


Datum ReceiveFunctionCall(FmgrInfo *flinfo, StringInfo buf, Oid typioparam, int32 typmod)

{
	FunctionCallInfoData fcinfo;
	Datum		result;
	bool		pushed;

	if (buf == NULL && flinfo->fn_strict)
		return (Datum) 0;		

	pushed = SPI_push_conditional();

	InitFunctionCallInfoData(fcinfo, flinfo, 3, InvalidOid, NULL, NULL);

	fcinfo.arg[0] = PointerGetDatum(buf);
	fcinfo.arg[1] = ObjectIdGetDatum(typioparam);
	fcinfo.arg[2] = Int32GetDatum(typmod);
	fcinfo.argnull[0] = (buf == NULL);
	fcinfo.argnull[1] = false;
	fcinfo.argnull[2] = false;

	result = FunctionCallInvoke(&fcinfo);

	
	if (buf == NULL)
	{
		if (!fcinfo.isnull)
			elog(ERROR, "receive function %u returned non-NULL", fcinfo.flinfo->fn_oid);
	}
	else {
		if (fcinfo.isnull)
			elog(ERROR, "receive function %u returned NULL", fcinfo.flinfo->fn_oid);
	}

	SPI_pop_conditional(pushed);

	return result;
}


bytea * SendFunctionCall(FmgrInfo *flinfo, Datum val)
{
	bytea	   *result;
	bool		pushed;

	pushed = SPI_push_conditional();

	result = DatumGetByteaP(FunctionCall1(flinfo, val));

	SPI_pop_conditional(pushed);

	return result;
}


Datum OidInputFunctionCall(Oid functionId, char *str, Oid typioparam, int32 typmod)
{
	FmgrInfo	flinfo;

	fmgr_info(functionId, &flinfo);
	return InputFunctionCall(&flinfo, str, typioparam, typmod);
}

char * OidOutputFunctionCall(Oid functionId, Datum val)
{
	FmgrInfo	flinfo;

	fmgr_info(functionId, &flinfo);
	return OutputFunctionCall(&flinfo, val);
}

Datum OidReceiveFunctionCall(Oid functionId, StringInfo buf, Oid typioparam, int32 typmod)

{
	FmgrInfo	flinfo;

	fmgr_info(functionId, &flinfo);
	return ReceiveFunctionCall(&flinfo, buf, typioparam, typmod);
}

bytea * OidSendFunctionCall(Oid functionId, Datum val)
{
	FmgrInfo	flinfo;

	fmgr_info(functionId, &flinfo);
	return SendFunctionCall(&flinfo, val);
}



char * fmgr(Oid procedureId,...)
{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	int			n_arguments;
	Datum		result;

	fmgr_info(procedureId, &flinfo);

	MemSet(&fcinfo, 0, sizeof(fcinfo));
	fcinfo.flinfo = &flinfo;
	fcinfo.nargs = flinfo.fn_nargs;
	n_arguments = fcinfo.nargs;

	if (n_arguments > 0)
	{
		va_list		pvar;
		int			i;

		if (n_arguments > FUNC_MAX_ARGS)
			ereport(ERROR, (errcode(ERRCODE_TOO_MANY_ARGUMENTS), errmsg("function %u has too many arguments (%d, maximum is %d)", flinfo.fn_oid, n_arguments, FUNC_MAX_ARGS)));


		va_start(pvar, procedureId);
		for (i = 0; i < n_arguments; i++)
			fcinfo.arg[i] = PointerGetDatum(va_arg(pvar, char *));
		va_end(pvar);
	}

	result = FunctionCallInvoke(&fcinfo);

	
	if (fcinfo.isnull)
		elog(ERROR, "function %u returned NULL", flinfo.fn_oid);

	return DatumGetPointer(result);
}






Datum Int64GetDatum(int64 X)
{
	int64	   *retval = (int64 *) palloc(sizeof(int64));

	*retval = X;
	return PointerGetDatum(retval);
}


Datum Float4GetDatum(float4 X)
{

	union {
		float4		value;
		int32		retval;
	}			myunion;

	myunion.value = X;
	return SET_4_BYTES(myunion.retval);

	float4	   *retval = (float4 *) palloc(sizeof(float4));

	*retval = X;
	return PointerGetDatum(retval);

}



float4 DatumGetFloat4(Datum X)
{
	union {
		int32		value;
		float4		retval;
	}			myunion;

	myunion.value = GET_4_BYTES(X);
	return myunion.retval;
}


Datum Float8GetDatum(float8 X)
{

	union {
		float8		value;
		int64		retval;
	}			myunion;

	myunion.value = X;
	return SET_8_BYTES(myunion.retval);

	float8	   *retval = (float8 *) palloc(sizeof(float8));

	*retval = X;
	return PointerGetDatum(retval);

}



float8 DatumGetFloat8(Datum X)
{
	union {
		int64		value;
		float8		retval;
	}			myunion;

	myunion.value = GET_8_BYTES(X);
	return myunion.retval;
}





struct varlena * pg_detoast_datum(struct varlena * datum)
{
	if (VARATT_IS_EXTENDED(datum))
		return heap_tuple_untoast_attr(datum);
	else return datum;
}

struct varlena * pg_detoast_datum_copy(struct varlena * datum)
{
	if (VARATT_IS_EXTENDED(datum))
		return heap_tuple_untoast_attr(datum);
	else {
		
		Size		len = VARSIZE(datum);
		struct varlena *result = (struct varlena *) palloc(len);

		memcpy(result, datum, len);
		return result;
	}
}

struct varlena * pg_detoast_datum_slice(struct varlena * datum, int32 first, int32 count)
{
	
	return heap_tuple_untoast_attr_slice(datum, first, count);
}

struct varlena * pg_detoast_datum_packed(struct varlena * datum)
{
	if (VARATT_IS_COMPRESSED(datum) || VARATT_IS_EXTERNAL(datum))
		return heap_tuple_untoast_attr(datum);
	else return datum;
}




Oid get_fn_expr_rettype(FmgrInfo *flinfo)
{
	Node	   *expr;

	
	if (!flinfo || !flinfo->fn_expr)
		return InvalidOid;

	expr = flinfo->fn_expr;

	return exprType(expr);
}


Oid get_fn_expr_argtype(FmgrInfo *flinfo, int argnum)
{
	
	if (!flinfo || !flinfo->fn_expr)
		return InvalidOid;

	return get_call_expr_argtype(flinfo->fn_expr, argnum);
}


Oid get_call_expr_argtype(Node *expr, int argnum)
{
	List	   *args;
	Oid			argtype;

	if (expr == NULL)
		return InvalidOid;

	if (IsA(expr, FuncExpr))
		args = ((FuncExpr *) expr)->args;
	else if (IsA(expr, OpExpr))
		args = ((OpExpr *) expr)->args;
	else if (IsA(expr, DistinctExpr))
		args = ((DistinctExpr *) expr)->args;
	else if (IsA(expr, ScalarArrayOpExpr))
		args = ((ScalarArrayOpExpr *) expr)->args;
	else if (IsA(expr, ArrayCoerceExpr))
		args = list_make1(((ArrayCoerceExpr *) expr)->arg);
	else if (IsA(expr, NullIfExpr))
		args = ((NullIfExpr *) expr)->args;
	else if (IsA(expr, WindowFunc))
		args = ((WindowFunc *) expr)->args;
	else return InvalidOid;

	if (argnum < 0 || argnum >= list_length(args))
		return InvalidOid;

	argtype = exprType((Node *) list_nth(args, argnum));

	
	if (IsA(expr, ScalarArrayOpExpr) && argnum == 1)
		argtype = get_base_element_type(argtype);
	else if (IsA(expr, ArrayCoerceExpr) && argnum == 0)
		argtype = get_base_element_type(argtype);

	return argtype;
}


bool get_fn_expr_arg_stable(FmgrInfo *flinfo, int argnum)
{
	
	if (!flinfo || !flinfo->fn_expr)
		return false;

	return get_call_expr_arg_stable(flinfo->fn_expr, argnum);
}


bool get_call_expr_arg_stable(Node *expr, int argnum)
{
	List	   *args;
	Node	   *arg;

	if (expr == NULL)
		return false;

	if (IsA(expr, FuncExpr))
		args = ((FuncExpr *) expr)->args;
	else if (IsA(expr, OpExpr))
		args = ((OpExpr *) expr)->args;
	else if (IsA(expr, DistinctExpr))
		args = ((DistinctExpr *) expr)->args;
	else if (IsA(expr, ScalarArrayOpExpr))
		args = ((ScalarArrayOpExpr *) expr)->args;
	else if (IsA(expr, ArrayCoerceExpr))
		args = list_make1(((ArrayCoerceExpr *) expr)->arg);
	else if (IsA(expr, NullIfExpr))
		args = ((NullIfExpr *) expr)->args;
	else if (IsA(expr, WindowFunc))
		args = ((WindowFunc *) expr)->args;
	else return false;

	if (argnum < 0 || argnum >= list_length(args))
		return false;

	arg = (Node *) list_nth(args, argnum);

	
	if (IsA(arg, Const))
		return true;
	if (IsA(arg, Param) && ((Param *) arg)->paramkind == PARAM_EXTERN)
		return true;

	return false;
}


bool get_fn_expr_variadic(FmgrInfo *flinfo)
{
	Node	   *expr;

	
	if (!flinfo || !flinfo->fn_expr)
		return false;

	expr = flinfo->fn_expr;

	if (IsA(expr, FuncExpr))
		return ((FuncExpr *) expr)->funcvariadic;
	else return false;
}