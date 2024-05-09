





































static void compute_return_type(TypeName *returnType, Oid languageOid, Oid *prorettype_p, bool *returnsSet_p)

{
	Oid			rettype;
	Type		typtup;
	AclResult	aclresult;

	typtup = LookupTypeName(NULL, returnType, NULL, false);

	if (typtup)
	{
		if (!((Form_pg_type) GETSTRUCT(typtup))->typisdefined)
		{
			if (languageOid == SQLlanguageId)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("SQL function cannot return shell type %s", TypeNameToString(returnType))));


			else ereport(NOTICE, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("return type %s is only a shell", TypeNameToString(returnType))));



		}
		rettype = typeTypeId(typtup);
		ReleaseSysCache(typtup);
	}
	else {
		char	   *typnam = TypeNameToString(returnType);
		Oid			namespaceId;
		AclResult	aclresult;
		char	   *typname;

		
		if (languageOid != INTERNALlanguageId && languageOid != ClanguageId)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("type \"%s\" does not exist", typnam)));


		
		if (returnType->typmods != NIL)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("type modifier cannot be specified for shell type \"%s\"", typnam)));



		
		ereport(NOTICE, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("type \"%s\" is not yet defined", typnam), errdetail("Creating a shell type definition.")));


		namespaceId = QualifiedNameGetCreationNamespace(returnType->names, &typname);
		aclresult = pg_namespace_aclcheck(namespaceId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(namespaceId));
		rettype = TypeShellMake(typname, namespaceId, GetUserId());
		Assert(OidIsValid(rettype));
	}

	aclresult = pg_type_aclcheck(rettype, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, rettype);

	*prorettype_p = rettype;
	*returnsSet_p = returnType->setof;
}


void interpret_function_parameter_list(List *parameters, Oid languageOid, bool is_aggregate, const char *queryString, oidvector **parameterTypes, ArrayType **allParameterTypes, ArrayType **parameterModes, ArrayType **parameterNames, List **parameterDefaults, Oid *variadicArgType, Oid *requiredResultType)










{
	int			parameterCount = list_length(parameters);
	Oid		   *inTypes;
	int			inCount = 0;
	Datum	   *allTypes;
	Datum	   *paramModes;
	Datum	   *paramNames;
	int			outCount = 0;
	int			varCount = 0;
	bool		have_names = false;
	bool		have_defaults = false;
	ListCell   *x;
	int			i;
	ParseState *pstate;

	*variadicArgType = InvalidOid;		
	*requiredResultType = InvalidOid;	

	inTypes = (Oid *) palloc(parameterCount * sizeof(Oid));
	allTypes = (Datum *) palloc(parameterCount * sizeof(Datum));
	paramModes = (Datum *) palloc(parameterCount * sizeof(Datum));
	paramNames = (Datum *) palloc0(parameterCount * sizeof(Datum));
	*parameterDefaults = NIL;

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	
	i = 0;
	foreach(x, parameters)
	{
		FunctionParameter *fp = (FunctionParameter *) lfirst(x);
		TypeName   *t = fp->argType;
		bool		isinput = false;
		Oid			toid;
		Type		typtup;
		AclResult	aclresult;

		typtup = LookupTypeName(NULL, t, NULL, false);
		if (typtup)
		{
			if (!((Form_pg_type) GETSTRUCT(typtup))->typisdefined)
			{
				
				if (languageOid == SQLlanguageId)
					ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("SQL function cannot accept shell type %s", TypeNameToString(t))));


				
				else if (is_aggregate)
					ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("aggregate cannot accept shell type %s", TypeNameToString(t))));


				else ereport(NOTICE, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("argument type %s is only a shell", TypeNameToString(t))));



			}
			toid = typeTypeId(typtup);
			ReleaseSysCache(typtup);
		}
		else {
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("type %s does not exist", TypeNameToString(t))));


			toid = InvalidOid;	
		}

		aclresult = pg_type_aclcheck(toid, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error_type(aclresult, toid);

		if (t->setof)
		{
			if (is_aggregate)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("aggregates cannot accept set arguments")));

			else ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("functions cannot accept set arguments")));


		}

		
		if (fp->mode != FUNC_PARAM_OUT && fp->mode != FUNC_PARAM_TABLE)
		{
			
			if (varCount > 0)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("VARIADIC parameter must be the last input parameter")));

			inTypes[inCount++] = toid;
			isinput = true;
		}

		
		if (fp->mode != FUNC_PARAM_IN && fp->mode != FUNC_PARAM_VARIADIC)
		{
			if (outCount == 0)	
				*requiredResultType = toid;
			outCount++;
		}

		if (fp->mode == FUNC_PARAM_VARIADIC)
		{
			*variadicArgType = toid;
			varCount++;
			
			switch (toid)
			{
				case ANYARRAYOID:
				case ANYOID:
					
					break;
				default:
					if (!OidIsValid(get_element_type(toid)))
						ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("VARIADIC parameter must be an array")));

					break;
			}
		}

		allTypes[i] = ObjectIdGetDatum(toid);

		paramModes[i] = CharGetDatum(fp->mode);

		if (fp->name && fp->name[0])
		{
			ListCell   *px;

			
			foreach(px, parameters)
			{
				FunctionParameter *prevfp = (FunctionParameter *) lfirst(px);

				if (prevfp == fp)
					break;
				
				if ((fp->mode == FUNC_PARAM_IN || fp->mode == FUNC_PARAM_VARIADIC) && (prevfp->mode == FUNC_PARAM_OUT || prevfp->mode == FUNC_PARAM_TABLE))


					continue;
				if ((prevfp->mode == FUNC_PARAM_IN || prevfp->mode == FUNC_PARAM_VARIADIC) && (fp->mode == FUNC_PARAM_OUT || fp->mode == FUNC_PARAM_TABLE))


					continue;
				if (prevfp->name && prevfp->name[0] && strcmp(prevfp->name, fp->name) == 0)
					ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("parameter name \"%s\" used more than once", fp->name)));


			}

			paramNames[i] = CStringGetTextDatum(fp->name);
			have_names = true;
		}

		if (fp->defexpr)
		{
			Node	   *def;

			if (!isinput)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only input parameters can have default values")));


			def = transformExpr(pstate, fp->defexpr, EXPR_KIND_FUNCTION_DEFAULT);
			def = coerce_to_specific_type(pstate, def, toid, "DEFAULT");
			assign_expr_collations(pstate, def);

			
			if (list_length(pstate->p_rtable) != 0 || contain_var_clause(def))
				ereport(ERROR, (errcode(ERRCODE_INVALID_COLUMN_REFERENCE), errmsg("cannot use table references in parameter default value")));


			

			*parameterDefaults = lappend(*parameterDefaults, def);
			have_defaults = true;
		}
		else {
			if (isinput && have_defaults)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("input parameters after one with a default value must also have defaults")));

		}

		i++;
	}

	free_parsestate(pstate);

	
	*parameterTypes = buildoidvector(inTypes, inCount);

	if (outCount > 0 || varCount > 0)
	{
		*allParameterTypes = construct_array(allTypes, parameterCount, OIDOID, sizeof(Oid), true, 'i');
		*parameterModes = construct_array(paramModes, parameterCount, CHAROID, 1, true, 'c');
		if (outCount > 1)
			*requiredResultType = RECORDOID;
		
	}
	else {
		*allParameterTypes = NULL;
		*parameterModes = NULL;
	}

	if (have_names)
	{
		for (i = 0; i < parameterCount; i++)
		{
			if (paramNames[i] == PointerGetDatum(NULL))
				paramNames[i] = CStringGetTextDatum("");
		}
		*parameterNames = construct_array(paramNames, parameterCount, TEXTOID, -1, false, 'i');
	}
	else *parameterNames = NULL;
}



static bool compute_common_attribute(DefElem *defel, DefElem **volatility_item, DefElem **strict_item, DefElem **security_item, DefElem **leakproof_item, List **set_items, DefElem **cost_item, DefElem **rows_item)







{
	if (strcmp(defel->defname, "volatility") == 0)
	{
		if (*volatility_item)
			goto duplicate_error;

		*volatility_item = defel;
	}
	else if (strcmp(defel->defname, "strict") == 0)
	{
		if (*strict_item)
			goto duplicate_error;

		*strict_item = defel;
	}
	else if (strcmp(defel->defname, "security") == 0)
	{
		if (*security_item)
			goto duplicate_error;

		*security_item = defel;
	}
	else if (strcmp(defel->defname, "leakproof") == 0)
	{
		if (*leakproof_item)
			goto duplicate_error;

		*leakproof_item = defel;
	}
	else if (strcmp(defel->defname, "set") == 0)
	{
		*set_items = lappend(*set_items, defel->arg);
	}
	else if (strcmp(defel->defname, "cost") == 0)
	{
		if (*cost_item)
			goto duplicate_error;

		*cost_item = defel;
	}
	else if (strcmp(defel->defname, "rows") == 0)
	{
		if (*rows_item)
			goto duplicate_error;

		*rows_item = defel;
	}
	else return false;

	
	return true;

duplicate_error:
	ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

	return false;				
}

static char interpret_func_volatility(DefElem *defel)
{
	char	   *str = strVal(defel->arg);

	if (strcmp(str, "immutable") == 0)
		return PROVOLATILE_IMMUTABLE;
	else if (strcmp(str, "stable") == 0)
		return PROVOLATILE_STABLE;
	else if (strcmp(str, "volatile") == 0)
		return PROVOLATILE_VOLATILE;
	else {
		elog(ERROR, "invalid volatility \"%s\"", str);
		return 0;				
	}
}


static ArrayType * update_proconfig_value(ArrayType *a, List *set_items)
{
	ListCell   *l;

	foreach(l, set_items)
	{
		VariableSetStmt *sstmt = (VariableSetStmt *) lfirst(l);

		Assert(IsA(sstmt, VariableSetStmt));
		if (sstmt->kind == VAR_RESET_ALL)
			a = NULL;
		else {
			char	   *valuestr = ExtractSetVariableArgs(sstmt);

			if (valuestr)
				a = GUCArrayAdd(a, sstmt->name, valuestr);
			else	 a = GUCArrayDelete(a, sstmt->name);
		}
	}

	return a;
}



static void compute_attributes_sql_style(List *options, List **as, char **language, bool *windowfunc_p, char *volatility_p, bool *strict_p, bool *security_definer, bool *leakproof_p, ArrayType **proconfig, float4 *procost, float4 *prorows)










{
	ListCell   *option;
	DefElem    *as_item = NULL;
	DefElem    *language_item = NULL;
	DefElem    *windowfunc_item = NULL;
	DefElem    *volatility_item = NULL;
	DefElem    *strict_item = NULL;
	DefElem    *security_item = NULL;
	DefElem    *leakproof_item = NULL;
	List	   *set_items = NIL;
	DefElem    *cost_item = NULL;
	DefElem    *rows_item = NULL;

	foreach(option, options)
	{
		DefElem    *defel = (DefElem *) lfirst(option);

		if (strcmp(defel->defname, "as") == 0)
		{
			if (as_item)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			as_item = defel;
		}
		else if (strcmp(defel->defname, "language") == 0)
		{
			if (language_item)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			language_item = defel;
		}
		else if (strcmp(defel->defname, "window") == 0)
		{
			if (windowfunc_item)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			windowfunc_item = defel;
		}
		else if (compute_common_attribute(defel, &volatility_item, &strict_item, &security_item, &leakproof_item, &set_items, &cost_item, &rows_item))






		{
			
			continue;
		}
		else elog(ERROR, "option \"%s\" not recognized", defel->defname);

	}

	
	if (as_item)
		*as = (List *) as_item->arg;
	else {
		ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("no function body specified")));

		*as = NIL;				
	}

	if (language_item)
		*language = strVal(language_item->arg);
	else {
		ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("no language specified")));

		*language = NULL;		
	}

	
	if (windowfunc_item)
		*windowfunc_p = intVal(windowfunc_item->arg);
	if (volatility_item)
		*volatility_p = interpret_func_volatility(volatility_item);
	if (strict_item)
		*strict_p = intVal(strict_item->arg);
	if (security_item)
		*security_definer = intVal(security_item->arg);
	if (leakproof_item)
		*leakproof_p = intVal(leakproof_item->arg);
	if (set_items)
		*proconfig = update_proconfig_value(NULL, set_items);
	if (cost_item)
	{
		*procost = defGetNumeric(cost_item);
		if (*procost <= 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("COST must be positive")));

	}
	if (rows_item)
	{
		*prorows = defGetNumeric(rows_item);
		if (*prorows <= 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("ROWS must be positive")));

	}
}



static void compute_attributes_with_style(List *parameters, bool *isStrict_p, char *volatility_p)
{
	ListCell   *pl;

	foreach(pl, parameters)
	{
		DefElem    *param = (DefElem *) lfirst(pl);

		if (pg_strcasecmp(param->defname, "isstrict") == 0)
			*isStrict_p = defGetBoolean(param);
		else if (pg_strcasecmp(param->defname, "iscachable") == 0)
		{
			
			if (defGetBoolean(param))
				*volatility_p = PROVOLATILE_IMMUTABLE;
		}
		else ereport(WARNING, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("unrecognized function attribute \"%s\" ignored", param->defname)));



	}
}



static void interpret_AS_clause(Oid languageOid, const char *languageName, char *funcname, List *as, char **prosrc_str_p, char **probin_str_p)


{
	Assert(as != NIL);

	if (languageOid == ClanguageId)
	{
		
		*probin_str_p = strVal(linitial(as));
		if (list_length(as) == 1)
			*prosrc_str_p = funcname;
		else {
			*prosrc_str_p = strVal(lsecond(as));
			if (strcmp(*prosrc_str_p, "-") == 0)
				*prosrc_str_p = funcname;
		}
	}
	else {
		
		*prosrc_str_p = strVal(linitial(as));
		*probin_str_p = NULL;

		if (list_length(as) != 1)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only one AS item needed for language \"%s\"", languageName)));



		if (languageOid == INTERNALlanguageId)
		{
			
			if (strlen(*prosrc_str_p) == 0)
				*prosrc_str_p = funcname;
		}
	}
}




Oid CreateFunction(CreateFunctionStmt *stmt, const char *queryString)
{
	char	   *probin_str;
	char	   *prosrc_str;
	Oid			prorettype;
	bool		returnsSet;
	char	   *language;
	Oid			languageOid;
	Oid			languageValidator;
	char	   *funcname;
	Oid			namespaceId;
	AclResult	aclresult;
	oidvector  *parameterTypes;
	ArrayType  *allParameterTypes;
	ArrayType  *parameterModes;
	ArrayType  *parameterNames;
	List	   *parameterDefaults;
	Oid			variadicArgType;
	Oid			requiredResultType;
	bool		isWindowFunc, isStrict, security, isLeakProof;


	char		volatility;
	ArrayType  *proconfig;
	float4		procost;
	float4		prorows;
	HeapTuple	languageTuple;
	Form_pg_language languageStruct;
	List	   *as_clause;

	
	namespaceId = QualifiedNameGetCreationNamespace(stmt->funcname, &funcname);

	
	aclresult = pg_namespace_aclcheck(namespaceId, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(namespaceId));

	
	isWindowFunc = false;
	isStrict = false;
	security = false;
	isLeakProof = false;
	volatility = PROVOLATILE_VOLATILE;
	proconfig = NULL;
	procost = -1;				
	prorows = -1;				

	
	compute_attributes_sql_style(stmt->options, &as_clause, &language, &isWindowFunc, &volatility, &isStrict, &security, &isLeakProof, &proconfig, &procost, &prorows);




	
	languageTuple = SearchSysCache1(LANGNAME, PointerGetDatum(language));
	if (!HeapTupleIsValid(languageTuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("language \"%s\" does not exist", language), (PLTemplateExists(language) ? errhint("Use CREATE LANGUAGE to load the language into the database.") : 0)));




	languageOid = HeapTupleGetOid(languageTuple);
	languageStruct = (Form_pg_language) GETSTRUCT(languageTuple);

	if (languageStruct->lanpltrusted)
	{
		
		AclResult	aclresult;

		aclresult = pg_language_aclcheck(languageOid, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_LANGUAGE, NameStr(languageStruct->lanname));
	}
	else {
		
		if (!superuser())
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE, NameStr(languageStruct->lanname));
	}

	languageValidator = languageStruct->lanvalidator;

	ReleaseSysCache(languageTuple);

	
	if (isLeakProof && !superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("only superuser can define a leakproof function")));


	
	interpret_function_parameter_list(stmt->parameters, languageOid, false, queryString, &parameterTypes, &allParameterTypes, &parameterModes, &parameterNames, &parameterDefaults, &variadicArgType, &requiredResultType);










	if (stmt->returnType)
	{
		
		compute_return_type(stmt->returnType, languageOid, &prorettype, &returnsSet);
		if (OidIsValid(requiredResultType) && prorettype != requiredResultType)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("function result type must be %s because of OUT parameters", format_type_be(requiredResultType))));


	}
	else if (OidIsValid(requiredResultType))
	{
		
		prorettype = requiredResultType;
		returnsSet = false;
	}
	else {
		ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("function result type must be specified")));

		
		prorettype = VOIDOID;
		returnsSet = false;
	}

	compute_attributes_with_style(stmt->withClause, &isStrict, &volatility);

	interpret_AS_clause(languageOid, language, funcname, as_clause, &prosrc_str, &probin_str);

	
	if (procost < 0)
	{
		
		if (languageOid == INTERNALlanguageId || languageOid == ClanguageId)
			procost = 1;
		else procost = 100;
	}
	if (prorows < 0)
	{
		if (returnsSet)
			prorows = 1000;
		else prorows = 0;
	}
	else if (!returnsSet)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("ROWS is not applicable when function does not return a set")));


	
	return ProcedureCreate(funcname, namespaceId, stmt->replace, returnsSet, prorettype, GetUserId(), languageOid, languageValidator, prosrc_str, probin_str, false, isWindowFunc, security, isLeakProof, isStrict, volatility, parameterTypes, PointerGetDatum(allParameterTypes), PointerGetDatum(parameterModes), PointerGetDatum(parameterNames), parameterDefaults, PointerGetDatum(proconfig), procost, prorows);






















}



void RemoveFunctionById(Oid funcOid)
{
	Relation	relation;
	HeapTuple	tup;
	bool		isagg;

	
	relation = heap_open(ProcedureRelationId, RowExclusiveLock);

	tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcOid));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for function %u", funcOid);

	isagg = ((Form_pg_proc) GETSTRUCT(tup))->proisagg;

	simple_heap_delete(relation, &tup->t_self);

	ReleaseSysCache(tup);

	heap_close(relation, RowExclusiveLock);

	
	if (isagg)
	{
		relation = heap_open(AggregateRelationId, RowExclusiveLock);

		tup = SearchSysCache1(AGGFNOID, ObjectIdGetDatum(funcOid));
		if (!HeapTupleIsValid(tup))		
			elog(ERROR, "cache lookup failed for pg_aggregate tuple for function %u", funcOid);

		simple_heap_delete(relation, &tup->t_self);

		ReleaseSysCache(tup);

		heap_close(relation, RowExclusiveLock);
	}
}


Oid AlterFunction(AlterFunctionStmt *stmt)
{
	HeapTuple	tup;
	Oid			funcOid;
	Form_pg_proc procForm;
	Relation	rel;
	ListCell   *l;
	DefElem    *volatility_item = NULL;
	DefElem    *strict_item = NULL;
	DefElem    *security_def_item = NULL;
	DefElem    *leakproof_item = NULL;
	List	   *set_items = NIL;
	DefElem    *cost_item = NULL;
	DefElem    *rows_item = NULL;

	rel = heap_open(ProcedureRelationId, RowExclusiveLock);

	funcOid = LookupFuncNameTypeNames(stmt->func->funcname, stmt->func->funcargs, false);


	tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(funcOid));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for function %u", funcOid);

	procForm = (Form_pg_proc) GETSTRUCT(tup);

	
	if (!pg_proc_ownercheck(funcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC, NameListToString(stmt->func->funcname));

	if (procForm->proisagg)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is an aggregate function", NameListToString(stmt->func->funcname))));



	
	foreach(l, stmt->actions)
	{
		DefElem    *defel = (DefElem *) lfirst(l);

		if (compute_common_attribute(defel, &volatility_item, &strict_item, &security_def_item, &leakproof_item, &set_items, &cost_item, &rows_item) == false)






			elog(ERROR, "option \"%s\" not recognized", defel->defname);
	}

	if (volatility_item)
		procForm->provolatile = interpret_func_volatility(volatility_item);
	if (strict_item)
		procForm->proisstrict = intVal(strict_item->arg);
	if (security_def_item)
		procForm->prosecdef = intVal(security_def_item->arg);
	if (leakproof_item)
	{
		if (intVal(leakproof_item->arg) && !superuser())
			ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("only superuser can define a leakproof function")));

		procForm->proleakproof = intVal(leakproof_item->arg);
	}
	if (cost_item)
	{
		procForm->procost = defGetNumeric(cost_item);
		if (procForm->procost <= 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("COST must be positive")));

	}
	if (rows_item)
	{
		procForm->prorows = defGetNumeric(rows_item);
		if (procForm->prorows <= 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("ROWS must be positive")));

		if (!procForm->proretset)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("ROWS is not applicable when function does not return a set")));

	}
	if (set_items)
	{
		Datum		datum;
		bool		isnull;
		ArrayType  *a;
		Datum		repl_val[Natts_pg_proc];
		bool		repl_null[Natts_pg_proc];
		bool		repl_repl[Natts_pg_proc];

		
		datum = SysCacheGetAttr(PROCOID, tup, Anum_pg_proc_proconfig, &isnull);
		a = isnull ? NULL : DatumGetArrayTypeP(datum);

		
		a = update_proconfig_value(a, set_items);

		
		memset(repl_repl, false, sizeof(repl_repl));
		repl_repl[Anum_pg_proc_proconfig - 1] = true;

		if (a == NULL)
		{
			repl_val[Anum_pg_proc_proconfig - 1] = (Datum) 0;
			repl_null[Anum_pg_proc_proconfig - 1] = true;
		}
		else {
			repl_val[Anum_pg_proc_proconfig - 1] = PointerGetDatum(a);
			repl_null[Anum_pg_proc_proconfig - 1] = false;
		}

		tup = heap_modify_tuple(tup, RelationGetDescr(rel), repl_val, repl_null, repl_repl);
	}

	
	simple_heap_update(rel, &tup->t_self, tup);
	CatalogUpdateIndexes(rel, tup);

	InvokeObjectPostAlterHook(ProcedureRelationId, funcOid, 0);

	heap_close(rel, NoLock);
	heap_freetuple(tup);

	return funcOid;
}


void SetFunctionReturnType(Oid funcOid, Oid newRetType)
{
	Relation	pg_proc_rel;
	HeapTuple	tup;
	Form_pg_proc procForm;

	pg_proc_rel = heap_open(ProcedureRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(funcOid));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for function %u", funcOid);
	procForm = (Form_pg_proc) GETSTRUCT(tup);

	if (procForm->prorettype != OPAQUEOID)		
		elog(ERROR, "function %u doesn't return OPAQUE", funcOid);

	
	procForm->prorettype = newRetType;

	
	simple_heap_update(pg_proc_rel, &tup->t_self, tup);

	CatalogUpdateIndexes(pg_proc_rel, tup);

	heap_close(pg_proc_rel, RowExclusiveLock);
}



void SetFunctionArgType(Oid funcOid, int argIndex, Oid newArgType)
{
	Relation	pg_proc_rel;
	HeapTuple	tup;
	Form_pg_proc procForm;

	pg_proc_rel = heap_open(ProcedureRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(funcOid));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for function %u", funcOid);
	procForm = (Form_pg_proc) GETSTRUCT(tup);

	if (argIndex < 0 || argIndex >= procForm->pronargs || procForm->proargtypes.values[argIndex] != OPAQUEOID)
		elog(ERROR, "function %u doesn't take OPAQUE", funcOid);

	
	procForm->proargtypes.values[argIndex] = newArgType;

	
	simple_heap_update(pg_proc_rel, &tup->t_self, tup);

	CatalogUpdateIndexes(pg_proc_rel, tup);

	heap_close(pg_proc_rel, RowExclusiveLock);
}




Oid CreateCast(CreateCastStmt *stmt)
{
	Oid			sourcetypeid;
	Oid			targettypeid;
	char		sourcetyptype;
	char		targettyptype;
	Oid			funcid;
	Oid			castid;
	int			nargs;
	char		castcontext;
	char		castmethod;
	Relation	relation;
	HeapTuple	tuple;
	Datum		values[Natts_pg_cast];
	bool		nulls[Natts_pg_cast];
	ObjectAddress myself, referenced;
	AclResult	aclresult;

	sourcetypeid = typenameTypeId(NULL, stmt->sourcetype);
	targettypeid = typenameTypeId(NULL, stmt->targettype);
	sourcetyptype = get_typtype(sourcetypeid);
	targettyptype = get_typtype(targettypeid);

	
	if (sourcetyptype == TYPTYPE_PSEUDO)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("source data type %s is a pseudo-type", TypeNameToString(stmt->sourcetype))));



	if (targettyptype == TYPTYPE_PSEUDO)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("target data type %s is a pseudo-type", TypeNameToString(stmt->targettype))));



	
	if (!pg_type_ownercheck(sourcetypeid, GetUserId())
		&& !pg_type_ownercheck(targettypeid, GetUserId()))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be owner of type %s or type %s", format_type_be(sourcetypeid), format_type_be(targettypeid))));




	aclresult = pg_type_aclcheck(sourcetypeid, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, sourcetypeid);

	aclresult = pg_type_aclcheck(targettypeid, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, targettypeid);

	
	if (sourcetyptype == TYPTYPE_DOMAIN)
		ereport(WARNING, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cast will be ignored because the source data type is a domain")));


	else if (targettyptype == TYPTYPE_DOMAIN)
		ereport(WARNING, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cast will be ignored because the target data type is a domain")));


	
	if (stmt->func != NULL)
		castmethod = COERCION_METHOD_FUNCTION;
	else if (stmt->inout)
		castmethod = COERCION_METHOD_INOUT;
	else castmethod = COERCION_METHOD_BINARY;

	if (castmethod == COERCION_METHOD_FUNCTION)
	{
		Form_pg_proc procstruct;

		funcid = LookupFuncNameTypeNames(stmt->func->funcname, stmt->func->funcargs, false);


		tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcid));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for function %u", funcid);

		procstruct = (Form_pg_proc) GETSTRUCT(tuple);
		nargs = procstruct->pronargs;
		if (nargs < 1 || nargs > 3)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cast function must take one to three arguments")));

		if (!IsBinaryCoercible(sourcetypeid, procstruct->proargtypes.values[0]))
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("argument of cast function must match or be binary-coercible from source data type")));

		if (nargs > 1 && procstruct->proargtypes.values[1] != INT4OID)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("second argument of cast function must be type integer")));

		if (nargs > 2 && procstruct->proargtypes.values[2] != BOOLOID)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("third argument of cast function must be type boolean")));

		if (!IsBinaryCoercible(procstruct->prorettype, targettypeid))
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("return data type of cast function must match or be binary-coercible to target data type")));


		

		if (procstruct->provolatile == PROVOLATILE_VOLATILE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cast function must not be volatile")));


		if (procstruct->proisagg)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cast function must not be an aggregate function")));

		if (procstruct->proiswindow)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cast function must not be a window function")));

		if (procstruct->proretset)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cast function must not return a set")));


		ReleaseSysCache(tuple);
	}
	else {
		funcid = InvalidOid;
		nargs = 0;
	}

	if (castmethod == COERCION_METHOD_BINARY)
	{
		int16		typ1len;
		int16		typ2len;
		bool		typ1byval;
		bool		typ2byval;
		char		typ1align;
		char		typ2align;

		
		if (!superuser())
			ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to create a cast WITHOUT FUNCTION")));


		
		get_typlenbyvalalign(sourcetypeid, &typ1len, &typ1byval, &typ1align);
		get_typlenbyvalalign(targettypeid, &typ2len, &typ2byval, &typ2align);
		if (typ1len != typ2len || typ1byval != typ2byval || typ1align != typ2align)

			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("source and target data types are not physically compatible")));


		
		if (sourcetyptype == TYPTYPE_COMPOSITE || targettyptype == TYPTYPE_COMPOSITE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("composite data types are not binary-compatible")));


		if (sourcetyptype == TYPTYPE_ENUM || targettyptype == TYPTYPE_ENUM)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("enum data types are not binary-compatible")));


		if (OidIsValid(get_element_type(sourcetypeid)) || OidIsValid(get_element_type(targettypeid)))
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("array data types are not binary-compatible")));


		
		if (sourcetyptype == TYPTYPE_DOMAIN || targettyptype == TYPTYPE_DOMAIN)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("domain data types must not be marked binary-compatible")));

	}

	
	if (sourcetypeid == targettypeid && nargs < 2)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("source data type and target data type are the same")));


	
	switch (stmt->context)
	{
		case COERCION_IMPLICIT:
			castcontext = COERCION_CODE_IMPLICIT;
			break;
		case COERCION_ASSIGNMENT:
			castcontext = COERCION_CODE_ASSIGNMENT;
			break;
		case COERCION_EXPLICIT:
			castcontext = COERCION_CODE_EXPLICIT;
			break;
		default:
			elog(ERROR, "unrecognized CoercionContext: %d", stmt->context);
			castcontext = 0;	
			break;
	}

	relation = heap_open(CastRelationId, RowExclusiveLock);

	
	tuple = SearchSysCache2(CASTSOURCETARGET, ObjectIdGetDatum(sourcetypeid), ObjectIdGetDatum(targettypeid));

	if (HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("cast from type %s to type %s already exists", format_type_be(sourcetypeid), format_type_be(targettypeid))));




	
	values[Anum_pg_cast_castsource - 1] = ObjectIdGetDatum(sourcetypeid);
	values[Anum_pg_cast_casttarget - 1] = ObjectIdGetDatum(targettypeid);
	values[Anum_pg_cast_castfunc - 1] = ObjectIdGetDatum(funcid);
	values[Anum_pg_cast_castcontext - 1] = CharGetDatum(castcontext);
	values[Anum_pg_cast_castmethod - 1] = CharGetDatum(castmethod);

	MemSet(nulls, false, sizeof(nulls));

	tuple = heap_form_tuple(RelationGetDescr(relation), values, nulls);

	castid = simple_heap_insert(relation, tuple);

	CatalogUpdateIndexes(relation, tuple);

	
	myself.classId = CastRelationId;
	myself.objectId = castid;
	myself.objectSubId = 0;

	
	referenced.classId = TypeRelationId;
	referenced.objectId = sourcetypeid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	
	referenced.classId = TypeRelationId;
	referenced.objectId = targettypeid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	
	if (OidIsValid(funcid))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = funcid;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	recordDependencyOnCurrentExtension(&myself, false);

	
	InvokeObjectPostCreateHook(CastRelationId, castid, 0);

	heap_freetuple(tuple);

	heap_close(relation, RowExclusiveLock);

	return castid;
}


Oid get_cast_oid(Oid sourcetypeid, Oid targettypeid, bool missing_ok)
{
	Oid			oid;

	oid = GetSysCacheOid2(CASTSOURCETARGET, ObjectIdGetDatum(sourcetypeid), ObjectIdGetDatum(targettypeid));

	if (!OidIsValid(oid) && !missing_ok)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("cast from type %s to type %s does not exist", format_type_be(sourcetypeid), format_type_be(targettypeid))));



	return oid;
}

void DropCastById(Oid castOid)
{
	Relation	relation;
	ScanKeyData scankey;
	SysScanDesc scan;
	HeapTuple	tuple;

	relation = heap_open(CastRelationId, RowExclusiveLock);

	ScanKeyInit(&scankey, ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(castOid));


	scan = systable_beginscan(relation, CastOidIndexId, true, NULL, 1, &scankey);

	tuple = systable_getnext(scan);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for cast %u", castOid);
	simple_heap_delete(relation, &tuple->t_self);

	systable_endscan(scan);
	heap_close(relation, RowExclusiveLock);
}


void IsThereFunctionInNamespace(const char *proname, int pronargs, oidvector *proargtypes, Oid nspOid)

{
	
	if (SearchSysCacheExists3(PROCNAMEARGSNSP, CStringGetDatum(proname), PointerGetDatum(proargtypes), ObjectIdGetDatum(nspOid)))


		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_FUNCTION), errmsg("function %s already exists in schema \"%s\"", funcname_signature_string(proname, pronargs, NIL, proargtypes->values), get_namespace_name(nspOid))));




}


void ExecuteDoStmt(DoStmt *stmt)
{
	InlineCodeBlock *codeblock = makeNode(InlineCodeBlock);
	ListCell   *arg;
	DefElem    *as_item = NULL;
	DefElem    *language_item = NULL;
	char	   *language;
	Oid			laninline;
	HeapTuple	languageTuple;
	Form_pg_language languageStruct;

	
	foreach(arg, stmt->args)
	{
		DefElem    *defel = (DefElem *) lfirst(arg);

		if (strcmp(defel->defname, "as") == 0)
		{
			if (as_item)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			as_item = defel;
		}
		else if (strcmp(defel->defname, "language") == 0)
		{
			if (language_item)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			language_item = defel;
		}
		else elog(ERROR, "option \"%s\" not recognized", defel->defname);

	}

	if (as_item)
		codeblock->source_text = strVal(as_item->arg);
	else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("no inline code specified")));



	
	if (language_item)
		language = strVal(language_item->arg);
	else language = "plpgsql";

	
	languageTuple = SearchSysCache1(LANGNAME, PointerGetDatum(language));
	if (!HeapTupleIsValid(languageTuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("language \"%s\" does not exist", language), (PLTemplateExists(language) ? errhint("Use CREATE LANGUAGE to load the language into the database.") : 0)));




	codeblock->langOid = HeapTupleGetOid(languageTuple);
	languageStruct = (Form_pg_language) GETSTRUCT(languageTuple);
	codeblock->langIsTrusted = languageStruct->lanpltrusted;

	if (languageStruct->lanpltrusted)
	{
		
		AclResult	aclresult;

		aclresult = pg_language_aclcheck(codeblock->langOid, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_LANGUAGE, NameStr(languageStruct->lanname));
	}
	else {
		
		if (!superuser())
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE, NameStr(languageStruct->lanname));
	}

	
	laninline = languageStruct->laninline;
	if (!OidIsValid(laninline))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("language \"%s\" does not support inline code execution", NameStr(languageStruct->lanname))));



	ReleaseSysCache(languageTuple);

	
	OidFunctionCall1(laninline, PointerGetDatum(codeblock));
}
