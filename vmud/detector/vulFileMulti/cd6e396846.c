


























































typedef struct RI_ConstraintInfo {
	Oid			constraint_id;	
	NameData	conname;		
	Oid			pk_relid;		
	Oid			fk_relid;		
	char		confupdtype;	
	char		confdeltype;	
	char		confmatchtype;	
	int			nkeys;			
	int16		pk_attnums[RI_MAX_NUMKEYS];		
	int16		fk_attnums[RI_MAX_NUMKEYS];		
	Oid			pf_eq_oprs[RI_MAX_NUMKEYS];		
	Oid			pp_eq_oprs[RI_MAX_NUMKEYS];		
	Oid			ff_eq_oprs[RI_MAX_NUMKEYS];		
} RI_ConstraintInfo;



typedef struct RI_QueryKey {
	char		constr_type;
	Oid			constr_id;
	int32		constr_queryno;
	Oid			fk_relid;
	Oid			pk_relid;
	int32		nkeypairs;
	int16		keypair[RI_MAX_NUMKEYS][2];
} RI_QueryKey;



typedef struct RI_QueryHashEntry {
	RI_QueryKey key;
	SPIPlanPtr	plan;
} RI_QueryHashEntry;



typedef struct RI_CompareKey {
	Oid			eq_opr;			
	Oid			typeid;			
} RI_CompareKey;



typedef struct RI_CompareHashEntry {
	RI_CompareKey key;
	bool		valid;			
	FmgrInfo	eq_opr_finfo;	
	FmgrInfo	cast_func_finfo;	
} RI_CompareHashEntry;



static HTAB *ri_query_cache = NULL;
static HTAB *ri_compare_cache = NULL;



static void quoteOneName(char *buffer, const char *name);
static void quoteRelationName(char *buffer, Relation rel);
static void ri_GenerateQual(StringInfo buf, const char *sep, const char *leftop, Oid leftoptype, Oid opoid, const char *rightop, Oid rightoptype);



static int ri_NullCheck(Relation rel, HeapTuple tup, RI_QueryKey *key, int pairidx);
static void ri_BuildQueryKeyFull(RI_QueryKey *key, const RI_ConstraintInfo *riinfo, int32 constr_queryno);

static void ri_BuildQueryKeyPkCheck(RI_QueryKey *key, const RI_ConstraintInfo *riinfo, int32 constr_queryno);

static bool ri_KeysEqual(Relation rel, HeapTuple oldtup, HeapTuple newtup, const RI_ConstraintInfo *riinfo, bool rel_is_pk);
static bool ri_AllKeysUnequal(Relation rel, HeapTuple oldtup, HeapTuple newtup, const RI_ConstraintInfo *riinfo, bool rel_is_pk);
static bool ri_OneKeyEqual(Relation rel, int column, HeapTuple oldtup, HeapTuple newtup, const RI_ConstraintInfo *riinfo, bool rel_is_pk);

static bool ri_AttributesEqual(Oid eq_opr, Oid typeid, Datum oldvalue, Datum newvalue);
static bool ri_Check_Pk_Match(Relation pk_rel, Relation fk_rel, HeapTuple old_row, const RI_ConstraintInfo *riinfo);


static void ri_InitHashTables(void);
static SPIPlanPtr ri_FetchPreparedPlan(RI_QueryKey *key);
static void ri_HashPreparedPlan(RI_QueryKey *key, SPIPlanPtr plan);
static RI_CompareHashEntry *ri_HashCompareOp(Oid eq_opr, Oid typeid);

static void ri_CheckTrigger(FunctionCallInfo fcinfo, const char *funcname, int tgkind);
static void ri_FetchConstraintInfo(RI_ConstraintInfo *riinfo, Trigger *trigger, Relation trig_rel, bool rel_is_pk);
static SPIPlanPtr ri_PlanCheck(const char *querystr, int nargs, Oid *argtypes, RI_QueryKey *qkey, Relation fk_rel, Relation pk_rel, bool cache_plan);

static bool ri_PerformCheck(RI_QueryKey *qkey, SPIPlanPtr qplan, Relation fk_rel, Relation pk_rel, HeapTuple old_tuple, HeapTuple new_tuple, bool detectNewRows, int expect_OK, const char *constrname);



static void ri_ExtractValues(RI_QueryKey *qkey, int key_idx, Relation rel, HeapTuple tuple, Datum *vals, char *nulls);

static void ri_ReportViolation(RI_QueryKey *qkey, const char *constrname, Relation pk_rel, Relation fk_rel, HeapTuple violator, TupleDesc tupdesc, bool spi_err);





static Datum RI_FKey_check(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	new_row;
	HeapTuple	old_row;
	Buffer		new_row_buf;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_check", RI_TRIGTYPE_INUP);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, false);

	if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
	{
		old_row = trigdata->tg_trigtuple;
		new_row = trigdata->tg_newtuple;
		new_row_buf = trigdata->tg_newtuplebuf;
	}
	else {
		old_row = NULL;
		new_row = trigdata->tg_trigtuple;
		new_row_buf = trigdata->tg_trigtuplebuf;
	}

	
	Assert(new_row_buf != InvalidBuffer);
	if (!HeapTupleSatisfiesVisibility(new_row, SnapshotSelf, new_row_buf))
		return PointerGetDatum(NULL);

	
	fk_rel = trigdata->tg_relation;
	pk_rel = heap_open(riinfo.pk_relid, RowShareLock);

	
	if (riinfo.nkeys == 0)
	{
		ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_CHECK_LOOKUPPK_NOCOLS);

		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed");

		if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
		{
			char		querystr[MAX_QUOTED_REL_NAME_LEN + 100];
			char		pkrelname[MAX_QUOTED_REL_NAME_LEN];

			
			quoteRelationName(pkrelname, pk_rel);
			snprintf(querystr, sizeof(querystr), "SELECT 1 FROM ONLY %s x FOR SHARE OF x", pkrelname);


			
			qplan = ri_PlanCheck(querystr, 0, NULL, &qkey, fk_rel, pk_rel, true);
		}

		
		ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, NULL, NULL, false, SPI_OK_SELECT, NameStr(riinfo.conname));





		if (SPI_finish() != SPI_OK_FINISH)
			elog(ERROR, "SPI_finish failed");

		heap_close(pk_rel, RowShareLock);

		return PointerGetDatum(NULL);
	}

	if (riinfo.confmatchtype == FKCONSTR_MATCH_PARTIAL)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));


	ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_CHECK_LOOKUPPK);

	switch (ri_NullCheck(fk_rel, new_row, &qkey, RI_KEYPAIR_FK_IDX))
	{
		case RI_KEYS_ALL_NULL:

			
			heap_close(pk_rel, RowShareLock);
			return PointerGetDatum(NULL);

		case RI_KEYS_SOME_NULL:

			
			switch (riinfo.confmatchtype)
			{
				case FKCONSTR_MATCH_FULL:

					
					ereport(ERROR, (errcode(ERRCODE_FOREIGN_KEY_VIOLATION), errmsg("insert or update on table \"%s\" violates foreign key constraint \"%s\"", RelationGetRelationName(trigdata->tg_relation), NameStr(riinfo.conname)), errdetail("MATCH FULL does not allow mixing of null and nonnull key values.")));




					heap_close(pk_rel, RowShareLock);
					return PointerGetDatum(NULL);

				case FKCONSTR_MATCH_UNSPECIFIED:

					
					heap_close(pk_rel, RowShareLock);
					return PointerGetDatum(NULL);

				case FKCONSTR_MATCH_PARTIAL:

					
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

					heap_close(pk_rel, RowShareLock);
					return PointerGetDatum(NULL);
			}

		case RI_KEYS_NONE_NULL:

			
			break;
	}

	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed");

	
	if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
	{
		StringInfoData querybuf;
		char		pkrelname[MAX_QUOTED_REL_NAME_LEN];
		char		attname[MAX_QUOTED_NAME_LEN];
		char		paramname[16];
		const char *querysep;
		Oid			queryoids[RI_MAX_NUMKEYS];

		
		initStringInfo(&querybuf);
		quoteRelationName(pkrelname, pk_rel);
		appendStringInfo(&querybuf, "SELECT 1 FROM ONLY %s x", pkrelname);
		querysep = "WHERE";
		for (i = 0; i < riinfo.nkeys; i++)
		{
			Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
			Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

			quoteOneName(attname, RIAttName(pk_rel, riinfo.pk_attnums[i]));
			sprintf(paramname, "$%d", i + 1);
			ri_GenerateQual(&querybuf, querysep, attname, pk_type, riinfo.pf_eq_oprs[i], paramname, fk_type);


			querysep = "AND";
			queryoids[i] = fk_type;
		}
		appendStringInfo(&querybuf, " FOR SHARE OF x");

		
		qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
	}

	
	ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, NULL, new_row, false, SPI_OK_SELECT, NameStr(riinfo.conname));





	if (SPI_finish() != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed");

	heap_close(pk_rel, RowShareLock);

	return PointerGetDatum(NULL);
}



Datum RI_FKey_check_ins(PG_FUNCTION_ARGS)
{
	return RI_FKey_check(fcinfo);
}



Datum RI_FKey_check_upd(PG_FUNCTION_ARGS)
{
	return RI_FKey_check(fcinfo);
}



static bool ri_Check_Pk_Match(Relation pk_rel, Relation fk_rel, HeapTuple old_row, const RI_ConstraintInfo *riinfo)


{
	SPIPlanPtr	qplan;
	RI_QueryKey qkey;
	int			i;
	bool		result;

	ri_BuildQueryKeyPkCheck(&qkey, riinfo, RI_PLAN_CHECK_LOOKUPPK);

	switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
	{
		case RI_KEYS_ALL_NULL:

			
			return true;

		case RI_KEYS_SOME_NULL:

			
			switch (riinfo->confmatchtype)
			{
				case FKCONSTR_MATCH_FULL:
				case FKCONSTR_MATCH_UNSPECIFIED:

					
					return true;

				case FKCONSTR_MATCH_PARTIAL:

					
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

					break;
			}

		case RI_KEYS_NONE_NULL:

			
			break;
	}

	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed");

	
	if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
	{
		StringInfoData querybuf;
		char		pkrelname[MAX_QUOTED_REL_NAME_LEN];
		char		attname[MAX_QUOTED_NAME_LEN];
		char		paramname[16];
		const char *querysep;
		Oid			queryoids[RI_MAX_NUMKEYS];

		
		initStringInfo(&querybuf);
		quoteRelationName(pkrelname, pk_rel);
		appendStringInfo(&querybuf, "SELECT 1 FROM ONLY %s x", pkrelname);
		querysep = "WHERE";
		for (i = 0; i < riinfo->nkeys; i++)
		{
			Oid			pk_type = RIAttType(pk_rel, riinfo->pk_attnums[i]);

			quoteOneName(attname, RIAttName(pk_rel, riinfo->pk_attnums[i]));
			sprintf(paramname, "$%d", i + 1);
			ri_GenerateQual(&querybuf, querysep, attname, pk_type, riinfo->pp_eq_oprs[i], paramname, pk_type);


			querysep = "AND";
			queryoids[i] = pk_type;
		}
		appendStringInfo(&querybuf, " FOR SHARE OF x");

		
		qplan = ri_PlanCheck(querybuf.data, riinfo->nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
	}

	
	result = ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_SELECT, NULL);




	if (SPI_finish() != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed");

	return result;
}



Datum RI_FKey_noaction_del(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_noaction_del", RI_TRIGTYPE_DELETE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowShareLock);
	pk_rel = trigdata->tg_relation;
	old_row = trigdata->tg_trigtuple;

	if (ri_Check_Pk_Match(pk_rel, fk_rel, old_row, &riinfo))
	{
		
		heap_close(fk_rel, RowShareLock);
		return PointerGetDatum(NULL);
	}

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_NOACTION_DEL_CHECKREF);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowShareLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "SELECT 1 FROM ONLY %s x", fkrelname);
				querysep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&querybuf, querysep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfo(&querybuf, " FOR SHARE OF x");

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_SELECT, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowShareLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_noaction_upd(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	new_row;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_noaction_upd", RI_TRIGTYPE_UPDATE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowShareLock);
	pk_rel = trigdata->tg_relation;
	new_row = trigdata->tg_newtuple;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_NOACTION_UPD_CHECKREF);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowShareLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			
			if (ri_KeysEqual(pk_rel, old_row, new_row, &riinfo, true))
			{
				heap_close(fk_rel, RowShareLock);
				return PointerGetDatum(NULL);
			}

			if (ri_Check_Pk_Match(pk_rel, fk_rel, old_row, &riinfo))
			{
				
				heap_close(fk_rel, RowShareLock);
				return PointerGetDatum(NULL);
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "SELECT 1 FROM ONLY %s x", fkrelname);
				querysep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&querybuf, querysep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfo(&querybuf, " FOR SHARE OF x");

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_SELECT, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowShareLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_cascade_del(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_cascade_del", RI_TRIGTYPE_DELETE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowExclusiveLock);
	pk_rel = trigdata->tg_relation;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_CASCADE_DEL_DODELETE);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowExclusiveLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "DELETE FROM ONLY %s", fkrelname);
				querysep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&querybuf, querysep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = "AND";
					queryoids[i] = pk_type;
				}

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_DELETE, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowExclusiveLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_cascade_upd(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	new_row;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;
	int			j;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_cascade_upd", RI_TRIGTYPE_UPDATE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowExclusiveLock);
	pk_rel = trigdata->tg_relation;
	new_row = trigdata->tg_newtuple;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_CASCADE_UPD_DOUPDATE);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowExclusiveLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			
			if (ri_KeysEqual(pk_rel, old_row, new_row, &riinfo, true))
			{
				heap_close(fk_rel, RowExclusiveLock);
				return PointerGetDatum(NULL);
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				StringInfoData qualbuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				const char *qualsep;
				Oid			queryoids[RI_MAX_NUMKEYS * 2];

				
				initStringInfo(&querybuf);
				initStringInfo(&qualbuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "UPDATE ONLY %s SET", fkrelname);
				querysep = "";
				qualsep = "WHERE";
				for (i = 0, j = riinfo.nkeys; i < riinfo.nkeys; i++, j++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					appendStringInfo(&querybuf, "%s %s = $%d", querysep, attname, i + 1);

					sprintf(paramname, "$%d", j + 1);
					ri_GenerateQual(&qualbuf, qualsep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = ",";
					qualsep = "AND";
					queryoids[i] = pk_type;
					queryoids[j] = pk_type;
				}
				appendStringInfoString(&querybuf, qualbuf.data);

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys * 2, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, new_row, true, SPI_OK_UPDATE, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowExclusiveLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_restrict_del(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_restrict_del", RI_TRIGTYPE_DELETE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowShareLock);
	pk_rel = trigdata->tg_relation;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_RESTRICT_DEL_CHECKREF);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowShareLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "SELECT 1 FROM ONLY %s x", fkrelname);
				querysep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&querybuf, querysep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfo(&querybuf, " FOR SHARE OF x");

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_SELECT, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowShareLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_restrict_upd(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	new_row;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_restrict_upd", RI_TRIGTYPE_UPDATE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowShareLock);
	pk_rel = trigdata->tg_relation;
	new_row = trigdata->tg_newtuple;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_RESTRICT_UPD_CHECKREF);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowShareLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			
			if (ri_KeysEqual(pk_rel, old_row, new_row, &riinfo, true))
			{
				heap_close(fk_rel, RowShareLock);
				return PointerGetDatum(NULL);
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "SELECT 1 FROM ONLY %s x", fkrelname);
				querysep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&querybuf, querysep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfo(&querybuf, " FOR SHARE OF x");

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_SELECT, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowShareLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_setnull_del(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_setnull_del", RI_TRIGTYPE_DELETE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowExclusiveLock);
	pk_rel = trigdata->tg_relation;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_SETNULL_DEL_DOUPDATE);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowExclusiveLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			if ((qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				StringInfoData qualbuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				const char *qualsep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				initStringInfo(&qualbuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "UPDATE ONLY %s SET", fkrelname);
				querysep = "";
				qualsep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					appendStringInfo(&querybuf, "%s %s = NULL", querysep, attname);

					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&qualbuf, qualsep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = ",";
					qualsep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfoString(&querybuf, qualbuf.data);

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, true);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_UPDATE, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowExclusiveLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_setnull_upd(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	new_row;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;
	int			i;
	bool		use_cached_query;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_setnull_upd", RI_TRIGTYPE_UPDATE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowExclusiveLock);
	pk_rel = trigdata->tg_relation;
	new_row = trigdata->tg_newtuple;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_SETNULL_UPD_DOUPDATE);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowExclusiveLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			
			if (ri_KeysEqual(pk_rel, old_row, new_row, &riinfo, true))
			{
				heap_close(fk_rel, RowExclusiveLock);
				return PointerGetDatum(NULL);
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			

			use_cached_query = (riinfo.confmatchtype == FKCONSTR_MATCH_FULL) || ri_AllKeysUnequal(pk_rel, old_row, new_row, &riinfo, true);


			
			if (!use_cached_query || (qplan = ri_FetchPreparedPlan(&qkey)) == NULL)
			{
				StringInfoData querybuf;
				StringInfoData qualbuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				const char *qualsep;
				Oid			queryoids[RI_MAX_NUMKEYS];

				
				initStringInfo(&querybuf);
				initStringInfo(&qualbuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "UPDATE ONLY %s SET", fkrelname);
				querysep = "";
				qualsep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));

					
					if (riinfo.confmatchtype == FKCONSTR_MATCH_FULL || !ri_OneKeyEqual(pk_rel, i, old_row, new_row, &riinfo, true))

					{
						appendStringInfo(&querybuf, "%s %s = NULL", querysep, attname);

						querysep = ",";
					}
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&qualbuf, qualsep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					qualsep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfoString(&querybuf, qualbuf.data);

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, use_cached_query);

			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_UPDATE, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowExclusiveLock);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_setdefault_del(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_setdefault_del", RI_TRIGTYPE_DELETE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowExclusiveLock);
	pk_rel = trigdata->tg_relation;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_SETNULL_DEL_DOUPDATE);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowExclusiveLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			{
				StringInfoData querybuf;
				StringInfoData qualbuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				const char *qualsep;
				Oid			queryoids[RI_MAX_NUMKEYS];
				int			i;

				
				initStringInfo(&querybuf);
				initStringInfo(&qualbuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "UPDATE ONLY %s SET", fkrelname);
				querysep = "";
				qualsep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
					appendStringInfo(&querybuf, "%s %s = DEFAULT", querysep, attname);

					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&qualbuf, qualsep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					querysep = ",";
					qualsep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfoString(&querybuf, qualbuf.data);

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, false);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_UPDATE, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowExclusiveLock);

			
			RI_FKey_noaction_del(fcinfo);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



Datum RI_FKey_setdefault_upd(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	Relation	pk_rel;
	HeapTuple	new_row;
	HeapTuple	old_row;
	RI_QueryKey qkey;
	SPIPlanPtr	qplan;

	
	ri_CheckTrigger(fcinfo, "RI_FKey_setdefault_upd", RI_TRIGTYPE_UPDATE);

	
	ri_FetchConstraintInfo(&riinfo, trigdata->tg_trigger, trigdata->tg_relation, true);

	
	if (riinfo.nkeys == 0)
		return PointerGetDatum(NULL);

	
	fk_rel = heap_open(riinfo.fk_relid, RowExclusiveLock);
	pk_rel = trigdata->tg_relation;
	new_row = trigdata->tg_newtuple;
	old_row = trigdata->tg_trigtuple;

	switch (riinfo.confmatchtype)
	{
			
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_SETNULL_DEL_DOUPDATE);

			switch (ri_NullCheck(pk_rel, old_row, &qkey, RI_KEYPAIR_PK_IDX))
			{
				case RI_KEYS_ALL_NULL:
				case RI_KEYS_SOME_NULL:

					
					heap_close(fk_rel, RowExclusiveLock);
					return PointerGetDatum(NULL);

				case RI_KEYS_NONE_NULL:

					
					break;
			}

			
			if (ri_KeysEqual(pk_rel, old_row, new_row, &riinfo, true))
			{
				heap_close(fk_rel, RowExclusiveLock);
				return PointerGetDatum(NULL);
			}

			if (SPI_connect() != SPI_OK_CONNECT)
				elog(ERROR, "SPI_connect failed");

			
			{
				StringInfoData querybuf;
				StringInfoData qualbuf;
				char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
				char		attname[MAX_QUOTED_NAME_LEN];
				char		paramname[16];
				const char *querysep;
				const char *qualsep;
				Oid			queryoids[RI_MAX_NUMKEYS];
				int			i;

				
				initStringInfo(&querybuf);
				initStringInfo(&qualbuf);
				quoteRelationName(fkrelname, fk_rel);
				appendStringInfo(&querybuf, "UPDATE ONLY %s SET", fkrelname);
				querysep = "";
				qualsep = "WHERE";
				for (i = 0; i < riinfo.nkeys; i++)
				{
					Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
					Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

					quoteOneName(attname, RIAttName(fk_rel, riinfo.fk_attnums[i]));

					
					if (riinfo.confmatchtype == FKCONSTR_MATCH_FULL || !ri_OneKeyEqual(pk_rel, i, old_row, new_row, &riinfo, true))

					{
						appendStringInfo(&querybuf, "%s %s = DEFAULT", querysep, attname);

						querysep = ",";
					}
					sprintf(paramname, "$%d", i + 1);
					ri_GenerateQual(&qualbuf, qualsep, paramname, pk_type, riinfo.pf_eq_oprs[i], attname, fk_type);


					qualsep = "AND";
					queryoids[i] = pk_type;
				}
				appendStringInfoString(&querybuf, qualbuf.data);

				
				qplan = ri_PlanCheck(querybuf.data, riinfo.nkeys, queryoids, &qkey, fk_rel, pk_rel, false);
			}

			
			ri_PerformCheck(&qkey, qplan, fk_rel, pk_rel, old_row, NULL, true, SPI_OK_UPDATE, NameStr(riinfo.conname));





			if (SPI_finish() != SPI_OK_FINISH)
				elog(ERROR, "SPI_finish failed");

			heap_close(fk_rel, RowExclusiveLock);

			
			RI_FKey_noaction_upd(fcinfo);

			return PointerGetDatum(NULL);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			return PointerGetDatum(NULL);
	}

	
	elog(ERROR, "invalid confmatchtype");
	return PointerGetDatum(NULL);
}



bool RI_FKey_keyequal_upd_pk(Trigger *trigger, Relation pk_rel, HeapTuple old_row, HeapTuple new_row)

{
	RI_ConstraintInfo riinfo;
	Relation	fk_rel;
	RI_QueryKey qkey;

	
	ri_FetchConstraintInfo(&riinfo, trigger, pk_rel, true);

	
	if (riinfo.nkeys == 0)
		return true;

	fk_rel = heap_open(riinfo.fk_relid, AccessShareLock);

	switch (riinfo.confmatchtype)
	{
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_KEYEQUAL_UPD);

			heap_close(fk_rel, AccessShareLock);

			
			return ri_KeysEqual(pk_rel, old_row, new_row, &riinfo, true);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			break;
	}

	
	elog(ERROR, "invalid confmatchtype");
	return false;
}


bool RI_FKey_keyequal_upd_fk(Trigger *trigger, Relation fk_rel, HeapTuple old_row, HeapTuple new_row)

{
	RI_ConstraintInfo riinfo;
	Relation	pk_rel;
	RI_QueryKey qkey;

	
	ri_FetchConstraintInfo(&riinfo, trigger, fk_rel, false);

	
	if (riinfo.nkeys == 0)
		return true;

	pk_rel = heap_open(riinfo.pk_relid, AccessShareLock);

	switch (riinfo.confmatchtype)
	{
		case FKCONSTR_MATCH_UNSPECIFIED:
		case FKCONSTR_MATCH_FULL:
			ri_BuildQueryKeyFull(&qkey, &riinfo, RI_PLAN_KEYEQUAL_UPD);
			heap_close(pk_rel, AccessShareLock);

			
			return ri_KeysEqual(fk_rel, old_row, new_row, &riinfo, false);

			
		case FKCONSTR_MATCH_PARTIAL:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

			break;
	}

	
	elog(ERROR, "invalid confmatchtype");
	return false;
}


bool RI_Initial_Check(Trigger *trigger, Relation fk_rel, Relation pk_rel)
{
	RI_ConstraintInfo riinfo;
	const char *constrname = trigger->tgname;
	StringInfoData querybuf;
	char		pkrelname[MAX_QUOTED_REL_NAME_LEN];
	char		fkrelname[MAX_QUOTED_REL_NAME_LEN];
	char		pkattname[MAX_QUOTED_NAME_LEN + 3];
	char		fkattname[MAX_QUOTED_NAME_LEN + 3];
	const char *sep;
	int			i;
	int			old_work_mem;
	char		workmembuf[32];
	int			spi_result;
	SPIPlanPtr	qplan;

	
	if (pg_class_aclcheck(RelationGetRelid(fk_rel), GetUserId(), ACL_SELECT) != ACLCHECK_OK)
		return false;
	if (pg_class_aclcheck(RelationGetRelid(pk_rel), GetUserId(), ACL_SELECT) != ACLCHECK_OK)
		return false;

	ri_FetchConstraintInfo(&riinfo, trigger, fk_rel, false);

	
	initStringInfo(&querybuf);
	appendStringInfo(&querybuf, "SELECT ");
	sep = "";
	for (i = 0; i < riinfo.nkeys; i++)
	{
		quoteOneName(fkattname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
		appendStringInfo(&querybuf, "%sfk.%s", sep, fkattname);
		sep = ", ";
	}

	quoteRelationName(pkrelname, pk_rel);
	quoteRelationName(fkrelname, fk_rel);
	appendStringInfo(&querybuf, " FROM ONLY %s fk LEFT OUTER JOIN ONLY %s pk ON", fkrelname, pkrelname);


	strcpy(pkattname, "pk.");
	strcpy(fkattname, "fk.");
	sep = "(";
	for (i = 0; i < riinfo.nkeys; i++)
	{
		Oid			pk_type = RIAttType(pk_rel, riinfo.pk_attnums[i]);
		Oid			fk_type = RIAttType(fk_rel, riinfo.fk_attnums[i]);

		quoteOneName(pkattname + 3, RIAttName(pk_rel, riinfo.pk_attnums[i]));
		quoteOneName(fkattname + 3, RIAttName(fk_rel, riinfo.fk_attnums[i]));
		ri_GenerateQual(&querybuf, sep, pkattname, pk_type, riinfo.pf_eq_oprs[i], fkattname, fk_type);


		sep = "AND";
	}

	
	quoteOneName(pkattname, RIAttName(pk_rel, riinfo.pk_attnums[0]));
	appendStringInfo(&querybuf, ") WHERE pk.%s IS NULL AND (", pkattname);

	sep = "";
	for (i = 0; i < riinfo.nkeys; i++)
	{
		quoteOneName(fkattname, RIAttName(fk_rel, riinfo.fk_attnums[i]));
		appendStringInfo(&querybuf, "%sfk.%s IS NOT NULL", sep, fkattname);

		switch (riinfo.confmatchtype)
		{
			case FKCONSTR_MATCH_UNSPECIFIED:
				sep = " AND ";
				break;
			case FKCONSTR_MATCH_FULL:
				sep = " OR ";
				break;
			case FKCONSTR_MATCH_PARTIAL:
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("MATCH PARTIAL not yet implemented")));

				break;
			default:
				elog(ERROR, "unrecognized match type: %d", riinfo.confmatchtype);
				break;
		}
	}
	appendStringInfo(&querybuf, ")");

	
	old_work_mem = work_mem;
	snprintf(workmembuf, sizeof(workmembuf), "%d", maintenance_work_mem);
	(void) set_config_option("work_mem", workmembuf, PGC_USERSET, PGC_S_SESSION, GUC_ACTION_LOCAL, true);


	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed");

	
	qplan = SPI_prepare(querybuf.data, 0, NULL);

	if (qplan == NULL)
		elog(ERROR, "SPI_prepare returned %d for %s", SPI_result, querybuf.data);

	
	spi_result = SPI_execute_snapshot(qplan, NULL, NULL, CopySnapshot(GetLatestSnapshot()), InvalidSnapshot, true, false, 1);




	
	if (spi_result != SPI_OK_SELECT)
		elog(ERROR, "SPI_execute_snapshot returned %d", spi_result);

	
	if (SPI_processed > 0)
	{
		HeapTuple	tuple = SPI_tuptable->vals[0];
		TupleDesc	tupdesc = SPI_tuptable->tupdesc;
		RI_QueryKey qkey;

		
		if (riinfo.confmatchtype == FKCONSTR_MATCH_FULL)
		{
			bool		isnull = false;

			for (i = 1; i <= riinfo.nkeys; i++)
			{
				(void) SPI_getbinval(tuple, tupdesc, i, &isnull);
				if (isnull)
					break;
			}
			if (isnull)
				ereport(ERROR, (errcode(ERRCODE_FOREIGN_KEY_VIOLATION), errmsg("insert or update on table \"%s\" violates foreign key constraint \"%s\"", RelationGetRelationName(fk_rel), constrname), errdetail("MATCH FULL does not allow mixing of null and nonnull key values.")));




		}

		
		MemSet(&qkey, 0, sizeof(qkey));
		qkey.constr_queryno = RI_PLAN_CHECK_LOOKUPPK;
		qkey.nkeypairs = riinfo.nkeys;
		for (i = 0; i < riinfo.nkeys; i++)
			qkey.keypair[i][RI_KEYPAIR_FK_IDX] = i + 1;

		ri_ReportViolation(&qkey, constrname, pk_rel, fk_rel, tuple, tupdesc, false);


	}

	if (SPI_finish() != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed");

	
	snprintf(workmembuf, sizeof(workmembuf), "%d", old_work_mem);
	(void) set_config_option("work_mem", workmembuf, PGC_USERSET, PGC_S_SESSION, GUC_ACTION_LOCAL, true);


	return true;
}






static void quoteOneName(char *buffer, const char *name)
{
	
	*buffer++ = '"';
	while (*name)
	{
		if (*name == '"')
			*buffer++ = '"';
		*buffer++ = *name++;
	}
	*buffer++ = '"';
	*buffer = '\0';
}


static void quoteRelationName(char *buffer, Relation rel)
{
	quoteOneName(buffer, get_namespace_name(RelationGetNamespace(rel)));
	buffer += strlen(buffer);
	*buffer++ = '.';
	quoteOneName(buffer, RelationGetRelationName(rel));
}


static void ri_GenerateQual(StringInfo buf, const char *sep, const char *leftop, Oid leftoptype, Oid opoid, const char *rightop, Oid rightoptype)




{
	HeapTuple	opertup;
	Form_pg_operator operform;
	char	   *oprname;
	char	   *nspname;

	opertup = SearchSysCache(OPEROID, ObjectIdGetDatum(opoid), 0, 0, 0);

	if (!HeapTupleIsValid(opertup))
		elog(ERROR, "cache lookup failed for operator %u", opoid);
	operform = (Form_pg_operator) GETSTRUCT(opertup);
	Assert(operform->oprkind == 'b');
	oprname = NameStr(operform->oprname);

	nspname = get_namespace_name(operform->oprnamespace);

	appendStringInfo(buf, " %s %s", sep, leftop);
	if (leftoptype != operform->oprleft)
		appendStringInfo(buf, "::%s", format_type_be(operform->oprleft));
	appendStringInfo(buf, " OPERATOR(%s.", quote_identifier(nspname));
	appendStringInfoString(buf, oprname);
	appendStringInfo(buf, ") %s", rightop);
	if (rightoptype != operform->oprright)
		appendStringInfo(buf, "::%s", format_type_be(operform->oprright));

	ReleaseSysCache(opertup);
}


static void ri_BuildQueryKeyFull(RI_QueryKey *key, const RI_ConstraintInfo *riinfo, int32 constr_queryno)

{
	int			i;

	MemSet(key, 0, sizeof(RI_QueryKey));
	key->constr_type = FKCONSTR_MATCH_FULL;
	key->constr_id = riinfo->constraint_id;
	key->constr_queryno = constr_queryno;
	key->fk_relid = riinfo->fk_relid;
	key->pk_relid = riinfo->pk_relid;
	key->nkeypairs = riinfo->nkeys;
	for (i = 0; i < riinfo->nkeys; i++)
	{
		key->keypair[i][RI_KEYPAIR_FK_IDX] = riinfo->fk_attnums[i];
		key->keypair[i][RI_KEYPAIR_PK_IDX] = riinfo->pk_attnums[i];
	}
}


static void ri_CheckTrigger(FunctionCallInfo fcinfo, const char *funcname, int tgkind)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;

	if (!CALLED_AS_TRIGGER(fcinfo))
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("function \"%s\" was not called by trigger manager", funcname)));


	
	if (!TRIGGER_FIRED_AFTER(trigdata->tg_event) || !TRIGGER_FIRED_FOR_ROW(trigdata->tg_event))
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("function \"%s\" must be fired AFTER ROW", funcname)));


	switch (tgkind)
	{
		case RI_TRIGTYPE_INSERT:
			if (!TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
				ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("function \"%s\" must be fired for INSERT", funcname)));

			break;
		case RI_TRIGTYPE_UPDATE:
			if (!TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
				ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("function \"%s\" must be fired for UPDATE", funcname)));

			break;
		case RI_TRIGTYPE_INUP:
			if (!TRIGGER_FIRED_BY_INSERT(trigdata->tg_event) && !TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
				ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("function \"%s\" must be fired for INSERT or UPDATE", funcname)));


			break;
		case RI_TRIGTYPE_DELETE:
			if (!TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
				ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("function \"%s\" must be fired for DELETE", funcname)));

			break;
	}
}



static void ri_FetchConstraintInfo(RI_ConstraintInfo *riinfo, Trigger *trigger, Relation trig_rel, bool rel_is_pk)

{
	Oid			constraintOid = trigger->tgconstraint;
	HeapTuple	tup;
	Form_pg_constraint conForm;
	Datum		adatum;
	bool		isNull;
	ArrayType  *arr;
	int			numkeys;

	
	if (!OidIsValid(constraintOid))
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("no pg_constraint entry for trigger \"%s\" on table \"%s\"", trigger->tgname, RelationGetRelationName(trig_rel)), errhint("Remove this referential integrity trigger and its mates, then do ALTER TABLE ADD CONSTRAINT.")));




	
	tup = SearchSysCache(CONSTROID, ObjectIdGetDatum(constraintOid), 0, 0, 0);

	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for constraint %u", constraintOid);
	conForm = (Form_pg_constraint) GETSTRUCT(tup);

	
	if (rel_is_pk)
	{
		if (conForm->contype != CONSTRAINT_FOREIGN || conForm->conrelid != trigger->tgconstrrelid || conForm->confrelid != RelationGetRelid(trig_rel))

			elog(ERROR, "wrong pg_constraint entry for trigger \"%s\" on table \"%s\"", trigger->tgname, RelationGetRelationName(trig_rel));
	}
	else {
		if (conForm->contype != CONSTRAINT_FOREIGN || conForm->conrelid != RelationGetRelid(trig_rel) || conForm->confrelid != trigger->tgconstrrelid)

			elog(ERROR, "wrong pg_constraint entry for trigger \"%s\" on table \"%s\"", trigger->tgname, RelationGetRelationName(trig_rel));
	}

	
	riinfo->constraint_id = constraintOid;
	memcpy(&riinfo->conname, &conForm->conname, sizeof(NameData));
	riinfo->pk_relid = conForm->confrelid;
	riinfo->fk_relid = conForm->conrelid;
	riinfo->confupdtype = conForm->confupdtype;
	riinfo->confdeltype = conForm->confdeltype;
	riinfo->confmatchtype = conForm->confmatchtype;

	
	adatum = SysCacheGetAttr(CONSTROID, tup, Anum_pg_constraint_conkey, &isNull);
	if (isNull)
		elog(ERROR, "null conkey for constraint %u", constraintOid);
	arr = DatumGetArrayTypeP(adatum);	
	numkeys = ARR_DIMS(arr)[0];
	if (ARR_NDIM(arr) != 1 || numkeys < 0 || numkeys > RI_MAX_NUMKEYS || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != INT2OID)



		elog(ERROR, "conkey is not a 1-D smallint array");
	riinfo->nkeys = numkeys;
	memcpy(riinfo->fk_attnums, ARR_DATA_PTR(arr), numkeys * sizeof(int16));

	adatum = SysCacheGetAttr(CONSTROID, tup, Anum_pg_constraint_confkey, &isNull);
	if (isNull)
		elog(ERROR, "null confkey for constraint %u", constraintOid);
	arr = DatumGetArrayTypeP(adatum);	
	numkeys = ARR_DIMS(arr)[0];
	if (ARR_NDIM(arr) != 1 || numkeys != riinfo->nkeys || numkeys > RI_MAX_NUMKEYS || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != INT2OID)



		elog(ERROR, "confkey is not a 1-D smallint array");
	memcpy(riinfo->pk_attnums, ARR_DATA_PTR(arr), numkeys * sizeof(int16));

	adatum = SysCacheGetAttr(CONSTROID, tup, Anum_pg_constraint_conpfeqop, &isNull);
	if (isNull)
		elog(ERROR, "null conpfeqop for constraint %u", constraintOid);
	arr = DatumGetArrayTypeP(adatum);	
	numkeys = ARR_DIMS(arr)[0];
	if (ARR_NDIM(arr) != 1 || numkeys != riinfo->nkeys || numkeys > RI_MAX_NUMKEYS || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != OIDOID)



		elog(ERROR, "conpfeqop is not a 1-D Oid array");
	memcpy(riinfo->pf_eq_oprs, ARR_DATA_PTR(arr), numkeys * sizeof(Oid));

	adatum = SysCacheGetAttr(CONSTROID, tup, Anum_pg_constraint_conppeqop, &isNull);
	if (isNull)
		elog(ERROR, "null conppeqop for constraint %u", constraintOid);
	arr = DatumGetArrayTypeP(adatum);	
	numkeys = ARR_DIMS(arr)[0];
	if (ARR_NDIM(arr) != 1 || numkeys != riinfo->nkeys || numkeys > RI_MAX_NUMKEYS || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != OIDOID)



		elog(ERROR, "conppeqop is not a 1-D Oid array");
	memcpy(riinfo->pp_eq_oprs, ARR_DATA_PTR(arr), numkeys * sizeof(Oid));

	adatum = SysCacheGetAttr(CONSTROID, tup, Anum_pg_constraint_conffeqop, &isNull);
	if (isNull)
		elog(ERROR, "null conffeqop for constraint %u", constraintOid);
	arr = DatumGetArrayTypeP(adatum);	
	numkeys = ARR_DIMS(arr)[0];
	if (ARR_NDIM(arr) != 1 || numkeys != riinfo->nkeys || numkeys > RI_MAX_NUMKEYS || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != OIDOID)



		elog(ERROR, "conffeqop is not a 1-D Oid array");
	memcpy(riinfo->ff_eq_oprs, ARR_DATA_PTR(arr), numkeys * sizeof(Oid));

	ReleaseSysCache(tup);
}



static SPIPlanPtr ri_PlanCheck(const char *querystr, int nargs, Oid *argtypes, RI_QueryKey *qkey, Relation fk_rel, Relation pk_rel, bool cache_plan)


{
	SPIPlanPtr	qplan;
	Relation	query_rel;
	Oid			save_uid;

	
	if (qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK || qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK_NOCOLS)
		query_rel = pk_rel;
	else query_rel = fk_rel;

	
	save_uid = GetUserId();
	SetUserId(RelationGetForm(query_rel)->relowner);

	
	qplan = SPI_prepare(querystr, nargs, argtypes);

	if (qplan == NULL)
		elog(ERROR, "SPI_prepare returned %d for %s", SPI_result, querystr);

	
	SetUserId(save_uid);

	
	if (cache_plan)
	{
		qplan = SPI_saveplan(qplan);
		ri_HashPreparedPlan(qkey, qplan);
	}

	return qplan;
}


static bool ri_PerformCheck(RI_QueryKey *qkey, SPIPlanPtr qplan, Relation fk_rel, Relation pk_rel, HeapTuple old_tuple, HeapTuple new_tuple, bool detectNewRows, int expect_OK, const char *constrname)




{
	Relation	query_rel, source_rel;
	int			key_idx;
	Snapshot	test_snapshot;
	Snapshot	crosscheck_snapshot;
	int			limit;
	int			spi_result;
	Oid			save_uid;
	Datum		vals[RI_MAX_NUMKEYS * 2];
	char		nulls[RI_MAX_NUMKEYS * 2];

	
	if (qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK || qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK_NOCOLS)
		query_rel = pk_rel;
	else query_rel = fk_rel;

	
	if (qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK && constrname != NULL)
	{
		source_rel = fk_rel;
		key_idx = RI_KEYPAIR_FK_IDX;
	}
	else {
		source_rel = pk_rel;
		key_idx = RI_KEYPAIR_PK_IDX;
	}

	
	if (new_tuple)
	{
		ri_ExtractValues(qkey, key_idx, source_rel, new_tuple, vals, nulls);
		if (old_tuple)
			ri_ExtractValues(qkey, key_idx, source_rel, old_tuple, vals + qkey->nkeypairs, nulls + qkey->nkeypairs);
	}
	else {
		ri_ExtractValues(qkey, key_idx, source_rel, old_tuple, vals, nulls);
	}

	
	if (IsXactIsoLevelSerializable && detectNewRows)
	{
		CommandCounterIncrement();		
		test_snapshot = CopySnapshot(GetLatestSnapshot());
		crosscheck_snapshot = CopySnapshot(GetTransactionSnapshot());
	}
	else {
		
		test_snapshot = InvalidSnapshot;
		crosscheck_snapshot = InvalidSnapshot;
	}

	
	limit = (expect_OK == SPI_OK_SELECT) ? 1 : 0;

	
	save_uid = GetUserId();
	SetUserId(RelationGetForm(query_rel)->relowner);

	
	spi_result = SPI_execute_snapshot(qplan, vals, nulls, test_snapshot, crosscheck_snapshot, false, false, limit);



	
	SetUserId(save_uid);

	
	if (spi_result < 0)
		elog(ERROR, "SPI_execute_snapshot returned %d", spi_result);

	if (expect_OK >= 0 && spi_result != expect_OK)
		ri_ReportViolation(qkey, constrname ? constrname : "", pk_rel, fk_rel, new_tuple ? new_tuple : old_tuple, NULL, true);




	
	if (constrname && expect_OK == SPI_OK_SELECT && (SPI_processed == 0) == (qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK))
		ri_ReportViolation(qkey, constrname, pk_rel, fk_rel, new_tuple ? new_tuple : old_tuple, NULL, false);




	return SPI_processed != 0;
}


static void ri_ExtractValues(RI_QueryKey *qkey, int key_idx, Relation rel, HeapTuple tuple, Datum *vals, char *nulls)


{
	int			i;
	bool		isnull;

	for (i = 0; i < qkey->nkeypairs; i++)
	{
		vals[i] = SPI_getbinval(tuple, rel->rd_att, qkey->keypair[i][key_idx], &isnull);

		nulls[i] = isnull ? 'n' : ' ';
	}
}


static void ri_ReportViolation(RI_QueryKey *qkey, const char *constrname, Relation pk_rel, Relation fk_rel, HeapTuple violator, TupleDesc tupdesc, bool spi_err)



{

	char		key_names[BUFLENGTH];
	char		key_values[BUFLENGTH];
	char	   *name_ptr = key_names;
	char	   *val_ptr = key_values;
	bool		onfk;
	int			idx, key_idx;

	if (spi_err)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("referential integrity query on \"%s\" from constraint \"%s\" on \"%s\" gave unexpected result", RelationGetRelationName(pk_rel), constrname, RelationGetRelationName(fk_rel)), errhint("This is most likely due to a rule having rewritten the query.")));






	
	onfk = (qkey->constr_queryno == RI_PLAN_CHECK_LOOKUPPK);
	if (onfk)
	{
		key_idx = RI_KEYPAIR_FK_IDX;
		if (tupdesc == NULL)
			tupdesc = fk_rel->rd_att;
	}
	else {
		key_idx = RI_KEYPAIR_PK_IDX;
		if (tupdesc == NULL)
			tupdesc = pk_rel->rd_att;
	}

	
	if (qkey->nkeypairs == 0)
	{
		ereport(ERROR, (errcode(ERRCODE_FOREIGN_KEY_VIOLATION), errmsg("insert or update on table \"%s\" violates foreign key constraint \"%s\"", RelationGetRelationName(fk_rel), constrname), errdetail("No rows were found in \"%s\".", RelationGetRelationName(pk_rel))));




	}

	
	for (idx = 0; idx < qkey->nkeypairs; idx++)
	{
		int			fnum = qkey->keypair[idx][key_idx];
		char	   *name, *val;

		name = SPI_fname(tupdesc, fnum);
		val = SPI_getvalue(violator, tupdesc, fnum);
		if (!val)
			val = "null";

		
		if (strlen(name) >= (key_names + BUFLENGTH - 5) - name_ptr || strlen(val) >= (key_values + BUFLENGTH - 5) - val_ptr)
		{
			sprintf(name_ptr, "...");
			sprintf(val_ptr, "...");
			break;
		}

		name_ptr += sprintf(name_ptr, "%s%s", idx > 0 ? "," : "", name);
		val_ptr += sprintf(val_ptr, "%s%s", idx > 0 ? "," : "", val);
	}

	if (onfk)
		ereport(ERROR, (errcode(ERRCODE_FOREIGN_KEY_VIOLATION), errmsg("insert or update on table \"%s\" violates foreign key constraint \"%s\"", RelationGetRelationName(fk_rel), constrname), errdetail("Key (%s)=(%s) is not present in table \"%s\".", key_names, key_values, RelationGetRelationName(pk_rel))));





	else ereport(ERROR, (errcode(ERRCODE_FOREIGN_KEY_VIOLATION), errmsg("update or delete on table \"%s\" violates foreign key constraint \"%s\" on table \"%s\"", RelationGetRelationName(pk_rel), constrname, RelationGetRelationName(fk_rel)), errdetail("Key (%s)=(%s) is still referenced from table \"%s\".", key_names, key_values, RelationGetRelationName(fk_rel))));







}


static void ri_BuildQueryKeyPkCheck(RI_QueryKey *key, const RI_ConstraintInfo *riinfo, int32 constr_queryno)

{
	int			i;

	MemSet(key, 0, sizeof(RI_QueryKey));
	key->constr_type = FKCONSTR_MATCH_FULL;
	key->constr_id = riinfo->constraint_id;
	key->constr_queryno = constr_queryno;
	key->fk_relid = InvalidOid;
	key->pk_relid = riinfo->pk_relid;
	key->nkeypairs = riinfo->nkeys;
	for (i = 0; i < riinfo->nkeys; i++)
	{
		key->keypair[i][RI_KEYPAIR_FK_IDX] = 0;
		key->keypair[i][RI_KEYPAIR_PK_IDX] = riinfo->pk_attnums[i];
	}
}



static int ri_NullCheck(Relation rel, HeapTuple tup, RI_QueryKey *key, int pairidx)
{
	int			i;
	bool		isnull;
	bool		allnull = true;
	bool		nonenull = true;

	for (i = 0; i < key->nkeypairs; i++)
	{
		isnull = false;
		SPI_getbinval(tup, rel->rd_att, key->keypair[i][pairidx], &isnull);
		if (isnull)
			nonenull = false;
		else allnull = false;
	}

	if (allnull)
		return RI_KEYS_ALL_NULL;

	if (nonenull)
		return RI_KEYS_NONE_NULL;

	return RI_KEYS_SOME_NULL;
}



static void ri_InitHashTables(void)
{
	HASHCTL		ctl;

	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(RI_QueryKey);
	ctl.entrysize = sizeof(RI_QueryHashEntry);
	ctl.hash = tag_hash;
	ri_query_cache = hash_create("RI query cache", RI_INIT_QUERYHASHSIZE, &ctl, HASH_ELEM | HASH_FUNCTION);

	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(RI_CompareKey);
	ctl.entrysize = sizeof(RI_CompareHashEntry);
	ctl.hash = tag_hash;
	ri_compare_cache = hash_create("RI compare cache", RI_INIT_QUERYHASHSIZE, &ctl, HASH_ELEM | HASH_FUNCTION);
}



static SPIPlanPtr ri_FetchPreparedPlan(RI_QueryKey *key)
{
	RI_QueryHashEntry *entry;

	
	if (!ri_query_cache)
		ri_InitHashTables();

	
	entry = (RI_QueryHashEntry *) hash_search(ri_query_cache, (void *) key, HASH_FIND, NULL);

	if (entry == NULL)
		return NULL;
	return entry->plan;
}



static void ri_HashPreparedPlan(RI_QueryKey *key, SPIPlanPtr plan)
{
	RI_QueryHashEntry *entry;
	bool		found;

	
	if (!ri_query_cache)
		ri_InitHashTables();

	
	entry = (RI_QueryHashEntry *) hash_search(ri_query_cache, (void *) key, HASH_ENTER, &found);

	entry->plan = plan;
}



static bool ri_KeysEqual(Relation rel, HeapTuple oldtup, HeapTuple newtup, const RI_ConstraintInfo *riinfo, bool rel_is_pk)

{
	TupleDesc	tupdesc = RelationGetDescr(rel);
	const int16 *attnums;
	const Oid  *eq_oprs;
	int			i;

	if (rel_is_pk)
	{
		attnums = riinfo->pk_attnums;
		eq_oprs = riinfo->pp_eq_oprs;
	}
	else {
		attnums = riinfo->fk_attnums;
		eq_oprs = riinfo->ff_eq_oprs;
	}

	for (i = 0; i < riinfo->nkeys; i++)
	{
		Datum		oldvalue;
		Datum		newvalue;
		bool		isnull;

		
		oldvalue = SPI_getbinval(oldtup, tupdesc, attnums[i], &isnull);
		if (isnull)
			return false;

		
		newvalue = SPI_getbinval(newtup, tupdesc, attnums[i], &isnull);
		if (isnull)
			return false;

		
		if (!ri_AttributesEqual(eq_oprs[i], RIAttType(rel, attnums[i]), oldvalue, newvalue))
			return false;
	}

	return true;
}



static bool ri_AllKeysUnequal(Relation rel, HeapTuple oldtup, HeapTuple newtup, const RI_ConstraintInfo *riinfo, bool rel_is_pk)

{
	TupleDesc	tupdesc = RelationGetDescr(rel);
	const int16 *attnums;
	const Oid  *eq_oprs;
	int			i;

	if (rel_is_pk)
	{
		attnums = riinfo->pk_attnums;
		eq_oprs = riinfo->pp_eq_oprs;
	}
	else {
		attnums = riinfo->fk_attnums;
		eq_oprs = riinfo->ff_eq_oprs;
	}

	for (i = 0; i < riinfo->nkeys; i++)
	{
		Datum		oldvalue;
		Datum		newvalue;
		bool		isnull;

		
		oldvalue = SPI_getbinval(oldtup, tupdesc, attnums[i], &isnull);
		if (isnull)
			continue;

		
		newvalue = SPI_getbinval(newtup, tupdesc, attnums[i], &isnull);
		if (isnull)
			continue;

		
		if (ri_AttributesEqual(eq_oprs[i], RIAttType(rel, attnums[i]), oldvalue, newvalue))
			return false;		
	}

	return true;
}



static bool ri_OneKeyEqual(Relation rel, int column, HeapTuple oldtup, HeapTuple newtup, const RI_ConstraintInfo *riinfo, bool rel_is_pk)

{
	TupleDesc	tupdesc = RelationGetDescr(rel);
	const int16 *attnums;
	const Oid  *eq_oprs;
	Datum		oldvalue;
	Datum		newvalue;
	bool		isnull;

	if (rel_is_pk)
	{
		attnums = riinfo->pk_attnums;
		eq_oprs = riinfo->pp_eq_oprs;
	}
	else {
		attnums = riinfo->fk_attnums;
		eq_oprs = riinfo->ff_eq_oprs;
	}

	
	oldvalue = SPI_getbinval(oldtup, tupdesc, attnums[column], &isnull);
	if (isnull)
		return false;

	
	newvalue = SPI_getbinval(newtup, tupdesc, attnums[column], &isnull);
	if (isnull)
		return false;

	
	if (!ri_AttributesEqual(eq_oprs[column], RIAttType(rel, attnums[column]), oldvalue, newvalue))
		return false;

	return true;
}


static bool ri_AttributesEqual(Oid eq_opr, Oid typeid, Datum oldvalue, Datum newvalue)

{
	RI_CompareHashEntry *entry = ri_HashCompareOp(eq_opr, typeid);

	
	if (OidIsValid(entry->cast_func_finfo.fn_oid))
	{
		oldvalue = FunctionCall3(&entry->cast_func_finfo, oldvalue, Int32GetDatum(-1), BoolGetDatum(false));


		newvalue = FunctionCall3(&entry->cast_func_finfo, newvalue, Int32GetDatum(-1), BoolGetDatum(false));


	}

	
	return DatumGetBool(FunctionCall2(&entry->eq_opr_finfo, oldvalue, newvalue));
}


static RI_CompareHashEntry * ri_HashCompareOp(Oid eq_opr, Oid typeid)
{
	RI_CompareKey key;
	RI_CompareHashEntry *entry;
	bool		found;

	
	if (!ri_compare_cache)
		ri_InitHashTables();

	
	key.eq_opr = eq_opr;
	key.typeid = typeid;
	entry = (RI_CompareHashEntry *) hash_search(ri_compare_cache, (void *) &key, HASH_ENTER, &found);

	if (!found)
		entry->valid = false;

	
	if (!entry->valid)
	{
		Oid			lefttype, righttype, castfunc;

		CoercionPathType pathtype;

		
		fmgr_info_cxt(get_opcode(eq_opr), &entry->eq_opr_finfo, TopMemoryContext);

		
		op_input_types(eq_opr, &lefttype, &righttype);
		Assert(lefttype == righttype);
		if (typeid == lefttype)
			castfunc = InvalidOid;		
		else {
			pathtype = find_coercion_pathway(lefttype, typeid, COERCION_IMPLICIT, &castfunc);

			if (pathtype != COERCION_PATH_FUNC && pathtype != COERCION_PATH_RELABELTYPE)
			{
				
				if (lefttype != ANYARRAYOID)
					elog(ERROR, "no conversion function from %s to %s", format_type_be(typeid), format_type_be(lefttype));

			}
		}
		if (OidIsValid(castfunc))
			fmgr_info_cxt(castfunc, &entry->cast_func_finfo, TopMemoryContext);
		else entry->cast_func_finfo.fn_oid = InvalidOid;
		entry->valid = true;
	}

	return entry;
}



int RI_FKey_trigger_type(Oid tgfoid)
{
	switch (tgfoid)
	{
		case F_RI_FKEY_CASCADE_DEL:
		case F_RI_FKEY_CASCADE_UPD:
		case F_RI_FKEY_RESTRICT_DEL:
		case F_RI_FKEY_RESTRICT_UPD:
		case F_RI_FKEY_SETNULL_DEL:
		case F_RI_FKEY_SETNULL_UPD:
		case F_RI_FKEY_SETDEFAULT_DEL:
		case F_RI_FKEY_SETDEFAULT_UPD:
		case F_RI_FKEY_NOACTION_DEL:
		case F_RI_FKEY_NOACTION_UPD:
			return RI_TRIGGER_PK;

		case F_RI_FKEY_CHECK_INS:
		case F_RI_FKEY_CHECK_UPD:
			return RI_TRIGGER_FK;
	}

	return RI_TRIGGER_NONE;
}
