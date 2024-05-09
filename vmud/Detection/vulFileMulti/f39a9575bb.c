






























typedef struct {
	BlockNumber N;				
	int			n;				
	BlockNumber t;				
	int			m;				
} BlockSamplerData;
typedef BlockSamplerData *BlockSampler;


typedef struct AnlIndexData {
	IndexInfo  *indexInfo;		
	double		tupleFract;		
	VacAttrStats **vacattrstats;	
	int			attr_cnt;
} AnlIndexData;



int			default_statistics_target = 10;


static int	elevel = -1;

static MemoryContext anl_context = NULL;

static BufferAccessStrategy vac_strategy;


static void BlockSampler_Init(BlockSampler bs, BlockNumber nblocks, int samplesize);
static bool BlockSampler_HasMore(BlockSampler bs);
static BlockNumber BlockSampler_Next(BlockSampler bs);
static void compute_index_stats(Relation onerel, double totalrows, AnlIndexData *indexdata, int nindexes, HeapTuple *rows, int numrows, MemoryContext col_context);


static VacAttrStats *examine_attribute(Relation onerel, int attnum);
static int acquire_sample_rows(Relation onerel, HeapTuple *rows, int targrows, double *totalrows, double *totaldeadrows);
static double random_fract(void);
static double init_selection_state(int n);
static double get_next_S(double t, int n, double *stateptr);
static int	compare_rows(const void *a, const void *b);
static void update_attstats(Oid relid, int natts, VacAttrStats **vacattrstats);
static Datum std_fetch_func(VacAttrStatsP stats, int rownum, bool *isNull);
static Datum ind_fetch_func(VacAttrStatsP stats, int rownum, bool *isNull);

static bool std_typanalyze(VacAttrStats *stats);



void analyze_rel(Oid relid, VacuumStmt *vacstmt, BufferAccessStrategy bstrategy)

{
	Relation	onerel;
	int			attr_cnt, tcnt, i, ind;


	Relation   *Irel;
	int			nindexes;
	bool		hasindex;
	bool		analyzableindex;
	VacAttrStats **vacattrstats;
	AnlIndexData *indexdata;
	int			targrows, numrows;
	double		totalrows, totaldeadrows;
	HeapTuple  *rows;
	PGRUsage	ru0;
	TimestampTz starttime = 0;

	if (vacstmt->verbose)
		elevel = INFO;
	else elevel = DEBUG2;

	vac_strategy = bstrategy;

	
	anl_context = CurrentMemoryContext;

	
	CHECK_FOR_INTERRUPTS();

	
	onerel = try_relation_open(relid, ShareUpdateExclusiveLock);
	if (!onerel)
		return;

	
	if (!(pg_class_ownercheck(RelationGetRelid(onerel), GetUserId()) || (pg_database_ownercheck(MyDatabaseId, GetUserId()) && !onerel->rd_rel->relisshared)))
	{
		
		if (!vacstmt->vacuum)
			ereport(WARNING, (errmsg("skipping \"%s\" --- only table or database owner can analyze it", RelationGetRelationName(onerel))));

		relation_close(onerel, ShareUpdateExclusiveLock);
		return;
	}

	
	if (onerel->rd_rel->relkind != RELKIND_RELATION)
	{
		
		if (!vacstmt->vacuum)
			ereport(WARNING, (errmsg("skipping \"%s\" --- cannot analyze indexes, views, or special system tables", RelationGetRelationName(onerel))));

		relation_close(onerel, ShareUpdateExclusiveLock);
		return;
	}

	
	if (isOtherTempNamespace(RelationGetNamespace(onerel)))
	{
		relation_close(onerel, ShareUpdateExclusiveLock);
		return;
	}

	
	if (RelationGetRelid(onerel) == StatisticRelationId)
	{
		relation_close(onerel, ShareUpdateExclusiveLock);
		return;
	}

	
	LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);
	MyProc->vacuumFlags |= PROC_IN_ANALYZE;
	LWLockRelease(ProcArrayLock);

	
	if (IsAutoVacuumWorkerProcess() && Log_autovacuum_min_duration >= 0)
	{
		pg_rusage_init(&ru0);
		if (Log_autovacuum_min_duration > 0)
			starttime = GetCurrentTimestamp();
	}

	ereport(elevel, (errmsg("analyzing \"%s.%s\"", get_namespace_name(RelationGetNamespace(onerel)), RelationGetRelationName(onerel))));



	
	if (vacstmt->va_cols != NIL)
	{
		ListCell   *le;

		vacattrstats = (VacAttrStats **) palloc(list_length(vacstmt->va_cols) * sizeof(VacAttrStats *));
		tcnt = 0;
		foreach(le, vacstmt->va_cols)
		{
			char	   *col = strVal(lfirst(le));

			i = attnameAttNum(onerel, col, false);
			if (i == InvalidAttrNumber)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", col, RelationGetRelationName(onerel))));


			vacattrstats[tcnt] = examine_attribute(onerel, i);
			if (vacattrstats[tcnt] != NULL)
				tcnt++;
		}
		attr_cnt = tcnt;
	}
	else {
		attr_cnt = onerel->rd_att->natts;
		vacattrstats = (VacAttrStats **)
			palloc(attr_cnt * sizeof(VacAttrStats *));
		tcnt = 0;
		for (i = 1; i <= attr_cnt; i++)
		{
			vacattrstats[tcnt] = examine_attribute(onerel, i);
			if (vacattrstats[tcnt] != NULL)
				tcnt++;
		}
		attr_cnt = tcnt;
	}

	
	vac_open_indexes(onerel, AccessShareLock, &nindexes, &Irel);
	hasindex = (nindexes > 0);
	indexdata = NULL;
	analyzableindex = false;
	if (hasindex)
	{
		indexdata = (AnlIndexData *) palloc0(nindexes * sizeof(AnlIndexData));
		for (ind = 0; ind < nindexes; ind++)
		{
			AnlIndexData *thisdata = &indexdata[ind];
			IndexInfo  *indexInfo;

			thisdata->indexInfo = indexInfo = BuildIndexInfo(Irel[ind]);
			thisdata->tupleFract = 1.0; 
			if (indexInfo->ii_Expressions != NIL && vacstmt->va_cols == NIL)
			{
				ListCell   *indexpr_item = list_head(indexInfo->ii_Expressions);

				thisdata->vacattrstats = (VacAttrStats **)
					palloc(indexInfo->ii_NumIndexAttrs * sizeof(VacAttrStats *));
				tcnt = 0;
				for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
				{
					int			keycol = indexInfo->ii_KeyAttrNumbers[i];

					if (keycol == 0)
					{
						
						Node	   *indexkey;

						if (indexpr_item == NULL)		
							elog(ERROR, "too few entries in indexprs list");
						indexkey = (Node *) lfirst(indexpr_item);
						indexpr_item = lnext(indexpr_item);

						
						if (exprType(indexkey) != Irel[ind]->rd_att->attrs[i]->atttypid)
							continue;

						thisdata->vacattrstats[tcnt] = examine_attribute(Irel[ind], i + 1);
						if (thisdata->vacattrstats[tcnt] != NULL)
						{
							tcnt++;
							analyzableindex = true;
						}
					}
				}
				thisdata->attr_cnt = tcnt;
			}
		}
	}

	
	if (attr_cnt <= 0 && !analyzableindex)
	{
		
		if (!vacstmt->vacuum)
			pgstat_report_analyze(RelationGetRelid(onerel), onerel->rd_rel->relisshared, 0, 0);


		vac_close_indexes(nindexes, Irel, AccessShareLock);
		relation_close(onerel, ShareUpdateExclusiveLock);
		return;
	}

	
	targrows = 100;
	for (i = 0; i < attr_cnt; i++)
	{
		if (targrows < vacattrstats[i]->minrows)
			targrows = vacattrstats[i]->minrows;
	}
	for (ind = 0; ind < nindexes; ind++)
	{
		AnlIndexData *thisdata = &indexdata[ind];

		for (i = 0; i < thisdata->attr_cnt; i++)
		{
			if (targrows < thisdata->vacattrstats[i]->minrows)
				targrows = thisdata->vacattrstats[i]->minrows;
		}
	}

	
	rows = (HeapTuple *) palloc(targrows * sizeof(HeapTuple));
	numrows = acquire_sample_rows(onerel, rows, targrows, &totalrows, &totaldeadrows);

	
	if (numrows > 0)
	{
		MemoryContext col_context, old_context;

		col_context = AllocSetContextCreate(anl_context, "Analyze Column", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);



		old_context = MemoryContextSwitchTo(col_context);

		for (i = 0; i < attr_cnt; i++)
		{
			VacAttrStats *stats = vacattrstats[i];

			stats->rows = rows;
			stats->tupDesc = onerel->rd_att;
			(*stats->compute_stats) (stats, std_fetch_func, numrows, totalrows);


			MemoryContextResetAndDeleteChildren(col_context);
		}

		if (hasindex)
			compute_index_stats(onerel, totalrows, indexdata, nindexes, rows, numrows, col_context);



		MemoryContextSwitchTo(old_context);
		MemoryContextDelete(col_context);

		
		update_attstats(relid, attr_cnt, vacattrstats);

		for (ind = 0; ind < nindexes; ind++)
		{
			AnlIndexData *thisdata = &indexdata[ind];

			update_attstats(RelationGetRelid(Irel[ind]), thisdata->attr_cnt, thisdata->vacattrstats);
		}
	}

	
	if (!vacstmt->vacuum)
	{
		vac_update_relstats(RelationGetRelid(onerel), RelationGetNumberOfBlocks(onerel), totalrows, hasindex, InvalidTransactionId);



		for (ind = 0; ind < nindexes; ind++)
		{
			AnlIndexData *thisdata = &indexdata[ind];
			double		totalindexrows;

			totalindexrows = ceil(thisdata->tupleFract * totalrows);
			vac_update_relstats(RelationGetRelid(Irel[ind]), RelationGetNumberOfBlocks(Irel[ind]), totalindexrows, false, InvalidTransactionId);


		}

		
		pgstat_report_analyze(RelationGetRelid(onerel), onerel->rd_rel->relisshared, totalrows, totaldeadrows);

	}

	
	vac_close_indexes(nindexes, Irel, NoLock);

	
	relation_close(onerel, NoLock);

	
	if (IsAutoVacuumWorkerProcess() && Log_autovacuum_min_duration >= 0)
	{
		if (Log_autovacuum_min_duration == 0 || TimestampDifferenceExceeds(starttime, GetCurrentTimestamp(), Log_autovacuum_min_duration))

			ereport(LOG, (errmsg("automatic analyze of table \"%s.%s.%s\" system usage: %s", get_database_name(MyDatabaseId), get_namespace_name(RelationGetNamespace(onerel)), RelationGetRelationName(onerel), pg_rusage_show(&ru0))));




	}

	
	LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);
	MyProc->vacuumFlags &= ~PROC_IN_ANALYZE;
	LWLockRelease(ProcArrayLock);
}


static void compute_index_stats(Relation onerel, double totalrows, AnlIndexData *indexdata, int nindexes, HeapTuple *rows, int numrows, MemoryContext col_context)



{
	MemoryContext ind_context, old_context;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];
	int			ind, i;

	ind_context = AllocSetContextCreate(anl_context, "Analyze Index", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);



	old_context = MemoryContextSwitchTo(ind_context);

	for (ind = 0; ind < nindexes; ind++)
	{
		AnlIndexData *thisdata = &indexdata[ind];
		IndexInfo  *indexInfo = thisdata->indexInfo;
		int			attr_cnt = thisdata->attr_cnt;
		TupleTableSlot *slot;
		EState	   *estate;
		ExprContext *econtext;
		List	   *predicate;
		Datum	   *exprvals;
		bool	   *exprnulls;
		int			numindexrows, tcnt, rowno;

		double		totalindexrows;

		
		if (attr_cnt == 0 && indexInfo->ii_Predicate == NIL)
			continue;

		
		estate = CreateExecutorState();
		econtext = GetPerTupleExprContext(estate);
		
		slot = MakeSingleTupleTableSlot(RelationGetDescr(onerel));

		
		econtext->ecxt_scantuple = slot;

		
		predicate = (List *)
			ExecPrepareExpr((Expr *) indexInfo->ii_Predicate, estate);

		
		exprvals = (Datum *) palloc(numrows * attr_cnt * sizeof(Datum));
		exprnulls = (bool *) palloc(numrows * attr_cnt * sizeof(bool));
		numindexrows = 0;
		tcnt = 0;
		for (rowno = 0; rowno < numrows; rowno++)
		{
			HeapTuple	heapTuple = rows[rowno];

			
			ExecStoreTuple(heapTuple, slot, InvalidBuffer, false);

			
			if (predicate != NIL)
			{
				if (!ExecQual(predicate, econtext, false))
					continue;
			}
			numindexrows++;

			if (attr_cnt > 0)
			{
				
				FormIndexDatum(indexInfo, slot, estate, values, isnull);




				
				for (i = 0; i < attr_cnt; i++)
				{
					VacAttrStats *stats = thisdata->vacattrstats[i];
					int			attnum = stats->attr->attnum;

					exprvals[tcnt] = values[attnum - 1];
					exprnulls[tcnt] = isnull[attnum - 1];
					tcnt++;
				}
			}
		}

		
		thisdata->tupleFract = (double) numindexrows / (double) numrows;
		totalindexrows = ceil(thisdata->tupleFract * totalrows);

		
		if (numindexrows > 0)
		{
			MemoryContextSwitchTo(col_context);
			for (i = 0; i < attr_cnt; i++)
			{
				VacAttrStats *stats = thisdata->vacattrstats[i];

				stats->exprvals = exprvals + i;
				stats->exprnulls = exprnulls + i;
				stats->rowstride = attr_cnt;
				(*stats->compute_stats) (stats, ind_fetch_func, numindexrows, totalindexrows);


				MemoryContextResetAndDeleteChildren(col_context);
			}
		}

		
		MemoryContextSwitchTo(ind_context);

		ExecDropSingleTupleTableSlot(slot);
		FreeExecutorState(estate);
		MemoryContextResetAndDeleteChildren(ind_context);
	}

	MemoryContextSwitchTo(old_context);
	MemoryContextDelete(ind_context);
}


static VacAttrStats * examine_attribute(Relation onerel, int attnum)
{
	Form_pg_attribute attr = onerel->rd_att->attrs[attnum - 1];
	HeapTuple	typtuple;
	VacAttrStats *stats;
	bool		ok;

	
	if (attr->attisdropped)
		return NULL;

	
	if (attr->attstattarget == 0)
		return NULL;

	
	stats = (VacAttrStats *) palloc0(sizeof(VacAttrStats));
	stats->attr = (Form_pg_attribute) palloc(ATTRIBUTE_TUPLE_SIZE);
	memcpy(stats->attr, attr, ATTRIBUTE_TUPLE_SIZE);
	typtuple = SearchSysCache(TYPEOID, ObjectIdGetDatum(attr->atttypid), 0, 0, 0);

	if (!HeapTupleIsValid(typtuple))
		elog(ERROR, "cache lookup failed for type %u", attr->atttypid);
	stats->attrtype = (Form_pg_type) palloc(sizeof(FormData_pg_type));
	memcpy(stats->attrtype, GETSTRUCT(typtuple), sizeof(FormData_pg_type));
	ReleaseSysCache(typtuple);
	stats->anl_context = anl_context;
	stats->tupattnum = attnum;

	
	if (OidIsValid(stats->attrtype->typanalyze))
		ok = DatumGetBool(OidFunctionCall1(stats->attrtype->typanalyze, PointerGetDatum(stats)));
	else ok = std_typanalyze(stats);

	if (!ok || stats->compute_stats == NULL || stats->minrows <= 0)
	{
		pfree(stats->attrtype);
		pfree(stats->attr);
		pfree(stats);
		return NULL;
	}

	return stats;
}


static void BlockSampler_Init(BlockSampler bs, BlockNumber nblocks, int samplesize)
{
	bs->N = nblocks;			

	
	bs->n = samplesize;
	bs->t = 0;					
	bs->m = 0;					
}

static bool BlockSampler_HasMore(BlockSampler bs)
{
	return (bs->t < bs->N) && (bs->m < bs->n);
}

static BlockNumber BlockSampler_Next(BlockSampler bs)
{
	BlockNumber K = bs->N - bs->t;		
	int			k = bs->n - bs->m;		
	double		p;				
	double		V;				

	Assert(BlockSampler_HasMore(bs));	

	if ((BlockNumber) k >= K)
	{
		
		bs->m++;
		return bs->t++;
	}

	
	V = random_fract();
	p = 1.0 - (double) k / (double) K;
	while (V < p)
	{
		
		bs->t++;
		K--;					

		
		p *= 1.0 - (double) k / (double) K;
	}

	
	bs->m++;
	return bs->t++;
}


static int acquire_sample_rows(Relation onerel, HeapTuple *rows, int targrows, double *totalrows, double *totaldeadrows)

{
	int			numrows = 0;	
	double		liverows = 0;	
	double		deadrows = 0;	
	double		rowstoskip = -1;	
	BlockNumber totalblocks;
	BlockSamplerData bs;
	double		rstate;

	Assert(targrows > 1);

	totalblocks = RelationGetNumberOfBlocks(onerel);

	
	BlockSampler_Init(&bs, totalblocks, targrows);
	
	rstate = init_selection_state(targrows);

	
	while (BlockSampler_HasMore(&bs))
	{
		BlockNumber targblock = BlockSampler_Next(&bs);
		Buffer		targbuffer;
		Page		targpage;
		OffsetNumber targoffset, maxoffset;

		vacuum_delay_point();

		
		targbuffer = ReadBufferWithStrategy(onerel, targblock, vac_strategy);
		LockBuffer(targbuffer, BUFFER_LOCK_SHARE);
		targpage = BufferGetPage(targbuffer);
		maxoffset = PageGetMaxOffsetNumber(targpage);
		LockBuffer(targbuffer, BUFFER_LOCK_UNLOCK);

		
		for (targoffset = FirstOffsetNumber; targoffset <= maxoffset; targoffset++)
		{
			HeapTupleData targtuple;

			ItemPointerSet(&targtuple.t_self, targblock, targoffset);
			
			if (heap_release_fetch(onerel, SnapshotNow, &targtuple, &targbuffer, true, NULL))

			{
				
				if (numrows < targrows)
					rows[numrows++] = heap_copytuple(&targtuple);
				else {
					
					if (rowstoskip < 0)
						rowstoskip = get_next_S(liverows, targrows, &rstate);

					if (rowstoskip <= 0)
					{
						
						int			k = (int) (targrows * random_fract());

						Assert(k >= 0 && k < targrows);
						heap_freetuple(rows[k]);
						rows[k] = heap_copytuple(&targtuple);
					}

					rowstoskip -= 1;
				}

				liverows += 1;
			}
			else {
				
				if (targtuple.t_data != NULL)
					deadrows += 1;
			}
		}

		
		ReleaseBuffer(targbuffer);
	}

	
	if (numrows == targrows)
		qsort((void *) rows, numrows, sizeof(HeapTuple), compare_rows);

	
	if (bs.m > 0)
	{
		*totalrows = floor((liverows * totalblocks) / bs.m + 0.5);
		*totaldeadrows = floor((deadrows * totalblocks) / bs.m + 0.5);
	}
	else {
		*totalrows = 0.0;
		*totaldeadrows = 0.0;
	}

	
	ereport(elevel, (errmsg("\"%s\": scanned %d of %u pages, " "containing %.0f live rows and %.0f dead rows; " "%d rows in sample, %.0f estimated total rows", RelationGetRelationName(onerel), bs.m, totalblocks, liverows, deadrows, numrows, *totalrows)));







	return numrows;
}


static double random_fract(void)
{
	return ((double) random() + 1) / ((double) MAX_RANDOM_VALUE + 2);
}


static double init_selection_state(int n)
{
	
	return exp(-log(random_fract()) / n);
}

static double get_next_S(double t, int n, double *stateptr)
{
	double		S;

	
	if (t <= (22.0 * n))
	{
		
		double		V, quot;

		V = random_fract();		
		S = 0;
		t += 1;
		
		quot = (t - (double) n) / t;
		
		while (quot > V)
		{
			S += 1;
			t += 1;
			quot *= (t - (double) n) / t;
		}
	}
	else {
		
		double		W = *stateptr;
		double		term = t - (double) n + 1;

		for (;;)
		{
			double		numer, numer_lim, denom;

			double		U, X, lhs, rhs, y, tmp;





			
			U = random_fract();
			X = t * (W - 1.0);
			S = floor(X);		
			
			tmp = (t + 1) / term;
			lhs = exp(log(((U * tmp * tmp) * (term + S)) / (t + X)) / n);
			rhs = (((t + X) / (term + S)) * term) / t;
			if (lhs <= rhs)
			{
				W = rhs / lhs;
				break;
			}
			
			y = (((U * (t + 1)) / term) * (t + S + 1)) / (t + X);
			if ((double) n < S)
			{
				denom = t;
				numer_lim = term + S;
			}
			else {
				denom = t - (double) n + S;
				numer_lim = t + 1;
			}
			for (numer = t + S; numer >= numer_lim; numer -= 1)
			{
				y *= numer / denom;
				denom -= 1;
			}
			W = exp(-log(random_fract()) / n);	
			if (exp(log(y) / n) <= (t + X) / t)
				break;
		}
		*stateptr = W;
	}
	return S;
}


static int compare_rows(const void *a, const void *b)
{
	HeapTuple	ha = *(HeapTuple *) a;
	HeapTuple	hb = *(HeapTuple *) b;
	BlockNumber ba = ItemPointerGetBlockNumber(&ha->t_self);
	OffsetNumber oa = ItemPointerGetOffsetNumber(&ha->t_self);
	BlockNumber bb = ItemPointerGetBlockNumber(&hb->t_self);
	OffsetNumber ob = ItemPointerGetOffsetNumber(&hb->t_self);

	if (ba < bb)
		return -1;
	if (ba > bb)
		return 1;
	if (oa < ob)
		return -1;
	if (oa > ob)
		return 1;
	return 0;
}



static void update_attstats(Oid relid, int natts, VacAttrStats **vacattrstats)
{
	Relation	sd;
	int			attno;

	if (natts <= 0)
		return;					

	sd = heap_open(StatisticRelationId, RowExclusiveLock);

	for (attno = 0; attno < natts; attno++)
	{
		VacAttrStats *stats = vacattrstats[attno];
		HeapTuple	stup, oldtup;
		int			i, k, n;

		Datum		values[Natts_pg_statistic];
		char		nulls[Natts_pg_statistic];
		char		replaces[Natts_pg_statistic];

		
		if (!stats->stats_valid)
			continue;

		
		for (i = 0; i < Natts_pg_statistic; ++i)
		{
			nulls[i] = ' ';
			replaces[i] = 'r';
		}

		i = 0;
		values[i++] = ObjectIdGetDatum(relid);	
		values[i++] = Int16GetDatum(stats->attr->attnum);		
		values[i++] = Float4GetDatum(stats->stanullfrac);		
		values[i++] = Int32GetDatum(stats->stawidth);	
		values[i++] = Float4GetDatum(stats->stadistinct);		
		for (k = 0; k < STATISTIC_NUM_SLOTS; k++)
		{
			values[i++] = Int16GetDatum(stats->stakind[k]);		
		}
		for (k = 0; k < STATISTIC_NUM_SLOTS; k++)
		{
			values[i++] = ObjectIdGetDatum(stats->staop[k]);	
		}
		for (k = 0; k < STATISTIC_NUM_SLOTS; k++)
		{
			int			nnum = stats->numnumbers[k];

			if (nnum > 0)
			{
				Datum	   *numdatums = (Datum *) palloc(nnum * sizeof(Datum));
				ArrayType  *arry;

				for (n = 0; n < nnum; n++)
					numdatums[n] = Float4GetDatum(stats->stanumbers[k][n]);
				
				arry = construct_array(numdatums, nnum, FLOAT4OID, sizeof(float4), false, 'i');

				values[i++] = PointerGetDatum(arry);	
			}
			else {
				nulls[i] = 'n';
				values[i++] = (Datum) 0;
			}
		}
		for (k = 0; k < STATISTIC_NUM_SLOTS; k++)
		{
			if (stats->numvalues[k] > 0)
			{
				ArrayType  *arry;

				arry = construct_array(stats->stavalues[k], stats->numvalues[k], stats->attr->atttypid, stats->attrtype->typlen, stats->attrtype->typbyval, stats->attrtype->typalign);




				values[i++] = PointerGetDatum(arry);	
			}
			else {
				nulls[i] = 'n';
				values[i++] = (Datum) 0;
			}
		}

		
		oldtup = SearchSysCache(STATRELATT, ObjectIdGetDatum(relid), Int16GetDatum(stats->attr->attnum), 0, 0);



		if (HeapTupleIsValid(oldtup))
		{
			
			stup = heap_modifytuple(oldtup, RelationGetDescr(sd), values, nulls, replaces);



			ReleaseSysCache(oldtup);
			simple_heap_update(sd, &stup->t_self, stup);
		}
		else {
			
			stup = heap_formtuple(RelationGetDescr(sd), values, nulls);
			simple_heap_insert(sd, stup);
		}

		
		CatalogUpdateIndexes(sd, stup);

		heap_freetuple(stup);
	}

	heap_close(sd, RowExclusiveLock);
}


static Datum std_fetch_func(VacAttrStatsP stats, int rownum, bool *isNull)
{
	int			attnum = stats->tupattnum;
	HeapTuple	tuple = stats->rows[rownum];
	TupleDesc	tupDesc = stats->tupDesc;

	return heap_getattr(tuple, attnum, tupDesc, isNull);
}


static Datum ind_fetch_func(VacAttrStatsP stats, int rownum, bool *isNull)
{
	int			i;

	
	i = rownum * stats->rowstride;
	*isNull = stats->exprnulls[i];
	return stats->exprvals[i];
}












typedef struct {
	Oid			eqopr;			
	Oid			eqfunc;			
	Oid			ltopr;			
} StdAnalyzeData;

typedef struct {
	Datum		value;			
	int			tupno;			
} ScalarItem;

typedef struct {
	int			count;			
	int			first;			
} ScalarMCVItem;

typedef struct {
	FmgrInfo   *cmpFn;
	int			cmpFlags;
	int		   *tupnoLink;
} CompareScalarsContext;


static void compute_minimal_stats(VacAttrStatsP stats, AnalyzeAttrFetchFunc fetchfunc, int samplerows, double totalrows);


static void compute_scalar_stats(VacAttrStatsP stats, AnalyzeAttrFetchFunc fetchfunc, int samplerows, double totalrows);


static int	compare_scalars(const void *a, const void *b, void *arg);
static int	compare_mcvs(const void *a, const void *b);



static bool std_typanalyze(VacAttrStats *stats)
{
	Form_pg_attribute attr = stats->attr;
	Operator	func_operator;
	Oid			eqopr = InvalidOid;
	Oid			eqfunc = InvalidOid;
	Oid			ltopr = InvalidOid;
	StdAnalyzeData *mystats;

	
	
	if (attr->attstattarget < 0)
		attr->attstattarget = default_statistics_target;

	
	func_operator = equality_oper(attr->atttypid, true);
	if (func_operator != NULL)
	{
		eqopr = oprid(func_operator);
		eqfunc = oprfuncid(func_operator);
		ReleaseSysCache(func_operator);
	}
	if (!OidIsValid(eqfunc))
		return false;

	
	func_operator = ordering_oper(attr->atttypid, true);
	if (func_operator != NULL)
	{
		ltopr = oprid(func_operator);
		ReleaseSysCache(func_operator);
	}

	
	mystats = (StdAnalyzeData *) palloc(sizeof(StdAnalyzeData));
	mystats->eqopr = eqopr;
	mystats->eqfunc = eqfunc;
	mystats->ltopr = ltopr;
	stats->extra_data = mystats;

	
	if (OidIsValid(ltopr))
	{
		
		stats->compute_stats = compute_scalar_stats;
		
		stats->minrows = 300 * attr->attstattarget;
	}
	else {
		
		stats->compute_stats = compute_minimal_stats;
		
		stats->minrows = 300 * attr->attstattarget;
	}

	return true;
}


static void compute_minimal_stats(VacAttrStatsP stats, AnalyzeAttrFetchFunc fetchfunc, int samplerows, double totalrows)



{
	int			i;
	int			null_cnt = 0;
	int			nonnull_cnt = 0;
	int			toowide_cnt = 0;
	double		total_width = 0;
	bool		is_varlena = (!stats->attr->attbyval && stats->attr->attlen == -1);
	bool		is_varwidth = (!stats->attr->attbyval && stats->attr->attlen < 0);
	FmgrInfo	f_cmpeq;
	typedef struct {
		Datum		value;
		int			count;
	} TrackItem;
	TrackItem  *track;
	int			track_cnt, track_max;
	int			num_mcv = stats->attr->attstattarget;
	StdAnalyzeData *mystats = (StdAnalyzeData *) stats->extra_data;

	
	track_max = 2 * num_mcv;
	if (track_max < 10)
		track_max = 10;
	track = (TrackItem *) palloc(track_max * sizeof(TrackItem));
	track_cnt = 0;

	fmgr_info(mystats->eqfunc, &f_cmpeq);

	for (i = 0; i < samplerows; i++)
	{
		Datum		value;
		bool		isnull;
		bool		match;
		int			firstcount1, j;

		vacuum_delay_point();

		value = fetchfunc(stats, i, &isnull);

		
		if (isnull)
		{
			null_cnt++;
			continue;
		}
		nonnull_cnt++;

		
		if (is_varlena)
		{
			total_width += VARSIZE_ANY(DatumGetPointer(value));

			
			if (toast_raw_datum_size(value) > WIDTH_THRESHOLD)
			{
				toowide_cnt++;
				continue;
			}
			value = PointerGetDatum(PG_DETOAST_DATUM(value));
		}
		else if (is_varwidth)
		{
			
			total_width += strlen(DatumGetCString(value)) + 1;
		}

		
		match = false;
		firstcount1 = track_cnt;
		for (j = 0; j < track_cnt; j++)
		{
			if (DatumGetBool(FunctionCall2(&f_cmpeq, value, track[j].value)))
			{
				match = true;
				break;
			}
			if (j < firstcount1 && track[j].count == 1)
				firstcount1 = j;
		}

		if (match)
		{
			
			track[j].count++;
			
			while (j > 0 && track[j].count > track[j - 1].count)
			{
				swapDatum(track[j].value, track[j - 1].value);
				swapInt(track[j].count, track[j - 1].count);
				j--;
			}
		}
		else {
			
			if (track_cnt < track_max)
				track_cnt++;
			for (j = track_cnt - 1; j > firstcount1; j--)
			{
				track[j].value = track[j - 1].value;
				track[j].count = track[j - 1].count;
			}
			if (firstcount1 < track_cnt)
			{
				track[firstcount1].value = value;
				track[firstcount1].count = 1;
			}
		}
	}

	
	if (nonnull_cnt > 0)
	{
		int			nmultiple, summultiple;

		stats->stats_valid = true;
		
		stats->stanullfrac = (double) null_cnt / (double) samplerows;
		if (is_varwidth)
			stats->stawidth = total_width / (double) nonnull_cnt;
		else stats->stawidth = stats->attrtype->typlen;

		
		summultiple = 0;
		for (nmultiple = 0; nmultiple < track_cnt; nmultiple++)
		{
			if (track[nmultiple].count == 1)
				break;
			summultiple += track[nmultiple].count;
		}

		if (nmultiple == 0)
		{
			
			stats->stadistinct = -1.0;
		}
		else if (track_cnt < track_max && toowide_cnt == 0 && nmultiple == track_cnt)
		{
			
			stats->stadistinct = track_cnt;
		}
		else {
			
			int			f1 = nonnull_cnt - summultiple;
			int			d = f1 + nmultiple;
			double		numer, denom, stadistinct;


			numer = (double) samplerows *(double) d;

			denom = (double) (samplerows - f1) + (double) f1 *(double) samplerows / totalrows;

			stadistinct = numer / denom;
			
			if (stadistinct < (double) d)
				stadistinct = (double) d;
			if (stadistinct > totalrows)
				stadistinct = totalrows;
			stats->stadistinct = floor(stadistinct + 0.5);
		}

		
		if (stats->stadistinct > 0.1 * totalrows)
			stats->stadistinct = -(stats->stadistinct / totalrows);

		
		if (track_cnt < track_max && toowide_cnt == 0 && stats->stadistinct > 0 && track_cnt <= num_mcv)

		{
			
			num_mcv = track_cnt;
		}
		else {
			double		ndistinct = stats->stadistinct;
			double		avgcount, mincount;

			if (ndistinct < 0)
				ndistinct = -ndistinct * totalrows;
			
			avgcount = (double) samplerows / ndistinct;
			
			mincount = avgcount * 1.25;
			if (mincount < 2)
				mincount = 2;
			if (num_mcv > track_cnt)
				num_mcv = track_cnt;
			for (i = 0; i < num_mcv; i++)
			{
				if (track[i].count < mincount)
				{
					num_mcv = i;
					break;
				}
			}
		}

		
		if (num_mcv > 0)
		{
			MemoryContext old_context;
			Datum	   *mcv_values;
			float4	   *mcv_freqs;

			
			old_context = MemoryContextSwitchTo(stats->anl_context);
			mcv_values = (Datum *) palloc(num_mcv * sizeof(Datum));
			mcv_freqs = (float4 *) palloc(num_mcv * sizeof(float4));
			for (i = 0; i < num_mcv; i++)
			{
				mcv_values[i] = datumCopy(track[i].value, stats->attr->attbyval, stats->attr->attlen);

				mcv_freqs[i] = (double) track[i].count / (double) samplerows;
			}
			MemoryContextSwitchTo(old_context);

			stats->stakind[0] = STATISTIC_KIND_MCV;
			stats->staop[0] = mystats->eqopr;
			stats->stanumbers[0] = mcv_freqs;
			stats->numnumbers[0] = num_mcv;
			stats->stavalues[0] = mcv_values;
			stats->numvalues[0] = num_mcv;
		}
	}
	else if (null_cnt > 0)
	{
		
		stats->stats_valid = true;
		stats->stanullfrac = 1.0;
		if (is_varwidth)
			stats->stawidth = 0;	
		else stats->stawidth = stats->attrtype->typlen;
		stats->stadistinct = 0.0;		
	}

	
}



static void compute_scalar_stats(VacAttrStatsP stats, AnalyzeAttrFetchFunc fetchfunc, int samplerows, double totalrows)



{
	int			i;
	int			null_cnt = 0;
	int			nonnull_cnt = 0;
	int			toowide_cnt = 0;
	double		total_width = 0;
	bool		is_varlena = (!stats->attr->attbyval && stats->attr->attlen == -1);
	bool		is_varwidth = (!stats->attr->attbyval && stats->attr->attlen < 0);
	double		corr_xysum;
	Oid			cmpFn;
	int			cmpFlags;
	FmgrInfo	f_cmpfn;
	ScalarItem *values;
	int			values_cnt = 0;
	int		   *tupnoLink;
	ScalarMCVItem *track;
	int			track_cnt = 0;
	int			num_mcv = stats->attr->attstattarget;
	int			num_bins = stats->attr->attstattarget;
	StdAnalyzeData *mystats = (StdAnalyzeData *) stats->extra_data;

	values = (ScalarItem *) palloc(samplerows * sizeof(ScalarItem));
	tupnoLink = (int *) palloc(samplerows * sizeof(int));
	track = (ScalarMCVItem *) palloc(num_mcv * sizeof(ScalarMCVItem));

	SelectSortFunction(mystats->ltopr, false, &cmpFn, &cmpFlags);
	fmgr_info(cmpFn, &f_cmpfn);

	
	for (i = 0; i < samplerows; i++)
	{
		Datum		value;
		bool		isnull;

		vacuum_delay_point();

		value = fetchfunc(stats, i, &isnull);

		
		if (isnull)
		{
			null_cnt++;
			continue;
		}
		nonnull_cnt++;

		
		if (is_varlena)
		{
			total_width += VARSIZE_ANY(DatumGetPointer(value));

			
			if (toast_raw_datum_size(value) > WIDTH_THRESHOLD)
			{
				toowide_cnt++;
				continue;
			}
			value = PointerGetDatum(PG_DETOAST_DATUM(value));
		}
		else if (is_varwidth)
		{
			
			total_width += strlen(DatumGetCString(value)) + 1;
		}

		
		values[values_cnt].value = value;
		values[values_cnt].tupno = values_cnt;
		tupnoLink[values_cnt] = values_cnt;
		values_cnt++;
	}

	
	if (values_cnt > 0)
	{
		int			ndistinct,	 nmultiple, num_hist, dups_cnt;


		int			slot_idx = 0;
		CompareScalarsContext cxt;

		
		cxt.cmpFn = &f_cmpfn;
		cxt.cmpFlags = cmpFlags;
		cxt.tupnoLink = tupnoLink;
		qsort_arg((void *) values, values_cnt, sizeof(ScalarItem), compare_scalars, (void *) &cxt);

		
		corr_xysum = 0;
		ndistinct = 0;
		nmultiple = 0;
		dups_cnt = 0;
		for (i = 0; i < values_cnt; i++)
		{
			int			tupno = values[i].tupno;

			corr_xysum += ((double) i) * ((double) tupno);
			dups_cnt++;
			if (tupnoLink[tupno] == tupno)
			{
				
				ndistinct++;
				if (dups_cnt > 1)
				{
					nmultiple++;
					if (track_cnt < num_mcv || dups_cnt > track[track_cnt - 1].count)
					{
						
						int			j;

						if (track_cnt < num_mcv)
							track_cnt++;
						for (j = track_cnt - 1; j > 0; j--)
						{
							if (dups_cnt <= track[j - 1].count)
								break;
							track[j].count = track[j - 1].count;
							track[j].first = track[j - 1].first;
						}
						track[j].count = dups_cnt;
						track[j].first = i + 1 - dups_cnt;
					}
				}
				dups_cnt = 0;
			}
		}

		stats->stats_valid = true;
		
		stats->stanullfrac = (double) null_cnt / (double) samplerows;
		if (is_varwidth)
			stats->stawidth = total_width / (double) nonnull_cnt;
		else stats->stawidth = stats->attrtype->typlen;

		if (nmultiple == 0)
		{
			
			stats->stadistinct = -1.0;
		}
		else if (toowide_cnt == 0 && nmultiple == ndistinct)
		{
			
			stats->stadistinct = ndistinct;
		}
		else {
			
			int			f1 = ndistinct - nmultiple + toowide_cnt;
			int			d = f1 + nmultiple;
			double		numer, denom, stadistinct;


			numer = (double) samplerows *(double) d;

			denom = (double) (samplerows - f1) + (double) f1 *(double) samplerows / totalrows;

			stadistinct = numer / denom;
			
			if (stadistinct < (double) d)
				stadistinct = (double) d;
			if (stadistinct > totalrows)
				stadistinct = totalrows;
			stats->stadistinct = floor(stadistinct + 0.5);
		}

		
		if (stats->stadistinct > 0.1 * totalrows)
			stats->stadistinct = -(stats->stadistinct / totalrows);

		
		if (track_cnt == ndistinct && toowide_cnt == 0 && stats->stadistinct > 0 && track_cnt <= num_mcv)

		{
			
			num_mcv = track_cnt;
		}
		else {
			double		ndistinct = stats->stadistinct;
			double		avgcount, mincount, maxmincount;


			if (ndistinct < 0)
				ndistinct = -ndistinct * totalrows;
			
			avgcount = (double) samplerows / ndistinct;
			
			mincount = avgcount * 1.25;
			if (mincount < 2)
				mincount = 2;
			
			maxmincount = (double) samplerows / (double) num_bins;
			if (mincount > maxmincount)
				mincount = maxmincount;
			if (num_mcv > track_cnt)
				num_mcv = track_cnt;
			for (i = 0; i < num_mcv; i++)
			{
				if (track[i].count < mincount)
				{
					num_mcv = i;
					break;
				}
			}
		}

		
		if (num_mcv > 0)
		{
			MemoryContext old_context;
			Datum	   *mcv_values;
			float4	   *mcv_freqs;

			
			old_context = MemoryContextSwitchTo(stats->anl_context);
			mcv_values = (Datum *) palloc(num_mcv * sizeof(Datum));
			mcv_freqs = (float4 *) palloc(num_mcv * sizeof(float4));
			for (i = 0; i < num_mcv; i++)
			{
				mcv_values[i] = datumCopy(values[track[i].first].value, stats->attr->attbyval, stats->attr->attlen);

				mcv_freqs[i] = (double) track[i].count / (double) samplerows;
			}
			MemoryContextSwitchTo(old_context);

			stats->stakind[slot_idx] = STATISTIC_KIND_MCV;
			stats->staop[slot_idx] = mystats->eqopr;
			stats->stanumbers[slot_idx] = mcv_freqs;
			stats->numnumbers[slot_idx] = num_mcv;
			stats->stavalues[slot_idx] = mcv_values;
			stats->numvalues[slot_idx] = num_mcv;
			slot_idx++;
		}

		
		num_hist = ndistinct - num_mcv;
		if (num_hist > num_bins)
			num_hist = num_bins + 1;
		if (num_hist >= 2)
		{
			MemoryContext old_context;
			Datum	   *hist_values;
			int			nvals;

			
			qsort((void *) track, num_mcv, sizeof(ScalarMCVItem), compare_mcvs);

			
			if (num_mcv > 0)
			{
				int			src, dest;
				int			j;

				src = dest = 0;
				j = 0;			
				while (src < values_cnt)
				{
					int			ncopy;

					if (j < num_mcv)
					{
						int			first = track[j].first;

						if (src >= first)
						{
							
							src = first + track[j].count;
							j++;
							continue;
						}
						ncopy = first - src;
					}
					else ncopy = values_cnt - src;
					memmove(&values[dest], &values[src], ncopy * sizeof(ScalarItem));
					src += ncopy;
					dest += ncopy;
				}
				nvals = dest;
			}
			else nvals = values_cnt;
			Assert(nvals >= num_hist);

			
			old_context = MemoryContextSwitchTo(stats->anl_context);
			hist_values = (Datum *) palloc(num_hist * sizeof(Datum));
			for (i = 0; i < num_hist; i++)
			{
				int			pos;

				pos = (i * (nvals - 1)) / (num_hist - 1);
				hist_values[i] = datumCopy(values[pos].value, stats->attr->attbyval, stats->attr->attlen);

			}
			MemoryContextSwitchTo(old_context);

			stats->stakind[slot_idx] = STATISTIC_KIND_HISTOGRAM;
			stats->staop[slot_idx] = mystats->ltopr;
			stats->stavalues[slot_idx] = hist_values;
			stats->numvalues[slot_idx] = num_hist;
			slot_idx++;
		}

		
		if (values_cnt > 1)
		{
			MemoryContext old_context;
			float4	   *corrs;
			double		corr_xsum, corr_x2sum;

			
			old_context = MemoryContextSwitchTo(stats->anl_context);
			corrs = (float4 *) palloc(sizeof(float4));
			MemoryContextSwitchTo(old_context);

			
			corr_xsum = ((double) (values_cnt - 1)) * ((double) values_cnt) / 2.0;
			corr_x2sum = ((double) (values_cnt - 1)) * ((double) values_cnt) * (double) (2 * values_cnt - 1) / 6.0;

			
			corrs[0] = (values_cnt * corr_xysum - corr_xsum * corr_xsum) / (values_cnt * corr_x2sum - corr_xsum * corr_xsum);

			stats->stakind[slot_idx] = STATISTIC_KIND_CORRELATION;
			stats->staop[slot_idx] = mystats->ltopr;
			stats->stanumbers[slot_idx] = corrs;
			stats->numnumbers[slot_idx] = 1;
			slot_idx++;
		}
	}
	else if (nonnull_cnt == 0 && null_cnt > 0)
	{
		
		stats->stats_valid = true;
		stats->stanullfrac = 1.0;
		if (is_varwidth)
			stats->stawidth = 0;	
		else stats->stawidth = stats->attrtype->typlen;
		stats->stadistinct = 0.0;		
	}

	
}


static int compare_scalars(const void *a, const void *b, void *arg)
{
	Datum		da = ((ScalarItem *) a)->value;
	int			ta = ((ScalarItem *) a)->tupno;
	Datum		db = ((ScalarItem *) b)->value;
	int			tb = ((ScalarItem *) b)->tupno;
	CompareScalarsContext *cxt = (CompareScalarsContext *) arg;
	int32		compare;

	compare = ApplySortFunction(cxt->cmpFn, cxt->cmpFlags, da, false, db, false);
	if (compare != 0)
		return compare;

	
	if (cxt->tupnoLink[ta] < tb)
		cxt->tupnoLink[ta] = tb;
	if (cxt->tupnoLink[tb] < ta)
		cxt->tupnoLink[tb] = ta;

	
	return ta - tb;
}


static int compare_mcvs(const void *a, const void *b)
{
	int			da = ((ScalarMCVItem *) a)->first;
	int			db = ((ScalarMCVItem *) b)->first;

	return da - db;
}
