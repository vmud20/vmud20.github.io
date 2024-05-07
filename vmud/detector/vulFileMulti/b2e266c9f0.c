



















PG_FUNCTION_INFO_V1(brin_page_type);
PG_FUNCTION_INFO_V1(brin_page_items);
PG_FUNCTION_INFO_V1(brin_metapage_info);
PG_FUNCTION_INFO_V1(brin_revmap_data);

typedef struct brin_column_state {
	int			nstored;
	FmgrInfo	outputFn[FLEXIBLE_ARRAY_MEMBER];
} brin_column_state;


static Page verify_brin_page(bytea *raw_page, uint16 type, const char *strtype);

Datum brin_page_type(PG_FUNCTION_ARGS)
{
	bytea	   *raw_page = PG_GETARG_BYTEA_P(0);
	Page		page = VARDATA(raw_page);
	char	   *type;

	switch (BrinPageType(page))
	{
		case BRIN_PAGETYPE_META:
			type = "meta";
			break;
		case BRIN_PAGETYPE_REVMAP:
			type = "revmap";
			break;
		case BRIN_PAGETYPE_REGULAR:
			type = "regular";
			break;
		default:
			type = psprintf("unknown (%02x)", BrinPageType(page));
			break;
	}

	PG_RETURN_TEXT_P(cstring_to_text(type));
}


static Page verify_brin_page(bytea *raw_page, uint16 type, const char *strtype)
{
	Page		page;
	int			raw_page_size;

	raw_page_size = VARSIZE(raw_page) - VARHDRSZ;

	if (raw_page_size < SizeOfPageHeaderData)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("input page too small"), errdetail("Expected size %d, got %d", raw_page_size, BLCKSZ)));



	page = VARDATA(raw_page);

	
	if (BrinPageType(page) != type)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("page is not a BRIN page of type \"%s\"", strtype), errdetail("Expected special type %08x, got %08x.", type, BrinPageType(page))));




	return page;
}



Datum brin_page_items(PG_FUNCTION_ARGS)
{
	bytea	   *raw_page = PG_GETARG_BYTEA_P(0);
	Oid			indexRelid = PG_GETARG_OID(1);
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	MemoryContext oldcontext;
	Tuplestorestate *tupstore;
	Relation	indexRel;
	brin_column_state **columns;
	BrinDesc   *bdesc;
	BrinMemTuple *dtup;
	Page		page;
	OffsetNumber offset;
	AttrNumber	attno;
	bool		unusedItem;

	if (!superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), (errmsg("must be superuser to use raw page functions"))));


	
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));

	if (!(rsinfo->allowedModes & SFRM_Materialize) || rsinfo->expectedDesc == NULL)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("materialize mode required, but it is not allowed in this context")));


	
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	
	oldcontext = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	indexRel = index_open(indexRelid, AccessShareLock);
	bdesc = brin_build_desc(indexRel);

	
	page = verify_brin_page(raw_page, BRIN_PAGETYPE_REGULAR, "regular");

	
	columns = palloc(sizeof(brin_column_state *) * RelationGetDescr(indexRel)->natts);
	for (attno = 1; attno <= bdesc->bd_tupdesc->natts; attno++)
	{
		Oid			output;
		bool		isVarlena;
		BrinOpcInfo *opcinfo;
		int			i;
		brin_column_state *column;

		opcinfo = bdesc->bd_info[attno - 1];
		column = palloc(offsetof(brin_column_state, outputFn) + sizeof(FmgrInfo) * opcinfo->oi_nstored);

		column->nstored = opcinfo->oi_nstored;
		for (i = 0; i < opcinfo->oi_nstored; i++)
		{
			getTypeOutputInfo(opcinfo->oi_typcache[i]->type_id, &output, &isVarlena);
			fmgr_info(output, &column->outputFn[i]);
		}

		columns[attno - 1] = column;
	}

	offset = FirstOffsetNumber;
	unusedItem = false;
	dtup = NULL;
	for (;;)
	{
		Datum		values[7];
		bool		nulls[7];

		
		if (dtup == NULL)
		{
			ItemId		itemId;

			
			itemId = PageGetItemId(page, offset);
			if (ItemIdIsUsed(itemId))
			{
				dtup = brin_deform_tuple(bdesc, (BrinTuple *) PageGetItem(page, itemId));
				attno = 1;
				unusedItem = false;
			}
			else unusedItem = true;
		}
		else attno++;

		MemSet(nulls, 0, sizeof(nulls));

		if (unusedItem)
		{
			values[0] = UInt16GetDatum(offset);
			nulls[1] = true;
			nulls[2] = true;
			nulls[3] = true;
			nulls[4] = true;
			nulls[5] = true;
			nulls[6] = true;
		}
		else {
			int			att = attno - 1;

			values[0] = UInt16GetDatum(offset);
			values[1] = UInt32GetDatum(dtup->bt_blkno);
			values[2] = UInt16GetDatum(attno);
			values[3] = BoolGetDatum(dtup->bt_columns[att].bv_allnulls);
			values[4] = BoolGetDatum(dtup->bt_columns[att].bv_hasnulls);
			values[5] = BoolGetDatum(dtup->bt_placeholder);
			if (!dtup->bt_columns[att].bv_allnulls)
			{
				BrinValues *bvalues = &dtup->bt_columns[att];
				StringInfoData s;
				bool		first;
				int			i;

				initStringInfo(&s);
				appendStringInfoChar(&s, '{');

				first = true;
				for (i = 0; i < columns[att]->nstored; i++)
				{
					char	   *val;

					if (!first)
						appendStringInfoString(&s, " .. ");
					first = false;
					val = OutputFunctionCall(&columns[att]->outputFn[i], bvalues->bv_values[i]);
					appendStringInfoString(&s, val);
					pfree(val);
				}
				appendStringInfoChar(&s, '}');

				values[6] = CStringGetTextDatum(s.data);
				pfree(s.data);
			}
			else {
				nulls[6] = true;
			}
		}

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);

		
		if (unusedItem)
			offset = OffsetNumberNext(offset);
		else if (attno >= bdesc->bd_tupdesc->natts)
		{
			pfree(dtup);
			dtup = NULL;
			offset = OffsetNumberNext(offset);
		}

		
		if (offset > PageGetMaxOffsetNumber(page))
			break;
	}

	
	brin_free_desc(bdesc);
	tuplestore_donestoring(tupstore);
	index_close(indexRel, AccessShareLock);

	return (Datum) 0;
}

Datum brin_metapage_info(PG_FUNCTION_ARGS)
{
	bytea	   *raw_page = PG_GETARG_BYTEA_P(0);
	Page		page;
	BrinMetaPageData *meta;
	TupleDesc	tupdesc;
	Datum		values[4];
	bool		nulls[4];
	HeapTuple	htup;

	page = verify_brin_page(raw_page, BRIN_PAGETYPE_META, "metapage");

	
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");
	tupdesc = BlessTupleDesc(tupdesc);

	
	meta = (BrinMetaPageData *) PageGetContents(page);
	MemSet(nulls, 0, sizeof(nulls));
	values[0] = CStringGetTextDatum(psprintf("0x%08X", meta->brinMagic));
	values[1] = Int32GetDatum(meta->brinVersion);
	values[2] = Int32GetDatum(meta->pagesPerRange);
	values[3] = Int64GetDatum(meta->lastRevmapPage);

	htup = heap_form_tuple(tupdesc, values, nulls);

	PG_RETURN_DATUM(HeapTupleGetDatum(htup));
}


Datum brin_revmap_data(PG_FUNCTION_ARGS)
{
	struct {
		ItemPointerData *tids;
		int			idx;
	}		   *state;
	FuncCallContext *fctx;

	if (!superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), (errmsg("must be superuser to use raw page functions"))));


	if (SRF_IS_FIRSTCALL())
	{
		bytea	   *raw_page = PG_GETARG_BYTEA_P(0);
		MemoryContext mctx;
		Page		page;

		
		page = verify_brin_page(raw_page, BRIN_PAGETYPE_REVMAP, "revmap");

		
		fctx = SRF_FIRSTCALL_INIT();

		
		mctx = MemoryContextSwitchTo(fctx->multi_call_memory_ctx);

		state = palloc(sizeof(*state));
		state->tids = ((RevmapContents *) PageGetContents(page))->rm_tids;
		state->idx = 0;

		fctx->user_fctx = state;

		MemoryContextSwitchTo(mctx);
	}

	fctx = SRF_PERCALL_SETUP();
	state = fctx->user_fctx;

	if (state->idx < REVMAP_PAGE_MAXITEMS)
		SRF_RETURN_NEXT(fctx, PointerGetDatum(&state->tids[state->idx++]));

	SRF_RETURN_DONE(fctx);
}
