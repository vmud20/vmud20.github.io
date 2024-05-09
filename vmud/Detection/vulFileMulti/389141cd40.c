



































int			vacuum_freeze_min_age;


typedef struct VacPageData {
	BlockNumber blkno;			
	Size		free;			
	uint16		offsets_used;	
	uint16		offsets_free;	
	OffsetNumber offsets[1];	
} VacPageData;

typedef VacPageData *VacPage;

typedef struct VacPageListData {
	BlockNumber empty_end_pages;	
	int			num_pages;		
	int			num_allocated_pages;	
	VacPage    *pagedesc;		
} VacPageListData;

typedef VacPageListData *VacPageList;


typedef struct VTupleLinkData {
	ItemPointerData new_tid;	
	ItemPointerData this_tid;	
} VTupleLinkData;

typedef VTupleLinkData *VTupleLink;


typedef struct VTupleMoveData {
	ItemPointerData tid;		
	VacPage		vacpage;		
	bool		cleanVpd;		
} VTupleMoveData;

typedef VTupleMoveData *VTupleMove;


typedef struct VRelStats {
	
	BlockNumber rel_pages;		
	double		rel_tuples;		
	double		rel_indexed_tuples;		
	Size		min_tlen;		
	Size		max_tlen;		
	bool		hasindex;
	
	int			num_vtlinks;
	VTupleLink	vtlinks;
} VRelStats;


typedef struct ExecContextData {
	ResultRelInfo *resultRelInfo;
	EState	   *estate;
	TupleTableSlot *slot;
} ExecContextData;

typedef ExecContextData *ExecContext;

static void ExecContext_Init(ExecContext ec, Relation rel)
{
	TupleDesc	tupdesc = RelationGetDescr(rel);

	
	ec->estate = CreateExecutorState();

	ec->resultRelInfo = makeNode(ResultRelInfo);
	ec->resultRelInfo->ri_RangeTableIndex = 1;	
	ec->resultRelInfo->ri_RelationDesc = rel;
	ec->resultRelInfo->ri_TrigDesc = NULL;		

	ExecOpenIndices(ec->resultRelInfo);

	ec->estate->es_result_relations = ec->resultRelInfo;
	ec->estate->es_num_result_relations = 1;
	ec->estate->es_result_relation_info = ec->resultRelInfo;

	
	ec->slot = MakeSingleTupleTableSlot(tupdesc);
}

static void ExecContext_Finish(ExecContext ec)
{
	ExecDropSingleTupleTableSlot(ec->slot);
	ExecCloseIndices(ec->resultRelInfo);
	FreeExecutorState(ec->estate);
}




static MemoryContext vac_context = NULL;

static int	elevel = -1;

static TransactionId OldestXmin;
static TransactionId FreezeLimit;

static BufferAccessStrategy vac_strategy;



static List *get_rel_oids(List *relids, const RangeVar *vacrel, const char *stmttype);
static void vac_truncate_clog(TransactionId frozenXID);
static void vacuum_rel(Oid relid, VacuumStmt *vacstmt, char expected_relkind);
static void full_vacuum_rel(Relation onerel, VacuumStmt *vacstmt);
static void scan_heap(VRelStats *vacrelstats, Relation onerel, VacPageList vacuum_pages, VacPageList fraged_pages);
static void repair_frag(VRelStats *vacrelstats, Relation onerel, VacPageList vacuum_pages, VacPageList fraged_pages, int nindexes, Relation *Irel);

static void move_chain_tuple(Relation rel, Buffer old_buf, Page old_page, HeapTuple old_tup, Buffer dst_buf, Page dst_page, VacPage dst_vacpage, ExecContext ec, ItemPointer ctid, bool cleanVpd);


static void move_plain_tuple(Relation rel, Buffer old_buf, Page old_page, HeapTuple old_tup, Buffer dst_buf, Page dst_page, VacPage dst_vacpage, ExecContext ec);


static void update_hint_bits(Relation rel, VacPageList fraged_pages, int num_fraged_pages, BlockNumber last_move_dest_block, int num_moved);

static void vacuum_heap(VRelStats *vacrelstats, Relation onerel, VacPageList vacpagelist);
static void vacuum_page(Relation onerel, Buffer buffer, VacPage vacpage);
static void vacuum_index(VacPageList vacpagelist, Relation indrel, double num_tuples, int keep_tuples);
static void scan_index(Relation indrel, double num_tuples);
static bool tid_reaped(ItemPointer itemptr, void *state);
static void vac_update_fsm(Relation onerel, VacPageList fraged_pages, BlockNumber rel_pages);
static VacPage copy_vac_page(VacPage vacpage);
static void vpage_insert(VacPageList vacpagelist, VacPage vpnew);
static void *vac_bsearch(const void *key, const void *base, size_t nelem, size_t size, int (*compar) (const void *, const void *));

static int	vac_cmp_blk(const void *left, const void *right);
static int	vac_cmp_offno(const void *left, const void *right);
static int	vac_cmp_vtlinks(const void *left, const void *right);
static bool enough_space(VacPage vacpage, Size len);
static Size PageGetFreeSpaceWithFillFactor(Relation relation, Page page);






void vacuum(VacuumStmt *vacstmt, List *relids, BufferAccessStrategy bstrategy, bool isTopLevel)

{
	const char *stmttype = vacstmt->vacuum ? "VACUUM" : "ANALYZE";
	volatile MemoryContext anl_context = NULL;
	volatile bool all_rels, in_outer_xact, use_own_xacts;

	List	   *relations;

	if (vacstmt->verbose)
		elevel = INFO;
	else elevel = DEBUG2;

	
	if (vacstmt->vacuum)
	{
		PreventTransactionChain(isTopLevel, stmttype);
		in_outer_xact = false;
	}
	else in_outer_xact = IsInTransactionChain(isTopLevel);

	
	if (vacstmt->vacuum && !IsAutoVacuumWorkerProcess())
		pgstat_vacuum_tabstat();

	
	vac_context = AllocSetContextCreate(PortalContext, "Vacuum", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);




	
	if (bstrategy == NULL)
	{
		MemoryContext old_context = MemoryContextSwitchTo(vac_context);

		bstrategy = GetAccessStrategy(BAS_VACUUM);
		MemoryContextSwitchTo(old_context);
	}
	vac_strategy = bstrategy;

	
	all_rels = (relids == NIL && vacstmt->relation == NULL);

	
	relations = get_rel_oids(relids, vacstmt->relation, stmttype);

	
	if (vacstmt->vacuum)
		use_own_xacts = true;
	else {
		Assert(vacstmt->analyze);
		if (IsAutoVacuumWorkerProcess())
			use_own_xacts = true;
		else if (in_outer_xact)
			use_own_xacts = false;
		else if (list_length(relations) > 1)
			use_own_xacts = true;
		else use_own_xacts = false;
	}

	
	if (!use_own_xacts)
		anl_context = AllocSetContextCreate(PortalContext, "Analyze", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);




	
	if (use_own_xacts)
	{
		
		CommitTransactionCommand();
	}

	
	PG_TRY();
	{
		ListCell   *cur;

		VacuumCostActive = (VacuumCostDelay > 0);
		VacuumCostBalance = 0;

		
		foreach(cur, relations)
		{
			Oid			relid = lfirst_oid(cur);

			if (vacstmt->vacuum)
				vacuum_rel(relid, vacstmt, RELKIND_RELATION);

			if (vacstmt->analyze)
			{
				MemoryContext old_context = NULL;

				
				if (use_own_xacts)
				{
					StartTransactionCommand();
					
					ActiveSnapshot = CopySnapshot(GetTransactionSnapshot());
				}
				else old_context = MemoryContextSwitchTo(anl_context);

				analyze_rel(relid, vacstmt, vac_strategy);

				if (use_own_xacts)
					CommitTransactionCommand();
				else {
					MemoryContextSwitchTo(old_context);
					MemoryContextResetAndDeleteChildren(anl_context);
				}
			}
		}
	}
	PG_CATCH();
	{
		
		VacuumCostActive = false;
		PG_RE_THROW();
	}
	PG_END_TRY();

	
	VacuumCostActive = false;

	
	if (use_own_xacts)
	{
		

		
		StartTransactionCommand();

		
		ActiveSnapshot = CopySnapshot(GetTransactionSnapshot());
	}

	if (vacstmt->vacuum && !IsAutoVacuumWorkerProcess())
	{
		
		vac_update_datfrozenxid();

		
		if (all_rels)
			PrintFreeSpaceMapStatistics(elevel);
	}

	
	MemoryContextDelete(vac_context);
	vac_context = NULL;

	if (anl_context)
		MemoryContextDelete(anl_context);
}


static List * get_rel_oids(List *relids, const RangeVar *vacrel, const char *stmttype)
{
	List	   *oid_list = NIL;
	MemoryContext oldcontext;

	
	if (relids)
		return relids;

	if (vacrel)
	{
		
		Oid			relid;

		relid = RangeVarGetRelid(vacrel, false);

		
		oldcontext = MemoryContextSwitchTo(vac_context);
		oid_list = lappend_oid(oid_list, relid);
		MemoryContextSwitchTo(oldcontext);
	}
	else {
		
		Relation	pgclass;
		HeapScanDesc scan;
		HeapTuple	tuple;
		ScanKeyData key;

		ScanKeyInit(&key, Anum_pg_class_relkind, BTEqualStrategyNumber, F_CHAREQ, CharGetDatum(RELKIND_RELATION));



		pgclass = heap_open(RelationRelationId, AccessShareLock);

		scan = heap_beginscan(pgclass, SnapshotNow, 1, &key);

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			
			oldcontext = MemoryContextSwitchTo(vac_context);
			oid_list = lappend_oid(oid_list, HeapTupleGetOid(tuple));
			MemoryContextSwitchTo(oldcontext);
		}

		heap_endscan(scan);
		heap_close(pgclass, AccessShareLock);
	}

	return oid_list;
}


void vacuum_set_xid_limits(int freeze_min_age, bool sharedRel, TransactionId *oldestXmin, TransactionId *freezeLimit)


{
	int			freezemin;
	TransactionId limit;
	TransactionId safeLimit;

	
	*oldestXmin = GetOldestXmin(sharedRel, true);

	Assert(TransactionIdIsNormal(*oldestXmin));

	
	freezemin = freeze_min_age;
	if (freezemin < 0)
		freezemin = vacuum_freeze_min_age;
	freezemin = Min(freezemin, autovacuum_freeze_max_age / 2);
	Assert(freezemin >= 0);

	
	limit = *oldestXmin - freezemin;
	if (!TransactionIdIsNormal(limit))
		limit = FirstNormalTransactionId;

	
	safeLimit = ReadNewTransactionId() - autovacuum_freeze_max_age;
	if (!TransactionIdIsNormal(safeLimit))
		safeLimit = FirstNormalTransactionId;

	if (TransactionIdPrecedes(limit, safeLimit))
	{
		ereport(WARNING, (errmsg("oldest xmin is far in the past"), errhint("Close open transactions soon to avoid wraparound problems.")));

		limit = *oldestXmin;
	}

	*freezeLimit = limit;
}



void vac_update_relstats(Oid relid, BlockNumber num_pages, double num_tuples, bool hasindex, TransactionId frozenxid)

{
	Relation	rd;
	HeapTuple	ctup;
	Form_pg_class pgcform;
	bool		dirty;

	rd = heap_open(RelationRelationId, RowExclusiveLock);

	
	ctup = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);

	if (!HeapTupleIsValid(ctup))
		elog(ERROR, "pg_class entry for relid %u vanished during vacuuming", relid);
	pgcform = (Form_pg_class) GETSTRUCT(ctup);

	

	dirty = false;
	if (pgcform->relpages != (int32) num_pages)
	{
		pgcform->relpages = (int32) num_pages;
		dirty = true;
	}
	if (pgcform->reltuples != (float4) num_tuples)
	{
		pgcform->reltuples = (float4) num_tuples;
		dirty = true;
	}
	if (pgcform->relhasindex != hasindex)
	{
		pgcform->relhasindex = hasindex;
		dirty = true;
	}

	
	if (!hasindex)
	{
		if (pgcform->relhaspkey)
		{
			pgcform->relhaspkey = false;
			dirty = true;
		}
	}

	
	if (TransactionIdIsNormal(frozenxid) && TransactionIdPrecedes(pgcform->relfrozenxid, frozenxid))
	{
		pgcform->relfrozenxid = frozenxid;
		dirty = true;
	}

	
	if (dirty)
	{
		heap_inplace_update(rd, ctup);
		
	}
	else {
		
		CacheInvalidateRelcacheByTuple(ctup);
	}

	heap_close(rd, RowExclusiveLock);
}



void vac_update_datfrozenxid(void)
{
	HeapTuple	tuple;
	Form_pg_database dbform;
	Relation	relation;
	SysScanDesc scan;
	HeapTuple	classTup;
	TransactionId newFrozenXid;
	bool		dirty = false;

	
	newFrozenXid = RecentGlobalXmin;

	
	relation = heap_open(RelationRelationId, AccessShareLock);

	scan = systable_beginscan(relation, InvalidOid, false, SnapshotNow, 0, NULL);

	while ((classTup = systable_getnext(scan)) != NULL)
	{
		Form_pg_class classForm = (Form_pg_class) GETSTRUCT(classTup);

		
		if (classForm->relkind != RELKIND_RELATION && classForm->relkind != RELKIND_TOASTVALUE)
			continue;

		Assert(TransactionIdIsNormal(classForm->relfrozenxid));

		if (TransactionIdPrecedes(classForm->relfrozenxid, newFrozenXid))
			newFrozenXid = classForm->relfrozenxid;
	}

	
	systable_endscan(scan);
	heap_close(relation, AccessShareLock);

	Assert(TransactionIdIsNormal(newFrozenXid));

	
	relation = heap_open(DatabaseRelationId, RowExclusiveLock);

	
	tuple = SearchSysCacheCopy(DATABASEOID, ObjectIdGetDatum(MyDatabaseId), 0, 0, 0);

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for database %u", MyDatabaseId);
	dbform = (Form_pg_database) GETSTRUCT(tuple);

	
	if (TransactionIdPrecedes(dbform->datfrozenxid, newFrozenXid))
	{
		dbform->datfrozenxid = newFrozenXid;
		dirty = true;
	}

	if (dirty)
		heap_inplace_update(relation, tuple);

	heap_freetuple(tuple);
	heap_close(relation, RowExclusiveLock);

	
	if (dirty)
	{
		database_file_update_needed();
		vac_truncate_clog(newFrozenXid);
	}
}



static void vac_truncate_clog(TransactionId frozenXID)
{
	TransactionId myXID = GetCurrentTransactionId();
	Relation	relation;
	HeapScanDesc scan;
	HeapTuple	tuple;
	NameData	oldest_datname;
	bool		frozenAlreadyWrapped = false;

	
	namestrcpy(&oldest_datname, get_database_name(MyDatabaseId));

	
	relation = heap_open(DatabaseRelationId, AccessShareLock);

	scan = heap_beginscan(relation, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_database dbform = (Form_pg_database) GETSTRUCT(tuple);

		Assert(TransactionIdIsNormal(dbform->datfrozenxid));

		if (TransactionIdPrecedes(myXID, dbform->datfrozenxid))
			frozenAlreadyWrapped = true;
		else if (TransactionIdPrecedes(dbform->datfrozenxid, frozenXID))
		{
			frozenXID = dbform->datfrozenxid;
			namecpy(&oldest_datname, &dbform->datname);
		}
	}

	heap_endscan(scan);

	heap_close(relation, AccessShareLock);

	
	if (frozenAlreadyWrapped)
	{
		ereport(WARNING, (errmsg("some databases have not been vacuumed in over 2 billion transactions"), errdetail("You might have already suffered transaction-wraparound data loss.")));

		return;
	}

	
	TruncateCLOG(frozenXID);

	
	SetTransactionIdLimit(frozenXID, &oldest_datname);
}






static void vacuum_rel(Oid relid, VacuumStmt *vacstmt, char expected_relkind)
{
	LOCKMODE	lmode;
	Relation	onerel;
	LockRelId	onerelid;
	Oid			toast_relid;

	
	StartTransactionCommand();

	if (vacstmt->full)
	{
		
		ActiveSnapshot = CopySnapshot(GetTransactionSnapshot());
	}
	else {
		
		LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);
		MyProc->vacuumFlags |= PROC_IN_VACUUM;
		LWLockRelease(ProcArrayLock);
	}

	
	CHECK_FOR_INTERRUPTS();

	
	lmode = vacstmt->full ? AccessExclusiveLock : ShareUpdateExclusiveLock;

	
	onerel = try_relation_open(relid, lmode);

	if (!onerel)
	{
		CommitTransactionCommand();
		return;
	}

	
	if (!(pg_class_ownercheck(RelationGetRelid(onerel), GetUserId()) || (pg_database_ownercheck(MyDatabaseId, GetUserId()) && !onerel->rd_rel->relisshared)))
	{
		ereport(WARNING, (errmsg("skipping \"%s\" --- only table or database owner can vacuum it", RelationGetRelationName(onerel))));

		relation_close(onerel, lmode);
		CommitTransactionCommand();
		return;
	}

	
	if (onerel->rd_rel->relkind != expected_relkind)
	{
		ereport(WARNING, (errmsg("skipping \"%s\" --- cannot vacuum indexes, views, or special system tables", RelationGetRelationName(onerel))));

		relation_close(onerel, lmode);
		CommitTransactionCommand();
		return;
	}

	
	if (isOtherTempNamespace(RelationGetNamespace(onerel)))
	{
		relation_close(onerel, lmode);
		CommitTransactionCommand();
		return;
	}

	
	onerelid = onerel->rd_lockInfo.lockRelId;
	LockRelationIdForSession(&onerelid, lmode);

	
	toast_relid = onerel->rd_rel->reltoastrelid;

	
	if (vacstmt->full)
		full_vacuum_rel(onerel, vacstmt);
	else lazy_vacuum_rel(onerel, vacstmt, vac_strategy);

	
	relation_close(onerel, NoLock);

	
	CommitTransactionCommand();

	
	if (toast_relid != InvalidOid)
		vacuum_rel(toast_relid, vacstmt, RELKIND_TOASTVALUE);

	
	UnlockRelationIdForSession(&onerelid, lmode);
}






static void full_vacuum_rel(Relation onerel, VacuumStmt *vacstmt)
{
	VacPageListData vacuum_pages;		
	VacPageListData fraged_pages;		
	Relation   *Irel;
	int			nindexes, i;
	VRelStats  *vacrelstats;

	vacuum_set_xid_limits(vacstmt->freeze_min_age, onerel->rd_rel->relisshared, &OldestXmin, &FreezeLimit);

	
	XLogAsyncCommitFlush();

	
	vacrelstats = (VRelStats *) palloc(sizeof(VRelStats));
	vacrelstats->rel_pages = 0;
	vacrelstats->rel_tuples = 0;
	vacrelstats->rel_indexed_tuples = 0;
	vacrelstats->hasindex = false;

	
	vacuum_pages.num_pages = fraged_pages.num_pages = 0;
	scan_heap(vacrelstats, onerel, &vacuum_pages, &fraged_pages);

	
	vac_open_indexes(onerel, AccessExclusiveLock, &nindexes, &Irel);
	if (nindexes > 0)
		vacrelstats->hasindex = true;

	
	if (Irel != NULL)
	{
		if (vacuum_pages.num_pages > 0)
		{
			for (i = 0; i < nindexes; i++)
				vacuum_index(&vacuum_pages, Irel[i], vacrelstats->rel_indexed_tuples, 0);
		}
		else {
			
			for (i = 0; i < nindexes; i++)
				scan_index(Irel[i], vacrelstats->rel_indexed_tuples);
		}
	}

	if (fraged_pages.num_pages > 0)
	{
		
		repair_frag(vacrelstats, onerel, &vacuum_pages, &fraged_pages, nindexes, Irel);
		vac_close_indexes(nindexes, Irel, NoLock);
	}
	else {
		vac_close_indexes(nindexes, Irel, NoLock);
		if (vacuum_pages.num_pages > 0)
		{
			
			vacuum_heap(vacrelstats, onerel, &vacuum_pages);
		}
	}

	
	vac_update_fsm(onerel, &fraged_pages, vacrelstats->rel_pages);

	
	vac_update_relstats(RelationGetRelid(onerel), vacrelstats->rel_pages, vacrelstats->rel_tuples, vacrelstats->hasindex, FreezeLimit);


	
	pgstat_report_vacuum(RelationGetRelid(onerel), onerel->rd_rel->relisshared, vacstmt->analyze, vacrelstats->rel_tuples);
}



static void scan_heap(VRelStats *vacrelstats, Relation onerel, VacPageList vacuum_pages, VacPageList fraged_pages)

{
	BlockNumber nblocks, blkno;
	char	   *relname;
	VacPage		vacpage;
	BlockNumber empty_pages, empty_end_pages;
	double		num_tuples, num_indexed_tuples, tups_vacuumed, nkeep, nunused;



	double		free_space, usable_free_space;
	Size		min_tlen = MaxHeapTupleSize;
	Size		max_tlen = 0;
	bool		do_shrinking = true;
	VTupleLink	vtlinks = (VTupleLink) palloc(100 * sizeof(VTupleLinkData));
	int			num_vtlinks = 0;
	int			free_vtlinks = 100;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	relname = RelationGetRelationName(onerel);
	ereport(elevel, (errmsg("vacuuming \"%s.%s\"", get_namespace_name(RelationGetNamespace(onerel)), relname)));



	empty_pages = empty_end_pages = 0;
	num_tuples = num_indexed_tuples = tups_vacuumed = nkeep = nunused = 0;
	free_space = 0;

	nblocks = RelationGetNumberOfBlocks(onerel);

	
	vacpage = (VacPage) palloc(sizeof(VacPageData) + MaxOffsetNumber * sizeof(OffsetNumber));

	for (blkno = 0; blkno < nblocks; blkno++)
	{
		Page		page, tempPage = NULL;
		bool		do_reap, do_frag;
		Buffer		buf;
		OffsetNumber offnum, maxoff;
		bool		notup;
		OffsetNumber frozen[MaxOffsetNumber];
		int			nfrozen;

		vacuum_delay_point();

		buf = ReadBufferWithStrategy(onerel, blkno, vac_strategy);
		page = BufferGetPage(buf);

		
		LockBufferForCleanup(buf);

		vacpage->blkno = blkno;
		vacpage->offsets_used = 0;
		vacpage->offsets_free = 0;

		if (PageIsNew(page))
		{
			VacPage		vacpagecopy;

			ereport(WARNING, (errmsg("relation \"%s\" page %u is uninitialized --- fixing", relname, blkno)));

			PageInit(page, BufferGetPageSize(buf), 0);
			MarkBufferDirty(buf);
			vacpage->free = PageGetFreeSpaceWithFillFactor(onerel, page);
			free_space += vacpage->free;
			empty_pages++;
			empty_end_pages++;
			vacpagecopy = copy_vac_page(vacpage);
			vpage_insert(vacuum_pages, vacpagecopy);
			vpage_insert(fraged_pages, vacpagecopy);
			UnlockReleaseBuffer(buf);
			continue;
		}

		if (PageIsEmpty(page))
		{
			VacPage		vacpagecopy;

			vacpage->free = PageGetFreeSpaceWithFillFactor(onerel, page);
			free_space += vacpage->free;
			empty_pages++;
			empty_end_pages++;
			vacpagecopy = copy_vac_page(vacpage);
			vpage_insert(vacuum_pages, vacpagecopy);
			vpage_insert(fraged_pages, vacpagecopy);
			UnlockReleaseBuffer(buf);
			continue;
		}

		
		tups_vacuumed += heap_page_prune(onerel, buf, OldestXmin, true, false);

		
		nfrozen = 0;
		notup = true;
		maxoff = PageGetMaxOffsetNumber(page);
		for (offnum = FirstOffsetNumber;
			 offnum <= maxoff;
			 offnum = OffsetNumberNext(offnum))
		{
			ItemId		itemid = PageGetItemId(page, offnum);
			bool		tupgone = false;
			HeapTupleData tuple;

			
			if (!ItemIdIsUsed(itemid))
			{
				vacpage->offsets[vacpage->offsets_free++] = offnum;
				nunused += 1;
				continue;
			}

			
			if (ItemIdIsDead(itemid))
			{
				vacpage->offsets[vacpage->offsets_free++] = offnum;
				continue;
			}

			
			if (!ItemIdIsNormal(itemid))
				elog(ERROR, "relation \"%s\" TID %u/%u: unexpected redirect item", relname, blkno, offnum);

			tuple.t_data = (HeapTupleHeader) PageGetItem(page, itemid);
			tuple.t_len = ItemIdGetLength(itemid);
			ItemPointerSet(&(tuple.t_self), blkno, offnum);

			switch (HeapTupleSatisfiesVacuum(tuple.t_data, OldestXmin, buf))
			{
				case HEAPTUPLE_LIVE:
					
					if (onerel->rd_rel->relhasoids && !OidIsValid(HeapTupleGetOid(&tuple)))
						elog(WARNING, "relation \"%s\" TID %u/%u: OID is invalid", relname, blkno, offnum);

					
					if (do_shrinking && !(tuple.t_data->t_infomask & HEAP_XMIN_COMMITTED))
					{
						ereport(LOG, (errmsg("relation \"%s\" TID %u/%u: XMIN_COMMITTED not set for transaction %u --- cannot shrink relation", relname, blkno, offnum, HeapTupleHeaderGetXmin(tuple.t_data))));


						do_shrinking = false;
					}
					break;
				case HEAPTUPLE_DEAD:

					
					if (HeapTupleIsHotUpdated(&tuple))
					{
						nkeep += 1;
						if (do_shrinking)
							ereport(LOG, (errmsg("relation \"%s\" TID %u/%u: dead HOT-updated tuple --- cannot shrink relation", relname, blkno, offnum)));

						do_shrinking = false;
					}
					else {
						tupgone = true; 

						
					}
					break;
				case HEAPTUPLE_RECENTLY_DEAD:

					
					nkeep += 1;

					
					if (do_shrinking && !(tuple.t_data->t_infomask & HEAP_XMIN_COMMITTED))
					{
						ereport(LOG, (errmsg("relation \"%s\" TID %u/%u: XMIN_COMMITTED not set for transaction %u --- cannot shrink relation", relname, blkno, offnum, HeapTupleHeaderGetXmin(tuple.t_data))));


						do_shrinking = false;
					}

					
					if (do_shrinking && !(ItemPointerEquals(&(tuple.t_self), &(tuple.t_data->t_ctid))))

					{
						if (free_vtlinks == 0)
						{
							free_vtlinks = 1000;
							vtlinks = (VTupleLink) repalloc(vtlinks, (free_vtlinks + num_vtlinks) * sizeof(VTupleLinkData));

						}
						vtlinks[num_vtlinks].new_tid = tuple.t_data->t_ctid;
						vtlinks[num_vtlinks].this_tid = tuple.t_self;
						free_vtlinks--;
						num_vtlinks++;
					}
					break;
				case HEAPTUPLE_INSERT_IN_PROGRESS:

					
					if (do_shrinking)
						ereport(LOG, (errmsg("relation \"%s\" TID %u/%u: InsertTransactionInProgress %u --- cannot shrink relation", relname, blkno, offnum, HeapTupleHeaderGetXmin(tuple.t_data))));


					do_shrinking = false;
					break;
				case HEAPTUPLE_DELETE_IN_PROGRESS:

					
					if (do_shrinking)
						ereport(LOG, (errmsg("relation \"%s\" TID %u/%u: DeleteTransactionInProgress %u --- cannot shrink relation", relname, blkno, offnum, HeapTupleHeaderGetXmax(tuple.t_data))));


					do_shrinking = false;
					break;
				default:
					elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
					break;
			}

			if (tupgone)
			{
				ItemId		lpp;

				
				if (tempPage == NULL)
				{
					Size		pageSize;

					pageSize = PageGetPageSize(page);
					tempPage = (Page) palloc(pageSize);
					memcpy(tempPage, page, pageSize);
				}

				
				lpp = PageGetItemId(tempPage, offnum);
				ItemIdSetUnused(lpp);

				vacpage->offsets[vacpage->offsets_free++] = offnum;
				tups_vacuumed += 1;
			}
			else {
				num_tuples += 1;
				if (!HeapTupleIsHeapOnly(&tuple))
					num_indexed_tuples += 1;
				notup = false;
				if (tuple.t_len < min_tlen)
					min_tlen = tuple.t_len;
				if (tuple.t_len > max_tlen)
					max_tlen = tuple.t_len;

				
				if (heap_freeze_tuple(tuple.t_data, FreezeLimit, InvalidBuffer))
					frozen[nfrozen++] = offnum;
			}
		}						

		if (tempPage != NULL)
		{
			
			PageRepairFragmentation(tempPage);
			vacpage->free = PageGetFreeSpaceWithFillFactor(onerel, tempPage);
			pfree(tempPage);
			do_reap = true;
		}
		else {
			
			vacpage->free = PageGetFreeSpaceWithFillFactor(onerel, page);
			
			do_reap = (vacpage->offsets_free > 0);
		}

		free_space += vacpage->free;

		
		do_frag = (vacpage->free >= min_tlen || vacpage->free >= BLCKSZ / 10);

		if (do_reap || do_frag)
		{
			VacPage		vacpagecopy = copy_vac_page(vacpage);

			if (do_reap)
				vpage_insert(vacuum_pages, vacpagecopy);
			if (do_frag)
				vpage_insert(fraged_pages, vacpagecopy);
		}

		
		if (notup)
		{
			empty_pages++;
			empty_end_pages++;
		}
		else empty_end_pages = 0;

		
		if (nfrozen > 0)
		{
			MarkBufferDirty(buf);
			
			if (!onerel->rd_istemp)
			{
				XLogRecPtr	recptr;

				recptr = log_heap_freeze(onerel, buf, FreezeLimit, frozen, nfrozen);
				PageSetLSN(page, recptr);
				PageSetTLI(page, ThisTimeLineID);
			}
		}

		UnlockReleaseBuffer(buf);
	}

	pfree(vacpage);

	
	vacrelstats->rel_tuples = num_tuples;
	vacrelstats->rel_indexed_tuples = num_indexed_tuples;
	vacrelstats->rel_pages = nblocks;
	if (num_tuples == 0)
		min_tlen = max_tlen = 0;
	vacrelstats->min_tlen = min_tlen;
	vacrelstats->max_tlen = max_tlen;

	vacuum_pages->empty_end_pages = empty_end_pages;
	fraged_pages->empty_end_pages = empty_end_pages;

	
	if (do_shrinking)
	{
		int			i;

		Assert((BlockNumber) fraged_pages->num_pages >= empty_end_pages);
		fraged_pages->num_pages -= empty_end_pages;
		usable_free_space = 0;
		for (i = 0; i < fraged_pages->num_pages; i++)
			usable_free_space += fraged_pages->pagedesc[i]->free;
	}
	else {
		fraged_pages->num_pages = 0;
		usable_free_space = 0;
	}

	
	if (fraged_pages->num_pages > 0 && num_vtlinks > 0)
	{
		qsort((char *) vtlinks, num_vtlinks, sizeof(VTupleLinkData), vac_cmp_vtlinks);
		vacrelstats->vtlinks = vtlinks;
		vacrelstats->num_vtlinks = num_vtlinks;
	}
	else {
		vacrelstats->vtlinks = NULL;
		vacrelstats->num_vtlinks = 0;
		pfree(vtlinks);
	}

	ereport(elevel, (errmsg("\"%s\": found %.0f removable, %.0f nonremovable row versions in %u pages", RelationGetRelationName(onerel), tups_vacuumed, num_tuples, nblocks), errdetail("%.0f dead row versions cannot be removed yet.\n" "Nonremovable row versions range from %lu to %lu bytes long.\n" "There were %.0f unused item pointers.\n" "Total free space (including removable row versions) is %.0f bytes.\n" "%u pages are or will become empty, including %u at the end of the table.\n" "%u pages containing %.0f free bytes are potential move destinations.\n" "%s.", nkeep, (unsigned long) min_tlen, (unsigned long) max_tlen, nunused, free_space, empty_pages, empty_end_pages, fraged_pages->num_pages, usable_free_space, pg_rusage_show(&ru0))));
















}



static void repair_frag(VRelStats *vacrelstats, Relation onerel, VacPageList vacuum_pages, VacPageList fraged_pages, int nindexes, Relation *Irel)


{
	TransactionId myXID = GetCurrentTransactionId();
	Buffer		dst_buffer = InvalidBuffer;
	BlockNumber nblocks, blkno;
	BlockNumber last_move_dest_block = 0, last_vacuum_block;
	Page		dst_page = NULL;
	ExecContextData ec;
	VacPageListData Nvacpagelist;
	VacPage		dst_vacpage = NULL, last_vacuum_page, vacpage, *curpage;


	int			i;
	int			num_moved = 0, num_fraged_pages, vacuumed_pages;

	int			keep_tuples = 0;
	int			keep_indexed_tuples = 0;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	ExecContext_Init(&ec, onerel);

	Nvacpagelist.num_pages = 0;
	num_fraged_pages = fraged_pages->num_pages;
	Assert((BlockNumber) vacuum_pages->num_pages >= vacuum_pages->empty_end_pages);
	vacuumed_pages = vacuum_pages->num_pages - vacuum_pages->empty_end_pages;
	if (vacuumed_pages > 0)
	{
		
		last_vacuum_page = vacuum_pages->pagedesc[vacuumed_pages - 1];
		last_vacuum_block = last_vacuum_page->blkno;
	}
	else {
		last_vacuum_page = NULL;
		last_vacuum_block = InvalidBlockNumber;
	}

	vacpage = (VacPage) palloc(sizeof(VacPageData) + MaxOffsetNumber * sizeof(OffsetNumber));
	vacpage->offsets_used = vacpage->offsets_free = 0;

	
	nblocks = vacrelstats->rel_pages;
	for (blkno = nblocks - vacuum_pages->empty_end_pages - 1;
		 blkno > last_move_dest_block;
		 blkno--)
	{
		Buffer		buf;
		Page		page;
		OffsetNumber offnum, maxoff;
		bool		isempty, chain_tuple_moved;

		vacuum_delay_point();

		
		while (num_fraged_pages > 0 && fraged_pages->pagedesc[num_fraged_pages - 1]->blkno >= blkno)
		{
			Assert(fraged_pages->pagedesc[num_fraged_pages - 1]->offsets_used == 0);
			--num_fraged_pages;
		}

		
		buf = ReadBufferWithStrategy(onerel, blkno, vac_strategy);
		page = BufferGetPage(buf);

		vacpage->offsets_free = 0;

		isempty = PageIsEmpty(page);

		
		if (blkno == last_vacuum_block)
		{
			if (last_vacuum_page->offsets_free > 0)
			{
				
				Assert(!isempty);
				LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
				vacuum_page(onerel, buf, last_vacuum_page);
				LockBuffer(buf, BUFFER_LOCK_UNLOCK);
			}
			else Assert(isempty);
			--vacuumed_pages;
			if (vacuumed_pages > 0)
			{
				
				last_vacuum_page = vacuum_pages->pagedesc[vacuumed_pages - 1];
				last_vacuum_block = last_vacuum_page->blkno;
			}
			else {
				last_vacuum_page = NULL;
				last_vacuum_block = InvalidBlockNumber;
			}
			if (isempty)
			{
				ReleaseBuffer(buf);
				continue;
			}
		}
		else Assert(!isempty);

		chain_tuple_moved = false;		
		vacpage->blkno = blkno;
		maxoff = PageGetMaxOffsetNumber(page);
		for (offnum = FirstOffsetNumber;
			 offnum <= maxoff;
			 offnum = OffsetNumberNext(offnum))
		{
			Size		tuple_len;
			HeapTupleData tuple;
			ItemId		itemid = PageGetItemId(page, offnum);

			if (!ItemIdIsUsed(itemid))
				continue;

			if (ItemIdIsDead(itemid))
			{
				
				vacpage->offsets[vacpage->offsets_free++] = offnum;
				continue;
			}

			
			Assert(ItemIdIsNormal(itemid));

			tuple.t_data = (HeapTupleHeader) PageGetItem(page, itemid);
			tuple_len = tuple.t_len = ItemIdGetLength(itemid);
			ItemPointerSet(&(tuple.t_self), blkno, offnum);

			
			if (!(tuple.t_data->t_infomask & HEAP_XMIN_COMMITTED))
			{
				if (tuple.t_data->t_infomask & HEAP_MOVED_IN)
					elog(ERROR, "HEAP_MOVED_IN was not expected");
				if (!(tuple.t_data->t_infomask & HEAP_MOVED_OFF))
					elog(ERROR, "HEAP_MOVED_OFF was expected");

				
				if (HeapTupleHeaderGetXvac(tuple.t_data) != myXID)
					elog(ERROR, "invalid XVAC in tuple header");

				

				
				if (keep_tuples == 0)
					continue;
				if (chain_tuple_moved)
				{
					
					Assert(vacpage->offsets_free > 0);
					for (i = 0; i < vacpage->offsets_free; i++)
					{
						if (vacpage->offsets[i] == offnum)
							break;
					}
					if (i >= vacpage->offsets_free)		
					{
						vacpage->offsets[vacpage->offsets_free++] = offnum;

						
						if (!HeapTupleHeaderIsHeapOnly(tuple.t_data))
							keep_indexed_tuples--;
						keep_tuples--;
					}
				}
				else {
					vacpage->offsets[vacpage->offsets_free++] = offnum;

					
					if (!HeapTupleHeaderIsHeapOnly(tuple.t_data))
						keep_indexed_tuples--;
					keep_tuples--;
				}
				continue;
			}

			
			if (((tuple.t_data->t_infomask & HEAP_UPDATED) && !TransactionIdPrecedes(HeapTupleHeaderGetXmin(tuple.t_data), OldestXmin)) || (!(tuple.t_data->t_infomask & (HEAP_XMAX_INVALID | HEAP_IS_LOCKED)) && !(ItemPointerEquals(&(tuple.t_self), &(tuple.t_data->t_ctid)))))





			{
				Buffer		Cbuf = buf;
				bool		freeCbuf = false;
				bool		chain_move_failed = false;
				bool		moved_target = false;
				ItemPointerData Ctid;
				HeapTupleData tp = tuple;
				Size		tlen = tuple_len;
				VTupleMove	vtmove;
				int			num_vtmove;
				int			free_vtmove;
				VacPage		to_vacpage = NULL;
				int			to_item = 0;
				int			ti;

				if (dst_buffer != InvalidBuffer)
				{
					ReleaseBuffer(dst_buffer);
					dst_buffer = InvalidBuffer;
				}

				
				if (vacrelstats->vtlinks == NULL)
				{
					elog(DEBUG2, "parent item in update-chain not found --- cannot continue repair_frag");
					break;		
				}

				
				while (!(tp.t_data->t_infomask & (HEAP_XMAX_INVALID | HEAP_IS_LOCKED)) && !(ItemPointerEquals(&(tp.t_self), &(tp.t_data->t_ctid))))


				{
					ItemPointerData nextTid;
					TransactionId priorXmax;
					Buffer		nextBuf;
					Page		nextPage;
					OffsetNumber nextOffnum;
					ItemId		nextItemid;
					HeapTupleHeader nextTdata;
					HTSV_Result nextTstatus;

					nextTid = tp.t_data->t_ctid;
					priorXmax = HeapTupleHeaderGetXmax(tp.t_data);
					
					nextBuf = ReadBufferWithStrategy(onerel, ItemPointerGetBlockNumber(&nextTid), vac_strategy);

					nextPage = BufferGetPage(nextBuf);
					
					nextOffnum = ItemPointerGetOffsetNumber(&nextTid);
					if (nextOffnum < FirstOffsetNumber || nextOffnum > PageGetMaxOffsetNumber(nextPage))
					{
						ReleaseBuffer(nextBuf);
						break;
					}
					nextItemid = PageGetItemId(nextPage, nextOffnum);
					if (!ItemIdIsNormal(nextItemid))
					{
						ReleaseBuffer(nextBuf);
						break;
					}
					
					nextTdata = (HeapTupleHeader) PageGetItem(nextPage, nextItemid);
					if (!TransactionIdEquals(HeapTupleHeaderGetXmin(nextTdata), priorXmax))
					{
						ReleaseBuffer(nextBuf);
						break;
					}

					
					LockBuffer(nextBuf, BUFFER_LOCK_SHARE);
					nextTstatus = HeapTupleSatisfiesVacuum(nextTdata, OldestXmin, nextBuf);

					if (nextTstatus == HEAPTUPLE_DEAD || nextTstatus == HEAPTUPLE_INSERT_IN_PROGRESS)
					{
						UnlockReleaseBuffer(nextBuf);
						break;
					}
					LockBuffer(nextBuf, BUFFER_LOCK_UNLOCK);
					
					if (nextTstatus == HEAPTUPLE_DELETE_IN_PROGRESS)
						elog(ERROR, "updated tuple is already HEAP_MOVED_OFF");
					
					tp.t_data = nextTdata;
					tp.t_self = nextTid;
					tlen = tp.t_len = ItemIdGetLength(nextItemid);
					if (freeCbuf)
						ReleaseBuffer(Cbuf);
					Cbuf = nextBuf;
					freeCbuf = true;
				}

				
				vtmove = (VTupleMove) palloc(100 * sizeof(VTupleMoveData));
				num_vtmove = 0;
				free_vtmove = 100;

				
				for (;;)
				{
					Buffer		Pbuf;
					Page		Ppage;
					ItemId		Pitemid;
					HeapTupleHeader PTdata;
					VTupleLinkData vtld, *vtlp;

					
					if (to_vacpage == NULL || !enough_space(to_vacpage, tlen))
					{
						for (i = 0; i < num_fraged_pages; i++)
						{
							if (enough_space(fraged_pages->pagedesc[i], tlen))
								break;
						}

						if (i == num_fraged_pages)
						{
							
							chain_move_failed = true;
							break;		
						}
						to_item = i;
						to_vacpage = fraged_pages->pagedesc[to_item];
					}
					to_vacpage->free -= MAXALIGN(tlen);
					if (to_vacpage->offsets_used >= to_vacpage->offsets_free)
						to_vacpage->free -= sizeof(ItemIdData);
					(to_vacpage->offsets_used)++;

					
					if (free_vtmove == 0)
					{
						free_vtmove = 1000;
						vtmove = (VTupleMove)
							repalloc(vtmove, (free_vtmove + num_vtmove) * sizeof(VTupleMoveData));

					}
					vtmove[num_vtmove].tid = tp.t_self;
					vtmove[num_vtmove].vacpage = to_vacpage;
					if (to_vacpage->offsets_used == 1)
						vtmove[num_vtmove].cleanVpd = true;
					else vtmove[num_vtmove].cleanVpd = false;
					free_vtmove--;
					num_vtmove++;

					
					if (ItemPointerGetBlockNumber(&tp.t_self) == blkno && ItemPointerGetOffsetNumber(&tp.t_self) == offnum)
						moved_target = true;

					
					if (!(tp.t_data->t_infomask & HEAP_UPDATED) || TransactionIdPrecedes(HeapTupleHeaderGetXmin(tp.t_data), OldestXmin))

						break;	

					
					vtld.new_tid = tp.t_self;
					vtlp = (VTupleLink)
						vac_bsearch((void *) &vtld, (void *) (vacrelstats->vtlinks), vacrelstats->num_vtlinks, sizeof(VTupleLinkData), vac_cmp_vtlinks);



					if (vtlp == NULL)
					{
						
						elog(DEBUG2, "parent item in update-chain not found --- cannot continue repair_frag");
						chain_move_failed = true;
						break;	
					}
					tp.t_self = vtlp->this_tid;
					Pbuf = ReadBufferWithStrategy(onerel, ItemPointerGetBlockNumber(&(tp.t_self)), vac_strategy);

					Ppage = BufferGetPage(Pbuf);
					Pitemid = PageGetItemId(Ppage, ItemPointerGetOffsetNumber(&(tp.t_self)));
					
					if (!ItemIdIsNormal(Pitemid))
						elog(ERROR, "parent itemid marked as unused");
					PTdata = (HeapTupleHeader) PageGetItem(Ppage, Pitemid);

					
					Assert(ItemPointerEquals(&(vtld.new_tid), &(PTdata->t_ctid)));

					
					if ((PTdata->t_infomask & HEAP_XMAX_IS_MULTI) || !(TransactionIdEquals(HeapTupleHeaderGetXmax(PTdata), HeapTupleHeaderGetXmin(tp.t_data))))

					{
						ReleaseBuffer(Pbuf);
						elog(DEBUG2, "too old parent tuple found --- cannot continue repair_frag");
						chain_move_failed = true;
						break;	
					}
					tp.t_data = PTdata;
					tlen = tp.t_len = ItemIdGetLength(Pitemid);
					if (freeCbuf)
						ReleaseBuffer(Cbuf);
					Cbuf = Pbuf;
					freeCbuf = true;
				}				

				if (freeCbuf)
					ReleaseBuffer(Cbuf);
				freeCbuf = false;

				
				if (!moved_target && !chain_move_failed)
				{
					elog(DEBUG2, "failed to chain back to target --- cannot continue repair_frag");
					chain_move_failed = true;
				}

				if (chain_move_failed)
				{
					
					for (i = 0; i < num_vtmove; i++)
					{
						Assert(vtmove[i].vacpage->offsets_used > 0);
						(vtmove[i].vacpage->offsets_used)--;
					}
					pfree(vtmove);
					break;		
				}

				
				ItemPointerSetInvalid(&Ctid);
				for (ti = 0; ti < num_vtmove; ti++)
				{
					VacPage		destvacpage = vtmove[ti].vacpage;
					Page		Cpage;
					ItemId		Citemid;

					
					tuple.t_self = vtmove[ti].tid;
					Cbuf = ReadBufferWithStrategy(onerel, ItemPointerGetBlockNumber(&(tuple.t_self)), vac_strategy);


					
					dst_buffer = ReadBufferWithStrategy(onerel, destvacpage->blkno, vac_strategy);


					LockBuffer(dst_buffer, BUFFER_LOCK_EXCLUSIVE);
					if (dst_buffer != Cbuf)
						LockBuffer(Cbuf, BUFFER_LOCK_EXCLUSIVE);

					dst_page = BufferGetPage(dst_buffer);
					Cpage = BufferGetPage(Cbuf);

					Citemid = PageGetItemId(Cpage, ItemPointerGetOffsetNumber(&(tuple.t_self)));
					tuple.t_data = (HeapTupleHeader) PageGetItem(Cpage, Citemid);
					tuple_len = tuple.t_len = ItemIdGetLength(Citemid);

					move_chain_tuple(onerel, Cbuf, Cpage, &tuple, dst_buffer, dst_page, destvacpage, &ec, &Ctid, vtmove[ti].cleanVpd);


					
					if (HeapTupleHeaderIsHeapOnly(tuple.t_data))
						vacrelstats->rel_indexed_tuples++;

					num_moved++;
					if (destvacpage->blkno > last_move_dest_block)
						last_move_dest_block = destvacpage->blkno;

					
					if (Cbuf == buf)
						vacpage->offsets[vacpage->offsets_free++] = ItemPointerGetOffsetNumber(&(tuple.t_self));
					else {
						
						if (!HeapTupleHeaderIsHeapOnly(tuple.t_data))
							keep_indexed_tuples++;
						keep_tuples++;
					}

					ReleaseBuffer(dst_buffer);
					ReleaseBuffer(Cbuf);
				}				

				dst_buffer = InvalidBuffer;
				pfree(vtmove);
				chain_tuple_moved = true;

				
				continue;
			}					

			
			if (dst_buffer == InvalidBuffer || !enough_space(dst_vacpage, tuple_len))
			{
				if (dst_buffer != InvalidBuffer)
				{
					ReleaseBuffer(dst_buffer);
					dst_buffer = InvalidBuffer;
				}
				for (i = 0; i < num_fraged_pages; i++)
				{
					if (enough_space(fraged_pages->pagedesc[i], tuple_len))
						break;
				}
				if (i == num_fraged_pages)
					break;		
				dst_vacpage = fraged_pages->pagedesc[i];
				dst_buffer = ReadBufferWithStrategy(onerel, dst_vacpage->blkno, vac_strategy);

				LockBuffer(dst_buffer, BUFFER_LOCK_EXCLUSIVE);
				dst_page = BufferGetPage(dst_buffer);
				
				if (!PageIsEmpty(dst_page) && dst_vacpage->offsets_used == 0)
					vacuum_page(onerel, dst_buffer, dst_vacpage);
			}
			else LockBuffer(dst_buffer, BUFFER_LOCK_EXCLUSIVE);

			LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

			move_plain_tuple(onerel, buf, page, &tuple, dst_buffer, dst_page, dst_vacpage, &ec);

			
			if (HeapTupleHeaderIsHeapOnly(tuple.t_data))
				vacrelstats->rel_indexed_tuples++;

			num_moved++;
			if (dst_vacpage->blkno > last_move_dest_block)
				last_move_dest_block = dst_vacpage->blkno;

			
			vacpage->offsets[vacpage->offsets_free++] = offnum;
		}						

		
		if (offnum < maxoff && keep_tuples > 0)
		{
			OffsetNumber off;

			
			for (off = OffsetNumberNext(offnum);
				 off <= maxoff;
				 off = OffsetNumberNext(off))
			{
				ItemId		itemid = PageGetItemId(page, off);
				HeapTupleHeader htup;

				if (!ItemIdIsUsed(itemid))
					continue;
				
				Assert(ItemIdIsNormal(itemid));

				htup = (HeapTupleHeader) PageGetItem(page, itemid);
				if (htup->t_infomask & HEAP_XMIN_COMMITTED)
					continue;

				
				if (htup->t_infomask & HEAP_MOVED_IN)
					elog(ERROR, "HEAP_MOVED_IN was not expected");
				if (!(htup->t_infomask & HEAP_MOVED_OFF))
					elog(ERROR, "HEAP_MOVED_OFF was expected");
				if (HeapTupleHeaderGetXvac(htup) != myXID)
					elog(ERROR, "invalid XVAC in tuple header");

				if (chain_tuple_moved)
				{
					
					Assert(vacpage->offsets_free > 0);
					for (i = 0; i < vacpage->offsets_free; i++)
					{
						if (vacpage->offsets[i] == off)
							break;
					}
					if (i >= vacpage->offsets_free)		
					{
						vacpage->offsets[vacpage->offsets_free++] = off;
						Assert(keep_tuples > 0);

						
						if (!HeapTupleHeaderIsHeapOnly(htup))
							keep_indexed_tuples--;
						keep_tuples--;
					}
				}
				else {
					vacpage->offsets[vacpage->offsets_free++] = off;
					Assert(keep_tuples > 0);
					if (!HeapTupleHeaderIsHeapOnly(htup))
						keep_indexed_tuples--;
					keep_tuples--;
				}
			}
		}

		if (vacpage->offsets_free > 0)	
		{
			if (chain_tuple_moved)		
			{
				qsort((char *) (vacpage->offsets), vacpage->offsets_free, sizeof(OffsetNumber), vac_cmp_offno);
			}
			vpage_insert(&Nvacpagelist, copy_vac_page(vacpage));
		}

		ReleaseBuffer(buf);

		if (offnum <= maxoff)
			break;				

	}							

	blkno++;					

	if (dst_buffer != InvalidBuffer)
	{
		Assert(num_moved > 0);
		ReleaseBuffer(dst_buffer);
	}

	if (num_moved > 0)
	{
		
		ForceSyncCommit();
		(void) RecordTransactionCommit();
	}

	
	for (i = 0, curpage = vacuum_pages->pagedesc;
		 i < vacuumed_pages;
		 i++, curpage++)
	{
		vacuum_delay_point();

		Assert((*curpage)->blkno < blkno);
		if ((*curpage)->offsets_used == 0)
		{
			Buffer		buf;
			Page		page;

			
			buf = ReadBufferWithStrategy(onerel, (*curpage)->blkno, vac_strategy);

			LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
			page = BufferGetPage(buf);
			if (!PageIsEmpty(page))
				vacuum_page(onerel, buf, *curpage);
			UnlockReleaseBuffer(buf);
		}
	}

	
	update_hint_bits(onerel, fraged_pages, num_fraged_pages, last_move_dest_block, num_moved);

	
	ereport(elevel, (errmsg("\"%s\": moved %u row versions, truncated %u to %u pages", RelationGetRelationName(onerel), num_moved, nblocks, blkno), errdetail("%s.", pg_rusage_show(&ru0))));





	
	CommandCounterIncrement();

	if (Nvacpagelist.num_pages > 0)
	{
		
		if (Irel != NULL)
		{
			VacPage    *vpleft, *vpright, vpsave;


			
			for (vpleft = Nvacpagelist.pagedesc, vpright = Nvacpagelist.pagedesc + Nvacpagelist.num_pages - 1;
				 vpleft < vpright; vpleft++, vpright--)
			{
				vpsave = *vpleft;
				*vpleft = *vpright;
				*vpright = vpsave;
			}

			
			Assert(keep_tuples >= 0);
			for (i = 0; i < nindexes; i++)
				vacuum_index(&Nvacpagelist, Irel[i], vacrelstats->rel_indexed_tuples, keep_indexed_tuples);

		}

		
		if (vacpage->blkno == (blkno - 1) && vacpage->offsets_free > 0)
		{
			Buffer		buf;
			Page		page;
			OffsetNumber unused[MaxOffsetNumber];
			OffsetNumber offnum, maxoff;
			int			uncnt = 0;
			int			num_tuples = 0;

			buf = ReadBufferWithStrategy(onerel, vacpage->blkno, vac_strategy);
			LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
			page = BufferGetPage(buf);
			maxoff = PageGetMaxOffsetNumber(page);
			for (offnum = FirstOffsetNumber;
				 offnum <= maxoff;
				 offnum = OffsetNumberNext(offnum))
			{
				ItemId		itemid = PageGetItemId(page, offnum);
				HeapTupleHeader htup;

				if (!ItemIdIsUsed(itemid))
					continue;
				
				Assert(ItemIdIsNormal(itemid));

				htup = (HeapTupleHeader) PageGetItem(page, itemid);
				if (htup->t_infomask & HEAP_XMIN_COMMITTED)
					continue;

				
				if (htup->t_infomask & HEAP_MOVED_IN)
					elog(ERROR, "HEAP_MOVED_IN was not expected");
				if (!(htup->t_infomask & HEAP_MOVED_OFF))
					elog(ERROR, "HEAP_MOVED_OFF was expected");
				if (HeapTupleHeaderGetXvac(htup) != myXID)
					elog(ERROR, "invalid XVAC in tuple header");

				ItemIdSetUnused(itemid);
				num_tuples++;

				unused[uncnt++] = offnum;
			}
			Assert(vacpage->offsets_free == num_tuples);

			START_CRIT_SECTION();

			PageRepairFragmentation(page);

			MarkBufferDirty(buf);

			
			if (!onerel->rd_istemp)
			{
				XLogRecPtr	recptr;

				recptr = log_heap_clean(onerel, buf, NULL, 0, NULL, 0, unused, uncnt, false);


				PageSetLSN(page, recptr);
				PageSetTLI(page, ThisTimeLineID);
			}

			END_CRIT_SECTION();

			UnlockReleaseBuffer(buf);
		}

		
		curpage = Nvacpagelist.pagedesc;
		for (i = 0; i < Nvacpagelist.num_pages; i++, curpage++)
			pfree(*curpage);
		pfree(Nvacpagelist.pagedesc);
	}

	
	if (blkno < nblocks)
	{
		RelationTruncate(onerel, blkno);
		vacrelstats->rel_pages = blkno; 
	}

	
	pfree(vacpage);
	if (vacrelstats->vtlinks != NULL)
		pfree(vacrelstats->vtlinks);

	ExecContext_Finish(&ec);
}


static void move_chain_tuple(Relation rel, Buffer old_buf, Page old_page, HeapTuple old_tup, Buffer dst_buf, Page dst_page, VacPage dst_vacpage, ExecContext ec, ItemPointer ctid, bool cleanVpd)



{
	TransactionId myXID = GetCurrentTransactionId();
	HeapTupleData newtup;
	OffsetNumber newoff;
	ItemId		newitemid;
	Size		tuple_len = old_tup->t_len;

	
	heap_copytuple_with_tuple(old_tup, &newtup);

	
	CacheInvalidateHeapTuple(rel, old_tup);

	
	START_CRIT_SECTION();

	
	old_tup->t_data->t_infomask &= ~(HEAP_XMIN_COMMITTED | HEAP_XMIN_INVALID | HEAP_MOVED_IN);

	old_tup->t_data->t_infomask |= HEAP_MOVED_OFF;
	HeapTupleHeaderSetXvac(old_tup->t_data, myXID);

	
	if (!PageIsEmpty(dst_page) && cleanVpd)
	{
		int			sv_offsets_used = dst_vacpage->offsets_used;

		dst_vacpage->offsets_used = 0;
		vacuum_page(rel, dst_buf, dst_vacpage);
		dst_vacpage->offsets_used = sv_offsets_used;
	}

	
	newtup.t_data->t_infomask &= ~(HEAP_XMIN_COMMITTED | HEAP_XMIN_INVALID | HEAP_MOVED_OFF);

	newtup.t_data->t_infomask |= HEAP_MOVED_IN;
	HeapTupleHeaderClearHotUpdated(newtup.t_data);
	HeapTupleHeaderClearHeapOnly(newtup.t_data);
	HeapTupleHeaderSetXvac(newtup.t_data, myXID);
	newoff = PageAddItem(dst_page, (Item) newtup.t_data, tuple_len, InvalidOffsetNumber, false, true);
	if (newoff == InvalidOffsetNumber)
		elog(PANIC, "failed to add item with len = %lu to page %u while moving tuple chain", (unsigned long) tuple_len, dst_vacpage->blkno);
	newitemid = PageGetItemId(dst_page, newoff);
	
	pfree(newtup.t_data);
	newtup.t_data = (HeapTupleHeader) PageGetItem(dst_page, newitemid);

	ItemPointerSet(&(newtup.t_self), dst_vacpage->blkno, newoff);

	
	if (!ItemPointerIsValid(ctid))
		newtup.t_data->t_ctid = newtup.t_self;
	else newtup.t_data->t_ctid = *ctid;
	*ctid = newtup.t_self;

	MarkBufferDirty(dst_buf);
	if (dst_buf != old_buf)
		MarkBufferDirty(old_buf);

	
	if (!rel->rd_istemp)
	{
		XLogRecPtr	recptr = log_heap_move(rel, old_buf, old_tup->t_self, dst_buf, &newtup);

		if (old_buf != dst_buf)
		{
			PageSetLSN(old_page, recptr);
			PageSetTLI(old_page, ThisTimeLineID);
		}
		PageSetLSN(dst_page, recptr);
		PageSetTLI(dst_page, ThisTimeLineID);
	}

	END_CRIT_SECTION();

	LockBuffer(dst_buf, BUFFER_LOCK_UNLOCK);
	if (dst_buf != old_buf)
		LockBuffer(old_buf, BUFFER_LOCK_UNLOCK);

	
	if (ec->resultRelInfo->ri_NumIndices > 0)
	{
		ExecStoreTuple(&newtup, ec->slot, InvalidBuffer, false);
		ExecInsertIndexTuples(ec->slot, &(newtup.t_self), ec->estate, true);
		ResetPerTupleExprContext(ec->estate);
	}
}


static void move_plain_tuple(Relation rel, Buffer old_buf, Page old_page, HeapTuple old_tup, Buffer dst_buf, Page dst_page, VacPage dst_vacpage, ExecContext ec)



{
	TransactionId myXID = GetCurrentTransactionId();
	HeapTupleData newtup;
	OffsetNumber newoff;
	ItemId		newitemid;
	Size		tuple_len = old_tup->t_len;

	
	heap_copytuple_with_tuple(old_tup, &newtup);

	
	CacheInvalidateHeapTuple(rel, old_tup);

	
	START_CRIT_SECTION();

	
	newtup.t_data->t_infomask &= ~(HEAP_XMIN_COMMITTED | HEAP_XMIN_INVALID | HEAP_MOVED_OFF);

	newtup.t_data->t_infomask |= HEAP_MOVED_IN;
	HeapTupleHeaderClearHotUpdated(newtup.t_data);
	HeapTupleHeaderClearHeapOnly(newtup.t_data);
	HeapTupleHeaderSetXvac(newtup.t_data, myXID);

	
	newoff = PageAddItem(dst_page, (Item) newtup.t_data, tuple_len, InvalidOffsetNumber, false, true);
	if (newoff == InvalidOffsetNumber)
		elog(PANIC, "failed to add item with len = %lu to page %u (free space %lu, nusd %u, noff %u)", (unsigned long) tuple_len, dst_vacpage->blkno, (unsigned long) dst_vacpage->free, dst_vacpage->offsets_used, dst_vacpage->offsets_free);


	newitemid = PageGetItemId(dst_page, newoff);
	pfree(newtup.t_data);
	newtup.t_data = (HeapTupleHeader) PageGetItem(dst_page, newitemid);
	ItemPointerSet(&(newtup.t_data->t_ctid), dst_vacpage->blkno, newoff);
	newtup.t_self = newtup.t_data->t_ctid;

	
	old_tup->t_data->t_infomask &= ~(HEAP_XMIN_COMMITTED | HEAP_XMIN_INVALID | HEAP_MOVED_IN);

	old_tup->t_data->t_infomask |= HEAP_MOVED_OFF;
	HeapTupleHeaderSetXvac(old_tup->t_data, myXID);

	MarkBufferDirty(dst_buf);
	MarkBufferDirty(old_buf);

	
	if (!rel->rd_istemp)
	{
		XLogRecPtr	recptr = log_heap_move(rel, old_buf, old_tup->t_self, dst_buf, &newtup);

		PageSetLSN(old_page, recptr);
		PageSetTLI(old_page, ThisTimeLineID);
		PageSetLSN(dst_page, recptr);
		PageSetTLI(dst_page, ThisTimeLineID);
	}

	END_CRIT_SECTION();

	dst_vacpage->free = PageGetFreeSpaceWithFillFactor(rel, dst_page);
	LockBuffer(dst_buf, BUFFER_LOCK_UNLOCK);
	LockBuffer(old_buf, BUFFER_LOCK_UNLOCK);

	dst_vacpage->offsets_used++;

	
	if (ec->resultRelInfo->ri_NumIndices > 0)
	{
		ExecStoreTuple(&newtup, ec->slot, InvalidBuffer, false);
		ExecInsertIndexTuples(ec->slot, &(newtup.t_self), ec->estate, true);
		ResetPerTupleExprContext(ec->estate);
	}
}


static void update_hint_bits(Relation rel, VacPageList fraged_pages, int num_fraged_pages, BlockNumber last_move_dest_block, int num_moved)

{
	TransactionId myXID = GetCurrentTransactionId();
	int			checked_moved = 0;
	int			i;
	VacPage    *curpage;

	for (i = 0, curpage = fraged_pages->pagedesc;
		 i < num_fraged_pages;
		 i++, curpage++)
	{
		Buffer		buf;
		Page		page;
		OffsetNumber max_offset;
		OffsetNumber off;
		int			num_tuples = 0;

		vacuum_delay_point();

		if ((*curpage)->blkno > last_move_dest_block)
			break;				
		if ((*curpage)->offsets_used == 0)
			continue;			
		buf = ReadBufferWithStrategy(rel, (*curpage)->blkno, vac_strategy);
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buf);
		max_offset = PageGetMaxOffsetNumber(page);
		for (off = FirstOffsetNumber;
			 off <= max_offset;
			 off = OffsetNumberNext(off))
		{
			ItemId		itemid = PageGetItemId(page, off);
			HeapTupleHeader htup;

			if (!ItemIdIsUsed(itemid))
				continue;
			
			Assert(ItemIdIsNormal(itemid));

			htup = (HeapTupleHeader) PageGetItem(page, itemid);
			if (htup->t_infomask & HEAP_XMIN_COMMITTED)
				continue;

			
			if (!(htup->t_infomask & HEAP_MOVED))
				elog(ERROR, "HEAP_MOVED_OFF/HEAP_MOVED_IN was expected");
			if (HeapTupleHeaderGetXvac(htup) != myXID)
				elog(ERROR, "invalid XVAC in tuple header");

			if (htup->t_infomask & HEAP_MOVED_IN)
			{
				htup->t_infomask |= HEAP_XMIN_COMMITTED;
				htup->t_infomask &= ~HEAP_MOVED;
				num_tuples++;
			}
			else htup->t_infomask |= HEAP_XMIN_INVALID;
		}
		MarkBufferDirty(buf);
		UnlockReleaseBuffer(buf);
		Assert((*curpage)->offsets_used == num_tuples);
		checked_moved += num_tuples;
	}
	Assert(num_moved == checked_moved);
}


static void vacuum_heap(VRelStats *vacrelstats, Relation onerel, VacPageList vacuum_pages)
{
	Buffer		buf;
	VacPage    *vacpage;
	BlockNumber relblocks;
	int			nblocks;
	int			i;

	nblocks = vacuum_pages->num_pages;
	nblocks -= vacuum_pages->empty_end_pages;	

	for (i = 0, vacpage = vacuum_pages->pagedesc; i < nblocks; i++, vacpage++)
	{
		vacuum_delay_point();

		if ((*vacpage)->offsets_free > 0)
		{
			buf = ReadBufferWithStrategy(onerel, (*vacpage)->blkno, vac_strategy);

			LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
			vacuum_page(onerel, buf, *vacpage);
			UnlockReleaseBuffer(buf);
		}
	}

	
	Assert(vacrelstats->rel_pages >= vacuum_pages->empty_end_pages);
	if (vacuum_pages->empty_end_pages > 0)
	{
		relblocks = vacrelstats->rel_pages - vacuum_pages->empty_end_pages;
		ereport(elevel, (errmsg("\"%s\": truncated %u to %u pages", RelationGetRelationName(onerel), vacrelstats->rel_pages, relblocks)));


		RelationTruncate(onerel, relblocks);
		vacrelstats->rel_pages = relblocks;		
	}
}


static void vacuum_page(Relation onerel, Buffer buffer, VacPage vacpage)
{
	Page		page = BufferGetPage(buffer);
	int			i;

	
	Assert(vacpage->offsets_used == 0);

	START_CRIT_SECTION();

	for (i = 0; i < vacpage->offsets_free; i++)
	{
		ItemId		itemid = PageGetItemId(page, vacpage->offsets[i]);

		ItemIdSetUnused(itemid);
	}

	PageRepairFragmentation(page);

	MarkBufferDirty(buffer);

	
	if (!onerel->rd_istemp)
	{
		XLogRecPtr	recptr;

		recptr = log_heap_clean(onerel, buffer, NULL, 0, NULL, 0, vacpage->offsets, vacpage->offsets_free, false);


		PageSetLSN(page, recptr);
		PageSetTLI(page, ThisTimeLineID);
	}

	END_CRIT_SECTION();
}


static void scan_index(Relation indrel, double num_tuples)
{
	IndexBulkDeleteResult *stats;
	IndexVacuumInfo ivinfo;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	ivinfo.index = indrel;
	ivinfo.vacuum_full = true;
	ivinfo.message_level = elevel;
	ivinfo.num_heap_tuples = num_tuples;
	ivinfo.strategy = vac_strategy;

	stats = index_vacuum_cleanup(&ivinfo, NULL);

	if (!stats)
		return;

	
	vac_update_relstats(RelationGetRelid(indrel), stats->num_pages, stats->num_index_tuples, false, InvalidTransactionId);


	ereport(elevel, (errmsg("index \"%s\" now contains %.0f row versions in %u pages", RelationGetRelationName(indrel), stats->num_index_tuples, stats->num_pages), errdetail("%u index pages have been deleted, %u are currently reusable.\n" "%s.", stats->pages_deleted, stats->pages_free, pg_rusage_show(&ru0))));








	
	if (stats->num_index_tuples != num_tuples)
	{
		if (stats->num_index_tuples > num_tuples || !vac_is_partial_index(indrel))
			ereport(WARNING, (errmsg("index \"%s\" contains %.0f row versions, but table contains %.0f row versions", RelationGetRelationName(indrel), stats->num_index_tuples, num_tuples), errhint("Rebuild the index with REINDEX.")));



	}

	pfree(stats);
}


static void vacuum_index(VacPageList vacpagelist, Relation indrel, double num_tuples, int keep_tuples)

{
	IndexBulkDeleteResult *stats;
	IndexVacuumInfo ivinfo;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	ivinfo.index = indrel;
	ivinfo.vacuum_full = true;
	ivinfo.message_level = elevel;
	ivinfo.num_heap_tuples = num_tuples + keep_tuples;
	ivinfo.strategy = vac_strategy;

	
	stats = index_bulk_delete(&ivinfo, NULL, tid_reaped, (void *) vacpagelist);

	
	stats = index_vacuum_cleanup(&ivinfo, stats);

	if (!stats)
		return;

	
	vac_update_relstats(RelationGetRelid(indrel), stats->num_pages, stats->num_index_tuples, false, InvalidTransactionId);


	ereport(elevel, (errmsg("index \"%s\" now contains %.0f row versions in %u pages", RelationGetRelationName(indrel), stats->num_index_tuples, stats->num_pages), errdetail("%.0f index row versions were removed.\n" "%u index pages have been deleted, %u are currently reusable.\n" "%s.", stats->tuples_removed, stats->pages_deleted, stats->pages_free, pg_rusage_show(&ru0))));










	
	if (stats->num_index_tuples != num_tuples + keep_tuples)
	{
		if (stats->num_index_tuples > num_tuples + keep_tuples || !vac_is_partial_index(indrel))
			ereport(WARNING, (errmsg("index \"%s\" contains %.0f row versions, but table contains %.0f row versions", RelationGetRelationName(indrel), stats->num_index_tuples, num_tuples + keep_tuples), errhint("Rebuild the index with REINDEX.")));



	}

	pfree(stats);
}


static bool tid_reaped(ItemPointer itemptr, void *state)
{
	VacPageList vacpagelist = (VacPageList) state;
	OffsetNumber ioffno;
	OffsetNumber *voff;
	VacPage		vp, *vpp;
	VacPageData vacpage;

	vacpage.blkno = ItemPointerGetBlockNumber(itemptr);
	ioffno = ItemPointerGetOffsetNumber(itemptr);

	vp = &vacpage;
	vpp = (VacPage *) vac_bsearch((void *) &vp, (void *) (vacpagelist->pagedesc), vacpagelist->num_pages, sizeof(VacPage), vac_cmp_blk);




	if (vpp == NULL)
		return false;

	
	vp = *vpp;

	if (vp->offsets_free == 0)
	{
		
		return true;
	}

	voff = (OffsetNumber *) vac_bsearch((void *) &ioffno, (void *) (vp->offsets), vp->offsets_free, sizeof(OffsetNumber), vac_cmp_offno);




	if (voff == NULL)
		return false;

	
	return true;
}


static void vac_update_fsm(Relation onerel, VacPageList fraged_pages, BlockNumber rel_pages)

{
	int			nPages = fraged_pages->num_pages;
	VacPage    *pagedesc = fraged_pages->pagedesc;
	Size		threshold;
	PageFreeSpaceInfo *pageSpaces;
	int			outPages;
	int			i;

	
	threshold = GetAvgFSMRequestSize(&onerel->rd_node);

	pageSpaces = (PageFreeSpaceInfo *)
		palloc(nPages * sizeof(PageFreeSpaceInfo));
	outPages = 0;

	for (i = 0; i < nPages; i++)
	{
		
		if (pagedesc[i]->blkno >= rel_pages)
			break;

		if (pagedesc[i]->free >= threshold)
		{
			pageSpaces[outPages].blkno = pagedesc[i]->blkno;
			pageSpaces[outPages].avail = pagedesc[i]->free;
			outPages++;
		}
	}

	RecordRelationFreeSpace(&onerel->rd_node, outPages, outPages, pageSpaces);

	pfree(pageSpaces);
}


static VacPage copy_vac_page(VacPage vacpage)
{
	VacPage		newvacpage;

	
	newvacpage = (VacPage) palloc(sizeof(VacPageData) + vacpage->offsets_free * sizeof(OffsetNumber));

	
	if (vacpage->offsets_free > 0)
		memcpy(newvacpage->offsets, vacpage->offsets, vacpage->offsets_free * sizeof(OffsetNumber));
	newvacpage->blkno = vacpage->blkno;
	newvacpage->free = vacpage->free;
	newvacpage->offsets_used = vacpage->offsets_used;
	newvacpage->offsets_free = vacpage->offsets_free;

	return newvacpage;
}


static void vpage_insert(VacPageList vacpagelist, VacPage vpnew)
{


	
	if (vacpagelist->num_pages == 0)
	{
		vacpagelist->pagedesc = (VacPage *) palloc(PG_NPAGEDESC * sizeof(VacPage));
		vacpagelist->num_allocated_pages = PG_NPAGEDESC;
	}
	else if (vacpagelist->num_pages >= vacpagelist->num_allocated_pages)
	{
		vacpagelist->num_allocated_pages *= 2;
		vacpagelist->pagedesc = (VacPage *) repalloc(vacpagelist->pagedesc, vacpagelist->num_allocated_pages * sizeof(VacPage));
	}
	vacpagelist->pagedesc[vacpagelist->num_pages] = vpnew;
	(vacpagelist->num_pages)++;
}


static void * vac_bsearch(const void *key, const void *base, size_t nelem, size_t size, int (*compar) (const void *, const void *))


{
	int			res;
	const void *last;

	if (nelem == 0)
		return NULL;
	res = compar(key, base);
	if (res < 0)
		return NULL;
	if (res == 0)
		return (void *) base;
	if (nelem > 1)
	{
		last = (const void *) ((const char *) base + (nelem - 1) * size);
		res = compar(key, last);
		if (res > 0)
			return NULL;
		if (res == 0)
			return (void *) last;
	}
	if (nelem <= 2)
		return NULL;			
	return bsearch(key, base, nelem, size, compar);
}


static int vac_cmp_blk(const void *left, const void *right)
{
	BlockNumber lblk, rblk;

	lblk = (*((VacPage *) left))->blkno;
	rblk = (*((VacPage *) right))->blkno;

	if (lblk < rblk)
		return -1;
	if (lblk == rblk)
		return 0;
	return 1;
}

static int vac_cmp_offno(const void *left, const void *right)
{
	if (*(OffsetNumber *) left < *(OffsetNumber *) right)
		return -1;
	if (*(OffsetNumber *) left == *(OffsetNumber *) right)
		return 0;
	return 1;
}

static int vac_cmp_vtlinks(const void *left, const void *right)
{
	if (((VTupleLink) left)->new_tid.ip_blkid.bi_hi < ((VTupleLink) right)->new_tid.ip_blkid.bi_hi)
		return -1;
	if (((VTupleLink) left)->new_tid.ip_blkid.bi_hi > ((VTupleLink) right)->new_tid.ip_blkid.bi_hi)
		return 1;
	
	if (((VTupleLink) left)->new_tid.ip_blkid.bi_lo < ((VTupleLink) right)->new_tid.ip_blkid.bi_lo)
		return -1;
	if (((VTupleLink) left)->new_tid.ip_blkid.bi_lo > ((VTupleLink) right)->new_tid.ip_blkid.bi_lo)
		return 1;
	
	if (((VTupleLink) left)->new_tid.ip_posid < ((VTupleLink) right)->new_tid.ip_posid)
		return -1;
	if (((VTupleLink) left)->new_tid.ip_posid > ((VTupleLink) right)->new_tid.ip_posid)
		return 1;
	return 0;
}



void vac_open_indexes(Relation relation, LOCKMODE lockmode, int *nindexes, Relation **Irel)

{
	List	   *indexoidlist;
	ListCell   *indexoidscan;
	int			i;

	Assert(lockmode != NoLock);

	indexoidlist = RelationGetIndexList(relation);

	*nindexes = list_length(indexoidlist);

	if (*nindexes > 0)
		*Irel = (Relation *) palloc(*nindexes * sizeof(Relation));
	else *Irel = NULL;

	i = 0;
	foreach(indexoidscan, indexoidlist)
	{
		Oid			indexoid = lfirst_oid(indexoidscan);

		(*Irel)[i++] = index_open(indexoid, lockmode);
	}

	list_free(indexoidlist);
}


void vac_close_indexes(int nindexes, Relation *Irel, LOCKMODE lockmode)
{
	if (Irel == NULL)
		return;

	while (nindexes--)
	{
		Relation	ind = Irel[nindexes];

		index_close(ind, lockmode);
	}
	pfree(Irel);
}



bool vac_is_partial_index(Relation indrel)
{
	
	if (!indrel->rd_am->amindexnulls)
		return true;

	
	if (!heap_attisnull(indrel->rd_indextuple, Anum_pg_index_indpred))
		return true;

	return false;
}


static bool enough_space(VacPage vacpage, Size len)
{
	len = MAXALIGN(len);

	if (len > vacpage->free)
		return false;

	
	if (vacpage->offsets_used < vacpage->offsets_free)
		return true;

	
	if (len + sizeof(ItemIdData) <= vacpage->free)
		return true;

	return false;
}

static Size PageGetFreeSpaceWithFillFactor(Relation relation, Page page)
{
	Size		freespace = PageGetHeapFreeSpace(page);
	Size		targetfree;

	targetfree = RelationGetTargetPageFreeSpace(relation, HEAP_DEFAULT_FILLFACTOR);
	if (freespace > targetfree)
		return freespace - targetfree;
	else return 0;
}


void vacuum_delay_point(void)
{
	
	CHECK_FOR_INTERRUPTS();

	
	if (VacuumCostActive && !InterruptPending && VacuumCostBalance >= VacuumCostLimit)
	{
		int			msec;

		msec = VacuumCostDelay * VacuumCostBalance / VacuumCostLimit;
		if (msec > VacuumCostDelay * 4)
			msec = VacuumCostDelay * 4;

		pg_usleep(msec * 1000L);

		VacuumCostBalance = 0;

		
		AutoVacuumUpdateDelay();

		
		CHECK_FOR_INTERRUPTS();
	}
}
