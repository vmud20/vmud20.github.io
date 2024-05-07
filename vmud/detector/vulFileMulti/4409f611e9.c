


































int			DefaultXactIsoLevel = XACT_READ_COMMITTED;
int			XactIsoLevel;

bool		DefaultXactReadOnly = false;
bool		XactReadOnly;

bool		XactSyncCommit = true;

int			CommitDelay = 0;	
int			CommitSiblings = 5; 



typedef enum TransState {
	TRANS_DEFAULT,				 TRANS_START, TRANS_INPROGRESS, TRANS_COMMIT, TRANS_ABORT, TRANS_PREPARE } TransState;







typedef enum TBlockState {
	
	TBLOCK_DEFAULT,				 TBLOCK_STARTED,   TBLOCK_BEGIN, TBLOCK_INPROGRESS, TBLOCK_END, TBLOCK_ABORT, TBLOCK_ABORT_END, TBLOCK_ABORT_PENDING, TBLOCK_PREPARE,   TBLOCK_SUBBEGIN, TBLOCK_SUBINPROGRESS, TBLOCK_SUBEND, TBLOCK_SUBABORT, TBLOCK_SUBABORT_END, TBLOCK_SUBABORT_PENDING, TBLOCK_SUBRESTART, TBLOCK_SUBABORT_RESTART } TBlockState;






















typedef struct TransactionStateData {
	TransactionId transactionId;	
	SubTransactionId subTransactionId;	
	char	   *name;			
	int			savepointLevel; 
	TransState	state;			
	TBlockState blockState;		
	int			nestingLevel;	
	int			gucNestLevel;	
	MemoryContext curTransactionContext;		
	ResourceOwner curTransactionOwner;	
	List	   *childXids;		
	Oid			currentUser;	
	bool		prevXactReadOnly;		
	struct TransactionStateData *parent;		
} TransactionStateData;

typedef TransactionStateData *TransactionState;


static TransactionStateData TopTransactionStateData = {
	0,							 0, NULL, 0, TRANS_DEFAULT, TBLOCK_DEFAULT, 0, 0, NULL, NULL, NIL, 0, false, NULL };














static TransactionState CurrentTransactionState = &TopTransactionStateData;


static SubTransactionId currentSubTransactionId;
static CommandId currentCommandId;
static bool currentCommandIdUsed;


static TimestampTz xactStartTimestamp;
static TimestampTz stmtStartTimestamp;
static TimestampTz xactStopTimestamp;


static char *prepareGID;


static bool forceSyncCommit = false;


static MemoryContext TransactionAbortContext = NULL;


typedef struct XactCallbackItem {
	struct XactCallbackItem *next;
	XactCallback callback;
	void	   *arg;
} XactCallbackItem;

static XactCallbackItem *Xact_callbacks = NULL;


typedef struct SubXactCallbackItem {
	struct SubXactCallbackItem *next;
	SubXactCallback callback;
	void	   *arg;
} SubXactCallbackItem;

static SubXactCallbackItem *SubXact_callbacks = NULL;



static void AssignTransactionId(TransactionState s);
static void AbortTransaction(void);
static void AtAbort_Memory(void);
static void AtCleanup_Memory(void);
static void AtAbort_ResourceOwner(void);
static void AtCommit_LocalCache(void);
static void AtCommit_Memory(void);
static void AtStart_Cache(void);
static void AtStart_Memory(void);
static void AtStart_ResourceOwner(void);
static void CallXactCallbacks(XactEvent event);
static void CallSubXactCallbacks(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid);

static void CleanupTransaction(void);
static void CommitTransaction(void);
static TransactionId RecordTransactionAbort(bool isSubXact);
static void StartTransaction(void);

static void RecordSubTransactionCommit(void);
static void StartSubTransaction(void);
static void CommitSubTransaction(void);
static void AbortSubTransaction(void);
static void CleanupSubTransaction(void);
static void PushTransaction(void);
static void PopTransaction(void);

static void AtSubAbort_Memory(void);
static void AtSubCleanup_Memory(void);
static void AtSubAbort_ResourceOwner(void);
static void AtSubCommit_Memory(void);
static void AtSubStart_Memory(void);
static void AtSubStart_ResourceOwner(void);

static void ShowTransactionState(const char *str);
static void ShowTransactionStateRec(TransactionState state);
static const char *BlockStateAsString(TBlockState blockState);
static const char *TransStateAsString(TransState state);





bool IsTransactionState(void)
{
	TransactionState s = CurrentTransactionState;

	
	return (s->state == TRANS_INPROGRESS);
}


bool IsAbortedTransactionBlockState(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState == TBLOCK_ABORT || s->blockState == TBLOCK_SUBABORT)
		return true;

	return false;
}



TransactionId GetTopTransactionId(void)
{
	if (!TransactionIdIsValid(TopTransactionStateData.transactionId))
		AssignTransactionId(&TopTransactionStateData);
	return TopTransactionStateData.transactionId;
}


TransactionId GetTopTransactionIdIfAny(void)
{
	return TopTransactionStateData.transactionId;
}


TransactionId GetCurrentTransactionId(void)
{
	TransactionState s = CurrentTransactionState;

	if (!TransactionIdIsValid(s->transactionId))
		AssignTransactionId(s);
	return s->transactionId;
}


TransactionId GetCurrentTransactionIdIfAny(void)
{
	return CurrentTransactionState->transactionId;
}



static void AssignTransactionId(TransactionState s)
{
	bool		isSubXact = (s->parent != NULL);
	ResourceOwner currentOwner;

	
	Assert(!TransactionIdIsValid(s->transactionId));
	Assert(s->state == TRANS_INPROGRESS);

	
	if (isSubXact && !TransactionIdIsValid(s->parent->transactionId))
		AssignTransactionId(s->parent);

	
	s->transactionId = GetNewTransactionId(isSubXact);

	if (isSubXact)
		SubTransSetParent(s->transactionId, s->parent->transactionId);

	
	currentOwner = CurrentResourceOwner;
	PG_TRY();
	{
		CurrentResourceOwner = s->curTransactionOwner;
		XactLockTableInsert(s->transactionId);
	}
	PG_CATCH();
	{
		
		CurrentResourceOwner = currentOwner;
		PG_RE_THROW();
	}
	PG_END_TRY();
	CurrentResourceOwner = currentOwner;
}



SubTransactionId GetCurrentSubTransactionId(void)
{
	TransactionState s = CurrentTransactionState;

	return s->subTransactionId;
}



CommandId GetCurrentCommandId(bool used)
{
	
	if (used)
		currentCommandIdUsed = true;
	return currentCommandId;
}


TimestampTz GetCurrentTransactionStartTimestamp(void)
{
	return xactStartTimestamp;
}


TimestampTz GetCurrentStatementStartTimestamp(void)
{
	return stmtStartTimestamp;
}


TimestampTz GetCurrentTransactionStopTimestamp(void)
{
	if (xactStopTimestamp != 0)
		return xactStopTimestamp;
	return GetCurrentTimestamp();
}


void SetCurrentStatementStartTimestamp(void)
{
	stmtStartTimestamp = GetCurrentTimestamp();
}


static inline void SetCurrentTransactionStopTimestamp(void)
{
	xactStopTimestamp = GetCurrentTimestamp();
}


int GetCurrentTransactionNestLevel(void)
{
	TransactionState s = CurrentTransactionState;

	return s->nestingLevel;
}



bool TransactionIdIsCurrentTransactionId(TransactionId xid)
{
	TransactionState s;

	
	if (!TransactionIdIsNormal(xid))
		return false;

	
	for (s = CurrentTransactionState; s != NULL; s = s->parent)
	{
		ListCell   *cell;

		if (s->state == TRANS_ABORT)
			continue;
		if (!TransactionIdIsValid(s->transactionId))
			continue;			
		if (TransactionIdEquals(xid, s->transactionId))
			return true;
		foreach(cell, s->childXids)
		{
			if (TransactionIdEquals(xid, lfirst_xid(cell)))
				return true;
		}
	}

	return false;
}



void CommandCounterIncrement(void)
{
	
	if (currentCommandIdUsed)
	{
		currentCommandId += 1;
		if (currentCommandId == FirstCommandId)	
		{
			currentCommandId -= 1;
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("cannot have more than 2^32-1 commands in a transaction")));

		}
		currentCommandIdUsed = false;

		
		if (SerializableSnapshot)
			SerializableSnapshot->curcid = currentCommandId;
		if (LatestSnapshot)
			LatestSnapshot->curcid = currentCommandId;

		
		AtCommit_LocalCache();
	}

	
	AtStart_Cache();
}


void ForceSyncCommit(void)
{
	forceSyncCommit = true;
}





static void AtStart_Cache(void)
{
	AcceptInvalidationMessages();
}


static void AtStart_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (TransactionAbortContext == NULL)
		TransactionAbortContext = AllocSetContextCreate(TopMemoryContext, "TransactionAbortContext", 32 * 1024, 32 * 1024, 32 * 1024);





	
	Assert(TopTransactionContext == NULL);

	
	TopTransactionContext = AllocSetContextCreate(TopMemoryContext, "TopTransactionContext", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);





	
	CurTransactionContext = TopTransactionContext;
	s->curTransactionContext = CurTransactionContext;

	
	MemoryContextSwitchTo(CurTransactionContext);
}


static void AtStart_ResourceOwner(void)
{
	TransactionState s = CurrentTransactionState;

	
	Assert(TopTransactionResourceOwner == NULL);

	
	s->curTransactionOwner = ResourceOwnerCreate(NULL, "TopTransaction");

	TopTransactionResourceOwner = s->curTransactionOwner;
	CurTransactionResourceOwner = s->curTransactionOwner;
	CurrentResourceOwner = s->curTransactionOwner;
}




static void AtSubStart_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(CurTransactionContext != NULL);

	
	CurTransactionContext = AllocSetContextCreate(CurTransactionContext, "CurTransactionContext", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);



	s->curTransactionContext = CurTransactionContext;

	
	MemoryContextSwitchTo(CurTransactionContext);
}


static void AtSubStart_ResourceOwner(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parent != NULL);

	
	s->curTransactionOwner = ResourceOwnerCreate(s->parent->curTransactionOwner, "SubTransaction");


	CurTransactionResourceOwner = s->curTransactionOwner;
	CurrentResourceOwner = s->curTransactionOwner;
}




TransactionId RecordTransactionCommit(void)
{
	TransactionId xid = GetTopTransactionIdIfAny();
	bool		markXidCommitted = TransactionIdIsValid(xid);
	TransactionId latestXid = InvalidTransactionId;
	int			nrels;
	RelFileNode *rels;
	bool		haveNonTemp;
	int			nchildren;
	TransactionId *children;

	
	nrels = smgrGetPendingDeletes(true, &rels, &haveNonTemp);
	nchildren = xactGetCommittedChildren(&children);

	
	if (!markXidCommitted)
	{
		
		if (nrels != 0)
			elog(ERROR, "cannot commit a transaction that deleted files but has no xid");

		
		Assert(nchildren == 0);

		
		if (XactLastRecEnd.xrecoff == 0)
			goto cleanup;
	}
	else {
		
		XLogRecData rdata[3];
		int			lastrdata = 0;
		xl_xact_commit xlrec;

		
		BufmgrCommit();

		
		START_CRIT_SECTION();
		MyProc->inCommit = true;

		SetCurrentTransactionStopTimestamp();
		xlrec.xact_time = xactStopTimestamp;
		xlrec.nrels = nrels;
		xlrec.nsubxacts = nchildren;
		rdata[0].data = (char *) (&xlrec);
		rdata[0].len = MinSizeOfXactCommit;
		rdata[0].buffer = InvalidBuffer;
		
		if (nrels > 0)
		{
			rdata[0].next = &(rdata[1]);
			rdata[1].data = (char *) rels;
			rdata[1].len = nrels * sizeof(RelFileNode);
			rdata[1].buffer = InvalidBuffer;
			lastrdata = 1;
		}
		
		if (nchildren > 0)
		{
			rdata[lastrdata].next = &(rdata[2]);
			rdata[2].data = (char *) children;
			rdata[2].len = nchildren * sizeof(TransactionId);
			rdata[2].buffer = InvalidBuffer;
			lastrdata = 2;
		}
		rdata[lastrdata].next = NULL;

		(void) XLogInsert(RM_XACT_ID, XLOG_XACT_COMMIT, rdata);
	}

	
	if (XactSyncCommit || forceSyncCommit || haveNonTemp)
	{
		
		if (CommitDelay > 0 && enableFsync && CountActiveBackends() >= CommitSiblings)
			pg_usleep(CommitDelay);

		XLogFlush(XactLastRecEnd);

		
		if (markXidCommitted)
		{
			TransactionIdCommit(xid);
			
			TransactionIdCommitTree(nchildren, children);
		}
	}
	else {
		
		XLogSetAsyncCommitLSN(XactLastRecEnd);

		
		if (markXidCommitted)
		{
			TransactionIdAsyncCommit(xid, XactLastRecEnd);
			
			TransactionIdAsyncCommitTree(nchildren, children, XactLastRecEnd);
		}
	}

	
	if (markXidCommitted)
	{
		MyProc->inCommit = false;
		END_CRIT_SECTION();
	}

	
	latestXid = TransactionIdLatest(xid, nchildren, children);

	
	XactLastRecEnd.xrecoff = 0;

cleanup:
	
	if (rels)
		pfree(rels);
	if (children)
		pfree(children);

	return latestXid;
}



static void AtCommit_LocalCache(void)
{
	
	CommandEndInvalidationMessages();
}


static void AtCommit_Memory(void)
{
	
	MemoryContextSwitchTo(TopMemoryContext);

	
	Assert(TopTransactionContext != NULL);
	MemoryContextDelete(TopTransactionContext);
	TopTransactionContext = NULL;
	CurTransactionContext = NULL;
	CurrentTransactionState->curTransactionContext = NULL;
}




static void AtSubCommit_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parent != NULL);

	
	CurTransactionContext = s->parent->curTransactionContext;
	MemoryContextSwitchTo(CurTransactionContext);

	
	if (MemoryContextIsEmpty(s->curTransactionContext))
	{
		MemoryContextDelete(s->curTransactionContext);
		s->curTransactionContext = NULL;
	}
}


static void AtSubCommit_childXids(void)
{
	TransactionState s = CurrentTransactionState;
	MemoryContext old_cxt;

	Assert(s->parent != NULL);

	
	old_cxt = MemoryContextSwitchTo(TopTransactionContext);

	s->parent->childXids = lappend_xid(s->parent->childXids, s->transactionId);

	if (s->childXids != NIL)
	{
		s->parent->childXids = list_concat(s->parent->childXids, s->childXids);

		
		pfree(s->childXids);
		s->childXids = NIL;
	}

	MemoryContextSwitchTo(old_cxt);
}


static void RecordSubTransactionCommit(void)
{
	TransactionId xid = GetCurrentTransactionIdIfAny();

	
	if (TransactionIdIsValid(xid))
	{
		
		START_CRIT_SECTION();

		
		TransactionIdSubCommit(xid);

		END_CRIT_SECTION();
	}
}




static TransactionId RecordTransactionAbort(bool isSubXact)
{
	TransactionId xid = GetCurrentTransactionIdIfAny();
	TransactionId latestXid;
	int			nrels;
	RelFileNode *rels;
	int			nchildren;
	TransactionId *children;
	XLogRecData rdata[3];
	int			lastrdata = 0;
	xl_xact_abort xlrec;

	
	if (!TransactionIdIsValid(xid))
	{
		
		if (!isSubXact)
			XactLastRecEnd.xrecoff = 0;
		return InvalidTransactionId;
	}

	

	
	if (TransactionIdDidCommit(xid))
		elog(PANIC, "cannot abort transaction %u, it was already committed", xid);

	
	nrels = smgrGetPendingDeletes(false, &rels, NULL);
	nchildren = xactGetCommittedChildren(&children);

	
	START_CRIT_SECTION();

	
	if (isSubXact)
		xlrec.xact_time = GetCurrentTimestamp();
	else {
		SetCurrentTransactionStopTimestamp();
		xlrec.xact_time = xactStopTimestamp;
	}
	xlrec.nrels = nrels;
	xlrec.nsubxacts = nchildren;
	rdata[0].data = (char *) (&xlrec);
	rdata[0].len = MinSizeOfXactAbort;
	rdata[0].buffer = InvalidBuffer;
	
	if (nrels > 0)
	{
		rdata[0].next = &(rdata[1]);
		rdata[1].data = (char *) rels;
		rdata[1].len = nrels * sizeof(RelFileNode);
		rdata[1].buffer = InvalidBuffer;
		lastrdata = 1;
	}
	
	if (nchildren > 0)
	{
		rdata[lastrdata].next = &(rdata[2]);
		rdata[2].data = (char *) children;
		rdata[2].len = nchildren * sizeof(TransactionId);
		rdata[2].buffer = InvalidBuffer;
		lastrdata = 2;
	}
	rdata[lastrdata].next = NULL;

	(void) XLogInsert(RM_XACT_ID, XLOG_XACT_ABORT, rdata);

	
	TransactionIdAbort(xid);
	TransactionIdAbortTree(nchildren, children);

	END_CRIT_SECTION();

	
	latestXid = TransactionIdLatest(xid, nchildren, children);

	
	if (isSubXact)
		XidCacheRemoveRunningXids(xid, nchildren, children, latestXid);

	
	if (!isSubXact)
		XactLastRecEnd.xrecoff = 0;

	
	if (rels)
		pfree(rels);
	if (children)
		pfree(children);

	return latestXid;
}


static void AtAbort_Memory(void)
{
	
	if (TransactionAbortContext != NULL)
		MemoryContextSwitchTo(TransactionAbortContext);
	else MemoryContextSwitchTo(TopMemoryContext);
}


static void AtSubAbort_Memory(void)
{
	Assert(TransactionAbortContext != NULL);

	MemoryContextSwitchTo(TransactionAbortContext);
}



static void AtAbort_ResourceOwner(void)
{
	
	CurrentResourceOwner = TopTransactionResourceOwner;
}


static void AtSubAbort_ResourceOwner(void)
{
	TransactionState s = CurrentTransactionState;

	
	CurrentResourceOwner = s->curTransactionOwner;
}



static void AtSubAbort_childXids(void)
{
	TransactionState s = CurrentTransactionState;

	
	list_free(s->childXids);
	s->childXids = NIL;
}




static void AtCleanup_Memory(void)
{
	Assert(CurrentTransactionState->parent == NULL);

	
	MemoryContextSwitchTo(TopMemoryContext);

	
	if (TransactionAbortContext != NULL)
		MemoryContextResetAndDeleteChildren(TransactionAbortContext);

	
	if (TopTransactionContext != NULL)
		MemoryContextDelete(TopTransactionContext);
	TopTransactionContext = NULL;
	CurTransactionContext = NULL;
	CurrentTransactionState->curTransactionContext = NULL;
}





static void AtSubCleanup_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parent != NULL);

	
	MemoryContextSwitchTo(s->parent->curTransactionContext);
	CurTransactionContext = s->parent->curTransactionContext;

	
	if (TransactionAbortContext != NULL)
		MemoryContextResetAndDeleteChildren(TransactionAbortContext);

	
	if (s->curTransactionContext)
		MemoryContextDelete(s->curTransactionContext);
	s->curTransactionContext = NULL;
}




static void StartTransaction(void)
{
	TransactionState s;
	VirtualTransactionId vxid;

	
	s = &TopTransactionStateData;
	CurrentTransactionState = s;

	
	if (s->state != TRANS_DEFAULT)
		elog(WARNING, "StartTransaction while in %s state", TransStateAsString(s->state));

	
	s->state = TRANS_START;
	s->transactionId = InvalidTransactionId;	

	
	FreeXactSnapshot();
	XactIsoLevel = DefaultXactIsoLevel;
	XactReadOnly = DefaultXactReadOnly;
	forceSyncCommit = false;

	
	s->subTransactionId = TopSubTransactionId;
	currentSubTransactionId = TopSubTransactionId;
	currentCommandId = FirstCommandId;
	currentCommandIdUsed = false;

	
	AtStart_Memory();
	AtStart_ResourceOwner();

	
	vxid.backendId = MyBackendId;
	vxid.localTransactionId = GetNextLocalTransactionId();

	
	VirtualXactLockTableInsert(vxid);

	
	Assert(MyProc->backendId == vxid.backendId);
	MyProc->lxid = vxid.localTransactionId;

	PG_TRACE1(transaction__start, vxid.localTransactionId);

	
	xactStartTimestamp = stmtStartTimestamp;
	xactStopTimestamp = 0;
	pgstat_report_xact_timestamp(xactStartTimestamp);

	
	s->nestingLevel = 1;
	s->gucNestLevel = 1;
	s->childXids = NIL;

	

	
	AtStart_GUC();
	AtStart_Inval();
	AtStart_Cache();
	AfterTriggerBeginXact();

	
	s->state = TRANS_INPROGRESS;

	ShowTransactionState("StartTransaction");
}



static void CommitTransaction(void)
{
	TransactionState s = CurrentTransactionState;
	TransactionId latestXid;

	ShowTransactionState("CommitTransaction");

	
	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "CommitTransaction while in %s state", TransStateAsString(s->state));
	Assert(s->parent == NULL);

	
	for (;;)
	{
		
		AfterTriggerFireDeferred();

		
		if (!CommitHoldablePortals())
			break;
	}

	
	AfterTriggerEndXact(true);

	
	AtCommit_Portals();

	
	PreCommit_on_commit_actions();

	
	AtEOXact_LargeObject(true);

	
	AtCommit_Notify();

	
	AtEOXact_UpdateFlatFiles(true);

	
	HOLD_INTERRUPTS();

	
	s->state = TRANS_COMMIT;

	
	latestXid = RecordTransactionCommit();

	PG_TRACE1(transaction__commit, MyProc->lxid);

	
	ProcArrayEndTransaction(MyProc, latestXid);

	

	CallXactCallbacks(XACT_EVENT_COMMIT);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_BEFORE_LOCKS, true, true);


	
	AtEOXact_Buffers(true);

	
	AtEOXact_RelationCache(true);

	
	AtEOXact_Inval(true);

	
	smgrDoPendingDeletes(true);

	AtEOXact_MultiXact();

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_LOCKS, true, true);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_AFTER_LOCKS, true, true);


	
	AtEOXact_CatCache(true);

	AtEOXact_GUC(true, 1);
	AtEOXact_SPI(true);
	AtEOXact_on_commit_actions(true);
	AtEOXact_Namespace(true);
	
	AtEOXact_Files();
	AtEOXact_ComboCid();
	AtEOXact_HashTables(true);
	AtEOXact_PgStat(true);
	pgstat_report_xact_timestamp(0);

	CurrentResourceOwner = NULL;
	ResourceOwnerDelete(TopTransactionResourceOwner);
	s->curTransactionOwner = NULL;
	CurTransactionResourceOwner = NULL;
	TopTransactionResourceOwner = NULL;

	AtCommit_Memory();

	s->transactionId = InvalidTransactionId;
	s->subTransactionId = InvalidSubTransactionId;
	s->nestingLevel = 0;
	s->gucNestLevel = 0;
	s->childXids = NIL;

	
	s->state = TRANS_DEFAULT;

	RESUME_INTERRUPTS();
}



static void PrepareTransaction(void)
{
	TransactionState s = CurrentTransactionState;
	TransactionId xid = GetCurrentTransactionId();
	GlobalTransaction gxact;
	TimestampTz prepared_at;

	ShowTransactionState("PrepareTransaction");

	
	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "PrepareTransaction while in %s state", TransStateAsString(s->state));
	Assert(s->parent == NULL);

	
	for (;;)
	{
		
		AfterTriggerFireDeferred();

		
		if (!PrepareHoldablePortals())
			break;
	}

	
	AfterTriggerEndXact(true);

	
	AtCommit_Portals();

	
	PreCommit_on_commit_actions();

	
	AtEOXact_LargeObject(true);

	

	
	HOLD_INTERRUPTS();

	
	s->state = TRANS_PREPARE;

	prepared_at = GetCurrentTimestamp();

	
	BufmgrCommit();

	
	gxact = MarkAsPreparing(xid, prepareGID, prepared_at, GetUserId(), MyDatabaseId);
	prepareGID = NULL;

	
	StartPrepare(gxact);

	AtPrepare_Notify();
	AtPrepare_UpdateFlatFiles();
	AtPrepare_Inval();
	AtPrepare_Locks();
	AtPrepare_PgStat();

	
	EndPrepare(gxact);

	

	
	XactLastRecEnd.xrecoff = 0;

	
	ProcArrayClearTransaction(MyProc);

	

	CallXactCallbacks(XACT_EVENT_PREPARE);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_BEFORE_LOCKS, true, true);


	
	AtEOXact_Buffers(true);

	
	AtEOXact_RelationCache(true);

	

	PostPrepare_PgStat();

	PostPrepare_Inval();

	PostPrepare_smgr();

	AtEOXact_MultiXact();

	PostPrepare_Locks(xid);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_LOCKS, true, true);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_AFTER_LOCKS, true, true);


	
	AtEOXact_CatCache(true);

	
	AtEOXact_GUC(true, 1);
	AtEOXact_SPI(true);
	AtEOXact_on_commit_actions(true);
	AtEOXact_Namespace(true);
	
	AtEOXact_Files();
	AtEOXact_ComboCid();
	AtEOXact_HashTables(true);
	

	CurrentResourceOwner = NULL;
	ResourceOwnerDelete(TopTransactionResourceOwner);
	s->curTransactionOwner = NULL;
	CurTransactionResourceOwner = NULL;
	TopTransactionResourceOwner = NULL;

	AtCommit_Memory();

	s->transactionId = InvalidTransactionId;
	s->subTransactionId = InvalidSubTransactionId;
	s->nestingLevel = 0;
	s->gucNestLevel = 0;
	s->childXids = NIL;

	
	s->state = TRANS_DEFAULT;

	RESUME_INTERRUPTS();
}



static void AbortTransaction(void)
{
	TransactionState s = CurrentTransactionState;
	TransactionId latestXid;

	
	HOLD_INTERRUPTS();

	
	AtAbort_Memory();
	AtAbort_ResourceOwner();

	
	LWLockReleaseAll();

	
	AbortBufferIO();
	UnlockBuffers();

	
	LockWaitCancel();

	
	if (s->state != TRANS_INPROGRESS && s->state != TRANS_PREPARE)
		elog(WARNING, "AbortTransaction while in %s state", TransStateAsString(s->state));
	Assert(s->parent == NULL);

	
	s->state = TRANS_ABORT;

	
	AtAbort_UserId();

	
	AfterTriggerEndXact(false);
	AtAbort_Portals();
	AtEOXact_LargeObject(false);	
	AtAbort_Notify();
	AtEOXact_UpdateFlatFiles(false);

	
	latestXid = RecordTransactionAbort(false);

	PG_TRACE1(transaction__abort, MyProc->lxid);

	
	ProcArrayEndTransaction(MyProc, latestXid);

	

	CallXactCallbacks(XACT_EVENT_ABORT);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_BEFORE_LOCKS, false, true);

	AtEOXact_Buffers(false);
	AtEOXact_RelationCache(false);
	AtEOXact_Inval(false);
	smgrDoPendingDeletes(false);
	AtEOXact_MultiXact();
	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_LOCKS, false, true);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_AFTER_LOCKS, false, true);

	AtEOXact_CatCache(false);

	AtEOXact_GUC(false, 1);
	AtEOXact_SPI(false);
	AtEOXact_on_commit_actions(false);
	AtEOXact_Namespace(false);
	smgrabort();
	AtEOXact_Files();
	AtEOXact_ComboCid();
	AtEOXact_HashTables(false);
	AtEOXact_PgStat(false);
	pgstat_report_xact_timestamp(0);

	
	RESUME_INTERRUPTS();
}


static void CleanupTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (s->state != TRANS_ABORT)
		elog(FATAL, "CleanupTransaction: unexpected state %s", TransStateAsString(s->state));

	
	AtCleanup_Portals();		

	CurrentResourceOwner = NULL;	
	if (TopTransactionResourceOwner)
		ResourceOwnerDelete(TopTransactionResourceOwner);
	s->curTransactionOwner = NULL;
	CurTransactionResourceOwner = NULL;
	TopTransactionResourceOwner = NULL;

	AtCleanup_Memory();			

	s->transactionId = InvalidTransactionId;
	s->subTransactionId = InvalidSubTransactionId;
	s->nestingLevel = 0;
	s->gucNestLevel = 0;
	s->childXids = NIL;

	
	s->state = TRANS_DEFAULT;
}


void StartTransactionCommand(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_DEFAULT:
			StartTransaction();
			s->blockState = TBLOCK_STARTED;
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
			break;

			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(ERROR, "StartTransactionCommand: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	
	Assert(CurTransactionContext != NULL);
	MemoryContextSwitchTo(CurTransactionContext);
}


void CommitTransactionCommand(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_DEFAULT:
			elog(FATAL, "CommitTransactionCommand: unexpected state %s", BlockStateAsString(s->blockState));
			break;

			
		case TBLOCK_STARTED:
			CommitTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_BEGIN:
			s->blockState = TBLOCK_INPROGRESS;
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
			CommandCounterIncrement();
			break;

			
		case TBLOCK_END:
			CommitTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_ABORT_END:
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_ABORT_PENDING:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_PREPARE:
			PrepareTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_SUBBEGIN:
			StartSubTransaction();
			s->blockState = TBLOCK_SUBINPROGRESS;
			break;

			
		case TBLOCK_SUBEND:
			do {
				CommitSubTransaction();
				s = CurrentTransactionState;	
			} while (s->blockState == TBLOCK_SUBEND);
			
			if (s->blockState == TBLOCK_END)
			{
				Assert(s->parent == NULL);
				CommitTransaction();
				s->blockState = TBLOCK_DEFAULT;
			}
			else if (s->blockState == TBLOCK_PREPARE)
			{
				Assert(s->parent == NULL);
				PrepareTransaction();
				s->blockState = TBLOCK_DEFAULT;
			}
			else {
				Assert(s->blockState == TBLOCK_INPROGRESS || s->blockState == TBLOCK_SUBINPROGRESS);
			}
			break;

			
		case TBLOCK_SUBABORT_END:
			CleanupSubTransaction();
			CommitTransactionCommand();
			break;

			
		case TBLOCK_SUBABORT_PENDING:
			AbortSubTransaction();
			CleanupSubTransaction();
			CommitTransactionCommand();
			break;

			
		case TBLOCK_SUBRESTART:
			{
				char	   *name;
				int			savepointLevel;

				
				name = s->name;
				s->name = NULL;
				savepointLevel = s->savepointLevel;

				AbortSubTransaction();
				CleanupSubTransaction();

				DefineSavepoint(NULL);
				s = CurrentTransactionState;	
				s->name = name;
				s->savepointLevel = savepointLevel;

				
				AssertState(s->blockState == TBLOCK_SUBBEGIN);
				StartSubTransaction();
				s->blockState = TBLOCK_SUBINPROGRESS;
			}
			break;

			
		case TBLOCK_SUBABORT_RESTART:
			{
				char	   *name;
				int			savepointLevel;

				
				name = s->name;
				s->name = NULL;
				savepointLevel = s->savepointLevel;

				CleanupSubTransaction();

				DefineSavepoint(NULL);
				s = CurrentTransactionState;	
				s->name = name;
				s->savepointLevel = savepointLevel;

				
				AssertState(s->blockState == TBLOCK_SUBBEGIN);
				StartSubTransaction();
				s->blockState = TBLOCK_SUBINPROGRESS;
			}
			break;
	}
}


void AbortCurrentTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
		case TBLOCK_DEFAULT:
			if (s->state == TRANS_DEFAULT)
			{
				
			}
			else {
				
				if (s->state == TRANS_START)
					s->state = TRANS_INPROGRESS;
				AbortTransaction();
				CleanupTransaction();
			}
			break;

			
		case TBLOCK_STARTED:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_BEGIN:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_INPROGRESS:
			AbortTransaction();
			s->blockState = TBLOCK_ABORT;
			
			break;

			
		case TBLOCK_END:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_ABORT_END:
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_ABORT_PENDING:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_PREPARE:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_SUBINPROGRESS:
			AbortSubTransaction();
			s->blockState = TBLOCK_SUBABORT;
			break;

			
		case TBLOCK_SUBBEGIN:
		case TBLOCK_SUBEND:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
			AbortSubTransaction();
			CleanupSubTransaction();
			AbortCurrentTransaction();
			break;

			
		case TBLOCK_SUBABORT_END:
		case TBLOCK_SUBABORT_RESTART:
			CleanupSubTransaction();
			AbortCurrentTransaction();
			break;
	}
}


void PreventTransactionChain(bool isTopLevel, const char *stmtType)
{
	
	if (IsTransactionBlock())
		ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),  errmsg("%s cannot run inside a transaction block", stmtType)));




	
	if (IsSubTransaction())
		ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),  errmsg("%s cannot run inside a subtransaction", stmtType)));




	
	if (!isTopLevel)
		ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),  errmsg("%s cannot be executed from a function or multi-command string", stmtType)));




	
	if (CurrentTransactionState->blockState != TBLOCK_DEFAULT && CurrentTransactionState->blockState != TBLOCK_STARTED)
		elog(FATAL, "cannot prevent transaction chain");
	
}


void RequireTransactionChain(bool isTopLevel, const char *stmtType)
{
	
	if (IsTransactionBlock())
		return;

	
	if (IsSubTransaction())
		return;

	
	if (!isTopLevel)
		return;

	ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", stmtType)));



}


bool IsInTransactionChain(bool isTopLevel)
{
	
	if (IsTransactionBlock())
		return true;

	if (IsSubTransaction())
		return true;

	if (!isTopLevel)
		return true;

	if (CurrentTransactionState->blockState != TBLOCK_DEFAULT && CurrentTransactionState->blockState != TBLOCK_STARTED)
		return true;

	return false;
}



void RegisterXactCallback(XactCallback callback, void *arg)
{
	XactCallbackItem *item;

	item = (XactCallbackItem *)
		MemoryContextAlloc(TopMemoryContext, sizeof(XactCallbackItem));
	item->callback = callback;
	item->arg = arg;
	item->next = Xact_callbacks;
	Xact_callbacks = item;
}

void UnregisterXactCallback(XactCallback callback, void *arg)
{
	XactCallbackItem *item;
	XactCallbackItem *prev;

	prev = NULL;
	for (item = Xact_callbacks; item; prev = item, item = item->next)
	{
		if (item->callback == callback && item->arg == arg)
		{
			if (prev)
				prev->next = item->next;
			else Xact_callbacks = item->next;
			pfree(item);
			break;
		}
	}
}

static void CallXactCallbacks(XactEvent event)
{
	XactCallbackItem *item;

	for (item = Xact_callbacks; item; item = item->next)
		(*item->callback) (event, item->arg);
}



void RegisterSubXactCallback(SubXactCallback callback, void *arg)
{
	SubXactCallbackItem *item;

	item = (SubXactCallbackItem *)
		MemoryContextAlloc(TopMemoryContext, sizeof(SubXactCallbackItem));
	item->callback = callback;
	item->arg = arg;
	item->next = SubXact_callbacks;
	SubXact_callbacks = item;
}

void UnregisterSubXactCallback(SubXactCallback callback, void *arg)
{
	SubXactCallbackItem *item;
	SubXactCallbackItem *prev;

	prev = NULL;
	for (item = SubXact_callbacks; item; prev = item, item = item->next)
	{
		if (item->callback == callback && item->arg == arg)
		{
			if (prev)
				prev->next = item->next;
			else SubXact_callbacks = item->next;
			pfree(item);
			break;
		}
	}
}

static void CallSubXactCallbacks(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid)


{
	SubXactCallbackItem *item;

	for (item = SubXact_callbacks; item; item = item->next)
		(*item->callback) (event, mySubid, parentSubid, item->arg);
}





void BeginTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_STARTED:
			s->blockState = TBLOCK_BEGIN;
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			ereport(WARNING, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION), errmsg("there is already a transaction in progress")));

			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "BeginTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}
}


bool PrepareTransactionBlock(char *gid)
{
	TransactionState s;
	bool		result;

	
	result = EndTransactionBlock();

	
	if (result)
	{
		s = CurrentTransactionState;

		while (s->parent != NULL)
			s = s->parent;

		if (s->blockState == TBLOCK_END)
		{
			
			prepareGID = MemoryContextStrdup(TopTransactionContext, gid);

			s->blockState = TBLOCK_PREPARE;
		}
		else {
			
			Assert(s->blockState == TBLOCK_STARTED);
			
			result = false;
		}
	}

	return result;
}


bool EndTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;
	bool		result = false;

	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
			s->blockState = TBLOCK_END;
			result = true;
			break;

			
		case TBLOCK_ABORT:
			s->blockState = TBLOCK_ABORT_END;
			break;

			
		case TBLOCK_SUBINPROGRESS:
			while (s->parent != NULL)
			{
				if (s->blockState == TBLOCK_SUBINPROGRESS)
					s->blockState = TBLOCK_SUBEND;
				else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

				s = s->parent;
			}
			if (s->blockState == TBLOCK_INPROGRESS)
				s->blockState = TBLOCK_END;
			else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

			result = true;
			break;

			
		case TBLOCK_SUBABORT:
			while (s->parent != NULL)
			{
				if (s->blockState == TBLOCK_SUBINPROGRESS)
					s->blockState = TBLOCK_SUBABORT_PENDING;
				else if (s->blockState == TBLOCK_SUBABORT)
					s->blockState = TBLOCK_SUBABORT_END;
				else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

				s = s->parent;
			}
			if (s->blockState == TBLOCK_INPROGRESS)
				s->blockState = TBLOCK_ABORT_PENDING;
			else if (s->blockState == TBLOCK_ABORT)
				s->blockState = TBLOCK_ABORT_END;
			else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

			break;

			
		case TBLOCK_STARTED:
			ereport(WARNING, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION), errmsg("there is no transaction in progress")));

			result = true;
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	return result;
}


void UserAbortTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
			s->blockState = TBLOCK_ABORT_PENDING;
			break;

			
		case TBLOCK_ABORT:
			s->blockState = TBLOCK_ABORT_END;
			break;

			
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_SUBABORT:
			while (s->parent != NULL)
			{
				if (s->blockState == TBLOCK_SUBINPROGRESS)
					s->blockState = TBLOCK_SUBABORT_PENDING;
				else if (s->blockState == TBLOCK_SUBABORT)
					s->blockState = TBLOCK_SUBABORT_END;
				else elog(FATAL, "UserAbortTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

				s = s->parent;
			}
			if (s->blockState == TBLOCK_INPROGRESS)
				s->blockState = TBLOCK_ABORT_PENDING;
			else if (s->blockState == TBLOCK_ABORT)
				s->blockState = TBLOCK_ABORT_END;
			else elog(FATAL, "UserAbortTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

			break;

			
		case TBLOCK_STARTED:
			ereport(NOTICE, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION), errmsg("there is no transaction in progress")));

			s->blockState = TBLOCK_ABORT_PENDING;
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "UserAbortTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}
}


void DefineSavepoint(char *name)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
		case TBLOCK_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
			
			PushTransaction();
			s = CurrentTransactionState;		

			
			if (name)
				s->name = MemoryContextStrdup(TopTransactionContext, name);
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "DefineSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}
}


void ReleaseSavepoint(List *options)
{
	TransactionState s = CurrentTransactionState;
	TransactionState target, xact;
	ListCell   *cell;
	char	   *name = NULL;

	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
			ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("no such savepoint")));

			break;

			
		case TBLOCK_SUBINPROGRESS:
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "ReleaseSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	foreach(cell, options)
	{
		DefElem    *elem = lfirst(cell);

		if (strcmp(elem->defname, "savepoint_name") == 0)
			name = strVal(elem->arg);
	}

	Assert(PointerIsValid(name));

	for (target = s; PointerIsValid(target); target = target->parent)
	{
		if (PointerIsValid(target->name) && strcmp(target->name, name) == 0)
			break;
	}

	if (!PointerIsValid(target))
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("no such savepoint")));


	
	if (target->savepointLevel != s->savepointLevel)
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("no such savepoint")));


	
	xact = CurrentTransactionState;
	for (;;)
	{
		Assert(xact->blockState == TBLOCK_SUBINPROGRESS);
		xact->blockState = TBLOCK_SUBEND;
		if (xact == target)
			break;
		xact = xact->parent;
		Assert(PointerIsValid(xact));
	}
}


void RollbackToSavepoint(List *options)
{
	TransactionState s = CurrentTransactionState;
	TransactionState target, xact;
	ListCell   *cell;
	char	   *name = NULL;

	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
		case TBLOCK_ABORT:
			ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("no such savepoint")));

			break;

			
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "RollbackToSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	foreach(cell, options)
	{
		DefElem    *elem = lfirst(cell);

		if (strcmp(elem->defname, "savepoint_name") == 0)
			name = strVal(elem->arg);
	}

	Assert(PointerIsValid(name));

	for (target = s; PointerIsValid(target); target = target->parent)
	{
		if (PointerIsValid(target->name) && strcmp(target->name, name) == 0)
			break;
	}

	if (!PointerIsValid(target))
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("no such savepoint")));


	
	if (target->savepointLevel != s->savepointLevel)
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("no such savepoint")));


	
	xact = CurrentTransactionState;
	for (;;)
	{
		if (xact == target)
			break;
		if (xact->blockState == TBLOCK_SUBINPROGRESS)
			xact->blockState = TBLOCK_SUBABORT_PENDING;
		else if (xact->blockState == TBLOCK_SUBABORT)
			xact->blockState = TBLOCK_SUBABORT_END;
		else elog(FATAL, "RollbackToSavepoint: unexpected state %s", BlockStateAsString(xact->blockState));

		xact = xact->parent;
		Assert(PointerIsValid(xact));
	}

	
	if (xact->blockState == TBLOCK_SUBINPROGRESS)
		xact->blockState = TBLOCK_SUBRESTART;
	else if (xact->blockState == TBLOCK_SUBABORT)
		xact->blockState = TBLOCK_SUBABORT_RESTART;
	else elog(FATAL, "RollbackToSavepoint: unexpected state %s", BlockStateAsString(xact->blockState));

}


void BeginInternalSubTransaction(char *name)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
		case TBLOCK_STARTED:
		case TBLOCK_INPROGRESS:
		case TBLOCK_END:
		case TBLOCK_PREPARE:
		case TBLOCK_SUBINPROGRESS:
			
			PushTransaction();
			s = CurrentTransactionState;		

			
			if (name)
				s->name = MemoryContextStrdup(TopTransactionContext, name);
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
			elog(FATAL, "BeginInternalSubTransaction: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	CommitTransactionCommand();
	StartTransactionCommand();
}


void ReleaseCurrentSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState != TBLOCK_SUBINPROGRESS)
		elog(ERROR, "ReleaseCurrentSubTransaction: unexpected state %s", BlockStateAsString(s->blockState));
	Assert(s->state == TRANS_INPROGRESS);
	MemoryContextSwitchTo(CurTransactionContext);
	CommitSubTransaction();
	s = CurrentTransactionState;	
	Assert(s->state == TRANS_INPROGRESS);
}


void RollbackAndReleaseCurrentSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_INPROGRESS:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_ABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "RollbackAndReleaseCurrentSubTransaction: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	
	if (s->blockState == TBLOCK_SUBINPROGRESS)
		AbortSubTransaction();

	
	CleanupSubTransaction();

	s = CurrentTransactionState;	
	AssertState(s->blockState == TBLOCK_SUBINPROGRESS || s->blockState == TBLOCK_INPROGRESS || s->blockState == TBLOCK_STARTED);

}


void AbortOutOfAnyTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	do {
		switch (s->blockState)
		{
			case TBLOCK_DEFAULT:
				
				break;
			case TBLOCK_STARTED:
			case TBLOCK_BEGIN:
			case TBLOCK_INPROGRESS:
			case TBLOCK_END:
			case TBLOCK_ABORT_PENDING:
			case TBLOCK_PREPARE:
				
				AbortTransaction();
				CleanupTransaction();
				s->blockState = TBLOCK_DEFAULT;
				break;
			case TBLOCK_ABORT:
			case TBLOCK_ABORT_END:
				
				CleanupTransaction();
				s->blockState = TBLOCK_DEFAULT;
				break;

				
			case TBLOCK_SUBBEGIN:
			case TBLOCK_SUBINPROGRESS:
			case TBLOCK_SUBEND:
			case TBLOCK_SUBABORT_PENDING:
			case TBLOCK_SUBRESTART:
				AbortSubTransaction();
				CleanupSubTransaction();
				s = CurrentTransactionState;	
				break;

			case TBLOCK_SUBABORT:
			case TBLOCK_SUBABORT_END:
			case TBLOCK_SUBABORT_RESTART:
				
				CleanupSubTransaction();
				s = CurrentTransactionState;	
				break;
		}
	} while (s->blockState != TBLOCK_DEFAULT);

	
	Assert(s->parent == NULL);
}


bool IsTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState == TBLOCK_DEFAULT || s->blockState == TBLOCK_STARTED)
		return false;

	return true;
}


bool IsTransactionOrTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState == TBLOCK_DEFAULT)
		return false;

	return true;
}


char TransactionBlockStatusCode(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
			return 'I';			
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_END:
		case TBLOCK_SUBEND:
		case TBLOCK_PREPARE:
			return 'T';			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
			return 'E';			
	}

	
	elog(FATAL, "invalid transaction block state: %s", BlockStateAsString(s->blockState));
	return 0;					
}


bool IsSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->nestingLevel >= 2)
		return true;

	return false;
}


static void StartSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->state != TRANS_DEFAULT)
		elog(WARNING, "StartSubTransaction while in %s state", TransStateAsString(s->state));

	s->state = TRANS_START;

	
	AtSubStart_Memory();
	AtSubStart_ResourceOwner();
	AtSubStart_Inval();
	AtSubStart_Notify();
	AfterTriggerBeginSubXact();

	s->state = TRANS_INPROGRESS;

	
	CallSubXactCallbacks(SUBXACT_EVENT_START_SUB, s->subTransactionId, s->parent->subTransactionId);

	ShowTransactionState("StartSubTransaction");
}


static void CommitSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	ShowTransactionState("CommitSubTransaction");

	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "CommitSubTransaction while in %s state", TransStateAsString(s->state));

	

	s->state = TRANS_COMMIT;

	
	CommandCounterIncrement();

	
	RecordSubTransactionCommit();

	
	if (TransactionIdIsValid(s->transactionId))
		AtSubCommit_childXids();
	AfterTriggerEndSubXact(true);
	AtSubCommit_Portals(s->subTransactionId, s->parent->subTransactionId, s->parent->curTransactionOwner);

	AtEOSubXact_LargeObject(true, s->subTransactionId, s->parent->subTransactionId);
	AtSubCommit_Notify();
	AtEOSubXact_UpdateFlatFiles(true, s->subTransactionId, s->parent->subTransactionId);

	CallSubXactCallbacks(SUBXACT_EVENT_COMMIT_SUB, s->subTransactionId, s->parent->subTransactionId);

	ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_BEFORE_LOCKS, true, false);

	AtEOSubXact_RelationCache(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_Inval(true);
	AtSubCommit_smgr();

	
	CurrentResourceOwner = s->curTransactionOwner;
	if (TransactionIdIsValid(s->transactionId))
		XactLockTableDelete(s->transactionId);

	ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_LOCKS, true, false);

	ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_AFTER_LOCKS, true, false);


	AtEOXact_GUC(true, s->gucNestLevel);
	AtEOSubXact_SPI(true, s->subTransactionId);
	AtEOSubXact_on_commit_actions(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_Namespace(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_Files(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_HashTables(true, s->nestingLevel);
	AtEOSubXact_PgStat(true, s->nestingLevel);

	
	XactReadOnly = s->prevXactReadOnly;

	CurrentResourceOwner = s->parent->curTransactionOwner;
	CurTransactionResourceOwner = s->parent->curTransactionOwner;
	ResourceOwnerDelete(s->curTransactionOwner);
	s->curTransactionOwner = NULL;

	AtSubCommit_Memory();

	s->state = TRANS_DEFAULT;

	PopTransaction();
}


static void AbortSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	HOLD_INTERRUPTS();

	
	AtSubAbort_Memory();
	AtSubAbort_ResourceOwner();

	
	LWLockReleaseAll();

	AbortBufferIO();
	UnlockBuffers();

	LockWaitCancel();

	
	ShowTransactionState("AbortSubTransaction");

	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "AbortSubTransaction while in %s state", TransStateAsString(s->state));

	s->state = TRANS_ABORT;

	
	if (s->curTransactionOwner)
	{
		AfterTriggerEndSubXact(false);
		AtSubAbort_Portals(s->subTransactionId, s->parent->subTransactionId, s->parent->curTransactionOwner);

		AtEOSubXact_LargeObject(false, s->subTransactionId, s->parent->subTransactionId);
		AtSubAbort_Notify();
		AtEOSubXact_UpdateFlatFiles(false, s->subTransactionId, s->parent->subTransactionId);

		
		(void) RecordTransactionAbort(true);

		
		if (TransactionIdIsValid(s->transactionId))
			AtSubAbort_childXids();

		CallSubXactCallbacks(SUBXACT_EVENT_ABORT_SUB, s->subTransactionId, s->parent->subTransactionId);

		ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_BEFORE_LOCKS, false, false);

		AtEOSubXact_RelationCache(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_Inval(false);
		AtSubAbort_smgr();
		ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_LOCKS, false, false);

		ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_AFTER_LOCKS, false, false);


		AtEOXact_GUC(false, s->gucNestLevel);
		AtEOSubXact_SPI(false, s->subTransactionId);
		AtEOSubXact_on_commit_actions(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_Namespace(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_Files(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_HashTables(false, s->nestingLevel);
		AtEOSubXact_PgStat(false, s->nestingLevel);
	}

	
	SetUserId(s->currentUser);

	
	XactReadOnly = s->prevXactReadOnly;

	RESUME_INTERRUPTS();
}


static void CleanupSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	ShowTransactionState("CleanupSubTransaction");

	if (s->state != TRANS_ABORT)
		elog(WARNING, "CleanupSubTransaction while in %s state", TransStateAsString(s->state));

	AtSubCleanup_Portals(s->subTransactionId);

	CurrentResourceOwner = s->parent->curTransactionOwner;
	CurTransactionResourceOwner = s->parent->curTransactionOwner;
	if (s->curTransactionOwner)
		ResourceOwnerDelete(s->curTransactionOwner);
	s->curTransactionOwner = NULL;

	AtSubCleanup_Memory();

	s->state = TRANS_DEFAULT;

	PopTransaction();
}


static void PushTransaction(void)
{
	TransactionState p = CurrentTransactionState;
	TransactionState s;
	Oid			currentUser;

	
	currentUser = GetUserId();

	
	s = (TransactionState)
		MemoryContextAllocZero(TopTransactionContext, sizeof(TransactionStateData));

	
	currentSubTransactionId += 1;
	if (currentSubTransactionId == InvalidSubTransactionId)
	{
		currentSubTransactionId -= 1;
		pfree(s);
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("cannot have more than 2^32-1 subtransactions in a transaction")));

	}

	
	s->transactionId = InvalidTransactionId;	
	s->subTransactionId = currentSubTransactionId;
	s->parent = p;
	s->nestingLevel = p->nestingLevel + 1;
	s->gucNestLevel = NewGUCNestLevel();
	s->savepointLevel = p->savepointLevel;
	s->state = TRANS_DEFAULT;
	s->blockState = TBLOCK_SUBBEGIN;
	s->currentUser = currentUser;
	s->prevXactReadOnly = XactReadOnly;

	CurrentTransactionState = s;

	
}


static void PopTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->state != TRANS_DEFAULT)
		elog(WARNING, "PopTransaction while in %s state", TransStateAsString(s->state));

	if (s->parent == NULL)
		elog(FATAL, "PopTransaction with no parent");

	CurrentTransactionState = s->parent;

	
	CurTransactionContext = s->parent->curTransactionContext;
	MemoryContextSwitchTo(CurTransactionContext);

	
	CurTransactionResourceOwner = s->parent->curTransactionOwner;
	CurrentResourceOwner = s->parent->curTransactionOwner;

	
	if (s->name)
		pfree(s->name);
	pfree(s);
}


static void ShowTransactionState(const char *str)
{
	
	if (log_min_messages <= DEBUG3 || client_min_messages <= DEBUG3)
	{
		elog(DEBUG3, "%s", str);
		ShowTransactionStateRec(CurrentTransactionState);
	}
}


static void ShowTransactionStateRec(TransactionState s)
{
	if (s->parent)
		ShowTransactionStateRec(s->parent);

	
	ereport(DEBUG3, (errmsg_internal("name: %s; blockState: %13s; state: %7s, xid/subid/cid: %u/%u/%u%s, nestlvl: %d, children: %s", PointerIsValid(s->name) ? s->name : "unnamed", BlockStateAsString(s->blockState), TransStateAsString(s->state), (unsigned int) s->transactionId, (unsigned int) s->subTransactionId, (unsigned int) currentCommandId, currentCommandIdUsed ? " (used)" : "", s->nestingLevel, nodeToString(s->childXids))));









}


static const char * BlockStateAsString(TBlockState blockState)
{
	switch (blockState)
	{
		case TBLOCK_DEFAULT:
			return "DEFAULT";
		case TBLOCK_STARTED:
			return "STARTED";
		case TBLOCK_BEGIN:
			return "BEGIN";
		case TBLOCK_INPROGRESS:
			return "INPROGRESS";
		case TBLOCK_END:
			return "END";
		case TBLOCK_ABORT:
			return "ABORT";
		case TBLOCK_ABORT_END:
			return "ABORT END";
		case TBLOCK_ABORT_PENDING:
			return "ABORT PEND";
		case TBLOCK_PREPARE:
			return "PREPARE";
		case TBLOCK_SUBBEGIN:
			return "SUB BEGIN";
		case TBLOCK_SUBINPROGRESS:
			return "SUB INPROGRS";
		case TBLOCK_SUBEND:
			return "SUB END";
		case TBLOCK_SUBABORT:
			return "SUB ABORT";
		case TBLOCK_SUBABORT_END:
			return "SUB ABORT END";
		case TBLOCK_SUBABORT_PENDING:
			return "SUB ABRT PEND";
		case TBLOCK_SUBRESTART:
			return "SUB RESTART";
		case TBLOCK_SUBABORT_RESTART:
			return "SUB AB RESTRT";
	}
	return "UNRECOGNIZED";
}


static const char * TransStateAsString(TransState state)
{
	switch (state)
	{
		case TRANS_DEFAULT:
			return "DEFAULT";
		case TRANS_START:
			return "START";
		case TRANS_INPROGRESS:
			return "INPROGR";
		case TRANS_COMMIT:
			return "COMMIT";
		case TRANS_ABORT:
			return "ABORT";
		case TRANS_PREPARE:
			return "PREPARE";
	}
	return "UNRECOGNIZED";
}


int xactGetCommittedChildren(TransactionId **ptr)
{
	TransactionState s = CurrentTransactionState;
	int			nchildren;
	TransactionId *children;
	ListCell   *p;

	nchildren = list_length(s->childXids);
	if (nchildren == 0)
	{
		*ptr = NULL;
		return 0;
	}

	children = (TransactionId *) palloc(nchildren * sizeof(TransactionId));
	*ptr = children;

	foreach(p, s->childXids)
	{
		TransactionId child = lfirst_xid(p);

		*children++ = child;
	}

	return nchildren;
}



static void xact_redo_commit(xl_xact_commit *xlrec, TransactionId xid)
{
	TransactionId *sub_xids;
	TransactionId max_xid;
	int			i;

	TransactionIdCommit(xid);

	
	sub_xids = (TransactionId *) &(xlrec->xnodes[xlrec->nrels]);
	TransactionIdCommitTree(xlrec->nsubxacts, sub_xids);

	
	max_xid = xid;
	for (i = 0; i < xlrec->nsubxacts; i++)
	{
		if (TransactionIdPrecedes(max_xid, sub_xids[i]))
			max_xid = sub_xids[i];
	}
	if (TransactionIdFollowsOrEquals(max_xid, ShmemVariableCache->nextXid))
	{
		ShmemVariableCache->nextXid = max_xid;
		TransactionIdAdvance(ShmemVariableCache->nextXid);
	}

	
	for (i = 0; i < xlrec->nrels; i++)
	{
		XLogDropRelation(xlrec->xnodes[i]);
		smgrdounlink(smgropen(xlrec->xnodes[i]), false, true);
	}
}

static void xact_redo_abort(xl_xact_abort *xlrec, TransactionId xid)
{
	TransactionId *sub_xids;
	TransactionId max_xid;
	int			i;

	TransactionIdAbort(xid);

	
	sub_xids = (TransactionId *) &(xlrec->xnodes[xlrec->nrels]);
	TransactionIdAbortTree(xlrec->nsubxacts, sub_xids);

	
	max_xid = xid;
	for (i = 0; i < xlrec->nsubxacts; i++)
	{
		if (TransactionIdPrecedes(max_xid, sub_xids[i]))
			max_xid = sub_xids[i];
	}
	if (TransactionIdFollowsOrEquals(max_xid, ShmemVariableCache->nextXid))
	{
		ShmemVariableCache->nextXid = max_xid;
		TransactionIdAdvance(ShmemVariableCache->nextXid);
	}

	
	for (i = 0; i < xlrec->nrels; i++)
	{
		XLogDropRelation(xlrec->xnodes[i]);
		smgrdounlink(smgropen(xlrec->xnodes[i]), false, true);
	}
}

void xact_redo(XLogRecPtr lsn, XLogRecord *record)
{
	uint8		info = record->xl_info & ~XLR_INFO_MASK;

	if (info == XLOG_XACT_COMMIT)
	{
		xl_xact_commit *xlrec = (xl_xact_commit *) XLogRecGetData(record);

		xact_redo_commit(xlrec, record->xl_xid);
	}
	else if (info == XLOG_XACT_ABORT)
	{
		xl_xact_abort *xlrec = (xl_xact_abort *) XLogRecGetData(record);

		xact_redo_abort(xlrec, record->xl_xid);
	}
	else if (info == XLOG_XACT_PREPARE)
	{
		
		RecreateTwoPhaseFile(record->xl_xid, XLogRecGetData(record), record->xl_len);
	}
	else if (info == XLOG_XACT_COMMIT_PREPARED)
	{
		xl_xact_commit_prepared *xlrec = (xl_xact_commit_prepared *) XLogRecGetData(record);

		xact_redo_commit(&xlrec->crec, xlrec->xid);
		RemoveTwoPhaseFile(xlrec->xid, false);
	}
	else if (info == XLOG_XACT_ABORT_PREPARED)
	{
		xl_xact_abort_prepared *xlrec = (xl_xact_abort_prepared *) XLogRecGetData(record);

		xact_redo_abort(&xlrec->arec, xlrec->xid);
		RemoveTwoPhaseFile(xlrec->xid, false);
	}
	else elog(PANIC, "xact_redo: unknown op code %u", info);
}

static void xact_desc_commit(StringInfo buf, xl_xact_commit *xlrec)
{
	int			i;

	appendStringInfoString(buf, timestamptz_to_str(xlrec->xact_time));
	if (xlrec->nrels > 0)
	{
		appendStringInfo(buf, "; rels:");
		for (i = 0; i < xlrec->nrels; i++)
		{
			RelFileNode rnode = xlrec->xnodes[i];

			appendStringInfo(buf, " %u/%u/%u", rnode.spcNode, rnode.dbNode, rnode.relNode);
		}
	}
	if (xlrec->nsubxacts > 0)
	{
		TransactionId *xacts = (TransactionId *)
		&xlrec->xnodes[xlrec->nrels];

		appendStringInfo(buf, "; subxacts:");
		for (i = 0; i < xlrec->nsubxacts; i++)
			appendStringInfo(buf, " %u", xacts[i]);
	}
}

static void xact_desc_abort(StringInfo buf, xl_xact_abort *xlrec)
{
	int			i;

	appendStringInfoString(buf, timestamptz_to_str(xlrec->xact_time));
	if (xlrec->nrels > 0)
	{
		appendStringInfo(buf, "; rels:");
		for (i = 0; i < xlrec->nrels; i++)
		{
			RelFileNode rnode = xlrec->xnodes[i];

			appendStringInfo(buf, " %u/%u/%u", rnode.spcNode, rnode.dbNode, rnode.relNode);
		}
	}
	if (xlrec->nsubxacts > 0)
	{
		TransactionId *xacts = (TransactionId *)
		&xlrec->xnodes[xlrec->nrels];

		appendStringInfo(buf, "; subxacts:");
		for (i = 0; i < xlrec->nsubxacts; i++)
			appendStringInfo(buf, " %u", xacts[i]);
	}
}

void xact_desc(StringInfo buf, uint8 xl_info, char *rec)
{
	uint8		info = xl_info & ~XLR_INFO_MASK;

	if (info == XLOG_XACT_COMMIT)
	{
		xl_xact_commit *xlrec = (xl_xact_commit *) rec;

		appendStringInfo(buf, "commit: ");
		xact_desc_commit(buf, xlrec);
	}
	else if (info == XLOG_XACT_ABORT)
	{
		xl_xact_abort *xlrec = (xl_xact_abort *) rec;

		appendStringInfo(buf, "abort: ");
		xact_desc_abort(buf, xlrec);
	}
	else if (info == XLOG_XACT_PREPARE)
	{
		appendStringInfo(buf, "prepare");
	}
	else if (info == XLOG_XACT_COMMIT_PREPARED)
	{
		xl_xact_commit_prepared *xlrec = (xl_xact_commit_prepared *) rec;

		appendStringInfo(buf, "commit %u: ", xlrec->xid);
		xact_desc_commit(buf, &xlrec->crec);
	}
	else if (info == XLOG_XACT_ABORT_PREPARED)
	{
		xl_xact_abort_prepared *xlrec = (xl_xact_abort_prepared *) rec;

		appendStringInfo(buf, "abort %u: ", xlrec->xid);
		xact_desc_abort(buf, &xlrec->arec);
	}
	else appendStringInfo(buf, "UNKNOWN");
}
