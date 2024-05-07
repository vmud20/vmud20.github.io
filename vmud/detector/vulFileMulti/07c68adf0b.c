

















































extern bool bootstrap_data_checksums;









int			CheckPointSegments = 3;
int			wal_keep_segments = 0;
int			XLOGbuffers = -1;
int			XLogArchiveTimeout = 0;
bool		XLogArchiveMode = false;
char	   *XLogArchiveCommand = NULL;
bool		EnableHotStandby = false;
bool		fullPageWrites = true;
bool		log_checkpoints = false;
int			sync_method = DEFAULT_SYNC_METHOD;
int			wal_level = WAL_LEVEL_MINIMAL;
int			CommitDelay = 0;	
int			CommitSiblings = 5; 


bool		XLOG_DEBUG = false;







const struct config_enum_entry sync_method_options[] = {
	{"fsync", SYNC_METHOD_FSYNC, false},  {"fsync_writethrough", SYNC_METHOD_FSYNC_WRITETHROUGH, false},   {"fdatasync", SYNC_METHOD_FDATASYNC, false},   {"open_sync", SYNC_METHOD_OPEN, false},   {"open_datasync", SYNC_METHOD_OPEN_DSYNC, false},  {NULL, 0, false}












};


CheckpointStatsData CheckpointStats;


TimeLineID	ThisTimeLineID = 0;


bool		InRecovery = false;


HotStandbyState standbyState = STANDBY_DISABLED;

static XLogRecPtr LastRec;


static XLogRecPtr receivedUpto = 0;
static TimeLineID receiveTLI = 0;


static bool lastFullPageWrites;


static bool LocalRecoveryInProgress = true;


static bool LocalHotStandbyActive = false;


static int	LocalXLogInsertAllowed = -1;


bool ArchiveRecoveryRequested = false;
bool InArchiveRecovery = false;


static bool restoredFromArchive = false;


char *recoveryRestoreCommand = NULL;
static char *recoveryEndCommand = NULL;
static char *archiveCleanupCommand = NULL;
static RecoveryTargetType recoveryTarget = RECOVERY_TARGET_UNSET;
static bool recoveryTargetInclusive = true;
static bool recoveryPauseAtTarget = true;
static TransactionId recoveryTargetXid;
static TimestampTz recoveryTargetTime;
static char *recoveryTargetName;


static bool StandbyModeRequested = false;
static char *PrimaryConnInfo = NULL;
static char *TriggerFile = NULL;


bool StandbyMode = false;


static bool fast_promote = false;


static TransactionId recoveryStopXid;
static TimestampTz recoveryStopTime;
static char recoveryStopName[MAXFNAMELEN];
static bool recoveryStopAfter;


static TimeLineID recoveryTargetTLI;
static bool recoveryTargetIsLatest = false;
static List *expectedTLEs;
static TimeLineID curFileTLI;


static XLogRecPtr ProcLastRecPtr = InvalidXLogRecPtr;

XLogRecPtr	XactLastRecEnd = InvalidXLogRecPtr;


static XLogRecPtr RedoRecPtr;


static XLogRecPtr RedoStartLSN = InvalidXLogRecPtr;



typedef struct XLogwrtRqst {
	XLogRecPtr	Write;			
	XLogRecPtr	Flush;			
} XLogwrtRqst;

typedef struct XLogwrtResult {
	XLogRecPtr	Write;			
	XLogRecPtr	Flush;			
} XLogwrtResult;


typedef struct XLogCtlInsert {
	XLogRecPtr	PrevRecord;		
	int			curridx;		
	XLogPageHeader currpage;	
	char	   *currpos;		
	XLogRecPtr	RedoRecPtr;		
	bool		forcePageWrites;	

	
	bool		fullPageWrites;

	
	bool		exclusiveBackup;
	int			nonExclusiveBackups;
	XLogRecPtr	lastBackupStart;
} XLogCtlInsert;


typedef struct XLogCtlWrite {
	int			curridx;		
	pg_time_t	lastSegSwitchTime;		
} XLogCtlWrite;


typedef struct XLogCtlData {
	
	XLogCtlInsert Insert;

	
	XLogwrtRqst LogwrtRqst;
	uint32		ckptXidEpoch;	
	TransactionId ckptXid;
	XLogRecPtr	asyncXactLSN;	
	XLogSegNo	lastRemovedSegNo; 

	
	XLogRecPtr  unloggedLSN;
	slock_t		ulsn_lck;

	
	XLogCtlWrite Write;

	
	XLogwrtResult LogwrtResult;

	
	char	   *pages;			
	XLogRecPtr *xlblocks;		
	int			XLogCacheBlck;	

	
	TimeLineID	ThisTimeLineID;
	TimeLineID	PrevTimeLineID;

	
	char		archiveCleanupCommand[MAXPGPATH];

	
	bool		SharedRecoveryInProgress;

	
	bool		SharedHotStandbyActive;

	
	bool		WalWriterSleeping;

	
	Latch		recoveryWakeupLatch;

	
	XLogRecPtr	lastCheckPointRecPtr;
	CheckPoint	lastCheckPoint;

	
	XLogRecPtr	lastReplayedEndRecPtr;
	TimeLineID	lastReplayedTLI;
	XLogRecPtr	replayEndRecPtr;
	TimeLineID	replayEndTLI;
	
	TimestampTz recoveryLastXTime;
	
	TimeLineID	RecoveryTargetTLI;

	
	TimestampTz currentChunkStartTime;
	
	bool		recoveryPause;

	
	XLogRecPtr	lastFpwDisableRecPtr;

	slock_t		info_lck;		
} XLogCtlData;

static XLogCtlData *XLogCtl = NULL;


static ControlFileData *ControlFile = NULL;














static XLogwrtResult LogwrtResult = {0, 0};


typedef enum {
	XLOG_FROM_ANY = 0,		 XLOG_FROM_ARCHIVE, XLOG_FROM_PG_XLOG, XLOG_FROM_STREAM, } XLogSource;





static const char *xlogSourceNames[] = { "any", "archive", "pg_xlog", "stream" };


static int	openLogFile = -1;
static XLogSegNo openLogSegNo = 0;
static uint32 openLogOff = 0;


static int	readFile = -1;
static XLogSegNo readSegNo = 0;
static uint32 readOff = 0;
static uint32 readLen = 0;
static XLogSource readSource = 0;		


static XLogSource currentSource = 0;	
static bool	lastSourceFailed = false;

typedef struct XLogPageReadPrivate {
	int			emode;
	bool		fetching_ckpt;	
	bool		randAccess;
} XLogPageReadPrivate;


static TimestampTz XLogReceiptTime = 0;
static XLogSource XLogReceiptSource = 0;	


static XLogRecPtr ReadRecPtr;	
static XLogRecPtr EndRecPtr;	

static XLogRecPtr minRecoveryPoint;		
static TimeLineID minRecoveryPointTLI;
static bool updateMinRecoveryPoint = true;


bool		reachedConsistency = false;

static bool InRedo = false;


static bool bgwriterLaunched = false;


static void readRecoveryCommandFile(void);
static void exitArchiveRecovery(TimeLineID endTLI, XLogSegNo endLogSegNo);
static bool recoveryStopsHere(XLogRecord *record, bool *includeThis);
static void recoveryPausesHere(void);
static void SetLatestXTime(TimestampTz xtime);
static void SetCurrentChunkStartTime(TimestampTz xtime);
static void CheckRequiredParameterValues(void);
static void XLogReportParameters(void);
static void checkTimeLineSwitch(XLogRecPtr lsn, TimeLineID newTLI, TimeLineID prevTLI);
static void LocalSetXLogInsertAllowed(void);
static void CreateEndOfRecoveryRecord(void);
static void CheckPointGuts(XLogRecPtr checkPointRedo, int flags);
static void KeepLogSeg(XLogRecPtr recptr, XLogSegNo *logSegNo);

static bool XLogCheckBuffer(XLogRecData *rdata, bool doPageWrites, XLogRecPtr *lsn, BkpBlock *bkpb);
static bool AdvanceXLInsertBuffer(bool new_segment);
static bool XLogCheckpointNeeded(XLogSegNo new_segno);
static void XLogWrite(XLogwrtRqst WriteRqst, bool flexible, bool xlog_switch);
static bool InstallXLogFileSegment(XLogSegNo *segno, char *tmppath, bool find_free, int *max_advance, bool use_lock);

static int XLogFileRead(XLogSegNo segno, int emode, TimeLineID tli, int source, bool notexistOk);
static int XLogFileReadAnyTLI(XLogSegNo segno, int emode, int source);
static int XLogPageRead(XLogReaderState *xlogreader, XLogRecPtr targetPagePtr, int reqLen, XLogRecPtr targetRecPtr, char *readBuf, TimeLineID *readTLI);

static bool WaitForWALToBecomeAvailable(XLogRecPtr RecPtr, bool randAccess, bool fetching_ckpt, XLogRecPtr tliRecPtr);
static int	emode_for_corrupt_record(int emode, XLogRecPtr RecPtr);
static void XLogFileClose(void);
static void PreallocXlogFiles(XLogRecPtr endptr);
static void RemoveOldXlogFiles(XLogSegNo segno, XLogRecPtr endptr);
static void UpdateLastRemovedPtr(char *filename);
static void ValidateXLOGDirectoryStructure(void);
static void CleanupBackupHistory(void);
static void UpdateMinRecoveryPoint(XLogRecPtr lsn, bool force);
static XLogRecord *ReadRecord(XLogReaderState *xlogreader, XLogRecPtr RecPtr, int emode, bool fetching_ckpt);
static void CheckRecoveryConsistency(void);
static XLogRecord *ReadCheckpointRecord(XLogReaderState *xlogreader, XLogRecPtr RecPtr, int whichChkpti, bool report);
static bool rescanLatestTimeLine(void);
static void WriteControlFile(void);
static void ReadControlFile(void);
static char *str_time(pg_time_t tnow);
static bool CheckForStandbyTrigger(void);


static void xlog_outrec(StringInfo buf, XLogRecord *record);

static void pg_start_backup_callback(int code, Datum arg);
static bool read_backup_label(XLogRecPtr *checkPointLoc, bool *backupEndRequired, bool *backupFromStandby);
static void rm_redo_error_callback(void *arg);
static int	get_sync_bit(int method);



XLogRecPtr XLogInsert(RmgrId rmid, uint8 info, XLogRecData *rdata)
{
	XLogCtlInsert *Insert = &XLogCtl->Insert;
	XLogRecPtr	RecPtr;
	XLogRecPtr	WriteRqst;
	uint32		freespace;
	int			curridx;
	XLogRecData *rdt;
	XLogRecData *rdt_lastnormal;
	Buffer		dtbuf[XLR_MAX_BKP_BLOCKS];
	bool		dtbuf_bkp[XLR_MAX_BKP_BLOCKS];
	BkpBlock	dtbuf_xlg[XLR_MAX_BKP_BLOCKS];
	XLogRecPtr	dtbuf_lsn[XLR_MAX_BKP_BLOCKS];
	XLogRecData dtbuf_rdt1[XLR_MAX_BKP_BLOCKS];
	XLogRecData dtbuf_rdt2[XLR_MAX_BKP_BLOCKS];
	XLogRecData dtbuf_rdt3[XLR_MAX_BKP_BLOCKS];
	XLogRecData hdr_rdt;
	pg_crc32	rdata_crc;
	uint32		len, write_len;
	unsigned	i;
	bool		updrqst;
	bool		doPageWrites;
	bool		isLogSwitch = (rmid == RM_XLOG_ID && info == XLOG_SWITCH);
	bool		isHint = (rmid == RM_XLOG_ID && info == XLOG_HINT);
	uint8		info_orig = info;
	static XLogRecord *rechdr;

	if (rechdr == NULL)
	{
		rechdr = malloc(SizeOfXLogRecord);
		if (rechdr == NULL)
			elog(ERROR, "out of memory");
		MemSet(rechdr, 0, SizeOfXLogRecord);
	}

	
	if (!XLogInsertAllowed())
		elog(ERROR, "cannot make new WAL entries during recovery");

	
	if (info & XLR_INFO_MASK)
		elog(PANIC, "invalid xlog info mask %02X", info);

	TRACE_POSTGRESQL_XLOG_INSERT(rmid, info);

	
	if (IsBootstrapProcessingMode() && rmid != RM_XLOG_ID)
	{
		RecPtr = SizeOfXLogLongPHD;		
		return RecPtr;
	}

	
begin:;
	for (i = 0; i < XLR_MAX_BKP_BLOCKS; i++)
	{
		dtbuf[i] = InvalidBuffer;
		dtbuf_bkp[i] = false;
	}

	
	doPageWrites = Insert->fullPageWrites || Insert->forcePageWrites;

	len = 0;
	for (rdt = rdata;;)
	{
		if (rdt->buffer == InvalidBuffer)
		{
			
			len += rdt->len;
		}
		else {
			
			for (i = 0; i < XLR_MAX_BKP_BLOCKS; i++)
			{
				if (rdt->buffer == dtbuf[i])
				{
					
					if (dtbuf_bkp[i])
					{
						rdt->data = NULL;
						rdt->len = 0;
					}
					else if (rdt->data)
						len += rdt->len;
					break;
				}
				if (dtbuf[i] == InvalidBuffer)
				{
					
					dtbuf[i] = rdt->buffer;
					if (XLogCheckBuffer(rdt, doPageWrites, &(dtbuf_lsn[i]), &(dtbuf_xlg[i])))
					{
						dtbuf_bkp[i] = true;
						rdt->data = NULL;
						rdt->len = 0;
					}
					else if (rdt->data)
						len += rdt->len;
					break;
				}
			}
			if (i >= XLR_MAX_BKP_BLOCKS)
				elog(PANIC, "can backup at most %d blocks per xlog record", XLR_MAX_BKP_BLOCKS);
		}
		
		if (rdt->next == NULL)
			break;
		rdt = rdt->next;
	}

	
	if (len == 0 && !isLogSwitch)
		elog(PANIC, "invalid xlog record length %u", len);

	
	rdt_lastnormal = rdt;
	write_len = len;
	for (i = 0; i < XLR_MAX_BKP_BLOCKS; i++)
	{
		BkpBlock   *bkpb;
		char	   *page;

		if (!dtbuf_bkp[i])
			continue;

		info |= XLR_BKP_BLOCK(i);

		bkpb = &(dtbuf_xlg[i]);
		page = (char *) BufferGetBlock(dtbuf[i]);

		rdt->next = &(dtbuf_rdt1[i]);
		rdt = rdt->next;

		rdt->data = (char *) bkpb;
		rdt->len = sizeof(BkpBlock);
		write_len += sizeof(BkpBlock);

		rdt->next = &(dtbuf_rdt2[i]);
		rdt = rdt->next;

		if (bkpb->hole_length == 0)
		{
			rdt->data = page;
			rdt->len = BLCKSZ;
			write_len += BLCKSZ;
			rdt->next = NULL;
		}
		else {
			
			rdt->data = page;
			rdt->len = bkpb->hole_offset;
			write_len += bkpb->hole_offset;

			rdt->next = &(dtbuf_rdt3[i]);
			rdt = rdt->next;

			rdt->data = page + (bkpb->hole_offset + bkpb->hole_length);
			rdt->len = BLCKSZ - (bkpb->hole_offset + bkpb->hole_length);
			write_len += rdt->len;
			rdt->next = NULL;
		}
	}

	
	INIT_CRC32(rdata_crc);
	for (rdt = rdata; rdt != NULL; rdt = rdt->next)
		COMP_CRC32(rdata_crc, rdt->data, rdt->len);

	
	rechdr->xl_xid = GetCurrentTransactionIdIfAny();
	rechdr->xl_tot_len = SizeOfXLogRecord + write_len;
	rechdr->xl_len = len;		
	rechdr->xl_info = info;
	rechdr->xl_rmid = rmid;

	hdr_rdt.next = rdata;
	hdr_rdt.data = (char *) rechdr;
	hdr_rdt.len = SizeOfXLogRecord;

	write_len += SizeOfXLogRecord;

	START_CRIT_SECTION();

	
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);

	
	if (RedoRecPtr != Insert->RedoRecPtr)
	{
		Assert(RedoRecPtr < Insert->RedoRecPtr);
		RedoRecPtr = Insert->RedoRecPtr;

		if (doPageWrites)
		{
			for (i = 0; i < XLR_MAX_BKP_BLOCKS; i++)
			{
				if (dtbuf[i] == InvalidBuffer)
					continue;
				if (dtbuf_bkp[i] == false && dtbuf_lsn[i] <= RedoRecPtr)
				{
					
					LWLockRelease(WALInsertLock);
					END_CRIT_SECTION();
					rdt_lastnormal->next = NULL;
					info = info_orig;
					goto begin;
				}
			}
		}
	}

	
	if ((Insert->fullPageWrites || Insert->forcePageWrites) && !doPageWrites)
	{
		
		LWLockRelease(WALInsertLock);
		END_CRIT_SECTION();
		rdt_lastnormal->next = NULL;
		info = info_orig;
		goto begin;
	}

	
	if (isHint && !(info & XLR_BKP_BLOCK_MASK))
	{
		LWLockRelease(WALInsertLock);
		END_CRIT_SECTION();
		return InvalidXLogRecPtr;
	}

	
	updrqst = false;
	freespace = INSERT_FREESPACE(Insert);
	if (freespace == 0)
	{
		updrqst = AdvanceXLInsertBuffer(false);
		freespace = INSERT_FREESPACE(Insert);
	}

	
	curridx = Insert->curridx;
	INSERT_RECPTR(RecPtr, Insert, curridx);

	
	if (isLogSwitch && (RecPtr % XLogSegSize) == SizeOfXLogLongPHD)
	{
		
		LWLockRelease(WALInsertLock);

		RecPtr -= SizeOfXLogLongPHD;

		LWLockAcquire(WALWriteLock, LW_EXCLUSIVE);
		LogwrtResult = XLogCtl->LogwrtResult;
		if (LogwrtResult.Flush < RecPtr)
		{
			XLogwrtRqst FlushRqst;

			FlushRqst.Write = RecPtr;
			FlushRqst.Flush = RecPtr;
			XLogWrite(FlushRqst, false, false);
		}
		LWLockRelease(WALWriteLock);

		END_CRIT_SECTION();

		
		WalSndWakeupProcessRequests();
		return RecPtr;
	}

	
	rechdr->xl_prev = Insert->PrevRecord;

	
	COMP_CRC32(rdata_crc, (char *) rechdr, offsetof(XLogRecord, xl_crc));
	FIN_CRC32(rdata_crc);
	rechdr->xl_crc = rdata_crc;


	if (XLOG_DEBUG)
	{
		StringInfoData buf;

		initStringInfo(&buf);
		appendStringInfo(&buf, "INSERT @ %X/%X: ", (uint32) (RecPtr >> 32), (uint32) RecPtr);
		xlog_outrec(&buf, rechdr);
		if (rdata->data != NULL)
		{
			appendStringInfo(&buf, " - ");
			RmgrTable[rechdr->xl_rmid].rm_desc(&buf, rechdr->xl_info, rdata->data);
		}
		elog(LOG, "%s", buf.data);
		pfree(buf.data);
	}


	
	ProcLastRecPtr = RecPtr;
	Insert->PrevRecord = RecPtr;

	
	rdata = &hdr_rdt;
	while (write_len)
	{
		while (rdata->data == NULL)
			rdata = rdata->next;

		if (freespace > 0)
		{
			if (rdata->len > freespace)
			{
				memcpy(Insert->currpos, rdata->data, freespace);
				rdata->data += freespace;
				rdata->len -= freespace;
				write_len -= freespace;
			}
			else {
				memcpy(Insert->currpos, rdata->data, rdata->len);
				freespace -= rdata->len;
				write_len -= rdata->len;
				Insert->currpos += rdata->len;
				rdata = rdata->next;
				continue;
			}
		}

		
		updrqst = AdvanceXLInsertBuffer(false);
		curridx = Insert->curridx;
		
		Insert->currpage->xlp_info |= XLP_FIRST_IS_CONTRECORD;
		Insert->currpage->xlp_rem_len = write_len;
		freespace = INSERT_FREESPACE(Insert);
	}

	
	Insert->currpos = (char *) Insert->currpage + MAXALIGN(Insert->currpos - (char *) Insert->currpage);
	freespace = INSERT_FREESPACE(Insert);

	
	INSERT_RECPTR(RecPtr, Insert, curridx);

	
	if (isLogSwitch)
	{
		XLogwrtRqst FlushRqst;
		XLogRecPtr	OldSegEnd;

		TRACE_POSTGRESQL_XLOG_SWITCH();

		LWLockAcquire(WALWriteLock, LW_EXCLUSIVE);

		
		WriteRqst = XLogCtl->xlblocks[curridx];
		FlushRqst.Write = WriteRqst;
		FlushRqst.Flush = WriteRqst;
		XLogWrite(FlushRqst, false, true);

		
		
		(void) AdvanceXLInsertBuffer(true);

		
		curridx = Insert->curridx;
		Assert(curridx == XLogCtl->Write.curridx);

		
		OldSegEnd = XLogCtl->xlblocks[curridx];
		OldSegEnd -= XLOG_BLCKSZ;

		
		LogwrtResult.Write = OldSegEnd;
		LogwrtResult.Flush = OldSegEnd;

		
		{
			
			volatile XLogCtlData *xlogctl = XLogCtl;

			SpinLockAcquire(&xlogctl->info_lck);
			xlogctl->LogwrtResult = LogwrtResult;
			if (xlogctl->LogwrtRqst.Write < LogwrtResult.Write)
				xlogctl->LogwrtRqst.Write = LogwrtResult.Write;
			if (xlogctl->LogwrtRqst.Flush < LogwrtResult.Flush)
				xlogctl->LogwrtRqst.Flush = LogwrtResult.Flush;
			SpinLockRelease(&xlogctl->info_lck);
		}

		LWLockRelease(WALWriteLock);

		updrqst = false;		
	}
	else {
		

		
		if (freespace == 0)
		{
			
			updrqst = true;
		}
		else {
			
			curridx = PrevBufIdx(curridx);
		}
		WriteRqst = XLogCtl->xlblocks[curridx];
	}

	LWLockRelease(WALInsertLock);

	if (updrqst)
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		
		if (xlogctl->LogwrtRqst.Write < WriteRqst)
			xlogctl->LogwrtRqst.Write = WriteRqst;
		
		LogwrtResult = xlogctl->LogwrtResult;
		SpinLockRelease(&xlogctl->info_lck);
	}

	XactLastRecEnd = RecPtr;

	END_CRIT_SECTION();

	
	WalSndWakeupProcessRequests();

	return RecPtr;
}


static bool XLogCheckBuffer(XLogRecData *rdata, bool doPageWrites, XLogRecPtr *lsn, BkpBlock *bkpb)

{
	Page		page;

	page = BufferGetPage(rdata->buffer);

	
	*lsn = BufferGetLSNAtomic(rdata->buffer);

	if (doPageWrites && *lsn <= RedoRecPtr)
	{
		
		BufferGetTag(rdata->buffer, &bkpb->node, &bkpb->fork, &bkpb->block);

		if (rdata->buffer_std)
		{
			
			uint16		lower = ((PageHeader) page)->pd_lower;
			uint16		upper = ((PageHeader) page)->pd_upper;

			if (lower >= SizeOfPageHeaderData && upper > lower && upper <= BLCKSZ)

			{
				bkpb->hole_offset = lower;
				bkpb->hole_length = upper - lower;
			}
			else {
				
				bkpb->hole_offset = 0;
				bkpb->hole_length = 0;
			}
		}
		else {
			
			bkpb->hole_offset = 0;
			bkpb->hole_length = 0;
		}

		return true;			
	}

	return false;				
}


static bool AdvanceXLInsertBuffer(bool new_segment)
{
	XLogCtlInsert *Insert = &XLogCtl->Insert;
	int			nextidx = NextBufIdx(Insert->curridx);
	bool		update_needed = true;
	XLogRecPtr	OldPageRqstPtr;
	XLogwrtRqst WriteRqst;
	XLogRecPtr	NewPageEndPtr;
	XLogRecPtr	NewPageBeginPtr;
	XLogPageHeader NewPage;

	
	OldPageRqstPtr = XLogCtl->xlblocks[nextidx];
	if (LogwrtResult.Write < OldPageRqstPtr)
	{
		
		XLogRecPtr	FinishedPageRqstPtr;

		FinishedPageRqstPtr = XLogCtl->xlblocks[Insert->curridx];

		
		{
			
			volatile XLogCtlData *xlogctl = XLogCtl;

			SpinLockAcquire(&xlogctl->info_lck);
			if (xlogctl->LogwrtRqst.Write < FinishedPageRqstPtr)
				xlogctl->LogwrtRqst.Write = FinishedPageRqstPtr;
			LogwrtResult = xlogctl->LogwrtResult;
			SpinLockRelease(&xlogctl->info_lck);
		}

		update_needed = false;	

		
		if (LogwrtResult.Write < OldPageRqstPtr)
		{
			
			LWLockAcquire(WALWriteLock, LW_EXCLUSIVE);
			LogwrtResult = XLogCtl->LogwrtResult;
			if (LogwrtResult.Write >= OldPageRqstPtr)
			{
				
				LWLockRelease(WALWriteLock);
			}
			else {
				
				TRACE_POSTGRESQL_WAL_BUFFER_WRITE_DIRTY_START();
				WriteRqst.Write = OldPageRqstPtr;
				WriteRqst.Flush = 0;
				XLogWrite(WriteRqst, false, false);
				LWLockRelease(WALWriteLock);
				TRACE_POSTGRESQL_WAL_BUFFER_WRITE_DIRTY_DONE();
			}
		}
	}

	
	NewPageBeginPtr = XLogCtl->xlblocks[Insert->curridx];

	if (new_segment)
	{
		
		if (NewPageBeginPtr % XLogSegSize != 0)
			NewPageBeginPtr += XLogSegSize - NewPageBeginPtr % XLogSegSize;
	}

	NewPageEndPtr = NewPageBeginPtr;
	NewPageEndPtr += XLOG_BLCKSZ;
	XLogCtl->xlblocks[nextidx] = NewPageEndPtr;
	NewPage = (XLogPageHeader) (XLogCtl->pages + nextidx * (Size) XLOG_BLCKSZ);

	Insert->curridx = nextidx;
	Insert->currpage = NewPage;

	Insert->currpos = ((char *) NewPage) +SizeOfXLogShortPHD;

	
	MemSet((char *) NewPage, 0, XLOG_BLCKSZ);

	
	NewPage   ->xlp_magic = XLOG_PAGE_MAGIC;

		
	NewPage   ->xlp_tli = ThisTimeLineID;
	NewPage   ->xlp_pageaddr = NewPageBeginPtr;

	
	if (!Insert->forcePageWrites)
		NewPage   ->xlp_info |= XLP_BKP_REMOVABLE;

	
	if ((NewPage->xlp_pageaddr % XLogSegSize) == 0)
	{
		XLogLongPageHeader NewLongPage = (XLogLongPageHeader) NewPage;

		NewLongPage->xlp_sysid = ControlFile->system_identifier;
		NewLongPage->xlp_seg_size = XLogSegSize;
		NewLongPage->xlp_xlog_blcksz = XLOG_BLCKSZ;
		NewPage   ->xlp_info |= XLP_LONG_HEADER;

		Insert->currpos = ((char *) NewPage) +SizeOfXLogLongPHD;
	}

	return update_needed;
}


static bool XLogCheckpointNeeded(XLogSegNo new_segno)
{
	XLogSegNo	old_segno;

	XLByteToSeg(RedoRecPtr, old_segno);

	if (new_segno >= old_segno + (uint64) (CheckPointSegments - 1))
		return true;
	return false;
}


static void XLogWrite(XLogwrtRqst WriteRqst, bool flexible, bool xlog_switch)
{
	XLogCtlWrite *Write = &XLogCtl->Write;
	bool		ispartialpage;
	bool		last_iteration;
	bool		finishing_seg;
	bool		use_existent;
	int			curridx;
	int			npages;
	int			startidx;
	uint32		startoffset;

	
	Assert(CritSectionCount > 0);

	
	LogwrtResult = XLogCtl->LogwrtResult;

	
	npages = 0;
	startidx = 0;
	startoffset = 0;

	
	curridx = Write->curridx;

	while (LogwrtResult.Write < WriteRqst.Write)
	{
		
		if (LogwrtResult.Write >= XLogCtl->xlblocks[curridx])
			elog(PANIC, "xlog write request %X/%X is past end of log %X/%X", (uint32) (LogwrtResult.Write >> 32), (uint32) LogwrtResult.Write, (uint32) (XLogCtl->xlblocks[curridx] >> 32), (uint32) XLogCtl->xlblocks[curridx]);



		
		LogwrtResult.Write = XLogCtl->xlblocks[curridx];
		ispartialpage = WriteRqst.Write < LogwrtResult.Write;

		if (!XLByteInPrevSeg(LogwrtResult.Write, openLogSegNo))
		{
			
			Assert(npages == 0);
			if (openLogFile >= 0)
				XLogFileClose();
			XLByteToPrevSeg(LogwrtResult.Write, openLogSegNo);

			
			use_existent = true;
			openLogFile = XLogFileInit(openLogSegNo, &use_existent, true);
			openLogOff = 0;
		}

		
		if (openLogFile < 0)
		{
			XLByteToPrevSeg(LogwrtResult.Write, openLogSegNo);
			openLogFile = XLogFileOpen(openLogSegNo);
			openLogOff = 0;
		}

		
		if (npages == 0)
		{
			
			startidx = curridx;
			startoffset = (LogwrtResult.Write - XLOG_BLCKSZ) % XLogSegSize;
		}
		npages++;

		
		last_iteration = WriteRqst.Write <= LogwrtResult.Write;

		finishing_seg = !ispartialpage && (startoffset + npages * XLOG_BLCKSZ) >= XLogSegSize;

		if (last_iteration || curridx == XLogCtl->XLogCacheBlck || finishing_seg)

		{
			char	   *from;
			Size		nbytes;

			
			if (openLogOff != startoffset)
			{
				if (lseek(openLogFile, (off_t) startoffset, SEEK_SET) < 0)
					ereport(PANIC, (errcode_for_file_access(), errmsg("could not seek in log file %s to offset %u: %m", XLogFileNameP(ThisTimeLineID, openLogSegNo), startoffset)));



				openLogOff = startoffset;
			}

			
			from = XLogCtl->pages + startidx * (Size) XLOG_BLCKSZ;
			nbytes = npages * (Size) XLOG_BLCKSZ;
			errno = 0;
			if (write(openLogFile, from, nbytes) != nbytes)
			{
				
				if (errno == 0)
					errno = ENOSPC;
				ereport(PANIC, (errcode_for_file_access(), errmsg("could not write to log file %s " "at offset %u, length %lu: %m", XLogFileNameP(ThisTimeLineID, openLogSegNo), openLogOff, (unsigned long) nbytes)));




			}

			
			openLogOff += nbytes;
			Write->curridx = ispartialpage ? curridx : NextBufIdx(curridx);
			npages = 0;

			
			if (finishing_seg || (xlog_switch && last_iteration))
			{
				issue_xlog_fsync(openLogFile, openLogSegNo);

				
				WalSndWakeupRequest();

				LogwrtResult.Flush = LogwrtResult.Write;		

				if (XLogArchivingActive())
					XLogArchiveNotifySeg(openLogSegNo);

				Write->lastSegSwitchTime = (pg_time_t) time(NULL);

				
				if (IsUnderPostmaster && XLogCheckpointNeeded(openLogSegNo))
				{
					(void) GetRedoRecPtr();
					if (XLogCheckpointNeeded(openLogSegNo))
						RequestCheckpoint(CHECKPOINT_CAUSE_XLOG);
				}
			}
		}

		if (ispartialpage)
		{
			
			LogwrtResult.Write = WriteRqst.Write;
			break;
		}
		curridx = NextBufIdx(curridx);

		
		if (flexible && npages == 0)
			break;
	}

	Assert(npages == 0);
	Assert(curridx == Write->curridx);

	
	if (LogwrtResult.Flush < WriteRqst.Flush && LogwrtResult.Flush < LogwrtResult.Write)

	{
		
		if (sync_method != SYNC_METHOD_OPEN && sync_method != SYNC_METHOD_OPEN_DSYNC)
		{
			if (openLogFile >= 0 && !XLByteInPrevSeg(LogwrtResult.Write, openLogSegNo))
				XLogFileClose();
			if (openLogFile < 0)
			{
				XLByteToPrevSeg(LogwrtResult.Write, openLogSegNo);
				openLogFile = XLogFileOpen(openLogSegNo);
				openLogOff = 0;
			}

			issue_xlog_fsync(openLogFile, openLogSegNo);
		}

		
		WalSndWakeupRequest();

		LogwrtResult.Flush = LogwrtResult.Write;
	}

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		xlogctl->LogwrtResult = LogwrtResult;
		if (xlogctl->LogwrtRqst.Write < LogwrtResult.Write)
			xlogctl->LogwrtRqst.Write = LogwrtResult.Write;
		if (xlogctl->LogwrtRqst.Flush < LogwrtResult.Flush)
			xlogctl->LogwrtRqst.Flush = LogwrtResult.Flush;
		SpinLockRelease(&xlogctl->info_lck);
	}
}


void XLogSetAsyncXactLSN(XLogRecPtr asyncXactLSN)
{
	XLogRecPtr	WriteRqstPtr = asyncXactLSN;
	bool		sleeping;

	
	volatile XLogCtlData *xlogctl = XLogCtl;

	SpinLockAcquire(&xlogctl->info_lck);
	LogwrtResult = xlogctl->LogwrtResult;
	sleeping = xlogctl->WalWriterSleeping;
	if (xlogctl->asyncXactLSN < asyncXactLSN)
		xlogctl->asyncXactLSN = asyncXactLSN;
	SpinLockRelease(&xlogctl->info_lck);

	
	if (!sleeping)
	{
		
		WriteRqstPtr -= WriteRqstPtr % XLOG_BLCKSZ;

		
		if (WriteRqstPtr <= LogwrtResult.Flush)
			return;
	}

	
	if (ProcGlobal->walwriterLatch)
		SetLatch(ProcGlobal->walwriterLatch);
}


static void UpdateMinRecoveryPoint(XLogRecPtr lsn, bool force)
{
	
	if (!updateMinRecoveryPoint || (!force && lsn <= minRecoveryPoint))
		return;

	LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);

	
	minRecoveryPoint = ControlFile->minRecoveryPoint;
	minRecoveryPointTLI = ControlFile->minRecoveryPointTLI;

	
	if (minRecoveryPoint == 0)
		updateMinRecoveryPoint = false;
	else if (force || minRecoveryPoint < lsn)
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;
		XLogRecPtr	newMinRecoveryPoint;
		TimeLineID	newMinRecoveryPointTLI;

		
		SpinLockAcquire(&xlogctl->info_lck);
		newMinRecoveryPoint = xlogctl->replayEndRecPtr;
		newMinRecoveryPointTLI = xlogctl->replayEndTLI;
		SpinLockRelease(&xlogctl->info_lck);

		if (!force && newMinRecoveryPoint < lsn)
			elog(WARNING, "xlog min recovery request %X/%X is past current point %X/%X", (uint32) (lsn >> 32) , (uint32) lsn, (uint32) (newMinRecoveryPoint >> 32), (uint32) newMinRecoveryPoint);




		
		if (ControlFile->minRecoveryPoint < newMinRecoveryPoint)
		{
			ControlFile->minRecoveryPoint = newMinRecoveryPoint;
			ControlFile->minRecoveryPointTLI = newMinRecoveryPointTLI;
			UpdateControlFile();
			minRecoveryPoint = newMinRecoveryPoint;
			minRecoveryPointTLI = newMinRecoveryPointTLI;

			ereport(DEBUG2, (errmsg("updated min recovery point to %X/%X on timeline %u", (uint32) (minRecoveryPoint >> 32), (uint32) minRecoveryPoint, newMinRecoveryPointTLI)));



		}
	}
	LWLockRelease(ControlFileLock);
}


void XLogFlush(XLogRecPtr record)
{
	XLogRecPtr	WriteRqstPtr;
	XLogwrtRqst WriteRqst;

	
	if (!XLogInsertAllowed())
	{
		UpdateMinRecoveryPoint(record, false);
		return;
	}

	
	if (record <= LogwrtResult.Flush)
		return;


	if (XLOG_DEBUG)
		elog(LOG, "xlog flush request %X/%X; write %X/%X; flush %X/%X", (uint32) (record >> 32), (uint32) record, (uint32) (LogwrtResult.Write >> 32), (uint32) LogwrtResult.Write, (uint32) (LogwrtResult.Flush >> 32), (uint32) LogwrtResult.Flush);




	START_CRIT_SECTION();

	

	
	WriteRqstPtr = record;

	
	for (;;)
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		
		SpinLockAcquire(&xlogctl->info_lck);
		if (WriteRqstPtr < xlogctl->LogwrtRqst.Write)
			WriteRqstPtr = xlogctl->LogwrtRqst.Write;
		LogwrtResult = xlogctl->LogwrtResult;
		SpinLockRelease(&xlogctl->info_lck);

		
		if (record <= LogwrtResult.Flush)
			break;

		
		if (!LWLockAcquireOrWait(WALWriteLock, LW_EXCLUSIVE))
		{
			
			continue;
		}

		
		LogwrtResult = XLogCtl->LogwrtResult;
		if (record <= LogwrtResult.Flush)
		{
			LWLockRelease(WALWriteLock);
			break;
		}

		
		if (CommitDelay > 0 && enableFsync && MinimumActiveBackends(CommitSiblings))
			pg_usleep(CommitDelay);

		
		if (LWLockConditionalAcquire(WALInsertLock, LW_EXCLUSIVE))
		{
			XLogCtlInsert *Insert = &XLogCtl->Insert;
			uint32		freespace = INSERT_FREESPACE(Insert);

			if (freespace == 0)		
				WriteRqstPtr = XLogCtl->xlblocks[Insert->curridx];
			else {
				WriteRqstPtr = XLogCtl->xlblocks[Insert->curridx];
				WriteRqstPtr -= freespace;
			}
			LWLockRelease(WALInsertLock);
			WriteRqst.Write = WriteRqstPtr;
			WriteRqst.Flush = WriteRqstPtr;
		}
		else {
			WriteRqst.Write = WriteRqstPtr;
			WriteRqst.Flush = record;
		}
		XLogWrite(WriteRqst, false, false);

		LWLockRelease(WALWriteLock);
		
		break;
	}

	END_CRIT_SECTION();

	
	WalSndWakeupProcessRequests();

	
	if (LogwrtResult.Flush < record)
		elog(ERROR, "xlog flush request %X/%X is not satisfied --- flushed only to %X/%X", (uint32) (record >> 32), (uint32) record, (uint32) (LogwrtResult.Flush >> 32), (uint32) LogwrtResult.Flush);


}


bool XLogBackgroundFlush(void)
{
	XLogRecPtr	WriteRqstPtr;
	bool		flexible = true;
	bool		wrote_something = false;

	
	if (RecoveryInProgress())
		return false;

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		LogwrtResult = xlogctl->LogwrtResult;
		WriteRqstPtr = xlogctl->LogwrtRqst.Write;
		SpinLockRelease(&xlogctl->info_lck);
	}

	
	WriteRqstPtr -= WriteRqstPtr % XLOG_BLCKSZ;

	
	if (WriteRqstPtr <= LogwrtResult.Flush)
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		WriteRqstPtr = xlogctl->asyncXactLSN;
		SpinLockRelease(&xlogctl->info_lck);
		flexible = false;		
	}

	
	if (WriteRqstPtr <= LogwrtResult.Flush)
	{
		if (openLogFile >= 0)
		{
			if (!XLByteInPrevSeg(LogwrtResult.Write, openLogSegNo))
			{
				XLogFileClose();
			}
		}
		return false;
	}


	if (XLOG_DEBUG)
		elog(LOG, "xlog bg flush request %X/%X; write %X/%X; flush %X/%X", (uint32) (WriteRqstPtr >> 32), (uint32) WriteRqstPtr, (uint32) (LogwrtResult.Write >> 32), (uint32) LogwrtResult.Write, (uint32) (LogwrtResult.Flush >> 32), (uint32) LogwrtResult.Flush);




	START_CRIT_SECTION();

	
	LWLockAcquire(WALWriteLock, LW_EXCLUSIVE);
	LogwrtResult = XLogCtl->LogwrtResult;
	if (WriteRqstPtr > LogwrtResult.Flush)
	{
		XLogwrtRqst WriteRqst;

		WriteRqst.Write = WriteRqstPtr;
		WriteRqst.Flush = WriteRqstPtr;
		XLogWrite(WriteRqst, flexible, false);
		wrote_something = true;
	}
	LWLockRelease(WALWriteLock);

	END_CRIT_SECTION();

	
	WalSndWakeupProcessRequests();

	return wrote_something;
}


bool XLogNeedsFlush(XLogRecPtr record)
{
	
	if (RecoveryInProgress())
	{
		
		if (record <= minRecoveryPoint || !updateMinRecoveryPoint)
			return false;

		
		if (!LWLockConditionalAcquire(ControlFileLock, LW_SHARED))
			return true;
		minRecoveryPoint = ControlFile->minRecoveryPoint;
		minRecoveryPointTLI = ControlFile->minRecoveryPointTLI;
		LWLockRelease(ControlFileLock);

		
		if (minRecoveryPoint == 0)
			updateMinRecoveryPoint = false;

		
		if (record <= minRecoveryPoint || !updateMinRecoveryPoint)
			return false;
		else return true;
	}

	
	if (record <= LogwrtResult.Flush)
		return false;

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		LogwrtResult = xlogctl->LogwrtResult;
		SpinLockRelease(&xlogctl->info_lck);
	}

	
	if (record <= LogwrtResult.Flush)
		return false;

	return true;
}


int XLogFileInit(XLogSegNo logsegno, bool *use_existent, bool use_lock)
{
	char		path[MAXPGPATH];
	char		tmppath[MAXPGPATH];
	char	   *zbuffer;
	XLogSegNo	installed_segno;
	int			max_advance;
	int			fd;
	int			nbytes;

	XLogFilePath(path, ThisTimeLineID, logsegno);

	
	if (*use_existent)
	{
		fd = BasicOpenFile(path, O_RDWR | PG_BINARY | get_sync_bit(sync_method), S_IRUSR | S_IWUSR);
		if (fd < 0)
		{
			if (errno != ENOENT)
				ereport(ERROR, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", path)));

		}
		else return fd;
	}

	
	elog(DEBUG2, "creating and filling new WAL file");

	snprintf(tmppath, MAXPGPATH, XLOGDIR "/xlogtemp.%d", (int) getpid());

	unlink(tmppath);

	
	zbuffer = (char *) palloc0(XLOG_BLCKSZ);

	
	fd = BasicOpenFile(tmppath, O_RDWR | O_CREAT | O_EXCL | PG_BINARY, S_IRUSR | S_IWUSR);
	if (fd < 0)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not create file \"%s\": %m", tmppath)));


	
	for (nbytes = 0; nbytes < XLogSegSize; nbytes += XLOG_BLCKSZ)
	{
		errno = 0;
		if ((int) write(fd, zbuffer, XLOG_BLCKSZ) != (int) XLOG_BLCKSZ)
		{
			int			save_errno = errno;

			
			unlink(tmppath);

			close(fd);

			
			errno = save_errno ? save_errno : ENOSPC;

			ereport(ERROR, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", tmppath)));

		}
	}
	pfree(zbuffer);

	if (pg_fsync(fd) != 0)
	{
		close(fd);
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not fsync file \"%s\": %m", tmppath)));

	}

	if (close(fd))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not close file \"%s\": %m", tmppath)));


	
	installed_segno = logsegno;
	max_advance = XLOGfileslop;
	if (!InstallXLogFileSegment(&installed_segno, tmppath, *use_existent, &max_advance, use_lock))

	{
		
		unlink(tmppath);
	}

	
	*use_existent = false;

	
	fd = BasicOpenFile(path, O_RDWR | PG_BINARY | get_sync_bit(sync_method), S_IRUSR | S_IWUSR);
	if (fd < 0)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", path)));


	elog(DEBUG2, "done creating and filling new WAL file");

	return fd;
}


static void XLogFileCopy(XLogSegNo destsegno, TimeLineID srcTLI, XLogSegNo srcsegno)
{
	char		path[MAXPGPATH];
	char		tmppath[MAXPGPATH];
	char		buffer[XLOG_BLCKSZ];
	int			srcfd;
	int			fd;
	int			nbytes;

	
	XLogFilePath(path, srcTLI, srcsegno);
	srcfd = OpenTransientFile(path, O_RDONLY | PG_BINARY, 0);
	if (srcfd < 0)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", path)));


	
	snprintf(tmppath, MAXPGPATH, XLOGDIR "/xlogtemp.%d", (int) getpid());

	unlink(tmppath);

	
	fd = OpenTransientFile(tmppath, O_RDWR | O_CREAT | O_EXCL | PG_BINARY, S_IRUSR | S_IWUSR);
	if (fd < 0)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not create file \"%s\": %m", tmppath)));


	
	for (nbytes = 0; nbytes < XLogSegSize; nbytes += sizeof(buffer))
	{
		errno = 0;
		if ((int) read(srcfd, buffer, sizeof(buffer)) != (int) sizeof(buffer))
		{
			if (errno != 0)
				ereport(ERROR, (errcode_for_file_access(), errmsg("could not read file \"%s\": %m", path)));

			else ereport(ERROR, (errmsg("not enough data in file \"%s\"", path)));

		}
		errno = 0;
		if ((int) write(fd, buffer, sizeof(buffer)) != (int) sizeof(buffer))
		{
			int			save_errno = errno;

			
			unlink(tmppath);
			
			errno = save_errno ? save_errno : ENOSPC;

			ereport(ERROR, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", tmppath)));

		}
	}

	if (pg_fsync(fd) != 0)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not fsync file \"%s\": %m", tmppath)));


	if (CloseTransientFile(fd))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not close file \"%s\": %m", tmppath)));


	CloseTransientFile(srcfd);

	
	if (!InstallXLogFileSegment(&destsegno, tmppath, false, NULL, false))
		elog(ERROR, "InstallXLogFileSegment should not have failed");
}


static bool InstallXLogFileSegment(XLogSegNo *segno, char *tmppath, bool find_free, int *max_advance, bool use_lock)


{
	char		path[MAXPGPATH];
	struct stat stat_buf;

	XLogFilePath(path, ThisTimeLineID, *segno);

	
	if (use_lock)
		LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);

	if (!find_free)
	{
		
		unlink(path);
	}
	else {
		
		while (stat(path, &stat_buf) == 0)
		{
			if (*max_advance <= 0)
			{
				
				if (use_lock)
					LWLockRelease(ControlFileLock);
				return false;
			}
			(*segno)++;
			(*max_advance)--;
			XLogFilePath(path, ThisTimeLineID, *segno);
		}
	}

	

	if (link(tmppath, path) < 0)
	{
		if (use_lock)
			LWLockRelease(ControlFileLock);
		ereport(LOG, (errcode_for_file_access(), errmsg("could not link file \"%s\" to \"%s\" (initialization of log file): %m", tmppath, path)));


		return false;
	}
	unlink(tmppath);

	if (rename(tmppath, path) < 0)
	{
		if (use_lock)
			LWLockRelease(ControlFileLock);
		ereport(LOG, (errcode_for_file_access(), errmsg("could not rename file \"%s\" to \"%s\" (initialization of log file): %m", tmppath, path)));


		return false;
	}


	if (use_lock)
		LWLockRelease(ControlFileLock);

	return true;
}


int XLogFileOpen(XLogSegNo segno)
{
	char		path[MAXPGPATH];
	int			fd;

	XLogFilePath(path, ThisTimeLineID, segno);

	fd = BasicOpenFile(path, O_RDWR | PG_BINARY | get_sync_bit(sync_method), S_IRUSR | S_IWUSR);
	if (fd < 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not open xlog file \"%s\": %m", path)));


	return fd;
}


static int XLogFileRead(XLogSegNo segno, int emode, TimeLineID tli, int source, bool notfoundOk)

{
	char		xlogfname[MAXFNAMELEN];
	char		activitymsg[MAXFNAMELEN + 16];
	char		path[MAXPGPATH];
	int			fd;

	XLogFileName(xlogfname, tli, segno);

	switch (source)
	{
		case XLOG_FROM_ARCHIVE:
			
			snprintf(activitymsg, sizeof(activitymsg), "waiting for %s", xlogfname);
			set_ps_display(activitymsg, false);

			restoredFromArchive = RestoreArchivedFile(path, xlogfname, "RECOVERYXLOG", XLogSegSize, InRedo);


			if (!restoredFromArchive)
				return -1;
			break;

		case XLOG_FROM_PG_XLOG:
		case XLOG_FROM_STREAM:
			XLogFilePath(path, tli, segno);
			restoredFromArchive = false;
			break;

		default:
			elog(ERROR, "invalid XLogFileRead source %d", source);
	}

	
	if (source == XLOG_FROM_ARCHIVE)
	{
		KeepFileRestoredFromArchive(path, xlogfname);

		
		snprintf(path, MAXPGPATH, XLOGDIR "/%s", xlogfname);
	}

	fd = BasicOpenFile(path, O_RDONLY | PG_BINARY, 0);
	if (fd >= 0)
	{
		
		curFileTLI = tli;

		
		snprintf(activitymsg, sizeof(activitymsg), "recovering %s", xlogfname);
		set_ps_display(activitymsg, false);

		
		readSource = source;
		XLogReceiptSource = source;
		
		if (source != XLOG_FROM_STREAM)
			XLogReceiptTime = GetCurrentTimestamp();

		return fd;
	}
	if (errno != ENOENT || !notfoundOk) 
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", path)));

	return -1;
}


static int XLogFileReadAnyTLI(XLogSegNo segno, int emode, int source)
{
	char		path[MAXPGPATH];
	ListCell   *cell;
	int			fd;
	List	   *tles;

	
	if (expectedTLEs)
		tles = expectedTLEs;
	else tles = readTimeLineHistory(recoveryTargetTLI);

	foreach(cell, tles)
	{
		TimeLineID	tli = ((TimeLineHistoryEntry *) lfirst(cell))->tli;

		if (tli < curFileTLI)
			break;				

		if (source == XLOG_FROM_ANY || source == XLOG_FROM_ARCHIVE)
		{
			fd = XLogFileRead(segno, emode, tli, XLOG_FROM_ARCHIVE, true);
			if (fd != -1)
			{
				elog(DEBUG1, "got WAL segment from archive");
				if (!expectedTLEs)
					expectedTLEs = tles;
				return fd;
			}
		}

		if (source == XLOG_FROM_ANY || source == XLOG_FROM_PG_XLOG)
		{
			fd = XLogFileRead(segno, emode, tli, XLOG_FROM_PG_XLOG, true);
			if (fd != -1)
			{
				if (!expectedTLEs)
					expectedTLEs = tles;
				return fd;
			}
		}
	}

	
	XLogFilePath(path, recoveryTargetTLI, segno);
	errno = ENOENT;
	ereport(emode, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", path)));

	return -1;
}


static void XLogFileClose(void)
{
	Assert(openLogFile >= 0);

	

	if (!XLogIsNeeded())
		(void) posix_fadvise(openLogFile, 0, 0, POSIX_FADV_DONTNEED);


	if (close(openLogFile))
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not close log file %s: %m", XLogFileNameP(ThisTimeLineID, openLogSegNo))));


	openLogFile = -1;
}


static void PreallocXlogFiles(XLogRecPtr endptr)
{
	XLogSegNo	_logSegNo;
	int			lf;
	bool		use_existent;

	XLByteToPrevSeg(endptr, _logSegNo);
	if ((endptr - 1) % XLogSegSize >= (uint32) (0.75 * XLogSegSize))
	{
		_logSegNo++;
		use_existent = true;
		lf = XLogFileInit(_logSegNo, &use_existent, true);
		close(lf);
		if (!use_existent)
			CheckpointStats.ckpt_segs_added++;
	}
}


void CheckXLogRemoved(XLogSegNo segno, TimeLineID tli)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	XLogSegNo	lastRemovedSegNo;

	SpinLockAcquire(&xlogctl->info_lck);
	lastRemovedSegNo = xlogctl->lastRemovedSegNo;
	SpinLockRelease(&xlogctl->info_lck);

	if (segno <= lastRemovedSegNo)
	{
		char		filename[MAXFNAMELEN];

		XLogFileName(filename, tli, segno);
		ereport(ERROR, (errcode_for_file_access(), errmsg("requested WAL segment %s has already been removed", filename)));


	}
}


static void UpdateLastRemovedPtr(char *filename)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	uint32		tli;
	XLogSegNo	segno;

	XLogFromFileName(filename, &tli, &segno);

	SpinLockAcquire(&xlogctl->info_lck);
	if (segno > xlogctl->lastRemovedSegNo)
		xlogctl->lastRemovedSegNo = segno;
	SpinLockRelease(&xlogctl->info_lck);
}


static void RemoveOldXlogFiles(XLogSegNo segno, XLogRecPtr endptr)
{
	XLogSegNo	endlogSegNo;
	int			max_advance;
	DIR		   *xldir;
	struct dirent *xlde;
	char		lastoff[MAXFNAMELEN];
	char		path[MAXPGPATH];


	char		newpath[MAXPGPATH];

	struct stat statbuf;

	
	XLByteToPrevSeg(endptr, endlogSegNo);
	max_advance = XLOGfileslop;

	xldir = AllocateDir(XLOGDIR);
	if (xldir == NULL)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not open transaction log directory \"%s\": %m", XLOGDIR)));



	
	XLogFileName(lastoff, 0, segno);

	elog(DEBUG2, "attempting to remove WAL segments older than log file %s", lastoff);

	while ((xlde = ReadDir(xldir, XLOGDIR)) != NULL)
	{
		
		if (strlen(xlde->d_name) == 24 && strspn(xlde->d_name, "0123456789ABCDEF") == 24 && strcmp(xlde->d_name + 8, lastoff + 8) <= 0)

		{
			if (XLogArchiveCheckDone(xlde->d_name))
			{
				snprintf(path, MAXPGPATH, XLOGDIR "/%s", xlde->d_name);

				
				UpdateLastRemovedPtr(xlde->d_name);

				
				if (lstat(path, &statbuf) == 0 && S_ISREG(statbuf.st_mode) && InstallXLogFileSegment(&endlogSegNo, path, true, &max_advance, true))

				{
					ereport(DEBUG2, (errmsg("recycled transaction log file \"%s\"", xlde->d_name)));

					CheckpointStats.ckpt_segs_recycled++;
					
					if (max_advance > 0)
					{
						endlogSegNo++;
						max_advance--;
					}
				}
				else {
					
					int			rc;

					ereport(DEBUG2, (errmsg("removing transaction log file \"%s\"", xlde->d_name)));




					
					snprintf(newpath, MAXPGPATH, "%s.deleted", path);
					if (rename(path, newpath) != 0)
					{
						ereport(LOG, (errcode_for_file_access(), errmsg("could not rename old transaction log file \"%s\": %m", path)));


						continue;
					}
					rc = unlink(newpath);

					rc = unlink(path);

					if (rc != 0)
					{
						ereport(LOG, (errcode_for_file_access(), errmsg("could not remove old transaction log file \"%s\": %m", path)));


						continue;
					}
					CheckpointStats.ckpt_segs_removed++;
				}

				XLogArchiveCleanup(xlde->d_name);
			}
		}
	}

	FreeDir(xldir);
}


static void ValidateXLOGDirectoryStructure(void)
{
	char		path[MAXPGPATH];
	struct stat stat_buf;

	
	if (stat(XLOGDIR, &stat_buf) != 0 || !S_ISDIR(stat_buf.st_mode))
		ereport(FATAL, (errmsg("required WAL directory \"%s\" does not exist", XLOGDIR)));


	
	snprintf(path, MAXPGPATH, XLOGDIR "/archive_status");
	if (stat(path, &stat_buf) == 0)
	{
		
		if (!S_ISDIR(stat_buf.st_mode))
			ereport(FATAL, (errmsg("required WAL directory \"%s\" does not exist", path)));

	}
	else {
		ereport(LOG, (errmsg("creating missing WAL directory \"%s\"", path)));
		if (mkdir(path, S_IRWXU) < 0)
			ereport(FATAL, (errmsg("could not create missing directory \"%s\": %m", path)));

	}
}


static void CleanupBackupHistory(void)
{
	DIR		   *xldir;
	struct dirent *xlde;
	char		path[MAXPGPATH];

	xldir = AllocateDir(XLOGDIR);
	if (xldir == NULL)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not open transaction log directory \"%s\": %m", XLOGDIR)));



	while ((xlde = ReadDir(xldir, XLOGDIR)) != NULL)
	{
		if (strlen(xlde->d_name) > 24 && strspn(xlde->d_name, "0123456789ABCDEF") == 24 && strcmp(xlde->d_name + strlen(xlde->d_name) - strlen(".backup"), ".backup") == 0)


		{
			if (XLogArchiveCheckDone(xlde->d_name))
			{
				ereport(DEBUG2, (errmsg("removing transaction log backup history file \"%s\"", xlde->d_name)));

				snprintf(path, MAXPGPATH, XLOGDIR "/%s", xlde->d_name);
				unlink(path);
				XLogArchiveCleanup(xlde->d_name);
			}
		}
	}

	FreeDir(xldir);
}


Buffer RestoreBackupBlock(XLogRecPtr lsn, XLogRecord *record, int block_index, bool get_cleanup_lock, bool keep_buffer)

{
	Buffer		buffer;
	Page		page;
	BkpBlock	bkpb;
	char	   *blk;
	int			i;

	
	blk = (char *) XLogRecGetData(record) + record->xl_len;
	for (i = 0; i < XLR_MAX_BKP_BLOCKS; i++)
	{
		if (!(record->xl_info & XLR_BKP_BLOCK(i)))
			continue;

		memcpy(&bkpb, blk, sizeof(BkpBlock));
		blk += sizeof(BkpBlock);

		if (i == block_index)
		{
			
			buffer = XLogReadBufferExtended(bkpb.node, bkpb.fork, bkpb.block, RBM_ZERO);
			Assert(BufferIsValid(buffer));
			if (get_cleanup_lock)
				LockBufferForCleanup(buffer);
			else LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			page = (Page) BufferGetPage(buffer);

			if (bkpb.hole_length == 0)
			{
				memcpy((char *) page, blk, BLCKSZ);
			}
			else {
				memcpy((char *) page, blk, bkpb.hole_offset);
				
				MemSet((char *) page + bkpb.hole_offset, 0, bkpb.hole_length);
				memcpy((char *) page + (bkpb.hole_offset + bkpb.hole_length), blk + bkpb.hole_offset, BLCKSZ - (bkpb.hole_offset + bkpb.hole_length));

			}

			

			PageSetLSN(page, lsn);
			MarkBufferDirty(buffer);

			if (!keep_buffer)
				UnlockReleaseBuffer(buffer);

			return buffer;
		}

		blk += BLCKSZ - bkpb.hole_length;
	}

	
	elog(ERROR, "failed to restore block_index %d", block_index);
	return InvalidBuffer;		
}


static XLogRecord * ReadRecord(XLogReaderState *xlogreader, XLogRecPtr RecPtr, int emode, bool fetching_ckpt)

{
	XLogRecord *record;
	XLogPageReadPrivate *private = (XLogPageReadPrivate *) xlogreader->private_data;

	
	private->fetching_ckpt = fetching_ckpt;
	private->emode = emode;
	private->randAccess = (RecPtr != InvalidXLogRecPtr);

	
	lastSourceFailed = false;

	for (;;)
	{
		char   *errormsg;

		record = XLogReadRecord(xlogreader, RecPtr, &errormsg);
		ReadRecPtr = xlogreader->ReadRecPtr;
		EndRecPtr = xlogreader->EndRecPtr;
		if (record == NULL)
		{
			if (readFile >= 0)
			{
				close(readFile);
				readFile = -1;
			}

			
			if (errormsg)
				ereport(emode_for_corrupt_record(emode, RecPtr ? RecPtr : EndRecPtr), (errmsg_internal("%s", errormsg) ));

		}
		
		else if (!tliInHistory(xlogreader->latestPageTLI, expectedTLEs))
		{
			char		fname[MAXFNAMELEN];
			XLogSegNo segno;
			int32 offset;

			XLByteToSeg(xlogreader->latestPagePtr, segno);
			offset = xlogreader->latestPagePtr % XLogSegSize;
			XLogFileName(fname, xlogreader->readPageTLI, segno);
			ereport(emode_for_corrupt_record(emode, RecPtr ? RecPtr : EndRecPtr), (errmsg("unexpected timeline ID %u in log segment %s, offset %u", xlogreader->latestPageTLI, fname, offset)));




			record = NULL;
		}

		if (record)
		{
			
			return record;
		}
		else {
			
			lastSourceFailed = true;

			
			if (!InArchiveRecovery && ArchiveRecoveryRequested && !fetching_ckpt)
			{
				ereport(DEBUG1, (errmsg_internal("reached end of WAL in pg_xlog, entering archive recovery")));
				InArchiveRecovery = true;
				if (StandbyModeRequested)
					StandbyMode = true;

				
				LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
				ControlFile->state = DB_IN_ARCHIVE_RECOVERY;
				if (ControlFile->minRecoveryPoint < EndRecPtr)
				{
					ControlFile->minRecoveryPoint = EndRecPtr;
					ControlFile->minRecoveryPointTLI = ThisTimeLineID;
				}
				
				minRecoveryPoint = ControlFile->minRecoveryPoint;
				minRecoveryPointTLI = ControlFile->minRecoveryPointTLI;

				UpdateControlFile();
				LWLockRelease(ControlFileLock);

				CheckRecoveryConsistency();

				
				lastSourceFailed = false;
				currentSource = 0;

				continue;
			}

			
			if (StandbyMode && !CheckForStandbyTrigger())
				continue;
			else return NULL;
		}
	}
}


static bool rescanLatestTimeLine(void)
{
	List	   *newExpectedTLEs;
	bool		found;
	ListCell   *cell;
	TimeLineID	newtarget;
	TimeLineID	oldtarget = recoveryTargetTLI;
	TimeLineHistoryEntry *currentTle = NULL;

	newtarget = findNewestTimeLine(recoveryTargetTLI);
	if (newtarget == recoveryTargetTLI)
	{
		
		return false;
	}

	

	newExpectedTLEs = readTimeLineHistory(newtarget);

	
	found = false;
	foreach (cell, newExpectedTLEs)
	{
		currentTle = (TimeLineHistoryEntry *) lfirst(cell);

		if (currentTle->tli == recoveryTargetTLI)
		{
			found = true;
			break;
		}
	}
	if (!found)
	{
		ereport(LOG, (errmsg("new timeline %u is not a child of database system timeline %u", newtarget, ThisTimeLineID)));


		return false;
	}

	
	if (currentTle->end < EndRecPtr)
	{
		ereport(LOG, (errmsg("new timeline %u forked off current database system timeline %u before current recovery point %X/%X", newtarget, ThisTimeLineID, (uint32) (EndRecPtr >> 32), (uint32) EndRecPtr)));



		return false;
	}

	
	recoveryTargetTLI = newtarget;
	list_free_deep(expectedTLEs);
	expectedTLEs = newExpectedTLEs;

	
	restoreTimeLineHistoryFiles(oldtarget + 1, newtarget);

	ereport(LOG, (errmsg("new target timeline is %u", recoveryTargetTLI)));


	return true;
}


static void WriteControlFile(void)
{
	int			fd;
	char		buffer[PG_CONTROL_SIZE];		

	
	ControlFile->pg_control_version = PG_CONTROL_VERSION;
	ControlFile->catalog_version_no = CATALOG_VERSION_NO;

	ControlFile->maxAlign = MAXIMUM_ALIGNOF;
	ControlFile->floatFormat = FLOATFORMAT_VALUE;

	ControlFile->blcksz = BLCKSZ;
	ControlFile->relseg_size = RELSEG_SIZE;
	ControlFile->xlog_blcksz = XLOG_BLCKSZ;
	ControlFile->xlog_seg_size = XLOG_SEG_SIZE;

	ControlFile->nameDataLen = NAMEDATALEN;
	ControlFile->indexMaxKeys = INDEX_MAX_KEYS;

	ControlFile->toast_max_chunk_size = TOAST_MAX_CHUNK_SIZE;


	ControlFile->enableIntTimes = true;

	ControlFile->enableIntTimes = false;

	ControlFile->float4ByVal = FLOAT4PASSBYVAL;
	ControlFile->float8ByVal = FLOAT8PASSBYVAL;

	
	INIT_CRC32(ControlFile->crc);
	COMP_CRC32(ControlFile->crc, (char *) ControlFile, offsetof(ControlFileData, crc));

	FIN_CRC32(ControlFile->crc);

	
	if (sizeof(ControlFileData) > PG_CONTROL_SIZE)
		elog(PANIC, "sizeof(ControlFileData) is larger than PG_CONTROL_SIZE; fix either one");

	memset(buffer, 0, PG_CONTROL_SIZE);
	memcpy(buffer, ControlFile, sizeof(ControlFileData));

	fd = BasicOpenFile(XLOG_CONTROL_FILE, O_RDWR | O_CREAT | O_EXCL | PG_BINARY, S_IRUSR | S_IWUSR);

	if (fd < 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not create control file \"%s\": %m", XLOG_CONTROL_FILE)));



	errno = 0;
	if (write(fd, buffer, PG_CONTROL_SIZE) != PG_CONTROL_SIZE)
	{
		
		if (errno == 0)
			errno = ENOSPC;
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not write to control file: %m")));

	}

	if (pg_fsync(fd) != 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not fsync control file: %m")));


	if (close(fd))
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not close control file: %m")));

}

static void ReadControlFile(void)
{
	pg_crc32	crc;
	int			fd;

	
	fd = BasicOpenFile(XLOG_CONTROL_FILE, O_RDWR | PG_BINARY, S_IRUSR | S_IWUSR);

	if (fd < 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not open control file \"%s\": %m", XLOG_CONTROL_FILE)));



	if (read(fd, ControlFile, sizeof(ControlFileData)) != sizeof(ControlFileData))
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not read from control file: %m")));


	close(fd);

	

	if (ControlFile->pg_control_version != PG_CONTROL_VERSION && ControlFile->pg_control_version % 65536 == 0 && ControlFile->pg_control_version / 65536 != 0)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with PG_CONTROL_VERSION %d (0x%08x)," " but the server was compiled with PG_CONTROL_VERSION %d (0x%08x).", ControlFile->pg_control_version, ControlFile->pg_control_version, PG_CONTROL_VERSION, PG_CONTROL_VERSION), errhint("This could be a problem of mismatched byte ordering.  It looks like you need to initdb.")));






	if (ControlFile->pg_control_version != PG_CONTROL_VERSION)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with PG_CONTROL_VERSION %d," " but the server was compiled with PG_CONTROL_VERSION %d.", ControlFile->pg_control_version, PG_CONTROL_VERSION), errhint("It looks like you need to initdb.")));





	
	INIT_CRC32(crc);
	COMP_CRC32(crc, (char *) ControlFile, offsetof(ControlFileData, crc));

	FIN_CRC32(crc);

	if (!EQ_CRC32(crc, ControlFile->crc))
		ereport(FATAL, (errmsg("incorrect checksum in control file")));

	
	if (ControlFile->catalog_version_no != CATALOG_VERSION_NO)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with CATALOG_VERSION_NO %d," " but the server was compiled with CATALOG_VERSION_NO %d.", ControlFile->catalog_version_no, CATALOG_VERSION_NO), errhint("It looks like you need to initdb.")));




	if (ControlFile->maxAlign != MAXIMUM_ALIGNOF)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with MAXALIGN %d," " but the server was compiled with MAXALIGN %d.", ControlFile->maxAlign, MAXIMUM_ALIGNOF), errhint("It looks like you need to initdb.")));




	if (ControlFile->floatFormat != FLOATFORMAT_VALUE)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster appears to use a different floating-point number format than the server executable."), errhint("It looks like you need to initdb.")));


	if (ControlFile->blcksz != BLCKSZ)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with BLCKSZ %d," " but the server was compiled with BLCKSZ %d.", ControlFile->blcksz, BLCKSZ), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->relseg_size != RELSEG_SIZE)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with RELSEG_SIZE %d," " but the server was compiled with RELSEG_SIZE %d.", ControlFile->relseg_size, RELSEG_SIZE), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->xlog_blcksz != XLOG_BLCKSZ)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with XLOG_BLCKSZ %d," " but the server was compiled with XLOG_BLCKSZ %d.", ControlFile->xlog_blcksz, XLOG_BLCKSZ), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->xlog_seg_size != XLOG_SEG_SIZE)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with XLOG_SEG_SIZE %d," " but the server was compiled with XLOG_SEG_SIZE %d.", ControlFile->xlog_seg_size, XLOG_SEG_SIZE), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->nameDataLen != NAMEDATALEN)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with NAMEDATALEN %d," " but the server was compiled with NAMEDATALEN %d.", ControlFile->nameDataLen, NAMEDATALEN), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->indexMaxKeys != INDEX_MAX_KEYS)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with INDEX_MAX_KEYS %d," " but the server was compiled with INDEX_MAX_KEYS %d.", ControlFile->indexMaxKeys, INDEX_MAX_KEYS), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->toast_max_chunk_size != TOAST_MAX_CHUNK_SIZE)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with TOAST_MAX_CHUNK_SIZE %d," " but the server was compiled with TOAST_MAX_CHUNK_SIZE %d.", ControlFile->toast_max_chunk_size, (int) TOAST_MAX_CHUNK_SIZE), errhint("It looks like you need to recompile or initdb.")));






	if (ControlFile->enableIntTimes != true)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized without HAVE_INT64_TIMESTAMP" " but the server was compiled with HAVE_INT64_TIMESTAMP."), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->enableIntTimes != false)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with HAVE_INT64_TIMESTAMP" " but the server was compiled without HAVE_INT64_TIMESTAMP."), errhint("It looks like you need to recompile or initdb.")));






	if (ControlFile->float4ByVal != true)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized without USE_FLOAT4_BYVAL" " but the server was compiled with USE_FLOAT4_BYVAL."), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->float4ByVal != false)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with USE_FLOAT4_BYVAL" " but the server was compiled without USE_FLOAT4_BYVAL."), errhint("It looks like you need to recompile or initdb.")));






	if (ControlFile->float8ByVal != true)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized without USE_FLOAT8_BYVAL" " but the server was compiled with USE_FLOAT8_BYVAL."), errhint("It looks like you need to recompile or initdb.")));




	if (ControlFile->float8ByVal != false)
		ereport(FATAL, (errmsg("database files are incompatible with server"), errdetail("The database cluster was initialized with USE_FLOAT8_BYVAL" " but the server was compiled without USE_FLOAT8_BYVAL."), errhint("It looks like you need to recompile or initdb.")));




}

void UpdateControlFile(void)
{
	int			fd;

	INIT_CRC32(ControlFile->crc);
	COMP_CRC32(ControlFile->crc, (char *) ControlFile, offsetof(ControlFileData, crc));

	FIN_CRC32(ControlFile->crc);

	fd = BasicOpenFile(XLOG_CONTROL_FILE, O_RDWR | PG_BINARY, S_IRUSR | S_IWUSR);

	if (fd < 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not open control file \"%s\": %m", XLOG_CONTROL_FILE)));



	errno = 0;
	if (write(fd, ControlFile, sizeof(ControlFileData)) != sizeof(ControlFileData))
	{
		
		if (errno == 0)
			errno = ENOSPC;
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not write to control file: %m")));

	}

	if (pg_fsync(fd) != 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not fsync control file: %m")));


	if (close(fd))
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not close control file: %m")));

}


uint64 GetSystemIdentifier(void)
{
	Assert(ControlFile != NULL);
	return ControlFile->system_identifier;
}


bool DataChecksumsEnabled(void)
{
	Assert(ControlFile != NULL);
	return ControlFile->data_checksums;
}


XLogRecPtr GetFakeLSNForUnloggedRel(void)
{
	XLogRecPtr nextUnloggedLSN;

	
	volatile XLogCtlData *xlogctl = XLogCtl;

	
	SpinLockAcquire(&xlogctl->ulsn_lck);
	nextUnloggedLSN = xlogctl->unloggedLSN++;
	SpinLockRelease(&xlogctl->ulsn_lck);

	return nextUnloggedLSN;
}


static int XLOGChooseNumBuffers(void)
{
	int			xbuffers;

	xbuffers = NBuffers / 32;
	if (xbuffers > XLOG_SEG_SIZE / XLOG_BLCKSZ)
		xbuffers = XLOG_SEG_SIZE / XLOG_BLCKSZ;
	if (xbuffers < 8)
		xbuffers = 8;
	return xbuffers;
}


bool check_wal_buffers(int *newval, void **extra, GucSource source)
{
	
	if (*newval == -1)
	{
		
		if (XLOGbuffers == -1)
			return true;

		
		*newval = XLOGChooseNumBuffers();
	}

	
	if (*newval < 4)
		*newval = 4;

	return true;
}


Size XLOGShmemSize(void)
{
	Size		size;

	
	if (XLOGbuffers == -1)
	{
		char		buf[32];

		snprintf(buf, sizeof(buf), "%d", XLOGChooseNumBuffers());
		SetConfigOption("wal_buffers", buf, PGC_POSTMASTER, PGC_S_OVERRIDE);
	}
	Assert(XLOGbuffers > 0);

	
	size = sizeof(XLogCtlData);
	
	size = add_size(size, mul_size(sizeof(XLogRecPtr), XLOGbuffers));
	
	size = add_size(size, ALIGNOF_XLOG_BUFFER);
	
	size = add_size(size, mul_size(XLOG_BLCKSZ, XLOGbuffers));

	

	return size;
}

void XLOGShmemInit(void)
{
	bool		foundCFile, foundXLog;
	char	   *allocptr;

	ControlFile = (ControlFileData *)
		ShmemInitStruct("Control File", sizeof(ControlFileData), &foundCFile);
	XLogCtl = (XLogCtlData *)
		ShmemInitStruct("XLOG Ctl", XLOGShmemSize(), &foundXLog);

	if (foundCFile || foundXLog)
	{
		
		Assert(foundCFile && foundXLog);
		return;
	}

	memset(XLogCtl, 0, sizeof(XLogCtlData));

	
	allocptr = ((char *) XLogCtl) + sizeof(XLogCtlData);
	XLogCtl->xlblocks = (XLogRecPtr *) allocptr;
	memset(XLogCtl->xlblocks, 0, sizeof(XLogRecPtr) * XLOGbuffers);
	allocptr += sizeof(XLogRecPtr) * XLOGbuffers;

	
	allocptr = (char *) TYPEALIGN(ALIGNOF_XLOG_BUFFER, allocptr);
	XLogCtl->pages = allocptr;
	memset(XLogCtl->pages, 0, (Size) XLOG_BLCKSZ * XLOGbuffers);

	
	XLogCtl->XLogCacheBlck = XLOGbuffers - 1;
	XLogCtl->SharedRecoveryInProgress = true;
	XLogCtl->SharedHotStandbyActive = false;
	XLogCtl->WalWriterSleeping = false;
	XLogCtl->Insert.currpage = (XLogPageHeader) (XLogCtl->pages);
	SpinLockInit(&XLogCtl->info_lck);
	SpinLockInit(&XLogCtl->ulsn_lck);
	InitSharedLatch(&XLogCtl->recoveryWakeupLatch);

	
	if (!IsBootstrapProcessingMode())
		ReadControlFile();
}


void BootStrapXLOG(void)
{
	CheckPoint	checkPoint;
	char	   *buffer;
	XLogPageHeader page;
	XLogLongPageHeader longpage;
	XLogRecord *record;
	bool		use_existent;
	uint64		sysidentifier;
	struct timeval tv;
	pg_crc32	crc;

	
	gettimeofday(&tv, NULL);
	sysidentifier = ((uint64) tv.tv_sec) << 32;
	sysidentifier |= (uint32) (tv.tv_sec | tv.tv_usec);

	
	ThisTimeLineID = 1;

	
	buffer = (char *) palloc(XLOG_BLCKSZ + ALIGNOF_XLOG_BUFFER);
	page = (XLogPageHeader) TYPEALIGN(ALIGNOF_XLOG_BUFFER, buffer);
	memset(page, 0, XLOG_BLCKSZ);

	
	checkPoint.redo = XLogSegSize + SizeOfXLogLongPHD;
	checkPoint.ThisTimeLineID = ThisTimeLineID;
	checkPoint.PrevTimeLineID = ThisTimeLineID;
	checkPoint.fullPageWrites = fullPageWrites;
	checkPoint.nextXidEpoch = 0;
	checkPoint.nextXid = FirstNormalTransactionId;
	checkPoint.nextOid = FirstBootstrapObjectId;
	checkPoint.nextMulti = FirstMultiXactId;
	checkPoint.nextMultiOffset = 0;
	checkPoint.oldestXid = FirstNormalTransactionId;
	checkPoint.oldestXidDB = TemplateDbOid;
	checkPoint.oldestMulti = FirstMultiXactId;
	checkPoint.oldestMultiDB = TemplateDbOid;
	checkPoint.time = (pg_time_t) time(NULL);
	checkPoint.oldestActiveXid = InvalidTransactionId;

	ShmemVariableCache->nextXid = checkPoint.nextXid;
	ShmemVariableCache->nextOid = checkPoint.nextOid;
	ShmemVariableCache->oidCount = 0;
	MultiXactSetNextMXact(checkPoint.nextMulti, checkPoint.nextMultiOffset);
	SetTransactionIdLimit(checkPoint.oldestXid, checkPoint.oldestXidDB);
	SetMultiXactIdLimit(checkPoint.oldestMulti, checkPoint.oldestMultiDB);

	
	page->xlp_magic = XLOG_PAGE_MAGIC;
	page->xlp_info = XLP_LONG_HEADER;
	page->xlp_tli = ThisTimeLineID;
	page->xlp_pageaddr = XLogSegSize;
	longpage = (XLogLongPageHeader) page;
	longpage->xlp_sysid = sysidentifier;
	longpage->xlp_seg_size = XLogSegSize;
	longpage->xlp_xlog_blcksz = XLOG_BLCKSZ;

	
	record = (XLogRecord *) ((char *) page + SizeOfXLogLongPHD);
	record->xl_prev = 0;
	record->xl_xid = InvalidTransactionId;
	record->xl_tot_len = SizeOfXLogRecord + sizeof(checkPoint);
	record->xl_len = sizeof(checkPoint);
	record->xl_info = XLOG_CHECKPOINT_SHUTDOWN;
	record->xl_rmid = RM_XLOG_ID;
	memcpy(XLogRecGetData(record), &checkPoint, sizeof(checkPoint));

	INIT_CRC32(crc);
	COMP_CRC32(crc, &checkPoint, sizeof(checkPoint));
	COMP_CRC32(crc, (char *) record, offsetof(XLogRecord, xl_crc));
	FIN_CRC32(crc);
	record->xl_crc = crc;

	
	use_existent = false;
	openLogFile = XLogFileInit(1, &use_existent, false);

	
	errno = 0;
	if (write(openLogFile, page, XLOG_BLCKSZ) != XLOG_BLCKSZ)
	{
		
		if (errno == 0)
			errno = ENOSPC;
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not write bootstrap transaction log file: %m")));

	}

	if (pg_fsync(openLogFile) != 0)
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not fsync bootstrap transaction log file: %m")));


	if (close(openLogFile))
		ereport(PANIC, (errcode_for_file_access(), errmsg("could not close bootstrap transaction log file: %m")));


	openLogFile = -1;

	

	memset(ControlFile, 0, sizeof(ControlFileData));
	
	ControlFile->system_identifier = sysidentifier;
	ControlFile->state = DB_SHUTDOWNED;
	ControlFile->time = checkPoint.time;
	ControlFile->checkPoint = checkPoint.redo;
	ControlFile->checkPointCopy = checkPoint;
	ControlFile->unloggedLSN = 1;

	
	ControlFile->MaxConnections = MaxConnections;
	ControlFile->max_prepared_xacts = max_prepared_xacts;
	ControlFile->max_locks_per_xact = max_locks_per_xact;
	ControlFile->wal_level = wal_level;
	ControlFile->data_checksums = bootstrap_data_checksums;

	

	WriteControlFile();

	
	BootStrapCLOG();
	BootStrapSUBTRANS();
	BootStrapMultiXact();

	pfree(buffer);
}

static char * str_time(pg_time_t tnow)
{
	static char buf[128];

	pg_strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", pg_localtime(&tnow, log_timezone));


	return buf;
}


static void readRecoveryCommandFile(void)
{
	FILE	   *fd;
	TimeLineID	rtli = 0;
	bool		rtliGiven = false;
	ConfigVariable *item, *head = NULL, *tail = NULL;


	fd = AllocateFile(RECOVERY_COMMAND_FILE, "r");
	if (fd == NULL)
	{
		if (errno == ENOENT)
			return;				
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not open recovery command file \"%s\": %m", RECOVERY_COMMAND_FILE)));


	}

	
	(void) ParseConfigFp(fd, RECOVERY_COMMAND_FILE, 0, FATAL, &head, &tail);

	FreeFile(fd);

	for (item = head; item; item = item->next)
	{
		if (strcmp(item->name, "restore_command") == 0)
		{
			recoveryRestoreCommand = pstrdup(item->value);
			ereport(DEBUG2, (errmsg_internal("restore_command = '%s'", recoveryRestoreCommand)));

		}
		else if (strcmp(item->name, "recovery_end_command") == 0)
		{
			recoveryEndCommand = pstrdup(item->value);
			ereport(DEBUG2, (errmsg_internal("recovery_end_command = '%s'", recoveryEndCommand)));

		}
		else if (strcmp(item->name, "archive_cleanup_command") == 0)
		{
			archiveCleanupCommand = pstrdup(item->value);
			ereport(DEBUG2, (errmsg_internal("archive_cleanup_command = '%s'", archiveCleanupCommand)));

		}
		else if (strcmp(item->name, "pause_at_recovery_target") == 0)
		{
			if (!parse_bool(item->value, &recoveryPauseAtTarget))
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a Boolean value", "pause_at_recovery_target")));

			ereport(DEBUG2, (errmsg_internal("pause_at_recovery_target = '%s'", item->value)));

		}
		else if (strcmp(item->name, "recovery_target_timeline") == 0)
		{
			rtliGiven = true;
			if (strcmp(item->value, "latest") == 0)
				rtli = 0;
			else {
				errno = 0;
				rtli = (TimeLineID) strtoul(item->value, NULL, 0);
				if (errno == EINVAL || errno == ERANGE)
					ereport(FATAL, (errmsg("recovery_target_timeline is not a valid number: \"%s\"", item->value)));

			}
			if (rtli)
				ereport(DEBUG2, (errmsg_internal("recovery_target_timeline = %u", rtli)));
			else ereport(DEBUG2, (errmsg_internal("recovery_target_timeline = latest")));

		}
		else if (strcmp(item->name, "recovery_target_xid") == 0)
		{
			errno = 0;
			recoveryTargetXid = (TransactionId) strtoul(item->value, NULL, 0);
			if (errno == EINVAL || errno == ERANGE)
				ereport(FATAL, (errmsg("recovery_target_xid is not a valid number: \"%s\"", item->value)));

			ereport(DEBUG2, (errmsg_internal("recovery_target_xid = %u", recoveryTargetXid)));

			recoveryTarget = RECOVERY_TARGET_XID;
		}
		else if (strcmp(item->name, "recovery_target_time") == 0)
		{
			
			if (recoveryTarget == RECOVERY_TARGET_XID || recoveryTarget == RECOVERY_TARGET_NAME)
				continue;
			recoveryTarget = RECOVERY_TARGET_TIME;

			
			recoveryTargetTime = DatumGetTimestampTz(DirectFunctionCall3(timestamptz_in, CStringGetDatum(item->value), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1)));



			ereport(DEBUG2, (errmsg_internal("recovery_target_time = '%s'", timestamptz_to_str(recoveryTargetTime))));

		}
		else if (strcmp(item->name, "recovery_target_name") == 0)
		{
			
			if (recoveryTarget == RECOVERY_TARGET_XID)
				continue;
			recoveryTarget = RECOVERY_TARGET_NAME;

			recoveryTargetName = pstrdup(item->value);
			if (strlen(recoveryTargetName) >= MAXFNAMELEN)
				ereport(FATAL, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("recovery_target_name is too long (maximum %d characters)", MAXFNAMELEN - 1)));



			ereport(DEBUG2, (errmsg_internal("recovery_target_name = '%s'", recoveryTargetName)));

		}
		else if (strcmp(item->name, "recovery_target_inclusive") == 0)
		{
			
			if (!parse_bool(item->value, &recoveryTargetInclusive))
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a Boolean value", "recovery_target_inclusive")));


			ereport(DEBUG2, (errmsg_internal("recovery_target_inclusive = %s", item->value)));

		}
		else if (strcmp(item->name, "standby_mode") == 0)
		{
			if (!parse_bool(item->value, &StandbyModeRequested))
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a Boolean value", "standby_mode")));


			ereport(DEBUG2, (errmsg_internal("standby_mode = '%s'", item->value)));
		}
		else if (strcmp(item->name, "primary_conninfo") == 0)
		{
			PrimaryConnInfo = pstrdup(item->value);
			ereport(DEBUG2, (errmsg_internal("primary_conninfo = '%s'", PrimaryConnInfo)));

		}
		else if (strcmp(item->name, "trigger_file") == 0)
		{
			TriggerFile = pstrdup(item->value);
			ereport(DEBUG2, (errmsg_internal("trigger_file = '%s'", TriggerFile)));

		}
		else ereport(FATAL, (errmsg("unrecognized recovery parameter \"%s\"", item->name)));


	}

	
	if (StandbyModeRequested)
	{
		if (PrimaryConnInfo == NULL && recoveryRestoreCommand == NULL)
			ereport(WARNING, (errmsg("recovery command file \"%s\" specified neither primary_conninfo nor restore_command", RECOVERY_COMMAND_FILE), errhint("The database server will regularly poll the pg_xlog subdirectory to check for files placed there.")));


	}
	else {
		if (recoveryRestoreCommand == NULL)
			ereport(FATAL, (errmsg("recovery command file \"%s\" must specify restore_command when standby mode is not enabled", RECOVERY_COMMAND_FILE)));

	}

	
	ArchiveRecoveryRequested = true;

	
	if (rtliGiven)
	{
		if (rtli)
		{
			
			if (rtli != 1 && !existsTimeLineHistory(rtli))
				ereport(FATAL, (errmsg("recovery target timeline %u does not exist", rtli)));

			recoveryTargetTLI = rtli;
			recoveryTargetIsLatest = false;
		}
		else {
			
			recoveryTargetTLI = findNewestTimeLine(recoveryTargetTLI);
			recoveryTargetIsLatest = true;
		}
	}

	FreeConfigVariables(head);
}


static void exitArchiveRecovery(TimeLineID endTLI, XLogSegNo endLogSegNo)
{
	char		recoveryPath[MAXPGPATH];
	char		xlogpath[MAXPGPATH];

	
	InArchiveRecovery = false;

	
	UpdateMinRecoveryPoint(InvalidXLogRecPtr, true);

	
	if (readFile >= 0)
	{
		close(readFile);
		readFile = -1;
	}

	
	if (endTLI != ThisTimeLineID)
	{
		XLogFileCopy(endLogSegNo, endTLI, endLogSegNo);

		if (XLogArchivingActive())
		{
			XLogFileName(xlogpath, endTLI, endLogSegNo);
			XLogArchiveNotify(xlogpath);
		}
	}

	
	XLogFileName(xlogpath, ThisTimeLineID, endLogSegNo);
	XLogArchiveCleanup(xlogpath);

	
	snprintf(recoveryPath, MAXPGPATH, XLOGDIR "/RECOVERYXLOG");
	unlink(recoveryPath);		

	
	snprintf(recoveryPath, MAXPGPATH, XLOGDIR "/RECOVERYHISTORY");
	unlink(recoveryPath);		

	
	unlink(RECOVERY_COMMAND_DONE);
	if (rename(RECOVERY_COMMAND_FILE, RECOVERY_COMMAND_DONE) != 0)
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not rename file \"%s\" to \"%s\": %m", RECOVERY_COMMAND_FILE, RECOVERY_COMMAND_DONE)));



	ereport(LOG, (errmsg("archive recovery complete")));
}


static bool recoveryStopsHere(XLogRecord *record, bool *includeThis)
{
	bool		stopsHere;
	uint8		record_info;
	TimestampTz recordXtime;
	char		recordRPName[MAXFNAMELEN];

	
	if (record->xl_rmid != RM_XACT_ID && record->xl_rmid != RM_XLOG_ID)
		return false;
	record_info = record->xl_info & ~XLR_INFO_MASK;
	if (record->xl_rmid == RM_XACT_ID && record_info == XLOG_XACT_COMMIT_COMPACT)
	{
		xl_xact_commit_compact *recordXactCommitData;

		recordXactCommitData = (xl_xact_commit_compact *) XLogRecGetData(record);
		recordXtime = recordXactCommitData->xact_time;
	}
	else if (record->xl_rmid == RM_XACT_ID && record_info == XLOG_XACT_COMMIT)
	{
		xl_xact_commit *recordXactCommitData;

		recordXactCommitData = (xl_xact_commit *) XLogRecGetData(record);
		recordXtime = recordXactCommitData->xact_time;
	}
	else if (record->xl_rmid == RM_XACT_ID && record_info == XLOG_XACT_ABORT)
	{
		xl_xact_abort *recordXactAbortData;

		recordXactAbortData = (xl_xact_abort *) XLogRecGetData(record);
		recordXtime = recordXactAbortData->xact_time;
	}
	else if (record->xl_rmid == RM_XLOG_ID && record_info == XLOG_RESTORE_POINT)
	{
		xl_restore_point *recordRestorePointData;

		recordRestorePointData = (xl_restore_point *) XLogRecGetData(record);
		recordXtime = recordRestorePointData->rp_time;
		strncpy(recordRPName, recordRestorePointData->rp_name, MAXFNAMELEN);
	}
	else return false;

	
	if (recoveryTarget == RECOVERY_TARGET_UNSET)
	{
		
		if (record->xl_rmid == RM_XACT_ID)
			SetLatestXTime(recordXtime);
		return false;
	}

	if (recoveryTarget == RECOVERY_TARGET_XID)
	{
		
		stopsHere = (record->xl_xid == recoveryTargetXid);
		if (stopsHere)
			*includeThis = recoveryTargetInclusive;
	}
	else if (recoveryTarget == RECOVERY_TARGET_NAME)
	{
		
		stopsHere = (strcmp(recordRPName, recoveryTargetName) == 0);

		
		*includeThis = false;
	}
	else {
		
		if (recoveryTargetInclusive)
			stopsHere = (recordXtime > recoveryTargetTime);
		else stopsHere = (recordXtime >= recoveryTargetTime);
		if (stopsHere)
			*includeThis = false;
	}

	if (stopsHere)
	{
		recoveryStopXid = record->xl_xid;
		recoveryStopTime = recordXtime;
		recoveryStopAfter = *includeThis;

		if (record_info == XLOG_XACT_COMMIT_COMPACT || record_info == XLOG_XACT_COMMIT)
		{
			if (recoveryStopAfter)
				ereport(LOG, (errmsg("recovery stopping after commit of transaction %u, time %s", recoveryStopXid, timestamptz_to_str(recoveryStopTime))));


			else ereport(LOG, (errmsg("recovery stopping before commit of transaction %u, time %s", recoveryStopXid, timestamptz_to_str(recoveryStopTime))));



		}
		else if (record_info == XLOG_XACT_ABORT)
		{
			if (recoveryStopAfter)
				ereport(LOG, (errmsg("recovery stopping after abort of transaction %u, time %s", recoveryStopXid, timestamptz_to_str(recoveryStopTime))));


			else ereport(LOG, (errmsg("recovery stopping before abort of transaction %u, time %s", recoveryStopXid, timestamptz_to_str(recoveryStopTime))));



		}
		else {
			strncpy(recoveryStopName, recordRPName, MAXFNAMELEN);

			ereport(LOG, (errmsg("recovery stopping at restore point \"%s\", time %s", recoveryStopName, timestamptz_to_str(recoveryStopTime))));


		}

		
		if (record->xl_rmid == RM_XACT_ID && recoveryStopAfter)
			SetLatestXTime(recordXtime);
	}
	else if (record->xl_rmid == RM_XACT_ID)
		SetLatestXTime(recordXtime);

	return stopsHere;
}


static void recoveryPausesHere(void)
{
	
	if (!LocalHotStandbyActive)
		return;

	ereport(LOG, (errmsg("recovery has paused"), errhint("Execute pg_xlog_replay_resume() to continue.")));


	while (RecoveryIsPaused())
	{
		pg_usleep(1000000L);	
		HandleStartupProcInterrupts();
	}
}

bool RecoveryIsPaused(void)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	bool		recoveryPause;

	SpinLockAcquire(&xlogctl->info_lck);
	recoveryPause = xlogctl->recoveryPause;
	SpinLockRelease(&xlogctl->info_lck);

	return recoveryPause;
}

void SetRecoveryPause(bool recoveryPause)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;

	SpinLockAcquire(&xlogctl->info_lck);
	xlogctl->recoveryPause = recoveryPause;
	SpinLockRelease(&xlogctl->info_lck);
}


static void SetLatestXTime(TimestampTz xtime)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;

	SpinLockAcquire(&xlogctl->info_lck);
	xlogctl->recoveryLastXTime = xtime;
	SpinLockRelease(&xlogctl->info_lck);
}


TimestampTz GetLatestXTime(void)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	TimestampTz xtime;

	SpinLockAcquire(&xlogctl->info_lck);
	xtime = xlogctl->recoveryLastXTime;
	SpinLockRelease(&xlogctl->info_lck);

	return xtime;
}


static void SetCurrentChunkStartTime(TimestampTz xtime)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;

	SpinLockAcquire(&xlogctl->info_lck);
	xlogctl->currentChunkStartTime = xtime;
	SpinLockRelease(&xlogctl->info_lck);
}


TimestampTz GetCurrentChunkReplayStartTime(void)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	TimestampTz xtime;

	SpinLockAcquire(&xlogctl->info_lck);
	xtime = xlogctl->currentChunkStartTime;
	SpinLockRelease(&xlogctl->info_lck);

	return xtime;
}


void GetXLogReceiptTime(TimestampTz *rtime, bool *fromStream)
{
	
	Assert(InRecovery);

	*rtime = XLogReceiptTime;
	*fromStream = (XLogReceiptSource == XLOG_FROM_STREAM);
}















static void CheckRequiredParameterValues(void)
{
	
	if (InArchiveRecovery && ControlFile->wal_level == WAL_LEVEL_MINIMAL)
	{
		ereport(WARNING, (errmsg("WAL was generated with wal_level=minimal, data may be missing"), errhint("This happens if you temporarily set wal_level=minimal without taking a new base backup.")));

	}

	
	if (InArchiveRecovery && EnableHotStandby)
	{
		if (ControlFile->wal_level < WAL_LEVEL_HOT_STANDBY)
			ereport(ERROR, (errmsg("hot standby is not possible because wal_level was not set to \"hot_standby\" on the master server"), errhint("Either set wal_level to \"hot_standby\" on the master, or turn off hot_standby here.")));


		
		RecoveryRequiresIntParameter("max_connections", MaxConnections, ControlFile->MaxConnections);

		RecoveryRequiresIntParameter("max_prepared_transactions", max_prepared_xacts, ControlFile->max_prepared_xacts);

		RecoveryRequiresIntParameter("max_locks_per_transaction", max_locks_per_xact, ControlFile->max_locks_per_xact);

	}
}


void StartupXLOG(void)
{
	XLogCtlInsert *Insert;
	CheckPoint	checkPoint;
	bool		wasShutdown;
	bool		reachedStopPoint = false;
	bool		haveBackupLabel = false;
	XLogRecPtr	RecPtr, checkPointLoc, EndOfLog;

	XLogSegNo	endLogSegNo;
	TimeLineID	PrevTimeLineID;
	XLogRecord *record;
	uint32		freespace;
	TransactionId oldestActiveXID;
	bool		backupEndRequired = false;
	bool		backupFromStandby = false;
	DBState		dbstate_at_startup;
	XLogReaderState *xlogreader;
	XLogPageReadPrivate private;
	bool		fast_promoted = false;

	
	ReadControlFile();

	if (ControlFile->state < DB_SHUTDOWNED || ControlFile->state > DB_IN_PRODUCTION || !XRecOffIsValid(ControlFile->checkPoint))

		ereport(FATAL, (errmsg("control file contains invalid data")));

	if (ControlFile->state == DB_SHUTDOWNED)
		ereport(LOG, (errmsg("database system was shut down at %s", str_time(ControlFile->time))));

	else if (ControlFile->state == DB_SHUTDOWNED_IN_RECOVERY)
		ereport(LOG, (errmsg("database system was shut down in recovery at %s", str_time(ControlFile->time))));

	else if (ControlFile->state == DB_SHUTDOWNING)
		ereport(LOG, (errmsg("database system shutdown was interrupted; last known up at %s", str_time(ControlFile->time))));

	else if (ControlFile->state == DB_IN_CRASH_RECOVERY)
		ereport(LOG, (errmsg("database system was interrupted while in recovery at %s", str_time(ControlFile->time)), errhint("This probably means that some data is corrupted and" " you will have to use the last backup for recovery.")));



	else if (ControlFile->state == DB_IN_ARCHIVE_RECOVERY)
		ereport(LOG, (errmsg("database system was interrupted while in recovery at log time %s", str_time(ControlFile->checkPointCopy.time)), errhint("If this has occurred more than once some data might be corrupted" " and you might need to choose an earlier recovery target.")));



	else if (ControlFile->state == DB_IN_PRODUCTION)
		ereport(LOG, (errmsg("database system was interrupted; last known up at %s", str_time(ControlFile->time))));


	

	if (ControlFile->state != DB_SHUTDOWNED)
		pg_usleep(60000000L);


	
	ValidateXLOGDirectoryStructure();

	
	RelationCacheInitFileRemove();

	
	recoveryTargetTLI = ControlFile->checkPointCopy.ThisTimeLineID;

	
	readRecoveryCommandFile();

	
	strncpy(XLogCtl->archiveCleanupCommand, archiveCleanupCommand ? archiveCleanupCommand : "", sizeof(XLogCtl->archiveCleanupCommand));


	if (ArchiveRecoveryRequested)
	{
		if (StandbyModeRequested)
			ereport(LOG, (errmsg("entering standby mode")));
		else if (recoveryTarget == RECOVERY_TARGET_XID)
			ereport(LOG, (errmsg("starting point-in-time recovery to XID %u", recoveryTargetXid)));

		else if (recoveryTarget == RECOVERY_TARGET_TIME)
			ereport(LOG, (errmsg("starting point-in-time recovery to %s", timestamptz_to_str(recoveryTargetTime))));

		else if (recoveryTarget == RECOVERY_TARGET_NAME)
			ereport(LOG, (errmsg("starting point-in-time recovery to \"%s\"", recoveryTargetName)));

		else ereport(LOG, (errmsg("starting archive recovery")));

	}
	else if (ControlFile->minRecoveryPointTLI > 0)
	{
		
		Assert(ControlFile->minRecoveryPointTLI != 1);
		recoveryTargetTLI = ControlFile->minRecoveryPointTLI;
		recoveryTargetIsLatest = false;
	}

	
	if (StandbyModeRequested)
		OwnLatch(&XLogCtl->recoveryWakeupLatch);

	
	MemSet(&private, 0, sizeof(XLogPageReadPrivate));
	xlogreader = XLogReaderAllocate(&XLogPageRead, &private);
	if (!xlogreader)
		ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory"), errdetail("Failed while allocating an XLog reading processor")));


	xlogreader->system_identifier = ControlFile->system_identifier;

	if (read_backup_label(&checkPointLoc, &backupEndRequired, &backupFromStandby))
	{
		
		InArchiveRecovery = true;
		if (StandbyModeRequested)
			StandbyMode = true;

		
		record = ReadCheckpointRecord(xlogreader, checkPointLoc, 0, true);
		if (record != NULL)
		{
			memcpy(&checkPoint, XLogRecGetData(record), sizeof(CheckPoint));
			wasShutdown = (record->xl_info == XLOG_CHECKPOINT_SHUTDOWN);
			ereport(DEBUG1, (errmsg("checkpoint record is at %X/%X", (uint32) (checkPointLoc >> 32), (uint32) checkPointLoc)));

			InRecovery = true;	

			
			if (checkPoint.redo < checkPointLoc)
			{
				if (!ReadRecord(xlogreader, checkPoint.redo, LOG, false))
					ereport(FATAL, (errmsg("could not find redo location referenced by checkpoint record"), errhint("If you are not restoring from a backup, try removing the file \"%s/backup_label\".", DataDir)));

			}
		}
		else {
			ereport(FATAL, (errmsg("could not locate required checkpoint record"), errhint("If you are not restoring from a backup, try removing the file \"%s/backup_label\".", DataDir)));

			wasShutdown = false;	
		}
		
		haveBackupLabel = true;
	}
	else {
		
		if (ArchiveRecoveryRequested && (ControlFile->minRecoveryPoint != InvalidXLogRecPtr || ControlFile->backupEndRequired || ControlFile->backupEndPoint != InvalidXLogRecPtr || ControlFile->state == DB_SHUTDOWNED))



		{
			InArchiveRecovery = true;
			if (StandbyModeRequested)
				StandbyMode = true;
		}

		
		checkPointLoc = ControlFile->checkPoint;
		RedoStartLSN = ControlFile->checkPointCopy.redo;
		record = ReadCheckpointRecord(xlogreader, checkPointLoc, 1, true);
		if (record != NULL)
		{
			ereport(DEBUG1, (errmsg("checkpoint record is at %X/%X", (uint32) (checkPointLoc >> 32), (uint32) checkPointLoc)));

		}
		else if (StandbyMode)
		{
			
			ereport(PANIC, (errmsg("could not locate a valid checkpoint record")));
		}
		else {
			checkPointLoc = ControlFile->prevCheckPoint;
			record = ReadCheckpointRecord(xlogreader, checkPointLoc, 2, true);
			if (record != NULL)
			{
				ereport(LOG, (errmsg("using previous checkpoint record at %X/%X", (uint32) (checkPointLoc >> 32), (uint32) checkPointLoc)));

				InRecovery = true;		
			}
			else ereport(PANIC, (errmsg("could not locate a valid checkpoint record")));

		}
		memcpy(&checkPoint, XLogRecGetData(record), sizeof(CheckPoint));
		wasShutdown = (record->xl_info == XLOG_CHECKPOINT_SHUTDOWN);
	}

	
	Assert(expectedTLEs); 
	if (tliOfPointInHistory(checkPointLoc, expectedTLEs) != checkPoint.ThisTimeLineID)
	{
		XLogRecPtr switchpoint;

		
		switchpoint = tliSwitchPoint(ControlFile->checkPointCopy.ThisTimeLineID, expectedTLEs, NULL);
		ereport(FATAL, (errmsg("requested timeline %u is not a child of this server's history", recoveryTargetTLI), errdetail("Latest checkpoint is at %X/%X on timeline %u, but in the history of the requested timeline, the server forked off from that timeline at %X/%X", (uint32) (ControlFile->checkPoint >> 32), (uint32) ControlFile->checkPoint, ControlFile->checkPointCopy.ThisTimeLineID, (uint32) (switchpoint >> 32), (uint32) switchpoint)));







	}

	
	if (!XLogRecPtrIsInvalid(ControlFile->minRecoveryPoint) && tliOfPointInHistory(ControlFile->minRecoveryPoint - 1, expectedTLEs) != ControlFile->minRecoveryPointTLI)

		ereport(FATAL, (errmsg("requested timeline %u does not contain minimum recovery point %X/%X on timeline %u", recoveryTargetTLI, (uint32) (ControlFile->minRecoveryPoint >> 32), (uint32) ControlFile->minRecoveryPoint, ControlFile->minRecoveryPointTLI)));





	LastRec = RecPtr = checkPointLoc;

	ereport(DEBUG1, (errmsg("redo record is at %X/%X; shutdown %s", (uint32) (checkPoint.redo >> 32), (uint32) checkPoint.redo, wasShutdown ? "TRUE" : "FALSE")));


	ereport(DEBUG1, (errmsg("next transaction ID: %u/%u; next OID: %u", checkPoint.nextXidEpoch, checkPoint.nextXid, checkPoint.nextOid)));


	ereport(DEBUG1, (errmsg("next MultiXactId: %u; next MultiXactOffset: %u", checkPoint.nextMulti, checkPoint.nextMultiOffset)));

	ereport(DEBUG1, (errmsg("oldest unfrozen transaction ID: %u, in database %u", checkPoint.oldestXid, checkPoint.oldestXidDB)));

	ereport(DEBUG1, (errmsg("oldest MultiXactId: %u, in database %u", checkPoint.oldestMulti, checkPoint.oldestMultiDB)));

	if (!TransactionIdIsNormal(checkPoint.nextXid))
		ereport(PANIC, (errmsg("invalid next transaction ID")));

	
	ShmemVariableCache->nextXid = checkPoint.nextXid;
	ShmemVariableCache->nextOid = checkPoint.nextOid;
	ShmemVariableCache->oidCount = 0;
	MultiXactSetNextMXact(checkPoint.nextMulti, checkPoint.nextMultiOffset);
	SetTransactionIdLimit(checkPoint.oldestXid, checkPoint.oldestXidDB);
	SetMultiXactIdLimit(checkPoint.oldestMulti, checkPoint.oldestMultiDB);
	XLogCtl->ckptXidEpoch = checkPoint.nextXidEpoch;
	XLogCtl->ckptXid = checkPoint.nextXid;

	
	if (ControlFile->state == DB_SHUTDOWNED)
		XLogCtl->unloggedLSN = ControlFile->unloggedLSN;
	else XLogCtl->unloggedLSN = 1;

	
	ThisTimeLineID = checkPoint.ThisTimeLineID;

	
	restoreTimeLineHistoryFiles(ThisTimeLineID, recoveryTargetTLI);

	lastFullPageWrites = checkPoint.fullPageWrites;

	RedoRecPtr = XLogCtl->Insert.RedoRecPtr = checkPoint.redo;

	if (RecPtr < checkPoint.redo)
		ereport(PANIC, (errmsg("invalid redo in checkpoint record")));

	
	if (checkPoint.redo < RecPtr)
	{
		if (wasShutdown)
			ereport(PANIC, (errmsg("invalid redo record in shutdown checkpoint")));
		InRecovery = true;
	}
	else if (ControlFile->state != DB_SHUTDOWNED)
		InRecovery = true;
	else if (ArchiveRecoveryRequested)
	{
		
		InRecovery = true;
	}

	
	if (InRecovery)
	{
		int			rmid;

		
		volatile XLogCtlData *xlogctl = XLogCtl;

		
		dbstate_at_startup = ControlFile->state;
		if (InArchiveRecovery)
			ControlFile->state = DB_IN_ARCHIVE_RECOVERY;
		else {
			ereport(LOG, (errmsg("database system was not properly shut down; " "automatic recovery in progress")));

			if (recoveryTargetTLI > 0)
				ereport(LOG, (errmsg("crash recovery starts in timeline %u " "and has target timeline %u", ControlFile->checkPointCopy.ThisTimeLineID, recoveryTargetTLI)));



			ControlFile->state = DB_IN_CRASH_RECOVERY;
		}
		ControlFile->prevCheckPoint = ControlFile->checkPoint;
		ControlFile->checkPoint = checkPointLoc;
		ControlFile->checkPointCopy = checkPoint;
		if (InArchiveRecovery)
		{
			
			if (ControlFile->minRecoveryPoint < checkPoint.redo)
			{
				ControlFile->minRecoveryPoint = checkPoint.redo;
				ControlFile->minRecoveryPointTLI = checkPoint.ThisTimeLineID;
			}
		}

		
		if (haveBackupLabel)
		{
			ControlFile->backupStartPoint = checkPoint.redo;
			ControlFile->backupEndRequired = backupEndRequired;

			if (backupFromStandby)
			{
				if (dbstate_at_startup != DB_IN_ARCHIVE_RECOVERY)
					ereport(FATAL, (errmsg("backup_label contains data inconsistent with control file"), errhint("This means that the backup is corrupted and you will " "have to use another backup for recovery.")));


				ControlFile->backupEndPoint = ControlFile->minRecoveryPoint;
			}
		}
		ControlFile->time = (pg_time_t) time(NULL);
		
		UpdateControlFile();

		
		minRecoveryPoint = ControlFile->minRecoveryPoint;
		minRecoveryPointTLI = ControlFile->minRecoveryPointTLI;

		
		pgstat_reset_all();

		
		if (haveBackupLabel)
		{
			unlink(BACKUP_LABEL_OLD);
			if (rename(BACKUP_LABEL_FILE, BACKUP_LABEL_OLD) != 0)
				ereport(FATAL, (errcode_for_file_access(), errmsg("could not rename file \"%s\" to \"%s\": %m", BACKUP_LABEL_FILE, BACKUP_LABEL_OLD)));


		}

		
		CheckRequiredParameterValues();

		
		ResetUnloggedRelations(UNLOGGED_RELATION_CLEANUP);

		
		DeleteAllExportedSnapshotFiles();

		
		if (ArchiveRecoveryRequested && EnableHotStandby)
		{
			TransactionId *xids;
			int			nxids;

			ereport(DEBUG1, (errmsg("initializing for hot standby")));

			InitRecoveryTransactionEnvironment();

			if (wasShutdown)
				oldestActiveXID = PrescanPreparedTransactions(&xids, &nxids);
			else oldestActiveXID = checkPoint.oldestActiveXid;
			Assert(TransactionIdIsValid(oldestActiveXID));

			
			StartupCLOG();
			StartupSUBTRANS(oldestActiveXID);

			
			if (wasShutdown)
			{
				RunningTransactionsData running;
				TransactionId latestCompletedXid;

				
				running.xcnt = nxids;
				running.subxcnt = 0;
				running.subxid_overflow = false;
				running.nextXid = checkPoint.nextXid;
				running.oldestRunningXid = oldestActiveXID;
				latestCompletedXid = checkPoint.nextXid;
				TransactionIdRetreat(latestCompletedXid);
				Assert(TransactionIdIsNormal(latestCompletedXid));
				running.latestCompletedXid = latestCompletedXid;
				running.xids = xids;

				ProcArrayApplyRecoveryInfo(&running);

				StandbyRecoverPreparedTransactions(false);
			}
		}

		
		for (rmid = 0; rmid <= RM_MAX_ID; rmid++)
		{
			if (RmgrTable[rmid].rm_startup != NULL)
				RmgrTable[rmid].rm_startup();
		}

		
		SpinLockAcquire(&xlogctl->info_lck);
		xlogctl->replayEndRecPtr = ReadRecPtr;
		xlogctl->replayEndTLI = ThisTimeLineID;
		xlogctl->lastReplayedEndRecPtr = EndRecPtr;
		xlogctl->lastReplayedTLI = ThisTimeLineID;
		xlogctl->recoveryLastXTime = 0;
		xlogctl->currentChunkStartTime = 0;
		xlogctl->recoveryPause = false;
		SpinLockRelease(&xlogctl->info_lck);

		
		XLogReceiptTime = GetCurrentTimestamp();

		
		if (ArchiveRecoveryRequested && IsUnderPostmaster)
		{
			PublishStartupProcessInformation();
			SetForwardFsyncRequests();
			SendPostmasterSignal(PMSIGNAL_RECOVERY_STARTED);
			bgwriterLaunched = true;
		}

		
		CheckRecoveryConsistency();

		
		if (checkPoint.redo < RecPtr)
		{
			
			record = ReadRecord(xlogreader, checkPoint.redo, PANIC, false);
		}
		else {
			
			record = ReadRecord(xlogreader, InvalidXLogRecPtr, LOG, false);
		}

		if (record != NULL)
		{
			bool		recoveryContinue = true;
			bool		recoveryApply = true;
			ErrorContextCallback errcallback;
			TimestampTz xtime;

			InRedo = true;

			ereport(LOG, (errmsg("redo starts at %X/%X", (uint32) (ReadRecPtr >> 32), (uint32) ReadRecPtr)));


			
			do {
				bool switchedTLI = false;

				if (XLOG_DEBUG || (rmid == RM_XACT_ID && trace_recovery_messages <= DEBUG2) || (rmid != RM_XACT_ID && trace_recovery_messages <= DEBUG3))

				{
					StringInfoData buf;

					initStringInfo(&buf);
					appendStringInfo(&buf, "REDO @ %X/%X; LSN %X/%X: ", (uint32) (ReadRecPtr >> 32), (uint32) ReadRecPtr, (uint32) (EndRecPtr >> 32), (uint32) EndRecPtr);

					xlog_outrec(&buf, record);
					appendStringInfo(&buf, " - ");
					RmgrTable[record->xl_rmid].rm_desc(&buf, record->xl_info, XLogRecGetData(record));

					elog(LOG, "%s", buf.data);
					pfree(buf.data);
				}


				
				HandleStartupProcInterrupts();

				
				if (xlogctl->recoveryPause)
					recoveryPausesHere();

				
				if (recoveryStopsHere(record, &recoveryApply))
				{
					if (recoveryPauseAtTarget)
					{
						SetRecoveryPause(true);
						recoveryPausesHere();
					}
					reachedStopPoint = true;	
					recoveryContinue = false;

					
					if (!recoveryApply)
						break;
				}

				
				errcallback.callback = rm_redo_error_callback;
				errcallback.arg = (void *) record;
				errcallback.previous = error_context_stack;
				error_context_stack = &errcallback;

				
				if (TransactionIdFollowsOrEquals(record->xl_xid, ShmemVariableCache->nextXid))
				{
					LWLockAcquire(XidGenLock, LW_EXCLUSIVE);
					ShmemVariableCache->nextXid = record->xl_xid;
					TransactionIdAdvance(ShmemVariableCache->nextXid);
					LWLockRelease(XidGenLock);
				}

				
				if (record->xl_rmid == RM_XLOG_ID)
				{
					TimeLineID	newTLI = ThisTimeLineID;
					TimeLineID	prevTLI = ThisTimeLineID;
					uint8		info = record->xl_info & ~XLR_INFO_MASK;

					if (info == XLOG_CHECKPOINT_SHUTDOWN)
					{
						CheckPoint	checkPoint;

						memcpy(&checkPoint, XLogRecGetData(record), sizeof(CheckPoint));
						newTLI = checkPoint.ThisTimeLineID;
						prevTLI = checkPoint.PrevTimeLineID;
					}
					else if (info == XLOG_END_OF_RECOVERY)
					{
						xl_end_of_recovery	xlrec;

						memcpy(&xlrec, XLogRecGetData(record), sizeof(xl_end_of_recovery));
						newTLI = xlrec.ThisTimeLineID;
						prevTLI = xlrec.PrevTimeLineID;
					}

					if (newTLI != ThisTimeLineID)
					{
						
						checkTimeLineSwitch(EndRecPtr, newTLI, prevTLI);

						
						ThisTimeLineID = newTLI;
						switchedTLI = true;
					}
				}

				
				SpinLockAcquire(&xlogctl->info_lck);
				xlogctl->replayEndRecPtr = EndRecPtr;
				xlogctl->replayEndTLI = ThisTimeLineID;
				SpinLockRelease(&xlogctl->info_lck);

				
				if (standbyState >= STANDBY_INITIALIZED && TransactionIdIsValid(record->xl_xid))
					RecordKnownAssignedTransactionIds(record->xl_xid);

				
				RmgrTable[record->xl_rmid].rm_redo(EndRecPtr, record);

				
				error_context_stack = errcallback.previous;

				
				SpinLockAcquire(&xlogctl->info_lck);
				xlogctl->lastReplayedEndRecPtr = EndRecPtr;
				xlogctl->lastReplayedTLI = ThisTimeLineID;
				SpinLockRelease(&xlogctl->info_lck);

				
				LastRec = ReadRecPtr;

				
				CheckRecoveryConsistency();

				
				if (switchedTLI && AllowCascadeReplication())
					WalSndWakeup();

				
				if (!recoveryContinue)
					break;

				
				record = ReadRecord(xlogreader, InvalidXLogRecPtr, LOG, false);
			} while (record != NULL);

			

			ereport(LOG, (errmsg("redo done at %X/%X", (uint32) (ReadRecPtr >> 32), (uint32) ReadRecPtr)));

			xtime = GetLatestXTime();
			if (xtime)
				ereport(LOG, (errmsg("last completed transaction was at log time %s", timestamptz_to_str(xtime))));

			InRedo = false;
		}
		else {
			
			ereport(LOG, (errmsg("redo is not required")));
		}
	}

	
	ShutdownWalRcv();

	
	if (StandbyModeRequested)
		DisownLatch(&XLogCtl->recoveryWakeupLatch);

	
	StandbyMode = false;

	
	record = ReadRecord(xlogreader, LastRec, PANIC, false);
	EndOfLog = EndRecPtr;
	XLByteToPrevSeg(EndOfLog, endLogSegNo);

	
	if (InRecovery && (EndOfLog < minRecoveryPoint || !XLogRecPtrIsInvalid(ControlFile->backupStartPoint)))

	{
		if (reachedStopPoint)
		{
			
			ereport(FATAL, (errmsg("requested recovery stop point is before consistent recovery point")));
		}

		
		if (ArchiveRecoveryRequested || ControlFile->backupEndRequired)
		{
			if (ControlFile->backupEndRequired)
				ereport(FATAL, (errmsg("WAL ends before end of online backup"), errhint("All WAL generated while online backup was taken must be available at recovery.")));

			else if (!XLogRecPtrIsInvalid(ControlFile->backupStartPoint))
				ereport(FATAL, (errmsg("WAL ends before end of online backup"), errhint("Online backup started with pg_start_backup() must be ended with pg_stop_backup(), and all WAL up to that point must be available at recovery.")));

			else ereport(FATAL, (errmsg("WAL ends before consistent recovery point")));

		}
	}

	
	PrevTimeLineID = ThisTimeLineID;
	if (ArchiveRecoveryRequested)
	{
		char	reason[200];

		Assert(InArchiveRecovery);

		ThisTimeLineID = findNewestTimeLine(recoveryTargetTLI) + 1;
		ereport(LOG, (errmsg("selected new timeline ID: %u", ThisTimeLineID)));

		
		if (recoveryTarget == RECOVERY_TARGET_XID)
			snprintf(reason, sizeof(reason), "%s transaction %u", recoveryStopAfter ? "after" : "before", recoveryStopXid);


		else if (recoveryTarget == RECOVERY_TARGET_TIME)
			snprintf(reason, sizeof(reason), "%s %s\n", recoveryStopAfter ? "after" : "before", timestamptz_to_str(recoveryStopTime));


		else if (recoveryTarget == RECOVERY_TARGET_NAME)
			snprintf(reason, sizeof(reason), "at restore point \"%s\"", recoveryStopName);

		else snprintf(reason, sizeof(reason), "no recovery target specified");

		writeTimeLineHistory(ThisTimeLineID, recoveryTargetTLI, EndRecPtr, reason);
	}

	
	XLogCtl->ThisTimeLineID = ThisTimeLineID;
	XLogCtl->PrevTimeLineID = PrevTimeLineID;

	
	if (ArchiveRecoveryRequested)
		exitArchiveRecovery(xlogreader->readPageTLI, endLogSegNo);

	
	openLogSegNo = endLogSegNo;
	openLogFile = XLogFileOpen(openLogSegNo);
	openLogOff = 0;
	Insert = &XLogCtl->Insert;
	Insert->PrevRecord = LastRec;
	XLogCtl->xlblocks[0] = ((EndOfLog - 1) / XLOG_BLCKSZ + 1) * XLOG_BLCKSZ;

	
	if (EndOfLog % XLOG_BLCKSZ == 0)
	{
		memset(Insert->currpage, 0, XLOG_BLCKSZ);
	}
	else {
		Assert(readOff == (XLogCtl->xlblocks[0] - XLOG_BLCKSZ) % XLogSegSize);
		memcpy((char *) Insert->currpage, xlogreader->readBuf, XLOG_BLCKSZ);
	}
	Insert->currpos = (char *) Insert->currpage + (EndOfLog + XLOG_BLCKSZ - XLogCtl->xlblocks[0]);

	LogwrtResult.Write = LogwrtResult.Flush = EndOfLog;

	XLogCtl->LogwrtResult = LogwrtResult;

	XLogCtl->LogwrtRqst.Write = EndOfLog;
	XLogCtl->LogwrtRqst.Flush = EndOfLog;

	freespace = INSERT_FREESPACE(Insert);
	if (freespace > 0)
	{
		
		MemSet(Insert->currpos, 0, freespace);
		XLogCtl->Write.curridx = 0;
	}
	else {
		
		XLogCtl->Write.curridx = NextBufIdx(0);
	}

	
	oldestActiveXID = PrescanPreparedTransactions(NULL, NULL);

	
	Insert->fullPageWrites = lastFullPageWrites;
	LocalSetXLogInsertAllowed();
	UpdateFullPageWrites();
	LocalXLogInsertAllowed = -1;

	if (InRecovery)
	{
		int			rmid;

		
		LocalSetXLogInsertAllowed();

		
		for (rmid = 0; rmid <= RM_MAX_ID; rmid++)
		{
			if (RmgrTable[rmid].rm_cleanup != NULL)
				RmgrTable[rmid].rm_cleanup();
		}

		
		LocalXLogInsertAllowed = -1;

		
		if (bgwriterLaunched)
		{
			if (fast_promote)
			{
				checkPointLoc = ControlFile->prevCheckPoint;

				
				record = ReadCheckpointRecord(xlogreader, checkPointLoc, 1, false);
				if (record != NULL)
				{
					fast_promoted = true;
					CreateEndOfRecoveryRecord();
				}
			}

			if (!fast_promoted)
				RequestCheckpoint(CHECKPOINT_END_OF_RECOVERY | CHECKPOINT_IMMEDIATE | CHECKPOINT_WAIT);

		}
		else CreateCheckPoint(CHECKPOINT_END_OF_RECOVERY | CHECKPOINT_IMMEDIATE);

		
		if (recoveryEndCommand)
			ExecuteRecoveryCommand(recoveryEndCommand, "recovery_end_command", true);

	}

	
	PreallocXlogFiles(EndOfLog);

	
	if (InRecovery)
		ResetUnloggedRelations(UNLOGGED_RELATION_INIT);

	
	InRecovery = false;

	LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
	ControlFile->state = DB_IN_PRODUCTION;
	ControlFile->time = (pg_time_t) time(NULL);
	UpdateControlFile();
	LWLockRelease(ControlFileLock);

	
	XLogCtl->Write.lastSegSwitchTime = (pg_time_t) time(NULL);

	
	LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);
	ShmemVariableCache->latestCompletedXid = ShmemVariableCache->nextXid;
	TransactionIdRetreat(ShmemVariableCache->latestCompletedXid);
	LWLockRelease(ProcArrayLock);

	
	if (standbyState == STANDBY_DISABLED)
	{
		StartupCLOG();
		StartupSUBTRANS(oldestActiveXID);
	}

	
	StartupMultiXact();
	TrimCLOG();

	
	RecoverPreparedTransactions();

	
	if (standbyState != STANDBY_DISABLED)
		ShutdownRecoveryTransactionEnvironment();

	
	if (readFile >= 0)
	{
		close(readFile);
		readFile = -1;
	}
	XLogReaderFree(xlogreader);

	
	LocalSetXLogInsertAllowed();
	XLogReportParameters();

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		xlogctl->SharedRecoveryInProgress = false;
		SpinLockRelease(&xlogctl->info_lck);
	}

	
	WalSndWakeup();

	
	if (fast_promoted)
		RequestCheckpoint(0);
}


static void CheckRecoveryConsistency(void)
{
	
	if (XLogRecPtrIsInvalid(minRecoveryPoint))
		return;

	
	if (!XLogRecPtrIsInvalid(ControlFile->backupEndPoint) && ControlFile->backupEndPoint <= EndRecPtr)
	{
		
		elog(DEBUG1, "end of backup reached");

		LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);

		if (ControlFile->minRecoveryPoint < EndRecPtr)
			ControlFile->minRecoveryPoint = EndRecPtr;

		ControlFile->backupStartPoint = InvalidXLogRecPtr;
		ControlFile->backupEndPoint = InvalidXLogRecPtr;
		ControlFile->backupEndRequired = false;
		UpdateControlFile();

		LWLockRelease(ControlFileLock);
	}

	
	if (!reachedConsistency && !ControlFile->backupEndRequired && minRecoveryPoint <= XLogCtl->lastReplayedEndRecPtr && XLogRecPtrIsInvalid(ControlFile->backupStartPoint))

	{
		
		XLogCheckInvalidPages();

		reachedConsistency = true;
		ereport(LOG, (errmsg("consistent recovery state reached at %X/%X", (uint32) (XLogCtl->lastReplayedEndRecPtr >> 32), (uint32) XLogCtl->lastReplayedEndRecPtr)));


	}

	
	if (standbyState == STANDBY_SNAPSHOT_READY && !LocalHotStandbyActive && reachedConsistency && IsUnderPostmaster)


	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		xlogctl->SharedHotStandbyActive = true;
		SpinLockRelease(&xlogctl->info_lck);

		LocalHotStandbyActive = true;

		SendPostmasterSignal(PMSIGNAL_BEGIN_HOT_STANDBY);
	}
}


bool RecoveryInProgress(void)
{
	
	if (!LocalRecoveryInProgress)
		return false;
	else {
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		
		SpinLockAcquire(&xlogctl->info_lck);
		LocalRecoveryInProgress = xlogctl->SharedRecoveryInProgress;
		SpinLockRelease(&xlogctl->info_lck);

		
		if (!LocalRecoveryInProgress)
			InitXLOGAccess();

		return LocalRecoveryInProgress;
	}
}


bool HotStandbyActive(void)
{
	
	if (LocalHotStandbyActive)
		return true;
	else {
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		
		SpinLockAcquire(&xlogctl->info_lck);
		LocalHotStandbyActive = xlogctl->SharedHotStandbyActive;
		SpinLockRelease(&xlogctl->info_lck);

		return LocalHotStandbyActive;
	}
}


bool XLogInsertAllowed(void)
{
	
	if (LocalXLogInsertAllowed >= 0)
		return (bool) LocalXLogInsertAllowed;

	
	if (RecoveryInProgress())
		return false;

	
	LocalXLogInsertAllowed = 1;
	return true;
}


static void LocalSetXLogInsertAllowed(void)
{
	Assert(LocalXLogInsertAllowed == -1);
	LocalXLogInsertAllowed = 1;

	
	InitXLOGAccess();
}


static XLogRecord * ReadCheckpointRecord(XLogReaderState *xlogreader, XLogRecPtr RecPtr, int whichChkpt, bool report)

{
	XLogRecord *record;

	if (!XRecOffIsValid(RecPtr))
	{
		if (!report)
			return NULL;

		switch (whichChkpt)
		{
			case 1:
				ereport(LOG, (errmsg("invalid primary checkpoint link in control file")));
				break;
			case 2:
				ereport(LOG, (errmsg("invalid secondary checkpoint link in control file")));
				break;
			default:
				ereport(LOG, (errmsg("invalid checkpoint link in backup_label file")));
				break;
		}
		return NULL;
	}

	record = ReadRecord(xlogreader, RecPtr, LOG, true);

	if (record == NULL)
	{
		if (!report)
			return NULL;

		switch (whichChkpt)
		{
			case 1:
				ereport(LOG, (errmsg("invalid primary checkpoint record")));
				break;
			case 2:
				ereport(LOG, (errmsg("invalid secondary checkpoint record")));
				break;
			default:
				ereport(LOG, (errmsg("invalid checkpoint record")));
				break;
		}
		return NULL;
	}
	if (record->xl_rmid != RM_XLOG_ID)
	{
		switch (whichChkpt)
		{
			case 1:
				ereport(LOG, (errmsg("invalid resource manager ID in primary checkpoint record")));
				break;
			case 2:
				ereport(LOG, (errmsg("invalid resource manager ID in secondary checkpoint record")));
				break;
			default:
				ereport(LOG, (errmsg("invalid resource manager ID in checkpoint record")));
				break;
		}
		return NULL;
	}
	if (record->xl_info != XLOG_CHECKPOINT_SHUTDOWN && record->xl_info != XLOG_CHECKPOINT_ONLINE)
	{
		switch (whichChkpt)
		{
			case 1:
				ereport(LOG, (errmsg("invalid xl_info in primary checkpoint record")));
				break;
			case 2:
				ereport(LOG, (errmsg("invalid xl_info in secondary checkpoint record")));
				break;
			default:
				ereport(LOG, (errmsg("invalid xl_info in checkpoint record")));
				break;
		}
		return NULL;
	}
	if (record->xl_len != sizeof(CheckPoint) || record->xl_tot_len != SizeOfXLogRecord + sizeof(CheckPoint))
	{
		switch (whichChkpt)
		{
			case 1:
				ereport(LOG, (errmsg("invalid length of primary checkpoint record")));
				break;
			case 2:
				ereport(LOG, (errmsg("invalid length of secondary checkpoint record")));
				break;
			default:
				ereport(LOG, (errmsg("invalid length of checkpoint record")));
				break;
		}
		return NULL;
	}
	return record;
}


void InitXLOGAccess(void)
{
	
	ThisTimeLineID = XLogCtl->ThisTimeLineID;
	Assert(ThisTimeLineID != 0 || IsBootstrapProcessingMode());

	
	(void) GetRedoRecPtr();
}


XLogRecPtr GetRedoRecPtr(void)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;

	SpinLockAcquire(&xlogctl->info_lck);
	Assert(RedoRecPtr <= xlogctl->Insert.RedoRecPtr);
	RedoRecPtr = xlogctl->Insert.RedoRecPtr;
	SpinLockRelease(&xlogctl->info_lck);

	return RedoRecPtr;
}


XLogRecPtr GetInsertRecPtr(void)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	XLogRecPtr	recptr;

	SpinLockAcquire(&xlogctl->info_lck);
	recptr = xlogctl->LogwrtRqst.Write;
	SpinLockRelease(&xlogctl->info_lck);

	return recptr;
}


XLogRecPtr GetFlushRecPtr(void)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	XLogRecPtr	recptr;

	SpinLockAcquire(&xlogctl->info_lck);
	recptr = xlogctl->LogwrtResult.Flush;
	SpinLockRelease(&xlogctl->info_lck);

	return recptr;
}


pg_time_t GetLastSegSwitchTime(void)
{
	pg_time_t	result;

	
	LWLockAcquire(WALWriteLock, LW_SHARED);
	result = XLogCtl->Write.lastSegSwitchTime;
	LWLockRelease(WALWriteLock);

	return result;
}


void GetNextXidAndEpoch(TransactionId *xid, uint32 *epoch)
{
	uint32		ckptXidEpoch;
	TransactionId ckptXid;
	TransactionId nextXid;

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		ckptXidEpoch = xlogctl->ckptXidEpoch;
		ckptXid = xlogctl->ckptXid;
		SpinLockRelease(&xlogctl->info_lck);
	}

	
	nextXid = ReadNewTransactionId();

	
	if (nextXid < ckptXid)
		ckptXidEpoch++;

	*xid = nextXid;
	*epoch = ckptXidEpoch;
}


void ShutdownXLOG(int code, Datum arg)
{
	ereport(LOG, (errmsg("shutting down")));

	if (RecoveryInProgress())
		CreateRestartPoint(CHECKPOINT_IS_SHUTDOWN | CHECKPOINT_IMMEDIATE);
	else {
		
		if (XLogArchivingActive() && XLogArchiveCommandSet())
			RequestXLogSwitch();

		CreateCheckPoint(CHECKPOINT_IS_SHUTDOWN | CHECKPOINT_IMMEDIATE);
	}
	ShutdownCLOG();
	ShutdownSUBTRANS();
	ShutdownMultiXact();

	ereport(LOG, (errmsg("database system is shut down")));
}


static void LogCheckpointStart(int flags, bool restartpoint)
{
	const char *msg;

	
	if (restartpoint)
		msg = "restartpoint starting:%s%s%s%s%s%s%s";
	else msg = "checkpoint starting:%s%s%s%s%s%s%s";

	elog(LOG, msg, (flags & CHECKPOINT_IS_SHUTDOWN) ? " shutdown" : "", (flags & CHECKPOINT_END_OF_RECOVERY) ? " end-of-recovery" : "", (flags & CHECKPOINT_IMMEDIATE) ? " immediate" : "", (flags & CHECKPOINT_FORCE) ? " force" : "", (flags & CHECKPOINT_WAIT) ? " wait" : "", (flags & CHECKPOINT_CAUSE_XLOG) ? " xlog" : "", (flags & CHECKPOINT_CAUSE_TIME) ? " time" : "");






}


static void LogCheckpointEnd(bool restartpoint)
{
	long		write_secs, sync_secs, total_secs, longest_secs, average_secs;



	int			write_usecs, sync_usecs, total_usecs, longest_usecs, average_usecs;



	uint64		average_sync_time;

	CheckpointStats.ckpt_end_t = GetCurrentTimestamp();

	TimestampDifference(CheckpointStats.ckpt_write_t, CheckpointStats.ckpt_sync_t, &write_secs, &write_usecs);


	TimestampDifference(CheckpointStats.ckpt_sync_t, CheckpointStats.ckpt_sync_end_t, &sync_secs, &sync_usecs);


	
	BgWriterStats.m_checkpoint_write_time += write_secs * 1000 + write_usecs / 1000;
	BgWriterStats.m_checkpoint_sync_time += sync_secs * 1000 + sync_usecs / 1000;

	
	if (!log_checkpoints)
		return;

	TimestampDifference(CheckpointStats.ckpt_start_t, CheckpointStats.ckpt_end_t, &total_secs, &total_usecs);


	
	longest_secs = (long) (CheckpointStats.ckpt_longest_sync / 1000000);
	longest_usecs = CheckpointStats.ckpt_longest_sync - (uint64) longest_secs *1000000;

	average_sync_time = 0;
	if (CheckpointStats.ckpt_sync_rels > 0)
		average_sync_time = CheckpointStats.ckpt_agg_sync_time / CheckpointStats.ckpt_sync_rels;
	average_secs = (long) (average_sync_time / 1000000);
	average_usecs = average_sync_time - (uint64) average_secs *1000000;

	if (restartpoint)
		elog(LOG, "restartpoint complete: wrote %d buffers (%.1f%%); " "%d transaction log file(s) added, %d removed, %d recycled; " "write=%ld.%03d s, sync=%ld.%03d s, total=%ld.%03d s; " "sync files=%d, longest=%ld.%03d s, average=%ld.%03d s", CheckpointStats.ckpt_bufs_written, (double) CheckpointStats.ckpt_bufs_written * 100 / NBuffers, CheckpointStats.ckpt_segs_added, CheckpointStats.ckpt_segs_removed, CheckpointStats.ckpt_segs_recycled, write_secs, write_usecs / 1000, sync_secs, sync_usecs / 1000, total_secs, total_usecs / 1000, CheckpointStats.ckpt_sync_rels, longest_secs, longest_usecs / 1000, average_secs, average_usecs / 1000);













	else elog(LOG, "checkpoint complete: wrote %d buffers (%.1f%%); " "%d transaction log file(s) added, %d removed, %d recycled; " "write=%ld.%03d s, sync=%ld.%03d s, total=%ld.%03d s; " "sync files=%d, longest=%ld.%03d s, average=%ld.%03d s", CheckpointStats.ckpt_bufs_written, (double) CheckpointStats.ckpt_bufs_written * 100 / NBuffers, CheckpointStats.ckpt_segs_added, CheckpointStats.ckpt_segs_removed, CheckpointStats.ckpt_segs_recycled, write_secs, write_usecs / 1000, sync_secs, sync_usecs / 1000, total_secs, total_usecs / 1000, CheckpointStats.ckpt_sync_rels, longest_secs, longest_usecs / 1000, average_secs, average_usecs / 1000);














}


void CreateCheckPoint(int flags)
{
	bool		shutdown;
	CheckPoint	checkPoint;
	XLogRecPtr	recptr;
	XLogCtlInsert *Insert = &XLogCtl->Insert;
	XLogRecData rdata;
	uint32		freespace;
	XLogSegNo	_logSegNo;
	VirtualTransactionId *vxids;
	int	nvxids;

	
	if (flags & (CHECKPOINT_IS_SHUTDOWN | CHECKPOINT_END_OF_RECOVERY))
		shutdown = true;
	else shutdown = false;

	
	if (RecoveryInProgress() && (flags & CHECKPOINT_END_OF_RECOVERY) == 0)
		elog(ERROR, "can't create a checkpoint during recovery");

	
	LWLockAcquire(CheckpointLock, LW_EXCLUSIVE);

	
	MemSet(&CheckpointStats, 0, sizeof(CheckpointStats));
	CheckpointStats.ckpt_start_t = GetCurrentTimestamp();

	
	START_CRIT_SECTION();

	if (shutdown)
	{
		LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
		ControlFile->state = DB_SHUTDOWNING;
		ControlFile->time = (pg_time_t) time(NULL);
		UpdateControlFile();
		LWLockRelease(ControlFileLock);
	}

	
	smgrpreckpt();

	
	MemSet(&checkPoint, 0, sizeof(checkPoint));
	checkPoint.time = (pg_time_t) time(NULL);

	
	if (!shutdown && XLogStandbyInfoActive())
		checkPoint.oldestActiveXid = GetOldestActiveTransactionId();
	else checkPoint.oldestActiveXid = InvalidTransactionId;

	
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);

	
	if ((flags & (CHECKPOINT_IS_SHUTDOWN | CHECKPOINT_END_OF_RECOVERY | CHECKPOINT_FORCE)) == 0)
	{
		XLogRecPtr	curInsert;

		INSERT_RECPTR(curInsert, Insert, Insert->curridx);
		if (curInsert == ControlFile->checkPoint +  MAXALIGN(SizeOfXLogRecord + sizeof(CheckPoint)) && ControlFile->checkPoint == ControlFile->checkPointCopy.redo)

		{
			LWLockRelease(WALInsertLock);
			LWLockRelease(CheckpointLock);
			END_CRIT_SECTION();
			return;
		}
	}

	
	if (flags & CHECKPOINT_END_OF_RECOVERY)
		LocalSetXLogInsertAllowed();

	checkPoint.ThisTimeLineID = ThisTimeLineID;
	if (flags & CHECKPOINT_END_OF_RECOVERY)
		checkPoint.PrevTimeLineID = XLogCtl->PrevTimeLineID;
	else checkPoint.PrevTimeLineID = ThisTimeLineID;

	checkPoint.fullPageWrites = Insert->fullPageWrites;

	
	freespace = INSERT_FREESPACE(Insert);
	if (freespace == 0)
	{
		(void) AdvanceXLInsertBuffer(false);
		
		freespace = INSERT_FREESPACE(Insert);
	}
	INSERT_RECPTR(checkPoint.redo, Insert, Insert->curridx);

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		RedoRecPtr = xlogctl->Insert.RedoRecPtr = checkPoint.redo;
		SpinLockRelease(&xlogctl->info_lck);
	}

	
	LWLockRelease(WALInsertLock);

	
	if (log_checkpoints)
		LogCheckpointStart(flags, false);

	TRACE_POSTGRESQL_CHECKPOINT_START(flags);

	
	vxids = GetVirtualXIDsDelayingChkpt(&nvxids);
	if (nvxids > 0)
	{
		uint32	nwaits = 0;

		do {
			pg_usleep(10000L);	
			nwaits++;
		} while (HaveVirtualXIDsDelayingChkpt(vxids, nvxids));
	}
	pfree(vxids);

	
	LWLockAcquire(XidGenLock, LW_SHARED);
	checkPoint.nextXid = ShmemVariableCache->nextXid;
	checkPoint.oldestXid = ShmemVariableCache->oldestXid;
	checkPoint.oldestXidDB = ShmemVariableCache->oldestXidDB;
	LWLockRelease(XidGenLock);

	
	checkPoint.nextXidEpoch = ControlFile->checkPointCopy.nextXidEpoch;
	if (checkPoint.nextXid < ControlFile->checkPointCopy.nextXid)
		checkPoint.nextXidEpoch++;

	LWLockAcquire(OidGenLock, LW_SHARED);
	checkPoint.nextOid = ShmemVariableCache->nextOid;
	if (!shutdown)
		checkPoint.nextOid += ShmemVariableCache->oidCount;
	LWLockRelease(OidGenLock);

	MultiXactGetCheckptMulti(shutdown, &checkPoint.nextMulti, &checkPoint.nextMultiOffset, &checkPoint.oldestMulti, &checkPoint.oldestMultiDB);




	
	END_CRIT_SECTION();

	CheckPointGuts(checkPoint.redo, flags);

	
	if (!shutdown && XLogStandbyInfoActive())
		LogStandbySnapshot();

	START_CRIT_SECTION();

	
	rdata.data = (char *) (&checkPoint);
	rdata.len = sizeof(checkPoint);
	rdata.buffer = InvalidBuffer;
	rdata.next = NULL;

	recptr = XLogInsert(RM_XLOG_ID, shutdown ? XLOG_CHECKPOINT_SHUTDOWN :
						XLOG_CHECKPOINT_ONLINE, &rdata);

	XLogFlush(recptr);

	
	if (shutdown)
	{
		if (flags & CHECKPOINT_END_OF_RECOVERY)
			LocalXLogInsertAllowed = -1;		
		else LocalXLogInsertAllowed = 0;
	}

	
	if (shutdown && checkPoint.redo != ProcLastRecPtr)
		ereport(PANIC, (errmsg("concurrent transaction log activity while database system is shutting down")));

	
	XLByteToSeg(ControlFile->checkPointCopy.redo, _logSegNo);

	
	LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
	if (shutdown)
		ControlFile->state = DB_SHUTDOWNED;
	ControlFile->prevCheckPoint = ControlFile->checkPoint;
	ControlFile->checkPoint = ProcLastRecPtr;
	ControlFile->checkPointCopy = checkPoint;
	ControlFile->time = (pg_time_t) time(NULL);
	
	ControlFile->minRecoveryPoint = InvalidXLogRecPtr;
	ControlFile->minRecoveryPointTLI = 0;

	
	SpinLockAcquire(&XLogCtl->ulsn_lck);
	ControlFile->unloggedLSN = XLogCtl->unloggedLSN;
	SpinLockRelease(&XLogCtl->ulsn_lck);

	UpdateControlFile();
	LWLockRelease(ControlFileLock);

	
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		xlogctl->ckptXidEpoch = checkPoint.nextXidEpoch;
		xlogctl->ckptXid = checkPoint.nextXid;
		SpinLockRelease(&xlogctl->info_lck);
	}

	
	END_CRIT_SECTION();

	
	smgrpostckpt();

	
	if (_logSegNo)
	{
		KeepLogSeg(recptr, &_logSegNo);
		_logSegNo--;
		RemoveOldXlogFiles(_logSegNo, recptr);
	}

	
	if (!shutdown)
		PreallocXlogFiles(recptr);

	
	if (!RecoveryInProgress())
		TruncateSUBTRANS(GetOldestXmin(true, false));

	
	LogCheckpointEnd(false);

	TRACE_POSTGRESQL_CHECKPOINT_DONE(CheckpointStats.ckpt_bufs_written, NBuffers, CheckpointStats.ckpt_segs_added, CheckpointStats.ckpt_segs_removed, CheckpointStats.ckpt_segs_recycled);




	LWLockRelease(CheckpointLock);
}


void CreateEndOfRecoveryRecord(void)
{
	xl_end_of_recovery	xlrec;
	XLogRecData			rdata;
	XLogRecPtr			recptr;

	
	if (!RecoveryInProgress())
		elog(ERROR, "can only be used to end recovery");

	xlrec.end_time = time(NULL);

	LWLockAcquire(WALInsertLock, LW_SHARED);
	xlrec.ThisTimeLineID = ThisTimeLineID;
	xlrec.PrevTimeLineID = XLogCtl->PrevTimeLineID;
	LWLockRelease(WALInsertLock);

	LocalSetXLogInsertAllowed();

	START_CRIT_SECTION();

	rdata.data = (char *) &xlrec;
	rdata.len = sizeof(xl_end_of_recovery);
	rdata.buffer = InvalidBuffer;
	rdata.next = NULL;

	recptr = XLogInsert(RM_XLOG_ID, XLOG_END_OF_RECOVERY, &rdata);

	XLogFlush(recptr);

	
	LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
	ControlFile->time = (pg_time_t) xlrec.end_time;
	ControlFile->minRecoveryPoint = recptr;
	ControlFile->minRecoveryPointTLI = ThisTimeLineID;
	UpdateControlFile();
	LWLockRelease(ControlFileLock);

	END_CRIT_SECTION();

	LocalXLogInsertAllowed = -1;		
}


static void CheckPointGuts(XLogRecPtr checkPointRedo, int flags)
{
	CheckPointCLOG();
	CheckPointSUBTRANS();
	CheckPointMultiXact();
	CheckPointPredicate();
	CheckPointRelationMap();
	CheckPointBuffers(flags);	
	
	CheckPointTwoPhase(checkPointRedo);
}


static void RecoveryRestartPoint(const CheckPoint *checkPoint)
{
	int			rmid;

	
	volatile XLogCtlData *xlogctl = XLogCtl;

	
	for (rmid = 0; rmid <= RM_MAX_ID; rmid++)
	{
		if (RmgrTable[rmid].rm_safe_restartpoint != NULL)
			if (!(RmgrTable[rmid].rm_safe_restartpoint()))
			{
				elog(trace_recovery(DEBUG2), "RM %d not safe to record restart point at %X/%X", rmid, (uint32) (checkPoint->redo >> 32), (uint32) checkPoint->redo);



				return;
			}
	}

	
	if (XLogHaveInvalidPages())
	{
		elog(trace_recovery(DEBUG2), "could not record restart point at %X/%X because there " "are unresolved references to invalid pages", (uint32) (checkPoint->redo >> 32), (uint32) checkPoint->redo);



		return;
	}

	
	SpinLockAcquire(&xlogctl->info_lck);
	xlogctl->lastCheckPointRecPtr = ReadRecPtr;
	xlogctl->lastCheckPoint = *checkPoint;
	SpinLockRelease(&xlogctl->info_lck);
}


bool CreateRestartPoint(int flags)
{
	XLogRecPtr	lastCheckPointRecPtr;
	CheckPoint	lastCheckPoint;
	XLogSegNo	_logSegNo;
	TimestampTz xtime;

	
	volatile XLogCtlData *xlogctl = XLogCtl;

	
	LWLockAcquire(CheckpointLock, LW_EXCLUSIVE);

	
	SpinLockAcquire(&xlogctl->info_lck);
	lastCheckPointRecPtr = xlogctl->lastCheckPointRecPtr;
	lastCheckPoint = xlogctl->lastCheckPoint;
	SpinLockRelease(&xlogctl->info_lck);

	
	if (!RecoveryInProgress())
	{
		ereport(DEBUG2, (errmsg("skipping restartpoint, recovery has already ended")));
		LWLockRelease(CheckpointLock);
		return false;
	}

	
	if (XLogRecPtrIsInvalid(lastCheckPointRecPtr) || lastCheckPoint.redo <= ControlFile->checkPointCopy.redo)
	{
		ereport(DEBUG2, (errmsg("skipping restartpoint, already performed at %X/%X", (uint32) (lastCheckPoint.redo >> 32), (uint32) lastCheckPoint.redo)));


		UpdateMinRecoveryPoint(InvalidXLogRecPtr, true);
		if (flags & CHECKPOINT_IS_SHUTDOWN)
		{
			LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
			ControlFile->state = DB_SHUTDOWNED_IN_RECOVERY;
			ControlFile->time = (pg_time_t) time(NULL);
			UpdateControlFile();
			LWLockRelease(ControlFileLock);
		}
		LWLockRelease(CheckpointLock);
		return false;
	}

	
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
	SpinLockAcquire(&xlogctl->info_lck);
	xlogctl->Insert.RedoRecPtr = lastCheckPoint.redo;
	SpinLockRelease(&xlogctl->info_lck);
	LWLockRelease(WALInsertLock);

	
	MemSet(&CheckpointStats, 0, sizeof(CheckpointStats));
	CheckpointStats.ckpt_start_t = GetCurrentTimestamp();

	if (log_checkpoints)
		LogCheckpointStart(flags, true);

	CheckPointGuts(lastCheckPoint.redo, flags);

	
	XLByteToSeg(ControlFile->checkPointCopy.redo, _logSegNo);

	
	LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
	if (ControlFile->state == DB_IN_ARCHIVE_RECOVERY && ControlFile->checkPointCopy.redo < lastCheckPoint.redo)
	{
		ControlFile->prevCheckPoint = ControlFile->checkPoint;
		ControlFile->checkPoint = lastCheckPointRecPtr;
		ControlFile->checkPointCopy = lastCheckPoint;
		ControlFile->time = (pg_time_t) time(NULL);
		if (flags & CHECKPOINT_IS_SHUTDOWN)
			ControlFile->state = DB_SHUTDOWNED_IN_RECOVERY;
		UpdateControlFile();
	}
	LWLockRelease(ControlFileLock);

	
	if (_logSegNo)
	{
		XLogRecPtr	receivePtr;
		XLogRecPtr	replayPtr;
		XLogRecPtr	endptr;

		
		receivePtr = GetWalRcvWriteRecPtr(NULL, NULL);
		replayPtr = GetXLogReplayRecPtr(NULL);
		endptr = (receivePtr < replayPtr) ? replayPtr : receivePtr;

		KeepLogSeg(endptr, &_logSegNo);
		_logSegNo--;

		
		(void) GetXLogReplayRecPtr(&ThisTimeLineID);

		RemoveOldXlogFiles(_logSegNo, endptr);

		
		PreallocXlogFiles(endptr);
	}

	
	if (EnableHotStandby)
		TruncateSUBTRANS(GetOldestXmin(true, false));

	
	LogCheckpointEnd(true);

	xtime = GetLatestXTime();
	ereport((log_checkpoints ? LOG : DEBUG2), (errmsg("recovery restart point at %X/%X", (uint32) (lastCheckPoint.redo >> 32), (uint32) lastCheckPoint.redo), xtime ? errdetail("last completed transaction was at log time %s", timestamptz_to_str(xtime)) : 0));




	LWLockRelease(CheckpointLock);

	
	if (XLogCtl->archiveCleanupCommand[0])
		ExecuteRecoveryCommand(XLogCtl->archiveCleanupCommand, "archive_cleanup_command", false);


	return true;
}


static void KeepLogSeg(XLogRecPtr recptr, XLogSegNo *logSegNo)
{
	XLogSegNo	segno;

	if (wal_keep_segments == 0)
		return;

	XLByteToSeg(recptr, segno);

	
	if (segno <= wal_keep_segments)
		segno = 1;
	else segno = *logSegNo - wal_keep_segments;

	
	if (segno < *logSegNo)
		*logSegNo = segno;
}


void XLogPutNextOid(Oid nextOid)
{
	XLogRecData rdata;

	rdata.data = (char *) (&nextOid);
	rdata.len = sizeof(Oid);
	rdata.buffer = InvalidBuffer;
	rdata.next = NULL;
	(void) XLogInsert(RM_XLOG_ID, XLOG_NEXTOID, &rdata);

	
}


XLogRecPtr RequestXLogSwitch(void)
{
	XLogRecPtr	RecPtr;
	XLogRecData rdata;

	
	rdata.buffer = InvalidBuffer;
	rdata.data = NULL;
	rdata.len = 0;
	rdata.next = NULL;

	RecPtr = XLogInsert(RM_XLOG_ID, XLOG_SWITCH, &rdata);

	return RecPtr;
}


XLogRecPtr XLogRestorePoint(const char *rpName)
{
	XLogRecPtr	RecPtr;
	XLogRecData rdata;
	xl_restore_point xlrec;

	xlrec.rp_time = GetCurrentTimestamp();
	strncpy(xlrec.rp_name, rpName, MAXFNAMELEN);

	rdata.buffer = InvalidBuffer;
	rdata.data = (char *) &xlrec;
	rdata.len = sizeof(xl_restore_point);
	rdata.next = NULL;

	RecPtr = XLogInsert(RM_XLOG_ID, XLOG_RESTORE_POINT, &rdata);

	ereport(LOG, (errmsg("restore point \"%s\" created at %X/%X", rpName, (uint32) (RecPtr >> 32), (uint32) RecPtr)));


	return RecPtr;
}



XLogRecPtr XLogSaveBufferForHint(Buffer buffer)
{
	
	XLogRecData rdata[2];
	int			watermark = XLOG_HINT_WATERMARK;

	
	rdata[0].data = (char *) (&watermark);
	rdata[0].len = sizeof(int);
	rdata[0].buffer = InvalidBuffer;
	rdata[0].buffer_std = false;
	rdata[0].next = &(rdata[1]);

	rdata[1].data = NULL;
	rdata[1].len = 0;
	rdata[1].buffer = buffer;
	rdata[1].buffer_std = true;
	rdata[1].next = NULL;

	return XLogInsert(RM_XLOG_ID, XLOG_HINT, rdata);
}


static void XLogReportParameters(void)
{
	if (wal_level != ControlFile->wal_level || MaxConnections != ControlFile->MaxConnections || max_prepared_xacts != ControlFile->max_prepared_xacts || max_locks_per_xact != ControlFile->max_locks_per_xact)


	{
		
		if (wal_level != ControlFile->wal_level || XLogIsNeeded())
		{
			XLogRecData rdata;
			xl_parameter_change xlrec;

			xlrec.MaxConnections = MaxConnections;
			xlrec.max_prepared_xacts = max_prepared_xacts;
			xlrec.max_locks_per_xact = max_locks_per_xact;
			xlrec.wal_level = wal_level;

			rdata.buffer = InvalidBuffer;
			rdata.data = (char *) &xlrec;
			rdata.len = sizeof(xlrec);
			rdata.next = NULL;

			XLogInsert(RM_XLOG_ID, XLOG_PARAMETER_CHANGE, &rdata);
		}

		ControlFile->MaxConnections = MaxConnections;
		ControlFile->max_prepared_xacts = max_prepared_xacts;
		ControlFile->max_locks_per_xact = max_locks_per_xact;
		ControlFile->wal_level = wal_level;
		UpdateControlFile();
	}
}


void UpdateFullPageWrites(void)
{
	XLogCtlInsert *Insert = &XLogCtl->Insert;

	
	if (fullPageWrites == Insert->fullPageWrites)
		return;

	START_CRIT_SECTION();

	
	if (fullPageWrites)
	{
		LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
		Insert->fullPageWrites = true;
		LWLockRelease(WALInsertLock);
	}

	
	if (XLogStandbyInfoActive() && !RecoveryInProgress())
	{
		XLogRecData rdata;

		rdata.data = (char *) (&fullPageWrites);
		rdata.len = sizeof(bool);
		rdata.buffer = InvalidBuffer;
		rdata.next = NULL;

		XLogInsert(RM_XLOG_ID, XLOG_FPW_CHANGE, &rdata);
	}

	if (!fullPageWrites)
	{
		LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
		Insert->fullPageWrites = false;
		LWLockRelease(WALInsertLock);
	}
	END_CRIT_SECTION();
}


static void checkTimeLineSwitch(XLogRecPtr lsn, TimeLineID newTLI, TimeLineID prevTLI)
{
	
	if (prevTLI != ThisTimeLineID)
		ereport(PANIC, (errmsg("unexpected prev timeline ID %u (current timeline ID %u) in checkpoint record", prevTLI, ThisTimeLineID)));

	
	if (newTLI < ThisTimeLineID || !tliInHistory(newTLI, expectedTLEs))
		ereport(PANIC, (errmsg("unexpected timeline ID %u (after %u) in checkpoint record", newTLI, ThisTimeLineID)));


	
	if (!XLogRecPtrIsInvalid(minRecoveryPoint) && lsn < minRecoveryPoint && newTLI > minRecoveryPointTLI)

		ereport(PANIC, (errmsg("unexpected timeline ID %u in checkpoint record, before reaching minimum recovery point %X/%X on timeline %u", newTLI, (uint32) (minRecoveryPoint >> 32), (uint32) minRecoveryPoint, minRecoveryPointTLI)));





	
}


void xlog_redo(XLogRecPtr lsn, XLogRecord *record)
{
	uint8		info = record->xl_info & ~XLR_INFO_MASK;

	
	Assert(info == XLOG_HINT || !(record->xl_info & XLR_BKP_BLOCK_MASK));

	if (info == XLOG_NEXTOID)
	{
		Oid			nextOid;

		
		memcpy(&nextOid, XLogRecGetData(record), sizeof(Oid));
		LWLockAcquire(OidGenLock, LW_EXCLUSIVE);
		ShmemVariableCache->nextOid = nextOid;
		ShmemVariableCache->oidCount = 0;
		LWLockRelease(OidGenLock);
	}
	else if (info == XLOG_CHECKPOINT_SHUTDOWN)
	{
		CheckPoint	checkPoint;

		memcpy(&checkPoint, XLogRecGetData(record), sizeof(CheckPoint));
		
		LWLockAcquire(XidGenLock, LW_EXCLUSIVE);
		ShmemVariableCache->nextXid = checkPoint.nextXid;
		LWLockRelease(XidGenLock);
		LWLockAcquire(OidGenLock, LW_EXCLUSIVE);
		ShmemVariableCache->nextOid = checkPoint.nextOid;
		ShmemVariableCache->oidCount = 0;
		LWLockRelease(OidGenLock);
		MultiXactSetNextMXact(checkPoint.nextMulti, checkPoint.nextMultiOffset);
		SetTransactionIdLimit(checkPoint.oldestXid, checkPoint.oldestXidDB);
		SetMultiXactIdLimit(checkPoint.oldestMulti, checkPoint.oldestMultiDB);

		
		if (ArchiveRecoveryRequested && !XLogRecPtrIsInvalid(ControlFile->backupStartPoint) && XLogRecPtrIsInvalid(ControlFile->backupEndPoint))

			ereport(PANIC, (errmsg("online backup was canceled, recovery cannot continue")));

		
		if (standbyState >= STANDBY_INITIALIZED)
		{
			TransactionId *xids;
			int			nxids;
			TransactionId oldestActiveXID;
			TransactionId latestCompletedXid;
			RunningTransactionsData running;

			oldestActiveXID = PrescanPreparedTransactions(&xids, &nxids);

			
			running.xcnt = nxids;
			running.subxcnt = 0;
			running.subxid_overflow = false;
			running.nextXid = checkPoint.nextXid;
			running.oldestRunningXid = oldestActiveXID;
			latestCompletedXid = checkPoint.nextXid;
			TransactionIdRetreat(latestCompletedXid);
			Assert(TransactionIdIsNormal(latestCompletedXid));
			running.latestCompletedXid = latestCompletedXid;
			running.xids = xids;

			ProcArrayApplyRecoveryInfo(&running);

			StandbyRecoverPreparedTransactions(true);
		}

		
		ControlFile->checkPointCopy.nextXidEpoch = checkPoint.nextXidEpoch;
		ControlFile->checkPointCopy.nextXid = checkPoint.nextXid;

		
		{
			
			volatile XLogCtlData *xlogctl = XLogCtl;

			SpinLockAcquire(&xlogctl->info_lck);
			xlogctl->ckptXidEpoch = checkPoint.nextXidEpoch;
			xlogctl->ckptXid = checkPoint.nextXid;
			SpinLockRelease(&xlogctl->info_lck);
		}

		
		if (checkPoint.ThisTimeLineID != ThisTimeLineID)
			ereport(PANIC, (errmsg("unexpected timeline ID %u (should be %u) in checkpoint record", checkPoint.ThisTimeLineID, ThisTimeLineID)));


		RecoveryRestartPoint(&checkPoint);
	}
	else if (info == XLOG_CHECKPOINT_ONLINE)
	{
		CheckPoint	checkPoint;

		memcpy(&checkPoint, XLogRecGetData(record), sizeof(CheckPoint));
		
		LWLockAcquire(XidGenLock, LW_EXCLUSIVE);
		if (TransactionIdPrecedes(ShmemVariableCache->nextXid, checkPoint.nextXid))
			ShmemVariableCache->nextXid = checkPoint.nextXid;
		LWLockRelease(XidGenLock);
		
		LWLockAcquire(OidGenLock, LW_EXCLUSIVE);
		ShmemVariableCache->nextOid = checkPoint.nextOid;
		ShmemVariableCache->oidCount = 0;
		LWLockRelease(OidGenLock);
		MultiXactAdvanceNextMXact(checkPoint.nextMulti, checkPoint.nextMultiOffset);
		if (TransactionIdPrecedes(ShmemVariableCache->oldestXid, checkPoint.oldestXid))
			SetTransactionIdLimit(checkPoint.oldestXid, checkPoint.oldestXidDB);
		MultiXactAdvanceOldest(checkPoint.oldestMulti, checkPoint.oldestMultiDB);

		
		ControlFile->checkPointCopy.nextXidEpoch = checkPoint.nextXidEpoch;
		ControlFile->checkPointCopy.nextXid = checkPoint.nextXid;

		
		{
			
			volatile XLogCtlData *xlogctl = XLogCtl;

			SpinLockAcquire(&xlogctl->info_lck);
			xlogctl->ckptXidEpoch = checkPoint.nextXidEpoch;
			xlogctl->ckptXid = checkPoint.nextXid;
			SpinLockRelease(&xlogctl->info_lck);
		}

		
		if (checkPoint.ThisTimeLineID != ThisTimeLineID)
			ereport(PANIC, (errmsg("unexpected timeline ID %u (should be %u) in checkpoint record", checkPoint.ThisTimeLineID, ThisTimeLineID)));


		RecoveryRestartPoint(&checkPoint);
	}
	else if (info == XLOG_END_OF_RECOVERY)
	{
		xl_end_of_recovery xlrec;

		memcpy(&xlrec, XLogRecGetData(record), sizeof(xl_end_of_recovery));

		

		
		if (xlrec.ThisTimeLineID != ThisTimeLineID)
			ereport(PANIC, (errmsg("unexpected timeline ID %u (should be %u) in checkpoint record", xlrec.ThisTimeLineID, ThisTimeLineID)));

	}
	else if (info == XLOG_NOOP)
	{
		
	}
	else if (info == XLOG_SWITCH)
	{
		
	}
	else if (info == XLOG_RESTORE_POINT)
	{
		
	}
	else if (info == XLOG_HINT)
	{

		int	*watermark = (int *) XLogRecGetData(record);


		
		Assert(*watermark == XLOG_HINT_WATERMARK);

		
		Assert(record->xl_info & XLR_BKP_BLOCK_MASK);

		
		RestoreBackupBlock(lsn, record, 0, false, false);
	}
	else if (info == XLOG_BACKUP_END)
	{
		XLogRecPtr	startpoint;

		memcpy(&startpoint, XLogRecGetData(record), sizeof(startpoint));

		if (ControlFile->backupStartPoint == startpoint)
		{
			
			elog(DEBUG1, "end of backup reached");

			LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);

			if (ControlFile->minRecoveryPoint < lsn)
			{
				ControlFile->minRecoveryPoint = lsn;
				ControlFile->minRecoveryPointTLI = ThisTimeLineID;
			}
			ControlFile->backupStartPoint = InvalidXLogRecPtr;
			ControlFile->backupEndRequired = false;
			UpdateControlFile();

			LWLockRelease(ControlFileLock);
		}
	}
	else if (info == XLOG_PARAMETER_CHANGE)
	{
		xl_parameter_change xlrec;

		
		memcpy(&xlrec, XLogRecGetData(record), sizeof(xl_parameter_change));

		LWLockAcquire(ControlFileLock, LW_EXCLUSIVE);
		ControlFile->MaxConnections = xlrec.MaxConnections;
		ControlFile->max_prepared_xacts = xlrec.max_prepared_xacts;
		ControlFile->max_locks_per_xact = xlrec.max_locks_per_xact;
		ControlFile->wal_level = xlrec.wal_level;

		
		minRecoveryPoint = ControlFile->minRecoveryPoint;
		minRecoveryPointTLI = ControlFile->minRecoveryPointTLI;
		if (minRecoveryPoint != 0 && minRecoveryPoint < lsn)
		{
			ControlFile->minRecoveryPoint = lsn;
			ControlFile->minRecoveryPointTLI = ThisTimeLineID;
		}

		UpdateControlFile();
		LWLockRelease(ControlFileLock);

		
		CheckRequiredParameterValues();
	}
	else if (info == XLOG_FPW_CHANGE)
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;
		bool		fpw;

		memcpy(&fpw, XLogRecGetData(record), sizeof(bool));

		
		if (!fpw)
		{
			SpinLockAcquire(&xlogctl->info_lck);
			if (xlogctl->lastFpwDisableRecPtr < ReadRecPtr)
				xlogctl->lastFpwDisableRecPtr = ReadRecPtr;
			SpinLockRelease(&xlogctl->info_lck);
		}

		
		lastFullPageWrites = fpw;
	}
}



static void xlog_outrec(StringInfo buf, XLogRecord *record)
{
	int			i;

	appendStringInfo(buf, "prev %X/%X; xid %u", (uint32) (record->xl_prev >> 32), (uint32) record->xl_prev, record->xl_xid);



	appendStringInfo(buf, "; len %u", record->xl_len);

	for (i = 0; i < XLR_MAX_BKP_BLOCKS; i++)
	{
		if (record->xl_info & XLR_BKP_BLOCK(i))
			appendStringInfo(buf, "; bkpb%d", i);
	}

	appendStringInfo(buf, ": %s", RmgrTable[record->xl_rmid].rm_name);
}




static int get_sync_bit(int method)
{
	int			o_direct_flag = 0;

	
	if (!enableFsync)
		return 0;

	
	if (!XLogIsNeeded() && !AmWalReceiverProcess())
		o_direct_flag = PG_O_DIRECT;

	switch (method)
	{
			
		case SYNC_METHOD_FSYNC:
		case SYNC_METHOD_FSYNC_WRITETHROUGH:
		case SYNC_METHOD_FDATASYNC:
			return 0;

		case SYNC_METHOD_OPEN:
			return OPEN_SYNC_FLAG | o_direct_flag;


		case SYNC_METHOD_OPEN_DSYNC:
			return OPEN_DATASYNC_FLAG | o_direct_flag;

		default:
			
			elog(ERROR, "unrecognized wal_sync_method: %d", method);
			return 0;			
	}
}


void assign_xlog_sync_method(int new_sync_method, void *extra)
{
	if (sync_method != new_sync_method)
	{
		
		if (openLogFile >= 0)
		{
			if (pg_fsync(openLogFile) != 0)
				ereport(PANIC, (errcode_for_file_access(), errmsg("could not fsync log segment %s: %m", XLogFileNameP(ThisTimeLineID, openLogSegNo))));


			if (get_sync_bit(sync_method) != get_sync_bit(new_sync_method))
				XLogFileClose();
		}
	}
}



void issue_xlog_fsync(int fd, XLogSegNo segno)
{
	switch (sync_method)
	{
		case SYNC_METHOD_FSYNC:
			if (pg_fsync_no_writethrough(fd) != 0)
				ereport(PANIC, (errcode_for_file_access(), errmsg("could not fsync log file %s: %m", XLogFileNameP(ThisTimeLineID, segno))));


			break;

		case SYNC_METHOD_FSYNC_WRITETHROUGH:
			if (pg_fsync_writethrough(fd) != 0)
				ereport(PANIC, (errcode_for_file_access(), errmsg("could not fsync write-through log file %s: %m", XLogFileNameP(ThisTimeLineID, segno))));


			break;


		case SYNC_METHOD_FDATASYNC:
			if (pg_fdatasync(fd) != 0)
				ereport(PANIC, (errcode_for_file_access(), errmsg("could not fdatasync log file %s: %m", XLogFileNameP(ThisTimeLineID, segno))));


			break;

		case SYNC_METHOD_OPEN:
		case SYNC_METHOD_OPEN_DSYNC:
			
			break;
		default:
			elog(PANIC, "unrecognized wal_sync_method: %d", sync_method);
			break;
	}
}


char * XLogFileNameP(TimeLineID tli, XLogSegNo segno)
{
	char	   *result = palloc(MAXFNAMELEN);
	XLogFileName(result, tli, segno);
	return result;
}


XLogRecPtr do_pg_start_backup(const char *backupidstr, bool fast, TimeLineID *starttli_p, char **labelfile)

{
	bool		exclusive = (labelfile == NULL);
	bool		backup_started_in_recovery = false;
	XLogRecPtr	checkpointloc;
	XLogRecPtr	startpoint;
	TimeLineID	starttli;
	pg_time_t	stamp_time;
	char		strfbuf[128];
	char		xlogfilename[MAXFNAMELEN];
	XLogSegNo	_logSegNo;
	struct stat stat_buf;
	FILE	   *fp;
	StringInfoData labelfbuf;

	backup_started_in_recovery = RecoveryInProgress();

	if (!superuser() && !is_authenticated_user_replication_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser or replication role to run a backup")));


	
	if (backup_started_in_recovery && exclusive)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("recovery is in progress"), errhint("WAL control functions cannot be executed during recovery.")));



	
	if (!backup_started_in_recovery && !XLogIsNeeded())
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("WAL level not sufficient for making an online backup"), errhint("wal_level must be set to \"archive\" or \"hot_standby\" at server start.")));



	if (strlen(backupidstr) > MAXPGPATH)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("backup label too long (max %d bytes)", MAXPGPATH)));



	
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
	if (exclusive)
	{
		if (XLogCtl->Insert.exclusiveBackup)
		{
			LWLockRelease(WALInsertLock);
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("a backup is already in progress"), errhint("Run pg_stop_backup() and try again.")));


		}
		XLogCtl->Insert.exclusiveBackup = true;
	}
	else XLogCtl->Insert.nonExclusiveBackups++;
	XLogCtl->Insert.forcePageWrites = true;
	LWLockRelease(WALInsertLock);

	
	PG_ENSURE_ERROR_CLEANUP(pg_start_backup_callback, (Datum) BoolGetDatum(exclusive));
	{
		bool		gotUniqueStartpoint = false;

		
		if (!backup_started_in_recovery)
			RequestXLogSwitch();

		do {
			bool		checkpointfpw;

			
			RequestCheckpoint(CHECKPOINT_FORCE | CHECKPOINT_WAIT | (fast ? CHECKPOINT_IMMEDIATE : 0));

			
			LWLockAcquire(ControlFileLock, LW_SHARED);
			checkpointloc = ControlFile->checkPoint;
			startpoint = ControlFile->checkPointCopy.redo;
			starttli = ControlFile->checkPointCopy.ThisTimeLineID;
			checkpointfpw = ControlFile->checkPointCopy.fullPageWrites;
			LWLockRelease(ControlFileLock);

			if (backup_started_in_recovery)
			{
				
				volatile XLogCtlData *xlogctl = XLogCtl;
				XLogRecPtr	recptr;

				
				SpinLockAcquire(&xlogctl->info_lck);
				recptr = xlogctl->lastFpwDisableRecPtr;
				SpinLockRelease(&xlogctl->info_lck);

				if (!checkpointfpw || startpoint <= recptr)
					ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("WAL generated with full_page_writes=off was replayed " "since last restartpoint"), errhint("This means that the backup being taken on the standby " "is corrupt and should not be used. " "Enable full_page_writes and run CHECKPOINT on the master, " "and then try an online backup again.")));







				
				gotUniqueStartpoint = true;
			}

			
			LWLockAcquire(WALInsertLock, LW_SHARED);
			if (XLogCtl->Insert.lastBackupStart < startpoint)
			{
				XLogCtl->Insert.lastBackupStart = startpoint;
				gotUniqueStartpoint = true;
			}
			LWLockRelease(WALInsertLock);
		} while (!gotUniqueStartpoint);

		XLByteToSeg(startpoint, _logSegNo);
		XLogFileName(xlogfilename, ThisTimeLineID, _logSegNo);

		
		initStringInfo(&labelfbuf);

		
		stamp_time = (pg_time_t) time(NULL);
		pg_strftime(strfbuf, sizeof(strfbuf), "%Y-%m-%d %H:%M:%S %Z", pg_localtime(&stamp_time, log_timezone));

		appendStringInfo(&labelfbuf, "START WAL LOCATION: %X/%X (file %s)\n", (uint32) (startpoint >> 32), (uint32) startpoint, xlogfilename);
		appendStringInfo(&labelfbuf, "CHECKPOINT LOCATION: %X/%X\n", (uint32) (checkpointloc >> 32), (uint32) checkpointloc);
		appendStringInfo(&labelfbuf, "BACKUP METHOD: %s\n", exclusive ? "pg_start_backup" : "streamed");
		appendStringInfo(&labelfbuf, "BACKUP FROM: %s\n", backup_started_in_recovery ? "standby" : "master");
		appendStringInfo(&labelfbuf, "START TIME: %s\n", strfbuf);
		appendStringInfo(&labelfbuf, "LABEL: %s\n", backupidstr);

		
		if (exclusive)
		{
			
			if (stat(BACKUP_LABEL_FILE, &stat_buf) != 0)
			{
				if (errno != ENOENT)
					ereport(ERROR, (errcode_for_file_access(), errmsg("could not stat file \"%s\": %m", BACKUP_LABEL_FILE)));


			}
			else ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("a backup is already in progress"), errhint("If you're sure there is no backup in progress, remove file \"%s\" and try again.", BACKUP_LABEL_FILE)));





			fp = AllocateFile(BACKUP_LABEL_FILE, "w");

			if (!fp)
				ereport(ERROR, (errcode_for_file_access(), errmsg("could not create file \"%s\": %m", BACKUP_LABEL_FILE)));


			if (fwrite(labelfbuf.data, labelfbuf.len, 1, fp) != 1 || fflush(fp) != 0 || pg_fsync(fileno(fp)) != 0 || ferror(fp) || FreeFile(fp))



				ereport(ERROR, (errcode_for_file_access(), errmsg("could not write file \"%s\": %m", BACKUP_LABEL_FILE)));


			pfree(labelfbuf.data);
		}
		else *labelfile = labelfbuf.data;
	}
	PG_END_ENSURE_ERROR_CLEANUP(pg_start_backup_callback, (Datum) BoolGetDatum(exclusive));

	
	if (starttli_p)
		*starttli_p = starttli;
	return startpoint;
}


static void pg_start_backup_callback(int code, Datum arg)
{
	bool		exclusive = DatumGetBool(arg);

	
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
	if (exclusive)
	{
		Assert(XLogCtl->Insert.exclusiveBackup);
		XLogCtl->Insert.exclusiveBackup = false;
	}
	else {
		Assert(XLogCtl->Insert.nonExclusiveBackups > 0);
		XLogCtl->Insert.nonExclusiveBackups--;
	}

	if (!XLogCtl->Insert.exclusiveBackup && XLogCtl->Insert.nonExclusiveBackups == 0)
	{
		XLogCtl->Insert.forcePageWrites = false;
	}
	LWLockRelease(WALInsertLock);
}


XLogRecPtr do_pg_stop_backup(char *labelfile, bool waitforarchive, TimeLineID *stoptli_p)
{
	bool		exclusive = (labelfile == NULL);
	bool		backup_started_in_recovery = false;
	XLogRecPtr	startpoint;
	XLogRecPtr	stoppoint;
	TimeLineID	stoptli;
	XLogRecData rdata;
	pg_time_t	stamp_time;
	char		strfbuf[128];
	char		histfilepath[MAXPGPATH];
	char		startxlogfilename[MAXFNAMELEN];
	char		stopxlogfilename[MAXFNAMELEN];
	char		lastxlogfilename[MAXFNAMELEN];
	char		histfilename[MAXFNAMELEN];
	char		backupfrom[20];
	XLogSegNo	_logSegNo;
	FILE	   *lfp;
	FILE	   *fp;
	char		ch;
	int			seconds_before_warning;
	int			waits = 0;
	bool		reported_waiting = false;
	char	   *remaining;
	char	   *ptr;
	uint32		hi, lo;

	backup_started_in_recovery = RecoveryInProgress();

	if (!superuser() && !is_authenticated_user_replication_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), (errmsg("must be superuser or replication role to run a backup"))));


	
	if (backup_started_in_recovery && exclusive)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("recovery is in progress"), errhint("WAL control functions cannot be executed during recovery.")));



	
	if (!backup_started_in_recovery && !XLogIsNeeded())
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("WAL level not sufficient for making an online backup"), errhint("wal_level must be set to \"archive\" or \"hot_standby\" at server start.")));



	
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
	if (exclusive)
		XLogCtl->Insert.exclusiveBackup = false;
	else {
		
		Assert(XLogCtl->Insert.nonExclusiveBackups > 0);
		XLogCtl->Insert.nonExclusiveBackups--;
	}

	if (!XLogCtl->Insert.exclusiveBackup && XLogCtl->Insert.nonExclusiveBackups == 0)
	{
		XLogCtl->Insert.forcePageWrites = false;
	}
	LWLockRelease(WALInsertLock);

	if (exclusive)
	{
		
		struct stat statbuf;
		int			r;

		if (stat(BACKUP_LABEL_FILE, &statbuf))
		{
			if (errno != ENOENT)
				ereport(ERROR, (errcode_for_file_access(), errmsg("could not stat file \"%s\": %m", BACKUP_LABEL_FILE)));


			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("a backup is not in progress")));

		}

		lfp = AllocateFile(BACKUP_LABEL_FILE, "r");
		if (!lfp)
		{
			ereport(ERROR, (errcode_for_file_access(), errmsg("could not read file \"%s\": %m", BACKUP_LABEL_FILE)));


		}
		labelfile = palloc(statbuf.st_size + 1);
		r = fread(labelfile, statbuf.st_size, 1, lfp);
		labelfile[statbuf.st_size] = '\0';

		
		if (r != 1 || ferror(lfp) || FreeFile(lfp))
			ereport(ERROR, (errcode_for_file_access(), errmsg("could not read file \"%s\": %m", BACKUP_LABEL_FILE)));


		if (unlink(BACKUP_LABEL_FILE) != 0)
			ereport(ERROR, (errcode_for_file_access(), errmsg("could not remove file \"%s\": %m", BACKUP_LABEL_FILE)));


	}

	
	if (sscanf(labelfile, "START WAL LOCATION: %X/%X (file %24s)%c", &hi, &lo, startxlogfilename, &ch) != 4 || ch != '\n')

		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("invalid data in file \"%s\"", BACKUP_LABEL_FILE)));

	startpoint = ((uint64) hi) << 32 | lo;
	remaining = strchr(labelfile, '\n') + 1;	

	
	ptr = strstr(remaining, "BACKUP FROM:");
	if (!ptr || sscanf(ptr, "BACKUP FROM: %19s\n", backupfrom) != 1)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("invalid data in file \"%s\"", BACKUP_LABEL_FILE)));

	if (strcmp(backupfrom, "standby") == 0 && !backup_started_in_recovery)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("the standby was promoted during online backup"), errhint("This means that the backup being taken is corrupt " "and should not be used. " "Try taking another online backup.")));





	
	if (backup_started_in_recovery)
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;
		XLogRecPtr	recptr;

		
		SpinLockAcquire(&xlogctl->info_lck);
		recptr = xlogctl->lastFpwDisableRecPtr;
		SpinLockRelease(&xlogctl->info_lck);

		if (startpoint <= recptr)
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("WAL generated with full_page_writes=off was replayed " "during online backup"), errhint("This means that the backup being taken on the standby " "is corrupt and should not be used. " "Enable full_page_writes and run CHECKPOINT on the master, " "and then try an online backup again.")));








		LWLockAcquire(ControlFileLock, LW_SHARED);
		stoppoint = ControlFile->minRecoveryPoint;
		stoptli = ControlFile->minRecoveryPointTLI;
		LWLockRelease(ControlFileLock);

		if (stoptli_p)
			*stoptli_p = stoptli;
		return stoppoint;
	}

	
	rdata.data = (char *) (&startpoint);
	rdata.len = sizeof(startpoint);
	rdata.buffer = InvalidBuffer;
	rdata.next = NULL;
	stoppoint = XLogInsert(RM_XLOG_ID, XLOG_BACKUP_END, &rdata);
	stoptli = ThisTimeLineID;

	
	RequestXLogSwitch();

	XLByteToPrevSeg(stoppoint, _logSegNo);
	XLogFileName(stopxlogfilename, ThisTimeLineID, _logSegNo);

	
	stamp_time = (pg_time_t) time(NULL);
	pg_strftime(strfbuf, sizeof(strfbuf), "%Y-%m-%d %H:%M:%S %Z", pg_localtime(&stamp_time, log_timezone));


	
	XLByteToSeg(startpoint, _logSegNo);
	BackupHistoryFilePath(histfilepath, ThisTimeLineID, _logSegNo, (uint32) (startpoint % XLogSegSize));
	fp = AllocateFile(histfilepath, "w");
	if (!fp)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not create file \"%s\": %m", histfilepath)));


	fprintf(fp, "START WAL LOCATION: %X/%X (file %s)\n", (uint32) (startpoint >> 32), (uint32) startpoint, startxlogfilename);
	fprintf(fp, "STOP WAL LOCATION: %X/%X (file %s)\n", (uint32) (stoppoint >> 32), (uint32) stoppoint, stopxlogfilename);
	
	fprintf(fp, "%s", remaining);
	fprintf(fp, "STOP TIME: %s\n", strfbuf);
	if (fflush(fp) || ferror(fp) || FreeFile(fp))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not write file \"%s\": %m", histfilepath)));



	
	CleanupBackupHistory();

	
	if (waitforarchive && XLogArchivingActive())
	{
		XLByteToPrevSeg(stoppoint, _logSegNo);
		XLogFileName(lastxlogfilename, ThisTimeLineID, _logSegNo);

		XLByteToSeg(startpoint, _logSegNo);
		BackupHistoryFileName(histfilename, ThisTimeLineID, _logSegNo, (uint32) (startpoint % XLogSegSize));

		seconds_before_warning = 60;
		waits = 0;

		while (XLogArchiveIsBusy(lastxlogfilename) || XLogArchiveIsBusy(histfilename))
		{
			CHECK_FOR_INTERRUPTS();

			if (!reported_waiting && waits > 5)
			{
				ereport(NOTICE, (errmsg("pg_stop_backup cleanup done, waiting for required WAL segments to be archived")));
				reported_waiting = true;
			}

			pg_usleep(1000000L);

			if (++waits >= seconds_before_warning)
			{
				seconds_before_warning *= 2;	
				ereport(WARNING, (errmsg("pg_stop_backup still waiting for all required WAL segments to be archived (%d seconds elapsed)", waits), errhint("Check that your archive_command is executing properly.  " "pg_stop_backup can be canceled safely, " "but the database backup will not be usable without all the WAL segments.")));




			}
		}

		ereport(NOTICE, (errmsg("pg_stop_backup complete, all required WAL segments have been archived")));
	}
	else if (waitforarchive)
		ereport(NOTICE, (errmsg("WAL archiving is not enabled; you must ensure that all required WAL segments are copied through other means to complete the backup")));

	
	if (stoptli_p)
		*stoptli_p = stoptli;
	return stoppoint;
}



void do_pg_abort_backup(void)
{
	LWLockAcquire(WALInsertLock, LW_EXCLUSIVE);
	Assert(XLogCtl->Insert.nonExclusiveBackups > 0);
	XLogCtl->Insert.nonExclusiveBackups--;

	if (!XLogCtl->Insert.exclusiveBackup && XLogCtl->Insert.nonExclusiveBackups == 0)
	{
		XLogCtl->Insert.forcePageWrites = false;
	}
	LWLockRelease(WALInsertLock);
}


XLogRecPtr GetXLogReplayRecPtr(TimeLineID *replayTLI)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;
	XLogRecPtr	recptr;
	TimeLineID	tli;

	SpinLockAcquire(&xlogctl->info_lck);
	recptr = xlogctl->lastReplayedEndRecPtr;
	tli = xlogctl->lastReplayedTLI;
	SpinLockRelease(&xlogctl->info_lck);

	if (replayTLI)
		*replayTLI = tli;
	return recptr;
}


XLogRecPtr GetXLogInsertRecPtr(void)
{
	XLogCtlInsert *Insert = &XLogCtl->Insert;
	XLogRecPtr	current_recptr;

	LWLockAcquire(WALInsertLock, LW_SHARED);
	INSERT_RECPTR(current_recptr, Insert, Insert->curridx);
	LWLockRelease(WALInsertLock);

	return current_recptr;
}


XLogRecPtr GetXLogWriteRecPtr(void)
{
	{
		
		volatile XLogCtlData *xlogctl = XLogCtl;

		SpinLockAcquire(&xlogctl->info_lck);
		LogwrtResult = xlogctl->LogwrtResult;
		SpinLockRelease(&xlogctl->info_lck);
	}

	return LogwrtResult.Write;
}


void GetOldestRestartPoint(XLogRecPtr *oldrecptr, TimeLineID *oldtli)
{
	LWLockAcquire(ControlFileLock, LW_SHARED);
	*oldrecptr = ControlFile->checkPointCopy.redo;
	*oldtli = ControlFile->checkPointCopy.ThisTimeLineID;
	LWLockRelease(ControlFileLock);
}


static bool read_backup_label(XLogRecPtr *checkPointLoc, bool *backupEndRequired, bool *backupFromStandby)

{
	char		startxlogfilename[MAXFNAMELEN];
	TimeLineID	tli;
	FILE	   *lfp;
	char		ch;
	char		backuptype[20];
	char		backupfrom[20];
	uint32		hi, lo;

	*backupEndRequired = false;
	*backupFromStandby = false;

	
	lfp = AllocateFile(BACKUP_LABEL_FILE, "r");
	if (!lfp)
	{
		if (errno != ENOENT)
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not read file \"%s\": %m", BACKUP_LABEL_FILE)));


		return false;			
	}

	
	if (fscanf(lfp, "START WAL LOCATION: %X/%X (file %08X%16s)%c", &hi, &lo, &tli, startxlogfilename, &ch) != 5 || ch != '\n')
		ereport(FATAL, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("invalid data in file \"%s\"", BACKUP_LABEL_FILE)));

	RedoStartLSN = ((uint64) hi) << 32 | lo;
	if (fscanf(lfp, "CHECKPOINT LOCATION: %X/%X%c", &hi, &lo, &ch) != 3 || ch != '\n')
		ereport(FATAL, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("invalid data in file \"%s\"", BACKUP_LABEL_FILE)));

	*checkPointLoc = ((uint64) hi) << 32 | lo;

	
	if (fscanf(lfp, "BACKUP METHOD: %19s\n", backuptype) == 1)
	{
		if (strcmp(backuptype, "streamed") == 0)
			*backupEndRequired = true;
	}

	if (fscanf(lfp, "BACKUP FROM: %19s\n", backupfrom) == 1)
	{
		if (strcmp(backupfrom, "standby") == 0)
			*backupFromStandby = true;
	}

	if (ferror(lfp) || FreeFile(lfp))
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not read file \"%s\": %m", BACKUP_LABEL_FILE)));



	return true;
}


static void rm_redo_error_callback(void *arg)
{
	XLogRecord *record = (XLogRecord *) arg;
	StringInfoData buf;

	initStringInfo(&buf);
	RmgrTable[record->xl_rmid].rm_desc(&buf, record->xl_info, XLogRecGetData(record));


	
	if (buf.len > 0)
		errcontext("xlog redo %s", buf.data);

	pfree(buf.data);
}


bool BackupInProgress(void)
{
	struct stat stat_buf;

	return (stat(BACKUP_LABEL_FILE, &stat_buf) == 0);
}


void CancelBackup(void)
{
	struct stat stat_buf;

	
	if (stat(BACKUP_LABEL_FILE, &stat_buf) < 0)
		return;

	
	unlink(BACKUP_LABEL_OLD);

	if (rename(BACKUP_LABEL_FILE, BACKUP_LABEL_OLD) == 0)
	{
		ereport(LOG, (errmsg("online backup mode canceled"), errdetail("\"%s\" was renamed to \"%s\".", BACKUP_LABEL_FILE, BACKUP_LABEL_OLD)));


	}
	else {
		ereport(WARNING, (errcode_for_file_access(), errmsg("online backup mode was not canceled"), errdetail("Could not rename \"%s\" to \"%s\": %m.", BACKUP_LABEL_FILE, BACKUP_LABEL_OLD)));



	}
}


static int XLogPageRead(XLogReaderState *xlogreader, XLogRecPtr targetPagePtr, int reqLen, XLogRecPtr targetRecPtr, char *readBuf, TimeLineID *readTLI)

{
	XLogPageReadPrivate *private = (XLogPageReadPrivate *) xlogreader->private_data;
	int			emode = private->emode;
	uint32		targetPageOff;
	XLogSegNo	targetSegNo PG_USED_FOR_ASSERTS_ONLY;

	XLByteToSeg(targetPagePtr, targetSegNo);
	targetPageOff = targetPagePtr % XLogSegSize;

	
	if (readFile >= 0 && !XLByteInSeg(targetPagePtr, readSegNo))
	{
		
		if (StandbyModeRequested && bgwriterLaunched)
		{
			if (XLogCheckpointNeeded(readSegNo))
			{
				(void) GetRedoRecPtr();
				if (XLogCheckpointNeeded(readSegNo))
					RequestCheckpoint(CHECKPOINT_CAUSE_XLOG);
			}
		}

		close(readFile);
		readFile = -1;
		readSource = 0;
	}

	XLByteToSeg(targetPagePtr, readSegNo);

retry:
	
	if (readFile < 0 || (readSource == XLOG_FROM_STREAM && receivedUpto < targetPagePtr + reqLen))

	{
		if (!WaitForWALToBecomeAvailable(targetPagePtr + reqLen, private->randAccess, private->fetching_ckpt, targetRecPtr))


		{
			if (readFile >= 0)
				close(readFile);
			readFile = -1;
			readLen = 0;
			readSource = 0;

			return -1;
		}
	}

	
	Assert(readFile != -1);

	
	if (readSource == XLOG_FROM_STREAM)
	{
		if (((targetPagePtr) / XLOG_BLCKSZ) != (receivedUpto / XLOG_BLCKSZ))
			readLen = XLOG_BLCKSZ;
		else readLen = receivedUpto % XLogSegSize - targetPageOff;
	}
	else readLen = XLOG_BLCKSZ;

	
	readOff = targetPageOff;
	if (lseek(readFile, (off_t) readOff, SEEK_SET) < 0)
	{
		char fname[MAXFNAMELEN];

		XLogFileName(fname, curFileTLI, readSegNo);
		ereport(emode_for_corrupt_record(emode, targetPagePtr + reqLen), (errcode_for_file_access(), errmsg("could not seek in log segment %s to offset %u: %m", fname, readOff)));


		goto next_record_is_invalid;
	}

	if (read(readFile, readBuf, XLOG_BLCKSZ) != XLOG_BLCKSZ)
	{
		char fname[MAXFNAMELEN];

		XLogFileName(fname, curFileTLI, readSegNo);
		ereport(emode_for_corrupt_record(emode, targetPagePtr + reqLen), (errcode_for_file_access(), errmsg("could not read from log segment %s, offset %u: %m", fname, readOff)));


		goto next_record_is_invalid;
	}

	Assert(targetSegNo == readSegNo);
	Assert(targetPageOff == readOff);
	Assert(reqLen <= readLen);

	*readTLI = curFileTLI;
	return readLen;

next_record_is_invalid:
	lastSourceFailed = true;

	if (readFile >= 0)
		close(readFile);
	readFile = -1;
	readLen = 0;
	readSource = 0;

	
	if (StandbyMode)
		goto retry;
	else return -1;
}


static bool WaitForWALToBecomeAvailable(XLogRecPtr RecPtr, bool randAccess, bool fetching_ckpt, XLogRecPtr tliRecPtr)

{
	static pg_time_t last_fail_time = 0;
	pg_time_t now;

	
	if (!InArchiveRecovery)
		currentSource = XLOG_FROM_PG_XLOG;
	else if (currentSource == 0)
		currentSource = XLOG_FROM_ARCHIVE;

	for (;;)
	{
		int		oldSource = currentSource;

		
		if (lastSourceFailed)
		{
			switch (currentSource)
			{
				case XLOG_FROM_ARCHIVE:
					currentSource = XLOG_FROM_PG_XLOG;
					break;

				case XLOG_FROM_PG_XLOG:
					
					if (StandbyMode && CheckForStandbyTrigger())
					{
						ShutdownWalRcv();
						return false;
					}

					
					if (!StandbyMode)
						return false;

					
					if (PrimaryConnInfo)
					{
						XLogRecPtr ptr;
						TimeLineID tli;

						if (fetching_ckpt)
						{
							ptr = RedoStartLSN;
							tli = ControlFile->checkPointCopy.ThisTimeLineID;
						}
						else {
							ptr = RecPtr;
							tli = tliOfPointInHistory(tliRecPtr, expectedTLEs);

							if (curFileTLI > 0 && tli < curFileTLI)
								elog(ERROR, "according to history file, WAL location %X/%X belongs to timeline %u, but previous recovered WAL file came from timeline %u", (uint32) (ptr >> 32), (uint32) ptr, tli, curFileTLI);

						}
						curFileTLI = tli;
						RequestXLogStreaming(curFileTLI, ptr, PrimaryConnInfo);
					}
					
					currentSource = XLOG_FROM_STREAM;
					break;

				case XLOG_FROM_STREAM:
					
					
					if (WalRcvStreaming())
						ShutdownWalRcv();

					
					if (recoveryTargetIsLatest)
					{
						if (rescanLatestTimeLine())
						{
							currentSource = XLOG_FROM_ARCHIVE;
							break;
						}
					}

					
					now = (pg_time_t) time(NULL);
					if ((now - last_fail_time) < 5)
					{
						pg_usleep(1000000L * (5 - (now - last_fail_time)));
						now = (pg_time_t) time(NULL);
					}
					last_fail_time = now;
					currentSource = XLOG_FROM_ARCHIVE;
					break;

				default:
					elog(ERROR, "unexpected WAL source %d", currentSource);
			}
		}
		else if (currentSource == XLOG_FROM_PG_XLOG)
		{
			
			if (InArchiveRecovery)
				currentSource = XLOG_FROM_ARCHIVE;
		}

		if (currentSource != oldSource)
			elog(DEBUG2, "switched WAL source from %s to %s after %s", xlogSourceNames[oldSource], xlogSourceNames[currentSource], lastSourceFailed ? "failure" : "success");


		
		lastSourceFailed = false;

		switch (currentSource)
		{
			case XLOG_FROM_ARCHIVE:
			case XLOG_FROM_PG_XLOG:
				
				if (readFile >= 0)
				{
					close(readFile);
					readFile = -1;
				}
				
				if (randAccess)
					curFileTLI = 0;

				
				readFile = XLogFileReadAnyTLI(readSegNo, DEBUG2, currentSource);
				if (readFile >= 0)
					return true;	

				
				lastSourceFailed = true;
				break;

			case XLOG_FROM_STREAM:
			{
				bool		havedata;

				
				if (!WalRcvStreaming())
				{
					lastSourceFailed = true;
					break;
				}

				
				if (RecPtr < receivedUpto)
					havedata = true;
				else {
					XLogRecPtr	latestChunkStart;

					receivedUpto = GetWalRcvWriteRecPtr(&latestChunkStart, &receiveTLI);
					if (RecPtr < receivedUpto && receiveTLI == curFileTLI)
					{
						havedata = true;
						if (latestChunkStart <= RecPtr)
						{
							XLogReceiptTime = GetCurrentTimestamp();
							SetCurrentChunkStartTime(XLogReceiptTime);
						}
					}
					else havedata = false;
				}
				if (havedata)
				{
					
					if (readFile < 0)
					{
						if (!expectedTLEs)
							expectedTLEs = readTimeLineHistory(receiveTLI);
						readFile = XLogFileRead(readSegNo, PANIC, receiveTLI, XLOG_FROM_STREAM, false);

						Assert(readFile >= 0);
					}
					else {
						
						readSource = XLOG_FROM_STREAM;
						XLogReceiptSource = XLOG_FROM_STREAM;
						return true;
					}
					break;
				}

				
				if (CheckForStandbyTrigger())
				{
					
					lastSourceFailed = true;
					break;
				}

				
				WaitLatch(&XLogCtl->recoveryWakeupLatch, WL_LATCH_SET | WL_TIMEOUT, 5000L);

				ResetLatch(&XLogCtl->recoveryWakeupLatch);
				break;
			}

			default:
				elog(ERROR, "unexpected WAL source %d", currentSource);
		}

		
		HandleStartupProcInterrupts();
	} while (StandbyMode);

	return false;
}


static int emode_for_corrupt_record(int emode, XLogRecPtr RecPtr)
{
	static XLogRecPtr lastComplaint = 0;

	if (readSource == XLOG_FROM_PG_XLOG && emode == LOG)
	{
		if (RecPtr == lastComplaint)
			emode = DEBUG1;
		else lastComplaint = RecPtr;
	}
	return emode;
}


static bool CheckForStandbyTrigger(void)
{
	struct stat stat_buf;
	static bool triggered = false;

	if (triggered)
		return true;

	if (IsPromoteTriggered())
	{
		
		if (stat(FAST_PROMOTE_SIGNAL_FILE, &stat_buf) == 0)
		{
			unlink(FAST_PROMOTE_SIGNAL_FILE);
			unlink(PROMOTE_SIGNAL_FILE);
			fast_promote = true;
		}
		else if (stat(PROMOTE_SIGNAL_FILE, &stat_buf) == 0)
		{
			unlink(PROMOTE_SIGNAL_FILE);
			fast_promote = false;
		}

		
		if (fast_promote)
			ereport(LOG, (errmsg("received fast promote request")));
		else ereport(LOG, (errmsg("received promote request")));


		ResetPromoteTriggered();
		triggered = true;
		return true;
	}

	if (TriggerFile == NULL)
		return false;

	if (stat(TriggerFile, &stat_buf) == 0)
	{
		ereport(LOG, (errmsg("trigger file found: %s", TriggerFile)));
		unlink(TriggerFile);
		triggered = true;
		return true;
	}
	return false;
}


bool CheckPromoteSignal(void)
{
	struct stat stat_buf;

	if (stat(PROMOTE_SIGNAL_FILE, &stat_buf) == 0 || stat(FAST_PROMOTE_SIGNAL_FILE, &stat_buf) == 0)
		return true;

	return false;
}


void WakeupRecovery(void)
{
	SetLatch(&XLogCtl->recoveryWakeupLatch);
}


void SetWalWriterSleeping(bool sleeping)
{
	
	volatile XLogCtlData *xlogctl = XLogCtl;

	SpinLockAcquire(&xlogctl->info_lck);
	xlogctl->WalWriterSleeping = sleeping;
	SpinLockRelease(&xlogctl->info_lck);
}
