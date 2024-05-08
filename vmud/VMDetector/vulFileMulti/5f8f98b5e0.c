















































static HeapTuple GetDatabaseTuple(const char *dbname);
static HeapTuple GetDatabaseTupleByOid(Oid dboid);
static void PerformAuthentication(Port *port);
static void CheckMyDatabase(const char *name, bool am_superuser);
static void InitCommunication(void);
static void ShutdownPostgres(int code, Datum arg);
static void StatementTimeoutHandler(void);
static void LockTimeoutHandler(void);
static bool ThereIsAtLeastOneRole(void);
static void process_startup_options(Port *port, bool am_superuser);
static void process_settings(Oid databaseid, Oid roleid);






static HeapTuple GetDatabaseTuple(const char *dbname)
{
	HeapTuple	tuple;
	Relation	relation;
	SysScanDesc scan;
	ScanKeyData key[1];

	
	ScanKeyInit(&key[0], Anum_pg_database_datname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(dbname));



	
	relation = heap_open(DatabaseRelationId, AccessShareLock);
	scan = systable_beginscan(relation, DatabaseNameIndexId, criticalSharedRelcachesBuilt, SnapshotNow, 1, key);



	tuple = systable_getnext(scan);

	
	if (HeapTupleIsValid(tuple))
		tuple = heap_copytuple(tuple);

	
	systable_endscan(scan);
	heap_close(relation, AccessShareLock);

	return tuple;
}


static HeapTuple GetDatabaseTupleByOid(Oid dboid)
{
	HeapTuple	tuple;
	Relation	relation;
	SysScanDesc scan;
	ScanKeyData key[1];

	
	ScanKeyInit(&key[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(dboid));



	
	relation = heap_open(DatabaseRelationId, AccessShareLock);
	scan = systable_beginscan(relation, DatabaseOidIndexId, criticalSharedRelcachesBuilt, SnapshotNow, 1, key);



	tuple = systable_getnext(scan);

	
	if (HeapTupleIsValid(tuple))
		tuple = heap_copytuple(tuple);

	
	systable_endscan(scan);
	heap_close(relation, AccessShareLock);

	return tuple;
}



static void PerformAuthentication(Port *port)
{
	
	ClientAuthInProgress = true;	

	

	if (!load_hba())
	{
		
		ereport(FATAL, (errmsg("could not load pg_hba.conf")));
	}

	if (!load_ident())
	{
		
	}


	
	enable_timeout_after(STATEMENT_TIMEOUT, AuthenticationTimeout * 1000);

	
	ClientAuthentication(port); 

	
	disable_timeout(STATEMENT_TIMEOUT, false);

	if (Log_connections)
	{
		if (am_walsender)
			ereport(LOG, (errmsg("replication connection authorized: user=%s", port->user_name)));

		else ereport(LOG, (errmsg("connection authorized: user=%s database=%s", port->user_name, port->database_name)));


	}

	set_ps_display("startup", false);

	ClientAuthInProgress = false;		
}



static void CheckMyDatabase(const char *name, bool am_superuser)
{
	HeapTuple	tup;
	Form_pg_database dbform;
	char	   *collate;
	char	   *ctype;

	
	tup = SearchSysCache1(DATABASEOID, ObjectIdGetDatum(MyDatabaseId));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for database %u", MyDatabaseId);
	dbform = (Form_pg_database) GETSTRUCT(tup);

	
	if (strcmp(name, NameStr(dbform->datname)) != 0)
		ereport(FATAL, (errcode(ERRCODE_UNDEFINED_DATABASE), errmsg("database \"%s\" has disappeared from pg_database", name), errdetail("Database OID %u now seems to belong to \"%s\".", MyDatabaseId, NameStr(dbform->datname))));





	
	if (IsUnderPostmaster && !IsAutoVacuumWorkerProcess())
	{
		
		if (!dbform->datallowconn)
			ereport(FATAL, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("database \"%s\" is not currently accepting connections", name)));



		
		if (!am_superuser && pg_database_aclcheck(MyDatabaseId, GetUserId(), ACL_CONNECT) != ACLCHECK_OK)

			ereport(FATAL, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for database \"%s\"", name), errdetail("User does not have CONNECT privilege.")));



		
		if (dbform->datconnlimit >= 0 && !am_superuser && CountDBBackends(MyDatabaseId) > dbform->datconnlimit)

			ereport(FATAL, (errcode(ERRCODE_TOO_MANY_CONNECTIONS), errmsg("too many connections for database \"%s\"", name)));


	}

	
	SetDatabaseEncoding(dbform->encoding);
	
	SetConfigOption("server_encoding", GetDatabaseEncodingName(), PGC_INTERNAL, PGC_S_OVERRIDE);
	
	SetConfigOption("client_encoding", GetDatabaseEncodingName(), PGC_BACKEND, PGC_S_DYNAMIC_DEFAULT);

	
	collate = NameStr(dbform->datcollate);
	ctype = NameStr(dbform->datctype);

	if (pg_perm_setlocale(LC_COLLATE, collate) == NULL)
		ereport(FATAL, (errmsg("database locale is incompatible with operating system"), errdetail("The database was initialized with LC_COLLATE \"%s\", " " which is not recognized by setlocale().", collate), errhint("Recreate the database with another locale or install the missing locale.")));




	if (pg_perm_setlocale(LC_CTYPE, ctype) == NULL)
		ereport(FATAL, (errmsg("database locale is incompatible with operating system"), errdetail("The database was initialized with LC_CTYPE \"%s\", " " which is not recognized by setlocale().", ctype), errhint("Recreate the database with another locale or install the missing locale.")));




	
	SetConfigOption("lc_collate", collate, PGC_INTERNAL, PGC_S_OVERRIDE);
	SetConfigOption("lc_ctype", ctype, PGC_INTERNAL, PGC_S_OVERRIDE);

	

	pg_bind_textdomain_codeset(textdomain(NULL));


	ReleaseSysCache(tup);
}




static void InitCommunication(void)
{
	
	if (!IsUnderPostmaster)		
	{
		
		CreateSharedMemoryAndSemaphores(true, 0);
	}
}



void pg_split_opts(char **argv, int *argcp, char *optstr)
{
	while (*optstr)
	{
		while (isspace((unsigned char) *optstr))
			optstr++;
		if (*optstr == '\0')
			break;
		argv[(*argcp)++] = optstr;
		while (*optstr && !isspace((unsigned char) *optstr))
			optstr++;
		if (*optstr)
			*optstr++ = '\0';
	}
}


void InitializeMaxBackends(void)
{
	Assert(MaxBackends == 0);

	
	MaxBackends = MaxConnections + autovacuum_max_workers + 1 + GetNumShmemAttachedBgworkers();

	
	if (MaxBackends > MAX_BACKENDS)
		elog(ERROR, "too many backends configured");
}


void BaseInit(void)
{
	
	InitCommunication();
	DebugFileOpen();

	
	InitFileAccess();
	smgrinit();
	InitBufferPoolAccess();
}



void InitPostgres(const char *in_dbname, Oid dboid, const char *username, char *out_dbname)

{
	bool		bootstrap = IsBootstrapProcessingMode();
	bool		am_superuser;
	char	   *fullpath;
	char		dbname[NAMEDATALEN];

	elog(DEBUG3, "InitPostgres");

	
	InitProcessPhase2();

	
	MyBackendId = InvalidBackendId;

	SharedInvalBackendInit(false);

	if (MyBackendId > MaxBackends || MyBackendId <= 0)
		elog(FATAL, "bad backend ID: %d", MyBackendId);

	
	ProcSignalInit(MyBackendId);

	
	if (!bootstrap)
	{
		RegisterTimeout(DEADLOCK_TIMEOUT, CheckDeadLock);
		RegisterTimeout(STATEMENT_TIMEOUT, StatementTimeoutHandler);
		RegisterTimeout(LOCK_TIMEOUT, LockTimeoutHandler);
	}

	
	InitBufferPoolBackend();

	
	if (IsUnderPostmaster)
	{
		
		(void) RecoveryInProgress();
	}
	else {
		
		StartupXLOG();
		on_shmem_exit(ShutdownXLOG, 0);
	}

	
	RelationCacheInitialize();
	InitCatalogCache();
	InitPlanCache();

	
	EnablePortalManager();

	
	if (!bootstrap)
		pgstat_initialize();

	
	RelationCacheInitializePhase2();

	
	on_shmem_exit(ShutdownPostgres, 0);

	
	if (IsAutoVacuumLauncherProcess())
		return;

	
	if (!bootstrap)
	{
		
		SetCurrentStatementStartTimestamp();
		StartTransactionCommand();

		
		XactIsoLevel = XACT_READ_COMMITTED;

		(void) GetTransactionSnapshot();
	}

	
	if (bootstrap || IsAutoVacuumWorkerProcess())
	{
		InitializeSessionUserIdStandalone();
		am_superuser = true;
	}
	else if (!IsUnderPostmaster)
	{
		InitializeSessionUserIdStandalone();
		am_superuser = true;
		if (!ThereIsAtLeastOneRole())
			ereport(WARNING, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("no roles are defined in this database system"), errhint("You should immediately run CREATE USER \"%s\" SUPERUSER;.", username)));



	}
	else if (IsBackgroundWorker)
	{
		if (username == NULL)
		{
			InitializeSessionUserIdStandalone();
			am_superuser = true;
		}
		else {
			InitializeSessionUserId(username);
			am_superuser = superuser();
		}
	}
	else {
		
		Assert(MyProcPort != NULL);
		PerformAuthentication(MyProcPort);
		InitializeSessionUserId(username);
		am_superuser = superuser();
	}

	
	if ((!am_superuser || am_walsender) && MyProcPort != NULL && MyProcPort->canAcceptConnections == CAC_WAITBACKUP)

	{
		if (am_walsender)
			ereport(FATAL, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("new replication connections are not allowed during database shutdown")));

		else ereport(FATAL, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to connect during database shutdown")));


	}

	
	if (IsBinaryUpgrade && !am_superuser)
	{
		ereport(FATAL, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to connect in binary upgrade mode")));

	}

	
	if ((!am_superuser || am_walsender) && ReservedBackends > 0 && !HaveNFreeProcs(ReservedBackends))

		ereport(FATAL, (errcode(ERRCODE_TOO_MANY_CONNECTIONS), errmsg("remaining connection slots are reserved for non-replication superuser connections")));


	
	if (am_walsender)
	{
		Assert(!bootstrap);

		if (!superuser() && !is_authenticated_user_replication_role())
			ereport(FATAL, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser or replication role to start walsender")));


		
		if (MyProcPort != NULL)
			process_startup_options(MyProcPort, am_superuser);

		
		if (PostAuthDelay > 0)
			pg_usleep(PostAuthDelay * 1000000L);

		
		InitializeClientEncoding();

		
		pgstat_bestart();

		
		CommitTransactionCommand();

		return;
	}

	
	if (bootstrap)
	{
		MyDatabaseId = TemplateDbOid;
		MyDatabaseTableSpace = DEFAULTTABLESPACE_OID;
	}
	else if (in_dbname != NULL)
	{
		HeapTuple	tuple;
		Form_pg_database dbform;

		tuple = GetDatabaseTuple(in_dbname);
		if (!HeapTupleIsValid(tuple))
			ereport(FATAL, (errcode(ERRCODE_UNDEFINED_DATABASE), errmsg("database \"%s\" does not exist", in_dbname)));

		dbform = (Form_pg_database) GETSTRUCT(tuple);
		MyDatabaseId = HeapTupleGetOid(tuple);
		MyDatabaseTableSpace = dbform->dattablespace;
		
		strlcpy(dbname, in_dbname, sizeof(dbname));
	}
	else {
		
		HeapTuple	tuple;
		Form_pg_database dbform;

		tuple = GetDatabaseTupleByOid(dboid);
		if (!HeapTupleIsValid(tuple))
			ereport(FATAL, (errcode(ERRCODE_UNDEFINED_DATABASE), errmsg("database %u does not exist", dboid)));

		dbform = (Form_pg_database) GETSTRUCT(tuple);
		MyDatabaseId = HeapTupleGetOid(tuple);
		MyDatabaseTableSpace = dbform->dattablespace;
		Assert(MyDatabaseId == dboid);
		strlcpy(dbname, NameStr(dbform->datname), sizeof(dbname));
		
		if (out_dbname)
			strcpy(out_dbname, dbname);
	}

	
	
	MyProc->databaseId = MyDatabaseId;

	
	if (!bootstrap)
		LockSharedObject(DatabaseRelationId, MyDatabaseId, 0, RowExclusiveLock);

	
	if (!bootstrap)
	{
		HeapTuple	tuple;

		tuple = GetDatabaseTuple(dbname);
		if (!HeapTupleIsValid(tuple) || MyDatabaseId != HeapTupleGetOid(tuple) || MyDatabaseTableSpace != ((Form_pg_database) GETSTRUCT(tuple))->dattablespace)

			ereport(FATAL, (errcode(ERRCODE_UNDEFINED_DATABASE), errmsg("database \"%s\" does not exist", dbname), errdetail("It seems to have just been dropped or renamed.")));


	}

	
	fullpath = GetDatabasePath(MyDatabaseId, MyDatabaseTableSpace);

	if (!bootstrap)
	{
		if (access(fullpath, F_OK) == -1)
		{
			if (errno == ENOENT)
				ereport(FATAL, (errcode(ERRCODE_UNDEFINED_DATABASE), errmsg("database \"%s\" does not exist", dbname), errdetail("The database subdirectory \"%s\" is missing.", fullpath)));




			else ereport(FATAL, (errcode_for_file_access(), errmsg("could not access directory \"%s\": %m", fullpath)));



		}

		ValidatePgVersion(fullpath);
	}

	SetDatabasePath(fullpath);

	
	RelationCacheInitializePhase3();

	
	initialize_acl();

	
	if (!bootstrap)
		CheckMyDatabase(dbname, am_superuser);

	
	if (MyProcPort != NULL)
		process_startup_options(MyProcPort, am_superuser);

	
	process_settings(MyDatabaseId, GetSessionUserId());

	
	if (PostAuthDelay > 0)
		pg_usleep(PostAuthDelay * 1000000L);

	

	
	InitializeSearchPath();

	
	InitializeClientEncoding();

	
	if (!bootstrap)
		pgstat_bestart();

	
	if (!bootstrap)
		CommitTransactionCommand();
}


static void process_startup_options(Port *port, bool am_superuser)
{
	GucContext	gucctx;
	ListCell   *gucopts;

	gucctx = am_superuser ? PGC_SUSET : PGC_BACKEND;

	
	if (port->cmdline_options != NULL)
	{
		
		char	  **av;
		int			maxac;
		int			ac;

		maxac = 2 + (strlen(port->cmdline_options) + 1) / 2;

		av = (char **) palloc(maxac * sizeof(char *));
		ac = 0;

		av[ac++] = "postgres";

		
		pg_split_opts(av, &ac, port->cmdline_options);

		av[ac] = NULL;

		Assert(ac < maxac);

		(void) process_postgres_switches(ac, av, gucctx);
	}

	
	gucopts = list_head(port->guc_options);
	while (gucopts)
	{
		char	   *name;
		char	   *value;

		name = lfirst(gucopts);
		gucopts = lnext(gucopts);

		value = lfirst(gucopts);
		gucopts = lnext(gucopts);

		SetConfigOption(name, value, gucctx, PGC_S_CLIENT);
	}
}


static void process_settings(Oid databaseid, Oid roleid)
{
	Relation	relsetting;

	if (!IsUnderPostmaster)
		return;

	relsetting = heap_open(DbRoleSettingRelationId, AccessShareLock);

	
	ApplySetting(databaseid, roleid, relsetting, PGC_S_DATABASE_USER);
	ApplySetting(InvalidOid, roleid, relsetting, PGC_S_USER);
	ApplySetting(databaseid, InvalidOid, relsetting, PGC_S_DATABASE);
	ApplySetting(InvalidOid, InvalidOid, relsetting, PGC_S_GLOBAL);

	heap_close(relsetting, AccessShareLock);
}


static void ShutdownPostgres(int code, Datum arg)
{
	
	AbortOutOfAnyTransaction();

	
	LockReleaseAll(USER_LOCKMETHOD, true);
}



static void StatementTimeoutHandler(void)
{

	
	kill(-MyProcPid, SIGINT);

	kill(MyProcPid, SIGINT);
}


static void LockTimeoutHandler(void)
{

	
	kill(-MyProcPid, SIGINT);

	kill(MyProcPid, SIGINT);
}



static bool ThereIsAtLeastOneRole(void)
{
	Relation	pg_authid_rel;
	HeapScanDesc scan;
	bool		result;

	pg_authid_rel = heap_open(AuthIdRelationId, AccessShareLock);

	scan = heap_beginscan(pg_authid_rel, SnapshotNow, 0, NULL);
	result = (heap_getnext(scan, ForwardScanDirection) != NULL);

	heap_endscan(scan);
	heap_close(pg_authid_rel, AccessShareLock);

	return result;
}
