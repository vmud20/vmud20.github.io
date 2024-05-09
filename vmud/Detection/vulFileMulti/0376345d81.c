

































PG_MODULE_MAGIC;

typedef struct remoteConn {
	PGconn	   *conn;			
	int			openCursorCount;	
	bool		newXactForCursor;		
}	remoteConn;


static Datum dblink_record_internal(FunctionCallInfo fcinfo, bool is_async, bool do_get);
static remoteConn *getConnectionByName(const char *name);
static HTAB *createConnHash(void);
static void createNewConnection(const char *name, remoteConn * rconn);
static void deleteConnection(const char *name);
static char **get_pkey_attnames(Oid relid, int16 *numatts);
static char **get_text_array_contents(ArrayType *array, int *numitems);
static char *get_sql_insert(Oid relid, int2vector *pkattnums, int16 pknumatts, char **src_pkattvals, char **tgt_pkattvals);
static char *get_sql_delete(Oid relid, int2vector *pkattnums, int16 pknumatts, char **tgt_pkattvals);
static char *get_sql_update(Oid relid, int2vector *pkattnums, int16 pknumatts, char **src_pkattvals, char **tgt_pkattvals);
static char *quote_literal_cstr(char *rawstr);
static char *quote_ident_cstr(char *rawstr);
static int16 get_attnum_pk_pos(int2vector *pkattnums, int16 pknumatts, int16 key);
static HeapTuple get_tuple_of_interest(Oid relid, int2vector *pkattnums, int16 pknumatts, char **src_pkattvals);
static Oid	get_relid_from_relname(text *relname_text);
static char *generate_relation_name(Oid relid);


static remoteConn *pconn = NULL;
static HTAB *remoteConnHash = NULL;



typedef struct remoteConnHashEnt {
	char		name[NAMEDATALEN];
	remoteConn *rconn;
}	remoteConnHashEnt;
























































































PG_FUNCTION_INFO_V1(dblink_connect);
Datum dblink_connect(PG_FUNCTION_ARGS)
{
	char	   *connstr = NULL;
	char	   *connname = NULL;
	char	   *msg;
	MemoryContext oldcontext;
	PGconn	   *conn = NULL;
	remoteConn *rconn = NULL;

	DBLINK_INIT;

	if (PG_NARGS() == 2)
	{
		connstr = GET_STR(PG_GETARG_TEXT_P(1));
		connname = GET_STR(PG_GETARG_TEXT_P(0));
	}
	else if (PG_NARGS() == 1)
		connstr = GET_STR(PG_GETARG_TEXT_P(0));

	oldcontext = MemoryContextSwitchTo(TopMemoryContext);

	if (connname)
		rconn = (remoteConn *) palloc(sizeof(remoteConn));
	conn = PQconnectdb(connstr);

	MemoryContextSwitchTo(oldcontext);

	if (PQstatus(conn) == CONNECTION_BAD)
	{
		msg = pstrdup(PQerrorMessage(conn));
		PQfinish(conn);
		if (rconn)
			pfree(rconn);

		ereport(ERROR, (errcode(ERRCODE_SQLCLIENT_UNABLE_TO_ESTABLISH_SQLCONNECTION), errmsg("could not establish connection"), errdetail("%s", msg)));


	}

	if (!superuser())
	{
		if (!PQconnectionUsedPassword(conn))
		{
			PQfinish(conn);
			if (rconn)
				pfree(rconn);

			ereport(ERROR, (errcode(ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED), errmsg("password is required"), errdetail("Non-superuser cannot connect if the server does not request a password."), errhint("Target server's authentication method must be changed.")));



		}
	}

	if (connname)
	{
		rconn->conn = conn;
		createNewConnection(connname, rconn);
	}
	else pconn->conn = conn;

	PG_RETURN_TEXT_P(GET_TEXT("OK"));
}


PG_FUNCTION_INFO_V1(dblink_disconnect);
Datum dblink_disconnect(PG_FUNCTION_ARGS)
{
	char	   *conname = NULL;
	remoteConn *rconn = NULL;
	PGconn	   *conn = NULL;

	DBLINK_INIT;

	if (PG_NARGS() == 1)
	{
		conname = GET_STR(PG_GETARG_TEXT_P(0));
		rconn = getConnectionByName(conname);
		if (rconn)
			conn = rconn->conn;
	}
	else conn = pconn->conn;

	if (!conn)
		DBLINK_CONN_NOT_AVAIL;

	PQfinish(conn);
	if (rconn)
	{
		deleteConnection(conname);
		pfree(rconn);
	}
	else pconn->conn = NULL;

	PG_RETURN_TEXT_P(GET_TEXT("OK"));
}


PG_FUNCTION_INFO_V1(dblink_open);
Datum dblink_open(PG_FUNCTION_ARGS)
{
	char	   *msg;
	PGresult   *res = NULL;
	PGconn	   *conn = NULL;
	char	   *curname = NULL;
	char	   *sql = NULL;
	char	   *conname = NULL;
	StringInfoData buf;
	remoteConn *rconn = NULL;
	bool		fail = true;	

	DBLINK_INIT;
	initStringInfo(&buf);

	if (PG_NARGS() == 2)
	{
		
		curname = GET_STR(PG_GETARG_TEXT_P(0));
		sql = GET_STR(PG_GETARG_TEXT_P(1));
		rconn = pconn;
	}
	else if (PG_NARGS() == 3)
	{
		
		if (get_fn_expr_argtype(fcinfo->flinfo, 2) == BOOLOID)
		{
			curname = GET_STR(PG_GETARG_TEXT_P(0));
			sql = GET_STR(PG_GETARG_TEXT_P(1));
			fail = PG_GETARG_BOOL(2);
			rconn = pconn;
		}
		else {
			conname = GET_STR(PG_GETARG_TEXT_P(0));
			curname = GET_STR(PG_GETARG_TEXT_P(1));
			sql = GET_STR(PG_GETARG_TEXT_P(2));
			rconn = getConnectionByName(conname);
		}
	}
	else if (PG_NARGS() == 4)
	{
		
		conname = GET_STR(PG_GETARG_TEXT_P(0));
		curname = GET_STR(PG_GETARG_TEXT_P(1));
		sql = GET_STR(PG_GETARG_TEXT_P(2));
		fail = PG_GETARG_BOOL(3);
		rconn = getConnectionByName(conname);
	}

	if (!rconn || !rconn->conn)
		DBLINK_CONN_NOT_AVAIL;
	else conn = rconn->conn;

	
	if (PQtransactionStatus(conn) == PQTRANS_IDLE)
	{
		res = PQexec(conn, "BEGIN");
		if (PQresultStatus(res) != PGRES_COMMAND_OK)
			DBLINK_RES_INTERNALERROR("begin error");
		PQclear(res);
		rconn->newXactForCursor = TRUE;

		
		rconn->openCursorCount = 0;
	}

	
	if (rconn->newXactForCursor)
		(rconn->openCursorCount)++;

	appendStringInfo(&buf, "DECLARE %s CURSOR FOR %s", curname, sql);
	res = PQexec(conn, buf.data);
	if (!res || PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		if (fail)
			DBLINK_RES_ERROR("sql error");
		else {
			DBLINK_RES_ERROR_AS_NOTICE("sql error");
			PG_RETURN_TEXT_P(GET_TEXT("ERROR"));
		}
	}

	PQclear(res);
	PG_RETURN_TEXT_P(GET_TEXT("OK"));
}


PG_FUNCTION_INFO_V1(dblink_close);
Datum dblink_close(PG_FUNCTION_ARGS)
{
	PGconn	   *conn = NULL;
	PGresult   *res = NULL;
	char	   *curname = NULL;
	char	   *conname = NULL;
	StringInfoData buf;
	char	   *msg;
	remoteConn *rconn = NULL;
	bool		fail = true;	

	DBLINK_INIT;
	initStringInfo(&buf);

	if (PG_NARGS() == 1)
	{
		
		curname = GET_STR(PG_GETARG_TEXT_P(0));
		rconn = pconn;
	}
	else if (PG_NARGS() == 2)
	{
		
		if (get_fn_expr_argtype(fcinfo->flinfo, 1) == BOOLOID)
		{
			curname = GET_STR(PG_GETARG_TEXT_P(0));
			fail = PG_GETARG_BOOL(1);
			rconn = pconn;
		}
		else {
			conname = GET_STR(PG_GETARG_TEXT_P(0));
			curname = GET_STR(PG_GETARG_TEXT_P(1));
			rconn = getConnectionByName(conname);
		}
	}
	if (PG_NARGS() == 3)
	{
		
		conname = GET_STR(PG_GETARG_TEXT_P(0));
		curname = GET_STR(PG_GETARG_TEXT_P(1));
		fail = PG_GETARG_BOOL(2);
		rconn = getConnectionByName(conname);
	}

	if (!rconn || !rconn->conn)
		DBLINK_CONN_NOT_AVAIL;
	else conn = rconn->conn;

	appendStringInfo(&buf, "CLOSE %s", curname);

	
	res = PQexec(conn, buf.data);
	if (!res || PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		if (fail)
			DBLINK_RES_ERROR("sql error");
		else {
			DBLINK_RES_ERROR_AS_NOTICE("sql error");
			PG_RETURN_TEXT_P(GET_TEXT("ERROR"));
		}
	}

	PQclear(res);

	
	if (rconn->newXactForCursor)
	{
		(rconn->openCursorCount)--;

		
		if (rconn->openCursorCount == 0)
		{
			rconn->newXactForCursor = FALSE;

			res = PQexec(conn, "COMMIT");
			if (PQresultStatus(res) != PGRES_COMMAND_OK)
				DBLINK_RES_INTERNALERROR("commit error");
			PQclear(res);
		}
	}

	PG_RETURN_TEXT_P(GET_TEXT("OK"));
}


PG_FUNCTION_INFO_V1(dblink_fetch);
Datum dblink_fetch(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	TupleDesc	tupdesc = NULL;
	int			call_cntr;
	int			max_calls;
	AttInMetadata *attinmeta;
	char	   *msg;
	PGresult   *res = NULL;
	MemoryContext oldcontext;
	char	   *conname = NULL;
	remoteConn *rconn = NULL;

	DBLINK_INIT;

	
	if (SRF_IS_FIRSTCALL())
	{
		PGconn	   *conn = NULL;
		StringInfoData buf;
		char	   *curname = NULL;
		int			howmany = 0;
		bool		fail = true;	

		if (PG_NARGS() == 4)
		{
			
			conname = GET_STR(PG_GETARG_TEXT_P(0));
			curname = GET_STR(PG_GETARG_TEXT_P(1));
			howmany = PG_GETARG_INT32(2);
			fail = PG_GETARG_BOOL(3);

			rconn = getConnectionByName(conname);
			if (rconn)
				conn = rconn->conn;
		}
		else if (PG_NARGS() == 3)
		{
			
			if (get_fn_expr_argtype(fcinfo->flinfo, 2) == BOOLOID)
			{
				curname = GET_STR(PG_GETARG_TEXT_P(0));
				howmany = PG_GETARG_INT32(1);
				fail = PG_GETARG_BOOL(2);
				conn = pconn->conn;
			}
			else {
				conname = GET_STR(PG_GETARG_TEXT_P(0));
				curname = GET_STR(PG_GETARG_TEXT_P(1));
				howmany = PG_GETARG_INT32(2);

				rconn = getConnectionByName(conname);
				if (rconn)
					conn = rconn->conn;
			}
		}
		else if (PG_NARGS() == 2)
		{
			
			curname = GET_STR(PG_GETARG_TEXT_P(0));
			howmany = PG_GETARG_INT32(1);
			conn = pconn->conn;
		}

		if (!conn)
			DBLINK_CONN_NOT_AVAIL;

		initStringInfo(&buf);
		appendStringInfo(&buf, "FETCH %d FROM %s", howmany, curname);

		
		funcctx = SRF_FIRSTCALL_INIT();

		
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		res = PQexec(conn, buf.data);
		if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK))

		{
			if (fail)
				DBLINK_RES_ERROR("sql error");
			else {
				DBLINK_RES_ERROR_AS_NOTICE("sql error");
				SRF_RETURN_DONE(funcctx);
			}
		}
		else if (PQresultStatus(res) == PGRES_COMMAND_OK)
		{
			
			PQclear(res);
			ereport(ERROR, (errcode(ERRCODE_INVALID_CURSOR_NAME), errmsg("cursor \"%s\" does not exist", curname)));

		}

		funcctx->max_calls = PQntuples(res);

		
		funcctx->user_fctx = res;

		
		switch (get_call_result_type(fcinfo, NULL, &tupdesc))
		{
			case TYPEFUNC_COMPOSITE:
				
				break;
			case TYPEFUNC_RECORD:
				
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function returning record called in context " "that cannot accept type record")));


				break;
			default:
				
				elog(ERROR, "return type must be a row type");
				break;
		}

		
		tupdesc = CreateTupleDescCopy(tupdesc);

		
		if (PQnfields(res) != tupdesc->natts)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("remote query result rowtype does not match " "the specified FROM clause rowtype")));



		
		if (funcctx->max_calls < 1)
		{
			if (res)
				PQclear(res);
			SRF_RETURN_DONE(funcctx);
		}

		
		attinmeta = TupleDescGetAttInMetadata(tupdesc);
		funcctx->attinmeta = attinmeta;

		MemoryContextSwitchTo(oldcontext);
	}

	
	funcctx = SRF_PERCALL_SETUP();

	
	call_cntr = funcctx->call_cntr;
	max_calls = funcctx->max_calls;

	res = (PGresult *) funcctx->user_fctx;
	attinmeta = funcctx->attinmeta;
	tupdesc = attinmeta->tupdesc;

	if (call_cntr < max_calls)	
	{
		char	  **values;
		HeapTuple	tuple;
		Datum		result;
		int			i;
		int			nfields = PQnfields(res);

		values = (char **) palloc(nfields * sizeof(char *));
		for (i = 0; i < nfields; i++)
		{
			if (PQgetisnull(res, call_cntr, i) == 0)
				values[i] = PQgetvalue(res, call_cntr, i);
			else values[i] = NULL;
		}

		
		tuple = BuildTupleFromCStrings(attinmeta, values);

		
		result = HeapTupleGetDatum(tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else {
		
		PQclear(res);
		SRF_RETURN_DONE(funcctx);
	}
}


PG_FUNCTION_INFO_V1(dblink_record);
Datum dblink_record(PG_FUNCTION_ARGS)
{
	return dblink_record_internal(fcinfo, false, false);
}

PG_FUNCTION_INFO_V1(dblink_send_query);
Datum dblink_send_query(PG_FUNCTION_ARGS)
{
	return dblink_record_internal(fcinfo, true, false);
}

PG_FUNCTION_INFO_V1(dblink_get_result);
Datum dblink_get_result(PG_FUNCTION_ARGS)
{
	return dblink_record_internal(fcinfo, true, true);
}

static Datum dblink_record_internal(FunctionCallInfo fcinfo, bool is_async, bool do_get)
{
	FuncCallContext *funcctx;
	TupleDesc	tupdesc = NULL;
	int			call_cntr;
	int			max_calls;
	AttInMetadata *attinmeta;
	char	   *msg;
	PGresult   *res = NULL;
	bool		is_sql_cmd = false;
	char	   *sql_cmd_status = NULL;
	MemoryContext oldcontext;
	bool		freeconn = false;

	DBLINK_INIT;

	
	if (SRF_IS_FIRSTCALL())
	{
		PGconn	   *conn = NULL;
		char	   *connstr = NULL;
		char	   *sql = NULL;
		char	   *conname = NULL;
		remoteConn *rconn = NULL;
		bool		fail = true;	

		
		funcctx = SRF_FIRSTCALL_INIT();

		
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		if (!is_async)
		{
			if (PG_NARGS() == 3)
			{
				
				DBLINK_GET_CONN;
				sql = GET_STR(PG_GETARG_TEXT_P(1));
				fail = PG_GETARG_BOOL(2);
			}
			else if (PG_NARGS() == 2)
			{
				
				if (get_fn_expr_argtype(fcinfo->flinfo, 1) == BOOLOID)
				{
					conn = pconn->conn;
					sql = GET_STR(PG_GETARG_TEXT_P(0));
					fail = PG_GETARG_BOOL(1);
				}
				else {
					DBLINK_GET_CONN;
					sql = GET_STR(PG_GETARG_TEXT_P(1));
				}
			}
			else if (PG_NARGS() == 1)
			{
				
				conn = pconn->conn;
				sql = GET_STR(PG_GETARG_TEXT_P(0));
			}
			else  elog(ERROR, "wrong number of arguments");

		}
		else if (is_async && do_get)
		{
			
			if (PG_NARGS() == 2)
			{
				
				DBLINK_GET_CONN;
				fail = PG_GETARG_BOOL(2);
			}
			else if (PG_NARGS() == 1)
			{
				
				DBLINK_GET_CONN;
			}
			else  elog(ERROR, "wrong number of arguments");

		}
		else {
			
			if (PG_NARGS() == 2)
			{
				DBLINK_GET_CONN;
				sql = GET_STR(PG_GETARG_TEXT_P(1));
			}
			else  elog(ERROR, "wrong number of arguments");

		}

		if (!conn)
			DBLINK_CONN_NOT_AVAIL;

		if (!is_async || (is_async && do_get))
		{
			
			if (!is_async)
				res = PQexec(conn, sql);
			else {
				res = PQgetResult(conn);
				
				if (!res)
					SRF_RETURN_DONE(funcctx);
			}

			if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK))

			{
				if (fail)
					DBLINK_RES_ERROR("sql error");
				else {
					DBLINK_RES_ERROR_AS_NOTICE("sql error");
					if (freeconn)
						PQfinish(conn);
					SRF_RETURN_DONE(funcctx);
				}
			}

			if (PQresultStatus(res) == PGRES_COMMAND_OK)
			{
				is_sql_cmd = true;

				
				tupdesc = CreateTemplateTupleDesc(1, false);
				TupleDescInitEntry(tupdesc, (AttrNumber) 1, "status", TEXTOID, -1, 0);

				
				sql_cmd_status = PQcmdStatus(res);
				funcctx->max_calls = 1;
			}
			else funcctx->max_calls = PQntuples(res);

			
			funcctx->user_fctx = res;

			
			if (freeconn)
				PQfinish(conn);

			if (!is_sql_cmd)
			{
				
				switch (get_call_result_type(fcinfo, NULL, &tupdesc))
				{
					case TYPEFUNC_COMPOSITE:
						
						break;
					case TYPEFUNC_RECORD:
						
						ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function returning record called in context " "that cannot accept type record")));


						break;
					default:
						
						elog(ERROR, "return type must be a row type");
						break;
				}

				
				tupdesc = CreateTupleDescCopy(tupdesc);
			}

			
			if (PQnfields(res) != tupdesc->natts)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("remote query result rowtype does not match " "the specified FROM clause rowtype")));



			
			if (funcctx->max_calls < 1)
			{
				if (res)
					PQclear(res);
				SRF_RETURN_DONE(funcctx);
			}

			
			attinmeta = TupleDescGetAttInMetadata(tupdesc);
			funcctx->attinmeta = attinmeta;

			MemoryContextSwitchTo(oldcontext);
		}
		else {
			
			MemoryContextSwitchTo(oldcontext);
			PG_RETURN_INT32(PQsendQuery(conn, sql));
		}
	}

	if (is_async && !do_get)
	{
		
		elog(ERROR, "async query send called more than once");

	}

	
	funcctx = SRF_PERCALL_SETUP();

	
	call_cntr = funcctx->call_cntr;
	max_calls = funcctx->max_calls;

	res = (PGresult *) funcctx->user_fctx;
	attinmeta = funcctx->attinmeta;
	tupdesc = attinmeta->tupdesc;

	if (call_cntr < max_calls)	
	{
		char	  **values;
		HeapTuple	tuple;
		Datum		result;

		if (!is_sql_cmd)
		{
			int			i;
			int			nfields = PQnfields(res);

			values = (char **) palloc(nfields * sizeof(char *));
			for (i = 0; i < nfields; i++)
			{
				if (PQgetisnull(res, call_cntr, i) == 0)
					values[i] = PQgetvalue(res, call_cntr, i);
				else values[i] = NULL;
			}
		}
		else {
			values = (char **) palloc(1 * sizeof(char *));
			values[0] = sql_cmd_status;
		}

		
		tuple = BuildTupleFromCStrings(attinmeta, values);

		
		result = HeapTupleGetDatum(tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else {
		
		PQclear(res);
		SRF_RETURN_DONE(funcctx);
	}
}


PG_FUNCTION_INFO_V1(dblink_get_connections);
Datum dblink_get_connections(PG_FUNCTION_ARGS)
{
	HASH_SEQ_STATUS status;
	remoteConnHashEnt *hentry;
	ArrayBuildState *astate = NULL;

	if (remoteConnHash)
	{
		hash_seq_init(&status, remoteConnHash);
		while ((hentry = (remoteConnHashEnt *) hash_seq_search(&status)) != NULL)
		{
			
			astate = accumArrayResult(astate, PointerGetDatum(GET_TEXT(hentry->name)), false, TEXTOID, CurrentMemoryContext);

		}
	}

	if (astate)
		PG_RETURN_ARRAYTYPE_P(makeArrayResult(astate, CurrentMemoryContext));
	else PG_RETURN_NULL();
}


PG_FUNCTION_INFO_V1(dblink_is_busy);
Datum dblink_is_busy(PG_FUNCTION_ARGS)
{
	char	   *msg;
	PGconn	   *conn = NULL;
	char	   *conname = NULL;
	char	   *connstr = NULL;
	remoteConn *rconn = NULL;
	bool		freeconn = false;

	DBLINK_INIT;
	DBLINK_GET_CONN;
	if (!conn)
		DBLINK_CONN_NOT_AVAIL;

	PQconsumeInput(conn);
	PG_RETURN_INT32(PQisBusy(conn));
}


PG_FUNCTION_INFO_V1(dblink_cancel_query);
Datum dblink_cancel_query(PG_FUNCTION_ARGS)
{
	char	   *msg;
	int			res = 0;
	PGconn	   *conn = NULL;
	char	   *conname = NULL;
	char	   *connstr = NULL;
	remoteConn *rconn = NULL;
	bool		freeconn = false;
	PGcancel   *cancel;
	char		errbuf[256];

	DBLINK_INIT;
	DBLINK_GET_CONN;
	if (!conn)
		DBLINK_CONN_NOT_AVAIL;
	cancel = PQgetCancel(conn);

	res = PQcancel(cancel, errbuf, 256);
	PQfreeCancel(cancel);

	if (res == 0)
		PG_RETURN_TEXT_P(GET_TEXT("OK"));
	else PG_RETURN_TEXT_P(GET_TEXT(errbuf));
}



PG_FUNCTION_INFO_V1(dblink_error_message);
Datum dblink_error_message(PG_FUNCTION_ARGS)
{
	char	   *msg;
	PGconn	   *conn = NULL;
	char	   *conname = NULL;
	char	   *connstr = NULL;
	remoteConn *rconn = NULL;
	bool		freeconn = false;

	DBLINK_INIT;
	DBLINK_GET_CONN;
	if (!conn)
		DBLINK_CONN_NOT_AVAIL;

	msg = PQerrorMessage(conn);
	if (!msg)
		PG_RETURN_TEXT_P(GET_TEXT("OK"));
	else PG_RETURN_TEXT_P(GET_TEXT(msg));
}


PG_FUNCTION_INFO_V1(dblink_exec);
Datum dblink_exec(PG_FUNCTION_ARGS)
{
	char	   *msg;
	PGresult   *res = NULL;
	text	   *sql_cmd_status = NULL;
	TupleDesc	tupdesc = NULL;
	PGconn	   *conn = NULL;
	char	   *connstr = NULL;
	char	   *sql = NULL;
	char	   *conname = NULL;
	remoteConn *rconn = NULL;
	bool		freeconn = false;
	bool		fail = true;	

	DBLINK_INIT;

	if (PG_NARGS() == 3)
	{
		
		DBLINK_GET_CONN;
		sql = GET_STR(PG_GETARG_TEXT_P(1));
		fail = PG_GETARG_BOOL(2);
	}
	else if (PG_NARGS() == 2)
	{
		
		if (get_fn_expr_argtype(fcinfo->flinfo, 1) == BOOLOID)
		{
			conn = pconn->conn;
			sql = GET_STR(PG_GETARG_TEXT_P(0));
			fail = PG_GETARG_BOOL(1);
		}
		else {
			DBLINK_GET_CONN;
			sql = GET_STR(PG_GETARG_TEXT_P(1));
		}
	}
	else if (PG_NARGS() == 1)
	{
		
		conn = pconn->conn;
		sql = GET_STR(PG_GETARG_TEXT_P(0));
	}
	else  elog(ERROR, "wrong number of arguments");


	if (!conn)
		DBLINK_CONN_NOT_AVAIL;

	res = PQexec(conn, sql);
	if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK))

	{
		if (fail)
			DBLINK_RES_ERROR("sql error");
		else DBLINK_RES_ERROR_AS_NOTICE("sql error");

		
		tupdesc = CreateTemplateTupleDesc(1, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "status", TEXTOID, -1, 0);

		
		sql_cmd_status = GET_TEXT("ERROR");

	}
	else if (PQresultStatus(res) == PGRES_COMMAND_OK)
	{
		
		tupdesc = CreateTemplateTupleDesc(1, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "status", TEXTOID, -1, 0);

		
		sql_cmd_status = GET_TEXT(PQcmdStatus(res));
		PQclear(res);
	}
	else {
		PQclear(res);
		ereport(ERROR, (errcode(ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED), errmsg("statement returning results not allowed")));

	}

	
	if (freeconn)
		PQfinish(conn);

	PG_RETURN_TEXT_P(sql_cmd_status);
}



PG_FUNCTION_INFO_V1(dblink_get_pkey);
Datum dblink_get_pkey(PG_FUNCTION_ARGS)
{
	int16		numatts;
	Oid			relid;
	char	  **results;
	FuncCallContext *funcctx;
	int32		call_cntr;
	int32		max_calls;
	AttInMetadata *attinmeta;
	MemoryContext oldcontext;

	
	if (SRF_IS_FIRSTCALL())
	{
		TupleDesc	tupdesc = NULL;

		
		funcctx = SRF_FIRSTCALL_INIT();

		
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		
		relid = get_relid_from_relname(PG_GETARG_TEXT_P(0));
		if (!OidIsValid(relid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_TABLE), errmsg("relation \"%s\" does not exist", GET_STR(PG_GETARG_TEXT_P(0)))));



		
		tupdesc = CreateTemplateTupleDesc(2, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "position", INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "colname", TEXTOID, -1, 0);

		
		attinmeta = TupleDescGetAttInMetadata(tupdesc);
		funcctx->attinmeta = attinmeta;

		
		results = get_pkey_attnames(relid, &numatts);

		if ((results != NULL) && (numatts > 0))
		{
			funcctx->max_calls = numatts;

			
			funcctx->user_fctx = results;
		}
		else  SRF_RETURN_DONE(funcctx);


		MemoryContextSwitchTo(oldcontext);
	}

	
	funcctx = SRF_PERCALL_SETUP();

	
	call_cntr = funcctx->call_cntr;
	max_calls = funcctx->max_calls;

	results = (char **) funcctx->user_fctx;
	attinmeta = funcctx->attinmeta;

	if (call_cntr < max_calls)	
	{
		char	  **values;
		HeapTuple	tuple;
		Datum		result;

		values = (char **) palloc(2 * sizeof(char *));
		values[0] = (char *) palloc(12);		

		sprintf(values[0], "%d", call_cntr + 1);

		values[1] = results[call_cntr];

		
		tuple = BuildTupleFromCStrings(attinmeta, values);

		
		result = HeapTupleGetDatum(tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else {
		
		SRF_RETURN_DONE(funcctx);
	}
}



PG_FUNCTION_INFO_V1(dblink_build_sql_insert);
Datum dblink_build_sql_insert(PG_FUNCTION_ARGS)
{
	text	   *relname_text = PG_GETARG_TEXT_P(0);
	int2vector *pkattnums = (int2vector *) PG_GETARG_POINTER(1);
	int32		pknumatts_tmp = PG_GETARG_INT32(2);
	ArrayType  *src_pkattvals_arry = PG_GETARG_ARRAYTYPE_P(3);
	ArrayType  *tgt_pkattvals_arry = PG_GETARG_ARRAYTYPE_P(4);
	Oid			relid;
	int16		pknumatts = 0;
	char	  **src_pkattvals;
	char	  **tgt_pkattvals;
	int			src_nitems;
	int			tgt_nitems;
	char	   *sql;

	
	relid = get_relid_from_relname(relname_text);
	if (!OidIsValid(relid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_TABLE), errmsg("relation \"%s\" does not exist", GET_STR(relname_text))));



	
	if (pknumatts_tmp <= 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("number of key attributes must be > 0")));


	if (pknumatts_tmp <= SHRT_MAX)
		pknumatts = pknumatts_tmp;
	else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("input for number of primary key "  "attributes too large")))



	
	src_pkattvals = get_text_array_contents(src_pkattvals_arry, &src_nitems);

	
	if (src_nitems != pknumatts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("source key array length must match number of key "  "attributes")))


	
	tgt_pkattvals = get_text_array_contents(tgt_pkattvals_arry, &tgt_nitems);

	
	if (tgt_nitems != pknumatts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("target key array length must match number of key "  "attributes")))


	
	sql = get_sql_insert(relid, pkattnums, pknumatts, src_pkattvals, tgt_pkattvals);

	
	PG_RETURN_TEXT_P(GET_TEXT(sql));
}



PG_FUNCTION_INFO_V1(dblink_build_sql_delete);
Datum dblink_build_sql_delete(PG_FUNCTION_ARGS)
{
	text	   *relname_text = PG_GETARG_TEXT_P(0);
	int2vector *pkattnums = (int2vector *) PG_GETARG_POINTER(1);
	int32		pknumatts_tmp = PG_GETARG_INT32(2);
	ArrayType  *tgt_pkattvals_arry = PG_GETARG_ARRAYTYPE_P(3);
	Oid			relid;
	int16		pknumatts = 0;
	char	  **tgt_pkattvals;
	int			tgt_nitems;
	char	   *sql;

	
	relid = get_relid_from_relname(relname_text);
	if (!OidIsValid(relid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_TABLE), errmsg("relation \"%s\" does not exist", GET_STR(relname_text))));



	
	if (pknumatts_tmp <= 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("number of key attributes must be > 0")));


	if (pknumatts_tmp <= SHRT_MAX)
		pknumatts = pknumatts_tmp;
	else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("input for number of primary key "  "attributes too large")))



	
	tgt_pkattvals = get_text_array_contents(tgt_pkattvals_arry, &tgt_nitems);

	
	if (tgt_nitems != pknumatts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("target key array length must match number of key "  "attributes")))


	
	sql = get_sql_delete(relid, pkattnums, pknumatts, tgt_pkattvals);

	
	PG_RETURN_TEXT_P(GET_TEXT(sql));
}



PG_FUNCTION_INFO_V1(dblink_build_sql_update);
Datum dblink_build_sql_update(PG_FUNCTION_ARGS)
{
	text	   *relname_text = PG_GETARG_TEXT_P(0);
	int2vector *pkattnums = (int2vector *) PG_GETARG_POINTER(1);
	int32		pknumatts_tmp = PG_GETARG_INT32(2);
	ArrayType  *src_pkattvals_arry = PG_GETARG_ARRAYTYPE_P(3);
	ArrayType  *tgt_pkattvals_arry = PG_GETARG_ARRAYTYPE_P(4);
	Oid			relid;
	int16		pknumatts = 0;
	char	  **src_pkattvals;
	char	  **tgt_pkattvals;
	int			src_nitems;
	int			tgt_nitems;
	char	   *sql;

	
	relid = get_relid_from_relname(relname_text);
	if (!OidIsValid(relid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_TABLE), errmsg("relation \"%s\" does not exist", GET_STR(relname_text))));



	
	if (pknumatts_tmp <= 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("number of key attributes must be > 0")));


	if (pknumatts_tmp <= SHRT_MAX)
		pknumatts = pknumatts_tmp;
	else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("input for number of primary key "  "attributes too large")))



	
	src_pkattvals = get_text_array_contents(src_pkattvals_arry, &src_nitems);

	
	if (src_nitems != pknumatts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("source key array length must match number of key "  "attributes")))


	
	tgt_pkattvals = get_text_array_contents(tgt_pkattvals_arry, &tgt_nitems);

	
	if (tgt_nitems != pknumatts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("target key array length must match number of key "  "attributes")))


	
	sql = get_sql_update(relid, pkattnums, pknumatts, src_pkattvals, tgt_pkattvals);

	
	PG_RETURN_TEXT_P(GET_TEXT(sql));
}


PG_FUNCTION_INFO_V1(dblink_current_query);
Datum dblink_current_query(PG_FUNCTION_ARGS)
{
	if (debug_query_string)
		PG_RETURN_TEXT_P(GET_TEXT(debug_query_string));
	else PG_RETURN_NULL();
}






static char ** get_pkey_attnames(Oid relid, int16 *numatts)
{
	Relation	indexRelation;
	ScanKeyData entry;
	HeapScanDesc scan;
	HeapTuple	indexTuple;
	int			i;
	char	  **result = NULL;
	Relation	rel;
	TupleDesc	tupdesc;
	AclResult	aclresult;

	
	rel = relation_open(relid, AccessShareLock);

	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, RelationGetRelationName(rel));

	tupdesc = rel->rd_att;

	
	*numatts = 0;

	
	indexRelation = heap_open(IndexRelationId, AccessShareLock);
	ScanKeyInit(&entry, Anum_pg_index_indrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	scan = heap_beginscan(indexRelation, SnapshotNow, 1, &entry);

	while ((indexTuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_index index = (Form_pg_index) GETSTRUCT(indexTuple);

		
		if (index->indisprimary == TRUE)
		{
			*numatts = index->indnatts;
			if (*numatts > 0)
			{
				result = (char **) palloc(*numatts * sizeof(char *));

				for (i = 0; i < *numatts; i++)
					result[i] = SPI_fname(tupdesc, index->indkey.values[i]);
			}
			break;
		}
	}
	heap_endscan(scan);
	heap_close(indexRelation, AccessShareLock);
	relation_close(rel, AccessShareLock);

	return result;
}


static char ** get_text_array_contents(ArrayType *array, int *numitems)
{
	int			ndim = ARR_NDIM(array);
	int		   *dims = ARR_DIMS(array);
	int			nitems;
	int16		typlen;
	bool		typbyval;
	char		typalign;
	char	  **values;
	char	   *ptr;
	bits8	   *bitmap;
	int			bitmask;
	int			i;

	Assert(ARR_ELEMTYPE(array) == TEXTOID);

	*numitems = nitems = ArrayGetNItems(ndim, dims);

	get_typlenbyvalalign(ARR_ELEMTYPE(array), &typlen, &typbyval, &typalign);

	values = (char **) palloc(nitems * sizeof(char *));

	ptr = ARR_DATA_PTR(array);
	bitmap = ARR_NULLBITMAP(array);
	bitmask = 1;

	for (i = 0; i < nitems; i++)
	{
		if (bitmap && (*bitmap & bitmask) == 0)
		{
			values[i] = NULL;
		}
		else {
			values[i] = DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(ptr)));
			ptr = att_addlength_pointer(ptr, typlen, ptr);
			ptr = (char *) att_align_nominal(ptr, typalign);
		}

		
		if (bitmap)
		{
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				bitmap++;
				bitmask = 1;
			}
		}
	}

	return values;
}

static char * get_sql_insert(Oid relid, int2vector *pkattnums, int16 pknumatts, char **src_pkattvals, char **tgt_pkattvals)
{
	Relation	rel;
	char	   *relname;
	HeapTuple	tuple;
	TupleDesc	tupdesc;
	int			natts;
	StringInfoData buf;
	char	   *val;
	int16		key;
	int			i;
	bool		needComma;

	initStringInfo(&buf);

	
	relname = generate_relation_name(relid);

	
	rel = relation_open(relid, AccessShareLock);
	tupdesc = rel->rd_att;
	natts = tupdesc->natts;

	tuple = get_tuple_of_interest(relid, pkattnums, pknumatts, src_pkattvals);
	if (!tuple)
		ereport(ERROR, (errcode(ERRCODE_CARDINALITY_VIOLATION), errmsg("source row not found")));


	appendStringInfo(&buf, "INSERT INTO %s(", relname);

	needComma = false;
	for (i = 0; i < natts; i++)
	{
		if (tupdesc->attrs[i]->attisdropped)
			continue;

		if (needComma)
			appendStringInfo(&buf, ",");

		appendStringInfoString(&buf, quote_ident_cstr(NameStr(tupdesc->attrs[i]->attname)));
		needComma = true;
	}

	appendStringInfo(&buf, ") VALUES(");

	
	needComma = false;
	for (i = 0; i < natts; i++)
	{
		if (tupdesc->attrs[i]->attisdropped)
			continue;

		if (needComma)
			appendStringInfo(&buf, ",");

		if (tgt_pkattvals != NULL)
			key = get_attnum_pk_pos(pkattnums, pknumatts, i + 1);
		else key = -1;

		if (key > -1)
			val = tgt_pkattvals[key] ? pstrdup(tgt_pkattvals[key]) : NULL;
		else val = SPI_getvalue(tuple, tupdesc, i + 1);

		if (val != NULL)
		{
			appendStringInfoString(&buf, quote_literal_cstr(val));
			pfree(val);
		}
		else appendStringInfo(&buf, "NULL");
		needComma = true;
	}
	appendStringInfo(&buf, ")");

	relation_close(rel, AccessShareLock);
	return (buf.data);
}

static char * get_sql_delete(Oid relid, int2vector *pkattnums, int16 pknumatts, char **tgt_pkattvals)
{
	Relation	rel;
	char	   *relname;
	TupleDesc	tupdesc;
	int			natts;
	StringInfoData buf;
	int			i;

	initStringInfo(&buf);

	
	relname = generate_relation_name(relid);

	
	rel = relation_open(relid, AccessShareLock);
	tupdesc = rel->rd_att;
	natts = tupdesc->natts;

	appendStringInfo(&buf, "DELETE FROM %s WHERE ", relname);
	for (i = 0; i < pknumatts; i++)
	{
		int16		pkattnum = pkattnums->values[i];

		if (i > 0)
			appendStringInfo(&buf, " AND ");

		appendStringInfoString(&buf, quote_ident_cstr(NameStr(tupdesc->attrs[pkattnum - 1]->attname)));

		if (tgt_pkattvals == NULL)
			
			elog(ERROR, "target key array must not be NULL");

		if (tgt_pkattvals[i] != NULL)
			appendStringInfo(&buf, " = %s", quote_literal_cstr(tgt_pkattvals[i]));
		else appendStringInfo(&buf, " IS NULL");
	}

	relation_close(rel, AccessShareLock);
	return (buf.data);
}

static char * get_sql_update(Oid relid, int2vector *pkattnums, int16 pknumatts, char **src_pkattvals, char **tgt_pkattvals)
{
	Relation	rel;
	char	   *relname;
	HeapTuple	tuple;
	TupleDesc	tupdesc;
	int			natts;
	StringInfoData buf;
	char	   *val;
	int16		key;
	int			i;
	bool		needComma;

	initStringInfo(&buf);

	
	relname = generate_relation_name(relid);

	
	rel = relation_open(relid, AccessShareLock);
	tupdesc = rel->rd_att;
	natts = tupdesc->natts;

	tuple = get_tuple_of_interest(relid, pkattnums, pknumatts, src_pkattvals);
	if (!tuple)
		ereport(ERROR, (errcode(ERRCODE_CARDINALITY_VIOLATION), errmsg("source row not found")));


	appendStringInfo(&buf, "UPDATE %s SET ", relname);

	needComma = false;
	for (i = 0; i < natts; i++)
	{
		if (tupdesc->attrs[i]->attisdropped)
			continue;

		if (needComma)
			appendStringInfo(&buf, ", ");

		appendStringInfo(&buf, "%s = ", quote_ident_cstr(NameStr(tupdesc->attrs[i]->attname)));

		if (tgt_pkattvals != NULL)
			key = get_attnum_pk_pos(pkattnums, pknumatts, i + 1);
		else key = -1;

		if (key > -1)
			val = tgt_pkattvals[key] ? pstrdup(tgt_pkattvals[key]) : NULL;
		else val = SPI_getvalue(tuple, tupdesc, i + 1);

		if (val != NULL)
		{
			appendStringInfoString(&buf, quote_literal_cstr(val));
			pfree(val);
		}
		else appendStringInfoString(&buf, "NULL");
		needComma = true;
	}

	appendStringInfo(&buf, " WHERE ");

	for (i = 0; i < pknumatts; i++)
	{
		int16		pkattnum = pkattnums->values[i];

		if (i > 0)
			appendStringInfo(&buf, " AND ");

		appendStringInfo(&buf, "%s", quote_ident_cstr(NameStr(tupdesc->attrs[pkattnum - 1]->attname)));

		if (tgt_pkattvals != NULL)
			val = tgt_pkattvals[i] ? pstrdup(tgt_pkattvals[i]) : NULL;
		else val = SPI_getvalue(tuple, tupdesc, pkattnum);

		if (val != NULL)
		{
			appendStringInfo(&buf, " = %s", quote_literal_cstr(val));
			pfree(val);
		}
		else appendStringInfo(&buf, " IS NULL");
	}

	relation_close(rel, AccessShareLock);
	return (buf.data);
}


static char * quote_literal_cstr(char *rawstr)
{
	text	   *rawstr_text;
	text	   *result_text;
	char	   *result;

	rawstr_text = DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(rawstr)));
	result_text = DatumGetTextP(DirectFunctionCall1(quote_literal, PointerGetDatum(rawstr_text)));
	result = DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(result_text)));

	return result;
}


static char * quote_ident_cstr(char *rawstr)
{
	text	   *rawstr_text;
	text	   *result_text;
	char	   *result;

	rawstr_text = DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(rawstr)));
	result_text = DatumGetTextP(DirectFunctionCall1(quote_ident, PointerGetDatum(rawstr_text)));
	result = DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(result_text)));

	return result;
}

static int16 get_attnum_pk_pos(int2vector *pkattnums, int16 pknumatts, int16 key)
{
	int			i;

	
	for (i = 0; i < pknumatts; i++)
		if (key == pkattnums->values[i])
			return i;

	return -1;
}

static HeapTuple get_tuple_of_interest(Oid relid, int2vector *pkattnums, int16 pknumatts, char **src_pkattvals)
{
	Relation	rel;
	char	   *relname;
	TupleDesc	tupdesc;
	StringInfoData buf;
	int			ret;
	HeapTuple	tuple;
	int			i;

	initStringInfo(&buf);

	
	relname = generate_relation_name(relid);

	
	rel = relation_open(relid, AccessShareLock);
	tupdesc = CreateTupleDescCopy(rel->rd_att);
	relation_close(rel, AccessShareLock);

	
	if ((ret = SPI_connect()) < 0)
		
		elog(ERROR, "SPI connect failure - returned %d", ret);

	
	appendStringInfo(&buf, "SELECT * FROM %s WHERE ", relname);

	for (i = 0; i < pknumatts; i++)
	{
		int16		pkattnum = pkattnums->values[i];

		if (i > 0)
			appendStringInfo(&buf, " AND ");

		appendStringInfoString(&buf, quote_ident_cstr(NameStr(tupdesc->attrs[pkattnum - 1]->attname)));

		if (src_pkattvals[i] != NULL)
			appendStringInfo(&buf, " = %s", quote_literal_cstr(src_pkattvals[i]));
		else appendStringInfo(&buf, " IS NULL");
	}

	
	ret = SPI_exec(buf.data, 0);
	pfree(buf.data);

	
	if ((ret == SPI_OK_SELECT) && (SPI_processed > 1))
		ereport(ERROR, (errcode(ERRCODE_CARDINALITY_VIOLATION), errmsg("source criteria matched more than one record")));


	else if (ret == SPI_OK_SELECT && SPI_processed == 1)
	{
		SPITupleTable *tuptable = SPI_tuptable;

		tuple = SPI_copytuple(tuptable->vals[0]);
		SPI_finish();

		return tuple;
	}
	else {
		
		SPI_finish();

		return NULL;
	}

	
	return NULL;
}

static Oid get_relid_from_relname(text *relname_text)
{
	RangeVar   *relvar;
	Relation	rel;
	Oid			relid;

	relvar = makeRangeVarFromNameList(textToQualifiedNameList(relname_text));
	rel = heap_openrv(relvar, AccessShareLock);
	relid = RelationGetRelid(rel);
	relation_close(rel, AccessShareLock);

	return relid;
}


static char * generate_relation_name(Oid relid)
{
	HeapTuple	tp;
	Form_pg_class reltup;
	char	   *nspname;
	char	   *result;

	tp = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);

	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for relation %u", relid);

	reltup = (Form_pg_class) GETSTRUCT(tp);

	
	if (RelationIsVisible(relid))
		nspname = NULL;
	else nspname = get_namespace_name(reltup->relnamespace);

	result = quote_qualified_identifier(nspname, NameStr(reltup->relname));

	ReleaseSysCache(tp);

	return result;
}


static remoteConn * getConnectionByName(const char *name)
{
	remoteConnHashEnt *hentry;
	char		key[NAMEDATALEN];

	if (!remoteConnHash)
		remoteConnHash = createConnHash();

	MemSet(key, 0, NAMEDATALEN);
	snprintf(key, NAMEDATALEN - 1, "%s", name);
	hentry = (remoteConnHashEnt *) hash_search(remoteConnHash, key, HASH_FIND, NULL);

	if (hentry)
		return (hentry->rconn);

	return (NULL);
}

static HTAB * createConnHash(void)
{
	HASHCTL		ctl;

	ctl.keysize = NAMEDATALEN;
	ctl.entrysize = sizeof(remoteConnHashEnt);

	return hash_create("Remote Con hash", NUMCONN, &ctl, HASH_ELEM);
}

static void createNewConnection(const char *name, remoteConn * rconn)
{
	remoteConnHashEnt *hentry;
	bool		found;
	char		key[NAMEDATALEN];

	if (!remoteConnHash)
		remoteConnHash = createConnHash();

	MemSet(key, 0, NAMEDATALEN);
	snprintf(key, NAMEDATALEN - 1, "%s", name);
	hentry = (remoteConnHashEnt *) hash_search(remoteConnHash, key, HASH_ENTER, &found);

	if (found)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("duplicate connection name")));


	hentry->rconn = rconn;
	strlcpy(hentry->name, name, sizeof(hentry->name));
}

static void deleteConnection(const char *name)
{
	remoteConnHashEnt *hentry;
	bool		found;
	char		key[NAMEDATALEN];

	if (!remoteConnHash)
		remoteConnHash = createConnHash();

	MemSet(key, 0, NAMEDATALEN);
	snprintf(key, NAMEDATALEN - 1, "%s", name);

	hentry = (remoteConnHashEnt *) hash_search(remoteConnHash, key, HASH_REMOVE, &found);

	if (!hentry)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("undefined connection name")));


}
