





















const char * assign_datestyle(const char *value, bool doit, GucSource source)
{
	int			newDateStyle = DateStyle;
	int			newDateOrder = DateOrder;
	bool		have_style = false;
	bool		have_order = false;
	bool		ok = true;
	char	   *rawstring;
	char	   *result;
	List	   *elemlist;
	ListCell   *l;

	
	rawstring = pstrdup(value);

	
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		
		pfree(rawstring);
		list_free(elemlist);
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid list syntax for parameter \"datestyle\"")));

		return NULL;
	}

	foreach(l, elemlist)
	{
		char	   *tok = (char *) lfirst(l);

		

		if (pg_strcasecmp(tok, "ISO") == 0)
		{
			if (have_style && newDateStyle != USE_ISO_DATES)
				ok = false;		
			newDateStyle = USE_ISO_DATES;
			have_style = true;
		}
		else if (pg_strcasecmp(tok, "SQL") == 0)
		{
			if (have_style && newDateStyle != USE_SQL_DATES)
				ok = false;		
			newDateStyle = USE_SQL_DATES;
			have_style = true;
		}
		else if (pg_strncasecmp(tok, "POSTGRES", 8) == 0)
		{
			if (have_style && newDateStyle != USE_POSTGRES_DATES)
				ok = false;		
			newDateStyle = USE_POSTGRES_DATES;
			have_style = true;
		}
		else if (pg_strcasecmp(tok, "GERMAN") == 0)
		{
			if (have_style && newDateStyle != USE_GERMAN_DATES)
				ok = false;		
			newDateStyle = USE_GERMAN_DATES;
			have_style = true;
			
			if (!have_order)
				newDateOrder = DATEORDER_DMY;
		}
		else if (pg_strcasecmp(tok, "YMD") == 0)
		{
			if (have_order && newDateOrder != DATEORDER_YMD)
				ok = false;		
			newDateOrder = DATEORDER_YMD;
			have_order = true;
		}
		else if (pg_strcasecmp(tok, "DMY") == 0 || pg_strncasecmp(tok, "EURO", 4) == 0)
		{
			if (have_order && newDateOrder != DATEORDER_DMY)
				ok = false;		
			newDateOrder = DATEORDER_DMY;
			have_order = true;
		}
		else if (pg_strcasecmp(tok, "MDY") == 0 || pg_strcasecmp(tok, "US") == 0 || pg_strncasecmp(tok, "NONEURO", 7) == 0)

		{
			if (have_order && newDateOrder != DATEORDER_MDY)
				ok = false;		
			newDateOrder = DATEORDER_MDY;
			have_order = true;
		}
		else if (pg_strcasecmp(tok, "DEFAULT") == 0)
		{
			
			int			saveDateStyle = DateStyle;
			int			saveDateOrder = DateOrder;
			const char *subval;

			subval = assign_datestyle(GetConfigOptionResetString("datestyle"), true, source);
			if (!have_style)
				newDateStyle = DateStyle;
			if (!have_order)
				newDateOrder = DateOrder;
			DateStyle = saveDateStyle;
			DateOrder = saveDateOrder;
			if (!subval)
			{
				ok = false;
				break;
			}
			
			
			free((char *) subval);
		}
		else {
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("unrecognized \"datestyle\" key word: \"%s\"", tok)));


			ok = false;
			break;
		}
	}

	pfree(rawstring);
	list_free(elemlist);

	if (!ok)
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("conflicting \"datestyle\" specifications")));

		return NULL;
	}

	
	if (!doit)
		return value;

	
	result = (char *) malloc(32);
	if (!result)
		return NULL;

	switch (newDateStyle)
	{
		case USE_ISO_DATES:
			strcpy(result, "ISO");
			break;
		case USE_SQL_DATES:
			strcpy(result, "SQL");
			break;
		case USE_GERMAN_DATES:
			strcpy(result, "German");
			break;
		default:
			strcpy(result, "Postgres");
			break;
	}
	switch (newDateOrder)
	{
		case DATEORDER_YMD:
			strcat(result, ", YMD");
			break;
		case DATEORDER_DMY:
			strcat(result, ", DMY");
			break;
		default:
			strcat(result, ", MDY");
			break;
	}

	
	DateStyle = newDateStyle;
	DateOrder = newDateOrder;

	return result;
}





const char * assign_timezone(const char *value, bool doit, GucSource source)
{
	char	   *result;
	char	   *endptr;
	double		hours;

	
	if (pg_strncasecmp(value, "interval", 8) == 0)
	{
		const char *valueptr = value;
		char	   *val;
		Interval   *interval;

		valueptr += 8;
		while (isspace((unsigned char) *valueptr))
			valueptr++;
		if (*valueptr++ != '\'')
			return NULL;
		val = pstrdup(valueptr);
		
		endptr = strchr(val, '\'');
		if (!endptr || endptr[1] != '\0')
		{
			pfree(val);
			return NULL;
		}
		*endptr = '\0';

		
		interval = DatumGetIntervalP(DirectFunctionCall3(interval_in, CStringGetDatum(val), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1)));



		pfree(val);
		if (interval->month != 0)
		{
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid interval value for time zone: month not allowed")));

			pfree(interval);
			return NULL;
		}
		if (interval->day != 0)
		{
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid interval value for time zone: day not allowed")));

			pfree(interval);
			return NULL;
		}
		if (doit)
		{
			

			CTimeZone = -(interval->time / USECS_PER_SEC);

			CTimeZone = -interval->time;


			HasCTZSet = true;
		}
		pfree(interval);
	}
	else {
		
		hours = strtod(value, &endptr);
		if (endptr != value && *endptr == '\0')
		{
			if (doit)
			{
				
				CTimeZone = -hours * SECS_PER_HOUR;
				HasCTZSet = true;
			}
		}
		else if (pg_strcasecmp(value, "UNKNOWN") == 0)
		{
			
			if (doit)
			{
				const char *curzone = pg_get_timezone_name(global_timezone);

				if (curzone)
					value = curzone;
			}
		}
		else {
			
			pg_tz	   *new_tz;

			new_tz = pg_tzset(value);

			if (!new_tz)
			{
				ereport((source >= PGC_S_INTERACTIVE) ? ERROR : LOG, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("unrecognized time zone name: \"%s\"", value)));


				return NULL;
			}

			if (!tz_acceptable(new_tz))
			{
				ereport((source >= PGC_S_INTERACTIVE) ? ERROR : LOG, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("time zone \"%s\" appears to use leap seconds", value), errdetail("PostgreSQL does not support leap seconds.")));



				return NULL;
			}

			if (doit)
			{
				
				global_timezone = new_tz;
				HasCTZSet = false;
			}
		}
	}

	
	if (!doit)
		return value;

	
	if (HasCTZSet)
	{
		result = (char *) malloc(64);
		if (!result)
			return NULL;
		snprintf(result, 64, "%.5f", (double) (-CTimeZone) / (double) SECS_PER_HOUR);
	}
	else result = strdup(value);

	return result;
}


const char * show_timezone(void)
{
	const char *tzn;

	if (HasCTZSet)
	{
		Interval	interval;

		interval.month = 0;
		interval.day = 0;

		interval.time = -(CTimeZone * USECS_PER_SEC);

		interval.time = -CTimeZone;


		tzn = DatumGetCString(DirectFunctionCall1(interval_out, IntervalPGetDatum(&interval)));
	}
	else tzn = pg_get_timezone_name(global_timezone);

	if (tzn != NULL)
		return tzn;

	return "unknown";
}




const char * assign_XactIsoLevel(const char *value, bool doit, GucSource source)
{
	if (SerializableSnapshot != NULL)
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION), errmsg("SET TRANSACTION ISOLATION LEVEL must be called before any query")));

		
		else if (source != PGC_S_OVERRIDE)
			return NULL;
	}
	if (IsSubTransaction())
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION), errmsg("SET TRANSACTION ISOLATION LEVEL must not be called in a subtransaction")));

		
		else if (source != PGC_S_OVERRIDE)
			return NULL;
	}

	if (strcmp(value, "serializable") == 0)
	{
		if (doit)
			XactIsoLevel = XACT_SERIALIZABLE;
	}
	else if (strcmp(value, "repeatable read") == 0)
	{
		if (doit)
			XactIsoLevel = XACT_REPEATABLE_READ;
	}
	else if (strcmp(value, "read committed") == 0)
	{
		if (doit)
			XactIsoLevel = XACT_READ_COMMITTED;
	}
	else if (strcmp(value, "read uncommitted") == 0)
	{
		if (doit)
			XactIsoLevel = XACT_READ_UNCOMMITTED;
	}
	else if (strcmp(value, "default") == 0)
	{
		if (doit)
			XactIsoLevel = DefaultXactIsoLevel;
	}
	else return NULL;

	return value;
}

const char * show_XactIsoLevel(void)
{
	switch (XactIsoLevel)
	{
		case XACT_READ_UNCOMMITTED:
			return "read uncommitted";
		case XACT_READ_COMMITTED:
			return "read committed";
		case XACT_REPEATABLE_READ:
			return "repeatable read";
		case XACT_SERIALIZABLE:
			return "serializable";
		default:
			return "bogus";
	}
}




bool assign_random_seed(double value, bool doit, GucSource source)
{
	
	if (doit && source >= PGC_S_INTERACTIVE)
		DirectFunctionCall1(setseed, Float8GetDatum(value));
	return true;
}

const char * show_random_seed(void)
{
	return "unavailable";
}




const char * assign_client_encoding(const char *value, bool doit, GucSource source)
{
	int			encoding;

	encoding = pg_valid_client_encoding(value);
	if (encoding < 0)
		return NULL;

	
	if (SetClientEncoding(encoding, doit) < 0)
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("conversion between %s and %s is not supported", value, GetDatabaseEncodingName())));


		return NULL;
	}
	return value;
}



extern char *session_authorization_string;		

const char * assign_session_authorization(const char *value, bool doit, GucSource source)
{
	Oid			roleid = InvalidOid;
	bool		is_superuser = false;
	const char *actual_rolename = NULL;
	char	   *result;

	if (strspn(value, "x") == NAMEDATALEN && (value[NAMEDATALEN] == 'T' || value[NAMEDATALEN] == 'F'))
	{
		
		Oid			savedoid;
		char	   *endptr;

		savedoid = (Oid) strtoul(value + NAMEDATALEN + 1, &endptr, 10);

		if (endptr != value + NAMEDATALEN + 1 && *endptr == ',')
		{
			
			roleid = savedoid;
			is_superuser = (value[NAMEDATALEN] == 'T');
			actual_rolename = endptr + 1;
		}
	}

	if (roleid == InvalidOid)
	{
		
		HeapTuple	roleTup;

		if (!IsTransactionState())
		{
			
			return NULL;
		}

		roleTup = SearchSysCache(AUTHNAME, PointerGetDatum(value), 0, 0, 0);

		if (!HeapTupleIsValid(roleTup))
		{
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("role \"%s\" does not exist", value)));

			return NULL;
		}

		roleid = HeapTupleGetOid(roleTup);
		is_superuser = ((Form_pg_authid) GETSTRUCT(roleTup))->rolsuper;
		actual_rolename = value;

		ReleaseSysCache(roleTup);
	}

	if (doit)
		SetSessionAuthorization(roleid, is_superuser);

	result = (char *) malloc(NAMEDATALEN + 32 + strlen(actual_rolename));
	if (!result)
		return NULL;

	memset(result, 'x', NAMEDATALEN);

	sprintf(result + NAMEDATALEN, "%c%u,%s", is_superuser ? 'T' : 'F', roleid, actual_rolename);



	return result;
}

const char * show_session_authorization(void)
{
	
	const char *value = session_authorization_string;
	Oid			savedoid;
	char	   *endptr;

	Assert(strspn(value, "x") == NAMEDATALEN && (value[NAMEDATALEN] == 'T' || value[NAMEDATALEN] == 'F'));

	savedoid = (Oid) strtoul(value + NAMEDATALEN + 1, &endptr, 10);

	Assert(endptr != value + NAMEDATALEN + 1 && *endptr == ',');

	return endptr + 1;
}



extern char *role_string;		

const char * assign_role(const char *value, bool doit, GucSource source)
{
	Oid			roleid = InvalidOid;
	bool		is_superuser = false;
	const char *actual_rolename = value;
	char	   *result;

	if (strspn(value, "x") == NAMEDATALEN && (value[NAMEDATALEN] == 'T' || value[NAMEDATALEN] == 'F'))
	{
		
		Oid			savedoid;
		char	   *endptr;

		savedoid = (Oid) strtoul(value + NAMEDATALEN + 1, &endptr, 10);

		if (endptr != value + NAMEDATALEN + 1 && *endptr == ',')
		{
			
			roleid = savedoid;
			is_superuser = (value[NAMEDATALEN] == 'T');
			actual_rolename = endptr + 1;
		}
	}

	if (roleid == InvalidOid && strcmp(actual_rolename, "none") != 0)
	{
		
		HeapTuple	roleTup;

		if (!IsTransactionState())
		{
			
			return NULL;
		}

		roleTup = SearchSysCache(AUTHNAME, PointerGetDatum(value), 0, 0, 0);

		if (!HeapTupleIsValid(roleTup))
		{
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("role \"%s\" does not exist", value)));

			return NULL;
		}

		roleid = HeapTupleGetOid(roleTup);
		is_superuser = ((Form_pg_authid) GETSTRUCT(roleTup))->rolsuper;

		ReleaseSysCache(roleTup);

		
		if (!is_member_of_role(GetSessionUserId(), roleid))
		{
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to set role \"%s\"", value)));


			return NULL;
		}
	}

	if (doit)
		SetCurrentRoleId(roleid, is_superuser);

	result = (char *) malloc(NAMEDATALEN + 32 + strlen(actual_rolename));
	if (!result)
		return NULL;

	memset(result, 'x', NAMEDATALEN);

	sprintf(result + NAMEDATALEN, "%c%u,%s", is_superuser ? 'T' : 'F', roleid, actual_rolename);



	return result;
}

const char * show_role(void)
{
	
	const char *value = role_string;
	Oid			savedoid;
	char	   *endptr;

	
	if (value == NULL || strcmp(value, "none") == 0)
		return "none";

	Assert(strspn(value, "x") == NAMEDATALEN && (value[NAMEDATALEN] == 'T' || value[NAMEDATALEN] == 'F'));

	savedoid = (Oid) strtoul(value + NAMEDATALEN + 1, &endptr, 10);

	Assert(endptr != value + NAMEDATALEN + 1 && *endptr == ',');

	
	if (savedoid != GetCurrentRoleId())
		return "none";

	return endptr + 1;
}
