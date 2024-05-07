




































ProcessingMode Mode = InitProcessing;


static List *lock_files = NIL;




bool		IgnoreSystemIndexes = false;




void SetDatabasePath(const char *path)
{
	
	Assert(!DatabasePath);
	DatabasePath = MemoryContextStrdup(TopMemoryContext, path);
}


void SetDataDir(const char *dir)
{
	char	   *new;

	AssertArg(dir);

	
	new = make_absolute_path(dir);

	if (DataDir)
		free(DataDir);
	DataDir = new;
}


void ChangeToDataDir(void)
{
	AssertState(DataDir);

	if (chdir(DataDir) < 0)
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not change directory to \"%s\": %m", DataDir)));


}


char * make_absolute_path(const char *path)
{
	char	   *new;

	
	if (path == NULL)
		return NULL;

	if (!is_absolute_path(path))
	{
		char	   *buf;
		size_t		buflen;

		buflen = MAXPGPATH;
		for (;;)
		{
			buf = malloc(buflen);
			if (!buf)
				ereport(FATAL, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));


			if (getcwd(buf, buflen))
				break;
			else if (errno == ERANGE)
			{
				free(buf);
				buflen *= 2;
				continue;
			}
			else {
				free(buf);
				elog(FATAL, "could not get current working directory: %m");
			}
		}

		new = malloc(strlen(buf) + strlen(path) + 2);
		if (!new)
			ereport(FATAL, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));

		sprintf(new, "%s/%s", buf, path);
		free(buf);
	}
	else {
		new = strdup(path);
		if (!new)
			ereport(FATAL, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));

	}

	
	canonicalize_path(new);

	return new;
}



static Oid	AuthenticatedUserId = InvalidOid;
static Oid	SessionUserId = InvalidOid;
static Oid	OuterUserId = InvalidOid;
static Oid	CurrentUserId = InvalidOid;


static bool AuthenticatedUserIsSuperuser = false;
static bool SessionUserIsSuperuser = false;

static int	SecurityRestrictionContext = 0;


static bool SetRoleIsActive = false;



Oid GetUserId(void)
{
	AssertState(OidIsValid(CurrentUserId));
	return CurrentUserId;
}



Oid GetOuterUserId(void)
{
	AssertState(OidIsValid(OuterUserId));
	return OuterUserId;
}


static void SetOuterUserId(Oid userid)
{
	AssertState(SecurityRestrictionContext == 0);
	AssertArg(OidIsValid(userid));
	OuterUserId = userid;

	
	CurrentUserId = userid;
}



Oid GetSessionUserId(void)
{
	AssertState(OidIsValid(SessionUserId));
	return SessionUserId;
}


static void SetSessionUserId(Oid userid, bool is_superuser)
{
	AssertState(SecurityRestrictionContext == 0);
	AssertArg(OidIsValid(userid));
	SessionUserId = userid;
	SessionUserIsSuperuser = is_superuser;
	SetRoleIsActive = false;

	
	OuterUserId = userid;
	CurrentUserId = userid;
}



void GetUserIdAndSecContext(Oid *userid, int *sec_context)
{
	*userid = CurrentUserId;
	*sec_context = SecurityRestrictionContext;
}

void SetUserIdAndSecContext(Oid userid, int sec_context)
{
	CurrentUserId = userid;
	SecurityRestrictionContext = sec_context;
}



bool InLocalUserIdChange(void)
{
	return (SecurityRestrictionContext & SECURITY_LOCAL_USERID_CHANGE) != 0;
}


bool InSecurityRestrictedOperation(void)
{
	return (SecurityRestrictionContext & SECURITY_RESTRICTED_OPERATION) != 0;
}



void GetUserIdAndContext(Oid *userid, bool *sec_def_context)
{
	*userid = CurrentUserId;
	*sec_def_context = InLocalUserIdChange();
}

void SetUserIdAndContext(Oid userid, bool sec_def_context)
{
	
	if (InSecurityRestrictedOperation())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("cannot set parameter \"%s\" within security-restricted operation", "role")));


	CurrentUserId = userid;
	if (sec_def_context)
		SecurityRestrictionContext |= SECURITY_LOCAL_USERID_CHANGE;
	else SecurityRestrictionContext &= ~SECURITY_LOCAL_USERID_CHANGE;
}



bool is_authenticated_user_replication_role(void)
{
	bool		result = false;
	HeapTuple	utup;

	utup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(AuthenticatedUserId));
	if (HeapTupleIsValid(utup))
	{
		result = ((Form_pg_authid) GETSTRUCT(utup))->rolreplication;
		ReleaseSysCache(utup);
	}
	return result;
}


void InitializeSessionUserId(const char *rolename)
{
	HeapTuple	roleTup;
	Form_pg_authid rform;
	Oid			roleid;

	
	AssertState(!IsBootstrapProcessingMode());

	
	AssertState(!OidIsValid(AuthenticatedUserId));

	roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum(rolename));
	if (!HeapTupleIsValid(roleTup))
		ereport(FATAL, (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("role \"%s\" does not exist", rolename)));


	rform = (Form_pg_authid) GETSTRUCT(roleTup);
	roleid = HeapTupleGetOid(roleTup);

	AuthenticatedUserId = roleid;
	AuthenticatedUserIsSuperuser = rform->rolsuper;

	
	SetSessionUserId(roleid, AuthenticatedUserIsSuperuser);

	
	
	MyProc->roleId = roleid;

	
	if (IsUnderPostmaster)
	{
		
		if (!rform->rolcanlogin)
			ereport(FATAL, (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("role \"%s\" is not permitted to log in", rolename)));



		
		if (rform->rolconnlimit >= 0 && !AuthenticatedUserIsSuperuser && CountUserBackends(roleid) > rform->rolconnlimit)

			ereport(FATAL, (errcode(ERRCODE_TOO_MANY_CONNECTIONS), errmsg("too many connections for role \"%s\"", rolename)));


	}

	
	SetConfigOption("session_authorization", rolename, PGC_BACKEND, PGC_S_OVERRIDE);
	SetConfigOption("is_superuser", AuthenticatedUserIsSuperuser ? "on" : "off", PGC_INTERNAL, PGC_S_OVERRIDE);


	ReleaseSysCache(roleTup);
}



void InitializeSessionUserIdStandalone(void)
{
	
	AssertState(!IsUnderPostmaster || IsAutoVacuumWorkerProcess() || IsBackgroundWorker);

	
	AssertState(!OidIsValid(AuthenticatedUserId));

	AuthenticatedUserId = BOOTSTRAP_SUPERUSERID;
	AuthenticatedUserIsSuperuser = true;

	SetSessionUserId(BOOTSTRAP_SUPERUSERID, true);
}



void SetSessionAuthorization(Oid userid, bool is_superuser)
{
	
	AssertState(OidIsValid(AuthenticatedUserId));

	if (userid != AuthenticatedUserId && !AuthenticatedUserIsSuperuser)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to set session authorization")));


	SetSessionUserId(userid, is_superuser);

	SetConfigOption("is_superuser", is_superuser ? "on" : "off", PGC_INTERNAL, PGC_S_OVERRIDE);

}


Oid GetCurrentRoleId(void)
{
	if (SetRoleIsActive)
		return OuterUserId;
	else return InvalidOid;
}


void SetCurrentRoleId(Oid roleid, bool is_superuser)
{
	
	if (!OidIsValid(roleid))
	{
		if (!OidIsValid(SessionUserId))
			return;

		roleid = SessionUserId;
		is_superuser = SessionUserIsSuperuser;

		SetRoleIsActive = false;
	}
	else SetRoleIsActive = true;

	SetOuterUserId(roleid);

	SetConfigOption("is_superuser", is_superuser ? "on" : "off", PGC_INTERNAL, PGC_S_OVERRIDE);

}



char * GetUserNameFromId(Oid roleid)
{
	HeapTuple	tuple;
	char	   *result;

	tuple = SearchSysCache1(AUTHOID, ObjectIdGetDatum(roleid));
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("invalid role OID: %u", roleid)));


	result = pstrdup(NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname));

	ReleaseSysCache(tuple);
	return result;
}





static void UnlinkLockFiles(int status, Datum arg)
{
	ListCell   *l;

	foreach(l, lock_files)
	{
		char	   *curfile = (char *) lfirst(l);

		unlink(curfile);
		
	}
	
	lock_files = NIL;
}


static void CreateLockFile(const char *filename, bool amPostmaster, const char *socketDir, bool isDDLock, const char *refName)


{
	int			fd;
	char		buffer[MAXPGPATH * 2 + 256];
	int			ntries;
	int			len;
	int			encoded_pid;
	pid_t		other_pid;
	pid_t		my_pid, my_p_pid, my_gp_pid;

	const char *envvar;

	
	my_pid = getpid();


	my_p_pid = getppid();


	
	my_p_pid = 0;


	envvar = getenv("PG_GRANDPARENT_PID");
	if (envvar)
		my_gp_pid = atoi(envvar);
	else my_gp_pid = 0;

	
	for (ntries = 0;; ntries++)
	{
		
		fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd >= 0)
			break;				

		
		if ((errno != EEXIST && errno != EACCES) || ntries > 100)
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not create lock file \"%s\": %m", filename)));



		
		fd = open(filename, O_RDONLY, 0600);
		if (fd < 0)
		{
			if (errno == ENOENT)
				continue;		
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not open lock file \"%s\": %m", filename)));


		}
		if ((len = read(fd, buffer, sizeof(buffer) - 1)) < 0)
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not read lock file \"%s\": %m", filename)));


		close(fd);

		if (len == 0)
		{
			ereport(FATAL, (errcode(ERRCODE_LOCK_FILE_EXISTS), errmsg("lock file \"%s\" is empty", filename), errhint("Either another server is starting, or the lock file is the remnant of a previous server startup crash.")));


		}

		buffer[len] = '\0';
		encoded_pid = atoi(buffer);

		
		other_pid = (pid_t) (encoded_pid < 0 ? -encoded_pid : encoded_pid);

		if (other_pid <= 0)
			elog(FATAL, "bogus data in lock file \"%s\": \"%s\"", filename, buffer);

		
		if (other_pid != my_pid && other_pid != my_p_pid && other_pid != my_gp_pid)
		{
			if (kill(other_pid, 0) == 0 || (errno != ESRCH && errno != EPERM))
			{
				
				ereport(FATAL, (errcode(ERRCODE_LOCK_FILE_EXISTS), errmsg("lock file \"%s\" already exists", filename), isDDLock ? (encoded_pid < 0 ? errhint("Is another postgres (PID %d) running in data directory \"%s\"?", (int) other_pid, refName) :






						  errhint("Is another postmaster (PID %d) running in data directory \"%s\"?", (int) other_pid, refName)) :
						 (encoded_pid < 0 ? errhint("Is another postgres (PID %d) using socket file \"%s\"?", (int) other_pid, refName) :

						  errhint("Is another postmaster (PID %d) using socket file \"%s\"?", (int) other_pid, refName))));
			}
		}

		
		if (isDDLock)
		{
			char	   *ptr = buffer;
			unsigned long id1, id2;
			int			lineno;

			for (lineno = 1; lineno < LOCK_FILE_LINE_SHMEM_KEY; lineno++)
			{
				if ((ptr = strchr(ptr, '\n')) == NULL)
					break;
				ptr++;
			}

			if (ptr != NULL && sscanf(ptr, "%lu %lu", &id1, &id2) == 2)
			{
				if (PGSharedMemoryIsInUse(id1, id2))
					ereport(FATAL, (errcode(ERRCODE_LOCK_FILE_EXISTS), errmsg("pre-existing shared memory block " "(key %lu, ID %lu) is still in use", id1, id2), errhint("If you're sure there are no old " "server processes still running, remove " "the shared memory block " "or just delete the file \"%s\".", filename)));








			}
		}

		
		if (unlink(filename) < 0)
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not remove old lock file \"%s\": %m", filename), errhint("The file seems accidentally left over, but " "it could not be removed. Please remove the file " "by hand and try again.")));





	}

	
	snprintf(buffer, sizeof(buffer), "%d\n%s\n%ld\n%d\n%s\n", amPostmaster ? (int) my_pid : -((int) my_pid), DataDir, (long) MyStartTime, PostPortNumber, socketDir);





	
	if (isDDLock && !amPostmaster)
		strlcat(buffer, "\n", sizeof(buffer));

	errno = 0;
	if (write(fd, buffer, strlen(buffer)) != strlen(buffer))
	{
		int			save_errno = errno;

		close(fd);
		unlink(filename);
		
		errno = save_errno ? save_errno : ENOSPC;
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not write lock file \"%s\": %m", filename)));

	}
	if (pg_fsync(fd) != 0)
	{
		int			save_errno = errno;

		close(fd);
		unlink(filename);
		errno = save_errno;
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not write lock file \"%s\": %m", filename)));

	}
	if (close(fd) != 0)
	{
		int			save_errno = errno;

		unlink(filename);
		errno = save_errno;
		ereport(FATAL, (errcode_for_file_access(), errmsg("could not write lock file \"%s\": %m", filename)));

	}

	
	if (lock_files == NIL)
		on_proc_exit(UnlinkLockFiles, 0);

	lock_files = lappend(lock_files, pstrdup(filename));
}


void CreateDataDirLockFile(bool amPostmaster)
{
	CreateLockFile(DIRECTORY_LOCK_FILE, amPostmaster, "", true, DataDir);
}


void CreateSocketLockFile(const char *socketfile, bool amPostmaster, const char *socketDir)

{
	char		lockfile[MAXPGPATH];

	snprintf(lockfile, sizeof(lockfile), "%s.lock", socketfile);
	CreateLockFile(lockfile, amPostmaster, socketDir, false, socketfile);
}


void TouchSocketLockFiles(void)
{
	ListCell   *l;

	foreach(l, lock_files)
	{
		char	   *socketLockFile = (char *) lfirst(l);

		
		if (strcmp(socketLockFile, DIRECTORY_LOCK_FILE) == 0)
			continue;

		

		utime(socketLockFile, NULL);


		utimes(socketLockFile, NULL);

		int			fd;
		char		buffer[1];

		fd = open(socketLockFile, O_RDONLY | PG_BINARY, 0);
		if (fd >= 0)
		{
			read(fd, buffer, sizeof(buffer));
			close(fd);
		}


	}
}



void AddToDataDirLockFile(int target_line, const char *str)
{
	int			fd;
	int			len;
	int			lineno;
	char	   *srcptr;
	char	   *destptr;
	char		srcbuffer[BLCKSZ];
	char		destbuffer[BLCKSZ];

	fd = open(DIRECTORY_LOCK_FILE, O_RDWR | PG_BINARY, 0);
	if (fd < 0)
	{
		ereport(LOG, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", DIRECTORY_LOCK_FILE)));


		return;
	}
	len = read(fd, srcbuffer, sizeof(srcbuffer) - 1);
	if (len < 0)
	{
		ereport(LOG, (errcode_for_file_access(), errmsg("could not read from file \"%s\": %m", DIRECTORY_LOCK_FILE)));


		close(fd);
		return;
	}
	srcbuffer[len] = '\0';

	
	srcptr = srcbuffer;
	for (lineno = 1; lineno < target_line; lineno++)
	{
		if ((srcptr = strchr(srcptr, '\n')) == NULL)
		{
			elog(LOG, "incomplete data in \"%s\": found only %d newlines while trying to add line %d", DIRECTORY_LOCK_FILE, lineno - 1, target_line);
			close(fd);
			return;
		}
		srcptr++;
	}
	memcpy(destbuffer, srcbuffer, srcptr - srcbuffer);
	destptr = destbuffer + (srcptr - srcbuffer);

	
	snprintf(destptr, destbuffer + sizeof(destbuffer) - destptr, "%s\n", str);
	destptr += strlen(destptr);

	
	if ((srcptr = strchr(srcptr, '\n')) != NULL)
	{
		srcptr++;
		snprintf(destptr, destbuffer + sizeof(destbuffer) - destptr, "%s", srcptr);
	}

	
	len = strlen(destbuffer);
	errno = 0;
	if (lseek(fd, (off_t) 0, SEEK_SET) != 0 || (int) write(fd, destbuffer, len) != len)
	{
		
		if (errno == 0)
			errno = ENOSPC;
		ereport(LOG, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", DIRECTORY_LOCK_FILE)));


		close(fd);
		return;
	}
	if (pg_fsync(fd) != 0)
	{
		ereport(LOG, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", DIRECTORY_LOCK_FILE)));


	}
	if (close(fd) != 0)
	{
		ereport(LOG, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", DIRECTORY_LOCK_FILE)));


	}
}





void ValidatePgVersion(const char *path)
{
	char		full_path[MAXPGPATH];
	FILE	   *file;
	int			ret;
	long		file_major, file_minor;
	long		my_major = 0, my_minor = 0;
	char	   *endptr;
	const char *version_string = PG_VERSION;

	my_major = strtol(version_string, &endptr, 10);
	if (*endptr == '.')
		my_minor = strtol(endptr + 1, NULL, 10);

	snprintf(full_path, sizeof(full_path), "%s/PG_VERSION", path);

	file = AllocateFile(full_path, "r");
	if (!file)
	{
		if (errno == ENOENT)
			ereport(FATAL, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("\"%s\" is not a valid data directory", path), errdetail("File \"%s\" is missing.", full_path)));



		else ereport(FATAL, (errcode_for_file_access(), errmsg("could not open file \"%s\": %m", full_path)));


	}

	ret = fscanf(file, "%ld.%ld", &file_major, &file_minor);
	if (ret != 2)
		ereport(FATAL, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("\"%s\" is not a valid data directory", path), errdetail("File \"%s\" does not contain valid data.", full_path), errhint("You might need to initdb.")));






	FreeFile(file);

	if (my_major != file_major || my_minor != file_minor)
		ereport(FATAL, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("database files are incompatible with server"), errdetail("The data directory was initialized by PostgreSQL version %ld.%ld, " "which is not compatible with this version %s.", file_major, file_minor, version_string)));




}




char	   *shared_preload_libraries_string = NULL;
char	   *local_preload_libraries_string = NULL;


bool		process_shared_preload_libraries_in_progress = false;


static void load_libraries(const char *libraries, const char *gucname, bool restricted)
{
	char	   *rawstring;
	List	   *elemlist;
	int			elevel;
	ListCell   *l;

	if (libraries == NULL || libraries[0] == '\0')
		return;					

	
	rawstring = pstrdup(libraries);

	
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		
		pfree(rawstring);
		list_free(elemlist);
		ereport(LOG, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("invalid list syntax in parameter \"%s\"", gucname)));


		return;
	}

	

	if (IsUnderPostmaster && process_shared_preload_libraries_in_progress)
		elevel = DEBUG2;
	else  elevel = LOG;


	foreach(l, elemlist)
	{
		char	   *tok = (char *) lfirst(l);
		char	   *filename;

		filename = pstrdup(tok);
		canonicalize_path(filename);
		
		if (restricted && first_dir_separator(filename) == NULL)
		{
			char	   *expanded;

			expanded = palloc(strlen("$libdir/plugins/") + strlen(filename) + 1);
			strcpy(expanded, "$libdir/plugins/");
			strcat(expanded, filename);
			pfree(filename);
			filename = expanded;
		}
		load_file(filename, restricted);
		ereport(elevel, (errmsg("loaded library \"%s\"", filename)));
		pfree(filename);
	}

	pfree(rawstring);
	list_free(elemlist);
}


void process_shared_preload_libraries(void)
{
	process_shared_preload_libraries_in_progress = true;
	load_libraries(shared_preload_libraries_string, "shared_preload_libraries", false);

	process_shared_preload_libraries_in_progress = false;
}


void process_local_preload_libraries(void)
{
	load_libraries(local_preload_libraries_string, "local_preload_libraries", true);

}

void pg_bindtextdomain(const char *domain)
{

	if (my_exec_path[0] != '\0')
	{
		char		locale_path[MAXPGPATH];

		get_locale_path(my_exec_path, locale_path);
		bindtextdomain(domain, locale_path);
		pg_bind_textdomain_codeset(domain);
	}

}
