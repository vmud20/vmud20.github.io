











































































extern bool Log_disconnections;
extern bool check_function_bodies;
extern int	CommitDelay;
extern int	CommitSiblings;
extern char *default_tablespace;
extern bool fullPageWrites;


extern bool trace_sort;


static const char *assign_log_destination(const char *value, bool doit, GucSource source);


static int	syslog_facility = LOG_LOCAL0;

static const char *assign_syslog_facility(const char *facility, bool doit, GucSource source);
static const char *assign_syslog_ident(const char *ident, bool doit, GucSource source);


static const char *assign_defaultxactisolevel(const char *newval, bool doit, GucSource source);
static const char *assign_log_min_messages(const char *newval, bool doit, GucSource source);
static const char *assign_client_min_messages(const char *newval, bool doit, GucSource source);
static const char *assign_min_error_statement(const char *newval, bool doit, GucSource source);
static const char *assign_msglvl(int *var, const char *newval, bool doit, GucSource source);
static const char *assign_log_error_verbosity(const char *newval, bool doit, GucSource source);
static const char *assign_log_statement(const char *newval, bool doit, GucSource source);
static const char *show_num_temp_buffers(void);
static bool assign_phony_autocommit(bool newval, bool doit, GucSource source);
static const char *assign_custom_variable_classes(const char *newval, bool doit, GucSource source);
static bool assign_debug_assertions(bool newval, bool doit, GucSource source);
static bool assign_ssl(bool newval, bool doit, GucSource source);
static bool assign_stage_log_stats(bool newval, bool doit, GucSource source);
static bool assign_log_stats(bool newval, bool doit, GucSource source);
static bool assign_transaction_read_only(bool newval, bool doit, GucSource source);
static const char *assign_canonical_path(const char *newval, bool doit, GucSource source);

static bool assign_tcp_keepalives_idle(int newval, bool doit, GucSource source);
static bool assign_tcp_keepalives_interval(int newval, bool doit, GucSource source);
static bool assign_tcp_keepalives_count(int newval, bool doit, GucSource source);
static const char *show_tcp_keepalives_idle(void);
static const char *show_tcp_keepalives_interval(void);
static const char *show_tcp_keepalives_count(void);



bool		assert_enabled = true;

bool		assert_enabled = false;

bool		log_duration = false;
bool		Debug_print_plan = false;
bool		Debug_print_parse = false;
bool		Debug_print_rewritten = false;
bool		Debug_pretty_print = false;
bool		Explain_pretty_print = true;

bool		log_parser_stats = false;
bool		log_planner_stats = false;
bool		log_executor_stats = false;
bool		log_statement_stats = false;		
bool		log_btree_build_stats = false;

bool		SQL_inheritance = true;

bool		Australian_timezones = false;

bool		Password_encryption = true;

bool		default_with_oids = false;

int			log_min_error_statement = PANIC;
int			log_min_messages = NOTICE;
int			client_min_messages = NOTICE;
int			log_min_duration_statement = -1;

int			num_temp_buffers = 1000;

char	   *ConfigFileName;
char	   *HbaFileName;
char	   *IdentFileName;
char	   *external_pid_file;

int			tcp_keepalives_idle;
int			tcp_keepalives_interval;
int			tcp_keepalives_count;


static char *client_min_messages_str;
static char *log_min_messages_str;
static char *log_error_verbosity_str;
static char *log_statement_str;
static char *log_min_error_statement_str;
static char *log_destination_string;
static char *syslog_facility_str;
static char *syslog_ident_str;
static bool phony_autocommit;
static bool session_auth_is_superuser;
static double phony_random_seed;
static char *client_encoding_string;
static char *datestyle_string;
static char *default_iso_level_string;
static char *locale_collate;
static char *locale_ctype;
static char *regex_flavor_string;
static char *server_encoding_string;
static char *server_version_string;
static char *timezone_string;
static char *XactIsoLevel_string;
static char *data_directory;
static char *custom_variable_classes;
static int	max_function_args;
static int	max_index_keys;
static int	max_identifier_length;
static int	block_size;
static bool integer_datetimes;
static bool standard_conforming_strings;


char	   *role_string;
char	   *session_authorization_string;



const char *const GucContext_Names[] = {
	  "internal", "postmaster", "sighup", "backend", "superuser", "user" };







const char *const GucSource_Names[] = {
	  "default", "environment variable", "configuration file", "command line", "database", "user", "client", "override", "interactive", "test", "session" };












const char *const config_group_names[] = {
	
	gettext_noop("Ungrouped"),  gettext_noop("File Locations"),  gettext_noop("Connections and Authentication"),  gettext_noop("Connections and Authentication / Connection Settings"),  gettext_noop("Connections and Authentication / Security and Authentication"),  gettext_noop("Resource Usage"),  gettext_noop("Resource Usage / Memory"),  gettext_noop("Resource Usage / Free Space Map"),  gettext_noop("Resource Usage / Kernel Resources"),  gettext_noop("Write-Ahead Log"),  gettext_noop("Write-Ahead Log / Settings"),  gettext_noop("Write-Ahead Log / Checkpoints"),  gettext_noop("Query Tuning"),  gettext_noop("Query Tuning / Planner Method Configuration"),  gettext_noop("Query Tuning / Planner Cost Constants"),  gettext_noop("Query Tuning / Genetic Query Optimizer"),  gettext_noop("Query Tuning / Other Planner Options"),  gettext_noop("Reporting and Logging"),  gettext_noop("Reporting and Logging / Where to Log"),  gettext_noop("Reporting and Logging / When to Log"),  gettext_noop("Reporting and Logging / What to Log"),  gettext_noop("Statistics"),  gettext_noop("Statistics / Monitoring"),  gettext_noop("Statistics / Query and Index Statistics Collector"),  gettext_noop("Autovacuum"),  gettext_noop("Client Connection Defaults"),  gettext_noop("Client Connection Defaults / Statement Behavior"),  gettext_noop("Client Connection Defaults / Locale and Formatting"),  gettext_noop("Client Connection Defaults / Other Defaults"),  gettext_noop("Lock Management"),  gettext_noop("Version and Platform Compatibility"),  gettext_noop("Version and Platform Compatibility / Previous PostgreSQL Versions"),  gettext_noop("Version and Platform Compatibility / Other Platforms and Clients"),  gettext_noop("Preset Options"),  gettext_noop("Customized Options"),  gettext_noop("Developer Options"),  NULL };










































































const char *const config_type_names[] = {
	  "bool", "integer", "real", "string" };










static struct config_bool ConfigureNamesBool[] = {
	{
		{"enable_seqscan", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of sequential-scan plans."), NULL }, &enable_seqscan, true, NULL, NULL }, {






		{"enable_indexscan", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of index-scan plans."), NULL }, &enable_indexscan, true, NULL, NULL }, {






		{"enable_bitmapscan", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of bitmap-scan plans."), NULL }, &enable_bitmapscan, true, NULL, NULL }, {






		{"enable_tidscan", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of TID scan plans."), NULL }, &enable_tidscan, true, NULL, NULL }, {






		{"enable_sort", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of explicit sort steps."), NULL }, &enable_sort, true, NULL, NULL }, {






		{"enable_hashagg", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of hashed aggregation plans."), NULL }, &enable_hashagg, true, NULL, NULL }, {






		{"enable_nestloop", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of nested-loop join plans."), NULL }, &enable_nestloop, true, NULL, NULL }, {






		{"enable_mergejoin", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of merge join plans."), NULL }, &enable_mergejoin, true, NULL, NULL }, {






		{"enable_hashjoin", PGC_USERSET, QUERY_TUNING_METHOD, gettext_noop("Enables the planner's use of hash join plans."), NULL }, &enable_hashjoin, true, NULL, NULL }, {






		{"constraint_exclusion", PGC_USERSET, QUERY_TUNING_OTHER, gettext_noop("Enables the planner to use constraints to optimize queries."), gettext_noop("Child table scans will be skipped if their " "constraints guarantee that no rows match the query.")


		}, &constraint_exclusion, false, NULL, NULL }, {



		{"geqo", PGC_USERSET, QUERY_TUNING_GEQO, gettext_noop("Enables genetic query optimization."), gettext_noop("This algorithm attempts to do planning without " "exhaustive searching.")


		}, &enable_geqo, true, NULL, NULL }, {



		
		{"is_superuser", PGC_INTERNAL, UNGROUPED, gettext_noop("Shows whether the current user is a superuser."), NULL, GUC_REPORT | GUC_NO_SHOW_ALL | GUC_NO_RESET_ALL | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &session_auth_is_superuser, false, NULL, NULL }, {







		{"ssl", PGC_POSTMASTER, CONN_AUTH_SECURITY, gettext_noop("Enables SSL connections."), NULL }, &EnableSSL, false, assign_ssl, NULL }, {






		{"fsync", PGC_SIGHUP, WAL_SETTINGS, gettext_noop("Forces synchronization of updates to disk."), gettext_noop("The server will use the fsync() system call in several places to make " "sure that updates are physically written to disk. This insures " "that a database cluster will recover to a consistent state after " "an operating system or hardware crash.")




		}, &enableFsync, true, NULL, NULL }, {



		{"zero_damaged_pages", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("Continues processing past damaged page headers."), gettext_noop("Detection of a damaged page header normally causes PostgreSQL to " "report an error, aborting the current transaction. Setting " "zero_damaged_pages to true causes the system to instead report a " "warning, zero out the damaged page, and continue processing. This " "behavior will destroy data, namely all the rows on the damaged page."), GUC_NOT_IN_SAMPLE }, &zero_damaged_pages, false, NULL, NULL }, {











		{"full_page_writes", PGC_SIGHUP, WAL_SETTINGS, gettext_noop("Writes full pages to WAL when first modified after a checkpoint."), gettext_noop("A page write in process during an operating system crash might be " "only partially written to disk.  During recovery, the row changes " "stored in WAL are not enough to recover.  This option writes " "pages when first modified after a checkpoint to WAL so full recovery " "is possible.")





		}, &fullPageWrites, true, NULL, NULL }, {



		{"silent_mode", PGC_POSTMASTER, LOGGING_WHEN, gettext_noop("Runs the server silently."), gettext_noop("If this parameter is set, the server will automatically run in the " "background and any controlling terminals are dissociated.")


		}, &SilentMode, false, NULL, NULL }, {



		{"log_connections", PGC_BACKEND, LOGGING_WHAT, gettext_noop("Logs each successful connection."), NULL }, &Log_connections, false, NULL, NULL }, {






		{"log_disconnections", PGC_BACKEND, LOGGING_WHAT, gettext_noop("Logs end of a session, including duration."), NULL }, &Log_disconnections, false, NULL, NULL }, {






		{"debug_assertions", PGC_USERSET, DEVELOPER_OPTIONS, gettext_noop("Turns on various assertion checks."), gettext_noop("This is a debugging aid."), GUC_NOT_IN_SAMPLE }, &assert_enabled,  true,  false,  assign_debug_assertions, NULL }, {












		
		{"exit_on_error", PGC_USERSET, UNGROUPED, gettext_noop("no description available"), NULL, GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE }, &ExitOnAnyError, false, NULL, NULL }, {







		{"log_duration", PGC_SUSET, LOGGING_WHAT, gettext_noop("Logs the duration of each completed SQL statement."), NULL }, &log_duration, false, NULL, NULL }, {






		{"debug_print_parse", PGC_USERSET, LOGGING_WHAT, gettext_noop("Prints the parse tree to the server log."), NULL }, &Debug_print_parse, false, NULL, NULL }, {






		{"debug_print_rewritten", PGC_USERSET, LOGGING_WHAT, gettext_noop("Prints the parse tree after rewriting to server log."), NULL }, &Debug_print_rewritten, false, NULL, NULL }, {






		{"debug_print_plan", PGC_USERSET, LOGGING_WHAT, gettext_noop("Prints the execution plan to server log."), NULL }, &Debug_print_plan, false, NULL, NULL }, {






		{"debug_pretty_print", PGC_USERSET, LOGGING_WHAT, gettext_noop("Indents parse and plan tree displays."), NULL }, &Debug_pretty_print, false, NULL, NULL }, {






		{"log_parser_stats", PGC_SUSET, STATS_MONITORING, gettext_noop("Writes parser performance statistics to the server log."), NULL }, &log_parser_stats, false, assign_stage_log_stats, NULL }, {






		{"log_planner_stats", PGC_SUSET, STATS_MONITORING, gettext_noop("Writes planner performance statistics to the server log."), NULL }, &log_planner_stats, false, assign_stage_log_stats, NULL }, {






		{"log_executor_stats", PGC_SUSET, STATS_MONITORING, gettext_noop("Writes executor performance statistics to the server log."), NULL }, &log_executor_stats, false, assign_stage_log_stats, NULL }, {






		{"log_statement_stats", PGC_SUSET, STATS_MONITORING, gettext_noop("Writes cumulative performance statistics to the server log."), NULL }, &log_statement_stats, false, assign_log_stats, NULL },  {







		{"log_btree_build_stats", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &log_btree_build_stats, false, NULL, NULL },   {









		{"explain_pretty_print", PGC_USERSET, CLIENT_CONN_OTHER, gettext_noop("Uses the indented output format for EXPLAIN VERBOSE."), NULL }, &Explain_pretty_print, true, NULL, NULL }, {






		{"stats_start_collector", PGC_POSTMASTER, STATS_COLLECTOR, gettext_noop("Starts the server statistics-collection subprocess."), NULL }, &pgstat_collect_startcollector, true, NULL, NULL }, {






		{"stats_reset_on_server_start", PGC_POSTMASTER, STATS_COLLECTOR, gettext_noop("Zeroes collected statistics on server restart."), NULL }, &pgstat_collect_resetonpmstart, false, NULL, NULL }, {






		{"stats_command_string", PGC_SUSET, STATS_COLLECTOR, gettext_noop("Collects statistics about executing commands."), gettext_noop("Enables the collection of statistics on the currently " "executing command of each session, along with the time " "at which that command began execution.")



		}, &pgstat_collect_querystring, false, NULL, NULL }, {



		{"stats_row_level", PGC_SUSET, STATS_COLLECTOR, gettext_noop("Collects row-level statistics on database activity."), NULL }, &pgstat_collect_tuplelevel, false, NULL, NULL }, {






		{"stats_block_level", PGC_SUSET, STATS_COLLECTOR, gettext_noop("Collects block-level statistics on database activity."), NULL }, &pgstat_collect_blocklevel, false, NULL, NULL },  {







		{"autovacuum", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Starts the autovacuum subprocess."), NULL }, &autovacuum_start_daemon, false, NULL, NULL },  {







		{"trace_notify", PGC_USERSET, DEVELOPER_OPTIONS, gettext_noop("Generates debugging output for LISTEN and NOTIFY."), NULL, GUC_NOT_IN_SAMPLE }, &Trace_notify, false, NULL, NULL },   {









		{"trace_locks", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &Trace_locks, false, NULL, NULL }, {







		{"trace_userlocks", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &Trace_userlocks, false, NULL, NULL }, {







		{"trace_lwlocks", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &Trace_lwlocks, false, NULL, NULL }, {







		{"debug_deadlocks", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &Debug_deadlocks, false, NULL, NULL },   {









		{"log_hostname", PGC_SIGHUP, LOGGING_WHAT, gettext_noop("Logs the host name in the connection logs."), gettext_noop("By default, connection logs only show the IP address " "of the connecting host. If you want them to show the host name you " "can turn this on, but depending on your host name resolution " "setup it might impose a non-negligible performance penalty.")




		}, &log_hostname, false, NULL, NULL }, {



		{"sql_inheritance", PGC_USERSET, COMPAT_OPTIONS_PREVIOUS, gettext_noop("Causes subtables to be included by default in various commands."), NULL }, &SQL_inheritance, true, NULL, NULL }, {






		{"australian_timezones", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Interprets ACST, CST, EST, and SAT as Australian time zones."), gettext_noop("Otherwise they are interpreted as North/South American " "time zones and Saturday.")


		}, &Australian_timezones, false, ClearDateCache, NULL }, {



		{"password_encryption", PGC_USERSET, CONN_AUTH_SECURITY, gettext_noop("Encrypt passwords."), gettext_noop("When a password is specified in CREATE USER or " "ALTER USER without writing either ENCRYPTED or UNENCRYPTED, " "this parameter determines whether the password is to be encrypted.")



		}, &Password_encryption, true, NULL, NULL }, {



		{"transform_null_equals", PGC_USERSET, COMPAT_OPTIONS_CLIENT, gettext_noop("Treats \"expr=NULL\" as \"expr IS NULL\"."), gettext_noop("When turned on, expressions of the form expr = NULL " "(or NULL = expr) are treated as expr IS NULL, that is, they " "return true if expr evaluates to the null value, and false " "otherwise. The correct behavior of expr = NULL is to always " "return null (unknown).")





		}, &Transform_null_equals, false, NULL, NULL }, {



		{"db_user_namespace", PGC_SIGHUP, CONN_AUTH_SECURITY, gettext_noop("Enables per-database user names."), NULL }, &Db_user_namespace, false, NULL, NULL }, {






		
		{"autocommit", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("This parameter doesn't do anything."), gettext_noop("It's just here so that we won't choke on SET AUTOCOMMIT TO ON from 7.3-vintage clients."), GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE }, &phony_autocommit, true, assign_phony_autocommit, NULL }, {







		{"default_transaction_read_only", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the default read-only status of new transactions."), NULL }, &DefaultXactReadOnly, false, NULL, NULL }, {






		{"transaction_read_only", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the current transaction's read-only status."), NULL, GUC_NO_RESET_ALL | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &XactReadOnly, false, assign_transaction_read_only, NULL }, {







		{"add_missing_from", PGC_USERSET, COMPAT_OPTIONS_PREVIOUS, gettext_noop("Automatically adds missing table references to FROM clauses."), NULL }, &add_missing_from, false, NULL, NULL }, {






		{"check_function_bodies", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Check function bodies during CREATE FUNCTION."), NULL }, &check_function_bodies, true, NULL, NULL }, {






		{"array_nulls", PGC_USERSET, COMPAT_OPTIONS_PREVIOUS, gettext_noop("Enable input of NULL elements in arrays."), gettext_noop("When turned on, unquoted NULL in an array input " "value means a NULL value; " "otherwise it is taken literally.")



		}, &Array_nulls, true, NULL, NULL }, {



		{"default_with_oids", PGC_USERSET, COMPAT_OPTIONS_PREVIOUS, gettext_noop("Create new tables with OIDs by default."), NULL }, &default_with_oids, false, NULL, NULL }, {






		{"redirect_stderr", PGC_POSTMASTER, LOGGING_WHERE, gettext_noop("Start a subprocess to capture stderr output into log files."), NULL }, &Redirect_stderr, false, NULL, NULL }, {






		{"log_truncate_on_rotation", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Truncate existing log files of same name during log rotation."), NULL }, &Log_truncate_on_rotation, false, NULL, NULL },   {








		{"trace_sort", PGC_USERSET, DEVELOPER_OPTIONS, gettext_noop("Emit information about resource usage in sorting."), NULL, GUC_NOT_IN_SAMPLE }, &trace_sort, false, NULL, NULL },    {










		{"wal_debug", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("Emit WAL-related debugging output."), NULL, GUC_NOT_IN_SAMPLE }, &XLOG_DEBUG, false, NULL, NULL },   {









		{"integer_datetimes", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("Datetimes are integer based."), NULL, GUC_REPORT | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &integer_datetimes,  true, NULL, NULL  false, NULL, NULL  },  {












		{"krb_caseins_users", PGC_POSTMASTER, CONN_AUTH_SECURITY, gettext_noop("Sets whether Kerberos user names should be treated as case-insensitive."), NULL }, &pg_krb_caseins_users, false, NULL, NULL },  {







		{"escape_string_warning", PGC_USERSET, COMPAT_OPTIONS_PREVIOUS, gettext_noop("Warn about backslash escapes in ordinary string literals."), NULL }, &escape_string_warning, false, NULL, NULL },  {







		{"standard_conforming_strings", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("'...' strings treat backslashes literally."), NULL, GUC_REPORT | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &standard_conforming_strings, false, NULL, NULL },  {








		{"allow_system_table_mods", PGC_POSTMASTER, DEVELOPER_OPTIONS, gettext_noop("Allows modifications of the structure of system tables."), NULL, GUC_NOT_IN_SAMPLE }, &allowSystemTableMods, false, NULL, NULL },  {








		{"ignore_system_indexes", PGC_BACKEND, DEVELOPER_OPTIONS, gettext_noop("Disabled reading from system indexes."), gettext_noop("It does not prevent updating the indexes, so it is safe " "to use.  The worst consequence is slowness."), GUC_NOT_IN_SAMPLE }, &IgnoreSystemIndexes, false, NULL, NULL },   {










		{NULL, 0, 0, NULL, NULL}, NULL, false, NULL, NULL }
};


static struct config_int ConfigureNamesInt[] = {
	{
		{"post_auth_delay", PGC_BACKEND, DEVELOPER_OPTIONS, gettext_noop("Waits N seconds on connection startup after authentication."), gettext_noop("This allows attaching a debugger to the process."), GUC_NOT_IN_SAMPLE }, &PostAuthDelay, 0, 0, INT_MAX, NULL, NULL }, {







		{"default_statistics_target", PGC_USERSET, QUERY_TUNING_OTHER, gettext_noop("Sets the default statistics target."), gettext_noop("This applies to table columns that have not had a " "column-specific target set via ALTER TABLE SET STATISTICS.")


		}, &default_statistics_target, 10, 1, 1000, NULL, NULL }, {



		{"from_collapse_limit", PGC_USERSET, QUERY_TUNING_OTHER, gettext_noop("Sets the FROM-list size beyond which subqueries are not " "collapsed."), gettext_noop("The planner will merge subqueries into upper " "queries if the resulting FROM list would have no more than " "this many items.")




		}, &from_collapse_limit, 8, 1, INT_MAX, NULL, NULL }, {



		{"join_collapse_limit", PGC_USERSET, QUERY_TUNING_OTHER, gettext_noop("Sets the FROM-list size beyond which JOIN constructs are not " "flattened."), gettext_noop("The planner will flatten explicit JOIN " "constructs into lists of FROM items whenever a list of no more " "than this many items would result.")




		}, &join_collapse_limit, 8, 1, INT_MAX, NULL, NULL }, {



		{"geqo_threshold", PGC_USERSET, QUERY_TUNING_GEQO, gettext_noop("Sets the threshold of FROM items beyond which GEQO is used."), NULL }, &geqo_threshold, 12, 2, INT_MAX, NULL, NULL }, {






		{"geqo_effort", PGC_USERSET, QUERY_TUNING_GEQO, gettext_noop("GEQO: effort is used to set the default for other GEQO parameters."), NULL }, &Geqo_effort, DEFAULT_GEQO_EFFORT, MIN_GEQO_EFFORT, MAX_GEQO_EFFORT, NULL, NULL }, {






		{"geqo_pool_size", PGC_USERSET, QUERY_TUNING_GEQO, gettext_noop("GEQO: number of individuals in the population."), gettext_noop("Zero selects a suitable default value.")

		}, &Geqo_pool_size, 0, 0, INT_MAX, NULL, NULL }, {



		{"geqo_generations", PGC_USERSET, QUERY_TUNING_GEQO, gettext_noop("GEQO: number of iterations of the algorithm."), gettext_noop("Zero selects a suitable default value.")

		}, &Geqo_generations, 0, 0, INT_MAX, NULL, NULL },  {




		{"deadlock_timeout", PGC_SIGHUP, LOCK_MANAGEMENT, gettext_noop("The time in milliseconds to wait on lock before checking for deadlock."), NULL }, &DeadlockTimeout, 1000, 0, INT_MAX, NULL, NULL },   {








		{"max_connections", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the maximum number of concurrent connections."), NULL }, &MaxBackends, 100, 1, INT_MAX / 4, NULL, NULL },  {







		{"superuser_reserved_connections", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the number of connection slots reserved for superusers."), NULL }, &ReservedBackends, 2, 0, INT_MAX / 4, NULL, NULL },  {







		{"shared_buffers", PGC_POSTMASTER, RESOURCES_MEM, gettext_noop("Sets the number of shared memory buffers used by the server."), NULL }, &NBuffers, 1000, 16, INT_MAX / 2, NULL, NULL },  {







		{"temp_buffers", PGC_USERSET, RESOURCES_MEM, gettext_noop("Sets the maximum number of temporary buffers used by each session."), NULL }, &num_temp_buffers, 1000, 100, INT_MAX / 2, NULL, show_num_temp_buffers },  {







		{"port", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the TCP port the server listens on."), NULL }, &PostPortNumber, DEF_PGPORT, 1, 65535, NULL, NULL },  {







		{"unix_socket_permissions", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the access permissions of the Unix-domain socket."), gettext_noop("Unix-domain sockets use the usual Unix file system " "permission set. The parameter value is expected to be an numeric mode " "specification in the form accepted by the chmod and umask system " "calls. (To use the customary octal format the number must start with " "a 0 (zero).)")





		}, &Unix_socket_permissions, 0777, 0000, 0777, NULL, NULL },  {




		{"work_mem", PGC_USERSET, RESOURCES_MEM, gettext_noop("Sets the maximum memory to be used for query workspaces."), gettext_noop("This much memory may be used by each internal " "sort operation and hash table before switching to " "temporary disk files.")



		}, &work_mem, 1024, 8 * BLCKSZ / 1024, MAX_KILOBYTES, NULL, NULL },  {




		{"maintenance_work_mem", PGC_USERSET, RESOURCES_MEM, gettext_noop("Sets the maximum memory to be used for maintenance operations."), gettext_noop("This includes operations such as VACUUM and CREATE INDEX.")

		}, &maintenance_work_mem, 16384, 1024, MAX_KILOBYTES, NULL, NULL },  {




		{"max_stack_depth", PGC_SUSET, RESOURCES_MEM, gettext_noop("Sets the maximum stack depth, in kilobytes."), NULL }, &max_stack_depth, 2048, 100, MAX_KILOBYTES, assign_max_stack_depth, NULL },  {







		{"vacuum_cost_page_hit", PGC_USERSET, RESOURCES, gettext_noop("Vacuum cost for a page found in the buffer cache."), NULL }, &VacuumCostPageHit, 1, 0, 10000, NULL, NULL },  {







		{"vacuum_cost_page_miss", PGC_USERSET, RESOURCES, gettext_noop("Vacuum cost for a page not found in the buffer cache."), NULL }, &VacuumCostPageMiss, 10, 0, 10000, NULL, NULL },  {







		{"vacuum_cost_page_dirty", PGC_USERSET, RESOURCES, gettext_noop("Vacuum cost for a page dirtied by vacuum."), NULL }, &VacuumCostPageDirty, 20, 0, 10000, NULL, NULL },  {







		{"vacuum_cost_limit", PGC_USERSET, RESOURCES, gettext_noop("Vacuum cost amount available before napping."), NULL }, &VacuumCostLimit, 200, 1, 10000, NULL, NULL },  {







		{"vacuum_cost_delay", PGC_USERSET, RESOURCES, gettext_noop("Vacuum cost delay in milliseconds."), NULL }, &VacuumCostDelay, 0, 0, 1000, NULL, NULL },  {







		{"autovacuum_vacuum_cost_delay", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Vacuum cost delay in milliseconds, for autovacuum."), NULL }, &autovacuum_vac_cost_delay, -1, -1, 1000, NULL, NULL },  {







		{"autovacuum_vacuum_cost_limit", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Vacuum cost amount available before napping, for autovacuum."), NULL }, &autovacuum_vac_cost_limit, -1, -1, 10000, NULL, NULL },  {







		{"max_files_per_process", PGC_POSTMASTER, RESOURCES_KERNEL, gettext_noop("Sets the maximum number of simultaneously open files for each server process."), NULL }, &max_files_per_process, 1000, 25, INT_MAX, NULL, NULL },  {







		{"max_prepared_transactions", PGC_POSTMASTER, RESOURCES, gettext_noop("Sets the maximum number of simultaneously prepared transactions."), NULL }, &max_prepared_xacts, 5, 0, INT_MAX, NULL, NULL },   {








		{"trace_lock_oidmin", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &Trace_lock_oidmin, FirstNormalObjectId, 0, INT_MAX, NULL, NULL }, {







		{"trace_lock_table", PGC_SUSET, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &Trace_lock_table, 0, 0, INT_MAX, NULL, NULL },   {









		{"statement_timeout", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the maximum allowed duration (in milliseconds) of any statement."), gettext_noop("A value of 0 turns off the timeout.")

		}, &StatementTimeout, 0, 0, INT_MAX, NULL, NULL },  {




		{"max_fsm_relations", PGC_POSTMASTER, RESOURCES_FSM, gettext_noop("Sets the maximum number of tables and indexes for which free space is tracked."), NULL }, &MaxFSMRelations, 1000, 100, INT_MAX, NULL, NULL }, {






		{"max_fsm_pages", PGC_POSTMASTER, RESOURCES_FSM, gettext_noop("Sets the maximum number of disk pages for which free space is tracked."), NULL }, &MaxFSMPages, 20000, 1000, INT_MAX, NULL, NULL },  {







		{"max_locks_per_transaction", PGC_POSTMASTER, LOCK_MANAGEMENT, gettext_noop("Sets the maximum number of locks per transaction."), gettext_noop("The shared lock table is sized on the assumption that " "at most max_locks_per_transaction * max_connections distinct " "objects will need to be locked at any one time.")



		}, &max_locks_per_xact, 64, 10, INT_MAX, NULL, NULL },  {




		{"authentication_timeout", PGC_SIGHUP, CONN_AUTH_SECURITY, gettext_noop("Sets the maximum time in seconds to complete client authentication."), NULL }, &AuthenticationTimeout, 60, 1, 600, NULL, NULL },  {







		
		{"pre_auth_delay", PGC_SIGHUP, DEVELOPER_OPTIONS, gettext_noop("no description available"), NULL, GUC_NOT_IN_SAMPLE }, &PreAuthDelay, 0, 0, 60, NULL, NULL },  {








		{"checkpoint_segments", PGC_SIGHUP, WAL_CHECKPOINTS, gettext_noop("Sets the maximum distance in log segments between automatic WAL checkpoints."), NULL }, &CheckPointSegments, 3, 1, INT_MAX, NULL, NULL },  {







		{"checkpoint_timeout", PGC_SIGHUP, WAL_CHECKPOINTS, gettext_noop("Sets the maximum time in seconds between automatic WAL checkpoints."), NULL }, &CheckPointTimeout, 300, 30, 3600, NULL, NULL },  {







		{"checkpoint_warning", PGC_SIGHUP, WAL_CHECKPOINTS, gettext_noop("Logs if filling of checkpoint segments happens more " "frequently than this (in seconds)."), gettext_noop("Write a message to the server log if checkpoints " "caused by the filling of checkpoint segment files happens more " "frequently than this number of seconds. Zero turns off the warning.")




		}, &CheckPointWarning, 30, 0, INT_MAX, NULL, NULL },  {




		{"wal_buffers", PGC_POSTMASTER, WAL_SETTINGS, gettext_noop("Sets the number of disk-page buffers in shared memory for WAL."), NULL }, &XLOGbuffers, 8, 4, INT_MAX, NULL, NULL },  {







		{"commit_delay", PGC_USERSET, WAL_CHECKPOINTS, gettext_noop("Sets the delay in microseconds between transaction commit and " "flushing WAL to disk."), NULL }, &CommitDelay, 0, 0, 100000, NULL, NULL },  {








		{"commit_siblings", PGC_USERSET, WAL_CHECKPOINTS, gettext_noop("Sets the minimum concurrent open transactions before performing " "commit_delay."), NULL }, &CommitSiblings, 5, 1, 1000, NULL, NULL },  {








		{"extra_float_digits", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the number of digits displayed for floating-point values."), gettext_noop("This affects real, double precision, and geometric data types. " "The parameter value is added to the standard number of digits " "(FLT_DIG or DBL_DIG as appropriate).")



		}, &extra_float_digits, 0, -15, 2, NULL, NULL },  {




		{"log_min_duration_statement", PGC_SUSET, LOGGING_WHEN, gettext_noop("Sets the minimum execution time in milliseconds above which statements will " "be logged."), gettext_noop("Zero prints all queries. The default is -1 (turning this feature off).")


		}, &log_min_duration_statement, -1, -1, INT_MAX / 1000, NULL, NULL },  {




		{"bgwriter_delay", PGC_SIGHUP, RESOURCES, gettext_noop("Background writer sleep time between rounds in milliseconds"), NULL }, &BgWriterDelay, 200, 10, 10000, NULL, NULL },  {







		{"bgwriter_lru_maxpages", PGC_SIGHUP, RESOURCES, gettext_noop("Background writer maximum number of LRU pages to flush per round"), NULL }, &bgwriter_lru_maxpages, 5, 0, 1000, NULL, NULL },  {







		{"bgwriter_all_maxpages", PGC_SIGHUP, RESOURCES, gettext_noop("Background writer maximum number of all pages to flush per round"), NULL }, &bgwriter_all_maxpages, 5, 0, 1000, NULL, NULL },  {







		{"log_rotation_age", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Automatic log file rotation will occur after N minutes"), NULL }, &Log_RotationAge, HOURS_PER_DAY * MINS_PER_HOUR, 0, INT_MAX / MINS_PER_HOUR, NULL, NULL },  {







		{"log_rotation_size", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Automatic log file rotation will occur after N kilobytes"), NULL }, &Log_RotationSize, 10 * 1024, 0, INT_MAX / 1024, NULL, NULL },  {







		{"max_function_args", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("Shows the maximum number of function arguments."), NULL, GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &max_function_args, FUNC_MAX_ARGS, FUNC_MAX_ARGS, FUNC_MAX_ARGS, NULL, NULL },  {








		{"max_index_keys", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("Shows the maximum number of index keys."), NULL, GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &max_index_keys, INDEX_MAX_KEYS, INDEX_MAX_KEYS, INDEX_MAX_KEYS, NULL, NULL },  {








		{"max_identifier_length", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("Shows the maximum identifier length"), NULL, GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &max_identifier_length, NAMEDATALEN - 1, NAMEDATALEN - 1, NAMEDATALEN - 1, NULL, NULL },  {








		{"block_size", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("Shows size of a disk block"), NULL, GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &block_size, BLCKSZ, BLCKSZ, BLCKSZ, NULL, NULL },  {








		{"autovacuum_naptime", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Time to sleep between autovacuum runs, in seconds."), NULL }, &autovacuum_naptime, 60, 1, INT_MAX, NULL, NULL }, {






		{"autovacuum_vacuum_threshold", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Minimum number of tuple updates or deletes prior to vacuum."), NULL }, &autovacuum_vac_thresh, 1000, 0, INT_MAX, NULL, NULL }, {






		{"autovacuum_analyze_threshold", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Minimum number of tuple inserts, updates or deletes prior to analyze."), NULL }, &autovacuum_anl_thresh, 500, 0, INT_MAX, NULL, NULL },  {







		{"tcp_keepalives_idle", PGC_USERSET, CLIENT_CONN_OTHER, gettext_noop("Seconds between issuing TCP keepalives."), gettext_noop("A value of 0 uses the system default."), }, &tcp_keepalives_idle, 0, 0, INT_MAX, assign_tcp_keepalives_idle, show_tcp_keepalives_idle },  {







		{"tcp_keepalives_interval", PGC_USERSET, CLIENT_CONN_OTHER, gettext_noop("Seconds between TCP keepalive retransmits."), gettext_noop("A value of 0 uses the system default."), }, &tcp_keepalives_interval, 0, 0, INT_MAX, assign_tcp_keepalives_interval, show_tcp_keepalives_interval },  {







		{"tcp_keepalives_count", PGC_USERSET, CLIENT_CONN_OTHER, gettext_noop("Maximum number of TCP keepalive retransmits."), gettext_noop("This controls the number of consecutive keepalive retransmits that can be " "lost before a connection is considered dead. A value of 0 uses the " "system default."), }, &tcp_keepalives_count, 0, 0, INT_MAX, assign_tcp_keepalives_count, show_tcp_keepalives_count },   {










		{NULL, 0, 0, NULL, NULL}, NULL, 0, 0, 0, NULL, NULL }
};


static struct config_real ConfigureNamesReal[] = {
	{
		{"effective_cache_size", PGC_USERSET, QUERY_TUNING_COST, gettext_noop("Sets the planner's assumption about size of the disk cache."), gettext_noop("That is, the portion of the kernel's disk cache that " "will be used for PostgreSQL data files. This is measured in disk " "pages, which are normally 8 kB each.")



		}, &effective_cache_size, DEFAULT_EFFECTIVE_CACHE_SIZE, 1, DBL_MAX, NULL, NULL }, {



		{"random_page_cost", PGC_USERSET, QUERY_TUNING_COST, gettext_noop("Sets the planner's estimate of the cost of a nonsequentially " "fetched disk page."), gettext_noop("This is measured as a multiple of the cost of a " "sequential page fetch. A higher value makes it more likely a " "sequential scan will be used, a lower value makes it more likely an " "index scan will be used.")





		}, &random_page_cost, DEFAULT_RANDOM_PAGE_COST, 0, DBL_MAX, NULL, NULL }, {



		{"cpu_tuple_cost", PGC_USERSET, QUERY_TUNING_COST, gettext_noop("Sets the planner's estimate of the cost of processing each tuple (row)."), gettext_noop("This is measured as a fraction of the cost of a " "sequential page fetch.")


		}, &cpu_tuple_cost, DEFAULT_CPU_TUPLE_COST, 0, DBL_MAX, NULL, NULL }, {



		{"cpu_index_tuple_cost", PGC_USERSET, QUERY_TUNING_COST, gettext_noop("Sets the planner's estimate of processing cost for each " "index tuple (row) during index scan."), gettext_noop("This is measured as a fraction of the cost of a " "sequential page fetch.")



		}, &cpu_index_tuple_cost, DEFAULT_CPU_INDEX_TUPLE_COST, 0, DBL_MAX, NULL, NULL }, {



		{"cpu_operator_cost", PGC_USERSET, QUERY_TUNING_COST, gettext_noop("Sets the planner's estimate of processing cost of each operator in WHERE."), gettext_noop("This is measured as a fraction of the cost of a sequential " "page fetch.")


		}, &cpu_operator_cost, DEFAULT_CPU_OPERATOR_COST, 0, DBL_MAX, NULL, NULL },  {




		{"geqo_selection_bias", PGC_USERSET, QUERY_TUNING_GEQO, gettext_noop("GEQO: selective pressure within the population."), NULL }, &Geqo_selection_bias, DEFAULT_GEQO_SELECTION_BIAS, MIN_GEQO_SELECTION_BIAS, MAX_GEQO_SELECTION_BIAS, NULL, NULL },  {








		{"bgwriter_lru_percent", PGC_SIGHUP, RESOURCES, gettext_noop("Background writer percentage of LRU buffers to flush per round"), NULL }, &bgwriter_lru_percent, 1.0, 0.0, 100.0, NULL, NULL },  {







		{"bgwriter_all_percent", PGC_SIGHUP, RESOURCES, gettext_noop("Background writer percentage of all buffers to flush per round"), NULL }, &bgwriter_all_percent, 0.333, 0.0, 100.0, NULL, NULL },  {







		{"seed", PGC_USERSET, UNGROUPED, gettext_noop("Sets the seed for random-number generation."), NULL, GUC_NO_SHOW_ALL | GUC_NO_RESET_ALL | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &phony_random_seed, 0.5, 0.0, 1.0, assign_random_seed, show_random_seed },  {








		{"autovacuum_vacuum_scale_factor", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Number of tuple updates or deletes prior to vacuum as a fraction of reltuples."), NULL }, &autovacuum_vac_scale, 0.4, 0.0, 100.0, NULL, NULL }, {






		{"autovacuum_analyze_scale_factor", PGC_SIGHUP, AUTOVACUUM, gettext_noop("Number of tuple inserts, updates or deletes prior to analyze as a fraction of reltuples."), NULL }, &autovacuum_anl_scale, 0.2, 0.0, 100.0, NULL, NULL },   {








		{NULL, 0, 0, NULL, NULL}, NULL, 0.0, 0.0, 0.0, NULL, NULL }
};


static struct config_string ConfigureNamesString[] = {
	{
		{"archive_command", PGC_SIGHUP, WAL_SETTINGS, gettext_noop("WAL archiving command."), gettext_noop("The shell command that will be called to archive a WAL file.")

		}, &XLogArchiveCommand, "", NULL, NULL },  {




		{"client_encoding", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the client's character set encoding."), NULL, GUC_REPORT }, &client_encoding_string, "SQL_ASCII", assign_client_encoding, NULL },  {








		{"client_min_messages", PGC_USERSET, LOGGING_WHEN, gettext_noop("Sets the message levels that are sent to the client."), gettext_noop("Valid values are DEBUG5, DEBUG4, DEBUG3, DEBUG2, " "DEBUG1, LOG, NOTICE, WARNING, and ERROR. Each level includes all the " "levels that follow it. The later the level, the fewer messages are " "sent.")




		}, &client_min_messages_str, "notice", assign_client_min_messages, NULL },  {




		{"log_min_messages", PGC_SUSET, LOGGING_WHEN, gettext_noop("Sets the message levels that are logged."), gettext_noop("Valid values are DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, " "INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. Each level " "includes all the levels that follow it.")



		}, &log_min_messages_str, "notice", assign_log_min_messages, NULL },  {




		{"log_error_verbosity", PGC_SUSET, LOGGING_WHEN, gettext_noop("Sets the verbosity of logged messages."), gettext_noop("Valid values are \"terse\", \"default\", and \"verbose\".")

		}, &log_error_verbosity_str, "default", assign_log_error_verbosity, NULL }, {



		{"log_statement", PGC_SUSET, LOGGING_WHAT, gettext_noop("Sets the type of statements logged."), gettext_noop("Valid values are \"none\", \"ddl\", \"mod\", and \"all\".")

		}, &log_statement_str, "none", assign_log_statement, NULL },  {




		{"log_min_error_statement", PGC_SUSET, LOGGING_WHEN, gettext_noop("Causes all statements generating error at or above this level to be logged."), gettext_noop("All SQL statements that cause an error of the " "specified level or a higher level are logged.")


		}, &log_min_error_statement_str, "panic", assign_min_error_statement, NULL },  {




		{"log_line_prefix", PGC_SIGHUP, LOGGING_WHAT, gettext_noop("Controls information prefixed to each log line"), gettext_noop("if blank no prefix is used")

		}, &Log_line_prefix, "", NULL, NULL },   {





		{"DateStyle", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the display format for date and time values."), gettext_noop("Also controls interpretation of ambiguous " "date inputs."), GUC_LIST_INPUT | GUC_REPORT }, &datestyle_string, "ISO, MDY", assign_datestyle, NULL },  {









		{"default_tablespace", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the default tablespace to create tables and indexes in."), gettext_noop("An empty string selects the database's default tablespace.")

		}, &default_tablespace, "", assign_default_tablespace, NULL },  {




		{"default_transaction_isolation", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the transaction isolation level of each new transaction."), gettext_noop("Each SQL transaction has an isolation level, which " "can be either \"read uncommitted\", \"read committed\", \"repeatable read\", or \"serializable\".")


		}, &default_iso_level_string, "read committed", assign_defaultxactisolevel, NULL },  {




		{"dynamic_library_path", PGC_SUSET, CLIENT_CONN_OTHER, gettext_noop("Sets the path for dynamically loadable modules."), gettext_noop("If a dynamically loadable module needs to be opened and " "the specified name does not have a directory component (i.e., the " "name does not contain a slash), the system will search this path for " "the specified file."), GUC_SUPERUSER_ONLY }, &Dynamic_library_path, "$libdir", NULL, NULL },  {











		{"krb_server_keyfile", PGC_POSTMASTER, CONN_AUTH_SECURITY, gettext_noop("Sets the location of the Kerberos server key file."), NULL, GUC_SUPERUSER_ONLY }, &pg_krb_server_keyfile, PG_KRB_SRVTAB, NULL, NULL },  {








		{"krb_srvname", PGC_POSTMASTER, CONN_AUTH_SECURITY, gettext_noop("Sets the name of the Kerberos service."), NULL }, &pg_krb_srvnam, PG_KRB_SRVNAM, NULL, NULL },  {







		{"krb_server_hostname", PGC_POSTMASTER, CONN_AUTH_SECURITY, gettext_noop("Sets the hostname of the Kerberos server."), NULL }, &pg_krb_server_hostname, NULL, NULL, NULL },  {







		{"bonjour_name", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the Bonjour broadcast service name."), NULL }, &bonjour_name, "", NULL, NULL },    {









		{"lc_collate", PGC_INTERNAL, CLIENT_CONN_LOCALE, gettext_noop("Shows the collation order locale."), NULL, GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &locale_collate, "C", NULL, NULL },  {








		{"lc_ctype", PGC_INTERNAL, CLIENT_CONN_LOCALE, gettext_noop("Shows the character classification and case conversion locale."), NULL, GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &locale_ctype, "C", NULL, NULL },  {








		{"lc_messages", PGC_SUSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the language in which messages are displayed."), NULL }, &locale_messages, "", locale_messages_assign, NULL },  {







		{"lc_monetary", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the locale for formatting monetary amounts."), NULL }, &locale_monetary, "C", locale_monetary_assign, NULL },  {







		{"lc_numeric", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the locale for formatting numbers."), NULL }, &locale_numeric, "C", locale_numeric_assign, NULL },  {







		{"lc_time", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the locale for formatting date and time values."), NULL }, &locale_time, "C", locale_time_assign, NULL },  {







		{"preload_libraries", PGC_POSTMASTER, RESOURCES_KERNEL, gettext_noop("Lists shared libraries to preload into server."), NULL, GUC_LIST_INPUT | GUC_LIST_QUOTE | GUC_SUPERUSER_ONLY }, &preload_libraries_string, "", NULL, NULL },  {








		{"regex_flavor", PGC_USERSET, COMPAT_OPTIONS_PREVIOUS, gettext_noop("Sets the regular expression \"flavor\"."), gettext_noop("This can be set to advanced, extended, or basic.")

		}, &regex_flavor_string, "advanced", assign_regex_flavor, NULL },  {




		{"search_path", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the schema search order for names that are not schema-qualified."), NULL, GUC_LIST_INPUT | GUC_LIST_QUOTE }, &namespace_search_path, "\"$user\",public", assign_search_path, NULL },  {








		
		{"server_encoding", PGC_INTERNAL, CLIENT_CONN_LOCALE, gettext_noop("Sets the server (database) character set encoding."), NULL, GUC_REPORT | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &server_encoding_string, "SQL_ASCII", NULL, NULL },  {








		
		{"server_version", PGC_INTERNAL, PRESET_OPTIONS, gettext_noop("Shows the server version."), NULL, GUC_REPORT | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &server_version_string, PG_VERSION, NULL, NULL },  {








		
		{"role", PGC_USERSET, UNGROUPED, gettext_noop("Sets the current role."), NULL, GUC_NO_SHOW_ALL | GUC_NO_RESET_ALL | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &role_string, "none", assign_role, show_role },  {








		
		{"session_authorization", PGC_USERSET, UNGROUPED, gettext_noop("Sets the session user name."), NULL, GUC_REPORT | GUC_NO_SHOW_ALL | GUC_NO_RESET_ALL | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &session_authorization_string, NULL, assign_session_authorization, show_session_authorization },  {








		{"log_destination", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Sets the destination for server log output."), gettext_noop("Valid values are combinations of \"stderr\", \"syslog\", " "and \"eventlog\", depending on the platform."), GUC_LIST_INPUT }, &log_destination_string, "stderr", assign_log_destination, NULL }, {








		{"log_directory", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Sets the destination directory for log files."), gettext_noop("May be specified as relative to the data directory " "or as absolute path."), GUC_SUPERUSER_ONLY }, &Log_directory, "pg_log", assign_canonical_path, NULL }, {








		{"log_filename", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Sets the file name pattern for log files."), NULL, GUC_SUPERUSER_ONLY }, &Log_filename, "postgresql-%Y-%m-%d_%H%M%S.log", NULL, NULL },   {









		{"syslog_facility", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Sets the syslog \"facility\" to be used when syslog enabled."), gettext_noop("Valid values are LOCAL0, LOCAL1, LOCAL2, LOCAL3, " "LOCAL4, LOCAL5, LOCAL6, LOCAL7.")


		}, &syslog_facility_str, "LOCAL0", assign_syslog_facility, NULL }, {



		{"syslog_ident", PGC_SIGHUP, LOGGING_WHERE, gettext_noop("Sets the program name used to identify PostgreSQL " "messages in syslog."), NULL }, &syslog_ident_str, "postgres", assign_syslog_ident, NULL },   {









		{"TimeZone", PGC_USERSET, CLIENT_CONN_LOCALE, gettext_noop("Sets the time zone for displaying and interpreting time stamps."), NULL, GUC_REPORT }, &timezone_string, "UNKNOWN", assign_timezone, show_timezone },  {








		{"transaction_isolation", PGC_USERSET, CLIENT_CONN_STATEMENT, gettext_noop("Sets the current transaction's isolation level."), NULL, GUC_NO_RESET_ALL | GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE }, &XactIsoLevel_string, NULL, assign_XactIsoLevel, show_XactIsoLevel },  {








		{"unix_socket_group", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the owning group of the Unix-domain socket."), gettext_noop("(The owning user of the socket is always the user " "that starts the server.)")


		}, &Unix_socket_group, "", NULL, NULL },  {




		{"unix_socket_directory", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the directory where the Unix-domain socket will be created."), NULL, GUC_SUPERUSER_ONLY }, &UnixSocketDir, "", assign_canonical_path, NULL },  {








		{"listen_addresses", PGC_POSTMASTER, CONN_AUTH_SETTINGS, gettext_noop("Sets the host name or IP address(es) to listen to."), NULL, GUC_LIST_INPUT }, &ListenAddresses, "localhost", NULL, NULL },  {








		{"wal_sync_method", PGC_SIGHUP, WAL_SETTINGS, gettext_noop("Selects the method used for forcing WAL updates out to disk."), NULL }, &XLOG_sync_method, XLOG_sync_method_default, assign_xlog_sync_method, NULL },  {







		{"custom_variable_classes", PGC_SIGHUP, CUSTOM_OPTIONS, gettext_noop("Sets the list of known custom variable classes."), NULL, GUC_LIST_INPUT | GUC_LIST_QUOTE }, &custom_variable_classes, NULL, assign_custom_variable_classes, NULL },  {








		{"data_directory", PGC_POSTMASTER, FILE_LOCATIONS, gettext_noop("Sets the server's data directory."), NULL, GUC_SUPERUSER_ONLY }, &data_directory, NULL, NULL, NULL },  {








		{"config_file", PGC_POSTMASTER, FILE_LOCATIONS, gettext_noop("Sets the server's main configuration file."), NULL, GUC_DISALLOW_IN_FILE | GUC_SUPERUSER_ONLY }, &ConfigFileName, NULL, NULL, NULL },  {








		{"hba_file", PGC_POSTMASTER, FILE_LOCATIONS, gettext_noop("Sets the server's \"hba\" configuration file"), NULL, GUC_SUPERUSER_ONLY }, &HbaFileName, NULL, NULL, NULL },  {








		{"ident_file", PGC_POSTMASTER, FILE_LOCATIONS, gettext_noop("Sets the server's \"ident\" configuration file"), NULL, GUC_SUPERUSER_ONLY }, &IdentFileName, NULL, NULL, NULL },  {








		{"external_pid_file", PGC_POSTMASTER, FILE_LOCATIONS, gettext_noop("Writes the postmaster PID to the specified file."), NULL, GUC_SUPERUSER_ONLY }, &external_pid_file, NULL, assign_canonical_path, NULL },   {









		{NULL, 0, 0, NULL, NULL}, NULL, NULL, NULL, NULL }
};






static const char *const map_old_guc_names[] = {
	"sort_mem", "work_mem", "vacuum_mem", "maintenance_work_mem", NULL };





static struct config_generic **guc_variables;


static int	num_guc_variables;


static int	size_guc_variables;


static bool guc_dirty;			

static bool reporting_enabled;	


static int	guc_var_compare(const void *a, const void *b);
static int	guc_name_compare(const char *namea, const char *nameb);
static void push_old_value(struct config_generic * gconf);
static void ReportGUCOption(struct config_generic * record);
static void ShowGUCConfigOption(const char *name, DestReceiver *dest);
static void ShowAllGUCConfig(DestReceiver *dest);
static char *_ShowOption(struct config_generic * record);
static bool is_newvalue_equal(struct config_generic *record, const char *newvalue);



static void * guc_malloc(int elevel, size_t size)
{
	void	   *data;

	data = malloc(size);
	if (data == NULL)
		ereport(elevel, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));

	return data;
}

static void * guc_realloc(int elevel, void *old, size_t size)
{
	void	   *data;

	data = realloc(old, size);
	if (data == NULL)
		ereport(elevel, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));

	return data;
}

static char * guc_strdup(int elevel, const char *src)
{
	char	   *data;

	data = strdup(src);
	if (data == NULL)
		ereport(elevel, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));

	return data;
}



static void set_string_field(struct config_string * conf, char **field, char *newval)
{
	char	   *oldval = *field;
	GucStack   *stack;

	
	*field = newval;

	
	if (oldval == NULL || oldval == *(conf->variable) || oldval == conf->reset_val || oldval == conf->tentative_val)


		return;
	for (stack = conf->gen.stack; stack; stack = stack->prev)
	{
		if (oldval == stack->tentative_val.stringval || oldval == stack->value.stringval)
			return;
	}

	
	free(oldval);
}


static bool string_field_used(struct config_string * conf, char *strval)
{
	GucStack   *stack;

	if (strval == *(conf->variable) || strval == conf->reset_val || strval == conf->tentative_val)

		return true;
	for (stack = conf->gen.stack; stack; stack = stack->prev)
	{
		if (strval == stack->tentative_val.stringval || strval == stack->value.stringval)
			return true;
	}
	return false;
}


struct config_generic ** get_guc_variables(void)
{
	return guc_variables;
}



void build_guc_variables(void)
{
	int			size_vars;
	int			num_vars = 0;
	struct config_generic **guc_vars;
	int			i;

	for (i = 0; ConfigureNamesBool[i].gen.name; i++)
	{
		struct config_bool *conf = &ConfigureNamesBool[i];

		
		conf->gen.vartype = PGC_BOOL;
		num_vars++;
	}

	for (i = 0; ConfigureNamesInt[i].gen.name; i++)
	{
		struct config_int *conf = &ConfigureNamesInt[i];

		conf->gen.vartype = PGC_INT;
		num_vars++;
	}

	for (i = 0; ConfigureNamesReal[i].gen.name; i++)
	{
		struct config_real *conf = &ConfigureNamesReal[i];

		conf->gen.vartype = PGC_REAL;
		num_vars++;
	}

	for (i = 0; ConfigureNamesString[i].gen.name; i++)
	{
		struct config_string *conf = &ConfigureNamesString[i];

		conf->gen.vartype = PGC_STRING;
		num_vars++;
	}

	
	size_vars = num_vars + num_vars / 4;

	guc_vars = (struct config_generic **)
		guc_malloc(FATAL, size_vars * sizeof(struct config_generic *));

	num_vars = 0;

	for (i = 0; ConfigureNamesBool[i].gen.name; i++)
		guc_vars[num_vars++] = &ConfigureNamesBool[i].gen;

	for (i = 0; ConfigureNamesInt[i].gen.name; i++)
		guc_vars[num_vars++] = &ConfigureNamesInt[i].gen;

	for (i = 0; ConfigureNamesReal[i].gen.name; i++)
		guc_vars[num_vars++] = &ConfigureNamesReal[i].gen;

	for (i = 0; ConfigureNamesString[i].gen.name; i++)
		guc_vars[num_vars++] = &ConfigureNamesString[i].gen;

	if (guc_variables)
		free(guc_variables);
	guc_variables = guc_vars;
	num_guc_variables = num_vars;
	size_guc_variables = size_vars;
	qsort((void *) guc_variables, num_guc_variables, sizeof(struct config_generic *), guc_var_compare);
}

static bool is_custom_class(const char *name, int dotPos)
{
	
	bool		result = false;
	const char *ccs = GetConfigOption("custom_variable_classes");

	if (ccs != NULL)
	{
		const char *start = ccs;

		for (;; ++ccs)
		{
			int			c = *ccs;

			if (c == 0 || c == ',')
			{
				if (dotPos == ccs - start && strncmp(start, name, dotPos) == 0)
				{
					result = true;
					break;
				}
				if (c == 0)
					break;
				start = ccs + 1;
			}
		}
	}
	return result;
}


static bool add_guc_variable(struct config_generic * var, int elevel)
{
	if (num_guc_variables + 1 >= size_guc_variables)
	{
		
		int			size_vars = size_guc_variables + size_guc_variables / 4;
		struct config_generic **guc_vars;

		if (size_vars == 0)
		{
			size_vars = 100;
			guc_vars = (struct config_generic **)
				guc_malloc(elevel, size_vars * sizeof(struct config_generic *));
		}
		else {
			guc_vars = (struct config_generic **)
				guc_realloc(elevel, guc_variables, size_vars * sizeof(struct config_generic *));
		}

		if (guc_vars == NULL)
			return false;		

		guc_variables = guc_vars;
		size_guc_variables = size_vars;
	}
	guc_variables[num_guc_variables++] = var;
	qsort((void *) guc_variables, num_guc_variables, sizeof(struct config_generic *), guc_var_compare);
	return true;
}


static struct config_string * add_placeholder_variable(const char *name, int elevel)
{
	size_t		sz = sizeof(struct config_string) + sizeof(char *);
	struct config_string *var;
	struct config_generic *gen;

	var = (struct config_string *) guc_malloc(elevel, sz);
	if (var == NULL)
		return NULL;

	gen = &var->gen;
	memset(var, 0, sz);

	gen->name = guc_strdup(elevel, name);
	if (gen->name == NULL)
	{
		free(var);
		return NULL;
	}

	gen->context = PGC_USERSET;
	gen->group = CUSTOM_OPTIONS;
	gen->short_desc = "GUC placeholder variable";
	gen->flags = GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE | GUC_CUSTOM_PLACEHOLDER;
	gen->vartype = PGC_STRING;

	
	var->variable = (char **) (var + 1);

	if (!add_guc_variable((struct config_generic *) var, elevel))
	{
		free((void *) gen->name);
		free(var);
		return NULL;
	}

	return var;
}


static struct config_generic * find_option(const char *name, int elevel)
{
	const char *dot;
	const char **key = &name;
	struct config_generic **res;
	int			i;

	Assert(name);

	
	res = (struct config_generic **) bsearch((void *) &key, (void *) guc_variables, num_guc_variables, sizeof(struct config_generic *), guc_var_compare);



	if (res)
		return *res;

	
	for (i = 0; map_old_guc_names[i] != NULL; i += 2)
	{
		if (guc_name_compare(name, map_old_guc_names[i]) == 0)
			return find_option(map_old_guc_names[i + 1], elevel);
	}

	
	dot = strchr(name, GUC_QUALIFIER_SEPARATOR);
	if (dot != NULL && is_custom_class(name, dot - name))
		
		return (struct config_generic *) add_placeholder_variable(name, elevel);

	
	return NULL;
}



static int guc_var_compare(const void *a, const void *b)
{
	struct config_generic *confa = *(struct config_generic **) a;
	struct config_generic *confb = *(struct config_generic **) b;

	return guc_name_compare(confa->name, confb->name);
}


static int guc_name_compare(const char *namea, const char *nameb)
{
	
	while (*namea && *nameb)
	{
		char		cha = *namea++;
		char		chb = *nameb++;

		if (cha >= 'A' && cha <= 'Z')
			cha += 'a' - 'A';
		if (chb >= 'A' && chb <= 'Z')
			chb += 'a' - 'A';
		if (cha != chb)
			return cha - chb;
	}
	if (*namea)
		return 1;				
	if (*nameb)
		return -1;				
	return 0;
}



void InitializeGUCOptions(void)
{
	int			i;
	char	   *env;

	
	build_guc_variables();

	
	for (i = 0; i < num_guc_variables; i++)
	{
		struct config_generic *gconf = guc_variables[i];

		gconf->status = 0;
		gconf->reset_source = PGC_S_DEFAULT;
		gconf->tentative_source = PGC_S_DEFAULT;
		gconf->source = PGC_S_DEFAULT;
		gconf->stack = NULL;

		switch (gconf->vartype)
		{
			case PGC_BOOL:
				{
					struct config_bool *conf = (struct config_bool *) gconf;

					if (conf->assign_hook)
						if (!(*conf->assign_hook) (conf->reset_val, true, PGC_S_DEFAULT))
							elog(FATAL, "failed to initialize %s to %d", conf->gen.name, (int) conf->reset_val);
					*conf->variable = conf->reset_val;
					break;
				}
			case PGC_INT:
				{
					struct config_int *conf = (struct config_int *) gconf;

					Assert(conf->reset_val >= conf->min);
					Assert(conf->reset_val <= conf->max);
					if (conf->assign_hook)
						if (!(*conf->assign_hook) (conf->reset_val, true, PGC_S_DEFAULT))
							elog(FATAL, "failed to initialize %s to %d", conf->gen.name, conf->reset_val);
					*conf->variable = conf->reset_val;
					break;
				}
			case PGC_REAL:
				{
					struct config_real *conf = (struct config_real *) gconf;

					Assert(conf->reset_val >= conf->min);
					Assert(conf->reset_val <= conf->max);
					if (conf->assign_hook)
						if (!(*conf->assign_hook) (conf->reset_val, true, PGC_S_DEFAULT))
							elog(FATAL, "failed to initialize %s to %g", conf->gen.name, conf->reset_val);
					*conf->variable = conf->reset_val;
					break;
				}
			case PGC_STRING:
				{
					struct config_string *conf = (struct config_string *) gconf;
					char	   *str;

					*conf->variable = NULL;
					conf->reset_val = NULL;
					conf->tentative_val = NULL;

					if (conf->boot_val == NULL)
					{
						
						break;
					}

					str = guc_strdup(FATAL, conf->boot_val);
					conf->reset_val = str;

					if (conf->assign_hook)
					{
						const char *newstr;

						newstr = (*conf->assign_hook) (str, true, PGC_S_DEFAULT);
						if (newstr == NULL)
						{
							elog(FATAL, "failed to initialize %s to \"%s\"", conf->gen.name, str);
						}
						else if (newstr != str)
						{
							free(str);

							
							str = (char *) newstr;
							conf->reset_val = str;
						}
					}
					*conf->variable = str;
					break;
				}
		}
	}

	guc_dirty = false;

	reporting_enabled = false;

	
	SetConfigOption("transaction_isolation", "default", PGC_POSTMASTER, PGC_S_OVERRIDE);
	SetConfigOption("transaction_read_only", "no", PGC_POSTMASTER, PGC_S_OVERRIDE);

	

	env = getenv("PGPORT");
	if (env != NULL)
		SetConfigOption("port", env, PGC_POSTMASTER, PGC_S_ENV_VAR);

	env = getenv("PGDATESTYLE");
	if (env != NULL)
		SetConfigOption("datestyle", env, PGC_POSTMASTER, PGC_S_ENV_VAR);

	env = getenv("PGCLIENTENCODING");
	if (env != NULL)
		SetConfigOption("client_encoding", env, PGC_POSTMASTER, PGC_S_ENV_VAR);
}



bool SelectConfigFiles(const char *userDoption, const char *progname)
{
	char	   *configdir;
	char	   *fname;
	struct stat stat_buf;

	
	if (userDoption)
		configdir = make_absolute_path(userDoption);
	else configdir = make_absolute_path(getenv("PGDATA"));

	
	if (ConfigFileName)
		fname = make_absolute_path(ConfigFileName);
	else if (configdir)
	{
		fname = guc_malloc(FATAL, strlen(configdir) + strlen(CONFIG_FILENAME) + 2);
		sprintf(fname, "%s/%s", configdir, CONFIG_FILENAME);
	}
	else {
		write_stderr("%s does not know where to find the server configuration file.\n" "You must specify the --config-file or -D invocation " "option or set the PGDATA environment variable.\n", progname);


		return false;
	}

	
	SetConfigOption("config_file", fname, PGC_POSTMASTER, PGC_S_OVERRIDE);
	free(fname);

	
	if (stat(ConfigFileName, &stat_buf) != 0)
	{
		write_stderr("%s cannot access the server configuration file \"%s\": %s\n", progname, ConfigFileName, strerror(errno));
		return false;
	}

	ProcessConfigFile(PGC_POSTMASTER);

	
	if (data_directory)
		SetDataDir(data_directory);
	else if (configdir)
		SetDataDir(configdir);
	else {
		write_stderr("%s does not know where to find the database system data.\n" "This can be specified as \"data_directory\" in \"%s\", " "or by the -D invocation option, or by the " "PGDATA environment variable.\n", progname, ConfigFileName);



		return false;
	}

	
	SetConfigOption("data_directory", DataDir, PGC_POSTMASTER, PGC_S_OVERRIDE);

	
	if (HbaFileName)
		fname = make_absolute_path(HbaFileName);
	else if (configdir)
	{
		fname = guc_malloc(FATAL, strlen(configdir) + strlen(HBA_FILENAME) + 2);
		sprintf(fname, "%s/%s", configdir, HBA_FILENAME);
	}
	else {
		write_stderr("%s does not know where to find the \"hba\" configuration file.\n" "This can be specified as \"hba_file\" in \"%s\", " "or by the -D invocation option, or by the " "PGDATA environment variable.\n", progname, ConfigFileName);



		return false;
	}
	SetConfigOption("hba_file", fname, PGC_POSTMASTER, PGC_S_OVERRIDE);
	free(fname);

	
	if (IdentFileName)
		fname = make_absolute_path(IdentFileName);
	else if (configdir)
	{
		fname = guc_malloc(FATAL, strlen(configdir) + strlen(IDENT_FILENAME) + 2);
		sprintf(fname, "%s/%s", configdir, IDENT_FILENAME);
	}
	else {
		write_stderr("%s does not know where to find the \"ident\" configuration file.\n" "This can be specified as \"ident_file\" in \"%s\", " "or by the -D invocation option, or by the " "PGDATA environment variable.\n", progname, ConfigFileName);



		return false;
	}
	SetConfigOption("ident_file", fname, PGC_POSTMASTER, PGC_S_OVERRIDE);
	free(fname);

	free(configdir);

	return true;
}



void ResetAllOptions(void)
{
	int			i;

	for (i = 0; i < num_guc_variables; i++)
	{
		struct config_generic *gconf = guc_variables[i];

		
		if (gconf->context != PGC_SUSET && gconf->context != PGC_USERSET)
			continue;
		
		if (gconf->flags & GUC_NO_RESET_ALL)
			continue;
		
		if (gconf->source <= PGC_S_OVERRIDE)
			continue;

		
		push_old_value(gconf);

		switch (gconf->vartype)
		{
			case PGC_BOOL:
				{
					struct config_bool *conf = (struct config_bool *) gconf;

					if (conf->assign_hook)
						if (!(*conf->assign_hook) (conf->reset_val, true, PGC_S_SESSION))
							elog(ERROR, "failed to reset %s", conf->gen.name);
					*conf->variable = conf->reset_val;
					conf->tentative_val = conf->reset_val;
					conf->gen.source = conf->gen.reset_source;
					conf->gen.tentative_source = conf->gen.reset_source;
					conf->gen.status |= GUC_HAVE_TENTATIVE;
					guc_dirty = true;
					break;
				}
			case PGC_INT:
				{
					struct config_int *conf = (struct config_int *) gconf;

					if (conf->assign_hook)
						if (!(*conf->assign_hook) (conf->reset_val, true, PGC_S_SESSION))
							elog(ERROR, "failed to reset %s", conf->gen.name);
					*conf->variable = conf->reset_val;
					conf->tentative_val = conf->reset_val;
					conf->gen.source = conf->gen.reset_source;
					conf->gen.tentative_source = conf->gen.reset_source;
					conf->gen.status |= GUC_HAVE_TENTATIVE;
					guc_dirty = true;
					break;
				}
			case PGC_REAL:
				{
					struct config_real *conf = (struct config_real *) gconf;

					if (conf->assign_hook)
						if (!(*conf->assign_hook) (conf->reset_val, true, PGC_S_SESSION))
							elog(ERROR, "failed to reset %s", conf->gen.name);
					*conf->variable = conf->reset_val;
					conf->tentative_val = conf->reset_val;
					conf->gen.source = conf->gen.reset_source;
					conf->gen.tentative_source = conf->gen.reset_source;
					conf->gen.status |= GUC_HAVE_TENTATIVE;
					guc_dirty = true;
					break;
				}
			case PGC_STRING:
				{
					struct config_string *conf = (struct config_string *) gconf;
					char	   *str;

					if (conf->reset_val == NULL)
					{
						
						break;
					}

					
					str = conf->reset_val;

					if (conf->assign_hook)
					{
						const char *newstr;

						newstr = (*conf->assign_hook) (str, true, PGC_S_SESSION);
						if (newstr == NULL)
							elog(ERROR, "failed to reset %s", conf->gen.name);
						else if (newstr != str)
						{
							
							str = (char *) newstr;
						}
					}

					set_string_field(conf, conf->variable, str);
					set_string_field(conf, &conf->tentative_val, str);
					conf->gen.source = conf->gen.reset_source;
					conf->gen.tentative_source = conf->gen.reset_source;
					conf->gen.status |= GUC_HAVE_TENTATIVE;
					guc_dirty = true;
					break;
				}
		}

		if (gconf->flags & GUC_REPORT)
			ReportGUCOption(gconf);
	}
}



static void push_old_value(struct config_generic * gconf)
{
	int			my_level = GetCurrentTransactionNestLevel();
	GucStack   *stack;

	
	if (my_level == 0)
		return;

	for (;;)
	{
		
		if (gconf->stack && gconf->stack->nest_level >= my_level)
			return;

		
		stack = (GucStack *) MemoryContextAlloc(TopTransactionContext, sizeof(GucStack));

		stack->prev = gconf->stack;
		stack->nest_level = stack->prev ? stack->prev->nest_level + 1 : 1;
		stack->status = gconf->status;
		stack->tentative_source = gconf->tentative_source;
		stack->source = gconf->source;

		switch (gconf->vartype)
		{
			case PGC_BOOL:
				stack->tentative_val.boolval = ((struct config_bool *) gconf)->tentative_val;
				stack->value.boolval = *((struct config_bool *) gconf)->variable;
				break;

			case PGC_INT:
				stack->tentative_val.intval = ((struct config_int *) gconf)->tentative_val;
				stack->value.intval = *((struct config_int *) gconf)->variable;
				break;

			case PGC_REAL:
				stack->tentative_val.realval = ((struct config_real *) gconf)->tentative_val;
				stack->value.realval = *((struct config_real *) gconf)->variable;
				break;

			case PGC_STRING:
				stack->tentative_val.stringval = ((struct config_string *) gconf)->tentative_val;
				stack->value.stringval = *((struct config_string *) gconf)->variable;
				break;
		}

		gconf->stack = stack;

		
		gconf->status = GUC_HAVE_STACK;

		
		guc_dirty = true;
	}
}


void AtEOXact_GUC(bool isCommit, bool isSubXact)
{
	int			my_level;
	int			i;

	
	if (!guc_dirty)
		return;

	my_level = GetCurrentTransactionNestLevel();
	Assert(isSubXact ? (my_level > 1) : (my_level == 1));

	for (i = 0; i < num_guc_variables; i++)
	{
		struct config_generic *gconf = guc_variables[i];
		int			my_status = gconf->status;
		GucStack   *stack = gconf->stack;
		bool		useTentative;
		bool		changed;

		
		if (my_status == 0)
		{
			Assert(stack == NULL);
			continue;
		}
		
		Assert(stack != NULL && (my_status & GUC_HAVE_STACK));
		
		if (stack->nest_level < my_level)
			continue;
		Assert(stack->nest_level == my_level);

		
		gconf->status = stack->status;

		

		useTentative = isCommit && (my_status & GUC_HAVE_TENTATIVE) != 0;
		changed = false;

		switch (gconf->vartype)
		{
			case PGC_BOOL:
				{
					struct config_bool *conf = (struct config_bool *) gconf;
					bool		newval;
					GucSource	newsource;

					if (useTentative)
					{
						newval = conf->tentative_val;
						newsource = conf->gen.tentative_source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
					}
					else {
						newval = stack->value.boolval;
						newsource = stack->source;
						conf->tentative_val = stack->tentative_val.boolval;
						conf->gen.tentative_source = stack->tentative_source;
					}

					if (*conf->variable != newval)
					{
						if (conf->assign_hook)
							if (!(*conf->assign_hook) (newval, true, PGC_S_OVERRIDE))
								elog(LOG, "failed to commit %s", conf->gen.name);
						*conf->variable = newval;
						changed = true;
					}
					conf->gen.source = newsource;
					break;
				}
			case PGC_INT:
				{
					struct config_int *conf = (struct config_int *) gconf;
					int			newval;
					GucSource	newsource;

					if (useTentative)
					{
						newval = conf->tentative_val;
						newsource = conf->gen.tentative_source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
					}
					else {
						newval = stack->value.intval;
						newsource = stack->source;
						conf->tentative_val = stack->tentative_val.intval;
						conf->gen.tentative_source = stack->tentative_source;
					}

					if (*conf->variable != newval)
					{
						if (conf->assign_hook)
							if (!(*conf->assign_hook) (newval, true, PGC_S_OVERRIDE))
								elog(LOG, "failed to commit %s", conf->gen.name);
						*conf->variable = newval;
						changed = true;
					}
					conf->gen.source = newsource;
					break;
				}
			case PGC_REAL:
				{
					struct config_real *conf = (struct config_real *) gconf;
					double		newval;
					GucSource	newsource;

					if (useTentative)
					{
						newval = conf->tentative_val;
						newsource = conf->gen.tentative_source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
					}
					else {
						newval = stack->value.realval;
						newsource = stack->source;
						conf->tentative_val = stack->tentative_val.realval;
						conf->gen.tentative_source = stack->tentative_source;
					}

					if (*conf->variable != newval)
					{
						if (conf->assign_hook)
							if (!(*conf->assign_hook) (newval, true, PGC_S_OVERRIDE))
								elog(LOG, "failed to commit %s", conf->gen.name);
						*conf->variable = newval;
						changed = true;
					}
					conf->gen.source = newsource;
					break;
				}
			case PGC_STRING:
				{
					struct config_string *conf = (struct config_string *) gconf;
					char	   *newval;
					GucSource	newsource;

					if (useTentative)
					{
						newval = conf->tentative_val;
						newsource = conf->gen.tentative_source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
					}
					else {
						newval = stack->value.stringval;
						newsource = stack->source;
						set_string_field(conf, &conf->tentative_val, stack->tentative_val.stringval);
						conf->gen.tentative_source = stack->tentative_source;
					}

					if (*conf->variable != newval)
					{
						if (conf->assign_hook)
						{
							const char *newstr;

							newstr = (*conf->assign_hook) (newval, true, PGC_S_OVERRIDE);
							if (newstr == NULL)
								elog(LOG, "failed to commit %s", conf->gen.name);
							else if (newstr != newval)
							{
								
								newval = (char *) newstr;
							}
						}

						set_string_field(conf, conf->variable, newval);
						changed = true;
					}
					conf->gen.source = newsource;
					
					set_string_field(conf, &stack->value.stringval, NULL);
					set_string_field(conf, &stack->tentative_val.stringval, NULL);
					
					if (!isSubXact)
						set_string_field(conf, &conf->tentative_val, NULL);
					break;
				}
		}

		
		gconf->stack = stack->prev;
		pfree(stack);

		
		if (!isSubXact)
		{
			Assert(gconf->stack == NULL);
			gconf->status = 0;
		}

		
		if (changed && (gconf->flags & GUC_REPORT))
			ReportGUCOption(gconf);
	}

	
	if (!isSubXact)
		guc_dirty = false;
}



void BeginReportingGUCOptions(void)
{
	int			i;

	
	if (whereToSendOutput != DestRemote || PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
		return;

	reporting_enabled = true;

	
	for (i = 0; i < num_guc_variables; i++)
	{
		struct config_generic *conf = guc_variables[i];

		if (conf->flags & GUC_REPORT)
			ReportGUCOption(conf);
	}
}


static void ReportGUCOption(struct config_generic * record)
{
	if (reporting_enabled && (record->flags & GUC_REPORT))
	{
		char	   *val = _ShowOption(record);
		StringInfoData msgbuf;

		pq_beginmessage(&msgbuf, 'S');
		pq_sendstring(&msgbuf, record->name);
		pq_sendstring(&msgbuf, val);
		pq_endmessage(&msgbuf);

		pfree(val);
	}
}



static bool parse_bool(const char *value, bool *result)
{
	size_t		len = strlen(value);

	if (pg_strncasecmp(value, "true", len) == 0)
	{
		if (result)
			*result = true;
	}
	else if (pg_strncasecmp(value, "false", len) == 0)
	{
		if (result)
			*result = false;
	}

	else if (pg_strncasecmp(value, "yes", len) == 0)
	{
		if (result)
			*result = true;
	}
	else if (pg_strncasecmp(value, "no", len) == 0)
	{
		if (result)
			*result = false;
	}

	else if (pg_strcasecmp(value, "on") == 0)
	{
		if (result)
			*result = true;
	}
	else if (pg_strcasecmp(value, "off") == 0)
	{
		if (result)
			*result = false;
	}

	else if (pg_strcasecmp(value, "1") == 0)
	{
		if (result)
			*result = true;
	}
	else if (pg_strcasecmp(value, "0") == 0)
	{
		if (result)
			*result = false;
	}

	else {
		if (result)
			*result = false;	
		return false;
	}
	return true;
}




static bool parse_int(const char *value, int *result)
{
	long		val;
	char	   *endptr;

	errno = 0;
	val = strtol(value, &endptr, 0);
	if (endptr == value || *endptr != '\0' || errno == ERANGE   || val != (long) ((int32) val)



		)
	{
		if (result)
			*result = 0;		
		return false;
	}
	if (result)
		*result = (int) val;
	return true;
}




static bool parse_real(const char *value, double *result)
{
	double		val;
	char	   *endptr;

	errno = 0;
	val = strtod(value, &endptr);
	if (endptr == value || *endptr != '\0' || errno == ERANGE)
	{
		if (result)
			*result = 0;		
		return false;
	}
	if (result)
		*result = val;
	return true;
}



static const char * call_string_assign_hook(GucStringAssignHook assign_hook, char *newval, bool doit, GucSource source)

{
	const char *result;

	PG_TRY();
	{
		result = (*assign_hook) (newval, doit, source);
	}
	PG_CATCH();
	{
		free(newval);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return result;
}



bool set_config_option(const char *name, const char *value, GucContext context, GucSource source, bool isLocal, bool changeVal)


{
	struct config_generic *record;
	int			elevel;
	bool		makeDefault;

	if (context == PGC_SIGHUP || source == PGC_S_DEFAULT)
	{
		
		elevel = IsUnderPostmaster ? DEBUG2 : LOG;
	}
	else if (source == PGC_S_DATABASE || source == PGC_S_USER)
		elevel = INFO;
	else elevel = ERROR;

	record = find_option(name, elevel);
	if (record == NULL)
	{
		ereport(elevel, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("unrecognized configuration parameter \"%s\"", name)));

		return false;
	}

	
	switch (record->context)
	{
		case PGC_INTERNAL:
			if (context == PGC_SIGHUP)
				return true;
			if (context != PGC_INTERNAL)
			{
				ereport(elevel, (errcode(ERRCODE_CANT_CHANGE_RUNTIME_PARAM), errmsg("parameter \"%s\" cannot be changed", name)));


				return false;
			}
			break;
		case PGC_POSTMASTER:
			if (context == PGC_SIGHUP)
			{
				if (changeVal && !is_newvalue_equal(record, value))
					ereport(elevel, (errcode(ERRCODE_CANT_CHANGE_RUNTIME_PARAM), errmsg("parameter \"%s\" cannot be changed after server start; configuration file change ignored", name)));



				return true;
			}
			if (context != PGC_POSTMASTER)
			{
				ereport(elevel, (errcode(ERRCODE_CANT_CHANGE_RUNTIME_PARAM), errmsg("parameter \"%s\" cannot be changed after server start", name)));


				return false;
			}
			break;
		case PGC_SIGHUP:
			if (context != PGC_SIGHUP && context != PGC_POSTMASTER)
			{
				ereport(elevel, (errcode(ERRCODE_CANT_CHANGE_RUNTIME_PARAM), errmsg("parameter \"%s\" cannot be changed now", name)));


				return false;
			}

			
			break;
		case PGC_BACKEND:
			if (context == PGC_SIGHUP)
			{
				
				if (IsUnderPostmaster)
					return true;
			}
			else if (context != PGC_BACKEND && context != PGC_POSTMASTER)
			{
				ereport(elevel, (errcode(ERRCODE_CANT_CHANGE_RUNTIME_PARAM), errmsg("parameter \"%s\" cannot be set after connection start", name)));


				return false;
			}
			break;
		case PGC_SUSET:
			if (context == PGC_USERSET || context == PGC_BACKEND)
			{
				ereport(elevel, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to set parameter \"%s\"", name)));


				return false;
			}
			break;
		case PGC_USERSET:
			
			break;
	}

	
	makeDefault = changeVal && (source <= PGC_S_OVERRIDE) && (value != NULL);

	
	if (record->source > source)
	{
		if (changeVal && !makeDefault)
		{
			elog(DEBUG3, "\"%s\": setting ignored because previous source is higher priority", name);
			return true;
		}
		changeVal = false;
	}

	
	switch (record->vartype)
	{
		case PGC_BOOL:
			{
				struct config_bool *conf = (struct config_bool *) record;
				bool		newval;

				if (value)
				{
					if (!parse_bool(value, &newval))
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a Boolean value", name)));


						return false;
					}
				}
				else {
					newval = conf->reset_val;
					source = conf->gen.reset_source;
				}

				if (conf->assign_hook)
					if (!(*conf->assign_hook) (newval, changeVal, source))
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid value for parameter \"%s\": %d", name, (int) newval)));


						return false;
					}

				if (changeVal || makeDefault)
				{
					
					if (!makeDefault)
						push_old_value(&conf->gen);
					if (changeVal)
					{
						*conf->variable = newval;
						conf->gen.source = source;
					}
					if (makeDefault)
					{
						GucStack   *stack;

						if (conf->gen.reset_source <= source)
						{
							conf->reset_val = newval;
							conf->gen.reset_source = source;
						}
						for (stack = conf->gen.stack; stack; stack = stack->prev)
						{
							if (stack->source <= source)
							{
								stack->value.boolval = newval;
								stack->source = source;
							}
						}
					}
					else if (isLocal)
					{
						conf->gen.status |= GUC_HAVE_LOCAL;
						guc_dirty = true;
					}
					else {
						conf->tentative_val = newval;
						conf->gen.tentative_source = source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
						guc_dirty = true;
					}
				}
				break;
			}

		case PGC_INT:
			{
				struct config_int *conf = (struct config_int *) record;
				int			newval;

				if (value)
				{
					if (!parse_int(value, &newval))
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires an integer value", name)));


						return false;
					}
					if (newval < conf->min || newval > conf->max)
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("%d is outside the valid range for parameter \"%s\" (%d .. %d)", newval, name, conf->min, conf->max)));


						return false;
					}
				}
				else {
					newval = conf->reset_val;
					source = conf->gen.reset_source;
				}

				if (conf->assign_hook)
					if (!(*conf->assign_hook) (newval, changeVal, source))
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid value for parameter \"%s\": %d", name, newval)));


						return false;
					}

				if (changeVal || makeDefault)
				{
					
					if (!makeDefault)
						push_old_value(&conf->gen);
					if (changeVal)
					{
						*conf->variable = newval;
						conf->gen.source = source;
					}
					if (makeDefault)
					{
						GucStack   *stack;

						if (conf->gen.reset_source <= source)
						{
							conf->reset_val = newval;
							conf->gen.reset_source = source;
						}
						for (stack = conf->gen.stack; stack; stack = stack->prev)
						{
							if (stack->source <= source)
							{
								stack->value.intval = newval;
								stack->source = source;
							}
						}
					}
					else if (isLocal)
					{
						conf->gen.status |= GUC_HAVE_LOCAL;
						guc_dirty = true;
					}
					else {
						conf->tentative_val = newval;
						conf->gen.tentative_source = source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
						guc_dirty = true;
					}
				}
				break;
			}

		case PGC_REAL:
			{
				struct config_real *conf = (struct config_real *) record;
				double		newval;

				if (value)
				{
					if (!parse_real(value, &newval))
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a numeric value", name)));


						return false;
					}
					if (newval < conf->min || newval > conf->max)
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("%g is outside the valid range for parameter \"%s\" (%g .. %g)", newval, name, conf->min, conf->max)));


						return false;
					}
				}
				else {
					newval = conf->reset_val;
					source = conf->gen.reset_source;
				}

				if (conf->assign_hook)
					if (!(*conf->assign_hook) (newval, changeVal, source))
					{
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid value for parameter \"%s\": %g", name, newval)));


						return false;
					}

				if (changeVal || makeDefault)
				{
					
					if (!makeDefault)
						push_old_value(&conf->gen);
					if (changeVal)
					{
						*conf->variable = newval;
						conf->gen.source = source;
					}
					if (makeDefault)
					{
						GucStack   *stack;

						if (conf->gen.reset_source <= source)
						{
							conf->reset_val = newval;
							conf->gen.reset_source = source;
						}
						for (stack = conf->gen.stack; stack; stack = stack->prev)
						{
							if (stack->source <= source)
							{
								stack->value.realval = newval;
								stack->source = source;
							}
						}
					}
					else if (isLocal)
					{
						conf->gen.status |= GUC_HAVE_LOCAL;
						guc_dirty = true;
					}
					else {
						conf->tentative_val = newval;
						conf->gen.tentative_source = source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
						guc_dirty = true;
					}
				}
				break;
			}

		case PGC_STRING:
			{
				struct config_string *conf = (struct config_string *) record;
				char	   *newval;

				if (value)
				{
					newval = guc_strdup(elevel, value);
					if (newval == NULL)
						return false;
				}
				else if (conf->reset_val)
				{
					
					newval = guc_strdup(elevel, conf->reset_val);
					if (newval == NULL)
						return false;
					source = conf->gen.reset_source;
				}
				else {
					
					break;
				}

				if (conf->assign_hook)
				{
					const char *hookresult;

					
					hookresult = call_string_assign_hook(conf->assign_hook, newval, changeVal, source);


					if (hookresult == NULL)
					{
						free(newval);
						ereport(elevel, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid value for parameter \"%s\": \"%s\"", name, value ? value : "")));


						return false;
					}
					else if (hookresult != newval)
					{
						free(newval);

						
						newval = (char *) hookresult;
					}
				}

				if (changeVal || makeDefault)
				{
					
					if (!makeDefault)
						push_old_value(&conf->gen);
					if (changeVal)
					{
						set_string_field(conf, conf->variable, newval);
						conf->gen.source = source;
					}
					if (makeDefault)
					{
						GucStack   *stack;

						if (conf->gen.reset_source <= source)
						{
							set_string_field(conf, &conf->reset_val, newval);
							conf->gen.reset_source = source;
						}
						for (stack = conf->gen.stack; stack; stack = stack->prev)
						{
							if (stack->source <= source)
							{
								set_string_field(conf, &stack->value.stringval, newval);
								stack->source = source;
							}
						}
						
						if (!string_field_used(conf, newval))
							free(newval);
					}
					else if (isLocal)
					{
						conf->gen.status |= GUC_HAVE_LOCAL;
						guc_dirty = true;
					}
					else {
						set_string_field(conf, &conf->tentative_val, newval);
						conf->gen.tentative_source = source;
						conf->gen.status |= GUC_HAVE_TENTATIVE;
						guc_dirty = true;
					}
				}
				else free(newval);
				break;
			}
	}

	if (changeVal && (record->flags & GUC_REPORT))
		ReportGUCOption(record);

	return true;
}



void SetConfigOption(const char *name, const char *value, GucContext context, GucSource source)

{
	(void) set_config_option(name, value, context, source, false, true);
}




const char * GetConfigOption(const char *name)
{
	struct config_generic *record;
	static char buffer[256];

	record = find_option(name, ERROR);
	if (record == NULL)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("unrecognized configuration parameter \"%s\"", name)));

	if ((record->flags & GUC_SUPERUSER_ONLY) && !superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to examine \"%s\"", name)));


	switch (record->vartype)
	{
		case PGC_BOOL:
			return *((struct config_bool *) record)->variable ? "on" : "off";

		case PGC_INT:
			snprintf(buffer, sizeof(buffer), "%d", *((struct config_int *) record)->variable);
			return buffer;

		case PGC_REAL:
			snprintf(buffer, sizeof(buffer), "%g", *((struct config_real *) record)->variable);
			return buffer;

		case PGC_STRING:
			return *((struct config_string *) record)->variable;
	}
	return NULL;
}


const char * GetConfigOptionResetString(const char *name)
{
	struct config_generic *record;
	static char buffer[256];

	record = find_option(name, ERROR);
	if (record == NULL)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("unrecognized configuration parameter \"%s\"", name)));

	if ((record->flags & GUC_SUPERUSER_ONLY) && !superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to examine \"%s\"", name)));


	switch (record->vartype)
	{
		case PGC_BOOL:
			return ((struct config_bool *) record)->reset_val ? "on" : "off";

		case PGC_INT:
			snprintf(buffer, sizeof(buffer), "%d", ((struct config_int *) record)->reset_val);
			return buffer;

		case PGC_REAL:
			snprintf(buffer, sizeof(buffer), "%g", ((struct config_real *) record)->reset_val);
			return buffer;

		case PGC_STRING:
			return ((struct config_string *) record)->reset_val;
	}
	return NULL;
}


bool IsSuperuserConfigOption(const char *name)
{
	struct config_generic *record;

	record = find_option(name, ERROR);
	
	if (record == NULL)
		return false;
	return (record->context == PGC_SUSET);
}



char * flatten_set_variable_args(const char *name, List *args)
{
	struct config_generic *record;
	int			flags;
	StringInfoData buf;
	ListCell   *l;

	
	if (args == NIL)
		return NULL;

	
	record = find_option(name, ERROR);
	if (record == NULL)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("unrecognized configuration parameter \"%s\"", name)));


	flags = record->flags;

	
	if ((flags & GUC_LIST_INPUT) == 0 && list_length(args) != 1)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("SET %s takes only one argument", name)));


	initStringInfo(&buf);

	foreach(l, args)
	{
		A_Const    *arg = (A_Const *) lfirst(l);
		char	   *val;

		if (l != list_head(args))
			appendStringInfo(&buf, ", ");

		if (!IsA(arg, A_Const))
			elog(ERROR, "unrecognized node type: %d", (int) nodeTag(arg));

		switch (nodeTag(&arg->val))
		{
			case T_Integer:
				appendStringInfo(&buf, "%ld", intVal(&arg->val));
				break;
			case T_Float:
				
				appendStringInfoString(&buf, strVal(&arg->val));
				break;
			case T_String:
				val = strVal(&arg->val);
				if (arg->typename != NULL)
				{
					
					Datum		interval;
					char	   *intervalout;

					interval = DirectFunctionCall3(interval_in, CStringGetDatum(val), ObjectIdGetDatum(InvalidOid), Int32GetDatum(arg->typename->typmod));




					intervalout = DatumGetCString(DirectFunctionCall1(interval_out, interval));

					appendStringInfo(&buf, "INTERVAL '%s'", intervalout);
				}
				else {
					
					if (flags & GUC_LIST_QUOTE)
						appendStringInfoString(&buf, quote_identifier(val));
					else appendStringInfoString(&buf, val);
				}
				break;
			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(&arg->val));
				break;
		}
	}

	return buf.data;
}



void SetPGVariable(const char *name, List *args, bool is_local)
{
	char	   *argstring = flatten_set_variable_args(name, args);

	
	set_config_option(name, argstring, (superuser() ? PGC_SUSET : PGC_USERSET), PGC_S_SESSION, is_local, true);




}


Datum set_config_by_name(PG_FUNCTION_ARGS)
{
	char	   *name;
	char	   *value;
	char	   *new_value;
	bool		is_local;
	text	   *result_text;

	if (PG_ARGISNULL(0))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("SET requires parameter name")));


	
	name = DatumGetCString(DirectFunctionCall1(textout, PG_GETARG_DATUM(0)));

	
	if (PG_ARGISNULL(1))
		value = NULL;
	else value = DatumGetCString(DirectFunctionCall1(textout, PG_GETARG_DATUM(1)));

	
	if (PG_ARGISNULL(2))
		is_local = false;
	else is_local = PG_GETARG_BOOL(2);

	
	set_config_option(name, value, (superuser() ? PGC_SUSET : PGC_USERSET), PGC_S_SESSION, is_local, true);





	
	new_value = GetConfigOptionByName(name, NULL);

	
	result_text = DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(new_value)));

	
	PG_RETURN_TEXT_P(result_text);
}

static void define_custom_variable(struct config_generic * variable)
{
	const char *name = variable->name;
	const char **nameAddr = &name;
	const char *value;
	struct config_string *pHolder;
	struct config_generic **res = (struct config_generic **) bsearch( (void *) &nameAddr, (void *) guc_variables, num_guc_variables, sizeof(struct config_generic *), guc_var_compare);





	if (res == NULL)
	{
		add_guc_variable(variable, ERROR);
		return;
	}

	
	if (((*res)->flags & GUC_CUSTOM_PLACEHOLDER) == 0)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("attempt to redefine parameter \"%s\"", name)));


	Assert((*res)->vartype == PGC_STRING);
	pHolder = (struct config_string *) * res;

	
	*res = variable;

	value = *pHolder->variable;

	
	set_config_option(name, value, pHolder->gen.context, pHolder->gen.source, false, true);


	
	set_string_field(pHolder, pHolder->variable, NULL);
	set_string_field(pHolder, &pHolder->reset_val, NULL);
	set_string_field(pHolder, &pHolder->tentative_val, NULL);

	free(pHolder);
}

static void init_custom_variable(struct config_generic * gen, const char *name, const char *short_desc, const char *long_desc, GucContext context, enum config_type type)





{
	gen->name = guc_strdup(ERROR, name);
	gen->context = context;
	gen->group = CUSTOM_OPTIONS;
	gen->short_desc = short_desc;
	gen->long_desc = long_desc;
	gen->vartype = type;
}

void DefineCustomBoolVariable(const char *name, const char *short_desc, const char *long_desc, bool *valueAddr, GucContext context, GucBoolAssignHook assign_hook, GucShowHook show_hook)






{
	size_t		sz = sizeof(struct config_bool);
	struct config_bool *var = (struct config_bool *) guc_malloc(ERROR, sz);

	memset(var, 0, sz);
	init_custom_variable(&var->gen, name, short_desc, long_desc, context, PGC_BOOL);

	var->variable = valueAddr;
	var->reset_val = *valueAddr;
	var->assign_hook = assign_hook;
	var->show_hook = show_hook;
	define_custom_variable(&var->gen);
}

void DefineCustomIntVariable(const char *name, const char *short_desc, const char *long_desc, int *valueAddr, int minValue, int maxValue, GucContext context, GucIntAssignHook assign_hook, GucShowHook show_hook)








{
	size_t		sz = sizeof(struct config_int);
	struct config_int *var = (struct config_int *) guc_malloc(ERROR, sz);

	memset(var, 0, sz);
	init_custom_variable(&var->gen, name, short_desc, long_desc, context, PGC_INT);

	var->variable = valueAddr;
	var->reset_val = *valueAddr;
	var->min = minValue;
	var->max = maxValue;
	var->assign_hook = assign_hook;
	var->show_hook = show_hook;
	define_custom_variable(&var->gen);
}

void DefineCustomRealVariable(const char *name, const char *short_desc, const char *long_desc, double *valueAddr, double minValue, double maxValue, GucContext context, GucRealAssignHook assign_hook, GucShowHook show_hook)








{
	size_t		sz = sizeof(struct config_real);
	struct config_real *var = (struct config_real *) guc_malloc(ERROR, sz);

	memset(var, 0, sz);
	init_custom_variable(&var->gen, name, short_desc, long_desc, context, PGC_REAL);

	var->variable = valueAddr;
	var->reset_val = *valueAddr;
	var->min = minValue;
	var->max = maxValue;
	var->assign_hook = assign_hook;
	var->show_hook = show_hook;
	define_custom_variable(&var->gen);
}

void DefineCustomStringVariable(const char *name, const char *short_desc, const char *long_desc, char **valueAddr, GucContext context, GucStringAssignHook assign_hook, GucShowHook show_hook)






{
	size_t		sz = sizeof(struct config_string);
	struct config_string *var = (struct config_string *) guc_malloc(ERROR, sz);

	memset(var, 0, sz);
	init_custom_variable(&var->gen, name, short_desc, long_desc, context, PGC_STRING);

	var->variable = valueAddr;
	var->reset_val = *valueAddr;
	var->assign_hook = assign_hook;
	var->show_hook = show_hook;
	define_custom_variable(&var->gen);
}

void EmitWarningsOnPlaceholders(const char *className)
{
	struct config_generic **vars = guc_variables;
	struct config_generic **last = vars + num_guc_variables;

	int			nameLen = strlen(className);

	while (vars < last)
	{
		struct config_generic *var = *vars++;

		if ((var->flags & GUC_CUSTOM_PLACEHOLDER) != 0 && strncmp(className, var->name, nameLen) == 0 && var->name[nameLen] == GUC_QUALIFIER_SEPARATOR)

		{
			ereport(INFO, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("unrecognized configuration parameter \"%s\"", var->name)));

		}
	}
}



void GetPGVariable(const char *name, DestReceiver *dest)
{
	if (pg_strcasecmp(name, "all") == 0)
		ShowAllGUCConfig(dest);
	else ShowGUCConfigOption(name, dest);
}

TupleDesc GetPGVariableResultDesc(const char *name)
{
	TupleDesc	tupdesc;

	if (pg_strcasecmp(name, "all") == 0)
	{
		
		tupdesc = CreateTemplateTupleDesc(3, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "name", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "setting", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "description", TEXTOID, -1, 0);

	}
	else {
		const char *varname;

		
		(void) GetConfigOptionByName(name, &varname);

		
		tupdesc = CreateTemplateTupleDesc(1, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, varname, TEXTOID, -1, 0);
	}
	return tupdesc;
}


void ResetPGVariable(const char *name)
{
	if (pg_strcasecmp(name, "all") == 0)
		ResetAllOptions();
	else set_config_option(name, NULL, (superuser() ? PGC_SUSET : PGC_USERSET), PGC_S_SESSION, false, true);





}



static void ShowGUCConfigOption(const char *name, DestReceiver *dest)
{
	TupOutputState *tstate;
	TupleDesc	tupdesc;
	const char *varname;
	char	   *value;

	
	value = GetConfigOptionByName(name, &varname);

	
	tupdesc = CreateTemplateTupleDesc(1, false);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, varname, TEXTOID, -1, 0);

	
	tstate = begin_tup_output_tupdesc(dest, tupdesc);

	
	do_text_output_oneline(tstate, value);

	end_tup_output(tstate);
}


static void ShowAllGUCConfig(DestReceiver *dest)
{
	bool		am_superuser = superuser();
	int			i;
	TupOutputState *tstate;
	TupleDesc	tupdesc;
	char	   *values[3];

	
	tupdesc = CreateTemplateTupleDesc(3, false);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "name", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "setting", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "description", TEXTOID, -1, 0);


	
	tstate = begin_tup_output_tupdesc(dest, tupdesc);

	for (i = 0; i < num_guc_variables; i++)
	{
		struct config_generic *conf = guc_variables[i];

		if ((conf->flags & GUC_NO_SHOW_ALL) || ((conf->flags & GUC_SUPERUSER_ONLY) && !am_superuser))
			continue;

		
		values[0] = (char *) conf->name;
		values[1] = _ShowOption(conf);
		values[2] = (char *) conf->short_desc;

		
		do_tup_output(tstate, values);

		
		if (values[1] != NULL)
			pfree(values[1]);
	}

	end_tup_output(tstate);
}


char * GetConfigOptionByName(const char *name, const char **varname)
{
	struct config_generic *record;

	record = find_option(name, ERROR);
	if (record == NULL)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("unrecognized configuration parameter \"%s\"", name)));

	if ((record->flags & GUC_SUPERUSER_ONLY) && !superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to examine \"%s\"", name)));


	if (varname)
		*varname = record->name;

	return _ShowOption(record);
}


void GetConfigOptionByNum(int varnum, const char **values, bool *noshow)
{
	char		buffer[256];
	struct config_generic *conf;

	
	Assert((varnum >= 0) && (varnum < num_guc_variables));

	conf = guc_variables[varnum];

	if (noshow)
	{
		if ((conf->flags & GUC_NO_SHOW_ALL) || ((conf->flags & GUC_SUPERUSER_ONLY) && !superuser()))
			*noshow = true;
		else *noshow = false;
	}

	

	
	values[0] = conf->name;

	
	values[1] = _ShowOption(conf);

	
	values[2] = config_group_names[conf->group];

	
	values[3] = conf->short_desc;

	
	values[4] = conf->long_desc;

	
	values[5] = GucContext_Names[conf->context];

	
	values[6] = config_type_names[conf->vartype];

	
	values[7] = GucSource_Names[conf->source];

	
	switch (conf->vartype)
	{
		case PGC_BOOL:
			{
				
				values[8] = NULL;

				
				values[9] = NULL;
			}
			break;

		case PGC_INT:
			{
				struct config_int *lconf = (struct config_int *) conf;

				
				snprintf(buffer, sizeof(buffer), "%d", lconf->min);
				values[8] = pstrdup(buffer);

				
				snprintf(buffer, sizeof(buffer), "%d", lconf->max);
				values[9] = pstrdup(buffer);
			}
			break;

		case PGC_REAL:
			{
				struct config_real *lconf = (struct config_real *) conf;

				
				snprintf(buffer, sizeof(buffer), "%g", lconf->min);
				values[8] = pstrdup(buffer);

				
				snprintf(buffer, sizeof(buffer), "%g", lconf->max);
				values[9] = pstrdup(buffer);
			}
			break;

		case PGC_STRING:
			{
				
				values[8] = NULL;

				
				values[9] = NULL;
			}
			break;

		default:
			{
				

				
				values[8] = NULL;

				
				values[9] = NULL;
			}
			break;
	}
}


int GetNumConfigOptions(void)
{
	return num_guc_variables;
}


Datum show_config_by_name(PG_FUNCTION_ARGS)
{
	char	   *varname;
	char	   *varval;
	text	   *result_text;

	
	varname = DatumGetCString(DirectFunctionCall1(textout, PG_GETARG_DATUM(0)));

	
	varval = GetConfigOptionByName(varname, NULL);

	
	result_text = DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(varval)));

	
	PG_RETURN_TEXT_P(result_text);
}




Datum show_all_settings(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	TupleDesc	tupdesc;
	int			call_cntr;
	int			max_calls;
	AttInMetadata *attinmeta;
	MemoryContext oldcontext;

	
	if (SRF_IS_FIRSTCALL())
	{
		
		funcctx = SRF_FIRSTCALL_INIT();

		
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		
		tupdesc = CreateTemplateTupleDesc(NUM_PG_SETTINGS_ATTS, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "name", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "setting", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "category", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 4, "short_desc", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 5, "extra_desc", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 6, "context", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 7, "vartype", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 8, "source", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 9, "min_val", TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 10, "max_val", TEXTOID, -1, 0);

		
		attinmeta = TupleDescGetAttInMetadata(tupdesc);
		funcctx->attinmeta = attinmeta;

		
		funcctx->max_calls = GetNumConfigOptions();

		MemoryContextSwitchTo(oldcontext);
	}

	
	funcctx = SRF_PERCALL_SETUP();

	call_cntr = funcctx->call_cntr;
	max_calls = funcctx->max_calls;
	attinmeta = funcctx->attinmeta;

	if (call_cntr < max_calls)	
	{
		char	   *values[NUM_PG_SETTINGS_ATTS];
		bool		noshow;
		HeapTuple	tuple;
		Datum		result;

		
		do {
			GetConfigOptionByNum(call_cntr, (const char **) values, &noshow);
			if (noshow)
			{
				
				call_cntr = ++funcctx->call_cntr;

				
				if (call_cntr >= max_calls)
					SRF_RETURN_DONE(funcctx);
			}
		} while (noshow);

		
		tuple = BuildTupleFromCStrings(attinmeta, values);

		
		result = HeapTupleGetDatum(tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else {
		
		SRF_RETURN_DONE(funcctx);
	}
}

static char * _ShowOption(struct config_generic * record)
{
	char		buffer[256];
	const char *val;

	switch (record->vartype)
	{
		case PGC_BOOL:
			{
				struct config_bool *conf = (struct config_bool *) record;

				if (conf->show_hook)
					val = (*conf->show_hook) ();
				else val = *conf->variable ? "on" : "off";
			}
			break;

		case PGC_INT:
			{
				struct config_int *conf = (struct config_int *) record;

				if (conf->show_hook)
					val = (*conf->show_hook) ();
				else {
					snprintf(buffer, sizeof(buffer), "%d", *conf->variable);
					val = buffer;
				}
			}
			break;

		case PGC_REAL:
			{
				struct config_real *conf = (struct config_real *) record;

				if (conf->show_hook)
					val = (*conf->show_hook) ();
				else {
					snprintf(buffer, sizeof(buffer), "%g", *conf->variable);
					val = buffer;
				}
			}
			break;

		case PGC_STRING:
			{
				struct config_string *conf = (struct config_string *) record;

				if (conf->show_hook)
					val = (*conf->show_hook) ();
				else if (*conf->variable && **conf->variable)
					val = *conf->variable;
				else val = "unset";
			}
			break;

		default:
			
			val = "???";
			break;
	}

	return pstrdup(val);
}


static bool is_newvalue_equal(struct config_generic *record, const char *newvalue)
{
	switch (record->vartype)
	{
		case PGC_BOOL:
		{
			struct config_bool *conf = (struct config_bool *) record;
			bool newval;

			return parse_bool(newvalue, &newval) && *conf->variable == newval;
		}
		case PGC_INT:
		{
			struct config_int *conf = (struct config_int *) record;
			int newval;

			return parse_int(newvalue, &newval) && *conf->variable == newval;
		}
		case PGC_REAL:
		{
			struct config_real *conf = (struct config_real *) record;
			double newval;

			return parse_real(newvalue, &newval) && *conf->variable == newval;
		}
		case PGC_STRING:
		{
			struct config_string *conf = (struct config_string *) record;

			return strcmp(*conf->variable, newvalue) == 0;
		}
	}

	return false;
}





void write_nondefault_variables(GucContext context)
{
	int			i;
	int			elevel;
	FILE	   *fp;

	Assert(context == PGC_POSTMASTER || context == PGC_SIGHUP);

	elevel = (context == PGC_SIGHUP) ? LOG : ERROR;

	
	fp = AllocateFile(CONFIG_EXEC_PARAMS_NEW, "w");
	if (!fp)
	{
		ereport(elevel, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", CONFIG_EXEC_PARAMS_NEW)));


		return;
	}

	for (i = 0; i < num_guc_variables; i++)
	{
		struct config_generic *gconf = guc_variables[i];

		if (gconf->source != PGC_S_DEFAULT)
		{
			fprintf(fp, "%s", gconf->name);
			fputc(0, fp);

			switch (gconf->vartype)
			{
				case PGC_BOOL:
					{
						struct config_bool *conf = (struct config_bool *) gconf;

						if (*conf->variable == 0)
							fprintf(fp, "false");
						else fprintf(fp, "true");
					}
					break;

				case PGC_INT:
					{
						struct config_int *conf = (struct config_int *) gconf;

						fprintf(fp, "%d", *conf->variable);
					}
					break;

				case PGC_REAL:
					{
						struct config_real *conf = (struct config_real *) gconf;

						
						fprintf(fp, "%f", *conf->variable);
					}
					break;

				case PGC_STRING:
					{
						struct config_string *conf = (struct config_string *) gconf;

						fprintf(fp, "%s", *conf->variable);
					}
					break;
			}

			fputc(0, fp);

			fwrite(&gconf->source, sizeof(gconf->source), 1, fp);
		}
	}

	if (FreeFile(fp))
	{
		ereport(elevel, (errcode_for_file_access(), errmsg("could not write to file \"%s\": %m", CONFIG_EXEC_PARAMS_NEW)));


		return;
	}

	
	rename(CONFIG_EXEC_PARAMS_NEW, CONFIG_EXEC_PARAMS);
}



static char * read_string_with_null(FILE *fp)
{
	int			i = 0, ch, maxlen = 256;

	char	   *str = NULL;

	do {
		if ((ch = fgetc(fp)) == EOF)
		{
			if (i == 0)
				return NULL;
			else elog(FATAL, "invalid format of exec config params file");
		}
		if (i == 0)
			str = guc_malloc(FATAL, maxlen);
		else if (i == maxlen)
			str = guc_realloc(FATAL, str, maxlen *= 2);
		str[i++] = ch;
	} while (ch != 0);

	return str;
}



void read_nondefault_variables(void)
{
	FILE	   *fp;
	char	   *varname, *varvalue;
	int			varsource;

	
	fp = AllocateFile(CONFIG_EXEC_PARAMS, "r");
	if (!fp)
	{
		
		if (errno != ENOENT)
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not read from file \"%s\": %m", CONFIG_EXEC_PARAMS)));


		return;
	}

	for (;;)
	{
		struct config_generic *record;

		if ((varname = read_string_with_null(fp)) == NULL)
			break;

		if ((record = find_option(varname, FATAL)) == NULL)
			elog(FATAL, "failed to locate variable %s in exec config params file", varname);
		if ((varvalue = read_string_with_null(fp)) == NULL)
			elog(FATAL, "invalid format of exec config params file");
		if (fread(&varsource, sizeof(varsource), 1, fp) == 0)
			elog(FATAL, "invalid format of exec config params file");

		(void) set_config_option(varname, varvalue, record->context, varsource, false, true);
		free(varname);
		free(varvalue);
	}

	FreeFile(fp);
}




void ParseLongOption(const char *string, char **name, char **value)
{
	size_t		equal_pos;
	char	   *cp;

	AssertArg(string);
	AssertArg(name);
	AssertArg(value);

	equal_pos = strcspn(string, "=");

	if (string[equal_pos] == '=')
	{
		*name = guc_malloc(FATAL, equal_pos + 1);
		strncpy(*name, string, equal_pos);
		(*name)[equal_pos] = '\0';

		*value = guc_strdup(FATAL, &string[equal_pos + 1]);
	}
	else {
		
		*name = guc_strdup(FATAL, string);
		*value = NULL;
	}

	for (cp = *name; *cp; cp++)
		if (*cp == '-')
			*cp = '_';
}



void ProcessGUCArray(ArrayType *array, GucSource source)
{
	int			i;

	Assert(array != NULL);
	Assert(ARR_ELEMTYPE(array) == TEXTOID);
	Assert(ARR_NDIM(array) == 1);
	Assert(ARR_LBOUND(array)[0] == 1);
	Assert(source == PGC_S_DATABASE || source == PGC_S_USER);

	for (i = 1; i <= ARR_DIMS(array)[0]; i++)
	{
		Datum		d;
		bool		isnull;
		char	   *s;
		char	   *name;
		char	   *value;

		d = array_ref(array, 1, &i, -1  , -1  , false  , 'i'  , &isnull);





		if (isnull)
			continue;

		s = DatumGetCString(DirectFunctionCall1(textout, d));

		ParseLongOption(s, &name, &value);
		if (!value)
		{
			ereport(WARNING, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("could not parse setting for parameter \"%s\"", name)));

			free(name);
			continue;
		}

		
		SetConfigOption(name, value, PGC_SUSET, source);

		free(name);
		if (value)
			free(value);
	}
}



ArrayType * GUCArrayAdd(ArrayType *array, const char *name, const char *value)
{
	const char *varname;
	Datum		datum;
	char	   *newval;
	ArrayType  *a;

	Assert(name);
	Assert(value);

	
	set_config_option(name, value, superuser() ? PGC_SUSET : PGC_USERSET, PGC_S_TEST, false, false);


	
	(void) GetConfigOptionByName(name, &varname);
	name = varname;

	newval = palloc(strlen(name) + 1 + strlen(value) + 1);
	sprintf(newval, "%s=%s", name, value);
	datum = DirectFunctionCall1(textin, CStringGetDatum(newval));

	if (array)
	{
		int			index;
		bool		isnull;
		int			i;

		Assert(ARR_ELEMTYPE(array) == TEXTOID);
		Assert(ARR_NDIM(array) == 1);
		Assert(ARR_LBOUND(array)[0] == 1);

		index = ARR_DIMS(array)[0] + 1; 

		for (i = 1; i <= ARR_DIMS(array)[0]; i++)
		{
			Datum		d;
			char	   *current;

			d = array_ref(array, 1, &i, -1  , -1  , false  , 'i'  , &isnull);




			if (isnull)
				continue;
			current = DatumGetCString(DirectFunctionCall1(textout, d));
			if (strncmp(current, newval, strlen(name) + 1) == 0)
			{
				index = i;
				break;
			}
		}

		a = array_set(array, 1, &index, datum, false, -1  , -1  , false  , 'i'  );





	}
	else a = construct_array(&datum, 1, TEXTOID, -1, false, 'i');



	return a;
}



ArrayType * GUCArrayDelete(ArrayType *array, const char *name)
{
	const char *varname;
	ArrayType  *newarray;
	int			i;
	int			index;

	Assert(name);

	
	set_config_option(name, NULL, superuser() ? PGC_SUSET : PGC_USERSET, PGC_S_TEST, false, false);


	
	(void) GetConfigOptionByName(name, &varname);
	name = varname;

	
	if (!array)
		return NULL;

	newarray = NULL;
	index = 1;

	for (i = 1; i <= ARR_DIMS(array)[0]; i++)
	{
		Datum		d;
		char	   *val;
		bool		isnull;

		d = array_ref(array, 1, &i, -1  , -1  , false  , 'i'  , &isnull);




		if (isnull)
			continue;
		val = DatumGetCString(DirectFunctionCall1(textout, d));

		
		if (strncmp(val, name, strlen(name)) == 0 && val[strlen(name)] == '=')
			continue;

		
		if (newarray)
		{
			newarray = array_set(newarray, 1, &index, d, false, -1  , -1  , false  , 'i'  );





		}
		else newarray = construct_array(&d, 1, TEXTOID, -1, false, 'i');



		index++;
	}

	return newarray;
}




static const char * assign_log_destination(const char *value, bool doit, GucSource source)
{
	char	   *rawstring;
	List	   *elemlist;
	ListCell   *l;
	int			newlogdest = 0;

	
	rawstring = pstrdup(value);

	
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		
		pfree(rawstring);
		list_free(elemlist);
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid list syntax for parameter \"log_destination\"")));

		return NULL;
	}

	foreach(l, elemlist)
	{
		char	   *tok = (char *) lfirst(l);

		if (pg_strcasecmp(tok, "stderr") == 0)
			newlogdest |= LOG_DESTINATION_STDERR;

		else if (pg_strcasecmp(tok, "syslog") == 0)
			newlogdest |= LOG_DESTINATION_SYSLOG;


		else if (pg_strcasecmp(tok, "eventlog") == 0)
			newlogdest |= LOG_DESTINATION_EVENTLOG;

		else {
			if (source >= PGC_S_INTERACTIVE)
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("unrecognized \"log_destination\" key word: \"%s\"", tok)));


			pfree(rawstring);
			list_free(elemlist);
			return NULL;
		}
	}

	if (doit)
		Log_destination = newlogdest;

	pfree(rawstring);
	list_free(elemlist);

	return value;
}



static const char * assign_syslog_facility(const char *facility, bool doit, GucSource source)
{
	int			syslog_fac;

	if (pg_strcasecmp(facility, "LOCAL0") == 0)
		syslog_fac = LOG_LOCAL0;
	else if (pg_strcasecmp(facility, "LOCAL1") == 0)
		syslog_fac = LOG_LOCAL1;
	else if (pg_strcasecmp(facility, "LOCAL2") == 0)
		syslog_fac = LOG_LOCAL2;
	else if (pg_strcasecmp(facility, "LOCAL3") == 0)
		syslog_fac = LOG_LOCAL3;
	else if (pg_strcasecmp(facility, "LOCAL4") == 0)
		syslog_fac = LOG_LOCAL4;
	else if (pg_strcasecmp(facility, "LOCAL5") == 0)
		syslog_fac = LOG_LOCAL5;
	else if (pg_strcasecmp(facility, "LOCAL6") == 0)
		syslog_fac = LOG_LOCAL6;
	else if (pg_strcasecmp(facility, "LOCAL7") == 0)
		syslog_fac = LOG_LOCAL7;
	else return NULL;

	if (doit)
	{
		syslog_facility = syslog_fac;
		set_syslog_parameters(syslog_ident_str ? syslog_ident_str : "postgres", syslog_facility);
	}

	return facility;
}

static const char * assign_syslog_ident(const char *ident, bool doit, GucSource source)
{
	if (doit)
		set_syslog_parameters(ident, syslog_facility);

	return ident;
}



static const char * assign_defaultxactisolevel(const char *newval, bool doit, GucSource source)
{
	if (pg_strcasecmp(newval, "serializable") == 0)
	{
		if (doit)
			DefaultXactIsoLevel = XACT_SERIALIZABLE;
	}
	else if (pg_strcasecmp(newval, "repeatable read") == 0)
	{
		if (doit)
			DefaultXactIsoLevel = XACT_REPEATABLE_READ;
	}
	else if (pg_strcasecmp(newval, "read committed") == 0)
	{
		if (doit)
			DefaultXactIsoLevel = XACT_READ_COMMITTED;
	}
	else if (pg_strcasecmp(newval, "read uncommitted") == 0)
	{
		if (doit)
			DefaultXactIsoLevel = XACT_READ_UNCOMMITTED;
	}
	else return NULL;
	return newval;
}

static const char * assign_log_min_messages(const char *newval, bool doit, GucSource source)

{
	return (assign_msglvl(&log_min_messages, newval, doit, source));
}

static const char * assign_client_min_messages(const char *newval, bool doit, GucSource source)
{
	return (assign_msglvl(&client_min_messages, newval, doit, source));
}

static const char * assign_min_error_statement(const char *newval, bool doit, GucSource source)
{
	return (assign_msglvl(&log_min_error_statement, newval, doit, source));
}

static const char * assign_msglvl(int *var, const char *newval, bool doit, GucSource source)
{
	if (pg_strcasecmp(newval, "debug") == 0)
	{
		if (doit)
			(*var) = DEBUG2;
	}
	else if (pg_strcasecmp(newval, "debug5") == 0)
	{
		if (doit)
			(*var) = DEBUG5;
	}
	else if (pg_strcasecmp(newval, "debug4") == 0)
	{
		if (doit)
			(*var) = DEBUG4;
	}
	else if (pg_strcasecmp(newval, "debug3") == 0)
	{
		if (doit)
			(*var) = DEBUG3;
	}
	else if (pg_strcasecmp(newval, "debug2") == 0)
	{
		if (doit)
			(*var) = DEBUG2;
	}
	else if (pg_strcasecmp(newval, "debug1") == 0)
	{
		if (doit)
			(*var) = DEBUG1;
	}
	else if (pg_strcasecmp(newval, "log") == 0)
	{
		if (doit)
			(*var) = LOG;
	}

	
	else if (pg_strcasecmp(newval, "info") == 0)
	{
		if (doit)
			(*var) = INFO;
	}
	else if (pg_strcasecmp(newval, "notice") == 0)
	{
		if (doit)
			(*var) = NOTICE;
	}
	else if (pg_strcasecmp(newval, "warning") == 0)
	{
		if (doit)
			(*var) = WARNING;
	}
	else if (pg_strcasecmp(newval, "error") == 0)
	{
		if (doit)
			(*var) = ERROR;
	}
	
	else if (pg_strcasecmp(newval, "fatal") == 0)
	{
		if (doit)
			(*var) = FATAL;
	}
	else if (pg_strcasecmp(newval, "panic") == 0)
	{
		if (doit)
			(*var) = PANIC;
	}
	else return NULL;
	return newval;				
}

static const char * assign_log_error_verbosity(const char *newval, bool doit, GucSource source)
{
	if (pg_strcasecmp(newval, "terse") == 0)
	{
		if (doit)
			Log_error_verbosity = PGERROR_TERSE;
	}
	else if (pg_strcasecmp(newval, "default") == 0)
	{
		if (doit)
			Log_error_verbosity = PGERROR_DEFAULT;
	}
	else if (pg_strcasecmp(newval, "verbose") == 0)
	{
		if (doit)
			Log_error_verbosity = PGERROR_VERBOSE;
	}
	else return NULL;
	return newval;				
}

static const char * assign_log_statement(const char *newval, bool doit, GucSource source)
{
	if (pg_strcasecmp(newval, "none") == 0)
	{
		if (doit)
			log_statement = LOGSTMT_NONE;
	}
	else if (pg_strcasecmp(newval, "ddl") == 0)
	{
		if (doit)
			log_statement = LOGSTMT_DDL;
	}
	else if (pg_strcasecmp(newval, "mod") == 0)
	{
		if (doit)
			log_statement = LOGSTMT_MOD;
	}
	else if (pg_strcasecmp(newval, "all") == 0)
	{
		if (doit)
			log_statement = LOGSTMT_ALL;
	}
	else return NULL;
	return newval;				
}

static const char * show_num_temp_buffers(void)
{
	
	static char nbuf[32];

	sprintf(nbuf, "%d", NLocBuffer ? NLocBuffer : num_temp_buffers);
	return nbuf;
}

static bool assign_phony_autocommit(bool newval, bool doit, GucSource source)
{
	if (!newval)
	{
		if (doit && source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("SET AUTOCOMMIT TO OFF is no longer supported")));

		return false;
	}
	return true;
}

static const char * assign_custom_variable_classes(const char *newval, bool doit, GucSource source)
{
	
	bool		hasSpaceAfterToken = false;
	const char *cp = newval;
	int			symLen = 0;
	int			c;
	StringInfoData buf;

	initStringInfo(&buf);
	while ((c = *cp++) != 0)
	{
		if (isspace(c))
		{
			if (symLen > 0)
				hasSpaceAfterToken = true;
			continue;
		}

		if (c == ',')
		{
			hasSpaceAfterToken = false;
			if (symLen > 0)
			{
				symLen = 0;
				appendStringInfoChar(&buf, ',');
			}
			continue;
		}

		if (hasSpaceAfterToken || !isalnum(c))
		{
			
			ereport(LOG, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("invalid syntax for \"custom_variable_classes\": \"%s\"", newval)));

			pfree(buf.data);
			return NULL;
		}
		symLen++;
		appendStringInfoChar(&buf, (char) c);
	}

	
	if (symLen == 0 && buf.len > 0)
		buf.data[--buf.len] = '\0';

	if (buf.len == 0)
		newval = NULL;
	else if (doit)
		newval = strdup(buf.data);

	pfree(buf.data);
	return newval;
}

static bool assign_debug_assertions(bool newval, bool doit, GucSource source)
{

	if (newval)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("assertion checking is not supported by this build")));


	return true;
}

static bool assign_ssl(bool newval, bool doit, GucSource source)
{

	if (newval)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("SSL is not supported by this build")));


	return true;
}

static bool assign_stage_log_stats(bool newval, bool doit, GucSource source)
{
	if (newval && log_statement_stats)
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("cannot enable parameter when \"log_statement_stats\" is true")));

		
		else if (source != PGC_S_OVERRIDE)
			return false;
	}
	return true;
}

static bool assign_log_stats(bool newval, bool doit, GucSource source)
{
	if (newval && (log_parser_stats || log_planner_stats || log_executor_stats))
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("cannot enable \"log_statement_stats\" when " "\"log_parser_stats\", \"log_planner_stats\", " "or \"log_executor_stats\" is true")));



		
		else if (source != PGC_S_OVERRIDE)
			return false;
	}
	return true;
}

static bool assign_transaction_read_only(bool newval, bool doit, GucSource source)
{
	
	if (newval == false && XactReadOnly && IsSubTransaction())
	{
		if (source >= PGC_S_INTERACTIVE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("cannot set transaction read-write mode inside a read-only transaction")));

		
		else if (source != PGC_S_OVERRIDE)
			return false;
	}
	return true;
}

static const char * assign_canonical_path(const char *newval, bool doit, GucSource source)
{
	if (doit)
	{
		char	   *canon_val = guc_strdup(ERROR, newval);

		canonicalize_path(canon_val);
		return canon_val;
	}
	else return newval;
}

static bool assign_tcp_keepalives_idle(int newval, bool doit, GucSource source)
{
	if (doit)
		return (pq_setkeepalivesidle(newval, MyProcPort) == STATUS_OK);

	return true;
}

static const char * show_tcp_keepalives_idle(void)
{
	static char nbuf[16];

	snprintf(nbuf, sizeof(nbuf), "%d", pq_getkeepalivesidle(MyProcPort));
	return nbuf;
}

static bool assign_tcp_keepalives_interval(int newval, bool doit, GucSource source)
{
	if (doit)
		return (pq_setkeepalivesinterval(newval, MyProcPort) == STATUS_OK);

	return true;
}

static const char * show_tcp_keepalives_interval(void)
{
	static char nbuf[16];

	snprintf(nbuf, sizeof(nbuf), "%d", pq_getkeepalivesinterval(MyProcPort));
	return nbuf;
}

static bool assign_tcp_keepalives_count(int newval, bool doit, GucSource source)
{
	if (doit)
		return (pq_setkeepalivescount(newval, MyProcPort) == STATUS_OK);

	return true;
}

static const char * show_tcp_keepalives_count(void)
{
	static char nbuf[16];

	snprintf(nbuf, sizeof(nbuf), "%d", pq_getkeepalivescount(MyProcPort));
	return nbuf;
}


