






































struct mosquitto_db int_db;

bool flag_reload = false;

bool flag_db_backup = false;

bool flag_tree_print = false;
int run;


int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;


void handle_sigint(int signal);
void handle_sigusr1(int signal);
void handle_sigusr2(int signal);

struct mosquitto_db *_mosquitto_get_db(void)
{
	return &int_db;
}


int drop_privileges(struct mqtt3_config *config, bool temporary)
{

	struct passwd *pwd;
	char err[256];
	int rc;

	if(geteuid() == 0){
		if(config->user && strcmp(config->user, "root")){
			pwd = getpwnam(config->user);
			if(!pwd){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid user '%s'.", config->user);
				return 1;
			}
			if(initgroups(config->user, pwd->pw_gid) == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting groups whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = setegid(pwd->pw_gid);
			}else{
				rc = setgid(pwd->pw_gid);
			}
			if(rc == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = seteuid(pwd->pw_uid);
			}else{
				rc = setuid(pwd->pw_uid);
			}
			if(rc == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst dropping privileges: %s.", err);
				return 1;
			}
		}
		if(geteuid() == 0 || getegid() == 0){
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Mosquitto should not be run as root/administrator.");
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int restore_privileges(void)
{

	char err[256];
	int rc;

	if(getuid() == 0){
		rc = setegid(0);
		if(rc == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst restoring privileges: %s.", err);
			return 1;
		}
		rc = seteuid(0);
		if(rc == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst restoring privileges: %s.", err);
			return 1;
		}
	}

	return MOSQ_ERR_SUCCESS;
}



void handle_sighup(int signal)
{
	flag_reload = true;
}



void handle_sigint(int signal)
{
	run = 0;
}


void handle_sigusr1(int signal)
{

	flag_db_backup = true;

}

void mosquitto__daemonise(void)
{

	char err[256];
	pid_t pid;

	pid = fork();
	if(pid < 0){
		strerror_r(errno, err, 256);
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error in fork: %s", err);
		exit(1);
	}
	if(pid > 0){
		exit(0);
	}
	if(setsid() < 0){
		strerror_r(errno, err, 256);
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error in setsid: %s", err);
		exit(1);
	}

	assert(freopen("/dev/null", "r", stdin));
	assert(freopen("/dev/null", "w", stdout));
	assert(freopen("/dev/null", "w", stderr));

	_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Can't start in daemon mode in Windows.");

}


void handle_sigusr2(int signal)
{
	flag_tree_print = true;
}

int main(int argc, char *argv[])
{
	mosq_sock_t *listensock = NULL;
	int listensock_count = 0;
	int listensock_index = 0;
	struct mqtt3_config config;

	char buf[1024];

	int i, j;
	FILE *pid;
	int listener_max;
	int rc;

	SYSTEMTIME st;

	struct timeval tv;

	struct mosquitto *ctxt, *ctxt_tmp;


	if(argc == 2){
		if(!strcmp(argv[1], "run")){
			service_run();
			return 0;
		}else if(!strcmp(argv[1], "install")){
			service_install();
			return 0;
		}else if(!strcmp(argv[1], "uninstall")){
			service_uninstall();
			return 0;
		}
	}




	GetSystemTime(&st);
	srand(st.wSecond + st.wMilliseconds);

	gettimeofday(&tv, NULL);
	srand(tv.tv_sec + tv.tv_usec);


	memset(&int_db, 0, sizeof(struct mosquitto_db));

	_mosquitto_net_init();

	mqtt3_config_init(&config);
	rc = mqtt3_config_parse_args(&config, argc, argv);
	if(rc != MOSQ_ERR_SUCCESS) return rc;
	int_db.config = &config;

	if(config.daemon){
		mosquitto__daemonise();
	}

	if(config.daemon && config.pid_file){
		pid = _mosquitto_fopen(config.pid_file, "wt");
		if(pid){
			fprintf(pid, "%d", getpid());
			fclose(pid);
		}else{
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to write pid file.");
			return 1;
		}
	}

	rc = mqtt3_db_open(&config, &int_db);
	if(rc != MOSQ_ERR_SUCCESS){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Couldn't open database.");
		return rc;
	}

	
	if(mqtt3_log_init(&config)){
		rc = 1;
		return rc;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s (build date %s) starting", VERSION, TIMESTAMP);
	if(config.config_file){
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Config loaded from %s.", config.config_file);
	}else{
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Using default config.");
	}

	rc = mosquitto_security_module_init(&int_db);
	if(rc) return rc;
	rc = mosquitto_security_init(&int_db, false);
	if(rc) return rc;


	if(config.sys_interval > 0){
		
		snprintf(buf, 1024, "mosquitto version %s", VERSION);
		mqtt3_db_messages_easy_queue(&int_db, NULL, "$SYS/broker/version", 2, strlen(buf), buf, 1);
		snprintf(buf, 1024, "%s", TIMESTAMP);
		mqtt3_db_messages_easy_queue(&int_db, NULL, "$SYS/broker/timestamp", 2, strlen(buf), buf, 1);
	}


	listener_max = -1;
	listensock_index = 0;
	for(i=0; i<config.listener_count; i++){
		if(config.listeners[i].protocol == mp_mqtt){
			if(mqtt3_socket_listen(&config.listeners[i])){
				mqtt3_db_close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			listensock_count += config.listeners[i].sock_count;
			listensock = _mosquitto_realloc(listensock, sizeof(mosq_sock_t)*listensock_count);
			if(!listensock){
				mqtt3_db_close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			for(j=0; j<config.listeners[i].sock_count; j++){
				if(config.listeners[i].socks[j] == INVALID_SOCKET){
					mqtt3_db_close(&int_db);
					if(config.pid_file){
						remove(config.pid_file);
					}
					return 1;
				}
				listensock[listensock_index] = config.listeners[i].socks[j];
				if(listensock[listensock_index] > listener_max){
					listener_max = listensock[listensock_index];
				}
				listensock_index++;
			}
		}else if(config.listeners[i].protocol == mp_websockets){

			config.listeners[i].ws_context = mosq_websockets_init(&config.listeners[i], config.websockets_log_level);
			if(!config.listeners[i].ws_context){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create websockets listener on port %d.", config.listeners[i].port);
				return 1;
			}

		}
	}

	rc = drop_privileges(&config, false);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

	signal(SIGHUP, handle_sighup);


	signal(SIGUSR1, handle_sigusr1);
	signal(SIGUSR2, handle_sigusr2);
	signal(SIGPIPE, SIG_IGN);



	for(i=0; i<config.bridge_count; i++){
		if(mqtt3_bridge_new(&int_db, &(config.bridges[i]))){
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.",  config.bridges[i].name);
		}
	}


	run = 1;
	rc = mosquitto_main_loop(&int_db, listensock, listensock_count, listener_max);

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s terminating", VERSION);
	mqtt3_log_close(&config);


	if(config.persistence){
		mqtt3_db_backup(&int_db, true);
	}



	for(i=0; i<int_db.config->listener_count; i++){
		if(int_db.config->listeners[i].ws_context){
			libwebsocket_context_destroy(int_db.config->listeners[i].ws_context);
		}
		if(int_db.config->listeners[i].ws_protocol){
			_mosquitto_free(int_db.config->listeners[i].ws_protocol);
		}
	}


	HASH_ITER(hh_id, int_db.contexts_by_id, ctxt, ctxt_tmp){

		if(!ctxt->wsi){
			mqtt3_context_cleanup(&int_db, ctxt, true);
		}

		mqtt3_context_cleanup(&int_db, ctxt, true);

	}
	HASH_ITER(hh_sock, int_db.contexts_by_sock, ctxt, ctxt_tmp){
		mqtt3_context_cleanup(&int_db, ctxt, true);
	}

	for(i=0; i<int_db.bridge_count; i++){
		if(int_db.bridges[i]){
			mqtt3_context_cleanup(&int_db, int_db.bridges[i], true);
		}
	}
	if(int_db.bridges){
		_mosquitto_free(int_db.bridges);
	}

	mosquitto__free_disused_contexts(&int_db);

	mqtt3_db_close(&int_db);

	if(listensock){
		for(i=0; i<listensock_count; i++){
			if(listensock[i] != INVALID_SOCKET){

				close(listensock[i]);

				closesocket(listensock[i]);

			}
		}
		_mosquitto_free(listensock);
	}

	mosquitto_security_module_cleanup(&int_db);

	if(config.pid_file){
		remove(config.pid_file);
	}

	mqtt3_config_cleanup(int_db.config);
	_mosquitto_net_cleanup();

	return rc;
}


int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char **argv;
	int argc = 1;
	char *token;
	char *saveptr = NULL;
	int rc;

	argv = _mosquitto_malloc(sizeof(char *)*1);
	argv[0] = "mosquitto";
	token = strtok_r(lpCmdLine, " ", &saveptr);
	while(token){
		argc++;
		argv = _mosquitto_realloc(argv, sizeof(char *)*argc);
		if(!argv){
			fprintf(stderr, "Error: Out of memory.\n");
			return MOSQ_ERR_NOMEM;
		}
		argv[argc-1] = token;
		token = strtok_r(NULL, " ", &saveptr);
	}
	rc = main(argc, argv);
	_mosquitto_free(argv);
	return rc;
}

