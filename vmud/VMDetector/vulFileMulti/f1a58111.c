
















extern struct mosquitto_db int_db;


HANDLE syslog_h;





static int log_destinations = MQTT3_LOG_STDERR;
static int log_priorities = MOSQ_LOG_ERR | MOSQ_LOG_WARNING | MOSQ_LOG_NOTICE | MOSQ_LOG_INFO;

int mqtt3_log_init(struct mqtt3_config *config)
{
	int rc = 0;

	log_priorities = config->log_type;
	log_destinations = config->log_dest;

	if(log_destinations & MQTT3_LOG_SYSLOG){

		openlog("mosquitto", LOG_PID|LOG_CONS, config->log_facility);

		syslog_h = OpenEventLog(NULL, "mosquitto");

	}

	if(log_destinations & MQTT3_LOG_FILE){
		if(drop_privileges(config, true)){
			return 1;
		}
		config->log_fptr = _mosquitto_fopen(config->log_file, "at");
		if(!config->log_fptr){
			log_destinations = MQTT3_LOG_STDERR;
			log_priorities = MOSQ_LOG_ERR;
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open log file %s for writing.", config->log_file);
			return MOSQ_ERR_INVAL;
		}
		restore_privileges();
	}
	return rc;
}

int mqtt3_log_close(struct mqtt3_config *config)
{
	if(log_destinations & MQTT3_LOG_SYSLOG){

		closelog();

		CloseEventLog(syslog_h);

	}
	if(log_destinations & MQTT3_LOG_FILE){
		if(config->log_fptr){
			fclose(config->log_fptr);
			config->log_fptr = NULL;
		}
	}

	
	return MOSQ_ERR_SUCCESS;
}

int _mosquitto_log_vprintf(struct mosquitto *mosq, int priority, const char *fmt, va_list va)
{
	char *s;
	char *st;
	int len;

	char *sp;

	const char *topic;
	int syslog_priority;
	time_t now = time(NULL);
	static time_t last_flush = 0;

	if((log_priorities & priority) && log_destinations != MQTT3_LOG_NONE){
		switch(priority){
			case MOSQ_LOG_SUBSCRIBE:
				topic = "$SYS/broker/log/M/subscribe";

				syslog_priority = LOG_NOTICE;

				syslog_priority = EVENTLOG_INFORMATION_TYPE;

				break;
			case MOSQ_LOG_UNSUBSCRIBE:
				topic = "$SYS/broker/log/M/unsubscribe";

				syslog_priority = LOG_NOTICE;

				syslog_priority = EVENTLOG_INFORMATION_TYPE;

				break;
			case MOSQ_LOG_DEBUG:
				topic = "$SYS/broker/log/D";

				syslog_priority = LOG_DEBUG;

				syslog_priority = EVENTLOG_INFORMATION_TYPE;

				break;
			case MOSQ_LOG_ERR:
				topic = "$SYS/broker/log/E";

				syslog_priority = LOG_ERR;

				syslog_priority = EVENTLOG_ERROR_TYPE;

				break;
			case MOSQ_LOG_WARNING:
				topic = "$SYS/broker/log/W";

				syslog_priority = LOG_WARNING;

				syslog_priority = EVENTLOG_WARNING_TYPE;

				break;
			case MOSQ_LOG_NOTICE:
				topic = "$SYS/broker/log/N";

				syslog_priority = LOG_NOTICE;

				syslog_priority = EVENTLOG_INFORMATION_TYPE;

				break;
			case MOSQ_LOG_INFO:
				topic = "$SYS/broker/log/I";

				syslog_priority = LOG_INFO;

				syslog_priority = EVENTLOG_INFORMATION_TYPE;

				break;

			case MOSQ_LOG_WEBSOCKETS:
				topic = "$SYS/broker/log/WS";

				syslog_priority = LOG_DEBUG;

				syslog_priority = EVENTLOG_INFORMATION_TYPE;

				break;

			default:
				topic = "$SYS/broker/log/E";

				syslog_priority = LOG_ERR;

				syslog_priority = EVENTLOG_ERROR_TYPE;

		}
		len = strlen(fmt) + 500;
		s = _mosquitto_malloc(len*sizeof(char));
		if(!s) return MOSQ_ERR_NOMEM;

		vsnprintf(s, len, fmt, va);
		s[len-1] = '\0'; 

		if(log_destinations & MQTT3_LOG_STDOUT){
			if(int_db.config && int_db.config->log_timestamp){
				fprintf(stdout, "%d: %s\n", (int)now, s);
			}else{
				fprintf(stdout, "%s\n", s);
			}
			fflush(stdout);
		}
		if(log_destinations & MQTT3_LOG_STDERR){
			if(int_db.config && int_db.config->log_timestamp){
				fprintf(stderr, "%d: %s\n", (int)now, s);
			}else{
				fprintf(stderr, "%s\n", s);
			}
			fflush(stderr);
		}
		if(log_destinations & MQTT3_LOG_FILE && int_db.config->log_fptr){
			if(int_db.config && int_db.config->log_timestamp){
				fprintf(int_db.config->log_fptr, "%d: %s\n", (int)now, s);
			}else{
				fprintf(int_db.config->log_fptr, "%s\n", s);
			}
			if(now - last_flush > 1){
				fflush(int_db.config->log_fptr);
				last_flush = now;
			}
		}
		if(log_destinations & MQTT3_LOG_SYSLOG){

			syslog(syslog_priority, "%s", s);

			sp = (char *)s;
			ReportEvent(syslog_h, syslog_priority, 0, 0, NULL, 1, 0, &sp, NULL);

		}
		if(log_destinations & MQTT3_LOG_TOPIC && priority != MOSQ_LOG_DEBUG){
			if(int_db.config && int_db.config->log_timestamp){
				len += 30;
				st = _mosquitto_malloc(len*sizeof(char));
				if(!st){
					_mosquitto_free(s);
					return MOSQ_ERR_NOMEM;
				}
				snprintf(st, len, "%d: %s", (int)now, s);
				mqtt3_db_messages_easy_queue(&int_db, NULL, topic, 2, strlen(st), st, 0);
				_mosquitto_free(st);
			}else{
				mqtt3_db_messages_easy_queue(&int_db, NULL, topic, 2, strlen(s), s, 0);
			}
		}
		_mosquitto_free(s);
	}

	return MOSQ_ERR_SUCCESS;
}

int _mosquitto_log_printf(struct mosquitto *mosq, int priority, const char *fmt, ...)
{
	va_list va;
	int rc;

	va_start(va, fmt);
	rc = _mosquitto_log_vprintf(mosq, priority, fmt, va);
	va_end(va);

	return rc;
}

void mosquitto_log_printf(int level, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	_mosquitto_log_vprintf(NULL, level, fmt, va);
	va_end(va);
}

