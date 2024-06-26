













































typedef struct GAPersistentState {

    int64_t fd_counter;
} GAPersistentState;

struct GAState {
    JSONMessageParser parser;
    GMainLoop *main_loop;
    GAChannel *channel;
    bool virtio; 
    GACommandState *command_state;
    GLogLevelFlags log_level;
    FILE *log_file;
    bool logging_enabled;

    GAService service;

    bool delimit_response;
    bool frozen;
    GList *blacklist;
    const char *state_filepath_isfrozen;
    struct {
        const char *log_filepath;
        const char *pid_filepath;
    } deferred_options;

    const char *fsfreeze_hook;

    const gchar *pstate_filepath;
    GAPersistentState pstate;
};

struct GAState *ga_state;


static const char *ga_freeze_whitelist[] = {
    "guest-ping", "guest-info", "guest-sync", "guest-sync-delimited", "guest-fsfreeze-status", "guest-fsfreeze-thaw", NULL };








DWORD WINAPI service_ctrl_handler(DWORD ctrl, DWORD type, LPVOID data, LPVOID ctx);
VOID WINAPI service_main(DWORD argc, TCHAR *argv[]);


static void quit_handler(int sig)
{
    
    if (ga_is_frozen(ga_state)) {
        return;
    }
    g_debug("received signal num %d, quitting", sig);

    if (g_main_loop_is_running(ga_state->main_loop)) {
        g_main_loop_quit(ga_state->main_loop);
    }
}


static gboolean register_signal_handlers(void)
{
    struct sigaction sigact;
    int ret;

    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = quit_handler;

    ret = sigaction(SIGINT, &sigact, NULL);
    if (ret == -1) {
        g_error("error configuring signal handler: %s", strerror(errno));
    }
    ret = sigaction(SIGTERM, &sigact, NULL);
    if (ret == -1) {
        g_error("error configuring signal handler: %s", strerror(errno));
    }

    return true;
}


void reopen_fd_to_null(int fd)
{
    int nullfd;

    nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0) {
        return;
    }

    dup2(nullfd, fd);

    if (nullfd != fd) {
        close(nullfd);
    }
}


static void usage(const char *cmd)
{
    printf( "Usage: %s [-m <method> -p <path>] [<options>]\n" "QEMU Guest Agent %s\n" "\n" "  -m, --method      transport method: one of unix-listen, virtio-serial, or\n" "                    isa-serial (virtio-serial is the default)\n" "  -p, --path        device/socket path (the default for virtio-serial is:\n" "                    %s)\n" "  -l, --logfile     set logfile path, logs to stderr by default\n" "  -f, --pidfile     specify pidfile (default is %s)\n"  "  -F, --fsfreeze-hook\n" "                    enable fsfreeze hook. Accepts an optional argument that\n" "                    specifies script to run on freeze/thaw. Script will be\n" "                    called with 'freeze'/'thaw' arguments accordingly.\n" "                    (default is %s)\n" "                    If using -F with an argument, do not follow -F with a\n" "                    space.\n" "                    (for example: -F/var/run/fsfreezehook.sh)\n"  "  -t, --statedir    specify dir to store state information (absolute paths\n" "                    only, default is %s)\n" "  -v, --verbose     log extra debugging information\n" "  -V, --version     print version information and exit\n" "  -d, --daemonize   become a daemon\n"  "  -s, --service     service commands: install, uninstall\n"  "  -b, --blacklist   comma-separated list of RPCs to disable (no spaces, \"?\"\n" "                    to list available RPCs)\n" "  -h, --help        display this help and exit\n" "\n" "Report bugs to <mdroth@linux.vnet.ibm.com>\n" , cmd, QEMU_VERSION, QGA_VIRTIO_PATH_DEFAULT, QGA_PIDFILE_DEFAULT,  QGA_FSFREEZE_HOOK_DEFAULT,  QGA_STATEDIR_DEFAULT);




































}

static const char *ga_log_level_str(GLogLevelFlags level)
{
    switch (level & G_LOG_LEVEL_MASK) {
        case G_LOG_LEVEL_ERROR:
            return "error";
        case G_LOG_LEVEL_CRITICAL:
            return "critical";
        case G_LOG_LEVEL_WARNING:
            return "warning";
        case G_LOG_LEVEL_MESSAGE:
            return "message";
        case G_LOG_LEVEL_INFO:
            return "info";
        case G_LOG_LEVEL_DEBUG:
            return "debug";
        default:
            return "user";
    }
}

bool ga_logging_enabled(GAState *s)
{
    return s->logging_enabled;
}

void ga_disable_logging(GAState *s)
{
    s->logging_enabled = false;
}

void ga_enable_logging(GAState *s)
{
    s->logging_enabled = true;
}

static void ga_log(const gchar *domain, GLogLevelFlags level, const gchar *msg, gpointer opaque)
{
    GAState *s = opaque;
    GTimeVal time;
    const char *level_str = ga_log_level_str(level);

    if (!ga_logging_enabled(s)) {
        return;
    }

    level &= G_LOG_LEVEL_MASK;

    if (domain && strcmp(domain, "syslog") == 0) {
        syslog(LOG_INFO, "%s: %s", level_str, msg);
    } else if (level & s->log_level) {

    if (level & s->log_level) {

        g_get_current_time(&time);
        fprintf(s->log_file, "%lu.%lu: %s: %s\n", time.tv_sec, time.tv_usec, level_str, msg);
        fflush(s->log_file);
    }
}

void ga_set_response_delimited(GAState *s)
{
    s->delimit_response = true;
}

static FILE *ga_open_logfile(const char *logfile)
{
    FILE *f;

    f = fopen(logfile, "a");
    if (!f) {
        return NULL;
    }

    qemu_set_cloexec(fileno(f));
    return f;
}


static bool ga_open_pidfile(const char *pidfile)
{
    int pidfd;
    char pidstr[32];

    pidfd = qemu_open(pidfile, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
    if (pidfd == -1 || lockf(pidfd, F_TLOCK, 0)) {
        g_critical("Cannot lock pid file, %s", strerror(errno));
        if (pidfd != -1) {
            close(pidfd);
        }
        return false;
    }

    if (ftruncate(pidfd, 0)) {
        g_critical("Failed to truncate pid file");
        goto fail;
    }
    snprintf(pidstr, sizeof(pidstr), "%d\n", getpid());
    if (write(pidfd, pidstr, strlen(pidstr)) != strlen(pidstr)) {
        g_critical("Failed to write pid file");
        goto fail;
    }

    
    return true;

fail:
    unlink(pidfile);
    close(pidfd);
    return false;
}

static bool ga_open_pidfile(const char *pidfile)
{
    return true;
}


static gint ga_strcmp(gconstpointer str1, gconstpointer str2)
{
    return strcmp(str1, str2);
}


static void ga_disable_non_whitelisted(void)
{
    char **list_head, **list;
    bool whitelisted;
    int i;

    list_head = list = qmp_get_command_list();
    while (*list != NULL) {
        whitelisted = false;
        i = 0;
        while (ga_freeze_whitelist[i] != NULL) {
            if (strcmp(*list, ga_freeze_whitelist[i]) == 0) {
                whitelisted = true;
            }
            i++;
        }
        if (!whitelisted) {
            g_debug("disabling command: %s", *list);
            qmp_disable_command(*list);
        }
        g_free(*list);
        list++;
    }
    g_free(list_head);
}


static void ga_enable_non_blacklisted(GList *blacklist)
{
    char **list_head, **list;

    list_head = list = qmp_get_command_list();
    while (*list != NULL) {
        if (g_list_find_custom(blacklist, *list, ga_strcmp) == NULL && !qmp_command_is_enabled(*list)) {
            g_debug("enabling command: %s", *list);
            qmp_enable_command(*list);
        }
        g_free(*list);
        list++;
    }
    g_free(list_head);
}

static bool ga_create_file(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
    if (fd == -1) {
        g_warning("unable to open/create file %s: %s", path, strerror(errno));
        return false;
    }
    close(fd);
    return true;
}

static bool ga_delete_file(const char *path)
{
    int ret = unlink(path);
    if (ret == -1) {
        g_warning("unable to delete file: %s: %s", path, strerror(errno));
        return false;
    }

    return true;
}

bool ga_is_frozen(GAState *s)
{
    return s->frozen;
}

void ga_set_frozen(GAState *s)
{
    if (ga_is_frozen(s)) {
        return;
    }
    
    ga_disable_non_whitelisted();
    g_warning("disabling logging due to filesystem freeze");
    ga_disable_logging(s);
    s->frozen = true;
    if (!ga_create_file(s->state_filepath_isfrozen)) {
        g_warning("unable to create %s, fsfreeze may not function properly", s->state_filepath_isfrozen);
    }
}

void ga_unset_frozen(GAState *s)
{
    if (!ga_is_frozen(s)) {
        return;
    }

    
    if (s->deferred_options.log_filepath) {
        s->log_file = ga_open_logfile(s->deferred_options.log_filepath);
        if (!s->log_file) {
            s->log_file = stderr;
        }
        s->deferred_options.log_filepath = NULL;
    }
    ga_enable_logging(s);
    g_warning("logging re-enabled due to filesystem unfreeze");
    if (s->deferred_options.pid_filepath) {
        if (!ga_open_pidfile(s->deferred_options.pid_filepath)) {
            g_warning("failed to create/open pid file");
        }
        s->deferred_options.pid_filepath = NULL;
    }

    
    ga_enable_non_blacklisted(s->blacklist);
    s->frozen = false;
    if (!ga_delete_file(s->state_filepath_isfrozen)) {
        g_warning("unable to delete %s, fsfreeze may not function properly", s->state_filepath_isfrozen);
    }
}


const char *ga_fsfreeze_hook(GAState *s)
{
    return s->fsfreeze_hook;
}


static void become_daemon(const char *pidfile)
{

    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (pidfile) {
        if (!ga_open_pidfile(pidfile)) {
            g_critical("failed to create pidfile");
            exit(EXIT_FAILURE);
        }
    }

    umask(0);
    sid = setsid();
    if (sid < 0) {
        goto fail;
    }
    if ((chdir("/")) < 0) {
        goto fail;
    }

    reopen_fd_to_null(STDIN_FILENO);
    reopen_fd_to_null(STDOUT_FILENO);
    reopen_fd_to_null(STDERR_FILENO);
    return;

fail:
    if (pidfile) {
        unlink(pidfile);
    }
    g_critical("failed to daemonize");
    exit(EXIT_FAILURE);

}

static int send_response(GAState *s, QObject *payload)
{
    const char *buf;
    QString *payload_qstr, *response_qstr;
    GIOStatus status;

    g_assert(payload && s->channel);

    payload_qstr = qobject_to_json(payload);
    if (!payload_qstr) {
        return -EINVAL;
    }

    if (s->delimit_response) {
        s->delimit_response = false;
        response_qstr = qstring_new();
        qstring_append_chr(response_qstr, QGA_SENTINEL_BYTE);
        qstring_append(response_qstr, qstring_get_str(payload_qstr));
        QDECREF(payload_qstr);
    } else {
        response_qstr = payload_qstr;
    }

    qstring_append_chr(response_qstr, '\n');
    buf = qstring_get_str(response_qstr);
    status = ga_channel_write_all(s->channel, buf, strlen(buf));
    QDECREF(response_qstr);
    if (status != G_IO_STATUS_NORMAL) {
        return -EIO;
    }

    return 0;
}

static void process_command(GAState *s, QDict *req)
{
    QObject *rsp = NULL;
    int ret;

    g_assert(req);
    g_debug("processing command");
    rsp = qmp_dispatch(QOBJECT(req));
    if (rsp) {
        ret = send_response(s, rsp);
        if (ret) {
            g_warning("error sending response: %s", strerror(ret));
        }
        qobject_decref(rsp);
    }
}


static void process_event(JSONMessageParser *parser, QList *tokens)
{
    GAState *s = container_of(parser, GAState, parser);
    QObject *obj;
    QDict *qdict;
    Error *err = NULL;
    int ret;

    g_assert(s && parser);

    g_debug("process_event: called");
    obj = json_parser_parse_err(tokens, NULL, &err);
    if (err || !obj || qobject_type(obj) != QTYPE_QDICT) {
        qobject_decref(obj);
        qdict = qdict_new();
        if (!err) {
            g_warning("failed to parse event: unknown error");
            error_set(&err, QERR_JSON_PARSING);
        } else {
            g_warning("failed to parse event: %s", error_get_pretty(err));
        }
        qdict_put_obj(qdict, "error", qmp_build_error_object(err));
        error_free(err);
    } else {
        qdict = qobject_to_qdict(obj);
    }

    g_assert(qdict);

    
    if (qdict_haskey(qdict, "execute")) {
        process_command(s, qdict);
    } else {
        if (!qdict_haskey(qdict, "error")) {
            QDECREF(qdict);
            qdict = qdict_new();
            g_warning("unrecognized payload format");
            error_set(&err, QERR_UNSUPPORTED);
            qdict_put_obj(qdict, "error", qmp_build_error_object(err));
            error_free(err);
        }
        ret = send_response(s, QOBJECT(qdict));
        if (ret) {
            g_warning("error sending error response: %s", strerror(ret));
        }
    }

    QDECREF(qdict);
}


static gboolean channel_event_cb(GIOCondition condition, gpointer data)
{
    GAState *s = data;
    gchar buf[QGA_READ_COUNT_DEFAULT+1];
    gsize count;
    GError *err = NULL;
    GIOStatus status = ga_channel_read(s->channel, buf, QGA_READ_COUNT_DEFAULT, &count);
    if (err != NULL) {
        g_warning("error reading channel: %s", err->message);
        g_error_free(err);
        return false;
    }
    switch (status) {
    case G_IO_STATUS_ERROR:
        g_warning("error reading channel");
        return false;
    case G_IO_STATUS_NORMAL:
        buf[count] = 0;
        g_debug("read data, count: %d, data: %s", (int)count, buf);
        json_message_parser_feed(&s->parser, (char *)buf, (int)count);
        break;
    case G_IO_STATUS_EOF:
        g_debug("received EOF");
        if (!s->virtio) {
            return false;
        }
        
    case G_IO_STATUS_AGAIN:
        
        if (s->virtio) {
            usleep(100*1000);
        }
        return true;
    default:
        g_warning("unknown channel read status, closing");
        return false;
    }
    return true;
}

static gboolean channel_init(GAState *s, const gchar *method, const gchar *path)
{
    GAChannelMethod channel_method;

    if (method == NULL) {
        method = "virtio-serial";
    }

    if (path == NULL) {
        if (strcmp(method, "virtio-serial") != 0) {
            g_critical("must specify a path for this channel");
            return false;
        }
        
        path = QGA_VIRTIO_PATH_DEFAULT;
    }

    if (strcmp(method, "virtio-serial") == 0) {
        s->virtio = true; 
        channel_method = GA_CHANNEL_VIRTIO_SERIAL;
    } else if (strcmp(method, "isa-serial") == 0) {
        channel_method = GA_CHANNEL_ISA_SERIAL;
    } else if (strcmp(method, "unix-listen") == 0) {
        channel_method = GA_CHANNEL_UNIX_LISTEN;
    } else {
        g_critical("unsupported channel method/type: %s", method);
        return false;
    }

    s->channel = ga_channel_new(channel_method, path, channel_event_cb, s);
    if (!s->channel) {
        g_critical("failed to create guest agent channel");
        return false;
    }

    return true;
}


DWORD WINAPI service_ctrl_handler(DWORD ctrl, DWORD type, LPVOID data, LPVOID ctx)
{
    DWORD ret = NO_ERROR;
    GAService *service = &ga_state->service;

    switch (ctrl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            quit_handler(SIGTERM);
            service->status.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(service->status_handle, &service->status);
            break;

        default:
            ret = ERROR_CALL_NOT_IMPLEMENTED;
    }
    return ret;
}

VOID WINAPI service_main(DWORD argc, TCHAR *argv[])
{
    GAService *service = &ga_state->service;

    service->status_handle = RegisterServiceCtrlHandlerEx(QGA_SERVICE_NAME, service_ctrl_handler, NULL);

    if (service->status_handle == 0) {
        g_critical("Failed to register extended requests function!\n");
        return;
    }

    service->status.dwServiceType = SERVICE_WIN32;
    service->status.dwCurrentState = SERVICE_RUNNING;
    service->status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    service->status.dwWin32ExitCode = NO_ERROR;
    service->status.dwServiceSpecificExitCode = NO_ERROR;
    service->status.dwCheckPoint = 0;
    service->status.dwWaitHint = 0;
    SetServiceStatus(service->status_handle, &service->status);

    g_main_loop_run(ga_state->main_loop);

    service->status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(service->status_handle, &service->status);
}


static void set_persistent_state_defaults(GAPersistentState *pstate)
{
    g_assert(pstate);
    pstate->fd_counter = QGA_PSTATE_DEFAULT_FD_COUNTER;
}

static void persistent_state_from_keyfile(GAPersistentState *pstate, GKeyFile *keyfile)
{
    g_assert(pstate);
    g_assert(keyfile);
    
    set_persistent_state_defaults(pstate);

    if (g_key_file_has_key(keyfile, "global", "fd_counter", NULL)) {
        pstate->fd_counter = g_key_file_get_integer(keyfile, "global", "fd_counter", NULL);
    }
}

static void persistent_state_to_keyfile(const GAPersistentState *pstate, GKeyFile *keyfile)
{
    g_assert(pstate);
    g_assert(keyfile);

    g_key_file_set_integer(keyfile, "global", "fd_counter", pstate->fd_counter);
}

static gboolean write_persistent_state(const GAPersistentState *pstate, const gchar *path)
{
    GKeyFile *keyfile = g_key_file_new();
    GError *gerr = NULL;
    gboolean ret = true;
    gchar *data = NULL;
    gsize data_len;

    g_assert(pstate);

    persistent_state_to_keyfile(pstate, keyfile);
    data = g_key_file_to_data(keyfile, &data_len, &gerr);
    if (gerr) {
        g_critical("failed to convert persistent state to string: %s", gerr->message);
        ret = false;
        goto out;
    }

    g_file_set_contents(path, data, data_len, &gerr);
    if (gerr) {
        g_critical("failed to write persistent state to %s: %s", path, gerr->message);
        ret = false;
        goto out;
    }

out:
    if (gerr) {
        g_error_free(gerr);
    }
    if (keyfile) {
        g_key_file_free(keyfile);
    }
    g_free(data);
    return ret;
}

static gboolean read_persistent_state(GAPersistentState *pstate, const gchar *path, gboolean frozen)
{
    GKeyFile *keyfile = NULL;
    GError *gerr = NULL;
    struct stat st;
    gboolean ret = true;

    g_assert(pstate);

    if (stat(path, &st) == -1) {
        
        if (errno != ENOENT) {
            g_critical("unable to access state file at path %s: %s", path, strerror(errno));
            ret = false;
            goto out;
        }

        
        set_persistent_state_defaults(pstate);
        if (!frozen) {
            ret = write_persistent_state(pstate, path);
            if (!ret) {
                g_critical("unable to create state file at path %s", path);
                ret = false;
                goto out;
            }
        }
        ret = true;
        goto out;
    }

    keyfile = g_key_file_new();
    g_key_file_load_from_file(keyfile, path, 0, &gerr);
    if (gerr) {
        g_critical("error loading persistent state from path: %s, %s", path, gerr->message);
        ret = false;
        goto out;
    }

    persistent_state_from_keyfile(pstate, keyfile);

out:
    if (keyfile) {
        g_key_file_free(keyfile);
    }
    if (gerr) {
        g_error_free(gerr);
    }

    return ret;
}

int64_t ga_get_fd_handle(GAState *s, Error **errp)
{
    int64_t handle;

    g_assert(s->pstate_filepath);
    
    g_assert(!ga_is_frozen(s));

    handle = s->pstate.fd_counter++;

    
    if (s->pstate.fd_counter == INT64_MAX) {
        abort();
    }

    if (!write_persistent_state(&s->pstate, s->pstate_filepath)) {
        error_setg(errp, "failed to commit persistent state to disk");
    }

    return handle;
}

int main(int argc, char **argv)
{
    const char *sopt = "hVvdm:p:l:f:F::b:s:t:";
    const char *method = NULL, *path = NULL;
    const char *log_filepath = NULL;
    const char *pid_filepath = QGA_PIDFILE_DEFAULT;

    const char *fsfreeze_hook = NULL;

    const char *state_dir = QGA_STATEDIR_DEFAULT;

    const char *service = NULL;

    const struct option lopt[] = {
        { "help", 0, NULL, 'h' }, { "version", 0, NULL, 'V' }, { "logfile", 1, NULL, 'l' }, { "pidfile", 1, NULL, 'f' },  { "fsfreeze-hook", 2, NULL, 'F' },  { "verbose", 0, NULL, 'v' }, { "method", 1, NULL, 'm' }, { "path", 1, NULL, 'p' }, { "daemonize", 0, NULL, 'd' }, { "blacklist", 1, NULL, 'b' },  { "service", 1, NULL, 's' },  { "statedir", 1, NULL, 't' }, { NULL, 0, NULL, 0 }















    };
    int opt_ind = 0, ch, daemonize = 0, i, j, len;
    GLogLevelFlags log_level = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL;
    GList *blacklist = NULL;
    GAState *s;

    module_call_init(MODULE_INIT_QAPI);

    while ((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
        switch (ch) {
        case 'm':
            method = optarg;
            break;
        case 'p':
            path = optarg;
            break;
        case 'l':
            log_filepath = optarg;
            break;
        case 'f':
            pid_filepath = optarg;
            break;

        case 'F':
            fsfreeze_hook = optarg ? optarg : QGA_FSFREEZE_HOOK_DEFAULT;
            break;

        case 't':
             state_dir = optarg;
             break;
        case 'v':
            
            log_level = G_LOG_LEVEL_MASK;
            break;
        case 'V':
            printf("QEMU Guest Agent %s\n", QEMU_VERSION);
            return 0;
        case 'd':
            daemonize = 1;
            break;
        case 'b': {
            char **list_head, **list;
            if (is_help_option(optarg)) {
                list_head = list = qmp_get_command_list();
                while (*list != NULL) {
                    printf("%s\n", *list);
                    g_free(*list);
                    list++;
                }
                g_free(list_head);
                return 0;
            }
            for (j = 0, i = 0, len = strlen(optarg); i < len; i++) {
                if (optarg[i] == ',') {
                    optarg[i] = 0;
                    blacklist = g_list_append(blacklist, &optarg[j]);
                    j = i + 1;
                }
            }
            if (j < i) {
                blacklist = g_list_append(blacklist, &optarg[j]);
            }
            break;
        }

        case 's':
            service = optarg;
            if (strcmp(service, "install") == 0) {
                return ga_install_service(path, log_filepath);
            } else if (strcmp(service, "uninstall") == 0) {
                return ga_uninstall_service();
            } else {
                printf("Unknown service command.\n");
                return EXIT_FAILURE;
            }
            break;

        case 'h':
            usage(argv[0]);
            return 0;
        case '?':
            g_print("Unknown option, try '%s --help' for more information.\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    s = g_malloc0(sizeof(GAState));
    s->log_level = log_level;
    s->log_file = stderr;

    s->fsfreeze_hook = fsfreeze_hook;

    g_log_set_default_handler(ga_log, s);
    g_log_set_fatal_mask(NULL, G_LOG_LEVEL_ERROR);
    ga_enable_logging(s);
    s->state_filepath_isfrozen = g_strdup_printf("%s/qga.state.isfrozen", state_dir);
    s->pstate_filepath = g_strdup_printf("%s/qga.state", state_dir);
    s->frozen = false;


    
    struct stat st;
    if (stat(s->state_filepath_isfrozen, &st) == -1) {
        
        if (errno != ENOENT) {
            g_critical("unable to access state file at path %s: %s", s->state_filepath_isfrozen, strerror(errno));
            return EXIT_FAILURE;
        }
    } else {
        g_warning("previous instance appears to have exited with frozen" " filesystems. deferring logging/pidfile creation and" " disabling non-fsfreeze-safe commands until" " guest-fsfreeze-thaw is issued, or filesystems are" " manually unfrozen and the file %s is removed", s->state_filepath_isfrozen);




        s->frozen = true;
    }


    if (ga_is_frozen(s)) {
        if (daemonize) {
            
            s->deferred_options.pid_filepath = pid_filepath;
            become_daemon(NULL);
        }
        if (log_filepath) {
            
            s->deferred_options.log_filepath = log_filepath;
        }
        ga_disable_logging(s);
        ga_disable_non_whitelisted();
    } else {
        if (daemonize) {
            become_daemon(pid_filepath);
        }
        if (log_filepath) {
            FILE *log_file = ga_open_logfile(log_filepath);
            if (!log_file) {
                g_critical("unable to open specified log file: %s", strerror(errno));
                goto out_bad;
            }
            s->log_file = log_file;
        }
    }

    
    if (!read_persistent_state(&s->pstate, s->pstate_filepath, ga_is_frozen(s))) {

        g_critical("failed to load persistent state");
        goto out_bad;
    }

    if (blacklist) {
        s->blacklist = blacklist;
        do {
            g_debug("disabling command: %s", (char *)blacklist->data);
            qmp_disable_command(blacklist->data);
            blacklist = g_list_next(blacklist);
        } while (blacklist);
    }
    s->command_state = ga_command_state_new();
    ga_command_state_init(s, s->command_state);
    ga_command_state_init_all(s->command_state);
    json_message_parser_init(&s->parser, process_event);
    ga_state = s;

    if (!register_signal_handlers()) {
        g_critical("failed to register signal handlers");
        goto out_bad;
    }


    s->main_loop = g_main_loop_new(NULL, false);
    if (!channel_init(ga_state, method, path)) {
        g_critical("failed to initialize guest agent channel");
        goto out_bad;
    }

    g_main_loop_run(ga_state->main_loop);

    if (daemonize) {
        SERVICE_TABLE_ENTRY service_table[] = {
            { (char *)QGA_SERVICE_NAME, service_main }, { NULL, NULL } };
        StartServiceCtrlDispatcher(service_table);
    } else {
        g_main_loop_run(ga_state->main_loop);
    }


    ga_command_state_cleanup_all(ga_state->command_state);
    ga_channel_free(ga_state->channel);

    if (daemonize) {
        unlink(pid_filepath);
    }
    return 0;

out_bad:
    if (daemonize) {
        unlink(pid_filepath);
    }
    return EXIT_FAILURE;
}
