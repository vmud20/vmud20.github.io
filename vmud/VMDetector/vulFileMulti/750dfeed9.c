





















































struct replay_closure {
    const char *iolog_dir;
    struct sudo_event_base *evbase;
    struct sudo_event *delay_ev;
    struct sudo_event *keyboard_ev;
    struct sudo_event *output_ev;
    struct sudo_event *sighup_ev;
    struct sudo_event *sigint_ev;
    struct sudo_event *sigquit_ev;
    struct sudo_event *sigterm_ev;
    struct sudo_event *sigtstp_ev;
    struct timespec *offset;
    struct timespec *max_delay;
    struct timing_closure timing;
    int iolog_dir_fd;
    bool interactive;
    bool suspend_wait;
    struct io_buffer {
	unsigned int len; 
	unsigned int off; 
	unsigned int toread; 
	int lastc;	  
	char buf[64 * 1024];
    } iobuf;
};


STAILQ_HEAD(search_node_list, search_node);
struct search_node {
    STAILQ_ENTRY(search_node) entries;










    char type;
    bool negated;
    bool or;
    union {
	regex_t cmdre;
	struct timespec tstamp;
	char *cwd;
	char *host;
	char *tty;
	char *user;
	char *runas_group;
	char *runas_user;
	struct search_node_list expr;
	void *ptr;
    } u;
};

static struct search_node_list search_expr = STAILQ_HEAD_INITIALIZER(search_expr);

static double speed_factor = 1.0;

static const char *session_dir = _PATH_SUDO_IO_LOGDIR;

static bool terminal_can_resize, terminal_was_resized, follow_mode;

static int terminal_lines, terminal_cols;

static int ttyfd = -1;

static struct iolog_file iolog_files[] = {
    { false },	 { false }, { false }, { false }, { false }, { true, }, };






static const char short_opts[] =  "d:f:Fhlm:nRSs:V";
static struct option long_opts[] = {
    { "directory",	required_argument,	NULL,	'd' }, { "filter",		required_argument,	NULL,	'f' }, { "follow",		no_argument,		NULL,	'F' }, { "help",		no_argument,		NULL,	'h' }, { "list",		no_argument,		NULL,	'l' }, { "max-wait",	required_argument,	NULL,	'm' }, { "non-interactive", no_argument,		NULL,	'n' }, { "no-resize",	no_argument,		NULL,	'R' }, { "suspend-wait",	no_argument,		NULL,	'S' }, { "speed",		required_argument,	NULL,	's' }, { "version",	no_argument,		NULL,	'V' }, { NULL,		no_argument,		NULL,	'\0' }, };













extern char *get_timestr(time_t, int);
extern time_t get_date(char *);

static int list_sessions(int, char **, const char *, const char *, const char *);
static int parse_expr(struct search_node_list *, char **, bool);
static void read_keyboard(int fd, int what, void *v);
static int replay_session(int iolog_dir_fd, const char *iolog_dir, struct timespec *offset, struct timespec *max_wait, const char *decimal, bool interactive, bool suspend_wait);

static void sudoreplay_cleanup(void);
static void write_output(int fd, int what, void *v);
static void restore_terminal_size(void);
static void setup_terminal(struct eventlog *evlog, bool interactive, bool resize);
sudo_noreturn static void help(void);
sudo_noreturn static void usage(void);












sudo_dso_public int main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int ch, i, iolog_dir_fd, len, exitcode = EXIT_FAILURE;
    bool def_filter = true, listonly = false;
    bool interactive = true, suspend_wait = false, resize = true;
    const char *decimal, *id, *user = NULL, *pattern = NULL, *tty = NULL;
    char *cp, *ep, iolog_dir[PATH_MAX];
    struct timespec offset = { 0, 0};
    struct eventlog *evlog;
    struct timespec max_delay_storage, *max_delay = NULL;
    double dval;
    debug_decl(main, SUDO_DEBUG_MAIN);


    {
	extern char *malloc_options;
	malloc_options = "S";
    }


    initprogname(argc > 0 ? argv[0] : "sudoreplay");
    setlocale(LC_ALL, "");
    decimal = localeconv()->decimal_point;
    bindtextdomain("sudoers", LOCALEDIR); 
    textdomain("sudoers");

    
    sudo_fatal_callback_register(sudoreplay_cleanup);

    
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	exit(EXIT_FAILURE);
    sudo_debug_register(getprogname(), NULL, NULL, sudo_conf_debug_files(getprogname()), -1);

    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'd':
	    session_dir = optarg;
	    break;
	case 'f':
	    
	    def_filter = false;
	    for (cp = strtok_r(optarg, ",", &ep); cp; cp = strtok_r(NULL, ",", &ep)) {
		if (strcmp(cp, "stdin") == 0)
		    iolog_files[IOFD_STDIN].enabled = true;
		else if (strcmp(cp, "stdout") == 0)
		    iolog_files[IOFD_STDOUT].enabled = true;
		else if (strcmp(cp, "stderr") == 0)
		    iolog_files[IOFD_STDERR].enabled = true;
		else if (strcmp(cp, "ttyin") == 0)
		    iolog_files[IOFD_TTYIN].enabled = true;
		else if (strcmp(cp, "ttyout") == 0)
		    iolog_files[IOFD_TTYOUT].enabled = true;
		else sudo_fatalx(U_("invalid filter option: %s"), optarg);
	    }
	    break;
	case 'F':
	    follow_mode = true;
	    break;
	case 'h':
	    help();
	    
	case 'l':
	    listonly = true;
	    break;
	case 'm':
	    errno = 0;
	    dval = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		sudo_fatalx(U_("invalid max wait: %s"), optarg);
	    if (dval <= 0.0) {
		sudo_timespecclear(&max_delay_storage);
	    } else {
		max_delay_storage.tv_sec = dval;
		max_delay_storage.tv_nsec = (dval - max_delay_storage.tv_sec) * 1000000000.0;
	    }
	    max_delay = &max_delay_storage;
	    break;
	case 'n':
	    interactive = false;
	    break;
	case 'R':
	    resize = false;
	    break;
	case 'S':
	    suspend_wait = true;
	    break;
	case 's':
	    errno = 0;
	    speed_factor = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		sudo_fatalx(U_("invalid speed factor: %s"), optarg);
	    break;
	case 'V':
	    (void) printf(_("%s version %s\n"), getprogname(), PACKAGE_VERSION);
	    exitcode = EXIT_SUCCESS;
	    goto done;
	default:
	    usage();
	    
	}

    }
    argc -= optind;
    argv += optind;

    if (listonly) {
	exitcode = list_sessions(argc, argv, pattern, user, tty);
	goto done;
    }

    if (argc != 1)
	usage();

    
    if (def_filter) {
	iolog_files[IOFD_STDOUT].enabled = true;
	iolog_files[IOFD_STDERR].enabled = true;
	iolog_files[IOFD_TTYOUT].enabled = true;
    }

    
    id = argv[0];
    if ((cp = strchr(id, '@')) != NULL) {
	ep = iolog_parse_delay(cp + 1, &offset, decimal);
	if (ep == NULL || *ep != '\0')
	    sudo_fatalx(U_("invalid time offset %s"), cp + 1);
	*cp = '\0';
    }

    
    if (VALID_ID(id)) {
	len = snprintf(iolog_dir, sizeof(iolog_dir), "%s/%.2s/%.2s/%.2s", session_dir, id, &id[2], &id[4]);
	if (len < 0 || len >= ssizeof(iolog_dir))
	    sudo_fatalx(U_("%s/%.2s/%.2s/%.2s: %s"), session_dir, id, &id[2], &id[4], strerror(ENAMETOOLONG));
    } else if (id[0] == '/') {
	len = snprintf(iolog_dir, sizeof(iolog_dir), "%s", id);
	if (len < 0 || len >= ssizeof(iolog_dir))
	    sudo_fatalx(U_("%s/timing: %s"), id, strerror(ENAMETOOLONG));
    } else {
	len = snprintf(iolog_dir, sizeof(iolog_dir), "%s/%s", session_dir, id);
	if (len < 0 || len >= ssizeof(iolog_dir)) {
	    sudo_fatalx(U_("%s/%s: %s"), session_dir, id, strerror(ENAMETOOLONG));
	}
    }

    
    if ((iolog_dir_fd = iolog_openat(AT_FDCWD, iolog_dir, O_RDONLY)) == -1)
	sudo_fatal("%s", iolog_dir);
    for (i = 0; i < IOFD_MAX; i++) {
	if (!iolog_open(&iolog_files[i], iolog_dir_fd, i, "r")) {
	    if (errno != ENOENT) {
		sudo_fatal(U_("unable to open %s/%s"), iolog_dir, iolog_fd_to_name(i));
	    }
	}
    }
    if (!iolog_files[IOFD_TIMING].enabled) {
	sudo_fatal(U_("unable to open %s/%s"), iolog_dir, iolog_fd_to_name(IOFD_TIMING));
    }

    
    if ((evlog = iolog_parse_loginfo(iolog_dir_fd, iolog_dir)) == NULL)
	goto done;
    printf(_("Replaying sudo session: %s"), evlog->command);

    
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
	interactive = false;
    setup_terminal(evlog, interactive, resize);
    putchar('\r');
    putchar('\n');

    
    eventlog_free(evlog);
    evlog = NULL;

    
    exitcode = replay_session(iolog_dir_fd, iolog_dir, &offset, max_delay, decimal, interactive, suspend_wait);

    restore_terminal_size();
    sudo_term_restore(ttyfd, true);
done:
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    return exitcode;
}


struct term_names {
    const char *name;
    unsigned int len;
} compatible_terms[] = {
    { "Eterm", 5 }, { "aterm", 5 }, { "dtterm", 6 }, { "gnome", 5 }, { "konsole", 7 }, { "kvt\0", 4 }, { "mlterm", 6 }, { "rxvt", 4 }, { "xterm", 5 }, { NULL, 0 }








};

struct getsize_closure {
    int nums[2];
    int nums_depth;
    int nums_maxdepth;
    int state;
    const char *cp;
    struct sudo_event *ev;
    struct timespec timeout;
};









static void getsize_cb(int fd, int what, void *v)
{
    struct getsize_closure *gc = v;
    unsigned char ch = '\0';
    debug_decl(getsize_cb, SUDO_DEBUG_UTIL);

    for (;;) {
	if (gc->cp[0] == '\0') {
	    gc->state = GOTSIZE;
	    goto done;
	}
	if (ISSET(gc->state, READCHAR)) {
	    ssize_t nread = read(ttyfd, &ch, 1);
	    switch (nread) {
	    case -1:
		if (errno == EAGAIN)
		    goto another;
		FALLTHROUGH;
	    case 0:
		goto done;
	    default:
		CLR(gc->state, READCHAR);
		break;
	    }
	}
	switch (gc->state) {
	case INITIAL:
	    if (ch == 0233 && gc->cp[0] == '\033') {
		
		ch = '[';
		gc->cp++;
	    }
	    if (gc->cp[0] == '%' && gc->cp[1] == 'd') {
		gc->state = NEW_NUMBER;
		continue;
	    }
	    if (gc->cp[0] != ch) {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO, "got %d, expected %d", ch, gc->cp[0]);
		goto done;
	    }
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO, "got %d", ch);
	    SET(gc->state, READCHAR);
	    gc->cp++;
	    break;
	case NEW_NUMBER:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO, "parsing number");
	    if (!isdigit(ch))
		goto done;
	    gc->cp += 2;
	    if (gc->nums_depth > gc->nums_maxdepth)
		goto done;
	    gc->nums[gc->nums_depth] = 0;
	    gc->state = NUMBER;
	    FALLTHROUGH;
	case NUMBER:
	    if (!isdigit(ch)) {
		
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO, "number %d (ch %d)", gc->nums[gc->nums_depth], ch);
		gc->nums_depth++;
		gc->state = INITIAL;
		continue;
	    }
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO, "got %d", ch);
	    if (gc->nums[gc->nums_depth] > INT_MAX / 10)
		goto done;
	    gc->nums[gc->nums_depth] *= 10;
	    gc->nums[gc->nums_depth] += (ch - '0');
	    SET(gc->state, READCHAR);
	    break;
	}
    }

another:
    if (sudo_ev_add(NULL, gc->ev, &gc->timeout, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));
done:
    debug_return;
}



static bool xterm_get_size(int *new_lines, int *new_cols)
{
    struct sudo_event_base *evbase;
    struct getsize_closure gc;
    const char getsize_request[] = "\0337\033[r\033[999;999H\033[6n";
    const char getsize_response[] = "\033[%d;%dR";
    bool ret = false;
    debug_decl(xterm_get_size, SUDO_DEBUG_UTIL);

    
    if (write(ttyfd, getsize_request, strlen(getsize_request)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "%s: error writing xterm size request", __func__);
	goto done;
    }

    
    gc.state = INITIAL|READCHAR;
    gc.nums_depth = 0;
    gc.nums_maxdepth = 1;
    gc.cp = getsize_response;
    gc.timeout.tv_sec = 10;
    gc.timeout.tv_nsec = 0;

    
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    gc.ev = sudo_ev_alloc(ttyfd, SUDO_EV_READ, getsize_cb, &gc);
    if (gc.ev == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    
    if (sudo_ev_add(evbase, gc.ev, &gc.timeout, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));
    sudo_ev_dispatch(evbase);

    if (gc.state == GOTSIZE) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "terminal size %d x %x", gc.nums[0], gc.nums[1]);
	*new_lines = gc.nums[0];
	*new_cols = gc.nums[1];
	ret = true;
    }

    sudo_ev_base_free(evbase);
    sudo_ev_free(gc.ev);

done:
    debug_return_bool(ret);
}


static bool xterm_set_size(int lines, int cols)
{
    const char setsize_fmt[] = "\033[8;%d;%dt";
    int len, new_lines, new_cols;
    bool ret = false;
    char buf[1024];
    debug_decl(xterm_set_size, SUDO_DEBUG_UTIL);

    
    len = snprintf(buf, sizeof(buf), setsize_fmt, lines, cols);
    if (len < 0 || len >= ssizeof(buf)) {
	
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "%s: internal error, buffer too small?", __func__);
	goto done;
    }
    if (write(ttyfd, buf, strlen(buf)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "%s: error writing xterm resize request", __func__);
	goto done;
    }
    
    if (!xterm_get_size(&new_lines, &new_cols))
	goto done;
    if (lines == new_lines && cols == new_cols)
	ret = true;

done:
    debug_return_bool(ret);
}

static void setup_terminal(struct eventlog *evlog, bool interactive, bool resize)
{
    const char *term;
    debug_decl(check_terminal, SUDO_DEBUG_UTIL);

    fflush(stdout);

    
    if (interactive) {
	ttyfd = open(_PATH_TTY, O_RDWR);
	while (!sudo_term_raw(ttyfd, 1)) {
	    if (errno != EINTR)
		sudo_fatal("%s", U_("unable to set tty to raw mode"));
	    kill(getpid(), SIGTTOU);
	}
    }

    
    if (evlog->lines == 0 && evlog->columns == 0) {
	
	debug_return;
    }

    if (resize && ttyfd != -1) {
	term = getenv("TERM");
	if (term != NULL && *term != '\0') {
	    struct term_names *tn;

	    for (tn = compatible_terms; tn->name != NULL; tn++) {
		if (strncmp(term, tn->name, tn->len) == 0) {
		    
		    if (xterm_get_size(&terminal_lines, &terminal_cols))
			terminal_can_resize = true;
		    break;
		}
	    }
	}
    }

    if (!terminal_can_resize) {
	
	sudo_get_ttysize(&terminal_lines, &terminal_cols);
    }

    if (evlog->lines == terminal_lines && evlog->columns == terminal_cols) {
	
	debug_return;
    }

    if (terminal_can_resize) {
	
	if (xterm_set_size(evlog->lines, evlog->columns)) {
	    
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "resized terminal to %d x %x", evlog->lines, evlog->columns);
	    terminal_was_resized = true;
	    debug_return;
	}
	
	terminal_can_resize = false;
    }

    if (evlog->lines > terminal_lines || evlog->columns > terminal_cols) {
	fputs(_("Warning: your terminal is too small to properly replay the log.\n"), stdout);
	printf(_("Log geometry is %d x %d, your terminal's geometry is %d x %d."), evlog->lines, evlog->columns, terminal_lines, terminal_cols);
    }
    debug_return;
}

static void resize_terminal(int lines, int cols)
{
    debug_decl(resize_terminal, SUDO_DEBUG_UTIL);

    if (terminal_can_resize) {
	if (xterm_set_size(lines, cols))
	    terminal_was_resized = true;
	else terminal_can_resize = false;
    }

    debug_return;
}

static void restore_terminal_size(void)
{
    debug_decl(restore_terminal, SUDO_DEBUG_UTIL);

    if (terminal_was_resized) {
	
	putchar('\r');
	fputs(U_("Replay finished, press any key to restore the terminal."), stdout);
	fflush(stdout);
	(void)getchar();
	xterm_set_size(terminal_lines, terminal_cols);
	putchar('\r');
	putchar('\n');
    }

    debug_return;
}

static bool iolog_complete(struct replay_closure *closure)
{
    struct stat sb;
    debug_decl(iolog_complete, SUDO_DEBUG_UTIL);

    if (fstatat(closure->iolog_dir_fd, "timing", &sb, 0) != -1) {
	if (ISSET(sb.st_mode, S_IWUSR|S_IWGRP|S_IWOTH))
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}


static int get_timing_record(struct replay_closure *closure)
{
    struct timing_closure *timing = &closure->timing;
    bool nodelay = false;
    debug_decl(get_timing_record, SUDO_DEBUG_UTIL);

    if (follow_mode && timing->event == IO_EVENT_COUNT) {
	
	nodelay = true;
    }

    switch (iolog_read_timing_record(&iolog_files[IOFD_TIMING], timing)) {
    case -1:
	
	debug_return_int(-1);
    case 1:
	
	if (!follow_mode || iolog_complete(closure)) {
	    debug_return_int(1);
	}
	
	iolog_clearerr(&iolog_files[IOFD_TIMING]);
	timing->delay.tv_sec = 0;
	timing->delay.tv_nsec = 1000000;
	timing->iol = NULL;
	timing->event = IO_EVENT_COUNT;
	break;
    default:
	
	if (timing->event != IO_EVENT_WINSIZE && timing->event != IO_EVENT_SUSPEND) {
	    closure->iobuf.len = 0;
	    closure->iobuf.off = 0;
	    closure->iobuf.lastc = '\0';
	    closure->iobuf.toread = timing->u.nbytes;
	}

	if (sudo_timespecisset(closure->offset)) {
	    if (sudo_timespeccmp(&timing->delay, closure->offset, >)) {
		sudo_timespecsub(&timing->delay, closure->offset, &timing->delay);
		sudo_timespecclear(closure->offset);
	    } else {
		sudo_timespecsub(closure->offset, &timing->delay, closure->offset);
		sudo_timespecclear(&timing->delay);
	    }
	}

	if (nodelay) {
	    
	    timing->delay.tv_sec = 0;
	    timing->delay.tv_nsec = 0;
	} else {
	    
	    iolog_adjust_delay(&timing->delay, closure->max_delay, speed_factor);
	}
	break;
    }

    
    if (sudo_ev_add(closure->evbase, closure->delay_ev, &timing->delay, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    debug_return_int(0);
}


static void next_timing_record(struct replay_closure *closure)
{
    debug_decl(next_timing_record, SUDO_DEBUG_UTIL);

again:
    switch (get_timing_record(closure)) {
    case 0:
	
	if (closure->timing.event == IO_EVENT_SUSPEND && closure->timing.u.signo == SIGCONT && !closure->suspend_wait) {
	    
	    goto again;
	}
	break;
    case 1:
	
	sudo_ev_loopexit(closure->evbase);
	break;
    default:
	
	sudo_ev_loopbreak(closure->evbase);
	break;
    }
    debug_return;
}

static bool fill_iobuf(struct replay_closure *closure)
{
    const size_t space = sizeof(closure->iobuf.buf) - closure->iobuf.len;
    const struct timing_closure *timing = &closure->timing;
    const char *errstr;
    debug_decl(fill_iobuf, SUDO_DEBUG_UTIL);

    if (closure->iobuf.toread != 0 && space != 0) {
	const size_t len = closure->iobuf.toread < space ? closure->iobuf.toread : space;
	ssize_t nread = iolog_read(timing->iol, closure->iobuf.buf + closure->iobuf.off, len, &errstr);
	if (nread <= 0) {
	    if (nread == 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "%s/%s: premature EOF, expected %u bytes", closure->iolog_dir, iolog_fd_to_name(timing->event), closure->iobuf.toread);


	    } else {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "%s/%s: read error: %s", closure->iolog_dir, iolog_fd_to_name(timing->event), errstr);

	    }
	    sudo_warnx(U_("unable to read %s/%s: %s"), closure->iolog_dir, iolog_fd_to_name(timing->event), errstr);
	    debug_return_bool(false);
	}
	closure->iobuf.toread -= nread;
	closure->iobuf.len += nread;
    }

    debug_return_bool(true);
}


static void delay_cb(int fd, int what, void *v)
{
    struct replay_closure *closure = v;
    struct timing_closure *timing = &closure->timing;
    debug_decl(delay_cb, SUDO_DEBUG_UTIL);

    switch (timing->event) {
    case IO_EVENT_WINSIZE:
	resize_terminal(timing->u.winsize.lines, timing->u.winsize.cols);
	break;
    case IO_EVENT_STDIN:
	if (iolog_files[IOFD_STDIN].enabled)
	    timing->iol = &iolog_files[IOFD_STDIN];
	break;
    case IO_EVENT_STDOUT:
	if (iolog_files[IOFD_STDOUT].enabled)
	    timing->iol = &iolog_files[IOFD_STDOUT];
	break;
    case IO_EVENT_STDERR:
	if (iolog_files[IOFD_STDERR].enabled)
	    timing->iol = &iolog_files[IOFD_STDERR];
	break;
    case IO_EVENT_TTYIN:
	if (iolog_files[IOFD_TTYIN].enabled)
	    timing->iol = &iolog_files[IOFD_TTYIN];
	break;
    case IO_EVENT_TTYOUT:
	if (iolog_files[IOFD_TTYOUT].enabled)
	    timing->iol = &iolog_files[IOFD_TTYOUT];
	break;
    }

    if (timing->iol != NULL) {
	
	if (sudo_ev_add(closure->evbase, closure->output_ev, NULL, false) == -1)
	    sudo_fatal("%s", U_("unable to add event to queue"));
    } else {
	
	next_timing_record(closure);
    }

    debug_return;
}

static void replay_closure_free(struct replay_closure *closure)
{
    
    if (closure->iolog_dir_fd != -1)
	close(closure->iolog_dir_fd);
    sudo_ev_free(closure->delay_ev);
    sudo_ev_free(closure->keyboard_ev);
    sudo_ev_free(closure->output_ev);
    sudo_ev_free(closure->sighup_ev);
    sudo_ev_free(closure->sigint_ev);
    sudo_ev_free(closure->sigquit_ev);
    sudo_ev_free(closure->sigterm_ev);
    sudo_ev_free(closure->sigtstp_ev);
    sudo_ev_base_free(closure->evbase);
    free(closure);
}

static void signal_cb(int signo, int what, void *v)
{
    struct replay_closure *closure = v;
    debug_decl(signal_cb, SUDO_DEBUG_UTIL);

    switch (signo) {
    case SIGHUP:
    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
	
	replay_closure_free(closure);

	
	sudoreplay_cleanup();
	kill(getpid(), signo);
	break;
    case SIGTSTP:
	
	break;
    }

    debug_return;
}

static struct replay_closure * replay_closure_alloc(int iolog_dir_fd, const char *iolog_dir, struct timespec *offset, struct timespec *max_delay, const char *decimal, bool interactive, bool suspend_wait)


{
    struct replay_closure *closure;
    debug_decl(replay_closure_alloc, SUDO_DEBUG_UTIL);

    if ((closure = calloc(1, sizeof(*closure))) == NULL)
	debug_return_ptr(NULL);

    closure->iolog_dir_fd = iolog_dir_fd;
    closure->iolog_dir = iolog_dir;
    closure->interactive = interactive;
    closure->offset = offset;
    closure->suspend_wait = suspend_wait;
    closure->max_delay = max_delay;
    closure->timing.decimal = decimal;

    
    closure->evbase = sudo_ev_base_alloc();
    if (closure->evbase == NULL)
	goto bad;
    closure->delay_ev = sudo_ev_alloc(-1, SUDO_EV_TIMEOUT, delay_cb, closure);
    if (closure->delay_ev == NULL)
        goto bad;
    if (interactive) {
	closure->keyboard_ev = sudo_ev_alloc(ttyfd, SUDO_EV_READ|SUDO_EV_PERSIST, read_keyboard, closure);
	if (closure->keyboard_ev == NULL)
	    goto bad;
	if (sudo_ev_add(closure->evbase, closure->keyboard_ev, NULL, false) == -1)
	    sudo_fatal("%s", U_("unable to add event to queue"));
    }
    closure->output_ev = sudo_ev_alloc(interactive ? ttyfd : STDOUT_FILENO, SUDO_EV_WRITE, write_output, closure);
    if (closure->output_ev == NULL)
        goto bad;

    
    closure->sighup_ev = sudo_ev_alloc(SIGHUP, SUDO_EV_SIGNAL, signal_cb, closure);
    if (closure->sighup_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sighup_ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    closure->sigint_ev = sudo_ev_alloc(SIGINT, SUDO_EV_SIGNAL, signal_cb, closure);
    if (closure->sigint_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigint_ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    closure->sigquit_ev = sudo_ev_alloc(SIGQUIT, SUDO_EV_SIGNAL, signal_cb, closure);
    if (closure->sigquit_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigquit_ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    closure->sigterm_ev = sudo_ev_alloc(SIGTERM, SUDO_EV_SIGNAL, signal_cb, closure);
    if (closure->sigterm_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigterm_ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    closure->sigtstp_ev = sudo_ev_alloc(SIGTSTP, SUDO_EV_SIGNAL, signal_cb, closure);
    if (closure->sigtstp_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigtstp_ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    debug_return_ptr(closure);
bad:
    replay_closure_free(closure);
    debug_return_ptr(NULL);
}

static int replay_session(int iolog_dir_fd, const char *iolog_dir, struct timespec *offset, struct timespec *max_delay, const char *decimal, bool interactive, bool suspend_wait)


{
    struct replay_closure *closure;
    int ret = 0;
    debug_decl(replay_session, SUDO_DEBUG_UTIL);

    
    closure = replay_closure_alloc(iolog_dir_fd, iolog_dir, offset, max_delay, decimal, interactive, suspend_wait);
    if (get_timing_record(closure) != 0) {
	ret = 1;
	goto done;
    }

    
    sudo_ev_dispatch(closure->evbase);
    if (sudo_ev_got_break(closure->evbase))
	ret = 1;

done:
    
    replay_closure_free(closure);
    debug_return_int(ret);
}


static void write_output(int fd, int what, void *v)
{
    struct replay_closure *closure = v;
    const struct timing_closure *timing = &closure->timing;
    struct io_buffer *iobuf = &closure->iobuf;
    unsigned iovcnt = 1;
    struct iovec iov[2];
    bool added_cr = false;
    size_t nbytes, nwritten;
    debug_decl(write_output, SUDO_DEBUG_UTIL);

    
    if (!fill_iobuf(closure)) {
	sudo_ev_loopbreak(closure->evbase);
	debug_return;
    }

    nbytes = iobuf->len - iobuf->off;
    iov[0].iov_base = iobuf->buf + iobuf->off;
    iov[0].iov_len = nbytes;

    if (closure->interactive && (timing->event == IO_EVENT_STDOUT || timing->event == IO_EVENT_STDERR)) {
	char *nl;

	
	nl = memchr(iov[0].iov_base, '\n', iov[0].iov_len);
	if (nl != NULL) {
	    size_t len = (size_t)(nl - (char *)iov[0].iov_base);
	    if ((nl == iov[0].iov_base && iobuf->lastc != '\r') || (nl != iov[0].iov_base && nl[-1] != '\r')) {
		iov[0].iov_len = len;
		iov[1].iov_base = (char *)"\r\n";
		iov[1].iov_len = 2;
		iovcnt = 2;
		nbytes = iov[0].iov_len + iov[1].iov_len;
		added_cr = true;
	    }
	}
    }

    nwritten = writev(fd, iov, iovcnt);
    switch ((ssize_t)nwritten) {
    case -1:
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to write to %s"), "stdout");
	break;
    case 0:
	
	break;
    default:
	if (added_cr && nwritten >= nbytes - 1) {
	    
	    iobuf->lastc = nwritten == nbytes ? '\n' : '\r';
	} else {
	    
	    iobuf->lastc = *((char *)iov[0].iov_base + nwritten);
	}
	if (added_cr) {
	    
	    nwritten--;
	}
	iobuf->off += nwritten;
	break;
    }

    if (iobuf->off == iobuf->len) {
	
	switch (get_timing_record(closure)) {
	case 0:
	    
	    break;
	case 1:
	    
	    sudo_ev_loopexit(closure->evbase);
	    break;
	default:
	    
	    sudo_ev_loopbreak(closure->evbase);
	    break;
	}
    } else {
	
	if (sudo_ev_add(NULL, closure->output_ev, NULL, false) == -1)
	    sudo_fatal("%s", U_("unable to add event to queue"));
    }
    debug_return;
}


static int parse_expr(struct search_node_list *head, char *argv[], bool sub_expr)
{
    bool or = false, not = false;
    struct search_node *sn;
    char type, **av;
    const char *errstr;
    debug_decl(parse_expr, SUDO_DEBUG_UTIL);

    for (av = argv; *av != NULL; av++) {
	switch (av[0][0]) {
	case 'a': 
	    if (strncmp(*av, "and", strlen(*av)) != 0)
		goto bad;
	    continue;
	case 'o': 
	    if (strncmp(*av, "or", strlen(*av)) != 0)
		goto bad;
	    or = true;
	    continue;
	case '!': 
	    if (av[0][1] != '\0')
		goto bad;
	    not = true;
	    continue;
	case 'c': 
	    if (av[0][1] == '\0')
		sudo_fatalx(U_("ambiguous expression \"%s\""), *av);
	    if (strncmp(*av, "cwd", strlen(*av)) == 0)
		type = ST_CWD;
	    else if (strncmp(*av, "command", strlen(*av)) == 0)
		type = ST_PATTERN;
	    else goto bad;
	    break;
	case 'f': 
	    if (strncmp(*av, "fromdate", strlen(*av)) != 0)
		goto bad;
	    type = ST_FROMDATE;
	    break;
	case 'g': 
	    if (strncmp(*av, "group", strlen(*av)) != 0)
		goto bad;
	    type = ST_RUNASGROUP;
	    break;
	case 'h': 
	    if (strncmp(*av, "host", strlen(*av)) != 0)
		goto bad;
	    type = ST_HOST;
	    break;
	case 'r': 
	    if (strncmp(*av, "runas", strlen(*av)) != 0)
		goto bad;
	    type = ST_RUNASUSER;
	    break;
	case 't': 
	    if (av[0][1] == '\0')
		sudo_fatalx(U_("ambiguous expression \"%s\""), *av);
	    if (strncmp(*av, "todate", strlen(*av)) == 0)
		type = ST_TODATE;
	    else if (strncmp(*av, "tty", strlen(*av)) == 0)
		type = ST_TTY;
	    else goto bad;
	    break;
	case 'u': 
	    if (strncmp(*av, "user", strlen(*av)) != 0)
		goto bad;
	    type = ST_USER;
	    break;
	case '(': 
	    if (av[0][1] != '\0')
		goto bad;
	    type = ST_EXPR;
	    break;
	case ')': 
	    if (av[0][1] != '\0')
		goto bad;
	    if (!sub_expr)
		sudo_fatalx("%s", U_("unmatched ')' in expression"));
	    debug_return_int(av - argv + 1);
	default:
	bad:
	    sudo_fatalx(U_("unknown search term \"%s\""), *av);
	    
	}

	
	if ((sn = calloc(1, sizeof(*sn))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	sn->type = type;
	sn->or = or;
	sn->negated = not;
	if (type == ST_EXPR) {
	    STAILQ_INIT(&sn->u.expr);
	    av += parse_expr(&sn->u.expr, av + 1, true);
	} else {
	    if (*(++av) == NULL)
		sudo_fatalx(U_("%s requires an argument"), av[-1]);
	    if (type == ST_PATTERN) {
		if (!sudo_regex_compile(&sn->u.cmdre, *av, &errstr)) {
		    sudo_fatalx(U_("invalid regular expression \"%s\": %s"), *av, U_(errstr));
		}
	    } else if (type == ST_TODATE || type == ST_FROMDATE) {
		sn->u.tstamp.tv_sec = get_date(*av);
		sn->u.tstamp.tv_nsec = 0;
		if (sn->u.tstamp.tv_sec == -1)
		    sudo_fatalx(U_("could not parse date \"%s\""), *av);
	    } else {
		sn->u.ptr = *av;
	    }
	}
	not = or = false; 
	STAILQ_INSERT_TAIL(head, sn, entries);
    }
    if (sub_expr)
	sudo_fatalx("%s", U_("unmatched '(' in expression"));
    if (or)
	sudo_fatalx("%s", U_("illegal trailing \"or\""));
    if (not)
	sudo_fatalx("%s", U_("illegal trailing \"!\""));

    debug_return_int(av - argv);
}

static bool match_expr(struct search_node_list *head, struct eventlog *evlog, bool last_match)
{
    struct search_node *sn;
    bool res = false, matched = last_match;
    int rc;
    debug_decl(match_expr, SUDO_DEBUG_UTIL);

    STAILQ_FOREACH(sn, head, entries) {
	switch (sn->type) {
	case ST_EXPR:
	    res = match_expr(&sn->u.expr, evlog, matched);
	    break;
	case ST_CWD:
	    if (evlog->cwd != NULL)
		res = strcmp(sn->u.cwd, evlog->cwd) == 0;
	    break;
	case ST_HOST:
	    if (evlog->submithost != NULL)
		res = strcmp(sn->u.host, evlog->submithost) == 0;
	    break;
	case ST_TTY:
	    if (evlog->ttyname != NULL)
		res = strcmp(sn->u.tty, evlog->ttyname) == 0;
	    break;
	case ST_RUNASGROUP:
	    if (evlog->rungroup != NULL)
		res = strcmp(sn->u.runas_group, evlog->rungroup) == 0;
	    break;
	case ST_RUNASUSER:
	    if (evlog->runuser != NULL)
		res = strcmp(sn->u.runas_user, evlog->runuser) == 0;
	    break;
	case ST_USER:
	    if (evlog->submituser != NULL)
		res = strcmp(sn->u.user, evlog->submituser) == 0;
	    break;
	case ST_PATTERN:
	    rc = regexec(&sn->u.cmdre, evlog->command, 0, NULL, 0);
	    if (rc && rc != REG_NOMATCH) {
		char buf[BUFSIZ];
		regerror(rc, &sn->u.cmdre, buf, sizeof(buf));
		sudo_fatalx("%s", buf);
	    }
	    res = rc == REG_NOMATCH ? 0 : 1;
	    break;
	case ST_FROMDATE:
	    res = sudo_timespeccmp(&evlog->submit_time, &sn->u.tstamp, >=);
	    break;
	case ST_TODATE:
	    res = sudo_timespeccmp(&evlog->submit_time, &sn->u.tstamp, <=);
	    break;
	default:
	    sudo_fatalx(U_("unknown search type %d"), sn->type);
	    
	}
	if (sn->negated)
	    res = !res;
	matched = sn->or ? (res || last_match) : (res && last_match);
	last_match = matched;
    }
    debug_return_bool(matched);
}

static int list_session(char *log_dir, regex_t *re, const char *user, const char *tty)
{
    char idbuf[7], *idstr, *cp;
    struct eventlog *evlog = NULL;
    const char *timestr;
    int ret = -1;
    debug_decl(list_session, SUDO_DEBUG_UTIL);

    if ((evlog = iolog_parse_loginfo(-1, log_dir)) == NULL)
	goto done;

    if (evlog->command == NULL || evlog->submituser == NULL || evlog->runuser == NULL) {
	goto done;
    }

    
    if (!STAILQ_EMPTY(&search_expr) && !match_expr(&search_expr, evlog, true))
	goto done;

    
    cp = log_dir + strlen(session_dir) + 1;
    if (IS_IDLOG(cp)) {
	idbuf[0] = cp[0];
	idbuf[1] = cp[1];
	idbuf[2] = cp[3];
	idbuf[3] = cp[4];
	idbuf[4] = cp[6];
	idbuf[5] = cp[7];
	idbuf[6] = '\0';
	idstr = idbuf;
    } else {
	
	idstr = cp;
    }
    
    timestr = get_timestr(evlog->submit_time.tv_sec, 1);
    printf("%s : %s : ", timestr ? timestr : "invalid date", evlog->submituser);
    if (evlog->submithost != NULL)
	printf("HOST=%s ; ", evlog->submithost);
    if (evlog->ttyname != NULL)
	printf("TTY=%s ; ", evlog->ttyname);
    if (evlog->runchroot != NULL)
	printf("CHROOT=%s ; ", evlog->runchroot);
    if (evlog->runcwd != NULL || evlog->cwd != NULL)
	printf("CWD=%s ; ", evlog->runcwd ? evlog->runcwd : evlog->cwd);
    printf("USER=%s ; ", evlog->runuser);
    if (evlog->rungroup != NULL)
	printf("GROUP=%s ; ", evlog->rungroup);
    printf("TSID=%s ; COMMAND=%s\n", idstr, evlog->command);

    ret = 0;

done:
    eventlog_free(evlog);
    debug_return_int(ret);
}

static int session_compare(const void *v1, const void *v2)
{
    const char *s1 = *(const char **)v1;
    const char *s2 = *(const char **)v2;
    return strcmp(s1, s2);
}


static int find_sessions(const char *dir, regex_t *re, const char *user, const char *tty)
{
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    size_t sdlen, sessions_len = 0, sessions_size = 0;
    unsigned int i;
    int len;
    char pathbuf[PATH_MAX], **sessions = NULL;

    bool checked_type = true;

    const bool checked_type = false;

    debug_decl(find_sessions, SUDO_DEBUG_UTIL);

    d = opendir(dir);
    if (d == NULL)
	sudo_fatal(U_("unable to open %s"), dir);

    
    sdlen = strlcpy(pathbuf, dir, sizeof(pathbuf));
    if (sdlen + 1 >= sizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	sudo_fatal("%s/", dir);
    }
    pathbuf[sdlen++] = '/';
    pathbuf[sdlen] = '\0';

    
    while ((dp = readdir(d)) != NULL) {
	
	if (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
	    continue;

	if (checked_type) {
	    if (dp->d_type != DT_DIR) {
		
		if (dp->d_type != DT_UNKNOWN)
		    continue;
		checked_type = false;
	    }
	}


	
	if (sessions_len + 1 > sessions_size) {
	    if (sessions_size == 0)
		sessions_size = 36 * 36 / 2;
	    sessions = reallocarray(sessions, sessions_size, 2 * sizeof(char *));
	    if (sessions == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    sessions_size *= 2;
	}
	if ((sessions[sessions_len] = strdup(dp->d_name)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	sessions_len++;
    }
    closedir(d);

    
    if (sessions != NULL) {
	qsort(sessions, sessions_len, sizeof(char *), session_compare);
	for (i = 0; i < sessions_len; i++) {
	    len = snprintf(&pathbuf[sdlen], sizeof(pathbuf) - sdlen, "%s/log", sessions[i]);
	    if (len < 0 || (size_t)len >= sizeof(pathbuf) - sdlen) {
		errno = ENAMETOOLONG;
		sudo_fatal("%s/%s/log", dir, sessions[i]);
	    }
	    free(sessions[i]);

	    
	    if (lstat(pathbuf, &sb) == 0 && S_ISREG(sb.st_mode)) {
		pathbuf[sdlen + len - 4] = '\0';
		list_session(pathbuf, re, user, tty);
	    } else {
		
		pathbuf[sdlen + len - 4] = '\0';
		if (checked_type || (lstat(pathbuf, &sb) == 0 && S_ISDIR(sb.st_mode)))
		    find_sessions(pathbuf, re, user, tty);
	    }
	}
	free(sessions);
    }

    debug_return_int(0);
}


static int list_sessions(int argc, char **argv, const char *pattern, const char *user, const char *tty)

{
    regex_t rebuf, *re = NULL;
    const char *errstr;
    debug_decl(list_sessions, SUDO_DEBUG_UTIL);

    
    parse_expr(&search_expr, argv, false);

    
    if (pattern) {
	re = &rebuf;
	if (!sudo_regex_compile(re, pattern, &errstr)) {
	    sudo_fatalx(U_("invalid regular expression \"%s\": %s"), pattern, U_(errstr));
	}
    }

    debug_return_int(find_sessions(session_dir, re, user, tty));
}


static void read_keyboard(int fd, int what, void *v)
{
    struct replay_closure *closure = v;
    static bool paused = false;
    struct timespec ts;
    ssize_t nread;
    char ch;
    debug_decl(read_keyboard, SUDO_DEBUG_UTIL);

    nread = read(fd, &ch, 1);
    switch (nread) {
    case -1:
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to read %s"), "stdin");
	break;
    case 0:
	
	break;
    default:
	if (paused) {
	    
	    paused = false;
	    delay_cb(-1, SUDO_EV_TIMEOUT, closure);
	    debug_return;
	}
	switch (ch) {
	case ' ':
	    paused = true;
	    
	    sudo_ev_del(closure->evbase, closure->delay_ev);
	    break;
	case '<':
	    speed_factor /= 2;
	    if (sudo_ev_pending(closure->delay_ev, SUDO_EV_TIMEOUT, &ts)) {
		
		ts.tv_sec *= 2;
		ts.tv_nsec *= 2;
		if (ts.tv_nsec >= 1000000000) {
		    ts.tv_sec++;
		    ts.tv_nsec -= 1000000000;
		}
		if (sudo_ev_add(NULL, closure->delay_ev, &ts, false) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "failed to double remaining delay timeout");
		}
            }
	    break;
	case '>':
	    speed_factor *= 2;
	    if (sudo_ev_pending(closure->delay_ev, SUDO_EV_TIMEOUT, &ts)) {
		
		if (ts.tv_sec & 1)
		    ts.tv_nsec += 500000000;
		ts.tv_sec /= 2;
		ts.tv_nsec /= 2;
		if (sudo_ev_add(NULL, closure->delay_ev, &ts, false) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "failed to halve remaining delay timeout");
		}
            }
	    break;
	case '\r':
	case '\n':
	    
	    sudo_ev_del(closure->evbase, closure->delay_ev);
	    delay_cb(-1, SUDO_EV_TIMEOUT, closure);
	    break;
	default:
	    
	    break;
	}
	break;
    }
    debug_return;
}

static void print_usage(FILE *fp)
{
    fprintf(fp, _("usage: %s [-hnRS] [-d dir] [-m num] [-s num] ID\n"), getprogname());
    fprintf(fp, _("usage: %s [-h] [-d dir] -l [search expression]\n"), getprogname());
}

static void usage(void)
{
    print_usage(stderr);
    exit(EXIT_FAILURE);
}

static void help(void)
{
    (void) printf(_("%s - replay sudo session logs\n\n"), getprogname());
    print_usage(stdout);
    (void) puts(_("\nOptions:\n" "  -d, --directory=dir    specify directory for session logs\n" "  -f, --filter=filter    specify which I/O type(s) to display\n" "  -h, --help             display help message and exit\n" "  -l, --list             list available session IDs, with optional expression\n" "  -m, --max-wait=num     max number of seconds to wait between events\n" "  -n, --non-interactive  no prompts, session is sent to the standard output\n" "  -R, --no-resize        do not attempt to re-size the terminal\n" "  -S, --suspend-wait     wait while the command was suspended\n" "  -s, --speed=num        speed up or slow down output\n" "  -V, --version          display version information and exit"));









    exit(EXIT_SUCCESS);
}


static void sudoreplay_cleanup(void)
{
    restore_terminal_size();
    sudo_term_restore(ttyfd, false);
}
