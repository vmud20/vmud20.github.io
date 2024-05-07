































































































static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_cgroups_agent_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_time_change_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_user_lookup_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_jobs_in_progress(sd_event_source *source, usec_t usec, void *userdata);
static int manager_dispatch_run_queue(sd_event_source *source, void *userdata);
static int manager_dispatch_sigchld(sd_event_source *source, void *userdata);
static int manager_dispatch_timezone_change(sd_event_source *source, const struct inotify_event *event, void *userdata);
static int manager_run_environment_generators(Manager *m);
static int manager_run_generators(Manager *m);

static void manager_watch_jobs_in_progress(Manager *m) {
        usec_t next;
        int r;

        assert(m);

        
        if (!manager_is_confirm_spawn_disabled(m))
                return;

        if (m->jobs_in_progress_event_source)
                return;

        next = now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_WAIT_USEC;
        r = sd_event_add_time( m->event, &m->jobs_in_progress_event_source, CLOCK_MONOTONIC, next, 0, manager_dispatch_jobs_in_progress, m);




        if (r < 0)
                return;

        (void) sd_event_source_set_description(m->jobs_in_progress_event_source, "manager-jobs-in-progress");
}



static void draw_cylon(char buffer[], size_t buflen, unsigned width, unsigned pos) {
        char *p = buffer;

        assert(buflen >= CYLON_BUFFER_EXTRA + width + 1);
        assert(pos <= width+1); 

        if (pos > 1) {
                if (pos > 2)
                        p = mempset(p, ' ', pos-2);
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_RED);
                *p++ = '*';
        }

        if (pos > 0 && pos <= width) {
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_HIGHLIGHT_RED);
                *p++ = '*';
        }

        if (log_get_show_color())
                p = stpcpy(p, ANSI_NORMAL);

        if (pos < width) {
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_RED);
                *p++ = '*';
                if (pos < width-1)
                        p = mempset(p, ' ', width-1-pos);
                if (log_get_show_color())
                        strcpy(p, ANSI_NORMAL);
        }
}

void manager_flip_auto_status(Manager *m, bool enable) {
        assert(m);

        if (enable) {
                if (m->show_status == SHOW_STATUS_AUTO)
                        manager_set_show_status(m, SHOW_STATUS_TEMPORARY);
        } else {
                if (m->show_status == SHOW_STATUS_TEMPORARY)
                        manager_set_show_status(m, SHOW_STATUS_AUTO);
        }
}

static void manager_print_jobs_in_progress(Manager *m) {
        _cleanup_free_ char *job_of_n = NULL;
        Iterator i;
        Job *j;
        unsigned counter = 0, print_nr;
        char cylon[6 + CYLON_BUFFER_EXTRA + 1];
        unsigned cylon_pos;
        char time[FORMAT_TIMESPAN_MAX], limit[FORMAT_TIMESPAN_MAX] = "no limit";
        uint64_t x;

        assert(m);
        assert(m->n_running_jobs > 0);

        manager_flip_auto_status(m, true);

        print_nr = (m->jobs_in_progress_iteration / JOBS_IN_PROGRESS_PERIOD_DIVISOR) % m->n_running_jobs;

        HASHMAP_FOREACH(j, m->jobs, i)
                if (j->state == JOB_RUNNING && counter++ == print_nr)
                        break;

        
        assert(counter == print_nr + 1);
        assert(j);

        cylon_pos = m->jobs_in_progress_iteration % 14;
        if (cylon_pos >= 8)
                cylon_pos = 14 - cylon_pos;
        draw_cylon(cylon, sizeof(cylon), 6, cylon_pos);

        m->jobs_in_progress_iteration++;

        if (m->n_running_jobs > 1) {
                if (asprintf(&job_of_n, "(%u of %u) ", counter, m->n_running_jobs) < 0)
                        job_of_n = NULL;
        }

        format_timespan(time, sizeof(time), now(CLOCK_MONOTONIC) - j->begin_usec, 1*USEC_PER_SEC);
        if (job_get_timeout(j, &x) > 0)
                format_timespan(limit, sizeof(limit), x - j->begin_usec, 1*USEC_PER_SEC);

        manager_status_printf(m, STATUS_TYPE_EPHEMERAL, cylon, "%sA %s job is running for %s (%s / %s)", strempty(job_of_n), job_type_to_string(j->type), unit_description(j->unit), time, limit);




}

static int have_ask_password(void) {
        _cleanup_closedir_ DIR *dir;
        struct dirent *de;

        dir = opendir("/run/systemd/ask-password");
        if (!dir) {
                if (errno == ENOENT)
                        return false;
                else return -errno;
        }

        FOREACH_DIRENT_ALL(de, dir, return -errno) {
                if (startswith(de->d_name, "ask."))
                        return true;
        }
        return false;
}

static int manager_dispatch_ask_password_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);

        (void) flush_fd(fd);

        m->have_ask_password = have_ask_password();
        if (m->have_ask_password < 0)
                
                log_error_errno(m->have_ask_password, "Failed to list /run/systemd/ask-password: %m");

        return 0;
}

static void manager_close_ask_password(Manager *m) {
        assert(m);

        m->ask_password_event_source = sd_event_source_unref(m->ask_password_event_source);
        m->ask_password_inotify_fd = safe_close(m->ask_password_inotify_fd);
        m->have_ask_password = -EINVAL;
}

static int manager_check_ask_password(Manager *m) {
        int r;

        assert(m);

        if (!m->ask_password_event_source) {
                assert(m->ask_password_inotify_fd < 0);

                mkdir_p_label("/run/systemd/ask-password", 0755);

                m->ask_password_inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (m->ask_password_inotify_fd < 0)
                        return log_error_errno(errno, "inotify_init1() failed: %m");

                if (inotify_add_watch(m->ask_password_inotify_fd, "/run/systemd/ask-password", IN_CREATE|IN_DELETE|IN_MOVE) < 0) {
                        log_error_errno(errno, "Failed to add watch on /run/systemd/ask-password: %m");
                        manager_close_ask_password(m);
                        return -errno;
                }

                r = sd_event_add_io(m->event, &m->ask_password_event_source, m->ask_password_inotify_fd, EPOLLIN, manager_dispatch_ask_password_fd, m);

                if (r < 0) {
                        log_error_errno(errno, "Failed to add event source for /run/systemd/ask-password: %m");
                        manager_close_ask_password(m);
                        return -errno;
                }

                (void) sd_event_source_set_description(m->ask_password_event_source, "manager-ask-password");

                
                manager_dispatch_ask_password_fd(m->ask_password_event_source, m->ask_password_inotify_fd, EPOLLIN, m);
        }

        return m->have_ask_password;
}

static int manager_watch_idle_pipe(Manager *m) {
        int r;

        assert(m);

        if (m->idle_pipe_event_source)
                return 0;

        if (m->idle_pipe[2] < 0)
                return 0;

        r = sd_event_add_io(m->event, &m->idle_pipe_event_source, m->idle_pipe[2], EPOLLIN, manager_dispatch_idle_pipe_fd, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch idle pipe: %m");

        (void) sd_event_source_set_description(m->idle_pipe_event_source, "manager-idle-pipe");

        return 0;
}

static void manager_close_idle_pipe(Manager *m) {
        assert(m);

        m->idle_pipe_event_source = sd_event_source_unref(m->idle_pipe_event_source);

        safe_close_pair(m->idle_pipe);
        safe_close_pair(m->idle_pipe + 2);
}

static int manager_setup_time_change(Manager *m) {
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        m->time_change_event_source = sd_event_source_unref(m->time_change_event_source);
        m->time_change_fd = safe_close(m->time_change_fd);

        m->time_change_fd = time_change_fd();
        if (m->time_change_fd < 0)
                return log_error_errno(m->time_change_fd, "Failed to create timer change timer fd: %m");

        r = sd_event_add_io(m->event, &m->time_change_event_source, m->time_change_fd, EPOLLIN, manager_dispatch_time_change_fd, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create time change event source: %m");

        
        r = sd_event_source_set_priority(m->time_change_event_source, SD_EVENT_PRIORITY_NORMAL-1);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of time change event sources: %m");

        (void) sd_event_source_set_description(m->time_change_event_source, "manager-time-change");

        log_debug("Set up TFD_TIMER_CANCEL_ON_SET timerfd.");

        return 0;
}

static int manager_read_timezone_stat(Manager *m) {
        struct stat st;
        bool changed;

        assert(m);

        
        if (lstat("/etc/localtime", &st) < 0) {
                log_debug_errno(errno, "Failed to stat /etc/localtime, ignoring: %m");
                changed = m->etc_localtime_accessible;
                m->etc_localtime_accessible = false;
        } else {
                usec_t k;

                k = timespec_load(&st.st_mtim);
                changed = !m->etc_localtime_accessible || k != m->etc_localtime_mtime;

                m->etc_localtime_mtime = k;
                m->etc_localtime_accessible = true;
        }

        return changed;
}

static int manager_setup_timezone_change(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *new_event = NULL;
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        

        r = sd_event_add_inotify(m->event, &new_event, "/etc/localtime", IN_ATTRIB|IN_MOVE_SELF|IN_CLOSE_WRITE|IN_DONT_FOLLOW, manager_dispatch_timezone_change, m);
        if (r == -ENOENT) {
                

                log_debug_errno(r, "/etc/localtime doesn't exist yet, watching /etc instead.");
                r = sd_event_add_inotify(m->event, &new_event, "/etc", IN_CREATE|IN_MOVED_TO|IN_ONLYDIR, manager_dispatch_timezone_change, m);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to create timezone change event source: %m");

        
        r = sd_event_source_set_priority(new_event, SD_EVENT_PRIORITY_NORMAL-1);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of timezone change event sources: %m");

        sd_event_source_unref(m->timezone_change_event_source);
        m->timezone_change_event_source = TAKE_PTR(new_event);

        return 0;
}

static int enable_special_signals(Manager *m) {
        _cleanup_close_ int fd = -1;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        
        if (reboot(RB_DISABLE_CAD) < 0 && !IN_SET(errno, EPERM, EINVAL))
                log_warning_errno(errno, "Failed to enable ctrl-alt-del handling: %m");

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                
                if (fd != -ENOENT)
                        log_warning_errno(errno, "Failed to open /dev/tty0: %m");
        } else {
                
                if (ioctl(fd, KDSIGACCEPT, SIGWINCH) < 0)
                        log_warning_errno(errno, "Failed to enable kbrequest handling: %m");
        }

        return 0;
}



static int manager_setup_signals(Manager *m) {
        struct sigaction sa = {
                .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDSTOP|SA_RESTART, };

        sigset_t mask;
        int r;

        assert(m);

        assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

        

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGCHLD, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2, SIGINT, SIGWINCH, SIGPWR,  SIGRTMIN+0, SIGRTMIN+1, SIGRTMIN+2, SIGRTMIN+3, SIGRTMIN+4, SIGRTMIN+5, SIGRTMIN+6,    SIGRTMIN+13, SIGRTMIN+14, SIGRTMIN+15, SIGRTMIN+16,    SIGRTMIN+20, SIGRTMIN+21, SIGRTMIN+22, SIGRTMIN+23, SIGRTMIN+24,      RTSIG_IF_AVAILABLE(SIGRTMIN+26), RTSIG_IF_AVAILABLE(SIGRTMIN+27), RTSIG_IF_AVAILABLE(SIGRTMIN+28), RTSIG_IF_AVAILABLE(SIGRTMIN+29),   -1);










































        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (m->signal_fd < 0)
                return -errno;

        r = sd_event_add_io(m->event, &m->signal_event_source, m->signal_fd, EPOLLIN, manager_dispatch_signal_fd, m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->signal_event_source, "manager-signal");

        
        r = sd_event_source_set_priority(m->signal_event_source, SD_EVENT_PRIORITY_NORMAL-6);
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(m))
                return enable_special_signals(m);

        return 0;
}

static void manager_sanitize_environment(Manager *m) {
        assert(m);

        
        strv_env_unset_many( m->environment, "EXIT_CODE", "EXIT_STATUS", "INVOCATION_ID", "JOURNAL_STREAM", "LISTEN_FDNAMES", "LISTEN_FDS", "LISTEN_PID", "MAINPID", "MANAGERPID", "NOTIFY_SOCKET", "REMOTE_ADDR", "REMOTE_PORT", "SERVICE_RESULT", "WATCHDOG_PID", "WATCHDOG_USEC", NULL);

















        
        strv_sort(m->environment);
}

static int manager_default_environment(Manager *m) {
        assert(m);

        if (MANAGER_IS_SYSTEM(m)) {
                
                m->environment = strv_new("PATH=" DEFAULT_PATH, NULL);

                
                locale_setup(&m->environment);
        } else  m->environment = strv_copy(environ);


        if (!m->environment)
                return -ENOMEM;

        manager_sanitize_environment(m);

        return 0;
}

static int manager_setup_prefix(Manager *m) {
        struct table_entry {
                uint64_t type;
                const char *suffix;
        };

        static const struct table_entry paths_system[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME] = { SD_PATH_SYSTEM_RUNTIME, NULL }, [EXEC_DIRECTORY_STATE] = { SD_PATH_SYSTEM_STATE_PRIVATE, NULL }, [EXEC_DIRECTORY_CACHE] = { SD_PATH_SYSTEM_STATE_CACHE, NULL }, [EXEC_DIRECTORY_LOGS] = { SD_PATH_SYSTEM_STATE_LOGS, NULL }, [EXEC_DIRECTORY_CONFIGURATION] = { SD_PATH_SYSTEM_CONFIGURATION, NULL }, };





        static const struct table_entry paths_user[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME] = { SD_PATH_USER_RUNTIME, NULL }, [EXEC_DIRECTORY_STATE] = { SD_PATH_USER_CONFIGURATION, NULL }, [EXEC_DIRECTORY_CACHE] = { SD_PATH_USER_STATE_CACHE, NULL }, [EXEC_DIRECTORY_LOGS] = { SD_PATH_USER_CONFIGURATION, "log" }, [EXEC_DIRECTORY_CONFIGURATION] = { SD_PATH_USER_CONFIGURATION, NULL }, };





        const struct table_entry *p;
        ExecDirectoryType i;
        int r;

        assert(m);

        if (MANAGER_IS_SYSTEM(m))
                p = paths_system;
        else p = paths_user;

        for (i = 0; i < _EXEC_DIRECTORY_TYPE_MAX; i++) {
                r = sd_path_home(p[i].type, p[i].suffix, &m->prefix[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_setup_run_queue(Manager *m) {
        int r;

        assert(m);
        assert(!m->run_queue_event_source);

        r = sd_event_add_defer(m->event, &m->run_queue_event_source, manager_dispatch_run_queue, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->run_queue_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(m->run_queue_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->run_queue_event_source, "manager-run-queue");

        return 0;
}

static int manager_setup_sigchld_event_source(Manager *m) {
        int r;

        assert(m);
        assert(!m->sigchld_event_source);

        r = sd_event_add_defer(m->event, &m->sigchld_event_source, manager_dispatch_sigchld, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->sigchld_event_source, SD_EVENT_PRIORITY_NORMAL-7);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->sigchld_event_source, "manager-sigchld");

        return 0;
}

int manager_new(UnitFileScope scope, ManagerTestRunFlags test_run_flags, Manager **_m) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(_m);
        assert(IN_SET(scope, UNIT_FILE_SYSTEM, UNIT_FILE_USER));

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .unit_file_scope = scope, .objective = _MANAGER_OBJECTIVE_INVALID,  .default_timer_accuracy_usec = USEC_PER_MINUTE, .default_memory_accounting = MEMORY_ACCOUNTING_DEFAULT, .default_tasks_accounting = true, .default_tasks_max = UINT64_MAX, .default_timeout_start_usec = DEFAULT_TIMEOUT_USEC, .default_timeout_stop_usec = DEFAULT_TIMEOUT_USEC, .default_restart_usec = DEFAULT_RESTART_USEC,  .original_log_level = -1, .original_log_target = _LOG_TARGET_INVALID,  .notify_fd = -1, .cgroups_agent_fd = -1, .signal_fd = -1, .time_change_fd = -1, .user_lookup_fds = { -1, -1 }, .private_listen_fd = -1, .dev_autofs_fd = -1, .cgroup_inotify_fd = -1, .pin_cgroupfs_fd = -1, .ask_password_inotify_fd = -1, .idle_pipe = { -1, -1, -1, -1},   .current_job_id = 1,  .have_ask_password = -EINVAL, .first_boot = -1, .test_run_flags = test_run_flags, };

































        if (MANAGER_IS_SYSTEM(m) && detect_container() <= 0)
                boot_timestamps(m->timestamps + MANAGER_TIMESTAMP_USERSPACE, m->timestamps + MANAGER_TIMESTAMP_FIRMWARE, m->timestamps + MANAGER_TIMESTAMP_LOADER);



        
        if (MANAGER_IS_SYSTEM(m)) {
                m->unit_log_field = "UNIT=";
                m->unit_log_format_string = "UNIT=%s";

                m->invocation_log_field = "INVOCATION_ID=";
                m->invocation_log_format_string = "INVOCATION_ID=%s";
        } else {
                m->unit_log_field = "USER_UNIT=";
                m->unit_log_format_string = "USER_UNIT=%s";

                m->invocation_log_field = "USER_INVOCATION_ID=";
                m->invocation_log_format_string = "USER_INVOCATION_ID=%s";
        }

        
        RATELIMIT_INIT(m->ctrl_alt_del_ratelimit, 2 * USEC_PER_SEC, 7);

        r = manager_default_environment(m);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->units, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->jobs, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->cgroup_unit, &path_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->watch_bus, &string_hash_ops);
        if (r < 0)
                return r;

        r = manager_setup_prefix(m);
        if (r < 0)
                return r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = manager_setup_run_queue(m);
        if (r < 0)
                return r;

        if (test_run_flags == MANAGER_TEST_RUN_MINIMAL) {
                m->cgroup_root = strdup("");
                if (!m->cgroup_root)
                        return -ENOMEM;
        } else {
                r = manager_setup_signals(m);
                if (r < 0)
                        return r;

                r = manager_setup_cgroup(m);
                if (r < 0)
                        return r;

                r = manager_setup_time_change(m);
                if (r < 0)
                        return r;

                r = manager_read_timezone_stat(m);
                if (r < 0)
                        return r;

                (void) manager_setup_timezone_change(m);

                r = manager_setup_sigchld_event_source(m);
                if (r < 0)
                        return r;
        }

        if (MANAGER_IS_SYSTEM(m) && test_run_flags == 0) {
                r = mkdir_label("/run/systemd/units", 0755);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        m->taint_usr = !in_initrd() && dir_is_empty("/usr") > 0;


        

        *_m = TAKE_PTR(m);

        return 0;
}

static int manager_setup_notify(Manager *m) {
        int r;

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        if (m->notify_fd < 0) {
                _cleanup_close_ int fd = -1;
                union sockaddr_union sa = {};
                int salen;

                
                m->notify_socket = mfree(m->notify_socket);
                m->notify_event_source = sd_event_source_unref(m->notify_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate notification socket: %m");

                fd_inc_rcvbuf(fd, NOTIFY_RCVBUF_SIZE);

                m->notify_socket = strappend(m->prefix[EXEC_DIRECTORY_RUNTIME], "/systemd/notify");
                if (!m->notify_socket)
                        return log_oom();

                salen = sockaddr_un_set_path(&sa.un, m->notify_socket);
                if (salen < 0)
                        return log_error_errno(salen, "Notify socket '%s' not valid for AF_UNIX socket address, refusing.", m->notify_socket);

                (void) mkdir_parents_label(m->notify_socket, 0755);
                (void) sockaddr_un_unlink(&sa.un);

                r = bind(fd, &sa.sa, salen);
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", m->notify_socket);

                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        return log_error_errno(r, "SO_PASSCRED failed: %m");

                m->notify_fd = TAKE_FD(fd);

                log_debug("Using notification socket %s", m->notify_socket);
        }

        if (!m->notify_event_source) {
                r = sd_event_add_io(m->event, &m->notify_event_source, m->notify_fd, EPOLLIN, manager_dispatch_notify_fd, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate notify event source: %m");

                
                r = sd_event_source_set_priority(m->notify_event_source, SD_EVENT_PRIORITY_NORMAL-8);
                if (r < 0)
                        return log_error_errno(r, "Failed to set priority of notify event source: %m");

                (void) sd_event_source_set_description(m->notify_event_source, "manager-notify");
        }

        return 0;
}

static int manager_setup_cgroups_agent(Manager *m) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX, .un.sun_path = "/run/systemd/cgroups-agent", };

        int r;

        

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        if (!MANAGER_IS_SYSTEM(m))
                return 0;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether unified cgroups hierarchy is used: %m");
        if (r > 0) 
                return 0;

        if (m->cgroups_agent_fd < 0) {
                _cleanup_close_ int fd = -1;

                
                m->cgroups_agent_event_source = sd_event_source_unref(m->cgroups_agent_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate cgroups agent socket: %m");

                fd_inc_rcvbuf(fd, CGROUPS_AGENT_RCVBUF_SIZE);

                (void) sockaddr_un_unlink(&sa.un);

                
                RUN_WITH_UMASK(0077)
                        r = bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                m->cgroups_agent_fd = TAKE_FD(fd);
        }

        if (!m->cgroups_agent_event_source) {
                r = sd_event_add_io(m->event, &m->cgroups_agent_event_source, m->cgroups_agent_fd, EPOLLIN, manager_dispatch_cgroups_agent_fd, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate cgroups agent event source: %m");

                
                r = sd_event_source_set_priority(m->cgroups_agent_event_source, SD_EVENT_PRIORITY_NORMAL-4);
                if (r < 0)
                        return log_error_errno(r, "Failed to set priority of cgroups agent event source: %m");

                (void) sd_event_source_set_description(m->cgroups_agent_event_source, "manager-cgroups-agent");
        }

        return 0;
}

static int manager_setup_user_lookup_fd(Manager *m) {
        int r;

        assert(m);

        

        if (m->user_lookup_fds[0] < 0) {

                
                safe_close_pair(m->user_lookup_fds);
                m->user_lookup_event_source = sd_event_source_unref(m->user_lookup_event_source);

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, m->user_lookup_fds) < 0)
                        return log_error_errno(errno, "Failed to allocate user lookup socket: %m");

                (void) fd_inc_rcvbuf(m->user_lookup_fds[0], NOTIFY_RCVBUF_SIZE);
        }

        if (!m->user_lookup_event_source) {
                r = sd_event_add_io(m->event, &m->user_lookup_event_source, m->user_lookup_fds[0], EPOLLIN, manager_dispatch_user_lookup_fd, m);
                if (r < 0)
                        return log_error_errno(errno, "Failed to allocate user lookup event source: %m");

                
                r = sd_event_source_set_priority(m->user_lookup_event_source, SD_EVENT_PRIORITY_NORMAL-11);
                if (r < 0)
                        return log_error_errno(errno, "Failed to set priority ot user lookup event source: %m");

                (void) sd_event_source_set_description(m->user_lookup_event_source, "user-lookup");
        }

        return 0;
}

static unsigned manager_dispatch_cleanup_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;

        assert(m);

        while ((u = m->cleanup_queue)) {
                assert(u->in_cleanup_queue);

                unit_free(u);
                n++;
        }

        return n;
}

enum {
        GC_OFFSET_IN_PATH,   GC_OFFSET_UNSURE, GC_OFFSET_GOOD, GC_OFFSET_BAD, _GC_OFFSET_MAX };





static void unit_gc_mark_good(Unit *u, unsigned gc_marker) {
        Unit *other;
        Iterator i;
        void *v;

        u->gc_marker = gc_marker + GC_OFFSET_GOOD;

        
        HASHMAP_FOREACH_KEY(v, other, u->dependencies[UNIT_REFERENCES], i)
                if (other->gc_marker == gc_marker + GC_OFFSET_UNSURE)
                        unit_gc_mark_good(other, gc_marker);
}

static void unit_gc_sweep(Unit *u, unsigned gc_marker) {
        Unit *other;
        bool is_bad;
        Iterator i;
        void *v;

        assert(u);

        if (IN_SET(u->gc_marker - gc_marker, GC_OFFSET_GOOD, GC_OFFSET_BAD, GC_OFFSET_UNSURE, GC_OFFSET_IN_PATH))
                return;

        if (u->in_cleanup_queue)
                goto bad;

        if (!unit_may_gc(u))
                goto good;

        u->gc_marker = gc_marker + GC_OFFSET_IN_PATH;

        is_bad = true;

        HASHMAP_FOREACH_KEY(v, other, u->dependencies[UNIT_REFERENCED_BY], i) {
                unit_gc_sweep(other, gc_marker);

                if (other->gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (other->gc_marker != gc_marker + GC_OFFSET_BAD)
                        is_bad = false;
        }

        if (u->refs_by_target) {
                const UnitRef *ref;

                LIST_FOREACH(refs_by_target, ref, u->refs_by_target) {
                        unit_gc_sweep(ref->source, gc_marker);

                        if (ref->source->gc_marker == gc_marker + GC_OFFSET_GOOD)
                                goto good;

                        if (ref->source->gc_marker != gc_marker + GC_OFFSET_BAD)
                                is_bad = false;
                }
        }

        if (is_bad)
                goto bad;

        
        u->gc_marker = gc_marker + GC_OFFSET_UNSURE;
        unit_add_to_gc_queue(u);
        return;

bad:
        
        u->gc_marker = gc_marker + GC_OFFSET_BAD;
        unit_add_to_cleanup_queue(u);
        return;

good:
        unit_gc_mark_good(u, gc_marker);
}

static unsigned manager_dispatch_gc_unit_queue(Manager *m) {
        unsigned n = 0, gc_marker;
        Unit *u;

        assert(m);

        

        m->gc_marker += _GC_OFFSET_MAX;
        if (m->gc_marker + _GC_OFFSET_MAX <= _GC_OFFSET_MAX)
                m->gc_marker = 1;

        gc_marker = m->gc_marker;

        while ((u = m->gc_unit_queue)) {
                assert(u->in_gc_queue);

                unit_gc_sweep(u, gc_marker);

                LIST_REMOVE(gc_queue, m->gc_unit_queue, u);
                u->in_gc_queue = false;

                n++;

                if (IN_SET(u->gc_marker - gc_marker, GC_OFFSET_BAD, GC_OFFSET_UNSURE)) {
                        if (u->id)
                                log_unit_debug(u, "Collecting.");
                        u->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue(u);
                }
        }

        return n;
}

static unsigned manager_dispatch_gc_job_queue(Manager *m) {
        unsigned n = 0;
        Job *j;

        assert(m);

        while ((j = m->gc_job_queue)) {
                assert(j->in_gc_queue);

                LIST_REMOVE(gc_queue, m->gc_job_queue, j);
                j->in_gc_queue = false;

                n++;

                if (!job_may_gc(j))
                        continue;

                log_unit_debug(j->unit, "Collecting job.");
                (void) job_finish_and_invalidate(j, JOB_COLLECTED, false, false);
        }

        return n;
}

static unsigned manager_dispatch_stop_when_unneeded_queue(Manager *m) {
        unsigned n = 0;
        Unit *u;
        int r;

        assert(m);

        while ((u = m->stop_when_unneeded_queue)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                assert(m->stop_when_unneeded_queue);

                assert(u->in_stop_when_unneeded_queue);
                LIST_REMOVE(stop_when_unneeded_queue, m->stop_when_unneeded_queue, u);
                u->in_stop_when_unneeded_queue = false;

                n++;

                if (!unit_is_unneeded(u))
                        continue;

                log_unit_debug(u, "Unit is not needed anymore.");

                

                if (!ratelimit_below(&u->auto_stop_ratelimit)) {
                        log_unit_warning(u, "Unit not needed anymore, but not stopping since we tried this too often recently.");
                        continue;
                }

                
                r = manager_add_job(u->manager, JOB_STOP, u, JOB_FAIL, &error, NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enqueue stop job, ignoring: %s", bus_error_message(&error, r));
        }

        return n;
}

static void manager_clear_jobs_and_units(Manager *m) {
        Unit *u;

        assert(m);

        while ((u = hashmap_first(m->units)))
                unit_free(u);

        manager_dispatch_cleanup_queue(m);

        assert(!m->load_queue);
        assert(!m->run_queue);
        assert(!m->dbus_unit_queue);
        assert(!m->dbus_job_queue);
        assert(!m->cleanup_queue);
        assert(!m->gc_unit_queue);
        assert(!m->gc_job_queue);
        assert(!m->stop_when_unneeded_queue);

        assert(hashmap_isempty(m->jobs));
        assert(hashmap_isempty(m->units));

        m->n_on_console = 0;
        m->n_running_jobs = 0;
        m->n_installed_jobs = 0;
        m->n_failed_jobs = 0;
}

Manager* manager_free(Manager *m) {
        ExecDirectoryType dt;
        UnitType c;

        if (!m)
                return NULL;

        manager_clear_jobs_and_units(m);

        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

        
        manager_shutdown_cgroup(m, IN_SET(m->objective, MANAGER_EXIT, MANAGER_REBOOT, MANAGER_POWEROFF, MANAGER_HALT, MANAGER_KEXEC));

        lookup_paths_flush_generator(&m->lookup_paths);

        bus_done(m);

        exec_runtime_vacuum(m);
        hashmap_free(m->exec_runtime_by_id);

        dynamic_user_vacuum(m, false);
        hashmap_free(m->dynamic_users);

        hashmap_free(m->units);
        hashmap_free(m->units_by_invocation_id);
        hashmap_free(m->jobs);
        hashmap_free(m->watch_pids);
        hashmap_free(m->watch_bus);

        set_free(m->startup_units);
        set_free(m->failed_units);

        sd_event_source_unref(m->signal_event_source);
        sd_event_source_unref(m->sigchld_event_source);
        sd_event_source_unref(m->notify_event_source);
        sd_event_source_unref(m->cgroups_agent_event_source);
        sd_event_source_unref(m->time_change_event_source);
        sd_event_source_unref(m->timezone_change_event_source);
        sd_event_source_unref(m->jobs_in_progress_event_source);
        sd_event_source_unref(m->run_queue_event_source);
        sd_event_source_unref(m->user_lookup_event_source);
        sd_event_source_unref(m->sync_bus_names_event_source);

        safe_close(m->signal_fd);
        safe_close(m->notify_fd);
        safe_close(m->cgroups_agent_fd);
        safe_close(m->time_change_fd);
        safe_close_pair(m->user_lookup_fds);

        manager_close_ask_password(m);

        manager_close_idle_pipe(m);

        sd_event_unref(m->event);

        free(m->notify_socket);

        lookup_paths_free(&m->lookup_paths);
        strv_free(m->environment);

        hashmap_free(m->cgroup_unit);
        set_free_free(m->unit_path_cache);

        free(m->switch_root);
        free(m->switch_root_init);

        rlimit_free_all(m->rlimit);

        assert(hashmap_isempty(m->units_requiring_mounts_for));
        hashmap_free(m->units_requiring_mounts_for);

        hashmap_free(m->uid_refs);
        hashmap_free(m->gid_refs);

        for (dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++)
                m->prefix[dt] = mfree(m->prefix[dt]);

        return mfree(m);
}

static void manager_enumerate_perpetual(Manager *m) {
        UnitType c;

        assert(m);

        
        for (c = 0; c < _UNIT_TYPE_MAX; c++) {
                if (!unit_type_supported(c)) {
                        log_debug("Unit type .%s is not supported on this system.", unit_type_to_string(c));
                        continue;
                }

                if (unit_vtable[c]->enumerate_perpetual)
                        unit_vtable[c]->enumerate_perpetual(m);
        }
}

static void manager_enumerate(Manager *m) {
        UnitType c;

        assert(m);

        
        for (c = 0; c < _UNIT_TYPE_MAX; c++) {
                if (!unit_type_supported(c)) {
                        log_debug("Unit type .%s is not supported on this system.", unit_type_to_string(c));
                        continue;
                }

                if (unit_vtable[c]->enumerate)
                        unit_vtable[c]->enumerate(m);
        }

        manager_dispatch_load_queue(m);
}

static void manager_coldplug(Manager *m) {
        Iterator i;
        Unit *u;
        char *k;
        int r;

        assert(m);

        log_debug("Invoking unit coldplug() handlers…");

        
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                
                if (u->id != k)
                        continue;

                r = unit_coldplug(u);
                if (r < 0)
                        log_warning_errno(r, "We couldn't coldplug %s, proceeding anyway: %m", u->id);
        }
}

static void manager_catchup(Manager *m) {
        Iterator i;
        Unit *u;
        char *k;

        assert(m);

        log_debug("Invoking unit catchup() handlers…");

        
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                
                if (u->id != k)
                        continue;

                unit_catchup(u);
        }
}

static void manager_build_unit_path_cache(Manager *m) {
        char **i;
        int r;

        assert(m);

        set_free_free(m->unit_path_cache);

        m->unit_path_cache = set_new(&path_hash_ops);
        if (!m->unit_path_cache) {
                r = -ENOMEM;
                goto fail;
        }

        

        STRV_FOREACH(i, m->lookup_paths.search_path) {
                _cleanup_closedir_ DIR *d = NULL;
                struct dirent *de;

                d = opendir(*i);
                if (!d) {
                        if (errno != ENOENT)
                                log_warning_errno(errno, "Failed to open directory %s, ignoring: %m", *i);
                        continue;
                }

                FOREACH_DIRENT(de, d, r = -errno; goto fail) {
                        char *p;

                        p = strjoin(streq(*i, "/") ? "" : *i, "/", de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        r = set_consume(m->unit_path_cache, p);
                        if (r < 0)
                                goto fail;
                }
        }

        return;

fail:
        log_warning_errno(r, "Failed to build unit path cache, proceeding without: %m");
        m->unit_path_cache = set_free_free(m->unit_path_cache);
}

static void manager_distribute_fds(Manager *m, FDSet *fds) {
        Iterator i;
        Unit *u;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i) {

                if (fdset_size(fds) <= 0)
                        break;

                if (!UNIT_VTABLE(u)->distribute_fds)
                        continue;

                UNIT_VTABLE(u)->distribute_fds(u, fds);
        }
}

static bool manager_dbus_is_running(Manager *m, bool deserialized) {
        Unit *u;

        assert(m);

        

        if (MANAGER_IS_TEST_RUN(m))
                return false;

        u = manager_get_unit(m, SPECIAL_DBUS_SOCKET);
        if (!u)
                return false;
        if ((deserialized ? SOCKET(u)->deserialized_state : SOCKET(u)->state) != SOCKET_RUNNING)
                return false;

        u = manager_get_unit(m, SPECIAL_DBUS_SERVICE);
        if (!u)
                return false;
        if (!IN_SET((deserialized ? SERVICE(u)->deserialized_state : SERVICE(u)->state), SERVICE_RUNNING, SERVICE_RELOAD))
                return false;

        return true;
}

static void manager_setup_bus(Manager *m) {
        assert(m);

        
        (void) bus_init_private(m);

        
        if (MANAGER_IS_USER(m))
                (void) bus_init_system(m);

        
        if (manager_dbus_is_running(m, MANAGER_IS_RELOADING(m))) {
                (void) bus_init_api(m);

                if (MANAGER_IS_SYSTEM(m))
                        (void) bus_init_system(m);
        }
}

static void manager_preset_all(Manager *m) {
        int r;

        assert(m);

        if (m->first_boot <= 0)
                return;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (MANAGER_IS_TEST_RUN(m))
                return;

        
        r = unit_file_preset_all(UNIT_FILE_SYSTEM, 0, NULL, UNIT_FILE_PRESET_ENABLE_ONLY, NULL, 0);
        if (r < 0)
                log_full_errno(r == -EEXIST ? LOG_NOTICE : LOG_WARNING, r, "Failed to populate /etc with preset unit settings, ignoring: %m");
        else log_info("Populated /etc with preset unit settings.");
}

static void manager_vacuum(Manager *m) {
        assert(m);

        
        dynamic_user_vacuum(m, true);

        
        manager_vacuum_uid_refs(m);
        manager_vacuum_gid_refs(m);

        
        exec_runtime_vacuum(m);
}

static void manager_ready(Manager *m) {
        assert(m);

        

        m->objective = MANAGER_OK; 

        
        manager_recheck_journal(m);
        manager_recheck_dbus(m);

        
        (void) manager_enqueue_sync_bus_names(m);

        
        manager_catchup(m);
}

static Manager* manager_reloading_start(Manager *m) {
        m->n_reloading++;
        return m;
}
static void manager_reloading_stopp(Manager **m) {
        if (*m) {
                assert((*m)->n_reloading > 0);
                (*m)->n_reloading--;
        }
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r;

        assert(m);

        
        r = lookup_paths_init(&m->lookup_paths, m->unit_file_scope, MANAGER_IS_TEST_RUN(m) ? LOOKUP_PATHS_TEMPORARY_GENERATED : 0, NULL);

        if (r < 0)
                return log_error_errno(r, "Failed to initialize path lookup table: %m");

        dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_GENERATORS_START));
        r = manager_run_environment_generators(m);
        if (r >= 0)
                r = manager_run_generators(m);
        dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_GENERATORS_FINISH));
        if (r < 0)
                return r;

        manager_preset_all(m);

        r = lookup_paths_reduce(&m->lookup_paths);
        if (r < 0)
                log_warning_errno(r, "Failed ot reduce unit file paths, ignoring: %m");

        manager_build_unit_path_cache(m);

        {
                
                _cleanup_(manager_reloading_stopp) Manager *reloading = NULL;

                
                if (serialization)
                        reloading = manager_reloading_start(m);

                
                dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_UNITS_LOAD_START));
                manager_enumerate_perpetual(m);
                manager_enumerate(m);
                dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_UNITS_LOAD_FINISH));

                
                if (serialization) {
                        r = manager_deserialize(m, serialization, fds);
                        if (r < 0)
                                return log_error_errno(r, "Deserialization failed: %m");
                }

                
                manager_distribute_fds(m, fds);

                
                r = manager_setup_notify(m);
                if (r < 0)
                        
                        return r;

                r = manager_setup_cgroups_agent(m);
                if (r < 0)
                        
                        return r;

                r = manager_setup_user_lookup_fd(m);
                if (r < 0)
                        
                        return r;

                
                manager_setup_bus(m);

                
                r = bus_track_coldplug(m, &m->subscribed, false, m->deserialized_subscribed);
                if (r < 0)
                        log_warning_errno(r, "Failed to deserialized tracked clients, ignoring: %m");
                m->deserialized_subscribed = strv_free(m->deserialized_subscribed);

                
                manager_coldplug(m);

                
                manager_vacuum(m);

                if (serialization)
                        
                        m->send_reloading_done = true;
        }

        manager_ready(m);

        return 0;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, sd_bus_error *e, Job **_ret) {
        int r;
        Transaction *tr;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START)
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Isolate is only valid for start.");

        if (mode == JOB_ISOLATE && !unit->allow_isolate)
                return sd_bus_error_setf(e, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");

        log_unit_debug(unit, "Trying to enqueue job %s/%s/%s", unit->id, job_type_to_string(type), job_mode_to_string(mode));

        type = job_type_collapse(type, unit);

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        r = transaction_add_job_and_dependencies(tr, type, unit, NULL, true, false, IN_SET(mode, JOB_IGNORE_DEPENDENCIES, JOB_IGNORE_REQUIREMENTS), mode == JOB_IGNORE_DEPENDENCIES, e);

        if (r < 0)
                goto tr_abort;

        if (mode == JOB_ISOLATE) {
                r = transaction_add_isolate_jobs(tr, m);
                if (r < 0)
                        goto tr_abort;
        }

        r = transaction_activate(tr, m, mode, e);
        if (r < 0)
                goto tr_abort;

        log_unit_debug(unit, "Enqueued job %s/%s as %u", unit->id, job_type_to_string(type), (unsigned) tr->anchor_job->id);


        if (_ret)
                *_ret = tr->anchor_job;

        transaction_free(tr);
        return 0;

tr_abort:
        transaction_abort(tr);
        transaction_free(tr);
        return r;
}

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, sd_bus_error *e, Job **ret) {
        Unit *unit = NULL;  
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        r = manager_load_unit(m, name, NULL, NULL, &unit);
        if (r < 0)
                return r;
        assert(unit);

        return manager_add_job(m, type, unit, mode, e, ret);
}

int manager_add_job_by_name_and_warn(Manager *m, JobType type, const char *name, JobMode mode, Job **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        r = manager_add_job_by_name(m, type, name, mode, &error, ret);
        if (r < 0)
                return log_warning_errno(r, "Failed to enqueue %s job for %s: %s", job_mode_to_string(mode), name, bus_error_message(&error, r));

        return r;
}

int manager_propagate_reload(Manager *m, Unit *unit, JobMode mode, sd_bus_error *e) {
        int r;
        Transaction *tr;

        assert(m);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);
        assert(mode != JOB_ISOLATE); 

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        
        r = transaction_add_job_and_dependencies(tr, JOB_NOP, unit, NULL, false, false, true, true, e);
        if (r < 0)
                goto tr_abort;

        
        transaction_add_propagate_reload_jobs(tr, unit, tr->anchor_job, mode == JOB_IGNORE_DEPENDENCIES, e);

        r = transaction_activate(tr, m, mode, e);
        if (r < 0)
                goto tr_abort;

        transaction_free(tr);
        return 0;

tr_abort:
        transaction_abort(tr);
        transaction_free(tr);
        return r;
}

Job *manager_get_job(Manager *m, uint32_t id) {
        assert(m);

        return hashmap_get(m->jobs, UINT32_TO_PTR(id));
}

Unit *manager_get_unit(Manager *m, const char *name) {
        assert(m);
        assert(name);

        return hashmap_get(m->units, name);
}

static int manager_dispatch_target_deps_queue(Manager *m) {
        Unit *u;
        unsigned k;
        int r = 0;

        static const UnitDependency deps[] = {
                UNIT_REQUIRED_BY, UNIT_REQUISITE_OF, UNIT_WANTED_BY, UNIT_BOUND_BY };




        assert(m);

        while ((u = m->target_deps_queue)) {
                assert(u->in_target_deps_queue);

                LIST_REMOVE(target_deps_queue, u->manager->target_deps_queue, u);
                u->in_target_deps_queue = false;

                for (k = 0; k < ELEMENTSOF(deps); k++) {
                        Unit *target;
                        Iterator i;
                        void *v;

                        HASHMAP_FOREACH_KEY(v, target, u->dependencies[deps[k]], i) {
                                r = unit_add_default_target_dependency(u, target);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return r;
}

unsigned manager_dispatch_load_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;

        assert(m);

        
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;

        

        while ((u = m->load_queue)) {
                assert(u->in_load_queue);

                unit_load(u);
                n++;
        }

        m->dispatching_load_queue = false;

        
        (void) manager_dispatch_target_deps_queue(m);

        return n;
}

int manager_load_unit_prepare( Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **_ret) {





        _cleanup_(unit_freep) Unit *cleanup_ret = NULL;
        Unit *ret;
        UnitType t;
        int r;

        assert(m);
        assert(name || path);
        assert(_ret);

        

        if (path && !is_path(path))
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not absolute.", path);

        if (!name)
                name = basename(path);

        t = unit_name_to_type(name);

        if (t == _UNIT_TYPE_INVALID || !unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE))
                        return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is missing the instance name.", name);

                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is not valid.", name);
        }

        ret = manager_get_unit(m, name);
        if (ret) {
                *_ret = ret;
                return 1;
        }

        ret = cleanup_ret = unit_new(m, unit_vtable[t]->object_size);
        if (!ret)
                return -ENOMEM;

        if (path) {
                ret->fragment_path = strdup(path);
                if (!ret->fragment_path)
                        return -ENOMEM;
        }

        r = unit_add_name(ret, name);
        if (r < 0)
                return r;

        unit_add_to_load_queue(ret);
        unit_add_to_dbus_queue(ret);
        unit_add_to_gc_queue(ret);

        *_ret = ret;
        cleanup_ret = NULL;

        return 0;
}

int manager_load_unit( Manager *m, const char *name, const char *path, sd_bus_error *e, Unit **_ret) {





        int r;

        assert(m);
        assert(_ret);

        

        r = manager_load_unit_prepare(m, name, path, e, _ret);
        if (r != 0)
                return r;

        manager_dispatch_load_queue(m);

        *_ret = unit_follow_merge(*_ret);
        return 0;
}

int manager_load_startable_unit_or_warn( Manager *m, const char *name, const char *path, Unit **ret) {




        

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *unit;
        int r;

        r = manager_load_unit(m, name, path, &error, &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to load %s %s: %s", name ? "unit" : "unit file", name ?: path, bus_error_message(&error, r));


        r = bus_unit_validate_load_state(unit, &error);
        if (r < 0)
                return log_error_errno(r, "%s", bus_error_message(&error, r));

        *ret = unit;
        return 0;
}

void manager_dump_jobs(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Job *j;

        assert(s);
        assert(f);

        HASHMAP_FOREACH(j, s->jobs, i)
                job_dump(j, f, prefix);
}

void manager_dump_units(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Unit *u;
        const char *t;

        assert(s);
        assert(f);

        HASHMAP_FOREACH_KEY(u, t, s->units, i)
                if (u->id == t)
                        unit_dump(u, f, prefix);
}

void manager_dump(Manager *m, FILE *f, const char *prefix) {
        ManagerTimestamp q;

        assert(m);
        assert(f);

        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                char buf[FORMAT_TIMESTAMP_MAX];

                if (dual_timestamp_is_set(m->timestamps + q))
                        fprintf(f, "%sTimestamp %s: %s\n", strempty(prefix), manager_timestamp_to_string(q), format_timestamp(buf, sizeof(buf), m->timestamps[q].realtime));


        }

        manager_dump_units(m, f, prefix);
        manager_dump_jobs(m, f, prefix);
}

int manager_get_dump_string(Manager *m, char **ret) {
        _cleanup_free_ char *dump = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t size;
        int r;

        assert(m);
        assert(ret);

        f = open_memstream(&dump, &size);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        manager_dump(m, f, NULL);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        f = safe_fclose(f);

        *ret = TAKE_PTR(dump);

        return 0;
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->jobs)))
                
                job_finish_and_invalidate(j, JOB_CANCELED, false, false);
}

static int manager_dispatch_run_queue(sd_event_source *source, void *userdata) {
        Manager *m = userdata;
        Job *j;

        assert(source);
        assert(m);

        while ((j = m->run_queue)) {
                assert(j->installed);
                assert(j->in_run_queue);

                job_run_and_invalidate(j);
        }

        if (m->n_running_jobs > 0)
                manager_watch_jobs_in_progress(m);

        if (m->n_on_console > 0)
                manager_watch_idle_pipe(m);

        return 1;
}

static unsigned manager_dispatch_dbus_queue(Manager *m) {
        unsigned n = 0, budget;
        Unit *u;
        Job *j;

        assert(m);

        if (m->dispatching_dbus_queue)
                return 0;

        
        if (!m->dbus_unit_queue && !m->dbus_job_queue && !m->send_reloading_done && !m->queued_message)
                return 0;

        
        if (manager_bus_n_queued_write(m) > MANAGER_BUS_BUSY_THRESHOLD)
                return 0;

        
        budget = MANAGER_BUS_MESSAGE_BUDGET;

        m->dispatching_dbus_queue = true;

        while (budget > 0 && (u = m->dbus_unit_queue)) {

                assert(u->in_dbus_queue);

                bus_unit_send_change_signal(u);
                n++, budget--;
        }

        while (budget > 0 && (j = m->dbus_job_queue)) {
                assert(j->in_dbus_queue);

                bus_job_send_change_signal(j);
                n++, budget--;
        }

        m->dispatching_dbus_queue = false;

        if (budget > 0 && m->send_reloading_done) {
                m->send_reloading_done = false;
                bus_manager_send_reloading(m, false);
                n++, budget--;
        }

        if (budget > 0 && m->queued_message) {
                bus_send_queued_message(m);
                n++;
        }

        return n;
}

static int manager_dispatch_cgroups_agent_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        char buf[PATH_MAX+1];
        ssize_t n;

        n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0)
                return log_error_errno(errno, "Failed to read cgroups agent message: %m");
        if (n == 0) {
                log_error("Got zero-length cgroups agent message, ignoring.");
                return 0;
        }
        if ((size_t) n >= sizeof(buf)) {
                log_error("Got overly long cgroups agent message, ignoring.");
                return 0;
        }

        if (memchr(buf, 0, n)) {
                log_error("Got cgroups agent message with embedded NUL byte, ignoring.");
                return 0;
        }
        buf[n] = 0;

        manager_notify_cgroup_empty(m, buf);
        (void) bus_forward_agent_released(m, buf);

        return 0;
}

static void manager_invoke_notify_message( Manager *m, Unit *u, const struct ucred *ucred, const char *buf, FDSet *fds) {





        assert(m);
        assert(u);
        assert(ucred);
        assert(buf);

        if (u->notifygen == m->notifygen) 
                return;
        u->notifygen = m->notifygen;

        if (UNIT_VTABLE(u)->notify_message) {
                _cleanup_strv_free_ char **tags = NULL;

                tags = strv_split(buf, NEWLINE);
                if (!tags) {
                        log_oom();
                        return;
                }

                UNIT_VTABLE(u)->notify_message(u, ucred, tags, fds);

        } else if (DEBUG_LOGGING) {
                _cleanup_free_ char *x = NULL, *y = NULL;

                x = ellipsize(buf, 20, 90);
                if (x)
                        y = cescape(x);

                log_unit_debug(u, "Got notification message \"%s\", ignoring.", strnull(y));
        }
}

static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {

        _cleanup_fdset_free_ FDSet *fds = NULL;
        Manager *m = userdata;
        char buf[NOTIFY_BUFFER_MAX+1];
        struct iovec iovec = {
                .iov_base = buf, .iov_len = sizeof(buf)-1, };

        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)];
        } control = {};
        struct msghdr msghdr = {
                .msg_iov = &iovec, .msg_iovlen = 1, .msg_control = &control, .msg_controllen = sizeof(control), };




        struct cmsghdr *cmsg;
        struct ucred *ucred = NULL;
        _cleanup_free_ Unit **array_copy = NULL;
        Unit *u1, *u2, **array;
        int r, *fd_array = NULL;
        size_t n_fds = 0;
        bool found = false;
        ssize_t n;

        assert(m);
        assert(m->notify_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for notify fd.");
                return 0;
        }

        n = recvmsg(m->notify_fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC|MSG_TRUNC);
        if (n < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0; 

                
                return log_error_errno(errno, "Failed to receive notification message: %m");
        }

        CMSG_FOREACH(cmsg, &msghdr) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {

                        fd_array = (int*) CMSG_DATA(cmsg);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {


                        ucred = (struct ucred*) CMSG_DATA(cmsg);
                }
        }

        if (n_fds > 0) {
                assert(fd_array);

                r = fdset_new_array(&fds, fd_array, n_fds);
                if (r < 0) {
                        close_many(fd_array, n_fds);
                        log_oom();
                        return 0;
                }
        }

        if (!ucred || !pid_is_valid(ucred->pid)) {
                log_warning("Received notify message without valid credentials. Ignoring.");
                return 0;
        }

        if ((size_t) n >= sizeof(buf) || (msghdr.msg_flags & MSG_TRUNC)) {
                log_warning("Received notify message exceeded maximum size. Ignoring.");
                return 0;
        }

        
        if (n > 1 && memchr(buf, 0, n-1)) {
                log_warning("Received notify message with embedded NUL bytes. Ignoring.");
                return 0;
        }

        
        buf[n] = 0;

        
        m->notifygen++;

        
        u1 = manager_get_unit_by_pid_cgroup(m, ucred->pid);
        u2 = hashmap_get(m->watch_pids, PID_TO_PTR(ucred->pid));
        array = hashmap_get(m->watch_pids, PID_TO_PTR(-ucred->pid));
        if (array) {
                size_t k = 0;

                while (array[k])
                        k++;

                array_copy = newdup(Unit*, array, k+1);
                if (!array_copy)
                        log_oom();
        }
        
        if (u1) {
                manager_invoke_notify_message(m, u1, ucred, buf, fds);
                found = true;
        }
        if (u2) {
                manager_invoke_notify_message(m, u2, ucred, buf, fds);
                found = true;
        }
        if (array_copy)
                for (size_t i = 0; array_copy[i]; i++) {
                        manager_invoke_notify_message(m, array_copy[i], ucred, buf, fds);
                        found = true;
                }

        if (!found)
                log_warning("Cannot find unit for notify message of PID "PID_FMT", ignoring.", ucred->pid);

        if (fdset_size(fds) > 0)
                log_warning("Got extra auxiliary fds with notification message, closing them.");

        return 0;
}

static void manager_invoke_sigchld_event( Manager *m, Unit *u, const siginfo_t *si) {



        assert(m);
        assert(u);
        assert(si);

        
        if (u->sigchldgen == m->sigchldgen)
                return;
        u->sigchldgen = m->sigchldgen;

        log_unit_debug(u, "Child "PID_FMT" belongs to %s.", si->si_pid, u->id);
        unit_unwatch_pid(u, si->si_pid);

        if (UNIT_VTABLE(u)->sigchld_event)
                UNIT_VTABLE(u)->sigchld_event(u, si->si_pid, si->si_code, si->si_status);
}

static int manager_dispatch_sigchld(sd_event_source *source, void *userdata) {
        Manager *m = userdata;
        siginfo_t si = {};
        int r;

        assert(source);
        assert(m);

        

        if (waitid(P_ALL, 0, &si, WEXITED|WNOHANG|WNOWAIT) < 0) {

                if (errno != ECHILD)
                        log_error_errno(errno, "Failed to peek for child with waitid(), ignoring: %m");

                goto turn_off;
        }

        if (si.si_pid <= 0)
                goto turn_off;

        if (IN_SET(si.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED)) {
                _cleanup_free_ Unit **array_copy = NULL;
                _cleanup_free_ char *name = NULL;
                Unit *u1, *u2, **array;

                (void) get_process_comm(si.si_pid, &name);

                log_debug("Child "PID_FMT" (%s) died (code=%s, status=%i/%s)", si.si_pid, strna(name), sigchld_code_to_string(si.si_code), si.si_status, strna(si.si_code == CLD_EXITED ? exit_status_to_string(si.si_status, EXIT_STATUS_FULL)




                                : signal_to_string(si.si_status)));

                
                m->sigchldgen++;

                
                u1 = manager_get_unit_by_pid_cgroup(m, si.si_pid);
                u2 = hashmap_get(m->watch_pids, PID_TO_PTR(si.si_pid));
                array = hashmap_get(m->watch_pids, PID_TO_PTR(-si.si_pid));
                if (array) {
                        size_t n = 0;

                        
                        while (array[n])
                                n++;

                        
                        array_copy = newdup(Unit*, array, n+1);
                        if (!array_copy)
                                log_oom();
                }

                
                if (u1)
                        manager_invoke_sigchld_event(m, u1, &si);
                if (u2)
                        manager_invoke_sigchld_event(m, u2, &si);
                if (array_copy)
                        for (size_t i = 0; array_copy[i]; i++)
                                manager_invoke_sigchld_event(m, array_copy[i], &si);
        }

        
        if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0) {
                log_error_errno(errno, "Failed to dequeue child, ignoring: %m");
                return 0;
        }

        return 0;

turn_off:
        

        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to disable SIGCHLD event source: %m");

        return 0;
}

static void manager_start_target(Manager *m, const char *name, JobMode mode) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        log_debug("Activating special unit %s", name);

        r = manager_add_job_by_name(m, JOB_START, name, mode, &error, NULL);
        if (r < 0)
                log_error("Failed to enqueue %s job: %s", name, bus_error_message(&error, r));
}

static void manager_handle_ctrl_alt_del(Manager *m) {
        

        if (ratelimit_below(&m->ctrl_alt_del_ratelimit) || m->cad_burst_action == EMERGENCY_ACTION_NONE)
                manager_start_target(m, SPECIAL_CTRL_ALT_DEL_TARGET, JOB_REPLACE_IRREVERSIBLY);
        else emergency_action(m, m->cad_burst_action, EMERGENCY_ACTION_WARN, NULL, "Ctrl-Alt-Del was pressed more than 7 times within 2s");

}

static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        ssize_t n;
        struct signalfd_siginfo sfsi;
        int r;

        assert(m);
        assert(m->signal_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected events from signal file descriptor.");
                return 0;
        }

        n = read(m->signal_fd, &sfsi, sizeof(sfsi));
        if (n != sizeof(sfsi)) {
                if (n >= 0) {
                        log_warning("Truncated read from signal fd (%zu bytes), ignoring!", n);
                        return 0;
                }

                if (IN_SET(errno, EINTR, EAGAIN))
                        return 0;

                
                return log_error_errno(errno, "Reading from signal fd failed: %m");
        }

        log_received_signal(sfsi.ssi_signo == SIGCHLD || (sfsi.ssi_signo == SIGTERM && MANAGER_IS_USER(m))
                            ? LOG_DEBUG : LOG_INFO, &sfsi);

        switch (sfsi.ssi_signo) {

        case SIGCHLD:
                r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_ON);
                if (r < 0)
                        log_warning_errno(r, "Failed to enable SIGCHLD event source, ignoring: %m");

                break;

        case SIGTERM:
                if (MANAGER_IS_SYSTEM(m)) {
                        
                        if (verify_run_space_and_log("Refusing to reexecute") < 0)
                                break;

                        m->objective = MANAGER_REEXECUTE;
                        break;
                }

                _fallthrough_;
        case SIGINT:
                if (MANAGER_IS_SYSTEM(m))
                        manager_handle_ctrl_alt_del(m);
                else manager_start_target(m, SPECIAL_EXIT_TARGET, JOB_REPLACE_IRREVERSIBLY);

                break;

        case SIGWINCH:
                
                if (MANAGER_IS_SYSTEM(m))
                        manager_start_target(m, SPECIAL_KBREQUEST_TARGET, JOB_REPLACE);

                break;

        case SIGPWR:
                
                if (MANAGER_IS_SYSTEM(m))
                        manager_start_target(m, SPECIAL_SIGPWR_TARGET, JOB_REPLACE);

                break;

        case SIGUSR1:
                if (manager_dbus_is_running(m, false)) {
                        log_info("Trying to reconnect to bus...");

                        (void) bus_init_api(m);

                        if (MANAGER_IS_SYSTEM(m))
                                (void) bus_init_system(m);
                } else {
                        log_info("Starting D-Bus service...");
                        manager_start_target(m, SPECIAL_DBUS_SERVICE, JOB_REPLACE);
                }

                break;

        case SIGUSR2: {
                _cleanup_free_ char *dump = NULL;

                r = manager_get_dump_string(m, &dump);
                if (r < 0) {
                        log_warning_errno(errno, "Failed to acquire manager dump: %m");
                        break;
                }

                log_dump(LOG_INFO, dump);
                break;
        }

        case SIGHUP:
                if (verify_run_space_and_log("Refusing to reload") < 0)
                        break;

                m->objective = MANAGER_RELOAD;
                break;

        default: {

                
                static const struct {
                        const char *target;
                        JobMode mode;
                } target_table[] = {
                        [0] = { SPECIAL_DEFAULT_TARGET,   JOB_ISOLATE }, [1] = { SPECIAL_RESCUE_TARGET,    JOB_ISOLATE }, [2] = { SPECIAL_EMERGENCY_TARGET, JOB_ISOLATE }, [3] = { SPECIAL_HALT_TARGET,      JOB_REPLACE_IRREVERSIBLY }, [4] = { SPECIAL_POWEROFF_TARGET,  JOB_REPLACE_IRREVERSIBLY }, [5] = { SPECIAL_REBOOT_TARGET,    JOB_REPLACE_IRREVERSIBLY }, [6] = { SPECIAL_KEXEC_TARGET,     JOB_REPLACE_IRREVERSIBLY }, };







                
                static const ManagerObjective objective_table[] = {
                        [0] = MANAGER_HALT, [1] = MANAGER_POWEROFF, [2] = MANAGER_REBOOT, [3] = MANAGER_KEXEC, };




                if ((int) sfsi.ssi_signo >= SIGRTMIN+0 && (int) sfsi.ssi_signo < SIGRTMIN+(int) ELEMENTSOF(target_table)) {
                        int idx = (int) sfsi.ssi_signo - SIGRTMIN;
                        manager_start_target(m, target_table[idx].target, target_table[idx].mode);
                        break;
                }

                if ((int) sfsi.ssi_signo >= SIGRTMIN+13 && (int) sfsi.ssi_signo < SIGRTMIN+13+(int) ELEMENTSOF(objective_table)) {
                        m->objective = objective_table[sfsi.ssi_signo - SIGRTMIN - 13];
                        break;
                }

                switch (sfsi.ssi_signo - SIGRTMIN) {

                case 20:
                        manager_set_show_status(m, SHOW_STATUS_YES);
                        break;

                case 21:
                        manager_set_show_status(m, SHOW_STATUS_NO);
                        break;

                case 22:
                        manager_override_log_level(m, LOG_DEBUG);
                        break;

                case 23:
                        manager_restore_original_log_level(m);
                        break;

                case 24:
                        if (MANAGER_IS_USER(m)) {
                                m->objective = MANAGER_EXIT;
                                return 0;
                        }

                        
                        break;

                case 26:
                case 29: 
                        manager_restore_original_log_target(m);
                        break;

                case 27:
                        manager_override_log_target(m, LOG_TARGET_CONSOLE);
                        break;

                case 28:
                        manager_override_log_target(m, LOG_TARGET_KMSG);
                        break;

                default:
                        log_warning("Got unhandled signal <%s>.", signal_to_string(sfsi.ssi_signo));
                }
        }}

        return 0;
}

static int manager_dispatch_time_change_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Iterator i;
        Unit *u;

        assert(m);
        assert(m->time_change_fd == fd);

        log_struct(LOG_DEBUG, "MESSAGE_ID=" SD_MESSAGE_TIME_CHANGE_STR, LOG_MESSAGE("Time has been changed"));


        
        (void) manager_setup_time_change(m);

        HASHMAP_FOREACH(u, m->units, i)
                if (UNIT_VTABLE(u)->time_change)
                        UNIT_VTABLE(u)->time_change(u);

        return 0;
}

static int manager_dispatch_timezone_change( sd_event_source *source, const struct inotify_event *e, void *userdata) {



        Manager *m = userdata;
        int changed;
        Iterator i;
        Unit *u;

        assert(m);

        log_debug("inotify event for /etc/localtime");

        changed = manager_read_timezone_stat(m);
        if (changed < 0)
                return changed;
        if (!changed)
                return 0;

        
        (void) manager_setup_timezone_change(m);

        
        tzset();

        log_debug("Timezone has been changed (now: %s).", tzname[daylight]);

        HASHMAP_FOREACH(u, m->units, i)
                if (UNIT_VTABLE(u)->timezone_change)
                        UNIT_VTABLE(u)->timezone_change(u);

        return 0;
}

static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);
        assert(m->idle_pipe[2] == fd);

        
        m->no_console_output = m->n_on_console > 0;

        
        manager_close_idle_pipe(m);

        return 0;
}

static int manager_dispatch_jobs_in_progress(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = userdata;
        int r;
        uint64_t next;

        assert(m);
        assert(source);

        manager_print_jobs_in_progress(m);

        next = now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_PERIOD_USEC;
        r = sd_event_source_set_time(source, next);
        if (r < 0)
                return r;

        return sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
}

int manager_loop(Manager *m) {
        int r;

        RATELIMIT_DEFINE(rl, 1*USEC_PER_SEC, 50000);

        assert(m);
        assert(m->objective == MANAGER_OK); 

        
        m->unit_path_cache = set_free_free(m->unit_path_cache);

        manager_check_finished(m);

        
        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SIGCHLD event source: %m");

        while (m->objective == MANAGER_OK) {
                usec_t wait_usec;

                if (m->runtime_watchdog > 0 && m->runtime_watchdog != USEC_INFINITY && MANAGER_IS_SYSTEM(m))
                        watchdog_ping();

                if (!ratelimit_below(&rl)) {
                        
                        log_warning("Looping too fast. Throttling execution a little.");
                        sleep(1);
                }

                if (manager_dispatch_load_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_job_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_unit_queue(m) > 0)
                        continue;

                if (manager_dispatch_cleanup_queue(m) > 0)
                        continue;

                if (manager_dispatch_cgroup_realize_queue(m) > 0)
                        continue;

                if (manager_dispatch_stop_when_unneeded_queue(m) > 0)
                        continue;

                if (manager_dispatch_dbus_queue(m) > 0)
                        continue;

                
                if (m->runtime_watchdog > 0 && m->runtime_watchdog != USEC_INFINITY && MANAGER_IS_SYSTEM(m)) {
                        wait_usec = m->runtime_watchdog / 2;
                        if (wait_usec <= 0)
                                wait_usec = 1;
                } else wait_usec = USEC_INFINITY;

                r = sd_event_run(m->event, wait_usec);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");
        }

        return m->objective;
}

int manager_load_unit_from_dbus_path(Manager *m, const char *s, sd_bus_error *e, Unit **_u) {
        _cleanup_free_ char *n = NULL;
        sd_id128_t invocation_id;
        Unit *u;
        int r;

        assert(m);
        assert(s);
        assert(_u);

        r = unit_name_from_dbus_path(s, &n);
        if (r < 0)
                return r;

        
        r = sd_id128_from_string(n, &invocation_id);
        if (r >= 0) {
                u = hashmap_get(m->units_by_invocation_id, &invocation_id);
                if (u) {
                        *_u = u;
                        return 0;
                }

                return sd_bus_error_setf(e, BUS_ERROR_NO_UNIT_FOR_INVOCATION_ID, "No unit with the specified invocation ID " SD_ID128_FORMAT_STR " known.", SD_ID128_FORMAT_VAL(invocation_id));

        }

        
        if (!unit_name_is_valid(n, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                _cleanup_free_ char *nn = NULL;

                nn = cescape(n);
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is neither a valid invocation ID nor unit name.", strnull(nn));
        }

        r = manager_load_unit(m, n, NULL, e, &u);
        if (r < 0)
                return r;

        *_u = u;
        return 0;
}

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j) {
        const char *p;
        unsigned id;
        Job *j;
        int r;

        assert(m);
        assert(s);
        assert(_j);

        p = startswith(s, "/org/freedesktop/systemd1/job/");
        if (!p)
                return -EINVAL;

        r = safe_atou(p, &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return -ENOENT;

        *_j = j;

        return 0;
}

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success) {


        _cleanup_free_ char *p = NULL;
        const char *msg;
        int audit_fd, r;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        audit_fd = get_audit_fd();
        if (audit_fd < 0)
                return;

        
        if (MANAGER_IS_RELOADING(m))
                return;

        if (u->type != UNIT_SERVICE)
                return;

        r = unit_name_to_prefix_and_instance(u->id, &p);
        if (r < 0) {
                log_error_errno(r, "Failed to extract prefix and instance of unit name: %m");
                return;
        }

        msg = strjoina("unit=", p);
        if (audit_log_user_comm_message(audit_fd, type, msg, "systemd", NULL, NULL, NULL, success) < 0) {
                if (errno == EPERM)
                        
                        close_audit_fd();
                else log_warning_errno(errno, "Failed to send audit message: %m");
        }


}

void manager_send_unit_plymouth(Manager *m, Unit *u) {
        static const union sockaddr_union sa = PLYMOUTH_SOCKET;
        _cleanup_free_ char *message = NULL;
        _cleanup_close_ int fd = -1;
        int n = 0;

        
        if (MANAGER_IS_RELOADING(m))
                return;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (detect_container() > 0)
                return;

        if (!IN_SET(u->type, UNIT_SERVICE, UNIT_MOUNT, UNIT_SWAP))
                return;

        
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_error_errno(errno, "socket() failed: %m");
                return;
        }

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0) {
                if (!IN_SET(errno, EPIPE, EAGAIN, ENOENT, ECONNREFUSED, ECONNRESET, ECONNABORTED))
                        log_error_errno(errno, "connect() failed: %m");
                return;
        }

        if (asprintf(&message, "U\002%c%s%n", (int) (strlen(u->id) + 1), u->id, &n) < 0) {
                log_oom();
                return;
        }

        errno = 0;
        if (write(fd, message, n + 1) != n + 1)
                if (!IN_SET(errno, EPIPE, EAGAIN, ENOENT, ECONNREFUSED, ECONNRESET, ECONNABORTED))
                        log_error_errno(errno, "Failed to write Plymouth message: %m");
}

int manager_open_serialization(Manager *m, FILE **_f) {
        int fd;
        FILE *f;

        assert(_f);

        fd = open_serialization_fd("systemd-state");
        if (fd < 0)
                return fd;

        f = fdopen(fd, "w+");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        *_f = f;
        return 0;
}

int manager_serialize( Manager *m, FILE *f, FDSet *fds, bool switching_root) {




        ManagerTimestamp q;
        const char *t;
        Iterator i;
        Unit *u;
        int r;

        assert(m);
        assert(f);
        assert(fds);

        _cleanup_(manager_reloading_stopp) _unused_ Manager *reloading = manager_reloading_start(m);

        fprintf(f, "current-job-id=%"PRIu32"\n", m->current_job_id);
        fprintf(f, "n-installed-jobs=%u\n", m->n_installed_jobs);
        fprintf(f, "n-failed-jobs=%u\n", m->n_failed_jobs);
        fprintf(f, "taint-usr=%s\n", yes_no(m->taint_usr));
        fprintf(f, "ready-sent=%s\n", yes_no(m->ready_sent));
        fprintf(f, "taint-logged=%s\n", yes_no(m->taint_logged));
        fprintf(f, "service-watchdogs=%s\n", yes_no(m->service_watchdogs));

        t = show_status_to_string(m->show_status);
        if (t)
                fprintf(f, "show-status=%s\n", t);

        if (m->log_level_overridden)
                fprintf(f, "log-level-override=%i\n", log_get_max_level());
        if (m->log_target_overridden)
                fprintf(f, "log-target-override=%s\n", log_target_to_string(log_get_target()));

        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                
                if (in_initrd() && IN_SET(q, MANAGER_TIMESTAMP_USERSPACE, MANAGER_TIMESTAMP_FINISH, MANAGER_TIMESTAMP_SECURITY_START, MANAGER_TIMESTAMP_SECURITY_FINISH, MANAGER_TIMESTAMP_GENERATORS_START, MANAGER_TIMESTAMP_GENERATORS_FINISH, MANAGER_TIMESTAMP_UNITS_LOAD_START, MANAGER_TIMESTAMP_UNITS_LOAD_FINISH))



                        continue;

                t = manager_timestamp_to_string(q);
                const char *field = strjoina(t, "-timestamp");
                dual_timestamp_serialize(f, field, m->timestamps + q);
        }

        if (!switching_root)
                (void) serialize_environment(f, m->environment);

        if (m->notify_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, m->notify_fd);
                if (copy < 0)
                        return copy;

                fprintf(f, "notify-fd=%i\n", copy);
                fprintf(f, "notify-socket=%s\n", m->notify_socket);
        }

        if (m->cgroups_agent_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, m->cgroups_agent_fd);
                if (copy < 0)
                        return copy;

                fprintf(f, "cgroups-agent-fd=%i\n", copy);
        }

        if (m->user_lookup_fds[0] >= 0) {
                int copy0, copy1;

                copy0 = fdset_put_dup(fds, m->user_lookup_fds[0]);
                if (copy0 < 0)
                        return copy0;

                copy1 = fdset_put_dup(fds, m->user_lookup_fds[1]);
                if (copy1 < 0)
                        return copy1;

                fprintf(f, "user-lookup=%i %i\n", copy0, copy1);
        }

        bus_track_serialize(m->subscribed, f, "subscribed");

        r = dynamic_user_serialize(m, f, fds);
        if (r < 0)
                return r;

        manager_serialize_uid_refs(m, f);
        manager_serialize_gid_refs(m, f);

        r = exec_runtime_serialize(m, f, fds);
        if (r < 0)
                return r;

        (void) fputc('\n', f);

        HASHMAP_FOREACH_KEY(u, t, m->units, i) {
                if (u->id != t)
                        continue;

                
                fputs(u->id, f);
                fputc('\n', f);

                r = unit_serialize(u, f, fds, !switching_root);
                if (r < 0)
                        return r;
        }

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        r = bus_fdset_add_all(m, fds);
        if (r < 0)
                return r;

        return 0;
}

int manager_deserialize(Manager *m, FILE *f, FDSet *fds) {
        int r = 0;

        assert(m);
        assert(f);

        log_debug("Deserializing state...");

        
        _cleanup_(manager_reloading_stopp) _unused_ Manager *reloading = manager_reloading_start(m);

        for (;;) {
                char line[LINE_MAX];
                const char *val, *l;

                errno = 0;
                if (!fgets(line, sizeof(line), f)) {
                        if (!feof(f))
                                return -errno ?: -EIO;
                        return 0;
                }

                char_array_0(line);
                l = strstrip(line);

                if (l[0] == 0)
                        break;

                if ((val = startswith(l, "current-job-id="))) {
                        uint32_t id;

                        if (safe_atou32(val, &id) < 0)
                                log_notice("Failed to parse current job id value '%s', ignoring.", val);
                        else m->current_job_id = MAX(m->current_job_id, id);

                } else if ((val = startswith(l, "n-installed-jobs="))) {
                        uint32_t n;

                        if (safe_atou32(val, &n) < 0)
                                log_notice("Failed to parse installed jobs counter '%s', ignoring.", val);
                        else m->n_installed_jobs += n;

                } else if ((val = startswith(l, "n-failed-jobs="))) {
                        uint32_t n;

                        if (safe_atou32(val, &n) < 0)
                                log_notice("Failed to parse failed jobs counter '%s', ignoring.", val);
                        else m->n_failed_jobs += n;

                } else if ((val = startswith(l, "taint-usr="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse taint /usr flag '%s', ignoring.", val);
                        else m->taint_usr = m->taint_usr || b;

                } else if ((val = startswith(l, "ready-sent="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse ready-sent flag '%s', ignoring.", val);
                        else m->ready_sent = m->ready_sent || b;

                } else if ((val = startswith(l, "taint-logged="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse taint-logged flag '%s', ignoring.", val);
                        else m->taint_logged = m->taint_logged || b;

                } else if ((val = startswith(l, "service-watchdogs="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse service-watchdogs flag '%s', ignoring.", val);
                        else m->service_watchdogs = b;

                } else if ((val = startswith(l, "show-status="))) {
                        ShowStatus s;

                        s = show_status_from_string(val);
                        if (s < 0)
                                log_notice("Failed to parse show-status flag '%s', ignoring.", val);
                        else manager_set_show_status(m, s);

                } else if ((val = startswith(l, "log-level-override="))) {
                        int level;

                        level = log_level_from_string(val);
                        if (level < 0)
                                log_notice("Failed to parse log-level-override value '%s', ignoring.", val);
                        else manager_override_log_level(m, level);

                } else if ((val = startswith(l, "log-target-override="))) {
                        LogTarget target;

                        target = log_target_from_string(val);
                        if (target < 0)
                                log_notice("Failed to parse log-target-override value '%s', ignoring.", val);
                        else manager_override_log_target(m, target);

                } else if (startswith(l, "env=")) {
                        r = deserialize_environment(&m->environment, l);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                log_notice_errno(r, "Failed to parse environment entry: \"%s\", ignoring: %m", l);

                } else if ((val = startswith(l, "notify-fd="))) {
                        int fd;

                        if (safe_atoi(val, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                                log_notice("Failed to parse notify fd, ignoring: \"%s\"", val);
                        else {
                                m->notify_event_source = sd_event_source_unref(m->notify_event_source);
                                safe_close(m->notify_fd);
                                m->notify_fd = fdset_remove(fds, fd);
                        }

                } else if ((val = startswith(l, "notify-socket="))) {
                        r = free_and_strdup(&m->notify_socket, val);
                        if (r < 0)
                                return r;

                } else if ((val = startswith(l, "cgroups-agent-fd="))) {
                        int fd;

                        if (safe_atoi(val, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                                log_notice("Failed to parse cgroups agent fd, ignoring.: %s", val);
                        else {
                                m->cgroups_agent_event_source = sd_event_source_unref(m->cgroups_agent_event_source);
                                safe_close(m->cgroups_agent_fd);
                                m->cgroups_agent_fd = fdset_remove(fds, fd);
                        }

                } else if ((val = startswith(l, "user-lookup="))) {
                        int fd0, fd1;

                        if (sscanf(val, "%i %i", &fd0, &fd1) != 2 || fd0 < 0 || fd1 < 0 || fd0 == fd1 || !fdset_contains(fds, fd0) || !fdset_contains(fds, fd1))
                                log_notice("Failed to parse user lookup fd, ignoring: %s", val);
                        else {
                                m->user_lookup_event_source = sd_event_source_unref(m->user_lookup_event_source);
                                safe_close_pair(m->user_lookup_fds);
                                m->user_lookup_fds[0] = fdset_remove(fds, fd0);
                                m->user_lookup_fds[1] = fdset_remove(fds, fd1);
                        }

                } else if ((val = startswith(l, "dynamic-user=")))
                        dynamic_user_deserialize_one(m, val, fds);
                else if ((val = startswith(l, "destroy-ipc-uid=")))
                        manager_deserialize_uid_refs_one(m, val);
                else if ((val = startswith(l, "destroy-ipc-gid=")))
                        manager_deserialize_gid_refs_one(m, val);
                else if ((val = startswith(l, "exec-runtime=")))
                        exec_runtime_deserialize_one(m, val, fds);
                else if ((val = startswith(l, "subscribed="))) {

                        if (strv_extend(&m->deserialized_subscribed, val) < 0)
                                return -ENOMEM;

                } else {
                        ManagerTimestamp q;

                        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                                val = startswith(l, manager_timestamp_to_string(q));
                                if (!val)
                                        continue;

                                val = startswith(val, "-timestamp=");
                                if (val)
                                        break;
                        }

                        if (q < _MANAGER_TIMESTAMP_MAX) 
                                dual_timestamp_deserialize(val, m->timestamps + q);
                        else if (!startswith(l, "kdbus-fd=")) 
                                log_notice("Unknown serialization item '%s', ignoring.", l);
                }
        }

        for (;;) {
                Unit *u;
                char name[UNIT_NAME_MAX+2];
                const char* unit_name;

                
                errno = 0;
                if (!fgets(name, sizeof(name), f)) {
                        if (!feof(f))
                                return -errno ?: -EIO;
                        return 0;
                }

                char_array_0(name);
                unit_name = strstrip(name);

                r = manager_load_unit(m, unit_name, NULL, NULL, &u);
                if (r < 0) {
                        if (r == -ENOMEM)
                                return r;

                        log_notice_errno(r, "Failed to load unit \"%s\", skipping deserialization: %m", unit_name);
                        unit_deserialize_skip(f);
                        continue;
                }

                r = unit_deserialize(u, f, fds);
                if (r < 0) {
                        if (r == -ENOMEM)
                                return r;

                        log_notice_errno(r, "Failed to deserialize unit \"%s\": %m", unit_name);
                }
        }

        return 0;
}

static void manager_flush_finished_jobs(Manager *m) {
        Job *j;

        while ((j = set_steal_first(m->pending_finished_jobs))) {
                bus_job_send_removed_signal(j);
                job_free(j);
        }

        m->pending_finished_jobs = set_free(m->pending_finished_jobs);
}

int manager_reload(Manager *m) {
        _cleanup_(manager_reloading_stopp) Manager *reloading = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        r = manager_open_serialization(m, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create serialization file: %m");

        fds = fdset_new();
        if (!fds)
                return log_oom();

        
        reloading = manager_reloading_start(m);

        r = manager_serialize(m, f, fds, false);
        if (r < 0)
                return log_error_errno(r, "Failed to serialize manager: %m");

        if (fseeko(f, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to beginning of serialization: %m");

        
        reloading = NULL;

        bus_manager_send_reloading(m, true);

        

        manager_clear_jobs_and_units(m);
        lookup_paths_flush_generator(&m->lookup_paths);
        lookup_paths_free(&m->lookup_paths);
        exec_runtime_vacuum(m);
        dynamic_user_vacuum(m, false);
        m->uid_refs = hashmap_free(m->uid_refs);
        m->gid_refs = hashmap_free(m->gid_refs);

        r = lookup_paths_init(&m->lookup_paths, m->unit_file_scope, 0, NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to initialize path lookup table, ignoring: %m");

        (void) manager_run_environment_generators(m);
        (void) manager_run_generators(m);

        r = lookup_paths_reduce(&m->lookup_paths);
        if (r < 0)
                log_warning_errno(r, "Failed ot reduce unit file paths, ignoring: %m");

        manager_build_unit_path_cache(m);

        
        manager_enumerate_perpetual(m);
        manager_enumerate(m);

        
        r = manager_deserialize(m, f, fds);
        if (r < 0)
                log_warning_errno(r, "Deserialization failed, proceeding anyway: %m");

        
        f = safe_fclose(f);

        
        (void) manager_setup_notify(m);
        (void) manager_setup_cgroups_agent(m);
        (void) manager_setup_user_lookup_fd(m);

        
        manager_coldplug(m);

        
        manager_vacuum(m);

        
        assert(m->n_reloading > 0);
        m->n_reloading--;

        manager_ready(m);

        if (!MANAGER_IS_RELOADING(m))
                manager_flush_finished_jobs(m);

        m->send_reloading_done = true;
        return 0;
}

void manager_reset_failed(Manager *m) {
        Unit *u;
        Iterator i;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i)
                unit_reset_failed(u);
}

bool manager_unit_inactive_or_pending(Manager *m, const char *name) {
        Unit *u;

        assert(m);
        assert(name);

        
        u = manager_get_unit(m, name);
        if (!u)
                return true;

        return unit_inactive_or_pending(u);
}

static void log_taint_string(Manager *m) {
        _cleanup_free_ char *taint = NULL;

        assert(m);

        if (MANAGER_IS_USER(m) || m->taint_logged)
                return;

        m->taint_logged = true; 

        taint = manager_taint_string(m);
        if (isempty(taint))
                return;

        log_struct(LOG_NOTICE, LOG_MESSAGE("System is tainted: %s", taint), "TAINT=%s", taint, "MESSAGE_ID=" SD_MESSAGE_TAINTED_STR);


}

static void manager_notify_finished(Manager *m) {
        char userspace[FORMAT_TIMESPAN_MAX], initrd[FORMAT_TIMESPAN_MAX], kernel[FORMAT_TIMESPAN_MAX], sum[FORMAT_TIMESPAN_MAX];
        usec_t firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec;

        if (MANAGER_IS_TEST_RUN(m))
                return;

        if (MANAGER_IS_SYSTEM(m) && detect_container() <= 0) {
                char ts[FORMAT_TIMESPAN_MAX];
                char buf[FORMAT_TIMESPAN_MAX + STRLEN(" (firmware) + ") + FORMAT_TIMESPAN_MAX + STRLEN(" (loader) + ")] = {};
                char *p = buf;
                size_t size = sizeof buf;

                

                firmware_usec = m->timestamps[MANAGER_TIMESTAMP_FIRMWARE].monotonic - m->timestamps[MANAGER_TIMESTAMP_LOADER].monotonic;
                loader_usec = m->timestamps[MANAGER_TIMESTAMP_LOADER].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                userspace_usec = m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic - m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic;
                total_usec = m->timestamps[MANAGER_TIMESTAMP_FIRMWARE].monotonic + m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic;

                if (firmware_usec > 0)
                        size = strpcpyf(&p, size, "%s (firmware) + ", format_timespan(ts, sizeof(ts), firmware_usec, USEC_PER_MSEC));
                if (loader_usec > 0)
                        size = strpcpyf(&p, size, "%s (loader) + ", format_timespan(ts, sizeof(ts), loader_usec, USEC_PER_MSEC));

                if (dual_timestamp_is_set(&m->timestamps[MANAGER_TIMESTAMP_INITRD])) {

                        
                        kernel_usec = m->timestamps[MANAGER_TIMESTAMP_INITRD].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                        initrd_usec = m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic - m->timestamps[MANAGER_TIMESTAMP_INITRD].monotonic;

                        log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_STARTUP_FINISHED_STR, "KERNEL_USEC="USEC_FMT, kernel_usec, "INITRD_USEC="USEC_FMT, initrd_usec, "USERSPACE_USEC="USEC_FMT, userspace_usec, LOG_MESSAGE("Startup finished in %s%s (kernel) + %s (initrd) + %s (userspace) = %s.", buf, format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC), format_timespan(initrd, sizeof(initrd), initrd_usec, USEC_PER_MSEC), format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC), format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)));









                } else {
                        

                        kernel_usec = m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                        initrd_usec = 0;

                        log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_STARTUP_FINISHED_STR, "KERNEL_USEC="USEC_FMT, kernel_usec, "USERSPACE_USEC="USEC_FMT, userspace_usec, LOG_MESSAGE("Startup finished in %s%s (kernel) + %s (userspace) = %s.", buf, format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC), format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC), format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)));







                }
        } else {
                
                firmware_usec = loader_usec = initrd_usec = kernel_usec = 0;
                total_usec = userspace_usec = m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic - m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic;

                log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_USER_STARTUP_FINISHED_STR, "USERSPACE_USEC="USEC_FMT, userspace_usec, LOG_MESSAGE("Startup finished in %s.", format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)));



        }

        bus_manager_send_finished(m, firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec);

        sd_notifyf(false, m->ready_sent ? "STATUS=Startup finished in %s." : "READY=1\n" "STATUS=Startup finished in %s.", format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC));



        m->ready_sent = true;

        log_taint_string(m);
}

static void manager_send_ready(Manager *m) {
        assert(m);

        
        if (!MANAGER_IS_USER(m) || m->ready_sent)
                return;

        m->ready_sent = true;

        sd_notifyf(false, "READY=1\n" "STATUS=Reached " SPECIAL_BASIC_TARGET ".");

}

static void manager_check_basic_target(Manager *m) {
        Unit *u;

        assert(m);

        
        if (m->ready_sent && m->taint_logged)
                return;

        u = manager_get_unit(m, SPECIAL_BASIC_TARGET);
        if (!u || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                return;

        
        manager_send_ready(m);

        
        log_taint_string(m);
}

void manager_check_finished(Manager *m) {
        assert(m);

        if (MANAGER_IS_RELOADING(m))
                return;

        
        if (!MANAGER_IS_RUNNING(m))
                return;

        manager_check_basic_target(m);

        if (hashmap_size(m->jobs) > 0) {
                if (m->jobs_in_progress_event_source)
                        
                        (void) sd_event_source_set_time(m->jobs_in_progress_event_source, now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_WAIT_USEC);

                return;
        }

        manager_flip_auto_status(m, false);

        
        manager_close_idle_pipe(m);

        
        m->confirm_spawn = NULL;

        
        manager_close_ask_password(m);

        
        manager_set_first_boot(m, false);

        if (MANAGER_IS_FINISHED(m))
                return;

        dual_timestamp_get(m->timestamps + MANAGER_TIMESTAMP_FINISH);

        manager_notify_finished(m);

        manager_invalidate_startup_units(m);
}

static bool generator_path_any(const char* const* paths) {
        char **path;
        bool found = false;

        
        STRV_FOREACH(path, (char**) paths)
                if (access(*path, F_OK) == 0)
                        found = true;
                else if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open generator directory %s: %m", *path);

        return found;
}

static const char* system_env_generator_binary_paths[] = {
        "/run/systemd/system-environment-generators", "/etc/systemd/system-environment-generators", "/usr/local/lib/systemd/system-environment-generators", SYSTEM_ENV_GENERATOR_PATH, NULL };





static const char* user_env_generator_binary_paths[] = {
        "/run/systemd/user-environment-generators", "/etc/systemd/user-environment-generators", "/usr/local/lib/systemd/user-environment-generators", USER_ENV_GENERATOR_PATH, NULL };





static int manager_run_environment_generators(Manager *m) {
        char **tmp = NULL; 
        const char **paths;
        void* args[] = {&tmp, &tmp, &m->environment};

        if (MANAGER_IS_TEST_RUN(m) && !(m->test_run_flags & MANAGER_TEST_RUN_ENV_GENERATORS))
                return 0;

        paths = MANAGER_IS_SYSTEM(m) ? system_env_generator_binary_paths : user_env_generator_binary_paths;

        if (!generator_path_any(paths))
                return 0;

        return execute_directories(paths, DEFAULT_TIMEOUT_USEC, gather_environment, args, NULL, m->environment);
}

static int manager_run_generators(Manager *m) {
        _cleanup_strv_free_ char **paths = NULL;
        const char *argv[5];
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m) && !(m->test_run_flags & MANAGER_TEST_RUN_GENERATORS))
                return 0;

        paths = generator_binary_paths(m->unit_file_scope);
        if (!paths)
                return log_oom();

        if (!generator_path_any((const char* const*) paths))
                return 0;

        r = lookup_paths_mkdir_generator(&m->lookup_paths);
        if (r < 0) {
                log_error_errno(r, "Failed to create generator directories: %m");
                goto finish;
        }

        argv[0] = NULL; 
        argv[1] = m->lookup_paths.generator;
        argv[2] = m->lookup_paths.generator_early;
        argv[3] = m->lookup_paths.generator_late;
        argv[4] = NULL;

        RUN_WITH_UMASK(0022)
                (void) execute_directories((const char* const*) paths, DEFAULT_TIMEOUT_USEC, NULL, NULL, (char**) argv, m->environment);

        r = 0;

finish:
        lookup_paths_trim_generator(&m->lookup_paths);
        return r;
}

int manager_environment_add(Manager *m, char **minus, char **plus) {
        char **a = NULL, **b = NULL, **l;
        assert(m);

        l = m->environment;

        if (!strv_isempty(minus)) {
                a = strv_env_delete(l, 1, minus);
                if (!a)
                        return -ENOMEM;

                l = a;
        }

        if (!strv_isempty(plus)) {
                b = strv_env_merge(2, l, plus);
                if (!b) {
                        strv_free(a);
                        return -ENOMEM;
                }

                l = b;
        }

        if (m->environment != l)
                strv_free(m->environment);
        if (a != l)
                strv_free(a);
        if (b != l)
                strv_free(b);

        m->environment = l;
        manager_sanitize_environment(m);

        return 0;
}

int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit) {
        int i;

        assert(m);

        for (i = 0; i < _RLIMIT_MAX; i++) {
                m->rlimit[i] = mfree(m->rlimit[i]);

                if (!default_rlimit[i])
                        continue;

                m->rlimit[i] = newdup(struct rlimit, default_rlimit[i], 1);
                if (!m->rlimit[i])
                        return log_oom();
        }

        return 0;
}

void manager_recheck_dbus(Manager *m) {
        assert(m);

        

        if (MANAGER_IS_RELOADING(m))
                return; 

        if (manager_dbus_is_running(m, false)) {
                (void) bus_init_api(m);

                if (MANAGER_IS_SYSTEM(m))
                        (void) bus_init_system(m);
        } else {
                (void) bus_done_api(m);

                if (MANAGER_IS_SYSTEM(m))
                        (void) bus_done_system(m);
        }
}

static bool manager_journal_is_running(Manager *m) {
        Unit *u;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return false;

        
        if (!MANAGER_IS_SYSTEM(m))
                return true;

        
        u = manager_get_unit(m, SPECIAL_JOURNALD_SOCKET);
        if (!u)
                return false;
        if (SOCKET(u)->state != SOCKET_RUNNING)
                return false;

        
        u = manager_get_unit(m, SPECIAL_JOURNALD_SERVICE);
        if (!u)
                return false;
        if (!IN_SET(SERVICE(u)->state, SERVICE_RELOAD, SERVICE_RUNNING))
                return false;

        return true;
}

void manager_recheck_journal(Manager *m) {

        assert(m);

        
        if (getpid_cached() != 1)
                return;

        
        if (MANAGER_IS_RELOADING(m))
                return;

        
        log_set_prohibit_ipc(!manager_journal_is_running(m));
        log_open();
}

void manager_set_show_status(Manager *m, ShowStatus mode) {
        assert(m);
        assert(IN_SET(mode, SHOW_STATUS_AUTO, SHOW_STATUS_NO, SHOW_STATUS_YES, SHOW_STATUS_TEMPORARY));

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (m->show_status != mode)
                log_debug("%s showing of status.", mode == SHOW_STATUS_NO ? "Disabling" : "Enabling");
        m->show_status = mode;

        if (IN_SET(mode, SHOW_STATUS_TEMPORARY, SHOW_STATUS_YES))
                (void) touch("/run/systemd/show-status");
        else (void) unlink("/run/systemd/show-status");
}

static bool manager_get_show_status(Manager *m, StatusType type) {
        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return false;

        if (m->no_console_output)
                return false;

        if (!IN_SET(manager_state(m), MANAGER_INITIALIZING, MANAGER_STARTING, MANAGER_STOPPING))
                return false;

        
        if (type != STATUS_TYPE_EMERGENCY && manager_check_ask_password(m) > 0)
                return false;

        return IN_SET(m->show_status, SHOW_STATUS_TEMPORARY, SHOW_STATUS_YES);
}

const char *manager_get_confirm_spawn(Manager *m) {
        static int last_errno = 0;
        const char *vc = m->confirm_spawn;
        struct stat st;
        int r;

        

        if (!vc || path_equal(vc, "/dev/console"))
                return vc;

        r = stat(vc, &st);
        if (r < 0)
                goto fail;

        if (!S_ISCHR(st.st_mode)) {
                errno = ENOTTY;
                goto fail;
        }

        last_errno = 0;
        return vc;
fail:
        if (last_errno != errno) {
                last_errno = errno;
                log_warning_errno(errno, "Failed to open %s: %m, using default console", vc);
        }
        return "/dev/console";
}

void manager_set_first_boot(Manager *m, bool b) {
        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (m->first_boot != (int) b) {
                if (b)
                        (void) touch("/run/systemd/first-boot");
                else (void) unlink("/run/systemd/first-boot");
        }

        m->first_boot = b;
}

void manager_disable_confirm_spawn(void) {
        (void) touch("/run/systemd/confirm_spawn_disabled");
}

bool manager_is_confirm_spawn_disabled(Manager *m) {
        if (!m->confirm_spawn)
                return true;

        return access("/run/systemd/confirm_spawn_disabled", F_OK) >= 0;
}

void manager_status_printf(Manager *m, StatusType type, const char *status, const char *format, ...) {
        va_list ap;

        

        if (m && !manager_get_show_status(m, type))
                return;

        
        if (type == STATUS_TYPE_EPHEMERAL && m && m->n_on_console > 0)
                return;

        va_start(ap, format);
        status_vprintf(status, true, type == STATUS_TYPE_EPHEMERAL, format, ap);
        va_end(ap);
}

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path) {
        char p[strlen(path)+1];

        assert(m);
        assert(path);

        strcpy(p, path);
        path_simplify(p, false);

        return hashmap_get(m->units_requiring_mounts_for, streq(p, "/") ? "" : p);
}

int manager_update_failed_units(Manager *m, Unit *u, bool failed) {
        unsigned size;
        int r;

        assert(m);
        assert(u->manager == m);

        size = set_size(m->failed_units);

        if (failed) {
                r = set_ensure_allocated(&m->failed_units, NULL);
                if (r < 0)
                        return log_oom();

                if (set_put(m->failed_units, u) < 0)
                        return log_oom();
        } else (void) set_remove(m->failed_units, u);

        if (set_size(m->failed_units) != size)
                bus_manager_send_change_signal(m);

        return 0;
}

ManagerState manager_state(Manager *m) {
        Unit *u;

        assert(m);

        
        if (!MANAGER_IS_FINISHED(m)) {

                u = manager_get_unit(m, SPECIAL_BASIC_TARGET);
                if (!u || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                        return MANAGER_INITIALIZING;

                return MANAGER_STARTING;
        }

        
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u && unit_active_or_pending(u))
                return MANAGER_STOPPING;

        if (MANAGER_IS_SYSTEM(m)) {
                
                u = manager_get_unit(m, SPECIAL_RESCUE_TARGET);
                if (u && unit_active_or_pending(u))
                        return MANAGER_MAINTENANCE;

                u = manager_get_unit(m, SPECIAL_EMERGENCY_TARGET);
                if (u && unit_active_or_pending(u))
                        return MANAGER_MAINTENANCE;
        }

        
        if (set_size(m->failed_units) > 0)
                return MANAGER_DEGRADED;

        return MANAGER_RUNNING;
}



static void manager_unref_uid_internal( Manager *m, Hashmap **uid_refs, uid_t uid, bool destroy_now, int (*_clean_ipc)(uid_t uid)) {





        uint32_t c, n;

        assert(m);
        assert(uid_refs);
        assert(uid_is_valid(uid));
        assert(_clean_ipc);

        

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (uid == 0) 
                return;

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));

        n = c & ~DESTROY_IPC_FLAG;
        assert(n > 0);
        n--;

        if (destroy_now && n == 0) {
                hashmap_remove(*uid_refs, UID_TO_PTR(uid));

                if (c & DESTROY_IPC_FLAG) {
                        log_debug("%s " UID_FMT " is no longer referenced, cleaning up its IPC.", _clean_ipc == clean_ipc_by_uid ? "UID" : "GID", uid);

                        (void) _clean_ipc(uid);
                }
        } else {
                c = n | (c & DESTROY_IPC_FLAG);
                assert_se(hashmap_update(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c)) >= 0);
        }
}

void manager_unref_uid(Manager *m, uid_t uid, bool destroy_now) {
        manager_unref_uid_internal(m, &m->uid_refs, uid, destroy_now, clean_ipc_by_uid);
}

void manager_unref_gid(Manager *m, gid_t gid, bool destroy_now) {
        manager_unref_uid_internal(m, &m->gid_refs, (uid_t) gid, destroy_now, clean_ipc_by_gid);
}

static int manager_ref_uid_internal( Manager *m, Hashmap **uid_refs, uid_t uid, bool clean_ipc) {




        uint32_t c, n;
        int r;

        assert(m);
        assert(uid_refs);
        assert(uid_is_valid(uid));

        

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (uid == 0) 
                return 0;

        r = hashmap_ensure_allocated(uid_refs, &trivial_hash_ops);
        if (r < 0)
                return r;

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));

        n = c & ~DESTROY_IPC_FLAG;
        n++;

        if (n & DESTROY_IPC_FLAG) 
                return -EOVERFLOW;

        c = n | (c & DESTROY_IPC_FLAG) | (clean_ipc ? DESTROY_IPC_FLAG : 0);

        return hashmap_replace(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c));
}

int manager_ref_uid(Manager *m, uid_t uid, bool clean_ipc) {
        return manager_ref_uid_internal(m, &m->uid_refs, uid, clean_ipc);
}

int manager_ref_gid(Manager *m, gid_t gid, bool clean_ipc) {
        return manager_ref_uid_internal(m, &m->gid_refs, (uid_t) gid, clean_ipc);
}

static void manager_vacuum_uid_refs_internal( Manager *m, Hashmap **uid_refs, int (*_clean_ipc)(uid_t uid)) {



        Iterator i;
        void *p, *k;

        assert(m);
        assert(uid_refs);
        assert(_clean_ipc);

        HASHMAP_FOREACH_KEY(p, k, *uid_refs, i) {
                uint32_t c, n;
                uid_t uid;

                uid = PTR_TO_UID(k);
                c = PTR_TO_UINT32(p);

                n = c & ~DESTROY_IPC_FLAG;
                if (n > 0)
                        continue;

                if (c & DESTROY_IPC_FLAG) {
                        log_debug("Found unreferenced %s " UID_FMT " after reload/reexec. Cleaning up.", _clean_ipc == clean_ipc_by_uid ? "UID" : "GID", uid);

                        (void) _clean_ipc(uid);
                }

                assert_se(hashmap_remove(*uid_refs, k) == p);
        }
}

void manager_vacuum_uid_refs(Manager *m) {
        manager_vacuum_uid_refs_internal(m, &m->uid_refs, clean_ipc_by_uid);
}

void manager_vacuum_gid_refs(Manager *m) {
        manager_vacuum_uid_refs_internal(m, &m->gid_refs, clean_ipc_by_gid);
}

static void manager_serialize_uid_refs_internal( Manager *m, FILE *f, Hashmap **uid_refs, const char *field_name) {




        Iterator i;
        void *p, *k;

        assert(m);
        assert(f);
        assert(uid_refs);
        assert(field_name);

        

        HASHMAP_FOREACH_KEY(p, k, *uid_refs, i) {
                uint32_t c;
                uid_t uid;

                uid = PTR_TO_UID(k);
                c = PTR_TO_UINT32(p);

                if (!(c & DESTROY_IPC_FLAG))
                        continue;

                fprintf(f, "%s=" UID_FMT "\n", field_name, uid);
        }
}

void manager_serialize_uid_refs(Manager *m, FILE *f) {
        manager_serialize_uid_refs_internal(m, f, &m->uid_refs, "destroy-ipc-uid");
}

void manager_serialize_gid_refs(Manager *m, FILE *f) {
        manager_serialize_uid_refs_internal(m, f, &m->gid_refs, "destroy-ipc-gid");
}

static void manager_deserialize_uid_refs_one_internal( Manager *m, Hashmap** uid_refs, const char *value) {



        uid_t uid;
        uint32_t c;
        int r;

        assert(m);
        assert(uid_refs);
        assert(value);

        r = parse_uid(value, &uid);
        if (r < 0 || uid == 0) {
                log_debug("Unable to parse UID reference serialization");
                return;
        }

        r = hashmap_ensure_allocated(uid_refs, &trivial_hash_ops);
        if (r < 0) {
                log_oom();
                return;
        }

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));
        if (c & DESTROY_IPC_FLAG)
                return;

        c |= DESTROY_IPC_FLAG;

        r = hashmap_replace(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c));
        if (r < 0) {
                log_debug("Failed to add UID reference entry");
                return;
        }
}

void manager_deserialize_uid_refs_one(Manager *m, const char *value) {
        manager_deserialize_uid_refs_one_internal(m, &m->uid_refs, value);
}

void manager_deserialize_gid_refs_one(Manager *m, const char *value) {
        manager_deserialize_uid_refs_one_internal(m, &m->gid_refs, value);
}

int manager_dispatch_user_lookup_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        struct buffer {
                uid_t uid;
                gid_t gid;
                char unit_name[UNIT_NAME_MAX+1];
        } _packed_ buffer;

        Manager *m = userdata;
        ssize_t l;
        size_t n;
        Unit *u;

        assert_se(source);
        assert_se(m);

        

        l = recv(fd, &buffer, sizeof(buffer), MSG_DONTWAIT);
        if (l < 0) {
                if (IN_SET(errno, EINTR, EAGAIN))
                        return 0;

                return log_error_errno(errno, "Failed to read from user lookup fd: %m");
        }

        if ((size_t) l <= offsetof(struct buffer, unit_name)) {
                log_warning("Received too short user lookup message, ignoring.");
                return 0;
        }

        if ((size_t) l > offsetof(struct buffer, unit_name) + UNIT_NAME_MAX) {
                log_warning("Received too long user lookup message, ignoring.");
                return 0;
        }

        if (!uid_is_valid(buffer.uid) && !gid_is_valid(buffer.gid)) {
                log_warning("Got user lookup message with invalid UID/GID pair, ignoring.");
                return 0;
        }

        n = (size_t) l - offsetof(struct buffer, unit_name);
        if (memchr(buffer.unit_name, 0, n)) {
                log_warning("Received lookup message with embedded NUL character, ignoring.");
                return 0;
        }

        buffer.unit_name[n] = 0;
        u = manager_get_unit(m, buffer.unit_name);
        if (!u) {
                log_debug("Got user lookup message but unit doesn't exist, ignoring.");
                return 0;
        }

        log_unit_debug(u, "User lookup succeeded: uid=" UID_FMT " gid=" GID_FMT, buffer.uid, buffer.gid);

        unit_notify_user_lookup(u, buffer.uid, buffer.gid);
        return 0;
}

char *manager_taint_string(Manager *m) {
        _cleanup_free_ char *destination = NULL, *overflowuid = NULL, *overflowgid = NULL;
        char *buf, *e;
        int r;

        

        assert(m);

        buf = new(char, sizeof("split-usr:" "cgroups-missing:" "local-hwclock:" "var-run-bad:" "overflowuid-not-65534:" "overflowgid-not-65534:"));




        if (!buf)
                return NULL;

        e = buf;
        buf[0] = 0;

        if (m->taint_usr)
                e = stpcpy(e, "split-usr:");

        if (access("/proc/cgroups", F_OK) < 0)
                e = stpcpy(e, "cgroups-missing:");

        if (clock_is_localtime(NULL) > 0)
                e = stpcpy(e, "local-hwclock:");

        r = readlink_malloc("/var/run", &destination);
        if (r < 0 || !PATH_IN_SET(destination, "../run", "/run"))
                e = stpcpy(e, "var-run-bad:");

        r = read_one_line_file("/proc/sys/kernel/overflowuid", &overflowuid);
        if (r >= 0 && !streq(overflowuid, "65534"))
                e = stpcpy(e, "overflowuid-not-65534:");

        r = read_one_line_file("/proc/sys/kernel/overflowgid", &overflowgid);
        if (r >= 0 && !streq(overflowgid, "65534"))
                e = stpcpy(e, "overflowgid-not-65534:");

        
        if (e != buf)
                e[-1] = 0;

        return buf;
}

void manager_ref_console(Manager *m) {
        assert(m);

        m->n_on_console++;
}

void manager_unref_console(Manager *m) {

        assert(m->n_on_console > 0);
        m->n_on_console--;

        if (m->n_on_console == 0)
                m->no_console_output = false; 
}

void manager_override_log_level(Manager *m, int level) {
        _cleanup_free_ char *s = NULL;
        assert(m);

        if (!m->log_level_overridden) {
                m->original_log_level = log_get_max_level();
                m->log_level_overridden = true;
        }

        (void) log_level_to_string_alloc(level, &s);
        log_info("Setting log level to %s.", strna(s));

        log_set_max_level(level);
}

void manager_restore_original_log_level(Manager *m) {
        _cleanup_free_ char *s = NULL;
        assert(m);

        if (!m->log_level_overridden)
                return;

        (void) log_level_to_string_alloc(m->original_log_level, &s);
        log_info("Restoring log level to original (%s).", strna(s));

        log_set_max_level(m->original_log_level);
        m->log_level_overridden = false;
}

void manager_override_log_target(Manager *m, LogTarget target) {
        assert(m);

        if (!m->log_target_overridden) {
                m->original_log_target = log_get_target();
                m->log_target_overridden = true;
        }

        log_info("Setting log target to %s.", log_target_to_string(target));
        log_set_target(target);
}

void manager_restore_original_log_target(Manager *m) {
        assert(m);

        if (!m->log_target_overridden)
                return;

        log_info("Restoring log target to original %s.", log_target_to_string(m->original_log_target));

        log_set_target(m->original_log_target);
        m->log_target_overridden = false;
}

ManagerTimestamp manager_timestamp_initrd_mangle(ManagerTimestamp s) {
        if (in_initrd() && s >= MANAGER_TIMESTAMP_SECURITY_START && s <= MANAGER_TIMESTAMP_UNITS_LOAD_FINISH)

                return s - MANAGER_TIMESTAMP_SECURITY_START + MANAGER_TIMESTAMP_INITRD_SECURITY_START;
        return s;
}

static const char *const manager_state_table[_MANAGER_STATE_MAX] = {
        [MANAGER_INITIALIZING] = "initializing", [MANAGER_STARTING] = "starting", [MANAGER_RUNNING] = "running", [MANAGER_DEGRADED] = "degraded", [MANAGER_MAINTENANCE] = "maintenance", [MANAGER_STOPPING] = "stopping", };






DEFINE_STRING_TABLE_LOOKUP(manager_state, ManagerState);

static const char *const manager_timestamp_table[_MANAGER_TIMESTAMP_MAX] = {
        [MANAGER_TIMESTAMP_FIRMWARE] = "firmware", [MANAGER_TIMESTAMP_LOADER] = "loader", [MANAGER_TIMESTAMP_KERNEL] = "kernel", [MANAGER_TIMESTAMP_INITRD] = "initrd", [MANAGER_TIMESTAMP_USERSPACE] = "userspace", [MANAGER_TIMESTAMP_FINISH] = "finish", [MANAGER_TIMESTAMP_SECURITY_START] = "security-start", [MANAGER_TIMESTAMP_SECURITY_FINISH] = "security-finish", [MANAGER_TIMESTAMP_GENERATORS_START] = "generators-start", [MANAGER_TIMESTAMP_GENERATORS_FINISH] = "generators-finish", [MANAGER_TIMESTAMP_UNITS_LOAD_START] = "units-load-start", [MANAGER_TIMESTAMP_UNITS_LOAD_FINISH] = "units-load-finish", [MANAGER_TIMESTAMP_INITRD_SECURITY_START] = "initrd-security-start", [MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH] = "initrd-security-finish", [MANAGER_TIMESTAMP_INITRD_GENERATORS_START] = "initrd-generators-start", [MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH] = "initrd-generators-finish", [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START] = "initrd-units-load-start", [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH] = "initrd-units-load-finish", };


















DEFINE_STRING_TABLE_LOOKUP(manager_timestamp, ManagerTimestamp);
