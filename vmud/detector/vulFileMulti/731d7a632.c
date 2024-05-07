






















































lxc_log_define(lxc_attach, lxc);

static struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid)
{
	struct lxc_proc_context_info *info = calloc(1, sizeof(*info));
	FILE *proc_file;
	char proc_fn[MAXPATHLEN];
	char *line = NULL;
	size_t line_bufsz = 0;
	int ret, found;

	if (!info) {
		SYSERROR("Could not allocate memory.");
		return NULL;
	}

	
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/status", pid);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file) {
		SYSERROR("Could not open %s", proc_fn);
		goto out_error;
	}

	found = 0;
	while (getline(&line, &line_bufsz, proc_file) != -1) {
		ret = sscanf(line, "CapBnd: %llx", &info->capability_mask);
		if (ret != EOF && ret > 0) {
			found = 1;
			break;
		}
	}

	free(line);
	fclose(proc_file);

	if (!found) {
		SYSERROR("Could not read capability bounding set from %s", proc_fn);
		errno = ENOENT;
		goto out_error;
	}

	info->lsm_label = lsm_process_label_get(pid);

	return info;

out_error:
	free(info);
	return NULL;
}

static void lxc_proc_put_context_info(struct lxc_proc_context_info *ctx)
{
	free(ctx->lsm_label);
	if (ctx->container)
		lxc_container_put(ctx->container);
	free(ctx);
}

static int lxc_attach_to_ns(pid_t pid, int which)
{
	char path[MAXPATHLEN];
	
	static char *ns[] = { "user", "mnt", "pid", "uts", "ipc", "net" };
	static int flags[] = {
		CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWNET };

	static const int size = sizeof(ns) / sizeof(char *);
	int fd[size];
	int i, j, saved_errno;


	snprintf(path, MAXPATHLEN, "/proc/%d/ns", pid);
	if (access(path, X_OK)) {
		ERROR("Does this kernel version support 'attach' ?");
		return -1;
	}

	for (i = 0; i < size; i++) {
		
		if (which != -1 && !(which & flags[i])) {
			fd[i] = -1;
			continue;
		}

		snprintf(path, MAXPATHLEN, "/proc/%d/ns/%s", pid, ns[i]);
		fd[i] = open(path, O_RDONLY | O_CLOEXEC);
		if (fd[i] < 0) {
			saved_errno = errno;

			
			for (j = 0; j < i; j++)
				close(fd[j]);

			errno = saved_errno;
			SYSERROR("failed to open '%s'", path);
			return -1;
		}
	}

	for (i = 0; i < size; i++) {
		if (fd[i] >= 0 && setns(fd[i], 0) != 0) {
			saved_errno = errno;

			for (j = i; j < size; j++)
				close(fd[j]);

			errno = saved_errno;
			SYSERROR("failed to set namespace '%s'", ns[i]);
			return -1;
		}

		close(fd[i]);
	}

	return 0;
}

static int lxc_attach_remount_sys_proc(void)
{
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		SYSERROR("failed to unshare mount namespace");
		return -1;
	}

	if (detect_shared_rootfs()) {
		if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
			SYSERROR("Failed to make / rslave");
			ERROR("Continuing...");
		}
	}

	
	ret = umount2("/proc", MNT_DETACH);
	if (ret < 0) {
		SYSERROR("failed to unmount /proc");
		return -1;
	}

	ret = mount("none", "/proc", "proc", 0, NULL);
	if (ret < 0) {
		SYSERROR("failed to remount /proc");
		return -1;
	}

	
	ret = umount2("/sys", MNT_DETACH);
	if (ret < 0 && errno != EINVAL) {
		SYSERROR("failed to unmount /sys");
		return -1;
	} else if (ret == 0) {
		
		ret = mount("none", "/sys", "sysfs", 0, NULL);
		if (ret < 0) {
			SYSERROR("failed to remount /sys");
			return -1;
		}
	}

	return 0;
}

static int lxc_attach_drop_privs(struct lxc_proc_context_info *ctx)
{
	int last_cap = lxc_caps_last_cap();
	int cap;

	for (cap = 0; cap <= last_cap; cap++) {
		if (ctx->capability_mask & (1LL << cap))
			continue;

		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) {
			SYSERROR("failed to remove capability id %d", cap);
			return -1;
		}
	}

	return 0;
}

static int lxc_attach_set_environment(enum lxc_attach_env_policy_t policy, char** extra_env, char** extra_keep)
{
	if (policy == LXC_ATTACH_CLEAR_ENV) {
		char **extra_keep_store = NULL;
		int path_kept = 0;

		if (extra_keep) {
			size_t count, i;

			for (count = 0; extra_keep[count]; count++);

			extra_keep_store = calloc(count, sizeof(char *));
			if (!extra_keep_store) {
				SYSERROR("failed to allocate memory for storing current " "environment variable values that will be kept");
				return -1;
			}
			for (i = 0; i < count; i++) {
				char *v = getenv(extra_keep[i]);
				if (v) {
					extra_keep_store[i] = strdup(v);
					if (!extra_keep_store[i]) {
						SYSERROR("failed to allocate memory for storing current " "environment variable values that will be kept");
						while (i > 0)
							free(extra_keep_store[--i]);
						free(extra_keep_store);
						return -1;
					}
					if (strcmp(extra_keep[i], "PATH") == 0)
						path_kept = 1;
				}
				
			}
		}

		if (clearenv()) {
			char **p;
			SYSERROR("failed to clear environment");
			if (extra_keep_store) {
				for (p = extra_keep_store; *p; p++)
					free(*p);
				free(extra_keep_store);
			}
			return -1;
		}

		if (extra_keep_store) {
			size_t i;
			for (i = 0; extra_keep[i]; i++) {
				if (extra_keep_store[i]) {
					if (setenv(extra_keep[i], extra_keep_store[i], 1) < 0)
						SYSERROR("Unable to set environment variable");
				}
				free(extra_keep_store[i]);
			}
			free(extra_keep_store);
		}

		
		if (!path_kept)
			setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
	}

	if (putenv("container=lxc")) {
		SYSERROR("failed to set environment variable");
		return -1;
	}

	
	if (extra_env) {
		for (; *extra_env; extra_env++) {
			
			char *p = strdup(*extra_env);
			
			if (!p) {
				SYSERROR("failed to allocate memory for additional environment " "variables");
				return -1;
			}
			putenv(p);
		}
	}

	return 0;
}

static char *lxc_attach_getpwshell(uid_t uid)
{
	
	pid_t pid;
	int pipes[2];
	int ret;
	int fd;
	char *result = NULL;

	
	ret = pipe(pipes);
	if (ret < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		close(pipes[0]);
		close(pipes[1]);
		return NULL;
	}

	if (pid) {
		
		FILE *pipe_f;
		char *line = NULL;
		size_t line_bufsz = 0;
		int found = 0;
		int status;

		close(pipes[1]);

		pipe_f = fdopen(pipes[0], "r");
		while (getline(&line, &line_bufsz, pipe_f) != -1) {
			char *token;
			char *saveptr = NULL;
			long value;
			char *endptr = NULL;
			int i;

			
			if (found)
				continue;

			
			for (i = strlen(line); i > 0 && (line[i - 1] == '\n' || line[i - 1] == '\r'); --i)
				line[i - 1] = '\0';

			
			token = strtok_r(line, ":", &saveptr);
			if (!token)
				continue;
			
			token = strtok_r(NULL, ":", &saveptr);
			if (!token)
				continue;
			
			token = strtok_r(NULL, ":", &saveptr);
			value = token ? strtol(token, &endptr, 10) : 0;
			if (!token || !endptr || *endptr || value == LONG_MIN || value == LONG_MAX)
				continue;
			
			if ((uid_t) value != uid)
				continue;
			
			for (i = 0; i < 4; i++) {
				token = strtok_r(NULL, ":", &saveptr);
				if (!token)
					break;
			}
			if (!token)
				continue;
			free(result);
			result = strdup(token);

			
			token = strtok_r(NULL, ":", &saveptr);
			if (token)
				continue;

			found = 1;
		}

		free(line);
		fclose(pipe_f);
	again:
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				goto again;
			return NULL;
		}

		

		if (!WIFEXITED(status))
			return NULL;

		if (WEXITSTATUS(status) != 0)
			return NULL;

		if (!found)
			return NULL;

		return result;
	} else {
		
		char uid_buf[32];
		char *arguments[] = {
			"getent", "passwd", uid_buf, NULL };




		close(pipes[0]);

		
		dup2(pipes[1], 1);
		close(pipes[1]);

		
		fd = open("/dev/null", O_RDWR);
		if (fd < 0) {
			close(0);
			close(2);
		} else {
			dup2(fd, 0);
			dup2(fd, 2);
			close(fd);
		}

		
		ret = snprintf(uid_buf, sizeof(uid_buf), "%ld", (long) uid);
		if (ret <= 0)
			exit(-1);

		
		(void) execvp("getent", arguments);
		exit(-1);
	}
}

static void lxc_attach_get_init_uidgid(uid_t* init_uid, gid_t* init_gid)
{
	FILE *proc_file;
	char proc_fn[MAXPATHLEN];
	char *line = NULL;
	size_t line_bufsz = 0;
	int ret;
	long value = -1;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;

	
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/status", 1);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file)
		return;

	while (getline(&line, &line_bufsz, proc_file) != -1) {
		
		ret = sscanf(line, "Uid: %ld", &value);
		if (ret != EOF && ret > 0) {
			uid = (uid_t) value;
		} else {
			ret = sscanf(line, "Gid: %ld", &value);
			if (ret != EOF && ret > 0)
				gid = (gid_t) value;
		}
		if (uid != (uid_t)-1 && gid != (gid_t)-1)
			break;
	}

	fclose(proc_file);
	free(line);

	
	if (uid != (uid_t)-1)
		*init_uid = uid;
	if (gid != (gid_t)-1)
		*init_gid = gid;

	
}

struct attach_clone_payload {
	int ipc_socket;
	lxc_attach_options_t* options;
	struct lxc_proc_context_info* init_ctx;
	lxc_attach_exec_t exec_function;
	void* exec_payload;
};

static int attach_child_main(void* data);





static lxc_attach_options_t attach_static_default_options = LXC_ATTACH_OPTIONS_DEFAULT;

static bool fetch_seccomp(const char *name, const char *lxcpath, struct lxc_proc_context_info *i, lxc_attach_options_t *options)
{
	struct lxc_container *c;

	if (!(options->namespaces & CLONE_NEWNS) || !(options->attach_flags & LXC_ATTACH_LSM))
		return true;

	c = lxc_container_new(name, lxcpath);
	if (!c)
		return false;
	i->container = c;
	if (!c->lxc_conf)
		return false;
	if (lxc_read_seccomp_config(c->lxc_conf) < 0) {
		ERROR("Error reading seccomp policy");
		return false;
	}

	return true;
}

static signed long get_personality(const char *name, const char *lxcpath)
{
	char *p = lxc_cmd_get_config_item(name, "lxc.arch", lxcpath);
	signed long ret;

	if (!p)
		return -1;
	ret = lxc_config_parse_arch(p);
	free(p);
	return ret;
}

int lxc_attach(const char* name, const char* lxcpath, lxc_attach_exec_t exec_function, void* exec_payload, lxc_attach_options_t* options, pid_t* attached_process)
{
	int ret, status;
	pid_t init_pid, pid, attached_pid, expected;
	struct lxc_proc_context_info *init_ctx;
	char* cwd;
	char* new_cwd;
	int ipc_sockets[2];
	signed long personality;

	if (!options)
		options = &attach_static_default_options;

	init_pid = lxc_cmd_get_init_pid(name, lxcpath);
	if (init_pid < 0) {
		ERROR("failed to get the init pid");
		return -1;
	}

	init_ctx = lxc_proc_get_context_info(init_pid);
	if (!init_ctx) {
		ERROR("failed to get context of the init process, pid = %ld", (long)init_pid);
		return -1;
	}

	personality = get_personality(name, lxcpath);
	if (init_ctx->personality < 0) {
		ERROR("Failed to get personality of the container");
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}
	init_ctx->personality = personality;

	if (!fetch_seccomp(name, lxcpath, init_ctx, options))
		WARN("Failed to get seccomp policy");

	cwd = getcwd(NULL, 0);

	
	if (options->namespaces == -1) {
		options->namespaces = lxc_cmd_get_clone_flags(name, lxcpath);
		
		if (options->namespaces == -1) {
			ERROR("failed to automatically determine the " "namespaces which the container unshared");
			free(cwd);
			lxc_proc_put_context_info(init_ctx);
			return -1;
		}
	}

	
	ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	if (ret < 0) {
		SYSERROR("could not set up required IPC mechanism for attaching");
		free(cwd);
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	
	pid = fork();

	if (pid < 0) {
		SYSERROR("failed to create first subprocess");
		free(cwd);
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	if (pid) {
		pid_t to_cleanup_pid = pid;

		
		close(ipc_sockets[1]);
		free(cwd);

		
		if (options->attach_flags & LXC_ATTACH_MOVE_TO_CGROUP) {
			if (!cgroup_attach(name, lxcpath, pid))
				goto cleanup_error;
		}

		
		status = 0;
		ret = lxc_write_nointr(ipc_sockets[0], &status, sizeof(status));
		if (ret <= 0) {
			ERROR("error using IPC to notify attached process for initialization (0)");
			goto cleanup_error;
		}

		
		ret = lxc_read_nointr_expect(ipc_sockets[0], &attached_pid, sizeof(attached_pid), NULL);
		if (ret <= 0) {
			if (ret != 0)
				ERROR("error using IPC to receive pid of attached process");
			goto cleanup_error;
		}

		
		if (options->stdin_fd == 0) {
			signal(SIGINT, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
		}

		
		ret = wait_for_pid(pid);
		if (ret < 0)
			goto cleanup_error;

		
		to_cleanup_pid = attached_pid;

		
		status = 0;
		ret = lxc_write_nointr(ipc_sockets[0], &status, sizeof(status));
		if (ret <= 0) {
			ERROR("error using IPC to notify attached process for initialization (0)");
			goto cleanup_error;
		}

		
		expected = 1;
		ret = lxc_read_nointr_expect(ipc_sockets[0], &status, sizeof(status), &expected);
		if (ret <= 0) {
			if (ret != 0)
				ERROR("error using IPC to receive notification from attached process (1)");
			goto cleanup_error;
		}

		
		status = 2;
		ret = lxc_write_nointr(ipc_sockets[0], &status, sizeof(status));
		if (ret <= 0) {
			ERROR("error using IPC to notify attached process for initialization (2)");
			goto cleanup_error;
		}

		
		shutdown(ipc_sockets[0], SHUT_RDWR);
		close(ipc_sockets[0]);
		lxc_proc_put_context_info(init_ctx);

		

		*attached_process = attached_pid;
		return 0;

	cleanup_error:
		
		shutdown(ipc_sockets[0], SHUT_RDWR);
		close(ipc_sockets[0]);
		if (to_cleanup_pid)
			(void) wait_for_pid(to_cleanup_pid);
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	
	close(ipc_sockets[0]);

	
	expected = 0;
	status = -1;
	ret = lxc_read_nointr_expect(ipc_sockets[1], &status, sizeof(status), &expected);
	if (ret <= 0) {
		ERROR("error communicating with child process");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	
	ret = lxc_attach_to_ns(init_pid, options->namespaces);
	if (ret < 0) {
		ERROR("failed to enter the namespace");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	
	if (options->initial_cwd)
		new_cwd = options->initial_cwd;
	else new_cwd = cwd;
	ret = chdir(new_cwd);
	if (ret < 0)
		WARN("could not change directory to '%s'", new_cwd);
	free(cwd);

	
	{
		struct attach_clone_payload payload = {
			.ipc_socket = ipc_sockets[1], .options = options, .init_ctx = init_ctx, .exec_function = exec_function, .exec_payload = exec_payload };




		
		pid = lxc_clone(attach_child_main, &payload, CLONE_PARENT);
	}

	
	if (pid <= 0) {
		SYSERROR("failed to create subprocess");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	
	ret = lxc_write_nointr(ipc_sockets[1], &pid, sizeof(pid));
	if (ret != sizeof(pid)) {
		
		ERROR("error using IPC to notify main process of pid of the attached process");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	
	rexit(0);
}

static int attach_child_main(void* data)
{
	struct attach_clone_payload* payload = (struct attach_clone_payload*)data;
	int ipc_socket = payload->ipc_socket;
	lxc_attach_options_t* options = payload->options;
	struct lxc_proc_context_info* init_ctx = payload->init_ctx;

	long new_personality;

	int ret;
	int status;
	int expected;
	long flags;
	int fd;
	uid_t new_uid;
	gid_t new_gid;

	
	expected = 0;
	status = -1;
	ret = lxc_read_nointr_expect(ipc_socket, &status, sizeof(status), &expected);
	if (ret <= 0) {
		ERROR("error using IPC to receive notification from initial process (0)");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	
	if (!(options->namespaces & CLONE_NEWNS) && (options->attach_flags & LXC_ATTACH_REMOUNT_PROC_SYS)) {
		ret = lxc_attach_remount_sys_proc();
		if (ret < 0) {
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}

	

	if (options->personality < 0)
		new_personality = init_ctx->personality;
	else new_personality = options->personality;

	if (options->attach_flags & LXC_ATTACH_SET_PERSONALITY) {
		ret = personality(new_personality);
		if (ret < 0) {
			SYSERROR("could not ensure correct architecture");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}


	if (options->attach_flags & LXC_ATTACH_DROP_CAPABILITIES) {
		ret = lxc_attach_drop_privs(init_ctx);
		if (ret < 0) {
			ERROR("could not drop privileges");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}

	
	ret = lxc_attach_set_environment(options->env_policy, options->extra_env_vars, options->extra_keep_env);
	if (ret < 0) {
		ERROR("could not set initial environment for attached process");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	
	new_uid = 0;
	new_gid = 0;
	
	if (options->namespaces & CLONE_NEWUSER)
		lxc_attach_get_init_uidgid(&new_uid, &new_gid);

	if (options->uid != (uid_t)-1)
		new_uid = options->uid;
	if (options->gid != (gid_t)-1)
		new_gid = options->gid;

	
	if (options->stdin_fd && isatty(options->stdin_fd)) {
		if (setsid() < 0) {
			SYSERROR("unable to setsid");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}

		if (ioctl(options->stdin_fd, TIOCSCTTY, (char *)NULL) < 0) {
			SYSERROR("unable to TIOCSTTY");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}

	
	if ((new_gid != 0 || options->namespaces & CLONE_NEWUSER)) {
		if (setgid(new_gid) || setgroups(0, NULL)) {
			SYSERROR("switching to container gid");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}
	if ((new_uid != 0 || options->namespaces & CLONE_NEWUSER) && setuid(new_uid)) {
		SYSERROR("switching to container uid");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	
	status = 1;
	ret = lxc_write_nointr(ipc_socket, &status, sizeof(status));
	if (ret != sizeof(status)) {
		ERROR("error using IPC to notify initial process for initialization (1)");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	
	expected = 2;
	status = -1;
	ret = lxc_read_nointr_expect(ipc_socket, &status, sizeof(status), &expected);
	if (ret <= 0) {
		ERROR("error using IPC to receive final notification from initial process (2)");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	shutdown(ipc_socket, SHUT_RDWR);
	close(ipc_socket);

	
	if ((options->namespaces & CLONE_NEWNS) && (options->attach_flags & LXC_ATTACH_LSM)) {
		int on_exec;
		int proc_mounted;

		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? 1 : 0;
		proc_mounted = mount_proc_if_needed("/");
		if (proc_mounted == -1) {
			ERROR("Error mounting a sane /proc");
			rexit(-1);
		}
		ret = lsm_process_label_set(init_ctx->lsm_label, init_ctx->container->lxc_conf, 0, on_exec);
		if (proc_mounted)
			umount("/proc");
		if (ret < 0) {
			rexit(-1);
		}
	}

	if (init_ctx->container && init_ctx->container->lxc_conf && lxc_seccomp_load(init_ctx->container->lxc_conf) != 0) {
		ERROR("Loading seccomp policy");
		rexit(-1);
	}

	lxc_proc_put_context_info(init_ctx);

	

	
	if (options->stdin_fd >= 0 && options->stdin_fd != 0)
		dup2(options->stdin_fd, 0);
	if (options->stdout_fd >= 0 && options->stdout_fd != 1)
		dup2(options->stdout_fd, 1);
	if (options->stderr_fd >= 0 && options->stderr_fd != 2)
		dup2(options->stderr_fd, 2);

	
	if (options->stdin_fd > 2)
		close(options->stdin_fd);
	if (options->stdout_fd > 2)
		close(options->stdout_fd);
	if (options->stderr_fd > 2)
		close(options->stderr_fd);

	
	for (fd = 0; fd <= 2; fd++) {
		flags = fcntl(fd, F_GETFL);
		if (flags < 0)
			continue;
		if (flags & FD_CLOEXEC) {
			if (fcntl(fd, F_SETFL, flags & ~FD_CLOEXEC) < 0) {
				SYSERROR("Unable to clear CLOEXEC from fd");
			}
		}
	}

	
	rexit(payload->exec_function(payload->exec_payload));
}

int lxc_attach_run_command(void* payload)
{
	lxc_attach_command_t* cmd = (lxc_attach_command_t*)payload;

	execvp(cmd->program, cmd->argv);
	SYSERROR("failed to exec '%s'", cmd->program);
	return -1;
}

int lxc_attach_run_shell(void* payload)
{
	uid_t uid;
	struct passwd *passwd;
	char *user_shell;

	
	(void)payload;

	uid = getuid();
	passwd = getpwuid(uid);

	
	if (!passwd)
		user_shell = lxc_attach_getpwshell(uid);
	else user_shell = passwd->pw_shell;

	if (user_shell)
		execlp(user_shell, user_shell, NULL);

	
	execlp("/bin/sh", "/bin/sh", NULL);
	SYSERROR("failed to exec shell");
	return -1;
}
