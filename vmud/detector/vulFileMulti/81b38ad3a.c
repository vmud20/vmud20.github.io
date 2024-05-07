













int xmkstemp(char **tmpname, char *dir)
{
	char *localtmp;
	char *tmpenv;
	mode_t old_mode;
	int fd, rc;

	
	if (dir != NULL)
		tmpenv = dir;
	else tmpenv = getenv("TMPDIR");

	if (tmpenv)
		rc = asprintf(&localtmp, "%s/%s.XXXXXX", tmpenv, program_invocation_short_name);
	else rc = asprintf(&localtmp, "%s/%s.XXXXXX", _PATH_TMP, program_invocation_short_name);


	if (rc < 0)
		return -1;

	old_mode = umask(077);
	fd = mkostemp(localtmp, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC);
	umask(old_mode);
	if (fd == -1) {
		free(localtmp);
		localtmp = NULL;
	}
	*tmpname = localtmp;
	return fd;
}

int dup_fd_cloexec(int oldfd, int lowfd)
{
	int fd, flags, errno_save;


	fd = fcntl(oldfd, F_DUPFD_CLOEXEC, lowfd);
	if (fd >= 0)
		return fd;


	fd = dup(oldfd);
	if (fd < 0)
		return fd;

	flags = fcntl(fd, F_GETFD);
	if (flags < 0)
		goto unwind;
	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
		goto unwind;

	return fd;

unwind:
	errno_save = errno;
	close(fd);
	errno = errno_save;

	return -1;
}


int get_fd_tabsize(void)
{
	int m;


	m = getdtablesize();

	struct rlimit rl;

	getrlimit(RLIMIT_NOFILE, &rl);
	m = rl.rlim_cur;

	m = sysconf(_SC_OPEN_MAX);

	m = OPEN_MAX;

	return m;
}


int main(void)
{
	FILE *f;
	char *tmpname;
	f = xfmkstemp(&tmpname, NULL);
	unlink(tmpname);
	free(tmpname);
	fclose(f);
	return EXIT_FAILURE;
}



int mkdir_p(const char *path, mode_t mode)
{
	char *p, *dir;
	int rc = 0;

	if (!path || !*path)
		return -EINVAL;

	dir = p = strdup(path);
	if (!dir)
		return -ENOMEM;

	if (*p == '/')
		p++;

	while (p && *p) {
		char *e = strchr(p, '/');
		if (e)
			*e = '\0';
		if (*p) {
			rc = mkdir(dir, mode);
			if (rc && errno != EEXIST)
				break;
			rc = 0;
		}
		if (!e)
			break;
		*e = '/';
		p = e + 1;
	}

	free(dir);
	return rc;
}


char *stripoff_last_component(char *path)
{
	char *p = path ? strrchr(path, '/') : NULL;

	if (!p)
		return NULL;
	*p = '\0';
	return p + 1;
}
