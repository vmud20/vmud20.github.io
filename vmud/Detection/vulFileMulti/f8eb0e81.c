
























typedef enum {
	inode_unknown = 0, inode_file = 1, inode_dir = 2, inode_fifo = 3, } inode_t;




const char *applet = NULL;
const char *extraopts ="path1 [path2] [...]";
const char *getoptstring = "dDfFpm:o:sW" getoptstring_COMMON;
const struct option longopts[] = {
	{ "directory",          0, NULL, 'd', { "directory-truncate", 0, NULL, 'D', { "file",               0, NULL, 'f', { "file-truncate",      0, NULL, 'F', { "pipe",               0, NULL, 'p', { "mode",               1, NULL, 'm', { "owner",              1, NULL, 'o', { "symlinks",           0, NULL, 's', { "writable",           0, NULL, 'W', longopts_COMMON };









const char * const longopts_help[] = {
	"Create a directory if not exists", "Create/empty directory", "Create a file if not exists", "Truncate file", "Create a named pipe (FIFO) if not exists", "Mode to check", "Owner to check (user:group)", "follow symbolic links (irrelivent on linux)", "Check whether the path is writable or not", longopts_help_COMMON };









const char *usagestring = NULL;

static int get_dirfd(char *path, bool symlinks)
{
	char *ch;
	char *item;
	char *linkpath = NULL;
	char *path_dupe;
	char *str;
	int components = 0;
	int dirfd;
	int flags = 0;
	int new_dirfd;
	struct stat st;
	ssize_t linksize;

	if (!path || *path != '/')
		eerrorx("%s: empty or relative path", applet);
	dirfd = openat(dirfd, "/", O_RDONLY);
	if (dirfd == -1)
		eerrorx("%s: unable to open the root directory: %s", applet, strerror(errno));
	path_dupe = xstrdup(path);
	ch = path_dupe;
	while (*ch) {
		if (*ch == '/')
			components++;
		ch++;
	}
	item = strtok(path_dupe, "/");

	flags |= O_PATH;

	if (!symlinks)
		flags |= O_NOFOLLOW;
	flags |= O_RDONLY;
	while (dirfd > 0 && item && components > 1) {
		str = xstrdup(linkpath ? linkpath : item);
		new_dirfd = openat(dirfd, str, flags);
		if (new_dirfd == -1)
			eerrorx("%s: %s: could not open %s: %s", applet, path, str, strerror(errno));
		if (fstat(new_dirfd, &st) == -1)
			eerrorx("%s: %s: unable to stat %s: %s", applet, path, item, strerror(errno));
		if (S_ISLNK(st.st_mode) ) {
			if (st.st_uid != 0)
				eerrorx("%s: %s: symbolic link %s not owned by root", applet, path, str);
			linksize = st.st_size+1;
			if (linkpath)
				free(linkpath);
			linkpath = xmalloc(linksize);
			memset(linkpath, 0, linksize);
			if (readlinkat(new_dirfd, "", linkpath, linksize) != st.st_size)
				eerrorx("%s: symbolic link destination changed", applet);
			
			close(new_dirfd);
		} else {
			close(dirfd);
			dirfd = new_dirfd;
			free(linkpath);
			linkpath = NULL;
			item = strtok(NULL, "/");
			components--;
		}
	}
	free(path_dupe);
	if (linkpath) {
		free(linkpath);
		linkpath = NULL;
	}
	return dirfd;
}

static int do_check(char *path, uid_t uid, gid_t gid, mode_t mode, inode_t type, bool trunc, bool chowner, bool symlinks, bool selinux_on)
{
	struct stat st;
	char *name = NULL;
	int dirfd;
	int fd;
	int flags;
	int r;
	int readfd;
	int readflags;
	int u;

	memset(&st, 0, sizeof(st));
	flags = O_CREAT|O_NDELAY|O_WRONLY|O_NOCTTY;
	readflags = O_NDELAY|O_NOCTTY|O_RDONLY;

	flags |= O_CLOEXEC;
	readflags |= O_CLOEXEC;


	flags |= O_NOFOLLOW;
	readflags |= O_NOFOLLOW;

	if (trunc)
		flags |= O_TRUNC;
	xasprintf(&name, "%s", basename_c(path));
	dirfd = get_dirfd(path, symlinks);
	readfd = openat(dirfd, name, readflags);
	if (readfd == -1 || (type == inode_file && trunc)) {
		if (type == inode_file) {
			einfo("%s: creating file", path);
			if (!mode) 
				mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
			u = umask(0);
			fd = openat(dirfd, name, flags, mode);
			umask(u);
			if (fd == -1) {
				eerror("%s: open: %s", applet, strerror(errno));
				return -1;
			}
			if (readfd != -1 && trunc)
				close(readfd);
			readfd = fd;
		} else if (type == inode_dir) {
			einfo("%s: creating directory", path);
			if (!mode) 
				mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
			u = umask(0);
			
			r = mkdirat(dirfd, name, mode);
			umask(u);
			if (r == -1 && errno != EEXIST) {
				eerror("%s: mkdirat: %s", applet, strerror (errno));
				return -1;
			}
			readfd = openat(dirfd, name, readflags);
			if (readfd == -1) {
				eerror("%s: unable to open directory: %s", applet, strerror(errno));
				return -1;
			}
		} else if (type == inode_fifo) {
			einfo("%s: creating fifo", path);
			if (!mode) 
				mode = S_IRUSR | S_IWUSR;
			u = umask(0);
			r = mkfifo(path, mode);
			umask(u);
			if (r == -1 && errno != EEXIST) {
				eerror("%s: mkfifo: %s", applet, strerror (errno));
				return -1;
			}
			readfd = openat(dirfd, name, readflags);
			if (readfd == -1) {
				eerror("%s: unable to open fifo: %s", applet, strerror(errno));
				return -1;
			}
		}
	}
	if (fstat(readfd, &st) != -1) {
		if (type != inode_dir && S_ISDIR(st.st_mode)) {
			eerror("%s: is a directory", path);
			close(readfd);
			return 1;
		}
		if (type != inode_file && S_ISREG(st.st_mode)) {
			eerror("%s: is a file", path);
			close(readfd);
			return 1;
		}
		if (type != inode_fifo && S_ISFIFO(st.st_mode)) {
			eerror("%s: is a fifo", path);
			close(readfd);
			return -1;
		}

		if (mode && (st.st_mode & 0777) != mode) {
			if ((type != inode_dir) && (st.st_nlink > 1)) {
				eerror("%s: chmod: Too many hard links to %s", applet, path);
				close(readfd);
				return -1;
			}
			if (S_ISLNK(st.st_mode)) {
				eerror("%s: chmod: %s %s", applet, path, " is a symbolic link");
				close(readfd);
				return -1;
			}
			einfo("%s: correcting mode", path);
			if (fchmod(readfd, mode)) {
				eerror("%s: chmod: %s", applet, strerror(errno));
				close(readfd);
				return -1;
			}
		}

		if (chowner && (st.st_uid != uid || st.st_gid != gid)) {
			if ((type != inode_dir) && (st.st_nlink > 1)) {
				eerror("%s: chown: %s %s", applet, "Too many hard links to", path);
				close(readfd);
				return -1;
			}
			if (S_ISLNK(st.st_mode)) {
				eerror("%s: chown: %s %s", applet, path, " is a symbolic link");
				close(readfd);
				return -1;
			}
			einfo("%s: correcting owner", path);
			if (fchown(readfd, uid, gid)) {
				eerror("%s: chown: %s", applet, strerror(errno));
				close(readfd);
				return -1;
			}
		}
		if (selinux_on)
			selinux_util_label(path);
	} else {
		eerror("fstat: %s: %s", path, strerror(errno));
		close(readfd);
		return -1;
	}
	close(readfd);

	return 0;
}

static int parse_owner(struct passwd **user, struct group **group, const char *owner)
{
	char *u = xstrdup (owner);
	char *g = strchr (u, ':');
	int id = 0;
	int retval = 0;

	if (g)
		*g++ = '\0';

	if (user && *u) {
		if (sscanf(u, "%d", &id) == 1)
			*user = getpwuid((uid_t) id);
		else *user = getpwnam(u);
		if (*user == NULL)
			retval = -1;
	}

	if (group && g && *g) {
		if (sscanf(g, "%d", &id) == 1)
			*group = getgrgid((gid_t) id);
		else *group = getgrnam(g);
		if (*group == NULL)
			retval = -1;
	}

	free(u);
	return retval;
}

int main(int argc, char **argv)
{
	int opt;
	uid_t uid = geteuid();
	gid_t gid = getgid();
	mode_t mode = 0;
	struct passwd *pw = NULL;
	struct group *gr = NULL;
	inode_t type = inode_unknown;
	int retval = EXIT_SUCCESS;
	bool trunc = false;
	bool chowner = false;
	bool symlinks = false;
	bool writable = false;
	bool selinux_on = false;

	applet = basename_c(argv[0]);
	while ((opt = getopt_long(argc, argv, getoptstring, longopts, (int *) 0)) != -1)
	{
		switch (opt) {
		case 'D':
			trunc = true;
			
		case 'd':
			type = inode_dir;
			break;
		case 'F':
			trunc = true;
			
		case 'f':
			type = inode_file;
			break;
		case 'p':
			type = inode_fifo;
			break;
		case 'm':
			if (parse_mode(&mode, optarg) != 0)
				eerrorx("%s: invalid mode `%s'", applet, optarg);
			break;
		case 'o':
			chowner = true;
			if (parse_owner(&pw, &gr, optarg) != 0)
				eerrorx("%s: owner `%s' not found", applet, optarg);
			break;
		case 's':

			symlinks = true;

			break;
		case 'W':
			writable = true;
			break;

		case_RC_COMMON_GETOPT }
	}

	if (optind >= argc)
		usage(EXIT_FAILURE);

	if (writable && type != inode_unknown)
		eerrorx("%s: -W cannot be specified along with -d, -f or -p", applet);

	if (pw) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
	}
	if (gr)
		gid = gr->gr_gid;

	if (selinux_util_open() == 1)
		selinux_on = true;

	while (optind < argc) {
		if (writable)
			exit(!is_writable(argv[optind]));
		if (do_check(argv[optind], uid, gid, mode, type, trunc, chowner, symlinks, selinux_on))
			retval = EXIT_FAILURE;
		optind++;
	}

	if (selinux_on)
		selinux_util_close();

	return retval;
}
