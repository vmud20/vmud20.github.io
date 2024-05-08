






















static int have_mtab_info = 0;
static int var_mtab_does_not_exist = 0;
static int var_mtab_is_a_symlink = 0;

static void get_mtab_info(void) {
	struct stat mtab_stat;

	if (!have_mtab_info) {
		if (lstat(MOUNTED, &mtab_stat))
			var_mtab_does_not_exist = 1;
		else if (S_ISLNK(mtab_stat.st_mode))
			var_mtab_is_a_symlink = 1;
		have_mtab_info = 1;
	}
}

int mtab_does_not_exist(void) {
	get_mtab_info();
	return var_mtab_does_not_exist;
}

static int mtab_is_a_symlink(void) {
	get_mtab_info();
	return var_mtab_is_a_symlink;
}

int mtab_is_writable() {
	int fd;

	
	if (mtab_is_a_symlink())
		return 0;

	fd = open(MOUNTED, O_RDWR | O_CREAT, 0644);
	if (fd >= 0) {
		close(fd);
		return 1;
	} else return 0;
}



struct mntentchn mounttable, fstab;
static int got_mtab = 0;
static int got_fstab = 0;

static void read_mounttable(void), read_fstab(void);

struct mntentchn * mtab_head() {
	if (!got_mtab)
		read_mounttable();
	return &mounttable;
}

struct mntentchn * fstab_head() {
	if (!got_fstab)
		read_fstab();
	return &fstab;
}

static void my_free(const void *s) {
	if (s)
		free((void *) s);
}

static void my_free_mc(struct mntentchn *mc) {
	if (mc) {
		my_free(mc->m.mnt_fsname);
		my_free(mc->m.mnt_dir);
		my_free(mc->m.mnt_type);
		my_free(mc->m.mnt_opts);
		free(mc);
	}
}


static void discard_mntentchn(struct mntentchn *mc0) {
	struct mntentchn *mc, *mc1;

	for (mc = mc0->nxt; mc && mc != mc0; mc = mc1) {
		mc1 = mc->nxt;
		my_free_mc(mc);
	}
}

static void read_mntentchn(mntFILE *mfp, const char *fnam, struct mntentchn *mc0) {
	struct mntentchn *mc = mc0;
	struct my_mntent *mnt;

	while ((mnt = my_getmntent(mfp)) != NULL) {
		if (!streq(mnt->mnt_type, MNTTYPE_IGNORE)) {
			mc->nxt = (struct mntentchn *) xmalloc(sizeof(*mc));
			mc->nxt->prev = mc;
			mc = mc->nxt;
			mc->m = *mnt;
			mc->nxt = mc0;
		}
	}
	mc0->prev = mc;
	if (ferror(mfp->mntent_fp)) {
		int errsv = errno;
		error(_("warning: error reading %s: %s"), fnam, strerror (errsv));
		mc0->nxt = mc0->prev = NULL;
	}
	my_endmntent(mfp);
}


static void read_mounttable() {
	mntFILE *mfp;
	const char *fnam;
	struct mntentchn *mc = &mounttable;

	got_mtab = 1;
	mc->nxt = mc->prev = NULL;

	fnam = MOUNTED;
	mfp = my_setmntent (fnam, "r");
	if (mfp == NULL || mfp->mntent_fp == NULL) {
		int errsv = errno;
		fnam = PROC_MOUNTS;
		mfp = my_setmntent (fnam, "r");
		if (mfp == NULL || mfp->mntent_fp == NULL) {
			error(_("warning: can't open %s: %s"), MOUNTED, strerror (errsv));
			return;
		}
		if (verbose)
			printf (_("mount: could not open %s - " "using %s instead\n"), MOUNTED, PROC_MOUNTS);

	}
	read_mntentchn(mfp, fnam, mc);
}

static void read_fstab() {
	mntFILE *mfp = NULL;
	const char *fnam;
	struct mntentchn *mc = &fstab;

	got_fstab = 1;
	mc->nxt = mc->prev = NULL;

	fnam = _PATH_FSTAB;
	mfp = my_setmntent (fnam, "r");
	if (mfp == NULL || mfp->mntent_fp == NULL) {
		int errsv = errno;
		error(_("warning: can't open %s: %s"), _PATH_FSTAB, strerror (errsv));
		return;
	}
	read_mntentchn(mfp, fnam, mc);
}
     

 
struct mntentchn * getmntfile (const char *name) {
	struct mntentchn *mc, *mc0;

	mc0 = mtab_head();
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if (streq(mc->m.mnt_dir, name) || streq(mc->m.mnt_fsname, name))
			return mc;
	return NULL;
}

 
struct mntentchn * getmntdirbackward (const char *name, struct mntentchn *mcprev) {
	struct mntentchn *mc, *mc0;

	mc0 = mtab_head();
	if (!mcprev)
		mcprev = mc0;
	for (mc = mcprev->prev; mc && mc != mc0; mc = mc->prev)
		if (streq(mc->m.mnt_dir, name))
			return mc;
	return NULL;
}

 
struct mntentchn * getmntdevbackward (const char *name, struct mntentchn *mcprev) {
	struct mntentchn *mc, *mc0;

	mc0 = mtab_head();
	if (!mcprev)
		mcprev = mc0;
	for (mc = mcprev->prev; mc && mc != mc0; mc = mc->prev)
		if (streq(mc->m.mnt_fsname, name))
			return mc;
	return NULL;
}


int is_mounted_once(const char *name) {
	struct mntentchn *mc, *mc0;
	int ct = 0;

	mc0 = mtab_head();
	for (mc = mc0->prev; mc && mc != mc0; mc = mc->prev)
		if (streq(mc->m.mnt_dir, name) || streq(mc->m.mnt_fsname, name))
			ct++;
	return (ct == 1);
}

 
struct mntentchn * getmntoptfile (const char *file) {
	struct mntentchn *mc, *mc0;
	const char *opts, *s;
	int l;

	if (!file)
		return NULL;

	l = strlen(file);

	mc0 = mtab_head();
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if ((opts = mc->m.mnt_opts) != NULL && (s = strstr(opts, "loop="))
		    && !strncmp(s+5, file, l)
		    && (s == opts || s[-1] == ',')
		    && (s[l+5] == 0 || s[l+5] == ','))
			return mc;
	return NULL;
}

static int has_label(const char *device, const char *label) {
	const char *devlabel;
	int ret;

	devlabel = fsprobe_get_label_by_devname(device);
	ret = !strcmp(label, devlabel);
	
	return ret;
}

static int has_uuid(const char *device, const char *uuid){
	const char *devuuid;
	int ret;

	devuuid = fsprobe_get_uuid_by_devname(device);
	ret = !strcmp(uuid, devuuid);
	
	return ret;
}


struct mntentchn * getfsspecfile (const char *spec, const char *file) {
	struct mntentchn *mc, *mc0;

	mc0 = fstab_head();

	
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if (streq(mc->m.mnt_dir, file) && streq(mc->m.mnt_fsname, spec))
			return mc;

	
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if ((streq(mc->m.mnt_dir, file) || streq(canonicalize(mc->m.mnt_dir), file))
		    && (streq(mc->m.mnt_fsname, spec) || streq(canonicalize(mc->m.mnt_fsname), spec)))
			return mc;

	
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt) {
		if (!strncmp (mc->m.mnt_fsname, "LABEL=", 6) && (streq(mc->m.mnt_dir, file) || streq(canonicalize(mc->m.mnt_dir), file))) {

			if (has_label(spec, mc->m.mnt_fsname+6))
				return mc;
		}
		if (!strncmp (mc->m.mnt_fsname, "UUID=", 5) && (streq(mc->m.mnt_dir, file) || streq(canonicalize(mc->m.mnt_dir), file))) {

			if (has_uuid(spec, mc->m.mnt_fsname+5))
				return mc;
		}
	}
	return NULL;
}


struct mntentchn * getfsfile (const char *file) {
	struct mntentchn *mc, *mc0;

	mc0 = fstab_head();
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if (streq(mc->m.mnt_dir, file))
			return mc;
	return NULL;
}


struct mntentchn * getfsspec (const char *spec) {
	struct mntentchn *mc, *mc0;

	mc0 = fstab_head();
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if (streq(mc->m.mnt_fsname, spec))
			return mc;
	return NULL;
}


struct mntentchn * getfsuuidspec (const char *uuid) {
	struct mntentchn *mc, *mc0;

	mc0 = fstab_head();
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if (strncmp (mc->m.mnt_fsname, "UUID=", 5) == 0 && streq(mc->m.mnt_fsname + 5, uuid))
			return mc;
	return NULL;
}


struct mntentchn * getfsvolspec (const char *label) {
	struct mntentchn *mc, *mc0;

	mc0 = fstab_head();
	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt)
		if (strncmp (mc->m.mnt_fsname, "LABEL=", 6) == 0 && streq(mc->m.mnt_fsname + 6, label))
			return mc;
	return NULL;
}




static int we_created_lockfile = 0;
static int lockfile_fd = -1;


static int signals_have_been_setup = 0;


extern char *strsignal(int sig);	

static void handler (int sig) {
     die(EX_USER, "%s", strsignal(sig));
}

static void setlkw_timeout (int sig) {
     
}


void unlock_mtab (void) {
	if (we_created_lockfile) {
		close(lockfile_fd);
		lockfile_fd = -1;
		unlink (MOUNTED_LOCK);
		we_created_lockfile = 0;
	}
}
















void lock_mtab (void) {
	int i;
	struct timespec waittime;
	struct timeval maxtime;
	char linktargetfile[MOUNTLOCK_LINKTARGET_LTH];

	at_die = unlock_mtab;

	if (!signals_have_been_setup) {
		int sig = 0;
		struct sigaction sa;

		sa.sa_handler = handler;
		sa.sa_flags = 0;
		sigfillset (&sa.sa_mask);

		while (sigismember (&sa.sa_mask, ++sig) != -1 && sig != SIGCHLD) {
			if (sig == SIGALRM)
				sa.sa_handler = setlkw_timeout;
			else sa.sa_handler = handler;
			sigaction (sig, &sa, (struct sigaction *) 0);
		}
		signals_have_been_setup = 1;
	}

	sprintf(linktargetfile, MOUNTLOCK_LINKTARGET, getpid ());

	i = open (linktargetfile, O_WRONLY|O_CREAT, 0);
	if (i < 0) {
		int errsv = errno;
		
		die (EX_FILEIO, _("can't create lock file %s: %s " "(use -n flag to override)"), linktargetfile, strerror (errsv));

	}
	close(i);

	gettimeofday(&maxtime, NULL);
	maxtime.tv_sec += MOUNTLOCK_MAXTIME;

	waittime.tv_sec = 0;
	waittime.tv_nsec = (1000 * MOUNTLOCK_WAITTIME);

	
	while (!we_created_lockfile) {
		struct timeval now;
		struct flock flock;
		int errsv, j;

		j = link(linktargetfile, MOUNTED_LOCK);
		errsv = errno;

		if (j == 0)
			we_created_lockfile = 1;

		if (j < 0 && errsv != EEXIST) {
			(void) unlink(linktargetfile);
			die (EX_FILEIO, _("can't link lock file %s: %s " "(use -n flag to override)"), MOUNTED_LOCK, strerror (errsv));

		}

		lockfile_fd = open (MOUNTED_LOCK, O_WRONLY);

		if (lockfile_fd < 0) {
			
			int errsv = errno;
			gettimeofday(&now, NULL);
			if (errno == ENOENT && now.tv_sec < maxtime.tv_sec) {
				we_created_lockfile = 0;
				continue;
			}
			(void) unlink(linktargetfile);
			die (EX_FILEIO, _("can't open lock file %s: %s " "(use -n flag to override)"), MOUNTED_LOCK, strerror (errsv));

		}

		flock.l_type = F_WRLCK;
		flock.l_whence = SEEK_SET;
		flock.l_start = 0;
		flock.l_len = 0;

		if (j == 0) {
			
			if (fcntl (lockfile_fd, F_SETLK, &flock) == -1) {
				if (verbose) {
				    int errsv = errno;
				    printf(_("Can't lock lock file %s: %s\n"), MOUNTED_LOCK, strerror (errsv));
				}
				
			}
			(void) unlink(linktargetfile);
		} else {
			
			gettimeofday(&now, NULL);
			if (now.tv_sec < maxtime.tv_sec) {
				alarm(maxtime.tv_sec - now.tv_sec);
				if (fcntl (lockfile_fd, F_SETLKW, &flock) == -1) {
					int errsv = errno;
					(void) unlink(linktargetfile);
					die (EX_FILEIO, _("can't lock lock file %s: %s"), MOUNTED_LOCK, (errno == EINTR) ? _("timed out") : strerror (errsv));

				}
				alarm(0);

				nanosleep(&waittime, NULL);
			} else {
				(void) unlink(linktargetfile);
				die (EX_FILEIO, _("Cannot create link %s\n" "Perhaps there is a stale lock file?\n"), MOUNTED_LOCK);

			}
			close(lockfile_fd);
		}
	}
}



void update_mtab (const char *dir, struct my_mntent *instead) {
	mntFILE *mfp, *mftmp;
	const char *fnam = MOUNTED;
	struct mntentchn mtabhead;	
	struct mntentchn *mc, *mc0, *absent = NULL;

	if (mtab_does_not_exist() || !mtab_is_writable())
		return;

	lock_mtab();

	
	mc0 = mc = &mtabhead;
	mc->nxt = mc->prev = NULL;

	mfp = my_setmntent(fnam, "r");
	if (mfp == NULL || mfp->mntent_fp == NULL) {
		int errsv = errno;
		error (_("cannot open %s (%s) - mtab not updated"), fnam, strerror (errsv));
		goto leave;
	}

	read_mntentchn(mfp, fnam, mc);

	
	for (mc = mc0->prev; mc && mc != mc0; mc = mc->prev)
		if (streq(mc->m.mnt_dir, dir))
			break;
	if (mc && mc != mc0) {
		if (instead == NULL) {
			
			if (mc && mc != mc0) {
				mc->prev->nxt = mc->nxt;
				mc->nxt->prev = mc->prev;
				my_free_mc(mc);
			}
		} else if (!strcmp(mc->m.mnt_dir, instead->mnt_dir)) {
			
			my_free(mc->m.mnt_opts);
			mc->m.mnt_opts = xstrdup(instead->mnt_opts);
		} else {
			
			my_free(mc->m.mnt_dir);
			mc->m.mnt_dir = xstrdup(instead->mnt_dir);
		}
	} else if (instead) {
		
		absent = xmalloc(sizeof(*absent));
		absent->m.mnt_fsname = xstrdup(instead->mnt_fsname);
		absent->m.mnt_dir = xstrdup(instead->mnt_dir);
		absent->m.mnt_type = xstrdup(instead->mnt_type);
		absent->m.mnt_opts = xstrdup(instead->mnt_opts);
		absent->m.mnt_freq = instead->mnt_freq;
		absent->m.mnt_passno = instead->mnt_passno;
		absent->nxt = mc0;
		if (mc0->prev != NULL) {
			absent->prev = mc0->prev;
			mc0->prev->nxt = absent;
		} else {
			absent->prev = mc0;
		}
		mc0->prev = absent;
		if (mc0->nxt == NULL)
			mc0->nxt = absent;
	}

	
	mftmp = my_setmntent (MOUNTED_TEMP, "w");
	if (mftmp == NULL || mftmp->mntent_fp == NULL) {
		int errsv = errno;
		error (_("cannot open %s (%s) - mtab not updated"), MOUNTED_TEMP, strerror (errsv));
		discard_mntentchn(mc0);
		goto leave;
	}

	for (mc = mc0->nxt; mc && mc != mc0; mc = mc->nxt) {
		if (my_addmntent(mftmp, &(mc->m)) == 1) {
			int errsv = errno;
			die (EX_FILEIO, _("error writing %s: %s"), MOUNTED_TEMP, strerror (errsv));
		}
	}

	discard_mntentchn(mc0);

	if (fchmod (fileno (mftmp->mntent_fp), S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) < 0) {
		int errsv = errno;
		fprintf(stderr, _("error changing mode of %s: %s\n"), MOUNTED_TEMP, strerror (errsv));
	}
	my_endmntent (mftmp);

	{ 
	    struct stat sbuf;
	    if (stat (MOUNTED, &sbuf) == 0)
		chown (MOUNTED_TEMP, sbuf.st_uid, sbuf.st_gid);
	}

	
	if (rename (MOUNTED_TEMP, MOUNTED) < 0) {
		int errsv = errno;
		fprintf(stderr, _("can't rename %s to %s: %s\n"), MOUNTED_TEMP, MOUNTED, strerror(errsv));
	}

 leave:
	unlock_mtab();
}







int verbose;
int mount_quiet;
char *progname;

const char *fsprobe_get_label_by_devname(const char *spec) { return NULL; }
const char *fsprobe_get_uuid_by_devname(const char *spec) { return NULL; }
struct my_mntent *my_getmntent (mntFILE *mfp) { return NULL; }
mntFILE *my_setmntent (const char *file, char *mode) { return NULL; }
void my_endmntent (mntFILE *mfp) { }
int my_addmntent (mntFILE *mfp, struct my_mntent *mnt) { return 0; }
char *myrealpath(const char *path, char *resolved_path, int m) { return NULL; }

int main(int argc, char **argv)
{
	time_t synctime;
	char *filename;
	int nloops, id, i;
	pid_t pid = getpid();
	unsigned int usecs;
	struct timeval tv;
	struct stat st;
	long last = 0;

	progname = argv[0];

	if (argc < 3)
		die(EXIT_FAILURE, "usage: %s <id> <synctime> <file> <nloops>\n", progname);


	id = atoi(argv[1]);
	synctime = (time_t) atol(argv[2]);
	filename = argv[3];
	nloops = atoi(argv[4]);

	if (stat(filename, &st) < -1)
		die(EXIT_FAILURE, "%s: %s\n", filename, strerror(errno));

	fprintf(stderr, "%05d (pid=%05d): START\n", id, pid);

	gettimeofday(&tv, NULL);
	if (synctime && synctime - tv.tv_sec > 1) {
		usecs = ((synctime - tv.tv_sec) * 1000000UL) - (1000000UL - tv.tv_usec);
		usleep(usecs);
	}

	for (i = 0; i < nloops; i++) {
		FILE *f;
		long num;
		char buf[256];

		lock_mtab();

		if (!(f = fopen(filename, "r"))) {
			unlock_mtab();
			die(EXIT_FAILURE, "ERROR: %d (pid=%d, loop=%d): " "open for read failed\n", id, pid, i);
		}
		if (!fgets(buf, sizeof(buf), f)) {
			unlock_mtab();
			die(EXIT_FAILURE, "ERROR: %d (pid=%d, loop=%d): " "read failed\n", id, pid, i);
		}
		fclose(f);

		num = atol(buf) + 1;

		if (!(f = fopen(filename, "w"))) {
			unlock_mtab();
			die(EXIT_FAILURE, "ERROR: %d (pid=%d, loop=%d): " "open for write failed\n", id, pid, i);
		}
		fprintf(f, "%ld", num);
		fclose(f);

		unlock_mtab();

		gettimeofday(&tv, NULL);

		fprintf(stderr, "%010ld.%06ld %04d (pid=%05d, loop=%05d): " "num=%09ld last=%09ld\n", tv.tv_sec, tv.tv_usec, id, pid, i, num, last);


		last = num;

		
		usleep(50000);
	}

	fprintf(stderr, "%05d (pid=%05d): DONE\n", id, pid);

	exit(EXIT_SUCCESS);
}


