





































struct sinfo {
	char *username;
	char *shell;
};


static void __attribute__((__noreturn__)) usage (FILE *fp)
{
	fputs(USAGE_HEADER, fp);
	fprintf(fp, _(" %s [options] [<username>]\n"), program_invocation_short_name);

	fputs(USAGE_SEPARATOR, fp);
	fputs(_("Change your login shell.\n"), fp);

	fputs(USAGE_OPTIONS, fp);
	fputs(_(" -s, --shell <shell>  specify login shell\n"), fp);
	fputs(_(" -l, --list-shells    print list of shells and exit\n"), fp);
	fputs(USAGE_SEPARATOR, fp);
	fputs(_(" -u, --help     display this help and exit\n"), fp);
	fputs(_(" -v, --version  output version information and exit\n"), fp);
	fprintf(fp, USAGE_MAN_TAIL("chsh(1)"));
	exit(fp == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}


static int get_shell_list(const char *shell_name)
{
	FILE *fp;
	int found = 0;
	char *buf = NULL;
	size_t sz = 0;
	ssize_t len;

	fp = fopen(_PATH_SHELLS, "r");
	if (!fp) {
		if (!shell_name)
			warnx(_("No known shells."));
		return 0;
	}
	while ((len = getline(&buf, &sz, fp)) != -1) {
		
		if (*buf == '#' || len < 2)
			continue;
		
		if (buf[len - 1] == '\n')
			buf[len - 1] = 0;
		
		if (shell_name) {
			if (!strcmp(shell_name, buf)) {
				found = 1;
				break;
			}
		} else printf("%s\n", buf);
	}
	fclose(fp);
	free(buf);
	return found;
}


static void parse_argv(int argc, char **argv, struct sinfo *pinfo)
{
	static const struct option long_options[] = {
		{"shell", required_argument, 0, 's', {"list-shells", no_argument, 0, 'l', {"help", no_argument, 0, 'u', {"version", no_argument, 0, 'v', {NULL, no_argument, 0, '0', };




	int c;

	while ((c = getopt_long(argc, argv, "s:luv", long_options, NULL)) != -1) {
		switch (c) {
		case 'v':
			printf(UTIL_LINUX_VERSION);
			exit(EXIT_SUCCESS);
		case 'u':
			usage(stdout);
		case 'l':
			get_shell_list(NULL);
			exit(EXIT_SUCCESS);
		case 's':
			if (!optarg)
				usage(stderr);
			pinfo->shell = optarg;
			break;
		default:
			usage(stderr);
		}
	}
	
	if (optind < argc) {
		if (optind + 1 < argc)
			usage(stderr);
		pinfo->username = argv[optind];
	}
}


static char *ask_new_shell(char *question, char *oldshell)
{
	int len;
	char *ans = NULL;
	size_t dummy = 0;
	ssize_t sz;

	if (!oldshell)
		oldshell = "";
	printf("%s [%s]: ", question, oldshell);
	sz = getline(&ans, &dummy, stdin);
	if (sz == -1)
		return NULL;
	
	ltrim_whitespace((unsigned char *) ans);
	len = rtrim_whitespace((unsigned char *) ans);
	if (len == 0)
		return NULL;
	return ans;
}


static void check_shell(const char *shell)
{
	if (*shell != '/')
		errx(EXIT_FAILURE, _("shell must be a full path name"));
	if (access(shell, F_OK) < 0)
		errx(EXIT_FAILURE, _("\"%s\" does not exist"), shell);
	if (access(shell, X_OK) < 0)
		errx(EXIT_FAILURE, _("\"%s\" is not executable"), shell);
	if (illegal_passwd_chars(shell))
		errx(EXIT_FAILURE, _("%s: has illegal characters"), shell);
	if (!get_shell_list(shell)) {

		if (!getuid())
			warnx(_("Warning: \"%s\" is not listed in %s."), shell, _PATH_SHELLS);
		else errx(EXIT_FAILURE, _("\"%s\" is not listed in %s.\n" "Use %s -l to see list."), shell, _PATH_SHELLS, program_invocation_short_name);




		warnx(_("\"%s\" is not listed in %s.\n" "Use %s -l to see list."), shell, _PATH_SHELLS, program_invocation_short_name);


	}
}

int main(int argc, char **argv)
{
	char *oldshell;
	int nullshell = 0;
	const uid_t uid = getuid();
	struct sinfo info = { 0 };
	struct passwd *pw;

	sanitize_env();
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	atexit(close_stdout);

	parse_argv(argc, argv, &info);
	if (!info.username) {
		pw = getpwuid(uid);
		if (!pw)
			errx(EXIT_FAILURE, _("you (user %d) don't exist."), uid);
	} else {
		pw = getpwnam(info.username);
		if (!pw)
			errx(EXIT_FAILURE, _("user \"%s\" does not exist."), info.username);
	}


	if (!(is_local(pw->pw_name)))
		errx(EXIT_FAILURE, _("can only change local entries"));



	if (is_selinux_enabled() > 0) {
		if (uid == 0) {
			if (checkAccess(pw->pw_name, PASSWD__CHSH) != 0) {
				security_context_t user_context;
				if (getprevcon(&user_context) < 0)
					user_context = (security_context_t) NULL;

				errx(EXIT_FAILURE, _("%s is not authorized to change the shell of %s"), user_context ? : _("Unknown user context"), pw->pw_name);


			}
		}
		if (setupDefaultContext(_PATH_PASSWD) != 0)
			errx(EXIT_FAILURE, _("can't set default context for %s"), _PATH_PASSWD);
	}


	oldshell = pw->pw_shell;
	if (oldshell == NULL || *oldshell == '\0') {
		oldshell = _PATH_BSHELL;	
		nullshell = 1;
	}

	

	
	if (geteuid() != getuid() && uid != pw->pw_uid) {

	if (uid != 0 && uid != pw->pw_uid) {

		errno = EACCES;
		err(EXIT_FAILURE, _("running UID doesn't match UID of user we're " "altering, shell change denied"));

	}
	if (uid != 0 && !get_shell_list(oldshell)) {
		errno = EACCES;
		err(EXIT_FAILURE, _("your shell is not in %s, " "shell change denied"), _PATH_SHELLS);
	}

	printf(_("Changing shell for %s.\n"), pw->pw_name);


	if (!auth_pam("chsh", uid, pw->pw_name)) {
		return EXIT_FAILURE;
	}

	if (!info.shell) {
		info.shell = ask_new_shell(_("New shell"), oldshell);
		if (!info.shell)
			return EXIT_SUCCESS;
	}

	check_shell(info.shell);

	if (!nullshell && strcmp(oldshell, info.shell) == 0)
		errx(EXIT_SUCCESS, _("Shell not changed."));


	if (set_value_libuser("chsh", pw->pw_name, uid, LU_LOGINSHELL, info.shell) < 0)
		errx(EXIT_FAILURE, _("Shell *NOT* changed.  Try again later."));

	pw->pw_shell = info.shell;
	if (setpwnam(pw) < 0)
		err(EXIT_FAILURE, _("setpwnam failed\n" "Shell *NOT* changed.  Try again later."));


	printf(_("Shell changed.\n"));
	return EXIT_SUCCESS;
}
