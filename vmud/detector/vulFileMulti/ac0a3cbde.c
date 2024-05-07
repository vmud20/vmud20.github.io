





































struct finfo {
	char *full_name;
	char *office;
	char *office_phone;
	char *home_phone;
	char *other;
};

struct chfn_control {
	struct passwd *pw;
	char *username;
	
	struct finfo oldf, newf;
	unsigned int allow_fullname:1, allow_room:1, allow_work:1, allow_home:1, changed:1, interactive:1;





};




static void __attribute__((__noreturn__)) usage(FILE *fp)
{
	fputs(USAGE_HEADER, fp);
	fprintf(fp, _(" %s [options] [<username>]\n"), program_invocation_short_name);

	fputs(USAGE_SEPARATOR, fp);
	fputs(_("Change your finger information.\n"), fp);

	fputs(USAGE_OPTIONS, fp);
	fputs(_(" -f, --full-name <full-name>  real name\n"), fp);
	fputs(_(" -o, --office <office>        office number\n"), fp);
	fputs(_(" -p, --office-phone <phone>   office phone number\n"), fp);
	fputs(_(" -h, --home-phone <phone>     home phone number\n"), fp);
	fputs(USAGE_SEPARATOR, fp);
	fputs(_(" -u, --help     display this help and exit\n"), fp);
	fputs(_(" -v, --version  output version information and exit\n"), fp);
	fprintf(fp, USAGE_MAN_TAIL("chfn(1)"));
	exit(fp == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}


static int check_gecos_string(const char *msg, char *gecos)
{
	const size_t len = strlen(gecos);

	if (MAX_FIELD_SIZE < len) {
		warnx(_("field %s is too long"), msg);
		return -1;
	}
	if (illegal_passwd_chars(gecos)) {
		warnx(_("%s: has illegal characters"), gecos);
		return -1;
	}
	return 0;
}


static void parse_argv(struct chfn_control *ctl, int argc, char **argv)
{
	int index, c, status = 0;
	static const struct option long_options[] = {
		{"full-name", required_argument, 0, 'f', {"office", required_argument, 0, 'o', {"office-phone", required_argument, 0, 'p', {"home-phone", required_argument, 0, 'h', {"help", no_argument, 0, 'u', {"version", no_argument, 0, 'v', {NULL, no_argument, 0, '0', };







	while ((c = getopt_long(argc, argv, "f:r:p:h:o:uv", long_options, &index)) != -1) {
		switch (c) {
		case 'f':
			if (!ctl->allow_fullname)
				errx(EXIT_FAILURE, _("login.defs forbids setting %s"), _("Name"));
			ctl->newf.full_name = optarg;
			status += check_gecos_string(_("Name"), optarg);
			break;
		case 'o':
			if (!ctl->allow_room)
				errx(EXIT_FAILURE, _("login.defs forbids setting %s"), _("Office"));
			ctl->newf.office = optarg;
			status += check_gecos_string(_("Office"), optarg);
			break;
		case 'p':
			if (!ctl->allow_work)
				errx(EXIT_FAILURE, _("login.defs forbids setting %s"), _("Office Phone"));
			ctl->newf.office_phone = optarg;
			status += check_gecos_string(_("Office Phone"), optarg);
			break;
		case 'h':
			if (!ctl->allow_home)
				errx(EXIT_FAILURE, _("login.defs forbids setting %s"), _("Home Phone"));
			ctl->newf.home_phone = optarg;
			status += check_gecos_string(_("Home Phone"), optarg);
			break;
		case 'v':
			printf(UTIL_LINUX_VERSION);
			exit(EXIT_SUCCESS);
		case 'u':
			usage(stdout);
		default:
			usage(stderr);
		}
		ctl->changed = 1;
		ctl->interactive = 0;
	}
	if (status != 0)
		exit(EXIT_FAILURE);
	
	if (optind < argc) {
		if (optind + 1 < argc)
			usage(stderr);
		ctl->username = argv[optind];
	}
	return;
}


static void parse_passwd(struct chfn_control *ctl)
{
	char *gecos;

	if (!ctl->pw)
		return;
	
	gecos = xstrdup(ctl->pw->pw_gecos);
	
	ctl->oldf.full_name = strsep(&gecos, ",");
	ctl->oldf.office = strsep(&gecos, ",");
	ctl->oldf.office_phone = strsep(&gecos, ",");
	ctl->oldf.home_phone = strsep(&gecos, ",");
	
	ctl->oldf.other = strsep(&gecos, ",");
}


static char *ask_new_field(struct chfn_control *ctl, const char *question, char *def_val)
{
	int len;
	char *ans;
	char buf[MAX_FIELD_SIZE + 2];

	if (!def_val)
		def_val = "";
	while (true) {
		printf("%s [%s]: ", question, def_val);
		__fpurge(stdin);
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			errx(EXIT_FAILURE, _("Aborted."));
		ans = buf;
		
		ltrim_whitespace((unsigned char *) ans);
		len = rtrim_whitespace((unsigned char *) ans);
		if (len == 0)
			return xstrdup(def_val);
		if (!strcasecmp(ans, "none")) {
			ctl->changed = 1;
			return xstrdup("");
		}
		if (check_gecos_string(question, ans) >= 0)
			break;
	}
	ctl->changed = 1;
	return xstrdup(ans);
}


static void get_login_defs(struct chfn_control *ctl)
{
	const char *s;
	size_t i;
	int broken = 0;

	
	if (geteuid() == getuid() && getuid() == 0) {
		ctl->allow_fullname = ctl->allow_room = ctl->allow_work = ctl->allow_home = 1;
		return;
	}
	s = getlogindefs_str("CHFN_RESTRICT", "");
	if (!strcmp(s, "yes")) {
		ctl->allow_room = ctl->allow_work = ctl->allow_home = 1;
		return;
	}
	if (!strcmp(s, "no")) {
		ctl->allow_fullname = ctl->allow_room = ctl->allow_work = ctl->allow_home = 1;
		return;
	}
	for (i = 0; s[i]; i++) {
		switch (s[i]) {
		case 'f':
			ctl->allow_fullname = 1;
			break;
		case 'r':
			ctl->allow_room = 1;
			break;
		case 'w':
			ctl->allow_work = 1;
			break;
		case 'h':
			ctl->allow_home = 1;
			break;
		default:
			broken = 1;
		}
	}
	if (broken)
		warnx(_("%s: CHFN_RESTRICT has unexpected value: %s"), _PATH_LOGINDEFS, s);
	if (!ctl->allow_fullname && !ctl->allow_room && !ctl->allow_work && !ctl->allow_home)
		errx(EXIT_FAILURE, _("%s: CHFN_RESTRICT does not allow any changes"), _PATH_LOGINDEFS);
	return;
}


static void ask_info(struct chfn_control *ctl)
{
	if (ctl->allow_fullname)
		ctl->newf.full_name = ask_new_field(ctl, _("Name"), ctl->oldf.full_name);
	if (ctl->allow_room)
		ctl->newf.office = ask_new_field(ctl, _("Office"), ctl->oldf.office);
	if (ctl->allow_work)
		ctl->newf.office_phone = ask_new_field(ctl, _("Office Phone"), ctl->oldf.office_phone);
	if (ctl->allow_home)
		ctl->newf.home_phone = ask_new_field(ctl, _("Home Phone"), ctl->oldf.home_phone);
	putchar('\n');
}


static char *find_field(char *nf, char *of)
{
	if (nf)
		return nf;
	if (of)
		return of;
	return xstrdup("");
}


static void add_missing(struct chfn_control *ctl)
{
	ctl->newf.full_name = find_field(ctl->newf.full_name, ctl->oldf.full_name);
	ctl->newf.office = find_field(ctl->newf.office, ctl->oldf.office);
	ctl->newf.office_phone = find_field(ctl->newf.office_phone, ctl->oldf.office_phone);
	ctl->newf.home_phone = find_field(ctl->newf.home_phone, ctl->oldf.home_phone);
	ctl->newf.other = find_field(ctl->newf.other, ctl->oldf.other);
	printf("\n");
}


static int save_new_data(struct chfn_control *ctl)
{
	char *gecos;
	int len;

	
	len = xasprintf(&gecos, "%s,%s,%s,%s,%s", ctl->newf.full_name, ctl->newf.office, ctl->newf.office_phone, ctl->newf.home_phone, ctl->newf.other);





	
	if (!ctl->newf.other) {
		while (len > 0 && gecos[len - 1] == ',')
			len--;
		gecos[len] = 0;
	}


	if (set_value_libuser("chfn", ctl->username, ctl->pw->pw_uid, LU_GECOS, gecos) < 0) {

	
	ctl->pw->pw_gecos = gecos;
	if (setpwnam(ctl->pw) < 0) {
		warn("setpwnam failed");

		printf(_ ("Finger information *NOT* changed.  Try again later.\n"));
		return -1;
	}
	free(gecos);
	printf(_("Finger information changed.\n"));
	return 0;
}

int main(int argc, char **argv)
{
	uid_t uid;
	struct chfn_control ctl = {
		.interactive = 1 };

	sanitize_env();
	setlocale(LC_ALL, "");	
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	atexit(close_stdout);
	uid = getuid();

	
	get_login_defs(&ctl);

	parse_argv(&ctl, argc, argv);
	if (!ctl.username) {
		ctl.pw = getpwuid(uid);
		if (!ctl.pw)
			errx(EXIT_FAILURE, _("you (user %d) don't exist."), uid);
		ctl.username = ctl.pw->pw_name;
	} else {
		ctl.pw = getpwnam(ctl.username);
		if (!ctl.pw)
			errx(EXIT_FAILURE, _("user \"%s\" does not exist."), ctl.username);
	}
	parse_passwd(&ctl);

	if (!(is_local(ctl.username)))
		errx(EXIT_FAILURE, _("can only change local entries"));



	if (is_selinux_enabled() > 0) {
		if (uid == 0) {
			if (checkAccess(ctl.username, PASSWD__CHFN) != 0) {
				security_context_t user_context;
				if (getprevcon(&user_context) < 0)
					user_context = NULL;
				errx(EXIT_FAILURE, _("%s is not authorized to change " "the finger info of %s"), user_context ? : _("Unknown user context"), ctl.username);



			}
		}
		if (setupDefaultContext(_PATH_PASSWD))
			errx(EXIT_FAILURE, _("can't set default context for %s"), _PATH_PASSWD);
	}



	
	if (geteuid() != getuid() && uid != ctl.pw->pw_uid) {

	if (uid != 0 && uid != ctl.pw->pw_uid) {

		errno = EACCES;
		err(EXIT_FAILURE, _("running UID doesn't match UID of user we're " "altering, change denied"));
	}

	printf(_("Changing finger information for %s.\n"), ctl.username);


	if (!auth_pam("chfn", uid, ctl.username)) {
		return EXIT_FAILURE;
	}


	if (ctl.interactive)
		ask_info(&ctl);

	add_missing(&ctl);

	if (!ctl.changed) {
		printf(_("Finger information not changed.\n"));
		return EXIT_SUCCESS;
	}

	return save_new_data(&ctl) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
