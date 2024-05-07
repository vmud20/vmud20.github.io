















































static rzip_control base_control, local_control, *control;

static void usage(bool compat)
{
	print_output("lrz%s version %s\n", compat ? "" : "ip", PACKAGE_VERSION);
	print_output("Copyright (C) Con Kolivas 2006-2021\n");
	print_output("Based on rzip ");
	print_output("Copyright (C) Andrew Tridgell 1998-2003\n\n");
	print_output("Usage: lrz%s [options] <file...>\n", compat ? "" : "ip");
	print_output("General options:\n");
	if (compat) {
		print_output("	-c, --stdout		output to STDOUT\n");
		print_output("	-C, --check		check integrity of file written on decompression\n");
	} else print_output("	-c, -C, --check		check integrity of file written on decompression\n");
	print_output("	-d, --decompress	decompress\n");
	print_output("	-e, --encrypt[=password] password protected sha512/aes128 encryption on compression\n");
	print_output("	-h, -?, --help		show help\n");
	print_output("	-H, --hash		display md5 hash integrity information\n");
	print_output("	-i, --info		show compressed file information\n");
	if (compat) {
		print_output("	-L, --license		display software version and license\n");
		print_output("	-P, --progress		show compression progress\n");
	} else print_output("	-q, --quiet		don't show compression progress\n");
	print_output("	-r, --recursive		operate recursively on directories\n");
	print_output("	-t, --test		test compressed file integrity\n");
	print_output("	-v[v%s], --verbose	Increase verbosity\n", compat ? "v" : "");
	print_output("	-V, --version		show version\n");
	print_output("Options affecting output:\n");
	if (!compat)
		print_output("	-D, --delete		delete existing files\n");
	print_output("	-f, --force		force overwrite of any existing files\n");
	if (compat)
		print_output("	-k, --keep		don't delete source files on de/compression\n");
	print_output("	-K, --keep-broken	keep broken or damaged output files\n");
	print_output("	-o, --outfile filename	specify the output file name and/or path\n");
	print_output("	-O, --outdir directory	specify the output directory when -o is not used\n");
	print_output("	-S, --suffix suffix	specify compressed suffix (default '.lrz')\n");
	print_output("Options affecting compression:\n");
	print_output("	--lzma			lzma compression (default)\n");
	print_output("	-b, --bzip2		bzip2 compression\n");
	print_output("	-g, --gzip		gzip compression using zlib\n");
	print_output("	-l, --lzo		lzo compression (ultra fast)\n");
	print_output("	-n, --no-compress	no backend compression - prepare for other compressor\n");
	print_output("	-z, --zpaq		zpaq compression (best, extreme compression, extremely slow)\n");
	print_output("Low level options:\n");
	if (compat) {
		print_output("	-1 .. -9		set lzma/bzip2/gzip compression level (1-9, default 7)\n");
		print_output("	--fast			alias for -1\n");
		print_output("	--best			alias for -9\n");
	}
	if (!compat)
		print_output("	-L, --level level	set lzma/bzip2/gzip compression level (1-9, default 7)\n");
	print_output("	-N, --nice-level value	Set nice value to value (default %d)\n", compat ? 0 : 19);
	print_output("	-p, --threads value	Set processor count to override number of threads\n");
	print_output("	-m, --maxram size	Set maximum available ram in hundreds of MB\n");
	print_output("				overrides detected amount of available ram\n");
	print_output("	-T, --threshold		Disable LZ4 compressibility testing\n");
	print_output("	-U, --unlimited		Use unlimited window size beyond ramsize (potentially much slower)\n");
	print_output("	-w, --window size	maximum compression window in hundreds of MB\n");
	print_output("				default chosen by heuristic dependent on ram and chosen compression\n");
	print_output("\nLRZIP=NOCONFIG environment variable setting can be used to bypass lrzip.conf.\n");
	print_output("TMP environment variable will be used for storage of temporary files when needed.\n");
	print_output("TMPDIR may also be stored in lrzip.conf file.\n");
	print_output("\nIf no filenames or \"-\" is specified, stdin/out will be used.\n");

}

static void license(void)
{
	print_output("lrz version %s\n", PACKAGE_VERSION);
	print_output("Copyright (C) Con Kolivas 2006-2016\n");
	print_output("Based on rzip ");
	print_output("Copyright (C) Andrew Tridgell 1998-2003\n\n");
	print_output("This is free software.  You may redistribute copies of it under the terms of\n");
	print_output("the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\n");
	print_output("There is NO WARRANTY, to the extent permitted by law.\n");
}

static void sighandler(int sig __UNUSED__)
{
	signal(sig, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	print_err("Interrupted\n");
	fatal_exit(&local_control);
}

static void show_summary(void)
{
	
	if (!INFO) {
		if (!TEST_ONLY)
			print_verbose("The following options are in effect for this %s.\n", DECOMPRESS ? "DECOMPRESSION" : "COMPRESSION");
		print_verbose("Threading is %s. Number of CPUs detected: %d\n", control->threads > 1? "ENABLED" : "DISABLED", control->threads);
		print_verbose("Detected %lld bytes ram\n", control->ramsize);
		print_verbose("Compression level %d\n", control->compression_level);
		print_verbose("Nice Value: %d\n", control->nice_val);
		print_verbose("Show Progress\n");
		print_maxverbose("Max ");
		print_verbose("Verbose\n");
		if (FORCE_REPLACE)
			print_verbose("Overwrite Files\n");
		if (!KEEP_FILES)
			print_verbose("Remove input files on completion\n");
		if (control->outdir)
			print_verbose("Output Directory Specified: %s\n", control->outdir);
		else if (control->outname)
			print_verbose("Output Filename Specified: %s\n", control->outname);
		if (TEST_ONLY)
			print_verbose("Test file integrity\n");
		if (control->tmpdir)
			print_verbose("Temporary Directory set as: %s\n", control->tmpdir);

		
		if (!DECOMPRESS && !TEST_ONLY) {
			print_verbose("Compression mode is: ");
			if (LZMA_COMPRESS)
				print_verbose("LZMA. LZ4 Compressibility testing %s\n", (LZ4_TEST? "enabled" : "disabled"));
			else if (LZO_COMPRESS)
				print_verbose("LZO\n");
			else if (BZIP2_COMPRESS)
				print_verbose("BZIP2. LZ4 Compressibility testing %s\n", (LZ4_TEST? "enabled" : "disabled"));
			else if (ZLIB_COMPRESS)
				print_verbose("GZIP\n");
			else if (ZPAQ_COMPRESS)
				print_verbose("ZPAQ. LZ4 Compressibility testing %s\n", (LZ4_TEST? "enabled" : "disabled"));
			else if (NO_COMPRESS)
				print_verbose("RZIP pre-processing only\n");
			if (control->window)
				print_verbose("Compression Window: %lld = %lldMB\n", control->window, control->window * 100ull);
			
			if (!control->window && !UNLIMITED) {
				i64 temp_chunk, temp_window;

				if (STDOUT || STDIN)
					temp_chunk = control->maxram;
				else temp_chunk = control->ramsize * 2 / 3;
				temp_window = temp_chunk / (100 * 1024 * 1024);
				print_verbose("Heuristically Computed Compression Window: %lld = %lldMB\n", temp_window, temp_window * 100ull);
			}
			if (UNLIMITED)
				print_verbose("Using Unlimited Window size\n");
		}
		if (!DECOMPRESS && !TEST_ONLY)
			print_maxverbose("Storage time in seconds %lld\n", control->secs);
		if (ENCRYPT)
			print_maxverbose("Encryption hash loops %lld\n", control->encloops);
	}
}

static struct option long_options[] = {
	{"bzip2",	no_argument,	0,	'b',  {"check",	no_argument,	0,	'c', {"check",	no_argument,	0,	'C', {"decompress",	no_argument,	0,	'd', {"delete",	no_argument,	0,	'D', {"encrypt",	optional_argument,	0,	'e', {"force",	no_argument,	0,	'f', {"gzip",	no_argument,	0,	'g', {"help",	no_argument,	0,	'h', {"hash",	no_argument,	0,	'H', {"info",	no_argument,	0,	'i', {"keep-broken",	no_argument,	0,	'k', {"keep-broken",	no_argument,	0,	'K', {"lzo",		no_argument,	0,	'l', {"lzma",       	no_argument,	0,	'/', {"level",	optional_argument,	0,	'L', {"license",	no_argument,	0,	'L', {"maxram",	required_argument,	0,	'm', {"no-compress",	no_argument,	0,	'n', {"nice-level",	required_argument,	0,	'N', {"outfile",	required_argument,	0,	'o', {"outdir",	required_argument,	0,	'O', {"threads",	required_argument,	0,	'p', {"progress",	no_argument,	0,	'P', {"quiet",	no_argument,	0,	'q', {"recursive",	no_argument,	0,	'r', {"suffix",	required_argument,	0,	'S', {"test",	no_argument,	0,	't', {"threshold",	required_argument,	0,	'T', {"unlimited",	no_argument,	0,	'U', {"verbose",	no_argument,	0,	'v', {"version",	no_argument,	0,	'V', {"window",	required_argument,	0,	'w', {"zpaq",	no_argument,	0,	'z', {"fast",	no_argument,	0,	'1', {"best",	no_argument,	0,	'9', {0,	0,	0,	0}, };





































static void set_stdout(struct rzip_control *control)
{
	control->flags |= FLAG_STDOUT;
	control->outFILE = stdout;
	control->msgout = stderr;
	register_outputfile(control, control->msgout);
}


static void recurse_dirlist(char *indir, char **dirlist, int *entries)
{
	char fname[MAX_PATH_LEN];
	struct stat istat;
	struct dirent *dp;
	DIR *dirp;

	dirp = opendir(indir);
	if (unlikely(!dirp))
		failure("Unable to open directory %s\n", indir);
	while ((dp = readdir(dirp)) != NULL) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		sprintf(fname, "%s/%s", indir, dp->d_name);
		if (unlikely(stat(fname, &istat)))
			failure("Unable to stat file %s\n", fname);
		if (S_ISDIR(istat.st_mode)) {
			recurse_dirlist(fname, dirlist, entries);
			continue;
		}
		if (!S_ISREG(istat.st_mode)) {
			print_err("Not regular file %s\n", fname);
			continue;
		}
		print_maxverbose("Added file %s\n", fname);
		*dirlist = realloc(*dirlist, MAX_PATH_LEN * (*entries + 1));
		strcpy(*dirlist + MAX_PATH_LEN * (*entries)++, fname);
	}
	closedir(dirp);
}

static const char *loptions = "bcCdDefghHiKlL:nN:o:O:p:PqrS:tTUm:vVw:z?";
static const char *coptions = "bcCdefghHikKlLnN:o:O:p:PrS:tTUm:vVw:z?123456789";

int main(int argc, char *argv[])
{
	bool lrzcat = false, compat = false, recurse = false;
	bool options_file = false, conf_file_compression_set = false; 
	struct timeval start_time, end_time;
	struct sigaction handler;
	double seconds,total_time; 
	bool nice_set = false;
	int c, i;
	int hours,minutes;
	extern int optind;
	char *eptr, *av; 
	char *endptr = NULL;

        control = &base_control;

	initialise_control(control);

	av = basename(argv[0]);
	if (!strcmp(av, "lrunzip"))
		control->flags |= FLAG_DECOMPRESS;
	else if (!strcmp(av, "lrzcat")) {
		control->flags |= FLAG_DECOMPRESS | FLAG_STDOUT;
		lrzcat = true;
	} else if (!strcmp(av, "lrz")) {
		
		control->flags &= ~FLAG_SHOW_PROGRESS;
		control->flags &= ~FLAG_KEEP_FILES;
		compat = true;
		long_options[1].name = "stdout";
		long_options[11].name = "keep";
	}

	
	CrcGenerateTable();

	
	eptr = getenv("LRZIP");
	if (eptr == NULL)
		options_file = read_config(control);
	else if (!strstr(eptr,"NOCONFIG"))
		options_file = read_config(control);
	if (options_file && (control->flags & FLAG_NOT_LZMA))		
		conf_file_compression_set = true;			

	while ((c = getopt_long(argc, argv, compat ? coptions : loptions, long_options, &i)) != -1) {
		switch (c) {
		case 'b':
		case 'g':
		case 'l':
		case 'n':
		case 'z':
			
			if ((control->flags & FLAG_NOT_LZMA) && conf_file_compression_set == false)
				failure("Can only use one of -l, -b, -g, -z or -n\n");
			
			control->flags &= ~FLAG_NOT_LZMA; 
			if (c == 'b')
				control->flags |= FLAG_BZIP2_COMPRESS;
			else if (c == 'g')
				control->flags |= FLAG_ZLIB_COMPRESS;
			else if (c == 'l')
				control->flags |= FLAG_LZO_COMPRESS;
			else if (c == 'n')
				control->flags |= FLAG_NO_COMPRESS;
			else if (c == 'z')
				control->flags |= FLAG_ZPAQ_COMPRESS;
			
			conf_file_compression_set = false;
			break;
		case '/':							
			control->flags &= ~FLAG_NOT_LZMA;			
			break;
		case 'c':
			if (compat) {
				control->flags |= FLAG_KEEP_FILES;
				set_stdout(control);
				break;
			}
			
		case 'C':
			control->flags |= FLAG_CHECK;
			control->flags |= FLAG_HASH;
			break;
		case 'd':
			control->flags |= FLAG_DECOMPRESS;
			break;
		case 'D':
			control->flags &= ~FLAG_KEEP_FILES;
			break;
		case 'e':
			control->flags |= FLAG_ENCRYPT;
			control->passphrase = optarg;
			break;
		case 'f':
			control->flags |= FLAG_FORCE_REPLACE;
			break;
		case 'h':
			usage(compat);
			exit(0);
			break;
		case 'H':
			control->flags |= FLAG_HASH;
			break;
		case 'i':
			control->flags |= FLAG_INFO;
			control->flags &= ~FLAG_DECOMPRESS;
			break;
		case 'k':
			if (compat) {
				control->flags |= FLAG_KEEP_FILES;
				break;
			}
			
		case 'K':
			control->flags |= FLAG_KEEP_BROKEN;
			break;
		case 'L':
			if (compat) {
				license();
				exit(0);
			}
			control->compression_level = strtol(optarg, &endptr, 10);
			if (control->compression_level < 1 || control->compression_level > 9)
				failure("Invalid compression level (must be 1-9)\n");
			if (*endptr)
				failure("Extra characters after compression level: \'%s\'\n", endptr);
			break;
		case 'm':
			control->ramsize = strtol(optarg, &endptr, 10) * 1024 * 1024 * 100;
			if (*endptr)
				failure("Extra characters after ramsize: \'%s\'\n", endptr);
			break;
		case 'N':
			nice_set = true;
			control->nice_val = strtol(optarg, &endptr, 10);
			if (control->nice_val < PRIO_MIN || control->nice_val > PRIO_MAX)
				failure("Invalid nice value (must be %d...%d)\n", PRIO_MIN, PRIO_MAX);
			if (*endptr)
				failure("Extra characters after nice level: \'%s\'\n", endptr);
			break;
		case 'o':
			if (control->outdir)
				failure("Cannot have -o and -O together\n");
			if (unlikely(STDOUT))
				failure("Cannot specify an output filename when outputting to stdout\n");
			control->outname = optarg;
			control->suffix = "";
			break;
		case 'O':
			if (control->outname)	
				failure("Cannot have options -o and -O together\n");
			if (unlikely(STDOUT))
				failure("Cannot specify an output directory when outputting to stdout\n");
			control->outdir = malloc(strlen(optarg) + 2);
			if (control->outdir == NULL)
				fatal("Failed to allocate for outdir\n");
			strcpy(control->outdir,optarg);
			if (strcmp(optarg+strlen(optarg) - 1, "/")) 	
				strcat(control->outdir, "/");
			break;
		case 'p':
			control->threads = strtol(optarg, &endptr, 10);
			if (control->threads < 1)
				failure("Must have at least one thread\n");
			if (*endptr)
				failure("Extra characters after number of threads: \'%s\'\n", endptr);
			break;
		case 'P':
			control->flags |= FLAG_SHOW_PROGRESS;
			break;
		case 'q':
			control->flags &= ~FLAG_SHOW_PROGRESS;
			break;
		case 'r':
			recurse = true;
			break;
		case 'S':
			if (control->outname)
				failure("Specified output filename already, can't specify an extension.\n");
			if (unlikely(STDOUT))
				failure("Cannot specify a filename suffix when outputting to stdout\n");
			control->suffix = optarg;
			break;
		case 't':
			if (control->outname)
				failure("Cannot specify an output file name when just testing.\n");
			if (compat)
				control->flags |= FLAG_KEEP_FILES;
			if (!KEEP_FILES)
				failure("Doubt that you want to delete a file when just testing.\n");
			control->flags |= FLAG_TEST_ONLY;
			break;
		case 'T':
			control->flags &= ~FLAG_THRESHOLD;
			break;
		case 'U':
			control->flags |= FLAG_UNLIMITED;
			break;
		case 'v':
			
			if (!(control->flags & FLAG_SHOW_PROGRESS))
				control->flags |= FLAG_SHOW_PROGRESS;
			else if (!(control->flags & FLAG_VERBOSITY) && !(control->flags & FLAG_VERBOSITY_MAX))
				control->flags |= FLAG_VERBOSITY;
			else if ((control->flags & FLAG_VERBOSITY)) {
				control->flags &= ~FLAG_VERBOSITY;
				control->flags |= FLAG_VERBOSITY_MAX;
			}
			break;
		case 'V':
			control->msgout = stdout;
			print_output("lrzip version %s\n", PACKAGE_VERSION);
			exit(0);
			break;
		case 'w':
			control->window = strtol(optarg, &endptr, 10);
			if (control->window < 1)
				failure("Window must be positive\n");
			if (*endptr)
				failure("Extra characters after window size: \'%s\'\n", endptr);
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			control->compression_level = c - '0';
			break;
		default:
			usage(compat);
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	if (control->outname) {
		if (argc > 1)
			failure("Cannot specify output filename with more than 1 file\n");
		if (recurse)
			failure("Cannot specify output filename with recursive\n");
	}

	if (VERBOSE && !SHOW_PROGRESS) {
		print_err("Cannot have -v and -q options. -v wins.\n");
		control->flags |= FLAG_SHOW_PROGRESS;
	}

	if (UNLIMITED && control->window) {
		print_err("If -U used, cannot specify a window size with -w.\n");
		control->window = 0;
	}

	if (argc < 1)
		control->flags |= FLAG_STDIN;

	if (UNLIMITED && STDIN) {
		print_err("Cannot have -U and stdin, unlimited mode disabled.\n");
		control->flags &= ~FLAG_UNLIMITED;
	}

	setup_overhead(control);

	
	control->current_priority = getpriority(PRIO_PROCESS, 0);
	if (nice_set) {
		if (!NO_COMPRESS) {
			
			if (unlikely(setpriority(PRIO_PROCESS, 0, control->nice_val/2) == -1)) {
				print_err("Warning, unable to set nice value %d...Resetting to %d\n", control->nice_val, control->current_priority);
				setpriority(PRIO_PROCESS, 0, (control->nice_val=control->current_priority));
			}
		} else {
			if (unlikely(setpriority(PRIO_PROCESS, 0, control->nice_val) == -1)) {
				print_err("Warning, unable to set nice value %d...Resetting to %d\n", control->nice_val, control->current_priority);
				setpriority(PRIO_PROCESS, 0, (control->nice_val=control->current_priority));
			}
		}
	}

	
	for (i = 0; i <= argc; i++) {
		char *dirlist = NULL, *infile = NULL;
		int direntries = 0, curentry = 0;

		if (i < argc)
			infile = argv[i];
		else if (!(i == 0 && STDIN))
			break;
		if (infile) {
			if ((strcmp(infile, "-") == 0))
				control->flags |= FLAG_STDIN;
			else {
				bool isdir = false;
				struct stat istat;

				if (unlikely(stat(infile, &istat)))
					failure("Failed to stat %s\n", infile);
				isdir = S_ISDIR(istat.st_mode);
				if (!recurse && (isdir || !S_ISREG(istat.st_mode))) {
					failure("lrzip only works directly on regular FILES.\n" "Use -r recursive, lrztar or pipe through tar for compressing directories.\n");
				}
				if (recurse && !isdir)
					failure("%s not a directory, -r recursive needs a directory\n", infile);
			}
		}

		if (recurse) {
			if (unlikely(STDIN || STDOUT))
				failure("Cannot use -r recursive with STDIO\n");
			recurse_dirlist(infile, &dirlist, &direntries);
		}

		if (INFO && STDIN)
			failure("Will not get file info from STDIN\n");
recursion:
		if (recurse) {
			if (curentry >= direntries) {
				infile = NULL;
				continue;
			}
			infile = dirlist + MAX_PATH_LEN * curentry++;
		}
		control->infile = infile;

		
		if ((control->outname && (strcmp(control->outname, "-") == 0)) || (!control->outname && STDIN) || lrzcat)
				set_stdout(control);

		if (lrzcat) {
			control->msgout = stderr;
			control->outFILE = stdout;
			register_outputfile(control, control->msgout);
		}

		if (!STDOUT) {
			control->msgout = stdout;
			register_outputfile(control, control->msgout);
		}

		if (STDIN)
			control->inFILE = stdin;

		
		sigemptyset(&handler.sa_mask);
		handler.sa_flags = 0;
		handler.sa_handler = &sighandler;
		sigaction(SIGTERM, &handler, 0);
		sigaction(SIGINT, &handler, 0);

		if (!FORCE_REPLACE) {
			if (STDIN && isatty(fileno((FILE *)stdin))) {
				print_err("Will not read stdin from a terminal. Use -f to override.\n");
				usage(compat);
				exit (1);
			}
			if (!TEST_ONLY && STDOUT && isatty(fileno((FILE *)stdout)) && !compat) {
				print_err("Will not write stdout to a terminal. Use -f to override.\n");
				usage(compat);
				exit (1);
			}
		}

		if (CHECK_FILE) {
			if (!DECOMPRESS) {
				print_err("Can only check file written on decompression.\n");
				control->flags &= ~FLAG_CHECK;
			} else if (STDOUT) {
				print_err("Can't check file written when writing to stdout. Checking disabled.\n");
				control->flags &= ~FLAG_CHECK;
			}
		}

		setup_ram(control);
		show_summary();

		gettimeofday(&start_time, NULL);

		if (unlikely((STDIN || STDOUT) && ENCRYPT))
			failure("Unable to work from STDIO while reading password\n");

		memcpy(&local_control, &base_control, sizeof(rzip_control));
		if (DECOMPRESS || TEST_ONLY)
			decompress_file(&local_control);
		else if (INFO)
			get_fileinfo(&local_control);
		else compress_file(&local_control);

		
		gettimeofday(&end_time, NULL);
		total_time = (end_time.tv_sec + (double)end_time.tv_usec / 1000000) - (start_time.tv_sec + (double)start_time.tv_usec / 1000000);
		hours = (int)total_time / 3600;
		minutes = (int)(total_time / 60) % 60;
		seconds = total_time - hours * 3600 - minutes * 60;
		if (!INFO)
			print_progress("Total time: %02d:%02d:%05.2f\n", hours, minutes, seconds);
		if (recurse)
			goto recursion;
	}

	return 0;
}
