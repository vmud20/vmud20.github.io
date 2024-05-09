




































































































extern char build_date[];
extern char build_time[];
extern char build_rev[];
extern char build_platform[];
extern char build_type[];
extern char build_cflags[];
extern char build_cxxflags[];
extern char build_linkflags[];
extern char build_system[];



static int print_help(int argc, const char **argv, void *data);
static int print_version(int argc, const char **argv, void *data);



extern int pluginapi_force_ref(void);  

char bprogname[FILE_MAX]; 
char btempdir[FILE_MAX];




static void setCallbacks(void); 



static void fpe_handler(int UNUSED(sig))
{
	
}




static void blender_esc(int sig)
{
	static int count = 0;
	
	G.afbreek = 1;	
	
	if (sig == 2) {
		if (count) {
			printf("\nBlender killed\n");
			exit(2);
		}
		printf("\nSent an internal break event. Press ^C again to kill Blender\n");
		count++;
	}
}




static void strip_quotes(char *str)
{
	if(str[0] == '"') {
		int len= strlen(str) - 1;
		memmove(str, str+1, len);
		if(str[len-1] == '"') {
			str[len-1]= '\0';
		}
	}
}


static int print_version(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	printf (BLEND_VERSION_STRING_FMT);

	printf ("\tbuild date: %s\n", build_date);
	printf ("\tbuild time: %s\n", build_time);
	printf ("\tbuild revision: %s\n", build_rev);
	printf ("\tbuild platform: %s\n", build_platform);
	printf ("\tbuild type: %s\n", build_type);
	printf ("\tbuild c flags: %s\n", build_cflags);
	printf ("\tbuild c++ flags: %s\n", build_cxxflags);
	printf ("\tbuild link flags: %s\n", build_linkflags);
	printf ("\tbuild system: %s\n", build_system);

	exit(0);

	return 0;
}

static int print_help(int UNUSED(argc), const char **UNUSED(argv), void *data)
{
	bArgs *ba = (bArgs*)data;

	printf (BLEND_VERSION_STRING_FMT);
	printf ("Usage: blender [args ...] [file] [args ...]\n\n");

	printf ("Render Options:\n");
	BLI_argsPrintArgDoc(ba, "--background");
	BLI_argsPrintArgDoc(ba, "--render-anim");
	BLI_argsPrintArgDoc(ba, "--scene");
	BLI_argsPrintArgDoc(ba, "--render-frame");
	BLI_argsPrintArgDoc(ba, "--frame-start");
	BLI_argsPrintArgDoc(ba, "--frame-end");
	BLI_argsPrintArgDoc(ba, "--frame-jump");
	BLI_argsPrintArgDoc(ba, "--render-output");
	BLI_argsPrintArgDoc(ba, "--engine");
	
	printf("\n");
	printf ("Format Options:\n");
	BLI_argsPrintArgDoc(ba, "--render-format");
	BLI_argsPrintArgDoc(ba, "--use-extension");
	BLI_argsPrintArgDoc(ba, "--threads");

	printf("\n");
	printf ("Animation Playback Options:\n");
	BLI_argsPrintArgDoc(ba, "-a");
				
	printf("\n");
	printf ("Window Options:\n");
	BLI_argsPrintArgDoc(ba, "--window-border");
	BLI_argsPrintArgDoc(ba, "--window-borderless");
	BLI_argsPrintArgDoc(ba, "--window-geometry");
	BLI_argsPrintArgDoc(ba, "--start-console");

	printf("\n");
	printf ("Game Engine Specific Options:\n");
	BLI_argsPrintArgDoc(ba, "-g");

	printf("\n");
	printf ("Misc Options:\n");
	BLI_argsPrintArgDoc(ba, "--debug");
	BLI_argsPrintArgDoc(ba, "--debug-fpe");
	printf("\n");
	BLI_argsPrintArgDoc(ba, "--factory-startup");
	printf("\n");
	BLI_argsPrintArgDoc(ba, "--env-system-config");
	BLI_argsPrintArgDoc(ba, "--env-system-datafiles");
	BLI_argsPrintArgDoc(ba, "--env-system-scripts");
	BLI_argsPrintArgDoc(ba, "--env-system-plugins");
	BLI_argsPrintArgDoc(ba, "--env-system-python");
	printf("\n");
	BLI_argsPrintArgDoc(ba, "-nojoystick");
	BLI_argsPrintArgDoc(ba, "-noglsl");
	BLI_argsPrintArgDoc(ba, "-noaudio");
	BLI_argsPrintArgDoc(ba, "-setaudio");

	printf("\n");

	BLI_argsPrintArgDoc(ba, "--help");

	printf("\n");

	BLI_argsPrintArgDoc(ba, "--enable-autoexec");
	BLI_argsPrintArgDoc(ba, "--disable-autoexec");

	printf("\n");

	BLI_argsPrintArgDoc(ba, "--python");
	BLI_argsPrintArgDoc(ba, "--python-console");
	BLI_argsPrintArgDoc(ba, "--addons");


	BLI_argsPrintArgDoc(ba, "-R");
	BLI_argsPrintArgDoc(ba, "-r");

	BLI_argsPrintArgDoc(ba, "--version");

	BLI_argsPrintArgDoc(ba, "--");

	printf ("Other Options:\n");
	BLI_argsPrintOtherDoc(ba);

	printf ("Argument Parsing:\n");
	printf ("\targuments must be separated by white space. eg\n");
	printf ("\t\t\"blender -ba test.blend\"\n");
	printf ("\t...will ignore the 'a'\n");
	printf ("\t\t\"blender -b test.blend -f8\"\n");
	printf ("\t...will ignore 8 because there is no space between the -f and the frame value\n\n");

	printf ("Argument Order:\n");
	printf ("Arguments are executed in the order they are given. eg\n");
	printf ("\t\t\"blender --background test.blend --render-frame 1 --render-output /tmp\"\n");
	printf ("\t...will not render to /tmp because '--render-frame 1' renders before the output path is set\n");
	printf ("\t\t\"blender --background --render-output /tmp test.blend --render-frame 1\"\n");
	printf ("\t...will not render to /tmp because loading the blend file overwrites the render output that was set\n");
	printf ("\t\t\"blender --background test.blend --render-output /tmp --render-frame 1\" works as expected.\n\n");

	printf ("\nEnvironment Variables:\n");
	printf ("  $BLENDER_USER_CONFIG      Directory for user configuration files.\n");
	printf ("  $BLENDER_SYSTEM_CONFIG    Directory for system wide configuration files.\n");
	printf ("  $BLENDER_USER_SCRIPTS     Directory for user scripts.\n");
	printf ("  $BLENDER_SYSTEM_SCRIPTS   Directory for system wide scripts.\n");
	printf ("  $BLENDER_USER_DATAFILES   Directory for user data files (icons, translations, ..).\n");
	printf ("  $BLENDER_SYSTEM_DATAFILES Directory for system wide data files.\n");
	printf ("  $BLENDER_SYSTEM_PYTHON    Directory for system python libraries.\n");

	printf ("  $TEMP                     Store temporary files here.\n");

	printf ("  $TMP or $TMPDIR           Store temporary files here.\n");


	printf ("  $SDL_AUDIODRIVER          LibSDL audio driver - alsa, esd, dma.\n");

	printf ("  $PYTHONHOME               Path to the python directory, eg. /usr/lib/python.\n\n");

	exit(0);

	return 0;
}


double PIL_check_seconds_timer(void);



static int end_arguments(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	return -1;
}

static int enable_python(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	G.f |= G_SCRIPT_AUTOEXEC;
	G.f |= G_SCRIPT_OVERRIDE_PREF;
	return 0;
}

static int disable_python(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	G.f &= ~G_SCRIPT_AUTOEXEC;
	G.f |= G_SCRIPT_OVERRIDE_PREF;
	return 0;
}

static int background_mode(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	G.background = 1;
	return 0;
}

static int debug_mode(int UNUSED(argc), const char **UNUSED(argv), void *data)
{
	G.f |= G_DEBUG;		
	printf(BLEND_VERSION_STRING_FMT);
	MEM_set_memory_debug();


	printf("Build: %s %s %s %s\n", build_date, build_time, build_platform, build_type);


	BLI_argsPrint(data);
	return 0;
}

static int set_fpe(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{

	
	signal(SIGFPE, fpe_handler);


	feenableexcept(FE_DIVBYZERO | FE_INVALID | FE_OVERFLOW );


	
	_MM_SET_EXCEPTION_MASK(_MM_MASK_MASK &~ (_MM_MASK_OVERFLOW|_MM_MASK_INVALID|_MM_MASK_DIV_ZERO));


	_controlfp_s(NULL, 0, _MCW_EM); 
	_controlfp_s(NULL, _EM_DENORMAL | _EM_UNDERFLOW | _EM_INEXACT, _MCW_EM); 



	return 0;
}

static int set_factory_startup(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	G.factory_startup= 1;
	return 0;
}

static int set_env(int argc, const char **argv, void *UNUSED(data))
{
	

	char env[64]= "BLENDER";
	char *ch_dst= env + 7; 
	const char *ch_src= argv[0] + 5; 

	if (argc < 2) {
		printf("%s requires one argument\n", argv[0]);
		exit(1);
	}

	for(; *ch_src; ch_src++, ch_dst++) {
		*ch_dst= (*ch_src == '-') ? '_' : (*ch_src)-32; 
	}

	*ch_dst= '\0';
	BLI_setenv(env, argv[1]);
	return 1;
}

static int playback_mode(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	
	if (G.background == 0) {


		exit(0);
	}

	return -2;
}

static int prefsize(int argc, const char **argv, void *UNUSED(data))
{
	int stax, stay, sizx, sizy;

	if (argc < 5) {
		printf ("-p requires four arguments\n");
		exit(1);
	}

	stax= atoi(argv[1]);
	stay= atoi(argv[2]);
	sizx= atoi(argv[3]);
	sizy= atoi(argv[4]);

	WM_setprefsize(stax, stay, sizx, sizy);

	return 4;
}

static int with_borders(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	WM_setinitialstate_normal();
	return 0;
}

static int without_borders(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	WM_setinitialstate_fullscreen();
	return 0;
}

extern int wm_start_with_console; 
static int start_with_console(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	wm_start_with_console = 1;
	return 0;
}

static int register_extension(int UNUSED(argc), const char **UNUSED(argv), void *data)
{

	if (data)
		G.background = 1;
	RegisterBlendExtension();

	(void)data; 

	return 0;
}

static int no_joystick(int UNUSED(argc), const char **UNUSED(argv), void *data)
{

	(void)data;

	SYS_SystemHandle *syshandle = data;

	
	SYS_WriteCommandLineInt(*syshandle, "nojoystick",1);
	if (G.f & G_DEBUG) printf("disabling nojoystick\n");


	return 0;
}

static int no_glsl(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	GPU_extensions_disable();
	return 0;
}

static int no_audio(int UNUSED(argc), const char **UNUSED(argv), void *UNUSED(data))
{
	sound_force_device(0);
	return 0;
}

static int set_audio(int argc, const char **argv, void *UNUSED(data))
{
	if (argc < 1) {
		printf("-setaudio require one argument\n");
		exit(1);
	}

	sound_force_device(sound_define_from_str(argv[1]));
	return 1;
}

static int set_output(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (argc >= 1){
		if (CTX_data_scene(C)) {
			Scene *scene= CTX_data_scene(C);
			BLI_strncpy(scene->r.pic, argv[1], FILE_MAXDIR);
		} else {
			printf("\nError: no blend loaded. cannot use '-o / --render-output'.\n");
		}
		return 1;
	} else {
		printf("\nError: you must specify a path after '-o  / --render-output'.\n");
		return 0;
	}
}

static int set_engine(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (argc >= 1)
	{
		if (!strcmp(argv[1],"help"))
		{
			RenderEngineType *type = NULL;

			for( type = R_engines.first; type; type = type->next )
			{
				printf("\t%s\n", type->idname);
			}
			exit(0);
		}
		else {
			if (CTX_data_scene(C)==NULL)
			{
				printf("\nError: no blend loaded. order the arguments so '-E  / --engine ' is after a blend is loaded.\n");
			}
			else {
				Scene *scene= CTX_data_scene(C);
				RenderData *rd = &scene->r;

				if(BLI_findstring(&R_engines, argv[1], offsetof(RenderEngineType, idname))) {
					BLI_strncpy(rd->engine, argv[1], sizeof(rd->engine));
				}
			}
		}

		return 1;
	}
	else {
		printf("\nEngine not specified.\n");
		return 0;
	}
}

static int set_image_type(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (argc >= 1){
		const char *imtype = argv[1];
		if (CTX_data_scene(C)==NULL) {
			printf("\nError: no blend loaded. order the arguments so '-F  / --render-format' is after the blend is loaded.\n");
		} else {
			Scene *scene= CTX_data_scene(C);
			if      (!strcmp(imtype,"TGA")) scene->r.imtype = R_TARGA;
			else if (!strcmp(imtype,"IRIS")) scene->r.imtype = R_IRIS;

			else if (!strcmp(imtype,"DDS")) scene->r.imtype = R_DDS;

			else if (!strcmp(imtype,"JPEG")) scene->r.imtype = R_JPEG90;
			else if (!strcmp(imtype,"IRIZ")) scene->r.imtype = R_IRIZ;
			else if (!strcmp(imtype,"RAWTGA")) scene->r.imtype = R_RAWTGA;
			else if (!strcmp(imtype,"AVIRAW")) scene->r.imtype = R_AVIRAW;
			else if (!strcmp(imtype,"AVIJPEG")) scene->r.imtype = R_AVIJPEG;
			else if (!strcmp(imtype,"PNG")) scene->r.imtype = R_PNG;
			else if (!strcmp(imtype,"AVICODEC")) scene->r.imtype = R_AVICODEC;
			else if (!strcmp(imtype,"QUICKTIME")) scene->r.imtype = R_QUICKTIME;
			else if (!strcmp(imtype,"BMP")) scene->r.imtype = R_BMP;

			else if (!strcmp(imtype,"HDR")) scene->r.imtype = R_RADHDR;


			else if (!strcmp(imtype,"TIFF")) scene->r.imtype = R_TIFF;


			else if (!strcmp(imtype,"EXR")) scene->r.imtype = R_OPENEXR;
			else if (!strcmp(imtype,"MULTILAYER")) scene->r.imtype = R_MULTILAYER;

			else if (!strcmp(imtype,"MPEG")) scene->r.imtype = R_FFMPEG;
			else if (!strcmp(imtype,"FRAMESERVER")) scene->r.imtype = R_FRAMESERVER;

			else if (!strcmp(imtype,"CINEON")) scene->r.imtype = R_CINEON;
			else if (!strcmp(imtype,"DPX")) scene->r.imtype = R_DPX;


			else if (!strcmp(imtype,"JP2")) scene->r.imtype = R_JP2;

			else printf("\nError: Format from '-F / --render-format' not known or not compiled in this release.\n");
		}
		return 1;
	} else {
		printf("\nError: you must specify a format after '-F  / --render-foramt'.\n");
		return 0;
	}
}

static int set_threads(int argc, const char **argv, void *UNUSED(data))
{
	if (argc >= 1) {
		if(G.background) {
			RE_set_max_threads(atoi(argv[1]));
		} else {
			printf("Warning: threads can only be set in background mode\n");
		}
		return 1;
	} else {
		printf("\nError: you must specify a number of threads between 0 and 8 '-t  / --threads'.\n");
		return 0;
	}
}

static int set_extension(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (argc >= 1) {
		if (CTX_data_scene(C)) {
			Scene *scene= CTX_data_scene(C);
			if (argv[1][0] == '0') {
				scene->r.scemode &= ~R_EXTENSION;
			} else if (argv[1][0] == '1') {
				scene->r.scemode |= R_EXTENSION;
			} else {
				printf("\nError: Use '-x 1 / -x 0' To set the extension option or '--use-extension'\n");
			}
		} else {
			printf("\nError: no blend loaded. order the arguments so '-o ' is after '-x '.\n");
		}
		return 1;
	} else {
		printf("\nError: you must specify a path after '- '.\n");
		return 0;
	}
}

static int set_ge_parameters(int argc, const char **argv, void *data)
{
	int a = 0;

	SYS_SystemHandle syshandle = *(SYS_SystemHandle*)data;

	(void)data;




	if(argc >= 1)
	{
		const char *paramname = argv[a];
		
		if (a+1 < argc && (*(argv[a+1]) == '='))
		{
			a++;
			if (a+1 < argc)
			{
				a++;
				

				SYS_WriteCommandLineString(syshandle,paramname,argv[a]);

			}  else {
				printf("error: argument assignment (%s) without value.\n",paramname);
				return 0;
			}
			

		} else {

			SYS_WriteCommandLineInt(syshandle,argv[a],1);

			
			if (!strcmp(argv[a],"nomipmap"))
			{
				GPU_set_mipmap(0); 
			}
			
			if (!strcmp(argv[a],"linearmipmap"))
			{
				GPU_set_linear_mipmap(1); 
			}


		} 
	}

	return a;
}

static int render_frame(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (CTX_data_scene(C)) {
		Main *bmain= CTX_data_main(C);
		Scene *scene= CTX_data_scene(C);

		if (argc > 1) {
			Render *re = RE_NewRender(scene->id.name);
			int frame;
			ReportList reports;

			switch(*argv[1]) {
			case '+':
				frame= scene->r.sfra + atoi(argv[1]+1);
				break;
			case '-':
				frame= (scene->r.efra - atoi(argv[1]+1)) + 1;
				break;
			default:
				frame= atoi(argv[1]);
				break;
			}

			BKE_reports_init(&reports, RPT_PRINT);

			frame = MIN2(MAXFRAME, MAX2(MINAFRAME, frame));

			RE_BlenderAnim(re, bmain, scene, scene->lay, frame, frame, scene->r.frame_step, &reports);
			return 1;
		} else {
			printf("\nError: frame number must follow '-f / --render-frame'.\n");
			return 0;
		}
	} else {
		printf("\nError: no blend loaded. cannot use '-f / --render-frame'.\n");
		return 0;
	}
}

static int render_animation(int UNUSED(argc), const char **UNUSED(argv), void *data)
{
	bContext *C = data;
	if (CTX_data_scene(C)) {
		Main *bmain= CTX_data_main(C);
		Scene *scene= CTX_data_scene(C);
		Render *re= RE_NewRender(scene->id.name);
		ReportList reports;
		BKE_reports_init(&reports, RPT_PRINT);
		RE_BlenderAnim(re, bmain, scene, scene->lay, scene->r.sfra, scene->r.efra, scene->r.frame_step, &reports);
	} else {
		printf("\nError: no blend loaded. cannot use '-a'.\n");
	}
	return 0;
}

static int set_scene(int argc, const char **argv, void *data)
{
	if(argc > 1) {
		bContext *C= data;
		Scene *sce= set_scene_name(CTX_data_main(C), argv[1]);
		if(sce) {
			CTX_data_scene_set(C, sce);
		}
		return 1;
	} else {
		printf("\nError: Scene name must follow '-S / --scene'.\n");
		return 0;
	}
}

static int set_start_frame(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (CTX_data_scene(C)) {
		Scene *scene= CTX_data_scene(C);
		if (argc > 1) {
			int frame = atoi(argv[1]);
			(scene->r.sfra) = CLAMPIS(frame, MINFRAME, MAXFRAME);
			return 1;
		} else {
			printf("\nError: frame number must follow '-s / --frame-start'.\n");
			return 0;
		}
	} else {
		printf("\nError: no blend loaded. cannot use '-s / --frame-start'.\n");
		return 0;
	}
}

static int set_end_frame(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (CTX_data_scene(C)) {
		Scene *scene= CTX_data_scene(C);
		if (argc > 1) {
			int frame = atoi(argv[1]);
			(scene->r.efra) = CLAMPIS(frame, MINFRAME, MAXFRAME);
			return 1;
		} else {
			printf("\nError: frame number must follow '-e / --frame-end'.\n");
			return 0;
		}
	} else {
		printf("\nError: no blend loaded. cannot use '-e / --frame-end'.\n");
		return 0;
	}
}

static int set_skip_frame(int argc, const char **argv, void *data)
{
	bContext *C = data;
	if (CTX_data_scene(C)) {
		Scene *scene= CTX_data_scene(C);
		if (argc > 1) {
			int frame = atoi(argv[1]);
			(scene->r.frame_step) = CLAMPIS(frame, 1, MAXFRAME);
			return 1;
		} else {
			printf("\nError: number of frames to step must follow '-j / --frame-jump'.\n");
			return 0;
		}
	} else {
		printf("\nError: no blend loaded. cannot use '-j / --frame-jump'.\n");
		return 0;
	}
}





















static int run_python(int argc, const char **argv, void *data)
{

	bContext *C = data;

	
	if (argc > 1) {
		
		char filename[FILE_MAXDIR + FILE_MAXFILE];
		BLI_strncpy(filename, argv[1], sizeof(filename));
		BLI_path_cwd(filename);

		BPY_CTX_SETUP(BPY_filepath_exec(C, filename, NULL))

		return 1;
	} else {
		printf("\nError: you must specify a Python script after '-P / --python'.\n");
		return 0;
	}

	(void)argc; (void)argv; (void)data; 
	printf("This blender was built without python support\n");
	return 0;

}

static int run_python_console(int UNUSED(argc), const char **argv, void *data)
{

	bContext *C = data;

	BPY_CTX_SETUP(BPY_string_exec(C, "__import__('code').interact()"))

	return 0;

	(void)argv; (void)data; 
	printf("This blender was built without python support\n");
	return 0;

}

static int set_addons(int argc, const char **argv, void *data)
{
	
	if (argc > 1) {

		const int slen= strlen(argv[1]) + 128;
		char *str= malloc(slen);
		bContext *C= data;
		BLI_snprintf(str, slen, "[__import__('addon_utils').enable(i, default_set=False) for i in '%s'.split(',')]", argv[1]);
		BPY_CTX_SETUP(BPY_string_exec(C, str));
		free(str);

		(void)argv; (void)data; 

		return 1;
	}
	else {
		printf("\nError: you must specify a comma separated list after '--addons'.\n");
		return 0;
	}
}


static int load_file(int UNUSED(argc), const char **argv, void *data)
{
	bContext *C = data;

	
	char filename[FILE_MAXDIR + FILE_MAXFILE];
	BLI_strncpy(filename, argv[0], sizeof(filename));
	BLI_path_cwd(filename);

	if (G.background) {
		int retval = BKE_read_file(C, filename, NULL);

		
		if (retval != BKE_READ_FILE_FAIL) {
			wmWindowManager *wm= CTX_wm_manager(C);

			
			if(wm==NULL && CTX_data_main(C)->wm.first==NULL) {
				extern void wm_add_default(bContext *C);

				
				CTX_wm_screen_set(C, CTX_data_main(C)->screen.first);
				wm_add_default(C);
			}

			CTX_wm_manager_set(C, NULL); 
			WM_check(C);
			G.relbase_valid = 1;
			if (CTX_wm_manager(C) == NULL) CTX_wm_manager_set(C, wm); 

			DAG_on_visible_update(CTX_data_main(C), TRUE);
		}

		

		
		BPY_driver_reset();
		BPY_modules_load_user(C);


		
	
	
	} else {
		
		ReportList reports;
		BKE_reports_init(&reports, RPT_PRINT);
		WM_read_file(C, filename, &reports);
		BKE_reports_clear(&reports);
	}

	G.file_loaded = 1;

	return 0;
}

static void setupArguments(bContext *C, bArgs *ba, SYS_SystemHandle *syshandle)
{
	static char output_doc[] = "<path>" "\n\tSet the render path and file name." "\n\tUse // at the start of the path to" "\n\t\trender relative to the blend file." "\n\tThe # characters are replaced by the frame number, and used to define zero padding." "\n\t\tani_##_test.png becomes ani_01_test.png" "\n\t\ttest-######.png becomes test-000001.png" "\n\t\tWhen the filename does not contain #, The suffix #### is added to the filename" "\n\tThe frame number will be added at the end of the filename." "\n\t\teg: blender -b foobar.blend -o //render_ -F PNG -x 1 -a" "\n\t\t//render_ becomes //render_####, writing frames as //render_0001.png//";










	static char format_doc[] = "<format>" "\n\tSet the render format, Valid options are..." "\n\t\tTGA IRIS JPEG MOVIE IRIZ RAWTGA" "\n\t\tAVIRAW AVIJPEG PNG BMP FRAMESERVER" "\n\t(formats that can be compiled into blender, not available on all systems)" "\n\t\tHDR TIFF EXR MULTILAYER MPEG AVICODEC QUICKTIME CINEON DPX DDS";





	static char playback_doc[] = "<options> <file(s)>" "\n\tPlayback <file(s)>, only operates this way when not running in background." "\n\t\t-p <sx> <sy>\tOpen with lower left corner at <sx>, <sy>" "\n\t\t-m\t\tRead from disk (Don't buffer)" "\n\t\t-f <fps> <fps-base>\t\tSpecify FPS to start with" "\n\t\t-j <frame>\tSet frame step to <frame>";





	static char game_doc[] = "Game Engine specific options" "\n\t-g fixedtime\t\tRun on 50 hertz without dropping frames" "\n\t-g vertexarrays\t\tUse Vertex Arrays for rendering (usually faster)" "\n\t-g nomipmap\t\tNo Texture Mipmapping" "\n\t-g linearmipmap\t\tLinear Texture Mipmapping instead of Nearest (default)";




	static char debug_doc[] = "\n\tTurn debugging on\n" "\n\t* Prints every operator call and their arguments" "\n\t* Disables mouse grab (to interact with a debugger in some cases)" "\n\t* Keeps python sys.stdin rather then setting it to None";



	

	
	BLI_argsAdd(ba, -1, "--", NULL, "\n\tEnds option processing, following arguments passed unchanged. Access via python's sys.argv", end_arguments, NULL);

	
	BLI_argsAdd(ba, 1, "-h", "--help", "\n\tPrint this help text and exit", print_help, ba);
	
	BLI_argsAdd(ba, 1, "/?", NULL, "\n\tPrint this help text and exit (windows only)", print_help, ba);

	BLI_argsAdd(ba, 1, "-v", "--version", "\n\tPrint Blender version and exit", print_version, NULL);

	BLI_argsAdd(ba, 1, "-y", "--enable-autoexec", "\n\tEnable automatic python script execution (default)", enable_python, NULL);
	BLI_argsAdd(ba, 1, "-Y", "--disable-autoexec", "\n\tDisable automatic python script execution (pydrivers, pyconstraints, pynodes)", disable_python, NULL);

	BLI_argsAdd(ba, 1, "-b", "--background", "<file>\n\tLoad <file> in background (often used for UI-less rendering)", background_mode, NULL);

	BLI_argsAdd(ba, 1, "-a", NULL, playback_doc, playback_mode, NULL);

	BLI_argsAdd(ba, 1, "-d", "--debug", debug_doc, debug_mode, ba);
	BLI_argsAdd(ba, 1, NULL, "--debug-fpe", "\n\tEnable floating point exceptions", set_fpe, NULL);

	BLI_argsAdd(ba, 1, NULL, "--factory-startup", "\n\tSkip reading the "STRINGIFY(BLENDER_STARTUP_FILE)" in the users home directory", set_factory_startup, NULL);

	
	BLI_argsAdd(ba, 1, NULL, "--env-system-config",		"\n\tSet the "STRINGIFY_ARG(BLENDER_SYSTEM_CONFIG)" environment variable", set_env, NULL);
	BLI_argsAdd(ba, 1, NULL, "--env-system-datafiles",	"\n\tSet the "STRINGIFY_ARG(BLENDER_SYSTEM_DATAFILES)" environment variable", set_env, NULL);
	BLI_argsAdd(ba, 1, NULL, "--env-system-scripts",	"\n\tSet the "STRINGIFY_ARG(BLENDER_SYSTEM_SCRIPTS)" environment variable", set_env, NULL);
	BLI_argsAdd(ba, 1, NULL, "--env-system-plugins",	"\n\tSet the "STRINGIFY_ARG(BLENDER_SYSTEM_PLUGINS)" environment variable", set_env, NULL);
	BLI_argsAdd(ba, 1, NULL, "--env-system-python",		"\n\tSet the "STRINGIFY_ARG(BLENDER_SYSTEM_PYTHON)" environment variable", set_env, NULL);

	
	BLI_argsAdd(ba, 2, "-p", "--window-geometry", "<sx> <sy> <w> <h>\n\tOpen with lower left corner at <sx>, <sy> and width and height as <w>, <h>", prefsize, NULL);
	BLI_argsAdd(ba, 2, "-w", "--window-border", "\n\tForce opening with borders (default)", with_borders, NULL);
	BLI_argsAdd(ba, 2, "-W", "--window-borderless", "\n\tForce opening without borders", without_borders, NULL);
	BLI_argsAdd(ba, 2, "-con", "--start-console", "\n\tStart with the console window open (ignored if -b is set)", start_with_console, NULL);
	BLI_argsAdd(ba, 2, "-R", NULL, "\n\tRegister .blend extension, then exit (Windows only)", register_extension, NULL);
	BLI_argsAdd(ba, 2, "-r", NULL, "\n\tSilently register .blend extension, then exit (Windows only)", register_extension, ba);

	
	BLI_argsAddCase(ba, 3, "-nojoystick", 1, NULL, 0, "\n\tDisable joystick support", no_joystick, syshandle);
	BLI_argsAddCase(ba, 3, "-noglsl", 1, NULL, 0, "\n\tDisable GLSL shading", no_glsl, NULL);
	BLI_argsAddCase(ba, 3, "-noaudio", 1, NULL, 0, "\n\tForce sound system to None", no_audio, NULL);
	BLI_argsAddCase(ba, 3, "-setaudio", 1, NULL, 0, "\n\tForce sound system to a specific device\n\tNULL SDL OPENAL JACK", set_audio, NULL);

	
	BLI_argsAdd(ba, 4, "-g", NULL, game_doc, set_ge_parameters, syshandle);
	BLI_argsAdd(ba, 4, "-f", "--render-frame", "<frame>\n\tRender frame <frame> and save it.\n\t+<frame> start frame relative, -<frame> end frame relative.", render_frame, C);
	BLI_argsAdd(ba, 4, "-a", "--render-anim", "\n\tRender frames from start to end (inclusive)", render_animation, C);
	BLI_argsAdd(ba, 4, "-S", "--scene", "<name>\n\tSet the active scene <name> for rendering", set_scene, C);
	BLI_argsAdd(ba, 4, "-s", "--frame-start", "<frame>\n\tSet start to frame <frame> (use before the -a argument)", set_start_frame, C);
	BLI_argsAdd(ba, 4, "-e", "--frame-end", "<frame>\n\tSet end to frame <frame> (use before the -a argument)", set_end_frame, C);
	BLI_argsAdd(ba, 4, "-j", "--frame-jump", "<frames>\n\tSet number of frames to step forward after each rendered frame", set_skip_frame, C);
	BLI_argsAdd(ba, 4, "-P", "--python", "<filename>\n\tRun the given Python script (filename or Blender Text)", run_python, C);
	BLI_argsAdd(ba, 4, NULL, "--python-console", "\n\tRun blender with an interactive console", run_python_console, C);
	BLI_argsAdd(ba, 4, NULL, "--addons", "\n\tComma separated list of addons (no spaces)", set_addons, C);

	BLI_argsAdd(ba, 4, "-o", "--render-output", output_doc, set_output, C);
	BLI_argsAdd(ba, 4, "-E", "--engine", "<engine>\n\tSpecify the render engine\n\tuse -E help to list available engines", set_engine, C);

	BLI_argsAdd(ba, 4, "-F", "--render-format", format_doc, set_image_type, C);
	BLI_argsAdd(ba, 4, "-t", "--threads", "<threads>\n\tUse amount of <threads> for rendering in background\n\t[1-" STRINGIFY(BLENDER_MAX_THREADS) "], 0 for systems processor count.", set_threads, NULL);
	BLI_argsAdd(ba, 4, "-x", "--use-extension", "<bool>\n\tSet option to add the file extension to the end of the file", set_extension, C);

}






int main(int argc, const char **argv)
{
	SYS_SystemHandle syshandle;
	bContext *C= CTX_create();
	bArgs *ba;






	br_init( NULL );


	setCallbacks();

		
	if (argc==2 && strncmp(argv[1], "-psn_", 5)==0) {
		extern int GHOST_HACK_getFirstFile(char buf[]);
		static char firstfilebuf[512];

		argc= 1;

		if (GHOST_HACK_getFirstFile(firstfilebuf)) {
			argc= 2;
			argv[1]= firstfilebuf;
		}
	}




	fpsetmask(0);


	
	

	BLI_where_am_i(bprogname, sizeof(bprogname), argv[0]);
	

	strip_quotes(build_date);
	strip_quotes(build_time);
	strip_quotes(build_rev);
	strip_quotes(build_platform);
	strip_quotes(build_type);
	strip_quotes(build_cflags);
	strip_quotes(build_cxxflags);
	strip_quotes(build_linkflags);
	strip_quotes(build_system);


	BLI_threadapi_init();

	RNA_init();
	RE_engines_init();

		
	pluginapi_force_ref();

	init_nodesystem();
	
	initglobals();	

	IMB_init();


	syshandle = SYS_GetSystem();
	GEN_init_messaging_system();

	syshandle= 0;


	
	ba = BLI_argsInit(argc, argv); 
	setupArguments(C, ba, &syshandle);

	BLI_argsParse(ba, 1, NULL, NULL);


	setuid(getuid()); 



	G.background= 1; 

	
	if(G.background) signal(SIGINT, blender_esc);	


	
	BKE_font_register_builtin(datatoc_Bfont, datatoc_Bfont_size);

	
	sound_init_once();
	
	init_def_material();

	if(G.background==0) {
		BLI_argsParse(ba, 2, NULL, NULL);
		BLI_argsParse(ba, 3, NULL, NULL);

		WM_init(C, argc, argv);

		
		BLI_where_is_temp(btempdir, FILE_MAX, 1); 


	BLI_setenv("SDL_VIDEODRIVER", "dummy");

	}
	else {
		BLI_argsParse(ba, 3, NULL, NULL);

		WM_init(C, argc, argv);

		BLI_where_is_temp(btempdir, FILE_MAX, 0); 
	}

	

	

	printf("\n* WARNING * - Blender compiled without Python!\nthis is not intended for typical usage\n\n");

	
	CTX_py_init_set(C, 1);
	WM_keymap_init(C);

	
	BLI_argsParse(ba, 4, load_file, C);

	BLI_argsFree(ba);


	return 0; 


	if(G.background) {
		
		WM_exit(C);
	}

	else {
		if((G.fileflags & G_FILE_AUTOPLAY) && (G.f & G_SCRIPT_AUTOEXEC))
		{
			if(WM_init_game(C))
				return 0;
		}
		else if(!G.file_loaded)
			WM_init_splash(C);
	}

	WM_main(C);


	 

	return 0;
} 

static void error_cb(const char *err)
{
	
	printf("%s\n", err);	
}

static void mem_error_cb(const char *errorStr)
{
	fputs(errorStr, stderr);
	fflush(stderr);
}

static void setCallbacks(void)
{
	
	MEM_set_error_callback(mem_error_cb);


	

	BLI_setErrorCallBack(error_cb); 


}
